"""Phase-20 probation soak: policy, evaluator, assessment, models, start eligibility and the collector.

The evaluator / assessment tests are PURE (no database, no clock).  Everything else runs the PRODUCTION code on a REAL Probation bundle (a real
Phase-17 Partial (UAT) run on the simulated network) under a CONTROLLED clock: no real time passes, the SSH read is the only thing replaced.
"""

from __future__ import annotations

import ast
import copy
import inspect
import logging
import re
from datetime import timedelta
from pathlib import Path
from unittest import mock

import yaml
from django.conf import settings
from django.db import IntegrityError, transaction
from django.test import SimpleTestCase, TestCase

from core import models
from core.services import bundle_service as bs, execution_service, notification_service, slack_service, soak_service as ss
from core.services.health import codes as health_codes, results as health_results
from core.services.soak import assessment, codes as soak_codes, evaluator, interference, lifecycle, policy as soak_policy, sampling
from core.tests.helpers import bundles as bh, health as h, soak as sh

SR, SS, SRes = models.SoakSampleResult, models.SoakState, models.SoakResult
T0, END = sh.T0, sh.END
POLICY = soak_policy.SoakPolicy(version="20.0.0", duration_seconds=7200, sample_interval_seconds=600, max_gap_seconds=1800, min_coverage_percent=90,
                                resource_consecutive_samples=3, decision_max_age_seconds=7200, freshness_healthy_seconds=60.0, freshness_stale_seconds=120.0,
                                production_duration_seconds=604800)


def fact(bucket, result=SR.PASS, *, at=None, integrity=True, interference=False, terminal=False, critical=(), warnings=0, expected="PASS", fresh="FRESH"):
    return evaluator.SampleFacts(bucket, at if at is not None else T0 + timedelta(seconds=600 * bucket), result, integrity, interference, terminal, tuple(critical),
                                 expected, fresh, warnings)


def healthy(buckets=range(0, 12)):
    return [fact(b) for b in buckets]


def verdict(facts, now=END, **kwargs):
    return evaluator.evaluate(POLICY, T0, END, facts, now, **kwargs)


class ImmediateGuard:
    def __init__(self, integrity_ok=True, interference=()):
        self.integrity_ok, self.interference = integrity_ok, list(interference)


# =============================================================================================================================
class PolicyTests(SimpleTestCase):
    def test_the_production_duration_is_exactly_168_elapsed_hours_and_the_cadence_matches_the_monitoring_event_window(self):
        self.assertEqual(settings.SOAK_PRODUCTION_DURATION_SECONDS, 7 * 24 * 3600)
        self.assertEqual(settings.PROBATION_SOAK_DURATION_SECONDS, 604800)        # the default; an environment variable can only RAISE it
        topology = yaml.safe_load((Path(settings.REPO_ROOT) / "monitoring/config/topology.yml").read_text())
        self.assertEqual(settings.PROBATION_SOAK_SAMPLE_INTERVAL_SECONDS, topology["recent_event_window_seconds"],
                         "consecutive samples must tile the timeline: the topology service counts critical events inside this window")
        policy = soak_policy.current_policy()
        self.assertEqual((policy.duration_seconds, policy.total_buckets, policy.is_production_duration), (604800, 672, True))
        self.assertEqual(policy.resource_consecutive_samples, yaml.safe_load((Path(settings.REPO_ROOT) / "monitoring/config/cpu_threshold_policy.yml").read_text())["consecutive_samples"])

    def test_the_environment_can_raise_but_never_shorten_the_production_duration_and_bad_values_are_refused(self):
        source = (Path(settings.BASE_DIR) / "config" / "settings.py").read_text()
        self.assertRegex(source, r'"PROBATION_SOAK_DURATION_SECONDS", str\(SOAK_PRODUCTION_DURATION_SECONDS\), SOAK_PRODUCTION_DURATION_SECONDS,')   # lower bound == 7 days
        for label, overrides in (("zero duration", {"PROBATION_SOAK_DURATION_SECONDS": 0}), ("gap below one interval", {"PROBATION_SOAK_MAX_GAP_SECONDS": 60}),
                                 ("coverage over 100", {"PROBATION_SOAK_MIN_COVERAGE_PERCENT": 101})):
            with self.subTest(case=label), self.settings(**{**sh.SHORT, **overrides}), self.assertRaises(ValueError):
                soak_policy.current_policy()
        with self.settings(**sh.SHORT):
            self.assertFalse(soak_policy.current_policy().is_production_duration)   # a short (test) policy is marked, never mistaken for production

    def test_every_health_check_code_is_classified_by_a_rule_so_a_new_code_forces_a_soak_decision(self):
        for code in health_codes.CODES:
            for status in health_codes.CheckStatus.ALL:
                with self.subTest(code=code, status=status):
                    result = health_results.CheckResult(code, status, "R1", "m", "TELEMETRY", role=health_codes.Role.TARGET)
                    self.assertIn(assessment.classify(result), {"OK", "WARNING", "UNAVAILABLE", "RESOURCE_CRITICAL", "INTENDED_STATE_FAILED"})


# =============================================================================================================================
class EvaluatorTests(SimpleTestCase):
    def test_duration_boundary_is_inclusive_and_nothing_passes_before_the_pinned_end(self):
        samples = healthy()
        for label, now, state, result in (
            ("one second before", END - timedelta(seconds=1), SS.RUNNING, ""), ("exactly the required duration", END, SS.COMPLETED, SRes.PASS),
            ("long after", END + timedelta(days=3), SS.COMPLETED, SRes.PASS), ("at the start", T0, SS.RUNNING, ""),
        ):
            with self.subTest(case=label):
                v = verdict(samples, now)
                self.assertEqual((v.state, v.result), (state, result))

    def test_coverage_matrix(self):
        every = healthy()
        cases = {
            "adequate distributed samples": (every, SRes.PASS, []),
            "one missed interval is inside the 90% tolerance": ([f for f in every if f.bucket != 5], SRes.PASS, []),
            "too few samples": ([f for f in every if f.bucket in (0, 6, 11)], SRes.INCOMPLETE, {"MIN_COVERAGE"}),
            "no samples at all": ([], SRes.INCOMPLETE, {"NO_USABLE_SAMPLES", "MIN_COVERAGE", "LEADING_GAP", "TRAILING_GAP"}),
            "a gap over the maximum in the middle": ([f for f in every if f.bucket not in (4, 5, 6, 7)], SRes.INCOMPLETE, {"MIN_COVERAGE", "MAX_GAP"}),
            "missing the start": ([f for f in every if f.bucket > 3], SRes.INCOMPLETE, {"MIN_COVERAGE", "LEADING_GAP"}),
            "missing the end": ([f for f in every if f.bucket < 8], SRes.INCOMPLETE, {"MIN_COVERAGE", "TRAILING_GAP"}),
            "a single sample at each end is not coverage": ([every[0], every[-1]], SRes.INCOMPLETE, {"MIN_COVERAGE", "MAX_GAP"}),
            "incomplete samples never count": ([fact(b, SR.INCOMPLETE, fresh="STALE") if b in (3, 4, 5, 6) else fact(b) for b in range(12)], SRes.INCOMPLETE, {"MIN_COVERAGE", "MAX_GAP"}),
        }
        for label, (samples, result, problems) in cases.items():
            with self.subTest(case=label):
                v = verdict(samples)
                self.assertEqual((v.state, v.result), (SS.COMPLETED, result))
                if problems:
                    self.assertEqual(set(v.problems) & problems, problems, v.problems)
                    self.assertEqual(v.reason, soak_codes.COVERAGE_INSUFFICIENT)
                else:
                    self.assertEqual((v.problems, v.reason), ([], soak_codes.TECHNICAL_PASS))

    def test_the_closing_sample_taken_after_the_end_never_extends_coverage(self):
        without_tail = [f for f in healthy() if f.bucket < 8]
        closing = fact(12, at=END + timedelta(seconds=30))
        v = verdict([*without_tail, closing])
        self.assertEqual((v.result, "TRAILING_GAP" in v.problems), (SRes.INCOMPLETE, True))
        self.assertEqual(verdict([*healthy(), closing]).result, SRes.PASS)

    def test_terminal_outcomes_are_never_averaged_away_and_arrive_before_the_end(self):
        early = T0 + timedelta(seconds=1200)
        cases = {
            "integrity failure": (dict(integrity=False), SS.INVALIDATED, soak_codes.BUNDLE_INTEGRITY_FAILED, ""),
            "interference": (dict(interference=True), SS.INVALIDATED, soak_codes.OVERLAPPING_EXECUTION, ""),
            "intended-state failure": (dict(result=SR.FAIL, terminal=True), SS.COMPLETED, soak_codes.EXPECTED_STATE_FAILED, SRes.FAIL),
        }
        for label, (kwargs, state, reason, result) in cases.items():
            with self.subTest(case=label):
                v = verdict([*healthy(range(0, 2)), fact(2, **kwargs)], early)
                self.assertEqual((v.state, v.result, v.reason, v.terminal), (state, result, reason, True))
        v = verdict(healthy(), END, guard=ImmediateGuard(interference=[{"run_id": "x"}]))
        self.assertEqual((v.state, v.reason), (SS.INVALIDATED, soak_codes.OVERLAPPING_EXECUTION), "the guard invalidates even with perfect samples")
        v = verdict(healthy(), END, guard=ImmediateGuard(integrity_ok=False))
        self.assertEqual((v.state, v.reason), (SS.INVALIDATED, soak_codes.BUNDLE_INTEGRITY_FAILED))

    def test_a_critical_resource_needs_the_project_consecutive_sample_limit_and_a_normal_sample_resets_it(self):
        crit = lambda b: fact(b, SR.FAIL, critical=("R1:CPU_HIGH",))      # noqa: E731
        early = T0 + timedelta(seconds=3000)
        self.assertEqual(verdict([fact(0), crit(1), crit(2)], early).state, SS.RUNNING, "two consecutive critical samples: a transient")
        v = verdict([fact(0), crit(1), crit(2), crit(3)], early)
        self.assertEqual((v.state, v.result, v.reason), (SS.COMPLETED, SRes.FAIL, soak_codes.RESOURCE_CRITICAL_SUSTAINED))
        self.assertEqual(verdict([crit(0), crit(1), fact(2), crit(3), crit(4)], early).state, SS.RUNNING, "a healthy sample resets the streak")
        self.assertEqual(verdict([crit(0), fact(1, SR.INCOMPLETE, fresh="STALE"), crit(2), crit(3)], early).state, SS.COMPLETED, "an incomplete sample neither extends nor resets")
        self.assertEqual(verdict([fact(0, SR.FAIL, critical=("R1:CPU_HIGH",)), fact(1, SR.FAIL, critical=("R2:CPU_HIGH",)), fact(2, SR.FAIL, critical=("R1:MEMORY_HIGH",))], early).state,
                         SS.RUNNING, "different devices / metrics are different streaks")

    def test_clock_anomalies_never_produce_a_pass(self):
        backwards = [*healthy(range(0, 5)), fact(5, at=T0 + timedelta(seconds=100)), *healthy(range(6, 12))]
        v = verdict(backwards)
        self.assertEqual((v.result, "CLOCK_ANOMALY" in v.problems), (SRes.INCOMPLETE, True))
        before_start = verdict([fact(0, at=T0 - timedelta(seconds=5)), *healthy(range(1, 12))])
        self.assertEqual(before_start.result, SRes.INCOMPLETE)

    def test_evaluation_is_deterministic_and_the_evidence_digest_binds_the_samples(self):
        samples = healthy()
        first, second = verdict(samples), verdict(list(reversed(samples)))
        self.assertEqual((first.state, first.result, first.stats), (second.state, second.result, second.stats))
        self.assertEqual(evaluator.samples_digest(samples), evaluator.samples_digest(list(reversed(samples))))
        self.assertNotEqual(evaluator.samples_digest(samples), evaluator.samples_digest([*samples[:-1], fact(11, SR.PASS_WITH_WARNINGS)]))
        self.assertRegex(evaluator.evidence_digest({"a": 1}), r"^[0-9a-f]{64}$")
        self.assertEqual(evaluator.evidence_digest({"a": 1, "b": 2}), evaluator.evidence_digest({"b": 2, "a": 1}))


# =============================================================================================================================
def check(code, status, *, role=health_codes.Role.TARGET, device="R1"):
    return health_results.CheckResult(code, status, device, f"{code} {status}", "TELEMETRY", role=role)


class AssessmentTests(SimpleTestCase):
    def evaluation(self, result="PASS", results=()):
        return type("E", (), {"result": result, "results": list(results), "summary": {"requirements": 2}})()

    def assess(self, health=(), evaluation=None, freshness=None, pipeline_ok=True):
        return assessment.assess(health_results=list(health), evaluation=evaluation or self.evaluation(), freshness={"R1": "FRESH"} if freshness is None else freshness, device_facts={},
                                 pipeline_ok=pipeline_ok, observed_at=None, device_health="HEALTHY")

    def test_the_classification_table(self):
        S = health_codes.CheckStatus
        rows = [
            ("stale telemetry (warn) is missing evidence", "DEVICE_TELEMETRY_STALE", S.WARN, "UNAVAILABLE"),
            ("expired telemetry (fail) is missing evidence, not a device failure", "DEVICE_TELEMETRY_STALE", S.FAIL, "UNAVAILABLE"),
            ("unavailable telemetry", "DEVICE_TELEMETRY_UNAVAILABLE", S.UNKNOWN, "UNAVAILABLE"),
            ("an unreachable device we cannot corroborate", "DEVICE_UNREACHABLE", S.UNKNOWN, "UNAVAILABLE"),
            ("an unhealthy pipeline is missing evidence", "MONITORING_PIPELINE_UNHEALTHY", S.FAIL, "UNAVAILABLE"),
            ("cpu warning", "CPU_HIGH", S.WARN, "WARNING"), ("cpu critical", "CPU_HIGH", S.FAIL, "RESOURCE_CRITICAL"), ("memory critical", "MEMORY_HIGH", S.FAIL, "RESOURCE_CRITICAL"),
            ("unknown cpu is missing evidence", "CPU_HIGH", S.UNKNOWN, "UNAVAILABLE"),
            ("recent critical events are a warning only", "CRITICAL_EVENTS_RECENT", S.WARN, "WARNING"),
            ("a non-blocking link failure is a warning (existing policy)", "LINK_HEALTH_DEGRADED", S.FAIL, "WARNING"),
            ("a blocking interface failure on a target ends the soak", "INTERFACE_OPER_DOWN", S.FAIL, "INTENDED_STATE_FAILED"),
            ("the same failure on a PEER is not blocking", "INTERFACE_OPER_DOWN", S.FAIL, "WARNING"),
            ("a passing check", "DEVICE_TELEMETRY_FRESH", S.PASS, "OK"),
        ]
        for label, code, status, expected in rows:
            with self.subTest(case=label):
                role = health_codes.Role.PEER if "PEER" in label else health_codes.Role.TARGET
                self.assertEqual(assessment.classify(check(code, status, role=role)), expected)

    def test_the_sample_verdict_order_and_that_low_cpu_never_hides_a_failed_requirement(self):
        S = health_codes.CheckStatus
        healthy_cpu = [check("CPU_HIGH", S.PASS), check("DEVICE_TELEMETRY_FRESH", S.PASS)]
        cases = {
            "all healthy": (dict(health=healthy_cpu), SR.PASS, False),
            "a warning": (dict(health=[*healthy_cpu, check("CRITICAL_EVENTS_RECENT", S.WARN)]), SR.PASS_WITH_WARNINGS, False),
            "warnings from the postcheck": (dict(health=healthy_cpu, evaluation=self.evaluation("PASS_WITH_WARNINGS")), SR.PASS_WITH_WARNINGS, False),
            "a failed requirement with healthy CPU": (dict(health=healthy_cpu, evaluation=self.evaluation("FAIL", [check("ROUTE_MISSING", S.FAIL)])), SR.FAIL, True),
            "a failed requirement is authoritative even from a non-blocking role": (dict(health=healthy_cpu, evaluation=self.evaluation("FAIL", [check("OSPF_ADJACENCY_DOWN", S.FAIL, role=health_codes.Role.PEER)])), SR.FAIL, True),
            "critical cpu alone": (dict(health=[check("CPU_HIGH", S.FAIL)]), SR.FAIL, False),
            "incomplete postcheck": (dict(health=healthy_cpu, evaluation=self.evaluation("INCOMPLETE", [check("POSTCHECK_DATA_UNAVAILABLE", S.UNKNOWN)])), SR.INCOMPLETE, False),
            "stale telemetry even when every check passed": (dict(health=healthy_cpu, freshness={"R1": "STALE"}), SR.INCOMPLETE, False),
            "expired telemetry": (dict(health=healthy_cpu, freshness={"R1": "EXPIRED"}), SR.INCOMPLETE, False),
            "no telemetry evidence at all": (dict(health=healthy_cpu, freshness={"R1": "UNKNOWN"}), SR.INCOMPLETE, False),
            "monitoring pipeline down": (dict(health=healthy_cpu, pipeline_ok=False), SR.INCOMPLETE, False),
            "no scoped device at all": (dict(health=[], freshness={}), SR.INCOMPLETE, False),
        }
        for label, (kwargs, result, terminal) in cases.items():
            with self.subTest(case=label):
                sample = self.assess(**kwargs)
                self.assertEqual((sample.result, sample.terminal_failure), (result, terminal))
        self.assertEqual(self.assess(health=[check("CPU_HIGH", S.FAIL, device="R1")]).resource_critical, ["R1:CPU_HIGH"])

    def test_a_guard_failure_invalidates_without_reading_health(self):
        sample = assessment.invalidated(integrity_ok=False, interference=[{"run_id": "r", "change_id": "c", "outcome": "SUCCEEDED", "devices": ["R1"]}], integrity_codes=["PAYLOAD_DIGEST_MISMATCH"])
        self.assertEqual((sample.result, sample.integrity_ok, bool(sample.interference)), (SR.INVALIDATED, False, True))
        self.assertEqual({f["check_code"] for f in sample.findings}, {"BUNDLE_INTEGRITY_FAILED", "OVERLAPPING_EXECUTION"})


# =============================================================================================================================
SoakFixture, history_run = sh.SoakFixture, sh.history_run


class ModelTests(SoakFixture):
    def test_identity_pinned_timestamps_policy_and_state_result_shape(self):
        run = self.start().run
        self.assertEqual((run.soak_id, run.state, run.result, run.terminal_reason), (f"SOAK-{run.pk:06d}", SS.RUNNING, "", ""))
        self.assertEqual((run.started_at, run.required_end_at), (T0, END))
        self.assertEqual((run.started_at.tzinfo is not None, run.duration_seconds, run.policy_version, run.bundle_digest), (True, 7200, "20.0.0", self.f.prob.bundle_digest))
        with self.settings(PROBATION_SOAK_DURATION_SECONDS=60):   # changing the global setting later never shortens a run that already started
            self.assertEqual(self.run_row().duration_seconds, 7200)
            self.assertEqual(soak_policy.SoakPolicy.from_dict(self.run_row().policy).duration_seconds, 7200)
        bad = {"a running run with a result": dict(state=SS.RUNNING, result=SRes.PASS), "a completed run with no result": dict(state=SS.COMPLETED, finished_at=T0),
               "an invalidated run with a result": dict(state=SS.INVALIDATED, result=SRes.PASS, finished_at=T0), "an unfinished terminal run": dict(state=SS.CANCELLED)}
        for label, changes in bad.items():
            with self.subTest(case=label), self.assertRaises(ValueError):
                candidate = models.ProbationSoakRun.objects.get(pk=run.pk)
                for name, value in changes.items():
                    setattr(candidate, name, value)
                candidate.save()

    def test_one_active_soak_per_bundle_is_a_database_guarantee_and_retries_are_new_runs(self):
        first = self.start().run
        self.assertEqual(ss.start_soak(self.f.prob, actor="tester", now=T0 + timedelta(seconds=5)).run.pk, first.pk, "a double click returns the active run")
        self.assertEqual(models.ProbationSoakRun.objects.count(), 1)
        rival = models.ProbationSoakRun(bundle=self.f.prob, bundle_digest=self.f.prob.bundle_digest, policy_version="20.0.0", policy=first.policy, started_at=T0,
                                        required_end_at=END, started_by="x")
        with self.assertRaises(IntegrityError), transaction.atomic():
            rival.save()          # the partial unique index, not the service, refuses a second RUNNING run
        self.assertTrue(ss.cancel_soak(first, actor="tester", now=T0 + timedelta(seconds=10)).cancelled)
        second = ss.start_soak(self.f.prob, actor="tester", now=T0 + timedelta(seconds=20))
        self.assertTrue(second.created and second.run.pk != first.pk)
        self.assertEqual(models.ProbationSoakRun.objects.filter(bundle=self.f.prob).count(), 2)   # history is kept, the bundle is untouched

    def test_a_finished_run_and_every_sample_are_immutable_and_history_is_never_deleted(self):
        run = self.start().run
        sh.drive(self.f.world, start=T0, until=T0 + timedelta(seconds=1500))
        sample = run.samples.first()
        self.assertEqual(run.samples.count(), 3)
        for label, action in (("sample field", lambda: (setattr(sample, "result", SR.FAIL), sample.save())), ("sample delete", sample.delete),
                              ("sample queryset update", lambda: run.samples.update(result=SR.FAIL)), ("sample queryset delete", run.samples.all().delete),
                              ("run delete", run.delete), ("run queryset delete", lambda: models.ProbationSoakRun.objects.filter(pk=run.pk).delete())):
            with self.subTest(case=label), self.assertRaises(ValueError):
                action()
        duplicate = models.ProbationSoakSample(run=run, bucket=0, sampled_at=T0, collector_version="x", result=SR.PASS, integrity_ok=True, interference=False)
        with self.assertRaises(IntegrityError), transaction.atomic():
            duplicate.save()
        ss.cancel_soak(run, actor="tester", now=T0 + timedelta(seconds=1600))
        finished = self.run_row()
        for name, value in (("started_at", T0 + timedelta(hours=1)), ("policy", {}), ("state", SS.RUNNING), ("result", SRes.PASS), ("required_end_at", END + timedelta(days=9))):
            with self.subTest(field=name), self.assertRaises(ValueError):
                setattr(finished, name, value)
                finished.save()
        self.assertEqual(run.samples.count(), 3, "cancelling keeps the evidence")

    def test_the_bundle_is_never_touched_by_a_soak(self):
        before = (models.ConfigurationBundle.objects.count(), self.f.prob.bundle_digest, self.f.prob.manifest)
        sh.passed(self.f)
        prob = models.ConfigurationBundle.objects.get(pk=self.f.prob.pk)
        self.assertEqual((models.ConfigurationBundle.objects.count(), prob.bundle_digest, prob.manifest), before)
        self.assertTrue(bs.verify_bundle_integrity(prob).ok)


class StartEligibilityTests(SoakFixture):
    def codes(self, bundle=None):
        return [b["code"] for b in ss.check_soak_start(bundle or self.f.prob).blockers]

    def test_an_intact_verified_probation_bundle_is_eligible_and_only_probation_bundles_are_soaked(self):
        check = ss.check_soak_start(self.f.prob)
        self.assertEqual((check.eligible, check.blockers, check.devices), (True, [], ["R1", "R2"]))
        self.assertEqual(self.codes(self.f.uat), ["NOT_PROBATION"])
        refused = ss.start_soak(self.f.uat, actor="tester", now=T0)
        self.assertTrue(refused.refused and refused.run is None)
        self.assertFalse(models.ProbationSoakRun.objects.exists())

    def test_a_later_overlapping_execution_before_start_supersedes_the_candidate_and_a_non_overlapping_one_does_not(self):
        cases = {
            "a later run on the same devices": (dict(devices=["R1"]), ["SUPERSEDED"]),
            "a later run that partly overlaps": (dict(devices=["R2", "R5"]), ["SUPERSEDED"]),
            "a later run on other devices": (dict(devices=["R3"]), []),
            "a later run that changed nothing (blocked)": (dict(devices=["R1"], outcome="BLOCKED"), []),
            "a later run that failed with no mutation": (dict(devices=["R1"], outcome="FAILED_NO_MUTATION"), []),
            "a later run still in flight": (dict(devices=["R1"], state="RUNNING"), ["SUPERSEDED"]),
            "a later failed run that left partial effects": (dict(devices=["R2"], outcome="FAILED_PARTIAL_APPLIED"), ["SUPERSEDED"]),
        }
        for label, (kwargs, expected) in cases.items():
            with self.subTest(case=label), bh.rolled_back():
                history_run(self.f.prob, **kwargs)
                self.assertEqual(self.codes(), expected)
                if expected:
                    self.assertTrue(ss.start_soak(self.f.prob, actor="tester", now=T0).refused)
                    self.assertFalse(models.ProbationSoakRun.objects.exists(), "nothing is silently created and no new Probation artifact appears")

    def test_the_integrity_of_the_candidate_is_verified_now_and_a_failure_is_audited_not_repaired(self):
        bh.oob(models.ConfigurationBundle).filter(pk=self.f.prob.pk).update(bundle_digest="0" * 64)
        prob = bs.get_bundle(self.f.prob.bundle_id)
        self.assertEqual(self.codes(prob), ["BUNDLE_INTEGRITY_FAILED"])
        self.assertTrue(ss.start_soak(prob, actor="tester", now=T0).refused)
        self.assertTrue(models.AuditEvent.objects.filter(event_type=models.AuditEventType.BUNDLE_INTEGRITY_FAILED).exists())
        self.assertFalse(models.ProbationSoakRun.objects.exists())

    def test_an_unsupported_evidence_scope_is_refused_and_start_never_reruns_or_contacts_anything(self):
        with mock.patch("core.services.health.inventory.get_managed_device", return_value=None):
            self.assertEqual(self.codes(), ["EVIDENCE_SCOPE_UNSUPPORTED"])
        with mock.patch("core.services.health.live.get_capability", return_value={"status": "NOT_IMPLEMENTED"}):
            self.assertEqual(self.codes(), ["EVIDENCE_SCOPE_UNSUPPORTED"])
        before = bh.table_counts()
        with bh.no_device_or_network(), self.assertLogs(lifecycle.log, logging.ERROR):   # (this also makes the notification service fail: that must never corrupt a soak)
            with mock.patch("core.services.health.live.read_device", side_effect=AssertionError("start must not read a device")):
                started = ss.start_soak(self.f.prob, actor="tester", now=T0)
        self.assertTrue(started.created)
        self.assertEqual(set(bh.count_changes(before, bh.table_counts())), {"ProbationSoakRun", "AuditEvent"}, "start writes the run and one audit event, nothing else")
        self.assertEqual(models.AuditEvent.objects.filter(event_type="PROBATION_SOAK_STARTED").count(), 1)

    def test_a_golden_child_ends_the_soakability_of_its_probation_bundle(self):
        golden = bh.golden_from(self.f.prob)
        self.assertIn("GOLDEN_EXISTS", self.codes(bs.get_bundle(self.f.prob.bundle_id)))
        self.assertEqual(golden.parent_id, self.f.prob.pk)

    def test_a_running_soak_blocks_a_second_one_and_the_reason_is_reported(self):
        self.start()
        self.assertEqual(self.codes(), ["SOAK_ACTIVE"])


# =============================================================================================================================
class CollectorTests(SoakFixture):
    def world(self, *, break_r1=False):
        world = copy.deepcopy(self.f.world)
        if break_r1:
            world.state["R1"]["interfaces"].pop("Ethernet1")   # the intended interface disappears from the device
        return world

    def sample_at(self, seconds, world=None, **telemetry):
        sh.tick(sh.at(seconds), world or self.world(), **telemetry)
        return self.run_row().samples.order_by("-bucket").first()

    def ticks(self, seconds, world=None, **telemetry):
        world = world or self.world()
        for moment in seconds:
            sh.tick(sh.at(moment), world, **telemetry)
        return self.run_row()

    def test_one_sample_per_interval_a_repeated_tick_is_idempotent_and_a_dry_run_writes_nothing(self):
        self.start()
        first = sh.tick(sh.at(0), self.world())
        self.assertEqual([r.action for r in first.runs], ["SAMPLED"])
        for again in (sh.tick(sh.at(0), self.world()), sh.tick(sh.at(300), self.world())):
            self.assertEqual([r.action for r in again.runs], ["NOT_DUE"])
        before = bh.table_counts()
        dry = sh.tick(sh.at(900), self.world(), dry_run=True)
        self.assertEqual([(r.action, r.bucket) for r in dry.runs], [("WOULD_SAMPLE", 1)])
        self.assertEqual(bh.count_changes(before, bh.table_counts()), {}, "a dry run reads nothing external and writes nothing")
        self.assertEqual(self.run_row().samples.count(), 1)
        sh.tick(sh.at(600), self.world())
        self.assertEqual(list(self.run_row().samples.values_list("bucket", flat=True)), [0, 1])

    def test_two_collectors_racing_for_the_same_interval_persist_exactly_one_sample(self):
        self.start()
        original = sampling.collect

        def other_collector_wins(bundle, **kwargs):
            result = original(bundle, **kwargs)
            models.ProbationSoakSample(run=self.run_row(), bucket=0, sampled_at=sh.at(1), collector_version="other", **result.to_kwargs()).save()
            return result

        with mock.patch.object(sampling, "collect", side_effect=other_collector_wins):
            report = sh.tick(sh.at(5), self.world())
        self.assertEqual([r.action for r in report.runs], ["DUPLICATE"])
        self.assertEqual(list(self.run_row().samples.values_list("bucket", "collector_version")), [(0, "other")])

    def test_what_one_sample_concludes_matrix(self):
        broken = lambda: self.world(break_r1=True)   # noqa: E731
        cases = {
            "healthy": (dict(), None, SR.PASS, False),
            "stale telemetry is never a pass": (dict(ages={"R1": 90}), None, SR.INCOMPLETE, False),
            "expired telemetry": (dict(ages={"R2": 500}), None, SR.INCOMPLETE, False),
            "no timestamp at all": (dict(ages={"R1": None}), None, SR.INCOMPLETE, False),
            "an unmonitored device": (dict(unmonitored=("R1",)), None, SR.INCOMPLETE, False),
            "the monitoring backend is in error": (dict(backend="ERROR"), None, SR.INCOMPLETE, False),
            "a cpu warning is warning-only": (dict(cpu={"R1": 75}), None, SR.PASS_WITH_WARNINGS, False),
            "recent critical events are warning-only": (dict(events={"R2": 3}), None, SR.PASS_WITH_WARNINGS, False),
            "a critical memory level is a failed sample but not yet terminal": (dict(memory={"R1": 95}), None, SR.FAIL, False),
            "a missing intended interface is a terminal failure": (dict(), broken, SR.FAIL, True),
            "a failed requirement with perfectly healthy cpu and memory": (dict(cpu={"R1": 1, "R2": 1}, memory={"R1": 1, "R2": 1}), broken, SR.FAIL, True),
        }
        for label, (telemetry, world_factory, result, terminal) in cases.items():
            with self.subTest(case=label), bh.rolled_back():
                self.start()
                sample = self.sample_at(0, world_factory() if world_factory else None, **telemetry)
                self.assertEqual((sample.result, sample.terminal_failure), (result, terminal), [(f["check_code"], f["class"]) for f in sample.findings])
                self.assertTrue(sample.integrity_ok and not sample.interference)

    def test_a_failed_requirement_ends_the_soak_at_once_with_fail_and_can_never_be_promoted(self):
        self.start()
        run = self.ticks([0, 300, 600], self.world())
        self.assertTrue(run.is_running)
        run = self.ticks([900, 1200], self.world(break_r1=True))
        self.assertEqual((run.state, run.result, run.terminal_reason), (SS.COMPLETED, SRes.FAIL, soak_codes.EXPECTED_STATE_FAILED))
        self.assertLess(run.finished_at, run.required_end_at, "it ended before the window did")
        self.assertEqual(sh.tick(sh.at(1500), self.world()).runs, [], "a finished run is no longer collected")
        self.assertTrue(ss.check_soak_start(self.f.prob).eligible, "the candidate itself is untouched: a retry is a NEW run")
        self.assertTrue(models.AuditEvent.objects.filter(event_type="PROBATION_SOAK_FAILED").exists())

    def test_critical_resources_end_the_soak_only_after_the_projects_consecutive_sample_limit(self):
        self.start()
        world = self.world()
        run = self.ticks([0, 600], world, memory={"R1": 95})
        self.assertTrue(run.is_running, "two critical samples in a row are tolerated (the project's policy is three)")
        run = self.ticks([1200], world, memory={"R1": 40})
        self.assertTrue(run.is_running, "a healthy sample resets the streak")
        run = self.ticks([1800, 2400], world, memory={"R1": 95})
        self.assertTrue(run.is_running)
        run = self.ticks([3000], world, memory={"R1": 95})
        self.assertEqual((run.state, run.result, run.terminal_reason), (SS.COMPLETED, SRes.FAIL, soak_codes.RESOURCE_CRITICAL_SUSTAINED))

    def test_a_full_healthy_window_passes_but_only_at_the_required_duration_and_never_becomes_golden_by_itself(self):
        self.start()
        world = self.world()
        sh.drive(world, start=T0, until=END - timedelta(seconds=1))
        self.assertTrue(self.run_row().is_running, "168 h minus one second is still RUNNING")
        sh.tick(END, world)
        run = self.run_row()
        self.assertEqual((run.state, run.result, run.terminal_reason, run.finished_at), (SS.COMPLETED, SRes.PASS, soak_codes.TECHNICAL_PASS, END))
        self.assertTrue(run.is_technical_pass and not models.GoldenDecision.objects.exists())
        self.assertFalse(models.ConfigurationBundle.objects.filter(kind="GOLDEN").exists(), "technical completion is NOT promotion")
        self.assertEqual(evaluator.verify_run(run), [])
        self.assertEqual(run.evidence_digest, evaluator.evidence_digest(run.evaluation))

    def test_outages_within_the_gap_budget_recover_and_longer_ones_make_the_soak_incomplete(self):
        for label, degraded, result in (("one missed interval", range(3000, 3600, 300), SRes.PASS), ("two missed intervals", range(2400, 3600, 300), SRes.INCOMPLETE)):
            with self.subTest(case=label), bh.rolled_back():
                self.start()
                sh.drive(self.world(), start=T0, until=END, telemetry_at=lambda moment: {"ages": {"R1": 500}} if (moment - T0).total_seconds() in degraded else None)
                run = self.run_row()
                self.assertEqual((run.state, run.result), (SS.COMPLETED, result), run.evaluation.get("problems"))

    def test_a_scheduler_outage_is_never_backfilled_and_makes_the_soak_incomplete(self):
        self.start()
        self.ticks([0, 300, 600, 900, 1200])
        run = self.ticks([6300, 6600, 6900, 7200, 7500])         # nothing ran between 20 minutes and 105 minutes
        times = list(run.samples.values_list("bucket", "sampled_at"))
        self.assertEqual([b for b, _ in times], [0, 1, 2, 10, 11, 12], "no sample exists for the downtime")
        self.assertEqual((run.state, run.result), (SS.COMPLETED, SRes.INCOMPLETE))
        self.assertIn("MAX_GAP", run.evaluation["problems"])
        self.assertEqual(run.evaluation["reason"], soak_codes.COVERAGE_INSUFFICIENT)

    def test_a_crash_between_reading_and_committing_loses_nothing_and_the_next_tick_finishes_it(self):
        self.start()
        world = self.world()
        sh.drive(world, start=T0, until=END - timedelta(seconds=300))
        with mock.patch.object(lifecycle, "finalize", side_effect=RuntimeError("process crashed")), self.assertLogs(lifecycle.log, logging.ERROR):
            report = sh.tick(END, world)
        self.assertEqual([r.action for r in report.runs], ["ERROR"])
        crashed = self.run_row()
        self.assertTrue(crashed.is_running, "a crashed collector never leaves a run falsely finished")
        self.assertEqual(crashed.samples.filter(bucket=12).count(), 0, "the interrupted unit of work rolled back as a whole")
        sh.tick(END + timedelta(seconds=30), world)
        run = self.run_row()
        self.assertEqual((run.state, run.result), (SS.COMPLETED, SRes.PASS))
        self.assertEqual(sorted(run.samples.values_list("bucket", flat=True)), list(range(0, 13)), "exactly one sample per interval, none duplicated")

    def test_a_clock_that_moves_backwards_or_starts_early_collects_nothing_and_fabricates_nothing(self):
        self.start()
        self.ticks([1200])
        for label, moment in (("earlier than recorded evidence", 900), ("before the soak started", -600)):
            with self.subTest(case=label):
                report = sh.tick(sh.at(moment), self.world())
                self.assertEqual([r.action for r in report.runs], ["CLOCK_ANOMALY"])
        self.assertEqual(list(self.run_row().samples.values_list("bucket", flat=True)), [2])

    def test_a_later_overlapping_execution_invalidates_the_soak_even_between_samples(self):
        self.start()
        self.ticks([0, 300])
        history_run(self.f.prob, ["R2"], outcome="UAT_SCOPE_APPLIED", mode="PARTIAL_UAT")
        report = sh.tick(sh.at(360), self.world())        # NOT a sample instant: the guard alone notices
        self.assertEqual([r.action for r in report.runs], ["FINALIZED"])
        run = self.run_row()
        self.assertEqual((run.state, run.result, run.terminal_reason), (SS.INVALIDATED, "", soak_codes.OVERLAPPING_EXECUTION))
        self.assertEqual(run.samples.count(), 1, "the earlier evidence is kept")
        self.assertEqual(run.evaluation["interference"], "DETECTED")
        self.assertTrue(models.AuditEvent.objects.filter(event_type="PROBATION_SOAK_INVALIDATED").exists())
        self.assertFalse(models.ProbationSoakRun.objects.filter(state=SS.RUNNING).exists(), "no lock or run is left behind")

    def test_a_non_overlapping_or_non_mutating_later_execution_does_not_invalidate(self):
        self.start()
        history_run(self.f.prob, ["R3", "R4"])
        history_run(self.f.prob, ["R1"], outcome="BLOCKED", after=120)
        self.ticks([0, 600, 1200])
        self.assertTrue(self.run_row().is_running)
        self.assertEqual(list(self.run_row().samples.values_list("result", flat=True)), [SR.PASS] * 3)

    def test_a_bundle_that_stops_verifying_invalidates_the_soak_and_is_never_repaired(self):
        self.start()
        self.ticks([0])
        bh.oob(models.ConfigurationBundle).filter(pk=self.f.prob.pk).update(payload_digest="0" * 64)
        sh.tick(sh.at(120), self.world())
        run = self.run_row()
        self.assertEqual((run.state, run.terminal_reason), (SS.INVALIDATED, soak_codes.BUNDLE_INTEGRITY_FAILED))
        self.assertEqual(models.ConfigurationBundle.objects.get(pk=self.f.prob.pk).payload_digest, "0" * 64, "the tampered bundle is reported, not repaired")

    def test_the_collector_reads_only_and_writes_only_evidence_audit_and_notifications(self):
        self.start()
        world = self.world()
        forbidden = AssertionError("the soak collector must never mutate a device, NetBox, Git or a bundle, or create a Golden bundle")
        before = bh.table_counts()
        from core.services.bundles import golden, persistence
        from core.services.execution import engine
        from core.services.execution.executors import registry

        with mock.patch.object(execution_service, "execute_change", side_effect=forbidden), mock.patch.object(engine, "execute_change", side_effect=forbidden), \
                mock.patch.object(registry, "executor_for", side_effect=forbidden), mock.patch.object(golden, "create_golden_bundle", side_effect=forbidden), \
                mock.patch.object(persistence, "seal_bundle", side_effect=forbidden), mock.patch("subprocess.run", side_effect=forbidden), \
                mock.patch("subprocess.Popen", side_effect=forbidden), mock.patch("socket.socket.connect", side_effect=forbidden), \
                mock.patch("netmiko.ConnectHandler", side_effect=forbidden):
            sh.drive(world, start=T0, until=END)
        self.assertTrue(self.run_row().is_technical_pass)
        touched = set(bh.count_changes(before, bh.table_counts()))
        self.assertEqual(touched, {"ProbationSoakSample", "AuditEvent", "Notification"}, "run rows are updated in place; nothing else is written")

    def test_notifications_mark_transitions_only_never_every_sample_and_a_failure_never_corrupts_state(self):
        self.start()
        sh.drive(self.world(), start=T0, until=END)
        events = list(models.Notification.objects.order_by("id").values_list("event_type", "severity"))
        self.assertEqual(events, [("SOAK_STARTED", "INFO"), ("SOAK_COMPLETE", "SUCCESS")], "started + ready for the decision; 13 samples produced no notification")
        self.assertTrue(self.run_row().is_technical_pass)
        with mock.patch.object(notification_service, "publish_event", side_effect=RuntimeError("slack is down")), self.assertLogs(lifecycle.log, logging.ERROR):
            second = ss.start_soak(self.f.prob, actor="tester", now=T0 + timedelta(days=2))
            self.assertTrue(second.created and second.run.is_running, "a notification failure never corrupts the soak")
            self.assertTrue(models.AuditEvent.objects.filter(object_id=second.run.soak_id).exists())

    def test_failed_incomplete_and_invalidated_soaks_notify_as_regressions(self):
        for label, action, event in (
            ("failure", lambda: self.ticks([0], self.world(break_r1=True)), "PROBATION_SOAK_FAILED"),
            ("invalidation", lambda: (self.ticks([0]), history_run(self.f.prob, ["R1"]), sh.tick(sh.at(60), self.world())), "PROBATION_SOAK_INVALIDATED"),
        ):
            with self.subTest(case=label), bh.rolled_back():
                self.start()
                action()
                self.assertTrue(models.AuditEvent.objects.filter(event_type=event).exists())
                self.assertEqual(models.Notification.objects.filter(event_type="SOAK_REGRESSION").count(), 1)
        with bh.rolled_back():
            self.start()
            self.ticks([0, 300, 600], self.world())
            self.ticks([7200])
            self.assertEqual((self.run_row().result, models.Notification.objects.filter(event_type="SOAK_REGRESSION", severity="WARNING").count()), (SRes.INCOMPLETE, 1))

    def test_cancelling_keeps_evidence_is_audited_and_can_never_be_resumed_or_promoted(self):
        self.start()
        self.ticks([0, 600])
        result = ss.cancel_soak(self.run_row(), actor="operator", now=sh.at(700))
        run = self.run_row()
        self.assertEqual((result.cancelled, run.state, run.result, run.ended_by, run.terminal_reason), (True, SS.CANCELLED, "", "operator", soak_codes.CANCELLED_BY_OPERATOR))
        self.assertEqual(run.samples.count(), 2)
        again = ss.cancel_soak(run, actor="operator", now=sh.at(800))
        self.assertEqual((again.cancelled, [b["code"] for b in again.blockers]), (False, ["NOT_RUNNING"]))
        self.assertEqual(sh.tick(sh.at(1200), self.world()).runs, [])
        self.assertFalse(ss.decide(run, decision="APPROVE", actor="operator", confirm=sh.confirm_of(run)).bundle)
        self.assertEqual(models.AuditEvent.objects.filter(event_type="PROBATION_SOAK_CANCELLED").count(), 1)
        self.assertEqual(models.Notification.objects.filter(event_type="SOAK_REGRESSION").count(), 0, "a cancellation is not a regression")


# =============================================================================================================================
SOAK_DIR = Path(__file__).resolve().parents[1] / "services" / "soak"
BANNED_IMPORTS = {"netmiko", "paramiko", "subprocess", "socket", "urllib", "http", "requests", "pynetbox", "git", "github", "influxdb", "influxdb_client", "docker",
                  "execution", "execution_service", "engine", "executors", "configlet_service", "netbox_ipam", "ipam_context", "nsot_live", "nsot_netbox", "nsot_git",
                  "ci_service", "raw_configlet_service", "sandbox", "verifier", "lifecycle_service", "change_plan_service", "change_validation_service"}
COLLECTOR_MODULES = ("assessment", "sampling", "evaluator", "lifecycle", "policy", "interference", "eligibility", "codes")


def imports_of(path: Path) -> set[str]:
    names: set[str] = set()
    for node in ast.walk(ast.parse(path.read_text())):
        if isinstance(node, ast.Import):
            names.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                names.update(node.module.split("."))
            names.update(alias.name for alias in node.names)
    return names


class SoakBoundaryContractTests(SimpleTestCase):
    def test_the_collector_side_imports_no_device_network_shell_engine_or_golden_module(self):
        for name in COLLECTOR_MODULES:
            with self.subTest(module=name):
                found = imports_of(SOAK_DIR / f"{name}.py")
                self.assertEqual(found & BANNED_IMPORTS, set())
                self.assertNotIn("golden", found)
                self.assertNotIn("decision", found, "the collector never imports the operator-decision module")

    def test_no_soak_module_names_the_engine_entry_point_a_golden_creation_call_or_a_persistence_command(self):
        engine_name = "execute_" + "change"
        for path in sorted(SOAK_DIR.glob("*.py")):
            source = path.read_text()
            code = "\n".join(line for line in source.splitlines() if not line.lstrip().startswith(("#", '"""')))
            with self.subTest(module=path.name):
                self.assertNotIn(engine_name, source)
                for token in ("write memory", "copy running", "startup-config", "send_config", "shell=True", "subprocess", "os.system", "eval(", "exec(", "containerlab", "master.py"):
                    self.assertNotIn(token, code.replace("startup-config persistence", ""), token)
                if path.stem != "decision":
                    self.assertNotIn("create_golden_bundle", source)
                    self.assertNotIn("seal_bundle", source)
                    self.assertNotIn("GoldenDecision.objects.create", source)

    def test_the_scheduler_commands_call_only_the_soak_service_and_the_probe_persists_nothing(self):
        commands = Path(__file__).resolve().parents[1] / "management" / "commands"
        tick = imports_of(commands / "probation_soak_tick.py")
        self.assertEqual(tick & (BANNED_IMPORTS | {"golden", "decision", "bundle_service"}), set())
        probe = (commands / "probation_soak_probe.py").read_text()
        self.assertNotIn(".save(", probe)
        self.assertNotIn("objects.create", probe)
        self.assertNotIn("start_soak", probe)
        self.assertEqual(imports_of(commands / "probation_soak_probe.py") & BANNED_IMPORTS, set())

    def test_soak_code_only_writes_its_own_rows_audit_and_notifications_and_never_a_bundle_or_netbox_row(self):
        created = set()
        for path in sorted(SOAK_DIR.glob("*.py")):
            source = path.read_text()
            created.update(re.findall(r"models\.(\w+)\.objects\.create\(", source))
            created.update(re.findall(r"models\.(ProbationSoak\w+|GoldenDecision)\(", source))
            writes = re.compile(r"(\b(client|nb|netbox|pynetbox|endpoint|api)\b[\w\.\[\]\"']*\.(create|update|delete|save|post|put|patch)\("
                                r"|\bnb\.(dcim|ipam)\b|\b(reconcile_object|ensure_tag|ensure_custom_field|ensure_interface_mac)\()")
            self.assertIsNone(writes.search(source), path.name)
        self.assertEqual(created, {"AuditEvent", "GoldenDecision", "ProbationSoakRun", "ProbationSoakSample"})


class DocumentationTests(SimpleTestCase):
    def test_the_soak_document_states_the_real_duration_the_no_auto_promotion_rule_the_limitations_and_the_20b_runbook(self):
        text = (Path(settings.REPO_ROOT) / "docs" / "PROBATION_SOAK_AND_PROMOTION.md").read_text()
        for phrase in ("168 elapsed hours", "604 800 s", "There is no automatic promotion", "NOT A PRODUCTION DURATION", "never a PASS", "probation_soak_tick",
                       "Startup-config persistence is NOT implemented", "Checkpoint 4 is not created", "Phase-20B operational runbook", "never alter timestamps",
                       "consecutive_samples", "recent_event_window_seconds", "`INVALIDATED`", "Golden is not byte-identical", "GitHub Actions is **not** a scheduler",
                       "master.py --snmp-only", "PROMOTION_MISMATCH", "verify_export"):
            with self.subTest(phrase=phrase):
                self.assertIn(phrase, text)
        bundles_doc = (Path(settings.REPO_ROOT) / "docs" / "IMMUTABLE_CONFIGURATION_BUNDLES.md").read_text()
        self.assertIn("Phase-20 extension", bundles_doc)
        self.assertIn("lineage.promotion", bundles_doc)
