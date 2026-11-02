"""Lab 7 closure -- the Phase-20 probation soak lifecycle, each remaining entry point called directly on a REAL Probation bundle.

``soak.lifecycle`` (ids, lookup, audit, notifications, finalisation, progress, reports), ``soak_service`` read models, ``soak.eligibility``,
``soak.overview``, ``soak.config_state``, ``soak.sampling``, ``soak.assessment``, ``soak.baseline`` and ``soak.interference``.

Hermetic: the shared ``SoakFixture`` (a real Probation bundle built by the production Phase-17/19 engine on the simulated network); every
device configuration read is the ``test_soak_baseline.configs`` fake; Slack is never configured; the clock is explicit (``sh.T0``).  No device,
NetBox, Slack or socket is reached.  POSITIVE: exact ids, rows, audit / notification records, digests, statistics.  NEGATIVE: malformed ids
and unknown runs resolve to nothing, secret-shaped audit keys and non-terminal verdicts are refused (nothing persisted), a failed delivery
never raises, unmanaged / unreadable devices are UNAVAILABLE, drift invalidates a sample, interference and integrity failures are reported.
"""
from __future__ import annotations

from datetime import timedelta
from types import SimpleNamespace
from unittest import mock

from django.db import transaction
from django.test import override_settings

from core import models
from core.services import notification_service, soak_service as ss
from core.services.soak import (assessment, baseline as baseline_module, codes, config_state, eligibility, evaluator, interference, lifecycle,
                                overview, sampling)
from core.services.soak.policy import SoakPolicy
from core.tests.helpers import health as h, soak as sh
from core.tests.test_soak_baseline import configs, healthy

State, Result = models.SoakState, models.SoakResult
T0 = sh.T0


@override_settings(PROBATION_SOAK_REQUIRE_BASELINE_DIGEST=True)
class SoakLifecycleClosureTests(sh.SoakFixture):
    def begin(self, now=T0):
        with configs(healthy()), sh.simulated(self.f.world):
            result = ss.start_soak(self.f.prob, actor="operator", now=now, snapshot=h.snapshot(now=now))
        self.assertIsNotNone(result.run, [b["code"] for b in result.blockers])
        self.f.run = result.run
        return result.run

    # --- ids and lookup -------------------------------------------------------------------------------------------------------
    def test_parse_soak_id_returns_the_primary_key(self):
        self.assertEqual((lifecycle.parse_soak_id("SOAK-000042"), lifecycle.parse_soak_id("SOAK-1234567")), (42, 1234567))

    def test_parse_soak_id_of_invalid_values_is_none(self):
        for value in ("SOAK-42", "soak-000042", "SOAK-000042 ", "", None, "LBR-000001"):
            with self.subTest("invalid " + repr(value)):
                self.assertIsNone(lifecycle.parse_soak_id(value))

    def test_get_run_returns_the_persisted_run(self):
        run = self.begin()
        self.assertEqual(lifecycle.get_run(run.soak_id).pk, run.pk)

    def test_get_run_of_unknown_or_malformed_ids_is_none(self):
        self.begin()
        for value in ("SOAK-999999", "garbage", ""):
            with self.subTest("unknown " + repr(value)):
                self.assertIsNone(lifecycle.get_run(value))

    # --- audit / notifications ------------------------------------------------------------------------------------------------
    def test_audit_event_records_one_event_with_run_metadata(self):
        run = self.begin()
        before = models.AuditEvent.objects.count()
        lifecycle.audit_event(models.AuditEventType.PROBATION_SOAK_STARTED, run, actor="operator", summary="closure check", extra={"bucket": 3})
        event = models.AuditEvent.objects.order_by("-id").first()
        self.assertEqual(models.AuditEvent.objects.count(), before + 1)
        self.assertEqual((event.object_id, event.actor, event.summary), (run.soak_id, "operator", f"{run.bundle.change.change_id}: closure check"))
        self.assertEqual((event.metadata["bundle_digest"], event.metadata["bucket"]), (run.bundle_digest, 3))

    def test_audit_event_refuses_secret_shaped_metadata_keys(self):
        run = self.begin()
        before = models.AuditEvent.objects.count()
        with self.assertRaises(ValueError):
            lifecycle.audit_event(models.AuditEventType.PROBATION_SOAK_STARTED, run, actor="operator", summary="x", extra={"password": "hunter2"})
        self.assertEqual(models.AuditEvent.objects.count(), before)

    def test_note_for_returns_a_correlated_note(self):
        run = self.begin()
        note = lifecycle.note_for(run, models.Notification.EventType.SOAK_STARTED, models.Notification.Severity.INFO, "t", "m", "started", extra="1")
        self.assertEqual((note.correlation, note.change_id, note.metadata),
                         (f"SOAK:{run.soak_id}:started", run.bundle.change.change_id, {"soak_id": run.soak_id, "bundle_id": run.bundle.bundle_id, "extra": "1"}))

    def test_note_for_a_run_without_a_bundle_raises(self):
        with self.assertRaises(AttributeError):
            lifecycle.note_for(SimpleNamespace(soak_id="SOAK-000001"), "E", "INFO", "t", "m", "x")

    def test_publish_persists_each_note_through_the_notification_service(self):
        run = self.begin()
        before = models.Notification.objects.count()
        note = lifecycle.note_for(run, models.Notification.EventType.SOAK_STARTED, models.Notification.Severity.INFO, "Started", "body", "closure")
        self.assertIsNone(lifecycle.publish([note]))
        self.assertEqual(models.Notification.objects.count(), before + 1)
        self.assertEqual(models.Notification.objects.order_by("-id").first().title, "Started")

    def test_publish_with_a_failing_delivery_never_raises(self):
        note = lifecycle.Note("E", "INFO", "t", "m", "SOAK:x:y", "CHG-1")
        with mock.patch.object(notification_service, "publish_event", side_effect=RuntimeError("slack down")), \
                self.assertLogs("core.services.soak.lifecycle", level="ERROR") as logs:
            self.assertIsNone(lifecycle.publish([note, note]))
        self.assertEqual(len(logs.records), 2)

    # --- finalisation, progress and reports ----------------------------------------------------------------------------------
    def test_finalize_records_state_evidence_audit_and_one_note(self):
        run = self.begin()
        policy = SoakPolicy.from_dict(run.policy)
        verdict = evaluator.Verdict(State.COMPLETED, Result.PASS, codes.TECHNICAL_PASS, stats=evaluator.statistics(policy, run.started_at, run.required_end_at, []))
        notes = []
        with transaction.atomic():
            locked = models.ProbationSoakRun.objects.select_for_update().select_related("bundle__change").get(pk=run.pk)
            self.assertIsNone(lifecycle.finalize(locked, policy, [], verdict, sh.END, actor="tester", notes=notes))
        run.refresh_from_db()
        self.assertEqual((run.state, run.result, run.terminal_reason, run.finished_at, run.ended_by), (State.COMPLETED, Result.PASS, codes.TECHNICAL_PASS, sh.END, "tester"))
        self.assertEqual(run.evidence_digest, evaluator.evidence_digest(run.evaluation))
        self.assertEqual([n.correlation for n in notes], [f"SOAK:{run.soak_id}:ready"])
        self.assertTrue(models.AuditEvent.objects.filter(object_id=run.soak_id, event_type=models.AuditEventType.PROBATION_SOAK_READY).exists())

    def test_finalize_refuses_a_non_terminal_verdict_and_persists_nothing(self):
        run = self.begin()
        policy = SoakPolicy.from_dict(run.policy)
        with self.assertRaisesRegex(ValueError, "A running soak has no result, reason or finish time yet"):   # the model refuses the save
            with transaction.atomic():
                locked = models.ProbationSoakRun.objects.select_for_update().select_related("bundle__change").get(pk=run.pk)
                lifecycle.finalize(locked, policy, [], evaluator.Verdict(State.RUNNING), sh.END, actor="tester", notes=[])
        run.refresh_from_db()
        self.assertEqual((run.state, run.evidence_digest), (State.RUNNING, ""))

    def test_progress_returns_server_side_elapsed_and_remaining(self):
        run = self.begin()
        result = lifecycle.progress(run, now=T0 + timedelta(seconds=1800))
        self.assertEqual((result["elapsed_seconds"], result["remaining_seconds"], result["percent_elapsed"], result["latest"]), (1800, 5400, 25.0, None))

    def test_run_and_tick_reports_return_compact_dicts(self):
        report = lifecycle.RunReport("SOAK-000001", "SAMPLED", bucket=0, sample_result="PASS")
        self.assertEqual(report.to_dict(), {"soak_id": "SOAK-000001", "action": "SAMPLED", "bucket": 0, "sample_result": "PASS"})
        self.assertEqual(lifecycle.TickReport(now=T0, runs=[report]).to_dict(),
                         {"now": "2026-09-21T12:00:00Z", "dry_run": False, "runs": [report.to_dict()]})

    # --- service read models / eligibility / overview ------------------------------------------------------------------------
    def test_list_runs_and_active_run_return_the_running_soak(self):
        run = self.begin()
        self.assertEqual([r.pk for r in ss.list_runs(bundle=self.f.prob)], [run.pk])
        self.assertEqual([r.pk for r in ss.list_runs(limit=5)], [run.pk])
        self.assertEqual(eligibility.active_run(self.f.prob).pk, run.pk)

    def test_list_runs_and_active_run_of_a_bundle_without_soaks_are_empty(self):
        self.assertEqual((ss.list_runs(bundle=self.f.uat), eligibility.active_run(self.f.prob), ss.list_runs(limit=0)), ([], None, []))

    def test_decision_of_an_approved_run_returns_the_golden_decision(self):
        run = self.begin()
        with configs(healthy()):
            sh.drive(self.f.world, start=T0, until=sh.END + timedelta(seconds=sh.INTERVAL))
        run.refresh_from_db()
        self.assertTrue(run.is_technical_pass, (run.state, run.result, run.terminal_reason))
        with configs(healthy()), sh.simulated(self.f.world):
            outcome = ss.decide(run, decision="APPROVE", actor="operator", confirm=sh.confirm_of(run), now=run.finished_at)
        decision = ss.decision_of(run)
        self.assertEqual((decision.decision, decision.golden_bundle.pk), ("APPROVE", outcome.bundle.pk))

    def test_decision_of_an_undecided_run_is_none(self):
        run = self.begin()
        self.assertIsNone(ss.decision_of(run))

    def test_collector_status_of_an_unsampled_old_run_is_stale(self):
        run = self.begin()
        policy = SoakPolicy.from_dict(run.policy)
        status = overview.collector_status(run, None, policy, T0 + timedelta(seconds=3 * policy.sample_interval_seconds))
        self.assertEqual((status["state"], status["last_sample_at"], status["age_seconds"]), (overview.STALE, None, 1800))

    def test_overview_with_no_soak_running_is_empty(self):
        result = overview.overview(now=T0)
        self.assertEqual((result["active"], result["awaiting_decision"], result["finished"]), ([], [], []))

    # --- configuration state ---------------------------------------------------------------------------------------------------
    def test_read_device_and_read_return_per_section_digests(self):
        with configs(healthy()):
            one = config_state.read_device("R1", now=T0)
            both = config_state.read(["R2", "R1"], now=T0)
        self.assertEqual((one["state"], one["error"], one["read_at"]), (config_state.OK, "", "2026-09-21T12:00:00Z"))
        self.assertRegex(one["digest"], r"^[0-9a-f]{64}$")
        self.assertEqual(list(both), ["R1", "R2"])
        self.assertEqual(both["R1"]["digest"], one["digest"])

    def test_read_device_and_read_of_unmanaged_or_unreachable_devices_are_unavailable(self):
        with configs({"R2": {}}):
            unmanaged = config_state.read_device("R9", now=T0)
            unreachable = config_state.read(["R1"], now=T0)["R1"]
        self.assertEqual((unmanaged["state"], unmanaged["error"]), (config_state.UNAVAILABLE, "NOT_MANAGED"))
        self.assertEqual((unreachable["state"], unreachable["digest"]), (config_state.UNAVAILABLE, ""))
        self.assertIn("CONNECTION_FAILED", unreachable["error"])

    def test_compare_of_an_unreadable_device_is_unavailable_never_match(self):
        pinned = {"R1": {"digest": "a" * 64, "sections": {"running-config": "1"}}}
        result = config_state.compare(pinned, {"R1": {"state": config_state.UNAVAILABLE, "error": "CONNECTION_FAILED"}})
        self.assertEqual(result["R1"], {"state": config_state.UNAVAILABLE, "baseline": "a" * 64, "current": "", "changed_sections": [],
                                        "error": "CONNECTION_FAILED"})

    # --- sampling / assessment ------------------------------------------------------------------------------------------------
    def test_guard_returns_an_intact_uninterfered_guard(self):
        checked = sampling.guard(self.f.prob)
        self.assertEqual((checked.integrity_ok, checked.interference, checked.ok), (True, [], True))

    def test_guard_and_collect_with_a_later_overlapping_execution_invalidate(self):
        sh.history_run(self.f.prob, ["R1"], outcome=models.ExecutionOutcome.SUCCEEDED)
        checked = sampling.guard(self.f.prob)
        self.assertFalse(checked.ok)
        sample = sampling.collect(self.f.prob, now=T0, guard_result=checked)
        self.assertEqual((sample.result, sample.interference[0]["devices"]), (models.SoakSampleResult.INVALIDATED, ["R1"]))
        self.assertEqual(sample.findings[0]["check_code"], "OVERLAPPING_EXECUTION")

    def test_invalidated_returns_one_finding_per_cause(self):
        sample = assessment.invalidated(integrity_ok=False, interference=[{"run_id": "r", "change_id": "c", "outcome": "SUCCEEDED", "devices": ["R1"],
                                                                           "mode": "COMPLETE"}], integrity_codes=["ITEMS_MISMATCH"])
        self.assertEqual([f["check_code"] for f in sample.findings], ["BUNDLE_INTEGRITY_FAILED", "OVERLAPPING_EXECUTION"])
        self.assertEqual((sample.counts, "mode" in sample.findings[1]["detail"]), ({"invalidating": 2}, False))

    def test_apply_config_state_keeps_a_matching_sample_and_records_the_comparison(self):
        sample = assessment.SampleAssessment(result=models.SoakSampleResult.PASS, counts={})
        result = assessment.apply_config_state(sample, {"R1": {"state": "MATCH", "changed_sections": []}})
        self.assertEqual((result.result, result.config_drift, result.evidence["config"]["R1"]["state"]), (models.SoakSampleResult.PASS, False, "MATCH"))
        self.assertIs(assessment.apply_config_state(sample, {}), sample)

    def test_apply_config_state_invalidates_drift_and_never_passes_unreadable_devices(self):
        with self.subTest("refused drift"):
            drift = assessment.apply_config_state(assessment.SampleAssessment(result=models.SoakSampleResult.PASS, counts={}),
                                                  {"R1": {"state": "DRIFT", "changed_sections": ["running-config"]}})
        self.assertEqual((drift.result, drift.config_drift, drift.counts["invalidating"]), (models.SoakSampleResult.INVALIDATED, True, 1))
        with self.subTest("refused unreadable"):
            unreadable = assessment.apply_config_state(assessment.SampleAssessment(result=models.SoakSampleResult.PASS, counts={}),
                                                       {"R2": {"state": "UNAVAILABLE", "changed_sections": []}})
        self.assertNotEqual(unreadable.result, models.SoakSampleResult.PASS)
        self.assertEqual(unreadable.findings[-1]["check_code"], "CONFIG_READ_UNAVAILABLE")

    # --- baseline -------------------------------------------------------------------------------------------------------------
    def test_build_and_digest_return_the_pinned_start_document(self):
        policy = ss.current_policy()
        document = baseline_module.build(self.f.prob, policy=policy, started_at=T0, required_end_at=sh.END, device_digests={"R1": {"digest": "d"}},
                                         actor="operator")
        self.assertEqual((document["probation"]["bundle_id"], document["devices"], document["health"], document["topology"]),
                         (self.f.prob.bundle_id, {"R1": {"digest": "d"}}, None, None))
        self.assertEqual(document["window"], {"started_at": "2026-09-21T12:00:00Z", "required_end_at": evaluator.iso(sh.END)})
        self.assertEqual(baseline_module.digest(document), baseline_module.digest(dict(reversed(list(document.items())))))

    def test_build_of_a_bundle_without_lineage_raises_and_a_tampered_digest_differs(self):
        with self.assertRaises(AttributeError):
            baseline_module.build(SimpleNamespace(source_uat=None, parent=None), policy=ss.current_policy(), started_at=T0, required_end_at=sh.END,
                                  device_digests={})
        with self.subTest("refused tampered baseline"):
            self.assertNotEqual(baseline_module.digest({"devices": {"R1": "a"}}), baseline_module.digest({"devices": {"R1": "b"}}))

    def test_repository_head_returns_a_commit_sha_or_empty(self):
        self.assertRegex(baseline_module.repository_head(), r"^([0-9a-f]{40})?$")

    # --- interference ---------------------------------------------------------------------------------------------------------
    def test_bundle_devices_and_find_interference_return_overlapping_later_runs(self):
        self.assertEqual(interference.bundle_devices(self.f.prob), ["R1", "R2"])
        sh.history_run(self.f.prob, ["R2", "R7"], state="RUNNING")
        found = interference.find_interference(self.f.prob)
        self.assertEqual([(f["devices"], f["outcome"]) for f in found], [(["R2"], "RUNNING")])

    def test_bundle_devices_and_find_interference_ignore_non_mutating_or_unrelated_runs(self):
        sh.history_run(self.f.prob, ["R1"], outcome=models.ExecutionOutcome.BLOCKED)
        sh.history_run(self.f.prob, ["R9"])
        with self.subTest("none for non-mutating or unrelated runs"):
            self.assertEqual(interference.bundle_devices(SimpleNamespace(payload={})), [])
            self.assertEqual(interference.find_interference(self.f.prob), [])
