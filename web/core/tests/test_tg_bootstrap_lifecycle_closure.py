"""Lab 7 closure -- the one-time legacy bootstrap: ``bootstrap.lifecycle``, ``bootstrap.capture``, ``bootstrap.evidence``,
``bootstrap.interference`` and ``bootstrap.baseline.active_run``, each remaining entry point called directly.

Hermetic: the candidate is a REAL capture of the simulated ``helpers.bootstrap.World`` (every managed device answers the production read-only
sessions with canned output, including secret-bearing running configurations); the clock is the controlled ``bh.T0`` timeline; the driver's
``sleep`` / ``clock`` are injected; Slack is never configured.  No device, NetBox, Slack or socket is reached.  POSITIVE: exact ids, rows,
transports, sanitized sections, payloads, comparisons, requirements, verdicts.  NEGATIVE: malformed / unknown ids resolve to nothing, a
non-legacy candidate cannot start, secret-shaped audit keys and non-terminal verdicts are refused, unreadable / unsupported devices are
UNAVAILABLE (never MATCH), drift and lost links are failures, overlapping executions are interference, secrets are never stored.
"""
from __future__ import annotations

from datetime import timedelta
from types import SimpleNamespace
from unittest import mock

from django.db import transaction
from django.test import TestCase

from core import models
from core.services import bootstrap_service as bs, notification_service, slack_service
from core.services.bootstrap import baseline, capture, codes, evaluator, evidence, interference, lifecycle
from core.services.health.codes import CheckStatus as S
from core.services.health.evidence import DeviceEvidence
from core.services.soak.policy import SoakPolicy
from core.tests.helpers import bootstrap as bh, soak as sh

State, Result = models.SoakState, models.SoakResult
T0, END = bh.T0, bh.END
CEOS = {"name": "R1", "platform": "ceos", "address": "192.168.200.11"}


class BootstrapBase(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.candidate, cls.world = bh.candidate_of()

    def setUp(self):
        patcher = mock.patch.object(slack_service, "is_configured", return_value=False)
        patcher.start()
        self.addCleanup(patcher.stop)

    def begin(self, now=T0):
        result = bs.start_bootstrap(self.candidate, actor="operator", now=now)
        self.assertIsNotNone(result.run, [b["code"] for b in result.blockers])
        return result.run

    def history(self, devices, *, outcome="SUCCEEDED", state="FINISHED", when=None):
        if not hasattr(self, "_probation"):      # per test: the class-level rows roll back with each test
            self._probation = sh.probation()
        fixture = self._probation
        when = when or T0 + timedelta(seconds=400)
        return models.ChangeExecutionRun.objects.create(
            change=fixture.prob.change, plan=fixture.prob.plan, validation_run=fixture.prob.validation_run, mode="COMPLETE", state=state,
            outcome=outcome if state == "FINISHED" else "", engine_version="t", plan_hash="0" * 64, validation_input_hash="0" * 64,
            validation_source_hash="0" * 64, devices=list(devices), started_at=when, finished_at=when + timedelta(seconds=30) if state == "FINISHED" else None,
            lease_expires_at=when + timedelta(seconds=1800))


class LifecycleTests(BootstrapBase):
    def test_parse_run_id_returns_the_primary_key(self):
        self.assertEqual(lifecycle.parse_run_id("BOOT-000007"), 7)

    def test_parse_run_id_of_invalid_values_is_none(self):
        for value in ("BOOT-7", "SOAK-000007", "", None, "boot-000007"):
            with self.subTest("invalid " + repr(value)):
                self.assertIsNone(lifecycle.parse_run_id(value))

    def test_get_run_list_runs_and_active_run_return_the_running_observation(self):
        run = self.begin()
        self.assertEqual((lifecycle.get_run(run.run_id).pk, [r.pk for r in lifecycle.list_runs(limit=5)], baseline.active_run().pk), (run.pk, [run.pk], run.pk))

    def test_get_run_list_runs_and_decision_of_with_no_observation_are_none_or_empty(self):
        self.assertEqual((lifecycle.get_run("BOOT-999999"), lifecycle.get_run("nonsense"), lifecycle.list_runs(), lifecycle.list_runs(limit=0)),
                         (None, None, [], []))
        run = self.begin()
        self.assertIsNone(lifecycle.decision_of(run))

    def test_audit_event_records_the_legacy_provenance(self):
        run = self.begin()
        lifecycle.audit_event(models.AuditEventType.LEGACY_BOOTSTRAP_STARTED, run, actor="operator", summary="closure", extra={"bucket": 1})
        event = models.AuditEvent.objects.order_by("-id").first()
        self.assertEqual((event.object_id, event.summary, event.change_id), (run.run_id, "legacy bootstrap: closure", None))
        self.assertEqual((event.metadata["provenance_type"], event.metadata["bucket"]), ("LEGACY_BOOTSTRAP", 1))

    def test_audit_event_refuses_secret_shaped_keys(self):
        run = self.begin()
        before = models.AuditEvent.objects.count()
        with self.assertRaises(ValueError):
            lifecycle.audit_event(models.AuditEventType.LEGACY_BOOTSTRAP_STARTED, run, actor="operator", summary="x", extra={"token": "abc"})
        self.assertEqual(models.AuditEvent.objects.count(), before)

    def test_note_for_and_publish_persist_one_notification(self):
        run = self.begin()
        before = models.Notification.objects.count()
        note = lifecycle.note_for(run, models.Notification.EventType.SOAK_STARTED, models.Notification.Severity.INFO, "Observation", "m", "closure", k="v")
        self.assertEqual((note.correlation, note.metadata), (f"BOOT:{run.run_id}:closure", {"run_id": run.run_id, "candidate_bundle_id": self.candidate.bundle_id,
                                                                                          "k": "v"}))
        self.assertIsNone(lifecycle.publish([note]))
        self.assertEqual(models.Notification.objects.count(), before + 1)

    def test_note_for_without_a_candidate_raises_and_publish_failures_never_raise(self):
        with self.assertRaises(AttributeError):
            lifecycle.note_for(SimpleNamespace(run_id="BOOT-000001"), "E", "INFO", "t", "m", "x")
        with mock.patch.object(notification_service, "publish_event", side_effect=RuntimeError("down")), \
                self.assertLogs("core.services.bootstrap.lifecycle", level="ERROR"), self.subTest("never raises"):
            self.assertIsNone(lifecycle.publish([lifecycle.Note("E", "INFO", "t", "m", "BOOT:x")]))

    def test_check_start_returns_no_blockers_for_a_fresh_intact_candidate(self):
        blockers, report = lifecycle.check_start(self.candidate, now=T0 + timedelta(seconds=10))
        self.assertEqual((blockers, report.ok), ([], True))

    def test_check_start_refuses_non_legacy_stale_or_interfered_candidates(self):
        probation = sh.probation().prob
        with self.subTest("refused non-legacy"):
            blockers, report = lifecycle.check_start(probation, now=T0)
            self.assertEqual(([b["code"] for b in blockers], report), (["CANDIDATE_NOT_LEGACY"], None))
        with self.subTest("refused stale"):
            blockers, _ = lifecycle.check_start(self.candidate, now=T0 + timedelta(days=30))
            self.assertIn("CANDIDATE_STALE", [b["code"] for b in blockers])
        self.history(["R1"], when=T0 + timedelta(seconds=5))
        with self.subTest("refused interfered"):
            blockers, _ = lifecycle.check_start(self.candidate, now=T0 + timedelta(seconds=10))
            self.assertIn("CANDIDATE_INTERFERED", [b["code"] for b in blockers])

    def test_finalize_records_a_cancelled_run_once(self):
        run = self.begin()
        pinned = SoakPolicy.from_dict(run.policy)
        verdict = evaluator.Verdict(State.CANCELLED, reason=codes.CANCELLED_BY_OPERATOR, stats=evaluator.statistics(pinned, run.started_at, run.required_end_at, []))
        notes = []
        with transaction.atomic():
            locked = models.LegacyBootstrapRun.objects.select_for_update().select_related("candidate").get(pk=run.pk)
            self.assertIsNone(lifecycle.finalize(locked, pinned, [], verdict, T0 + timedelta(seconds=60), actor="operator", notes=notes))
        run.refresh_from_db()
        self.assertEqual((run.state, run.terminal_reason, run.ended_by), (State.CANCELLED, codes.CANCELLED_BY_OPERATOR, "operator"))
        self.assertEqual((notes, run.evidence_digest), ([], evaluator.evidence_digest(run.evaluation)))

    def test_finalize_refuses_a_non_terminal_verdict_and_persists_nothing(self):
        run = self.begin()
        pinned = SoakPolicy.from_dict(run.policy)
        with self.assertRaises((ValueError, KeyError)):
            with transaction.atomic():
                locked = models.LegacyBootstrapRun.objects.select_for_update().select_related("candidate").get(pk=run.pk)
                lifecycle.finalize(locked, pinned, [], evaluator.Verdict(State.RUNNING), END, actor="operator", notes=[])
        run.refresh_from_db()
        self.assertEqual((run.state, run.evidence_digest), (State.RUNNING, ""))

    def test_cancel_bootstrap_cancels_the_running_observation(self):
        run = self.begin()
        result = lifecycle.cancel_bootstrap(run, actor="operator", now=T0 + timedelta(seconds=90))
        self.assertTrue(result.cancelled)
        self.assertEqual((result.run.state, result.run.terminal_reason, result.run.finished_at), (State.CANCELLED, codes.CANCELLED_BY_OPERATOR,
                                                                                                  T0 + timedelta(seconds=90)))

    def test_next_wake_returns_seconds_to_the_next_boundary(self):
        run = self.begin()
        self.assertEqual((lifecycle.next_wake(run, now=T0 + timedelta(seconds=10)), lifecycle.next_wake(run, now=T0 + timedelta(seconds=1700))), (290.0, 100.0))

    def test_next_wake_after_the_required_end_is_zero_never_negative(self):
        run = self.begin()
        self.assertEqual(lifecycle.next_wake(run, now=END + timedelta(seconds=999)), 0.0)

    def test_drive_ticks_and_waits_until_the_observation_completes(self):
        run = self.begin()
        clock = {"now": T0}
        sleeps, lines = [], []

        def sleep(seconds):
            sleeps.append(seconds)
            clock["now"] += timedelta(seconds=seconds)

        finished = lifecycle.drive(run, snapshot_fn=lambda: bh.snapshot(clock["now"]), session_factory=self.world.factory, dhcp_state=bh.DHCP,
                                   sleep=sleep, clock=lambda: clock["now"], emit=lines.append)
        self.assertEqual((finished.state, finished.result), (State.COMPLETED, Result.PASS))
        self.assertEqual(finished.samples.count(), 7)
        self.assertTrue(all(0 < s <= 15.0 for s in sleeps))
        self.assertTrue(any("FINALIZED" in line for line in lines))

    def test_progress_returns_server_side_elapsed(self):
        run = self.begin()
        result = lifecycle.progress(run, now=T0 + timedelta(seconds=450))
        self.assertEqual((result["elapsed_seconds"], result["remaining_seconds"], result["percent_elapsed"], result["samples"]), (450, 1350, 25.0, []))

    def test_progress_of_a_run_missing_its_pinned_policy_raises(self):
        with self.assertRaises(KeyError):
            lifecycle.progress(SimpleNamespace(policy={}), now=T0)

    def test_run_and_tick_reports_return_compact_dicts(self):
        report = lifecycle.RunReport("BOOT-000001", "NOT_DUE", bucket=2)
        self.assertEqual(lifecycle.TickReport(now=T0, dry_run=True, runs=[report]).to_dict(),
                         {"now": "2035-03-01T12:00:00Z", "dry_run": True, "runs": [{"run_id": "BOOT-000001", "action": "NOT_DUE", "bucket": 2}]})
        self.assertEqual(lifecycle.RunReport("BOOT-000002", "FINALIZED", bucket=0, result="PASS").to_dict(),
                         {"run_id": "BOOT-000002", "action": "FINALIZED", "bucket": 0, "result": "PASS"})  # 0 is kept, blanks dropped


class CaptureTests(BootstrapBase):
    def test_transport_and_credential_ref_follow_the_session_rule(self):
        docker = {"name": "R5", "platform": "ceos", "container": "clab-R5"}
        linux = {"name": "R3", "platform": "linux"}
        self.assertEqual((capture.transport_of(CEOS), capture.transport_of(docker), capture.transport_of(linux)),
                         (capture.TRANSPORT["ceos"], capture.TRANSPORT_DOCKER_CLI, capture.TRANSPORT["linux"]))
        self.assertEqual((capture.credential_ref_of(CEOS), capture.credential_ref_of(docker), capture.credential_ref_of(linux)),
                         ("inventory.yml#ceos_credentials", "none (docker exec)", "none (docker exec)"))

    def test_transport_credential_and_raw_keys_of_an_unsupported_platform_are_empty(self):
        junos = {"name": "X", "platform": "junos"}
        self.assertEqual((capture.transport_of(junos), capture.credential_ref_of(junos), capture.raw_keys("junos")), ("NOT_SUPPORTED", "", ()))

    def test_raw_keys_and_device_read_name_return_the_platform_reads(self):
        self.assertIn("running_config", capture.raw_keys("ceos"))
        self.assertIn("frr_config", capture.raw_keys("linux"))
        self.assertEqual(capture.DeviceRead(CEOS, DeviceEvidence(device="R1")).name, "R1")

    def reads(self, world=None):
        world = world or self.world
        return capture.read_all(capture.managed_scope(), session_factory=world.factory, now=T0)

    def test_read_all_of_an_unreachable_device_records_its_error(self):
        world = bh.World()
        world.take_down("R1")
        reads = self.reads(world)
        self.assertEqual(reads["R1"].evidence.live_error, "CONNECTION_FAILED")
        self.assertEqual(sorted(reads), sorted(capture.managed_scope()))

    def test_sanitize_sections_returns_redacted_sections(self):
        sections, problems = capture.sanitize_sections(self.reads()["R1"])
        self.assertEqual(problems, [])
        text = "".join(s["sanitized"] for s in sections)
        for secret in bh.SECRETS:
            self.assertNotIn(secret, text)
        self.assertTrue(all(s["sha256"] and s["redacted_lines"] >= 0 for s in sections))

    def test_sanitize_sections_of_a_missing_or_empty_section_is_a_problem(self):
        read = self.reads()["R1"]
        missing = capture.DeviceRead(read.device, read.evidence, {}, {"running_config": "COMMAND_FAILED"}, T0)
        empty = capture.DeviceRead(read.device, read.evidence, dict(read.raw, running_config="! only a comment\n"), {}, T0)
        self.assertEqual(capture.sanitize_sections(missing), ([], ["R1:running-config:COMMAND_FAILED"]))
        self.assertEqual(capture.sanitize_sections(empty)[1], ["R1:running-config:EMPTY"])

    def test_topology_facts_returns_sorted_nodes_and_edges(self):
        facts = capture.topology_facts(bh.snapshot(T0))
        self.assertEqual(facts["nodes"], sorted(facts["nodes"]))
        self.assertTrue(facts["edges"] and all(e["status"] == "UP" for e in facts["edges"]))

    def test_topology_facts_of_an_unavailable_snapshot_is_none(self):
        self.assertEqual((capture.topology_facts(None), capture.topology_facts(SimpleNamespace(available=False))), (None, None))

    def test_build_payload_refuses_an_incomplete_capture(self):
        world = bh.World()
        world.take_down("R2")
        payload, problems = capture.build_payload(self.reads(world), capture_started_at=T0, capture_finished_at=T0, snapshot=None)
        self.assertIsNone(payload)
        self.assertEqual((problems[0], problems[-1]), ("R2:LIVE:CONNECTION_FAILED", "TOPOLOGY:UNAVAILABLE"))

    def test_compare_config_and_compare_all_match_an_unchanged_network(self):
        reads = self.reads()
        record = next(r for r in self.candidate.payload["baseline"]["devices"] if r["device"] == "R1")
        self.assertEqual(capture.compare_config(record, reads["R1"]).to_dict(), {"device": "R1", "status": "MATCH"})
        self.assertEqual({c.status for c in capture.compare_all(self.candidate, reads)}, {"MATCH"})

    def test_compare_config_and_compare_all_report_drift_and_unreadable_devices(self):
        world = bh.World()
        world.edit_config("R1", "description uplink R1", "description CHANGED")
        world.take_down("R2")
        reads = self.reads(world)
        record = next(r for r in self.candidate.payload["baseline"]["devices"] if r["device"] == "R1")
        with self.subTest("refused drift and unreadable devices"):
            drift = capture.compare_config(record, reads["R1"])
            by_device = {c.device: c for c in capture.compare_all(self.candidate, {k: v for k, v in reads.items() if k != "S1"})}
        self.assertEqual((drift.status, drift.added, drift.removed, drift.sample_added), ("DRIFT", 1, 1, ["   description CHANGED"]))
        self.assertEqual((by_device["R2"].status, by_device["R2"].reason, by_device["S1"].reason), ("UNAVAILABLE", "CONNECTION_FAILED", "NOT_READ"))

    def test_recheck_configuration_returns_match_for_the_same_world(self):
        result = capture.recheck_configuration(self.candidate, session_factory=self.world.factory, now=T0 + timedelta(minutes=40))
        self.assertEqual((result["result"], result["baseline_digest"], result["checked_at_dt"]), ("MATCH", self.candidate.payload_digest,
                                                                                                 T0 + timedelta(minutes=40)))


class EvidenceTests(BootstrapBase):
    def test_guard_and_guard_ok_return_an_intact_candidate(self):
        checked = evidence.guard(self.candidate)
        self.assertEqual((checked.integrity_ok, checked.interference, checked.ok, checked.config_drift), (True, [], True, False))

    def test_guard_and_collect_with_an_overlapping_execution_invalidate(self):
        self.history(["S2"], state="RUNNING")
        checked = evidence.guard(self.candidate)
        self.assertFalse(checked.ok)
        sample = evidence.collect(self.candidate, now=T0, guard_result=checked)
        self.assertEqual((sample.result, sample.config_drift, sample.findings[0]["check_code"]), (models.SoakSampleResult.INVALIDATED, False, "OVERLAPPING_EXECUTION"))

    def test_collect_returns_a_passing_sample_for_the_captured_network(self):
        sample = evidence.collect(self.candidate, now=T0 + timedelta(seconds=300), snapshot=bh.snapshot(T0 + timedelta(seconds=300)),
                                  session_factory=self.world.factory, dhcp_state=bh.DHCP)
        self.assertEqual((sample.result, sample.config_drift, sample.evidence["config"]["compared"]), (models.SoakSampleResult.PASS, False,
                                                                                                       len(capture.managed_scope())))
        self.assertEqual(sample.to_kwargs()["config_drift"], False)

    def test_collect_with_drifted_configuration_is_invalidated(self):
        world = bh.World()
        world.edit_config("R1", "description uplink R1", "description CHANGED")
        with self.subTest("invalid drifted configuration"):
            sample = evidence.collect(self.candidate, now=T0 + timedelta(seconds=300), snapshot=bh.snapshot(T0 + timedelta(seconds=300)),
                                      session_factory=world.factory, dhcp_state=bh.DHCP)
        self.assertEqual((sample.result, sample.config_drift, sample.findings[0]["check_code"]), (models.SoakSampleResult.INVALIDATED, True, "CONFIG_DRIFT_DETECTED"))

    def test_baseline_requirements_return_what_was_healthy_at_capture(self):
        requirements = evidence.baseline_requirements(self.candidate)
        self.assertTrue(requirements)
        self.assertTrue(all(r.cfg_id.startswith(codes.BASELINE_ID_PREFIX) for r in requirements))
        self.assertEqual(len({r.cfg_id for r in requirements}), len(requirements))

    def test_baseline_requirements_never_require_what_was_down_or_absent(self):
        candidate = SimpleNamespace(payload={"baseline": {"devices": [{"device": "R1", "expected_state": {
            "interfaces": {"Ethernet9": {"admin": "UP", "oper": "DOWN"}}, "ospf": [{"state": "INIT", "interface": "Ethernet9", "family": "ipv4"}],
            "bgp": [{"state": "IDLE", "peer": "10.0.0.9"}]}}]}})
        self.assertEqual((evidence.baseline_requirements(candidate), evidence.baseline_requirements(SimpleNamespace(payload={}))), ([], []))

    def check(self, code, status, cfg_id="BL-R1-001", blocking=False):
        return SimpleNamespace(check_code=code, status=status, cfg_id=cfg_id, blocking=blocking)

    def test_classify_bootstrap_keeps_passing_checks_ok(self):
        self.assertEqual(evidence.classify_bootstrap(self.check("INTERFACE_OPER_DOWN", S.PASS)), "OK")

    def test_classify_bootstrap_fails_a_lost_baseline_interface_or_down_link(self):
        for label, result in (("refused baseline interface down", self.check("INTERFACE_OPER_DOWN", S.WARN)),
                              ("refused link down", self.check("LINK_HEALTH_DEGRADED", S.FAIL, cfg_id=""))):
            with self.subTest(label):
                self.assertEqual(evidence.classify_bootstrap(result), evidence.INTENDED_STATE_FAILED)

    def test_topology_results_of_an_unchanged_topology_are_empty_pass(self):
        baseline_topology = capture.topology_facts(bh.snapshot(T0))
        with self.subTest("same links up"):
            self.assertEqual(evidence.topology_results(bh.snapshot(T0 + timedelta(seconds=60)), baseline_topology), [])

    def test_topology_results_fail_a_link_that_is_no_longer_up(self):
        baseline_topology = {"edges": [{"id": "R1:R2", "status": "UP"}, {"id": "X:Y", "status": "DOWN"}]}
        snapshot = SimpleNamespace(available=True, edges=[])
        results = evidence.topology_results(snapshot, baseline_topology)
        self.assertEqual([(r.check_code, r.status, r.observed["status"]) for r in results], [("LINK_HEALTH_DEGRADED", S.FAIL, "ABSENT")])


class InterferenceTests(BootstrapBase):
    def test_bundle_devices_and_capture_times_come_from_the_payload(self):
        self.assertEqual(interference.bundle_devices(self.candidate), sorted(capture.managed_scope()))
        self.assertEqual((interference.capture_started_at(self.candidate), interference.capture_finished_at(self.candidate)), (T0, T0))

    def test_bundle_devices_and_capture_times_of_a_malformed_payload_are_empty_or_none(self):
        bad = SimpleNamespace(payload={"baseline": {"capture_started_at": "not-a-time"}})
        self.assertEqual((interference.bundle_devices(bad), interference.capture_started_at(bad), interference.capture_finished_at(bad)), ([], None, None))

    def test_find_interference_returns_a_later_mutating_execution(self):
        self.history(["R1", "H1"])
        found = interference.find_interference(self.candidate)
        self.assertEqual([(f["devices"], f["outcome"]) for f in found], [(["R1"], "SUCCEEDED")])

    def test_find_interference_ignores_blocked_earlier_or_unrelated_executions(self):
        self.history(["R1"], outcome="BLOCKED")
        self.history(["R1"], when=T0 - timedelta(hours=2))
        self.history(["H1"])
        with self.subTest("none for blocked, earlier or unrelated"):
            self.assertEqual(interference.find_interference(self.candidate), [])
