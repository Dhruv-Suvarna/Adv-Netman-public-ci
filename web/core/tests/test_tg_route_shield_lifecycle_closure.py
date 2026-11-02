"""Lab 7 closure -- ``route_shield.lifecycle``: the ``Environment`` hooks, the record lookups, the revert basis, the in-lock precheck and
every step of one ``_Attempt`` (note, abort, gate, pause, window check, apply, compensate, final checks, persistence, report), each called
directly instead of only through ``_execute``.

Hermetic: the six devices are the simulated network of ``test_route_shield_lifecycle`` -- the REAL ``KernelCoverExecutor`` over an emulated
``ip`` / ``vtysh`` for R3/R4 and ``SimCeos`` for S1/S2/R1/R2 -- with a fake probe source, host gate, clock and sleep.  No device, NetBox,
Slack or socket is reached and no real time passes.  POSITIVE: exact outcomes, stages, digests, records.  NEGATIVE: a missing probe source or
host gate, a failing check, a busy host, a stalled probe flow, an out-of-band step and a second abort are refused or reported; a blocked
attempt reports nothing applied.
"""
from __future__ import annotations

from types import SimpleNamespace

from django.test import SimpleTestCase, TestCase, override_settings
from django.utils import timezone

from core import models
from core.services.execution import locking
from core.services.execution.executors.base import ConfigletSpec
from core.services.execution.scope import resolve_scope
from core.services.route_shield import gates, lifecycle, migration
from core.tests.test_route_shield_closure import Flow
from core.tests.test_route_shield_lifecycle import DEVICES, D, Network, Probes, environment


def attempt_of(case, **env_kwargs):
    """The ``_Attempt`` ``_execute`` would build for an approved case: the lock is taken, nothing is driven."""
    change, now = case.change, timezone.now()
    plan, precheck, ops, blockers = lifecycle._gate(change, D, change.change_id, now)
    assert not blockers, blockers
    scope, _ = resolve_scope(plan, models.ExecutionMode.COMPLETE)
    run = locking.acquire(change=change, plan=plan, precheck_run=precheck, mode=models.ExecutionMode.COMPLETE, actor="operator", scope=scope,
                          devices=list(D.devices), now=now)
    env = environment(case.net, **env_kwargs)
    return lifecycle._Attempt(run=run, change=change, plan=plan, precheck=precheck, definition=D, env=env, ops=ops,
                              specs=[ConfigletSpec.from_configlet(row) for row in scope.selected], actor="operator")


def armed(attempt):
    """What ``drive`` does before its first write: connect, record the baseline and the expected digests."""
    attempt.env.connect(D.devices)
    blockers, facts = lifecycle.precheck_blockers(D, attempt.ops, attempt.env)
    assert not blockers, blockers
    attempt.baseline = attempt.env.baseline = facts["digests"]
    attempt.expected = {name: attempt.baseline[name]["config"] for name in D.access_devices}
    return attempt


class Recorder:
    def __init__(self, fail=False):
        self.fail, self.calls = fail, []

    def connect(self):
        self.calls.append("connect")

    def close(self):
        self.calls.append("close")
        if self.fail:
            raise OSError("session already gone")


class EnvironmentTests(SimpleTestCase):
    def env(self, **kwargs):
        made = []

        def factory(device):
            made.append(device["name"])
            return Recorder(fail=device["name"] == "R3")
        return lifecycle.Environment(devices=DEVICES, executor_factory=factory, read=None, **kwargs), made

    def test_connect_opens_each_device_once_and_close_clears_every_executor(self):
        env, made = self.env()
        env.connect(["R3", "S1"])
        env.connect(["R3", "S1"])
        self.assertEqual((made, sorted(env.executors)), (["R3", "S1"], ["R3", "S1"]))
        executors = dict(env.executors)
        env.close()
        self.assertEqual((env.executors, [e.calls for e in executors.values()]), ({}, [["connect", "close"], ["connect", "close"]]))

    def test_notify_passes_the_event_to_the_observer(self):
        seen = []
        env, _ = self.env(observer=lambda event, key: seen.append((event, key)))
        env.notify("before", "R3-cover")
        self.assertEqual(seen, [("before", "R3-cover")])

    def test_notify_without_an_observer_is_silent(self):
        env, _ = self.env()
        self.assertIsNone(env.notify("before", "R3-cover"))

    @override_settings(TRANSITION_PLAN_MAX_AGE_SECONDS=60)
    def test_plan_max_age_seconds_follows_the_setting(self):
        self.assertEqual(lifecycle.plan_max_age_seconds(), 60.0)

    def test_kind_of_a_plain_change_is_empty(self):
        self.assertEqual((lifecycle.kind_of(SimpleNamespace(metadata=None)), lifecycle.kind_of(SimpleNamespace(metadata={"transition": {}}))), ("", ""))

    def test_is_transition_follows_the_transition_kind(self):
        self.assertTrue(lifecycle.is_transition(SimpleNamespace(metadata={"transition": {"kind": migration.KIND}})))
        with self.subTest("refused plain change"):
            self.assertFalse(lifecycle.is_transition(SimpleNamespace(metadata={})))


class RecordLookupTests(Flow, TestCase):
    def test_latest_validation_plan_and_precheck_return_the_recorded_runs(self):
        case = self.prepare()
        self.assertEqual(lifecycle.latest_validation(case.change).status, "PASS")
        self.assertEqual(lifecycle.latest_plan(case.change).pk, case.plan.pk)
        self.assertEqual(lifecycle.latest_precheck(case.change, case.plan).pk, case.precheck.pk)

    def test_latest_records_of_an_unvalidated_change_are_none(self):
        change = lifecycle.create_change(actor="operator")
        self.assertEqual((lifecycle.latest_validation(change), lifecycle.latest_plan(change), lifecycle.latest_precheck(change, None)), (None, None, None))

    def test_revert_basis_names_the_succeeded_migration_run_and_its_digests(self):
        case, result = self.migrated()
        result.run.refresh_from_db()
        revert = lifecycle.create_revert(actor="operator", migration_run_id=str(result.run.run_id))
        basis = lifecycle.revert_basis(revert)
        self.assertEqual(basis["run"].pk, result.run.pk)
        self.assertEqual((basis["premigration"], basis["migrated"]), (result.run.report["baseline_digests"], result.run.report["permanent_intent"]["baseline_digests"]))

    def test_revert_basis_of_a_change_without_a_reverted_run_is_none(self):
        case = self.prepare()
        self.assertIsNone(lifecycle.revert_basis(case.change))

    def test_unresolved_transitions_lists_a_running_attempt(self):
        case = self.prepare()
        attempt = attempt_of(case)
        self.assertEqual(lifecycle.unresolved_transitions(), [f"{case.change.change_id}: {attempt.run.outcome or attempt.run.state}"])

    def test_precheck_blockers_of_a_healthy_network_records_every_digest(self):
        case = self.prepare()
        env = environment(case.net)
        env.connect(D.devices)
        blockers, facts = lifecycle.precheck_blockers(D, migration.operations(migration.KIND, D), env)
        self.assertEqual((blockers, sorted(facts["digests"])), ([], sorted(D.devices)))
        self.assertEqual(facts["host"], {"load1": 5.0})

    def test_precheck_blockers_refuses_a_missing_probe_source_or_host_gate(self):
        case = self.prepare()
        for label, change, code in (("refused missing probes", {"probes": None}, gates.PROBES_UNHEALTHY), ("refused missing host gate", {"host_gate": None}, gates.HOST_GATE)):
            with self.subTest(label):
                env = environment(case.net)
                for name, value in change.items():
                    setattr(env, name, value)
                self.assertEqual([b["code"] for b in lifecycle.precheck_blockers(D, [], env)[0]], [code])


class AttemptStepTests(Flow, TestCase):
    def setUp(self):
        self.case = self.prepare()
        self.attempt = attempt_of(self.case)

    def test_note_appends_a_timestamped_stage(self):
        self.attempt.note("window", "PASS", before="cover")
        self.assertEqual({k: v for k, v in self.attempt.stages[-1].items() if k != "at"}, {"stage": "window", "status": "PASS", "before": "cover"})
        with self.subTest("refused stage noted"):
            self.attempt.note(migration.PRECHECK, "BLOCKED", blockers=["HOST_GATE"])
        self.assertEqual(self.attempt.stages[-1]["status"], "BLOCKED")

    def test_lost_counts_probes_lost_since_the_start(self):
        probes = Probes()
        self.attempt.env.probes, self.attempt.lost_at_start, probes.count = probes, 1, 3
        self.assertEqual(self.attempt.lost(), 2)

    def test_an_abort_records_its_code_detail_and_note(self):
        with self.subTest("code detail and operation recorded"):
            self.attempt.fail("APPLY_FAILED", "R3-cover: timeout", "R3-cover")
        self.assertEqual(self.attempt.failure, {"code": "APPLY_FAILED", "detail": "R3-cover: timeout", "operation": "R3-cover"})
        self.assertEqual(([b["code"] for b in self.attempt.blockers], self.attempt.stages[-1]["stage"]), (["APPLY_FAILED"], "abort"))

    def test_a_second_abort_never_replaces_the_first(self):
        with self.subTest("first abort recorded"):
            self.attempt.fail("APPLY_FAILED", "first")
        self.attempt.fail("PACKET_LOSS", "second")
        self.assertEqual((self.attempt.failure["code"], len(self.attempt.blockers)), ("APPLY_FAILED", 1))

    def test_gate_passes_settled_checks(self):
        check = migration.Check("always", lambda env: (True, "ok"), 0)
        self.assertTrue(self.attempt.gate([check, check], "op", "before"))
        self.assertEqual(self.attempt.failure, {})

    def test_gate_refuses_a_failing_check(self):
        check = migration.Check("route owned", lambda env: (False, "still static"), 0)
        self.assertFalse(self.attempt.gate([check], "op", "after"))
        self.assertEqual((self.attempt.failure["code"], self.attempt.failure["detail"]), ("GATE_FAILED", "after: route owned: still static"))

    def test_pause_sleeps_heartbeats_and_maintains_the_probes(self):
        slept, maintained = [], []
        self.attempt.env.sleep = slept.append
        self.attempt.env.probes = SimpleNamespace(maintain=lambda: maintained.append(True))
        self.attempt.pause(5)
        self.assertEqual((slept, maintained), ([5], [True]))
        self.attempt.run.refresh_from_db()
        self.assertGreater(self.attempt.run.lease_expires_at, timezone.now())

    def test_pause_of_zero_seconds_never_sleeps(self):
        slept = []
        self.attempt.env.sleep = slept.append
        self.attempt.pause(0)
        self.assertEqual(slept, [])

    def test_changed_restarts_the_quiet_period_after_an_access_step(self):
        access = next(op for op in self.attempt.ops if op.device in D.access_devices)
        self.attempt.changed(access)
        self.assertIsNotNone(self.attempt.env.last_change_at)

    def test_a_core_cover_change_does_not_restart_the_quiet_period(self):
        cover = next(op for op in self.attempt.ops if op.device in D.cores)
        self.attempt.changed(cover)
        self.assertIsNone(self.attempt.env.last_change_at)

    def test_digest_of_an_access_device_is_its_configuration_state(self):
        armed(self.attempt)
        self.assertEqual(self.attempt.digest("S1"), self.attempt.baseline["S1"]["config"])

    def test_digest_of_a_core_router_is_none(self):
        self.assertIsNone(self.attempt.digest("R3"))

    def test_window_check_passes_a_quiet_host_with_advancing_probes(self):
        self.assertTrue(self.attempt.window_guard(migration.FINAL_VALIDATION))
        self.assertEqual((self.attempt.stages[-1]["status"], self.attempt.stages[-1]["load1"]), ("PASS", 5.0))

    def test_window_guard_refuses_a_busy_host_a_stalled_flow_or_lost_probes(self):
        for label, host, probes, code in (("refused busy host", lambda: (False, {"failed": ["cpu busy 97%"]}), Probes(), gates.WINDOW_CONDITION_LOST),
                                          ("refused stalled flow", lambda: (True, {}), SimpleNamespace(lost=lambda: 0), gates.PROBE_TIMING_UNRELIABLE),
                                          ("refused lost probes", lambda: (True, {}), SimpleNamespace(lost=lambda: 4, advancing=lambda: (True, {})), gates.PACKET_LOSS)):
            with self.subTest(label):
                attempt = self.attempt
                attempt.failure, attempt.blockers = {}, []
                attempt.env.host_gate, attempt.env.probes = host, probes
                self.assertFalse(attempt.window_guard("switchover"))
                self.assertEqual(attempt.failure["code"], code)

    def test_apply_installs_verifies_and_compensate_restores_the_first_cover(self):
        attempt = armed(self.attempt)
        op, spec = attempt.ops[0], attempt.specs[0]
        self.assertTrue(attempt.apply(op, spec))
        self.assertEqual(attempt.stages[-1]["status"], "APPLIED")
        self.assertEqual(attempt.temporary_remaining(), [f"R3: {D.covers_of('R3')[0].prefix}"])
        attempt.fail("INJECTED", "closure")
        attempt.compensate()
        self.assertTrue(attempt.restored)
        self.assertEqual([e["status"] for e in attempt.compensation], ["COMPENSATED"])
        self.assertEqual(attempt.temporary_remaining(), [])

    def test_apply_refuses_an_access_device_changed_out_of_band(self):
        attempt = armed(self.attempt)
        index = next(i for i, op in enumerate(attempt.ops) if op.device in D.access_devices)
        op, spec = attempt.ops[index], attempt.specs[index]
        attempt.env.executors[op.device].net.paths[op.device].add("ipv6 route 2001:db8:99::/64 2001:db8:110:1::9")
        attempt.gate = lambda checks, key, phase: True          # isolate the out-of-band check from the stage gates
        self.assertFalse(attempt.apply(op, spec))
        self.assertEqual((attempt.failure["code"], attempt.applied), (gates.OUT_OF_BAND, []))

    def test_restore_startup_writes_the_baseline_startup_again(self):
        attempt = armed(self.attempt)
        attempt.persisted = ["S1"]
        self.assertTrue(attempt.restore_startup())
        self.assertEqual(attempt.persistence["S1"]["recovery"], "STARTUP_RESTORED")

    def test_drive_succeeds_and_the_final_checks_persistence_validation_and_report_hold(self):
        outcome = self.attempt.drive()
        self.assertEqual(outcome, "SUCCEEDED", self.attempt.failure)
        self.assertEqual((self.attempt.final_checks(), self.attempt.persist()), ([], []))
        self.attempt.final_validation()
        self.assertEqual(self.attempt.postcheck_run.status, "PASS")
        report = self.attempt.report(outcome)
        self.assertEqual((report["outcome"], report["persistence"]["status"], report["compensation"]["status"]), ("SUCCEEDED", "VERIFIED", "NOT_ATTEMPTED"))
        self.assertEqual((len(report["state"]["applied"]), report["temporary_state"]["remaining"]), (len(self.attempt.specs), []))

    def test_report_of_a_blocked_attempt_has_nothing_applied(self):
        self.attempt.blockers = [{"code": gates.HOST_GATE}]
        report = self.attempt.report("BLOCKED")
        self.assertEqual((report["persistence"]["status"], report["compensation"]["status"], report["postcheck"]["result"]), ("NOT_RUN", "NOT_ATTEMPTED", "NOT_RUN"))
        self.assertEqual((report["state"]["applied"], report["temporary_state"]["remaining"], report["probes"]), ([], [], {"lost": 0}))
        self.assertEqual(Network().paths, self.case.net.paths)
