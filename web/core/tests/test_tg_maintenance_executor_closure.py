"""Lab 7 closure -- the Maintenance Mode run engine (device-write path), each ``Run`` method called directly on the
statement-keyed fake devices of ``test_maintenance_live`` (no device, no network, no NetBox).

POSITIVE: one planned operation is sent, read back and journaled; the verified running state becomes the startup state;
compensation puts back exactly the pre-run state.  NEGATIVE: a guard refusal, an out-of-band change, a rejected
command, a failed gate, a busy host, a stalled or lossy probe each stop the run BEFORE any further write, the failure
is the first one recorded, and a core router handed out read-only refuses every write.
"""

from __future__ import annotations

from django.test import SimpleTestCase

from core.services.execution.executors.base import ExecutorError
from core.services.maintenance_mode import executor
from core.services.route_shield import gates
from core.services.route_shield.migration import Check
from core.tests import test_maintenance_live as ml

OPS = ml.simple_ops()
SHIELD_OP, METRIC_OP = OPS[0], OPS[1]


def run(**kw):
    log = []
    env = ml.environment(log, fail_on=kw.pop("fail_on", ""))
    found = executor.Run(env, kw.pop("ops", list(OPS)), **kw)
    found._expected = {name: found._digest(name) for name in env.executors}
    found._startup = {name: env.executors[name].startup_state_digest() for name in env.executors}
    return found, env, log


def writes(log):
    return [entry for entry in log if entry[0] in ("apply", "undo", "save")]


class SpecTests(SimpleTestCase):
    def test_spec_of_an_addition_and_a_removal(self):
        add = executor.spec_of(METRIC_OP, 2)
        self.assertEqual((add.cfg_id, add.sequence, add.device, add.operation, add.lines), ("MNT-002", 2, "S1", "CREATE_DEFINE", METRIC_OP.lines))
        self.assertEqual(add.expected["inverse_lines"], list(METRIC_OP.inverse))
        removal = executor.spec_of(OPS[2], 3)
        self.assertEqual((removal.operation, removal.origin, removal.removal["restore_lines"]), ("REMOVE_DELETE", "REMOVAL", list(OPS[2].inverse)))

    def test_read_only_cores_refuse_every_write(self):
        build = executor.read_only(lambda device: ml.FakeDevice(device["name"], []), ["R3"])
        core, switch = build({"name": "R3"}), build({"name": "S1"})
        self.assertIsInstance(core, executor.CoreReader)
        for method in ("apply", "compensate", "save_startup", "assess"):
            with self.subTest(case=f"refused {method}"), self.assertRaises(ExecutorError) as caught:
                getattr(core, method)
            self.assertEqual(caught.exception.code, executor.READ_ONLY)
        self.assertIsInstance(switch, ml.FakeDevice)


class RunEvidenceTests(SimpleTestCase):
    def test_note_appends_a_timestamped_stage(self):
        found, _env, _log = run()
        found.note("precheck", "PASS", host={"load1": 1.0})
        self.assertEqual({k: v for k, v in found.stages[0].items() if k != "at"}, {"stage": "precheck", "status": "PASS", "host": {"load1": 1.0}})
        self.assertRegex(found.stages[0]["at"], r"^\d{4}-\d\d-\d\dT")

    def test_note_of_a_blocked_stage_keeps_its_codes(self):
        found, _env, _log = run()
        found.note("precheck", "BLOCKED", blockers=["HOST_GATE"])
        self.assertEqual((found.stages[-1]["status"], found.stages[-1]["blockers"]), ("BLOCKED", ["HOST_GATE"]))

    def test_lost_counts_probes_since_the_start_monotonically(self):
        found, env, _log = run()
        found.lost_at_start, env.probes.count = 1, 4
        self.assertEqual(found.lost(), 3)
        env.probes.count = 2
        self.assertEqual(found.lost(), 3)

    def test_first_recorded_problem_keeps_code_detail_and_stage(self):
        found, _env, _log = run()
        found.fail("GATE_FAILED", "x" * 400, "s1-shield")
        self.assertEqual(found.failure, {"code": "GATE_FAILED", "detail": "x" * 300, "operation": "s1-shield"})
        self.assertEqual((found.stages[-1]["stage"], found.stages[-1]["status"]), ("abort", "GATE_FAILED"))

    def test_fail_a_second_time_never_overwrites_the_first_failure(self):
        found, _env, _log = run()
        found.fail("APPLY_FAILED", "first")
        found.fail("PACKET_LOSS", "second")
        self.assertEqual((found.failure["code"], len(found.stages)), ("APPLY_FAILED", 1))

    def test_report_carries_outcome_stages_applied_and_probes(self):
        found, _env, _log = run()
        self.assertTrue(found.apply(SHIELD_OP, executor.spec_of(SHIELD_OP, 1)))
        report = found.report("SUCCEEDED")
        self.assertEqual((report["outcome"], report["failure"], report["applied"], report["probes"]), ("SUCCEEDED", {}, ["s1-shield"], {"lost": 0}))

    def test_report_of_a_failed_run_names_the_failure_and_lost_probes_with_flows(self):
        found, env, _log = run()
        env.probes.report = lambda: [{"flow": "H1", "lost": 2}]
        found.fail("PRODUCTION_PACKET_LOSS", "lost")
        found.probes_lost = 2
        report = found.report("FAILED_ROLLED_BACK")
        self.assertEqual((report["failure"]["code"], report["probes"]), ("PRODUCTION_PACKET_LOSS", {"lost": 2, "flows": [{"flow": "H1", "lost": 2}]}))


class WindowGuardTests(SimpleTestCase):
    def test_window_check_holds_on_a_quiet_host_with_advancing_probes(self):
        found, _env, _log = run()
        self.assertTrue(found.window_guard("NORTHBOUND"))
        self.assertEqual((found.stages[-1]["stage"], found.stages[-1]["before"], found.stages[-1]["load1"]), ("window", "NORTHBOUND", 1.0))

    def test_window_guard_stops_on_a_busy_host_stalled_or_lossy_probes(self):
        def busy(env):
            env.host_gate = lambda: (False, {"failed": ["load1 4.0 > 2.0"]})

        def stalled(env):
            env.probes.advancing = lambda: (False, {"stalled_flows": ["H1-v6"]})

        def silent(env):
            env.probes.advancing = None

        def lossy(env):
            env.probes.count = 1

        for label, breaks, code in (("busy host", busy, gates.WINDOW_CONDITION_LOST), ("stalled probe", stalled, gates.PROBE_TIMING_UNRELIABLE),
                                    ("probe without progress", silent, gates.PROBE_TIMING_UNRELIABLE), ("lost probe", lossy, gates.PACKET_LOSS)):
            found, env, log = run()
            breaks(env)
            with self.subTest(case=f"failure {label}"):
                self.assertFalse(found.window_guard("SOUTHBOUND"))
                self.assertEqual((found.failure["code"], found.failure["operation"], writes(log)), (code, "SOUTHBOUND", []))


class ApplyTests(SimpleTestCase):
    def test_apply_sends_reads_back_and_journals_one_operation(self):
        found, env, log = run()
        events = []
        env.observer = lambda event, key: events.append((event, key))
        self.assertTrue(found.apply(SHIELD_OP, executor.spec_of(SHIELD_OP, 1)))
        self.assertEqual(writes(log), [("apply", "S1", ml.SHIELD)])
        self.assertEqual(events, [("before", "s1-shield"), ("after", "s1-shield")])
        self.assertEqual((len(found.applied), found._expected["S1"], found.stages[-1]["status"]), (1, ml.SHIELD, "APPLIED"))

    def test_apply_stops_before_any_write_on_a_guard_out_of_band_change_or_failed_gate(self):
        failing = Check("the uplink is up", lambda env: (False, "down"))
        cases = (("guard refusal", dict(guard=lambda op: "MANAGEMENT_PLANE_PROTECTED: names VLAN 200"), SHIELD_OP, None, "MANAGEMENT_PLANE_PROTECTED"),
                 ("out of band change", {}, SHIELD_OP, lambda env: env.executors["S1"].config.add("other"), gates.OUT_OF_BAND),
                 ("state already present", {}, SHIELD_OP, lambda env: (env.executors["S1"].config.add(ml.SHIELD)), gates.OUT_OF_BAND),
                 ("failed before gate", {}, ml.Operation("g", "NORTHBOUND", "S1", "TEMPORARY", ml.ADD, (ml.SHIELD,), (ml.UNSHIELD,), before=(failing,)), None,
                  "GATE_FAILED"))
        for label, kw, op, mutate, code in cases:
            found, env, log = run(**kw)
            if mutate is not None:
                mutate(env)
                if label == "state already present":
                    found._expected["S1"] = found._digest("S1")
            with self.subTest(case=f"failure {label}"):
                self.assertFalse(found.apply(op, executor.spec_of(op, 1)))
                self.assertEqual((found.failure["code"], writes(log), found.applied), (code, [], []))

    def test_apply_of_a_rejected_command_fails_and_records_nothing_applied(self):
        found, _env, log = run(fail_on="isis metric 1000")
        self.assertFalse(found.apply(METRIC_OP, executor.spec_of(METRIC_OP, 2)))
        self.assertEqual((found.failure["code"], found.applied, writes(log)), ("APPLY_FAILED", [], []))


class FinishAndCompensateTests(SimpleTestCase):
    def test_finish_persists_exactly_the_verified_running_state(self):
        found, env, log = run(persist=("S1",))
        self.assertTrue(found.apply(SHIELD_OP, executor.spec_of(SHIELD_OP, 1)))
        found.finish()
        self.assertEqual((found.failure, found.persisted), ({}, {"S1": "VERIFIED"}))
        self.assertEqual(env.executors["S1"].startup, frozenset({ml.SHIELD}))
        self.assertEqual([(st["stage"], st["status"]) for st in found.stages if st["stage"] == "FINAL_VALIDATION"], [("FINAL_VALIDATION", "PASS")])
        self.assertIn(("save", "S1"), log)

    def test_finish_refuses_to_persist_a_state_that_fails_validation_or_changed(self):
        found, env, log = run(persist=("S1",), final=(Check("the metric holds", lambda env: (False, "metric 10")),))
        found.finish()
        self.assertEqual((found.failure["code"], found.persisted, writes(log)), ("FINAL_STATE_NOT_VERIFIED", {}, []))
        found, env, log = run(persist=("S1",))
        env.executors["S1"].config.add("changed after validation")
        found.finish()
        self.assertEqual((found.failure["code"], writes(log)), ("PERSISTENCE_NOT_VERIFIED", []))

    def test_compensate_restores_the_pre_run_state_newest_first(self):
        found, env, log = run(persist=("S1",))
        for sequence, op in enumerate(OPS[:2], 1):
            self.assertTrue(found.apply(op, executor.spec_of(op, sequence)))
        found.finish()
        found.compensate()
        self.assertEqual((found.restored, env.executors["S1"].config, found.persisted["S1"]), (True, set(), "STARTUP_RESTORED"))
        self.assertEqual([e["operation"] for e in found.compensation], ["s1-metric", "s1-shield"])
        self.assertEqual([e[0] for e in writes(log)], ["apply", "apply", "save", "undo", "undo", "save"])

    def test_compensate_that_cannot_undo_is_reported_incomplete(self):
        found, env, _log = run()
        self.assertTrue(found.apply(SHIELD_OP, executor.spec_of(SHIELD_OP, 1)))
        env.executors["S1"].broken_undo = True
        found.compensate()
        self.assertEqual((found.restored, found.compensation[0]["status"], found.stages[-1]["status"]), (False, "COMPENSATION_FAILED", "RESTORE_INCOMPLETE"))
