"""Lab 7 closure -- the remaining ``route_shield`` modules, each symbol called directly: ``probes`` (``Flow.target``, every ``HostProbes``
step), ``model.Transition`` specs and requirements, ``runner`` (``Result.record``, ``evaluate``, ``execute``), ``gates`` (``WindowGate``,
``default_host_gate``, ``cpu_consecutive_samples``, ``precheck``), ``lab``, ``migration`` helpers, ``source_of_truth``, ``dry_run.WriteGuard``,
``readiness.refusal`` and the ``production`` wiring.

Hermetic: the probe runner, the kernel runner, ``subprocess.run`` of ``production.host_addresses`` and the inventory are fakes; the only
files read are the tracked CPU policy and the tracked templates (read-only), and ``default_host_gate``'s ``/proc`` reads are replaced.  No
``docker exec``, device, NetBox or socket is reached.  POSITIVE: exact commands, counts, specs, verdicts.  NEGATIVE: unknown sides / kinds,
a management uplink or core hop, unreadable host facts, an unmeasured window, missing evidence, a failed address read, missing templates
and missing addresses are refused or reported.
"""
from __future__ import annotations

import json
import subprocess
import tempfile
from dataclasses import replace
from types import SimpleNamespace
from unittest import mock

import yaml
from django.conf import settings
from django.test import SimpleTestCase, override_settings

from core.services.execution.executors.ceos import CeosExecutor
from core.services.route_shield import core_cover, dry_run, gates, lab, migration, model, probes, production, readiness, runner, source_of_truth
from core.tests.test_route_shield import environment as runner_environment, isis_takes_over, switch
from core.tests.test_tg_route_shield_core_cover_closure import COVER, FakeKernel

D = migration.PRODUCTION
S1 = lab.SWITCHES["S1"]


# ------------------------------------------------------------------------------------------------------------------- probes
class ProbeRunner:
    """``runner(container, argv, detach=, timeout=)``: records every command; ``awk`` answers ``lost answered span``."""

    def __init__(self, counts=(0, 500, 500)):
        self.counts, self.calls = counts, []

    def __call__(self, container, argv, *, detach=False, timeout=30.0):
        self.calls.append((container, argv[0], detach, argv[-1]))
        out = " ".join(str(n) for n in self.counts) if argv[0] == "awk" else ""
        return subprocess.CompletedProcess(argv, 0, out, "")


class ProbeTests(SimpleTestCase):
    def setUp(self):
        self.now, self.slept = 0.0, []
        self.flow = probes.Flow("h1-service-v6", "clab-H1", "2001:db8:50::10", 0.01, "2001:db8:10::100")
        self.run = ProbeRunner()
        self.probes = probes.HostProbes([self.flow], runner=self.run, window_seconds=240, hold_seconds=3, clock=lambda: self.now, sleep=self.slept.append)

    def test_flow_target_is_family_source_and_destination(self):
        self.assertEqual(self.flow.target, "-6 -I 2001:db8:10::100 2001:db8:50::10")
        self.assertEqual(probes.Flow("h1-service-v4", "clab-H1", "172.30.50.10").target, "-4 172.30.50.10")

    def test_host_probes_init_start_report_lost_and_healthy(self):
        self.probes = probes.HostProbes([self.flow], runner=self.run, window_seconds=240, hold_seconds=3, clock=lambda: self.now, sleep=self.slept.append)
        self.assertEqual((self.probes.flows, len(self.probes.run_id), self.probes.errors), ([self.flow], 12, []))
        self.probes.start()
        self.assertEqual([(c, cmd, detach) for c, cmd, detach, _ in self.run.calls], [("clab-H1", "sh", False), ("clab-H1", "sh", True)])
        self.assertIn(f"exec ping -D -O -w 900 -i 0.01 {self.flow.target} > /tmp/nmas-transition-probes/h1-service-v6.{self.probes.run_id}.1.log", self.run.calls[1][3])
        self.assertEqual(self.probes.report(), [{"flow": "h1-service-v6", "destination": "2001:db8:50::10", "answered": 500, "lost": 0}])
        self.assertEqual(self.probes.lost(), 0)
        self.assertEqual(self.probes.healthy(), (True, {"lost": 0, "answered": 500, "flows": 1, "unanswered_flows": [], "errors": []}))

    def test_advancing_judges_samples_after_the_minimum_interval(self):
        self.probes.start()
        self.assertEqual(self.probes.advancing(), (True, {"judged": False}))
        self.now, self.run.counts = 2.0, (0, 600, 600)
        self.assertEqual(self.probes.advancing(), (True, {"judged": False}))
        self.now, self.run.counts = 10.0, (0, 1400, 1400)
        ok, detail = self.probes.advancing()
        self.assertEqual((ok, detail["judged"], detail["stalled_flows"], detail["elapsed_seconds"]), (True, True, [], 10.0))

    def test_maintain_restarts_the_generation_after_the_window_and_stop_halts_it(self):
        self.probes.start()
        self.probes.maintain()                               # inside the window: nothing happens
        self.assertEqual(len(self.run.calls), 2)
        self.now = 241.0
        self.probes.maintain()
        self.assertEqual(self.slept, [4.0])
        self.assertTrue(any(f".{self.probes.run_id}.2.log" in tail for _c, _cmd, _d, tail in self.run.calls))
        self.assertTrue(any(tail.startswith("kill -INT $(cat /tmp/nmas-transition-probes/h1-service-v6.") and tail.endswith(".1.pid)") for *_x, tail in self.run.calls))
        self.probes.stop()
        self.assertEqual(self.slept, [4.0, 3])
        self.assertEqual(self.probes.report(), [{"flow": "h1-service-v6", "destination": "2001:db8:50::10", "answered": 1000, "lost": 0}])

    def test_halt_run_signals_only_the_named_runs_pid_files(self):
        self.probes.halt_run("0123456789ab")
        self.assertEqual(len(self.run.calls), 1)
        self.assertIn("/tmp/nmas-transition-probes/*.0123456789ab.*.pid", self.run.calls[0][3])


# ------------------------------------------------------------------------------------------------------------- model, runner
class ModelRunnerTests(SimpleTestCase):
    def test_transition_specs_and_requirements_are_the_shield_change_and_owners(self):
        t = lab.switch_to_isis(S1)
        install, remove = t.install_spec(), t.remove_spec()
        self.assertEqual((install.cfg_id, install.lines), (f"RS-{t.key}-1-shield-install", t.shield_lines()))
        self.assertEqual((remove.operation, remove.lines), ("REMOVE_DELETE", tuple(f"no {line}" for line in t.shield_lines())))
        self.assertEqual([spec.sequence for spec in t.step_specs()], list(range(10, 10 + len(t.steps))))
        self.assertEqual([r.expected["prefix"] for r in t.shield_requirements()], list(t.shield_prefixes))
        self.assertEqual([r.kind for r in t.old_requirements()], ["ROUTE_INTENDED", "ISIS_ROUTE_INTENDED"])
        self.assertEqual([(r.kind, r.expected["interfaces"]) for r in t.new_requirements()], [("ISIS_ROUTE_INTENDED", [S1.uplink])])

    def test_result_record_appends_a_stage(self):
        result = runner.Result("t", "S1")
        result.record("precheck", "PASS", host={"load1": 1.0})
        self.assertEqual({k: v for k, v in result.stages[0].items() if k != "at"}, {"stage": "precheck", "status": "PASS", "host": {"load1": 1.0}})
        with self.subTest("refused stage recorded"):
            result.record("readiness", "REFUSED", detail="TRANSITION_NOT_READY")
        self.assertEqual(result.stages[-1]["status"], "REFUSED")

    def test_evaluate_passes_the_current_owner(self):
        device, t = switch(), lab.switch_to_isis(S1)
        self.assertEqual({row["status"] for row in runner.evaluate(t.old_requirements(), lambda name: device.evidence(), "S1")}, {"PASS"})

    def test_evaluate_fails_an_owner_that_is_not_installed(self):
        device, t = switch(), lab.switch_to_isis(S1)
        self.assertIn("FAIL", {row["status"] for row in runner.evaluate(t.new_requirements(), lambda name: device.evidence(), "S1")})

    def test_execute_runs_a_ready_switch_transition(self):
        device, t = switch(), lab.switch_to_isis(S1)
        isis_takes_over(device, [lab.AGGREGATE], "Ethernet1")
        env, _probes = runner_environment(device)
        result = runner.execute(t, env)
        self.assertTrue(result.ok, result.stages[-1])
        self.assertEqual(result.stages[-1]["stage"], "final-verify")

    def test_readiness_of_a_ready_kind_allows_execution(self):
        with self.subTest("ready kind is executable"):
            self.assertEqual(readiness.refusal(readiness.STATIC_IPV6_TO_ISIS), "")


# ---------------------------------------------------------------------------------------------------------------- gates, lab
class GateLabTests(SimpleTestCase):
    def test_cpu_consecutive_samples_is_the_tracked_policy(self):
        with open(f"{settings.REPO_ROOT}/{gates.CPU_POLICY_FILE}", encoding="utf-8") as handle:
            self.assertEqual(gates.cpu_consecutive_samples(), max(1, int(yaml.safe_load(handle)["consecutive_samples"])))

    def test_window_gate_refuses_a_call_before_the_quiet_host_was_measured(self):
        gate = gates.WindowGate(gate=lambda probes_running: (True, {"failed": []}), consecutive_samples=lambda: 3)
        self.assertEqual(gate(), (False, {"failed": ["the quiet-host gate was not evaluated before the probes started"]}))

    def test_default_host_gate_refuses_unreadable_host_facts(self):
        with mock.patch.object(gates, "open", side_effect=OSError("no /proc"), create=True):
            self.assertEqual(gates.default_host_gate(), (False, {"error": "host facts unreadable"}))

    def test_precheck_without_evidence_is_unavailable(self):
        self.assertEqual([b["code"] for b in gates.precheck(lab.switch_to_isis(S1), None)], [gates.EVIDENCE_UNAVAILABLE])

    def test_switch_to_static_is_the_rollback_of_switch_to_isis(self):
        t = lab.switch_to_static(S1)
        self.assertEqual((t.old.source, t.new.source, t.new.next_hop, t.shield_prefixes), (model.ISIS, model.STATIC, S1.router_v6, lab.switch_to_isis(S1).shield_prefixes))

    def test_switch_to_static_refuses_a_management_uplink(self):
        with self.assertRaisesMessage(model.ShieldError, "management"):
            lab.switch_to_static(replace(S1, uplink="Management0"))

    def test_baseline_migration_and_rollback_of_an_unknown_side_raise(self):
        for label, build in (("migration unknown side", lab.baseline_migration), ("rollback unknown side", lab.baseline_rollback)):
            with self.subTest(label), self.assertRaises(KeyError):
                build("S9")


# -------------------------------------------------------------------------------------------------------------- migration
class MigrationHelperTests(SimpleTestCase):
    def setUp(self):
        self.ops = migration.operations(migration.KIND, D)

    def test_operations_of_an_unknown_kind_raises(self):
        with self.assertRaisesMessage(ValueError, "unknown transition kind 'X'"):
            migration.operations("X", D)

    def test_operations_of_the_migration_is_the_forward_plan(self):
        self.assertEqual([op.key for op in self.ops], [op.key for op in migration.forward_operations(D)])

    def test_permanent_and_temporary_lines_of_the_wrong_states_are_empty(self):
        temporary_only = [op for op in self.ops if op.state == migration.TEMPORARY]
        permanent_only = [op for op in self.ops if op.state == migration.PERMANENT]
        self.assertEqual((migration.permanent_lines(temporary_only), migration.temporary_lines(permanent_only)), ({}, ()))

    def test_plan_hash_of_a_reordered_plan_is_not_the_same(self):
        self.assertNotEqual(migration.plan_hash(self.ops), migration.plan_hash(list(reversed(self.ops))))

    def test_revert_operations_never_reuse_a_forward_key(self):
        revert = migration.revert_operations(D)
        self.assertEqual(len(revert), len(self.ops))
        self.assertFalse({op.key for op in revert} & {op.key for op in self.ops})

    def test_with_cabling_refuses_a_management_core_hop(self):
        with self.assertRaises(core_cover.CoverError):
            migration.with_cabling(D, name="sandbox", access_interface="Ethernet3",
                                   core_hops={"R3": (("fe80::1", "Management0"), ("fe80::2", "eth2")), "R4": (("fe80::1", "eth1"), ("fe80::2", "eth2"))})


# ------------------------------------------------------------------------------------------------------- source of truth
class SourceOfTruthTests(SimpleTestCase):
    def test_template_path_of_an_unknown_device_is_absent(self):
        path = source_of_truth.template_path("ZZ9")
        self.assertEqual((path.name, path.exists()), ("ZZ9.cfg.j2", False))

    def test_tracked_state_of_missing_templates_is_unreadable(self):
        with tempfile.TemporaryDirectory() as root, override_settings(REPO_ROOT=root):
            self.assertEqual(source_of_truth.tracked_state(), {name: {"state": "UNREADABLE"} for name in D.access_devices})

    def test_intent_template_never_keeps_a_superseded_static(self):
        text = f"hostname S1\nipv6 route {lab.AGGREGATE} {S1.router_v6}\n"
        intent = source_of_truth.intent_template("S1", text)
        self.assertNotIn(f"ipv6 route {lab.AGGREGATE} {S1.router_v6}", intent)
        self.assertIn("router isis NMAS", intent)

    def test_required_updates_never_name_a_temporary_statement(self):
        rows = source_of_truth.required_updates()
        self.assertEqual([row["target"] for row in rows][:4], [f"templates/{name}.cfg.j2" for name in D.access_devices])
        self.assertFalse([row for row in rows if "/63" in row["update"] or " 250" in row["update"]])


# ------------------------------------------------------------------------------------------------- dry run, production
class DryRunProductionTests(SimpleTestCase):
    def test_write_guard_factory_passes_core_reads_through(self):
        guard, kernel = dry_run.WriteGuard(), FakeKernel()
        build = guard.factory(lambda device: core_cover.KernelCoverExecutor(device, runner=kernel))
        executor = build({"name": "R3", "container": "clab-sandbox-R3"})
        self.assertEqual(executor.routes(COVER.protects)[0]["dst"], COVER.protects)
        self.assertEqual((guard.reads, guard.attempts), (1, []))

    def test_executor_for_never_gives_a_core_router_the_ceos_executor(self):
        self.assertIsInstance(production.executor_for({"name": "R3", "container": "clab-R3"}), core_cover.KernelCoverExecutor)
        self.assertIsInstance(production.executor_for({"name": "S1", "host": "192.0.2.1", "platform": "ceos"}), CeosExecutor)

    def test_host_addresses_reads_the_client_addresses(self):
        rows = [{"addr_info": [{"local": "2001:db8:10::100"}, {"local": "192.168.10.5"}, {"local": "2001:db8:10::200", "deprecated": True},
                               {"local": "fe80::1"}, {"local": "not-an-address"}]}]
        with mock.patch.object(production.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, json.dumps(rows), "")) as run:
            self.assertEqual(production.host_addresses("clab-H1"), ["192.168.10.5", "2001:db8:10::100"])
        self.assertEqual(run.call_args.args[0], ["docker", "exec", "clab-H1", "ip", "-j", "addr", "show"])

    def test_host_addresses_of_a_failed_read_is_empty(self):
        with mock.patch.object(production.subprocess, "run", return_value=subprocess.CompletedProcess([], 1, "", "no such container")):
            self.assertEqual(production.host_addresses("clab-H9"), [])

    def test_flows_without_host_addresses_probe_only_toward_the_service(self):
        with mock.patch.object(production.inventory, "load_inventory", return_value={"lab_name": "lab", "hosts": {"H1": {"ipv6": True, "ipv4": True}}}):
            found = production.flows(read_addresses=lambda container: [])
        self.assertEqual([(f.label, f.container, f.destination) for f in found],
                         [("h1-service-v6", "clab-lab-H1", production.SERVICE_V6), ("h1-service-v4", "clab-lab-H1", production.SERVICE_V4)])

    def test_environment_without_managed_devices_has_no_devices(self):
        source = SimpleNamespace()
        with mock.patch.object(production.inventory, "managed_devices", return_value={}):
            env = production.environment(probe_source=source)
        self.assertEqual((env.devices, env.probes), ({}, source))
        self.assertIsInstance(env.host_gate, gates.WindowGate)

    def test_start_probes_without_a_quiet_measure_only_starts_the_probes(self):
        started = []
        env = SimpleNamespace(host_gate=lambda: (True, {}), probes=SimpleNamespace(start=lambda: started.append(True)))
        production.start_probes(env)
        self.assertEqual(started, [True])
