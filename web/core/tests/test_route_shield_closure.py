"""Live-window readiness closure of the baseline migration: the locked R3/R4 cover inventory, the persistence stage and
its recovery, the operator-initiated revert of a COMPLETED migration, the read-only production dry run, the window
resource gate, the permanent source-of-truth definition and the operator command's safety.

The simulated network is the one of ``test_route_shield_lifecycle``.
"""

from __future__ import annotations

import json
from datetime import timedelta
from io import StringIO
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from django.conf import settings
from django.core.management import CommandError, call_command
from django.test import SimpleTestCase, TestCase
from django.utils import timezone

from core import models
from core.services.execution.executors.base import REFUSE, ApplyOutcome, ExecutorError
from core.services.health import inventory
from core.services.route_shield import core_cover, dry_run, gates, lab, lifecycle, migration, readiness, source_of_truth
from core.services.route_shield.core_cover import CoverRoute, KernelCoverExecutor
from core.tests.test_route_shield_lifecycle import ACKS, BASE, DEVICES, D, Network, Probes, R1LL, R2LL, SimCeos, environment, ip_runner

BASELINE = {name: set(lines) for name, lines in BASE.items()}
TEMPORARY_MARKS = ("/63", "/33", " 250")


def is_temporary(path: str) -> bool:
    return path.startswith("ipv6 route ") and (any(mark in path for mark in TEMPORARY_MARKS[:2]) or path.endswith(TEMPORARY_MARKS[2]))


class Boom(Exception):
    pass


class Flow:
    """A lifecycle on the simulated network, for either kind of Change."""

    def prepare(self, net=None, *, change=None):
        net = net or Network()
        change = change or lifecycle.create_change(actor="operator")
        lifecycle.validate_change(change, actor="operator", inventory=DEVICES)
        plan = lifecycle.build_plan(change, actor="operator")
        precheck = lifecycle.run_precheck(change, actor="operator", env=environment(net))
        if precheck.status == "PASS":
            lifecycle.approve(change, actor="approver", confirmation=change.change_id, acknowledgements=ACKS)
            change.refresh_from_db()
        return SimpleNamespace(net=net, change=change, plan=plan, precheck=precheck)

    def execute(self, case, **kw):
        result = lifecycle._execute(case.change, actor="operator", confirmation=case.change.change_id, env=environment(case.net, **kw), definition=D)
        case.change.refresh_from_db()
        return result

    def migrated(self):
        case = self.prepare()
        result = self.execute(case)
        assert result.outcome == "SUCCEEDED", result.run.report.get("failure")
        return case, result


# ------------------------------------------------------------------------------------------------ 9. the locked cover inventory
class CoverAllowListTests(SimpleTestCase):
    def setUp(self):
        self.net = Network()
        self.executor = KernelCoverExecutor(DEVICES["R3"], runner=ip_runner(self.net))
        self.executor.connect()

    def test_the_inventory_is_a_constant_of_exactly_six_routes(self):
        self.assertEqual(len(core_cover.APPROVED_COVERS), 6)
        self.assertEqual({(c.core, c.prefix) for c in core_cover.APPROVED_COVERS},
                         {(core, f"2001:db8:{n}::/63") for core in ("R3", "R4") for n in (10, 20, 30)})
        self.assertEqual({c.core: c.next_hops for c in core_cover.APPROVED_COVERS},
                         {"R3": ((R1LL, "Vlan101"), (R2LL, "Vlan103")), "R4": ((R1LL, "Vlan102"), (R2LL, "Vlan104"))})
        self.assertIs(D.covers, core_cover.APPROVED_COVERS)

    def test_a_well_formed_route_that_is_not_in_the_inventory_is_refused_and_nothing_is_sent(self):
        outside = (
            CoverRoute("R3", "2001:db8:40::/63", "2001:db8:40::/64", ((R1LL, "Vlan101"), (R2LL, "Vlan103"))),       # another prefix
            CoverRoute("R3", "2001:db8:10::/63", "2001:db8:10::/64", (("fe80::1", "Vlan101"), (R2LL, "Vlan103"))),  # another next hop
            CoverRoute("R3", "2001:db8:10::/63", "2001:db8:10::/64", ((R1LL, "Vlan102"), (R2LL, "Vlan103"))),       # another interface
            CoverRoute("R3", "2001:db8:10::/63", "2001:db8:10::/64", ((R2LL, "Vlan101"), (R1LL, "Vlan103"))),       # the next hops swapped
        )
        for route in outside:
            for spec in (core_cover.install_spec(route, "CFG-001", 1), core_cover.remove_spec(route, "CFG-002", 2)):
                with self.subTest(route=route.prefix, hops=route.next_hops, operation=spec.operation):
                    self.assertFalse(core_cover.is_approved(route))
                    found = self.executor.assess(spec)
                    self.assertEqual((found.action, found.reason), (REFUSE, core_cover.NOT_A_COVER))
                    self.assertFalse(self.executor.apply(spec, found).ok)
        self.assertEqual(self.net.sent, [])

    def test_an_approved_cover_on_the_other_core_is_refused(self):
        spec = core_cover.install_spec(D.covers_of("R4")[0], "CFG-001", 1)
        self.assertEqual(self.executor.assess(spec).action, REFUSE)

    def test_the_production_container_never_accepts_another_inventory(self):
        production = inventory.inventory_devices()["R3"]
        other = core_cover.covers_for({"R3": (("fe80::1", "eth1"), ("fe80::2", "eth2"))})
        with self.assertRaises(ExecutorError) as raised:
            KernelCoverExecutor(production, runner=ip_runner(self.net), sandbox_covers=other).connect()
        self.assertEqual(raised.exception.code, core_cover.NOT_A_COVER)
        sandbox = KernelCoverExecutor({"name": "R3", "platform": "linux", "container": "R3"}, runner=ip_runner(self.net), sandbox_covers=other)
        sandbox.connect()                                           # a disposable container may carry its own measured covers
        self.assertTrue(sandbox.allowed(other[0]))
        self.assertFalse(sandbox.allowed(D.covers_of("R3")[0]))

    def test_the_production_plan_is_blocked_when_its_covers_are_not_the_inventory(self):
        from dataclasses import replace

        changed = replace(D, covers=core_cover.covers_for({"R3": (("fe80::1", "Vlan101"), (R2LL, "Vlan103")), "R4": ((R1LL, "Vlan102"), (R2LL, "Vlan104"))}))
        codes = {row["code"] for row in migration.validate(changed, migration.forward_operations(changed))}
        self.assertIn("COVER_INVENTORY_MISMATCH", codes)

    def test_the_production_wiring_builds_the_executor_without_any_other_inventory(self):
        from core.services.route_shield import production

        executor = production.executor_for(production.devices()["R4"])
        self.assertIsNone(executor._sandbox_covers)
        self.assertTrue(all(executor.allowed(c) for c in D.covers_of("R4")))


# ------------------------------------------------------------------------------------------------------------ 6. persistence
class PersistenceTests(Flow, TestCase):
    def test_success_requires_a_verified_startup_configuration_and_nothing_temporary_is_ever_persisted(self):
        case, result = self.migrated()
        report = result.run.report
        self.assertEqual(report["persistence"]["status"], "VERIFIED")
        self.assertEqual(report["persistence"]["written"], ["R1", "R2", "S1", "S2"])
        self.assertEqual([device for device, _ in case.net.saves], ["R1", "R2", "S1", "S2"])            # once each, after the final validation
        for device, written in case.net.saves:
            self.assertFalse([p for p in written if is_temporary(p)], device)
            self.assertIn("router isis NMAS > is-type level-2", written)
        self.assertEqual(case.net.startup, case.net.paths)
        for name in D.access_devices:
            entry = report["persistence"]["devices"][name]
            self.assertEqual((entry["status"], entry["startup_digest"]), ("VERIFIED", report["permanent_intent"]["baseline_digests"][name]))
        for core in D.cores:                                                                          # the covers were never persisted
            self.assertEqual(report["persistence"]["devices"][core], {"status": "UNCHANGED", "persisted": False})
            self.assertEqual(case.net.boot[core], Network().boot[core])
        self.assertEqual(result.run.postcheck_run.report["persistence"]["S2"]["status"], "VERIFIED")
        self.assertEqual(case.plan.summary["persistence"]["devices"], ["R1", "R2", "S1", "S2"])

    def test_a_rejected_or_unverified_persistence_never_ends_succeeded_and_everything_goes_back(self):
        for attribute, device in (("fail_save", "S1"), ("lose_save", "R2"), ("lose_save", "S2")):
            with self.subTest(failure=attribute, device=device):
                case = self.prepare()
                seen = []

                def observer(event, key, case=case, attribute=attribute, device=device, seen=seen):
                    seen.append((event, key))
                    if (event, key) == ("before", f"PERSISTENCE-{device}"):
                        getattr(case.net, attribute).add(device)
                    if (event, key) == ("before", "revert-marker"):
                        getattr(case.net, attribute).discard(device)
                original = lifecycle._Attempt.compensate

                def compensate(attempt, case=case, attribute=attribute, device=device):
                    getattr(case.net, attribute).discard(device)          # the fault clears before recovery: the recovery path itself is what is proven
                    return original(attempt)
                with mock.patch.object(lifecycle._Attempt, "compensate", compensate):
                    result = self.execute(case, observer=observer)
                report = result.run.report
                self.assertEqual((result.outcome, case.change.lifecycle_state), ("POSTCHECK_FAILED_ROLLED_BACK", "ROLLED_BACK"), report.get("failure"))
                self.assertEqual(report["failure"]["code"], "PERSISTENCE_NOT_VERIFIED")
                self.assertEqual(report["persistence"]["status"], "RECOVERED")
                self.assertTrue(report["restored"])
                self.assertEqual(case.net.paths, BASELINE)
                self.assertEqual(case.net.startup, BASELINE)                                           # startup restored with the running configuration
                self.assertEqual(report["temporary_state"]["remaining"], [])
                self.assertEqual(result.run.postcheck_run.status, "FAIL")

    def test_a_startup_configuration_that_cannot_be_restored_fails_closed_with_evidence(self):
        case = self.prepare()

        def observer(event, key):
            if (event, key) == ("before", "PERSISTENCE-S1"):
                case.net.fail_save.update({"S1", "R1"})                    # S1 rejects; later R1 cannot be written back either
        result = self.execute(case, observer=observer)
        report = result.run.report
        self.assertEqual(result.outcome, "POSTCHECK_FAILED_COMPENSATION_INCOMPLETE", report.get("failure"))
        self.assertFalse(report["restored"])
        self.assertEqual(report["persistence"]["status"], "NOT_VERIFIED")
        self.assertEqual(report["persistence"]["devices"]["R1"]["recovery"], "NOT_RESTORED")
        self.assertEqual(report["persistence"]["devices"]["R2"]["recovery"], "STARTUP_RESTORED")
        self.assertEqual(case.net.paths, BASELINE)                         # the running configuration is back; the report says exactly what is not
        again = self.execute(case)
        self.assertEqual((again.outcome, {b["code"] for b in again.blockers} >= {"PRIOR_RUN_UNRESOLVED"}), ("BLOCKED", True))

    def test_an_injected_failure_during_persistence_restores_running_and_startup(self):
        case = self.prepare()

        def observer(event, key):
            if (event, key) == ("after", "PERSISTENCE-R2"):
                raise Boom()
        result = self.execute(case, observer=observer)
        report = result.run.report
        self.assertEqual(result.outcome, "FAILED_ROLLED_BACK", report.get("failure"))
        self.assertEqual(len(report["state"]["compensated"]), 48)
        self.assertEqual((case.net.paths, case.net.startup), (BASELINE, BASELINE))
        self.assertEqual([device for device, _ in case.net.saves], ["R1", "R2", "R1", "R2"])           # written, then written back

    def test_the_precheck_blocks_a_device_whose_startup_is_not_its_running_configuration(self):
        net = Network()
        net.startup["S2"].add("ipv6 route 2001:db8:77::/64 2001:db8:110:2::1")
        case = self.prepare(net)
        self.assertEqual(case.precheck.status, "BLOCKED")
        self.assertIn("STARTUP_NOT_IN_SYNC", case.precheck.summary["blockers"])
        self.assertEqual(net.sent, [])

    def test_a_cover_that_reached_the_boot_configuration_fails_the_run(self):
        case = self.prepare()

        def observer(event, key):
            if (event, key) == ("before", migration.FINAL_VALIDATION):
                case.net.boot["R3"] += "ipv6 route 2001:db8:10::/63 fe80::1 Vlan101\n"
        result = self.execute(case, observer=observer)
        self.assertNotEqual(result.outcome, "SUCCEEDED")
        self.assertEqual(case.net.saves, [])                               # no startup configuration was written at all


# ----------------------------------------------------------------------------------- 8. revert of a COMPLETED migration
class RevertTests(Flow, TestCase):
    def revert(self, case, result):
        change = lifecycle.create_revert(actor="operator", migration_run_id=str(result.run.run_id))
        return self.prepare(case.net, change=change)

    def test_the_revert_plan_is_the_migration_inverted_with_the_covers_first_and_last(self):
        forward, ops = migration.forward_operations(D), migration.revert_operations(D)
        self.assertEqual(migration.validate(D, ops), [])
        self.assertEqual(len(ops), 48)
        self.assertEqual([op.action for op in ops[:6]], [migration.COVER_INSTALL] * 6)
        self.assertEqual([op.action for op in ops[-6:]], [migration.COVER_REMOVE] * 6)
        self.assertEqual({op.device for op in ops[:6]} | {op.device for op in ops[-6:]}, {"R3", "R4"})
        for op, source in zip(ops, reversed(forward)):
            self.assertEqual((op.lines, op.inverse, op.state, op.device), (source.inverse, source.lines, source.state, source.device))
        self.assertEqual(sorted(migration.temporary_lines(ops)), sorted(migration.temporary_lines(forward)))
        self.assertNotEqual(migration.plan_hash(ops), migration.plan_hash(forward))
        first_static = next(i for i, op in enumerate(ops) if op.key == "revert-R2-client-statics-remove")
        isis_gone = next(i for i, op in enumerate(ops) if op.key == "revert-R2-isis-process")
        shield_on = next(i for i, op in enumerate(ops) if op.key == "revert-R2-shield-remove")
        shield_off = next(i for i, op in enumerate(ops) if op.key == "revert-R2-shield-install")
        self.assertLess(shield_on, first_static)                      # the old statics come back under the shield
        self.assertLess(first_static, shield_off)
        self.assertLess(shield_off, isis_gone)                        # IS-IS goes only once the statics forward again

    def test_only_a_succeeded_persisted_migration_can_be_reverted(self):
        case = self.prepare()
        with self.assertRaises(lifecycle.LifecycleError) as raised:
            lifecycle.create_revert(actor="operator", migration_run_id="00000000-0000-0000-0000-000000000000")
        self.assertEqual(raised.exception.blockers[0]["code"], "REVERT_SOURCE_NOT_SUCCEEDED")

        def observer(event, key):
            if (event, key) == ("after", "R1-shield-install"):
                raise Boom()
        failed = self.execute(case, observer=observer)
        self.assertEqual(failed.outcome, "FAILED_ROLLED_BACK")
        with self.assertRaises(lifecycle.LifecycleError):
            lifecycle.create_revert(actor="operator", migration_run_id=str(failed.run.run_id))

    def test_the_complete_revert_restores_the_pre_migration_baseline_and_its_startup(self):
        case, result = self.migrated()
        sent_before = len(case.net.sent)
        revert = self.revert(case, result)
        self.assertEqual(revert.precheck.status, "PASS", revert.precheck.report["blockers"])
        self.assertEqual(lifecycle.kind_of(revert.change), migration.REVERT_KIND)
        self.assertEqual(revert.change.metadata["transition"]["reverts"], {"change": case.change.change_id, "run_id": str(result.run.run_id)})
        done = self.execute(revert)
        report = done.run.report
        self.assertEqual((done.outcome, revert.change.lifecycle_state), ("SUCCEEDED", "DEPLOYED"), report.get("failure"))
        self.assertEqual((case.net.paths, case.net.startup), (BASELINE, BASELINE))
        self.assertEqual(report["transition"], {"kind": migration.REVERT_KIND, "definition": "production", "reverts": str(result.run.run_id)})
        self.assertEqual(report["temporary_state"]["remaining"], [])
        self.assertEqual(report["persistence"]["status"], "VERIFIED")
        self.assertEqual(report["permanent_intent"]["baseline_digests"], {n: v["config"] for n, v in result.run.report["baseline_digests"].items() if n in D.access_devices})
        sent = case.net.sent[sent_before:]
        self.assertEqual([device for device, _ in sent[:6]], ["R4"] * 3 + ["R3"] * 3)                   # covers in first ...
        self.assertTrue(all(" add " in command for _, command in sent[:6]))
        self.assertTrue(all(device in D.cores and " del " in command for device, command in sent[-6:]))   # ... and out last
        for name in D.cores:
            self.assertEqual(sorted(case.net.kernel[name]), sorted([*lab.CLIENTS, "default"]))
        self.assertEqual(case.net.routes("R1")["2001:db8:10::/64"][0], "static")
        with self.assertRaises(lifecycle.LifecycleError) as raised:                                    # one migration is reverted once
            lifecycle.create_revert(actor="operator", migration_run_id=str(result.run.run_id))
        self.assertEqual(raised.exception.blockers[0]["code"], "REVERT_ALREADY_RUN")

    def test_a_failure_inside_the_revert_returns_to_the_migrated_state(self):
        case, result = self.migrated()
        migrated_paths = {name: set(paths) for name, paths in case.net.paths.items()}
        for key in ("revert-R2-client-statics-remove", "revert-S1-isis-process", "revert-R3-cover-2001:db8:20::/63"):
            with self.subTest(failure_after=key):
                revert = self.revert(case, result)

                def observer(event, name, key=key):
                    if (event, name) == ("after", key):
                        raise Boom()
                done = self.execute(revert, observer=observer)
                self.assertEqual(done.outcome, "FAILED_ROLLED_BACK", done.run.report.get("failure"))
                self.assertEqual((case.net.paths, case.net.startup), (migrated_paths, migrated_paths))
                self.assertEqual(done.run.report["temporary_state"]["remaining"], [])

    def test_a_revert_is_blocked_when_the_devices_are_no_longer_what_the_migration_left(self):
        case, result = self.migrated()
        case.net.paths["S1"].add("ipv6 route 2001:db8:77::/64 2001:db8:110:1::1")
        case.net.startup["S1"].add("ipv6 route 2001:db8:77::/64 2001:db8:110:1::1")
        revert = self.revert(case, result)
        self.assertEqual(revert.precheck.status, "BLOCKED")
        self.assertIn("REVERT_BASIS_DRIFTED", revert.precheck.summary["blockers"])
        with self.assertRaises(lifecycle.LifecycleError):
            lifecycle.approve(revert.change, actor="approver", confirmation=revert.change.change_id, acknowledgements=ACKS)

    def test_the_revert_needs_its_own_approval_and_the_service_entry_point_refuses_it(self):
        case, result = self.migrated()
        change = lifecycle.create_revert(actor="operator", migration_run_id=str(result.run.run_id))
        lifecycle.validate_change(change, actor="operator", inventory=DEVICES)
        lifecycle.build_plan(change, actor="operator")
        lifecycle.run_precheck(change, actor="operator", env=environment(case.net))
        blocked = lifecycle._execute(change, actor="operator", confirmation=change.change_id, env=environment(case.net), definition=D)
        self.assertEqual((blocked.outcome, "NOT_APPROVED" in {b["code"] for b in blocked.blockers}), ("BLOCKED", True))
        lifecycle.approve(change, actor="approver", confirmation=change.change_id, acknowledgements=ACKS)
        change.refresh_from_db()
        refused = lifecycle.execute(change, actor="operator", confirmation=change.change_id, env=environment(case.net))
        self.assertEqual((refused.outcome, refused.blockers[0]["code"]), ("BLOCKED", "TRANSITION_PROVEN_NOT_AUTHORIZED"))
        self.assertEqual(readiness.READINESS[readiness.ISIS_TO_STATIC_IPV6_REVERT], readiness.NOT_AUTHORIZED)


# --------------------------------------------------------------------------------------- 10. gates of the live mode
class LiveModeGateTests(Flow, TestCase):
    def test_a_plan_from_another_day_is_refused(self):
        case = self.prepare()
        models.ChangePlan.objects.filter(pk=case.plan.pk).update(created_at=timezone.now() - timedelta(hours=13))
        result = self.execute(case)
        self.assertEqual(result.outcome, "BLOCKED")
        self.assertIn("PLAN_STALE", {b["code"] for b in result.blockers})
        self.assertEqual(case.net.sent, [])

    def test_an_unresolved_transition_of_any_change_blocks_every_other_one(self):
        first = self.prepare()
        first.net.fail_delete = True

        def observer(event, key):
            if (event, key) == ("after", "R4-cover-2001:db8:30::/63"):
                raise Boom()
        stuck = self.execute(first, observer=observer)
        self.assertEqual(stuck.outcome, "FAILED_COMPENSATION_INCOMPLETE")
        self.assertTrue(lifecycle.unresolved_transitions())
        other = self.prepare()
        self.assertEqual(other.precheck.status, "BLOCKED")
        self.assertIn("PRIOR_TRANSITION_UNRESOLVED", other.precheck.summary["blockers"])

    def test_the_command_has_a_read_only_mode_and_no_unsafe_override(self):
        from core.management.commands.nmas_isis_migration import Command

        parser = Command().create_parser("manage.py", "nmas_isis_migration")
        subparsers = next(action for action in parser._actions if getattr(action, "choices", None) and "execute" in action.choices)
        self.assertEqual(set(subparsers.choices), {"create", "validate", "plan", "precheck", "approve", "execute", "show", "dry-run", "source-of-truth", "create-revert"})
        forbidden = ("force", "skip", "ignore", "no-rollback", "no_rollback", "override", "unsafe", "yes", "bypass", "no-precheck", "no-probe")
        for name, sub in subparsers.choices.items():
            options = [text for action in sub._actions for text in action.option_strings]
            self.assertFalse([o for o in options if any(word in o.lower() for word in forbidden)], name)
        self.assertEqual(sorted(o for a in subparsers.choices["execute"]._actions for o in a.option_strings if o.startswith("--")),
                         ["--actor", "--change", "--confirm", "--help"])
        self.assertEqual(sorted(o for a in subparsers.choices["dry-run"]._actions for o in a.option_strings if o.startswith("--")), ["--help", "--output", "--warm-up"])

    def test_the_command_creates_a_revert_and_cannot_execute_it(self):
        case, result = self.migrated()

        def run(*args):
            out = StringIO()
            call_command("nmas_isis_migration", *args, stdout=out)
            return json.loads(out.getvalue())

        with mock.patch("core.services.route_shield.production.environment", side_effect=AssertionError("no device or probe may be touched")):
            made = run("create-revert", "--actor", "operator", "--migration-run", str(result.run.run_id))
            self.assertEqual((made["kind"], made["reverts"]["change"]), (migration.REVERT_KIND, case.change.change_id))
            self.assertEqual(run("validate", "--change", made["change"], "--actor", "operator")["validation"], "PASS")
            self.assertEqual(run("plan", "--change", made["change"], "--actor", "operator")["operations"], 48)
            refused = run("execute", "--change", made["change"], "--actor", "operator", "--confirm", made["change"])
            self.assertEqual((refused["outcome"], refused["blockers"][0]["code"]), ("BLOCKED", "TRANSITION_PROVEN_NOT_AUTHORIZED"))
            with self.assertRaises(CommandError):
                run("create-revert", "--actor", "operator", "--migration-run", "not-a-run")
            truth = run("source-of-truth")
            self.assertEqual({row["state"] for row in truth["tracked_intent"].values()}, {"POST_MIGRATION"})


# ---------------------------------------------------------------------------------------------- 4/5. the read-only dry run
class DryRunProbes(Probes):
    def __init__(self):
        super().__init__()
        self.calls = []

    def start(self):
        self.calls.append("start")

    def stop(self):
        self.calls.append("stop")

    def healthy(self):
        return self.ok, {"lost": self.count, "answered": 1000, "flows": 14, "unanswered_flows": [], "errors": []}

    def report(self):
        return [{"flow": "h1-service-v6", "destination": "2001:db8:3050::10", "answered": 1000, "lost": 0}]


NETBOX = SimpleNamespace(status="available", data={
    "prefixes": [{"prefix": "2001:db8:110:3::/64", "family": 6, "vlan": 99}],
    "ip_addresses": [{"ip": "2001:db8:110:3::1", "family": 6, "device": "S1", "interface": "Vlan99"},
                     {"ip": "2001:db8:110:3::2", "family": 6, "device": "S2", "interface": "Vlan99"}]})
TOPOLOGY = SimpleNamespace(status="available", data={"nodes": {name: {"kind": "linux" if name in D.cores else "arista_ceos"} for name in D.devices}})


class DryRunTests(TestCase):
    def run_dry(self, net, **changes):
        env = environment(net, probe_source=changes.pop("probes", None) or DryRunProbes())
        for name, value in changes.items():
            setattr(env, name, value)
        with mock.patch("core.services.nsot_live.get_live_target", return_value={"platform": "ceos"}), \
                mock.patch("core.services.validation.sources.collect_netbox", return_value=NETBOX), \
                mock.patch("core.services.validation.sources.collect_topology", return_value=TOPOLOGY):
            return dry_run.run(environment=env, warm_up_seconds=0, sleep=lambda seconds: None), env

    def test_a_healthy_production_passes_and_nothing_is_written_or_recorded(self):
        net = Network()
        counts = {model.__name__: model.objects.count() for model in (models.Change, models.ChangePlan, models.OperationalCheckRun, models.ChangeExecutionRun, models.AuditEvent)}
        report, env = self.run_dry(net)
        failed = [row for row in report["checks"] if row["status"] != "PASS"]
        self.assertEqual((report["PRODUCTION_READ_ONLY_DRY_RUN"], report["PRODUCTION_PRECHECK"], failed), ("PASS", "PASS", []))
        self.assertEqual((net.sent, net.saves, report["write_attempts"]), ([], [], []))
        self.assertEqual(env.probes.calls, ["start", "stop"])
        self.assertEqual(counts, {model.__name__: model.objects.count() for model in (models.Change, models.ChangePlan, models.OperationalCheckRun, models.ChangeExecutionRun, models.AuditEvent)})
        self.assertEqual(len(report["checks"]), 13)
        snapshot = report["snapshot"]
        self.assertEqual(set(snapshot["access"]), {"R1", "R2", "S1", "S2"})
        self.assertTrue(all(row["startup_matches_running"] and row["running_config_digest"] for row in snapshot["access"].values()))
        self.assertTrue(all(route["installed_by_static"] for row in snapshot["access"].values() for route in row["expected_static_ipv6_routes"]))
        self.assertEqual(len(snapshot["access"]["R1"]["expected_static_ipv6_routes"]), 3)
        self.assertTrue(all(row["approved_covers_absent"] and row["conflicts"] == [] and len(row["ospfv3_full_neighbours"]) == 2 for row in snapshot["core"].values()))
        self.assertEqual((snapshot["global"]["netbox_vlan99_ipv6"]["state"], snapshot["global"]["netbox_vlan99_ipv6"]["conflicts"]), ("POST_MIGRATION", []))
        self.assertEqual(snapshot["global"]["temporary_state"], {"access_devices_clean": True, "detail": "none configured", "covers_absent": True})
        self.assertEqual((snapshot["global"]["pending_migration"], snapshot["global"]["unresolved_transitions"]), ([], []))
        self.assertEqual({row["state"] for row in snapshot["global"]["tracked_intent"].values()}, {"POST_MIGRATION"})
        self.assertGreater(next(row for row in report["checks"] if row["check"] == "every postcheck reader functions")["detail"]["readers"], 40)

    def test_the_guard_refuses_and_reports_every_write_capable_call(self):
        net, guard = Network(), dry_run.WriteGuard()
        build = guard.factory(lambda device: KernelCoverExecutor(device, runner=ip_runner(net)) if device["platform"] == "linux" else SimCeos(net, device))
        core, access = build(DEVICES["R3"]), build(DEVICES["S1"])
        core.connect()
        cover = D.covers_of("R3")[0]
        spec = core_cover.install_spec(cover, "CFG-001", 1)
        for call in (lambda: core.apply(spec, core.assess(spec)), lambda: core.compensate(spec, core.assess(spec)), lambda: core._run(cover.add_argv()),
                     lambda: core._run(cover.del_argv()), lambda: core._run(["vtysh", "-c", "configure terminal"]), access.save_startup,
                     lambda: access.apply(None, None), lambda: access.compensate(None, None)):
            with self.assertRaises(ExecutorError) as raised:
                call()
            self.assertEqual(raised.exception.code, dry_run.READ_ONLY)
        self.assertEqual(len(guard.attempts), 8)
        self.assertEqual((net.sent, net.saves), ([], []))
        self.assertEqual(core.state(cover), "ABSENT")                    # reads still work

    def test_the_session_guard_lets_only_reads_through(self):
        guard, sent = dry_run.WriteGuard(), []
        connection = SimpleNamespace(send_command=lambda command, **kw: sent.append(command) or "ok", send_config_set=lambda *a, **k: sent.append("CONFIG"),
                                     config_mode=lambda **k: sent.append("MODE"))
        guard._session("R1", connection)
        self.assertEqual(connection.send_command("show running-config", read_timeout=5), "ok")
        connection.send_command("ping ipv6 2001:db8:110:1::2 repeat 2")
        for call in (lambda: connection.send_command("copy running-config startup-config"), lambda: connection.send_command("configure terminal"),
                     lambda: connection.send_command("write memory"), lambda: connection.send_config_set(["router isis X"]), connection.config_mode):
            with self.assertRaises(ExecutorError):
                call()
        self.assertEqual(sent, ["show running-config", "ping ipv6 2001:db8:110:1::2 repeat 2"])
        self.assertEqual(len(guard.attempts), 5)

    def test_a_write_attempt_fails_the_dry_run(self):
        net = Network()

        class Writing(DryRunProbes):
            def healthy(self):
                return self.ok, {"lost": 0}

        def host_gate():
            env_holder["env"].executors["S1"].save_startup()
            return True, {}
        env_holder = {}
        env = environment(net, probe_source=Writing())
        env.host_gate = host_gate
        env_holder["env"] = env
        with mock.patch("core.services.nsot_live.get_live_target", return_value={"platform": "ceos"}), \
                mock.patch("core.services.validation.sources.collect_netbox", return_value=NETBOX), \
                mock.patch("core.services.validation.sources.collect_topology", return_value=TOPOLOGY):
            report = dry_run.run(environment=env, warm_up_seconds=0, sleep=lambda seconds: None)
        self.assertEqual(report["PRODUCTION_READ_ONLY_DRY_RUN"], "FAIL")
        self.assertEqual(report["write_attempts"], ["S1: save_startup"])
        self.assertEqual(net.saves, [])

    def test_precheck_blockers_are_reported_separately_from_the_transport_verdict(self):
        net = Network()
        net.kernel["R4"]["2001:db8:20::/63"] = {"protocol": "static", "hops": [("fe80::dead", "Vlan102")]}
        report, _env = self.run_dry(net, host_gate=lambda: (False, {"failed": ["the Challenge Console is running"]}))
        self.assertEqual((report["PRODUCTION_READ_ONLY_DRY_RUN"], report["PRODUCTION_PRECHECK"]), ("PASS", "BLOCKED"))
        codes = {row["code"] for row in report["precheck"]["blockers"]}
        self.assertEqual(codes, {gates.HOST_GATE, gates.OUT_OF_BAND})
        self.assertFalse(report["snapshot"]["core"]["R4"]["approved_covers_absent"])
        self.assertTrue(report["snapshot"]["core"]["R3"]["approved_covers_absent"])

    def test_an_unreachable_device_or_missing_credential_fails_the_dry_run(self):
        net = Network()
        env = environment(net, probe_source=DryRunProbes())
        factory = env.executor_factory

        def broken(device):
            executor = factory(device)
            if device["name"] == "R2":
                executor.connect = mock.Mock(side_effect=ExecutorError("AUTH_FAILED"))
            return executor
        env.executor_factory = broken
        with mock.patch("core.services.nsot_live.get_live_target", side_effect=lambda name: None if name == "R2" else {"platform": "ceos"}):
            report = dry_run.run(environment=env, warm_up_seconds=0, sleep=lambda seconds: None)
        self.assertEqual((report["PRODUCTION_READ_ONLY_DRY_RUN"], report["PRODUCTION_PRECHECK"]), ("FAIL", "NOT_EVALUATED"))
        failed = {row["check"]: row["detail"] for row in report["checks"] if row["status"] == "FAIL"}
        self.assertEqual(failed["transport connects to all six devices"]["R2"], "AUTH_FAILED")
        self.assertIs(failed["credentials resolve for R1, R2, S1, S2 (values never read out)"]["R2"], False)


# ------------------------------------------------------------------------------------------------- 11. the window resource gate
class WindowHostGateTests(SimpleTestCase):
    def gate(self, *, load="3.10 3.40 3.60 2/900 1", swap_free=4194300, processes=(), containers=("clab-srlceos01-R1", "netbox-netbox-1"), cpu=22.0,
             probes_running=False):
        import tempfile

        with tempfile.TemporaryDirectory() as folder:
            Path(folder, "loadavg").write_text(load)
            Path(folder, "meminfo").write_text(f"MemAvailable: 60000000 kB\nSwapTotal: 4194300 kB\nSwapFree: {swap_free} kB\n")
            return gates.window_host_gate(processes=lambda: list(processes), containers=lambda: list(containers), cpu_busy=lambda: cpu, probes_running=probes_running,
                                          loadavg=str(Path(folder, "loadavg")), meminfo=str(Path(folder, "meminfo")))

    def test_a_quiet_host_passes(self):
        ok, facts = self.gate()
        self.assertTrue(ok, facts)
        self.assertEqual(facts["cpu_warning_percent"], 70.0)             # the project's own collector-alert policy
        self.assertEqual(facts["load_limit"], round(gates.QUIET_LOAD1_MAX_MEASURED * gates.QUIET_LOAD_MARGIN, 2))

    def test_each_condition_of_the_window_is_enforced(self):
        limit = gates.QUIET_LOAD1_MAX_MEASURED * gates.QUIET_LOAD_MARGIN
        cases = {
            "the Challenge Console is running": dict(processes=["/home/student/Scripts/.venv/bin/python -m challenge_console"]),
            "a Django test run is in progress": dict(processes=["python manage.py test core"]),
            "a Tier-3 run is in progress": dict(processes=["python tier3.py --mode full"]),
            "a disposable lab exists": dict(containers=["clab-srlceos01-R1", "isisbx-r1", "isisbx-c3"]),
            "swap is in use": dict(swap_free=4000000),
            "host CPU is at": dict(cpu=71.0),
            "is above the measured quiet baseline limit": dict(load=f"{limit + 0.5:.2f} 3.00 3.00 2/900 1"),
        }
        for reason, change in cases.items():
            with self.subTest(reason=reason):
                ok, facts = self.gate(**change)
                self.assertFalse(ok)
                self.assertEqual(len(facts["failed"]), 1, facts["failed"])
                self.assertIn(reason, facts["failed"][0])
        ok, facts = self.gate(load=f"3.00 {limit + 0.5:.2f} 3.00 2/900 1")           # a host that was busy a minute ago is not stable yet
        self.assertFalse(ok)
        ok, facts = self.gate(processes=["/bin/bash -c grep -r 'python -m challenge_console' docs", "vim tier3.py", "less manage.py test notes"])
        self.assertTrue(ok, facts)                                                    # text that mentions a process is not that process

    def test_unreadable_host_facts_fail_closed(self):
        self.assertEqual(gates.window_host_gate(loadavg="/nonexistent/loadavg"), (False, {"failed": ["host facts unreadable"]}))

    def test_with_the_probes_running_cpu_is_held_below_critical_and_load_is_reported_only(self):
        ok, facts = self.gate(cpu=83.0, load="17.30 11.89 9.00 2/900 1", probes_running=True)
        self.assertTrue(ok, facts)
        self.assertEqual((facts["phase"], facts["cpu_critical_percent"]), ("PROBED", 90.0))
        self.assertFalse(self.gate(cpu=90.0, probes_running=True)[0])
        for change in (dict(processes=["/usr/bin/python3 -m challenge_console"]), dict(containers=["isisbx-r1"]), dict(swap_free=4000000)):
            self.assertFalse(self.gate(probes_running=True, **change)[0])

    def test_the_production_environment_measures_the_quiet_host_before_the_probes_start(self):
        from core.services.route_shield import production

        order = []
        quiet = {"ok": True}

        def gate(*, probes_running):
            order.append("probed-gate" if probes_running else "quiet-gate")
            return (True, {"failed": []}) if probes_running or quiet["ok"] else (False, {"failed": ["the Challenge Console is running"]})
        with mock.patch.object(production, "flows", return_value=[production.probes.Flow("h1-service-v6", "c", "2001:db8:3050::10")]):
            env = production.environment()
        self.assertIsInstance(env.host_gate, gates.WindowGate)
        self.assertEqual(gates.WindowGate(gate)(), (False, {"failed": ["the quiet-host gate was not evaluated before the probes started"]}))
        env.host_gate = gates.WindowGate(gate)
        env.probes = SimpleNamespace(start=lambda: order.append("probes-start"))
        production.start_probes(env)
        self.assertEqual(env.host_gate()[0], True)
        self.assertEqual(order, ["quiet-gate", "probes-start", "probed-gate"])
        quiet["ok"] = False                                              # a host that was not quiet stays refused once the probes run
        env.host_gate.measure_quiet()
        self.assertEqual(env.host_gate(), (False, {"failed": ["the Challenge Console is running"], "quiet": {"failed": ["the Challenge Console is running"]}}))


class UptimeTests(SimpleTestCase):
    def test_every_form_frr_prints_is_read_and_nothing_else_is_guessed(self):
        for text, seconds in (("00:02:05", 125), ("23:59:59", 86399), ("4d21h45m", 4 * 86400 + 21 * 3600 + 45 * 60), ("01w2d03h", 604800 + 2 * 86400 + 3 * 3600),
                              ("1d00h00m", 86400)):
            self.assertEqual(core_cover.uptime_seconds(text), seconds, text)
        for text in ("", "never", "4 days", "1:2"):
            with self.assertRaises(ValueError):
                core_cover.uptime_seconds(text)

    def test_a_route_that_is_days_old_is_installed_and_quiet(self):
        net = Network()
        net.quiet = "4d21h45m"
        executor = KernelCoverExecutor(DEVICES["R3"], runner=ip_runner(net))
        executor.connect()
        self.assertEqual(executor.client_route("2001:db8:10::/64"), {"installed": True, "active_next_hops": 2, "quiet_seconds": 423900})


# ------------------------------------------------------------------------------------------ 7. permanent source of truth
class SourceOfTruthTests(SimpleTestCase):
    def test_the_tracked_templates_are_the_migrated_baseline(self):
        state = source_of_truth.tracked_state()
        self.assertEqual(set(state), {"R1", "R2", "S1", "S2"})                                  # R3 and R4 have no intent to update
        self.assertEqual({row["state"] for row in state.values()}, {source_of_truth.POST_MIGRATION})   # CHG-20261012-0002 SUCCEEDED
        self.assertTrue(all(row["superseded_present"] == 0 and row["temporary_present"] == [] for row in state.values()))

    def test_the_tracked_templates_are_the_reviewed_copies_and_hold_nothing_temporary(self):
        reviewed = Path(settings.REPO_ROOT) / source_of_truth.REVIEWED_COPIES
        for device in D.access_devices:
            with self.subTest(device=device):
                tracked = source_of_truth.template_path(device).read_text(encoding="utf-8")
                self.assertEqual((reviewed / f"{device}.cfg.j2").read_text(encoding="utf-8"), tracked)   # applied once, by review
                state = source_of_truth._state(tracked, device, D)
                self.assertEqual((state["state"], state["superseded_present"], state["temporary_present"]), (source_of_truth.POST_MIGRATION, 0, []))
                self.assertFalse([line for line in tracked.splitlines() if "/63" in line or "/33" in line or line.rstrip().endswith(" 250")])
                self.assertEqual(tracked.count(source_of_truth.MARKER), 1)
                self.assertEqual(source_of_truth.intent_template(device, tracked).count(source_of_truth.MARKER), 2)   # not idempotent by design
        self.assertEqual(sorted(p.name for p in reviewed.iterdir()), ["R1.cfg.j2", "R2.cfg.j2", "S1.cfg.j2", "S2.cfg.j2"])

    def test_every_required_update_is_named_with_its_verification(self):
        rows = source_of_truth.required_updates()
        self.assertEqual([row["target"] for row in rows][:4], [f"templates/{d}.cfg.j2" for d in D.access_devices])
        self.assertEqual([row["kind"] for row in rows].count("TEMPORARY_EXECUTION_EVIDENCE"), 1)
        self.assertTrue(all(row["update"] and row["verify"] for row in rows))
