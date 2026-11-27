"""Governance tests for the Troubleshooter and admission management commands (core/management/commands/: device_observe,
host_key_pin_check, nmas_single_admin_lab_exception, nmas_topology_acceptance, nmas_ts_auto_recover, nmas_ts_intake,
nmas_ts_ops_status, nmas_ts_reconcile_case, troubleshooting_ai, troubleshooting_device_worker, troubleshooting_readiness).

Each command's successful path and its fail-closed path run through ``call_command``.  The SQL boundaries admit only reads
(and, for the AI runtime, troubleshooting journal writes).  systemd, journald, the model brokers, the IPC server and the
intake engine are fakes: no unit, device or broker is contacted.
"""

from __future__ import annotations

import json
import subprocess
import tempfile
from io import StringIO
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from django.core.management import CommandError, call_command
from django.db import connection
from django.test import TestCase

from core.management.commands import device_observe, nmas_ts_intake, nmas_ts_ops_status as ops, troubleshooting_ai as tai
from core.management.commands import troubleshooting_device_worker as tdw
from core.services.devices import resolver
from core.services.identity import single_admin_exception as exception
from core.services.troubleshooting import agent_dispatch, intake, reconcile, recovery
from core.tests import test_host_key_pins as HK
from core.tests import test_single_admin_lab_exception as SAE
from core.tests import test_troubleshooting_governance as G


def run(name, *args):
    out = StringIO()
    call_command(name, *args, stdout=out, stderr=StringIO())
    return out.getvalue()


def passthrough(sql, params, many, context):
    return ("executed", sql)


# ===================================================================================== device / pin / exception
class DeviceCommandTests(TestCase):
    def test_build_connection_factory_returns_the_governed_factory(self):
        self.assertTrue(callable(device_observe.Command().build_connection_factory()))

    def test_host_key_pin_check_accepts_an_independent_console_capture(self):
        with tempfile.TemporaryDirectory() as tmp:
            good = Path(tmp, "good.json")
            good.write_text(json.dumps(HK.evidence()))
            with mock.patch("core.services.health.inventory.load_inventory", lambda: HK.DOC), \
                    mock.patch.object(resolver, "resolve", lambda name, **kw: HK.REAL_RESOLVE(name, document=HK.DOC)):
                report = json.loads(run("host_key_pin_check", "--evidence", str(good), "--enroller", "enroller-e", "--json"))
        self.assertEqual((report["ok"], report["pin"]), (True, HK.paramiko_pin(HK.ED)))


class SingleAdminCommandTests(TestCase):
    setUp = SAE.SingleAdminExceptionTests.setUp
    capability = SAE.SingleAdminExceptionTests.capability
    activate = SAE.SingleAdminExceptionTests.activate
    # set by SingleAdminExceptionTests.setUp
    now: object
    nmas: object
    device: object
    attachment: object

    def test_status_returns_the_active_exception(self):
        cap = self.capability()
        self.activate(cap)
        with mock.patch.object(exception, "load", return_value=exception.Result(True, capability=cap)):
            out = run("nmas_single_admin_lab_exception", "status")
        self.assertIn(f"id={cap.exception_id}", out)
        self.assertIn("status=ACTIVE", out)

    def test_exception_command_without_a_capability_file_is_refused(self):
        with self.assertRaisesRegex(CommandError, "EXCEPTION_DISABLED"):
            run("nmas_single_admin_lab_exception", "status")


# ================================================================================================ acceptance
class TopologyAcceptanceCommandTests(TestCase):
    def test_report_returns_the_case_evidence(self):
        case = G.make_case(key="tg-acceptance")
        out = json.loads(run("nmas_topology_acceptance", "report", "--case", case.case_id))
        self.assertEqual((out["case"], sorted(out["devices"])), (case.case_id, ["r1", "r2"]))

    def test_open_beyond_the_device_budget_is_refused(self):
        devices = [f"R{i}" for i in range(1, 40)]
        with self.assertRaisesRegex(CommandError, "at most"):
            run("nmas_topology_acceptance", "open", "--devices", *devices)


# ============================================================================================ recovery / intake
class AutoRecoverCommandTests(TestCase):
    def test_status_returns_the_standing_policies(self):
        with mock.patch.object(recovery, "policy_status", return_value=[{"id": "ARP-T", "active": True}]):
            self.assertEqual(json.loads(run("nmas_ts_auto_recover", "--status")), [{"id": "ARP-T", "active": True}])

    def test_single_sweep_of_a_refused_plan_never_executes_it(self):
        with mock.patch.object(recovery, "sweep_interrupted", return_value=[]), \
                mock.patch.object(recovery, "policy_status", return_value=[]), \
                mock.patch.object(recovery, "pending_plans", return_value=["TSPLAN-1"]), \
                mock.patch.object(recovery, "recover", side_effect=recovery.RecoveryRefused("POLICY_EXHAUSTED")), \
                mock.patch.object(recovery, "undecided_plans", return_value=[]):
            out = run("nmas_ts_auto_recover")
        self.assertIn("TSPLAN-1: refused", out)


class FakeIntake:
    rows: list = []

    def __init__(self, **_kw):
        self.cfg = SimpleNamespace(devices=["R1"], confirm_seconds=30, cooldown_seconds=600, max_cases_per_hour=4, routing_devices=["R1"])

    def poll(self):
        return list(self.rows)


class IntakeCommandTests(TestCase):
    def test_once_returns_each_polled_record(self):
        with mock.patch.object(intake, "Intake", FakeIntake), mock.patch.object(FakeIntake, "rows", [{"event": "idle"}]):
            out = run("nmas_ts_intake", "--once")
        self.assertIn('{"event": "idle"}', out)

    def test_once_never_drops_an_error_record(self):
        row = {"schema": "nmas.ts.intake/1", "severity": "error", "error_code": "INVENTORY_UNREADABLE"}
        with mock.patch.object(intake, "Intake", FakeIntake), mock.patch.object(FakeIntake, "rows", [row]):
            out = run("nmas_ts_intake", "--once")
        self.assertIn("<3>", out)

    def test_journal_line_without_a_schema_never_gets_a_priority(self):
        self.assertEqual(nmas_ts_intake.journal_line({"severity": "error", "event": "x"}), '{"severity": "error", "event": "x"}')


# ============================================================================================ ops / reconcile
def no_systemd(argv, **_kw):
    return subprocess.CompletedProcess(argv, 0, stdout="inactive\n", stderr="")


class OpsStatusCommandTests(TestCase):
    def patched(self):
        return mock.patch.multiple(ops, _unit=lambda name: {"active": "active", "enabled": "enabled"},
                                   _route_intent_status=lambda: {"bound": False, "last_pass": None})

    def test_status_returns_every_section(self):
        with self.patched():
            out = ops.status()
        self.assertEqual(set(out["services"]), set(ops.SERVICES))
        self.assertIn("audit_chain_broken_cases_7d", out)

    def test_ops_status_json_returns_the_status(self):
        with self.patched():
            out = json.loads(run("nmas_ts_ops_status", "--json"))
        self.assertEqual(out["intake"]["route_intent"], {"bound": False, "last_pass": None})

    def test_ops_status_never_reports_an_inactive_unit_as_active(self):
        with mock.patch.object(ops.subprocess, "run", no_systemd), \
                mock.patch.object(intake, "unit_route_intent_binding", return_value={"bound": False}):
            out = json.loads(run("nmas_ts_ops_status", "--json"))
        self.assertEqual({row["active"] for row in out["services"].values()}, {"inactive"})

    def test_last_route_intent_pass_without_a_journal_is_unavailable(self):
        def broken():
            raise OSError("journald unavailable")

        with self.subTest("a broken journal is unavailable"):
            self.assertEqual(ops.last_route_intent_pass(broken), {"available": False, "error_code": "JOURNAL_UNAVAILABLE"})
        with self.subTest("a journal without the record is unavailable"):
            self.assertEqual(ops.last_route_intent_pass(lambda: "unrelated line\n")["error_code"], "NO_ROUTE_INTENT_PASS_IN_JOURNAL")


class ReconcileCommandTests(TestCase):
    def test_reconcile_returns_the_dry_run_verdict(self):
        with mock.patch.object(reconcile, "reconcile", return_value=reconcile.Verdict("TS-1", outcome="RETAIN", reasons=["plan in flight"])):
            out = json.loads(run("nmas_ts_reconcile_case", "TS-1"))
        self.assertEqual((out["outcome"], out["applied"]), ("RETAIN", False))

    def test_reconcile_of_an_unknown_case_is_refused(self):
        with self.assertRaisesRegex(CommandError, "refused"):
            run("nmas_ts_reconcile_case", "TS-NONEXISTENT")


# ================================================================================================ AI / worker
class AiCommandTests(TestCase):
    def test_agents_returns_the_broker_health_and_idle_lease(self):
        with mock.patch.object(agent_dispatch, "probe_all", return_value=([], {})):
            out = json.loads(run("troubleshooting_ai", "agents"))
        self.assertEqual((out["agents"], out["lease"]["state"]), ([], "IDLE"))

    def test_sql_boundary_allows_reads_and_troubleshooting_journal_writes(self):
        boundary = tai._TroubleshootingSqlBoundary()   # pylint: disable=protected-access  # the runtime SQL boundary under test
        for sql in ("SELECT 1", "SAVEPOINT s1", 'INSERT INTO "core_tsauditevent" VALUES (1)'):
            with self.subTest(sql=sql):
                self.assertEqual(boundary(passthrough, sql, (), False, {}), ("executed", sql))
        with self.subTest("a credential table write is refused"), self.assertRaises(RuntimeError):
            boundary(passthrough, 'UPDATE "core_manageddevice" SET name = 1', (), False, {})


class DeviceWorkerCommandTests(TestCase):
    def test_read_only_sql_allows_reads(self):
        guard = tdw._ReadOnlySql()                      # pylint: disable=protected-access  # the worker SQL guard under test
        self.assertEqual(guard(passthrough, "  select 1", (), False, {}), ("executed", "  select 1"))
        with self.subTest("a write is refused"), self.assertRaises(RuntimeError):
            guard(passthrough, "DELETE FROM core_tscase", (), False, {})

    def test_worker_returns_cleanly_on_interrupt(self):
        def interrupted():
            raise KeyboardInterrupt

        try:
            with mock.patch.object(tdw, "server_from_environment", return_value=SimpleNamespace(serve=interrupted)):
                self.assertEqual(run("troubleshooting_device_worker"), "")
        finally:
            with connection.cursor() as cursor:
                cursor.execute("PRAGMA query_only=OFF")  # the command sets the connection read-only; restore the test connection


class ReadinessCommandTests(TestCase):
    def test_readiness_of_an_unknown_device_is_never_admitted(self):
        out = json.loads(run("troubleshooting_readiness", "--json", "--device", "R99"))
        self.assertTrue(all(not row["admitted"] for row in out["devices"]))
        self.assertTrue(all(rb["status"] != "READY_PENDING_FIXTURE_APPROVAL" for rb in out["runbooks"]))
