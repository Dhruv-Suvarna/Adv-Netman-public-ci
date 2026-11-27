"""Direct tests for the small reviewed operator controllers.

Covered: the worker credential sync (deploy/credentials), the additive diagnostic target overlay, the sandbox policy
renderer, the Stage B inventory eligibility report (deploy/sandbox) and the fault-campaign harness (break.py).

Each controller is loaded by file path and driven through its real entry points.  Only the host boundary is faked:
root ownership of fixture files, ``nft`` / ``ip``, and ``systemctl``.  No namespace, firewall, unit or device is touched.
"""

from __future__ import annotations

import importlib.util
import io
import json
import os
import pwd
import sqlite3
import subprocess
import sys
import tempfile
from contextlib import ExitStack, redirect_stdout
from pathlib import Path, PosixPath
from unittest import mock

from django.test import SimpleTestCase

ROOT = Path(__file__).resolve().parents[3]
SANDBOX = ROOT / "deploy" / "sandbox"


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


swc = _load("sync_worker_credential", ROOT / "deploy" / "credentials" / "sync_worker_credential.py")
dto = _load("diagnostic_target_overlay", SANDBOX / "diagnostic_target_overlay.py")
rp = _load("render_policy_units", SANDBOX / "render_policy.py")
sbi = _load("stage_b_inventory", SANDBOX / "stage_b_inventory.py")
brk = _load("nmas_break", ROOT / "break.py")
inventory_suite = _load("stage_b_inventory_suite", SANDBOX / "test_stage_b_inventory.py")
ME = pwd.getpwuid(os.geteuid()).pw_name


class Temp(SimpleTestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.tmp = Path(tmp.name)


# ===================================================================================== worker credential sync
FULL_STORE = {"schema_version": 2, "secrets": {"r1-nmas-diag": {"current": "c1", "pending": None, "history": ["old"]},
                                               "r1-admin": {"current": "admin-secret", "pending": None}}}


class WorkerCredentialSyncTests(Temp):
    def test_restricted_returns_only_allowlisted_current_and_pending(self):
        self.assertEqual(swc.restricted(FULL_STORE, ["r1-nmas-diag"]),
                         {"schema_version": 2, "secrets": {"r1-nmas-diag": {"current": "c1", "pending": None}}})

    def test_restricted_refuses_a_store_without_the_allowlisted_identity(self):
        for label, store in (("a missing identity", {"secrets": {}}), ("no secrets map", {"secrets": []})):
            with self.subTest(f"{label} is refused"), self.assertRaises(swc.SyncError):
                swc.restricted(store, ["r1-nmas-diag"])

    def test_write_atomic_writes_a_private_owned_copy(self):
        target = self.tmp / "copy.json"
        swc.write_atomic(str(target), {"a": 1}, ME)
        self.assertEqual((json.loads(target.read_text()), oct(target.stat().st_mode & 0o777)), ({"a": 1}, "0o600"))
        self.assertEqual(list(self.tmp.glob(".worker-store.*")), [])

    def test_write_atomic_refuses_an_unknown_owner(self):
        with self.assertRaises(KeyError):
            swc.write_atomic(str(self.tmp / "copy.json"), {"a": 1}, "nmas-no-such-account")
        self.assertFalse((self.tmp / "copy.json").exists())

    def test_sync_copies_once_then_reports_unchanged(self):
        full, copy = self.tmp / "store.json", self.tmp / "copy.json"
        full.write_text(json.dumps(FULL_STORE))
        restarts = []
        self.assertEqual(swc.sync(str(full), str(copy), ["r1-nmas-diag"], ME, lambda: restarts.append(1)), "SYNCED")
        self.assertEqual(swc.sync(str(full), str(copy), ["r1-nmas-diag"], ME, lambda: restarts.append(1)), "UNCHANGED")
        self.assertEqual(restarts, [1])
        self.assertNotIn("admin-secret", copy.read_text())

    def test_sync_refuses_a_store_missing_an_identity_and_never_restarts(self):
        full = self.tmp / "store.json"
        full.write_text(json.dumps({"secrets": {}}))
        restart = mock.Mock()
        with self.assertRaises(swc.SyncError):
            swc.sync(str(full), str(self.tmp / "copy.json"), ["r1-nmas-diag"], ME, restart)
        restart.assert_not_called()

    def test_main_returns_zero_and_prints_identity_names_only(self):
        full = self.tmp / "store.json"
        full.write_text(json.dumps(FULL_STORE))
        out = io.StringIO()
        with redirect_stdout(out):
            rc = swc.main(["--full", str(full), "--copy", str(self.tmp / "copy.json"), "--allow", "r1-nmas-diag",
                           "--owner", ME, "--no-restart"])
        self.assertEqual(rc, 0)
        self.assertIn("SYNCED: r1-nmas-diag", out.getvalue())
        self.assertNotIn("c1", out.getvalue().replace("SYNCED", ""))

    def test_main_fails_closed_for_an_unreadable_store(self):
        with mock.patch.object(sys, "stderr", io.StringIO()) as err:
            self.assertEqual(swc.main(["--full", str(self.tmp / "absent.json"), "--copy", str(self.tmp / "c.json"), "--no-restart"]), 1)
        self.assertIn("FAILED", err.getvalue())


# =============================================================================== diagnostic target overlay
class FakeNetwork:
    """The diagnostic host table, namespace table and namespace routes, reached only through ``_run``."""

    def __init__(self, base_targets):
        self.host, self.ns = set(base_targets), set(base_targets)
        self.routes = {t.rsplit(":", 1)[0] for t in base_targets}
        self.calls = []

    @staticmethod
    def doc(elements):
        return json.dumps({"nftables": [{"set": {"elem": [{"concat": [e.rsplit(":", 1)[0], 22]} for e in sorted(elements)]}}]})

    def __call__(self, *argv, capture=False, check=True):
        del capture, check
        self.calls.append(argv)
        ns = argv[:4] == ("ip", "netns", "exec", dto.NAMESPACE)
        cmd = argv[4:] if ns else argv
        table = self.ns if ns else self.host
        out = ""
        if cmd[:4] == ("nft", "-j", "list", "set"):
            out = self.doc(table)
        elif cmd[:3] in (("nft", "add", "element"), ("nft", "delete", "element")):
            element = cmd[7].replace(" . ", ":")
            (table.add if cmd[1] == "add" else table.discard)(element)
        elif argv[:5] == ("ip", "-j", "-n", dto.NAMESPACE, "-4"):
            out = json.dumps([{"dst": r, "gateway": "169.254.86.1"} for r in sorted(self.routes)])
        elif argv[:4] == ("ip", "-n", dto.NAMESPACE, "route"):
            address = argv[5].split("/")[0]
            (self.routes.add if argv[4] == "add" else self.routes.discard)(address)
        return subprocess.CompletedProcess(argv, 0, out, "")


class DiagnosticOverlayTests(Temp):
    BASE = ["192.168.200.1:22"]

    def setUp(self):
        super().setUp()
        self.config, self.state, self.receipt = self.tmp / "diagnostic.env", self.tmp / "diagnostic.json", self.tmp / "ns" / "overlay.json"
        self.config.write_text("ACTIVATION_ID=TEST-ACTIVATION-DIAG-0001\nIPV4_GATEWAY=169.254.86.1\nTARGETS=tcp:192.168.200.1:22\n")
        self.config.chmod(0o644)
        self.state.write_text(json.dumps({"status": "active", "namespace": dto.NAMESPACE, "activation_id": "TEST-ACTIVATION-DIAG-0001",
                                          "config_digest": "a" * 64}))
        self.state.chmod(0o600)
        self.policy_path = self.tmp / "policy.json"
        self.policy_path.write_text(json.dumps({"schema": dto.SCHEMA, "overlay_id": "OVERLAY-TEST-0001",
                                                "base_activation_id": "TEST-ACTIVATION-DIAG-0001", "base_config_digest": "a" * 64,
                                                "authorization_id": "CHG-NMAS-TEST-0001", "expires_at": "2999-01-01T00:00:00Z",
                                                "targets": [{"address": "192.168.200.7", "port": 22}]}))
        self.policy_path.chmod(0o600)
        self.net = FakeNetwork(self.BASE)
        real_lstat, fixtures = PosixPath.lstat, {self.config, self.state, self.policy_path, self.receipt}

        def root_owned(path):                        # the fixture files stand in for root-owned files
            info = real_lstat(path)
            if path not in fixtures:
                return info
            fields = list(info)
            fields[4] = fields[5] = 0
            return os.stat_result(fields)
        stack = ExitStack()
        self.addCleanup(stack.close)
        stack.enter_context(mock.patch.object(PosixPath, "lstat", root_owned))
        for name, value in (("BASE_CONFIG", self.config), ("BASE_STATE", self.state), ("RECEIPT", self.receipt), ("_run", self.net)):
            stack.enter_context(mock.patch.object(dto, name, value))
        self.policy, self.digest = dto._policy(self.policy_path)   # pylint: disable=protected-access  # the controller's own policy loader

    def test_apply_adds_the_exact_target_and_records_a_receipt(self):
        self.assertEqual(dto.apply(self.policy, self.digest), {"status": "active", "overlay_id": "OVERLAY-TEST-0001", "targets": 1})
        self.assertEqual((self.net.host, self.net.routes), ({"192.168.200.1:22", "192.168.200.7:22"}, {"192.168.200.1", "192.168.200.7"}))
        self.assertEqual(json.loads(self.receipt.read_text())["policy_sha256"], self.digest)

    def test_apply_refuses_a_policy_bound_to_another_base_and_changes_nothing(self):
        with self.assertRaises(dto.Refused):
            dto.apply({**self.policy, "base_config_digest": "b" * 64}, self.digest)
        self.assertEqual(self.net.calls, [])

    def test_validate_confirms_the_applied_overlay(self):
        dto.apply(self.policy, self.digest)
        self.assertEqual(dto.validate(self.policy, self.digest)["status"], "active")

    def test_validate_refuses_a_set_that_drifted_from_the_policy(self):
        dto.apply(self.policy, self.digest)
        self.net.ns.add("10.0.0.9:22")
        with self.assertRaises(dto.Refused):
            dto.validate(self.policy, self.digest)

    def test_rollback_removes_only_the_overlay_targets(self):
        dto.apply(self.policy, self.digest)
        self.assertEqual(dto.rollback(self.policy, self.digest)["status"], "rolled_back")
        self.assertEqual((self.net.host, self.net.ns, self.net.routes), ({"192.168.200.1:22"}, {"192.168.200.1:22"}, {"192.168.200.1"}))
        self.assertEqual(json.loads(self.receipt.read_text())["status"], "rolled_back")

    def test_rollback_refuses_while_the_base_namespace_is_inactive(self):
        self.state.write_text(json.dumps({"status": "rollback", "namespace": dto.NAMESPACE}))
        with self.assertRaises(dto.Refused):
            dto.rollback(self.policy, self.digest)

    def test_main_returns_zero_and_prints_the_validation(self):
        dto.apply(self.policy, self.digest)
        out = io.StringIO()
        with mock.patch.object(sys, "argv", ["diagnostic_target_overlay.py", "validate", str(self.policy_path)]), redirect_stdout(out):
            self.assertEqual(dto.main(), 0)
        self.assertEqual(json.loads(out.getvalue())["targets"], 1)


# ======================================================================================== sandbox policy renderer
def reviewed_manifest():
    return {"topology_id": "srlceos01", "inventory_revision": "a" * 64,
            "deployment_paths": {"production_database": "/home/student/Scripts/clab_dualstack_lab-deploy/web/db.sqlite3",
                                 "production_web_directory": "/home/student/Scripts/clab_dualstack_lab-deploy/web",
                                 "production_inventory": "/home/student/Scripts/clab_dualstack_lab-deploy/inventory.yml",
                                 "device_credential_store":
                                     "/home/student/Scripts/clab_dualstack_lab-deploy/monitoring/runtime/device-credentials/store.json"},
            "protected_addresses": ["192.168.200.100"],
            "approved_targets": [{"device": "R6", "identity_state": "VERIFIED", "lifecycle_state": "IN_SERVICE", "admission_state": "ADMITTED",
                                  "approved_paths": [{"address": "192.168.200.6", "port": 22, "transport": "SSH"}]}],
            "dns_resolvers": ["1.1.1.1"],
            "research_destinations": [{"hostname": "www.rfc-editor.org", "addresses": ["104.18.20.81"]}]}


class RenderPolicyTests(Temp):
    def test_validate_returns_exact_endpoints_resolvers_and_destinations(self):
        self.assertEqual(rp.validate(reviewed_manifest()), ([("192.168.200.6", 22)], ["1.1.1.1"], {"www.rfc-editor.org": ["104.18.20.81"]}))

    def test_render_refuses_a_deployment_path_outside_production(self):
        manifest = reviewed_manifest()
        manifest["deployment_paths"]["production_database"] = "/tmp/other.sqlite3"
        with self.assertRaises(rp.ManifestRefused):
            rp.render(manifest, "@DEVICE_IP_ADDRESS_ALLOW@\n", "@DNS4@\n")

    def test_main_returns_zero_and_writes_private_activation_files(self):
        manifest = self.tmp / "manifest.json"
        manifest.write_text(json.dumps(reviewed_manifest()))
        with mock.patch.object(sys, "argv", ["render_policy.py", str(manifest), "--output", str(self.tmp / "out")]):
            self.assertEqual(rp.main(), 0)
        self.assertEqual((self.tmp / "out/diagnostic-targets.env").read_text(), "TARGETS=tcp:192.168.200.6:22\n")
        self.assertEqual(oct((self.tmp / "out/research-egress.nft").stat().st_mode & 0o777), "0o600")


# ===================================================================================== Stage B inventory report
class StageBInventoryTests(Temp):
    def fixture(self):
        """The standalone suite's inventory/topology/database, created by running its own main in a captured temp root."""
        captured = {}
        real = sbi.report

        def keep(inventory, database, topology=None):
            for path in (inventory, database, topology):
                (self.tmp / path.name).write_bytes(path.read_bytes())
            captured["paths"] = (self.tmp / inventory.name, self.tmp / database.name, self.tmp / topology.name)
            return real(inventory, database, topology)
        with mock.patch.object(inventory_suite.MODULE, "report", keep), redirect_stdout(io.StringIO()):
            inventory_suite.main()
        return captured["paths"]

    def test_report_returns_approved_paths_and_ready_candidates(self):
        inventory, database, topology = self.fixture()
        value = sbi.report(inventory, database, topology)
        self.assertEqual([row["device"] for row in value["approved_eligible"]], ["R1"])
        self.assertTrue({row["device"]: row for row in value["candidate_batch"]}["R1"]["approval_ready"])
        self.assertFalse(value["governance"]["discovery_is_approval"])

    def test_report_never_marks_an_unverified_device_ready_and_refuses_a_missing_database(self):
        inventory, database, topology = self.fixture()
        rows = {row["device"]: row for row in sbi.report(inventory, database, topology)["candidate_batch"]}
        self.assertFalse(rows["R2"]["approval_ready"])
        self.assertIn("IDENTITY_UNVERIFIED", rows["R2"]["blockers"])
        with self.subTest("a missing database is refused"), self.assertRaises(sqlite3.OperationalError):
            sbi.report(inventory, self.tmp / "absent.sqlite3", topology)

    def test_main_returns_zero_and_writes_the_report(self):
        inventory, database, topology = self.fixture()
        out = self.tmp / "report.json"
        argv = ["stage_b_inventory.py", "--inventory", str(inventory), "--topology", str(topology), "--database", str(database), "--output", str(out)]
        with mock.patch.object(sys, "argv", argv):
            self.assertEqual(sbi.main(), 0)
        self.assertEqual(json.loads(out.read_text())["schema"], "nmas.stage-b-diagnostic-eligibility/1")


# ======================================================================================== fault-campaign harness
class BreakHarnessTests(Temp):
    def policy_file(self, *, live: bool) -> Path:
        policy = json.loads((SANDBOX / "fault-campaign.fixture.json").read_text(encoding="utf-8"))
        if live:
            policy["campaign"]["fixture_only"], policy["topology"] = False, "srlceos01"
        path = self.tmp / ("live.json" if live else "fixture.json")
        path.write_text(json.dumps(policy))
        return path

    def test_parser_returns_the_fixture_state_default(self):
        args = brk.parser().parse_args(["digest", "--policy", "p.json"])
        self.assertEqual((args.action, args.state_dir, args.poll_seconds), ("digest", "/tmp/nmas-fault-fixture", 5))

    def test_main_returns_zero_for_a_policy_digest(self):
        out = io.StringIO()
        with mock.patch.object(sys, "argv", ["break.py", "digest", "--policy", str(self.policy_file(live=False))]), redirect_stdout(out):
            self.assertEqual(brk.main(), 0)
        self.assertEqual(len(json.loads(out.getvalue())["policy_sha256"]), 64)

    def test_live_status_returns_the_campaign_summary_only(self):
        path = self.policy_file(live=True)
        state_dir = self.tmp / "live-state"
        state_dir.mkdir(mode=0o700)
        (state_dir / "FIXTURE-CAMPAIGN-1.json").write_text(json.dumps({"campaign_id": "FIXTURE-CAMPAIGN-1", "status": "RESTORED",
                                                                        "fault": "ground truth", "events": [1, 2]}))
        (self.tmp / "flows.json").write_text("{}")
        args = brk.parser().parse_args(["status", "--policy", str(path), "--fault-id", "fixture-link-down", "--flow-map",
                                        str(self.tmp / "flows.json"), "--live-state-dir", str(state_dir)])
        out = io.StringIO()
        with redirect_stdout(out):
            self.assertEqual(brk.live(args, brk.fi.load_policy(str(path))), 0)
        summary = json.loads(out.getvalue())
        self.assertEqual((summary["status"], summary["event_count"]), ("RESTORED", 2))
        self.assertNotIn("ground truth", out.getvalue())

    def test_live_refuses_a_fixture_only_policy(self):
        path = self.policy_file(live=False)
        args = brk.parser().parse_args(["run", "--policy", str(path), "--fault-id", "fixture-link-down", "--flow-map", "x.json"])
        with self.assertRaises(brk.fi.FaultRefused) as caught:
            brk.live(args, brk.fi.load_policy(str(path)))
        self.assertEqual(caught.exception.code, "LIVE_POLICY_REQUIRED")
