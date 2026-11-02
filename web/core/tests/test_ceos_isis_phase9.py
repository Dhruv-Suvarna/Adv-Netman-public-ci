"""Focused cEOS IS-IS closure contracts; no device is contacted by these tests."""

import importlib.util
import json
import os
import subprocess
import tempfile
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from django.test import SimpleTestCase, TestCase

from core.services.capabilities import batch_ceos_isis, fixture_ceos_ssh
from core.services.capabilities.batch_ceos_isis import _imported, _specs
from core.services.capabilities.features import by_key
from core.services.capabilities.offline_verify import verify_cell
from core.services.capabilities.batch_live import registry


class IsisPlanTests(SimpleTestCase):
    def test_nmas_candidate_yields_only_the_process_and_two_bindings(self):
        specs, _ = _specs()
        self.assertEqual([spec.object_type for spec in specs], ["routing_isis", "routing_binding", "routing_binding"])
        self.assertEqual(specs[0].lines[0], "router isis NMAS")
        self.assertEqual(specs[1].lines[0], "interface Ethernet2")
        self.assertEqual(specs[2].lines[0], "interface Loopback444")
        self.assertIn("   isis passive", specs[2].lines)
        self.assertFalse(any("ip address" in line or "no switchport" in line for spec in specs for line in spec.lines))

    def test_import_requires_net_level_family_and_both_bindings(self):
        text = "\n".join(line for spec in _specs()[0] for line in spec.lines)
        self.assertTrue(_imported(text))
        for changed in (text.replace("49.0001.0000.0000.0044.00", "49.0001.0000.0000.0099.00"),
                        text.replace("isis metric 10", "isis metric 20"), text.replace("isis passive", "")):
            with self.subTest(changed=changed[-40:]):
                self.assertFalse(_imported(changed))

    def test_live_registry_selects_the_isolated_probe(self):
        self.assertIn(("arista_ceos", "routing.ISIS"), registry())


class IsisOfflineGateTests(TestCase):
    def test_all_offline_stages_pass_before_a_live_probe_is_allowed(self):
        cell = verify_cell("arista_ceos", by_key()["routing.ISIS"], head="5e40d28")
        failed = {name: row["reason"] for name, row in cell.probes.items()
                  if name not in ("live_read", "live_write", "live_post_write_validation", "compensation", "runtime_validation")
                  and row["outcome"] != "PASS"}
        self.assertEqual(failed, {})
        self.assertEqual(cell.blockers, [])


class IsisLiveAdapterUnitTests(SimpleTestCase):
    """Unit coverage for live adapters with every external boundary replaced."""

    @staticmethod
    def _successful_result():
        return {
            "applied": True,
            "read_ok": True,
            "post_ok": True,
            "imported": True,
            "verified": True,
            "control": True,
            "compensated": True,
            "config_restored": True,
            "after": True,
            "restored": True,
            "actions": ["routing_isis:APPLY/True/-"],
            "statuses": ["COMPENSATED"],
            "failure": "",
        }

    def test_probe_ceos_isis_positive_records_all_live_stages(self):
        cell = SimpleNamespace(probes={}, runtime_version="")
        with mock.patch.object(batch_ceos_isis, "_scenario", return_value=self._successful_result()):
            batch_ceos_isis.probe_ceos_isis(cell)
        self.assertEqual({row["outcome"] for row in cell.probes.values()}, {"PASS"})
        self.assertIn("ceos:4.36.2F", cell.runtime_version)

    def test_probe_ceos_isis_negative_records_a_failed_stage(self):
        result = self._successful_result()
        result["post_ok"] = False
        cell = SimpleNamespace(probes={}, runtime_version="")
        with mock.patch.object(batch_ceos_isis, "_scenario", return_value=result):
            batch_ceos_isis.probe_ceos_isis(cell)
        self.assertEqual(cell.probes["live_post_write_validation"]["outcome"], "FAIL")

    def test_fixture_ceos_ssh_positive_builds_a_pinned_session(self):
        network = fixture_ceos_ssh.NETWORK
        inspected = [{
            "Config": {"Labels": {"containerlab": fixture_ceos_ssh.LAB}},
            "NetworkSettings": {"Networks": {network: {
                "IPAddress": "198.51.100.10",
                "NetworkID": "0123456789abcdef",
                "Gateway": "198.51.100.1",
            }}},
        }]

        def command_result(argv, **_kwargs):
            if argv[:2] == ["docker", "inspect"]:
                return subprocess.CompletedProcess(argv, 0, json.dumps(inspected), "")
            if argv[:3] == ["ip", "route", "get"]:
                return subprocess.CompletedProcess(
                    argv, 0, "198.51.100.10 dev br-0123456789ab src 198.51.100.1 uid 1000\n", ""
                )
            return subprocess.CompletedProcess(argv, 0, "ssh-ed25519 dGVzdC1rZXk=\n", "")

        sock = mock.Mock()
        with mock.patch.dict(os.environ, {"NMAS_CAP_CEOS_PASSWORD": "unit-test-placeholder"}), \
                mock.patch.object(fixture_ceos_ssh, "_target", return_value=({"container": "fixture"}, None, None)), \
                mock.patch.object(fixture_ceos_ssh, "_run", side_effect=command_result), \
                mock.patch.object(fixture_ceos_ssh.socket, "socket", return_value=sock), \
                mock.patch("netmiko.arista.arista.AristaSSH._open"), \
                mock.patch("netmiko.arista.arista.AristaSSH.check_enable_mode", return_value=True), \
                mock.patch("netmiko.arista.arista.AristaSSH.disconnect"):
            fixture = fixture_ceos_ssh.FixtureCeosSsh()
            fixture.conn.send_command = mock.Mock(return_value="ok")
            session = fixture.session(fixture.device)
            self.assertEqual(session.run("version"), "ok")
            session.close()
            fixture.close()
        sock.connect.assert_called_once_with(("198.51.100.10", 22))

    def test_fixture_ceos_ssh_negative_refuses_a_missing_runtime_secret(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            with self.assertRaisesRegex(RuntimeError, "required"):
                fixture_ceos_ssh.FixtureCeosSsh()


class IsisIsolatedScriptTests(SimpleTestCase):
    @staticmethod
    def _load(name):
        root = Path(__file__).resolve().parents[3]
        path = root / "labs/phase9-ceos-isis-isolated" / f"{name}.py"
        spec = importlib.util.spec_from_file_location(f"phase9_ceos_isis_{name}", path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def test_negative_script_main_positive_records_both_refusals(self):
        module = self._load("negative")
        with tempfile.TemporaryDirectory() as directory, \
                mock.patch.dict(os.environ, {"NMAS_CAP_CEOS_PASSWORD": "unit-test-placeholder"}), \
                mock.patch.object(module, "ROOT", Path(directory)), \
                mock.patch.object(module.transport, "FixtureCeosSsh", side_effect=RuntimeError("refused")), \
                mock.patch("builtins.print"):
            module.main()
            evidence = json.loads((Path(directory) / "docs/evidence/v2-phase9-closure/ceos-isis/negative-transport.json").read_text())
        self.assertEqual(evidence["checks"], {"wrong_management_route": True, "wrong_pinned_host_key": True})
        self.assertFalse(evidence["device_mutated"])

    def test_run_script_main_positive_uses_an_ephemeral_database(self):
        module = self._load("run")
        cell = SimpleNamespace(
            probes={"render": {"outcome": "PASS"}}, blockers=[], complete=True,
            status="SUPPORTED", as_dict=lambda: {"status": "SUPPORTED"},
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            paths = (
                "web/core/services/capabilities/fixture_ceos_ssh.py",
                "web/core/services/capabilities/batch_ceos_isis.py",
                "web/core/services/capabilities/batch_live.py",
                "web/core/tests/test_ceos_isis_phase9.py",
            )
            for name in paths:
                target = root / name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text("safe fixture\n")
            with mock.patch.dict(os.environ, {"NMAS_CAP_CEOS_PASSWORD": "unit-test-placeholder"}), \
                    mock.patch.dict(module.settings.DATABASES["default"], {}, clear=False), \
                    mock.patch.object(module, "ROOT", root), \
                    mock.patch.object(module.subprocess, "check_output", return_value="revision\n"), \
                    mock.patch.object(module, "call_command"), \
                    mock.patch.object(module, "verify_cell", return_value=cell), \
                    mock.patch.object(module, "probe_ceos_isis"), \
                    mock.patch.object(module.phase9_ledger, "stages_for", return_value={"live": True}), \
                    mock.patch("builtins.print"):
                module.main()
            evidence = json.loads((root / "docs/evidence/v2-phase9-closure/ceos-isis/assessment.json").read_text())
        self.assertTrue(evidence["ephemeral_database"])
        self.assertEqual(evidence["repository_head"], "revision")
