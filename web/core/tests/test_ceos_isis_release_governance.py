"""Direct offline coverage of the cEOS IS-IS live runner and pinned SSH fixture.

The actual SSH, adjacency, route and restoration proof is recorded separately in the isolated live evidence.
"""

from __future__ import annotations

import importlib.util
import json
import subprocess
import tempfile
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import paramiko
from django.conf import settings
from django.test import SimpleTestCase
from netmiko.arista.arista import AristaSSH

from core.services.capabilities import batch_ceos_isis as isis
from core.services.capabilities import fixture_ceos_ssh as ssh
from core.services.health import live
from core.services.test_governance.constants import REPO_ROOT


def _script(name):
    path = REPO_ROOT / "labs/phase9-ceos-isis-isolated" / name
    spec = importlib.util.spec_from_file_location(f"nmas_ceos_isis_{name.removesuffix('.py')}", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class CeosIsisReleaseGovernanceTests(SimpleTestCase):
    def test_pinned_ssh_constructor_session_and_close_use_only_verified_management_path(self):
        bridge, gateway, address = "br-abcdef123456", "172.31.248.1", "172.31.248.11"
        network = {"IPAddress": address, "NetworkID": "abcdef1234567890", "Gateway": gateway}
        row = {"NetworkSettings": {"Networks": {ssh.NETWORK: network}},
               "Config": {"Labels": {"containerlab": ssh.LAB}}}
        calls = []

        def run(argv, **_kwargs):
            calls.append(argv)
            if argv[:2] == ["docker", "inspect"]:
                return subprocess.CompletedProcess(argv, 0, json.dumps([row]), "")
            if argv[:3] == ["ip", "route", "get"]:
                return subprocess.CompletedProcess(argv, 0, f"{address} dev {bridge} src {gateway} uid 0\n", "")
            if argv[:2] == ["docker", "exec"]:
                return subprocess.CompletedProcess(argv, 0, "ssh-ed25519 YQ==\n", "")
            raise AssertionError(argv)

        sock = mock.Mock()
        target = ({"name": "ceos", "platform": "arista_ceos", "container": "clab-nmas-cap-validation-ceos"}, "", "")
        with mock.patch.object(ssh, "_target", return_value=target), mock.patch.object(ssh, "_run", side_effect=run), \
                mock.patch.object(ssh.socket, "socket", return_value=sock), \
                mock.patch.object(AristaSSH, "__init__", return_value=None), \
                mock.patch.object(AristaSSH, "_open"), \
                mock.patch.object(AristaSSH, "check_enable_mode", return_value=True), \
                mock.patch.object(AristaSSH, "send_command", return_value="read-back") as send, \
                mock.patch.object(AristaSSH, "disconnect") as disconnect, \
                mock.patch.dict(ssh.os.environ, {"NMAS_CAP_CEOS_PASSWORD": "offline-test-only"}):
            fixture = ssh.FixtureCeosSsh()
            self.assertEqual(fixture.management, {"address": address, "source": gateway, "bridge": bridge,
                                                   "host_key": ssh._fingerprint(b"a")})
            sock.setsockopt.assert_called_once_with(ssh.socket.SOL_SOCKET, ssh.socket.SO_BINDTODEVICE,
                                                    bridge.encode() + b"\0")
            sock.bind.assert_called_once_with((gateway, 0))
            sock.connect.assert_called_once_with((address, 22))
            client = fixture.conn._build_ssh_client()
            client._policy.missing_host_key(None, address, SimpleNamespace(asbytes=lambda: b"a"))
            with self.assertRaises(paramiko.SSHException):
                client._policy.missing_host_key(None, address, SimpleNamespace(asbytes=lambda: b"wrong"))
            reader = fixture.session(fixture.device)
            self.assertEqual(reader.run("isis"), "read-back")
            send.assert_called_once_with(live.CEOS_COMMANDS["isis"], read_timeout=60)
            with self.assertRaises(live.LiveError):
                reader.run("configure terminal")
            reader.close()
            fixture.close()
            self.assertIsNone(fixture.conn)
            disconnect.assert_called_once()
            client.close()
        self.assertEqual(len(calls), 3)

    def test_probe_records_positive_live_verdict_without_changing_a_device(self):
        result = {"actions": ["APPLY"], "statuses": ["COMPENSATED"], "control": True,
                  "applied": True, "read_ok": True, "post_ok": True, "imported": True,
                  "verified": True, "compensated": True, "config_restored": True,
                  "after": True, "restored": True, "failure": ""}
        cell = SimpleNamespace(probes={}, runtime_version="")
        with mock.patch.object(isis, "_scenario", return_value=result):
            isis.probe_ceos_isis(cell)
        self.assertEqual({row["outcome"] for row in cell.probes.values()}, {"PASS"})
        self.assertEqual(len(cell.probes), 6)

    def test_probe_refuses_failed_live_verdict_without_changing_a_device(self):
        result = {"actions": ["APPLY"], "statuses": ["COMPENSATED"], "control": True,
                  "applied": True, "read_ok": True, "post_ok": True, "imported": True,
                  "verified": True, "compensated": True, "config_restored": True,
                  "after": True, "restored": True, "failure": ""}
        failed = {**result, "verified": False, "config_restored": False}
        cell = SimpleNamespace(probes={}, runtime_version="")
        with mock.patch.object(isis, "_scenario", return_value=failed):
            isis.probe_ceos_isis(cell)
        self.assertEqual(cell.probes["runtime_validation"]["outcome"], "FAIL")
        self.assertEqual(cell.probes["compensation"]["outcome"], "FAIL")

    def test_positive_runner_main_writes_source_bound_evidence_in_a_temporary_root(self):
        module = _script("run.py")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            paths = ("web/core/services/capabilities/fixture_ceos_ssh.py",
                     "web/core/services/capabilities/batch_ceos_isis.py",
                     "web/core/services/capabilities/batch_live.py", "web/core/tests/test_ceos_isis_phase9.py")
            for name in paths:
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("offline fixture")
            cell = SimpleNamespace(probes={"renderer": {"outcome": "PASS"}}, complete=True, status="SUPPORTED",
                                   as_dict=lambda: {"final_status": "SUPPORTED"})
            old_db = settings.DATABASES["default"]["NAME"]
            try:
                with mock.patch.object(module, "ROOT", root), mock.patch.object(module, "call_command"), \
                        mock.patch.object(module, "verify_cell", return_value=cell), \
                        mock.patch.object(module, "probe_ceos_isis") as probe, \
                        mock.patch.object(module.subprocess, "check_output", return_value="a" * 40), \
                        mock.patch.object(module.phase9_ledger, "stages_for", return_value={"all": True}), \
                        mock.patch.dict(module.os.environ, {"NMAS_CAP_CEOS_PASSWORD": "offline-test-only"}):
                    module.main()
                probe.assert_called_once_with(cell)
                path = root / "docs/evidence/v2-phase9-closure/ceos-isis/assessment.json"
                record = json.loads(path.read_text())
                self.assertEqual((record["repository_head"], len(record["uncommitted_source_sha256"])), ("a" * 40, 4))
                self.assertTrue(record["ephemeral_database"])
            finally:
                settings.DATABASES["default"]["NAME"] = old_db

    def test_runner_main_records_both_nonmutating_transport_refusals(self):
        module = _script("negative.py")
        route = "172.31.248.11 dev br-abcdef123456 src 172.31.248.1\n"

        def run(argv, **_kwargs):
            if argv[:3] == ["ip", "route", "get"]:
                return subprocess.CompletedProcess(argv, 0, route, "")
            return subprocess.CompletedProcess(argv, 0, "ssh-ed25519 YQ==\n", "")

        class RefusingSession:
            def __init__(self):
                route_result = module.transport._run(["ip", "route", "get", "172.31.248.11"])
                key_result = module.transport._run(["docker", "exec", "fixture", "Cli", "-c",
                                                    "show management ssh hostkey ed25519 public"])
                if "dev br-abcdef123456 src 172.31.248.1" not in route_result.stdout or \
                        "ssh-ed25519 YQ==" not in key_result.stdout:
                    raise RuntimeError("transport refused")

            def close(self):
                pass

        with tempfile.TemporaryDirectory() as temporary, mock.patch.object(module, "ROOT", Path(temporary)), \
                mock.patch.object(module.transport, "_run", side_effect=run), \
                mock.patch.object(module.transport, "FixtureCeosSsh", RefusingSession), \
                mock.patch.dict(module.os.environ, {"NMAS_CAP_CEOS_PASSWORD": "offline-test-only"}):
            module.main()
            path = Path(temporary) / "docs/evidence/v2-phase9-closure/ceos-isis/negative-transport.json"
            result = json.loads(path.read_text())
            self.assertEqual(result["checks"], {"wrong_pinned_host_key": True, "wrong_management_route": True})
            self.assertFalse(result["device_mutated"])
