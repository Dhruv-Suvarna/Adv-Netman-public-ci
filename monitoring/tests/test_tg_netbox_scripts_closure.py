"""Lab 7 closure -- the NetBox operational scripts' units: ``ensure_api_token``, ``pin_stable_identities``,
``shadow_render`` and ``sync_interface_macs``.

``subprocess.run`` (docker), the NetBox client and every NetBox write helper are replaced, and the ``.env`` file is a
temporary copy, so no container, NetBox instance or real token is touched.  POSITIVE: a created token is stored 0600
without being printed, a dynamic interface is discovered and planned, every device renders PASS, a live MAC is read
and reconciled.  NEGATIVE: a missing ``.env`` / user / result line, an existing NetBox token, a failing manage.py,
malformed MACs, an unmanaged device, a not-ready NetBox, a non-equivalent device and unreadable MAC output each fail
closed with the documented exit code.
"""
from __future__ import annotations

import contextlib
import importlib.util
import io
import stat
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from modules import ipam_context as ic
from modules import netbox_ipam as nb

SCRIPTS = Path(__file__).resolve().parents[2] / "netbox" / "scripts"
FAKE_TOKEN = "nbt_fakekey.fake-token-value-55"


def load(name):
    spec = importlib.util.spec_from_file_location(f"tg_{name}", SCRIPTS / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


token = load("ensure_api_token")
pin = load("pin_stable_identities")
shadow = load("shadow_render")
macs = load("sync_interface_macs")


def captured(function, *args):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = function(*args)
    return code, out.getvalue(), err.getvalue()


class EnsureApiTokenTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.env = Path(self.tmp.name, ".env")
        self.env.write_text("# netbox\nSUPERUSER_NAME=admin\nNETBOX_TOKEN=\n")
        patcher = patch.object(token, "ENV_FILE", self.env)
        patcher.start()
        self.addCleanup(patcher.stop)

    def shell(self, stdout, returncode=0):
        return patch.object(token.subprocess, "run", return_value=SimpleNamespace(returncode=returncode, stdout=stdout, stderr=""))

    def test_read_env_and_write_token_replace_only_the_token_line(self):
        self.assertEqual(token.read_env(self.env), {"SUPERUSER_NAME": "admin", "NETBOX_TOKEN": ""})
        token.write_token(self.env, FAKE_TOKEN)
        self.assertEqual(self.env.read_text(), f"# netbox\nSUPERUSER_NAME=admin\nNETBOX_TOKEN={FAKE_TOKEN}\n")
        self.assertEqual(stat.S_IMODE(self.env.stat().st_mode), 0o600)
        appended = Path(self.tmp.name, "other.env")
        appended.write_text("A=1\n")
        token.write_token(appended, FAKE_TOKEN)
        self.assertEqual(appended.read_text(), f"A=1\nNETBOX_TOKEN={FAKE_TOKEN}\n")

    def test_write_token_to_a_missing_env_file_raises_and_creates_nothing(self):
        missing = Path(self.tmp.name, "absent.env")
        with self.assertRaises(FileNotFoundError):
            token.write_token(missing, FAKE_TOKEN)
        self.assertFalse(missing.exists())

    def test_read_env_of_a_missing_file_is_refused(self):
        with self.assertRaisesRegex(SystemExit, "does not exist. Run bootstrap_netbox.sh first."):
            token.read_env(Path(self.tmp.name, "missing.env"))

    def test_run_in_netbox_and_extract_result_return_the_marked_json_line(self):
        with self.shell("banner\nNETBOX_TOKEN_RESULT {\"status\": \"exists\", \"count\": 1}\n") as run:
            stdout = token.run_in_netbox("print(1)")
        self.assertEqual(token.extract_result(stdout), {"status": "exists", "count": 1})
        self.assertEqual(run.call_args.args[0][-3:], ["shell", "-c", "print(1)"])
        self.assertEqual(run.call_args.kwargs["timeout"], 60)

    def test_run_in_netbox_failure_and_unmarked_output_are_refused(self):
        with self.shell("", returncode=3), self.assertRaisesRegex(SystemExit, r"manage.py shell failed .*\(exit 3\)"):
            token.run_in_netbox("print(1)")
        with self.assertRaisesRegex(SystemExit, "did not emit a parseable result line"):
            token.extract_result("banner only\n")

    def test_main_stores_a_created_token_and_prints_only_a_notice(self):
        with self.shell(f'NETBOX_TOKEN_RESULT {{"status": "created", "token": "{FAKE_TOKEN}"}}\n'):
            code, out, err = captured(token.main)
        self.assertEqual((code, err), (0, ""))
        self.assertEqual(out, "API token created for user 'admin' and stored in netbox/.env (not displayed).\n")
        self.assertNotIn(FAKE_TOKEN, out)
        self.assertEqual(token.read_env(self.env)["NETBOX_TOKEN"], FAKE_TOKEN)
        with self.shell("unused") as run:
            self.assertEqual(captured(token.main)[0], 0)
        run.assert_not_called()

    def test_main_never_duplicates_an_existing_token_or_proceeds_without_a_user(self):
        with self.shell('NETBOX_TOKEN_RESULT {"status": "exists", "count": 2}\n'):
            code, _out, err = captured(token.main)
        self.assertEqual(code, 2)
        self.assertIn("will NOT create a duplicate", err)
        self.assertEqual(token.read_env(self.env)["NETBOX_TOKEN"], "")
        with self.shell('NETBOX_TOKEN_RESULT {"status": "error", "message": "No such user: admin"}\n'), \
                self.assertRaisesRegex(SystemExit, "^ERROR: No such user: admin$"):
            token.main()
        self.env.write_text("NETBOX_TOKEN=\n")
        with self.assertRaisesRegex(SystemExit, "SUPERUSER_NAME is not set"):
            token.main()


class PinStableIdentitiesTests(unittest.TestCase):
    def test_predicted_iaid_returns_the_last_four_octets(self):
        self.assertEqual(pin.predicted_iaid("AA-C1-AB-8F-0A-40"), "ab:8f:0a:40")

    def test_predicted_iaid_of_a_malformed_or_multicast_mac_is_refused(self):
        for mac in ("aa:bb", "01:00:5e:00:00:01", "00:00:00:00:00:00"):
            with self.subTest(case=f"refused {mac}"), self.assertRaises(ValueError):
                pin.predicted_iaid(mac)

    def test_discover_dynamic_targets_returns_the_policy_marked_interfaces(self):
        modes = {"Ethernet7": ("dhcp-reserved", "static"), "Ethernet8": ("static", "dhcpv6-reserved")}
        with patch.object(nb, "get_managed_devices", return_value=["R4", "R3"]), \
                patch.object(nb, "get_device_interface_names", return_value=["Ethernet7", "Ethernet8"]), \
                patch.object(nb, "get_assignment_modes", side_effect=lambda d, i, c: dict(zip(("ipv4_mode", "ipv6_mode"), modes[i]))):
            found = pin.discover_dynamic_targets(object())
        self.assertEqual(found, [("R3", "Ethernet7", {4}), ("R3", "Ethernet8", {6}), ("R4", "Ethernet7", {4}), ("R4", "Ethernet8", {6})])

    def test_main_plans_the_linux_identity_in_check_mode(self):
        result = nb.ReconcileResult(nb.CHECK_UPDATE)
        with patch.object(nb, "build_client", return_value=object()), patch.object(nb, "check_status"), patch.object(nb, "load_config"), \
                patch.object(pin, "discover_dynamic_targets", return_value=[("R3", "eth1", {4, 6})]), \
                patch.object(pin, "_is_ceos", return_value=False), \
                patch.object(nb, "mark_mac_authoritative", return_value=result) as mark, \
                patch.object(nb, "get_interface_mac", return_value={"mac_address": "aa:c1:ab:8f:0a:40"}), \
                patch.object(nb, "set_dhcpv6_identity", return_value=result) as identity:
            code, out, err = captured(pin.main, ["--check"])
        self.assertEqual((code, err), (0, ""))
        self.assertIn(f"{'R3':<10} {'eth1':<10} {'CHECK-UPDATE':<20} {'CHECK-UPDATE':<20}", out)
        self.assertEqual((mark.call_args.kwargs["apply"], mark.call_args.kwargs["description"]), (False, pin.LINUX_MAC_MECHANISM))
        self.assertEqual((identity.call_args.kwargs["duid"], identity.call_args.kwargs["iaid"]), ("00:03:00:01:aa:c1:ab:8f:0a:40", "ab:8f:0a:40"))


class ShadowRenderTests(unittest.TestCase):
    def test_run_device_returns_the_comparison_and_writes_a_candidate(self):
        facts = ic.DeviceFacts(interfaces={"Ethernet1": {"ipv4": "10.0.0.1/31", "ipv6": None}})
        with patch.object(ic, "extract_legacy_facts", return_value=facts), patch.object(ic, "build_netbox_facts", return_value=facts), \
                patch.object(ic, "write_candidate_config", return_value=Path("/runtime/R1.cfg")) as write:
            code_out = io.StringIO()
            with contextlib.redirect_stdout(code_out):
                result = shadow.run_device("R1", write_candidates=True)
        self.assertEqual((result.device, result.equivalent), ("R1", True))
        self.assertEqual(code_out.getvalue(), "  candidate written: /runtime/R1.cfg\n")
        write.assert_called_once_with("R1")

    def test_run_device_reports_a_mismatch_without_writing(self):
        with patch.object(ic, "extract_legacy_facts", return_value=ic.DeviceFacts(interfaces={"Ethernet1": {"ipv4": "10.0.0.1/31", "ipv6": None}})), \
                patch.object(ic, "build_netbox_facts", return_value=ic.DeviceFacts(interfaces={"Ethernet1": {"ipv4": "10.0.0.9/31", "ipv6": None}})), \
                patch.object(ic, "write_candidate_config") as write:
            result = shadow.run_device("R1", write_candidates=False)
        self.assertFalse(result.equivalent)
        write.assert_not_called()

    def main(self, argv, results=None, ready_error=None):
        def run_device(device, *, write_candidates):
            value = (results or {}).get(device, ic.ComparisonResult(device))
            if isinstance(value, Exception):
                raise value
            return value
        with patch.object(ic, "validate_netbox_ready", side_effect=ready_error, return_value={"managed_devices": list(ic.MANAGED_DEVICES)}), \
                patch.object(shadow, "run_device", side_effect=run_device):
            return captured(shadow.main, argv)

    def test_main_passes_when_every_managed_device_is_equivalent(self):
        code, out, err = self.main(["--all", "-v"])
        self.assertEqual((code, err), (0, ""))
        self.assertTrue(out.rstrip().endswith("Overall: PASS"))
        self.assertEqual(sum(line.endswith(" PASS") and not line.startswith("Overall") for line in out.splitlines()), len(ic.MANAGED_DEVICES))

    def test_main_fails_closed_for_unready_netbox_unknown_devices_errors_and_drift(self):
        self.assertEqual(self.main(["--all"], ready_error=nb.NetboxConnectionError("down"))[0], 1)
        code, _out, err = self.main(["--device", "R5"])
        self.assertEqual((code, err), (1, "ERROR: not a managed device: ['R5']\n"))
        self.assertEqual(self.main(["--device", "R1"], results={"R1": nb.NetboxModelError("gone")})[0], 1)
        drift = ic.ComparisonResult("R1", [ic.FieldDifference("interface", "Ethernet1.ipv4", "10.0.0.1/31", "10.0.0.9/31", "BUG")])
        code, out, _err = self.main(["--device", "R1"], results={"R1": drift})
        self.assertEqual(code, 2)
        self.assertIn("    interface: legacy='10.0.0.1/31' netbox='10.0.0.9/31' [BUG]", out)


class SyncInterfaceMacsTests(unittest.TestCase):
    def read(self, platform="ceos", returncode=0, stdout="aa:c1:ab:8f:0a:40\n"):
        with patch.object(nb, "get_device", return_value={"device_type": platform}), \
                patch.object(macs.subprocess, "run", return_value=SimpleNamespace(returncode=returncode, stdout=stdout, stderr="no such device")) as run:
            try:
                return macs.discover_mac("R1", object()), run
            except RuntimeError as exc:
                return exc, run

    def test_discover_mac_returns_the_live_value_of_the_platform_interface(self):
        found, run = self.read()
        self.assertEqual((found, run.call_args.args[0]), ("aa:c1:ab:8f:0a:40", ["docker", "exec", "clab-srlceos01-R1", "cat", "/sys/class/net/vlan200/address"]))
        self.assertEqual(self.read(platform="ubuntu")[1].call_args.args[0][-1], "/sys/class/net/Vlan200/address")

    def test_discover_mac_refuses_failed_or_malformed_output(self):
        for name, kwargs, message in (("exit", {"returncode": 1}, "R1: could not read MAC for vlan200 in clab-srlceos01-R1: no such device"),
                                      ("malformed", {"stdout": "aa:bb\n"}, "R1: unexpected MAC output for vlan200: 'aa:bb'")):
            with self.subTest(case=f"refused {name}"):
                self.assertEqual(str(self.read(**kwargs)[0]), message)

    def test_main_reconciles_each_readable_managed_mac(self):
        def discover(device, client):
            if device == "S1":
                raise RuntimeError("S1: container down")
            return "aa:c1:ab:8f:0a:40"
        with patch.object(nb, "build_client", return_value=object()), patch.object(nb, "check_status"), patch.object(nb, "load_config"), \
                patch.object(nb, "get_managed_devices", return_value=["R1", "S1"]), patch.object(macs, "discover_mac", side_effect=discover), \
                patch.object(nb, "ensure_interface_mac", return_value=nb.ReconcileResult(nb.CHECK_UPDATE)) as ensure:
            code, out, err = captured(macs.main, ["--check"])
        self.assertEqual(code, 1)
        self.assertIn(f"{'R1':<10} {'Vlan200':<10} {'aa:c1:ab:8f:0a:40':<20} CHECK-UPDATE", out)
        self.assertIn("S1: container down", err)
        ensure.assert_called_once_with("R1", "Vlan200", "aa:c1:ab:8f:0a:40", ensure.call_args.args[3], apply=False)
        with self.subTest(case="refused unreachable netbox"), patch.object(nb, "build_client", side_effect=nb.NetboxConnectionError("down")):
            self.assertEqual(captured(macs.main, ["--apply"])[0], 1)


if __name__ == "__main__":
    unittest.main()
