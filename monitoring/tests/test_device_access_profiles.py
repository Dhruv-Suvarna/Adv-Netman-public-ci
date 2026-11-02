"""Per-device cEOS automation identity selection; fixture-only."""
from __future__ import annotations

import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import address_report
import master
import yaml
from modules.device_credentials import SecretProviderError, ceos_access_profile, ceos_access_profiles


INVENTORY = {
    "network_devices": {
        "R1": {
            "username": "nmas-automation",
            "credential_ref": "runtime://device-credentials/r1-nmas-automation",
        },
        "R2": {
            "username": "nmas-automation",
            "credential_ref": "runtime://device-credentials/r2-nmas-automation",
        },
    },
}


class _Provider:
    def candidates(self, reference):
        return (SimpleNamespace(value="TEST_ONLY_DEVICE_PASSWORD", version=reference),)


class _Connection:
    def check_enable_mode(self):
        return True

    def send_command(self, _command, **_kwargs):
        return ""

    def disconnect(self):
        pass


class DeviceAccessProfileTests(unittest.TestCase):
    def test_tracked_inventory_routes_every_managed_ceos_target_by_device(self):
        repo = Path(__file__).resolve().parents[2]
        inventory = yaml.safe_load((repo / "inventory.yml").read_text())
        for device in ("R1", "R2", "S1", "S2", "S3", "S4", "mgmt_swt"):
            with self.subTest(device=device):
                profiles = ceos_access_profiles(inventory, device)
                self.assertEqual(profiles[0].username, "nmas-automation")
                self.assertEqual(profiles[0].credential_ref,
                                 f"runtime://device-credentials/{device.lower()}-nmas-automation")
                self.assertEqual(len(profiles), 1)

    def test_every_device_requires_its_own_profile(self):
        r1 = ceos_access_profile(INVENTORY, "R1")
        r2 = ceos_access_profile(INVENTORY, "R2")
        self.assertEqual((r1.username, r1.credential_ref), (
            "nmas-automation", "runtime://device-credentials/r1-nmas-automation",
        ))
        self.assertEqual((r2.username, r2.credential_ref), (
            "nmas-automation", "runtime://device-credentials/r2-nmas-automation",
        ))
        broken = {"network_devices": {"R2": {}}}
        with self.assertRaises(SecretProviderError):
            ceos_access_profiles(broken, "R2")

    def test_master_push_and_verify_connection_uses_device_profile(self):
        conn = _Connection()
        with mock.patch.object(master, "FileSecretProvider", return_value=_Provider()), \
                mock.patch.object(master, "ConnectHandler", return_value=conn) as connect:
            self.assertIs(master.eos_conn("R1", "192.0.2.1", INVENTORY), conn)
            self.assertEqual(connect.call_args.kwargs["username"], "nmas-automation")
            connect.reset_mock()
            self.assertIs(master.eos_conn("R2", "192.0.2.2", INVENTORY), conn)
            self.assertEqual(connect.call_args.kwargs["username"], "nmas-automation")

    def test_master_never_falls_back_after_device_identity_fails(self):
        with mock.patch.object(master, "FileSecretProvider", return_value=_Provider()), \
                mock.patch.object(master, "ConnectHandler", side_effect=RuntimeError("fixture auth failure")) as connect, \
                self.assertRaisesRegex(RuntimeError, "every protected credential candidate"):
            master.eos_conn("R1", "192.0.2.1", INVENTORY)
        self.assertEqual([call.kwargs["username"] for call in connect.call_args_list], ["nmas-automation"])

    def test_address_report_uses_only_the_host_side_console(self):
        with mock.patch.object(address_report, "docker_exec", side_effect=["", ""]) as console:
            self.assertEqual(address_report.eos_addresses("lab", "R1"), [])
        self.assertEqual(console.call_count, 2)
        self.assertTrue(all(call.args[0] == "clab-lab-R1" for call in console.call_args_list))


if __name__ == "__main__":
    unittest.main()
