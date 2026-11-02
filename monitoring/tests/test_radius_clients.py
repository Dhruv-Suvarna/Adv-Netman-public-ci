"""Protected per-device FreeRADIUS client rendering; fake secrets only."""
from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

import yaml

from monitoring.human_mfa import render_radius_clients as clients


class RadiusClientRendererTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.inventory = self.root / "inventory.yml"
        network_devices = {}
        for index, device in enumerate(clients.ELIGIBLE, start=1):
            platform = "linux" if device in clients.LINUX_ELIGIBLE else "ceos"
            network_devices[device] = {"monitoring": {"platform": platform, "address": f"192.0.2.{index}"}}
        self.inventory.write_text(yaml.safe_dump({"network_devices": network_devices}))
        self.secrets = self.root / "secrets"
        self.secrets.mkdir(mode=0o700)
        for device in clients.ELIGIBLE:
            path = self.secrets / f"radius_{device.lower()}_secret"
            path.write_text(f"TEST_ONLY_{device}_UNIQUE_RADIUS_SECRET\n")
            path.chmod(0o600)
        fixture = self.secrets / "radius_fixture_secret"
        fixture.write_text("TEST_ONLY_LOCAL_FIXTURE_RADIUS_SECRET\n")
        fixture.chmod(0o600)

    def tearDown(self):
        self.tmp.cleanup()

    def test_only_selected_devices_are_rendered_with_unique_runtime_values(self):
        text = clients.render(["R1", "R2"], inventory_path=self.inventory, secret_root=self.secrets)
        self.assertIn("client R1", text)
        self.assertIn("client R2", text)
        self.assertNotIn("client S1", text)
        self.assertIn("192.0.2.1", text)
        self.assertIn("TEST_ONLY_R1_UNIQUE_RADIUS_SECRET", text)
        self.assertIn("TEST_ONLY_R2_UNIQUE_RADIUS_SECRET", text)
        self.assertIn("client local_fixture", text)

    def test_linux_clients_are_independent_and_platform_checked(self):
        text = clients.render(["R3"], inventory_path=self.inventory, secret_root=self.secrets)
        self.assertIn("client R3", text)
        self.assertNotIn("client R4", text)
        fixture = yaml.safe_load(self.inventory.read_text())
        fixture["network_devices"]["R3"]["monitoring"]["platform"] = "ceos"
        self.inventory.write_text(yaml.safe_dump(fixture))
        with self.assertRaisesRegex(clients.RadiusClientError, "not Linux"):
            clients.render(["R3"], inventory_path=self.inventory, secret_root=self.secrets)

    def test_deferred_duplicate_wrong_platform_and_unsafe_secret_are_refused(self):
        for selected in (["R5"], ["R1", "R1"]):
            with self.subTest(selected=selected), self.assertRaises(clients.RadiusClientError):
                clients.render(selected, inventory_path=self.inventory, secret_root=self.secrets)
        fixture = yaml.safe_load(self.inventory.read_text())
        fixture["network_devices"]["R2"]["monitoring"]["platform"] = "linux"
        self.inventory.write_text(yaml.safe_dump(fixture))
        with self.assertRaisesRegex(clients.RadiusClientError, "not cEOS"):
            clients.render(["R2"], inventory_path=self.inventory, secret_root=self.secrets)
        fixture["network_devices"]["R2"]["monitoring"]["platform"] = "ceos"
        self.inventory.write_text(yaml.safe_dump(fixture))
        os.chmod(self.secrets / "radius_r2_secret", 0o644)
        with self.assertRaisesRegex(clients.RadiusClientError, "unsafe"):
            clients.render(["R2"], inventory_path=self.inventory, secret_root=self.secrets)

    def test_atomic_output_is_private_and_idempotent(self):
        destination = self.root / "runtime" / "clients.conf"
        text = clients.render(["R1"], inventory_path=self.inventory, secret_root=self.secrets)
        clients.write_atomic(text, destination)
        first = destination.read_bytes()
        clients.write_atomic(text, destination)
        self.assertEqual(destination.read_bytes(), first)
        self.assertEqual(destination.stat().st_mode & 0o777, 0o600)


if __name__ == "__main__":
    unittest.main()
