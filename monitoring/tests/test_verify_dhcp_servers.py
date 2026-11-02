"""Offline unit tests for netbox/scripts/verify_dhcp_servers.py (Phase 3G
Step 28 observability). Only the parsing logic is tested offline; `_run()`
is mocked so no docker/systemctl call is ever made."""
from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path
from unittest.mock import patch

BASE = Path(__file__).resolve().parents[2]
SCRIPT_PATH = BASE / "netbox" / "scripts" / "verify_dhcp_servers.py"


def _load():
    spec = importlib.util.spec_from_file_location("verify_dhcp_servers", SCRIPT_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


v = _load()

_SAMPLE_SHOW_DHCP_SERVER = """IPv4 DHCP server is active
Active leases: 0
Subnet: 192.168.10.0/24
Active leases: 3

IPv6 DHCP server is inactive
Active leases: 0
"""


class ParsingTests(unittest.TestCase):
    def test_r2_status_parses_both_families_and_leases(self):
        with patch.object(v, "_run", return_value=_SAMPLE_SHOW_DHCP_SERVER):
            status = v.r2_status()
        self.assertEqual(status["ipv4"], "active")
        self.assertEqual(status["ipv6"], "inactive")
        self.assertEqual(status["lease_lines"], ["0", "3", "0"])

    def test_nmas_status_reports_both_families(self):
        with patch.object(v, "_run", side_effect=["active\n", "inactive\n"]):
            status = v.nmas_status()
        self.assertEqual(status, {"server": "NMAS", "ipv4": "active", "ipv6": "inactive"})


class MainTests(unittest.TestCase):
    def test_both_active_exits_0(self):
        with patch.object(v, "nmas_status", return_value={"server": "NMAS", "ipv4": "active", "ipv6": "active"}), \
             patch.object(v, "r2_status", return_value={"server": "R2", "ipv4": "active", "ipv6": "active", "lease_lines": []}):
            self.assertEqual(v.main(), 0)

    def test_both_families_inactive_on_one_server_exits_1(self):
        with patch.object(v, "nmas_status", return_value={"server": "NMAS", "ipv4": "inactive", "ipv6": "inactive"}), \
             patch.object(v, "r2_status", return_value={"server": "R2", "ipv4": "active", "ipv6": "active", "lease_lines": []}):
            self.assertEqual(v.main(), 1)

    def test_inspection_failure_exits_1(self):
        with patch.object(v, "nmas_status", side_effect=RuntimeError("boom")):
            self.assertEqual(v.main(), 1)

    def test_never_writes_or_restarts_anything(self):
        source = SCRIPT_PATH.read_text()
        for forbidden in ("systemctl restart", "systemctl reload", "write_text", "dhcpd -t"):
            self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
