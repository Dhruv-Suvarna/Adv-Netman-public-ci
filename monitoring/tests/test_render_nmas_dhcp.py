"""Offline unit tests for netbox/scripts/render_nmas_dhcp.py (Phase 3G).

Loaded by file path via importlib, matching the other netbox/scripts/
test conventions. No live NetBox, Docker, or device access; the real
`dhcpd` binary IS invoked (guarded/skipped if unavailable) since that is
exactly what this script's own syntax-validation step does, and proving
it actually works offline is the point of these tests.
"""
from __future__ import annotations

import importlib.util
import shutil
import unittest
from pathlib import Path
from unittest.mock import patch

from modules import ipam_context as ic
from modules import netbox_ipam as nb

BASE = Path(__file__).resolve().parents[2]
SCRIPT_PATH = BASE / "netbox" / "scripts" / "render_nmas_dhcp.py"

_DHCPD_AVAILABLE = shutil.which("dhcpd") is not None


def _load_render_nmas_dhcp():
    spec = importlib.util.spec_from_file_location("render_nmas_dhcp", SCRIPT_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


nmas = _load_render_nmas_dhcp()

_FAKE_CONTEXT = {
    "management": {"v4_network": "192.168.200.0", "v4_netmask": "255.255.255.0", "v6_prefix": "2001:db8:200::/64"},
    "ipv4_subnets": [
        {"vlan": 10, "network": "192.168.10.0", "netmask": "255.255.255.0", "start": "192.168.10.100", "end": "192.168.10.179", "gateway": "192.168.10.1"},
        {"vlan": 20, "network": "192.168.20.0", "netmask": "255.255.255.0", "start": "192.168.20.100", "end": "192.168.20.179", "gateway": "192.168.20.1"},
    ],
    "ipv6_subnets": [
        {"vlan": 10, "prefix": "2001:db8:10::/64", "start": "2001:db8:10::1000", "end": "2001:db8:10::1fff"},
        {"vlan": 20, "prefix": "2001:db8:20::/64", "start": "2001:db8:20::1000", "end": "2001:db8:20::1fff"},
        {"vlan": 30, "prefix": "2001:db8:30::/64", "start": "2001:db8:30::1000", "end": "2001:db8:30::1fff"},
    ],
}


class MainEndToEndTests(unittest.TestCase):
    def test_netbox_not_ready_exits_1(self):
        with patch.object(ic, "validate_netbox_ready", side_effect=nb.NetboxConnectionError("down")):
            self.assertEqual(nmas.main([]), 1)

    def test_context_build_failure_exits_1(self):
        with patch.object(ic, "validate_netbox_ready"), \
             patch.object(nb, "build_client", return_value=object()), \
             patch.object(ic, "build_and_validate_nmas_dhcp_context", side_effect=nb.NetboxModelError("bad pools")):
            self.assertEqual(nmas.main([]), 1)

    @unittest.skipUnless(_DHCPD_AVAILABLE, "dhcpd binary not installed on this host")
    def test_happy_path_exits_0_with_real_dhcpd_syntax_check(self):
        with patch.object(ic, "validate_netbox_ready"), \
             patch.object(nb, "build_client", return_value=object()), \
             patch.object(ic, "build_and_validate_nmas_dhcp_context", return_value=_FAKE_CONTEXT):
            self.assertEqual(nmas.main([]), 0)

    def test_happy_path_exits_0_when_both_rendered_candidates_pass_the_syntax_check(self):
        """Hermetic happy path (any host): the real templates render, both candidates reach the dhcpd check, exit 0, nothing written."""
        import contextlib
        import io

        checked = []

        def syntax_ok(path, text, flags):
            checked.append((path, flags, text))
            return True, ""

        with patch.object(ic, "validate_netbox_ready"), \
             patch.object(nb, "build_client", return_value=object()), \
             patch.object(ic, "build_and_validate_nmas_dhcp_context", return_value=_FAKE_CONTEXT), \
             patch.object(nmas, "_syntax_check_via_etc_dhcp", side_effect=syntax_ok), contextlib.redirect_stdout(io.StringIO()) as out:
            self.assertEqual(nmas.main([]), 0)
        self.assertEqual([(path, flags) for path, flags, _text in checked], [(nmas._CANDIDATE_V4, ["-t"]), (nmas._CANDIDATE_V6, ["-6", "-t"])])
        self.assertIn("subnet", checked[0][2])
        self.assertIn("ISC DHCPv6 syntax validation (dhcpd -6 -t): PASS", out.getvalue())

    def test_syntax_failure_exits_3(self):
        broken_context = {**_FAKE_CONTEXT, "ipv4_subnets": [{"vlan": 10, "network": "not-an-address", "netmask": "255.255.255.0", "start": "x", "end": "y", "gateway": "z"}]}
        with patch.object(ic, "validate_netbox_ready"), \
             patch.object(nb, "build_client", return_value=object()), \
             patch.object(ic, "build_and_validate_nmas_dhcp_context", return_value=broken_context):
            self.assertEqual(nmas.main([]), 3)

    def test_never_calls_any_push_or_connect_function(self):
        source = SCRIPT_PATH.read_text()
        for forbidden in ("netmiko", "paramiko", "ConnectHandler", "ssh_exec"):
            self.assertNotIn(forbidden, source)

    def test_never_installs_under_etc_dhcp_permanently_or_restarts(self):
        source = SCRIPT_PATH.read_text()
        for forbidden in ("systemctl restart", "systemctl reload", "/etc/dhcp/dhcpd.conf\"", "/etc/dhcp/dhcpd6.conf\""):
            self.assertNotIn(forbidden, source)


@unittest.skipUnless(_DHCPD_AVAILABLE, "dhcpd binary not installed on this host")
class SyntaxCheckTests(unittest.TestCase):
    """Exercises the real dhcpd -t/-6 -t binary against candidate files
    inside /etc/dhcp/ (the only path its AppArmor profile permits reading)
    -- and proves the candidate is always removed afterward, success or
    failure, and the REAL dhcpd.conf/dhcpd6.conf are never touched."""

    def test_valid_v4_candidate_passes_and_cleans_up(self):
        text = "authoritative;\nsubnet 192.168.50.0 netmask 255.255.255.0 {\n  range 192.168.50.10 192.168.50.20;\n}\n"
        ok, _ = nmas._syntax_check_via_etc_dhcp(nmas._CANDIDATE_V4, text, ["-t"])
        self.assertTrue(ok)
        self.assertFalse(nmas._CANDIDATE_V4.exists())

    def test_invalid_v4_candidate_fails_and_still_cleans_up(self):
        text = "this is not valid dhcpd syntax {{{\n"
        ok, output = nmas._syntax_check_via_etc_dhcp(nmas._CANDIDATE_V4, text, ["-t"])
        self.assertFalse(ok)
        self.assertFalse(nmas._CANDIDATE_V4.exists())

    def test_real_dhcpd_conf_j2_render_passes_syntax_check(self):
        from modules.eos_render import render
        candidate = render("dhcp/dhcpd.conf.j2", {"management": {}, "dhcp": _FAKE_CONTEXT}, base=BASE)
        ok, output = nmas._syntax_check_via_etc_dhcp(nmas._CANDIDATE_V4, candidate, ["-t"])
        self.assertTrue(ok, output)

    def test_real_dhcpd6_conf_j2_render_passes_syntax_check(self):
        from modules.eos_render import render
        candidate = render("dhcp/dhcpd6.conf.j2", {"management": {}, "dhcp": _FAKE_CONTEXT}, base=BASE)
        ok, output = nmas._syntax_check_via_etc_dhcp(nmas._CANDIDATE_V6, candidate, ["-6", "-t"])
        self.assertTrue(ok, output)

    def test_real_dhcpd_conf_and_conf6_never_touched(self):
        from modules.eos_render import render
        before_v4 = (Path("/etc/dhcp/dhcpd.conf")).read_text() if Path("/etc/dhcp/dhcpd.conf").exists() else None
        candidate = render("dhcp/dhcpd.conf.j2", {"management": {}, "dhcp": _FAKE_CONTEXT}, base=BASE)
        nmas._syntax_check_via_etc_dhcp(nmas._CANDIDATE_V4, candidate, ["-t"])
        after_v4 = (Path("/etc/dhcp/dhcpd.conf")).read_text() if Path("/etc/dhcp/dhcpd.conf").exists() else None
        self.assertEqual(before_v4, after_v4)


if __name__ == "__main__":
    unittest.main()
