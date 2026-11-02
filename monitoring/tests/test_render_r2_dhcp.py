"""Offline unit tests for netbox/scripts/render_r2_dhcp.py (Phase 3C/3D).

Loaded by file path via importlib, matching test_populate_netbox.py's
convention (netbox/scripts/ is not a Python package). No live NetBox,
Docker, or device access is used anywhere in this file.
"""
from __future__ import annotations

import importlib.util
import re
import unittest
from pathlib import Path
from unittest.mock import patch

from modules import ipam_context as ic
from modules import netbox_ipam as nb
from modules.eos_render import eos_commands, render

BASE = Path(__file__).resolve().parents[2]
SCRIPT_PATH = BASE / "netbox" / "scripts" / "render_r2_dhcp.py"
FRAGMENT_PATH = BASE / "templates" / "R2_dhcp_server.cfg.j2"
FULL_TEMPLATE_PATH = BASE / "templates" / "R2.cfg.j2"


def _load_render_r2_dhcp():
    spec = importlib.util.spec_from_file_location("render_r2_dhcp", SCRIPT_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


r2 = _load_render_r2_dhcp()


def _pool(vlan, family, server, start, end, gateway=None, prefix=None, relay_targets=()):
    return ic.DhcpPool(vlan=vlan, family=family, server=server, prefix=prefix, start=start, end=end, gateway=gateway, relay_targets=tuple(relay_targets), description=None)


_REAL_CONTEXT = {
    "ipv4_subnets": [
        _pool(10, 4, "secondary", "192.168.10.200", "192.168.10.220", gateway="192.168.10.1", prefix="192.168.10.0/24"),
        _pool(20, 4, "secondary", "192.168.20.200", "192.168.20.220", gateway="192.168.20.1", prefix="192.168.20.0/24"),
    ],
    "ipv6_subnets": [
        _pool(10, 6, "secondary", "2001:db8:10::2000", "2001:db8:10::20ff", prefix="2001:db8:10::/64"),
        _pool(20, 6, "secondary", "2001:db8:20::2000", "2001:db8:20::20ff", prefix="2001:db8:20::/64"),
        _pool(30, 6, "secondary", "2001:db8:30::2000", "2001:db8:30::20ff", prefix="2001:db8:30::/64"),
    ],
}

_BASE_CONTEXT = {"management": {}, "node": "R2"}


class TemplateDoesNotHardcodePoolBoundariesTests(unittest.TestCase):
    """Content-scan of the RAW (unrendered) fragment source: none of the
    actual pool boundary literals may appear as text -- they must only
    ever reach the output through `{{ pool.* }}` substitution."""

    def test_no_literal_pool_addresses_in_fragment_source(self):
        source = FRAGMENT_PATH.read_text()
        literal_values = [
            "192.168.10.200", "192.168.10.220", "192.168.20.200", "192.168.20.220",
            "192.168.10.1", "192.168.20.1",
            "2001:db8:10::2000", "2001:db8:10::20ff", "2001:db8:20::2000", "2001:db8:20::20ff",
            "2001:db8:30::2000", "2001:db8:30::20ff",
        ]
        for value in literal_values:
            self.assertNotIn(value, source, f"{value!r} must not be a literal in the fragment source")

    def test_fragment_only_references_pool_via_jinja_context(self):
        source = FRAGMENT_PATH.read_text()
        self.assertIn("dhcp.ipv4_subnets", source)
        self.assertIn("dhcp.ipv6_subnets", source)
        for match in re.finditer(r"\b\d{1,3}(?:\.\d{1,3}){3}\b|[0-9a-fA-F:]{4,}::[0-9a-fA-F:]*", source):
            start = source.rfind("{{", 0, match.start())
            end = source.find("}}", match.start())
            self.assertNotEqual(start, -1, f"literal {match.group()!r} is not inside a Jinja expression")
            self.assertNotEqual(end, -1, f"literal {match.group()!r} is not inside a Jinja expression")


class IntegratedRenderTests(unittest.TestCase):
    """The REAL push-path template (templates/R2.cfg.j2), rendered exactly
    as master.py's _build_eos_config() would -- this is Step 3's "ONE
    authoritative desired R2 configuration", not a second parallel one."""

    def test_full_render_includes_dhcp_context(self):
        candidate = render("templates/R2.cfg.j2", {**_BASE_CONTEXT, "dhcp": _REAL_CONTEXT}, base=BASE)
        self.assertIn("dhcp server", candidate)
        self.assertIn("subnet 192.168.10.0/24", candidate)
        self.assertIn("range 192.168.10.200 192.168.10.220", candidate)
        self.assertIn("subnet 2001:db8:30::/64", candidate)
        self.assertIn("dhcp server ipv4", candidate)
        self.assertIn("dhcp server ipv6", candidate)

    def test_full_render_preserves_existing_r2_config(self):
        """Everything non-DHCP that was in R2.cfg.j2 before Phase 3D must
        still be present, verbatim, in the integrated render."""
        candidate = render("templates/R2.cfg.j2", {**_BASE_CONTEXT, "dhcp": _REAL_CONTEXT}, base=BASE)
        for expected in (
            "hostname R2", "router rip", "router ospf 10", "ipv6 router ospf 10",
            "no nexthop-group IPIP-S2", "no ip decap-group IPIP-DECAP",
            "interface Ethernet2", "interface Vlan103", "interface Vlan104",
            "route-map RIP-TO-OSPF permit 10", "ipv6 prefix-list CLIENT-V6",
            "ipv6 route 2001:db8::/32 2001:db8:100:101::2", "router isis NMAS",
        ):
            self.assertIn(expected, candidate)

    def test_vlan200_static_addresses_remain(self):
        candidate = render("templates/R2.cfg.j2", {**_BASE_CONTEXT, "dhcp": _REAL_CONTEXT}, base=BASE)
        self.assertIn("ip address 192.168.200.2/24", candidate)
        self.assertIn("ipv6 address 2001:db8:200::2/64", candidate)

    def test_without_dhcp_context_render_is_byte_identical_to_pre_3d(self):
        """Rendering R2.cfg.j2 without a `dhcp` context (every other
        device's shape, and R2's own shape before Phase 3D) must produce
        NO stray output from the new {% if %} guards."""
        candidate = render("templates/R2.cfg.j2", _BASE_CONTEXT, base=BASE)
        self.assertNotIn("dhcp server", candidate)
        self.assertNotIn("{% if", candidate)
        self.assertNotIn("{%if", candidate)

    def test_render_changes_when_context_changes(self):
        altered = {
            "ipv4_subnets": [_pool(10, 4, "secondary", "192.168.10.240", "192.168.10.250", gateway="192.168.10.1", prefix="192.168.10.0/24")],
            "ipv6_subnets": [],
        }
        candidate = render("templates/R2.cfg.j2", {**_BASE_CONTEXT, "dhcp": altered}, base=BASE)
        self.assertIn("range 192.168.10.240 192.168.10.250", candidate)
        self.assertNotIn("192.168.10.200", candidate)


class SemanticDeltaTests(unittest.TestCase):
    def test_real_integration_delta_is_dhcp_only(self):
        base_candidate = render("templates/R2.cfg.j2", _BASE_CONTEXT, base=BASE)
        integrated_candidate = render("templates/R2.cfg.j2", {**_BASE_CONTEXT, "dhcp": _REAL_CONTEXT}, base=BASE)
        delta = ic.dhcp_render_delta(eos_commands(base_candidate), eos_commands(integrated_candidate))
        self.assertEqual(r2._validate_delta_is_dhcp_only(delta), [])
        self.assertEqual(delta["removed"], [])

    def test_a_non_dhcp_addition_is_rejected(self):
        delta = {"added": ["router bgp 65000"], "removed": []}
        problems = r2._validate_delta_is_dhcp_only(delta)
        self.assertTrue(any("not DHCP-shaped" in p for p in problems))

    def test_any_removal_is_rejected(self):
        delta = {"added": [], "removed": ["router rip"]}
        problems = r2._validate_delta_is_dhcp_only(delta)
        self.assertTrue(any("removed" in p for p in problems))

    def test_bare_exit_is_accepted(self):
        delta = {"added": ["dhcp server", "exit"], "removed": []}
        self.assertEqual(r2._validate_delta_is_dhcp_only(delta), [])


class ValidateNestingTests(unittest.TestCase):
    def test_real_fragment_render_has_no_nesting_problems(self):
        candidate = render("templates/R2_dhcp_server.cfg.j2", {"dhcp": _REAL_CONTEXT}, base=BASE)
        self.assertEqual(r2._validate_nesting(candidate), [])

    def test_detects_a_child_command_under_the_wrong_parent(self):
        text = "dhcp server\n   range 10.0.0.1 10.0.0.2\n"  # "range" is not a direct child of "dhcp server"
        problems = r2._validate_nesting(text)
        self.assertTrue(any("not a recognized child" in p for p in problems))

    def test_ignores_blank_lines_and_bangs(self):
        text = "dhcp server\n\n!\n   subnet 10.0.0.0/24\n      range 10.0.0.10 10.0.0.20\n"
        self.assertEqual(r2._validate_nesting(text), [])


class MainEndToEndTests(unittest.TestCase):
    def test_netbox_not_ready_exits_1(self):
        with patch.object(ic, "validate_netbox_ready", side_effect=nb.NetboxConnectionError("down")):
            self.assertEqual(r2.main([]), 1)

    def test_context_build_failure_exits_1(self):
        with patch.object(ic, "validate_netbox_ready"), \
             patch.object(nb, "build_client", return_value=object()), \
             patch.object(ic, "build_and_validate_r2_dhcp_context", side_effect=nb.NetboxModelError("bad pools")):
            self.assertEqual(r2.main([]), 1)

    def test_happy_path_exits_0(self):
        with patch.object(ic, "validate_netbox_ready"), \
             patch.object(nb, "build_client", return_value=object()), \
             patch.object(ic, "build_and_validate_r2_dhcp_context", return_value=_REAL_CONTEXT), \
             patch.object(ic, "validate_r2_candidate_render"):
            self.assertEqual(r2.main([]), 0)

    def test_never_calls_any_push_or_connect_function(self):
        """Structural guarantee: this module has no netmiko/paramiko/ssh
        import at all, so it cannot push configuration even by accident."""
        source = SCRIPT_PATH.read_text()
        for forbidden in ("netmiko", "paramiko", "ConnectHandler", "ssh_exec"):
            self.assertNotIn(forbidden, source)

    def test_never_emits_a_commit_command(self):
        """This script only ever renders/prints text -- it has no
        mechanism to reach a live device at all, so 'commit' can never be
        part of its output pipeline (Step 9's non-goal, checked directly
        against the script's own source rather than a mocked run)."""
        source = SCRIPT_PATH.read_text()
        self.assertNotIn('"commit"', source)
        self.assertNotIn("'commit'", source)


if __name__ == "__main__":
    unittest.main()
