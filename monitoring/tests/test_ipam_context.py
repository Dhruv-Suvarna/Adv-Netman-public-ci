"""Offline unit tests for modules/ipam_context.py (Phase 3A: NetBox-backed
configuration context + shadow rendering).

`extract_legacy_facts`/`render_candidate_config` are tested against the
REAL templates/*.cfg.j2 files (read-only) -- this catches a future template
edit that silently breaks the regex extraction. Everything that would
otherwise need a live NetBox instance is tested by mocking
`modules.netbox_ipam`'s public functions directly (this module never talks
to pynetbox itself, only to that API), so no live NetBox instance, Docker,
or network access is used anywhere in this file.
"""
from __future__ import annotations

import unittest
from unittest.mock import patch

from modules import ipam_context as ic
from modules import netbox_ipam as nb
from modules.eos_render import render


class ExtractLegacyFactsTests(unittest.TestCase):
    """Regression tests against the real, unmodified templates."""

    def test_r1_interfaces(self):
        facts = ic.extract_legacy_facts("R1")
        self.assertEqual(facts.interfaces["Loopback0"], {"ipv4": "192.168.255.1/32", "ipv6": "2001:db8:255::1/128"})
        self.assertEqual(facts.interfaces["Vlan200"], {"ipv4": "192.168.200.1/24", "ipv6": "2001:db8:200::1/64"})
        self.assertEqual(facts.interfaces["Ethernet2"], {"ipv4": "192.168.110.0/31", "ipv6": "2001:db8:110:1::1/64"})

    def test_r1_static_route_next_hops(self):
        facts = ic.extract_legacy_facts("R1")
        self.assertIn("2001:db8:100:103::2", facts.peer_candidates)   # the aggregate anchors; the client statics went with the IS-IS migration

    def test_r3_bgp_neighbor_and_nat(self):
        facts = ic.extract_legacy_facts("R3")
        self.assertIn("172.20.5.1", facts.peer_candidates)
        self.assertIn("2001:db8:205:1::2", facts.peer_candidates)
        self.assertEqual(facts.nat_sources, {"192.168.10.0/24", "192.168.20.0/24"})

    def test_r3_uses_bash_style_addr_add(self):
        facts = ic.extract_legacy_facts("R3")
        self.assertEqual(facts.interfaces["lo"], {"ipv4": "192.168.255.3/32", "ipv6": "2001:db8:255::3/128"})

    def test_s1_vrrp_gateways(self):
        facts = ic.extract_legacy_facts("S1")
        self.assertEqual(facts.vrrp_gateways["Vlan10"], {"ipv4": "192.168.10.1", "ipv6": "2001:db8:10::1"})
        self.assertEqual(facts.vrrp_gateways["Vlan30"], {"ipv6": "2001:db8:30::1"})
        self.assertNotIn("ipv4", facts.vrrp_gateways["Vlan30"])  # IPv6-only VLAN30 preserved

    def test_s1_vlan30_has_no_ipv4(self):
        facts = ic.extract_legacy_facts("S1")
        self.assertNotIn("ipv4", facts.interfaces["Vlan30"])
        self.assertEqual(facts.interfaces["Vlan30"]["ipv6"], "2001:db8:30::2/64")

    def test_s3_has_only_management(self):
        facts = ic.extract_legacy_facts("S3")
        self.assertEqual(set(facts.interfaces), {"Vlan200"})
        self.assertEqual(facts.vrrp_gateways, {})
        self.assertEqual(facts.peer_candidates, set())

    def test_mgmt_swt_has_only_management(self):
        facts = ic.extract_legacy_facts("mgmt_swt")
        self.assertEqual(set(facts.interfaces), {"Vlan200"})

    def test_all_nine_managed_devices_extract_without_error(self):
        for device in ic.MANAGED_DEVICES:
            with self.subTest(device=device):
                facts = ic.extract_legacy_facts(device)
                self.assertIn("Vlan200", facts.interfaces)  # every managed device has a management SVI

    def test_missing_template_raises(self):
        with self.assertRaises(FileNotFoundError):
            ic.extract_legacy_facts("NoSuchDevice")


class CompareFactsTests(unittest.TestCase):
    def test_identical_facts_are_equivalent(self):
        legacy = ic.DeviceFacts(interfaces={"Vlan200": {"ipv4": "192.168.200.1/24", "ipv6": None}})
        netbox_facts = ic.DeviceFacts(interfaces={"Vlan200": {"ipv4": "192.168.200.1/24", "ipv6": None}})
        result = ic.compare_facts("R1", legacy, netbox_facts)
        self.assertTrue(result.equivalent)
        self.assertEqual(result.differences, [])

    def test_interface_address_mismatch_is_a_bug(self):
        legacy = ic.DeviceFacts(interfaces={"Vlan200": {"ipv4": "192.168.200.1/24", "ipv6": None}})
        netbox_facts = ic.DeviceFacts(interfaces={"Vlan200": {"ipv4": "192.168.200.99/24", "ipv6": None}})
        result = ic.compare_facts("R1", legacy, netbox_facts)
        self.assertFalse(result.equivalent)
        self.assertEqual(len(result.differences), 1)
        self.assertEqual(result.differences[0].classification, ic.BUG)
        self.assertEqual(result.differences[0].legacy, "192.168.200.1/24")
        self.assertEqual(result.differences[0].netbox, "192.168.200.99/24")

    def test_vrrp_gateway_mismatch_is_reported(self):
        legacy = ic.DeviceFacts(vrrp_gateways={"Vlan10": {"ipv4": "192.168.10.1"}})
        netbox_facts = ic.DeviceFacts(vrrp_gateways={"Vlan10": {"ipv4": "192.168.10.254"}})
        result = ic.compare_facts("S1", legacy, netbox_facts)
        self.assertFalse(result.equivalent)
        self.assertEqual(result.differences[0].category, "vrrp_gateway:Vlan10:ipv4")

    def test_missing_peer_candidate_is_reported(self):
        legacy = ic.DeviceFacts(peer_candidates={"172.20.5.1"})
        netbox_facts = ic.DeviceFacts(peer_candidates=set())
        result = ic.compare_facts("R3", legacy, netbox_facts)
        self.assertFalse(result.equivalent)
        self.assertEqual(result.differences[0].category, "peer_candidate")

    def test_extra_netbox_peer_candidate_is_not_a_difference(self):
        """NetBox is allowed to know about MORE peer relationships than the
        legacy template references (e.g. from unrelated devices) -- only a
        legacy value with no NetBox counterpart is a difference."""
        legacy = ic.DeviceFacts(peer_candidates={"172.20.5.1"})
        netbox_facts = ic.DeviceFacts(peer_candidates={"172.20.5.1", "172.20.5.3"})
        result = ic.compare_facts("R3", legacy, netbox_facts)
        self.assertTrue(result.equivalent)

    def test_missing_nat_source_is_reported(self):
        legacy = ic.DeviceFacts(nat_sources={"192.168.10.0/24"})
        netbox_facts = ic.DeviceFacts(nat_sources=set())
        result = ic.compare_facts("R3", legacy, netbox_facts)
        self.assertFalse(result.equivalent)
        self.assertEqual(result.differences[0].category, "nat_source")

    def test_missing_referenced_prefix_is_reported(self):
        legacy = ic.DeviceFacts(referenced_prefixes={"2001:db8:10::/64"})
        netbox_facts = ic.DeviceFacts(referenced_prefixes=set())
        result = ic.compare_facts("R1", legacy, netbox_facts)
        self.assertFalse(result.equivalent)
        self.assertEqual(result.differences[0].category, "referenced_prefix")

    def test_interface_only_in_legacy_is_reported(self):
        legacy = ic.DeviceFacts(interfaces={"Ethernet2": {"ipv4": "192.168.110.0/31", "ipv6": None}})
        netbox_facts = ic.DeviceFacts(interfaces={})
        result = ic.compare_facts("R1", legacy, netbox_facts)
        self.assertFalse(result.equivalent)

    def test_interface_only_in_netbox_is_reported(self):
        """The reverse direction matters too: if NetBox has an address for
        an interface the current template doesn't mention, that is still
        worth surfacing (e.g. a manifest drift), not silently ignored."""
        legacy = ic.DeviceFacts(interfaces={})
        netbox_facts = ic.DeviceFacts(interfaces={"Ethernet2": {"ipv4": "192.168.110.0/31", "ipv6": None}})
        result = ic.compare_facts("R1", legacy, netbox_facts)
        self.assertFalse(result.equivalent)


class BuildNetboxFactsTests(unittest.TestCase):
    """build_netbox_facts orchestrates several modules.netbox_ipam calls;
    mock that layer directly so this is fully offline and deterministic."""

    def test_uses_legacy_interface_names_and_netbox_values(self):
        def fake_get_interface_address(device, iface, family, client=None):
            table = {
                ("R1", "Vlan200", 4): {"cidr": "192.168.200.1/24", "address": "192.168.200.1"},
                ("R1", "Vlan200", 6): {"cidr": "2001:db8:200::1/64", "address": "2001:db8:200::1"},
            }
            return table.get((device, iface, family))

        with patch.object(nb, "get_interface_address", side_effect=fake_get_interface_address), \
             patch.object(nb, "get_peer_addresses", return_value=[]), \
             patch.object(nb, "list_all_prefix_cidrs", return_value=set()), \
             patch.object(ic, "extract_legacy_facts", return_value=ic.DeviceFacts(interfaces={"Vlan200": {"ipv4": "x", "ipv6": "y"}})):
            facts = ic.build_netbox_facts("R1", client=object())
        self.assertEqual(facts.interfaces["Vlan200"], {"ipv4": "192.168.200.1/24", "ipv6": "2001:db8:200::1/64"})

    def test_skips_peer_lookup_for_missing_family(self):
        """A legacy interface with no IPv6 address at all (e.g. Vlan99)
        must not trigger a peer lookup for that family."""
        calls = []

        def fake_get_peer_addresses(device, iface, family, client=None):
            calls.append(family)
            return []

        with patch.object(nb, "get_interface_address", return_value=None), \
             patch.object(nb, "get_peer_addresses", side_effect=fake_get_peer_addresses), \
             patch.object(nb, "list_all_prefix_cidrs", return_value=set()), \
             patch.object(ic, "extract_legacy_facts", return_value=ic.DeviceFacts(interfaces={"Vlan99": {"ipv4": "z"}})):
            ic.build_netbox_facts("S1", client=object())
        self.assertEqual(calls, [])  # get_interface_address returned None for both families -> no peer lookups at all

    def test_vrrp_gateway_vlan_id_inferred_from_interface_name(self):
        fake_client = object()
        with patch.object(nb, "get_interface_address", return_value=None), \
             patch.object(nb, "get_peer_addresses", return_value=[]), \
             patch.object(nb, "get_shared_gateway", return_value={"address": "192.168.10.1"}) as mock_gw, \
             patch.object(nb, "list_all_prefix_cidrs", return_value=set()), \
             patch.object(ic, "extract_legacy_facts", return_value=ic.DeviceFacts(vrrp_gateways={"Vlan10": {"ipv4": "192.168.10.1"}})):
            facts = ic.build_netbox_facts("S1", client=fake_client)
        mock_gw.assert_any_call(10, 4, fake_client)
        mock_gw.assert_any_call(10, 6, fake_client)
        self.assertEqual(facts.vrrp_gateways["Vlan10"]["ipv4"], "192.168.10.1")

    def test_vrrp_interface_name_must_be_vlan_shaped(self):
        with self.assertRaises(nb.NetboxModelError):
            ic._vlan_id_for_interface("Ethernet2")

    def test_nat_sources_filtered_to_known_universe(self):
        with patch.object(nb, "get_interface_address", return_value=None), \
             patch.object(nb, "get_peer_addresses", return_value=[]), \
             patch.object(nb, "list_all_prefix_cidrs", return_value={"192.168.10.0/24"}), \
             patch.object(ic, "extract_legacy_facts", return_value=ic.DeviceFacts(
                 nat_sources={"192.168.10.0/24", "10.0.0.0/24"},
             )):
            facts = ic.build_netbox_facts("R3", client=object())
        self.assertEqual(facts.nat_sources, {"192.168.10.0/24"})  # 10.0.0.0/24 is not a real NetBox prefix

    def test_referenced_prefix_normalizes_host_address_form(self):
        """EOS's `network 192.168.110.1/31` RIP statement uses a host
        address, not the canonical network base -- it must still match the
        canonical '192.168.110.0/31' universe entry."""
        with patch.object(nb, "get_interface_address", return_value=None), \
             patch.object(nb, "get_peer_addresses", return_value=[]), \
             patch.object(nb, "list_all_prefix_cidrs", return_value={"192.168.110.0/31"}), \
             patch.object(ic, "extract_legacy_facts", return_value=ic.DeviceFacts(
                 referenced_prefixes={"192.168.110.1/31"},
             )):
            facts = ic.build_netbox_facts("S1", client=object())
        self.assertEqual(facts.referenced_prefixes, {"192.168.110.1/31"})


class ValidateNetboxReadyTests(unittest.TestCase):
    # A real (tokenless) NetboxConfig, not a MagicMock: `has_token` must be
    # a real False so validate_netbox_ready's `if config.has_token:` branch
    # behaves correctly (a MagicMock's attributes are truthy by default,
    # which would wrongly trigger a real, unmocked verify_authentication()
    # call and thus a real HTTP request).
    NO_AUTH_CONFIG = nb.NetboxConfig(url="http://127.0.0.1:8000", token=None)

    def test_ready_when_everything_checks_out(self):
        with patch.object(nb, "load_config", return_value=self.NO_AUTH_CONFIG), \
             patch.object(nb, "check_status"), \
             patch.object(nb, "build_client", return_value=object()), \
             patch.object(nb, "get_managed_devices", return_value=list(ic.MANAGED_DEVICES)), \
             patch.object(nb, "get_primary_address", return_value={"address": "x"}):
            result = ic.validate_netbox_ready()
        self.assertEqual(result["status"], "ready")

    def test_fails_closed_on_connection_error(self):
        with patch.object(nb, "load_config", return_value=self.NO_AUTH_CONFIG), \
             patch.object(nb, "check_status", side_effect=nb.NetboxConnectionError("down")):
            with self.assertRaises(nb.NetboxConnectionError):
                ic.validate_netbox_ready()

    def test_fails_closed_on_authentication_error(self):
        fake_config = nb.NetboxConfig(url="http://x", token="bad")
        with patch.object(nb, "load_config", return_value=fake_config), \
             patch.object(nb, "check_status"), \
             patch.object(nb, "verify_authentication", side_effect=nb.NetboxAuthenticationError("bad token")):
            with self.assertRaises(nb.NetboxAuthenticationError):
                ic.validate_netbox_ready()

    def test_fails_closed_on_unexpected_managed_set(self):
        with patch.object(nb, "load_config", return_value=self.NO_AUTH_CONFIG), \
             patch.object(nb, "check_status"), \
             patch.object(nb, "build_client", return_value=object()), \
             patch.object(nb, "get_managed_devices", return_value=["R1"]):  # missing everyone else
            with self.assertRaises(nb.NetboxModelError):
                ic.validate_netbox_ready()

    def test_fails_closed_when_a_managed_device_has_no_primary_address(self):
        with patch.object(nb, "load_config", return_value=self.NO_AUTH_CONFIG), \
             patch.object(nb, "check_status"), \
             patch.object(nb, "build_client", return_value=object()), \
             patch.object(nb, "get_managed_devices", return_value=list(ic.MANAGED_DEVICES)), \
             patch.object(nb, "get_primary_address", return_value=None):
            with self.assertRaises(nb.NetboxModelError):
                ic.validate_netbox_ready()


class ManagedScopeEnforcementTests(unittest.TestCase):
    def test_build_device_context_refuses_r5(self):
        with patch.object(nb, "get_managed_devices", return_value=list(ic.MANAGED_DEVICES)):
            with self.assertRaises(nb.NetboxModelError):
                ic.build_device_context("R5", client=object())

    def test_build_device_context_refuses_webserver(self):
        with patch.object(nb, "get_managed_devices", return_value=list(ic.MANAGED_DEVICES)):
            with self.assertRaises(nb.NetboxModelError):
                ic.build_device_context("WebServer", client=object())

    def test_render_candidate_config_refuses_unmanaged_device(self):
        with patch.object(nb, "get_managed_devices", return_value=list(ic.MANAGED_DEVICES)):
            with self.assertRaises(nb.NetboxModelError):
                ic.render_candidate_config("R5", client=object())


class RenderCandidateConfigTests(unittest.TestCase):
    def test_no_substitution_needed_yields_identical_text(self):
        """When NetBox agrees with the current template on every address
        (the expected, verified Phase 2 state), the candidate render is
        byte-identical to the original template -- the strongest form of
        the equivalence proof."""
        with patch.object(nb, "require_managed_device"), \
             patch.object(ic, "build_netbox_facts", side_effect=lambda device, client=None: ic.extract_legacy_facts(device)):
            candidate = ic.render_candidate_config("S3", client=object())
        original = (ic.TEMPLATES_DIR / "S3.cfg.j2").read_text()
        self.assertEqual(candidate, original)

    def test_substitution_changes_only_the_targeted_literal(self):
        legacy = ic.extract_legacy_facts("S3")
        changed = ic.DeviceFacts(interfaces={"Vlan200": {"ipv4": "192.168.200.99/24", "ipv6": legacy.interfaces["Vlan200"]["ipv6"]}})
        with patch.object(nb, "require_managed_device"), \
             patch.object(ic, "build_netbox_facts", return_value=changed):
            candidate = ic.render_candidate_config("S3", client=object())
        self.assertIn("192.168.200.99/24", candidate)
        self.assertNotIn("192.168.200.13/24", candidate)


# ---------------------------------------------------------------------------
# Phase 3B: deterministic dynamic-assignment reservation view + validation.
# ---------------------------------------------------------------------------


def _row(**overrides):
    row = {
        "device": "R1", "interface": "Vlan200", "mac_address": "00:1C:73:20:AB:82",
        "mac_identity_status": nb.IDENTITY_AUTHORITATIVE, "platform": "cEOS",
        "ipv4": "192.168.200.1", "ipv4_mode": "dhcp-reserved",
        "ipv6": "2001:db8:200::1", "ipv6_mode": "dhcpv6-reserved",
        "dhcpv6_duid": None, "dhcpv6_iaid": None,
        "dhcpv6_identity_status": nb.IDENTITY_AUTHORITATIVE,
    }
    row.update(overrides)
    return row


class GetAddressReservationsTests(unittest.TestCase):
    def test_one_row_per_managed_device_interface(self):
        with patch.object(nb, "get_managed_devices", return_value=["R1"]), \
             patch.object(nb, "get_device", return_value={"device_type": "ceos-4-36-2f"}), \
             patch.object(nb, "get_device_interface_names", return_value=["Vlan200", "Loopback0"]), \
             patch.object(nb, "get_interface_address", return_value=None), \
             patch.object(nb, "get_assignment_modes", return_value={"ipv4_mode": "static", "ipv6_mode": "static", "dhcpv6_duid": None, "dhcpv6_iaid": None, "dhcpv6_identity_status": None}), \
             patch.object(nb, "get_interface_mac", return_value=None):
            rows = ic.get_address_reservations(client=object())
        self.assertEqual({r["interface"] for r in rows}, {"Vlan200", "Loopback0"})
        self.assertTrue(all(r["device"] == "R1" for r in rows))

    def test_addresses_and_mac_come_straight_from_netbox(self):
        """Reservation values are never independently generated -- they are
        exactly what modules.netbox_ipam's own read functions return (Step
        12: a reservation can never disagree with NetBox's own mapping,
        because it IS that mapping)."""
        with patch.object(nb, "get_managed_devices", return_value=["R1"]), \
             patch.object(nb, "get_device", return_value={"device_type": "ceos-4-36-2f"}), \
             patch.object(nb, "get_device_interface_names", return_value=["Vlan200"]), \
             patch.object(nb, "get_interface_address", side_effect=lambda d, i, fam, client=None: {"address": "192.168.200.1"} if fam == 4 else {"address": "2001:db8:200::1"}), \
             patch.object(nb, "get_assignment_modes", return_value={"ipv4_mode": "dhcp-reserved", "ipv6_mode": "dhcpv6-reserved", "dhcpv6_duid": "duid-x", "dhcpv6_iaid": "iaid-y", "dhcpv6_identity_status": nb.IDENTITY_OBSERVED}), \
             patch.object(nb, "get_interface_mac", return_value={"mac_address": "00:1C:73:20:AB:82", "identity_status": nb.IDENTITY_AUTHORITATIVE}):
            rows = ic.get_address_reservations(client=object())
        self.assertEqual(rows[0]["ipv4"], "192.168.200.1")
        self.assertEqual(rows[0]["ipv6"], "2001:db8:200::1")
        self.assertEqual(rows[0]["mac_address"], "00:1C:73:20:AB:82")
        self.assertEqual(rows[0]["dhcpv6_duid"], "duid-x")
        self.assertEqual(rows[0]["dhcpv6_iaid"], "iaid-y")
        self.assertEqual(rows[0]["mac_identity_status"], nb.IDENTITY_AUTHORITATIVE)
        self.assertEqual(rows[0]["dhcpv6_identity_status"], nb.IDENTITY_OBSERVED)
        self.assertEqual(rows[0]["platform"], "cEOS")

    def test_unmanaged_devices_never_appear(self):
        """R5/WebServer exclusion (Step 15) is structural: only
        get_managed_devices()'s own result is ever iterated."""
        with patch.object(nb, "get_managed_devices", return_value=["R1"]) as mock_managed, \
             patch.object(nb, "get_device", return_value={"device_type": "ceos-4-36-2f"}), \
             patch.object(nb, "get_device_interface_names", return_value=[]):
            rows = ic.get_address_reservations(client=object())
        mock_managed.assert_called_once()
        self.assertEqual(rows, [])

    def test_netbox_failure_propagates(self):
        with patch.object(nb, "get_managed_devices", side_effect=nb.NetboxConnectionError("down")):
            with self.assertRaises(nb.NetboxConnectionError):
                ic.get_address_reservations(client=object())


class ValidateReservationsTests(unittest.TestCase):
    def test_fully_valid_dhcp_row_passes(self):
        report = ic.validate_reservations([_row(dhcpv6_duid="00:03:00:01:00:1c:73:20:ab:82")])
        self.assertTrue(report.ok)
        self.assertEqual(report.readiness_counts, {"READY": 2, "BLOCKED": 0, "FAIL": 0})

    def test_fully_valid_static_row_passes(self):
        report = ic.validate_reservations([_row(ipv4_mode="static", ipv6_mode="static")])
        self.assertTrue(report.ok)

    def test_none_mode_with_no_address_passes(self):
        report = ic.validate_reservations([_row(ipv4=None, ipv4_mode="none", mac_address=None, ipv6_mode="static")])
        self.assertTrue(report.ok)

    def test_missing_mac_for_dhcp_reserved_fails(self):
        report = ic.validate_reservations([_row(mac_address=None, ipv6_mode="static", ipv6=None)])
        self.assertFalse(report.ok)
        self.assertTrue(any(i.category == "missing-mac" for i in report.issues))

    def test_missing_dhcpv6_identity_fails(self):
        report = ic.validate_reservations([_row()])  # duid/iaid default to None
        self.assertFalse(report.ok)
        self.assertTrue(any(i.category == "missing-dhcpv6-identity" for i in report.issues))

    def test_duid_and_iaid_both_present_is_not_missing_identity(self):
        report = ic.validate_reservations([_row(dhcpv6_duid="00:03:00:01:00:1c:73:20:ab:82", dhcpv6_iaid="20:ab:82:01")])
        self.assertFalse(any(i.category == "missing-dhcpv6-identity" for i in report.issues))

    def test_observed_mac_is_not_ready(self):
        report = ic.validate_reservations([_row(mac_identity_status=nb.IDENTITY_OBSERVED, ipv6_mode="static")])
        self.assertTrue(any(i.category == "mac-identity-observed" for i in report.issues))
        self.assertEqual(report.readiness[0].status, ic.READINESS_FAIL)

    def test_authoritative_mac_is_ready(self):
        report = ic.validate_reservations([_row(ipv6_mode="static")])
        self.assertEqual(report.readiness[0].status, ic.READINESS_READY)

    def test_blocked_mac_reports_blocker(self):
        report = ic.validate_reservations([_row(mac_identity_status=nb.IDENTITY_BLOCKED, ipv6_mode="static")])
        self.assertTrue(any(i.category == "mac-identity-blocked" and i.status == "BLOCKED" for i in report.issues))
        self.assertEqual(report.overall_status, ic.READINESS_BLOCKED)

    def test_missing_mac_identity_status_fails(self):
        report = ic.validate_reservations([_row(mac_identity_status=None, ipv6_mode="static")])
        self.assertTrue(any(i.category == "missing-mac-identity-status" for i in report.issues))

    def test_invalid_mac_fails(self):
        report = ic.validate_reservations([_row(mac_address="not-a-mac", ipv6_mode="static")])
        self.assertTrue(any(i.category == "invalid-mac" for i in report.issues))

    def test_multicast_mac_fails(self):
        report = ic.validate_reservations([_row(mac_address="01:00:5e:00:00:01", ipv6_mode="static")])
        self.assertTrue(any(i.category == "multicast-mac" for i in report.issues))

    def test_valid_unicast_mac_passes(self):
        report = ic.validate_reservations([_row(ipv6_mode="static")])
        self.assertFalse(any(i.category in {"invalid-mac", "multicast-mac"} for i in report.issues))

    def test_valid_deterministic_duid_passes_without_iaid(self):
        report = ic.validate_reservations([_row(ipv4_mode="static", dhcpv6_duid="00:03:00:01:00:1c:73:20:ab:82", dhcpv6_iaid=None)])
        self.assertTrue(report.ok)
        self.assertEqual(report.readiness[0].status, ic.READINESS_READY)

    def test_malformed_duid_fails(self):
        report = ic.validate_reservations([_row(ipv4_mode="static", dhcpv6_duid="00:01:broken")])
        self.assertTrue(any(i.category == "invalid-duid" for i in report.issues))

    def test_duid_must_correspond_to_authoritative_mac(self):
        report = ic.validate_reservations([_row(ipv4_mode="static", dhcpv6_duid="00:03:00:01:00:1c:73:20:ab:83")])
        self.assertTrue(any(i.category == "duid-mac-mismatch" for i in report.issues))

    def test_duplicate_duid_fails(self):
        duid = "00:03:00:01:00:1c:73:20:ab:82"
        rows = [
            _row(ipv4_mode="static", dhcpv6_duid=duid),
            _row(device="R2", mac_address="00:1C:73:20:AB:83", ipv4_mode="static", ipv4="192.168.200.2", ipv6="2001:db8:200::2", dhcpv6_duid=duid),
        ]
        report = ic.validate_reservations(rows)
        self.assertTrue(any(i.category == "duplicate-duid" for i in report.issues))

    def test_observed_dhcpv6_identity_is_not_ready(self):
        report = ic.validate_reservations([_row(ipv4_mode="static", dhcpv6_duid="00:03:00:01:00:1c:73:20:ab:82", dhcpv6_identity_status=nb.IDENTITY_OBSERVED)])
        self.assertTrue(any(i.category == "dhcpv6-identity-observed" for i in report.issues))

    def test_blocked_dhcpv6_reports_blocker_not_missing_identity(self):
        report = ic.validate_reservations([_row(ipv4_mode="static", platform="cEOS", dhcpv6_identity_status=nb.IDENTITY_BLOCKED)])
        self.assertTrue(any(i.category == "dhcpv6-identity-blocked" and i.status == "BLOCKED" for i in report.issues))
        self.assertFalse(any(i.category == "missing-dhcpv6-identity" for i in report.issues))
        self.assertEqual(report.overall_status, ic.READINESS_BLOCKED)

    def test_iaid_absence_is_non_blocking(self):
        report = ic.validate_reservations([_row(ipv4_mode="static", dhcpv6_duid="00:03:00:01:00:1c:73:20:ab:82", dhcpv6_iaid=None)])
        self.assertTrue(report.ok)

    def test_iaid_remains_represented_when_available(self):
        row = _row(ipv4_mode="static", dhcpv6_duid="00:03:00:01:00:1c:73:20:ab:82", dhcpv6_iaid="20:ab:82:01")
        report = ic.validate_reservations([row])
        self.assertEqual(report.rows[0]["dhcpv6_iaid"], "20:ab:82:01")

    def test_duplicate_mac_detected(self):
        rows = [_row(interface="Vlan200"), _row(device="R2", interface="Vlan200")]  # same MAC by default
        report = ic.validate_reservations(rows)
        self.assertTrue(any(i.category == "duplicate-mac" for i in report.issues))

    def test_duplicate_ipv4_detected(self):
        rows = [_row(mac_address="aa:aa:aa:aa:aa:aa"), _row(device="R2", mac_address="bb:bb:bb:bb:bb:bb")]  # same ipv4 default
        report = ic.validate_reservations(rows)
        self.assertTrue(any(i.category == "duplicate-ipv4" for i in report.issues))

    def test_duplicate_ipv6_detected(self):
        rows = [
            _row(mac_address="aa:aa:aa:aa:aa:aa", ipv4="192.168.200.1"),
            _row(device="R2", mac_address="bb:bb:bb:bb:bb:bb", ipv4="192.168.200.2"),  # same ipv6 default
        ]
        report = ic.validate_reservations(rows)
        self.assertTrue(any(i.category == "duplicate-ipv6" for i in report.issues))

    def test_conflicting_mode_none_but_address_present(self):
        report = ic.validate_reservations([_row(ipv4_mode="none")])  # ipv4 still set
        self.assertTrue(any(i.category == "conflicting-assignment-mode" for i in report.issues))

    def test_missing_address_for_declared_mode(self):
        report = ic.validate_reservations([_row(ipv4=None, ipv4_mode="static")])
        self.assertTrue(any(i.category == "missing-ipv4" for i in report.issues))

    def test_invalid_assignment_mode_value(self):
        report = ic.validate_reservations([_row(ipv4_mode="dhcp-selects-any-free-address")])
        self.assertTrue(any(i.category == "invalid-assignment-mode" for i in report.issues))

    def test_unmanaged_device_row_rejected(self):
        for device in ("R5", "WebServer"):
            with self.subTest(device=device):
                report = ic.validate_reservations([_row(device=device)], managed_devices={"R1"})
                self.assertTrue(any(i.category == "unmanaged-provisioning-target" for i in report.issues))

    def test_pool_collision_detected(self):
        pools = [{"start": "192.168.200.0", "end": "192.168.200.5", "family": 4}]
        report = ic.validate_reservations([_row()], dhcp_ranges=pools)
        self.assertTrue(any(i.category == "pool-collision" for i in report.issues))

    def test_no_pool_collision_outside_range(self):
        pools = [{"start": "192.168.200.100", "end": "192.168.200.179", "family": 4}]
        report = ic.validate_reservations([_row()], dhcp_ranges=pools)
        self.assertFalse(any(i.category == "pool-collision" for i in report.issues))

    def test_pool_collision_applies_to_static_addresses_too(self):
        """A STATIC infrastructure address inside an active DHCP pool range
        is still a real collision risk (Step 13): a DHCP server has no way
        to know to avoid handing that same address to a dynamic client
        unless it is separately excluded/reserved -- being statically
        configured does not make the numeric overlap safe."""
        pools = [{"start": "192.168.200.0", "end": "192.168.200.5", "family": 4}]
        report = ic.validate_reservations([_row(ipv4_mode="static", ipv6_mode="static")], dhcp_ranges=pools)
        self.assertTrue(any(i.category == "pool-collision" for i in report.issues))

    def test_pool_collision_ignored_when_mode_is_none(self):
        """An interface with mode="none" for a family has no address to
        collide with in the first place (already covered by
        test_none_mode_with_no_address_passes) -- confirmed here
        explicitly against a pool that would otherwise match."""
        pools = [{"start": "192.168.200.0", "end": "192.168.200.5", "family": 4}]
        report = ic.validate_reservations(
            [_row(ipv4=None, ipv4_mode="none", mac_address=None, ipv6_mode="static")], dhcp_ranges=pools,
        )
        self.assertFalse(any(i.category == "pool-collision" for i in report.issues))

    def test_empty_row_set_passes(self):
        report = ic.validate_reservations([])
        self.assertTrue(report.ok)
        self.assertEqual(report.rows, [])

    def test_multiple_issues_all_reported(self):
        rows = [_row(mac_address=None), _row(device="R2", ipv4="192.168.200.1", mac_address="ff:ff:ff:ff:ff:ff")]
        report = ic.validate_reservations(rows)
        categories = {i.category for i in report.issues}
        self.assertIn("missing-mac", categories)
        self.assertIn("duplicate-ipv4", categories)


class AssignmentModePolicyTests(unittest.TestCase):
    """The Phase 3B interface-classification policy in
    netbox/scripts/populate_netbox.py -- loaded by path like
    test_populate_netbox.py does."""

    @classmethod
    def setUpClass(cls):
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "populate_netbox_policy", ic.BASE / "netbox" / "scripts" / "populate_netbox.py",
        )
        cls.populate_netbox = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.populate_netbox)

    def test_management_interface_is_static(self):
        """Phase 3B.3: Vlan200 is the management VLAN and stays static --
        superseding Phase 3B's original dhcp-reserved/dhcpv6-reserved
        classification (see docs/NETBOX_IPAM.md 'Phase 3B.3')."""
        self.assertEqual(self.populate_netbox._assignment_mode("Vlan200", 4, True), "static")
        self.assertEqual(self.populate_netbox._assignment_mode("Vlan200", 6, True), "static")

    def test_no_interface_is_classified_dynamic(self):
        """No interface name maps to dhcp-reserved/dhcpv6-reserved today --
        those ASSIGNMENT_MODES values remain valid in the schema for a
        genuinely future target, but nothing currently uses them."""
        for name in ("Vlan200", "Loopback0", "Ethernet2", "Vlan10", "Vlan101", "lo"):
            for family in (4, 6):
                self.assertIn(self.populate_netbox._assignment_mode(name, family, True), ("static",))

    def test_loopback_is_static(self):
        self.assertEqual(self.populate_netbox._assignment_mode("Loopback0", 4, True), "static")
        self.assertEqual(self.populate_netbox._assignment_mode("lo", 6, True), "static")

    def test_transit_interface_is_static(self):
        self.assertEqual(self.populate_netbox._assignment_mode("Ethernet2", 4, True), "static")
        self.assertEqual(self.populate_netbox._assignment_mode("Vlan101", 6, True), "static")

    def test_client_vlan_own_svi_is_static(self):
        self.assertEqual(self.populate_netbox._assignment_mode("Vlan10", 4, True), "static")

    def test_absent_family_is_none_regardless_of_interface(self):
        """VLAN30's IPv6-only nature (Step 7 of Phase 2, preserved here):
        an interface with no address of a given family is classified
        "none" for that family, never fabricated as static/dhcp."""
        self.assertEqual(self.populate_netbox._assignment_mode("Vlan30", 4, False), "none")
        self.assertEqual(self.populate_netbox._assignment_mode("Vlan200", 4, False), "none")


class Phase3B3ManagementVlanStaticTests(unittest.TestCase):
    """Acceptance tests for Phase 3B.3 -- the management-VLAN policy
    correction. Vlan200 is the static management VLAN on all nine managed
    devices; it must never be evaluated as a DHCP/DHCPv6 reservation
    target, and a legacy 'blocked' DHCPv6 identity decision left over from
    the superseded Phase 3B/3B.1/3B.2 design must not block the corrected,
    all-static architecture."""

    def test_static_vlan200_row_produces_no_reservation_target(self):
        """A row shaped exactly like a corrected, live Vlan200 (static/
        static, no MAC, no DUID/IAID -- none of that is required anymore)
        produces zero READY/BLOCKED/FAIL entries."""
        row = _row(ipv4_mode="static", ipv6_mode="static", mac_address=None, mac_identity_status=None,
                    dhcpv6_duid=None, dhcpv6_iaid=None, dhcpv6_identity_status=None)
        report = ic.validate_reservations([row])
        self.assertTrue(report.ok)
        self.assertEqual(report.readiness, [])
        self.assertEqual(report.readiness_counts, {"READY": 0, "BLOCKED": 0, "FAIL": 0})
        self.assertEqual(report.overall_status, ic.READINESS_READY)

    def test_static_vlan200_does_not_require_mac_identity(self):
        row = _row(ipv4_mode="static", mac_address=None, mac_identity_status=None)
        report = ic.validate_reservations([row])
        self.assertFalse(any(i.category in ("missing-mac", "missing-mac-identity-status") for i in report.issues))

    def test_static_vlan200_does_not_require_duid_or_iaid(self):
        row = _row(ipv6_mode="static", dhcpv6_duid=None, dhcpv6_iaid=None, dhcpv6_identity_status=None)
        report = ic.validate_reservations([row])
        self.assertFalse(any(i.category in ("missing-dhcpv6-identity", "missing-dhcpv6-identity-status") for i in report.issues))

    def test_leftover_blocked_cEOS_dhcpv6_status_does_not_block_when_mode_is_static(self):
        """A row still carrying the SUPERSEDED Phase 3B.2 'blocked' DHCPv6
        finding (stale data a previous run wrote) must not surface as a
        BLOCKED reservation once the interface's mode is corrected to
        static -- the cEOS DHCPv6 investigation is historical context, not
        an active blocker on the current management architecture."""
        row = _row(
            ipv4_mode="static", mac_address=None, mac_identity_status=None,
            ipv6_mode="static", dhcpv6_identity_status=nb.IDENTITY_BLOCKED, dhcpv6_duid=None, dhcpv6_iaid=None,
        )
        report = ic.validate_reservations([row])
        self.assertEqual(report.readiness, [])
        self.assertEqual(report.overall_status, ic.READINESS_READY)

    def test_all_nine_managed_vlan200_are_static_end_to_end(self):
        """Drives the real assignment-mode policy (not a mock) across all
        nine managed devices' real manifest Vlan200 entries and confirms
        the resulting rows are never reservation targets."""
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "populate_netbox_e2e", ic.BASE / "netbox" / "scripts" / "populate_netbox.py",
        )
        populate_netbox = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(populate_netbox)
        manifest = populate_netbox.load_manifest()
        managed_vlan200_rows = []
        for device in manifest["devices"]:
            if not device.get("managed", True):
                continue
            by_name = {iface["name"]: iface for iface in device["interfaces"]}
            self.assertIn("Vlan200", by_name, f"{device['name']} missing Vlan200")
            addrs = by_name["Vlan200"]["addresses"]
            families = {__import__("ipaddress").ip_interface(a["address"]).version for a in addrs}
            self.assertEqual(families, {4, 6})
            row = _row(
                device=device["name"], interface="Vlan200",
                ipv4=f"10.0.0.{len(managed_vlan200_rows)}", ipv6=f"fd00::{len(managed_vlan200_rows)}",
                ipv4_mode=populate_netbox._assignment_mode("Vlan200", 4, True),
                ipv6_mode=populate_netbox._assignment_mode("Vlan200", 6, True),
                mac_address=None, mac_identity_status=None,
                dhcpv6_duid=None, dhcpv6_iaid=None, dhcpv6_identity_status=None,
            )
            self.assertEqual(row["ipv4_mode"], "static")
            self.assertEqual(row["ipv6_mode"], "static")
            managed_vlan200_rows.append(row)
        self.assertEqual(len(managed_vlan200_rows), 9)
        report = ic.validate_reservations(managed_vlan200_rows)
        self.assertTrue(report.ok)
        self.assertEqual(report.readiness, [])

    def test_r3_r4_vlan200_no_longer_dhcpv6_reserved(self):
        """R3/R4 previously had the one platform combination Phase 3B.1
        actually marked DHCPv6 'READY' (deterministic DUID-LL) -- confirm
        the correction applies to their real manifest entries too, not
        just the cEOS devices."""
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "populate_netbox_r3r4", ic.BASE / "netbox" / "scripts" / "populate_netbox.py",
        )
        populate_netbox = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(populate_netbox)
        manifest = populate_netbox.load_manifest()
        by_name = {d["name"]: d for d in manifest["devices"]}
        for device_name in ("R3", "R4"):
            iface = next(i for i in by_name[device_name]["interfaces"] if i["name"] == "Vlan200")
            families = {__import__("ipaddress").ip_interface(a["address"]).version for a in iface["addresses"]}
            self.assertEqual(families, {4, 6})
            mode_v4 = populate_netbox._assignment_mode("Vlan200", 4, True)
            mode_v6 = populate_netbox._assignment_mode("Vlan200", 6, True)
            self.assertEqual(mode_v4, "static")
            self.assertEqual(mode_v6, "static")
            self.assertNotEqual(mode_v6, "dhcpv6-reserved")


# ---------------------------------------------------------------------------
# Phase 3C: R2 secondary DHCP server -- normalized pool context.
# ---------------------------------------------------------------------------


def _vlan_dict(vid, v4_prefix=None, v6_prefix=None):
    def _prefix(cidr):
        if cidr is None:
            return None
        return {"prefix": cidr, "family": ic.ipaddress.ip_network(cidr).version, "prefix_length": None, "vlan_vid": vid, "role": "client", "managed": True, "description": None}
    return {"vid": vid, "name": f"VLAN{vid}", "role": "client", "prefix_ipv4": _prefix(v4_prefix), "prefix_ipv6": _prefix(v6_prefix)}


_VLANS = {
    10: _vlan_dict(10, "192.168.10.0/24", "2001:db8:10::/64"),
    20: _vlan_dict(20, "192.168.20.0/24", "2001:db8:20::/64"),
    30: _vlan_dict(30, None, "2001:db8:30::/64"),
}


def _range(server, start, end, family, description=None):
    return {"start": start, "end": end, "family": family, "server": server, "description": description}


_ALL_RANGES = {
    10: [
        _range("primary", "192.168.10.100", "192.168.10.179", 4),
        _range("secondary", "192.168.10.200", "192.168.10.220", 4),
        _range("primary", "2001:db8:10::1000", "2001:db8:10::1fff", 6),
        _range("secondary", "2001:db8:10::2000", "2001:db8:10::20ff", 6),
    ],
    20: [
        _range("primary", "192.168.20.100", "192.168.20.179", 4),
        _range("secondary", "192.168.20.200", "192.168.20.220", 4),
        _range("primary", "2001:db8:20::1000", "2001:db8:20::1fff", 6),
        _range("secondary", "2001:db8:20::2000", "2001:db8:20::20ff", 6),
    ],
    30: [
        _range("primary", "2001:db8:30::1000", "2001:db8:30::1fff", 6),
        _range("secondary", "2001:db8:30::2000", "2001:db8:30::20ff", 6),
    ],
}

_GATEWAYS = {
    (10, 4): "192.168.10.1", (10, 6): "2001:db8:10::1",
    (20, 4): "192.168.20.1", (20, 6): "2001:db8:20::1",
    (30, 4): None, (30, 6): "2001:db8:30::1",
}


def _patched_dhcp_context(ranges_by_vlan=None, vlans=None):
    ranges_by_vlan = ranges_by_vlan if ranges_by_vlan is not None else _ALL_RANGES
    vlans = vlans if vlans is not None else _VLANS

    def fake_get_vlan(vid, client=None):
        return vlans[vid]

    def fake_get_dhcp_ranges(vid=None, client=None):
        return ranges_by_vlan.get(vid, [])

    def fake_get_shared_gateway(vid, family, client=None):
        addr = _GATEWAYS.get((vid, family))
        return {"address": addr} if addr else None

    def fake_get_relay_targets(prefix, client=None):
        return ["192.168.200.100", "192.168.200.2"] if ic.ipaddress.ip_network(prefix).version == 4 else ["2001:db8:200::100", "2001:db8:200::2"]

    return (
        patch.object(nb, "get_vlan", side_effect=fake_get_vlan),
        patch.object(nb, "get_dhcp_ranges", side_effect=fake_get_dhcp_ranges),
        patch.object(nb, "get_shared_gateway", side_effect=fake_get_shared_gateway),
        patch.object(nb, "get_dhcp_relay_targets", side_effect=fake_get_relay_targets),
    )


class GetDhcpPoolContextTests(unittest.TestCase):
    def test_returns_every_primary_and_secondary_pool(self):
        patches = _patched_dhcp_context()
        with patches[0], patches[1], patches[2], patches[3]:
            pools = ic.get_dhcp_pool_context(client=object())
        # 4 pools each for VLAN10/20 (v4 primary+secondary, v6 primary+secondary), 2 for VLAN30 (v6 only)
        self.assertEqual(len(pools), 10)
        self.assertTrue(all(p.vlan in (10, 20, 30) for p in pools))

    def test_vlan30_never_has_an_ipv4_pool(self):
        patches = _patched_dhcp_context()
        with patches[0], patches[1], patches[2], patches[3]:
            pools = ic.get_dhcp_pool_context(client=object())
        self.assertFalse(any(p.vlan == 30 and p.family == 4 for p in pools))

    def test_untagged_range_reports_server_unknown_not_fabricated(self):
        ranges = {10: [_range(None, "192.168.10.50", "192.168.10.60", 4)], 20: [], 30: []}
        patches = _patched_dhcp_context(ranges_by_vlan=ranges)
        with patches[0], patches[1], patches[2], patches[3]:
            pools = ic.get_dhcp_pool_context(client=object())
        self.assertEqual(pools[0].server, "unknown")

    def test_gateway_and_relay_targets_are_attached(self):
        patches = _patched_dhcp_context()
        with patches[0], patches[1], patches[2], patches[3]:
            pools = ic.get_dhcp_pool_context(client=object())
        v10_v4_secondary = next(p for p in pools if p.vlan == 10 and p.family == 4 and p.server == "secondary")
        self.assertEqual(v10_v4_secondary.gateway, "192.168.10.1")
        self.assertEqual(v10_v4_secondary.relay_targets, ("192.168.200.100", "192.168.200.2"))


class GetR2DhcpContextTests(unittest.TestCase):
    def test_contains_exactly_five_secondary_pools(self):
        patches = _patched_dhcp_context()
        with patches[0], patches[1], patches[2], patches[3]:
            context = ic.get_r2_dhcp_context(client=object())
        total = len(context["ipv4_subnets"]) + len(context["ipv6_subnets"])
        self.assertEqual(total, 5)
        self.assertEqual(len(context["ipv4_subnets"]), 2)  # VLAN10, VLAN20
        self.assertEqual(len(context["ipv6_subnets"]), 3)  # VLAN10, VLAN20, VLAN30
        self.assertTrue(all(p.server == "secondary" for p in context["ipv4_subnets"] + context["ipv6_subnets"]))

    def test_never_includes_a_vlan30_ipv4_pool(self):
        patches = _patched_dhcp_context()
        with patches[0], patches[1], patches[2], patches[3]:
            context = ic.get_r2_dhcp_context(client=object())
        self.assertFalse(any(p.vlan == 30 and p.family == 4 for p in context["ipv4_subnets"]))

    def test_missing_secondary_pool_raises_model_error(self):
        ranges = dict(_ALL_RANGES)
        ranges[20] = [r for r in _ALL_RANGES[20] if not (r["server"] == "secondary" and r["family"] == 4)]
        patches = _patched_dhcp_context(ranges_by_vlan=ranges)
        with patches[0], patches[1], patches[2], patches[3]:
            with self.assertRaises(nb.NetboxModelError):
                ic.get_r2_dhcp_context(client=object())

    def test_stale_vlan30_ipv4_secondary_pool_raises_model_error(self):
        """Fail-closed: if a VLAN30 IPv4 secondary pool ever gets added to
        NetBox later, get_r2_dhcp_context() must refuse to render rather
        than silently including it (VLAN30 stays IPv6-only)."""
        ranges = dict(_ALL_RANGES)
        ranges[30] = list(_ALL_RANGES[30]) + [_range("secondary", "192.168.30.200", "192.168.30.220", 4)]
        vlans = dict(_VLANS)
        vlans[30] = _vlan_dict(30, "192.168.30.0/24", "2001:db8:30::/64")  # hypothetical future prefix
        patches = _patched_dhcp_context(ranges_by_vlan=ranges, vlans=vlans)
        with patches[0], patches[1], patches[2], patches[3]:
            with self.assertRaises(nb.NetboxModelError):
                ic.get_r2_dhcp_context(client=object())


class ValidateDhcpPoolSafetyTests(unittest.TestCase):
    def _pool(self, vlan, family, server, start, end, gateway=None, prefix=None):
        return ic.DhcpPool(vlan=vlan, family=family, server=server, prefix=prefix, start=start, end=end, gateway=gateway, relay_targets=(), description=None)

    def test_no_problems_for_the_real_matrix(self):
        patches = _patched_dhcp_context()
        with patches[0], patches[1], patches[2], patches[3]:
            pools = ic.get_dhcp_pool_context(client=object())
        self.assertEqual(ic.validate_dhcp_pool_safety(pools), [])

    def test_primary_secondary_overlap_detected(self):
        pools = [
            self._pool(10, 4, "primary", "192.168.10.100", "192.168.10.210", prefix="192.168.10.0/24"),
            self._pool(10, 4, "secondary", "192.168.10.200", "192.168.10.220", prefix="192.168.10.0/24"),
        ]
        problems = ic.validate_dhcp_pool_safety(pools)
        self.assertTrue(any("overlap" in p for p in problems))

    def test_non_overlapping_pools_pass(self):
        pools = [
            self._pool(10, 4, "primary", "192.168.10.100", "192.168.10.179", prefix="192.168.10.0/24"),
            self._pool(10, 4, "secondary", "192.168.10.200", "192.168.10.220", prefix="192.168.10.0/24"),
        ]
        self.assertEqual(ic.validate_dhcp_pool_safety(pools), [])

    def test_pool_outside_its_prefix_detected(self):
        pools = [self._pool(10, 4, "secondary", "192.168.99.200", "192.168.99.220", prefix="192.168.10.0/24")]
        problems = ic.validate_dhcp_pool_safety(pools)
        self.assertTrue(any("not inside its prefix" in p for p in problems))

    def test_pool_containing_gateway_detected(self):
        pools = [self._pool(10, 4, "secondary", "192.168.10.1", "192.168.10.220", gateway="192.168.10.1", prefix="192.168.10.0/24")]
        problems = ic.validate_dhcp_pool_safety(pools)
        self.assertTrue(any("protected address" in p for p in problems))

    def test_pool_containing_infrastructure_address_detected(self):
        pools = [self._pool(10, 4, "secondary", "192.168.10.2", "192.168.10.220", prefix="192.168.10.0/24")]
        problems = ic.validate_dhcp_pool_safety(pools, infrastructure_addresses={"192.168.10.2"})
        self.assertTrue(any("protected address" in p for p in problems))

    def test_a_pool_own_gateway_is_not_flagged_against_itself_falsely(self):
        """A pool whose range genuinely does NOT include its own gateway
        must not be flagged -- this is the ordinary, expected case."""
        pools = [self._pool(10, 4, "primary", "192.168.10.100", "192.168.10.179", gateway="192.168.10.1", prefix="192.168.10.0/24")]
        self.assertEqual(ic.validate_dhcp_pool_safety(pools), [])

    def test_vlan30_ipv4_pool_is_rejected(self):
        pools = [self._pool(30, 4, "secondary", "192.168.30.200", "192.168.30.220", prefix="192.168.30.0/24")]
        problems = ic.validate_dhcp_pool_safety(pools)
        self.assertTrue(any("VLAN30 must stay IPv6-only" in p for p in problems))

    def test_different_family_gateway_does_not_false_positive(self):
        """An IPv6 gateway must never be checked against an IPv4 pool
        (and vice versa) merely because both are numerically similar."""
        pools = [
            self._pool(10, 4, "secondary", "192.168.10.200", "192.168.10.220", prefix="192.168.10.0/24"),
            self._pool(10, 6, "secondary", "2001:db8:10::2000", "2001:db8:10::20ff", gateway="2001:db8:10::1", prefix="2001:db8:10::/64"),
        ]
        self.assertEqual(ic.validate_dhcp_pool_safety(pools), [])


# ---------------------------------------------------------------------------
# Phase 3D: R2 DHCP integration into the real push path.
# ---------------------------------------------------------------------------


class GetR2ProtectedAddressesTests(unittest.TestCase):
    def test_collects_s1_s2_client_svi_addresses(self):
        def fake_get_interface_address(device, interface, family, client=None):
            table = {
                ("S1", "Vlan10", 4): {"address": "192.168.10.2"},
                ("S1", "Vlan10", 6): {"address": "2001:db8:10::2"},
                ("S2", "Vlan10", 4): {"address": "192.168.10.3"},
            }
            return table.get((device, interface, family))

        with patch.object(nb, "get_interface_address", side_effect=fake_get_interface_address):
            self.assertEqual(ic.get_r2_protected_addresses(client=object()), {"192.168.10.2", "2001:db8:10::2", "192.168.10.3"})

    def test_missing_addresses_are_skipped_not_fabricated(self):
        with patch.object(nb, "get_interface_address", return_value=None):
            self.assertEqual(ic.get_r2_protected_addresses(client=object()), set())


class BuildAndValidateR2DhcpContextTests(unittest.TestCase):
    _SENTINEL_CONTEXT = {"ipv4_subnets": [], "ipv6_subnets": []}

    def test_returns_context_when_everything_is_safe(self):
        with patch.object(ic, "get_dhcp_pool_context", return_value=[]), \
             patch.object(ic, "get_r2_dhcp_context", return_value=self._SENTINEL_CONTEXT), \
             patch.object(ic, "get_r2_protected_addresses", return_value=set()), \
             patch.object(ic, "validate_dhcp_pool_safety", return_value=[]):
            result = ic.build_and_validate_r2_dhcp_context(client=object())
        self.assertIs(result, self._SENTINEL_CONTEXT)

    def test_raises_when_pool_safety_finds_a_problem(self):
        with patch.object(ic, "get_dhcp_pool_context", return_value=[]), \
             patch.object(ic, "get_r2_dhcp_context", return_value=self._SENTINEL_CONTEXT), \
             patch.object(ic, "get_r2_protected_addresses", return_value=set()), \
             patch.object(ic, "validate_dhcp_pool_safety", return_value=["VLAN10 IPv4 pools overlap: x vs y"]):
            with self.assertRaises(nb.NetboxModelError):
                ic.build_and_validate_r2_dhcp_context(client=object())

    def test_netbox_connection_failure_propagates_not_swallowed(self):
        """The fail-closed contract (Step 7): a NetBox outage must raise,
        never silently return a context that would let the caller render
        R2 without DHCP."""
        with patch.object(ic, "get_dhcp_pool_context", side_effect=nb.NetboxConnectionError("down")):
            with self.assertRaises(nb.NetboxConnectionError):
                ic.build_and_validate_r2_dhcp_context(client=object())

    def test_missing_secondary_pool_propagates_not_swallowed(self):
        """get_r2_dhcp_context()'s own missing/unexpected-pool check must
        still propagate through this wrapper."""
        with patch.object(ic, "get_dhcp_pool_context", return_value=[]), \
             patch.object(ic, "get_r2_dhcp_context", side_effect=nb.NetboxModelError("missing pool")):
            with self.assertRaises(nb.NetboxModelError):
                ic.build_and_validate_r2_dhcp_context(client=object())


class ValidateR2CandidateRenderTests(unittest.TestCase):
    def _primary(self, cidr):
        def fake(device, family, client=None):
            return {"cidr": cidr}
        return fake

    def test_passes_when_dhcp_section_and_addresses_present(self):
        candidate = "interface Vlan200\n   ip address 192.168.200.2/24\n   ipv6 address 2001:db8:200::2/64\n!\ndhcp server\n!\n"

        def fake_get_primary_address(device, family, client=None):
            return {"cidr": "192.168.200.2/24" if family == 4 else "2001:db8:200::2/64"}

        with patch.object(nb, "get_primary_address", side_effect=fake_get_primary_address):
            ic.validate_r2_candidate_render(candidate, client=object())  # must not raise

    def test_missing_dhcp_section_raises(self):
        candidate = "interface Vlan200\n   ip address 192.168.200.2/24\n!\n"
        with self.assertRaises(nb.NetboxModelError):
            ic.validate_r2_candidate_render(candidate, client=object())

    def test_lost_ipv4_address_raises(self):
        candidate = "interface Vlan200\n   ipv6 address 2001:db8:200::2/64\n!\ndhcp server\n!\n"

        def fake_get_primary_address(device, family, client=None):
            return {"cidr": "192.168.200.2/24" if family == 4 else "2001:db8:200::2/64"}

        with patch.object(nb, "get_primary_address", side_effect=fake_get_primary_address):
            with self.assertRaises(nb.NetboxModelError):
                ic.validate_r2_candidate_render(candidate, client=object())

    def test_lost_ipv6_address_raises(self):
        candidate = "interface Vlan200\n   ip address 192.168.200.2/24\n!\ndhcp server\n!\n"

        def fake_get_primary_address(device, family, client=None):
            return {"cidr": "192.168.200.2/24" if family == 4 else "2001:db8:200::2/64"}

        with patch.object(nb, "get_primary_address", side_effect=fake_get_primary_address):
            with self.assertRaises(nb.NetboxModelError):
                ic.validate_r2_candidate_render(candidate, client=object())

    def test_missing_primary_address_in_netbox_raises(self):
        candidate = "dhcp server\n!\n"
        with patch.object(nb, "get_primary_address", return_value=None):
            with self.assertRaises(nb.NetboxModelError):
                ic.validate_r2_candidate_render(candidate, client=object())


class DhcpRenderDeltaTests(unittest.TestCase):
    def test_reports_added_and_removed(self):
        base = ["hostname R2", "interface Vlan200", "ip address 192.168.200.2/24", "exit"]
        integrated = ["hostname R2", "interface Vlan200", "ip address 192.168.200.2/24", "dhcp server ipv4", "exit", "dhcp server", "exit"]
        delta = ic.dhcp_render_delta(base, integrated)
        self.assertEqual(delta["added"], sorted({"dhcp server ipv4", "dhcp server"}))
        self.assertEqual(delta["removed"], [])

    def test_identical_input_has_empty_delta(self):
        commands = ["hostname R2", "interface Vlan200", "exit"]
        self.assertEqual(ic.dhcp_render_delta(commands, commands), {"added": [], "removed": []})

    def test_detects_a_removed_line(self):
        base = ["a", "b", "c"]
        integrated = ["a", "c"]
        self.assertEqual(ic.dhcp_render_delta(base, integrated), {"added": [], "removed": ["b"]})


# ---------------------------------------------------------------------------
# Phase 3G: NMAS primary DHCP pool cutover to NetBox.
# ---------------------------------------------------------------------------


class GetNmasDhcpContextTests(unittest.TestCase):
    def test_returns_exactly_five_primary_pools_in_isc_shape(self):
        patches = _patched_dhcp_context()
        with patches[0], patches[1], patches[2], patches[3], \
             patch.object(nb, "get_prefix", side_effect=lambda prefix, client=None: {"prefix": prefix}):
            context = ic.get_nmas_dhcp_context(client=object())
        self.assertEqual(len(context["ipv4_subnets"]), 2)  # VLAN10, VLAN20
        self.assertEqual(len(context["ipv6_subnets"]), 3)  # VLAN10, VLAN20, VLAN30
        v10_v4 = next(s for s in context["ipv4_subnets"] if s["vlan"] == 10)
        self.assertEqual(v10_v4["network"], "192.168.10.0")
        self.assertEqual(v10_v4["netmask"], "255.255.255.0")
        self.assertEqual(v10_v4["start"], "192.168.10.100")
        self.assertEqual(v10_v4["gateway"], "192.168.10.1")

    def test_never_includes_a_vlan30_ipv4_pool(self):
        patches = _patched_dhcp_context()
        with patches[0], patches[1], patches[2], patches[3], \
             patch.object(nb, "get_prefix", side_effect=lambda prefix, client=None: {"prefix": prefix}):
            context = ic.get_nmas_dhcp_context(client=object())
        self.assertFalse(any(s["vlan"] == 30 for s in context["ipv4_subnets"]))

    def test_missing_primary_pool_raises_model_error(self):
        ranges = dict(_ALL_RANGES)
        ranges[20] = [r for r in _ALL_RANGES[20] if not (r["server"] == "primary" and r["family"] == 4)]
        patches = _patched_dhcp_context(ranges_by_vlan=ranges)
        with patches[0], patches[1], patches[2], patches[3], \
             patch.object(nb, "get_prefix", side_effect=lambda prefix, client=None: {"prefix": prefix}):
            with self.assertRaises(nb.NetboxModelError):
                ic.get_nmas_dhcp_context(client=object())

    def test_management_subnet_is_netbox_derived(self):
        patches = _patched_dhcp_context()
        seen = {}

        def fake_get_prefix(prefix, client=None):
            seen[prefix] = True
            return {"prefix": prefix}

        with patches[0], patches[1], patches[2], patches[3], \
             patch.object(nb, "get_prefix", side_effect=fake_get_prefix):
            context = ic.get_nmas_dhcp_context(client=object())
        self.assertIn("192.168.200.0/24", seen)
        self.assertIn("2001:db8:200::/64", seen)
        self.assertEqual(context["management"]["v4_network"], "192.168.200.0")
        self.assertEqual(context["management"]["v4_netmask"], "255.255.255.0")
        self.assertEqual(context["management"]["v6_prefix"], "2001:db8:200::/64")


class BuildAndValidateNmasDhcpContextTests(unittest.TestCase):
    _SENTINEL = {"ipv4_subnets": [], "ipv6_subnets": []}

    def test_returns_context_when_everything_is_safe(self):
        with patch.object(ic, "get_dhcp_pool_context", return_value=[]), \
             patch.object(ic, "get_nmas_dhcp_context", return_value=self._SENTINEL), \
             patch.object(ic, "get_r2_protected_addresses", return_value=set()), \
             patch.object(ic, "validate_dhcp_pool_safety", return_value=[]):
            result = ic.build_and_validate_nmas_dhcp_context(client=object())
        self.assertIs(result, self._SENTINEL)

    def test_raises_when_pool_safety_finds_a_problem(self):
        with patch.object(ic, "get_dhcp_pool_context", return_value=[]), \
             patch.object(ic, "get_nmas_dhcp_context", return_value=self._SENTINEL), \
             patch.object(ic, "get_r2_protected_addresses", return_value=set()), \
             patch.object(ic, "validate_dhcp_pool_safety", return_value=["overlap detected"]):
            with self.assertRaises(nb.NetboxModelError):
                ic.build_and_validate_nmas_dhcp_context(client=object())

    def test_netbox_failure_propagates_not_swallowed(self):
        with patch.object(ic, "get_dhcp_pool_context", side_effect=nb.NetboxConnectionError("down")):
            with self.assertRaises(nb.NetboxConnectionError):
                ic.build_and_validate_nmas_dhcp_context(client=object())

    def test_missing_primary_pool_propagates_not_swallowed(self):
        with patch.object(ic, "get_dhcp_pool_context", return_value=[]), \
             patch.object(ic, "get_nmas_dhcp_context", side_effect=nb.NetboxModelError("missing pool")):
            with self.assertRaises(nb.NetboxModelError):
                ic.build_and_validate_nmas_dhcp_context(client=object())

    def test_shares_the_same_safety_validator_as_r2(self):
        """Step 15: one shared safety model -- both NMAS and R2 gates call
        the exact same validate_dhcp_pool_safety()/get_dhcp_pool_context()/
        get_r2_protected_addresses(), never a second, independent copy."""
        pool_calls = []
        with patch.object(ic, "get_dhcp_pool_context", side_effect=lambda client=None: (pool_calls.append("pool"), [])[1]), \
             patch.object(ic, "get_nmas_dhcp_context", return_value=self._SENTINEL), \
             patch.object(ic, "get_r2_dhcp_context", return_value=self._SENTINEL), \
             patch.object(ic, "get_r2_protected_addresses", return_value=set()), \
             patch.object(ic, "validate_dhcp_pool_safety", return_value=[]) as mock_validate:
            ic.build_and_validate_nmas_dhcp_context(client=object())
            ic.build_and_validate_r2_dhcp_context(client=object())
        self.assertEqual(mock_validate.call_count, 2)
        self.assertEqual(len(pool_calls), 2)


class NmasTemplateNetboxDrivenTests(unittest.TestCase):
    """Templates contain no permanent pool-boundary literals -- proven the
    same way as R2's fragment (Phase 3C): a content scan of the raw
    template source."""

    def test_dhcpd_conf_j2_has_no_literal_pool_addresses(self):
        source = (ic.BASE / "dhcp" / "dhcpd.conf.j2").read_text()
        for literal in ("192.168.10.100", "192.168.10.179", "192.168.20.100", "192.168.20.179", "192.168.10.1", "192.168.20.1"):
            self.assertNotIn(literal, source)
        self.assertIn("dhcp.ipv4_subnets", source)
        self.assertIn("dhcp.management", source)

    def test_dhcpd6_conf_j2_has_no_literal_pool_addresses(self):
        source = (ic.BASE / "dhcp" / "dhcpd6.conf.j2").read_text()
        for literal in ("2001:db8:10::1000", "2001:db8:10::1fff", "2001:db8:20::1000", "2001:db8:30::1000"):
            self.assertNotIn(literal, source)
        self.assertIn("dhcp.ipv6_subnets", source)
        self.assertIn("dhcp.management", source)

    def test_dhcpd_conf_j2_render_matches_pre_cutover_output_exactly(self):
        """Step 20's semantic-equivalence proof, as a permanent regression
        test: rendering with the real, current NetBox-derived context
        must still produce byte-identical output to the original,
        hand-written literal file."""
        patches = _patched_dhcp_context()
        with patches[0], patches[1], patches[2], patches[3], \
             patch.object(nb, "get_prefix", side_effect=lambda prefix, client=None: {"prefix": prefix}):
            context = ic.get_nmas_dhcp_context(client=object())
        rendered = render("dhcp/dhcpd.conf.j2", {"management": {}, "dhcp": context})
        expected = (
            "authoritative;\n"
            "default-lease-time 28800;\n"
            "max-lease-time 28800;\n\n"
            "# Local NMAS management segment; no leases are handed out here.\n"
            "subnet 192.168.200.0 netmask 255.255.255.0 {\n}\n\n"
            "subnet 192.168.10.0 netmask 255.255.255.0 {\n"
            "  range 192.168.10.100 192.168.10.179;\n"
            "  option routers 192.168.10.1;\n"
            "  option subnet-mask 255.255.255.0;\n}\n\n"
            "subnet 192.168.20.0 netmask 255.255.255.0 {\n"
            "  range 192.168.20.100 192.168.20.179;\n"
            "  option routers 192.168.20.1;\n"
            "  option subnet-mask 255.255.255.0;\n}\n"
        )
        self.assertEqual(rendered, expected)


if __name__ == "__main__":
    unittest.main()
