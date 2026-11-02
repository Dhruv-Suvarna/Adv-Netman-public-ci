"""Offline unit tests for netbox/scripts/populate_netbox.py (Phase 2):
manifest parsing/validation and lab-specific scope logic.

No live NetBox instance is used here -- see
monitoring/tests/test_netbox_ipam.py for the (also offline, fake-endpoint-
based) generic reconciliation-primitive tests, and
`netbox/scripts/verify_netbox_model.py` for the live desired-state check.

`populate_netbox.py` lives under netbox/scripts/ (not a Python package), so
it is loaded here by file path via importlib rather than a normal import.
"""
from __future__ import annotations

import copy
import importlib.util
import ipaddress
import unittest
from pathlib import Path
from unittest.mock import patch

import yaml

from modules import netbox_ipam

BASE = Path(__file__).resolve().parents[2]
MANIFEST_PATH = BASE / "netbox" / "ipam.yml"
SCRIPT_PATH = BASE / "netbox" / "scripts" / "populate_netbox.py"
PIN_SCRIPT_PATH = BASE / "netbox" / "scripts" / "pin_stable_identities.py"


def _load_populate_netbox():
    spec = importlib.util.spec_from_file_location("populate_netbox", SCRIPT_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


populate_netbox = _load_populate_netbox()


def _load_pin_stable_identities():
    spec = importlib.util.spec_from_file_location("pin_stable_identities", PIN_SCRIPT_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


pin_stable_identities = _load_pin_stable_identities()


def _minimal_manifest() -> dict:
    """A tiny, self-consistent manifest -- enough to exercise
    _validate_manifest's checks without needing the full real lab."""
    return {
        "tags": {"ownership": "csci5840-iac", "managed": "managed", "unmanaged": "unmanaged"},
        "manufacturers": [{"name": "Arista", "slug": "arista"}],
        "device_types": [{"model": "cEOS", "slug": "ceos", "manufacturer": "arista"}],
        "device_roles": [{"name": "Router", "slug": "router"}],
        "ipam_roles": [{"name": "Client", "slug": "client"}],
        "vlans": [{"vid": 10, "name": "USERS10"}],
        "prefixes": [
            {"prefix": "192.168.10.0/24", "vlan": 10, "role": "client", "gateway_v4": "192.168.10.1"},
        ],
        "dhcp_ranges": [
            {"name": "VLAN10-v4", "start": "192.168.10.100", "end": "192.168.10.179", "vlan": 10},
        ],
        "dhcp_relay_targets": {},
        "devices": [
            {
                "name": "R1", "role": "router", "device_type": "ceos", "managed": True,
                "interfaces": [{"name": "Vlan10", "addresses": [{"address": "192.168.10.2/24"}]}],
            },
        ],
        "virtual_ips": [{"address": "192.168.10.1/24", "role": "vrrp"}],
    }


class ManifestValidationTests(unittest.TestCase):
    def test_minimal_manifest_is_valid(self):
        populate_netbox._validate_manifest(_minimal_manifest())  # must not raise

    def test_duplicate_prefix_is_rejected(self):
        manifest = _minimal_manifest()
        manifest["prefixes"].append(dict(manifest["prefixes"][0]))
        with self.assertRaisesRegex(ValueError, "Duplicate prefix"):
            populate_netbox._validate_manifest(manifest)

    def test_invalid_prefix_syntax_is_rejected(self):
        manifest = _minimal_manifest()
        manifest["prefixes"][0]["prefix"] = "not-a-prefix"
        with self.assertRaisesRegex(ValueError, "Invalid prefix"):
            populate_netbox._validate_manifest(manifest)

    def test_non_strict_prefix_is_rejected(self):
        """A prefix with host bits set (e.g. 192.168.10.5/24 instead of
        192.168.10.0/24) is a real authoring mistake, not a valid network."""
        manifest = _minimal_manifest()
        manifest["prefixes"][0]["prefix"] = "192.168.10.5/24"
        with self.assertRaisesRegex(ValueError, "Invalid prefix"):
            populate_netbox._validate_manifest(manifest)

    def test_gateway_outside_prefix_is_rejected(self):
        manifest = _minimal_manifest()
        manifest["prefixes"][0]["gateway_v4"] = "10.0.0.1"
        with self.assertRaisesRegex(ValueError, "not inside the prefix"):
            populate_netbox._validate_manifest(manifest)

    def test_prefix_referencing_unknown_vlan_is_rejected(self):
        manifest = _minimal_manifest()
        manifest["prefixes"][0]["vlan"] = 999
        with self.assertRaisesRegex(ValueError, "unknown vlan"):
            populate_netbox._validate_manifest(manifest)

    def test_prefix_referencing_unknown_role_is_rejected(self):
        manifest = _minimal_manifest()
        manifest["prefixes"][0]["role"] = "nonexistent-role"
        with self.assertRaisesRegex(ValueError, "unknown ipam role"):
            populate_netbox._validate_manifest(manifest)

    def test_device_referencing_unknown_device_type_is_rejected(self):
        manifest = _minimal_manifest()
        manifest["devices"][0]["device_type"] = "nonexistent-type"
        with self.assertRaisesRegex(ValueError, "unknown device_type"):
            populate_netbox._validate_manifest(manifest)

    def test_device_referencing_unknown_role_is_rejected(self):
        manifest = _minimal_manifest()
        manifest["devices"][0]["role"] = "nonexistent-role"
        with self.assertRaisesRegex(ValueError, "unknown role"):
            populate_netbox._validate_manifest(manifest)

    def test_duplicate_device_name_is_rejected(self):
        manifest = _minimal_manifest()
        manifest["devices"].append(copy.deepcopy(manifest["devices"][0]))
        with self.assertRaisesRegex(ValueError, "Duplicate device name"):
            populate_netbox._validate_manifest(manifest)

    def test_duplicate_interface_name_on_one_device_is_rejected(self):
        manifest = _minimal_manifest()
        manifest["devices"][0]["interfaces"].append(dict(manifest["devices"][0]["interfaces"][0]))
        with self.assertRaisesRegex(ValueError, "duplicate interface name"):
            populate_netbox._validate_manifest(manifest)

    def test_invalid_interface_address_is_rejected(self):
        manifest = _minimal_manifest()
        manifest["devices"][0]["interfaces"][0]["addresses"][0]["address"] = "999.999.999.999/24"
        with self.assertRaisesRegex(ValueError, "invalid address"):
            populate_netbox._validate_manifest(manifest)

    def test_same_address_on_two_different_owners_is_rejected(self):
        manifest = _minimal_manifest()
        manifest["devices"].append({
            "name": "R2", "role": "router", "device_type": "ceos", "managed": True,
            "interfaces": [{"name": "Vlan10", "addresses": [{"address": "192.168.10.2/24"}]}],
        })
        with self.assertRaisesRegex(ValueError, "Duplicate IP assignment"):
            populate_netbox._validate_manifest(manifest)

    def test_same_address_twice_on_the_same_interface_is_not_a_false_duplicate(self):
        """The dedupe check keys on (address, owner) -- re-declaring the
        identical address under the identical device/interface is not the
        bug it is meant to catch."""
        manifest = _minimal_manifest()
        manifest["devices"][0]["interfaces"][0]["addresses"].append(
            dict(manifest["devices"][0]["interfaces"][0]["addresses"][0])
        )
        populate_netbox._validate_manifest(manifest)  # must not raise

    def test_dhcp_range_start_after_end_is_rejected(self):
        manifest = _minimal_manifest()
        manifest["dhcp_ranges"][0]["start"], manifest["dhcp_ranges"][0]["end"] = (
            manifest["dhcp_ranges"][0]["end"], manifest["dhcp_ranges"][0]["start"],
        )
        with self.assertRaisesRegex(ValueError, "start is after end"):
            populate_netbox._validate_manifest(manifest)

    def test_dhcp_range_mixed_families_is_rejected(self):
        manifest = _minimal_manifest()
        manifest["dhcp_ranges"][0]["end"] = "2001:db8:10::1fff"
        with self.assertRaisesRegex(ValueError, "mixes address families"):
            populate_netbox._validate_manifest(manifest)

    def test_dhcp_range_invalid_address_is_rejected(self):
        manifest = _minimal_manifest()
        manifest["dhcp_ranges"][0]["start"] = "not-an-address"
        with self.assertRaisesRegex(ValueError, "invalid address"):
            populate_netbox._validate_manifest(manifest)

    def test_dhcp_range_unknown_vlan_is_rejected(self):
        manifest = _minimal_manifest()
        manifest["dhcp_ranges"][0]["vlan"] = 999
        with self.assertRaisesRegex(ValueError, "unknown vlan"):
            populate_netbox._validate_manifest(manifest)

    def test_invalid_virtual_ip_is_rejected(self):
        manifest = _minimal_manifest()
        manifest["virtual_ips"][0]["address"] = "not-an-address"
        with self.assertRaisesRegex(ValueError, "Invalid virtual_ips address"):
            populate_netbox._validate_manifest(manifest)

    def test_duplicate_vlan_id_is_rejected(self):
        manifest = _minimal_manifest()
        manifest["vlans"].append(dict(manifest["vlans"][0]))
        with self.assertRaisesRegex(ValueError, "Duplicate VLAN id"):
            populate_netbox._validate_manifest(manifest)

    def test_multiple_errors_are_all_reported_together(self):
        manifest = _minimal_manifest()
        manifest["prefixes"][0]["prefix"] = "not-a-prefix"
        manifest["devices"][0]["device_type"] = "nonexistent"
        with self.assertRaises(ValueError) as ctx:
            populate_netbox._validate_manifest(manifest)
        message = str(ctx.exception)
        self.assertIn("Invalid prefix", message)
        self.assertIn("unknown device_type", message)


class PopulatorScopeTests(unittest.TestCase):
    """Tests for the manifest-driven managed/unmanaged scope logic, using
    the ownership/tag helper directly (no NetBox calls involved)."""

    def setUp(self):
        self.manifest = _minimal_manifest()
        self.populator = populate_netbox.Populator(client=None, manifest=self.manifest, apply=False)

    def test_ownership_tags_always_include_ownership_marker(self):
        self.assertIn("csci5840-iac", self.populator.ownership_tags())
        self.assertIn("csci5840-iac", self.populator.ownership_tags(managed=True))
        self.assertIn("csci5840-iac", self.populator.ownership_tags(managed=False))

    def test_managed_true_adds_managed_tag_only(self):
        tags = self.populator.ownership_tags(managed=True)
        self.assertIn("managed", tags)
        self.assertNotIn("unmanaged", tags)

    def test_managed_false_adds_unmanaged_tag_only(self):
        tags = self.populator.ownership_tags(managed=False)
        self.assertIn("unmanaged", tags)
        self.assertNotIn("managed", tags)

    def test_managed_none_adds_neither_scope_tag(self):
        tags = self.populator.ownership_tags(managed=None)
        self.assertNotIn("managed", tags)
        self.assertNotIn("unmanaged", tags)


class RealManifestContentTests(unittest.TestCase):
    """Assertions against the ACTUAL lab manifest (netbox/ipam.yml) -- these
    catch a future manifest edit that accidentally breaks a Phase-2
    invariant, not just the parsing/validation logic in isolation."""

    @classmethod
    def setUpClass(cls):
        cls.manifest = yaml.safe_load(MANIFEST_PATH.read_text())

    def test_real_manifest_is_structurally_valid(self):
        populate_netbox._validate_manifest(self.manifest)  # must not raise

    def test_r5_and_webserver_are_never_managed(self):
        devices_by_name = {d["name"]: d for d in self.manifest["devices"]}
        for name in ("R5", "WebServer"):
            self.assertIn(name, devices_by_name, f"{name} should be modeled (for IPAM collision prevention)")
            self.assertFalse(devices_by_name[name].get("managed", True), f"{name} must be managed: false")

    def test_every_other_managed_device_is_managed_true(self):
        expected_managed = {"R1", "R2", "R3", "R4", "S1", "S2", "S3", "S4", "mgmt_swt"}
        devices_by_name = {d["name"]: d for d in self.manifest["devices"]}
        for name in expected_managed:
            self.assertTrue(devices_by_name[name].get("managed", True), f"{name} should be managed: true")

    def test_vlan30_has_no_ipv4_prefix(self):
        """H4's IPv6-only design (Step 6/15) must be preserved: VLAN30 gets
        an IPv6 prefix and NO IPv4 prefix anywhere in the manifest."""
        vlan30_prefixes = [p for p in self.manifest["prefixes"] if p.get("vlan") == 30]
        self.assertTrue(vlan30_prefixes, "VLAN30 should have at least one prefix")
        for entry in vlan30_prefixes:
            self.assertEqual(ipaddress.ip_network(entry["prefix"]).version, 6, f"{entry['prefix']} should not exist for VLAN30")

    def test_vlan30_has_no_ipv4_dhcp_range(self):
        vlan30_ranges = [r for r in self.manifest.get("dhcp_ranges", []) if r.get("vlan") == 30]
        self.assertTrue(vlan30_ranges, "VLAN30 should have at least one DHCP range")
        for entry in vlan30_ranges:
            self.assertEqual(ipaddress.ip_address(entry["start"]).version, 6)

    def test_client_vlans_have_both_v4_and_v6_dhcp_ranges_except_vlan30(self):
        by_vlan: dict[int, set[int]] = {}
        for entry in self.manifest.get("dhcp_ranges", []):
            by_vlan.setdefault(entry["vlan"], set()).add(ipaddress.ip_address(entry["start"]).version)
        self.assertEqual(by_vlan[10], {4, 6})
        self.assertEqual(by_vlan[20], {4, 6})
        self.assertEqual(by_vlan[30], {6})

    # -- Phase 3C: R2 secondary DHCP server modeling ------------------------

    def test_five_primary_ranges_remain_exact(self):
        """Regression: the 5 original NMAS primary ranges (Phase 2) must be
        byte-for-byte unchanged by the Phase 3C secondary-pool addition."""
        primaries = {e["name"]: e for e in self.manifest["dhcp_ranges"] if e.get("server", "nmas") == "nmas"}
        expected = {
            "VLAN10-v4-primary": ("192.168.10.100", "192.168.10.179"),
            "VLAN20-v4-primary": ("192.168.20.100", "192.168.20.179"),
            "VLAN10-v6-primary": ("2001:db8:10::1000", "2001:db8:10::1fff"),
            "VLAN20-v6-primary": ("2001:db8:20::1000", "2001:db8:20::1fff"),
            "VLAN30-v6-primary": ("2001:db8:30::1000", "2001:db8:30::1fff"),
        }
        self.assertEqual(set(primaries), set(expected))
        for name, (start, end) in expected.items():
            self.assertEqual(str(primaries[name]["start"]), start)
            self.assertEqual(str(primaries[name]["end"]), end)

    def test_five_secondary_ranges_exist(self):
        secondaries = {e["name"] for e in self.manifest["dhcp_ranges"] if e.get("server") == "r2"}
        self.assertEqual(
            secondaries,
            {"VLAN10-v4-secondary", "VLAN20-v4-secondary", "VLAN10-v6-secondary", "VLAN20-v6-secondary", "VLAN30-v6-secondary"},
        )

    def test_primary_and_secondary_ranges_never_overlap(self):
        by_vlan_family: dict[tuple[int, int], list[tuple[str, int, int]]] = {}
        for entry in self.manifest["dhcp_ranges"]:
            start, end = ipaddress.ip_address(entry["start"]), ipaddress.ip_address(entry["end"])
            key = (entry["vlan"], start.version)
            by_vlan_family.setdefault(key, []).append((entry.get("server", "nmas"), int(start), int(end)))
        for key, ranges in by_vlan_family.items():
            for i, (server_a, a_start, a_end) in enumerate(ranges):
                for server_b, b_start, b_end in ranges[i + 1:]:
                    overlap = a_start <= b_end and b_start <= a_end
                    self.assertFalse(overlap, f"VLAN/family {key}: {server_a} and {server_b} ranges overlap")

    def test_all_ranges_belong_to_correct_prefixes(self):
        prefixes_by_vlan_family: dict[tuple[int, int], str] = {}
        for entry in self.manifest["prefixes"]:
            if entry.get("vlan") is None:
                continue
            network = ipaddress.ip_network(entry["prefix"])
            prefixes_by_vlan_family[(entry["vlan"], network.version)] = entry["prefix"]
        for entry in self.manifest["dhcp_ranges"]:
            start = ipaddress.ip_address(entry["start"])
            end = ipaddress.ip_address(entry["end"])
            prefix = prefixes_by_vlan_family.get((entry["vlan"], start.version))
            self.assertIsNotNone(prefix, f"{entry['name']}: no matching prefix for VLAN{entry['vlan']} IPv{start.version}")
            network = ipaddress.ip_network(prefix)
            self.assertIn(start, network, f"{entry['name']}: start {start} not inside {prefix}")
            self.assertIn(end, network, f"{entry['name']}: end {end} not inside {prefix}")

    def test_vlan10_has_v4_and_v6_primary_and_secondary(self):
        by_key = {(e["vlan"], ipaddress.ip_address(e["start"]).version, e.get("server", "nmas")) for e in self.manifest["dhcp_ranges"]}
        for family in (4, 6):
            self.assertIn((10, family, "nmas"), by_key)
            self.assertIn((10, family, "r2"), by_key)

    def test_vlan20_has_v4_and_v6_primary_and_secondary(self):
        by_key = {(e["vlan"], ipaddress.ip_address(e["start"]).version, e.get("server", "nmas")) for e in self.manifest["dhcp_ranges"]}
        for family in (4, 6):
            self.assertIn((20, family, "nmas"), by_key)
            self.assertIn((20, family, "r2"), by_key)

    def test_vlan30_has_v6_only_primary_and_secondary(self):
        vlan30 = [e for e in self.manifest["dhcp_ranges"] if e["vlan"] == 30]
        self.assertEqual({e.get("server", "nmas") for e in vlan30}, {"nmas", "r2"})
        self.assertTrue(all(ipaddress.ip_address(e["start"]).version == 6 for e in vlan30))

    def test_h1_through_h4_remain_ordinary_dynamic_clients(self):
        """Phase 3C added no fixed reservation anywhere -- H1-H4 are not
        NetBox devices at all and dhcp_ranges never encodes a per-host
        mapping, only pool boundaries."""
        device_names = {d["name"] for d in self.manifest["devices"]}
        self.assertTrue(device_names.isdisjoint({"H1", "H2", "H3", "H4"}))
        for entry in self.manifest["dhcp_ranges"]:
            self.assertNotIn("mac", entry)
            self.assertNotIn("reservation", entry)

    def test_no_device_type_or_role_reference_is_dangling(self):
        # Exercised indirectly by test_real_manifest_is_structurally_valid,
        # but asserted explicitly here for clarity of intent.
        device_type_slugs = {t["slug"] for t in self.manifest["device_types"]}
        role_slugs = {r["slug"] for r in self.manifest["device_roles"]}
        for device in self.manifest["devices"]:
            self.assertIn(device["device_type"], device_type_slugs)
            self.assertIn(device["role"], role_slugs)

    def test_no_managed_interface_is_a_dynamic_reservation_target(self):
        """Phase 3B.3: Vlan200 is the static management VLAN, so no
        managed interface -- Vlan200 included -- is classified
        dhcp-reserved/dhcpv6-reserved (see docs/NETBOX_IPAM.md 'Phase
        3B.3'). This supersedes Phase 3B's original "Vlan200 only" test."""
        for device in self.manifest["devices"]:
            if not device.get("managed", True):
                continue
            for iface in device["interfaces"]:
                families = {ipaddress.ip_interface(a["address"]).version for a in iface["addresses"]}
                for family in (4, 6):
                    mode = populate_netbox._assignment_mode(iface["name"], family, family in families)
                    dynamic = mode in {"dhcp-reserved", "dhcpv6-reserved"}
                    self.assertFalse(dynamic, f"{iface['name']} family {family} unexpectedly dynamic")

    def test_vlan200_is_static_on_every_managed_device(self):
        for device in self.manifest["devices"]:
            if not device.get("managed", True):
                continue
            by_name = {iface["name"]: iface for iface in device["interfaces"]}
            self.assertIn("Vlan200", by_name, f"{device['name']} has no Vlan200 interface in the manifest")
            families = {ipaddress.ip_interface(a["address"]).version for a in by_name["Vlan200"]["addresses"]}
            self.assertEqual(families, {4, 6}, f"{device['name']}/Vlan200 should be dual-stack")
            for family in (4, 6):
                self.assertEqual(populate_netbox._assignment_mode("Vlan200", family, True), "static")

    def test_s1_s2_client_svis_remain_static(self):
        by_name = {device["name"]: device for device in self.manifest["devices"]}
        for device_name in ("S1", "S2"):
            interfaces = {iface["name"]: iface for iface in by_name[device_name]["interfaces"]}
            for iface_name in ("Vlan10", "Vlan20", "Vlan30"):
                for address in interfaces[iface_name]["addresses"]:
                    family = ipaddress.ip_interface(address["address"]).version
                    self.assertEqual(populate_netbox._assignment_mode(iface_name, family, True), "static")

    def test_shared_gateway_addresses_are_not_interface_assignments(self):
        assigned = {
            str(ipaddress.ip_interface(address["address"]))
            for device in self.manifest["devices"]
            for iface in device["interfaces"]
            for address in iface["addresses"]
        }
        gateways = {str(ipaddress.ip_interface(entry["address"])) for entry in self.manifest["virtual_ips"]}
        self.assertTrue(gateways)
        self.assertTrue(gateways.isdisjoint(assigned))


class StableIdentityPlanningTests(unittest.TestCase):
    def test_linux_duid_ll_is_deterministic_and_matches_mac(self):
        mac = "AA:C1:AB:8F:0A:40"
        self.assertEqual(pin_stable_identities.duid_ll(mac), "00:03:00:01:aa:c1:ab:8f:0a:40")
        self.assertEqual(pin_stable_identities.duid_ll(mac), pin_stable_identities.duid_ll(mac))

    def test_duid_ll_rejects_malformed_mac(self):
        for mac in ("not-a-mac", "aa:bb:cc", "gg:00:00:00:00:01"):
            with self.subTest(mac=mac), self.assertRaises(ValueError):
                pin_stable_identities.duid_ll(mac)

    def test_duid_ll_rejects_multicast_mac(self):
        with self.assertRaises(ValueError):
            pin_stable_identities.duid_ll("01:00:5e:00:00:01")

    def test_linux_plan_is_authoritative_with_informational_iaid(self):
        result = pin_stable_identities.planned_dhcpv6_identity(
            is_ceos=False, mac_address="AA:C1:AB:8F:0A:40",
        )
        self.assertEqual(result["status"], netbox_ipam.IDENTITY_AUTHORITATIVE)
        self.assertEqual(result["duid"], "00:03:00:01:aa:c1:ab:8f:0a:40")
        self.assertEqual(result["iaid"], "ab:8f:0a:40")

    def test_ceos_plan_remains_explicitly_blocked_without_identity(self):
        result = pin_stable_identities.planned_dhcpv6_identity(
            is_ceos=True, mac_address="00:1C:73:20:AB:82",
        )
        self.assertEqual(result, {"status": netbox_ipam.IDENTITY_BLOCKED, "duid": None, "iaid": None})


class DiscoverDynamicTargetsTests(unittest.TestCase):
    """Phase 3B.3: `pin_stable_identities.py` no longer hard-codes Vlan200
    -- it discovers its targets from NetBox's own assignment-mode policy
    (modules.netbox_ipam.get_assignment_modes()). These tests mock that
    policy directly, so they exercise the discovery logic regardless of
    what today's real (all-static) model reports."""

    def _modes(self, ipv4_mode=None, ipv6_mode=None):
        return {"ipv4_mode": ipv4_mode, "ipv6_mode": ipv6_mode, "dhcpv6_duid": None, "dhcpv6_iaid": None, "dhcpv6_identity_status": None}

    def test_all_static_yields_no_targets(self):
        """The corrected, current architecture: every managed interface is
        static, so discovery must return an empty list -- never fabricate
        a target to keep the tool 'interesting' (Step 10)."""
        with patch.object(netbox_ipam, "get_managed_devices", return_value=["R1"]), \
             patch.object(netbox_ipam, "get_device_interface_names", return_value=["Vlan200", "Loopback0"]), \
             patch.object(netbox_ipam, "get_assignment_modes", return_value=self._modes("static", "static")):
            targets = pin_stable_identities.discover_dynamic_targets(client=object())
        self.assertEqual(targets, [])

    def test_dhcp_reserved_interface_is_discovered_by_mode_not_name(self):
        """A hypothetical future dynamic target on an interface that is
        NOT named Vlan200 must still be discovered -- proving the fix is
        driven by policy, not a hard-coded interface name."""
        def modes(device, interface, client):
            if interface == "Ethernet7":
                return self._modes("dhcp-reserved", "dhcpv6-reserved")
            return self._modes("static", "static")

        with patch.object(netbox_ipam, "get_managed_devices", return_value=["R1"]), \
             patch.object(netbox_ipam, "get_device_interface_names", return_value=["Vlan200", "Ethernet7"]), \
             patch.object(netbox_ipam, "get_assignment_modes", side_effect=modes):
            targets = pin_stable_identities.discover_dynamic_targets(client=object())
        self.assertEqual(targets, [("R1", "Ethernet7", {4, 6})])

    def test_vlan200_named_interface_with_static_mode_is_not_a_target(self):
        """Named Vlan200 but no longer classified dynamic -- must NOT be
        discovered (the exact Phase 3B.3 regression this class guards)."""
        with patch.object(netbox_ipam, "get_managed_devices", return_value=["R1"]), \
             patch.object(netbox_ipam, "get_device_interface_names", return_value=["Vlan200"]), \
             patch.object(netbox_ipam, "get_assignment_modes", return_value=self._modes("static", "static")):
            targets = pin_stable_identities.discover_dynamic_targets(client=object())
        self.assertEqual(targets, [])

    def test_main_reports_nothing_to_pin_and_exits_zero(self):
        with patch.object(netbox_ipam, "build_client", return_value=object()), \
             patch.object(netbox_ipam, "check_status"), \
             patch.object(netbox_ipam, "load_config"), \
             patch.object(pin_stable_identities, "discover_dynamic_targets", return_value=[]):
            exit_code = pin_stable_identities.main(["--check"])
        self.assertEqual(exit_code, 0)


if __name__ == "__main__":
    unittest.main()
