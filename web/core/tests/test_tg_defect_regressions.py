"""Lab 7 closure sprint -- regression tests for the defects the governance matrix found (F2, F3).

F2  Per-interface render contributions (OSPF/IS-IS bindings, ACL attachment, DHCP relay, VARP addresses) and the cEOS
    device-global ``vlan`` / ``ip virtual-router mac-address`` lines were rendered whatever the capability registry said:
    with a feature NOT_IMPLEMENTED the object definition was withheld and the refusal marker emitted, but its interface
    lines still reached the candidate.  Every contribution is now gated by the same registry lookup the object renderer uses.
F3  Network-configuration validation with NetBox unavailable reported MANAGED_SCOPE as WARNING (the backward-compatible
    "field not included" branch), so an L2-only candidate (no address to look up) passed with WARNING and no evidence that
    the target is managed.  NetBox unavailable now BLOCKS, exactly as the running-configuration import path already did.

The registry is the real one: each negative uses a platform where the feature genuinely is not SUPPORTED, so no mock
stands between the test and the gate.
"""

from __future__ import annotations

from django.test import SimpleTestCase, TestCase

from core.services import network_config_validation as ncv
from core.services import platform_drivers as pd
from core.services.validation import sources

OSPF_V2 = {"version": "OSPFV2", "process_id": 10, "area": "0", "cost": 10, "network_type": "POINT_TO_POINT", "path": "routing.ospf.o1"}
OSPF_V3 = {**OSPF_V2, "version": "OSPFV3"}
ACL = {"family": "IPV4", "acl_name": "EDGE_IN", "direction": "IN"}
RELAY_V4 = {"family": "IPV4", "destination": "192.0.2.10"}
RELAY_V6 = {"family": "IPV6", "destination": "2001:db8::10"}
VARP_V4 = {"id": "f1", "protocol": "VARP", "address_family": "IPV4", "path": "fhrp.instances.f1",
           "virtual_ips": {"v1": {"id": "v1", "sequence": 1, "address": "198.18.0.3"}}}


def _interface(**scope) -> dict:
    return {"id": "i1", "name": "Ethernet1", "kind": "ROUTED_PHYSICAL", "_scope": scope}


def _texts(descriptors: list[dict]) -> list[str]:
    return [d.get("text") or d["template"].format(value=d.get("value")) for d in descriptors]


class F2RenderContributionGateTests(SimpleTestCase):
    """Interface-level lines render exactly when, and only when, their feature is SUPPORTED on the platform."""

    def test_ospf_bindings_render_exact_ceos_lines_when_supported(self):
        lines = pd._ospf_interface_contributions(_interface(ospf=[OSPF_V2, OSPF_V3]), ceos=True, platform="arista_ceos")
        self.assertEqual(_texts(lines), ["   ip ospf area 0", "   ip ospf cost 10", "   ip ospf network point-to-point",
                                         "   ipv6 ospf 10 area 0", "   ipv6 ospf cost 10", "   ipv6 ospf network point-to-point"])

    def test_ospf_bindings_never_render_where_ospf_is_not_implemented(self):
        self.assertEqual(pd.capability_for_routing("sonic", "OSPFV2").status, pd.CapabilityStatus.NOT_IMPLEMENTED)
        self.assertEqual(pd._ospf_interface_contributions(_interface(ospf=[OSPF_V2, OSPF_V3]), ceos=False, platform="sonic"), [])

    def test_ospfv3_binding_refused_while_ospfv2_still_renders_on_a_v2_only_platform(self):
        # Cisco IOS-XE: OSPFv2 SUPPORTED, OSPFv3 NOT_IMPLEMENTED -- the gate is per version, not per protocol family
        lines = pd._ospf_interface_contributions(_interface(ospf=[OSPF_V2, OSPF_V3]), ceos=False, platform="cisco_c8000v_iosxe")
        self.assertEqual(_texts(lines), ["   ip ospf area 0", "   ip ospf cost 10", "   ip ospf network point-to-point"])

    def test_frr_interface_block_not_rendered_when_ospf_is_unsupported(self):
        driver = pd.UbuntuFrrDriver()
        self.assertEqual(_texts(driver.interface_contribution_descriptors(_interface(ospf=[OSPF_V2]))),
                         ["!", "interface Ethernet1", "   ip ospf area 0", "   ip ospf cost 10", "   ip ospf network point-to-point"])
        original = pd.ROUTING_CAPABILITIES["ubuntu_frr"][pd.RoutingProtocol.OSPFV2]
        try:
            pd.ROUTING_CAPABILITIES["ubuntu_frr"][pd.RoutingProtocol.OSPFV2] = pd.PlatformCapability(pd.CapabilityStatus.NOT_IMPLEMENTED, "probe")
            self.assertEqual(driver.interface_contribution_descriptors(_interface(ospf=[OSPF_V2])), [])
        finally:
            pd.ROUTING_CAPABILITIES["ubuntu_frr"][pd.RoutingProtocol.OSPFV2] = original

    def test_isis_binding_renders_on_ceos_and_never_where_isis_is_not_implemented(self):
        binding = {"path": "routing.isis.n1", "metric": 20, "passive": True}
        self.assertEqual(_texts(pd._ceos_isis_interface_contributions(_interface(isis=[binding]), platform="arista_ceos")),
                         ["   isis enable NMAS", "   isis metric 20", "   isis passive"])
        # Ubuntu/FRR IS-IS is SUPPORTED since V2 Phase 9; SR Linux IS-IS is still NOT_IMPLEMENTED.
        self.assertEqual(pd.capability_for_routing("nokia_srlinux", pd.RoutingProtocol.ISIS).status, pd.CapabilityStatus.NOT_IMPLEMENTED)
        self.assertEqual(pd._ceos_isis_interface_contributions(_interface(isis=[binding]), platform="nokia_srlinux"), [])

    def test_acl_attachment_renders_exact_line_on_ceos(self):
        self.assertEqual(_texts(pd._acl_interface_contributions(_interface(acl_attachments=[ACL]), platform="arista_ceos")),
                         ["   ip access-group EDGE_IN in"])

    def test_acl_attachment_not_rendered_where_attachment_is_not_implemented(self):
        self.assertEqual(pd._acl_interface_contributions(_interface(acl_attachments=[ACL]), platform="ubuntu_frr"), [])

    def test_dhcp_relay_renders_both_families_on_ceos(self):
        self.assertEqual(_texts(pd._dhcp_interface_contributions(_interface(dhcp_relays=[RELAY_V4, RELAY_V6]), platform="arista_ceos")),
                         ["   ip helper-address 192.0.2.10", "   ipv6 dhcp relay destination 2001:db8::10"])

    def test_dhcp_relay_not_rendered_for_unknown_or_unsupported_family(self):
        self.assertEqual(pd._dhcp_interface_contributions(_interface(dhcp_relays=[RELAY_V4, RELAY_V6]), platform="ubuntu_frr"), [])
        self.assertEqual(pd._dhcp_interface_contributions(_interface(dhcp_relays=[{"family": "IPX", "destination": "x"}]),
                                                         platform="arista_ceos"), [])

    def test_varp_address_renders_on_ceos(self):
        self.assertEqual(_texts(pd._fhrp_interface_contributions(_interface(fhrp=[VARP_V4]), platform="arista_ceos")),
                         ["   ip virtual-router address 198.18.0.3"])

    def test_varp_address_not_rendered_where_varp_is_not_implemented(self):
        self.assertEqual(pd._fhrp_interface_contributions(_interface(fhrp=[VARP_V4]), platform="ubuntu_frr"), [])

    def test_service_policy_gate_refuses_unknown_feature_names(self):
        self.assertTrue(pd._service_policy_supported("arista_ceos", "ACL_ATTACH_IPV4"))
        self.assertFalse(pd._service_policy_supported("arista_ceos", "NOT_A_FEATURE"))
        self.assertFalse(pd._service_policy_supported("not_a_platform", "ACL_ATTACH_IPV4"))


def _bundle(netbox: sources.SourceResult) -> sources.SourceBundle:
    other = [sources.SourceResult(name, "available", {}) for name in ("TOPOLOGY", "INVENTORY", "CAPABILITY")]
    return sources.SourceBundle(netbox, *other, repository_head="0" * 40)


class F3ManagedScopeFailClosedTests(TestCase):
    SNAPSHOT = {"devices": [{"device_name": "S1"}]}

    def test_netbox_unavailable_blocks_managed_scope(self):
        checks = ncv._managed_scope_checks(self.SNAPSHOT, _bundle(sources.SourceResult("NETBOX", "unavailable", None, "down")))
        self.assertEqual([(c["check"], c["status"]) for c in checks], [("MANAGED_SCOPE", "BLOCKED")])
        self.assertEqual(checks[0]["message"], "Authoritative managed scope is unavailable.")

    def test_managed_target_passes_with_netbox_membership(self):
        checks = ncv._managed_scope_checks(self.SNAPSHOT, _bundle(sources.SourceResult("NETBOX", "available", {"managed_devices": ["S1", "S2"]})))
        self.assertEqual([(c["check"], c["status"], c["message"]) for c in checks], [("MANAGED_SCOPE", "PASS", "All targets are managed.")])

    def test_target_outside_membership_is_blocked(self):
        checks = ncv._managed_scope_checks(self.SNAPSHOT, _bundle(sources.SourceResult("NETBOX", "available", {"managed_devices": ["S2"]})))
        self.assertEqual((checks[0]["status"], checks[0]["evidence"]["outside_scope"]), ("BLOCKED", ["S1"]))

    def test_available_source_without_membership_field_stays_a_visible_warning(self):
        checks = ncv._managed_scope_checks(self.SNAPSHOT, _bundle(sources.SourceResult("NETBOX", "available", {})))
        self.assertEqual(checks[0]["status"], "WARNING")
