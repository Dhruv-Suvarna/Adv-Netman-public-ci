"""Nokia SR Linux platform driver (Phase 20.5).

No SR Linux node is deployed in this lab (see
docs/PHASE_20_5_PLATFORM_CAPABILITY_AUDIT.md "Evidence boundary"), so every
assertion here is fixture-tested against authoritative Nokia SR Linix
documentation (Configuration Basics Guide: interfaces, network-instances,
OSPF, BGP; srl_nokia-acl data-model reference) -- never live-tested. That
distinction is load-bearing: these tests prove the renderer emits real,
documented `set` command shapes, not that a physical/virtual SR Linix box
accepted them.
"""

from __future__ import annotations

from django.test import TestCase

from core import models
from core.services import candidate_renderer, platform_drivers
from core.services import routing_intent_service as routing_service
from core.services import service_policy_intent_service as service
from core.tests.helpers.candidates import (
    add_bgp_neighbor,
    add_bgp_network,
    add_binding,
    add_instance,
    add_interface,
    add_static_route,
    commit,
    make_candidate,
)

SRL = models.Platform.NOKIA_SRLINUX


class SrlinuxLiveJsonShapeTests(TestCase):
    def test_cli_yang_list_imports_loopback(self):
        from core.services.config_import import parser_srlinux

        parsed = parser_srlinux.parse({"interface": [{"name": "lo44", "admin-state": "enable",
            "subinterface": [{"index": 0, "admin-state": "enable",
                              "ipv4": {"address": [{"ip-prefix": "198.18.0.1/30"}]}}]}]})
        self.assertEqual([(i.name, i.kind) for i in parsed.interfaces], [("lo44", "LOOPBACK")])
        self.assertIn("198.18.0.1/30", [a["cidr"] for a in parsed.interfaces[0].addresses])


def _srl_candidate(device_name="SRL1"):
    return make_candidate(platform=SRL, device_name=device_name)


class CapabilityMatrixTests(TestCase):
    """The registry, not the renderer, is the single source of truth for
    what's SUPPORTED -- these assertions must never silently drift from what
    the renderer below actually emits."""

    def test_interface_kinds_platform_supports_are_marked_supported(self):
        for kind in ("ROUTED_PHYSICAL", "SUBINTERFACE", "LOOPBACK", "MANAGEMENT"):
            cap = platform_drivers.capability_for("nokia_srlinux", kind)
            self.assertEqual(cap.status, platform_drivers.CapabilityStatus.SUPPORTED, kind)

    def test_bridging_interface_kinds_remain_honestly_not_implemented(self):
        for kind in ("ACCESS", "TRUNK", "SVI"):
            cap = platform_drivers.capability_for("nokia_srlinux", kind)
            self.assertEqual(cap.status, platform_drivers.CapabilityStatus.NOT_IMPLEMENTED, kind)

    def test_routing_protocols_supported_by_the_project(self):
        for protocol in (
            platform_drivers.RoutingProtocol.STATIC_IPV4, platform_drivers.RoutingProtocol.STATIC_IPV6,
            platform_drivers.RoutingProtocol.OSPFV2, platform_drivers.RoutingProtocol.OSPFV3,
            platform_drivers.RoutingProtocol.BGP_IPV4, platform_drivers.RoutingProtocol.BGP_IPV6,
        ):
            cap = platform_drivers.capability_for_routing("nokia_srlinux", protocol)
            self.assertEqual(cap.status, platform_drivers.CapabilityStatus.SUPPORTED, protocol)

    def test_rip_is_a_genuine_platform_limitation_not_a_project_gap(self):
        for protocol in (platform_drivers.RoutingProtocol.RIPV2, platform_drivers.RoutingProtocol.RIPNG):
            cap = platform_drivers.capability_for_routing("nokia_srlinux", protocol)
            self.assertEqual(cap.status, platform_drivers.CapabilityStatus.UNSUPPORTED, protocol)
            self.assertIn("does not implement RIP", cap.evidence)

    def test_acl_features_are_supported(self):
        for feature in (
            platform_drivers.ServicePolicyFeature.ACL_IPV4_STANDARD, platform_drivers.ServicePolicyFeature.ACL_IPV4_EXTENDED,
            platform_drivers.ServicePolicyFeature.ACL_IPV6_STANDARD, platform_drivers.ServicePolicyFeature.ACL_IPV6_EXTENDED,
            platform_drivers.ServicePolicyFeature.ACL_ATTACH_IPV4, platform_drivers.ServicePolicyFeature.ACL_ATTACH_IPV6,
        ):
            cap = platform_drivers.capability_for_service_policy("nokia_srlinux", feature)
            self.assertEqual(cap.status, platform_drivers.CapabilityStatus.SUPPORTED, feature)

    def test_dhcp_relay_features_are_supported(self):
        for feature in (
            platform_drivers.ServicePolicyFeature.DHCP_OVERRIDE,
            platform_drivers.ServicePolicyFeature.DHCP_RELAY_IPV4,
            platform_drivers.ServicePolicyFeature.DHCP_RELAY_IPV6,
        ):
            cap = platform_drivers.capability_for_service_policy("nokia_srlinux", feature)
            self.assertEqual(cap.status, platform_drivers.CapabilityStatus.SUPPORTED, feature)
            self.assertIn("dhcp-relay server", cap.evidence)

    def test_unverified_fhrp_and_nat_are_unknown_not_false_platform_claims(self):
        cap = platform_drivers.capability_for_service_policy("nokia_srlinux", platform_drivers.ServicePolicyFeature.FHRP_VARP_IPV4)
        self.assertEqual(cap.status, platform_drivers.CapabilityStatus.UNKNOWN)
        cap = platform_drivers.capability_for_service_policy("nokia_srlinux", platform_drivers.ServicePolicyFeature.NAT_NAT44_PAT)
        self.assertEqual(cap.status, platform_drivers.CapabilityStatus.UNKNOWN)

    def test_every_platform_still_appears_in_every_matrix(self):
        """Guards against a typo in the registry silently dropping a platform column."""
        for matrix_fn in (
            platform_drivers.capability_matrix, platform_drivers.routing_capability_matrix,
            platform_drivers.service_policy_capability_matrix,
        ):
            matrix = matrix_fn()
            self.assertIn("nokia_srlinux", [driver.name for driver in matrix["platforms"]])


class InterfaceAndAddressingTests(TestCase):
    def test_routed_physical_interface_and_addressing(self):
        change, intent, revision = _srl_candidate()
        iface = add_interface(revision, kind="ROUTED_PHYSICAL", name="ethernet-1/1")
        commit(change, intent, revision, f"interfaces.{iface['id']}.mtu", 9000)
        from core.services import interface_intent_service
        address = interface_intent_service.add_address(revision=revision, interface_id=iface["id"], family="IPV4", source="MANUAL")
        commit(change, intent, revision, f"interfaces.{iface['id']}.addresses.{address['id']}.cidr", "192.0.2.1/31")
        text = candidate_renderer.render(intent, revision)["text"]
        self.assertIn("set interface ethernet-1/1 admin-state enable", text)
        # the canonical MTU is the L3 MTU: SR Linux holds it as the subinterface ip-mtu (port mtu is the L2 frame size)
        self.assertIn("set interface ethernet-1/1 subinterface 0 ip-mtu 9000", text)
        self.assertNotIn("set interface ethernet-1/1 mtu 9000", text)
        self.assertIn("set interface ethernet-1/1 subinterface 0 ipv4 admin-state enable", text)
        self.assertIn("set interface ethernet-1/1 subinterface 0 type routed", text)
        self.assertIn("set network-instance default interface ethernet-1/1.0", text)
        self.assertIn("set interface ethernet-1/1 subinterface 0 ipv4 address 192.0.2.1/31", text)
        self.assertNotIn("set /", text)  # no leading-slash CLI fabrication

    def test_management_interface_binds_to_the_mgmt_network_instance_not_default(self):
        change, intent, revision = _srl_candidate()
        iface = add_interface(revision, kind="MANAGEMENT", name="mgmt0")
        text = candidate_renderer.render(intent, revision)["text"]
        self.assertIn("set network-instance mgmt interface mgmt0.0", text)
        self.assertNotIn("set network-instance default interface mgmt0.0", text)

    def test_subinterface_uses_parent_name_and_encapsulation_vlan_as_index(self):
        change, intent, revision = _srl_candidate()
        parent = add_interface(revision, kind="ROUTED_PHYSICAL", name="ethernet-1/2")
        sub = add_interface(revision, kind="SUBINTERFACE", name="ethernet-1/2.100")
        commit(change, intent, revision, f"interfaces.{sub['id']}.parent_id", parent["id"])
        commit(change, intent, revision, f"interfaces.{sub['id']}.encapsulation_vlan", 100)
        from core.services import interface_intent_service
        address = interface_intent_service.add_address(revision=revision, interface_id=sub["id"], family="IPV6", source="MANUAL")
        commit(change, intent, revision, f"interfaces.{sub['id']}.addresses.{address['id']}.cidr", "2001:db8::1/64")
        text = candidate_renderer.render(intent, revision)["text"]
        self.assertIn("set interface ethernet-1/2 vlan-tagging true", text)
        self.assertIn("set interface ethernet-1/2 subinterface 100 type routed", text)
        self.assertIn("set interface ethernet-1/2 subinterface 100 vlan encap single-tagged vlan-id 100", text)
        self.assertIn("set network-instance default interface ethernet-1/2.100", text)
        # the address command must reference the PARENT physical name, not the subinterface's own display name
        self.assertIn("set interface ethernet-1/2 subinterface 100 ipv6 address 2001:db8::1/64", text)

    def test_loopback_admin_disabled_reflects_in_the_candidate(self):
        change, intent, revision = _srl_candidate()
        iface = add_interface(revision, kind="LOOPBACK", name="lo0")
        commit(change, intent, revision, f"interfaces.{iface['id']}.admin_state", "DISABLED")
        text = candidate_renderer.render(intent, revision)["text"]
        self.assertIn("set interface lo0 admin-state disable", text)


class RoutingTests(TestCase):
    def test_static_route_uses_next_hop_group_indirection(self):
        change, intent, revision = _srl_candidate()
        route = add_static_route(revision)
        commit(change, intent, revision, f"routing.static_routes.{route['id']}.destination", "10.0.0.0/8")
        commit(change, intent, revision, f"routing.static_routes.{route['id']}.next_hop_address", "192.0.2.0")
        commit(change, intent, revision, f"routing.static_routes.{route['id']}.distance", 110)
        text = candidate_renderer.render(intent, revision)["text"]
        self.assertIn("set network-instance default static-routes route 10.0.0.0/8 admin-state enable", text)
        self.assertIn("set network-instance default static-routes route 10.0.0.0/8 preference 110", text)
        self.assertIn(f"next-hop-group nhg-{route['id']}", text)
        self.assertIn(f"set network-instance default next-hop-groups group nhg-{route['id']} nexthop 1 ip-address 192.0.2.0", text)

    def test_interface_next_hop_is_reported_honestly_not_fabricated(self):
        change, intent, revision = _srl_candidate()
        egress = add_interface(revision, name="ethernet-1/3")
        route = add_static_route(revision)
        commit(change, intent, revision, f"routing.static_routes.{route['id']}.destination", "10.0.0.0/8")
        commit(change, intent, revision, f"routing.static_routes.{route['id']}.next_hop_type", "INTERFACE")
        commit(change, intent, revision, f"routing.static_routes.{route['id']}.next_hop_interface_id", egress["id"])
        text = candidate_renderer.render(intent, revision)["text"]
        self.assertIn("next-hop-groups require an IP next-hop address", text)
        self.assertNotIn("next-hop-group nhg-", text)

    def test_ospfv2_instance_version_router_id_and_area_interface(self):
        change, intent, revision = _srl_candidate()
        iface = add_interface(revision, name="ethernet-1/1")
        instance = add_instance(revision, family="ospf", version="OSPFV2")
        commit(change, intent, revision, routing_service._instance_path("ospf", instance["id"], "process_id"), 10)
        commit(change, intent, revision, routing_service._instance_path("ospf", instance["id"], "router_id"), "1.1.1.1")
        binding = add_binding(revision, family="ospf", instance_id=instance["id"], interface_id=iface["id"])
        commit(change, intent, revision, routing_service._binding_path("ospf", instance["id"], binding["id"], "area"), "0.0.0.0")
        text = candidate_renderer.render(intent, revision)["text"]
        self.assertIn("set network-instance default protocols ospf instance 10 version ospf-v2", text)
        self.assertIn("set network-instance default protocols ospf instance 10 router-id 1.1.1.1", text)
        self.assertIn("set network-instance default protocols ospf instance 10 area 0.0.0.0 interface ethernet-1/1.0", text)

    def test_ospfv3_uses_ospf_v3_version_string(self):
        change, intent, revision = _srl_candidate()
        instance = add_instance(revision, family="ospf", version="OSPFV3")
        commit(change, intent, revision, routing_service._instance_path("ospf", instance["id"], "process_id"), 20)
        text = candidate_renderer.render(intent, revision)["text"]
        self.assertIn("set network-instance default protocols ospf instance 20 version ospf-v3", text)

    def test_tagged_subinterface_reference_is_not_double_suffixed(self):
        change, intent, revision = _srl_candidate()
        parent = add_interface(revision, kind="ROUTED_PHYSICAL", name="ethernet-1/2")
        sub = add_interface(revision, kind="SUBINTERFACE", name="ethernet-1/2.100")
        commit(change, intent, revision, f"interfaces.{sub['id']}.parent_id", parent["id"])
        commit(change, intent, revision, f"interfaces.{sub['id']}.encapsulation_vlan", 100)
        instance = add_instance(revision, family="ospf", version="OSPFV2")
        commit(change, intent, revision, routing_service._instance_path("ospf", instance["id"], "process_id"), 10)
        binding = add_binding(revision, family="ospf", instance_id=instance["id"], interface_id=sub["id"])
        commit(change, intent, revision, routing_service._binding_path("ospf", instance["id"], binding["id"], "area"), "0.0.0.0")
        text = candidate_renderer.render(intent, revision)["text"]
        self.assertIn("area 0.0.0.0 interface ethernet-1/2.100", text)
        self.assertNotIn("ethernet-1/2.100.100", text)

    def test_bgp_neighbor_requires_a_peer_group_and_peer_as(self):
        change, intent, revision = _srl_candidate()
        instance = add_instance(revision, family="bgp", local_asn=65010)
        commit(change, intent, revision, f"routing.bgp.{instance['id']}.router_id", "1.1.1.1")
        neighbor = add_bgp_neighbor(revision, instance_id=instance["id"], peer_address="192.0.2.5", remote_asn=65020)
        commit(change, intent, revision, f"routing.bgp.{instance['id']}.neighbors.{neighbor['id']}.activate_ipv4", True)
        add_bgp_network(revision, instance_id=instance["id"], family="IPV4", cidr="10.0.0.0/8")
        text = candidate_renderer.render(intent, revision)["text"]
        self.assertIn("set network-instance default protocols bgp autonomous-system 65010", text)
        self.assertIn("set network-instance default protocols bgp router-id 1.1.1.1", text)
        group = f"peer-{neighbor['id']}"
        self.assertIn(f"set network-instance default protocols bgp group {group} admin-state enable", text)
        self.assertIn(f"set network-instance default protocols bgp neighbor 192.0.2.5 peer-group {group}", text)
        self.assertIn(f"set network-instance default protocols bgp neighbor 192.0.2.5 peer-as 65020", text)
        # SR Linux has no network statement: the advertisement is an exact prefix-set, an accepting policy, and that
        # policy exported by BGP (24.10.7: ``match prefix-set``); RFC 8212 reject-all is opted out as FRR does
        policy = f"nmas-bgp-{instance['id']}"
        self.assertIn(f"set routing-policy prefix-set {policy} prefix 10.0.0.0/8 mask-length-range exact", text)
        self.assertIn(f"set routing-policy policy {policy} statement 10 match prefix-set {policy}", text)
        self.assertIn(f"set routing-policy policy {policy} statement 10 action policy-result accept", text)
        self.assertIn(f"set network-instance default protocols bgp export-policy [ {policy} ]", text)
        self.assertIn("set network-instance default protocols bgp ebgp-default-policy import-reject-all false", text)
        self.assertIn(f"set network-instance default protocols bgp group {group} afi-safi ipv4-unicast admin-state enable", text)
        self.assertNotIn("network 10.0.0.0/8", text)

    def test_rip_cannot_even_be_created_for_srlinux_because_the_platform_genuinely_lacks_it(self):
        """Unlike a NOT_IMPLEMENTED feature (which the operator can still add
        as preserved-but-unrenderable intent), RIP is UNSUPPORTED for SR
        Linix -- the intent service refuses creation outright, matching a
        genuine vendor limitation rather than a project gap."""
        from core.services import interface_intent_service
        change, intent, revision = _srl_candidate()
        add_interface(revision)
        with self.assertRaises(interface_intent_service.CollectionMutationError):
            add_instance(revision, family="rip", address_family="IPV4")


class AclTests(TestCase):
    def test_extended_ipv4_acl_definition_and_interface_attachment(self):
        change, intent, revision = _srl_candidate()
        iface = add_interface(revision, name="ethernet-1/1")
        acl = service.add_acl(revision=revision, name="EDGE-IN", family="IPV4", acl_type="EXTENDED")
        ace = service.add_ace(revision=revision, acl_id=acl["id"], action="PERMIT", protocol="TCP")
        commit(change, intent, revision, f"security.acls.{acl['id']}.entries.{ace['id']}.source_type", "PREFIX")
        commit(change, intent, revision, f"security.acls.{acl['id']}.entries.{ace['id']}.source_value", "10.0.0.0/8")
        commit(change, intent, revision, f"security.acls.{acl['id']}.entries.{ace['id']}.destination_type", "ANY")
        service.add_acl_attachment(revision=revision, acl_id=acl["id"], interface_id=iface["id"], direction="IN")
        text = candidate_renderer.render(intent, revision)["text"]
        # 24.10 ``acl-filter NAME type ipv4`` (``ipv4-filter`` does not exist on 24.10.7)
        self.assertIn("set acl acl-filter EDGE-IN type ipv4", text)
        self.assertIn("set acl acl-filter EDGE-IN type ipv4 entry 10 match ipv4 source-ip prefix 10.0.0.0/8", text)
        self.assertIn("set acl acl-filter EDGE-IN type ipv4 entry 10 match ipv4 destination-ip prefix 0.0.0.0/0", text)
        self.assertIn("set acl acl-filter EDGE-IN type ipv4 entry 10 match ipv4 protocol tcp", text)
        self.assertIn("set acl acl-filter EDGE-IN type ipv4 entry 10 action accept", text)
        self.assertIn("set acl interface ethernet-1/1.0 input acl-filter EDGE-IN type ipv4", text)
        self.assertNotIn("ipv4-filter", text)

    def test_standard_acl_omits_destination_and_protocol_match(self):
        change, intent, revision = _srl_candidate()
        acl = service.add_acl(revision=revision, name="MGMT-ALLOW", family="IPV4", acl_type="STANDARD")
        ace = service.add_ace(revision=revision, acl_id=acl["id"], action="DENY", protocol="IP")
        commit(change, intent, revision, f"security.acls.{acl['id']}.entries.{ace['id']}.source_type", "HOST")
        commit(change, intent, revision, f"security.acls.{acl['id']}.entries.{ace['id']}.source_value", "203.0.113.5")
        text = candidate_renderer.render(intent, revision)["text"]
        self.assertIn("set acl acl-filter MGMT-ALLOW type ipv4 entry 10 match ipv4 source-ip prefix 203.0.113.5/32", text)
        self.assertIn("set acl acl-filter MGMT-ALLOW type ipv4 entry 10 action drop", text)
        self.assertNotIn("match ipv4 protocol", text)
        self.assertNotIn("match destination-ip", text)

    def test_ipv6_acl_is_an_acl_filter_of_type_ipv6(self):
        change, intent, revision = _srl_candidate()
        acl = service.add_acl(revision=revision, name="V6-IN", family="IPV6", acl_type="STANDARD")
        ace = service.add_ace(revision=revision, acl_id=acl["id"], action="PERMIT", protocol="IP")
        commit(change, intent, revision, f"security.acls.{acl['id']}.entries.{ace['id']}.source_type", "ANY")
        text = candidate_renderer.render(intent, revision)["text"]
        self.assertIn("set acl acl-filter V6-IN type ipv6", text)
        self.assertIn("set acl acl-filter V6-IN type ipv6 entry 10 match ipv6 source-ip prefix ::/0", text)
        self.assertNotIn("ipv6-filter", text)


class DhcpRelayTests(TestCase):
    def test_ipv4_and_ipv6_servers_render_under_the_subinterface_model(self):
        change, intent, revision = _srl_candidate()
        iface = add_interface(revision, name="ethernet-1/1")
        service.add_dhcp_relay(
            revision=revision, family="IPV4", interface_id=iface["id"], destination="192.0.2.53"
        )
        service.add_dhcp_relay(
            revision=revision, family="IPV6", interface_id=iface["id"], destination="2001:db8::53"
        )
        text = candidate_renderer.render(intent, revision)["text"]
        self.assertIn(
            "set interface ethernet-1/1 subinterface 0 ipv4 dhcp-relay server [ 192.0.2.53 ]", text
        )
        self.assertIn(
            "set interface ethernet-1/1 subinterface 0 ipv6 dhcp-relay server [ 2001:db8::53 ]", text
        )


class DeterminismTests(TestCase):
    def test_render_is_byte_identical_across_calls(self):
        change, intent, revision = _srl_candidate()
        add_interface(revision, name="ethernet-1/1")
        first = candidate_renderer.render(intent, revision)["text"]
        second = candidate_renderer.render(intent, revision)["text"]
        self.assertEqual(first, second)
