"""Cisco IOS XR platform driver (kept separate from Catalyst 8000V / IOS XE).

No IOS XR node is deployed in this lab (see
docs/PHASE_20_5_PLATFORM_CAPABILITY_AUDIT.md "Evidence boundary"), so every
assertion here is fixture-tested against authoritative Cisco IOS XR
documentation (Interfaces; IP Addresses and Services; Implementing OSPF;
Implementing BGP; Access Lists configuration guides) -- never live-tested.
This fixture suite now uses the explicit IOS XR platform identity.
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

IOS = models.Platform.CISCO_IOSXR


def _ios_candidate(device_name="XR1"):
    return make_candidate(platform=IOS, device_name=device_name)


class CapabilityMatrixTests(TestCase):
    def test_interface_kinds_platform_supports_are_marked_supported(self):
        for kind in ("ROUTED_PHYSICAL", "SUBINTERFACE", "LOOPBACK", "MANAGEMENT"):
            cap = platform_drivers.capability_for("cisco_iosxr", kind)
            self.assertEqual(cap.status, platform_drivers.CapabilityStatus.SUPPORTED, kind)

    def test_bridging_interface_kinds_remain_honestly_not_implemented(self):
        for kind in ("ACCESS", "TRUNK", "SVI"):
            cap = platform_drivers.capability_for("cisco_iosxr", kind)
            self.assertEqual(cap.status, platform_drivers.CapabilityStatus.NOT_IMPLEMENTED, kind)

    def test_routing_protocols_supported_by_the_project(self):
        for protocol in (
            platform_drivers.RoutingProtocol.STATIC_IPV4, platform_drivers.RoutingProtocol.STATIC_IPV6,
            platform_drivers.RoutingProtocol.OSPFV2, platform_drivers.RoutingProtocol.OSPFV3,
            platform_drivers.RoutingProtocol.BGP_IPV4, platform_drivers.RoutingProtocol.BGP_IPV6,
        ):
            cap = platform_drivers.capability_for_routing("cisco_iosxr", protocol)
            self.assertEqual(cap.status, platform_drivers.CapabilityStatus.SUPPORTED, protocol)

    def test_ripv2_is_supported_and_ripng_has_a_specific_model_blocker(self):
        cap = platform_drivers.capability_for_routing("cisco_iosxr", platform_drivers.RoutingProtocol.RIPV2)
        self.assertEqual(cap.status, platform_drivers.CapabilityStatus.SUPPORTED)
        self.assertIn("router rip", cap.evidence)
        ripng = platform_drivers.capability_for_routing("cisco_iosxr", platform_drivers.RoutingProtocol.RIPNG)
        self.assertEqual(ripng.status, platform_drivers.CapabilityStatus.NOT_IMPLEMENTED)
        self.assertIn("VRF", ripng.evidence)

    def test_acl_features_are_supported(self):
        for feature in (
            platform_drivers.ServicePolicyFeature.ACL_IPV4_STANDARD, platform_drivers.ServicePolicyFeature.ACL_IPV4_EXTENDED,
            platform_drivers.ServicePolicyFeature.ACL_IPV6_STANDARD, platform_drivers.ServicePolicyFeature.ACL_IPV6_EXTENDED,
            platform_drivers.ServicePolicyFeature.ACL_ATTACH_IPV4, platform_drivers.ServicePolicyFeature.ACL_ATTACH_IPV6,
        ):
            cap = platform_drivers.capability_for_service_policy("cisco_iosxr", feature)
            self.assertEqual(cap.status, platform_drivers.CapabilityStatus.SUPPORTED, feature)

    def test_dhcp_relay_features_are_supported(self):
        for feature in (
            platform_drivers.ServicePolicyFeature.DHCP_OVERRIDE,
            platform_drivers.ServicePolicyFeature.DHCP_RELAY_IPV4,
            platform_drivers.ServicePolicyFeature.DHCP_RELAY_IPV6,
        ):
            cap = platform_drivers.capability_for_service_policy("cisco_iosxr", feature)
            self.assertEqual(cap.status, platform_drivers.CapabilityStatus.SUPPORTED, feature)
            self.assertIn("profile", cap.evidence)

    def test_platform_identity_is_still_ios_xr_not_classic_ios(self):
        driver = platform_drivers.get_driver("cisco_iosxr")
        self.assertEqual(driver.name, "cisco_iosxr")
        self.assertIn("XR", platform_drivers._IOSXR_IMPL)


class InterfaceAndAddressingTests(TestCase):
    def test_routed_physical_interface_and_ipv4_uses_a_dotted_mask_not_cidr(self):
        change, intent, revision = _ios_candidate()
        iface = add_interface(revision, kind="ROUTED_PHYSICAL", name="GigabitEthernet0/0/0/0")
        commit(change, intent, revision, f"interfaces.{iface['id']}.mtu", 9000)
        from core.services import interface_intent_service
        address = interface_intent_service.add_address(revision=revision, interface_id=iface["id"], family="IPV4", source="MANUAL")
        commit(change, intent, revision, f"interfaces.{iface['id']}.addresses.{address['id']}.cidr", "192.0.2.1/31")
        text = candidate_renderer.render(intent, revision)["text"]
        self.assertIn("interface GigabitEthernet0/0/0/0", text)
        self.assertIn("mtu 9000", text)
        self.assertIn("no shutdown", text)
        self.assertIn("ipv4 address 192.0.2.1 255.255.255.254", text)
        self.assertNotIn("192.0.2.1/31", text)  # never CIDR for IOS XR IPv4

    def test_ipv6_address_keeps_cidr_notation(self):
        change, intent, revision = _ios_candidate()
        iface = add_interface(revision, kind="ROUTED_PHYSICAL", name="GigabitEthernet0/0/0/1")
        from core.services import interface_intent_service
        address = interface_intent_service.add_address(revision=revision, interface_id=iface["id"], family="IPV6", source="MANUAL")
        commit(change, intent, revision, f"interfaces.{iface['id']}.addresses.{address['id']}.cidr", "2001:db8::1/64")
        text = candidate_renderer.render(intent, revision)["text"]
        self.assertIn("ipv6 address 2001:db8::1/64", text)

    def test_subinterface_uses_dot1q_encapsulation_and_parent_dotted_name(self):
        change, intent, revision = _ios_candidate()
        parent = add_interface(revision, kind="ROUTED_PHYSICAL", name="GigabitEthernet0/0/0/2")
        sub = add_interface(revision, kind="SUBINTERFACE", name="GigabitEthernet0/0/0/2.100")
        commit(change, intent, revision, f"interfaces.{sub['id']}.parent_id", parent["id"])
        commit(change, intent, revision, f"interfaces.{sub['id']}.encapsulation_vlan", 100)
        text = candidate_renderer.render(intent, revision)["text"]
        self.assertIn("interface GigabitEthernet0/0/0/2.100", text)
        self.assertIn("encapsulation dot1q 100", text)

    def test_management_interface_renders(self):
        change, intent, revision = _ios_candidate()
        add_interface(revision, kind="MANAGEMENT", name="MgmtEth0/RP0/CPU0/0")
        text = candidate_renderer.render(intent, revision)["text"]
        self.assertIn("interface MgmtEth0/RP0/CPU0/0", text)
        self.assertIn("MANAGEMENT / STATIC", text)


class RoutingTests(TestCase):
    def test_static_route_uses_router_static_address_family_hierarchy_with_cidr_prefix(self):
        change, intent, revision = _ios_candidate()
        route = add_static_route(revision)
        commit(change, intent, revision, f"routing.static_routes.{route['id']}.destination", "10.0.0.0/8")
        commit(change, intent, revision, f"routing.static_routes.{route['id']}.next_hop_address", "192.0.2.0")
        commit(change, intent, revision, f"routing.static_routes.{route['id']}.distance", 110)
        text = candidate_renderer.render(intent, revision)["text"]
        self.assertIn("router static", text)
        self.assertIn("address-family ipv4 unicast", text)
        self.assertIn("10.0.0.0/8 192.0.2.0 110", text)  # CIDR prefix, unlike interface addressing

    def test_ospfv2_uses_router_ospf_with_nested_area_interface(self):
        change, intent, revision = _ios_candidate()
        iface = add_interface(revision, name="GigabitEthernet0/0/0/0")
        instance = add_instance(revision, family="ospf", version="OSPFV2")
        commit(change, intent, revision, routing_service._instance_path("ospf", instance["id"], "process_id"), 10)
        commit(change, intent, revision, routing_service._instance_path("ospf", instance["id"], "router_id"), "1.1.1.1")
        binding = add_binding(revision, family="ospf", instance_id=instance["id"], interface_id=iface["id"])
        commit(change, intent, revision, routing_service._binding_path("ospf", instance["id"], binding["id"], "area"), "0.0.0.0")
        text = candidate_renderer.render(intent, revision)["text"]
        self.assertIn("router ospf 10", text)
        self.assertIn("router-id 1.1.1.1", text)
        self.assertIn("area 0.0.0.0", text)
        self.assertIn("interface GigabitEthernet0/0/0/0", text)

    def test_ospfv3_uses_router_ospfv3_as_a_distinct_process_type(self):
        change, intent, revision = _ios_candidate()
        instance = add_instance(revision, family="ospf", version="OSPFV3")
        commit(change, intent, revision, routing_service._instance_path("ospf", instance["id"], "process_id"), 20)
        text = candidate_renderer.render(intent, revision)["text"]
        self.assertIn("router ospfv3 20", text)
        self.assertNotIn("router ospf 20", text)

    def test_bgp_requires_explicit_address_family_activation_at_global_and_neighbor_level(self):
        change, intent, revision = _ios_candidate()
        instance = add_instance(revision, family="bgp", local_asn=65010)
        commit(change, intent, revision, f"routing.bgp.{instance['id']}.router_id", "1.1.1.1")
        neighbor = add_bgp_neighbor(revision, instance_id=instance["id"], peer_address="192.0.2.5", remote_asn=65020)
        commit(change, intent, revision, f"routing.bgp.{instance['id']}.neighbors.{neighbor['id']}.activate_ipv4", True)
        add_bgp_network(revision, instance_id=instance["id"], family="IPV4", cidr="10.0.0.0/8")
        text = candidate_renderer.render(intent, revision)["text"]
        self.assertIn("router bgp 65010", text)
        self.assertIn("bgp router-id 1.1.1.1", text)
        self.assertIn("address-family ipv4 unicast", text)
        self.assertIn("network 10.0.0.0/8", text)
        self.assertIn("neighbor 192.0.2.5", text)
        self.assertIn("remote-as 65020", text)

    def test_ripv2_uses_router_rip_with_nested_interface_and_passive_mode(self):
        change, intent, revision = _ios_candidate()
        iface = add_interface(revision, name="GigabitEthernet0/0/0/0")
        instance = add_instance(revision, family="rip", address_family="IPV4")
        binding = add_binding(revision, family="rip", instance_id=instance["id"], interface_id=iface["id"])
        commit(change, intent, revision, routing_service._binding_path("rip", instance["id"], binding["id"], "passive"), True)
        text = candidate_renderer.render(intent, revision)["text"]
        self.assertIn("router rip", text)
        self.assertIn(" interface GigabitEthernet0/0/0/0", text)
        self.assertIn("  passive-interface", text)


class AclTests(TestCase):
    def test_extended_ipv4_acl_definition_and_interface_attachment(self):
        change, intent, revision = _ios_candidate()
        iface = add_interface(revision, name="GigabitEthernet0/0/0/0")
        acl = service.add_acl(revision=revision, name="EDGE-IN", family="IPV4", acl_type="EXTENDED")
        ace = service.add_ace(revision=revision, acl_id=acl["id"], action="PERMIT", protocol="TCP")
        commit(change, intent, revision, f"security.acls.{acl['id']}.entries.{ace['id']}.source_type", "PREFIX")
        commit(change, intent, revision, f"security.acls.{acl['id']}.entries.{ace['id']}.source_value", "10.0.0.0/8")
        commit(change, intent, revision, f"security.acls.{acl['id']}.entries.{ace['id']}.destination_type", "ANY")
        service.add_acl_attachment(revision=revision, acl_id=acl["id"], interface_id=iface["id"], direction="IN")
        text = candidate_renderer.render(intent, revision)["text"]
        self.assertIn("ipv4 access-list EDGE-IN", text)
        self.assertIn("10 permit tcp 10.0.0.0/8 any", text)
        self.assertIn("ipv4 access-group EDGE-IN in", text)

    def test_standard_acl_omits_destination_and_protocol(self):
        change, intent, revision = _ios_candidate()
        acl = service.add_acl(revision=revision, name="MGMT-ALLOW", family="IPV4", acl_type="STANDARD")
        ace = service.add_ace(revision=revision, acl_id=acl["id"], action="DENY", protocol="IP")
        commit(change, intent, revision, f"security.acls.{acl['id']}.entries.{ace['id']}.source_type", "HOST")
        commit(change, intent, revision, f"security.acls.{acl['id']}.entries.{ace['id']}.source_value", "203.0.113.5")
        text = candidate_renderer.render(intent, revision)["text"]
        self.assertIn("10 deny 203.0.113.5/32", text)

    def test_ipv6_acl_uses_the_ipv6_namespace(self):
        change, intent, revision = _ios_candidate()
        acl = service.add_acl(revision=revision, name="V6-IN", family="IPV6", acl_type="STANDARD")
        ace = service.add_ace(revision=revision, acl_id=acl["id"], action="PERMIT", protocol="IP")
        commit(change, intent, revision, f"security.acls.{acl['id']}.entries.{ace['id']}.source_type", "ANY")
        text = candidate_renderer.render(intent, revision)["text"]
        self.assertIn("ipv6 access-list V6-IN", text)
        self.assertIn("10 permit any", text)


class DhcpRelayTests(TestCase):
    def test_ipv4_and_ipv6_relays_use_ios_xr_profiles_and_attachments(self):
        change, intent, revision = _ios_candidate()
        iface = add_interface(revision, name="GigabitEthernet0/0/0/0")
        relay4 = service.add_dhcp_relay(
            revision=revision, family="IPV4", interface_id=iface["id"], destination="192.0.2.53"
        )
        relay6 = service.add_dhcp_relay(
            revision=revision, family="IPV6", interface_id=iface["id"], destination="2001:db8::53"
        )
        text = candidate_renderer.render(intent, revision)["text"]
        self.assertIn("dhcp ipv4", text)
        self.assertIn(f" profile nmas-{relay4['id']} relay", text)
        self.assertIn("  helper-address vrf default 192.0.2.53", text)
        self.assertIn(f" interface GigabitEthernet0/0/0/0 relay profile nmas-{relay4['id']}", text)
        self.assertIn("dhcp ipv6", text)
        self.assertIn(f" profile nmas-{relay6['id']} relay", text)
        self.assertIn("  helper-address vrf default 2001:db8::53", text)
        self.assertIn(f" interface GigabitEthernet0/0/0/0 relay profile nmas-{relay6['id']}", text)
        self.assertNotIn("ip helper-address", text)


class DeterminismTests(TestCase):
    def test_render_is_byte_identical_across_calls(self):
        change, intent, revision = _ios_candidate()
        add_interface(revision, name="GigabitEthernet0/0/0/0")
        first = candidate_renderer.render(intent, revision)["text"]
        second = candidate_renderer.render(intent, revision)["text"]
        self.assertEqual(first, second)
