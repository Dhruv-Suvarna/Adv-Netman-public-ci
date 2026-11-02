"""SONiC platform driver (Phase 20.5).

SONiC's authoritative configuration representation is config_db (a
Redis-backed table/key/field store applied via `config load <file>.json` /
`config reload`), not a `show running-config`-style CLI -- see
docs/PHASE_20_5_PLATFORM_CAPABILITY_AUDIT.md and this project's own prior
evidence ("Existing driver records SONiC as structured config_db-style
configuration"). No SONiC node is deployed in this lab, so every assertion
here is fixture-tested against sonic-net/SONiC's own design docs and
vendor SONiC documentation (INTERFACE/LOOPBACK_INTERFACE/MGMT_INTERFACE,
VLAN/VLAN_MEMBER/VLAN_INTERFACE,
STATIC_ROUTE, BGP_GLOBALS/BGP_NEIGHBOR/BGP_NEIGHBOR_AF, ACL_TABLE/ACL_RULE)
-- never live-tested.
"""

from __future__ import annotations

import json

from django.test import TestCase

from core import models
from core.services import candidate_renderer, platform_drivers
from core.services import service_policy_intent_service as service
from core.tests.helpers.candidates import (
    add_bgp_neighbor,
    add_instance,
    add_interface,
    add_static_route,
    commit,
    make_candidate,
)

SONIC = models.Platform.SONIC


def _sonic_candidate(device_name="SONIC1"):
    return make_candidate(platform=SONIC, device_name=device_name)


def _config_db(text: str) -> dict:
    """The candidate's config_db JSON body, excluding the shared
    '! Candidate Configuration' / disclaimer preamble every platform's
    candidate carries and any trailing UNSUPPORTED_OBJECT_MARKER lines."""
    body_lines = [line for line in text.splitlines() if not line.startswith("!") and not line.startswith("//")]
    return json.loads("\n".join(l for l in body_lines if l.strip()))


class CapabilityMatrixTests(TestCase):
    def test_interface_kinds_platform_supports_are_marked_supported(self):
        for kind in ("ROUTED_PHYSICAL", "SUBINTERFACE", "LOOPBACK", "MANAGEMENT", "ACCESS", "TRUNK", "SVI"):
            cap = platform_drivers.capability_for("sonic", kind)
            self.assertEqual(cap.status, platform_drivers.CapabilityStatus.SUPPORTED, kind)

    def test_static_and_bgp_supported_ospf_honestly_not(self):
        for protocol in (platform_drivers.RoutingProtocol.STATIC_IPV4, platform_drivers.RoutingProtocol.STATIC_IPV6,
                         platform_drivers.RoutingProtocol.BGP_IPV4, platform_drivers.RoutingProtocol.BGP_IPV6):
            cap = platform_drivers.capability_for_routing("sonic", protocol)
            self.assertEqual(cap.status, platform_drivers.CapabilityStatus.SUPPORTED, protocol)
        for protocol in (platform_drivers.RoutingProtocol.OSPFV2, platform_drivers.RoutingProtocol.OSPFV3):
            cap = platform_drivers.capability_for_routing("sonic", protocol)
            self.assertEqual(cap.status, platform_drivers.CapabilityStatus.NOT_IMPLEMENTED, protocol)
            self.assertIn("no stable, well-documented config_db table", cap.evidence)

    def test_acl_is_supported(self):
        cap = platform_drivers.capability_for_service_policy("sonic", platform_drivers.ServicePolicyFeature.ACL_IPV4_EXTENDED)
        self.assertEqual(cap.status, platform_drivers.CapabilityStatus.SUPPORTED)


class InterfaceAndAddressingTests(TestCase):
    def test_routed_physical_and_loopback_render_as_interface_and_loopback_tables(self):
        change, intent, revision = _sonic_candidate()
        phys = add_interface(revision, kind="ROUTED_PHYSICAL", name="Ethernet0")
        from core.services import interface_intent_service
        address = interface_intent_service.add_address(revision=revision, interface_id=phys["id"], family="IPV4", source="MANUAL")
        commit(change, intent, revision, f"interfaces.{phys['id']}.addresses.{address['id']}.cidr", "192.0.2.1/31")
        lo = add_interface(revision, kind="LOOPBACK", name="Loopback0")
        text = candidate_renderer.render(intent, revision)["text"]
        doc = _config_db(text)
        self.assertIn("Ethernet0", doc["INTERFACE"])
        self.assertIn("Ethernet0|192.0.2.1/31", doc["INTERFACE"])
        self.assertIn("Loopback0", doc["LOOPBACK_INTERFACE"])
        self.assertEqual(doc["DEVICE_METADATA"]["localhost"]["hostname"], "SONIC1")

    def test_management_interface_uses_mgmt_interface_table(self):
        change, intent, revision = _sonic_candidate()
        add_interface(revision, kind="MANAGEMENT", name="eth0")
        doc = _config_db(candidate_renderer.render(intent, revision)["text"])
        self.assertIn("eth0", doc["MGMT_INTERFACE"])
        self.assertNotIn("MGMT_INTERFACE", doc.get("INTERFACE", {}))

    def test_subinterface_name_is_parent_dot_vlan(self):
        change, intent, revision = _sonic_candidate()
        parent = add_interface(revision, kind="ROUTED_PHYSICAL", name="Ethernet4")
        sub = add_interface(revision, kind="SUBINTERFACE", name="Ethernet4.100")
        commit(change, intent, revision, f"interfaces.{sub['id']}.parent_id", parent["id"])
        commit(change, intent, revision, f"interfaces.{sub['id']}.encapsulation_vlan", 100)
        doc = _config_db(candidate_renderer.render(intent, revision)["text"])
        self.assertIn("Ethernet4.100", doc["INTERFACE"])

    def test_access_trunk_and_svi_use_documented_vlan_tables(self):
        change, intent, revision = _sonic_candidate()
        access = add_interface(revision, kind="ACCESS", name="Ethernet8")
        commit(change, intent, revision, f"interfaces.{access['id']}.access_vlan", 10)
        trunk = add_interface(revision, kind="TRUNK", name="Ethernet12")
        commit(change, intent, revision, f"interfaces.{trunk['id']}.trunk_allowed_vlans", "10,20")
        commit(change, intent, revision, f"interfaces.{trunk['id']}.native_vlan", 10)
        svi = add_interface(revision, kind="SVI", name="Vlan20")
        commit(change, intent, revision, f"interfaces.{svi['id']}.vlan_id", 20)
        from core.services import interface_intent_service
        address = interface_intent_service.add_address(
            revision=revision, interface_id=svi["id"], family="IPV4", source="MANUAL"
        )
        commit(change, intent, revision, f"interfaces.{svi['id']}.addresses.{address['id']}.cidr", "192.0.2.1/24")

        doc = _config_db(candidate_renderer.render(intent, revision)["text"])
        self.assertEqual(doc["VLAN"]["Vlan10"]["vlanid"], "10")
        self.assertEqual(doc["VLAN_MEMBER"]["Vlan10|Ethernet8"]["tagging_mode"], "untagged")
        self.assertEqual(doc["VLAN_MEMBER"]["Vlan10|Ethernet12"]["tagging_mode"], "untagged")
        self.assertEqual(doc["VLAN_MEMBER"]["Vlan20|Ethernet12"]["tagging_mode"], "tagged")
        self.assertIn("Vlan20|192.0.2.1/24", doc["VLAN_INTERFACE"])

    def test_candidate_is_genuinely_valid_json_when_everything_is_supported(self):
        change, intent, revision = _sonic_candidate()
        add_interface(revision, kind="ROUTED_PHYSICAL", name="Ethernet0")
        text = candidate_renderer.render(intent, revision)["text"]
        # every non-comment line must be part of one parseable JSON document
        _config_db(text)  # raises if invalid


class RoutingTests(TestCase):
    def test_static_route_uses_static_route_table_keyed_by_vrf_and_prefix(self):
        change, intent, revision = _sonic_candidate()
        route = add_static_route(revision)
        commit(change, intent, revision, f"routing.static_routes.{route['id']}.destination", "10.0.0.0/8")
        commit(change, intent, revision, f"routing.static_routes.{route['id']}.next_hop_address", "192.0.2.0")
        commit(change, intent, revision, f"routing.static_routes.{route['id']}.distance", 110)
        doc = _config_db(candidate_renderer.render(intent, revision)["text"])
        entry = doc["STATIC_ROUTE"]["default|10.0.0.0/8"]
        self.assertEqual(entry["nexthop"], "192.0.2.0")
        self.assertEqual(entry["distance"], "110")

    def test_interface_next_hop_is_reported_honestly_not_fabricated(self):
        change, intent, revision = _sonic_candidate()
        egress = add_interface(revision, name="Ethernet8")
        route = add_static_route(revision)
        commit(change, intent, revision, f"routing.static_routes.{route['id']}.destination", "10.0.0.0/8")
        commit(change, intent, revision, f"routing.static_routes.{route['id']}.next_hop_type", "INTERFACE")
        commit(change, intent, revision, f"routing.static_routes.{route['id']}.next_hop_interface_id", egress["id"])
        text = candidate_renderer.render(intent, revision)["text"]
        self.assertIn("STATIC_ROUTE next-hop requires an IP address", text)
        doc = _config_db(text)
        self.assertNotIn("STATIC_ROUTE", doc)

    def test_bgp_uses_globals_neighbor_and_neighbor_af_tables(self):
        change, intent, revision = _sonic_candidate()
        instance = add_instance(revision, family="bgp", local_asn=65010)
        commit(change, intent, revision, f"routing.bgp.{instance['id']}.router_id", "1.1.1.1")
        neighbor = add_bgp_neighbor(revision, instance_id=instance["id"], peer_address="192.0.2.5", remote_asn=65020)
        commit(change, intent, revision, f"routing.bgp.{instance['id']}.neighbors.{neighbor['id']}.activate_ipv4", True)
        doc = _config_db(candidate_renderer.render(intent, revision)["text"])
        self.assertEqual(doc["BGP_GLOBALS"]["default"], {"local_asn": "65010", "router_id": "1.1.1.1"})
        self.assertEqual(doc["BGP_NEIGHBOR"]["default|192.0.2.5"]["asn"], "65020")
        self.assertIn("default|192.0.2.5|ipv4_unicast", doc["BGP_NEIGHBOR_AF"])

    def test_ospf_cannot_even_be_created_pending_a_verified_schema(self):
        from core.services import interface_intent_service
        change, intent, revision = _sonic_candidate()
        add_interface(revision)
        with self.assertRaises(interface_intent_service.CollectionMutationError):
            add_instance(revision, family="ospf", version="OSPFV2")

    def test_rip_preserved_but_unsupported_never_corrupts_the_json_body(self):
        """RIP can't even be created (NOT_IMPLEMENTED, like OSPF above); simulate
        arriving via import/platform-switch the same way test_routing_renderer.py
        does, and confirm the marker line sits outside the JSON, not inside it."""
        change, intent, revision = _sonic_candidate()
        add_interface(revision, name="Ethernet12")
        sections = dict(revision.sections or {})
        sections["routing"] = dict(sections.get("routing") or {})
        sections["routing"]["rip"] = {"rip_0000000000000001": {
            "id": "rip_0000000000000001", "sequence": 1, "address_family": "IPV4", "enabled": True, "interfaces": {},
        }}
        revision.sections = sections
        revision.save(update_fields=["sections"])
        revision.refresh_from_db()
        text = candidate_renderer.render(intent, revision)["text"]
        self.assertIn(platform_drivers.UNSUPPORTED_OBJECT_MARKER, text)
        _config_db(text)  # still parses: the marker line was correctly excluded


class AclTests(TestCase):
    def test_extended_acl_uses_acl_table_and_acl_rule(self):
        change, intent, revision = _sonic_candidate()
        iface = add_interface(revision, name="Ethernet0")
        acl = service.add_acl(revision=revision, name="EDGE-IN", family="IPV4", acl_type="EXTENDED")
        ace = service.add_ace(revision=revision, acl_id=acl["id"], action="PERMIT", protocol="TCP")
        commit(change, intent, revision, f"security.acls.{acl['id']}.entries.{ace['id']}.source_type", "PREFIX")
        commit(change, intent, revision, f"security.acls.{acl['id']}.entries.{ace['id']}.source_value", "10.0.0.0/8")
        commit(change, intent, revision, f"security.acls.{acl['id']}.entries.{ace['id']}.destination_type", "ANY")
        service.add_acl_attachment(revision=revision, acl_id=acl["id"], interface_id=iface["id"], direction="IN")
        doc = _config_db(candidate_renderer.render(intent, revision)["text"])
        table = doc["ACL_TABLE"]["EDGE-IN"]
        self.assertEqual(table["type"], "L3")
        self.assertEqual(table["ports"], ["Ethernet0"])
        self.assertEqual(table["stage"], "ingress")
        rule = doc["ACL_RULE"]["EDGE-IN|RULE_10"]
        self.assertEqual(rule["PACKET_ACTION"], "FORWARD")
        self.assertEqual(rule["SRC_IP"], "10.0.0.0/8")
        self.assertNotIn("DST_IP", rule)  # ANY omits the key entirely
        self.assertEqual(rule["IP_PROTOCOL"], "TCP")

    def test_deny_action_maps_to_drop(self):
        change, intent, revision = _sonic_candidate()
        acl = service.add_acl(revision=revision, name="BLOCK", family="IPV4", acl_type="STANDARD")
        ace = service.add_ace(revision=revision, acl_id=acl["id"], action="DENY", protocol="IP")
        commit(change, intent, revision, f"security.acls.{acl['id']}.entries.{ace['id']}.source_type", "HOST")
        commit(change, intent, revision, f"security.acls.{acl['id']}.entries.{ace['id']}.source_value", "203.0.113.5")
        doc = _config_db(candidate_renderer.render(intent, revision)["text"])
        rule = doc["ACL_RULE"]["BLOCK|RULE_10"]
        self.assertEqual(rule["PACKET_ACTION"], "DROP")
        self.assertEqual(rule["SRC_IP"], "203.0.113.5/32")


class DeterminismTests(TestCase):
    def test_render_is_byte_identical_across_calls(self):
        change, intent, revision = _sonic_candidate()
        add_interface(revision, name="Ethernet0")
        first = candidate_renderer.render(intent, revision)["text"]
        second = candidate_renderer.render(intent, revision)["text"]
        self.assertEqual(first, second)
