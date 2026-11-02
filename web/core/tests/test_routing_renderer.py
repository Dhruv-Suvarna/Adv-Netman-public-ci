"""Routing output of the ONE authoritative candidate renderer.

Vendor syntax is a table (platform + intent -> lines that must / must not
appear); honest unsupported-feature behavior is a second table.  Nothing here
re-tests validators (see ``test_routing_service``).
"""

from __future__ import annotations

from django.test import TestCase

from core import models
from core.services import candidate_renderer, platform_drivers, routing_intent_service as service
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


def _ceos_bgp(change, intent, revision):
    instance = add_instance(revision, family="bgp", local_asn=65005)
    add_bgp_neighbor(revision, instance_id=instance["id"], peer_address="172.20.5.0", remote_asn=65003)
    add_bgp_network(revision, instance_id=instance["id"], family="IPV4", cidr="172.30.50.10/32")


def _frr_bgp(change, intent, revision):
    instance = add_instance(revision, family="bgp", local_asn=65003)
    add_bgp_neighbor(revision, instance_id=instance["id"], peer_address="172.20.5.1", remote_asn=65005)


def _ceos_ospfv2(change, intent, revision):
    interface = add_interface(revision)
    instance = add_instance(revision, family="ospf", version="OSPFV2")
    commit(change, intent, revision, service._instance_path("ospf", instance["id"], "router_id"), "192.168.255.1")
    commit(change, intent, revision, service._instance_path("ospf", instance["id"], "process_id"), 10)
    binding = add_binding(revision, family="ospf", instance_id=instance["id"], interface_id=interface["id"])
    commit(change, intent, revision, service._binding_path("ospf", instance["id"], binding["id"], "area"), "0")


def _frr_ospf(version, router_id):
    def build(change, intent, revision):
        instance = add_instance(revision, family="ospf", version=version)
        commit(change, intent, revision, service._instance_path("ospf", instance["id"], "router_id"), router_id)
    return build


def _ceos_rip(change, intent, revision):
    interface = add_interface(revision)
    instance = add_instance(revision, family="rip", address_family="IPV4")
    add_binding(revision, family="rip", instance_id=instance["id"], interface_id=interface["id"])


def _frr_rip(family):
    def build(change, intent, revision):
        interface = add_interface(revision, name="eth1")
        instance = add_instance(revision, family="rip", address_family=family)
        add_binding(revision, family="rip", instance_id=instance["id"], interface_id=interface["id"])
    return build


# (case, platform, device, builder, lines that must appear, lines that must not appear)
SYNTAX_CASES = [
    ("cEOS BGP: address-family without 'unicast'", models.Platform.ARISTA_CEOS, "R5", _ceos_bgp,
     ["router bgp 65005", "neighbor 172.20.5.0 remote-as 65003", "address-family ipv4\n"],
     ["address-family ipv4 unicast", "exit-address-family", "route-map", "prefix-list", "route-policy"]),
    ("FRR BGP: 'unicast' + exit-address-family", models.Platform.UBUNTU_FRR, "R3", _frr_bgp,
     ["router bgp 65003", "address-family ipv4 unicast", "exit-address-family"], ["route-map", "prefix-list"]),
    ("cEOS OSPFv2: process number and per-interface area", models.Platform.ARISTA_CEOS, "R1", _ceos_ospfv2,
     ["router ospf 10", "router-id 192.168.255.1", "ip ospf area 0.0.0.0"], []),
    ("FRR OSPFv2: no process number", models.Platform.UBUNTU_FRR, "R3", _frr_ospf("OSPFV2", "192.168.255.3"),
     ["router ospf\n", "ospf router-id 192.168.255.3"], []),
    ("FRR OSPFv3: router ospf6", models.Platform.UBUNTU_FRR, "R3", _frr_ospf("OSPFV3", "192.168.255.3"),
     ["router ospf6", "ospf6 router-id 192.168.255.3"], []),
    ("cEOS RIP: v2 only", models.Platform.ARISTA_CEOS, "R1", _ceos_rip, ["router rip"], ["version 1"]),
    ("FRR RIPv2", models.Platform.UBUNTU_FRR, "R3", _frr_rip("IPV4"),
     ["router rip", "version 2", "network eth1"], ["router ripng"]),
    ("FRR RIPng", models.Platform.UBUNTU_FRR, "R3", _frr_rip("IPV6"),
     ["router ripng", "network eth1"], ["version 2"]),
]


class RoutingSyntaxTests(TestCase):
    def test_vendor_syntax_comes_from_the_platform_driver(self):
        for label, platform, device, build, expected, forbidden in SYNTAX_CASES:
            with self.subTest(case=label):
                change, intent, revision = make_candidate(platform=platform, device_name=device)
                build(change, intent, revision)
                text = candidate_renderer.render(intent, revision)["text"]
                for line in expected:
                    self.assertIn(line, text)
                for line in forbidden:
                    self.assertNotIn(line, text)

    def test_bgp_password_reference_is_never_rendered_as_plaintext(self):
        change, intent, revision = make_candidate()
        instance = add_instance(revision, family="bgp", local_asn=65000)
        neighbor = add_bgp_neighbor(revision, instance_id=instance["id"], peer_address="192.0.2.1", remote_asn=65001)
        commit(change, intent, revision, service._bgp_neighbor_path(instance["id"], neighbor["id"], "password_ref"), "vault:bgp/r1-r5")
        text = candidate_renderer.render(intent, revision)["text"]
        self.assertIn("authentication reference present", text)
        self.assertNotIn("neighbor 192.0.2.1 password", text)

    def test_render_carries_routing_deterministically_and_wan_metadata_generates_no_routes(self):
        change, intent, revision = make_candidate()
        interface = add_interface(revision)
        add_static_route(revision)
        instance = add_instance(revision, family="ospf", version="OSPFV2")
        commit(change, intent, revision, f"routing.ospf.{instance['id']}.router_id", "192.168.255.1")
        first, second = candidate_renderer.render(intent, revision), candidate_renderer.render(intent, revision)
        self.assertEqual(set(first["routing"]), set(service.PROTOCOL_FAMILIES))
        self.assertEqual(first["text"], second["text"])  # byte-identical

        commit(change, intent, revision, f"interfaces.{interface['id']}.wan.state", "ENABLED")
        commit(change, intent, revision, f"interfaces.{interface['id']}.wan.gateway_ipv4", "203.0.113.1")
        text = candidate_renderer.render(intent, revision)["text"]
        self.assertNotIn("ip route 203.0.113", text)
        self.assertIn("no route or routing protocol is generated", text)


class HonestFallbackTests(TestCase):
    """Preserved-but-unrenderable intent is reported, never turned into fabricated vendor CLI."""

    @staticmethod
    def routing(**families):
        base = {"static_routes": {}, "rip": {}, "ospf": {}, "isis": {}, "eigrp": {}, "bgp": {}}
        base.update(families)
        return base

    def test_unsupported_objects_emit_an_explicit_comment_not_fake_cli(self):
        eigrp = {"eigrp_0000000000000001": {"id": "eigrp_0000000000000001", "sequence": 1, "asn": 100, "router_id": "",
                                            "address_family": "IPV4", "interfaces": {}}}
        isis = {"isis_0000000000000001": {"id": "isis_0000000000000001", "sequence": 1, "net": "", "level": "LEVEL_2",
                                           "address_family_ipv4": True, "address_family_ipv6": False}}
        # (case, platform, preserved routing, text that must be absent, text that must be present)
        cases = [
            # SR Linix genuinely implements BGP/OSPF/static (Phase 20.5) -- ISIS remains a real gap.
            ("SR Linux preserved ISIS (NOT_IMPLEMENTED)", models.Platform.NOKIA_SRLINUX, self.routing(isis=isis), "router isis", None),
            # IOS XR now also renders documented default-VRF RIPv2; RIPng
            # remains model/version blocked and is covered by its own driver tests.
            ("cEOS preserved EIGRP (UNSUPPORTED)", models.Platform.ARISTA_CEOS, self.routing(eigrp=eigrp), "router eigrp", "EIGRP"),
        ]
        for label, platform, routing, absent, present in cases:
            with self.subTest(case=label):
                _, intent, revision = make_candidate(platform=platform, device_name="X1")
                revision.sections = {**revision.sections, "routing": routing}
                revision.save(update_fields=["sections"])
                text = candidate_renderer.render(intent, revision)["text"]
                self.assertIn("UNSUPPORTED CANDIDATE OBJECT", text)
                self.assertNotIn(absent, text)
                if present:
                    self.assertIn(present, text)

    def test_platform_with_nothing_configured_says_so(self):
        """SONiC now genuinely renders config_db JSON (Phase 20.5), so this no
        longer tests 'a platform with zero renderer' -- it tests the same
        honest empty-candidate gate every platform has (see
        test_candidate_renderer.py's PlatformDriverRegistryTests)."""
        _, intent, revision = make_candidate(platform=models.Platform.SONIC, device_name="SONIC1")
        # The hostname validator refuses an empty commit (like every platform's), so
        # simulate "nothing configured yet" the same way other tests here inject
        # otherwise-unreachable state: directly, not through the commit boundary.
        revision.field_states.filter(path="device.hostname").update(accepted_value="")
        self.assertEqual(candidate_renderer.render(intent, revision)["descriptors"], [platform_drivers.NOT_IMPLEMENTED_LINE])
