"""Interface / address / WAN output of the ONE authoritative candidate renderer.

The vendor-syntax cases are a table (build intent -> lines that must / must not
appear); the renderer *contract* (determinism, accepted-vs-draft, honesty
header, unsupported objects) is asserted once.
"""

from __future__ import annotations

from django.test import TestCase

from core import models
from core.services import candidate_renderer, interface_intent_service
from core.tests.helpers.candidates import add_interface, commit, make_candidate


def address(change, intent, revision, interface, family, cidr):
    row = interface_intent_service.add_address(revision=revision, interface_id=interface["id"], family=family)
    commit(change, intent, revision, f"interfaces.{interface['id']}.addresses.{row['id']}.cidr", cidr)
    return row


def ceos_routed_dual_stack(change, intent, revision):
    interface = add_interface(revision)
    address(change, intent, revision, interface, "IPV4", "192.0.2.1/31")
    address(change, intent, revision, interface, "IPV6", "2001:db8::1/64")


def ceos_access(change, intent, revision):
    commit(change, intent, revision, f"interfaces.{add_interface(revision, kind='ACCESS')['id']}.access_vlan", 10)


def ceos_trunk(change, intent, revision):
    commit(change, intent, revision, f"interfaces.{add_interface(revision, kind='TRUNK')['id']}.trunk_allowed_vlans", "10,11,12,20,20")


def ceos_subinterface(change, intent, revision):
    parent = add_interface(revision)
    child = add_interface(revision, kind="SUBINTERFACE", name="Ethernet1.100")
    commit(change, intent, revision, f"interfaces.{child['id']}.parent_id", parent["id"])
    commit(change, intent, revision, f"interfaces.{child['id']}.encapsulation_vlan", 100)


def ceos_svi(change, intent, revision):
    commit(change, intent, revision, f"interfaces.{add_interface(revision, kind='SVI', name='Vlan10')['id']}.vlan_id", 10)


def ceos_management(change, intent, revision):
    add_interface(revision, kind="MANAGEMENT", name="Vlan200")


def ceos_loopback(change, intent, revision):
    address(change, intent, revision, add_interface(revision, kind="LOOPBACK", name="Loopback0"), "IPV4", "192.0.2.5/24")


def ubuntu_routed(change, intent, revision):
    address(change, intent, revision, add_interface(revision, name="eth1"), "IPV4", "192.0.2.1/31")


def ubuntu_ipv6(change, intent, revision):
    address(change, intent, revision, add_interface(revision, name="eth1"), "IPV6", "2001:db8::1/64")


def auto_address(change, intent, revision):
    interface = add_interface(revision)
    row = interface_intent_service.add_address(revision=revision, interface_id=interface["id"], source="AUTO")
    commit(change, intent, revision, f"interfaces.{interface['id']}.addresses.{row['id']}.ipam_prefix", "192.0.2.0/24")


def wan_metadata(change, intent, revision):
    base = f"interfaces.{add_interface(revision)['id']}.wan"
    commit(change, intent, revision, f"{base}.state", "ENABLED")
    commit(change, intent, revision, f"{base}.provider_name", "ExampleNet")
    commit(change, intent, revision, f"{base}.gateway_ipv4", "192.0.2.2")


CEOS, UBUNTU = models.Platform.ARISTA_CEOS, models.Platform.UBUNTU_FRR
# (case, platform, builder, lines that must appear, lines that must not appear (compared lowercase))
SYNTAX_CASES = [
    ("cEOS routed dual-stack", CEOS, ceos_routed_dual_stack,
     ["interface Ethernet1", "no switchport", "ip address 192.0.2.1/31", "ipv6 address 2001:db8::1/64"], []),
    ("cEOS access port", CEOS, ceos_access, ["switchport access vlan 10"], []),
    ("cEOS trunk serializes the normalized VLAN set", CEOS, ceos_trunk, ["switchport trunk allowed vlan 10-12,20"], []),
    ("cEOS subinterface uses the candidate parent", CEOS, ceos_subinterface, ["parent intent: Ethernet1", "encapsulation dot1q vlan 100"], []),
    ("cEOS SVI", CEOS, ceos_svi, ["vlan 10", "interface Vlan10"], []),
    ("cEOS management is explicitly static", CEOS, ceos_management, ["MANAGEMENT / STATIC"], []),
    ("cEOS loopback does not force a prefix length", CEOS, ceos_loopback, ["ip address 192.0.2.5/24"], []),
    ("Ubuntu routed IPv4", UBUNTU, ubuntu_routed, ["ip link set dev eth1 up", "ip addr replace 192.0.2.1/31 dev eth1"], []),
    ("Ubuntu routed IPv6", UBUNTU, ubuntu_ipv6, ["ip -6 addr replace 2001:db8::1/64 dev eth1"], []),
    ("AUTO address is a comment only (never DHCP)", CEOS, auto_address,
     ["AUTO IPAM prefix 192.0.2.0/24: allocation unresolved and unreserved"], ["dhcp client", "dhclient"]),
    ("WAN is metadata only and generates no routing", CEOS, wan_metadata, ["WAN metadata only", "WAN provider: ExampleNet"],
     ["ip route ", "ipv6 route ", "router bgp", "route-map", "ip nat", "tunnel mode gre", "crypto ipsec"]),
]


class InterfaceSyntaxTests(TestCase):
    def test_vendor_syntax_comes_from_the_platform_driver(self):
        for label, platform, build, expected, forbidden in SYNTAX_CASES:
            with self.subTest(case=label):
                change, intent, revision = make_candidate(platform=platform, device_name="R3" if platform == UBUNTU else "R1")
                build(change, intent, revision)
                text = candidate_renderer.render(intent, revision)["text"]
                for line in expected:
                    self.assertIn(line, text)
                for line in forbidden:
                    self.assertNotIn(line, text.lower())


class RendererContractTests(TestCase):
    def test_render_is_deterministic_and_keeps_accepted_and_draft_apart(self):
        change, intent, revision = make_candidate()
        add_interface(revision, name="Ethernet2")
        interface = add_interface(revision, name="Ethernet1")
        self.assertEqual(candidate_renderer.render(intent, revision)["text"].encode(),
                         candidate_renderer.render(intent, revision)["text"].encode())  # byte-identical
        revision.field_states.filter(path=f"interfaces.{interface['id']}.description").update(draft_value="draft-only", dirty=True)
        self.assertNotIn("draft-only", candidate_renderer.render(intent, revision)["text"])
        self.assertIn("draft-only", candidate_renderer.render(intent, revision, use_draft=True)["text"])

    def test_header_states_the_tier1_honesty_boundary(self):
        _, intent, revision = make_candidate()
        text = candidate_renderer.render(intent, revision)["text"]
        self.assertIn("Tier-1 syntax acceptance only", text)
        self.assertIn("project validation is pending", text)

    def test_object_incompatible_with_the_platform_is_reported_never_faked(self):
        change, intent, revision = make_candidate()
        add_interface(revision, kind="ACCESS")
        commit(change, intent, revision, "device.platform", models.Platform.UBUNTU_FRR)
        intent.refresh_from_db()
        text = candidate_renderer.render(intent, revision)["text"]
        self.assertIn("UNSUPPORTED CANDIDATE OBJECT", text)
        self.assertNotIn("switchport access", text)
