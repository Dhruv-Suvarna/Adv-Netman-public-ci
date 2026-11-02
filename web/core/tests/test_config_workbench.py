"""Remove Configuration / Configuration Changes -- the pure analysis layer (no device, no DB).

Fixtures mirror the tracked Lab-1 templates' real EOS syntax (S1: VLAN / SVI / trunk / VARP / relays; R1: OSPF / RIP /
route-maps / prefix-lists / Management0 default route) and FRR's ``exit``-terminated blocks.
"""
from __future__ import annotations

from django.test import SimpleTestCase

from core.services.config_workbench import removal, semantics, structure

SWITCH = """hostname S1
ip routing
vlan 10
   name USERS10
vlan 20
   name USERS20
vlan 30
   name IPV6_ONLY
vlan 40
   name LAB_ONLY
vlan 50
   name TRUNK_ONLY
vlan 200
   name MANAGEMENT
snmp-server ipv4 access-list NMAS_SNMP
interface Ethernet2
   description S1_S2_TRUNK
   switchport mode trunk
   switchport trunk allowed vlan 10,20,50
interface Ethernet3
   description H1_VLAN10
   switchport access vlan 10
interface Ethernet5
   switchport access vlan 200
interface Management0
   ip address 172.20.20.13/24
interface Vlan200
   ip address 192.168.200.11/24
interface Vlan10
   ip address 192.168.10.2/24
   ip address 192.168.11.2/24 secondary
   ip virtual-router address 192.168.10.1
   ip helper-address 192.168.200.100
interface Vlan30
   ipv6 address 2001:db8:30::2/64
interface Vlan40
   ip address 192.168.40.2/24
interface Vlan50
   ip address 192.168.50.2/24
ip access-list standard NMAS_SNMP
   10 permit host 192.168.200.100
ip access-list LAB_ACL
   10 permit ip any any
   20 deny ip any any
interface Ethernet6
   ip access-group LAB_ACL in
ip route 10.99.0.0/16 192.168.110.0
ip route 0.0.0.0/0 172.20.20.1
router bgp 65001
   router-id 1.1.1.1
   neighbor 10.0.0.2 remote-as 65002
   neighbor 10.0.0.2 route-map RM-IN in
   neighbor 10.0.0.3 remote-as 65003
   address-family ipv4
      neighbor 10.0.0.2 activate
      network 10.1.0.0/16
route-map RM-IN permit 10
   match ip address prefix-list PL1
ip prefix-list PL1
   seq 10 permit 10.0.0.0/8
policy-map type pbr PBR1
   10 class CM1
      set nexthop 192.168.110.1
   20 class CM2
      set nexthop 192.168.110.3
interface Ethernet7
   service-policy type pbr input PBR1
end
"""

FRR = """frr version 8.4.4
hostname R3
interface eth1
 ip address 10.0.34.3/24
exit
router bgp 65003
 neighbor 10.0.34.4 remote-as 65004
 address-family ipv4 unicast
  network 10.3.0.0/16
 exit-address-family
exit
ip route 10.50.0.0/16 10.0.34.4
"""


def line_of(text: str, needle: str) -> int:
    return next(n for n, line in enumerate(text.splitlines(), start=1) if line.strip() == needle)


def analyze(text=SWITCH, platform="arista_ceos", **kw):
    return removal.analyze(text, platform, **kw).to_dict()


class StructureTests(SimpleTestCase):
    def test_line_numbers_match_the_displayed_text_and_hierarchy_is_indentation_based(self):
        tree = structure.parse(SWITCH)
        number = line_of(SWITCH, "neighbor 10.0.0.2 activate")
        node = tree.node(number)
        self.assertEqual([a.stripped for a in node.ancestors()], ["router bgp 65001", "address-family ipv4"])
        self.assertEqual(node.path(), "router bgp 65001 > address-family ipv4 > neighbor 10.0.0.2 activate")

    def test_frr_exit_terminators_close_their_own_block(self):
        tree = structure.parse(FRR)
        exit_af = tree.node(line_of(FRR, "exit-address-family"))
        self.assertTrue(exit_af.terminator)
        self.assertEqual(exit_af.parent.stripped, "address-family ipv4 unicast")
        route = tree.node(line_of(FRR, "ip route 10.50.0.0/16 10.0.34.4"))
        self.assertIsNone(route.parent)

    def test_config_paths_expand_vlan_ranges(self):
        paths = structure.config_paths("vlan 101-102\n   name X\n")
        self.assertTrue({"vlan 101", "vlan 102", "vlan 101-102"} <= paths)


class SviVlanDependencyTests(SimpleTestCase):
    def test_svi_that_is_the_only_consumer_proposes_the_now_unused_vlan(self):
        result = analyze(mode="SEMANTIC", object_ids=["interface:Vlan40"])
        self.assertEqual(result["status"], "READY")
        self.assertEqual([i["id"] for i in result["items"]], ["interface:Vlan40"])      # the VLAN is NOT added silently
        self.assertEqual([p["object"] for p in result["proposals"]], ["vlan:40"])

    def test_accepting_the_proposal_shows_both_operations_svi_first(self):
        result = analyze(mode="SEMANTIC", object_ids=["interface:Vlan40"], accepted_proposals=["vlan:40"])
        self.assertEqual([i["removal_lines"] for i in result["items"]], [["no interface Vlan40"], ["no vlan 40"]])
        self.assertEqual(result["proposals"], [])

    def test_svi_removal_preserves_a_vlan_used_by_an_access_port(self):
        result = analyze(mode="SEMANTIC", object_ids=["interface:Vlan10"])
        self.assertEqual(result["status"], "READY")
        self.assertEqual(result["proposals"], [])

    def test_svi_removal_preserves_a_vlan_carried_by_a_trunk(self):
        result = analyze(mode="SEMANTIC", object_ids=["interface:Vlan50"])
        self.assertEqual((result["status"], result["proposals"]), ("READY", []))

    def test_vlan_removal_while_referenced_is_blocked_with_every_referrer(self):
        result = analyze(mode="SEMANTIC", object_ids=["vlan:10"])
        self.assertEqual(result["status"], "BLOCKED")
        blocker = result["blockers"][0]
        self.assertEqual(blocker["code"], removal.REFERENCED)
        self.assertIn(line_of(SWITCH, "switchport access vlan 10"), blocker["referrer_lines"])
        self.assertIn(line_of(SWITCH, "switchport trunk allowed vlan 10,20,50"), blocker["referrer_lines"])
        self.assertIn(line_of(SWITCH, "interface Vlan10"), blocker["referrer_lines"])

    def test_a_trunk_without_an_allowed_list_carries_every_vlan(self):
        text = SWITCH.replace("   switchport trunk allowed vlan 10,20,50\n", "")
        self.assertEqual(analyze(text, mode="SEMANTIC", object_ids=["interface:Vlan40"])["proposals"], [])
        self.assertEqual(analyze(text, mode="SEMANTIC", object_ids=["vlan:40"])["status"], "BLOCKED")

    def test_management_vlan_and_svi_are_protected(self):
        for oid in ("vlan:200", "interface:Vlan200", "primary_address:Vlan200/192.168.200.11/24"):
            result = analyze(mode="SEMANTIC", object_ids=[oid])
            self.assertEqual(result["blockers"][0]["code"], removal.PROTECTED, oid)


class GranularSmartRemovalTests(SimpleTestCase):
    def test_one_bgp_neighbor(self):
        result = analyze(mode="SEMANTIC", object_ids=["bgp_neighbor:65001/10.0.0.3"])
        self.assertEqual(result["status"], "READY")
        self.assertEqual(result["items"][0]["removal_lines"], ["router bgp 65001", "   no neighbor 10.0.0.3"])
        self.assertEqual(result["items"][0]["operation"], "REMOVE_DELETE")

    def test_neighbor_with_an_af_activation_is_blocked_until_the_activation_is_included(self):
        self.assertEqual(analyze(mode="SEMANTIC", object_ids=["bgp_neighbor:65001/10.0.0.2"])["status"], "BLOCKED")
        both = analyze(mode="SEMANTIC", object_ids=["bgp_neighbor:65001/10.0.0.2", "bgp_neighbor_af:65001/10.0.0.2/address-family ipv4"])
        self.assertEqual(both["status"], "READY")
        self.assertEqual(both["items"][0]["operation"], "DEACTIVATE_DETACH")   # detach before delete
        self.assertEqual([p["object"] for p in both["proposals"]], ["route_map:RM-IN"])

    def test_one_secondary_ip(self):
        result = analyze(mode="SEMANTIC", object_ids=["secondary_address:Vlan10/192.168.11.2/24"])
        self.assertEqual(result["items"][0]["removal_lines"], ["interface Vlan10", "   no ip address 192.168.11.2/24 secondary"])
        self.assertEqual(result["items"][0]["operation"], "DEACTIVATE_DETACH")

    def test_primary_with_secondaries_is_not_removable(self):
        result = analyze(mode="SEMANTIC", object_ids=["primary_address:Vlan10/192.168.10.2/24"])
        self.assertEqual(result["blockers"][0]["reason"], semantics.PRIMARY_WITH_SECONDARIES)

    def test_one_acl_sequence_and_the_attached_acl_is_protected_from_deletion(self):
        entry = analyze(mode="SEMANTIC", object_ids=["acl_entry:LAB_ACL/20"])
        self.assertEqual(entry["items"][0]["removal_lines"], ["ip access-list LAB_ACL", "   no 20"])
        self.assertEqual(entry["status"], "READY")
        self.assertTrue(any(w["code"] == "POLICY_CHANGES" for w in entry["warnings"]))
        whole = analyze(mode="SEMANTIC", object_ids=["acl:LAB_ACL"])
        self.assertEqual(whole["blockers"][0]["code"], removal.REFERENCED)

    def test_management_acl_entries_are_protected(self):
        result = analyze(mode="SEMANTIC", object_ids=["acl_entry:NMAS_SNMP/10"])
        self.assertEqual(result["blockers"][0]["code"], removal.PROTECTED)

    def test_one_pbr_sequence(self):
        result = analyze(mode="SEMANTIC", object_ids=["pbr_sequence:PBR1/20"])
        self.assertEqual(result["status"], "READY")
        self.assertEqual(result["items"][0]["removal_lines"], ["policy-map type pbr PBR1", "   no 20"])
        self.assertEqual(analyze(mode="SEMANTIC", object_ids=["pbr_policy:PBR1"])["blockers"][0]["code"], removal.REFERENCED)

    def test_referenced_route_map_and_prefix_list_are_blocked(self):
        self.assertEqual(analyze(mode="SEMANTIC", object_ids=["route_map:RM-IN"])["blockers"][0]["code"], removal.REFERENCED)
        self.assertEqual(analyze(mode="SEMANTIC", object_ids=["prefix_list_entry:PL1/10"])["blockers"][0]["code"], removal.REFERENCED)

    def test_one_bgp_network_inside_an_address_family(self):
        result = analyze(mode="SEMANTIC", object_ids=["bgp_network:65001/10.1.0.0/16"])
        self.assertEqual(result["items"][0]["removal_lines"], ["router bgp 65001", "   address-family ipv4", "      no network 10.1.0.0/16"])

    def test_management_default_route_via_management0_subnet_is_protected(self):
        result = analyze(mode="SEMANTIC", object_ids=["static_route:ip route 0.0.0.0/0 172.20.20.1"])
        self.assertEqual(result["blockers"][0]["code"], removal.PROTECTED)
        ok = analyze(mode="SEMANTIC", object_ids=["static_route:ip route 10.99.0.0/16 192.168.110.0"])
        self.assertEqual(ok["items"][0]["removal_lines"], ["no ip route 10.99.0.0/16 192.168.110.0"])

    def test_restore_lines_and_absent_paths_are_derived_for_verification(self):
        item = analyze(mode="SEMANTIC", object_ids=["bgp_neighbor:65001/10.0.0.3"])["items"][0]
        self.assertEqual(item["restore_lines"], ["router bgp 65001", "   neighbor 10.0.0.3 remote-as 65003"])
        self.assertEqual(item["absent_paths"], ["router bgp 65001 > neighbor 10.0.0.3 remote-as 65003"])
        self.assertTrue(item["restorable"])


class LineRangeTests(SimpleTestCase):
    def test_a_complete_stanza_resolves_to_its_object(self):
        start = line_of(SWITCH, "interface Vlan40")
        result = analyze(mode="LINE_RANGE", line_range=(start, start + 1))
        self.assertEqual([i["id"] for i in result["items"]], ["interface:Vlan40"])
        self.assertEqual(result["status"], "READY")

    def test_a_granular_child_line_is_removed_in_context(self):
        number = line_of(SWITCH, "neighbor 10.0.0.2 route-map RM-IN in")
        result = analyze(mode="LINE_RANGE", line_range=(number, number))
        self.assertEqual(result["status"], "READY")
        self.assertEqual(result["items"][0]["removal_lines"], ["router bgp 65001", "   no neighbor 10.0.0.2 route-map RM-IN in"])
        self.assertEqual([p["object"] for p in result["proposals"]], ["route_map:RM-IN"])

    def test_a_range_cutting_through_a_stanza_is_blocked_as_partial_context(self):
        start = line_of(SWITCH, "router bgp 65001")
        result = analyze(mode="LINE_RANGE", line_range=(start, start + 2))
        self.assertEqual(result["status"], "BLOCKED")
        self.assertEqual(result["blockers"][0]["code"], removal.PARTIAL_CONTEXT)
        self.assertEqual(result["blockers"][0]["needed"][0], start)

    def test_the_identity_line_alone_is_partial_context(self):
        number = line_of(SWITCH, "neighbor 10.0.0.2 remote-as 65002")
        self.assertEqual(analyze(mode="LINE_RANGE", line_range=(number, number))["blockers"][0]["code"], removal.PARTIAL_CONTEXT)

    def test_trunk_allowed_list_removal_is_refused_because_it_would_widen(self):
        number = line_of(SWITCH, "switchport trunk allowed vlan 10,20,50")
        blocker = analyze(mode="LINE_RANGE", line_range=(number, number))["blockers"][0]
        self.assertEqual(blocker["reason"], semantics.WIDENS)

    def test_out_of_range_and_unmanaged_lines(self):
        self.assertEqual(analyze(mode="LINE_RANGE", line_range=(0, 3))["blockers"][0]["code"], removal.OUT_OF_RANGE)
        self.assertEqual(analyze(mode="LINE_RANGE", line_range=(1, 1))["blockers"][0]["code"], removal.PROTECTED)


class PlatformHonestyTests(SimpleTestCase):
    def test_frr_is_rendered_for_preview_but_never_executable(self):
        result = analyze(FRR, "ubuntu_frr", mode="SEMANTIC", object_ids=["bgp_neighbor:65003/10.0.34.4"])
        self.assertEqual(result["items"][0]["removal_lines"], ["router bgp 65003", " no neighbor 10.0.34.4"])
        self.assertEqual(result["items"][0]["support"], removal.FIXTURE_ONLY)
        self.assertTrue(any(w["code"] == "NOT_EXECUTABLE" for w in result["warnings"]))
        self.assertFalse(removal.executable("ubuntu_frr", "bgp_neighbor"))

    def test_only_parser_validated_ceos_forms_are_executable(self):
        self.assertTrue(removal.executable("arista_ceos", "svi"))
        self.assertFalse(removal.executable("arista_ceos", "nat_pool"))      # the live parser rejected the rendered form
        self.assertFalse(removal.executable("arista_ceos", "attribute:ip_rip"))
        self.assertEqual(removal.support_status("sonic", "vlan"), removal.NOT_IMPLEMENTED)

    def test_unsupported_platform_is_blocked(self):
        self.assertEqual(analyze(platform="sonic", mode="SEMANTIC", object_ids=["vlan:10"])["status"], "BLOCKED")

    def test_redacted_lines_are_never_removed_or_claimed_restorable(self):
        text = "router bgp 65001\n   neighbor 10.0.0.9 remote-as 65009\n   neighbor 10.0.0.9 password <REDACTED>\n"
        number = line_of(text, "neighbor 10.0.0.9 password <REDACTED>")
        self.assertEqual(analyze(text, mode="LINE_RANGE", line_range=(number, number))["blockers"][0]["reason"], semantics.REDACTED)
        whole = analyze(text, mode="SEMANTIC", object_ids=["bgp_neighbor:65001/10.0.0.9"])
        self.assertEqual(whole["status"], "READY")
        self.assertFalse(whole["items"][0]["restorable"])
