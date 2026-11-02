"""Lab 7 closure -- ``core.services.config_workbench.semantics``: every ``_Builder`` step, the ``ConfigModel`` /
``ConfigObject`` queries, ``attribute_kind`` and ``build_model``, each called directly on small sanitized configs.

Pure: text in, objects out -- nothing is read from or written to a device.  POSITIVE: exact object ids, kinds,
owned lines, references, parents and ``no ...`` removal lines for every recognised construct.  NEGATIVE: the
management plane (VLAN 200, Management0, routes into its subnets) is protected, physical interfaces / negated /
redacted / unrecognised / identity lines are never removable, unmanaged stanzas are protected and referencing,
unknown references resolve to nothing, and an empty configuration has no objects.
"""
from __future__ import annotations

from django.test import SimpleTestCase

from core.services.config_workbench import semantics as s

EOS = """vlan 10,200
interface Vlan10
   description users
   ip address 10.0.10.1/24
   ip address 10.0.11.1/24 secondary
   ip virtual-router address 10.0.10.254
   ip access-group EDGE-IN in
   service-policy type pbr input PBR-A
interface Ethernet1
   switchport mode trunk
interface Management0
   ip address 192.168.200.11/24
ip route 10.50.0.0/16 10.0.10.2
ip route 0.0.0.0/0 192.168.200.1
ip access-list EDGE-IN
   10 permit ip any any
   bogus line
route-map RM-OUT permit 10
   match ip address prefix-list PL-OUT
ip prefix-list PL-OUT
   seq 10 permit 10.0.0.0/8
router bgp 65001
   neighbor 10.0.0.2 remote-as 65002
   neighbor 10.0.0.2 route-map RM-OUT out
   network 10.255.0.1/32
   bgp log-neighbor-changes
   address-family ipv4
      neighbor 10.0.0.2 activate
router ospf 1
   network 10.0.0.0/8 area 0
   passive-interface Loopback0
   max-lsa 100
policy-map type pbr PBR-A
   10 class CM-A
class-map type pbr match-any CM-A
   match ip access-group EDGE-IN
ip nat pool POOL-A 10.0.0.1 10.0.0.9 prefix-length 24
management api http-commands
   protocol https access-group EDGE-IN
"""


def builder(text, platform="arista_ceos"):
    return s._Builder(text, platform)


def root(b, prefix):
    return next(node for node in b.tree.roots if node.stripped.startswith(prefix))


class BuilderInitAndRegistrationTests(SimpleTestCase):
    def test_builder_init_returns_an_indexed_tree_and_empty_registries(self):
        b = s._Builder("interface Loopback0\n   description x\n", "arista_ceos")
        self.assertEqual((b.platform, [n.number for n in b.tree.roots], b.objects, b.attributes, b.owner),
                         ("arista_ceos", [1], {}, {}, {}))
        self.assertEqual(b.named, {"acl": set(), "route_map": set(), "prefix_list": set(), "pbr_policy": set(), "pbr_class": set()})

    def test_builder_init_of_an_empty_config_has_no_roots(self):
        b = s._Builder("", "ubuntu_frr")
        self.assertEqual((b.tree.roots, b.tree.line_count), ([], 0))

    def test_add_returns_the_object_and_the_most_specific_owner_wins(self):
        b = builder("interface Vlan10\n   description x\n")
        parent = b.add(s.ConfigObject(id="interface:Vlan10", kind="svi", label="Vlan10", node=b.tree.node(1), lines=[1, 2]))
        child = b.add(s.ConfigObject(id="x:2", kind="x", label="x", node=b.tree.node(2), lines=[2]))
        self.assertIs(b.objects["interface:Vlan10"], parent)
        self.assertEqual((b.owner[1], b.owner[2]), ("interface:Vlan10", "x:2"))
        self.assertEqual([n.number for n in child.owned_nodes], [2])

    def test_add_of_a_duplicate_identity_never_replaces_the_first_and_folds_lines(self):
        b = builder("ip nat pool P 1\nip nat pool P 2\n")
        first = b.add(s.ConfigObject(id="nat_pool:P", kind="nat_pool", label="first", node=b.tree.node(1), lines=[1]))
        again = b.add(s.ConfigObject(id="nat_pool:P", kind="nat_pool", label="second", node=b.tree.node(2), lines=[2]))
        self.assertIs(again, first)
        self.assertEqual((first.label, first.lines, [n.number for n in first.owned_nodes]), ("first", [1, 2], [1, 2]))

    def test_attribute_returns_a_removable_child_with_its_removal(self):
        b = builder("interface Vlan10\n   mtu 9000\n")
        self.assertIsNone(b.attribute(b.tree.node(2), "interface:Vlan10", removable=True, references={"vlan:10"}))
        attr = b.attributes[2]
        self.assertEqual((attr.removable, attr.kind, attr.references, attr.removal_lines),
                         (True, "mtu", {"vlan:10"}, ["interface Vlan10", "   no mtu 9000"]))
        self.assertEqual(b.owner[2], "interface:Vlan10")

    def test_attribute_never_removes_a_redacted_or_negated_line(self):
        b = builder("interface Vlan10\n   description <REDACTED>\n   no shutdown\n")
        for number, reason in ((2, s.REDACTED), (3, s.NEGATED)):
            with self.subTest(case=f"refused {reason}"):
                b.attribute(b.tree.node(number), "interface:Vlan10", removable=True)
                self.assertEqual((b.attributes[number].removable, b.attributes[number].reason, b.attributes[number].removal_lines),
                                 (False, reason, []))

    def test_virtual_returns_after_grouping_members_under_a_named_object(self):
        b = builder("route-map RM permit 10\nroute-map RM permit 20\n")
        for number, seq in ((1, 10), (2, 20)):
            b.add(s.ConfigObject(id=f"route_map_entry:RM/{seq}", kind="route_map_entry", label="", node=b.tree.node(number), lines=[number]))
            self.assertIsNone(b.virtual("route_map", "RM", f"route_map_entry:RM/{seq}", "route-map RM"))
        obj = b.objects["route_map:RM"]
        self.assertEqual((obj.node, obj.lines, obj.members), (None, [1, 2], ["route_map_entry:RM/10", "route_map_entry:RM/20"]))
        self.assertEqual(b.named["route_map"], {"RM"})

    def test_virtual_with_an_unknown_member_raises_and_registers_no_name(self):
        b = builder("")
        with self.assertRaises(KeyError):
            b.virtual("acl", "X", "acl_entry:X/10", "ACL X")
        self.assertEqual(b.named["acl"], set())


class TopLevelTests(SimpleTestCase):
    def test_top_returns_after_classifying_each_recognised_stanza(self):
        b = builder(EOS)
        cases = {"vlan 10": ["vlan:10", "vlan:200"], "ip route 10.50": ["static_route:ip route 10.50.0.0/16 10.0.10.2"],
                 "ip access-list": ["acl:EDGE-IN", "acl_entry:EDGE-IN/10"], "route-map": ["route_map_entry:RM-OUT/10", "route_map:RM-OUT"],
                 "ip prefix-list": ["prefix_list_entry:PL-OUT/10", "prefix_list:PL-OUT"],
                 "class-map": ["pbr_class:CM-A"], "ip nat pool": ["nat_pool:POOL-A"]}
        for prefix, expected in cases.items():
            with self.subTest(case=f"classifies {prefix}"):
                before = set(b.objects)
                self.assertIsNone(b.top(root(b, prefix)))
                self.assertEqual(sorted(set(b.objects) - before), sorted(expected))
        self.assertEqual(b.objects["vlan:10"].removal_lines, ["no vlan 10"])
        self.assertEqual(b.objects["pbr_class:CM-A"].references, {"acl:EDGE-IN"})
        self.assertEqual(b.objects["route_map_entry:RM-OUT/10"].references, {"prefix_list:PL-OUT"})

    def test_top_returns_frr_flat_acl_and_prefix_list_objects(self):
        b = builder("access-list A seq 5 permit 10.0.0.0/8\nip prefix-list P seq 5 permit 10.0.0.0/8\nip prefix-list Q\n", "ubuntu_frr")
        for node in b.tree.roots:
            b.top(node)
        self.assertEqual(sorted(b.objects), ["acl:A", "acl_entry:A/5", "prefix_list:P", "prefix_list:Q", "prefix_list_entry:P/5"])
        self.assertEqual(b.objects["prefix_list:Q"].removal_lines, ["no ip prefix-list Q"])
        self.assertEqual(b.objects["acl_entry:A/5"].removal_lines, ["no access-list A seq 5 permit 10.0.0.0/8"])

    def test_top_protects_management_vlans_routes_and_unmanaged_stanzas_and_skips_terminators(self):
        b = builder(EOS)
        for prefix in ("vlan 10", "ip route 0.0.0.0", "management api"):
            b.top(root(b, prefix))
        lone = builder("exit\n")
        with self.subTest(case="protected management vlan"):
            self.assertEqual((b.objects["vlan:200"].removable, b.objects["vlan:200"].reason), (False, s.PROTECTED_MANAGEMENT))
        with self.subTest(case="protected management route"):
            route = b.objects["static_route:ip route 0.0.0.0/0 192.168.200.1"]
            self.assertEqual((route.removable, route.protected), (False, True))
        with self.subTest(case="unmanaged stanza is protected"):
            unmanaged = b.objects["unmanaged:38"]
            self.assertEqual((unmanaged.removable, unmanaged.reason, unmanaged.lines), (False, s.UNMANAGED, [38, 39]))
            self.assertEqual((b.attributes[39].removable, b.attributes[39].reason), (False, s.UNMANAGED))
        with self.subTest(case="terminator adds nothing"):
            self.assertIsNone(lone.top(lone.tree.roots[0]))
            self.assertEqual((lone.objects, lone.attributes), ({}, {}))


class InterfaceTests(SimpleTestCase):
    def test_interface_returns_after_building_svi_children_and_attributes(self):
        b = builder(EOS)
        self.assertIsNone(b.interface(root(b, "interface Vlan10"), "Vlan10"))
        iface = b.objects["interface:Vlan10"]
        self.assertEqual((iface.kind, iface.removable, iface.references), ("svi", True, {"vlan:10"}))
        self.assertEqual(sorted(oid for oid, obj in b.objects.items() if obj.parent_id == "interface:Vlan10"), [
            "acl_attachment:Vlan10/EDGE-IN/in", "fhrp_vip:Vlan10/10.0.10.254", "pbr_attachment:Vlan10/PBR-A",
            "primary_address:Vlan10/10.0.10.1/24", "secondary_address:Vlan10/10.0.11.1/24"])
        self.assertEqual(b.objects["secondary_address:Vlan10/10.0.11.1/24"].removal_lines,
                         ["interface Vlan10", "   no ip address 10.0.11.1/24 secondary"])
        self.assertEqual(b.objects["fhrp_vip:Vlan10/10.0.10.254"].references, {"primary_address:Vlan10/*"})
        self.assertEqual((b.attributes[3].removable, b.attributes[3].kind), (True, "description"))

    def test_interface_kinds_cover_loopback_dummy_subinterface_port_channel_and_vrrp(self):
        text = ("interface Loopback0\ninterface dummy0\ninterface Ethernet1.10\ninterface Port-Channel1\ninterface Ethernet2\n"
                "   vrrp 5 ipv4 10.0.0.1\n   vrrp 5 priority-level 200\n   ip ospf area 0\n   ipv6 ospf 1 area 0\n"
                "   ipv6 address 2001:db8::1/64\n   switchport access vlan 30\n   channel-group 1 mode active\n"
                "   ip helper-address 10.0.0.9\n   ip nat source static 10.0.0.1 192.0.2.1\n")
        b = builder(text, "ubuntu_frr")
        for node in b.tree.roots:
            b.interface(node, node.stripped.split()[1])
        kinds = {oid: b.objects[oid].kind for oid in ("interface:Loopback0", "interface:dummy0", "interface:Ethernet1.10",
                                                       "interface:Port-Channel1", "interface:Ethernet2")}
        self.assertEqual(kinds, {"interface:Loopback0": "loopback", "interface:dummy0": "loopback", "interface:Ethernet1.10": "subinterface",
                                 "interface:Port-Channel1": "port_channel", "interface:Ethernet2": "physical_interface"})
        vrrp = b.objects["vrrp_group:Ethernet2/5"]
        self.assertEqual((vrrp.lines, vrrp.operation, vrrp.removal_lines), ([6, 7], s.DEACTIVATE_DETACH, ["interface Ethernet2", "   no vrrp 5"]))
        self.assertEqual(b.objects["ospf_attach:Ethernet2"].references, {"ospf_process:*"})
        self.assertEqual(b.objects["ospf3_attach:Ethernet2"].references, {"ospf3_process:1"})
        self.assertEqual(b.objects["vlan_access:Ethernet2"].references, {"vlan:30"})
        self.assertIn("dhcp_relay:Ethernet2/10.0.0.9", b.objects)
        self.assertIn("ipv6_address:Ethernet2/2001:db8::1/64", b.objects)
        self.assertEqual(b.attributes[12].references, {"interface:Port-Channel1"})

    def test_interface_never_removes_management_physical_or_widening_trunk_lines(self):
        b = builder("interface Management0\n   ip address 192.168.200.11/24\ninterface Ethernet1\n   switchport mode trunk\n"
                    "   switchport trunk allowed vlan 10-11\n   switchport trunk native vlan 99\n   no shutdown\n")
        for node in b.tree.roots:
            b.interface(node, node.stripped.split()[1])
        with self.subTest(case="protected management interface and children"):
            self.assertEqual((b.objects["interface:Management0"].kind, b.objects["interface:Management0"].reason),
                             ("management_interface", s.PROTECTED_MANAGEMENT))
            self.assertTrue(b.objects["primary_address:Management0/192.168.200.11/24"].protected)
        with self.subTest(case="physical interface not deletable"):
            self.assertEqual((b.objects["interface:Ethernet1"].removable, b.objects["interface:Ethernet1"].reason), (False, s.PHYSICAL))
        with self.subTest(case="allowed list never removable"):
            self.assertEqual((b.attributes[5].removable, b.attributes[5].reason, b.attributes[5].references),
                             (False, s.WIDENS, {"vlan:10", "vlan:11"}))
            self.assertNotIn(s.ALL_VLANS, b.objects["interface:Ethernet1"].references)
        with self.subTest(case="negated line not removable"):
            self.assertEqual((b.attributes[7].removable, b.attributes[7].reason), (False, s.NEGATED))

    def test_child_object_returns_a_detachable_child(self):
        b = builder("interface Vlan10\n   ip helper-address 10.0.0.9\n")
        parent = b.add(s.ConfigObject(id="interface:Vlan10", kind="svi", label="", node=b.tree.node(1), lines=[1, 2]))
        obj = b.child_object(b.tree.node(2), parent, "dhcp_relay", "dhcp_relay:Vlan10/10.0.0.9", "relay", "ip helper-address 10.0.0.9")
        self.assertEqual((obj.parent_id, obj.operation, obj.removable, obj.removal_lines),
                         ("interface:Vlan10", s.DEACTIVATE_DETACH, True, ["interface Vlan10", "   no ip helper-address 10.0.0.9"]))

    def test_child_object_with_a_redacted_value_is_never_removable(self):
        b = builder("interface Vlan10\n   vrrp 1 authentication text ********\n")
        parent = b.add(s.ConfigObject(id="interface:Vlan10", kind="svi", label="", node=b.tree.node(1), lines=[1, 2]))
        obj = b.child_object(b.tree.node(2), parent, "x", "x:1", "x", "vrrp 1 authentication")
        self.assertEqual((obj.removable, obj.reason), (False, s.REDACTED))


class RoutingTests(SimpleTestCase):
    def test_router_simple_returns_a_process_with_networks_and_redistribution(self):
        b = builder("router ospf 1\n   network 10.0.0.0/8 area 0\n   redistribute connected route-map RM\n   passive-interface Lo0\n")
        self.assertIsNone(b.router_simple(b.tree.node(1), "ospf_process", "ospf_process:1", "OSPF process 1"))
        self.assertEqual(b.objects["ospf_process:1"].removal_lines, ["no router ospf 1"])
        self.assertEqual(b.objects["ospf_network:1/10.0.0.0/8"].parent_id, "ospf_process:1")
        self.assertEqual(b.objects["redistribute:ospf_process:1/connected"].references, {"route_map:RM"})
        self.assertEqual((b.attributes[4].removable, b.attributes[4].kind), (True, "passive_interface"))

    def test_router_simple_keeps_unrecognised_children_never_removable(self):
        b = builder("router rip\n   timers basic 5 15 15\n", "ubuntu_frr")
        b.router_simple(b.tree.node(1), "rip_process", "rip_process:rip", "RIP")
        self.assertEqual((b.attributes[2].removable, b.attributes[2].reason), (False, s.UNRECOGNISED_ATTRIBUTE))

    def test_router_children_returns_after_typing_rip_networks(self):
        b = builder("router rip\n network 10.0.0.0/8\n exit\n", "ubuntu_frr")
        proc = b.add(s.ConfigObject(id="rip_process:rip", kind="rip_process", label="RIP", node=b.tree.node(1), lines=[1, 2, 3]))
        self.assertIsNone(b.router_children(b.tree.node(1), proc))
        self.assertEqual(b.objects["rip_network:rip/10.0.0.0/8"].kind, "rip_network")
        self.assertNotIn(3, b.attributes)

    def test_router_children_of_a_bgp_process_never_treats_network_as_igp_network(self):
        b = builder("router bgp 1\n   network 10.0.0.0/8\n")
        proc = b.add(s.ConfigObject(id="bgp_process:1", kind="bgp_process", label="BGP AS 1", node=b.tree.node(1), lines=[1, 2]))
        b.router_children(b.tree.node(1), proc)
        self.assertEqual(set(b.objects), {"bgp_process:1"})
        self.assertEqual((b.attributes[2].removable, b.attributes[2].reason), (False, s.UNRECOGNISED_ATTRIBUTE))

    def test_router_bgp_returns_neighbors_networks_and_address_families(self):
        b = builder(EOS)
        self.assertIsNone(b.router_bgp(root(b, "router bgp"), "65001"))
        neighbor = b.objects["bgp_neighbor:65001/10.0.0.2"]
        self.assertEqual((neighbor.lines, neighbor.removal_lines), ([23, 24], ["router bgp 65001", "   no neighbor 10.0.0.2"]))
        self.assertEqual(b.attributes[24].references, {"route_map:RM-OUT"})
        self.assertEqual(b.owner[24], "bgp_neighbor:65001/10.0.0.2")
        self.assertEqual(b.objects["bgp_neighbor_af:65001/10.0.0.2/address-family ipv4"].references, {"bgp_neighbor:65001/10.0.0.2"})
        self.assertIn("bgp_network:65001/10.255.0.1/32", b.objects)

    def test_router_bgp_peer_groups_and_unrecognised_lines_are_never_removable_as_attributes(self):
        b = builder("router bgp 1\n neighbor PG peer group\n neighbor 10.0.0.2 peer group PG\n neighbor 10.0.0.2 remote-as 2\n"
                    " bgp router-id 1.1.1.1\n redistribute connected\n", "ubuntu_frr")
        b.router_bgp(b.tree.node(1), "1")
        group = b.objects["peer_group:1/PG"]
        self.assertEqual((group.kind, group.removal_lines), ("bgp_peer_group", ["router bgp 1", " no neighbor PG"]))
        self.assertEqual(b.objects["bgp_neighbor:1/10.0.0.2"].references, {"peer_group:1/PG"})
        self.assertEqual((b.attributes[5].removable, b.attributes[5].reason), (False, s.UNRECOGNISED_ATTRIBUTE))
        self.assertIn("redistribute:bgp_process:1/connected", b.objects)

    def test_bgp_address_family_returns_activations_networks_and_neighbor_attributes(self):
        b = builder("router bgp 1\n address-family ipv4 unicast\n  neighbor PG activate\n  network 10.0.0.0/8\n"
                    "  neighbor 10.0.0.2 route-map RM in\n  redistribute static\n exit-address-family\n", "ubuntu_frr")
        proc = b.add(s.ConfigObject(id="bgp_process:1", kind="bgp_process", label="BGP AS 1", node=b.tree.node(1), lines=[1]))
        self.assertIsNone(b.bgp_address_family(b.tree.node(2), proc, "1"))
        self.assertEqual(b.objects["bgp_neighbor_af:1/PG/address-family ipv4 unicast"].references, {"peer_group:1/PG"})
        self.assertIn("bgp_network:1/10.0.0.0/8", b.objects)
        self.assertEqual((b.attributes[5].removable, b.attributes[5].references), (True, {"route_map:RM"}))
        self.assertIn("redistribute:bgp_process:1/address-family ipv4 unicast/static", b.objects)

    def test_bgp_address_family_header_and_unknown_lines_are_never_removable(self):
        b = builder("router bgp 1\n   address-family ipv6\n      bgp additional-paths receive\n")
        proc = b.add(s.ConfigObject(id="bgp_process:1", kind="bgp_process", label="", node=b.tree.node(1), lines=[1]))
        b.bgp_address_family(b.tree.node(2), proc, "1")
        self.assertEqual((b.attributes[2].removable, b.attributes[2].reason), (False, s.IDENTITY))
        self.assertEqual((b.attributes[3].removable, b.attributes[3].reason), (False, s.UNRECOGNISED_ATTRIBUTE))

    def test_neighbor_references_returns_every_named_reference(self):
        b = builder("")
        cases = {"neighbor 1.1.1.1 route-map RM out": {"route_map:RM"}, "neighbor 1.1.1.1 prefix-list PL in": {"prefix_list:PL"},
                 "neighbor 1.1.1.1 peer-group PG": {"peer_group:7/PG"}, "neighbor 1.1.1.1 update-source Loopback0": {"interface:Loopback0"}}
        for text, expected in cases.items():
            with self.subTest(case=f"returns {text.split()[2]}"):
                self.assertEqual(b.neighbor_references("7", text), expected)

    def test_neighbor_references_of_a_group_definition_or_plain_attribute_is_empty(self):
        b = builder("")
        for text in ("neighbor PG peer group", "neighbor PG peer-group", "neighbor 1.1.1.1 remote-as 2"):
            with self.subTest(case=f"none for {text}"):
                self.assertEqual(b.neighbor_references("7", text), set())

    def test_match_references_returns_prefix_lists_route_maps_acls_and_pools(self):
        self.assertEqual(builder("").match_references("ip nat inside source list access-list A pool P route-map RM prefix-list PL"),
                         {"acl:A", "nat_pool:P", "route_map:RM", "prefix_list:PL"})

    def test_match_references_of_plain_text_is_empty(self):
        self.assertEqual(builder("").match_references("set local-preference 200"), set())


class AclPbrAndPassTests(SimpleTestCase):
    def test_acl_returns_numbered_entries_with_standard_header(self):
        b = builder("ip access-list standard STD\n   10 permit 10.0.0.0/8\n   20 remark ok\n")
        self.assertIsNone(b.acl(b.tree.node(1), "STD", "ip", standard=True))
        self.assertEqual(b.objects["acl:STD"].removal_lines, ["no ip access-list standard STD"])
        self.assertEqual(sorted(oid for oid in b.objects if oid.startswith("acl_entry:")), ["acl_entry:STD/10", "acl_entry:STD/20"])
        self.assertEqual(b.objects["acl_entry:STD/10"].operation, s.REMOVE_DELETE)
        self.assertEqual(b.named["acl"], {"STD"})

    def test_acl_unnumbered_lines_are_never_removable(self):
        b = builder("ipv6 access-list V6\n   statistics per-entry\n")
        b.acl(b.tree.node(1), "V6", "ipv6", standard=False)
        self.assertEqual(b.objects["acl:V6"].removal_lines, ["no ipv6 access-list V6"])
        self.assertEqual((b.attributes[2].removable, b.attributes[2].reason), (False, s.UNRECOGNISED_ATTRIBUTE))

    def test_pbr_policy_returns_sequences_referencing_classes(self):
        b = builder("policy-map type pbr P\n   10 class C\n")
        self.assertIsNone(b.pbr_policy(b.tree.node(1), "P"))
        self.assertEqual(b.objects["pbr_sequence:P/10"].references, {"pbr_class:C"})
        self.assertEqual(b.named["pbr_policy"], {"P"})

    def test_pbr_policy_unknown_lines_are_never_removable(self):
        b = builder("policy-map type pbr P\n   counters per-entry\n")
        b.pbr_policy(b.tree.node(1), "P")
        self.assertEqual((b.attributes[2].removable, b.attributes[2].reason), (False, s.UNRECOGNISED_ATTRIBUTE))

    def test_protect_management_routes_returns_after_protecting_routes_into_management_subnets(self):
        b = builder("interface Management0\n   ip address 172.20.20.11/24\nip route 10.9.0.0/16 172.20.20.1\nip route 10.8.0.0/16 10.0.0.1\n")
        for node in b.tree.roots:
            b.top(node)
        self.assertIsNone(b.protect_management_routes())
        self.assertEqual(b.objects["static_route:ip route 10.9.0.0/16 172.20.20.1"].reason, s.PROTECTED_MANAGEMENT)
        self.assertTrue(b.objects["static_route:ip route 10.8.0.0/16 10.0.0.1"].removable)

    def test_scan_named_references_returns_after_marking_unmanaged_referrers(self):
        b = builder("ip access-list SNMP-ACL\n   10 permit ip any any\nsnmp-server community <REDACTED> ro SNMP-ACL\n"
                    "snmp-server community ******** ro\n")
        for node in b.tree.roots:
            b.top(node)
        self.assertIsNone(b.scan_named_references())
        self.assertEqual(b.objects["unmanaged:3"].references, {"acl:SNMP-ACL", s.ANY_ACL})
        self.assertEqual(b.objects["unmanaged:4"].references, {s.ANY_ACL})

    def test_finish_virtual_returns_after_aggregating_members_and_expanding_wildcards(self):
        b = builder("interface Ethernet1\n   ip ospf area 0\nrouter ospf 1\nroute-map RM permit 10\n   set metric <REDACTED>\n")
        for node in b.tree.roots:
            b.top(node)
        self.assertIsNone(b.finish_virtual())
        self.assertEqual(b.objects["ospf_attach:Ethernet1"].references, {"ospf_process:1"})
        rm = b.objects["route_map:RM"]
        self.assertEqual((rm.removal_lines, rm.removable, rm.operation), (["no route-map RM permit 10"], True, s.REMOVE_DELETE))

    def test_build_returns_the_full_model(self):
        model = builder(EOS).build()
        self.assertIsInstance(model, s.ConfigModel)
        self.assertEqual(len(model.objects), 30)
        self.assertEqual(model.owner_of_line[16], "acl_entry:EDGE-IN/10")
        self.assertEqual(model.objects["unmanaged:38"].references, {"acl:EDGE-IN"})


class ModelQueryTests(SimpleTestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.model = s.build_model(EOS, "arista_ceos")

    def test_build_model_returns_classified_objects_for_the_platform(self):
        model = s.build_model(EOS, "arista_ceos")
        self.assertEqual(model.platform, "arista_ceos")
        self.assertEqual(model.objects["interface:Vlan10"].kind, "svi")
        self.assertEqual(model.objects["prefix_list:PL-OUT"].members, ["prefix_list_entry:PL-OUT/10"])

    def test_build_model_of_an_empty_config_has_no_objects(self):
        model = s.build_model("", "ubuntu_frr")
        self.assertEqual((model.objects, model.attributes, model.owner_of_line), ({}, {}, {}))

    def test_referrers_returns_objects_and_attribute_lines(self):
        self.assertEqual(self.model.referrers("acl:EDGE-IN"), ["acl_attachment:Vlan10/EDGE-IN/in", "attr:36", "pbr_class:CM-A", "unmanaged:38"])
        self.assertEqual(self.model.referrers("vlan:10"), ["interface:Ethernet1", "interface:Vlan10"])

    def test_referrers_of_an_unreferenced_object_is_empty(self):
        self.assertEqual(self.model.referrers("nat_pool:POOL-A"), [])

    def test_label_of_returns_object_and_line_labels(self):
        self.assertEqual(self.model.label_of("acl:EDGE-IN"), "ACL EDGE-IN")
        self.assertEqual(self.model.label_of("attr:36"), "line 36: match ip access-group EDGE-IN")

    def test_label_of_an_unknown_reference_or_missing_line_is_the_reference_itself(self):
        self.assertEqual(self.model.label_of("acl:NOPE"), "acl:NOPE")
        self.assertEqual(self.model.label_of("attr:999"), "attr:999")

    def test_lines_of_returns_owned_lines(self):
        self.assertEqual(self.model.lines_of("acl:EDGE-IN"), [15, 16, 17])
        self.assertEqual(self.model.lines_of("attr:19"), [19])

    def test_lines_of_an_unknown_object_is_empty(self):
        self.assertEqual(self.model.lines_of("acl:NOPE"), [])

    def test_descendants_of_returns_every_nested_child(self):
        self.assertEqual(self.model.descendants_of("bgp_process:65001"), {
            "bgp_network:65001/10.255.0.1/32", "bgp_neighbor:65001/10.0.0.2", "bgp_neighbor_af:65001/10.0.0.2/address-family ipv4"})

    def test_descendants_of_a_leaf_object_is_empty(self):
        self.assertEqual(self.model.descendants_of("nat_pool:POOL-A"), set())

    def test_config_object_compensation_properties_return_the_exact_text(self):
        neighbor = self.model.objects["bgp_neighbor:65001/10.0.0.2"]
        self.assertEqual(neighbor.restore_lines, ["router bgp 65001", "   neighbor 10.0.0.2 remote-as 65002",
                                                  "   neighbor 10.0.0.2 route-map RM-OUT out"])
        self.assertTrue(neighbor.restorable)
        self.assertEqual(neighbor.absent_paths, ["router bgp 65001 > neighbor 10.0.0.2 remote-as 65002"])
        self.assertEqual(self.model.objects["vlan:10"].absent_paths, ["vlan 10"])
        self.assertEqual((self.model.objects["route_map:RM-OUT"].restore_lines, self.model.objects["route_map:RM-OUT"].absent_paths), ([], []))

    def test_config_object_with_redacted_or_no_lines_is_not_restorable(self):
        model = s.build_model("interface Vlan10\n   vrrp 1 authentication text ********\n", "arista_ceos")
        self.assertFalse(model.objects["vrrp_group:Vlan10/1"].restorable)
        self.assertFalse(self.model.objects["route_map:RM-OUT"].restorable)

    def test_attribute_kind_returns_the_statement_kind(self):
        cases = {"description x": "description", "mtu 9000": "mtu", "switchport trunk native vlan 9": "native_vlan",
                 "neighbor 1.1.1.1 timers 1 3": "neighbor_attribute", "passive-interface Lo0": "passive_interface",
                 "ip ospf cost 5": "ip_ospf", "match ip address prefix-list P": "route_map_clause", "ip rip split-horizon": "ip_rip"}
        for statement, kind in cases.items():
            with self.subTest(case=f"returns {kind}"):
                self.assertEqual(s.attribute_kind(statement), kind)

    def test_attribute_kind_of_an_unknown_statement_is_other(self):
        self.assertEqual(s.attribute_kind("switchport mode trunk"), "other")
