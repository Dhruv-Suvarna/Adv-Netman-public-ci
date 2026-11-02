"""Ubuntu/FRR import parser: three authoritative sources, one canonical edge."""

from __future__ import annotations

import json

from django.test import SimpleTestCase

from core.services.config_import import parser_frr


FRR = """Building configuration...
Current configuration:
!
hostname R3
!
interface eth1
 description R2 transit
 ip ospf area 0.0.0.0
 ip ospf cost 20
!
interface Vlan101
 ipv6 ospf6 area 0.0.0.0
!
ip route 203.0.113.0/24 192.0.2.2 25
ipv6 route 2001:db8:ffff::/48 eth1
!
router ospf
 ospf router-id 10.255.0.3
 redistribute connected
!
router ospf6
 ospf6 router-id 10.255.0.3
!
router bgp 65003
 bgp router-id 10.255.0.3
 neighbor 192.0.2.2 remote-as 65002
 address-family ipv4 unicast
  neighbor 192.0.2.2 activate
  network 10.255.0.3/32
 exit-address-family
!
route-map DIRECT permit 10
!
end
"""

ADDR = json.dumps([
    {"ifname": "eth1", "flags": ["UP", "LOWER_UP"], "mtu": 1500,
     "addr_info": [{"family": "inet", "local": "192.0.2.3", "prefixlen": 31}]},
    {"ifname": "Vlan101", "flags": ["UP"], "mtu": 1500,
     "addr_info": [{"family": "inet6", "local": "2001:db8:101::3", "prefixlen": 64}]},
])

NFT = """table ip EDGE_PAT {
 chain postrouting {
  type nat hook postrouting priority srcnat; policy accept;
  oifname \"eth1\" ip saddr 10.0.0.0/8 masquerade
 }
}
table ip filter { chain input { type filter hook input priority filter; policy accept; } }
"""


class FrrParserTests(SimpleTestCase):
    def setUp(self):
        self.parsed = parser_frr.parse(FRR, addr_json=ADDR, nft_text=NFT)

    def test_linux_and_frr_interface_state_are_merged_by_name(self):
        interfaces = {row.name: row for row in self.parsed.interfaces}
        self.assertEqual(interfaces["eth1"].description, "R2 transit")
        self.assertEqual(interfaces["eth1"].addresses[0]["cidr"], "192.0.2.3/31")
        self.assertEqual(interfaces["Vlan101"].kind, "SVI")
        self.assertEqual(interfaces["Vlan101"].vlan_id, 101)

    def test_routes_ospf_and_bgp_are_structured(self):
        self.assertEqual([(r.family, r.destination) for r in self.parsed.static_routes], [
            ("IPV4", "203.0.113.0/24"), ("IPV6", "2001:db8:ffff::/48")])
        ospf = [r for r in self.parsed.routing_instances if r.family == "ospf"]
        self.assertEqual({r.fields["version"] for r in ospf}, {"OSPFV2", "OSPFV3"})
        self.assertEqual(ospf[0].fields["router_id"], "10.255.0.3")
        bgp = next(r for r in self.parsed.routing_instances if r.family == "bgp")
        self.assertEqual(bgp.fields["local_asn"], 65003)
        self.assertTrue(bgp.neighbors[0]["activate_ipv4"])
        self.assertEqual(bgp.networks, [{"family": "IPV4", "cidr": "10.255.0.3/32"}])

    def test_supported_pat_is_structured_and_complete_nft_source_is_preserved(self):
        self.assertEqual(self.parsed.nat_rules[0].outside_interface, "eth1")
        self.assertEqual(self.parsed.nat_rules[0].original_source, "10.0.0.0/8")
        nft = next(block for block in self.parsed.unmanaged_blocks if "nftables" in block.label)
        self.assertIn("table ip filter", "\n".join(nft.lines))

    def test_unknown_frr_configuration_is_never_dropped(self):
        route_map = next(block for block in self.parsed.unmanaged_blocks if block.lines[0].startswith("route-map"))
        self.assertEqual(route_map.classification, "UNKNOWN")
        ospf = next(r for r in self.parsed.routing_instances if r.family == "ospf" and r.fields["version"] == "OSPFV2")
        self.assertIn(" redistribute connected", ospf.preserved_lines)

    def test_malformed_inputs_do_not_raise(self):
        parser_frr.parse("not frr\n indented", addr_json="{broken", nft_text="nonsense")
