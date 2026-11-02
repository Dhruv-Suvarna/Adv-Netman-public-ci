from __future__ import annotations

import copy

from django.test import TestCase

from core.tests.helpers.validation import (
    Dev, codes, findings, link, make_sources, nb_ip, netbox_data, new_change, topology_data, validate,
)

L12 = link("R1", "Ethernet1", "R2", "Ethernet1")


def sources(links=(L12,), **kw):
    return make_sources(topology=topology_data(links=list(links), nodes=("R1", "R2", "R3", "R4", "S1", "S2")), **kw)


class OspfTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.change = new_change()
        cls.r1, cls.r2 = Dev(cls.change, "R1"), Dev(cls.change, "R2")
        cls.a, cls.z = cls.r1.iface("Ethernet1"), cls.r2.iface("Ethernet1")
        cls.r1.address(cls.a, "192.0.2.0/31")
        cls.r2.address(cls.z, "192.0.2.1/31")

    def bind_both(self, area_a="0.0.0.0", area_z="0.0.0.0", version_a="OSPFV2", version_z="OSPFV2"):
        o1, o2 = self.r1.ospf(version_a), self.r2.ospf(version_z)
        self.r1.bind("ospf", o1, self.a, area=area_a)
        self.r2.bind("ospf", o2, self.z, area=area_z)
        return o1, o2

    def test_matching_area_accepted(self):
        self.bind_both()
        run = validate(self.change, sources())
        self.assertFalse([c for c in codes(run) if c.startswith("OSPF_")])
        self.assertEqual(run.status, "PASS")

    def test_equivalent_area_spellings_are_equal(self):
        self.bind_both(area_a="0", area_z="0.0.0.0")
        self.assertNotIn("OSPF_AREA_MISMATCH", codes(validate(self.change, sources())))

    def test_area_mismatch_blocked(self):
        self.bind_both(area_a="0.0.0.0", area_z="0.0.0.1")
        run = validate(self.change, sources())
        (finding,) = findings(run, "OSPF_AREA_MISMATCH")
        self.assertTrue(finding["blocking"])
        self.assertEqual(run.status, "BLOCKED")

    def test_version_mismatch_blocked(self):
        self.bind_both(version_a="OSPFV2", version_z="OSPFV3")
        self.assertTrue(findings(validate(self.change, sources()), "OSPF_VERSION_MISMATCH")[0]["blocking"])

    def test_network_type_mismatch_is_warning(self):
        o1, o2 = self.bind_both()
        binding_1 = next(iter(self.r1.refresh().sections["routing"]["ospf"][o1["id"]]["interfaces"]))
        binding_2 = next(iter(self.r2.refresh().sections["routing"]["ospf"][o2["id"]]["interfaces"]))
        self.r1.set(f"routing.ospf.{o1['id']}.interfaces.{binding_1}.network_type", "POINT_TO_POINT")
        self.r2.set(f"routing.ospf.{o2['id']}.interfaces.{binding_2}.network_type", "BROADCAST")
        (finding,) = findings(validate(self.change, sources()), "OSPF_NETWORK_TYPE_MISMATCH")
        self.assertFalse(finding["blocking"])

    def test_one_sided_participation_does_not_block(self):
        o1 = self.r1.ospf()
        self.r1.bind("ospf", o1, self.a)
        run = validate(self.change, sources())
        (finding,) = findings(run, "OSPF_ONE_SIDED")
        self.assertEqual((finding["severity"], finding["blocking"]), ("INFO", False))
        self.assertEqual(run.status, "PASS")

    def test_dangling_interface_reference_is_resolved_or_blocked(self):
        o1 = self.r1.ospf()
        binding = self.r1.bind("ospf", o1, self.a)
        self.r1.force(f"routing.ospf.{o1['id']}.interfaces.{binding['id']}.interface_id", "if_0000000000000000")
        self.assertTrue(findings(validate(self.change, sources()), "DEPENDENCY_MISSING")[0]["blocking"])

    def test_mtu_mismatch_on_ospf_link_is_called_out(self):
        self.r1.set(f"interfaces.{self.a['id']}.mtu", 9000)
        self.r2.set(f"interfaces.{self.z['id']}.mtu", 1500)
        o1 = self.r1.ospf(); self.r1.bind("ospf", o1, self.a)
        (finding,) = findings(validate(self.change, sources()), "LINK_MTU_MISMATCH")
        self.assertTrue(finding["evidence"]["ospf_on_link"])
        self.assertFalse(finding["blocking"])

    def test_ospfv2_interface_without_ipv4_address_is_warned(self):
        r3 = Dev(self.change, "R3"); bare = r3.iface("Ethernet5")
        o = r3.ospf(); r3.bind("ospf", o, bare)
        self.assertIn("ROUTING_INTERFACE_NO_ADDRESS", codes(validate(self.change, sources())))


class RouterIdTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.change = new_change()
        cls.r1, cls.r2 = Dev(cls.change, "R1"), Dev(cls.change, "R2")

    def test_duplicate_ospf_router_id_detected(self):
        self.r1.ospf(router_id="10.255.0.1"); self.r2.ospf(router_id="10.255.0.1")
        (finding,) = findings(validate(self.change), "ROUTER_ID_DUPLICATE")
        self.assertTrue(finding["blocking"])
        self.assertEqual(finding["evidence"]["devices"], ["R1", "R2"])

    def test_unique_router_ids_pass(self):
        self.r1.ospf(router_id="10.255.0.1"); self.r2.ospf(router_id="10.255.0.2")
        self.assertNotIn("ROUTER_ID_DUPLICATE", codes(validate(self.change)))

    def test_duplicate_bgp_router_id_in_same_asn_detected(self):
        self.r1.bgp(65001, router_id="10.255.0.9"); self.r2.bgp(65001, router_id="10.255.0.9")
        self.assertTrue(findings(validate(self.change), "ROUTER_ID_DUPLICATE")[0]["blocking"])

    def test_duplicate_bgp_router_id_between_unrelated_asns_is_only_a_warning(self):
        self.r1.bgp(65001, router_id="10.255.0.9"); self.r2.bgp(65002, router_id="10.255.0.9")
        (finding,) = findings(validate(self.change), "ROUTER_ID_DUPLICATE")
        self.assertFalse(finding["blocking"])

    def test_same_router_id_across_unrelated_protocol_families_is_not_a_conflict(self):
        self.r1.ospf(router_id="10.255.0.1"); self.r2.bgp(65002, router_id="10.255.0.1")
        self.assertNotIn("ROUTER_ID_DUPLICATE", codes(validate(self.change)))

    def test_ospf_v2_and_v3_router_ids_are_separate_domains(self):
        self.r1.ospf("OSPFV2", router_id="10.255.0.1"); self.r2.ospf("OSPFV3", router_id="10.255.0.1")
        self.assertNotIn("ROUTER_ID_DUPLICATE", codes(validate(self.change)))


class BgpTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.change = new_change()
        cls.r1, cls.r2 = Dev(cls.change, "R1"), Dev(cls.change, "R2")
        cls.a, cls.z = cls.r1.iface("Ethernet1"), cls.r2.iface("Ethernet1")
        cls.r1.address(cls.a, "192.0.2.0/31"); cls.r2.address(cls.z, "192.0.2.1/31")
        cls.b1, cls.b2 = cls.r1.bgp(65001), cls.r2.bgp(65002)

    def peers(self, remote_1=65002, remote_2=65001):
        n1 = self.r1.neighbor(self.b1, "192.0.2.1", remote_1)
        n2 = self.r2.neighbor(self.b2, "192.0.2.0", remote_2)
        return n1, n2

    def test_candidate_internal_peers_are_resolved(self):
        self.peers()
        run = validate(self.change, sources())
        resolved = [f for f in run.derived_facts if f["type"] == "BGP_PEER_RESOLVED"]
        self.assertEqual({(f["device"], f["peer_device"]) for f in resolved}, {("R1", "R2"), ("R2", "R1")})
        self.assertTrue(all(f["scope"] == "CANDIDATE" and f["reciprocal"] for f in resolved))

    def test_reciprocal_asn_match_accepted(self):
        self.peers()
        run = validate(self.change, sources())
        self.assertFalse([c for c in codes(run) if c.startswith("BGP_")])
        self.assertEqual(run.status, "PASS")

    def test_remote_as_mismatch_blocked(self):
        self.peers(remote_1=65099)
        run = validate(self.change, sources())
        (finding,) = findings(run, "BGP_REMOTE_AS_MISMATCH")
        self.assertTrue(finding["blocking"])
        self.assertEqual(finding["evidence"]["configured_remote_asn"], 65099)
        self.assertEqual(finding["evidence"]["peer_local_asn"], 65002)
        self.assertEqual(run.status, "BLOCKED")

    def test_reverse_direction_mismatch_is_also_detected(self):
        self.peers(remote_2=65099)
        (finding,) = findings(validate(self.change, sources()), "BGP_REMOTE_AS_MISMATCH")
        self.assertEqual(finding["device"], "R2")

    def test_address_family_mismatch_detected(self):
        n1, n2 = self.peers()
        self.r2.set(f"routing.bgp.{self.b2['id']}.neighbors.{n2['id']}.activate_ipv4", False)
        self.r2.set(f"routing.bgp.{self.b2['id']}.neighbors.{n2['id']}.activate_ipv6", True)
        (finding,) = findings(validate(self.change, sources()), "BGP_AF_MISMATCH")
        self.assertTrue(finding["blocking"])

    def test_missing_reciprocal_neighbor_is_warning(self):
        self.r1.neighbor(self.b1, "192.0.2.1", 65002)
        run = validate(self.change, sources())
        (finding,) = findings(run, "BGP_PEER_NO_RECIPROCAL")
        self.assertFalse(finding["blocking"])

    def test_peer_device_without_bgp_is_warning_not_block(self):
        r3 = Dev(self.change, "R3"); e = r3.iface("Ethernet1"); r3.address(e, "192.0.2.5/31")
        self.r1.neighbor(self.b1, "192.0.2.5", 65003)
        run = validate(self.change, sources())
        self.assertIn("BGP_PEER_NO_RECIPROCAL", codes(run))
        self.assertNotIn("BGP_REMOTE_AS_MISMATCH", codes(run))

    def test_unresolved_external_peer_is_warning_not_internal_mismatch(self):
        self.r1.neighbor(self.b1, "203.0.113.9", 64500)
        run = validate(self.change, sources())
        (finding,) = findings(run, "BGP_PEER_UNRESOLVED")
        self.assertEqual((finding["severity"], finding["blocking"]), ("WARNING", False))
        self.assertEqual(finding["evidence"]["session_type"], "EBGP")
        self.assertNotIn("BGP_REMOTE_AS_MISMATCH", codes(run))
        self.assertEqual(run.status, "PASS_WITH_WARNINGS")

    def test_peer_known_only_to_netbox_is_resolved_without_asn_checks(self):
        self.r1.neighbor(self.b1, "203.0.113.9", 64500)
        nb = netbox_data(ip_addresses=[nb_ip("203.0.113.9/30", "ISP1", "eth0")])
        run = validate(self.change, sources(netbox=nb))
        self.assertNotIn("BGP_PEER_UNRESOLVED", codes(run))
        (fact,) = [f for f in run.derived_facts if f["type"] == "BGP_PEER_RESOLVED"]
        self.assertEqual(fact["scope"], "NETBOX")

    def test_advertised_prefix_without_evidence_warns(self):
        self.r1.bgp_network(self.b1, "198.51.100.0/24")
        (finding,) = findings(validate(self.change, sources()), "BGP_NETWORK_NO_EVIDENCE")
        self.assertFalse(finding["blocking"])

    def test_advertised_connected_prefix_has_evidence(self):
        self.r1.bgp_network(self.b1, "192.0.2.0/31")
        self.assertNotIn("BGP_NETWORK_NO_EVIDENCE", codes(validate(self.change, sources())))

    def test_advertised_static_route_prefix_has_evidence(self):
        self.r1.static_route("198.51.100.0/24", next_hop="192.0.2.1")
        self.r1.bgp_network(self.b1, "198.51.100.0/24")
        self.assertNotIn("BGP_NETWORK_NO_EVIDENCE", codes(validate(self.change, sources())))

    def test_ipv6_network_with_only_ipv4_neighbors_warns(self):
        self.peers()
        self.r1.bgp_network(self.b1, "2001:db8:77::/64", family="IPV6")
        self.assertTrue(any(f["severity"] == "WARNING" for f in findings(validate(self.change, sources()), "BGP_AF_MISMATCH")))


class StaticRouteTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.change = new_change()
        cls.r1 = Dev(cls.change, "R1")
        cls.a = cls.r1.iface("Ethernet1"); cls.r1.address(cls.a, "192.0.2.0/31")

    def test_next_hop_in_connected_network_resolves(self):
        self.r1.static_route("10.9.0.0/24", next_hop="192.0.2.1")
        run = validate(self.change)
        self.assertNotIn("ROUTE_NEXT_HOP_UNRESOLVED", codes(run))
        self.assertTrue([f for f in run.derived_facts if f["type"] == "STATIC_ROUTE_NEXT_HOP"])

    def test_next_hop_not_connected_is_warning(self):
        self.r1.static_route("10.9.0.0/24", next_hop="172.16.9.9")
        run = validate(self.change)
        (finding,) = findings(run, "ROUTE_NEXT_HOP_UNRESOLVED")
        self.assertFalse(finding["blocking"])
        self.assertEqual(run.status, "PASS_WITH_WARNINGS")

    def test_next_hop_reachable_through_netbox_connected_network(self):
        self.r1.static_route("10.9.0.0/24", next_hop="172.16.9.9")
        nb = netbox_data(ip_addresses=[nb_ip("172.16.9.1/24", "R1", "Ethernet7")])
        self.assertNotIn("ROUTE_NEXT_HOP_UNRESOLVED", codes(validate(self.change, make_sources(netbox=nb))))

    def test_next_hop_equal_to_own_address_is_blocked(self):
        self.r1.static_route("10.9.0.0/24", next_hop="192.0.2.1")
        self.r1.address(self.r1.iface("Ethernet2"), "192.0.2.1/24")
        self.assertTrue(findings(validate(self.change), "ROUTE_NEXT_HOP_SELF")[0]["blocking"])

    def test_family_mismatch_defended_against_persisted_data(self):
        route = self.r1.static_route("10.9.0.0/24", next_hop="192.0.2.1")
        self.r1.force(f"routing.static_routes.{route['id']}.destination", "2001:db8::/64")
        self.assertTrue(findings(validate(self.change), "ROUTE_FAMILY_MISMATCH")[0]["blocking"])

    def test_exit_interface_layer2_is_implausible(self):
        acc = self.r1.iface("Ethernet4", kind="ACCESS", access_vlan=10)
        self.r1.static_route("10.9.0.0/24", interface=acc)
        self.assertIn("ROUTE_EXIT_INTERFACE_IMPLAUSIBLE", codes(validate(self.change)))

    def test_no_routing_simulation_claim(self):
        run = validate(self.change)
        self.assertTrue(any("not simulated" in text for text in run.report["limitations"]))


class RipAndOtherProtocolTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.change = new_change()
        cls.r1, cls.r2 = Dev(cls.change, "R1"), Dev(cls.change, "R2")
        cls.a, cls.z = cls.r1.iface("Ethernet1"), cls.r2.iface("Ethernet1")

    def test_rip_family_agreement(self):
        r1, r2 = self.r1.rip("IPV4"), self.r2.rip("IPV4")
        self.r1.bind("rip", r1, self.a); self.r2.bind("rip", r2, self.z)
        self.assertNotIn("RIP_FAMILY_MISMATCH", codes(validate(self.change, sources())))

    def test_rip_family_mismatch_warns(self):
        r1 = self.r1.rip("IPV4")
        self.r1.bind("rip", r1, self.a)
        # RIPng is not selectable on cEOS; preserve it the way real data arises (platform switch is not needed --
        # inject the persisted instance directly).
        def inject(sections):
            sections["routing"]["rip"]["rip_ng"] = {"id": "rip_ng", "sequence": 9, "address_family": "IPV6", "enabled": True,
                                                    "interfaces": {"bind_ng": {"id": "bind_ng", "sequence": 1, "interface_id": self.z["id"], "passive": False}}}
        revision = self.r2.refresh(); sections = copy.deepcopy(revision.sections)
        sections.setdefault("routing", {}).setdefault("rip", {})
        inject(sections); revision.sections = sections; revision.save(update_fields=["sections"])
        self.assertIn("RIP_FAMILY_MISMATCH", codes(validate(self.change, sources())))

    def test_preserved_isis_is_not_capability_blocked_on_ceos(self):
        revision = self.r1.refresh(); sections = copy.deepcopy(revision.sections)
        sections.setdefault("routing", {}).setdefault("isis", {})["isis_x"] = {
            "id": "isis_x", "sequence": 1, "net": "49.0001.0000.0000.0001.00", "level": "LEVEL_2",
            "address_family_ipv4": True, "address_family_ipv6": False, "interfaces": {}}
        revision.sections = sections; revision.save(update_fields=["sections"])
        run = validate(self.change, sources())
        blocked = [f for f in run.report["findings"] if f["code"] in ("PLATFORM_FEATURE_NOT_IMPLEMENTED", "PLATFORM_FEATURE_UNSUPPORTED")
                   and f["object_type"] == "routing_isis"]
        self.assertEqual(blocked, [])  # cEOS renders and executes IS-IS; FRR stays refused (test_routing_service)

    def test_preserved_eigrp_is_capability_blocked(self):
        revision = self.r1.refresh(); sections = copy.deepcopy(revision.sections)
        sections.setdefault("routing", {}).setdefault("eigrp", {})["eigrp_x"] = {
            "id": "eigrp_x", "sequence": 1, "asn": 100, "router_id": "", "address_family": "IPV4", "interfaces": {}}
        revision.sections = sections; revision.save(update_fields=["sections"])
        run = validate(self.change, sources())
        self.assertTrue([f for f in run.report["findings"] if f["object_type"] == "routing_eigrp" and f["blocking"]])
