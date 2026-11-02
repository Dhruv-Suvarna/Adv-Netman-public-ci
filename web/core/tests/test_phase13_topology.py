from __future__ import annotations

from django.test import TestCase

from core.tests.helpers.validation import (
    Dev, codes, findings, link, make_sources, nb_ip, netbox_data, new_change, topology_data, validate,
)

L12 = link("R1", "Ethernet1", "R2", "Ethernet1")
L_S = link("S1", "Ethernet2", "S2", "Ethernet2")


def sources(links, **kw):
    return make_sources(topology=topology_data(links=links, nodes=("R1", "R2", "S1", "S2")), **kw)


class P2PAddressingTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.change = new_change()
        cls.r1, cls.r2 = Dev(cls.change, "R1"), Dev(cls.change, "R2")
        cls.a, cls.z = cls.r1.iface("Ethernet1"), cls.r2.iface("Ethernet1")

    def run_pair(self, a_cidrs, z_cidrs):
        for cidr in a_cidrs:
            self.r1.address(self.a, cidr)
        for cidr in z_cidrs:
            self.r2.address(self.z, cidr)
        return validate(self.change, sources([L12]))

    def test_valid_slash31_pair_accepted(self):
        run = self.run_pair(["192.0.2.0/31"], ["192.0.2.1/31"])
        self.assertNotIn("LINK_PREFIX_MISMATCH", codes(run))
        self.assertEqual(run.status, "PASS")

    def test_slash31_wrong_subnet_blocked(self):
        run = self.run_pair(["192.0.2.0/31"], ["192.0.3.1/31"])
        (finding,) = findings(run, "LINK_PREFIX_MISMATCH")
        self.assertTrue(finding["blocking"])
        self.assertEqual(finding["evidence"]["evidence_kind"], "candidate_vs_candidate")
        self.assertEqual(run.status, "BLOCKED")

    def test_slash31_with_different_31_blocks_even_in_same_24(self):
        run = self.run_pair(["192.0.2.0/31"], ["192.0.2.3/31"])
        self.assertIn("LINK_PREFIX_MISMATCH", codes(run))

    def test_valid_slash127_pair_accepted(self):
        run = self.run_pair(["2001:db8:1::/127"], ["2001:db8:1::1/127"])
        self.assertNotIn("LINK_PREFIX_MISMATCH", codes(run))

    def test_slash127_mismatch_blocked(self):
        run = self.run_pair(["2001:db8:1::/127"], ["2001:db8:2::1/127"])
        self.assertTrue(findings(run, "LINK_PREFIX_MISMATCH")[0]["blocking"])

    def test_ipv4_only_link_allowed(self):
        run = self.run_pair(["192.0.2.0/31"], ["192.0.2.1/31"])
        self.assertEqual(run.status, "PASS")

    def test_ipv6_only_link_allowed(self):
        self.assertEqual(self.run_pair(["2001:db8:1::/127"], ["2001:db8:1::1/127"]).status, "PASS")

    def test_one_end_dual_stack_other_ipv4_only_is_allowed(self):
        run = self.run_pair(["192.0.2.0/31", "2001:db8:1::/127"], ["192.0.2.1/31"])
        self.assertNotIn("LINK_PREFIX_MISMATCH", codes(run))

    def test_larger_than_31_prefix_is_legitimate(self):
        run = self.run_pair(["10.9.0.1/24"], ["10.9.0.2/24"])
        self.assertEqual(run.status, "PASS")

    def test_mask_mismatch_on_same_network_is_flagged(self):
        run = self.run_pair(["10.9.0.1/24"], ["10.9.0.2/25"])
        self.assertIn("LINK_PREFIX_MISMATCH", codes(run))

    def test_far_end_outside_change_is_compared_with_netbox_as_warning_only(self):
        change = new_change()
        r1 = Dev(change, "R1"); a = r1.iface("Ethernet1"); r1.address(a, "192.0.2.0/31")
        nb = netbox_data(ip_addresses=[nb_ip("192.0.9.1/31", "R2", "Ethernet1")])
        run = validate(change, sources([L12], netbox=nb))
        (finding,) = findings(run, "LINK_PREFIX_MISMATCH")
        self.assertFalse(finding["blocking"])
        self.assertEqual(finding["evidence"]["evidence_kind"], "candidate_vs_netbox")

    def test_unlinked_devices_are_not_compared(self):
        run = validate(self.change, sources([]))
        self.assertNotIn("LINK_PREFIX_MISMATCH", codes(run))


class SwitchLinkTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.change = new_change()
        cls.s1, cls.s2 = Dev(cls.change, "S1"), Dev(cls.change, "S2")

    def run_l(self):
        return validate(self.change, sources([L_S]))

    def test_access_vlan_match_accepted(self):
        self.s1.iface("Ethernet2", kind="ACCESS", access_vlan=10)
        self.s2.iface("Ethernet2", kind="ACCESS", access_vlan=10)
        run = self.run_l()
        self.assertNotIn("LINK_ACCESS_VLAN_MISMATCH", codes(run))
        self.assertEqual(run.status, "PASS")

    def test_access_vlan_mismatch_blocked(self):
        self.s1.iface("Ethernet2", kind="ACCESS", access_vlan=10)
        self.s2.iface("Ethernet2", kind="ACCESS", access_vlan=20)
        run = self.run_l()
        self.assertTrue(findings(run, "LINK_ACCESS_VLAN_MISMATCH")[0]["blocking"])
        self.assertEqual(run.status, "BLOCKED")

    def test_access_one_end_unset_is_only_a_warning(self):
        self.s1.iface("Ethernet2", kind="ACCESS", access_vlan=10)
        self.s2.iface("Ethernet2", kind="ACCESS")
        (finding,) = findings(self.run_l(), "LINK_ACCESS_VLAN_MISMATCH")
        self.assertFalse(finding["blocking"])

    def test_trunk_required_vlan_carried_is_accepted(self):
        for dev in (self.s1, self.s2):
            dev.iface("Ethernet2", kind="TRUNK", trunk_allowed_vlans="10,20")
            dev.iface("Vlan10", kind="SVI", vlan_id=10)
        self.assertNotIn("LINK_TRUNK_VLAN_MISSING", codes(self.run_l()))

    def test_required_vlan_missing_from_one_trunk_end_is_detected(self):
        self.s1.iface("Ethernet2", kind="TRUNK", trunk_allowed_vlans="10,20")
        self.s2.iface("Ethernet2", kind="TRUNK", trunk_allowed_vlans="20")
        for dev in (self.s1, self.s2):
            dev.iface("Vlan10", kind="SVI", vlan_id=10)
        (finding,) = findings(self.run_l(), "LINK_TRUNK_VLAN_MISSING")
        self.assertEqual(finding["evidence"]["vlan"], 10)
        self.assertFalse(finding["blocking"])  # concrete evidence of use, but not proof the trunk must carry it

    def test_disjoint_allowed_vlans_are_blocked(self):
        self.s1.iface("Ethernet2", kind="TRUNK", trunk_allowed_vlans="10")
        self.s2.iface("Ethernet2", kind="TRUNK", trunk_allowed_vlans="20")
        self.assertTrue(findings(self.run_l(), "LINK_TRUNK_VLAN_MISSING")[0]["blocking"])

    def test_one_side_carrying_extra_vlans_is_not_demanded_identical(self):
        self.s1.iface("Ethernet2", kind="TRUNK", trunk_allowed_vlans="10,20,30")
        self.s2.iface("Ethernet2", kind="TRUNK", trunk_allowed_vlans="10,20")
        self.assertNotIn("LINK_TRUNK_VLAN_MISSING", codes(self.run_l()))

    def test_native_vlan_mismatch_detected(self):
        self.s1.iface("Ethernet2", kind="TRUNK", native_vlan=10)
        self.s2.iface("Ethernet2", kind="TRUNK", native_vlan=20)
        self.assertTrue(findings(self.run_l(), "LINK_NATIVE_VLAN_MISMATCH")[0]["blocking"])

    def test_default_native_equals_explicit_native_1(self):
        self.s1.iface("Ethernet2", kind="TRUNK", native_vlan=1)
        self.s2.iface("Ethernet2", kind="TRUNK")
        self.assertNotIn("LINK_NATIVE_VLAN_MISMATCH", codes(self.run_l()))

    def test_access_to_trunk_provably_compatible_is_silent(self):
        self.s1.iface("Ethernet2", kind="ACCESS", access_vlan=10)
        self.s2.iface("Ethernet2", kind="TRUNK", native_vlan=10)
        self.assertNotIn("LINK_MODE_MISMATCH", codes(self.run_l()))

    def test_access_to_trunk_ambiguous_is_warning_not_block(self):
        self.s1.iface("Ethernet2", kind="ACCESS", access_vlan=10)
        self.s2.iface("Ethernet2", kind="TRUNK", native_vlan=20)
        (finding,) = findings(self.run_l(), "LINK_MODE_MISMATCH")
        self.assertEqual((finding["severity"], finding["blocking"]), ("WARNING", False))

    def test_mtu_mismatch_is_a_warning(self):
        self.s1.iface("Ethernet2", kind="TRUNK", mtu=9000)
        self.s2.iface("Ethernet2", kind="TRUNK", mtu=1500)
        run = self.run_l()
        (finding,) = findings(run, "LINK_MTU_MISMATCH")
        self.assertEqual((finding["severity"], finding["blocking"]), ("WARNING", False))
        self.assertEqual(run.status, "PASS_WITH_WARNINGS")

    def test_matching_mtu_is_silent(self):
        self.s1.iface("Ethernet2", kind="TRUNK", mtu=9000)
        self.s2.iface("Ethernet2", kind="TRUNK", mtu=9000)
        self.assertNotIn("LINK_MTU_MISMATCH", codes(self.run_l()))

    def test_subinterface_tag_not_allowed_on_trunk_is_blocked(self):
        r1 = Dev(self.change, "R1")
        parent = r1.iface("Ethernet1")
        r1.iface("Ethernet1.30", kind="SUBINTERFACE", parent_id=parent["id"], encapsulation_vlan=30)
        self.s2.iface("Ethernet1", kind="TRUNK", trunk_allowed_vlans="10,20")
        run = validate(self.change, sources([link("R1", "Ethernet1", "S2", "Ethernet1")]))
        self.assertTrue(any(f["blocking"] for f in findings(run, "LINK_TRUNK_VLAN_MISSING")))

    def test_routed_port_without_subinterfaces_facing_trunk_warns(self):
        r1 = Dev(self.change, "R1"); r1.iface("Ethernet1")
        self.s2.iface("Ethernet1", kind="TRUNK")
        run = validate(self.change, sources([link("R1", "Ethernet1", "S2", "Ethernet1")]))
        self.assertIn("LINK_MODE_MISMATCH", codes(run))


class InterfaceReferenceAndSourceTests(TestCase):
    def test_missing_interface_reference_blocks(self):
        change = new_change()
        r1 = Dev(change, "R1"); e1 = r1.iface("Ethernet1")
        route = r1.static_route("10.9.0.0/24", interface=e1)
        r1.force(f"routing.static_routes.{route['id']}.next_hop_interface_id", "if_deadbeefdeadbeef")
        run = validate(change)
        (finding,) = findings(run, "DEPENDENCY_MISSING")
        self.assertTrue(finding["blocking"])
        self.assertEqual(run.status, "BLOCKED")

    def test_unknown_vlan_id_is_flagged_against_netbox(self):
        change = new_change()
        s1 = Dev(change, "S1"); s1.iface("Ethernet3", kind="ACCESS", access_vlan=777)
        self.assertIn("VLAN_NOT_IN_NETBOX", codes(validate(change)))

    def test_known_vlan_is_not_flagged(self):
        change = new_change()
        s1 = Dev(change, "S1"); s1.iface("Ethernet3", kind="ACCESS", access_vlan=10)
        self.assertNotIn("VLAN_NOT_IN_NETBOX", codes(validate(change)))

    def test_device_missing_from_topology_is_reported(self):
        change = new_change()
        Dev(change, "R1").iface("Ethernet1")
        run = validate(change, make_sources(topology=topology_data(nodes=("R2",))))
        (finding,) = findings(run, "TOPOLOGY_DEVICE_UNKNOWN")
        self.assertEqual(finding["severity"], "WARNING")

    def test_new_device_missing_from_topology_is_only_info(self):
        from core import models
        change = new_change()
        Dev(change, "R9", target_type=models.DeviceIntentTargetType.NEW_DEVICE).iface("Ethernet1")
        run = validate(change, make_sources(topology=topology_data(nodes=("R2",))))
        self.assertEqual(findings(run, "TOPOLOGY_DEVICE_UNKNOWN")[0]["severity"], "INFO")

    def test_topology_unavailable_does_not_guess_adjacency_and_is_incomplete(self):
        change = new_change()
        r1, r2 = Dev(change, "R1"), Dev(change, "R2")
        r1.address(r1.iface("Ethernet1"), "192.0.2.0/31")
        r2.address(r2.iface("Ethernet1"), "192.0.3.1/31")   # would mismatch IF adjacency were guessed
        run = validate(change, make_sources(topology=None))
        self.assertIn("SOURCE_TOPOLOGY_UNAVAILABLE", codes(run))
        self.assertNotIn("LINK_PREFIX_MISMATCH", codes(run))
        self.assertEqual(run.status, "INCOMPLETE")
        self.assertIn("addressing", run.summary["validators_completed"])
