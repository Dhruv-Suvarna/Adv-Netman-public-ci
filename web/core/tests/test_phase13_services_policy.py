from __future__ import annotations

from unittest import mock

from django.test import TestCase

from core import models
from core.services import platform_drivers as pd
from core.services.platform_drivers import CapabilityStatus, PlatformCapability, ServicePolicyFeature
from core.tests.helpers.validation import (
    Dev, codes, findings, make_sources, nb_ip, nb_prefix, netbox_data, new_change, topology_data, validate,
)

MAC_A, MAC_B = "00:1c:73:00:00:99", "00:1c:73:00:00:98"


class FhrpTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.change = new_change()
        cls.s1, cls.s2 = Dev(cls.change, "S1"), Dev(cls.change, "S2")
        cls.v1 = cls.s1.iface("Vlan10", kind="SVI", vlan_id=10)
        cls.v2 = cls.s2.iface("Vlan10", kind="SVI", vlan_id=10)

    def fhrp_codes(self, run):
        return [c for c in codes(run) if c.startswith("FHRP_")]

    def test_matching_varp_group_and_vip_accepted_without_duplicate_ip_false_positive(self):
        self.s1.fhrp(self.v1, vips=["192.168.10.1"], virtual_mac=MAC_A)
        self.s2.fhrp(self.v2, vips=["192.168.10.1"], virtual_mac=MAC_A)
        run = validate(self.change)
        self.assertEqual(self.fhrp_codes(run), [])
        self.assertNotIn("IP_DUPLICATE", codes(run))
        (domain,) = [f for f in run.derived_facts if f["type"] == "FHRP_DOMAIN"]
        self.assertEqual(domain["devices"], ["S1", "S2"])
        self.assertEqual(run.status, "PASS")

    def test_vip_set_mismatch_detected(self):
        self.s1.fhrp(self.v1, vips=["192.168.10.1"])
        self.s2.fhrp(self.v2, vips=["192.168.10.254"])
        (finding,) = findings(validate(self.change), "FHRP_GROUP_MISMATCH")
        self.assertTrue(finding["blocking"])
        self.assertEqual(sorted(finding["evidence"]["virtual_ips_by_device"]), ["S1", "S2"])

    def test_shared_domain_virtual_mac_mismatch_detected(self):
        self.s1.fhrp(self.v1, vips=["192.168.10.1"], virtual_mac=MAC_A)
        self.s2.fhrp(self.v2, vips=["192.168.10.1"], virtual_mac=MAC_B)
        self.assertTrue(findings(validate(self.change), "FHRP_VIRTUAL_MAC_MISMATCH")[0]["blocking"])

    def test_mac_set_on_only_one_peer_is_warning(self):
        self.s1.fhrp(self.v1, vips=["192.168.10.1"], virtual_mac=MAC_A)
        self.s2.fhrp(self.v2, vips=["192.168.10.1"])
        (finding,) = findings(validate(self.change), "FHRP_VIRTUAL_MAC_MISMATCH")
        self.assertFalse(finding["blocking"])

    def test_one_global_varp_mac_per_device(self):
        v20 = self.s1.iface("Vlan20", kind="SVI", vlan_id=20)
        self.s1.fhrp(self.v1, vips=["192.168.10.1"], virtual_mac=MAC_A)
        self.s1.fhrp(v20, vips=["192.168.20.1"], virtual_mac=MAC_B)
        self.assertTrue(any(f["device"] == "S1" and f["blocking"] for f in findings(validate(self.change), "FHRP_VIRTUAL_MAC_MISMATCH")))

    def test_same_vip_in_unrelated_domains_is_a_conflict(self):
        v20 = self.s1.iface("Vlan20", kind="SVI", vlan_id=20)
        self.s1.fhrp(self.v1, vips=["192.168.10.1"])
        self.s1.fhrp(v20, vips=["192.168.10.1"])
        self.assertTrue(findings(validate(self.change), "FHRP_VIP_CONFLICT")[0]["blocking"])

    def test_vip_equal_to_ordinary_interface_address_blocks(self):
        self.s1.fhrp(self.v1, vips=["192.168.10.1"])
        r1 = Dev(self.change, "R1"); r1.address(r1.iface("Ethernet1"), "192.168.10.1/24")
        run = validate(self.change)
        (finding,) = findings(run, "FHRP_VIP_CONFLICT")
        self.assertTrue(finding["blocking"])
        self.assertEqual(finding["related_devices"], ["R1"])
        self.assertEqual(run.status, "BLOCKED")

    def test_vip_outside_interface_subnet_warns(self):
        self.s1.address(self.v1, "192.168.10.11/24")
        self.s1.fhrp(self.v1, vips=["192.168.77.1"])
        self.assertIn("FHRP_VIP_OFF_SUBNET", codes(validate(self.change)))

    def test_vip_matching_netbox_shared_role_record_is_accepted(self):
        self.s1.fhrp(self.v1, vips=["192.168.10.1"])
        nb = netbox_data(ip_addresses=[nb_ip("192.168.10.1/24", None, None, role="vrrp")])
        self.assertNotIn("IP_NETBOX_COLLISION", codes(validate(self.change, make_sources(netbox=nb))))

    def test_vip_equal_to_netbox_ordinary_assignment_collides(self):
        self.s1.fhrp(self.v1, vips=["192.168.10.1"])
        nb = netbox_data(ip_addresses=[nb_ip("192.168.10.1/24", "R9", "Ethernet1")])
        self.assertTrue(findings(validate(self.change, make_sources(netbox=nb)), "IP_NETBOX_COLLISION")[0]["blocking"])

    def test_vip_inside_dynamic_pool_conflicts(self):
        self.s1.fhrp(self.v1, vips=["192.168.10.120"])
        nb = netbox_data(dhcp_ranges=[{"start": "192.168.10.100", "end": "192.168.10.179", "family": 4, "server": "primary"}])
        self.assertIn("IP_DHCP_POOL_CONFLICT", codes(validate(self.change, make_sources(netbox=nb))))

    def test_duplicate_priority_treated_as_documented_warning(self):
        def inject(sections):
            sections["fhrp"] = {"instances": {}}
            for i, dev_iface in enumerate((self.v1, self.v2)):
                pass
        for dev, iface, key in ((self.s1, self.v1, "h1"), (self.s2, self.v2, "h2")):
            dev.inject(lambda s, iface=iface, key=key: s.setdefault("fhrp", {"instances": {}})["instances"].__setitem__(
                key, {"id": key, "sequence": 1, "protocol": "HSRP", "interface_id": iface["id"], "address_family": "IPV4",
                      "group_id": 5, "priority": 100, "preempt": False, "preempt_delay": None, "hello_timer": None,
                      "hold_timer": None, "virtual_mac": "", "auth_secret_ref": "", "description": "",
                      "virtual_ips": {"v": {"id": "v", "sequence": 1, "address": "192.168.10.1"}}}))
        run = validate(self.change)
        (finding,) = findings(run, "FHRP_PRIORITY_DUPLICATE")
        self.assertEqual((finding["severity"], finding["blocking"]), ("WARNING", False))
        self.assertTrue(any(f["code"].startswith("PLATFORM_FEATURE") for f in run.report["findings"]))  # HSRP is not renderable on cEOS

    def test_hsrp_group_id_mismatch_in_one_domain_blocks(self):
        for dev, iface, key, group in ((self.s1, self.v1, "h1", 5), (self.s2, self.v2, "h2", 6)):
            dev.inject(lambda s, iface=iface, key=key, group=group: s.setdefault("fhrp", {"instances": {}})["instances"].__setitem__(
                key, {"id": key, "sequence": 1, "protocol": "HSRP", "interface_id": iface["id"], "address_family": "IPV4",
                      "group_id": group, "priority": 100 + group, "preempt": False, "preempt_delay": None, "hello_timer": None,
                      "hold_timer": None, "virtual_mac": "", "auth_secret_ref": "", "description": "",
                      "virtual_ips": {"v": {"id": "v", "sequence": 1, "address": "192.168.10.1"}}}))
        self.assertTrue(findings(validate(self.change), "FHRP_GROUP_MISMATCH")[0]["blocking"])

    def test_varp_priority_is_not_demanded_or_compared(self):
        self.s1.fhrp(self.v1, vips=["192.168.10.1"], priority=100)
        self.s2.fhrp(self.v2, vips=["192.168.10.1"], priority=100)
        self.assertNotIn("FHRP_PRIORITY_DUPLICATE", codes(validate(self.change)))


class NatTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.change = new_change()
        cls.r3 = Dev(cls.change, "R3", platform=models.Platform.UBUNTU_FRR)
        cls.inside, cls.outside = cls.r3.iface("eth1"), cls.r3.iface("eth2")

    def test_valid_pat_rule_is_clean_and_role_note_is_informational(self):
        self.r3.nat_rule(inside=self.inside, outside=self.outside, source="10.0.0.0/8")
        run = validate(self.change)
        self.assertEqual(run.status, "PASS")
        self.assertEqual(findings(run, "NAT_ROLE_UNVERIFIED")[0]["severity"], "INFO")

    def test_missing_nat_interface_dependency_blocks(self):
        rule = self.r3.nat_rule(inside=self.inside, outside=self.outside, source="10.0.0.0/8")
        self.r3.force(f"nat.rules.{rule['id']}.outside_interface_id", "if_0000000000000000")
        self.assertTrue(findings(validate(self.change), "DEPENDENCY_MISSING")[0]["blocking"])

    def test_missing_nat_pool_dependency_blocks(self):
        rule = self.r3.nat_rule(inside=self.inside, outside=self.outside, source="10.0.0.0/8")
        self.r3.force(f"nat.rules.{rule['id']}.pool_id", "pool_0000000000000000")
        self.assertTrue(findings(validate(self.change), "DEPENDENCY_MISSING")[0]["blocking"])

    def test_dynamic_rule_without_pool_blocks(self):
        rule = self.r3.nat_rule(inside=self.inside, outside=self.outside, source="10.0.0.0/8")
        self.r3.force(f"nat.rules.{rule['id']}.mode", "DYNAMIC")
        self.assertTrue([f for f in findings(validate(self.change), "DEPENDENCY_MISSING") if f["object_type"] == "nat_rule"])

    def test_incompatible_pool_family_detected(self):
        def inject(sections):
            sections["nat"]["pools"]["pool_v6"] = {"id": "pool_v6", "sequence": 1, "name": "P6", "family": "NAT66",
                                                   "start_address": "2001:db8::1", "end_address": "2001:db8::9", "prefix_length": None, "description": ""}
        self.r3.inject(inject)
        rule = self.r3.nat_rule(inside=self.inside, outside=self.outside, source="10.0.0.0/8")
        self.r3.force(f"nat.rules.{rule['id']}.pool_id", "pool_v6")
        self.assertTrue([f for f in findings(validate(self.change), "NAT_POOL_CONFLICT") if "family" in f["message"]])

    def test_pool_holding_wrong_family_addresses_conflicts(self):
        def inject(sections):
            sections["nat"]["pools"]["pool_x"] = {"id": "pool_x", "sequence": 1, "name": "PX", "family": "NAT44",
                                                  "start_address": "2001:db8::1", "end_address": "2001:db8::9", "prefix_length": None, "description": ""}
        self.r3.inject(inject)
        self.assertTrue(findings(validate(self.change), "NAT_POOL_CONFLICT")[0]["blocking"])

    def test_same_interface_inside_and_outside_is_role_conflict(self):
        self.r3.nat_rule(inside=self.inside, outside=self.inside, source="10.0.0.0/8")
        self.assertTrue(findings(validate(self.change), "NAT_INTERFACE_ROLE_CONFLICT")[0]["blocking"])

    def test_wan_inside_and_lan_outside_is_a_warning_role_conflict(self):
        self.r3.set(f"interfaces.{self.inside['id']}.wan.state", "ENABLED")
        self.r3.nat_rule(inside=self.inside, outside=self.outside, source="10.0.0.0/8")
        (finding,) = findings(validate(self.change), "NAT_INTERFACE_ROLE_CONFLICT")
        self.assertFalse(finding["blocking"])

    def test_nat44_source_of_wrong_family_is_flagged(self):
        rule = self.r3.nat_rule(inside=self.inside, outside=self.outside, source="10.0.0.0/8")
        self.r3.force(f"nat.rules.{rule['id']}.original_source", "2001:db8::/64")
        self.assertTrue(findings(validate(self.change), "NAT_FAMILY_MISMATCH")[0]["blocking"])

    def test_overlapping_pools_conflict(self):
        def inject(sections):
            for key, (start, end) in {"p1": ("203.0.113.1", "203.0.113.20"), "p2": ("203.0.113.10", "203.0.113.30")}.items():
                sections["nat"]["pools"][key] = {"id": key, "sequence": 1, "name": key, "family": "NAT44", "start_address": start,
                                                 "end_address": end, "prefix_length": None, "description": ""}
        self.r3.inject(inject)
        self.assertTrue([f for f in findings(validate(self.change), "NAT_POOL_CONFLICT") if "overlap" in f["message"]])

    def test_pool_containing_interface_address_conflicts(self):
        self.r3.address(self.outside, "203.0.113.5/24")
        def inject(sections):
            sections["nat"]["pools"]["p1"] = {"id": "p1", "sequence": 1, "name": "p1", "family": "NAT44", "start_address": "203.0.113.1",
                                              "end_address": "203.0.113.20", "prefix_length": None, "description": ""}
        self.r3.inject(inject)
        self.assertTrue([f for f in findings(validate(self.change), "NAT_POOL_CONFLICT") if "interface address" in f["message"]])

    def test_pool_containing_management_service_address_conflicts(self):
        def inject(sections):
            sections["nat"]["pools"]["p1"] = {"id": "p1", "sequence": 1, "name": "p1", "family": "NAT44", "start_address": "192.168.200.90",
                                              "end_address": "192.168.200.110", "prefix_length": None, "description": ""}
        self.r3.inject(inject)
        self.assertTrue([f for f in findings(validate(self.change), "NAT_POOL_CONFLICT") if "management" in f["message"]])

    def test_unsupported_nat_is_blocked_via_capability(self):
        self.r3.nat_rule(inside=self.inside, outside=self.outside, source="10.0.0.0/8")
        self.r3.switch_platform(models.Platform.ARISTA_CEOS)
        self.assertTrue([f for f in findings(validate(self.change)) if f["code"].startswith("PLATFORM_FEATURE") and f["object_type"] == "nat_rule"])

    def test_no_nat_simulation_overclaim(self):
        self.r3.nat_rule(inside=self.inside, outside=self.outside, source="10.0.0.0/8")
        run = validate(self.change)
        self.assertTrue(any("not simulated" in t for t in run.report["limitations"]))
        message = findings(run, "NAT_ROLE_UNVERIFIED")[0]["message"]
        self.assertIn("no translation behavior is simulated", message)


class DhcpDnsTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.change = new_change()
        cls.s1 = Dev(cls.change, "S1")
        cls.svi = cls.s1.iface("Vlan10", kind="SVI", vlan_id=10)

    def test_relay_to_known_project_destination_is_accepted_and_recorded(self):
        self.s1.relay(self.svi, "192.168.200.100")
        run = validate(self.change)
        self.assertNotIn("DHCP_RELAY_UNRESOLVED", codes(run))
        (fact,) = [f for f in run.derived_facts if f["type"] == "DHCP_RELAY_DESTINATION"]
        self.assertIn("inventory.management", fact["known_as"])

    def test_relay_to_netbox_relay_target_is_known(self):
        self.s1.relay(self.svi, "10.99.0.5")
        nb = netbox_data(prefixes=[nb_prefix("192.168.10.0/24", 10, ["10.99.0.5"])])
        self.assertNotIn("DHCP_RELAY_UNRESOLVED", codes(validate(self.change, make_sources(netbox=nb))))

    def test_unknown_relay_destination_warns(self):
        self.s1.relay(self.svi, "203.0.113.50")
        run = validate(self.change)
        (finding,) = findings(run, "DHCP_RELAY_UNRESOLVED")
        self.assertEqual((finding["severity"], finding["blocking"]), ("WARNING", False))
        self.assertEqual(run.status, "PASS_WITH_WARNINGS")

    def test_relay_family_mismatch_blocks(self):
        relay = self.s1.relay(self.svi, "192.168.200.100")
        self.s1.force(f"services.dhcp.relays.{relay['id']}.destination", "2001:db8:200::100")
        self.assertTrue(findings(validate(self.change), "DHCP_RELAY_FAMILY_MISMATCH")[0]["blocking"])

    def test_vlan200_dynamic_delivery_is_prohibited(self):
        m = self.s1.iface("Vlan200", kind="SVI", vlan_id=200)
        def inject(sections):
            sections["services"]["dhcp"]["clients"]["dhcp_c"] = {"id": "dhcp_c", "sequence": 1, "family": "IPV4", "interface_id": m["id"], "description": ""}
        self.s1.inject(inject)
        self.assertIn("DHCP_VLAN200_FORBIDDEN", codes(validate(self.change)))

    def test_dns_override_blocks_via_capability_and_warns_on_unknown_resolver(self):
        def inject(sections):
            sections.setdefault("services", {}).setdefault("dns", {})
            sections["services"]["dns"].update({"mode": "OVERRIDE", "search_domains": {}, "domain_name": "",
                                               "resolvers": {"dns_a": {"id": "dns_a", "sequence": 1, "family": "IPV4", "address": "8.8.8.8"}}})
        self.s1.inject(inject)
        run = validate(self.change)
        blocked = [f for f in run.report["findings"] if f["object_type"] == "dns_override"]
        self.assertTrue(blocked and blocked[0]["blocking"])
        self.assertEqual(blocked[0]["code"], "PLATFORM_FEATURE_NOT_IMPLEMENTED")
        self.assertIn("DNS_RESOLVER_UNRESOLVED", codes(run))

    def test_no_live_dns_query_is_ever_made(self):
        def inject(sections):
            sections.setdefault("services", {}).setdefault("dns", {})
            sections["services"]["dns"].update({"mode": "OVERRIDE", "search_domains": {}, "domain_name": "example.invalid",
                                               "resolvers": {"dns_a": {"id": "dns_a", "sequence": 1, "family": "IPV4", "address": "8.8.8.8"}}})
        self.s1.inject(inject)
        boom = AssertionError("validation must not resolve names")
        with mock.patch("socket.getaddrinfo", side_effect=boom), mock.patch("socket.gethostbyname", side_effect=boom), \
                mock.patch("socket.socket", side_effect=boom):
            validate(self.change)

    def test_dhcp_pool_conflict_for_static_address(self):
        e = self.s1.iface("Ethernet1"); self.s1.address(e, "192.168.10.150/24")
        nb = netbox_data(dhcp_ranges=[{"start": "192.168.10.100", "end": "192.168.10.179", "family": 4, "server": "primary"}])
        self.assertIn("IP_DHCP_POOL_CONFLICT", codes(validate(self.change, make_sources(netbox=nb))))


class AclTests(TestCase):
    NMAS = "192.168.200.100"

    @classmethod
    def setUpTestData(cls):
        cls.change = new_change()
        cls.s1 = Dev(cls.change, "S1")
        cls.mgmt = cls.s1.iface("Vlan200", kind="SVI", vlan_id=200)
        cls.s1.address(cls.mgmt, "192.168.200.11/24")
        cls.acl = cls.s1.acl("MGMT-IN")

    def attach(self, direction="IN"):
        return self.s1.attach_acl(self.acl, self.mgmt, direction)

    def run_v(self):
        return validate(self.change)

    def test_first_match_earlier_deny_is_not_rescued_by_later_permit(self):
        self.s1.ace(self.acl, "DENY", "IP")
        self.s1.ace(self.acl, "PERMIT", "TCP", source_type="HOST", source_value=self.NMAS, destination_port="22")
        self.attach()
        run = self.run_v()
        denied = findings(run, "ACL_REQUIRED_FLOW_DENIED")
        self.assertTrue(denied and all(f["blocking"] for f in denied))
        self.assertEqual(run.status, "BLOCKED")
        self.assertEqual(denied[0]["evidence"]["matched_entry"]["action"], "DENY")

    def test_provable_required_flow_denial_blocks_with_flow_evidence(self):
        self.s1.ace(self.acl, "DENY", "TCP", destination_port="22")
        self.attach()
        flows = {f["evidence"]["flow"] for f in findings(self.run_v(), "ACL_REQUIRED_FLOW_DENIED")}
        self.assertIn("management-ssh-request", flows)

    def test_prior_matching_permit_prevents_a_false_deny(self):
        self.s1.ace(self.acl, "PERMIT", "IP", source_type="HOST", source_value=self.NMAS)
        self.s1.ace(self.acl, "DENY", "IP")
        self.attach()
        run = self.run_v()
        self.assertNotIn("ACL_REQUIRED_FLOW_DENIED", codes(run))
        self.assertNotIn("ACL_EFFECT_UNKNOWN", codes(run))
        self.assertEqual(run.status, "PASS")

    def test_later_deny_does_not_matter_after_definitive_permit(self):
        self.s1.ace(self.acl, "PERMIT", "IP")
        self.s1.ace(self.acl, "DENY", "IP", source_type="HOST", source_value=self.NMAS)
        self.attach()
        self.assertNotIn("ACL_REQUIRED_FLOW_DENIED", codes(self.run_v()))

    def test_no_matching_entry_is_unknown_warning_not_a_block(self):
        self.s1.ace(self.acl, "PERMIT", "TCP", source_type="PREFIX", source_value="10.0.0.0/8")
        self.attach()
        run = self.run_v()
        unknown = findings(run, "ACL_EFFECT_UNKNOWN")
        self.assertTrue(unknown)
        self.assertTrue(all(not f["blocking"] and f["severity"] == "WARNING" for f in unknown))
        self.assertNotIn("ACL_REQUIRED_FLOW_DENIED", codes(run))
        self.assertEqual(run.status, "PASS_WITH_WARNINGS")

    def test_uncertain_earlier_entry_that_could_flip_the_outcome_is_unknown(self):
        e1 = self.s1.iface("Ethernet1"); self.s1.address(e1, "192.0.2.0/31")
        o = self.s1.ospf(); self.s1.bind("ospf", o, e1)
        acl = self.s1.acl("OSPF-IN")
        self.s1.ace(acl, "DENY", "IP", source_type="HOST", source_value="192.0.2.1")   # peer unknown -> MAYBE
        self.s1.ace(acl, "PERMIT", "IP")
        self.s1.attach_acl(acl, e1)
        run = validate(self.change, make_sources(topology=topology_data(links=[], nodes=("S1", "S2"))))
        self.assertIn("ACL_EFFECT_UNKNOWN", codes(run))
        self.assertNotIn("ACL_REQUIRED_FLOW_DENIED", codes(run))

    def test_ospf_hello_explicitly_denied_blocks(self):
        e1 = self.s1.iface("Ethernet1"); self.s1.address(e1, "192.0.2.0/31")
        o = self.s1.ospf(); self.s1.bind("ospf", o, e1)
        acl = self.s1.acl("NO-OSPF"); self.s1.ace(acl, "DENY", "IP"); self.s1.attach_acl(acl, e1)
        denied = findings(validate(self.change), "ACL_REQUIRED_FLOW_DENIED")
        self.assertIn("ospf-hello-in", {f["evidence"]["flow"] for f in denied})

    def test_ospf_passive_binding_needs_no_hello_flow(self):
        e1 = self.s1.iface("Ethernet1"); self.s1.address(e1, "192.0.2.0/31")
        o = self.s1.ospf(); self.s1.bind("ospf", o, e1, passive=True)
        acl = self.s1.acl("NO-OSPF"); self.s1.ace(acl, "DENY", "IP"); self.s1.attach_acl(acl, e1)
        self.assertNotIn("ACL_REQUIRED_FLOW_DENIED", codes(validate(self.change)))

    def test_bgp_tcp179_denied_toward_candidate_peer_blocks(self):
        e1 = self.s1.iface("Ethernet1"); self.s1.address(e1, "192.0.2.0/31")
        b = self.s1.bgp(65001); self.s1.neighbor(b, "192.0.2.1", 65002)
        acl = self.s1.acl("NO-BGP"); self.s1.ace(acl, "DENY", "TCP", destination_port="179"); self.s1.attach_acl(acl, e1)
        flows = {f["evidence"]["flow"] for f in findings(validate(self.change), "ACL_REQUIRED_FLOW_DENIED")}
        self.assertIn("bgp-in-to-179", flows)

    def test_dhcp_relay_udp_denied_blocks(self):
        svi = self.s1.iface("Vlan10", kind="SVI", vlan_id=10)
        self.s1.relay(svi, "192.168.200.100")
        acl = self.s1.acl("NO-DHCP"); self.s1.ace(acl, "DENY", "UDP", destination_port="67"); self.s1.attach_acl(acl, svi)
        flows = {f["evidence"]["flow"] for f in findings(validate(self.change), "ACL_REQUIRED_FLOW_DENIED")}
        self.assertIn("dhcp-client-to-relay", flows)

    def test_shadowed_entry_is_flagged_as_contradictory(self):
        self.s1.ace(self.acl, "PERMIT", "IP")
        self.s1.ace(self.acl, "DENY", "TCP", destination_port="22")
        self.attach()
        (finding,) = findings(self.run_v(), "ACL_ENTRY_SHADOWED")
        self.assertTrue(finding["evidence"]["contradictory"])

    def test_two_acls_on_one_interface_direction_family_warn(self):
        other = self.s1.acl("OTHER")
        self.s1.ace(self.acl, "PERMIT", "IP"); self.s1.ace(other, "PERMIT", "IP")
        self.attach(); self.s1.attach_acl(other, self.mgmt)
        self.assertIn("ACL_DUPLICATE_ATTACHMENT", codes(self.run_v()))

    def test_acl_definition_dependency_is_resolved(self):
        self.s1.ace(self.acl, "PERMIT", "IP")
        attachment = self.attach()
        run = self.run_v()
        edges = [e for e in run.dependency_graph["edges"] if e["type"] == "DEFINE_BEFORE_ATTACH"]
        self.assertTrue(edges and all(e["status"] == "RESOLVED" for e in edges))
        self.assertNotIn("DEPENDENCY_MISSING", codes(run))

    def test_missing_acl_attachment_reference_blocks(self):
        attachment = self.attach()
        self.s1.force(f"security.attachments.{attachment['id']}.acl_id", "acl_0000000000000000")
        self.assertTrue(findings(self.run_v(), "DEPENDENCY_MISSING")[0]["blocking"])

    def test_evaluation_is_structured_and_never_parses_raw_cli(self):
        import ast, pathlib
        from core.services.validation import acl as acl_module
        tree = ast.parse(pathlib.Path(acl_module.__file__).read_text())
        imported = {a.name for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names}
        imported |= {n.module for n in ast.walk(tree) if isinstance(n, ast.ImportFrom) and n.module}
        self.assertFalse({"re", "shlex"} & imported)
        result = acl_module.evaluate(
            {"entries": {"a": {"id": "a", "sequence": 10, "action": "PERMIT", "protocol": "IP", "source_type": "ANY", "destination_type": "ANY"}}},
            {"proto": "TCP", "family": 4, "src": None, "dst": None, "sport": None, "dport": 22})
        self.assertEqual(result["verdict"], "PERMIT")

    def test_management_flow_needs_inventory_evidence(self):
        self.s1.ace(self.acl, "DENY", "IP")
        self.attach()
        run = validate(self.change, make_sources(inventory=None))
        self.assertNotIn("management-ssh-request", {f["evidence"].get("flow") for f in run.report["findings"]})


class PbrTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.change = new_change()
        cls.r1 = Dev(cls.change, "R1")
        cls.e1 = cls.r1.iface("Ethernet1")
        cls.r1.address(cls.e1, "192.0.2.0/31")

        def inject(sections):
            sections["policy"] = {"pbr": {
                "policies": {"pbr_p": {"id": "pbr_p", "sequence": 1, "name": "P", "family": "IPV4", "description": "", "sequences": {
                    "seq1": {"id": "seq1", "sequence": 10, "source_prefix": "", "destination_prefix": "", "protocol": "IP",
                             "next_hop": "172.16.99.1", "output_interface_id": "", "description": ""}}}},
                "attachments": {"att1": {"id": "att1", "sequence": 1, "policy_id": "pbr_p", "interface_id": cls.e1["id"], "direction": "IN"}}}}
        cls.r1.inject(inject)

    def test_unsupported_pbr_is_blocked_via_capability(self):
        run = validate(self.change)
        pbr = [f for f in run.report["findings"] if f["code"] == "PLATFORM_FEATURE_NOT_IMPLEMENTED" and f["object_type"].startswith("pbr")]
        self.assertTrue(pbr and all(f["blocking"] for f in pbr))
        self.assertEqual(run.status, "BLOCKED")

    def test_reference_integrity_is_still_checked(self):
        self.r1.force("policy.pbr.attachments.att1.interface_id", "if_0000000000000000")
        self.assertIn("DEPENDENCY_MISSING", codes(validate(self.change)))
        self.r1.force("policy.pbr.attachments.att1.policy_id", "pbr_gone")
        self.assertGreaterEqual(len(findings(validate(self.change), "DEPENDENCY_MISSING")), 2)

    def test_no_reachability_simulation_for_an_undeployable_feature(self):
        self.assertNotIn("PBR_NEXT_HOP_UNRESOLVED", codes(validate(self.change)))

    def test_next_hop_is_checked_only_when_the_registry_supports_pbr(self):
        cap = PlatformCapability(CapabilityStatus.SUPPORTED, "test")
        with mock.patch.dict(pd.SERVICE_POLICY_CAPABILITIES["arista_ceos"], {ServicePolicyFeature.PBR_IPV4: cap}):
            self.assertIn("PBR_NEXT_HOP_UNRESOLVED", codes(validate(self.change)))
