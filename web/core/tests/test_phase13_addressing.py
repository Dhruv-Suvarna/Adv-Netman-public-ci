from __future__ import annotations

import copy

from django.test import TestCase

from core.services import change_validation_service as cvs
from core.tests.helpers.validation import (
    Dev, codes, findings, make_sources, nb_ip, nb_prefix, netbox_data, new_change, validate,
)


def mutate_sections(dev, fn):
    """Simulate a persisted-but-malformed revision (manual DB edit / migration bug)."""
    revision = dev.refresh()
    sections = copy.deepcopy(revision.sections)
    fn(sections)
    revision.sections = sections
    revision.save(update_fields=["sections"])


class CandidateDuplicateTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.change = new_change()
        cls.r1, cls.r2 = Dev(cls.change, "R1"), Dev(cls.change, "R2")

    def test_duplicate_ipv4_is_blocked_and_reports_both_objects(self):
        a = self.r1.iface("Ethernet1"); self.r1.address(a, "192.0.2.1/31")
        b = self.r2.iface("Ethernet2"); self.r2.address(b, "192.0.2.1/31")
        run = validate(self.change)
        (finding,) = findings(run, "IP_DUPLICATE")
        self.assertEqual(run.status, "BLOCKED")
        self.assertTrue(finding["blocking"])
        self.assertEqual(finding["severity"], "ERROR")
        self.assertEqual(sorted({finding["device"], *finding["related_devices"]}), ["R1", "R2"])
        self.assertEqual(len(finding["related_objects"]), 2)
        self.assertEqual(len(finding["evidence"]["assignments"]), 2)

    def test_duplicate_ipv6_is_blocked(self):
        a = self.r1.iface("Ethernet1"); self.r1.address(a, "2001:db8:1::1/127")
        b = self.r2.iface("Ethernet2"); self.r2.address(b, "2001:db8:1::1/127")
        self.assertIn("IP_DUPLICATE", codes(validate(self.change)))

    def test_same_subnet_different_hosts_is_not_a_collision(self):
        a = self.r1.iface("Ethernet1"); self.r1.address(a, "192.0.2.1/24")
        b = self.r2.iface("Ethernet2"); self.r2.address(b, "192.0.2.2/24")
        run = validate(self.change)
        self.assertNotIn("IP_DUPLICATE", codes(run))
        self.assertEqual(run.status, "PASS")

    def test_same_ip_on_two_interfaces_of_one_device_is_blocked(self):
        a = self.r1.iface("Ethernet1"); self.r1.address(a, "192.0.2.1/24")
        b = self.r1.iface("Ethernet2"); self.r1.address(b, "192.0.2.1/24")
        self.assertIn("IP_DUPLICATE", codes(validate(self.change)))

    def test_link_local_and_loopback_addresses_are_exempt(self):
        a = self.r1.iface("Ethernet1"); self.r1.address(a, "fe80::1/64")
        b = self.r2.iface("Ethernet2"); self.r2.address(b, "fe80::1/64")
        self.assertNotIn("IP_DUPLICATE", codes(validate(self.change)))

    def test_malformed_persisted_address_is_defended(self):
        a = self.r1.iface("Ethernet1"); row = self.r1.address(a, "192.0.2.1/24")
        def corrupt(sections):
            sections["interfaces"][a["id"]]["addresses"][row["id"]]["cidr"] = "999.1.1.1/8"
        mutate_sections(self.r1, corrupt)
        # accepted state overlays IntentFieldState, so corrupt the accepted value too
        from core import models
        models.IntentFieldState.objects.filter(path=f"interfaces.{a['id']}.addresses.{row['id']}.cidr").update(
            accepted_value="999.1.1.1/8", draft_value="999.1.1.1/8")
        self.assertIn("ADDRESS_INVALID", codes(validate(self.change)))


class NetBoxCollisionTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.change = new_change()
        cls.r1 = Dev(cls.change, "R1")
        cls.e1 = cls.r1.iface("Ethernet1")
        cls.r1.address(cls.e1, "192.0.2.1/24")

    def run_with(self, rows):
        return validate(self.change, make_sources(netbox=netbox_data(ip_addresses=rows)))

    def test_existing_device_exact_self_match_is_not_a_collision(self):
        run = self.run_with([nb_ip("192.0.2.1/24", "R1", "Ethernet1")])
        self.assertNotIn("IP_NETBOX_COLLISION", codes(run))
        self.assertEqual(run.status, "PASS")

    def test_same_ip_on_unrelated_netbox_object_is_blocked(self):
        run = self.run_with([nb_ip("192.0.2.1/24", "R9", "Ethernet7")])
        (finding,) = findings(run, "IP_NETBOX_COLLISION")
        self.assertTrue(finding["blocking"])
        self.assertEqual(finding["related_devices"], ["R9"])
        self.assertEqual(run.status, "BLOCKED")

    def test_same_device_different_interface_is_still_a_collision(self):
        run = self.run_with([nb_ip("192.0.2.1/24", "R1", "Ethernet9")])
        self.assertIn("IP_NETBOX_COLLISION", codes(run))

    def test_different_host_in_same_prefix_is_not_a_collision(self):
        run = self.run_with([nb_ip("192.0.2.2/24", "R9", "Ethernet7")])
        self.assertNotIn("IP_NETBOX_COLLISION", codes(run))

    def test_unassigned_netbox_record_is_only_a_warning(self):
        run = self.run_with([nb_ip("192.0.2.1/24")])
        (finding,) = findings(run, "IP_NETBOX_COLLISION")
        self.assertFalse(finding["blocking"])
        self.assertEqual(run.status, "PASS_WITH_WARNINGS")

    def test_netbox_shared_vip_used_as_ordinary_address_is_blocked(self):
        run = self.run_with([nb_ip("192.0.2.1/24", None, None, role="vrrp")])
        self.assertTrue(findings(run, "IP_NETBOX_COLLISION")[0]["blocking"])

    def test_address_released_by_the_same_change_is_not_blocking(self):
        # NetBox has the IP on R2 Ethernet1; R2's accepted intent defines that interface without it.
        r2 = Dev(self.change, "R2")
        r2.iface("Ethernet1")
        run = self.run_with([nb_ip("192.0.2.1/24", "R2", "Ethernet1")])
        (finding,) = findings(run, "IP_NETBOX_COLLISION")
        self.assertFalse(finding["blocking"])
        self.assertEqual(finding["evidence"]["kind"], "released")


class DhcpAndReservationTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.change = new_change()
        cls.r1 = Dev(cls.change, "R1")
        cls.e1 = cls.r1.iface("Ethernet1")
        cls.pool = {"start": "192.168.10.100", "end": "192.168.10.179", "family": 4, "server": "primary"}

    def test_static_address_inside_dynamic_pool_is_blocked(self):
        self.r1.address(self.e1, "192.168.10.150/24")
        run = validate(self.change, make_sources(netbox=netbox_data(dhcp_ranges=[self.pool])))
        (finding,) = findings(run, "IP_DHCP_POOL_CONFLICT")
        self.assertTrue(finding["blocking"])
        self.assertEqual(finding["evidence"]["pool_start"], "192.168.10.100")

    def test_static_address_outside_pool_is_fine(self):
        self.r1.address(self.e1, "192.168.10.50/24")
        run = validate(self.change, make_sources(netbox=netbox_data(dhcp_ranges=[self.pool])))
        self.assertNotIn("IP_DHCP_POOL_CONFLICT", codes(run))

    def test_pool_edges_are_inclusive(self):
        self.r1.address(self.e1, "192.168.10.100/24")
        run = validate(self.change, make_sources(netbox=netbox_data(dhcp_ranges=[self.pool])))
        self.assertIn("IP_DHCP_POOL_CONFLICT", codes(run))

    def test_reservation_owned_by_another_identity_is_blocked(self):
        self.r1.address(self.e1, "192.168.10.55/24")
        netbox = netbox_data(
            ip_addresses=[nb_ip("192.168.10.55/24", "H1", "eth1")],
            interface_modes=[{"device": "H1", "interface": "eth1", "ipv4_mode": "dhcp-reserved", "ipv6_mode": None}],
        )
        run = validate(self.change, make_sources(netbox=netbox))
        (finding,) = findings(run, "IP_RESERVATION_CONFLICT")
        self.assertTrue(finding["blocking"])
        self.assertEqual(finding["related_devices"], ["H1"])

    def test_own_reservation_with_matching_address_is_not_a_conflict(self):
        self.r1.address(self.e1, "192.168.10.55/24")
        netbox = netbox_data(
            ip_addresses=[nb_ip("192.168.10.55/24", "R1", "Ethernet1")],
            interface_modes=[{"device": "R1", "interface": "Ethernet1", "ipv4_mode": "dhcp-reserved", "ipv6_mode": None}],
        )
        self.assertNotIn("IP_RESERVATION_CONFLICT", codes(validate(self.change, make_sources(netbox=netbox))))

    def test_reserved_identity_given_a_different_static_address_is_blocked(self):
        self.r1.address(self.e1, "192.168.10.60/24")
        netbox = netbox_data(
            ip_addresses=[nb_ip("192.168.10.55/24", "R1", "Ethernet1")],
            interface_modes=[{"device": "R1", "interface": "Ethernet1", "ipv4_mode": "dhcp-reserved", "ipv6_mode": None}],
        )
        self.assertIn("IP_RESERVATION_CONFLICT", codes(validate(self.change, make_sources(netbox=netbox))))

    def test_existing_pool_safety_problems_are_reported_as_project_state_warnings(self):
        netbox = netbox_data(
            prefixes=[nb_prefix("192.168.10.0/24", vlan=10)],
            dhcp_ranges=[self.pool, {**self.pool, "start": "192.168.10.150", "end": "192.168.10.170", "server": "secondary"}],
        )
        run = validate(self.change, make_sources(netbox=netbox))
        overlap = findings(run, "DHCP_POOL_OVERLAP")
        self.assertTrue(overlap)
        self.assertFalse(any(f["blocking"] for f in overlap))


class Vlan200DefenseTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.change = new_change()
        cls.r1 = Dev(cls.change, "R1")
        cls.vlan200 = cls.r1.iface("Vlan200", kind="SVI", vlan_id=200)

    def test_persisted_dhcp_client_on_vlan200_is_blocked(self):
        def inject(sections):
            sections.setdefault("services", {}).setdefault("dhcp", {"mode": "OVERRIDE", "relays": {}, "clients": {}, "local_server_override": False})
            sections["services"]["dhcp"]["clients"]["dhcp_x"] = {
                "id": "dhcp_x", "sequence": 1, "family": "IPV4", "interface_id": self.vlan200["id"], "description": ""}
        mutate_sections(self.r1, inject)
        (finding,) = findings(validate(self.change), "DHCP_VLAN200_FORBIDDEN")
        self.assertTrue(finding["blocking"])
        self.assertEqual(finding["object_type"], "dhcp_client")

    def test_persisted_dhcpv6_client_on_vlan200_is_blocked(self):
        def inject(sections):
            sections.setdefault("services", {}).setdefault("dhcp", {"mode": "OVERRIDE", "relays": {}, "clients": {}, "local_server_override": False})
            sections["services"]["dhcp"]["clients"]["dhcp_y"] = {
                "id": "dhcp_y", "sequence": 1, "family": "IPV6", "interface_id": self.vlan200["id"], "description": ""}
        mutate_sections(self.r1, inject)
        (finding,) = findings(validate(self.change), "DHCP_VLAN200_FORBIDDEN")
        self.assertIn("DHCPv6", finding["message"])

    def test_persisted_auto_address_on_vlan200_is_blocked(self):
        def inject(sections):
            sections["interfaces"][self.vlan200["id"]]["addresses"]["addr_bad"] = {
                "id": "addr_bad", "sequence": 1, "family": "IPV4", "cidr": "", "source": "AUTO", "role": "PRIMARY", "ipam_prefix": "192.168.200.0/24"}
        mutate_sections(self.r1, inject)
        self.assertIn("DHCP_VLAN200_FORBIDDEN", codes(validate(self.change)))

    def test_dhcp_relay_on_vlan200_is_blocked(self):
        def inject(sections):
            sections.setdefault("services", {}).setdefault("dhcp", {"mode": "OVERRIDE", "relays": {}, "clients": {}, "local_server_override": False})
            sections["services"]["dhcp"]["relays"]["dhcp_z"] = {
                "id": "dhcp_z", "sequence": 1, "family": "IPV4", "interface_id": self.vlan200["id"], "destination": "192.168.200.100", "description": ""}
        mutate_sections(self.r1, inject)
        self.assertIn("DHCP_VLAN200_FORBIDDEN", codes(validate(self.change)))

    def test_netbox_reservation_on_management_interface_is_blocked(self):
        netbox = netbox_data(interface_modes=[{"device": "R1", "interface": "Vlan200", "ipv4_mode": "dhcp-reserved", "ipv6_mode": None}])
        self.assertIn("DHCP_VLAN200_FORBIDDEN", codes(validate(self.change, make_sources(netbox=netbox))))

    def test_static_vlan200_address_is_accepted(self):
        self.r1.address(self.vlan200, "192.168.200.1/24")
        run = validate(self.change)
        self.assertNotIn("DHCP_VLAN200_FORBIDDEN", codes(run))
        self.assertEqual(run.status, "PASS")


class AutoAddressTests(TestCase):
    PREFIX = "198.51.100.0/29"

    @classmethod
    def setUpTestData(cls):
        cls.change = new_change()
        cls.r1, cls.r2 = Dev(cls.change, "R1"), Dev(cls.change, "R2")
        cls.e1 = cls.r1.iface("Ethernet1")
        cls.auto = cls.r1.auto_address(cls.e1, cls.PREFIX)

    def sources(self, **kw):
        base = dict(prefixes=[nb_prefix(self.PREFIX)])
        base.update(kw)
        return make_sources(netbox=netbox_data(**base))

    def proposed(self, run, object_id=None):
        facts = [f for f in run.derived_facts if f["type"] == "AUTO_ADDRESS" and (object_id is None or f["object_id"] == object_id)]
        return facts[0]["proposed_address"] if facts else None

    def test_derives_deterministically_lowest_free_host(self):
        first = validate(self.change, self.sources())
        second = validate(self.change, self.sources())
        self.assertEqual(self.proposed(first), "198.51.100.1/29")
        self.assertEqual(first.derived_facts, second.derived_facts)

    def test_derived_fact_says_proposed_not_reserved(self):
        (fact,) = [f for f in validate(self.change, self.sources()).derived_facts if f["type"] == "AUTO_ADDRESS"]
        self.assertIs(fact["reserved"], False)
        self.assertEqual(fact["status"], "PROPOSED")
        self.assertIn("NOT RESERVED", fact["note"])
        self.assertIn("rechecked immediately before deployment", fact["note"])
        for key in ("object_id", "selected_prefix", "proposed_address", "source", "algorithm"):
            self.assertIn(key, fact)

    def test_excludes_netbox_assigned_host(self):
        run = validate(self.change, self.sources(ip_addresses=[nb_ip("198.51.100.1/29", "R9", "Ethernet1")]))
        self.assertEqual(self.proposed(run), "198.51.100.2/29")

    def test_excludes_candidate_manual_host(self):
        e2 = self.r2.iface("Ethernet1"); self.r2.address(e2, "198.51.100.1/29")
        self.assertEqual(self.proposed(validate(self.change, self.sources())), "198.51.100.2/29")

    def test_excludes_earlier_derived_auto_host(self):
        e2 = self.r2.iface("Ethernet1"); second = self.r2.auto_address(e2, self.PREFIX)
        run = validate(self.change, self.sources())
        self.assertEqual(self.proposed(run, self.auto["id"]), "198.51.100.1/29")
        self.assertEqual(self.proposed(run, second["id"]), "198.51.100.2/29")

    def test_excludes_dynamic_dhcp_range(self):
        pool = {"start": "198.51.100.1", "end": "198.51.100.2", "family": 4, "server": "primary"}
        self.assertEqual(self.proposed(validate(self.change, self.sources(dhcp_ranges=[pool]))), "198.51.100.3/29")

    def test_excludes_reservation_owned_by_others(self):
        run = validate(self.change, self.sources(
            ip_addresses=[nb_ip("198.51.100.1/29", "H1", "eth1")],
            interface_modes=[{"device": "H1", "interface": "eth1", "ipv4_mode": "dhcp-reserved", "ipv6_mode": None}]))
        self.assertEqual(self.proposed(run), "198.51.100.2/29")

    def test_excludes_fhrp_vips_and_project_service_addresses(self):
        from core.tests.helpers.validation import inventory_data
        svi = self.r2.iface("Vlan10", kind="SVI", vlan_id=10)
        self.r2.fhrp(svi, vips=["192.168.200.3"])
        e3 = self.r1.iface("Ethernet3"); auto = self.r1.auto_address(e3, "192.168.200.0/29")
        inventory = inventory_data(devices=("R1",))          # R1 monitoring address = 192.168.200.1
        inventory["management"]["nmas_ipv4"] = "192.168.200.2"
        run = validate(self.change, make_sources(
            netbox=netbox_data(prefixes=[nb_prefix(self.PREFIX), nb_prefix("192.168.200.0/29")]), inventory=inventory))
        # .1 = R1 inventory address, .2 = NMAS service address, .3 = FHRP virtual IP -> first free host is .4
        self.assertEqual(self.proposed(run, auto["id"]), "192.168.200.4/29")

    def test_no_available_host_is_a_blocking_finding(self):
        rows = [nb_ip(f"198.51.100.{n}/29", "R9", f"Ethernet{n}") for n in range(1, 7)]
        run = validate(self.change, self.sources(ip_addresses=rows))
        (finding,) = findings(run, "AUTO_IP_NO_AVAILABLE_ADDRESS")
        self.assertTrue(finding["blocking"])
        self.assertEqual(run.status, "BLOCKED")
        self.assertEqual(self.proposed(run), None)

    def test_missing_prefix_is_unresolved_and_blocking(self):
        self.r1.auto_address(self.e1, "")
        run = validate(self.change, self.sources())
        self.assertTrue(any(f["blocking"] for f in findings(run, "AUTO_IP_UNRESOLVED")))

    def test_prefix_unknown_to_netbox_is_unresolved(self):
        run = validate(self.change, self.sources(prefixes=[nb_prefix("203.0.113.0/29")]))
        self.assertIn("AUTO_IP_UNRESOLVED", codes(run))
        self.assertEqual(self.proposed(run), None)

    def test_netbox_unavailable_makes_auto_incomplete_not_pass(self):
        run = validate(self.change, make_sources(netbox=None))
        self.assertEqual(run.status, "INCOMPLETE")
        (finding,) = findings(run, "AUTO_IP_UNRESOLVED")
        self.assertTrue(finding["incomplete"])
        self.assertFalse(finding["blocking"])

    def test_derivation_never_modifies_accepted_intent(self):
        before = copy.deepcopy(self.r1.refresh().sections)
        hash_before = cvs.hash_snapshot(cvs.build_change_snapshot(self.change))
        validate(self.change, self.sources())
        self.assertEqual(self.r1.refresh().sections, before)
        self.assertEqual(cvs.hash_snapshot(cvs.build_change_snapshot(self.change)), hash_before)
        self.assertEqual(self.r1.refresh().sections["interfaces"][self.e1["id"]]["addresses"][self.auto["id"]]["cidr"], "")

    def test_derived_address_participates_in_duplicate_checks_only_by_construction(self):
        run = validate(self.change, self.sources())
        self.assertNotIn("IP_DUPLICATE", codes(run))

    def test_ipv6_auto_derivation(self):
        e2 = self.r2.iface("Ethernet2"); auto6 = self.r2.auto_address(e2, "2001:db8:99::/64", family="IPV6")
        run = validate(self.change, self.sources(prefixes=[nb_prefix(self.PREFIX), nb_prefix("2001:db8:99::/64")]))
        self.assertEqual(self.proposed(run, auto6["id"]), "2001:db8:99::1/64")
