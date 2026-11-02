"""Lab 7 closure -- the validation project model and context (``validation/context.py``), each accessor called directly.

Every validator reads the candidate through this model, so the exact parsing matters both ways.  POSITIVE: interfaces,
sections, addresses, labels and source views are exactly what the snapshot / bundle hold.  NEGATIVE: an absent
section, device, interface or unavailable source yields an empty value -- never a guessed one -- and malformed or
family-mismatched addresses are set aside as invalid instead of being parsed into the model.
"""

from __future__ import annotations

import ipaddress
from types import SimpleNamespace

from django.test import SimpleTestCase

from core.services.validation import context as vc

SVI = {"id": "i1", "name": "Vlan10", "kind": "SVI", "vlan_id": 10,
       "addresses": {"a1": {"id": "a1", "cidr": "192.168.10.2/24", "family": "IPV4", "source": "MANUAL", "role": "primary"},
                     "a2": {"id": "a2", "cidr": "2001:db8:10::2/64", "family": "IPV6", "source": "MANUAL"},
                     "a3": {"id": "a3", "source": "AUTO"}, "a4": {"id": "a4", "cidr": "", "source": "MANUAL"},
                     "a5": {"id": "a5", "cidr": "not-an-address", "source": "MANUAL"}, "a6": {"id": "a6", "cidr": "10.0.0.1/31", "family": "IPV6"}}}
UPLINK = {"id": "i2", "name": "Ethernet1", "kind": "ROUTED_PHYSICAL", "addresses": {"b1": {"id": "b1", "cidr": "10.0.0.0/31", "source": "MANUAL"}}}
FULL = {"device_name": "S1", "platform": "arista_ceos", "target_type": "device", "interfaces": {"i1": SVI, "i2": UPLINK},
        "routing": {"ospf": {"enabled": True}}, "fhrp": {"instances": {"f1": {"id": "f1"}}}, "nat": {"rules": []},
        "services": {"dhcp": {"relay": ["10.9.9.9"]}, "dns": {"servers": ["1.1.1.1"]}},
        "security": {"acls": {"x": {"id": "x"}}, "attachments": {"y": {"id": "y"}}}, "policy": {"pbr": {"p": {"id": "p"}}}}
BARE = {"device_name": "R9", "platform": "ubuntu_frr", "target_type": "device"}


def project():
    return vc.ProjectModel({"devices": [FULL, BARE]})


def source(data=None, available=True):
    return SimpleNamespace(data=data, available=available)


NETBOX = {"ip_addresses": [{"ip": "192.168.10.2", "device": "S1", "interface": "vlan10"}, {"ip": "10.0.0.0", "device": "R1", "interface": "Ethernet2"}],
          "prefixes": [{"relay_targets": ["10.9.9.9"]}]}
INVENTORY = {"management": {"nmas": "192.168.200.100", "unused": ""}, "network_devices": {"R1": {"monitoring_address": "192.168.200.1"}}}


def context(netbox=NETBOX, inventory=INVENTORY, available=True):
    sources = SimpleNamespace(netbox=source(netbox, available), topology=source({"links": []}, available), inventory=source(inventory, available))
    return vc.ValidationContext(snapshot={}, model=project(), sources=sources)


class HelperTests(SimpleTestCase):
    def test_norm_name_strips_and_lowercases(self):
        self.assertEqual(vc.norm_name("  Vlan10 "), "vlan10")

    def test_norm_name_of_none_is_empty(self):
        self.assertEqual(vc.norm_name(None), "")

    def test_vlan_context_from_id_tag_or_name(self):
        self.assertEqual((vc.vlan_context({"vlan_id": 10}), vc.vlan_context({"encapsulation_vlan": 20}), vc.vlan_context({"name": "VLAN30"})), (10, 20, 30))

    def test_vlan_context_none_for_an_unbound_interface(self):
        self.assertEqual((vc.vlan_context({"name": "Ethernet1"}), vc.vlan_context({"vlan_id": "10"})), (None, None))

    def test_is_management_interface_by_kind_name_or_vlan(self):
        for interface in ({"kind": "MANAGEMENT"}, {"name": "Vlan200"}, {"vlan_id": 200}):
            with self.subTest(case=f"management {interface}"):
                self.assertTrue(vc.is_management_interface(interface))

    def test_is_management_interface_is_not_true_for_a_production_interface(self):
        self.assertFalse(vc.is_management_interface({"name": "Vlan10", "vlan_id": 10, "kind": "SVI"}))


class DeviceModelTests(SimpleTestCase):
    def test_sections_are_read_from_the_entry(self):
        device = project().devices["S1"]
        self.assertEqual((set(device.interfaces), device.routing, set(device.fhrp_instances), device.nat), ({"i1", "i2"}, {"ospf": {"enabled": True}}, {"f1"}, {"rules": []}))
        self.assertEqual((device.dhcp, device.dns, set(device.acls), set(device.acl_attachments), set(device.pbr)),
                         ({"relay": ["10.9.9.9"]}, {"servers": ["1.1.1.1"]}, {"x"}, {"y"}, {"p"}))

    def test_sections_of_a_bare_device_are_empty(self):
        device = project().devices["R9"]
        self.assertEqual((device.interfaces, device.routing, device.fhrp_instances, device.nat, device.dhcp, device.dns, device.acls, device.acl_attachments, device.pbr),
                         ({}, {}, {}, {}, {}, {}, {}, {}, {}))

    def test_interface_by_name_ignores_case_and_ordered_sorts_by_name(self):
        device = project().devices["S1"]
        self.assertIs(device.interface_by_name("VLAN10"), device.interfaces["i1"])
        self.assertEqual([row["name"] for row in device.ordered(device.interfaces)], ["Ethernet1", "Vlan10"])

    def test_interface_by_name_none_for_an_unknown_name_and_ordered_of_nothing_is_empty(self):
        device = project().devices["R9"]
        self.assertIsNone(device.interface_by_name("Vlan10"))
        self.assertEqual(device.ordered({}), [])


class ProjectModelTests(SimpleTestCase):
    def test_project_parses_manual_addresses_and_sets_auto_ones_aside(self):
        model = project()
        self.assertEqual(sorted(str(a.iface) for a in model.addresses), ["10.0.0.0/31", "192.168.10.2/24", "2001:db8:10::2/64"])
        self.assertEqual([a["address"]["id"] for a in model.auto_addresses], ["a3"])
        record = model.addresses_of("S1", "i1")[0]
        self.assertEqual((record.object_key, record.family, str(record.network), record.role), ("S1:Vlan10:a1", 4, "192.168.10.0/24", "primary"))

    def test_project_sets_malformed_and_family_mismatched_addresses_aside_as_invalid(self):
        self.assertEqual(sorted((a["address"]["id"], a["reason"]) for a in project().invalid_addresses), [("a5", "unparseable"), ("a6", "family")])

    def test_address_queries_by_device_interface_and_owner(self):
        model = project()
        derived = vc.AddressRecord("R9", "x", "eth1", "ROUTED_PHYSICAL", "d1", ipaddress.ip_interface("10.0.0.1/31"), "DERIVED")
        model.add_derived(derived)
        self.assertEqual(model.device_addresses("R9"), [derived])
        self.assertEqual([a.device for a in model.owners_of_ip(ipaddress.ip_address("10.0.0.1"))], ["R9"])
        self.assertEqual(len(model.addresses_of("S1", "i1")), 2)

    def test_address_queries_for_unknown_devices_or_addresses_are_empty(self):
        model = project()
        self.assertEqual((model.addresses_of("S1", "nope"), model.owners_of_ip(ipaddress.ip_address("203.0.113.1")), model.device_addresses("R9")), ([], [], []))

    def test_find_interface_and_label(self):
        model = project()
        self.assertIs(model.find_interface("S1", "i2"), UPLINK)
        self.assertEqual(model.interface_label("S1", "i2"), "Ethernet1")
        self.assertTrue(model.has_any_interface())

    def test_find_interface_none_and_label_falls_back_for_unknown_objects(self):
        model = project()
        self.assertEqual((model.find_interface("NOPE", "i1"), model.find_interface("S1", "nope")), (None, None))
        self.assertEqual((model.interface_label("S1", "i9"), model.interface_label("NOPE", "")), ("i9", "?"))
        self.assertFalse(vc.ProjectModel({"devices": [BARE]}).has_any_interface())

    def test_project_without_a_devices_list_raises(self):
        with self.assertRaises(KeyError):
            vc.ProjectModel({})


class ValidationContextTests(SimpleTestCase):
    def test_add_and_derive_record_findings_and_facts(self):
        ctx = context()
        finding = ctx.add("IP_DUPLICATE", "duplicate", device="S1")
        fact = ctx.derive("gateway", device="S1", ip="192.168.10.1")
        self.assertEqual((ctx.findings, finding.code, finding.device), ([finding], "IP_DUPLICATE", "S1"))
        self.assertEqual(ctx.derived, [fact])
        self.assertEqual(fact, {"type": "gateway", "device": "S1", "ip": "192.168.10.1"})

    def test_add_refuses_an_unknown_code_or_field_and_records_nothing(self):
        ctx = context()
        with self.assertRaises(ValueError):
            ctx.add("NOT_A_CATALOGUED_CODE", "y")
        with self.assertRaises(TypeError):
            ctx.add("IP_DUPLICATE", "y", unknown_field=1)
        self.assertEqual(ctx.findings, [])
        self.assertEqual(ctx.derive("none"), {"type": "none"})

    def test_source_views_return_available_data(self):
        ctx = context()
        self.assertEqual((ctx.netbox, ctx.topology, ctx.inventory), (NETBOX, {"links": []}, INVENTORY))

    def test_netbox_lookups_by_ip_and_interface(self):
        ctx = context()
        self.assertEqual(ctx.netbox_records_for_ip(ipaddress.ip_address("192.168.10.2")), [NETBOX["ip_addresses"][0]])
        self.assertEqual(ctx.netbox_addresses_of("S1", "Vlan10"), [NETBOX["ip_addresses"][0]])

    def test_netbox_lookups_are_empty_when_netbox_is_unavailable_or_holds_no_record(self):
        down = context(available=False)
        self.assertEqual((down.netbox, down.topology, down.inventory), (None, None, None))
        self.assertEqual((down.netbox_records_for_ip("192.168.10.2"), down.netbox_addresses_of("S1", "Vlan10")), ([], []))
        self.assertEqual(context().netbox_records_for_ip("203.0.113.9"), [])

    def test_known_service_addresses_label_inventory_netbox_and_candidate_addresses(self):
        found = context().known_service_addresses()
        self.assertEqual(found["192.168.200.100"], "inventory.management.nmas")
        self.assertEqual(found["192.168.200.1"], "inventory.R1.monitoring_address")
        self.assertEqual(found["10.9.9.9"], "netbox.dhcp_relay_targets")
        self.assertEqual(found["192.168.10.2"], "candidate S1:Vlan10")
        self.assertNotIn("", found)

    def test_known_service_addresses_without_sources_are_only_candidate_addresses(self):
        found = context(available=False).known_service_addresses()
        self.assertEqual(set(found), {"192.168.10.2", "2001:db8:10::2", "10.0.0.0"})
