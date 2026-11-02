"""Lab 7 closure -- ``routing_intent_service`` (getters, ordering, removals, accepted-field mirroring, editor summary)
and ``interface_intent_service`` (draft guard, address getters, management protection, mirroring, editor rows), each
called directly against a real draft candidate in the test database.

Draft-only and database-local: nothing is rendered, deployed or sent to NetBox.  POSITIVE: exact stored objects,
ordering, mirrored fields, field-state cleanup on removal, exact editor paths / labels / capability flags.  NEGATIVE:
unknown / foreign IDs and families, unconfirmed removals, paths outside the candidate, non-draft changes and the
static management plane are refused, leaving the revision unchanged.
"""
from __future__ import annotations

from django.test import TestCase

from core import models
from core.services import interface_intent_service as ifs
from core.services import routing_intent_service as ris
from core.tests.helpers.candidates import add_interface, make_candidate


class RoutingCase(TestCase):
    def setUp(self):
        self.change, self.intent, self.revision = make_candidate()
        self.eth = add_interface(self.revision, kind="ROUTED_PHYSICAL", name="Ethernet1")
        self.route = ris.add_static_route(revision=self.revision, family="IPV4")
        self.ospf = ris.add_protocol_instance(revision=self.revision, family="ospf", version="OSPFV2")
        self.binding = ris.add_interface_binding(revision=self.revision, family="ospf", instance_id=self.ospf["id"], interface_id=self.eth["id"])
        self.ospf_net = ris.add_ospf_network(revision=self.revision, instance_id=self.ospf["id"], prefix="10.0.0.0/8", area="0")
        self.bgp = ris.add_protocol_instance(revision=self.revision, family="bgp", local_asn=65001)
        self.peer = ris.add_bgp_neighbor(revision=self.revision, instance_id=self.bgp["id"], peer_address="10.0.0.2", remote_asn=65002)
        self.bgp_net = ris.add_bgp_network(revision=self.revision, instance_id=self.bgp["id"], family="IPV4", cidr="10.1.0.0/16")

    def paths(self, prefix):
        return set(self.revision.field_states.filter(path__startswith=prefix).values_list("path", flat=True))

    def routing(self):
        self.revision.refresh_from_db()
        return self.revision.sections["routing"]


class RoutingGetterTests(RoutingCase):
    def getters(self):
        return {"static route": (ris.get_static_route, (self.route["id"],)),
                "protocol instance": (ris.get_protocol_instance, ("ospf", self.ospf["id"])),
                "interface binding": (ris.get_interface_binding, ("ospf", self.ospf["id"], self.binding["id"])),
                "ospf network": (ris.get_ospf_network, (self.ospf["id"], self.ospf_net["id"])),
                "bgp neighbor": (ris.get_bgp_neighbor, (self.bgp["id"], self.peer["id"])),
                "bgp network": (ris.get_bgp_network, (self.bgp["id"], self.bgp_net["id"]))}

    def test_routing_getters_return_the_owned_object(self):
        for label, (getter, args) in self.getters().items():
            with self.subTest(case=f"returns {label}"):
                self.assertEqual(getter(self.revision, *args)["id"], args[-1])

    def test_routing_getters_refuse_unknown_ids_and_families(self):
        for label, (getter, args) in self.getters().items():
            with self.subTest(case=f"refused unknown {label}"):
                with self.assertRaises(ris.CollectionOwnershipError):
                    getter(self.revision, *args[:-1], "unknown_id")
        with self.subTest(case="refused unknown family"):
            with self.assertRaisesRegex(ris.CollectionOwnershipError, "Unknown routing protocol family"):
                ris.get_protocol_instance(self.revision, "igrp", self.ospf["id"])
        with self.subTest(case="refused instance of another family"):
            with self.assertRaises(ris.CollectionOwnershipError):
                ris.get_bgp_neighbor(self.revision, self.ospf["id"], self.peer["id"])

    def test_ordered_collection_returns_rows_by_sequence_then_id(self):
        rows = {"b": {"id": "b", "sequence": 1}, "a": {"id": "a", "sequence": 1}, "c": {"id": "c", "sequence": 0}}
        self.assertEqual([r["id"] for r in ris.ordered_collection(rows)], ["c", "a", "b"])

    def test_ordered_collection_of_an_empty_mapping_is_empty(self):
        self.assertEqual(ris.ordered_collection({}), [])

    def test_ordered_static_routes_returns_every_route_in_order(self):
        second = ris.add_static_route(revision=self.revision, family="IPV6")
        self.assertEqual([r["id"] for r in ris.ordered_static_routes(self.revision)], [self.route["id"], second["id"]])

    def test_ordered_static_routes_of_a_candidate_without_routes_is_empty(self):
        _, _, revision = make_candidate(device_name="R2")
        self.assertEqual(ris.ordered_static_routes(revision), [])


class RoutingRemovalTests(RoutingCase):
    def test_remove_ospf_network_returns_after_deleting_it_and_its_field_states(self):
        prefix = f"routing.ospf.{self.ospf['id']}.networks.{self.ospf_net['id']}."
        self.assertTrue(self.paths(prefix))
        self.assertIsNone(ris.remove_ospf_network(revision=self.revision, instance_id=self.ospf["id"], net_id=self.ospf_net["id"], confirmation="REMOVE"))
        self.assertEqual((self.routing()["ospf"][self.ospf["id"]]["networks"], self.paths(prefix)), ({}, set()))

    def test_remove_protocol_instance_returns_after_deleting_it_and_every_child_state(self):
        prefix = f"routing.bgp.{self.bgp['id']}."
        self.assertIsNone(ris.remove_protocol_instance(revision=self.revision, family="bgp", instance_id=self.bgp["id"], confirmation="REMOVE"))
        self.assertEqual((self.routing()["bgp"], self.paths(prefix)), ({}, set()))

    def test_remove_interface_binding_refuses_missing_confirmation_or_unknown_ids_and_keeps_it(self):
        for label, kwargs in (("missing confirmation", {"binding_id": self.binding["id"], "confirmation": "yes"}),
                              ("unknown binding", {"binding_id": "bind_x", "confirmation": "REMOVE"})):
            with self.subTest(case=f"refused {label}"):
                with self.assertRaises((ris.CollectionMutationError, ris.CollectionOwnershipError)):
                    ris.remove_interface_binding(revision=self.revision, family="ospf", instance_id=self.ospf["id"], **kwargs)
        self.assertIn(self.binding["id"], self.routing()["ospf"][self.ospf["id"]]["interfaces"])


class RoutingMirrorAndSummaryTests(RoutingCase):
    def test_mirror_accepted_field_returns_after_writing_each_allowlisted_field(self):
        o, b = self.ospf["id"], self.bgp["id"]
        cases = ((f"routing.static_routes.{self.route['id']}.destination", "10.9.0.0/16", lambda r: r["static_routes"][self.route["id"]]["destination"]),
                 (f"routing.ospf.{o}.router_id", "1.1.1.1", lambda r: r["ospf"][o]["router_id"]),
                 (f"routing.ospf.{o}.interfaces.{self.binding['id']}.cost", 50, lambda r: r["ospf"][o]["interfaces"][self.binding["id"]]["cost"]),
                 (f"routing.ospf.{o}.networks.{self.ospf_net['id']}.area", "1", lambda r: r["ospf"][o]["networks"][self.ospf_net["id"]]["area"]),
                 (f"routing.bgp.{b}.neighbors.{self.peer['id']}.description", "peer", lambda r: r["bgp"][b]["neighbors"][self.peer["id"]]["description"]),
                 (f"routing.bgp.{b}.networks.{self.bgp_net['id']}.cidr", "10.2.0.0/16", lambda r: r["bgp"][b]["networks"][self.bgp_net["id"]]["cidr"]))
        for path, value, read in cases:
            with self.subTest(case=f"mirrors {path.rsplit('.', 1)[-1]}"):
                self.assertIsNone(ris.mirror_accepted_field(revision=self.revision, path=path, value=value))
                self.assertEqual(read(self.routing()), value)

    def test_editor_routing_summary_returns_paths_labels_and_capabilities(self):
        summary = ris.editor_routing_summary(revision=self.revision, platform="arista_ceos")
        self.assertEqual(summary["counts"]["static_routes"], 1)
        self.assertEqual(summary["static_routes"][0]["paths"]["destination"], f"routing.static_routes.{self.route['id']}.destination")
        ospf = summary["ospf"][0]
        self.assertEqual((ospf["interfaces"][0]["interface_label"], ospf["is_compatible"]), ("Ethernet1", True))
        self.assertEqual(ospf["networks"][0]["paths"]["prefix"], f"routing.ospf.{self.ospf['id']}.networks.{self.ospf_net['id']}.prefix")
        bgp = summary["bgp"][0]
        self.assertEqual((bgp["is_compatible"], bgp["neighbors"][0]["paths"]["remote_asn"]),
                         (True, f"routing.bgp.{self.bgp['id']}.neighbors.{self.peer['id']}.remote_asn"))
        self.assertFalse(summary["has_incompatible_objects"])

    def test_editor_routing_summary_flags_incompatible_objects_for_an_unsupported_platform(self):
        summary = ris.editor_routing_summary(revision=self.revision, platform="sonic")
        incompatible = [obj for family in ("static_routes", "ospf", "bgp") for obj in summary[family] if not obj["is_compatible"]]
        self.assertTrue(incompatible)
        self.assertTrue(summary["has_incompatible_objects"])


class InterfaceTests(TestCase):
    def setUp(self):
        self.change, self.intent, self.revision = make_candidate()
        self.svi = add_interface(self.revision, kind="SVI", name="Vlan10")
        self.address = ifs.add_address(revision=self.revision, interface_id=self.svi["id"], family="IPV4", source="AUTO")
        self.manual = ifs.add_address(revision=self.revision, interface_id=self.svi["id"], family="IPV6", source="MANUAL")

    def sections(self):
        self.revision.refresh_from_db()
        return self.revision.sections["interfaces"]

    def test_require_draft_returns_for_a_draft_change(self):
        self.assertIsNone(ifs.require_draft(self.revision))

    def test_require_draft_refuses_a_change_that_is_not_draft(self):
        models.Change.objects.filter(pk=self.change.pk).update(lifecycle_state=models.ChangeLifecycleState.CI_PENDING)
        with self.assertRaises(ifs.DraftOnlyError):
            ifs.require_draft(models.DeviceIntentRevision.objects.get(pk=self.revision.pk))

    def test_get_address_returns_the_owned_address(self):
        self.assertEqual(ifs.get_address(self.revision, self.svi["id"], self.address["id"])["source"], "AUTO")

    def test_address_is_auto_returns_the_source_mode(self):
        self.assertIs(ifs.address_is_auto(self.revision, self.svi["id"], self.address["id"]), True)
        self.assertIs(ifs.address_is_auto(self.revision, self.svi["id"], self.manual["id"]), False)

    def test_address_is_auto_refuses_an_unknown_address(self):
        with self.assertRaises(ifs.CollectionOwnershipError):
            ifs.address_is_auto(self.revision, self.svi["id"], "addr_unknown")

    def test_is_management_static_returns_true_for_the_management_plane(self):
        for label, row in (("management kind", {"kind": "MANAGEMENT"}), ("vlan200 name", {"name": "Vlan200"}), ("vlan id", {"vlan_id": 200})):
            with self.subTest(case=f"returns true for {label}"):
                self.assertTrue(ifs.is_management_static(row))

    def test_is_management_static_is_false_for_a_non_management_interface(self):
        with self.subTest(case="refused access port on vlan 200"):
            self.assertFalse(ifs.is_management_static({"kind": "ACCESS", "name": "Ethernet3", "access_vlan": 200}))

    def test_ordered_interfaces_of_a_candidate_without_interfaces_is_empty(self):
        _, _, revision = make_candidate(device_name="R2")
        self.assertEqual(ifs.ordered_interfaces(revision), [])

    def test_mirror_accepted_field_returns_after_writing_interface_wan_and_address_fields(self):
        i = self.svi["id"]
        cases = ((f"interfaces.{i}.description", "users", lambda s: s[i]["description"]),
                 (f"interfaces.{i}.kind", "ROUTED_PHYSICAL", lambda s: (s[i]["kind"], s[i]["mode"])),
                 (f"interfaces.{i}.wan.provider_name", "ISP", lambda s: s[i]["wan"]["provider_name"]),
                 (f"interfaces.{i}.addresses.{self.manual['id']}.cidr", "2001:db8::1/64", lambda s: s[i]["addresses"][self.manual["id"]]["cidr"]))
        expected = ("users", ("ROUTED_PHYSICAL", ifs.KIND_MODES["ROUTED_PHYSICAL"]), "ISP", "2001:db8::1/64")
        for (path, value, read), want in zip(cases, expected):
            with self.subTest(case=f"mirrors {path.rsplit('.', 1)[-1]}"):
                self.assertIsNone(ifs.mirror_accepted_field(revision=self.revision, path=path, value=value))
                self.assertEqual(read(self.sections()), want)

    def test_mirror_accepted_field_refuses_paths_outside_the_candidate(self):
        before = self.sections()
        for label, path in (("unknown interface", "interfaces.if_x.description"), ("unknown field", f"interfaces.{self.svi['id']}.colour"),
                            ("unknown address", f"interfaces.{self.svi['id']}.addresses.addr_x.cidr"), ("short path", "interfaces")):
            with self.subTest(case=f"refused {label}"):
                with self.assertRaises(ifs.CollectionOwnershipError):
                    ifs.mirror_accepted_field(revision=self.revision, path=path, value="x")
        self.assertEqual(self.sections(), before)

    def test_editor_interfaces_returns_rows_with_paths_addresses_and_capability(self):
        rows = ifs.editor_interfaces(revision=self.revision, platform="arista_ceos")
        row = rows[0]
        self.assertEqual((row["name"], row["is_compatible"], row["is_static_management"]), ("Vlan10", True, False))
        self.assertEqual(row["paths"]["description"], f"interfaces.{self.svi['id']}.description")
        self.assertEqual([a["id"] for a in row["addresses"]], [self.address["id"], self.manual["id"]])
        self.assertEqual(row["address_summary"][0], "AUTO: prefix not selected")
        self.assertEqual(row["addresses"][1]["paths"]["cidr"], f"interfaces.{self.svi['id']}.addresses.{self.manual['id']}.cidr")
