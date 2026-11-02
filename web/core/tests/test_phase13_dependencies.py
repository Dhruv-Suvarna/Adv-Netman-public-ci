from __future__ import annotations

import json

from django.test import SimpleTestCase, TestCase

from core import models
from core.services.validation import dependency_graph as dg
from core.tests.helpers.validation import Dev, codes, findings, new_change, validate


def edge_types(run, source_type, target_type):
    nodes = {n["id"]: n for n in run.dependency_graph["nodes"]}
    return [
        e for e in run.dependency_graph["edges"]
        if nodes.get(e["from"], {}).get("type") == source_type and nodes.get(e["to"], {}).get("type") == target_type
    ]


class GraphEdgeTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.change = new_change()
        cls.r1 = Dev(cls.change, "R1")
        cls.e1 = cls.r1.iface("Ethernet1")

    def test_address_requires_interface(self):
        self.r1.address(self.e1, "192.0.2.0/31")
        (edge,) = edge_types(validate(self.change), "address", "interface")
        self.assertEqual((edge["type"], edge["status"]), (dg.REQUIRES, "RESOLVED"))

    def test_subinterface_requires_parent(self):
        self.r1.iface("Ethernet1.10", kind="SUBINTERFACE", parent_id=self.e1["id"], encapsulation_vlan=10)
        (edge,) = edge_types(validate(self.change), "interface", "interface")
        self.assertEqual(edge["type"], dg.PARENT_BEFORE_CHILD)

    def test_ospf_binding_requires_interface_and_instance(self):
        o = self.r1.ospf(); self.r1.bind("ospf", o, self.e1)
        run = validate(self.change)
        self.assertEqual(edge_types(run, "routing_binding", "interface")[0]["type"], dg.INTERFACE_BEFORE_SERVICE)
        self.assertEqual(edge_types(run, "routing_binding", "routing_ospf")[0]["type"], dg.REQUIRES)

    def test_routing_binding_depends_on_the_interface_address(self):
        self.r1.address(self.e1, "192.0.2.0/31")
        o = self.r1.ospf(); self.r1.bind("ospf", o, self.e1)
        self.assertEqual(edge_types(validate(self.change), "routing_binding", "address")[0]["type"], dg.ADDRESS_BEFORE_ROUTING)

    def test_bgp_update_source_requires_interface(self):
        self.r1.address(self.e1, "192.0.2.0/31")
        b = self.r1.bgp(65001)
        self.r1.neighbor(b, "192.0.2.1", 65002, update_source_interface_id=self.e1["id"])
        run = validate(self.change)
        self.assertEqual(edge_types(run, "bgp_neighbor", "interface")[0]["type"], dg.INTERFACE_BEFORE_SERVICE)
        self.assertEqual(edge_types(run, "bgp_neighbor", "address")[0]["type"], dg.ADDRESS_BEFORE_ROUTING)

    def test_nat_rule_requires_pool_defined_first(self):
        r3 = Dev(self.change, "R3", platform=models.Platform.UBUNTU_FRR)
        inside, outside = r3.iface("eth1"), r3.iface("eth2")
        rule = r3.nat_rule(inside=inside, outside=outside, source="10.0.0.0/8")
        def inject(sections):
            sections["nat"]["pools"]["pool_x"] = {"id": "pool_x", "sequence": 1, "name": "P", "family": "NAT44", "start_address": "203.0.113.1",
                                                  "end_address": "203.0.113.9", "prefix_length": None, "description": ""}
        r3.inject(inject); r3.force(f"nat.rules.{rule['id']}.pool_id", "pool_x")
        (edge,) = edge_types(validate(self.change), "nat_rule", "nat_pool")
        self.assertEqual((edge["type"], edge["status"]), (dg.DEFINE_BEFORE_ATTACH, "RESOLVED"))

    def test_acl_attachment_requires_definition_and_interface(self):
        acl = self.r1.acl(); self.r1.attach_acl(acl, self.e1)
        run = validate(self.change)
        self.assertEqual(edge_types(run, "acl_attachment", "acl")[0]["type"], dg.DEFINE_BEFORE_ATTACH)
        self.assertEqual(edge_types(run, "acl_attachment", "interface")[0]["type"], dg.INTERFACE_BEFORE_SERVICE)

    def test_pbr_attachment_requires_policy(self):
        def inject(sections):
            sections["policy"] = {"pbr": {"policies": {"pbr_p": {"id": "pbr_p", "sequence": 1, "name": "P", "family": "IPV4", "description": "", "sequences": {}}},
                                          "attachments": {"a1": {"id": "a1", "sequence": 1, "policy_id": "pbr_p", "interface_id": self.e1["id"], "direction": "IN"}}}}
        self.r1.inject(inject)
        run = validate(self.change)
        self.assertEqual(edge_types(run, "pbr_attachment", "pbr_policy")[0]["type"], dg.DEFINE_BEFORE_ATTACH)
        self.assertEqual(edge_types(run, "pbr_attachment", "interface")[0]["type"], dg.INTERFACE_BEFORE_SERVICE)

    def test_dhcp_relay_requires_interface(self):
        svi = self.r1.iface("Vlan10", kind="SVI", vlan_id=10); self.r1.relay(svi, "192.168.200.100")
        self.assertEqual(edge_types(validate(self.change), "dhcp_relay", "interface")[0]["type"], dg.INTERFACE_BEFORE_SERVICE)

    def test_fhrp_requires_interface(self):
        svi = self.r1.iface("Vlan10", kind="SVI", vlan_id=10); self.r1.fhrp(svi, vips=["192.168.10.1"])
        self.assertTrue(edge_types(validate(self.change), "fhrp", "interface"))

    def test_every_edge_type_is_from_the_explicit_vocabulary(self):
        self.r1.address(self.e1, "192.0.2.0/31"); o = self.r1.ospf(); self.r1.bind("ospf", o, self.e1)
        self.assertTrue({e["type"] for e in validate(self.change).dependency_graph["edges"]} <= set(dg.EDGE_TYPES))


class MissingAndCycleTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.change = new_change()
        cls.r1 = Dev(cls.change, "R1")
        cls.a = cls.r1.iface("Ethernet1")
        cls.sub = cls.r1.iface("Ethernet1.10", kind="SUBINTERFACE", parent_id=cls.a["id"], encapsulation_vlan=10)

    def test_missing_dependency_is_reported_never_silently_dropped(self):
        self.r1.force(f"interfaces.{self.sub['id']}.parent_id", "if_0000000000000000")
        run = validate(self.change)
        (finding,) = findings(run, "DEPENDENCY_MISSING")
        self.assertTrue(finding["blocking"])
        self.assertEqual(finding["object_id"], self.sub["id"])
        missing = [e for e in run.dependency_graph["edges"] if e["status"] == "MISSING"]
        self.assertEqual(len(missing), 1)
        self.assertEqual(run.dependency_graph["summary"]["missing"], 1)

    def test_unset_required_reference_is_missing(self):
        acl = self.r1.acl(); att = self.r1.attach_acl(acl, self.a)
        self.r1.force(f"security.attachments.{att['id']}.interface_id", "")
        self.assertIn("DEPENDENCY_MISSING", codes(validate(self.change)))

    def test_cycle_is_detected_with_full_path_evidence(self):
        self.r1.force(f"interfaces.{self.a['id']}.parent_id", self.sub["id"])   # A -> sub, sub -> A
        run = validate(self.change)
        (finding,) = findings(run, "DEPENDENCY_CYCLE")
        cycle = finding["evidence"]["cycle"]
        self.assertTrue(finding["blocking"])
        self.assertEqual(cycle[0], cycle[-1])
        self.assertEqual(len(cycle), 3)
        self.assertIn("->", finding["message"])
        self.assertEqual(run.dependency_graph["summary"]["cycles"], 1)

    def test_self_parent_is_a_cycle(self):
        self.r1.force(f"interfaces.{self.a['id']}.parent_id", self.a["id"])
        (finding,) = findings(validate(self.change), "DEPENDENCY_CYCLE")
        self.assertEqual(len(finding["evidence"]["cycle"]), 2)


class FindCyclesUnitTests(SimpleTestCase):
    def edges(self, pairs, status="RESOLVED"):
        return [{"from": a, "to": b, "type": dg.REQUIRES, "status": status, "reason": ""} for a, b in pairs]

    def test_acyclic_graph_has_no_cycles(self):
        self.assertEqual(dg.find_cycles(self.edges([("a", "b"), ("b", "c"), ("a", "c")])), [])

    def test_three_node_cycle(self):
        self.assertEqual(dg.find_cycles(self.edges([("a", "b"), ("b", "c"), ("c", "a")])), [["a", "b", "c", "a"]])

    def test_each_cycle_reported_once_and_deterministically(self):
        edges = self.edges([("x", "y"), ("y", "x"), ("m", "n"), ("n", "m")])
        self.assertEqual(dg.find_cycles(edges), dg.find_cycles(list(reversed(edges))))
        self.assertEqual(len(dg.find_cycles(edges)), 2)

    def test_missing_edges_do_not_form_cycles(self):
        self.assertEqual(dg.find_cycles(self.edges([("a", "b"), ("b", "a")], status="MISSING")), [])

    def test_unknown_edge_type_is_rejected(self):
        with self.assertRaises(ValueError):
            dg.GraphBuilder().edge("a", "b", "MAYBE_BEFORE")


class GraphShapeTests(TestCase):
    def build(self):
        change = new_change()
        r1 = Dev(change, "R1"); e1 = r1.iface("Ethernet1"); r1.address(e1, "192.0.2.0/31")
        o = r1.ospf(); r1.bind("ospf", o, e1)
        acl = r1.acl(); r1.attach_acl(acl, e1)
        return change

    def test_graph_ordering_and_serialization_are_deterministic(self):
        change = self.build()
        first, second = validate(change), validate(change)
        self.assertEqual(json.dumps(first.dependency_graph, sort_keys=True), json.dumps(second.dependency_graph, sort_keys=True))
        ids = [n["id"] for n in first.dependency_graph["nodes"]]
        self.assertEqual(ids, sorted(ids))
        edges = [(e["from"], e["to"], e["type"]) for e in first.dependency_graph["edges"]]
        self.assertEqual(edges, sorted(edges))

    def test_graph_is_not_a_configlet_execution_plan(self):
        change = self.build()
        run = validate(change)
        text = json.dumps({k: v for k, v in run.dependency_graph.items() if k != "note"})  # the note is the disclaimer
        for plan_word in ("cfg_id", "CFG-", "deployment_priority", "execution_order", "stage", "rollback", "transaction"):
            self.assertNotIn(plan_word, text)
        self.assertIn("NOT a deployment plan", run.dependency_graph["note"])
        self.assertEqual(models.Configlet.objects.count(), 0)
        for key in ("order", "sequence", "priority", "plan"):
            self.assertNotIn(key, run.dependency_graph)
        self.assertTrue(all("sequence" not in n and "priority" not in n for n in run.dependency_graph["nodes"]))

    def test_node_identity_is_stable_object_id(self):
        change = self.build()
        run = validate(change)
        for node in run.dependency_graph["nodes"]:
            self.assertEqual(node["id"], f"{node['device']}/{node['type']}/{node['object_id']}")
