"""Lab 7 closure -- the pure Configuration-Changes / Remove-Configuration building blocks: ``candidate_composition``
(scope builder, conflicts, ``compose``), ``config_workbench.structure`` (line index helpers), ``config_workbench.removal``
(line-range resolution, catalogue, support classification, digests) and ``config_workbench.contribution`` (snapshot
context, operation checks, direct-CLI normalization), each called directly.

Pure: text and dicts in, plans out -- nothing is sent to a device.  POSITIVE: exact scopes, objects, catalogue rows,
operations and digests.  NEGATIVE: duplicate interface identities and single-slot collisions become explicit
conflicts, unknown interfaces contribute nothing, out-of-range / empty / partial / protected selections are blocked,
unsupported platforms are not executable, invalid / incomplete / protected operations are refused, and secret-bearing,
negating or unrecognised CLI is rejected without echoing a secret.
"""
from __future__ import annotations

from django.test import SimpleTestCase

from core.services import candidate_composition as cc
from core.services.config_workbench import contribution, removal, semantics, structure
from core.tests.test_tg_workbench_semantics_closure import EOS


def interfaces():
    return [{"id": "if_b", "sequence": 2, "name": "Vlan10", "addresses": {"a2": {"id": "a2", "cidr": "10.0.0.2/24"}}},
            {"id": "if_a", "sequence": 1, "name": "vlan10", "addresses": {"a1": {"id": "a1", "cidr": "10.0.0.1/24"}}},
            {"id": "if_c", "sequence": 3, "name": "Ethernet1"}]


class CompositionTests(SimpleTestCase):
    def test_builder_init_returns_one_scope_per_interface_name(self):
        builder = cc._Builder([{"id": "if_c", "name": "Ethernet1"}, {"id": "if_d", "name": "Ethernet2"}])
        self.assertEqual([row["name"] for row in builder.interfaces], ["Ethernet1", "Ethernet2"])
        self.assertEqual(set(builder.interfaces[0]["_scope"]), {"ospf", "isis", "fhrp", "acl_attachments", "pbr_attachments", "nat_roles", "dhcp_relays"})
        self.assertEqual(builder.conflicts, [])

    def test_builder_init_with_duplicate_interface_identities_records_a_conflict_never_two_scopes(self):
        builder = cc._Builder(interfaces())
        self.assertEqual([row["name"] for row in builder.interfaces], ["vlan10", "Ethernet1"])
        self.assertIs(builder.by_id["if_b"], builder.by_id["if_a"])
        self.assertEqual(builder.by_id["if_a"]["_source_interface_ids"], ["if_a", "if_b"])
        self.assertEqual(set(builder.by_id["if_a"]["addresses"]), {"a1", "a2"})
        self.assertEqual([c.to_dict()["field"] for c in builder.conflicts], ["identity"])

    def test_conflict_returns_after_recording_one_conflict(self):
        builder = cc._Builder([])
        kwargs = dict(scope_kind="INTERFACE", scope_id="E1", field="fhrp.1", existing=1, incoming=2, existing_source="a", incoming_source="b")
        self.assertIsNone(builder.conflict(**kwargs))
        self.assertEqual([c.to_dict() for c in builder.conflicts], [kwargs])

    def test_conflict_of_a_duplicate_is_never_recorded_twice(self):
        builder = cc._Builder([])
        kwargs = dict(scope_kind="INTERFACE", scope_id="E1", field="x", existing=1, incoming=2, existing_source="a", incoming_source="b")
        builder.conflict(**kwargs)
        builder.conflict(**kwargs)
        self.assertEqual(len(builder.conflicts), 1)

    def test_composition_conflict_to_dict_returns_every_field(self):
        item = cc.CompositionConflict("INTERFACE", "E1", "identity", "if_a", "if_b", "interfaces.if_a", "interfaces.if_b")
        self.assertEqual(item.to_dict(), {"scope_kind": "INTERFACE", "scope_id": "E1", "field": "identity", "existing": "if_a",
                                          "incoming": "if_b", "existing_source": "interfaces.if_a", "incoming_source": "interfaces.if_b"})

    def test_add_single_returns_after_claiming_a_slot_and_accepts_an_identical_claim(self):
        builder = cc._Builder([{"id": "if_c", "name": "Ethernet1"}])
        self.assertIsNone(builder.add_single("if_c", "fhrp", "IPV4", {"vip": "10.0.0.1"}, semantic={"vip": "10.0.0.1"}, source="fhrp.a"))
        builder.add_single("if_c", "fhrp", "IPV4", {"vip": "10.0.0.1"}, semantic={"vip": "10.0.0.1"}, source="fhrp.b")
        self.assertEqual((builder.by_id["if_c"]["_scope"]["fhrp"], builder.conflicts), ([{"vip": "10.0.0.1"}], []))

    def test_add_single_conflicting_claim_or_unknown_interface_is_refused(self):
        builder = cc._Builder([{"id": "if_c", "name": "Ethernet1"}])
        builder.add_single("if_c", "fhrp", "IPV4", {"vip": "1"}, semantic={"vip": "1"}, source="fhrp.a")
        builder.add_single("if_c", "fhrp", "IPV4", {"vip": "2"}, semantic={"vip": "2"}, source="fhrp.b")
        builder.add_single("if_unknown", "fhrp", "IPV4", {"vip": "3"}, semantic={"vip": "3"}, source="fhrp.c")
        self.assertEqual(builder.by_id["if_c"]["_scope"]["fhrp"], [{"vip": "1"}])
        self.assertEqual([(c.field, c.existing_source, c.incoming_source) for c in builder.conflicts], [("fhrp.IPV4", "fhrp.a", "fhrp.b")])

    def test_add_many_returns_after_appending_distinct_contributions(self):
        builder = cc._Builder([{"id": "if_c", "name": "Ethernet1"}])
        for destination in ("10.9.9.9", "10.9.9.8"):
            self.assertIsNone(builder.add_many("if_c", "dhcp_relays", "IPV4", {"destination": destination}, semantic=destination))
        self.assertEqual(builder.by_id["if_c"]["_scope"]["dhcp_relays"], [{"destination": "10.9.9.9"}, {"destination": "10.9.9.8"}])

    def test_add_many_duplicate_or_unknown_interface_adds_nothing(self):
        builder = cc._Builder([{"id": "if_c", "name": "Ethernet1"}])
        builder.add_many("if_c", "dhcp_relays", "IPV4", {"destination": "10.9.9.9"}, semantic="10.9.9.9")
        builder.add_many("if_c", "dhcp_relays", "IPV4", {"destination": "10.9.9.9"}, semantic="10.9.9.9")
        builder.add_many("if_unknown", "dhcp_relays", "IPV4", {"destination": "10.9.9.7"}, semantic="10.9.9.7")
        self.assertEqual(builder.by_id["if_c"]["_scope"]["dhcp_relays"], [{"destination": "10.9.9.9"}])

    def test_compose_returns_the_normalized_candidate(self):
        result = cc.compose(field_values={"hostname": "R1"}, interfaces=[{"id": "if_c", "name": "Ethernet1"}], routing={}, phase12={},
                            process_scope_key=lambda family, row: (family, row.get("id")))
        self.assertEqual(result["field_values"], {"hostname": "R1"})
        self.assertEqual([row["name"] for row in result["interfaces"]], ["Ethernet1"])
        self.assertEqual(result["conflicts"], [])
        self.assertEqual(set(result), {"field_values", "interfaces", "routing", "phase12", "global", "conflicts"})


class StructureTests(SimpleTestCase):
    def test_node_descendants_and_span_return_every_nested_line(self):
        tree = structure.parse("router bgp 1\n   address-family ipv4\n      network 10.0.0.0/8\n   bgp log\n")
        root = tree.roots[0]
        self.assertEqual([n.number for n in root.descendants()], [2, 3, 4])
        self.assertEqual(root.span(), [1, 2, 3, 4])
        self.assertEqual(tree.node(3).span(), [3])

    def test_normalize_returns_single_spaced_text(self):
        self.assertEqual(structure.normalize("  ip   route  0.0.0.0/0\t10.0.0.1 "), "ip route 0.0.0.0/0 10.0.0.1")

    def test_normalize_of_empty_or_none_is_empty(self):
        self.assertEqual((structure.normalize(""), structure.normalize(" \t ")), ("", ""))

    def test_vlan_ids_returns_the_expanded_vlan_list(self):
        self.assertEqual(structure.vlan_ids("10,20-22"), [10, 20, 21, 22])

    def test_vlan_ids_of_invalid_text_is_empty(self):
        self.assertEqual(structure.vlan_ids("none"), [])


class RemovalTests(SimpleTestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.model = semantics.build_model(EOS, "arista_ceos")

    def test_support_status_of_unsupported_platforms_or_unvalidated_kinds_is_not_executable(self):
        cases = {("sonic", "acl"): removal.NOT_IMPLEMENTED, ("ubuntu_frr", "acl"): removal.FIXTURE_ONLY,
                 ("arista_ceos", "nat_pool"): removal.FIXTURE_ONLY}
        for (platform, kind), expected in cases.items():
            with self.subTest(case=f"refused {platform} {kind}"):
                self.assertEqual(removal.support_status(platform, kind), expected)
                self.assertFalse(removal.executable(platform, kind))

    def test_item_support_kind_returns_object_and_attribute_kinds(self):
        self.assertEqual(removal.item_support_kind({"kind": "acl"}), "acl")
        self.assertEqual(removal.item_support_kind({"kind": "attribute", "attribute_kind": "mtu"}), "attribute:mtu")

    def test_item_support_kind_of_an_unclassified_attribute_is_other(self):
        with self.subTest(case="unknown attribute kind"):
            self.assertEqual(removal.item_support_kind({"kind": "attribute"}), "attribute:other")

    def test_content_hash_returns_a_stable_order_independent_digest(self):
        self.assertEqual(removal.content_hash({"b": 1, "a": [2]}), removal.content_hash({"a": [2], "b": 1}))
        self.assertRegex(removal.content_hash({}), r"^[0-9a-f]{64}$")

    def test_content_hash_of_different_content_never_collides(self):
        self.assertNotEqual(removal.content_hash({"a": 1}), removal.content_hash({"a": 2}))

    def test_object_catalogue_returns_every_managed_object_with_support(self):
        rows = {row["id"]: row for row in removal.object_catalogue(EOS, "arista_ceos")}
        self.assertNotIn("unmanaged:38", rows)
        self.assertEqual(rows["acl:EDGE-IN"], {"id": "acl:EDGE-IN", "kind": "acl", "label": "ACL EDGE-IN", "lines": [15, 16, 17], "removable": True,
                                               "reason": "", "parent": "", "operation": semantics.REMOVE_DELETE, "support": removal.PARSER_VALIDATED})
        self.assertEqual((rows["vlan:200"]["removable"], rows["vlan:200"]["reason"]), (False, semantics.PROTECTED_MANAGEMENT))

    def test_object_catalogue_of_an_empty_config_is_empty(self):
        self.assertEqual(removal.object_catalogue("", "arista_ceos"), [])

    def test_resolve_line_range_returns_whole_objects_and_removable_attributes(self):
        objects, attributes, blockers = removal.resolve_line_range(self.model, 15, 17)
        self.assertEqual((objects, attributes, blockers), (["acl:EDGE-IN"], [], []))
        objects, attributes, blockers = removal.resolve_line_range(self.model, 3, 3)
        self.assertEqual((objects, attributes, blockers), ([], [3], []))

    def test_resolve_line_range_blocks_out_of_range_partial_and_unremovable_selections(self):
        cases = {"out of range": ((0, 2), removal.OUT_OF_RANGE), "beyond end": ((1, 999), removal.OUT_OF_RANGE),
                 "partial context": ((2, 3), removal.PARTIAL_CONTEXT), "unremovable line": ((17, 17), removal.NOT_REMOVABLE)}
        for label, ((start, end), code) in cases.items():
            with self.subTest(case=f"refused {label}"):
                _objects, _attributes, blockers = removal.resolve_line_range(self.model, start, end)
                self.assertEqual(blockers[0]["code"], code)
        empty = semantics.build_model("interface Loopback0\n\n\n", "arista_ceos")
        with self.subTest(case="refused empty selection"):
            self.assertEqual(removal.resolve_line_range(empty, 2, 3)[2][0]["code"], removal.EMPTY_SELECTION)


class ContributionTests(SimpleTestCase):
    def test_contribution_error_returns_joined_problems(self):
        error = contribution.ContributionError(["a", "b"])
        self.assertEqual((error.problems, str(error)), (["a", "b"], "a; b"))

    def test_contribution_error_of_no_problems_is_empty(self):
        self.assertEqual(str(contribution.ContributionError([])), "")

    def test_snapshot_context_returns_interfaces_processes_and_protected_interfaces(self):
        self.assertEqual(contribution.snapshot_context(EOS, "arista_ceos"), {
            "interfaces": ["Ethernet1", "Management0", "Vlan10"], "bgp_processes": ["65001"], "ospf_processes": ["1"],
            "protected_interfaces": ["Management0"]})

    def test_snapshot_context_of_an_empty_config_has_no_objects(self):
        self.assertEqual(contribution.snapshot_context("", "arista_ceos"),
                         {"interfaces": [], "bgp_processes": [], "ospf_processes": [], "protected_interfaces": []})

    def test_check_operation_accepts_valid_operations_on_the_device(self):
        context = contribution.snapshot_context(EOS, "arista_ceos")
        for op in ({"op": "static_route", "destination": "10.9.0.0/16", "next_hop": "10.0.10.2"},
                   {"op": "interface_address", "interface": "Vlan10", "cidr": "10.0.12.1/24"},
                   {"op": "bgp_network", "cidr": "10.7.0.0/16"}):
            with self.subTest(case=f"accepts {op['op']}"):
                self.assertEqual(contribution.check_operation(op, "arista_ceos", context), [])

    def test_check_operation_refuses_unknown_incomplete_invalid_or_protected_operations(self):
        context = contribution.snapshot_context(EOS, "arista_ceos")
        cases = {"unknown operation": ({"op": "reboot"}, "Unknown operation 'reboot'."),
                 "missing field": ({"op": "static_route", "destination": "10.0.0.0/8"}, "Static route: next hop is required."),
                 "missing interface": ({"op": "dhcp_relay", "interface": "Vlan99", "destination": "10.9.9.9"}, "Interface Vlan99 does not exist on the device."),
                 "protected interface": ({"op": "interface_address", "interface": "Management0", "cidr": "10.0.0.1/24"},
                                         "Interface Management0 is part of the protected management plane."),
                 "existing loopback": ({"op": "loopback", "name": "Vlan10"}, "Vlan10 already exists; use 'Address on an existing interface'."),
                 "invalid prefix": ({"op": "bgp_network", "cidr": "10.0.0.0/99"}, "'10.0.0.0/99' is not a valid address or prefix.")}
        for label, (op, problem) in cases.items():
            with self.subTest(case=f"refused {label}"):
                self.assertIn(problem, contribution.check_operation(op, "arista_ceos", context))
        empty = contribution.snapshot_context("", "arista_ceos")
        with self.subTest(case="refused without a bgp process"):
            self.assertIn("The device has no BGP process to attach to (create it through Device Builder).",
                          contribution.check_operation({"op": "bgp_network", "cidr": "10.0.0.0/8"}, "arista_ceos", empty))

    def test_parse_direct_cli_rejects_secret_negating_unknown_and_contextless_lines(self):
        fragment = ("username admin secret Sup3rSecretValue!\nno ip route 0.0.0.0/0 10.0.0.1\nhostname evil\n   description x\n"
                    "interface Ethernet9\nrouter bgp 99\ninterface Vlan10\n   shutdown\nrouter bgp 65001\n   timers bgp 1 3\n")
        result = contribution.parse_direct_cli(fragment, "arista_ceos", EOS)
        self.assertEqual(result["operations"], [])
        self.assertEqual([r["reason"] for r in result["rejected"]], [
            "SECRET_MATERIAL_REFUSED", "REMOVAL_BELONGS_IN_REMOVE_CONFIGURATION", "UNRECOGNISED_STATEMENT", "NO_RECOGNISED_CONTEXT",
            "INTERFACE_NOT_ON_DEVICE", "BGP_PROCESS_NOT_ON_DEVICE", "UNRECOGNISED_STATEMENT", "UNRECOGNISED_STATEMENT"])
        self.assertNotIn("Sup3rSecretValue", repr(result))
        self.assertEqual(contribution.parse_direct_cli("  ", "arista_ceos", EOS), {"operations": [], "rejected": [{"line": 0, "text": "", "reason": "EMPTY"}]})
