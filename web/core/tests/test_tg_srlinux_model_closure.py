"""Lab 7 closure -- the SR Linux data-model primitives (``srlinux_model``), each called directly.

These conversions decide what an SR Linux write and its rollback look like, so exactness matters in both directions.
POSITIVE: paths, values, statements, trees, digests and inverses are exactly the documented shapes.  NEGATIVE: comment
lines and module qualifiers are dropped, non-``set`` text and an unbracketed leaf-list member are refused, an unprovable
inverse (a non-scalar captured value) is None so the caller fails closed, and an empty gNMI response is an empty tree.  Pure.
"""

from __future__ import annotations

from django.test import SimpleTestCase

from core.services import srlinux_model as sm

IFACE = sm.Step("interface", "name", "ethernet-1/1")
SUB = sm.Step("subinterface", "index", 0)


class StepAndValueTests(SimpleTestCase):
    def test_step_cli_gnmi_and_operation_schema(self):
        self.assertEqual((IFACE.cli, IFACE.gnmi), ("interface ethernet-1/1", "interface[name=ethernet-1/1]"))
        self.assertEqual((sm.Step("ipv4").cli, sm.Step("ipv4").gnmi), ("ipv4", "ipv4"))
        self.assertEqual(sm.Operation((IFACE, SUB, sm.Step("ipv4")), "admin-state", "enable").schema, "interface/subinterface/ipv4")

    def test_cli_and_gnmi_paths_with_a_leaf_returns_the_joined_path(self):
        self.assertEqual(sm.cli_path((IFACE, SUB), "description"), "interface ethernet-1/1 subinterface 0 description")
        self.assertEqual(sm.gnmi_path((IFACE, SUB), "description"), "/interface[name=ethernet-1/1]/subinterface[index=0]/description")

    def test_cli_and_gnmi_paths_of_no_steps_are_the_root_only(self):
        self.assertEqual((sm.cli_path(()), sm.gnmi_path(())), ("", "/"))

    def test_format_value_of_plain_tokens_and_booleans(self):
        self.assertEqual([sm.format_value(v) for v in ("lab", 9000, True, False)], ["lab", "9000", "true", "false"])

    def test_format_value_quotes_empty_spaced_or_hash_values_never_leaving_them_bare(self):
        self.assertEqual([sm.format_value(v) for v in ("", "two words", 'q"uote', "a#b")], ['""', '"two words"', '"q\\"uote"', '"a#b"'])


class StatementTests(SimpleTestCase):
    def test_statements_keep_set_lines_in_order(self):
        self.assertEqual(sm.statements(["set / interface ethernet-1/1 admin-state enable", "  set / system name host-name R1  "]),
                         ["set / interface ethernet-1/1 admin-state enable", "set / system name host-name R1"])

    def test_statements_drop_comments_and_refuse_other_text(self):
        self.assertEqual(sm.statements(["! note", "# hash", "   ", ""]), [])
        with self.assertRaisesRegex(sm.ModelError, "Not an SR Linux set statement"):
            sm.statements(["delete / interface ethernet-1/1"])

    def test_looks_like_set_lines_of_rendered_statements(self):
        self.assertTrue(sm.looks_like_set_lines("! c\nset / interface ethernet-1/1 admin-state enable\n"))

    def test_looks_like_set_lines_is_false_for_json_or_text_without_set(self):
        self.assertFalse(sm.looks_like_set_lines('{"interface": []}\nset x'))
        self.assertFalse(sm.looks_like_set_lines("interface ethernet-1/1\n"))
        self.assertFalse(sm.looks_like_set_lines(""))


class TreeTests(SimpleTestCase):
    def test_normalize_strips_module_qualifiers_and_annotations(self):
        value = {"srl_nokia-interfaces:interface": [{"name": "ethernet-1/1", "admin-state": "srl_nokia-common:enable", "_annotate": {"x": 1}}]}
        self.assertEqual(sm.normalize(value), {"interface": [{"name": "ethernet-1/1", "admin-state": "enable"}]})

    def test_normalize_never_strips_a_foreign_prefix_or_changes_scalars(self):
        self.assertEqual(sm.normalize({"openconfig:x": "other:value", "n": 5, "b": None}), {"openconfig:x": "other:value", "n": 5, "b": None})

    def test_tree_from_gnmi_merges_rooted_and_keyed_updates(self):
        response = {"notification": [{"update": [
            {"path": "", "val": {"srl_nokia-system:system": {"name": {"host-name": "R1"}}}},
            {"path": "interface[name=ethernet-1/1]", "val": {"admin-state": "enable"}},
            {"path": "interface[name=ethernet-1/1]/mtu", "val": 9000}]}]}
        self.assertEqual(sm.tree_from_gnmi(response), {"system": {"name": {"host-name": "R1"}},
                                                       "interface": [{"name": "ethernet-1/1", "admin-state": "enable", "mtu": 9000}]})

    def test_tree_from_gnmi_of_an_empty_or_missing_response_is_empty(self):
        self.assertEqual((sm.tree_from_gnmi({}), sm.tree_from_gnmi(None), sm.tree_from_gnmi({"notification": [{"update": None}]})), ({}, {}, {}))
        self.assertEqual(sm.tree_from_gnmi({"notification": [{"update": [{"path": "", "val": "scalar"}]}]}), {})

    def test_digest_text_is_order_independent_for_keyed_lists(self):
        a = {"interface": [{"name": "e1"}, {"name": "e2"}], "b": 1}
        b = {"b": 1, "interface": [{"name": "e2"}, {"name": "e1"}]}
        self.assertEqual(sm.digest_text(a), sm.digest_text(b))
        self.assertEqual(sm.digest_text({"b": 1}), '{"b":1}')

    def test_digest_text_of_a_changed_or_empty_tree_differs(self):
        self.assertNotEqual(sm.digest_text({"interface": [{"name": "e1", "mtu": 1500}]}), sm.digest_text({"interface": [{"name": "e1", "mtu": 9000}]}))
        self.assertEqual(sm.digest_text({}), "{}")


class InverseTests(SimpleTestCase):
    TREE = {"interface": [{"name": "ethernet-1/1", "description": "old", "admin-state": "enable",
                           "subinterface": [{"index": 0, "ipv4": {"address": [{"ip-prefix": "10.0.0.1/31"}]}}]}]}

    def ops(self, *lines):
        return sm.operations(lines, strict=True)

    def test_inverse_deletes_new_nodes_and_restores_replaced_leaves(self):
        found = sm.inverse(self.ops("set / interface ethernet-1/1 description new",
                                    "set / interface ethernet-1/1 subinterface 0 ipv4 address 10.0.0.9/31",
                                    "set / interface ethernet-1/2 admin-state enable",
                                    "set / interface ethernet-1/1 mtu 9000"), self.TREE)
        self.assertEqual(found, ["delete / interface ethernet-1/2", "delete / interface ethernet-1/1 subinterface 0 ipv4 address 10.0.0.9/31",
                                 "delete / interface ethernet-1/1 mtu", "set / interface ethernet-1/1 description old"])
        self.assertEqual(sm.inverse(self.ops("set / interface ethernet-1/1 admin-state enable"), self.TREE), [])

    def test_inverse_deletes_a_new_leaf_list_and_restores_a_replaced_one(self):
        relay = self.ops("set / interface ethernet-1/1 subinterface 0 ipv4 dhcp-relay server [ 192.0.2.9 ]")
        empty = {"interface": [{"name": "ethernet-1/1", "subinterface": [{"index": 0, "ipv4": {"dhcp-relay": {}}}]}]}
        held = {"interface": [{"name": "ethernet-1/1", "subinterface": [{"index": 0, "ipv4": {"dhcp-relay": {"server": ["192.0.2.7"]}}}]}]}
        self.assertEqual(sm.inverse(relay, empty), ["delete / interface ethernet-1/1 subinterface 0 ipv4 dhcp-relay server"])
        self.assertEqual(sm.inverse(relay, held), ["set / interface ethernet-1/1 subinterface 0 ipv4 dhcp-relay server [ 192.0.2.7 ]"])

    def test_inverse_is_none_for_an_unbracketed_leaf_list_or_a_non_scalar_captured_value(self):
        with self.assertRaises(sm.ModelError):
            self.ops("set / interface ethernet-1/1 subinterface 0 ipv4 dhcp-relay server 192.0.2.9")
        self.assertIsNone(sm.inverse(self.ops("set / interface ethernet-1/1 description x"), {"interface": [{"name": "ethernet-1/1", "description": {"a": 1}}]}))

    def test_operations_refuse_unmodelled_or_malformed_statements(self):
        for name, line in (("unmodelled", "set / acl ipv4-filter X entry 10 action accept"), ("unbalanced", 'set / interface "e1 admin-state enable'),
                           ("empty", "set /"), ("keyless", "set / interface"), ("root leaf", "set / hostname R1")):
            with self.subTest(case=f"refused {name}"), self.assertRaises(sm.ModelError):
                sm.operations([line], strict=True)
