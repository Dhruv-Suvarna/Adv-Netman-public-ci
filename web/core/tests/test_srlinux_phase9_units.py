"""V2 Phase 9 -- the SR Linux routing / ACL / DHCP-relay building blocks, each called directly (pure, no device).

POSITIVE: a leaf-list Configlet is sent widened by the members the node already holds and inverted back to them, the
statement / key helpers spell the 24.10.7 grammar, the gNMI state readers report OSPF adjacencies, BGP sessions, ACLs and
relays exactly as the health model spells them, and the routing rows / policy name are the planner's.  NEGATIVE: an
unmodelled or non-``set`` statement is refused (or not invertible: None), a scalar leaf is never widened, and empty
gNMI state or configuration yields no adjacency, session, row or relay.
"""

from __future__ import annotations

import json

from django.test import SimpleTestCase

from core.services import platform_drivers
from core.services import srlinux_model as model
from core.services.capabilities import batch_srlinux_phase9 as P
from core.services.execution.executors import srlinux
from core.services.health import evaluators, live, routing_config

RELAY = "set / interface ethernet-1/1 subinterface 0 ipv4 dhcp-relay server [ 192.0.2.1 ]"
HELD = {"interface": [{"name": "ethernet-1/1", "subinterface": [{"index": 0, "ipv4": {"dhcp-relay": {"server": ["192.0.2.99"]}}}]}]}


def _tree(*groups) -> dict:
    tree: dict = {}
    for lines in groups:
        for op in model.additive(model.operations(lines), tree):
            model.apply_operation(tree, op)
    return tree


def _gnmi(tree: dict) -> str:
    return json.dumps({"notification": [{"update": [{"path": "", "val": tree}]}]})


class SrLinuxLeafListExecutionTests(SimpleTestCase):
    def test_outgoing_sends_the_held_members_plus_the_configlet_member(self):
        self.assertEqual(srlinux.outgoing([RELAY], HELD),
                         ["set / interface ethernet-1/1 subinterface 0 ipv4 dhcp-relay server [ 192.0.2.99 192.0.2.1 ]"])
        self.assertEqual(srlinux.outgoing(["! comment", RELAY], {}), [RELAY])

    def test_outgoing_never_rewrites_a_scalar_statement(self):
        line = "set / interface ethernet-1/1 description lab"
        self.assertEqual(srlinux.outgoing([line], {"interface": [{"name": "ethernet-1/1", "description": "old"}]}), [line])

    def test_outgoing_refuses_text_that_is_not_a_set_statement(self):
        with self.assertRaises(model.ModelError):
            srlinux.outgoing(["delete / interface ethernet-1/1"], {})

    def test_config_inverse_restores_the_held_relay_members(self):
        self.assertEqual(srlinux.config_inverse([RELAY], HELD),
                         ["set / interface ethernet-1/1 subinterface 0 ipv4 dhcp-relay server [ 192.0.2.99 ]"])
        factory = {"acl": {"policers": {"system-cpu-policer": [{"name": "icmp"}]}}}    # 24.10.7 always holds the acl container
        self.assertEqual(srlinux.config_inverse(["set / acl acl-filter A type ipv4 entry 10 action accept"], factory),
                         ["delete / acl acl-filter A type ipv4"])

    def test_config_inverse_is_none_for_an_unmodelled_or_unbracketed_statement(self):
        self.assertIsNone(srlinux.config_inverse(["set / interface ethernet-1/1 subinterface 0 ipv4 dhcp-relay server 192.0.2.1"], {}))
        self.assertIsNone(srlinux.config_inverse(["set / system name host-name x"], {}))


class SrLinuxModelStatementTests(SimpleTestCase):
    def test_step_keys_and_values_of_a_multi_key_list(self):
        step = model.Step("acl-filter", ("name", "type"), ("A", "ipv4"))
        self.assertEqual((step.keys, step.values, step.cli, step.gnmi),
                         (("name", "type"), ("A", "ipv4"), "acl-filter A type ipv4", "acl-filter[name=A][type=ipv4]"))
        self.assertEqual((model.Step("ipv4").keys, model.Step("interface", "name", "e1").values), ((), ("e1",)))

    def test_statement_renders_a_leaf_list_leaf_and_container(self):
        ops = model.operations([RELAY, "set / interface ethernet-1/1 mtu 9000", "set / acl acl-filter A type ipv4 entry 10 action drop"],
                               strict=True)
        self.assertEqual([model.statement(op) for op in ops],
                         [RELAY, "set / interface ethernet-1/1 mtu 9000", "set / acl acl-filter A type ipv4 entry 10 action drop"])

    def test_statement_without_a_leaf_names_no_value(self):
        op = model.Operation((model.Step("interface", "name", "lo44"),), "", None)
        self.assertEqual(model.statement(op), "set / interface lo44")

    def test_additive_never_widens_a_scalar_leaf_or_an_absent_leaf_list(self):
        scalar = model.operations(["set / interface ethernet-1/1 mtu 9000"], strict=True)
        self.assertEqual(model.additive(scalar, {"interface": [{"name": "ethernet-1/1", "mtu": 1500}]}), scalar)
        relay = model.operations([RELAY], strict=True)
        self.assertEqual(model.additive(relay, {}), relay)
        self.assertEqual(model.additive(relay, {"interface": [{"name": "ethernet-1/1", "subinterface": [{"index": 0, "ipv4": {
            "dhcp-relay": {"server": []}}}]}]}), relay)

    def test_additive_keeps_a_member_already_held_only_once(self):
        relay = model.operations([RELAY], strict=True)
        held = {"interface": [{"name": "ethernet-1/1", "subinterface": [{"index": 0, "ipv4": {"dhcp-relay": {"server": ["192.0.2.1"]}}}]}]}
        self.assertEqual(model.additive(relay, held)[0].value, ("192.0.2.1",))


class SrLinuxStateReaderTests(SimpleTestCase):
    OSPF = {"network-instance": [{"name": "default", "protocols": {"ospf": {"instance": [
        {"name": "44", "version": "ospf-v3", "area": [{"area-id": "0.0.0.0", "interface": [
            {"interface-name": "ethernet-1/1.0", "neighbor": [{"router-id": "198.18.44.2", "adjacency-state": "full"},
                                                             {"adjacency-state": "init"}]}]}]},
        {"name": "45", "version": "ospf-v2", "area": [{"area-id": "0.0.0.0", "interface": [
            {"interface-name": "ethernet-1/2.5", "neighbor": [{"router-id": "198.18.44.3", "adjacency-state": "two-way"}]}]}]}]}}}]}
    BGP = {"network-instance": [{"name": "default", "protocols": {"bgp": {"neighbor": [
        {"peer-address": "2001:db8:44::2", "peer-as": 65045, "session-state": "established",
         "afi-safi": [{"afi-safi-name": "ipv4-unicast", "received-routes": 9}, {"afi-safi-name": "ipv6-unicast", "received-routes": 1}]},
        {"peer-address": "198.18.0.2", "peer-as": 65045, "session-state": "active",
         "afi-safi": [{"afi-safi-name": "ipv4-unicast", "received-routes": 0}]},
        {"peer-as": 1}]}}}]}

    def test_parse_srl_ospf_returns_adjacencies_with_the_parent_interface_name(self):
        self.assertEqual(live.parse_srl_ospf(_gnmi(self.OSPF)), [
            {"family": "OSPFV2", "neighbor_id": "198.18.44.3", "interface": "ethernet-1/2.5", "state": "TWO_WAY"},
            {"family": "OSPFV3", "neighbor_id": "198.18.44.2", "interface": "ethernet-1/1", "state": "FULL"}])

    def test_parse_srl_ospf_of_empty_state_has_no_adjacency(self):
        self.assertEqual((live.parse_srl_ospf(""), live.parse_srl_ospf(_gnmi({"network-instance": [{"name": "default"}]}))), ([], []))

    def test_parse_srl_bgp_returns_sessions_with_received_routes_of_their_family(self):
        self.assertEqual(live.parse_srl_bgp(_gnmi(self.BGP)), [
            {"peer": "198.18.0.2", "remote_as": "65045", "family": 4, "state": "ACTIVE", "prefixes_received": None},
            {"peer": "2001:db8:44::2", "remote_as": "65045", "family": 6, "state": "ESTABLISHED", "prefixes_received": 1}])

    def test_parse_srl_bgp_of_empty_state_has_no_session(self):
        self.assertEqual(live.parse_srl_bgp(_gnmi({})), [])

    def test_parse_srl_config_returns_acls_attachments_and_relays(self):
        acl = P.plan("service_policy.ACL_IPV4_STANDARD")
        relay = P.plan("service_policy.DHCP_RELAY_IPV4")
        tree = _tree(acl[0], *(spec.lines for spec in acl[1]), *(spec.lines for spec in relay[1]))
        self.assertEqual(live.parse_srl_config(_gnmi(tree)), {
            "acl_definitions": ["CAP_ACL"],
            "acl_attachments": [{"interface": "ethernet-1/1", "acl": "CAP_ACL", "direction": "IN"}],
            "dhcp_relays": [{"interface": "ethernet-1/1", "destination": "192.0.2.1"}]})

    def test_parse_srl_config_of_an_empty_configuration_has_no_acl_or_relay(self):
        self.assertEqual(live.parse_srl_config(_gnmi({})), {"acl_definitions": [], "acl_attachments": [], "dhcp_relays": []})

    def test_parse_srl_routes_names_ospf_routes_by_protocol(self):
        state = {"network-instance": [{"name": "default", "route-table": {"ipv4-unicast": {"route": [
            {"ipv4-prefix": "192.0.2.0/24", "route-type": "ospfv2", "active": True}]}}}]}
        self.assertEqual([r["type"] for r in live.parse_srl_routes(_gnmi(state))], ["ospf"])

    def test_srl_routing_reads_are_state_or_config_gets_never_writes(self):
        self.assertEqual({live.SRLINUX_QUERIES[k][1] for k in ("ospf", "bgp")}, {"state"})
        self.assertEqual(live.SRLINUX_QUERIES["running_config"], ("/", "config"))


class SrLinuxRoutingRowTests(SimpleTestCase):
    def test_srlinux_returns_the_planned_bgp_row(self):
        prerequisites, specs, _req, _sections = P.plan("routing.BGP_IPV4")
        (row,) = routing_config.srlinux(_tree(prerequisites, *(spec.lines for spec in specs)))
        self.assertEqual((row["protocol"], row["local_asn"], row["router_id"], row["networks"]),
                         ("bgp", 65044, "198.18.44.1", [{"family": "IPV4", "cidr": "203.0.113.0/24"}]))
        self.assertEqual([(n["peer_address"], n["activate_ipv4"], n["activate_ipv6"]) for n in row["neighbors"]], [("198.18.0.2", True, False)])

    def test_srlinux_of_an_empty_tree_has_no_rows(self):
        self.assertEqual(routing_config.srlinux({}), [])

    def test_srl_bgp_policy_name_returns_the_instance_policy(self):
        self.assertEqual(platform_drivers.srl_bgp_policy_name({"id": "bgp_0000000000000003"}), "nmas-bgp-bgp_0000000000000003")

    def test_srl_bgp_policy_name_without_an_id_is_the_instance_default(self):
        self.assertEqual(platform_drivers.srl_bgp_policy_name({}), "nmas-bgp-instance")

    def test_family_label_of_an_empty_or_unknown_value_is_not_a_family(self):
        self.assertEqual((evaluators.family_label(None), evaluators.family_label(""), evaluators.family_label("ospf")), ("", "", "OSPF"))
