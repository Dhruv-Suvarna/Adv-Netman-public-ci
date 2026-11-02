"""SR Linux shared model, gNMI executor, state reader and import parser (no device: a tree-backed fake gNMI node)."""

from __future__ import annotations

import copy
import json

from django.test import SimpleTestCase

from core.services import platform_drivers, srlinux_model as model
from core.services.capabilities import batch_srlinux
from core.services.config_import import parser_srlinux
from core.services.execution import capability, transport_capability
from core.services.execution.executors import registry
from core.services.execution.executors.base import ConfigletSpec, ExecutorError
from core.services.execution.executors.srlinux import SrLinuxExecutor
from core.services.execution.writers.srlinux_gnmi import GnmiError, GnmiSession
from core.services.health import live

BASE = ["set interface ethernet-1/1 admin-state enable", "set interface mgmt0 admin-state enable",
        "set interface mgmt0 subinterface 0 admin-state enable", "set network-instance mgmt interface mgmt0.0"]
LOOPBACK = ["set interface lo44 admin-state enable", 'set interface lo44 description "NMAS isolated assessment"',
            "set interface lo44 subinterface 0 admin-state enable", "set network-instance default interface lo44.0"]
ADDRESS = ["set interface lo44 subinterface 0 ipv4 admin-state enable", "set interface lo44 subinterface 0 ipv4 address 198.18.0.1/30"]
ROUTE = ["set network-instance default static-routes route 203.0.113.0/24 admin-state enable",
         "set network-instance default static-routes route 203.0.113.0/24 preference 200",
         "set network-instance default static-routes route 203.0.113.0/24 next-hop-group nhg-1",
         "set network-instance default next-hop-groups group nhg-1 nexthop 1 ip-address 198.18.0.2"]


def _qualified(value, top=True):
    """Re-create the JSON_IETF module qualifiers a real node returns, so normalisation is exercised on every read."""
    if isinstance(value, dict):
        return {(f"srl_nokia-x:{k}" if top else k): _qualified(v, False) for k, v in value.items()}
    if isinstance(value, list):
        return [_qualified(v, False) for v in value]
    return f"srl_nokia-interfaces:{value}" if value == "routed" else value


class FakeNode:
    """A gNMI client over one in-memory configuration tree: Set is atomic, exactly like the device."""

    def __init__(self, lines=BASE):
        self.tree = model.tree_from_set_lines(lines)
        self.sets, self.reject, self.drift = [], False, None

    def get(self, path, datatype, encoding):
        assert (path, datatype, encoding) == (["/"], "config", "json_ietf")
        return {"notification": [{"update": [{"path": None, "val": _qualified(copy.deepcopy(self.tree))}]}]}

    def set(self, update, encoding):
        ((origin, text),) = update
        assert (origin, encoding) == ("cli:/", "ascii")
        self.sets.append(text.splitlines())
        if self.reject:
            raise RuntimeError("Error in path: .interface  [InvalidArgument] rejected")
        working = copy.deepcopy(self.tree)
        for line in text.splitlines():
            verb, rest = line.split(" / ", 1)
            if verb == "set":
                model.apply_operation(working, model.operation(f"set {rest}"))
                continue
            op = model.operation(f"set {rest}")
            steps, leaf = (op.steps, op.leaf) if op.leaf else (op.steps[:-1], op.steps[-1])
            parent = model.lookup(working, steps)
            assert parent is not model.MISSING, line
            if isinstance(leaf, str):
                parent.pop(leaf)
            elif leaf.key:
                parent[leaf.name] = [row for row in parent[leaf.name] if str(row[leaf.key]) != str(leaf.value)]
                if not parent[leaf.name]:
                    parent.pop(leaf.name)
            else:
                parent.pop(leaf.name)
        self.tree = working
        if self.drift:
            model.apply_operation(self.tree, model.operation(self.drift))

    def close(self):
        pass


def _spec(n, kind, lines, **kwargs):
    return ConfigletSpec(f"CFG-{n}", n, "srl", "nokia_srlinux", kind, "CREATE_DEFINE", tuple(lines), **kwargs)


def _executor(node):
    executor = SrLinuxExecutor({"name": "srl", "platform": "nokia_srlinux"}, connection_factory=lambda _d: GnmiSession(client=node))
    executor.connect()
    return executor


class ModelTests(SimpleTestCase):
    def test_set_lines_build_the_keyed_tree(self):
        tree = model.tree_from_set_lines([*LOOPBACK, *ADDRESS, *ROUTE, "! comment", ""])
        lo = next(i for i in tree["interface"] if i["name"] == "lo44")
        self.assertEqual(lo["description"], "NMAS isolated assessment")
        self.assertEqual(lo["subinterface"][0], {"index": 0, "admin-state": "enable",
                                                 "ipv4": {"admin-state": "enable", "address": [{"ip-prefix": "198.18.0.1/30"}]}})
        ni = tree["network-instance"][0]
        self.assertEqual(ni["interface"], [{"name": "lo44.0"}])
        self.assertEqual(ni["static-routes"]["route"][0]["preference"], 200)
        self.assertEqual(ni["next-hop-groups"]["group"][0]["nexthop"], [{"index": 1, "ip-address": "198.18.0.2"}])

    def test_gnmi_json_ietf_is_normalised(self):
        response = {"notification": [{"update": [
            {"path": "srl_nokia-interfaces:interface[name=ethernet-1/1]/subinterface[index=0]",
             "val": {"type": "srl_nokia-interfaces:routed", "srl_nokia-interfaces-nbr:arp": {"timeout": 1}}},
            {"path": None, "val": {"_annotate": "x", "srl_nokia-system:system": {"name": {"host-name": "srl"}}}}]}]}
        tree = model.tree_from_gnmi(response)
        self.assertEqual(tree["interface"][0]["subinterface"][0], {"index": 0, "type": "routed", "arp": {"timeout": 1}})
        self.assertEqual(tree["system"], {"name": {"host-name": "srl"}})

    def test_inverse_deletes_only_the_topmost_node_that_was_absent(self):
        pristine = model.tree_from_set_lines(BASE)
        self.assertEqual(model.inverse(model.operations(LOOPBACK), pristine),
                         ["delete / network-instance default", "delete / interface lo44"])
        existing = model.tree_from_set_lines([*BASE, *LOOPBACK])
        self.assertEqual(model.inverse(model.operations(ADDRESS), existing), ["delete / interface lo44 subinterface 0 ipv4"])
        enabled = model.tree_from_set_lines([*BASE, *LOOPBACK, ADDRESS[0]])
        self.assertEqual(model.inverse(model.operations(ADDRESS), enabled),
                         ["delete / interface lo44 subinterface 0 ipv4 address 198.18.0.1/30"])

    def test_inverse_restores_replaced_values_and_is_empty_when_satisfied(self):
        seeded = model.tree_from_set_lines([*BASE, *[line.replace("NMAS isolated assessment", "legacy loopback") for line in LOOPBACK]])
        self.assertEqual(model.inverse(model.operations(LOOPBACK), seeded), ['set / interface lo44 description "legacy loopback"'])
        self.assertEqual(model.inverse(model.operations(LOOPBACK), model.tree_from_set_lines([*BASE, *LOOPBACK])), [])

    def test_unmodelled_and_multi_valued_statements_fail_closed(self):
        for line in ("set system name host-name X", "set network-instance default protocols bgp autonomous-system 65001",
                     "set acl ipv4-filter A entry 10 action accept"):
            with self.assertRaises(model.ModelError):
                model.operation(line, strict=True)
        with self.assertRaises(model.ModelError):
            model.statements(["hostname not-srlinux"])
        relay = model.operations(["set interface ethernet-1/1 subinterface 0 ipv4 dhcp-relay server 192.0.2.1"])
        self.assertIsNone(model.inverse(relay, model.tree_from_set_lines(BASE + relay_lines())))


def relay_lines():
    return ["set interface ethernet-1/1 subinterface 0 ipv4 dhcp-relay server 192.0.2.9"]


class ExecutorTests(SimpleTestCase):
    def test_registered_through_the_shared_execution_architecture(self):
        self.assertIsInstance(registry.executor_for({"name": "srl", "platform": "nokia_srlinux"}), SrLinuxExecutor)
        for kind in ("interface", "address", "static_route"):
            cap = capability.capability_for("nokia_srlinux", kind)
            self.assertEqual((cap.apply, cap.compensation, cap.transport), ("SUPPORTED", "SUPPORTED", "gnmi-set"))
        self.assertEqual(capability.capability_for("nokia_srlinux", "routing_bgp").apply, "NOT_IMPLEMENTED")
        self.assertEqual(transport_capability.selected_transport("nokia_srlinux"), "GNMI_SET")
        with self.assertRaises(ExecutorError):
            registry.executor_for({"name": "x", "platform": "sonic"})

    def test_transaction_applies_atomically_and_compensates_to_the_exact_capture(self):
        node = FakeNode()
        before = copy.deepcopy(node.tree)
        executor = _executor(node)
        specs = [_spec(1, "interface", LOOPBACK), _spec(2, "address", ADDRESS), _spec(3, "static_route", ROUTE)]
        preflights = [executor.assess(spec) for spec in specs]
        self.assertEqual([(p.action, p.restorable) for p in preflights], [("APPLY", True)] * 3)
        self.assertFalse(node.sets)                                   # preflight never writes
        for spec, preflight in zip(specs, preflights):
            self.assertTrue(executor.apply(spec, preflight).ok)
        self.assertEqual(node.sets[0], [f"set / {line[4:]}" for line in LOOPBACK])     # one SetRequest per Configlet
        self.assertTrue(any(r.destination == "203.0.113.0/24" and r.next_hop_address == "198.18.0.2"
                            for r in parser_srlinux.parse(executor.config_tree()).static_routes))
        statuses = [executor.compensate(spec, preflight).status for spec, preflight in reversed(list(zip(specs, preflights)))]
        self.assertEqual(statuses, ["COMPENSATED"] * 3)
        self.assertEqual(node.tree, before)
        # the route Configlet found the network-instance already created by the interface Configlet: it removes only its own
        self.assertEqual(node.sets[3], ["delete / network-instance default next-hop-groups",
                                        "delete / network-instance default static-routes"])

    def test_existing_object_keeps_unrelated_configuration(self):
        seed = [*BASE, *[line.replace("NMAS isolated assessment", "legacy") for line in LOOPBACK],
                "set interface lo44 subinterface 0 ipv4 admin-state enable", "set interface lo44 subinterface 0 ipv4 address 198.18.7.1/32"]
        node = FakeNode(seed)
        before = copy.deepcopy(node.tree)
        executor = _executor(node)
        specs = [_spec(1, "interface", LOOPBACK), _spec(2, "address", ADDRESS)]
        preflights = [executor.assess(spec) for spec in specs]
        for spec, preflight in zip(specs, preflights):
            self.assertTrue(executor.apply(spec, preflight).ok)
        for spec, preflight in reversed(list(zip(specs, preflights))):
            self.assertEqual(executor.compensate(spec, preflight).status, "COMPENSATED")
        self.assertEqual(node.sets[-2:], [["delete / interface lo44 subinterface 0 ipv4 address 198.18.0.1/30"],
                                          ['set / interface lo44 description legacy']])
        self.assertEqual(node.tree, before)

    def test_satisfied_configlet_is_skipped_and_never_sent(self):
        node = FakeNode([*BASE, *LOOPBACK])
        executor = _executor(node)
        self.assertEqual(executor.assess(_spec(1, "interface", LOOPBACK)).action, "SKIP_SATISFIED")
        self.assertFalse(node.sets)

    def test_refuses_what_it_cannot_invert(self):
        executor = _executor(FakeNode())
        for spec in (_spec(1, "routing_bgp", ["set network-instance default protocols bgp autonomous-system 65001"]),
                     _spec(2, "interface", ["set system name host-name X"]),
                     _spec(3, "interface", LOOPBACK, origin="RAW"), _spec(4, "interface", ())):
            found = executor.assess(spec)
            self.assertEqual((found.action, found.restorable), ("REFUSE", False))

    def test_rejected_set_has_no_partial_effect_and_drift_is_not_reported_restored(self):
        node = FakeNode()
        executor = _executor(node)
        spec = _spec(1, "interface", LOOPBACK)
        preflight = executor.assess(spec)
        node.reject = True
        outcome = executor.apply(spec, preflight)
        self.assertEqual((outcome.ok, outcome.error_code, outcome.partial_effects), (False, "COMMAND_REJECTED", False))
        self.assertEqual(executor.compensate(spec, preflight).detail, {"action": "NONE_NEEDED"})
        node.reject = False
        self.assertTrue(executor.apply(spec, preflight).ok)
        node.drift = "set interface ethernet-1/1 description drift"
        failed = executor.compensate(spec, preflight)
        self.assertEqual((failed.status, failed.error_code), ("COMPENSATION_FAILED", "STATE_NOT_RESTORED"))

    def test_unreadable_state_is_never_guessed(self):
        executor = SrLinuxExecutor({"name": "srl", "platform": "nokia_srlinux"},
                                   connection_factory=lambda _d: (_ for _ in ()).throw(GnmiError("AUTH_FAILED")))
        with self.assertRaises(ExecutorError) as raised:
            executor.connect()
        self.assertEqual(raised.exception.code, "AUTH_FAILED")
        with self.assertRaises(ExecutorError):
            executor.assess(_spec(1, "interface", LOOPBACK))

    def test_session_only_sends_set_and_delete(self):
        session = GnmiSession(client=FakeNode())
        for bad in (["show version"], [], ["set /"], ["set / a\nset / b"]):
            with self.assertRaises(GnmiError):
                session.set_cli(bad)
        with self.assertRaises(GnmiError):
            session.get("/", "operational")


IF_STATE = {"notification": [{"update": [{"path": None, "val": {"srl_nokia-interfaces:interface": [
    {"name": "ethernet-1/1", "admin-state": "enable", "oper-state": "up", "subinterface": [
        {"index": 0, "admin-state": "enable", "oper-state": "up",
         "ipv4": {"address": [{"ip-prefix": "198.18.0.1/30", "origin": "static"}]},
         "ipv6": {"address": [{"ip-prefix": "2001:db8:44::1/64", "type": "global-unicast", "origin": "static"},
                              {"ip-prefix": "fe80::1/64", "type": "link-local-unicast", "origin": "link-layer"}]}},
        {"index": 44, "admin-state": "enable", "oper-state": "down", "vlan": {"encap": {"single-tagged": {"vlan-id": 44}}},
         "ipv4": {"address": [{"ip-prefix": "198.18.44.1/24", "origin": "static"}]}}]},
    {"name": "lo44", "admin-state": "enable", "oper-state": "up",
     "subinterface": [{"index": 0, "admin-state": "enable", "oper-state": "down", "oper-down-reason": "no-ip-config"}]},
    {"name": "ethernet-1/2", "admin-state": "disable", "oper-state": "down"}]}}]}]}
RT_STATE = {"notification": [{"update": [{"path": "srl_nokia-network-instance:network-instance[name=default]/route-table", "val": {
    "srl_nokia-ip-route-tables:ipv4-unicast": {"route": [
        {"ipv4-prefix": "203.0.113.0/24", "route-type": "srl_nokia-common:static", "active": True, "next-hop-group": "20"},
        {"ipv4-prefix": "192.0.2.0/24", "route-type": "srl_nokia-common:static", "active": False, "next-hop-group": "20"},
        {"ipv4-prefix": "198.18.0.0/30", "route-type": "srl_nokia-common:local", "active": True, "next-hop-group": "21"}]},
    "srl_nokia-ip-route-tables:next-hop-group": [{"index": "20", "next-hop": [{"id": 0, "next-hop": "9"}]},
                                                 {"index": "21", "next-hop": [{"id": 0, "next-hop": "8"}]}],
    "srl_nokia-ip-route-tables:next-hop": [{"index": "9", "type": "srl_nokia-ip-route-tables:indirect", "ip-address": "198.18.0.2"},
                                           {"index": "8", "ip-address": "198.18.0.1", "subinterface": "ethernet-1/1.0"}]}}]}]}


class StateReaderTests(SimpleTestCase):
    def test_subinterface_state_follows_sr_linux_semantics(self):
        interfaces, addresses = live.parse_srl_interfaces(json.dumps(IF_STATE))
        self.assertEqual(interfaces["ethernet-1/1"], {"admin": "UP", "oper": "UP"})
        self.assertEqual(addresses["ethernet-1/1"], ["198.18.0.1/30", "2001:db8:44::1/64"])       # no link-local
        self.assertEqual(interfaces["ethernet-1/1.44"], {"admin": "UP", "oper": "DOWN"})
        self.assertEqual(addresses["ethernet-1/1.44"], ["198.18.44.1/24"])
        self.assertEqual(interfaces["lo44"], {"admin": "UP", "oper": "DOWN"})                     # no-ip-config
        self.assertEqual(interfaces["ethernet-1/2"], {"admin": "DOWN", "oper": "DOWN"})

    def test_only_active_routes_with_resolved_next_hops(self):
        routes = live.parse_srl_routes(json.dumps(RT_STATE))
        self.assertEqual(routes, [
            {"prefix": "203.0.113.0/24", "type": "static", "next_hops": ["198.18.0.2"], "interfaces": []},
            {"prefix": "198.18.0.0/30", "type": "local", "next_hops": ["198.18.0.1"], "interfaces": ["ethernet-1/1"]}])

    def test_read_device_uses_allowlisted_gnmi_get_only(self):
        class Gnmi:
            calls = []

            def get(self, path, datatype):
                self.calls.append((path, datatype))
                return IF_STATE if path == "/interface" else RT_STATE

        gnmi = Gnmi()
        device = {"name": "srl", "platform": "nokia_srlinux"}
        evidence = live.read_device(device, session_factory=lambda d: live.SrLinuxSession(d, gnmi=gnmi))
        self.assertTrue(evidence.live_reachable)
        self.assertEqual(set(gnmi.calls), {("/interface", "state"), ("/network-instance[name=default]/route-table", "state")})
        self.assertIn("lo44", evidence.facts("interfaces"))
        self.assertEqual(len(evidence.facts("routes")), 2)
        with self.assertRaises(live.LiveError):
            live.SrLinuxSession(device, gnmi=gnmi).run("running_config")
        self.assertEqual(live.read_device(device).live_error, "NOT_CONFIGURED")      # no inventory target: never guessed


class ImportAndRenderTests(SimpleTestCase):
    def test_parser_accepts_set_lines_and_gnmi_trees_alike(self):
        lines = [*BASE, *LOOPBACK, *ADDRESS, *ROUTE, "set interface ethernet-1/1 subinterface 0 ip-mtu 1400",
                 "set interface ethernet-1/1 vlan-tagging true", "set interface ethernet-1/1 subinterface 44 type routed",
                 "set interface ethernet-1/1 subinterface 44 vlan encap single-tagged vlan-id 44"]
        for source in ("\n".join(lines), _qualified(model.tree_from_set_lines(lines))):
            parsed = parser_srlinux.parse(source)
            names = {i.name: i for i in parsed.interfaces}
            self.assertEqual((names["lo44"].kind, names["lo44"].addresses[0]["cidr"]), ("LOOPBACK", "198.18.0.1/30"))
            self.assertEqual((names["mgmt0"].kind, names["ethernet-1/1"].mtu), ("MANAGEMENT", 1400))
            self.assertEqual((names["ethernet-1/1.44"].kind, names["ethernet-1/1.44"].encapsulation_vlan), ("SUBINTERFACE", 44))
            self.assertEqual([(r.destination, r.next_hop_address, r.distance) for r in parsed.static_routes],
                             [("203.0.113.0/24", "198.18.0.2", 200)])
            self.assertEqual(parsed.unmanaged_blocks, [])

    def test_planner_shaped_configlets_respect_sr_linux_semantics(self):
        _, specs, _, _ = batch_srlinux.plan("interface.ROUTED_PHYSICAL")
        self.assertIn("set interface ethernet-1/1 subinterface 0 ip-mtu 1500", specs[0].lines)       # L3 MTU, not port MTU
        self.assertNotIn("set interface ethernet-1/1 mtu 1500", specs[0].lines)
        self.assertEqual(list(specs[1].lines), ["set interface ethernet-1/1 subinterface 0 ipv4 admin-state enable",
                                                "set interface ethernet-1/1 subinterface 0 ipv4 address 198.18.0.1/30"])
        prerequisites, specs, _, _ = batch_srlinux.plan("interface.SUBINTERFACE")
        self.assertFalse([line for line in prerequisites if "subinterface 0" in line])               # tagged carrier
        self.assertIn("set interface ethernet-1/1 subinterface 44 vlan encap single-tagged vlan-id 44", specs[0].lines)
        _, specs, _, _ = batch_srlinux.plan("routing.STATIC_IPV6")
        self.assertIn("nexthop 1 ip-address 2001:db8:44::2", specs[0].lines[-1])
        for spec in specs:
            model.operations(spec.lines, strict=True)

    def test_driver_reports_gnmi_as_the_deployment_transport(self):
        rows = {row["transport"]: row["status"] for row in transport_capability.deployment_transport_matrix("nokia_srlinux")}
        self.assertEqual(rows["GNMI_SET"], "AVAILABLE")
        self.assertEqual(platform_drivers.get_driver("nokia_srlinux").name, "nokia_srlinux")
