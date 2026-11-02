"""Lab 7 closure -- Maintenance Mode topology derivation and drain / restore observations, each public function called directly.

The maintenance drain changes forwarding on a production boundary router, so every observation it gates on is proven both ways
here against the simulated lab of ``test_maintenance_live`` (the same fixtures the service tests use; no device, no write):
POSITIVE the derived relation / check is exactly right on the healthy lab; NEGATIVE an unreadable, missing or contradicting
fact never yields a passing check, an adjacency or a path that was not observed.
"""

from __future__ import annotations

from django.test import SimpleTestCase

from core.services.execution.executors.base import ExecutorError
from core.services.health.evidence import DeviceEvidence, FactGroup
from core.services.maintenance_mode import drain, model, topology
from core.services.route_shield import lab, migration
from core.services.route_shield.migration import ADD, REMOVE, TEMPORARY, Operation
from core.tests.test_maintenance_live import ACCESS, LINKS, SERVICE6, STATE, network, topo

BOTH = {(model.IPV6, model.NORTHBOUND), (model.IPV6, model.SOUTHBOUND)}


class TopologyRelationTests(SimpleTestCase):
    def test_neighbours_cabling_and_production_neighbours(self):
        t = topo()
        self.assertEqual(t.neighbours("R1"), {"S3", "S1", "mgmt_swt"})
        self.assertEqual(t.production_neighbours("R1"), {"S3", "S1"})
        self.assertEqual((t.cabled("R1", "Ethernet2"), t.cabled("S1", "eth1")), ("S1", "R1"))

    def test_neighbours_and_cabling_of_unknown_nodes_or_ports_are_empty(self):
        t = topo()
        self.assertEqual((t.neighbours("NOPE"), t.production_neighbours("NOPE")), (set(), set()))
        self.assertEqual((t.cabled("R1", "Ethernet99"), t.cabled("NOPE", "eth1")), ("", ""))

    def test_from_clab_reads_cabling_hosts_and_the_management_switch(self):
        doc = {"topology": {"links": [{"endpoints": [f"{a}:{ai}", f"{b}:{bi}"]} for a, ai, b, bi in LINKS] + [{"type": "host", "mtu": 1500}],
                            "nodes": {}}}
        devices = {name: {"name": name} for name in ("R1", "R2", "R3", "R4", "R5", "S1", "S2", "mgmt_swt")}
        inventory = {"lab_name": "lab", "hosts": {"H1": {"ipv6": True}}}
        t = topology.from_clab(doc, inventory, devices, service_host="WebServer", service_v4="172.30.50.10", service_v6=SERVICE6)
        self.assertEqual(t.management, ("mgmt_swt",))
        self.assertEqual(len(t.links), len(LINKS))

    def test_from_clab_without_links_has_no_cabling_and_no_management_switch(self):
        t = topology.from_clab({"topology": {}}, {"lab_name": "lab"}, {"R1": {"name": "R1"}}, service_host="W", service_v4="1.1.1.1", service_v6="::1")
        self.assertEqual((t.links, t.management), ([], ()) if isinstance(t.links, list) else ((), ()))

    def test_owners_of_an_interface_and_a_virtual_router_address(self):
        found = network()
        self.assertEqual(topology.owners(found, "2001:db8:110:1::1"), {"R1"})
        self.assertEqual(topology.owners(found, "192.168.10.1"), {"S1", "S2"})            # the VARP address both switches hold

    def test_owners_of_an_unknown_address_is_nobody_and_a_malformed_one_raises(self):
        self.assertEqual(topology.owners(network(), "203.0.113.9"), set())
        with self.assertRaises(ValueError):
            topology.owners(network(), "not-an-address")

    def test_adjacent_by_isis_and_ospf(self):
        found = network()
        self.assertEqual(topology.adjacent(found, "R1", "Ethernet2"), {"S1"})
        self.assertEqual(topology.adjacent(found, "R1", "Vlan101"), {"R3"})

    def test_adjacent_without_a_matching_adjacency_or_cable_is_empty(self):
        self.assertEqual(topology.adjacent(network(), "R1", "Ethernet99"), set())
        unreadable = network()
        unreadable["R1"] = DeviceEvidence(device="R1", platform="ceos", live_attempted=True, live_error="TIMEOUT")
        self.assertEqual(topology.adjacent(unreadable, "R1", "Ethernet2"), set())

    def test_lookup_returns_the_longest_matching_route(self):
        route = topology.lookup(network(), "R1", "2001:db8:10::101")
        self.assertEqual(route["prefix"], "2001:db8:10::/64")

    def test_lookup_empty_for_an_unrouted_address_and_none_when_routes_are_unreadable(self):
        found = network()
        self.assertEqual(topology.lookup(found, "R5", "203.0.113.1"), {})
        found["R1"].groups["routes"] = FactGroup(data=None, source="LIVE")
        self.assertIsNone(topology.lookup(found, "R1", "2001:db8:10::101"))

    def test_merged_paths_union_devices_and_hops(self):
        a = topology.Path(("S1", "R1"), True, "a", {"S1": ("R1",)})
        b = topology.Path(("S1", "S2"), True, "b", {"S1": ("S2",)})
        merged = topology.merged([a, b])
        self.assertEqual((merged.devices, merged.complete, merged.detail, merged.hops), (("S1", "R1", "S2"), True, "a; b", {"S1": ("R1", "S2")}))

    def test_merged_is_incomplete_when_any_path_is_or_when_no_address_is_known(self):
        self.assertFalse(topology.merged([topology.Path(("S1",), True, "a"), topology.Path(("S1",), False, "b")]).complete)
        self.assertEqual((topology.merged([]).complete, topology.merged([]).detail), (False, "host address unknown"))

    def test_access_as_dict_lists_tuples(self):
        found = ACCESS.as_dict()
        self.assertEqual((found["switch"], found["cores"]), ("S1", ["R3", "R4"]))

    def test_ospfv3_peers_are_the_cores_with_a_full_adjacency(self):
        self.assertEqual(topology.ospfv3_peers(network(), "R1"), ("R3", "R4"))

    def test_ospfv3_peers_none_for_a_device_without_core_adjacencies(self):
        self.assertEqual(topology.ospfv3_peers(network(), "S1"), ())

    def test_access_of_refuses_a_router_without_exactly_one_access_adjacency(self):
        found = network()
        found["R1"].groups["isis"] = FactGroup(data=[], source="LIVE")
        access, why = topology.access_of(found, "R1")
        self.assertIsNone(access)
        self.assertEqual(why, "R1 has 0 IS-IS adjacencies up, expected the one toward its switch")
        self.assertIsNone(topology.access_of(network(), "S3")[0])                          # not even read

    def test_role_of_unread_or_plain_devices_is_transit_never_a_boundary(self):
        t = topo()
        self.assertEqual(topology.role_of(t, network(), "R5"), topology.TRANSIT)
        self.assertEqual(topology.role_of(t, {}, "NOPE"), topology.TRANSIT)


# -- drain -----------------------------------------------------------------------------------------------------------------
class FakeRouter:
    """Read-only executor fake for the drain observations: a running configuration, routes and digests -- nothing is written."""

    def __init__(self, running="", *, routes=None, fib=None, digests=None, fail=False):
        self.running, self._routes, self.fib, self.digests, self.fail = running, routes or {}, fib or {}, digests or {}, fail

    def _guard(self):
        if self.fail:
            raise ExecutorError("CONNECTION_FAILED")

    def show(self, _command):
        self._guard()
        return self.running

    def routes(self, prefix):
        self._guard()
        return self._routes.get(prefix, [])

    def client_route(self, prefix):
        self._guard()
        return self.fib.get(prefix, {"installed": False, "active_next_hops": 0})

    def config_state_digest(self):
        self._guard()
        return self.digests.get("config", "")

    def static_route_digest(self):
        self._guard()
        return self.digests.get("static_routes", "")

    def frr_config_digest(self):
        return self.digests.get("frr_config", "")

    def persistent_config_digest(self):
        return self.digests.get("persistent_config", "")


class Env:
    def __init__(self, **executors):
        self.executors = executors


DRAINED_SWITCH = "interface Ethernet1\n   isis metric 1000\n"
DRAINED_ROUTER = f"{drain.ROUTE_MAP}\n   match ipv6 address prefix-list CLIENT-V6\n   set metric {drain.EXTERNAL_DRAIN_METRIC}\n"
BASE_ROUTER = f"{drain.ROUTE_MAP}\n   match ipv6 address prefix-list CLIENT-V6\n"


class DrainStatementTests(SimpleTestCase):
    def test_maintenance_lines_are_the_uplink_metric_and_the_external_metric(self):
        self.assertEqual(drain.maintenance_lines(ACCESS), ("interface Ethernet1", f"   isis metric {lab.DRAIN_METRIC}", drain.ROUTE_MAP,
                                                           f"   set metric {drain.EXTERNAL_DRAIN_METRIC}"))

    def test_maintenance_lines_refuse_a_value_that_is_not_an_access(self):
        with self.assertRaises(AttributeError):
            drain.maintenance_lines(None)

    def test_shield_lines_cover_both_directions_and_the_drain_shield_is_one_of_them(self):
        both, drain_only = drain.shield_lines(ACCESS), drain.drain_shield_lines(ACCESS)
        self.assertEqual(drain_only, ("ipv6 route 2001:db8::/33 2001:db8:110:3::2", "ipv6 route 2001:db8:8000::/33 2001:db8:110:3::2"))
        self.assertTrue(set(drain_only) < set(both))

    def test_shield_lines_refuse_a_missing_access(self):
        for call in (drain.shield_lines, drain.drain_shield_lines):
            with self.subTest(case=f"invalid {call.__name__}"), self.assertRaises(AttributeError):
                call(None)

    def test_temporary_lines_are_the_added_temporary_statements_only(self):
        ops = [Operation("a", "N", "S1", TEMPORARY, ADD, ("x",), ("no x",)), Operation("b", "N", "S1", TEMPORARY, REMOVE, ("no x",), ("x",)),
               Operation("c", "N", "S1", drain.MAINTENANCE, ADD, ("y",), ("no y",))]
        self.assertEqual(drain.temporary_lines(ops), ("x",))

    def test_temporary_lines_none_without_temporary_additions(self):
        self.assertEqual(drain.temporary_lines([]), ())

    def test_final_checks_for_drain_and_restore(self):
        self.assertEqual([c.label for c in drain.final_checks(ACCESS, migration.PRODUCTION, STATE, BOTH, drain=True)],
                         ["exactly the planned maintenance statements are configured", "the cores hold nothing they did not hold before"])
        self.assertEqual(drain.final_checks(ACCESS, migration.PRODUCTION, STATE, BOTH, drain=False)[0].label,
                         "the pre-maintenance forwarding configuration is restored exactly")

    def test_final_checks_never_hold_on_an_unreadable_device(self):
        broken = Env(**{name: FakeRouter(fail=True) for name in ("S1", "R1", "R3", "R4")})
        for check in drain.final_checks(ACCESS, migration.PRODUCTION, {**STATE, "cores": {"R3": {"static_routes": "s"}}}, BOTH, drain=True):
            with self.subTest(case=f"failure {check.label}"):
                self.assertFalse(check.run(broken)[0])


class DrainObservationTests(SimpleTestCase):
    def test_present_lines_reports_configured_statements(self):
        env = Env(S1=FakeRouter(DRAINED_SWITCH))
        self.assertEqual(drain.present_lines(env, "S1", ("interface Ethernet1", "   isis metric 1000")), ["interface Ethernet1 > isis metric 1000"])

    def test_present_lines_none_when_the_statement_is_absent(self):
        self.assertEqual(drain.present_lines(Env(S1=FakeRouter("interface Ethernet1\n   isis metric 10\n")), "S1",
                                             ("interface Ethernet1", "   isis metric 1000")), [])

    def test_drained_passes_with_exactly_the_planned_statements(self):
        env = Env(S1=FakeRouter(DRAINED_SWITCH), R1=FakeRouter(DRAINED_ROUTER))
        self.assertEqual(drain.drained(env, access=ACCESS, cells=BOTH), (True, "northbound metric set, southbound metric set"))

    def test_drained_fails_with_a_leftover_shield_a_missing_metric_or_an_unreadable_device(self):
        shield = "\n".join(drain.drain_shield_lines(ACCESS)) + "\n"
        for label, env in (("leftover shield", Env(S1=FakeRouter(DRAINED_SWITCH + shield), R1=FakeRouter(DRAINED_ROUTER))),
                           ("missing southbound metric", Env(S1=FakeRouter(DRAINED_SWITCH), R1=FakeRouter(BASE_ROUTER))),
                           ("unreadable device", Env(S1=FakeRouter(fail=True), R1=FakeRouter(DRAINED_ROUTER)))):
            with self.subTest(case=f"failure {label}"):
                self.assertFalse(drain.drained(env, access=ACCESS, cells=BOTH)[0])

    def test_restored_exactly_when_the_captured_state_is_back(self):
        state = {**STATE, "config": {**STATE["config"], "S1": "s1-before"}}
        env = Env(S1=FakeRouter("interface Ethernet1\n   isis metric 10\n", digests={"config": "s1-before"}), R1=FakeRouter(BASE_ROUTER))
        self.assertEqual(drain.restored_exactly(env, access=ACCESS, state=state), (True, "pre-maintenance state"))

    def test_restored_exactly_fails_on_a_different_switch_route_map_or_a_remaining_statement(self):
        for label, env in (("switch differs", Env(S1=FakeRouter(digests={"config": "other"}), R1=FakeRouter(BASE_ROUTER))),
                           ("route map differs", Env(S1=FakeRouter(digests={"config": "s1-before"}), R1=FakeRouter(DRAINED_ROUTER))),
                           ("unreadable", Env(S1=FakeRouter(fail=True), R1=FakeRouter(BASE_ROUTER)))):
            with self.subTest(case=f"failure {label}"):
                self.assertFalse(drain.restored_exactly(env, access=ACCESS, state=STATE)[0])

    def test_cores_unchanged_when_every_digest_matches(self):
        digests = {"static_routes": "s", "frr_config": "f", "persistent_config": "p"}
        env = Env(R3=FakeRouter(digests=digests))
        self.assertEqual(drain.cores_unchanged(env, state={"cores": {"R3": digests}}), (True, "unchanged"))

    def test_cores_unchanged_fails_on_a_new_static_route_or_an_unreadable_core(self):
        before = {"static_routes": "s", "frr_config": "f", "persistent_config": "p"}
        self.assertEqual(drain.cores_unchanged(Env(R3=FakeRouter(digests={**before, "static_routes": "s2"})), state={"cores": {"R3": before}}),
                         (False, "R3: static_routes differs from the pre-maintenance state"))
        self.assertEqual(drain.cores_unchanged(Env(R3=FakeRouter(fail=True)), state={"cores": {"R3": before}}), (False, "CONNECTION_FAILED"))

    @staticmethod
    def _core(hops, active):
        rows = {prefix: [{"dst": prefix, "nexthops": [{"gateway": a, "dev": i} for a, i in hops]}] for prefix in lab.CLIENTS}
        return FakeRouter(routes=rows, fib={prefix: {"installed": True, "active_next_hops": active} for prefix in lab.CLIENTS})

    def test_installed_hops_and_cores_route_both_routers(self):
        hops = (("fe80::1", "Vlan101"), ("fe80::2", "Vlan103"))
        core = self._core(hops, 2)
        found = drain.installed_hops(core)
        self.assertEqual(found, frozenset(hops))
        self.assertEqual(drain.cores_route(Env(R3=core), cores={"R3": hops[0]}, prefixes=lab.CLIENTS, both=True),
                         (True, "both boundary routers"))

    def test_installed_hops_empty_and_cores_route_fails_when_routes_are_missing_or_unreadable(self):
        self.assertEqual(drain.installed_hops(FakeRouter()), frozenset())
        self.assertFalse(drain.cores_route(Env(R3=FakeRouter()), cores={"R3": ("fe80::1", "Vlan101")}, prefixes=lab.CLIENTS, both=True)[0])
        self.assertEqual(drain.cores_route(Env(R3=FakeRouter(fail=True)), cores={"R3": ("fe80::1", "Vlan101")}, prefixes=lab.CLIENTS, both=True),
                         (False, "CONNECTION_FAILED"))


# -- capture / router_healthy: a whole-lab read-only fake ------------------------------------------------------------------
import json  # noqa: E402

R1_RUNNING = f"router ospfv3\n   redistribute isis route-map {migration.TO_OSPF}\n{BASE_ROUTER}"
S1_RUNNING = "interface Ethernet1\n   isis metric 10\n"
CORE_HOPS = {"R3": (("fe80::1", "Vlan101"), ("fe80::3", "Vlan103")), "R4": (("fe80::2", "Vlan102"), ("fe80::4", "Vlan104"))}


def eos_route(kind, interface, programmed=True):
    return {"routeType": kind, "vias": [{"interface": interface, "nexthopAddr": "fe80::9"}], "hardwareProgrammed": programmed, "kernelProgrammed": programmed}


class LabDevice(FakeRouter):
    """Answers the EOS show commands the drain reads; ``isis_up`` / ``eos_routes`` / ``full`` are what the device reports."""

    def __init__(self, running="", *, isis_up=(), eos_routes=None, full=(), **kw):
        super().__init__(running, **kw)
        self.isis_up, self.eos_routes, self.full = isis_up, eos_routes or {}, full

    def show(self, command):
        self._guard()
        if command == "show isis neighbors | json":
            adjacencies = [{"interfaceName": i, "state": "up", "hostname": "S1", "level": "level-2"} for i in self.isis_up]
            return json.dumps({"vrfs": {"default": {"isisInstances": {"1": {"neighbors": {"0000.0000.0001": {"adjacencies": adjacencies}}}}}}})
        if command.startswith("show ipv6 route "):
            prefix = command.split()[3]
            found = self.eos_routes.get(prefix)
            return json.dumps({"vrfs": {"default": {"routes": {prefix: found} if found else {}}}})
        return self.running

    def startup_state_digest(self):
        self._guard()
        return self.digests.get("startup", "")

    def full_neighbours(self):
        self._guard()
        return set(self.full)


class LabEnv(Env):
    def __init__(self, **executors):
        super().__init__(**executors)
        self.devices, self._evidence = {name: name for name in executors}, network()

    def read(self, device):
        return self._evidence[device]


def lab_env(*, s1=S1_RUNNING, r1=R1_RUNNING, fail="", r3_hops=None):
    cores = {name: DrainObservationTests._core(hops if name != "R3" or r3_hops is None else r3_hops, 2) for name, hops in CORE_HOPS.items()}
    for core in cores.values():
        core.digests = {"static_routes": "s", "frr_config": "f", "persistent_config": "p"}
    edge = {name: LabDevice(text, digests={"config": f"{name}-c", "startup": f"{name}-s"}, fail=(name == fail))
            for name, text in (("S1", s1), ("R1", r1), ("S2", ""), ("R2", ""))}
    return LabEnv(**edge, **cores)


class DrainCaptureTests(SimpleTestCase):
    def test_capture_records_the_exact_pre_maintenance_state(self):
        state, problems = drain.capture(lab_env(), ACCESS, migration.PRODUCTION)
        self.assertEqual(problems, [])
        self.assertEqual((state["uplink_metric"], state["route_map"]), (10, ["match ipv6 address prefix-list CLIENT-V6"]))
        self.assertEqual(state["config"], {"S1": "S1-c", "R1": "R1-c", "S2": "S2-c", "R2": "R2-c"})
        self.assertEqual(state["cores"]["R3"]["target_hop"], ["fe80::1", "Vlan101"])
        self.assertEqual(state["cores"]["R4"]["static_routes"], "s")

    def test_capture_reports_why_a_state_cannot_be_reversed(self):
        drained_metric = S1_RUNNING.replace("metric 10", f"metric {lab.DRAIN_METRIC}")
        metric_set = R1_RUNNING + f"   set metric {drain.EXTERNAL_DRAIN_METRIC}\n"
        for label, env, code in (("metric already drained", lab_env(s1=drained_metric), "PRE_STATE_NOT_BASELINE"),
                                 ("route map already sets a metric", lab_env(r1=metric_set), "PRE_STATE_NOT_BASELINE"),
                                 ("no redistribution", lab_env(r1=BASE_ROUTER), "PRE_STATE_NOT_BASELINE"),
                                 ("core with one next hop", lab_env(r3_hops=(("fe80::1", "Vlan101"),)), "TOPOLOGY_MISMATCH"),
                                 ("unreadable switch", lab_env(fail="S1"), "LIVE_EVIDENCE_UNAVAILABLE")):
            with self.subTest(case=f"failure {label}"):
                _state, problems = drain.capture(env, ACCESS, migration.PRODUCTION)
                self.assertEqual(len(problems), 1, problems)
                self.assertTrue(problems[0].startswith(code), problems)


HEALTHY_R1 = {**{p: eos_route("isisL2", "Ethernet2") for p in lab.CLIENTS}, lab.AGGREGATE: eos_route("static", "Vlan101")}


class RouterHealthTests(SimpleTestCase):
    def env(self, *, isis_up=("Ethernet2",), eos_routes=HEALTHY_R1, full=(("fe80::1", "Vlan101"),)):
        return Env(R1=LabDevice(isis_up=isis_up, eos_routes=eos_routes), R3=LabDevice(full=full))

    def test_router_healthy_with_its_adjacency_prefixes_aggregate_and_core_peering(self):
        self.assertEqual(drain.router_healthy(self.env(), access=ACCESS, cores={"R3": ("fe80::1", "Vlan101")}),
                         (True, "adjacencies up, client prefixes and aggregate held"))

    def test_router_healthy_fails_on_any_missing_fact(self):
        unprogrammed = {**HEALTHY_R1, lab.CLIENTS[0]: eos_route("isisL2", "Ethernet2", programmed=False)}
        no_aggregate = {p: r for p, r in HEALTHY_R1.items() if p != lab.AGGREGATE}
        for label, env, why in (("adjacency down", self.env(isis_up=()), "R1 IS-IS: up on nothing"),
                                ("unprogrammed client prefix", self.env(eos_routes=unprogrammed), f"R1 {lab.CLIENTS[0]}: isisL2 via Ethernet2 programmed=False"),
                                ("no aggregate", self.env(eos_routes=no_aggregate), f"R1 {lab.AGGREGATE}: no route"),
                                ("core not full", self.env(full=()), "R3 has no Full OSPFv3 adjacency with R1")):
            with self.subTest(case=f"failure {label}"):
                self.assertEqual(drain.router_healthy(env, access=ACCESS, cores={"R3": ("fe80::1", "Vlan101")}), (False, why))
        unreadable_core = Env(R1=self.env().executors["R1"], R3=LabDevice(fail=True))
        self.assertEqual(drain.router_healthy(unreadable_core, access=ACCESS, cores={"R3": ("fe80::1", "Vlan101")}), (False, "CONNECTION_FAILED"))
