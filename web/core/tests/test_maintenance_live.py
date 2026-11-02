"""Maintenance Mode on live observations: the collector's facts, the derived topology, the drain operations, the staged
executor with its compensation, entry, exit, the deadline sweep and the refusal of conflicting Changes.

The network is a production-shaped fake (health evidence per device, scripted host counters); the executors are fakes.
No device is contacted."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest import mock

from django.test import SimpleTestCase, TestCase

from core import models
from core.services.execution import eligibility
from core.services.execution.executors.base import APPLY, SKIP_SATISFIED, ApplyOutcome, Assessment, CompensationOutcome, ExecutorError
from core.services.health.evidence import DeviceEvidence, FactGroup
from core.services.maintenance_mode import collector, drain, executor, lifecycle, model, plan, policy, protection, readiness, service, store, topology
from core.services.maintenance_mode import evidence as chain
from core.services.maintenance_mode.model import ACTIVE, IPV4, IPV6, NORTHBOUND, QUIESCED, SOUTHBOUND, UNKNOWN
from core.services.route_shield import lab, migration
from core.services.route_shield import lifecycle as shield_lifecycle
from core.services.route_shield import readiness as shield_readiness
from core.services.route_shield.migration import ADD, REMOVE, Check, Operation

T0 = datetime(2026, 10, 13, 12, 0, tzinfo=timezone.utc)
READY = {shield_readiness.ISIS_METRIC_STEER: model.READY, shield_readiness.OSPFV3_EXTERNAL_METRIC_STEER: model.READY}
SERVICE4, SERVICE6 = "172.30.50.10", "2001:db8:3050::10"
HOSTS = {"H1": ("S1", "192.168.10.101", "2001:db8:10::101"), "H2": ("S1", "192.168.20.101", "2001:db8:20::101"),
         "H3": ("S2", "192.168.10.103", "2001:db8:10::103"), "H4": ("S2", "", "2001:db8:30::104")}
LINKS = (("R3", "eth1", "S3", "eth1"), ("R4", "eth1", "S4", "eth1"), ("S3", "eth2", "S4", "eth2"), ("S3", "eth3", "R1", "eth1"), ("S4", "eth3", "R2", "eth1"),
         ("R3", "eth2", "R5", "eth1"), ("R4", "eth2", "R5", "eth2"), ("R5", "eth3", "WebServer", "eth1"),
         ("R1", "eth2", "S1", "eth1"), ("R2", "eth2", "S2", "eth1"), ("S1", "eth2", "S2", "eth2"),
         ("S1", "eth3", "H1", "eth1"), ("S1", "eth4", "H2", "eth1"), ("S2", "eth3", "H3", "eth1"), ("S2", "eth4", "H4", "eth1"),
         *((("mgmt_swt", f"eth{n}", name, "eth9")) for n, name in enumerate(("R1", "R2", "R3", "R4", "S1", "S2"), 1)))


def route(prefix, kind, interfaces=(), hops=()):
    return {"prefix": prefix, "type": kind, "interfaces": sorted(interfaces), "next_hops": sorted(hops)}


def evidence(name, platform, addresses, routes, isis=(), ospf=(), virtual=None):
    found = DeviceEvidence(device=name, platform=platform, live_attempted=True)
    data = {"addresses": addresses, "routes": routes, "virtual_addresses": virtual or {}, "config_paths": [f"hostname {name}"],
            "isis": [{"interface": i, "hostname": h, "state": "UP"} for i, h in isis],
            "ospf": [{"family": "OSPFV3", "interface": i, "neighbor_id": rid, "state": "FULL"} for i, rid in ospf]}
    found.groups = {key: FactGroup(data=value, source="LIVE", observed_at=T0) for key, value in data.items()}
    return found


def network(drained: str = "") -> dict:
    """The lab after the IS-IS migration.  ``drained``: that boundary router has both IPv6 directions steered away."""
    clients6, found = ("2001:db8:10::/64", "2001:db8:20::/64", "2001:db8:30::/64"), {}
    for index, (switch, router) in enumerate((("S1", "R1"), ("S2", "R2")), 1):
        other = "S2" if switch == "S1" else "S1"
        up6 = ["Vlan99"] if drained == router else ["Ethernet1"]
        found[switch] = evidence(
            switch, "ceos",
            {"Ethernet1": [f"192.168.110.{2 * index - 1}/31", f"2001:db8:110:{index}::2/64"], "Vlan99": [f"192.168.110.{3 + index}/31", f"2001:db8:110:3::{index}/64"],
             "Vlan10": [f"192.168.10.{1 + index}/24", f"2001:db8:10::{1 + index}/64"], "Vlan20": [f"192.168.20.{1 + index}/24", f"2001:db8:20::{1 + index}/64"],
             "Vlan30": [f"2001:db8:30::{1 + index}/64"]},
            [route("2001:db8::/32", "isisLevel2", up6), route(f"{SERVICE4}/32", "rip", ["Ethernet1"], [f"192.168.110.{2 * index - 2}"]),
             *(route(p, "connected", [f"Vlan{v}"]) for p, v in zip(clients6, (10, 20, 30))),
             route("192.168.10.0/24", "connected", ["Vlan10"]), route("192.168.20.0/24", "connected", ["Vlan20"])],
            isis=[("Ethernet1", router), ("Vlan99", other)],
            virtual={"Vlan10": ["192.168.10.1", "2001:db8:10::1"], "Vlan20": ["192.168.20.1", "2001:db8:20::1"], "Vlan30": ["2001:db8:30::1"]})
        core = (101, 102) if router == "R1" else (103, 104)
        found[router] = evidence(
            router, "ceos",
            {"Ethernet2": [f"192.168.110.{2 * index - 2}/31", f"2001:db8:110:{index}::1/64"], "Loopback0": [f"192.168.255.{index}/32"],
             f"Vlan{core[0]}": [f"192.168.100.{4 * index - 4}/31", f"2001:db8:100:{core[0]}::1/64"],
             f"Vlan{core[1]}": [f"192.168.100.{4 * index - 2}/31", f"2001:db8:100:{core[1]}::1/64"]},
            [route("2001:db8::/32", "static", [f"Vlan{core[0]}", f"Vlan{core[1]}"]), route(f"{SERVICE4}/32", "ospfExternal", [f"Vlan{core[0]}", f"Vlan{core[1]}"]),
             *(route(p, "isisLevel2", ["Ethernet2"]) for p in clients6),
             route("192.168.10.0/24", "rip", ["Ethernet2"], [f"192.168.110.{2 * index - 1}"]), route("192.168.20.0/24", "rip", ["Ethernet2"], [f"192.168.110.{2 * index - 1}"])],
            isis=[("Ethernet2", switch)], ospf=[(f"Vlan{core[0]}", "192.168.255.3"), (f"Vlan{core[1]}", "192.168.255.4")])
    for index, name in ((3, "R3"), (4, "R4")):
        r1, r2 = (101, 103) if name == "R3" else (102, 104)
        down = [f"Vlan{v}" for v, router in ((r1, "R1"), (r2, "R2")) if router != drained]
        found[name] = evidence(
            name, "linux",
            {"lo": [f"192.168.255.{index}/32"], f"Vlan{r1}": [f"2001:db8:100:{r1}::2/64"], f"Vlan{r2}": [f"2001:db8:100:{r2}::2/64"], "eth2": [f"10.{index}.0.0/31"]},
            [*(route(p, "ospf", down) for p in clients6), route("192.168.10.0/24", "ospf", [f"Vlan{r1}", f"Vlan{r2}"]), route("192.168.20.0/24", "ospf", [f"Vlan{r1}", f"Vlan{r2}"]),
             route(f"{SERVICE6}/128", "bgp", ["eth2"]), route(f"{SERVICE4}/32", "bgp", ["eth2"])],
            ospf=[(f"Vlan{r1}", "192.168.255.1"), (f"Vlan{r2}", "192.168.255.2")])
    found["R5"] = evidence("R5", "ceos", {"Ethernet1": ["10.3.0.1/31"], "Ethernet2": ["10.4.0.1/31"]},
                           [*(route(p, "eBGP", ["Ethernet1", "Ethernet2"]) for p in (*clients6, "192.168.10.0/24", "192.168.20.0/24"))])
    return found


def topo() -> topology.Topology:
    devices = {name: {"name": name} for name in ("R1", "R2", "R3", "R4", "R5", "S1", "S2", "mgmt_swt")}
    hosts = {name: topology.Host(name, f"c-{name}", "eth1", (4, 6) if v4 else (6,), switch) for name, (switch, v4, _v6) in HOSTS.items()}
    return topology.Topology(LINKS, hosts, topology.Service("WebServer", "c-web", SERVICE4, SERVICE6, "R5"), devices, ("mgmt_swt",))


class Hosts:
    """Scripted hosts: ``active`` names (host, version, direction) triples that exchange packets between the two reads."""

    def __init__(self, active=(), broken=()):
        self.active, self.broken, self.reads = set(active), set(broken), {}

    def addresses(self, host):
        _switch, v4, v6 = HOSTS[host.name]
        return {4: [v4] if v4 else [], 6: [v6]}

    def gateways(self, host):
        _switch, v4, v6 = HOSTS[host.name]
        return {4: [v4.rsplit(".", 1)[0] + ".1"] if v4 else [], 6: [v6.rsplit(":", 1)[0] + ":1"]}

    def counters(self, host):
        if host.name in self.broken:
            raise OSError("unreadable")
        self.reads[host.name] = self.reads.get(host.name, 0) + 1
        return {(v, d): 1000 + (25 if (host.name, v, d) in self.active and self.reads[host.name] > 1 else 0) for v in (4, 6) for d in model.DIRECTIONS}


def sources(evidence_by_device=None, *, active=(), broken=(), states=None):
    found = evidence_by_device if evidence_by_device is not None else network()
    return collector.Sources(topo(), lambda device: found[device["name"]], hosts=Hosts(active, broken), shield_states=states,
                             dhcp_servers=lambda: {"secondary_device": "R2"}, dhcp_state=lambda: {"nmas": {"ipv4": "active", "ipv6": "active"}},
                             window_seconds=20, sleep=lambda _s: None, now=lambda: T0)


def verdict(device, src):
    observation = collector.observe(device, src)
    return observation, readiness.evaluate(model.Request(device, "op", "work", timedelta(hours=2), T0), observation.flows, observation.dependencies,
                                           alternates=observation.alternates, mechanisms=observation.mechanisms)


def blocked(report):
    return sorted((f.code, f.family, f.direction, f.workloads) for f in report.blockers)


class TopologyTests(SimpleTestCase):
    def test_the_access_relations_of_a_boundary_router_are_read_from_the_devices(self):
        access, why = topology.access_of(network(), "R1")
        self.assertEqual(why, "")
        self.assertEqual((access.switch, access.uplink, access.router_v6, access.transit, access.far_switch, access.far_switch_v6, access.peer_router,
                          access.peer_access_interface, access.far_uplink, access.cores, access.access_interface),
                         ("S1", "Ethernet1", "2001:db8:110:1::1", "Vlan99", "S2", "2001:db8:110:3::2", "R2", "Ethernet2", "Ethernet1", ("R3", "R4"), "Ethernet2"))
        tracked = lab.SWITCHES["S1"]            # what the devices show is what the tracked design says
        self.assertEqual(lab.Switch(access.switch, access.uplink, access.router_v6, access.transit, access.far_switch_v6, access.far_switch), tracked)
        self.assertEqual(topology.access_of(network(), "R2")[0].switch, "S2")

    def test_roles_single_homed_hosts_and_the_management_cut_come_from_cabling_and_adjacencies(self):
        found, t = network(), topo()
        self.assertEqual([topology.role_of(t, found, name) for name in ("R1", "R2", "S1", "S2", "R3")],
                         ["BOUNDARY_ROUTER", "BOUNDARY_ROUTER", "ACCESS_SWITCH", "ACCESS_SWITCH", "TRANSIT"])
        self.assertEqual((t.single_homed("S1"), t.single_homed("S2"), t.single_homed("R1")), (("H1", "H2"), ("H3", "H4"), ()))
        self.assertEqual((t.cut_off_from_management("R1"), t.management), ((), ("mgmt_swt",)))

    def test_a_path_follows_every_equal_cost_branch_and_an_unreadable_hop_makes_it_incomplete(self):
        found = network()
        north = topology.trace(found, ["S1"], SERVICE6, ends=("R5",), cabling=topo())
        self.assertTrue(north.complete)
        self.assertEqual(north.detail, "S1 > R1 > R3|R4 > R5")
        south = topology.trace(found, ["R5"], "2001:db8:10::103", cabling=topo())
        self.assertEqual((south.complete, set(south.devices)), (True, {"R5", "R3", "R4", "R1", "R2", "S1", "S2"}))
        found["R3"].groups["routes"] = FactGroup(data=None, source="LIVE")
        self.assertFalse(topology.trace(found, ["S1"], SERVICE6, ends=("R5",), cabling=topo()).complete)

    def test_an_equal_cost_branch_toward_an_unreadable_device_makes_the_path_incomplete(self):
        found = network()
        found["R3"] = DeviceEvidence(device="R3", platform="linux", live_attempted=True, live_error="TIMEOUT")    # nothing of R3 is known
        path = topology.trace(found, ["S2"], SERVICE6, ends=("R5",), cabling=topo())
        self.assertFalse(path.complete)                                     # never "S2 > R2 > R4 > R5, complete"
        self.assertIn("toward no device that was read", path.detail)
        observation = collector.observe("R1", sources(found, active={("H3", 6, NORTHBOUND)}))
        self.assertEqual({f.label: f.activity for f in observation.flows}["h3-v6-north"], UNKNOWN)

    def test_a_drained_router_is_on_no_ipv6_path(self):
        found = network(drained="R1")
        self.assertEqual(topology.trace(found, ["S1"], SERVICE6, ends=("R5",), cabling=topo()).detail, "S1 > S2 > R2 > R3|R4 > R5")
        self.assertNotIn("R1", topology.trace(found, ["R5"], "2001:db8:10::101", cabling=topo()).devices)


class DerivedManagementTests(SimpleTestCase):
    """The management switch and what depends on it come from the cabling, never from a device name."""

    def doc(self, name):
        links = [{"endpoints": [f"{name}:eth{i}", f"{dev}:eth9"]} for i, dev in enumerate(("A", "B", "C", "D"), 1)]
        links += [{"endpoints": ["A:eth1", "B:eth1"]}, {"endpoints": ["B:eth2", "HOST1:eth1"]}, {"type": "host", "endpoint": {"node": name}}]
        return {"topology": {"links": links}}

    def test_a_renamed_management_switch_is_found_and_blocks_by_its_dependants(self):
        devices = {name: {"name": name} for name in ("A", "B", "C", "D", "oob-7")}
        topo = topology.from_clab(self.doc("oob-7"), {"lab_name": "x", "hosts": {"HOST1": {"ipv6": True}}}, devices,
                                  service_host="WEB", service_v4="", service_v6="")
        self.assertEqual(topo.management, ("oob-7",))
        self.assertEqual(topo.cut_off_from_management("oob-7"), ("A", "B", "C", "D"))
        self.assertEqual(topo.cut_off_from_management("A"), ())                # every other device keeps its own management cable

    def test_management_ports_are_the_devices_own_not_a_name_convention(self):
        topo = topology.Topology((), {}, topology.Service("W", "c", "", "", ""), {"C": {"name": "C"}, "E": {"name": "E"}}, (), {"C": ()})
        self.assertFalse(topology._is_management("eth0", "C", topo))         # a core whose eth0 is a data link (the sandbox's FRR cores)
        self.assertTrue(topology._is_management("eth0", "E", topo))          # no stated ports: the Containerlab convention
        self.assertTrue(topology._is_management("Management0", "E", topo))
        stated = topology.Topology((), {}, topology.Service("W", "c", "", "", ""), {"R": {"name": "R"}}, (), {"R": ("Ethernet3", "Management0")})
        self.assertTrue(topology._is_management("Ethernet3", "R", stated))   # cabled to the management switch
        self.assertFalse(topology._is_management("Ethernet1", "R", stated))

    def test_a_device_that_is_the_only_way_to_the_management_switch_strands_what_hangs_off_it(self):
        links = (("M", "e1", "A", "e9"), ("M", "e2", "B", "e9"), ("M", "e3", "C", "e9"), ("A", "e1", "D", "e1"))
        topo = topology.Topology(links, {}, topology.Service("W", "c", "", "", ""), {name: {"name": name} for name in "ABCDM"}, ("M",))
        self.assertEqual(topo.cut_off_from_management("A"), ("D",))
        self.assertEqual(topo.cut_off_from_management("B"), ())


class CollectorTests(SimpleTestCase):
    def test_it_produces_one_classified_flow_per_host_family_and_direction_with_its_path(self):
        observation = collector.observe("R1", sources(active={("H1", 6, NORTHBOUND)}))
        self.assertEqual(len(observation.flows), 14)                       # H1 to H3 in both families, H4 in IPv6 only
        by_label = {flow.label: flow for flow in observation.flows}
        self.assertEqual((by_label["h1-v6-north"].activity, by_label["h1-v6-north"].on_device, by_label["h1-v6-north"].workload), (ACTIVE, True, "H1 to WebServer"))
        self.assertIn("S1 > R1 > R3|R4 > R5", by_label["h1-v6-north"].evidence)
        self.assertEqual((by_label["h3-v6-north"].activity, by_label["h3-v6-north"].on_device), (QUIESCED, False))     # H3 leaves through S2 and R2
        self.assertTrue(by_label["h3-v6-south"].on_device)                 # the cores still choose R1 for half of it
        self.assertEqual(observation.role, "BOUNDARY_ROUTER")
        self.assertEqual(observation.alternates, {(IPV6, NORTHBOUND): True, (IPV6, SOUTHBOUND): True})
        self.assertEqual(observation.intersects, ("R2", "R3", "R4", "S1", "S2"))
        summary = observation.summary()
        self.assertEqual(summary["protocols"]["R1"]["isis_up"], ["Ethernet2:S1"])
        self.assertEqual(summary["hosts"]["H1"]["packets"]["v6/NORTHBOUND"], 25)
        self.assertTrue(all(summary["digests"][name] for name in ("R1", "R2", "S1", "S2")))

    def test_a_host_without_an_address_is_quiesced_only_when_its_counters_prove_it(self):
        class NoV4(Hosts):
            def addresses(self, host):
                found = super().addresses(host)
                return {**found, 4: []} if host.name == "H1" else found

        quiet = sources()
        quiet.hosts = NoV4()
        by_label = {flow.label: flow for flow in collector.observe("S1", quiet).flows}
        self.assertEqual((by_label["h1-v4-north"].activity, by_label["h1-v4-north"].on_device), (QUIESCED, False))
        busy = sources(active={("H1", 4, NORTHBOUND)})
        busy.hosts = NoV4({("H1", 4, NORTHBOUND)})
        self.assertEqual({f.label: f.activity for f in collector.observe("S1", busy).flows}["h1-v4-north"], UNKNOWN)
        broken = sources()
        broken.hosts = NoV4(broken={"H1"})
        self.assertEqual({f.label: f.activity for f in collector.observe("S1", broken).flows}["h1-v4-north"], UNKNOWN)

    def test_every_address_of_a_host_is_traced_southbound_and_one_unroutable_one_is_unknown(self):
        class Two(Hosts):
            def addresses(self, host):
                found = super().addresses(host)
                return {**found, 6: [*found[6], "2001:db8:110:9::7"]} if host.name == "H1" else found      # an address nothing routes to

        src = sources(active={("H1", 6, SOUTHBOUND)})
        src.hosts = Two({("H1", 6, SOUTHBOUND)})
        flow = {f.label: f for f in collector.observe("R1", src).flows}["h1-v6-south"]
        self.assertEqual(flow.activity, UNKNOWN)                              # never read as "the path avoids the device"

    def test_ipv4_routing_multicast_a_host_did_not_join_is_not_production_traffic(self):
        def proc(rip_dropped, delivered):
            snmp = ("Ip: Forwarding DefaultTTL InReceives InHdrErrors InAddrErrors ForwDatagrams InUnknownProtos InDiscards InDelivers OutRequests\n"
                    f"Ip: 1 64 {1000 + rip_dropped + delivered} 0 0 0 0 0 {1000 + delivered} 500\n")
            netstat = "IpExt: InNoRoutes InMcastPkts OutMcastPkts InBcastPkts OutBcastPkts\nIpExt: 0 0 0 0 0\n"
            six = "Ip6InReceives 10\nIp6InMcastPkts 10\nIp6OutRequests 3\nIp6OutMcastPkts 3\n"
            return lambda container, argv: {"/proc/net/snmp": snmp, "/proc/net/netstat": netstat}.get(argv[-1], six)

        host = topology.Host("H1", "c-H1", "eth1", (4, 6), "S1")
        first = collector.HostReader(proc(0, 0)).counters(host)
        quiet = collector.HostReader(proc(3, 0)).counters(host)                # three RIP updates, nothing delivered
        busy = collector.HostReader(proc(3, 2)).counters(host)
        self.assertEqual(quiet[(4, SOUTHBOUND)] - first[(4, SOUTHBOUND)], 0)
        self.assertEqual(busy[(4, SOUTHBOUND)] - first[(4, SOUTHBOUND)], 2)

    def test_reset_missing_or_unreadable_counters_are_never_quiesced(self):
        class Reset(Hosts):
            def counters(self, host):
                found = super().counters(host)
                return {key: (0 if self.reads[host.name] > 1 and host.name == "H1" else value) for key, value in found.items()}

        class Missing(Hosts):
            def counters(self, host):
                if host.name == "H1":
                    raise KeyError("Ip6InReceives")
                return super().counters(host)

        for hosts in (Reset(), Missing(), Hosts(broken={"H1"})):
            src = sources()
            src.hosts = hosts
            observation, report = verdict("S1", src)
            activity = {f.label: f.activity for f in observation.flows}
            self.assertEqual({activity[f"h1-v{v}-{d}"] for v in (4, 6) for d in ("north", "south")}, {UNKNOWN}, type(hosts).__name__)
            self.assertFalse(report.ready)
            self.assertIn(readiness.TRAFFIC_UNKNOWN, [f.code for f in report.blockers])

    def test_freshness_is_per_collected_group_and_missing_evidence_is_never_fresh(self):
        limits = {"healthy": 60.0, "stale": 120.0}
        summary = collector.observe("R1", sources()).summary()
        self.assertEqual(set(collector.freshness(summary, now=T0 + timedelta(seconds=30), thresholds=limits).values()), {"FRESH"})
        later = collector.freshness(summary, now=T0 + timedelta(seconds=90), thresholds=limits)
        self.assertEqual(set(later.values()), {"STALE"})
        summary["provenance"]["R3"]["groups"]["isis"] = None                     # a group the platform does not collect
        self.assertEqual(collector.freshness(summary, now=T0, thresholds=limits)["R3"], "FRESH")
        summary["provenance"]["R1"]["groups"]["routes"]["available"] = False    # one that was read and is not there
        self.assertEqual(collector.freshness(summary, now=T0, thresholds=limits)["R1"], "UNKNOWN")

    def test_northbound_ready_never_makes_the_device_ready_while_southbound_active_traffic_is_unsafe(self):
        north_only = {shield_readiness.ISIS_METRIC_STEER: shield_readiness.READY, shield_readiness.OSPFV3_EXTERNAL_METRIC_STEER: shield_readiness.NOT_READY}
        _o, report = verdict("R1", sources(active=ACTIVE_H1, states=north_only))
        self.assertFalse(report.ready)
        self.assertEqual((report.cells[(IPV6, NORTHBOUND)]["verdict"], report.cells[(IPV6, SOUTHBOUND)]["verdict"]), (readiness.DRAINABLE, readiness.BLOCKED))
        self.assertIn((readiness.MECHANISM_NOT_READY, IPV6, SOUTHBOUND, ("WebServer to H1",)), blocked(report))
        _o, report = verdict("R1", sources(active={("H1", 6, NORTHBOUND)}, states=north_only))       # southbound quiesced: policy lets it proceed
        self.assertTrue(report.ready)
        self.assertEqual([(step.family, step.direction) for step in plan.build(report)], [(IPV6, NORTHBOUND)])

    def test_unknown_stays_blocked(self):
        _o, report = verdict("S1", sources(broken={"H1"}))
        self.assertIn((readiness.TRAFFIC_UNKNOWN, IPV6, NORTHBOUND, ("H1 to WebServer",)), blocked(report))
        found = network()
        found["R3"].groups["routes"] = FactGroup(data=None, source="LIVE")   # active traffic whose path cannot be followed
        observation, report = verdict("R2", sources(found, active={("H1", 6, NORTHBOUND)}))
        self.assertEqual({f.label: f.activity for f in observation.flows}["h1-v6-north"], UNKNOWN)
        self.assertIn(readiness.TRAFFIC_UNKNOWN, [f.code for f in report.blockers])
        self.assertEqual(observation.alternates, {(IPV6, NORTHBOUND): None, (IPV6, SOUTHBOUND): None})

    def test_quiesced_traffic_is_ready_without_redundancy_and_an_active_single_homed_workload_blocks_by_name(self):
        observation, report = verdict("S1", sources())
        self.assertTrue(report.ready)
        self.assertEqual((observation.mechanisms, observation.facts["single_homed"]), ({}, ["H1", "H2"]))
        _o, report = verdict("S1", sources(active={("H2", 4, SOUTHBOUND), ("H1", 6, NORTHBOUND)}))
        self.assertEqual(blocked(report), [(readiness.NO_LOSSLESS_DRAIN, IPV4, SOUTHBOUND, ("WebServer to H2",)),
                                           (readiness.NO_LOSSLESS_DRAIN, IPV6, NORTHBOUND, ("H1 to WebServer",))])
        _o, report = verdict("S2", sources(active={("H1", 6, NORTHBOUND)}))    # H1 leaves through S1: not S2's traffic
        self.assertTrue(report.ready)

    def test_r1_active_ipv6_is_blocked_today_and_drainable_only_with_both_mechanisms_ready(self):
        _o, report = verdict("R1", sources(active={("H1", 6, NORTHBOUND), ("H1", 6, SOUTHBOUND)}))
        self.assertEqual(blocked(report), [(readiness.MECHANISM_NOT_READY, IPV6, NORTHBOUND, ("H1 to WebServer",)),
                                           (readiness.MECHANISM_NOT_READY, IPV6, SOUTHBOUND, ("WebServer to H1",))])
        north_only = {**READY, shield_readiness.OSPFV3_EXTERNAL_METRIC_STEER: model.NOT_READY}
        _o, report = verdict("R1", sources(active={("H1", 6, NORTHBOUND), ("H1", 6, SOUTHBOUND)}, states=north_only))
        self.assertEqual(blocked(report), [(readiness.MECHANISM_NOT_READY, IPV6, SOUTHBOUND, ("WebServer to H1",))])
        _o, report = verdict("R1", sources(active={("H1", 6, NORTHBOUND), ("H1", 6, SOUTHBOUND)}, states=READY))
        self.assertTrue(report.ready)
        self.assertEqual([(cell, value["verdict"]) for cell, value in report.cells.items() if value["verdict"] != readiness.CLEAR],
                         [((IPV6, NORTHBOUND), readiness.DRAINABLE), ((IPV6, SOUTHBOUND), readiness.DRAINABLE)])

    def test_quiet_ipv6_is_still_drained_when_the_mechanisms_are_ready(self):
        _o, report = verdict("R1", sources(states=READY))
        self.assertTrue(report.cells[(IPV6, NORTHBOUND)].get("preventive") and report.cells[(IPV6, SOUTHBOUND)].get("preventive"))
        _o, report = verdict("R1", sources())                               # not READY: quiet traffic needs no drain and blocks nothing
        self.assertTrue(report.ready and all(cell["verdict"] == readiness.CLEAR for cell in report.cells.values()))

    def test_active_ipv4_with_no_proven_drain_blocks_and_quiet_ipv4_does_not(self):
        _o, report = verdict("R1", sources(active={("H1", 4, NORTHBOUND)}, states=READY))
        self.assertEqual(blocked(report), [(readiness.ALTERNATE_UNHEALTHY, IPV4, NORTHBOUND, ("H1 to WebServer",)),
                                           (readiness.MECHANISM_NOT_READY, IPV4, NORTHBOUND, ("H1 to WebServer",))])
        self.assertIn(f"{policy.RIP_IPV4} is NOT_READY", [f.detail for f in report.blockers])
        _o, report = verdict("R1", sources(states=READY))
        self.assertEqual(report.cells[(IPV4, NORTHBOUND)]["verdict"], readiness.CLEAR)

    def test_an_unhealthy_alternate_and_a_stranded_dependency_block(self):
        found = network()
        found["S2"].groups["routes"].data[0]["interfaces"] = ["Vlan99"]     # S2 would hand the traffic straight back
        observation, report = verdict("R1", sources(found, active={("H1", 6, NORTHBOUND)}, states=READY))
        self.assertIs(observation.alternates[(IPV6, NORTHBOUND)], False)
        self.assertIn(readiness.ALTERNATE_UNHEALTHY, [f.code for f in report.blockers])
        src = sources()
        src.dhcp_state = lambda: {"nmas": {"ipv4": "active", "ipv6": "inactive"}}
        _o, report = verdict("R2", src)
        self.assertEqual([(f.code, f.workloads) for f in report.blockers], [(readiness.DEPENDENCY_STRANDED, ("DHCP service",))])
        found = network()
        found["S2"].groups["virtual_addresses"].data = {}
        _o, report = verdict("S1", sources(found))
        self.assertIn(("gateway 192.168.10.1",), [f.workloads for f in report.blockers])

    def test_the_backup_dhcp_dependency_reads_the_verifiers_own_report(self):
        """The production reader (health.live.dhcp_service_state -> verify_dhcp_servers.nmas_status) feeds the collector
        directly: an active primary in both families frees R2, anything else keeps it blocked."""
        from core.services.health import live
        from netbox.scripts import verify_dhcp_servers

        def run(states):
            def fake(cmd, timeout=15):
                if cmd[0] == "systemctl":
                    return states[cmd[-1]] + "\n"
                return "IPv4 DHCP server is active\nIPv6 DHCP server is active\n"
            return fake

        def dhcp(states):
            with mock.patch.object(verify_dhcp_servers, "_run", run(states)):
                src = sources()
                src.dhcp_state = live.dhcp_service_state
                return [d for d in collector.observe("R2", src).dependencies if d.kind == "DHCP"][0]

        both = dhcp({"isc-dhcp-server": "active", "isc-dhcp-server6": "active"})
        self.assertIs(both.stranded, False)
        self.assertIn("primary active", both.detail)
        self.assertIs(dhcp({"isc-dhcp-server": "active", "isc-dhcp-server6": "inactive"}).stranded, True)
        self.assertIs(dhcp({"isc-dhcp-server": "failed", "isc-dhcp-server6": "active"}).stranded, True)
        self.assertIsNone(dhcp({"isc-dhcp-server": "", "isc-dhcp-server6": "active"}).stranded)
        self.assertIsNone(collector.primary_dhcp_active(None))
        self.assertIsNone(collector.primary_dhcp_active({"active": True}))       # not the verifier's shape: not established


ACCESS = topology.access_of(network(), "R1")[0]
STATE = {"access": ACCESS.as_dict(), "uplink_metric": 10, "route_map": ["match ipv6 address prefix-list CLIENT-V6"], "config": {"S1": "s1-before", "R1": "", "S2": "", "R2": ""}, "startup": {"S1": "", "R1": ""},
         "cores": {"R3": {"target_hop": ["fe80::21c:73ff:fe20:ab82", "Vlan101"]}, "R4": {"target_hop": ["fe80::21c:73ff:fe20:ab82", "Vlan102"]}}}
BOTH = ((IPV6, NORTHBOUND), (IPV6, SOUTHBOUND))


class DrainPlanTests(SimpleTestCase):
    def test_entering_drains_northbound_then_southbound_and_writes_no_core(self):
        ops = drain.operations(ACCESS, migration.PRODUCTION, STATE, BOTH, drain=True)
        self.assertEqual([op.stage for op in ops], [drain.NORTH] * 3 + [drain.SOUTH])
        north, south = ops[:3], ops[3]
        self.assertEqual([op.lines for op in north], [("ipv6 route 2001:db8::/33 2001:db8:110:3::2", "ipv6 route 2001:db8:8000::/33 2001:db8:110:3::2"),
                                                      ("interface Ethernet1", "   isis metric 1000"),
                                                      ("no ipv6 route 2001:db8::/33 2001:db8:110:3::2", "no ipv6 route 2001:db8:8000::/33 2001:db8:110:3::2")])
        self.assertEqual(north[1].inverse, ("interface Ethernet1", "   isis metric 10"))          # the captured value, not a constant
        self.assertEqual((south.device, south.lines, south.inverse), ("R1", ("route-map ISIS6-TO-OSPF3 permit 10", "   set metric 10000"),
                                                                      ("route-map ISIS6-TO-OSPF3 permit 10", "   no set metric")))
        self.assertEqual({op.device for op in ops}, {"S1", "R1"})                                    # the switch and the router, never a core
        self.assertTrue(all(op.cover is None for op in ops))                                        # no kernel cover: the migration guard is not a primitive

    def test_the_restore_is_the_reverse_and_offers_the_router_southbound_traffic_first(self):
        ops = drain.operations(ACCESS, migration.PRODUCTION, STATE, BOTH, drain=False)
        self.assertEqual([op.stage for op in ops], [drain.SOUTH] + [drain.NORTH] * 3)
        south, north = ops[0], ops[1:4]
        self.assertEqual((south.action, south.lines), (REMOVE, ("route-map ISIS6-TO-OSPF3 permit 10", "   no set metric")))
        self.assertIn("healthy", south.before[0].label)                                             # never offered traffic unverified
        self.assertEqual(north[0].lines[0], "ipv6 route 2001:db8::/33 2001:db8:110:1::1")            # shield toward the path about to carry it
        self.assertEqual(north[1].lines, ("interface Ethernet1", "   isis metric 10"))
        self.assertEqual({op.device for op in ops}, {"S1", "R1"})

    def test_each_direction_is_planned_on_its_own(self):
        self.assertEqual([op.stage for op in drain.operations(ACCESS, migration.PRODUCTION, STATE, BOTH[:1], drain=True)], [drain.NORTH] * 3)
        self.assertEqual([op.stage for op in drain.operations(ACCESS, migration.PRODUCTION, STATE, BOTH[1:], drain=True)], [drain.SOUTH])

    def test_every_planned_statement_is_an_existing_drain_primitive(self):
        for cells in (BOTH, BOTH[:1], BOTH[1:]):
            for direction in (True, False):
                ops = drain.operations(ACCESS, migration.PRODUCTION, STATE, cells, drain=direction)
                self.assertEqual(protection.violations(ops, writable={"S1", "R1"}), [])

    def test_a_core_cover_or_a_new_route_is_refused_as_a_maintenance_step(self):
        cover = migration.PRODUCTION.covers[0]
        op = Operation("r3-cover", "SOUTHBOUND", "R3", "TEMPORARY", ADD, cover.lines(), cover.removal_lines(), cover)
        found = protection.violations([op], writable={"R3"})
        self.assertTrue(any(text.startswith(protection.NOT_A_PRIMITIVE) and "kernel cover" in text for text in found))
        for line in ("ipv6 route 2001:db8:10::/63 fe80::1", "ipv6 route 2001:db8:10::/64 2001:db8:110:3::2", "shutdown",
                     "redistribute static", "ipv6 route 2001:db8::/33 Ethernet1"):
            self.assertTrue(protection.statement_violation(line), line)
        with self.assertRaises(ExecutorError):
            executor.spec_of(op, 1)

    def test_a_device_on_a_platform_without_proven_statements_is_refused(self):
        ops = drain.operations(ACCESS, migration.PRODUCTION, STATE, BOTH, drain=True)
        found = protection.violations(ops, writable={"S1", "R1"}, platforms={"S1": "ceos", "R1": "linux"})
        self.assertTrue(found and all(text.startswith(protection.NOT_A_PRIMITIVE) and "R1 (linux)" in text for text in found))
        self.assertEqual(protection.violations(ops, writable={"S1", "R1"}, platforms={"S1": "ceos", "R1": "ceos"}), [])

    def test_a_core_router_is_read_only_to_a_maintenance(self):
        class Core:
            def routes(self, prefix):
                return [prefix]

            def apply(self, *args):
                raise AssertionError("written")

        build = executor.read_only(lambda device: Core(), ("R3",))
        reader = build({"name": "R3"})
        self.assertEqual(reader.routes("x"), ["x"])
        for name in ("assess", "apply", "compensate", "save_startup"):
            with self.assertRaises(ExecutorError):
                getattr(reader, name)
        self.assertIsInstance(build({"name": "S1"}), Core)


class FakeDevice:
    """An executor fake: a set of applied operation keys is its whole configuration."""

    def __init__(self, name, log, fail_on=""):
        self.name, self.log, self.fail_on, self.config, self.startup, self.broken_undo = name, log, fail_on, set(), frozenset(), False

    def config_state_digest(self):
        return "|".join(sorted(self.config))

    def startup_state_digest(self):
        return "|".join(sorted(self.startup))

    def save_startup(self):
        self.startup = frozenset(self.config)
        self.log.append(("save", self.name))
        return ApplyOutcome(True)

    def _key(self, spec):
        return "|".join(spec.lines if spec.operation == "CREATE_DEFINE" else (spec.removal or {}).get("restore_lines") or spec.lines)

    def assess(self, spec):
        present = self._key(spec) in self.config
        wanted = spec.operation == "CREATE_DEFINE"
        return Assessment(SKIP_SATISFIED if present == wanted else APPLY, True)

    def apply(self, spec, assessment):
        if self.fail_on and self.fail_on in spec.lines[-1]:
            return ApplyOutcome(False, "COMMAND_REJECTED")
        (self.config.add if spec.operation == "CREATE_DEFINE" else self.config.discard)(self._key(spec))
        self.log.append(("apply", self.name, spec.lines[-1].strip()))
        return ApplyOutcome(True)

    def compensate(self, spec, assessment):
        if self.broken_undo:
            return CompensationOutcome("COMPENSATION_FAILED", "TRANSPORT_ERROR")
        (self.config.discard if spec.operation == "CREATE_DEFINE" else self.config.add)(self._key(spec))
        self.log.append(("undo", self.name, spec.lines[-1].strip()))
        return CompensationOutcome("COMPENSATED")


class Probes:
    run_id = "0a0a0a0a0a0a"

    def __init__(self):
        self.count, self.is_healthy, self.stopped, self.halted = 0, True, False, []

    def halt_run(self, run_id):
        self.halted.append(run_id)

    def lost(self):
        return self.count

    def healthy(self):
        return self.is_healthy, {"lost": self.count}

    def advancing(self):
        return True, {}

    def stop(self):
        self.stopped = True


def environment(log, probes=None, observer=None, fail_on=""):
    ticks = [0.0]                                # a clock that only moves when the run waits: no test ever sleeps
    env = shield_lifecycle.Environment(devices={}, executor_factory=None, read=None, probes=probes or Probes(), host_gate=lambda: (True, {"load1": 1.0}),
                                       observer=observer, sleep=lambda seconds: ticks.__setitem__(0, ticks[0] + seconds), clock=lambda: ticks[0])
    env.executors = {name: FakeDevice(name, log, fail_on) for name in ("S1", "R1", "S2", "R2", "R3", "R4")}
    env.connect = lambda _names: None
    return env


SHIELD = "ipv6 route 2001:db8::/33 2001:db8:110:3::2"           # one real shield half: the fakes key on statements
UNSHIELD = f"no {SHIELD}"


def simple_ops(drain_direction=True):
    if drain_direction:
        return [Operation("s1-shield", "NORTHBOUND", "S1", "TEMPORARY", ADD, (SHIELD,), (UNSHIELD,)),
                Operation("s1-metric", "NORTHBOUND", "S1", "MAINTENANCE", ADD, ("interface Ethernet1", "   isis metric 1000"), ("interface Ethernet1", "   isis metric 10")),
                Operation("s1-unshield", "NORTHBOUND", "S1", "TEMPORARY", REMOVE, (UNSHIELD,), (SHIELD,)),
                Operation("r1-metric", "SOUTHBOUND", "R1", "MAINTENANCE", ADD, ("route-map X permit 10", "   set metric 10000"), ("route-map X permit 10", "   no set metric"))]
    return [Operation("r1-metric-back", "SOUTHBOUND", "R1", "MAINTENANCE", REMOVE, ("route-map X permit 10", "   no set metric"), ("route-map X permit 10", "   set metric 10000")),
            Operation("s1-metric-back", "NORTHBOUND", "S1", "MAINTENANCE", REMOVE, ("interface Ethernet1", "   isis metric 10"), ("interface Ethernet1", "   isis metric 1000"))]


class ExecutorTests(SimpleTestCase):
    def test_a_staged_run_applies_reads_back_and_persists_exactly_the_verified_state(self):
        log = []
        env = environment(log)
        run = executor.Run(env, simple_ops(), persist=("S1", "R1"))
        self.assertEqual(run.precheck(), [])
        self.assertEqual(run.drive(), executor.SUCCEEDED)
        self.assertEqual([entry for entry in log if entry[0] == "apply"], [("apply", "S1", SHIELD), ("apply", "S1", "isis metric 1000"), ("apply", "S1", UNSHIELD),
                                                                          ("apply", "R1", "set metric 10000")])
        self.assertEqual(run.persisted, {"S1": "VERIFIED", "R1": "VERIFIED"})
        self.assertEqual(env.executors["S1"].startup_state_digest(), env.executors["S1"].config_state_digest())
        self.assertEqual([s["read_back"] for s in run.stages if s["status"] == "APPLIED"], [SKIP_SATISFIED] * 4)

    def test_a_failed_step_compensates_everything_newest_first_and_restores_the_exact_state(self):
        log = []
        env = environment(log, fail_on="set metric 10000")
        before = {name: device.config_state_digest() for name, device in env.executors.items()}
        run = executor.Run(env, simple_ops(), persist=("S1", "R1"))
        self.assertEqual(run.drive(), executor.ROLLED_BACK)
        self.assertEqual(run.failure["code"], "APPLY_FAILED")
        self.assertEqual([entry for entry in log if entry[0] == "undo"], [("undo", "S1", UNSHIELD), ("undo", "S1", "isis metric 1000"), ("undo", "S1", SHIELD)])
        self.assertEqual({name: device.config_state_digest() for name, device in env.executors.items()}, before)
        self.assertEqual(run.persisted, {})                                 # nothing unverified ever reached a startup configuration

    def test_one_lost_probe_aborts_and_compensates(self):
        log, probes = [], Probes()

        def observer(event, key):
            if (event, key) == ("after", "s1-metric"):
                probes.count = 3

        run = executor.Run(environment(log, probes, observer), simple_ops())
        self.assertEqual(run.drive(), executor.ROLLED_BACK)
        self.assertEqual((run.failure["code"], run.probes_lost), ("PRODUCTION_PACKET_LOSS", 3))
        self.assertEqual(len([entry for entry in log if entry[0] == "undo"]), 2)

    def test_a_compensation_that_cannot_be_proven_is_reported_incomplete(self):
        log = []
        env = environment(log, fail_on="set metric 10000")
        env.executors["S1"].broken_undo = True
        run = executor.Run(env, simple_ops())
        self.assertEqual(run.drive(), executor.INCOMPLETE)
        self.assertEqual(run.compensation[0]["status"], "COMPENSATION_FAILED")

    def test_a_failed_gate_a_changed_device_and_an_unhealthy_precheck_all_refuse(self):
        ops = simple_ops()
        ops[1] = Operation("s1-metric", "NORTHBOUND", "S1", "MAINTENANCE", ADD, ops[1].lines, ops[1].inverse, after=(Check("aggregate moved", lambda env: (False, "still on the uplink")),))
        run = executor.Run(environment([]), ops)
        self.assertEqual((run.drive(), run.failure["code"]), (executor.ROLLED_BACK, "GATE_FAILED"))
        env = environment([])
        env.observer = lambda event, key: env.executors["S1"].config.add("someone else") if (event, key) == ("after", "s1-shield") else None
        run = executor.Run(env, simple_ops())
        run.drive()
        self.assertEqual(run.failure["code"], "OUT_OF_BAND_CHANGE")
        probes = Probes()
        probes.is_healthy = False
        env = environment([], probes)
        env.executors["S1"].config.add("unsaved")
        self.assertEqual([b["code"] for b in executor.Run(env, simple_ops(), persist=("S1",)).precheck()], ["PRODUCTION_PROBES_UNHEALTHY", "STARTUP_NOT_IN_SYNC"])

    def test_a_restore_finishes_an_interrupted_run(self):
        log = []
        env = environment(log)
        env.executors["S1"].config.add("interface Ethernet1|   isis metric 1000")       # R1 was already restored when the run was interrupted
        run = executor.Run(env, simple_ops(False), resume=True)
        self.assertEqual(run.drive(), executor.SUCCEEDED)
        self.assertEqual([entry for entry in log if entry[0] == "apply"], [("apply", "S1", "isis metric 10")])


OBSERVE = collector.observe                  # the real collector: ServiceTests replaces the module attribute with a script
ACTIVE_H1 = (("H1", 6, NORTHBOUND), ("H1", 6, SOUTHBOUND))


def observation(device="R1", *, moved=True, active=(), states=READY, found=None):
    return OBSERVE(device, sources(found if found is not None else network(drained=device if moved else ""), active=active, states=states))


class ServiceFixture(TestCase):
    """The executor on fakes and the drain layer's device reads stubbed.  The fake devices keep their configuration
    between two commands, as real devices do."""

    def setUp(self):
        self.log, self.clock, self.probes, self.healthy, self.observations = [], [T0], Probes(), True, []
        self.devices = {name: FakeDevice(name, self.log) for name in ("S1", "R1", "S2", "R2", "R3", "R4")}
        patches = [mock.patch.object(drain, "capture", lambda env, access, definition: (dict(STATE), [])),
                   mock.patch.object(drain, "operations", lambda access, definition, state, cells, drain: simple_ops(drain)),
                   mock.patch.object(drain, "final_checks", lambda *args, **kwargs: ()),
                   mock.patch.object(drain, "router_healthy", lambda env, **kwargs: (self.healthy, "IS-IS adjacency down")),
                   mock.patch.object(service, "_remaining", lambda env, access, cells=None: tuple(
                       f"{name}: {key}" for name, device in sorted(self.devices.items()) for key in sorted(device.config) if "metric" in key or "ipv6 route" in key)),
                   mock.patch.object(service, "_uncertain", lambda env, access: tuple(
                       key for key in sorted(self.devices["S1"].config) if key == SHIELD)),
                   mock.patch.object(collector, "observe", self._observe)]
        for patch in patches:
            patch.start()
            self.addCleanup(patch.stop)
        self.runtime = service.Runtime(sources(states=READY), self._environment, lambda env: None, migration.PRODUCTION, gated=False, probe_warmup=0, sleep=lambda _s: None)

    def _observe(self, device, src):
        if not self.observations:
            raise AssertionError("an observation was not scripted")
        return self.observations.pop(0)

    def _environment(self):
        env = environment(self.log, self.probes)
        env.executors = dict(self.devices)                                    # the same devices for every command
        return env

    def now(self):
        return self.clock[0]

    def configured(self):
        return {name: set(device.config) for name, device in self.devices.items() if device.config}

    def writes(self):
        return [entry for entry in self.log if entry[0] in ("apply", "undo")]

    def approved(self, device="R1", active=ACTIVE_H1):
        row = service.request(device, "operator", "replace a line card", timedelta(hours=4), now=T0, runtime=self.runtime)
        self.observations.append(observation(device, moved=False, active=active))
        row = service.evaluate(row.pk, "operator", now=T0, runtime=self.runtime)
        self.assertEqual(row.state, lifecycle.PLANNED)
        return service.approve(row.pk, "lead", now=T0, plan_hash=row.plan_hash)

    def enter(self, row, *, moved=True, active=ACTIVE_H1):
        self.observations += [observation(row.device_name, moved=False, active=active), observation(row.device_name, moved=moved)]
        return service.enter(row.pk, "operator", now=self.now, runtime=self.runtime)

    def tick(self):
        return service.tick(now=self.now, runtime_factory=lambda: self.runtime)

    def restored_view(self, device="R1", found=None):
        """What the post-restore verification reads: the device back on its paths."""
        self.observations.append(observation(device, moved=False, found=found))



class ServiceTests(ServiceFixture):
    """Entry, exit, the deadline, the worker and Change refusal."""

    # -- entry --------------------------------------------------------------------------------------------------------
    def test_r1_becomes_active_only_with_both_directions_proven_and_zero_loss(self):
        row = self.approved()
        self.assertEqual((row.state, [step["mechanism"] for step in row.snapshot["steps"]]), (lifecycle.APPROVED, [policy.ISIS_NORTHBOUND, policy.OSPFV3_SOUTHBOUND]))
        row = self.enter(row)
        self.assertEqual(row.state, lifecycle.ACTIVE)
        self.assertEqual(row.deadline_at, T0 + timedelta(days=7))
        evidence_ = row.snapshot["evidence"]
        self.assertEqual((evidence_["entry"]["outcome"], evidence_["entry"]["probes"]["lost"], evidence_["prestate"]["uplink_metric"]), (executor.SUCCEEDED, 0, 10))
        self.assertEqual(evidence_["entry"]["persistence"], {"R1": "VERIFIED", "S1": "VERIFIED"})
        self.assertTrue(self.probes.stopped)
        self.assertTrue(all(proof["moved"] and proof["probes_lost"] == 0 for proof in evidence_["entry"]["proofs"]))
        self.assertFalse(models.ExecutionDeviceLock.objects.exists())          # the locks are held only while the drain runs
        self.assertEqual((row.claim_token, row.queued_action), ("", ""))

    def test_a_direction_that_is_not_proven_moved_takes_the_device_back_out(self):
        row = self.approved()
        self.observations += [observation("R1", moved=False, active=ACTIVE_H1), observation("R1", moved=False)]    # the drain ran, and a production flow still passes R1
        self.restored_view()
        row = service.enter(row.pk, "operator", now=self.now, runtime=self.runtime)
        self.assertEqual((row.state, row.escalated), (lifecycle.ABORTED_RESTORED, False))
        self.assertIn("TRAFFIC_NOT_MOVED", row.snapshot["evidence"]["entry"]["aborted"])
        self.assertEqual(self.configured(), {})

    def test_a_failure_during_the_drain_is_compensated_and_the_entry_ends_restored(self):
        row = self.approved()
        for device in self.devices.values():
            device.fail_on = "set metric 10000"
        self.observations.append(observation("R1", moved=False, active=ACTIVE_H1))
        self.restored_view()
        with self.assertRaises(model.MaintenanceError) as caught:
            service.enter(row.pk, "operator", now=self.now, runtime=self.runtime)
        self.assertEqual(caught.exception.code, "ENTRY_ABORTED")
        row.refresh_from_db()
        self.assertEqual((row.state, row.escalated), (lifecycle.ABORTED_RESTORED, False))
        self.assertEqual(row.snapshot["evidence"]["entry"]["outcome"], executor.ROLLED_BACK)
        self.assertEqual([entry[2] for entry in self.writes()], [SHIELD, "isis metric 1000", UNSHIELD, UNSHIELD, "isis metric 1000", SHIELD])
        self.assertEqual(self.configured(), {})
        self.assertEqual(row.claim_token, "")

    def test_entry_is_refused_with_nothing_written_when_a_gate_fails(self):
        row = self.approved()
        self.probes.is_healthy = False
        self.observations += [observation("R1", moved=False, active=ACTIVE_H1)]
        with self.assertRaises(model.MaintenanceError) as caught:
            service.enter(row.pk, "operator", now=self.now, runtime=self.runtime)
        row.refresh_from_db()
        self.assertEqual((caught.exception.code, row.state, self.writes()), ("ENTRY_REFUSED", lifecycle.APPROVED, []))
        self.assertIn("PRODUCTION_PROBES_UNHEALTHY", [f["code"] for f in row.snapshot["findings"]])
        refused = models.MaintenanceEvidence.objects.filter(record=row, kind=chain.REFUSED).get()
        self.assertIn("PRODUCTION_PROBES_UNHEALTHY", [f["code"] for f in refused.payload["findings"]])
        self.assertTrue(models.AuditEvent.objects.filter(event_type="MAINTENANCE_REFUSED", object_id=row.record_id).exists())

    def test_the_managed_network_refuses_a_mechanism_that_is_not_ready(self):
        row = self.approved()
        self.runtime.gated = True
        self.observations += [observation("R1", moved=False, active=ACTIVE_H1)]
        with self.assertRaises(model.MaintenanceError):
            service.enter(row.pk, "operator", now=self.now, runtime=self.runtime)
        row.refresh_from_db()
        self.assertEqual((row.state, self.log), (lifecycle.APPROVED, []))
        self.assertIn("TRANSITION_PROVEN_NOT_AUTHORIZED", [f["code"] for f in row.snapshot["findings"]])

    # -- the plan -----------------------------------------------------------------------------------------------------
    def test_the_plan_is_reviewable_hashed_and_names_every_action_check_and_inverse(self):
        row = self.approved()
        document = row.snapshot["plan"]
        self.assertEqual(row.plan_hash, plan.digest(document))
        self.assertEqual((document["target"]["device"], row.plan_status), ("R1", plan.CURRENT))
        self.assertEqual([op["key"] for op in document["drain"]["operations"]], ["s1-shield", "s1-metric", "s1-unshield", "r1-metric"])
        self.assertEqual([op["key"] for op in document["restore"]["operations"]], ["r1-metric-back", "s1-metric-back"])
        self.assertEqual(document["drain"]["operations"][1]["inverse"], ["interface Ethernet1", "   isis metric 10"])
        self.assertIn("R1 is healthy enough to take traffic", document["restore"]["guards"])
        self.assertEqual(document["baseline"]["prestate"]["uplink_metric"], 10)
        self.assertEqual(document["deadline"]["maintenance_cycle_seconds"], 7 * 86400)
        self.assertEqual(document["protected"]["management_vlan"], 200)
        self.assertEqual(self.log, [])                                        # planning wrote nothing

    def test_approval_is_bound_to_the_plan_hash(self):
        row = service.request("R1", "operator", "work", timedelta(hours=1), now=T0, runtime=self.runtime)
        self.observations.append(observation("R1", moved=False, active=ACTIVE_H1))
        row = service.evaluate(row.pk, "operator", now=T0, runtime=self.runtime)
        with self.assertRaises(model.MaintenanceError) as caught:
            service.approve(row.pk, "lead", now=T0, plan_hash="0" * 64)
        self.assertEqual(caught.exception.code, "PLAN_HASH_MISMATCH")
        with self.assertRaises(model.MaintenanceError) as caught:
            service.approve(row.pk, "lead", now=T0 + service.PLAN_VALIDITY + timedelta(seconds=1), plan_hash=row.plan_hash)
        self.assertEqual(caught.exception.code, plan.PLAN_EXPIRED)
        old = row.plan_hash
        self.observations.append(observation("R1", moved=False, active=ACTIVE_H1))
        row = service.evaluate(row.pk, "operator", now=T0 + timedelta(minutes=1), runtime=self.runtime)     # a new plan replaces the old one
        self.assertNotEqual(old, row.plan_hash)
        with self.assertRaises(model.MaintenanceError) as caught:
            service.approve(row.pk, "lead", now=T0 + timedelta(minutes=1), plan_hash=old)
        self.assertEqual(caught.exception.code, "PLAN_HASH_MISMATCH")
        self.assertEqual(store.load(row).approved_by, "")

    def test_a_changed_device_makes_the_approved_plan_stale_and_refuses_entry(self):
        row = self.approved()
        changed = network()
        changed["S2"].groups["config_paths"] = FactGroup(data=["hostname S2", "interface Ethernet7 > shutdown"], source="LIVE", observed_at=T0)
        self.observations.append(observation("R1", active=ACTIVE_H1, found=changed))
        with self.assertRaises(model.MaintenanceError) as caught:
            service.enter(row.pk, "operator", now=self.now, runtime=self.runtime)
        row.refresh_from_db()
        self.assertEqual((caught.exception.code, row.state, row.plan_status, self.log), ("ENTRY_REFUSED", lifecycle.APPROVED, plan.STALE, []))
        stale = [f for f in row.snapshot["findings"] if f["code"] == plan.PLAN_STALE]
        self.assertIn("baseline", stale[0]["detail"])
        with self.assertRaises(model.MaintenanceError):                       # a stale plan cannot be queued for entry either
            service.queue(row.pk, service.ENTER, "operator", now=T0, plan_hash=row.plan_hash)

    def test_an_expired_plan_refuses_entry(self):
        row = self.approved()
        self.clock[0] = T0 + service.PLAN_VALIDITY + timedelta(minutes=1)
        self.observations.append(observation("R1", moved=False, active=ACTIVE_H1))
        with self.assertRaises(model.MaintenanceError):
            service.enter(row.pk, "operator", now=self.now, runtime=self.runtime)
        row.refresh_from_db()
        self.assertIn(plan.PLAN_EXPIRED, [f["code"] for f in row.snapshot["findings"]])
        self.assertEqual(self.log, [])

    def test_a_stale_observation_builds_no_plan_and_refuses_entry(self):
        row = service.request("R1", "operator", "work", timedelta(hours=1), now=T0, runtime=self.runtime)
        self.observations.append(observation("R1", moved=False, active=ACTIVE_H1))          # read at T0, judged 90 s later
        row = service.evaluate(row.pk, "operator", now=T0 + timedelta(seconds=90), runtime=self.runtime)
        self.assertEqual((row.state, row.plan_hash), (lifecycle.BLOCKED, ""))
        self.assertIn(service.NOT_FRESH, [f["code"] for f in row.snapshot["findings"]])
        service.cancel(row.pk, "operator", now=T0)
        row = self.approved()
        self.clock[0] = T0 + timedelta(seconds=90)                                           # the entry's own observation is not fresh
        self.observations.append(observation("R1", moved=False, active=ACTIVE_H1))
        with self.assertRaises(model.MaintenanceError):
            service.enter(row.pk, "operator", now=self.now, runtime=self.runtime)
        row.refresh_from_db()
        self.assertIn(service.NOT_FRESH, [f["code"] for f in row.snapshot["findings"]])
        self.assertEqual((row.state, self.log), (lifecycle.APPROVED, []))

    def test_a_plan_that_would_install_a_core_cover_is_refused_before_anything_is_written(self):
        cover = migration.PRODUCTION.covers[0]
        bad = [Operation("r3-cover", "SOUTHBOUND", "R3", "TEMPORARY", ADD, cover.lines(), cover.removal_lines(), cover)]
        with mock.patch.object(drain, "operations", lambda access, definition, state, cells, drain: bad):
            row = service.request("R1", "operator", "work", timedelta(hours=1), now=T0, runtime=self.runtime)
            self.observations.append(observation("R1", moved=False, active=ACTIVE_H1))
            row = service.evaluate(row.pk, "operator", now=T0, runtime=self.runtime)
        self.assertEqual(row.state, lifecycle.BLOCKED)
        self.assertIn(protection.NOT_A_PRIMITIVE, [f["code"] for f in row.snapshot["findings"]])
        self.assertEqual(self.log, [])

    def test_a_plan_that_would_touch_the_protected_scope_is_refused(self):
        bad = [Operation("s1-mgmt", "NORTHBOUND", "S1", "MAINTENANCE", ADD, ("interface Vlan200", "   shutdown"), ("interface Vlan200", "   no shutdown"))]
        with mock.patch.object(drain, "operations", lambda access, definition, state, cells, drain: bad):
            row = service.request("R1", "operator", "work", timedelta(hours=1), now=T0, runtime=self.runtime)
            self.observations.append(observation("R1", moved=False, active=ACTIVE_H1))
            row = service.evaluate(row.pk, "operator", now=T0, runtime=self.runtime)
        self.assertEqual((row.state, row.plan_hash), (lifecycle.BLOCKED, ""))
        self.assertIn(protection.PROTECTED_SCOPE, [f["code"] for f in row.snapshot["findings"]])
        outside = [Operation("r5-x", "NORTHBOUND", "R5", "MAINTENANCE", ADD, ("router bgp 65005",), ("no router bgp 65005",))]
        self.assertTrue(protection.violations(outside, writable={"R1", "S1"})[0].startswith(protection.OUTSIDE_SCOPE))
        run = executor.Run(environment([]), bad, guard=lambda op: protection.violations((op,), writable={"S1"})[0])     # and the executor refuses the write itself
        self.assertEqual((run.drive(), run.failure["code"]), (executor.ROLLED_BACK, protection.PROTECTED_SCOPE))

    # -- exit and restore ---------------------------------------------------------------------------------------------
    def test_manual_exit_restores_from_the_stored_pre_state(self):
        row = self.enter(self.approved())
        self.assertEqual(len(self.configured()), 2)                           # S1 and R1 carry the drain metrics
        self.restored_view()
        row = service.leave(row.pk, "operator", now=self.now, runtime=self.runtime)
        self.assertEqual((row.state, row.restore_trigger, row.escalated), (lifecycle.RESTORED, lifecycle.MANUAL_EXIT, False))
        self.assertEqual(row.snapshot["evidence"]["restore"]["outcome"], executor.SUCCEEDED)
        self.assertEqual([e[2] for e in self.log if e[0] == "apply"][-2:], ["no set metric", "isis metric 10"])
        self.assertEqual(self.configured(), {})
        self.assertEqual(row.snapshot["evidence"]["restore_verification"]["findings"], [])

    def test_an_unhealthy_device_is_not_restored_and_the_drained_state_is_kept(self):
        row = self.enter(self.approved())
        self.healthy = False
        applied = len(self.log)
        row = service.leave(row.pk, "operator", now=self.now, runtime=self.runtime)
        self.assertEqual((row.state, row.escalated), (lifecycle.RESTORE_FAILED, True))
        self.assertEqual(len(self.log), applied)                             # nothing was written
        self.assertEqual(len(row.snapshot["maintenance_only_state"]), 2)
        self.assertIn("PRECHECK_FAILED", [f["code"] for f in row.snapshot["findings"]])
        self.healthy = True                                                  # the operator repairs it and runs the exit again
        self.restored_view()
        row = service.leave(row.pk, "operator", now=self.now, runtime=self.runtime)
        self.assertEqual((row.state, row.escalated), (lifecycle.RESTORED, True))

    def test_a_restore_is_restored_only_when_the_fresh_observation_shows_the_baseline_back(self):
        row = self.enter(self.approved())
        broken = network()
        broken["R1"].groups["isis"] = FactGroup(data=[], source="LIVE", observed_at=T0)       # the access adjacency did not come back
        for _attempt in range(service.VERIFY_ATTEMPTS):
            self.restored_view(found=broken)
        row = service.leave(row.pk, "operator", now=self.now, runtime=self.runtime)
        self.assertEqual((row.state, row.escalated), (lifecycle.RESTORE_FAILED, True))
        self.assertIn("ADJACENCY_NOT_RESTORED", [f["code"] for f in row.snapshot["findings"]])
        self.assertEqual(row.snapshot["evidence"]["restore_verification"]["attempts"], service.VERIFY_ATTEMPTS)

    # -- deadline and worker ------------------------------------------------------------------------------------------
    def test_the_deadline_worker_runs_the_same_restore_and_the_requested_window_does_not(self):
        row = self.enter(self.approved())
        self.clock[0] = T0 + timedelta(hours=5)                              # past the requested four hours
        self.assertEqual(self.tick(), [])
        self.clock[0] = T0 + timedelta(days=7, minutes=1)
        self.restored_view()
        (result,) = self.tick()
        row.refresh_from_db()
        self.assertEqual((result["item"], result["outcome"], row.state, row.restore_trigger), (service.DEADLINE, "DONE", lifecycle.RESTORED, lifecycle.DEADLINE))
        self.assertEqual(self.tick(), [])                                     # idempotent

    def test_a_deadline_restore_that_is_not_safe_escalates_and_keeps_the_evidence(self):
        row = self.enter(self.approved())
        self.healthy = False
        self.clock[0] = T0 + timedelta(days=8)
        (result,) = self.tick()
        row.refresh_from_db()
        self.assertEqual((row.state, row.restore_trigger, row.escalated, result["escalated"]), (lifecycle.RESTORE_FAILED, lifecycle.DEADLINE, True, True))
        self.assertEqual(row.snapshot["evidence"]["restore"]["outcome"], executor.BLOCKED)
        self.assertEqual(self.tick(), [])                                     # an escalated record waits for an operator, it is not retried blindly

    def test_queued_requests_are_run_once_by_the_worker(self):
        row = service.request("R1", "operator", "work", timedelta(hours=1), now=T0, runtime=self.runtime)
        row = service.queue(row.pk, service.EVALUATE, "operator", now=T0)
        with self.assertRaises(model.MaintenanceError) as caught:
            service.queue(row.pk, service.EVALUATE, "operator", now=T0)
        self.assertEqual(caught.exception.code, "RECORD_BUSY")
        self.observations.append(observation("R1", moved=False, active=ACTIVE_H1))
        (result,) = self.tick()
        row.refresh_from_db()
        self.assertEqual((result["outcome"], row.state, row.queued_action), ("DONE", lifecycle.PLANNED, ""))
        with self.assertRaises(model.MaintenanceError):                       # entry only of an approved plan
            service.queue(row.pk, service.ENTER, "operator", now=T0, plan_hash=row.plan_hash)
        row = service.approve(row.pk, "lead", now=T0, plan_hash=row.plan_hash)
        row = service.queue(row.pk, service.ENTER, "operator", now=T0, plan_hash=row.plan_hash)
        self.observations += [observation("R1", moved=False, active=ACTIVE_H1), observation("R1")]
        (result,) = self.tick()
        row.refresh_from_db()
        self.assertEqual((result["outcome"], row.state), ("DONE", lifecycle.ACTIVE))
        self.assertEqual(row.snapshot["history"][-2]["actor"], "operator")    # the operator who queued it, not the worker
        self.assertEqual(self.tick(), [])

    def test_a_claimed_record_is_never_acted_on_twice(self):
        row = self.approved()
        token = service._claim(row, service.ENTER, at=T0)
        with self.assertRaises(model.MaintenanceError) as caught:
            service.enter(row.pk, "operator", now=self.now, runtime=self.runtime)
        self.assertEqual(caught.exception.code, "RECORD_BUSY")
        for call in (lambda: service.queue(row.pk, service.ENTER, "operator", now=T0, plan_hash=row.plan_hash),
                     lambda: service.cancel(row.pk, "operator", now=T0), lambda: service.approve(row.pk, "lead", now=T0, plan_hash=row.plan_hash)):
            with self.assertRaises(model.MaintenanceError):
                call()
        models.MaintenanceRecord.objects.filter(pk=row.pk).update(queued_action=service.ENTER)
        self.assertEqual(self.tick(), [])                                     # a fresh claim: the worker leaves it alone
        service._release(row, token)
        for direct in (lambda: service.enter(row.pk, "operator", now=self.now, runtime=self.runtime),     # queued: not run directly too
                       lambda: service.evaluate(row.pk, now=T0, runtime=self.runtime), lambda: service.leave(row.pk, "operator", now=self.now, runtime=self.runtime)):
            with self.assertRaises(model.MaintenanceError) as caught:
                direct()
            self.assertEqual(caught.exception.code, "RECORD_BUSY")
        self.assertEqual(self.log, [])

    def test_an_interrupted_entry_is_recovered_by_aborting_and_restoring(self):
        row = self.approved()

        def die(event, key):                                                  # the worker process stops after the uplink metric was set
            if (event, key) == ("after", "s1-metric"):
                raise SystemExit("killed")

        base = self._environment
        self.runtime.environment = lambda: (lambda env: (setattr(env, "observer", die), env)[1])(base())
        self.observations.append(observation("R1", moved=False, active=ACTIVE_H1))
        with self.assertRaises(SystemExit):
            service.enter(row.pk, "operator", now=self.now, runtime=self.runtime)
        models.MaintenanceRecord.objects.filter(pk=row.pk).update(claim_token="dead", claim_action=service.ENTER, heartbeat_at=T0 - timedelta(hours=1))
        row.refresh_from_db()
        self.assertEqual(row.state, lifecycle.ENTERING)
        self.assertEqual(self.configured(), {"S1": {SHIELD, "interface Ethernet1|   isis metric 1000"}})     # half drained
        self.runtime.environment = base
        (result,) = self.tick()
        row.refresh_from_db()
        self.assertEqual(result["item"], service.RECOVER)
        self.assertTrue(any(entry["note"].startswith("entry interrupted") for entry in row.snapshot["history"]))
        interrupted = next(e for e in chain.entries(row) if e.summary == "entry interrupted")
        self.assertEqual(interrupted.payload["journal"], {"last": "after s1-metric", "open": "", "probe_runs": [Probes.run_id]})  # where it stopped, durably
        self.assertEqual(self.probes.halted, [Probes.run_id])                 # the dead worker's probes were stopped before the restore measured
        # the drain was interrupted inside its northbound stage (its temporary shield is still there): no restore is built
        # for that state, so nothing is written; the record is escalated with the exact state listed, never guessed away
        self.assertEqual(self.configured(), {"S1": {SHIELD, "interface Ethernet1|   isis metric 1000"}})
        self.assertEqual(self.writes()[-1], ("apply", "S1", "isis metric 1000"))                  # the last write is still the drain's
        self.assertEqual((row.state, row.escalated), (lifecycle.RESTORE_FAILED, True))
        self.assertIn(service.UNCERTAIN, [f["code"] for f in row.snapshot["findings"]])
        self.assertEqual(sorted(row.snapshot["maintenance_only_state"]), sorted([f"S1: {SHIELD}", "S1: interface Ethernet1|   isis metric 1000"]))
        self.assertEqual(row.claim_token, "")

    def test_a_device_held_by_another_execution_refuses_entry(self):
        row = self.approved()
        other = models.MaintenanceRecord.objects.create(device_name="R2", state=lifecycle.ENTERING, requested_by="x", reason="y", requested_at=T0,
                                                        requested_duration_seconds=60)
        models.ExecutionDeviceLock.objects.create(device="S1", maintenance=other)
        self.observations.append(observation("R1", moved=False, active=ACTIVE_H1))
        with self.assertRaises(model.MaintenanceError):
            service.enter(row.pk, "operator", now=self.now, runtime=self.runtime)
        row.refresh_from_db()
        self.assertEqual((row.state, self.log), (lifecycle.APPROVED, []))
        self.assertIn("DEVICE_LOCKED", [f["code"] for f in row.snapshot["findings"]])
        self.assertEqual(list(models.ExecutionDeviceLock.objects.values_list("device", "maintenance_id")), [("S1", other.pk)])

    # -- scope ---------------------------------------------------------------------------------------------------------
    def test_only_the_writable_managed_scope_can_be_requested(self):
        self.runtime.writable = lambda: {"R1", "R2", "R3", "R4", "S1", "S2", "mgmt_swt"}
        with self.assertRaises(model.MaintenanceError) as caught:
            service.request("R5", "operator", "work", timedelta(hours=1), now=T0, runtime=self.runtime)
        self.assertEqual(caught.exception.code, protection.OUTSIDE_SCOPE)
        self.assertFalse(models.MaintenanceRecord.objects.exists())

    def test_the_management_switch_strands_every_managed_device(self):
        observation_ = OBSERVE("mgmt_swt", sources())
        management = [d for d in observation_.dependencies if d.kind == "MANAGEMENT"]
        self.assertEqual((management[0].stranded, "R1" in management[0].detail, "R5" in management[0].detail), (True, True, False))
        report = readiness.evaluate(model.Request("mgmt_swt", "op", "work", timedelta(hours=1), T0), observation_.flows, observation_.dependencies,
                                    alternates=observation_.alternates, mechanisms=observation_.mechanisms)
        self.assertIn(readiness.DEPENDENCY_STRANDED, [f.code for f in report.blockers])

    # -- Changes, status, evidence -------------------------------------------------------------------------------------
    def test_conflicting_changes_are_refused(self):
        self.assertEqual(service.conflict("R1"), "")
        row = self.enter(self.approved())
        self.assertIn("R1 is ACTIVE in maintenance", service.conflict("R1"))  # ACTIVE: the target is reserved until it is restored
        self.assertIn("carries the traffic or the drain state of R1", service.conflict("S1"))
        self.assertIn("R1", service.conflict("R2"))
        self.assertEqual(service.conflict("S3"), "")
        self.assertEqual(eligibility._maintenance_conflicts(["R1", "R2", "S3"]).keys(), {"R1", "R2"})
        self.healthy = False
        service.leave(row.pk, "operator", now=self.now, runtime=self.runtime)
        self.assertIn("RESTORE_FAILED_ESCALATED", service.conflict("R1"))    # escalated: nothing may change the device
        self.assertEqual(models.MaintenanceRecord.objects.get(pk=row.pk).state, lifecycle.RESTORE_FAILED)
        self.assertEqual(eligibility._maintenance_conflicts(["R1", "R2", "S1", "S3"]).keys(), {"R1", "R2", "S1"})   # nor what it leans on

    def test_status_names_the_block_reason_and_the_escalation(self):
        row = service.request("S1", "operator", "replace a fan", timedelta(hours=1), now=T0, runtime=self.runtime)
        self.observations.append(observation("S1", moved=False, active={("H1", 6, NORTHBOUND)}))
        row = service.evaluate(row.pk, now=T0, runtime=self.runtime)
        status = service.status(row.pk, now=T0)
        self.assertEqual((status["state"], status["readiness"], status["cells"]["IPV6/NORTHBOUND"]), (lifecycle.BLOCKED, "BLOCKED", readiness.BLOCKED))
        self.assertIn("H1 to WebServer", status["block_reasons"][0])
        self.assertEqual(store.load(row).evidence["observation"]["single_homed"], ["H1", "H2"])
        h1 = next(flow for flow in status["flows"] if flow["label"] == "h1-v6-north")
        self.assertEqual((h1["source"], h1["destination"], h1["activity"], h1["redundancy"], h1["proven_drain"], h1["verdict"]),
                         ("H1", "WebServer", ACTIVE, "none: the host is single-homed to this device", False, readiness.BLOCKED))
        self.assertIn(readiness.NO_LOSSLESS_DRAIN, h1["blocking"][0])
        h3 = next(flow for flow in status["flows"] if flow["label"] == "h3-v6-north")
        self.assertEqual(h3["verdict"], readiness.IRRELEVANT)

    def record(self, device, state, **fields):
        return models.MaintenanceRecord.objects.create(device_name=device, state=state, requested_by="x", reason="y", requested_at=T0,
                                                       requested_duration_seconds=60, **fields)

    def test_the_target_is_reserved_in_every_maintenance_state_and_released_by_no_other(self):
        """A record with no plan step (as an entry with nothing to move): its target alone is reserved."""
        for state in lifecycle.IN_MAINTENANCE:                               # ENTERING, ACTIVE, RESTORING, RESTORE_FAILED_ESCALATED
            row = self.record("S1", state)
            self.assertIn(f"S1 is {state} in maintenance", service.conflict("S1"))
            self.assertEqual(eligibility._maintenance_conflicts(["S1", "S2", "R1", "R2", "S3"]).keys(), {"S1"}, state)   # neighbours are free
            row.delete()
        for state in (lifecycle.REQUESTED, lifecycle.BLOCKED, lifecycle.READY, lifecycle.PLANNED, lifecycle.APPROVED,
                      lifecycle.RESTORED, lifecycle.ABORTED_RESTORED, lifecycle.CANCELLED):
            row = self.record("S1", state)
            self.assertEqual(service.conflict("S1"), "", state)               # before entry and once resolved: nothing is reserved
            row.delete()

    def test_a_zero_step_maintenance_reserves_its_target_from_entry_to_restore(self):
        row = self.approved("S1", active=())
        self.assertEqual((row.snapshot["steps"], service.conflict("S1")), ([], ""))       # approved, not entered: not reserved
        self.observations += [observation("S1", moved=False)]
        row = service.enter(row.pk, "operator", now=self.now, runtime=self.runtime)
        self.assertEqual((row.state, self.log), (lifecycle.ACTIVE, []))
        self.assertIn("S1 is ACTIVE in maintenance", service.conflict("S1"))
        self.assertEqual(eligibility._maintenance_conflicts(["S1", "S2", "R1", "R2", "S3"]).keys(), {"S1"})
        self.assertFalse(models.ExecutionDeviceLock.objects.exists())        # the reservation is the state, not a held lock
        self.restored_view("S1")
        row = service.leave(row.pk, "operator", now=self.now, runtime=self.runtime)
        self.assertEqual((row.state, self.log), (lifecycle.RESTORED, []))
        self.assertEqual(service.conflict("S1"), "")

    def test_a_zero_step_entry_is_refused_while_another_execution_holds_its_target(self):
        row = self.approved("S1", active=())
        other = self.record("S2", lifecycle.ENTERING)
        models.ExecutionDeviceLock.objects.create(device="S1", maintenance=other)
        self.observations += [observation("S1", moved=False)]
        with self.assertRaises(model.MaintenanceError):
            service.enter(row.pk, "operator", now=self.now, runtime=self.runtime)
        row.refresh_from_db()
        self.assertEqual((row.state, self.log), (lifecycle.APPROVED, []))
        self.assertIn("DEVICE_LOCKED", [f["code"] for f in row.snapshot["findings"]])
        self.assertEqual(list(models.ExecutionDeviceLock.objects.values_list("device", "maintenance_id")), [("S1", other.pk)])

    def test_a_quiet_access_switch_enters_and_leaves_without_any_write(self):
        row = self.approved("S1", active=())
        self.assertEqual(row.snapshot["steps"], [])
        self.observations += [observation("S1", moved=False)]
        row = service.enter(row.pk, "operator", now=self.now, runtime=self.runtime)
        self.assertEqual((row.state, self.log), (lifecycle.ACTIVE, []))
        self.restored_view("S1")
        row = service.leave(row.pk, "operator", now=self.now, runtime=self.runtime)
        self.assertEqual((row.state, self.log), (lifecycle.RESTORED, []))

    def test_the_evidence_is_append_only_hash_chained_and_tamper_evident(self):
        row = self.enter(self.approved())
        self.restored_view()
        row = service.leave(row.pk, "operator", now=self.now, runtime=self.runtime)
        kinds = [entry.kind for entry in chain.entries(row) if entry.kind != chain.STEP]
        self.assertEqual(kinds, [chain.REQUESTED, chain.OBSERVED, chain.PLANNED, chain.APPROVED, chain.TRANSITION, chain.ENTRY,
                                 chain.TRANSITION, chain.RESTORE])
        steps = [entry.summary for entry in chain.entries(row) if entry.kind == chain.STEP]
        self.assertEqual(steps[:3], [f"probes {Probes.run_id}", "before s1-shield", "after s1-shield"])   # written as the run goes, before the next write
        self.assertEqual(chain.journal(row), {"last": steps[-1], "open": "", "probe_runs": [Probes.run_id]})
        self.assertFalse(models.AuditEvent.objects.filter(summary__contains="before s1-shield").exists())   # evidence, not audit noise
        self.assertEqual(chain.verify(row), (True, []))
        first = chain.entries(row)[0]
        with self.assertRaises(ValueError):
            first.save()
        with self.assertRaises(ValueError):
            first.delete()
        with self.assertRaises(ValueError):
            models.MaintenanceEvidence.objects.filter(record=row).update(summary="x")
        with self.assertRaises(ValueError):
            models.MaintenanceEvidence.objects.filter(record=row).delete()
        from django.db import connection

        with connection.cursor() as cursor:                                  # tampering below the ORM is detected
            cursor.execute("UPDATE core_maintenanceevidence SET payload = %s WHERE id = %s", ['{"device": "R9"}', first.pk])
        intact, problems = chain.verify(row)
        self.assertFalse(intact)
        self.assertIn("payload does not match", problems[0])
        self.assertEqual(models.AuditEvent.objects.filter(object_id=row.record_id).count(), len(kinds))


class CommandTests(ServiceFixture):
    """``maintenance_tick`` (the timer's command) and ``nmas_maintenance`` (the operator's), on the same fakes."""

    def call(self, *args):
        from io import StringIO

        from django.core.management import call_command

        out = StringIO()
        call_command(*args, stdout=out)
        return out.getvalue()

    def test_an_idle_worker_pass_reads_one_table_and_builds_no_runtime(self):
        def refuse():
            raise AssertionError("the runtime was built although nothing was due")

        with mock.patch.object(service, "production_runtime", refuse):
            self.assertIn("MAINTENANCE_TICK: 0 item(s)", self.call("maintenance_tick"))
            self.assertIn("recover=0, queued=0, deadline=0", self.call("maintenance_tick", "--dry-run"))

    def test_the_worker_command_runs_a_due_deadline_and_fails_visibly_on_escalation(self):
        from django.core.management.base import CommandError

        self.enter(self.approved())
        self.healthy = False
        with mock.patch.object(service, "production_runtime", lambda: self.runtime), \
                mock.patch("django.utils.timezone.now", lambda: T0 + timedelta(days=7, minutes=5)):
            self.assertIn("deadline=1", self.call("maintenance_tick", "--dry-run"))      # the dry run claims and contacts nothing
            self.assertEqual(self.log[-1][0], "save")
            with self.assertRaises(CommandError):
                self.call("maintenance_tick")
        row = models.MaintenanceRecord.objects.get()
        self.assertEqual((row.state, row.restore_trigger), (lifecycle.RESTORE_FAILED, lifecycle.DEADLINE))

    def test_the_operator_command_verifies_the_evidence_and_requires_the_plan_hash(self):
        from django.core.management.base import CommandError

        row = self.approved()
        self.assertIn("evidence chain INTACT (4 entries)", self.call("nmas_maintenance", "verify", "--id", row.record_id))
        self.assertIn(row.record_id, self.call("nmas_maintenance", "list"))
        with self.assertRaises(CommandError):
            self.call("nmas_maintenance", "enter", "--id", row.record_id, "--actor", "x", "--confirm", "MNT-000999")
        with self.assertRaises(CommandError):                                 # argparse: --plan-hash is required
            self.call("nmas_maintenance", "approve", "--id", row.record_id, "--actor", "x")
        self.assertEqual(self.log, [])


class ProductionWiringTests(SimpleTestCase):
    """The production runtime built from the REAL tracked cabling and inventory (NetBox's managed scope stubbed): no device,
    no host and no NetBox is contacted; nothing is connected."""

    def test_the_tracked_lab_gives_the_expected_roles_scope_and_protected_interfaces(self):
        from core.services.config_workbench import scope as workbench_scope

        managed = ["R1", "R2", "R3", "R4", "S1", "S2", "S3", "S4", "mgmt_swt"]
        with mock.patch.object(workbench_scope, "NETBOX_MANAGED", lambda: {"status": "available", "data": managed}):
            runtime = service.production_runtime()
            self.assertEqual(runtime.scope(), set(managed))                   # R5 is not writable
        topo = runtime.sources.topology
        self.assertEqual((topo.management, topo.service.gateway, topo.service.name), (("mgmt_swt",), "R5", "WebServer"))
        self.assertEqual({name: host.attached_to for name, host in topo.hosts.items()}, {"H1": "S1", "H2": "S1", "H3": "S2", "H4": "S2"})
        self.assertEqual((topo.single_homed("S1"), topo.single_homed("S2"), topo.single_homed("R1")), (("H1", "H2"), ("H3", "H4"), ()))
        self.assertEqual(topo.hosts["H4"].families, (6,))
        self.assertEqual(topo.cut_off_from_management("R1"), ())
        self.assertEqual(set(topo.cut_off_from_management("mgmt_swt")), set(managed) - {"mgmt_swt"})
        self.assertIn("Ethernet3", runtime.management_interfaces["R1"])       # R1 eth3 is cabled to the management switch
        self.assertIn("Vlan200", runtime.management_interfaces["S1"])
        self.assertIn("eth3", runtime.management_interfaces["R3"])
        self.assertEqual(runtime.definition, migration.PRODUCTION)
        self.assertTrue(runtime.gated)                                        # the managed network always requires READY mechanisms
