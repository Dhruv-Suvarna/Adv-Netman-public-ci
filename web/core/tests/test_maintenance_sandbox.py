"""The production-shaped Maintenance Mode sandbox: the REAL service, plan, drain operations, route-shield checks, executor,
compensation, collector and worker against a simulated lab in its post-migration state (IS-IS access, OSPFv3 core).

    S1 / S2 / R1 / R2   cEOS-like: each device's configuration is a set of statement paths, and its IPv6 routing table is
                        derived from it the way the lab forwards: connected < static (1) < IS-IS (115); the aggregate on a
                        switch follows the cheaper IS-IS path (its uplink metric against VLAN 99 plus the other switch's
                        uplink); a boundary router's client prefixes come from its switch by IS-IS.
    R3 / R4             the REAL ``KernelCoverExecutor`` over an emulated kernel: the client /64s are installed toward the
                        boundary routers whose OSPFv3 external metric is the lowest (both, unless one carries ``set
                        metric``), next to any kernel route installed by hand (a maintenance installs none).
    observation         the collector reads health evidence derived from the same state, and the hosts' counters.

Nothing here contacts a device.  Each test is one of the scenarios that must pass before any live pilot."""

from __future__ import annotations

import ipaddress
import json
import subprocess
from datetime import timedelta
from unittest import mock

from django.test import TestCase

from core import models
from core.services.execution.executors.base import APPLY, REFUSE, SKIP_SATISFIED, ApplyOutcome, Assessment, CompensationOutcome
from core.services.health.evidence import DeviceEvidence, FactGroup
from core.services.maintenance_mode import collector, drain, executor, lifecycle, model, plan, protection, readiness, service
from core.services.maintenance_mode import evidence as chain
from core.services.route_shield import core_cover, lab, lifecycle as shield_lifecycle, migration
from core.services.route_shield.core_cover import KernelCoverExecutor
from core.services.route_shield.migration import ADD, Operation
from core.tests import test_maintenance_live as live

D = migration.PRODUCTION
R1LL, R2LL = core_cover.R1_LINK_LOCAL, core_cover.R2_LINK_LOCAL
MGMT = {"S1": "interface Vlan200 > ip address 192.168.200.11/24", "S2": "interface Vlan200 > ip address 192.168.200.12/24",
        "R1": "interface Vlan200 > ip address 192.168.200.1/24", "R2": "interface Vlan200 > ip address 192.168.200.2/24"}
CONNECTED = {
    "S1": {"2001:db8:110:1::/64": "Ethernet1", "2001:db8:110:3::/64": "Vlan99", **{p: f"Vlan{v}" for p, v in zip(lab.CLIENTS, (10, 20, 30))}},
    "S2": {"2001:db8:110:2::/64": "Ethernet1", "2001:db8:110:3::/64": "Vlan99", **{p: f"Vlan{v}" for p, v in zip(lab.CLIENTS, (10, 20, 30))}},
    "R1": {"2001:db8:110:1::/64": "Ethernet2", "2001:db8:100:103::/64": "Vlan103", "2001:db8:100:104::/64": "Vlan104"},
    "R2": {"2001:db8:110:2::/64": "Ethernet2", "2001:db8:100:101::/64": "Vlan101", "2001:db8:100:102::/64": "Vlan102"},
}
SWITCH_OF, ROUTER_OF = {"R1": "S1", "R2": "S2"}, {"S1": "R1", "S2": "R2"}


def _switch(name: str) -> set:
    return {"router isis NMAS > net 49.0001", "interface Ethernet1 > isis enable NMAS", "interface Ethernet1 > isis metric 10",
            "interface Vlan99 > isis enable NMAS", "interface Vlan99 > isis metric 10", "vlan 200", MGMT[name],
            "ipv6 route ::/0 3fff:172:20:20::1"}


def _router(name: str, anchor: str) -> set:
    return {"router isis NMAS > net 49.0002", "interface Ethernet2 > isis enable NMAS", "interface Ethernet2 > isis metric 10",
            f"ipv6 route {lab.AGGREGATE} {anchor}", "route-map ISIS6-TO-OSPF3 permit 10 > match ipv6 address prefix-list CLIENT-V6",
            "ipv6 router ospf 10 > redistribute isis level-2 route-map ISIS6-TO-OSPF3", MGMT[name], "ipv6 route ::/0 3fff:172:20:20::1"}


BASE = {"S1": _switch("S1"), "S2": _switch("S2"), "R1": _router("R1", "2001:db8:100:103::2"), "R2": _router("R2", "2001:db8:100:101::2")}


def _render(paths) -> str:
    tree: dict = {}
    for path in sorted(paths):
        node = tree
        for part in path.split(" > "):
            node = node.setdefault(part, {})
    lines = []

    def walk(node, depth):
        for text, child in node.items():
            lines.append("   " * depth + text)
            walk(child, depth + 1)
    walk(tree, 0)
    return "\n".join(lines)


def _group(data):
    return FactGroup(data=data, source="LIVE", observed_at=live.T0)


class Lab:
    """The simulated lab.  ``sent`` records every mutating command, in order; ``fail`` makes one operation fail."""

    def __init__(self):
        self.paths = {name: set(lines) for name, lines in BASE.items()}
        self.startup = {name: set(lines) for name, lines in BASE.items()}
        self.covers = {core: {} for core in D.cores}         # prefix -> hops (kernel routes NMAS installed)
        self.boot = {core: f"hostname {core}\nrouter ospf6\n" for core in D.cores}
        self.sent: list[tuple[str, str]] = []
        self.fail: tuple[str, str] | None = None             # (device, substring of the operation's last line)
        self.adjacency_down: set[str] = set()                # boundary routers whose access IS-IS adjacency is down

    # -- derived routing ----------------------------------------------------------------------------------------------
    def metric(self, device: str, interface: str) -> int:
        found = [int(p.rsplit(" ", 1)[1]) for p in self.paths[device] if p.startswith(f"interface {interface} > isis metric ")]
        return min(found) if found else 10

    def access_up(self, router: str) -> bool:
        return router not in self.adjacency_down and "interface Ethernet1 > isis enable NMAS" in self.paths[SWITCH_OF[router]]

    def external_metric(self, router: str) -> int:
        found = [int(p.rsplit(" ", 1)[1]) for p in self.paths[router] if p.startswith("route-map ISIS6-TO-OSPF3 permit 10 > set metric ")]
        return found[0] if found else 20

    def north_drained(self, switch: str) -> bool:
        return self.isis_routes(switch).get(lab.AGGREGATE, ("", ""))[0] != "Ethernet1"

    def south_drained(self, router: str) -> bool:
        return router not in self.core_routers()

    def core_routers(self) -> tuple:
        alive = [r for r in ("R1", "R2") if self.access_up(r)]
        best = min((self.external_metric(r) for r in alive), default=None)
        return tuple(r for r in alive if self.external_metric(r) == best)

    def isis_routes(self, name: str) -> dict:
        """prefix -> (interface, next hop) learned by IS-IS."""
        if name.startswith("S"):
            other, router = ("S2" if name == "S1" else "S1"), ROUTER_OF[name]
            options = []
            if self.access_up(router):
                options.append((self.metric(name, "Ethernet1"), "Ethernet1", "fe80::1"))
            if self.access_up(ROUTER_OF[other]):
                options.append((self.metric(name, "Vlan99") + self.metric(other, "Ethernet1"), "Vlan99", "fe80::2"))
            if not options:
                return {}
            best = min(options)
            return {lab.AGGREGATE: best[1:]}
        return {p: ("Ethernet2", "fe80::3") for p in lab.CLIENTS} if self.access_up(name) else {}

    def routes(self, name: str) -> dict:
        """prefix -> (type, interface, next hop): the installed route only."""
        best = {prefix: (0, "connected", interface, "") for prefix, interface in CONNECTED[name].items()}
        for prefix, (interface, hop) in self.isis_routes(name).items():
            if prefix not in best:
                best[prefix] = (115, "isisL2", interface, hop)
        for line in self.paths[name]:
            if not line.startswith("ipv6 route "):
                continue
            parts = line.split()
            prefix, hop, distance = str(ipaddress.ip_network(parts[2])), parts[3], int(parts[4]) if len(parts) > 4 else 1
            interface = next((i for net, i in CONNECTED[name].items() if ipaddress.ip_address(hop) in ipaddress.ip_network(net)),
                             "Management0" if hop.startswith("3fff") else "Vlan103")
            if prefix not in best or distance < best[prefix][0]:
                best[prefix] = (distance, "static", interface, hop)
        return {p: row[1:] for p, row in best.items()}

    def client_hops(self, core: str) -> list:
        pair = dict(zip(("R1", "R2"), D.covers_of(core)[0].next_hops))
        return [pair[r] for r in self.core_routers()]

    # -- health evidence (what read_device would return) -------------------------------------------------------------
    def health(self, device: dict) -> DeviceEvidence:
        name = device["name"]
        if name in D.cores:
            hops = D.covers_of(name)[0].next_hops
            ospf = [{"family": "OSPFV3", "neighbor_id": f"192.168.255.{i}", "interface": interface,
                     "state": "INIT" if f"R{i}" in self.adjacency_down else "FULL"} for i, (_a, interface) in enumerate(hops, 1)]
            return DeviceEvidence(device=name, platform="linux", live_attempted=True, groups={
                "interfaces": _group({interface: {"admin": "UP", "oper": "UP"} for _a, interface in hops}), "ospf": _group(ospf)})
        routes = [{"prefix": p, "type": kind, "interfaces": [i] if i else [], "next_hops": [h] if h else []} for p, (kind, i, h) in sorted(self.routes(name).items())]
        index = {"R1": 1, "R2": 2, "S1": 11, "S2": 12}[name]
        return DeviceEvidence(device=name, platform="ceos", live_attempted=True, groups={
            "routes": _group(routes), "addresses": _group({"Loopback0": [f"192.168.255.{index}/32"]}),
            "interfaces": _group({i: {"admin": "UP", "oper": "UP"} for i in ("Ethernet1", "Ethernet2", "Vlan99")}), "isis": _group([])})

    def observed(self) -> dict:
        """The collector's view: the production-shaped evidence of ``test_maintenance_live`` with this lab's forwarding."""
        found = live.network()
        for switch in ("S1", "S2"):
            if self.north_drained(switch):
                found[switch].groups["routes"].data[0]["interfaces"] = ["Vlan99"]
            found[switch].groups["config_paths"] = _group(sorted(self.paths[switch]))
        for router in ("R1", "R2"):
            found[router].groups["config_paths"] = _group(sorted(self.paths[router]))
            if router in self.adjacency_down:
                found[router].groups["isis"] = _group([])
        for core, (first, second) in (("R3", ("Vlan101", "Vlan103")), ("R4", ("Vlan102", "Vlan104"))):
            down = [interface for router, interface in (("R1", first), ("R2", second)) if router in self.core_routers()]
            for row in found[core].groups["routes"].data:
                if row["prefix"] in lab.CLIENTS:
                    row["interfaces"] = down
        return found

    def vlan200(self) -> dict:
        return {name: sorted(p for p in paths if "Vlan200" in p or p == "vlan 200") for name, paths in self.paths.items()}


class SimCeos:
    """The executor contract and the read-back commands over one simulated cEOS access device."""

    def __init__(self, net: Lab, device: dict):
        self.net, self.name = net, device["name"]

    def connect(self):
        return None

    def close(self):
        return None

    def config_state_digest(self):
        return "|".join(sorted(self.net.paths[self.name]))

    def startup_state_digest(self):
        return "|".join(sorted(self.net.startup[self.name]))

    def save_startup(self):
        self.net.sent.append((self.name, "copy running-config startup-config"))
        self.net.startup[self.name] = set(self.net.paths[self.name])
        return ApplyOutcome(True, lines_sent=1)

    def neighbour_answers(self, address, interface=""):
        return True

    def show(self, command):
        paths = self.net.paths[self.name]
        if command == "show running-config":
            return _render(paths)
        if command == "show isis neighbors | json":
            interface = "Ethernet2" if self.name.startswith("R") else "Ethernet1"
            up = [interface] if (self.name.startswith("R") and self.net.access_up(self.name)) or (self.name.startswith("S") and self.net.access_up(ROUTER_OF[self.name])) else []
            rows = {f"sys{n}": {"adjacencies": [{"interfaceName": i, "state": "up", "level": "level-2", "hostname": "x"}]} for n, i in enumerate(up)}
            return json.dumps({"vrfs": {"default": {"isisInstances": {"NMAS": {"neighbors": rows}}}}})
        target = command.removeprefix("show ipv6 route ").removesuffix(" | json")
        routes = self.net.routes(self.name)
        if "/" in target:
            key = str(ipaddress.ip_network(target))
            found = {key: routes[key]} if key in routes else {}
        else:
            address = ipaddress.ip_address(target)
            match = max((p for p in routes if address in ipaddress.ip_network(p)), key=lambda p: ipaddress.ip_network(p).prefixlen, default=None)
            found = {match: routes[match]} if match else {}
        return json.dumps({"routes": {p: {"routeType": kind, "hardwareProgrammed": True, "kernelProgrammed": True,
                                          "vias": [{"interface": i, **({"nexthopAddr": h} if h else {})}]} for p, (kind, i, h) in found.items()}})

    @staticmethod
    def _wanted(spec):
        return list(spec.removal["absent_paths"]) if spec.origin == "REMOVAL" else list(spec.expected["present_paths"])

    def assess(self, spec):
        wanted, paths = self._wanted(spec), self.net.paths[self.name]
        found = [p for p in wanted if p in paths]
        facts = {"kind": "config_block", "config_digest": self.config_state_digest()}
        if spec.origin != "REMOVAL":                                         # an ADD of a value replaces the old value of the same key
            stale = [p for p in paths for w in wanted if p != w and p.rsplit(" ", 1)[0] == w.rsplit(" ", 1)[0] and " metric " in w]
            facts["replaced"] = stale
        if found and len(found) != len(wanted):
            return Assessment(REFUSE, False, facts, "REMOVAL_TARGET_DRIFTED")
        if spec.origin == "REMOVAL":
            return Assessment(APPLY if found else SKIP_SATISFIED, True, facts)
        return Assessment(SKIP_SATISFIED if found else APPLY, True, facts)

    def _set(self, wanted, *, add: bool):
        paths = self.net.paths[self.name]
        for path in wanted:
            key = path.rsplit(" ", 1)[0]
            if add and " metric " in path:                                   # a metric is one value per interface / route map
                for old in [p for p in paths if p.rsplit(" ", 1)[0] == key]:
                    paths.discard(old)
            (paths.add if add else paths.discard)(path)

    def apply(self, spec, assessment):
        if self.net.fail and self.net.fail[0] == self.name and self.net.fail[1] in spec.lines[-1]:
            return ApplyOutcome(False, "COMMAND_REJECTED")
        self.net.sent.append((self.name, " / ".join(line.strip() for line in spec.lines)))
        self._set(self._wanted(spec), add=spec.origin != "REMOVAL")
        return ApplyOutcome(True, lines_sent=len(spec.lines))

    def compensate(self, spec, assessment):
        self.net.sent.append((self.name, f"undo {spec.cfg_id}"))
        paths = self.net.paths[self.name]
        if spec.origin == "REMOVAL":
            paths |= set(self._wanted(spec))
        else:
            paths -= set(self._wanted(spec))
            paths |= set(assessment.previous_state.get("replaced") or ())
        return CompensationOutcome("COMPENSATED")


def kernel_runner(net: Lab):
    """``docker exec <core> ip|vtysh ...`` over the emulated kernel of R3 / R4: client routes follow the boundary routers'
    OSPFv3 external metric, covers are what NMAS installed."""

    def table(core):
        rows = {p: {"protocol": "ospf", "hops": net.client_hops(core)} for p in lab.CLIENTS}
        rows.update({p: {"protocol": "boot", "hops": hops} for p, hops in net.covers[core].items()})
        rows["default"] = {"protocol": "boot", "hops": [("3fff:172:20:20::1", "eth0")]}
        return rows

    def row(prefix, entry):
        hops = entry["hops"]
        body = {"gateway": hops[0][0], "dev": hops[0][1]} if len(hops) == 1 else {"nexthops": [{"gateway": a, "dev": d} for a, d in hops]}
        return {"dst": prefix, "protocol": entry["protocol"], **body}

    def run(container, argv, timeout):
        rows = table(container)
        ok = lambda out="": subprocess.CompletedProcess(argv, 0, out, "")  # noqa: E731
        if argv == ["cat", core_cover.PERSISTENT_CONFIG]:
            return ok(net.boot[container])
        if argv == ["hostname"]:
            return ok(container + "\n")
        if argv[:2] == ["vtysh", "-c"]:
            if argv[2] == "show version":
                return ok("FRRouting 8.4.4 on Linux\n")
            if argv[2] == "show running-config":
                return ok("router ospf6\n ospf6 router-id 192.168.255.3\n")
            if argv[2] == "show ipv6 ospf6 neighbor detail json":
                hops = D.covers_of(container)[0].next_hops
                return ok(json.dumps({f"192.168.255.{i}%{dev}": {"interface": dev, "linkLocalAddress": address,
                                                                "neighborState": "Init" if f"R{i}" in net.adjacency_down else "Full"}
                                      for i, (address, dev) in enumerate(hops, 1)}))
            prefix = argv[2].split()[3]
            return ok(json.dumps({prefix: [{"installed": prefix in rows, "internalNextHopActiveNum": len(rows.get(prefix, {}).get("hops", ())), "uptime": "00:10:00"}]}))
        if argv[:4] == ["ip", "-j", "-6", "neigh"]:
            return ok(json.dumps([{"dst": argv[5], "dev": argv[7], "lladdr": "00:1c:73:00:00:01", "state": ["REACHABLE"]}]))
        if argv[:5] == ["ip", "-j", "-6", "route", "get"]:
            address = ipaddress.ip_address(argv[5])
            match = max((p for p in rows if p != "default" and address in ipaddress.ip_network(p)), key=lambda p: ipaddress.ip_network(p).prefixlen, default="default")
            return ok(json.dumps([{"dst": str(address), "gateway": rows[match]["hops"][0][0], "dev": rows[match]["hops"][0][1]}]))
        if argv[:5] == ["ip", "-j", "-6", "route", "show"]:
            rest = argv[5:]
            if rest == ["table", "all"]:
                return ok(json.dumps([row(p, e) for p, e in rows.items()]))
            if rest[0] == "root":
                inside = ipaddress.ip_network(rest[1])
                return ok(json.dumps([row(p, e) for p, e in rows.items() if p != "default" and ipaddress.ip_network(p).subnet_of(inside)]))
            return ok(json.dumps([row(p, e) for p, e in rows.items() if p == rest[0]]))
        if argv[:4] == ["ip", "-6", "route", "add"]:
            net.sent.append((container, " ".join(argv)))
            if argv[4] in net.covers[container]:
                return subprocess.CompletedProcess(argv, 2, "", "RTNETLINK answers: File exists")
            net.covers[container][argv[4]] = [(argv[i + 2], argv[i + 4]) for i, word in enumerate(argv) if word == "nexthop"]
            return ok()
        if argv[:4] == ["ip", "-6", "route", "del"]:
            net.sent.append((container, " ".join(argv)))
            if argv[4] not in net.covers[container]:
                return subprocess.CompletedProcess(argv, 2, "", "RTNETLINK answers: No such process")
            del net.covers[container][argv[4]]
            return ok()
        raise AssertionError(f"unexpected command {argv}")
    return run


class Hosts(live.Hosts):
    """The client hosts: an active flow's unicast counter advances on every read, so every observation sees it."""

    def counters(self, host):
        if host.name in self.broken:
            raise OSError("unreadable")
        self.reads[host.name] = self.reads.get(host.name, 0) + 1
        return {(v, d): 1000 + (25 * self.reads[host.name] if (host.name, v, d) in self.active else 0) for v in (4, 6) for d in model.DIRECTIONS}


class Probes:
    """The production probe matrix: ``lose_after`` (an operation key) makes the probes report a loss from then on."""

    def __init__(self):
        self.count, self.started, self.stopped = 0, 0, 0

    def start(self):
        self.started += 1

    def stop(self):
        self.stopped += 1

    def healthy(self):
        return True, {"lost": self.count}

    def lost(self):
        return self.count

    def advancing(self):
        return True, {}


DEVICES = {name: {"name": name, "platform": "linux" if name in D.cores else "ceos", "container": name, "address": ""} for name in D.devices}
READY = {"ISIS_METRIC_STEER": model.READY, "OSPFV3_EXTERNAL_METRIC_STEER": model.READY}      # the sandbox: mechanism readiness not required
SCOPE = {"R1", "R2", "R3", "R4", "S1", "S2", "S3", "S4", "mgmt_swt"}


class SandboxTests(TestCase):
    def setUp(self):
        self.net, self.probes, self.clock, self.active, self.events = Lab(), Probes(), [live.T0], set(), []
        self.lose_after = ""
        self.read_fails: set[str] = set()
        topo = live.topo()
        for name in topo.devices:
            topo.devices[name]["platform"] = "linux" if name in ("R3", "R4") else "ceos"
        inventory = {"network_devices": {name: {"monitoring": {"source_interface": "Vlan200"}} for name in topo.devices}}

        def read(device):
            if device["name"] in self.read_fails:
                return DeviceEvidence(device=device["name"], platform="ceos", live_attempted=True, live_error="TIMEOUT")
            return self.net.observed()[device["name"]]

        self.sources = collector.Sources(topo, read, hosts=Hosts(), shield_states=READY, dhcp_servers=lambda: {"secondary_device": "R2"},
                                         dhcp_state=lambda: {"nmas": {"ipv4": "active", "ipv6": "active"}}, window_seconds=20, sleep=lambda _s: None, now=self.now)
        self.runtime = service.Runtime(self.sources, self.environment, lambda env: env.probes.start(), D, gated=False, probe_warmup=0, sleep=lambda _s: None,
                                       writable=lambda: SCOPE, management_interfaces=service.management_interfaces(inventory, topo))
        self.baseline = {"paths": {n: set(p) for n, p in self.net.paths.items()}, "startup": {n: set(p) for n, p in self.net.startup.items()}}

    def now(self):
        return self.clock[0]

    def observer(self, event, key):
        self.events.append((event, key))
        if event == "after" and key == self.lose_after:
            self.probes.count += 2

    def environment(self):
        runner = kernel_runner(self.net)
        return shield_lifecycle.Environment(
            devices=DEVICES, executor_factory=lambda device: KernelCoverExecutor(device, runner=runner) if device["platform"] == "linux" else SimCeos(self.net, device),
            read=self.net.health, probes=self.probes, host_gate=lambda: (True, {"load1": 2.0}), observer=self.observer,
            sleep=lambda seconds: None, poll_seconds=0, clock=lambda ticks=iter(range(0, 10**9, 25)): next(ticks))

    def traffic(self, *flows):
        self.active = set(flows)
        self.sources.hosts = Hosts(active=self.active)

    def requested(self, device="R1"):
        return service.request(device, "operator", "line card replacement", timedelta(hours=6), now=self.now(), runtime=self.runtime)

    def ready(self, device="R1"):
        row = service.evaluate(self.requested(device).pk, "operator", now=self.now(), runtime=self.runtime)
        return row

    def approved(self, device="R1"):
        row = self.ready(device)
        self.assertEqual(row.state, lifecycle.PLANNED, row.snapshot.get("findings"))
        return service.approve(row.pk, "lead", now=self.now(), plan_hash=row.plan_hash)

    def entered(self, device="R1"):
        row = self.approved(device)
        return service.enter(row.pk, "operator", now=self.now, runtime=self.runtime)

    def writes(self):
        return [entry for entry in self.net.sent if entry[1] != "copy running-config startup-config"]

    def assert_baseline(self):
        self.assertEqual(self.net.paths, self.baseline["paths"])
        self.assertEqual(self.net.startup, self.baseline["startup"])
        self.assertEqual(self.net.covers, {core: {} for core in D.cores})

    # 1 ---------------------------------------------------------------------------------------------------------------
    def test_01_ready_with_existing_redundancy(self):
        self.traffic(("H1", 6, model.NORTHBOUND), ("H1", 6, model.SOUTHBOUND), ("H3", 6, model.SOUTHBOUND))
        row = self.ready("R1")
        self.assertEqual(row.state, lifecycle.PLANNED, row.snapshot.get("findings"))
        document = row.snapshot["plan"]
        cells = document["readiness"]["cells"]
        self.assertEqual((cells["IPV6/NORTHBOUND"]["verdict"], cells["IPV6/SOUTHBOUND"]["verdict"]), (readiness.DRAINABLE, readiness.DRAINABLE))
        self.assertEqual((cells["IPV4/NORTHBOUND"]["verdict"], cells["IPV4/SOUTHBOUND"]["verdict"]), (readiness.CLEAR, readiness.CLEAR))
        stages = [op["stage"] for op in document["drain"]["operations"]]
        self.assertEqual(stages, [drain.NORTH] * 3 + [drain.SOUTH])
        self.assertEqual(document["baseline"]["prestate"]["uplink_metric"], 10)
        self.assertEqual(self.writes(), [])                                   # planning read, never wrote

    # 2 ---------------------------------------------------------------------------------------------------------------
    def test_02_active_traffic_without_a_proven_lossless_drain_blocks(self):
        self.traffic(("H1", 6, model.NORTHBOUND))
        row = self.ready("S1")                                                # H1 is single-homed to S1: nothing can move it
        self.assertEqual(row.state, lifecycle.BLOCKED)
        self.assertIn((readiness.NO_LOSSLESS_DRAIN, "IPV6", "NORTHBOUND"), {(f["code"], f["family"], f["direction"]) for f in row.snapshot["findings"]})
        self.traffic(("H1", 4, model.NORTHBOUND))                             # IPv4 / RIP has no proven drain on R1
        row = service.evaluate(self.requested("R1").pk, now=self.now(), runtime=self.runtime)
        self.assertEqual(row.state, lifecycle.BLOCKED)
        self.assertIn(readiness.MECHANISM_NOT_READY, [f["code"] for f in row.snapshot["findings"]])
        self.assertEqual((self.writes(), row.plan_hash), ([], ""))

    # 3 ---------------------------------------------------------------------------------------------------------------
    def test_03_quiesced_traffic_is_allowed_without_redundancy(self):
        row = self.entered("S1")                                              # H1 and H2 are quiet: S1 may go without any drain
        self.assertEqual((row.state, row.snapshot["steps"], self.writes()), (lifecycle.ACTIVE, [], []))
        row = service.leave(row.pk, "operator", now=self.now, runtime=self.runtime)
        self.assertEqual((row.state, self.writes()), (lifecycle.RESTORED, []))

    # 4 and 5 ---------------------------------------------------------------------------------------------------------
    def test_04_05_a_successful_drain_moves_every_planned_direction_off_the_router(self):
        self.traffic(("H1", 6, model.NORTHBOUND), ("H1", 6, model.SOUTHBOUND))
        row = self.entered("R1")
        self.assertEqual(row.state, lifecycle.ACTIVE, row.snapshot.get("findings"))
        self.assertTrue(self.net.north_drained("S1") and self.net.south_drained("R1"))
        self.assertIn("interface Ethernet1 > isis metric 1000", self.net.paths["S1"])
        self.assertIn("route-map ISIS6-TO-OSPF3 permit 10 > set metric 10000", self.net.paths["R1"])
        self.assertFalse(any("ipv6 route 2001:db8::/33" in p or "2001:db8:8000::/33" in p for p in self.net.paths["S1"]))   # shields gone
        self.assertEqual(self.net.covers, {core: {} for core in D.cores})    # nothing was ever installed on a core
        self.assertEqual(self.net.startup["S1"], self.net.paths["S1"])        # the drained state survives a reload
        entry = row.snapshot["evidence"]["entry"]
        self.assertEqual((entry["outcome"], entry["probes"]["lost"]), (executor.SUCCEEDED, 0))
        self.assertTrue(all(proof["moved"] and proof["alternate_healthy"] for proof in entry["proofs"]))
        paths = entry["after"]["paths"]
        self.assertEqual(paths["h1-v6-north"]["path"], "S1 > S2 > R2 > R3|R4 > R5")       # traffic moved: proven, not assumed
        self.assertFalse(paths["h1-v6-south"]["on_device"])
        self.assertEqual([cmd for device, cmd in self.net.sent if device in D.cores], [])      # the cores were read, never written

    # 6 ---------------------------------------------------------------------------------------------------------------
    def test_06_a_successful_restore_returns_the_exact_pre_maintenance_state(self):
        self.traffic(("H1", 6, model.NORTHBOUND), ("H1", 6, model.SOUTHBOUND))
        row = self.entered("R1")
        row = service.leave(row.pk, "operator", now=self.now, runtime=self.runtime)
        self.assertEqual((row.state, row.escalated), (lifecycle.RESTORED, False), row.snapshot.get("findings"))
        self.assert_baseline()
        self.assertEqual(row.snapshot["evidence"]["restore_verification"]["findings"], [])
        south = next(n for n, (d, c) in enumerate(self.net.sent) if d == "R1" and "no set metric" in c)
        north = next(n for n, (d, c) in enumerate(self.net.sent) if d == "S1" and "isis metric 10" in c and "1000" not in c)
        self.assertLess(south, north)                                         # offered southbound traffic first, once verified healthy

    # 7 ---------------------------------------------------------------------------------------------------------------
    def test_07_a_failure_during_entry_is_compensated_and_verified(self):
        self.traffic(("H1", 6, model.NORTHBOUND), ("H1", 6, model.SOUTHBOUND))
        row = self.approved("R1")
        self.net.fail = ("R1", "set metric 10000")                           # northbound already drained
        with self.assertRaises(model.MaintenanceError) as caught:
            service.enter(row.pk, "operator", now=self.now, runtime=self.runtime)
        self.assertEqual(caught.exception.code, "ENTRY_ABORTED")
        row.refresh_from_db()
        self.assertEqual((row.state, row.escalated), (lifecycle.ABORTED_RESTORED, False), row.snapshot.get("findings"))
        self.assertEqual(row.snapshot["evidence"]["entry"]["outcome"], executor.ROLLED_BACK)
        self.assert_baseline()

    def test_07b_a_lost_production_probe_aborts_and_compensates(self):
        self.traffic(("H1", 6, model.NORTHBOUND), ("H1", 6, model.SOUTHBOUND))
        row = self.approved("R1")
        self.lose_after = "S1-uplink-metric-drain"
        with self.assertRaises(model.MaintenanceError):
            service.enter(row.pk, "operator", now=self.now, runtime=self.runtime)
        row.refresh_from_db()
        self.assertEqual(row.snapshot["evidence"]["entry"]["failure"]["code"], "PRODUCTION_PACKET_LOSS")
        self.assertEqual(self.net.paths, self.baseline["paths"])

    # 8 ---------------------------------------------------------------------------------------------------------------
    def test_08_the_deadline_triggers_the_verified_restore(self):
        self.traffic(("H1", 6, model.NORTHBOUND))
        row = self.entered("R1")
        self.clock[0] = live.T0 + timedelta(hours=7)                          # past the requested six hours: nothing happens
        self.assertEqual(service.tick(now=self.now, runtime_factory=lambda: self.runtime), [])
        self.assertTrue(self.net.north_drained("S1"))
        self.clock[0] = live.T0 + timedelta(days=7, minutes=1)
        (result,) = service.tick(now=self.now, runtime_factory=lambda: self.runtime)
        row.refresh_from_db()
        self.assertEqual((result["item"], row.state, row.restore_trigger), (service.DEADLINE, lifecycle.RESTORED, lifecycle.DEADLINE))
        self.assert_baseline()

    # 9 ---------------------------------------------------------------------------------------------------------------
    def test_09_a_failed_restore_escalates_keeps_the_drained_state_and_can_be_retried(self):
        self.traffic(("H1", 6, model.NORTHBOUND), ("H1", 6, model.SOUTHBOUND))
        row = self.entered("R1")
        drained = {name: set(paths) for name, paths in self.net.paths.items()}
        self.net.adjacency_down.add("R1")                                     # R1 came back from its work without its access adjacency
        sent = len(self.net.sent)
        row = service.leave(row.pk, "operator", now=self.now, runtime=self.runtime)
        self.assertEqual((row.state, row.escalated), (lifecycle.RESTORE_FAILED, True))
        self.assertEqual((self.net.paths, len(self.net.sent)), (drained, sent))      # nothing written: R1 is never offered traffic
        self.assertIn("S1: interface Ethernet1 > isis metric 1000", row.snapshot["maintenance_only_state"])
        self.assertIn("RESTORE_FAILED_ESCALATED", service.conflict("R1"))
        other = service.request("R2", "operator", "unrelated", timedelta(hours=1), now=self.now(), runtime=self.runtime)
        self.assertIn("R1", service.store.prior_unresolved("R2", intersects=("R1", "S2")))    # R2's traffic would lean on R1
        self.assertEqual(service.store.prior_unresolved("S4", intersects=("S3",)), ())       # unrelated infrastructure is not frozen
        service.cancel(other.pk, "operator", now=self.now())
        self.net.adjacency_down.clear()                                       # repaired; an operator runs the restore again
        row = service.leave(row.pk, "operator", now=self.now, runtime=self.runtime)
        self.assertEqual((row.state, row.escalated), (lifecycle.RESTORED, True))
        self.assert_baseline()

    # 10 --------------------------------------------------------------------------------------------------------------
    def test_10_stale_facts_block_the_entry(self):
        self.traffic(("H1", 6, model.NORTHBOUND))
        row = self.approved("R1")
        self.net.paths["S2"].add("interface Ethernet7 > shutdown")            # an out-of-band change on the path the traffic would take
        with self.assertRaises(model.MaintenanceError):
            service.enter(row.pk, "operator", now=self.now, runtime=self.runtime)
        row.refresh_from_db()
        self.assertEqual((row.state, row.plan_status), (lifecycle.APPROVED, plan.STALE))
        self.assertIn(plan.PLAN_STALE, [f["code"] for f in row.snapshot["findings"]])
        self.net.paths["S2"].discard("interface Ethernet7 > shutdown")
        self.assertEqual(self.writes(), [])
        self.read_fails.add("R3")                                             # unreadable evidence is never "safe"
        self.traffic(("H1", 6, model.NORTHBOUND), ("H3", 6, model.NORTHBOUND))      # H3's path cannot be followed past R3
        row = service.evaluate(row.pk, now=self.now(), runtime=self.runtime)
        self.assertEqual(row.state, lifecycle.BLOCKED)
        self.assertIn(readiness.TRAFFIC_UNKNOWN, [f["code"] for f in row.snapshot["findings"]])
        self.read_fails.clear()
        row = service.evaluate(row.pk, now=self.now(), runtime=self.runtime)
        row = service.approve(row.pk, "lead", now=self.now(), plan_hash=row.plan_hash)
        self.clock[0] = self.now() + service.PLAN_VALIDITY + timedelta(minutes=1)
        with self.assertRaises(model.MaintenanceError):
            service.enter(row.pk, "operator", now=self.now, runtime=self.runtime)
        row.refresh_from_db()
        self.assertIn(plan.PLAN_EXPIRED, [f["code"] for f in row.snapshot["findings"]])
        self.assertEqual(self.writes(), [])

    # 11 --------------------------------------------------------------------------------------------------------------
    def test_11_vlan_200_is_never_altered(self):
        before = self.net.vlan200()
        self.traffic(("H1", 6, model.NORTHBOUND), ("H1", 6, model.SOUTHBOUND))
        row = self.entered("R1")
        service.leave(row.pk, "operator", now=self.now, runtime=self.runtime)
        self.assertEqual(self.net.vlan200(), before)
        self.assertFalse([cmd for _device, cmd in self.net.sent if "vlan200" in cmd.lower().replace(" ", "") or " dev eth0" in cmd])
        document = models.MaintenanceRecord.objects.get(pk=row.pk).snapshot["plan"]
        self.assertFalse([line for op in (*document["drain"]["operations"], *document["restore"]["operations"]) for line in (*op["lines"], *op["inverse"])
                          if protection.line_violation(line, self.runtime.management_interfaces.get(op["device"], ()))])
        bad = Operation("S1-mgmt", drain.NORTH, "S1", drain.MAINTENANCE, ADD, ("interface Vlan200", "   shutdown"), ("interface Vlan200", "   no shutdown"))
        env = self.environment()
        env.connect(("S1",))
        run = executor.Run(env, [bad], guard=service._guard(self.runtime))
        sent = len(self.net.sent)
        self.assertEqual((run.drive(), run.failure["code"], len(self.net.sent)), (executor.ROLLED_BACK, protection.PROTECTED_SCOPE, sent))
        mgmt = OBSERVE("mgmt_swt", self.sources)                              # taking the management switch out is never ready
        self.assertTrue(any(d.kind == "MANAGEMENT" and d.stranded for d in mgmt.dependencies))

    # 12 --------------------------------------------------------------------------------------------------------------
    def test_12_r5_and_every_out_of_scope_device_is_never_targeted(self):
        with self.assertRaises(model.MaintenanceError) as caught:
            service.request("R5", "operator", "x", timedelta(hours=1), now=self.now(), runtime=self.runtime)
        self.assertEqual(caught.exception.code, protection.OUTSIDE_SCOPE)
        self.traffic(("H1", 6, model.NORTHBOUND), ("H1", 6, model.SOUTHBOUND))
        row = self.entered("R1")
        service.leave(row.pk, "operator", now=self.now, runtime=self.runtime)
        written = {device for device, _cmd in self.net.sent}
        self.assertTrue(written <= {"S1", "R1", "R3", "R4"})                   # the drain's devices only: never R5, never S2 / R2
        document = models.MaintenanceRecord.objects.get(pk=row.pk).snapshot["plan"]
        self.assertTrue({op["device"] for op in document["drain"]["operations"]} <= SCOPE - {"R5"})
        outside = Operation("R5-x", drain.NORTH, "R5", drain.MAINTENANCE, ADD, ("router bgp 65005",), ("no router bgp 65005",))
        self.assertTrue(service._guard(self.runtime)(outside).startswith(protection.OUTSIDE_SCOPE))

    # evidence of the whole cycle ---------------------------------------------------------------------------------------
    def test_the_whole_cycle_leaves_an_intact_evidence_chain(self):
        self.traffic(("H1", 6, model.NORTHBOUND), ("H1", 6, model.SOUTHBOUND))
        row = self.entered("R1")
        row = service.leave(row.pk, "operator", now=self.now, runtime=self.runtime)
        self.assertEqual(chain.verify(row), (True, []))
        run = next(entry for entry in chain.entries(row) if entry.kind == chain.ENTRY)
        self.assertEqual(run.payload["run"]["outcome"], executor.SUCCEEDED)
        self.assertEqual(len(run.payload["run"]["applied"]), 4)
        self.assertFalse(models.ExecutionDeviceLock.objects.exists())


OBSERVE = collector.observe
