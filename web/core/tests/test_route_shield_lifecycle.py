"""The baseline migration as one NMAS transaction: the R3/R4 kernel-cover capability, the plan, every gate, the full
Change -> validation -> Plan -> Precheck -> approval -> execution lifecycle, and the reverse path.

The simulated network keeps each access device's configuration as a set of statement paths and derives its routing table
from it the way cEOS 4.36.2F did in the disposable sandbox (static 1 < IS-IS 115 < floating static 250).  The core
routers are the REAL ``KernelCoverExecutor`` over an emulated ``ip`` / ``vtysh``: every argv it would send is exercised.
"""

from __future__ import annotations

import ipaddress
import json
import re
import subprocess
from types import SimpleNamespace

from django.test import SimpleTestCase, TestCase
from django.utils import timezone

from core import models
from core.services import execution_service
from core.services.execution.executors.base import APPLY, REFUSE, SKIP_SATISFIED, ApplyOutcome, Assessment, CompensationOutcome, ConfigletSpec, ExecutorError
from core.services.execution.executors.ceos import CeosExecutor
from core.services.health.evidence import DeviceEvidence, FactGroup
from core.services.route_shield import core_cover, gates, lab, lifecycle, migration, probes, readiness
from core.services.route_shield.core_cover import CoverError, CoverRoute, KernelCoverExecutor

D = migration.PRODUCTION
R1LL, R2LL = core_cover.R1_LINK_LOCAL, core_cover.R2_LINK_LOCAL
ACKS = {name: True for name, _ in lifecycle.ACKNOWLEDGEMENTS}
CONNECTED = {
    "S1": {"2001:db8:110:1::/64": "Ethernet1", "2001:db8:110:3::/64": "Vlan99"}, "S2": {"2001:db8:110:2::/64": "Ethernet1", "2001:db8:110:3::/64": "Vlan99"},
    "R1": {"2001:db8:110:1::/64": "Ethernet2", "2001:db8:100:103::/64": "Vlan103", "2001:db8:100:104::/64": "Vlan104"},
    "R2": {"2001:db8:110:2::/64": "Ethernet2", "2001:db8:100:101::/64": "Vlan101", "2001:db8:100:102::/64": "Vlan102"},
}
PEER = {"S1": "R1", "S2": "R2", "R1": "S1", "R2": "S2"}
BASE = {
    "S1": {"ipv6 route ::/0 3fff:172:20:20::1", "ipv6 route 2001:db8::/32 2001:db8:110:1::1"},
    "S2": {"ipv6 route ::/0 3fff:172:20:20::1", "ipv6 route 2001:db8::/32 2001:db8:110:2::1"},
    "R1": {"ipv6 route ::/0 3fff:172:20:20::1", *(f"ipv6 route {p} 2001:db8:110:1::2" for p in lab.CLIENTS),
           "route-map STATIC6-TO-OSPF permit 10 > match ipv6 address prefix-list CLIENT-V6", "ipv6 router ospf 10 > redistribute static route-map STATIC6-TO-OSPF"},
    "R2": {"ipv6 route ::/0 3fff:172:20:20::1", *(f"ipv6 route {p} 2001:db8:110:2::2" for p in lab.CLIENTS),
           "route-map STATIC6-TO-OSPF permit 10 > match ipv6 address prefix-list CLIENT-V6", "ipv6 router ospf 10 > redistribute static route-map STATIC6-TO-OSPF"},
}


def _group(data):
    return FactGroup(data=data, source="LIVE", observed_at=timezone.now())


class Network:
    """Six simulated devices.  ``sent`` records every mutating command of the whole run, in order."""

    def __init__(self):
        self.paths = {name: set(lines) for name, lines in BASE.items()}
        self.kernel = {core: {p: {"protocol": "ospf", "hops": list(D.covers_of(core)[0].next_hops)} for p in lab.CLIENTS} for core in D.cores}
        for core in D.cores:
            self.kernel[core]["default"] = {"protocol": "boot", "hops": [("3fff:172:20:20::1", "eth0")]}
        self.startup = {name: set(lines) for name, lines in BASE.items()}       # what each access device would boot
        self.boot = {core: f"hostname {core}\nrouter ospf6\n" for core in D.cores}   # /etc/frr/frr.conf of each core router
        self.saves: list[tuple[str, frozenset]] = []                             # every startup write: (device, what was written)
        self.fail_save: set[str] = set()                                         # devices that reject the persistence command
        self.lose_save: set[str] = set()                                         # devices that accept it and keep the old startup
        self.sent: list[tuple[str, str]] = []
        self.quiet = "00:10:00"
        self.answers = True
        self.adjacent = True
        self.fail_delete = False

    # -- access devices -------------------------------------------------------------------------------------------------
    def isis_routes(self, name) -> dict:
        own, peer = self.paths[name], self.paths[PEER[name]]
        if name.startswith("S"):
            ok = "interface Ethernet1 > isis enable NMAS" in own and "router isis NMAS > address-family ipv6 unicast > redistribute static route-map STATIC6-TO-ISIS6" in peer
            return {lab.AGGREGATE: "Ethernet1"} if ok else {}
        ok = "interface Ethernet2 > isis enable NMAS" in own and "interface Vlan10 > isis passive" in peer
        return {p: "Ethernet2" for p in lab.CLIENTS} if ok else {}

    def routes(self, name) -> dict:
        """prefix -> (type, interface, next hop): the installed route only."""
        best = {prefix: (0, "connected", interface, "") for prefix, interface in CONNECTED[name].items()}
        for prefix, interface in self.isis_routes(name).items():
            best[prefix] = (115, "isisL2", interface, "fe80::1")
        for line in self.paths[name]:
            if not line.startswith("ipv6 route "):
                continue
            parts = line.split()
            prefix, hop, distance = parts[2], parts[3], int(parts[4]) if len(parts) > 4 else 1
            interface = next((i for net, i in CONNECTED[name].items() if ipaddress.ip_address(hop) in ipaddress.ip_network(net)), "Management0" if hop.startswith("3fff") else "Vlan103")
            if prefix not in best or distance < best[prefix][0]:
                best[prefix] = (distance, "static", interface, hop)
        return {str(ipaddress.ip_network(p)): row[1:] for p, row in best.items()}

    def evidence(self, device):
        name = device["name"]
        if name in D.cores:
            hops = D.covers_of(name)[0].next_hops
            return DeviceEvidence(device=name, platform="linux", live_attempted=True, groups={
                "interfaces": _group({interface: {"admin": "UP", "oper": "UP"} for _a, interface in hops}),
                "ospf": _group([{"family": "OSPFV3", "neighbor_id": f"192.168.255.{i}", "interface": interface, "state": "FULL"} for i, (_a, interface) in enumerate(hops, 1)])})
        routes = [{"prefix": p, "type": kind, "interfaces": [i] if i else [], "next_hops": [h] if h else []} for p, (kind, i, h) in sorted(self.routes(name).items())]
        interfaces = {i: {"admin": "UP", "oper": "UP"} for i in ("Ethernet1", "Ethernet2", "Vlan99", "Management0")}
        return DeviceEvidence(device=name, platform="ceos", live_attempted=True, groups={"routes": _group(routes), "interfaces": _group(interfaces), "isis": _group([])})


def _render(paths) -> str:
    """Statement paths back to an indented configuration text."""
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


class SimCeos:
    """The executor contract, the read-back commands and the echo probe over one simulated access device."""

    def __init__(self, net: Network, device: dict):
        self.net, self.name = net, device["name"]

    def connect(self):
        return None

    def close(self):
        return None

    def config_state_digest(self):
        return "|".join(sorted(self.net.paths[self.name]))

    def startup_state_digest(self):
        return "|".join(sorted(self.net.startup[self.name]))

    def startup_config_text(self):
        return _render(self.net.startup[self.name])

    def save_startup(self):
        if self.name in self.net.fail_save:
            return ApplyOutcome(False, "COMMAND_REJECTED", partial_effects=True, lines_sent=1)
        self.net.saves.append((self.name, frozenset(self.net.paths[self.name])))
        if self.name not in self.net.lose_save:
            self.net.startup[self.name] = set(self.net.paths[self.name])
        return ApplyOutcome(True, lines_sent=1)

    def neighbour_answers(self, address, interface=""):
        return self.net.answers

    def show(self, command):
        paths = self.net.paths[self.name]
        if command == "show running-config":
            return _render(paths)
        if command == "show hostname | json":
            return json.dumps({"hostname": self.name})
        if command == "show version | json":
            return json.dumps({"modelName": "cEOSLab", "version": "4.36.2F"})
        if command == "show running-config section router rip":
            return "router rip\n   no shutdown\n"
        if command == "show isis neighbors | json":
            up = [i for i in ("Ethernet1", "Ethernet2", "Vlan99") if f"interface {i} > isis enable NMAS" in paths and any(p.startswith("router isis NMAS > net ") for p in paths)]
            rows = {f"sys{n}": {"adjacencies": [{"interfaceName": i, "state": "up", "level": "level-2", "hostname": "x"}]} for n, i in enumerate(up)}
            return json.dumps({"vrfs": {"default": {"isisInstances": {"NMAS": {"neighbors": rows}}}}})
        if command == "show isis database detail":
            peer = self.net.paths[PEER[self.name]]
            held = [lab.AGGREGATE] if "router isis NMAS > address-family ipv6 unicast > redistribute static route-map STATIC6-TO-ISIS6" in (peer | paths) else []
            held += list(lab.CLIENTS) if "interface Vlan10 > isis passive" in (peer | paths) else []
            return "\n".join(f"  Reachability : {p} Metric: 10" for p in held)
        target = command.removeprefix("show ipv6 route ").removesuffix(" | json")
        routes = self.net.routes(self.name)
        if "/" in target:
            found = {target: routes[target]} if target in routes else {}
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
        wanted = self._wanted(spec)
        found = [p for p in wanted if p in self.net.paths[self.name]]
        facts = {"kind": "config_block", "config_digest": self.config_state_digest()}
        if found and len(found) != len(wanted):
            return Assessment(REFUSE, False, facts, "REMOVAL_TARGET_DRIFTED")
        if spec.origin == "REMOVAL":
            return Assessment(APPLY if found else SKIP_SATISFIED, True, facts)
        return Assessment(SKIP_SATISFIED if found else APPLY, True, facts)

    def apply(self, spec, assessment):
        self.net.sent.append((self.name, spec.cfg_id))
        if spec.origin == "REMOVAL":
            self.net.paths[self.name] -= set(self._wanted(spec))
        else:
            self.net.paths[self.name] |= set(self._wanted(spec))
        return ApplyOutcome(True, lines_sent=len(spec.lines))

    def compensate(self, spec, assessment):
        self.net.sent.append((self.name, f"undo {spec.cfg_id}"))
        if spec.origin == "REMOVAL":
            self.net.paths[self.name] |= set(self._wanted(spec))
        else:
            self.net.paths[self.name] -= set(self._wanted(spec))
        return CompensationOutcome("COMPENSATED")


def ip_runner(net: Network):
    """``docker exec <core> ip|vtysh ...`` over the simulated kernel tables."""

    def row(prefix, entry):
        hops = entry["hops"]
        body = {"gateway": hops[0][0], "dev": hops[0][1]} if len(hops) == 1 else {"nexthops": [{"gateway": a, "dev": d} for a, d in hops]}
        return {"dst": prefix, "protocol": entry["protocol"], **body}

    def run(container, argv, timeout):
        table = net.kernel[container]
        ok = lambda out="": subprocess.CompletedProcess(argv, 0, out, "")  # noqa: E731
        if argv == ["cat", core_cover.PERSISTENT_CONFIG]:
            return ok(net.boot[container])
        if argv == ["hostname"]:
            return ok(container + "\n")
        if argv[:2] == ["vtysh", "-c"]:
            if argv[2] == "show version":
                return ok("FRRouting 8.4.4 (R3) on Linux\n")
            if argv[2] == "show running-config":
                return ok("Building configuration...\nrouter ospf6\n ospf6 router-id 192.168.255.3\n")
            if argv[2] == "show ipv6 ospf6 neighbor detail json":
                hops = D.covers_of(container)[0].next_hops
                return ok(json.dumps({f"192.168.255.{i}%{dev}": {"interface": dev, "linkLocalAddress": address, "neighborState": "Full" if net.adjacent else "Init"}
                                      for i, (address, dev) in enumerate(hops, 1)}))
            prefix = argv[2].split()[3]
            return ok(json.dumps({prefix: [{"installed": prefix in table, "internalNextHopActiveNum": 2, "uptime": net.quiet}]}))
        if argv[:4] == ["ip", "-j", "-6", "neigh"]:
            return ok(json.dumps([{"dst": argv[5], "dev": argv[7], "lladdr": "00:1c:73:00:00:01", "state": ["REACHABLE" if net.answers else "FAILED"]}]))
        if argv[:5] == ["ip", "-j", "-6", "route", "get"]:
            address = ipaddress.ip_address(argv[5])
            match = max((p for p in table if p != "default" and address in ipaddress.ip_network(p)), key=lambda p: ipaddress.ip_network(p).prefixlen, default="default")
            return ok(json.dumps([{"dst": str(address), "gateway": table[match]["hops"][0][0], "dev": table[match]["hops"][0][1]}]))
        if argv[:5] == ["ip", "-j", "-6", "route", "show"]:
            rest = argv[5:]
            if rest == ["table", "all"]:
                return ok(json.dumps([row(p, e) for p, e in table.items()]))
            if rest[0] == "root":
                inside = ipaddress.ip_network(rest[1])
                return ok(json.dumps([row(p, e) for p, e in table.items() if p != "default" and ipaddress.ip_network(p).subnet_of(inside)]))
            return ok(json.dumps([row(p, e) for p, e in table.items() if p == rest[0]]))
        if argv[:4] == ["ip", "-6", "route", "add"]:
            net.sent.append((container, " ".join(argv)))
            if argv[4] in table:
                return subprocess.CompletedProcess(argv, 2, "", "RTNETLINK answers: File exists")
            table[argv[4]] = {"protocol": "boot", "hops": [(argv[i + 2], argv[i + 4]) for i, word in enumerate(argv) if word == "nexthop"]}
            return ok()
        if argv[:4] == ["ip", "-6", "route", "del"]:
            net.sent.append((container, " ".join(argv)))
            if net.fail_delete or argv[4] not in table:
                return subprocess.CompletedProcess(argv, 2, "", "RTNETLINK answers: No such process")
            del table[argv[4]]
            return ok()
        raise AssertionError(f"unexpected command {argv}")
    return run


class Probes:
    def __init__(self):
        self.ok, self.count = True, 0

    def healthy(self):
        return self.ok, {"lost": self.count}

    def lost(self):
        return self.count

    def advancing(self):
        return getattr(self, "advances", True), {"judged": True, "stalled_flows": [] if getattr(self, "advances", True) else ["h1-service-v6"]}


DEVICES = {name: {"name": name, "platform": "linux" if name in D.cores else "ceos", "container": name, "address": ""} for name in D.devices}


def environment(net: Network, *, observer=None, probe_source=None):
    runner = ip_runner(net)
    return lifecycle.Environment(
        devices=DEVICES, executor_factory=lambda device: KernelCoverExecutor(device, runner=runner) if device["platform"] == "linux" else SimCeos(net, device),
        read=net.evidence, probes=probe_source or Probes(), host_gate=lambda: (True, {"load1": 5.0}), observer=observer,
        sleep=lambda seconds: None, poll_seconds=0, clock=lambda ticks=iter(range(0, 10**9, 25)): next(ticks))


def core(net: Network, name="R3") -> KernelCoverExecutor:
    executor = KernelCoverExecutor(DEVICES[name], runner=ip_runner(net))
    executor.connect()
    return executor


# ------------------------------------------------------------------------------------------------------------- R3 / R4 covers
class CoverModelTests(SimpleTestCase):
    def cover(self, **changes):
        base = dict(core="R3", prefix="2001:db8:10::/63", protects="2001:db8:10::/64", next_hops=((R1LL, "Vlan101"), (R2LL, "Vlan103")))
        return CoverRoute(**{**base, **changes})

    def test_the_approved_inventory_is_three_covers_on_each_core_toward_both_boundary_routers(self):
        self.assertEqual([(c.core, c.prefix, c.next_hops) for c in D.covers], [
            (core_name, prefix, hops) for core_name, hops in (("R3", ((R1LL, "Vlan101"), (R2LL, "Vlan103"))), ("R4", ((R1LL, "Vlan102"), (R2LL, "Vlan104"))))
            for prefix in ("2001:db8:10::/63", "2001:db8:20::/63", "2001:db8:30::/63")])
        self.assertEqual(self.cover().add_argv(), ["ip", "-6", "route", "add", "2001:db8:10::/63", "nexthop", "via", R1LL, "dev", "Vlan101",
                                                   "nexthop", "via", R2LL, "dev", "Vlan103"])
        self.assertEqual(self.cover().del_argv(), ["ip", "-6", "route", "del", "2001:db8:10::/63"])
        self.assertEqual(self.cover().probe_address, "2001:db8:10:1::1")

    def test_anything_that_is_not_the_approved_shape_builds_nothing(self):
        for changes in (dict(core="R1"), dict(core="R5"), dict(prefix="2001:db8:10::/62"), dict(prefix="2001:db8:10::/64"), dict(prefix="2001:db8:20::/63"),
                        dict(protects="2001:db8:10::/65"), dict(next_hops=((R1LL, "Vlan101"),)), dict(next_hops=((R1LL, "Vlan101"), (R2LL, "Vlan101"))),
                        dict(next_hops=(("2001:db8:100:101::1", "Vlan101"), (R2LL, "Vlan103"))), dict(next_hops=((R1LL, "lo"), (R2LL, "Vlan103"))), dict(next_hops=((R1LL, "Management0"), (R2LL, "Vlan103"))),
                        dict(next_hops=((R1LL, "Vlan101; reboot"), (R2LL, "Vlan103")))):
            with self.subTest(changes=changes), self.assertRaises(CoverError):
                self.cover(**changes)


class KernelCoverExecutorTests(SimpleTestCase):
    def setUp(self):
        self.net = Network()
        self.executor = core(self.net)
        self.cover = D.covers_of("R3")[0]
        self.install = core_cover.install_spec(self.cover, "CFG-001", 1)
        self.remove = core_cover.remove_spec(self.cover, "CFG-043", 43)

    def test_install_read_back_remove_and_idempotency(self):
        before = self.executor.static_route_digest()
        first = self.executor.assess(self.install)
        self.assertEqual((first.action, first.restorable, first.previous_state["state"]), (APPLY, True, "ABSENT"))
        self.assertTrue(self.executor.apply(self.install, first).ok)
        self.assertEqual(self.net.sent, [("R3", " ".join(self.cover.add_argv()))])
        self.assertEqual(self.executor.state(self.cover), "EXACT")
        self.assertTrue(self.executor.forwards(self.cover))
        self.assertEqual(self.executor.assess(self.install).action, SKIP_SATISFIED)            # a second install sends nothing
        self.assertNotEqual(self.executor.static_route_digest(), before)
        gone = self.executor.assess(self.remove)
        self.assertEqual(gone.action, APPLY)
        self.assertTrue(self.executor.apply(self.remove, gone).ok)
        self.assertEqual(self.executor.state(self.cover), "ABSENT")
        self.assertEqual(self.executor.assess(self.remove).action, SKIP_SATISFIED)             # and a second removal too
        self.assertEqual(self.executor.static_route_digest(), before)

    def test_an_existing_different_route_is_never_overwritten(self):
        self.net.kernel["R3"][self.cover.prefix] = {"protocol": "static", "hops": [("fe80::dead", "Vlan101")]}
        for spec in (self.install, self.remove):
            found = self.executor.assess(spec)
            self.assertEqual((found.action, found.reason), (REFUSE, core_cover.PREFIX_OCCUPIED))
        self.assertEqual(self.net.sent, [])

    def test_compensation_restores_exactly_what_was_found(self):
        found = self.executor.assess(self.install)
        self.executor.apply(self.install, found)
        self.assertEqual(self.executor.compensate(self.install, found).status, "COMPENSATED")
        self.assertEqual(self.executor.state(self.cover), "ABSENT")
        self.executor.apply(self.install, found)
        removing = self.executor.assess(self.remove)
        self.executor.apply(self.remove, removing)
        self.assertEqual(self.executor.compensate(self.remove, removing).status, "COMPENSATED")     # a removal is undone by installing it again
        self.assertEqual(self.executor.state(self.cover), "EXACT")

    def test_a_failed_cleanup_is_reported_not_hidden(self):
        found = self.executor.assess(self.install)
        self.executor.apply(self.install, found)
        self.net.fail_delete = True
        self.assertEqual(self.executor.compensate(self.install, found).status, "COMPENSATION_FAILED")
        self.assertFalse(self.executor.apply(self.remove, self.executor.assess(self.remove)).ok)

    def test_only_the_planned_text_of_an_approved_cover_is_ever_executed(self):
        tampered = ConfigletSpec("CFG-001", 1, "R3", core_cover.PLATFORM, core_cover.OBJECT_TYPE, "CREATE_DEFINE", ("ip -6 route add ::/0 via fe80::1 dev eth0",),
                                 self.cover.to_expected())
        other_type = ConfigletSpec("CFG-001", 1, "R3", core_cover.PLATFORM, "static_route", "CREATE_DEFINE", self.cover.lines(), self.cover.to_expected())
        wrong_device = core_cover.install_spec(D.covers_of("R4")[0], "CFG-004", 4)
        for spec in (tampered, other_type, wrong_device):
            self.assertEqual(self.executor.assess(spec).action, REFUSE)
            self.assertFalse(self.executor.apply(spec, Assessment(APPLY, True)).ok)
        self.assertEqual(self.net.sent, [])
        with self.assertRaises(ExecutorError):
            KernelCoverExecutor({"name": "R1", "container": "R1"}, runner=ip_runner(self.net)).connect()

    def test_precheck_blocks_every_unsafe_pre_state(self):
        covers = D.covers_of("R3")
        self.assertEqual(core_cover.precheck(covers, self.executor, self.net.evidence(DEVICES["R3"])), [])

        def codes(mutate, evidence=None):
            net = Network()
            mutate(net)
            return {row["code"] for row in core_cover.precheck(covers, core(net), evidence or net.evidence(DEVICES["R3"]))}

        self.assertIn(gates.OUT_OF_BAND, codes(lambda n: n.kernel["R3"].update({"2001:db8:10::/63": {"protocol": "boot", "hops": list(covers[0].next_hops)}})))
        self.assertIn(gates.OLD_ROUTE_ABSENT, codes(lambda n: n.kernel["R3"].update({"2001:db8:10::/64": {"protocol": "ospf", "hops": [(R1LL, "Vlan101")]}})))
        self.assertIn(gates.OLD_ROUTE_ABSENT, codes(lambda n: n.kernel["R3"].pop("2001:db8:20::/64")))
        self.assertIn(gates.CLASSIFICATION_UNKNOWN, codes(lambda n: n.kernel["R3"].update({"2001:db8:10:1::/64": {"protocol": "static", "hops": [(R1LL, "Vlan101")]}})))
        self.assertIn(gates.NEXT_HOP_UNHEALTHY, codes(lambda n: setattr(n, "answers", False)))
        self.assertIn(gates.MANAGEMENT_FALLBACK, codes(lambda n: n.kernel["R3"].update({"default": {"protocol": "boot", "hops": [("fe80::1", "Vlan103")]}})))
        down = self.net.evidence(DEVICES["R3"])
        down.groups["interfaces"].data["Vlan103"]["oper"] = "DOWN"
        self.assertIn(gates.NEXT_HOP_UNHEALTHY, codes(lambda n: None, down))
        self.assertIn(gates.NEXT_HOP_UNHEALTHY, codes(lambda n: setattr(n, "adjacent", False)))
        self.assertEqual(codes(lambda n: None, DeviceEvidence(device="R3", platform="linux", live_attempted=True, groups={})), {gates.EVIDENCE_UNAVAILABLE})

    def test_postcheck_requires_the_exact_cover_forwarding_and_unchanged_adjacencies(self):
        covers, evidence = D.covers_of("R3"), self.net.evidence(DEVICES["R3"])
        before = core_cover.adjacencies(evidence)
        self.assertTrue(core_cover.postcheck(covers, self.executor, evidence, adjacencies_before=before))            # nothing installed yet
        for cover in covers:
            self.executor.apply(core_cover.install_spec(cover, "CFG-001", 1), Assessment(APPLY, True))
        self.assertEqual(core_cover.postcheck(covers, self.executor, evidence, adjacencies_before=before), [])
        self.assertTrue(core_cover.postcheck(covers, self.executor, evidence, adjacencies_before=before, present=False))
        changed = self.net.evidence(DEVICES["R3"])
        changed.groups["ospf"].data[1]["state"] = "EXSTART"
        self.assertEqual([row["code"] for row in core_cover.postcheck(covers, self.executor, changed, adjacencies_before=before)], [gates.NEXT_HOP_UNHEALTHY])


# ----------------------------------------------------------------------------------------------------------------------- plan
class PlanTests(SimpleTestCase):
    def setUp(self):
        self.ops = migration.forward_operations(D)

    def test_the_plan_is_valid_and_spans_exactly_the_six_devices(self):
        self.assertEqual(migration.validate(D, self.ops), [])
        self.assertEqual({op.device for op in self.ops}, {"S1", "S2", "R1", "R2", "R3", "R4"})
        self.assertEqual([op.stage for op in self.ops[:6]], [migration.CORE_COVER_INSTALL] * 6)
        self.assertEqual([op.stage for op in self.ops[-6:]], [migration.CORE_COVER_REMOVE] * 6)

    def test_the_proven_order_of_one_side(self):
        side = [op.key for op in self.ops if op.stage in (migration.SHIELD_INSTALL, migration.STATIC_REMOVAL, migration.SHIELD_REMOVE)][:9]
        self.assertEqual(side, ["S1-shield-install", "R1-shield-install", "S1-static-aggregate-remove", "R1-floating-statics-add", "R1-client-statics-remove",
                                "R1-floating-statics-remove", "R1-old-redistribution-remove", "R1-shield-remove", "S1-shield-remove"])

    def test_temporary_state_is_separate_from_permanent_intent(self):
        temporary = set(migration.temporary_lines(self.ops))
        self.assertEqual(len(temporary), 6 + 2 * 2 + 2 * 3 + 2 * 3)          # covers, /33 pairs, /63 shields, floating statics
        intent = migration.permanent_lines(self.ops)
        self.assertEqual(set(intent), {"S1", "S2", "R1", "R2"})              # nothing permanent on R3 / R4
        self.assertFalse(temporary & {line for lines in intent.values() for line in lines})
        self.assertFalse(any("/63" in line or "/33" in line or line.endswith(" 250") for lines in intent.values() for line in lines))
        for op in self.ops:
            self.assertEqual(op.state == migration.TEMPORARY, op.device in ("R3", "R4") or "shield" in op.key or "floating" in op.key, op.key)

    def test_every_operation_has_an_exact_inverse(self):
        for op in self.ops:
            self.assertTrue(op.lines and op.inverse and op.paths, op.key)

    def test_a_plan_that_departs_from_the_design_is_blocked(self):
        from dataclasses import replace

        def codes(ops):
            return {row["code"] for row in migration.validate(D, ops)}

        self.assertIn("TEMPORARY_STATE_UNBALANCED", codes([op for op in self.ops if op.key != "R1-shield-remove"]))
        self.assertIn("COVER_INVENTORY_MISMATCH", codes([op for op in self.ops if op.key != "R4-cover-2001:db8:30::/63"]))
        self.assertIn("COVER_WINDOW_INCOMPLETE", codes([*self.ops[6:], *self.ops[:6]]))
        self.assertIn("CORE_SCOPE_EXCEEDED", codes([*self.ops, replace(self.ops[6], device="R3")]))
        on_management = replace(self.ops[0], cover=replace(self.ops[0].cover, next_hops=((R1LL, "eth0"), (R2LL, "Vlan103"))))
        self.assertIn("COVER_INVENTORY_MISMATCH", codes([on_management, *self.ops[1:]]))
        self.assertIn("TEMPORARY_STATE_IN_INTENT", codes([replace(op, state=migration.PERMANENT) if op.key == "S1-shield-install" else op for op in self.ops]))

    def test_the_sandbox_cabling_changes_interfaces_only(self):
        sandbox = migration.with_cabling(D, name="sandbox", access_interface="Ethernet3",
                                         core_hops={"R3": (("fe80::1", "eth1"), ("fe80::2", "eth2")), "R4": (("fe80::1", "eth1"), ("fe80::2", "eth2"))})
        ops = migration.forward_operations(sandbox)
        self.assertEqual([op.key for op in ops], [op.key for op in self.ops])
        self.assertEqual(migration.validate(sandbox, ops), [])
        swap = lambda line: line.replace("Ethernet3", "Ethernet2")  # noqa: E731
        for mine, theirs in zip(self.ops, ops):
            if mine.device not in ("R3", "R4"):
                self.assertEqual(mine.lines, tuple(swap(line) for line in theirs.lines))


class DeclaredInverseTests(SimpleTestCase):
    """cEOS: a route-shield statement that names its own inverse (a nested child has no derivable one)."""

    CONFIG = "router isis NMAS\n   net 49.0110.1921.6825.5001.00\n   address-family ipv6 unicast\n"

    def executor(self, text):
        conn = SimpleNamespace(send_command=lambda command, **kw: text if command == "show running-config" else "PING\n2 packets transmitted, 2 received")
        executor = CeosExecutor({"name": "R1"}, connection_factory=lambda device: conn,
                                reader=lambda device: DeviceEvidence(device="R1", platform="ceos", live_attempted=True, groups={
                                    name: _group(data) for name, data in (("interfaces", {}), ("addresses", {}), ("routes", []))}))
        executor.connect()
        return executor

    def spec(self):
        op = next(op for op in migration.forward_operations(D) if op.key == "R1-aggregate-into-isis")
        return ConfigletSpec.from_configlet(SimpleNamespace(pk=1, raw_revision=None, **lifecycle._configlet_fields(op, 20))), op

    def test_assessment_follows_the_declared_paths(self):
        spec, op = self.spec()
        absent = self.executor(self.CONFIG).assess(spec)
        self.assertEqual((absent.action, absent.restorable), (APPLY, True))
        present = self.executor(self.CONFIG + "      redistribute static route-map STATIC6-TO-ISIS6\n").assess(spec)
        self.assertEqual(present.action, SKIP_SATISFIED)
        self.assertEqual(op.inverse[-1].strip(), "no redistribute static route-map STATIC6-TO-ISIS6")

    def test_read_back_accepts_show_commands_only(self):
        executor = self.executor(self.CONFIG)
        self.assertIn("router isis", executor.show("show running-config"))
        for command in ("configure terminal", "show running-config | append flash:x", "bash rm -rf /", "show x; reload"):
            with self.subTest(command=command), self.assertRaises(ExecutorError):
                executor.show(command)
        self.assertTrue(executor.neighbour_answers("2001:db8:110:1::2"))
        self.assertFalse(executor.neighbour_answers("192.168.1.1"))
        self.assertFalse(executor.neighbour_answers("fe80::1", "Ethernet1; reload"))


class ProbeTests(SimpleTestCase):
    def test_a_dead_runs_probes_can_never_write_into_a_new_runs_files_and_end_on_their_own(self):
        scripts = []

        def runner(container, argv, detach=False, timeout=30.0):
            if detach:
                scripts.append(argv[-1])
            return subprocess.CompletedProcess(argv, 0, "0 1 1\n", "")
        flow = probes.Flow("h1-web-v6", "h1", "2001:db8:3050::10", 0.01)
        for _run in range(2):                                     # a worker killed mid-run, then the recovery's own probes
            probes.HostProbes([flow], runner=runner, sleep=lambda s: None).start()
        first, second = (re.search(r"> (\S+\.log)", script).group(1) for script in scripts)
        self.assertNotEqual(first, second)
        self.assertTrue(all(" -w 900 " in script for script in scripts))
        calls = []
        source = probes.HostProbes([flow], runner=lambda container, argv, detach=False, timeout=30.0: calls.append((container, argv[-1])) or
                                   subprocess.CompletedProcess(argv, 0, "", ""), sleep=lambda s: None)
        source.halt_run("0123456789ab")                               # the dead run's own pid files, and only live pings
        self.assertEqual([c for c, _ in calls], ["h1"])
        self.assertIn("*.0123456789ab.*.pid", calls[0][1])
        self.assertIn("/proc/$p/comm", calls[0][1])
        with self.assertRaises(ValueError):
            source.halt_run("*; reboot")

    def test_a_flow_that_cannot_be_read_counts_as_loss(self):
        calls = []

        def runner(container, argv, detach=False, timeout=30.0):
            calls.append(argv[0])
            return subprocess.CompletedProcess(argv, 0, "0 500 500\n" if container == "h1" else "", "")
        source = probes.HostProbes([probes.Flow("h1-web-v6", "h1", "2001:db8:3050::10", 0.01), probes.Flow("h2-web-v6", "h2", "2001:db8:3050::10", 0.01)],
                                   runner=runner, sleep=lambda s: None)
        source.start()
        self.assertEqual(source.report()[0], {"flow": "h1-web-v6", "destination": "2001:db8:3050::10", "answered": 500, "lost": 0})
        self.assertGreater(source.lost(), 0)
        self.assertFalse(source.healthy()[0])
        with self.assertRaises(ValueError):
            probes.Flow("x; reboot", "h1", "2001:db8::1")
        self.assertFalse(source.advancing()[0])                    # an unreadable flow is never "advancing"

    def test_a_flow_that_stops_delivering_samples_is_unreliable_timing_not_zero_loss(self):
        now, seen = [0.0], {"h1": 0, "h2": 0}

        def runner(container, argv, detach=False, timeout=30.0):
            return subprocess.CompletedProcess(argv, 0, f"0 {seen[container]} {seen[container]}\n", "")
        source = probes.HostProbes([probes.Flow("h1-web-v6", "h1", "2001:db8:3050::10", 0.01), probes.Flow("h2-web-v4", "h2", "192.168.50.10", 0.1)],
                                   runner=runner, sleep=lambda s: None, clock=lambda: now[0])
        source.start()
        self.assertEqual(source.advancing(), (True, {"judged": False}))                       # the first call is only the reference
        now[0], seen["h1"], seen["h2"] = 5.0, 0, 0
        self.assertEqual(source.advancing(), (True, {"judged": False}))                       # too short an interval to judge
        now[0], seen["h1"], seen["h2"] = 60.0, 4700, 550                                      # 78 % and 92 % of nominal: a loaded host
        self.assertTrue(source.advancing()[0])
        now[0], seen["h1"], seen["h2"] = 120.0, 4700 + 2000, 550 + 560                        # 33 % of nominal on one flow, nothing "lost"
        ok, detail = source.advancing()
        self.assertEqual((ok, detail["stalled_flows"], source.lost()), (False, ["h1-web-v6"], 0))
        self.assertEqual(detail["samples_seen_of_expected"], {"h1-web-v6": [2000, 6000]})
        now[0], seen["h1"], seen["h2"] = 180.0, 6700 + 5000, 1110                             # the other flow went silent
        self.assertEqual(source.advancing()[1]["stalled_flows"], ["h2-web-v4"])
        with self.assertRaises(ValueError):
            probes.Flow("ok", "h1", "not-an-address")


# ------------------------------------------------------------------------------------------------------------------ lifecycle
class LifecycleTests(TestCase):
    def prepare(self, net=None, *, approve=True):
        net = net or Network()
        change = lifecycle.create_change(actor="operator")
        validation = lifecycle.validate_change(change, actor="operator", inventory=DEVICES)
        plan = lifecycle.build_plan(change, actor="operator")
        precheck = lifecycle.run_precheck(change, actor="operator", env=environment(net))
        if approve and precheck.status == "PASS":
            lifecycle.approve(change, actor="approver", confirmation=change.change_id, acknowledgements=ACKS)
            change.refresh_from_db()
        return SimpleNamespace(net=net, change=change, validation=validation, plan=plan, precheck=precheck)

    def execute(self, case, **kw):
        env = environment(case.net, **kw)
        result = lifecycle._execute(case.change, actor="operator", confirmation=case.change.change_id, env=env, definition=D)
        case.change.refresh_from_db()
        return result

    def assert_baseline(self, net):
        self.assertEqual(net.paths, {name: set(lines) for name, lines in BASE.items()})
        self.assertEqual(net.startup, {name: set(lines) for name, lines in BASE.items()})
        for name in D.cores:
            self.assertFalse([p for p in net.kernel[name] if p.endswith("/63")])

    # -- the records ------------------------------------------------------------------------------------------------------
    def test_validation_and_plan_are_immutable_evidence(self):
        case = self.prepare(approve=False)
        self.assertEqual((case.validation.status, case.change.validation_state), ("PASS", "PASSED"))
        self.assertEqual(case.validation.report["readiness"], readiness.READY)
        self.assertEqual(len(case.validation.report["cover_inventory"]), 6)
        self.assertEqual(sorted(t.device_name for t in case.change.targets.all()), ["R1", "R2", "R3", "R4", "S1", "S2"])
        rows = list(case.plan.configlets.order_by("sequence"))
        self.assertEqual(len(rows), 48)
        states = {row.cfg_id: row.metadata["transition"]["state"] for row in rows}
        self.assertEqual(sum(state == "TEMPORARY" for state in states.values()), len(case.plan.summary["temporary"]))
        self.assertTrue(all(row.description.startswith(f"[{states[row.cfg_id]}]") for row in rows))
        self.assertEqual(set(case.plan.summary["permanent_intent"]), {"S1", "S2", "R1", "R2"})
        self.assertIs(lifecycle.build_plan(case.change, actor="operator").pk, case.plan.pk)            # the same validation gives the same plan
        rows[0].rendered_config = "ip -6 route add ::/0 via fe80::1 dev eth0"
        with self.assertRaises(ValueError):
            rows[0].save()
        with self.assertRaises(ValueError):
            case.validation.save()

    def test_validation_blocks_a_device_that_is_not_what_the_design_expects(self):
        change = lifecycle.create_change(actor="operator")
        run = lifecycle.validate_change(change, actor="operator", inventory={**DEVICES, "R3": {**DEVICES["R3"], "platform": "ceos"}, "R4": None})
        self.assertEqual(run.status, "BLOCKED")
        self.assertEqual({row["code"] for row in run.report["findings"]}, {"PLATFORM_MISMATCH", "DEVICE_NOT_MANAGED"})
        with self.assertRaises(lifecycle.LifecycleError):
            lifecycle.build_plan(change, actor="operator")

    def test_the_general_execution_engine_refuses_a_transition_change(self):
        case = self.prepare()
        gate = execution_service.check_execution_eligibility(case.change, confirm_mode="COMPLETE", check_sources=False)
        self.assertTrue(gate.has("TRANSITION_CHANGE_NOT_GENERIC"))
        self.assertFalse(gate.eligible)

    # -- the forward path --------------------------------------------------------------------------------------------------
    def test_the_complete_lifecycle_reaches_the_final_state_with_nothing_temporary_left(self):
        seen = []
        case = self.prepare()
        result = self.execute(case, observer=lambda event, key: seen.append((event, key)))
        report = result.run.report
        self.assertEqual((result.outcome, case.change.lifecycle_state), ("SUCCEEDED", "DEPLOYED"), report.get("failure"))
        self.assertEqual(len(report["state"]["applied"]), 48)
        self.assertEqual(report["temporary_state"]["remaining"], [])
        self.assertEqual(len(report["temporary_state"]["installed"]), len(report["temporary_state"]["removed"]))
        self.assertEqual(result.run.postcheck_run.status, "PASS")
        self.assertEqual(set(report["permanent_intent"]["baseline_digests"]), {"R1", "R2", "S1", "S2"})
        self.assertEqual(result.run.results.filter(phase="APPLY", status="APPLIED").count(), 48)
        self.assertFalse(models.ExecutionDeviceLock.objects.exists())
        # covers first, covers last, and the six devices are one transaction
        self.assertEqual([device for device, _ in case.net.sent[:6]], ["R3"] * 3 + ["R4"] * 3)
        self.assertEqual([device for device, _ in case.net.sent[-6:]], ["R3"] * 3 + ["R4"] * 3)
        self.assertTrue(all(" del " in command for _, command in case.net.sent[-6:]))
        for name in D.cores:
            self.assertEqual(sorted(case.net.kernel[name]), sorted([*lab.CLIENTS, "default"]))
        for name, paths in case.net.paths.items():
            self.assertFalse([p for p in paths if "/63" in p or "/33" in p or p.endswith(" 250")], name)
            self.assertIn("router isis NMAS > is-type level-2", paths)
        self.assertNotIn("ipv6 route 2001:db8::/32 2001:db8:110:1::1", case.net.paths["S1"])
        self.assertEqual(case.net.routes("R1")["2001:db8:10::/64"][0], "isisL2")
        self.assertEqual([key for event, key in seen if event == "before"][:1], ["R3-cover-2001:db8:10::/63"])
        self.assertIn("DEPLOYMENT_RECORDED", set(models.AuditEvent.objects.filter(change=case.change).values_list("event_type", flat=True)))
        again = self.execute(case)                                           # a finished Change cannot be run twice
        self.assertEqual(again.outcome, "BLOCKED")

    # -- the reverse path --------------------------------------------------------------------------------------------------
    def test_a_failure_after_any_stage_restores_everything(self):
        class Boom(Exception):
            pass

        for key in ("R3-cover-2001:db8:20::/63", "S2-isis-links", "R2-isis-into-ospfv3", "R1-shield-install", "R1-client-statics-remove", "S1-shield-remove",
                    "R2-floating-statics-remove", "S2-shield-remove", "R3-cover-2001:db8:10::/63-remove", "R4-cover-2001:db8:30::/63-remove"):
            with self.subTest(failure_after=key):
                case = self.prepare()

                def observer(event, name, key=key):
                    if (event, name) == ("after", key):
                        raise Boom()
                result = self.execute(case, observer=observer)
                report = result.run.report
                self.assertEqual((result.outcome, case.change.lifecycle_state), ("FAILED_ROLLED_BACK", "ROLLED_BACK"), report.get("failure"))
                self.assertTrue(report["restored"])
                self.assertEqual(report["temporary_state"]["remaining"], [])
                self.assertEqual(report["compensation"]["status"], "COMPENSATED")
                self.assertEqual(len(report["state"]["compensated"]), len(report["state"]["applied"]))
                self.assert_baseline(case.net)
                undone = [command for device, command in case.net.sent if command.startswith("undo ") or " del " in command]
                self.assertTrue(undone)
                self.assertTrue(all(device in D.cores for device, _ in case.net.sent[-3:]))        # the core covers are the last thing to go
                self.assertFalse(models.ExecutionDeviceLock.objects.exists())

    def test_a_cover_that_disturbs_a_core_adjacency_stops_the_run_before_any_access_device_changes(self):
        case = self.prepare()
        evidence = case.net.evidence

        def observer(event, key):
            if (event, key) == ("before", "R3-cover-2001:db8:30::/63"):
                def changed(device):
                    found = evidence(device)
                    if device["name"] == "R3":
                        found.groups["ospf"].data[0]["state"] = "EXSTART"
                    return found
                case.net.evidence = changed
        env = environment(case.net, observer=observer)
        env.read = lambda device: case.net.evidence(device)
        result = lifecycle._execute(case.change, actor="operator", confirmation=case.change.change_id, env=env, definition=D)
        self.assertEqual(result.run.report["failure"]["code"], "GATE_FAILED")
        self.assertIn("adjacencies unchanged", result.run.report["failure"]["detail"])
        self.assertFalse([entry for entry in case.net.sent if entry[0] not in D.cores])          # no access device was touched
        self.assertFalse([p for p in case.net.kernel["R3"] if p.endswith("/63")])

    def test_a_lost_production_probe_aborts_and_restores(self):
        case = self.prepare()
        source = Probes()

        def observer(event, key):
            if (event, key) == ("after", "R1-client-statics-remove"):
                source.count = 1
        result = self.execute(case, observer=observer, probe_source=source)
        self.assertEqual(result.outcome, "FAILED_ROLLED_BACK")
        self.assertEqual(result.run.report["failure"]["code"], gates.PACKET_LOSS)
        self.assertEqual(result.run.report["probes"]["lost"], 1)
        self.assert_baseline(case.net)

    # -- between two stages: the window's own conditions ---------------------------------------------------------------------
    def window_env(self, case, *, host=None, source=None, samples=None, observer=None):
        env = environment(case.net, observer=observer, probe_source=source)
        if host is not None:
            env.host_gate = host
            if samples is not None:
                env.host_gate.consecutive_samples = samples
        return env

    def run_env(self, case, env):
        result = lifecycle._execute(case.change, actor="operator", confirmation=case.change.change_id, env=env, definition=D)
        case.change.refresh_from_db()
        return result

    def test_a_host_at_the_critical_condition_aborts_before_the_next_stage_and_restores(self):
        case, state = self.prepare(), {"busy": False, "calls": 0}

        def host():
            state["calls"] += state["busy"]
            return (False, {"failed": ["host CPU is at 93.0% with the probes running, the critical threshold is 90.0%"], "cpu_busy_percent": 93.0}) if state["busy"] else (True, {"cpu_busy_percent": 82.0})
        host.consecutive_samples = 3

        def observer(event, key):
            if (event, key) == ("after", "R1-shield-install"):       # the last operation of a stage: the next one is PROTECTED_STATIC_REMOVAL
                state["busy"] = True
        result = self.run_env(case, self.window_env(case, host=host, observer=observer))
        report = result.run.report
        self.assertEqual((result.outcome, case.change.lifecycle_state), ("FAILED_ROLLED_BACK", "ROLLED_BACK"), report.get("failure"))
        self.assertEqual(report["failure"]["code"], gates.WINDOW_CONDITION_LOST)
        self.assertIn("before PROTECTED_STATIC_REMOVAL", report["failure"]["detail"])
        self.assertEqual(state["calls"], 3)                                                    # the policy's consecutive samples, then the abort
        self.assertFalse([c for device, c in case.net.sent if device in ("S1", "R1") and c.startswith("no ipv6 route 2001:db8::/32")])   # the next stage never started
        self.assertEqual([entry["stage"] for entry in report["stages"] if entry["status"] == "APPLIED"][-1], migration.SHIELD_INSTALL)
        self.assertTrue(report["restored"])
        self.assert_baseline(case.net)

    def test_one_busy_sample_is_a_spike_and_does_not_abort(self):
        case, state = self.prepare(), {"spikes": 0, "armed": False}

        def host():
            if state["armed"]:
                state["armed"], state["spikes"] = False, state["spikes"] + 1
                return False, {"failed": ["host CPU is at 91.0% with the probes running, the critical threshold is 90.0%"]}
            return True, {"cpu_busy_percent": 83.0}
        host.consecutive_samples = lambda: 3

        def observer(event, key):
            if (event, key) == ("after", "R1-shield-install"):
                state["armed"] = True
        result = self.run_env(case, self.window_env(case, host=host, observer=observer))
        self.assertEqual((result.outcome, state["spikes"]), ("SUCCEEDED", 1), result.run.report.get("failure"))
        self.assertTrue([entry for entry in result.run.report["stages"] if entry["stage"] == "window" and entry["status"] == "PASS"])

    def test_a_probe_flow_that_stops_delivering_samples_aborts_although_nothing_was_lost(self):
        case, source = self.prepare(), Probes()

        def observer(event, key):
            if (event, key) == ("after", "S2-shield-install"):
                source.advances = False
        result = self.run_env(case, self.window_env(case, source=source, observer=observer))
        report = result.run.report
        self.assertEqual((result.outcome, report["failure"]["code"], report["probes"]["lost"]), ("FAILED_ROLLED_BACK", gates.PROBE_TIMING_UNRELIABLE, 0))
        self.assert_baseline(case.net)

    def test_a_window_condition_lost_before_the_first_stage_writes_nothing(self):
        case, state = self.prepare(), {"calls": 0}

        def host():
            state["calls"] += 1
            return (True, {}) if state["calls"] == 1 else (False, {"failed": ["the Challenge Console is running"]})      # the in-lock precheck passes, then the console starts
        result = self.run_env(case, self.window_env(case, host=host))
        self.assertEqual((result.outcome, result.run.report["failure"]["code"]), ("FAILED_NO_MUTATION", gates.WINDOW_CONDITION_LOST))
        self.assertEqual(case.net.sent, [])
        self.assert_baseline(case.net)

    def test_a_window_condition_lost_before_the_final_validation_persists_nothing(self):
        case, source = self.prepare(), Probes()

        def observer(event, key):
            if (event, key) == ("after", "R4-cover-2001:db8:30::/63-remove"):
                source.advances = False
        result = self.run_env(case, self.window_env(case, source=source, observer=observer))
        self.assertEqual((result.outcome, result.run.report["persistence"]["status"]), ("FAILED_ROLLED_BACK", "NOT_RUN"))
        self.assert_baseline(case.net)

    def test_a_probe_source_that_cannot_report_progress_is_a_refusal(self):
        class Silent:
            def healthy(self):
                return True, {"lost": 0}

            def lost(self):
                return 0
        case = self.prepare()
        result = self.run_env(case, self.window_env(case, source=Silent()))
        self.assertEqual((result.outcome, result.run.report["failure"]["code"]), ("FAILED_NO_MUTATION", gates.PROBE_TIMING_UNRELIABLE))

    def test_a_failed_final_validation_takes_the_reverse_path(self):
        case = self.prepare()

        def observer(event, key):
            if (event, key) == ("before", migration.FINAL_VALIDATION):
                case.net.paths["S1"].add("ipv6 route 2001:db8::/33 2001:db8:110:1::1")          # a temporary statement reappears
        result = self.execute(case, observer=observer)
        self.assertEqual(result.run.postcheck_run.status, "FAIL")
        self.assertIn(result.outcome, ("POSTCHECK_FAILED_COMPENSATION_INCOMPLETE", "POSTCHECK_FAILED_ROLLED_BACK"))
        self.assertNotEqual(result.outcome, "SUCCEEDED")

    def test_covers_that_cannot_be_removed_safely_stay_and_the_run_is_not_reported_as_restored(self):
        class Boom(Exception):
            pass
        case = self.prepare()

        def observer(event, key):
            if (event, key) == ("after", "R1-shield-install"):
                case.net.quiet = "00:00:05"                    # the cores keep replacing the client routes: removing a cover is not safe
                raise Boom()
        result = self.execute(case, observer=observer)
        report = result.run.report
        self.assertEqual((result.outcome, case.change.lifecycle_state), ("FAILED_COMPENSATION_INCOMPLETE", "FAILED"))
        self.assertFalse(report["restored"])
        self.assertEqual(len([row for row in report["temporary_state"]["remaining"] if "/63" in row]), 6)
        self.assertEqual(case.net.paths, {name: set(lines) for name, lines in BASE.items()})          # everything else was put back under the covers
        self.assertEqual(report["compensation"]["steps"][-1]["status"], "NOT_COMPENSATED")
        self.assertEqual(self.execute(case).outcome, "BLOCKED")                                          # unresolved: no second attempt

    def test_a_cover_that_will_not_delete_fails_closed(self):
        class Boom(Exception):
            pass
        case = self.prepare()

        def observer(event, key):
            if (event, key) == ("after", "S1-vlan99-ipv6"):
                case.net.fail_delete = True
                raise Boom()
        result = self.execute(case, observer=observer)
        self.assertEqual(result.outcome, "FAILED_COMPENSATION_INCOMPLETE")
        self.assertEqual(len(result.run.report["temporary_state"]["remaining"]), 6)
        self.assertTrue(result.run.results.filter(phase="COMPENSATE", status="COMPENSATION_FAILED").exists())

    # -- the gates ---------------------------------------------------------------------------------------------------------
    def test_nothing_runs_without_precheck_approval_and_confirmation(self):
        case = self.prepare(approve=False)
        self.assertEqual(self.execute(case).run.report["blockers"][0]["code"], "NOT_APPROVED")
        for confirmation, acks in (("yes", ACKS), (case.change.change_id, {}), (case.change.change_id, {**ACKS, "core_kernel_routes": False})):
            with self.assertRaises(lifecycle.LifecycleError):
                lifecycle.approve(case.change, actor="approver", confirmation=confirmation, acknowledgements=acks)
        lifecycle.approve(case.change, actor="approver", confirmation=case.change.change_id, acknowledgements=ACKS)
        case.change.refresh_from_db()
        wrong = lifecycle._execute(case.change, actor="operator", confirmation="CHG-0", env=environment(case.net), definition=D)
        self.assertEqual([b["code"] for b in wrong.blockers], ["CONFIRMATION_MISMATCH"])
        self.assertEqual(case.net.sent, [])

    def test_the_precheck_blocks_an_unexpected_pre_state_and_approval_is_refused(self):
        for mutate, code in (
                (lambda n: n.kernel["R4"].update({"2001:db8:30::/63": {"protocol": "static", "hops": [(R1LL, "Vlan102")]}}), gates.OUT_OF_BAND),
                (lambda n: n.paths["S1"].add("router isis NMAS > is-type level-2"), gates.OUT_OF_BAND),
                (lambda n: n.paths["R2"].discard("ipv6 route 2001:db8:20::/64 2001:db8:110:2::2"), gates.OLD_ROUTE_ABSENT),
                (lambda n: setattr(n, "answers", False), gates.NEXT_HOP_UNHEALTHY)):
            with self.subTest(code=code):
                net = Network()
                mutate(net)
                case = self.prepare(net, approve=False)
                self.assertEqual(case.precheck.status, "BLOCKED")
                self.assertIn(code, case.precheck.summary["blockers"])
                with self.assertRaises(lifecycle.LifecycleError):
                    lifecycle.approve(case.change, actor="approver", confirmation=case.change.change_id, acknowledgements=ACKS)
                self.assertEqual(net.sent, [])

    def test_unhealthy_probes_or_host_block_the_precheck(self):
        net, source = Network(), Probes()
        source.ok = False
        change = lifecycle.create_change(actor="operator")
        lifecycle.validate_change(change, actor="operator", inventory=DEVICES)
        lifecycle.build_plan(change, actor="operator")
        env = environment(net, probe_source=source)
        env.host_gate = lambda: (False, {"load1": 99.0})
        run = lifecycle.run_precheck(change, actor="operator", env=env)
        self.assertEqual(set(run.summary["blockers"]), {gates.PROBES_UNHEALTHY, gates.HOST_GATE})

    def test_a_device_that_changed_after_the_approved_precheck_blocks_before_any_write(self):
        case = self.prepare()
        case.net.paths["R1"].add("ipv6 route 2001:db8:99::/64 2001:db8:110:1::2")
        case.net.startup["R1"].add("ipv6 route 2001:db8:99::/64 2001:db8:110:1::2")          # changed and saved by someone else
        result = self.execute(case)
        self.assertEqual(result.outcome, "BLOCKED")
        self.assertEqual([b["code"] for b in result.blockers], [gates.BASELINE_STALE])
        self.assertEqual(case.net.sent, [])
        self.assertFalse(models.ExecutionDeviceLock.objects.exists())

    def test_the_service_entry_point_passes_the_readiness_gate_and_keeps_every_other_gate(self):
        self.assertEqual(readiness.READINESS[readiness.STATIC_IPV6_TO_ISIS], readiness.READY)
        case = self.prepare()
        for kw in ({"confirmation": "yes", "env": environment(case.net)}, {"confirmation": case.change.change_id, "env": None}):
            result = lifecycle.execute(case.change, actor="operator", **kw)
            self.assertEqual((result.outcome, [b["code"] for b in result.blockers]),
                             ("BLOCKED", ["CONFIRMATION_MISMATCH" if kw["env"] else "NO_PRODUCTION_ENVIRONMENT"]))
            self.assertEqual(case.net.sent, [])
        result = lifecycle.execute(case.change, actor="operator", confirmation=case.change.change_id, env=environment(case.net))
        self.assertEqual((result.outcome, result.blockers), ("SUCCEEDED", []), result.run.report.get("failure"))
        sandbox = migration.with_cabling(D, name="sandbox", access_interface="Ethernet3", core_hops={c: D.covers_of(c)[0].next_hops for c in D.cores})
        other = lifecycle.create_change(actor="operator", definition=sandbox)
        with self.assertRaises(lifecycle.LifecycleError):                    # only the production definition is ever accepted there
            lifecycle.execute(other, actor="operator", confirmation=other.change_id, env=environment(case.net))


# ------------------------------------------------------------------------------------------------- production wiring, operator
class ProductionWiringTests(TestCase):
    def test_the_six_managed_devices_get_the_right_executor(self):
        from core.services.route_shield import production

        devices = production.devices()
        self.assertEqual(sorted(devices), ["R1", "R2", "R3", "R4", "S1", "S2"])
        self.assertEqual({name: device["platform"] for name, device in devices.items()},
                         {"R1": "ceos", "R2": "ceos", "S1": "ceos", "S2": "ceos", "R3": "linux", "R4": "linux"})
        self.assertIsInstance(production.executor_for(devices["R3"]), KernelCoverExecutor)
        self.assertIsInstance(production.executor_for(devices["R4"]), KernelCoverExecutor)
        self.assertIsInstance(production.executor_for(devices["R1"]), CeosExecutor)

    def test_every_client_host_is_probed_in_each_family_it_has(self):
        from core.services.route_shield import production

        addresses = {"H1": ["192.168.10.102", "2001:db8:10::2001"], "H4": ["2001:db8:30::104"]}
        flows = production.flows(lambda container: addresses.get(container.rsplit("-", 1)[-1], []))
        forward = {(flow.label, flow.destination) for flow in flows if not flow.source}
        self.assertEqual(forward, {(f"h{n}-service-v6", production.SERVICE_V6) for n in (1, 2, 3, 4)} | {(f"h{n}-service-v4", production.SERVICE_V4) for n in (1, 2, 3)})
        back = sorted((flow.destination, flow.source) for flow in flows if flow.source)
        self.assertEqual(back, [("192.168.10.102", production.SERVICE_V4), ("2001:db8:10::2001", production.SERVICE_V6), ("2001:db8:30::104", production.SERVICE_V6)])
        self.assertTrue(all(flow.container.endswith(("-H1", "-H2", "-H3", "-H4", "-WebServer")) for flow in flows))

    def test_the_operator_command_walks_the_lifecycle_and_execute_is_held_by_the_approval_gates_only(self):
        from io import StringIO
        from unittest import mock

        from django.core.management import CommandError, call_command

        def run(*args):
            out = StringIO()
            call_command("nmas_isis_migration", *args, stdout=out)
            return json.loads(out.getvalue())

        with mock.patch("core.services.route_shield.production.environment", side_effect=AssertionError("no device or probe may be touched")):
            change_id = run("create", "--actor", "operator")["change"]
            self.assertEqual(run("validate", "--change", change_id, "--actor", "operator")["validation"], "PASS")
            plan = run("plan", "--change", change_id, "--actor", "operator")
            self.assertEqual((plan["operations"], len(plan["temporary"])), (48, 24))
            with self.assertRaises(CommandError):                      # no precheck yet: nothing can be approved
                run("approve", "--change", change_id, "--actor", "approver", "--confirm", change_id, *(x for name in ACKS for x in ("--ack", name)))
        net, stopped = Network(), Probes()
        stopped.stop = lambda: None
        with mock.patch("core.services.route_shield.production.environment", return_value=environment(net, probe_source=stopped)), \
                mock.patch("core.services.route_shield.production.start_probes"), mock.patch("time.sleep"):
            refused = run("execute", "--change", change_id, "--actor", "operator", "--confirm", change_id)
        codes = {b["code"] for b in refused["blockers"]}                # past the readiness gate, held by the unapproved Change
        self.assertEqual((refused["outcome"], codes >= {"NOT_APPROVED", "PRECHECK_NOT_PASSED"}), ("BLOCKED", True))
        self.assertFalse([code for code in codes if code.startswith("TRANSITION_")])
        self.assertEqual(net.sent, [])
        with mock.patch("core.services.route_shield.production.environment", side_effect=AssertionError("no device or probe may be touched")):
            shown = run("show", "--change", change_id)
            self.assertEqual((shown["readiness"], shown["runs"][0]["outcome"], len(shown["operations"])), ("READY", "BLOCKED", 48))
            with self.assertRaises(CommandError):
                run("show", "--change", "CHG-19000101-0001")


class ChangePagesTests(TestCase):
    """A transition Change is an ordinary record: every existing Change page renders it, and none of them can execute it."""

    def test_the_existing_pages_show_the_transition_and_the_execute_page_is_blocked(self):
        from django.urls import reverse

        from core.tests.runner import OperatorClient

        case = LifecycleTests.prepare(self)
        result = LifecycleTests.execute(self, case)
        self.assertEqual(result.outcome, "SUCCEEDED")
        sent = list(case.net.sent)
        client, change_id, run_id = OperatorClient(), case.change.change_id, str(result.run.run_id)
        pages = [("device_builder_change_detail", ()), ("change_plan", ()), ("change_plan_detail", (str(case.plan.plan_id),)), ("change_precheck", ()),
                 ("change_precheck_detail", (str(case.precheck.run_id),)), ("change_execute", ()), ("change_executions", ()),
                 ("change_execution_detail", (run_id,)), ("change_execution_report", (run_id,))]
        for name, extra in pages:
            with self.subTest(page=name):
                response = client.get(reverse(f"core:{name}", args=[change_id, *extra]))
                self.assertEqual(response.status_code, 200, name)
        report = json.loads(client.get(reverse("core:change_execution_report", args=[change_id, run_id])).content)
        self.assertEqual(report["outcome"], "SUCCEEDED")
        self.assertEqual(report["report"]["temporary_state"]["remaining"], [])
        runs = models.ChangeExecutionRun.objects.count()
        response = client.post(reverse("core:change_execute_run", args=[change_id]), {"confirm_mode": "COMPLETE"})
        self.assertIn(response.status_code, (200, 302, 400, 403, 409))
        blocked = models.ChangeExecutionRun.objects.order_by("-id").first()
        self.assertTrue(models.ChangeExecutionRun.objects.count() == runs or blocked.outcome == "BLOCKED")
        self.assertEqual(case.net.sent, sent)                                  # the web surface sent nothing to any device
