"""The route-shield workflow: validation, planning, every fail-closed gate, abort-and-restore, and the service gate.

The fake device keeps a set of configuration lines and derives its routing table from them the way cEOS 4.36.2F did in
the disposable sandbox: the lowest distance wins, IS-IS is 115, a floating static (250) is configured but not installed.
"""

from __future__ import annotations

import ipaddress
from unittest import mock

from django.test import SimpleTestCase
from django.utils import timezone

from core.services import route_shield
from core.services.execution.executors.base import APPLY, REFUSE, SKIP_SATISFIED, ApplyOutcome, Assessment, CompensationOutcome
from core.services.execution.executors.ceos import CONFIG_BLOCK_TYPES, config_inverse
from core.services.health.evidence import DeviceEvidence, FactGroup
from core.services.route_shield import gates, lab, model, readiness, runner

S1, R1 = lab.SWITCHES["S1"], lab.ROUTERS["R1"]
S1_BASE = {"ipv6 route ::/0 3fff:172:20:20::1", f"ipv6 route {lab.AGGREGATE} {S1.router_v6}", "interface Ethernet1 > isis metric 10"}
R1_BASE = {"ipv6 route ::/0 3fff:172:20:20::1", *(f"ipv6 route {p} {R1.switch_v6}" for p in lab.CLIENTS),
           "route-map STATIC6-TO-OSPF permit 10", "route-map STATIC6-TO-OSPF permit 10 > match ipv6 address prefix-list CLIENT-V6",
           "ipv6 router ospf 10 > redistribute static route-map STATIC6-TO-OSPF"}


class FakeDevice:
    def __init__(self, name, lines, connected, *, isis=None, adjacencies=(), install_shield=True):
        self.name, self.lines, self.connected = name, set(lines), dict(connected)
        self.isis = dict(isis or {})                 # prefix -> interface: what IS-IS holds, installed only when it wins
        self.adjacencies = set(adjacencies)
        self.sent: list[list[str]] = []
        self.on_apply = None                         # hook(spec) run right after a Configlet was applied
        self.install_shield = install_shield

    def _interface(self, hop):
        address = ipaddress.ip_address(hop)
        return next((name for prefix, name in self.connected.items() if address in ipaddress.ip_network(prefix)), "")

    def routes(self):
        best = {prefix: (0, "connected", name, "") for prefix, name in self.connected.items()}
        for prefix, name in self.isis.items():
            best[prefix] = (115, "isisL2", name, "fe80::1")
        for line in self.lines:
            if not line.startswith("ipv6 route "):
                continue
            parts = line.split()
            prefix, hop, distance = parts[2], parts[3], int(parts[4]) if len(parts) > 4 else 1
            if not self.install_shield and ipaddress.ip_network(prefix).prefixlen in (33, 63):
                continue
            if prefix not in best or distance < best[prefix][0]:
                best[prefix] = (distance, "static", self._interface(hop), hop)
        return sorted(({"prefix": str(ipaddress.ip_network(p)), "type": kind, "interfaces": [name] if name else [], "next_hops": [hop] if hop else []}
                       for p, (_d, kind, name, hop) in best.items()), key=lambda r: r["prefix"])

    def evidence(self):
        group = lambda data: FactGroup(data=data, source="LIVE", observed_at=timezone.now())  # noqa: E731
        interfaces = {name: {"admin": "UP", "oper": "UP"} for name in set(self.connected.values()) | {"Ethernet1", "Ethernet2", "Vlan99"}}
        isis = [{"instance": "NMAS", "system_id": "x", "hostname": "x", "interface": name, "level": "L2", "state": "UP"} for name in sorted(self.adjacencies)]
        return DeviceEvidence(device=self.name, platform="ceos", live_attempted=True,
                              groups={"routes": group(self.routes()), "interfaces": group(interfaces), "isis": group(isis)})


class FakeExecutor:
    """The executor contract over a FakeDevice: additive lines, intentional removals, exact inverse."""

    def __init__(self, device):
        self.d = device

    @staticmethod
    def _paths(lines):
        paths, header = [], ""
        for line in lines:
            if line.startswith(" "):
                paths.append(f"{header} > {line.strip()}")
            else:
                header = line
                if line.startswith(("ipv6 route ", "route-map ", "ipv6 prefix-list ")):
                    paths.append(line)
        return paths

    def config_state_digest(self):
        return "|".join(sorted(self.d.lines))

    def assess(self, spec):
        if spec.origin == "REMOVAL":
            wanted = list(spec.removal["absent_paths"])
            found = [p for p in wanted if p in self.d.lines]
            if not found:
                return Assessment(SKIP_SATISFIED, True)
            return Assessment(APPLY, True) if len(found) == len(wanted) else Assessment(REFUSE, False, {}, "REMOVAL_TARGET_DRIFTED")
        missing = [p for p in self._paths(spec.lines) if p not in self.d.lines]
        return Assessment(APPLY, True, {"missing": missing}) if missing else Assessment(SKIP_SATISFIED, True)

    def apply(self, spec, assessment):
        self.d.sent.append(list(spec.lines))
        if spec.origin == "REMOVAL":
            gone = set(spec.removal["absent_paths"])                       # removing a block removes what is under it
            self.d.lines = {line for line in self.d.lines if line not in gone and not any(line.startswith(f"{path} > ") for path in gone)}
        else:
            for path in self._paths(spec.lines):
                if " > isis metric " in path:
                    self.d.lines = {line for line in self.d.lines if not line.startswith(path.rsplit(" ", 1)[0])}
                self.d.lines.add(path)
        if self.d.on_apply:
            self.d.on_apply(spec)
        return ApplyOutcome(True, lines_sent=len(spec.lines))

    def compensate(self, spec, assessment):
        if spec.origin == "REMOVAL":
            self.d.lines |= set(self._paths(spec.removal["restore_lines"])) | {p for p in spec.removal["absent_paths"]}
        else:
            self.d.lines -= set(assessment.previous_state.get("missing", []))
            if any(" > isis metric " in p for p in assessment.previous_state.get("missing", [])):
                self.d.lines.add("interface Ethernet1 > isis metric 10")
        return CompensationOutcome("COMPENSATED")


class Probes:
    def __init__(self):
        self.ok, self.count = True, 0

    def healthy(self):
        return self.ok, "all production flows answer"

    def lost(self):
        return self.count


def switch(**kw):
    return FakeDevice("S1", S1_BASE, {"2001:db8:110:1::/64": "Ethernet1", "2001:db8:110:3::/64": "Vlan99", "3fff:172:20:20::/64": "Management0"},
                      isis={}, adjacencies={"Ethernet1", "Vlan99"}, **kw)


def router():
    return FakeDevice("R1", R1_BASE, {"2001:db8:110:1::/64": "Ethernet2", "3fff:172:20:20::/64": "Management0"}, adjacencies={"Ethernet2"})


def environment(device, **overrides):
    probes = Probes()
    executor = FakeExecutor(device)
    env = runner.Environment(
        executors={device.name: executor}, read=lambda name: device.evidence(), probes=probes, host_gate=lambda: (True, {"load1": 5.0}),
        next_hop_alive=lambda name, hop: True, new_route_available=lambda t: True, resolve_takeover=lambda name, t: True,
        upstream_covered=lambda t: True, peer_forwards_onward=lambda t: True,
        baseline_digests={device.name: executor.config_state_digest()}, sleep=lambda s: None, poll_seconds=0,
        clock=lambda ticks=iter(range(0, 10**9, 25)): next(ticks))             # every look at the clock is 25 s later: no real waiting
    for key, value in overrides.items():
        setattr(env, key, value)
    return env, probes


def isis_takes_over(device, prefixes, interface):
    """IS-IS holds the prefixes all along; the fake installs them as soon as no better static remains."""
    device.isis.update({p: interface for p in prefixes})


def run(transition, device, **overrides):
    env, probes = environment(device, **overrides)
    return runner._execute(transition, env), probes


class ValidationTests(SimpleTestCase):
    def build(self, **changes):
        base = dict(key="t", kind=readiness.STATIC_IPV6_TO_ISIS, device="S1", protected=(lab.AGGREGATE,), old=model.Owner("static", "Ethernet1", S1.router_v6),
                    new=model.Owner("isis", "Ethernet1"), shield_kind=model.MORE_SPECIFIC, shield_prefixes=("2001:db8::/33", "2001:db8:8000::/33"),
                    shield_next_hop=S1.router_v6, shield_interface="Ethernet1", steps=(model.Step("x", ("no y",), ("y",), ("y",)),))
        return model.Transition(**{**base, **changes})

    def test_the_proven_shapes_build(self):
        self.build()
        for t in (*lab.baseline_migration("S1"), *lab.baseline_rollback("S2"), lab.steer(S1, drain=True), lab.steer(S1, drain=False)):
            self.assertTrue(t.shield_lines())

    def test_a_cover_longer_than_64_is_refused(self):
        with self.assertRaisesMessage(model.ShieldError, "longer than /64"):
            self.build(protected=("2001:db8:10::/64",), shield_prefixes=("2001:db8:10::/65", "2001:db8:10:0:8000::/65"))

    def test_the_management_interface_can_never_be_a_path(self):
        for change in ({"shield_interface": "Management0"}, {"new": model.Owner("isis", "Management0")}):
            with self.assertRaisesMessage(model.ShieldError, "management"):
                self.build(**change)

    def test_a_pair_must_be_exactly_the_two_halves_and_a_cover_exactly_one_shorter_prefix(self):
        with self.assertRaises(model.ShieldError):
            self.build(shield_prefixes=("2001:db8::/33",))
        with self.assertRaises(model.ShieldError):
            self.build(shield_prefixes=("2001:db8::/33", "2001:db8:8000::/33", "2001:db9::/32"))
        with self.assertRaises(model.ShieldError):
            self.build(shield_kind=model.LESS_SPECIFIC, protected=("2001:db8:10::/64",), shield_prefixes=("2001:db8:20::/63",))
        with self.assertRaises(model.ShieldError):
            self.build(shield_next_hop="fe80::1")

    def test_floating_and_shield_statements_are_undone_from_the_running_configuration(self):
        self.assertIn(model.SHIELD_OBJECT, CONFIG_BLOCK_TYPES)
        running = "ipv6 route 2001:db8:10::/64 2001:db8:110:1::2\nipv6 route ::/0 3fff:172:20:20::1\n"
        floating = "ipv6 route 2001:db8:10::/64 2001:db8:110:1::2 250"
        self.assertEqual(config_inverse([floating], running), [f"no {floating}"])          # not mistaken for the installed route
        self.assertEqual(config_inverse(list(lab.router_to_isis(R1).shield_lines()), running),
                         [f"no {line}" for line in reversed(lab.router_to_isis(R1).shield_lines())])


class PlanTests(SimpleTestCase):
    def test_the_router_static_is_removed_behind_a_floating_copy(self):
        labels = [step.label for step in lab.router_to_isis(R1).steps]
        self.assertEqual(labels, ["floating-add", "static-remove", "floating-remove", "old-redistribution-remove"])
        remove = lab.router_to_isis(R1).steps[1]
        self.assertTrue(remove.wait_new_owner)
        self.assertEqual(remove.lines[0], "no ipv6 route 2001:db8:10::/64 2001:db8:110:1::2 1")   # distance 1 only: the copy stays

    def test_the_shield_points_at_the_path_that_is_about_to_carry_the_traffic(self):
        self.assertEqual({lab.steer(S1, drain=True).shield_next_hop, lab.steer(S1, drain=False).shield_next_hop}, {S1.far_switch_v6, S1.router_v6})
        self.assertEqual(lab.steer(S1, drain=True).shield_interface, "Vlan99")
        self.assertEqual(lab.router_to_isis(R1).shield_prefixes, ("2001:db8:10::/63", "2001:db8:20::/63", "2001:db8:30::/63"))

    def test_forward_is_switch_then_router_and_rollback_is_the_reverse(self):
        self.assertEqual([t.device for t in lab.baseline_migration("S2")], ["S2", "R2"])
        self.assertEqual([t.device for t in lab.baseline_rollback("S2")], ["R2", "S2"])


class RunTests(SimpleTestCase):
    def test_a_switch_transition_runs_every_stage_in_order_and_leaves_no_shield(self):
        device, transition = switch(), lab.switch_to_isis(S1)
        isis_takes_over(device, [lab.AGGREGATE], "Ethernet1")
        result, _ = run(transition, device)
        self.assertTrue(result.ok, result.stages[-1])
        self.assertEqual([s["stage"] for s in result.stages],
                         ["precheck", "shield-install", "shield-verify", "transition", "transition-verify", "shield-remove", "final-verify"])
        self.assertEqual(device.sent[0], list(transition.shield_lines()))                       # the shield is the first thing sent
        self.assertEqual(device.sent[-1], [f"no {line}" for line in transition.shield_lines()])  # and the last thing removed
        self.assertFalse(any(line in device.lines for line in lab.temporary_lines(transition)))
        self.assertNotIn(f"ipv6 route {lab.AGGREGATE} {S1.router_v6}", device.lines)

    def test_a_router_transition_leaves_neither_cover_nor_floating_routes(self):
        device, transition = router(), lab.router_to_isis(R1)
        isis_takes_over(device, lab.CLIENTS, "Ethernet2")
        result, _ = run(transition, device)
        self.assertTrue(result.ok, result.stages[-1])
        self.assertEqual(device.lines, {"ipv6 route ::/0 3fff:172:20:20::1"})
        self.assertEqual(len(lab.temporary_lines(transition)), 6)       # 3 covers, 3 floating copies

    def test_forward_then_rollback_restores_the_original_configuration(self):
        device = router()
        isis_takes_over(device, lab.CLIENTS, "Ethernet2")
        self.assertTrue(run(lab.router_to_isis(R1), device)[0].ok)
        result, _ = run(lab.router_to_static(R1), device)
        self.assertTrue(result.ok, result.stages[-1])
        self.assertEqual(device.lines, R1_BASE)

    def test_a_drain_and_its_restore(self):
        device = switch()
        device.lines.discard(f"ipv6 route {lab.AGGREGATE} {S1.router_v6}")
        device.isis[lab.AGGREGATE] = "Ethernet1"
        device.on_apply = lambda spec: device.isis.update({lab.AGGREGATE: "Vlan99" if "isis metric 1000" in " ".join(spec.lines) else
                                                           "Ethernet1" if "isis metric 10" in " ".join(spec.lines) else device.isis[lab.AGGREGATE]})
        before = set(device.lines)
        self.assertTrue(run(lab.steer(S1, drain=True), device)[0].ok)
        self.assertIn("interface Ethernet1 > isis metric 1000", device.lines)
        self.assertTrue(run(lab.steer(S1, drain=False), device)[0].ok)
        self.assertEqual(device.lines, before)


class FailClosedTests(SimpleTestCase):
    def refused(self, device=None, transition=None, **overrides):
        device = device or switch()
        if lab.AGGREGATE not in device.isis and device.name == "S1":
            isis_takes_over(device, [lab.AGGREGATE], "Ethernet1")
        result, _ = run(transition or lab.switch_to_isis(S1), device, **overrides)
        self.assertFalse(result.ok)
        self.assertEqual(device.sent, [], "a refused transition must not send a single line")
        return result.aborted, [b["code"] for b in result.blockers]

    def test_expected_old_route_absent(self):
        device = switch()
        device.lines.discard(f"ipv6 route {lab.AGGREGATE} {S1.router_v6}")
        self.assertIn(gates.OLD_ROUTE_ABSENT, self.refused(device, baseline_digests={"S1": FakeExecutor(device).config_state_digest()})[1])

    def test_expected_new_path_unavailable(self):
        device = switch()
        device.adjacencies.discard("Ethernet1")
        self.assertIn(gates.NEW_PATH_UNAVAILABLE, self.refused(device)[1])
        self.assertIn(gates.NEW_PATH_UNAVAILABLE, self.refused(new_route_available=lambda t: False)[1])
        self.assertIn(gates.NEW_PATH_UNAVAILABLE, self.refused(new_route_available=None)[1])

    def test_a_drain_toward_a_switch_that_would_send_the_traffic_back_is_refused(self):
        self.assertEqual((lab.steer(S1, drain=True).via_peer, lab.steer(S1, drain=False).via_peer), ("S2", ""))
        for unproven in ({"peer_forwards_onward": lambda t: False}, {"peer_forwards_onward": None}):
            device = switch()
            device.lines.discard(f"ipv6 route {lab.AGGREGATE} {S1.router_v6}")
            device.isis[lab.AGGREGATE] = "Ethernet1"
            result, _ = run(lab.steer(S1, drain=True), device, **unproven)
            self.assertEqual(result.aborted, gates.NEW_PATH_UNAVAILABLE)
            self.assertEqual(device.sent, [])

    def test_a_router_transition_is_refused_unless_every_core_router_shows_its_cover(self):
        self.assertEqual((lab.router_to_isis(R1).upstream, lab.router_to_static(R1).upstream, lab.switch_to_isis(S1).upstream), (("R3", "R4"),) * 2 + ((),))
        for unproven in ({"upstream_covered": lambda t: False}, {"upstream_covered": None}):
            device = router()
            isis_takes_over(device, lab.CLIENTS, "Ethernet2")
            result, _ = run(lab.router_to_isis(R1), device, **unproven)
            self.assertEqual(result.aborted, gates.UPSTREAM_COVER_UNCONFIRMED)
            self.assertEqual(device.sent, [])

    def test_the_core_cover_is_a_kernel_route_toward_both_boundary_routers(self):
        cover = lab.CORE_COVERS["R3"]
        hops = [("fe80::1", "Vlan101"), ("fe80::2", "Vlan103")]
        self.assertEqual(cover.install(hops)[0], "ip -6 route add 2001:db8:10::/63 nexthop via fe80::1 dev Vlan101 nexthop via fe80::2 dev Vlan103")
        self.assertEqual(cover.remove()[0], "ip -6 route del 2001:db8:10::/63")
        with self.assertRaises(ValueError):
            cover.install(hops[:1])                         # one boundary router only: the cover would follow a router being changed
        self.assertEqual(set(lab.CORE_COVERS), set(R1.upstream))

    def test_alternate_next_hop_unhealthy(self):
        self.assertIn(gates.NEXT_HOP_UNHEALTHY, self.refused(next_hop_alive=lambda name, hop: False)[1])
        self.assertIn(gates.NEXT_HOP_UNHEALTHY, self.refused(next_hop_alive=None)[1])
        device = switch()
        device.connected.pop("2001:db8:110:1::/64")
        self.assertIn(gates.NEXT_HOP_UNHEALTHY, self.refused(device)[1])

    def test_route_classification_unknown(self):
        device = switch()
        with mock.patch.object(FakeDevice, "routes", lambda self: [{"prefix": lab.AGGREGATE, "type": "gribi", "interfaces": ["Ethernet1"], "next_hops": []},
                                                                 {"prefix": "2001:db8:110:1::/64", "type": "connected", "interfaces": ["Ethernet1"], "next_hops": []}]):
            self.assertIn(gates.CLASSIFICATION_UNKNOWN, self.refused(device)[1])

    def test_a_cover_that_would_catch_a_foreign_route_is_refused(self):
        device = router()
        device.connected["2001:db8:10:1::/64"] = "Ethernet2"          # the other half of the /63 cover is in use
        isis_takes_over(device, lab.CLIENTS, "Ethernet2")
        self.assertIn(gates.CLASSIFICATION_UNKNOWN, self.refused(device, lab.router_to_isis(R1))[1])

    def test_production_probes_unhealthy_before_start(self):
        probes = Probes()
        probes.ok = False
        self.assertEqual(self.refused(probes=probes)[0], gates.PROBES_UNHEALTHY)
        self.assertEqual(self.refused(probes=None)[0], gates.PROBES_UNHEALTHY)

    def test_management_route_would_become_the_forwarding_fallback(self):
        device = switch()
        device.connected = {"2001:db8:110:1::/64": "Management0"}
        self.assertIn(gates.MANAGEMENT_FALLBACK, self.refused(device)[1])

    def test_config_baseline_stale(self):
        self.assertEqual(self.refused(baseline_digests={"S1": "another digest"})[0], gates.BASELINE_STALE)
        self.assertEqual(self.refused(baseline_digests={})[0], gates.BASELINE_STALE)

    def test_host_resource_gate(self):
        self.assertEqual(self.refused(host_gate=lambda: (False, {"load1": 60.0}))[0], gates.HOST_GATE)
        self.assertEqual(self.refused(host_gate=None)[0], gates.HOST_GATE)

    def test_a_leftover_shield_route_is_an_out_of_band_change(self):
        device = switch()
        device.lines.add(f"ipv6 route 2001:db8::/33 {S1.router_v6}")
        self.assertIn(gates.OUT_OF_BAND, self.refused(device)[1])

    def test_unreadable_evidence_is_never_a_pass(self):
        self.assertIn(gates.EVIDENCE_UNAVAILABLE, [b["code"] for b in gates.precheck(lab.switch_to_isis(S1), DeviceEvidence(device="S1"))])


class AbortTests(SimpleTestCase):
    def aborted(self, device, transition, **overrides):
        baseline = set(device.lines)
        result, _ = run(transition, device, **overrides)
        self.assertFalse(result.ok)
        self.assertTrue(result.restored, result.stages[-1])
        self.assertEqual(device.lines, baseline, "the original configuration must be back")
        self.assertEqual(result.stages[-1]["stage"], "restore")
        return result

    def test_a_shield_that_cannot_be_confirmed_stops_before_the_change(self):
        device = switch(install_shield=False)
        isis_takes_over(device, [lab.AGGREGATE], "Ethernet1")
        result = self.aborted(device, lab.switch_to_isis(S1))
        self.assertEqual(result.aborted, gates.SHIELD_UNCONFIRMED)
        self.assertEqual(len(device.sent), 1)                       # only the shield was ever sent; the static was never touched

    def test_any_lost_production_probe_during_the_change_aborts_and_restores(self):
        device, transition = router(), lab.router_to_isis(R1)
        isis_takes_over(device, lab.CLIENTS, "Ethernet2")
        env, probes = environment(device)
        device.on_apply = lambda spec: setattr(probes, "count", probes.count + (1 if "static-remove" in spec.cfg_id else 0))
        result = self.aborted(device, transition, probes=probes)
        self.assertEqual(result.aborted, gates.PACKET_LOSS)
        self.assertEqual([row["status"] for row in result.compensation], ["COMPENSATED"] * 3)   # the change first, the shield last
        self.assertTrue(result.compensation[-1]["cfg_id"].endswith("shield-install"))
        self.assertEqual(result.probes_lost, 1)
        self.assertEqual(result.stages[-2]["stage"], "abort")                                    # the evidence is kept

    def test_an_out_of_band_change_between_two_steps_aborts(self):
        device, transition = router(), lab.router_to_isis(R1)
        isis_takes_over(device, lab.CLIENTS, "Ethernet2")
        env, probes = environment(device)
        sent_before = []

        def lost():                                   # somebody else changes the device right after the floating copies went in
            if any("250" in line for lines in device.sent for line in lines) and not sent_before:
                sent_before.append(len(device.sent))
                device.lines.add("ipv6 route 2001:db8:99::/64 2001:db8:110:1::2")
            return 0

        probes.lost = lost
        result, _ = run(transition, device, probes=probes)
        self.assertEqual(result.aborted, gates.OUT_OF_BAND)
        self.assertFalse(any("no ipv6 route 2001:db8:10::/64" in line and line.endswith(" 1") for lines in device.sent for line in lines),
                         "the protected route must not be touched after an out-of-band change")
        self.assertFalse(result.restored)            # the device is not what it was: restoring cannot be claimed, and is not

    def test_a_new_owner_that_never_takes_over_is_rolled_back(self):
        device = switch()                             # IS-IS never offers the aggregate
        result = self.aborted(device, lab.switch_to_isis(S1))
        self.assertEqual(result.aborted, "TRANSITION_NOT_VERIFIED")
        self.assertIn(f"ipv6 route {lab.AGGREGATE} {S1.router_v6}", device.lines)

    def test_an_unresolved_take_over_next_hop_keeps_the_shield_and_restores(self):
        device = switch()
        isis_takes_over(device, [lab.AGGREGATE], "Ethernet1")
        self.assertEqual(self.aborted(device, lab.switch_to_isis(S1), resolve_takeover=lambda name, t: False).aborted, gates.NEW_PATH_UNAVAILABLE)


class ServiceGateTests(SimpleTestCase):
    def test_only_the_baseline_migration_is_ready_and_a_refused_transition_reads_and_sends_nothing(self):
        self.assertEqual(readiness.READINESS, {readiness.STATIC_IPV6_TO_ISIS: readiness.READY,
                                               readiness.ISIS_TO_STATIC_IPV6_REVERT: readiness.NOT_AUTHORIZED,
                                               readiness.ISIS_METRIC_STEER: readiness.NOT_AUTHORIZED,
                                               readiness.OSPFV3_EXTERNAL_METRIC_STEER: readiness.NOT_READY})
        self.assertEqual(readiness.refusal(readiness.OSPFV3_EXTERNAL_METRIC_STEER), "TRANSITION_NOT_READY: OSPFV3_EXTERNAL_METRIC_STEER")
        self.assertEqual(readiness.refusal(readiness.STATIC_IPV6_TO_ISIS), "")
        self.assertEqual(readiness.refusal(readiness.ISIS_TO_STATIC_IPV6_REVERT), "TRANSITION_PROVEN_NOT_AUTHORIZED: ISIS_TO_STATIC_IPV6_REVERT")
        self.assertEqual(readiness.refusal(readiness.ISIS_METRIC_STEER), "TRANSITION_PROVEN_NOT_AUTHORIZED: ISIS_METRIC_STEER")
        for transition in (lab.steer(S1, drain=True), lab.steer(S1, drain=False)):
            device = switch()
            env, _ = environment(device, read=mock.Mock(side_effect=AssertionError("a refused transition must not read a device")))
            result = route_shield.execute(transition, env)
            self.assertFalse(result.ok)
            self.assertTrue(result.aborted.startswith("TRANSITION_"), result.aborted)
            self.assertEqual(device.sent, [])

    def test_an_unknown_kind_is_never_executable(self):
        self.assertTrue(readiness.refusal("SOMETHING_NEW").startswith("TRANSITION_NOT_READY"))
        self.assertTrue(readiness.refusal(""))

    def test_the_host_gate_reads_real_host_facts(self):
        ok, facts = gates.default_host_gate(max_load_per_cpu=1e9, min_available_mb=0, max_swap_used_mb=10**9)
        self.assertTrue(ok)
        self.assertEqual(gates.default_host_gate(max_load_per_cpu=0.0)[0], False)
        self.assertIn("load1", facts)
