"""The lab's shielded transitions: R1/R2 boundary routers, S1/S2 access switches.  Pure: names and addresses in, Transitions out.

Exactly the configuration proven on the disposable sandbox (docs/V2_LOSSLESS_ROUTE_SHIELD.md):

* switch aggregate ``2001:db8::/32``   shield = its two /33 halves toward the path that is about to carry the traffic;
* router client /64s                    shield = one /63 under each, toward the router's own switch; the static routes are
                                        removed behind a floating copy (distance 250) so the router's OSPFv3 external LSAs are
                                        not withdrawn at that moment;
* core routers R3/R4 (FRR)              replace a client /64 by delete-then-add in the kernel, their forwarding plane, with
                                        only a management default behind it, whenever a boundary router re-originates an
                                        external LSA.  They hold kernel /63 covers toward R1 and R2 for the whole migration
                                        window (``CORE_COVERS``); a router transition is refused unless every core shows them.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass

from . import readiness
from .model import ISIS, LESS_SPECIFIC, MORE_SPECIFIC, STATIC, Owner, Step, Transition

AGGREGATE = "2001:db8::/32"
CLIENTS = ("2001:db8:10::/64", "2001:db8:20::/64", "2001:db8:30::/64")
OLD_MAP, CLIENT_LIST = "STATIC6-TO-OSPF", "CLIENT-V6"
FLOATING_DISTANCE = 250
CORES = ("R3", "R4")
METRIC, DRAIN_METRIC = 10, 1000


@dataclass(frozen=True)
class Router:
    name: str
    access_interface: str            # toward its switch
    switch_v6: str                   # the switch's address on that link
    ospfv3_process: int = 10
    upstream: tuple[str, ...] = CORES


@dataclass(frozen=True)
class Switch:
    name: str
    uplink: str
    router_v6: str                   # its router's address on the uplink
    transit: str                     # the VLAN99 SVI
    far_switch_v6: str               # the OTHER switch's address on VLAN99
    far_switch: str = ""             # and its name


ROUTERS = {"R1": Router("R1", "Ethernet2", "2001:db8:110:1::2"), "R2": Router("R2", "Ethernet2", "2001:db8:110:2::2")}
SWITCHES = {"S1": Switch("S1", "Ethernet1", "2001:db8:110:1::1", "Vlan99", "2001:db8:110:3::2", "S2"),
            "S2": Switch("S2", "Ethernet1", "2001:db8:110:2::1", "Vlan99", "2001:db8:110:3::1", "S1")}


def _halves(prefix: str) -> tuple[str, ...]:
    return tuple(str(n) for n in ipaddress.ip_network(prefix).subnets(prefixlen_diff=1))


def _cover(prefix: str) -> str:
    return str(ipaddress.ip_network(prefix).supernet(prefixlen_diff=1))


def _route(prefix: str, hop: str, distance: int | None = None) -> str:
    return f"ipv6 route {prefix} {hop}" + (f" {distance}" if distance else "")


def switch_to_isis(s: Switch) -> Transition:
    """Baseline migration, switch side: the static aggregate gives way to the IS-IS aggregate over the same uplink."""
    old = _route(AGGREGATE, s.router_v6)
    return Transition(f"{s.name}-aggregate-static-to-isis", readiness.STATIC_IPV6_TO_ISIS, s.name, (AGGREGATE,),
                      Owner(STATIC, s.uplink, s.router_v6), Owner(ISIS, s.uplink), MORE_SPECIFIC, _halves(AGGREGATE), s.router_v6, s.uplink,
                      (Step("static-remove", (f"no {old}",), (old,), (old,)),))


def switch_to_static(s: Switch) -> Transition:
    """Rollback of ``switch_to_isis``."""
    return Transition(f"{s.name}-aggregate-isis-to-static", readiness.STATIC_IPV6_TO_ISIS, s.name, (AGGREGATE,),
                      Owner(ISIS, s.uplink), Owner(STATIC, s.uplink, s.router_v6), MORE_SPECIFIC, _halves(AGGREGATE), s.router_v6, s.uplink,
                      (Step("static-restore", (_route(AGGREGATE, s.router_v6),)),))


def _old_redistribution(r: Router) -> tuple[tuple[str, ...], tuple[str, ...], tuple[str, ...]]:
    header, child, policy = f"ipv6 router ospf {r.ospfv3_process}", f"redistribute static route-map {OLD_MAP}", f"route-map {OLD_MAP} permit 10"
    add = (policy, f"   match ipv6 address prefix-list {CLIENT_LIST}", header, f"   {child}")
    return add, (header, f"   no {child}", f"no {policy}"), (f"{header} > {child}", policy)


def router_to_isis(r: Router) -> Transition:
    """Baseline migration, router side: the three client statics give way to the IS-IS routes learned from the switch."""
    statics = tuple(_route(p, r.switch_v6) for p in CLIENTS)
    floating = tuple(_route(p, r.switch_v6, FLOATING_DISTANCE) for p in CLIENTS)
    add, remove, paths = _old_redistribution(r)
    steps = (
        Step("floating-add", floating),
        Step("static-remove", tuple(f"no {line} 1" for line in statics), statics, statics, wait_new_owner=True),
        Step("floating-remove", tuple(f"no {line}" for line in floating), floating, floating),
        Step("old-redistribution-remove", remove, paths, add),
    )
    return Transition(f"{r.name}-clients-static-to-isis", readiness.STATIC_IPV6_TO_ISIS, r.name, CLIENTS,
                      Owner(STATIC, r.access_interface, r.switch_v6), Owner(ISIS, r.access_interface), LESS_SPECIFIC,
                      tuple(_cover(p) for p in CLIENTS), r.switch_v6, r.access_interface, steps, upstream=r.upstream)


def router_to_static(r: Router) -> Transition:
    """Rollback of ``router_to_isis``."""
    add, _remove, _paths = _old_redistribution(r)
    steps = (Step("old-redistribution-restore", add), Step("static-restore", tuple(_route(p, r.switch_v6) for p in CLIENTS)))
    return Transition(f"{r.name}-clients-isis-to-static", readiness.STATIC_IPV6_TO_ISIS, r.name, CLIENTS,
                      Owner(ISIS, r.access_interface), Owner(STATIC, r.access_interface, r.switch_v6), LESS_SPECIFIC,
                      tuple(_cover(p) for p in CLIENTS), r.switch_v6, r.access_interface, steps, upstream=r.upstream)


@dataclass(frozen=True)
class CoreCover:
    """The temporary kernel routes one core router holds for the whole migration window (not FRR configuration).
    Each cover uses the next hops the core's own client /64 is installed with at that moment: both boundary routers."""

    core: str
    prefixes: tuple[str, ...]

    def install(self, next_hops) -> tuple[str, ...]:
        """``next_hops``: the (address, interface) pairs read from the core's installed client route; exactly two."""
        if len(next_hops) != 2:
            raise ValueError(f"{self.core}: a cover needs both boundary routers as next hops, got {len(next_hops)}")
        hops = " ".join(f"nexthop via {address} dev {interface}" for address, interface in next_hops)
        return tuple(f"ip -6 route add {p} {hops}" for p in self.prefixes)

    def remove(self) -> tuple[str, ...]:
        return tuple(f"ip -6 route del {p}" for p in self.prefixes)


CORE_COVERS = {core: CoreCover(core, tuple(_cover(p) for p in CLIENTS)) for core in CORES}
CORE_QUIET_SECONDS = 120             # a core must have left every client /64 alone this long before its cover may go


def steer(s: Switch, *, drain: bool) -> Transition:
    """Planned maintenance of the router behind ``s``: move the aggregate between the uplink and the VLAN99 transit by
    the IS-IS metric of the uplink.  The shield points at the path that is about to carry the traffic."""
    uplink, transit = Owner(ISIS, s.uplink), Owner(ISIS, s.transit)
    metric = Step("uplink-metric", (f"interface {s.uplink}", f"   isis metric {DRAIN_METRIC if drain else METRIC}"), object_type="routing_binding")
    old, new, hop, interface = (uplink, transit, s.far_switch_v6, s.transit) if drain else (transit, uplink, s.router_v6, s.uplink)
    return Transition(f"{s.name}-aggregate-{'drain' if drain else 'restore'}", readiness.ISIS_METRIC_STEER, s.name, (AGGREGATE,),
                      old, new, MORE_SPECIFIC, _halves(AGGREGATE), hop, interface, (metric,), via_peer=s.far_switch if drain else "")


def baseline_migration(side: str, *, routers=None, switches=None) -> list[Transition]:
    """Forward order for one side (``S1`` or ``S2``): the switch first, then its router."""
    switches, routers = switches or SWITCHES, routers or ROUTERS
    s = switches[side]
    return [switch_to_isis(s), router_to_isis(routers[side.replace("S", "R")])]


def baseline_rollback(side: str, *, routers=None, switches=None) -> list[Transition]:
    switches, routers = switches or SWITCHES, routers or ROUTERS
    return [router_to_static(routers[side.replace("S", "R")]), switch_to_static(switches[side])]


def temporary_lines(transition: Transition) -> tuple[str, ...]:
    """Every migration-only line a transition may leave behind if it is interrupted: none may be in a permanent baseline."""
    floating = tuple(line for step in transition.steps for line in step.lines if line.startswith("ipv6 route ") and line.endswith(f" {FLOATING_DISTANCE}"))
    return (*transition.shield_lines(), *floating)
