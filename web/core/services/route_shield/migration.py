"""The baseline static-IPv6 to IS-IS migration as ONE ordered list of operations across S1, S2, R1, R2, R3 and R4.

Exactly the sequence proven by the 20 forward + 20 rollback sandbox run (docs/V2_LOSSLESS_ROUTE_SHIELD.md, section 3
and run ``proof20kc``): the same statements, in the same order, with the same waits.  Nothing here selects a device or
opens a connection: a ``Definition`` in, ``Operation`` rows out.

Every operation is either PERMANENT intent (it is part of the final desired configuration, or removes something the
final configuration no longer has) or TEMPORARY transition state (a shield, a floating static, a core cover): installed
by one operation, removed by a later one, recorded in the execution evidence and never part of the final state.

The reverse path is not a second list.  It is this list undone from the failure point backwards, each operation by its
own exact inverse, which is the proven rollback order: shields back first, statics back under them, shields away, the
additive IS-IS stages last, the core covers at the very end.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field, replace
from functools import partial

from ..bundles import canonical
from ..config_workbench.structure import parse
from . import checks, lab
from . import core_cover
from .core_cover import CoverRoute

PERMANENT, TEMPORARY = "PERMANENT", "TEMPORARY"
ADD, REMOVE, COVER_INSTALL, COVER_REMOVE = "ADD", "REMOVE", "COVER_INSTALL", "COVER_REMOVE"
KIND = "BASELINE_STATIC_IPV6_TO_ISIS"
REVERT_KIND = "REVERT_COMPLETED_BASELINE_MIGRATION"      # operator-initiated, after a SUCCEEDED migration (never automatic)
KINDS = (KIND, REVERT_KIND)
PLANNER_VERSION = "route-shield-1"

PRECHECK, CORE_COVER_INSTALL, VLAN99_IPV6, ISIS_FORMATION, BOUNDARY_POLICY = "PRECHECK", "CORE_COVER_INSTALL", "VLAN99_IPV6", "ISIS_FORMATION", "BOUNDARY_POLICY"
SHIELD_INSTALL, STATIC_REMOVAL, SHIELD_REMOVE, CORE_COVER_REMOVE, FINAL_VALIDATION = "SHIELD_INSTALL", "PROTECTED_STATIC_REMOVAL", "SHIELD_REMOVE", "CORE_COVER_REMOVE", "FINAL_VALIDATION"
PERSISTENCE = "PERSISTENCE"              # after the final validation: startup configuration of R1, R2, S1, S2 (never R3/R4)
STAGES = (PRECHECK, CORE_COVER_INSTALL, VLAN99_IPV6, ISIS_FORMATION, BOUNDARY_POLICY, SHIELD_INSTALL, STATIC_REMOVAL, SHIELD_REMOVE,
          CORE_COVER_REMOVE, FINAL_VALIDATION, PERSISTENCE)

ISIS_INSTANCE = "NMAS"
SVIS = ("Vlan10", "Vlan20", "Vlan30")
AGG_LIST, TO_OSPF, TO_ISIS = "ACCESS6-NORTHBOUND-AGG", "ISIS6-TO-OSPF3", "STATIC6-TO-ISIS6"
EXTERNAL_DISTANCE = 130


@dataclass(frozen=True)
class Check:
    """One named observation.  ``run(env) -> (ok, detail)``; polled until it holds or ``timeout`` seconds have passed."""

    label: str
    run: object = field(compare=False, repr=False)
    timeout: float = 0.0


@dataclass(frozen=True)
class Operation:
    key: str
    stage: str
    device: str
    state: str                               # PERMANENT or TEMPORARY
    action: str                              # ADD, REMOVE, COVER_INSTALL, COVER_REMOVE
    lines: tuple[str, ...]
    inverse: tuple[str, ...] = ()            # ADD: the statements that undo it; REMOVE: the statements that restore it
    cover: CoverRoute | None = None
    description: str = ""
    before: tuple[Check, ...] = ()           # must hold before the operation is sent
    after: tuple[Check, ...] = ()            # must hold after it (settled), before the next operation
    pause: float = 0.0                       # then wait this long (the proven sequence's own settling pauses)
    undo_before: tuple[Check, ...] = ()      # must hold before the operation is UNDONE during compensation
    undo_after: tuple[Check, ...] = ()
    undo_pause: float = 0.0

    @property
    def paths(self) -> tuple[str, ...]:
        """The leaf statements that prove an ADD is configured (or, for a REMOVE, the ones that must be gone)."""
        text = "\n".join(self.lines if self.action == ADD else self.inverse)
        return tuple(sorted(node.path() for node in parse(text).by_number.values() if not node.children and not node.terminator))

    def canonical(self) -> dict:
        return {"key": self.key, "stage": self.stage, "device": self.device, "state": self.state, "action": self.action, "lines": list(self.lines),
                "inverse": list(self.inverse), "cover": self.cover.to_expected() if self.cover else None,
                "before": [c.label for c in self.before], "after": [c.label for c in self.after], "pause": self.pause,
                "undo_before": [c.label for c in self.undo_before], "undo_after": [c.label for c in self.undo_after], "undo_pause": self.undo_pause}


@dataclass(frozen=True)
class Definition:
    """The lab facts one migration is built from.  ``PRODUCTION`` is the only definition the service entry point accepts."""

    name: str
    routers: dict                            # name -> lab.Router
    switches: dict                           # name -> lab.Switch
    nets: dict                               # device -> IS-IS NET
    anchors: dict                            # router -> the three next hops of its static 2001:db8::/32 anchor
    transit_v6: dict                         # switch -> its VLAN99 IPv6 address with length
    covers: tuple[CoverRoute, ...]
    service: str = "2001:db8:3050::10"
    sides: tuple[tuple[str, str], ...] = (("S1", "R1"), ("S2", "R2"))
    core_management: tuple[str, ...] = ("eth0",)      # never a cover next hop; the precheck also reads it from the default route
    core_quiet_seconds: float = float(lab.CORE_QUIET_SECONDS)
    settle_seconds: float = 5.0

    @property
    def cores(self) -> tuple[str, ...]:
        return tuple(dict.fromkeys(cover.core for cover in self.covers))

    @property
    def access_devices(self) -> tuple[str, ...]:
        return (*self.routers, *self.switches)

    @property
    def devices(self) -> tuple[str, ...]:
        return (*self.switches, *self.routers, *self.cores)

    def covers_of(self, core: str) -> list[CoverRoute]:
        return [cover for cover in self.covers if cover.core == core]


_covers = core_cover.covers_for


# Production values, read from the running devices (read-only) and the tracked configuration.  The cover next hops are the
# boundary routers' link-local addresses on the core-facing VLANs: R3 reaches R1 on Vlan101 and R2 on Vlan103, R4 reaches
# R1 on Vlan102 and R2 on Vlan104.  The precheck refuses the migration if a core's installed client /64 does not use
# exactly these next hops.
PRODUCTION = Definition(
    name="production",
    routers=dict(lab.ROUTERS), switches=dict(lab.SWITCHES),
    nets={"R1": "49.0110.1921.6825.5001.00", "R2": "49.0110.1921.6825.5002.00", "S1": "49.0110.1921.6825.5011.00", "S2": "49.0110.1921.6825.5012.00"},
    anchors={"R1": ("2001:db8:100:103::2", "2001:db8:100:104::2", "2001:db8:3050::10"),
             "R2": ("2001:db8:100:101::2", "2001:db8:100:102::2", "2001:db8:3050::10")},
    transit_v6={"S1": "2001:db8:110:3::1/64", "S2": "2001:db8:110:3::2/64"},
    covers=core_cover.APPROVED_COVERS,              # the locked inventory: core_cover.py
)


def with_cabling(definition: Definition, *, name: str, access_interface: str, core_hops: dict, core_management: tuple = ()) -> Definition:
    """The same migration on differently cabled devices (the disposable sandbox): only interface names and the cores'
    measured next hops differ.  Prefixes, statements and order are untouched."""
    routers = {key: replace(router, access_interface=access_interface) for key, router in definition.routers.items()}
    return replace(definition, name=name, routers=routers, covers=_covers(core_hops), core_management=tuple(core_management))


# ---------------------------------------------------------------------------------------------------------------- building
def _no(lines) -> tuple[str, ...]:
    return tuple(f"no {line}" for line in lines)


def _host(prefix: str) -> str:
    return str(ipaddress.ip_network(prefix).network_address + 0x100)


def _half_of(address: str) -> str:
    return next(half for half in lab._halves(lab.AGGREGATE) if ipaddress.ip_address(address) in ipaddress.ip_network(half))


def forward_operations(d: Definition) -> list[Operation]:
    ops: list[Operation] = []
    agg, clients = lab.AGGREGATE, lab.CLIENTS

    def add(key, stage, device, state, lines, inverse, **more):
        ops.append(Operation(key, stage, device, state, ADD, tuple(lines), tuple(inverse), **more))

    def remove(key, stage, device, state, lines, restore, **more):
        ops.append(Operation(key, stage, device, state, REMOVE, tuple(lines), tuple(restore), **more))

    quiet = Check(f"cores left every client route alone for {d.core_quiet_seconds:.0f} s",
                  partial(checks.cores_quiet, cores=d.cores, prefixes=clients, seconds=d.core_quiet_seconds), d.core_quiet_seconds + 260)

    # -- the core covers go in before anything else changes ------------------------------------------------------------------
    for cover in d.covers:
        steady = (Check(f"{cover.core} OSPF adjacencies unchanged by the covers", partial(checks.core_adjacencies_unchanged, core=cover.core), 10),) \
            if cover is d.covers_of(cover.core)[-1] else ()
        ops.append(Operation(f"{cover.core}-cover-{cover.prefix}", CORE_COVER_INSTALL, cover.core, TEMPORARY, COVER_INSTALL, cover.lines(), cover.removal_lines(),
                             cover, f"temporary kernel cover of {cover.protects}",
                             after=(Check(f"{cover.core} {cover.prefix} is the approved cover and forwards", partial(checks.cover_installed, cover=cover), 10), *steady),
                             undo_before=(quiet,), undo_after=(Check(f"{cover.core} {cover.prefix} is gone", partial(checks.cover_absent, cover=cover), 10),)))

    # -- additive stages: nothing is replaced -------------------------------------------------------------------------------
    for s in d.switches.values():
        address = d.transit_v6[s.name]
        add(f"{s.name}-vlan99-ipv6", VLAN99_IPV6, s.name, PERMANENT, [f"interface {s.transit}", f"   ipv6 address {address}"],
            [f"interface {s.transit}", f"   no ipv6 address {address}"], description="VLAN99 IPv6 transit address")
    for name in d.access_devices:
        add(f"{name}-isis-process", ISIS_FORMATION, name, PERMANENT,
            [f"router isis {ISIS_INSTANCE}", f"   net {d.nets[name]}", "   is-type level-2", "   address-family ipv6 unicast"],
            [f"no router isis {ISIS_INSTANCE}"], description="IS-IS Level-2 process")
    enable, disable = (f"   isis enable {ISIS_INSTANCE}", f"   isis metric {lab.METRIC}"), ("   no isis metric", "   no isis enable")
    for r in d.routers.values():
        add(f"{r.name}-isis-access", ISIS_FORMATION, r.name, PERMANENT, [f"interface {r.access_interface}", *enable],
            [f"interface {r.access_interface}", *disable], description="IS-IS on the access link")
    adjacencies = tuple(Check(f"{name} IS-IS adjacency up on {', '.join(interfaces)}", partial(checks.adjacencies_up, device=name, interfaces=interfaces), 120)
                        for name, interfaces in (*((r.name, (r.access_interface,)) for r in d.routers.values()),
                                                 *((s.name, (s.uplink, s.transit)) for s in d.switches.values())))
    last = list(d.switches)[-1]
    for s in d.switches.values():
        add(f"{s.name}-isis-links", ISIS_FORMATION, s.name, PERMANENT, [f"interface {s.uplink}", *enable, f"interface {s.transit}", *enable],
            [f"interface {s.uplink}", *disable, f"interface {s.transit}", *disable], description="IS-IS on the uplink and VLAN99",
            after=adjacencies if s.name == last else ())
    for s in d.switches.values():
        add(f"{s.name}-client-svis-passive", BOUNDARY_POLICY, s.name, PERMANENT,
            [line for svi in SVIS for line in (f"interface {svi}", f"   isis enable {ISIS_INSTANCE}", "   isis passive")],
            [line for svi in SVIS for line in (f"interface {svi}", "   no isis passive", "   no isis enable")], description="client SVIs passive in IS-IS")
    available = []
    for s_name, r_name in d.sides:
        s, r = d.switches[s_name], d.routers[r_name]
        available += [
            Check(f"{s_name} IS-IS database holds {agg}", partial(checks.database_holds, device=s_name, prefixes=(agg,)), 90),
            Check(f"{r_name} IS-IS database holds the client prefixes", partial(checks.database_holds, device=r_name, prefixes=clients), 90),
            Check(f"{s_name} static still owns {agg}", partial(checks.owned, device=s_name, prefix=agg, source="static", interface=s.uplink), 90),
            *(Check(f"{r_name} static still owns {p}", partial(checks.owned, device=r_name, prefix=p, source="static", interface=r.access_interface), 90)
              for p in clients)]
    last_router = list(d.routers)[-1]
    for r in d.routers.values():
        anchors = [f"ipv6 route {agg} {hop}" for hop in d.anchors[r.name]]
        add(f"{r.name}-boundary-policy", BOUNDARY_POLICY, r.name, PERMANENT,
            [f"ipv6 prefix-list {AGG_LIST}", f"   seq 10 permit {agg}", f"route-map {TO_OSPF} permit 10", f"   match ipv6 address prefix-list {lab.CLIENT_LIST}",
             f"route-map {TO_ISIS} permit 10", f"   match ipv6 address prefix-list {AGG_LIST}", *anchors],
            [*_no(anchors), f"no route-map {TO_ISIS} permit 10", f"no route-map {TO_OSPF} permit 10", f"no ipv6 prefix-list {AGG_LIST}"],
            description="northbound policy and the multi-anchor aggregate",
            after=(Check(f"{r.name} holds {agg} as a static route", partial(checks.owned, device=r.name, prefix=agg, source="static", interface=""), 30),))
        add(f"{r.name}-aggregate-into-isis", BOUNDARY_POLICY, r.name, PERMANENT,
            [f"router isis {ISIS_INSTANCE}", "   address-family ipv6 unicast", f"      redistribute static route-map {TO_ISIS}"],
            [f"router isis {ISIS_INSTANCE}", "   address-family ipv6 unicast", f"      no redistribute static route-map {TO_ISIS}"],
            description="aggregate advertised into IS-IS")
        header = f"ipv6 router ospf {r.ospfv3_process}"
        add(f"{r.name}-isis-into-ospfv3", BOUNDARY_POLICY, r.name, PERMANENT,
            [header, f"   distance ospf external {EXTERNAL_DISTANCE}", f"   redistribute isis level-2 route-map {TO_OSPF}"],
            [header, f"   no redistribute isis level-2 route-map {TO_OSPF}", f"   no distance ospf external {EXTERNAL_DISTANCE}"],
            description="client prefixes from IS-IS into OSPFv3", after=tuple(available) if r.name == last_router else (),
            pause=3.0 if r.name == last_router else 0.0)

    # -- the protected switchover, one side at a time ------------------------------------------------------------------------
    for s_name, r_name in d.sides:
        s, r = d.switches[s_name], d.routers[r_name]
        s_shield = [f"ipv6 route {half} {s.router_v6}" for half in lab._halves(agg)]
        r_shield = [f"ipv6 route {lab._cover(p)} {r.switch_v6}" for p in clients]
        statics = [f"ipv6 route {p} {r.switch_v6}" for p in clients]
        floating = [f"{line} {lab.FLOATING_DISTANCE}" for line in statics]
        old_static = f"ipv6 route {agg} {s.router_v6}"
        restore_old, remove_old, _paths = lab._old_redistribution(r)

        def own(device, prefix, source, interface, timeout=60.0):
            return Check(f"{device} {prefix} owned by {source}" + (f" via {interface}" if interface else ""),
                         partial(checks.owned, device=device, prefix=prefix, source=source, interface=interface), timeout)

        s_static, s_isis = own(s_name, agg, "static", s.uplink), own(s_name, agg, "isis", s.uplink)
        r_static = tuple(own(r_name, p, "static", r.access_interface) for p in clients)
        r_isis = tuple(own(r_name, p, "isis", r.access_interface) for p in clients)
        s_shielded = tuple(Check(f"{s_name} shield {half} programmed via {s.uplink}",
                                 partial(checks.owned, device=s_name, prefix=half, source="static", interface=s.uplink, next_hop=s.router_v6), 20)
                           for half in lab._halves(agg))
        r_shielded = tuple(Check(f"{r_name} shield {lab._cover(p)} programmed via {r.access_interface}",
                                 partial(checks.owned, device=r_name, prefix=lab._cover(p), source="static", interface=r.access_interface, next_hop=r.switch_v6), 20)
                           for p in clients)
        s_unshielded = tuple(Check(f"{s_name} shield {half} gone", partial(checks.absent, device=s_name, prefix=half), 20) for half in lab._halves(agg))
        r_unshielded = tuple(Check(f"{r_name} shield {lab._cover(p)} gone", partial(checks.absent, device=r_name, prefix=lab._cover(p)), 20) for p in clients)
        s_alive = Check(f"{s_name} shield next hop {s.router_v6} answers", partial(checks.answers, device=s_name, address=s.router_v6), 10)
        r_alive = Check(f"{r_name} shield next hop {r.switch_v6} answers", partial(checks.answers, device=r_name, address=r.switch_v6), 10)
        s_takeover = Check(f"{s_name} take-over next hop of {agg} resolved", partial(checks.takeover_ready, device=s_name, prefixes=(agg,)), 20)
        r_takeover = Check(f"{r_name} take-over next hops of the client prefixes resolved", partial(checks.takeover_ready, device=r_name, prefixes=clients), 20)
        through_shield = (
            Check(f"{s_name} forwards the service through the shield", partial(checks.lookup, device=s_name, address=d.service, prefix=_half_of(d.service),
                                                                                source="static", interface=s.uplink), 10),
            *(Check(f"{r_name} forwards {_host(p)} toward its switch", partial(checks.lookup, device=r_name, address=_host(p), prefix=p, source="",
                                                                                  interface=r.access_interface), 10) for p in clients))
        final = (
            Check(f"{s_name} forwards the service by IS-IS", partial(checks.lookup, device=s_name, address=d.service, prefix=agg, source="isis", interface=s.uplink), 20),
            *(Check(f"{r_name} forwards {_host(p)} by IS-IS", partial(checks.lookup, device=r_name, address=_host(p), prefix=p, source="isis",
                                                                        interface=r.access_interface), 20) for p in clients))

        add(f"{s_name}-shield-install", SHIELD_INSTALL, s_name, TEMPORARY, s_shield, _no(s_shield), description="temporary /33 pair around the aggregate",
            before=(s_alive,), after=s_shielded, undo_before=(s_static, s_takeover), undo_after=s_unshielded, undo_pause=3.0)
        add(f"{r_name}-shield-install", SHIELD_INSTALL, r_name, TEMPORARY, r_shield, _no(r_shield), description="temporary /63 under each client prefix",
            before=(r_alive,), after=(*r_shielded, *through_shield), pause=3.0, undo_before=(*r_static, r_takeover), undo_after=r_unshielded)
        remove(f"{s_name}-static-aggregate-remove", STATIC_REMOVAL, s_name, PERMANENT, [f"no {old_static}"], [old_static],
               description="superseded static aggregate", undo_after=(s_static,), undo_pause=d.settle_seconds)
        add(f"{r_name}-floating-statics-add", STATIC_REMOVAL, r_name, TEMPORARY, floating, _no(floating), pause=2.0,
            description="floating copies keep the OSPFv3 external LSAs from being withdrawn")
        remove(f"{r_name}-client-statics-remove", STATIC_REMOVAL, r_name, PERMANENT, [f"no {line} 1" for line in statics], statics,
               description="superseded client static routes", after=r_isis, pause=2.0, undo_after=r_static)
        remove(f"{r_name}-floating-statics-remove", STATIC_REMOVAL, r_name, TEMPORARY, _no(floating), floating, after=(s_isis, *r_isis), pause=d.settle_seconds,
               description="floating copies removed once IS-IS owns the routes")
        remove(f"{r_name}-old-redistribution-remove", STATIC_REMOVAL, r_name, PERMANENT, remove_old, restore_old,
               description="superseded static-to-OSPFv3 redistribution", undo_pause=2.0)
        remove(f"{r_name}-shield-remove", SHIELD_REMOVE, r_name, TEMPORARY, _no(r_shield), r_shield, description="router shield removed",
               before=(r_takeover,), after=r_unshielded, undo_before=(r_alive,), undo_after=r_shielded, undo_pause=3.0)
        remove(f"{s_name}-shield-remove", SHIELD_REMOVE, s_name, TEMPORARY, _no(s_shield), s_shield, description="switch shield removed",
               before=(s_takeover,), after=(*s_unshielded, *final), pause=3.0, undo_before=(s_alive,), undo_after=s_shielded)

    # -- the core covers go last, and only once the cores are quiet ----------------------------------------------------------
    temporary = tuple(line for op in ops if op.state == TEMPORARY and op.action == ADD for line in op.lines)
    clean = Check("no temporary migration line on any access device", partial(checks.no_temporary_lines, devices=d.access_devices, lines=temporary), 0)
    for index, cover in enumerate(d.covers):
        ops.append(Operation(f"{cover.core}-cover-{cover.prefix}-remove", CORE_COVER_REMOVE, cover.core, TEMPORARY, COVER_REMOVE, cover.removal_lines(), cover.lines(),
                             cover, f"temporary kernel cover of {cover.protects} removed", before=(clean, quiet) if index == 0 else (),
                             after=(Check(f"{cover.core} {cover.prefix} is gone", partial(checks.cover_absent, cover=cover), 10),),
                             undo_after=(Check(f"{cover.core} {cover.prefix} is the approved cover again", partial(checks.cover_installed, cover=cover), 10),)))
    return ops


_INVERSE_ACTION = {ADD: REMOVE, REMOVE: ADD, COVER_INSTALL: COVER_REMOVE, COVER_REMOVE: COVER_INSTALL}


def revert_operations(d: Definition) -> list[Operation]:
    """REVERT COMPLETED BASELINE MIGRATION: the forward list walked backwards, every operation replaced by its exact
    inverse, gated by that operation's own undo gates.  This is the order the automatic reverse path takes when a
    migration fails after its last step (covers in first, shields back, statics restored under them, shields away, IS-IS
    removed, covers out last); here it is a plan of its own, validated, prechecked and approved like the migration."""
    forward = forward_operations(d)
    ops = [replace(op, key=f"revert-{op.key}", action=_INVERSE_ACTION[op.action], lines=op.inverse, inverse=op.lines,
                   description=f"revert: {op.description or op.key}", before=op.undo_before, after=op.undo_after, pause=op.undo_pause,
                   undo_before=op.before, undo_after=op.after, undo_pause=op.pause)
           for op in reversed(forward)]
    temporary = tuple(line for op in ops if op.state == TEMPORARY and op.action == ADD for line in op.lines)
    clean = Check("no temporary migration line on any access device", partial(checks.no_temporary_lines, devices=d.access_devices, lines=temporary), 0)
    steady = tuple(Check(f"{core} OSPF adjacencies unchanged by the covers", partial(checks.core_adjacencies_unchanged, core=core), 10) for core in d.cores)
    last_install = max(i for i, op in enumerate(ops) if op.action == COVER_INSTALL)
    first_removal = min(i for i, op in enumerate(ops) if op.action == COVER_REMOVE)
    ops[last_install] = replace(ops[last_install], after=(*ops[last_install].after, *steady))
    ops[first_removal] = replace(ops[first_removal], before=(clean, *ops[first_removal].before))
    return ops


def operations(kind: str, d: Definition) -> list[Operation]:
    if kind == KIND:
        return forward_operations(d)
    if kind == REVERT_KIND:
        return revert_operations(d)
    raise ValueError(f"unknown transition kind {kind!r}")


def temporary_lines(ops) -> tuple[str, ...]:
    """Every migration-only statement of the plan: none may be configured once the transaction has finished."""
    return tuple(line for op in ops if op.state == TEMPORARY and op.action in (ADD, COVER_INSTALL) for line in op.lines)


def permanent_lines(ops) -> dict:
    """device -> the statements the final desired configuration gains (PERMANENT additions only)."""
    found: dict[str, list[str]] = {}
    for op in ops:
        if op.state == PERMANENT and op.action == ADD:
            found.setdefault(op.device, []).extend(op.lines)
    return found


def plan_hash(ops) -> str:
    return canonical.text_hash(canonical.canonical_json([op.canonical() for op in ops]))


def validate(d: Definition, ops) -> list[dict]:
    """Structural validation of the plan against the approved design.  Pure; every finding is a blocker."""
    found: list[dict] = []

    def block(code: str, detail: str) -> None:
        found.append({"code": code, "detail": detail})

    covers = [op for op in ops if op.action in (COVER_INSTALL, COVER_REMOVE)]
    expected = {(core, str(ipaddress.ip_network(p).supernet(new_prefix=63))) for core in ("R3", "R4") for p in lab.CLIENTS}
    for action in (COVER_INSTALL, COVER_REMOVE):
        if {(op.device, op.cover.prefix) for op in covers if op.action == action} != expected:
            block("COVER_INVENTORY_MISMATCH", f"{action}: the plan does not hold exactly the three /63 covers on each of R3 and R4")
    if any(op.device not in ("R3", "R4") or op.cover is None or op.cover.core != op.device for op in covers):
        block("COVER_INVENTORY_MISMATCH", "a cover operation targets something other than its own core router")
    if any(interface in d.core_management for op in covers if op.cover is not None for _address, interface in op.cover.next_hops):
        block("COVER_INVENTORY_MISMATCH", "a cover next hop is on a core router's management interface")
    if any(op.device in ("R3", "R4") and op.action not in (COVER_INSTALL, COVER_REMOVE) for op in ops):
        block("CORE_SCOPE_EXCEEDED", "a core router may only receive cover operations")
    if any(op.stage not in STAGES or op.state not in (PERMANENT, TEMPORARY) for op in ops):
        block("PLAN_MALFORMED", "an operation has an unknown stage or state")
    first_change = next((i for i, op in enumerate(ops) if op.action in (ADD, REMOVE)), len(ops))
    last_change = max((i for i, op in enumerate(ops) if op.action in (ADD, REMOVE)), default=-1)
    if any(i > first_change for i, op in enumerate(ops) if op.action == COVER_INSTALL) or any(i < last_change for i, op in enumerate(ops) if op.action == COVER_REMOVE):
        block("COVER_WINDOW_INCOMPLETE", "the covers must be installed before the first change and removed after the last")
    # every temporary statement is removed again, by exactly its own negation, later in the plan
    open_lines: dict[tuple[str, str], int] = {}
    taken_back = {(op.device, line) for op in ops if op.state == TEMPORARY and op.action in (REMOVE, COVER_REMOVE) for line in op.inverse}
    for index, op in enumerate(ops):
        if op.state != TEMPORARY:
            if op.action == ADD and any((op.device, line) in taken_back for line in op.lines):
                block("TEMPORARY_STATE_IN_INTENT", f"{op.key} adds as permanent intent a statement the plan removes again as temporary")
            continue
        if op.action in (ADD, COVER_INSTALL):
            for line in op.lines:
                open_lines[(op.device, line)] = index
        else:
            for line in op.inverse:
                if open_lines.pop((op.device, line), None) is None:
                    block("TEMPORARY_STATE_UNBALANCED", f"{op.key} removes {line!r}, which the plan never installed")
    for (device, line), index in open_lines.items():
        block("TEMPORARY_STATE_UNBALANCED", f"{device}: {line!r} (operation {ops[index].key}) is never removed")
    for op in ops:
        if op.action in (ADD, REMOVE) and (not op.lines or not op.inverse or not op.paths):
            block("COMPENSATION_NOT_PROVABLE", f"{op.key} has no exact inverse")
    if d.name == PRODUCTION.name and (len(d.covers) != len(core_cover.APPROVED_COVERS) or not all(core_cover.is_approved(c) for c in d.covers)):
        block("COVER_INVENTORY_MISMATCH", "the production covers are not exactly the approved inventory")
    if set(d.devices) != {"S1", "S2", "R1", "R2", "R3", "R4"}:
        block("SCOPE_MISMATCH", "the migration spans exactly S1, S2, R1, R2, R3 and R4")
    return found
