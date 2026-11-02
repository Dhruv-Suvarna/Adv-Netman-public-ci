"""The IPv6 maintenance drain of a boundary router and its exact reverse, as ordered operations.

Both directions, with the existing protocols and the existing routed paths only:

    northbound   the IS-IS metric of the switch's uplink toward the router (``route_shield.lab.steer``), under the proven
                 /33 shield pointing at the path that is about to carry the traffic;
    southbound   the metric of the router's own OSPFv3 external routes (``set metric`` in the existing
                 IS-IS-to-OSPFv3 route map), so that the cores stop choosing it.

Nothing here writes to a core router (R3/R4).  The temporary kernel covers of ``route_shield.core_cover`` were a guard of
the static-to-IS-IS migration only, removed when it completed; they are not part of the topology, and a maintenance must
not install them to manufacture a lossless southbound drain.  Without them the cores replace their client routes when the
external metric changes (FRR 8.4.4 deletes and adds an IPv6 kernel route), which is why the southbound mechanism is
``NOT_READY`` in ``route_shield.readiness`` until the real sandbox proves it loss-free as it is.  The cores are read
through a read-only session (``executor.CoreReader``); the final check proves they hold nothing they did not hold before.

Make-before-break: the router keeps forwarding in both directions until the traffic has left it; nothing is shut.
The operations reuse ``route_shield.migration.Operation`` / ``Check`` and the gate observations of
``route_shield.checks``; the statements of the northbound step are the ones ``lab.steer`` builds.  ``capture`` reads the
exact pre-maintenance state the restore later has to reproduce.  Pure apart from ``capture`` and the check functions,
which read through the run's own executor sessions.
"""

from __future__ import annotations

import re
from functools import partial

from ..config_workbench.structure import config_paths, parse
from ..execution.executors.base import ExecutorError
from ..route_shield import checks, core_cover, lab
from ..route_shield.migration import ADD, REMOVE, TEMPORARY, TO_OSPF, Check, Operation
from . import model, topology

MAINTENANCE = "MAINTENANCE"                      # a statement that exists only while the device is in maintenance
NORTH, SOUTH = "NORTHBOUND", "SOUTHBOUND"
EXTERNAL_DRAIN_METRIC = 10000                    # OSPFv3 external metric of the drained router; the other router keeps its own
ROUTE_MAP = f"route-map {TO_OSPF} permit 10"
_METRIC = re.compile(r"^isis metric (\d+)$")


def _config(env, device: str) -> dict:
    """header -> child lines of the running configuration of ``device`` (top-level blocks only)."""
    blocks, header = {}, None
    for line in env.executors[device].show("show running-config").splitlines():
        if not line.strip() or line.lstrip().startswith("!"):
            continue
        if not line.startswith(" "):
            header = line.rstrip()
            blocks.setdefault(header, [])
        elif header is not None:
            blocks[header].append(line.strip())
    return blocks


def installed_hops(executor) -> frozenset:
    """The (address, interface) next hops a core forwards EVERY client prefix to, read from its routing table now; empty
    when the prefixes do not share one set of next hops.  Topology as it is, not a tracked expectation."""
    found = set()
    for prefix in lab.CLIENTS:
        rows = executor.routes(prefix)
        found.add(frozenset(core_cover._row_hops(rows[0])) if len(rows) == 1 else frozenset())
    return next(iter(found)) if len(found) == 1 else frozenset()


def capture(env, access: topology.Access, definition) -> tuple[dict, list]:
    """The exact pre-maintenance state: -> (state, problems).  Read through the run's sessions; nothing is written.
    ``problems`` is why the state is not one this drain can be reversed from."""
    problems, state = [], {"access": access.as_dict(), "config": {}, "startup": {}, "cores": {}}
    tracked = definition.switches.get(access.switch)
    derived = lab.Switch(access.switch, access.uplink, access.router_v6, access.transit, access.far_switch_v6, access.far_switch)
    if tracked != derived or sorted(access.cores) != sorted(definition.cores):
        problems.append(f"TOPOLOGY_MISMATCH: the devices show {derived} and cores {access.cores}, the tracked design says {tracked} and {definition.cores}")
    try:
        for name in (access.switch, access.router, access.far_switch, access.peer_router):
            state["config"][name] = env.executors[name].config_state_digest()
            state["startup"][name] = env.executors[name].startup_state_digest()
        uplink = _config(env, access.switch).get(f"interface {access.uplink}", [])
        metrics = [int(m.group(1)) for m in map(_METRIC.match, uplink) if m]
        if len(metrics) != 1 or metrics[0] >= lab.DRAIN_METRIC:
            problems.append(f"PRE_STATE_NOT_BASELINE: {access.switch} {access.uplink} does not carry one normal IS-IS metric ({metrics})")
        state["uplink_metric"] = metrics[0] if metrics else None
        router = _config(env, access.router)
        route_map = router.get(ROUTE_MAP)
        if route_map is None or any(line.startswith("set metric") for line in route_map):
            problems.append(f"PRE_STATE_NOT_BASELINE: {access.router} {ROUTE_MAP} is missing or already sets a metric")
        if not any(f"route-map {TO_OSPF}" in line and line.startswith("redistribute isis") for lines in router.values() for line in lines):
            problems.append(f"PRE_STATE_NOT_BASELINE: {access.router} does not redistribute IS-IS into OSPFv3 through {TO_OSPF}")
        state["route_map"] = list(route_map or [])
        mine = {str(ip) for _i, ip, _n in topology._addresses({access.router: env.read(env.devices[access.router])}, access.router)}
        for core in definition.cores:
            executor, evidence = env.executors[core], env.read(env.devices[core])
            toward = {row["interface"] for row in evidence.facts("ospf") or [] if row.get("family") == "OSPFV3" and row.get("neighbor_id") in mine}
            hops = installed_hops(executor)
            target = sorted(hop for hop in hops if hop[1] in toward)
            if len(target) != 1 or len(hops) != 2:
                problems.append(f"TOPOLOGY_MISMATCH: {core} does not forward every client prefix to both boundary routers, one of them {access.router}")
            state["cores"][core] = {"static_routes": executor.static_route_digest(), "frr_config": executor.frr_config_digest(),
                                    "persistent_config": executor.persistent_config_digest(), "adjacencies": core_cover.adjacencies(evidence),
                                    "target_hop": list(target[0]) if len(target) == 1 else None}
    except ExecutorError as exc:
        problems.append(f"LIVE_EVIDENCE_UNAVAILABLE: {exc.code}")
    return state, problems


# ------------------------------------------------------------------------------------------------------------------ observations
def cores_route(env, *, cores: dict, prefixes, both: bool):
    """Every core forwards every client prefix to both boundary routers (``both``), or to the other router only.
    ``cores``: name -> the (address, interface) next hop that is the router under maintenance."""
    try:
        for core, target in cores.items():
            for prefix in prefixes:
                rows = env.executors[core].routes(prefix)
                hops = core_cover._row_hops(rows[0]) if len(rows) == 1 else ()
                fib = env.executors[core].client_route(prefix)
                if not fib["installed"] or fib["active_next_hops"] != (2 if both else 1) or len(hops) != (2 if both else 1) or (tuple(target) in hops) != both:
                    return False, f"{core}: {prefix} via {', '.join(interface for _a, interface in hops) or 'nothing'}"
    except ExecutorError as exc:
        return False, exc.code
    return True, "both boundary routers" if both else "the other boundary router only"


def router_healthy(env, *, access: topology.Access, cores):
    """The router may take traffic again: its access adjacency is up, it holds every client prefix by IS-IS toward its
    switch and the aggregate toward the core, and every core has a Full OSPFv3 adjacency with it."""
    ok, detail = checks.adjacencies_up(env, device=access.router, interfaces=(access.access_interface,))
    if not ok:
        return False, f"{access.router} IS-IS: {detail}"
    for prefix in lab.CLIENTS:
        ok, detail = checks.owned(env, device=access.router, prefix=prefix, source="isis", interface=access.access_interface)
        if not ok:
            return False, f"{access.router} {detail}"
    ok, detail = checks.owned(env, device=access.router, prefix=lab.AGGREGATE, source="static", interface="")
    if not ok:
        return False, f"{access.router} {detail}"
    try:
        for core, target in cores.items():
            if tuple(target) not in env.executors[core].full_neighbours():
                return False, f"{core} has no Full OSPFv3 adjacency with {access.router}"
    except ExecutorError as exc:
        return False, exc.code
    return True, "adjacencies up, client prefixes and aggregate held"


# ---------------------------------------------------------------------------------------------------------------------- operations
def _own(device, prefix, source, interface, timeout=60.0, next_hop=""):
    return Check(f"{device} {prefix} owned by {source} via {interface}",
                 partial(checks.owned, device=device, prefix=prefix, source=source, interface=interface, next_hop=next_hop), timeout)


def _north(access: topology.Access, definition, state: dict, *, drain: bool) -> list[Operation]:
    """The shielded metric steer of ``lab.steer``: shield toward the path about to carry the traffic, metric, shield away."""
    switch = lab.Switch(access.switch, access.uplink, access.router_v6, access.transit, access.far_switch_v6, access.far_switch)
    steer = lab.steer(switch, drain=drain)
    s, agg, shield = access.switch, lab.AGGREGATE, steer.shield_lines()
    old, new = steer.old.interface, steer.new.interface
    was, now = (state["uplink_metric"], lab.DRAIN_METRIC) if drain else (lab.DRAIN_METRIC, state["uplink_metric"])
    header = f"interface {access.uplink}"
    alive = Check(f"{s} shield next hop {steer.shield_next_hop} answers", partial(checks.answers, device=s, address=steer.shield_next_hop), 10)
    onward = Check(f"{access.far_switch} forwards the service through its own uplink",
                   partial(checks.lookup, device=access.far_switch, address=definition.service, prefix=agg, source="isis", interface=access.far_uplink), 10)
    shielded = tuple(_own(s, half, "static", new, 20, steer.shield_next_hop) for half in steer.shield_prefixes)
    unshielded = tuple(Check(f"{s} shield {half} gone", partial(checks.absent, device=s, prefix=half), 20) for half in steer.shield_prefixes)
    takeover = Check(f"{s} take-over next hop of {agg} resolved", partial(checks.takeover_ready, device=s, prefixes=(agg,)), 20)
    final = Check(f"{s} forwards the service by IS-IS via {new}", partial(checks.lookup, device=s, address=definition.service, prefix=agg, source="isis", interface=new), 20)
    tag, stage = ("drain" if drain else "restore"), NORTH
    return [
        Operation(f"{s}-shield-install-{tag}", stage, s, TEMPORARY, ADD, shield, tuple(f"no {line}" for line in shield), description="temporary /33 pair around the aggregate",
                  before=(alive, onward) if drain else (alive,), after=shielded, undo_before=(_own(s, agg, "isis", old), takeover), undo_after=unshielded, undo_pause=3.0),
        Operation(f"{s}-uplink-metric-{tag}", stage, s, MAINTENANCE, ADD, (header, f"   isis metric {now}"), (header, f"   isis metric {was}"),
                  description=f"IS-IS metric of the uplink toward {access.router}: {was} to {now}", after=(_own(s, agg, "isis", new),), pause=definition.settle_seconds,
                  undo_after=(_own(s, agg, "isis", old),), undo_pause=definition.settle_seconds),
        Operation(f"{s}-shield-remove-{tag}", stage, s, TEMPORARY, REMOVE, tuple(f"no {line}" for line in shield), shield, description="switch shield removed",
                  before=(takeover,), after=(*unshielded, final), pause=3.0, undo_before=(alive,), undo_after=shielded),
    ]


def _south(access: topology.Access, definition, state: dict, *, drain: bool) -> list[Operation]:
    r, targets = access.router, {core: tuple(row["target_hop"]) for core, row in state["cores"].items()}
    line = f"   set metric {EXTERNAL_DRAIN_METRIC}"
    away = Check(f"the cores forward the client prefixes to {access.peer_router} only", partial(cores_route, cores=targets, prefixes=lab.CLIENTS, both=False), 90)
    both = Check("the cores forward the client prefixes to both boundary routers", partial(cores_route, cores=targets, prefixes=lab.CLIENTS, both=True), 90)
    peer = tuple(_own(access.peer_router, prefix, "isis", access.peer_access_interface, 20) for prefix in lab.CLIENTS)
    if drain:
        return [Operation(f"{r}-external-metric-drain", SOUTH, r, MAINTENANCE, ADD, (ROUTE_MAP, line), (ROUTE_MAP, "   no set metric"),
                          description=f"OSPFv3 external metric of {r} raised to {EXTERNAL_DRAIN_METRIC}", before=peer, after=(away,), pause=definition.settle_seconds,
                          undo_after=(both,), undo_pause=definition.settle_seconds)]
    healthy = Check(f"{r} is healthy enough to take traffic", partial(router_healthy, access=access, cores=targets), 30)
    return [Operation(f"{r}-external-metric-restore", SOUTH, r, MAINTENANCE, REMOVE, (ROUTE_MAP, "   no set metric"), (ROUTE_MAP, line),
                      description=f"OSPFv3 external metric of {r} back to its own", before=(healthy,), after=(both,), pause=definition.settle_seconds,
                      undo_after=(away,), undo_pause=definition.settle_seconds)]


def maintenance_lines(access: topology.Access) -> tuple[str, ...]:
    """Every statement that exists only because the router is in maintenance."""
    return (f"interface {access.uplink}", f"   isis metric {lab.DRAIN_METRIC}", ROUTE_MAP, f"   set metric {EXTERNAL_DRAIN_METRIC}")


def shield_lines(access: topology.Access) -> tuple[str, ...]:
    """The temporary switch shields of both directions: an interrupted drain or restore may have left either in place."""
    switch = lab.Switch(access.switch, access.uplink, access.router_v6, access.transit, access.far_switch_v6, access.far_switch)
    return tuple(dict.fromkeys((*lab.steer(switch, drain=True).shield_lines(), *lab.steer(switch, drain=False).shield_lines())))


def drain_shield_lines(access: topology.Access) -> tuple[str, ...]:
    """The temporary shield the DRAIN installs (toward the other switch).  Present outside its own step only when a drain
    was interrupted inside its northbound stage: a state no restore operation was built for."""
    switch = lab.Switch(access.switch, access.uplink, access.router_v6, access.transit, access.far_switch_v6, access.far_switch)
    return lab.steer(switch, drain=True).shield_lines()


def temporary_lines(ops) -> tuple[str, ...]:
    return tuple(line for op in ops if op.state == TEMPORARY and op.action == ADD for line in op.lines)


def operations(access: topology.Access, definition, state: dict, cells, *, drain: bool) -> list[Operation]:
    """The ordered operations for the (family, direction) ``cells`` of the plan.  Entering: northbound, southbound.
    Restoring: southbound, northbound (the router is offered the southbound traffic only once it is verified healthy, and
    the northbound traffic after that).  Every operation writes to the switch or the router; none to a core."""
    cells = set(cells)
    north = _north(access, definition, state, drain=drain) if (model.IPV6, model.NORTHBOUND) in cells else []
    south = _south(access, definition, state, drain=drain) if (model.IPV6, model.SOUTHBOUND) in cells else []
    return [*north, *south] if drain else [*south, *north]


def present_lines(env, device: str, lines) -> list[str]:
    """Which of ``lines`` (header and child statements) are configured on ``device`` right now."""
    wanted = {node.path() for node in parse("\n".join(lines)).by_number.values() if not node.children and not node.terminator}
    return sorted(wanted & config_paths(env.executors[device].show("show running-config")))


# ---------------------------------------------------------------------------------------------------------------- final state
def cores_unchanged(env, *, state: dict):
    """No core holds a non-dynamic route it did not hold before (no cover, no static), and no FRR configuration changed."""
    try:
        for core, before in state["cores"].items():
            executor = env.executors[core]
            for name, read in (("static_routes", executor.static_route_digest), ("frr_config", executor.frr_config_digest),
                               ("persistent_config", executor.persistent_config_digest)):
                if read() != before[name]:
                    return False, f"{core}: {name} differs from the pre-maintenance state"
    except ExecutorError as exc:
        return False, exc.code
    return True, "unchanged"


def drained(env, *, access: topology.Access, cells):
    """Exactly the maintenance statements of the planned cells are configured, and nothing temporary."""
    lines = maintenance_lines(access)
    try:
        north, south = present_lines(env, access.switch, lines[:2]), present_lines(env, access.router, lines[2:])
        shields = present_lines(env, access.switch, shield_lines(access))
    except ExecutorError as exc:
        return False, exc.code
    if shields:
        return False, f"temporary shield still configured: {shields[0]}"
    wanted = (bool((model.IPV6, model.NORTHBOUND) in cells), bool((model.IPV6, model.SOUTHBOUND) in cells))
    return (bool(north), bool(south)) == wanted, f"northbound metric {'set' if north else 'not set'}, southbound metric {'set' if south else 'not set'}"


def restored_exactly(env, *, access: topology.Access, state: dict):
    """The captured pre-maintenance forwarding configuration is back: the switch is byte-for-byte the captured state, the
    router's route map and the switch's uplink metric are the captured ones, and no maintenance statement remains."""
    try:
        if env.executors[access.switch].config_state_digest() != state["config"][access.switch]:
            return False, f"{access.switch}: the running configuration is not the pre-maintenance one"
        if _config(env, access.router).get(ROUTE_MAP) != state["route_map"]:
            return False, f"{access.router}: {ROUTE_MAP} is not the pre-maintenance one"
        left = present_lines(env, access.switch, maintenance_lines(access)[:2]) + present_lines(env, access.router, maintenance_lines(access)[2:])
    except ExecutorError as exc:
        return False, exc.code
    return not left, f"still configured: {left[0]}" if left else "pre-maintenance state"


def final_checks(access: topology.Access, definition, state: dict, cells, *, drain: bool) -> tuple:
    cores = Check("the cores hold nothing they did not hold before", partial(cores_unchanged, state=state), 10)
    if drain:
        return (Check("exactly the planned maintenance statements are configured", partial(drained, access=access, cells=set(cells)), 10), cores)
    return (Check("the pre-maintenance forwarding configuration is restored exactly", partial(restored_exactly, access=access, state=state), 10), cores)
