"""The observations the migration is gated on.  Each takes the run's environment and returns ``(ok, detail)``.

Every read goes through the run's own executor session (``CeosExecutor.show`` / ``KernelCoverExecutor``): the same
devices, the same sessions, nothing a caller could substitute.  An unreadable device is a failed check, never a pass.
"""

from __future__ import annotations

import ipaddress
import json

from ..config_workbench.structure import config_paths
from ..execution.executors.base import ExecutorError
from ..health import live

_SOURCES = {"static": ("static",), "isis": ("isisl2", "isisl1", "isis"), "": ()}


def _is_management(name: str) -> bool:
    return str(name).lower().startswith(("management", "ma"))


def _find(value, key):
    if isinstance(value, dict):
        if key in value:
            return value[key]
        for child in value.values():
            hit = _find(child, key)
            if hit is not None:
                return hit
    return None


def route(env, device: str, target: str):
    """The route EOS selects for ``target`` (a prefix: that exact route; an address: the longest match), or None.
    -> {"prefix", "type", "interfaces", "next_hops", "programmed"}"""
    try:
        data = json.loads(env.executors[device].show(f"show ipv6 route {target} | json") or "{}")
    except (ValueError, ExecutorError):
        return None
    routes = _find(data, "routes") or {}
    if "/" in target:
        wanted = str(ipaddress.ip_network(target))
        routes = {prefix: entry for prefix, entry in routes.items() if str(ipaddress.ip_network(prefix)) == wanted}
    for prefix, entry in routes.items():
        vias = entry.get("vias") or []
        return {"prefix": str(ipaddress.ip_network(prefix)), "type": str(entry.get("routeType", "")),
                "interfaces": sorted({str(v.get("interface", "")) for v in vias}),
                "next_hops": sorted({str(ipaddress.ip_address(v["nexthopAddr"])) for v in vias if v.get("nexthopAddr")}),
                "vias": [(str(v.get("nexthopAddr", "")), str(v.get("interface", ""))) for v in vias],
                "programmed": bool(entry.get("hardwareProgrammed")) and bool(entry.get("kernelProgrammed"))}
    return None


def owned(env, *, device: str, prefix: str, source: str, interface: str, next_hop: str = ""):
    """``prefix`` is installed by ``source`` (through ``interface`` and ``next_hop`` when given), programmed, never via management."""
    found = route(env, device, prefix)
    if found is None:
        return False, f"{prefix}: no route"
    ok = found["type"].lower() in _SOURCES[source] and found["programmed"] and not any(_is_management(i) for i in found["interfaces"]) \
        and (not interface or found["interfaces"] == [interface]) and (not next_hop or str(ipaddress.ip_address(next_hop)) in found["next_hops"])
    return ok, f"{prefix}: {found['type']} via {','.join(found['interfaces'])} programmed={found['programmed']}"


def absent(env, *, device: str, prefix: str):
    found = route(env, device, prefix)
    return found is None, f"{prefix}: {'absent' if found is None else found['type']}"


def lookup(env, *, device: str, address: str, prefix: str, source: str, interface: str):
    """A packet to ``address`` matches ``prefix`` (from ``source`` when given) and leaves through ``interface``."""
    found = route(env, device, address)
    if found is None:
        return False, f"{address}: no route"
    ok = found["prefix"] == str(ipaddress.ip_network(prefix)) and found["interfaces"] == [interface] \
        and (not source or found["type"].lower() in _SOURCES[source])
    return ok, f"{address}: {found['prefix']} {found['type']} via {','.join(found['interfaces'])}"


def adjacencies_up(env, *, device: str, interfaces):
    try:
        rows = live.parse_eos_isis(env.executors[device].show("show isis neighbors | json"))
    except (ExecutorError, live.LiveError, ValueError):
        return False, "IS-IS neighbours unreadable"
    up = sorted({row["interface"] for row in rows if row["state"] == "UP"})
    return up == sorted(interfaces), f"up on {', '.join(up) or 'nothing'}"


def database_holds(env, *, device: str, prefixes):
    try:
        text = env.executors[device].show("show isis database detail")
    except ExecutorError:
        return False, "IS-IS database unreadable"
    missing = [prefix for prefix in prefixes if prefix not in text]
    return not missing, f"missing {', '.join(missing)}" if missing else "all present"


def answers(env, *, device: str, address: str, interface: str = ""):
    ok = bool(env.executors[device].neighbour_answers(address, interface))
    return ok, f"{address} {'answered' if ok else 'did not answer'}"


def takeover_ready(env, *, device: str, prefixes):
    """The route that forwards once a shield goes is programmed and each of its next hops answers now: the first packet
    to an unresolved next hop is dropped while the neighbour is being discovered."""
    for prefix in prefixes:
        found = route(env, device, prefix)
        if found is None or not found["programmed"] or any(_is_management(i) for i in found["interfaces"]):
            return False, f"{prefix}: take-over route is not programmed"
        for hop, interface in found["vias"]:
            if not hop:
                return False, f"{prefix}: take-over route has no next hop"
            scoped = interface if ipaddress.ip_address(hop).is_link_local else ""
            if not env.executors[device].neighbour_answers(hop, scoped):
                return False, f"{prefix}: next hop {hop} on {interface} does not answer"
    return True, "every take-over next hop answers"


def no_temporary_lines(env, *, devices, lines):
    """None of the plan's migration-only statements is configured on any access device."""
    wanted = set(config_paths("\n".join(lines)))
    for device in devices:
        try:
            present = config_paths(env.executors[device].show("show running-config"))
        except ExecutorError:
            return False, f"{device}: running configuration unreadable"
        left = sorted(wanted & present)
        if left:
            return False, f"{device} still holds {left[0]}"
    return True, "none configured"


def cover_installed(env, *, cover):
    executor = env.executors[cover.core]
    try:
        state = executor.state(cover)
        return state == "EXACT" and executor.forwards(cover), f"{cover.prefix}: {state}"
    except ExecutorError as exc:
        return False, exc.code


def cover_absent(env, *, cover):
    try:
        state = env.executors[cover.core].state(cover)
    except ExecutorError as exc:
        return False, exc.code
    return state == "ABSENT", f"{cover.prefix}: {state}"


def cores_quiet(env, *, cores, prefixes, seconds: float):
    """Every core has left every client route alone for ``seconds``, and so has this run: the boundary routers
    re-originate their external LSAs for a while after a change, and each time a core may replace the route."""
    ages = []
    try:
        for core in cores:
            for prefix in prefixes:
                row = env.executors[core].client_route(prefix)
                if not row["installed"] or row["active_next_hops"] != 2:
                    return False, f"{core}: {prefix} is not installed toward both boundary routers"
                ages.append(row["quiet_seconds"])
    except ExecutorError as exc:
        return False, exc.code
    since_change = env.clock() - env.last_change_at if env.last_change_at is not None else seconds
    quiet = min([*ages, since_change])
    return quiet >= seconds, f"quiet for {int(quiet)} s"


def core_adjacencies_unchanged(env, *, core: str):
    """The core router's OSPF adjacencies are exactly the ones the precheck recorded: a cover must not disturb them."""
    from . import core_cover

    before = (env.baseline.get(core) or {}).get("adjacencies")
    now = core_cover.adjacencies(env.read(env.devices[core]))
    same = before is not None and now is not None and [list(row) for row in now] == [list(row) for row in before]
    return same, "unchanged" if same else "the adjacency state differs from the precheck"
