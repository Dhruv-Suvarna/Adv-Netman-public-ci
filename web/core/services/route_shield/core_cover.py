"""Temporary kernel covering routes on the FRR core routers (R3/R4): a migration guard, not routing intent.

FRR 8.4.4 updates an IPv6 route in the kernel by deleting it and adding it again, the kernel is the core router's
forwarding plane, and the only less-specific route behind a client /64 there is the management default.  For the whole
static-to-IS-IS migration window each core therefore holds one kernel /63 under every client /64, toward the same two
boundary routers the /64 itself uses (docs/V2_LOSSLESS_ROUTE_SHIELD.md, 2.4).

Runtime truth: these are ``ip -6 route`` entries (protocol ``boot``).  ``staticd`` is not running on R3/R4, so nothing
here is FRR configuration and nothing is written with ``vtysh``; the FRR running configuration must be byte-identical
before and after.  A cover is never startup configuration, Golden content, NetBox intent or part of a final candidate.

This is NOT a static-route capability: the only prefixes, devices and command shapes it can ever send are the ones a
validated ``CoverRoute`` names.
"""

from __future__ import annotations

import ipaddress
import json
import re
import subprocess
from dataclasses import dataclass

from ..bundles import canonical
from ..execution.executors.base import APPLY, REFUSE, SKIP_SATISFIED, ApplyOutcome, Assessment, CompensationOutcome, ConfigletSpec, DeviceExecutor, ExecutorError
from ..execution.executors.linux import docker_exec

OBJECT_TYPE = "transition_kernel_cover"      # no generic executor accepts this type: only ``KernelCoverExecutor`` does
PLATFORM = "ubuntu_frr"
APPROVED_CORES = ("R3", "R4")
COVER_LENGTH = 63
STATIC_PROTOCOLS = frozenset({"boot", "static", "kernel"})        # what is not installed by a routing daemon
_INTERFACE = re.compile(r"^[A-Za-z][A-Za-z0-9_.-]{0,14}$")
_RESOLVED = frozenset({"REACHABLE", "STALE", "DELAY", "PROBE", "PERMANENT"})

PREFIX_OCCUPIED = "COVER_PREFIX_OCCUPIED"
NOT_A_COVER = "NOT_AN_APPROVED_COVER"
PERSISTENT_CONFIG = "/etc/frr/frr.conf"      # what a core router boots from; a cover must never reach it


class CoverError(ValueError):
    """Not a cover of the approved design.  Nothing is planned or sent from it."""


def _is_management(interface: str) -> bool:
    return str(interface).lower() == "lo" or str(interface).lower().startswith(("management", "ma", "mgmt"))


@dataclass(frozen=True)
class CoverRoute:
    """One approved cover: ``prefix`` on ``core`` toward exactly two boundary routers, by link-local address and interface."""

    core: str
    prefix: str                                   # the /63
    protects: str                                 # the client /64 underneath it
    next_hops: tuple[tuple[str, str], ...]        # ((link-local address, interface), (link-local address, interface))

    def __post_init__(self):
        if self.core not in APPROVED_CORES:
            raise CoverError(f"{self.core}: covers exist on {' and '.join(APPROVED_CORES)} only.")
        try:
            cover, client = ipaddress.ip_network(self.prefix), ipaddress.ip_network(self.protects)
            hops = [(ipaddress.ip_address(address), interface) for address, interface in self.next_hops]
        except ValueError as exc:
            raise CoverError(f"{self.core}: {exc}") from None
        if cover.version != 6 or client.version != 6 or client.prefixlen != 64 or cover != client.supernet(new_prefix=COVER_LENGTH):
            raise CoverError(f"{self.core}: the cover of {client} is exactly its /{COVER_LENGTH}.")
        if len(hops) != 2 or len({interface for _, interface in hops}) != 2:
            raise CoverError(f"{self.core}: a cover points at both boundary routers, each on its own interface.")
        for address, interface in hops:
            if address.version != 6 or not address.is_link_local:
                raise CoverError(f"{self.core}: a cover next hop is the boundary router's link-local address.")
            if not _INTERFACE.fullmatch(interface) or _is_management(interface):
                raise CoverError(f"{self.core}: {interface!r} cannot carry production traffic.")

    @property
    def hops(self) -> tuple[tuple[str, str], ...]:
        return tuple(sorted((str(ipaddress.ip_address(address)), interface) for address, interface in self.next_hops))

    @property
    def probe_address(self) -> str:
        """An address only the cover matches: in the half of the /63 that is not the client /64."""
        cover, client = ipaddress.ip_network(self.prefix), ipaddress.ip_network(self.protects)
        other = next(half for half in cover.subnets(prefixlen_diff=1) if half != client)
        return str(other.network_address + 1)

    def add_argv(self) -> list[str]:
        return ["ip", "-6", "route", "add", self.prefix, *(word for address, interface in self.next_hops
                                                             for word in ("nexthop", "via", str(ipaddress.ip_address(address)), "dev", interface))]

    def del_argv(self) -> list[str]:
        return ["ip", "-6", "route", "del", self.prefix]

    def lines(self) -> tuple[str, ...]:
        return (" ".join(self.add_argv()),)

    def removal_lines(self) -> tuple[str, ...]:
        return (" ".join(self.del_argv()),)

    def to_expected(self) -> dict:
        return {"core": self.core, "prefix": self.prefix, "protects": self.protects, "next_hops": [list(hop) for hop in self.next_hops]}

    @classmethod
    def from_expected(cls, expected: dict) -> "CoverRoute":
        try:
            return cls(str(expected["core"]), str(expected["prefix"]), str(expected["protects"]),
                       tuple((str(address), str(interface)) for address, interface in expected["next_hops"]))
        except (KeyError, TypeError, ValueError) as exc:
            raise CoverError(str(exc)) from None


# THE approved inventory (docs/V2_LOSSLESS_ROUTE_SHIELD.md, 2.4): three /63 on each of R3 and R4, toward the link-local
# addresses of R1 and R2 on the core-facing VLANs.  It is a constant of the code: no setting, argument, Change field or
# plan row can add to it, and the production executor sends nothing that is not in it.
CLIENT_PREFIXES = ("2001:db8:10::/64", "2001:db8:20::/64", "2001:db8:30::/64")
R1_LINK_LOCAL, R2_LINK_LOCAL = "fe80::21c:73ff:fe20:ab82", "fe80::21c:73ff:fe17:db73"
APPROVED_NEXT_HOPS = {"R3": ((R1_LINK_LOCAL, "Vlan101"), (R2_LINK_LOCAL, "Vlan103")),
                      "R4": ((R1_LINK_LOCAL, "Vlan102"), (R2_LINK_LOCAL, "Vlan104"))}


def covers_for(next_hops: dict) -> tuple[CoverRoute, ...]:
    return tuple(CoverRoute(core, str(ipaddress.ip_network(client).supernet(new_prefix=COVER_LENGTH)), client, tuple(pair))
                 for core, pair in next_hops.items() for client in CLIENT_PREFIXES)


APPROVED_COVERS = covers_for(APPROVED_NEXT_HOPS)


def is_approved(route: CoverRoute) -> bool:
    return any(route.core == known.core and route.prefix == known.prefix and route.protects == known.protects and route.hops == known.hops
               for known in APPROVED_COVERS)


def _is_production_container(device: dict) -> bool:
    """The device dict names the managed production container of that core router (read from ``inventory.yml``)."""
    try:
        from ..health import inventory

        managed = inventory.inventory_devices().get(str(device.get("name"))) or {}
    except Exception:  # noqa: BLE001 - an unreadable inventory is treated as production: the narrower rule applies
        return True
    return bool(managed) and managed.get("container") == device.get("container")


_UPTIME_UNITS = {"w": 604800, "d": 86400, "h": 3600, "m": 60, "s": 1}


def uptime_seconds(text: str) -> int:
    """FRR's route age: ``HH:MM:SS`` under a day, then ``1d02h03m``, then ``01w2d03h`` (found on production R3/R4, whose
    client routes are days old; the sandbox only ever showed the first form).  Anything else is an error, never a guess."""
    if re.fullmatch(r"\d{1,2}:\d{2}:\d{2}", text):
        hours, minutes, seconds = (int(part) for part in text.split(":"))
        return hours * 3600 + minutes * 60 + seconds
    parts = re.fullmatch(r"(?:(\d+)w)?(?:(\d+)d)?(?:(\d+)h)?(?:(\d+)m)?(?:(\d+)s)?", text)
    if not text or parts is None:
        raise ValueError(f"unknown uptime {text!r}")
    return sum(int(value) * _UPTIME_UNITS[unit] for value, unit in zip(parts.groups(), "wdhms") if value)


def install_spec(route: CoverRoute, cfg_id: str, sequence: int) -> ConfigletSpec:
    return ConfigletSpec(cfg_id, sequence, route.core, PLATFORM, OBJECT_TYPE, "CREATE_DEFINE", route.lines(), route.to_expected())


def remove_spec(route: CoverRoute, cfg_id: str, sequence: int) -> ConfigletSpec:
    return ConfigletSpec(cfg_id, sequence, route.core, PLATFORM, OBJECT_TYPE, "REMOVE_DELETE", route.removal_lines(), route.to_expected())


def _row_hops(row: dict) -> tuple[tuple[str, str], ...]:
    hops = [(n.get("gateway"), n.get("dev")) for n in row.get("nexthops") or []] or [(row.get("gateway"), row.get("dev"))]
    return tuple(sorted((str(ipaddress.ip_address(address)), str(interface)) for address, interface in hops if address and interface))


class KernelCoverExecutor(DeviceExecutor):
    """Reads, installs, verifies and removes approved covers in one core router's kernel routing table.

    Every spawn is ``docker exec <container> <argv list>`` (no shell).  The argv is rebuilt from the validated
    ``CoverRoute``; a Configlet's text is never executed.
    """

    platform = PLATFORM

    def __init__(self, device: dict, *, runner=None, timeout: float = 20.0, sandbox_covers=None):
        """``sandbox_covers``: the measured covers of a DISPOSABLE sandbox core.  It is refused for the managed production
        container, where the allow-list is always ``APPROVED_COVERS`` and nothing else."""
        self._device, self._timeout = device, timeout
        self._runner = runner or docker_exec
        self._connected = False
        self._sandbox_covers = None if sandbox_covers is None else tuple(sandbox_covers)

    def allowed(self, route: CoverRoute) -> bool:
        if self._sandbox_covers is None:
            return is_approved(route)
        return any(route == known for known in self._sandbox_covers)

    # -- transport ------------------------------------------------------------------------------------------------------
    def _run(self, argv: list[str]):
        try:
            return self._runner(self._device["container"], argv, self._timeout)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise ExecutorError("TIMEOUT" if isinstance(exc, subprocess.TimeoutExpired) else "TRANSPORT_ERROR") from exc

    def _read_json(self, argv: list[str]):
        done = self._run(argv)
        if done.returncode:
            raise ExecutorError("PREVIOUS_STATE_UNAVAILABLE")
        try:
            return json.loads(done.stdout or "[]")
        except ValueError:
            raise ExecutorError("PREVIOUS_STATE_UNAVAILABLE") from None

    def connect(self) -> None:
        if self._device.get("name") not in APPROVED_CORES or not self._device.get("container"):
            raise ExecutorError("NOT_CONFIGURED")
        if self._sandbox_covers is not None and _is_production_container(self._device):
            raise ExecutorError(NOT_A_COVER)              # the production allow-list cannot be replaced
        self._read_json(["ip", "-j", "-6", "route", "show", "default"])
        self._connected = True

    # -- reads ----------------------------------------------------------------------------------------------------------
    def routes(self, prefix: str) -> list[dict]:
        """Every kernel route for exactly ``prefix``."""
        return [row for row in self._read_json(["ip", "-j", "-6", "route", "show", str(ipaddress.ip_network(prefix))])]

    def routes_within(self, prefix: str) -> list[dict]:
        return list(self._read_json(["ip", "-j", "-6", "route", "show", "root", str(ipaddress.ip_network(prefix))]))

    def state(self, route: CoverRoute) -> str:
        """ABSENT, EXACT (the approved route and nothing else) or OTHER (anything else occupies the prefix)."""
        rows = self.routes(route.prefix)
        if not rows:
            return "ABSENT"
        if len(rows) == 1 and _row_hops(rows[0]) == route.hops and str(rows[0].get("protocol", "boot")) == "boot":
            return "EXACT"
        return "OTHER"

    def forwards(self, route: CoverRoute) -> bool:
        """A lookup of an address only the cover matches leaves toward a boundary router, never the management network."""
        rows = self._read_json(["ip", "-j", "-6", "route", "get", route.probe_address])
        return len(rows) == 1 and (str(ipaddress.ip_address(rows[0].get("gateway") or "::")), str(rows[0].get("dev"))) in route.hops

    def management_interfaces(self) -> set[str]:
        """The interfaces the default route leaves through: on a core router that is the management network."""
        rows = self._read_json(["ip", "-j", "-6", "route", "show", "default"])
        return {str(hop_interface) for row in rows for _address, hop_interface in _row_hops(row)}

    def neighbour_state(self, address: str, interface: str) -> str:
        """RESOLVED, UNRESOLVED (the kernel tried and failed) or UNUSED (no entry: nothing was forwarded to it lately)."""
        rows = self._read_json(["ip", "-j", "-6", "neigh", "show", str(ipaddress.ip_address(address)), "dev", interface])
        if not rows:
            return "UNUSED"
        return "RESOLVED" if any(row.get("lladdr") and _RESOLVED.intersection(row.get("state") or []) for row in rows) else "UNRESOLVED"

    def full_neighbours(self) -> set[tuple[str, str]]:
        """(link-local address, interface) of every OSPFv3 neighbour in state Full: who the core really exchanges packets with."""
        rows = self._read_json(["vtysh", "-c", "show ipv6 ospf6 neighbor detail json"])
        found = set()
        for row in rows.values() if isinstance(rows, dict) else []:
            if str(row.get("neighborState", "")).lower() == "full" and row.get("linkLocalAddress") and row.get("interface"):
                found.add((str(ipaddress.ip_address(row["linkLocalAddress"])), str(row["interface"])))
        return found

    def static_route_digest(self) -> str:
        """Every IPv6 kernel route no routing daemon installed.  Equal digests: the same non-dynamic routing state."""
        rows = [row for row in self._read_json(["ip", "-j", "-6", "route", "show", "table", "all"])
                if str(row.get("protocol", "boot")) in STATIC_PROTOCOLS and str(row.get("type", "unicast")) == "unicast"
                and not str(row.get("dst", "")).startswith("fe80")]
        facts = sorted((str(row.get("dst")), str(row.get("table", "main")), str(row.get("protocol", "boot")), _row_hops(row)) for row in rows)
        return canonical.text_hash(canonical.canonical_json(facts))

    def frr_config_digest(self) -> str:
        """The FRR running configuration: a cover must never appear in it."""
        done = self._run(["vtysh", "-c", "show running-config"])
        if done.returncode:
            raise ExecutorError("PREVIOUS_STATE_UNAVAILABLE")
        text = "\n".join(line.rstrip() for line in done.stdout.splitlines() if line.strip() and not line.startswith(("!", "Building", "Current")))
        return canonical.text_hash(text)

    def client_route(self, prefix: str) -> dict:
        """FRR's own view of a client route: installed, both next hops active, and how long it has been left alone."""
        done = self._run(["vtysh", "-c", f"show ipv6 route {ipaddress.ip_network(prefix)} json"])
        try:
            row = (json.loads(done.stdout or "{}").get(str(ipaddress.ip_network(prefix))) or [{}])[0]
            quiet = uptime_seconds(str(row.get("uptime", "")))
        except (ValueError, TypeError, AttributeError):
            return {"installed": False, "active_next_hops": 0, "quiet_seconds": -1}
        return {"installed": bool(row.get("installed")), "active_next_hops": int(row.get("internalNextHopActiveNum") or 0), "quiet_seconds": quiet}

    def persistent_config_digest(self) -> str:
        """The configuration the core router boots from (``/etc/frr/frr.conf``): unchanged by a cover, before and after."""
        done = self._run(["cat", PERSISTENT_CONFIG])
        if done.returncode:
            raise ExecutorError("PREVIOUS_STATE_UNAVAILABLE")
        return canonical.text_hash(done.stdout)

    def identity(self) -> dict:
        """Who answers: the host name and the routing suite (read-only)."""
        name, version = self._run(["hostname"]), self._run(["vtysh", "-c", "show version"])
        if name.returncode or version.returncode:
            raise ExecutorError("PREVIOUS_STATE_UNAVAILABLE")
        return {"hostname": name.stdout.strip(), "platform": "FRRouting" if "FRRouting" in version.stdout else "unknown",
                "version": (re.search(r"FRRouting (\S+)", version.stdout) or [None, ""])[1]}

    # -- contract -------------------------------------------------------------------------------------------------------
    def _route(self, spec: ConfigletSpec) -> CoverRoute | None:
        if spec.object_type != OBJECT_TYPE or spec.device != self._device.get("name"):
            return None
        try:
            route = CoverRoute.from_expected(spec.expected)
        except CoverError:
            return None
        wanted = route.removal_lines() if spec.operation == "REMOVE_DELETE" else route.lines()
        if not self.allowed(route):                           # not in the locked inventory: nothing is assessed or sent
            return None
        return route if route.core == spec.device and tuple(spec.lines) == wanted else None     # the plan text is what will be sent

    def assess(self, spec: ConfigletSpec) -> Assessment:
        route = self._route(spec)
        if route is None or not self._connected:
            return Assessment(REFUSE, False, {}, NOT_A_COVER)
        found = self.state(route)
        facts = {"kind": "kernel_cover", "prefix": route.prefix, "state": found, "static_route_digest": self.static_route_digest()}
        if found == "OTHER":
            return Assessment(REFUSE, False, facts, PREFIX_OCCUPIED)          # never overwritten
        if spec.operation == "REMOVE_DELETE":
            return Assessment(SKIP_SATISFIED if found == "ABSENT" else APPLY, True, facts)
        return Assessment(SKIP_SATISFIED if found == "EXACT" else APPLY, True, facts)

    def apply(self, spec: ConfigletSpec, assessment: Assessment) -> ApplyOutcome:
        route = self._route(spec)
        if route is None:
            return ApplyOutcome(False, "COMMAND_REJECTED")
        try:
            done = self._run(route.del_argv() if spec.operation == "REMOVE_DELETE" else route.add_argv())
        except ExecutorError as exc:
            return ApplyOutcome(False, exc.code, partial_effects=True, lines_sent=1)
        return ApplyOutcome(True, lines_sent=1) if done.returncode == 0 else ApplyOutcome(False, "COMMAND_REJECTED", lines_sent=1)

    def compensate(self, spec: ConfigletSpec, assessment: Assessment) -> CompensationOutcome:
        """Put back exactly what this Configlet found: an install is deleted again, a removal is installed again."""
        route = self._route(spec)
        if route is None:
            return CompensationOutcome("COMPENSATION_FAILED", "UNSUPPORTED")
        before = (assessment.previous_state or {}).get("state")
        wanted_digest = (assessment.previous_state or {}).get("static_route_digest")
        try:
            now = self.state(route)
            if now == "OTHER" or before not in ("ABSENT", "EXACT"):
                return CompensationOutcome("COMPENSATION_FAILED", PREFIX_OCCUPIED)
            if now != before:
                done = self._run(route.del_argv() if before == "ABSENT" else route.add_argv())
                if done.returncode:
                    return CompensationOutcome("COMPENSATION_FAILED", "COMMAND_REJECTED")
            if self.state(route) != before or (wanted_digest and self.static_route_digest() != wanted_digest):
                return CompensationOutcome("COMPENSATION_FAILED", "STATE_NOT_RESTORED")
        except ExecutorError as exc:
            return CompensationOutcome("COMPENSATION_UNVERIFIED", exc.code)
        return CompensationOutcome("COMPENSATED", detail={"action": "NONE_NEEDED" if now == before else "INVERSE_APPLIED"})


# -- fail-closed prechecks and postchecks (pure: facts in, blocker rows out) ----------------------------------------------------
def _block(code: str, core: str, detail: str) -> dict:
    return {"code": code, "device": core, "detail": detail}


def precheck(routes: list[CoverRoute], executor: KernelCoverExecutor, evidence) -> list[dict]:
    """Everything that must hold on ONE core router before its first cover is written.  ``evidence``: a fresh health read."""
    from . import gates

    core = routes[0].core if routes else ""
    found: list[dict] = []
    interfaces, ospf = (evidence.facts(name) if evidence is not None else None for name in ("interfaces", "ospf"))
    if not routes or interfaces is None or ospf is None or not getattr(evidence, "live_reachable", False):
        return [_block(gates.EVIDENCE_UNAVAILABLE, core, "interfaces and OSPFv3 neighbours of the core router must be readable")]
    try:
        management, full = executor.management_interfaces(), executor.full_neighbours()
        for route in routes:
            if management.intersection(interface for _address, interface in route.hops):
                found.append(_block(gates.MANAGEMENT_FALLBACK, core, f"a next hop of {route.prefix} is on the management interface"))
            client = executor.routes(route.protects)
            if len(client) != 1 or _row_hops(client[0]) != route.hops:
                found.append(_block(gates.OLD_ROUTE_ABSENT, core, f"{route.protects} is not installed toward exactly the approved next hops"))
            state = executor.state(route)
            if state != "ABSENT":
                found.append(_block(gates.OUT_OF_BAND, core, f"a route for {route.prefix} already exists ({state}); it is not overwritten"))
            foreign = sorted({str(row.get("dst")) for row in executor.routes_within(route.prefix)} - {route.protects, route.prefix})
            if foreign:
                found.append(_block(gates.CLASSIFICATION_UNKNOWN, core, f"{route.prefix} would also cover {', '.join(foreign)}"))
            fib = executor.client_route(route.protects)
            if not fib["installed"] or fib["active_next_hops"] != 2:
                found.append(_block(gates.OLD_ROUTE_ABSENT, core, f"FRR does not hold {route.protects} with both next hops active"))
            for address, interface in route.hops:
                if (interfaces.get(interface) or {}).get("oper") != "UP":
                    found.append(_block(gates.NEXT_HOP_UNHEALTHY, core, f"{interface} is not up"))
                elif (address, interface) not in full:          # reachable and the boundary router itself: the adjacency runs over this very address
                    found.append(_block(gates.NEXT_HOP_UNHEALTHY, core, f"{address} is not a Full OSPFv3 neighbour on {interface}"))
                elif executor.neighbour_state(address, interface) == "UNRESOLVED":
                    found.append(_block(gates.NEXT_HOP_UNHEALTHY, core, f"{address} on {interface} failed neighbour resolution"))
    except ExecutorError as exc:
        found.append(_block(gates.EVIDENCE_UNAVAILABLE, core, exc.code))
    unique = []
    for row in found:
        if row not in unique:
            unique.append(row)
    return unique


def postcheck(routes: list[CoverRoute], executor: KernelCoverExecutor, evidence, *, adjacencies_before=None, present: bool = True) -> list[dict]:
    """After install (``present``) every cover is exact and forwards; after removal none remains.  Adjacencies unchanged."""
    from . import gates

    core = routes[0].core if routes else ""
    found: list[dict] = []
    try:
        for route in routes:
            state = executor.state(route)
            if present and state != "EXACT":
                found.append(_block(gates.SHIELD_UNCONFIRMED, core, f"{route.prefix} is {state}, not the approved cover"))
            elif present and not executor.forwards(route):
                found.append(_block(gates.MANAGEMENT_FALLBACK, core, f"a lookup under {route.prefix} does not leave toward a boundary router"))
            elif not present and state != "ABSENT":
                found.append(_block("TEMPORARY_STATE_REMAINS", core, f"{route.prefix} is still installed"))
    except ExecutorError as exc:
        found.append(_block(gates.EVIDENCE_UNAVAILABLE, core, exc.code))
    if adjacencies_before is not None:
        now = adjacencies(evidence)
        if now is None or now != adjacencies_before:
            found.append(_block(gates.NEXT_HOP_UNHEALTHY, core, "the OSPFv3 adjacency state of the core router changed"))
    return found


def adjacencies(evidence) -> list | None:
    ospf = evidence.facts("ospf") if evidence is not None else None
    if ospf is None:
        return None
    return sorted((str(row.get("family")), str(row.get("interface")), str(row.get("neighbor_id")), str(row.get("state")).upper()) for row in ospf)
