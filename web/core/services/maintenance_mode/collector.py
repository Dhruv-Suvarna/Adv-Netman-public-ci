"""The read-only live observation that feeds the readiness model.

One ``observe(device, sources)`` reads every managed device through the health engine's own reader, reads the client
hosts' packet counters twice, and returns the facts the readiness engine expects: one production ``Flow`` per host,
address family and direction (activity, whether its path passes the device, the path), the health of the path the
traffic would move to, the routing-protocol state, the dependencies, and the configuration digests of that moment.

Nothing here writes, and nothing here is a second telemetry path: devices are read with ``health.live.read_device``, the
hosts with fixed read-only commands (``cat`` of three ``/proc/net`` files, ``ip -j``).  Whatever could not be read or
derived stays UNKNOWN / None, which the readiness engine and the entry gate treat as a refusal.

Production traffic is what the client hosts exchange with the network, per address family: unicast IP packets counted
by the host itself.  A host with no unicast packet in or out during the window is QUIESCED in that family and
direction; any packet makes it ACTIVE.  Multicast and broadcast (router advertisements, DHCP discovery) are control.
"""

from __future__ import annotations

import ipaddress
import json
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime

from ..bundles import canonical
from ..route_shield import readiness as shield_readiness
from . import model, policy, protection, topology

WINDOW_SECONDS = 20.0
FAMILY = {4: model.IPV4, 6: model.IPV6}


def _docker(container: str, argv: list[str]) -> str:
    done = subprocess.run(["docker", "exec", container, *argv], capture_output=True, text=True, timeout=20, shell=False, check=False)  # noqa: S603,S607
    if done.returncode:
        raise OSError(f"{container}: {argv[0]} failed")
    return done.stdout


class HostReader:
    """What a client host reports about itself.  Fixed read-only commands; ``run`` is injectable for tests."""

    def __init__(self, run=_docker):
        self._run = run

    def addresses(self, host: topology.Host) -> dict:
        """{4: [address, ...], 6: [...]}: the global addresses on the host's data interface that it would source from."""
        found = {4: [], 6: []}
        for row in json.loads(self._run(host.container, ["ip", "-j", "addr", "show", "dev", host.interface]) or "[]"):
            for entry in row.get("addr_info") or []:
                if entry.get("scope") == "global" and not entry.get("deprecated") and not entry.get("tentative"):
                    address = ipaddress.ip_address(entry["local"])
                    found[address.version].append(str(address))
        return {version: sorted(values) for version, values in found.items()}

    def gateways(self, host: topology.Host) -> dict:
        found = {}
        for version in (4, 6):
            rows = json.loads(self._run(host.container, ["ip", "-j", f"-{version}", "route", "show", "default", "dev", host.interface]) or "[]")
            found[version] = sorted({str(row["gateway"]) for row in rows if row.get("gateway")})
        return found

    @staticmethod
    def _table(text: str, prefix: str) -> dict:
        """One ``Header: names`` / ``Header: values`` pair of /proc/net/snmp or /proc/net/netstat."""
        lines = [line.split() for line in text.splitlines() if line.startswith(prefix + ":")]
        return dict(zip(lines[0][1:], (int(v) for v in lines[1][1:]))) if len(lines) == 2 else {}

    def counters(self, host: topology.Host) -> dict:
        """Unicast IP packets this host has received and sent, per family, since boot.  IPv6 from the data interface's
        own counters; IPv4 from the host's IP counters (multicast and broadcast removed).  IPv4 received is counted as
        DELIVERED, not as received: multicast of a group the host has not joined (RIP's 224.0.0.9 on a client VLAN) is
        counted in ``InReceives`` and dropped before ``InMcastPkts``, so ``InReceives`` would read routing chatter as
        production traffic."""
        six = dict(line.split() for line in self._run(host.container, ["cat", f"/proc/net/dev_snmp6/{host.interface}"]).splitlines() if len(line.split()) == 2)
        ip = self._table(self._run(host.container, ["cat", "/proc/net/snmp"]), "Ip")
        ext = self._table(self._run(host.container, ["cat", "/proc/net/netstat"]), "IpExt")
        return {(6, model.SOUTHBOUND): int(six["Ip6InReceives"]) - int(six.get("Ip6InMcastPkts", 0)),
                (6, model.NORTHBOUND): int(six["Ip6OutRequests"]) - int(six.get("Ip6OutMcastPkts", 0)),
                (4, model.SOUTHBOUND): ip["InDelivers"] - ext.get("InMcastPkts", 0) - ext.get("InBcastPkts", 0),
                (4, model.NORTHBOUND): ip["OutRequests"] - ext.get("OutMcastPkts", 0) - ext.get("OutBcastPkts", 0)}


@dataclass
class Sources:
    """Everything an observation reads from.  ``read`` is ``health.live.read_device``."""

    topology: topology.Topology
    read: object
    hosts: HostReader = field(default_factory=HostReader)
    dhcp_servers: object = None              # () -> {"primary", "secondary", "secondary_device"} (health.inventory.dhcp_hosts)
    dhcp_state: object = None                # () -> {"nmas": {...}|None, ...} (health.live.dhcp_service_state)
    shield_states: dict | None = None        # route_shield.readiness.READINESS unless a test says otherwise
    window_seconds: float = WINDOW_SECONDS
    sleep: object = time.sleep
    now: object = None                       # () -> datetime
    telemetry: object = None                 # () -> health.telemetry.TelemetrySnapshot (the topology service), or None: not collected


@dataclass
class Observation:
    device: str
    at: datetime
    role: str
    flows: list
    dependencies: list
    alternates: dict
    mechanisms: dict
    intersects: tuple[str, ...]
    access: topology.Access | None = None
    facts: dict = field(default_factory=dict)          # protocol state, paths, digests, host counters: the evidence behind the above

    def summary(self) -> dict:
        """The stored, JSON-safe form of the evidence."""
        return {"at": self.at.isoformat(), "role": self.role, "intersects": list(self.intersects), "access": self.access.as_dict() if self.access else None,
                "alternates": {f"{family}/{direction}": value for (family, direction), value in self.alternates.items()},
                "mechanisms": {f"{family}/{direction}": {"key": m.key, "state": m.state} for (family, direction), m in self.mechanisms.items()},
                "flows": [{"label": f.label, "workload": f.workload, "family": f.family, "direction": f.direction, "activity": f.activity,
                           "on_device": f.on_device, "evidence": f.evidence} for f in self.flows],
                "dependencies": [{"name": d.name, "kind": d.kind, "stranded": d.stranded, "detail": d.detail} for d in self.dependencies],
                **self.facts}


def read_all(sources: Sources) -> dict:
    devices = {name: device for name, device in sources.topology.devices.items() if name not in sources.topology.management}
    with ThreadPoolExecutor(max_workers=4) as pool:
        return dict(zip(devices, pool.map(sources.read, devices.values())))


def digest(evidence) -> str | None:
    """The configured state of a cEOS device at this read: the hash of its statement signatures (sanitized running
    configuration).  None when it could not be read."""
    paths = evidence.facts("config_paths") if evidence is not None else None
    return None if paths is None else canonical.text_hash("\n".join(paths))


def _protocols(evidence: dict, device: str) -> dict:
    found = evidence.get(device)
    if found is None or not found.live_reachable:
        return {"reachable": False}
    ospf, isis = found.facts("ospf"), found.facts("isis")
    return {"reachable": True,
            "isis_up": None if isis is None else sorted(f"{row['interface']}:{row['hostname']}" for row in isis if row.get("state") == "UP"),
            "ospfv3_full": None if ospf is None else sorted(f"{row['interface']}:{row['neighbor_id']}" for row in ospf
                                                            if row.get("family") == "OSPFV3" and str(row.get("state")).upper().startswith("FULL")),
            "ospfv2_full": None if ospf is None else sorted(f"{row['interface']}:{row['neighbor_id']}" for row in ospf
                                                            if row.get("family") == "OSPFV2" and str(row.get("state")).upper().startswith("FULL")),
            "rip_neighbors": None if found.facts("rip_neighbors") is None else len(found.facts("rip_neighbors"))}


def _clock(sources: Sources) -> datetime:
    return sources.now() if sources.now is not None else datetime.now().astimezone()


def _host_facts(sources: Sources) -> dict:
    """name -> {"addresses", "gateways", "delta": {(version, direction): packets | None}, "error", "read_at"}: two counter
    reads, ``window_seconds`` apart, each with the time it was taken."""
    facts, first = {}, {}
    for name, host in sources.topology.hosts.items():
        facts[name] = {"addresses": None, "gateways": None, "delta": {}, "error": "", "read_at": []}
        try:
            facts[name].update(addresses=sources.hosts.addresses(host), gateways=sources.hosts.gateways(host))
            first[name] = sources.hosts.counters(host)
            facts[name]["read_at"].append(_clock(sources).isoformat())
        except (OSError, ValueError, KeyError, subprocess.SubprocessError) as exc:
            facts[name]["error"] = type(exc).__name__
    sources.sleep(sources.window_seconds)
    for name, host in sources.topology.hosts.items():
        if name not in first:
            continue
        try:
            second = sources.hosts.counters(host)
            facts[name]["read_at"].append(_clock(sources).isoformat())
        except (OSError, ValueError, KeyError, subprocess.SubprocessError) as exc:
            facts[name]["error"] = type(exc).__name__
            continue
        facts[name]["delta"] = {key: (second[key] - value if second[key] >= value else None) for key, value in first[name].items()}
    return facts


# --------------------------------------------------------------------------------------------------------------- provenance
HOST_SOURCE = "HOST_COUNTERS"                # /proc/net counters of the client host itself, read twice (docker exec, read-only)
PROVENANCE_GROUPS = ("interfaces", "addresses", "virtual_addresses", "routes", "ospf", "isis", "bgp", "rip_neighbors", "config_paths")


def provenance(evidence: dict) -> dict:
    """device -> where every fact group came from and when: source, observation time, availability and the sanitized
    error of a group that could not be read.  The raw command output is never kept; the sanitized running configuration
    is referenced by its digest (``digests``)."""
    found = {}
    for name, device in sorted(evidence.items()):
        groups = {}
        for group in PROVENANCE_GROUPS:
            fact = device.group(group) if device is not None else None
            groups[group] = None if fact is None else {"source": fact.source, "observed_at": fact.observed_at.isoformat() if fact.observed_at else None,
                                                       "available": fact.available, "complete": fact.complete, "error": fact.error}
        found[name] = {"platform": device.platform, "reachable": device.live_reachable, "live_error": device.live_error, "groups": groups}
    return found


def freshness(summary: dict, *, now: datetime, thresholds: dict) -> dict:
    """device -> FRESH / STALE / EXPIRED / UNKNOWN of its oldest routing fact group (``health.thresholds.classify_age``, the
    one threshold system).  A group that was read but not available is UNKNOWN: missing evidence is never fresh.  A group
    the device's platform reader does not collect at all (IS-IS on an FRR core) is not part of its evidence."""
    from ..health.thresholds import classify_age

    order = ("FRESH", "STALE", "EXPIRED", "UNKNOWN")
    found = {}
    for name, row in (summary.get("provenance") or {}).items():
        worst = "FRESH" if row.get("reachable") else "UNKNOWN"
        for group in ("addresses", "routes", "ospf", "isis"):
            groups = row.get("groups") or {}
            if group in groups and groups[group] is None:
                continue
            fact = groups.get(group)
            if not fact or not fact.get("available") or not fact.get("observed_at"):
                worst = "UNKNOWN"
                continue
            age = (now - datetime.fromisoformat(fact["observed_at"])).total_seconds()
            level = str(classify_age(age, thresholds))
            worst = max(worst, level, key=order.index)
        found[name] = worst
    return found


def _bgp(evidence: dict, names) -> dict:
    """device -> its BGP sessions as the device reports them (peer, remote AS, state), or None when not readable."""
    found = {}
    for name in names:
        device = evidence.get(name)
        rows = device.facts("bgp") if device is not None else None
        found[name] = None if rows is None else [{"peer": r.get("peer"), "remote_as": r.get("remote_as"), "state": r.get("state"), "family": r.get("family")} for r in rows]
    return found


def _interfaces(evidence: dict, names, topo: topology.Topology) -> dict:
    """device -> {interface: oper state} of its cabled production ports and its routed SVIs; management ports left out."""
    found = {}
    for name in names:
        device = evidence.get(name)
        rows = device.facts("interfaces") if device is not None else None
        if rows is None:
            found[name] = None
            continue
        found[name] = {interface: (state or {}).get("oper") for interface, state in sorted(rows.items())
                       if not topology._is_management(interface, name, topo) and (topo.cabled(name, interface) not in ("", *topo.management) or interface.lower().startswith("vlan"))
                       and interface.lower() != f"vlan{protection.MANAGEMENT_VLAN}"}
    return found


def _fhrp(evidence: dict, names) -> dict:
    """device -> its virtual-router (VARP) gateway addresses and which other read device also holds each one."""
    found = {}
    for name in names:
        device = evidence.get(name)
        virtual = device.facts("virtual_addresses") if device is not None else None
        if virtual is None:
            found[name] = None
            continue
        found[name] = {address: sorted(topology.owners(evidence, address) - {name})
                       for address in sorted({str(v).split("/")[0] for values in virtual.values() for v in values})}
    return found


def _mlag(evidence: dict, names) -> dict:
    """device -> whether an MLAG domain is configured (from the sanitized configuration signatures), None when unreadable."""
    found = {}
    for name in names:
        device = evidence.get(name)
        paths = device.facts("config_paths") if device is not None else None
        found[name] = None if paths is None else any(str(path).startswith("mlag configuration") for path in paths)
    return found


def _ecmp(evidence: dict, paths: dict, observed: dict) -> dict:
    """label -> {device: number of next-hop devices} on the derived path of each flow: where traffic is spread over
    more than one next hop, the redundancy already exists in the forwarding table."""
    return {label: {device: len(nexts) for device, nexts in sorted((observed.get(label) or {}).items()) if len(nexts) > 1} for label in paths}


def _telemetry(sources: Sources, names) -> dict:
    """The topology service's telemetry for the devices: last sample time and its freshness, CPU, memory, adjacent links.
    Link utilization is not carried by that source and is reported as not available, never as zero."""
    if sources.telemetry is None:
        return {"collected": False, "reason": "not collected"}
    from ..health import telemetry as health_telemetry

    try:
        snapshot = sources.telemetry()
    except Exception as exc:  # noqa: BLE001 - telemetry is supporting evidence; its absence is recorded, never read as healthy
        return {"collected": False, "reason": type(exc).__name__}
    if not snapshot.available:
        return {"collected": False, "reason": snapshot.reason}
    devices = {}
    for name in names:
        group = health_telemetry.device_evidence(snapshot, name).group("telemetry")
        data = group.data if group is not None and group.available else None
        devices[name] = None if data is None else {
            "observed_at": group.observed_at.isoformat() if group.observed_at else None,
            "freshness": str(group.freshness(snapshot.now, snapshot.thresholds)), "cpu_percent": data["cpu_percent"], "memory_percent": data["memory_percent"],
            "links": health_telemetry.link_states(snapshot, name), "utilization": None}
    return {"collected": True, "generated_at": snapshot.generated_at.isoformat() if snapshot.generated_at else None,
            "backend": snapshot.backend_status, "devices": devices}


def _flows(device: str, sources: Sources, evidence: dict, hosts: dict) -> tuple[list, dict]:
    topo, flows, paths = sources.topology, [], {}
    for name, host in sorted(topo.hosts.items()):
        facts = hosts[name]
        for version in (4, 6):
            if version not in host.families:
                continue
            family, service = FAMILY[version], (topo.service.v4 if version == 4 else topo.service.v6)
            addresses = (facts["addresses"] or {}).get(version) or []
            for direction in model.DIRECTIONS:
                north = direction == model.NORTHBOUND
                label, workload = f"{name.lower()}-v{version}-{'north' if north else 'south'}", (f"{name} to {topo.service.name}" if north else f"{topo.service.name} to {name}")
                packets = facts["delta"].get((version, direction))
                if facts["addresses"] is not None and not addresses:
                    # no address in this family: quiesced only when its counters also prove no unicast packet moved
                    if packets == 0:
                        flows.append(model.Flow(label, workload, family, direction, activity=model.QUIESCED, on_device=False,
                                                evidence=f"{name} holds no IPv{version} address and moved 0 unicast IPv{version} packets in {sources.window_seconds:.0f} s"))
                    else:
                        flows.append(model.Flow(label, workload, family, direction, activity=model.UNKNOWN,
                                                evidence=f"{name} holds no IPv{version} address but its counters show {'no reading' if packets is None else f'{packets} packets'}"))
                    continue
                if north:
                    gateways = (facts["gateways"] or {}).get(version) or []
                    start = sorted(set().union(*(topology.owners(evidence, gateway) for gateway in gateways))) if gateways else []
                    start = [host.attached_to] if host.attached_to in start or not start else start
                    path = topology.trace(evidence, start, service, ends=(topo.service.gateway,), cabling=topo)
                else:
                    path = topology.merged(topology.trace(evidence, [topo.service.gateway], address, cabling=topo) for address in addresses)   # every address it holds
                passed = set(path.devices) | {host.attached_to}                 # the host's own switch carries its frames either way
                on_device = True if device in passed else (False if path.complete else None)
                paths[label] = {"path": path.detail, "complete": path.complete, "on_device": on_device,
                                "hops": {name: list(nexts) for name, nexts in sorted(path.hops.items())}}
                if packets is None:
                    activity, why = model.UNKNOWN, f"{name}: packet counters not readable ({facts['error'] or 'counter reset'})"
                elif packets == 0:
                    activity, why = model.QUIESCED, f"0 unicast IPv{version} packets {'sent' if north else 'received'} by {name} in {sources.window_seconds:.0f} s"
                elif on_device is None or not path.complete:              # active on a path that cannot be followed to its end, on any branch
                    activity, why = model.UNKNOWN, f"{packets} packets in {sources.window_seconds:.0f} s and the path is not established: {path.detail}"
                else:
                    activity, why = model.ACTIVE, f"{packets} unicast IPv{version} packets {'sent' if north else 'received'} by {name} in {sources.window_seconds:.0f} s"
                flows.append(model.Flow(label, workload, family, direction, activity=activity, on_device=on_device,
                                        evidence=f"{why}; path {path.detail}" if on_device is not None and activity != model.UNKNOWN else why))
    return flows, paths


def _alternates(sources: Sources, evidence: dict, access: topology.Access, hosts: dict) -> dict:
    """Health of the path each IPv6 direction would move to.  True / False, or None when it could not be established."""
    service = sources.topology.service.v6
    needed = (access.switch, access.far_switch, access.peer_router, *access.cores)
    if any(evidence.get(name) is None or evidence[name].facts("routes") is None for name in needed):
        return {(model.IPV6, model.NORTHBOUND): None, (model.IPV6, model.SOUTHBOUND): None}
    onward = topology.lookup(evidence, access.far_switch, service) or {}
    beyond = topology.lookup(evidence, access.peer_router, service) or {}
    peer_cores = set(topology.ospfv3_peers(evidence, access.peer_router))
    north = (onward.get("interfaces") == [access.far_uplink]
             and bool(beyond) and access.peer_access_interface not in (beyond.get("interfaces") or []) and not any(topology._is_management(i, access.peer_router, sources.topology) for i in beyond.get("interfaces") or [])
             and set(access.cores) <= peer_cores)
    clients = sorted({address for facts in hosts.values() for address in (facts["addresses"] or {}).get(6) or []})
    south = bool(clients) and set(access.cores) <= peer_cores
    for address in clients:
        down = topology.lookup(evidence, access.peer_router, address) or {}
        south = south and down.get("interfaces") == [access.peer_access_interface]
        for core in access.cores:
            route = topology.lookup(evidence, core, address) or {}
            south = south and access.peer_router in set().union(*(topology.adjacent(evidence, core, i) for i in route.get("interfaces") or []), set())
    return {(model.IPV6, model.NORTHBOUND): bool(north), (model.IPV6, model.SOUTHBOUND): bool(south)}


DHCP_FAMILIES = ("ipv4", "ipv6")


def primary_dhcp_active(status) -> bool | None:
    """Whether the primary DHCP server serves without the backup, from the verifier's own report
    (``netbox/scripts/verify_dhcp_servers.nmas_status``: {"ipv4": <systemctl is-active>, "ipv6": ...}).  True only when
    EVERY family is "active": the backup is not needed only when nothing would fall back to it.  None when a family's
    state is missing (not established); False for any other state ("inactive", "failed", ...)."""
    if not status or any(status.get(family) in (None, "") for family in DHCP_FAMILIES):
        return None
    return all(str(status[family]).strip() == "active" for family in DHCP_FAMILIES)


def _dependencies(device: str, sources: Sources, evidence: dict) -> list:
    topo, found = sources.topology, []
    cut = topo.cut_off_from_management(device)
    found.append(model.Dependency("management reachability of the other devices", "MANAGEMENT", stranded=bool(cut),
                                  detail=f"reach the management network only through {device}: {', '.join(cut)}" if cut else ""))
    virtual = (evidence[device].facts("virtual_addresses") if evidence.get(device) is not None else None)
    if virtual is None:
        found.append(model.Dependency(f"gateway addresses of {device}", "GATEWAY", stranded=None, detail="virtual addresses not readable"))
    for address in sorted({str(value).split("/")[0] for values in (virtual or {}).values() for value in values}):
        others = topology.owners(evidence, address) - {device}
        found.append(model.Dependency(f"gateway {address}", "GATEWAY", stranded=not others,
                                      detail=f"also held by {', '.join(sorted(others))}" if others else f"only {device} holds it"))
    servers = sources.dhcp_servers() if sources.dhcp_servers is not None else {}
    if servers.get("secondary_device") == device:
        state = sources.dhcp_state() if sources.dhcp_state is not None else {}
        healthy = primary_dhcp_active((state or {}).get("nmas"))
        found.append(model.Dependency("DHCP service", "DHCP", stranded=None if healthy is None else not healthy,
                                      detail=f"{device} is the backup DHCP server; primary {'not established' if healthy is None else 'active' if healthy else 'not active'}"))
    return found


def observe(device: str, sources: Sources) -> Observation:
    topo = sources.topology
    if device not in topo.devices:
        raise model.MaintenanceError("DEVICE_NOT_MANAGED", f"{device} is not a managed device of this topology")
    at = _clock(sources)
    evidence = read_all(sources)
    hosts = _host_facts(sources)
    role = topology.role_of(topo, evidence, device)
    flows, paths = _flows(device, sources, evidence, hosts)
    access, why, alternates = None, "", {}
    if role == topology.BOUNDARY_ROUTER:
        access, why = topology.access_of(evidence, device)
        alternates = _alternates(sources, evidence, access, hosts) if access is not None else {(model.IPV6, d): None for d in model.DIRECTIONS}
    mechanisms = policy.mechanisms_for(role, sources.shield_states if sources.shield_states is not None else shield_readiness.READINESS)
    if access is not None:
        intersects = {access.switch, access.far_switch, access.peer_router, *access.cores}
    else:
        intersects = {name for name in topo.production_neighbours(device) if name in topo.devices}
    related = sorted({device, *intersects})
    facts = {"protocols": {name: _protocols(evidence, name) for name in related}, "paths": paths,
             "digests": {name: digest(evidence.get(name)) for name in related if evidence.get(name) is not None and evidence[name].platform == "ceos"},
             "hosts": {name: {"addresses": row["addresses"], "gateways": row["gateways"], "error": row["error"], "source": HOST_SOURCE, "read_at": row["read_at"],
                              "packets": {f"v{version}/{direction}": value for (version, direction), value in row["delta"].items()}} for name, row in hosts.items()},
             "single_homed": list(topo.single_homed(device)), "window_seconds": sources.window_seconds, "access_not_derived": why,
             "provenance": provenance(evidence), "bgp": _bgp(evidence, related), "interfaces": _interfaces(evidence, related, topo),
             "fhrp": _fhrp(evidence, related), "mlag": _mlag(evidence, related), "ecmp": _ecmp(evidence, paths, {label: row["hops"] for label, row in paths.items()}),
             "telemetry": _telemetry(sources, related),
             "scope": {"read": sorted(evidence), "management": list(topo.management), "service": {"name": topo.service.name, "gateway": topo.service.gateway}}}
    return Observation(device, at, role, flows, _dependencies(device, sources, evidence), alternates, mechanisms, tuple(sorted(intersects - {device})), access, facts)
