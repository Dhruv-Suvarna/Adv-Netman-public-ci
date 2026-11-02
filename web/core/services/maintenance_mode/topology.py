"""Where traffic goes and what hangs off a device, derived from the tracked cabling and from what the devices report now.

Pure: a ``Topology`` (cabling, hosts, service) and fresh health evidence in, relations out.  Nothing here is a table of
device names: the access relations of a boundary router, the cores above it, the path of a flow and the devices a
maintenance touches are all read from interfaces, addresses, routes and protocol adjacencies.  What cannot be derived is
reported as not derived, and the caller treats that as unknown.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field

BOUNDARY_ROUTER, ACCESS_SWITCH, TRANSIT = "BOUNDARY_ROUTER", "ACCESS_SWITCH", "TRANSIT"
MAX_HOPS = 8


@dataclass(frozen=True)
class Host:
    name: str
    container: str
    interface: str                      # its data interface (the cabled one)
    families: tuple[int, ...]           # 4 and/or 6, as declared in the inventory
    attached_to: str                    # the device at the other end of its cable


@dataclass(frozen=True)
class Service:
    name: str
    container: str
    v4: str
    v6: str
    gateway: str                        # the managed device its cable ends on


@dataclass(frozen=True)
class Topology:
    links: tuple[tuple[str, str, str, str], ...]        # (node, interface, node, interface), as cabled
    hosts: dict
    service: Service
    devices: dict                                       # name -> inventory device dict of every managed device that is read
    management: tuple[str, ...] = ()                    # the management switch(es): cabling toward them is not a production path
    management_ports: dict = field(default_factory=dict)    # device -> its management interface names (from the inventory and the
                                                            # cabling); a device without an entry falls back to the naming convention

    def neighbours(self, node: str) -> set[str]:
        return {b if a == node else a for a, _ai, b, _bi in self.links if node in (a, b)}

    def production_neighbours(self, node: str) -> set[str]:
        return {other for other in self.neighbours(node) if other not in self.management}

    def cabled(self, node: str, interface: str) -> str:
        """The node at the other end of the cable on ``interface`` of ``node`` ('' for an interface that is not a cabled port)."""
        port = str(interface).lower().replace("ethernet", "eth")
        return next((b if a == node else a for a, a_if, b, b_if in self.links if (a, a_if) == (node, port) or (b, b_if) == (node, port)), "")

    def single_homed(self, device: str) -> tuple[str, ...]:
        """The hosts whose only production cable ends on ``device``."""
        return tuple(sorted(name for name, host in self.hosts.items() if host.attached_to == device and self.production_neighbours(name) == {device}))

    def cut_off_from_management(self, device: str) -> tuple[str, ...]:
        """Managed devices that reach a management switch only through ``device``.  The management switch itself is the
        management network: taking it out cuts every other device off (VLAN 200 is not redundant in this lab)."""
        if device in self.management:
            others = set(self.management) - {device}
            if not others:                      # the devices cabled to it (one without such a cable is managed some other way)
                return tuple(sorted(name for name in self.devices if name != device and device in self.neighbours(name)))
            seen, queue = set(others), list(others)
            while queue:
                for other in self.neighbours(queue.pop()):
                    if other != device and other not in seen:
                        seen.add(other)
                        queue.append(other)
            return tuple(sorted(name for name in self.devices if name != device and name not in seen))
        seen, queue = set(self.management), list(self.management)
        while queue:
            for other in self.neighbours(queue.pop()):
                if other != device and other not in seen:
                    seen.add(other)
                    queue.append(other)
        return tuple(sorted(name for name in self.devices if name != device and name not in seen)) if self.management else ()


def from_clab(document: dict, inventory: dict, devices: dict, *, service_host: str, service_v4: str, service_v6: str) -> Topology:
    """The production topology: the tracked Containerlab file gives the cabling, the inventory the hosts and devices."""
    lab = inventory.get("lab_name", "")
    links = []
    for row in (document.get("topology") or {}).get("links") or []:
        if "endpoints" not in row:                      # a host link (the management switch to the NMAS host itself): not lab cabling
            continue
        (a, a_if), (b, b_if) = (str(end).split(":", 1) for end in row["endpoints"])
        links.append((a, a_if, b, b_if))
    # the management switch is the one device cabled to most of the managed devices and to nothing else
    management = tuple(sorted(name for name in devices if not any(name in (a, b) and {a, b} - {name} - set(devices) for a, _x, b, _y in links)
                              and sum(name in (a, b) for a, _x, b, _y in links) > len(devices) / 2))

    def cable(node):
        return next(((b, a_if) if a == node else (a, b_if) for a, a_if, b, b_if in links if node in (a, b)), ("", ""))

    hosts = {}
    for name, families in sorted((inventory.get("hosts") or {}).items()):
        other, interface = cable(name)
        hosts[name] = Host(name, f"clab-{lab}-{name}", interface, tuple(v for v, key in ((4, "ipv4"), (6, "ipv6")) if (families or {}).get(key)), other)
    gateway, _interface = cable(service_host)
    return Topology(tuple(links), hosts, Service(service_host, f"clab-{lab}-{service_host}", service_v4, service_v6, gateway), dict(devices), management)


# ------------------------------------------------------------------------------------------------------------ reading evidence
def _facts(evidence: dict, device: str, group: str):
    found = evidence.get(device)
    return found.facts(group) if found is not None else None


def _addresses(evidence: dict, device: str) -> list[tuple[str, ipaddress._BaseAddress, ipaddress._BaseNetwork]]:
    rows = []
    for interface, cidrs in (_facts(evidence, device, "addresses") or {}).items():
        for cidr in cidrs:
            try:
                found = ipaddress.ip_interface(cidr)
            except ValueError:
                continue
            rows.append((interface, found.ip, found.network))
    return rows


def owners(evidence: dict, address: str) -> set[str]:
    """Every read device that holds ``address`` on an interface or as a virtual-router address."""
    wanted, found = ipaddress.ip_address(address), set()
    for device in evidence:
        if any(ip == wanted for _interface, ip, _network in _addresses(evidence, device)):
            found.add(device)
        for values in (_facts(evidence, device, "virtual_addresses") or {}).values():
            if any(_same(value, wanted) for value in values):
                found.add(device)
    return found


def _same(text, wanted) -> bool:
    try:
        return ipaddress.ip_address(str(text).split("/")[0]) == wanted
    except ValueError:
        return False


def _is_management(interface: str, device: str = "", cabling: "Topology | None" = None) -> bool:
    """Whether ``interface`` of ``device`` carries management, never production traffic.  The device's own management
    ports when the topology states them; otherwise the naming convention (Management*, Ma*, mgmt*, and eth0, which
    Containerlab gives every node as its management port)."""
    name = str(interface).lower()
    ports = (cabling.management_ports.get(device) if cabling is not None else None)
    if ports is not None:
        return name in {str(port).lower() for port in ports}
    return name.startswith(("management", "ma", "mgmt")) or name == "eth0"


def _by_name(evidence: dict, hostname: str) -> str:
    return next((device for device in evidence if device.lower() == str(hostname).lower()), "")


def adjacent(evidence: dict, device: str, interface: str, cabling: Topology | None = None) -> set[str]:
    """The devices ``device`` has an established routing adjacency with on ``interface`` (IS-IS UP, OSPF FULL).  For a
    cabled routed port with no such adjacency (a BGP or static next hop) the device at the other end of the cable."""
    found = set()
    for row in _facts(evidence, device, "isis") or []:
        if row.get("interface") == interface and row.get("state") == "UP" and _by_name(evidence, row.get("hostname")):
            found.add(_by_name(evidence, row["hostname"]))
    for row in _facts(evidence, device, "ospf") or []:
        if row.get("interface") == interface and str(row.get("state")).upper().startswith("FULL"):
            try:
                found |= owners(evidence, row.get("neighbor_id", "")) - {device}
            except ValueError:
                continue
    if not found and cabling is not None and cabling.cabled(device, interface) in evidence:
        found.add(cabling.cabled(device, interface))
    if not found:                                       # last: whoever holds an address on the subnet of that interface
        mine = {network for name, _ip, network in _addresses(evidence, device) if name == interface}
        found = {other for other in evidence if other != device and any(network in mine for _n, _ip, network in _addresses(evidence, other))}
    return found


def lookup(evidence: dict, device: str, address: str):
    """The route ``device`` forwards ``address`` with (longest match), or None when its routes are not readable."""
    routes = _facts(evidence, device, "routes")
    if routes is None:
        return None
    wanted, best = ipaddress.ip_address(address), None
    for route in routes:
        try:
            network = ipaddress.ip_network(route["prefix"])
        except (ValueError, KeyError):
            continue
        if network.version == wanted.version and wanted in network and (best is None or network.prefixlen > ipaddress.ip_network(best["prefix"]).prefixlen):  # pylint: disable=unsubscriptable-object  # best is not None on this branch
            best = route
    return best or {}


@dataclass
class Path:
    devices: tuple[str, ...] = ()       # every managed device a packet of the flow can pass (all equal-cost branches)
    complete: bool = False              # every branch was followed to the destination
    detail: str = ""
    hops: dict = field(default_factory=dict)            # device -> the devices it hands the packet to


def trace(evidence: dict, start, destination: str, *, ends=(), cabling: Topology | None = None) -> Path:
    """Follow ``destination`` hop by hop from the ``start`` devices.  A branch ends where the destination is connected or
    owned, or on a device named in ``ends``.  A branch that leaves through a management interface, has no route, cannot
    be resolved to a read device or loops makes the path incomplete."""
    seen, hops, problems = [], {}, []
    queue = [(device, 0) for device in start]
    target = ipaddress.ip_address(destination)
    while queue:
        device, depth = queue.pop(0)
        if device in seen:
            continue
        seen.append(device)
        if device in ends or device in owners(evidence, destination):
            continue
        route = lookup(evidence, device, destination)
        if route is None:
            problems.append(f"{device}: routes unreadable")
            continue
        if not route:
            problems.append(f"{device}: no route to {destination}")
            continue
        interfaces, kind = route.get("interfaces") or [], str(route.get("type", "")).lower()
        if any(_is_management(name, device, cabling) for name in interfaces):
            problems.append(f"{device}: {destination} leaves through the management interface")
            continue
        if kind.startswith(("connected", "kernel", "attached")) and not route.get("next_hops") and target in ipaddress.ip_network(route["prefix"]):
            continue                                    # on-link here: this device delivers it
        nexts, unresolved = set(), []
        for hop in route.get("next_hops") or []:
            if not ipaddress.ip_address(hop).is_link_local:
                nexts |= owners(evidence, hop) - {device}
        for interface in interfaces:
            found = adjacent(evidence, device, interface, cabling)
            if not found:
                unresolved.append(interface)
            nexts |= found
        if unresolved and nexts:                        # an equal-cost branch toward a device that could not be read: never dropped silently
            problems.append(f"{device}: {route.get('prefix')} also leaves through {', '.join(unresolved)} toward no device that was read")
        if not nexts:
            problems.append(f"{device}: next hop of {route.get('prefix')} is not a device that was read")
            continue
        if depth + 1 >= MAX_HOPS:
            problems.append(f"{device}: path longer than {MAX_HOPS} hops")
            continue
        hops[device] = tuple(sorted(nexts))
        queue += [(other, depth + 1) for other in sorted(nexts)]
    text = " > ".join("|".join(sorted(level)) for level in _levels(start, hops))
    return Path(tuple(seen), not problems and bool(seen), "; ".join(problems) or text, hops)


def merged(paths) -> Path:
    """The paths toward every address of one host as one: complete only if every one is; every device and hop of each."""
    paths = list(paths)
    if not paths:
        return Path(detail="host address unknown")
    hops = {}
    for path in paths:
        for device, nexts in path.hops.items():
            hops[device] = tuple(sorted(set(hops.get(device, ())) | set(nexts)))
    devices = tuple(dict.fromkeys(device for path in paths for device in path.devices))
    details = list(dict.fromkeys(path.detail for path in paths))
    return Path(devices, all(path.complete for path in paths), "; ".join(details), hops)


def _levels(start, hops) -> list[set]:
    levels, current, seen = [], set(start), set()
    while current and len(levels) < MAX_HOPS:
        levels.append(current)
        seen |= current
        current = {other for device in current for other in hops.get(device, ())} - seen
    return levels


# ------------------------------------------------------------------------------------------------------------- relations
@dataclass(frozen=True)
class Access:
    """A boundary router and the access side it serves, as the devices report it now."""

    router: str
    access_interface: str               # the router's interface toward its switch
    router_v6: str
    switch: str
    uplink: str                         # the switch's interface toward the router
    switch_v6: str
    transit: str                        # the switch's interface toward the other switch
    far_switch: str
    far_switch_v6: str
    peer_router: str                    # the boundary router behind the other switch
    peer_access_interface: str
    far_uplink: str
    cores: tuple[str, ...]              # the routers that hold an OSPFv3 adjacency with the router

    def as_dict(self) -> dict:
        return {key: list(value) if isinstance(value, tuple) else value for key, value in self.__dict__.items()}


def _isis_up(evidence, device) -> list[tuple[str, str]]:
    return sorted({(row.get("interface", ""), _by_name(evidence, row.get("hostname"))) for row in _facts(evidence, device, "isis") or []
                   if row.get("state") == "UP" and _by_name(evidence, row.get("hostname"))})


def _shared_v6(evidence, a: str, a_interface: str, b: str) -> tuple[str, str, str]:
    """(address of a, interface of b, address of b) on the IPv6 subnet ``a_interface`` shares with ``b``."""
    for interface, ip, network in _addresses(evidence, a):
        if interface != a_interface or ip.version != 6 or ip.is_link_local:
            continue
        for other_interface, other_ip, other_network in _addresses(evidence, b):
            if other_network == network and other_ip != ip:
                return str(ip), other_interface, str(other_ip)
    return "", "", ""


def ospfv3_peers(evidence: dict, device: str) -> tuple[str, ...]:
    """The read devices that report a FULL OSPFv3 adjacency with ``device`` (by its router id, one of its addresses)."""
    mine = {str(ip) for _interface, ip, _network in _addresses(evidence, device)}
    return tuple(sorted(other for other in evidence if other != device and any(
        row.get("family") == "OSPFV3" and str(row.get("state")).upper().startswith("FULL") and row.get("neighbor_id") in mine
        for row in _facts(evidence, other, "ospf") or [])))


def access_of(evidence: dict, router: str) -> tuple[Access | None, str]:
    """The access relations of ``router``, or (None, why) when the devices do not show exactly one such arrangement."""
    mine = _isis_up(evidence, router)
    if len(mine) != 1:
        return None, f"{router} has {len(mine)} IS-IS adjacencies up, expected the one toward its switch"
    access_interface, switch = mine[0]
    router_v6, uplink, switch_v6 = _shared_v6(evidence, router, access_interface, switch)
    others = [(interface, name) for interface, name in _isis_up(evidence, switch) if name != router]
    if not router_v6 or len(others) != 1:
        return None, f"{switch} does not show one uplink to {router} and one IS-IS adjacency to another switch"
    transit, far_switch = others[0]
    _mine, _far_interface, far_switch_v6 = _shared_v6(evidence, switch, transit, far_switch)
    peers = [(interface, name) for interface, name in _isis_up(evidence, far_switch) if name != switch]
    if not far_switch_v6 or len(peers) != 1:
        return None, f"{far_switch} does not show one transit to {switch} and one uplink to a boundary router"
    far_uplink, peer_router = peers[0]
    peer_access = next((interface for interface, name in _isis_up(evidence, peer_router) if name == far_switch), "")
    cores = ospfv3_peers(evidence, router)
    if not peer_access or not cores:
        return None, f"{peer_router} access adjacency or the OSPFv3 neighbours of {router} could not be read"
    return Access(router, access_interface, router_v6, switch, uplink, switch_v6, transit, far_switch, far_switch_v6, peer_router, peer_access, far_uplink, cores), ""


def role_of(topology: Topology, evidence: dict, device: str) -> str:
    """BOUNDARY_ROUTER: runs the access protocol (IS-IS) and the core protocol (OSPFv3) at once.  ACCESS_SWITCH: a host is
    cabled to it.  Anything else that forwards is TRANSIT."""
    if any(host.attached_to == device for host in topology.hosts.values()):
        return ACCESS_SWITCH
    if _isis_up(evidence, device) and any(row.get("family") == "OSPFV3" for row in _facts(evidence, device, "ospf") or []):
        return BOUNDARY_ROUTER
    return TRANSIT
