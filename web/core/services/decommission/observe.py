"""The read-only live observation behind decommission readiness and the traffic transition.

    activity     each monitored production flow's sender and receiver count their own unicast IP packets over a window
                 (``/proc/net/snmp`` / ``snmp6``); any packet both ways makes the flow ACTIVE, none QUIESCED, unreadable UNKNOWN
    path         derived hop by hop from the routers' live RIBs (``show ip|ipv6 route <dst> | json``), each next hop resolved to
                 the OSPF neighbor on the egress interface -- never from device names or adjacent addresses
    alternate    the FULL OSPF adjacency graph of that family with the device removed still connects the flow's two gateways
    mechanism    the device's own OSPF process of that family (``readiness.mechanisms``)

Routers are read through ``routers[name](command) -> text`` (the executor's ``show`` in production and in the fixture); hosts
through ``hosts[name]() -> counters``.  Whatever cannot be read becomes a blind spot or an UNKNOWN, which readiness refuses.
"""

from __future__ import annotations

import ipaddress
import json
import time
from datetime import datetime, timezone

import networkx as nx

from ..maintenance_mode import model
from . import eos
from .readiness import Observation

ROUTE = {model.IPV4: "show ip route {} | json", model.IPV6: "show ipv6 route {} | json"}
NEIGHBORS = {model.IPV4: ("show ip ospf neighbor | json", "ospfNeighborEntries"), model.IPV6: ("show ipv6 ospf neighbor | json", "ospf3NeighborEntries")}
MAX_HOPS = 12


def proc_counters(snmp: str, snmp6: str) -> dict:
    """{IPV4: {out, in}, IPV6: {out, in}} unicast IP packets a host sent / delivered (ND and multicast excluded for IPv6)."""
    v4, lines = {}, [line.split() for line in (snmp or "").splitlines() if line.startswith("Ip:")]
    if len(lines) >= 2 and len(lines[0]) == len(lines[1]):
        v4 = dict(zip(lines[0][1:], lines[1][1:]))
    v6 = dict(line.split()[:2] for line in (snmp6 or "").splitlines() if len(line.split()) >= 2)

    def number(table, key):
        value = table.get(key)
        return int(value) if value is not None and str(value).lstrip("-").isdigit() else None

    out = {}
    if number(v4, "OutRequests") is not None and number(v4, "InDelivers") is not None:
        out[model.IPV4] = {"out": number(v4, "OutRequests"), "in": number(v4, "InDelivers")}
    keys = ("Ip6OutRequests", "Ip6OutMcastPkts", "Ip6InDelivers", "Ip6InMcastPkts", "Icmp6OutNeighborSolicits",
            "Icmp6OutNeighborAdvertisements", "Icmp6InNeighborSolicits", "Icmp6InNeighborAdvertisements")
    if all(number(v6, k) is not None for k in keys):
        out[model.IPV6] = {
            "out": number(v6, "Ip6OutRequests") - number(v6, "Ip6OutMcastPkts") - number(v6, "Icmp6OutNeighborSolicits")
            - number(v6, "Icmp6OutNeighborAdvertisements"),
            "in": number(v6, "Ip6InDelivers") - number(v6, "Ip6InMcastPkts") - number(v6, "Icmp6InNeighborSolicits")
            - number(v6, "Icmp6InNeighborAdvertisements")}
    return out


def _json(text: str) -> dict:
    try:
        value = json.loads(text or "")
    except ValueError:
        return {}
    return value if isinstance(value, dict) else {}


def _default_vrf(document: dict) -> dict:
    return ((document.get("vrfs") or {}).get("default") or {})


class LiveObserver:
    """``flows``: [{label, workload, family, direction, sender, receiver, src_gateway, dst_gateway, destination}]."""

    def __init__(self, *, routers: dict, hosts: dict, flows: list[dict], window_seconds: float = 10.0, sleep=time.sleep):
        self.routers, self.hosts, self.flows = dict(routers), dict(hosts), list(flows)
        self.window_seconds, self.sleep = float(window_seconds), sleep

    # -- reads -------------------------------------------------------------------------------------------------------------
    def _read(self, router: str, command: str) -> str | None:
        reader = self.routers.get(router)
        if reader is None:
            return None
        try:
            return reader(command)
        except Exception:  # pylint: disable=broad-exception-caught  # noqa: BLE001 - an unreadable router is a blind spot, never a fact
            return None

    def router_ids(self) -> dict:
        """{OSPF router-id: router name} for every readable router (OSPFv2 and OSPFv3 ids)."""
        found = {}
        for name in self.routers:
            for command in ("show ip ospf | json", "show ipv6 ospf | json"):
                for inst in (_default_vrf(_json(self._read(name, command))).get("instList") or {}).values():
                    if inst.get("routerId"):
                        found[str(inst["routerId"])] = name
        return found

    def neighbors(self, family: str) -> dict:
        """{router: [{"peer_id", "interface", "state"}]} from each router's live OSPF neighbor table (None = unreadable)."""
        command, key = NEIGHBORS[family]
        table = {}
        for name in self.routers:
            text = self._read(name, command)
            if text is None:
                table[name] = None
                continue
            entries = []
            for inst in (_default_vrf(_json(text)).get("instList") or {}).values():
                for entry in inst.get(key) or []:
                    entries.append({"peer_id": str(entry.get("routerId", "")), "interface": str(entry.get("interfaceName", "")),
                                    "state": str(entry.get("adjacencyState", "")).lower()})
            table[name] = entries
        return table

    def adjacency_graph(self, family: str, neighbors: dict, ids: dict) -> nx.Graph:
        graph = nx.Graph()
        graph.add_nodes_from(self.routers)
        for name, entries in neighbors.items():
            for entry in entries or []:
                peer = ids.get(entry["peer_id"])
                if peer and entry["state"] == "full":
                    graph.add_edge(name, peer)
        return graph

    def path(self, flow: dict, neighbors: dict, ids: dict) -> list[str] | None:
        """The routers the flow's packets traverse from its source gateway, derived from live RIBs; None when not derivable."""
        here, hops = flow["src_gateway"], []
        for _ in range(MAX_HOPS):
            hops.append(here)
            routes = _default_vrf(_json(self._read(here, ROUTE[flow["family"]].format(flow["destination"])) or "")).get("routes") or {}
            if not routes:
                return None
            route = next(iter(routes.values()))
            if route.get("directlyConnected"):
                return hops
            vias = route.get("vias") or []
            if len(vias) != 1:
                return None                       # ECMP: the flow's exact hop is not derivable from the RIB alone
            interface = vias[0].get("interface", "")
            peers = [ids.get(e["peer_id"]) for e in (neighbors.get(here) or []) if e["interface"] == interface and e["state"] == "full"]
            if len(peers) != 1 or not peers[0] or peers[0] in hops:
                return None
            here = peers[0]
        return None

    def counters(self) -> dict:
        found = {}
        for name, reader in self.hosts.items():
            try:
                found[name] = reader() or {}
            except Exception:  # pylint: disable=broad-exception-caught  # noqa: BLE001 - an unreadable host leaves its flows UNKNOWN
                found[name] = {}
        return found

    # -- the observation ---------------------------------------------------------------------------------------------------
    def observe(self, device: str, *, window_seconds: float | None = None) -> Observation:
        started = datetime.now(timezone.utc)
        before = self.counters()
        self.sleep(self.window_seconds if window_seconds is None else window_seconds)
        after = self.counters()
        finished = datetime.now(timezone.utc)
        ids = self.router_ids()
        observation = Observation(device=device, window={"started": started.isoformat(), "finished": finished.isoformat(),
                                                         "seconds": round((finished - started).total_seconds(), 3)})
        config = self._read(device, "show running-config")
        if config is None:
            observation.blind_spots.append(f"{device}: running configuration unreadable")
        observation.ospf = eos.ospf_processes(config or "")
        graphs, tables = {}, {}
        for family in model.FAMILIES:
            tables[family] = self.neighbors(family)
            unreadable = sorted(name for name, entries in tables[family].items() if entries is None)
            if unreadable:
                observation.blind_spots.append(f"{family}: OSPF neighbors unreadable on {', '.join(unreadable)}")
            graphs[family] = self.adjacency_graph(family, tables[family], ids)
            observation.adjacencies[family] = {
                "device": sorted(ids.get(e["peer_id"], e["peer_id"]) for e in (tables[family].get(device) or []) if e["state"] == "full"),
                "graph": sorted(sorted(edge) for edge in graphs[family].edges())}
        for name in self.hosts:
            observation.counters[name] = {family: {"before": (before.get(name) or {}).get(family), "after": (after.get(name) or {}).get(family)}
                                          for family in model.FAMILIES}
        cell_alternates: dict = {}
        for spec in self.flows:
            family, label = spec["family"], spec["label"]
            sent = _delta(before, after, spec["sender"], family, "out")
            got = _delta(before, after, spec["receiver"], family, "in")
            if sent is None or got is None:
                activity, evidence = model.UNKNOWN, "host counters unreadable"
            elif sent > 0 and got > 0:
                activity, evidence = model.ACTIVE, f"{sent} unicast packets sent, {got} delivered in {observation.window['seconds']} s"
            elif sent == 0 and got == 0:
                activity, evidence = model.QUIESCED, f"no unicast packet in {observation.window['seconds']} s"
            else:
                activity, evidence = model.ACTIVE, f"one-way unicast traffic ({sent} sent, {got} delivered)"
            hops = self.path(spec, tables[family], ids)
            observation.paths[label] = {"path": " > ".join(hops or []), "complete": hops is not None}
            on_device = None if hops is None else device in hops
            observation.flows.append(model.Flow(label, spec["workload"], family, spec["direction"], model.PRODUCTION, activity, evidence, on_device))
            if on_device is not False:
                gateways = (spec["src_gateway"], spec["dst_gateway"])
                if device in gateways:
                    healthy = False                     # the device is the flow's own gateway: nothing can carry it around the device
                else:
                    reduced = graphs[family].copy()
                    if reduced.has_node(device):
                        reduced.remove_node(device)
                    healthy = all(reduced.has_node(g) for g in gateways) and nx.has_path(reduced, *gateways)
                key = (family, spec["direction"])
                cell_alternates[key] = healthy if cell_alternates.get(key, True) is not False else False
        observation.alternates = cell_alternates
        return observation


def _delta(before: dict, after: dict, host: str, family: str, key: str) -> int | None:
    first = ((before.get(host) or {}).get(family) or {}).get(key)
    last = ((after.get(host) or {}).get(family) or {}).get(key)
    if not isinstance(first, int) or not isinstance(last, int) or last < first:
        return None
    return last - first


def flow_specs(*, workload: str, sender: str, receiver: str, sender_gateway: str, receiver_gateway: str, addresses: dict) -> list[dict]:
    """The four monitored cells of one bidirectional dual-stack production relation (``addresses``: {host: {IPV4, IPV6}})."""
    specs = []
    for family in model.FAMILIES:
        for direction, (src, dst, sgw, dgw) in ((model.NORTHBOUND, (sender, receiver, sender_gateway, receiver_gateway)),
                                                (model.SOUTHBOUND, (receiver, sender, receiver_gateway, sender_gateway))):
            destination = str(ipaddress.ip_address(addresses[dst][family]))
            specs.append({"label": f"{src}->{dst} {family}", "workload": f"{src} to {dst}", "family": family, "direction": direction,
                          "sender": src, "receiver": dst, "src_gateway": sgw, "dst_gateway": dgw, "destination": destination})
    return specs
