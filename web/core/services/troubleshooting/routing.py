"""Routing-aware troubleshooting: pure, read-only parsing and deterministic classification.

No ORM, no I/O, no clock reads (``now`` is always an argument), no model.  The inputs are the documents that the
registered read-only collectors already return (``collectors.COMMAND_CATALOG``): cEOS ``show ... | json`` and Linux/FRR
``ip -j route`` / ``vtysh -c '... json'``.

* adjacency parsing       cEOS OSPFv2 / OSPFv3 / BGP IPv4 / BGP IPv6, and FRR ospfd / ospf6d / bgpd, into ``faults.AdjacencySample``
* RIB parsing             cEOS ``show ip[v6] route`` and Linux ``ip -j -4|-6 route``, into ``RibEntry`` with a normalised source
                          protocol (rip, ospf, ospf_external, ospf3, ospf3_external, isis, bgp, connected, static, kernel, ra)
* route classification    MISSING_ROUTE / WRONG_NEXT_HOP / UNEXPECTED_SOURCE (a redistribution mismatch) against an
                          expectation that is ALWAYS labelled (learned baseline, or an operator/intent source); there is no
                          silent default expectation
* source-count collapse   a learned route source (e.g. RIP, redistributed OSPF externals, BGP) dropping to zero / by half
* redistribution          ``correlate_redistribution``: is the prefix still present in the origin protocol at the
                          redistributing router?  That separates "origin lost the route" from "redistribution broke"
* forwarding path         ``reconstruct_path``: hop-by-hop longest-prefix match over per-device RIBs, with next-hop
                          ownership from interface addresses; BLACKHOLE / LOOP / NO_EVIDENCE are reported, never guessed
* path-aware correlation  ``explain_by_path``: a route/flow symptom on a redundant topology is explained by a failed link only
                          if its baseline forwarding path traversed that link (complements ``correlation.correlate_alarms``)

Every RIB view is a RIB, not a validated FIB (see ``collectors``); results say so.
"""

from __future__ import annotations

import ipaddress
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Iterable

from . import faults

SCHEMA = "nmas.troubleshooting.routing/1"

# subtypes carried in Classification.evidence["subtype"] (the category stays ROUTE_OR_REACHABILITY_FAILURE /
# ROUTING_ADJACENCY_FAILURE, so the deterministic decision table -- DIAGNOSE_AND_ESCALATE, no registered write -- is unchanged)
MISSING_ROUTE = "MISSING_ROUTE"
WRONG_NEXT_HOP = "WRONG_NEXT_HOP"
UNEXPECTED_SOURCE = "UNEXPECTED_SOURCE"          # route present but from a different protocol: redistribution mismatch
SOURCE_COLLAPSE = "SOURCE_COLLAPSE"              # a whole learned route source vanished / halved

# path verdicts
DELIVERED = "DELIVERED"            # the destination is a connected address of the last hop
BLACKHOLE = "BLACKHOLE"            # a hop has no matching route (or a drop/reject route)
LOOP = "LOOP"
NO_EVIDENCE = "NO_EVIDENCE"        # the next device's RIB was not collected / next hop owner unknown: stop, do not guess
MAX_HOPS = 16

_CEOS_SOURCES = {
    "rip": "rip", "ospf": "ospf", "ospfinterarea": "ospf", "ospfintraarea": "ospf",
    "ospfexternaltype1": "ospf_external", "ospfexternaltype2": "ospf_external",
    "nssaexternaltype1": "ospf_external", "nssaexternaltype2": "ospf_external",
    "isisl1": "isis", "isisl2": "isis", "isis": "isis",
    "ebgp": "bgp", "ibgp": "bgp", "bgp": "bgp", "bgpaggregate": "bgp",
    "connected": "connected", "static": "static", "staticnonpersistent": "static", "dhcp": "dhcp", "attached": "connected",
    "internal": "internal", "dropped": "drop", "unreachable": "drop",
}
_V6_RENAME = {"ospf": "ospf3", "ospf_external": "ospf3_external"}
_LINUX_SOURCES = {"ospf": "ospf", "ospf6": "ospf3", "bgp": "bgp", "rip": "rip", "ripng": "rip", "isis": "isis", "static": "static",
                  "kernel": "connected", "ra": "ra", "dhcp": "dhcp", "boot": "static", "": "static", "zebra": "static"}
# sources that exist only because a router redistributes another protocol into it
REDISTRIBUTED_SOURCES = frozenset({"ospf_external", "ospf3_external"})


def _af(prefix: str) -> str:
    return "ipv6" if ":" in prefix else "ipv4"


def _norm_prefix(dst: str, af: str) -> str:
    if dst == "default":
        return "::/0" if af == "ipv6" else "0.0.0.0/0"
    if "/" not in dst:
        dst = f"{dst}/{128 if af == 'ipv6' else 32}"
    return str(ipaddress.ip_network(dst, strict=False))


# ------------------------------------------------------------------------------------------------------------- adjacencies
def _ceos_state(row: dict) -> str:
    return str(row.get("adjacencyState", ""))


def ceos_adjacency_samples(device: str, docs: dict, at: datetime) -> list[faults.AdjacencySample]:
    """docs: {"ospf", "ospf3", "bgp", "bgp6"} -> cEOS JSON (absent / ``{"errors": [...]}`` documents contribute nothing)."""
    out: list[faults.AdjacencySample] = []
    for key, entries, proto in (("ospf", "ospfNeighborEntries", "ospf"), ("ospf3", "ospf3NeighborEntries", "ospfv3")):
        for vrf in ((docs.get(key) or {}).get("vrfs") or {}).values():
            for inst in (vrf.get("instList") or {}).values():
                for n in inst.get(entries) or []:
                    out.append(faults.AdjacencySample(device, proto, str(n.get("routerId", "")), str(n.get("interfaceName", "")),
                                                      _ceos_state(n), at))
    for key, proto in (("bgp", "bgp"), ("bgp6", "bgp6")):
        for vrf in ((docs.get(key) or {}).get("vrfs") or {}).values():
            for peer, row in (vrf.get("peers") or {}).items():
                out.append(faults.AdjacencySample(device, proto, str(peer), "", str(row.get("peerState", "")), at))
    return out


def frr_adjacency_samples(device: str, docs: dict, at: datetime) -> list[faults.AdjacencySample]:
    """docs: {"ospf": vtysh 'show ip ospf neighbor json', "ospf6": 'show ipv6 ospf6 neighbor json', "bgp": 'show bgp summary json'}.

    FRR states are 'Full/Backup', 'Full/DR', '2-Way/DROther' ...: the adjacency part before '/' is the state.  FRR's
    ``peerState`` ("OK") is a session-admin flag, NOT the FSM state; the FSM state is ``state`` ("Established")."""
    out: list[faults.AdjacencySample] = []
    for rid, rows in ((docs.get("ospf") or {}).get("neighbors") or {}).items():
        for n in rows if isinstance(rows, list) else [rows]:
            state = str(n.get("nbrState") or n.get("state") or "").split("/", 1)[0]
            iface = str(n.get("ifaceName", "")).split(":", 1)[0]
            out.append(faults.AdjacencySample(device, "ospf", str(rid), iface, state.lower(), at))
    for n in (docs.get("ospf6") or {}).get("neighbors") or []:
        out.append(faults.AdjacencySample(device, "ospfv3", str(n.get("neighborId", "")), str(n.get("interfaceName", "")),
                                          str(n.get("state", "")).lower(), at))
    for afi, proto in (("ipv4Unicast", "bgp"), ("ipv6Unicast", "bgp6")):
        for peer, row in (((docs.get("bgp") or {}).get(afi) or {}).get("peers") or {}).items():
            out.append(faults.AdjacencySample(device, proto, str(peer), "", str(row.get("state", "")), at))
    return out


# ---------------------------------------------------------------------------------------------------------------------- RIB
@dataclass(frozen=True)
class RibEntry:
    prefix: str
    source: str                                   # normalised (see module docstring)
    raw_type: str
    next_hops: tuple = ()                         # ((address or "", interface or ""), ...) sorted
    af: str = "ipv4"

    @property
    def addresses(self) -> list[str]:
        return sorted({a for a, _i in self.next_hops if a})

    @property
    def interfaces(self) -> list[str]:
        return sorted({i for _a, i in self.next_hops if i})

    def as_dict(self) -> dict:
        return {"prefix": self.prefix, "source": self.source, "raw_type": self.raw_type, "af": self.af,
                "next_hops": [{"address": a, "interface": i} for a, i in self.next_hops]}


def ceos_rib(doc: dict | None, *, af: str | None = None) -> dict[str, RibEntry] | None:
    """cEOS ``show ip route | json`` / ``show ipv6 route | json`` (default VRF).  None = unreadable (never "empty")."""
    routes = (((doc or {}).get("vrfs") or {}).get("default") or {}).get("routes")
    if not isinstance(routes, dict):
        return None
    out: dict[str, RibEntry] = {}
    for prefix, row in routes.items():
        fam = af or _af(prefix)
        raw = str(row.get("routeType", ""))
        src = _CEOS_SOURCES.get(raw.lower(), raw.lower() or "unknown")
        if fam == "ipv6":
            src = _V6_RENAME.get(src, src)
        if row.get("routeAction") in ("drop", "reject"):
            src = "drop"
        hops = tuple(sorted((str(v.get("nexthopAddr", "") or ""), str(v.get("interface", "") or "")) for v in row.get("vias") or []))
        out[_norm_prefix(prefix, fam)] = RibEntry(_norm_prefix(prefix, fam), src, raw, hops, fam)
    return out


def linux_rib(rows: list | None, af: str) -> dict[str, RibEntry] | None:
    """Linux ``ip -j -4|-6 route show`` (main table; a kernel RIB view)."""
    if not isinstance(rows, list):
        return None
    out: dict[str, RibEntry] = {}
    for r in rows:
        if not isinstance(r, dict) or r.get("type") in ("unreachable", "blackhole", "prohibit"):
            if isinstance(r, dict) and r.get("dst"):
                p = _norm_prefix(str(r["dst"]), af)
                out[p] = RibEntry(p, "drop", str(r.get("type")), (), af)
            continue
        prefix = _norm_prefix(str(r.get("dst", "")), af)
        raw = str(r.get("protocol", ""))
        hops = [(str(r.get("gateway", "") or ""), str(r.get("dev", "") or ""))]
        if r.get("nexthops"):
            hops = [(str(n.get("gateway", "") or ""), str(n.get("dev", "") or "")) for n in r["nexthops"]]
        src = _LINUX_SOURCES.get(raw, raw or "static")
        if af == "ipv6":
            src = _V6_RENAME.get(src, src)                  # zebra labels ospf6d routes "ospf" in the kernel
        out[prefix] = RibEntry(prefix, src, raw, tuple(sorted(hops)), af)
    return out


def clab_links(topology: dict) -> list[dict]:
    """Links from a parsed Containerlab topology document: [{"a", "a_if", "b", "b_if"}] (kernel interface names)."""
    out = []
    for ln in ((topology or {}).get("topology") or {}).get("links") or []:
        ends = ln.get("endpoints") or []
        if len(ends) == 2 and all(":" in e for e in ends):
            (a, a_if), (b, b_if) = (e.split(":", 1) for e in ends)
            out.append({"a": a, "a_if": a_if, "b": b, "b_if": b_if})
    return out


def _kernel_if(interface: str) -> str:
    """cEOS EthernetN is kernel ethN; everything else is compared as-is."""
    return "eth" + interface[len("Ethernet"):] if interface.startswith("Ethernet") and interface[len("Ethernet"):].isdigit() else interface


def _link_peers(links: Iterable[dict], device: str, egress: str) -> set[str]:
    k = _kernel_if(egress)
    return {(ln["b"] if ln["a"] == device else ln["a"]) for ln in links
            if (ln["a"] == device and ln.get("a_if") == k) or (ln["b"] == device and ln.get("b_if") == k)}


def lpm(rib: dict[str, RibEntry], address: str) -> RibEntry | None:
    """Longest-prefix match (most specific wins; ties are impossible in a dict keyed by prefix)."""
    ip = ipaddress.ip_address(address)
    best, best_len = None, -1
    for prefix, entry in rib.items():
        net = ipaddress.ip_network(prefix)
        if net.version == ip.version and ip in net and net.prefixlen > best_len:
            best, best_len = entry, net.prefixlen
    return best


def source_counts(rib: dict[str, RibEntry]) -> dict[str, int]:
    return dict(sorted(Counter(e.source for e in rib.values()).items()))


def ceos_summary_counts(doc: dict | None, af: str) -> dict[str, int] | None:
    """cEOS ``show ip route summary | json`` / ``show ipv6 route summary | json`` -> the same normalised source names as
    ``source_counts`` (cheap: one small document instead of the full RIB).  None = unreadable."""
    v = (((doc or {}).get("vrfs") or {}).get("default"))
    if not isinstance(v, dict):
        return None
    six = af == "ipv6"
    ospf = v.get("ospfCounts6" if six else "ospfCounts") or {}
    ext = sum(int(ospf.get(k, 0) or 0) for k in ("ospfExternal1", "ospfExternal2", "nssaExternal1", "nssaExternal2"))
    out = {("ospf3" if six else "ospf"): int(ospf.get("ospfTotal", 0) or 0) - ext,
           ("ospf3_external" if six else "ospf_external"): ext,
           "bgp": int((v.get("bgpCounts6" if six else "bgpCounts") or {}).get("bgpTotal", 0) or 0),
           "isis": int((v.get("isisCounts6" if six else "isisCounts") or {}).get("isisTotal", 0) or 0),
           "connected": int(v.get("connected", 0) or 0), "static": int(v.get("static", 0) or 0)}
    if not six:
        out["rip"] = int(v.get("rip", 0) or 0)
    return dict(sorted(out.items()))


# ---------------------------------------------------------------------------------------------------- route classification
def classify_route_change(device: str, prefix: str, expected: RibEntry | dict, observed_rib: dict[str, RibEntry] | None, *,
                          now: datetime, expectation_source: str) -> faults.Classification:
    """Compare one expected route (exact prefix) with the device's current RIB.

    ``expectation_source`` is mandatory and recorded: a learned baseline is NOT intent, and the result says which it was."""
    exp = expected if isinstance(expected, RibEntry) else RibEntry(**{**expected, "next_hops": tuple(map(tuple, expected.get("next_hops", ())))})
    scope = {"device": device, "prefix": prefix, "af": exp.af}
    base_ev = {"expected": exp.as_dict(), "expectation_source": expectation_source, "rib_is_not_fib": True}
    if observed_rib is None:
        return faults.Classification(faults.INDETERMINATE, scope, False, faults.CAUSE_INSUFFICIENT, f"{device} route {prefix}: RIB unreadable",
                                     evidence={**base_ev, "observed": None})
    got = observed_rib.get(prefix)
    if got is None or got.source == "drop":
        covering = None if got else lpm({k: v for k, v in observed_rib.items() if k != prefix}, prefix.split("/")[0])
        return faults.Classification(
            faults.ROUTE_OR_REACHABILITY_FAILURE, scope, True, faults.CAUSE_UNDETERMINED,
            f"{device}: expected {exp.source} route {prefix} ({exp.af}) {'missing' if got is None else 'is a drop route'}"
            + (f"; traffic now follows covering {covering.prefix} via {covering.source}" if covering else ""),
            possible_causes=["routing adjacency loss toward the next hop", "origin withdrew or filtered the prefix",
                             "redistribution/route-map change at the redistributing router"]
            if exp.source in REDISTRIBUTED_SOURCES else ["routing adjacency loss toward the next hop", "origin withdrew or filtered the prefix"],
            evidence={**base_ev, "subtype": MISSING_ROUTE, "observed": got.as_dict() if got else None,
                      "covering_route": covering.as_dict() if covering else None},
            observed_at=now.isoformat())
    if got.source != exp.source:
        redist = exp.source in REDISTRIBUTED_SOURCES or got.source in REDISTRIBUTED_SOURCES
        return faults.Classification(
            faults.ROUTE_OR_REACHABILITY_FAILURE, scope, True, faults.CAUSE_UNDETERMINED,
            f"{device}: route {prefix} learned via {got.source} ({got.raw_type}), expected {exp.source} ({exp.raw_type})"
            + (" -- redistribution mismatch" if redist else ""),
            possible_causes=(["redistribution route-map/policy change", "origin protocol lost the route; a different source now wins"]
                             if redist else ["preferred protocol lost the route; a less-preferred source now wins",
                                             "administrative distance/policy change"]),
            evidence={**base_ev, "subtype": UNEXPECTED_SOURCE, "redistribution_related": redist, "observed": got.as_dict()},
            observed_at=now.isoformat())
    if exp.addresses and not set(got.addresses) & set(exp.addresses):
        return faults.Classification(
            faults.ROUTE_OR_REACHABILITY_FAILURE, scope, True, faults.CAUSE_UNDETERMINED,
            f"{device}: route {prefix} via {got.addresses or got.interfaces}, expected {exp.addresses}",
            possible_causes=["failover after a primary-path fault", "metric/cost/policy change"],
            evidence={**base_ev, "subtype": WRONG_NEXT_HOP, "observed": got.as_dict()}, observed_at=now.isoformat())
    return faults.Classification(faults.NO_FAULT, scope, False, faults.CAUSE_CONFIRMED, f"{device} route {prefix} present via expected source and next hop",
                                 evidence={**base_ev, "observed": got.as_dict()})


def classify_source_counts(device: str, af: str, baseline: dict[str, int], observed: dict[str, int] | None, *, now: datetime,
                           expectation_source: str, sources: Iterable[str] = ("rip", "ospf", "ospf_external", "ospf3", "ospf3_external",
                                                                              "isis", "bgp")) -> list[faults.Classification]:
    """A learned dynamic route source that vanished, or lost at least half its routes, on one device."""
    if observed is None:
        return [faults.Classification(faults.INDETERMINATE, {"device": device, "af": af}, False, faults.CAUSE_INSUFFICIENT,
                                      f"{device} {af} route summary unreadable", evidence={"expectation_source": expectation_source})]
    out = []
    for src in sources:
        was, now_n = int(baseline.get(src, 0)), int(observed.get(src, 0))
        if was <= 0 or now_n * 2 > was:
            continue
        redist = src in REDISTRIBUTED_SOURCES
        out.append(faults.Classification(
            faults.ROUTE_OR_REACHABILITY_FAILURE, {"device": device, "af": af, "source": src}, True, faults.CAUSE_UNDETERMINED,
            f"{device} {af}: {src} routes {was} -> {now_n}" + (" (redistributed routes lost)" if redist else ""),
            possible_causes=(["redistribution stopped at the redistributing router", "origin protocol lost its routes",
                              "adjacency loss toward the redistributing router"] if redist else
                             [f"{src} adjacency/process loss", "upstream withdrew the routes", "filtering/policy change"]),
            evidence={"subtype": SOURCE_COLLAPSE, "baseline_count": was, "observed_count": now_n, "expectation_source": expectation_source,
                      "redistribution_related": redist},
            observed_at=now.isoformat()))
    return out


def correlate_redistribution(prefix: str, *, redistributor: str, redistributor_rib: dict[str, RibEntry] | None, origin_sources: Iterable[str],
                             remote: dict[str, dict[str, RibEntry] | None], redistributed_source: str) -> dict[str, Any]:
    """Locate a redistribution fault domain for one prefix.

    origin present at the redistributor + absent (or not ``redistributed_source``) at every remote reader -> the
    redistribution step at ``redistributor`` is the fault domain (CONFIRMED for the domain, not for the root cause);
    origin absent at the redistributor -> the origin protocol lost the route (redistribution not implicated);
    any reader unreadable -> INSUFFICIENT_EVIDENCE for that reader, never assumed."""
    if redistributor_rib is None:
        return {"prefix": prefix, "verdict": "INSUFFICIENT_EVIDENCE", "reason": f"{redistributor} RIB unreadable"}
    origin = redistributor_rib.get(prefix)
    origin_ok = origin is not None and origin.source in set(origin_sources)
    readers, unreadable = {}, []
    for dev, rib in sorted(remote.items()):
        if rib is None:
            unreadable.append(dev)
            continue
        got = rib.get(prefix)
        readers[dev] = got.source if got else None
    missing = sorted(d for d, s in readers.items() if s != redistributed_source)
    if not origin_ok:
        verdict, reason = "ORIGIN_LOST", f"{prefix} absent from {sorted(origin_sources)} at {redistributor}: redistribution is not implicated"
    elif readers and len(missing) == len(readers):
        verdict, reason = "REDISTRIBUTION_FAULT_DOMAIN", (f"{prefix} present at {redistributor} via {origin.source} but not "
                                                          f"{redistributed_source} at {missing}")
    elif missing:
        verdict, reason = "PARTIAL", f"{prefix} missing as {redistributed_source} only at {missing}: suspect the path to those readers"
    else:
        verdict, reason = "CONSISTENT", f"{prefix} redistributed as {redistributed_source} everywhere it was read"
    return {"prefix": prefix, "verdict": verdict, "reason": reason, "redistributor": redistributor,
            "origin": origin.as_dict() if origin else None, "readers": readers, "unreadable": unreadable,
            "evidence_quality": "PARTIAL" if unreadable else "COMPLETE"}


# --------------------------------------------------------------------------------------------------------- forwarding paths
def ceos_addresses(addr4: dict | None, addr6: dict | None) -> dict[str, str]:
    """{ip: interface} from cEOS ``show ip interface brief | json`` and ``show ipv6 interface brief | json``."""
    out: dict[str, str] = {}
    for ifn, row in ((addr4 or {}).get("interfaces") or {}).items():
        ip = ((row.get("interfaceAddress") or {}).get("ipAddr") or {}).get("address")
        if ip and ip != "0.0.0.0":
            out[ip] = ifn
    for ifn, row in ((addr6 or {}).get("interfaces") or {}).items():
        for a in [row.get("linkLocal") or {}, *(row.get("addresses") or [])]:
            if a.get("address"):
                out[str(ipaddress.ip_address(a["address"]))] = ifn
    return out


def linux_addresses(rows: list | None) -> dict[str, str]:
    out: dict[str, str] = {}
    for link in rows or []:
        for a in link.get("addr_info") or []:
            if a.get("local") and a.get("scope") in ("global", "link"):
                out[str(ipaddress.ip_address(a["local"]))] = str(link.get("ifname", ""))
    return out


def owner_map(addresses: dict[str, dict[str, str]]) -> dict[str, list[tuple[str, str]]]:
    """{ip: [(device, interface), ...]}.  Link-local addresses can repeat across devices; callers disambiguate by link."""
    out: dict[str, list[tuple[str, str]]] = {}
    for dev, addrs in addresses.items():
        for ip, ifn in addrs.items():
            out.setdefault(ip, []).append((dev, ifn))
    return out


def _next_device(owners: dict, hop_addr: str, egress: str, device: str, links: Iterable[dict] | None) -> tuple[str | None, str]:
    cands = [o for o in owners.get(str(ipaddress.ip_address(hop_addr)), []) if o[0] != device] if hop_addr else []
    if len(cands) == 1:
        return cands[0][0], "next-hop address owner"
    peers = _link_peers(links, device, egress) if links is not None and egress else set()
    if len(cands) > 1 and peers:                          # link-local / anycast reused: keep the owner on our egress link
        on_link = [o for o in cands if o[0] in peers]
        if len(on_link) == 1:
            return on_link[0][0], "next-hop owner on the egress link"
    if len(peers) == 1:
        # The egress is a point-to-point cable with exactly one far end in the tracked topology (e.g. a host behind an
        # anycast/VARP gateway whose virtual address is owned by no single interface): that far end is the next device.
        return next(iter(peers)), "sole topology peer on the egress link"
    return None, "next-hop owner " + ("ambiguous" if cands else "unknown")


def reconstruct_path(source: str, destination: str, ribs: dict[str, dict[str, RibEntry] | None], addresses: dict[str, dict[str, str]], *,
                     links: Iterable[dict] | None = None, max_hops: int = MAX_HOPS) -> dict[str, Any]:
    """Hop-by-hop RIB walk from ``source`` toward ``destination``.  Only collected evidence is used: a missing RIB, an unknown
    next-hop owner or a multi-path fan-out that cannot be followed stops the walk with a stated reason."""
    owners = owner_map(addresses)
    dst = str(ipaddress.ip_address(destination))
    hops: list[dict] = []
    device, seen = source, []
    links = list(links) if links is not None else None
    while len(hops) < max_hops:
        if device in seen:
            return {"verdict": LOOP, "hops": hops, "reason": f"{device} visited twice", "rib_is_not_fib": True}
        seen.append(device)
        if dst in (addresses.get(device) or {}):
            return {"verdict": DELIVERED, "hops": hops, "delivered_to": device, "rib_is_not_fib": True}
        rib = ribs.get(device)
        if rib is None:
            return {"verdict": NO_EVIDENCE, "hops": hops, "reason": f"no RIB collected for {device}", "stopped_at": device, "rib_is_not_fib": True}
        entry = lpm(rib, dst)
        if entry is None or entry.source == "drop":
            return {"verdict": BLACKHOLE, "hops": hops, "reason": f"{device} has no usable route to {dst}", "stopped_at": device,
                    "rib_is_not_fib": True}
        hop = {"device": device, "prefix": entry.prefix, "source": entry.source, "next_hops": [list(h) for h in entry.next_hops]}
        if entry.source == "connected" or not entry.addresses:
            egress = entry.interfaces[0] if entry.interfaces else ""
            nxt = [o for o in owners.get(dst, []) if o[0] != device]
            hop.update(egress=egress, next_device=nxt[0][0] if len(nxt) == 1 else None, how="destination on a connected network")
            hops.append(hop)
            if len(nxt) != 1:
                return {"verdict": NO_EVIDENCE, "hops": hops, "reason": f"{dst} on {device}'s connected network but its owner was not collected",
                        "stopped_at": device, "rib_is_not_fib": True}
            device = nxt[0][0]
            continue
        nexts = []
        for addr, egress in entry.next_hops:
            nd, how = _next_device(owners, addr, egress, device, links)
            nexts.append((nd, egress, addr, how))
        hop["candidates"] = [{"device": n, "egress": e, "address": a, "how": h} for n, e, a, h in nexts]
        known = sorted({n for n, *_ in nexts if n})
        if len(known) != 1 or any(n is None for n, *_ in nexts):
            hops.append(hop)
            return {"verdict": NO_EVIDENCE, "hops": hops, "stopped_at": device,
                    "reason": "ECMP fan-out across devices (each branch must be walked separately)" if len(known) > 1 else nexts[0][3],
                    "rib_is_not_fib": True}
        hop.update(egress=nexts[0][1], next_device=known[0], how=nexts[0][3])
        hops.append(hop)
        device = known[0]
    return {"verdict": LOOP, "hops": hops, "reason": f"more than {max_hops} hops", "rib_is_not_fib": True}


def reconstruct_all_paths(source: str, destination: str, ribs: dict[str, dict[str, RibEntry] | None], addresses: dict[str, dict[str, str]], *,
                          links: Iterable[dict] | None = None, max_branches: int = 8) -> dict[str, Any]:
    """Every ECMP branch walked separately (bounded).  Each branch is a ``reconstruct_path``-shaped dict; the summary verdict is
    DELIVERED only if every branch is delivered, BLACKHOLE/LOOP if any branch is, else NO_EVIDENCE."""
    links = list(links) if links is not None else None
    owners = owner_map(addresses)
    done: list[dict] = []
    todo: list[tuple[str, list[dict]]] = [(source, [])]
    while todo and len(done) + len(todo) <= max_branches:
        start, prefix_hops = todo.pop(0)
        p = reconstruct_path(start, destination, ribs, addresses, links=links)
        hops = prefix_hops + p["hops"]
        if p["verdict"] == NO_EVIDENCE and p.get("reason", "").startswith("ECMP"):
            fan = hops[-1]
            branches = sorted({c["device"] for c in fan.get("candidates", []) if c.get("device")})
            for b in branches:
                cand = next(c for c in fan["candidates"] if c["device"] == b)
                todo.append((b, hops[:-1] + [{**fan, "egress": cand["egress"], "next_device": b, "how": cand["how"] + " (ECMP branch)"}]))
            continue
        loop = len({h["device"] for h in hops}) != len(hops)
        done.append({**p, "hops": hops, "verdict": LOOP if loop else p["verdict"]})
    if todo:
        done.append({"verdict": NO_EVIDENCE, "hops": [], "reason": f"more than {max_branches} ECMP branches", "rib_is_not_fib": True})
    verdicts = {d["verdict"] for d in done}
    overall = (DELIVERED if verdicts == {DELIVERED} else BLACKHOLE if BLACKHOLE in verdicts else LOOP if LOOP in verdicts else NO_EVIDENCE)
    return {"verdict": overall, "branches": done, "destination": str(ipaddress.ip_address(destination)), "source": source,
            "owners_known": len(owners), "rib_is_not_fib": True}


def path_links(path: dict) -> list[tuple[str, str, str]]:
    """[(device, egress interface, next device)] for every resolved hop."""
    return [(h["device"], h.get("egress", ""), h.get("next_device") or "") for h in path.get("hops", []) if h.get("next_device")]


def explain_by_path(symptom: dict, failed: dict, baseline_paths: dict[str, dict], *,
                    l2_members: dict[tuple[str, str], Iterable[str]] | None = None) -> tuple[bool, str]:
    """Is a route/flow symptom explained by a failed link because its BASELINE forwarding path used that link?

    symptom: {"id", "device", "kind", "flow"?: path key}; failed: {"a", "a_if", "b", "b_if"} (kernel names);
    baseline_paths: {path key: reconstruct_path() or reconstruct_all_paths()}.  A hop that egresses a routed VLAN interface
    (SVI) is matched to a physical port only through ``l2_members`` {(device, "Vlan101"): ["eth1", ...]}; without it the
    SVI hop is not claimed (no guessing).  Complements ``correlation.correlate_alarms`` rule R3, which on a redundant
    topology rejects such a symptom because the device stays reachable from the vantage."""
    key = symptom.get("flow")
    path = baseline_paths.get(key) if key else None
    if not path:
        return False, "no baseline forwarding path recorded for this symptom"
    ends = {(failed["a"], failed.get("a_if", "")), (failed["b"], failed.get("b_if", ""))}
    branches = path.get("branches") or [path]
    for br in branches:
        for dev, egress, _nxt in path_links(br):
            ports = {_kernel_if(egress)} | set((l2_members or {}).get((dev, egress), ()))
            hit = next((p for p in ports if (dev, p) in ends), None)
            if hit:
                scope = "every" if len(branches) == 1 else "an ECMP"
                return True, f"{scope} baseline forwarding branch of {key} egressed {dev}:{egress} ({hit}), an end of the failed link"
    return False, f"baseline forwarding path {key} did not traverse the failed link"


def correlate_with_paths(alarms: list[dict], links: list[dict], *, vantage: str, baseline_paths: dict[str, dict],
                         l2_members: dict | None = None, **kw) -> dict[str, Any]:
    """``correlation.correlate_alarms`` plus path awareness: an alarm that R3 rejected (redundant topology) and that carries a
    ``flow`` key is re-examined with ``explain_by_path`` and, if its baseline forwarding path used the failed link, moved to
    that group's symptoms with the reason.  Everything else -- grouping, time window, unrelated reporting -- is unchanged, so
    unrelated faults stay independent incidents."""
    from . import correlation

    out = correlation.correlate_alarms(alarms, links, vantage=vantage, **kw)
    by_id = {a["id"]: a for a in alarms}
    moved: set[str] = set()
    for g in out["groups"]:
        keep = []
        for r in g["rejected"]:
            a = by_id.get(r["id"], {})
            ok, why = (False, "")
            if r["id"] not in moved and a.get("flow") and "topology-inconsistent" in r["reason"]:
                ok, why = explain_by_path(a, g["cause_link"], baseline_paths, l2_members=l2_members)
            if ok:
                g["symptoms"].append({"id": r["id"], "device": r["device"], "kind": r["kind"], "reason": "path: " + why})
                g["alert_ids"].append(r["id"])
                moved.add(r["id"])
            else:
                keep.append(r)
        g["rejected"] = keep
        if any(s["reason"].startswith("path: ") for s in g["symptoms"]):
            g["rules"] = [*g["rules"], "R5 baseline forwarding path traversed the failed link (routing-aware)"]
    out["unrelated"] = [u for u in out["unrelated"] if u["id"] not in moved]
    out["grouped_alarms"] += len(moved)
    return out


def flow_impact(path_before: dict, path_now: dict | None) -> dict[str, Any]:
    """Service-flow impact class from two path reconstructions of the same flow (RIB-based)."""
    if path_now is None or path_now.get("verdict") == NO_EVIDENCE:
        return {"impact": "UNKNOWN", "reason": (path_now or {}).get("reason", "current path not reconstructed")}
    if path_now["verdict"] in (BLACKHOLE, LOOP):
        return {"impact": "BROKEN", "reason": path_now.get("reason", path_now["verdict"])}
    before = [h["device"] for h in path_before.get("hops", [])]
    now_ = [h["device"] for h in path_now.get("hops", [])]
    if before == now_ and path_links(path_before) == path_links(path_now):
        return {"impact": "UNCHANGED", "path": now_}
    return {"impact": "REROUTED", "before": before, "after": now_}


@dataclass
class EvidenceItem:
    """Freshness wrapper for multi-device evidence: anything older than ``max_age_s`` at ``now`` is excluded and reported."""
    device: str
    kind: str
    observed_at: datetime | None
    max_age_s: int = 120
    payload: Any = field(default=None, repr=False)

    def fresh(self, now: datetime) -> bool:
        return self.observed_at is not None and 0 <= (now - self.observed_at).total_seconds() <= self.max_age_s


def evidence_quality(items: Iterable[EvidenceItem], *, now: datetime, required_devices: Iterable[str]) -> dict[str, Any]:
    items = list(items)
    fresh = {(i.device, i.kind) for i in items if i.fresh(now)}
    stale = sorted({f"{i.device}:{i.kind}" for i in items if not i.fresh(now)})
    missing = sorted(d for d in set(required_devices) if not any(f[0] == d for f in fresh))
    quality = "COMPLETE" if not stale and not missing else ("PARTIAL" if fresh else "NONE")
    return {"quality": quality, "stale": stale, "missing_devices": missing, "fresh": sorted(f"{d}:{k}" for d, k in fresh)}
