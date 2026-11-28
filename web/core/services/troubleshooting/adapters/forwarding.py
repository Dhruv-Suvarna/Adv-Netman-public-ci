"""Forwarding source adapter: RIB route and ARP/ND neighbour evidence for HC10 / HC15 / HC24 (RB01 host connectivity), from existing read-only CLI commands.

Flow: ``collectors.CliCollector`` (catalogue ``ip_route``/``ipv6_route``/``route4``/``route6``/``arp``/``ipv6_neighbors``/``neigh``) -> ``normalization.normalize_routes`` /
``normalize_neighbor_table`` (parsers ``route.table`` / ``neighbor.table``, version gated) -> ``runtime.map_observations`` -> engine keys
``route.rib@<prefix>`` and ``arp.entry@<address>`` with the exact value contracts the runbook reads:

* ``route.rib``  ``{present, prefix, matched_prefix, exact, next_hop, next_hop_device, ...}``  (HC15 forward path, HC24 return path)
* ``arp.entry``  ``{state, mac, dup_macs, ...}``  (HC10 first-hop resolution)

What this module refuses to do
* FIB is NEVER synthesised from the RIB.  ``route.fib`` stays an explicit unavailable gap (``fib_gap_reason``) unless a distinct, injected, authoritative forwarding
  source (``RuntimeDeps.fib_source`` -> ``collectors.FibCollector`` -> ``normalization.normalize_fib_state`` -> ``fib_lookup``) supplies it; see docs/troubleshooting/fib-source.md.
  A Linux ``ip route`` table is the kernel routing table, reported as such, not as independent FIB evidence.
* Route absence is only asserted from a COMPLETE (untruncated, fully parsed) table of the right VRF and family; otherwise the answer is UNKNOWN.
* A missing ARP/ND cache entry is a cache fact: it is UNKNOWN, never "unresolved".  Only an entry the device itself reports FAILED/INCOMPLETE is a resolution failure.

Nothing here touches a device; the context is caller-owned, per case.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from typing import Iterable

from .. import normalization as nz

SOURCE_VERSION = "1.0.0"
PARSER_IDS = ("route.table", "neighbor.table")
SUPPORTED = {"ceos": {"os_min": "4.28", "os_max_exclusive": "5.0", "commands": ["show ip route | json", "show ipv6 route | json", "show ip arp | json", "show ipv6 neighbors | json"]},
             "linux": {"os_min": "5.0", "commands": ["ip -j -4 route show", "ip -j -6 route show", "ip -j neigh show"]}}
LIVE, RECORDED, SIMULATED = "LIVE_GATEWAY_PINNED", "RECORDED", "SIMULATED"
FIB_GAP_REASON = ("UNSUPPORTED_OPERATION: no independent validated forwarding-table (FIB) source is available; the FIB is never derived from the RIB, "
                  "so RIB/FIB consistency is UNKNOWN")
USABLE_STATES = ("REACHABLE", "STALE", "DELAY", "PROBE")        # states HC10 accepts as resolved
FAILED_STATES = ("FAILED", "INCOMPLETE")
_STATE_RANK = {s: i for i, s in enumerate(("REACHABLE", "DELAY", "PROBE", "STALE", "PERMANENT", "NOARP", "INCOMPLETE", "FAILED"))}


@dataclass
class ForwardingContext:
    """``RuntimeDeps.forwarding_context``.  All maps come from authoritative intent (NetBox), never from the device being judged.

    ``address_owners``  next-hop IP -> device name;  ``link_peers`` (device, interface) -> device on the other end (used when a hop has no address);
    ``gateways``        device -> first-hop IPs whose ARP/ND state is asked;  ``extra_prefixes`` more prefixes to answer on every device."""

    address_owners: dict = field(default_factory=dict)
    link_peers: dict = field(default_factory=dict)
    gateways: dict = field(default_factory=dict)
    extra_prefixes: tuple = ()


@dataclass(frozen=True)
class RouteQuery:
    prefix: str
    vrf: str
    family: str


def _net(text):
    try:
        return ipaddress.ip_network(str(text), strict=False)
    except ValueError:
        return None


def route_queries(flow: dict | None, ctx: ForwardingContext | None = None) -> list[RouteQuery]:
    """Prefixes the runbook will ask about: forward (``dst_prefix``) and return (``src_prefix``) destinations of the production flow, in the flow's VRF."""
    flow = flow or {}
    vrf = str(flow.get("vrf") or "default")
    seen, out = set(), []
    for text in (flow.get("dst_prefix"), flow.get("src_prefix"), *(ctx.extra_prefixes if ctx else ())):
        net = _net(text) if text else None
        if net is None or str(net) in seen:
            continue
        seen.add(str(net))
        out.append(RouteQuery(str(net), vrf, "ipv4" if net.version == 4 else "ipv6"))
    return out


def wanted_families(flow: dict | None, ctx: ForwardingContext | None = None) -> set:
    """Address families whose tables are worth reading.  No prefix known => IPv4 only (the existing default); IPv6 tables are read only when asked."""
    fams = {q.family for q in route_queries(flow, ctx)}
    for gws in (ctx.gateways.values() if ctx else ()):
        for g in gws:
            try:
                fams.add("ipv6" if ipaddress.ip_address(g).version == 6 else "ipv4")
            except ValueError:
                pass
    return fams or {"ipv4"}


def gateway_subjects(device: str, ctx: ForwardingContext | None) -> list[str]:
    out = []
    for g in (ctx.gateways.get(device, ()) if ctx else ()):
        try:
            out.append(str(ipaddress.ip_address(g)))
        except ValueError:
            continue
    return out


def _owner(ctx: ForwardingContext | None, device: str, hop: dict):
    if ctx is None:
        return None
    addr = hop.get("address")
    if addr and addr in ctx.address_owners:
        return ctx.address_owners[addr]
    if not addr and hop.get("interface"):
        return ctx.link_peers.get((device, hop["interface"]))
    return None


def rib_lookup(tables: Iterable[dict], query: RouteQuery, *, device: str, ctx: ForwardingContext | None = None):
    """-> ``(value, reason)``.  ``value`` is the ``route.rib`` contract or ``None`` (UNKNOWN, with ``reason``).  Longest covering prefix wins; discard routes win like any other."""
    tables = [t for t in tables if t["value"].get("vrf") == query.vrf and t["value"].get("family") == query.family]
    if not tables:
        return None, f"no {query.family} routing table for VRF {query.vrf} was collected (the collected command may not cover it)"
    value = tables[0]["value"]
    q = _net(query.prefix)
    best, best_len = [], -1
    for r in value["routes"]:
        net = _net(r["prefix"])
        if net is None or net.version != q.version or not net.supernet_of(q):
            continue
        if net.prefixlen > best_len:
            best, best_len = [r], net.prefixlen
        elif net.prefixlen == best_len:
            best.append(r)
    base = {"prefix": query.prefix, "vrf": query.vrf, "family": query.family, "table_kind": value.get("table_kind"), "fib_evidence": False, "table_complete": bool(value.get("complete"))}
    if not best:
        if not value.get("complete"):
            return None, "routing table is incomplete (truncated or partially parsed): absence of a covering route cannot be asserted"
        return {**base, "present": False, "matched_prefix": None, "exact": False, "next_hop": None, "next_hops": [], "next_hop_device": None, "next_hop_devices": [],
                "reason": "NO_COVERING_ROUTE"}, None
    # kernel / EOS preference: lowest preference then lowest metric; equal-best routes are ECMP
    def key(r):
        return (r.get("preference") if r.get("preference") is not None else 0, r.get("metric") if r.get("metric") is not None else 0)
    top = min(key(r) for r in best)
    chosen = [r for r in best if key(r) == top]
    hops = [h for r in chosen for h in r["next_hops"]]
    discard = next((r["discard"] for r in chosen if r.get("discard")), None)
    matched = chosen[0]["prefix"]
    common = {**base, "matched_prefix": matched, "exact": matched == query.prefix, "protocol": chosen[0]["protocol"], "metric": chosen[0].get("metric"),
              "preference": chosen[0].get("preference"), "connected": all(r.get("connected") for r in chosen)}
    if discard:
        return {**common, "present": False, "discard": discard, "next_hop": None, "next_hops": [], "next_hop_device": None, "next_hop_devices": [], "reason": "DISCARD_ROUTE"}, None
    owners = [_owner(ctx, device, h) for h in hops]
    resolved = sorted({o for o in owners if o})
    single = resolved[0] if len(resolved) == 1 and all(owners) else None      # ECMP / unresolved hops never claim one device
    first = next((h["address"] for h in hops if h.get("address")), None)
    return {**common, "present": True, "next_hop": first, "next_hops": hops, "next_hop_device": single, "next_hop_devices": resolved,
            "next_hops_unresolved": sum(1 for o in owners if not o), "ecmp": len(hops) > 1}, None


FIB_QUALIFICATION = (
    "authoritative forwarding-plane source identity (id, kind in normalization.FIB_SOURCE_KINDS, authoritative=true, derived_from_rib=false)",
    "platform + OS version equal to the admitted device, and a SUPPORTED capability naming the read-only API",
    "VRF / address-family / coverage (FULL_TABLE or PREFIX_LOOKUP with the queried prefixes) equal to the asked scope",
    "completeness (source-reported, untruncated, no entry rejected) and an explicit restart/convergence statement (converging=false)",
    "provenance label + collected_at; LIVE_GATEWAY_PINNED only for a gateway-recorded run, never from this module",
    "external qualification on real platforms (cEOS/IOS-XE/FRR+kernel FIB) is NOT performed by this module: fixtures are SIMULATED unless gateway-recorded")


def fib_requests(flow: dict | None, ctx: ForwardingContext | None = None) -> list[dict]:
    """One bounded read per (VRF, family) covering every asked prefix: ``[{vrf, family, prefixes}]``."""
    groups: dict[tuple, list] = {}
    for q in route_queries(flow, ctx):
        groups.setdefault((q.vrf, q.family), []).append(q.prefix)
    return [{"vrf": v, "family": f, "prefixes": p} for (v, f), p in sorted(groups.items())]


def fib_lookup(tables: Iterable[dict], query: RouteQuery):
    """-> ``(value, reason)``; ``value`` is the ``route.fib`` contract ``{installed, next_hop, resolved, ...}`` or ``None`` (UNKNOWN, with ``reason``).

    Absence (``installed=False``) is asserted only from a COMPLETE table of the right VRF/family: FULL_TABLE (longest covering entry) or PREFIX_LOOKUP that lists the
    query.  An incomplete table answers only with an EXACT entry (a more specific entry may be missing from it); anything else is UNKNOWN."""
    tables = [t for t in tables if t["value"].get("vrf") == query.vrf and t["value"].get("family") == query.family]
    if not tables:
        return None, f"no {query.family} forwarding table for VRF {query.vrf} was collected (wrong scope or source did not cover it)"
    v = tables[0]["value"]
    q = _net(query.prefix)
    if v["coverage"] == "PREFIX_LOOKUP" and query.prefix not in v.get("queried", ()):
        return None, f"forwarding source did not look up {query.prefix} (queried: {len(v.get('queried', ()))} prefix(es))"
    best, best_len = None, -1
    for e in v["entries"]:
        net = _net(e["prefix"])
        if net is None or net.version != q.version or not net.supernet_of(q):
            continue
        if not v["complete"] and net != q:
            continue
        if net.prefixlen > best_len:
            best, best_len = e, net.prefixlen
    base = {"prefix": query.prefix, "vrf": query.vrf, "family": query.family, "fib_evidence": True, "table_complete": bool(v["complete"]), "coverage": v["coverage"],
            "source": v["source"], "provenance": v["provenance"]}
    if best is None:
        if not v["complete"]:
            return None, "forwarding table is incomplete (partial, truncated or device re-converging): absence of an entry cannot be asserted"
        return {**base, "installed": False, "matched_prefix": None, "next_hop": None, "next_hops": [], "resolved": None, "reason": "NO_FIB_ENTRY"}, None
    hops = best["next_hops"]
    first = next((h["address"] for h in hops if h.get("address")), None)
    res = [h["resolved"] for h in hops]
    resolved = False if any(r is False for r in res) else (True if res and all(r is True for r in res) else None)
    installed = best["programmed"] and best["action"] == "forward"
    return {**base, "installed": installed, "matched_prefix": best["prefix"], "exact": best["prefix"] == query.prefix, "action": best["action"], "next_hop": first,
            "next_hops": hops, "resolved": resolved, "ecmp": len(hops) > 1}, None


def neighbor_values(entries: Iterable[dict], *, vrf: str = "default") -> dict:
    """``{subject: (value, quality_override|None, flags)}`` for the ``arp.entry`` contract.  Subject = address in the asked VRF, ``address%vrf`` elsewhere.

    ``dup_macs`` = other distinct MACs claimed for the SAME address.  EOS ARP does not report a state: a learned entry is surfaced as STALE (resolved, liveness
    unconfirmed) with ``state_reported`` false.  PERMANENT / NOARP / state-vs-MAC contradictions are UNTRUSTED (the runbook cannot judge them)."""
    groups: dict[tuple, list] = {}
    for e in entries:
        groups.setdefault((e["value"]["vrf"], e["value"]["address"]), []).append(e)
    out = {}
    for (v, addr), items in groups.items():
        rows = sorted((i["value"] for i in items), key=lambda r: _STATE_RANK.get(r["state"] or "STALE", 9))
        best = rows[0]
        state = best["state"] or "STALE"
        macs = sorted({r["mac"] for r in rows if r["mac"]})
        dups = [m for m in macs if m != best["mac"]]
        flags, quality = [], None
        if not best["state_reported"]:
            flags.append("ARP_STATE_NOT_REPORTED")
        if state in ("PERMANENT", "NOARP") or (state in USABLE_STATES and not best["mac"]):
            quality = "UNTRUSTED"
            flags.append("NEIGHBOR_STATE_NOT_JUDGEABLE")
        out[addr if v == vrf else f"{addr}%{v}"] = ({"state": state, "raw_state": best["state"], "state_reported": best["state_reported"], "mac": best["mac"], "dup_macs": dups,
                                                    "interface": best["interface"], "address": addr, "family": best["family"], "vrf": v, "age_s": best.get("age_s"),
                                                    "entries": len(rows), "cache_entry": True}, quality, flags)
    return out


def describe_source(*, gateway: dict | None = None, recorded: bool = False, fib_source: dict | None = None) -> dict:
    """Provenance label.  Only a gateway-recorded run (``gateway['live'] is True``) is LIVE; this is a label, not an attestation verifier."""
    label = LIVE if gateway and gateway.get("live") is True else (RECORDED if recorded else SIMULATED)
    return {"source": "forwarding", "label": label, "live": label == LIVE, "supported": {k: dict(v) for k, v in SUPPORTED.items()}, "gateway": gateway or None,
            "adapter_version": SOURCE_VERSION, "fib": ({"available": True, "source": fib_source, "qualification": list(FIB_QUALIFICATION)} if fib_source else
                    {"available": False, "reason": FIB_GAP_REASON, "qualification": list(FIB_QUALIFICATION)}),
            "parsers": {pid: [s.version for s in nz.PARSERS[pid]] for pid in PARSER_IDS}}


def is_supported(platform: str, os_version: str, parser_id: str = "route.table") -> bool:
    try:
        nz.select_parser(parser_id, platform, os_version)
        return True
    except nz.ParserSelectionError:
        return False
