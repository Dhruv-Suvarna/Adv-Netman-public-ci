"""Stage "Correlate" (spec 3.4): pure, deterministic, explainable functions.  No ORM, no I/O, no clock reads (``now`` is always an argument).

Everything returns plain dicts so that ``engine`` can persist them as ``CorrelationRecord`` / ``TopologyPath`` / ``DriftAssessment`` rows.

* ``correlate_alarms``      topology- and time-aware alarm-storm grouping: one primary fault + preserved secondary symptoms (UT-035/036).
* ``compare_topology``      NetBox intent versus observed (LLDP/telemetry) links -- kept separate and differenced (UT-025).
* ``intended_paths`` / ``diff_path``   follow-the-path reconstruction from the topology graph, observed hop sequence divergence.
* ``rib_fib_gap``           RIB present / FIB missing => forwarding-installation discrepancy (UT-037).
* ``protocol_distinction``  per-transport-protocol service policy: TCP healthy + ICMP denied is NOT an outage (UT-031).
* ``exception_matches``     scoped, expiring operator-confirmed anomaly suppression that can never hide production loss (UT-032/033/034).
* ``counter_flow_correlation``  ACL/QoS counter deltas versus flow impairment, with direction and time window (UT-038).
* ``change_correlation``    changes versus incident onset and topology distance -- temporal proximity is NEVER blame (UT-028).
"""

from __future__ import annotations

from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable

from . import contracts as c

PHYSICAL_KINDS = frozenset({"LINK_DOWN", "INTERFACE_DOWN", "OPTICS_ALARM", "LINK_FLAP"})
LINK_SYMPTOM_KINDS = {"NEIGHBOR_DOWN", "BGP_PEER_DOWN", "OSPF_NBR_DOWN", "ISIS_ADJ_DOWN", "ROUTE_WITHDRAWN", "UNREACHABLE", "HOST_UNREACHABLE",
                      "INTERFACE_DOWN", "LINK_DOWN", "SNMP_TIMEOUT", "FLOW_DEGRADED", "LACP_MEMBER_DOWN", "BFD_DOWN"}


# --------------------------------------------------------------------------------------------------------------------- graph
def build_graph(links: Iterable[dict]) -> dict[str, dict[str, list[dict]]]:
    """links: {a, a_if, b, b_if[, id]} -> adjacency {device: {peer: [link,...]}} (parallel links preserved)."""
    g: dict[str, dict[str, list[dict]]] = defaultdict(lambda: defaultdict(list))
    for ln in links:
        g[ln["a"]][ln["b"]].append(ln)
        g[ln["b"]][ln["a"]].append(ln)
    return g


def _reach(g, start: str, banned: tuple[str, str, str, str] | None = None) -> set[str]:
    """Devices reachable from ``start`` ignoring one failed link (identified by its 4-tuple)."""
    seen, q = {start}, deque([start])
    while q:
        d = q.popleft()
        for peer, lns in g.get(d, {}).items():
            usable = [ln for ln in lns if _lk(ln) != banned]
            if usable and peer not in seen:
                seen.add(peer)
                q.append(peer)
    return seen


def _lk(ln: dict) -> tuple[str, str, str, str]:
    a, b = sorted([(ln["a"], ln.get("a_if", "")), (ln["b"], ln.get("b_if", ""))])
    return (a[0], a[1], b[0], b[1])


def find_link(links: Iterable[dict], device: str, interface: str) -> dict | None:
    for ln in links:
        if (ln["a"] == device and ln.get("a_if") == interface) or (ln["b"] == device and ln.get("b_if") == interface):
            return ln
    return None


# ---------------------------------------------------------------------------------------------------------- alarm correlation
def correlate_alarms(alarms: list[dict], links: list[dict], *, vantage: str, window_seconds: int = 180, clock_skew_seconds: int = 5,
                     min_cause_kinds: Iterable[str] = PHYSICAL_KINDS) -> dict[str, Any]:
    """Group an alarm storm into topology-consistent primary faults with preserved symptoms.

    alarms: {id, device, interface?, kind, at(ISO), severity?, peer?}.  ``vantage`` = where the NMS sits; devices that lose reachability
    from the vantage when the failed link is removed are *downstream* and legitimately explainable by that link.

    Rules (all recorded on each group):
      R1  primary candidate = earliest alarm whose kind is physical on a link present in the topology graph;
      R2  a symptom must occur within [t_cause - skew, t_cause + window];
      R3  a symptom is explained only if its device is (a) an endpoint of the failed link or (b) downstream of it -- i.e. cut off from the
          vantage once the link is removed.  If the link is redundant (graph stays connected) only (a) and protocol alarms that name an
          endpoint as their peer are explained; everything else is *rejected*, never silently merged (UT-036);
      R4  repeated (device, interface, kind) alarms are collapsed in the *summary*, every original id stays in ``alert_ids``.
    """
    parsed = []
    for a in alarms:
        t = c.parse_time(a.get("at"))
        parsed.append({**a, "_t": t})
    parsed.sort(key=lambda a: (a["_t"] is None, a["_t"] or datetime.min.replace(tzinfo=timezone.utc), a["id"]))
    g = build_graph(links)
    claimed: set[str] = set()
    groups: list[dict[str, Any]] = []
    cause_kinds = set(min_cause_kinds)
    for a in parsed:
        if a["id"] in claimed or a["_t"] is None or a["kind"] not in cause_kinds or not a.get("interface"):
            continue
        ln = find_link(links, a["device"], a["interface"])
        if ln is None:
            continue  # alarm names an interface that is in no known link: cannot be a topology cause
        key = _lk(ln)
        endpoints = {ln["a"], ln["b"]}
        reach = _reach(g, vantage, key)
        downstream = set(g) - reach if vantage in g else set()
        redundant = not downstream
        t0 = a["_t"]
        symptoms, rejected = [], []
        for b in parsed:
            if b["id"] == a["id"] or b["id"] in claimed:
                continue
            reason = _explain(b, t0, endpoints, downstream, key, window_seconds, clock_skew_seconds)
            (symptoms if reason[0] else rejected).append({"id": b["id"], "device": b["device"], "kind": b["kind"], "reason": reason[1]})
        # Only alarms that are genuinely explained are claimed; the rest stay available to later groups / reported as unrelated.
        sym_ids = {s["id"] for s in symptoms}
        claimed |= sym_ids | {a["id"]}
        peer_corroboration = any(s["device"] in endpoints and s["device"] != a["device"] and s["kind"] in PHYSICAL_KINDS for s in symptoms)
        explained = len(symptoms)
        total_other = max(len(parsed) - 1, 1)
        conf = 0.45 + (0.2 if peer_corroboration else 0) + (0.2 if explained / total_other >= 0.8 else 0.05 if explained else 0)
        conf += 0.1 if not redundant and downstream else 0
        conf = round(min(conf, 0.95), 2)
        collapsed: dict[tuple, int] = defaultdict(int)
        for s in [a, *[next(p for p in parsed if p["id"] == x["id"]) for x in symptoms]]:
            collapsed[(s["device"], s.get("interface", ""), s["kind"])] += 1
        groups.append({
            "primary": {"id": a["id"], "device": a["device"], "interface": a["interface"], "kind": a["kind"], "at": c.iso(t0)},
            "cause_link": {"a": ln["a"], "a_if": ln.get("a_if", ""), "b": ln["b"], "b_if": ln.get("b_if", ""), "id": ln.get("id", "")},
            "downstream_devices": sorted(downstream), "link_redundant": redundant,
            "symptoms": symptoms, "rejected": rejected, "alert_ids": [a["id"], *[s["id"] for s in symptoms]],
            "collapsed": [{"device": k[0], "interface": k[1], "kind": k[2], "count": n} for k, n in sorted(collapsed.items())],
            "peer_corroboration": peer_corroboration, "confidence": conf,
            "time_window": {"start": c.iso(t0 - timedelta(seconds=clock_skew_seconds)), "end": c.iso(t0 + timedelta(seconds=window_seconds))},
            "rules": ["R1 earliest physical alarm on a known link", "R2 symptom time window", "R3 topology-consistent (endpoint/downstream)",
                      "R4 duplicates collapsed in summary only"],
            "false_positive_risk": "LOW" if peer_corroboration and not redundant else "MEDIUM",
            "caveat": "correlation by topology and time identifies the likely common upstream fault; causality of the physical event is still to be "
                      "established by the RB01/RB07 tests",
        })
    # nothing is silently dropped: alarms not explained by any group are listed with the rule that rejected them
    rej = {}
    for gr in groups:
        for r in gr["rejected"]:
            rej.setdefault(r["id"], r["reason"])
    unrelated = [{"id": a["id"], "device": a["device"], "kind": a["kind"], "at": c.iso(a["_t"]),
                  "reason": rej.get(a["id"], "no physical cause candidate in the topology explains this alarm")}
                 for a in parsed if a["id"] not in claimed]
    return {"groups": groups, "unrelated": unrelated, "total_alarms": len(parsed),
            "grouped_alarms": len(claimed), "dedup_ratio": round(1 - (len(groups) + len(unrelated)) / max(len(parsed), 1), 3),
            "all_alert_ids": [a["id"] for a in parsed]}


def _explain(b: dict, t0: datetime, endpoints: set[str], downstream: set[str], link_key, window: int, skew: int) -> tuple[bool, str]:
    t = b["_t"]
    if t is None:
        return False, "no usable timestamp; cannot be time-correlated"
    if t < t0 - timedelta(seconds=skew):
        return False, f"occurred {int((t0 - t).total_seconds())}s BEFORE the candidate cause (> {skew}s clock-skew tolerance)"
    if t > t0 + timedelta(seconds=window):
        return False, f"occurred {int((t - t0).total_seconds())}s after the candidate cause (window {window}s)"
    dev = b["device"]
    if dev in endpoints:
        if b.get("interface") and b["kind"] in PHYSICAL_KINDS and (dev, b["interface"]) not in {(link_key[0], link_key[1]), (link_key[2], link_key[3])}:
            return False, f"physical alarm on {dev}:{b['interface']}, a different interface from the failed link"
        return True, "device is an endpoint of the failed link"
    if dev in downstream:
        return True, "device lost reachability from the vantage point when the link is removed (downstream)"
    peer = b.get("peer")
    if peer in endpoints and b["kind"] in LINK_SYMPTOM_KINDS and not b.get("interface"):
        return True, f"protocol alarm names {peer}, an endpoint of the failed link, as its peer"
    return False, "topology-inconsistent: device is neither an endpoint nor downstream of the failed link (redundant path remains)"


# ----------------------------------------------------------------------------------------------------- intent vs observed topology
def compare_topology(intent_links: list[dict], observed_links: list[dict]) -> dict[str, Any]:
    """NetBox intent and observed adjacency stay separate; only the difference is computed.  Intent is not proof of state."""
    ik = {_lk(ln): ln for ln in intent_links}
    ok_ = {_lk(ln): ln for ln in observed_links}
    missing = [ik[k] for k in ik if k not in ok_]
    unexpected = [ok_[k] for k in ok_ if k not in ik]
    # a "miscabled" port: same endpoint interface appears with a different peer
    by_port_i = {(ln["a"], ln.get("a_if")): ln for ln in intent_links} | {(ln["b"], ln.get("b_if")): ln for ln in intent_links}
    miscabled = []
    for ln in unexpected:
        for end in ((ln["a"], ln.get("a_if")), (ln["b"], ln.get("b_if"))):
            exp = by_port_i.get(end)
            if exp is not None and _lk(exp) != _lk(ln):
                miscabled.append({"port": f"{end[0]}:{end[1]}", "intended": _lk(exp), "observed": _lk(ln)})
    return {"intent_count": len(ik), "observed_count": len(ok_), "missing_in_observed": missing, "unexpected_in_observed": unexpected,
            "miscabled": miscabled, "conforms": not (missing or unexpected)}


def intended_paths(links: list[dict], src: str, dst: str, *, limit: int = 4) -> list[list[dict]]:
    """Up to ``limit`` loop-free shortest-first device paths src->dst as hop lists [{device, in_if, out_if}] (BFS by hop count)."""
    g = build_graph(links)
    paths: list[list[str]] = []
    q: deque[list[str]] = deque([[src]])
    best = None
    while q and len(paths) < limit:
        p = q.popleft()
        if best is not None and len(p) > best + 1:
            break
        if p[-1] == dst:
            best = len(p) if best is None else best
            paths.append(p)
            continue
        for peer in sorted(g.get(p[-1], {})):
            if peer not in p:
                q.append([*p, peer])
    out = []
    for p in paths:
        hops = []
        for i, dev in enumerate(p):
            in_if = out_if = ""
            if i > 0:
                ln = g[p[i - 1]][dev][0]
                in_if = ln["b_if"] if ln["b"] == dev else ln["a_if"]
            if i < len(p) - 1:
                ln = g[dev][p[i + 1]][0]
                out_if = ln["a_if"] if ln["a"] == dev else ln["b_if"]
            hops.append({"device": dev, "in_if": in_if, "out_if": out_if})
        out.append(hops)
    return out


def l3_view(path: list[dict], roles: dict[str, str], src: str) -> list[dict]:
    """Hops a traceroute can show: routers/firewalls/destination.  The source and pure L2 switches are invisible to IP traceroute."""
    return [h for h in path if h["device"] != src and roles.get(h["device"]) != "switch"]


def diff_path(intended: list[dict], observed_devices: list[str]) -> dict[str, Any]:
    """Compare the intended device sequence with a traceroute/RIB-derived sequence; report first divergence and asymmetry limits."""
    want = [h["device"] for h in intended]
    got = list(observed_devices)
    first = next((i for i, (a, b) in enumerate(zip(want, got)) if a != b), None)
    if first is None and len(got) < len(want):
        first = len(got)
    return {"intended": want, "observed": got, "conforms": want[:len(got)] == got and len(got) >= len(want) - 1 and first is None,
            "first_divergence_index": first, "first_divergence": {"expected": want[first] if first is not None and first < len(want) else None,
                                                                   "observed": got[first] if first is not None and first < len(got) else None},
            "limits": "traceroute shows the forward path only; return path must be proven from the destination side RIB/FIB"}


# --------------------------------------------------------------------------------------------------------------- RIB vs FIB
def rib_fib_gap(rib: dict | None, fib: dict | None) -> dict[str, Any]:
    if rib is None or fib is None:
        return {"verdict": "UNKNOWN", "reason": "RIB or FIB observation missing/unusable; no conclusion"}
    in_rib, in_fib = bool(rib.get("present")), bool(fib.get("installed"))
    if in_rib and not in_fib:
        return {"verdict": "FIB_INSTALL_DISCREPANCY", "reason": "route selected in the RIB but not installed in the FIB (forwarding discrepancy)",
                "rib_next_hop": rib.get("next_hop")}
    if in_rib and in_fib and fib.get("next_hop") != rib.get("next_hop"):
        return {"verdict": "NEXT_HOP_MISMATCH", "reason": f"RIB next hop {rib.get('next_hop')} != FIB next hop {fib.get('next_hop')}"}
    if in_rib and in_fib and fib.get("resolved") is False:
        return {"verdict": "UNRESOLVED_ADJACENCY", "reason": "FIB entry present but next-hop adjacency (ARP/ND) unresolved"}
    if not in_rib:
        return {"verdict": "NO_ROUTE", "reason": "no RIB route for the service prefix"}
    return {"verdict": "CONSISTENT", "reason": "RIB and FIB agree"}


# ---------------------------------------------------------------------------------------------- per-protocol service distinction
def protocol_distinction(probes: dict[str, dict], flow: dict, *, intentionally_blocked: Iterable[str] = (), loss_threshold_pct: float = 1.0) -> dict[str, Any]:
    """Evaluate each transport protocol on its own.  probes: {"tcp": {"sent":20,"ok":20}, "icmp": {...}}.

    The *production* protocol is flow['protocol']; failure there is production impact whatever the diagnostic protocols do.  Diagnostic
    protocol failure while production is healthy is NO_PRODUCTION_IMPACT (EXPECTED_BLOCK when it is intentionally blocked)."""
    prod = flow.get("protocol", "tcp")
    blocked = {p.lower() for p in intentionally_blocked}
    per = {}
    for proto, r in probes.items():
        sent, okn = int(r.get("sent", 0)), int(r.get("ok", 0))
        loss = round(100.0 * (sent - okn) / sent, 2) if sent else None
        per[proto] = {"sent": sent, "ok": okn, "loss_pct": loss, "role": "PRODUCTION" if proto == prod else "DIAGNOSTIC",
                      "intentionally_blocked": proto in blocked}
    p = per.get(prod)
    if p is None or p["loss_pct"] is None:
        return {"classification": "UNKNOWN", "per_protocol": per, "reason": f"no usable {prod} production-service probe"}
    if p["loss_pct"] > loss_threshold_pct:
        return {"classification": "PRODUCTION_IMPACT", "per_protocol": per,
                "reason": f"production {prod.upper()} loss {p['loss_pct']}% exceeds {loss_threshold_pct}%; diagnostic-protocol results cannot mask it"}
    failing = [k for k, v in per.items() if v["role"] == "DIAGNOSTIC" and v["loss_pct"] and v["loss_pct"] > loss_threshold_pct]
    if failing and all(k in blocked for k in failing):
        return {"classification": "NO_PRODUCTION_IMPACT", "per_protocol": per, "expected_protocol_distinction": True,
                "reason": f"production {prod.upper()} healthy; {','.join(failing)} failure matches an intentional block"}
    if failing:
        return {"classification": "NO_PRODUCTION_IMPACT_UNEXPLAINED_DIAGNOSTIC_FAILURE", "per_protocol": per, "expected_protocol_distinction": False,
                "reason": f"production {prod.upper()} healthy; {','.join(failing)} failing without a recorded intent or exception (no remediation, needs explanation)"}
    return {"classification": "HEALTHY", "per_protocol": per, "reason": "all probed protocols healthy"}


# --------------------------------------------------------------------------------------------------------- scoped exceptions
def exception_matches(policy: dict, signal: dict, *, current_revisions: dict[str, str], now: datetime) -> dict[str, Any]:
    """Does an operator-confirmed expected-anomaly policy suppress *this* test alarm?

    policy: {id, scope{src,dst,vrf,protocols[],ports?}, expires_at, bound_revisions, status}
    signal: {src, dst, vrf, protocol, kind: "TEST_FAILURE"|"PRODUCTION_LOSS", production: bool}
    A policy never matches production loss, and never matches a protocol that is not listed in its scope."""
    expires = c.parse_time(policy.get("expires_at"))
    if policy.get("status", "ACTIVE") != "ACTIVE":
        return {"suppressed": False, "status": policy["status"], "reason": f"policy is {policy['status']}"}
    if expires is None or expires <= now:
        return {"suppressed": False, "status": "EXPIRED", "reason": "policy expired; the alarm is live again"}
    for name, rev in (policy.get("bound_revisions") or {}).items():
        if current_revisions.get(name) != rev:
            return {"suppressed": False, "status": "INVALIDATED", "reason": f"bound revision {name} changed ({rev} -> {current_revisions.get(name)})"}
    if signal.get("production") or signal.get("kind") == "PRODUCTION_LOSS":
        return {"suppressed": False, "status": "ACTIVE", "reason": "production-flow loss is never suppressed by a test exception"}
    scope = policy.get("scope") or {}
    if not scope:
        return {"suppressed": False, "status": "ACTIVE", "reason": "empty scope"}
    for field in ("src", "dst", "vrf"):
        if scope.get(field) not in (None, "", signal.get(field)):
            return {"suppressed": False, "status": "ACTIVE", "reason": f"out of scope: {field}={signal.get(field)!r} != {scope.get(field)!r}"}
    if signal.get("protocol", "").lower() not in {p.lower() for p in scope.get("protocols", [])}:
        return {"suppressed": False, "status": "ACTIVE", "reason": f"protocol {signal.get('protocol')!r} not in scope {scope.get('protocols')}"}
    return {"suppressed": True, "status": "ACTIVE", "reason": "matches scope; the suppressed test keeps being observed", "policy": policy.get("id", "")}


# ------------------------------------------------------------------------------------------- counters vs flow impairment (ACL/QoS)
def counter_flow_correlation(counter_samples: list[dict], flow_samples: list[dict], *, direction: str, window_seconds: int = 120) -> dict[str, Any]:
    """counter_samples: [{at, hits, direction}] cumulative; flow_samples: [{at, loss_pct, direction?}].  Correlates the counter *delta* with a
    flow impairment onset only when the direction matches and the first counter increase is within ``window_seconds`` of the flow impairment."""
    cs = sorted((s for s in counter_samples if s.get("direction", direction) == direction), key=lambda s: s["at"])
    wrong_dir = [s for s in counter_samples if s.get("direction", direction) != direction]
    if len(cs) < 2:
        return {"correlated": None, "reason": "need two counter samples in the matching direction to compute a delta"
                                              + (f" ({len(wrong_dir)} sample(s) in the opposite direction ignored)" if wrong_dir else "")}
    first_inc = None
    total = 0
    for prev, cur in zip(cs, cs[1:]):
        d = cur["hits"] - prev["hits"]
        if d < 0:
            return {"correlated": None, "reason": "counter decreased (reset/wrap); delta unusable"}
        if d > 0 and first_inc is None:
            first_inc = c.parse_time(prev["at"])
        total += d
    imp = [s for s in flow_samples if s.get("loss_pct", 0) and s["loss_pct"] > 1.0]
    if total == 0:
        return {"correlated": False, "reason": "counter did not increase in the matching direction", "delta": 0}
    if not imp:
        return {"correlated": False, "reason": "counter increases but no flow impairment recorded", "delta": total}
    onset = min(c.parse_time(s["at"]) for s in imp)
    gap = abs((onset - first_inc).total_seconds()) if first_inc else None
    ok = gap is not None and gap <= window_seconds
    return {"correlated": ok, "delta": total, "gap_seconds": gap, "direction": direction,
            "reason": f"counter delta {total} in the {direction} direction; flow impairment onset {'within' if ok else 'outside'} {window_seconds}s of first increase"}


# ----------------------------------------------------------------------------------------------------------- change correlation
def change_correlation(changes: list[dict], *, onset: datetime, path_devices: list[str], links: list[dict], lookback_seconds: int = 7 * 86400,
                       now: datetime | None = None) -> list[dict]:
    """One row per change that could have preceded the onset.  ``blame`` is ALWAYS False: proximity is evidence for a hypothesis, not a verdict."""
    g = build_graph(links)
    rows = []
    for ch in changes:
        t = c.parse_time(ch.get("at"))
        if t is None:
            rows.append({**ch, "relation": "UNKNOWN_TIME", "blame": False, "note": "no timestamp; cannot be ordered against the onset"})
            continue
        delta = (onset - t).total_seconds()
        if delta < 0:
            rel = "AFTER_ONSET"
        elif delta > lookback_seconds:
            rel = "OUTSIDE_LOOKBACK"
        else:
            rel = "BEFORE_ONSET"
        dist = _min_distance(g, ch.get("devices", []), path_devices)
        in_path = dist == 0
        score = 0.0
        if rel == "BEFORE_ONSET":
            score = round(max(0.1, 1.0 - delta / lookback_seconds) * (1.0 if in_path else 0.5 if (dist is not None and dist <= 1) else 0.2), 2)
        rows.append({"change_id": ch.get("change_id", ""), "approved": ch.get("approved"), "kind": ch.get("kind", ""), "devices": ch.get("devices", []),
                     "at": c.iso(t), "seconds_before_onset": int(delta), "relation": rel, "topology_distance": dist, "on_affected_path": in_path,
                     "in_soak": bool(ch.get("in_soak")), "score": score, "blame": False,
                     "note": "temporal/topological proximity only; a causal test must confirm before any remediation"})
    rows.sort(key=lambda r: (-r.get("score", 0), r.get("change_id", "")))
    return rows


def _min_distance(g, a: list[str], b: list[str]) -> int | None:
    if not a or not b:
        return None
    best = None
    for s in a:
        seen, q = {s: 0}, deque([s])
        while q:
            d = q.popleft()
            for peer in g.get(d, {}):
                if peer not in seen:
                    seen[peer] = seen[d] + 1
                    q.append(peer)
        for t in b:
            if t in seen and (best is None or seen[t] < best):
                best = seen[t]
    return best
