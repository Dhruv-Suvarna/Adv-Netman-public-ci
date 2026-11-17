"""Deterministic multi-fault observation, classification and remediation decision (no model call anywhere in this module).

Pipeline (each stage is a pure function over structured, time-stamped evidence so it can be replayed from stored records):

1. **Observation**: ``interface_samples`` normalizes a cEOS ``show interfaces | json`` read into ``InterfaceSample`` rows
   (administrative vs operational state, link status, device-side transition counter, last-change time, error/discard
   counters, bandwidth/rates).  ``adjacency_samples`` / ``bgp_samples`` normalize routing-neighbor reads.
2. **History**: ``LinkHistory`` keeps a bounded per-interface transition history (poll-observed UP/DOWN edges plus the
   device's own ``linkStatusChanges`` deltas, so transitions shorter than the poll interval are still counted) and counter
   deltas with reset/discontinuity detection.
3. **Classification**: ``classify_interface`` / ``classify_link`` / ``classify_adjacency`` / ``classify_route`` /
   ``classify_reachability`` return a ``Classification``: the fault category, whether the *condition* is confirmed, the
   root-cause status (CONFIRMED / UNDETERMINED / INSUFFICIENT_EVIDENCE), possible causes that are explicitly NOT asserted,
   and the evidence used.
4. **Decision**: ``decide`` maps a classification to exactly one ``RemediationOutcome`` and lists every reason automatic
   remediation is denied.  Only ``ADMIN_STATE_MISMATCH`` has a registered corrective operation (``interface_enable``), and
   only a standing owner policy for that exact device/interface can make it ``AUTO_REMEDIATE`` -- and even then every
   governance gate is re-verified on live facts at execution time (``recovery.recover``).
5. **Proposal validation**: ``proposal_problem`` rejects a model-proposed operation that the stored evidence shows cannot
   work (``interface_enable`` on an interface observed administratively UP), so an ineffective change is refused visibly
   instead of being silently dropped or "succeeding" as a no-op.
"""

from __future__ import annotations

from collections import deque
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Iterable

# ------------------------------------------------------------------------------------------------------------- vocabulary
ADMIN_STATE_MISMATCH = "ADMIN_STATE_MISMATCH"
OPERATIONAL_LINK_DOWN = "OPERATIONAL_LINK_DOWN"
LINK_FLAPPING = "LINK_FLAPPING"
INTERFACE_DEGRADATION = "INTERFACE_DEGRADATION"
ROUTING_ADJACENCY_FAILURE = "ROUTING_ADJACENCY_FAILURE"
ROUTE_OR_REACHABILITY_FAILURE = "ROUTE_OR_REACHABILITY_FAILURE"
NO_FAULT = "NO_FAULT"
INDETERMINATE = "INDETERMINATE"
CATEGORIES = (ADMIN_STATE_MISMATCH, OPERATIONAL_LINK_DOWN, LINK_FLAPPING, INTERFACE_DEGRADATION, ROUTING_ADJACENCY_FAILURE,
              ROUTE_OR_REACHABILITY_FAILURE, NO_FAULT, INDETERMINATE)

# root-cause status: the *condition* can be confirmed while its *cause* stays undetermined (e.g. oper-down: no carrier is a
# fact; which of medium / optic / peer caused it is not, without further evidence)
CAUSE_CONFIRMED = "CONFIRMED"
CAUSE_UNDETERMINED = "UNDETERMINED"
CAUSE_INSUFFICIENT = "INSUFFICIENT_EVIDENCE"

AUTO_REMEDIATE = "AUTO_REMEDIATE"
PROPOSE_FOR_APPROVAL = "PROPOSE_FOR_APPROVAL"
DIAGNOSE_AND_ESCALATE = "DIAGNOSE_AND_ESCALATE"
INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"
NO_ACTION_REQUIRED = "NO_ACTION_REQUIRED"
OUTCOMES = (AUTO_REMEDIATE, PROPOSE_FOR_APPROVAL, DIAGNOSE_AND_ESCALATE, INSUFFICIENT_EVIDENCE, NO_ACTION_REQUIRED)

SCHEMA = "nmas.troubleshooting.fault-classification/1"
EVIDENCE_KEY = "intake.interface_state"          # case observation key (target=<device>, subject=<interface>)

# ------------------------------------------------------------------------------------------------------------- thresholds
FLAP_WINDOW_SECONDS = 300            # bounded observation window for transition counting
FLAP_MIN_TRANSITIONS = 4             # >= 2 full DOWN/UP cycles inside the window == unstable (a single outage is 1-2)
FLAP_STABLE_SECONDS = 60             # no transition for this long == the link has stabilised
HISTORY_MAX = 64                     # bounded transition / sample history per interface
ERR_DELTA_MIN = 10                   # errors in one interval that may matter at all ...
ERR_RATE_MIN = 0.05                  # ... and as a rate (per second)
DISCARD_DELTA_MIN = 100
DISCARD_RATIO_MIN = 0.01             # discards as a fraction of packets in the interval
DEGRADED_INTERVALS = 2               # consecutive degraded intervals before it is a fault (debounce)
REACH_LOSS_FAIL_PCT = 50.0
REACH_CONSECUTIVE = 2


def _iso(value: datetime | None) -> str | None:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z") if value else None


def _epoch(value: Any) -> datetime | None:
    try:
        return datetime.fromtimestamp(float(value), tz=timezone.utc) if value else None
    except (TypeError, ValueError, OverflowError, OSError):
        return None


# ------------------------------------------------------------------------------------------------------------ observation
@dataclass(frozen=True)
class InterfaceSample:
    device: str
    interface: str
    at: datetime
    admin: str                   # up | down  (cEOS interfaceStatus "disabled" == administratively down)
    oper: str                    # up | down  (connected + line protocol up == up)
    link_status: str             # raw cEOS interfaceStatus: connected | notconnect | disabled | errdisabled | ...
    protocol: str                # raw lineProtocolStatus
    link_status_changes: int | None = None
    last_change: datetime | None = None
    counters: dict = field(default_factory=dict)
    bandwidth_bps: int | None = None
    rates: dict = field(default_factory=dict)
    duplex: str = ""
    source: str = "ceos:show interfaces | json"

    def as_dict(self) -> dict:
        d = asdict(self)
        d["at"], d["last_change"] = _iso(self.at), _iso(self.last_change)
        return d


COUNTER_FIELDS = ("totalInErrors", "totalOutErrors", "inDiscards", "outDiscards", "inTotalPkts", "outTotalPkts")


def interface_samples(device: str, document: dict, at: datetime, *, source: str = "ceos:show interfaces | json") -> list[InterfaceSample]:
    """Normalize one cEOS ``show interfaces | json`` document (read-only) into samples; Management interfaces are skipped."""
    out = []
    for name, row in ((document or {}).get("interfaces") or {}).items():
        if not isinstance(row, dict) or name.startswith("Management"):
            continue
        status = str(row.get("interfaceStatus", ""))
        protocol = str(row.get("lineProtocolStatus", ""))
        counters = row.get("interfaceCounters") or {}
        stats = row.get("interfaceStatistics") or {}
        out.append(InterfaceSample(
            device=device, interface=name, at=at, admin="down" if status == "disabled" else "up",
            oper="up" if status == "connected" and protocol == "up" else "down", link_status=status, protocol=protocol,
            link_status_changes=counters.get("linkStatusChanges") if isinstance(counters.get("linkStatusChanges"), int) else None,
            last_change=_epoch(row.get("lastStatusChangeTimestamp")),
            counters={k: counters[k] for k in COUNTER_FIELDS if isinstance(counters.get(k), int)},
            bandwidth_bps=row.get("bandwidth") if isinstance(row.get("bandwidth"), int) else None,
            rates={k: stats[k] for k in ("inBitsRate", "outBitsRate", "inPktsRate", "outPktsRate") if isinstance(stats.get(k), (int, float))},
            duplex=str(row.get("duplex", "")), source=source))
    return out


# ---------------------------------------------------------------------------------------------------------------- history
@dataclass
class CounterDelta:
    interval_s: float
    reset: bool
    deltas: dict
    error_rate: float = 0.0
    discard_ratio: float = 0.0
    utilization_pct: float | None = None

    def degraded(self) -> list[str]:
        if self.reset or self.interval_s <= 0:
            return []
        why = []
        errors = self.deltas.get("totalInErrors", 0) + self.deltas.get("totalOutErrors", 0)
        if errors >= ERR_DELTA_MIN and self.error_rate >= ERR_RATE_MIN:
            why.append(f"errors +{errors} in {self.interval_s:.0f}s ({self.error_rate:.2f}/s)")
        discards = self.deltas.get("inDiscards", 0) + self.deltas.get("outDiscards", 0)
        if discards >= DISCARD_DELTA_MIN and self.discard_ratio >= DISCARD_RATIO_MIN:
            why.append(f"discards +{discards} in {self.interval_s:.0f}s ({100 * self.discard_ratio:.1f}% of packets)")
        return why


def counter_delta(prev: InterfaceSample, cur: InterfaceSample) -> CounterDelta:
    """Delta between two samples.  A counter that went backwards (clear, process or device restart) is a discontinuity: the
    interval is marked ``reset`` and never read as either a fault or health."""
    interval = (cur.at - prev.at).total_seconds()
    deltas, reset = {}, False
    for key in COUNTER_FIELDS:
        a, b = prev.counters.get(key), cur.counters.get(key)
        if a is None or b is None:
            continue
        if b < a:
            reset = True
        deltas[key] = b - a
    if prev.link_status_changes is not None and cur.link_status_changes is not None and cur.link_status_changes < prev.link_status_changes:
        reset = True
    pkts = deltas.get("inTotalPkts", 0) + deltas.get("outTotalPkts", 0)
    errors = deltas.get("totalInErrors", 0) + deltas.get("totalOutErrors", 0)
    discards = deltas.get("inDiscards", 0) + deltas.get("outDiscards", 0)
    util = None
    if cur.bandwidth_bps and cur.rates:
        util = round(100.0 * max(cur.rates.get("inBitsRate", 0.0), cur.rates.get("outBitsRate", 0.0)) / cur.bandwidth_bps, 3)
    return CounterDelta(interval_s=interval, reset=reset, deltas=deltas,
                        error_rate=(errors / interval) if interval > 0 else 0.0,
                        discard_ratio=(discards / pkts) if pkts > 0 else (1.0 if discards else 0.0), utilization_pct=util)


@dataclass
class LinkHistory:
    """Bounded per-interface history.  Transitions come from two independent sources: edges between consecutive polls, and the
    device's own ``linkStatusChanges`` counter (catches transitions shorter than the poll interval).  The larger wins."""
    transitions: deque = field(default_factory=lambda: deque(maxlen=HISTORY_MAX))      # (at, "up"|"down", source)
    counter_steps: deque = field(default_factory=lambda: deque(maxlen=HISTORY_MAX))    # (at, delta)
    degraded_streak: int = 0
    last_delta: CounterDelta | None = None
    last: InterfaceSample | None = None
    down_since: datetime | None = None
    admin_down_seen: deque = field(default_factory=lambda: deque(maxlen=HISTORY_MAX))  # times an admin-down was observed

    def update(self, s: InterfaceSample) -> None:
        prev = self.last
        if s.admin == "down":
            self.admin_down_seen.append(s.at)
        if prev is not None:
            if prev.oper != s.oper:
                self.transitions.append((s.at, s.oper, "poll"))
            if prev.link_status_changes is not None and s.link_status_changes is not None and s.link_status_changes >= prev.link_status_changes:
                step = s.link_status_changes - prev.link_status_changes
                if step:
                    self.counter_steps.append((s.at, step))
            self.last_delta = counter_delta(prev, s)
            self.degraded_streak = self.degraded_streak + 1 if self.last_delta.degraded() else 0
        if s.oper == "down":
            self.down_since = self.down_since or s.at
        else:
            self.down_since = None
        self.last = s

    def window(self, now: datetime, seconds: int = FLAP_WINDOW_SECONDS) -> dict:
        start = now - timedelta(seconds=seconds)
        edges = [t for t in self.transitions if t[0] >= start]
        counted = sum(step for at, step in self.counter_steps if at >= start)
        last_edge = max([t[0] for t in edges] + [at for at, _ in self.counter_steps if at >= start] +
                        ([self.last.last_change] if self.last and self.last.last_change and self.last.last_change >= start else []),
                        default=None)
        count = max(len(edges), counted)
        return {"window_s": seconds, "transitions": count, "poll_edges": [{"at": _iso(a), "state": st} for a, st, _ in edges],
                "device_counter_transitions": counted, "last_transition_at": _iso(last_edge),
                "stable_for_s": round((now - last_edge).total_seconds(), 1) if last_edge else None,
                "admin_down_observed_in_window": any(t >= start for t in self.admin_down_seen),
                "severity": flap_severity(count)}


def flap_severity(transitions: int) -> str:
    if transitions < FLAP_MIN_TRANSITIONS:
        return "NONE"
    if transitions < 8:
        return "MODERATE"
    return "HIGH" if transitions < 16 else "SEVERE"


# ------------------------------------------------------------------------------------------------------------ classification
@dataclass
class Classification:
    category: str
    scope: dict                              # {"device", "interface"} or {"link": [...]} / {"device", "protocol", "neighbor"}
    condition_confirmed: bool                # the abnormal condition itself is observed (not merely suspected)
    cause_status: str                        # CONFIRMED | UNDETERMINED | INSUFFICIENT_EVIDENCE
    summary: str
    cause: str = ""                          # only when cause_status == CONFIRMED
    possible_causes: list = field(default_factory=list)   # explicitly NOT asserted
    evidence: dict = field(default_factory=dict)
    secondary: list = field(default_factory=list)         # consequences explained by this fault (e.g. adjacency loss)
    observed_at: str | None = None

    def as_dict(self) -> dict:
        return {"schema": SCHEMA, **asdict(self)}


OPER_DOWN_CAUSES = ["physical medium or cabling failure", "transceiver/optic failure", "remote endpoint shutdown or fault",
                    "speed/duplex or negotiation mismatch", "remote device failure"]


def classify_interface(sample: InterfaceSample | None, intended_admin: str | None, history: LinkHistory | None, *,
                       now: datetime, confirm_seconds: int = 30) -> Classification:
    """One interface end.  Order matters: an administrative mismatch is never mistaken for a physical fault and vice versa."""
    if sample is None:
        return Classification(INDETERMINATE, {}, False, CAUSE_INSUFFICIENT, "interface state could not be read")
    scope = {"device": sample.device, "interface": sample.interface}
    ev = {"observed": {"admin": sample.admin, "oper": sample.oper, "link_status": sample.link_status, "protocol": sample.protocol},
          "intended_admin": intended_admin, "source": sample.source, "sampled_at": _iso(sample.at),
          "freshness_s": round((now - sample.at).total_seconds(), 1)}
    win = history.window(now) if history else {"transitions": 0, "admin_down_observed_in_window": False}
    ev["transitions"] = win
    if history and history.last_delta:
        ev["counters"] = {"interval_s": history.last_delta.interval_s, "reset": history.last_delta.reset,
                          "deltas": history.last_delta.deltas, "utilization_pct": history.last_delta.utilization_pct}
    if intended_admin is None:
        return Classification(INDETERMINATE, scope, False, CAUSE_INSUFFICIENT,
                              f"{sample.device} {sample.interface}: no authoritative intended state", evidence=ev, observed_at=_iso(sample.at))
    if intended_admin == "down":
        return Classification(NO_FAULT, scope, False, CAUSE_CONFIRMED,
                              f"{sample.device} {sample.interface} is intentionally disabled", evidence=ev, observed_at=_iso(sample.at))
    if sample.admin == "down":
        return Classification(ADMIN_STATE_MISMATCH, scope, True, CAUSE_CONFIRMED,
                              f"{sample.device} {sample.interface} administratively down but intended up",
                              cause="administrative shutdown contrary to configuration intent", evidence=ev, observed_at=_iso(sample.at))
    if win["transitions"] >= FLAP_MIN_TRANSITIONS and not win["admin_down_observed_in_window"]:
        return Classification(LINK_FLAPPING, scope, True, CAUSE_UNDETERMINED,
                              f"{sample.device} {sample.interface} admin up with {win['transitions']} link transitions in "
                              f"{win['window_s']}s (severity {win['severity']}, now oper {sample.oper})",
                              possible_causes=OPER_DOWN_CAUSES, evidence=ev, observed_at=_iso(sample.at))
    if sample.oper == "down":
        down_for = (now - history.down_since).total_seconds() if history and history.down_since else 0.0
        ev["oper_down_for_s"] = round(down_for, 1)
        if down_for >= confirm_seconds:
            errdis = sample.link_status == "errdisabled"
            return Classification(OPERATIONAL_LINK_DOWN, scope, True, CAUSE_UNDETERMINED,
                                  f"{sample.device} {sample.interface} administratively UP but operationally DOWN "
                                  f"({sample.link_status}/{sample.protocol}) for {down_for:.0f}s",
                                  possible_causes=(["error-disable action by the device (inspect the err-disable reason)"] if errdis else [])
                                  + OPER_DOWN_CAUSES, evidence=ev, observed_at=_iso(sample.at))
        return Classification(INDETERMINATE, scope, False, CAUSE_INSUFFICIENT,
                              f"{sample.device} {sample.interface} oper down for {down_for:.0f}s (< {confirm_seconds}s debounce)",
                              evidence=ev, observed_at=_iso(sample.at))
    if history and history.degraded_streak >= DEGRADED_INTERVALS and history.last_delta:
        return Classification(INTERFACE_DEGRADATION, scope, True, CAUSE_UNDETERMINED,
                              f"{sample.device} {sample.interface}: " + "; ".join(history.last_delta.degraded()),
                              possible_causes=["physical-layer errors (cabling/optic)", "congestion or buffer exhaustion",
                                               "MTU or encapsulation mismatch", "peer transmitting malformed frames"],
                              evidence=ev, observed_at=_iso(sample.at))
    return Classification(NO_FAULT, scope, False, CAUSE_CONFIRMED, f"{sample.device} {sample.interface} up/up, stable",
                          evidence=ev, observed_at=_iso(sample.at))


_RANK = {ADMIN_STATE_MISMATCH: 0, LINK_FLAPPING: 1, OPERATIONAL_LINK_DOWN: 2, INTERFACE_DEGRADATION: 3, INDETERMINATE: 4, NO_FAULT: 5}


def classify_link(ends: list[Classification]) -> Classification:
    """Combine the two ends of one physical link into ONE incident classification.

    An administrative shutdown at one end explains loss of carrier at the other (the far end is a consequence, not a second
    fault).  Both ends admin-up and oper-down is an operational link fault whose cause stays UNDETERMINED."""
    ends = [e for e in ends if e is not None]
    if not ends:
        return Classification(INDETERMINATE, {}, False, CAUSE_INSUFFICIENT, "no interface evidence")
    primary = min(ends, key=lambda e: _RANK.get(e.category, 9))
    others = [e for e in ends if e is not primary]
    link = [e.scope for e in ends if e.scope]
    result = Classification(primary.category, {**primary.scope, "link": link}, primary.condition_confirmed, primary.cause_status,
                            primary.summary, cause=primary.cause, possible_causes=list(primary.possible_causes),
                            evidence={"ends": [e.as_dict() for e in ends]}, observed_at=primary.observed_at)
    if primary.category == ADMIN_STATE_MISMATCH:
        result.secondary = [f"{o.scope.get('device')} {o.scope.get('interface')}: {o.summary} (explained by the administrative shutdown "
                            "at the far end)" for o in others if o.category in (OPERATIONAL_LINK_DOWN, INDETERMINATE)]
    elif primary.category in (OPERATIONAL_LINK_DOWN, LINK_FLAPPING):
        unreadable = [o for o in others if not o.scope]
        both_up_admin = all(e.evidence.get("observed", {}).get("admin") == "up" for e in ends if e.evidence.get("observed"))
        if unreadable:
            result.possible_causes = ["remote device failure or loss of its management path"] + result.possible_causes
            result.summary += "; far end unreadable"
        elif both_up_admin and len(ends) == 2:
            result.summary += "; both ends administratively UP (no administrative cause on either end)"
            dup = {e.evidence.get("observed", {}).get("duplex") for e in ends}
            result.evidence["both_ends_admin_up"] = True
            if len(dup - {None, ""}) > 1:
                result.possible_causes.insert(0, "duplex mismatch observed between the ends")
    return result


@dataclass(frozen=True)
class AdjacencySample:
    device: str
    protocol: str            # ospf | ospfv3 | bgp
    neighbor: str            # router-id / peer address
    interface: str
    state: str               # full | 2ways | init | down | Established | Active | ...
    at: datetime

    @property
    def key(self) -> tuple:
        return (self.device, self.protocol, self.neighbor)

    @property
    def healthy(self) -> bool:
        return self.state.lower() in ("full", "established")


def adjacency_samples(device: str, ospf_doc: dict | None, bgp_doc: dict | None, at: datetime) -> list[AdjacencySample]:
    out = []
    for vrf in ((ospf_doc or {}).get("vrfs") or {}).values():
        for inst in (vrf.get("instList") or {}).values():
            for n in inst.get("ospfNeighborEntries") or []:
                out.append(AdjacencySample(device, "ospf", str(n.get("routerId", "")), str(n.get("interfaceName", "")),
                                           str(n.get("adjacencyState", "")), at))
    for vrf in ((bgp_doc or {}).get("vrfs") or {}).values():
        for peer, row in (vrf.get("peers") or {}).items():
            out.append(AdjacencySample(device, "bgp", str(peer), "", str(row.get("peerState", "")), at))
    return out


def classify_adjacency(expected: Iterable[AdjacencySample], observed: Iterable[AdjacencySample], *, now: datetime,
                       expectation_source: str, link_incidents: dict[str, str] | None = None) -> list[Classification]:
    """Expected adjacencies (from an authoritative or explicitly labelled learned baseline) that are absent or not FULL /
    Established.  A loss on a device that has a concurrent link incident is recorded as POSSIBLY secondary to it."""
    seen = {o.key: o for o in observed}
    out = []
    for exp in expected:
        got = seen.get(exp.key)
        if got is not None and got.healthy:
            continue
        ev = {"expected": {"neighbor": exp.neighbor, "interface": exp.interface, "state": exp.state},
              "observed": None if got is None else {"state": got.state, "interface": got.interface},
              "expectation_source": expectation_source, "observed_at": _iso(now)}
        related = (link_incidents or {}).get(exp.device)
        c = Classification(ROUTING_ADJACENCY_FAILURE, {"device": exp.device, "protocol": exp.protocol, "neighbor": exp.neighbor,
                                                       "interface": exp.interface}, True, CAUSE_UNDETERMINED,
                           f"{exp.device} {exp.protocol} adjacency to {exp.neighbor} via {exp.interface or '-'} "
                           f"{'absent' if got is None else got.state} (expected {exp.state})",
                           possible_causes=(([f"loss of the underlying link ({related})"] if related else [])
                                            + ["neighbor device or process failure", "authentication/timer/area/MTU mismatch",
                                               "intermediate L2 path failure"]),
                           evidence=ev, observed_at=_iso(now))
        if related:
            c.evidence["possibly_secondary_to"] = related
        out.append(c)
    return out


def classify_route(device: str, prefix: str, expected_next_hops: list[str], observed_next_hops: list[str] | None, *,
                   now: datetime, protocol: str = "", af: str = "ipv4") -> Classification:
    scope = {"device": device, "prefix": prefix, "af": af}
    ev = {"expected_next_hops": sorted(expected_next_hops), "observed_next_hops": None if observed_next_hops is None else sorted(observed_next_hops),
          "protocol": protocol}
    if observed_next_hops is None:
        return Classification(INDETERMINATE, scope, False, CAUSE_INSUFFICIENT, f"{device} route {prefix}: RIB unreadable", evidence=ev)
    if not observed_next_hops:
        return Classification(ROUTE_OR_REACHABILITY_FAILURE, scope, True, CAUSE_UNDETERMINED, f"{device}: expected route {prefix} ({af}) missing",
                              possible_causes=["routing adjacency loss", "origin withdrew or filtered the prefix", "redistribution/policy change"],
                              evidence=ev, observed_at=_iso(now))
    if expected_next_hops and not set(observed_next_hops) & set(expected_next_hops):
        return Classification(ROUTE_OR_REACHABILITY_FAILURE, scope, True, CAUSE_UNDETERMINED,
                              f"{device}: route {prefix} via {sorted(observed_next_hops)}, expected {sorted(expected_next_hops)}",
                              possible_causes=["failover after a primary-path fault", "metric/policy change"], evidence=ev, observed_at=_iso(now))
    return Classification(NO_FAULT, scope, False, CAUSE_CONFIRMED, f"{device} route {prefix} present via expected next hop", evidence=ev)


def classify_reachability(flow: dict, samples: list[dict], *, baseline_loss_pct: float, routes: list[Classification] | None = None,
                          now: datetime) -> Classification:
    """``samples``: [{"at", "loss_pct", "measured"}] newest last.  Loss well above baseline in consecutive samples is a failure;
    a correlated missing route makes the route the confirmed fault domain, otherwise the cause stays undetermined."""
    scope = {"source": flow.get("source"), "destination": flow.get("destination"), "af": flow.get("af"), "path": flow.get("path", [])}
    measured = [s for s in samples if s.get("measured")]
    ev = {"samples": samples[-10:], "baseline_loss_pct": baseline_loss_pct}
    if len(measured) < REACH_CONSECUTIVE:
        return Classification(INDETERMINATE, scope, False, CAUSE_INSUFFICIENT, "too few reachability samples", evidence=ev)
    tail = measured[-REACH_CONSECUTIVE:]
    if all(float(s["loss_pct"]) >= max(REACH_LOSS_FAIL_PCT, baseline_loss_pct + REACH_LOSS_FAIL_PCT / 2) for s in tail):
        bad_routes = [r for r in routes or [] if r.category == ROUTE_OR_REACHABILITY_FAILURE]
        c = Classification(ROUTE_OR_REACHABILITY_FAILURE, scope, True, CAUSE_CONFIRMED if bad_routes else CAUSE_UNDETERMINED,
                           f"{scope['source']}->{scope['destination']} ({scope['af']}) loss {tail[-1]['loss_pct']}% vs baseline {baseline_loss_pct}%",
                           cause=bad_routes[0].summary if bad_routes else "",
                           possible_causes=[] if bad_routes else ["path link or device failure", "filtering (ACL)", "routing", "end-host fault"],
                           evidence={**ev, "correlated_routes": [r.summary for r in bad_routes]}, observed_at=_iso(now))
        return c
    return Classification(NO_FAULT, scope, False, CAUSE_CONFIRMED, f"{scope['source']}->{scope['destination']} within baseline", evidence=ev)


# --------------------------------------------------------------------------------------------------------------- decision
REGISTERED_CORRECTIONS = {ADMIN_STATE_MISMATCH: "interface_enable"}   # the ONLY category with a registered automatic correction


def decide(cl: Classification, *, policy_lookup: Callable[[dict], dict | None] | None = None) -> dict:
    """Exactly one outcome, with every reason automatic remediation is denied.  Deterministic; never consults a model.

    ``policy_lookup(op)`` returns the ACTIVE standing policy that names ``op`` exactly, else None.  AUTO_REMEDIATE here means
    only "a policy names this exact correction": execution still re-verifies every gate on live facts (recovery.recover)."""
    lookup = policy_lookup or (lambda _op: None)
    base = {"schema": "nmas.troubleshooting.remediation-decision/1", "category": cl.category, "scope": cl.scope,
            "cause_status": cl.cause_status, "operation": None, "policy_id": "", "denied": [], "requires_human": True}
    if cl.category == NO_FAULT:
        return {**base, "outcome": NO_ACTION_REQUIRED, "requires_human": False, "rationale": "service and interface state match intent"}
    if cl.category == INDETERMINATE or not cl.condition_confirmed:
        return {**base, "outcome": INSUFFICIENT_EVIDENCE, "denied": ["EVIDENCE_INSUFFICIENT: the abnormal condition is not confirmed"],
                "rationale": cl.summary}
    if cl.category == ADMIN_STATE_MISMATCH:
        op = {"kind": "interface_enable", "device": cl.scope.get("device"), "interface": cl.scope.get("interface"), "intended_state": "admin_up"}
        pol = lookup(op)
        if pol:
            return {**base, "outcome": AUTO_REMEDIATE, "operation": op, "policy_id": pol.get("id", ""), "requires_human": False,
                    "rationale": f"administrative shutdown contrary to intent; standing policy {pol.get('id')} names this exact correction "
                                 "(every gate is re-verified on live facts before the Change Engine runs)"}
        return {**base, "outcome": PROPOSE_FOR_APPROVAL, "operation": op,
                "denied": [f"NO_STANDING_POLICY: no active policy authorizes interface_enable on {op['device']} {op['interface']}"],
                "rationale": "technically appropriate correction (restore intended admin state) but not pre-authorized: human approval required"}
    denied = ["NO_REGISTERED_SAFE_CORRECTION: no registered operation restores this fault without human judgement",
              "STANDING_POLICIES_COVER_ONLY_interface_enable: interface_bounce, interface_shutdown, neighbor_reset, process_restart, "
              "routing and debounce changes can never be pre-authorized"]
    if cl.category in (OPERATIONAL_LINK_DOWN, LINK_FLAPPING):
        ends = [e for e in cl.evidence.get("ends", []) if e.get("scope")] or [{"scope": cl.scope, "evidence": cl.evidence}]
        admin_up = [f"{e['scope'].get('device')} {e['scope'].get('interface')}" for e in ends
                    if (e.get("evidence") or {}).get("observed", {}).get("admin") == "up"]
        if admin_up:
            denied.insert(0, f"INTERFACE_ENABLE_INEFFECTIVE: {', '.join(admin_up)} administratively UP; enabling cannot restore carrier")
        denied.append("AUTOMATIC_BOUNCE_OR_SHUTDOWN_UNSAFE: bouncing or disabling an unstable/physically failed link is not authorized")
        if cl.category == OPERATIONAL_LINK_DOWN:
            denied.append("PHYSICAL_OR_PEER_CAUSE_UNDETERMINED: " + "; ".join(cl.possible_causes[:5]))
    elif cl.category == INTERFACE_DEGRADATION:
        denied.append("COUNTER_CLEAR_DESTROYS_EVIDENCE: clearing counters hides the fault and is not a repair")
    elif cl.category == ROUTING_ADJACENCY_FAILURE:
        denied.append("ROUTING_PROCESS_OR_NEIGHBOR_CHANGE_NOT_AUTHORIZED: no automatic restart or neighbor reconfiguration")
        if cl.evidence.get("possibly_secondary_to"):
            denied.append(f"POSSIBLY_SECONDARY: concurrent link incident {cl.evidence['possibly_secondary_to']}")
    elif cl.category == ROUTE_OR_REACHABILITY_FAILURE:
        denied.append("SPECULATIVE_ROUTE_CHANGE_NOT_AUTHORIZED: no automatic static route, metric or protocol change")
    return {**base, "outcome": DIAGNOSE_AND_ESCALATE, "denied": denied,
            "rationale": f"{cl.category}: {cl.summary}. Evidence preserved; escalated to an engineer (safe non-remediation)."}


# ------------------------------------------------------------------------------------------------------ proposal validation
PROPOSAL_EVIDENCE_MAX_AGE_S = 900


def proposal_problem(case, op: dict, *, now: datetime | None = None) -> str:
    """'' when the operation is not contradicted by the case's own stored evidence, else the reason it cannot work.

    ``interface_enable`` restores an ADMINISTRATIVE state.  When the freshest stored observation of that interface (from the
    intake or a worker test) shows it administratively UP, the operation cannot change anything and the real fault is
    elsewhere (physical, peer, flapping): the proposal is refused so the model must escalate instead.  No evidence -> no
    objection here; the recovery policy still re-reads live state before any execution."""
    if not isinstance(op, dict) or op.get("kind") != "interface_enable":
        return ""
    from core import models as m

    now = now or datetime.now(timezone.utc)
    dev, ifn = str(op.get("device", "")), str(op.get("interface", ""))
    rows = m.TsObservation.objects.filter(case=case, target=dev, is_missing_data=False,
                                          key__in=[f"{EVIDENCE_KEY}@{ifn}", f"interface.admin_state@{ifn}"],
                                          observed_at__gte=now - timedelta(seconds=PROPOSAL_EVIDENCE_MAX_AGE_S)).order_by("-observed_at")
    latest = rows.first()
    if latest is None:
        return ""
    value = latest.value
    admin = (value.get("admin") if isinstance(value, dict) else value)
    if str(admin).lower() == "up":
        oper = value.get("oper") if isinstance(value, dict) else "unknown"
        return (f"INEFFECTIVE_OPERATION: {dev} {ifn} was observed administratively UP at {_iso(latest.observed_at)} (oper {oper}, "
                f"observation {latest.record_id}); interface_enable cannot restore an operational/physical fault. Escalate with the "
                "evidence instead of proposing a configuration change")
    return ""
