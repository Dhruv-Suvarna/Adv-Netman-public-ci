"""ONE read-only evidence read for one bootstrap sample (and for the capture-time / readiness assessment).

There is NO new monitoring stack and no second health engine.  Everything below composes services that already exist, each already read-only:

    integrity      ``bundles.integrity.verify_bundle_integrity``                the candidate still verifies (database only)
    interference   ``bootstrap.interference.find_interference``                 the persisted Phase-17 execution history (database only)
    reachability,  ``health.device.deep_checks``                                the SAME Deep-Health checks every device gets elsewhere: live read-only
    interfaces,                                                                 reachability, addressed-interface state, every OSPF / BGP neighbor
    routing,                                                                    healthy, and the Fleet-Quick telemetry checks (freshness, CPU, memory,
    CPU / memory,                                                               critical events, adjacent-link health) from the topology service
    freshness
    routes, links, ``health.evaluators.evaluate_requirements``                  the Phase-15 evaluators, fed BASELINE-RELATIVE requirements: whatever was
    adjacencies    over requirements derived from the captured baseline         up / present / FULL / Established at capture must still be
    topology       the topology snapshot vs the captured node / link set        the topology service still shows the captured nodes and links
    drift          ``capture.compare_all``                                      the running configuration of every device re-read and compared, sanitized,
                                                                                with the captured baseline

Grafana is a visualization and is never read; nothing is refreshed (``master.py --snmp-only`` is never called: it can converge devices).  A failed
read is missing evidence (INCOMPLETE), never PASS and never an exception.  Nothing is mutated to make a check pass.

"Required" needs a definition for a network nobody planned: it means REGRESSION FROM THE BASELINE -- what was healthy at capture must stay healthy.
Limitations that follow (documented): no synthetic data-plane traffic is generated (the repository has no read-only allowlisted probe for it, and the
known H1 -> WebServer issue is out of scope), so "IP connectivity" is management-plane reachability plus interface, adjacency, route and link
evidence; and RIP has no dedicated evaluator, so RIP is covered through the routes it installs.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from ..bundles import integrity as bundle_integrity
from ..health import device as health_device, evaluators, telemetry
from ..health.codes import CheckStatus, Freshness, Phase, Role
from ..health.evidence import DeviceEvidence, EvidenceSet, merge_precedence
from ..health.requirements import Requirement, expand
from ..health.results import CheckResult, aggregate_health, iso
from ..soak import assessment
from ..soak.assessment import INTENDED_STATE_FAILED, classify
from ..soak.codes import SampleResult
from . import capture, interference
from .codes import BASELINE_ID_PREFIX

S = CheckStatus


@dataclass
class Guard:
    integrity_ok: bool = True
    integrity_codes: list = field(default_factory=list)
    interference: list = field(default_factory=list)
    config_drift: bool = False       # never known from the database alone: it needs a device read (see ``collect``)

    @property
    def ok(self) -> bool:
        return self.integrity_ok and not self.interference


def guard(candidate) -> Guard:
    """The two database-only invalidation checks, run on EVERY collector tick."""
    report = bundle_integrity.verify_bundle_integrity(candidate)
    return Guard(report.ok, report.codes, interference.find_interference(candidate))


@dataclass
class BootAssessment(assessment.SampleAssessment):
    config_drift: bool = False

    def to_kwargs(self) -> dict:
        return {**super().to_kwargs(), "config_drift": self.config_drift}


def _boot(base: assessment.SampleAssessment, *, config_drift: bool = False) -> BootAssessment:
    # the shared sample assessment gained its own ``config_drift`` in V2 Phase 5C; the bootstrap's value is decided here, explicitly
    return BootAssessment(**{name: getattr(base, name) for name in base.__dataclass_fields__ if name != "config_drift"}, config_drift=config_drift)


def classify_bootstrap(result) -> str:
    """The Phase-20 classification, made stricter in exactly two places because a bootstrap has no plan to tell it which failures matter: what was up
    at capture MUST stay up.  A baseline interface that is no longer operationally up, and a DOWN link, are demonstrated failures (not warnings)."""
    base = classify(result)
    if base != INTENDED_STATE_FAILED:
        if result.check_code == "INTERFACE_OPER_DOWN" and result.status in (S.WARN, S.FAIL) and str(result.cfg_id).startswith(BASELINE_ID_PREFIX):
            return INTENDED_STATE_FAILED
        if result.check_code == "LINK_HEALTH_DEGRADED" and result.status == S.FAIL:
            return INTENDED_STATE_FAILED
    return base


# --- baseline-relative requirements ---------------------------------------------------------------------------------------------
def _req(device: str, kind: str, label: str, expected: dict, serial: int) -> Requirement:
    return Requirement(cfg_id=f"{BASELINE_ID_PREFIX}{device}-{serial:03d}", device=device, kind=kind, label=label, object_type="baseline", object_id=label,
                       expected=expected, check_types=expand(kind, expected))


def baseline_requirements(candidate) -> list[Requirement]:
    """What was healthy at capture, as Phase-15 requirements (deterministic order).  Nothing that was down / absent at capture is required."""
    out = []
    for record in ((candidate.payload.get("baseline") or {}).get("devices") or []):
        device, state, serial = record["device"], record.get("expected_state") or {}, 0

        def add(kind, label, expected):
            nonlocal serial
            serial += 1
            out.append(_req(device, kind, label, expected, serial))

        for name, row in sorted((state.get("interfaces") or {}).items()):
            if row.get("admin") == "UP" and row.get("oper") == "UP":
                add("INTERFACE_PRESENT", f"{device} {name}", {"interface": name, "admin_enabled": True})
        for name, addresses in sorted((state.get("addresses") or {}).items()):
            for address in addresses:
                add("ADDRESS_PRESENT", f"{device} {name} {address}", {"interface": name, "address": address})
        for route in state.get("routes") or []:
            add("ROUTE_INTENDED", f"{device} route {route['prefix']}", {"prefix": route["prefix"]})
        for neighbor in state.get("ospf") or []:
            if neighbor.get("state") == "FULL":
                add("ROUTING_INTERFACE_ENABLED", f"{device} OSPF {neighbor['interface']}",
                    {"protocol": "ospf", "interface": neighbor["interface"], "version": neighbor["family"]})
        for peer in state.get("bgp") or []:
            if peer.get("state") == "ESTABLISHED":
                add("BGP_PEER_INTENDED", f"{device} BGP {peer['peer']}", {"peer": peer["peer"]})
    return out


def topology_results(snapshot, baseline_topology: dict | None) -> list[CheckResult]:
    """The topology service must still show every captured node, and every link that was UP at capture must still exist and be UP."""
    if not baseline_topology or not snapshot.available:
        return []
    current = {str(e["id"]): str(e.get("status") or "UNKNOWN").upper() for e in snapshot.edges}
    results = []
    for edge in baseline_topology.get("edges") or []:
        if edge.get("status") != "UP":
            continue
        now_status = current.get(edge["id"])
        if now_status != "UP":
            results.append(CheckResult(
                "LINK_HEALTH_DEGRADED", S.FAIL if now_status in (None, "DOWN") else S.WARN if now_status == "DEGRADED" else S.UNKNOWN, "FLEET",
                f"Link {edge['id']} was UP at capture and is now {now_status or 'absent from the topology'}.", telemetry.SOURCE, role=Role.TARGET,
                observed={"link": edge["id"], "status": now_status or "ABSENT"}, expected={"status": "UP"}, subject=edge["id"], freshness=Freshness.FRESH))
    return results


def _device_facts(merged: DeviceEvidence, fresh: str, now: datetime, config_status: str) -> dict:
    group = merged.group("telemetry")
    data = group.data if group is not None and group.available else {}
    age = group.age_seconds(now) if group is not None else None
    count = lambda name: len(merged.facts(name)) if merged.facts(name) is not None else None   # noqa: E731
    return {
        "freshness": fresh, "age_seconds": None if age is None else round(age, 1), "cpu_percent": data.get("cpu_percent"),
        "memory_percent": data.get("memory_percent"), "critical_events": int(data.get("critical_syslog", 0)) + int(data.get("snmp_traps", 0)),
        "live": "OK" if merged.live_reachable else (merged.live_error or "NOT_ATTEMPTED"), "config": config_status,
        "routes": count("routes"), "ospf_neighbors": count("ospf"), "bgp_peers": count("bgp"),
    }


def collect(candidate, *, now: datetime, snapshot=None, session_factory=None, live_reads: bool = True, dhcp_state: dict | None = None,
            guard_result: Guard | None = None, reads: dict | None = None) -> BootAssessment:
    """Read every evidence source once and return the sample verdict.  ``snapshot`` / ``session_factory`` / ``dhcp_state`` / ``reads`` are injectable
    for tests only."""
    checked = guard_result or guard(candidate)
    if not checked.ok:
        return _boot(assessment.invalidated(integrity_ok=checked.integrity_ok, interference=checked.interference, integrity_codes=checked.integrity_codes))
    baseline = candidate.payload.get("baseline") or {}
    records = {r["device"]: r for r in baseline.get("devices") or []}
    snapshot = snapshot or telemetry.collect(now=now)
    scope = capture.managed_scope()
    wanted = {name: scope[name] for name in sorted(records) if name in scope}
    if reads is None:
        reads = capture.read_all(wanted, session_factory=session_factory, now=now) if live_reads else {}
    comparisons = {c.device: c for c in capture.compare_all(candidate, reads)} if live_reads else {}

    merged: dict = {}
    health_results, freshness, facts, observed = [], {}, {}, []
    for name in sorted(records):
        entry = scope.get(name)
        if entry is None:      # a captured device that is no longer a managed inventory device: missing evidence, never assumed fine
            health_results.append(CheckResult("DEVICE_UNREACHABLE", S.UNKNOWN, name, "The captured device is no longer a managed inventory device.", "LIVE",
                                              observed={"reason_code": "NOT_MANAGED"}, role=Role.TARGET))
            freshness[name] = Freshness.UNKNOWN
            continue
        tele = telemetry.device_evidence(snapshot, name, entry["platform"])
        read = reads.get(name)
        device_evidence = merge_precedence(read.evidence if read is not None else None, tele)
        merged[name] = device_evidence
        group = device_evidence.group("telemetry")
        freshness[name] = group.freshness(now, snapshot.thresholds) if group is not None and group.available else Freshness.UNKNOWN
        if group is not None and group.available and group.observed_at is not None:
            observed.append(group.observed_at)
        health_results += health_device.deep_checks(name, device_evidence, snapshot, now, role=Role.TARGET, dhcp_state=dhcp_state)
        comparison = comparisons.get(name)
        if live_reads and comparison is not None and comparison.status == "UNAVAILABLE":
            health_results.append(CheckResult("POSTCHECK_DATA_UNAVAILABLE", S.UNKNOWN, name, "The running configuration could not be re-read for the drift comparison.",
                                              "LIVE", observed={"reason_code": comparison.reason}, role=Role.TARGET, subject="configuration"))
        facts[name] = _device_facts(device_evidence, freshness[name], now, comparison.status if comparison is not None else "NOT_CHECKED")
    health_results += topology_results(snapshot, baseline.get("topology"))

    pipeline = {"available": snapshot.available and snapshot.backend_status == "OK", "topology_available": snapshot.available, "backend_status": snapshot.backend_status}
    evidence_set = EvidenceSet(devices=merged, now=now, thresholds=snapshot.thresholds, pipeline=pipeline)
    evaluation = evaluators.evaluate_requirements(baseline_requirements(candidate), Phase.POSTCHECK, evidence_set, roles={n: Role.TARGET for n in merged})
    base = assessment.assess(
        health_results=health_results, evaluation=evaluation, freshness=freshness, device_facts=facts, pipeline_ok=bool(pipeline["available"]),
        observed_at=iso(min(observed)) if observed else None, device_health=aggregate_health(health_results), classifier=classify_bootstrap,
    )
    result = _boot(base)
    drifted = [c for c in comparisons.values() if c.status == "DRIFT"]
    result.evidence["config"] = {
        "compared": len(comparisons), "match": sum(1 for c in comparisons.values() if c.status == "MATCH"),
        "unavailable": sorted(c.device for c in comparisons.values() if c.status == "UNAVAILABLE"), "drift": [c.to_dict() for c in drifted][:10],
    }
    result.evidence["topology"] = {"available": snapshot.available, "nodes": len(snapshot.nodes), "edges": len(snapshot.edges)}
    if drifted:   # the baseline is no longer what is running: INVALIDATED, whatever else was healthy.  Never adopted automatically.
        result.config_drift = True
        result.result = SampleResult.INVALIDATED
        result.findings = [{"class": "INVALIDATING", "check_code": "CONFIG_DRIFT_DETECTED", "device": c.device, "detail": c.to_dict()} for c in drifted[:5]] + result.findings
        result.counts = {**result.counts, "invalidating": len(drifted)}
    return result
