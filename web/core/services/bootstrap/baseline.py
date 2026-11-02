"""Capture the current baseline (creating the LEGACY_BASELINE candidate) and the read-only readiness probe.

    capture_candidate(actor=..)     READ-ONLY reads of every managed device -> sanitized, canonical payload -> immutable LEGACY_BASELINE candidate.
                                    All-or-nothing; refuses an unhealthy or unobservable network; never Golden, never an observation.
    readiness_probe()               the same reads and the same assessment, persisting NOTHING: what a capture would see and every current blocker.

Neither touches a device beyond the allowlisted read-only sessions, and neither configures, repairs or refreshes anything to make a check pass.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from types import SimpleNamespace

from django.utils import timezone

from ... import models
from ..bundles import legacy
from ..health import inventory, live, telemetry
from ..health.results import iso
from ..soak.codes import SampleResult
from ..validation import sources as validation_sources
from . import capture, evidence, policy
from .codes import POLICY_VERSION, blocker

MAX_FINDINGS_RECORDED = 15
MAX_PROBLEMS_SHOWN = 20


@dataclass
class CaptureResult:
    bundle: object | None = None
    created: bool = False
    blockers: list = field(default_factory=list)
    refused: bool = False


def active_run():
    return models.LegacyBootstrapRun.objects.filter(state=models.SoakState.RUNNING).first()


def _health_blockers(assessed) -> list[dict]:
    """A network that is demonstrably unhealthy (or unobservable) right now must not be adopted as the known-good baseline."""
    if assessed.result == SampleResult.FAIL or assessed.terminal_failure:
        return [blocker("BASELINE_UNHEALTHY", findings=[{k: f.get(k) for k in ("class", "device", "check_code", "subject")} for f in assessed.findings[:10]])]
    if assessed.result == SampleResult.INCOMPLETE:
        return [blocker("BASELINE_EVIDENCE_UNAVAILABLE", findings=[{k: f.get(k) for k in ("class", "device", "check_code", "subject")} for f in assessed.findings[:10]])]
    return []


def _summary(assessed) -> dict:
    return {"result": assessed.result, "expected_state": assessed.expected_state_result, "telemetry_freshness": assessed.telemetry_freshness, "counts": assessed.counts,
            "findings": [{k: f.get(k) for k in ("class", "device", "check_code", "status", "subject")} for f in assessed.findings[:MAX_FINDINGS_RECORDED]]}


def _read_and_assess(*, now, session_factory, snapshot, dhcp_state):
    """-> (payload | None, problems, assessed | None, reads, snapshot).  The shared read of the capture and the probe."""
    started = now or timezone.now()
    snapshot = snapshot or telemetry.collect(now=started)
    reads = capture.read_all(capture.managed_scope(), session_factory=session_factory, now=started)
    finished = now or timezone.now()
    payload, problems = capture.build_payload(reads, capture_started_at=started, capture_finished_at=finished, snapshot=snapshot,
                                              repository_head=validation_sources.repository_head(), policy_version=POLICY_VERSION)
    assessed = None
    if payload is not None:    # judge the freshly read network by the SAME rules a sample uses (against itself, so drift is trivially none)
        assessed = evidence.collect(SimpleNamespace(payload=payload), now=started, snapshot=snapshot, reads=reads, guard_result=evidence.Guard(), dhcp_state=dhcp_state)
    return payload, problems, assessed, reads, snapshot


def capture_candidate(*, actor: str, now: datetime | None = None, session_factory=None, snapshot=None, dhcp_state=None) -> CaptureResult:
    """Explicit action.  Read-only against the network; writes only the candidate bundle + one audit event, and only when everything held."""
    gate = legacy.gate_blockers()
    if gate:
        return CaptureResult(blockers=gate, refused=True)
    if active_run() is not None:
        return CaptureResult(blockers=[blocker("BOOTSTRAP_ACTIVE")], refused=True)
    payload, problems, assessed, _reads, _snapshot = _read_and_assess(now=now, session_factory=session_factory, snapshot=snapshot, dhcp_state=dhcp_state)
    if payload is None:   # ALL-OR-NOTHING: BOOTSTRAP_BASELINE_INCOMPLETE and STOP -- nothing is created, nothing is omitted
        return CaptureResult(blockers=[blocker("BOOTSTRAP_BASELINE_INCOMPLETE", problems=problems[:MAX_PROBLEMS_SHOWN])], refused=True)
    unhealthy = _health_blockers(assessed)
    if unhealthy:
        return CaptureResult(blockers=unhealthy, refused=True)
    payload["baseline"]["capture_assessment"] = _summary(assessed)
    sealed = legacy.seal_candidate(payload, actor=actor, policy_version=POLICY_VERSION)
    if sealed.bundle is None:
        return CaptureResult(blockers=sealed.blockers, refused=True)
    return CaptureResult(sealed.bundle, created=True)


def readiness_probe(*, now: datetime | None = None, session_factory=None, snapshot=None, dhcp_state=None) -> dict:
    """READ-ONLY dry probe (no bundle, no run, no audit row): managed devices, capture support, unreachable devices, the health evaluators, monitoring
    freshness and every current blocker.  Fixes nothing and configures nothing."""
    started = now or timezone.now()
    gate = legacy.gate_blockers()
    running = active_run()
    payload, problems, assessed, reads, snapshot = _read_and_assess(now=now, session_factory=session_factory, snapshot=snapshot, dhcp_state=dhcp_state)
    devices = []
    for name in sorted(capture.managed_scope()):
        read = reads[name]
        entry = read.device
        tele = telemetry.device_evidence(snapshot, name, entry["platform"]).group("telemetry")
        fresh = tele.freshness(started, snapshot.thresholds) if tele is not None and tele.available else "UNKNOWN"
        sections, section_problems = capture.sanitize_sections(read)
        devices.append({
            "device": name, "platform": entry["platform"], "capability": live.get_capability(entry["platform"])["status"],
            "capture_method": capture.transport_of(entry), "reachable": not read.evidence.live_error,
            "live_error": read.evidence.live_error or "", "sections": [{"name": s["name"], "kept_lines": s["kept_lines"], "redacted_lines": s["redacted_lines"]} for s in sections],
            "section_problems": section_problems, "telemetry_freshness": fresh,
            "groups": {g: bool(read.evidence.group(g) and read.evidence.group(g).available) for g in sorted(read.evidence.groups)},
        })
    blockers = list(gate)
    if running is not None:
        blockers.append(blocker("BOOTSTRAP_ACTIVE"))
    if payload is None:
        blockers.append(blocker("BOOTSTRAP_BASELINE_INCOMPLETE", problems=problems[:MAX_PROBLEMS_SHOWN]))
    else:
        blockers += _health_blockers(assessed)
    return {
        "generated_at": iso(started), "policy": policy.current_policy().to_dict(), "gate": gate, "active_run": running.run_id if running else None,
        "managed_devices": [d["device"] for d in devices], "devices": devices, "unreachable": [d["device"] for d in devices if not d["reachable"]],
        "monitoring": {"topology_available": snapshot.available, "backend_status": snapshot.backend_status,
                       "fresh_devices": sum(1 for d in devices if d["telemetry_freshness"] == "FRESH"), "total_devices": len(devices)},
        "assessment": _summary(assessed) if assessed is not None else None, "capture_problems": problems[:MAX_PROBLEMS_SHOWN],
        "blockers": blockers, "ready": not blockers,
        "evaluators": ["health.device.deep_checks", "health.evaluators.evaluate_requirements (baseline-relative)", "topology snapshot vs captured links",
                       "capture.compare_all (configuration drift)", "bundles.integrity", "bootstrap.interference"],
    }
