"""Deterministic evaluation of a bootstrap observation.  PURE: the same policy + the same samples + the same ``now`` always give the same verdict.

The Phase-20 evaluator is REUSED, not copied: coverage statistics, the resource-streak rule and the duration / coverage / gap rules are
``soak.evaluator``'s own functions.  The bootstrap adds exactly ONE rule, ahead of the shared ones, because it observes an unmanaged legacy
network rather than an applied change:

    1  candidate integrity failure                         -> INVALIDATED  BUNDLE_INTEGRITY_FAILED
    2  a network execution touched an included device      -> INVALIDATED  OVERLAPPING_EXECUTION
    3  CONFIGURATION DRIFT in any sample                   -> INVALIDATED  CONFIG_DRIFT_DETECTED      (never auto-adopted; a new bootstrap is needed)
    4+ a required health failure, a sustained critical resource, ``now`` before the required end (RUNNING; ``now >= required_end_at`` is enough),
       coverage / gap / clock problems (INCOMPLETE), else PASS                                      (shared with the soak evaluator)

A technical PASS never creates Golden.  Stale or missing evidence is INCOMPLETE, never PASS.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from ... import models
from ..bundles.canonical import canonical_json
from ..soak import evaluator as soak_evaluator
from ..soak.evaluator import SampleFacts, Verdict, iso, resource_streak, statistics
from ..soak.policy import SoakPolicy
from . import codes
from .codes import EVIDENCE_SCHEMA_VERSION

SR = models.SoakSampleResult

__all__ = ["BootFacts", "Verdict", "evaluate", "evidence_digest", "facts_of", "final_summary", "iso", "resource_streak", "samples_digest", "statistics", "verify_run"]


@dataclass(frozen=True)
class BootFacts(SampleFacts):
    config_drift: bool = False


def facts_of(sample) -> BootFacts:
    base = soak_evaluator.facts_of(sample)
    return BootFacts(**{name: getattr(base, name) for name in base.__dataclass_fields__ if name != "config_drift"}, config_drift=bool(sample.config_drift))  # pylint: disable=no-member  # facts_of() returns a dataclass instance


def evaluate(policy: SoakPolicy, started_at, required_end_at, facts, now, *, guard=None) -> Verdict:
    """The verdict.  ``guard`` needs ``integrity_ok``, ``interference`` and (optionally) ``config_drift`` attributes."""
    facts = sorted(facts, key=lambda f: f.bucket)
    stats = statistics(policy, started_at, required_end_at, facts)
    state = models.SoakState
    if (guard is not None and not guard.integrity_ok) or any(not f.integrity_ok for f in facts):
        return Verdict(state.INVALIDATED, reason=codes.BUNDLE_INTEGRITY_FAILED, stats=stats)
    if (guard is not None and guard.interference) or any(f.interference for f in facts):
        return Verdict(state.INVALIDATED, reason=codes.OVERLAPPING_EXECUTION, stats=stats)
    if (guard is not None and getattr(guard, "config_drift", False)) or any(getattr(f, "config_drift", False) for f in facts):
        return Verdict(state.INVALIDATED, reason=codes.CONFIG_DRIFT_DETECTED, stats=stats)
    return soak_evaluator.evaluate(policy, started_at, required_end_at, facts, now)


# --- the canonical final evidence summary and its digest ----------------------------------------------------------------------
def samples_digest(facts) -> str:
    rows = [[f.bucket, iso(f.sampled_at), f.result, f.expected_state_result, f.telemetry_freshness, f.integrity_ok, f.interference, f.terminal_failure,
             bool(getattr(f, "config_drift", False))] for f in sorted(facts, key=lambda f: f.bucket)]
    return hashlib.sha256(canonical_json({"domain": "clab.bootstrap.samples", "schema": EVIDENCE_SCHEMA_VERSION, "value": rows}).encode("ascii")).hexdigest()


def _tally(values) -> dict:
    out: dict = {}
    for value in values:
        out[value or "NOT_EVALUATED"] = out.get(value or "NOT_EVALUATED", 0) + 1
    return dict(sorted(out.items()))


def _resources(samples) -> dict:
    cpu, memory, warnings, drift_checks, config_devices = [], [], 0, 0, set()
    for sample in samples:
        evidence = sample.evidence or {}
        for facts in (evidence.get("devices") or {}).values():
            if isinstance(facts.get("cpu_percent"), (int, float)):
                cpu.append(float(facts["cpu_percent"]))
            if isinstance(facts.get("memory_percent"), (int, float)):
                memory.append(float(facts["memory_percent"]))
        config = evidence.get("config") or {}
        if config.get("compared"):
            drift_checks += 1
            config_devices.add(int(config["compared"]))
        warnings += int((sample.counts or {}).get("warning", 0))
    return {"max_cpu_percent": round(max(cpu), 1) if cpu else None, "max_memory_percent": round(max(memory), 1) if memory else None,
            "samples_with_config_comparison": drift_checks, "devices_compared_per_sample": sorted(config_devices), "warning_findings": warnings}


def final_summary(run, policy: SoakPolicy, samples, verdict: Verdict, completed_at) -> dict:
    """The canonical evidence summary the operator's approval is justified by (bounded; raw metrics stay in InfluxDB)."""
    facts = sorted((facts_of(s) for s in samples), key=lambda f: f.bucket)
    return {
        "summary_schema": EVIDENCE_SCHEMA_VERSION, "run_id": run.run_id, "candidate_bundle_digest": run.candidate_digest, "policy_version": run.policy_version,
        "policy": policy.to_dict(), "state": verdict.state, "technical_result": verdict.result, "reason": verdict.reason, "problems": list(verdict.problems),
        "observation": {"started_at": iso(run.started_at), "required_end_at": iso(run.required_end_at), "completed_at": iso(completed_at)},
        "coverage": verdict.stats, "samples_digest": samples_digest(facts), "expected_state": _tally(f.expected_state_result for f in facts),
        "telemetry_freshness": _tally(f.telemetry_freshness for f in facts),
        "interference": "DETECTED" if verdict.reason == codes.OVERLAPPING_EXECUTION or any(f.interference for f in facts) else "NONE",
        "integrity": "FAILED" if verdict.reason == codes.BUNDLE_INTEGRITY_FAILED or any(not f.integrity_ok for f in facts) else "INTACT",
        "config_drift": "DETECTED" if verdict.reason == codes.CONFIG_DRIFT_DETECTED or any(f.config_drift for f in facts) else "NONE",
        "resources": _resources(samples),
    }


def evidence_digest(summary: dict) -> str:
    return hashlib.sha256(canonical_json({"domain": "clab.bootstrap.evidence", "schema": EVIDENCE_SCHEMA_VERSION, "value": summary}).encode("ascii")).hexdigest()


def verify_run(run) -> list[str]:
    """Re-derive a COMPLETED / PASS run's evidence from its own persisted rows.  [] == the stored verdict, summary and digest all reproduce."""
    if not run.is_technical_pass:
        return ["NOT_TECHNICAL_PASS"]
    samples = list(run.samples.all())
    facts = [facts_of(s) for s in samples]
    summary = run.evaluation or {}
    problems = []
    if evidence_digest(summary) != run.evidence_digest:
        problems.append("EVIDENCE_DIGEST")
    if summary.get("samples_digest") != samples_digest(facts):
        problems.append("SAMPLES_DIGEST")
    if summary.get("run_id") != run.run_id or summary.get("candidate_bundle_digest") != run.candidate_digest:
        problems.append("SUMMARY_IDENTITY")
    if run.finished_at is None or run.finished_at < run.required_end_at:
        problems.append("DURATION_NOT_ELAPSED")
    else:
        policy = SoakPolicy.from_dict(run.policy)
        if summary.get("coverage") != statistics(policy, run.started_at, run.required_end_at, facts):
            problems.append("COVERAGE_MISMATCH")
        again = evaluate(policy, run.started_at, run.required_end_at, facts, run.finished_at)
        if (again.state, again.result) != (models.SoakState.COMPLETED, models.SoakResult.PASS):
            problems.append("VERDICT_NOT_REPRODUCED")
    return problems
