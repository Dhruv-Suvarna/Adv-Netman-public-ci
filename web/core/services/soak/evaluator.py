"""Deterministic soak evaluation: the same policy + the same samples + the same ``now`` always give the same verdict.

PURE (no I/O, no clock of its own: ``now`` is a parameter; only ``verify_run`` reads the run's own sample rows).  The order of the rules IS the
policy, and there is no score:

    1  integrity failure (any sample / the guard)      -> INVALIDATED  BUNDLE_INTEGRITY_FAILED   terminal, never repaired
    2  interference (any sample / the guard)           -> INVALIDATED  OVERLAPPING_EXECUTION     terminal
    3  a demonstrated intended-state failure           -> COMPLETED / FAIL  EXPECTED_STATE_FAILED    terminal at once (never averaged away)
    4  critical CPU / memory for N consecutive samples -> COMPLETED / FAIL  RESOURCE_CRITICAL_SUSTAINED   (N = the project's own alert policy)
    5  ``now`` before ``required_end_at``              -> RUNNING          (elapsed < the pinned duration, boundary inclusive: now >= end is enough)
    6  clock anomaly / too few covered intervals / a gap
       longer than the maximum (leading and trailing edges included) / no usable sample
                                                       -> COMPLETED / INCOMPLETE  COVERAGE_INSUFFICIENT
    7  otherwise                                       -> COMPLETED / PASS       TECHNICAL_PASS  (an operator decision is STILL required)

A "usable" sample is PASS or PASS_WITH_WARNINGS.  INCOMPLETE samples (missing / stale evidence) are never usable, so they only ever widen a gap;
they neither fail nor pass anything.  Warnings never fail a soak.  Samples taken AFTER the window ends (the closing sample) never extend
coverage, but their failures and invalidations still count.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timezone

from ... import models
from ..bundles.canonical import canonical_json
from .codes import EVIDENCE_SCHEMA_VERSION, TECHNICAL_PASS
from . import codes
from .policy import SoakPolicy

SR = models.SoakSampleResult
USABLE = frozenset({SR.PASS, SR.PASS_WITH_WARNINGS})


def iso(value: datetime | None) -> str | None:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z") if value else None


@dataclass(frozen=True)
class SampleFacts:
    bucket: int
    sampled_at: datetime
    result: str
    integrity_ok: bool
    interference: bool
    terminal_failure: bool
    resource_critical: tuple
    expected_state_result: str
    telemetry_freshness: str
    warnings: int
    config_drift: bool = False


def facts_of(sample) -> SampleFacts:
    return SampleFacts(
        bucket=sample.bucket, sampled_at=sample.sampled_at, result=sample.result, integrity_ok=sample.integrity_ok, interference=sample.interference,
        terminal_failure=sample.terminal_failure, resource_critical=tuple(sample.resource_critical or ()),
        expected_state_result=sample.expected_state_result, telemetry_freshness=sample.telemetry_freshness,
        warnings=int((sample.counts or {}).get("warning", 0)), config_drift=bool(getattr(sample, "config_drift", False)),
    )


@dataclass
class Verdict:
    state: str
    result: str = ""
    reason: str = ""
    problems: list = field(default_factory=list)
    stats: dict = field(default_factory=dict)

    @property
    def terminal(self) -> bool:
        return self.state != models.SoakState.RUNNING


def statistics(policy: SoakPolicy, started_at: datetime, required_end_at: datetime, facts) -> dict:
    """Coverage facts of a sample set.  Deterministic, JSON-safe, independent of ``now``."""
    facts = sorted(facts, key=lambda f: f.bucket)
    total = policy.total_buckets
    usable = [f for f in facts if f.result in USABLE and started_at <= f.sampled_at <= required_end_at]
    covered = {f.bucket for f in usable if f.bucket < total}
    times = sorted(f.sampled_at for f in usable)
    points = [started_at, *times] + ([required_end_at] if not times or times[-1] < required_end_at else [])
    gaps = [(later - earlier).total_seconds() for earlier, later in zip(points, points[1:])]
    anomalies = sum(1 for f in facts if f.sampled_at < started_at) + sum(1 for a, b in zip(facts, facts[1:]) if b.sampled_at < a.sampled_at)
    return {
        "expected_intervals": total, "covered_intervals": len(covered), "coverage_percent": round(100 * len(covered) / total, 2) if total else 0.0,
        "samples": len(facts), "usable_samples": len(usable), "incomplete_samples": sum(1 for f in facts if f.result == SR.INCOMPLETE),
        "warning_samples": sum(1 for f in facts if f.result == SR.PASS_WITH_WARNINGS), "failed_samples": sum(1 for f in facts if f.result == SR.FAIL),
        "invalidated_samples": sum(1 for f in facts if f.result == SR.INVALIDATED), "warning_findings": sum(f.warnings for f in facts),
        "blocking_findings": sum(1 for f in facts if f.terminal_failure), "max_gap_seconds": max(gaps) if gaps else 0.0,
        "leading_gap_seconds": gaps[0] if gaps else 0.0, "trailing_gap_seconds": gaps[-1] if gaps else 0.0, "clock_anomalies": anomalies,
        "first_sample_at": iso(facts[0].sampled_at) if facts else None, "last_sample_at": iso(max(f.sampled_at for f in facts)) if facts else None,
    }


def resource_streak(facts) -> tuple[int, str]:
    """The longest run of CONSECUTIVE samples with the same device:code at a critical level.  INCOMPLETE samples carry no information about
    resources, so they neither extend nor reset a streak."""
    current: dict = {}
    best, best_key = 0, ""
    for fact in sorted(facts, key=lambda f: f.bucket):
        if fact.result == SR.INCOMPLETE:
            continue
        keys = set(fact.resource_critical)
        current = {key: current.get(key, 0) + 1 for key in keys}
        for key, count in sorted(current.items()):
            if count > best:
                best, best_key = count, key
    return best, best_key


def evaluate(policy: SoakPolicy, started_at: datetime, required_end_at: datetime, facts, now: datetime, *, guard=None) -> Verdict:
    """The verdict (see the module docstring for the rule order).  ``guard`` needs ``integrity_ok`` and ``interference`` attributes."""
    facts = sorted(facts, key=lambda f: f.bucket)
    stats = statistics(policy, started_at, required_end_at, facts)
    state = models.SoakState
    if (guard is not None and not guard.integrity_ok) or any(not f.integrity_ok for f in facts):
        return Verdict(state.INVALIDATED, reason=codes.BUNDLE_INTEGRITY_FAILED, stats=stats)
    if (guard is not None and guard.interference) or any(f.interference for f in facts):
        return Verdict(state.INVALIDATED, reason=codes.OVERLAPPING_EXECUTION, stats=stats)
    if any(f.config_drift for f in facts):     # the configuration under observation changed: invalid, never "failed" and never recoverable
        return Verdict(state.INVALIDATED, reason=codes.CONFIGURATION_DRIFT, stats=stats)
    if any(f.terminal_failure for f in facts):
        return Verdict(state.COMPLETED, models.SoakResult.FAIL, codes.EXPECTED_STATE_FAILED, stats=stats)
    streak, key = resource_streak(facts)
    if streak >= policy.resource_consecutive_samples:
        return Verdict(state.COMPLETED, models.SoakResult.FAIL, codes.RESOURCE_CRITICAL_SUSTAINED, problems=[f"{key} x{streak}"], stats=stats)
    if now < required_end_at:
        return Verdict(state.RUNNING, stats=stats)
    problems = []
    if stats["clock_anomalies"]:
        problems.append("CLOCK_ANOMALY")
    if not stats["usable_samples"]:
        problems.append("NO_USABLE_SAMPLES")
    if stats["covered_intervals"] * 100 < policy.min_coverage_percent * stats["expected_intervals"]:
        problems.append("MIN_COVERAGE")
    if stats["leading_gap_seconds"] > policy.max_gap_seconds:
        problems.append("LEADING_GAP")
    if stats["trailing_gap_seconds"] > policy.max_gap_seconds:
        problems.append("TRAILING_GAP")
    if stats["max_gap_seconds"] > policy.max_gap_seconds and not {"LEADING_GAP", "TRAILING_GAP"} & set(problems):
        problems.append("MAX_GAP")
    if problems:
        return Verdict(state.COMPLETED, models.SoakResult.INCOMPLETE, codes.COVERAGE_INSUFFICIENT, problems=problems, stats=stats)
    return Verdict(state.COMPLETED, models.SoakResult.PASS, TECHNICAL_PASS, stats=stats)


# --- the canonical final evidence summary and its digest ----------------------------------------------------------------------
def samples_digest(facts) -> str:
    """SHA-256 over the ordered core facts of every sample: binds the summary to the persisted sample rows without copying them."""
    # a drift marker is appended ONLY to a drifted sample's row, so every digest computed before V2 Phase 5C still reproduces
    rows = [[f.bucket, iso(f.sampled_at), f.result, f.expected_state_result, f.telemetry_freshness, f.integrity_ok, f.interference, f.terminal_failure,
             *(["CONFIGURATION_DRIFT"] if f.config_drift else [])]
            for f in sorted(facts, key=lambda f: f.bucket)]
    return hashlib.sha256(canonical_json({"domain": "clab.soak.samples", "schema": EVIDENCE_SCHEMA_VERSION, "value": rows}).encode("ascii")).hexdigest()


def _tally(values) -> dict:
    out: dict = {}
    for value in values:
        out[value or "NOT_EVALUATED"] = out.get(value or "NOT_EVALUATED", 0) + 1
    return dict(sorted(out.items()))


def final_summary(run, policy: SoakPolicy, facts, verdict: Verdict, completed_at: datetime) -> dict:
    """The canonical evidence summary a Golden decision is justified by (bounded; raw metrics stay in InfluxDB)."""
    facts = sorted(facts, key=lambda f: f.bucket)
    return {
        "summary_schema": EVIDENCE_SCHEMA_VERSION, "soak_id": run.soak_id, "probation_bundle_digest": run.bundle_digest, "policy_version": run.policy_version,
        "policy": policy.to_dict(), "state": verdict.state, "technical_result": verdict.result, "reason": verdict.reason, "problems": list(verdict.problems),
        "observation": {"started_at": iso(run.started_at), "required_end_at": iso(run.required_end_at), "completed_at": iso(completed_at)},
        "coverage": verdict.stats, "samples_digest": samples_digest(facts),
        "expected_state": _tally(f.expected_state_result for f in facts), "telemetry_freshness": _tally(f.telemetry_freshness for f in facts),
        "interference": "DETECTED" if verdict.reason == codes.OVERLAPPING_EXECUTION or any(f.interference for f in facts) else "NONE",
        "integrity": "FAILED" if verdict.reason == codes.BUNDLE_INTEGRITY_FAILED or any(not f.integrity_ok for f in facts) else "INTACT",
    }


def evidence_digest(summary: dict) -> str:
    return hashlib.sha256(canonical_json({"domain": "clab.soak.evidence", "schema": EVIDENCE_SCHEMA_VERSION, "value": summary}).encode("ascii")).hexdigest()


def verify_run(run) -> list[str]:
    """Re-derive a COMPLETED / PASS run's evidence from its own persisted rows.  [] == the stored verdict, summary and digest all reproduce.

    A tampered sample, summary or digest, or a verdict that no longer follows from the samples, is reported (never repaired)."""
    if not run.is_technical_pass:
        return ["NOT_TECHNICAL_PASS"]
    facts = [facts_of(sample) for sample in run.samples.all()]
    summary = run.evaluation or {}
    problems = []
    if evidence_digest(summary) != run.evidence_digest:
        problems.append("EVIDENCE_DIGEST")
    if summary.get("samples_digest") != samples_digest(facts):
        problems.append("SAMPLES_DIGEST")
    if summary.get("soak_id") != run.soak_id or summary.get("probation_bundle_digest") != run.bundle_digest:
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
