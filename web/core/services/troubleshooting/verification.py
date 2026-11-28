"""M5 verification, soak and honest final disposition (spec 6.3, 6.4, 7.3, 0.1).

A case is RESOLVED_VERIFIED only when (1) the service-specific checks pass, (2) no regression is observed on the surrounding
flows, (3) the soak window (when required) elapsed with no degradation, and (4) a VERIFIED ``TsVerificationRecord`` exists --
``repository.close_case`` independently enforces (4).  "Command succeeded" is never sufficient (UT-074).
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from statistics import mean
from typing import Any, Callable

from core import models as m

from . import contracts as c
from . import governance as gov
from . import repository as repo
from . import runtime_ports as rp

OUTCOMES = ("RESOLVED_VERIFIED", "ROOT_CAUSE_IDENTIFIED_REMEDIATION_PENDING", "EXPECTED_BEHAVIOR_CONFIRMED",
            "INCONCLUSIVE_ESCALATED", "EXTERNAL_PREREQUISITE_BLOCKED", "REMEDIATION_FAILED_RESTORED",
            "REMEDIATION_FAILED_UNRESTORED")
DEFAULT_SOAK = rp.DEFAULT_WINDOW


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _flow_table(before: dict, after: dict) -> list[dict]:
    rows = []
    for key in sorted(set(before) | set(after)):
        b, a = before.get(key) or {}, after.get(key) or {}
        rows.append({"flow": key, "before_loss_pct": b.get("loss_pct"), "after_loss_pct": a.get("loss_pct"),
                     "coverage": a.get("coverage"), "measurable": a.get("loss_pct") is not None})
    return rows


def verify(actor: repo.Actor, plan_id: str, ports: gov.Ports, *, service_checks: Callable[[], list[dict]],
           surrounding_flows: list[dict] | None = None, soak_window: timedelta | None = None,
           soak_status: Callable[[m.TsRemediationPlan], dict] | None = None,
           now: datetime | None = None) -> m.TsVerificationRecord:
    """Run service-specific verification after an applied plan.

    ``service_checks()`` -> ``[{"name", "passed": bool|None, "observed", "evidence_ids"}]`` (None == could not measure => not passed).
    Outcome: FAILED (any failed/unmeasured check or regression), SOAKING (checks pass, window still open), or VERIFIED.
    """
    plan = gov.get_plan(actor, plan_id)
    now = now or ports.clock()
    if plan.status not in ("VERIFYING", "SOAKING"):
        raise gov.GovernanceRefused("NOT_VERIFIABLE", f"plan is {plan.status}; only an applied plan can be verified")
    ex = m.TsActionExecution.objects.filter(plan=plan, status="APPLIED").order_by("-id").first()
    if ex is None:
        raise gov.GovernanceRefused("NO_APPLIED_EXECUTION", "no applied execution to verify")
    checks = [c.redact_value(x) for x in service_checks()]
    failed = [x.get("name", "unnamed check") for x in checks
              if x.get("passed") is not True or not x.get("evidence_ids")]
    if not checks:
        failed.append("no service-specific verification checks supplied")
    before = ex.command_or_intent.get("baseline_flows", {})
    th = plan.approval["abort_thresholds"]
    flow_defs = list(plan.impacted_flows) + [f for f in (surrounding_flows or []) if f.get("key") not in {x.get("key") for x in plan.impacted_flows}]
    required = sorted({f["key"] for f in flow_defs if f.get("key")} | set(before))
    after = ports.flow_sample(flow_defs) if flow_defs else {}
    regressions = []
    traffic = bool(plan.blast_radius.get("traffic_affecting"))
    if traffic and not required:
        regressions.append("traffic-affecting plan names no production flow; post-change service impact cannot be shown")
    for key in required:      # every named flow must have a measured, sufficiently covered sample -- absence is never "healthy"
        s_ = after.get(key)
        if s_ is None:
            regressions.append(f"{key}: missing post-change production sample")
        elif s_.get("loss_pct") is None:
            regressions.append(f"{key}: not measurable after change")
        elif (s_.get("coverage") or 0) < th["min_coverage"]:
            regressions.append(f"{key}: sample coverage {s_.get('coverage')} below required {th['min_coverage']}")
        elif s_["loss_pct"] - ((before.get(key) or {}).get("loss_pct") or 0.0) > th["max_loss_increase_pct"]:
            regressions.append(f"{key}: loss {s_['loss_pct']}% vs {(before.get(key) or {}).get('loss_pct') or 0.0}% before")
    window = max(soak_window if soak_window is not None else rp.DEFAULT_WINDOW, rp.MIN_WINDOW)   # a caller can lengthen, never shorten
    soak = {"required": bool(plan.approval.get("soak_required")), "window_seconds": int(window.total_seconds())}
    outcome, soak_state = "VERIFIED", "NOT_REQUIRED"
    if plan.approval.get("soak_required"):
        # The persisted production-flow ledger is MANDATORY evidence.  An elapsed deadline alone never proves a clean soak, and a
        # recovered sample after degradation/gap cannot erase it (runtime_ports.assess_ledger).
        led = rp.plan_soak_status(plan, now, window=window)
        soak_state = led.get("state", "UNKNOWN")
        soak.update({"ledger": {k: led.get(k) for k in ("state", "samples", "usable_samples", "coverage", "gaps", "degraded_samples",
                                                       "started_at", "ends_at", "reasons")}})
        led_keys = {f["key"] for f in (rp.read_ledger(plan) or {}).get("flows", [])}
        if led_keys and set(required) - led_keys:
            regressions.append("flows not covered by the soak ledger: " + ", ".join(sorted(set(required) - led_keys)))
        if soak_state in ("RUNNING", "NO_EVIDENCE"):
            outcome = "SOAKING"
        elif soak_state != "PASSED":
            outcome = "FAILED"
            failed.append(f"soak {soak_state}: " + "; ".join(led.get("reasons", [])[:3]))
        ext = soak_status(plan) if soak_status else None     # optionally ALSO require the core soak run (both must pass)
        if ext is not None:
            soak.update({"external": ext})
            if ext.get("result") == "FAILED" or ext.get("state") in ("FAILED", "CANCELLED"):
                outcome = "FAILED"
            elif ext.get("state") != "PASSED" and outcome == "VERIFIED":
                outcome = "SOAKING"
    if failed or regressions:
        outcome = "FAILED"
        soak_state = "FAILED" if soak["required"] and soak_state in ("PASSED", "RUNNING", "NO_EVIDENCE", "NOT_REQUIRED") else soak_state
    rec = repo.record(
        actor, plan.case, "verification", basis="OBSERVED" if all(x.get("evidence_ids") for x in checks) and checks else "DERIVED",
        evidence_ids=[i for x in checks for i in x.get("evidence_ids", [])], stage_decision=f"{outcome}: {len(checks)} check(s)", now=now,
        original_symptom=plan.case.symptom, before_after={"flows": _flow_table(before, after)},
        test_steps=[{"name": x.get("name"), "passed": x.get("passed")} for x in checks],
        observed_values={"checks": [{"name": x.get("name"), "observed": x.get("observed")} for x in checks], "soak": soak},
        soak_status=soak_state, regressions=regressions, final_diagnosis=plan.approval.get("addressed_fault", "")[:255],
        residual_impact=("; ".join(failed + regressions))[:255], outcome=outcome)
    repo.audit(actor, plan.case, "VERIFICATION_RECORDED", decision=rec.record_id, result=outcome, risk=plan.risk, operation=plan.record_id,
               rationale=rec.residual_impact, now=now)
    if outcome == "VERIFIED":
        gov._set_status(actor, plan, "RESOLVED", "service verification passed", now=now)
    elif outcome == "SOAKING" and plan.status == "VERIFYING":
        gov._set_status(actor, plan, "SOAKING", "soak window open", now=now)
    return rec


def _started(plan: m.TsRemediationPlan, now: datetime) -> datetime:
    ex = m.TsActionExecution.objects.filter(plan=plan, status="APPLIED").order_by("-id").first()
    return ex.executed_at or now


def abort_failed_verification(actor: repo.Actor, plan_id: str, ports: gov.Ports, *, now: datetime | None = None) -> m.TsCase:
    """Verification FAILED after a successful config command: honest unresolved disposition, never RESOLVED_VERIFIED (UT-074)."""
    plan = gov.get_plan(actor, plan_id)
    now = now or ports.clock()
    rec = m.TsVerificationRecord.objects.filter(case=plan.case).order_by("-id").first()
    if rec is None or rec.outcome != "FAILED":
        raise gov.GovernanceRefused("NO_FAILED_VERIFICATION")
    disp = {"outcome": "INCONCLUSIVE_ESCALATED", "reason": "change applied but service verification failed",
            "residual_impact": rec.residual_impact, "plan": plan.record_id, "action_applied_and_not_reverted": True}
    return repo.transition_case(actor, plan.case, "UNRESOLVED", reason="verification failed", disposition=disp, now=now) \
        if plan.case.state in ("VERIFYING", "TESTING", "REMEDIATING") else plan.case


def finalize(actor: repo.Actor, case: m.TsCase, *, now: datetime | None = None) -> dict[str, Any]:
    """Compute the one honest outcome (spec 0.1) from recorded facts; close the case only when the outcome is terminal."""
    case = repo.get_case(actor, case.case_id)
    now = now or _now()
    outcome, why = compute_outcome(case)
    doc = {"outcome": outcome, "why": why, "computed_at": c.iso(now)}
    terminal = {"RESOLVED_VERIFIED": "RESOLVED_VERIFIED", "EXPECTED_BEHAVIOR_CONFIRMED": "NO_FAULT_FOUND",
                "INCONCLUSIVE_ESCALATED": "UNRESOLVED", "EXTERNAL_PREREQUISITE_BLOCKED": "EXTERNALLY_BLOCKED",
                "REMEDIATION_FAILED_RESTORED": "UNRESOLVED", "REMEDIATION_FAILED_UNRESTORED": "UNRESOLVED"}
    if outcome in terminal and case.state not in m.TS_TERMINAL_CASE_STATES:
        legal = repo._TRANSITIONS.get(case.state, set())
        if terminal[outcome] in legal:
            repo.close_case(actor, case, terminal[outcome], disposition=doc, now=now)
            doc["closed"] = True
        else:
            doc["closed"] = False
            doc["note"] = f"case state {case.state} cannot move directly to {terminal[outcome]}"
    else:
        doc["closed"] = case.state in m.TS_TERMINAL_CASE_STATES
    return doc


def compute_outcome(case: m.TsCase) -> tuple[str, str]:
    if case.disposition.get("outcome") in ("REMEDIATION_FAILED_UNRESTORED", "REMEDIATION_FAILED_RESTORED"):
        return case.disposition["outcome"], case.disposition.get("stop_reason", "")
    last_exec = m.TsActionExecution.objects.filter(case=case).order_by("-id").first()
    if last_exec is not None and last_exec.status == "ABORTED_UNRESTORED":
        return "REMEDIATION_FAILED_UNRESTORED", last_exec.stop_reason
    if last_exec is not None and last_exec.status == "ABORTED_RESTORED":
        return "REMEDIATION_FAILED_RESTORED", last_exec.stop_reason
    ver = m.TsVerificationRecord.objects.filter(case=case).order_by("-id").first()
    if ver is not None:
        if ver.outcome == "VERIFIED":
            return "RESOLVED_VERIFIED", "service-specific verification (and soak when required) passed"
        if ver.outcome == "SOAKING":
            return "ROOT_CAUSE_IDENTIFIED_REMEDIATION_PENDING", "soak window still open; not resolved yet"
        return "INCONCLUSIVE_ESCALATED", f"verification {ver.outcome}: {ver.residual_impact}"
    handoff = m.TsAIHandoff.objects.filter(case=case).order_by("-id").first()
    if handoff is not None and handoff.status in ("BLOCKED",):
        return "EXTERNAL_PREREQUISITE_BLOCKED", handoff.checkpoint.get("blocked_reason", "")
    if handoff is not None and handoff.status in ("ESCALATED", "EXHAUSTED"):
        return "INCONCLUSIVE_ESCALATED", handoff.checkpoint.get("escalation_reason", "")
    confirmed = m.TsHypothesis.objects.filter(case=case, state="CONFIRMED").exists()
    if confirmed:
        return "ROOT_CAUSE_IDENTIFIED_REMEDIATION_PENDING", "root cause confirmed; no verified remediation"
    if case.disposition.get("expected_behavior"):
        return "EXPECTED_BEHAVIOR_CONFIRMED", "operator/engine confirmed expected behavior with no production impact"
    return "INCONCLUSIVE_ESCALATED", "no confirmed root cause and no verified remediation"


def metrics(actor: repo.Actor, *, now: datetime | None = None) -> dict[str, Any]:
    """MTTD / MTTI / MTTR (spec 7.3).  MTTR uses ONLY cases that reached RESOLVED_VERIFIED; others are reported as censored."""
    now = now or _now()
    cases = repo.list_cases(actor)
    mttd, mtti, mttr, censored, by_outcome = [], [], [], 0, {}
    for case in cases:
        if case.first_detected_at:
            mttd.append((case.opened_at - case.first_detected_at).total_seconds())
        hyp = m.TsHypothesis.objects.filter(case=case, state="CONFIRMED").order_by("created_at").first()
        if hyp:
            mtti.append((hyp.created_at - (case.first_detected_at or case.opened_at)).total_seconds())
        out = case.disposition.get("outcome") or case.state
        by_outcome[out] = by_outcome.get(out, 0) + 1
        if case.state == "RESOLVED_VERIFIED" and case.closed_at:
            mttr.append((case.closed_at - (case.first_detected_at or case.opened_at)).total_seconds())
        else:
            censored += 1
    tests = m.TsDiagnosticTest.objects.filter(case__in=cases)
    def avg(xs):
        return round(mean(xs), 1) if xs else None
    return {"schema": "nmas.troubleshooting.metrics/1", "generated_at": c.iso(now), "cases": len(cases),
            "mttd_seconds": avg(mttd), "mtti_seconds": avg(mtti), "mttr_seconds": avg(mttr),
            "mttr_sample": len(mttr), "censored_unresolved_or_open": censored, "outcomes": by_outcome,
            "tests_executed": tests.exclude(verdict__in=["SKIPPED", "UNAVAILABLE"]).count(),
            "tests_skipped_or_unavailable": tests.filter(verdict__in=["SKIPPED", "UNAVAILABLE"]).count(),
            "ai_handoffs": m.TsAIHandoff.objects.filter(case__in=cases).count(),
            "rollbacks_attempted": m.TsActionExecution.objects.filter(case__in=cases).exclude(rollback={}).count()}
