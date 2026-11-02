"""Change-aware precheck: "can this CURRENT validated CURRENT plan be attempted safely RIGHT NOW?"

It DEPLOYS NOTHING and re-derives nothing.  It consumes:

* the latest Phase-13 validation -- must be CURRENT and PASS / PASS_WITH_WARNINGS (never re-run here);
* the latest Phase-14 plan -- must be CURRENT and pinned to that validation (never rebuilt here);
* current health evidence for the plan-derived affected scope only (an unrelated fleet fault never blocks).

Prerequisite gates (validation / plan) short-circuit BEFORE any device is touched.  Health preconditions and the plan's
PRECHECK-phase requirements then evaluate against evidence gathered once for the scope.  Blocking policy: see
``results.effective_blocking`` and ``codes.CODES`` (docs/HEALTH_PRECHECK_POSTCHECK.md, "Blocking policy").
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from .. import change_plan_service, change_validation_service as cvs
from ..validation.findings import Currency, Status
from . import device as device_module, inventory, live, telemetry
from .codes import CheckStatus, Mode, Phase, PrecheckResult, Role
from .evaluators import RequirementEvaluation, evaluate_plan_requirements
from .evidence import DeviceEvidence, EvidenceSet, merge_precedence
from .fleet import quick_checks
from .requirements import normalize_plan
from .results import CheckResult, ordered, precheck_result, utcnow

S = CheckStatus


@dataclass
class PrecheckOutcome:
    result: str
    results: list
    scope: object | None = None
    evaluation: RequirementEvaluation | None = None
    run: object | None = None
    report: dict = field(default_factory=dict)
    plan: object | None = None


def _gate(change, sources, check_sources: bool) -> tuple[list[CheckResult], object | None]:
    """Validation + plan prerequisites.  Returns (gate results, plan-if-ready).  Never runs validation, never builds a plan."""
    results: list[CheckResult] = []
    if sources is None and check_sources:
        sources = cvs.build_source_snapshot(change)  # ONE read-only source snapshot shared by both currency checks
    currency = cvs.get_validation_currency(change, sources=sources, check_sources=check_sources)
    state, latest = currency["state"], currency["latest"]
    plan = change_plan_service.get_latest_plan(change)

    def gate(code, status, message, observed=None):
        results.append(CheckResult(code, status, change.change_id, message, "PLAN", observed=observed, role=Role.PLAN, freshness="FRESH"))

    validation_ok = False
    if state == Currency.NEVER_RUN:
        gate("VALIDATION_NOT_PASSING", S.UNKNOWN, "The Change has never been validated.", {"validation": "NEVER_RUN"})
    elif state == Currency.STALE:
        gate("PLAN_VALIDATION_STALE", S.FAIL, "The latest validation is STALE; re-run Change Validation.", {"reasons": currency["reasons"]})
    elif latest.status == Status.BLOCKED:
        gate("VALIDATION_NOT_PASSING", S.FAIL, "The latest validation is BLOCKED.", {"status": latest.status, "run_id": str(latest.run_id)})
    elif latest.status == Status.INCOMPLETE:
        gate("VALIDATION_NOT_PASSING", S.UNKNOWN, "The latest validation is INCOMPLETE.", {"status": latest.status, "run_id": str(latest.run_id)})
    else:
        validation_ok = True
        gate("PLAN_VALIDATION_CURRENT", S.PASS, f"The latest validation is CURRENT and {latest.status}.", {"status": latest.status, "run_id": str(latest.run_id)})

    ready = None
    if plan is None:
        if validation_ok:
            gate("PLAN_MISSING", S.UNKNOWN, "No plan has been built for this Change.", {})
    else:
        plan_currency = change_plan_service.get_plan_currency(plan, sources=sources, check_sources=check_sources)
        if plan_currency["state"] == "CURRENT":
            gate("PLAN_CURRENT", S.PASS, "The plan is CURRENT and pinned to the current validation.", {"plan_id": str(plan.plan_id)})
            ready = plan if validation_ok else None
        else:
            gate("PLAN_STALE", S.FAIL, "The plan is STALE and must not be handed to deployment.",
                 {"plan_id": str(plan.plan_id), "reasons": plan_currency["reasons"]})
    return results, ready


def collect_scope_evidence(scope, snapshot: telemetry.TelemetrySnapshot, *, live_reads: bool = True, session_factory=None,
                           dhcp_needed: bool = False, dhcp_state: dict | None = None, now: datetime | None = None) -> EvidenceSet:
    """Gather evidence ONCE for the scope: telemetry for every device, a bounded live read for each managed one."""
    now = now or utcnow()
    devices: dict[str, DeviceEvidence] = {}
    for name in scope.devices:
        managed = inventory.get_managed_device(name)
        tele = telemetry.device_evidence(snapshot, name, managed["platform"] if managed else "")
        live_evidence = live.read_device(managed, session_factory=session_factory, now=now) if (live_reads and managed) else None
        if managed is None:
            tele.live_error = "NOT_MANAGED"
        devices[name] = merge_precedence(live_evidence, tele) if live_evidence is not None else tele
    services = {}
    if dhcp_needed:
        services["dhcp"] = dhcp_state if dhcp_state is not None else live.dhcp_service_state()
    pipeline = {"available": snapshot.available and snapshot.backend_status == "OK", "topology_available": snapshot.available,
                "backend_status": snapshot.backend_status}
    return EvidenceSet(devices=devices, now=now, thresholds=snapshot.thresholds, pipeline=pipeline, services=services)


def _monitoring_check(scope, evidence: EvidenceSet) -> CheckResult:
    """Postchecks want monitoring visibility.  It blocks only when some TARGET has no live-read path of its own."""
    pipeline = evidence.pipeline
    if pipeline["available"]:
        return CheckResult("MONITORING_PIPELINE_UNHEALTHY", S.PASS, "FLEET", "The monitoring backend is healthy; postcheck telemetry is available.",
                           "TELEMETRY", observed=pipeline, role=Role.PLAN)
    needs = [name for name in scope.names(Role.TARGET) if live.get_capability((inventory.get_managed_device(name) or {}).get("platform", ""))["status"] != "SUPPORTED"]
    if not needs:
        return CheckResult("MONITORING_PIPELINE_UNHEALTHY", S.WARN, "FLEET",
                           "The monitoring backend is unhealthy, but every target device can be verified by live read-only queries.",
                           "TELEMETRY", observed={**pipeline, "targets_needing_telemetry": []}, role=Role.PLAN)
    status = S.UNKNOWN if not pipeline["topology_available"] else S.FAIL
    return CheckResult("MONITORING_PIPELINE_UNHEALTHY", status, "FLEET",
                       "The monitoring backend is unhealthy and some targets can only be verified through telemetry.",
                       "TELEMETRY", observed={**pipeline, "targets_needing_telemetry": needs}, role=Role.PLAN)


def _health_results(scope, evidence: EvidenceSet, snapshot, now) -> list[CheckResult]:
    results = []
    for name, member in sorted(scope.devices.items()):
        device_evidence = evidence.device(name) or DeviceEvidence(device=name)
        group = device_evidence.group("telemetry")
        fresh = group.freshness(now, snapshot.thresholds) if group is not None and group.available else "UNKNOWN"
        results.append(device_module.reachability_check(name, device_evidence, fresh, role=member.role))
        results += quick_checks(name, device_evidence, snapshot, now=now, role=member.role, live_ok=device_evidence.live_reachable)
    return results


def run_change_precheck(change, *, actor: str = "", evidence: EvidenceSet | None = None, sources=None, check_sources: bool = True,
                        live_reads: bool = True, snapshot: telemetry.TelemetrySnapshot | None = None, session_factory=None,
                        dhcp_state: dict | None = None, now: datetime | None = None, persist: bool = True) -> PrecheckOutcome:
    """Explicit precheck.  Deploys nothing; never validates or plans; never changes the Change, plan or lifecycle."""
    started = now or utcnow()
    gate_results, plan = _gate(change, sources, check_sources)
    outcome = PrecheckOutcome(result=precheck_result(gate_results), results=list(gate_results), plan=plan)
    extra = {"change_id": change.change_id, "gate": [r.to_dict() for r in gate_results]}

    if plan is not None:
        scope = _scope(plan)
        snapshot = snapshot or telemetry.collect(now=started)
        requirements = normalize_plan(plan)
        dhcp_needed = any(r.kind == "DHCP_RELAY_INTENDED" for r in requirements)
        if evidence is None:
            evidence = collect_scope_evidence(scope, snapshot, live_reads=live_reads, session_factory=session_factory,
                                              dhcp_needed=dhcp_needed, dhcp_state=dhcp_state, now=started)
        health = _health_results(scope, evidence, snapshot, started)
        health.append(_monitoring_check(scope, evidence))
        if dhcp_needed:
            health.append(device_module.dhcp_state_check(evidence.services.get("dhcp") or {"error": "NOT_COLLECTED"}, device="FLEET", role=Role.PLAN))
        evaluation = evaluate_plan_requirements(plan, Phase.PRECHECK, evidence, roles=scope.roles)
        results = [*gate_results, *health, *evaluation.results]
        verdict = precheck_result(results)
        if verdict == PrecheckResult.BLOCKED:
            blockers = sorted({f"{r.device}:{r.check_code}" for r in results if r.blocking and r.status == S.FAIL and r.role != Role.PLAN})
            if blockers:
                results.append(CheckResult("PLAN_HEALTH_PRECONDITION_FAILED", S.FAIL, change.change_id,
                                           f"{len(blockers)} blocking health precondition(s) failed.", "PLAN", observed={"blockers": blockers}, role=Role.PLAN))
        outcome = PrecheckOutcome(result=verdict, results=results, scope=scope, evaluation=evaluation, plan=plan)
        extra.update({"scope": scope.to_dict(), "requirements": evaluation.summary, "thresholds": snapshot.thresholds,
                      "evidence": {name: device_module.facts_summary(ev) for name, ev in sorted(evidence.devices.items())},
                      "services": {k: v for k, v in evidence.services.items()}, "pipeline": evidence.pipeline})
        extra["provenance"] = _provenance(change, plan)
    else:
        extra["provenance"] = _provenance(change, change_plan_service.get_latest_plan(change))

    if persist:
        from .persistence import record_run, serialize_health_run

        outcome.run = record_run(mode=Mode.CHANGE_PRECHECK, status=outcome.result, results=ordered(outcome.results), extra=extra, actor=actor,
                                 change=change, plan=plan or change_plan_service.get_latest_plan(change), started_at=started)
        outcome.report = serialize_health_run(outcome.run)["report"]
    return outcome


def _scope(plan):
    from .scope import build_affected_scope

    return build_affected_scope(plan)


def _provenance(change, plan) -> dict:
    if plan is None:
        return {"change_id": change.change_id, "plan": None}
    return {"change_id": change.change_id, "plan_id": str(plan.plan_id), "plan_hash": plan.plan_hash,
            "validation_run_id": str(plan.validation_run.run_id), "validation_input_hash": plan.validation_input_hash,
            "planner_version": plan.planner_version}
