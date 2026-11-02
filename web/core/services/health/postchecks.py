"""Post-deployment verification wrapper around the reusable engine.

Phase 15 does not deploy, so it proved this with synthetic / fake evidence.  Phase 17's execution engine
(``core.services.execution``) calls ``run_plan_postcheck`` after a push -- optionally restricted to the executed
Configlets (``cfg_ids``) -- and persists the final evaluation with ``record_postcheck_run``.  It gets the SAME evaluators
the precheck used, with POSTCHECK expectations: missing evidence is INCOMPLETE, a demonstrated deviation is FAIL, and
only fully observed requirements PASS.  This module itself never deploys or contacts a device beyond the read-only
evidence collection of ``prechecks.collect_scope_evidence``.
"""

from __future__ import annotations

from datetime import datetime

from . import telemetry
from .codes import CheckStatus, Mode, Phase, PostcheckResult, Role
from .evaluators import RequirementEvaluation, _one_sided_ospf, evaluate_plan_requirements, evaluate_requirements, isolated_ports
from .requirements import normalize_plan
from .prechecks import collect_scope_evidence, _scope
from .results import CheckResult, ordered, utcnow


def _evaluate(plan, phase_evidence, scope, cfg_ids):
    """The plan's requirements (optionally only those of ``cfg_ids``: a Partial (UAT) run must not demand Configlets it
    intentionally did not execute) against the supplied evidence, using the SAME engine the precheck used."""
    if cfg_ids is None:
        return evaluate_plan_requirements(plan, Phase.POSTCHECK, phase_evidence, roles=scope.roles)
    wanted = set(cfg_ids)
    return evaluate_requirements([r for r in normalize_plan(plan) if r.cfg_id in wanted], Phase.POSTCHECK, phase_evidence,
                                 roles=scope.roles, one_sided_ospf=_one_sided_ospf(plan), isolated_ports=isolated_ports(plan))


def record_postcheck_run(plan, evaluation: RequirementEvaluation, *, actor: str = "", started_at: datetime | None = None, cfg_ids=None):
    """Persist an already-computed evaluation as one append-only CHANGE_POSTCHECK run (used after a settling poll)."""
    from .persistence import record_run

    scope = _scope(plan)
    recorded = list(evaluation.results)
    failed = sorted({f"{r.cfg_id}:{r.check_code}" for r in evaluation.results if r.status == CheckStatus.FAIL})
    if evaluation.result == PostcheckResult.FAIL:  # a plan-level summary row for the run; the engine's own results are unchanged
        recorded.append(CheckResult("POSTCHECK_REQUIREMENT_FAILED", CheckStatus.FAIL, plan.change.change_id,
                                    f"{len(failed)} verification requirement(s) failed.", "PLAN", observed={"failed": failed},
                                    role=Role.PLAN, phase=Phase.POSTCHECK))
    extra = {"change_id": plan.change.change_id, "scope": scope.to_dict(), "requirements": evaluation.summary,
             "provenance": {"plan_id": str(plan.plan_id), "plan_hash": plan.plan_hash, "validation_run_id": str(plan.validation_run.run_id)}}
    if cfg_ids is not None:
        extra["cfg_ids"] = sorted(cfg_ids)
    return record_run(mode=Mode.CHANGE_POSTCHECK, status=evaluation.result, results=ordered(recorded), extra=extra,
                      actor=actor, change=plan.change, plan=plan, started_at=started_at)


def run_plan_postcheck(plan, *, actor: str = "", evidence=None, live_reads: bool = True, snapshot=None, session_factory=None,
                       now: datetime | None = None, persist: bool = True, cfg_ids=None):
    """-> (RequirementEvaluation, run | None).  Evaluates the plan's requirements for POSTCHECK against supplied or freshly collected
    evidence.  ``cfg_ids`` restricts the evaluation to those Configlets (Phase 17: the executed scope of a Partial (UAT) run)."""
    started = now or utcnow()
    scope = _scope(plan)
    if evidence is None:
        snapshot = snapshot or telemetry.collect(now=started)
        evidence = collect_scope_evidence(scope, snapshot, live_reads=live_reads, session_factory=session_factory, now=started)
    evaluation: RequirementEvaluation = _evaluate(plan, evidence, scope, cfg_ids)
    run = record_postcheck_run(plan, evaluation, actor=actor, started_at=started, cfg_ids=cfg_ids) if persist else None
    return evaluation, run
