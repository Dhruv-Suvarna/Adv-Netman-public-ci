"""The Golden bundle: the Phase-19 structure, and the Phase-20 evidence-checked promotion.

A Golden bundle is a ``GOLDEN`` ``ConfigurationBundle`` whose parent is a Probation bundle: immutable, content-addressed, lineage-backed.  Since
Phase 20 there is exactly ONE way to make one, and it accepts exactly ONE kind of evidence:

    create_golden_bundle(probation, evidence=<ProbationSoakRun>, actor=.., reason=..)

It is called by the operator's explicit APPROVE (``soak.decision.decide``) and by nothing else: never by the collector, never by a view, never
by a flag.  Immediately before creating anything -- inside the creating transaction, on a locked soak row -- it RE-CHECKS everything, because the
time between the last sample and the operator's click is real:

    the Probation bundle still verifies                 the soak observed THIS bundle (id and digest)
    the soak COMPLETED with result PASS                 its verdict, summary and digest reproduce from its own samples (``verify_run``)
    the pinned duration really elapsed                  the technical pass is still inside the decision window
    no later execution touched the candidate's devices  no decision is already recorded for the soak
    no Golden child exists (else: return that one)

It never re-renders, re-loads or re-verifies anything: the Golden payload is a deep copy of the Probation payload (so the payload digest is
equal and only kind / lineage / promotion differ), and it sends nothing to any device -- promotion is artifact + audit work, not deployment.
Whether the running configuration is also persisted to startup-config is NOT decided here (documented limitation).
"""

from __future__ import annotations

import copy

from django.db import transaction
from django.utils import timezone

from ... import models
from ..soak import evaluator as soak_evaluator, interference as soak_interference
from . import eligibility, persistence
from .codes import GOLDEN_BLOCKERS, GOLDEN_BUILDER_VERSION, blocker
from .eligibility import DerivationEligibility
from .integrity import verify_bundle_integrity
from .persistence import BundleResult

MAX_REASON_CHARS = 500


def check_golden_eligibility(probation, evidence=None, *, now=None) -> DerivationEligibility:
    """May this Probation bundle become Golden, on this evidence, RIGHT NOW?  Read-only; every blocker has a stable code."""
    now = now or timezone.now()
    existing = eligibility.existing_child(probation, models.BundleKind.GOLDEN)
    if probation.kind != models.BundleKind.PROBATION:
        return DerivationEligibility(False, [blocker(GOLDEN_BLOCKERS, "SOURCE_NOT_PROBATION", kind=probation.kind)], existing)
    integrity = verify_bundle_integrity(probation)
    blockers = []
    if not integrity.ok:
        blockers.append(blocker(GOLDEN_BLOCKERS, "SOURCE_INTEGRITY_FAILED", findings=integrity.codes))
    if evidence is None:
        blockers.append(blocker(GOLDEN_BLOCKERS, "PHASE20_EVIDENCE_REQUIRED"))
        return DerivationEligibility(False, blockers, existing, integrity)
    if not isinstance(evidence, models.ProbationSoakRun):
        blockers.append(blocker(GOLDEN_BLOCKERS, "EVIDENCE_TYPE_UNSUPPORTED"))
        return DerivationEligibility(False, blockers, existing, integrity)
    run = evidence
    if run.bundle_id != probation.pk:
        blockers.append(blocker(GOLDEN_BLOCKERS, "SOAK_BUNDLE_MISMATCH"))
    if run.bundle_digest != probation.bundle_digest:
        blockers.append(blocker(GOLDEN_BLOCKERS, "PROBATION_DIGEST_CHANGED"))
    if not run.is_technical_pass:
        blockers.append(blocker(GOLDEN_BLOCKERS, "SOAK_NOT_PASSED", state=run.state, result=run.result or "NONE"))
    else:
        if run.finished_at is None or run.finished_at < run.required_end_at:
            blockers.append(blocker(GOLDEN_BLOCKERS, "SOAK_DURATION_NOT_MET"))
        problems = [p for p in soak_evaluator.verify_run(run) if p != "DURATION_NOT_ELAPSED"]
        if problems:
            blockers.append(blocker(GOLDEN_BLOCKERS, "SOAK_EVIDENCE_INVALID", problems=problems))
        if run.finished_at is not None and (now - run.finished_at).total_seconds() > int((run.policy or {}).get("decision_max_age_seconds", 0)):
            blockers.append(blocker(GOLDEN_BLOCKERS, "SOAK_EVIDENCE_EXPIRED"))
    decision = models.GoldenDecision.objects.filter(run=run).first()
    if decision is not None and not (decision.decision == models.GoldenDecisionKind.APPROVE and existing is not None):
        blockers.append(blocker(GOLDEN_BLOCKERS, "DECISION_ALREADY_RECORDED", decision=decision.decision))
    later = soak_interference.find_interference(probation)
    if later:
        blockers.append(blocker(GOLDEN_BLOCKERS, "INTERFERENCE_DETECTED", executions=[{k: r[k] for k in ("run_id", "change_id", "outcome", "devices")} for r in later]))
    return DerivationEligibility(not blockers and existing is None, blockers, existing, integrity)


def can_create_golden_from(probation, evidence=None) -> bool:
    return check_golden_eligibility(probation, evidence).eligible


def create_golden_bundle(probation, *, evidence=None, actor: str = "", reason: str = "", now=None) -> BundleResult:
    """Seal the exact Probation payload into a NEW Golden bundle.  Idempotent per Probation bundle; refuses (writing nothing) unless every
    check above holds inside the transaction."""
    now = now or timezone.now()

    def find():
        return eligibility.existing_child(probation, models.BundleKind.GOLDEN)

    existing = find()
    if existing is not None:
        return BundleResult(existing)
    try:
        with transaction.atomic():
            locked_probation = models.ConfigurationBundle.objects.select_for_update().get(pk=probation.pk)
            run = models.ProbationSoakRun.objects.select_for_update().get(pk=evidence.pk) if isinstance(evidence, models.ProbationSoakRun) else evidence
            check = check_golden_eligibility(locked_probation, run, now=now)
            if check.existing is not None:
                return BundleResult(check.existing)
            if check.blockers:
                if check.integrity is not None and not check.integrity.ok:
                    persistence.record_integrity_failure(locked_probation, check.integrity, actor=actor, context="golden promotion refused")
                return BundleResult(None, blockers=check.blockers, refused=True)
            rows = list(locked_probation.items.select_related("configlet", "raw_revision", "raw_verification", "execution_result").order_by("sequence"))
            specs = [{"record": copy.deepcopy(r.record), "configlet": r.configlet, "raw_revision": r.raw_revision, "raw_verification": r.raw_verification,
                      "execution_result": r.execution_result} for r in rows]
            refs = dict(change=locked_probation.change, plan=locked_probation.plan, validation_run=locked_probation.validation_run,
                        execution_run=locked_probation.execution_run, postcheck_run=locked_probation.postcheck_run)
            promotion = {
                "soak_id": run.soak_id, "soak_policy_version": run.policy_version, "soak_duration_seconds": run.duration_seconds,
                "observation_started_at": soak_evaluator.iso(run.started_at), "observation_required_end_at": soak_evaluator.iso(run.required_end_at),
                "observation_completed_at": soak_evaluator.iso(run.finished_at), "evidence_digest": run.evidence_digest,
                "probation_bundle_digest": locked_probation.bundle_digest, "decision": models.GoldenDecisionKind.APPROVE, "decided_by": actor,
                "decided_at": soak_evaluator.iso(now),
            }
            bundle = persistence.seal_bundle(
                kind=models.BundleKind.GOLDEN, payload=copy.deepcopy(locked_probation.manifest["payload"]),   # SEAL the same payload: never an edit
                lineage={"parent_bundle_digest": locked_probation.bundle_digest, "source_uat_bundle_digest": locked_probation.source_uat.bundle_digest,
                         "promotion": promotion},
                refs=refs, item_specs=specs, actor=actor, parent=locked_probation, source_uat=locked_probation.source_uat, find_existing=find,
                builder_version=GOLDEN_BUILDER_VERSION,
                audit_extra={"result": "APPROVED", "soak_id": run.soak_id, "evidence_digest": run.evidence_digest, "decided_at": soak_evaluator.iso(now),
                             "reason_chars": len(reason or "")},
            )
            models.GoldenDecision.objects.create(
                run=run, bundle=locked_probation, decision=models.GoldenDecisionKind.APPROVE, decided_by=actor, decided_at=now,
                reason=(reason or "")[:MAX_REASON_CHARS], probation_bundle_digest=locked_probation.bundle_digest, evidence_digest=run.evidence_digest,
                policy_version=run.policy_version, golden_bundle=bundle,
            )
    except persistence._AlreadyExists as duplicate:   # a concurrent approval created the SAME artifact first: that one wins
        return BundleResult(duplicate.bundle)
    return BundleResult(bundle, created=True)


__all__ = ["GOLDEN_BLOCKERS", "can_create_golden_from", "check_golden_eligibility", "create_golden_bundle"]
