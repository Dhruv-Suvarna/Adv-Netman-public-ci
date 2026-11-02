"""The operator's explicit Golden decision.  The ONLY caller of the Golden creation path.

    decide(run, decision="APPROVE", actor=.., reason=.., confirm={soak_id, bundle_id, bundle_digest})

* A technical PASS never promotes anything by itself.  Golden needs this explicit call, which a view makes only on an operator POST.
* ``confirm`` is what the page SHOWED (the exact soak, Probation bundle and digest).  It is a staleness guard compared with the current
  records, never an authority: the browser cannot supply a manifest, a digest replacement, a timestamp or any evidence.
* APPROVE delegates to ``bundles.golden.create_golden_bundle`` -- which re-checks integrity, interference, the soak's own evidence and the
  decision window inside its transaction -- and never touches a device (promotion is artifact + audit work; the configuration is already
  the applied Probation configuration).  Idempotent: a double click returns the existing Golden bundle.
* REJECT records an immutable decision and creates nothing.  It deletes no bundle or evidence and rolls nothing back (Phase 21).  A decision is
  never edited: reconsidering a rejected soak requires a NEW soak (documented retry semantics).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from django.db import transaction
from django.utils import timezone

from ... import models
from ..bundles import golden
from ..bundles.codes import GOLDEN_BLOCKERS, blocker as golden_blocker
from ..raw_configlets import static_gate
from . import evaluator
from .codes import DECISION_BLOCKERS, MAX_REASON_CHARS, blocker
from .lifecycle import audit_event, note_for, publish

Kind = models.GoldenDecisionKind
Notif = models.Notification


@dataclass
class DecisionResult:
    decision: object | None = None
    bundle: object | None = None
    created: bool = False
    blockers: list = field(default_factory=list)
    refused: bool = False


def _reason_problem(reason: str) -> bool:
    return any(static_gate.secret_patterns(line) for line in reason.splitlines())


def _refuse(blockers) -> DecisionResult:
    return DecisionResult(blockers=list(blockers), refused=True)


def _confirmation_blockers(run, confirm) -> list:
    expected = {"soak_id": run.soak_id, "bundle_id": run.bundle.bundle_id, "bundle_digest": run.bundle_digest}
    given = {k: str((confirm or {}).get(k, "")) for k in expected}
    return [] if given == expected else [blocker(DECISION_BLOCKERS, "CONFIRMATION_MISMATCH")]


def decide(run, *, decision: str, actor: str, reason: str = "", confirm: dict | None = None, now: datetime | None = None) -> DecisionResult:
    """Record the operator's decision on a technically passed soak.  Every server-side rule is re-checked here, whatever the page showed."""
    now = now or timezone.now()
    run = models.ProbationSoakRun.objects.select_related("bundle__change", "bundle__source_uat").get(pk=run.pk)
    if decision not in Kind.values:
        return _refuse([blocker(DECISION_BLOCKERS, "DECISION_INVALID")])
    reason = str(reason or "").strip()[:MAX_REASON_CHARS]
    blockers = _confirmation_blockers(run, confirm)
    if _reason_problem(reason):
        blockers.append(blocker(DECISION_BLOCKERS, "REASON_SECRET_SHAPED"))
    if blockers:
        return _refuse(blockers)
    return _approve(run, actor, reason, now) if decision == Kind.APPROVE else _reject(run, actor, reason, now)


def _approve(run, actor: str, reason: str, now: datetime) -> DecisionResult:
    result = golden.create_golden_bundle(run.bundle, evidence=run, actor=actor, reason=reason, now=now)
    if result.bundle is None:
        return _refuse(result.blockers)
    row = models.GoldenDecision.objects.filter(golden_bundle=result.bundle).select_related("run").first()
    if result.created:
        publish([note_for(
            run, Notif.EventType.GOLDEN_APPROVED, Notif.Severity.SUCCESS, f"Golden approved: {result.bundle.bundle_id}",
            f"The operator approved {run.bundle.bundle_id} as Golden ({result.bundle.bundle_id}) after {run.soak_id}. No device was contacted.",
            "approved", golden_bundle_id=result.bundle.bundle_id)])
    return DecisionResult(row, result.bundle, created=result.created)


def _reject(run, actor: str, reason: str, now: datetime) -> DecisionResult:
    notes: list = []
    with transaction.atomic():
        locked = models.ProbationSoakRun.objects.select_for_update().select_related("bundle__change").get(pk=run.pk)
        existing = models.GoldenDecision.objects.filter(run=locked).first()
        if existing is not None:
            if existing.decision == Kind.REJECT:
                return DecisionResult(existing)       # idempotent: the same explicit decision again
            return _refuse([golden_blocker(GOLDEN_BLOCKERS, "DECISION_ALREADY_RECORDED", decision=existing.decision)])
        if not locked.is_technical_pass:
            return _refuse([golden_blocker(GOLDEN_BLOCKERS, "SOAK_NOT_PASSED", state=locked.state, result=locked.result or "NONE")])
        row = models.GoldenDecision.objects.create(
            run=locked, bundle=locked.bundle, decision=Kind.REJECT, decided_by=actor, decided_at=now, reason=reason,
            probation_bundle_digest=locked.bundle_digest, evidence_digest=locked.evidence_digest, policy_version=locked.policy_version,
        )
        audit_event(models.AuditEventType.GOLDEN_REJECTED, locked, actor=actor, summary=f"Golden REJECTED for {locked.bundle.bundle_id} after {locked.soak_id}",
                    extra={"decision": Kind.REJECT, "decided_at": evaluator.iso(now), "evidence_digest": locked.evidence_digest, "reason_chars": len(reason)})
        notes.append(note_for(locked, Notif.EventType.GOLDEN_REJECTED, Notif.Severity.WARNING, f"Golden rejected: {locked.bundle.bundle_id}",
                              f"The operator rejected Golden promotion of {locked.bundle.bundle_id} after {locked.soak_id}. Nothing was deleted or rolled back.", "rejected"))
    publish(notes)
    return DecisionResult(row, created=True)
