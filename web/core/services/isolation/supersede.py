"""Close a stale isolation / admission transition Change as SUPERSEDED -- records only, never a device.

An isolation-apply or isolation-release Change (``transaction.create_change``) leaves its pending lifecycle state only from
inside ``transaction.execute``.  Two governed paths finish the work without that call, and the Change then stays
READY_TO_DEPLOY forever, counted as pending by every quiescence check:

* the execution lease expired (``locking.reap_expired`` finalises the run INTERRUPTED and never touches the lifecycle) and
  ``isolation.reconcile`` later proved the policy's state from the upstream;
* the release run was BLOCKED and the admission finished RESTORED / FAILED / CANCELLED; a later admission releases the
  policy through its own Change.

``assess`` proves from the records alone that the Change can never run again and that its owner finished through another
path, and names the evidence (owner state, successor Change, every execution run).  ``supersede`` re-checks that under a
row lock and appends one SUPERSEDED lifecycle event (``lifecycle_service``: event + audit row, append-only), carrying that
evidence.  Nothing is deleted, nothing is executed, no plan or Configlet is touched.  Owners still open are refused: their
own workflow closes them (``isolation.cancel``, ``admission.cancel``, ``reconcile``).
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field

from django.db import transaction

from ... import models
from .. import lifecycle_service
from . import transaction as iso_transaction

SCHEMA = "nmas.transition-supersede/1"
APPLY_KIND, RELEASE_KIND = "TRUSTED_ISOLATION_APPLY", "TRUSTED_ISOLATION_RELEASE"
PENDING = frozenset({models.ChangeLifecycleState.DRAFT, models.ChangeLifecycleState.VALIDATED,
                     models.ChangeLifecycleState.CI_PENDING, models.ChangeLifecycleState.READY_TO_DEPLOY})
#: an apply Change is dead once its policy was proven to hold (or to have held and been released) on the upstream
APPLY_SETTLED = frozenset({models.IsolationState.ENFORCED, models.IsolationState.VERIFIED, models.IsolationState.RELEASED})
#: a release Change is dead once its admission finished without it being executed successfully
RELEASE_SETTLED = frozenset({models.AdmissionState.RESTORED, models.AdmissionState.FAILED, models.AdmissionState.CANCELLED})

CODES = {
    "SUPERSEDE_NOT_TRANSITION": ("The Change is not an isolation apply / release transition.", "Close it through its own workflow."),
    "SUPERSEDE_NOT_PENDING": ("The Change is not pending (it already reached a lifecycle outcome).", "Nothing to close."),
    "SUPERSEDE_REASON_REQUIRED": ("No reason was given.", "State why the Change is superseded."),
    "SUPERSEDE_ACTOR_REQUIRED": ("No actor was given.", "Name the operator or service recording the closure."),
    "SUPERSEDE_EXECUTION_IN_FLIGHT": ("An execution run of the Change is RUNNING or still holds a device lock.",
                                      "Wait for it to finish or for the lease reaper."),
    "SUPERSEDE_CHANGE_EXECUTED": ("An execution run of the Change SUCCEEDED; its lifecycle is inconsistent, not stale.",
                                  "Investigate the run; never supersede executed work."),
    "SUPERSEDE_OWNER_MISSING": ("No isolation policy / admission references the Change.", "Investigate the record."),
    "SUPERSEDE_OWNER_OPEN": ("The owning policy / admission has not finished.",
                             "Finish it through its own workflow (cancel / reconcile / execute) first."),
    "SUPERSEDE_SUCCESSOR_NOT_DEPLOYED": ("The policy was released by another Change that is not DEPLOYED.",
                                         "Resolve the successor first."),
    "SUPERSEDE_STATE_CHANGED": ("The Change changed while it was being closed.", "Re-assess."),
}


def _blocker(code: str, **details) -> dict:
    message, remediation = CODES[code]
    return {"code": code, "message": message, "remediation": remediation, **details}


@dataclass
class Assessment:
    change: object
    blockers: list = field(default_factory=list)
    evidence: dict = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return not self.blockers


def _runs(change) -> list[dict]:
    return [{"run_id": str(run.run_id), "state": run.state, "outcome": run.outcome,
             "started_at": run.started_at.isoformat() if run.started_at else "",
             "finished_at": run.finished_at.isoformat() if run.finished_at else "",
             "locks": run.device_locks.count()}
            for run in change.execution_runs.order_by("started_at", "id")]


def _owner(change, kind: str) -> tuple[dict, list[dict]]:
    if kind == APPLY_KIND:
        policy = models.IsolationPolicy.objects.filter(apply_change=change).first()
        if policy is None:
            return {}, [_blocker("SUPERSEDE_OWNER_MISSING", kind=kind)]
        owner = {"type": "IsolationPolicy", "id": policy.policy_id, "state": policy.state,
                 "enforced_at": policy.enforced_at.isoformat() if policy.enforced_at else ""}
        if policy.state not in APPLY_SETTLED or policy.enforced_at is None:
            return owner, [_blocker("SUPERSEDE_OWNER_OPEN", owner=policy.policy_id, state=policy.state)]
        successor = policy.release_change if policy.state == models.IsolationState.RELEASED else None
    else:
        admission = models.ProductionAdmission.objects.filter(release_change=change).first()
        if admission is None:
            return {}, [_blocker("SUPERSEDE_OWNER_MISSING", kind=kind)]
        policy = models.IsolationPolicy.objects.get(pk=admission.isolation_policy_id)
        owner = {"type": "ProductionAdmission", "id": admission.admission_id, "state": admission.state,
                 "finished_at": admission.finished_at.isoformat() if admission.finished_at else "",
                 "policy": policy.policy_id, "policy_state": policy.state}
        if admission.state not in RELEASE_SETTLED:
            return owner, [_blocker("SUPERSEDE_OWNER_OPEN", owner=admission.admission_id, state=admission.state)]
        successor = policy.release_change if policy.release_change_id not in (None, change.pk) else None
    if successor is not None:
        owner["successor"] = {"change": successor.change_id, "state": successor.lifecycle_state}
        if successor.lifecycle_state != models.ChangeLifecycleState.DEPLOYED:
            return owner, [_blocker("SUPERSEDE_SUCCESSOR_NOT_DEPLOYED", successor=successor.change_id,
                                   state=successor.lifecycle_state)]
    return owner, []


def assess(change, *, actor: str = "", reason: str = "") -> Assessment:
    """Read-only: may ``change`` be closed as SUPERSEDED, and on what evidence."""
    kind = iso_transaction.kind_of(change)
    found: list[dict] = []
    if kind not in (APPLY_KIND, RELEASE_KIND):
        return Assessment(change, [_blocker("SUPERSEDE_NOT_TRANSITION", kind=kind)])
    if change.lifecycle_state not in PENDING:
        found.append(_blocker("SUPERSEDE_NOT_PENDING", state=change.lifecycle_state))
    if not str(reason or "").strip():
        found.append(_blocker("SUPERSEDE_REASON_REQUIRED"))
    if not str(actor or "").strip():
        found.append(_blocker("SUPERSEDE_ACTOR_REQUIRED"))
    runs = _runs(change)
    if any(run["state"] == models.ExecutionRunState.RUNNING or run["locks"] for run in runs):
        found.append(_blocker("SUPERSEDE_EXECUTION_IN_FLIGHT"))
    if any(run["outcome"] == "SUCCEEDED" for run in runs):
        found.append(_blocker("SUPERSEDE_CHANGE_EXECUTED"))
    owner, owner_blockers = _owner(change, kind)
    found.extend(owner_blockers)
    evidence = {"schema": SCHEMA, "change": change.change_id, "kind": kind, "from_state": change.lifecycle_state,
                "owner": owner, "runs": runs}
    evidence["digest"] = hashlib.sha256(json.dumps(evidence, sort_keys=True, default=str).encode()).hexdigest()
    return Assessment(change, found, evidence)


def supersede(change, *, actor: str, reason: str) -> Assessment:
    """Close ``change`` as SUPERSEDED when ``assess`` proves it stale; refused (no write) otherwise."""
    first = assess(change, actor=actor, reason=reason)
    if not first.ok:
        return first
    with transaction.atomic():
        locked = models.Change.objects.select_for_update().get(pk=change.pk)
        again = assess(locked, actor=actor, reason=reason)
        if not again.ok or again.evidence["digest"] != first.evidence["digest"]:
            return Assessment(change, again.blockers or [_blocker("SUPERSEDE_STATE_CHANGED")], again.evidence)
        lifecycle_service.record_lifecycle_event(change=locked, to_state=models.ChangeLifecycleState.SUPERSEDED,
                                                 reason=str(reason).strip()[:500], actor=str(actor).strip()[:150],
                                                 metadata={"supersede": again.evidence})
    change.refresh_from_db()
    return Assessment(change, [], again.evidence)
