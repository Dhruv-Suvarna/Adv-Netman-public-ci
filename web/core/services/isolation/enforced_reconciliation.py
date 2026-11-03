"""RECONCILED_AS_ENFORCED: resolve ONE interrupted trusted-isolation APPLY run whose policy is proven enforced on the upstream now.

An APPLY run that lost its lease (``INTERRUPTED``) stays unresolved forever: ``isolation.reconcile`` later proves the policy
ENFORCED, but the finished run is immutable, so ``transaction.unresolved_runs`` keeps reporting PRIOR_TRANSITION_UNRESOLVED and no
later isolation transaction on that upstream (the admission release included) can run.  The existing BASELINE mark does not fit:
the device was not returned to the state the run started from, it reached the state the run was meant to produce.

``reconcile_interrupted_apply`` records that second fact, append-only, and only when ALL of these hold at that moment:
    * the run is the FINISHED / INTERRUPTED run of the policy's own TRUSTED_ISOLATION_APPLY Change (transition metadata, the
      policy's ``apply_change`` and the run all name the same policy and device);
    * the run's plan hash is the policy's plan hash and the hash the human approved;
    * the device identity is verified and the verified serial / base MAC are the expected ones;
    * the policy is ENFORCED / VERIFIED (never DRIFTED, UNCERTAIN, RELEASED ...);
    * a FRESH, authenticated read-back verification run by this call, with the device attached and with traffic probes, passed
      every isolation check: READ_BACK, L2, ROUTING (no adjacency and no route learned through the isolated port -- this is the
      RIP control-plane condition), MANAGEMENT_PLANE, ATTACHMENT and TRAFFIC, newer than the enforcement and within the evidence
      maximum age.
The mark binds the policy, the run, the Change, the device identity, the plan hash, the intent hash and the observed digest.  The
run itself (outcome, report, results) is never rewritten.  ``is_reconciled_as_enforced`` honours a mark only while its binding
still matches and the policy is not DRIFTED / UNCERTAIN; every other unresolved run keeps blocking exactly as before.
"""

from __future__ import annotations

from datetime import datetime, timedelta

from django.db import transaction as db_transaction
from django.utils import timezone

from ... import models
from ..execution.codes import Outcome

MARK = "RECONCILED_AS_ENFORCED"
ACTION = "ISO_RECONCILE_ENFORCED"
APPLY_KIND = "TRUSTED_ISOLATION_APPLY"
REQUIRED_CHECKS = ("READ_BACK", "L2", "ROUTING", "MANAGEMENT_PLANE", "ATTACHMENT", "TRAFFIC")
DRIFT_CHECKS = ("READ_BACK", "L2", "MANAGEMENT_PLANE")
ENFORCED_STATES = ("ENFORCED", "VERIFIED")
BROKEN_STATES = ("DRIFTED", "UNCERTAIN")


def _problem(code: str, **details) -> dict:
    return {"code": code, "details": details}


def _transition(change) -> dict:
    return ((getattr(change, "metadata", None) or {}).get("transition") or {})


def binding(policy, run, device) -> dict:
    """Everything the mark is bound to (no secret, no free text)."""
    return {"policy": policy.policy_id, "run_id": str(run.run_id), "change": run.change.change_id, "device": device.device_id,
            "serial": device.verified_serial, "base_mac": str(device.verified_base_mac or "").lower(), "plan_hash": run.plan_hash,
            "intent_hash": policy.intent_hash}


def problems(*, policy, run, device, approved_plan_hash: str, verification: dict | None, now: datetime,
             max_age_seconds: float) -> list[dict]:
    """Pure gate: [] when the run may be recorded RECONCILED_AS_ENFORCED; otherwise every reason it may not."""
    found: list[dict] = []
    change = run.change
    meta = _transition(change)
    if run.state != models.ExecutionRunState.FINISHED or run.outcome != Outcome.INTERRUPTED:
        found.append(_problem("RECONCILE_RUN_NOT_INTERRUPTED", state=run.state, outcome=run.outcome))
    if meta.get("kind") != APPLY_KIND or meta.get("policy") != policy.policy_id or policy.apply_change_id != change.pk:
        found.append(_problem("RECONCILE_WRONG_POLICY", change=change.change_id, policy=policy.policy_id))
    if policy.device_id != device.pk or meta.get("device") != device.device_id:
        found.append(_problem("RECONCILE_IDENTITY_MISMATCH", reason="the run, the policy and the device disagree"))
    identity_ok = (device.identity_state == models.IdentityVerificationState.VERIFIED and bool(device.verified_serial)
                   and device.verified_serial == device.expected_serial
                   and str(device.verified_base_mac or "").lower() == str(device.expected_base_mac or "").lower())
    if not identity_ok:
        found.append(_problem("RECONCILE_IDENTITY_MISMATCH", reason="device identity is not the verified expected identity"))
    if not run.plan_hash or not (run.plan_hash == policy.plan_hash == approved_plan_hash):
        found.append(_problem("RECONCILE_PLAN_HASH_MISMATCH"))
    if policy.state not in ENFORCED_STATES:
        found.append(_problem("RECONCILE_POLICY_NOT_ENFORCED", state=policy.state))
    checks = (verification or {}).get("checks") or {}
    missing = [kind for kind in REQUIRED_CHECKS if kind not in checks]
    if not verification or not verification.get("with_device") or missing:
        found.append(_problem("RECONCILE_EVIDENCE_INSUFFICIENT", missing=missing, with_device=bool((verification or {}).get("with_device"))))
    drifted = [kind for kind in DRIFT_CHECKS if kind in checks and not checks[kind].get("ok")]
    if drifted:
        found.append(_problem("RECONCILE_DRIFT", checks=drifted))
    failed = [kind for kind in REQUIRED_CHECKS if kind in checks and not checks[kind].get("ok") and kind not in drifted]
    if failed:
        found.append(_problem("ISOLATION_LEAK" if "ROUTING" in failed or "TRAFFIC" in failed else "ISOLATION_NOT_VERIFIED", checks=failed))
    at = _parse((verification or {}).get("at"))
    floor = max(filter(None, (policy.enforced_at, now - timedelta(seconds=max_age_seconds))))
    if verification and (at is None or at < floor or at > now + timedelta(seconds=5)):
        found.append(_problem("RECONCILE_EVIDENCE_STALE", at=(verification or {}).get("at")))
    return found


def _parse(value):
    if isinstance(value, datetime):
        return value
    try:
        return datetime.fromisoformat(str(value))
    except (TypeError, ValueError):
        return None


def _marks(run):
    return models.AuditEvent.objects.filter(object_type="ChangeExecutionRun", object_id=str(run.run_id), metadata__reconciliation=MARK)


def is_reconciled_as_enforced(run) -> bool:
    """A recorded mark whose binding still matches the live rows, while the policy is not DRIFTED / UNCERTAIN."""
    if run.outcome != Outcome.INTERRUPTED:
        return False
    for event in _marks(run).order_by("-created_at"):
        meta = event.metadata or {}
        policy = models.IsolationPolicy.objects.filter(apply_change_id=run.change_id).select_related("device").first()
        if policy is None or policy.state in BROKEN_STATES:
            return False
        bound = binding(policy, run, policy.device)
        if all(meta.get(key) == value for key, value in bound.items()):
            return True
    return False


def interrupted_apply_run(policy):
    """The single FINISHED / INTERRUPTED run of the policy's own apply Change, or None."""
    if policy.apply_change_id is None:
        return None
    runs = list(policy.apply_change.execution_runs.filter(state=models.ExecutionRunState.FINISHED, outcome=Outcome.INTERRUPTED))
    return runs[0] if len(runs) == 1 else None


def reconcile_interrupted_apply(policy, *, actor: str, traffic, access=None, now=None):
    """Fresh verification (device attached, traffic probes), then the gate, then ONE append-only mark.  -> IsolationResult."""
    from . import service, transaction  # noqa: PLC0415 - service imports transaction, which imports this module

    run = interrupted_apply_run(policy)
    device = policy.device
    if run is None:
        return service._refuse(device, ACTION, [service.blocker("RECONCILE_RUN_NOT_INTERRUPTED")], actor=actor, policy=policy)
    if is_reconciled_as_enforced(run):
        return service.IsolationResult(True, ACTION, policy, [], {"run_id": str(run.run_id), "already": True})
    verified = service.verify(policy, actor=actor, access=access, traffic=traffic, with_device=True)
    policy.refresh_from_db()
    device.refresh_from_db()
    now = now or timezone.now()
    approved = transaction.approval(run.change).get("plan_hash", "")
    found = problems(policy=policy, run=run, device=device, approved_plan_hash=approved, verification=verified.detail,
                     now=now, max_age_seconds=service.evidence_max_age_seconds())
    if found:
        return service._refuse(device, ACTION, [service.blocker(p["code"], **p["details"]) for p in found], actor=actor, policy=policy)
    bound = binding(policy, run, device)
    summary = verified.detail
    with db_transaction.atomic():
        models.AuditEvent.objects.create(
            event_type=models.AuditEventType.DEPLOYMENT_RECORDED, change=run.change, object_type="ChangeExecutionRun",
            object_id=str(run.run_id), actor=actor[:150],
            summary=f"{run.change.change_id}: interrupted run {str(run.run_id)[:8]} reconciled as enforced ({policy.policy_id})"[:255],
            metadata={"reconciliation": MARK, **bound, "outcome": run.outcome, "verification": {
                "at": summary.get("at"), "correlation_id": summary.get("correlation_id"), "checks": summary.get("checks")}})
        service._event(device, ACTION, service.Outcome.RECORDED,
                       actor=actor, policy=policy, correlation_id=summary.get("correlation_id", ""),
                       evidence={"run_id": str(run.run_id), "mark": MARK, "plan_hash": run.plan_hash})
    return service.IsolationResult(True, ACTION, policy, [], {"run_id": str(run.run_id), **bound})
