"""Lifecycle evidence: one append-only, hash-chained ``DeviceLifecycleEvent`` per attempted action, plus the domain ``AuditEvent``.

Refusals are evidence too.  A refusal that concerns no existing device record (an unknown name, an out-of-scope adoption) has
no device chain to join, so it is written as an ``AuditEvent`` only.  Everything recorded is bounded and passes through
``secret_policy.redact`` -- no credential, key or token can be stored even by mistake.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
import uuid

from django.conf import settings

from ... import models
from .. import secret_policy

Outcome = models.DeviceLifecycleEventOutcome
HUMAN, AUTOMATION = "HUMAN", "AUTOMATION"
_EVENT_AUDIT = {
    "REGISTER": models.AuditEventType.DEVICE_REGISTERED,
    "ADOPT": models.AuditEventType.DEVICE_ADOPTED,
    "BOOTSTRAP_AUTH_REQUEST": models.AuditEventType.BOOTSTRAP_AUTH_REQUESTED,
    "BOOTSTRAP_AUTH_APPROVE": models.AuditEventType.BOOTSTRAP_AUTH_APPROVED,
    "BOOTSTRAP_AUTH_REVOKE": models.AuditEventType.BOOTSTRAP_AUTH_REVOKED,
    "BOOTSTRAP_AUTH_EXPIRE": models.AuditEventType.BOOTSTRAP_AUTH_REVOKED,
    "BOOTSTRAP_AUTH_DECIDE": models.AuditEventType.BOOTSTRAP_AUTH_DECIDED,
    "BOOTSTRAP_AUTH_CONSUME": models.AuditEventType.BOOTSTRAP_AUTH_DECIDED,
    # V2 Phase 3 -- native ZTP
    "ZTP_SESSION_OPEN": models.AuditEventType.ZTP_SESSION_CHANGED,
    "ZTP_SESSION_CANCEL": models.AuditEventType.ZTP_SESSION_CHANGED,
    "ZTP_FAILURE": models.AuditEventType.ZTP_SESSION_CHANGED,
    "ZTP_HOST_KEY_ENROLL": models.AuditEventType.ZTP_SESSION_CHANGED,
    "ZTP_MANAGEMENT_CONTACT": models.AuditEventType.ZTP_SESSION_CHANGED,
    "ZTP_STATE": models.AuditEventType.ZTP_SESSION_CHANGED,
    "ZTP_DISCOVERY": models.AuditEventType.ZTP_DISCOVERY_OBSERVED,
    "ZTP_ARTIFACT_DELIVERED": models.AuditEventType.ZTP_ARTIFACT_DELIVERY,
    "ZTP_ARTIFACT_DELIVERY": models.AuditEventType.ZTP_ARTIFACT_DELIVERY,
    "ZTP_MANAGEMENT_VERIFY": models.AuditEventType.ZTP_MANAGEMENT_VERIFIED,
    "BOOTSTRAP": models.AuditEventType.DEVICE_BOOTSTRAPPED,
    "ZTP_DHCP_POLICY": models.AuditEventType.DHCP_POLICY_APPLIED,
    "DHCP_POLICY_VALIDATED": models.AuditEventType.DHCP_POLICY_APPLIED,
    "DHCP_POLICY_APPLIED": models.AuditEventType.DHCP_POLICY_APPLIED,
    "DHCP_POLICY_ROLLED_BACK": models.AuditEventType.DHCP_POLICY_APPLIED,
    "DHCP_POLICY_FAILED": models.AuditEventType.DHCP_POLICY_APPLIED,
    "BOOTSTRAP_NETWORK_CREATE": models.AuditEventType.DHCP_POLICY_APPLIED,
    # V2 Phase 4 -- management paths, failover, bootstrap credential retirement
    **{action: models.AuditEventType.MANAGEMENT_PATH_CHANGED for action in (
        "MGMT_PATH_REGISTER", "MGMT_PATH_APPROVE", "MGMT_PATH_REVOKE", "MGMT_PATH_PROBE", "MGMT_RECONCILED")},
    **{f"MGMT_{kind}": models.AuditEventType.MANAGEMENT_PATH_SWITCHED for kind in models.ManagementTransitionKind.values},
    **{action: models.AuditEventType.BOOTSTRAP_CREDENTIAL_CHANGED for action in (
        "BCRED_PLAN", "BCRED_APPROVE", "BCRED_CANCEL", "BCRED_STEP", "BCRED_COMPLETE", "BCRED_FAILED")},
    # V2 Phases 5-6 -- trusted isolation, commissioning, production admission, lifecycle outbox
    **{action: models.AuditEventType.ISOLATION_CHANGED for action in (
        "ISO_REQUIRE", "ISO_PLAN", "ISO_PRECHECK", "ISO_APPROVE", "ISO_APPLY", "ISO_VERIFY", "ISO_DRIFT", "ISO_RECONCILE", "ISO_CANCEL",
        "ISO_RELEASE_PLAN", "ISO_RELEASE_PRECHECK", "ISO_RELEASE_APPROVE", "ISO_RELEASE", "ISOLATE")},
    **{action: models.AuditEventType.COMMISSIONING_CHANGED for action in (
        "COM_DEPENDENCY_ADD", "COM_DEPENDENCY_REMOVE", "COM_OPEN", "COM_READINESS", "COM_APPROVE", "COM_CONFIGURE", "COM_ABORT",
        "COM_RECONCILE", "COMMISSION_READY", "COMMISSION", "COMMISSION_READY_WITHDRAW", "COMMISSION_ABORT")},
    **{action: models.AuditEventType.PRODUCTION_ADMISSION_CHANGED for action in (
        "ADM_PLAN", "ADM_PRECHECK", "ADM_APPROVE", "ADM_EXECUTE", "ADM_CANCEL", "ADM_RECONCILE", "COMMISSION_COMPLETE")},
    **{action: models.AuditEventType.LIFECYCLE_OUTBOX_RECORDED for action in ("OUTBOX_RECORD", "OUTBOX_DELIVER")},
}


def repository_head() -> str:
    try:
        done = subprocess.run(["git", "-C", str(settings.REPO_ROOT), "rev-parse", "HEAD"], capture_output=True, text=True, timeout=5,
                              shell=False, check=False)  # noqa: S603,S607 - fixed argv list
    except (OSError, subprocess.SubprocessError):
        return ""
    head = done.stdout.strip()
    return head if done.returncode == 0 and len(head) == 40 else ""


def new_correlation_id() -> str:
    return str(uuid.uuid4())


def _digest(payload: dict) -> str:
    return hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode()).hexdigest()


def record(device, action: str, outcome: str, *, actor: str, actor_kind: str = HUMAN, from_state: str = "", to_state: str = "",
           authorization: dict | None = None, blockers=(), evidence: dict | None = None, correlation_id: str = "",
           bootstrap_authorization=None, attachment=None, observation=None, head: str | None = None) -> models.DeviceLifecycleEvent:
    """Append one event to ``device``'s chain (call inside the caller's transaction) and mirror it as an AuditEvent."""
    if actor_kind not in (HUMAN, AUTOMATION):
        raise ValueError("actor_kind must be HUMAN or AUTOMATION.")
    previous = models.DeviceLifecycleEvent.objects.filter(device=device).order_by("-sequence").first()
    sequence = (previous.sequence + 1) if previous else 1
    correlation = correlation_id or new_correlation_id()
    head = repository_head() if head is None else head
    body = {
        "device": device.device_id, "name": device.name, "sequence": sequence, "action": action, "outcome": outcome,
        "from_state": from_state, "to_state": to_state, "actor": actor[:150], "actor_kind": actor_kind,
        "authorization": secret_policy.redact(authorization or {}), "blockers": secret_policy.redact(list(blockers)),
        "evidence": secret_policy.redact(evidence or {}), "correlation_id": correlation, "repository_head": head,
        "bootstrap_authorization": bootstrap_authorization.auth_id if bootstrap_authorization else "",
        "attachment": attachment.pk if attachment else None, "observation": observation.pk if observation else None,
    }
    previous_digest = previous.entry_digest if previous else ""
    event = models.DeviceLifecycleEvent.objects.create(
        device=device, sequence=sequence, action=action[:40], outcome=outcome, from_state=from_state, to_state=to_state,
        actor=actor[:150], actor_kind=actor_kind, authorization=body["authorization"], blockers=body["blockers"],
        evidence=body["evidence"], bootstrap_authorization=bootstrap_authorization, attachment=attachment, observation=observation,
        correlation_id=correlation, repository_head=head, previous_digest=previous_digest,
        entry_digest=_digest({"previous": previous_digest, "body": body}),
    )
    audit(action, outcome, actor=actor, object_id=device.device_id, summary=f"{device.device_id} {device.name}: {action} {outcome}",
          metadata={"device": device.device_id, "name": device.name, "from": from_state, "to": to_state,
                    "codes": [b.get("code") for b in body["blockers"]], "correlation_id": correlation, "sequence": sequence})
    emit_fact(device, action, outcome, actor=actor, to_state=to_state, evidence=body["evidence"])
    return event


def emit_fact(device, action: str, outcome: str, *, actor: str, to_state: str = "", evidence: dict | None = None) -> list:
    """V2 Phase 8: the infrastructure fact hook.  An ADVANCED / RECORDED lifecycle action that maps to a fact (DISCOVER,
    VERIFY_IDENTITY, BOOTSTRAP, ISOLATE, COMMISSION*, attachment approval / verification, management-path switches) writes its
    outbox fact in the same transaction.  OUTBOX_* never emits (no recursion); DECOMMISSION* / RESTORE* are recorded
    explicitly by Phase 7 (no double emission).  -> the fact events written ([] = none)."""
    from ..commissioning import outbox          # late import: outbox imports this module

    return outbox.emit_for_event(device, action, outcome, actor=actor, to_state=to_state, evidence=evidence)


def audit(action: str, outcome: str, *, actor: str, object_id: str, summary: str, metadata: dict | None = None) -> models.AuditEvent:
    """The domain audit row (also used alone for refusals that concern no device record)."""
    event_type = models.AuditEventType.DEVICE_LIFECYCLE_REFUSED if outcome == Outcome.REFUSED else _EVENT_AUDIT.get(
        action, models.AuditEventType.DEVICE_LIFECYCLE_CHANGED)
    return models.AuditEvent.objects.create(
        event_type=event_type, object_type="ManagedDevice", object_id=object_id[:64], actor=actor[:150], summary=summary[:255],
        outcome=outcome.lower()[:16], metadata=secret_policy.redact({"action": action, **(metadata or {})}),
    )


def verify_chain(device) -> bool:
    """Recompute every entry digest of ``device``'s chain from its stored body: False when any entry was altered or removed."""
    previous_digest = ""
    for expected_sequence, event in enumerate(models.DeviceLifecycleEvent.objects.filter(device=device).order_by("sequence"), start=1):
        body = {
            "device": device.device_id, "name": device.name, "sequence": event.sequence, "action": event.action, "outcome": event.outcome,
            "from_state": event.from_state, "to_state": event.to_state, "actor": event.actor, "actor_kind": event.actor_kind,
            "authorization": event.authorization, "blockers": event.blockers, "evidence": event.evidence,
            "correlation_id": event.correlation_id, "repository_head": event.repository_head,
            "bootstrap_authorization": event.bootstrap_authorization.auth_id if event.bootstrap_authorization_id else "",
            "attachment": event.attachment_id, "observation": event.observation_id,
        }
        if event.sequence != expected_sequence or event.previous_digest != previous_digest \
                or event.entry_digest != _digest({"previous": previous_digest, "body": body}):
            return False
        previous_digest = event.entry_digest
    return True
