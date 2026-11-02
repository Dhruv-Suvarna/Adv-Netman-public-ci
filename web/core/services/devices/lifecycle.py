"""The managed-device lifecycle: registration, adoption, observations, identity verification and state transitions.

Separate concerns, separate fields (see ``models.ManagedDevice``):

    lifecycle_state     REGISTERED -> DISCOVERED -> BOOTSTRAPPED -> ISOLATED -> READY_FOR_COMMISSIONING -> COMMISSIONING
                        -> IN_SERVICE -> DECOMMISSION_PENDING -> DECOMMISSIONED;  REGISTERED / DISCOVERED / FAILED -> WITHDRAWN
    identity_state      UNVERIFIED -> PENDING_VERIFICATION (discovered) -> VERIFIED | MISMATCH
    admission_state     NOT_ADMITTED | LEGACY_PREEXISTING (adopted) | ADMITTED (later phase) | WITHDRAWN (later phase)
    ztp_state, compliance_state   UNKNOWN until a later phase observes them
    maintenance         ``MaintenanceRecord`` (read, never duplicated here)
    bootstrap authorization       ``BootstrapAuthorization`` (``authorization.py``)

Every edge has an owner phase.  An edge whose evidence producer does not exist yet (isolation, commissioning, decommissioning)
is refused with ``TRANSITION_NOT_AVAILABLE`` -- never simulated.  BOOTSTRAP and FAIL (Phase 3) are available and demand the
ZTP session's own evidence (``_bootstrap_prerequisites`` / ``_failure_prerequisites``).  Every attempt, advanced or refused, is a
hash-chained ``DeviceLifecycleEvent``.  Writes are a version compare-and-swap inside one transaction: a concurrent writer makes
the second attempt refuse with nothing changed, and a failure part-way rolls the whole action back.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field

from django.db import IntegrityError, transaction
from django.db.models import Q
from django.utils import timezone

from ... import models
from . import events, identity, resolver
from .codes import blocker, codes

S = models.DeviceLifecycleState
I = models.IdentityVerificationState  # noqa: E741 - the identity-state vocabulary
A = models.ProductionAdmissionState
Outcome = models.DeviceLifecycleEventOutcome
HUMAN, AUTOMATION = events.HUMAN, events.AUTOMATION
ROLES = ("router", "switch", "edge")


@dataclass(frozen=True)
class Edge:
    action: str
    owner_phase: int
    available: bool          # the evidence producer exists in this codebase
    actors: tuple = (HUMAN,)


EDGES = {
    (S.REGISTERED, S.DISCOVERED): Edge("DISCOVER", 2, True, (HUMAN, AUTOMATION)),
    (S.REGISTERED, S.WITHDRAWN): Edge("WITHDRAW", 2, True),
    (S.DISCOVERED, S.WITHDRAWN): Edge("WITHDRAW", 2, True),
    (S.FAILED, S.WITHDRAWN): Edge("WITHDRAW", 2, True),
    (S.DISCOVERED, S.BOOTSTRAPPED): Edge("BOOTSTRAP", 3, True, (AUTOMATION,)),
    (S.DISCOVERED, S.FAILED): Edge("FAIL", 3, True, (HUMAN, AUTOMATION)),
    (S.BOOTSTRAPPED, S.ISOLATED): Edge("ISOLATE", 5, True, (HUMAN, AUTOMATION)),
    (S.BOOTSTRAPPED, S.FAILED): Edge("FAIL", 3, True, (HUMAN, AUTOMATION)),
    (S.BOOTSTRAPPED, S.DECOMMISSION_PENDING): Edge("DECOMMISSION_REQUEST", 7, True),
    (S.ISOLATED, S.READY_FOR_COMMISSIONING): Edge("COMMISSION_READY", 6, True, (HUMAN, AUTOMATION)),
    (S.ISOLATED, S.DECOMMISSION_PENDING): Edge("DECOMMISSION_REQUEST", 7, True),
    (S.READY_FOR_COMMISSIONING, S.COMMISSIONING): Edge("COMMISSION", 6, True),
    (S.READY_FOR_COMMISSIONING, S.ISOLATED): Edge("COMMISSION_READY_WITHDRAW", 6, True, (HUMAN, AUTOMATION)),
    (S.READY_FOR_COMMISSIONING, S.DECOMMISSION_PENDING): Edge("DECOMMISSION_REQUEST", 7, True),
    (S.COMMISSIONING, S.IN_SERVICE): Edge("COMMISSION_COMPLETE", 6, True, (HUMAN, AUTOMATION)),
    (S.COMMISSIONING, S.ISOLATED): Edge("COMMISSION_ABORT", 6, True, (HUMAN, AUTOMATION)),
    (S.COMMISSIONING, S.FAILED): Edge("FAIL", 6, True, (HUMAN, AUTOMATION)),
    (S.IN_SERVICE, S.DECOMMISSION_PENDING): Edge("DECOMMISSION_REQUEST", 7, True),
    (S.DECOMMISSION_PENDING, S.IN_SERVICE): Edge("DECOMMISSION_CANCEL", 7, True),
    (S.DECOMMISSION_PENDING, S.DECOMMISSIONED): Edge("DECOMMISSION", 7, True),
    (S.FAILED, S.DECOMMISSION_PENDING): Edge("DECOMMISSION_REQUEST", 7, True),
}


@dataclass
class LifecycleResult:
    device: object | None
    ok: bool
    action: str
    blockers: list = field(default_factory=list)
    event: object | None = None
    changed: bool = False

    @property
    def codes(self) -> list[str]:
        return codes(self.blockers)


class _Refused(Exception):
    """Internal: abort the transaction of an action; the refusal is recorded after the rollback."""

    def __init__(self, blockers):
        super().__init__("refused")
        self.blockers = blockers


def allowed_targets(state: str) -> list[dict]:
    """The lifecycle edges out of ``state``, each with its owner phase and whether it is executable in this codebase."""
    return [{"to": to, "action": edge.action, "owner_phase": edge.owner_phase, "available": edge.available}
            for (source, to), edge in EDGES.items() if source == state]


def get_device(device_id: str):
    text = str(device_id or "")
    if not text.startswith("DEV-") or not text[4:].isdigit():
        return None
    return models.ManagedDevice.objects.filter(pk=int(text[4:])).first()


def _write(device, **fields) -> None:
    """Compare-and-swap the lifecycle-owned ``fields`` (inside the caller's transaction); refuse when a concurrent writer won."""
    if not models.ManagedDevice.objects.compare_and_swap(device.pk, device.version, **fields):
        raise _Refused([blocker("CONCURRENT_MODIFICATION")])
    for name, value in fields.items():
        setattr(device, name, value)
    device.version += 1


def _locked(device, expected_version):
    """Re-read ``device`` under a row lock; refuse when it moved past the version the operator acted on, or is terminal."""
    fresh = models.ManagedDevice.objects.select_for_update().get(pk=device.pk)
    if expected_version is not None and int(expected_version) != fresh.version:
        raise _Refused([blocker("CONCURRENT_MODIFICATION", expected=int(expected_version), current=fresh.version)])
    if fresh.is_terminal:
        raise _Refused([blocker("DEVICE_TERMINAL", state=fresh.lifecycle_state)])
    return fresh


def _refused(device, action: str, blockers, *, actor: str, actor_kind: str, correlation_id: str = "", **refs) -> LifecycleResult:
    fresh = models.ManagedDevice.objects.get(pk=device.pk)
    with transaction.atomic():
        event = events.record(fresh, action, Outcome.REFUSED, actor=actor, actor_kind=actor_kind, from_state=fresh.lifecycle_state,
                              blockers=blockers, correlation_id=correlation_id, **refs)
    return LifecycleResult(fresh, False, action, list(blockers), event)


def _refused_without_device(action: str, blockers, *, actor: str, subject: str) -> LifecycleResult:
    events.audit(action, Outcome.REFUSED, actor=actor, object_id=subject[:64], summary=f"{action} {subject} refused",
                 metadata={"subject": subject[:64], "codes": codes(blockers)})
    return LifecycleResult(None, False, action, list(blockers))


def _actor_ok(edge: Edge, actor: str, actor_kind: str) -> bool:
    return bool(str(actor or "").strip()) and actor_kind in edge.actors


# --- the generic, fail-closed transition ----------------------------------------------------------------------------------------
def transition(device, to_state: str, *, actor: str, actor_kind: str = HUMAN, expected_version=None, evidence: dict | None = None,
               correlation_id: str = "") -> LifecycleResult:
    """Move ``device`` to ``to_state`` along a lifecycle edge, or record exactly why not.  Idempotent on the current state."""
    action = f"TRANSITION_{to_state}"
    if to_state not in S.values:
        return _refused(device, action, [blocker("TRANSITION_INVALID", to=str(to_state)[:32])], actor=actor, actor_kind=actor_kind)
    try:
        with transaction.atomic():
            fresh = _locked(device, expected_version)
            if fresh.lifecycle_state == to_state:
                event = events.record(fresh, action, Outcome.UNCHANGED, actor=actor, actor_kind=actor_kind, from_state=to_state,
                                      to_state=to_state, correlation_id=correlation_id)
                return LifecycleResult(fresh, True, action, [], event, changed=False)
            edge = EDGES.get((fresh.lifecycle_state, to_state))
            if edge is None:
                raise _Refused([blocker("TRANSITION_INVALID", **{"from": fresh.lifecycle_state, "to": to_state})])
            if not edge.available:
                raise _Refused([blocker("TRANSITION_NOT_AVAILABLE", action=edge.action, owner_phase=edge.owner_phase)])
            if not _actor_ok(edge, actor, actor_kind):
                raise _Refused([blocker("ACTOR_NOT_AUTHORIZED", action=edge.action, actor_kind=actor_kind)])
            return _apply_edge(fresh, edge, to_state, actor=actor, actor_kind=actor_kind, evidence=evidence or {},
                               correlation_id=correlation_id)
    except _Refused as refusal:
        return _refused(device, f"TRANSITION_{to_state}", refusal.blockers, actor=actor, actor_kind=actor_kind, correlation_id=correlation_id)


def _apply_edge(device, edge: Edge, to_state: str, *, actor, actor_kind, evidence, correlation_id) -> LifecycleResult:
    """The prerequisites and side fields of the edges this phase implements (inside the transaction, row locked)."""
    previous = device.lifecycle_state
    fields = {"lifecycle_state": to_state}
    if edge.action == "DISCOVER":
        observation_id = evidence.get("observation")
        # reference data (lab topology, NetBox) is not an observation of the device: it never discovers anything
        if not models.DeviceObservation.objects.filter(device=device, pk=observation_id).exclude(trust=models.ObservationTrust.REFERENCE).exists():
            raise _Refused([blocker("OBSERVATION_INVALID")])
        if device.identity_state == I.UNVERIFIED:
            fields["identity_state"] = I.PENDING_VERIFICATION
    elif edge.action == "BOOTSTRAP":
        fields.update(_bootstrap_prerequisites(device, evidence))
    elif edge.action == "FAIL":
        _failure_prerequisites(device, evidence)
    elif edge.action == "ISOLATE":
        from ..isolation import service as isolation_service      # Phase 5: the trusted-upstream policy's own evidence

        problems = isolation_service.isolate_problems(device)
        if problems:
            raise _Refused(problems)
        evidence = {**evidence, "isolation_policy": isolation_service.device_policy(device).policy_id}
    elif edge.action in _COMMISSIONING_EDGES:
        fields.update(_commissioning_prerequisites(device, edge.action, evidence))
    elif edge.action in _DECOMMISSION_EDGES:
        fields.update(_decommission_prerequisites(device, edge.action, evidence))
    elif edge.action == "WITHDRAW":
        if device.origin != models.DeviceOrigin.REGISTERED_NEW:
            raise _Refused([blocker("ORIGIN_NOT_ELIGIBLE", origin=device.origin)])
        fields["retired_at"] = timezone.now()
        for auth in device.bootstrap_authorizations.filter(state__in=tuple(models.BOOTSTRAP_AUTHORIZATION_OPEN)):
            auth.state, auth.revoked_by, auth.revoked_at = models.BootstrapAuthorizationState.REVOKED, actor[:150], timezone.now()
            auth.revocation_reason, auth.closed_at = "Device registration withdrawn.", timezone.now()
            auth.save(update_fields=["state", "revoked_by", "revoked_at", "revocation_reason", "closed_at", "updated_at"])
    _write(device, **fields)
    event = events.record(device, edge.action, Outcome.ADVANCED, actor=actor, actor_kind=actor_kind, from_state=previous, to_state=to_state,
                          authorization={"actor_kind": actor_kind, "edge": edge.action, "owner_phase": edge.owner_phase},
                          evidence={k: v for k, v in evidence.items() if k in ("observation", "reason", "ztp_session", "verification_digest",
                                                                                "isolation_policy", "commissioning", "admission",
                                                                                "decommission")},
                          correlation_id=correlation_id)
    return LifecycleResult(device, True, edge.action, [], event, changed=True)


def _bootstrap_prerequisites(device, evidence: dict) -> dict:
    """DISCOVERED -> BOOTSTRAPPED (Phase 3) only on the ZTP session's own evidence: the native bootstrap was delivered and its
    minimal management state verified over an authenticated session whose host key was enrolled out of band, recorded as an
    AUTHENTICATED_SESSION observation of this device.  A DHCP lease or a served file is never enough.  Identity verification
    and production admission stay separate: nothing here changes ``identity_state`` or ``admission_state``."""
    session = models.ZtpSession.objects.filter(device=device, pk=evidence.get("ztp_session")).first() \
        if str(evidence.get("ztp_session", "")).isdigit() else None
    if session is None or session.stage != models.ZtpSessionStage.MANAGEMENT_VERIFIED or not (session.verification or {}).get("ok") \
            or not session.enrolled_host_key or not session.deliveries.filter(outcome="SERVED").exists():
        raise _Refused([blocker("BOOTSTRAP_VERIFICATION_FAILED")])
    if session.authorization.state not in (models.BootstrapAuthorizationState.APPROVED, models.BootstrapAuthorizationState.CONSUMED):
        # an operator's revocation (or a withdrawal) stops the onboarding even after the bytes were delivered
        raise _Refused([blocker("AUTHORIZATION_STATE_INVALID", state=session.authorization.state)])
    observation = models.DeviceObservation.objects.filter(device=device, pk=evidence.get("observation")).first() \
        if str(evidence.get("observation", "")).isdigit() else None
    if observation is None or observation.source != models.ObservationSource.AUTHENTICATED_SESSION \
            or observation.result == models.ObservationResult.MISMATCH \
            or (observation.claims or {}).get("host_key") != session.enrolled_host_key:
        raise _Refused([blocker("IDENTITY_NOT_OBSERVED")])
    if device.admission_state != A.NOT_ADMITTED:
        raise _Refused([blocker("PRODUCTION_ADMISSION_REFUSED")])
    fields = {}
    if (session.verification or {}).get("ztp_disabled") is True:
        fields["ztp_state"] = models.ZtpState.DISABLED_VERIFIED
    return fields


# Phase 6: each commissioning edge is taken only on its own commissioning / admission record's evidence (written in the same
# transaction by ``core.services.commissioning``); a bare transition request can never move a device toward production.
_COMMISSIONING_EDGES = {
    "COMMISSION_READY": ("READY",),
    "COMMISSION": ("APPROVED",),
    "COMMISSION_READY_WITHDRAW": ("OPEN", "ABORTED"),
    "COMMISSION_ABORT": ("ABORTED", "OPEN"),
    "COMMISSION_COMPLETE": ("ADMITTED",),
}


def _record_pk(value, prefix: str):
    text = str(value or "")
    return int(text[len(prefix):]) if text.startswith(prefix) and text[len(prefix):].isdigit() else None


def _commissioning_prerequisites(device, action: str, evidence: dict) -> dict:
    record = models.CommissioningRecord.objects.filter(device=device, pk=_record_pk(evidence.get("commissioning"), "COM-")).first()
    if record is None or record.state not in _COMMISSIONING_EDGES[action]:
        raise _Refused([blocker("COMMISSIONING_STATE_INVALID", action=action, state=getattr(record, "state", ""))])
    if device.admission_state != A.NOT_ADMITTED:
        raise _Refused([blocker("PRODUCTION_ADMISSION_REFUSED")])
    if action == "COMMISSION" and not record.approved_by:
        raise _Refused([blocker("COMMISSIONING_STATE_INVALID", action=action, detail="no approver")])
    if action != "COMMISSION_COMPLETE":
        return {}
    admission = models.ProductionAdmission.objects.filter(device=device, commissioning=record, state=models.AdmissionState.ADMITTED,
                                                          pk=_record_pk(evidence.get("admission"), "ADM-")).first()
    if admission is None or admission.isolation_policy.state != models.IsolationState.RELEASED:
        raise _Refused([blocker("PRODUCTION_ADMISSION_REFUSED", detail="no verified production admission")])
    return {"admission_state": A.ADMITTED}


# Phase 7: each decommission edge is taken only on its own DecommissionRecord's evidence (``core.services.decommission``)
_DECOMMISSION_EDGES = {
    "DECOMMISSION_REQUEST": ("APPROVED",),
    "DECOMMISSION": ("DECOMMISSIONED",),
    "DECOMMISSION_CANCEL": ("ROLLED_BACK", "BLOCKED"),
}


def _decommission_prerequisites(device, action: str, evidence: dict) -> dict:
    record = models.DecommissionRecord.objects.filter(device=device, pk=_record_pk(evidence.get("decommission"), "DCM-")).first()
    if record is None or record.state not in _DECOMMISSION_EDGES[action]:
        raise _Refused([blocker("DECOMMISSION_STATE_INVALID", action=action, state=getattr(record, "state", ""))])
    if action == "DECOMMISSION_REQUEST" and not record.approved_by:
        raise _Refused([blocker("DECOMMISSION_STATE_INVALID", action=action, detail="no approver")])
    if action == "DECOMMISSION_CANCEL" and device.admission_state not in (A.ADMITTED, A.LEGACY_PREEXISTING):
        raise _Refused([blocker("DECOMMISSION_STATE_INVALID", action=action, detail="never in service")])
    return {"retired_at": timezone.now()} if action == "DECOMMISSION" else {}


def register_restored(predecessor, *, actor: str, restoration: str, evidence: dict) -> object:
    """Phase 7: register the successor of a DECOMMISSIONED device whose restoration was approved, executed and postchecked
    (``core.services.decommission``; inside its transaction).  The successor keeps the predecessor's name, platform, role and
    inventory authority; it is IN_SERVICE with the predecessor's admission (ADMITTED / LEGACY_PREEXISTING) and identity only
    because the restoration re-observed that identity in place.  Anything else is re-enrolled through Phases 3-6."""
    if predecessor.lifecycle_state != S.DECOMMISSIONED or predecessor.admission_state not in (A.ADMITTED, A.LEGACY_PREEXISTING):
        raise ValueError("Only a decommissioned, previously admitted device can be restored.")
    if not models.RestorationRecord.objects.filter(device=predecessor, pk=_record_pk(restoration, "RST-"), state="RESTORING").exists():
        raise ValueError("The restoration is not executing.")
    verified = predecessor.identity_state == I.VERIFIED
    row = models.ManagedDevice(
        name=predecessor.name, platform=predecessor.platform, role=predecessor.role, origin=models.DeviceOrigin.RESTORED,
        inventory_authority=predecessor.inventory_authority, lifecycle_state=S.IN_SERVICE, admission_state=predecessor.admission_state,
        identity_state=I.VERIFIED if verified else I.UNVERIFIED, manufacturer=predecessor.manufacturer, model=predecessor.model,
        verified_serial=predecessor.verified_serial if verified else "", verified_base_mac=predecessor.verified_base_mac if verified else "",
        verified_host_key=predecessor.verified_host_key if verified else "", identity_verified_at=timezone.now() if verified else None,
        identity_verified_by=actor[:150] if verified else "", netbox_device_id=predecessor.netbox_device_id, predecessor=predecessor,
        registered_by=actor[:150], repository_head=events.repository_head(), ztp_state=predecessor.ztp_state)
    row._lifecycle_write = True
    row.save()
    events.record(row, "RESTORE", Outcome.ADVANCED, actor=actor, to_state=S.IN_SERVICE,
                  evidence={"predecessor": predecessor.device_id, "restoration": restoration, "admission_state": row.admission_state,
                            "identity_state": row.identity_state, **{k: v for k, v in (evidence or {}).items() if k in ("digest", "identity")}})
    return row


def _failure_prerequisites(device, evidence: dict) -> None:
    """-> FAILED needs a recorded, non-retryable ZTP failure of this device's session (a retryable native failure never fails
    the device: the native mechanism retries) or an operator's reason."""
    if evidence.get("reason") and str(evidence["reason"]).strip():
        return
    session = models.ZtpSession.objects.filter(device=device, pk=evidence.get("ztp_session")).first() \
        if str(evidence.get("ztp_session", "")).isdigit() else None
    if session is None or session.stage != models.ZtpSessionStage.FAILED or (session.failure or {}).get("retryable", True):
        raise _Refused([blocker("ZTP_SESSION_STATE_INVALID")])


def record_ztp_state(device, ztp_state: str, *, actor: str, evidence: dict, correlation_id: str = "") -> LifecycleResult:
    """Record an OBSERVED native-ZTP state (ENABLED when the device's own native ZTP request was seen through a trusted relay;
    DISABLED_VERIFIED only from an authenticated read-back).  Idempotent: an unchanged state writes no event."""
    action = "ZTP_STATE"
    if ztp_state not in (models.ZtpState.ENABLED, models.ZtpState.DISABLED_VERIFIED):
        return _refused(device, action, [blocker("OBSERVATION_INVALID")], actor=actor, actor_kind=AUTOMATION)
    try:
        with transaction.atomic():
            fresh = _locked(device, None)
            if fresh.ztp_state == ztp_state:
                return LifecycleResult(fresh, True, action, [], None, changed=False)
            before = fresh.ztp_state
            _write(fresh, ztp_state=ztp_state)
            event = events.record(fresh, action, Outcome.RECORDED, actor=actor, actor_kind=AUTOMATION, from_state=fresh.lifecycle_state,
                                  to_state=fresh.lifecycle_state, correlation_id=correlation_id,
                                  evidence={"ztp_state": {"from": before, "to": ztp_state}, **evidence})
            return LifecycleResult(fresh, True, action, [], event, changed=True)
    except _Refused as refusal:
        return _refused(device, action, refusal.blockers, actor=actor, actor_kind=AUTOMATION)


def withdraw(device, *, actor: str, reason: str, expected_version=None) -> LifecycleResult:
    """Withdraw a registration that never reached service (revokes its open bootstrap authorizations).  Terminal."""
    text, problems = identity.clean_text(reason, max_length=300)
    if problems or not text:
        return _refused(device, "WITHDRAW", problems or [blocker("REASON_REQUIRED")], actor=actor, actor_kind=HUMAN)
    return transition(device, S.WITHDRAWN, actor=actor, actor_kind=HUMAN, expected_version=expected_version, evidence={"reason": text})


# --- registration of a NEW device -----------------------------------------------------------------------------------------------
def register_device(*, name: str, platform: str, role: str, actor: str, manufacturer: str = "", model: str = "",
                    expected_serial: str = "", expected_base_mac: str = "", netbox_device_id=None) -> LifecycleResult:
    """Register an expected new device (REGISTERED, identity UNVERIFIED, NOT_ADMITTED).  Nothing outside the NMAS database changes."""
    action = "REGISTER"
    name, blockers = identity.validate_name(name)
    if platform not in models.Platform.values:
        blockers.append(blocker("PLATFORM_UNKNOWN"))
    if role not in ROLES:
        blockers.append(blocker("ROLE_INVALID", roles=list(ROLES)))
    serial, problems = identity.normalize_serial(expected_serial)
    blockers += problems
    mac, problems = identity.normalize_mac(expected_base_mac)
    blockers += problems
    manufacturer, problems = identity.clean_text(manufacturer, max_length=64)
    blockers += problems
    model, problems = identity.clean_text(model, max_length=64)
    blockers += problems
    if netbox_device_id not in (None, "") and not str(netbox_device_id).isdigit():
        blockers.append(blocker("TEXT_INVALID", field="netbox_device_id"))
    if not blockers:
        blockers += identity.name_collisions(name) + identity.identity_conflicts(serial=serial, mac=mac)
    if blockers:
        return _refused_without_device(action, blockers, actor=actor, subject=name or "(invalid name)")
    try:
        with transaction.atomic():
            row = models.ManagedDevice(
                name=name, platform=platform, role=role, origin=models.DeviceOrigin.REGISTERED_NEW,
                inventory_authority=models.InventoryAuthority.NMAS_REGISTRY, lifecycle_state=S.REGISTERED, manufacturer=manufacturer,
                model=model, expected_serial=serial, expected_base_mac=mac, registered_by=actor[:150], repository_head=events.repository_head(),
                netbox_device_id=int(netbox_device_id) if str(netbox_device_id or "").isdigit() else None,
            )
            row._lifecycle_write = True
            row.save()
            event = events.record(row, action, Outcome.ADVANCED, actor=actor, to_state=S.REGISTERED, evidence={
                "origin": row.origin, "expected_identity": {"serial_known": bool(serial), "base_mac_known": bool(mac)},
                "identity_state": row.identity_state, "admission_state": row.admission_state})
    except IntegrityError:      # a concurrent registration won the name or the identity
        return _refused_without_device(action, [blocker("NAME_COLLISION", holders=["LIFECYCLE_REGISTRY"])], actor=actor, subject=name)
    return LifecycleResult(row, True, action, [], event, changed=True)


def update_expected_identity(device, *, actor: str, expected_serial: str = "", expected_base_mac: str = "", manufacturer: str = "",
                             model: str = "", expected_version=None) -> LifecycleResult:
    """Edit the operator-authorized expected identity of a registered device that has no open bootstrap authorization."""
    action = "EXPECTED_IDENTITY"
    serial, blockers = identity.normalize_serial(expected_serial)
    mac, problems = identity.normalize_mac(expected_base_mac)
    blockers += problems
    manufacturer, problems = identity.clean_text(manufacturer, max_length=64)
    blockers += problems
    model, problems = identity.clean_text(model, max_length=64)
    blockers += problems
    if blockers:
        return _refused(device, action, blockers, actor=actor, actor_kind=HUMAN)
    try:
        with transaction.atomic():
            fresh = _locked(device, expected_version)
            # a VERIFIED identity is locked too: editing it would leave the expected and verified identities disagreeing
            if fresh.origin != models.DeviceOrigin.REGISTERED_NEW or fresh.lifecycle_state not in (S.REGISTERED, S.DISCOVERED) \
                    or fresh.identity_state == I.VERIFIED \
                    or fresh.bootstrap_authorizations.filter(state__in=tuple(models.BOOTSTRAP_AUTHORIZATION_OPEN)).exists():
                raise _Refused([blocker("IDENTITY_LOCKED")])
            conflicts = identity.identity_conflicts(serial=serial, mac=mac, exclude_pk=fresh.pk)
            if conflicts:
                raise _Refused(conflicts)
            before = {"serial_known": bool(fresh.expected_serial), "base_mac_known": bool(fresh.expected_base_mac)}
            _write(fresh, expected_serial=serial, expected_base_mac=mac, manufacturer=manufacturer, model=model)
            event = events.record(fresh, action, Outcome.ADVANCED, actor=actor, from_state=fresh.lifecycle_state, to_state=fresh.lifecycle_state,
                                  evidence={"before": before, "after": {"serial_known": bool(serial), "base_mac_known": bool(mac)}})
            return LifecycleResult(fresh, True, action, [], event, changed=True)
    except _Refused as refusal:
        return _refused(device, action, refusal.blockers, actor=actor, actor_kind=HUMAN)
    except IntegrityError:
        return _refused(device, action, [blocker("IDENTITY_CONFLICT")], actor=actor, actor_kind=HUMAN)


# --- adoption of an EXISTING managed device -------------------------------------------------------------------------------------
def _linked_history(name: str) -> dict:
    """Counts of the device's existing records -- referenced as evidence, never copied, moved or edited."""
    return {
        "changes": models.ChangeTarget.objects.filter(device_name=name).values("change").distinct().count(),
        "executions": models.ChangeExecutionRun.objects.filter(change__targets__device_name=name).distinct().count(),
        "access_records": models.DeviceCredential.objects.filter(device_name=name).count(),
        "maintenance_records": models.MaintenanceRecord.objects.filter(device_name=name).count(),
        "provisioning_runs": models.ProvisioningRun.objects.filter(device_name=name).count(),
    }


def adoption_candidates(*, document: dict | None = None) -> list[dict]:
    """Every inventory network device with its adoption eligibility (read-only)."""
    resolution = resolver.resolve_all(document=document)
    rows = []
    for target in resolution.targets.values():
        if target.authority != resolver.Authority.INVENTORY_FILE:
            continue
        code = "" if target.writable and target.platform else ("OUT_OF_WRITABLE_SCOPE" if not target.writable else "PLATFORM_UNMAPPED")
        rows.append({"target": target, "adopted": bool(target.lifecycle), "refusal": code})
    return rows


def adopt_existing(name: str, *, role: str, actor: str) -> LifecycleResult:
    """Adopt an existing ``inventory.yml`` device into the lifecycle registry as a LEGACY_ADOPTION, IN_SERVICE asset.

    Writes NMAS state only.  Hardware identity stays UNVERIFIED, production participation is LEGACY_PREEXISTING (it predates NMAS
    admission control), ZTP and compliance stay UNKNOWN, and no provisioning / ZTP / commissioning history is created.
    Repeating it is a recorded no-op.  R5, endpoints and unknown names are refused.
    """
    action = "ADOPT"
    target, code = resolver.adoption_scope(name)
    if code:
        return _refused_without_device(action, [blocker(code)], actor=actor, subject=str(name)[:64])
    existing = models.ManagedDevice.objects.filter(identity.LIVE, name=target.name).first()
    if existing is not None:
        if existing.origin != models.DeviceOrigin.LEGACY_ADOPTION:
            return _refused(existing, action, [blocker("NAME_COLLISION", holders=["LIFECYCLE_REGISTRY"])], actor=actor, actor_kind=HUMAN)
        with transaction.atomic():
            event = events.record(existing, action, Outcome.UNCHANGED, actor=actor, from_state=existing.lifecycle_state,
                                  to_state=existing.lifecycle_state, blockers=[blocker("ALREADY_ADOPTED")])
        return LifecycleResult(existing, True, action, [], event, changed=False)
    if role not in ROLES:
        return _refused_without_device(action, [blocker("ROLE_INVALID", roles=list(ROLES))], actor=actor, subject=target.name)
    collisions = [b for b in identity.name_collisions(target.name, allow_adopted_inventory=True)]
    if collisions:
        return _refused_without_device(action, collisions, actor=actor, subject=target.name)
    entry = (resolver.health_inventory.load_inventory().get("network_devices") or {}).get(target.name) or {}
    try:
        with transaction.atomic():
            row = models.ManagedDevice(
                name=target.name, platform=target.platform, role=role, origin=models.DeviceOrigin.LEGACY_ADOPTION,
                inventory_authority=models.InventoryAuthority.INVENTORY_FILE, lifecycle_state=S.IN_SERVICE,
                admission_state=A.LEGACY_PREEXISTING, registered_by=actor[:150], repository_head=events.repository_head(),
            )
            row._lifecycle_write = True
            row.save()
            event = events.record(row, action, Outcome.ADVANCED, actor=actor, to_state=S.IN_SERVICE, evidence={
                "basis": "LEGACY_ADOPTION", "inventory_authority": "inventory.yml",
                "inventory_entry_digest": hashlib.sha256(json.dumps(entry, sort_keys=True, default=str).encode()).hexdigest(),
                "scope": target.scope, "management_candidates": [c.as_dict() for c in target.management_candidates],
                "access_reference_keys": sorted(k for k in target.credential_refs if k.endswith("_ref")),
                "linked_history": _linked_history(target.name),
                "identity_state": row.identity_state, "admission_state": row.admission_state, "ztp_state": row.ztp_state,
                "compliance_state": row.compliance_state, "onboarding_history": "NONE (pre-existing device; no ZTP or commissioning record)",
            })
    except IntegrityError:      # a concurrent adoption won: report it as the idempotent repeat it is
        existing = models.ManagedDevice.objects.filter(identity.LIVE, name=target.name).first()
        if existing is not None and existing.origin == models.DeviceOrigin.LEGACY_ADOPTION:
            return LifecycleResult(existing, True, action, [], None, changed=False)
        return _refused_without_device(action, [blocker("NAME_COLLISION")], actor=actor, subject=target.name)
    return LifecycleResult(row, True, action, [], event, changed=True)


# --- observations and identity verification -------------------------------------------------------------------------------------
CLAIM_KEYS = ("serial", "base_mac", "host_key", "hostname", "client_id")


def _normalize_claims(claims: dict) -> tuple[dict, list[dict]]:
    out, blockers = {}, []
    for key, value in (claims or {}).items():
        if key not in CLAIM_KEYS:
            blockers.append(blocker("OBSERVATION_INVALID", key=str(key)[:32]))
            continue
        normalizer = {"serial": identity.normalize_serial, "base_mac": identity.normalize_mac, "host_key": identity.normalize_host_key}.get(key)
        if normalizer:
            normalized, problems = normalizer(value)
        else:
            normalized, problems = identity.clean_text(value, max_length=128)
        blockers += problems
        if normalized:
            out[key] = normalized
    return out, blockers


def _identity_mismatches(device, claims: dict) -> list[dict]:
    found = []
    for key, expected in (("serial", device.expected_serial), ("base_mac", device.expected_base_mac),
                          ("serial", device.verified_serial), ("base_mac", device.verified_base_mac), ("host_key", device.verified_host_key)):
        if expected and claims.get(key) and claims[key] != expected:
            found.append({"field": key, "expected": "authorized value", "observed": "different value"})
    return found


def record_observation(device, *, kind: str, source: str, actor: str, actor_kind: str = AUTOMATION, claims: dict | None = None,
                       upstream_device: str = "", upstream_interface: str = "", local_interface: str = "", observed_at=None,
                       correlation_id: str = "") -> LifecycleResult:
    """Record one identity / attachment observation (Phase 3+ producers call this).  Trust follows the source; claims can only ever
    DENY (a contradicting claim is a mismatch), never establish identity.  A REGISTERED device becomes DISCOVERED."""
    action = f"OBSERVE_{kind}"
    if kind not in models.ObservationKind.values or source not in models.ObservationSource.values or actor_kind not in (HUMAN, AUTOMATION):
        return _refused(device, action, [blocker("OBSERVATION_INVALID")], actor=actor, actor_kind=HUMAN)
    normalized, blockers = _normalize_claims(claims or {})
    for value in (upstream_device, upstream_interface, local_interface):
        if value and not (models.INTERFACE_RE.fullmatch(value) or models.DEVICE_NAME_VALIDATOR.regex.fullmatch(value)):
            blockers.append(blocker("OBSERVATION_INVALID"))
    if kind == models.ObservationKind.ATTACHMENT and not (upstream_device and upstream_interface):
        blockers.append(blocker("OBSERVATION_INVALID", missing="upstream"))
    if blockers:
        return _refused(device, action, blockers, actor=actor, actor_kind=actor_kind)
    trust = models.OBSERVATION_TRUST[models.ObservationSource(source)]
    try:
        with transaction.atomic():
            fresh = _locked(device, None)
            attachment, result, mismatches = None, models.ObservationResult.RECORDED, []
            if kind == models.ObservationKind.IDENTITY:
                mismatches = _identity_mismatches(fresh, normalized)
                result = models.ObservationResult.MISMATCH if mismatches else (
                    models.ObservationResult.MATCH if trust == models.ObservationTrust.OBSERVED else models.ObservationResult.UNTRUSTED)
            else:
                from . import attachments as attachment_service

                attachment, result, mismatches = attachment_service.compare(fresh, trust, upstream_device, upstream_interface, local_interface)
            observation = models.DeviceObservation.objects.create(
                device=fresh, kind=kind, source=source, trust=trust, claims=normalized, upstream_device=upstream_device,
                upstream_interface=upstream_interface, local_interface=local_interface, attachment=attachment, result=result,
                mismatches=mismatches, recorded_by=actor[:150], observed_at=observed_at or timezone.now(),
            )
            if kind == models.ObservationKind.ATTACHMENT:
                from . import attachments as attachment_service

                attachment_service.apply_observation(fresh, observation)
            if kind == models.ObservationKind.IDENTITY and result == models.ObservationResult.MISMATCH \
                    and trust == models.ObservationTrust.OBSERVED and fresh.identity_state != I.MISMATCH:
                _write(fresh, identity_state=I.MISMATCH)
            event = events.record(fresh, action, Outcome.RECORDED, actor=actor, actor_kind=actor_kind, from_state=fresh.lifecycle_state,
                                  to_state=fresh.lifecycle_state, observation=observation, attachment=attachment, correlation_id=correlation_id,
                                  evidence={"source": source, "trust": trust, "result": result, "mismatches": mismatches,
                                            "claimed_keys": sorted(normalized)})
            discovered = None
            if fresh.lifecycle_state == S.REGISTERED and fresh.origin == models.DeviceOrigin.REGISTERED_NEW \
                    and trust != models.ObservationTrust.REFERENCE:
                discovered = _apply_edge(fresh, EDGES[(S.REGISTERED, S.DISCOVERED)], S.DISCOVERED, actor=actor, actor_kind=actor_kind,
                                         evidence={"observation": observation.pk}, correlation_id=event.correlation_id)
    except _Refused as refusal:
        return _refused(device, action, refusal.blockers, actor=actor, actor_kind=actor_kind, correlation_id=correlation_id)
    result_obj = LifecycleResult(fresh, True, action, [], discovered.event if discovered else event, changed=bool(discovered))
    result_obj.observation = observation
    return result_obj


def verify_identity(device, observation_id, *, actor: str, expected_version=None) -> LifecycleResult:
    """Promote an independently observed identity (an authenticated-session observation with the SSH host key) to VERIFIED.

    Claims and reference data are refused; an expected serial / MAC must be present in the observation and equal to it; the
    verified values must not belong to another live device.  Never marks a device verified without such an observation.
    """
    action = "VERIFY_IDENTITY"
    try:
        with transaction.atomic():
            fresh = _locked(device, expected_version)
            observation = models.DeviceObservation.objects.filter(device=fresh, pk=observation_id).first() if str(observation_id).isdigit() else None
            if observation is None or observation.kind != models.ObservationKind.IDENTITY:
                raise _Refused([blocker("OBSERVATION_INVALID")])
            if observation.trust != models.ObservationTrust.OBSERVED or observation.source != models.ObservationSource.AUTHENTICATED_SESSION:
                raise _Refused([blocker("IDENTITY_NOT_OBSERVED", source=observation.source, trust=observation.trust)])
            claims = observation.claims or {}
            if not claims.get("host_key") or (fresh.expected_serial and not claims.get("serial")) \
                    or (fresh.expected_base_mac and not claims.get("base_mac")):
                raise _Refused([blocker("IDENTITY_EVIDENCE_INSUFFICIENT")])
            mismatches = _identity_mismatches(fresh, claims)
            # stale evidence: a later trusted observation contradicted the identity this one shows
            contradicted = models.DeviceObservation.objects.filter(
                Q(observed_at__gt=observation.observed_at) | Q(observed_at=observation.observed_at, pk__gt=observation.pk),
                device=fresh, kind=models.ObservationKind.IDENTITY, trust=models.ObservationTrust.OBSERVED,
                result=models.ObservationResult.MISMATCH).exists()
            if mismatches or contradicted or observation.result == models.ObservationResult.MISMATCH:
                raise _Refused([blocker("IDENTITY_MISMATCH", fields=[m["field"] for m in mismatches])])
            conflicts = identity.identity_conflicts(serial=claims.get("serial", ""), mac=claims.get("base_mac", ""),
                                                    host_key=claims["host_key"], exclude_pk=fresh.pk)
            if conflicts:
                raise _Refused(conflicts)
            before = fresh.identity_state
            _write(fresh, identity_state=I.VERIFIED, verified_serial=claims.get("serial", ""), verified_base_mac=claims.get("base_mac", ""),
                   verified_host_key=claims["host_key"], identity_verified_at=timezone.now(), identity_verified_by=actor[:150])
            event = events.record(fresh, action, Outcome.ADVANCED, actor=actor, from_state=fresh.lifecycle_state, to_state=fresh.lifecycle_state,
                                  observation=observation, evidence={"identity_state": {"from": before, "to": I.VERIFIED},
                                                                     "verified_keys": sorted(k for k in ("serial", "base_mac", "host_key") if claims.get(k))})
            return LifecycleResult(fresh, True, action, [], event, changed=True)
    except _Refused as refusal:
        return _refused(device, action, refusal.blockers, actor=actor, actor_kind=HUMAN)
    except IntegrityError:
        return _refused(device, action, [blocker("IDENTITY_CONFLICT")], actor=actor, actor_kind=HUMAN)


def maintenance_state(device) -> dict:
    """The device's maintenance as ``MaintenanceRecord`` holds it (read-only; maintenance is never stored here)."""
    record = models.MaintenanceRecord.objects.filter(device_name=device.name).order_by("-id").first()
    return {"record_id": record.record_id, "state": record.state} if record else {}
