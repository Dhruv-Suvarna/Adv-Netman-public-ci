"""Expected attachments: where an operator says a device is connected, and how observations confirm or contradict it.

An attachment names a trusted upstream -- an ``inventory.yml`` device that NMAS writes to and that was adopted IN_SERVICE --
and one of its interfaces.  Nothing is inferred from names or addresses.  A device may have several attachments (multihoming).

VLAN rules: a ROUTED attachment carries no VLAN; TRUNK and SUBINTERFACE attachments need one; VLAN 200 (the static
management network) may only be named by a MANAGEMENT attachment.  Recording an attachment changes no device and no
network: it is an expectation in the NMAS database, nothing more.

Evidence: only an OBSERVED source can make an attachment VERIFIED.  A claim can contradict it (MISMATCH) but never confirm it.
Reference data (lab topology, a NetBox cable) proves nothing about the cable that is really there.
"""

from __future__ import annotations

from django.db import IntegrityError, transaction
from django.db.models import Q
from django.utils import timezone

from ... import models
from . import events, identity, resolver
from .codes import blocker

S = models.DeviceLifecycleState
Approval = models.AttachmentApproval
Verification = models.AttachmentVerification
Outcome = models.DeviceLifecycleEventOutcome
MANAGEMENT_VLAN = 200
LIVE_ATTACHMENT = ~Q(approval_state=Approval.REVOKED)


class _Refused(Exception):
    def __init__(self, blockers):
        super().__init__("refused")
        self.blockers = blockers


def _result(device, ok, action, blockers=(), event=None, changed=False, attachment=None):
    from .lifecycle import LifecycleResult

    result = LifecycleResult(device, ok, action, list(blockers), event, changed)
    result.attachment = attachment
    return result


def _refuse(device, action, blockers, *, actor, attachment=None):
    with transaction.atomic():
        event = events.record(device, action, Outcome.REFUSED, actor=actor, from_state=device.lifecycle_state, blockers=blockers,
                              attachment=attachment)
    return _result(device, False, action, blockers, event, attachment=attachment)


def upstream_problems(device_name: str, upstream_device: str) -> list[dict]:
    """Why ``upstream_device`` cannot carry an expected attachment ([] when it can)."""
    if not upstream_device or upstream_device == device_name:
        return [blocker("UPSTREAM_UNKNOWN")]
    target = resolver.resolve(upstream_device)
    if target is None:
        return [blocker("UPSTREAM_UNKNOWN")]
    if target.authority != resolver.Authority.INVENTORY_FILE:
        return commissioned_upstream_problems(upstream_device)
    lifecycle = target.lifecycle or {}
    if not target.writable or lifecycle.get("lifecycle_state") != S.IN_SERVICE \
            or lifecycle.get("origin") != models.DeviceOrigin.LEGACY_ADOPTION:
        return [blocker("UPSTREAM_NOT_TRUSTED", scope=target.scope, adopted=bool(lifecycle))]
    return []


def commissioned_upstream_problems(upstream_device: str) -> list[dict]:
    """The generic onboarding dependency (e.g. R4 -> R6 -> R7): a NEW device can carry a downstream device's attachment only
    once it is itself IN_SERVICE and ADMITTED to production by NMAS (Phases 5-6).  Until then the downstream device stays
    blocked with the upstream's own state as the reason -- nothing is special-cased by name."""
    row = models.ManagedDevice.objects.filter(identity.LIVE, name=upstream_device, origin=models.DeviceOrigin.REGISTERED_NEW).first()
    if row is None:
        return [blocker("UPSTREAM_UNKNOWN")]
    if row.lifecycle_state != S.IN_SERVICE or row.admission_state != models.ProductionAdmissionState.ADMITTED:
        return [blocker("UPSTREAM_NOT_TRUSTED", dependency=row.device_id, lifecycle_state=row.lifecycle_state,
                        admission_state=row.admission_state)]
    return []


def vlan_problems(*, purpose: str, connectivity: str, vlan) -> list[dict]:
    """The VLAN rules of an expected attachment ([] when ``vlan`` is consistent with ``purpose`` and ``connectivity``)."""
    if connectivity == models.AttachmentConnectivity.ROUTED:
        return [blocker("VLAN_INVALID", reason="routed attachments carry no VLAN")] if vlan is not None else []
    if connectivity in (models.AttachmentConnectivity.TRUNK, models.AttachmentConnectivity.SUBINTERFACE) and vlan is None:
        return [blocker("VLAN_INVALID", reason="a VLAN is required")]
    if vlan is not None and not 1 <= vlan <= 4094:
        return [blocker("VLAN_INVALID", reason="out of range")]
    if vlan == MANAGEMENT_VLAN and purpose != models.AttachmentPurpose.MANAGEMENT:
        return [blocker("VLAN200_PURPOSE_FORBIDDEN")]
    return []


def _parse_vlan(value):
    text = str(value if value is not None else "").strip()
    if not text:
        return None, []
    if not text.isdigit():
        return None, [blocker("VLAN_INVALID", reason="not a number")]
    return int(text), []


def register_attachment(device, *, upstream_device: str, upstream_interface: str, purpose: str, connectivity: str, actor: str,
                        local_interface: str = "", vlan=None, source: str = models.AttachmentSource.OPERATOR) -> object:
    """Record one expected attachment (PENDING approval).  Refused for terminal devices, untrusted upstreams, taken ports and
    VLAN rule violations."""
    action = "ATTACHMENT_REGISTER"
    upstream_device = str(upstream_device or "").strip()
    upstream_interface = str(upstream_interface or "").strip()
    local_interface = str(local_interface or "").strip()
    blockers = []
    if device.is_terminal:
        blockers.append(blocker("DEVICE_TERMINAL", state=device.lifecycle_state))
    if not models.INTERFACE_RE.fullmatch(upstream_interface) or (local_interface and not models.INTERFACE_RE.fullmatch(local_interface)):
        blockers.append(blocker("INTERFACE_INVALID"))
    if purpose not in models.AttachmentPurpose.values or connectivity not in models.AttachmentConnectivity.values \
            or source not in models.AttachmentSource.values:
        blockers.append(blocker("ATTACHMENT_STATE_INVALID"))
    vlan, problems = _parse_vlan(vlan)
    blockers += problems
    if not blockers:
        blockers += vlan_problems(purpose=purpose, connectivity=connectivity, vlan=vlan)
        blockers += upstream_problems(device.name, upstream_device)
    if not blockers:
        if models.DeviceAttachment.objects.filter(LIVE_ATTACHMENT, upstream_device=upstream_device, upstream_interface=upstream_interface).exists():
            blockers.append(blocker("UPSTREAM_PORT_TAKEN"))
        if local_interface and models.DeviceAttachment.objects.filter(LIVE_ATTACHMENT, device=device, local_interface=local_interface).exists():
            blockers.append(blocker("LOCAL_PORT_TAKEN"))
    if blockers:
        return _refuse(device, action, blockers, actor=actor)
    try:
        with transaction.atomic():
            row = models.DeviceAttachment.objects.create(
                device=device, upstream_device=upstream_device, upstream_interface=upstream_interface, local_interface=local_interface,
                purpose=purpose, connectivity=connectivity, vlan=vlan, source=source, created_by=actor[:150])
            event = events.record(device, action, Outcome.RECORDED, actor=actor, from_state=device.lifecycle_state,
                                  to_state=device.lifecycle_state, attachment=row, evidence={
                                      "upstream": f"{upstream_device}:{upstream_interface}", "local_interface": local_interface,
                                      "purpose": purpose, "connectivity": connectivity, "vlan": vlan, "source": source})
    except IntegrityError:
        return _refuse(device, action, [blocker("UPSTREAM_PORT_TAKEN")], actor=actor)
    return _result(device, True, action, [], event, True, attachment=row)


def get_attachment(device, attachment_id):
    return models.DeviceAttachment.objects.filter(device=device, pk=attachment_id).first() if str(attachment_id).isdigit() else None


def approve_attachment(device, attachment_id, *, actor: str) -> object:
    """PENDING -> APPROVED by a different person than the one who recorded it; the upstream must still be trusted."""
    action = "ATTACHMENT_APPROVE"
    row = get_attachment(device, attachment_id)
    if row is None:
        return _refuse(device, action, [blocker("ATTACHMENT_NOT_FOUND")], actor=actor)
    blockers = []
    if row.approval_state != Approval.PENDING:
        blockers.append(blocker("ATTACHMENT_STATE_INVALID", state=row.approval_state))
    if actor == row.created_by:
        blockers.append(blocker("APPROVAL_SELF"))
    if device.is_terminal:
        blockers.append(blocker("DEVICE_TERMINAL", state=device.lifecycle_state))
    if not blockers:
        blockers += upstream_problems(device.name, row.upstream_device)
    if blockers:
        return _refuse(device, action, blockers, actor=actor, attachment=row)
    try:
        with transaction.atomic():
            locked = models.DeviceAttachment.objects.select_for_update().get(pk=row.pk)
            if locked.approval_state != Approval.PENDING:     # a concurrent approver / revoker won
                raise _Refused([blocker("CONCURRENT_MODIFICATION", state=locked.approval_state)])
            locked.approval_state, locked.approved_by, locked.approved_at = Approval.APPROVED, actor[:150], timezone.now()
            locked.save(update_fields=["approval_state", "approved_by", "approved_at", "updated_at"])
            event = events.record(device, action, Outcome.RECORDED, actor=actor, from_state=device.lifecycle_state,
                                  to_state=device.lifecycle_state, attachment=locked, evidence={"approval_state": Approval.APPROVED})
    except _Refused as refusal:
        return _refuse(device, action, refusal.blockers, actor=actor, attachment=row)
    return _result(device, True, action, [], event, True, attachment=locked)


def revoke_attachment(device, attachment_id, *, actor: str, reason: str) -> object:
    """Revoke an expected attachment.  Any open bootstrap authorization bound to it is revoked in the same transaction."""
    action = "ATTACHMENT_REVOKE"
    row = get_attachment(device, attachment_id)
    if row is None:
        return _refuse(device, action, [blocker("ATTACHMENT_NOT_FOUND")], actor=actor)
    text, problems = identity.clean_text(reason, max_length=300)
    if problems or not text:
        return _refuse(device, action, problems or [blocker("REASON_REQUIRED")], actor=actor, attachment=row)
    if row.approval_state == Approval.REVOKED:
        return _refuse(device, action, [blocker("ATTACHMENT_STATE_INVALID", state=row.approval_state)], actor=actor, attachment=row)
    with transaction.atomic():
        now = timezone.now()
        revoked = []
        for auth in row.bootstrap_authorizations.select_for_update().filter(state__in=tuple(models.BOOTSTRAP_AUTHORIZATION_OPEN)):
            auth.state, auth.revoked_by, auth.revoked_at, auth.closed_at = models.BootstrapAuthorizationState.REVOKED, actor[:150], now, now
            auth.revocation_reason = "Bound attachment revoked."
            auth.save(update_fields=["state", "revoked_by", "revoked_at", "revocation_reason", "closed_at", "updated_at"])
            revoked.append(auth.auth_id)
        row.approval_state, row.revoked_by, row.revoked_at = Approval.REVOKED, actor[:150], now
        row.save(update_fields=["approval_state", "revoked_by", "revoked_at", "updated_at"])
        event = events.record(device, action, Outcome.RECORDED, actor=actor, from_state=device.lifecycle_state,
                              to_state=device.lifecycle_state, attachment=row,
                              evidence={"reason": text, "revoked_bootstrap_ids": revoked})
    return _result(device, True, action, [], event, True, attachment=row)


# --- observations ---------------------------------------------------------------------------------------------------------------
def compare(device, trust: str, upstream_device: str, upstream_interface: str, local_interface: str = "") -> tuple:
    """Compare one attachment observation to the expectations -> (matching attachment | None, ObservationResult, mismatches)."""
    Result = models.ObservationResult
    if trust == models.ObservationTrust.REFERENCE:
        row = models.DeviceAttachment.objects.filter(LIVE_ATTACHMENT, device=device, upstream_device=upstream_device,
                                                     upstream_interface=upstream_interface).first()
        return row, Result.UNTRUSTED, []
    mismatches = []
    other = models.DeviceAttachment.objects.filter(LIVE_ATTACHMENT, upstream_device=upstream_device,
                                                   upstream_interface=upstream_interface).exclude(device=device).first()
    if other is not None:
        mismatches.append({"field": "upstream_port", "detail": "the port is expected to carry another device"})
    row = models.DeviceAttachment.objects.filter(LIVE_ATTACHMENT, device=device, upstream_device=upstream_device,
                                                 upstream_interface=upstream_interface).first()
    expected_any = models.DeviceAttachment.objects.filter(LIVE_ATTACHMENT, device=device).exists()
    if row is None and expected_any:
        mismatches.append({"field": "upstream_port", "detail": "not an expected attachment of this device"})
    if row is not None and row.local_interface and local_interface and row.local_interface != local_interface:
        mismatches.append({"field": "local_interface", "detail": "a different local interface was seen"})
    if mismatches:
        return row, Result.MISMATCH, mismatches
    if row is None:
        return None, Result.RECORDED, []
    return row, (Result.MATCH if trust == models.ObservationTrust.OBSERVED else Result.UNTRUSTED), []


def apply_observation(device, observation) -> None:
    """Fold one attachment observation into its attachment's verification state (inside the caller's transaction).

    OBSERVED evidence verifies or contradicts; a CLAIM can only contradict; REFERENCE data changes nothing."""
    row = observation.attachment
    if row is None or row.device_id != device.pk or row.approval_state == Approval.REVOKED:
        return
    if row.observed_at and observation.observed_at < row.observed_at:     # out of order: never overwrite newer evidence
        return
    Result = models.ObservationResult
    if observation.result == Result.MISMATCH and observation.trust in (models.ObservationTrust.OBSERVED, models.ObservationTrust.CLAIMED):
        row.verification_state, row.mismatch = Verification.MISMATCH, {"observation": observation.pk, "mismatches": observation.mismatches}
    elif observation.result == Result.MATCH and observation.trust == models.ObservationTrust.OBSERVED:
        row.verification_state, row.mismatch = Verification.VERIFIED, {}
    else:
        return
    row.observed_at = observation.observed_at
    row.save(update_fields=["verification_state", "mismatch", "observed_at", "updated_at"])
