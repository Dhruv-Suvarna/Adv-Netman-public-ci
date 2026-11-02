"""Shared, read-only lifecycle lookups for the Phase 8 consumers (no writes, no I/O)."""

from __future__ import annotations

from ... import models
from ..commissioning import outbox
from ..devices import identity
from ..maintenance_mode import lifecycle as maintenance_lifecycle

TERMINAL = frozenset(models.DEVICE_LIFECYCLE_TERMINAL)
ADMITTED_STATES = frozenset({models.ProductionAdmissionState.ADMITTED, models.ProductionAdmissionState.LEGACY_PREEXISTING})


class ConsumerError(Exception):
    """A retryable consumer failure.  ``code`` is a fixed token (it becomes ``LifecycleOutboxEvent.last_error``)."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = str(code)[:64]


def fact_of(event) -> str:
    """The fact an outbox event carries: the payload's ``fact`` (Phase 8 topics) or ADMITTED (a Phase 6 admission hand-off)."""
    if event.topic in outbox.FACT_TOPICS:
        return str((event.payload or {}).get("fact", ""))
    return outbox.ADMITTED


def superseded(event, last_sequence: int) -> bool:
    """True when a fact is older than (or the same as) what the projection already applied.  Admission hand-offs
    (sequence 0) are never superseded: they re-derive the full state."""
    return bool(event.sequence) and int(event.sequence) <= int(last_sequence or 0)


def under_maintenance(name: str) -> bool:
    """The maintenance engine's own answer (``MaintenanceRecord`` in an IN_MAINTENANCE state) -- never duplicated here."""
    return models.MaintenanceRecord.objects.filter(device_name=str(name), state__in=maintenance_lifecycle.IN_MAINTENANCE).exists()


def live_device(name: str):
    """The live (non-terminal) managed device called ``name``, or None."""
    return models.ManagedDevice.objects.filter(identity.LIVE, name=str(name)).order_by("-pk").first()


def attachment_ref(attachment) -> str:
    return f"ATT-{attachment.pk:06d}"


def verified_production_attachments(device):
    """APPROVED + VERIFIED production attachments of ``device`` -- the only provenance of a production link."""
    return models.DeviceAttachment.objects.filter(device=device, purpose=models.AttachmentPurpose.PRODUCTION,
                                                  approval_state=models.AttachmentApproval.APPROVED,
                                                  verification_state=models.AttachmentVerification.VERIFIED).order_by("id")


def successor_of(device):
    """The restored successor registration of ``device`` (Phase 7: same name, origin RESTORED, ``predecessor`` FK), or None."""
    return models.ManagedDevice.objects.filter(predecessor=device).order_by("-pk").first()


def provenance_attachments(device):
    """``device``'s verified production attachments; a restored successor with none of its own inherits its predecessor's
    (the same physical links, proven before decommissioning) -> (attachments, inherited_from device_id or '')."""
    own = list(verified_production_attachments(device))
    if own or not device.predecessor_id:
        return own, ""
    predecessor = models.ManagedDevice.objects.get(pk=device.predecessor_id)
    return list(verified_production_attachments(predecessor)), predecessor.device_id
