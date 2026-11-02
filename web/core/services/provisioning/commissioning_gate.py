"""The provisioning side of V2 Phase 6 commissioning.  A run with the ``ZTP_MANAGEMENT`` transport carries the production
configuration of a natively onboarded device; it is created and approved only through ``core.services.commissioning``, executed
through the ordinary execution engine, and reaches NetBox activation only after production admission.  Thin by design: every rule
lives in the commissioning service (imported lazily, the two packages reference each other)."""

from __future__ import annotations

from ... import models
from ..execution.codes import blocker as execution_blocker
from .codes import blocker


def is_commissioning(run) -> bool:
    return run is not None and run.bootstrap_transport == models.BootstrapTransport.ZTP_MANAGEMENT


def record_of(run):
    return models.CommissioningRecord.objects.filter(provisioning_run=run).first() if run is not None and run.pk else None


def identity_blockers(run, target: dict) -> list[dict]:
    """The ZTP_MANAGEMENT target must be the very device this run is named after (no other device's session)."""
    device_id = str(target.get("device") or "")
    device = models.ManagedDevice.objects.filter(pk=int(device_id[4:])).first() if device_id[4:].isdigit() else None
    if device is None or device.name != run.device_name:
        return [blocker("BOOTSTRAP_TARGET_INVALID")]
    return []


def approval_blockers(run, actor: str) -> list[dict]:
    """A commissioning run is approved only by the commissioning approval itself (same approver, record APPROVED, fresh)."""
    if not is_commissioning(run):
        return []
    from ..commissioning import service

    record = record_of(run)
    if record is None or record.state != models.CommissioningState.APPROVED or record.approved_by != actor:
        return [blocker("COMMISSIONING_NOT_APPROVED")]
    if service.staleness(record):
        return [blocker("COMMISSIONING_STALE")]
    return []


def execution_blockers(run) -> list[dict]:
    """Part of THE execution gate for a commissioning run: approved, still fresh, and the device still isolated."""
    if not is_commissioning(run):
        return []
    from ..commissioning import service

    record = record_of(run)
    if record is None or record.state not in (models.CommissioningState.APPROVED, models.CommissioningState.CONFIGURING):
        return [execution_blocker("COMMISSIONING_NOT_APPROVED", prov_id=run.prov_id)]
    stale = service.staleness(record)
    if stale:
        return [execution_blocker("COMMISSIONING_STALE", prov_id=run.prov_id, codes=[b["code"] for b in stale][:5])]
    return []


def sync_blockers(run) -> list[dict]:
    if not is_commissioning(run):
        return []
    device = models.ManagedDevice.objects.filter(name=run.device_name, origin=models.DeviceOrigin.REGISTERED_NEW).exclude(
        lifecycle_state__in=tuple(models.DEVICE_LIFECYCLE_TERMINAL)).first()
    if device is None or device.admission_state != models.ProductionAdmissionState.ADMITTED:
        return [blocker("COMMISSIONING_NOT_ADMITTED")]
    return []


def config_reader(device: dict) -> str:
    from ..commissioning import transport

    return transport.config_reader(device)


def mark_configuring(run) -> None:
    """Write-ahead: the commissioning record enters CONFIGURING before the engine's first write to the device."""
    if not is_commissioning(run):
        return
    from ..commissioning import service

    service.mark_configuring(run)
