"""Deterministic server-side concurrency protection (not a browser-side disabled button).

Two DB-level guarantees, both enforced by UNIQUE constraints so they hold however many requests race:

* one ACTIVE run per Change      ``unique_active_execution_per_change`` (partial unique index on state = RUNNING);
* one run per DEVICE at a time   ``ExecutionDeviceLock.device`` (unique) -- overlapping executions of different Changes
                                 cannot both hold the same device.

A run and all its device locks are created in ONE transaction, so acquisition is all-or-nothing.  A crashed process cannot
hold locks forever: every run carries a lease, and an expired-lease run is reaped (finalised INTERRUPTED, its in-flight
results marked UNKNOWN, its locks released) at the next acquisition.  An INTERRUPTED run is deliberately not "resumed":
its plan is marked unresolved (see ``eligibility``) because the device state is unknown.
"""

from __future__ import annotations

from datetime import datetime, timedelta

from django.db import IntegrityError, transaction
from django.utils import timezone

from ... import models
from .codes import ENGINE_VERSION, Outcome, Status, lease_seconds
from .device_mutex import DeviceBusy, DeviceMutex


class LockRefused(Exception):
    def __init__(self, code: str, **details):
        super().__init__(code)
        self.code, self.details = code, details


def reap_expired(now: datetime | None = None) -> list[str]:
    """Finalise abandoned runs (lease expired while RUNNING) as INTERRUPTED and free their locks.  Returns run ids."""
    now = now or timezone.now()
    reaped = []
    for run in list(models.ChangeExecutionRun.objects.filter(state=models.ExecutionRunState.RUNNING, lease_expires_at__lte=now)):
        with transaction.atomic():
            for result in run.results.filter(status=Status.IN_PROGRESS):
                result.status, result.error_code, result.partial_effects, result.finished_at = Status.UNKNOWN, "LEASE_EXPIRED", True, now
                result.save()
            run.state, run.outcome, run.finished_at = models.ExecutionRunState.FINISHED, Outcome.INTERRUPTED, now
            run.report = {**(run.report or {}), "interrupted": {"reason": "LEASE_EXPIRED"}}
            run.summary = {**(run.summary or {}), "outcome": Outcome.INTERRUPTED}
            run.save()
            run.device_locks.all().delete()
            models.AuditEvent.objects.create(
                event_type=models.AuditEventType.DEPLOYMENT_RECORDED, change=run.change, object_type="ChangeExecutionRun",
                object_id=str(run.run_id), actor="execution-engine",
                summary=f"{run.change.change_id}: execution {str(run.run_id)[:8]} INTERRUPTED (lease expired)",
                metadata={"run_id": str(run.run_id), "stage": "FINISHED", "outcome": Outcome.INTERRUPTED, "reason": "LEASE_EXPIRED"},
            )
        reaped.append(str(run.run_id))
    return reaped


def acquire(*, change, plan, precheck_run, mode: str, actor: str, scope, devices: list[str], now: datetime | None = None) -> models.ChangeExecutionRun:
    """Create the RUNNING run and every device lock atomically, or raise ``LockRefused`` and change nothing."""
    now = now or timezone.now()
    reap_expired(now)
    try:
        with DeviceMutex(devices), transaction.atomic():
            run = models.ChangeExecutionRun.objects.create(
                change=change, plan=plan, validation_run=plan.validation_run, precheck_run=precheck_run, mode=mode, actor=actor,
                engine_version=ENGINE_VERSION, plan_hash=plan.plan_hash, validation_input_hash=plan.validation_input_hash,
                validation_source_hash=plan.validation_source_hash, scope=scope.to_dict(), devices=list(devices),
                started_at=now, lease_expires_at=now + timedelta(seconds=lease_seconds()),
            )
            for device in devices:
                models.ExecutionDeviceLock.objects.create(device=device, run=run)
            models.AuditEvent.objects.create(
                event_type=models.AuditEventType.DEPLOYMENT_RECORDED, change=change, object_type="ChangeExecutionRun",
                object_id=str(run.run_id), actor=actor,
                summary=f"{change.change_id}: {mode} execution {str(run.run_id)[:8]} started",
                metadata={"run_id": str(run.run_id), "stage": "STARTED", "mode": mode, "plan_id": str(plan.plan_id), "plan_hash": plan.plan_hash,
                          "devices": list(devices), "configlets": scope.requested_cfg_ids,
                          "raw_configlets": [{"cfg_id": c.cfg_id, **{k: ((c.metadata or {}).get("raw") or {}).get(k) for k in ("raw_id", "revision", "content_hash")}}
                                             for c in scope.selected if c.origin == "RAW"]},
            )
    except DeviceBusy as exc:
        raise LockRefused("DEVICE_LOCKED", devices=list(exc.devices)) from None
    except IntegrityError:
        if models.ChangeExecutionRun.objects.filter(change=change, state=models.ExecutionRunState.RUNNING).exists():
            raise LockRefused("EXECUTION_IN_PROGRESS") from None
        held = sorted(models.ExecutionDeviceLock.objects.filter(device__in=devices).values_list("device", flat=True))
        raise LockRefused("DEVICE_LOCKED", devices=held) from None
    return run


def heartbeat(run, now: datetime | None = None) -> None:
    """Extend the lease of a RUNNING run (queryset update: touches only the lease, never a finished row)."""
    now = now or timezone.now()
    models.ChangeExecutionRun.objects.filter(pk=run.pk, state=models.ExecutionRunState.RUNNING).update(
        lease_expires_at=now + timedelta(seconds=lease_seconds())
    )
