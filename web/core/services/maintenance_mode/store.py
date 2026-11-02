"""The stored form of a maintenance record (``core.models.MaintenanceRecord``) and the two reads the pages need.

``save`` writes the lifecycle record as it is; it decides nothing.  Loading a row gives back an equal record."""

from __future__ import annotations

from datetime import datetime, timedelta

from . import lifecycle, model, plan, visibility


def _finding(f: model.Finding) -> dict:
    return {"code": f.code, "family": f.family, "direction": f.direction, "traffic_class": f.traffic_class, "workloads": list(f.workloads), "detail": f.detail}


def _to_finding(d: dict) -> model.Finding:
    return model.Finding(d["code"], d["family"], d["direction"], d["traffic_class"], tuple(d["workloads"]), d["detail"])


def snapshot(record: lifecycle.Record) -> dict:
    report = record.report
    return {
        "report": None if report is None else {
            "cells": {f"{family}/{direction}": {**cell, "active": list(cell["active"])} for (family, direction), cell in report.cells.items()},
            "blockers": [_finding(f) for f in report.blockers], "notes": [_finding(f) for f in report.notes]},
        "steps": [{"family": s.family, "direction": s.direction, "mechanism": s.mechanism, "workloads": list(s.workloads)} for s in record.steps],
        "findings": [_finding(f) for f in record.findings],
        "maintenance_only_state": list(record.maintenance_only_state), "baseline_untrusted": record.baseline_untrusted,
        "history": [{**entry, "at": entry["at"].isoformat()} for entry in record.history],
        "evidence": record.evidence,
        "plan": record.plan,
    }


def save(record: lifecycle.Record, row=None):
    """Create or update the row of ``record``.  -> the row."""
    from core import models

    request = record.request
    row = row or models.MaintenanceRecord(device_name=request.device, requested_by=request.operator, reason=request.reason,
                                          requested_at=request.requested_at, requested_duration_seconds=int(request.requested_duration.total_seconds()))
    row.state, row.approved_by, row.entered_at, row.deadline_at = record.state, record.approved_by, record.entered_at, record.cycle_deadline
    row.restore_trigger, row.escalated, row.snapshot = record.restore_trigger, record.escalated, snapshot(record)
    if row.pk is None:
        row.save()
    else:                                   # the queue and claim columns change only by conditional updates (service): never overwritten here
        row.save(update_fields=["state", "approved_by", "entered_at", "deadline_at", "restore_trigger", "escalated", "snapshot", "plan_hash",
                                "plan_status", "updated_at"])
    return row


def load(row) -> lifecycle.Record:
    data = row.snapshot or {}
    report = None
    if data.get("report") is not None:
        report = model.Report(row.device_name)
        for key, cell in data["report"]["cells"].items():
            report.cells[tuple(key.split("/"))] = {**cell, "active": tuple(cell["active"])}
        report.blockers = [_to_finding(d) for d in data["report"]["blockers"]]
        report.notes = [_to_finding(d) for d in data["report"]["notes"]]
    return lifecycle.Record(
        request=model.Request(row.device_name, row.requested_by, row.reason, timedelta(seconds=row.requested_duration_seconds), row.requested_at),
        state=row.state, report=report,
        steps=tuple(plan.Step(d["family"], d["direction"], d["mechanism"], tuple(d["workloads"])) for d in data.get("steps", [])),
        approved_by=row.approved_by, entered_at=row.entered_at, restore_trigger=row.restore_trigger,
        findings=[_to_finding(d) for d in data.get("findings", [])], maintenance_only_state=tuple(data.get("maintenance_only_state", [])),
        escalated=row.escalated, baseline_untrusted=bool(data.get("baseline_untrusted")), history=[{**entry, "at": datetime.fromisoformat(entry["at"])} for entry in data.get("history", [])],
        evidence=dict(data.get("evidence") or {}), plan=dict(data.get("plan") or {}))


def under_maintenance() -> list:
    """The records of every device that must be treated as under maintenance right now."""
    from core import models

    return [load(row) for row in models.MaintenanceRecord.objects.filter(state__in=lifecycle.IN_MAINTENANCE)]


def notices(now: datetime) -> list[dict]:
    """One entry per device under maintenance: the status row plus the warning line the pages show."""
    records = under_maintenance()
    return [{**visibility.status(record, now=now), "warning": visibility.device_warning(records, record.request.device)} for record in records]


def prior_unresolved(device: str, intersects=None) -> tuple[str, ...]:
    """Stored form of ``lifecycle.unresolved``: what ``gates.Facts.prior_unresolved`` must be given before an entry."""
    from core import models

    return lifecycle.unresolved([load(row) for row in models.MaintenanceRecord.objects.exclude(state__in=lifecycle.RESOLVED)], device=device, intersects=intersects)


def start_due_restores(now: datetime) -> list:
    """Move every ACTIVE record whose 7-day safety deadline has passed to RESTORING (trigger DEADLINE).  -> the rows moved.
    This only records that the restore workflow is owed; it restores nothing and touches no device."""
    from core import models

    moved = []
    for row in models.MaintenanceRecord.objects.filter(state=lifecycle.ACTIVE, deadline_at__lte=now):
        record = load(row)
        if record.on_deadline(now=now):
            moved.append(save(record, row))
    return moved
