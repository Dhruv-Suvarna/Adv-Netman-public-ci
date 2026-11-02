"""What an operator sees of a maintenance: one status row per record, and the warning the Device Builder and the
Automation pages show for a device that is under maintenance.  Plain values; the pages only render them."""

from __future__ import annotations

from datetime import datetime

from . import lifecycle


def status(record: lifecycle.Record, *, now: datetime) -> dict:
    request, deadline = record.request, record.cycle_deadline
    blocked = [finding.text() for finding in record.findings]
    return {
        "device": request.device, "state": record.state, "requested_by": request.operator, "reason": request.reason,
        "requested_at": request.requested_at, "requested_duration_seconds": int(request.requested_duration.total_seconds()),
        "approved_by": record.approved_by, "under_maintenance": record.state in lifecycle.IN_MAINTENANCE,
        "readiness": None if record.report is None else ("READY" if record.report.ready else "BLOCKED"),
        "block_reasons": blocked, "entered_at": record.entered_at, "requested_until": record.requested_until,
        "past_requested_window": bool(record.requested_until and record.state == lifecycle.ACTIVE and now >= record.requested_until),
        "cycle_deadline": deadline, "overdue": bool(deadline and record.state == lifecycle.ACTIVE and now >= deadline),
        "restore": {"trigger": record.restore_trigger, "state": record.state if record.state in
                    (lifecycle.RESTORING, lifecycle.RESTORED, lifecycle.ABORTED_RESTORED, lifecycle.RESTORE_FAILED) else "",
                    "escalated": record.escalated, "baseline_untrusted": record.baseline_untrusted, "remaining": list(record.maintenance_only_state)},
    }


def device_warning(records, device: str) -> str:
    """'' unless ``device`` is under maintenance; otherwise one line for a page that is about to change the device."""
    for record in records:
        if record.request.device == device and record.state in lifecycle.IN_MAINTENANCE:
            request = record.request
            text = f"{device} is under maintenance ({record.state}), requested by {request.operator}: {request.reason}."
            if record.state == lifecycle.RESTORE_FAILED:
                text += " Its restore was not completed and is escalated; do not change this device until that is resolved."
            elif record.cycle_deadline is not None:
                text += f" Requested until {record.requested_until.isoformat()}; safety deadline {record.cycle_deadline.isoformat()}."
            return text
    return ""
