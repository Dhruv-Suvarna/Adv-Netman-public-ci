"""Append-only run history: ONE ``OperationalCheckRun`` model for every mode, with bounded, sanitized reports.

Only normalized facts and check results are stored -- never raw command output, credentials, or unbounded lists.  An
explicit run also records ONE ``AuditEvent`` (actor, mode, scope, run id, status); passive page views never do.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime

from django.db import transaction

from ... import models
from .. import secret_policy
from .codes import ENGINE_VERSION, REPORT_SCHEMA_VERSION, Mode
from .results import MAX_REPORT_BYTES, bound, bounded_results, count_by_status, utcnow

MAX_HISTORY = 10

_AUDIT_TYPE = {
    Mode.FLEET_QUICK: models.AuditEventType.HEALTH_RUN_RECORDED,
    Mode.DEVICE_DEEP: models.AuditEventType.HEALTH_RUN_RECORDED,
    Mode.CHANGE_PRECHECK: models.AuditEventType.PRECHECK_RECORDED,
    Mode.CHANGE_POSTCHECK: models.AuditEventType.POSTCHECK_RECORDED,
}


def build_report(mode: str, status: str, results, extra: dict) -> tuple[dict, dict]:
    """(report, summary): sanitized, bounded, deterministic.  Optional heavy sections are dropped first if too large."""
    rows, truncated = bounded_results(results)
    counts = count_by_status(results)
    report = {
        "report_schema_version": REPORT_SCHEMA_VERSION, "engine_version": ENGINE_VERSION, "mode": mode, "status": status,
        "counts": counts, "results": rows, "results_truncated": truncated, **{k: bound(v) if k != "results" else v for k, v in extra.items()},
    }
    for droppable in ("evidence", "facts", "fleet_devices"):
        if len(json.dumps(report, default=str)) <= MAX_REPORT_BYTES:
            break
        report.pop(droppable, None)
        report["truncated_sections"] = [*report.get("truncated_sections", []), droppable]
    if len(json.dumps(report, default=str)) > MAX_REPORT_BYTES:  # last resort: keep only the most severe results
        report["results"] = report["results"][:50]
        report["results_truncated"] = True
    summary = {"counts": counts, "results": len(results), "results_truncated": truncated}
    summary.update({k: v for k, v in extra.get("summary", {}).items()} if isinstance(extra.get("summary"), dict) else {})
    return report, summary


def record_run(*, mode: str, status: str, results, extra: dict | None = None, actor: str = "", device: str = "", change=None,
               plan=None, started_at: datetime | None = None) -> models.OperationalCheckRun:
    extra = dict(extra or {})
    report, summary = build_report(mode, status, results, extra)
    secret_policy.assert_no_secret_shaped_keys(report, context="Operational run report")
    finished = utcnow()
    with transaction.atomic():
        run = models.OperationalCheckRun.objects.create(
            mode=mode, status=status, device=device, change=change, plan=plan, engine_version=ENGINE_VERSION,
            started_at=started_at or finished, finished_at=finished, created_by=actor, summary=summary, report=report,
        )
        scope = device or (change.change_id if change is not None else "FLEET")
        models.AuditEvent.objects.create(
            event_type=_AUDIT_TYPE[mode], change=change, object_type="OperationalCheckRun", object_id=str(run.run_id), actor=actor,
            summary=f"{scope}: {mode} {status}"[:255],
            metadata={"run_id": str(run.run_id), "mode": mode, "status": status, "device": device, "scope": scope,
                      "plan_id": str(plan.plan_id) if plan is not None else "", "counts": summary["counts"]},
        )
    return run


def get_run(run_id) -> models.OperationalCheckRun | None:
    try:
        parsed = uuid.UUID(str(run_id))
    except ValueError:
        return None
    return models.OperationalCheckRun.objects.filter(run_id=parsed).select_related("change", "plan").first()


def recent_runs(*, mode: str | None = None, device: str | None = None, change=None, limit: int = MAX_HISTORY) -> list:
    queryset = models.OperationalCheckRun.objects.all()
    if mode:
        queryset = queryset.filter(mode=mode)
    if device:
        queryset = queryset.filter(device=device)
    if change is not None:
        queryset = queryset.filter(change=change)
    return list(queryset.select_related("change")[: max(1, min(int(limit), 50))])


def latest_run(*, mode: str, device: str | None = None, change=None) -> models.OperationalCheckRun | None:
    rows = recent_runs(mode=mode, device=device, change=change, limit=1)
    return rows[0] if rows else None


def serialize_health_run(run: models.OperationalCheckRun) -> dict:
    """Sanitized machine-readable document for a stored run (safe for the UI and a JSON download)."""
    return bound_document({
        "run_id": str(run.run_id), "mode": run.mode, "status": run.status, "device": run.device,
        "change_id": run.change.change_id if run.change_id else "", "plan_id": str(run.plan.plan_id) if run.plan_id else "",
        "engine_version": run.engine_version, "started_at": run.started_at.isoformat(), "finished_at": run.finished_at.isoformat(),
        "created_by": run.created_by, "summary": run.summary, "report": run.report,
    })


def bound_document(document: dict) -> dict:
    """Second-line redaction of secret-shaped keys anywhere in a stored document (values were sanitized on write)."""
    from .results import _secret_key

    def walk(value):
        if isinstance(value, dict):
            return {k: ("[REDACTED]" if _secret_key(k) else walk(v)) for k, v in value.items()}
        if isinstance(value, list):
            return [walk(item) for item in value]
        return value

    return walk(document)
