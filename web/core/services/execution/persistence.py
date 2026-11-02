"""Append-oriented execution history: run + per-Configlet results, audit events, notifications, serialization.

Only bounded, sanitized, secret-free facts are stored: fixed error CODES (never device text or exception text), Configlet
identifiers, bounded previous-state facts.  Every JSON payload passes the shared ``secret_policy``.  A run and each result
are created when work STARTS (write-ahead, so an interruption is visible) and finalised exactly once.
"""

from __future__ import annotations

import json
from datetime import datetime

from django.db import transaction
from django.utils import timezone

from ... import models
from .. import secret_policy
from .codes import ENGINE_VERSION, OUTCOME_PRESENTATION, REPORT_SCHEMA_VERSION, SUCCESS_OUTCOMES, Outcome, Phase, Status, error_message

MAX_HISTORY = 25
_CONFIGLET_STATUS = {
    Status.APPLIED: models.ConfigletExecutionStatus.DEPLOYED,
    Status.ALREADY_SATISFIED: models.ConfigletExecutionStatus.DEPLOYED,
    Status.FAILED: models.ConfigletExecutionStatus.FAILED,
    Status.UNKNOWN: models.ConfigletExecutionStatus.FAILED,
    Status.COMPENSATED: models.ConfigletExecutionStatus.ROLLED_BACK,
}


def _safe(value, context):
    return secret_policy.assert_no_secret_shaped_keys(value, context=context)


# --- results -------------------------------------------------------------------------------------------------------------
def start_result(run, spec, phase: str, *, previous_state: dict | None = None, now: datetime | None = None):
    now = now or timezone.now()
    facts = dict(previous_state or {})
    if spec.origin == "RAW":  # Phase 18: the history references the EXACT pinned revision, whatever the executor recorded
        facts["raw"] = dict(spec.raw or {})
    return models.ConfigletExecutionResult.objects.create(
        run=run, configlet_id=spec.pk, cfg_id=spec.cfg_id, sequence=spec.sequence, device=spec.device, object_type=spec.object_type,
        operation=spec.operation, phase=phase, status=Status.IN_PROGRESS, started_at=now,
        previous_state=_safe(facts, "Execution previous state"),
    )


def finish_result(result, status: str, *, error_code: str = "", partial_effects: bool = False, lines_sent: int = 0,
                  detail: dict | None = None, now: datetime | None = None):
    now = now or timezone.now()
    result.status, result.error_code, result.partial_effects, result.lines_sent = status, error_code, partial_effects, lines_sent
    result.finished_at = now
    result.detail = _safe(dict(detail or {}), "Execution result detail")
    result.save()
    mirrored = _CONFIGLET_STATUS.get(status)
    if mirrored is not None and result.configlet_id:
        # the Configlet's own (writable) execution field mirrors the LATEST attempt; the run's results are the history
        models.Configlet.objects.filter(pk=result.configlet_id).update(execution_status=mirrored, updated_at=now)
    return result


def record_previous_state(run, spec, previous_state: dict, *, strategy: str, now: datetime | None = None) -> None:
    """Replace the Phase-14 ``UNKNOWN_DEFERRED`` marker with a REFERENCE to the captured, evidence-backed previous state."""
    if spec.pk is None:
        return
    now = now or timezone.now()
    reference = _safe({"status": "CAPTURED", "run_id": str(run.run_id), "strategy": strategy, "captured_at": now.isoformat(),
                       "facts": previous_state}, "Configlet previous state")
    models.Configlet.objects.filter(pk=spec.pk).update(previous_state_ref=reference, updated_at=now)


def add_not_attempted(run, specs, *, now: datetime | None = None) -> None:
    now = now or timezone.now()
    for spec in specs:
        models.ConfigletExecutionResult.objects.get_or_create(
            run=run, sequence=spec.sequence, phase=Phase.APPLY,
            defaults=dict(configlet_id=spec.pk, cfg_id=spec.cfg_id, device=spec.device, object_type=spec.object_type, operation=spec.operation,
                          status=Status.NOT_ATTEMPTED, started_at=now, finished_at=now),
        )


# --- run finalisation ------------------------------------------------------------------------------------------------------
def _audit_metadata(run, outcome: str, report: dict) -> dict:
    state = report.get("state") or {}
    return {
        "run_id": str(run.run_id), "stage": "FINISHED", "mode": run.mode, "outcome": outcome, "plan_id": str(run.plan.plan_id),
        "plan_hash": run.plan_hash, "devices": list(run.devices), "applied": state.get("applied", []), "failed": state.get("failed", []),
        "unapplied": state.get("unapplied", []), "compensated": state.get("compensated", []),
        "compensation": (report.get("compensation") or {}).get("status", "NOT_ATTEMPTED"),
        "postcheck": (report.get("postcheck") or {}).get("result", "NOT_RUN"),
        "raw_configlets": [{k: r.get(k) for k in ("cfg_id", "raw_id", "revision", "content_hash")} for r in report.get("raw_configlets", [])],
    }


def finalize_run(run, *, outcome: str, report: dict, postcheck_run=None, now: datetime | None = None):
    """RUNNING -> FINISHED exactly once; frees every device lock; writes the audit trail.  One transaction."""
    now = now or timezone.now()
    state = report.get("state") or {}
    summary = {
        "outcome": outcome, "applied": len(state.get("applied", [])), "failed": len(state.get("failed", [])),
        "unapplied": len(state.get("unapplied", [])), "compensated": len(state.get("compensated", [])),
        "devices": len(run.devices), "compensation": (report.get("compensation") or {}).get("status", "NOT_ATTEMPTED"),
        "postcheck": (report.get("postcheck") or {}).get("result", "NOT_RUN"),
    }
    _safe(report, "Execution report")
    with transaction.atomic():
        run.state, run.outcome, run.finished_at = models.ExecutionRunState.FINISHED, outcome, now
        run.report, run.summary, run.postcheck_run = report, summary, postcheck_run
        run.save()
        run.device_locks.all().delete()
        change = run.change
        models.AuditEvent.objects.create(
            event_type=models.AuditEventType.DEPLOYMENT_RECORDED, change=change, object_type="ChangeExecutionRun", object_id=str(run.run_id),
            actor=run.actor, summary=f"{change.change_id}: {run.mode} execution {str(run.run_id)[:8]} {outcome}"[:255],
            metadata=_safe(_audit_metadata(run, outcome, report), "Execution audit"),
        )
        comp = report.get("compensation") or {}
        if comp.get("attempted"):
            models.AuditEvent.objects.create(
                event_type=models.AuditEventType.ROLLBACK_RECORDED, change=change, object_type="ChangeExecutionRun", object_id=str(run.run_id),
                actor=run.actor, summary=f"{change.change_id}: compensation {comp.get('status')} for execution {str(run.run_id)[:8]}"[:255],
                metadata=_safe({"run_id": str(run.run_id), "status": comp.get("status"), "compensated": state.get("compensated", []),
                                "not_compensated": comp.get("not_compensated", [])}, "Compensation audit"),
            )
    return run


def record_blocked(change, plan, *, precheck_run, mode: str, actor: str, blockers: list, scope=None, now: datetime | None = None):
    """A refused attempt: an append-only, already-FINISHED BLOCKED run when a plan exists, else an audit event only."""
    now = now or timezone.now()
    codes = [b["code"] for b in blockers]
    with transaction.atomic():
        run = None
        if plan is not None:
            run = models.ChangeExecutionRun.objects.create(
                change=change, plan=plan, validation_run=plan.validation_run, precheck_run=precheck_run, mode=mode, actor=actor,
                state=models.ExecutionRunState.FINISHED, outcome=Outcome.BLOCKED, engine_version=ENGINE_VERSION, plan_hash=plan.plan_hash,
                validation_input_hash=plan.validation_input_hash, validation_source_hash=plan.validation_source_hash,
                scope=scope.to_dict() if scope is not None else {}, devices=scope.devices if scope is not None else [],
                started_at=now, finished_at=now, lease_expires_at=now, summary={"outcome": Outcome.BLOCKED, "blockers": codes},
                report=_safe({"report_schema_version": REPORT_SCHEMA_VERSION, "engine_version": ENGINE_VERSION, "mode": mode,
                              "outcome": Outcome.BLOCKED, "blockers": blockers, "state": {"applied": [], "failed": [], "unapplied": [], "compensated": []}},
                             "Blocked execution report"),
            )
        models.AuditEvent.objects.create(
            event_type=models.AuditEventType.DEPLOYMENT_RECORDED, change=change, object_type="ChangeExecutionRun",
            object_id=str(run.run_id) if run else "", actor=actor,
            summary=f"{change.change_id}: {mode} execution BLOCKED ({', '.join(codes[:4])})"[:255],
            metadata=_safe({"stage": "BLOCKED", "mode": mode, "outcome": Outcome.BLOCKED, "blockers": codes,
                            "run_id": str(run.run_id) if run else ""}, "Blocked execution audit"),
        )
    return run


# --- notifications (persist first, Slack second; a failure here never corrupts the run) -----------------------------------
_NOTIFICATION = {
    Outcome.SUCCEEDED: ("DEPLOYMENT_SUCCEEDED", "SUCCESS"),
    Outcome.UAT_SCOPE_APPLIED: ("UAT_PARTIAL", "INFO"),
    Outcome.UAT_SCOPE_APPLIED_UNVERIFIED: ("UAT_PARTIAL", "WARNING"),
    Outcome.UAT_SCOPE_APPLIED_POSTCHECK_FAILED: ("UAT_PARTIAL", "ERROR"),
    Outcome.FAILED_PARTIAL_APPLIED: ("DEPLOYMENT_FAILED", "ERROR"),
    Outcome.FAILED_NO_MUTATION: ("DEPLOYMENT_FAILED", "ERROR"),
    Outcome.FAILED_ROLLED_BACK: ("ROLLBACK_SUCCEEDED", "WARNING"),
    Outcome.POSTCHECK_FAILED_ROLLED_BACK: ("ROLLBACK_SUCCEEDED", "WARNING"),
    Outcome.FAILED_COMPENSATION_INCOMPLETE: ("ROLLBACK_FAILED", "CRITICAL"),
    Outcome.POSTCHECK_FAILED_COMPENSATION_INCOMPLETE: ("ROLLBACK_FAILED", "CRITICAL"),
    Outcome.INTERRUPTED: ("DEPLOYMENT_FAILED", "CRITICAL"),
}


def default_notifier(**kwargs):
    from .. import notification_service

    return notification_service.publish_event(**kwargs)


def notify_outcome(run, notifier=None) -> bool:
    """Publish one notification for a finished run (BLOCKED refusals are shown immediately and are not published)."""
    mapping = _NOTIFICATION.get(run.outcome)
    if mapping is None:
        return False
    event_type, severity = mapping
    state = (run.report or {}).get("state") or {}
    devices = list(run.devices)
    try:
        (notifier or default_notifier)(
            event_type=event_type, severity=severity, title=f"{run.change.change_id}: {run.get_outcome_display()}",
            message=OUTCOME_PRESENTATION[run.outcome][1], source="execution", device=devices[0] if len(devices) == 1 else "",
            change_id=run.change.change_id, lifecycle_state=run.change.lifecycle_state,
            metadata={"run_id": str(run.run_id), "mode": run.mode, "outcome": run.outcome, "applied": len(state.get("applied", [])),
                      "failed": len(state.get("failed", [])), "unapplied": len(state.get("unapplied", []))},
            correlation_key=f"execution:{run.run_id}",
        )
        return True
    except Exception:  # noqa: BLE001 - notification failure must never affect the primary (already committed) execution record
        return False


# --- reads ---------------------------------------------------------------------------------------------------------------
def get_run(change, run_id):
    import uuid

    try:
        parsed = uuid.UUID(str(run_id))
    except ValueError:
        return None
    return change.execution_runs.filter(run_id=parsed).select_related("plan", "validation_run", "precheck_run", "postcheck_run").first()


def list_runs(change, *, limit: int = MAX_HISTORY):
    return list(change.execution_runs.select_related("plan").order_by("-started_at", "-id")[:limit])


def latest_run(change):
    return change.execution_runs.order_by("-started_at", "-id").first()


def _result_row(result) -> dict:
    return {
        "cfg_id": result.cfg_id, "sequence": result.sequence, "device": result.device, "object_type": result.object_type,
        "operation": result.operation, "phase": result.phase, "status": result.status, "error_code": result.error_code,
        "error": error_message(result.error_code) if result.error_code else "", "partial_effects": result.partial_effects,
        "lines_sent": result.lines_sent, "started_at": result.started_at.isoformat(),
        "finished_at": result.finished_at.isoformat() if result.finished_at else None,
        "previous_state": result.previous_state, "detail": result.detail,
    }


def serialize_run(run) -> dict:
    """Sanitized, bounded, machine-readable run (safe for the UI and a JSON download).  Secret-shaped keys are replaced."""
    from ..validation.findings import _secret_key

    rows = [_result_row(r) for r in run.results.all()]
    document = {
        "report_schema_version": REPORT_SCHEMA_VERSION, "engine_version": run.engine_version, "run_id": str(run.run_id),
        "change_id": run.change.change_id, "plan_id": str(run.plan.plan_id), "plan_hash": run.plan_hash,
        "validation_run_id": str(run.validation_run.run_id), "validation_input_hash": run.validation_input_hash,
        "validation_source_hash": run.validation_source_hash,
        "precheck_run_id": str(run.precheck_run.run_id) if run.precheck_run_id else "",
        "postcheck_run_id": str(run.postcheck_run.run_id) if run.postcheck_run_id else "",
        "mode": run.mode, "state": run.state, "outcome": run.outcome, "outcome_summary": OUTCOME_PRESENTATION.get(run.outcome, ("", ""))[1],
        "actor": run.actor, "started_at": run.started_at.isoformat(), "finished_at": run.finished_at.isoformat() if run.finished_at else None,
        "scope": run.scope, "devices": run.devices, "summary": run.summary, "results": rows, "report": run.report,
    }

    def walk(value):
        if isinstance(value, dict):
            return {k: ("[REDACTED]" if _secret_key(k) else walk(v)) for k, v in value.items()}
        if isinstance(value, list):
            return [walk(item) for item in value]
        return value

    return walk(document)


def report_filename(run) -> str:
    return f"{run.change.change_id}-execution-{str(run.run_id)[:8]}.json"


def report_json(run) -> str:
    return json.dumps(serialize_run(run), indent=2, sort_keys=True, default=str) + "\n"


def is_success(run) -> bool:
    return run.outcome in SUCCESS_OUTCOMES
