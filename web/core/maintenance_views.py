"""Maintenance Mode pages.

GET pages are read-only: they read the database and the tracked topology files and contact NO device.  Every POST is an
explicit, confirmed, CSRF-protected operator action, authorized by the one route table (``identity.policy``):

    request a maintenance                       EDIT        application state only
    evaluate readiness (queued)                 VALIDATE    the worker observes the network, read-only
    approve the plan (by its hash)              APPROVE     application state only
    cancel before entry                         EDIT        application state only
    enter maintenance (queued)                  EXECUTE     the worker drains the device
    restore (queued)                            EXECUTE     the worker restores the device

The browser never supplies a device state, a plan, an operation, a time or a digest to trust: only the record, the plan
hash it was shown (a staleness guard) and the confirmation.  The device-contacting steps are queued for the worker
(``manage.py maintenance_tick``): a drain holds the core covers for minutes and must not live inside a web request.
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta
from urllib.parse import urlencode

from django.http import Http404
from django.shortcuts import redirect, render
from django.urls import reverse
from django.utils import timezone
from django.views.decorators.http import require_GET, require_http_methods, require_POST

from . import models
from .services.health import thresholds
from .services.identity import audit, policy
from .services.maintenance_mode import collector, evidence, lifecycle, model, plan, readiness, service, store, visibility

MAX_REASON = 500
MAX_HOURS = 24 * 365                    # a typing guard only; the requested duration is never capped to the safety cycle

TONE = {lifecycle.REQUESTED: "neutral", lifecycle.BLOCKED: "danger", lifecycle.READY: "info", lifecycle.PLANNED: "info", lifecycle.APPROVED: "warning",
        lifecycle.ENTERING: "warning", lifecycle.ACTIVE: "warning", lifecycle.RESTORING: "warning", lifecycle.RESTORED: "success",
        lifecycle.ABORTED_RESTORED: "success", lifecycle.RESTORE_FAILED: "danger", lifecycle.CANCELLED: "neutral"}
VERDICT_TONE = {readiness.CLEAR: "success", readiness.DRAINABLE: "info", readiness.BLOCKED: "danger", readiness.IRRELEVANT: "neutral"}

NOTICES = {
    "REQUESTED": ("success", "Maintenance requested. Queue a readiness evaluation to observe the network (read-only)."),
    "EVALUATE_QUEUED": ("success", "Readiness evaluation queued. The worker observes the network (read-only) within about a minute; reload this page."),
    "APPROVED": ("success", "Plan approved. Entry may now be queued; it is refused if the facts the plan was built from have changed."),
    "ENTER_QUEUED": ("warning", "Entry queued. The worker re-observes, rebuilds and compares the plan, runs every gate and only then drains the device."),
    "RESTORE_QUEUED": ("warning", "Restore queued. The worker restores the captured pre-maintenance state and verifies it before calling the device restored."),
    "CANCELLED": ("success", "Maintenance cancelled before entry. Nothing was written to any device."),
    "CONFIRM_REQUIRED": ("danger", "Nothing was done: the explicit confirmation was missing or did not repeat the maintenance id."),
    "REFUSED": ("danger", "Nothing was done: the step was refused."),
}


def _actor(request) -> str:
    return audit.actor_for(request)


def _row_or_404(record_id):
    try:
        return service._row(record_id)
    except model.MaintenanceError:
        raise Http404("Unknown maintenance") from None


def _back(row, page: str = "maintenance_detail", **query):
    target = reverse(f"core:{page}", args=[row.record_id])
    return redirect(f"{target}?{urlencode(query)}" if query else target)


_CODE = re.compile(r"[A-Z][A-Z0-9_]{2,63}")


def _refused(row, error: model.MaintenanceError, page: str = "maintenance_detail"):
    """Only the stable refusal code travels in the URL (never free text a crafted link could put on an NMAS page); the
    findings of a refused entry are read from the record itself."""
    return _back(row, page, notice="REFUSED", code=error.code)


def _notice(request) -> dict | None:
    key = request.GET.get("notice", "")
    if key not in NOTICES:
        return None
    tone, text = NOTICES[key]
    code = request.GET.get("code", "")
    return {"tone": tone, "text": text, "code": code if _CODE.fullmatch(code) else ""}


def _common(request, row, record, title: str) -> dict:
    now = timezone.now()
    return {
        "page_title": title, "page_key": "automation", "row": row, "record": record, "status": visibility.status(record, now=now),
        "tone": TONE.get(record.state, "neutral"), "actions": policy.user_actions(request.user), "notice": _notice(request), "now": now,
        "can": {"evaluate": record.state in service.QUEUE_STATES[service.EVALUATE], "approve": record.state == lifecycle.PLANNED and row.plan_status == plan.CURRENT,
                "cancel": record.state in (lifecycle.REQUESTED, lifecycle.BLOCKED, lifecycle.READY, lifecycle.PLANNED, lifecycle.APPROVED),
                "enter": record.state == lifecycle.APPROVED and row.plan_status == plan.CURRENT,
                "restore": record.state in service.QUEUE_STATES[service.RESTORE]},
        "busy": bool(row.queued_action or row.claim_token),
    }


def _tracked_scope() -> dict:
    """The writable managed scope and, per device, what the tracked cabling says hangs off it.  Reads files and the
    (cached) NetBox scope; contacts no device.  The readiness evaluation confirms it from the devices."""
    runtime = service.production_runtime()
    topo, devices = runtime.sources.topology, sorted(runtime.scope())
    rows = []
    for name in devices:
        if name not in topo.devices:
            continue
        rows.append({"device": name, "neighbours": sorted(n for n in topo.production_neighbours(name) if n in topo.devices),
                     "single_homed": list(topo.single_homed(name)), "management_cut": list(topo.cut_off_from_management(name)),
                     "management_switch": name in topo.management})
    return {"devices": devices, "rows": rows, "out_of_scope": sorted(set(topo.devices) - set(devices))}


# ------------------------------------------------------------------------------------------------------------------- pages
@require_GET
def maintenance_list(request):
    rows = list(models.MaintenanceRecord.objects.all()[:300])
    groups = {"active": [], "pending": [], "blocked": [], "historical": []}
    for row in rows:
        key = ("active" if row.state in lifecycle.IN_MAINTENANCE else "blocked" if row.state == lifecycle.BLOCKED
               else "historical" if row.state in lifecycle.RESOLVED else "pending")
        groups[key].append({"row": row, "tone": TONE.get(row.state, "neutral")})
    return render(request, "core/maintenance/list.html", {"page_title": "Maintenance Mode", "page_key": "automation", "groups": groups,
                                                         "actions": policy.user_actions(request.user), "cycle_days": model.MAINTENANCE_CYCLE.days})


@require_http_methods(["GET", "POST"])
def maintenance_request(request):
    """GET: the request form.  POST (EDIT): create the record; nothing is observed or contacted."""
    error, values = None, {"device": "", "reason": "", "hours": ""}
    if request.method == "POST":
        values = {key: request.POST.get(key, "").strip() for key in values}
        try:
            hours = float(values["hours"])
        except ValueError:
            hours = 0.0
        if not 0 < hours <= MAX_HOURS:
            error = "The requested duration must be a positive number of hours."
        elif not values["reason"] or len(values["reason"]) > MAX_REASON:
            error = f"A reason of at most {MAX_REASON} characters is required."
        else:
            try:
                row = service.request(values["device"], _actor(request), values["reason"], timedelta(hours=hours), now=timezone.now(),
                                      runtime=service.production_runtime())
                return _back(row, notice="REQUESTED")
            except model.MaintenanceError as refused:
                error = str(refused)
    try:
        scope, scope_error = _tracked_scope(), ""
    except Exception as exc:  # noqa: BLE001 - the form is still shown; the request itself is refused fail-closed
        scope, scope_error = {"devices": [], "rows": [], "out_of_scope": []}, type(exc).__name__
    return render(request, "core/maintenance/request.html", {"page_title": "Request maintenance", "page_key": "automation", "scope": scope,
                                                            "scope_error": scope_error, "error": error, "values": values, "max_reason": MAX_REASON,
                                                            "cycle_days": model.MAINTENANCE_CYCLE.days})


@require_GET
def maintenance_detail(request, record_id):
    """The overview and, while in maintenance, the active page: timings, state, affected dependencies, actions."""
    row = _row_or_404(record_id)
    record = store.load(row)
    context = _common(request, row, record, f"{row.record_id} · {row.device_name}")
    context["dependencies"] = (record.plan.get("affected") or {}).get("dependencies") or (record.evidence.get("observation") or {}).get("dependencies") or []
    context["intersects"] = (record.plan.get("baseline") or {}).get("intersects") or (record.evidence.get("observation") or {}).get("intersects") or []
    context["entry"] = record.evidence.get("entry") or {}
    context["restore"] = record.evidence.get("restore") or {}
    context["verification"] = record.evidence.get("restore_verification") or {}
    context["chain"] = evidence.verify(row)
    context["evidence_count"] = len(evidence.entries(row))
    context["locks"] = list(models.ExecutionDeviceLock.objects.filter(maintenance=row).values_list("device", flat=True))
    return render(request, "core/maintenance/detail.html", context)


@require_GET
def maintenance_readiness(request, record_id):
    row = _row_or_404(record_id)
    record = store.load(row)
    context = _common(request, row, record, f"{row.record_id} · readiness")
    observation = record.evidence.get("observation") or {}
    context["observation"] = observation
    context["cells"] = [{"key": f"{family}/{direction}", "family": family, "direction": direction, **cell, "tone": VERDICT_TONE.get(cell["verdict"], "neutral")}
                        for (family, direction), cell in (record.report.cells.items() if record.report else ())]
    context["flows"] = [{**flow, "tone": VERDICT_TONE.get(flow["verdict"], "neutral")}
                        for flow in (readiness.flow_rows(record.report, observation) if record.report and observation else [])]
    context["blockers"] = [f.text() for f in (record.report.blockers if record.report else [])]
    context["notes"] = [f.text() for f in (record.report.notes if record.report else [])]
    try:
        limits = thresholds.load_thresholds()["freshness"]
    except Exception:  # noqa: BLE001 - freshness is then UNKNOWN, never FRESH
        limits = None
    fresh = collector.freshness(observation, now=context["now"], thresholds=limits) if observation and limits else {}
    context["provenance"] = [{"device": name, **row_, "freshness": fresh.get(name, "UNKNOWN")} for name, row_ in sorted((observation.get("provenance") or {}).items())]
    return render(request, "core/maintenance/readiness.html", context)


@require_GET
def maintenance_plan(request, record_id):
    row = _row_or_404(record_id)
    record = store.load(row)
    context = _common(request, row, record, f"{row.record_id} · plan")
    context["plan"] = record.plan
    context["expired"] = bool(record.plan) and context["now"] > datetime.fromisoformat(record.plan["valid_until"])
    return render(request, "core/maintenance/plan.html", context)


@require_GET
def maintenance_history(request, record_id):
    row = _row_or_404(record_id)
    record = store.load(row)
    context = _common(request, row, record, f"{row.record_id} · history")
    context["entries"] = evidence.entries(row)
    context["chain"] = evidence.verify(row)
    context["history"] = list(reversed(record.history))
    return render(request, "core/maintenance/history.html", context)


# ------------------------------------------------------------------------------------------------------------------ actions
def _confirmed(request, row) -> bool:
    return request.POST.get("confirm") == "on" and request.POST.get("confirm_id", "").strip().upper() == row.record_id


@require_POST
def maintenance_evaluate(request, record_id):
    row = _row_or_404(record_id)
    if request.POST.get("confirm") != "on":
        return _back(row, notice="CONFIRM_REQUIRED")
    try:
        service.queue(row.pk, service.EVALUATE, _actor(request), now=timezone.now())
    except model.MaintenanceError as refused:
        return _refused(row, refused)
    return _back(row, notice="EVALUATE_QUEUED")


@require_POST
def maintenance_approve(request, record_id):
    row = _row_or_404(record_id)
    if request.POST.get("confirm") != "on":
        return _back(row, "maintenance_plan", notice="CONFIRM_REQUIRED")
    try:
        service.approve(row.pk, _actor(request), now=timezone.now(), plan_hash=request.POST.get("plan_hash", ""))
    except model.MaintenanceError as refused:
        return _refused(row, refused, "maintenance_plan")
    return _back(row, "maintenance_plan", notice="APPROVED")


@require_POST
def maintenance_cancel(request, record_id):
    row = _row_or_404(record_id)
    if not _confirmed(request, row):
        return _back(row, notice="CONFIRM_REQUIRED")
    try:
        service.cancel(row.pk, _actor(request), now=timezone.now())
    except model.MaintenanceError as refused:
        return _refused(row, refused)
    return _back(row, notice="CANCELLED")


@require_POST
def maintenance_enter(request, record_id):
    row = _row_or_404(record_id)
    if not _confirmed(request, row):
        return _back(row, "maintenance_plan", notice="CONFIRM_REQUIRED")
    try:
        service.queue(row.pk, service.ENTER, _actor(request), now=timezone.now(), plan_hash=request.POST.get("plan_hash", ""))
    except model.MaintenanceError as refused:
        return _refused(row, refused, "maintenance_plan")
    return _back(row, notice="ENTER_QUEUED")


@require_POST
def maintenance_restore(request, record_id):
    row = _row_or_404(record_id)
    if not _confirmed(request, row):
        return _back(row, notice="CONFIRM_REQUIRED")
    try:
        service.queue(row.pk, service.RESTORE, _actor(request), now=timezone.now())
    except model.MaintenanceError as refused:
        return _refused(row, refused)
    return _back(row, notice="RESTORE_QUEUED")
