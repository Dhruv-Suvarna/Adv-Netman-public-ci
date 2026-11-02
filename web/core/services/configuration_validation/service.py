"""Dispatch, tracking, staleness and the execution gate of Configuration Validation.

    on_validation(run)      called by ``change_validation_service.validate_change`` after it stored a Tier-2 run: a PASSING
                            run is sent to GitHub Actions, any other run sends nothing
    refresh(row)            asks GitHub for the state of that one run (by correlation id) and records it
    reconcile(change)       the same for every row of a Change that still owes a result; run by the Change pages, the
                            explicit Refresh action and the ``reconcile`` command.  NMAS polls; GitHub never calls NMAS
    effective_status(row)   the recorded status, or STALE when the Change is no longer the snapshot that was tested
    gate(change, ...)       the execution blocker, or None when the latest matching run is PASS for the current candidate

A dispatch never blocks the request for longer than one bounded API call and never raises into the validation that
triggered it: a GitHub outage is recorded on the row (ERROR / NOT_TRIGGERED) and the gate then refuses execution.
"""

from __future__ import annotations

import uuid
from datetime import timedelta

from django.conf import settings
from django.db import transaction
from django.utils import timezone

from ... import models
from .. import candidate_renderer
from ..bundles.legacy_sanitize import SanitizeError, sanitize_config
from ..validation import snapshot as snapshot_module
from . import bundle as bundle_module
from . import checks, github

S = models.ConfigurationValidationStatus
PASSING_TIER2 = ("PASS", "PASS_WITH_WARNINGS")
PENDING = (S.QUEUED, S.IN_PROGRESS)
MAX_GRAPH_EDGES = 400
RUN_APPEARS_WITHIN = timedelta(minutes=15)         # a dispatch whose run never shows up is an error, not "queued" for ever
# The deliberate failure a demonstration bundle carries: the protected management VLAN removed from one device.
DEMONSTRATION_VIOLATION = ("no interface Vlan200",)


def enabled() -> bool:
    return bool(getattr(settings, "NMAS_CONFIGURATION_VALIDATION_ENABLED", True))


def exempt(change) -> str:
    """Why ``change`` is outside Configuration Validation, or ''.  ONE narrow case: a controlled routing transition
    (``route_shield.lifecycle``).  It has its own validation, precheck and executor, the general execution engine
    refuses it outright (TRANSITION_CHANGE_NOT_GENERIC), and it is not a candidate the device renderers produce."""
    kind = ((change.metadata or {}).get("transition") or {}).get("kind")
    return f"routing transition {kind}: validated and executed by its own workflow" if kind else ""


# ------------------------------------------------------------------------------------------------------------------- bundle
def _scope_facts(change, input_hash: str) -> dict:
    run = change.network_config_validation_runs.filter(input_hash=input_hash).order_by("-created_at", "-id").first()
    for check in (run.checks if run is not None else None) or []:
        if check.get("check") == "MANAGED_SCOPE":
            evidence = check.get("evidence") or {}
            return {"check": check.get("status", ""), "outside_scope": list(evidence.get("outside_scope") or []),
                    "provisioning": list(evidence.get("provisioning") or []), "nmas_active": list(evidence.get("nmas_active") or [])}
    return {"check": "NOT_RECORDED", "outside_scope": [], "provisioning": [], "nmas_active": []}


def build_bundle(change, run, correlation_id) -> dict:
    """The sanitized bundle of ``run``.  Refused when the Change is no longer the snapshot ``run`` validated."""
    snapshot = snapshot_module.build_change_snapshot(change)
    if snapshot_module.hash_snapshot(snapshot) != run.input_hash:
        raise bundle_module.BundleError("CONFIG_VALIDATION_SNAPSHOT_CHANGED", "the Change was edited after this validation run")
    entries = {device["device_name"]: device for device in snapshot.get("devices") or []}
    devices = []
    for intent in change.device_intents.order_by("device_name"):
        revision = intent.latest_revision()
        if revision is None:
            continue
        rendered = candidate_renderer.render(intent, revision)
        try:
            text = sanitize_config(rendered["text"]).text
        except SanitizeError as exc:
            raise bundle_module.BundleError(bundle_module.UNSAFE, f"{intent.device_name}: {exc}") from None
        devices.append({"device": intent.device_name, "platform": intent.platform, "target_type": intent.target_type, "revision": revision.revision,
                        "features": bundle_module.features_of(entries.get(intent.device_name) or {}), "candidate": text,
                        "candidate_sha256": bundle_module.digest(text), "composition_conflicts": len(rendered.get("composition_conflicts") or [])})
    removals = [{"device": r.device_name, "platform": r.platform, "mode": r.mode, "status": r.status, "content_hash": r.content_hash, "features": []}
                for r in change.config_removals.order_by("device_name")]
    findings = (run.report or {}).get("findings") or []
    graph = run.dependency_graph or {}
    edges = graph.get("edges") or []
    truncated = bool(graph.get("truncated")) or len(edges) > MAX_GRAPH_EDGES
    metadata = change.metadata or {}
    return {
        "schema_version": bundle_module.SCHEMA_VERSION, "kind": bundle_module.KIND, "correlation_id": str(correlation_id),
        "change": {"change_id": change.change_id, "category": change.category, "workflow": metadata.get("workflow", ""), "execution_mode": change.execution_mode,
                   "transition_kind": (metadata.get("transition") or {}).get("kind", "")},
        "validation": {"run_id": str(run.run_id), "status": run.status, "engine_version": run.engine_version, "input_hash": run.input_hash,
                       "source_hash": run.source_hash, "repository_sha": run.repository_head, "summary": run.summary,
                       "blocking_findings": sorted({f.get("code", "") for f in findings if f.get("blocking")}),
                       "finding_codes": sorted({f.get("code", "") for f in findings})},
        "snapshot_hash": run.input_hash, "candidate_hash": bundle_module.candidate_hash(devices, removals),
        "targets": sorted(snapshot.get("targets") or []), "devices": devices, "removals": removals, "intent": snapshot,
        "dependencies": {"nodes": [] if truncated else [{"id": node.get("id")} for node in graph.get("nodes") or []],
                         "edges": [] if truncated else [{key: edge.get(key) for key in ("from", "to", "type", "status")} for edge in edges],
                         "cycles": graph.get("cycles") or [], "truncated": truncated},
        "matrix": [{"platform": d["platform"], "feature": feature, "status": checks.matrix_status(d["platform"], feature)} for d in devices for feature in d["features"]],
        "scope": _scope_facts(change, run.input_hash),
    }


# ------------------------------------------------------------------------------------------------------------------ dispatch
def _audit(row, summary: str) -> None:
    models.AuditEvent.objects.create(
        event_type=models.AuditEventType.VALIDATION_RECORDED, change=row.change, object_type="ConfigurationValidationRun", object_id=str(row.correlation_id),
        actor=row.triggered_by, summary=f"{row.change.change_id}: configuration validation {summary}"[:255],
        metadata={"correlation_id": str(row.correlation_id), "status": row.status, "snapshot_hash": row.snapshot_hash, "candidate_hash": row.candidate_hash,
                  "validation_run_id": str(row.validation_run.run_id), "demonstration": row.demonstration})


def dispatch(run, *, actor: str = "", demonstration: bool = False):
    """Send ``run`` (a passing Tier-2 run) to GitHub Actions and record the result.  -> the tracking row.
    ``demonstration``: the bundle carries a labelled protected-VLAN violation so that the workflow visibly fails; such a
    row never satisfies the gate and never replaces the real one."""
    change = run.change
    row = models.ConfigurationValidationRun(change=change, validation_run=run, snapshot_hash=run.input_hash, repository=github.repository(),
                                            triggered_by=actor[:150], demonstration=demonstration, correlation_id=uuid.uuid4())
    try:
        bundle = build_bundle(change, run, row.correlation_id)
        if demonstration:
            target = bundle["devices"][0] if bundle["devices"] else None
            if target is None:
                raise bundle_module.BundleError("CONFIG_VALIDATION_DEMONSTRATION_NEEDS_A_CANDIDATE", "the Change renders no device candidate")
            target["candidate"] = "\n".join([target["candidate"].rstrip("\n"), *DEMONSTRATION_VIOLATION]) + "\n"  # pylint: disable=unsupported-assignment-operation,unsubscriptable-object  # target is None raises on the line above
            target["candidate_sha256"] = bundle_module.digest(target["candidate"])  # pylint: disable=unsupported-assignment-operation,unsubscriptable-object  # target is None raises above
            bundle["candidate_hash"] = bundle_module.candidate_hash(bundle["devices"], bundle["removals"])
            bundle["demonstration"] = "deliberately invalid: removes the protected management VLAN"
        row.candidate_hash = bundle["candidate_hash"]
        payload = bundle_module.encode(bundle)
        row.bundle_sha256 = payload["bundle_sha256"]
        github.dispatch(bundle_module.EVENT_TYPE, payload)
        row.status, row.triggered_at = S.QUEUED, timezone.now()
    except bundle_module.BundleError as exc:
        row.status, row.failure_summary = S.ERROR, str(exc)[:500]
    except github.GitHubError as exc:
        row.status = S.NOT_TRIGGERED if exc.code == github.NOT_CONFIGURED else S.ERROR
        row.failure_summary = str(exc)[:500]
    except Exception as exc:  # noqa: BLE001 - a defect here must fail closed on the row, never break the validation that triggered it
        row.status, row.failure_summary = S.ERROR, f"CONFIG_VALIDATION_DISPATCH_FAILED: {type(exc).__name__}"
    with transaction.atomic():
        if not demonstration:                      # an older result can never speak for the new candidate
            change.configuration_validation_runs.filter(demonstration=False).exclude(status=S.STALE).update(status=S.STALE, updated_at=timezone.now())
        row.save()
        _audit(row, f"{row.status} ({row.candidate_hash[:12] or 'no candidate hash'})")
    return row


def on_validation(run, *, actor: str = ""):
    """The automatic trigger.  -> the tracking row, or None when nothing is dispatched (not enabled, exempt, or the
    Tier-2 run did not pass: only a validated candidate is worth an external test)."""
    if not enabled() or run.status not in PASSING_TIER2 or exempt(run.change):
        return None
    return dispatch(run, actor=actor)


# ------------------------------------------------------------------------------------------------------------------- status
def latest(change, *, demonstration: bool = False):
    return change.configuration_validation_runs.filter(demonstration=demonstration).order_by("-created_at", "-id").first()


def effective_status(row, *, current_hash: str | None = None) -> str:
    """STALE as soon as the Change is not the snapshot this row tested, or a newer Tier-2 run exists."""
    if row.status == S.STALE:
        return S.STALE
    current = current_hash or snapshot_module.hash_snapshot(snapshot_module.build_change_snapshot(row.change))
    newest = row.change.validation_runs.order_by("-created_at", "-id").first()
    return S.STALE if current != row.snapshot_hash or newest is None or newest.pk != row.validation_run_id else row.status


AMBIGUOUS = "CONFIG_VALIDATION_RUN_AMBIGUOUS"
SUPERSEDED = "Superseded before its result was read."


def _completed_at(run: dict, now):
    from django.utils.dateparse import parse_datetime

    return parse_datetime(str(run.get("updated_at") or "")) or now


def _own_runs(row, runs: list[dict] | None) -> list[dict]:
    """The GitHub runs that are provably this row's: the Configuration Validation workflow of the configured repository,
    started by a dispatch, whose name carries this row's correlation id AND its Change id.  A row that already knows its
    run id accepts that run only."""
    if row.github_run_id:
        found = [run for run in runs or [] if run.get("id") == row.github_run_id] or [github.get_run(row.github_run_id)]
    else:
        found = github.find_runs(str(row.correlation_id), runs)
    mine = [run for run in found if github.is_validation_run(run) and str(row.correlation_id) in str(run.get("display_title") or "")
            and row.change.change_id in str(run.get("display_title") or "")]
    return [run for run in mine if run.get("id") == row.github_run_id] if row.github_run_id else mine


def _result(run: dict):
    """(status, conclusion) of a GitHub run.  Only ``completed`` + ``success`` is PASS; ``failure`` is FAIL; every other
    ending (cancelled, timed_out, action_required, skipped, an unknown word) is ERROR.  Anything not completed is pending."""
    if run.get("status") != "completed":
        return (S.IN_PROGRESS if run.get("status") == "in_progress" else S.QUEUED), ""
    conclusion = str(run.get("conclusion") or "")
    return {"success": S.PASS, "failure": S.FAIL}.get(conclusion, S.ERROR), conclusion


def _failure_text(row, status, conclusion: str) -> str:
    if status == S.FAIL:
        try:
            steps = github.failed_steps(row.github_run_id)
        except github.GitHubError:
            steps = []
        return ("Failed: " + "; ".join(steps))[:500] if steps else "The workflow run failed."
    return f"The workflow run ended as {conclusion or 'unknown'}."[:500] if status == S.ERROR else ""


def needs_reconciling(row) -> bool:
    """A pending row, or one that was superseded (STALE) before NMAS ever read what GitHub decided about it."""
    return row.status in PENDING or (row.status == S.STALE and row.triggered_at is not None and row.completed_at is None)


def refresh(row, *, now=None, runs: list[dict] | None = None):
    """Reconcile one row with GitHub (outbound request only; NMAS needs no inbound path).  Stateless: everything it
    needs is on the row, so a run that finished while NMAS was down is picked up by the next call.

    A pending row takes the status of its run.  A superseded row keeps STALE and only records what its run was (id, URL,
    tested commit, completion, result text): it can never authorize anything again.  Hashes are never touched.  No run,
    more than one run, or a GitHub failure leaves the row non-authorizing."""
    if not needs_reconciling(row):
        return row
    now = now or timezone.now()
    try:
        mine = _own_runs(row, runs)
        if len(mine) > 1:                          # identity is not provable: never pick one
            if row.status in PENDING:
                row.status, row.completed_at = S.ERROR, now
            row.failure_summary = f"{AMBIGUOUS}: {len(mine)} GitHub runs carry this correlation id"
            row.save()
            return row
        if not mine:
            if row.status in PENDING and row.triggered_at and now - row.triggered_at > RUN_APPEARS_WITHIN:
                row.status, row.completed_at = S.ERROR, now
                row.failure_summary = "CONFIG_VALIDATION_RUN_NOT_FOUND: GitHub accepted the dispatch and no matching Configuration Validation run exists"
                row.save(update_fields=["status", "completed_at", "failure_summary", "updated_at"])
            return row
        run = mine[0]
        status, conclusion = _result(run)
        row.github_run_id, row.run_url, row.tested_sha = run.get("id"), str(run.get("html_url") or "")[:300], str(run.get("head_sha") or "")[:64]
        if row.status == S.STALE:
            if status not in PENDING:
                row.completed_at = _completed_at(run, now)
                row.failure_summary = f"{SUPERSEDED} GitHub result: {status}. {_failure_text(row, status, conclusion)}".strip()[:500]
        else:
            row.status = status
            if status not in PENDING:
                row.completed_at, row.failure_summary = _completed_at(run, now), _failure_text(row, status, conclusion)
            else:
                row.failure_summary = ""
        row.save()
    except github.GitHubError as exc:              # the status simply stays what it was; the gate keeps refusing
        row.failure_summary = f"Status not refreshed: {exc}"[:500]
        row.save(update_fields=["failure_summary", "updated_at"])
    return row


def reconcile(change, *, now=None) -> list:
    """Reconcile every row of ``change`` that still owes a result, with ONE list request.  -> the rows it looked at."""
    rows = [row for row in change.configuration_validation_runs.order_by("-created_at", "-id")[:20] if needs_reconciling(row)]
    if not rows or not enabled():
        return rows
    try:
        runs = github.dispatch_runs()
    except github.GitHubError as exc:
        for row in rows:
            row.failure_summary = f"Status not refreshed: {exc}"[:500]
            row.save(update_fields=["failure_summary", "updated_at"])
        return rows
    return [refresh(row, now=now, runs=runs) for row in rows]


# --------------------------------------------------------------------------------------------------------------------- gate
REASONS = {
    S.NOT_TRIGGERED: "Configuration Validation was not sent to GitHub Actions for this candidate.",
    S.QUEUED: "Configuration Validation is queued in GitHub Actions; its result is required first.",
    S.IN_PROGRESS: "Configuration Validation is running in GitHub Actions; its result is required first.",
    S.FAIL: "Configuration Validation FAILED in GitHub Actions for this candidate.",
    S.ERROR: "Configuration Validation ended in an error and proves nothing about this candidate.",
    S.STALE: "The Change was edited or validated again after Configuration Validation: the tested candidate is not the current one.",
}


def gate(change, *, current_hash: str | None = None) -> dict | None:
    """None when execution may proceed: the latest run is PASS for exactly the current snapshot (or the Change is
    exempt, or the feature is off in the automated test environment).  Otherwise {"status", "reason", ...}."""
    if not enabled() or exempt(change):
        return None
    row = latest(change)
    if row is None:
        return {"status": S.NOT_TRIGGERED, "reason": "No Configuration Validation exists for this Change: validate it (Save Draft) to trigger one."}
    row = refresh(row)
    status = effective_status(row, current_hash=current_hash)
    if status == S.PASS:
        return None
    return {"status": status, "reason": REASONS[status], "correlation_id": str(row.correlation_id), "run_url": row.run_url,
            "candidate_hash": row.candidate_hash, "detail": row.failure_summary}


def panel(change) -> dict:
    """What the Change pages show.  Reconciles the rows that still owe a result first (one bounded API call)."""
    reconcile(change)
    row = latest(change)
    status = effective_status(row) if row is not None else S.NOT_TRIGGERED
    return {"enabled": enabled(), "exempt": exempt(change), "row": row, "status": status, "label": S(status).label,
            "stale_note": "candidate changed; new validation required" if row is not None and status == S.STALE else "",
            "demonstration": latest(change, demonstration=True), "configured": github.is_configured(), "repository": github.repository(),
            "history": list(change.configuration_validation_runs.select_related("validation_run").order_by("-created_at", "-id")[:20])}
