"""Phase-13 Tier-2 project-aware Change validation -- the reusable service API.

Views and Phase 14 call THIS module; none of the validation logic lives in a
view.  Nothing here deploys, writes NetBox/Git, contacts a device, creates a
Configlet, or advances Change.lifecycle_state.

    build_change_snapshot(change)          accepted-only deterministic snapshot
    build_source_snapshot(change=None)     read-only external sources + fingerprints
    validate_change(change, actor=..)      run + persist ONE append-only run
    get_validation_currency(change, ...)   NEVER_RUN / CURRENT / STALE
    get_latest_validation(change)          newest run or None
    get_validation_run(change, run_id)     one historical run (must belong to change)
    list_validation_runs(change)           newest first
    serialize_validation_run(run)          sanitized machine-readable report
"""

from __future__ import annotations

import uuid

from django.db import transaction

from .. import models
from .validation import engine, snapshot as snapshot_module, sources as sources_module
from .validation.findings import ENGINE_VERSION, REPORT_SCHEMA_VERSION, Category, Currency, Severity

MAX_HISTORY = 25
MAX_REPORT_BYTES = 2 * 1024 * 1024

SEVERITIES = Severity.ALL
CATEGORIES = Category.ALL

build_change_snapshot = snapshot_module.build_change_snapshot
hash_snapshot = snapshot_module.hash_snapshot
semantic_digest = engine.semantic_digest


def build_source_snapshot(change=None):
    """Collect every read-only external source once (never raises; outages are results)."""
    return sources_module.build_source_bundle()


def validate_change(change: models.Change, *, actor: str = "", sources=None, network_validated: bool = False) -> models.ChangeValidationRun:
    """Run Tier-2 validation for the WHOLE Change and append one immutable run.

    Validates ACCEPTED intent only.  Does not change lifecycle, NetBox, Git,
    topology, or Configlets; records one VALIDATION_RECORDED audit event.
    """
    bundle = sources if sources is not None else sources_module.build_source_bundle()
    # Configuration validation is a separate, mandatory evidence domain and must run first.  The same single source
    # snapshot is shared with Tier-2 so one operator action cannot validate the two gates against different NetBox data.
    # Callers that already
    # performed it in the same explicit workflow may set ``network_validated`` to avoid duplicate evidence.
    if not network_validated:
        from . import network_config_validation

        network_config_validation.validate_candidate(change, actor=actor, sources=bundle)
    snapshot = snapshot_module.build_change_snapshot(change)
    input_hash = snapshot_module.hash_snapshot(snapshot)
    report = engine.run_validation(snapshot, bundle)
    provenance = bundle.provenance()
    report["provenance"] = {
        **provenance,
        "input_hash": input_hash,
        "snapshot_schema_version": snapshot["schema_version"],
        "semantic_digest": engine.semantic_digest(report),
    }
    if len(engine.canonical_json(report)) > MAX_REPORT_BYTES:  # defensive bound; findings/graph already capped
        report["dependency_graph"] = {**report["dependency_graph"], "nodes": [], "edges": [], "truncated": True}

    with transaction.atomic():
        run = models.ChangeValidationRun.objects.create(
            change=change,
            status=report["status"],
            engine_version=ENGINE_VERSION,
            input_hash=input_hash,
            source_hash=bundle.source_hash(),
            repository_head=bundle.repository_head,
            created_by=actor,
            summary=report["summary"],
            report=report,
            derived_facts=report["derived_facts"],
            dependency_graph=report["dependency_graph"],
            intent_revision_map=snapshot_module.revision_map(change),
            source_provenance=provenance,
        )
        models.AuditEvent.objects.create(
            event_type=models.AuditEventType.VALIDATION_RECORDED,
            change=change,
            object_type="ChangeValidationRun",
            object_id=str(run.run_id),
            actor=actor,
            summary=f"{change.change_id}: validation {report['status']} ({run.input_hash[:12]})",
            metadata={
                "run_id": str(run.run_id),
                "status": report["status"],
                "input_hash": run.input_hash,
                "errors": report["summary"]["errors"],
                "warnings": report["summary"]["warnings"],
            },
        )
    # A passing run is a stable whole-Change validation point: its immutable snapshot is sent to the GitHub Actions workflow
    # "Configuration Validation" (never raises; a run that did not pass sends nothing).
    from .configuration_validation import service as configuration_validation

    configuration_validation.on_validation(run, actor=actor)
    return run


def get_latest_validation(change: models.Change):
    return change.validation_runs.order_by("-created_at", "-id").first()


def get_validation_run(change: models.Change, run_id) -> models.ChangeValidationRun | None:
    """A run is only ever addressed THROUGH its Change (never by a bare id)."""
    try:
        parsed = uuid.UUID(str(run_id))
    except ValueError:
        return None
    return change.validation_runs.filter(run_id=parsed).first()


def list_validation_runs(change: models.Change, *, limit: int = MAX_HISTORY):
    return list(change.validation_runs.order_by("-created_at", "-id")[:limit])


def get_validation_currency(change: models.Change, *, sources=None, check_sources: bool = False) -> dict:
    """NEVER_RUN / CURRENT / STALE, with machine-readable reasons.

    Intent staleness is always evaluated (cheap, local): the accepted-snapshot
    SHA-256 is compared with the latest run's.  External-source staleness is
    evaluated only when explicitly requested (``check_sources=True``) or when a
    ``sources`` bundle is supplied, because it reads NetBox/topology.  A
    STALE PASS is never current authorization -- re-run required.
    """
    latest = get_latest_validation(change)
    if latest is None:
        return {"state": Currency.NEVER_RUN, "reasons": [], "latest": None, "last_status": None,
                "current_input_hash": snapshot_module.hash_snapshot(snapshot_module.build_change_snapshot(change)),
                "sources_checked": False}
    current_hash = snapshot_module.hash_snapshot(snapshot_module.build_change_snapshot(change))
    reasons = []
    if current_hash != latest.input_hash:
        reasons.append("ACCEPTED_INTENT_CHANGED")
    sources_checked = False
    if sources is not None or check_sources:
        bundle = sources if sources is not None else sources_module.build_source_bundle()
        sources_checked = True
        recorded = (latest.source_provenance or {}).get("sources", {})
        for result in bundle.all():
            before = (recorded.get(result.name) or {}).get("fingerprint")
            if before is None:
                continue
            if not result.available and before != "UNAVAILABLE":
                reasons.append(f"SOURCE_UNVERIFIABLE:{result.name}")
            elif result.fingerprint != before:
                reasons.append(f"SOURCE_CHANGED:{result.name}")
        if (latest.source_provenance or {}).get("engine_version") != ENGINE_VERSION:
            reasons.append("ENGINE_VERSION_CHANGED")
    return {
        "state": Currency.STALE if reasons else Currency.CURRENT,
        "reasons": reasons,
        "latest": latest,
        "last_status": latest.status,
        "current_input_hash": current_hash,
        "sources_checked": sources_checked,
    }


def serialize_validation_run(run: models.ChangeValidationRun) -> dict:
    """Sanitized, bounded, machine-readable report (safe for the UI and JSON download)."""
    report = run.report or {}
    return sanitize_report({
        "report_schema_version": REPORT_SCHEMA_VERSION,
        "run_id": str(run.run_id),
        "change_id": run.change.change_id,
        "created_at": run.created_at.isoformat(),
        "created_by": run.created_by,
        "status": run.status,
        "engine_version": run.engine_version,
        "input_hash": run.input_hash,
        "source_hash": run.source_hash,
        "repository_head": run.repository_head,
        "intent_revision_map": run.intent_revision_map,
        "provenance": report.get("provenance", {}),
        "summary": run.summary,
        "findings": report.get("findings", []),
        "derived_facts": run.derived_facts,
        "dependency_graph": run.dependency_graph,
        "limitations": report.get("limitations", []),
    })


def sanitize_report(document: dict) -> dict:
    """Second-line redaction of secret-shaped KEYS anywhere (values are already secret-free)."""
    return _redact(document)


def _redact(value):
    from .validation.findings import _secret_key

    if isinstance(value, dict):
        return {k: ("[REDACTED]" if _secret_key(k) else _redact(v)) for k, v in value.items()}
    if isinstance(value, list):
        return [_redact(item) for item in value]
    return value


def report_filename(run: models.ChangeValidationRun) -> str:
    return f"{run.change.change_id}-validation-{str(run.run_id)[:8]}.json"


# --- presentation helpers (no validation logic; pure shaping of a stored report) ---------------

def filter_findings(findings: list[dict], *, severity: str = "", category: str = "", device: str = "",
                    blocking_only: bool = False) -> list[dict]:
    """Bookmarkable finding filters.  Unknown filter values are ignored, never trusted."""
    severity = severity if severity in Severity.ALL else ""
    category = category if category in Category.ALL else ""
    return [
        f for f in findings
        if (not severity or f["severity"] == severity)
        and (not category or f["category"] == category)
        and (not device or f.get("device") == device or device in f.get("related_devices", []))
        and (not blocking_only or f["blocking"])
    ]


def dependency_rows(graph: dict) -> list[dict]:
    """Readable "object -> depends on -> edge type -> status" rows from a stored graph."""
    labels = {node["id"]: node["label"] for node in graph.get("nodes", [])}
    cycle_nodes = {node for cycle in graph.get("cycles", []) for node in cycle}
    return [
        {
            "object": labels.get(edge["from"], edge["from"]),
            "depends_on": labels.get(edge["to"], edge["to"]),
            "edge_type": edge["type"],
            "status": edge["status"],
            "reason": edge.get("reason", ""),
            "in_cycle": edge["from"] in cycle_nodes and edge["to"] in cycle_nodes,
        }
        for edge in graph.get("edges", [])
    ]
