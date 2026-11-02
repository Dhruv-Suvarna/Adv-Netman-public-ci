"""Machine-readable plan report, built from the PERSISTED plan (what will actually be shown / downloaded).

Deterministic, bounded and secret-free: Configlet text comes from the authoritative renderer (which renders
secret *references* only, never values) and the whole document is passed through the shared
secret-key redaction.  The download filename is fixed and derived from server-side IDs only.
"""

from __future__ import annotations

from ... import models
from .. import change_validation_service as cvs
from . import priorities

REPORT_SCHEMA_VERSION = 1
LIMITATIONS = (
    "This plan is not executed: no Configlet has been sent to any device and nothing was written to NetBox, Git or GitHub.",
    "Previous device state is UNKNOWN_DEFERRED: Phase 14 performs no live retrieval, so no rollback text is fabricated.",
    "AUTO addresses use the validation-derived PROPOSED value; they are not reserved and must be rechecked before deployment.",
    "Verification requirements are declarative descriptors; real prechecks/postchecks belong to Phase 15.",
    "Order is derived from the pinned validation's dependency graph; priority is a coarse class and dependencies override it.",
    "Configlets are generated from accepted intent and are not free-form editable: edit the Device Intent, re-validate, rebuild.",
    "A RAW Configlet is operator-authored, opaque and pinned to an exact immutable revision and verification run; it cannot run in Complete mode.",
)


def plan_report_filename(plan) -> str:
    return f"{plan.change.change_id}-plan-{str(plan.plan_id)[:8]}.json"


def _configlet_record(configlet) -> dict:
    metadata = configlet.metadata or {}
    source = (configlet.desired_state_ref or {}).get("source", {})
    priority = int(configlet.deployment_priority)
    return {
        "cfg_id": configlet.cfg_id, "sequence": configlet.sequence,
        "device": configlet.target_device, "platform": source.get("platform", ""),
        "priority": priority, "stage": priorities.STAGE_KEYS[models.DeploymentPriority(priority)],
        "stage_label": configlet.get_deployment_priority_display(),
        "operation": configlet.operation_type, "operation_label": configlet.get_operation_type_display(),
        "namespace": configlet.feature_namespace,
        "source": {k: source.get(k, "") for k in ("node_id", "object_type", "object_id")},
        "label": metadata.get("label", ""), "description": configlet.description,
        "rendered_config": configlet.rendered_config,
        "dependencies": metadata.get("dependencies", []),
        "verification": (configlet.verification_spec or {}).get("requirements", []),
        "previous_state": configlet.previous_state_ref,
        "derived": metadata.get("derived"),
        "warnings": metadata.get("warnings", []),
        "origin": configlet.origin,
        "raw": metadata.get("raw"),
        "execution_status": configlet.execution_status,
        "created_at": configlet.created_at.isoformat(),
    }


def serialize_plan(plan, *, currency: dict | None = None) -> dict:
    """The plan as a sanitized, ordered, machine-readable document."""
    configlets = [_configlet_record(c) for c in plan.configlets.order_by("sequence")]
    edges = [
        {"configlet": dep.configlet.cfg_id, "depends_on": dep.depends_on.cfg_id}
        for dep in models.ConfigletDependency.objects.filter(configlet__plan=plan).select_related("configlet", "depends_on")
    ]
    edges.sort(key=lambda e: (e["configlet"], e["depends_on"]))
    stages = [{**stage, "cfg_ids": [c["cfg_id"] for c in configlets if c["priority"] == stage["priority"]]}
              for stage in priorities.stage_table()]
    validation = (plan.provenance or {}).get("validation", {})
    return cvs.sanitize_report({
        "report_schema_version": REPORT_SCHEMA_VERSION,
        "kind": "change_plan",
        "plan": {
            "plan_id": str(plan.plan_id), "change_id": plan.change.change_id, "planner_version": plan.planner_version,
            "created_at": plan.created_at.isoformat(), "created_by": plan.created_by, "plan_hash": plan.plan_hash,
            "currency": (currency or {}).get("state"), "currency_reasons": (currency or {}).get("reasons", []),
            "change_lifecycle_state": plan.change.lifecycle_state,
        },
        "validation": {
            **validation, "pinned_input_hash": plan.validation_input_hash, "pinned_source_hash": plan.validation_source_hash,
            "pinned_engine_version": plan.validation_engine_version,
        },
        "summary": plan.summary,
        "stages": stages,
        "configlets": configlets,
        "dependencies": edges,
        "warnings": plan.warnings,
        "limitations": list(LIMITATIONS),
    })
