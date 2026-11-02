"""View-facing facade for the Configuration Changes / Remove Configuration workbench pages.

Views stay thin: every decision lives in ``config_workbench`` (analysis) or the existing lifecycle services (validation,
planning, precheck, execution).  Nothing here contacts a device except ``snapshots.capture_snapshot`` (read-only, explicit
POST only), and nothing here executes: the ONE execution route remains the Change's own Execute page.
"""

from __future__ import annotations

from copy import deepcopy

from django.db import transaction
from django.utils import timezone

from .. import models
from . import change_plan_service, change_service, change_validation_service, intent_service
from .config_workbench import contribution, removal, snapshots  # noqa: F401 - re-exported for views
from .planning.errors import PlanGenerationError


class RemovalRefused(ValueError):
    def __init__(self, analysis: dict):
        self.analysis = analysis
        super().__init__("; ".join(b["message"] for b in analysis.get("blockers") or []) or "Removal refused.")


def removal_selection(mode: str, *, from_line=None, to_line=None, object_ids=(), accepted_proposals=()) -> dict:
    selection = {"accepted_proposals": sorted({str(p) for p in accepted_proposals if p})}
    if mode == models.RemovalMode.LINE_RANGE:
        selection.update({"from_line": int(from_line), "to_line": int(to_line)})
    else:
        selection["object_ids"] = sorted({str(o) for o in object_ids if o})
    return selection


def analyze_removal(snapshot, mode: str, selection: dict) -> dict:
    line_range = (selection.get("from_line"), selection.get("to_line")) if mode == models.RemovalMode.LINE_RANGE else None
    return removal.analyze(snapshot.text, snapshot.platform, mode=mode, line_range=line_range,
                           object_ids=selection.get("object_ids") or (), accepted_proposals=selection.get("accepted_proposals") or ()).to_dict()


def create_removal_change(*, snapshot, mode: str, selection: dict, actor: str = "", title: str = "") -> models.Change:
    """Persist an intentional removal as a normal Change (Draft).  A BLOCKED analysis is refused -- nothing is saved."""
    analysis = analyze_removal(snapshot, mode, selection)
    if analysis["status"] != models.RemovalAnalysisStatus.READY:
        raise RemovalRefused(analysis)
    with transaction.atomic():
        change = change_service.create_change(
            title=(title or f"Remove configuration on {snapshot.device_name}")[:200], created_by=actor[:150],
            category=models.ChangeCategory.CONFIGURATION_CHANGE,
            metadata={"workflow": models.ChangeWorkflow.REMOVE_CONFIGURATION, "workflow_snapshot": {
                "device": snapshot.device_name, "digest": snapshot.digest, "snapshot_id": str(snapshot.snapshot_id)}},
        )
        change_service.add_target(change=change, device_name=snapshot.device_name)
        models.ConfigRemoval.objects.create(
            change=change, device_name=snapshot.device_name, platform=snapshot.platform, snapshot=snapshot, mode=mode,
            selection=selection, analysis=analysis, status=analysis["status"], content_hash=removal.content_hash(analysis), created_by=actor[:150],
        )
    return change


def validate_and_plan(change, *, actor: str = "") -> dict:
    """Explicit operator action: the EXISTING validation engine, then (only if it passes) the EXISTING planner.

    Reads NetBox / topology / inventory read-only through the validation sources; never contacts a device; never executes.
    """
    run = change_validation_service.validate_change(change, actor=actor)
    result = {"validation": run, "plan": None, "plan_error": ""}
    if run.status not in ("PASS", "PASS_WITH_WARNINGS"):
        return result
    try:
        plan, _created = change_plan_service.build_change_plan(change, actor=actor)
        result["plan"] = plan
    except PlanGenerationError as exc:
        result["plan_error"] = exc.message
    return result


class RevisionRefused(ValueError):
    """A workbench Change cannot safely start another immutable revision."""


def revise_change(*, change: models.Change, actor: str = "", title: str = "") -> list[models.DeviceIntentRevision]:
    """Clone the current accepted intent into a new revision for editing.

    Prior revisions and every validation/plan/execution row remain untouched.
    The clone intentionally invalidates currency: the operator must edit (if
    desired), revalidate, rebuild the plan and precheck before execution.
    """
    if (change.metadata or {}).get("archived_at"):
        raise RevisionRefused("An archived Change cannot be revised.")
    if change.lifecycle_state != models.ChangeLifecycleState.DRAFT:
        raise RevisionRefused("Only a Draft Change can start a new revision.")
    if models.ChangeExecutionRun.objects.filter(change=change).exists():
        raise RevisionRefused("A Change with execution history cannot be revised in place; create a new Change.")
    intents = list(change.device_intents.prefetch_related("revisions__field_states"))
    if not intents:
        raise RevisionRefused("This Change has no device intent to revise.")

    created = []
    with transaction.atomic():
        for device_intent in intents:
            previous = device_intent.latest_revision()
            if previous is None:
                raise RevisionRefused(f"{device_intent.device_name} has no revision to copy.")
            revision = intent_service.create_candidate_revision(
                device_intent=device_intent,
                sections=deepcopy(previous.sections),
                schema_version=previous.schema_version,
                created_by=actor[:150],
                metadata={
                    **deepcopy(previous.metadata or {}),
                    "revised_from_revision": previous.revision,
                },
            )
            models.IntentFieldState.objects.bulk_create([
                models.IntentFieldState(
                    revision=revision,
                    path=state.path,
                    draft_value=deepcopy(state.accepted_value),
                    accepted_value=deepcopy(state.accepted_value),
                    dirty=False,
                    last_committed_at=state.last_committed_at,
                    validation_state=state.validation_state,
                    validation_message=state.validation_message,
                )
                for state in previous.field_states.all()
            ])
            created.append(revision)
        metadata = deepcopy(change.metadata or {})
        metadata["last_revised_at"] = timezone.now().isoformat()
        metadata["last_revised_by"] = actor[:150]
        change.metadata = metadata
        if title.strip():
            change.title = title.strip()[:200]
            change.save(update_fields=["title", "metadata", "updated_at"])
        else:
            change.save(update_fields=["metadata", "updated_at"])
    return created


def archive_change(*, change: models.Change, actor: str = "") -> None:
    """Retire a workbench Change without deleting any historical evidence."""
    if (change.metadata or {}).get("archived_at"):
        return
    with transaction.atomic():
        metadata = deepcopy(change.metadata or {})
        metadata.update({"archived_at": timezone.now().isoformat(), "archived_by": actor[:150]})
        change.metadata = metadata
        change.save(update_fields=["metadata", "updated_at"])
        models.AuditEvent.objects.create(
            event_type=models.AuditEventType.CHANGE_ARCHIVED,
            change=change,
            object_type="Change",
            object_id=change.change_id,
            actor=actor[:150],
            summary=f"Change {change.change_id} archived; immutable evidence retained",
        )


def workflow_changes(workflow: str, device: str | None = None, *, limit: int = 10):
    query = models.Change.objects.filter(metadata__workflow=workflow).exclude(metadata__has_key="archived_at").order_by("-created_at")
    if device:
        query = query.filter(targets__device_name=device)
    return list(query[:limit])


def plan_rows(change) -> list[dict]:
    from .planning import builder

    plan = builder.get_latest_plan(change)
    if plan is None:
        return []
    return [{"cfg_id": c.cfg_id, "operation": c.operation_type, "origin": c.origin, "label": (c.metadata or {}).get("label", c.description),
             "rendered": c.rendered_config, "device": c.target_device}
            for c in plan.configlets.order_by("sequence")]


__all__ = ["RemovalRefused", "RevisionRefused", "analyze_removal", "archive_change", "contribution", "create_removal_change",
           "plan_rows", "removal_selection", "revise_change", "snapshots", "validate_and_plan", "workflow_changes"]
