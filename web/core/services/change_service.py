"""
Change control-plane service. CRUD and identifier allocation only -- no
config rendering, no validation beyond structural invariants, no deployment.
See docs/DEVICE_INTENT_CHANGE_MODEL.md for the full architecture.

Concurrency note: change_id allocation ("read max, add 1") is protected by
the database UNIQUE constraint on Change.change_id, not by trusting the read
alone -- a collision from a concurrent writer raises IntegrityError inside
the atomic block, and this module simply retries with the next candidate
id. This is safe under SQLite (no reliance on SELECT ... FOR UPDATE, which
SQLite does not support) and remains safe if the project later moves to a
database that does support row locking.
"""

from __future__ import annotations

from django.db import IntegrityError, transaction
from django.utils import timezone

from .. import models
from . import secret_policy

MAX_CHANGE_ID_RETRIES = 10


def _next_change_id(now=None) -> str:
    day = (now or timezone.now()).strftime("%Y%m%d")
    prefix = f"CHG-{day}-"
    last_id = (
        models.Change.objects.filter(change_id__startswith=prefix)
        .order_by("-change_id")
        .values_list("change_id", flat=True)
        .first()
    )
    next_seq = int(last_id.rsplit("-", 1)[1]) + 1 if last_id else 1
    return f"{prefix}{next_seq:04d}"


def create_change(
    *,
    title: str,
    description: str = "",
    category: str = models.ChangeCategory.CONFIGURATION_CHANGE,
    execution_mode: str = models.ExecutionMode.COMPLETE,
    created_by: str = "",
    metadata: dict | None = None,
) -> models.Change:
    """Creates a Change with a fresh CHG-YYYYMMDD-NNNN id, plus its initial
    DRAFT lifecycle event and CHANGE_CREATED audit record, all in one
    transaction (a Change never exists without its initial lifecycle row)."""
    if not title:
        raise ValueError("title is required")
    if category not in models.ChangeCategory.values:
        raise ValueError(f"Unknown category {category!r}")
    if execution_mode not in models.ExecutionMode.values:
        raise ValueError(f"Unknown execution_mode {execution_mode!r}")
    metadata = secret_policy.assert_no_secret_shaped_keys(dict(metadata or {}), context="Change metadata")

    for _ in range(MAX_CHANGE_ID_RETRIES):
        change_id = _next_change_id()
        try:
            with transaction.atomic():
                change = models.Change.objects.create(
                    change_id=change_id,
                    title=title,
                    description=description,
                    category=category,
                    execution_mode=execution_mode,
                    created_by=created_by,
                    metadata=metadata,
                )
                models.ChangeLifecycleEvent.objects.create(
                    change=change,
                    from_state="",
                    to_state=models.ChangeLifecycleState.DRAFT,
                    actor=created_by,
                    reason="Change created",
                )
                models.AuditEvent.objects.create(
                    event_type=models.AuditEventType.CHANGE_CREATED,
                    change=change,
                    object_type="Change",
                    object_id=change.change_id,
                    actor=created_by,
                    summary=f"Change {change.change_id} created",
                )
            return change
        except IntegrityError:
            continue
    raise RuntimeError("Could not allocate a unique change_id after several attempts.")


def add_target(
    *, change: models.Change, device_name: str, netbox_device_ref: str = "", site: str = ""
) -> models.ChangeTarget:
    target, _ = models.ChangeTarget.objects.get_or_create(
        change=change,
        device_name=device_name,
        defaults={"netbox_device_ref": netbox_device_ref, "site": site},
    )
    return target


def get_change_or_404(change_id: str) -> models.Change:
    from django.shortcuts import get_object_or_404

    return get_object_or_404(models.Change, change_id=change_id)


def list_changes():
    return models.Change.objects.all()


class DraftDeletionError(Exception):
    """Refused draft-deletion request; never a device/NetBox/Golden-state change."""


def _draft_deletion_blockers(change: models.Change) -> list[str]:
    """Every reason `change` may not be deleted as a draft.  Lifecycle state
    alone is NOT sufficient: nothing in this codebase automatically advances
    `lifecycle_state` on validation/plan/precheck/execution (transitions are
    always an explicit, separate action -- see ChangeLifecycleState's own
    docstring), so a Change can carry real execution/precheck/bundle history
    while still reading DRAFT. Each of these is checked independently so a
    Change with history is refused regardless of what its lifecycle_state
    happens to say."""
    blockers = []
    if change.lifecycle_state != models.ChangeLifecycleState.DRAFT:
        blockers.append(
            "Only a Change still in DRAFT may be deleted this way; a Change that has progressed "
            "past Draft carries real history and must not be silently discarded."
        )
    if models.ChangeExecutionRun.objects.filter(change=change).exists():
        blockers.append("This Change has execution history and can never be deleted.")
    if models.OperationalCheckRun.objects.filter(change=change).exists():
        blockers.append("This Change has recorded health/precheck history and can never be deleted.")
    if models.ConfigurationBundle.objects.filter(change=change).exists():
        blockers.append("This Change produced a configuration bundle and can never be deleted.")
    return blockers


def can_delete_draft(change: models.Change) -> bool:
    """Read-only check the UI uses to decide whether to offer Delete at all."""
    return not _draft_deletion_blockers(change)


def delete_draft_change(*, change: models.Change, confirmation: str, actor: str = "") -> str:
    """Permanently remove one never-executed DRAFT Change (application state
    only) so an operator can discard work they no longer want to continue.

    This can NEVER touch a device, NetBox, or a Golden/Probation/UAT bundle:
    every guard in `_draft_deletion_blockers` is checked before anything is
    deleted, and the ones that matter are double-enforced by the DB schema
    itself (`ConfigurationBundle.change` is `on_delete=PROTECT`, so a bundled
    Change's delete would fail even if this check were ever bypassed).
    `AuditEvent` rows survive (their `change` FK is `on_delete=SET_NULL`) so
    the fact that this Change existed and was deleted remains in the audit
    trail; `ChangeLifecycleEvent` rows are Change-scoped history and are
    deleted along with the Change they describe.
    """
    if confirmation != "DELETE":
        raise DraftDeletionError("Explicit DELETE confirmation is required.")
    blockers = _draft_deletion_blockers(change)
    if blockers:
        raise DraftDeletionError(blockers[0])

    change_id = change.change_id
    with transaction.atomic():
        models.AuditEvent.objects.create(
            event_type=models.AuditEventType.DRAFT_CHANGE_DELETED,
            change=change,
            object_type="Change",
            object_id=change_id,
            actor=actor,
            summary=f"Draft Change {change_id} deleted by the operator before any execution",
        )
        change.delete()
    return change_id
