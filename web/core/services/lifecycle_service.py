"""
Lifecycle transition recording. Phase 8 scope: EXPLICIT, service-triggered
transitions only -- there is no autonomous transition engine, no Golden
promotion, no soak timer, no auto-rollback. Every call here is one
append-only ChangeLifecycleEvent row plus one generic AuditEvent row, and
updates Change.lifecycle_state to match (never leaves the two out of sync).
"""

from __future__ import annotations

from django.db import transaction

from .. import models
from . import secret_policy


def record_lifecycle_event(
    *,
    change: models.Change,
    to_state: str,
    reason: str = "",
    actor: str = "",
    metadata: dict | None = None,
) -> models.ChangeLifecycleEvent:
    if to_state not in models.ChangeLifecycleState.values:
        raise ValueError(f"Unknown lifecycle state {to_state!r}")
    metadata = secret_policy.assert_no_secret_shaped_keys(dict(metadata or {}), context="Lifecycle event metadata")
    from_state = change.lifecycle_state

    with transaction.atomic():
        event = models.ChangeLifecycleEvent.objects.create(
            change=change,
            from_state=from_state,
            to_state=to_state,
            reason=reason,
            actor=actor,
            metadata=metadata,
        )
        change.lifecycle_state = to_state
        change.save(update_fields=["lifecycle_state", "updated_at"])
        models.AuditEvent.objects.create(
            event_type=models.AuditEventType.LIFECYCLE_CHANGED,
            change=change,
            object_type="Change",
            object_id=change.change_id,
            actor=actor,
            summary=f"{change.change_id}: {from_state or '(none)'} -> {to_state}",
        )
    return event


def list_lifecycle_history(change: models.Change):
    return change.lifecycle_events.all()
