"""
Device Intent + candidate revision + draft/accepted field-state service.

This is the Phase-9 Device Builder's server-side contract in miniature: it
stores durable candidate state (revisions, accepted values, dirty flags) but
never becomes a keystroke database -- the browser will own live typing
state in Phase 9, calling set_draft_field() only on commit-worthy moments,
not per keystroke.

No network validation happens here (no NetBox/device reachability checks).
Field-level "validation" is entirely a Phase 9+ concern; accept_field_value()
here performs no semantic validation, only the structural promotion of
draft_value -> accepted_value.
"""

from __future__ import annotations

from django.db import IntegrityError, transaction
from django.utils import timezone

from .. import models
from . import secret_policy

MAX_REVISION_RETRIES = 10


def create_or_get_device_intent(
    *,
    change: models.Change,
    device_name: str,
    platform: str,
    target_type: str = models.DeviceIntentTargetType.EXISTING_DEVICE,
    image_reference: str = "",
    netbox_device_ref: str = "",
    metadata: dict | None = None,
) -> tuple[models.DeviceIntent, bool]:
    if target_type not in models.DeviceIntentTargetType.values:
        raise ValueError(f"Unknown target_type {target_type!r}")
    if platform not in models.Platform.values:
        raise ValueError(f"Unsupported platform identifier {platform!r}")
    metadata = secret_policy.assert_no_secret_shaped_keys(dict(metadata or {}), context="DeviceIntent metadata")

    intent, created = models.DeviceIntent.objects.get_or_create(
        change=change,
        device_name=device_name,
        defaults={
            "target_type": target_type,
            "platform": platform,
            "image_reference": image_reference,
            "netbox_device_ref": netbox_device_ref,
            "metadata": metadata,
        },
    )
    if created:
        models.AuditEvent.objects.create(
            event_type=models.AuditEventType.INTENT_CREATED,
            change=change,
            object_type="DeviceIntent",
            object_id=str(intent.pk),
            summary=f"DeviceIntent created for {device_name}",
        )
    return intent, created


def create_candidate_revision(
    *,
    device_intent: models.DeviceIntent,
    sections: dict | None = None,
    schema_version: int = 1,
    created_by: str = "",
    metadata: dict | None = None,
) -> models.DeviceIntentRevision:
    if schema_version < 1:
        raise ValueError("schema_version must be a positive integer.")
    sections = secret_policy.assert_no_secret_shaped_keys(dict(sections or {}), context="Intent revision sections")
    metadata = secret_policy.assert_no_secret_shaped_keys(dict(metadata or {}), context="Intent revision metadata")

    for _ in range(MAX_REVISION_RETRIES):
        last = device_intent.revisions.order_by("-revision").first()
        next_revision = (last.revision + 1) if last else 1
        try:
            with transaction.atomic():
                revision = models.DeviceIntentRevision.objects.create(
                    device_intent=device_intent,
                    revision=next_revision,
                    schema_version=schema_version,
                    sections=sections,
                    created_by=created_by,
                    metadata=metadata,
                )
                models.AuditEvent.objects.create(
                    event_type=models.AuditEventType.INTENT_REVISED,
                    change=device_intent.change,
                    object_type="DeviceIntentRevision",
                    object_id=str(revision.pk),
                    actor=created_by,
                    summary=f"Revision {next_revision} created for {device_intent.device_name}",
                )
            return revision
        except IntegrityError:
            continue
    raise RuntimeError("Could not allocate a unique revision number after several attempts.")


def set_draft_field(*, revision: models.DeviceIntentRevision, path: str, draft_value) -> models.IntentFieldState:
    """Set only this field's draft_value. accepted_value and every sibling
    IntentFieldState row are left untouched."""
    field_state, created = models.IntentFieldState.objects.get_or_create(
        revision=revision,
        path=path,
        defaults={"draft_value": draft_value, "accepted_value": draft_value, "dirty": False},
    )
    if not created:
        field_state.draft_value = draft_value
        field_state.dirty = draft_value != field_state.accepted_value
        field_state.save(update_fields=["draft_value", "dirty", "updated_at"])
    return field_state


def accept_field_value(*, revision: models.DeviceIntentRevision, path: str) -> models.IntentFieldState:
    """Promote draft_value to accepted_value for exactly one field. No
    semantic validation is performed -- that is Phase 9's field validator."""
    field_state = models.IntentFieldState.objects.get(revision=revision, path=path)
    field_state.accepted_value = field_state.draft_value
    field_state.dirty = False
    field_state.last_committed_at = timezone.now()
    field_state.save(update_fields=["accepted_value", "dirty", "last_committed_at", "updated_at"])
    models.AuditEvent.objects.create(
        event_type=models.AuditEventType.FIELD_ACCEPTED,
        change=revision.device_intent.change,
        object_type="IntentFieldState",
        object_id=str(field_state.pk),
        summary=f"Field {path} accepted for {revision.device_intent.device_name}",
    )
    return field_state


def rollback_draft_to_accepted(*, revision: models.DeviceIntentRevision, path: str) -> models.IntentFieldState:
    """Reverts only this field's draft_value to its last accepted_value --
    the Phase-9 behavior for a failed commit-time validation, modeled here
    without an actual validator."""
    field_state = models.IntentFieldState.objects.get(revision=revision, path=path)
    field_state.draft_value = field_state.accepted_value
    field_state.dirty = False
    field_state.save(update_fields=["draft_value", "dirty", "updated_at"])
    return field_state
