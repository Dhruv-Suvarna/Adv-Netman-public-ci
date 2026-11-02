"""
Phase 9 field-commit orchestration: the explicit Enter/Commit boundary that
turns a browser draft value into Tier-1-validated durable state.

This module is a thin layer on top of the UNCHANGED Phase-8 intent_service
primitives (set_draft_field / accept_field_value / rollback_draft_to_accepted)
-- it does not redesign that contract, only adds validation-then-decide
orchestration and the field allowlist/ownership checks a browser-facing
endpoint needs.

No NetBox, Git, GitHub, or live-device call happens anywhere in this module
-- every operation here is a plain Django ORM read/write.
"""

from __future__ import annotations

from django.shortcuts import get_object_or_404

from .. import models
from . import (
    field_registry,
    intent_service,
    interface_intent_service,
    routing_intent_service,
    service_policy_intent_service,
)


class UnknownFieldPathError(ValueError):
    """Raised when a browser-supplied field path is not in FIELD_REGISTRY."""


class RecordOwnershipError(ValueError):
    """Raised when supplied ids don't form a genuine Change/Intent/Revision chain."""


class RevisionMissingError(Exception):
    """Raised when a DeviceIntent has no revision yet -- callers turn this into HTTP 404/409."""


def resolve_intent(*, change: models.Change, intent_id: int) -> models.DeviceIntent:
    """Never trusts a bare intent_id -- it must belong to `change`."""
    return get_object_or_404(models.DeviceIntent, pk=intent_id, change=change)


def resolve_active_revision(intent: models.DeviceIntent) -> models.DeviceIntentRevision:
    """
    Phase 9 keeps exactly one active CandidateRevision per DeviceIntent while
    editing -- ordinary field commits reuse it rather than creating a new
    revision per commit. Creating a genuinely new revision is a distinct,
    explicit service action (not exposed by Phase 9's UI) reserved for later
    phases' probation-reset semantics.
    """
    revision = intent.latest_revision()
    if revision is None:
        raise RevisionMissingError(f"No candidate revision exists for {intent.device_name!r}.")
    return revision


def seed_device_identity_field_states(*, intent: models.DeviceIntent, revision: models.DeviceIntentRevision) -> None:
    """
    Called once, right after a DeviceIntentRevision is created, so the
    editor's initial page load has real IntentFieldState rows (draft ==
    accepted == the intent's creation-time value) for every foundational
    device-identity field instead of an empty revision.
    """
    seed_values = {
        "device.hostname": intent.device_name,
        "device.description": "",
        "device.target_type": intent.target_type,
        "device.platform": intent.platform,
        "device.image_reference": intent.image_reference,
    }
    for path, value in seed_values.items():
        intent_service.set_draft_field(revision=revision, path=path, draft_value=value)
        intent_service.accept_field_value(revision=revision, path=path)


def commit_field(
    *,
    change: models.Change,
    intent: models.DeviceIntent,
    revision: models.DeviceIntentRevision,
    path: str,
    raw_value,
) -> models.IntentFieldState:
    """
    Runs the full Tier-1 commit boundary for one field:

      1. verify the Change/Intent/Revision relationship chain (never trust
         browser-supplied ids to select unrelated records)
      2. verify `path` is allowlisted
      3. record the draft exactly like an ordinary set_draft_field() call
      4. run the Tier-1 validator
      5. valid -> normalize if needed, accept, mirror onto the DeviceIntent
         column if this path has one
      6. invalid -> roll back ONLY this field to its accepted value; every
         sibling IntentFieldState row is untouched because each field is its
         own row (the Phase-8 invariant this module builds on)
    """
    if intent.change_id != change.id:
        raise RecordOwnershipError("DeviceIntent does not belong to this Change.")
    if revision.device_intent_id != intent.id:
        raise RecordOwnershipError("DeviceIntentRevision does not belong to this DeviceIntent.")
    try:
        interface_intent_service.require_draft(revision)
    except interface_intent_service.DraftOnlyError as exc:
        raise RecordOwnershipError(str(exc)) from exc

    try:
        spec = field_registry.resolve_field_spec(path, revision=revision)
    except (interface_intent_service.CollectionOwnershipError, service_policy_intent_service.CollectionOwnershipError) as exc:
        raise RecordOwnershipError(str(exc)) from exc
    if spec is None:
        raise UnknownFieldPathError(f"Unknown or unallowed field path {path!r}.")

    intent_service.set_draft_field(revision=revision, path=path, draft_value=raw_value)
    ok, normalized_value, message = spec["validator"](raw_value)

    if ok:
        if normalized_value != raw_value:
            intent_service.set_draft_field(revision=revision, path=path, draft_value=normalized_value)
        field_state = intent_service.accept_field_value(revision=revision, path=path)
        field_state.validation_state = models.FieldValidationState.VALID
        field_state.validation_message = message or ""
        field_state.save(update_fields=["validation_state", "validation_message", "updated_at"])

        mirror_field = spec.get("mirrors_to")
        if mirror_field is not None:
            setattr(intent, mirror_field, normalized_value)
            intent.save(update_fields=[mirror_field, "updated_at"])
        if spec.get("dynamic"):
            # Dynamic paths live in one of two structured sub-namespaces of
            # `sections` (interfaces.* or routing.*); each owns its own
            # mirror function following the same contract.
            if path.startswith("routing."):
                mirror_service = routing_intent_service
            elif path.startswith(("fhrp.", "nat.", "services.", "security.", "policy.")):
                mirror_service = service_policy_intent_service
            else:
                mirror_service = interface_intent_service
            mirror_service.mirror_accepted_field(revision=revision, path=path, value=normalized_value)
    else:
        field_state = intent_service.rollback_draft_to_accepted(revision=revision, path=path)
        field_state.validation_state = models.FieldValidationState.INVALID
        field_state.validation_message = message or "Invalid value."
        field_state.save(update_fields=["validation_state", "validation_message", "updated_at"])

    return field_state
