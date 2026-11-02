"""Controllable-time rotation policy and due selection."""
from __future__ import annotations

from datetime import timedelta

from django.utils import timezone

from ...models import CredentialStatus, DeviceCredential


NON_RUNNABLE = (CredentialStatus.IN_PROGRESS, CredentialStatus.UNCERTAIN, CredentialStatus.BLOCKED)


def next_due_at(rotated_at, interval_days: int):
    if interval_days < 1:
        raise ValueError("Rotation interval must be at least one day.")
    return rotated_at + timedelta(days=interval_days)


def is_due(credential: DeviceCredential, *, at=None) -> bool:
    at = at or timezone.now()
    return bool(
        credential.rotation_enabled
        and credential.next_due_at is not None
        and credential.next_due_at <= at
        and credential.last_status not in NON_RUNNABLE
    )


def due_credentials(*, at=None):
    at = at or timezone.now()
    return DeviceCredential.objects.filter(
        rotation_enabled=True,
        next_due_at__isnull=False,
        next_due_at__lte=at,
    ).exclude(last_status__in=NON_RUNNABLE).order_by("next_due_at", "device_name", "username")
