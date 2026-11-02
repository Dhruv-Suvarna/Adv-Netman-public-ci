"""
The one reusable notification/event publishing API for the whole project.

Phase 3 shipped an honest empty-state placeholder here. Phase 4 replaces it
with a real backend: persistence in core.models.Notification plus a
provider-abstracted delivery step (today: Slack via slack_service; see
docs/NOTIFICATION_AND_SLACK_ARCHITECTURE.md for the full design and the
future producer map).

Conceptual flow (never change the order):

    publish_event(...)
          |
          v
    persist Notification  <-- SUCCESS is durable even if everything below fails
          |
          v
    attempt Slack (bounded, synchronous, never raises)
       /        \\
     SENT      FAILED / NOT_CONFIGURED / SKIPPED
      |            |
    record       record
    status       status + error summary

Every future Python subsystem (health alerts, GitHub Actions results,
deployment/rollback outcomes, Golden/soak lifecycle events -- see the
architecture doc's producer map) should call publish_event() instead of
writing its own Django ORM create() or its own Slack HTTP call.
"""

from __future__ import annotations

from datetime import timedelta

from django.shortcuts import get_object_or_404
from django.utils import timezone

from ..models import Notification
from . import secret_policy, slack_service

MAX_DROPDOWN_NOTIFICATIONS = 4

# How long a correlation_key suppresses a repeat event. Documented semantics:
# publishing the same correlation_key again within this window returns the
# existing notification unchanged (no new row, no repeat Slack delivery)
# instead of creating a duplicate. This is intentionally a simple
# time-window check, not a distributed dedup system -- sufficient for a
# single-process Django dev/lab deployment poling on the order of minutes
# (e.g. "SOAK_REGRESSION + CHG-58 + iteration 2 + CPU" polled once a
# minute must not create hundreds of notifications). See the architecture
# doc's "Deduplication / correlation support" section for known limitations
# (not race-proof under concurrent publishers).
DEDUP_WINDOW = timedelta(minutes=5)

# Metadata safety policy: publish_event() rejects (raises ValueError, does
# not silently strip) any metadata key whose name looks secret-shaped. This
# is a hard boundary, not a filter -- callers must not put secrets in
# metadata at all, per the Phase 4 brief. The denylist itself now lives in
# core.services.secret_policy so Phase 8's Change/DeviceIntent/Configlet
# models share exactly one policy instead of a second, drifting copy.
def _validate_metadata(metadata: dict) -> dict:
    return secret_policy.assert_no_secret_shaped_keys(metadata, context="Notification metadata")


def publish_event(
    *,
    event_type: str,
    severity: str,
    title: str,
    message: str,
    detail: str = "",
    source: str = "",
    device: str = "",
    interface: str = "",
    change_id: str = "",
    lifecycle_state: str = "",
    metadata: dict | None = None,
    detail_url: str = "",
    correlation_key: str = "",
    notify_slack: bool = True,
    is_test: bool = False,
) -> Notification:
    """
    The single entry point every Python subsystem should use to raise an
    operational event. Validates event_type/severity against the closed
    taxonomies, persists the notification first, then attempts Slack
    delivery (unless notify_slack=False) without ever losing the in-app
    record if that delivery fails.
    """
    if event_type not in Notification.EventType.values:
        raise ValueError(f"Unknown event_type {event_type!r}")
    if severity not in Notification.Severity.values:
        raise ValueError(f"Unknown severity {severity!r}")
    if not title:
        raise ValueError("title is required")
    if not message:
        raise ValueError("message is required")

    metadata = _validate_metadata(dict(metadata or {}))

    if correlation_key:
        cutoff = timezone.now() - DEDUP_WINDOW
        existing = (
            Notification.objects.filter(correlation_key=correlation_key, created_at__gte=cutoff)
            .order_by("-created_at")
            .first()
        )
        if existing is not None:
            return existing

    notification = Notification.objects.create(
        event_type=event_type,
        severity=severity,
        title=title,
        message=message,
        detail=detail,
        source=source,
        device=device,
        interface=interface,
        change_id=change_id,
        lifecycle_state=lifecycle_state,
        metadata=metadata,
        detail_url=detail_url,
        correlation_key=correlation_key,
        is_test=is_test,
        slack_status=Notification.SlackStatus.PENDING,
    )

    if notify_slack:
        _attempt_slack_delivery(notification)
    else:
        notification.slack_status = Notification.SlackStatus.SKIPPED
        notification.slack_attempted_at = timezone.now()
        notification.save(update_fields=["slack_status", "slack_attempted_at"])

    return notification


def _attempt_slack_delivery(notification: Notification) -> Notification:
    if not slack_service.is_configured():
        notification.slack_status = Notification.SlackStatus.NOT_CONFIGURED
        notification.slack_attempted_at = timezone.now()
        notification.save(update_fields=["slack_status", "slack_attempted_at"])
        return notification

    result = slack_service.send_notification(notification)
    notification.slack_status = result.status
    notification.slack_error = result.error
    notification.slack_attempted_at = timezone.now()
    notification.save(update_fields=["slack_status", "slack_error", "slack_attempted_at"])
    return notification


def retry_slack_delivery(notification_id: int) -> Notification:
    """Simple, bounded manual retry -- not an automatic/infinite retry loop."""
    notification = get_object_or_404(Notification, pk=notification_id)
    return _attempt_slack_delivery(notification)


def get_recent_notifications(
    limit: int | None = MAX_DROPDOWN_NOTIFICATIONS, unread_only: bool = False
) -> list[Notification]:
    """
    Returns at most `limit` notifications, newest first (`limit=None` means
    unbounded -- used by the full Notification Center).
    """
    queryset = Notification.objects.all()
    if unread_only:
        queryset = queryset.filter(is_read=False)
    if limit is not None:
        queryset = queryset[:limit]
    return list(queryset)


def list_notifications(
    *, unread_only: bool = False, severity: str | None = None, event_type: str | None = None
):
    """Unbounded, filterable queryset for the Notification Center (paginated by the view)."""
    queryset = Notification.objects.all()
    if unread_only:
        queryset = queryset.filter(is_read=False)
    if severity:
        queryset = queryset.filter(severity=severity)
    if event_type:
        queryset = queryset.filter(event_type=event_type)
    return queryset


def get_unread_count() -> int:
    return Notification.objects.filter(is_read=False).count()


def get_notification_or_404(notification_id: int) -> Notification:
    return get_object_or_404(Notification, pk=notification_id)


def mark_read(notification_id: int) -> Notification:
    notification = get_object_or_404(Notification, pk=notification_id)
    if not notification.is_read:
        notification.is_read = True
        notification.read_at = timezone.now()
        notification.save(update_fields=["is_read", "read_at"])
    return notification


def mark_all_read() -> int:
    """Returns the number of notifications newly marked read."""
    return Notification.objects.filter(is_read=False).update(is_read=True, read_at=timezone.now())


def severity_choices():
    return Notification.Severity.choices


def event_type_choices():
    return Notification.EventType.choices
