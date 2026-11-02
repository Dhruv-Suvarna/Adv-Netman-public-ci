"""
Slack delivery channel: the one adapter that knows how to turn a
Notification into an outbound Slack message.

Design boundaries (see docs/NOTIFICATION_AND_SLACK_ARCHITECTURE.md):
 - This module is the ONLY place that talks to Slack. Nothing else in the
   project should call urllib/requests against a Slack URL.
 - The webhook URL lives ONLY in the SLACK_WEBHOOK_URL environment
   variable. It is read at send time, never stored on a model, never
   logged, never placed in a template context.
 - Standard library only (urllib) -- this project's dependency convention
   (see web/requirements.txt) is to add a package only when the standard
   library is genuinely insufficient; POSTing one small JSON payload with a
   timeout is not that case, and requests is already a monitoring/ only
   dependency (monitoring/requirements.txt), not a web/ one.
 - Bounded, synchronous, single attempt. No retry loop, no queue. A manual
   retry is available via notification_service.retry_slack_delivery().
"""

from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

logger = logging.getLogger("core.notifications.slack")

SLACK_WEBHOOK_ENV_VAR = "SLACK_WEBHOOK_URL"
APP_BASE_URL_ENV_VAR = "APP_BASE_URL"
REQUEST_TIMEOUT_SECONDS = 5


@dataclass
class SlackDeliveryResult:
    status: str  # one of Notification.SlackStatus values
    error: str = ""


def is_configured() -> bool:
    return bool(os.environ.get(SLACK_WEBHOOK_ENV_VAR, "").strip())


def _webhook_url() -> str | None:
    value = os.environ.get(SLACK_WEBHOOK_ENV_VAR, "").strip()
    return value or None


def _app_base_url() -> str | None:
    """
    Optional externally-reachable base URL for building a detail link in
    Slack messages. Never fabricated -- if unset, no link field is added
    (a localhost URL is never sent to Slack as though it were reachable).
    """
    value = os.environ.get(APP_BASE_URL_ENV_VAR, "").strip()
    return value.rstrip("/") if value else None


def build_message(notification) -> dict:
    """
    Builds a concise Slack Incoming Webhook payload from a Notification.
    Plain "text" payload (no Block Kit) -- this is intentionally simple;
    see the architecture doc for why Block Kit was not used.
    """
    lines = [f"[{notification.severity}] {notification.title}"]
    if notification.message:
        lines.append(notification.message)

    context_bits = []
    if notification.device:
        context_bits.append(f"Device: {notification.device}")
    if notification.change_id:
        context_bits.append(f"Change: {notification.change_id}")
    if context_bits:
        lines.append(" · ".join(context_bits))

    lines.append(
        f"Event: {notification.event_type} · ID {notification.pk} · "
        f"{notification.created_at.isoformat()}"
    )

    base_url = _app_base_url()
    if base_url:
        lines.append(f"Details: {base_url}{notification.get_absolute_url()}")

    return {"text": "\n".join(lines)}


def send_notification(notification) -> SlackDeliveryResult:
    """
    Attempts one bounded, synchronous delivery. Never raises -- every
    failure mode (missing config, HTTP error, network error, timeout,
    anything unexpected) is caught and returned as a SlackDeliveryResult so
    the caller can persist it without risking the in-app notification.
    """
    from ..models import Notification  # local import avoids a hard app-loading cycle

    webhook_url = _webhook_url()
    if not webhook_url:
        return SlackDeliveryResult(status=Notification.SlackStatus.NOT_CONFIGURED)

    payload = build_message(notification)
    data = json.dumps(payload).encode("utf-8")
    request = Request(
        webhook_url,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    try:
        with urlopen(request, timeout=REQUEST_TIMEOUT_SECONDS) as response:
            status_code = getattr(response, "status", response.getcode())
            body = response.read().decode("utf-8", errors="replace")
            if 200 <= status_code < 300:
                return SlackDeliveryResult(status=Notification.SlackStatus.SENT)
            return SlackDeliveryResult(
                status=Notification.SlackStatus.FAILED,
                error=f"HTTP {status_code}: {body[:200]}",
            )
    except HTTPError as exc:
        body = ""
        try:
            body = exc.read().decode("utf-8", errors="replace")[:200]
        except Exception:  # pragma: no cover - defensive only
            pass
        return SlackDeliveryResult(
            status=Notification.SlackStatus.FAILED,
            error=f"HTTP {exc.code}: {exc.reason} {body}".strip(),
        )
    except URLError as exc:
        reason = getattr(exc, "reason", exc)
        return SlackDeliveryResult(
            status=Notification.SlackStatus.FAILED,
            error=f"Connection error: {reason}",
        )
    except TimeoutError:
        return SlackDeliveryResult(
            status=Notification.SlackStatus.FAILED,
            error=f"Timed out after {REQUEST_TIMEOUT_SECONDS}s",
        )
    except Exception:  # pragma: no cover - defensive catch-all
        logger.exception("Unexpected Slack delivery failure (notification id=%s)", notification.pk)
        return SlackDeliveryResult(
            status=Notification.SlackStatus.FAILED,
            error="Unexpected delivery error",
        )
