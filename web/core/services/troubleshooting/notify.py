"""Best-effort engineer notification: email the configured recipients when a troubleshooting issue is raised.

Recipients come from ``settings.NMAS_TS_ALERT_EMAILS`` (environment ``NMAS_TS_ALERT_EMAILS``, comma-separated), never from
source.  A notification failure is logged and swallowed: it must never block or roll back case intake.
"""

from __future__ import annotations

import logging

from django.conf import settings
from django.core.mail import send_mail

log = logging.getLogger(__name__)


def recipients() -> list[str]:
    return [a for a in getattr(settings, "NMAS_TS_ALERT_EMAILS", ()) if a]


def notify_issue(case) -> bool:
    """Send one issue email for ``case``.  True if handed to the mail backend; False if disabled or the send failed."""
    to = recipients()
    if not to:
        return False
    devices = ", ".join((case.affected_scope or {}).get("devices", []))
    subject = f"[NMAS] Troubleshooting issue {case.case_id}: {case.title or 'untitled'}"[:200]
    body = (f"NMAS opened troubleshooting case {case.case_id}.\n\n"
            f"Severity: {case.severity}\nDevices: {devices}\nSymptom: {case.symptom}\n"
            f"Opened: {case.opened_at:%Y-%m-%d %H:%M:%S %Z}\n\nReview it in the NMAS Troubleshooter.\n")
    try:
        send_mail(subject, body, getattr(settings, "DEFAULT_FROM_EMAIL", None), to, fail_silently=False)
        return True
    except Exception as exc:  # pylint: disable=broad-exception-caught  # noqa: BLE001 - notification is best-effort
        log.warning("issue notification for %s failed: %s", case.case_id, type(exc).__name__)
        return False
