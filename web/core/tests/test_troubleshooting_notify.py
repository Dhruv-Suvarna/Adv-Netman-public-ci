"""Engineer issue email: sent on committed case intake, disabled without recipients, never breaks the caller."""

from __future__ import annotations

from datetime import datetime, timezone
from types import SimpleNamespace
from unittest import mock

from django.core import mail
from django.test import SimpleTestCase, TestCase, override_settings

from core.services.troubleshooting import notify
from core.services.troubleshooting import repository as repo

CASE = SimpleNamespace(case_id="TS-20261117-ABCDEF12", title="R2 health alarm", severity="MEDIUM", symptom="R2 degraded",
                       affected_scope={"devices": ["R2"]}, opened_at=datetime(2026, 11, 17, 6, 0, tzinfo=timezone.utc))


@override_settings(EMAIL_BACKEND="django.core.mail.backends.locmem.EmailBackend")
class NotifyIssueTests(SimpleTestCase):
    @override_settings(NMAS_TS_ALERT_EMAILS=("engineer@example.com",))
    def test_sends_one_email_with_case_details(self):
        self.assertTrue(notify.notify_issue(CASE))
        self.assertEqual(len(mail.outbox), 1)
        msg = mail.outbox[0]
        self.assertEqual(msg.to, ["engineer@example.com"])
        self.assertIn("TS-20261117-ABCDEF12", msg.subject)
        self.assertIn("Devices: R2", msg.body)

    @override_settings(NMAS_TS_ALERT_EMAILS=())
    def test_disabled_without_recipients(self):
        self.assertFalse(notify.notify_issue(CASE))
        self.assertEqual(len(mail.outbox), 0)

    @override_settings(NMAS_TS_ALERT_EMAILS=("engineer@example.com",))
    def test_send_failure_is_swallowed(self):
        with mock.patch.object(notify, "send_mail", side_effect=OSError("smtp down")):
            self.assertFalse(notify.notify_issue(CASE))


@override_settings(EMAIL_BACKEND="django.core.mail.backends.locmem.EmailBackend", NMAS_TS_ALERT_EMAILS=("engineer@example.com",))
class OpenCaseNotificationTests(TestCase):
    def test_open_case_emails_after_commit(self):
        actor = repo.Actor("operator", "user", tenant="default")
        with self.captureOnCommitCallbacks(execute=True):
            case = repo.open_case(actor, trigger_source="operator", title="R2 alarm", symptom="R2 degraded",
                                  service_intent={"service": "H1-H2"}, affected_scope={"devices": ["R2"]}, runbook="RB02")
        self.assertEqual(len(mail.outbox), 1)
        self.assertIn(case.case_id, mail.outbox[0].subject)
