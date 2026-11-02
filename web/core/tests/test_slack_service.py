"""
Slack adapter tests. No test in this file makes a real network call --
every HTTP interaction is mocked via unittest.mock.patch.object on the
`urlopen` name imported into core.services.slack_service.
"""

import io
import os
from unittest import mock
from urllib.error import HTTPError, URLError

from django.test import TestCase
from django.urls import reverse

from core.models import Notification
from core.services import notification_service, slack_service


def _make_notification(**overrides):
    defaults = dict(
        event_type=Notification.EventType.TEST,
        severity=Notification.Severity.WARNING,
        title="Soak regression detected",
        message="R5 CPU regression",
        device="R5",
        change_id="CHG-58",
    )
    defaults.update(overrides)
    return Notification.objects.create(**defaults)


class _FakeResponse:
    def __init__(self, status=200, body=b"ok"):
        self.status = status
        self._body = body

    def read(self):
        return self._body

    def getcode(self):
        return self.status

    def __enter__(self):
        return self

    def __exit__(self, *exc_info):
        return False


class NotConfiguredTests(TestCase):
    def test_is_configured_false_without_env_var(self):
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop(slack_service.SLACK_WEBHOOK_ENV_VAR, None)
            self.assertFalse(slack_service.is_configured())

    def test_send_notification_returns_not_configured(self):
        notification = _make_notification()
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop(slack_service.SLACK_WEBHOOK_ENV_VAR, None)
            result = slack_service.send_notification(notification)
        self.assertEqual(result.status, Notification.SlackStatus.NOT_CONFIGURED)

    def test_publish_event_records_not_configured(self):
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop(slack_service.SLACK_WEBHOOK_ENV_VAR, None)
            notification = notification_service.publish_event(
                event_type=Notification.EventType.TEST,
                severity=Notification.Severity.INFO,
                title="a",
                message="b",
            )
        self.assertEqual(notification.slack_status, Notification.SlackStatus.NOT_CONFIGURED)


class MockedSlackDeliveryTests(TestCase):
    def setUp(self):
        self._env_patch = mock.patch.dict(os.environ, {slack_service.SLACK_WEBHOOK_ENV_VAR: "https://hooks.slack.example/T000/B000/fake"})
        self._env_patch.start()
        self.addCleanup(self._env_patch.stop)

    def test_mocked_success_records_sent(self):
        notification = _make_notification()
        with mock.patch.object(slack_service, "urlopen", return_value=_FakeResponse(status=200)) as urlopen:
            result = slack_service.send_notification(notification)
        urlopen.assert_called_once()
        self.assertEqual(result.status, Notification.SlackStatus.SENT)

    def test_mocked_http_error_records_failed(self):
        notification = _make_notification()
        http_error = HTTPError(url="https://hooks.slack.example", code=404, msg="not_found", hdrs=None, fp=io.BytesIO(b"no_such_webhook"))
        with mock.patch.object(slack_service, "urlopen", side_effect=http_error):
            result = slack_service.send_notification(notification)
        self.assertEqual(result.status, Notification.SlackStatus.FAILED)
        self.assertIn("404", result.error)

    def test_mocked_url_error_records_failed(self):
        notification = _make_notification()
        with mock.patch.object(slack_service, "urlopen", side_effect=URLError("connection refused")):
            result = slack_service.send_notification(notification)
        self.assertEqual(result.status, Notification.SlackStatus.FAILED)

    def test_mocked_timeout_records_failed_safely(self):
        notification = _make_notification()
        with mock.patch.object(slack_service, "urlopen", side_effect=TimeoutError):
            result = slack_service.send_notification(notification)
        self.assertEqual(result.status, Notification.SlackStatus.FAILED)
        self.assertIn("Timed out", result.error)

    def test_slack_failure_does_not_delete_in_app_notification(self):
        with mock.patch.object(slack_service, "urlopen", side_effect=URLError("boom")):
            notification = notification_service.publish_event(
                event_type=Notification.EventType.TEST,
                severity=Notification.Severity.WARNING,
                title="a",
                message="b",
            )
        self.assertTrue(Notification.objects.filter(pk=notification.pk).exists())
        notification.refresh_from_db()
        self.assertEqual(notification.slack_status, Notification.SlackStatus.FAILED)

    def test_mocked_success_via_publish_event_records_sent(self):
        with mock.patch.object(slack_service, "urlopen", return_value=_FakeResponse(status=200)):
            notification = notification_service.publish_event(
                event_type=Notification.EventType.TEST,
                severity=Notification.Severity.INFO,
                title="a",
                message="b",
            )
        self.assertEqual(notification.slack_status, Notification.SlackStatus.SENT)

    def test_no_real_http_call_when_mocked(self):
        # Any accidental real call would try to hit hooks.slack.example and
        # raise/hang; asserting the mock was used (not a real socket) is
        # the point of every test above. This test just double-checks the
        # mock is actually intercepting, not bypassed.
        notification = _make_notification()
        with mock.patch.object(slack_service, "urlopen") as urlopen:
            urlopen.return_value = _FakeResponse(status=200)
            slack_service.send_notification(notification)
        self.assertTrue(urlopen.called)
        called_request = urlopen.call_args[0][0]
        self.assertEqual(called_request.full_url, "https://hooks.slack.example/T000/B000/fake")


class WebhookNeverExposedTests(TestCase):
    def test_webhook_url_not_in_rendered_notification_pages(self):
        secret_url = "https://hooks.slack.example/T000/B000/super-secret-path"
        with mock.patch.dict(os.environ, {slack_service.SLACK_WEBHOOK_ENV_VAR: secret_url}):
            with mock.patch.object(slack_service, "urlopen", return_value=_FakeResponse(status=200)):
                notification = notification_service.publish_event(
                    event_type=Notification.EventType.TEST,
                    severity=Notification.Severity.INFO,
                    title="a",
                    message="b",
                )
            detail = self.client.get(reverse("core:notification_detail", args=[notification.pk]))
            listing = self.client.get(reverse("core:notifications"))
            home = self.client.get(reverse("core:home"))
        for response in (detail, listing, home):
            self.assertNotIn(secret_url, response.content.decode())
            self.assertNotIn("super-secret-path", response.content.decode())

    def test_webhook_url_not_stored_on_model(self):
        with mock.patch.dict(os.environ, {slack_service.SLACK_WEBHOOK_ENV_VAR: "https://hooks.slack.example/secret"}):
            with mock.patch.object(slack_service, "urlopen", return_value=_FakeResponse(status=200)):
                notification = notification_service.publish_event(
                    event_type=Notification.EventType.TEST,
                    severity=Notification.Severity.INFO,
                    title="a",
                    message="b",
                )
        field_names = {f.name for f in Notification._meta.get_fields()}
        self.assertNotIn("webhook", field_names)
        self.assertNotIn("slack_webhook_url", field_names)


class BuildMessageTests(TestCase):
    def test_message_includes_severity_title_device_change_id(self):
        notification = _make_notification()
        payload = slack_service.build_message(notification)
        text = payload["text"]
        self.assertIn("WARNING", text)
        self.assertIn("Soak regression detected", text)
        self.assertIn("R5", text)
        self.assertIn("CHG-58", text)
        self.assertIn(str(notification.pk), text)

    def test_no_detail_link_without_app_base_url(self):
        notification = _make_notification()
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop(slack_service.APP_BASE_URL_ENV_VAR, None)
            payload = slack_service.build_message(notification)
        self.assertNotIn("127.0.0.1", payload["text"])
        self.assertNotIn("Details:", payload["text"])

    def test_detail_link_included_when_app_base_url_configured(self):
        notification = _make_notification()
        with mock.patch.dict(os.environ, {slack_service.APP_BASE_URL_ENV_VAR: "https://nmas.example.org"}):
            payload = slack_service.build_message(notification)
        self.assertIn("https://nmas.example.org/notifications/", payload["text"])
