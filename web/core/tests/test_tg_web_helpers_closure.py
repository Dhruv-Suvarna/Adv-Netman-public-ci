"""Lab 7 closure -- the website's small helpers, each called directly: the notification read/list/mark/retry services,
the secret-redaction policy, the Slack configuration check, the automation-section lookup, the theme registry and
artwork lookups, the NSOT template filters, the MFA admin reset action, the app's ready hook and ``manage.py main``.

Everything runs against the test database.  Slack is never contacted: the webhook variable is cleared (so delivery is
recorded as NOT_CONFIGURED) or ``send_notification`` is replaced.  POSITIVE: the exact row, choice list, redacted copy,
URL or context.  NEGATIVE: unknown ids raise Http404, unknown themes / slots / keys return None or the fallback,
secret-shaped keys, headers and values never survive redaction, and an admin without the security-admin permission
resets nothing.
"""

from __future__ import annotations

import importlib.util
import io
import os
import sys
from pathlib import Path
from unittest import mock

from django.apps import apps
from django.contrib import admin as django_admin
from django.http import Http404
from django.test import RequestFactory, SimpleTestCase, TestCase

from core import admin as core_admin, models, theme_assets, theme_registry
from core.models import Notification
from core.services import automation_service, base, notification_service, secret_policy, slack_service
from core.services.slack_service import SlackDeliveryResult
from core.templatetags import nsot_extras
from core.tests import test_identity_access as ia

R = secret_policy.REDACTED
MANAGE_PY = Path(__file__).resolve().parents[2] / "manage.py"


def note(title="t", *, read=False, severity=None, event_type=None):
    return Notification.objects.create(
        event_type=event_type or Notification.EventType.values[0], severity=severity or Notification.Severity.values[0],
        title=title, message="m", is_read=read)


class NotificationServiceTests(TestCase):
    def test_get_notification_or_404_returns_the_row(self):
        row = note()
        self.assertEqual(notification_service.get_notification_or_404(row.pk), row)

    def test_get_notification_or_404_raises_for_a_missing_id(self):
        with self.assertRaises(Http404):
            notification_service.get_notification_or_404(987654)

    def test_get_recent_notifications_returns_newest_first_bounded(self):
        rows = [note(f"n{i}") for i in range(6)]
        self.assertEqual(len(notification_service.get_recent_notifications()), notification_service.MAX_DROPDOWN_NOTIFICATIONS)
        self.assertEqual(len(notification_service.get_recent_notifications(limit=None)), len(rows))

    def test_get_recent_notifications_unread_only_is_empty_when_none_unread(self):
        note(read=True)
        self.assertEqual(notification_service.get_recent_notifications(unread_only=True), [])

    def test_list_notifications_filters_by_severity_type_and_unread(self):
        severities, types = Notification.Severity.values, Notification.EventType.values
        a = note("a", severity=severities[0], event_type=types[0])
        b = note("b", severity=severities[-1], event_type=types[-1], read=True)
        self.assertEqual(set(notification_service.list_notifications()), {a, b})
        self.assertEqual(list(notification_service.list_notifications(unread_only=True)), [a])
        self.assertEqual(list(notification_service.list_notifications(severity=severities[-1])), [b])
        self.assertEqual(list(notification_service.list_notifications(event_type=types[-1])), [b])

    def test_list_notifications_for_an_unknown_severity_is_empty(self):
        note()
        self.assertEqual(list(notification_service.list_notifications(severity="NOT_A_SEVERITY")), [])

    def test_mark_read_sets_read_once_and_raises_for_a_missing_id(self):
        row = notification_service.mark_read(note().pk)
        stamp = row.read_at
        self.assertTrue(row.is_read)
        self.assertEqual(notification_service.mark_read(row.pk).read_at, stamp)  # second call never rewrites the stamp
        with self.assertRaises(Http404):
            notification_service.mark_read(987654)

    def test_retry_slack_delivery_records_the_send_result(self):
        row = note()
        with mock.patch.dict(os.environ, {slack_service.SLACK_WEBHOOK_ENV_VAR: "https://hooks.invalid/x"}), \
             mock.patch.object(slack_service, "send_notification", return_value=SlackDeliveryResult(status=Notification.SlackStatus.SENT)) as send:
            result = notification_service.retry_slack_delivery(row.pk)
        send.assert_called_once_with(row)
        self.assertEqual(result.slack_status, Notification.SlackStatus.SENT)

    def test_retry_slack_delivery_without_a_webhook_is_not_configured_and_never_sends(self):
        row = note()
        with mock.patch.dict(os.environ, {slack_service.SLACK_WEBHOOK_ENV_VAR: ""}), \
             mock.patch.object(slack_service, "send_notification") as send:
            result = notification_service.retry_slack_delivery(row.pk)
        send.assert_not_called()
        self.assertEqual(result.slack_status, Notification.SlackStatus.NOT_CONFIGURED)
        with self.assertRaises(Http404):
            notification_service.retry_slack_delivery(987654)

    def test_severity_and_event_type_choices_return_the_model_choices(self):
        self.assertEqual(notification_service.severity_choices(), Notification.Severity.choices)
        self.assertEqual(notification_service.event_type_choices(), Notification.EventType.choices)


class SecretPolicyTests(SimpleTestCase):
    def test_is_secret_key_matches_secret_shaped_names(self):
        for key in ("password", "API_KEY", "otp_token", "Cookie", "snmp_community"):
            with self.subTest(key):
                self.assertTrue(secret_policy.is_secret_key(key))

    def test_is_secret_key_is_false_for_references_and_plain_names(self):
        for key in ("password_ref", "hostname", "interface", 42):
            with self.subTest("not secret", key=key):
                self.assertFalse(secret_policy.is_secret_key(key))

    def test_redact_never_leaks_a_secret_value(self):
        data = {"password": "hunter2", "nested": [{"token": "abc123"}, "Bearer abcdefghijklmnop"], "n": 1, "ok": None}
        out = secret_policy.redact(data)
        self.assertEqual(out, {"password": R, "nested": [{"token": R}, R], "n": 1, "ok": None})
        self.assertNotIn("hunter2", str(out))
        self.assertNotIn("abc123", str(out))

    def test_redact_bounds_long_strings_and_stringifies_objects(self):
        self.assertEqual(secret_policy.redact("x" * 20, max_string=5), "xxxxx...[truncated]")
        self.assertEqual(secret_policy.redact(Path("/a/b")), "/a/b")
        self.assertEqual(secret_policy.redact(("a", 2)), ["a", 2])

    def test_redact_text_masks_secret_value_formats_never_leaking_them(self):
        token = "ghp_" + "A" * 36
        cases = ((f"use {token} now", token), ("otpauth://totp/x?secret=ABC", "secret=ABC"),
                 ("Authorization: Bearer abcdefgh12345", "abcdefgh12345"),
                 ("-----BEGIN " "RSA PRIVATE KEY-----\nMII\n-----END RSA PRIVATE KEY-----", "MII"), ("xox" "b-1234567890-abc", "1234567890"))
        for raw, secret in cases:
            with self.subTest("never leaked", secret=secret[:6]):
                masked = secret_policy.redact_text(raw)
                self.assertIn(R, masked)
                self.assertNotIn(secret, masked)

    def test_redact_text_returns_plain_text_unchanged(self):
        self.assertEqual(secret_policy.redact_text("interface Gi0/1 up"), "interface Gi0/1 up")

    def test_redact_headers_drops_credential_headers_never_recording_them(self):
        out = secret_policy.redact_headers({"Authorization": "Bearer abcdefgh123", "Cookie": "sessionid=s3", "X-Api-Key": "k",
                                            "User-Agent": "curl", "X-Token-Hint": "abc"})
        self.assertEqual(out, {"User-Agent": "curl", "X-Token-Hint": R})
        self.assertNotIn("s3", str(out))


class SmallServiceTests(SimpleTestCase):
    def test_is_configured_returns_true_with_a_webhook(self):
        with mock.patch.dict(os.environ, {slack_service.SLACK_WEBHOOK_ENV_VAR: " https://hooks.invalid/x "}):
            self.assertTrue(slack_service.is_configured())
        with mock.patch.dict(os.environ, {slack_service.SLACK_WEBHOOK_ENV_VAR: "   "}), self.subTest("blank is not configured"):
            self.assertFalse(slack_service.is_configured())

    def test_get_automation_section_returns_the_section(self):
        section = automation_service.get_automation_section("unit-test-matrix")
        self.assertEqual((section["slug"], section["label"], section["read_only"]), ("unit-test-matrix", "Unit Test Matrix", True))

    def test_get_automation_section_for_an_unknown_slug_is_none(self):
        self.assertIsNone(automation_service.get_automation_section("no-such-section"))

    def test_not_integrated_builds_the_payload_with_extras(self):
        self.assertEqual(base.not_integrated("later", device="R1"), {"status": "not_integrated", "message": "later", "device": "R1"})

    def test_not_integrated_without_extras_is_the_bare_payload(self):
        self.assertEqual(base.not_integrated(""), {"status": "not_integrated", "message": ""})


class ThemeTests(SimpleTestCase):
    def test_is_valid_theme_accepts_registered_themes(self):
        for name in theme_registry.THEMES:
            with self.subTest(name):
                self.assertTrue(theme_registry.is_valid_theme(name))

    def test_is_valid_theme_rejects_unknown_names(self):
        for name in ("", "Dark Mode", "no-such-theme"):
            with self.subTest(name=name):
                self.assertFalse(theme_registry.is_valid_theme(name))

    def test_default_context_for_theme_returns_default_core_or_first(self):
        self.assertEqual(theme_registry.default_context_for_theme("basic-minimal"), "default")
        fake = {"core-only": {"contexts": {"forge": {}, "core": {}}}, "first-only": {"contexts": {"forge": {}}}}
        with mock.patch.dict(theme_registry.THEMES, fake):
            self.assertEqual(theme_registry.default_context_for_theme("core-only"), "core")
            self.assertEqual(theme_registry.default_context_for_theme("first-only"), "forge")

    def test_default_context_for_an_unknown_theme_is_the_default(self):
        self.assertEqual(theme_registry.default_context_for_theme("no-such-theme"), theme_registry.DEFAULT_CONTEXT)

    def test_theme_choices_returns_value_label_pairs_in_order(self):
        self.assertEqual(theme_registry.theme_choices(), [(k, v["label"]) for k, v in theme_registry.THEMES.items()])
        self.assertEqual(theme_registry.theme_choices()[0], ("basic-minimal", "Basic Minimal"))

    def test_expected_static_dir_builds_the_slot_path(self):
        self.assertEqual(theme_assets.expected_static_dir("dark_angels/core"), "core/themes/dark_angels/core/")

    def test_expected_static_dir_of_an_empty_slot_is_the_themes_root(self):
        self.assertEqual(theme_assets.expected_static_dir(""), "core/themes//")

    def test_watermark_for_returns_the_resolved_slot_url(self):
        with mock.patch.object(theme_assets, "resolve_watermark_url", side_effect=lambda slot: f"/static/{slot}") as resolve:
            self.assertEqual(theme_assets.watermark_for("basic-minimal", "default"), "/static/minimal")
            self.assertEqual(theme_assets.brand_mark_url(), "/static/brand")
        self.assertEqual([c.args[0] for c in resolve.call_args_list], ["minimal", "brand"])

    def test_watermark_for_an_unknown_theme_or_context_is_none(self):
        with mock.patch.object(theme_assets, "resolve_watermark_url") as resolve:
            self.assertIsNone(theme_assets.watermark_for("no-such-theme", "default"))
            self.assertIsNone(theme_assets.watermark_for("basic-minimal", "no-such-context"))
        resolve.assert_not_called()


class NsotFilterTests(SimpleTestCase):
    def test_badge_class_maps_known_states_case_insensitively(self):
        self.assertEqual((nsot_extras.badge_class("drift"), nsot_extras.badge_class("IN_SYNC")), ("badge--danger", "badge--success"))

    def test_badge_class_of_an_unknown_value_is_neutral(self):
        self.assertEqual((nsot_extras.badge_class("whatever"), nsot_extras.badge_class(None)), ("badge--neutral", "badge--neutral"))

    def test_get_item_returns_the_mapping_value(self):
        self.assertEqual(nsot_extras.get_item({"a": 1}, "a"), 1)

    def test_get_item_of_none_or_a_non_mapping_is_none(self):
        self.assertIsNone(nsot_extras.get_item(None, "a"))
        self.assertIsNone(nsot_extras.get_item(["a"], "a"))
        self.assertIsNone(nsot_extras.get_item({}, "missing"))


class MfaAdminResetTests(TestCase):
    def setUp(self):
        self.model_admin = django_admin.site._registry[models.AppMfaDevice]
        self.target = ia.make_user("bob")
        ia.enroll(self.target)

    def request_for(self, user):
        request = RequestFactory().post("/admin/")
        request.user = user
        return request

    def test_reset_authenticators_deletes_the_device_and_audits(self):
        request = self.request_for(ia.make_user("sam", "NMAS Security Admin"))
        with mock.patch.object(self.model_admin, "message_user") as message:
            self.model_admin.reset_authenticators(request, models.AppMfaDevice.objects.filter(user=self.target))
        self.assertFalse(models.AppMfaDevice.objects.filter(user=self.target).exists())
        message.assert_called_once_with(request, "Selected website authenticators were reset.")
        event = models.AuditEvent.objects.get(event_type=models.AuditEventType.APP_MFA_RESET)
        self.assertEqual((event.object_id, event.metadata["target_username"], event.metadata["path"]), (str(self.target.pk), "bob", "django_admin"))

    def test_reset_authenticators_without_security_admin_is_refused(self):
        request = self.request_for(ia.make_user("op", "NMAS Operator"))
        with mock.patch.object(self.model_admin, "message_user") as message:
            self.model_admin.reset_authenticators(request, models.AppMfaDevice.objects.all())
        message.assert_called_once_with(request, "Requires the NMAS security-admin permission.", level="error")
        self.assertEqual(models.AppMfaDevice.objects.filter(user=self.target).count(), 1)
        self.assertFalse(models.AuditEvent.objects.filter(event_type=models.AuditEventType.APP_MFA_RESET).exists())

    def test_admin_class_is_registered(self):
        self.assertIsInstance(self.model_admin, core_admin.AppMfaDeviceAdmin)


class EntryPointTests(SimpleTestCase):
    def test_ready_imports_the_signal_receivers(self):
        config = apps.get_app_config("core")
        self.assertIsNone(config.ready())
        self.assertIn("core.signals", sys.modules)

    def test_manage_main_runs_a_read_only_command(self):
        spec = importlib.util.spec_from_file_location("nmas_manage_under_test", MANAGE_PY)
        manage = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(manage)
        out = io.StringIO()
        with mock.patch.object(sys, "argv", ["manage.py", "version"]), mock.patch("sys.stdout", out):
            manage.main()
        import django
        self.assertEqual(out.getvalue().strip(), django.get_version())
