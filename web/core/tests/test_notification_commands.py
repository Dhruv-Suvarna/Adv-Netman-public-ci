import os
from io import StringIO
from unittest import mock

from django.core.management import call_command
from django.test import TestCase

from core.models import Notification


class SendTestNotificationCommandTests(TestCase):
    def test_creates_a_clearly_labelled_test_notification(self):
        out = StringIO()
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("SLACK_WEBHOOK_URL", None)
            call_command("send_test_notification", stdout=out)
        self.assertEqual(Notification.objects.count(), 1)
        notification = Notification.objects.get()
        self.assertTrue(notification.is_test)
        self.assertEqual(notification.event_type, Notification.EventType.TEST)
        self.assertIn("TEST", notification.title.upper() + notification.message.upper())
        self.assertIn("Created TEST notification", out.getvalue())

    def test_no_slack_flag_skips_delivery(self):
        with mock.patch.dict(os.environ, {"SLACK_WEBHOOK_URL": "https://hooks.slack.example/fake"}):
            call_command("send_test_notification", "--no-slack", stdout=StringIO())
        notification = Notification.objects.get()
        self.assertEqual(notification.slack_status, Notification.SlackStatus.SKIPPED)

    def test_severity_option_is_applied(self):
        call_command("send_test_notification", "--severity", "WARNING", stdout=StringIO())
        notification = Notification.objects.get()
        self.assertEqual(notification.severity, Notification.Severity.WARNING)

    def test_command_never_touches_devices_or_netbox(self):
        # Static guarantee: the command module imports nothing automation-related.
        import ast
        import inspect

        from core.management.commands import send_test_notification

        source = inspect.getsource(send_test_notification)
        tree = ast.parse(source)
        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module.split(".")[0])
        for forbidden in ("netmiko", "pynetbox", "paramiko", "subprocess"):
            self.assertNotIn(forbidden, imported)


class CleanupTestNotificationsCommandTests(TestCase):
    def setUp(self):
        Notification.objects.create(
            event_type=Notification.EventType.TEST, severity=Notification.Severity.INFO,
            title="test one", message="m", is_test=True,
        )
        Notification.objects.create(
            event_type=Notification.EventType.DEVICE_HEALTH_CRITICAL, severity=Notification.Severity.CRITICAL,
            title="real alert", message="m", is_test=False,
        )

    def test_dry_run_does_not_delete(self):
        out = StringIO()
        call_command("cleanup_test_notifications", stdout=out)
        self.assertEqual(Notification.objects.count(), 2)
        self.assertIn("would be deleted", out.getvalue())

    def test_apply_deletes_only_test_notifications(self):
        call_command("cleanup_test_notifications", "--apply", stdout=StringIO())
        remaining = list(Notification.objects.all())
        self.assertEqual(len(remaining), 1)
        self.assertEqual(remaining[0].title, "real alert")
