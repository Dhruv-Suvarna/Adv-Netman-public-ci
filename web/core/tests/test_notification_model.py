from django.core.exceptions import ValidationError
from django.test import TestCase

from core.models import Notification
from core.services import notification_service


class NotificationModelTests(TestCase):
    def test_persists_a_normalized_event(self):
        notification = Notification.objects.create(
            event_type=Notification.EventType.DEVICE_HEALTH_CRITICAL,
            severity=Notification.Severity.CRITICAL,
            title="R5 CPU critical",
            message="CPU exceeded threshold",
            device="R5",
            change_id="CHG-58",
            metadata={"candidate_iteration": 2},
        )
        notification.refresh_from_db()
        self.assertEqual(notification.device, "R5")
        self.assertEqual(notification.metadata, {"candidate_iteration": 2})

    def test_default_state_is_unread(self):
        notification = Notification.objects.create(
            event_type=Notification.EventType.TEST, severity=Notification.Severity.INFO,
            title="t", message="m",
        )
        self.assertFalse(notification.is_read)
        self.assertIsNone(notification.read_at)

    def test_default_slack_status_is_pending_before_publish_flow(self):
        notification = Notification.objects.create(
            event_type=Notification.EventType.TEST, severity=Notification.Severity.INFO,
            title="t", message="m",
        )
        self.assertEqual(notification.slack_status, Notification.SlackStatus.PENDING)

    def test_invalid_severity_fails_full_clean(self):
        notification = Notification(
            event_type=Notification.EventType.TEST, severity="NOT_A_SEVERITY",
            title="t", message="m",
        )
        with self.assertRaises(ValidationError):
            notification.full_clean()

    def test_invalid_event_type_fails_full_clean(self):
        notification = Notification(
            event_type="NOT_A_TYPE", severity=Notification.Severity.INFO,
            title="t", message="m",
        )
        with self.assertRaises(ValidationError):
            notification.full_clean()

    def test_newest_first_ordering(self):
        first = Notification.objects.create(
            event_type=Notification.EventType.TEST, severity=Notification.Severity.INFO, title="a", message="m",
        )
        second = Notification.objects.create(
            event_type=Notification.EventType.TEST, severity=Notification.Severity.INFO, title="b", message="m",
        )
        ordered = list(Notification.objects.all())
        self.assertEqual(ordered, [second, first])

    def test_get_absolute_url(self):
        notification = Notification.objects.create(
            event_type=Notification.EventType.TEST, severity=Notification.Severity.INFO, title="a", message="m",
        )
        self.assertEqual(notification.get_absolute_url(), f"/notifications/{notification.pk}/")


class PublishEventTests(TestCase):
    def test_publish_event_persists_and_sets_not_configured_without_env_var(self):
        notification = notification_service.publish_event(
            event_type=Notification.EventType.TEST,
            severity=Notification.Severity.INFO,
            title="hello",
            message="world",
        )
        self.assertIsNotNone(notification.pk)
        self.assertEqual(notification.slack_status, Notification.SlackStatus.NOT_CONFIGURED)

    def test_publish_event_notify_slack_false_marks_skipped(self):
        notification = notification_service.publish_event(
            event_type=Notification.EventType.TEST,
            severity=Notification.Severity.INFO,
            title="hello",
            message="world",
            notify_slack=False,
        )
        self.assertEqual(notification.slack_status, Notification.SlackStatus.SKIPPED)

    def test_publish_event_rejects_unknown_event_type(self):
        with self.assertRaises(ValueError):
            notification_service.publish_event(
                event_type="NOT_REAL", severity=Notification.Severity.INFO, title="a", message="b"
            )

    def test_publish_event_rejects_unknown_severity(self):
        with self.assertRaises(ValueError):
            notification_service.publish_event(
                event_type=Notification.EventType.TEST, severity="NOT_REAL", title="a", message="b"
            )

    def test_publish_event_rejects_secret_looking_metadata_keys(self):
        for key in ("password", "api_token", "slack_webhook", "credential_id"):
            with self.subTest(key=key):
                with self.assertRaises(ValueError):
                    notification_service.publish_event(
                        event_type=Notification.EventType.TEST,
                        severity=Notification.Severity.INFO,
                        title="a",
                        message="b",
                        metadata={key: "x"},
                    )

    def test_publish_event_allows_safe_metadata(self):
        notification = notification_service.publish_event(
            event_type=Notification.EventType.SOAK_REGRESSION,
            severity=Notification.Severity.WARNING,
            title="Soak regression",
            message="R5 CPU regression",
            metadata={"device": "R5", "affected_feature": "ecmp", "candidate_iteration": 2},
        )
        self.assertEqual(notification.metadata["affected_feature"], "ecmp")

    def test_correlation_key_dedups_within_window(self):
        first = notification_service.publish_event(
            event_type=Notification.EventType.SOAK_REGRESSION,
            severity=Notification.Severity.WARNING,
            title="Soak regression",
            message="R5 CPU regression",
            correlation_key="SOAK_REGRESSION:CHG-58:iter2:cpu",
        )
        second = notification_service.publish_event(
            event_type=Notification.EventType.SOAK_REGRESSION,
            severity=Notification.Severity.WARNING,
            title="Soak regression (again)",
            message="R5 CPU regression again",
            correlation_key="SOAK_REGRESSION:CHG-58:iter2:cpu",
        )
        self.assertEqual(first.pk, second.pk)
        self.assertEqual(Notification.objects.count(), 1)

    def test_different_correlation_keys_do_not_dedup(self):
        notification_service.publish_event(
            event_type=Notification.EventType.SOAK_REGRESSION,
            severity=Notification.Severity.WARNING,
            title="a", message="b", correlation_key="key-a",
        )
        notification_service.publish_event(
            event_type=Notification.EventType.SOAK_REGRESSION,
            severity=Notification.Severity.WARNING,
            title="a", message="b", correlation_key="key-b",
        )
        self.assertEqual(Notification.objects.count(), 2)


class ReadStateServiceTests(TestCase):
    def setUp(self):
        self.a = notification_service.publish_event(
            event_type=Notification.EventType.TEST, severity=Notification.Severity.INFO,
            title="a", message="m", notify_slack=False,
        )
        self.b = notification_service.publish_event(
            event_type=Notification.EventType.TEST, severity=Notification.Severity.INFO,
            title="b", message="m", notify_slack=False,
        )

    def test_unread_count(self):
        self.assertEqual(notification_service.get_unread_count(), 2)

    def test_mark_read(self):
        notification_service.mark_read(self.a.pk)
        self.assertEqual(notification_service.get_unread_count(), 1)
        self.a.refresh_from_db()
        self.assertTrue(self.a.is_read)
        self.assertIsNotNone(self.a.read_at)

    def test_mark_all_read(self):
        changed = notification_service.mark_all_read()
        self.assertEqual(changed, 2)
        self.assertEqual(notification_service.get_unread_count(), 0)


class NotificationSchemaContractTests(TestCase):
    def test_notification_model_fields_unchanged(self):
        field_names = {f.name for f in Notification._meta.get_fields()}
        expected = {
            "event_type", "severity", "title", "message", "detail", "source", "device", "interface",
            "change_id", "lifecycle_state", "metadata", "detail_url", "correlation_key", "is_read",
            "read_at", "created_at", "updated_at", "slack_status", "slack_error", "slack_attempted_at",
            "is_test",
        }
        self.assertTrue(expected.issubset(field_names))
