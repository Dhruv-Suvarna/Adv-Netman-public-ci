from django.test import TestCase
from django.urls import reverse

from core.models import Notification


class NotificationEmptyStateTests(TestCase):
    def test_empty_state_message_on_notifications_page(self):
        response = self.client.get(reverse("core:notifications"))
        self.assertContains(response, "No notifications yet.")

    def test_empty_state_message_in_header_dropdown(self):
        response = self.client.get(reverse("core:home"))
        self.assertContains(response, "No notifications yet.")

    def test_no_fake_operational_alerts_present(self):
        response = self.client.get(reverse("core:home")).content.decode()
        # A handful of representative fake-alert phrases that must never
        # appear as real-looking operational data invented by Django.
        for forbidden in ("devices_up", "devices_down", "3 critical alerts"):
            self.assertNotIn(forbidden, response)


def _make_notification(i, **overrides):
    defaults = {
        "event_type": Notification.EventType.TEST,
        "severity": Notification.Severity.INFO,
        "title": f"Event {i}",
        "message": f"Synthetic fixture event {i}",
        "slack_status": Notification.SlackStatus.SKIPPED,
        "is_test": True,
    }
    defaults.update(overrides)
    return Notification.objects.create(**defaults)


class NotificationDropdownFixtureTests(TestCase):
    """Proves the dropdown/list are real-DB backed and structurally limit to four."""

    def setUp(self):
        self.notifications = [_make_notification(i) for i in range(6)]

    def test_service_layer_limits_to_four_by_default(self):
        from core.services import notification_service

        self.assertEqual(len(notification_service.get_recent_notifications()), 4)

    def test_full_notifications_page_is_unbounded(self):
        from core.services import notification_service

        self.assertEqual(len(notification_service.get_recent_notifications(limit=None)), 6)

    def test_header_dropdown_renders_at_most_four(self):
        response = self.client.get(reverse("core:home")).content.decode()
        self.assertEqual(response.count('<a class="notification-item'), 4)

    def test_notifications_page_renders_all_six(self):
        response = self.client.get(reverse("core:notifications")).content.decode()
        main_content = response[response.index('class="page-content"'):]
        self.assertEqual(main_content.count('<a class="notification-item'), 6)

    def test_newest_first_ordering(self):
        # The dropdown only shows the latest four (2..5); ordering is
        # proven on the unbounded Notification Center page instead, where
        # all six fixtures are present.
        response = self.client.get(reverse("core:notifications")).content.decode()
        self.assertLess(response.index("Event 5"), response.index("Event 0"))
