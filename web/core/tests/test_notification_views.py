from core.tests.runner import OperatorClient  # V2 Phase 1: authenticated, MFA-verified operator
from django.test import TestCase
from django.urls import reverse

from core.models import Notification


def _make(**overrides):
    defaults = dict(
        event_type=Notification.EventType.TEST,
        severity=Notification.Severity.INFO,
        title="Sample",
        message="Sample message",
        slack_status=Notification.SlackStatus.SKIPPED,
    )
    defaults.update(overrides)
    return Notification.objects.create(**defaults)


class NotificationDetailViewTests(TestCase):
    def test_detail_page_renders_expected_fields(self):
        notification = _make(
            title="Golden promotion blocked",
            message="Promotion blocked by soak regression",
            device="R5",
            interface="Ethernet3",
            change_id="CHG-58",
            lifecycle_state="probation",
            metadata={"affected_feature": "ecmp"},
            event_type=Notification.EventType.GOLDEN_PROMOTION_BLOCKED,
            severity=Notification.Severity.CRITICAL,
        )
        response = self.client.get(reverse("core:notification_detail", args=[notification.pk]))
        self.assertEqual(response.status_code, 200)
        content = response.content.decode()
        for expected in ("Golden promotion blocked", "R5", "Ethernet3", "CHG-58", "probation", "ecmp", "Critical", "GOLDEN_PROMOTION_BLOCKED"):
            self.assertIn(expected, content)

    def test_unknown_notification_is_404(self):
        response = self.client.get(reverse("core:notification_detail", args=[999999]))
        self.assertEqual(response.status_code, 404)

    def test_opening_detail_page_does_not_itself_mark_read(self):
        notification = _make()
        self.assertFalse(notification.is_read)
        self.client.get(reverse("core:notification_detail", args=[notification.pk]))
        notification.refresh_from_db()
        self.assertFalse(notification.is_read, "GET must never mutate state")


class MarkReadTests(TestCase):
    def test_mark_read_requires_post(self):
        notification = _make()
        response = self.client.get(reverse("core:notification_mark_read", args=[notification.pk]))
        self.assertEqual(response.status_code, 405)

    def test_mark_read_post_marks_notification_read(self):
        notification = _make()
        response = self.client.post(reverse("core:notification_mark_read", args=[notification.pk]))
        self.assertEqual(response.status_code, 302)
        notification.refresh_from_db()
        self.assertTrue(notification.is_read)
        self.assertIsNotNone(notification.read_at)

    def test_mark_read_enforces_csrf_when_enforced(self):
        notification = _make()
        enforcing_client = OperatorClient(enforce_csrf_checks=True)
        response = enforcing_client.post(reverse("core:notification_mark_read", args=[notification.pk]))
        self.assertEqual(response.status_code, 403)
        notification.refresh_from_db()
        self.assertFalse(notification.is_read)


class MarkAllReadTests(TestCase):
    def test_mark_all_read_requires_post(self):
        response = self.client.get(reverse("core:notification_mark_all_read"))
        self.assertEqual(response.status_code, 405)

    def test_mark_all_read_marks_every_unread_notification(self):
        a, b = _make(title="a"), _make(title="b")
        response = self.client.post(reverse("core:notification_mark_all_read"))
        self.assertEqual(response.status_code, 302)
        a.refresh_from_db()
        b.refresh_from_db()
        self.assertTrue(a.is_read)
        self.assertTrue(b.is_read)

    def test_mark_all_read_enforces_csrf(self):
        _make()
        enforcing_client = OperatorClient(enforce_csrf_checks=True)
        response = enforcing_client.post(reverse("core:notification_mark_all_read"))
        self.assertEqual(response.status_code, 403)


class UnreadBadgeTests(TestCase):
    def test_no_badge_when_zero_unread(self):
        response = self.client.get(reverse("core:home")).content.decode()
        self.assertNotIn("notif-count-badge", response)

    def test_badge_shows_count(self):
        _make(title="a")
        _make(title="b")
        response = self.client.get(reverse("core:home")).content.decode()
        self.assertIn("notif-count-badge", response)
        self.assertIn(">2<", response)

    def test_badge_caps_display_at_nine_plus(self):
        for i in range(11):
            _make(title=f"n{i}")
        response = self.client.get(reverse("core:home")).content.decode()
        self.assertIn(">9+<", response)


class FilteringAndPaginationTests(TestCase):
    def setUp(self):
        for i in range(30):
            _make(
                title=f"Event {i}",
                severity=Notification.Severity.WARNING if i % 2 == 0 else Notification.Severity.INFO,
            )

    def test_notifications_page_paginates(self):
        response = self.client.get(reverse("core:notifications"))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Page 1 of 2")

    def test_severity_filter_narrows_results(self):
        response = self.client.get(reverse("core:notifications"), {"severity": "WARNING"})
        content = response.content.decode()
        main_content = content[content.index('class="page-content"'):]
        self.assertEqual(main_content.count('<a class="notification-item'), 15)

    def test_unread_filter(self):
        Notification.objects.update(is_read=True)
        _make(title="still unread")
        response = self.client.get(reverse("core:notifications"), {"unread": "1"})
        content = response.content.decode()
        main_content = content[content.index('class="page-content"'):]
        self.assertEqual(main_content.count('<a class="notification-item'), 1)


class SecurityEscapingTests(TestCase):
    def test_title_and_message_are_escaped_in_dropdown(self):
        _make(title="<script>alert(1)</script>", message="<img src=x onerror=alert(2)>")
        response = self.client.get(reverse("core:home")).content.decode()
        self.assertNotIn("<script>alert(1)</script>", response)
        self.assertNotIn("<img src=x onerror=alert(2)>", response)
        self.assertIn("&lt;script&gt;", response)

    def test_title_and_message_are_escaped_on_detail_page(self):
        notification = _make(title="<b>bold</b>", message="<i>italic</i>")
        response = self.client.get(reverse("core:notification_detail", args=[notification.pk])).content.decode()
        self.assertNotIn("<b>bold</b>", response)
        self.assertNotIn("<i>italic</i>", response)

    def test_metadata_values_cannot_inject_html(self):
        notification = _make(metadata={"note": "<script>alert(3)</script>"})
        response = self.client.get(reverse("core:notification_detail", args=[notification.pk])).content.decode()
        self.assertNotIn("<script>alert(3)</script>", response)

    def test_notification_templates_never_use_safe_filter(self):
        import pathlib

        templates_dir = pathlib.Path(__file__).resolve().parent.parent / "templates" / "core"
        offenders = []
        for name in ("notifications.html", "notification_detail.html", "components/notification_item.html", "components/notification_dropdown.html"):
            text = (templates_dir / name).read_text()
            if "|safe" in text or "safe }}" in text:
                offenders.append(name)
        self.assertEqual(offenders, [])
