import re

from django.test import TestCase
from django.urls import reverse

EXPECTED_SIDEBAR_LABELS = ["Home", "Monitoring", "Health", "Device Builder", "NSOT", "Automation"]


class SidebarNavigationTests(TestCase):
    def _sidebar_html(self):
        html = self.client.get(reverse("core:home")).content.decode()
        start = html.index('<div class="sidebar__nav">')
        end = html.index("</nav>", start)
        return html[start:end]

    def test_sidebar_has_exactly_the_required_sections_and_one_active_link(self):
        sidebar_html = self._sidebar_html()
        found_labels = re.findall(r'sidebar__link[^>]*>\s*<span[^>]*>[^<]*</span>\s*([^<\n]+)', sidebar_html)
        self.assertEqual([label.strip() for label in found_labels], EXPECTED_SIDEBAR_LABELS)
        self.assertEqual(sidebar_html.count("sidebar__link"), len(EXPECTED_SIDEBAR_LABELS))
        self.assertEqual(sidebar_html.count("is-active"), 1)  # the active page is identifiable, exactly once

    def test_header_keeps_theme_and_notifications_without_profile_avatar(self):
        html = self.client.get(reverse("core:home")).content.decode()
        header_start = html.index("top-header")
        header_end = html.index("</header>")
        header_html = html[header_start:header_end]
        self.assertIn("data-dropdown-trigger", header_html)
        self.assertIn('id="theme-select"', header_html)
        self.assertIn(reverse("core:notifications"), header_html)
        self.assertNotIn(reverse("core:profile"), header_html)
        self.assertNotIn("avatar-button", header_html)
        self.assertNotIn("profile-menu", header_html)
