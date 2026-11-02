import re

from django.conf import settings
from django.test import TestCase
from django.urls import reverse
from pathlib import Path

from core import context_processors, theme_assets, theme_registry
from core.tests.helpers.candidates import make_candidate


class ThemeRegistryTests(TestCase):
    def test_exactly_four_top_level_themes(self):
        self.assertEqual(
            set(theme_registry.THEMES.keys()),
            {"basic-minimal", "dark-mode", "dark-angels", "adeptus-mechanicus"},
        )

    def test_dark_angels_contextual_variants(self):
        contexts = set(theme_registry.THEMES["dark-angels"]["contexts"].keys())
        self.assertEqual(contexts, {"core", "deathwing", "ravenwing", "hexagrammaton"})

    def test_mechanicus_contextual_variants(self):
        contexts = set(theme_registry.THEMES["adeptus-mechanicus"]["contexts"].keys())
        self.assertEqual(contexts, {"core", "forge", "monitoring"})

    def test_basic_minimal_and_dark_mode_have_no_contextual_variants(self):
        self.assertEqual(set(theme_registry.THEMES["basic-minimal"]["contexts"].keys()), {"default"})
        self.assertEqual(set(theme_registry.THEMES["dark-mode"]["contexts"].keys()), {"default"})

    def test_unknown_theme_falls_back_to_basic_minimal(self):
        self.assertEqual(theme_registry.resolve_theme("not-a-real-theme"), "basic-minimal")
        self.assertEqual(theme_registry.resolve_theme(None), "basic-minimal")
        self.assertEqual(theme_registry.resolve_theme(""), "basic-minimal")

    def test_known_theme_passes_through(self):
        self.assertEqual(theme_registry.resolve_theme("dark-mode"), "dark-mode")

    def test_page_context_resolves_without_changing_top_level_theme(self):
        theme = theme_registry.resolve_theme("dark-angels")
        context = theme_registry.resolve_context(theme, "monitoring")
        self.assertEqual(theme, "dark-angels")  # unchanged
        self.assertEqual(context, "ravenwing")

    def test_dark_angels_main_pages_use_page_specific_artwork_contexts(self):
        expected = {
            "home": "hexagrammaton",
            "monitoring": "ravenwing",
            "health": "core",
            "device_builder": "deathwing",
            "nsot": "core",
            "automation": "hexagrammaton",
        }
        for page_key, context in expected.items():
            with self.subTest(page_key=page_key):
                self.assertEqual(
                    theme_registry.resolve_context("dark-angels", page_key),
                    context,
                )

    def test_mechanicus_page_context_mapping(self):
        theme = theme_registry.resolve_theme("adeptus-mechanicus")
        self.assertEqual(theme_registry.resolve_context(theme, "automation"), "forge")
        self.assertEqual(theme_registry.resolve_context(theme, "monitoring"), "monitoring")
        self.assertEqual(theme_registry.resolve_context(theme, "home"), "core")

    def test_context_falls_back_to_default_for_unmapped_page(self):
        context = theme_registry.resolve_context("basic-minimal", "some-future-page")
        self.assertEqual(context, "default")


class ThemePersistenceTests(TestCase):
    def test_theme_selection_sets_cookie_and_persists_across_requests(self):
        response = self.client.post(
            reverse("core:set_theme"), {"theme": "dark-angels", "next": "/"}
        )
        self.assertEqual(response.cookies[settings.THEME_COOKIE_NAME].value, "dark-angels")

        self.client.cookies[settings.THEME_COOKIE_NAME] = "dark-angels"
        home = self.client.get(reverse("core:home"))
        self.assertContains(home, 'data-theme="dark-angels"')

    def test_unknown_theme_cookie_falls_back_safely_in_rendered_page(self):
        self.client.cookies[settings.THEME_COOKIE_NAME] = "not-a-real-theme"
        home = self.client.get(reverse("core:home"))
        self.assertContains(home, 'data-theme="basic-minimal"')

    def test_no_cookie_defaults_to_basic_minimal(self):
        home = self.client.get(reverse("core:home"))
        self.assertContains(home, 'data-theme="basic-minimal"')

    def test_set_theme_rejects_get(self):
        response = self.client.get(reverse("core:set_theme"))
        self.assertEqual(response.status_code, 405)

    def test_page_context_switches_without_changing_persisted_theme_cookie(self):
        self.client.cookies[settings.THEME_COOKIE_NAME] = "adeptus-mechanicus"
        home = self.client.get(reverse("core:home"))
        monitoring = self.client.get(reverse("core:monitoring_landing"))
        self.assertContains(home, 'data-theme="adeptus-mechanicus"')
        self.assertContains(monitoring, 'data-theme="adeptus-mechanicus"')
        self.assertContains(home, 'data-theme-context="core"')
        self.assertContains(monitoring, 'data-theme-context="monitoring"')

    def test_dark_angels_home_monitoring_and_nsot_render_distinct_backgrounds(self):
        self.client.cookies[settings.THEME_COOKIE_NAME] = "dark-angels"
        pages = {
            "home": self.client.get(reverse("core:home")),
            "monitoring": self.client.get(reverse("core:monitoring_landing")),
            "nsot": self.client.get(reverse("core:nsot")),
        }
        expected_slots = {
            "home": "dark_angels/hexagrammaton",
            "monitoring": "dark_angels/ravenwing",
            "nsot": "dark_angels/core",
        }
        rendered_urls = set()
        for page_key, response in pages.items():
            with self.subTest(page_key=page_key):
                expected_url = theme_assets.resolve_watermark_url(expected_slots[page_key])
                self.assertEqual(response.context["watermark_url"], expected_url)
                self.assertContains(response, f"background-image:url('{expected_url}')")
                rendered_urls.add(response.context["watermark_url"])
        self.assertEqual(len(rendered_urls), len(pages))


class ArtworkFallbackTests(TestCase):
    def test_unknown_slot_resolves_to_none_not_an_error(self):
        # Fallback logic must still degrade safely for a slot that
        # genuinely has no file -- proven with a slot name that cannot
        # exist, independent of whatever real artwork is checked in.
        self.assertIsNone(theme_assets.resolve_watermark_url("not-a-real-slot/does-not-exist"))

    def test_all_ten_real_assets_resolve(self):
        # Phase 4 (2026-09-20): the operator's ten real artwork files are
        # now present at their documented locations. Every slot must
        # resolve to a real static URL, not fall back to None/the CSS
        # gradient. See docs/NOTIFICATION_AND_SLACK_ARCHITECTURE.md is NOT
        # relevant here -- see DJANGO_UI_FOUNDATION.md Section 8 and the
        # Phase 4 addendum at the top of that document.
        resolved = []
        for slot in theme_registry.GLOBAL_ASSET_SLOTS:
            url = theme_assets.resolve_watermark_url(slot)
            self.assertIsNotNone(url, f"global slot {slot!r} did not resolve")
            resolved.append(url)
        for theme in theme_registry.THEMES.values():
            for context in theme["contexts"].values():
                slot = context["watermark_slot"]
                url = theme_assets.resolve_watermark_url(slot)
                self.assertIsNotNone(url, f"slot {slot!r} did not resolve")
                resolved.append(url)
        self.assertEqual(len(resolved), 10)
        self.assertEqual(len(set(resolved)), 10, "expected ten distinct resolved URLs")

    def test_home_page_no_longer_uses_fallback_watermark(self):
        # Basic Minimal (the no-cookie default) now has a real watermark,
        # so the CSS-only fallback must not be selected for it.
        response = self.client.get(reverse("core:home"))
        self.assertNotContains(response, "theme-watermark--fallback")
        self.assertContains(response, "core/themes/minimal/watermark")

    def test_watermark_uses_the_application_canvas_not_the_old_avatar_sized_cap(self):
        css = (Path(settings.BASE_DIR) / "core/static/core/css/base.css").read_text()
        block = css.split(".theme-watermark {", 1)[1].split("}", 1)[0]
        self.assertNotIn("560px", block)
        self.assertIn("background-repeat: no-repeat", block)
        self.assertIn("position: fixed", block)
        self.assertIn("inset: 60px 0 0 240px", block)
        # "cover" fills edge-to-edge with no distortion; right-anchored
        # positioning means the left edge is what gets cropped as the
        # viewport narrows, keeping the artwork's right side in view.
        self.assertIn("background-size: cover", block)
        self.assertIn("background-position: right center", block)


class DeviceBuilderThemeWiringTests(TestCase):
    """Device Builder routes carry the device_builder page key, which selects each theme's contextual variant."""

    def test_device_builder_routes_map_to_the_device_builder_page_key(self):
        for url_name in (
            "core:device_builder_capabilities",
            "core:device_builder_changes",
            "core:device_builder_change_detail",
            "core:device_builder_edit",
            "core:device_builder_advanced",
            "core:device_builder_candidate_diff",
            "core:change_validation",
            "core:change_plan",
        ):
            with self.subTest(url_name=url_name):
                self.assertEqual(context_processors.PAGE_URL_NAMES.get(url_name), "device_builder")

    def test_theme_context_resolves_for_the_editor_and_the_landing_page(self):
        change, intent, _ = make_candidate()
        self.client.cookies[settings.THEME_COOKIE_NAME] = "adeptus-mechanicus"
        response = self.client.get(reverse("core:device_builder_edit", args=[change.change_id, intent.pk]))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context["active_theme"], "adeptus-mechanicus")
        self.assertEqual(response.context["active_theme_context"], "forge")

        self.client.cookies[settings.THEME_COOKIE_NAME] = "dark-angels"
        response = self.client.get(reverse("core:device_builder"))
        self.assertEqual(response.context["active_theme_context"], "deathwing")


class ThemeContextPaletteSeparationTests(TestCase):
    """
    Architectural regression: a page context (e.g. Deathwing) must select
    ONLY artwork, never color. These tests parse tokens.css directly so a
    future contributor can't silently reintroduce a per-context palette
    override the way Deathwing/Forge/Monitoring previously did (Device
    Builder + Dark Angels rendered bone/gold instead of green because the
    "deathwing" context block redefined --accent, --bg-app, etc.).
    """

    PALETTE_TOKENS = {
        "--bg-app", "--bg-surface", "--bg-elevated", "--border",
        "--text-primary", "--text-secondary", "--text-muted",
        "--accent", "--accent-strong", "--accent-contrast",
        "--success", "--warning", "--danger", "--info", "--focus-ring",
        "--sidebar-bg", "--sidebar-text", "--sidebar-active-bg",
        "--sidebar-active-text", "--sidebar-border",
        "--header-bg", "--header-border",
        "--code-bg", "--code-text", "--code-border",
    }

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.tokens_css = (
            Path(settings.BASE_DIR) / "core/static/core/css/tokens.css"
        ).read_text()

    def _context_block_tokens(self, theme, context):
        selector = f'[data-theme="{theme}"][data-theme-context="{context}"]'
        start = self.tokens_css.index(selector)
        block = self.tokens_css[start:self.tokens_css.index("}", start)]
        return set(re.findall(r"(--[a-z-]+)\s*:", block))

    def test_dark_angels_contexts_only_select_artwork_not_palette(self):
        for context in ("deathwing", "ravenwing", "hexagrammaton"):
            with self.subTest(context=context):
                tokens = self._context_block_tokens("dark-angels", context)
                overridden_palette = tokens & self.PALETTE_TOKENS
                self.assertFalse(
                    overridden_palette,
                    f"dark-angels/{context} must not override palette tokens, "
                    f"only --watermark-opacity; found {overridden_palette}",
                )

    def test_mechanicus_contexts_only_select_artwork_not_palette(self):
        for context in ("forge", "monitoring"):
            with self.subTest(context=context):
                tokens = self._context_block_tokens("adeptus-mechanicus", context)
                overridden_palette = tokens & self.PALETTE_TOKENS
                self.assertFalse(
                    overridden_palette,
                    f"adeptus-mechanicus/{context} must not override palette "
                    f"tokens, only --watermark-opacity; found {overridden_palette}",
                )

    def test_dark_angels_active_nav_text_is_green_not_bone(self):
        # Regression for the specific bug the operator saw: the active
        # sidebar link previously rendered bone/gold (#d8cfa6) even in the
        # base Dark Angels theme, not just in the Deathwing context.
        start = self.tokens_css.index('[data-theme="dark-angels"] {')
        block = self.tokens_css[start:self.tokens_css.index("\n}\n", start)]
        self.assertNotIn("#d8cfa6", block)
        self.assertIn("--sidebar-active-text: #7fae72", block)


class SidebarBrandingTests(TestCase):
    def test_sidebar_brand_has_no_logo_image(self):
        response = self.client.get(reverse("core:home"))
        content = response.content.decode()
        brand_block = content.split("sidebar__brand", 1)[1].split("</div>", 1)[0]
        self.assertNotIn("<img", brand_block)
        self.assertIn("NMAS Control Plane", brand_block)


class StaticCacheBustingTests(TestCase):
    def test_base_css_and_tokens_css_links_are_version_stamped(self):
        response = self.client.get(reverse("core:home"))
        self.assertContains(response, "core/css/tokens.css?v=")
        self.assertContains(response, "core/css/base.css?v=")

    def test_version_stamp_changes_when_file_content_changes(self):
        from core.templatetags.core_extras import versioned_static

        first = versioned_static("core/css/base.css")
        css_path = Path(settings.BASE_DIR) / "core/static/core/css/base.css"
        original = css_path.read_text()
        try:
            css_path.write_text(original + "\n/* test touch */\n")
            second = versioned_static("core/css/base.css")
        finally:
            css_path.write_text(original)
        self.assertNotEqual(first, second)
