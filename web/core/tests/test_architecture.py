"""
Static assets must resolve through Django's normal static-file machinery and
the readability CSS must exist regardless of theme.  (The "views never contain
direct network-automation logic" rule lives in ``test_contracts``.)
"""

from django.contrib.staticfiles import finders
from django.test import TestCase


class StaticAssetResolutionTests(TestCase):
    def test_core_css_and_js_resolve(self):
        for path in ("core/css/tokens.css", "core/css/base.css", "core/js/app.js"):
            with self.subTest(path=path):
                self.assertIsNotNone(finders.find(path), f"{path} did not resolve via staticfiles finders")


class ReadabilitySurfaceTests(TestCase):
    """Config/log/code/diff/table CSS classes must exist regardless of theme
    (the classes are theme-independent by construction: they read --code-*
    tokens, never --accent, so they can't be reskinned to illegibility)."""

    def test_code_panel_classes_defined(self):
        css_path = finders.find("core/css/base.css")
        self.assertIsNotNone(css_path)
        with open(css_path, encoding="utf-8") as fh:
            css = fh.read()
        for selector in (".code-panel", ".data-table", ".diff-add", ".diff-remove", ".code-panel--log"):
            with self.subTest(selector=selector):
                self.assertIn(selector, css)

    def test_code_tokens_defined_for_every_theme(self):
        tokens_path = finders.find("core/css/tokens.css")
        with open(tokens_path, encoding="utf-8") as fh:
            css = fh.read()
        for theme_block in (":root {", '[data-theme="dark-mode"]', '[data-theme="dark-angels"]', '[data-theme="adeptus-mechanicus"]'):
            with self.subTest(theme_block=theme_block):
                self.assertIn(theme_block, css)
        self.assertEqual(css.count("--code-bg:"), 4)
