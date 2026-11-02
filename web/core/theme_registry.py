"""
Theme registry: the single source of truth for the four top-level themes,
their contextual variants, and which page defaults to which context.

Nothing outside this module should hardcode a theme name, a context name,
or a page->context default. Templates render off ``THEMES`` (via the
``theme_context`` context processor); tests assert against ``THEMES``
directly so the registry and the UI can never silently drift apart.

See docs/DJANGO_UI_FOUNDATION.md ("Theme architecture") for the full
design writeup, including why persistence uses a cookie rather than a
database model.
"""

from __future__ import annotations

DEFAULT_THEME = "basic-minimal"
DEFAULT_CONTEXT = "default"

# Each top-level theme lists its available contextual variants. A theme
# with only "default" has no contextual sub-variants (Basic Minimal, Dark
# Mode). Dark Angels and Adeptus Mechanicus are ONE theme each with several
# contexts -- never separate top-level themes -- per the Phase 3 spec.
THEMES = {
    "basic-minimal": {
        "label": "Basic Minimal",
        "description": (
            "Clean, neutral, restrained light theme suitable for "
            "university/enterprise demonstration."
        ),
        "contexts": {
            "default": {
                "label": "Default",
                "watermark_slot": "minimal",
            },
        },
    },
    "dark-mode": {
        "label": "Dark Mode",
        "description": (
            "Charcoal/graphite/slate NOC-console theme for comfortable "
            "long-session use."
        ),
        "contexts": {
            "default": {
                "label": "Default",
                "watermark_slot": "dark",
            },
        },
    },
    "dark-angels": {
        "label": "Dark Angels",
        "description": (
            "Deep forest/Caliban green, blackened metal, subdued silver, "
            "restrained bonewhite. Contextual variants below share one "
            "token set and differ only in accent/watermark."
        ),
        "contexts": {
            "core": {
                "label": "Core",
                "watermark_slot": "dark_angels/core",
            },
            "deathwing": {
                "label": "Deathwing",
                "watermark_slot": "dark_angels/deathwing",
                "future_use": "Golden States, archives, rollback/history, configuration history",
            },
            "ravenwing": {
                "label": "Ravenwing",
                "watermark_slot": "dark_angels/ravenwing",
                "future_use": "monitoring, link events, traffic, topology/live-state pages",
            },
            "hexagrammaton": {
                "label": "Hexagrammaton",
                "watermark_slot": "dark_angels/hexagrammaton",
                "future_use": "advanced/technical sections",
            },
        },
    },
    "adeptus-mechanicus": {
        "label": "Adeptus Mechanicus",
        "description": (
            "Martian crimson, blackened iron, gunmetal, muted brass, "
            "parchment accents. Industrial/technical/ritualistic, not "
            "\"dark mode but red.\""
        ),
        "contexts": {
            "core": {
                "label": "Core",
                "watermark_slot": "mechanicus/core",
            },
            "forge": {
                "label": "Forge / Automation",
                "watermark_slot": "mechanicus/forge",
                "future_use": "Automation, Device Builder",
            },
            "monitoring": {
                "label": "Data / Monitoring",
                "watermark_slot": "mechanicus/monitoring",
                "future_use": "Monitoring pages",
            },
        },
    },
}

# Global (theme-independent) artwork slot, e.g. an app identity mark used
# in the header across every theme. Counted among the ten supplied assets
# alongside the per-theme/context watermarks above.
#
# Phase 4 artwork-regression note (2026-09-20): this slot -- and
# "minimal"/"dark" above -- previously pointed one directory level too deep
# ("brand/app-mark", "minimal/default", "dark/default"), which never
# matched the single-directory-per-slot convention actually documented in
# core/static/core/themes/README.md and DJANGO_UI_FOUNDATION.md Section 8
# (e.g. "brand/", not "brand/app-mark/"), and never matched the .gitkeep
# placeholders Phase 3 actually created. The operator's ten real assets
# were dropped into the documented, correct directories; three of the ten
# silently failed to resolve because of this pre-existing slot-string bug,
# not because any file was missing. Fixed here to match the real directory
# layout -- no artwork file was moved, renamed, or altered.
GLOBAL_ASSET_SLOTS = ["brand"]

# Which context each top-level theme should use for a given page, when that
# theme is active. A theme/page combination not listed here falls back to
# "default" (for basic-minimal/dark-mode) or "core" (for dark-angels /
# adeptus-mechanicus). This is demonstrated, not deeply themed, in Phase 3.
PAGE_THEME_CONTEXT = {
    "home": {"dark-angels": "hexagrammaton", "adeptus-mechanicus": "core"},
    "monitoring": {"dark-angels": "ravenwing", "adeptus-mechanicus": "monitoring"},
    "health": {"dark-angels": "core", "adeptus-mechanicus": "core"},
    "device_builder": {"dark-angels": "deathwing", "adeptus-mechanicus": "forge"},
    "nsot": {"dark-angels": "core", "adeptus-mechanicus": "core"},
    "automation": {"dark-angels": "hexagrammaton", "adeptus-mechanicus": "forge"},
    "notifications": {"dark-angels": "ravenwing", "adeptus-mechanicus": "monitoring"},
    "profile": {"dark-angels": "core", "adeptus-mechanicus": "core"},
}


def is_valid_theme(theme_name: str) -> bool:
    return theme_name in THEMES


def resolve_theme(theme_name: str | None) -> str:
    """Unknown/missing theme names fall back to the safe default."""
    if theme_name and is_valid_theme(theme_name):
        return theme_name
    return DEFAULT_THEME


def default_context_for_theme(theme_name: str) -> str:
    contexts = THEMES.get(theme_name, {}).get("contexts", {})
    if "default" in contexts:
        return "default"
    if "core" in contexts:
        return "core"
    return next(iter(contexts), DEFAULT_CONTEXT)


def resolve_context(theme_name: str, page_key: str) -> str:
    """
    Resolve the contextual variant for `theme_name` on `page_key`, without
    ever changing the user's chosen top-level theme.
    """
    theme_name = resolve_theme(theme_name)
    page_map = PAGE_THEME_CONTEXT.get(page_key, {})
    context = page_map.get(theme_name)
    if context and context in THEMES[theme_name]["contexts"]:
        return context
    return default_context_for_theme(theme_name)


def theme_choices():
    """[(value, label), ...] in stable registry order, for template rendering."""
    return [(key, data["label"]) for key, data in THEMES.items()]
