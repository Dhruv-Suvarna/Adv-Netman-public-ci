"""
Artwork asset manifest + graceful-fallback lookup.

Phase 3 built this framework before the operator's ten real artwork files
existed anywhere in the session filesystem. Phase 4 (2026-09-20) confirmed
all ten are now present at their documented drop-in locations (see
core/static/core/themes/README.md) and fixed a pre-existing slot-path bug
in three of the ten slot names (brand/minimal/dark; see the note on
theme_registry.GLOBAL_ASSET_SLOTS) that had silently kept them
unresolvable even though the files existed. No artwork was renamed,
regenerated, recompressed, or moved as part of that fix -- only the slot
key strings in this module and theme_registry.py were corrected to match
the directory layout that was already documented and already on disk.

This module defines exactly where each of the ten expected assets should
be dropped, and resolves a slot to a static URL ONLY if a real file exists
there -- otherwise callers get None and the CSS gradient fallback in
tokens.css is used instead. This makes the whole framework safe to
demonstrate now and safe to "light up" later by dropping files in place,
with no template or Python changes required.

Destination directory convention: web/core/static/core/themes/<slot>/watermark.<ext>
"""

from __future__ import annotations

from django.contrib.staticfiles import finders
from django.core.exceptions import SuspiciousFileOperation

from . import theme_registry

# slot -> candidate filenames to look for, in priority order. Any raster
# or vector format is accepted; the first match wins.
_CANDIDATE_EXTENSIONS = ("svg", "png", "webp", "jpg", "jpeg")

# The ten expected slots: one global brand mark + one per theme/context
# watermark (1 minimal + 1 dark-mode + 4 dark-angels + 3 mechanicus = 9,
# plus the global brand mark = 10). Confirmed live (Phase 4, 2026-09-20)
# against the operator's actual ten uploaded files -- all ten now resolve.
ASSET_SLOTS = {
    "brand": "Global header/brand mark, used across every theme.",
    "minimal": "Basic Minimal background/watermark (subtle circuit motif).",
    "dark": "Dark Mode background/watermark.",
    "dark_angels/core": "Dark Angels - Core (Lion/knightly helm watermark).",
    "dark_angels/deathwing": "Dark Angels - Deathwing (terminator-helm watermark).",
    "dark_angels/ravenwing": "Dark Angels - Ravenwing watermark.",
    "dark_angels/hexagrammaton": "Dark Angels - Hexagrammaton/Inner Circle radial motif.",
    "mechanicus/core": "Adeptus Mechanicus - Core watermark.",
    "mechanicus/forge": "Adeptus Mechanicus - Forge/Automation watermark.",
    "mechanicus/monitoring": "Adeptus Mechanicus - Data/Monitoring watermark.",
}


def expected_static_dir(slot: str) -> str:
    return f"core/themes/{slot}/"


def resolve_watermark_url(slot: str) -> str | None:
    """
    Returns a static URL for the first matching file in this slot's
    directory, or None if no real asset has been placed there yet.

    `slot` only ever comes from theme_registry (never user input) in this
    project today, but this still defends the boundary: Django's own
    staticfiles finder already raises SuspiciousFileOperation for a
    traversal-style path (e.g. "../../etc/passwd") rather than silently
    resolving outside the static root; that is caught here and treated the
    same as "not found" instead of propagating as a server error.
    """
    for ext in _CANDIDATE_EXTENSIONS:
        candidate = f"core/themes/{slot}/watermark.{ext}"
        try:
            found = finders.find(candidate)
        except SuspiciousFileOperation:
            return None
        if found:
            from django.templatetags.static import static

            return static(candidate)
    return None


def watermark_for(theme_name: str, context_name: str) -> str | None:
    theme = theme_registry.THEMES.get(theme_name)
    if not theme:
        return None
    context = theme.get("contexts", {}).get(context_name)
    if not context:
        return None
    return resolve_watermark_url(context["watermark_slot"])


def brand_mark_url() -> str | None:
    return resolve_watermark_url(theme_registry.GLOBAL_ASSET_SLOTS[0])
