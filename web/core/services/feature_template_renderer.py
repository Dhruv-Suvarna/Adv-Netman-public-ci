"""Render reusable feature templates into browser-safe line descriptors.

Jinja templates remain the source of platform syntax.  Field values are
rendered as unique markers first; this module converts those markers into
the same descriptor contract Phase 9 established.  JavaScript therefore
only substitutes values into Python/Jinja-provided slots and never becomes
a second vendor renderer.
"""

from __future__ import annotations

import re
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, StrictUndefined

FEATURE_TEMPLATE_ROOT = Path(__file__).resolve().parents[3] / "templates" / "features"
_ENV = Environment(
    loader=FileSystemLoader(str(FEATURE_TEMPLATE_ROOT)),
    undefined=StrictUndefined,
    autoescape=False,
    keep_trailing_newline=False,
    trim_blocks=True,
    lstrip_blocks=True,
)
_MARKER_RE = re.compile(r"__DB_FIELD_([A-Za-z0-9_]+)__")


def render_descriptors(*, template_name: str, fields: dict[str, dict], flags: dict | None = None) -> list[dict]:
    markers = {key: f"__DB_FIELD_{key}__" for key in fields}
    rendered = _ENV.get_template(template_name).render(**markers, **(flags or {}))
    descriptors = []
    for line in rendered.splitlines():
        matches = _MARKER_RE.findall(line)
        if not matches:
            descriptors.append({"kind": "static", "text": line})
            continue
        if len(matches) != 1 or matches[0] not in fields:
            raise ValueError(f"Feature template {template_name!r} contains an invalid field marker line: {line!r}")
        key = matches[0]
        field = fields[key]
        descriptors.append(
            {
                "kind": "field",
                "path": field["path"],
                "template": line.replace(markers[key], "{value}"),
                "value": field.get("value", ""),
                "omit_if_empty": bool(field.get("omit_if_empty", False)),
            }
        )
    return descriptors

