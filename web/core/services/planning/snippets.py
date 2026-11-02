"""Configlet-level rendering that reuses the ONE authoritative platform renderer.

There is no vendor syntax here.  A Configlet's snippet is obtained by asking the
platform driver (``platform_drivers.get_driver(platform).render_candidate``) to
render two small state *slices* -- the context an object needs, without and with
the object -- and keeping the lines the object adds (a positional diff), plus the
minimal enclosing block headers so the snippet is self-contained
(``router bgp 65005`` / ``address-family ipv4`` / ``neighbor .. activate``).

Because the lines come from the driver's own descriptors, the syntax source is
the same platform drivers + Jinja feature templates the Device Builder preview
uses.  Nothing here reads a hostname, a device, NetBox, or the network.
"""

from __future__ import annotations

import difflib
import re

from .. import candidate_renderer, platform_drivers


def render_lines(driver, field_values: dict, *, interfaces=None, routing=None, phase12=None) -> list[str]:
    """Driver output for one state slice as plain text lines (blank lines dropped)."""
    descriptors = driver.render_candidate(
        field_values=field_values, interfaces=list(interfaces or []), routing=routing or {}, phase12=phase12 or {}
    )
    lines = []
    for descriptor in descriptors:
        text = candidate_renderer.descriptor_text(descriptor)
        if text is not None and text.strip():
            lines.append(text.rstrip())
    return lines


def _indent(line: str) -> int:
    return len(line) - len(line.lstrip())


def _is_comment(line: str) -> bool:
    return line.strip().startswith(("!", "#"))


def added_lines(before: list[str], after: list[str]) -> list[str]:
    """Lines ``after`` adds over ``before``, each preceded (once) by its enclosing block headers.

    Inserted ``!`` separators are dropped.  Comment lines never act as block headers and never
    close one (EOS/FRR treat ``!`` as a no-op inside a mode).
    """
    matcher = difflib.SequenceMatcher(a=before, b=after, autojunk=False)
    inserted: set[int] = set()
    for tag, _i1, _i2, j1, j2 in matcher.get_opcodes():
        if tag in ("insert", "replace"):
            inserted.update(range(j1, j2))

    result: list[str] = []
    stack: list[tuple[int, int, str]] = []  # (indent, index, line) of open, non-comment headers
    emitted: set[int] = set()
    for index, line in enumerate(after):
        if _is_comment(line):
            if index in inserted and line.strip() != "!":
                for header_indent, header_index, header in stack:
                    if header_indent < _indent(line) and header_index not in emitted:
                        result.append(header)
                        emitted.add(header_index)
                result.append(line)
            continue
        indent = _indent(line)
        while stack and stack[-1][0] >= indent:
            stack.pop()
        if index in inserted:
            for header_indent, header_index, header in stack:
                if header_index not in emitted:
                    result.append(header)
                    emitted.add(header_index)
            result.append(line)
            emitted.add(index)
        stack.append((indent, index, line))
    return result


def deployable(lines: list[str]) -> list[str]:
    return [line for line in lines if line.strip() and not _is_comment(line)]


# The renderer's own markers for "a required accepted value is missing" (candidate previews show them; a plan must not).
_PLACEHOLDER = re.compile(
    r"<(?:[a-z0-9]+(?:-[a-z0-9]+)*-required|no IPv[46] address configured on [^<>]+|invalid address)>"
)


def placeholders(lines: list[str]) -> list[str]:
    return sorted({m.group(0) for line in lines for m in _PLACEHOLDER.finditer(line)})


def has_unsupported_marker(lines: list[str]) -> bool:
    return any(line.strip().startswith(platform_drivers.UNSUPPORTED_OBJECT_MARKER) for line in lines)
