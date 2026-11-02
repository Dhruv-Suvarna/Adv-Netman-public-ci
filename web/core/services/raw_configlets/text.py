"""Deterministic Raw Configlet text handling: normalization, content hash and the command stream.

``command_lines`` and ``ceos_command_stream`` are the ONE definition of "what a Raw Configlet sends": the Phase-17 cEOS
executor and the Phase-18 cEOS verifier both call ``ceos_command_stream`` (which is ``modules.eos_render.eos_commands``, the
flattening ``master.py::push_eos`` uses), so what was verified is exactly what is executed.
"""

from __future__ import annotations

import hashlib
import sys

from . import codes


def normalize(text: str) -> str:
    """Line endings -> LF, trailing whitespace stripped per line, trailing blank lines dropped, one final newline.

    Deterministic and idempotent.  Nothing is truncated: size / line limits are enforced by the static gate on the result.
    """
    text = str(text).replace("\r\n", "\n").replace("\r", "\n")
    lines = [line.rstrip() for line in text.split("\n")]
    while lines and not lines[-1]:
        lines.pop()
    return "\n".join(lines) + "\n" if lines else ""


def content_hash(normalized: str) -> str:
    """SHA-256 of the normalized text (ASCII by construction after the static gate)."""
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def command_lines(normalized: str) -> list[str]:
    """The configuration statements: blank lines and full-line comments (``!`` / ``#``) removed, indentation preserved.

    Same comment rule as ``executors.base.ConfigletSpec.from_configlet`` uses for structured Configlets.
    """
    return [
        line.rstrip() for line in normalized.splitlines()
        if line.strip() and not line.strip().startswith(("!", "#"))
    ]


def ceos_command_stream(lines) -> list[str]:
    """Indentation -> a flat EOS command list with explicit ``exit``s (``modules.eos_render.eos_commands``)."""
    from django.conf import settings

    root = str(settings.REPO_ROOT)
    if root not in sys.path:
        sys.path.insert(0, root)
    from modules.eos_render import eos_commands  # the exact flattening master.py uses

    return eos_commands("\n".join(lines))


def stats(normalized: str) -> dict:
    return {
        "bytes": len(normalized.encode("utf-8")),
        "lines": len(normalized.splitlines()),
        "statements": len(command_lines(normalized)),
        "max_bytes": codes.MAX_BYTES,
        "max_lines": codes.MAX_LINES,
    }


def statements(normalized: str) -> list[tuple[int, str]]:
    """``(source line number, statement text)`` for every configuration statement (comments / blanks removed), in order.

    The verifier's error line numbers are mapped back to SOURCE lines through this list, so a finding points at the operator's own line.
    """
    return [
        (number, line.rstrip()) for number, line in enumerate(normalized.splitlines(), start=1)
        if line.strip() and not line.strip().startswith(("!", "#"))
    ]


def stream_sources(items: list[tuple[int, str]], stream: list[str]) -> list[int]:
    """For each command of a flattened stream, the source line it came from (a synthetic ``exit`` maps to the preceding statement).

    ``eos_commands`` only ever INSERTS ``exit`` (explicit ``exit`` statements are refused by the static gate), so the k-th non-``exit``
    command is the k-th statement.  If the counts disagree the mapping is unknown and every entry is 0 (never guessed).
    """
    real = [cmd for cmd in stream if cmd != "exit"]
    if len(real) != len(items):
        return [0] * len(stream)
    mapping, position = [], -1
    for command in stream:
        if command != "exit":
            position += 1
        mapping.append(items[max(position, 0)][0])
    return mapping
