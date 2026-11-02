"""Pylint results (``--output-format=json2``) -> per-artifact quality status against the tracked baseline.

CRITICAL messages fail the gate on ANY occurrence: every error / fatal message plus the correctness checks in
``CRITICAL_SYMBOLS``.  Non-critical messages are tracked per artifact in ``baseline.json``: existing debt stays
visible (WARN), an artifact that gains messages above its baseline FAILS, so new debt cannot appear silently.
False positives in byte-pinned files are listed with reasons in ``policy.yml``; elsewhere they are annotated inline.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from .constants import REPO_ROOT, PylintStatus
from .policy import Policy

CRITICAL_SYMBOLS = frozenset({"dangerous-default-value", "unreachable", "duplicate-key", "lost-exception", "return-in-finally",
                              "self-assigning-variable"})
MAX_MESSAGES_PER_ARTIFACT = 50


class PylintDataError(ValueError):
    pass


@dataclass
class ArtifactLint:
    path: str
    messages: list[dict] = field(default_factory=list)
    counts: dict[str, int] = field(default_factory=dict)
    critical: int = 0
    false_positives: int = 0

    def status(self, allowed: dict[str, int] | None) -> str:
        if self.critical:
            return PylintStatus.FAIL
        allowed = allowed or {}
        if any(n > allowed.get(sym, 0) for sym, n in self.counts.items()):
            return PylintStatus.FAIL
        return PylintStatus.WARN if self.counts else PylintStatus.PASS

    def over_baseline(self, allowed: dict[str, int] | None) -> dict[str, int]:
        allowed = allowed or {}
        return {sym: n - allowed.get(sym, 0) for sym, n in sorted(self.counts.items()) if n > allowed.get(sym, 0)}


def is_critical(message: dict) -> bool:
    return message.get("type") in ("error", "fatal") or message.get("symbol") in CRITICAL_SYMBOLS


def _relative(path: str, repo: Path) -> str:
    candidate = Path(path)
    if candidate.is_absolute():
        try:
            return candidate.resolve().relative_to(repo.resolve()).as_posix()
        except ValueError:
            return candidate.as_posix()
    return candidate.as_posix()


def parse_pylint(data, *, policy: Policy, repo: Path = REPO_ROOT, linted: list[str] | None = None) -> dict[str, ArtifactLint]:
    if not isinstance(data, dict) or not isinstance(data.get("messages"), list):
        raise PylintDataError("Pylint output is not json2 (no message list)")
    out: dict[str, ArtifactLint] = {p: ArtifactLint(p) for p in (linted or [])}
    for message in data["messages"]:
        if not isinstance(message, dict):
            raise PylintDataError("malformed Pylint message")
        path = _relative(str(message.get("absolutePath") or message.get("path") or ""), repo)
        entry = out.setdefault(path, ArtifactLint(path))
        symbol = str(message.get("symbol") or "")
        if policy.pylint_false_positive(path, symbol):
            entry.false_positives += 1
            continue
        critical = is_critical(message)
        entry.critical += int(critical)
        if not critical:
            entry.counts[symbol] = entry.counts.get(symbol, 0) + 1
        if len(entry.messages) < MAX_MESSAGES_PER_ARTIFACT:
            entry.messages.append({"line": int(message.get("line") or 0), "symbol": symbol, "type": str(message.get("type") or ""),
                                   "message": str(message.get("message") or "")[:200], "critical": critical})
    for entry in out.values():
        entry.messages.sort(key=lambda m: (not m["critical"], m["line"], m["symbol"]))
    return out
