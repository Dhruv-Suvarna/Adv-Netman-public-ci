"""Secret-shaped detection, redaction and output bounding for Tier-3 reports.

Reports and logs may be published as CI artifacts, so nothing raw is emitted: captured tool
output is redacted and bounded, and secret findings carry a path and a pattern NAME, never the
matched text.  The key denylist is the project-wide ``secret_policy`` (one policy, not a copy).
"""

from __future__ import annotations

import re

from .. import secret_policy
from .constants import MAX_OUTPUT_CHARS, MAX_OUTPUT_LINES, MAX_STRING

# High-confidence credential FORMATS only (no generic "password =" scan: historical lab credentials
# already exist in old source and are out of scope here; Tier 3 must not spread or re-flag them).
SECRET_PATTERNS: tuple[tuple[str, re.Pattern], ...] = (
    ("PRIVATE_KEY_BLOCK", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY")),
    ("SLACK_WEBHOOK_URL", re.compile(r"hooks\.slack\.com/services/[A-Za-z0-9/_-]{20,}")),
    ("SLACK_TOKEN", re.compile(r"\bxox[abposr]-[A-Za-z0-9-]{10,}")),
    ("GITHUB_TOKEN", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,})\b")),
    ("AWS_ACCESS_KEY_ID", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    # The public-history incident used short, ordinary-looking lab passwords
    # that entropy/token-format rules cannot detect.  Keep this deliberately
    # narrow: these legacy names must only point through a ``*_ref`` key and
    # must never again receive a literal value in Git.
    (
        "NMAS_LEGACY_PASSWORD_ASSIGNMENT",
        re.compile(
            r"(?i)^\s*(?:"
            r"(?:ceos_password|linux_root_password)\s*:\s*"
            r"(?![\"']?(?:runtime://|\$\{|\{\{|REDACTED|CHANGEME|EXAMPLE|DUMMY|NONE|NULL))"
            r"[\"']?[^\s#\"']{4,}"
            r"|ROOT_PASSWORD\s*=\s*[\"']"
            r"(?!REDACTED|CHANGEME|EXAMPLE|DUMMY|NONE|NULL)[^\"']{4,}[\"']"
            r")"
        ),
    ),
)

_KEY_WORDS = "|".join(re.escape(k) for k in secret_policy.FORBIDDEN_METADATA_KEY_SUBSTRINGS)
# ``name = value`` / ``name: value`` where the NAME looks secret-shaped and is not a ``*_ref`` reference.
_ASSIGNMENT_RE = re.compile(rf"(?i)\b([A-Za-z0-9_.-]*(?:{_KEY_WORDS})[A-Za-z0-9_.-]*)(\s*[=:]\s*)(\S+)")

CONFLICT_MARKER_RE = re.compile(r"^(?:<{7}|>{7})(?: |$)")


def scan_line(text: str) -> list[str]:
    """Names of every credential-format pattern present in one line (never the matched text)."""
    return [name for name, pattern in SECRET_PATTERNS if pattern.search(text)]


def redact_text(text: str) -> str:
    """Mask credential formats and secret-shaped ``key=value`` assignments."""
    for name, pattern in SECRET_PATTERNS:
        text = pattern.sub(f"[REDACTED:{name}]", text)

    def _mask(match: re.Match) -> str:
        key, sep, _value = match.groups()
        if key.lower().endswith("_ref"):
            return match.group(0)
        return f"{key}{sep}[REDACTED]"

    return _ASSIGNMENT_RE.sub(_mask, text)


def bound_output(text: str, *, max_lines: int = MAX_OUTPUT_LINES, max_chars: int = MAX_OUTPUT_CHARS) -> str:
    """Redacted tail of captured output: last ``max_lines`` lines, at most ``max_chars`` characters."""
    lines = redact_text(text).splitlines()
    tail = lines[-max_lines:]
    body = "\n".join(line[:MAX_STRING] for line in tail)
    if len(body) > max_chars:
        body = body[-max_chars:]
    return body


def bound_string(value: object, limit: int = MAX_STRING) -> str:
    text = redact_text(str(value))
    return text if len(text) <= limit else text[: limit - 1] + "…"
