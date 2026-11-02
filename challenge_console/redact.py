"""The last line of defence before anything is logged or saved.

Collectors already publish only fixed codes and parsed facts (never raw exception text, argv with a secret, or an HTTP header), and
no adapter selects a secret column.  This module still scrubs every record on its way to disk: a secret-named key loses its value and
a credential-shaped string is replaced, so a future mistake upstream cannot put a secret into a saved session.
"""

from __future__ import annotations

import re

REDACTED = "[REDACTED]"
MAX_STRING = 2000

_SECRET_KEY = re.compile(
    r"(pass(word|wd|phrase)|secret|token|api[_-]?key|private[_-]?key|credential|authorization|cookie|totp|otp|seed|"
    r"pepper|community|auth[_-]?key|priv[_-]?key|break[_-]?glass)", re.I)
# keys that merely NAME a credential object without carrying one (kept readable; values are still pattern-scrubbed)
_SAFE_KEYS = frozenset({"credential_id", "credentials", "credential_rotation", "token_window"})
_SECRET_VALUE = (
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?(-----END [A-Z ]*PRIVATE KEY-----|$)", re.S),
    re.compile(r"\b(Bearer|Token|Basic)\s+[A-Za-z0-9._~+/=-]{8,}", re.I),
    re.compile(r"\bnbt_[A-Za-z0-9]+\.[A-Za-z0-9]+"),
    re.compile(r"(?i)\b(password|passwd|secret|token|api[_-]?key)\s*[=:]\s*\S+"),
    re.compile(r"\b[a-z][a-z0-9+.-]*://[^/\s:@]+:[^/\s@]+@"),      # scheme://user:password@host
    re.compile(r"\$[1-9a-z]{1,2}\$[./A-Za-z0-9$]{20,}"),           # crypt(3) hashes (EOS ``secret sha512 ...``)
)


def scrub_text(text: str) -> str:
    for pattern in _SECRET_VALUE:
        text = pattern.sub(REDACTED, text)
    return text if len(text) <= MAX_STRING else text[:MAX_STRING] + "...[truncated]"


def scrub(value, key: str = ""):
    """A deep copy of ``value`` that is safe to persist."""
    if key and key not in _SAFE_KEYS and _SECRET_KEY.search(key) and not isinstance(value, (dict, list, tuple)):
        return REDACTED if value not in (None, "", False, True) else value
    if isinstance(value, dict):
        return {str(k): scrub(v, str(k)) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [scrub(item, key) for item in value]
    if isinstance(value, str):
        return scrub_text(value)
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    return scrub_text(str(value))


def classify_exception(exc: BaseException) -> str:
    """A fixed, secret-free class for an unexpected exception.  The exception TEXT is never logged: it can echo connection parameters."""
    name = type(exc).__name__
    if isinstance(exc, TimeoutError) or "Timeout" in name:
        return "TIMEOUT"
    if isinstance(exc, (ConnectionError, OSError)):
        return "IO_ERROR"
    if isinstance(exc, (ValueError, KeyError, TypeError, IndexError)):
        return "PARSE_ERROR"
    return "INTERNAL_ERROR"
