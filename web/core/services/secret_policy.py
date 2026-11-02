"""
Shared secret-shaped metadata policy.

One denylist, one behavior, reused by every subsystem that persists JSON
metadata: Phase 4's Notification event pipeline and Phase 8's Change/
DeviceIntent/Configlet control-plane models. Reject hard (raise ValueError),
never silently strip a key -- callers must not put secrets in structured
metadata at all.

A key ending in "_ref" (e.g. "secret_ref", "credential_ref") is treated as a
safe external reference to a secret held elsewhere (a credential store, an
inventory entry), not a secret value itself, and is exempt. This is the
sanctioned way to point at a credential without persisting it -- see
docs/DEVICE_INTENT_CHANGE_MODEL.md "Secret handling".

Originally Phase 4-only (notification_service._validate_metadata). Phase 8
generalizes it here rather than growing a second, slightly different
denylist, per the project's "one reusable policy" rule.
"""

from __future__ import annotations

import re
from typing import Any

# Case-insensitive substrings that make a metadata key "secret-shaped".
# Superset of the original Phase 4 list plus the Phase 8 additions
# (auth_key, priv_key, community) called out for device credential material.
FORBIDDEN_METADATA_KEY_SUBSTRINGS = (
    "password",
    "passwd",
    "secret",
    "token",
    "webhook",
    "credential",
    "apikey",
    "api_key",
    "private_key",
    "priv_key",
    "auth_key",
    "community",
)

_SAFE_KEY_SUFFIX = "_ref"


def assert_no_secret_shaped_keys(data: dict[str, Any], *, context: str = "metadata") -> dict[str, Any]:
    """
    Raise ValueError if any key in `data` (recursively, for nested dicts)
    looks like it holds a secret value. A key ending in "_ref" is exempt --
    it names a reference, not a value. Returns `data` unchanged so callers
    can use this as a validating pass-through.
    """
    _check(data, context)
    return data


def _check(value: Any, context: str) -> None:
    if isinstance(value, dict):
        for key, nested in value.items():
            lowered = str(key).lower()
            if not lowered.endswith(_SAFE_KEY_SUFFIX):
                for forbidden in FORBIDDEN_METADATA_KEY_SUBSTRINGS:
                    if forbidden in lowered:
                        raise ValueError(
                            f"{context} key {key!r} looks like a secret (matches "
                            f"{forbidden!r}) and cannot be stored. Use a "
                            "'<name>_ref' key holding a safe reference instead."
                        )
            _check(nested, context)
    elif isinstance(value, (list, tuple)):
        for item in value:
            _check(item, context)


# --- V2 Phase 1: redaction for request / audit evidence ------------------------------------------
#
# ``assert_no_secret_shaped_keys`` above REJECTS: a caller building structured metadata must never put a secret in it.
# Request auditing is different -- the middleware records data the *browser* chose to send, so it must never fail the
# request and must never persist a value.  ``redact`` is that one sanctioned path: the same denylist plus the
# web/identity-specific names below, applied recursively, returning a copy with every secret-shaped value replaced.
# A key ending in "_ref" stays exempt, exactly as for the rejecting check.

REDACTED = "[REDACTED]"

# Additional key substrings that are only meaningful for HTTP / identity evidence (form fields, headers, cookies).
# Kept separate from FORBIDDEN_METADATA_KEY_SUBSTRINGS so the rejecting check's long-standing behaviour is unchanged.
REDACT_EXTRA_KEY_SUBSTRINGS = (
    "otp",            # otp / totp / otp_token / one-time code fields
    "mfa_code",
    "seed",
    "recovery",
    "passphrase",
    "csrf",
    "cookie",
    "sessionid",
    "session_key",
    "authorization",
    "bearer",
    "radius",
    "cf_access",
    "cf-access",
    "tunnel_cred",
    "qr",
    "signature",
)
REDACT_KEY_SUBSTRINGS = FORBIDDEN_METADATA_KEY_SUBSTRINGS + REDACT_EXTRA_KEY_SUBSTRINGS

# Request headers that are never recorded, even redacted (they carry credentials or session state).
SENSITIVE_HEADER_NAMES = frozenset({
    "authorization", "proxy-authorization", "cookie", "set-cookie", "x-csrftoken", "x-csrf-token",
    "cf-access-jwt-assertion", "cf-access-client-secret", "cf-access-client-id", "x-api-key",
})

# High-confidence secret VALUE formats, redacted wherever they appear in a recorded string.

_SECRET_VALUE_PATTERNS = (
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?(?:-----END [A-Z ]*PRIVATE KEY-----|\Z)", re.S),
    re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{8,}"),
    re.compile(r"(?i)otpauth://\S+"),
    re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,})\b"),
    re.compile(r"\bxox[abposr]-[A-Za-z0-9-]{10,}"),
)


def is_secret_key(key: Any) -> bool:
    """True when ``key`` names a secret-shaped value (case-insensitive; a ``*_ref`` key is a reference, not a value)."""
    lowered = str(key).lower()
    if lowered.endswith(_SAFE_KEY_SUFFIX):
        return False
    return any(fragment in lowered for fragment in REDACT_KEY_SUBSTRINGS)


def redact_text(value: str) -> str:
    """Mask high-confidence secret value formats (private keys, bearer tokens, otpauth URIs, known token formats)."""
    for pattern in _SECRET_VALUE_PATTERNS:
        value = pattern.sub(REDACTED, value)
    return value


def redact(data: Any, *, max_string: int = 512) -> Any:
    """A redacted deep copy of ``data``: secret-shaped keys keep their name but lose their value; strings are
    value-scanned and bounded.  Never raises for ordinary JSON-shaped input."""
    if isinstance(data, dict):
        return {str(k): (REDACTED if is_secret_key(k) else redact(v, max_string=max_string)) for k, v in data.items()}
    if isinstance(data, (list, tuple)):
        return [redact(item, max_string=max_string) for item in data]
    if isinstance(data, str):
        text = redact_text(data)
        return text if len(text) <= max_string else text[:max_string] + "...[truncated]"
    if data is None or isinstance(data, (bool, int, float)):
        return data
    return redact(str(data), max_string=max_string)


def redact_headers(headers: dict[str, Any]) -> dict[str, Any]:
    """Drop credential-bearing headers entirely; redact the rest like any mapping."""
    kept = {k: v for k, v in headers.items() if str(k).lower() not in SENSITIVE_HEADER_NAMES}
    return redact(kept)
