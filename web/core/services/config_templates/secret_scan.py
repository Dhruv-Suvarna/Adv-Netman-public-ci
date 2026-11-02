"""Secret scanning for template content.  Extraction REDACTS (the offending value is dropped and recorded as an
exclusion); publication and package import REJECT.  Findings name the path and the pattern -- never the matched text."""

from __future__ import annotations

import re

from .. import secret_policy
from ..raw_configlets import static_gate

_VALUE_PATTERNS = (
    ("PRIVATE_KEY_BLOCK", re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----")),
    ("CRYPT_HASH", re.compile(r"\$(?:1|5|6|2[aby]|y)\$[./A-Za-z0-9]{2,}\$?[./A-Za-z0-9]{8,}")),
    ("OTPAUTH_URI", re.compile(r"(?i)otpauth://")),
    ("BEARER_OR_JWT", re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{16,}|\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.")),
    ("VENDOR_TOKEN", re.compile(r"\b(?:ghp_[A-Za-z0-9]{20,}|xox[abprs]-[A-Za-z0-9-]{10,}|AKIA[0-9A-Z]{16}|nbt_[A-Za-z0-9]{20,})\b")),
    ("SECRET_ASSIGNMENT", re.compile(
        r"(?i)\b(?:password|passwd|secret|key-string|pre-shared-key|community|api[_-]?key|token|radius[_-]?secret|totp[_-]?seed)\b\s*[:= ]\s*\S{4,}")),
    ("LONG_OPAQUE_TOKEN", re.compile(r"\b(?=[A-Za-z0-9+]*[A-Z])(?=[A-Za-z0-9+]*[a-z])(?=[A-Za-z0-9+]*\d)[A-Za-z0-9+]{40,}={0,2}")),
)
_SAFE_REF_RE = re.compile(r"^(?:runtime|vault|ref)://[A-Za-z0-9_./-]{1,120}$")


def _secret_shaped(key) -> bool:
    """Like ``secret_policy.is_secret_key`` but INCLUDING ``*_ref`` keys, which get their own (reference) handling here."""
    lowered = str(key).lower()
    return any(fragment in lowered for fragment in secret_policy.REDACT_KEY_SUBSTRINGS)


def _value_findings(text: str) -> list[str]:
    names = [name for name, pattern in _VALUE_PATTERNS if pattern.search(text)]
    for line in text.splitlines():
        names.extend(static_gate.secret_patterns(line))
    return sorted(set(names))


def scan(value, path: str = "") -> list[dict]:
    """Every secret-shaped key or value under ``value``: [{"path", "pattern"}]."""
    findings: list[dict] = []
    if isinstance(value, dict):
        for key, child in value.items():
            where = f"{path}.{key}" if path else str(key)
            if _secret_shaped(key):
                if str(key).lower().endswith("_ref"):
                    if child not in (None, "") and not (isinstance(child, str) and _SAFE_REF_RE.match(child)):
                        findings.append({"path": where, "pattern": "UNSAFE_SECRET_REFERENCE"})
                    continue
                if child not in (None, "", [], {}):
                    findings.append({"path": where, "pattern": "SECRET_SHAPED_KEY"})
                    continue
            findings.extend(scan(child, where))
    elif isinstance(value, (list, tuple)):
        for index, child in enumerate(value):
            findings.extend(scan(child, f"{path}[{index}]"))
    elif isinstance(value, str):
        findings.extend({"path": path, "pattern": name} for name in _value_findings(value))
    return findings


def redact(value, path: str = "") -> tuple[object, list[dict]]:
    """Remove every secret-shaped key / value.  -> (clean copy, findings).  Secret references are blanked too: a
    credential-provider reference is instance-local and has no meaning in a portable artifact."""
    findings: list[dict] = []
    if isinstance(value, dict):
        clean = {}
        for key, child in value.items():
            where = f"{path}.{key}" if path else str(key)
            if _secret_shaped(key):
                if child not in (None, "", [], {}):
                    findings.append({"path": where, "pattern": "SECRET_SHAPED_KEY"})
                if str(key).lower().endswith("_ref"):
                    clean[key] = ""
                continue
            clean[key], more = redact(child, where)
            findings.extend(more)
        return clean, findings
    if isinstance(value, list):
        out = []
        for index, child in enumerate(value):
            cleaned, more = redact(child, f"{path}[{index}]")
            findings.extend(more)
            out.append(cleaned)
        return out, findings
    if isinstance(value, str):
        names = _value_findings(value)
        if names:
            return "", [{"path": path, "pattern": name} for name in names]
    return value, findings
