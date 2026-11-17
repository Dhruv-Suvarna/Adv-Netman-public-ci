"""Versioned, serializable contracts for the troubleshooting engine (spec 2.1) plus redaction/freshness primitives.

Pure module: no Django, no I/O.  Every payload that crosses a milestone boundary (collectors -> repository, repository ->
AI handoff / API / report) is a plain ``dict`` carrying ``schema`` = ``"<name>/<major>"``; ``validate()`` checks it against
the registered schema and returns a list of human-readable problems (empty list == valid).  Unknown schema versions fail.

Schemas (``SCHEMAS``):  collection_bundle/1  observation/1  test_verdict/1  incident_report/1  ai_handoff/1
"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timedelta, timezone
from typing import Any

SCHEMA_VERSION_SUFFIX = "/1"

# ---------------------------------------------------------------------------------------------------------------- enums
VERDICTS = ("PASS", "FAIL", "INCONCLUSIVE", "SKIPPED", "UNAVAILABLE")
BASES = ("OBSERVED", "DERIVED", "AI_INFERRED", "OPERATOR_CONFIRMED")
QUALITIES = ("GOOD", "PARTIAL", "AMBIGUOUS", "UNTRUSTED", "MISSING")
STAGES = ("COLLECT", "NORMALIZE", "BASELINE", "CORRELATE", "TEST", "DIAGNOSE", "AI", "REMEDIATE", "VERIFY", "DOCUMENT")
RUN_STATUSES = ("PENDING", "RUNNING", "SUCCEEDED", "FAILED", "PARTIAL", "DENIED", "UNAVAILABLE", "SKIPPED")
LINK_STATUSES = ("OK", "BROKEN", "MISSING", "UNVERIFIED")
REPORT_SECTION_KEYS = (
    "incident_summary", "collection", "normalization", "baseline", "correlation", "test_matrix",
    "deterministic_diagnosis", "ai_investigation", "remediation_governance", "verification_soak", "final_disposition",
)
BASIS_LABEL = {
    "OBSERVED": "directly observed", "DERIVED": "deterministically derived",
    "AI_INFERRED": "AI-inferred", "OPERATOR_CONFIRMED": "operator-confirmed",
}
# Three-valued state: missing/stale/untrusted evidence is UNKNOWN, never false-healthy and never false-fault (UT-006).
UNKNOWN = "UNKNOWN"
FRESH, STALE, NO_DATA, UNTRUSTED = "FRESH", "STALE", "MISSING", "UNTRUSTED"


# ------------------------------------------------------------------------------------------------------ schema registry
def _s(required: dict[str, Any], optional: dict[str, Any] | None = None) -> dict[str, Any]:
    return {"required": required, "optional": optional or {}}


# type tokens: str int num bool dict list any, "T|null" nullable, ("enum", (...)) enumerations
def _ENUM(*vals):
    return ("enum", tuple(vals))
OBSERVATION_FIELDS = {
    "key": "str", "target": "str", "observed_at": "iso8601", "source": "str", "quality": _ENUM(*QUALITIES),
    "basis": _ENUM(*BASES),
}
SCHEMAS: dict[str, dict[str, Any]] = {
    "observation/1": _s(
        OBSERVATION_FIELDS,
        {"value": "any", "unit": "str", "max_age_seconds": "int", "confidence": "num", "parser_version": "str",
         "raw_hash": "str", "raw_pointer": "str", "redaction_status": "str", "evidence_id": "str",
         "is_missing_data": "bool", "missing_reason": "str", "dedupe_key": "str", "stage_decision": "str"}),
    "collection_bundle/1": _s(
        {"case_id": "str", "collector": "str", "adapter": "str", "adapter_version": "str", "idempotency_key": "str",
         "targets": "list", "command_or_api": "str", "status": _ENUM(*RUN_STATUSES), "observations": "list"},
        {"started_at": "iso8601", "finished_at": "iso8601", "attempts": "int", "timeout_seconds": "int",
         "rate_budget": "dict", "privileges": "str", "error": "str", "raw": "dict", "evidence_id": "str"}),
    "test_verdict/1": _s(
        {"test_id": "str", "test_version": "str", "target": "str", "expected": "str", "verdict": _ENUM(*VERDICTS),
         "reason": "str"},
        {"hypothesis": "str", "hypothesized_condition": "str", "preconditions": "list", "command_or_api": "str",
         "observed": "dict", "observed_summary": "str", "interpretation": "str", "next_action": "str",
         "evidence_ids": "list", "executed_at": "iso8601", "basis": _ENUM(*BASES), "attempt": "int"}),
    "incident_report/1": _s(
        {"case_id": "str", "generated_at": "iso8601", "sections": "dict", "section_order": "list",
         "limitations": "list", "evidence_index": "dict"},
        {"filters": "dict", "freshness": "dict"}),
    "ai_handoff/1": _s(
        {"case_id": "str", "coverage_manifest": "dict", "trigger_uncertainty": "str", "allowed_tools": "list",
         "allowed_targets": "list", "budget": "dict", "evidence_ids": "list", "return_conditions": "list"},
        {"reasoning_log": "list", "agent_identity": "str", "checkpoint": "dict"}),
}
CONTRACT_NAMES = tuple(SCHEMAS)


def schema_name(payload: dict[str, Any]) -> str:
    return str(payload.get("schema", "")) if isinstance(payload, dict) else ""


def _type_ok(value: Any, spec: Any) -> bool:
    if isinstance(spec, tuple) and spec[0] == "enum":
        return value in spec[1]
    nullable = isinstance(spec, str) and spec.endswith("|null")
    token = spec[:-5] if nullable else spec
    if value is None:
        return nullable or token == "any"
    if token == "any":
        return True
    if token == "str":
        return isinstance(value, str)
    if token == "int":
        return isinstance(value, int) and not isinstance(value, bool)
    if token == "num":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    if token == "bool":
        return isinstance(value, bool)
    if token == "dict":
        return isinstance(value, dict)
    if token == "list":
        return isinstance(value, list)
    if token == "iso8601":
        return isinstance(value, str) and parse_time(value) is not None
    return False


def validate(payload: Any, expected: str | None = None) -> list[str]:
    """Return a list of contract violations ([] == valid).  Unknown schema / version / extra keys / wrong types all fail."""
    if not isinstance(payload, dict):
        return ["payload must be an object"]
    name = schema_name(payload)
    if expected and name != expected:
        return [f"schema must be {expected!r}, got {name!r}"]
    spec = SCHEMAS.get(name)
    if spec is None:
        return [f"unknown or unsupported schema {name!r}"]
    problems = []
    body = {k: v for k, v in payload.items() if k != "schema"}
    for key, kind in spec["required"].items():
        if key not in body:
            problems.append(f"missing required field {key!r}")
        elif not _type_ok(body[key], kind):
            problems.append(f"field {key!r} has wrong type/value ({kind if isinstance(kind, str) else kind[1]})")
    for key, value in body.items():
        if key in spec["required"]:
            continue
        if key not in spec["optional"]:
            problems.append(f"unexpected field {key!r}")
        elif not _type_ok(value, spec["optional"][key]):
            problems.append(f"field {key!r} has wrong type")
    if name == "collection_bundle/1" and isinstance(body.get("observations"), list):
        for i, obs in enumerate(body["observations"]):
            problems += [f"observations[{i}]: {p}" for p in validate({"schema": "observation/1", **obs} if isinstance(obs, dict) else obs, "observation/1")]
    return problems


def assert_valid(payload: Any, expected: str | None = None) -> dict[str, Any]:
    problems = validate(payload, expected)
    if problems:
        raise ValueError("contract violation: " + "; ".join(problems))
    return payload


def with_schema(name: str, body: dict[str, Any]) -> dict[str, Any]:
    if name not in SCHEMAS:
        raise ValueError(f"unknown schema {name!r}")
    return {"schema": name, **body}


# --------------------------------------------------------------------------------------------------------- time / hashing
def parse_time(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if not isinstance(value, str) or not value:
        return None
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def iso(dt: datetime | None) -> str:
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z") if dt else ""


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str, ensure_ascii=True)


def sha256_text(text: str | bytes) -> str:
    data = text.encode("utf-8", "replace") if isinstance(text, str) else text
    return hashlib.sha256(data).hexdigest()


# --------------------------------------------------------------------------------------------------------------- redaction
REDACTED = "[REDACTED]"
_SECRET_KEY = re.compile(
    r"(password|passwd|secret|token|webhook|credential|api[_-]?key|private[_-]?key|priv[_-]?key|auth[_-]?key|community|"
    r"authorization|session|cookie|bearer|payload|ssn|email)", re.I)
_SAFE_REF = re.compile(r"_ref$", re.I)
_TEXT_PATTERNS = [
    # PEM blocks
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?(-----END [A-Z ]*PRIVATE KEY-----|\Z)", re.S), REDACTED),
    # Cisco/Arista "secret 5 $1$..." / "password 7 0822..." / "enable secret ..." / "username x secret ..."
    (re.compile(r"(?im)\b((?:enable\s+)?(?:secret|password)(?:\s+\d)?)\s+(\S+)"), r"\1 " + REDACTED),
    # SNMP communities / v3 keys
    (re.compile(r"(?im)\b(snmp-server\s+community)\s+(\S+)"), r"\1 " + REDACTED),
    (re.compile(r"(?im)\b(community|auth-key|priv-key|authentication\s+\S+\s+\S+|privacy\s+\S+\s+\S+)\s+(\S+)"), r"\1 " + REDACTED),
    # key=value / key: value secrets
    (re.compile(r"(?i)\b((?:[a-z0-9_.-]*)(?:password|passwd|secret|token|api[_-]?key|private[_-]?key|authorization|community)[a-z0-9_.-]*)\s*([=:])\s*(\"[^\"]*\"|'[^']*'|\S+)"), r"\1\2 " + REDACTED),
    # Bearer / Basic headers
    (re.compile(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]{8,}"), r"\1 " + REDACTED),
    # well-known token shapes (GitHub, Slack, AWS, JWT)
    (re.compile(r"\b(ghp|gho|ghs|ghu|github_pat)_[A-Za-z0-9_]{16,}"), REDACTED),
    (re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}"), REDACTED),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), REDACTED),
    (re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}"), REDACTED),
    # e-mail addresses (PII)
    (re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"), REDACTED),
]


def redact_text(text: str) -> tuple[str, int]:
    """Return (redacted_text, number_of_redactions).  Idempotent: already-redacted markers are not counted again."""
    count = 0
    out = text
    for pattern, repl in _TEXT_PATTERNS:
        def _sub(match, repl=repl):
            nonlocal count
            if match.group(0).rstrip().endswith(REDACTED):
                return match.group(0)
            count += 1
            return match.expand(repl)
        out = pattern.sub(_sub, out)
    return out, count


def redact_value(value: Any) -> Any:
    """Recursively redact a JSON-like value: secret-shaped keys lose their value, strings are pattern-redacted."""
    if isinstance(value, dict):
        out = {}
        for key, nested in value.items():
            if _SECRET_KEY.search(str(key)) and not _SAFE_REF.search(str(key)):
                # The value is dropped; the key is renamed to a "_ref" form so the shared secret-key policy still accepts the row.
                out[f"{key}_redacted_ref"] = REDACTED
            else:
                out[key] = redact_value(nested)
        return out
    if isinstance(value, (list, tuple)):
        return [redact_value(v) for v in value]
    if isinstance(value, str):
        return redact_text(value)[0]
    return value


def contains_secret(value: Any) -> bool:
    """True when redaction would change `value` (used by negative tests and export gates)."""
    return redact_value(value) != value


# -------------------------------------------------------------------------------------------------------------- freshness
def freshness(observed_at: datetime | None, max_age_seconds: int, now: datetime, *, quality: str = "GOOD",
              is_missing: bool = False, future_skew_seconds: int = 120) -> str:
    """FRESH | STALE | MISSING | UNTRUSTED.  Observations timestamped in the future beyond clock-skew tolerance are UNTRUSTED."""
    if is_missing or observed_at is None or quality == "MISSING":
        return NO_DATA
    if quality == "UNTRUSTED":
        return UNTRUSTED
    obs = parse_time(observed_at)
    if obs > now + timedelta(seconds=future_skew_seconds):
        return UNTRUSTED
    return FRESH if (now - obs).total_seconds() <= max_age_seconds else STALE


def tri_state(freshness_value: str, predicate_result: bool | None) -> str:
    """Collapse (freshness, predicate) to HEALTHY/FAULT/UNKNOWN.  Anything but FRESH evidence is UNKNOWN (UT-006)."""
    if freshness_value != FRESH or predicate_result is None:
        return UNKNOWN
    return "HEALTHY" if predicate_result else "FAULT"
