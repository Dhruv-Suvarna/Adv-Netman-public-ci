"""CheckResult (the structured-evidence record), bounded serialization and the aggregation rules.

Every result carries, at minimum: check_code, status, category, device, message, source, observed, expected,
timestamp, freshness, blocking, remediation -- never prose alone.  Aggregation is deterministic (no scores).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone

from .. import secret_policy
from .codes import CODES, CheckStatus, Health, PostcheckResult, PrecheckResult, Role

MAX_STRING = 240
MAX_LIST = 25
MAX_DEPTH = 4
MAX_RESULTS = 400
MAX_REPORT_BYTES = 384 * 1024


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def iso(value: datetime | None) -> str | None:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z") if value else None


def _secret_key(key) -> bool:
    lowered = str(key).lower()
    return not lowered.endswith("_ref") and any(part in lowered for part in secret_policy.FORBIDDEN_METADATA_KEY_SUBSTRINGS)


def bound(value, depth: int = 0):
    """A bounded, JSON-safe, secret-key-redacted copy (never raises, never mutates)."""
    if depth > MAX_DEPTH:
        return "[TRUNCATED]"
    if value is None or isinstance(value, (bool, int)):
        return value
    if isinstance(value, float):
        return round(value, 4)
    if isinstance(value, str):
        return value if len(value) <= MAX_STRING else value[: MAX_STRING - 3] + "..."
    if isinstance(value, dict):
        out, redacted = {}, 0
        for key in sorted(value, key=str)[:MAX_LIST]:
            if _secret_key(key):  # drop the secret-shaped KEY as well as its value, so a stored report can never carry the name
                redacted += 1
                out[f"redacted_field_{redacted}"] = "[REDACTED]"
            else:
                out[str(key)[:MAX_STRING]] = bound(value[key], depth + 1)
        return out
    if isinstance(value, (list, tuple, set, frozenset)):
        items = sorted(value, key=str) if isinstance(value, (set, frozenset)) else list(value)
        return [bound(item, depth + 1) for item in items[:MAX_LIST]]
    return bound(str(value), depth)


def effective_blocking(code: str, status: str, role: str) -> bool:
    """Blocking policy.  Only on a TARGET device or a PLAN-level gate:

    * a FAIL blocks when its code is ``blocking``  (the evidence demonstrates the problem -> precheck BLOCKED);
    * an UNKNOWN blocks when its code is ``unknown_blocks``  (evidence unavailable -> precheck INCOMPLETE).

    WARN never blocks; a PEER or fleet-wide (FLEET) result never blocks; PASS / NOT_APPLICABLE never block.
    """
    if role not in (Role.TARGET, Role.PLAN):
        return False
    spec = CODES[code]
    return (status == CheckStatus.FAIL and spec.blocking) or (status == CheckStatus.UNKNOWN and spec.unknown_blocks)


@dataclass
class CheckResult:
    check_code: str
    status: str
    device: str
    message: str
    source: str                      # LIVE | TELEMETRY | PLAN | SYNTHETIC | NONE
    observed: object = None
    expected: object = None
    observed_at: str | None = None   # when the underlying fact was observed (not when it was evaluated)
    freshness: str = "UNKNOWN"
    role: str = Role.FLEET
    phase: str = ""
    requirement: str = ""
    cfg_id: str = ""
    subject: str = ""
    timestamp: str = field(default_factory=lambda: iso(utcnow()))

    def __post_init__(self):
        if self.check_code not in CODES:
            raise ValueError(f"Unknown health check code {self.check_code!r}")
        if self.status not in CheckStatus.ALL:
            raise ValueError(f"Unknown check status {self.status!r}")

    @property
    def category(self) -> str:
        return CODES[self.check_code].category

    @property
    def remediation(self) -> str:
        return CODES[self.check_code].remediation

    @property
    def blocking(self) -> bool:
        return effective_blocking(self.check_code, self.status, self.role)

    def to_dict(self) -> dict:
        return {
            "check_code": self.check_code, "status": self.status, "category": self.category, "device": self.device,
            "message": bound(self.message), "source": self.source, "observed": bound(self.observed),
            "expected": bound(self.expected), "timestamp": self.timestamp, "observed_at": self.observed_at,
            "freshness": self.freshness, "blocking": self.blocking, "remediation": self.remediation,
            "role": self.role, "phase": self.phase, "requirement": self.requirement, "cfg_id": self.cfg_id,
            "subject": bound(self.subject),
        }


def _sort_key(result: CheckResult):
    return (result.device, result.category, result.check_code, result.cfg_id, result.subject, result.status)


def ordered(results) -> list[CheckResult]:
    return sorted(results, key=_sort_key)


def count_by_status(results) -> dict:
    counts = {status: 0 for status in CheckStatus.ALL}
    for result in results:
        counts[result.status] += 1
    return counts


# --- aggregation -------------------------------------------------------------------------------------------------
def aggregate_health(results) -> str:
    """HEALTHY / DEGRADED / UNHEALTHY / UNKNOWN from a device's (or the fleet's) results.

    1. any FAIL -> UNHEALTHY;  2. else any WARN -> DEGRADED;
    3. else the *core* liveness checks decide: if none of them PASSED the device is UNKNOWN (no proof of life);
    4. else HEALTHY.  A non-core UNKNOWN (e.g. an unavailable memory metric) is reported but never downgrades.
    """
    applicable = [r for r in results if r.status != CheckStatus.NOT_APPLICABLE]
    if any(r.status == CheckStatus.FAIL for r in applicable):
        return Health.UNHEALTHY
    if any(r.status == CheckStatus.WARN for r in applicable):
        return Health.DEGRADED
    core = [r for r in applicable if CODES[r.check_code].core]
    if not applicable or (core and not any(r.status == CheckStatus.PASS for r in core)):
        return Health.UNKNOWN
    if not core and not any(r.status == CheckStatus.PASS for r in applicable):
        return Health.UNKNOWN
    return Health.HEALTHY


def precheck_result(results) -> str:
    """BLOCKED on any blocking FAIL; INCOMPLETE on any blocking UNKNOWN; warnings otherwise; else PASS."""
    active = [r for r in results if r.status != CheckStatus.NOT_APPLICABLE]
    if any(r.blocking and r.status == CheckStatus.FAIL for r in active):
        return PrecheckResult.BLOCKED
    if any(r.blocking and r.status == CheckStatus.UNKNOWN for r in active):
        return PrecheckResult.INCOMPLETE
    if any(r.status in (CheckStatus.WARN, CheckStatus.FAIL, CheckStatus.UNKNOWN) for r in active):
        return PrecheckResult.PASS_WITH_WARNINGS
    return PrecheckResult.PASS


def postcheck_result(results) -> str:
    """FAIL on any FAIL; INCOMPLETE on any UNKNOWN or when nothing was actually verified; warnings; else PASS.

    Every requirement of a postcheck is *required*: a missing observation is never a PASS.
    """
    active = [r for r in results if r.status != CheckStatus.NOT_APPLICABLE]
    if any(r.status == CheckStatus.FAIL for r in active):
        return PostcheckResult.FAIL
    if any(r.status == CheckStatus.UNKNOWN for r in active) or not any(r.status == CheckStatus.PASS for r in active):
        return PostcheckResult.INCOMPLETE
    if any(r.status == CheckStatus.WARN for r in active):
        return PostcheckResult.PASS_WITH_WARNINGS
    return PostcheckResult.PASS


def bounded_results(results) -> tuple[list[dict], bool]:
    """Serialized results, capped at MAX_RESULTS keeping the most severe first.  -> (rows, truncated)."""
    rank = {CheckStatus.FAIL: 0, CheckStatus.UNKNOWN: 1, CheckStatus.WARN: 2, CheckStatus.PASS: 3, CheckStatus.NOT_APPLICABLE: 4}
    rows = sorted(ordered(results), key=lambda r: rank[r.status])
    truncated = len(rows) > MAX_RESULTS
    return [r.to_dict() for r in rows[:MAX_RESULTS]], truncated
