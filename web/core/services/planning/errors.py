"""Structured plan-generation failures.

A plan is generated atomically or not at all: every failure below is raised
BEFORE anything is persisted (or rolled back with the transaction), and carries
a stable machine-readable ``code`` plus an operator-safe ``message``.  Messages
are fixed text -- nothing from a browser, a device or an exception is echoed.
"""

from __future__ import annotations

# code -> operator-facing message (also the allowlist the UI accepts for ?refused=CODE)
ERROR_MESSAGES = {
    "VALIDATION_NEVER_RUN": "This Change has never been validated. Run Change Validation first; a plan is never built without it.",
    "VALIDATION_STALE": "The latest validation is stale (accepted intent or a consumed source changed). Re-run Change Validation, then build the plan.",
    "VALIDATION_BLOCKED": "The latest validation is BLOCKED. Resolve the blocking findings and re-run validation; a plan cannot be built.",
    "VALIDATION_INCOMPLETE": "The latest validation is INCOMPLETE (required evidence was unavailable). Re-run validation when the sources are available.",
    "INPUT_HASH_MISMATCH": "Accepted intent changed while the plan was being built. Re-run validation and try again.",
    "GRAPH_TRUNCATED": "The pinned validation's dependency graph was truncated, so no reliable order can be derived. Reduce the Change or re-run validation.",
    "DEPENDENCY_MISSING": "A validated dependency references an object that has no Configlet. The plan was not generated.",
    "CONFIGLET_CYCLE": "The Configlet dependency graph contains a cycle, so no safe order exists. The plan was not generated.",
    "RENDERER_INCONSISTENT": "The authoritative renderer produced no configuration for a supported object. The plan was not generated.",
    "UNSUPPORTED_OBJECT": "The Change contains an object the authoritative renderer reports as unsupported. The plan was not generated.",
    "AUTO_VALUE_MISSING": "An AUTO address has no derived value in the pinned validation. Re-run validation; the plan was not generated.",
    "UNRESOLVED_PLACEHOLDER": "A Configlet would contain an unresolved placeholder (a required value is missing from accepted intent). Complete the intent, re-validate, and rebuild.",
    "UNKNOWN_OBJECT_TYPE": "The pinned validation contains an object type the planner does not know. The plan was not generated.",
    "RAW_REVISION_MISMATCH": "A Raw Configlet revision named by the pinned validation is missing or no longer matches its content hash. Re-run validation; the plan was not generated.",
    "RAW_VERIFICATION_NOT_CURRENT": "A Raw Configlet has no CURRENT acceptable verification. Verify it, re-run validation, then build the plan.",
}


class PlanGenerationError(Exception):
    def __init__(self, code: str, **details):
        if code not in ERROR_MESSAGES:
            raise ValueError(f"Unknown plan error code {code!r}")
        self.code = code
        self.message = ERROR_MESSAGES[code]
        self.details = details
        super().__init__(f"{code}: {self.message}")

    def as_dict(self) -> dict:
        return {"code": self.code, "message": self.message, "details": self.details}
