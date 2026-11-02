"""Phase-18 vocabulary: versions, input bounds, verification result / currency words and the stable finding catalogue.

Everything an operator can be told is a FIXED message looked up by a stable code.  Sandbox / device text is never put into a
code or a message; findings carry bounded, sanitized evidence separately.  ``STALE`` is a currency state, never a result.
"""

from __future__ import annotations

# --- versions (a change to any of these makes existing verifications STALE for the affected revisions) ----------------------
VERIFIER_VERSION = "18.0.0"        # the verifier framework (orchestration, sanitization, result derivation)
POLICY_VERSION = "18.0.0-static1"  # the static safety policy (limits, denylists, secret rules)
SCHEMA_VERSION = 1                 # the Raw Configlet revision / snapshot schema

# --- input bounds (server-side; the browser's maxlength is never trusted) --------------------------------------------------
MAX_BYTES = 32 * 1024
MAX_LINES = 500
MAX_LINE_LENGTH = 512
MAX_NAME_LENGTH = 120
MAX_DESCRIPTION_LENGTH = 1000
MAX_DEPENDENCIES = 25
MAX_ASSERTIONS = 20

# --- output bounds (sandbox output is never stored unbounded) ----------------------------------------------------------------
MAX_CAPTURE_BYTES = 64 * 1024        # captured from a sandbox process before anything is parsed
MAX_EVIDENCE_LINES = 40
MAX_EVIDENCE_LINE_LENGTH = 240
MAX_FINDINGS = 60


class Result:
    """Verification RESULT vocabulary (shared with Phase-13 validation).  Never contains STALE."""

    PASS = "PASS"
    PASS_WITH_WARNINGS = "PASS_WITH_WARNINGS"
    BLOCKED = "BLOCKED"
    INCOMPLETE = "INCOMPLETE"
    ALL = (PASS, PASS_WITH_WARNINGS, BLOCKED, INCOMPLETE)
    ACCEPTABLE = (PASS, PASS_WITH_WARNINGS)


class Currency:
    NEVER_RUN = "NEVER_RUN"
    CURRENT = "CURRENT"
    STALE = "STALE"
    ALL = (NEVER_RUN, CURRENT, STALE)


class Stage:
    """Where a finding came from: the static gate, the sandbox lifecycle, or the platform parser itself."""

    STATIC = "STATIC"
    SANDBOX = "SANDBOX"
    PLATFORM = "PLATFORM"
    INTERNAL = "INTERNAL"


_E, _W, _I = "ERROR", "WARNING", "INFO"

# code -> (stage, severity, blocking, incomplete, meaning, remediation)
CODE_CATALOG: dict[str, tuple[str, str, bool, bool, str, str]] = {
    # --- static gate ---------------------------------------------------------------------------------------------------
    "RAW_EMPTY": (Stage.STATIC, _E, True, False, "The configuration body is empty.", "Enter at least one configuration statement."),
    "RAW_TOO_LARGE": (Stage.STATIC, _E, True, False, "The configuration exceeds the maximum size.", "Split it into several Raw Configlets."),
    "RAW_TOO_MANY_LINES": (Stage.STATIC, _E, True, False, "The configuration exceeds the maximum number of lines.", "Split it into several Raw Configlets."),
    "RAW_LINE_TOO_LONG": (Stage.STATIC, _E, True, False, "A line exceeds the maximum length.", "Shorten the line."),
    "RAW_NUL_BYTE": (Stage.STATIC, _E, True, False, "The input contains a NUL byte.", "Remove the NUL byte."),
    "RAW_INVALID_ENCODING": (Stage.STATIC, _E, True, False, "The input is not valid text (invalid encoding).", "Submit plain ASCII text."),
    "RAW_CONTROL_CHARACTER": (Stage.STATIC, _E, True, False, "The input contains a control character (tabs are not allowed; indent with spaces).", "Remove control characters."),
    "RAW_NON_ASCII_CHARACTER": (Stage.STATIC, _E, True, False, "The input contains a non-ASCII character.", "Use printable ASCII only."),
    "RAW_SECRET_SHAPED_CONTENT": (Stage.STATIC, _E, True, False, "A line looks like it carries a credential or secret. Raw Configlets cannot hold secret values and the project has no secret-reference resolution for raw CLI.", "Remove the credential; configure it through a mechanism that does not persist plaintext."),
    "RAW_PROMPT_TRANSCRIPT": (Stage.STATIC, _E, True, False, "A line looks like a device prompt / login transcript. Submit the configuration body only.", "Remove prompts such as 'R1(config)#'."),
    "RAW_MODE_CONTROL_COMMAND": (Stage.STATIC, _E, True, False, "A mode-control command (enable, configure, exit, end, ...) is not allowed: the executor owns configuration-mode entry and exit; express nesting with indentation.", "Remove the mode-control line."),
    "RAW_HOST_SHELL_COMMAND": (Stage.STATIC, _E, True, False, "A host-shell / remote-access / file command is not network configuration.", "Remove the command."),
    "RAW_SHELL_METACHARACTER": (Stage.STATIC, _E, True, False, "A shell metacharacter sequence is not allowed in configuration statements.", "Remove the metacharacter sequence."),
    "RAW_EXEC_MODE_COMMAND": (Stage.STATIC, _E, True, False, "An exec-mode / operational command (show, clear, write, copy, reload, ...) is outside the Raw Configlet contract.", "Raw Configlets carry configuration statements only."),
    "RAW_HOST_EXECUTION_CONSTRUCT": (Stage.STATIC, _E, True, False, "A configuration construct that can run host commands (event-handler, daemon, schedule, alias, action bash) is not allowed.", "Remove the construct."),
    "RAW_UNSUPPORTED_CONTEXT": (Stage.STATIC, _E, True, False, "A multi-line input context (for example a banner) is not supported.", "Remove the construct."),
    "RAW_PLATFORM_UNSUPPORTED": (Stage.STATIC, _E, True, False, "The target platform has no supported raw verification path.", "Raw Configlets are available only for platforms with an evidence-backed verifier."),
    # --- authoring metadata (validated server-side before a revision is persisted) -----------------------------------------
    "RAW_NAME_INVALID": (Stage.STATIC, _E, True, False, "The name is required and must be short printable text.", "Enter a name."),
    "RAW_TARGET_INVALID": (Stage.STATIC, _E, True, False, "The target device must be a device that already has a Device Intent in this Change.", "Add a Device Intent for the device first."),
    "RAW_PRIORITY_INVALID": (Stage.STATIC, _E, True, False, "The priority must be one of the nine canonical deployment priorities (1-9).", "Choose a priority."),
    "RAW_DEPENDENCY_INVALID": (Stage.STATIC, _E, True, False, "A dependency reference is malformed.", "Use a stable reference such as R1/interface/<id> or R1/raw_configlet/RAW-001."),
    "RAW_DEPENDENCY_SELF": (Stage.STATIC, _E, True, False, "A Raw Configlet cannot depend on itself.", "Remove the self-reference."),
    "RAW_ASSERTION_INVALID": (Stage.STATIC, _E, True, False, "A postcheck assertion is not valid for the closed assertion catalogue.", "Use one of the documented assertion kinds with valid values."),
    # --- sandbox lifecycle (a failure here is never a PASS) -------------------------------------------------------------
    "SANDBOX_DISABLED": (Stage.SANDBOX, _E, False, True, "This sandbox backend requires reduced isolation (a privileged container) and is disabled by server policy.", "An operator with server access must enable it explicitly; nothing was verified."),
    "SANDBOX_UNAVAILABLE": (Stage.SANDBOX, _E, False, True, "The container runtime is not available to the server.", "Restore the container runtime; nothing was verified."),
    "SANDBOX_IMAGE_MISSING": (Stage.SANDBOX, _E, False, True, "The server-owned sandbox image is not present locally.", "Build/import the documented image; nothing was verified."),
    "SANDBOX_START_FAILED": (Stage.SANDBOX, _E, False, True, "The sandbox could not be started.", "Retry; nothing was verified."),
    "SANDBOX_TIMEOUT": (Stage.SANDBOX, _E, False, True, "The sandbox did not finish within the time limit.", "Retry; nothing was verified."),
    "SANDBOX_CLEANUP_FAILED": (Stage.SANDBOX, _E, False, True, "The disposable sandbox could not be removed; verification is not reported as PASS.", "Remove the leftover sandbox container, then verify again."),
    "SANDBOX_OUTPUT_TRUNCATED": (Stage.SANDBOX, _W, False, False, "Sandbox output exceeded the bound and was truncated.", ""),
    "VERIFIER_OUTPUT_UNPARSEABLE": (Stage.INTERNAL, _E, False, True, "The verifier output could not be interpreted.", "Retry; nothing was verified."),
    "VERIFIER_INTERNAL_ERROR": (Stage.INTERNAL, _E, False, True, "The verifier failed unexpectedly.", "Report this defect; nothing was verified."),
    "RAW_REVISION_INTEGRITY": (Stage.INTERNAL, _E, True, False, "The stored revision text no longer matches its recorded content hash.", "Do not use this revision; save a new one."),
    "VERIFICATION_INTERRUPTED": (Stage.INTERNAL, _E, False, True, "The verification did not finish (lease expired).", "Verify again."),
    # --- platform parser -------------------------------------------------------------------------------------------------
    "SYNTAX_REJECTED": (Stage.PLATFORM, _E, True, False, "The platform parser rejected the configuration.", "Fix the rejected statement(s) and save a new revision."),
    "PLATFORM_WARNING": (Stage.PLATFORM, _W, False, False, "The platform parser emitted a warning.", ""),
    "SYNTAX_ACCEPTED": (Stage.PLATFORM, _I, False, False, "The platform parser accepted the configuration syntax.", ""),
    "SEMANTICS_NOT_VERIFIED": (Stage.PLATFORM, _I, False, False, "Only syntax was verified. The semantic / operational effect of this configuration is unknown; Change validation and the postcheck own that.", ""),
}


def finding(code: str, message: str = "", *, line: int | None = None, severity: str | None = None, **evidence) -> dict:
    """One structured finding.  ``evidence`` must be small, non-secret facts (line numbers, pattern NAMES, command words)."""
    stage, default_severity, blocking, incomplete, meaning, remediation = CODE_CATALOG[code]
    severity = severity or default_severity
    return {
        "code": code, "stage": stage, "severity": severity,
        "blocking": blocking and severity == _E, "incomplete": incomplete and severity == _E,
        "message": (message or meaning)[:400], "remediation": remediation, "line": line,
        "evidence": {k: v for k, v in sorted(evidence.items())},
    }


def derive_result(findings: list[dict]) -> str:
    """BLOCKED > INCOMPLETE > PASS_WITH_WARNINGS > PASS.  A verification with a gap is never PASS."""
    if any(f["blocking"] for f in findings):
        return Result.BLOCKED
    if any(f["incomplete"] for f in findings):
        return Result.INCOMPLETE
    if any(f["severity"] == _W for f in findings):
        return Result.PASS_WITH_WARNINGS
    return Result.PASS


def bounded_findings(findings: list[dict]) -> list[dict]:
    """Deterministic order (blocking first) and a hard bound."""
    rank = {_E: 0, _W: 1, _I: 2}
    ordered = sorted(findings, key=lambda f: (rank[f["severity"]], f["code"], f["line"] or 0, f["message"]))
    return ordered[:MAX_FINDINGS]
