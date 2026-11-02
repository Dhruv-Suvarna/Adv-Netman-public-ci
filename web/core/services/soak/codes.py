"""Phase-20 vocabularies, versions and the fixed operator-facing catalogues.

Everything an operator can be told is a FIXED message looked up by a stable code.  Nothing device-originated, no secret and no matched
text is ever put into a code, a message or a detail.
"""

from __future__ import annotations

from types import MappingProxyType

from ... import models

POLICY_VERSION = "20.0.0"        # the evaluation policy a run started under (pinned in the run)
COLLECTOR_VERSION = "20.0.0"     # the code that took a sample (creation metadata)
EVIDENCE_SCHEMA_VERSION = 1      # the canonical final evidence summary schema
COLLECTOR_ACTOR = "probation-soak-collector"
MAX_REASON_CHARS = 500           # the operator's Golden-decision comment
MAX_FINDINGS_PER_SAMPLE = 25
MAX_SAMPLE_ROWS_SHOWN = 100      # the soak detail timeline shows the newest N samples; the run stores them all

State = models.SoakState
Result = models.SoakResult
SampleResult = models.SoakSampleResult
Decision = models.GoldenDecisionKind

# sample classes (assessment.py)
OK, WARNING, UNAVAILABLE, RESOURCE_CRITICAL, INTENDED_STATE_FAILED = "OK", "WARNING", "UNAVAILABLE", "RESOURCE_CRITICAL", "INTENDED_STATE_FAILED"

# run.terminal_reason
BUNDLE_INTEGRITY_FAILED = "BUNDLE_INTEGRITY_FAILED"
OVERLAPPING_EXECUTION = "OVERLAPPING_EXECUTION"
CONFIGURATION_DRIFT = "CONFIGURATION_DRIFT"
EXPECTED_STATE_FAILED = "EXPECTED_STATE_FAILED"
RESOURCE_CRITICAL_SUSTAINED = "RESOURCE_CRITICAL_SUSTAINED"
COVERAGE_INSUFFICIENT = "COVERAGE_INSUFFICIENT"
CANCELLED_BY_OPERATOR = "CANCELLED_BY_OPERATOR"
TECHNICAL_PASS = "TECHNICAL_PASS"

TERMINAL_REASONS = MappingProxyType({
    BUNDLE_INTEGRITY_FAILED: "The Probation bundle no longer verifies against its recorded digests; the candidate is invalidated (never repaired).",
    OVERLAPPING_EXECUTION: "A later configuration execution touched the candidate's devices; this exact artifact is no longer what is running.",
    CONFIGURATION_DRIFT: "A device's running configuration no longer matches the digest recorded when probation started; this exact configuration is no longer what is running.",
    EXPECTED_STATE_FAILED: "An intended-state requirement of the candidate was demonstrably not met during the observation.",
    RESOURCE_CRITICAL_SUSTAINED: "A device stayed at a critical CPU / memory level for the project's consecutive-sample limit.",
    COVERAGE_INSUFFICIENT: "The observation period ended without enough usable evidence coverage (missing, stale or too-sparse samples).",
    CANCELLED_BY_OPERATOR: "The operator cancelled the soak; its evidence is kept and it can never become Golden.",
    TECHNICAL_PASS: "The observation window elapsed with sufficient healthy evidence; the operator's Golden decision is required.",
})

# --- may a soak START? ----------------------------------------------------------------------------------------------------
START_BLOCKERS = MappingProxyType({
    "NOT_PROBATION": ("Only a Probation bundle can be soaked.", "A soak observes a Probation candidate; UAT and Golden bundles are never soaked."),
    "BUNDLE_INTEGRITY_FAILED": ("The Probation bundle failed its integrity verification.", "A bundle whose manifest no longer verifies can never be soaked or promoted; nothing is repaired."),
    "GOLDEN_EXISTS": ("This Probation bundle already has its Golden descendant.", "One Golden bundle per Probation bundle; there is nothing left to soak."),
    "BASELINE_UNREADABLE": ("The configuration of a device in scope could not be read to record the probation baseline.", "Restore the read-only device session; a soak does not start without a real baseline digest of every device it observes."),
    "SOAK_ACTIVE": ("A soak is already running for this Probation bundle.", "Wait for it to finish or cancel it; only one soak may be active at a time."),
    "SOURCE_UNVERIFIED": ("The candidate's applied scope was never operationally verified.", "An UNVERIFIED scope cannot be soaked; run a UAT whose scope the postcheck can confirm."),
    "POSTCHECK_NOT_ACCEPTABLE": ("The candidate's UAT postcheck is not PASS / PASS_WITH_WARNINGS.", "A soak needs acceptable, persisted verification evidence."),
    "SOURCE_EMPTY": ("The Probation bundle contains no Configlet.", "Nothing to observe."),
    "SUPERSEDED": ("A later execution has touched this candidate's devices since its source UAT execution.", "The candidate is superseded / interfered with: it is no longer the exact configuration that was applied. Start a new UAT / Probation lifecycle."),
    "EVIDENCE_SCOPE_UNSUPPORTED": ("The candidate's scope cannot be evaluated by the soak policy.", "Every scoped device must be a managed device whose platform supports read-only verification, and the pinned descriptors must be evaluable."),
})

# --- may a soak be cancelled / decided? -------------------------------------------------------------------------------------
DECISION_BLOCKERS = MappingProxyType({
    "CONFIRMATION_MISMATCH": ("The confirmed soak / bundle / digest does not match the current record.", "Reload the page and review the exact artifact before deciding."),
    "REASON_SECRET_SHAPED": ("The comment looks like it carries a secret.", "Remove the credential-like text; nothing is stored or silently redacted."),
    "DECISION_INVALID": ("The decision must be APPROVE or REJECT.", "Use the buttons on the decision form."),
    "NOT_RUNNING": ("The soak is not running.", "A finished soak is immutable; a cancelled soak can never be resumed."),
})


def blocker(catalogue, code: str, **details) -> dict:
    message, remediation = catalogue[code]
    return {"code": code, "message": message, "remediation": remediation, **({"details": details} if details else {})}
