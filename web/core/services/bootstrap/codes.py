"""Vocabularies, versions and the fixed operator-facing catalogues of the one-time legacy bootstrap.

Everything an operator can be told is a FIXED message looked up by a stable code.  Nothing device-originated, no secret and no matched text is
ever put into a code, a message or a detail.
"""

from __future__ import annotations

from types import MappingProxyType

from ... import models
from ..bundles.codes import LEGACY_BLOCKERS

POLICY_VERSION = "LEGACY_BOOTSTRAP_POLICY_V1"
COLLECTOR_VERSION = "20.1.0"
EVIDENCE_SCHEMA_VERSION = 1
COLLECTOR_ACTOR = "legacy-bootstrap-collector"
MAX_REASON_CHARS = 500
MAX_FINDINGS_PER_SAMPLE = 25
MAX_SAMPLE_ROWS_SHOWN = 100
BASELINE_ID_PREFIX = "BL-"          # ``cfg_id`` of a baseline-relative requirement (it is not a plan Configlet)

State, Result, SampleResult = models.SoakState, models.SoakResult, models.SoakSampleResult

# run.terminal_reason (the first four are shared, by value, with the Phase-20 soak vocabulary so the pure evaluator can be reused unchanged)
BUNDLE_INTEGRITY_FAILED = "BUNDLE_INTEGRITY_FAILED"
OVERLAPPING_EXECUTION = "OVERLAPPING_EXECUTION"
EXPECTED_STATE_FAILED = "EXPECTED_STATE_FAILED"
RESOURCE_CRITICAL_SUSTAINED = "RESOURCE_CRITICAL_SUSTAINED"
COVERAGE_INSUFFICIENT = "COVERAGE_INSUFFICIENT"
CONFIG_DRIFT_DETECTED = "CONFIG_DRIFT_DETECTED"
CANCELLED_BY_OPERATOR = "CANCELLED_BY_OPERATOR"
TECHNICAL_PASS = "TECHNICAL_PASS"

TERMINAL_REASONS = MappingProxyType({
    BUNDLE_INTEGRITY_FAILED: "The legacy baseline candidate no longer verifies against its recorded digests; the observation is invalidated (never repaired).",
    OVERLAPPING_EXECUTION: "A network configuration execution touched an included device after the baseline was captured; the observed baseline is no longer what is running.",
    CONFIG_DRIFT_DETECTED: "The running configuration of an included device changed during the observation; the baseline is invalidated and is never adopted automatically.",
    EXPECTED_STATE_FAILED: "A required health condition of the observed network demonstrably failed (adjacency, route, interface, link or connectivity).",
    RESOURCE_CRITICAL_SUSTAINED: "A device stayed at a critical CPU / memory level for the project's consecutive-sample limit.",
    COVERAGE_INSUFFICIENT: "The observation ended without enough usable evidence coverage (missing, stale or too-sparse samples).",
    CANCELLED_BY_OPERATOR: "The operator cancelled the observation; its evidence is kept and it can never become Golden.",
    TECHNICAL_PASS: "The observation window elapsed with sufficient healthy evidence and no configuration drift; the operator's approval is required.",
})

# --- capture / start blockers (the gate blockers live in ``bundles.codes.LEGACY_BLOCKERS``) --------------------------------------------
BOOTSTRAP_BLOCKERS = MappingProxyType({
    **LEGACY_BLOCKERS,
    "BOOTSTRAP_BASELINE_INCOMPLETE": ("A required managed device could not be captured.", "The baseline is all-or-nothing: every managed device must be read, unreachable / unsupported / failing devices are never silently omitted. Nothing was created."),
    "BASELINE_UNHEALTHY": ("The network is not healthy right now, so it cannot be adopted as the known-good baseline.", "A demonstrated failure (adjacency, route, interface, link, connectivity, resource) blocks the capture. Nothing is repaired automatically."),
    "BASELINE_EVIDENCE_UNAVAILABLE": ("Required evidence (telemetry, monitoring pipeline) is unavailable or stale right now.", "Restore the source (gNMI collector / topology service); stale evidence is never treated as healthy."),
    "CANDIDATE_STALE": ("The captured baseline is older than the allowed age at observation start.", "Capture the baseline again immediately before starting the observation."),
    "CANDIDATE_INTERFERED": ("A network configuration execution touched an included device after the baseline was captured.", "Capture a new baseline."),
    "CONFIRMATION_MISMATCH": ("The confirmed run / candidate / digest does not match the current record.", "Reload the page and review the exact baseline before approving."),
    "CONFIRMATION_REQUIRED": ("Tick the confirmation to continue.", "The action needs your explicit confirmation."),
    "REASON_SECRET_SHAPED": ("The comment looks like it carries a secret.", "Remove the credential-like text; nothing is stored or silently redacted."),
    "NOT_RUNNING": ("The observation is not running.", "A finished observation is immutable."),
})


def blocker(code: str, **details) -> dict:
    message, remediation = BOOTSTRAP_BLOCKERS[code]
    return {"code": code, "message": message, "remediation": remediation, **({"details": details} if details else {})}
