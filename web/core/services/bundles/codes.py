"""Phase-19 vocabularies: versions, bounds, blocker / finding catalogues.

Everything an operator can be told is a FIXED message looked up by a stable code (the same idiom as the Phase-17 execution blockers).
Nothing device-originated, no secret and no matched text is ever put into a code, a message or a detail.
"""

from __future__ import annotations

from types import MappingProxyType

from ... import models

# The manifest schema.  Bump it ONLY with a deliberate migration story: a stored bundle is verified against the schema it was written with.
BUNDLE_SCHEMA_VERSION = 1
EXPORT_SCHEMA_VERSION = 1
BUILDER_VERSION = "19.0.0"       # the code that built a UAT / Probation bundle: creation metadata, outside every digest
GOLDEN_BUILDER_VERSION = "20.0.0"   # the code that derives a Golden bundle (Phase 20)
PROMOTION_KEYS = (
    "soak_id", "soak_policy_version", "soak_duration_seconds", "observation_started_at", "observation_required_end_at", "observation_completed_at",
    "evidence_digest", "probation_bundle_digest", "decision", "decided_by", "decided_at",
)
LEGACY_BUILDER_VERSION = "20.1.0"   # the code that captures a legacy baseline candidate / seals the initial Golden (one-time bootstrap)
LEGACY_PROVENANCE_TYPE = "LEGACY_BOOTSTRAP"
LEGACY_ROLE_CANDIDATE, LEGACY_ROLE_GOLDEN = "CANDIDATE", "INITIAL_GOLDEN"
# what the initial Golden's ``lineage.legacy_bootstrap`` block MUST pin (the candidate's block carries only the first three keys)
LEGACY_CANDIDATE_KEYS = ("provenance_type", "role", "policy_version")
LEGACY_GOLDEN_KEYS = (
    "provenance_type", "role", "policy_version", "candidate_bundle_id", "candidate_bundle_digest", "baseline_digest", "observation_run_id",
    "observation_duration_seconds", "observation_started_at", "observation_required_end_at", "observation_completed_at", "evidence_digest",
    "decision", "decided_by", "decided_at", "predates_automation_framework", "config_recheck_at", "config_recheck_result",
)
MAX_LEGACY_MANIFEST_BYTES = 6 * 1024 * 1024   # a legacy baseline holds every device's sanitized running configuration
DIGEST_ALGORITHM = "sha256"
UNKNOWN = "UNKNOWN"              # provenance that was never persisted is recorded as UNKNOWN, never fabricated

MAX_ITEMS = 500                  # bounds one bundle (a plan this large is far beyond anything the planner produces)
MAX_MANIFEST_BYTES = 2 * 1024 * 1024
MAX_LIST = 200                   # bundle list page size

Kind = models.BundleKind
Outcome = models.ExecutionOutcome
ResultStatus = models.ExecutionResultStatus

VERIFIED, UNVERIFIED = "VERIFIED", "UNVERIFIED"

# --- what a UAT bundle may be built from --------------------------------------------------------------------------------------
# ONLY a finished Partial (UAT) run that applied its whole requested scope.  A failed / interrupted / blocked run is never a UAT
# candidate; Complete is a deployment mode and is never reinterpreted as UAT.  ``UAT_SCOPE_APPLIED_UNVERIFIED`` is a legitimate terminal
# outcome (for example a Raw Configlet with no structured assertion): the bundle records it honestly as UNVERIFIED and can never enter Probation.
BUNDLEABLE_OUTCOMES = frozenset({Outcome.UAT_SCOPE_APPLIED, Outcome.UAT_SCOPE_APPLIED_UNVERIFIED})
# --- what a DEPLOYED bundle may be built from (V2 Phase 5) --------------------------------------------------------------------
# ONLY a finished COMPLETE run of a new-device provisioning Change that SUCCEEDED: the whole plan applied and the postcheck confirmed it.
# A failed, blocked, rolled-back or postcheck-failed Complete run is never a candidate, and an ordinary configuration Change keeps the
# Partial (UAT) lineage -- Complete stays a deployment mode there.
DEPLOYED_OUTCOMES = frozenset({Outcome.SUCCEEDED})
ACCEPTABLE_VALIDATION = frozenset({"PASS", "PASS_WITH_WARNINGS"})
ACCEPTABLE_POSTCHECK = frozenset({"PASS", "PASS_WITH_WARNINGS"})
APPLIED_RESULT_STATUSES = frozenset({ResultStatus.APPLIED, ResultStatus.ALREADY_SATISFIED})

# --- blockers (code -> (message, remediation)) -------------------------------------------------------------------------------
UAT_BLOCKERS = MappingProxyType({
    "RUN_NOT_FINISHED": ("The execution run has not finished.", "Wait for the run to finish; an active run is never bundled."),
    "ACTIVE_EXECUTION": ("Another execution of this Change (or of one of its devices) is still active.", "Wait until no execution is active, then try again."),
    "MODE_NOT_PARTIAL_UAT": ("Only a Partial (UAT) execution can produce a UAT bundle.", "Complete is a deployment mode; it is never reinterpreted as a UAT, Probation or Golden bundle."),
    "MODE_NOT_COMPLETE": ("Only a Complete execution can produce a Deployed bundle.", "A Partial (UAT) run produces a UAT bundle instead."),
    "OUTCOME_NOT_DEPLOYED": ("The Complete execution did not succeed.", "Only a SUCCEEDED Complete run (whole plan applied, postcheck confirmed) is a candidate; a failed, blocked or rolled-back run never is."),
    "OUTCOME_NOT_BUNDLEABLE": ("The execution did not end in an applied UAT scope.", "Only a run that applied its whole requested scope (UAT_SCOPE_APPLIED, or explicitly UNVERIFIED) can be bundled; a failed, interrupted, blocked or postcheck-failed run is never a UAT candidate."),
    "SCOPE_UNKNOWN": ("The executed scope cannot be reconstructed exactly from the run's historical record.", "The run's recorded scope is missing or inconsistent; nothing is guessed."),
    "PLAN_PROVENANCE_INVALID": ("The run, its plan and its validation no longer agree on the pinned provenance.", "Historical provenance is inconsistent; the run cannot be bundled."),
    "PLAN_HASH_MISSING": ("The plan has no valid pinned plan hash.", "Historical provenance is incomplete; the run cannot be bundled."),
    "VALIDATION_NOT_PASSING": ("The validation run pinned by the execution did not pass.", "Only a run built from a passing validation can be bundled."),
    "PLAN_CONFIGLETS_MISSING": ("A Configlet of the executed scope no longer resolves in its historical plan, or the plan order disagrees with the run.", "The historical plan is inconsistent with the run; the run cannot be bundled."),
    "DEPENDENCY_SCOPE_INCONSISTENT": ("The dependency graph of the executed scope is inconsistent (a prerequisite is outside the scope or out of order).", "A dependency-safe prefix is required; the run cannot be bundled."),
    "RESULT_MISSING": ("An executed Configlet has no final APPLY result.", "The execution history is incomplete; the run cannot be bundled."),
    "RESULT_NOT_APPLIED": ("A Configlet of the requested scope did not finish as applied.", "Only a scope where every Configlet was applied (or already satisfied) can be bundled."),
    "RESULT_OUT_OF_SCOPE": ("The run recorded an applied result for a Configlet outside its requested scope.", "The execution history is inconsistent; the run cannot be bundled."),
    "POSTCHECK_EVIDENCE_INVALID": ("The postcheck evidence pinned by the run is missing or contradicts the run's outcome.", "A verified UAT scope requires its persisted, acceptable postcheck run."),
    "RAW_PROVENANCE_MISSING": ("A Raw Configlet does not pin its exact immutable revision and verification run consistently with the execution record.", "Raw Configlets are bundled only through their exact Phase-18 revision and verification; nothing is looked up 'latest'."),
    "RAW_REVISION_INTEGRITY": ("A pinned Raw Configlet revision no longer hashes to its recorded content hash.", "The immutable revision was altered; the run cannot be bundled."),
    "RAW_VERIFICATION_INVALID": ("A pinned Raw Configlet verification run is not a finished, acceptable verification of that exact revision.", "The run cannot be bundled."),
    "SECRET_SHAPED_PAYLOAD": ("An included payload or descriptor looks like it carries a secret.", "Nothing is redacted and re-labelled as the executed configuration: bundle creation is blocked."),
    "BUNDLE_TOO_LARGE": ("The bundle would exceed the maximum size.", "The scope is beyond the supported bundle bound."),
})

PROBATION_BLOCKERS = MappingProxyType({
    "SOURCE_NOT_UAT": ("Only a UAT or Deployed bundle can be derived into a Probation bundle.", "Probation derives from an immutable root bundle (UAT, or Deployed for a provisioned device), never from another kind."),
    "SOURCE_INTEGRITY_FAILED": ("The source UAT bundle failed its integrity verification.", "A bundle whose manifest no longer verifies can never be derived from."),
    "SOURCE_UNVERIFIED": ("The source UAT scope was applied but not verified.", "An UNVERIFIED UAT scope cannot enter Probation; re-run a UAT whose scope the postcheck can confirm."),
    "POSTCHECK_NOT_ACCEPTABLE": ("The source UAT postcheck result is not PASS / PASS_WITH_WARNINGS.", "Probation requires acceptable, persisted postcheck evidence."),
    "RESULT_NOT_APPLIED": ("An included Configlet result is not an applied result.", "Every included Configlet must have been applied (or already satisfied)."),
    "SOURCE_EMPTY": ("The source UAT bundle contains no Configlet.", "Nothing to derive."),
})

GOLDEN_BLOCKERS = MappingProxyType({
    "SOURCE_NOT_PROBATION": ("Only a Probation bundle can be the source of a Golden bundle.", "Golden derives from a Probation bundle: no UAT -> Golden, no Golden -> Probation."),
    "SOURCE_INTEGRITY_FAILED": ("The source Probation bundle failed its integrity verification.", "A bundle whose manifest no longer verifies can never be derived from."),
    "PHASE20_EVIDENCE_REQUIRED": ("Golden promotion requires a technically passed probation soak and the operator's explicit decision.", "Start a soak from the Probation bundle page; no other evidence is accepted."),
    "EVIDENCE_TYPE_UNSUPPORTED": ("Only a probation soak run is accepted as Golden evidence.", "Nothing else (a flag, a dictionary, a string, a test result) can stand in for the soak."),
    "SOAK_BUNDLE_MISMATCH": ("The soak run observed a different Probation bundle.", "Evidence for another artifact is never transferred."),
    "PROBATION_DIGEST_CHANGED": ("The Probation bundle digest no longer equals the digest the soak observed.", "The soak evidence belongs to a different artifact; a new soak is required."),
    "SOAK_NOT_PASSED": ("The soak did not technically pass (it is running, failed, incomplete, invalidated or cancelled).", "Only a COMPLETED soak with result PASS is eligible for the operator's decision."),
    "SOAK_DURATION_NOT_MET": ("The soak did not run for its full pinned duration.", "The observation window must have elapsed in real time."),
    "SOAK_EVIDENCE_INVALID": ("The stored soak evidence does not reproduce its recorded verdict, summary or digest.", "The soak record is inconsistent and is never repaired; a new soak is required."),
    "SOAK_EVIDENCE_EXPIRED": ("The technical pass is older than the decision window.", "Start a new soak; the pass is no longer recent enough to justify Golden."),
    "DECISION_ALREADY_RECORDED": ("An operator decision is already recorded for this soak.", "A decision is immutable; reconsidering requires a NEW soak."),
    "INTERFERENCE_DETECTED": ("A later configuration execution touched the candidate's devices.", "The candidate is superseded; start a new UAT / Probation lifecycle."),
})

# --- integrity findings (code -> message) -----------------------------------------------------------------------------------
INTEGRITY_FINDINGS = MappingProxyType({
    "SCHEMA_UNSUPPORTED": "The manifest schema version is not supported by this verifier.",
    "MANIFEST_MALFORMED": "The stored manifest is not a well-formed bundle manifest.",
    "PAYLOAD_DIGEST_MISMATCH": "The payload digest does not match the recomputed canonical digest of the stored payload.",
    "BUNDLE_DIGEST_MISMATCH": "The bundle digest does not match the recomputed digest of kind, schema version, payload digest and lineage.",
    "KIND_MISMATCH": "The manifest kind differs from the bundle kind.",
    "LINEAGE_INVALID": "The parent / kind relationship violates the UAT -> Probation -> Golden lineage rules.",
    "PARENT_DIGEST_MISMATCH": "The lineage digest recorded in the manifest differs from the parent's own digest.",
    "ANCESTOR_INTEGRITY_FAILED": "An ancestor bundle failed its integrity verification.",
    "PAYLOAD_NOT_EQUIVALENT": "A derived bundle's payload differs from its parent's payload.",
    "ITEMS_MISMATCH": "The item rows do not match the manifest's ordered item list (count, order or sequence).",
    "ITEM_RECORD_MISMATCH": "An item row differs from its manifest entry.",
    "ITEM_DIGEST_MISMATCH": "An item digest does not match its canonical record.",
    "ITEM_PAYLOAD_HASH_MISMATCH": "An item payload no longer hashes to its recorded payload hash.",
    "SOURCE_PIN_MISMATCH": "A pinned source reference (change, plan, validation, execution, postcheck) disagrees with the manifest.",
    "SOURCE_REFERENCE_INVALID": "A pinned source record no longer agrees with the historical facts the manifest recorded.",
    "RAW_PIN_MISMATCH": "A Raw Configlet pin (revision, content hash or verification run) disagrees with the manifest or the immutable revision.",
    "SECRET_SHAPED_CONTENT": "The stored manifest contains secret-shaped content.",
    "EXPORT_DIGEST_MISMATCH": "The export digest does not match the recomputed digest of the exported document.",
    "PROMOTION_MISSING": "A Golden bundle carries no well-formed soak / decision provenance.",
    "PROMOTION_MISMATCH": "The Golden bundle's recorded soak / decision provenance disagrees with the stored soak run, evidence or decision.",
    "LEGACY_PROVENANCE_MISSING": "A legacy-bootstrap bundle carries no well-formed LEGACY_BOOTSTRAP provenance block.",
    "LEGACY_PROVENANCE_MISMATCH": "The legacy-bootstrap provenance disagrees with the stored provenance column, the observation run, the decision or the candidate.",
    "LEGACY_BASELINE_MALFORMED": "The legacy baseline payload is not a well-formed, deterministic device baseline.",
})

# --- the one-time legacy bootstrap gate (code -> (message, remediation)) -----------------------------------------------------------
LEGACY_BLOCKERS = MappingProxyType({
    "LEGACY_BOOTSTRAP_ALREADY_COMPLETED": ("The one-time legacy bootstrap has already produced the initial Golden bundle.",
                                            "This shortcut is permanently unavailable; every future Golden bundle follows the normal UAT -> Probation -> 7-day soak -> operator decision lifecycle."),
    "GOLDEN_EXISTS": ("A Golden bundle already exists.", "The legacy bootstrap can only create the FIRST Golden bundle of this deployment."),
    "BOOTSTRAP_ACTIVE": ("A legacy bootstrap observation is already running.", "Wait for it to finish; only one may run at a time."),
    "CANDIDATE_NOT_LEGACY": ("Only a legacy baseline candidate can be observed and promoted through the bootstrap.", "Capture the current baseline first."),
    "CANDIDATE_INTEGRITY_FAILED": ("The legacy baseline candidate failed its integrity verification.", "A candidate that no longer verifies can never be observed or promoted; capture a new baseline."),
    "OBSERVATION_NOT_PASSED": ("The bootstrap observation did not technically pass.", "Only a COMPLETED observation with result PASS can be approved."),
    "OBSERVATION_CANDIDATE_MISMATCH": ("The observation belongs to a different candidate or digest.", "Evidence for another baseline is never transferred."),
    "OBSERVATION_DURATION_NOT_MET": ("The observation did not run for its full pinned duration.", "The observation window must have elapsed in real time."),
    "OBSERVATION_EVIDENCE_INVALID": ("The stored observation evidence does not reproduce its recorded verdict, summary or digest.", "The record is inconsistent and never repaired; capture a new baseline."),
    "OBSERVATION_EXPIRED": ("The technical pass is older than the decision window.", "Capture a new baseline and observe again."),
    "DECISION_ALREADY_RECORDED": ("An operator decision is already recorded for this observation.", "A decision is immutable."),
    "INTERFERENCE_DETECTED": ("A configuration execution touched an included device after the baseline was captured.", "The observed baseline is no longer what is running; capture a new baseline."),
    "CONFIG_DRIFT_DETECTED": ("The running configuration of an included device no longer matches the observed baseline.", "Approval is blocked; a changed configuration is never adopted automatically. Capture a new baseline and observe it again."),
    "DRIFT_CHECK_INCOMPLETE": ("The decision-time configuration re-check could not read every included device.", "Approval needs a successful, current re-read of every device's configuration."),
})


def blocker(catalogue, code: str, **details) -> dict:
    message, remediation = catalogue[code]
    return {"code": code, "message": message, "remediation": remediation, **({"details": details} if details else {})}


def finding(code: str, **details) -> dict:
    return {"code": code, "message": INTEGRITY_FINDINGS[code], **({"details": details} if details else {})}
