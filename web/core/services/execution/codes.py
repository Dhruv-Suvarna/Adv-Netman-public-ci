"""Phase-17 vocabularies: blocker catalogue, sanitized error categories, outcome semantics, tunables.

Everything an operator can be told is a FIXED message looked up by a stable code.  Nothing device-originated (command
output, exception text, hostnames of upstream services) is ever put into a code, a message or a stored result: a
failure is reduced to one of ``ERROR_CATEGORIES`` at the executor boundary and nothing else leaves it.
"""

from __future__ import annotations

from types import MappingProxyType

from django.conf import settings

from ... import models
from ..health.codes import Capability  # SUPPORTED / NOT_IMPLEMENTED / UNSUPPORTED / UNKNOWN -- one vocabulary project-wide

ENGINE_VERSION = "17.0.0"
REPORT_SCHEMA_VERSION = 1

Outcome = models.ExecutionOutcome
Status = models.ExecutionResultStatus
Phase = models.ExecutionResultPhase
Mode = models.ExecutionMode

# Lifecycle states a Change may be executed FROM.  Nothing in Phases 13-15 advances the lifecycle (a validated, planned,
# prechecked Change is still DRAFT), and Phase 17 deliberately does not either, so DRAFT must be executable.  Every other
# state belongs to a later phase (CI / deployed / UAT / probation / golden / rolled back / superseded) and is refused.
EXECUTABLE_LIFECYCLE_STATES = frozenset({"DRAFT", "VALIDATED", "READY_TO_DEPLOY"})

PRECHECK_PERMITS = frozenset({"PASS", "PASS_WITH_WARNINGS"})
POSTCHECK_PERMITS = frozenset({"PASS", "PASS_WITH_WARNINGS"})

UAT_ACK_FIELDS = (
    ("uat_ack_target_is_authorized_nonprod", "The target device(s) are authorized non-production UAT targets."),
    ("uat_ack_partial_success_may_remain_applied", "A partially successful execution may remain applied; it is NOT rolled back automatically."),
    ("uat_ack_dependent_stages_may_stop", "Dependent stages may stop: execution halts at the first failure and later Configlets stay unapplied."),
    ("uat_ack_adjacent_traffic_may_be_affected", "Adjacent traffic may be affected while the change is partially applied."),
    ("uat_ack_operator_accepts_risk", "I accept the risk of this Partial (UAT) execution."),
)

# --- outcome semantics ------------------------------------------------------------------------------------------------
# Outcomes after which NO device configuration from this run remains (or none was ever changed).
CLEAN_OUTCOMES = frozenset({Outcome.BLOCKED, Outcome.FAILED_NO_MUTATION, Outcome.FAILED_ROLLED_BACK, Outcome.POSTCHECK_FAILED_ROLLED_BACK})
# Outcomes after which the device state is not what the operator started with AND not provably restored.
UNRESOLVED_OUTCOMES = frozenset({
    Outcome.FAILED_COMPENSATION_INCOMPLETE, Outcome.POSTCHECK_FAILED_COMPENSATION_INCOMPLETE, Outcome.INTERRUPTED,
})
SUCCESS_OUTCOMES = frozenset({Outcome.SUCCEEDED, Outcome.UAT_SCOPE_APPLIED})

OUTCOME_PRESENTATION = MappingProxyType({
    Outcome.SUCCEEDED: ("success", "Every planned Configlet was applied and the required postcheck confirmed the intended state."),
    Outcome.UAT_SCOPE_APPLIED: ("success", "The requested UAT scope was applied and the postcheck confirmed it. Configlets outside the scope were intentionally not applied."),
    Outcome.UAT_SCOPE_APPLIED_UNVERIFIED: ("warning", "The requested UAT scope was applied but the postcheck could not confirm all of it (missing evidence or no evaluator). Nothing was rolled back."),
    Outcome.UAT_SCOPE_APPLIED_POSTCHECK_FAILED: ("danger", "The requested UAT scope was applied but the postcheck found a deviation. Partial (UAT) never rolls back automatically."),
    Outcome.FAILED_PARTIAL_APPLIED: ("danger", "Execution stopped at the first failure. Earlier successful Configlets were PRESERVED (Partial UAT); later Configlets were not applied. The network is partially changed."),
    Outcome.FAILED_NO_MUTATION: ("danger", "Execution failed before any device configuration was changed."),
    Outcome.FAILED_ROLLED_BACK: ("warning", "Execution failed; the work applied by THIS run was compensated and the prior state was verified restored."),
    Outcome.FAILED_COMPENSATION_INCOMPLETE: ("danger", "Execution failed and compensation is INCOMPLETE or unproven: device state must be verified manually."),
    Outcome.POSTCHECK_FAILED_ROLLED_BACK: ("warning", "All Configlets applied but the required postcheck did not pass; the work was compensated and the prior state verified restored."),
    Outcome.POSTCHECK_FAILED_COMPENSATION_INCOMPLETE: ("danger", "All Configlets applied, the required postcheck did not pass, and compensation is INCOMPLETE or unproven: verify device state manually."),
    Outcome.BLOCKED: ("neutral", "Execution was refused before any device was changed."),
    Outcome.INTERRUPTED: ("danger", "The run was interrupted; the device state is unknown and must be verified manually."),
})

# --- blockers -----------------------------------------------------------------------------------------------------------
BLOCKERS = MappingProxyType({
    "CHANGE_LIFECYCLE_NOT_EXECUTABLE": ("The Change lifecycle state does not permit execution.", "Only Draft / Validated / Ready-to-deploy Changes can be executed."),
    "TRANSITION_CHANGE_NOT_GENERIC": ("This Change is a controlled routing transition and cannot be run by the general execution engine.",
                                      "It is executed only by its own transition workflow, which holds the shields, the core covers and the reverse path."),
    "CONFIGURATION_VALIDATION_NOT_PASSING": (
        "The GitHub Actions Configuration Validation of this exact candidate has not passed.",
        "Validate the Change (Save Draft) and wait for the Configuration Validation run to pass; a result for an earlier candidate does not count."),
    "CHANGE_ARCHIVED": ("This Change has been archived and is read-only.", "Create or revise an active Draft instead of executing archived history."),
    "BLOCKED_PREDATES_RECONCILED_BASELINE": (
        "This Change was created before the accepted baseline of a device it targets and no longer represents current intent.",
        "It stays as history. Create a new Change from the device's current accepted state."),
    "BLOCKED_SUPERSEDED_BY_RECONCILIATION": (
        "This historical Change was superseded by a reconciliation record and no longer represents current accepted intent.",
        "It stays as history and cannot be executed again. Create a new Change for what you want now."),
    "MODE_CONFIRMATION_MISMATCH": ("The confirmed execution mode does not match the Change's execution mode.", "Confirm the mode shown on the page."),
    "VALIDATION_NEVER_RUN": ("The Change has never been validated.", "Run Change Validation."),
    "VALIDATION_STALE": ("Validation is STALE (accepted intent or a consumed source changed).", "Re-run Change Validation, rebuild the plan and re-run the precheck."),
    "VALIDATION_NOT_PASSING": ("The latest validation is not PASS / PASS_WITH_WARNINGS.", "Fix the findings and re-run Change Validation."),
    "NETWORK_CONFIG_VALIDATION_NEVER_RUN": ("Network configuration validation has never run.", "Run Network Config Validation."),
    "NETWORK_CONFIG_VALIDATION_STALE": ("Network configuration validation is STALE.", "Re-run Network Config Validation, then Change Validation, plan and precheck."),
    "NETWORK_CONFIG_VALIDATION_NOT_PASSING": ("Network configuration validation is BLOCKED or failed.", "Resolve its configuration findings and re-run validation."),
    "PLAN_MISSING": ("No plan has been built for this Change.", "Build the Change Plan."),
    "PLAN_STALE": ("The plan is STALE.", "Re-run validation, then rebuild the plan and re-run the precheck."),
    "PLAN_PROVENANCE_INVALID": ("The plan's pinned validation provenance no longer matches its validation run.", "Rebuild the plan from a current validation."),
    "PLAN_EMPTY": ("The plan contains no deployable Configlet.", "Nothing to execute."),
    "PLAN_ORDER_INVALID": ("The plan's dependency order is inconsistent.", "Rebuild the plan."),
    "PRECHECK_MISSING": ("No precheck has been run for this Change.", "Run the Change Precheck."),
    "PRECHECK_WRONG_PLAN": ("The latest precheck belongs to a different plan.", "Run the Change Precheck for the current plan."),
    "PRECHECK_NOT_PERMITTING": ("The latest precheck for this plan does not permit execution (BLOCKED or INCOMPLETE).", "Resolve the precheck findings and re-run the precheck."),
    "PRECHECK_EXPIRED": ("The latest precheck is older than the allowed age.", "Re-run the Change Precheck."),
    "PRECHECK_BEFORE_LAST_EXECUTION": ("An execution attempt happened after the latest precheck.", "Re-run the Change Precheck: device state may have changed."),
    # V2 Phase 5A: a new-device provisioning Change executes through this same engine and this same gate
    "PROVISIONING_NOT_APPROVED": ("This provisioning Change has no current approval.", "Walk the provisioning request to APPROVED; a provisioning Change is never executed before its explicit approval."),
    "PROVISIONING_APPROVAL_STALE": ("The approved provisioning candidate is no longer the current one.", "The candidate or plan changed after approval; the request must be approved again."),
    "COMMISSIONING_NOT_APPROVED": ("This production configuration belongs to a commissioning that is not approved.",
                                   "Approve the commissioning record; its approval binds the evidence this execution relies on."),
    "COMMISSIONING_STALE": ("The commissioning evidence changed since approval (identity, attachment, isolation, credentials, dependencies or candidate).",
                            "Re-assess readiness and approve the commissioning again."),
    "PROVISIONING_DEVICE_UNREACHABLE": ("The device was not classified as a reachable bootstrap device.", "Probe the device from the provisioning request; an unreachable or already-configured device is never executed."),
    "PROVISIONING_BASELINE_UNREADABLE": ("The device's pre-change configuration could not be read.", "Restore the read-only session; nothing is written without a real baseline digest."),
    "PLAN_ALREADY_APPLIED": ("This plan was already executed successfully (Complete).", "Nothing to execute; use a new Change for further work."),
    "PLAN_STATE_UNRESOLVED": ("A previous run of this plan left device state unresolved (interrupted or compensation incomplete).", "Verify the devices manually; a new validation and plan are required."),
    "EXECUTION_IN_PROGRESS": ("Another execution of this Change is already in progress.", "Wait for it to finish."),
    "DEVICE_LOCKED": ("A device in scope is being changed by another execution.", "Wait for that execution to finish."),
    "DEVICE_UNDER_MAINTENANCE": ("A device in scope is in a Maintenance state that makes this Change unsafe.",
                                 "Restore the maintenance (or let its entry or restore finish) before changing that device."),
    "TARGET_DEVICE_UNRESOLVABLE": ("A target device is not a managed inventory device.", "Only inventory-managed devices can be executed against."),
    "TARGET_DEVICE_OUTSIDE_MANAGED_SCOPE": ("A target is outside the NetBox-authoritative managed scope.", "Ordinary infrastructure writes are limited to R1-R4, S1-S4 and mgmt_swt."),
    "PLATFORM_MISMATCH": ("The Configlet platform does not match the managed device's platform.", "Correct the device intent platform and rebuild the plan."),
    "PLATFORM_EXECUTION_UNSUPPORTED": ("No supported execution path exists for a Configlet's platform / object type.", "Execution is refused rather than guessed."),
    "COMPLETE_COMPENSATION_UNAVAILABLE": ("Complete mode cannot prove a compensation strategy for a Configlet.", "Use Partial (UAT), or restrict the plan to additive Configlets."),
    "COMPLETE_POSTCHECK_UNVERIFIABLE": ("Complete mode requires every requirement to be verifiable, and one has no evaluator.", "Use Partial (UAT); an unverifiable requirement can never confirm success."),
    "RAW_COMPLETE_FORBIDDEN": ("A raw Configlet lacks proven transactional compensation, so Complete mode cannot include it.", "Use Partial (UAT), or remove the Raw Configlet from the Change."),
    "RAW_VERIFICATION_NOT_CURRENT": ("A raw Configlet's pinned verification is missing, stale, not acceptable, or does not match its revision.", "Verify the revision again, re-run validation, rebuild the plan and re-run the precheck."),
    "RAW_REVISION_INTEGRITY": ("A raw Configlet's pinned revision is missing or no longer matches its content hash.", "Do not execute; rebuild the plan from a current validation."),
    "COMPENSATION_NOT_PROVABLE": ("The device's current state makes exact compensation unprovable for a Configlet.", "Complete mode is refused before any change; use Partial (UAT)."),
    "MANAGEMENT_SESSION_AT_RISK": ("A Configlet would change the addressing or state of the interface this device is being managed through.",
                                   "Refused before any change: the session that must deliver compensation would be lost. Change the management interface out of band."),
    "ROUTING_DAEMON_UNAVAILABLE": ("A routing daemon the Configlet needs is not running on the device, so the change would be accepted and silently dropped.", "Enable the daemon on the device (NMAS does not manage daemon lifecycle), then precheck again."),
    "BGP_PROCESS_CONFLICT": ("The device already runs BGP under a different autonomous system.", "The platform allows one autonomous system in the default routing instance; correct the intent ASN."),
    "UAT_ACK_MISSING": ("All five Partial (UAT) acknowledgements are required.", "Tick every acknowledgement."),
    "UAT_SCOPE_REQUIRED": ("Partial (UAT) requires an explicit last Configlet ('through').", "Choose the last Configlet to execute."),
    "UAT_SCOPE_INVALID": ("The requested Partial (UAT) scope is not a valid dependency-safe prefix of the plan.", "Choose a Configlet from this plan."),
    "AUTO_ADDRESS_RECHECK_FAILED": ("An AUTO-derived address can no longer be guaranteed.", "Re-run validation and rebuild the plan."),
    "VLAN200_AUTO_FORBIDDEN": ("VLAN 200 management addressing must stay static; AUTO is forbidden.", "Use a static address."),
    "PREPARATION_FAILED": ("Execution could not be prepared (a device could not be reached or read).", "Nothing was changed; check device reachability and retry."),
    "SNAPSHOT_STALE": ("The device's running configuration changed since the snapshot this Change was built from.",
                       "Nothing was changed. Refresh the running configuration, re-plan the change / removal and validate again."),
    "SNAPSHOT_UNVERIFIABLE": ("The running configuration could not be re-read to confirm the snapshot this Change was built from.",
                              "Nothing was changed; check device reachability and retry."),
    "REMOVAL_TARGET_DRIFTED": ("An object selected for removal is only partly present on the device now.",
                               "Nothing was changed. Refresh the running configuration and rebuild the removal."),
})

ERROR_CATEGORIES = MappingProxyType({
    "COMMAND_REJECTED": "The device rejected a configuration command.",
    "TIMEOUT": "The device did not respond within the timeout.",
    "AUTH_FAILED": "The device rejected the configured credentials.",
    "CONNECTION_FAILED": "The device could not be reached.",
    "TRANSPORT_ERROR": "The device session failed unexpectedly.",
    "NOT_CONFIGURED": "No access target is configured for this device.",
    "DOCKER_UNAVAILABLE": "The container runtime is not available to the server.",
    "PREVIOUS_STATE_UNAVAILABLE": "The device's current state could not be read.",
    "VERIFICATION_UNAVAILABLE": "The restored state could not be read back to verify it.",
    "STATE_NOT_RESTORED": "The device state after compensation still differs from the captured state.",
    "UNSUPPORTED": "No supported execution path exists for this Configlet.",
    "INTERNAL_ERROR": "The execution engine failed unexpectedly.",
    "POSTCHECK_ERROR": "The postcheck could not be evaluated.",
    "LEASE_EXPIRED": "The execution lease expired before the run finished.",
})

# Check types whose post-change value legitimately takes time to converge (adjacency / route install / link state).
SETTLING_CHECKS = frozenset({"OSPF_NEIGHBOR_EXPECTED", "ISIS_NEIGHBOR_EXPECTED", "BGP_NEIGHBOR_EXPECTED", "INTERFACE_OPER_STATE", "STATIC_ROUTE_PRESENT"})


def blocker(code: str, **details) -> dict:
    message, remediation = BLOCKERS[code]
    return {"code": code, "message": message, "remediation": remediation, **({"details": details} if details else {})}


def error_message(code: str) -> str:
    return ERROR_CATEGORIES.get(code, ERROR_CATEGORIES["INTERNAL_ERROR"])


# --- tunables (bounded; see settings.py) --------------------------------------------------------------------------------
def precheck_max_age_seconds() -> float:
    return float(getattr(settings, "EXECUTION_PRECHECK_MAX_AGE_SECONDS", 900))


def lease_seconds() -> float:
    return float(getattr(settings, "EXECUTION_LEASE_SECONDS", 1800))


def settle_timeout_seconds() -> float:
    return float(getattr(settings, "EXECUTION_SETTLE_TIMEOUT_SECONDS", 30))


def settle_interval_seconds() -> float:
    return float(getattr(settings, "EXECUTION_SETTLE_INTERVAL_SECONDS", 3))


def device_timeout_seconds() -> float:
    return float(getattr(settings, "EXECUTION_DEVICE_TIMEOUT_SECONDS", 20))
