"""Provisioning vocabularies: the stage order, and the fixed message / remediation of every blocker.

Nothing device- or NetBox-originated is ever put into a code or message: a refusal is a stable code plus bounded details.
"""

from __future__ import annotations

from ... import models

S = models.ProvisioningStatus

# stage name -> (status the run must be in, status it reaches).  One linear path; nothing skips a stage.
STAGES = (
    ("IDENTITY", S.DRAFT, S.IDENTIFIED),
    ("BOOTSTRAP", S.IDENTIFIED, S.BOOTSTRAP_CLASSIFIED),
    ("CAPABILITY", S.BOOTSTRAP_CLASSIFIED, S.CAPABILITY_RESOLVED),
    ("IPAM", S.CAPABILITY_RESOLVED, S.IPAM_PLANNED),
    ("CANDIDATE", S.IPAM_PLANNED, S.CANDIDATE_READY),
    ("VALIDATION", S.CANDIDATE_READY, S.VALIDATED),
    ("PLAN", S.VALIDATED, S.PLANNED),
    ("PRECHECK", S.PLANNED, S.PRECHECKED),
    ("APPROVAL", S.PRECHECKED, S.APPROVED),
    ("PROVISION", S.APPROVED, S.POSTCHECKED),
    ("NSOT_SYNC", S.POSTCHECKED, S.NSOT_SYNCED),
    ("PROBATION", S.NSOT_SYNCED, S.PROBATION),
)
STAGE_BY_NAME = {name: (source, target) for name, source, target in STAGES}
STAGE_OF_STATUS = {source: name for name, source, _target in STAGES}   # the NEXT stage of a run in this status

# After these statuses NetBox objects / a registry entry may exist and must be reconciled on failure or cancellation.
RESERVED_STATUSES = frozenset({S.IPAM_PLANNED, S.CANDIDATE_READY, S.VALIDATED, S.PLANNED, S.PRECHECKED, S.APPROVED, S.PROVISIONING})

BLOCKERS = {
    "WRONG_STAGE": ("The request is not at the stage this action belongs to.", "Follow the stages in order; nothing can be skipped."),
    "RUN_FINISHED": ("The provisioning request is finished and immutable.", "Create a new provisioning request."),
    "NAME_INVALID": ("The device name is not a valid NMAS device name.", "Use letters, digits, '-' and '_' only."),
    "NAME_CONFLICT": ("A device with this name already exists.", "Choose a name no inventory, registry or NetBox device uses."),
    "PLATFORM_UNKNOWN": ("The platform is not in the NMAS platform catalogue.", "Choose a catalogued platform."),
    "ROLE_INVALID": ("The intended role is not recognised.", "Choose router, switch or edge."),
    "SECRET_SHAPED_INPUT": ("The request contains secret-shaped content.", "Provisioning stores references only; never a credential."),
    "BOOTSTRAP_TRANSPORT_UNSUPPORTED": ("NMAS has no proven bootstrap transport for this platform.", "Use a platform whose executor transport is verified, or wait for that transport."),
    "BOOTSTRAP_TARGET_INVALID": ("The bootstrap target reference is incomplete or malformed.", "Give the container (or address) and the lab the device runs in."),
    "BOOTSTRAP_TARGET_IS_PRODUCTION": ("The bootstrap target belongs to the production lab.", "Provision only devices outside the production topology; R5 and the endpoints are out of scope."),
    "BOOTSTRAP_TARGET_IN_USE": ("The bootstrap target already belongs to another provisioned device.", "One container is one device: retire the device that owns it, or name a different target."),
    "DEVICE_UNREACHABLE": ("The device is not reachable yet.", "The request stays staged: planning and reservation are possible, execution is not. Re-run the bootstrap probe once the device answers."),
    "DEVICE_ALREADY_CONFIGURED": ("The device already carries configuration.", "This is onboarding of an existing device, not provisioning: import its running configuration through the existing-device workflow."),
    "CAPABILITY_UNSUPPORTED": ("The request relies on a capability that is not fully supported.", "Only cells that are SUPPORTED in the Phase-4 capability matrix can be provisioned."),
    "CAPABILITY_UNCLASSIFIED": ("A Configlet has no exact capability feature.", "A Configlet without an exact Phase-4 feature cannot be proved supported and is refused."),
    "MANAGEMENT_ADDRESS_INVALID": ("The management addressing is missing or malformed.", "Give interface plus a host address with its prefix length."),
    "MGMT_IP_DUPLICATE": ("A management address is already in use.", "Choose an address no NetBox record or inventory device holds."),
    "PREFIX_NOT_IN_IPAM": ("The management address is not inside a prefix NetBox knows.", "Create the prefix in NetBox first; only a disposable request may plan its own prefix."),
    "PREFIX_LENGTH_MISMATCH": ("The management prefix length differs from the NetBox prefix.", "Use the prefix length NetBox records for that network."),
    "DHCP_POOL_CONFLICT": ("The management address is inside a DHCP range.", "Choose an address outside every DHCP range."),
    "VLAN200_DHCP_FORBIDDEN": ("VLAN 200 is static management only.", "VLAN 200 addresses are static IPv4 and IPv6; DHCP and DHCPv6 are never used there."),
    "VLAN200_DUAL_STACK_REQUIRED": ("A VLAN 200 management interface needs static IPv4 and IPv6.", "Give both a static IPv4 and a static IPv6 address."),
    "DISPOSABLE_IN_PRODUCTION_MANAGEMENT": ("A disposable device cannot take a production management address.", "Disposable devices use their own lab management network, never VLAN 200."),
    "IPAM_UNAVAILABLE": ("NetBox could not be read or written.", "Restore NetBox; nothing is reserved without it."),
    "IPAM_RESERVATION_FAILED": ("The NetBox reservation failed and was rolled back.", "Read the reconciliation evidence, fix the cause and retry."),
    "CHANGE_MISSING": ("The request has no Change yet.", "Generate the candidate first."),
    "INTENT_EMPTY": ("The candidate carries no accepted intent.", "Add the intended configuration in the Device Builder."),
    "VALIDATION_NOT_PASSING": ("Validation has not passed for the current candidate.", "Run Change validation and network-configuration validation until both pass and are current."),
    "PLAN_NOT_CURRENT": ("There is no current plan for the validated candidate.", "Build the plan again."),
    "PRECHECK_NOT_PERMITTING": ("The precheck does not permit execution.", "Resolve the precheck findings and run it again."),
    "APPROVAL_CONFIRMATION_MISMATCH": ("The approval does not match the current candidate.", "Reload the page and approve the candidate hash it shows."),
    "APPROVAL_SELF": ("The requester cannot approve their own request.", "Another authorised operator must approve."),
    "APPROVAL_STALE": ("The approved candidate is no longer the current one.", "The candidate or plan changed after approval; approve the new one."),
    "EXECUTION_BLOCKED": ("The execution gate refused the run.", "Read the execution blockers."),
    "EXECUTION_FAILED": ("Provisioning failed.", "Read the execution result and the rollback evidence."),
    "POSTCHECK_NOT_PASSING": ("The postcheck did not confirm the intended state.", "Read the postcheck findings."),
    "DIGEST_UNAVAILABLE": ("The resulting configuration could not be read back.", "Restore the read-only session; nothing is recorded without a real digest."),
    "NSOT_SYNC_FAILED": ("NetBox could not be synchronized.", "Restore NetBox and retry; the device stays out of the managed scope until it succeeds."),
    "PROBATION_NOT_STARTABLE": ("Golden probation could not start.", "Read the bundle and soak blockers."),
    # V2 Phase 6 -- a provisioning run that carries the production configuration of a natively onboarded device
    "COMMISSIONING_NOT_APPROVED": ("This commissioning run has no current commissioning approval.",
                                   "Approve the commissioning record (it binds identity, attachment, isolation, credentials, dependencies and this candidate)."),
    "COMMISSIONING_STALE": ("The commissioning evidence changed after approval.", "Re-assess readiness and approve the commissioning again."),
    "COMMISSIONING_NOT_ADMITTED": ("The device is not admitted to production yet.",
                                   "NetBox objects become active only after the governed production admission succeeded."),
}


def blocker(code: str, **details) -> dict:
    message, remediation = BLOCKERS[code]
    return {"code": code, "message": message, "remediation": remediation, **({"details": details} if details else {})}
