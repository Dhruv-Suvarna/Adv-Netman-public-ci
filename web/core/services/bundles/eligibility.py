"""Explicit, read-only eligibility for bundle creation and derivation.  Every blocker has a stable code, a fixed message and a remediation.

The SERVER enforces these rules independently of any button: the views call the same functions, and the persistence layer re-evaluates
them inside its transaction.  Nothing here writes, re-runs a precheck / postcheck / verification, or contacts anything.

Which warnings are compatible with what (documented in docs/IMMUTABLE_CONFIGURATION_BUNDLES.md):

    UAT bundle creation   accepts a run that ended UAT_SCOPE_APPLIED or (explicitly) UAT_SCOPE_APPLIED_UNVERIFIED, whatever engine-gate
                          warnings it carried (they are recorded as codes, never hidden).
    Probation derivation  requires a VERIFIED scope: an UNVERIFIED bundle is blocked.  A PASS_WITH_WARNINGS postcheck and recorded
                          engine-gate warnings do NOT block; they stay visible on the bundle.  No score, no silent exception.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ... import models
from . import snapshot
from .codes import (
    ACCEPTABLE_POSTCHECK, APPLIED_RESULT_STATUSES, PROBATION_BLOCKERS, VERIFIED, blocker,
)
from .integrity import IntegrityReport, verify_bundle_integrity


@dataclass
class UatEligibility:
    eligible: bool
    blockers: list = field(default_factory=list)
    existing: object | None = None       # the UAT bundle already made from this run (creation is idempotent)
    verification_state: str = ""


@dataclass
class DerivationEligibility:
    eligible: bool
    blockers: list = field(default_factory=list)
    existing: object | None = None       # the child bundle already derived from this source (derivation is idempotent)
    integrity: IntegrityReport | None = None


def existing_uat(run):
    return models.ConfigurationBundle.objects.filter(kind=models.BundleKind.UAT, execution_run_id=run.pk).first()


def existing_deployed(run):
    return models.ConfigurationBundle.objects.filter(kind=models.BundleKind.DEPLOYED, execution_run_id=run.pk).first()


def check_deployed_eligibility(run) -> UatEligibility:
    """May this finished COMPLETE run (ordinary or provisioning Change) become a Deployed bundle?  Uses only the run's pinned historical records."""
    existing = existing_deployed(run)
    snap = snapshot.collect(run, kind=models.BundleKind.DEPLOYED)
    return UatEligibility(eligible=snap.ok and existing is None, blockers=snap.blockers, existing=existing, verification_state=snap.verification_state)


def existing_child(parent, kind: str):
    return models.ConfigurationBundle.objects.filter(kind=kind, parent_id=parent.pk).first()


def check_uat_eligibility(run) -> UatEligibility:
    """May this finished execution run become a UAT bundle?  Uses only the run's pinned historical records."""
    existing = existing_uat(run)
    snap = snapshot.collect(run)
    return UatEligibility(eligible=snap.ok and existing is None, blockers=snap.blockers, existing=existing, verification_state=snap.verification_state)


def check_probation_eligibility(uat, *, integrity: IntegrityReport | None = None) -> DerivationEligibility:
    """May this UAT bundle be sealed into a Probation bundle?  A derivation is artifact creation, never a network action."""
    existing = existing_child(uat, models.BundleKind.PROBATION)
    if uat.kind not in models.BUNDLE_ROOT_KINDS:
        return DerivationEligibility(False, [blocker(PROBATION_BLOCKERS, "SOURCE_NOT_UAT", kind=uat.kind)], existing)
    integrity = integrity if integrity is not None else verify_bundle_integrity(uat)
    if not integrity.ok:   # nothing manifest-derived below is trustworthy once the digests do not verify
        return DerivationEligibility(False, [blocker(PROBATION_BLOCKERS, "SOURCE_INTEGRITY_FAILED", findings=integrity.codes)], existing, integrity)
    blockers = []
    items = uat.payload.get("items") or []
    if not items:
        blockers.append(blocker(PROBATION_BLOCKERS, "SOURCE_EMPTY"))
    if uat.verification_state != VERIFIED:
        blockers.append(blocker(PROBATION_BLOCKERS, "SOURCE_UNVERIFIED", state=uat.verification_state or "UNKNOWN"))
    if (uat.verification.get("postcheck") or {}).get("result") not in ACCEPTABLE_POSTCHECK:
        blockers.append(blocker(PROBATION_BLOCKERS, "POSTCHECK_NOT_ACCEPTABLE"))
    bad = [i.get("cfg_id", "") for i in items if ((i.get("execution") or {}).get("status")) not in APPLIED_RESULT_STATUSES]
    if bad:
        blockers.append(blocker(PROBATION_BLOCKERS, "RESULT_NOT_APPLIED", configlets=bad))
    return DerivationEligibility(not blockers and existing is None, blockers, existing, integrity)
