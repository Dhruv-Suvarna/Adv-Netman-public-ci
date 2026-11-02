"""May this Probation bundle START a soak?  READ-ONLY: it never reruns a UAT, plan, precheck or raw verification, never edits a bundle and never
contacts a device.  Every blocker has a stable code, a fixed message and a remediation (``codes.START_BLOCKERS``).

The server enforces this independently of the page: ``lifecycle.start_soak`` re-evaluates it inside its transaction.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ... import models
from ..bundles import eligibility as bundle_eligibility, integrity as bundle_integrity
from ..bundles.codes import ACCEPTABLE_POSTCHECK, VERIFIED
from ..health import inventory, live, requirements
from . import interference
from .codes import START_BLOCKERS, blocker


@dataclass
class StartEligibility:
    eligible: bool
    blockers: list = field(default_factory=list)
    integrity: object | None = None
    active: object | None = None            # the RUNNING soak of this bundle, if any (start is idempotent: it is returned, not duplicated)
    interference: list = field(default_factory=list)
    devices: list = field(default_factory=list)


def active_run(bundle):
    return models.ProbationSoakRun.objects.filter(bundle=bundle, state=models.SoakState.RUNNING).first()


def _scope_blockers(bundle) -> list[dict]:
    """The candidate's evidence scope must be evaluable by THIS policy: managed devices whose platform supports read-only verification, and
    pinned descriptors that have an evaluator (nothing is invented and nothing unverifiable is silently ignored)."""
    devices = interference.bundle_devices(bundle)
    problems = {}
    for name in devices:
        managed = inventory.get_managed_device(name)
        if managed is None:
            problems[name] = "NOT_MANAGED"
        elif live.get_capability(managed["platform"])["status"] != "SUPPORTED":
            problems[name] = "NO_READ_ONLY_VERIFICATION"
    cfg_ids = {str(i.get("cfg_id")) for i in (bundle.payload.get("items") or [])}
    reqs = [r for r in requirements.normalize_plan(bundle.plan) if r.cfg_id in cfg_ids]
    unverifiable = sorted({f"{r.cfg_id}:{r.kind}" for r in reqs if set(r.check_types) & {requirements.NOT_IMPLEMENTED, requirements.UNKNOWN_TYPE}})
    if not devices or not reqs or problems or unverifiable:
        return [blocker(START_BLOCKERS, "EVIDENCE_SCOPE_UNSUPPORTED", devices=problems, unverifiable=unverifiable[:10], requirements=len(reqs))]
    return []


def check_start(bundle, *, integrity=None) -> StartEligibility:
    active = active_run(bundle)
    if bundle.kind != models.BundleKind.PROBATION:
        return StartEligibility(False, [blocker(START_BLOCKERS, "NOT_PROBATION", kind=bundle.kind)], active=active)
    integrity = integrity if integrity is not None else bundle_integrity.verify_bundle_integrity(bundle)
    blockers = []
    if not integrity.ok:   # nothing manifest-derived below is trustworthy once the digests do not verify
        return StartEligibility(False, [blocker(START_BLOCKERS, "BUNDLE_INTEGRITY_FAILED", findings=integrity.codes)], integrity, active)
    if bundle_eligibility.existing_child(bundle, models.BundleKind.GOLDEN) is not None:
        blockers.append(blocker(START_BLOCKERS, "GOLDEN_EXISTS"))
    if active is not None:
        blockers.append(blocker(START_BLOCKERS, "SOAK_ACTIVE", soak_id=active.soak_id))
    if not (bundle.payload.get("items") or []):
        blockers.append(blocker(START_BLOCKERS, "SOURCE_EMPTY"))
    if bundle.verification_state != VERIFIED:
        blockers.append(blocker(START_BLOCKERS, "SOURCE_UNVERIFIED", state=bundle.verification_state or "UNKNOWN"))
    if (bundle.verification.get("postcheck") or {}).get("result") not in ACCEPTABLE_POSTCHECK:
        blockers.append(blocker(START_BLOCKERS, "POSTCHECK_NOT_ACCEPTABLE"))
    later = interference.find_interference(bundle)
    if later:
        blockers.append(blocker(START_BLOCKERS, "SUPERSEDED", executions=[{k: r[k] for k in ("run_id", "change_id", "outcome", "devices")} for r in later]))
    if not blockers:
        blockers.extend(_scope_blockers(bundle))
    return StartEligibility(not blockers, blockers, integrity, active, later, interference.bundle_devices(bundle))
