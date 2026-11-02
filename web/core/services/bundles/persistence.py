"""Atomic, idempotent bundle persistence.  This is the ONLY code that writes a bundle.

Creating a bundle is ARTIFACT creation: database rows and one audit event.  It never contacts a device, NetBox, Git or GitHub, never
re-runs a validation / plan / precheck / postcheck / raw verification, and never touches the Change lifecycle.

* Atomic: the bundle, all its items and the audit event are written in one transaction; a failure leaves nothing that looks valid.
* Idempotent: one UAT bundle per execution run, one Probation bundle per UAT bundle, one Golden bundle per Probation bundle -- enforced
  by DATABASE unique constraints, so two racing requests can never create two artifacts (the loser re-reads and returns the winner).
* Sealing, not editing: a derived bundle is created from a deep copy of its parent's payload; its ``payload_digest`` equals the parent's
  (the model refuses anything else) and only kind / lineage differ, so its ``bundle_digest`` does.
"""

from __future__ import annotations

import copy
from dataclasses import dataclass, field

from django.db import IntegrityError, transaction
from django.db.models import Max

from ... import models
from .. import secret_policy
from . import canonical, eligibility, snapshot
from .codes import BUILDER_VERSION, BUNDLE_SCHEMA_VERSION

MAX_SEQUENCE_RETRIES = 5
_AUDIT = {
    models.BundleKind.UAT: models.AuditEventType.UAT_BUNDLE_CREATED,
    models.BundleKind.DEPLOYED: models.AuditEventType.DEPLOYED_BUNDLE_CREATED,
    models.BundleKind.PROBATION: models.AuditEventType.PROBATION_BUNDLE_CREATED,
    models.BundleKind.GOLDEN: models.AuditEventType.GOLDEN_APPROVED,   # Phase 20: written by ``golden.create_golden_bundle`` only
    models.BundleKind.LEGACY_BASELINE: models.AuditEventType.LEGACY_BASELINE_CAPTURED,   # one-time bootstrap: written by ``legacy.seal_candidate`` only
}


@dataclass
class BundleResult:
    bundle: object | None
    created: bool = False
    blockers: list = field(default_factory=list)
    refused: bool = False

    @property
    def existing(self) -> bool:
        return self.bundle is not None and not self.created


class _AlreadyExists(Exception):
    def __init__(self, bundle):
        self.bundle = bundle


def _next_sequence(kind: str) -> int:
    return (models.ConfigurationBundle.objects.filter(kind=kind).aggregate(top=Max("sequence"))["top"] or 0) + 1


def _audit_metadata(bundle, *, extra: dict | None = None) -> dict:
    return secret_policy.assert_no_secret_shaped_keys({
        "bundle_id": bundle.bundle_id, "kind": bundle.kind, "bundle_digest": bundle.bundle_digest, "payload_digest": bundle.payload_digest,
        "parent_bundle_id": bundle.parent.bundle_id if bundle.parent_id else "",
        "source_uat_bundle_id": bundle.source_uat.bundle_id if bundle.source_uat_id else "",
        "source_execution_run_id": str(bundle.execution_run.run_id) if bundle.execution_run_id else "",
        "verification_state": bundle.verification_state,
        "items": bundle.item_count, "result": "CREATED",
        **({"provenance": bundle.provenance} if bundle.provenance != models.BundleProvenance.EXECUTION_LINEAGE else {}),   # normal audit metadata stays byte-identical
        **(extra or {}),
    }, context="Bundle audit")


def seal_bundle(*, kind: str, payload: dict, lineage: dict, refs: dict, item_specs: list, actor: str, parent=None, source_uat=None,
                audit: bool = True, find_existing=None, audit_extra: dict | None = None, builder_version: str = BUILDER_VERSION,
                provenance: str = models.BundleProvenance.EXECUTION_LINEAGE, audit_event_type: str | None = None):
    """Write ONE bundle (+ items + audit) atomically.  ``refs``: change / plan / validation_run / execution_run / postcheck_run.

    Callers own eligibility.  A GOLDEN bundle's ``lineage`` carries its ``promotion`` provenance (soak run, evidence digest, operator decision),
    which the bundle digest covers; only ``golden.create_golden_bundle`` passes one, behind the soak evidence checks.

    The one-time legacy bootstrap (``legacy.py`` only) passes ``provenance=LEGACY_BOOTSTRAP`` with EMPTY ``refs`` and a ``legacy_bootstrap``
    block in ``lineage``: no Change, plan, validation or execution exists for a network configured before the framework, and none is
    fabricated.  The model and database constraints allow that ONLY for that provenance."""
    manifest = {"manifest_schema_version": BUNDLE_SCHEMA_VERSION, "kind": kind, "lineage": dict(lineage), "payload": payload}
    payload_digest = canonical.payload_digest(payload)
    bundle_digest = canonical.bundle_digest(
        kind=kind, payload_digest=payload_digest, parent_bundle_digest=lineage["parent_bundle_digest"],
        source_uat_bundle_digest=lineage["source_uat_bundle_digest"], promotion=lineage.get("promotion"), legacy_bootstrap=lineage.get("legacy_bootstrap"),
    )
    last_error = None
    for _ in range(MAX_SEQUENCE_RETRIES):
        sequence = _next_sequence(kind)
        try:
            with transaction.atomic():
                bundle = models.ConfigurationBundle(
                    bundle_id=f"{models.BUNDLE_ID_PREFIX[kind]}{sequence:06d}", kind=kind, sequence=sequence, schema_version=BUNDLE_SCHEMA_VERSION,
                    builder_version=builder_version, payload_digest=payload_digest, bundle_digest=bundle_digest, manifest=manifest,
                    parent=parent, source_uat=source_uat, created_by=actor, provenance=provenance, **refs,
                )
                bundle.save()
                models.ConfigurationBundleItem.objects.bulk_create([
                    models.ConfigurationBundleItem(
                        bundle=bundle, sequence=spec["record"]["order"], cfg_id=spec["record"]["cfg_id"], device=spec["record"]["device"],
                        platform=spec["record"]["platform"], origin=spec["record"]["origin"], operation=spec["record"]["operation"],
                        priority=spec["record"]["priority"], payload=spec["record"]["payload"], payload_hash=spec["record"]["payload_hash"],
                        item_digest=canonical.item_digest(spec["record"]), record=spec["record"], configlet=spec["configlet"],
                        raw_revision=spec["raw_revision"], raw_verification=spec["raw_verification"], execution_result=spec["execution_result"],
                    )
                    for spec in item_specs
                ])
                if audit:
                    change = refs.get("change")
                    models.AuditEvent.objects.create(
                        event_type=audit_event_type or _AUDIT[kind], change=change, object_type="ConfigurationBundle", object_id=bundle.bundle_id, actor=actor,
                        summary=f"{change.change_id + ': ' if change is not None else 'legacy bootstrap: '}{bundle.get_kind_display()} bundle {bundle.bundle_id} created"[:255],
                        metadata=_audit_metadata(bundle, extra=audit_extra),
                    )
            return bundle
        except IntegrityError as exc:
            last_error = exc
            existing = find_existing() if find_existing is not None else None
            if existing is not None:   # a concurrent request created the SAME artifact first: that one wins, nothing is duplicated
                raise _AlreadyExists(existing) from exc
            # otherwise a lost race on the per-kind sequence: take the next number
    raise last_error


def create_uat_bundle(run, *, actor: str) -> BundleResult:
    """Explicitly seal a finished Partial (UAT) execution run into an immutable UAT bundle.  Idempotent per run."""
    def find():
        return eligibility.existing_uat(run)

    existing = find()
    if existing is not None:
        return BundleResult(existing)
    try:
        with transaction.atomic():
            # serialise creators on the run row where the database supports it (a no-op on SQLite; uniqueness still holds)
            locked = models.ChangeExecutionRun.objects.select_for_update().get(pk=run.pk)
            snap = snapshot.collect(locked)
            if not snap.ok:
                return BundleResult(None, blockers=snap.blockers, refused=True)
            refs = dict(change=locked.change, plan=locked.plan, validation_run=locked.validation_run, execution_run=locked, postcheck_run=locked.postcheck_run)
            bundle = seal_bundle(
                kind=models.BundleKind.UAT, payload=snap.payload, lineage={"parent_bundle_digest": "", "source_uat_bundle_digest": ""}, refs=refs,
                item_specs=snap.item_specs, actor=actor, find_existing=find,
            )
    except _AlreadyExists as duplicate:
        return BundleResult(duplicate.bundle)
    return BundleResult(bundle, created=True)


def create_deployed_bundle(run, *, actor: str) -> BundleResult:
    """Explicitly seal a SUCCEEDED Complete run into an immutable Deployed bundle.  Idempotent per run.

    The ONE sealing path for every Complete execution: an ordinary configuration Change reaches it from its execution page, a provisioning
    Change from ``provisioning.lifecycle`` (which keeps its own reference to the Change on the ProvisioningRun).

    The same frozen-payload builder as a UAT bundle, over the run's own pinned records: nothing is copied from the current Change state and
    nothing is relabelled.  The bundle's root kind and the pinned execution mode are cross-checked by the integrity verifier.
    """
    def find():
        return eligibility.existing_deployed(run)

    existing = find()
    if existing is not None:
        return BundleResult(existing)
    try:
        with transaction.atomic():
            locked = models.ChangeExecutionRun.objects.select_for_update().get(pk=run.pk)
            snap = snapshot.collect(locked, kind=models.BundleKind.DEPLOYED)
            if not snap.ok:
                return BundleResult(None, blockers=snap.blockers, refused=True)
            refs = dict(change=locked.change, plan=locked.plan, validation_run=locked.validation_run, execution_run=locked, postcheck_run=locked.postcheck_run)
            bundle = seal_bundle(
                kind=models.BundleKind.DEPLOYED, payload=snap.payload, lineage={"parent_bundle_digest": "", "source_uat_bundle_digest": ""}, refs=refs,
                item_specs=snap.item_specs, actor=actor, find_existing=find,
            )
    except _AlreadyExists as duplicate:
        return BundleResult(duplicate.bundle)
    return BundleResult(bundle, created=True)


def record_integrity_failure(bundle, report, *, actor: str, context: str) -> None:
    """One bounded audit event when an explicit operator action was refused because a bundle failed its integrity verification."""
    models.AuditEvent.objects.create(
        event_type=models.AuditEventType.BUNDLE_INTEGRITY_FAILED, change=bundle.change, object_type="ConfigurationBundle", object_id=bundle.bundle_id,
        actor=actor, summary=f"{bundle.change.change_id + ': ' if bundle.change_id else ''}integrity check FAILED for {bundle.bundle_id} ({context})"[:255],
        metadata=secret_policy.assert_no_secret_shaped_keys({
            "bundle_id": bundle.bundle_id, "kind": bundle.kind, "bundle_digest": bundle.bundle_digest, "context": context,
            "finding_codes": report.codes[:20], "result": "FAILED",
        }, context="Bundle integrity audit"),
    )


def derive_probation_bundle(uat, *, actor: str) -> BundleResult:
    """Explicitly seal an eligible UAT bundle into a NEW Probation bundle (the UAT bundle is never touched).  Idempotent per UAT bundle.

    Probation means "this exact artifact is the candidate entering probation" -- not that any time has passed and not that it is Golden.
    No timer, no soak state, no lifecycle change and no device call exist here; that is Phase 20."""
    def find():
        return eligibility.existing_child(uat, models.BundleKind.PROBATION)

    existing = find()
    if existing is not None:
        return BundleResult(existing)
    try:
        with transaction.atomic():
            check = eligibility.check_probation_eligibility(uat)
            if check.blockers:
                if check.integrity is not None and not check.integrity.ok:
                    record_integrity_failure(uat, check.integrity, actor=actor, context="probation derivation refused")
                return BundleResult(None, blockers=check.blockers, refused=True)
            rows = list(uat.items.select_related("configlet", "raw_revision", "raw_verification", "execution_result").order_by("sequence"))
            specs = [{"record": copy.deepcopy(r.record), "configlet": r.configlet, "raw_revision": r.raw_revision, "raw_verification": r.raw_verification,
                      "execution_result": r.execution_result} for r in rows]
            refs = dict(change=uat.change, plan=uat.plan, validation_run=uat.validation_run, execution_run=uat.execution_run, postcheck_run=uat.postcheck_run)
            bundle = seal_bundle(
                kind=models.BundleKind.PROBATION, payload=copy.deepcopy(uat.manifest["payload"]),   # SEAL the same payload: never an edit
                lineage={"parent_bundle_digest": uat.bundle_digest, "source_uat_bundle_digest": uat.bundle_digest}, refs=refs, item_specs=specs,
                actor=actor, parent=uat, source_uat=uat, find_existing=find,
            )
    except _AlreadyExists as duplicate:
        return BundleResult(duplicate.bundle)
    return BundleResult(bundle, created=True)


# --- reads ---------------------------------------------------------------------------------------------------------------------
def get_bundle(bundle_id: str):
    import re

    if not re.fullmatch(r"BND-(?:UAT|DEP|PROB|GOLD|LEGACY)-\d{6}", str(bundle_id or "")):
        return None
    return models.ConfigurationBundle.objects.select_related(
        "change", "plan", "validation_run", "execution_run", "postcheck_run", "parent", "source_uat"
    ).filter(bundle_id=bundle_id).first()


def list_bundles(*, kind: str = "", change_id: str = "", limit: int = 100):
    """Newest first.  Never verifies integrity per row (that is a per-bundle, on-demand check)."""
    queryset = models.ConfigurationBundle.objects.select_related("change", "execution_run", "parent")
    if kind in models.BundleKind.values:
        queryset = queryset.filter(kind=kind)
    if change_id:
        queryset = queryset.filter(change__change_id=change_id)
    return list(queryset.order_by("-created_at", "-id")[:limit])


def lineage_of(bundle) -> dict:
    """The lineage around one bundle: its source execution, and the UAT / Probation / Golden artifacts (None where absent)."""
    kinds = models.BundleKind
    if bundle.provenance == models.BundleProvenance.LEGACY_BOOTSTRAP:   # no execution / UAT / Probation exists for a legacy baseline: none is invented
        candidate = bundle if bundle.kind == kinds.LEGACY_BASELINE else bundle.parent
        golden = bundle if bundle.kind == kinds.GOLDEN else eligibility.existing_child(candidate, kinds.GOLDEN)
        return {"execution": None, "uat": None, "probation": None, "golden": golden, "legacy_candidate": candidate}
    uat = bundle if bundle.kind in models.BUNDLE_ROOT_KINDS else bundle.source_uat   # the lineage ROOT: a UAT or a Deployed bundle
    if bundle.kind == kinds.GOLDEN:
        probation = bundle.parent
    elif bundle.kind == kinds.PROBATION:
        probation = bundle
    else:
        probation = eligibility.existing_child(bundle, kinds.PROBATION)
    if bundle.kind == kinds.GOLDEN:
        golden = bundle
    else:
        golden = eligibility.existing_child(probation, kinds.GOLDEN) if probation is not None else None
    return {"execution": bundle.execution_run, "uat": uat, "probation": probation, "golden": golden}
