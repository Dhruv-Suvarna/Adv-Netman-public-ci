"""Bundle integrity verification.  READ-ONLY: it never repairs, rewrites, re-runs or contacts anything.

(Phase 20: a GOLDEN bundle's ``promotion`` provenance is part of its bundle digest and is cross-checked against the stored soak run, its evidence
digest and the operator's decision.)

A stored flag such as ``integrity_ok`` would be trusted forever, so none exists: integrity is RECOMPUTED, on demand, from the persisted
contents -- schema, both canonical digests, the kind / parent / lineage rules, bundle-item consistency and order, the pinned source
references, the raw revision pins, and the secret hygiene of what is stored.  A bundle that fails is reported prominently, can never
be derived from, and can never feed a Golden transition.

Reads are bounded (one bundle, its items and at most two ancestors).  The bundle LIST never calls this per row.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ... import models
from .. import secret_policy
from ..raw_configlets import static_gate, text as raw_text
from ..soak import evaluator as soak_evaluator
from . import canonical
from .codes import BUNDLE_SCHEMA_VERSION, LEGACY_CANDIDATE_KEYS, LEGACY_GOLDEN_KEYS, LEGACY_PROVENANCE_TYPE, PROMOTION_KEYS, finding

SUPPORTED_SCHEMAS = frozenset({BUNDLE_SCHEMA_VERSION})
MAX_ANCESTOR_DEPTH = 2   # UAT <- PROBATION <- GOLDEN: never deeper


@dataclass
class IntegrityReport:
    findings: list = field(default_factory=list)
    checks: list = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.findings

    @property
    def state(self) -> str:
        return "INTACT" if self.ok else "FAILED"

    @property
    def codes(self) -> list[str]:
        return sorted({f["code"] for f in self.findings})


def _legacy_residue(manifest: dict) -> list[dict]:
    """Legacy baseline: stored device configuration lines that are still secret-shaped once the redaction markers are removed (imported lazily:
    ``legacy`` imports this module)."""
    from . import legacy

    return legacy.secret_residue(manifest)


def _secret_findings(manifest: dict) -> list[dict]:
    hits = []
    try:
        secret_policy.assert_no_secret_shaped_keys(manifest, context="Bundle manifest")
    except ValueError:
        hits.append({"where": "manifest key", "patterns": ["SECRET_SHAPED_KEY"]})
    for record in (manifest.get("payload") or {}).get("items") or []:
        for number, line in enumerate(str(record.get("payload", "")).splitlines(), start=1):
            names = static_gate.secret_patterns(line)
            if names:
                hits.append({"cfg_id": record.get("cfg_id", ""), "line": number, "patterns": names})
    if isinstance(manifest.get("lineage"), dict) and manifest["lineage"].get("legacy_bootstrap") is not None:
        hits += _legacy_residue(manifest)
    return hits[:20]


def verify_manifest(manifest, *, kind: str, stored_payload_digest: str, stored_bundle_digest: str, schema_version: int, report: IntegrityReport) -> bool:
    """The digest / shape checks that need ONLY the manifest and the stored digests (shared with the export verifier).
    -> True when the manifest is well-formed enough for further checks."""
    payload = manifest.get("payload") if isinstance(manifest, dict) else None
    lineage = manifest.get("lineage") if isinstance(manifest, dict) else None
    if not (isinstance(payload, dict) and isinstance(lineage, dict) and isinstance(payload.get("items"), list)):
        report.findings.append(finding("MANIFEST_MALFORMED"))
        return False
    if manifest.get("manifest_schema_version") != schema_version or schema_version not in SUPPORTED_SCHEMAS:
        report.findings.append(finding("SCHEMA_UNSUPPORTED", found=str(manifest.get("manifest_schema_version"))))
        return False
    report.checks.append("schema")
    if manifest.get("kind") != kind:
        report.findings.append(finding("KIND_MISMATCH"))
    try:
        recomputed = canonical.payload_digest(payload, schema_version=schema_version)
    except (TypeError, ValueError):
        report.findings.append(finding("MANIFEST_MALFORMED", reason="NOT_CANONICAL_JSON"))
        return False
    if recomputed != stored_payload_digest:
        report.findings.append(finding("PAYLOAD_DIGEST_MISMATCH"))
    report.checks.append("payload_digest")
    promotion, legacy = lineage.get("promotion"), lineage.get("legacy_bootstrap")
    if legacy is not None:   # the one-time legacy bootstrap: a candidate or the initial Golden -- and NOTHING else may carry the block
        if kind not in (models.BundleKind.LEGACY_BASELINE, models.BundleKind.GOLDEN) or promotion is not None:
            report.findings.append(finding("LINEAGE_INVALID", reason="LEGACY_ON_WRONG_KIND"))
            legacy = None
        else:
            keys = LEGACY_CANDIDATE_KEYS if kind == models.BundleKind.LEGACY_BASELINE else LEGACY_GOLDEN_KEYS
            if not (isinstance(legacy, dict) and legacy.get("provenance_type") == LEGACY_PROVENANCE_TYPE and all(key in legacy for key in keys)):
                report.findings.append(finding("LEGACY_PROVENANCE_MISSING"))
                legacy = legacy if isinstance(legacy, dict) else None
    elif kind == models.BundleKind.LEGACY_BASELINE:
        report.findings.append(finding("LEGACY_PROVENANCE_MISSING"))
    elif kind == models.BundleKind.GOLDEN:   # Phase 20: a normal Golden bundle is only ever the product of a soak + an operator decision
        if not (isinstance(promotion, dict) and all(key in promotion for key in PROMOTION_KEYS)):
            report.findings.append(finding("PROMOTION_MISSING"))
    elif promotion is not None:
        report.findings.append(finding("LINEAGE_INVALID", reason="PROMOTION_ON_NON_GOLDEN"))
        promotion = None
    expected = canonical.bundle_digest(
        kind=kind, payload_digest=stored_payload_digest, parent_bundle_digest=str(lineage.get("parent_bundle_digest", "")),
        source_uat_bundle_digest=str(lineage.get("source_uat_bundle_digest", "")), schema_version=schema_version,
        promotion=promotion if isinstance(promotion, dict) else None, legacy_bootstrap=legacy if isinstance(legacy, dict) else None,
    )
    if expected != stored_bundle_digest:
        report.findings.append(finding("BUNDLE_DIGEST_MISMATCH"))
    report.checks.append("bundle_digest")
    for record in payload["items"]:
        if not isinstance(record, dict) or canonical.text_hash(record.get("payload", "")) != record.get("payload_hash"):
            report.findings.append(finding("ITEM_PAYLOAD_HASH_MISMATCH", cfg_id=str((record or {}).get("cfg_id", "")) if isinstance(record, dict) else ""))
    hits = _secret_findings(manifest)
    if hits:
        report.findings.append(finding("SECRET_SHAPED_CONTENT", findings=hits))
    report.checks.append("secret_hygiene")
    return True


def _root_mode(bundle) -> str:
    """The execution mode the lineage ROOT of this bundle must have been sealed from (UAT: Partial; DEPLOYED: Complete)."""
    root = bundle if bundle.kind in models.BUNDLE_ROOT_KINDS else bundle.source_uat
    return models.BUNDLE_ROOT_MODE.get(getattr(root, "kind", ""), models.ExecutionMode.PARTIAL_UAT)


def _check_lineage(bundle, manifest: dict, report: IntegrityReport, depth: int) -> None:
    lineage = manifest.get("lineage") or {}
    parent_digest, root_digest = str(lineage.get("parent_bundle_digest", "")), str(lineage.get("source_uat_bundle_digest", ""))
    required = models.BUNDLE_PARENT_KIND.get(bundle.kind)
    if required is None:   # a UAT / DEPLOYED bundle is a root: it derives from an execution, never from another bundle
        if bundle.parent_id or bundle.source_uat_id or parent_digest or root_digest:
            report.findings.append(finding("LINEAGE_INVALID", reason="UAT_HAS_PARENT"))
        report.checks.append("lineage")
        return
    parent = bundle.parent
    if parent is None or parent.kind not in required or bundle.source_uat_id is None:
        report.findings.append(finding("LINEAGE_INVALID", reason="PARENT_KIND"))
        report.checks.append("lineage")
        return
    root = parent if parent.kind in models.BUNDLE_ROOT_KINDS else parent.source_uat
    if root is None or bundle.source_uat_id != root.pk:
        report.findings.append(finding("LINEAGE_INVALID", reason="SOURCE_UAT"))
    if parent_digest != parent.bundle_digest or (root is not None and root_digest != root.bundle_digest):
        report.findings.append(finding("PARENT_DIGEST_MISMATCH"))
    if bundle.payload_digest != parent.payload_digest:
        report.findings.append(finding("PAYLOAD_NOT_EQUIVALENT"))
    pinned = ("change_id", "plan_id", "validation_run_id", "execution_run_id", "postcheck_run_id")
    if any(getattr(bundle, name) != getattr(parent, name) for name in pinned):
        report.findings.append(finding("SOURCE_PIN_MISMATCH", reason="PARENT_SOURCES"))
    if depth < MAX_ANCESTOR_DEPTH:
        ancestor = verify_bundle_integrity(parent, _depth=depth + 1)
        if not ancestor.ok:
            report.findings.append(finding("ANCESTOR_INTEGRITY_FAILED", parent=parent.bundle_id, codes=ancestor.codes))
    report.checks.append("lineage")


def _check_promotion(bundle, manifest: dict, report: IntegrityReport) -> None:
    """A Golden bundle's recorded provenance must agree with the stored soak run, its evidence and the operator's decision (Phase 20)."""
    promotion = (manifest.get("lineage") or {}).get("promotion")
    if bundle.kind != models.BundleKind.GOLDEN or not isinstance(promotion, dict):
        report.checks.append("promotion")   # the structural findings (missing / on a non-Golden bundle) come from ``verify_manifest``
        return
    decision = models.GoldenDecision.objects.filter(golden_bundle=bundle).select_related("run").first()
    parent = bundle.parent
    problems = []
    if decision is None or decision.decision != models.GoldenDecisionKind.APPROVE or parent is None:
        problems.append("DECISION")
    else:
        run = decision.run
        expected = {
            "soak_id": run.soak_id, "soak_policy_version": run.policy_version, "soak_duration_seconds": run.duration_seconds,
            "observation_started_at": soak_evaluator.iso(run.started_at), "observation_required_end_at": soak_evaluator.iso(run.required_end_at),
            "observation_completed_at": soak_evaluator.iso(run.finished_at), "evidence_digest": run.evidence_digest,
            "probation_bundle_digest": parent.bundle_digest, "decision": models.GoldenDecisionKind.APPROVE, "decided_by": decision.decided_by,
            "decided_at": soak_evaluator.iso(decision.decided_at),
        }
        problems += [key.upper() for key, value in expected.items() if promotion.get(key) != value]
        if run.bundle_id != parent.pk or decision.bundle_id != parent.pk or decision.probation_bundle_digest != parent.bundle_digest \
                or run.bundle_digest != parent.bundle_digest or decision.evidence_digest != run.evidence_digest:
            problems.append("LINKS")
        problems += [f"SOAK_{issue}" for issue in soak_evaluator.verify_run(run)]
    if problems:
        report.findings.append(finding("PROMOTION_MISMATCH", problems=problems[:10]))
    report.checks.append("promotion")


def _check_items(bundle, payload: dict, schema_version: int, report: IntegrityReport) -> None:
    records = payload.get("items") or []
    rows = list(bundle.items.select_related("configlet", "raw_revision__raw", "raw_verification").order_by("sequence"))
    orders = [r.get("order") if isinstance(r, dict) else None for r in records]
    if len(rows) != len(records) or [r.sequence for r in rows] != list(range(1, len(rows) + 1)) or orders != list(range(1, len(records) + 1)):
        report.findings.append(finding("ITEMS_MISMATCH", rows=len(rows), manifest=len(records)))
        report.checks.append("items")
        return
    for row, record in zip(rows, records):
        cfg = row.cfg_id
        if row.record != record or (row.cfg_id, row.device, row.platform, row.origin, row.operation, row.priority) != (
                record.get("cfg_id"), record.get("device"), record.get("platform"), record.get("origin"), record.get("operation"), record.get("priority")):
            report.findings.append(finding("ITEM_RECORD_MISMATCH", cfg_id=cfg))
            continue
        if row.item_digest != canonical.item_digest(record, schema_version=schema_version):
            report.findings.append(finding("ITEM_DIGEST_MISMATCH", cfg_id=cfg))
        if row.payload != record.get("payload") or canonical.text_hash(row.payload) != row.payload_hash or row.payload_hash != record.get("payload_hash"):
            report.findings.append(finding("ITEM_PAYLOAD_HASH_MISMATCH", cfg_id=cfg))
        if row.configlet.cfg_id != cfg or row.configlet.plan_id != bundle.plan_id:
            report.findings.append(finding("SOURCE_REFERENCE_INVALID", cfg_id=cfg, reason="CONFIGLET"))
        raw = record.get("raw")
        revision, verification = row.raw_revision, row.raw_verification
        if raw is None:
            if revision is not None or verification is not None or row.origin != models.ConfigletOrigin.STRUCTURED:
                report.findings.append(finding("RAW_PIN_MISMATCH", cfg_id=cfg, reason="UNEXPECTED_RAW"))
            continue
        pinned_verification = (raw.get("verification") or {}).get("run_id")
        if (revision is None or verification is None or row.origin != models.ConfigletOrigin.RAW
                or (revision.raw.raw_id, revision.revision, revision.content_hash) != (raw.get("raw_id"), raw.get("revision"), raw.get("revision_content_hash"))
                or str(verification.run_id) != pinned_verification or verification.revision_id != revision.pk
                or raw_text.content_hash(revision.content) != revision.content_hash or revision.content != record.get("payload")):
            report.findings.append(finding("RAW_PIN_MISMATCH", cfg_id=cfg))
    report.checks.append("items")


def _check_sources(bundle, payload: dict, report: IntegrityReport) -> None:
    source = payload.get("source") or {}
    execution = source.get("execution") or {}
    run, plan, validation = bundle.execution_run, bundle.plan, bundle.validation_run
    postcheck = (payload.get("verification") or {}).get("postcheck") or {}
    expected_postcheck = str(bundle.postcheck_run.run_id) if bundle.postcheck_run_id else ""
    problems = []
    if not (run.plan_id == plan.pk and run.change_id == bundle.change_id == plan.change_id and plan.validation_run_id == validation.pk):
        problems.append("RELATIONS")
    if source.get("change_id") != bundle.change.change_id:
        problems.append("CHANGE")
    if (execution.get("run_id"), execution.get("mode"), execution.get("outcome")) != (str(run.run_id), run.mode, run.outcome) \
            or run.state != models.ExecutionRunState.FINISHED or run.mode != _root_mode(bundle):
        problems.append("EXECUTION")
    if not (execution.get("plan_hash") == run.plan_hash == plan.plan_hash == (source.get("plan") or {}).get("plan_hash")) \
            or (source.get("plan") or {}).get("plan_id") != str(plan.plan_id):
        problems.append("PLAN")
    if (source.get("validation") or {}).get("run_id") != str(validation.run_id):
        problems.append("VALIDATION")
    if (postcheck.get("run_id") or "") != expected_postcheck:
        problems.append("POSTCHECK")
    if problems:
        report.findings.append(finding("SOURCE_PIN_MISMATCH", pins=problems))
    report.checks.append("sources")


def verify_bundle_integrity(bundle, *, _depth: int = 0) -> IntegrityReport:
    """Recompute and compare.  Never raises for a tampered bundle: the failure IS the result."""
    report = IntegrityReport()
    manifest = bundle.manifest
    if not verify_manifest(manifest, kind=bundle.kind, stored_payload_digest=bundle.payload_digest, stored_bundle_digest=bundle.bundle_digest,
                           schema_version=bundle.schema_version, report=report):
        return report
    if bundle.provenance == models.BundleProvenance.LEGACY_BOOTSTRAP or bundle.kind == models.BundleKind.LEGACY_BASELINE \
            or (manifest.get("lineage") or {}).get("legacy_bootstrap") is not None:
        from . import legacy   # the one-time legacy bootstrap has its own lineage (candidate -> initial Golden) and NO execution sources to pin

        legacy.verify_bundle(bundle, manifest, report, _depth)
        return report
    _check_lineage(bundle, manifest, report, _depth)
    _check_promotion(bundle, manifest, report)
    _check_items(bundle, manifest["payload"], bundle.schema_version, report)
    _check_sources(bundle, manifest["payload"], report)
    return report
