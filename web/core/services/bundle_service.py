"""Phase-19 immutable configuration bundles -- the reusable service API.

Views and later phases call THIS module; no bundle logic lives in a view.  Bundle creation is ARTIFACT creation: database rows and one audit
event.  Nothing here executes a Configlet, contacts a device, writes NetBox / Git / GitHub, re-runs a validation / plan / precheck / postcheck /
raw verification, starts a soak or advances ``Change.lifecycle_state``.

    check_uat_eligibility(run)                  read-only: may this finished Partial (UAT) run become a UAT bundle?
    create_uat_bundle(run, actor=..)            explicit, atomic, idempotent (one per run)
    check_probation_eligibility(uat)            read-only: may this UAT bundle be sealed into a Probation candidate?
    derive_probation_bundle(uat, actor=..)      explicit, atomic, idempotent (one per UAT bundle); a NEW artifact, the UAT bundle is untouched
    verify_bundle_integrity(bundle)             read-only recomputation of every digest, the lineage, the items and the pins
    export_document(bundle) / export_json / export_filename / verify_export(document)
    get_bundle / list_bundles / lineage_of
    check_golden_eligibility / can_create_golden_from / create_golden_bundle   Phase 20: the evidence-checked Probation -> Golden promotion
                                                (accepts ONLY a technically passed ProbationSoakRun; called by ``soak.decision`` alone)
"""

from __future__ import annotations

from .bundles import canonical, codes, eligibility, entry, export, golden, integrity, persistence

check_uat_eligibility = eligibility.check_uat_eligibility
check_probation_eligibility = eligibility.check_probation_eligibility
check_golden_eligibility = golden.check_golden_eligibility
can_create_golden_from = golden.can_create_golden_from
create_golden_bundle = golden.create_golden_bundle
create_uat_bundle = persistence.create_uat_bundle
create_deployed_bundle = persistence.create_deployed_bundle
check_deployed_eligibility = eligibility.check_deployed_eligibility
derive_probation_bundle = persistence.derive_probation_bundle
BundleResult = persistence.BundleResult
get_bundle = persistence.get_bundle
list_bundles = persistence.list_bundles
lineage_of = persistence.lineage_of
verify_bundle_integrity = integrity.verify_bundle_integrity
IntegrityReport = integrity.IntegrityReport
export_document = export.export_document
export_json = export.export_json
export_filename = export.export_filename
verify_export = export.verify_export
BundleExportBlocked = export.BundleExportBlocked
BUNDLE_SCHEMA_VERSION = codes.BUNDLE_SCHEMA_VERSION
BUILDER_VERSION = codes.BUILDER_VERSION
UAT_BLOCKERS = codes.UAT_BLOCKERS
PROBATION_BLOCKERS = codes.PROBATION_BLOCKERS
GOLDEN_BLOCKERS = codes.GOLDEN_BLOCKERS
INTEGRITY_FINDINGS = codes.INTEGRITY_FINDINGS
canonical_json = canonical.canonical_json
known_good_baseline = entry.known_good_baseline   # Phase 21 entry: a normal Golden OR the one-time legacy-bootstrap Golden (the source is always reported)

__all__ = [
    "BUILDER_VERSION", "BUNDLE_SCHEMA_VERSION", "BundleExportBlocked", "BundleResult", "GOLDEN_BLOCKERS", "INTEGRITY_FINDINGS", "IntegrityReport",
    "PROBATION_BLOCKERS", "UAT_BLOCKERS", "can_create_golden_from", "canonical_json", "check_golden_eligibility", "check_probation_eligibility",
    "check_deployed_eligibility", "check_uat_eligibility", "create_deployed_bundle", "create_golden_bundle", "create_uat_bundle", "derive_probation_bundle", "export_document", "export_filename",
    "export_json", "get_bundle", "known_good_baseline", "lineage_of", "list_bundles", "verify_bundle_integrity", "verify_export",
]
