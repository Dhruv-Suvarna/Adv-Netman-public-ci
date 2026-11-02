"""Read-only, deterministic bundle manifest export.

The exported document is a pure function of STORED, immutable data (no live integrity result, no children -- those change over time), so
the same bundle always exports the same bytes.  It carries the schema versions, identity, kind, both digests, lineage ids, source ids and
the whole canonical manifest (ordered items, raw pins, verification quality) plus an ``export_digest`` over everything else.  It can be
verified WITHOUT the database (``verify_export``): recompute the payload digest, the bundle digest and the export digest from the document.

An export never includes credentials, resolved secrets, command output, logs or anything unbounded: it is the bounded manifest, and it is
re-scanned for secret-shaped content before it is released (a bundle that fails is refused, never sanitized-and-presented).
Exporting writes nothing: no file, no Git commit, no tag, no push, no release.
"""

from __future__ import annotations

import json

from ... import models
from . import canonical
from .codes import DIGEST_ALGORITHM, EXPORT_SCHEMA_VERSION, finding
from .integrity import IntegrityReport, _secret_findings, verify_manifest


class BundleExportBlocked(Exception):
    """The stored manifest contains secret-shaped content, so it is not released."""


def export_document(bundle) -> dict:
    manifest = bundle.manifest
    hits = _secret_findings(manifest) if isinstance(manifest, dict) else []
    if hits:
        raise BundleExportBlocked("SECRET_SHAPED_CONTENT")
    document = {
        "export_schema_version": EXPORT_SCHEMA_VERSION,
        "bundle": {
            "bundle_id": bundle.bundle_id, "kind": bundle.kind, "schema_version": bundle.schema_version, "builder_version": bundle.builder_version,
            "digest_algorithm": DIGEST_ALGORITHM, "payload_digest": bundle.payload_digest, "bundle_digest": bundle.bundle_digest,
            "created_at": bundle.created_at.isoformat(), "created_by": bundle.created_by,
            **({"provenance": bundle.provenance} if bundle.provenance != models.BundleProvenance.EXECUTION_LINEAGE else {}),
        },
        "lineage": {
            "parent_bundle_id": bundle.parent.bundle_id if bundle.parent_id else "",
            "source_uat_bundle_id": bundle.source_uat.bundle_id if bundle.source_uat_id else "",
        },
        "sources": {
            "change_id": bundle.change.change_id, "plan_id": str(bundle.plan.plan_id), "validation_run_id": str(bundle.validation_run.run_id),
            "execution_run_id": str(bundle.execution_run.run_id), "postcheck_run_id": str(bundle.postcheck_run.run_id) if bundle.postcheck_run_id else "",
        } if bundle.change_id else {   # the one-time legacy bootstrap has NO Change / plan / execution: none is fabricated, and the export says so
            "change_id": "", "plan_id": "", "validation_run_id": "", "execution_run_id": "", "postcheck_run_id": "", "provenance": bundle.provenance,
        },
        "manifest": manifest,
    }
    document["export_digest"] = canonical.export_digest(document)
    return document


def export_json(bundle) -> str:
    return json.dumps(export_document(bundle), indent=2, sort_keys=True, ensure_ascii=True, allow_nan=False) + "\n"


def export_filename(bundle) -> str:
    return f"{bundle.bundle_id}.manifest.json"   # server-derived only


def verify_export(document) -> IntegrityReport:
    """Verify an exported document on its own (a dict or its JSON text).  Never raises for a tampered document."""
    report = IntegrityReport()
    try:
        document = json.loads(document) if isinstance(document, (str, bytes)) else document
        claimed = dict(document)
        bundle = claimed["bundle"]
        manifest = claimed["manifest"]
        stored = claimed.pop("export_digest")
        schema = int(bundle["schema_version"])
        if canonical.export_digest(claimed, schema_version=int(claimed["export_schema_version"])) != stored:
            report.findings.append(finding("EXPORT_DIGEST_MISMATCH"))
        report.checks.append("export_digest")
        verify_manifest(manifest, kind=bundle["kind"], stored_payload_digest=bundle["payload_digest"], stored_bundle_digest=bundle["bundle_digest"],
                        schema_version=schema, report=report)
    except (KeyError, TypeError, ValueError):
        report.findings.append(finding("MANIFEST_MALFORMED", reason="EXPORT_DOCUMENT"))
    return report
