"""The one-time LEGACY BASELINE bootstrap, at the bundle layer: the candidate artifact, the initial Golden and the one-time lockout.

WHY THIS EXISTS.  The lab was configured traditionally BEFORE the automation framework existed.  Its running configuration therefore cannot
honestly be pushed through Change -> validation -> plan -> Partial UAT -> UAT bundle -> Probation bundle -> 168-hour soak -> Golden.  The operator
approved exactly ONE exception: adopt what is ACTUALLY RUNNING as the initial Golden, after a short real observation.  This module holds the two
artifacts of that exception and nothing else:

    LEGACY_BASELINE candidate   the sanitized running configuration of every managed device, captured read-only, content-addressed
    GOLDEN (LEGACY_BOOTSTRAP)   sealed from that exact candidate only on the operator's explicit approval of a technically passed observation

NOTHING IS FABRICATED.  There is no Change, plan, validation run, UAT execution, UAT bundle, Probation bundle or Probation soak behind these
artifacts, and none is created to satisfy the normal lineage.  Their provenance is an explicit, typed, digest-covered ``LEGACY_BOOTSTRAP`` block
plus a ``provenance`` column, enforced by model validation AND database constraints.  It is NOT a universal ``parent = NULL``: a normal Golden
still needs a Probation parent and a Change / plan / execution (a database CHECK), and ``legacy_bootstrap`` is rejected on every other kind.

THE LOCKOUT is persisted application state, not a flag: the shortcut is refused while ANY Golden bundle exists, and a unique partial index
allows at most one legacy-bootstrap Golden ever.  A server restart changes nothing.

This module never contacts a device, NetBox or Git: it only reads / writes application rows.  (Reading the devices is ``bootstrap.capture``.)
"""

from __future__ import annotations

import copy
from datetime import timedelta

from django.db import transaction
from django.utils import timezone

from ... import models
from ..bootstrap import evaluator as bootstrap_evaluator, interference as bootstrap_interference
from ..soak.evaluator import iso
from . import canonical, persistence
from .codes import (
    LEGACY_BLOCKERS, LEGACY_BUILDER_VERSION, LEGACY_GOLDEN_KEYS, LEGACY_PROVENANCE_TYPE, LEGACY_ROLE_CANDIDATE,
    LEGACY_ROLE_GOLDEN, MAX_LEGACY_MANIFEST_BYTES, blocker, finding,
)
from .integrity import IntegrityReport, verify_bundle_integrity
from .legacy_sanitize import residual_secret_lines
from .persistence import BundleResult

Kind, Provenance = models.BundleKind, models.BundleProvenance
PAYLOAD_SCHEMA_VERSION = 1
RECHECK_MAX_AGE_SECONDS = 180          # the decision-time configuration re-read must be this fresh when the Golden is sealed
DEVICE_KEYS = ("device", "platform", "management", "captured_at", "capture_method", "read_status", "sections", "config_digest", "expected_state")
SECTION_KEYS = ("name", "command_key", "command", "sanitized", "sha256", "raw_lines", "kept_lines", "redacted_lines", "redaction_patterns")


# --- the one-time gate ----------------------------------------------------------------------------------------------------------
def legacy_golden():
    """The initial Golden created through the bootstrap, if it ever was (persisted state: the lockout survives every restart)."""
    return models.ConfigurationBundle.objects.filter(kind=Kind.GOLDEN, provenance=Provenance.LEGACY_BOOTSTRAP).first()


def gate_blockers() -> list[dict]:
    """Why the legacy-bootstrap shortcut is unavailable (empty == available).  Read-only.  Persisted-state only."""
    blockers = []
    done = legacy_golden()
    if done is not None:
        blockers.append(blocker(LEGACY_BLOCKERS, "LEGACY_BOOTSTRAP_ALREADY_COMPLETED", golden=done.bundle_id))
    elif models.ConfigurationBundle.objects.filter(kind=Kind.GOLDEN).exists():
        blockers.append(blocker(LEGACY_BLOCKERS, "GOLDEN_EXISTS"))
    return blockers


# --- the baseline payload contract ------------------------------------------------------------------------------------------------
def device_config_digest(sections: list[dict]) -> str:
    """One digest per device over its ordered section names + sanitized-text hashes (canonical JSON, domain-tagged; never ``repr``)."""
    return canonical.item_digest({"sections": [{"name": s["name"], "sha256": s["sha256"]} for s in sections]})


def validate_payload(payload) -> list[str]:
    """Structural problems of a legacy baseline payload ([] == well-formed).  Stored text hashes must match, devices must be sorted / unique."""
    problems = []
    if not isinstance(payload, dict) or payload.get("provenance_type") != LEGACY_PROVENANCE_TYPE or payload.get("items") != []:
        return ["SHAPE"]
    baseline = payload.get("baseline")
    devices = (baseline or {}).get("devices") if isinstance(baseline, dict) else None
    if not isinstance(devices, list) or not devices:
        return ["NO_DEVICES"]
    names = [d.get("device") if isinstance(d, dict) else None for d in devices]
    if names != sorted(set(n for n in names if isinstance(n, str))) or len(names) != len(set(names)):
        problems.append("DEVICES_NOT_SORTED_UNIQUE")
    if sorted(str(d) for d in ((payload.get("scope") or {}).get("devices") or [])) != sorted(n for n in names if isinstance(n, str)):
        problems.append("SCOPE_MISMATCH")
    for record in devices:
        if not isinstance(record, dict) or any(key not in record for key in DEVICE_KEYS):
            problems.append("DEVICE_RECORD")
            continue
        if record["read_status"] != "OK":
            problems.append(f"DEVICE_NOT_CAPTURED:{record['device']}")
        sections = record["sections"]
        if not isinstance(sections, list) or not sections or any(not isinstance(s, dict) or any(k not in s for k in SECTION_KEYS) for s in sections):
            problems.append(f"SECTIONS:{record['device']}")
            continue
        if any(canonical.text_hash(s["sanitized"]) != s["sha256"] for s in sections):
            problems.append(f"SECTION_HASH:{record['device']}")
        if device_config_digest(sections) != record["config_digest"]:
            problems.append(f"CONFIG_DIGEST:{record['device']}")
    return problems[:20]


def secret_residue(manifest: dict) -> list[dict]:
    """Stored legacy configuration lines that are still secret-shaped (empty == every secret-bearing value was redacted).  Names / line numbers only."""
    hits = []
    for record in (((manifest.get("payload") or {}).get("baseline") or {}).get("devices") or []):
        for section in (record.get("sections") or []) if isinstance(record, dict) else []:
            for hit in residual_secret_lines(section.get("sanitized", "")):
                hits.append({"device": record.get("device", ""), "section": section.get("name", ""), **hit})
    return hits[:20]


def _candidate_lineage() -> dict:
    return {"parent_bundle_digest": "", "source_uat_bundle_digest": "",
            "legacy_bootstrap": {"provenance_type": LEGACY_PROVENANCE_TYPE, "role": LEGACY_ROLE_CANDIDATE, "policy_version": "LEGACY_BOOTSTRAP_POLICY_V1"}}


# --- the candidate ----------------------------------------------------------------------------------------------------------------
def seal_candidate(payload: dict, *, actor: str, policy_version: str) -> BundleResult:
    """Seal a captured legacy baseline payload into an immutable LEGACY_BASELINE candidate.  Refuses (writing nothing) when the one-time gate is
    closed or the payload is not a complete, well-formed baseline.  NOT Golden, and not an observation: it only records what was seen."""
    with transaction.atomic():
        blockers = gate_blockers()
        if blockers:
            return BundleResult(None, blockers=blockers, refused=True)
        problems = validate_payload(payload)
        if problems:
            return BundleResult(None, blockers=[{"code": "BOOTSTRAP_BASELINE_INCOMPLETE", "message": "The captured baseline is incomplete or malformed.",
                                                 "remediation": "Every managed device must be captured read-only; nothing is silently omitted.", "details": {"problems": problems}}],
                                refused=True)
        if len(canonical.canonical_json(payload)) > MAX_LEGACY_MANIFEST_BYTES:
            return BundleResult(None, blockers=[{"code": "BUNDLE_TOO_LARGE", "message": "The baseline exceeds the maximum bundle size.", "remediation": "Not supported."}], refused=True)
        lineage = _candidate_lineage()
        lineage["legacy_bootstrap"]["policy_version"] = policy_version
        bundle = persistence.seal_bundle(
            kind=models.BundleKind.LEGACY_BASELINE, payload=payload, lineage=lineage, refs={}, item_specs=[], actor=actor, provenance=Provenance.LEGACY_BOOTSTRAP,
            builder_version=LEGACY_BUILDER_VERSION,
            audit_extra={"result": "CAPTURED", "devices": len(payload["scope"]["devices"]), "baseline_digest": canonical.payload_digest(payload)},
        )
    return BundleResult(bundle, created=True)


# --- the initial Golden -----------------------------------------------------------------------------------------------------------
def check_initial_golden(candidate, run, recheck: dict | None, *, now=None) -> list[dict]:
    """Every blocker for sealing the initial Golden from this candidate on this observation RIGHT NOW.  Read-only; ``[]`` == may be sealed."""
    now = now or timezone.now()
    blockers = gate_blockers()
    if candidate.kind != Kind.LEGACY_BASELINE or candidate.provenance != Provenance.LEGACY_BOOTSTRAP:
        return blockers + [blocker(LEGACY_BLOCKERS, "CANDIDATE_NOT_LEGACY", kind=candidate.kind)]
    integrity = verify_bundle_integrity(candidate)
    if not integrity.ok:
        blockers.append(blocker(LEGACY_BLOCKERS, "CANDIDATE_INTEGRITY_FAILED", findings=integrity.codes))
    if not isinstance(run, models.LegacyBootstrapRun):
        return blockers + [blocker(LEGACY_BLOCKERS, "OBSERVATION_NOT_PASSED", state="NONE", result="NONE")]
    if run.candidate_id != candidate.pk or run.candidate_digest != candidate.bundle_digest:
        blockers.append(blocker(LEGACY_BLOCKERS, "OBSERVATION_CANDIDATE_MISMATCH"))
    if not run.is_technical_pass:
        blockers.append(blocker(LEGACY_BLOCKERS, "OBSERVATION_NOT_PASSED", state=run.state, result=run.result or "NONE"))
    else:
        if run.finished_at is None or run.finished_at < run.required_end_at:
            blockers.append(blocker(LEGACY_BLOCKERS, "OBSERVATION_DURATION_NOT_MET"))
        problems = [p for p in bootstrap_evaluator.verify_run(run) if p != "DURATION_NOT_ELAPSED"]
        if problems:
            blockers.append(blocker(LEGACY_BLOCKERS, "OBSERVATION_EVIDENCE_INVALID", problems=problems))
        if run.finished_at is not None and (now - run.finished_at).total_seconds() > int((run.policy or {}).get("decision_max_age_seconds", 0)):
            blockers.append(blocker(LEGACY_BLOCKERS, "OBSERVATION_EXPIRED"))
    if models.LegacyBootstrapDecision.objects.filter(run=run).exists():
        blockers.append(blocker(LEGACY_BLOCKERS, "DECISION_ALREADY_RECORDED"))
    if bootstrap_interference.find_interference(candidate):
        blockers.append(blocker(LEGACY_BLOCKERS, "INTERFERENCE_DETECTED"))
    # the decision-time re-read of the running configuration: it must be recent, complete and IDENTICAL to the observed baseline
    if not recheck or recheck.get("result") != "MATCH" or recheck.get("baseline_digest") != candidate.payload_digest:
        blockers.append(blocker(LEGACY_BLOCKERS, "CONFIG_DRIFT_DETECTED" if (recheck or {}).get("result") == "DRIFT" else "DRIFT_CHECK_INCOMPLETE"))
    else:
        checked_at = recheck.get("checked_at_dt")
        if checked_at is None or (now - checked_at).total_seconds() > RECHECK_MAX_AGE_SECONDS or checked_at > now + timedelta(seconds=5):
            blockers.append(blocker(LEGACY_BLOCKERS, "DRIFT_CHECK_INCOMPLETE"))
    return blockers


def create_initial_golden(candidate, *, evidence, recheck: dict, actor: str, reason: str = "", now=None) -> BundleResult:
    """Seal the exact candidate payload into THE initial Golden.  Called by ``bootstrap.decision`` (the operator's explicit approval) and nothing
    else.  Every check of ``check_initial_golden`` is repeated inside the creating transaction on locked rows; any failure writes nothing.  The
    payload is a deep copy of the candidate's (never re-read from a device after approval), so its payload digest equals the candidate's."""
    now = now or timezone.now()
    existing = legacy_golden()
    if existing is not None:
        return BundleResult(existing)
    try:
        with transaction.atomic():
            locked = models.ConfigurationBundle.objects.select_for_update().get(pk=candidate.pk)
            run = models.LegacyBootstrapRun.objects.select_for_update().get(pk=evidence.pk)
            blockers = check_initial_golden(locked, run, recheck, now=now)
            if blockers:
                integrity = verify_bundle_integrity(locked)
                if not integrity.ok and locked.kind == Kind.LEGACY_BASELINE:
                    persistence.record_integrity_failure(locked, integrity, actor=actor, context="initial golden refused")
                return BundleResult(None, blockers=blockers, refused=True)
            block = {
                "provenance_type": LEGACY_PROVENANCE_TYPE, "role": LEGACY_ROLE_GOLDEN, "policy_version": run.policy_version,
                "candidate_bundle_id": locked.bundle_id, "candidate_bundle_digest": locked.bundle_digest, "baseline_digest": locked.payload_digest,
                "observation_run_id": run.run_id, "observation_duration_seconds": run.duration_seconds,
                "observation_started_at": iso(run.started_at), "observation_required_end_at": iso(run.required_end_at),
                "observation_completed_at": iso(run.finished_at), "evidence_digest": run.evidence_digest, "decision": "APPROVE",
                "decided_by": actor, "decided_at": iso(now), "predates_automation_framework": True,
                "config_recheck_at": iso(recheck["checked_at_dt"]), "config_recheck_result": "MATCH",
            }
            bundle = persistence.seal_bundle(
                kind=models.BundleKind.GOLDEN, payload=copy.deepcopy(locked.manifest["payload"]),
                lineage={"parent_bundle_digest": locked.bundle_digest, "source_uat_bundle_digest": "", "legacy_bootstrap": block},
                refs={}, item_specs=[], actor=actor, parent=locked, source_uat=None, provenance=Provenance.LEGACY_BOOTSTRAP,
                find_existing=legacy_golden, builder_version=LEGACY_BUILDER_VERSION, audit_event_type=models.AuditEventType.LEGACY_GOLDEN_APPROVED,
                audit_extra={"result": "APPROVED", "provenance_type": LEGACY_PROVENANCE_TYPE, "observation_run_id": run.run_id, "evidence_digest": run.evidence_digest,
                             "baseline_digest": locked.payload_digest, "decided_at": iso(now), "reason_chars": len(reason or "")},
            )
            models.LegacyBootstrapDecision.objects.create(
                run=run, candidate=locked, decided_by=actor, decided_at=now, reason=(reason or "")[:500], candidate_digest=locked.bundle_digest,
                evidence_digest=run.evidence_digest, policy_version=run.policy_version, golden_bundle=bundle,
            )
    except persistence._AlreadyExists as duplicate:   # a concurrent approval sealed it first (the unique partial index): that one wins
        return BundleResult(duplicate.bundle)
    return BundleResult(bundle, created=True)


# --- integrity (called by ``integrity.verify_bundle_integrity`` for legacy provenance) -----------------------------------------------
def verify_bundle(bundle, manifest: dict, report: IntegrityReport, depth: int) -> None:
    """The legacy-specific checks that need the database.  ``verify_manifest`` (digests, shape, secret hygiene) has already run."""
    lineage = manifest.get("lineage") or {}
    block = lineage.get("legacy_bootstrap")
    problems = []
    if bundle.provenance != Provenance.LEGACY_BOOTSTRAP or not isinstance(block, dict) or block.get("provenance_type") != LEGACY_PROVENANCE_TYPE:
        report.findings.append(finding("LEGACY_PROVENANCE_MISMATCH", reason="PROVENANCE_COLUMN"))
        return
    bad = validate_payload(manifest.get("payload"))
    if bad:
        report.findings.append(finding("LEGACY_BASELINE_MALFORMED", problems=bad))
    if bundle.kind == Kind.LEGACY_BASELINE:
        if bundle.parent_id or bundle.source_uat_id or block.get("role") != LEGACY_ROLE_CANDIDATE:
            report.findings.append(finding("LINEAGE_INVALID", reason="CANDIDATE_SHAPE"))
        report.checks.append("legacy")
        return
    parent = bundle.parent if bundle.parent_id else None
    if bundle.kind != Kind.GOLDEN or parent is None or parent.kind != Kind.LEGACY_BASELINE or bundle.source_uat_id:
        report.findings.append(finding("LINEAGE_INVALID", reason="LEGACY_GOLDEN_PARENT"))
        return
    if lineage.get("parent_bundle_digest") != parent.bundle_digest:
        report.findings.append(finding("PARENT_DIGEST_MISMATCH"))
    if bundle.payload_digest != parent.payload_digest:
        report.findings.append(finding("PAYLOAD_NOT_EQUIVALENT"))
    if depth < 1:
        ancestor = verify_bundle_integrity(parent, _depth=depth + 1)
        if not ancestor.ok:
            report.findings.append(finding("ANCESTOR_INTEGRITY_FAILED", parent=parent.bundle_id, codes=ancestor.codes))
    decision = models.LegacyBootstrapDecision.objects.filter(golden_bundle=bundle).select_related("run").first()
    if decision is None or block.get("role") != LEGACY_ROLE_GOLDEN or any(key not in block for key in LEGACY_GOLDEN_KEYS):
        problems.append("DECISION")
    else:
        run = decision.run
        expected = {
            "policy_version": run.policy_version, "candidate_bundle_id": parent.bundle_id, "candidate_bundle_digest": parent.bundle_digest,
            "baseline_digest": parent.payload_digest, "observation_run_id": run.run_id, "observation_duration_seconds": run.duration_seconds,
            "observation_started_at": iso(run.started_at), "observation_required_end_at": iso(run.required_end_at),
            "observation_completed_at": iso(run.finished_at), "evidence_digest": run.evidence_digest, "decision": "APPROVE",
            "decided_by": decision.decided_by, "decided_at": iso(decision.decided_at), "predates_automation_framework": True,
        }
        problems += [key.upper() for key, value in expected.items() if block.get(key) != value]
        if run.candidate_id != parent.pk or decision.candidate_id != parent.pk or decision.candidate_digest != parent.bundle_digest \
                or run.candidate_digest != parent.bundle_digest or decision.evidence_digest != run.evidence_digest:
            problems.append("LINKS")
        problems += [f"OBSERVATION_{issue}" for issue in bootstrap_evaluator.verify_run(run)]
    if problems:
        report.findings.append(finding("LEGACY_PROVENANCE_MISMATCH", problems=problems[:10]))
    report.checks.append("legacy")


__all__ = ["check_initial_golden", "create_initial_golden", "gate_blockers", "legacy_golden", "seal_candidate", "validate_payload"]
