"""Exhaustive assessment ledger. Registry defaults NEVER count as a probe.

An offline run is useful progress, but deliberately cannot pass the completion
gate: runtime investigations and live probes must also be supplied. This is
separate from the binary operator support decision.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field

from django.db import transaction
from django.utils import timezone

from ... import models
from .. import secret_policy
from . import evidence, features, vocabulary
from .axes import Axis, EvidenceStatus, EvidenceType, TerminalStatus

PROBES = (
    "semantic_model", "device_builder_ui", "field_validation", "renderer",
    "candidate_generation", "config_validation", "parser_import", "automated_tests",
    "executor", "live_read", "live_write", "live_post_write_validation",
    "compensation", "runtime_validation",
)
LIVE_PROBES = frozenset({"live_read", "live_write", "live_post_write_validation", "compensation", "runtime_validation"})
# Layers without which an NMAS live write cannot be attempted at all. When one of
# these deliberately probed layers fails, the batch harness records the live
# stages as blocked by a ``gate:`` reference instead of booting a runtime merely
# to re-prove the absence.
PREREQUISITE_PROBES = ("semantic_model", "renderer", "candidate_generation", "executor")
GATE_PREFIX = "gate:"
# Flat per-cell layer names of the structured batch report -> named probe.
REPORT_LAYERS = {
    "semantic": "semantic_model", "device_builder": "device_builder_ui", "field_validation": "field_validation",
    "renderer": "renderer", "candidate": "candidate_generation", "validator": "config_validation",
    "parser": "parser_import", "automated_tests": "automated_tests", "executor": "executor",
    "live_read": "live_read", "live_write": "live_write", "postcheck": "live_post_write_validation",
    "compensation": "compensation", "runtime_test": "runtime_validation",
}
OUTCOMES = frozenset({"PASS", "FAIL", "BLOCKED", "PENDING"})
REASONS = frozenset({
    "PLATFORM_DOES_NOT_SUPPORT", "NMAS_MODEL_ABSENT", "UI_ABSENT", "FIELD_VALIDATION_FAILED", "RENDERER_ABSENT",
    "RENDERER_FAILED", "PARSER_ABSENT", "PARSER_FAILED", "VALIDATOR_ABSENT",
    "CONFIG_VALIDATION_FAILED", "EXECUTOR_ABSENT", "EXECUTOR_REFUSED",
    "LIVE_READ_ABSENT", "POSTCHECK_ABSENT", "COMPENSATION_ABSENT",
    "RUNTIME_IMAGE_UNAVAILABLE", "RUNTIME_BOOT_FAILED", "FUNCTIONAL_TEST_FAILED",
    "VENDOR_LIMITATION", "UNSAFE_TO_AUTOMATE", "HARNESS_ERROR",
})


def probe(outcome: str, detail: str, *, reason: str = "", test_type: str = "FIXTURE", reference: str = "") -> dict:
    if outcome not in OUTCOMES:
        raise ValueError("Invalid probe outcome or test type.")
    EvidenceType(test_type)
    if not detail.strip() or (outcome in {"FAIL", "BLOCKED"} and reason not in REASONS):
        raise ValueError("A deliberate failed/blocked probe needs a concrete classified reason.")
    return {"outcome": outcome, "detail": secret_policy.redact_text(detail)[:2000],
            "reason": reason, "test_type": test_type, "reference": reference[:255]}


@dataclass
class CellAssessment:
    platform: str
    feature: str
    repository_head: str
    runtime_version: str = ""
    probes: dict = field(default_factory=dict)
    evidence_ids: list = field(default_factory=list)
    assessed_at: str = field(default_factory=lambda: timezone.now().isoformat())
    assessment_id: int | None = None

    @property
    def blockers(self) -> list[str]:
        """Prerequisite layers that were deliberately probed and did not pass."""
        return [name for name in PREREQUISITE_PROBES if self.probes.get(name, {}).get("outcome") in {"FAIL", "BLOCKED"}]

    @property
    def gated(self) -> bool:
        return any(str(self.probes.get(name, {}).get("reference") or "").startswith(GATE_PREFIX) for name in LIVE_PROBES)

    @property
    def complete(self) -> bool:
        if set(self.probes) != set(PROBES) or not self.repository_head:
            return False
        if not self.runtime_version and self.probes["runtime_validation"].get("reason") != "RUNTIME_IMAGE_UNAVAILABLE":
            return False
        for name, result in self.probes.items():
            if result.get("outcome") not in {"PASS", "FAIL", "BLOCKED"} or not result.get("detail"):
                return False
            if result["outcome"] != "PASS" and result.get("reason") not in REASONS:
                return False
            if name in LIVE_PROBES and result["outcome"] == "PASS" and result.get("test_type") != "LIVE":
                return False
            # A blocked live investigation must reference an actual investigation,
            # not a registry claim or an offline renderer failure.
            reference = str(result.get("reference") or "")
            if name in LIVE_PROBES and result["outcome"] != "PASS" and not reference.startswith(("live:", "runtime:", GATE_PREFIX)):
                return False
            # A prerequisite gate is only an assessment when a prerequisite really
            # failed; a cell whose NMAS layers all pass must be exercised live.
            if name in LIVE_PROBES and reference.startswith(GATE_PREFIX) and (
                    result["outcome"] != "BLOCKED" or not self.blockers):
                return False
        return True

    @property
    def status(self) -> str:
        return TerminalStatus.SUPPORTED.value if self.complete and all(
            r["outcome"] == "PASS" for r in self.probes.values()
        ) else TerminalStatus.UNSUPPORTED.value

    @property
    def reasons(self) -> list[str]:
        return sorted({r["reason"] for r in self.probes.values() if r.get("reason")})

    def as_dict(self) -> dict:
        kinds = [EvidenceType(r["test_type"]) for r in self.probes.values() if r["outcome"] != "PENDING"]
        strength = {EvidenceType.STATIC: 1, EvidenceType.FIXTURE: 2, EvidenceType.LIVE: 3}
        return {
            "platform": self.platform, "feature": self.feature,
            "assessment_complete": self.complete, "final_status": self.status, "status": self.status,
            **dict(zip(("capability_status", "feasibility"), vocabulary.classify(
                self.status, complete=self.complete, reasons=self.reasons, platform=self.platform, feature=self.feature))),
            "assessment_basis": ("PREREQUISITE_GATE" if self.gated else "RUNTIME_INVESTIGATION") if self.complete else "INCOMPLETE",
            **{layer: self.probes.get(name, {}).get("outcome", "PENDING") for layer, name in REPORT_LAYERS.items()},
            "evidence_references": sorted({r["reference"] for r in self.probes.values() if r.get("reference")}),
            "unsupported_reasons": self.reasons,
            "strongest_test_type": max(kinds, key=strength.get).value if kinds else "",
            "repository_head": self.repository_head, "runtime_version": self.runtime_version,
            "timestamp": self.assessed_at, "assessment_id": self.assessment_id,
            "evidence_ids": self.evidence_ids, "probes": self.probes,
        }


@transaction.atomic
def persist(cell: CellAssessment, *, actor: str) -> models.CapabilityAssessment:
    if cell.platform not in features.platforms() or cell.feature not in features.by_key():
        raise ValueError("Assessment must identify a current matrix cell.")
    if not cell.repository_head or set(cell.probes) != set(PROBES):
        raise ValueError("Assessment requires repository HEAD and all named probes, including pending ones.")
    for name, result in cell.probes.items():
        # Validate callers too; no manual annotation can substitute an arbitrary green result.
        probe(**{k: result[k] for k in ("outcome", "detail", "reason", "test_type", "reference")})
        if result["outcome"] == "PENDING" or name.upper() not in Axis._value2member_map_:
            continue
        row = evidence.record_evidence(
            platform=cell.platform, feature=cell.feature, axis=name.upper(),
            status=EvidenceStatus.VERIFIED if result["outcome"] == "PASS" else EvidenceStatus.FAILED,
            source="exhaustive-capability-probe", evidence_type=result["test_type"],
            detail=f"{result['reason']}: {result['detail']}" if result["reason"] else result["detail"],
            evidence_ref=result["reference"], repository_head=cell.repository_head,
            runtime_version=cell.runtime_version, recorded_by=actor,
        )
        cell.evidence_ids.append(row.pk)
    row = models.CapabilityAssessment.objects.create(
        platform=cell.platform, feature=cell.feature, probes=cell.probes,
        evidence_ids=cell.evidence_ids, repository_head=cell.repository_head,
        runtime_version=cell.runtime_version, recorded_by=actor,
    )
    cell.assessment_id = row.pk
    cell.assessed_at = row.recorded_at.isoformat()
    return row


def from_row(row) -> CellAssessment:
    return CellAssessment(row.platform, row.feature, row.repository_head, row.runtime_version,
                          row.probes, list(row.evidence_ids), row.recorded_at.isoformat(), row.pk)


def latest_assessments() -> dict:
    result = {}
    for row in models.CapabilityAssessment.objects.order_by("-recorded_at", "-id").iterator():
        result.setdefault((row.platform, row.feature), from_row(row))
    return result


def report(cells: list[CellAssessment], *, selected_platforms=None, selected_features=None) -> dict:
    plats = tuple(selected_platforms or features.platforms())
    keys = tuple(selected_features or features.by_key())
    expected = {(p, f) for p in plats for f in keys}
    actual = {(c.platform, c.feature): c for c in cells}
    if len(actual) != len(cells) or set(actual) - expected:
        raise ValueError("Duplicate or out-of-scope assessment cells.")
    complete = [c for c in cells if c.complete]
    reasons = Counter(reason for c in cells for reason in c.reasons)
    by_platform = {}
    for platform in plats:
        group = [c for c in cells if c.platform == platform]
        by_platform[platform] = {
            "total": len(keys), "assessed": sum(c.complete for c in group),
            "supported": sum(c.status == "SUPPORTED" for c in group),
            "unsupported": len(keys) - sum(c.status == "SUPPORTED" for c in group),
            **{f"{kind.lower()}_tested": sum(any(r["test_type"] == kind and r["outcome"] != "PENDING"
                                             for r in c.probes.values()) for c in group)
               for kind in ("LIVE", "FIXTURE", "STATIC")},
        }
    return {
        "schema_version": 2, "total": len(expected), "assessed": len(complete),
        "unassessed": len(expected) - len(complete), "offline_attempted": len(cells),
        "supported": sum(c.status == "SUPPORTED" for c in cells),
        "unsupported": len(expected) - sum(c.status == "SUPPORTED" for c in cells),
        "reason_counts": dict(sorted(reasons.items())), "per_platform": by_platform,
        "capability_counts": _capability_counts([actual[key].as_dict() for key in sorted(actual)], len(expected) - len(actual)),
        "remaining_cells": [{"platform": p, "feature": f,
                             "remaining_probes": [n for n in PROBES if (p, f) not in actual or
                                                  actual[p, f].probes.get(n, {}).get("outcome") == "PENDING"]}
                            for p, f in sorted(expected) if (p, f) not in actual or not actual[p, f].complete],
        "cells": [actual[key].as_dict() for key in sorted(actual)],
    }


def _capability_counts(cells: list[dict], never_assessed: int) -> dict:
    found = vocabulary.counts(cells)
    found["NOT_IMPLEMENTED"] += never_assessed
    return found


def require_complete(result: dict) -> None:
    if result["unassessed"] or result["assessed"] != result["total"]:
        raise ValueError(f"Exhaustive validation incomplete: {result['unassessed']} cell(s) still require probes.")
