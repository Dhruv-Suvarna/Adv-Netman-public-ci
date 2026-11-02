"""Recording and reading EMPIRICAL capability evidence (append-only CapabilityEvidence rows + one audit event)."""

from __future__ import annotations

from ... import models
from .. import secret_policy
from .axes import EVIDENCE_TYPE_STRENGTH, EMPIRICAL_STATUSES, Axis, EvidenceStatus, EvidenceType
from .features import by_key, platforms


def record_evidence(*, platform: str, feature: str, axis: str, status: str, source: str, detail: str = "",
                    evidence_ref: str = "", recorded_by: str = "", evidence_type: str = EvidenceType.STATIC,
                    repository_head: str = "", runtime_version: str = "") -> models.CapabilityEvidence:
    """Validate and append one observation.  Only empirical statuses are accepted -- registry claims are derived."""
    if platform not in platforms():
        raise ValueError(f"Unknown platform {platform!r}.")
    if feature not in by_key():
        raise ValueError(f"Unknown capability feature {feature!r}.")
    axis = Axis(axis)
    status = EvidenceStatus(status)
    evidence_type = EvidenceType(evidence_type)
    if status not in EMPIRICAL_STATUSES:
        raise ValueError(f"{status} is a registry status; empirical evidence must be one of {sorted(EMPIRICAL_STATUSES)}.")
    if not source.strip():
        raise ValueError("Evidence needs a source (test id, run id, verifier name).")
    if axis in {Axis.LIVE_READ, Axis.LIVE_WRITE, Axis.LIVE_POST_WRITE_VALIDATION, Axis.RUNTIME_VALIDATION,
                Axis.COMPENSATION} and evidence_type != EvidenceType.LIVE and status == EvidenceStatus.VERIFIED:
        raise ValueError(f"{axis.value} evidence must be LIVE evidence.")
    row = models.CapabilityEvidence.objects.create(
        platform=platform, feature=feature, axis=axis.value, status=status.value, source=source[:64],
        evidence_type=evidence_type.value, detail=secret_policy.redact_text(detail)[:500],
        evidence_ref=evidence_ref[:255], repository_head=repository_head[:40], runtime_version=runtime_version[:128],
        recorded_by=recorded_by[:150],
    )
    models.AuditEvent.objects.create(
        event_type=models.AuditEventType.CAPABILITY_EVIDENCE_RECORDED, object_type="CapabilityEvidence", object_id=str(row.pk),
        actor=recorded_by[:150], summary=f"{platform} {feature} {axis.value}: {status.value}"[:255],
        metadata={"platform": platform, "feature": feature, "axis": axis.value, "status": status.value,
                  "source": source[:64], "evidence_type": evidence_type.value},
    )
    return row


def latest_evidence() -> dict[tuple[str, str, str], models.CapabilityEvidence]:
    """Strongest then newest row per cell/axis; a later static result cannot mask live evidence."""
    latest: dict[tuple[str, str, str], models.CapabilityEvidence] = {}
    for row in models.CapabilityEvidence.objects.order_by("-recorded_at", "-id").iterator():
        key = (row.platform, row.feature, row.axis)
        current = latest.get(key)
        row_strength = EVIDENCE_TYPE_STRENGTH.get(EvidenceType(row.evidence_type), 0)
        current_strength = EVIDENCE_TYPE_STRENGTH.get(EvidenceType(current.evidence_type), 0) if current else -1
        if current is None or row_strength > current_strength:
            latest[key] = row
    return latest
