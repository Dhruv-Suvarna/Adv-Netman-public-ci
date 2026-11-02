"""What may Phase 21 (rollback) treat as the known-good baseline?  Read-only.

A valid entry is EITHER

    A  NORMAL_LIFECYCLE   a Golden bundle produced by the full lifecycle: UAT -> Probation -> the normal 7-day soak -> the operator's decision
    B  LEGACY_BOOTSTRAP   the ONE-TIME initial Golden the operator approved after a 30-minute observation of the pre-existing network

Both must still verify (integrity is recomputed, never trusted from a flag).  The source is always REPORTED, never merged: B is never presented as A
and never described as having passed a seven-day soak -- its provenance is preserved forever in the bundle itself.  When several Golden bundles exist
the newest one that verifies is the entry.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ... import models
from .integrity import IntegrityReport, verify_bundle_integrity

NORMAL_LIFECYCLE = "NORMAL_LIFECYCLE"
LEGACY_BOOTSTRAP = "LEGACY_BOOTSTRAP"
NO_GOLDEN, GOLDEN_INTEGRITY_FAILED = "NO_GOLDEN", "GOLDEN_INTEGRITY_FAILED"
NOTES = {
    NORMAL_LIFECYCLE: "Produced by the full lifecycle: UAT, Probation, the normal seven-day soak and the operator's decision.",
    LEGACY_BOOTSTRAP: "The one-time initial Golden: the pre-existing network adopted after a 30-minute observation and the operator's approval. "
                      "It did NOT pass a seven-day soak and has no UAT or Probation bundle.",
}


@dataclass
class BaselineEntry:
    valid: bool
    golden: object | None = None
    source: str = ""
    note: str = ""
    integrity: IntegrityReport | None = None
    blockers: list = field(default_factory=list)


def known_good_baseline() -> BaselineEntry:
    goldens = list(models.ConfigurationBundle.objects.filter(kind=models.BundleKind.GOLDEN).order_by("-created_at", "-id"))
    if not goldens:
        return BaselineEntry(False, blockers=[NO_GOLDEN])
    failed = []
    for golden in goldens:
        report = verify_bundle_integrity(golden)
        if report.ok:
            source = LEGACY_BOOTSTRAP if golden.provenance == models.BundleProvenance.LEGACY_BOOTSTRAP else NORMAL_LIFECYCLE
            return BaselineEntry(True, golden, source, NOTES[source], report)
        failed.append(golden.bundle_id)
    return BaselineEntry(False, blockers=[GOLDEN_INTEGRITY_FAILED], note=", ".join(failed[:5]))
