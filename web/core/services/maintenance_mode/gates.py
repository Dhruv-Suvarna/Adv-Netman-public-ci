"""The fail-closed gate in front of ENTERING.  Pure: facts in, findings out.  There is no argument that forces a step,
skips the loss evidence or ignores a precheck; a fact that is missing counts as a failed fact.
"""

from __future__ import annotations

from dataclasses import dataclass

from . import model

PROBES_UNHEALTHY = "PRODUCTION_PROBES_UNHEALTHY"
LOSS_EVIDENCE_MISSING = "PACKET_LOSS_EVIDENCE_MISSING"
PACKET_LOSS = "PRODUCTION_PACKET_LOSS"
BASELINE_STALE = "CONFIG_BASELINE_STALE"
OUT_OF_BAND = "OUT_OF_BAND_CHANGE"
PRIOR_UNRESOLVED = "PRIOR_MAINTENANCE_UNRESOLVED"
READINESS_STALE = "READINESS_NOT_CURRENT"


@dataclass(frozen=True)
class Facts:
    """What must be freshly read before entry.  Every default is the failing value."""

    readiness_current: bool = False          # the approved readiness report is still the latest one
    probes_healthy: bool | None = None
    probes_lost: int | None = None           # None = no evidence
    baseline_fresh: bool = False
    out_of_band_change: bool | None = None   # None = not established
    prior_unresolved: tuple[str, ...] | None = None   # ids of unresolved maintenance transactions; None = not established


def entry_findings(report: model.Report, facts: Facts) -> list:
    """Everything that refuses entry.  The readiness blockers come first: an unknown classification, a mechanism that
    is not READY, an unhealthy alternate and a stranded dependency are all already findings of the report."""
    findings = list(report.blockers)
    if not facts.readiness_current:
        findings.append(model.Finding(READINESS_STALE, detail="evaluate readiness again"))
    if facts.probes_healthy is not True:
        findings.append(model.Finding(PROBES_UNHEALTHY))
    if facts.probes_lost is None:
        findings.append(model.Finding(LOSS_EVIDENCE_MISSING))
    elif facts.probes_lost > 0:
        findings.append(model.Finding(PACKET_LOSS, detail=f"{facts.probes_lost} lost"))
    if not facts.baseline_fresh:
        findings.append(model.Finding(BASELINE_STALE))
    if facts.out_of_band_change is not False:
        findings.append(model.Finding(OUT_OF_BAND, detail="not established" if facts.out_of_band_change is None else ""))
    if facts.prior_unresolved is None or facts.prior_unresolved:
        findings.append(model.Finding(PRIOR_UNRESOLVED, workloads=tuple(facts.prior_unresolved or ()),
                                      detail="" if facts.prior_unresolved else "not established"))
    return findings
