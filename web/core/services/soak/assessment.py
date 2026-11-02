"""PURE classification of health / postcheck results into ONE sample verdict -- the explicit transient-failure policy.

No I/O, no weighted score: every result is classified by a rule, and the sample verdict is the worst class present in a FIXED order, so a
required-state failure is never averaged away by healthy CPU.

    class                 when                                                                       sample effect
    INTENDED_STATE_FAILED a Phase-15 requirement FAILED (the postcheck verdict is FAIL), or a          FAIL, ends the soak
                          BLOCKING-coded FAIL on a scoped TARGET device (existing ``CODES`` policy)
    RESOURCE_CRITICAL     CPU_HIGH / MEMORY_HIGH at the project's CRITICAL level                       FAIL, ends the soak only after N consecutive
                                                                                                       samples (evaluator; N = the project's
                                                                                                       collector-alert ``consecutive_samples``)
    UNAVAILABLE           evidence missing, stale, expired or not implemented: any non-PASS            INCOMPLETE (never PASS); a coverage gap
                          telemetry-freshness / reachability / pipeline result, any UNKNOWN,
                          a postcheck verdict of INCOMPLETE
    WARNING               a WARN, or a FAIL whose code is not blocking / whose role is not a target    PASS_WITH_WARNINGS (recorded, shown to the
                          (existing ``effective_blocking`` policy), recent critical events            operator; never fails a soak by itself)
    OK                    PASS / NOT_APPLICABLE

Integrity failure or interference outranks everything: the sample is INVALIDATED.  Stale telemetry is therefore NEVER a PASS: a scoped device
whose telemetry is not FRESH makes the sample INCOMPLETE even when a live read succeeded, because the soak's monitoring evidence is missing.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..health.codes import CheckStatus, Freshness
from ..health.results import bound, count_by_status
from .codes import (
    INTENDED_STATE_FAILED, MAX_FINDINGS_PER_SAMPLE, OK, RESOURCE_CRITICAL, UNAVAILABLE, WARNING, SampleResult,
)

S = CheckStatus
# Codes that describe whether the soak's EVIDENCE exists and is current (a non-PASS one is never a device failure -- it is missing evidence).
AVAILABILITY_CODES = frozenset({
    "DEVICE_TELEMETRY_FRESH", "DEVICE_TELEMETRY_STALE", "DEVICE_TELEMETRY_UNAVAILABLE", "DEVICE_REACHABLE", "DEVICE_UNREACHABLE",
    "MONITORING_PIPELINE_UNHEALTHY", "TOPOLOGY_SERVICE_UNAVAILABLE", "TELEMETRY_COLLECTOR_SILENT",
})
RESOURCE_CODES = frozenset({"CPU_HIGH", "MEMORY_HIGH"})
_SEVERITY = {INTENDED_STATE_FAILED: 0, RESOURCE_CRITICAL: 1, UNAVAILABLE: 2, WARNING: 3, OK: 4}
_WORST_FRESHNESS = (Freshness.UNKNOWN, Freshness.EXPIRED, Freshness.STALE, Freshness.FRESH)


def classify(result) -> str:
    """The soak class of ONE CheckResult (see the module docstring)."""
    status, code = result.status, result.check_code
    if status in (S.PASS, S.NOT_APPLICABLE):
        return OK
    if code in AVAILABILITY_CODES:
        return UNAVAILABLE
    if status == S.UNKNOWN:
        return UNAVAILABLE
    if status == S.WARN:
        return WARNING
    # FAIL
    if code in RESOURCE_CODES:
        return RESOURCE_CRITICAL
    return INTENDED_STATE_FAILED if result.blocking else WARNING


@dataclass
class SampleAssessment:
    result: str
    integrity_ok: bool = True
    interference: list = field(default_factory=list)
    expected_state_result: str = ""
    device_health: str = ""
    telemetry_freshness: str = ""
    monitoring_state: str = ""
    terminal_failure: bool = False
    resource_critical: list = field(default_factory=list)
    counts: dict = field(default_factory=dict)
    findings: list = field(default_factory=list)
    evidence: dict = field(default_factory=dict)
    config_drift: bool = False

    def to_kwargs(self) -> dict:
        """The persisted columns of a ProbationSoakSample (the caller adds run / bucket / sampled_at / collector_version)."""
        return {
            "result": self.result, "integrity_ok": self.integrity_ok, "interference": bool(self.interference),
            "expected_state_result": self.expected_state_result, "device_health": self.device_health, "telemetry_freshness": self.telemetry_freshness,
            "monitoring_state": self.monitoring_state, "terminal_failure": self.terminal_failure, "resource_critical": list(self.resource_critical),
            "counts": self.counts, "findings": self.findings, "evidence": self.evidence, "config_drift": self.config_drift,
        }


def invalidated(*, integrity_ok: bool, interference: list, integrity_codes=()) -> SampleAssessment:
    """A sample whose guard failed: the health reads are skipped (nothing else about a superseded / corrupted candidate matters)."""
    findings = []
    if not integrity_ok:
        findings.append({"class": "INVALIDATING", "check_code": "BUNDLE_INTEGRITY_FAILED", "detail": {"codes": list(integrity_codes)[:10]}})
    for run in interference[:5]:
        findings.append({"class": "INVALIDATING", "check_code": "OVERLAPPING_EXECUTION",
                         "detail": {k: run[k] for k in ("run_id", "change_id", "outcome", "devices") if k in run}})
    return SampleAssessment(result=SampleResult.INVALIDATED, integrity_ok=integrity_ok, interference=list(interference), findings=findings,
                            counts={"invalidating": len(findings)})


def apply_config_state(sample: SampleAssessment, comparison: dict) -> SampleAssessment:
    """Fold the configuration comparison against the soak's baseline into a sample (V2 Phase 5C).

    DRIFT invalidates: the configuration under observation is no longer the one that entered probation.  A device whose configuration
    could not be read is missing evidence -- the sample is at best INCOMPLETE, never PASS.  Digests only; never configuration text.
    """
    if not comparison:
        return sample
    sample.evidence = {**sample.evidence, "config": comparison}
    drifted = sorted(name for name, row in comparison.items() if row["state"] == "DRIFT")
    unreadable = sorted(name for name, row in comparison.items() if row["state"] == "UNAVAILABLE")
    for name in drifted:
        sample.findings.insert(0, {"class": "INVALIDATING", "device": name, "check_code": "CONFIGURATION_DRIFT", "status": "FAIL",
                                   "message": "The running configuration differs from the probation baseline.",
                                   "detail": {"changed_sections": comparison[name]["changed_sections"]}})
    for name in unreadable:
        sample.findings.append({"class": UNAVAILABLE, "device": name, "check_code": "CONFIG_READ_UNAVAILABLE", "status": "UNKNOWN",
                                "message": "The running configuration could not be read; drift could not be evaluated."})
    sample.findings = sample.findings[:MAX_FINDINGS_PER_SAMPLE]
    if drifted:
        sample.config_drift, sample.result = True, SampleResult.INVALIDATED
        sample.counts = {**sample.counts, "invalidating": sample.counts.get("invalidating", 0) + len(drifted)}
    elif unreadable and sample.result in (SampleResult.PASS, SampleResult.PASS_WITH_WARNINGS):
        sample.result = SampleResult.INCOMPLETE
        sample.counts = {**sample.counts, "unavailable": sample.counts.get("unavailable", 0) + len(unreadable)}
    return sample


def _finding(result, klass: str) -> dict:
    return {"class": klass, "device": result.device, "check_code": result.check_code, "status": result.status, "message": bound(result.message),
            "cfg_id": result.cfg_id, "subject": bound(result.subject)}


def assess(*, health_results, evaluation, freshness: dict, device_facts: dict, pipeline_ok: bool, observed_at: str | None,
           device_health: str, classifier=None) -> SampleAssessment:
    """Combine the scoped devices' health results and the postcheck evaluation of the pinned descriptors into one sample verdict.

    ``evaluation`` is the Phase-15 ``RequirementEvaluation`` (its verdict is authoritative for the expected-state group); ``freshness`` is
    ``{device: FRESH|STALE|EXPIRED|UNKNOWN}`` of the required telemetry group."""
    classifier = classifier or classify   # the one-time legacy bootstrap passes a stricter classifier; the default is the unchanged Phase-20 policy
    classified = [(r, classifier(r)) for r in health_results]
    classified += [(r, classifier(r)) for r in evaluation.results]
    by_class = {klass: [r for r, c in classified if c == klass] for klass in _SEVERITY}
    # the postcheck engine's verdict is authoritative for the expected-state group (it fails on ANY failed requirement, whatever the role)
    terminal = bool(by_class[INTENDED_STATE_FAILED]) or evaluation.result == "FAIL"
    critical = sorted({f"{r.device}:{r.check_code}" for r in by_class[RESOURCE_CRITICAL]})
    worst = min((freshness.get(d, Freshness.UNKNOWN) for d in freshness), key=_WORST_FRESHNESS.index, default=Freshness.UNKNOWN)
    if terminal:
        result = SampleResult.FAIL
    elif critical:
        result = SampleResult.FAIL
    elif by_class[UNAVAILABLE] or evaluation.result == "INCOMPLETE" or worst != Freshness.FRESH or not pipeline_ok:
        result = SampleResult.INCOMPLETE
    elif by_class[WARNING] or evaluation.result == "PASS_WITH_WARNINGS":
        result = SampleResult.PASS_WITH_WARNINGS
    else:
        result = SampleResult.PASS
    ordered = sorted((pair for pair in classified if pair[1] != OK), key=lambda pair: (_SEVERITY[pair[1]], pair[0].device, pair[0].check_code, pair[0].cfg_id))
    findings = [_finding(r, c) for r, c in ordered[:MAX_FINDINGS_PER_SAMPLE]]
    counts = {**{name.lower(): n for name, n in count_by_status([r for r, _ in classified]).items()},
              **{klass.lower(): len(rows) for klass, rows in by_class.items() if klass != OK}}
    return SampleAssessment(
        result=result, expected_state_result=evaluation.result, device_health=device_health, telemetry_freshness=worst,
        monitoring_state="OK" if pipeline_ok else "UNAVAILABLE", terminal_failure=terminal, resource_critical=critical, counts=counts,
        findings=findings, evidence={"observed_at": observed_at, "devices": device_facts, "requirements": evaluation.summary.get("requirements", 0)},
    )
