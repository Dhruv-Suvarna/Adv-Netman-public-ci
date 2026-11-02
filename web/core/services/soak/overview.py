"""The Golden / probation overview (V2 Phase 5C): what is Golden now, what is in probation, and how far along it really is.

Read-only and database-only: it composes the Golden baseline accessor, the soak progress calculation and the persisted samples.  It never
reads a device, never refreshes telemetry and never implies a candidate is Golden -- a running soak is "in probation", a technically
passed one is "eligible for the operator's decision", and only a sealed Golden bundle is Golden.
"""

from __future__ import annotations

from datetime import datetime

from django.utils import timezone

from ... import models
from ..bundles import entry as bundle_entry
from . import interference, lifecycle
from .policy import SoakPolicy

FRESH, STALE, NO_SAMPLE = "FRESH", "STALE", "NO_SAMPLE"
MAX_EVENTS = 12


def collector_status(run, latest, policy: SoakPolicy, now: datetime) -> dict:
    """Is the scheduled collector really observing this soak?  FRESH = a sample within two intervals; nothing is assumed."""
    if latest is None:
        age = (now - run.started_at).total_seconds()
        return {"state": NO_SAMPLE if age <= 2 * policy.sample_interval_seconds else STALE, "last_sample_at": None, "age_seconds": int(age),
                "expected_every_seconds": policy.sample_interval_seconds}
    age = (now - latest.sampled_at).total_seconds()
    return {"state": FRESH if age <= 2 * policy.sample_interval_seconds else STALE, "last_sample_at": latest.sampled_at, "age_seconds": int(age),
            "expected_every_seconds": policy.sample_interval_seconds}


def _eligibility(run, verdict) -> dict:
    if run.state == models.SoakState.RUNNING:
        return {"code": "IN_PROBATION", "text": "In probation. Not eligible for Golden before the full policy period has elapsed."}
    if run.is_technical_pass:
        decided = models.GoldenDecision.objects.filter(run=run).first()
        if decided is None:
            return {"code": "ELIGIBLE_DECISION_REQUIRED", "text": "The full period passed with sufficient healthy evidence. The operator's Golden decision is required; nothing is promoted automatically."}
        return {"code": f"DECIDED_{decided.decision}", "text": f"Operator decision: {decided.decision}."}
    return {"code": "NOT_ELIGIBLE", "text": "This soak ended without passing and can never become Golden. A retry is a new soak with a new clock."}


def describe(run, *, now: datetime | None = None) -> dict:
    now = now or timezone.now()
    progress = lifecycle.progress(run, now=now)
    policy, latest, bundle = progress["policy"], progress["latest"], run.bundle
    pinned = (run.baseline or {}).get("devices") or {}
    latest_config = ((latest.evidence or {}).get("config") or {}) if latest is not None else {}
    devices = []
    for name in interference.bundle_devices(bundle):
        base, current = pinned.get(name) or {}, latest_config.get(name) or {}
        devices.append({"name": name, "baseline_digest": base.get("digest", ""), "current_digest": current.get("current", ""),
                        "drift_state": current.get("state") or ("NOT_SAMPLED" if base.get("digest") else "NO_BASELINE"),
                        "changed_sections": current.get("changed_sections", [])})
    events = []
    for sample in reversed(progress["samples"]):
        if sample.result in (models.SoakSampleResult.PASS,):
            continue
        events.append({"at": sample.sampled_at, "bucket": sample.bucket, "result": sample.result,
                       "codes": sorted({str(f.get("check_code", "")) for f in (sample.findings or [])} - {""})[:6]})
        if len(events) >= MAX_EVENTS:
            break
    provisioning = models.ProvisioningRun.objects.filter(change_id=bundle.change_id).first() if bundle.change_id else None
    return {
        "run": run, "bundle": bundle, "change": bundle.change, "provisioning": provisioning, "devices": devices,
        "started_at": run.started_at, "due_at": run.required_end_at, "elapsed_seconds": progress["elapsed_seconds"],
        "remaining_seconds": progress["remaining_seconds"], "percent_elapsed": progress["percent_elapsed"],
        "policy_seconds": policy.duration_seconds, "policy_days": policy.duration_seconds / 86400, "is_production_duration": policy.is_production_duration,
        "health": {"device_health": latest.device_health if latest else "", "sample_result": latest.result if latest else "",
                   "expected_state": latest.expected_state_result if latest else "", "telemetry_freshness": latest.telemetry_freshness if latest else ""},
        "collector": collector_status(run, latest, policy, now), "events": events, "samples": len(progress["samples"]),
        "coverage": progress["stats"], "eligibility": _eligibility(run, progress["verdict"]), "baseline_digest": run.baseline_digest,
    }


def overview(*, now: datetime | None = None, history: int = 10) -> dict:
    now = now or timezone.now()
    runs = models.ProbationSoakRun.objects.select_related("bundle", "bundle__change")
    active = [describe(run, now=now) for run in runs.filter(state=models.SoakState.RUNNING).order_by("started_at")]
    awaiting = [describe(run, now=now) for run in runs.filter(state=models.SoakState.COMPLETED, result=models.SoakResult.PASS, decision__isnull=True)]
    finished = list(runs.exclude(state=models.SoakState.RUNNING).order_by("-finished_at")[:history])
    return {"now": now, "golden": bundle_entry.known_good_baseline(), "active": active, "awaiting_decision": awaiting, "finished": finished}
