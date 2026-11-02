"""Did a network CONFIGURATION EXECUTION touch an included device since the baseline was captured?  (Phase-20 interference detection, reused.)

The baseline is "what was running at capture".  Any Phase-17 execution run that started at or after the capture, was still running, or finished
after the capture began -- and lists an included device -- means the baseline is no longer the configuration originally observed, unless it
demonstrably changed nothing (BLOCKED before any device change, FAILED_NO_MUTATION).  Read-only; it never contacts a device.  Out-of-band edits
leave no execution record: the per-sample CONFIGURATION DRIFT check is what sees those.
"""

from __future__ import annotations

from datetime import datetime, timezone

from django.db.models import Q

from ... import models
from ..soak.interference import MAX_REPORTED, NON_MUTATING_OUTCOMES


def bundle_devices(candidate) -> list[str]:
    return sorted({str(d) for d in ((candidate.payload.get("scope") or {}).get("devices") or [])})


def _baseline_time(candidate, key: str) -> datetime | None:
    text = str(((candidate.payload.get("baseline") or {}).get(key)) or "")
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def capture_started_at(candidate) -> datetime | None:
    return _baseline_time(candidate, "capture_started_at")


def capture_finished_at(candidate) -> datetime | None:
    """When the baseline was captured (recorded IN the immutable payload -- the honest age of the evidence, independent of when the row was written)."""
    return _baseline_time(candidate, "capture_finished_at")


def find_interference(candidate) -> list[dict]:
    """Executions that touched an included device (empty == none).  Bounded, sanitized, newest first."""
    devices = set(bundle_devices(candidate))
    since = capture_started_at(candidate)
    runs = models.ChangeExecutionRun.objects.select_related("change")
    if since is not None:
        runs = runs.filter(Q(state=models.ExecutionRunState.RUNNING) | Q(started_at__gte=since) | Q(finished_at__gte=since))
    found = []
    for run in runs.order_by("-started_at", "-id"):
        overlap = sorted(devices & {str(d) for d in (run.devices or [])})
        if not overlap or (run.state == models.ExecutionRunState.FINISHED and run.outcome in NON_MUTATING_OUTCOMES):
            continue
        found.append({"run_id": str(run.run_id), "change_id": run.change.change_id, "mode": run.mode, "state": run.state,
                      "outcome": run.outcome or "RUNNING", "started_at": run.started_at.isoformat(), "devices": overlap})
        if len(found) >= MAX_REPORTED:
            break
    return found
