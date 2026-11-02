"""Did a LATER configuration execution touch this candidate's devices?

The Probation bundle represents one exact executed configuration.  Nothing locks the network for the window, so interference is DETECTED from
the persisted Phase-17 execution history (``ChangeExecutionRun``) instead: every other run that started at or after the candidate's source
UAT execution and lists one of the candidate's devices is interference, unless it demonstrably changed nothing (BLOCKED before any device
change, or FAILED_NO_MUTATION).  A run that is still RUNNING (or whose lease expired mid-flight, so the device state is unknown) counts.

Deliberate conservatism: the overlap is at DEVICE level.  The recorded results do not let this check prove that two Configlets on the same
device are independent, so a later change to another object of the same device still supersedes the candidate.  This is PROJECT-driven
change only: an out-of-band manual edit on a device leaves no execution record, so it is only visible through the expected-state evidence
(documented limitation).  Read-only; it never contacts a device.
"""

from __future__ import annotations

from ... import models

NON_MUTATING_OUTCOMES = frozenset({models.ExecutionOutcome.BLOCKED, models.ExecutionOutcome.FAILED_NO_MUTATION})
MAX_REPORTED = 10


def bundle_devices(bundle) -> list[str]:
    """The devices of the candidate's executed scope, from its immutable manifest."""
    return sorted({str(d) for d in ((bundle.payload.get("scope") or {}).get("devices") or [])})


def find_interference(bundle) -> list[dict]:
    """Later executions that touched any of the candidate's devices (empty list == none).  Bounded, sanitized, newest first."""
    devices = set(bundle_devices(bundle))
    source = bundle.execution_run
    found = []
    later = models.ChangeExecutionRun.objects.exclude(pk=source.pk).filter(started_at__gte=source.started_at).select_related("change")
    for run in later.order_by("-started_at", "-id"):
        overlap = sorted(devices & {str(d) for d in (run.devices or [])})
        if not overlap or (run.state == models.ExecutionRunState.FINISHED and run.outcome in NON_MUTATING_OUTCOMES):
            continue
        found.append({"run_id": str(run.run_id), "change_id": run.change.change_id, "mode": run.mode, "state": run.state,
                      "outcome": run.outcome or "RUNNING", "started_at": run.started_at.isoformat(), "devices": overlap})
        if len(found) >= MAX_REPORTED:
            break
    return found
