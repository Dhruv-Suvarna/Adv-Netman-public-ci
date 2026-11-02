"""Phase-15 health / precheck / postcheck -- the reusable service API.

Views and later phases call THIS module; no health logic lives in a view.  Nothing here deploys, contacts NetBox for
writes, writes Git, edits a plan / Configlet / validation run, sends a notification, or advances a Change lifecycle.

    get_fleet_health()                     Fleet Quick (existing telemetry only; no device access)
    get_device_quick(device)               telemetry-only view of one managed device
    run_device_health(device, actor=..)    explicit read-only Deep Health for ONE managed device (persists a run)
    record_fleet_snapshot(actor=..)        explicit: persist the current Fleet Quick summary
    build_affected_scope(plan)             plan-derived affected-device scope
    run_change_precheck(change, actor=..)  explicit precheck of a CURRENT validated CURRENT plan
    evaluate_plan_requirements(plan, phase, evidence)   the reusable pre/postcheck engine (no I/O)
    run_plan_postcheck(plan, ...)          postcheck wrapper for a later execution phase
    serialize_health_run(run)              sanitized machine-readable run
"""

from __future__ import annotations

from .health import connectivity as _connectivity, device as _device, fleet as _fleet, inventory, live, persistence
from .health.codes import CODES, ENGINE_VERSION, Mode, Phase
from .health.evaluators import evaluate_plan_requirements, evaluate_requirements
from .health.evidence import DeviceEvidence, EvidenceSet, FactGroup
from .health.postchecks import record_postcheck_run, run_plan_postcheck
from .health.prechecks import collect_scope_evidence, run_change_precheck
from .health.requirements import REQUIREMENT_MAP, normalize_plan
from .health.results import CheckResult, aggregate_health
from .health.scope import build_affected_scope

UnknownDeviceError = _device.UnknownDeviceError
UnknownDestinationError = _connectivity.UnknownDestinationError
get_fleet_health = _fleet.get_fleet_health
get_device_quick = _fleet.get_device_quick
run_device_health = _device.run_device_health
serialize_health_run = persistence.serialize_health_run
get_run = persistence.get_run
recent_runs = persistence.recent_runs
latest_run = persistence.latest_run
managed_devices = inventory.managed_devices
get_managed_device = inventory.get_managed_device
get_capability = live.get_capability
ping_targets = _connectivity.ping_targets
run_connectivity = _connectivity.run_connectivity
latest_connectivity_run = _connectivity.latest_connectivity_run

__all__ = [
    "CODES", "ENGINE_VERSION", "Mode", "Phase", "CheckResult", "DeviceEvidence", "EvidenceSet", "FactGroup", "UnknownDeviceError",
    "UnknownDestinationError", "REQUIREMENT_MAP", "aggregate_health", "build_affected_scope", "collect_scope_evidence",
    "evaluate_plan_requirements", "evaluate_requirements", "get_capability", "get_device_quick", "get_fleet_health",
    "get_managed_device", "get_run", "latest_run", "managed_devices", "normalize_plan", "ping_targets", "record_fleet_snapshot",
    "recent_runs", "run_change_precheck", "run_connectivity", "run_device_health", "run_plan_postcheck", "record_postcheck_run",
    "latest_connectivity_run", "serialize_health_run", "serialize_fleet",
]


def serialize_fleet(fleet) -> dict:
    """The presentation / persistence document of a FleetHealth (bounded, no raw source payload)."""
    return {
        "generated_at": fleet.generated_at.isoformat(), "overall": fleet.overall, "counts": fleet.counts, "thresholds": fleet.snapshot.thresholds,
        "topology_available": fleet.snapshot.available, "devices": fleet.devices,
        "conditions": [c.to_dict() for c in fleet.conditions],
    }


def record_fleet_snapshot(*, actor: str = "", fleet=None):
    """Explicit operator action: persist the current Fleet Quick summary as one append-only run (passive views never do)."""
    fleet = fleet or get_fleet_health()
    devices = [{k: row[k] for k in ("device", "platform", "health", "freshness", "age_seconds", "cpu_percent", "memory_percent", "link_issues", "issues")}
               for row in fleet.devices]
    return persistence.record_run(
        mode=Mode.FLEET_QUICK, status=fleet.overall, results=[*fleet.results, *fleet.conditions],
        extra={"summary": {"counts": fleet.counts}, "fleet_devices": devices, "thresholds": fleet.snapshot.thresholds,
               "conditions": [c.to_dict() for c in fleet.conditions]},
        actor=actor,
    )
