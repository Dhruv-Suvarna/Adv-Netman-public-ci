"""ONE read-only evidence read for one soak sample.  This module has NO device client, NO Influx client and NO subprocess: it composes the
services that already exist, each of which is already a read-only, allowlisted evidence source.

    integrity      ``bundles.integrity.verify_bundle_integrity``           recomputed from the stored bundle (database only)
    interference   ``interference.find_interference``                      the persisted Phase-17 execution history (database only)
    expected state ``health_service.run_plan_postcheck(persist=False)``    the Phase-15 postcheck engine over the pinned descriptors of the executed
                                                                           prefix, fed by ``collect_scope_evidence`` (its fixed read-only ``show`` /
                                                                           ``ip -j`` allowlists) -- never a browser-supplied command
    telemetry      ``health.telemetry`` + ``health.fleet.quick_checks``    the EXISTING topology service (gNMI stream in InfluxDB): freshness,
                                                                           CPU, memory, critical events.  Grafana is a visualization and is never
                                                                           read; the SNMP on-demand poll is not a soak input.

Nothing here writes anything, refreshes telemetry, converges a device, saves a configuration or persists a health run (``persist=False``): the
caller stores one bounded ``ProbationSoakSample``.  A failed read is missing evidence (INCOMPLETE), never a PASS and never an exception.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from .. import health_service
from ..bundles import integrity as bundle_integrity
from ..health import device as health_device, fleet, telemetry
from ..health.codes import Freshness, Role
from ..health.evidence import DeviceEvidence
from ..health.results import aggregate_health, iso
from . import assessment, config_state, interference


@dataclass
class Guard:
    integrity_ok: bool = True
    integrity_codes: list = field(default_factory=list)
    interference: list = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return self.integrity_ok and not self.interference


def guard(bundle) -> Guard:
    """The two database-only invalidation checks, run on EVERY collector tick (a sample is not needed to notice interference)."""
    report = bundle_integrity.verify_bundle_integrity(bundle)
    return Guard(report.ok, report.codes, interference.find_interference(bundle))


def _scope(plan, devices: set):
    """The plan's affected scope, minus TARGET devices that host none of the candidate's executed Configlets (the unexecuted remainder)."""
    scope = health_service.build_affected_scope(plan)
    for name in [n for n, d in scope.devices.items() if d.role == Role.TARGET and n not in devices]:
        del scope.devices[name]
    return scope


def _facts(device_evidence: DeviceEvidence, freshness: str, now: datetime) -> dict:
    group = device_evidence.group("telemetry")
    data = group.data if group is not None and group.available else {}
    age = group.age_seconds(now) if group is not None else None
    return {
        "freshness": freshness, "age_seconds": None if age is None else round(age, 1), "cpu_percent": data.get("cpu_percent"),
        "memory_percent": data.get("memory_percent"), "critical_events": int(data.get("critical_syslog", 0)) + int(data.get("snmp_traps", 0)),
        "live": "OK" if device_evidence.live_reachable else (device_evidence.live_error or "NOT_ATTEMPTED"),
    }


def collect(bundle, *, now: datetime, snapshot=None, session_factory=None, live_reads: bool = True, guard_result: Guard | None = None,
            baseline: dict | None = None) -> assessment.SampleAssessment:
    """Read every evidence source once and return the sample verdict.  ``snapshot`` / ``session_factory`` are injectable for tests only.

    ``baseline`` is the soak's pinned per-device configuration digests; when given (and device reads are on) each device's configuration
    is re-read and compared (V2 Phase 5C): a drift invalidates the sample.
    """
    checked = guard_result or guard(bundle)
    if not checked.ok:
        return assessment.invalidated(integrity_ok=checked.integrity_ok, interference=checked.interference, integrity_codes=checked.integrity_codes)
    plan = bundle.plan
    devices = set(interference.bundle_devices(bundle))
    cfg_ids = [str(item["cfg_id"]) for item in bundle.payload.get("items") or []]
    scope = _scope(plan, devices)
    snapshot = snapshot or telemetry.collect(now=now)
    evidence = health_service.collect_scope_evidence(scope, snapshot, live_reads=live_reads, session_factory=session_factory, now=now)
    evaluation, _ = health_service.run_plan_postcheck(plan, evidence=evidence, cfg_ids=cfg_ids, persist=False, now=now)

    health_results, freshness, facts, observed = [], {}, {}, []
    for name in sorted(devices):
        device_evidence = evidence.device(name) or DeviceEvidence(device=name)
        group = device_evidence.group("telemetry")
        fresh = group.freshness(now, snapshot.thresholds) if group is not None and group.available else Freshness.UNKNOWN
        freshness[name] = fresh
        if group is not None and group.available and group.observed_at is not None:
            observed.append(group.observed_at)
        health_results.append(health_device.reachability_check(name, device_evidence, fresh, role=Role.TARGET))
        health_results += fleet.quick_checks(name, device_evidence, snapshot, now=now, role=Role.TARGET, live_ok=device_evidence.live_reachable)
        facts[name] = _facts(device_evidence, fresh, now)
    sample = assessment.assess(
        health_results=health_results, evaluation=evaluation, freshness=freshness, device_facts=facts, pipeline_ok=bool(evidence.pipeline.get("available")),
        observed_at=iso(min(observed)) if observed else None, device_health=aggregate_health(health_results),
    )
    pinned = {name: row for name, row in (baseline or {}).items() if row.get("digest")}
    if pinned and live_reads:
        current = config_state.read(pinned, session_factory=session_factory, now=now)
        sample = assessment.apply_config_state(sample, config_state.compare(pinned, current))
    return sample
