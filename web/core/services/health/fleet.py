"""Fleet Quick health: fast, fleet-wide, read-only, telemetry only.

One read of the existing topology/monitoring services (never a per-device connection).  For every managed device it
reports telemetry freshness, CPU, memory, link health and recent critical events; routing is reported as
NOT_AVAILABLE because the stored telemetry schema carries no routing state (a live, per-device Deep-Health concern).

``quick_checks`` is shared with Deep Health and the precheck so a device is judged by the SAME rules everywhere.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from . import inventory, telemetry
from .codes import CheckStatus, Freshness, Health, Role
from .evidence import DeviceEvidence
from .results import CheckResult, aggregate_health, iso, ordered, utcnow
from .thresholds import classify_level

EVENT_WINDOW_NOTE = "recent window (topology service)"


@dataclass
class FleetHealth:
    generated_at: datetime
    snapshot: telemetry.TelemetrySnapshot
    devices: list = field(default_factory=list)      # per-device summary rows
    conditions: list = field(default_factory=list)   # fleet-level CheckResults
    results: list = field(default_factory=list)      # every device CheckResult
    overall: str = Health.UNKNOWN
    counts: dict = field(default_factory=dict)


def _telemetry_check(device, evidence, snapshot, now, role, live_ok):
    group = evidence.group("telemetry")
    source = telemetry.SOURCE
    thresholds = snapshot.thresholds["freshness"]
    # Telemetry that cannot be read is UNKNOWN -- unless a live read-only query already proved the device reachable,
    # in which case it is only a WARN (postcheck visibility then rests on live reads).
    missing = CheckStatus.WARN if live_ok else CheckStatus.UNKNOWN
    suffix = " A live read-only query succeeded." if live_ok else ""

    def unavailable(message, observed):
        return CheckResult("DEVICE_TELEMETRY_UNAVAILABLE", missing, device, message + suffix, source, observed=observed, role=role)

    if not snapshot.available:
        return unavailable("Topology service unavailable; telemetry cannot be read.", {"reason": "TOPOLOGY_UNAVAILABLE"})
    if snapshot.backend_status != "OK":
        return unavailable("The monitoring backend reports an error; telemetry is not trustworthy.", {"backend_status": snapshot.backend_status})
    if group is None or not group.available:
        return unavailable("No telemetry evidence exists for this device.", {"reason": getattr(group, "error", "") or "NO_EVIDENCE"})
    if not group.data["monitored"]:
        return unavailable("The device has no continuous monitoring stream.", {"monitored": False})
    freshness = group.freshness(now, snapshot.thresholds)
    age = group.age_seconds(now)
    base = dict(source=source, observed={"age_seconds": None if age is None else round(age, 1), "topology_health": group.data["topology_health"]},
                expected={"fresh_within_seconds": thresholds["healthy"], "stale_within_seconds": thresholds["stale"]},
                observed_at=iso(group.observed_at), freshness=freshness, role=role)
    if freshness == Freshness.FRESH:
        return CheckResult("DEVICE_TELEMETRY_FRESH", CheckStatus.PASS, device, f"Telemetry is {age:.0f}s old.", **base)
    if freshness == Freshness.UNKNOWN:
        return CheckResult("DEVICE_TELEMETRY_UNAVAILABLE", missing, device, "Telemetry carries no timestamp." + suffix, **base)
    if freshness == Freshness.STALE or live_ok:
        note = " (a live read-only query succeeded, so the device itself is reachable)" if live_ok else ""
        return CheckResult("DEVICE_TELEMETRY_STALE", CheckStatus.WARN, device, f"Telemetry is {age:.0f}s old{note}.", **base)
    return CheckResult("DEVICE_TELEMETRY_STALE", CheckStatus.FAIL, device,
                       f"Telemetry is {age:.0f}s old, beyond the {thresholds['stale']:.0f}s freshness timeout.", **base)


def _resource_check(code, label, value, band, freshness, device, group, role):
    base = dict(source=telemetry.SOURCE, expected={"warning_pct": band["warning"], "critical_pct": band["critical"]},
                observed_at=iso(group.observed_at) if group is not None else None, freshness=freshness, role=role)
    if value is None or freshness in (Freshness.EXPIRED, Freshness.UNKNOWN):
        why = "the metric is not provided by telemetry" if value is None else "telemetry is too old to trust"
        return CheckResult(code, CheckStatus.UNKNOWN, device, f"{label} unavailable: {why}.", observed={"percent": value}, **base)
    level = classify_level(value, band)
    status = {"NORMAL": CheckStatus.PASS, "WARNING": CheckStatus.WARN, "CRITICAL": CheckStatus.FAIL}[level]
    return CheckResult(code, status, device, f"{label} {value:.0f}% ({level.lower()}).", observed={"percent": value, "level": level}, **base)


def quick_checks(device: str, evidence: DeviceEvidence, snapshot: telemetry.TelemetrySnapshot, *, now: datetime | None = None,
                 role: str = Role.FLEET, live_ok: bool | None = None) -> list[CheckResult]:
    """Telemetry-derived checks for ONE device (freshness, CPU, memory, events, links).  Pure: no I/O."""
    now = now or utcnow()
    results = [_telemetry_check(device, evidence, snapshot, now, role, bool(live_ok))]
    group = evidence.group("telemetry")
    usable = snapshot.available and snapshot.backend_status == "OK" and group is not None and group.available and group.data["monitored"]
    if not usable:
        return results
    freshness = group.freshness(now, snapshot.thresholds)
    results.append(_resource_check("CPU_HIGH", "CPU", group.data["cpu_percent"], snapshot.thresholds["cpu"], freshness, device, group, role))
    results.append(_resource_check("MEMORY_HIGH", "Memory", group.data["memory_percent"], snapshot.thresholds["memory"], freshness, device, group, role))
    events = group.data["critical_syslog"] + group.data["snmp_traps"]
    results.append(CheckResult(
        "CRITICAL_EVENTS_RECENT", CheckStatus.WARN if events else CheckStatus.PASS, device,
        f"{events} critical syslog event(s) / SNMP trap(s) in the {EVENT_WINDOW_NOTE}." if events else f"No critical events in the {EVENT_WINDOW_NOTE}.",
        telemetry.SOURCE, observed={"critical_syslog": group.data["critical_syslog"], "snmp_traps": group.data["snmp_traps"]},
        observed_at=iso(group.observed_at), freshness=freshness, role=role))
    links = telemetry.link_states(snapshot, device)
    if links:
        down = [row["id"] for row in links if row["status"] == "DOWN"]
        degraded = [row["id"] for row in links if row["status"] == "DEGRADED"]
        unknown = sum(1 for row in links if row["status"] == "UNKNOWN")
        status = CheckStatus.FAIL if down else CheckStatus.WARN if degraded else CheckStatus.PASS
        results.append(CheckResult(
            "LINK_HEALTH_DEGRADED", status, device,
            f"{len(down)} link(s) down, {len(degraded)} degraded, {unknown} without evidence of {len(links)}.",
            telemetry.SOURCE, observed={"links": len(links), "down": down, "degraded": degraded, "unknown": unknown},
            observed_at=iso(group.observed_at), freshness=freshness, role=role))
    return results


def device_row(device: dict, evidence: DeviceEvidence, snapshot, results: list[CheckResult], now: datetime) -> dict:
    """One presentation row.  A missing metric stays ``None`` ('not available'), never 0."""
    group = evidence.group("telemetry")
    data = group.data if group is not None and group.available else {}
    links = next((r for r in results if r.check_code == "LINK_HEALTH_DEGRADED"), None)
    link_issues = None if links is None else len(links.observed["down"]) + len(links.observed["degraded"])
    return {
        "device": device["name"], "platform": device["platform"], "health": aggregate_health(results),
        "freshness": next((r.freshness for r in results if r.check_code.startswith("DEVICE_TELEMETRY")), Freshness.UNKNOWN),
        "age_seconds": None if group is None or group.age_seconds(now) is None else round(group.age_seconds(now), 1),
        "cpu_percent": data.get("cpu_percent"), "memory_percent": data.get("memory_percent"),
        "link_issues": link_issues,
        "routing_issues": None,  # NOT_AVAILABLE: the stored telemetry schema carries no routing / adjacency state
        "last_evidence_at": iso(group.observed_at) if group is not None else None,
        "issues": [r.check_code for r in ordered(results) if r.status in (CheckStatus.WARN, CheckStatus.FAIL)],
        "checks": [r.to_dict() for r in ordered(results)],
    }


def _condition(code, status, message, *, observed=None, source="MONITORING") -> CheckResult:
    return CheckResult(code, status, "FLEET", message, source, observed=observed, role=Role.FLEET, freshness=Freshness.FRESH)


def fleet_conditions(snapshot, rows, *, netbox: bool | None, grafana: bool | None) -> list[CheckResult]:
    """Fleet-level service conditions.  They are reported next to -- never folded into -- the device aggregates."""
    S = CheckStatus
    out = [_condition("TOPOLOGY_SERVICE_UNAVAILABLE", S.PASS if snapshot.available else S.FAIL,
                      "The topology service answered." if snapshot.available else "The topology service could not be read.",
                      observed={"available": snapshot.available})]
    if not snapshot.available:
        backend = _condition("MONITORING_PIPELINE_UNHEALTHY", S.UNKNOWN, "Monitoring backend state is unknown while the topology service is unavailable.")
    else:
        backend = _condition("MONITORING_PIPELINE_UNHEALTHY", S.PASS if snapshot.backend_status == "OK" else S.FAIL,
                             f"Monitoring backend (InfluxDB via the topology service): {snapshot.backend_status}.",
                             observed={"backend_status": snapshot.backend_status})
    out.append(backend)
    if snapshot.available and snapshot.backend_status == "OK":
        fresh = sum(1 for row in rows if row["freshness"] == Freshness.FRESH)
        out.append(_condition("TELEMETRY_COLLECTOR_SILENT", S.PASS if fresh else S.WARN,
                              f"{fresh} of {len(rows)} managed devices have fresh telemetry.",
                              observed={"fresh_devices": fresh, "managed_devices": len(rows)}))
    if netbox is not None:
        out.append(_condition("NETBOX_SOURCE_UNAVAILABLE", S.PASS if netbox else S.WARN,
                              "NetBox (read-only source) answered." if netbox else "NetBox (read-only source) could not be read.", source="NETBOX"))
    if grafana is not None:
        out.append(_condition("GRAFANA_UNAVAILABLE", S.PASS if grafana else S.WARN,
                              "Grafana answered." if grafana else "Grafana could not be read.", source="GRAFANA"))
    return out


def get_fleet_health(*, snapshot: telemetry.TelemetrySnapshot | None = None, now: datetime | None = None,
                     include_sources: bool = True, netbox: bool | None = None, grafana: bool | None = None) -> FleetHealth:
    """Fleet Quick.  Reads existing telemetry once; performs no device, SSH, subprocess or InfluxDB access."""
    now = now or utcnow()
    snapshot = snapshot or telemetry.collect(now=now)
    fleet = FleetHealth(generated_at=now, snapshot=snapshot)
    for name, device in inventory.managed_devices().items():
        evidence = telemetry.device_evidence(snapshot, name, device["platform"])
        results = quick_checks(name, evidence, snapshot, now=now)
        fleet.results.extend(results)
        fleet.devices.append(device_row(device, evidence, snapshot, results, now))
    fleet.counts = {state.lower(): sum(1 for row in fleet.devices if row["health"] == state) for state in Health.ALL}
    fleet.counts["total"] = len(fleet.devices)
    if include_sources:
        netbox = telemetry.netbox_reachable() if netbox is None else netbox
        grafana = telemetry.grafana_available() if grafana is None else grafana
    fleet.conditions = fleet_conditions(snapshot, fleet.devices, netbox=netbox, grafana=grafana)
    states = {row["health"] for row in fleet.devices}
    fleet.overall = (Health.UNHEALTHY if Health.UNHEALTHY in states else Health.DEGRADED if Health.DEGRADED in states
                     else Health.HEALTHY if Health.HEALTHY in states else Health.UNKNOWN)
    return fleet


def get_device_quick(device_name: str, *, snapshot: telemetry.TelemetrySnapshot | None = None, now: datetime | None = None) -> dict | None:
    """The Quick (telemetry-only) view of ONE managed device, or None when the name is not a managed device."""
    device = inventory.get_managed_device(device_name)
    if device is None:
        return None
    now = now or utcnow()
    snapshot = snapshot or telemetry.collect(now=now)
    evidence = telemetry.device_evidence(snapshot, device["name"], device["platform"])
    return device_row(device, evidence, snapshot, quick_checks(device["name"], evidence, snapshot, now=now), now)
