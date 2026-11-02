"""Fleet-Quick adapter over the EXISTING monitoring services -- there is no second monitoring stack here.

The single source of operational telemetry is the topology service's read-only ``/api/topology`` document, already
consumed by ``core.services.topology_service``: per node the latest gNMI timestamp, CPU %, memory %, recent critical
syslog / SNMP-trap counts, and per link the fresh admin/oper state of each monitored endpoint -- all derived from the
existing InfluxDB bucket.  No Flux query, InfluxDB client, or device connection lives in this module (a contract test
enforces it), and no metric is invented: a value the source does not carry stays ``None`` (UNKNOWN), never ``0``.

The topology payload does NOT carry routing / adjacency state, so Fleet Quick reports routing as NOT_AVAILABLE
instead of guessing; routing state is a Deep-Health (live, read-only) concern.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone

from .. import monitoring_service, nsot_netbox, topology_service
from . import thresholds as thresholds_module
from .evidence import DeviceEvidence, FactGroup, unavailable
from .results import utcnow

SOURCE = "TELEMETRY"


@dataclass
class TelemetrySnapshot:
    available: bool
    reason: str = ""                      # fixed, sanitized text
    now: datetime = field(default_factory=utcnow)
    generated_at: datetime | None = None
    backend_status: str = "UNKNOWN"       # the topology service's InfluxDB status: OK / ERROR / UNKNOWN
    thresholds: dict = field(default_factory=dict)
    nodes: dict = field(default_factory=dict)
    edges: list = field(default_factory=list)


def _parse(value) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def collect(summary: dict | None = None, *, now: datetime | None = None) -> TelemetrySnapshot:
    """One read of the topology service (or the injected ``summary``); never raises."""
    now = now or utcnow()
    summary = summary if summary is not None else topology_service.get_topology_summary()
    if summary.get("status") != "available" or not isinstance(summary.get("data"), dict):
        return TelemetrySnapshot(available=False, reason="Topology service unavailable.", now=now,
                                 thresholds=thresholds_module.load_thresholds())
    payload = summary["data"]
    graph = payload.get("graph") or {}
    backend = payload.get("backend") or {}
    return TelemetrySnapshot(
        available=True, now=now, generated_at=_parse(payload.get("generated_at")),
        backend_status=str(backend.get("status") or "UNKNOWN").upper(),
        thresholds=thresholds_module.load_thresholds(payload.get("health_thresholds_seconds")),
        nodes={str(node["id"]): node for node in graph.get("nodes", [])},
        edges=list(graph.get("edges", [])),
    )


def _number(value):
    return float(value) if isinstance(value, (int, float)) and not isinstance(value, bool) else None


def device_evidence(snapshot: TelemetrySnapshot, device: str, platform: str = "") -> DeviceEvidence:
    """Telemetry evidence for one managed device: a ``telemetry`` group and a PARTIAL ``interfaces`` group."""
    evidence = DeviceEvidence(device=device, platform=platform)
    node = snapshot.nodes.get(device) if snapshot.available else None
    if node is None:
        reason = "TOPOLOGY_UNAVAILABLE" if not snapshot.available else "NOT_IN_TOPOLOGY"
        evidence.groups["telemetry"] = unavailable(SOURCE, reason)
        return evidence
    observed_at = _parse(node.get("last_telemetry_timestamp"))
    evidence.groups["telemetry"] = FactGroup(
        data={
            "monitored": bool(node.get("monitored")),
            "topology_health": node.get("health"),
            "cpu_percent": _number(node.get("cpu_percent")),
            "memory_percent": _number(node.get("memory_percent")),
            "critical_syslog": int(node.get("recent_critical_syslog_count") or 0),
            "snmp_traps": int(node.get("recent_snmp_trap_count") or 0),
        },
        source=SOURCE, observed_at=observed_at,
    )
    interfaces: dict = {}
    for edge in snapshot.edges:
        for endpoint in edge.get("endpoint_state", []):
            if endpoint.get("node") != device or not endpoint.get("evidence_fresh"):
                continue
            name = endpoint.get("monitor_interface") or endpoint.get("interface")
            if name and endpoint.get("oper_status") is not None:
                interfaces[str(name)] = {"admin": str(endpoint.get("admin_status") or "").upper() or None,
                                         "oper": str(endpoint["oper_status"]).upper()}
    if interfaces:  # PARTIAL: only monitored link endpoints -- absence here does not prove absence on the device
        evidence.groups["interfaces"] = FactGroup(data=interfaces, source=SOURCE, observed_at=observed_at, complete=False)
    return evidence


def link_states(snapshot: TelemetrySnapshot, device: str) -> list[dict]:
    """Adjacent links of ``device`` -> [{"id", "plane", "status", "reason"}] (status is the service's own UP/DOWN/...)."""
    if not snapshot.available:
        return []
    return sorted(
        ({"id": edge["id"], "plane": edge.get("plane", ""), "status": str(edge.get("status") or "UNKNOWN").upper(),
          "reason": str(edge.get("health_reason") or "")}
         for edge in snapshot.edges if device in (edge.get("source"), edge.get("target"))),
        key=lambda row: row["id"],
    )


# --- fleet-wide conditions (monitoring pipeline, NetBox as a read-only source) ----------------------------------
def netbox_reachable() -> bool | None:
    """NetBox is a read-only SOURCE for expectations, not a health engine: reachability is reported, never scored."""
    return nsot_netbox.health().get("status") == "available"


def grafana_available() -> bool | None:
    return monitoring_service.get_grafana_health().get("status") == "available"
