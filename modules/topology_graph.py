"""NetworkX graph model and real InfluxDB health overlay for NMAS topology.

This module is deliberately independent of the HTTP presentation and of
Containerlab lifecycle commands.  A validated active-topology snapshot is its
only topology input; all operational state comes from the existing InfluxDB
measurements.
"""
from __future__ import annotations

import csv
from datetime import datetime, timezone
import io
import json
import math
import re
from typing import Any

import networkx as nx
import requests

NODE_STATES = {"HEALTHY", "STALE", "OFFLINE", "UNKNOWN"}
EDGE_STATES = {"UP", "DOWN", "DEGRADED", "UNKNOWN"}
DEMO_MODE = "safe-link-down"


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def isoformat(value: datetime | None) -> str | None:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z") if value else None


def parse_time(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def age_seconds(value: datetime | None, now: datetime) -> float | None:
    if value is None:
        return None
    return max(0.0, (now - value).total_seconds())


def classify_node(
    *, monitored: bool, last_update: datetime | None, now: datetime,
    healthy_seconds: int, stale_seconds: int,
) -> tuple[str, str]:
    if not monitored:
        return "UNKNOWN", "No continuous monitoring stream is configured for this endpoint"
    age = age_seconds(last_update, now)
    if age is None:
        return "UNKNOWN", "No retained telemetry evidence exists"
    if age <= healthy_seconds:
        return "HEALTHY", f"Latest telemetry is {age:.1f}s old"
    if age <= stale_seconds:
        return "STALE", f"Latest telemetry is {age:.1f}s old"
    return "OFFLINE", f"Latest telemetry is {age:.1f}s old (freshness timeout exceeded)"


def canonical_edge_id(a: dict[str, Any], z: dict[str, Any]) -> str:
    values = sorted((f'{a["node"]}:{a["interface"]}', f'{z["node"]}:{z["interface"]}'))
    return "--".join(values)


def _node_link_data(graph: nx.Graph) -> dict[str, Any]:
    """Use the stable `edges` output key across supported NetworkX releases."""
    try:
        return nx.node_link_data(graph, edges="edges")
    except TypeError:  # NetworkX 3.2/3.3 compatibility
        return nx.node_link_data(graph, link="edges")  # pylint: disable=unexpected-keyword-arg  # NetworkX 3.2/3.3 compatibility branch; only reached on their TypeError


def _flux_string(value: str) -> str:
    return json.dumps(value)


def _clean_row(row: dict[str, str]) -> dict[str, str] | None:
    meaningful = {key: value for key, value in row.items() if key and key not in {"result", "table"} and value != ""}
    if not meaningful or any(value == key for key, value in meaningful.items()):
        return None
    return {key: value for key, value in row.items() if key and value != ""}


class InfluxEvidence:
    """Read-only access to the repository's existing monitoring bucket."""

    def __init__(self, *, org: str, bucket: str, token: str, url: str = "http://127.0.0.1:8086"):
        self.org = org
        self.bucket = bucket
        self.token = token
        self.url = url.rstrip("/")
        self.session = requests.Session()
        self.session.trust_env = False
        self.session.headers["Authorization"] = "Token " + token

    def query(self, flux: str) -> list[dict[str, str]]:
        response = self.session.post(
            self.url + "/api/v2/query",
            params={"org": self.org},
            headers={"Content-Type": "application/vnd.flux", "Accept": "application/csv"},
            data=flux,
            timeout=15,
        )
        response.raise_for_status()
        rows: list[dict[str, str]] = []
        header: list[str] | None = None
        for values in csv.reader(io.StringIO(response.text)):
            if not values or (values[0].startswith("#") if values[0] else False):
                continue
            if "result" in values and "table" in values and ("_time" in values or "_value" in values or "device" in values):
                header = values
                continue
            if header is None:
                continue
            row = dict(zip(header, values))
            clean = _clean_row(row)
            if clean:
                rows.append(clean)
        return rows

    def collect(self, event_window_seconds: int) -> dict[str, Any]:
        bucket = _flux_string(self.bucket)
        device_rows = self.query(
            f'from(bucket: {bucket}) |> range(start: -30d) '
            '|> filter(fn: (r) => r._measurement == "gnmi_telemetry" and '
            '(r.category == "system_identity" or r.category == "system_cpu" or r.category == "system_memory")) '
            '|> group(columns: ["device", "_field"]) |> last() '
            '|> keep(columns: ["_time", "device", "platform", "category", "_field", "_value"])'
        )
        interface_rows = self.query(
            f'from(bucket: {bucket}) |> range(start: -30d) '
            '|> filter(fn: (r) => r._measurement == "gnmi_telemetry" and r.category == "interface_state") '
            '|> group(columns: ["device", "interface", "_field"]) |> last() '
            '|> keep(columns: ["_time", "device", "interface", "_field", "_value"])'
        )
        counter_rows = self.query(
            f'from(bucket: {bucket}) |> range(start: -30d) '
            '|> filter(fn: (r) => r._measurement == "gnmi_telemetry" and r.category == "interface_counters" and '
            '(r._field == "in_errors" or r._field == "out_errors" or r._field == "in_discards" or r._field == "out_discards")) '
            '|> group(columns: ["device", "interface", "_field"]) |> last() '
            '|> keep(columns: ["_time", "device", "interface", "_field", "_value"])'
        )
        syslog_rows = self.query(
            f'from(bucket: {bucket}) |> range(start: -{int(event_window_seconds)}s) '
            '|> filter(fn: (r) => r._measurement == "syslog_event" and r._field == "message") '
            '|> keep(columns: ["_time", "device", "severity"]) |> limit(n: 2000)'
        )
        trap_rows = self.query(
            f'from(bucket: {bucket}) |> range(start: -{int(event_window_seconds)}s) '
            '|> filter(fn: (r) => r._measurement == "snmp_trap" and r._field == "raw_varbinds") '
            '|> keep(columns: ["_time", "device", "event_type", "ifindex"]) |> limit(n: 2000)'
        )
        ifindex_rows = self.query(
            f'from(bucket: {bucket}) |> range(start: -30d) '
            '|> filter(fn: (r) => r._measurement == "snmp_poll" and r.metric == "ifOperStatus" and r._field == "value") '
            '|> group(columns: ["device", "ifindex", "interface"]) |> last() '
            '|> keep(columns: ["device", "ifindex", "interface"])'
        )
        return normalize_evidence(device_rows, interface_rows, counter_rows, syslog_rows, trap_rows, ifindex_rows)


def _number(value: str) -> int | float | str:
    try:
        result = float(value)
        return int(result) if result.is_integer() else result
    except (TypeError, ValueError):
        return value


def normalize_evidence(
    device_rows: list[dict[str, str]], interface_rows: list[dict[str, str]],
    counter_rows: list[dict[str, str]], syslog_rows: list[dict[str, str]],
    trap_rows: list[dict[str, str]], ifindex_rows: list[dict[str, str]],
) -> dict[str, Any]:
    devices: dict[str, dict[str, Any]] = {}
    interfaces: dict[tuple[str, str], dict[str, Any]] = {}
    syslog: dict[str, list[dict[str, Any]]] = {}
    traps: dict[str, list[dict[str, Any]]] = {}
    link_events: dict[tuple[str, str], list[dict[str, Any]]] = {}

    for row in device_rows:
        device = row.get("device")
        stamp = parse_time(row.get("_time"))
        if not device or not stamp:
            continue
        item = devices.setdefault(device, {"fields": {}, "last_update": stamp})
        item["last_update"] = max(item["last_update"], stamp)
        item["platform"] = row.get("platform")
        item["fields"][row.get("_field", "unknown")] = _number(row.get("_value", ""))

    for row in [*interface_rows, *counter_rows]:
        device, interface = row.get("device"), row.get("interface")
        stamp = parse_time(row.get("_time"))
        if not device or not interface or not stamp:
            continue
        item = interfaces.setdefault((device, interface), {
            "fields": {}, "last_update": stamp, "state_last_update": None,
            "counter_last_update": None,
        })
        item["last_update"] = max(item["last_update"], stamp)
        field = row.get("_field", "unknown")
        item["fields"][field] = _number(row.get("_value", ""))
        timestamp_key = "state_last_update" if field in {"admin_status", "oper_status"} else "counter_last_update"
        item[timestamp_key] = max(filter(None, (item[timestamp_key], stamp)))

    for row in syslog_rows:
        device, stamp = row.get("device"), parse_time(row.get("_time"))
        if device and stamp:
            syslog.setdefault(device, []).append({"timestamp": stamp, "severity": row.get("severity", "unknown")})

    for row in trap_rows:
        device, stamp = row.get("device"), parse_time(row.get("_time"))
        if device and stamp:
            traps.setdefault(device, []).append({
                "timestamp": stamp, "event_type": row.get("event_type", "other"), "ifindex": row.get("ifindex"),
            })

    ifindex_map = {
        (row.get("device", ""), row.get("ifindex", "")): row.get("interface", "")
        for row in ifindex_rows if row.get("device") and row.get("ifindex") and row.get("interface")
    }
    for device, events in traps.items():
        for event in events:
            if event["event_type"] not in {"linkDown", "linkUp"}:
                continue
            interface = ifindex_map.get((device, event.get("ifindex", "")))
            if interface:
                link_events.setdefault((device, interface), []).append(event)
    for values in (*syslog.values(), *traps.values(), *link_events.values()):
        values.sort(key=lambda item: item["timestamp"])
    return {"devices": devices, "interfaces": interfaces, "syslog": syslog, "traps": traps, "link_events": link_events}


def empty_evidence() -> dict[str, Any]:
    return {"devices": {}, "interfaces": {}, "syslog": {}, "traps": {}, "link_events": {}}


def _memory_percent(fields: dict[str, Any]) -> float | None:
    physical, used = fields.get("mem_physical_bytes"), fields.get("mem_used_bytes")
    if not isinstance(physical, (int, float)) or not isinstance(used, (int, float)) or physical <= 0:
        return None
    return round(100.0 * used / physical, 2)


def _role(name: str) -> str:
    if re.fullmatch(r"R\d+", name):
        return "router"
    if re.fullmatch(r"S\d+", name):
        return "switch"
    if name == "mgmt_swt":
        return "management-switch"
    if re.fullmatch(r"H\d+", name):
        return "host"
    if name == "WebServer":
        return "server"
    return "unknown"


# --- Presentation-only hierarchical layout --------------------------------
#
# Everything below decides where an already-real node is *drawn*. It never
# adds, removes, or reinterprets a node or edge: `build_base_graph` above this
# point is the only place topology identity is established, straight from
# `active_topology_snapshot()`. The tier map keys on node identity, which the
# frozen Lab 1 baseline (see AGENTS.md) documents as stable naming
# (R1/R2/.../R5, S1-S4, H1-H4, WebServer, mgmt_swt); this is visualization
# metadata only and must never be read as a topology relationship. A node
# outside that documented set still renders (via the role-based fallback)
# instead of raising, but the frozen baseline is what the ordering targets.
#
# Within a tier, left-to-right order comes from a deterministic barycenter
# (median-heuristic) sweep over the *real* data-plane adjacency already on
# the graph -- the same technique layered ("Sugiyama-style") graph drawing
# tools use to cut down line crossings. No adjacency is invented for this;
# a tier with no resolvable neighbor above/below simply falls back to
# alphabetical order, which keeps every run of this function identical for
# an unchanged graph.
_PRESENTATION_TIER_BY_NAME: dict[str, int] = {
    "WebServer": 0,  # service/server
    "R5": 1,  # upstream/core
    "R3": 2, "R4": 2,  # upper routers
    "S3": 3, "S4": 3,  # upper switches
    "R1": 4, "R2": 4,  # edge routers
    "S1": 5, "S2": 5,  # access switches
    "H1": 6, "H2": 6, "H3": 6, "H4": 6,  # hosts
}
_PRESENTATION_TIER_BY_ROLE = {"server": 0, "router": 4, "switch": 5, "host": 6}
_MANAGEMENT_NODE_NAME = "mgmt_swt"
_TIER_HEIGHT = 130.0
_NODE_SPACING = 150.0
_MANAGEMENT_X_MARGIN = 340.0
_MANAGEMENT_ROW_SPACING = 70.0


def _presentation_tier(name: str, role: str) -> int | None:
    """Purely cosmetic vertical row for `name` (`None` => management zone).

    Documented for AGENTS.md-frozen names; anything else falls back to a
    role-derived row so the page still renders sensibly. This never affects
    graph node/edge identity, health, or the management/data `plane` field.
    """
    if name == _MANAGEMENT_NODE_NAME:
        return None
    if name in _PRESENTATION_TIER_BY_NAME:
        return _PRESENTATION_TIER_BY_NAME[name]
    return _PRESENTATION_TIER_BY_ROLE.get(role, max(_PRESENTATION_TIER_BY_NAME.values()))


def _order_tiers(graph: nx.Graph, tiers: dict[int, list[str]]) -> dict[int, list[str]]:
    """Deterministic barycenter ordering within each presentation row."""
    order = {level: sorted(members) for level, members in tiers.items()}
    levels = sorted(order)

    def resolve(level: int, reference: int) -> None:
        reference_position = {node: index for index, node in enumerate(order[reference])}

        def key(node: str) -> tuple[float, str]:
            neighbor_positions = [
                reference_position[other]
                for other in graph.neighbors(node)
                if graph[node][other].get("plane") == "data" and other in reference_position
            ]
            barycenter = (
                sum(neighbor_positions) / len(neighbor_positions)
                if neighbor_positions
                else float(reference_position.get(node, len(reference_position)))
            )
            return (barycenter, node)

        order[level] = sorted(order[level], key=key)

    for _ in range(2):  # a down sweep then an up sweep, twice, converges quickly for small rows
        for level, previous in zip(levels[1:], levels[:-1]):
            resolve(level, previous)
        for level, following in zip(reversed(levels[:-1]), reversed(levels[1:])):
            resolve(level, following)
    return order


def _tier_coordinates(order: dict[int, list[str]]) -> dict[str, tuple[float, float]]:
    coordinates: dict[str, tuple[float, float]] = {}
    for level, members in order.items():
        count = len(members)
        for index, node in enumerate(members):
            x = (index - (count - 1) / 2.0) * _NODE_SPACING
            coordinates[node] = (round(x, 6), round(level * _TIER_HEIGHT, 6))
    return coordinates


def build_base_graph(snapshot: dict[str, Any], layout_seed: int) -> nx.Graph:
    graph = nx.Graph(
        lab_name=snapshot["lab_name"],
        topology_source=snapshot["source"],
        topology_source_sha256=snapshot["source_sha256"],
        excluded_host_links=snapshot.get("excluded_host_links", 0),
    )
    for item in sorted(snapshot["nodes"], key=lambda value: value["id"]):
        node = dict(item)
        node["canonical_name"] = node["id"]
        node["role"] = _role(node["id"])
        graph.add_node(node.pop("id"), **node)
    for item in sorted(snapshot["edges"], key=lambda value: value["id"]):
        a, z = item["endpoints"]
        if graph.has_edge(a["node"], z["node"]):
            raise ValueError(f'Duplicate/parallel edge between {a["node"]} and {z["node"]}')
        edge = dict(item)
        edge.pop("endpoints")
        graph.add_edge(a["node"], z["node"], endpoints=[dict(a), dict(z)], **edge)
    if graph.number_of_nodes() == 0 or not nx.is_connected(graph):
        raise ValueError("Active topology graph must be non-empty and connected")

    # `layout_seed` no longer drives an angle offset: the layered policy is
    # fully deterministic from node identity and real data-plane adjacency.
    # The parameter and the `layout_seed` config key are kept so existing
    # config validation, tests, and provisioning content-hashing are
    # unaffected by this presentation-only change.
    del layout_seed
    tiers: dict[int, list[str]] = {}
    management_nodes: list[str] = []
    for node, meta in graph.nodes(data=True):
        tier = _presentation_tier(node, meta.get("role", ""))
        meta["presentation_tier"] = tier
        if tier is None:
            meta["presentation_region"] = "management-zone"
            management_nodes.append(node)
        else:
            meta["presentation_region"] = "data-plane"
            tiers.setdefault(tier, []).append(node)

    ordered = _order_tiers(graph, tiers)
    coordinates = _tier_coordinates(ordered)
    for node, (x, y) in coordinates.items():
        graph.nodes[node]["x"] = x
        graph.nodes[node]["y"] = y

    if management_nodes:
        levels = sorted(ordered)
        data_x = [x for x, _ in coordinates.values()]
        left_edge = min(data_x) if data_x else 0.0
        mgmt_x = round(left_edge - _MANAGEMENT_X_MARGIN, 6)
        mgmt_y = round(((levels[0] + levels[-1]) / 2.0) * _TIER_HEIGHT, 6) if levels else 0.0
        for index, node in enumerate(sorted(management_nodes)):
            offset = (index - (len(management_nodes) - 1) / 2.0) * _MANAGEMENT_ROW_SPACING
            graph.nodes[node]["x"] = mgmt_x
            graph.nodes[node]["y"] = round(mgmt_y + offset, 6)
    return graph


def _endpoint_view(endpoint: dict[str, Any], evidence: dict[str, Any], now: datetime, stale_seconds: int) -> dict[str, Any]:
    key = (endpoint["node"], endpoint["monitor_interface"])
    found = evidence["interfaces"].get(key)
    result = dict(endpoint)
    result.update({
        "admin_status": None, "oper_status": None, "last_update": None,
        "age_seconds": None, "evidence_fresh": False, "errors": None, "discards": None,
    })
    if not found:
        return result
    fields = found["fields"]
    state_update = found.get("state_last_update")
    age = age_seconds(state_update, now)
    error_values = [value for name, value in fields.items() if name in {"in_errors", "out_errors"} and isinstance(value, (int, float))]
    discard_values = [value for name, value in fields.items() if name in {"in_discards", "out_discards"} and isinstance(value, (int, float))]
    result.update({
        "admin_status": fields.get("admin_status"),
        "oper_status": fields.get("oper_status"),
        "last_update": isoformat(state_update),
        "age_seconds": round(age, 2) if age is not None else None,
        "evidence_fresh": age is not None and age <= stale_seconds and fields.get("oper_status") is not None,
        "errors": sum(error_values) if error_values else None,
        "discards": sum(discard_values) if discard_values else None,
    })
    return result


def classify_edge(
    endpoints: list[dict[str, Any]], recent_events: list[dict[str, Any]],
    monitored_nodes: set[str],
) -> tuple[str, str, str]:
    fresh = [item for item in endpoints if item["evidence_fresh"]]
    fresh_times = [parse_time(item["last_update"]) for item in fresh if item.get("last_update")]
    latest_state = max(fresh_times) if fresh_times else None
    latest_event = max(recent_events, key=lambda item: item["timestamp"]) if recent_events else None

    if any(str(item.get("oper_status", "")).upper() not in {"UP"} for item in fresh):
        return "DOWN", "A fresh monitored endpoint reports oper-status != UP", "gnmi_telemetry"
    if latest_event and (latest_state is None or latest_event["timestamp"] > latest_state):
        if latest_event["event_type"] == "linkDown":
            return "DOWN", "A linkDown notification is newer than interface telemetry", "snmp_trap"
        if latest_event["event_type"] == "linkUp":
            return "UP", "A linkUp notification is newer than interface telemetry", "snmp_trap"
    if any(str(item.get("admin_status", "")).upper() != "UP" for item in fresh):
        return "DEGRADED", "Fresh endpoint administrative state is not UP", "gnmi_telemetry"
    expected_monitored = sum(1 for item in endpoints if item["node"] in monitored_nodes)
    if not fresh:
        return "UNKNOWN", "No fresh monitored endpoint evidence is available", "none"
    if len(fresh) < expected_monitored:
        return "DEGRADED", "Only part of the monitored endpoint evidence is fresh", "gnmi_telemetry"
    return "UP", "All available monitored endpoint evidence reports admin/oper UP", "gnmi_telemetry"


def overlay_health(
    graph: nx.Graph, evidence: dict[str, Any], config: dict[str, Any],
    *, now: datetime | None = None, demo: str | None = None,
) -> dict[str, Any]:
    now = now or utc_now()
    monitored_nodes = {node for node, meta in graph.nodes(data=True) if meta.get("monitored")}
    for node, meta in graph.nodes(data=True):
        device = evidence["devices"].get(node)
        last_update = device.get("last_update") if device else None
        state, reason = classify_node(
            monitored=bool(meta.get("monitored")), last_update=last_update, now=now,
            healthy_seconds=int(config["healthy_seconds"]), stale_seconds=int(config["stale_seconds"]),
        )
        fields = device.get("fields", {}) if device else {}
        syslog_events = evidence["syslog"].get(node, [])
        trap_events = evidence["traps"].get(node, [])
        meta.update({
            "health": state,
            "health_reason": reason,
            "last_telemetry_timestamp": isoformat(last_update),
            "telemetry_age_seconds": round(age_seconds(last_update, now), 2) if last_update else None,
            "recent_critical_syslog_count": len(syslog_events),
            "recent_snmp_trap_count": len(trap_events),
            "latest_event_timestamp": isoformat(max(
                [item["timestamp"] for item in [*syslog_events, *trap_events]], default=None,
            )),
            "attention": bool(syslog_events or trap_events),
            "cpu_percent": fields.get("cpu_total_pct"),
            "memory_percent": _memory_percent(fields),
        })

    for source, target, meta in graph.edges(data=True):
        endpoints = [_endpoint_view(value, evidence, now, int(config["stale_seconds"])) for value in meta["endpoints"]]
        events: list[dict[str, Any]] = []
        for endpoint in endpoints:
            events.extend(evidence["link_events"].get((endpoint["node"], endpoint["monitor_interface"]), []))
        events.sort(key=lambda item: item["timestamp"])
        state, reason, state_source = classify_edge(endpoints, events, monitored_nodes)
        timestamps = [parse_time(item.get("last_update")) for item in endpoints if item.get("last_update")]
        timestamps.extend(item["timestamp"] for item in events)
        meta.update({
            "source": source,
            "target": target,
            "status": state,
            "health": state,
            "health_reason": reason,
            "status_source": state_source,
            "endpoint_state": endpoints,
            "last_state_update": isoformat(max(timestamps, default=None)),
            "recent_link_event_count": len(events),
            "latest_link_event": events[-1]["event_type"] if events else None,
            "latest_link_event_timestamp": isoformat(events[-1]["timestamp"]) if events else None,
        })

    demo_meta = {"active": False, "mode": "REAL", "label": "REAL MONITORING STATE", "target_edge": None}
    if demo:
        if demo != DEMO_MODE:
            raise ValueError("Unsupported demonstration mode")
        candidates = sorted(
            (
                meta for _, _, meta in graph.edges(data=True)
                if meta.get("plane") == "data"
                and all(endpoint["node"] in monitored_nodes for endpoint in meta["endpoints"])
            ),
            key=lambda item: item["id"],
        )
        if not candidates:
            raise ValueError("No fully monitored data-plane edge is available for the safe demonstration")
        target = candidates[0]
        target["real_status"] = target["status"]
        target["real_health_reason"] = target["health_reason"]
        target.update({
            "status": "DOWN", "health": "DOWN",
            "health_reason": "DEMO/SYNTHETIC overlay; no real interface or telemetry was changed",
            "status_source": "synthetic-demo-overlay", "synthetic": True,
        })
        demo_meta = {
            "active": True, "mode": "DEMO/SYNTHETIC",
            "label": "DEMO/SYNTHETIC — NO REAL NETWORK CHANGE",
            "target_edge": target["id"],
        }

    data = _node_link_data(graph)
    data["nodes"] = sorted(data["nodes"], key=lambda item: item["id"])
    data["edges"] = sorted(data["edges"], key=lambda item: item["id"])
    return {
        "schema_version": 1,
        "generated_at": isoformat(now),
        "refresh_interval_seconds": int(config["browser_refresh_seconds"]),
        "health_thresholds_seconds": {
            "healthy_max": int(config["healthy_seconds"]),
            "stale_max": int(config["stale_seconds"]),
        },
        "event_window_seconds": int(config["recent_event_window_seconds"]),
        "demo": demo_meta,
        "graph": data,
    }


def validate_graph_payload(payload: dict[str, Any]) -> None:
    graph = payload.get("graph", {})
    nodes, edges = graph.get("nodes", []), graph.get("edges", [])
    node_ids = [item.get("id") for item in nodes]
    edge_ids = [item.get("id") for item in edges]
    if len(node_ids) != len(set(node_ids)) or None in node_ids:
        raise ValueError("Graph contains duplicate or missing node identities")
    if len(edge_ids) != len(set(edge_ids)) or None in edge_ids:
        raise ValueError("Graph contains duplicate or missing edge identities")
    if not all(item.get("health") in NODE_STATES for item in nodes):
        raise ValueError("Graph contains an invalid node health state")
    if not all(item.get("status") in EDGE_STATES for item in edges):
        raise ValueError("Graph contains an invalid edge health state")
    if any(not math.isfinite(float(item.get(axis))) for item in nodes for axis in ("x", "y")):
        raise ValueError("Graph contains invalid layout coordinates")


class TopologyBuilder:
    def __init__(self, snapshot: dict[str, Any], config: dict[str, Any], influx: InfluxEvidence):
        self.snapshot = snapshot
        self.config = config
        self.influx = influx

    def build(self, *, demo: str | None = None) -> dict[str, Any]:
        now = utc_now()
        backend = {"status": "OK", "source": "InfluxDB existing network-monitoring bucket", "error": None}
        try:
            evidence = self.influx.collect(int(self.config["recent_event_window_seconds"]))
        except Exception as exc:  # keep the topology available, explicitly UNKNOWN
            evidence = empty_evidence()
            message = str(exc).replace(self.influx.token, "[REDACTED]")[:300]
            backend = {"status": "ERROR", "source": "InfluxDB existing network-monitoring bucket", "error": message}
        graph = build_base_graph(self.snapshot, int(self.config["layout_seed"]))
        payload = overlay_health(graph, evidence, self.config, now=now, demo=demo)
        payload["backend"] = backend
        payload["grafana_url"] = self.config.get("grafana_url")
        validate_graph_payload(payload)
        return payload
