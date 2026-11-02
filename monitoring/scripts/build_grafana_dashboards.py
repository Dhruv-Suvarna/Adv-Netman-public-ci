#!/usr/bin/env python3
"""Build deterministic, repository-owned Grafana dashboard JSON files."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from textwrap import dedent

BASE = Path(__file__).resolve().parents[1]
OUTPUT = BASE / "grafana/provisioning/dashboards/json"
BUCKET = "network-monitoring"  # Verified from the live datasource/bucket schema.
DATASOURCE = {"type": "influxdb", "uid": "nmas-influxdb"}


def flux(text: str) -> str:
    return dedent(text).strip()


def target(query: str, ref_id: str = "A") -> dict:
    return {
        "datasource": DATASOURCE,
        "query": flux(query),
        "refId": ref_id,
    }


def thresholds(*steps: tuple[str, float | None]) -> dict:
    return {"mode": "absolute", "steps": [{"color": color, "value": value} for color, value in steps]}


def panel(
    panel_id: int,
    title: str,
    kind: str,
    x: int,
    y: int,
    w: int,
    h: int,
    query: str,
    *,
    description: str = "",
    unit: str = "short",
    threshold_steps: tuple[tuple[str, float | None], ...] = (("green", None),),
    decimals: int | None = None,
    event_optional: bool = False,
) -> dict:
    """Build one panel dict.

    ``event_optional`` is the single, generator-owned declaration of whether
    this panel is allowed to legitimately return zero data rows (an event/
    notification/exception view that is empty during quiet, healthy
    operation) versus a metric/state panel that must always show a current
    value in a healthy system. It travels as a plain field on the panel JSON
    (ignored by Grafana itself) and is read directly back out of this same
    generated source by monitoring/tests/verify_grafana.py -- see
    docs/GRAFANA_MONITORING_TAXONOMY.md "Event-optional panel semantics" for
    the full reasoning. There is deliberately no separate hardcoded
    title-based allow-list anywhere else.
    """
    result = {
        "id": panel_id,
        "title": title,
        "description": description,
        "type": kind,
        "datasource": DATASOURCE,
        "eventOptional": event_optional,
        "gridPos": {"x": x, "y": y, "w": w, "h": h},
        "targets": [target(query)],
        "fieldConfig": {
            "defaults": {
                "color": {"mode": "thresholds" if kind in {"stat", "gauge", "bargauge"} else "palette-classic"},
                "unit": unit,
                "thresholds": thresholds(*threshold_steps),
                **({"decimals": decimals} if decimals is not None else {}),
            },
            "overrides": [],
        },
        "options": {},
    }
    if kind == "stat":
        result["options"] = {
            "colorMode": "value",
            "graphMode": "area",
            "justifyMode": "auto",
            "orientation": "auto",
            "reduceOptions": {"calcs": ["lastNotNull"], "fields": "", "values": False},
            "textMode": "auto",
        }
    elif kind == "bargauge":
        result["options"] = {
            "displayMode": "gradient",
            "minVizHeight": 10,
            "minVizWidth": 0,
            "namePlacement": "auto",
            "orientation": "horizontal",
            "reduceOptions": {"calcs": ["lastNotNull"], "fields": "", "values": False},
            "showUnfilled": True,
            "sizing": "auto",
            "valueMode": "color",
        }
    elif kind == "table":
        result["options"] = {"cellHeight": "sm", "showHeader": True, "sortBy": []}
        result["fieldConfig"]["defaults"]["custom"] = {"filterable": True}
    elif kind == "state-timeline":
        result["options"] = {
            "alignValue": "left",
            "mergeValues": True,
            "rowHeight": 0.9,
            "showValue": "auto",
            "legend": {"displayMode": "list", "placement": "bottom", "showLegend": True},
            "tooltip": {"mode": "single", "sort": "none"},
        }
    elif kind == "piechart":
        result["options"] = {
            "displayLabels": ["name", "percent"],
            "legend": {"displayMode": "table", "placement": "right", "showLegend": True, "values": ["value"]},
            "pieType": "pie",
            "reduceOptions": {"calcs": ["lastNotNull"], "fields": "", "values": True},
            "tooltip": {"mode": "single", "sort": "none"},
        }
    else:
        result["options"] = {
            "legend": {"calcs": ["lastNotNull", "max"], "displayMode": "table", "placement": "bottom", "showLegend": True},
            "tooltip": {"mode": "multi", "sort": "desc"},
        }
    return result


def query_variable(name: str, label: str, query: str, *, multi: bool = True) -> dict:
    return {
        "name": name,
        "label": label,
        "type": "query",
        "datasource": DATASOURCE,
        "query": flux(query),
        "definition": flux(query),
        "refresh": 2,
        "sort": 1,
        "multi": multi,
        "includeAll": multi,
        "allValue": ".*" if multi else None,
        "current": {"selected": True, "text": "All", "value": "$__all"} if multi else {},
        "hide": 0,
        "skipUrlSync": False,
    }


DEVICE_VAR = query_variable(
    "device",
    "Device",
    f'''from(bucket: "{BUCKET}")
      |> range(start: -30d)
      |> filter(fn: (r) => r._measurement == "gnmi_telemetry" and r.category == "system_identity" and r._field == "hostname")
      |> keep(columns: ["device"])
      |> group()
      |> distinct(column: "device")
      |> sort(columns: ["device"])''',
)

PLATFORM_VAR = query_variable(
    "platform",
    "Platform",
    f'''from(bucket: "{BUCKET}")
      |> range(start: -30d)
      |> filter(fn: (r) => r._measurement == "gnmi_telemetry" and r.category == "system_identity" and r._field == "hostname")
      |> keep(columns: ["platform"])
      |> group()
      |> distinct(column: "platform")
      |> sort(columns: ["platform"])''',
)

INTERFACE_VAR = query_variable(
    "interface",
    "Interface",
    f'''from(bucket: "{BUCKET}")
      |> range(start: -30d)
      |> filter(fn: (r) => r._measurement == "gnmi_telemetry" and r.category == "interface_state")
      |> filter(fn: (r) => r.device =~ /^${{device:regex}}$/ and r.platform =~ /^${{platform:regex}}$/)
      |> keep(columns: ["interface"])
      |> group()
      |> distinct(column: "interface")
      |> sort(columns: ["interface"])''',
)

SEVERITY_VAR = query_variable(
    "severity",
    "Severity",
    f'''from(bucket: "{BUCKET}")
      |> range(start: -30d)
      |> filter(fn: (r) => r._measurement == "syslog_event" and r._field == "message")
      |> keep(columns: ["severity"])
      |> group()
      |> distinct(column: "severity")
      |> sort(columns: ["severity"])''',
)

EVENT_TYPE_VAR = query_variable(
    "event_type",
    "Event type",
    f'''from(bucket: "{BUCKET}")
      |> range(start: -30d)
      |> filter(fn: (r) => r._measurement == "snmp_trap" and r._field == "value")
      |> keep(columns: ["event_type"])
      |> group()
      |> distinct(column: "event_type")
      |> sort(columns: ["event_type"])''',
)


def bool_variable(name: str, label: str, *, default: str = "false") -> dict:
    """A Grafana `custom` variable with two fixed text options, "false"/"true".

    The dashboard-JSON model used here (schemaVersion 40) has no native
    boolean variable type, so a two-option custom variable substituted as a
    plain string into a Flux `if`/comparison is the closest maintainable
    mechanism for a UI checkbox-like control. See
    docs/GRAFANA_MONITORING_TAXONOMY.md "Filter/variable design" for why this
    was chosen over alternatives.
    """
    options = ["false", "true"]
    return {
        "name": name,
        "label": label,
        "type": "custom",
        "query": ",".join(options),
        "options": [{"text": o, "value": o, "selected": o == default} for o in options],
        "current": {"text": default, "value": default, "selected": True},
        "hide": 0,
        "multi": False,
        "includeAll": False,
        "skipUrlSync": False,
    }


def dashboard(uid: str, title: str, description: str, variables: list[dict], panels: list[dict], *, start: str, extra_tags: tuple[str, ...] = ()) -> dict:
    return {
        "id": None,
        "uid": uid,
        "title": title,
        "description": description,
        "tags": ["nmas", "network-monitoring", "iac", *extra_tags],
        "timezone": "browser",
        "editable": False,
        "fiscalYearStartMonth": 0,
        "graphTooltip": 1,
        "links": [],
        "liveNow": True,
        "panels": panels,
        "refresh": "20s",
        "schemaVersion": 40,
        "templating": {"list": variables},
        "time": {"from": start, "to": "now"},
        "timepicker": {"refresh_intervals": ["10s", "20s", "30s", "1m", "5m"]},
        "version": 1,
        "weekStart": "",
    }


def fleet_dashboard() -> dict:
    panels = [
        panel(1, "Devices reporting (5m)", "stat", 0, 0, 4, 4, f'''from(bucket: "{BUCKET}")
          |> range(start: -5m)
          |> filter(fn: (r) => r._measurement == "gnmi_telemetry" and r.category == "system_identity" and r._field == "hostname")
          |> filter(fn: (r) => r.device =~ /^${{device:regex}}$/ and r.platform =~ /^${{platform:regex}}$/)
          |> group()
          |> unique(column: "device")
          |> count(column: "device")
          |> rename(columns: {{device: "_value"}})''', description="Count of devices with a real hostname telemetry sample in the last five minutes. Missing data is not treated as UP.", threshold_steps=(("red", None), ("orange", 1), ("green", 10))),
        panel(2, "Interfaces currently down", "stat", 4, 0, 4, 4, f'''from(bucket: "{BUCKET}")
          |> range(start: -15m)
          |> filter(fn: (r) => r._measurement == "gnmi_telemetry" and r.category == "interface_state" and r._field == "oper_status")
          |> filter(fn: (r) => r.device =~ /^${{device:regex}}$/ and r.platform =~ /^${{platform:regex}}$/)
          |> group(columns: ["device", "interface"])
          |> last()
          |> map(fn: (r) => ({{r with _value: if r._value == "UP" then 0 else 1}}))
          |> group()
          |> sum()''', description="Latest observed operational state. A missing series is not converted to UP.", threshold_steps=(("green", None), ("red", 1))),
        panel(3, "Critical syslog events", "stat", 8, 0, 4, 4, f'''from(bucket: "{BUCKET}")
          |> range(start: v.timeRangeStart, stop: v.timeRangeStop)
          |> filter(fn: (r) => r._measurement == "syslog_event" and r._field == "message")
          |> map(fn: (r) => ({{r with device: if r.device == "mgmt-swt" then "mgmt_swt" else r.device}}))
          |> filter(fn: (r) => r.device =~ /^${{device:regex}}$/)
          |> group()
          |> count()''', description="Critical-or-worse events in the selected dashboard time range.", threshold_steps=(("green", None), ("red", 1)), event_optional=True),
        panel(4, "SNMP traps", "stat", 12, 0, 4, 4, f'''from(bucket: "{BUCKET}")
          |> range(start: v.timeRangeStart, stop: v.timeRangeStop)
          |> filter(fn: (r) => r._measurement == "snmp_trap" and r._field == "value")
          |> filter(fn: (r) => r.device =~ /^${{device:regex}}$/)
          |> group()
          |> count()''', description="Authenticated SNMPv3 notifications received in the selected time range.", threshold_steps=(("green", None), ("orange", 1), ("red", 10)), event_optional=True),
        panel(5, "Latest CPU by device", "bargauge", 16, 0, 4, 4, f'''from(bucket: "{BUCKET}")
          |> range(start: v.timeRangeStart, stop: v.timeRangeStop)
          |> filter(fn: (r) => r._measurement == "gnmi_telemetry" and r.category == "system_cpu" and r._field == "cpu_total_pct")
          |> filter(fn: (r) => r.device =~ /^${{device:regex}}$/ and r.platform =~ /^${{platform:regex}}$/)
          |> group(columns: ["device"])
          |> aggregateWindow(every: 1m, fn: mean, createEmpty: false)
          |> last()''', unit="percent", threshold_steps=(("green", None), ("orange", 70), ("red", 90)), decimals=1),
        panel(6, "Worst telemetry age", "stat", 20, 0, 4, 4, f'''from(bucket: "{BUCKET}")
          |> range(start: -30d)
          |> filter(fn: (r) => r._measurement == "gnmi_telemetry" and r.category == "system_identity" and r._field == "hostname")
          |> filter(fn: (r) => r.device =~ /^${{device:regex}}$/ and r.platform =~ /^${{platform:regex}}$/)
          |> group(columns: ["device"])
          |> last()
          |> map(fn: (r) => ({{r with _value: float(v: int(v: now()) - int(v: r._time)) / 1000000000.0}}))
          |> group()
          |> max()''', description="Age of the stalest last-received identity sample. Green <60s, amber 60-120s, red >120s.", unit="s", threshold_steps=(("green", None), ("orange", 60), ("red", 120)), decimals=1),
        panel(7, "Per-device telemetry health", "table", 0, 4, 12, 8, f'''from(bucket: "{BUCKET}")
          |> range(start: -30d)
          |> filter(fn: (r) => r._measurement == "gnmi_telemetry" and r.category == "system_identity" and r._field == "hostname")
          |> filter(fn: (r) => r.device =~ /^${{device:regex}}$/ and r.platform =~ /^${{platform:regex}}$/)
          |> group(columns: ["device", "platform"])
          |> last()
          |> map(fn: (r) => ({{r with age_seconds: float(v: int(v: now()) - int(v: r._time)) / 1000000000.0, status: if int(v: now()) - int(v: r._time) < 60000000000 then "HEALTHY" else if int(v: now()) - int(v: r._time) < 120000000000 then "STALE" else "OFFLINE"}}))
          |> keep(columns: ["device", "platform", "_time", "age_seconds", "status"])
          |> group()
          |> sort(columns: ["device"])''', description="Health is based only on observed telemetry age; absent devices are never fabricated as healthy.", unit="short"),
        panel(8, "Current non-UP interfaces", "table", 12, 4, 12, 8, f'''from(bucket: "{BUCKET}")
          |> range(start: -15m)
          |> filter(fn: (r) => r._measurement == "gnmi_telemetry" and r.category == "interface_state" and (r._field == "admin_status" or r._field == "oper_status"))
          |> filter(fn: (r) => r.device =~ /^${{device:regex}}$/ and r.platform =~ /^${{platform:regex}}$/)
          |> group(columns: ["device", "platform", "interface", "_field"])
          |> last()
          |> group(columns: ["device", "platform", "interface"])
          |> pivot(rowKey: ["device", "platform", "interface"], columnKey: ["_field"], valueColumn: "_value")
          |> filter(fn: (r) => (exists r.oper_status and r.oper_status != "UP") or (exists r.admin_status and r.admin_status != "UP"))
          |> group()
          |> sort(columns: ["device", "interface"])''', description="Only interfaces whose latest observed admin or operational state is not UP. An empty table plus a zero count above means no observed down state.", event_optional=True),
        panel(9, "CPU utilization", "timeseries", 0, 12, 12, 8, f'''from(bucket: "{BUCKET}")
          |> range(start: v.timeRangeStart, stop: v.timeRangeStop)
          |> filter(fn: (r) => r._measurement == "gnmi_telemetry" and r.category == "system_cpu" and r._field == "cpu_total_pct")
          |> filter(fn: (r) => r.device =~ /^${{device:regex}}$/ and r.platform =~ /^${{platform:regex}}$/)
          |> group(columns: ["device"])
          |> aggregateWindow(every: v.windowPeriod, fn: mean, createEmpty: false)''', unit="percent", threshold_steps=(("green", None), ("orange", 70), ("red", 90)), decimals=1),
        panel(10, "Memory utilization", "timeseries", 12, 12, 12, 8, f'''from(bucket: "{BUCKET}")
          |> range(start: v.timeRangeStart, stop: v.timeRangeStop)
          |> filter(fn: (r) => r._measurement == "gnmi_telemetry" and r.category == "system_memory" and (r._field == "mem_used_bytes" or r._field == "mem_physical_bytes"))
          |> filter(fn: (r) => r.device =~ /^${{device:regex}}$/ and r.platform =~ /^${{platform:regex}}$/)
          |> pivot(rowKey: ["_time", "device", "platform"], columnKey: ["_field"], valueColumn: "_value")
          |> filter(fn: (r) => exists r.mem_physical_bytes and exists r.mem_used_bytes and r.mem_physical_bytes > 0)
          |> map(fn: (r) => ({{r with _value: 100.0 * float(v: r.mem_used_bytes) / float(v: r.mem_physical_bytes)}}))
          |> group(columns: ["device"])
          |> aggregateWindow(every: v.windowPeriod, fn: mean, createEmpty: false)''', unit="percent", threshold_steps=(("green", None), ("orange", 75), ("red", 90)), decimals=1),
        panel(11, "Recent linkDown notifications", "table", 0, 20, 12, 8, f'''from(bucket: "{BUCKET}")
          |> range(start: v.timeRangeStart, stop: v.timeRangeStop)
          |> filter(fn: (r) => r._measurement == "snmp_trap" and r._field == "raw_varbinds" and r.event_type == "linkDown")
          |> filter(fn: (r) => r.device =~ /^${{device:regex}}$/)
          |> map(fn: (r) => ({{r with ifindex: if exists r.ifindex then r.ifindex else "-"}}))
          |> keep(columns: ["_time", "device", "source_ip", "severity", "ifindex", "notification_oid", "_value"])
          |> rename(columns: {{_value: "raw_varbinds"}})
          |> group()
          |> sort(columns: ["_time"], desc: true)
          |> limit(n: 100)''', description="Stored authenticated linkDown notifications. Historical safe dummy-interface evidence remains visible when it falls within the selected range.", event_optional=True),
        panel(12, "Recent critical syslog", "table", 12, 20, 12, 8, f'''from(bucket: "{BUCKET}")
          |> range(start: v.timeRangeStart, stop: v.timeRangeStop)
          |> filter(fn: (r) => r._measurement == "syslog_event" and r._field == "message")
          |> map(fn: (r) => ({{r with device: if r.device == "mgmt-swt" then "mgmt_swt" else r.device, platform: if exists r.platform then r.platform else "unknown"}}))
          |> filter(fn: (r) => r.device =~ /^${{device:regex}}$/)
          |> keep(columns: ["_time", "device", "platform", "source_ip", "severity", "facility", "_value"])
          |> rename(columns: {{_value: "message"}})
          |> group()
          |> sort(columns: ["_time"], desc: true)
          |> limit(n: 100)''', description="Critical-or-worse events only, matching the deployed centralized logging policy.", event_optional=True),
    ]
    return dashboard(
        "nmas-fleet-overview",
        "NMAS Network Health Overview",
        "Fleet health across the 10 monitored routers/switches using observed gNMI, SNMP, and critical syslog data. R3/R4 telemetry is supplied by the documented read-only Linux adapter; all other devices use native cEOS services. Legacy/compatibility dashboard: superseded for new (Django) consumers by the canonical NMAS Resources dashboard (nmas-resources), retained unchanged for existing links.",
        [DEVICE_VAR, PLATFORM_VAR],
        panels,
        start="now-6h",
        extra_tags=("legacy",),
    )


def telemetry_dashboard() -> dict:
    filters = 'r.device =~ /^${device:regex}$/ and r.platform =~ /^${platform:regex}$/'
    interface_filter = filters + ' and r.interface =~ /^${interface:regex}$/'
    panels = [
        panel(1, "Telemetry freshness by device", "table", 0, 0, 8, 6, f'''from(bucket: "{BUCKET}")
          |> range(start: -30d)
          |> filter(fn: (r) => r._measurement == "gnmi_telemetry" and r.category == "system_identity" and r._field == "hostname")
          |> filter(fn: (r) => {filters})
          |> group(columns: ["device", "platform"])
          |> last()
          |> map(fn: (r) => ({{r with age_seconds: float(v: int(v: now()) - int(v: r._time)) / 1000000000.0, source: if r.platform == "linux" then "Linux read-only adapter" else "native cEOS gNMI"}}))
          |> keep(columns: ["device", "platform", "source", "_time", "age_seconds"])
          |> group()
          |> sort(columns: ["device"])''', description="Source column deliberately exposes the native cEOS versus R3/R4 adapter distinction."),
        panel(2, "Latest CPU", "bargauge", 8, 0, 8, 6, f'''from(bucket: "{BUCKET}")
          |> range(start: v.timeRangeStart, stop: v.timeRangeStop)
          |> filter(fn: (r) => r._measurement == "gnmi_telemetry" and r.category == "system_cpu" and r._field == "cpu_total_pct")
          |> filter(fn: (r) => {filters})
          |> group(columns: ["device"])
          |> aggregateWindow(every: 1m, fn: mean, createEmpty: false)
          |> last()''', unit="percent", threshold_steps=(("green", None), ("orange", 70), ("red", 90)), decimals=1),
        panel(3, "Current non-UP interfaces", "table", 16, 0, 8, 6, f'''from(bucket: "{BUCKET}")
          |> range(start: -15m)
          |> filter(fn: (r) => r._measurement == "gnmi_telemetry" and r.category == "interface_state" and (r._field == "admin_status" or r._field == "oper_status"))
          |> filter(fn: (r) => {interface_filter})
          |> group(columns: ["device", "platform", "interface", "_field"])
          |> last()
          |> group(columns: ["device", "platform", "interface"])
          |> pivot(rowKey: ["device", "platform", "interface"], columnKey: ["_field"], valueColumn: "_value")
          |> filter(fn: (r) => (exists r.oper_status and r.oper_status != "UP") or (exists r.admin_status and r.admin_status != "UP"))
          |> group()''', description="Shows only observed non-UP states; no result is fabricated for absent telemetry.", event_optional=True),
        panel(4, "CPU utilization", "timeseries", 0, 6, 12, 8, f'''from(bucket: "{BUCKET}")
          |> range(start: v.timeRangeStart, stop: v.timeRangeStop)
          |> filter(fn: (r) => r._measurement == "gnmi_telemetry" and r.category == "system_cpu" and r._field == "cpu_total_pct")
          |> filter(fn: (r) => {filters})
          |> group(columns: ["device"])
          |> aggregateWindow(every: v.windowPeriod, fn: mean, createEmpty: false)''', unit="percent", threshold_steps=(("green", None), ("orange", 70), ("red", 90)), decimals=1),
        panel(5, "Memory utilization", "timeseries", 12, 6, 12, 8, f'''from(bucket: "{BUCKET}")
          |> range(start: v.timeRangeStart, stop: v.timeRangeStop)
          |> filter(fn: (r) => r._measurement == "gnmi_telemetry" and r.category == "system_memory" and (r._field == "mem_used_bytes" or r._field == "mem_physical_bytes"))
          |> filter(fn: (r) => {filters})
          |> pivot(rowKey: ["_time", "device", "platform"], columnKey: ["_field"], valueColumn: "_value")
          |> filter(fn: (r) => exists r.mem_physical_bytes and exists r.mem_used_bytes and r.mem_physical_bytes > 0)
          |> map(fn: (r) => ({{r with _value: 100.0 * float(v: r.mem_used_bytes) / float(v: r.mem_physical_bytes)}}))
          |> group(columns: ["device"])
          |> aggregateWindow(every: v.windowPeriod, fn: mean, createEmpty: false)''', unit="percent", threshold_steps=(("green", None), ("orange", 75), ("red", 90)), decimals=1),
        panel(6, "Interface operational state", "state-timeline", 0, 14, 12, 9, f'''from(bucket: "{BUCKET}")
          |> range(start: v.timeRangeStart, stop: v.timeRangeStop)
          |> filter(fn: (r) => r._measurement == "gnmi_telemetry" and r.category == "interface_state" and r._field == "oper_status")
          |> filter(fn: (r) => {interface_filter})
          |> keep(columns: ["_time", "_value", "device", "interface"])
          |> group(columns: ["device", "interface"])''', description="Actual sampled OpenConfig operational state."),
        panel(7, "Interface administrative state", "state-timeline", 12, 14, 12, 9, f'''from(bucket: "{BUCKET}")
          |> range(start: v.timeRangeStart, stop: v.timeRangeStop)
          |> filter(fn: (r) => r._measurement == "gnmi_telemetry" and r.category == "interface_state" and r._field == "admin_status")
          |> filter(fn: (r) => {interface_filter})
          |> keep(columns: ["_time", "_value", "device", "interface"])
          |> group(columns: ["device", "interface"])''', description="Actual sampled OpenConfig administrative state."),
        panel(8, "Interface traffic rate", "timeseries", 0, 23, 12, 9, f'''from(bucket: "{BUCKET}")
          |> range(start: v.timeRangeStart, stop: v.timeRangeStop)
          |> filter(fn: (r) => r._measurement == "gnmi_telemetry" and r.category == "interface_counters" and (r._field == "in_octets" or r._field == "out_octets"))
          |> filter(fn: (r) => {interface_filter})
          |> group(columns: ["device", "interface", "_field"])
          |> derivative(unit: 1s, nonNegative: true)
          |> map(fn: (r) => ({{r with _value: r._value * 8.0}}))''', description="Non-negative derivative of streamed octet counters, converted to bits per second.", unit="bps", decimals=1),
        panel(9, "Error and discard rate", "timeseries", 12, 23, 12, 9, f'''from(bucket: "{BUCKET}")
          |> range(start: v.timeRangeStart, stop: v.timeRangeStop)
          |> filter(fn: (r) => r._measurement == "gnmi_telemetry" and r.category == "interface_counters" and (r._field == "in_errors" or r._field == "out_errors" or r._field == "in_discards" or r._field == "out_discards"))
          |> filter(fn: (r) => {interface_filter})
          |> group(columns: ["device", "interface", "_field"])
          |> derivative(unit: 1s, nonNegative: true)''', description="Counter derivatives. Any sustained value above zero deserves investigation.", unit="ops", threshold_steps=(("green", None), ("red", 0.001)), decimals=3),
        panel(10, "Latest interface counters", "table", 0, 32, 24, 9, f'''from(bucket: "{BUCKET}")
          |> range(start: -15m)
          |> filter(fn: (r) => r._measurement == "gnmi_telemetry" and r.category == "interface_counters")
          |> filter(fn: (r) => {interface_filter})
          |> group(columns: ["device", "platform", "interface", "_field"])
          |> last()
          |> group(columns: ["device", "platform", "interface"])
          |> pivot(rowKey: ["device", "platform", "interface"], columnKey: ["_field"], valueColumn: "_value")
          |> group()
          |> sort(columns: ["device", "interface"])''', description="Latest raw octet/error/discard counters. Packet counters are not stored by the current collector and are intentionally not fabricated."),
        panel(11, "Latest NETCONF RPC snapshots", "table", 0, 41, 24, 7, f'''from(bucket: "{BUCKET}")
          |> range(start: -30d)
          |> filter(fn: (r) => r._measurement == "netconf_snapshot" and r._field == "interface_count")
          |> filter(fn: (r) => {filters})
          |> group(columns: ["device", "platform"])
          |> last()
          |> map(fn: (r) => ({{r with snapshot_age_seconds: float(v: int(v: now()) - int(v: r._time)) / 1000000000.0}}))
          |> keep(columns: ["device", "platform", "_time", "snapshot_age_seconds", "_value"])
          |> rename(columns: {{_value: "interface_count"}})
          |> group()
          |> sort(columns: ["device"])''', description="Discrete read-only NETCONF <get> verification snapshots, not streaming telemetry. The age normally advances until the next telemetry verification run."),
    ]
    return dashboard(
        "nmas-streaming-telemetry",
        "NMAS Streaming Telemetry",
        "Real gNMI STREAM+SAMPLE data. cEOS devices are native endpoints; R3/R4 use the documented read-only Linux telemetry adapter. The current schema stores octets, errors, and discards but not packet counters. Legacy/compatibility dashboard: superseded for new (Django) consumers by the canonical NMAS Link State & Traffic dashboard (nmas-link-state-traffic), retained unchanged for existing links.",
        [DEVICE_VAR, PLATFORM_VAR, INTERFACE_VAR],
        panels,
        start="now-3h",
        extra_tags=("legacy",),
    )


def snmp_dashboard() -> dict:
    panels = [
        panel(1, "SNMP poll freshness", "table", 0, 0, 8, 6, f'''from(bucket: "{BUCKET}")
          |> range(start: -30d)
          |> filter(fn: (r) => r._measurement == "snmp_poll" and r.metric == "sysUpTime" and r._field == "value")
          |> filter(fn: (r) => r.device =~ /^${{device:regex}}$/)
          |> group(columns: ["device", "platform", "management_ip"])
          |> last()
          |> map(fn: (r) => ({{r with uptime_seconds: float(v: r._value) / 100.0, poll_age_seconds: float(v: int(v: now()) - int(v: r._time)) / 1000000000.0}}))
          |> keep(columns: ["device", "platform", "management_ip", "_time", "poll_age_seconds", "uptime_seconds"])
          |> group()
          |> sort(columns: ["device"])''', description="Last stored SNMP poll and device uptime. Polling is run by the verification workflow, not a background scheduler."),
        panel(2, "Latest polled CPU", "bargauge", 8, 0, 8, 6, f'''from(bucket: "{BUCKET}")
          |> range(start: v.timeRangeStart, stop: v.timeRangeStop)
          |> filter(fn: (r) => r._measurement == "snmp_poll" and r.metric == "cpu" and r._field == "value")
          |> filter(fn: (r) => r.device =~ /^${{device:regex}}$/)
          |> group(columns: ["device"])
          |> aggregateWindow(every: 5m, fn: mean, createEmpty: false)
          |> last()''', unit="percent", threshold_steps=(("green", None), ("orange", 70), ("red", 90)), decimals=1),
        panel(3, "Traps received", "stat", 16, 0, 4, 6, f'''from(bucket: "{BUCKET}")
          |> range(start: v.timeRangeStart, stop: v.timeRangeStop)
          |> filter(fn: (r) => r._measurement == "snmp_trap" and r._field == "value")
          |> filter(fn: (r) => r.device =~ /^${{device:regex}}$/)
          |> group()
          |> count()''', description="Authenticated SNMPv3 notifications in the selected range.", threshold_steps=(("green", None), ("orange", 1), ("red", 10)), event_optional=True),
        panel(4, "Current IF-MIB down", "stat", 20, 0, 4, 6, f'''from(bucket: "{BUCKET}")
          |> range(start: -30d)
          |> filter(fn: (r) => r._measurement == "snmp_poll" and r.metric == "ifOperStatus" and r._field == "value")
          |> filter(fn: (r) => r.device =~ /^${{device:regex}}$/)
          |> group(columns: ["device", "interface"])
          |> last()
          |> map(fn: (r) => ({{r with _value: if r._value == 1 then 0 else 1}}))
          |> group()
          |> sum()''', description="Latest polled IF-MIB operational state; 1=UP, every other standard state is counted non-UP.", threshold_steps=(("green", None), ("red", 1))),
        panel(5, "Polled CPU utilization", "timeseries", 0, 6, 12, 8, f'''from(bucket: "{BUCKET}")
          |> range(start: v.timeRangeStart, stop: v.timeRangeStop)
          |> filter(fn: (r) => r._measurement == "snmp_poll" and r.metric == "cpu" and r._field == "value")
          |> filter(fn: (r) => r.device =~ /^${{device:regex}}$/)
          |> group(columns: ["device"])
          |> aggregateWindow(every: v.windowPeriod, fn: mean, createEmpty: false)''', description="Mean HOST-RESOURCES-MIB processor load across reported logical processor indexes.", unit="percent", threshold_steps=(("green", None), ("orange", 70), ("red", 90)), decimals=1),
        panel(6, "Trap volume over time", "timeseries", 12, 6, 12, 8, f'''from(bucket: "{BUCKET}")
          |> range(start: v.timeRangeStart, stop: v.timeRangeStop)
          |> filter(fn: (r) => r._measurement == "snmp_trap" and r._field == "value")
          |> filter(fn: (r) => r.device =~ /^${{device:regex}}$/)
          |> group(columns: ["device"])
          |> aggregateWindow(every: v.windowPeriod, fn: count, createEmpty: false)''', description="Received notification count per dashboard interval.", unit="short", event_optional=True),
        panel(7, "Latest IF-MIB state", "table", 0, 14, 12, 9, f'''from(bucket: "{BUCKET}")
          |> range(start: -30d)
          |> filter(fn: (r) => r._measurement == "snmp_poll" and (r.metric == "ifAdminStatus" or r.metric == "ifOperStatus") and r._field == "value")
          |> filter(fn: (r) => r.device =~ /^${{device:regex}}$/)
          |> group(columns: ["device", "platform", "interface", "ifindex", "metric"])
          |> last()
          |> group(columns: ["device", "platform", "interface", "ifindex"])
          |> pivot(rowKey: ["device", "platform", "interface", "ifindex"], columnKey: ["metric"], valueColumn: "_value")
          |> group()
          |> sort(columns: ["device", "interface"])''', description="IF-MIB integer state values: 1 up, 2 down, 3 testing; operational states may also use 4-7 per IF-MIB."),
        panel(8, "Trap types", "bargauge", 12, 14, 12, 9, f'''from(bucket: "{BUCKET}")
          |> range(start: v.timeRangeStart, stop: v.timeRangeStop)
          |> filter(fn: (r) => r._measurement == "snmp_trap" and r._field == "value")
          |> filter(fn: (r) => r.device =~ /^${{device:regex}}$/)
          |> group(columns: ["event_type"])
          |> count()''', description="Includes linkUp/linkDown and explicitly labelled cEOS safe test notifications.", threshold_steps=(("green", None), ("orange", 1), ("red", 10)), event_optional=True),
        panel(9, "Recent SNMP notifications", "table", 0, 23, 24, 10, f'''from(bucket: "{BUCKET}")
          |> range(start: v.timeRangeStart, stop: v.timeRangeStop)
          |> filter(fn: (r) => r._measurement == "snmp_trap" and r._field == "raw_varbinds")
          |> filter(fn: (r) => r.device =~ /^${{device:regex}}$/)
          |> map(fn: (r) => ({{r with ifindex: if exists r.ifindex then r.ifindex else "-"}}))
          |> keep(columns: ["_time", "device", "source_ip", "event_type", "severity", "ifindex", "notification_oid", "_value"])
          |> rename(columns: {{_value: "raw_varbinds"}})
          |> group()
          |> sort(columns: ["_time"], desc: true)
          |> limit(n: 200)''', description="Event time, canonical device/source, notification class/OID, optional interface index, and decoded varbinds. CPU values are polled; no native CPU trap is claimed.", event_optional=True),
        panel(10, "NMAS Collector CPU Alerts", "table", 0, 33, 24, 9, f'''from(bucket: "{BUCKET}")
          |> range(start: v.timeRangeStart, stop: v.timeRangeStop)
          |> filter(fn: (r) => r._measurement == "collector_alert" and r.alert_type == "cpu_threshold")
          |> filter(fn: (r) => r.device =~ /^${{device:regex}}$/)
          |> filter(fn: (r) => r._field == "cpu_value" or r._field == "threshold_pct" or r._field == "consecutive_samples" or r._field == "previous_state")
          |> pivot(rowKey: ["_time", "device", "source", "severity", "transition", "monitoring_method", "verification"], columnKey: ["_field"], valueColumn: "_value")
          |> group()
          |> sort(columns: ["_time"], desc: true)
          |> limit(n: 200)''', description="NMAS/collector-generated CPU threshold events derived from repeated real SNMP CPU polls (measurement collector_alert, source=collector) -- distinct from the device-originated SNMP notifications above (measurement snmp_trap). Never implies a device-emitted CPU trap. verification=true rows are the safe, clearly-labelled deterministic self-test evidence.", event_optional=True),
    ]
    return dashboard(
        "nmas-snmp-monitoring",
        "NMAS SNMP Monitoring",
        "SNMPv3 authPriv polling and notification views. CPU comes from verified HOST-RESOURCES-MIB polling; trap panels show actual stored notifications and do not imply a native CPU threshold trap. Legacy/compatibility dashboard: its resource panels are superseded by NMAS Resources (nmas-resources) and its trap panels by NMAS Link Events (nmas-link-events); retained unchanged for existing links.",
        [DEVICE_VAR],
        panels,
        start="now-24h",
        extra_tags=("legacy",),
    )


def syslog_dashboard() -> dict:
    device_query = f'''from(bucket: "{BUCKET}")
      |> range(start: -30d)
      |> filter(fn: (r) => r._measurement == "syslog_event" and r._field == "message")
      |> map(fn: (r) => ({{r with device: if r.device == "mgmt-swt" then "mgmt_swt" else r.device}}))
      |> keep(columns: ["device"])
      |> group()
      |> distinct(column: "device")
      |> sort(columns: ["device"])'''
    severity_query = f'''from(bucket: "{BUCKET}")
      |> range(start: -30d)
      |> filter(fn: (r) => r._measurement == "syslog_event" and r._field == "message")
      |> keep(columns: ["severity"])
      |> group()
      |> distinct(column: "severity")
      |> sort(columns: ["severity"])'''
    syslog_device = query_variable("device", "Device", device_query)
    severity = query_variable("severity", "Severity", severity_query)
    normalize = 'map(fn: (r) => ({r with device: if r.device == "mgmt-swt" then "mgmt_swt" else r.device, platform: if exists r.platform then r.platform else "unknown"}))'
    panels = [
        panel(1, "Critical events", "stat", 0, 0, 6, 5, f'''from(bucket: "{BUCKET}")
          |> range(start: v.timeRangeStart, stop: v.timeRangeStop)
          |> filter(fn: (r) => r._measurement == "syslog_event" and r._field == "message")
          |> {normalize}
          |> filter(fn: (r) => r.device =~ /^${{device:regex}}$/ and r.severity =~ /^${{severity:regex}}$/)
          |> group()
          |> count()''', description="The deployed policy forwards emergency, alert, and critical only; current stored data is critical severity.", threshold_steps=(("green", None), ("red", 1)), event_optional=True),
        panel(2, "Events by device", "bargauge", 6, 0, 10, 5, f'''from(bucket: "{BUCKET}")
          |> range(start: v.timeRangeStart, stop: v.timeRangeStop)
          |> filter(fn: (r) => r._measurement == "syslog_event" and r._field == "message")
          |> {normalize}
          |> filter(fn: (r) => r.device =~ /^${{device:regex}}$/ and r.severity =~ /^${{severity:regex}}$/)
          |> group(columns: ["device"])
          |> count()''', threshold_steps=(("green", None), ("orange", 1), ("red", 10)), event_optional=True),
        panel(3, "Severity distribution", "piechart", 16, 0, 8, 5, f'''from(bucket: "{BUCKET}")
          |> range(start: v.timeRangeStart, stop: v.timeRangeStop)
          |> filter(fn: (r) => r._measurement == "syslog_event" and r._field == "message")
          |> {normalize}
          |> filter(fn: (r) => r.device =~ /^${{device:regex}}$/ and r.severity =~ /^${{severity:regex}}$/)
          |> group(columns: ["severity"])
          |> count()''', description="Only severities admitted by the centralized critical-event policy can appear.", event_optional=True),
        panel(4, "Critical event volume over time", "timeseries", 0, 5, 16, 9, f'''from(bucket: "{BUCKET}")
          |> range(start: v.timeRangeStart, stop: v.timeRangeStop)
          |> filter(fn: (r) => r._measurement == "syslog_event" and r._field == "message")
          |> {normalize}
          |> filter(fn: (r) => r.device =~ /^${{device:regex}}$/ and r.severity =~ /^${{severity:regex}}$/)
          |> group(columns: ["device"])
          |> aggregateWindow(every: v.windowPeriod, fn: count, createEmpty: false)''', description="Count of stored events by device and time interval.", event_optional=True),
        panel(5, "Facilities", "bargauge", 16, 5, 8, 9, f'''from(bucket: "{BUCKET}")
          |> range(start: v.timeRangeStart, stop: v.timeRangeStop)
          |> filter(fn: (r) => r._measurement == "syslog_event" and r._field == "message")
          |> {normalize}
          |> filter(fn: (r) => r.device =~ /^${{device:regex}}$/ and r.severity =~ /^${{severity:regex}}$/)
          |> group(columns: ["facility"])
          |> count()''', threshold_steps=(("green", None), ("orange", 1), ("red", 10)), event_optional=True),
        panel(6, "Recent critical events", "table", 0, 14, 24, 13, f'''from(bucket: "{BUCKET}")
          |> range(start: v.timeRangeStart, stop: v.timeRangeStop)
          |> filter(fn: (r) => r._measurement == "syslog_event" and r._field == "message")
          |> {normalize}
          |> filter(fn: (r) => r.device =~ /^${{device:regex}}$/ and r.severity =~ /^${{severity:regex}}$/)
          |> keep(columns: ["_time", "device", "platform", "source_ip", "severity", "facility", "_value"])
          |> rename(columns: {{_value: "message"}})
          |> group()
          |> sort(columns: ["_time"], desc: true)
          |> limit(n: 500)''', description="Search/filter the table by device, source, severity, facility, or message. Historical mgmt-swt records are normalized to the canonical mgmt_swt device name.", event_optional=True),
    ]
    return dashboard(
        "nmas-critical-syslog",
        "NMAS Critical Syslog",
        "Centralized critical-or-worse syslog only. Lower-severity data is intentionally absent because it is filtered at the device, not because the dashboard hides it. Legacy/compatibility dashboard: superseded for new (Django) consumers by the syslog panels on NMAS Resources (nmas-resources) and NMAS Link Events (nmas-link-events), retained unchanged for existing links.",
        [syslog_device, severity],
        panels,
        start="now-24h",
        extra_tags=("legacy",),
    )


def basic_filters(*, interface: bool = False) -> str:
    """Common device/platform[/interface] regex filter clause shared by the
    canonical dashboards. Kept as one function so the three canonical
    dashboards below never hand-copy this text independently."""
    clause = "r.device =~ /^${device:regex}$/ and r.platform =~ /^${platform:regex}$/"
    if interface:
        clause += " and r.interface =~ /^${interface:regex}$/"
    return clause


def link_state_filters() -> str:
    """Interface filter for the Link State & Traffic canonical dashboard:
    device/platform/interface plus the include_mgmt/include_loopback custom
    variables. "Management" interfaces are identified by the real observed
    names Management0 (cEOS) and Vlan200 (the frozen management SVI on every
    other cEOS device and the tag used for R1-R4's management identity, per
    inventory.yml); loopback interfaces by the real observed name "lo"
    (Linux) or an IF-MIB "Loopback*" name (cEOS convention, none currently
    provisioned in this lab). R3/R4 carry their management traffic on a
    numbered 802.1Q subinterface (e.g. eth1.10x) whose name does not
    self-describe a management role, so this pattern-based exclusion is not
    reliably honest for those two devices -- documented as a known
    limitation in docs/GRAFANA_MONITORING_TAXONOMY.md rather than guessed.
    """
    return (
        basic_filters(interface=True)
        + ' and ("${include_mgmt}" == "true" or not (r.interface =~ /^(Management|Vlan200)/))'
        + ' and ("${include_loopback}" == "true" or not (r.interface == "lo" or r.interface =~ /^Loopback/))'
    )


def recent_critical_syslog_panel(panel_id: int, x: int, y: int, w: int, h: int, *, title: str = "Recent critical syslog") -> dict:
    """Shared critical-syslog table used by both NMAS Resources and NMAS
    Link Events. syslog_event carries no topic tag distinguishing
    resource-related from interface/link-related messages, so both pages
    honestly show the same full critical-or-worse feed for the selected
    device/severity rather than a fabricated topic-specific split -- see
    docs/GRAFANA_MONITORING_TAXONOMY.md "Known limitations"."""
    return panel(panel_id, title, "table", x, y, w, h, f'''from(bucket: "{BUCKET}")
      |> range(start: v.timeRangeStart, stop: v.timeRangeStop)
      |> filter(fn: (r) => r._measurement == "syslog_event" and r._field == "message")
      |> map(fn: (r) => ({{r with device: if r.device == "mgmt-swt" then "mgmt_swt" else r.device, platform: if exists r.platform then r.platform else "unknown"}}))
      |> filter(fn: (r) => r.device =~ /^${{device:regex}}$/ and r.severity =~ /^${{severity:regex}}$/)
      |> keep(columns: ["_time", "device", "platform", "source_ip", "severity", "facility", "_value"])
      |> rename(columns: {{_value: "message"}})
      |> group()
      |> sort(columns: ["_time"], desc: true)
      |> limit(n: 200)''', description="Critical-or-worse syslog for the selected device/severity. syslog_event has no topic tag separating resource from interface/link messages, so this is the full matching feed, not a topic-specific subset -- a disclosed limitation, not a fabricated split.", event_optional=True)


def resources_dashboard() -> dict:
    filters = basic_filters()
    unhealthy_only = bool_variable("unhealthy_only", "Unhealthy only")
    panels = [
        panel(1, "Devices reporting (5m)", "stat", 0, 0, 6, 4, f'''from(bucket: "{BUCKET}")
          |> range(start: -5m)
          |> filter(fn: (r) => r._measurement == "gnmi_telemetry" and r.category == "system_identity" and r._field == "hostname")
          |> filter(fn: (r) => {filters})
          |> group()
          |> unique(column: "device")
          |> count(column: "device")
          |> rename(columns: {{device: "_value"}})''', description="Count of devices with a real hostname telemetry sample in the last five minutes. Missing data is not treated as UP.", threshold_steps=(("red", None), ("orange", 1), ("green", 10))),
        panel(2, "Worst telemetry age", "stat", 6, 0, 6, 4, f'''from(bucket: "{BUCKET}")
          |> range(start: -30d)
          |> filter(fn: (r) => r._measurement == "gnmi_telemetry" and r.category == "system_identity" and r._field == "hostname")
          |> filter(fn: (r) => {filters})
          |> group(columns: ["device"])
          |> last()
          |> map(fn: (r) => ({{r with _value: float(v: int(v: now()) - int(v: r._time)) / 1000000000.0}}))
          |> group()
          |> max()''', description="Age of the stalest last-received identity sample. Green <60s, amber 60-120s, red >120s.", unit="s", threshold_steps=(("green", None), ("orange", 60), ("red", 120)), decimals=1),
        panel(3, "Latest CPU by device", "bargauge", 12, 0, 6, 4, f'''from(bucket: "{BUCKET}")
          |> range(start: v.timeRangeStart, stop: v.timeRangeStop)
          |> filter(fn: (r) => r._measurement == "gnmi_telemetry" and r.category == "system_cpu" and r._field == "cpu_total_pct")
          |> filter(fn: (r) => {filters})
          |> group(columns: ["device"])
          |> aggregateWindow(every: 1m, fn: mean, createEmpty: false)
          |> last()''', unit="percent", threshold_steps=(("green", None), ("orange", 70), ("red", 90)), decimals=1),
        panel(4, "NMAS Collector CPU Alerts (range)", "stat", 18, 0, 6, 4, f'''from(bucket: "{BUCKET}")
          |> range(start: v.timeRangeStart, stop: v.timeRangeStop)
          |> filter(fn: (r) => r._measurement == "collector_alert" and r.alert_type == "cpu_threshold" and r.transition == "alert")
          |> filter(fn: (r) => {filters})
          |> group()
          |> count()''', description="Count of collector-generated CPU threshold ALERT transitions in the selected range (measurement collector_alert, source=collector) -- distinct from device-originated SNMP traps. Legitimately zero when no device has crossed the configured threshold.", threshold_steps=(("green", None), ("orange", 1), ("red", 3)), event_optional=True),
        panel(5, "Per-device health & freshness", "table", 0, 4, 24, 8, f'''from(bucket: "{BUCKET}")
          |> range(start: -30d)
          |> filter(fn: (r) => r._measurement == "gnmi_telemetry" and r.category == "system_identity" and r._field == "hostname")
          |> filter(fn: (r) => {filters})
          |> group(columns: ["device", "platform"])
          |> last()
          |> map(fn: (r) => ({{r with age_seconds: float(v: int(v: now()) - int(v: r._time)) / 1000000000.0, status: if int(v: now()) - int(v: r._time) < 60000000000 then "HEALTHY" else if int(v: now()) - int(v: r._time) < 120000000000 then "STALE" else "OFFLINE"}}))
          |> filter(fn: (r) => ("${{unhealthy_only}}" == "false") or r.status != "HEALTHY")
          |> keep(columns: ["device", "platform", "_time", "age_seconds", "status"])
          |> group()
          |> sort(columns: ["device"])''', description="Health is based only on observed telemetry age; absent devices are never fabricated as healthy. 'Unhealthy only' hides HEALTHY rows -- this can legitimately empty the table when the whole fleet is healthy.", event_optional=True),
        panel(6, "CPU utilization", "timeseries", 0, 12, 12, 8, f'''from(bucket: "{BUCKET}")
          |> range(start: v.timeRangeStart, stop: v.timeRangeStop)
          |> filter(fn: (r) => r._measurement == "gnmi_telemetry" and r.category == "system_cpu" and r._field == "cpu_total_pct")
          |> filter(fn: (r) => {filters})
          |> group(columns: ["device"])
          |> aggregateWindow(every: v.windowPeriod, fn: mean, createEmpty: false)''', unit="percent", threshold_steps=(("green", None), ("orange", 70), ("red", 90)), decimals=1),
        panel(7, "Memory utilization", "timeseries", 12, 12, 12, 8, f'''from(bucket: "{BUCKET}")
          |> range(start: v.timeRangeStart, stop: v.timeRangeStop)
          |> filter(fn: (r) => r._measurement == "gnmi_telemetry" and r.category == "system_memory" and (r._field == "mem_used_bytes" or r._field == "mem_physical_bytes"))
          |> filter(fn: (r) => {filters})
          |> pivot(rowKey: ["_time", "device", "platform"], columnKey: ["_field"], valueColumn: "_value")
          |> filter(fn: (r) => exists r.mem_physical_bytes and exists r.mem_used_bytes and r.mem_physical_bytes > 0)
          |> map(fn: (r) => ({{r with _value: 100.0 * float(v: r.mem_used_bytes) / float(v: r.mem_physical_bytes)}}))
          |> group(columns: ["device"])
          |> aggregateWindow(every: v.windowPeriod, fn: mean, createEmpty: false)''', unit="percent", threshold_steps=(("green", None), ("orange", 75), ("red", 90)), decimals=1),
        panel(8, "SNMP-polled CPU & device uptime", "table", 0, 20, 24, 8, f'''from(bucket: "{BUCKET}")
          |> range(start: -30d)
          |> filter(fn: (r) => r._measurement == "snmp_poll" and r.metric == "sysUpTime" and r._field == "value")
          |> filter(fn: (r) => r.device =~ /^${{device:regex}}$/)
          |> group(columns: ["device", "platform", "management_ip"])
          |> last()
          |> map(fn: (r) => ({{r with uptime_seconds: float(v: r._value) / 100.0, poll_age_seconds: float(v: int(v: now()) - int(v: r._time)) / 1000000000.0}}))
          |> keep(columns: ["device", "platform", "management_ip", "_time", "poll_age_seconds", "uptime_seconds"])
          |> group()
          |> sort(columns: ["device"])''', description="Device uptime and last SNMP poll age (HOST-RESOURCES-MIB sysUpTime) -- the only stored source of device uptime; gNMI does not stream an uptime leaf in the current schema."),
        recent_critical_syslog_panel(9, 0, 28, 24, 9, title="Resource-related critical syslog"),
    ]
    return dashboard(
        "nmas-resources",
        "NMAS Resources",
        "Canonical dashboard for the future Django 'Resources' page: device/system health -- CPU, memory, telemetry freshness, device uptime, and collector CPU-threshold alerts. Sources: gnmi_telemetry (continuous per-device state/metrics), snmp_poll (uptime/cross-check CPU), collector_alert (event-optional), syslog_event (event-optional). See docs/GRAFANA_MONITORING_TAXONOMY.md.",
        [DEVICE_VAR, PLATFORM_VAR, SEVERITY_VAR, unhealthy_only],
        panels,
        start="now-6h",
        extra_tags=("canonical",),
    )


def link_events_dashboard() -> dict:
    trap_filter = "r.device =~ /^${device:regex}$/ and r.event_type =~ /^${event_type:regex}$/"
    panels = [
        panel(1, "SNMP notifications (range)", "stat", 0, 0, 6, 4, f'''from(bucket: "{BUCKET}")
          |> range(start: v.timeRangeStart, stop: v.timeRangeStop)
          |> filter(fn: (r) => r._measurement == "snmp_trap" and r._field == "value")
          |> filter(fn: (r) => {trap_filter})
          |> group()
          |> count()''', description="Authenticated SNMPv3 notifications (including linkUp/linkDown) in the selected range. Legitimately zero on a fully quiet, stable network.", threshold_steps=(("green", None), ("orange", 1), ("red", 10)), event_optional=True),
        panel(2, "Critical syslog (range)", "stat", 6, 0, 6, 4, f'''from(bucket: "{BUCKET}")
          |> range(start: v.timeRangeStart, stop: v.timeRangeStop)
          |> filter(fn: (r) => r._measurement == "syslog_event" and r._field == "message")
          |> map(fn: (r) => ({{r with device: if r.device == "mgmt-swt" then "mgmt_swt" else r.device}}))
          |> filter(fn: (r) => r.device =~ /^${{device:regex}}$/ and r.severity =~ /^${{severity:regex}}$/)
          |> group()
          |> count()''', description="Critical-or-worse syslog events in range. Not topic-tagged to interfaces specifically -- see the recent-events table below.", threshold_steps=(("green", None), ("red", 1)), event_optional=True),
        panel(3, "Trap types", "bargauge", 12, 0, 12, 4, f'''from(bucket: "{BUCKET}")
          |> range(start: v.timeRangeStart, stop: v.timeRangeStop)
          |> filter(fn: (r) => r._measurement == "snmp_trap" and r._field == "value")
          |> filter(fn: (r) => {trap_filter})
          |> group(columns: ["event_type"])
          |> count()''', description="Includes linkUp/linkDown and explicitly labelled cEOS safe test notifications. collector_alert CPU events are a distinct measurement and never appear here.", threshold_steps=(("green", None), ("orange", 1), ("red", 10)), event_optional=True),
        panel(4, "Notification volume over time (by event type)", "timeseries", 0, 4, 24, 8, f'''from(bucket: "{BUCKET}")
          |> range(start: v.timeRangeStart, stop: v.timeRangeStop)
          |> filter(fn: (r) => r._measurement == "snmp_trap" and r._field == "value")
          |> filter(fn: (r) => {trap_filter})
          |> group(columns: ["event_type"])
          |> aggregateWindow(every: v.windowPeriod, fn: count, createEmpty: false)''', description="Received SNMP notification count per dashboard interval, grouped by event type (linkUp/linkDown/ceosTestNotification/other).", unit="short", event_optional=True),
        panel(5, "Recent SNMP notifications", "table", 0, 12, 24, 10, f'''from(bucket: "{BUCKET}")
          |> range(start: v.timeRangeStart, stop: v.timeRangeStop)
          |> filter(fn: (r) => r._measurement == "snmp_trap" and r._field == "raw_varbinds")
          |> filter(fn: (r) => {trap_filter})
          |> map(fn: (r) => ({{r with ifindex: if exists r.ifindex then r.ifindex else "-"}}))
          |> keep(columns: ["_time", "device", "source_ip", "event_type", "severity", "ifindex", "notification_oid", "_value"])
          |> rename(columns: {{_value: "raw_varbinds"}})
          |> group()
          |> sort(columns: ["_time"], desc: true)
          |> limit(n: 200)''', description="Chronological event feed: time, device/source, notification class/OID, optional interface index, decoded varbinds. No distinct admin-state-transition trap exists separately from linkUp/linkDown on either platform -- not fabricated here.", event_optional=True),
        recent_critical_syslog_panel(6, 0, 22, 24, 9),
    ]
    return dashboard(
        "nmas-link-events",
        "NMAS Link Events",
        "Canonical dashboard for the future Django 'Link Events' page: chronological interface/link notifications and related critical syslog. Sources: snmp_trap (linkUp/linkDown/other authenticated notifications -- event-shaped, legitimately empty when quiet) and syslog_event (event-optional). Does not fabricate a discrete transition-event log for gNMI continuous interface state or for interface errors/discards -- both are stored only as continuous samples/counters and are presented as such on NMAS Link State & Traffic instead. See docs/GRAFANA_MONITORING_TAXONOMY.md \"Known limitations\".",
        [DEVICE_VAR, EVENT_TYPE_VAR, SEVERITY_VAR],
        panels,
        start="now-24h",
        extra_tags=("canonical",),
    )


def link_state_traffic_dashboard() -> dict:
    state_filters = link_state_filters()
    hide_zero_traffic = bool_variable("hide_zero_traffic", "Hide zero traffic")
    hide_down = bool_variable("hide_down", "Hide down interfaces")
    active_only = bool_variable("active_only", "Active interfaces only")
    include_mgmt = bool_variable("include_mgmt", "Include management interfaces", default="true")
    include_loopback = bool_variable("include_loopback", "Include loopback interfaces", default="true")
    panels = [
        panel(1, "Interface administrative state", "state-timeline", 0, 0, 12, 9, f'''from(bucket: "{BUCKET}")
          |> range(start: v.timeRangeStart, stop: v.timeRangeStop)
          |> filter(fn: (r) => r._measurement == "gnmi_telemetry" and r.category == "interface_state" and r._field == "admin_status")
          |> filter(fn: (r) => {state_filters})
          |> keep(columns: ["_time", "_value", "device", "interface"])
          |> group(columns: ["device", "interface"])''', description="Actual sampled OpenConfig administrative state."),
        panel(2, "Interface operational state", "state-timeline", 12, 0, 12, 9, f'''from(bucket: "{BUCKET}")
          |> range(start: v.timeRangeStart, stop: v.timeRangeStop)
          |> filter(fn: (r) => r._measurement == "gnmi_telemetry" and r.category == "interface_state" and r._field == "oper_status")
          |> filter(fn: (r) => {state_filters})
          |> keep(columns: ["_time", "_value", "device", "interface"])
          |> group(columns: ["device", "interface"])''', description="Actual sampled OpenConfig operational state."),
        panel(3, "Current interface state", "table", 0, 9, 24, 8, f'''from(bucket: "{BUCKET}")
          |> range(start: -15m)
          |> filter(fn: (r) => r._measurement == "gnmi_telemetry" and r.category == "interface_state" and (r._field == "admin_status" or r._field == "oper_status"))
          |> filter(fn: (r) => {state_filters})
          |> group(columns: ["device", "platform", "interface", "_field"])
          |> last()
          |> group(columns: ["device", "platform", "interface"])
          |> pivot(rowKey: ["device", "platform", "interface"], columnKey: ["_field"], valueColumn: "_value")
          |> filter(fn: (r) => ("${{active_only}}" == "false") or (r.admin_status == "UP" and r.oper_status == "UP"))
          |> filter(fn: (r) => ("${{hide_down}}" == "false") or (r.oper_status == "UP"))
          |> group()
          |> sort(columns: ["device", "interface"])''', description="Latest observed admin/operational state for every selected interface (not only non-UP, unlike the legacy exception views). 'Active only' = admin UP and oper UP. 'Hide down' removes oper-down interfaces."),
        panel(4, "Interface traffic rate", "timeseries", 0, 17, 12, 8, f'''from(bucket: "{BUCKET}")
          |> range(start: v.timeRangeStart, stop: v.timeRangeStop)
          |> filter(fn: (r) => r._measurement == "gnmi_telemetry" and r.category == "interface_counters" and (r._field == "in_octets" or r._field == "out_octets"))
          |> filter(fn: (r) => {state_filters})
          |> group(columns: ["device", "interface", "_field"])
          |> derivative(unit: 1s, nonNegative: true)
          |> map(fn: (r) => ({{r with _value: r._value * 8.0}}))''', description="Non-negative derivative of streamed ingress/egress octet counters, converted to bits per second. Shown for the full selected time range regardless of current down/active state, so history is never retroactively hidden; use the ranking table below for a down/zero/active-filtered current view.", unit="bps", decimals=1),
        panel(5, "Error and discard rate", "timeseries", 12, 17, 12, 8, f'''from(bucket: "{BUCKET}")
          |> range(start: v.timeRangeStart, stop: v.timeRangeStop)
          |> filter(fn: (r) => r._measurement == "gnmi_telemetry" and r.category == "interface_counters" and (r._field == "in_errors" or r._field == "out_errors" or r._field == "in_discards" or r._field == "out_discards"))
          |> filter(fn: (r) => {state_filters})
          |> group(columns: ["device", "interface", "_field"])
          |> derivative(unit: 1s, nonNegative: true)''', description="Counter derivatives; any sustained value above zero deserves investigation.", unit="ops", threshold_steps=(("green", None), ("red", 0.001)), decimals=3),
        panel(6, "Active / highest-traffic interfaces", "table", 0, 25, 24, 8, f'''states = from(bucket: "{BUCKET}")
          |> range(start: -15m)
          |> filter(fn: (r) => r._measurement == "gnmi_telemetry" and r.category == "interface_state" and (r._field == "admin_status" or r._field == "oper_status"))
          |> filter(fn: (r) => {state_filters})
          |> group(columns: ["device", "platform", "interface", "_field"])
          |> last()
          |> group(columns: ["device", "platform", "interface"])
          |> pivot(rowKey: ["device", "platform", "interface"], columnKey: ["_field"], valueColumn: "_value")

        rates = from(bucket: "{BUCKET}")
          |> range(start: v.timeRangeStart, stop: v.timeRangeStop)
          |> filter(fn: (r) => r._measurement == "gnmi_telemetry" and r.category == "interface_counters" and (r._field == "in_octets" or r._field == "out_octets"))
          |> filter(fn: (r) => {state_filters})
          |> group(columns: ["device", "interface", "_field"])
          |> derivative(unit: 1s, nonNegative: true)
          |> map(fn: (r) => ({{r with _value: r._value * 8.0}}))
          |> group(columns: ["device", "interface"])
          |> mean()

        join(tables: {{s: states, r: rates}}, on: ["device", "interface"])
          |> filter(fn: (r) => ("${{active_only}}" == "false") or (r.admin_status == "UP" and r.oper_status == "UP"))
          |> filter(fn: (r) => ("${{hide_down}}" == "false") or (r.oper_status == "UP"))
          |> filter(fn: (r) => ("${{hide_zero_traffic}}" == "false") or (r._value > 0.0))
          |> group()
          |> sort(columns: ["_value"], desc: true)
          |> limit(n: 20)''', description="Interfaces ranked by mean bits/second (ingress+egress combined series) over the selected range, joined against their latest observed admin/oper state. 'Active' is defined as admin UP and oper UP. This is the one panel where hide_zero_traffic/hide_down/active_only are all honored together, since it is a current ranking rather than a historical chart.", unit="bps", decimals=1),
        panel(7, "Latest interface counters", "table", 0, 33, 24, 9, f'''from(bucket: "{BUCKET}")
          |> range(start: -15m)
          |> filter(fn: (r) => r._measurement == "gnmi_telemetry" and r.category == "interface_counters")
          |> filter(fn: (r) => {state_filters})
          |> group(columns: ["device", "platform", "interface", "_field"])
          |> last()
          |> group(columns: ["device", "platform", "interface"])
          |> pivot(rowKey: ["device", "platform", "interface"], columnKey: ["_field"], valueColumn: "_value")
          |> group()
          |> sort(columns: ["device", "interface"])''', description="Latest raw octet/error/discard counters. Packet counters are not stored by the current collector and are intentionally not fabricated."),
        panel(8, "Latest NETCONF RPC snapshots", "table", 0, 42, 24, 7, f'''from(bucket: "{BUCKET}")
          |> range(start: -30d)
          |> filter(fn: (r) => r._measurement == "netconf_snapshot" and r._field == "interface_count")
          |> filter(fn: (r) => {basic_filters()})
          |> group(columns: ["device", "platform"])
          |> last()
          |> map(fn: (r) => ({{r with snapshot_age_seconds: float(v: int(v: now()) - int(v: r._time)) / 1000000000.0}}))
          |> keep(columns: ["device", "platform", "_time", "snapshot_age_seconds", "_value"])
          |> rename(columns: {{_value: "interface_count"}})
          |> group()
          |> sort(columns: ["device"])''', description="Discrete read-only NETCONF <get> verification snapshots (device-level interface count), not streaming telemetry and not filtered per-interface."),
    ]
    return dashboard(
        "nmas-link-state-traffic",
        "NMAS Link State & Traffic",
        "Canonical dashboard for the future Django 'Link State & Traffic' page: interface admin/oper state, ingress/egress traffic rate, errors/discards, and raw counters, all derived from real gnmi_telemetry samples/counters. No packet-counter or utilization-percentage panel is fabricated: interface speed/capacity is not polled by any current collector, so only accurate bits-per-second rates are shown, never a percentage -- see docs/GRAFANA_MONITORING_TAXONOMY.md \"Rate and utilization semantics\".",
        [DEVICE_VAR, PLATFORM_VAR, INTERFACE_VAR, hide_zero_traffic, hide_down, active_only, include_mgmt, include_loopback],
        panels,
        start="now-3h",
        extra_tags=("canonical",),
    )


def definitions() -> dict[str, dict]:
    return {
        "fleet-overview.json": fleet_dashboard(),
        "streaming-telemetry.json": telemetry_dashboard(),
        "snmp-monitoring.json": snmp_dashboard(),
        "critical-syslog.json": syslog_dashboard(),
        "resources.json": resources_dashboard(),
        "link-events.json": link_events_dashboard(),
        "link-state-traffic.json": link_state_traffic_dashboard(),
    }


def encoded(value: dict) -> str:
    return json.dumps(value, indent=2, sort_keys=True) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true", help="fail if tracked JSON differs from deterministic output")
    args = parser.parse_args()
    mismatches = []
    for name, value in definitions().items():
        path = OUTPUT / name
        content = encoded(value)
        if args.check:
            if not path.exists() or path.read_text() != content:
                mismatches.append(str(path.relative_to(BASE)))
        else:
            OUTPUT.mkdir(parents=True, exist_ok=True)
            path.write_text(content)
    if mismatches:
        print("Dashboard JSON is stale: " + ", ".join(mismatches))
        return 1
    print(("Verified" if args.check else "Generated") + f" {len(definitions())} Grafana dashboards")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
