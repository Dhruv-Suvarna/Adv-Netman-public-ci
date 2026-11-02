"""Provision and verify repository-owned Grafana dashboards."""
from __future__ import annotations

import json
import re
import subprocess
import time

import requests

from modules.nmas import MONITORING, NmasError

RUNTIME = MONITORING / "runtime"
PROVISIONING = MONITORING / "grafana/provisioning"
DASHBOARD_DIR = PROVISIONING / "dashboards/json"
DATASOURCE_UID = "nmas-influxdb"
EXPECTED = {
    "nmas-device-lifecycle": {
        "title": "NMAS Device Lifecycle",
        "variables": {"device"},
        "panels": {"Lifecycle state", "Monitoring state", "Management path", "Generation / reconnects",
                   "Decommission / restore events", "Dynamic collection by management path"},
    },
    "nmas-fleet-overview": {
        "title": "NMAS Network Health Overview",
        "variables": {"device", "platform"},
        "panels": {
            "Devices reporting (5m)", "Interfaces currently down", "Latest CPU by device",
            "Worst telemetry age", "Per-device telemetry health", "Current non-UP interfaces",
            "CPU utilization", "Memory utilization", "Recent linkDown notifications",
            "Critical syslog events", "SNMP traps", "Recent critical syslog",
        },
    },
    "nmas-streaming-telemetry": {
        "title": "NMAS Streaming Telemetry",
        "variables": {"device", "platform", "interface"},
        "panels": {
            "Telemetry freshness by device", "Latest CPU", "Current non-UP interfaces",
            "CPU utilization", "Memory utilization", "Interface operational state",
            "Interface administrative state", "Interface traffic rate",
            "Error and discard rate", "Latest interface counters",
            "Latest NETCONF RPC snapshots",
        },
    },
    "nmas-snmp-monitoring": {
        "title": "NMAS SNMP Monitoring",
        "variables": {"device"},
        "panels": {
            "SNMP poll freshness", "Latest polled CPU", "Traps received",
            "Current IF-MIB down", "Polled CPU utilization", "Trap volume over time",
            "Latest IF-MIB state", "Trap types", "Recent SNMP notifications",
            "NMAS Collector CPU Alerts",
        },
    },
    "nmas-critical-syslog": {
        "title": "NMAS Critical Syslog",
        "variables": {"device", "severity"},
        "panels": {
            "Critical events", "Events by device", "Severity distribution",
            "Critical event volume over time", "Facilities", "Recent critical events",
        },
    },
    "nmas-resources": {
        "title": "NMAS Resources",
        "variables": {"device", "platform", "severity", "unhealthy_only"},
        "panels": {
            "Devices reporting (5m)", "Worst telemetry age", "Latest CPU by device",
            "NMAS Collector CPU Alerts (range)", "Per-device health & freshness",
            "CPU utilization", "Memory utilization", "SNMP-polled CPU & device uptime",
            "Resource-related critical syslog",
        },
    },
    "nmas-link-events": {
        "title": "NMAS Link Events",
        "variables": {"device", "event_type", "severity"},
        "panels": {
            "SNMP notifications (range)", "Critical syslog (range)", "Trap types",
            "Notification volume over time (by event type)", "Recent SNMP notifications",
            "Recent critical syslog",
        },
    },
    "nmas-link-state-traffic": {
        "title": "NMAS Link State & Traffic",
        "variables": {
            "device", "platform", "interface", "hide_zero_traffic", "hide_down",
            "active_only", "include_mgmt", "include_loopback",
        },
        "panels": {
            "Interface administrative state", "Interface operational state",
            "Current interface state", "Interface traffic rate", "Error and discard rate",
            "Active / highest-traffic interfaces", "Latest interface counters",
            "Latest NETCONF RPC snapshots",
        },
    },
}
CANONICAL = {"nmas-resources", "nmas-link-events", "nmas-link-state-traffic"}
# V2 Phase 8: the hand-authored lifecycle dashboard (core.services.infrastructure.grafana enforces its own contract as well).
LIFECYCLE = {"nmas-device-lifecycle"}
LEGACY = {"nmas-fleet-overview", "nmas-streaming-telemetry", "nmas-snmp-monitoring", "nmas-critical-syslog"}


def runtime_env() -> dict[str, str]:
    path = RUNTIME / "monitoring.env"
    if not path.is_file() or path.is_symlink() or path.stat().st_mode & 0o077:
        raise NmasError("Grafana requires protected monitoring/runtime/monitoring.env")
    env = dict(line.split("=", 1) for line in path.read_text().splitlines() if "=" in line)
    required = {"GRAFANA_ADMIN_USER", "GRAFANA_ADMIN_PASSWORD", "INFLUXDB_ORG", "INFLUXDB_BUCKET", "INFLUXDB_TOKEN"}
    if not required <= env.keys():
        raise NmasError("Grafana runtime environment is missing mandatory values")
    return env


def grafana_session(env: dict[str, str]) -> requests.Session:
    session = requests.Session()
    session.trust_env = False
    session.auth = (env["GRAFANA_ADMIN_USER"], env["GRAFANA_ADMIN_PASSWORD"])
    return session


def api(session: requests.Session, method: str, path: str, **kwargs) -> requests.Response:
    response = session.request(method, "http://127.0.0.1:3000" + path, timeout=30, **kwargs)
    if not response.ok:
        raise NmasError(f"Grafana API {method} {path} failed: HTTP {response.status_code} {response.text[:500]}")
    return response


def source_dashboards() -> dict[str, dict]:
    result = {}
    for path in sorted(DASHBOARD_DIR.glob("*.json")):
        value = json.loads(path.read_text())
        uid = value.get("uid")
        if uid in result:
            raise NmasError(f"Duplicate dashboard UID in source: {uid}")
        result[uid] = value
    if set(result) != set(EXPECTED):
        raise NmasError(f"Dashboard source UIDs differ: expected {sorted(EXPECTED)}, found {sorted(result)}")
    return result


def validate_source(env: dict[str, str]) -> dict[str, dict]:
    generator = MONITORING / "scripts/build_grafana_dashboards.py"
    result = subprocess.run(["python3", str(generator), "--check"], capture_output=True, text=True)
    if result.returncode:
        raise NmasError(result.stdout.strip() or result.stderr.strip() or "Grafana dashboard JSON is stale")
    datasource_text = (PROVISIONING / "datasources/influxdb.yml").read_text()
    required = ("uid: nmas-influxdb", "$__env{INFLUXDB_ORG}", "$__env{INFLUXDB_BUCKET}", "$__env{INFLUXDB_TOKEN}")
    if not all(value in datasource_text for value in required):
        raise NmasError("InfluxDB datasource must use the stable UID and runtime environment substitutions")
    source_files = [
        PROVISIONING / "datasources/influxdb.yml",
        PROVISIONING / "dashboards/provider.yml",
        *sorted(DASHBOARD_DIR.glob("*.json")),
    ]
    source = "\n".join(path.read_text() for path in source_files)
    for key, value in env.items():
        if ("PASSWORD" in key or "TOKEN" in key) and value and value in source:
            raise NmasError(f"Runtime secret {key} is embedded in Grafana source")
    if re.search(r'(?i)(?:password|token)\s*[=:]\s*["\']?(?!\$__env|redacted|placeholder)[A-Za-z0-9_.-]{12,}', source):
        raise NmasError("Possible literal credential found in Grafana source")
    dashboards = source_dashboards()
    for uid, expected in EXPECTED.items():
        value = dashboards[uid]
        if value.get("title") != expected["title"] or not value.get("editable") is False:
            raise NmasError(f"{uid}: unstable title or editable IaC dashboard")
        panels = {item.get("title") for item in value.get("panels", [])}
        variables = {item.get("name") for item in value.get("templating", {}).get("list", [])}
        if panels != expected["panels"] or variables != expected["variables"]:
            raise NmasError(f"{uid}: panel or variable contract differs")
        if not all(target.get("datasource", {}).get("uid") == DATASOURCE_UID for item in value["panels"] for target in item.get("targets", [])):
            raise NmasError(f"{uid}: a panel does not use the provisioned datasource UID")
    return dashboards


def datasource_status(session: requests.Session) -> dict:
    sources = api(session, "GET", "/api/datasources").json()
    matches = [item for item in sources if item.get("uid") == DATASOURCE_UID or item.get("name") == "NMAS InfluxDB"]
    if len(matches) != 1:
        raise NmasError(f"Expected exactly one datasource UID {DATASOURCE_UID}, found {len(matches)}")
    value = matches[0]
    if value.get("name") != "NMAS InfluxDB" or value.get("type") != "influxdb" or value.get("access") != "proxy":
        raise NmasError("Grafana datasource identity/type/access differs from desired state")
    health = api(session, "GET", f"/api/datasources/uid/{DATASOURCE_UID}/health").json()
    if health.get("status") != "OK":
        raise NmasError(f"Grafana datasource health failed: {health}")
    return {"id": value.get("id"), "uid": value.get("uid"), "health": health.get("status")}


def provision_grafana() -> None:
    env = runtime_env()
    validate_source(env)
    session = grafana_session(env)
    health = api(session, "GET", "/api/health").json()
    if health.get("database") != "ok":
        raise NmasError(f"Grafana health is not OK: {health}")
    try:
        datasource_status(session)
    except NmasError:
        api(session, "POST", "/api/admin/provisioning/datasources/reload")
        datasource_status(session)
    # The provisioning directory is already bind-mounted read-only. Reloading
    # the file provider applies source changes without recreating/restarting the
    # existing Grafana container.
    api(session, "POST", "/api/admin/provisioning/dashboards/reload")
    deadline = time.monotonic() + 30
    missing = set(EXPECTED)
    while missing and time.monotonic() < deadline:
        found = {item.get("uid") for item in api(session, "GET", "/api/search?type=dash-db").json()}
        missing = set(EXPECTED) - found
        if missing:
            time.sleep(1)
    if missing:
        raise NmasError(f"Grafana did not load provisioned dashboards: {sorted(missing)}")


CUSTOM_VARIABLE_DEFAULTS = {
    "unhealthy_only": "false",
    "hide_zero_traffic": "false",
    "hide_down": "false",
    "active_only": "false",
    "include_mgmt": "true",
    "include_loopback": "true",
}


def substitute_variables(query: str) -> str:
    for name in ("device", "platform", "interface", "severity", "event_type"):
        query = query.replace("${" + name + ":regex}", ".*")
    for name, default in CUSTOM_VARIABLE_DEFAULTS.items():
        query = query.replace("${" + name + "}", default)
    if "${" in query:
        raise NmasError("Unresolved Grafana variable in Flux query")
    return query


def panel_requires_data(panel: dict) -> bool:
    """True for metric/state panels that must show a current value in a
    healthy system; False for event/exception panels (their measurement is
    an event log such as snmp_trap/syslog_event/collector_alert, or their
    query is a filter that only selects an abnormal/non-nominal condition)
    that may legitimately return zero rows during quiet, healthy operation.

    The classification itself lives once, at panel-definition time, in
    monitoring/scripts/build_grafana_dashboards.py's panel(event_optional=...)
    calls -- this function only reads that already-generated field back out
    of the panel dict. There is deliberately no separate hardcoded
    title-based allow-list here; see docs/GRAFANA_MONITORING_TAXONOMY.md
    "Event-optional panel semantics" for the full reasoning and the current
    list of panels marked event-optional on each dashboard.
    """
    return not panel.get("eventOptional", False)


def frame_points(frames: list[dict]) -> int:
    total = 0
    for frame in frames:
        values = frame.get("data", {}).get("values", [])
        if values:
            total += len(values[0])
    return total


def execute_flux(session: requests.Session, query: str, *, hours: int = 24) -> tuple[int, int]:
    now_ms = int(time.time() * 1000)
    payload = {
        "from": str(now_ms - hours * 3600 * 1000),
        "to": str(now_ms),
        "queries": [{
            "refId": "A",
            "datasource": {"type": "influxdb", "uid": DATASOURCE_UID},
            "query": substitute_variables(query),
            "format": "table",
            "intervalMs": 60000,
            "maxDataPoints": 50000,
        }],
    }
    data = api(session, "POST", "/api/ds/query", json=payload).json()
    result = data.get("results", {}).get("A", {})
    if result.get("status") != 200 or result.get("error"):
        raise NmasError(f"Grafana Flux query failed: {result.get('error', 'missing successful result')}")
    frames = result.get("frames", [])
    return len(frames), frame_points(frames)


def verify_grafana(verbose: bool = False) -> dict:
    env = runtime_env()
    source = validate_source(env)
    session = grafana_session(env)
    health = api(session, "GET", "/api/health").json()
    if health.get("database") != "ok":
        raise NmasError("Grafana health endpoint did not report database=ok")
    ds = datasource_status(session)
    search = api(session, "GET", "/api/search?type=dash-db").json()
    found_uids = [item.get("uid") for item in search]
    results = {}
    print("DASHBOARD                         API PANELS VARIABLES QUERIES DATA")
    for uid, expected in EXPECTED.items():
        response = api(session, "GET", f"/api/dashboards/uid/{uid}").json()
        live = response.get("dashboard", {})
        if (found_uids.count(uid) != 1 or sum(item.get("title") == expected["title"] for item in search) != 1
                or live.get("uid") != uid or live.get("title") != expected["title"]
                or not response.get("meta", {}).get("provisioned")):
            raise NmasError(f"{uid}: dashboard API identity/duplicate check failed")
        live_panels = {item.get("title") for item in live.get("panels", [])}
        live_variables = {item.get("name") for item in live.get("templating", {}).get("list", [])}
        if live_panels != expected["panels"] or live_variables != expected["variables"]:
            raise NmasError(f"{uid}: live panels/variables differ from the source contract")
        source_panels = {item["title"]: item for item in source[uid]["panels"]}
        for item in live["panels"]:
            expected_targets = source_panels[item["title"]].get("targets", [])
            actual_targets = item.get("targets", [])
            if ([target.get("query") for target in actual_targets] != [target.get("query") for target in expected_targets]
                    or any(target.get("datasource", {}).get("uid") != DATASOURCE_UID for target in actual_targets)):
                raise NmasError(f"{uid}: live query/datasource differs for panel {item['title']}")
        source_variables = {item["name"]: item for item in source[uid]["templating"]["list"]}
        for variable in live["templating"]["list"]:
            if variable.get("query") != source_variables[variable["name"]].get("query"):
                raise NmasError(f"{uid}: live variable query differs for {variable['name']}")
        query_count = 0
        data_count = 0
        for variable in source[uid]["templating"]["list"]:
            if variable.get("type") != "query":
                # Custom (non-Flux) variables such as the boolean filter
                # toggles have no datasource query to execute; their values
                # are plain option lists, not queried from InfluxDB.
                continue
            _, points = execute_flux(session, variable["query"])
            query_count += 1
            data_count += points
            if points == 0:
                raise NmasError(f"{uid}: variable {variable['name']} returned no real data")
        for item in source[uid]["panels"]:
            for query_target in item.get("targets", []):
                _, points = execute_flux(session, query_target["query"])
                query_count += 1
                data_count += points
                if points == 0 and panel_requires_data(item):
                    raise NmasError(f"{uid}: panel {item['title']} returned no recent real data")
        results[uid] = {"panels": len(live_panels), "variables": len(live_variables), "queries": query_count, "points": data_count}
        print(f"{uid:<33} PASS PASS   PASS      PASS    PASS")
        if verbose:
            print(f"  title={live['title']!r} panels={len(live_panels)} variables={len(live_variables)} queries={query_count} sampled_points={data_count}")
    print(f"SUMMARY: dashboards={len(results)} panels={sum(v['panels'] for v in results.values())} variables={sum(v['variables'] for v in results.values())} queries={sum(v['queries'] for v in results.values())} datasource={ds['health']} secrets=PASS")
    return {"health": health, "datasource": ds, "dashboards": results}


def ensure_grafana_infrastructure(verbose: bool = False) -> dict:
    provision_grafana()
    return verify_grafana(verbose)
