#!/usr/bin/env python3
"""Live acceptance matrix for the NetworkX dynamic topology service."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess
import sys
import time

import networkx as nx
import requests

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from modules.topology import active_topology_snapshot, load_config, _monitoring_env
from modules.topology_graph import (
    InfluxEvidence, NODE_STATES, EDGE_STATES, age_seconds, parse_time, utc_now,
)

# --- Race-safe REAL_NODE_<name> comparison ---------------------------------
#
# `REAL_NODE_R1`/`REAL_NODE_R3` cross-check two *independent, asynchronous*
# observations of the same device: the topology HTTP API's cached snapshot
# (read once, at T1, in `main()`) and a direct InfluxDB read the verifier
# performs itself afterward (T2). Both are legitimately correct; they are
# just not simultaneous. Live measurement against the running system (8/8
# reproductions during this fix) shows the skew between them is exactly 0s
# while both land in the same ~10s topology-backend cache window, and jumps
# to ~20.0s (one gNMI SAMPLE period) whenever a fresh sample is recorded to
# InfluxDB in the gap between the API's cache snapshot and the verifier's
# direct query -- with no bug anywhere in the topology/health model.
#
# NODE_EVIDENCE_TOLERANCE_SECONDS bounds that acceptable T1/T2 drift instead
# of requiring the two timestamps to be identical:
#   - one gNMI SAMPLE interval   ~20s (a sample can land in the T1..T2 gap)
#   - one backend cache lifetime ~10s (config: backend_cache_seconds)
#   combined worst-case legitimate skew:                      ~30s
#   + ~50% margin for query/HTTP/process-scheduling jitter:    ~15s
#   => 45s tolerance window.
# 45s is comfortably under `healthy_seconds` (60s), so it can never mask a
# node that is genuinely STALE/OFFLINE, and far under `stale_seconds`
# (120s) -- a direct observation older or newer than that is still a FAIL.
NODE_EVIDENCE_TOLERANCE_SECONDS = 45


def evaluate_real_node(
    name: str,
    api_node: dict,
    direct: dict | None,
    *,
    now,
    healthy_seconds: int,
    tolerance_seconds: int = NODE_EVIDENCE_TOLERANCE_SECONDS,
) -> tuple[bool, str]:
    """Race-safe REAL_NODE_<name> verdict; pure function, unit-testable offline.

    Every substantive check the original exact-match assertion made is kept:
      - the device must actually exist in the *direct* InfluxDB evidence
        (evidence["devices"].get(name) is already keyed by device identity,
        so a wrong-device/category lookup naturally yields `direct is None`
        here and fails) -- the API can't be trusted on its own;
      - the API must report a node health of exactly HEALTHY;
      - the API and direct timestamps must describe the same underlying
        telemetry -- freshness/temporal-relationship, not byte-identity;
      - the direct evidence must itself be genuinely recent -- not stale,
        not fabricated, not from the future.
    Only the identity requirement (exact timestamp equality) is relaxed, and
    only within a bounded, justified tolerance.
    """
    api_stamp = parse_time(api_node.get("last_telemetry_timestamp"))
    if direct is None:
        return False, f"no direct InfluxDB evidence exists for device={name}"
    if api_stamp is None:
        return False, f"API reported no last_telemetry_timestamp for device={name}"
    direct_stamp = direct.get("last_update")
    if direct_stamp is None:
        return False, f"direct InfluxDB evidence for device={name} has no last_update"
    skew = (direct_stamp - api_stamp).total_seconds()
    if abs(skew) > tolerance_seconds:
        return False, (
            f"api/direct timestamp skew {skew:.2f}s for device={name} exceeds "
            f"{tolerance_seconds}s tolerance (api={api_stamp.isoformat()} direct={direct_stamp.isoformat()})"
        )
    direct_age = age_seconds(direct_stamp, now)
    if direct_age is None or direct_age > healthy_seconds + tolerance_seconds:
        return False, f"direct InfluxDB evidence for device={name} is not recent (age={direct_age}s)"
    if api_node.get("health") != "HEALTHY":
        return False, f"API health for device={name} is {api_node.get('health')!r}, not HEALTHY"
    return True, (
        f"health={api_node['health']} age={api_node.get('telemetry_age_seconds')}s "
        f"source={api_node.get('monitoring_implementation')} api_direct_skew={skew:.2f}s"
    )


def node_link_graph(value):
    try:
        return nx.node_link_graph(value, edges="edges")
    except TypeError:
        return nx.node_link_graph(value, link="edges")


def main() -> None:
    config = load_config()
    expected = active_topology_snapshot(config)
    env = _monitoring_env()
    base = f'http://{config["bind_address"]}:{config["port"]}'
    session = requests.Session()
    session.trust_env = False
    checks: list[tuple[str, str]] = []

    def check(label: str, condition: bool, detail: str = "") -> None:
        if not condition:
            raise AssertionError(label + (": " + detail if detail else ""))
        checks.append((label, detail or "PASS"))

    health_response = session.get(base + "/healthz", timeout=30)
    health = health_response.json()
    check("SERVICE_HEALTH", health_response.status_code == 200 and health.get("status") == "ok", str(health))
    html = session.get(base + "/", timeout=30)
    check("HTML_UI", html.status_code == 200 and "NMAS Dynamic Network Topology" in html.text and "/api/topology" in html.text)
    response = session.get(base + "/api/topology", timeout=30)
    response.raise_for_status()
    payload = response.json()
    check("API_SCHEMA", payload.get("schema_version") == 1 and payload.get("demo", {}).get("mode") == "REAL")
    graph = node_link_graph(payload["graph"])
    check("NETWORKX_GRAPH", isinstance(graph, nx.Graph) and nx.is_connected(graph), f"nodes={graph.number_of_nodes()} edges={graph.number_of_edges()}")

    expected_nodes = {item["id"] for item in expected["nodes"]}
    expected_edges = {item["id"] for item in expected["edges"]}
    actual_nodes = {item["id"] for item in payload["graph"]["nodes"]}
    actual_edges = {item["id"] for item in payload["graph"]["edges"]}
    check("ACTIVE_TOPOLOGY", actual_nodes == expected_nodes and actual_edges == expected_edges and len(actual_nodes) == 15 and len(actual_edges) == 23, f"nodes={len(actual_nodes)} edges={len(actual_edges)} host_links_excluded={expected['excluded_host_links']}")
    check("NO_DUPLICATES", len(actual_nodes) == len(payload["graph"]["nodes"]) and len(actual_edges) == len(payload["graph"]["edges"]))
    source = Path(config["runtime_metadata"])
    check("SOURCE_HASH", payload["graph"]["graph"]["topology_source_sha256"] == hashlib.sha256(source.read_bytes()).hexdigest())

    nodes = {item["id"]: item for item in payload["graph"]["nodes"]}
    edges = {item["id"]: item for item in payload["graph"]["edges"]}
    check("MONITORING_METADATA", sum(bool(item.get("monitored")) for item in nodes.values()) == 10 and all(item.get("monitoring_implementation") for item in nodes.values()))
    check("VALID_STATES", all(item["health"] in NODE_STATES for item in nodes.values()) and all(item["status"] in EDGE_STATES for item in edges.values()))
    check("UNKNOWN_IS_EXPLICIT", all(nodes[name]["health"] == "UNKNOWN" for name in ("H1", "H2", "H3", "H4", "WebServer")))

    evidence = InfluxEvidence(org=env["INFLUXDB_ORG"], bucket=env["INFLUXDB_BUCKET"], token=env["INFLUXDB_TOKEN"]).collect(int(config["recent_event_window_seconds"]))
    evidence_read_at = utc_now()
    for name in ("R1", "R3"):
        direct = evidence["devices"].get(name)
        passed, detail = evaluate_real_node(
            name, nodes[name], direct,
            now=evidence_read_at, healthy_seconds=int(config["healthy_seconds"]),
        )
        check(f"REAL_NODE_{name}", passed, detail)

    link_id = "R3:eth1--S3:eth1"
    link = edges[link_id]
    endpoint_values = {(item["node"], item["monitor_interface"]): item for item in link["endpoint_state"]}
    direct_r3 = evidence["interfaces"].get(("R3", "eth1"), {}).get("fields", {})
    direct_s3 = evidence["interfaces"].get(("S3", "Ethernet1"), {}).get("fields", {})
    check(
        "REAL_LINK_STATE",
        link["status"] == "UP"
        and endpoint_values[("R3", "eth1")]["oper_status"] == direct_r3.get("oper_status") == "UP"
        and endpoint_values[("S3", "Ethernet1")]["oper_status"] == direct_s3.get("oper_status") == "UP",
        f"{link_id}={link['status']} R3:eth1={direct_r3.get('oper_status')} S3:Ethernet1={direct_s3.get('oper_status')}",
    )

    historic = InfluxEvidence(org=env["INFLUXDB_ORG"], bucket=env["INFLUXDB_BUCKET"], token=env["INFLUXDB_TOKEN"]).collect(30 * 24 * 3600)
    dummy_events = [
        (device, interface, event)
        for (device, interface), events_found in historic["link_events"].items()
        for event in events_found
        if interface == "nmastest0" and event["event_type"] in {"linkDown", "linkUp"}
    ]
    active_interfaces = {(item["node"], item["monitor_interface"]) for edge in expected["edges"] for item in edge["endpoints"]}
    check("SAFE_HISTORICAL_EVENTS", bool(dummy_events) and not any((device, interface) in active_interfaces for device, interface, _ in dummy_events), f"recognized={len(dummy_events)} disposable-interface events; active links unaffected")

    demo = session.get(base + "/api/topology?demo=safe-link-down", timeout=30).json()
    synthetic = [item for item in demo["graph"]["edges"] if item.get("synthetic")]
    check("SAFE_DEMO", demo["demo"]["mode"] == "DEMO/SYNTHETIC" and len(synthetic) == 1 and synthetic[0]["status"] == "DOWN" and synthetic[0].get("real_status") in EDGE_STATES, demo["demo"]["target_edge"])

    first_generated = parse_time(payload["generated_at"])
    first_layout = {item["id"]: (item["x"], item["y"]) for item in payload["graph"]["nodes"]}
    time.sleep(int(config["backend_cache_seconds"]) + 1)
    second = session.get(base + "/api/topology", timeout=30).json()
    second_generated = parse_time(second["generated_at"])
    second_layout = {item["id"]: (item["x"], item["y"]) for item in second["graph"]["nodes"]}
    check("DYNAMIC_REFRESH", second_generated > first_generated and second_layout == first_layout and {item["id"] for item in second["graph"]["edges"]} == expected_edges, f"{payload['generated_at']} -> {second['generated_at']}")

    status = subprocess.run(["systemctl", "show", "nmas-topology.service", "-p", "MainPID", "-p", "ActiveState", "--value"], capture_output=True, text=True, check=True).stdout.splitlines()
    listeners = subprocess.run(["ss", "-lnt"], capture_output=True, text=True, check=True).stdout
    check("PROCESS_AND_BIND", status.count("active") == 1 and sum(line.strip().isdigit() and int(line.strip()) > 0 for line in status) == 1 and f'127.0.0.1:{config["port"]}' in listeners and f'0.0.0.0:{config["port"]}' not in listeners)

    serialized = json.dumps(payload) + html.text
    secrets = [value for key, value in env.items() if ("TOKEN" in key or "PASSWORD" in key) and value]
    source_text = "\n".join(path.read_text() for path in [
        Path(__file__), Path(__file__).parents[1] / "scripts/topology_server.py",
        Path(__file__).parents[2] / "modules/topology.py",
        Path(__file__).parents[2] / "modules/topology_graph.py",
        Path(__file__).parents[1] / "config/topology.yml",
    ])
    private_key_marker = "BEGIN " + "PRIVATE KEY"
    check("SECRETS", not any(secret in serialized or secret in source_text for secret in secrets) and private_key_marker not in source_text)
    check("REPRODUCIBLE_SOURCE", active_topology_snapshot(config) == active_topology_snapshot(config))

    print(f'{"ACCEPTANCE CHECK":<28} RESULT DETAIL')
    for label, detail in checks:
        print(f"{label:<28} PASS   {detail}")
    print(f"SUMMARY: PASS checks={len(checks)} nodes={len(actual_nodes)} edges={len(actual_edges)} real_mode=PASS demo_mode=PASS secrets=PASS")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print("TOPOLOGY VERIFICATION FAIL: " + str(exc), file=sys.stderr)
        raise SystemExit(1) from exc
