"""Provision the read-only NetworkX dynamic topology service on NMAS."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import subprocess
from typing import Any

import yaml

from modules.nmas import BASE, MONITORING, VENV, NmasError, stage

CONFIG_PATH = MONITORING / "config/topology.yml"
RUNTIME = MONITORING / "runtime"


def load_config() -> dict[str, Any]:
    value = yaml.safe_load(CONFIG_PATH.read_text())
    required = {
        "lab_name", "runtime_metadata", "bind_address", "port",
        "browser_refresh_seconds", "backend_cache_seconds", "healthy_seconds",
        "stale_seconds", "recent_event_window_seconds", "layout_seed",
    }
    if not isinstance(value, dict) or not required <= value.keys():
        raise NmasError("Dynamic topology configuration is incomplete")
    if value["bind_address"] != "127.0.0.1":
        raise NmasError("Dynamic topology must bind only to 127.0.0.1")
    if not 10 <= int(value["browser_refresh_seconds"]) <= 30:
        raise NmasError("Dynamic topology browser refresh must be between 10 and 30 seconds")
    if not 1 <= int(value["backend_cache_seconds"]) <= int(value["browser_refresh_seconds"]):
        raise NmasError("Dynamic topology cache interval is invalid")
    if int(value["healthy_seconds"]) >= int(value["stale_seconds"]):
        raise NmasError("Healthy timeout must be less than stale/offline timeout")
    return value


def _monitor_interface(kind: str, interface: str) -> str:
    match = re.fullmatch(r"eth(\d+)", interface)
    if kind == "arista_ceos" and match:
        return "Ethernet" + match.group(1)
    return interface


def resolve_monitoring_metadata(
    monitoring: dict[str, Any] | None, management_ipv4: str | None, management_ipv6: str | None,
) -> dict[str, Any]:
    """Resolve one node's dual-stack management/monitoring presentation
    metadata. Pure and offline-testable (no I/O): `monitoring` is the
    verbatim `network_devices.<name>.monitoring` block from inventory.yml,
    or None for an unmonitored node (hosts, WebServer).

    `address`/`address_v6` are the literal, verified management-VLAN
    (Vlan200) addresses recorded in inventory.yml -- never derived from a
    naming/numbering pattern. "auto" (R5's documented design: no static
    Vlan200 SVI -- see R5.cfg.j2/AGENTS.md) resolves to the live
    Containerlab-assigned `management_ipv4`/`management_ipv6` for BOTH
    families instead. A genuinely absent IPv6 stays `None`.
    """
    if not monitoring:
        return {
            "monitoring_address": None, "monitoring_address_v6": None,
            "monitoring_interface": None, "monitoring_implementation": "none",
            "monitoring_platform": None,
        }
    address = monitoring.get("address")
    address_v6 = monitoring.get("address_v6")
    if address == "auto":
        address = management_ipv4
        address_v6 = address_v6 or management_ipv6
    return {
        "monitoring_address": address,
        "monitoring_address_v6": address_v6,
        "monitoring_interface": monitoring.get("source_interface"),
        "monitoring_implementation": "native cEOS gNMI" if monitoring["platform"] == "ceos" else "Linux read-only adapter",
        "monitoring_platform": monitoring["platform"],
    }


def _inspect(config: dict[str, Any]) -> dict[str, Any]:
    result = subprocess.run(
        ["containerlab", "inspect", "--name", config["lab_name"], "--format", "json"],
        cwd=BASE, capture_output=True, text=True, timeout=30,
    )
    if result.returncode:
        raise NmasError("Read-only Containerlab inspect failed: " + (result.stderr or result.stdout)[-800:])
    try:
        document = json.loads(result.stdout)
        rows = document[config["lab_name"]]
    except (json.JSONDecodeError, KeyError, TypeError) as exc:
        raise NmasError("Containerlab inspect returned an unexpected schema") from exc
    return {row["name"].removeprefix("clab-" + config["lab_name"] + "-"): row for row in rows}


def active_topology_snapshot(config: dict[str, Any] | None = None) -> dict[str, Any]:
    """Reconcile active runtime edge metadata with read-only inspect output."""
    config = config or load_config()
    source = Path(config["runtime_metadata"])
    if not source.is_file():
        raise NmasError(f"Active Containerlab metadata is missing: {source}")
    raw = source.read_bytes()
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise NmasError("Active Containerlab topology-data.json is invalid") from exc
    if data.get("name") != config["lab_name"] or not isinstance(data.get("nodes"), dict) or not isinstance(data.get("links"), list):
        raise NmasError("Active Containerlab metadata does not match the configured lab")
    inspected = _inspect(config)
    active_names = set(data["nodes"])
    if active_names != set(inspected):
        raise NmasError("Containerlab inspect nodes differ from active topology metadata")
    not_running = sorted(name for name, item in inspected.items() if item.get("state") != "running")
    if not_running:
        raise NmasError("Active topology contains non-running nodes: " + ", ".join(not_running))

    inventory = yaml.safe_load((BASE / "inventory.yml").read_text())
    monitor_inventory = inventory.get("network_devices", {})
    nodes = []
    for name in sorted(active_names):
        meta = data["nodes"][name]
        live = inspected[name]
        monitoring = monitor_inventory.get(name, {}).get("monitoring")
        management_ipv4 = str(live.get("ipv4_address") or "").split("/", 1)[0] or None
        management_ipv6 = str(live.get("ipv6_address") or "").split("/", 1)[0] or None
        resolved = resolve_monitoring_metadata(monitoring, management_ipv4, management_ipv6)
        monitoring_address = resolved["monitoring_address"]
        monitoring_address_v6 = resolved["monitoring_address_v6"]
        monitoring_interface = resolved["monitoring_interface"]
        if monitoring:
            implementation = resolved["monitoring_implementation"]
            platform = resolved["monitoring_platform"]
        else:
            implementation = "none"
            platform = "linux-endpoint" if meta.get("kind") == "linux" else str(meta.get("kind", "unknown"))
        nodes.append({
            "id": name,
            "kind": meta.get("kind"),
            "image": meta.get("image"),
            "platform": platform,
            "runtime_state": live.get("state"),
            "management_ipv4": management_ipv4,
            "management_ipv6": management_ipv6,
            "monitoring_address": monitoring_address,
            "monitoring_address_v6": monitoring_address_v6,
            "monitoring_interface": monitoring_interface,
            "monitored": bool(monitoring),
            "monitoring_implementation": implementation,
        })

    edges = []
    excluded_host_links = 0
    for link in data["links"]:
        endpoint_map = link.get("endpoints")
        if not isinstance(endpoint_map, dict) or len(endpoint_map) != 2:
            raise NmasError("Active Containerlab link has an unexpected endpoint schema")
        endpoints = []
        for key in sorted(endpoint_map):
            endpoint = endpoint_map[key]
            node, interface = endpoint.get("node"), endpoint.get("interface")
            if node not in active_names:
                excluded_host_links += 1
                endpoints = []
                break
            endpoints.append({
                "node": node,
                "interface": interface,
                "monitor_interface": _monitor_interface(data["nodes"][node].get("kind", ""), interface),
            })
        if not endpoints:
            continue
        endpoints.sort(key=lambda item: (item["node"], item["interface"]))
        from modules.topology_graph import canonical_edge_id
        edge_id = canonical_edge_id(endpoints[0], endpoints[1])
        plane = "management" if "mgmt_swt" in {item["node"] for item in endpoints} else "data"
        edges.append({"id": edge_id, "endpoints": endpoints, "plane": plane})
    if len({item["id"] for item in edges}) != len(edges):
        raise NmasError("Active topology contains duplicate graph edge identities")
    return {
        "lab_name": config["lab_name"],
        "source": str(source),
        "source_sha256": hashlib.sha256(raw).hexdigest(),
        "nodes": nodes,
        "edges": sorted(edges, key=lambda item: item["id"]),
        "excluded_host_links": excluded_host_links,
    }


def _monitoring_env() -> dict[str, str]:
    path = RUNTIME / "monitoring.env"
    if not path.is_file() or path.is_symlink() or path.stat().st_mode & 0o077:
        raise NmasError("Dynamic topology requires protected monitoring/runtime/monitoring.env")
    values = dict(line.split("=", 1) for line in path.read_text().splitlines() if "=" in line)
    required = {"INFLUXDB_ORG", "INFLUXDB_BUCKET", "INFLUXDB_TOKEN"}
    if not required <= values.keys():
        raise NmasError("Dynamic topology runtime environment is incomplete")
    return values


def provision_topology(snapshot: dict[str, Any], config: dict[str, Any]) -> str:
    env = _monitoring_env()
    payload = {
        "python": str(VENV / "bin/python"),
        "server_script": (MONITORING / "scripts/topology_server.py").read_text(),
        "graph_module": (BASE / "modules/topology_graph.py").read_text(),
        "topology": snapshot,
        "config": config,
        "influx_org": env["INFLUXDB_ORG"],
        "influx_bucket": env["INFLUXDB_BUCKET"],
        "influx_token": env["INFLUXDB_TOKEN"],
    }
    script = (MONITORING / "scripts/provision_topology.py").read_text()
    result = subprocess.run(
        ["sudo", "-n", "python3", "-c", script], input=json.dumps(payload),
        capture_output=True, text=True, timeout=60,
    )
    output = (result.stdout + result.stderr).replace(env["INFLUXDB_TOKEN"], "[REDACTED]")
    if result.returncode:
        raise NmasError("Dynamic topology provisioning failed: " + output[-1200:])
    print(output.strip(), flush=True)
    return output.strip()


def ensure_topology_infrastructure(verbose: bool = False) -> str:
    config = load_config()
    snapshot = active_topology_snapshot(config)
    result = provision_topology(snapshot, config)
    stage(
        "Dynamic topology verification",
        [str(VENV / "bin/python"), str(MONITORING / "tests/verify_topology.py")],
        verbose,
    )
    return result
