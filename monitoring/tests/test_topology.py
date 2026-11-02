"""Offline contracts for the NetworkX topology health model."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import unittest

from modules.topology_graph import (
    build_base_graph, classify_edge, classify_node, empty_evidence,
    overlay_health, validate_graph_payload,
)


NOW = datetime(2026, 9, 7, 20, 0, tzinfo=timezone.utc)
CONFIG = {
    "browser_refresh_seconds": 20,
    "healthy_seconds": 60,
    "stale_seconds": 120,
    "recent_event_window_seconds": 900,
    "layout_seed": 5840,
}
SNAPSHOT = {
    "lab_name": "test",
    "source": "/read-only/topology-data.json",
    "source_sha256": "0" * 64,
    "excluded_host_links": 0,
    "nodes": [
        {"id": "R1", "kind": "arista_ceos", "image": "ceos:test", "platform": "ceos", "monitored": True, "monitoring_implementation": "native cEOS gNMI"},
        {"id": "R3", "kind": "linux", "image": "ubuntu:test", "platform": "linux", "monitored": True, "monitoring_implementation": "Linux read-only adapter"},
        {"id": "H1", "kind": "linux", "image": "ubuntu:test", "platform": "linux-endpoint", "monitored": False, "monitoring_implementation": "none"},
    ],
    "edges": [
        {"id": "R1:eth1--R3:eth1", "plane": "data", "endpoints": [
            {"node": "R1", "interface": "eth1", "monitor_interface": "Ethernet1"},
            {"node": "R3", "interface": "eth1", "monitor_interface": "eth1"},
        ]},
        {"id": "H1:eth1--R1:eth2", "plane": "data", "endpoints": [
            {"node": "H1", "interface": "eth1", "monitor_interface": "eth1"},
            {"node": "R1", "interface": "eth2", "monitor_interface": "Ethernet2"},
        ]},
    ],
}


def evidence() -> dict:
    value = empty_evidence()
    value["devices"] = {
        "R1": {"last_update": NOW - timedelta(seconds=10), "fields": {"cpu_total_pct": 20, "mem_physical_bytes": 100, "mem_used_bytes": 40}},
        "R3": {"last_update": NOW - timedelta(seconds=75), "fields": {"cpu_total_pct": 30}},
    }
    value["interfaces"] = {
        ("R1", "Ethernet1"): {"last_update": NOW - timedelta(seconds=10), "state_last_update": NOW - timedelta(seconds=10), "fields": {"admin_status": "UP", "oper_status": "UP", "in_errors": 0, "out_errors": 0}},
        ("R3", "eth1"): {"last_update": NOW - timedelta(seconds=10), "state_last_update": NOW - timedelta(seconds=10), "fields": {"admin_status": "UP", "oper_status": "UP"}},
        ("R1", "Ethernet2"): {"last_update": NOW - timedelta(seconds=10), "state_last_update": NOW - timedelta(seconds=10), "fields": {"admin_status": "UP", "oper_status": "UP"}},
    }
    return value


class TopologyModelTests(unittest.TestCase):
    def test_node_freshness_precedence_and_unknown(self):
        self.assertEqual(classify_node(monitored=True, last_update=NOW - timedelta(seconds=10), now=NOW, healthy_seconds=60, stale_seconds=120)[0], "HEALTHY")
        self.assertEqual(classify_node(monitored=True, last_update=NOW - timedelta(seconds=90), now=NOW, healthy_seconds=60, stale_seconds=120)[0], "STALE")
        self.assertEqual(classify_node(monitored=True, last_update=NOW - timedelta(seconds=121), now=NOW, healthy_seconds=60, stale_seconds=120)[0], "OFFLINE")
        self.assertEqual(classify_node(monitored=False, last_update=None, now=NOW, healthy_seconds=60, stale_seconds=120)[0], "UNKNOWN")

    def test_networkx_graph_and_layout_are_deterministic(self):
        first = build_base_graph(SNAPSHOT, 5840)
        second = build_base_graph(SNAPSHOT, 5840)
        self.assertEqual(set(first.nodes), {"R1", "R3", "H1"})
        self.assertEqual(first.number_of_edges(), 2)
        self.assertEqual({n: (first.nodes[n]["x"], first.nodes[n]["y"]) for n in first}, {n: (second.nodes[n]["x"], second.nodes[n]["y"]) for n in second})

    def test_real_health_overlay_uses_interface_evidence(self):
        graph = build_base_graph(SNAPSHOT, 5840)
        payload = overlay_health(graph, evidence(), CONFIG, now=NOW)
        validate_graph_payload(payload)
        nodes = {item["id"]: item for item in payload["graph"]["nodes"]}
        edges = {item["id"]: item for item in payload["graph"]["edges"]}
        self.assertEqual(nodes["R1"]["health"], "HEALTHY")
        self.assertEqual(nodes["R3"]["health"], "STALE")
        self.assertEqual(nodes["H1"]["health"], "UNKNOWN")
        self.assertEqual(edges["R1:eth1--R3:eth1"]["status"], "UP")
        self.assertEqual(edges["H1:eth1--R1:eth2"]["status"], "UP")

    def test_down_and_partial_freshness_precede_up(self):
        down = [
            {"node": "R1", "evidence_fresh": True, "admin_status": "UP", "oper_status": "DOWN", "last_update": "2026-09-07T20:00:00Z"},
            {"node": "R3", "evidence_fresh": True, "admin_status": "UP", "oper_status": "UP", "last_update": "2026-09-07T20:00:00Z"},
        ]
        self.assertEqual(classify_edge(down, [], {"R1", "R3"})[0], "DOWN")
        partial = [down[1], {"node": "R1", "evidence_fresh": False, "admin_status": None, "oper_status": None, "last_update": None}]
        self.assertEqual(classify_edge(partial, [], {"R1", "R3"})[0], "DEGRADED")

    def test_demo_is_labelled_and_does_not_replace_real_status(self):
        graph = build_base_graph(SNAPSHOT, 5840)
        payload = overlay_health(graph, evidence(), CONFIG, now=NOW, demo="safe-link-down")
        changed = [item for item in payload["graph"]["edges"] if item.get("synthetic")]
        self.assertEqual(payload["demo"]["mode"], "DEMO/SYNTHETIC")
        self.assertEqual(len(changed), 1)
        self.assertEqual(changed[0]["status"], "DOWN")
        self.assertEqual(changed[0]["real_status"], "UP")


if __name__ == "__main__":
    unittest.main()
