"""V2 Phase 1: one canonical topology interpretation -- the tracked srlceos01.clab.yml matches the deployed lab."""

import unittest
from pathlib import Path

import yaml
from django.conf import settings
from django.test import SimpleTestCase

TOPOLOGY = Path(settings.REPO_ROOT) / "srlceos01.clab.yml"
INVENTORY = Path(settings.REPO_ROOT) / "inventory.yml"
RUNTIME_TOPOLOGY = Path("/home/student/clab-quickstart/srlceos01.clab.yml")
MANAGED = {"R1", "R2", "R3", "R4", "S1", "S2", "S3", "S4", "mgmt_swt"}
OUT_OF_SCOPE = {"R5", "WebServer", "H1", "H2", "H3", "H4"}
_KIND = {"ceos": "arista_ceos", "linux": "linux"}


class TopologySourceTests(SimpleTestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.topo = yaml.safe_load(TOPOLOGY.read_text())
        cls.inventory = yaml.safe_load(INVENTORY.read_text())

    def test_r3_r4_are_ubuntu_frr(self):
        nodes = self.topo["topology"]["nodes"]
        for name in ("R3", "R4"):
            self.assertEqual((nodes[name]["kind"], nodes[name]["image"]), ("linux", "ubuntu:24.04"), name)

    def test_node_kinds_agree_with_inventory_platforms(self):
        nodes = self.topo["topology"]["nodes"]
        devices = self.inventory["network_devices"]
        for name, entry in devices.items():
            platform = entry.get("monitoring", {}).get("platform")
            self.assertIn(name, nodes)
            self.assertEqual(nodes[name]["kind"], _KIND[platform], name)

    def test_management_scope_is_unchanged(self):
        mgmt_peers = set()
        for link in self.topo["topology"]["links"]:
            endpoints = link.get("endpoints") or []
            if any(e.startswith("mgmt_swt:") for e in endpoints):
                mgmt_peers |= {e.split(":")[0] for e in endpoints if not e.startswith("mgmt_swt:")}
        self.assertEqual(mgmt_peers, MANAGED - {"mgmt_swt"})
        self.assertFalse(mgmt_peers & OUT_OF_SCOPE)
        self.assertEqual(set(self.topo["topology"]["nodes"]), MANAGED | OUT_OF_SCOPE)

    @unittest.skipUnless(RUNTIME_TOPOLOGY.exists(), "runtime topology only present on the lab host")
    def test_tracked_topology_equals_runtime_definition(self):
        runtime = yaml.safe_load(RUNTIME_TOPOLOGY.read_text())
        self.assertEqual(self.topo["name"], runtime["name"])
        self.assertEqual(self.topo["topology"]["nodes"], runtime["topology"]["nodes"])
        self.assertEqual(self.topo["topology"]["links"], runtime["topology"]["links"])
