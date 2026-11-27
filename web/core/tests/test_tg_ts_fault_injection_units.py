"""Direct tests for the fault-campaign state store, controller summaries and the fixture driver
(troubleshooting/fault_injection.py).

Campaign state is written atomically to a private directory; a rollback that cannot verify the baseline is refused
instead of reported as restored; and the fixture driver contacts nothing.  Only the fixture driver is used: no
container, host or device is touched.
"""

from __future__ import annotations

import os
import stat
import tempfile
from pathlib import Path

from django.test import SimpleTestCase

from core.services.troubleshooting import fault_injection as fi
from core.tests import test_troubleshooting_fault_injection as FI

FAULT = {"id": "fixture-link-down", "fault_type": "admin_down", "object_name": "R1:Ethernet1"}
TOPOLOGY = 'topology:\n  links:\n    - endpoints: ["r1:eth1", "r2:eth3"]\n'


class StateStoreTests(SimpleTestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.store = fi.StateStore(os.path.join(self.tmp.name, "state"), "campaign-1")

    def mode(self, path):
        return stat.S_IMODE(os.stat(path).st_mode)

    def test_prepare_and_lock_create_a_private_directory_and_lock_file(self):
        self.store.prepare()
        self.assertEqual(self.mode(self.store.root), 0o700)
        with self.store.locked() as handle:
            self.assertFalse(handle.closed)
        self.assertEqual(self.mode(self.store.lock_path), 0o600)

    def test_save_writes_a_private_state_file_that_loads_back(self):
        self.store.save({"campaign_id": "campaign-1", "status": "ARMED"})
        self.assertEqual((self.store.load()["status"], self.mode(self.store.state_path)), ("ARMED", 0o600))

    def test_save_of_an_unserializable_state_raises_and_leaves_no_partial_file(self):
        self.store.save({"status": "ARMED"})
        with self.assertRaises(TypeError):
            self.store.save({"status": object()})
        self.assertEqual(self.store.load()["status"], "ARMED")
        self.assertEqual(sorted(p.name for p in self.store.root.iterdir()), ["campaign-1.json"])


class ControllerTests(SimpleTestCase):
    setUp = FI.CampaignTests.setUp
    prepare = FI.CampaignTests.prepare
    inject = FI.CampaignTests.inject
    # set by CampaignTests.setUp
    controller: fi.CampaignController
    driver: fi.FixtureDriver

    def test_summary_returns_only_non_ground_truth_fields(self):
        state = {"campaign_id": "c", "status": "ACTIVE", "events": [{}, {}], "baseline": {"admin_up": True}, "fault_id": "x"}
        self.assertEqual(fi.CampaignController.summary(state)["event_count"], 2)
        self.assertNotIn("baseline", fi.CampaignController.summary(state))

    def test_summary_of_an_empty_state_has_no_status(self):
        out = fi.CampaignController.summary({})
        self.assertEqual((out["status"], out["event_count"]), (None, 0))

    def test_rollback_refuses_an_unverified_restore_and_never_rolls_back_an_armed_campaign(self):
        self.prepare()
        with self.subTest("an armed campaign is not rolled back"):
            self.assertEqual(self.controller.rollback()["status"], "ARMED")
            self.assertNotIn("rollback", self.driver.calls)
        self.inject()
        self.driver.matches_baseline = lambda fault, baseline: False
        with self.subTest("an unverified restore is refused"), self.assertRaisesRegex(fi.FaultRefused, "ROLLBACK_VERIFICATION_FAILED"):
            self.controller.rollback(reason="unit")


class FixtureDriverTests(SimpleTestCase):
    def test_capture_baseline_and_protected_health_return_the_fixture_state(self):
        driver = fi.FixtureDriver()
        self.assertTrue(driver.capture_baseline(FAULT)["admin_up"])
        health = driver.protected_health([])
        self.assertEqual((health["management_ok"], health["families"]["IPv6"]["loss_pct"]), (True, 0.0))

    def test_capture_baseline_of_a_down_interface_never_records_it_up(self):
        driver = fi.FixtureDriver()
        driver.up = False
        self.assertFalse(driver.capture_baseline(FAULT)["admin_up"])

    def test_rollback_restores_and_matches_the_baseline(self):
        driver = fi.FixtureDriver()
        baseline = driver.capture_baseline(FAULT)
        driver.inject(FAULT, "op-1")
        self.assertEqual(driver.rollback(FAULT, baseline, "op-2"), {"operation_id": "op-2", "restored": True})
        self.assertTrue(driver.matches_baseline(FAULT, baseline))

    def test_rollback_to_a_down_baseline_never_brings_the_interface_up(self):
        driver = fi.FixtureDriver()
        driver.rollback(FAULT, {"admin_up": False}, "op-1")
        self.assertFalse(driver.up)

    def test_matches_baseline_of_an_injected_fault_is_a_mismatch(self):
        driver = fi.FixtureDriver()
        baseline = driver.capture_baseline(FAULT)
        driver.inject(FAULT, "op-1")
        with self.subTest("an injected fault is a mismatch"):
            self.assertFalse(driver.matches_baseline(FAULT, baseline))


class TopologyPeerTests(SimpleTestCase):
    def test_topology_peer_of_an_unknown_endpoint_or_missing_file_is_none(self):
        with tempfile.TemporaryDirectory() as root:
            Path(root, "lab.clab.yml").write_text(TOPOLOGY, encoding="utf-8")
            self.assertEqual(fi.topology_peer("lab", "r1", "eth1", root=Path(root)), ("r2", "eth3"))
            self.assertIsNone(fi.topology_peer("lab", "r1", "eth9", root=Path(root)))
            self.assertIsNone(fi.topology_peer("absent", "r1", "eth1", root=Path(root)))
