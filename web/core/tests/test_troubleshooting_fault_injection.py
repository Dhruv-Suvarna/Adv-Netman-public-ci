import copy
import json
import os
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

from django.test import SimpleTestCase

from core.services.troubleshooting import fault_injection as fi


T0 = datetime(2026, 11, 15, 21, 0, tzinfo=timezone.utc)


def policy():
    path = Path(__file__).parents[3] / "deploy" / "sandbox" / "fault-campaign.fixture.json"
    return json.loads(path.read_text(encoding="utf-8"))


class PolicyTests(SimpleTestCase):
    def test_exact_fixture_policy_and_dual_stack_are_accepted(self):
        checked = fi.validate_policy(policy(), now=T0)
        self.assertEqual({f["family"] for f in checked["protected_flows"]}, {"IPv4", "IPv6"})

    def test_r5_wildcards_arbitrary_addresses_and_unknown_faults_are_refused(self):
        cases = []
        r5 = policy()
        r5["allowed_faults"][0]["device"] = "R5"
        cases.append(r5)
        wildcard = policy()
        wildcard["allowed_faults"][0]["device"] = "*"
        cases.append(wildcard)
        address = policy()
        address["allowed_faults"][0]["target_ip"] = "192.0.2.1"
        cases.append(address)
        unknown = policy()
        unknown["allowed_faults"][0]["fault_type"] = "arbitrary_cli"
        cases.append(unknown)
        for value in cases:
            with self.subTest(value=value["allowed_faults"][0]), self.assertRaises(fi.FaultRefused):
                fi.validate_policy(value, now=T0)

    def test_missing_ipv6_flow_is_refused(self):
        value = policy()
        value["protected_flows"] = [value["protected_flows"][0]]
        with self.assertRaisesRegex(fi.FaultRefused, "DUAL_STACK_PROTECTED_FLOWS_REQUIRED"):
            fi.validate_policy(value, now=T0)

    def test_unverified_or_ineligible_target_is_refused(self):
        for key in ("identity_verified", "lifecycle_eligible", "write_eligible"):
            value = policy()
            value["allowed_faults"][0][key] = False
            with self.subTest(key=key), self.assertRaisesRegex(fi.FaultRefused, "TARGET_NOT_ELIGIBLE"):
                fi.validate_policy(value, now=T0)


class CampaignTests(SimpleTestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.value = fi.validate_policy(policy(), now=T0)
        self.clock = [T0]
        self.driver = fi.FixtureDriver()
        self.store = fi.StateStore(self.tmp.name, self.value["campaign"]["id"])
        self.controller = fi.CampaignController(self.value, "fixture-link-down", self.store, self.driver,
                                                now=lambda: self.clock[0])
        self.confirm = fi.policy_digest(self.value)[:16]

    def prepare(self):
        return self.controller.prepare(authorization_id="FIXTURE-AUTH-1", confirm=self.confirm)

    def inject(self):
        return self.controller.inject(authorization_id="FIXTURE-AUTH-1", confirm=self.confirm)

    def test_full_mock_campaign_hides_ground_truth_and_restores(self):
        prepared = self.prepare()
        active = self.inject()
        watched = self.controller.watchdog()
        restored = self.controller.rollback(reason="fixture complete")
        self.assertEqual([prepared["status"], active["status"], watched["status"], restored["status"]],
                         ["ARMED", "ACTIVE", "ACTIVE", "RESTORED"])
        self.assertNotIn("baseline", active)
        self.assertNotIn("fault_id", active)
        self.assertTrue(self.driver.up)
        self.assertEqual(oct(os.stat(self.store.state_path).st_mode & 0o777), "0o600")
        self.assertEqual(oct(os.stat(self.store.root).st_mode & 0o777), "0o700")

    def test_wrong_authorization_or_policy_confirmation_is_refused(self):
        with self.assertRaisesRegex(fi.FaultRefused, "AUTHORIZATION_MISMATCH"):
            self.controller.prepare(authorization_id="WRONG", confirm=self.confirm)
        with self.assertRaisesRegex(fi.FaultRefused, "POLICY_CONFIRMATION_MISMATCH"):
            self.controller.prepare(authorization_id="FIXTURE-AUTH-1", confirm="0" * 16)

    def test_no_second_campaign_can_start(self):
        self.prepare()
        with self.assertRaisesRegex(fi.FaultRefused, "CAMPAIGN_ALREADY_RUNNING"):
            self.prepare()

    def test_ipv4_or_ipv6_loss_triggers_independent_rollback(self):
        for family in ("IPv4", "IPv6"):
            with self.subTest(family=family):
                if self.store.state_path.exists():
                    self.store.state_path.unlink()
                self.driver = fi.FixtureDriver()
                self.controller.driver = self.driver
                self.prepare()
                self.inject()
                self.driver.loss[family] = 0.1
                result = self.controller.watchdog()
                self.assertEqual(result["status"], "RESTORED")
                self.assertTrue(self.driver.up)

    def test_management_or_monitoring_failure_triggers_rollback(self):
        for attr in ("management_ok", "monitoring_ok"):
            with self.subTest(attr=attr):
                if self.store.state_path.exists():
                    self.store.state_path.unlink()
                self.driver = fi.FixtureDriver()
                self.controller.driver = self.driver
                self.prepare()
                self.inject()
                setattr(self.driver, attr, False)
                with self.assertRaisesRegex(fi.FaultRefused, "ROLLBACK_VERIFICATION_FAILED"):
                    self.controller.watchdog()
                self.assertTrue(self.driver.up)

    def test_deadline_expiry_rolls_back(self):
        self.prepare()
        self.inject()
        self.clock[0] = T0 + timedelta(seconds=31)
        result = self.controller.watchdog()
        self.assertEqual(result["status"], "RESTORED")
        self.assertTrue(self.driver.up)

    def test_preinjection_missing_health_prevents_any_fault(self):
        self.driver.loss["IPv6"] = 0.1
        with self.assertRaisesRegex(fi.FaultRefused, "PREINJECTION_HEALTH_FAILED"):
            self.prepare()
        self.assertNotIn("inject", self.driver.calls)

    def test_unrestricted_driver_is_refused(self):
        driver = copy.copy(self.driver)
        driver.restricted_interface = False
        with self.assertRaisesRegex(fi.FaultRefused, "UNRESTRICTED_DRIVER_REFUSED"):
            fi.CampaignController(self.value, "fixture-link-down", self.store, driver, now=lambda: T0)



class ContainerlabCeosDriverTests(SimpleTestCase):
    """Live driver logic against a scripted ``docker exec`` runner.  No container is contacted by these tests."""

    FAULT = {"id": "r2-eth9-down", "device": "R2", "platform": "arista_ceos", "object_type": "interface", "object_name": "Ethernet9",
             "fault_type": "admin_shutdown", "management_path_ref": "MP-000001", "identity_verified": True,
             "lifecycle_eligible": True, "write_eligible": True, "maximum_seconds": 60}
    FLOWS = [{"id": "v4", "family": "IPv4", "selector_ref": "FLOW-V4"}, {"id": "v6", "family": "IPv6", "selector_ref": "FLOW-V6"}]
    MAP = {"FLOW-V4": {"source": "H1", "destination": "10.0.0.1"}, "FLOW-V6": {"source": "H1", "destination": "2001:db8::1"}}

    def driver(self, *, loss="0", healthy=True, topology="srlceos01"):
        self.shutdown, self.calls = False, []

        def run(argv, timeout=20):
            self.calls.append(argv)
            self.assertEqual(argv[:2], ["/usr/bin/docker", "exec"])
            if argv[3] == "Cli":
                self.assertEqual(argv[2], "clab-srlceos01-R2")
                script = argv[-1].splitlines()
                if script[0] == "configure":
                    self.assertEqual(script[1], "interface Ethernet9")
                    self.assertNotIn("write memory", argv[-1])
                    self.shutdown = script[2] == "shutdown"
                    return 0, ""
                return 0, "interface Ethernet9\n   description lab\n" + ("   shutdown\n" if self.shutdown else "")
            return 0, f"5 packets transmitted, 5 received, {loss}% packet loss"
        return fi.ContainerlabCeosDriver(topology, self.MAP, run=run, management_probe=lambda: healthy)

    def test_full_cycle_injects_verifies_and_restores_the_exact_running_state(self):
        driver = self.driver()
        baseline = driver.capture_baseline(self.FAULT)
        self.assertTrue(baseline["admin_up"])
        receipt = driver.inject(self.FAULT, "op1")
        self.assertTrue(receipt["verified_down"])
        self.assertFalse(driver.matches_baseline(self.FAULT, baseline))
        self.assertTrue(driver.rollback(self.FAULT, baseline, "op2")["restored"])
        self.assertFalse(self.shutdown)
        health = driver.protected_health(self.FLOWS)
        self.assertEqual(health["families"], {"IPv4": {"measured": True, "loss_pct": 0.0}, "IPv6": {"measured": True, "loss_pct": 0.0}})

    def test_refuses_excluded_devices_other_objects_topologies_and_an_already_down_interface(self):
        driver = self.driver()
        for change in ({"device": "R5"}, {"device": "R2; reboot"}, {"object_name": "Management0"}, {"object_name": "Ethernet1\nreload"},
                       {"platform": "ubuntu_frr"}):
            with self.assertRaises(fi.FaultRefused):
                driver.capture_baseline({**self.FAULT, **change})
        self.assertEqual(self.calls, [])
        with self.assertRaises(fi.FaultRefused):
            self.driver(topology="other-lab")
        driver = self.driver()
        self.shutdown = True
        with self.assertRaises(fi.FaultRefused) as caught:
            driver.capture_baseline(self.FAULT)
        self.assertEqual(caught.exception.code, "BASELINE_UNAVAILABLE")

    def test_unmapped_or_unmeasured_flows_and_unhealthy_nmas_block_the_campaign(self):
        driver = fi.ContainerlabCeosDriver("srlceos01", {}, run=lambda argv, timeout=20: (0, ""), management_probe=lambda: True)
        self.assertEqual(driver.protected_health(self.FLOWS)["families"]["IPv4"], {"measured": False, "loss_pct": None})
        self.assertFalse(self.driver(healthy=False).protected_health(self.FLOWS)["management_ok"])
        self.assertEqual(self.driver(loss="40").protected_health(self.FLOWS)["families"]["IPv6"]["loss_pct"], 40.0)
