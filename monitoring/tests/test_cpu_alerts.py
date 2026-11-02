"""Offline unit tests for the NMAS collector-generated CPU threshold
evaluator (`modules/cpu_alerts.py`). No live device, no InfluxDB, and no
network access is used: `write_event`/`confirm_stored` are patched out, and
per-device state is redirected to a throwaway temporary directory for every
test.

These tests cover LAB_REQUIREMENTS.md section 14 item 5's mandatory
verification item at the unit level; monitoring/tests/verify_snmp.py plus
`modules.snmp.verify_cpu_threshold_alerting` separately prove the same logic
against a real, live SNMP-polled CPU value and a real InfluxDB write.
"""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from modules import cpu_alerts

POLICY = {"warning_pct": 70, "critical_pct": 90, "consecutive_samples": 3, "recovery_pct": 60}


class CpuAlertsTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        state_dir = Path(self._tmp.name)
        patcher = patch.object(cpu_alerts, "STATE_DIR", state_dir)
        patcher.start()
        self.addCleanup(patcher.stop)
        write_patcher = patch.object(cpu_alerts, "write_event")
        self.write_event = write_patcher.start()
        self.addCleanup(write_patcher.stop)

    def poll(self, device, value, *, platform="ceos", policy=None, verification=False, ts=1):
        return cpu_alerts.evaluate_cpu_threshold(
            device, platform, value, policy=policy or POLICY, verification=verification, timestamp_ns=ts
        )

    # 1. below threshold -> no event
    def test_below_threshold_produces_no_event(self):
        for i in range(5):
            self.assertIsNone(self.poll("R1", 10, ts=i))
        self.write_event.assert_not_called()

    # 1b. O2 regression: a non-finite / non-numeric sample is never "normal" -- it neither recovers nor raises an alert
    def test_invalid_samples_never_recover_an_active_alert_or_raise_a_new_one(self):
        for ts in range(1, 4):
            self.poll("R1", 95, ts=ts)                      # critical alert raised (1 event)
        state_before = cpu_alerts.load_state("R1")
        for ts, value in enumerate((float("nan"), float("inf"), float("-inf"), None, "12.5", True), start=10):
            with self.subTest(sample=repr(value)):
                self.assertIsNone(self.poll("R1", value, ts=ts))
        self.assertEqual(self.write_event.call_count, 1)    # no recovery from NaN, no second alert from +inf
        self.assertEqual(cpu_alerts.load_state("R1"), state_before)

    def test_invalid_samples_never_build_an_alert_streak(self):
        self.poll("R2", 95, ts=1)
        self.poll("R2", 95, ts=2)                           # 2/3 high
        self.assertIsNone(self.poll("R2", float("nan"), ts=3))
        self.assertEqual(cpu_alerts.load_state("R2")["streak"], 2)
        self.write_event.assert_not_called()

    # 2. one transient high sample when multiple samples required -> no alert
    def test_transient_spike_does_not_alert(self):
        self.assertIsNone(self.poll("R1", 95, ts=1))  # 1/3
        self.assertIsNone(self.poll("R1", 10, ts=2))  # drops back to normal, streak resets
        self.assertIsNone(self.poll("R1", 95, ts=3))  # 1/3 again
        self.write_event.assert_not_called()

    # 3. configured consecutive high samples -> exactly one alert
    def test_consecutive_high_samples_produce_exactly_one_alert(self):
        self.assertIsNone(self.poll("R1", 95, ts=1))
        self.assertIsNone(self.poll("R1", 95, ts=2))
        event = self.poll("R1", 95, ts=3)
        self.assertIsNotNone(event)
        self.assertEqual(event["transition"], "alert")
        self.assertEqual(event["severity"], "critical")
        self.assertEqual(event["consecutive_samples"], 3)
        self.assertEqual(self.write_event.call_count, 1)

    # 4. continuing high samples -> no duplicate event storm
    def test_continuing_high_samples_do_not_repeat_alert(self):
        for ts in range(1, 4):
            self.poll("R1", 95, ts=ts)
        self.assertEqual(self.write_event.call_count, 1)
        for ts in range(4, 20):
            event = self.poll("R1", 95, ts=ts)
            self.assertIsNone(event)
        self.assertEqual(self.write_event.call_count, 1)

    # 5. recovery -> exactly one recovery event
    def test_recovery_after_alert_produces_exactly_one_recovery_event(self):
        for ts in range(1, 4):
            self.poll("R1", 95, ts=ts)
        self.assertEqual(self.write_event.call_count, 1)
        recovery = self.poll("R1", 30, ts=5)
        self.assertIsNotNone(recovery)
        self.assertEqual(recovery["transition"], "recovery")
        self.assertEqual(recovery["previous_state"], "critical")
        self.assertEqual(self.write_event.call_count, 2)
        # Staying normal afterward must not re-fire recovery.
        for ts in range(6, 10):
            self.assertIsNone(self.poll("R1", 30, ts=ts))
        self.assertEqual(self.write_event.call_count, 2)

    # 6. device isolation: R1 alert state must never affect R2
    def test_device_state_is_isolated(self):
        for ts in range(1, 4):
            self.poll("R1", 95, ts=ts)
        self.assertEqual(self.write_event.call_count, 1)
        # R2 starts fresh even though R1 is currently alerting.
        self.assertIsNone(self.poll("R2", 95, ts=1))
        self.assertIsNone(self.poll("R2", 95, ts=2))
        event = self.poll("R2", 95, ts=3)
        self.assertIsNotNone(event)
        self.assertEqual(event["device"], "R2")
        self.assertEqual(self.write_event.call_count, 2)

    # 7. severity selection: warning vs critical
    def test_severity_selection_warning_then_escalation_to_critical(self):
        for ts in range(1, 4):
            event = self.poll("R1", 75, ts=ts)  # above warning_pct(70), below critical_pct(90)
        self.assertEqual(event["severity"], "warning")
        # Escalating to critical for another 3 consecutive samples fires a
        # second, distinct (non-duplicate) alert at the higher severity.
        for ts in range(4, 6):
            self.assertIsNone(self.poll("R1", 95, ts=ts))
        escalation = self.poll("R1", 95, ts=6)
        self.assertIsNotNone(escalation)
        self.assertEqual(escalation["severity"], "critical")
        self.assertEqual(escalation["previous_state"], "warning")
        self.assertEqual(self.write_event.call_count, 2)

    # 8 & 9. generated event explicitly says collector/NMAS, and never
    # claims to be a device trap.
    def test_event_identifies_as_collector_generated_not_a_device_trap(self):
        for ts in range(1, 4):
            event = self.poll("R1", 95, ts=ts)
        self.assertEqual(event["source"], "collector")
        self.assertEqual(event["alert_type"], "cpu_threshold")
        self.assertEqual(event["monitoring_method"], "snmp_polling")
        serialized = str(sorted(event.items()))
        self.assertNotIn("trap", serialized.lower())
        self.assertNotEqual(cpu_alerts.MEASUREMENT, "snmp_trap")
        self.assertEqual(cpu_alerts.MEASUREMENT, "collector_alert")

    # verification threshold does not mutate normal policy
    def test_verification_policy_never_mutates_production_policy(self):
        before = dict(cpu_alerts.PRODUCTION_POLICY)
        verification_policy = {"warning_pct": 1, "critical_pct": 2, "consecutive_samples": 1, "recovery_pct": 0.5}
        event = self.poll("R1", 1.5, policy=verification_policy, verification=True, ts=1)
        self.assertIsNotNone(event)
        self.assertTrue(event["verification"])
        self.assertEqual(cpu_alerts.PRODUCTION_POLICY, before)
        # And production state for the same device, under the default
        # (non-verification) policy, is completely unaffected.
        self.assertIsNone(self.poll("R1", 10, verification=False, ts=1))

    # verification state is isolated from production state for the same device
    def test_verification_state_is_isolated_from_production_state(self):
        for ts in range(1, 4):
            self.poll("R1", 95, ts=ts)  # production ALERT for R1
        self.assertEqual(self.write_event.call_count, 1)
        verification_policy = {"warning_pct": 1, "critical_pct": 2, "consecutive_samples": 1, "recovery_pct": 0.5}
        verification_event = self.poll("R1", 1.5, policy=verification_policy, verification=True, ts=1)
        self.assertIsNotNone(verification_event)
        self.assertTrue(verification_event["verification"])
        # Production state file is untouched: R1 remains in the alerted
        # state and a continued-high sample still does not duplicate.
        self.assertIsNone(self.poll("R1", 95, ts=10))
        self.assertEqual(self.write_event.call_count, 2)

    def test_policy_validation_rejects_bad_ordering(self):
        with self.assertRaises(cpu_alerts.NmasError):
            cpu_alerts.evaluate_cpu_threshold(
                "R1", "ceos", 50,
                policy={"warning_pct": 90, "critical_pct": 70, "consecutive_samples": 1, "recovery_pct": 60},
                timestamp_ns=1,
            )


if __name__ == "__main__":
    unittest.main()
