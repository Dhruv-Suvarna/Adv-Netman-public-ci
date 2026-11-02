"""Offline contracts for the REAL_NODE_<name> race-safe comparison in
`verify_topology.py`.

These tests exercise `evaluate_real_node` directly with synthetic
API/InfluxDB observations -- no live topology service or InfluxDB instance
is required -- to prove the bounded-tolerance rewrite still rejects every
class of bad evidence the original exact-equality check rejected, and only
tolerates the one specific race (legitimate telemetry/cache skew) it was
changed to tolerate.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import unittest

from verify_topology import NODE_EVIDENCE_TOLERANCE_SECONDS, evaluate_real_node

NOW = datetime(2026, 9, 7, 23, 30, 0, tzinfo=timezone.utc)
HEALTHY_SECONDS = 60


def api_node(*, last_telemetry_timestamp, health="HEALTHY", **extra) -> dict:
    return {
        "last_telemetry_timestamp": last_telemetry_timestamp,
        "health": health,
        "telemetry_age_seconds": extra.pop("telemetry_age_seconds", 5.0),
        "monitoring_implementation": extra.pop("monitoring_implementation", "native cEOS gNMI"),
        **extra,
    }


def iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


class EvaluateRealNodeTests(unittest.TestCase):
    def test_identical_timestamp_passes(self):
        """API snapshot T1 + identical direct-Influx timestamp -> PASS.

        The historical baseline case: no telemetry advanced between the two
        reads at all, so the exact-equality check would also have passed --
        this proves the rewrite did not lose the original passing behaviour.
        """
        stamp = NOW - timedelta(seconds=10)
        node = api_node(last_telemetry_timestamp=iso(stamp))
        direct = {"last_update": stamp}
        passed, detail = evaluate_real_node(
            "R1", node, direct, now=NOW, healthy_seconds=HEALTHY_SECONDS,
        )
        self.assertTrue(passed, detail)

    def test_newer_direct_observation_inside_tolerance_passes(self):
        """API snapshot T1 + newer direct-Influx T2 inside tolerance -> PASS.

        This is the actual reproduced race: a real gNMI SAMPLE (~20s cadence)
        landed in InfluxDB after the topology backend cached its API
        response but before the verifier's own direct InfluxDB read. That is
        exactly the scenario this fix must stop treating as a failure.
        """
        api_stamp = NOW - timedelta(seconds=15)
        direct_stamp = api_stamp + timedelta(seconds=20)  # observed live skew ~20.0s
        self.assertLessEqual((direct_stamp - api_stamp).total_seconds(), NODE_EVIDENCE_TOLERANCE_SECONDS)
        node = api_node(last_telemetry_timestamp=iso(api_stamp))
        direct = {"last_update": direct_stamp}
        passed, detail = evaluate_real_node(
            "R1", node, direct, now=NOW, healthy_seconds=HEALTHY_SECONDS,
        )
        self.assertTrue(passed, detail)

    def test_direct_observation_stale_beyond_tolerance_fails(self):
        """Direct observation drastically older than the API snapshot, beyond
        the allowed bounds -> FAIL.

        Proves the bounded window is not a no-op: it still rejects direct
        evidence that disagrees with the API by far more than one legitimate
        telemetry/cache race, which would indicate stale or fabricated
        API-side evidence rather than an in-flight sample.
        """
        api_stamp = NOW - timedelta(seconds=5)
        direct_stamp = api_stamp - timedelta(seconds=NODE_EVIDENCE_TOLERANCE_SECONDS + 30)
        node = api_node(last_telemetry_timestamp=iso(api_stamp))
        direct = {"last_update": direct_stamp}
        passed, detail = evaluate_real_node(
            "R1", node, direct, now=NOW, healthy_seconds=HEALTHY_SECONDS,
        )
        self.assertFalse(passed, detail)

    def test_future_direct_observation_beyond_tolerance_fails(self):
        """Direct InfluxDB timestamp drastically in the future relative to the
        API snapshot -> FAIL (the symmetric counterpart of the stale case)."""
        api_stamp = NOW - timedelta(seconds=5)
        direct_stamp = api_stamp + timedelta(seconds=NODE_EVIDENCE_TOLERANCE_SECONDS + 30)
        node = api_node(last_telemetry_timestamp=iso(api_stamp))
        direct = {"last_update": direct_stamp}
        passed, detail = evaluate_real_node(
            "R1", node, direct, now=NOW, healthy_seconds=HEALTHY_SECONDS,
        )
        self.assertFalse(passed, detail)

    def test_mismatched_device_identity_fails(self):
        """Wrong device/source/category (mismatched identity) -> FAIL.

        `evidence["devices"].get(name)` in verify_topology.py is keyed by
        device identity (and the InfluxDB query that builds it is itself
        scoped to the system_identity/system_cpu/system_memory categories),
        so evidence collected for a different device or an unmatched
        category surfaces here as a lookup miss: `direct is None`. This
        proves identity/category matching was not weakened away.
        """
        node = api_node(last_telemetry_timestamp=iso(NOW - timedelta(seconds=10)))
        passed, detail = evaluate_real_node(
            "R1", node, None, now=NOW, healthy_seconds=HEALTHY_SECONDS,
        )
        self.assertFalse(passed, detail)
        self.assertIn("no direct InfluxDB evidence", detail)

    def test_api_node_not_healthy_fails(self):
        """API node not HEALTHY -> FAIL, even with perfectly matching,
        perfectly fresh timestamps -- health is still a hard requirement."""
        stamp = NOW - timedelta(seconds=10)
        node = api_node(last_telemetry_timestamp=iso(stamp), health="STALE")
        direct = {"last_update": stamp}
        passed, detail = evaluate_real_node(
            "R1", node, direct, now=NOW, healthy_seconds=HEALTHY_SECONDS,
        )
        self.assertFalse(passed, detail)

    def test_direct_evidence_stale_relative_to_now_fails_even_if_close_to_api(self):
        """Genuinely stale direct evidence must fail even when it agrees with
        (an equally stale) API timestamp -- freshness is checked against
        wall-clock `now`, not only against the API snapshot."""
        stamp = NOW - timedelta(seconds=HEALTHY_SECONDS + NODE_EVIDENCE_TOLERANCE_SECONDS + 30)
        node = api_node(last_telemetry_timestamp=iso(stamp), health="HEALTHY")
        direct = {"last_update": stamp}
        passed, detail = evaluate_real_node(
            "R1", node, direct, now=NOW, healthy_seconds=HEALTHY_SECONDS,
        )
        self.assertFalse(passed, detail)

    def test_missing_api_timestamp_fails(self):
        node = api_node(last_telemetry_timestamp=None)
        direct = {"last_update": NOW - timedelta(seconds=5)}
        passed, detail = evaluate_real_node(
            "R1", node, direct, now=NOW, healthy_seconds=HEALTHY_SECONDS,
        )
        self.assertFalse(passed, detail)


if __name__ == "__main__":
    unittest.main()
