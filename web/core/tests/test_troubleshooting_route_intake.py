from __future__ import annotations

import copy
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

from django.test import TestCase

from core import models
from core.services.troubleshooting import faults, intake
from core.tests.test_troubleshooting_route_intent import evidence


INTENT = Path(__file__).resolve().parent / "fixtures" / "troubleshooting_routing" / "acceptance-intent-v1.json"
REVISION = "adf5fb5ac3c8bc0cbbc058595ee1207075b9cb30"
T0 = datetime(2026, 11, 26, tzinfo=timezone.utc)


class RouteIntentWorld:
    def __init__(self):
        self.ribs = evidence()
        self.observed_at = T0
        self.clock = T0
        self.service_telemetry = {}
        self.calls = 0

    def read(self, reviewed, cfg):
        self.calls += 1
        devices = {item.device for item in reviewed.expectations}
        return {
            "ribs": copy.deepcopy(self.ribs),
            "observed_at": self.observed_at.isoformat(),
            "device_observed_at": {device: self.observed_at.isoformat() for device in devices},
            "collector": "authorized-disposable-fixture-read",
            "gateway_evidence": [6239, 6240, 6240, True, "6241"],
            "service_telemetry": dict(self.service_telemetry),
            "service_devices": ["r1", "peer"] if self.service_telemetry else [],
        }


class VersionedRouteIntentIntakeTests(TestCase):
    def setUp(self):
        self.world = RouteIntentWorld()
        self.dispatched = []
        self.deps = intake.IntakeDeps(
            run_case=lambda actor, case_id, deps: None,
            open_handoff=lambda actor, case, **kw: SimpleNamespace(record_id="AIH-0123456789ab"),
            dispatch=lambda handoff: self.dispatched.append(handoff) or True,
            notify=lambda subject, body: None,
            maintenance=lambda devices: "",
        )

    def engine(self, **changes):
        values = dict(
            devices=(), routing_devices=(), routing_every=1, confirm_seconds=30,
            route_intent_path=str(INTENT), topology_revision=REVISION,
            route_intent_max_age_seconds=60, verify_clear=False,
        )
        values.update(changes)
        return intake.Intake(cfg=intake.IntakeConfig(**values), reader=lambda device, cfg: [],
                             deps=self.deps, _peers={}, route_reader=None,
                             adjacency_reader=lambda device, cfg: [], route_intent_reader=self.world.read,
                             freshness_clock=lambda: self.world.clock)

    def test_fresh_matching_snapshot_is_evaluated_without_opening_a_case(self):
        result = self.engine().poll(T0)
        self.assertEqual(result, [{
            "route_intent": "HEALTHY", "intent_revision": "srlceos01-h1-web-v1",
            "topology_revision": REVISION, "evaluated": 22, "faults": 0,
            "inconclusive": 0, "age_seconds": 0.0,
        }])
        self.assertEqual(self.world.calls, 1)
        self.assertFalse(models.TsCase.objects.exists())

    def test_topology_revision_mismatch_refuses_before_any_rib_read(self):
        result = self.engine(topology_revision="0" * 40).poll(T0)
        self.assertEqual(result[0]["route_intent"], "REFUSED")
        self.assertEqual(result[0]["reason"], "TOPOLOGY_REVISION_MISMATCH")
        self.assertEqual(self.world.calls, 0)

    def test_stale_or_unreadable_rib_is_indeterminate_never_missing_route(self):
        self.world.observed_at = T0 - timedelta(seconds=61)
        result = self.engine().poll(T0)
        self.assertEqual((result[0]["route_intent"], result[0]["reason"]),
                         ("INDETERMINATE", "RIB_SNAPSHOT_STALE_OR_FUTURE"))
        self.assertFalse(models.TsCase.objects.exists())

        self.world.observed_at = T0 + timedelta(seconds=1)
        result = self.engine().poll(T0)
        self.assertEqual((result[0]["route_intent"], result[0]["reason"]),
                         ("INDETERMINATE", "RIB_SNAPSHOT_STALE_OR_FUTURE"))
        self.assertFalse(models.TsCase.objects.exists())

        self.world.observed_at = T0
        self.world.ribs["ipv4"]["R4"] = None
        result = self.engine().poll(T0)
        self.assertEqual((result[0]["route_intent"], result[0]["inconclusive"]), ("INDETERMINATE", 2))
        self.assertFalse(models.TsCase.objects.exists())

    def test_confirmed_missing_route_opens_escalation_with_pinned_fresh_evidence(self):
        del self.world.ribs["ipv4"]["R1"]["172.30.50.10/32"]
        engine = self.engine()
        first = engine.poll(T0)
        self.assertEqual((first[0]["route_intent"], first[0]["faults"]), ("DEGRADED", 1))
        self.assertFalse(models.TsCase.objects.exists())

        self.world.observed_at = T0 + timedelta(seconds=31)
        self.world.clock = T0 + timedelta(seconds=31)
        self.world.service_telemetry = {"r1_peer_v4": False, "r1_peer_v6": True}
        result = engine.poll(T0 + timedelta(seconds=31))
        opened = [row for row in result if "case" in row]
        self.assertEqual(len(opened), 1, result)
        self.assertEqual((opened[0]["fingerprint"], opened[0]["category"], opened[0]["decision"]),
                         ("RINT:srlceos01-h1-web-v1:h1-to-web-v4:R1",
                          faults.ROUTE_OR_REACHABILITY_FAILURE, faults.DIAGNOSE_AND_ESCALATE))
        case = models.TsCase.objects.get(case_id=opened[0]["case"])
        self.assertEqual(case.service_intent["service"], "versioned per-prefix routing intent")
        self.assertEqual(case.affected_scope["route"]["target_id"], "h1-to-web-v4")
        observation = models.TsObservation.objects.get(case=case, key="intake.route_intent@h1-to-web-v4")
        self.assertEqual(observation.value["topology_revision"], REVISION)
        self.assertEqual(observation.value["classification"]["evidence"]["subtype"], "MISSING_ROUTE")
        self.assertEqual(observation.value["gateway_evidence"], [6239, 6240])
        correlation = models.TsCorrelationRecord.objects.get(case=case)
        self.assertEqual(correlation.metrics["devices"], ["peer", "r1"])
        self.assertEqual(correlation.metrics["failed_probes"], ["r1_peer_v4"])
        evidence_ref = models.TsEvidenceRef.objects.get(case=case, source_type="route_intent")
        self.assertEqual(evidence_ref.adapter, "nmas-intake")
        self.assertEqual(evidence_ref.collected_at, T0 + timedelta(seconds=31))
        self.assertEqual(len(self.dispatched), 1)
        self.assertFalse(models.TsRemediationPlan.objects.exists())

