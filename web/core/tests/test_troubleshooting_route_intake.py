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
        self.assertEqual(len(result), 1)
        self.assertLessEqual({
            "route_intent": "HEALTHY", "intent_revision": "srlceos01-h1-web-v1",
            "topology_revision": REVISION, "evaluated": 22, "faults": 0,
            "inconclusive": 0, "age_seconds": 0.0,
        }.items(), result[0].items())
        self.assertEqual((result[0]["schema"], result[0]["state"], result[0]["severity"], result[0]["error_code"]),
                         (intake.ROUTE_INTENT_PASS_SCHEMA, "HEALTHY", "info", None))
        self.assertEqual(result[0]["routes"], {"expected": 22, "evaluated": 22, "devices": 6,
                                               "by_category": {faults.NO_FAULT: 22}})
        self.assertEqual(result[0]["items"], [])
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



class RouteIntentStructuredRecordTests(TestCase):
    """The route-intent pass record is the journal/monitoring contract: counts, classifications, correlation ids, error codes."""

    setUp = VersionedRouteIntentIntakeTests.setUp
    engine = VersionedRouteIntentIntakeTests.engine

    def test_every_pass_carries_a_unique_correlation_id(self):
        engine = self.engine()
        first, second = engine.poll(T0)[0], engine.poll(T0)[0]
        self.assertRegex(first["pass_id"], r"^RIP-[0-9a-f]{12}$")
        self.assertNotEqual(first["pass_id"], second["pass_id"])
        self.assertEqual(first["at"], T0.isoformat())

    def test_refusals_and_indeterminate_passes_carry_stable_error_codes(self):
        result = self.engine(topology_revision="0" * 40).poll(T0)[0]
        self.assertEqual((result["state"], result["severity"], result["error_code"]),
                         ("REFUSED", "error", "TOPOLOGY_REVISION_MISMATCH"))
        self.assertNotIn("routes", result)
        self.world.observed_at = T0 - timedelta(seconds=61)
        result = self.engine().poll(T0)[0]
        self.assertEqual((result["severity"], result["error_code"]), ("warning", "RIB_SNAPSHOT_STALE_OR_FUTURE"))
        self.world.observed_at = T0
        self.world.ribs["ipv4"]["R4"] = None
        result = self.engine().poll(T0)[0]
        self.assertEqual((result["state"], result["error_code"]), ("INDETERMINATE", "RIB_ENTRIES_INDETERMINATE"))
        self.assertEqual(result["routes"]["by_category"][faults.INDETERMINATE], 2)
        self.assertEqual({i["status"] for i in result["items"]}, {"INDETERMINATE"})

    def test_invalid_intent_error_code_is_the_prefix_not_the_message(self):
        result = self.engine(route_intent_path=str(INTENT.parent / "does-not-exist.json")).poll(T0)[0]
        self.assertEqual((result["state"], result["error_code"]), ("REFUSED", "INTENT_INVALID"))

    def test_reader_exception_becomes_an_error_record_and_monitoring_continues(self):
        engine = self.engine()
        engine.route_intent_reader = lambda reviewed, cfg: (_ for _ in ()).throw(RuntimeError("secret device output"))
        result = engine.poll(T0)
        self.assertEqual((result[0]["state"], result[0]["error_code"], result[0]["exception"]),
                         ("ERROR", "ROUTE_INTENT_PASS_EXCEPTION", "RuntimeError"))
        self.assertNotIn("secret device output", repr(result))
        self.assertEqual(engine.passes, 1)

    def test_pending_then_confirmed_fault_is_correlated_from_journal_to_case(self):
        del self.world.ribs["ipv4"]["R1"]["172.30.50.10/32"]
        engine = self.engine()
        first = engine.poll(T0)[0]
        self.assertEqual((first["state"], first["severity"]), ("DEGRADED", "warning"))
        fp = "RINT:srlceos01-h1-web-v1:h1-to-web-v4:R1"
        self.assertEqual([(i["fingerprint"], i["status"], i["route_prefix"]) for i in first["items"]],
                         [(fp, "PENDING_CONFIRMATION", "172.30.50.10/32")])
        self.assertEqual(first["confirmed_fingerprints"], [])

        self.world.observed_at = self.world.clock = T0 + timedelta(seconds=31)
        result = engine.poll(T0 + timedelta(seconds=31))
        passed = result[0]
        self.assertEqual(passed["confirmed_fingerprints"], [fp])
        self.assertEqual(passed["items"][0]["status"], "CONFIRMED")
        case_event = next(r for r in result if r.get("event") == "route_intent_case")
        self.assertEqual(case_event["schema"], intake.ROUTE_INTENT_CASE_SCHEMA)
        self.assertEqual((case_event["pass_id"], case_event["fingerprint"]), (passed["pass_id"], fp))
        self.assertEqual(case_event["decision"], faults.DIAGNOSE_AND_ESCALATE)
        case = models.TsCase.objects.get(case_id=case_event["case_id"])
        stored = models.TsEvidenceRef.objects.get(case=case, source_type="route_intent")
        self.assertIn(passed["pass_id"], stored.raw_blob.content)     # same correlation id persisted on the case evidence

    def test_records_carry_no_observed_next_hops_or_raw_rib(self):
        del self.world.ribs["ipv4"]["R1"]["172.30.50.10/32"]
        text = repr(self.engine().poll(T0))
        for leaked in ("192.168.100.1", "192.168.100.3", "next_hops", "ribs"):
            self.assertNotIn(leaked, text)


class IntakeJournalLineTests(TestCase):
    def test_structured_records_get_a_journald_priority_prefix(self):
        from core.management.commands.nmas_ts_intake import journal_line

        self.assertTrue(journal_line({"schema": "x", "severity": "warning", "a": 1}).startswith('<4>{"a": 1'))
        self.assertTrue(journal_line({"schema": "x", "severity": "error"}).startswith("<3>"))
        self.assertTrue(journal_line({"schema": "x", "severity": "info"}).startswith("<6>"))
        self.assertEqual(journal_line({"case": "TS-1"}), '{"case": "TS-1"}')       # legacy rows unchanged


class OpsStatusRouteIntentTests(TestCase):
    def test_last_pass_is_read_from_the_intake_journal(self):
        from core.management.commands.nmas_ts_ops_status import last_route_intent_pass

        rec = {"schema": intake.ROUTE_INTENT_PASS_SCHEMA, "pass_id": "RIP-0123456789ab", "at": T0.isoformat(),
               "state": "HEALTHY", "severity": "info", "error_code": None, "routes": {"evaluated": 22}, "items": []}
        import json
        lines = "\n".join(["intake: devices=()", json.dumps(rec), '{"fingerprint": "LINK:x", "skipped": "COOLDOWN"}'])
        out = last_route_intent_pass(reader=lambda: lines)
        self.assertEqual((out["available"], out["pass_id"], out["state"], out["routes"]),
                         (True, "RIP-0123456789ab", "HEALTHY", {"evaluated": 22}))
        self.assertEqual(last_route_intent_pass(reader=lambda: "nothing")["error_code"], "NO_ROUTE_INTENT_PASS_IN_JOURNAL")

    def test_binding_is_read_from_the_running_unit_environment(self):
        raw = (f"NMAS_TS_ROUTE_INTENT_FILE=/x/intent.json NMAS_TS_TOPOLOGY_REVISION={REVISION} "
               "NMAS_TS_ROUTE_INTENT_MAX_AGE_SECONDS=60 DJANGO_SECRET_KEY=never-echoed")
        out = intake.unit_route_intent_binding(reader=lambda: raw)
        self.assertEqual((out["bound"], out["intent_file"], out["topology_revision"]), (True, "/x/intent.json", REVISION))
        self.assertNotIn("never-echoed", repr(out))
