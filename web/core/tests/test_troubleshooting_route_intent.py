from __future__ import annotations

import copy
import json
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from django.test import SimpleTestCase

from core.services.troubleshooting import faults, route_intent
from core.services.troubleshooting import routing
from core.tests.test_troubleshooting_routing import lab

FX = Path(__file__).resolve().parent / "fixtures" / "troubleshooting_routing"
INTENT = FX / "acceptance-intent-v1.json"
NOW = datetime(2026, 11, 25, tzinfo=timezone.utc)


def evidence():
    ribs4, ribs6, _addresses, _links = lab()
    return {"ipv4": ribs4, "ipv6": ribs6}


class VersionedRouteIntentTests(SimpleTestCase):
    def test_reviewed_dual_stack_forward_and_return_intent_matches_baseline(self):
        intent = route_intent.load(INTENT)
        self.assertEqual(intent.revision, "srlceos01-h1-web-v1")
        self.assertEqual(len(intent.expectations), 22)
        self.assertEqual({item.direction for item in intent.expectations}, {"forward", "return"})
        self.assertEqual({item.af for item in intent.expectations}, {"ipv4", "ipv6"})

        results = route_intent.evaluate(intent, evidence(), now=NOW)
        self.assertTrue(all(result.category == faults.NO_FAULT for result in results))
        self.assertTrue(all(result.evidence["intent_revision"] == intent.revision for result in results))
        self.assertTrue(all(result.evidence["expectation_source"].startswith("VERSIONED_INTENT") for result in results))

    def test_missing_wrong_next_hop_and_wrong_source_are_distinct(self):
        intent = route_intent.load(INTENT)

        missing = evidence()
        del missing["ipv4"]["R1"]["172.30.50.10/32"]
        found = route_intent.evaluate(intent, missing, now=NOW)
        fault = next(r for r in found if r.scope["target_id"] == "h1-to-web-v4" and r.scope["device"] == "R1")
        self.assertEqual(fault.evidence["subtype"], routing.MISSING_ROUTE)

        wrong_hop = evidence()
        old = wrong_hop["ipv6"]["R3"]["2001:db8:3050::10/128"]
        wrong_hop["ipv6"]["R3"][old.prefix] = routing.RibEntry(
            old.prefix, old.source, old.raw_type, (("2001:db8:ffff::1", "eth9"),), old.af,
        )
        found = route_intent.evaluate(intent, wrong_hop, now=NOW)
        fault = next(r for r in found if r.scope["target_id"] == "h1-to-web-v6" and r.scope["device"] == "R3")
        self.assertEqual(fault.evidence["subtype"], routing.WRONG_NEXT_HOP)

        wrong_source = evidence()
        old = wrong_source["ipv4"]["S1"]["172.30.50.10/32"]
        wrong_source["ipv4"]["S1"][old.prefix] = routing.RibEntry(
            old.prefix, "static", "static", old.next_hops, old.af,
        )
        found = route_intent.evaluate(intent, wrong_source, now=NOW)
        fault = next(r for r in found if r.scope["target_id"] == "h1-to-web-v4" and r.scope["device"] == "S1")
        self.assertEqual(fault.evidence["subtype"], routing.UNEXPECTED_SOURCE)

    def test_missing_reader_is_inconclusive_not_a_missing_route(self):
        intent = route_intent.load(INTENT)
        ribs = evidence()
        ribs["ipv4"]["R4"] = None
        found = route_intent.evaluate(intent, ribs, now=NOW)
        fault = next(r for r in found if r.scope["target_id"] == "h1-to-web-v4" and r.scope["device"] == "R4")
        self.assertEqual(fault.category, faults.INDETERMINATE)
        self.assertNotIn("subtype", fault.evidence)

    def test_isolated_fault_campaign_restores_the_exact_baseline(self):
        intent = route_intent.load(INTENT)
        baseline = evidence()
        working = copy.deepcopy(baseline)
        before = route_intent.evaluate(intent, working, now=NOW)
        self.assertTrue(all(result.category == faults.NO_FAULT for result in before))

        del working["ipv4"]["R1"]["172.30.50.10/32"]
        during = route_intent.evaluate(intent, working, now=NOW)
        faults_seen = [r for r in during if r.category != faults.NO_FAULT]
        self.assertEqual(len(faults_seen), 1)
        self.assertEqual(faults_seen[0].evidence["subtype"], routing.MISSING_ROUTE)

        working = copy.deepcopy(baseline)
        after = route_intent.evaluate(intent, working, now=NOW)
        self.assertEqual(working, baseline)
        self.assertTrue(all(result.category == faults.NO_FAULT for result in after))

    def test_unknown_fields_family_mismatches_and_duplicate_targets_fail_closed(self):
        base = json.loads(INTENT.read_text(encoding="utf-8"))
        cases = []
        unknown = copy.deepcopy(base)
        unknown["unexpected"] = True
        cases.append(unknown)
        mismatch = copy.deepcopy(base)
        mismatch["targets"][0]["expectations"][0]["af"] = "ipv6"
        cases.append(mismatch)
        duplicate = copy.deepcopy(base)
        duplicate["targets"].append(copy.deepcopy(duplicate["targets"][0]))
        cases.append(duplicate)
        for payload in cases:
            with self.subTest(case=len(cases)):
                with tempfile.TemporaryDirectory() as directory:
                    path = Path(directory) / "intent.json"
                    path.write_text(json.dumps(payload), encoding="utf-8")
                    with self.assertRaises(route_intent.IntentError):
                        route_intent.load(path)
