"""Direct tests for the three-reference baseline layer (troubleshooting/baselines.py).

Intent, the historical normal and the production contract each keep their own provenance; any source that cannot answer
is ``unavailable`` (never a guess), a policy actor is authorized only when its execution and audit records agree, and an
anomaly is a signal rather than a verdict.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

from django.test import SimpleTestCase, TestCase

from core import models as m
from core.services.troubleshooting import baselines as bl
from core.tests.test_tg_ts_engine_units import open_case
from core.tests.test_troubleshooting_engine import ACTOR, S, T0

NOW = datetime(2026, 11, 27, 6, 0, tzinfo=timezone.utc)


def iso(t):
    return t.isoformat().replace("+00:00", "Z")


class StaticSourceTests(SimpleTestCase):
    def test_static_sources_return_each_recorded_source(self):
        src = bl.StaticSources(S.static_data(T0))
        for name, value in (("intent", src.intent([], {})), ("history", src.history({}, [], T0)), ("slo", src.slo({})),
                            ("changes", src.changes([], T0, T0)), ("configs", src.configs([]))):
            with self.subTest(name=name):
                self.assertEqual((value["status"], value["source"]), ("available", f"static:{name}"))

    def test_distinct_provenance_keeps_each_reference_separate(self):
        bs = bl.gather(bl.StaticSources(S.static_data(T0)), devices=["r1"], flow=S.FLOW, now=T0, onset=T0)
        prov = bl.distinct_provenance(bs)
        self.assertEqual(prov["historical_normal"], "static:history")
        self.assertIn("golden-r7", prov["intended_design"])

    def test_distinct_provenance_of_unavailable_sources_names_them_unknown(self):
        failing = bl.StaticSources({}, fail=["intent", "golden", "history", "slo"])
        prov = bl.distinct_provenance(bl.gather(failing, devices=["r1"], flow=S.FLOW, now=T0, onset=T0))
        self.assertEqual(prov, {"intended_design": "intent|golden@-", "historical_normal": "history", "production_contract": "slo"})

    def test_gather_of_failing_sources_keeps_every_key_unavailable(self):
        bs = bl.gather(bl.StaticSources({}, fail=["changes", "golden"]), devices=["r1"], flow=S.FLOW, now=T0, onset=T0)
        self.assertEqual((bs["changes"]["status"], bs["classified_changes"], bs["soak_window"]["state"]), ("unavailable", [], "NONE"))


class Topology:
    def __init__(self, fail=False):
        self.fail = fail

    def get_topology_summary(self):
        if self.fail:
            raise ConnectionError("topology service down")
        return {"status": "available", "generated_at": "2026-11-27T06:00:00Z",
                "data": {"graph": {"nodes": [{"id": "r1", "health": "ok"}], "edges": [{"source": "r1", "target": "r2"}]}}}


NSOT = SimpleNamespace(get_devices=lambda: {"status": "available", "data": [{"name": "r1", "role": "router", "platform": "ceos"}]})


class DjangoSourceTests(SimpleTestCase):
    def test_django_intent_returns_netbox_and_topology_with_limitations(self):
        out = bl.DjangoBaselineSources(nsot=NSOT, topology=Topology()).intent(["r1"], {})
        self.assertEqual((out["status"], out["nodes"][0]["role"], len(out["links"])), ("available", "router", 1))
        self.assertTrue(out["limitations"])                       # topology edges carry no interface names

    def test_django_intent_of_a_failing_topology_is_unavailable(self):
        out = bl.DjangoBaselineSources(nsot=NSOT, topology=Topology(fail=True)).intent(["r1"], {})
        self.assertEqual((out["status"], out["source"]), ("unavailable", "netbox+topology"))

    def test_django_slo_returns_the_declared_case_contract(self):
        out = bl.DjangoBaselineSources(nsot=NSOT, topology=Topology()).slo({"slo": {"max_loss_pct": 1.0}, "slo_revision": "slo-3"})
        self.assertEqual((out["status"], out["contract"], out["revision"]), ("available", {"max_loss_pct": 1.0}, "slo-3"))

    def test_django_slo_without_a_declared_contract_is_unavailable(self):
        self.assertEqual(bl.DjangoBaselineSources(nsot=NSOT, topology=Topology()).slo({})["status"], "unavailable")


def series(n, *, start=NOW - timedelta(hours=1), value=10.0):
    return [{"t": iso(start - timedelta(minutes=5 * i)), "value": value + (i % 3)} for i in range(n)]


class LearnedNormalTests(SimpleTestCase):
    def test_learn_history_and_anomaly_returns_a_learned_normal(self):
        stats = bl.learn_history(series(40), now=NOW, key="flow:web")
        self.assertEqual((stats["state"], stats["samples"]), ("LEARNED", 40))
        self.assertTrue(bl.anomaly(500.0, stats)["anomalous"])
        self.assertFalse(bl.anomaly(11.0, stats, at=NOW)["anomalous"])

    def test_anomaly_against_an_unknown_or_stale_normal_makes_no_comparison(self):
        for label, stats in (("too few samples", bl.learn_history(series(3), now=NOW)),
                             ("a stale history", bl.learn_history(series(40, start=NOW - timedelta(days=60)), now=NOW))):
            with self.subTest(f"{label} is not compared"):
                self.assertIsNone(bl.anomaly(500.0, stats)["anomalous"])

    def test_soak_window_returns_an_active_window_containing_the_onset(self):
        soak = {"active": True, "soak_id": "SOAK-1", "started_at": iso(NOW - timedelta(hours=1)), "required_end_at": iso(NOW + timedelta(hours=1))}
        self.assertEqual((bl.soak_window(soak, NOW)["state"], bl.soak_window(soak, NOW)["onset_in_window"]), ("ACTIVE", True))

    def test_soak_window_without_an_active_soak_never_contains_the_onset(self):
        for label, soak in (("no soak", None), ("an ended soak", {"active": False, "state": "PASSED", "started_at": iso(NOW - timedelta(hours=1)),
                                                                 "required_end_at": iso(NOW + timedelta(hours=1))})):
            with self.subTest(f"{label} does not contain the onset"):
                self.assertFalse(bl.soak_window(soak, NOW)["onset_in_window"])

    def test_classify_changes_never_infers_approval_or_authorization(self):
        out = bl.classify_changes([{"change_id": "A"}, {"change_id": "B", "approved": "yes"}, {"change_id": "C", "approved": True, "authorized": False}],
                                  soak=None, onset=NOW)
        self.assertEqual([(c["approved"], c["approval_known"], c["authorized"]) for c in out],
                         [(False, False, False), (False, True, False), (True, True, False)])


class AuthorizationAndPersistenceTests(TestCase):
    def run_of(self, actor):
        return SimpleNamespace(change=SimpleNamespace(change_id="CHG-1"), actor=actor)

    def test_execution_authorization_returns_human_approval_for_a_person(self):
        self.assertEqual(bl.execution_authorization(self.run_of("alice"), human_approved=True)["authorization_mode"], "HUMAN_APPROVAL")

    def test_execution_authorization_refuses_an_unsupported_policy_actor(self):
        out = bl.execution_authorization(self.run_of("nmas-policy:ARP-1"), human_approved=False)
        self.assertEqual((out["authorization_mode"], out["authorized"]), ("NONE", False))
        self.assertIn("NOT treated as authorized", out["authorization_note"])

    def test_persist_baselines_of_unavailable_sources_records_no_link(self):
        case = open_case(key="tg-baselines")
        bs = bl.gather(bl.StaticSources({}, fail=["intent", "golden", "history", "slo"]), devices=["r1"], flow=S.FLOW, now=T0, onset=T0)
        records, _ev = bl.persist_baselines(ACTOR, case, bs, now=T0, link_checker=lambda url: True)
        golden = next(r for r in records if r.baseline_type == "GOLDEN_CONFIG")
        self.assertEqual((golden.operator_url, golden.link_status, golden.data["status"]), ("", "MISSING", "unavailable"))
        self.assertEqual(m.TsBaselineReference.objects.filter(case=case).count(), 4)
