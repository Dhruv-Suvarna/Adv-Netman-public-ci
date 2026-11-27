"""Direct tests for the deterministic Troubleshooter engine (troubleshooting/engine.py).

The engine pipeline is driven stage by stage on the SIMULATED host-lab scenario (``fixtures/troubleshooting_runbooks``);
``run()`` end to end is covered by test_troubleshooting_engine.  The handoff gate refuses AI escalation while safe
applicable tests remain unexamined, and no disposition ever claims "resolved" without verification.
"""

from __future__ import annotations

from datetime import timedelta

from django.test import SimpleTestCase, TestCase

from core.services.troubleshooting import baselines as bl
from core.services.troubleshooting import engine as eng
from core.services.troubleshooting import repository as repo
from core.services.troubleshooting.runbooks import REGISTRY
from core.tests.test_troubleshooting_engine import ACTOR, T0, S, run_case


def open_case(scope=None, key="tg-engine"):
    scope = scope or S.DEVICES
    return repo.open_case(ACTOR, trigger_source="alert:test", idempotency_key=key, service_intent={"service": "web"}, flow_scope=S.FLOW,
                          affected_scope={"devices": scope}, target_states={d: "VERIFIED" for d in scope}, severity="HIGH", symptom="s",
                          worked_before=True, first_detected_at=T0 - timedelta(minutes=10), last_known_good_at=T0 - timedelta(hours=3),
                          runbook="RB02", now=T0 - timedelta(minutes=5))


def fixture(fail=()):
    return eng.ReplayProvider(S.to_fixture(S.healthy_obs(), fixture_id="tg-engine"), fail_devices=fail)


class ReplayAndHelperTests(SimpleTestCase):
    def test_replay_provider_collect_returns_simulated_bundles_for_the_device(self):
        provider = fixture()
        bundles = provider.collect("CASE-1", "r1", ["ospf.neighbor"], T0)
        self.assertTrue(bundles)
        self.assertTrue(all(b["schema"] == "collection_bundle/1" and b["targets"] == ["r1"] for b in bundles))
        self.assertTrue(all(b["raw"]["text"].startswith("[SIMULATED]") for b in bundles))     # never mistaken for live evidence
        self.assertEqual(provider.calls, [("r1", ("ospf.neighbor",))])

    def test_replay_provider_collect_raises_for_a_failing_or_unknown_device(self):
        with self.subTest("a failing device raises a timeout"):
            with self.assertRaises(TimeoutError):
                fixture(fail=["r1"]).collect("CASE-1", "r1", [], T0)
        with self.subTest("an unknown device yields no bundle"):
            self.assertEqual(fixture().collect("CASE-1", "nope", [], T0), [])

    def test_case_target_returns_the_first_affected_device(self):
        self.assertEqual(eng.case_target(type("C", (), {"affected_scope": {"devices": ["r1", "r2"]}})), "r1")

    def test_case_target_without_devices_is_empty(self):
        self.assertEqual(eng.case_target(type("C", (), {"affected_scope": {}})), "")

    def test_intended_flow_paths_returns_forward_and_reverse_hops(self):
        fwd, rev = eng.intended_flow_paths(S.intent(), S.FLOW)
        self.assertTrue(fwd)
        self.assertEqual([h["device"] for h in rev], [h["device"] for h in reversed(fwd)])
        self.assertEqual((rev[0]["in_if"], rev[0]["out_if"]), (fwd[-1]["out_if"], fwd[-1]["in_if"]))

    def test_intended_flow_paths_without_links_flow_or_route_is_empty(self):
        for label, intent, flow in (("no links", {}, S.FLOW), ("no flow", S.intent(), {}),
                                    ("an unreachable destination", S.intent(), {**S.FLOW, "dst": "nowhere"})):
            with self.subTest(f"{label} yields no path"):
                self.assertEqual(eng.intended_flow_paths(intent, flow), ([], []))


MATRIX_ROW = {"test_id": "t1", "applicable": True, "status": "EXECUTED", "reason": "ran"}


def dossier(**over):
    cm = {"unexamined_applicable": [], "applicability_matrix": [MATRIX_ROW] * 3, "executed_count": 3,
          "diagnosis": {"outcome": "INCONCLUSIVE_ESCALATED"}, "baselines": {"provenance": ["SIMULATED"]}}
    return {"coverage_manifest": {**cm, **over}}


class PolicyHelperTests(SimpleTestCase):
    def test_handoff_gate_refuses_unexamined_superficial_or_resolved_cases(self):
        cases = (("an unexamined applicable test", {"unexamined_applicable": ["t9"]}), ("a superficial run", {"executed_count": 1}),
                 ("a resolved case", {"diagnosis": {"outcome": "EXPECTED_BEHAVIOR_CONFIRMED"}}), ("missing provenance", {"baselines": {}}),
                 ("a skip without a reason", {"applicability_matrix": [{**MATRIX_ROW, "status": "NOT_APPLICABLE", "reason": "n/a"}]}))
        for label, over in cases:
            with self.subTest(f"{label} is refused"):
                self.assertFalse(eng.handoff_gate(dossier(**over))["allowed"])
        with self.subTest("an unresolved, fully examined case is not refused"):
            self.assertEqual(eng.handoff_gate(dossier()), {"allowed": True, "purpose": "CONTINUED_INVESTIGATION", "reasons": []})

    def test_disposition_for_never_claims_resolved_without_verification(self):
        for outcome in ("ROOT_CAUSE_IDENTIFIED_REMEDIATION_PENDING", "EXPECTED_BEHAVIOR_CONFIRMED", "INCONCLUSIVE_ESCALATED"):
            with self.subTest(f"{outcome} is not resolved"):
                diag = {"outcome": outcome, "root_cause": {"title": "x", "remediation_hint": "y"}, "reason": "gaps"}
                self.assertTrue(eng.disposition_for(diag)["resolved"].startswith("NO"))
        self.assertEqual(eng.disposition_for({"outcome": "RESOLVED_VERIFIED"})["resolved"], "yes")

    def test_proposed_remediations_returns_an_unexecuted_skeleton(self):
        rb = REGISTRY["RB02"]
        finding = next(iter(rb.remediations), "UNDEFINED-FINDING")
        out = eng.proposed_remediations(rb, {"root_cause": {"finding": finding, "device": "r1"}})
        self.assertEqual((len(out), out[0]["executed"], out[0]["device"]), (1, False, "r1"))
        manual = eng.proposed_remediations(rb, {"root_cause": {"finding": "NO-SUCH-FINDING", "device": "r1"}})
        self.assertEqual(manual[0]["tier"], 2)

    def test_proposed_remediations_without_a_root_cause_is_empty(self):
        self.assertEqual(eng.proposed_remediations(REGISTRY["RB02"], {"root_cause": None}), [])

    def test_compare_runs_flags_regressions_and_never_recovers_a_still_failing_test(self):
        before = {"a": {"verdict": "FAIL"}, "b": {"verdict": "PASS"}, "c": {"verdict": "FAIL"}}
        with self.subTest("a regression is never recovered"):
            out = eng.compare_runs(before, {"a": {"verdict": "PASS"}, "b": {"verdict": "FAIL"}, "c": {"verdict": "PASS"}})
            self.assertEqual((out["fixed"], out["regressions"], out["recovered"]), (["a", "c"], ["b"], False))
        with self.subTest("a still failing test is never recovered"):
            out = eng.compare_runs(before, {"a": {"verdict": "PASS"}, "b": {"verdict": "PASS"}, "c": {"verdict": "FAIL"}})
            self.assertEqual((out["still_failing"], out["recovered"]), (["c"], False))
        with self.subTest("a full fix recovers"):
            self.assertTrue(eng.compare_runs(before, {k: {"verdict": "PASS"} for k in before})["recovered"])


class StagewiseEngineTests(TestCase):
    def engine(self):
        case = open_case()
        return eng.Engine(ACTOR, case, "RB02", sources=bl.StaticSources(S.static_data(T0)), provider=fixture(), now=T0,
                          link_checker=lambda url: True)

    def test_engine_stages_run_in_order_and_build_a_valid_dossier(self):
        e = self.engine()
        plan = e.plan()
        self.assertEqual(sorted(plan), sorted(S.DEVICES))
        e.stages["collect"] = e.collect()
        self.assertTrue(e.stages["collect"])
        e.stages["normalize"] = e.normalize()
        e.stages["baseline"] = e.baseline()
        e.stages["correlate"] = e.correlate()
        e.stages["test"] = e.test()
        self.assertGreaterEqual(len(e.stages["test"]["matrix"]), 20)
        e.stages["diagnosis"] = e.diagnose()
        self.assertEqual(e.stages["diagnosis"]["outcome"], "EXPECTED_BEHAVIOR_CONFIRMED")
        dossier_ = e.exhaustion_dossier()
        self.assertEqual(dossier_["case_id"], e.case.case_id)
        self.assertTrue(dossier_["budget"]["read_only"])

    def test_load_view_returns_the_case_observations_visible_to_the_actor(self):
        e, _stages = run_case("RB02", S.healthy_obs())
        view = eng.load_view(ACTOR, e.case, T0)
        self.assertTrue(view._latest)  # pylint: disable=protected-access  # the view exposes lookups only; its index is the observed set
        narrow = repo.Actor("bob", "user", tenant=ACTOR.tenant, devices=frozenset({"r1"}))
        self.assertEqual({k[1] for k in eng.load_view(narrow, e.case, T0)._latest}, {"r1"})  # pylint: disable=protected-access

    def test_load_view_of_another_tenant_raises(self):
        e, _stages = run_case("RB02", S.healthy_obs())
        with self.assertRaises(repo.AccessDenied):
            eng.load_view(repo.Actor("mallory", "user", tenant="other"), e.case, T0)

    def test_request_ai_handoff_records_an_explanation_handoff(self):
        e, stages = run_case("RB02", S.healthy_obs())
        record = eng.request_ai_handoff(ACTOR, e.case, stages["dossier"], purpose="EXPLANATION", now=T0)
        self.assertEqual((record.status, record.allowed_tools), ("OPEN", stages["dossier"]["allowed_tools"]))
