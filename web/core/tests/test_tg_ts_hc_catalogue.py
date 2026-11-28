"""Direct tests for the RB02 reachability catalogue HC01-HC29 (troubleshooting/runbooks/hc.py).

Positive: every check is called on the evidence context the engine builds for the healthy simulated host lab and returns PASS
(the healthy expectation held).  Negative: the same checks are called with the evidence withheld or the intent removed and
refuse to judge -- a ``Gap`` (missing evidence is not evidence of absence), INCONCLUSIVE, or "does not apply" -- never a PASS.
"""

from __future__ import annotations

from unittest import mock

from django.test import TestCase

from core.services.troubleshooting.runbooks import base, hc
from core.tests.test_troubleshooting_engine import S, run_case

CHECKS = [f"hc{n:02d}" for n in range(1, 29)]
APPLIES = ["hc07_applies", "hc08_applies", "hc11_applies", "hc14_applies", "hc16_applies", "hc18_applies", "hc19_applies",
           "hc25_applies", "hc26_applies"]
# checks that read only the case / baselines / intent (no device evidence), and so stay PASS without observations
CONTEXT_ONLY = ("hc01", "hc02")
# checks that answer INCONCLUSIVE themselves (instead of raising a Gap) when their observations are absent
SELF_INCONCLUSIVE = ("hc05", "hc19", "hc28")


class HcCatalogueTests(TestCase):
    def setUp(self):
        engine, _stages = run_case("RB02", S.healthy_obs())
        self.healthy = engine._context()

    def clone(self, **over):
        h = self.healthy
        kw = dict(view=h.view, now=h.now, case=h.case, flow=h.flow, intent=h.intent, baselines=h.baselines, changes=h.changes,
                  path_fwd=h.path_fwd, path_ret=h.path_ret, results=h.results, intent_evidence_ids=h.intent_evidence_ids, alarms=h.alarms,
                  correlation=h.correlation)
        kw.update(over)
        return base.Ctx(**kw)

    def test_every_check_returns_pass_on_the_healthy_lab(self):
        for name in CHECKS:
            with self.subTest(check=name):
                result = getattr(hc, name)(self.clone())
                self.assertEqual(result.verdict, "PASS", f"{name}: {result.summary or result.reason}")
                self.assertTrue(result.summary)

    def test_applicability_returns_true_where_the_lab_has_the_feature(self):
        for name in APPLIES:
            with self.subTest(check=name):
                applies, why = getattr(hc, name)(self.clone())
                self.assertIs(applies, True)
                self.assertIsInstance(why, str)

    def test_select_strategy_returns_follow_the_path_for_a_known_path(self):
        strategy, why = hc.select_strategy(self.clone())
        self.assertEqual(strategy, "follow-the-path")
        self.assertIn("path", why)

    def test_withheld_evidence_is_refused_never_passed(self):
        empty = self.clone(view=base.EvidenceView([], self.healthy.now))
        for name in CHECKS:
            if name in CONTEXT_ONLY:
                continue
            check = getattr(hc, name)
            if name in SELF_INCONCLUSIVE:
                with self.subTest(f"{name} refuses a verdict without observations"):
                    self.assertEqual(check(empty).verdict, "INCONCLUSIVE")
                continue
            with self.subTest(check=name):
                with self.assertRaises(base.Gap) as caught:
                    check(empty)
                self.assertEqual(caught.exception.status, "INCONCLUSIVE")
                self.assertIn("not collected", caught.exception.reason)

    def test_absent_contract_or_change_history_is_refused(self):
        bare = self.clone(view=base.EvidenceView([], self.healthy.now), baselines={}, case={}, flow={})
        with self.subTest("an incomplete production contract is refused as inconclusive"):
            self.assertEqual(hc.hc01(bare).verdict, "INCONCLUSIVE")
        with self.subTest("an unavailable change history is refused as inconclusive"):
            self.assertEqual(hc.hc02(bare).verdict, "INCONCLUSIVE")

    def test_absent_intent_is_refused_applicability(self):
        bare = self.clone(view=base.EvidenceView([], self.healthy.now), intent={"nodes": [], "links": []}, path_fwd=[], path_ret=[],
                          results={}, correlation={}, case={}, flow={})
        for name in APPLIES:
            with self.subTest(f"{name} refuses to apply without intent"):
                applies, why = getattr(hc, name)(bare)
                self.assertIs(applies, False)
                self.assertTrue(why)
        with self.subTest("an unknown path refuses follow-the-path"):
            self.assertEqual(hc.select_strategy(bare)[0], "top-down")


class AdminStateIntentTests(TestCase):
    """HC29: managed-device admin state against the tracked configuration intent (the intent source is the inventory templates)."""

    def setUp(self):
        engine, _stages = run_case("RB02", S.healthy_obs())
        self.healthy = engine._context()

    def ctx_with(self, *observations):
        h = self.healthy
        return base.Ctx(view=base.EvidenceView(observations, h.now), now=h.now, case=h.case, flow=h.flow, intent=h.intent,
                        baselines=h.baselines, changes=h.changes, path_fwd=h.path_fwd, path_ret=h.path_ret)

    def admin(self, value):
        return base.Obs(key="interface.admin_state", device="r1", subject="Ethernet1", value=value, observed_at=self.healthy.now,
                        evidence_ids=("ev-admin",))

    def test_hc29_returns_pass_when_admin_state_matches_intent(self):
        with mock.patch.object(hc, "_intended_admin_states", return_value={"Ethernet1": "up"}):
            ctx = self.ctx_with(self.admin("up"))
            self.assertEqual(hc.hc29_applies(ctx)[0], True)
            result = hc.hc29(ctx)
        self.assertEqual((result.verdict, result.observed["checked"]), ("PASS", 1))

    def test_hc29_fails_a_deviation_and_refuses_uncovered_interfaces(self):
        with mock.patch.object(hc, "_intended_admin_states", return_value={"Ethernet1": "up"}):
            with self.subTest("an administratively down interface intended up is refused as a fault"):
                result = hc.hc29(self.ctx_with(self.admin("down")))
                self.assertEqual((result.verdict, result.finding.id), ("FAIL", "F-admin-state"))
        with mock.patch.object(hc, "_intended_admin_states", return_value={}):
            ctx = self.ctx_with(self.admin("up"))
            with self.subTest("an interface no tracked template covers is refused applicability and a verdict"):
                self.assertEqual(hc.hc29_applies(ctx)[0], False)
                self.assertEqual(hc.hc29(ctx).verdict, "INCONCLUSIVE")
