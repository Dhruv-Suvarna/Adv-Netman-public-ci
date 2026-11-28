"""Direct tests for the Troubleshooter case repository (troubleshooting/repository.py).

Every read and write is tenant- and device-scoped, every probe passes the VERIFIED-target gate, collection runs are
read-only, idempotent and resumable, and claims resolve to their evidence (dangling references are reported, not hidden).
"""

from __future__ import annotations

from datetime import timedelta

from django.test import SimpleTestCase, TestCase

from core import models as m
from core.services.troubleshooting import contracts as c
from core.services.troubleshooting import repository as repo
from core.tests.test_tg_ts_engine_units import open_case
from core.tests.test_troubleshooting_engine import ACTOR, T0

OTHER_TENANT = repo.Actor("mallory", "user", tenant="other")
NARROW = repo.Actor("bob", "user", tenant=ACTOR.tenant, devices=frozenset({"r1"}))


class ActorTests(SimpleTestCase):
    def test_actor_can_see_device_within_its_scope(self):
        self.assertTrue(ACTOR.can_see_device("r9"))                 # no device list: every device of the tenant
        self.assertTrue(NARROW.can_see_device("r1"))
        self.assertTrue(NARROW.can_see_device(""))                  # a device-less record is tenant-scoped only

    def test_actor_cannot_see_a_device_outside_its_list(self):
        self.assertFalse(NARROW.can_see_device("r2"))


class CaseScopeTests(TestCase):
    def setUp(self):
        self.case = open_case(key="tg-repo")

    def evidence(self, device="r1"):
        return repo.store_evidence(ACTOR, self.case, source_type="cli", device=device, command_or_api="show version", adapter="unit",
                                   adapter_version="1", collected_at=T0, raw="version 4.36.2F")

    def test_get_case_returns_the_case_of_the_tenant(self):
        self.assertEqual(repo.get_case(ACTOR, self.case.case_id).pk, self.case.pk)

    def test_list_cases_never_returns_cases_outside_the_tenant_or_devices(self):
        with self.subTest("another tenant lists nothing"):
            self.assertEqual(repo.list_cases(OTHER_TENANT), [])
        with self.subTest("a device filter outside the case lists nothing"):
            self.assertEqual(repo.list_cases(ACTOR, device="nowhere"), [])
        with self.subTest("a narrow actor without a case device lists nothing"):
            self.assertEqual(repo.list_cases(repo.Actor("eve", "user", tenant=ACTOR.tenant, devices=frozenset({"zz"}))), [])

    def test_authorize_probe_allows_a_verified_target_in_scope(self):
        self.assertIsNone(repo.authorize_probe(ACTOR, self.case, "r1", now=T0))

    def test_close_case_closes_with_a_disposition(self):
        closed = repo.close_case(ACTOR, self.case, "NO_FAULT_FOUND", disposition={"outcome": "EXPECTED_BEHAVIOR_CONFIRMED"}, now=T0)
        self.assertEqual(closed.state, "NO_FAULT_FOUND")

    def test_get_evidence_returns_the_stored_reference(self):
        ref = self.evidence()
        self.assertEqual(repo.get_evidence(ACTOR, ref.evidence_id).pk, ref.pk)
        self.assertEqual(repo.get_evidence(NARROW, ref.evidence_id).device, "r1")

    def test_trace_claim_of_an_unknown_record_is_refused(self):
        with self.assertRaises(repo.AccessDenied):
            repo.trace_claim(ACTOR, self.case, "OBS-NOPE")

    def test_stage_journal_of_another_tenant_is_refused(self):
        with self.assertRaises(repo.AccessDenied):
            repo.stage_journal(OTHER_TENANT, self.case)
        self.assertEqual([r["kind"] for r in repo.stage_journal(ACTOR, self.case)], [])

    def run_(self, key="run-1", **kw):
        return repo.begin_collection_run(ACTOR, self.case, idempotency_key=key, collector="cli", targets=["r1"], command_or_api="show version",
                                         now=T0, **kw)

    def test_start_attempt_refuses_beyond_the_retry_budget(self):
        run = self.run_(max_attempts=1)
        self.assertEqual(repo.start_attempt(ACTOR, run, now=T0).status, "RUNNING")
        with self.subTest("an exhausted budget fails the run"):
            self.assertEqual(repo.start_attempt(ACTOR, run, now=T0).status, "FAILED")
        with self.subTest("a finished run is never restarted"):
            self.assertEqual(repo.start_attempt(ACTOR, run, now=T0).status, "FAILED")

    def test_finish_run_refuses_a_non_final_status_and_is_idempotent(self):
        run = self.run_()
        with self.subTest("a non-final status is refused"):
            with self.assertRaises(ValueError):
                repo.finish_run(ACTOR, run, "RUNNING", now=T0)
        done = repo.finish_run(ACTOR, run, "SUCCEEDED", now=T0)
        with self.subTest("a duplicate completion never changes the outcome"):
            self.assertEqual(repo.finish_run(ACTOR, run, "FAILED", error="late", now=T0).status, done.status)

    def test_resumable_runs_never_include_finished_runs(self):
        a, b = self.run_("run-a"), self.run_("run-b")
        repo.finish_run(ACTOR, a, "SUCCEEDED", now=T0)
        self.assertEqual([r.pk for r in repo.resumable_runs(ACTOR, self.case)], [b.pk])
        with self.subTest("another tenant cannot resume"):
            with self.assertRaises(repo.AccessDenied):
                repo.resumable_runs(OTHER_TENANT, self.case)

    def test_gap_recording_returns_an_explicit_unknown_record(self):
        obs = repo.record_missing_data(ACTOR, self.case, key="ospf.neighbor", target="r1", reason="permission denied", observed_at=T0)
        self.assertEqual((obs.is_missing_data, obs.quality, obs.value), (True, "MISSING", None))
        self.assertEqual(repo.current_state(ACTOR, self.case, "ospf.neighbor", "r1", T0)["state"], c.UNKNOWN)

    def observe(self, value, at=T0, max_age=300):
        ref = self.evidence()
        return repo.record_observation(ACTOR, self.case, key="intf.oper", target="r1", observed_at=at, value=value, evidence=ref,
                                       max_age_seconds=max_age)

    def test_evaluate_observation_and_current_state_returns_fresh_health(self):
        obs = self.observe("up")
        self.assertEqual(repo.evaluate_observation(obs, T0 + timedelta(seconds=10)), c.FRESH)
        st = repo.current_state(ACTOR, self.case, "intf.oper", "r1", T0 + timedelta(seconds=10), predicate=lambda v: v == "up")
        self.assertEqual((st["freshness"], st["observation_id"]), (c.FRESH, obs.record_id))

    def test_evaluate_observation_of_stale_data_is_never_fresh(self):
        obs = self.observe("up", max_age=60)
        self.assertEqual(repo.evaluate_observation(obs, T0 + timedelta(minutes=5)), c.STALE)
        self.assertEqual(repo.current_state(ACTOR, self.case, "intf.oper", "r1", T0 + timedelta(minutes=5), predicate=lambda v: True)["state"],
                         c.UNKNOWN)

    def test_update_hypothesis_records_supported_state_with_evidence(self):
        ref = self.evidence()
        hyp = repo.record(ACTOR, self.case, "hypothesis", basis="DERIVED", now=T0, title="link down", failure_domain="L1", ranking=1,
                          confidence=0.0, state="OPEN", test_ids=["hc01"], proposed_by="unit", stage_decision="unit hypothesis")
        out = repo.update_hypothesis(ACTOR, hyp, state="SUPPORTED", supporting=[ref.evidence_id], confidence=0.7, now=T0)
        self.assertEqual((out.state, out.supporting_evidence, out.confidence), ("SUPPORTED", [ref.evidence_id], 0.7))


class ExceptionStatusTests(SimpleTestCase):
    def policy(self, **kw):
        base = {"status": "ACTIVE", "expires_at": T0 + timedelta(hours=1), "bound_revisions": {"golden": "g7"}}
        return m.TsExceptionPolicy(**{**base, **kw})

    def test_exception_status_is_never_active_once_revoked_expired_or_invalidated(self):
        cases = (("a revoked policy", {"status": "REVOKED"}, {"golden": "g7"}, "REVOKED"),
                 ("an expired policy", {"expires_at": T0}, {"golden": "g7"}, "EXPIRED"),
                 ("a changed revision", {}, {"golden": "g8"}, "INVALIDATED"))
        for label, over, revisions, status in cases:
            with self.subTest(f"{label} is {status}"):
                self.assertEqual(repo.exception_status(self.policy(**over), revisions, T0), status)
        with self.subTest("an unchanged, unexpired policy is not refused"):
            self.assertEqual(repo.exception_status(self.policy(), {"golden": "g7"}, T0), "ACTIVE")
