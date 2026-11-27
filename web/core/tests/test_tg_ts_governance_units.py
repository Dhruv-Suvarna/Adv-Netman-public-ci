"""Direct tests for the remediation governance ports and plan APIs (troubleshooting/governance.py).

The default executor supports nothing; the production binding is a hand-off to the existing Change workflow whose
``dry_run`` is the real, read-only eligibility gate.  Plans are tenant- and device-scoped; only a human rejects; only a
Tier 3 plan is pre-authorized; an interrupted execution is never retried.
"""

from __future__ import annotations

from datetime import timedelta
from unittest import mock

from django.test import SimpleTestCase

from core.services.test_governance.cases import case
from core.services.troubleshooting import governance as gov
from core.services.troubleshooting import repository as repo
from core.tests.test_troubleshooting_governance import AGENT, APPROVER, PROPOSER, T0, GovernanceBase, make_ports, propose


class RefusalAndExecutorTests(SimpleTestCase):
    def test_governance_exception_carries_code_message_and_details(self):
        err = gov.GovernanceRefused("NOT_PREAUTHORIZED", "tier 2", reasons=["x"])
        self.assertEqual((err.code, err.details, str(err)), ("NOT_PREAUTHORIZED", {"reasons": ["x"]}, "NOT_PREAUTHORIZED: tier 2"))

    def test_unconfigured_executor_returns_its_fail_closed_answers(self):
        ex = gov.UnconfiguredExecutor()
        self.assertEqual((ex.configured, ex.supports({}), ex.dry_run({})), (False, False, {"ok": False, "errors": ["no executor configured"]}))
        for name, call in (("apply", lambda: ex.apply({})), ("readback", lambda: ex.readback({})), ("compensate", lambda: ex.compensate({}, []))):
            with self.subTest(name=name):
                with self.assertRaises(gov.GovernanceRefused) as caught:
                    call()
                self.assertEqual(caught.exception.code, "EXECUTOR_UNCONFIGURED")

    @case("TS_CHANGE_ENGINE_APPLY_HANDS_OFF_TO_CHANGE_PAGE", target="web/core/services/troubleshooting/governance.py::ChangeEngineExecutor.apply",
          polarity="POSITIVE", condition="an operation that references an existing, validated Change reaches the troubleshooting executor",
          expected="the intended outcome is a hand-off: EXECUTION_VIA_CHANGE_WORKFLOW naming that Change and the Change page; "
                   "the change engine is never called from troubleshooting")
    def test_change_engine_executor_builds_a_handoff_binding(self):
        change = mock.Mock()
        ex = gov.ChangeEngineExecutor(lambda cid: change if cid == "CHG-1" else None, actor="troubleshooting",
                                      readback_provider=lambda plan: {"r1": "digest"},
                                      rollback_runner=lambda cid: {"ok": True, "change": cid})
        self.assertTrue(ex.configured)
        self.assertTrue(ex.references_change({"change_id": "CHG-1"}))
        report = mock.Mock(eligible=True, codes=[])
        with mock.patch("core.services.execution.eligibility.check_execution_eligibility", return_value=report):
            self.assertEqual(ex.dry_run({"operations": [{"change_id": "CHG-1"}]}),
                             {"ok": True, "errors": [], "mode": "eligibility-gate (read-only)"})
        self.assertEqual(ex.readback({}), {"r1": "digest"})
        self.assertEqual(ex.compensate({}, [{"change_id": "CHG-1"}]), {"results": [{"ok": True, "change": "CHG-1"}]})
        with mock.patch("core.services.execution.engine.execute_change") as engine, \
                self.assertRaises(gov.GovernanceRefused) as caught:      # execution itself stays on the Change page
            ex.apply({"change_id": "CHG-1"})
        engine.assert_not_called()
        self.assertEqual(caught.exception.code, gov.ChangeEngineExecutor.HANDOFF_CODE)
        self.assertIn("CHG-1", str(caught.exception))
        self.assertIn("Change page", str(caught.exception))


class PlanApiTests(GovernanceBase):
    def test_get_plan_returns_the_plan_of_the_tenant(self):
        plan = propose(self.case, self.ev)
        self.assertEqual(gov.get_plan(PROPOSER, plan.record_id).pk, plan.pk)

    def test_an_approver_decision_records_the_plan_as_closed_by_a_human(self):
        plan = propose(self.case, self.ev)
        self.assertEqual(gov.reject(APPROVER, plan.record_id, reason="the fault is upstream", now=T0).status, "REJECTED")

    def test_reject_by_an_agent_is_refused(self):
        plan = propose(self.case, self.ev)
        with self.assertRaises(gov.GovernanceRefused) as caught:
            gov.reject(AGENT, plan.record_id, reason="agent opinion", now=T0)
        self.assertEqual(caught.exception.code, "AGENT_CANNOT_APPROVE")
        with self.subTest("another tenant cannot reach the plan"):
            with self.assertRaises(repo.AccessDenied):
                gov.reject(repo.Actor("mallory", "user", tenant="other"), plan.record_id, reason="x" * 10, now=T0)

    def test_preauthorize_a_tier_two_plan_is_refused(self):
        plan = propose(self.case, self.ev)
        with self.assertRaises(gov.GovernanceRefused) as caught:
            gov.preauthorize(PROPOSER, plan.record_id, make_ports(), now=T0)
        self.assertEqual(caught.exception.code, "NOT_PREAUTHORIZED")

    def test_recover_returns_each_held_lease_untouched(self):
        plan = propose(self.case, self.ev)
        ex = gov.m.TsActionExecution.objects.create(record_id=repo._rid("EXE"), plan=plan, case=self.case, status="EXECUTING",
                                                    idempotency_key="held", lock_lease=f"lease:tok:{(T0 + timedelta(minutes=5)).isoformat()}")
        self.assertEqual(gov.recover(PROPOSER, self.case, make_ports(), now=T0), [{"execution": ex.record_id, "action": "LEASE_STILL_HELD"}])
        ex.refresh_from_db()
        self.assertEqual(ex.status, "EXECUTING")

    def test_action_availability_without_a_configured_executor_disables_writes_with_the_reason(self):
        plan = propose(self.case, self.ev, ports=gov.Ports(clock=lambda: T0))
        rows = gov.action_availability(plan, can_approve=True, ports=gov.Ports(clock=lambda: T0), now=T0)
        self.assertEqual((rows["dry_run"]["enabled"], rows["execute"]["enabled"]), (False, False))
        self.assertTrue(rows["dry_run"]["reason"])
        self.assertTrue(rows["reject"]["enabled"])
        with self.subTest("a viewer without the approver role cannot reject"):
            self.assertFalse(gov.action_availability(plan, can_approve=False, ports=gov.Ports(clock=lambda: T0), now=T0)["reject"]["enabled"])
