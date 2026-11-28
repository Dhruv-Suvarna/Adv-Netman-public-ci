"""Closing an orphaned isolation apply / release transition Change as SUPERSEDED (``isolation.supersede``).

The two production shapes are rebuilt on the real isolation services and the in-memory upstream: an apply whose execution
lease expired (INTERRUPTED, lifecycle untouched) and whose policy ``reconcile`` then proved ENFORCED; and a release whose run
was BLOCKED while its admission finished RESTORED.  Closure is one append-only lifecycle event + audit row; nothing is sent to
the upstream, nothing is deleted.
"""

from __future__ import annotations

import io
from datetime import timedelta

from django.core.management import call_command
from django.test import TestCase
from django.utils import timezone

from core import models
from core.management.commands import nmas_transition_supersede as cmd
from core.services import change_service
from core.services.commissioning import acceptance
from core.services.execution.executors.ceos import _eos_commands
from core.services.isolation import service as iso
from core.services.isolation import supersede as S
from core.services.isolation import transaction as T
from core.tests.helpers import isolation as I
from core.tests.helpers import lifecycle as L
from core.tests.helpers import ztp as Z

St = models.IsolationState
Life = models.ChangeLifecycleState
REASON = "Work completed through a later governed path; this Change can never run again."


def run_for(change, *, state=models.ExecutionRunState.FINISHED, outcome="INTERRUPTED"):
    plan, validation = T.latest_plan(change), T.latest_validation(change)
    now = timezone.now()
    return models.ChangeExecutionRun.objects.create(
        change=change, plan=plan, validation_run=validation, mode=models.ExecutionMode.COMPLETE, state=state, outcome=outcome,
        actor=L.APPROVER, engine_version="test", plan_hash=plan.plan_hash, validation_input_hash=validation.input_hash,
        validation_source_hash=validation.source_hash, started_at=now - timedelta(minutes=5), lease_expires_at=now - timedelta(minutes=1),
        finished_at=None if state == models.ExecutionRunState.RUNNING else now)


class Base(Z.ZtpTestMixin, TestCase):
    real_isolation_gate = True

    def interrupted_apply(self):
        """The CHG-20261027-0008 shape: approved apply, lease-expired run, upstream holds the policy, reconcile -> ENFORCED."""
        flow = I.Flow(self)
        flow.approved()
        for op in iso.ops_of(flow.policy):
            flow.session.send_config_set(_eos_commands(op["lines"]))
        run_for(flow.policy.apply_change)
        iso._save(flow.refresh(), state=St.APPLYING)
        reconciled = iso.reconcile(flow.refresh(), actor=L.APPROVER, access=flow.access)
        self.assertEqual(reconciled.policy.state, St.ENFORCED, reconciled.codes)
        flow.refresh()
        return flow, flow.policy.apply_change

    def restored_release(self, *, admission_state=models.AdmissionState.RESTORED):
        """The CHG-20261103-0005 shape: approved release Change, BLOCKED run, admission finished RESTORED."""
        flow = I.Flow(self)
        flow.verified()
        self.assertTrue(iso.create_release(flow.refresh(), actor=L.OPERATOR, reference={"test": True}).ok)
        self.assertTrue(iso.release_precheck(flow.refresh(), actor=L.OPERATOR, access=flow.access).ok)
        plan_hash = T.latest_plan(flow.refresh().release_change).plan_hash
        self.assertTrue(iso.approve_release(flow.refresh(), actor=L.APPROVER, requested_by=L.OPERATOR, confirmation=plan_hash, extra={}).ok)
        change = flow.refresh().release_change
        run_for(change, outcome="BLOCKED")
        record = models.CommissioningRecord(device=flow.device, isolation_policy=flow.policy, requested_by=L.OPERATOR)
        record.__dict__["_commissioning_write"] = True                    # the model's sanctioned fixture write
        record.save()
        admission = models.ProductionAdmission(
            commissioning=record, device=flow.device, isolation_policy=flow.policy, release_change=change, state=admission_state,
            evidence_digest="0" * 64, requested_by=L.OPERATOR, approved_by=L.APPROVER, approved_at=timezone.now(),
            finished_at=None if admission_state in models.ADMISSION_OPEN else timezone.now())
        admission.__dict__["_admission_write"] = True
        admission.save()
        return flow, change, admission


class AssessTests(Base):
    def test_assess_accepts_an_interrupted_apply_whose_policy_reconcile_proved(self):
        _flow, change = self.interrupted_apply()
        result = S.assess(change, actor=L.OPERATOR, reason=REASON)
        self.assertTrue(result.ok, result.blockers)
        self.assertEqual(result.evidence["owner"]["state"], St.ENFORCED)
        self.assertEqual([run["outcome"] for run in result.evidence["runs"]], ["INTERRUPTED"])
        self.assertEqual(len(result.evidence["digest"]), 64)
        self.assertEqual(change.lifecycle_state, Life.READY_TO_DEPLOY)          # assess writes nothing

    def test_assess_accepts_a_restored_admission_release(self):
        _flow, change, admission = self.restored_release()
        result = S.assess(change, actor=L.OPERATOR, reason=REASON)
        self.assertTrue(result.ok, result.blockers)
        self.assertEqual(result.evidence["owner"]["id"], admission.admission_id)

    def test_assess_refuses_a_generic_change(self):
        change = change_service.create_change(title="generic", created_by=L.OPERATOR)
        self.assertEqual([b["code"] for b in S.assess(change, actor=L.OPERATOR, reason=REASON).blockers], ["SUPERSEDE_NOT_TRANSITION"])

    def test_assess_refuses_without_reason_or_actor(self):
        _flow, change = self.interrupted_apply()
        codes = [b["code"] for b in S.assess(change, actor="", reason=" ").blockers]
        self.assertEqual(codes, ["SUPERSEDE_REASON_REQUIRED", "SUPERSEDE_ACTOR_REQUIRED"])

    def test_assess_refuses_an_open_policy_that_cancel_owns(self):
        flow = I.Flow(self)
        flow.approved()
        codes = [b["code"] for b in S.assess(flow.policy.apply_change, actor=L.OPERATOR, reason=REASON).blockers]
        self.assertEqual(codes, ["SUPERSEDE_OWNER_OPEN"])

    def test_assess_refuses_an_executed_change(self):
        flow = I.Flow(self)
        flow.enforced()
        change = flow.refresh().apply_change
        self.assertEqual(change.lifecycle_state, Life.DEPLOYED)
        self.assertIn("SUPERSEDE_NOT_PENDING", [b["code"] for b in S.assess(change, actor=L.OPERATOR, reason=REASON).blockers])

    def test_assess_refuses_a_running_or_succeeded_run(self):
        _flow, change = self.interrupted_apply()
        running = run_for(change, state=models.ExecutionRunState.RUNNING, outcome="")
        self.assertIn("SUPERSEDE_EXECUTION_IN_FLIGHT", [b["code"] for b in S.assess(change, actor=L.OPERATOR, reason=REASON).blockers])
        running.state, running.outcome, running.finished_at = models.ExecutionRunState.FINISHED, "SUCCEEDED", timezone.now()
        running.save()
        self.assertIn("SUPERSEDE_CHANGE_EXECUTED", [b["code"] for b in S.assess(change, actor=L.OPERATOR, reason=REASON).blockers])

    def test_assess_refuses_an_open_admission(self):
        _flow, change, _admission = self.restored_release(admission_state=models.AdmissionState.APPROVED)
        self.assertEqual([b["code"] for b in S.assess(change, actor=L.OPERATOR, reason=REASON).blockers], ["SUPERSEDE_OWNER_OPEN"])

    def test_assess_refuses_a_transition_change_without_owner(self):
        flow = I.Flow(self)
        flow.required()
        change = T.create_change(kind=S.APPLY_KIND, device="S1", title="orphan", description="", actor=L.OPERATOR, reference={})
        self.assertEqual([b["code"] for b in S.assess(change, actor=L.OPERATOR, reason=REASON).blockers], ["SUPERSEDE_OWNER_MISSING"])

    def test_assess_refuses_while_the_successor_release_is_undeployed(self):
        flow, _change, _admission = self.restored_release()
        self.assertTrue(iso.create_release(flow.refresh(), actor=L.OPERATOR, reference={"retry": True}).ok)
        old = _change
        self.assertNotEqual(flow.refresh().release_change_id, old.pk)
        codes = [b["code"] for b in S.assess(old, actor=L.OPERATOR, reason=REASON).blockers]
        self.assertEqual(codes, ["SUPERSEDE_SUCCESSOR_NOT_DEPLOYED"])


class SupersedeTests(Base):
    def test_supersede_records_one_event_with_evidence_and_sends_nothing(self):
        flow, change = self.interrupted_apply()
        sent, configlets = len(flow.session.sent), change.configlets.count()
        result = S.supersede(change, actor=L.OPERATOR, reason=REASON)
        self.assertTrue(result.ok, result.blockers)
        change.refresh_from_db()
        self.assertEqual(change.lifecycle_state, Life.SUPERSEDED)
        event = change.lifecycle_events.order_by("-occurred_at", "-id").first()
        self.assertEqual((event.from_state, event.to_state, event.actor), (Life.READY_TO_DEPLOY, Life.SUPERSEDED, L.OPERATOR))
        self.assertEqual(event.metadata["supersede"]["digest"], result.evidence["digest"])
        self.assertTrue(models.AuditEvent.objects.filter(change=change, event_type=models.AuditEventType.LIFECYCLE_CHANGED,
                                                         summary__endswith="-> SUPERSEDED").exists())
        self.assertEqual((len(flow.session.sent), change.configlets.count(), change.execution_runs.count()), (sent, configlets, 1))

    def test_supersede_clears_the_acceptance_quiescence_pending_change(self):
        _flow, change, _admission = self.restored_release()
        pending = models.ChangeTarget.objects.filter(change=change).values_list("device_name", flat=True).first()
        self.assertTrue(S.supersede(change, actor=L.OPERATOR, reason=REASON).ok)
        still = models.ChangeTarget.objects.filter(device_name=pending, change__lifecycle_state__in=acceptance._CHANGE_PENDING,
                                                   change=change)
        self.assertFalse(still.exists())

    def test_supersede_refuses_twice_and_writes_nothing_on_refusal(self):
        _flow, change = self.interrupted_apply()
        self.assertTrue(S.supersede(change, actor=L.OPERATOR, reason=REASON).ok)
        events = change.lifecycle_events.count()
        again = S.supersede(change, actor=L.OPERATOR, reason=REASON)
        self.assertIn("SUPERSEDE_NOT_PENDING", [b["code"] for b in again.blockers])
        self.assertEqual(change.lifecycle_events.count(), events)

    def test_supersede_refuses_a_change_that_moved_during_closure(self):
        _flow, change = self.interrupted_apply()
        original = S.assess
        calls = {"n": 0}

        def moving(locked, **kwargs):
            calls["n"] += 1
            if calls["n"] == 2:
                run_for(locked, outcome="BLOCKED")                      # a new run appears between the two checks
            return original(locked, **kwargs)

        S.assess = moving
        try:
            result = S.supersede(change, actor=L.OPERATOR, reason=REASON)
        finally:
            S.assess = original
        self.assertEqual([b["code"] for b in result.blockers], ["SUPERSEDE_STATE_CHANGED"])
        change.refresh_from_db()
        self.assertEqual(change.lifecycle_state, Life.READY_TO_DEPLOY)

    def test_assessment_ok_is_true_for_a_clear_assessment(self):
        self.assertTrue(S.Assessment(change=None).ok)

    def test_assessment_ok_is_false_with_a_refusal(self):
        self.assertFalse(S.Assessment(change=None, blockers=[{"code": "SUPERSEDE_NOT_PENDING"}]).ok)


class CommandTests(Base):
    def test_command_assess_mode_reports_and_writes_nothing(self):
        _flow, change = self.interrupted_apply()
        out = io.StringIO()
        call_command("nmas_transition_supersede", "--change", change.change_id, "--actor", L.OPERATOR, "--reason", REASON, stdout=out)
        self.assertIn(f"{change.change_id}: OK state=READY_TO_DEPLOY", out.getvalue())
        change.refresh_from_db()
        self.assertEqual(change.lifecycle_state, Life.READY_TO_DEPLOY)

    def test_command_apply_closes_the_change(self):
        _flow, change, _admission = self.restored_release()
        out = io.StringIO()
        call_command("nmas_transition_supersede", "--change", change.change_id, "--actor", L.OPERATOR, "--reason", REASON,
                     "--apply", "--json", stdout=out)
        self.assertIn('"state": "SUPERSEDED"', out.getvalue())

    def test_command_handle_assesses_a_closable_change(self):
        _flow, change = self.interrupted_apply()
        out = io.StringIO()
        command = cmd.Command(stdout=out)
        command.handle(change=[change.change_id], actor=L.OPERATOR, reason=REASON, apply=False, json=False)
        self.assertIn(": OK ", out.getvalue())

    def test_command_handle_exits_3_on_refusal(self):
        flow = I.Flow(self)
        flow.approved()
        with self.assertRaises(SystemExit) as raised:
            call_command("nmas_transition_supersede", "--change", flow.policy.apply_change.change_id, "--actor", L.OPERATOR,
                         "--reason", REASON, "--apply", stdout=io.StringIO())
        self.assertEqual(raised.exception.code, 3)

    def test_command_handle_raises_for_an_unknown_change(self):
        from django.core.management.base import CommandError
        with self.assertRaises(CommandError):
            cmd.Command().handle(change=["CHG-00000000-9999"], actor=L.OPERATOR, reason=REASON, apply=False, json=False)

    def test_command_add_arguments_declares_the_change_option(self):
        import argparse
        parser = argparse.ArgumentParser()
        cmd.Command().add_arguments(parser)
        self.assertEqual(parser.parse_args(["--change", "CHG-1"]).change, ["CHG-1"])
