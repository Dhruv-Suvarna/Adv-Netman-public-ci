"""Change-history authorization semantics: human approval, policy authorization and outcome are distinct facts (campaign 008)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

from django.test import TestCase

from core import models
from core.services import change_plan_service as cps
from core.services import change_validation_service as cvs
from core.services import health_service as hs
from core.services import workbench_service as wb
from core.services.config_workbench import snapshots
from core.services.troubleshooting import ai_runtime as air
from core.services.troubleshooting import baselines
from core.services.troubleshooting import governance as gov
from core.services.troubleshooting import recovery
from core.services.troubleshooting import repository as repo
from core.services.troubleshooting.runbooks import hc
from core.tests.helpers import health as h
from core.tests.test_config_workflows import DEVICE, fetch_factory
from core.tests import test_troubleshooting_recovery_execution as rx

APPROVED_STATE = next(s for s in models.ChangeLifecycleState.values if s not in ("DRAFT", "VALIDATED", "CI_PENDING", "CI_FAILED"))


class ChangeAuthorizationTests(TestCase):
    setUp = rx.RecoveryExecutionTests.setUp
    deps = rx.RecoveryExecutionTests.deps
    write_policy = rx.RecoveryExecutionTests.write_policy
    run_recovery = rx.RecoveryExecutionTests.run_recovery

    def feed(self):
        now = datetime.now(timezone.utc)
        out = baselines.DjangoBaselineSources().changes([DEVICE], now - timedelta(hours=1), now + timedelta(minutes=1))
        self.assertEqual(out["status"], "available", out)
        return {r["change_id"]: r for r in out["changes"]}

    def manual_change(self, actor: str):
        """A real removal Change executed by the engine on behalf of ``actor`` (no policy records)."""
        snap, _ = snapshots.capture_snapshot(DEVICE, actor=actor, session_factory=fetch_factory(self.eos.text))
        line = recovery.shutdown_line(snap, "Ethernet2")
        sel = wb.removal_selection(models.RemovalMode.LINE_RANGE, from_line=line, to_line=line)
        change = wb.create_removal_change(snapshot=snap, mode=models.RemovalMode.LINE_RANGE, selection=sel, actor=actor)
        cvs.validate_change(change, actor=actor, sources=self.sources)
        cps.build_change_plan(change, actor=actor, sources=self.sources)
        hs.run_change_precheck(change, actor=actor, sources=self.sources, snapshot=h.snapshot(), session_factory=fetch_factory(self.eos.text), persist=True)
        result = self.deps().execute(change, actor=actor, confirm_mode=models.ExecutionMode.COMPLETE)
        self.assertEqual(result.outcome, models.ExecutionOutcome.SUCCEEDED)
        return change

    # ------------------------------------------------------------------------------------------------------------------------
    def test_executed_policy_authorized_change_is_recognized_without_implying_human_approval(self):
        out = self.run_recovery()
        row = self.feed()[out["change"]]
        self.assertEqual((row["authorization_mode"], row["authorizing_policy_id"], row["authorized"]),
                         ("PREAUTHORIZED_AUTOMATED_RECOVERY", "ARP-TEST-001", True))
        self.assertEqual((row["approved"], row["human_approved"], row["lifecycle"]), (False, False, "DRAFT"))   # facts kept
        self.assertEqual((row["execution_outcome"], row["postcheck"], row["service_verification"]), ("SUCCEEDED", "PASS", "VERIFIED"))
        self.assertEqual(row["authorization_evidence"]["run_actor"], "nmas-policy:ARP-TEST-001")

    def test_draft_change_without_authorization_remains_unapproved_and_unauthorized(self):
        change = self.manual_change("operator")
        row = self.feed()[change.change_id]
        self.assertEqual((row["approved"], row["authorized"], row["authorization_mode"]), (False, False, "NONE"))

    def test_human_approved_change_keeps_its_classification(self):
        change = self.manual_change("operator")
        models.Change.objects.filter(pk=change.pk).update(lifecycle_state=APPROVED_STATE)
        row = self.feed()[change.change_id]
        self.assertEqual((row["approved"], row["human_approved"], row["authorized"], row["authorization_mode"]),
                         (True, True, True, "HUMAN_APPROVAL"))

    def test_rolled_back_policy_change_is_not_shown_as_successful(self):
        self.lying_postcheck = True
        out = self.run_recovery()
        row = self.feed()[out["change"]]
        self.assertEqual(row["authorization_mode"], "PREAUTHORIZED_AUTOMATED_RECOVERY")
        self.assertIn("ROLLED_BACK", row["execution_outcome"])
        self.assertNotEqual(row["service_verification"], "VERIFIED")

    def test_policy_actor_or_metadata_without_policy_audit_records_is_not_authorization(self):
        change = self.manual_change("nmas-policy:ARP-TEST-001")                     # spoofed actor string, no policy records
        models.Change.objects.filter(pk=change.pk).update(metadata={**change.metadata, "recovery": {
            "authorization_type": "PREAUTHORIZED_AUTOMATED_RECOVERY", "policy_id": "ARP-TEST-001"}})
        row = self.feed()[change.change_id]
        self.assertEqual((row["authorized"], row["authorization_mode"]), (False, "NONE"))
        self.assertIn("NOT treated as authorized", row["authorization_note"])

    def test_history_consumers_distinguish_authorization_from_outcome(self):
        out = self.run_recovery()
        rows = baselines.classify_changes(list(self.feed().values()), soak=None, onset=datetime.now(timezone.utc))
        row = next(r for r in rows if r["change_id"] == out["change"])
        self.assertEqual((row["approved"], row["authorized"], row["authorization_mode"]), (False, True, "PREAUTHORIZED_AUTOMATED_RECOVERY"))
        ctx = SimpleNamespace(use_intent=lambda *a: None, baselines={"changes": {"status": "available"}, "soak_window": {}},
                              correlation={"changes": [{**row, "relation": "BEFORE_ONSET"}], "drift": []})
        result = hc.hc02(ctx)
        self.assertNotEqual(result.verdict if hasattr(result, "verdict") else result[0], "FAIL")     # authorized change is not blamed
        spoof = {**row, "authorized": False, "authorization_mode": "NONE", "relation": "BEFORE_ONSET"}
        ctx.correlation["changes"] = [spoof]
        self.assertEqual(hc.hc02(ctx).verdict if hasattr(hc.hc02(ctx), "verdict") else hc.hc02(ctx)[0], "FAIL")

    def test_model_is_told_rollback_needs_causal_evidence_and_minimal_repair(self):
        text = air.build_request({}, identity={}, catalog=[], seq=1)["instructions"]
        for phrase in ("MINIMAL operation set", "PREAUTHORIZED_AUTOMATED_RECOVERY", "config_rollback of a change ONLY when evidence",
                       "temporal proximity alone is not causation"):
            self.assertIn(phrase, text)

    def test_rollback_of_a_change_that_never_changed_the_device_is_rejected(self):
        self.assertIn("requires change_id", gov._rollback_target_problem({"kind": "config_rollback", "device": DEVICE}))
        self.assertIn("never changed", gov._rollback_target_problem({"kind": "config_rollback", "device": DEVICE, "change_id": "CHG-20990101-0001"}))
        out = self.run_recovery()                                                   # a Change that DID change the device stays rollback-able
        self.assertEqual(gov._rollback_target_problem({"kind": "config_rollback", "device": DEVICE, "change_id": out["change"]}), "")
        self.assertEqual(gov._rollback_target_problem({"kind": "config_rollback", "device": "R9", "change_id": out["change"]}),
                         f"config_rollback target {out['change']} never changed 'R9'; it cannot be the repair")

    def test_multi_operation_plan_outside_the_policy_is_still_rejected(self):
        two = models.TsRemediationPlan.objects.create(
            record_id=repo._rid("RPL"), case=self.case, basis="AI_INFERRED", status="RISK_ASSESSED", tier=2, risk="HIGH",
            operations=[rx.OP, {"kind": "config_rollback", "device": DEVICE, "change_id": "CHG-20990101-0001"}])
        self.assertNotIn(two.record_id, recovery.pending_plans())
        with self.assertRaises(recovery.RecoveryRefused) as ctx:
            recovery.recover(two.record_id, deps=self.deps(), policy_file=self.policy_file)
        self.assertEqual(ctx.exception.code, "PLAN_NOT_ELIGIBLE")
        self.assertEqual(self.eos.sent, [])

    def test_no_human_approval_is_fabricated(self):
        out = self.run_recovery()
        change = models.Change.objects.get(change_id=out["change"])
        self.assertEqual(change.lifecycle_state, "DRAFT")                            # never moved into an approved lifecycle
        self.assertFalse(change.lifecycle_events.exclude(to_state="DRAFT").exists() if hasattr(change, "lifecycle_events") else False)
        self.assertFalse(models.AuditEvent.objects.filter(change=change, event_type__icontains="APPROV").exists())
        self.plan.refresh_from_db()
        self.assertEqual((self.plan.approval["approved_by"], self.plan.approval["human_approval"]), ("", False))
