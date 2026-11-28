"""Standing-policy succession, revocation, visibility and restart safety of the unattended recovery watcher."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

from django.test import TestCase

from core import models
from core.services.troubleshooting import governance as gov
from core.services.troubleshooting import recovery
from core.services.troubleshooting import repository as repo
from core.tests import test_troubleshooting_recovery_execution as rx

PAST = (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat()


class RecoveryOperationsTests(TestCase):
    setUp = rx.RecoveryExecutionTests.setUp
    deps = rx.RecoveryExecutionTests.deps
    write_policy = rx.RecoveryExecutionTests.write_policy
    run_recovery = rx.RecoveryExecutionTests.run_recovery
    assertRefused = rx.RecoveryExecutionTests.assertRefused

    def write_policies(self, *items):
        Path(self.policy_file).write_text(json.dumps({"policies": list(items)}))

    def new_plan(self):
        self.plan = models.TsRemediationPlan.objects.create(record_id=repo._rid("RPL"), case=self.case, basis="AI_INFERRED", status="RISK_ASSESSED",
                                                            tier=2, risk="HIGH", operations=[rx.OP], evidence_ids=["EV-1"])
        return self.plan

    # ------------------------------------------------------------------------------------------------------------- succession
    def test_successor_policy_is_used_when_predecessor_is_expired(self):
        self.write_policies(rx.policy(id="ARP-OLD", expires_at=PAST), rx.policy(id="ARP-NEW", supersedes="ARP-OLD"))
        out = self.run_recovery()
        self.assertEqual((out["result"], out["policy"]), ("VERIFIED", "ARP-NEW"), out)

    def test_expired_predecessor_alone_is_refused_not_silently_extended(self):
        self.write_policies(rx.policy(id="ARP-OLD", expires_at=PAST))
        self.assertRefused("POLICY_DENIED", "POLICY_EXPIRED")

    def test_successor_honours_cooldown_of_predecessor_executions_for_the_same_scope(self):
        self.write_policies(rx.policy(id="ARP-OLD"))
        self.assertEqual(self.run_recovery()["result"], "VERIFIED")
        self.write_policies(rx.policy(id="ARP-OLD", max_executions=1), rx.policy(id="ARP-NEW", supersedes="ARP-OLD"))
        self.eos.text, self.eos.sent = rx.FAULTED, []
        self.new_plan()
        self.assertRefused("POLICY_DENIED", "COOLDOWN_ACTIVE")
        self.assertEqual(self.eos.sent, [])

    def test_revoked_policy_is_inactive_immediately(self):
        self.write_policies(rx.policy(revoked_at=datetime.now(timezone.utc).isoformat()))
        self.assertRefused("POLICY_DENIED", "POLICY_NOT_ACTIVE")
        self.assertEqual(self.eos.sent, [])

    def test_policy_status_reports_validity_executions_and_warnings(self):
        self.write_policies(rx.policy(id="ARP-OLD", expires_at=PAST), rx.policy(id="ARP-NEW", max_executions=2))
        self.assertEqual(self.run_recovery()["policy"], "ARP-NEW")
        rows = {r["id"]: r for r in recovery.policy_status(policy_file=self.policy_file)}
        self.assertEqual((rows["ARP-OLD"]["active"], rows["ARP-OLD"]["warnings"]), (False, ["EXPIRED"]))
        new = rows["ARP-NEW"]
        self.assertEqual((new["active"], new["executions_used"], new["executions_remaining"]), (True, 1, 1))
        self.assertIn("ONE_EXECUTION_LEFT", new["warnings"])
        self.assertGreater(new["cooldown_remaining_seconds"], 500)

    # ------------------------------------------------------------------------------------------------------------ restart safety
    def test_unexpected_error_fails_the_plan_closed_and_is_never_retried(self):
        with mock.patch.object(recovery.notify, "send"):
            self.assertEqual(recovery.fail_closed(self.plan.record_id, "RuntimeError: boom"), "BLOCKED")
        self.plan.refresh_from_db()
        self.assertEqual(self.plan.status, "BLOCKED")
        self.assertTrue(models.TsAuditEvent.objects.filter(case=self.case, action="AUTOMATED_RECOVERY_ERROR").exists())

    def test_restart_sweep_blocks_in_flight_plans_and_never_re_executes(self):
        actor = repo.Actor("nmas-policy:ARP-TEST-001", "system", tenant="default")
        for state in ("DRY_RUN_PASS", "PREAUTHORIZED"):
            gov._set_status(actor, self.plan, state, "test", approval={"mode": gov.AUTOMATED_RECOVERY} if state == "PREAUTHORIZED" else {})
        executing = self.new_plan()
        for state in ("DRY_RUN_PASS", "PREAUTHORIZED", "PRECHECK_PASS", "EXECUTING"):
            gov._set_status(actor, executing, state, "test", approval={"mode": gov.AUTOMATED_RECOVERY})
        ex = models.TsActionExecution.objects.create(record_id=repo._rid("ACT"), case=self.case, basis="DERIVED", stage="REMEDIATE",
                                                     stage_decision="policy ARP-TEST-001", plan=executing, status="EXECUTING",
                                                     command_or_intent={"change_id": "CHG-20990101-0001"}, idempotency_key="k1",
                                                     executed_at=datetime.now(timezone.utc))
        with mock.patch.object(recovery.notify, "send") as sent, mock.patch.object(recovery, "recover") as rec:
            out = recovery.sweep_interrupted()
        rec.assert_not_called()
        self.assertEqual(sorted(r["was"] for r in out), ["EXECUTING", "PREAUTHORIZED"])
        self.assertEqual(sent.call_count, 2)
        for plan in (self.plan, executing):
            plan.refresh_from_db()
            self.assertEqual(plan.status, "BLOCKED")
        ex.refresh_from_db()
        self.assertEqual(ex.status, "INTERRUPTED")
        self.assertEqual(recovery.pending_plans(), [])                                    # nothing is picked up again
        self.assertEqual(self.eos.sent, [])
        self.assertEqual(recovery.sweep_interrupted(), [])                                # idempotent
