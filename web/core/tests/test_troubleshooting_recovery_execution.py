"""Policy-authorized recovery through the REAL Change Engine (validation, plan, precheck, locks, apply, compensation, postcheck)."""

from __future__ import annotations

import json
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

from django.test import TestCase

from core import models
from core.services import change_plan_service as cps
from core.services import change_validation_service as cvs
from core.services import execution_service as es
from core.services import health_service as hs
from core.services.config_workbench import snapshots
from core.services.config_workbench.structure import config_paths
from core.services.execution.executors.ceos import CeosExecutor
from core.services.troubleshooting import governance as gov
from core.services.troubleshooting import recovery
from core.services.troubleshooting import repository as repo
from core.tests.helpers import health as h
from core.tests.helpers.validation import make_sources
from core.tests.helpers.workbench import use_scope
from core.tests.test_config_workbench import SWITCH
from core.tests.test_config_workflows import DEVICE, FakeEos, fetch_factory

IFACE = "Ethernet2"
TRUNK = "interface Ethernet2\n   description S1_S2_TRUNK\n   switchport mode trunk\n   switchport trunk allowed vlan 10,20,50\n"
assert TRUNK in SWITCH
FAULTED = SWITCH.replace(TRUNK, TRUNK + "   shutdown\n")
OP = {"kind": "interface_enable", "device": DEVICE, "interface": IFACE, "intended_state": "admin_up"}


def policy(**kw):
    base = {"id": "ARP-TEST-001", "owner_authorization": "OWNER-TEST", "device": DEVICE, "interface": IFACE, "kind": "interface_enable",
            "intended_state": "admin_up", "expires_at": (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(),
            "max_executions": 3, "cooldown_seconds": 600, "enabled": True, "protected_flows": [{"container": "h1", "dst": "x"}]}
    return {**base, **kw}


class RecoveryExecutionTests(TestCase):
    def setUp(self):
        use_scope(self)
        self.sources = make_sources()
        self.eos = FakeEos(FAULTED)
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.policy_file = str(Path(self.tmp.name) / "policies.json")
        self.write_policy(policy())
        actor = repo.Actor("operator", "user", tenant="default")
        self.case = repo.open_case(actor, trigger_source="operator", title="S1 alarm", symptom="trunk down", runbook="RB02",
                                   service_intent={"service": "x"}, affected_scope={"devices": [DEVICE]})
        self.plan = models.TsRemediationPlan.objects.create(record_id=repo._rid("RPL"), case=self.case, basis="AI_INFERRED", status="RISK_ASSESSED",
                                                            tier=2, risk="HIGH", operations=[OP], evidence_ids=["EV-1"])
        self.sent: list[tuple[str, str]] = []
        self.intent = {IFACE: "up"}
        self.flows_ok = True
        self.lying_postcheck = False
        self.ci_status = "PASS"

    def write_policy(self, data):
        Path(self.policy_file).write_text(json.dumps({"policies": [data]}))

    def deps(self):
        eos = self.eos

        def factory(device):
            return CeosExecutor(device, connection_factory=lambda d: eos, reader=lambda d: h.device_evidence(DEVICE))

        def evidence(plan, cfg_ids):
            text = FAULTED if self.lying_postcheck else eos.text
            return h.evidence_set(h.device_evidence(DEVICE, config_paths=sorted(config_paths(text))))

        def execute(change, *, actor, confirm_mode):
            return es.execute_change(change, actor=actor, confirm_mode=confirm_mode, sources=self.sources, executor_factory=factory,
                                     evidence_provider=evidence, notifier=lambda **k: None, sleep=lambda s: None,
                                     clock=iter(range(0, 10000, 5)).__next__)

        return recovery.RecoveryDeps(
            snapshot=lambda device, actor: snapshots.capture_snapshot(device, actor=actor, session_factory=fetch_factory(eos.text)),
            intent=lambda device: self.intent, flows=lambda flows: self.flows_ok,
            oper_state=lambda raw, iface: "down" if "   shutdown" in eos.text.split("interface Ethernet2\n", 1)[1].split("\ninterface", 1)[0] else "up",
            validate=lambda change, actor: cvs.validate_change(change, actor=actor, sources=self.sources),
            plan=lambda change, actor: cps.build_change_plan(change, actor=actor, sources=self.sources),
            precheck=lambda change, actor: hs.run_change_precheck(change, actor=actor, sources=self.sources, snapshot=h.snapshot(),
                                                                  session_factory=fetch_factory(eos.text), persist=True),
            execute=execute, notify=lambda s, b: self.sent.append((s, b)) or True, ci_wait=lambda change: self.ci_status)

    def run_recovery(self):
        return recovery.recover(self.plan.record_id, deps=self.deps(), policy_file=self.policy_file)

    # ---------------------------------------------------------------------------------------------------------------------
    def test_authorized_recovery_runs_only_no_shutdown_through_the_change_engine_and_is_attributed(self):
        out = self.run_recovery()
        self.assertEqual(out["result"], "VERIFIED", out)
        self.assertEqual([[c for c in cmds if c != "exit"] for cmds in self.eos.sent], [["interface Ethernet2", "no shutdown"]])         # the ONLY write, by the Change Engine
        self.assertEqual(self.eos.text, SWITCH)                                            # nothing else on the device changed
        change = models.Change.objects.get(change_id=out["change"])
        rec = change.metadata["recovery"]
        self.assertEqual((rec["authorization_type"], rec["policy_id"], rec["owner_authorization"], rec["policy_actor"], rec["human_approval"],
                          rec["risk"], rec["plan_id"], rec["case_id"]),
                         ("PREAUTHORIZED_AUTOMATED_RECOVERY", "ARP-TEST-001", "OWNER-TEST", "nmas-policy:ARP-TEST-001", False, "HIGH",
                          self.plan.record_id, self.case.case_id))
        run = change.execution_runs.get()
        self.assertEqual((run.outcome, run.actor if hasattr(run, "actor") else run.created_by), ("SUCCEEDED", "nmas-policy:ARP-TEST-001"))
        self.plan.refresh_from_db()
        self.assertEqual((self.plan.status, self.plan.risk, self.plan.approval["approved_by"], self.plan.approval["mode"]),
                         ("RESOLVED", "HIGH", "", "PREAUTHORIZED_AUTOMATED_RECOVERY"))
        ex = models.TsActionExecution.objects.get(plan=self.plan)
        self.assertEqual((ex.status, ex.observed_effect["admin"], ex.observed_effect["oper"]), ("SUCCEEDED", "up", "up"))
        actions = set(models.TsAuditEvent.objects.filter(case=self.case).values_list("action", flat=True))
        self.assertTrue({"AUTOMATED_RECOVERY_EXECUTED", "REMEDIATION_STATE"} <= actions)
        self.assertIn("COMPLETED", self.sent[-1][0])

    def test_failed_postcheck_is_compensated_to_the_captured_pre_change_state(self):
        self.lying_postcheck = True
        out = self.run_recovery()
        self.assertEqual(out["result"], "NOT_VERIFIED", out)
        self.assertIn("ROLLED_BACK", out["outcome"])
        block = self.eos.text.split("interface Ethernet2\n", 1)[1].split("\ninterface", 1)[0]
        self.assertIn("   shutdown", block)                                                 # restored to the real pre-state
        self.plan.refresh_from_db()
        self.assertEqual(self.plan.status, "ABORTED_RESTORED")

    def assertRefused(self, code, reason=None):
        out = self.run_recovery()
        self.assertEqual(out["result"], "REFUSED", out)
        self.assertEqual(out["code"], code)
        if reason:
            self.assertIn(reason, out["reasons"])
        self.assertEqual(self.eos.sent, [])                                                 # no device write at all
        self.plan.refresh_from_db()
        self.assertEqual(self.plan.status, "BLOCKED")
        self.assertIn("REFUSED", self.sent[-1][0])

    def test_disabled_expired_exhausted_policy_refused(self):
        self.write_policy(policy(enabled=False))
        self.assertRefused("POLICY_DENIED", "POLICY_NOT_ACTIVE")

    def test_expired_policy_refused(self):
        self.write_policy(policy(expires_at="2020-01-01T00:00:00+00:00"))
        self.assertRefused("POLICY_DENIED", "POLICY_EXPIRED")

    def test_missing_or_contrary_intent_refused(self):
        self.intent = {}
        self.assertRefused("POLICY_DENIED", "INTENT_UNAVAILABLE")

    def test_intentionally_disabled_interface_is_not_recovered(self):
        self.intent = {IFACE: "down"}
        self.assertRefused("POLICY_DENIED", "INTENT_DOES_NOT_REQUIRE_STATE")

    def test_unhealthy_protected_flows_refused(self):
        self.flows_ok = False
        self.assertRefused("POLICY_DENIED", "PROTECTED_FLOWS_NOT_HEALTHY")

    def test_conflicting_change_lock_refused(self):
        with mock.patch.object(recovery, "_conflicting_change", return_value=True):   # another Change holds the device lock
            self.assertRefused("POLICY_DENIED", "CONFLICTING_CHANGE")

    def test_unrelated_operation_or_target_has_no_policy(self):
        for op in ({**OP, "interface": "Ethernet3"}, {**OP, "device": "R9"}, {**OP, "kind": "config_hotfix"}):
            with self.subTest(op=op):
                plan = models.TsRemediationPlan.objects.create(record_id=repo._rid("RPL"), case=self.case, basis="AI_INFERRED",
                                                               status="RISK_ASSESSED", tier=2, risk="HIGH", operations=[op])
                with self.assertRaises(recovery.RecoveryRefused) as ctx:
                    recovery.recover(plan.record_id, deps=self.deps(), policy_file=self.policy_file)
                self.assertEqual(ctx.exception.code, "NO_POLICY")
        self.assertEqual(self.eos.sent, [])

    def test_already_up_is_a_noop(self):
        self.eos.text = SWITCH
        self.assertEqual(self.run_recovery()["result"], "NOOP")
        self.assertEqual(self.eos.sent, [])

    def test_no_policy_file_means_disabled(self):
        with self.assertRaises(recovery.RecoveryRefused):
            recovery.recover(self.plan.record_id, deps=self.deps(), policy_file=str(Path(self.tmp.name) / "absent.json"))

    def test_second_execution_inside_cooldown_refused(self):
        self.assertEqual(self.run_recovery()["result"], "VERIFIED")
        self.eos.text, self.eos.sent = FAULTED, []
        self.plan = models.TsRemediationPlan.objects.create(record_id=repo._rid("RPL"), case=self.case, basis="AI_INFERRED", status="RISK_ASSESSED",
                                                            tier=2, risk="HIGH", operations=[OP])
        self.assertRefused("POLICY_DENIED", "COOLDOWN_ACTIVE")

    def test_external_configuration_validation_must_pass_before_any_write(self):
        for status in ("FAIL", "ERROR", "QUEUED"):
            with self.subTest(status=status):
                self.plan = models.TsRemediationPlan.objects.create(record_id=repo._rid("RPL"), case=self.case, basis="AI_INFERRED",
                                                                    status="RISK_ASSESSED", tier=2, risk="HIGH", operations=[OP])
                self.ci_status = status
                self.assertRefused("CONFIGURATION_VALIDATION_NOT_PASSING", status)

    def test_change_feed_ignores_runs_that_changed_no_device(self):
        """HC02 'has anything changed?' must not blame a run the engine refused before any mutation (campaign 006 false lead)."""
        from core.services.troubleshooting.baselines import DjangoBaselineSources

        out = self.run_recovery()
        self.assertEqual(out["result"], "VERIFIED", out)
        change = models.Change.objects.get(change_id=out["change"])
        blocked = self.deps().execute(change, actor="tester", confirm_mode=models.ExecutionMode.COMPLETE)   # plan already executed
        self.assertEqual(blocked.outcome, models.ExecutionOutcome.BLOCKED)
        now = datetime.now(timezone.utc)
        feed = DjangoBaselineSources().changes([DEVICE], now - timedelta(hours=1), now + timedelta(minutes=1))
        self.assertEqual(feed["status"], "available", feed)
        self.assertEqual([r["outcome"] for r in feed["changes"]], ["SUCCEEDED"])           # the real write stays visible
