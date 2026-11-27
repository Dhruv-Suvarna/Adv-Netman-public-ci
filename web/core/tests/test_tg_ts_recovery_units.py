"""Direct tests for the standing-policy recovery helpers (troubleshooting/recovery.py).

``recover()`` itself is exercised end to end by test_troubleshooting_recovery_execution/_operations.  These cover each
helper directly: the policy store, activity and scope matching, the read-only live probes (subprocess is faked, nothing
reaches a container), the bounded CI wait, and the restart-safety / proposal-governance records.  Every helper fails
closed: an unreadable probe is "unknown" / not ready, never healthy.
"""

from __future__ import annotations

import json
import subprocess
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from django.test import SimpleTestCase, TestCase

from core import models
from core.services.troubleshooting import governance as gov
from core.services.troubleshooting import recovery
from core.services.troubleshooting import repository as repo
from core.tests import test_troubleshooting_recovery_execution as rx

NOW = datetime(2026, 11, 27, 6, 0, tzinfo=timezone.utc)
FLOW = {"name": "H1-H2-v4", "container": "h1", "dst": "10.0.0.2"}
PING_OK = "5 packets transmitted, 5 received, 0% packet loss, time 4004ms"


def ran(stdout="", exc=None):
    def run(argv, **kw):
        if exc is not None:
            raise exc
        return subprocess.CompletedProcess(argv, 0, stdout, "")
    return mock.patch.object(recovery.subprocess, "run", side_effect=run)


class RefusalAndPolicyStoreTests(SimpleTestCase):
    def test_recovery_exception_carries_code_and_detail_as_its_text(self):
        err = recovery.RecoveryRefused("POLICY_DENIED", "expired")
        self.assertEqual((err.code, err.detail, str(err)), ("POLICY_DENIED", "expired", "POLICY_DENIED: expired"))

    def test_recovery_refused_without_detail_is_just_the_code(self):
        self.assertEqual(str(recovery.RecoveryRefused("NO_PLAN")), "NO_PLAN")

    def test_load_policies_returns_policies_by_id(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "p.json"
            path.write_text(json.dumps({"policies": [rx.policy(), {"no": "id"}, "junk"]}))
            self.assertEqual(list(recovery.load_policies(str(path))), ["ARP-TEST-001"])

    def test_load_policies_without_a_file_is_empty_and_malformed_raises(self):
        with self.subTest("a missing file is empty"):
            self.assertEqual(recovery.load_policies("/nonexistent/policies.json"), {})
        with self.subTest("an unset path is empty"):
            self.assertEqual(recovery.load_policies(""), {})
        with self.subTest("malformed json raises"), tempfile.TemporaryDirectory() as d:
            (Path(d) / "p.json").write_text("{not json")
            with self.assertRaises(ValueError):
                recovery.load_policies(str(Path(d) / "p.json"))

    def test_policy_active_accepts_an_enabled_unexpired_policy(self):
        self.assertTrue(recovery.policy_active({"enabled": True, "expires_at": "2026-11-28T00:00:00Z"}, NOW))

    def test_policy_active_refuses_disabled_revoked_expired_or_undated_policies(self):
        for label, raw in (("a disabled policy", {"enabled": False, "expires_at": "2026-11-28T00:00:00Z"}),
                           ("a truthy non-true enable", {"enabled": "yes", "expires_at": "2026-11-28T00:00:00Z"}),
                           ("a revoked policy", {"enabled": True, "revoked_at": "2026-11-26", "expires_at": "2026-11-28T00:00:00Z"}),
                           ("an expired policy", {"enabled": True, "expires_at": "2026-11-26T00:00:00Z"}),
                           ("a malformed expiry", {"enabled": True, "expires_at": "tomorrow"})):
            with self.subTest(f"{label} is refused"):
                self.assertFalse(recovery.policy_active(raw, NOW))

    def test_policy_for_returns_the_active_successor_of_an_exact_target(self):
        old = rx.policy(id="ARP-OLD", expires_at="2020-01-01T00:00:00Z")
        new = rx.policy(id="ARP-NEW")
        self.assertEqual(recovery.policy_for(rx.OP, {"ARP-OLD": old, "ARP-NEW": new})["id"], "ARP-NEW")
        self.assertEqual(recovery.policy_for(rx.OP, {"ARP-OLD": old})["id"], "ARP-OLD")         # names the real refusal reason

    def test_policy_for_another_interface_is_none(self):
        self.assertIsNone(recovery.policy_for({**rx.OP, "interface": "Ethernet9"}, {"ARP-TEST-001": rx.policy()}))


class LiveProbeTests(SimpleTestCase):
    def test_sample_flows_accepts_zero_loss_on_every_flow(self):
        with ran("3 packets transmitted, 3 received, 0% packet loss") as run:
            self.assertTrue(recovery.sample_flows([FLOW, {**FLOW, "af": 6}]))
        self.assertIn("-6", run.call_args_list[1].args[0])

    def test_sample_flows_refuses_empty_lossy_or_unrunnable_probes(self):
        for label, patch, flows in (("no flow", ran(PING_OK), []), ("a lossy flow", ran("3 packets transmitted, 2 received, 33% packet loss"), [FLOW]),
                                    ("an unrunnable probe", ran(exc=subprocess.TimeoutExpired("ping", 15)), [FLOW])):
            with self.subTest(f"{label} is refused"), patch:
                self.assertFalse(recovery.sample_flows(flows))

    def test_measure_flows_returns_loss_and_coverage(self):
        with ran(PING_OK):
            self.assertEqual({k: (v["loss_pct"], v["coverage"]) for k, v in recovery.measure_flows([FLOW]).items()}, {"H1-H2-v4": (0.0, 1.0)})

    def test_measure_flows_of_an_unrunnable_probe_is_never_zero_loss(self):
        with ran(exc=OSError("docker missing")):
            out = recovery.measure_flows([FLOW])["H1-H2-v4"]
        self.assertEqual((out["loss_pct"], out["coverage"], out["raw"]), (None, 0, "OSError"))

    def test_read_oper_state_returns_up_or_down(self):
        rows = "Port       Name   Status       Vlan\nEt2        trunk  {}    trunk\n"
        with ran(rows.format("connected")):
            self.assertEqual(recovery.read_oper_state({"device_container": "c"}, "Ethernet2"), "up")
        with ran(rows.format("disabled ")):
            self.assertEqual(recovery.read_oper_state({"device_container": "c"}, "Ethernet2"), "down")

    def test_read_oper_state_unreadable_is_unknown(self):
        with ran(exc=OSError("x")), self.subTest("an unrunnable read is unknown"):
            self.assertIsNone(recovery.read_oper_state({"device_container": "c"}, "Ethernet2"))
        with ran("Port Name Status\nEt3 x connected\n"), self.subTest("an absent interface row is unknown"):
            self.assertIsNone(recovery.read_oper_state({"device_container": "c"}, "Ethernet2"))


class CiWaitTests(SimpleTestCase):
    def ci(self, statuses, *, enabled=True, exempt=False):
        rows = iter(statuses)
        fake = SimpleNamespace(enabled=lambda: enabled, exempt=lambda change: exempt, latest=lambda change: object(),
                               refresh=lambda row: row, effective_status=lambda row: next(rows))
        return mock.patch("core.services.configuration_validation.service", fake, create=True), \
            mock.patch.dict("sys.modules", {"core.services.configuration_validation.service": fake})

    def test_wait_configuration_validation_returns_the_settled_verdict(self):
        a, b = self.ci(["QUEUED", "IN_PROGRESS", "PASS"])
        with a, b, mock.patch.object(recovery.time, "sleep"):
            self.assertEqual(recovery.wait_configuration_validation(object(), timeout=60, interval=0), "PASS")
        a, b = self.ci([], enabled=False)
        with a, b, self.subTest("a disabled validation passes through"):
            self.assertEqual(recovery.wait_configuration_validation(object()), "PASS")

    def test_wait_configuration_validation_never_waits_beyond_its_timeout(self):
        a, b = self.ci(["QUEUED"] * 5)
        with a, b, mock.patch.object(recovery.time, "sleep"), mock.patch.object(recovery.time, "monotonic", side_effect=[0, 0, 999]):
            self.assertEqual(recovery.wait_configuration_validation(object(), timeout=10, interval=0), "QUEUED")


class RecoveryRecordTests(TestCase):
    setUp = rx.RecoveryExecutionTests.setUp
    write_policy = rx.RecoveryExecutionTests.write_policy

    def test_scope_executions_returns_other_policies_runs_for_the_same_target(self):
        models.TsActionExecution.objects.create(record_id=repo._rid("EXE"), plan=self.plan, case=self.case, status="APPLIED",
                                                stage_decision="policy ARP-OLD", executed_at=NOW, idempotency_key="exe-old")
        policies = {"ARP-OLD": rx.policy(id="ARP-OLD"), "ARP-NEW": rx.policy(id="ARP-NEW"),
                    "ARP-ELSE": rx.policy(id="ARP-ELSE", interface="Ethernet9")}
        self.assertEqual(recovery.scope_executions(policies["ARP-NEW"], policies), (NOW,))

    def test_scope_executions_never_count_the_policy_itself_or_another_target(self):
        models.TsActionExecution.objects.create(record_id=repo._rid("EXE"), plan=self.plan, case=self.case, status="APPLIED",
                                                stage_decision="policy ARP-ELSE", executed_at=NOW, idempotency_key="exe-else")
        policies = {"ARP-ELSE": rx.policy(id="ARP-ELSE", interface="Ethernet9"), "ARP-TEST-001": rx.policy()}
        self.assertEqual(recovery.scope_executions(policies["ARP-ELSE"], policies), ())
        self.assertEqual(recovery.scope_executions(policies["ARP-TEST-001"], policies), ())

    def test_pending_and_undecided_plans_returns_each_plan_once(self):
        with self.settings(NMAS_TS_RECOVERY_POLICY_FILE=self.policy_file):
            self.assertEqual(recovery.pending_plans(), [self.plan.record_id])
            self.assertEqual(recovery.undecided_plans(policy_file=self.policy_file), [])         # an active policy owns it
        self.write_policy(rx.policy(enabled=False))
        self.assertEqual(recovery.undecided_plans(policy_file=self.policy_file), [self.plan.record_id])

    def test_record_plan_decision_records_a_proposal_for_approval(self):
        self.write_policy(rx.policy(enabled=False))
        sent = []
        out = recovery.record_plan_decision(self.plan.record_id, policy_file=self.policy_file, send=lambda s, b: sent.append(s))
        self.assertEqual(out["outcome"], "PROPOSE_FOR_APPROVAL")
        self.assertTrue(out["denied"][0].startswith("POLICY_NOT_ACTIVE"))
        self.assertEqual(len(sent), 1)
        self.assertEqual(recovery.undecided_plans(policy_file=self.policy_file), [])             # decided once, never again
        self.plan.refresh_from_db()
        self.assertEqual(self.plan.status, "RISK_ASSESSED")

    def test_policy_status_flags_an_invalid_policy(self):
        self.write_policy({"id": "ARP-BROKEN", "device": "S1"})
        self.assertEqual(recovery.policy_status(policy_file=self.policy_file),
                         [{"id": "ARP-BROKEN", "active": False, "warnings": ["INVALID_POLICY: KeyError"]}])

    def test_closing_an_executed_plan_leaves_it_for_a_human_review(self):
        models.TsRemediationPlan.objects.filter(pk=self.plan.pk).update(status="VERIFYING")
        with mock.patch.object(recovery.notify, "send") as send:
            self.assertEqual(recovery.fail_closed(self.plan.record_id, "RuntimeError: x"), "LEFT_VERIFYING")
        send.assert_called_once()

    def test_sweep_interrupted_returns_nothing_when_nothing_is_in_flight(self):
        with mock.patch.object(recovery.notify, "send") as send:
            self.assertEqual(recovery.sweep_interrupted(), [])
        send.assert_not_called()

    def test_sweep_interrupted_records_a_verifying_automated_plan_without_executing(self):
        approval = {"mode": gov.AUTOMATED_RECOVERY}
        models.TsRemediationPlan.objects.filter(pk=self.plan.pk).update(status="VERIFYING", approval=approval)
        with mock.patch.object(recovery.notify, "send"):
            out = recovery.sweep_interrupted()
        self.assertEqual(out, [{"plan": self.plan.record_id, "was": "VERIFYING", "run_outcome": ""}])
        self.plan.refresh_from_db()
        self.assertEqual(self.plan.status, "VERIFYING")
        self.assertEqual(self.eos.sent, [])
