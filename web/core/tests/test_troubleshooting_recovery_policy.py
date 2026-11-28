"""Standing PREAUTHORIZED_AUTOMATED_RECOVERY policy: every gate must hold; any failure stops automation."""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone

from django.test import SimpleTestCase

from core.services.troubleshooting import governance as gov

NOW = datetime(2026, 11, 17, 6, 0, tzinfo=timezone.utc)
OP = {"kind": "interface_enable", "device": "R2", "interface": "Ethernet1", "intended_state": "admin_up"}
POLICY = gov.RecoveryPolicy(id="ARP-R2-E1-001", owner_authorization="OWNER-LAB-VALIDATION-20261117", device="R2", interface="Ethernet1",
                            kind="interface_enable", intended_state="admin_up", expires_at=NOW + timedelta(hours=1),
                            max_executions=3, cooldown_seconds=600, enabled=True)
CTX = gov.RecoveryContext(now=NOW, executions=(), authoritative_intent="admin_up", observed_admin_state="down",
                          observed_at=NOW - timedelta(seconds=30), maintenance_active=False, conflicting_change=False,
                          management_path_healthy=True, protected_flows_healthy=True, rollback_ready=True)


def decide(policy=POLICY, op=OP, ctx=CTX):
    return gov.evaluate_recovery_policy(policy, op, ctx, risk="HIGH")


class RecoveryPolicyTests(SimpleTestCase):
    def test_exact_match_authorizes_with_policy_attribution_and_retained_risk(self):
        d = decide()
        self.assertTrue(d["authorized"], d)
        self.assertEqual((d["authorization_type"], d["policy_id"], d["owner_authorization"], d["risk"]),
                         ("PREAUTHORIZED_AUTOMATED_RECOVERY", "ARP-R2-E1-001", "OWNER-LAB-VALIDATION-20261117", "HIGH"))

    def assertDenied(self, d, reason):
        self.assertFalse(d["authorized"], d)
        self.assertIn(reason, d["reasons"])

    def test_disabled_by_default_and_absent_policy_denied(self):
        self.assertDenied(decide(policy=replace(POLICY, enabled=False)), "POLICY_NOT_ACTIVE")
        self.assertDenied(decide(policy=None), "POLICY_NOT_ACTIVE")

    def test_unrelated_operation_and_wrong_target_denied(self):
        self.assertDenied(decide(op={"kind": "acl_change", "device": "R2"}), "POLICY_SCOPE_MISMATCH")
        self.assertDenied(decide(op={**OP, "device": "R1"}), "POLICY_SCOPE_MISMATCH")
        self.assertDenied(decide(op={**OP, "interface": "Ethernet2"}), "POLICY_SCOPE_MISMATCH")
        self.assertDenied(decide(policy=replace(POLICY, kind="config_hotfix"), op={**OP, "kind": "config_hotfix"}),
                          "POLICY_OPERATION_NOT_RECOVERABLE")

    def test_expiry_count_and_cooldown(self):
        self.assertDenied(decide(policy=replace(POLICY, expires_at=NOW)), "POLICY_EXPIRED")
        self.assertDenied(decide(ctx=replace(CTX, executions=(NOW - timedelta(hours=2),) * 3)), "EXECUTION_LIMIT_EXHAUSTED")
        self.assertDenied(decide(ctx=replace(CTX, executions=(NOW - timedelta(seconds=60),))), "COOLDOWN_ACTIVE")
        self.assertTrue(decide(ctx=replace(CTX, executions=(NOW - timedelta(seconds=700),)))["authorized"])

    def test_maintenance_conflict_intent_and_evidence_gates(self):
        self.assertDenied(decide(ctx=replace(CTX, maintenance_active=True)), "MAINTENANCE_ACTIVE")
        self.assertDenied(decide(ctx=replace(CTX, conflicting_change=True)), "CONFLICTING_CHANGE")
        self.assertDenied(decide(ctx=replace(CTX, authoritative_intent=None)), "INTENT_UNAVAILABLE")
        self.assertDenied(decide(ctx=replace(CTX, authoritative_intent="admin_down")), "INTENT_DOES_NOT_REQUIRE_STATE")
        self.assertDenied(decide(ctx=replace(CTX, observed_at=NOW - timedelta(seconds=301))), "EVIDENCE_STALE")
        self.assertDenied(decide(ctx=replace(CTX, observed_at=None)), "EVIDENCE_STALE")
        self.assertDenied(decide(ctx=replace(CTX, observed_admin_state=None)), "OBSERVED_STATE_UNAVAILABLE")

    def test_path_flow_and_rollback_gates(self):
        self.assertDenied(decide(ctx=replace(CTX, management_path_healthy=False)), "MANAGEMENT_PATH_NOT_HEALTHY")
        self.assertDenied(decide(ctx=replace(CTX, protected_flows_healthy=False)), "PROTECTED_FLOWS_NOT_HEALTHY")
        self.assertDenied(decide(ctx=replace(CTX, rollback_ready=False)), "ROLLBACK_NOT_READY")

    def test_already_up_is_idempotent_noop_not_an_execution(self):
        d = decide(ctx=replace(CTX, observed_admin_state="up"))
        self.assertEqual((d["authorized"], d["noop"], d["reasons"]), (False, True, []))

    def test_malformed_operation_never_authorized(self):
        self.assertDenied(decide(op={**OP, "interface": "Ethernet*"}), "POLICY_SCOPE_MISMATCH")
        self.assertTrue(any(r.startswith("INVALID_OPERATION") for r in decide(op={**OP, "interface": "Ethernet*"})["reasons"]))
