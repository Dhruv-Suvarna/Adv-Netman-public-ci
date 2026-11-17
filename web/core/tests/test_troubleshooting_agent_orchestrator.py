from datetime import datetime, timedelta, timezone

from django.test import TestCase

from core import models as m
from core.services.troubleshooting import agent_orchestrator as orch
from core.services.troubleshooting import ai
from core.services.troubleshooting import repository as repo


T0 = datetime(2026, 11, 15, 20, 0, tzinfo=timezone.utc)


def health(name, quota=60.0, **kw):
    return orch.AgentHealth(name=name, authenticated=kw.pop("authenticated", True),
                            responsive=kw.pop("responsive", True),
                            restricted_interface=kw.pop("restricted_interface", True),
                            remaining_quota_pct=quota, quota_reliable=quota is not None,
                            context_remaining_tokens=kw.pop("context_remaining_tokens", 50_000), **kw)


def fleet(**overrides):
    values = {"Codex": health("Codex", 60), "ClaudeA": health("ClaudeA", 60), "ClaudeB": health("ClaudeB", 60)}
    values.update(overrides)
    return list(values.values())


LONG = orch.WorkEstimate(12_000, 2_000, bounded=True, short_task=False)
SHORT = orch.WorkEstimate(1_000, 1_000, bounded=True, short_task=True)


class CapacitySelectionTests(TestCase):
    def test_seven_percent_is_rejected_and_healthy_capacity_wins(self):
        decision = orch.select_agent(fleet(Codex=health("Codex", 7)), LONG, now=T0)
        self.assertEqual(decision.selected, "ClaudeA")
        self.assertEqual(decision.rejected["Codex"], "QUOTA_BELOW_10_PERCENT")

    def test_low_quota_accepts_only_short_bounded_work(self):
        only_low = [health("Codex", 12)]
        self.assertIsNone(orch.select_agent(only_low, LONG, now=T0).selected)
        self.assertEqual(orch.select_agent(only_low, SHORT, now=T0).selected, "Codex")

    def test_unknown_quota_is_explicit_and_conservative(self):
        unknown = health("Codex", None)
        bounded = orch.select_agent([unknown], SHORT, now=T0)
        self.assertEqual(bounded.selected, "Codex")
        self.assertEqual(bounded.capacity["Codex"]["quota"], "UNKNOWN")
        unbounded = orch.select_agent([unknown], orch.WorkEstimate(1_000, bounded=False), now=T0)
        self.assertEqual(unbounded.rejected["Codex"], "UNKNOWN_QUOTA_REQUIRES_BOUNDED_TASK")

    def test_context_exhaustion_is_independent_of_account_quota(self):
        status = health("Codex", 90, context_remaining_tokens=2_500)
        decision = orch.select_agent([status], orch.WorkEstimate(2_000, 1_000), now=T0)
        self.assertEqual(decision.rejected["Codex"], "INSUFFICIENT_CONTEXT_CAPACITY")

    def test_cooldown_recovery(self):
        cooling = health("Codex", 80, cooldown_until=T0 + timedelta(minutes=1))
        self.assertIsNone(orch.select_agent([cooling], SHORT, now=T0).selected)
        self.assertEqual(orch.select_agent([cooling], SHORT, now=T0 + timedelta(minutes=2)).selected, "Codex")


class LeaseAndFailoverTests(TestCase):
    def setUp(self):
        self.case = m.TsCase.objects.create(case_id="TS-ORCH-1", tenant="acme", trigger_source="test",
                                            title="orchestration", opened_at=T0,
                                            target_states={"r1": "VERIFIED"}, affected_scope={"devices": ["r1"]})
        self.handoff = m.TsAIHandoff.objects.create(
            record_id="TSAI-ORCH-1", case=self.case, basis="DERIVED", stage="AI",
            allowed_tools=["get_case_summary"], allowed_targets=["r1"],
            budget={**ai.DEFAULT_BUDGET}, return_conditions=list(ai.RETURN_CONDITIONS), agent_identity="",
            checkpoint={"calls": 0, "bytes": 0, "iteration": 0, "devices": [], "nonces": {}, "results": {},
                        "started_at": "2026-11-15T20:00:00Z", "failures": 0, "inflight": None,
                        "inflight_until": None}, status="OPEN")

    def acquire(self, statuses=None, now=T0):
        return orch.acquire(self.handoff.record_id, statuses or fleet(), LONG, now=now)

    def test_global_exclusivity_and_monotonic_fence(self):
        grant = self.acquire()
        self.assertEqual((grant.agent, grant.fencing_token), ("Codex", 1))
        other_case = m.TsCase.objects.create(case_id="TS-ORCH-2", tenant="acme", trigger_source="test", opened_at=T0)
        m.TsAIHandoff.objects.create(record_id="TSAI-ORCH-2", case=other_case, checkpoint={}, status="OPEN")
        with self.assertRaisesRegex(orch.OrchestrationRefused, "GLOBAL_LEASE_BUSY"):
            orch.acquire("TSAI-ORCH-2", fleet(), LONG, now=T0)

    def test_mid_task_quota_exhaustion_skips_low_claude_a_and_uses_claude_b(self):
        grant = self.acquire()
        statuses = fleet(Codex=health("Codex", 0, recent_error="QUOTA_EXHAUSTED"), ClaudeA=health("ClaudeA", 12),
                         ClaudeB=health("ClaudeB", 70))
        replacement = orch.transfer(grant, statuses, LONG, reason="quota exhausted", now=T0 + timedelta(seconds=5))
        self.assertEqual(replacement.agent, "ClaudeB")
        self.assertGreater(replacement.fencing_token, grant.fencing_token)
        self.assertFalse(orch.assert_lease(grant.handoff_id, grant.agent, grant.fencing_token, now=T0 + timedelta(seconds=6)))

    def test_all_agents_exhausted_pauses_safely(self):
        grant = self.acquire()
        exhausted = [health("Codex", 0, recent_error="QUOTA_EXHAUSTED"), health("ClaudeA", 7), health("ClaudeB", 0)]
        self.assertIsNone(orch.transfer(grant, exhausted, LONG, reason="all exhausted", now=T0 + timedelta(seconds=5)))
        row = m.TsGlobalAgentLease.objects.get()
        self.assertEqual((row.state, row.active_agent), ("PAUSED", ""))
        self.handoff.refresh_from_db()
        self.assertEqual(self.handoff.checkpoint["execution_lease"]["state"], "PAUSED")

    def test_process_alive_but_stalled_fails_over(self):
        self.acquire()
        row = m.TsGlobalAgentLease.objects.get()
        row.progress_at = T0 - timedelta(minutes=10)
        row.save(update_fields=["progress_at"])
        result = orch.watchdog(fleet(), LONG, stall_seconds=60, now=T0 + timedelta(seconds=1))
        self.assertEqual((result.action, result.grant.agent), ("TRANSFERRED", "ClaudeA"))

    def test_crash_during_inflight_waits_then_transfers(self):
        grant = self.acquire()
        self.handoff.refresh_from_db()
        cp = self.handoff.checkpoint
        cp["inflight"] = "operation-1"
        cp["inflight_until"] = "2026-11-15T20:01:00Z"
        self.handoff.checkpoint = cp
        self.handoff.save(update_fields=["checkpoint"])
        crashed = fleet(Codex=health("Codex", 60, process_alive=False))
        waiting = orch.watchdog(crashed, LONG, now=T0 + timedelta(seconds=30))
        self.assertEqual(waiting.action, "WAIT_INFLIGHT")
        moved = orch.watchdog(crashed, LONG, now=T0 + timedelta(seconds=61))
        self.assertEqual((moved.action, moved.grant.agent), ("TRANSFERRED", "ClaudeA"))

    def test_liveness_heartbeat_is_not_progress(self):
        grant = self.acquire()
        orch.heartbeat(grant, useful_progress=False, now=T0 + timedelta(seconds=30))
        row = m.TsGlobalAgentLease.objects.get()
        self.assertEqual(row.progress_at, T0)

    def test_checkpoint_digest_and_case_evidence_survive_transfer(self):
        grant = self.acquire()
        m.TsEvidenceBlob.objects.create(stored_sha256="a" * 64, raw_sha256="b" * 64, content="safe evidence")
        before = m.TsEvidenceBlob.objects.count()
        self.handoff.refresh_from_db()
        cp = self.handoff.checkpoint
        cp["iteration"] = 3
        cp["results"]["nonce-safe-1"] = {"ok": True}
        orch.heartbeat(grant, useful_progress=True, checkpoint=cp, now=T0 + timedelta(seconds=5))
        replacement = orch.transfer(grant, fleet(), LONG, reason="planned handoff", now=T0 + timedelta(seconds=6))
        self.assertEqual(replacement.agent, "ClaudeA")
        self.assertEqual(m.TsEvidenceBlob.objects.count(), before)
        self.handoff.refresh_from_db()
        self.assertEqual(self.handoff.checkpoint["iteration"], 3)
        self.assertIn("nonce-safe-1", self.handoff.checkpoint["results"])
        self.assertEqual(m.TsGlobalAgentLease.objects.get().checkpoint_digest, orch._checkpoint_digest(cp))

    def test_old_agent_tool_request_after_handoff_is_rejected(self):
        grant = self.acquire()
        old_actor = repo.Actor("Codex", "agent", tenant="acme", devices=frozenset({"r1"}), tool_id="nmas-mcp")
        replacement = orch.transfer(grant, fleet(), LONG, reason="test transfer", now=T0 + timedelta(seconds=2))
        runtime = ai.Runtime(fencing_token=grant.fencing_token)
        denied = ai.call_tool(old_actor, self.handoff.record_id, "get_case_summary", {}, nonce="nonce-old-agent", rt=runtime,
                              now=T0 + timedelta(seconds=3))
        self.assertIn(denied["error_code"], {"NOT_HANDOFF_AGENT", "STALE_EXECUTION_LEASE"})
        self.assertEqual(replacement.agent, "ClaudeA")

    def test_provider_broker_discards_stale_completion(self):
        grant = self.acquire()

        class Provider:
            calls = 0

            def complete(self, request):
                self.calls += 1
                return {"action": "conclude", "conclude": {"outcome": "INCONCLUSIVE", "summary": "x"}}

        provider = Provider()
        broker = orch.FencedProviderBroker(provider, grant)
        orch.transfer(grant, fleet(), LONG, reason="fence old provider", now=T0 + timedelta(seconds=1))
        with self.assertRaises(orch.StaleExecutionLease):
            broker.complete({"bounded": True})
        self.assertEqual(provider.calls, 0)

    def test_paused_lease_can_recover_after_cooldown(self):
        grant = self.acquire()
        unavailable = [health("Codex", 0), health("ClaudeA", 0), health("ClaudeB", 0)]
        orch.transfer(grant, unavailable, LONG, reason="cooldown", now=T0 + timedelta(seconds=2))
        recovered = orch.acquire(self.handoff.record_id, [health("Codex", 80)], LONG, now=T0 + timedelta(minutes=5))
        self.assertEqual(recovered.agent, "Codex")
        self.assertGreater(recovered.fencing_token, grant.fencing_token)

