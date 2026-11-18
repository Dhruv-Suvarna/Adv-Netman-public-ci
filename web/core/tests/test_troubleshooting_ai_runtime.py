"""AIR-001 .. AIR-007: managed AI continuation across the REAL ai tool boundary and the REAL runtime diagnostic adapter.

Collector transports are simulated and the "model" is a scripted provider double: this is NOT live-model or live-device evidence.
"""

from __future__ import annotations

import io
import json

from django.core.management import call_command
from django.core.management.base import CommandError
from django.test import TestCase

from core import models as m
from core.services.troubleshooting import ai, ai_runtime as air
from core.services.troubleshooting import repository as repo
from core.services.troubleshooting import runtime as rt
from core.tests.test_troubleshooting_runtime import ACTOR, OUT, T0, Transport, deps, make_case

FORCE = {"force_refresh": True}


class Provider:
    """Scripted model double.  ``script`` items are dicts or callables(request)->dict."""
    def __init__(self, script, ident=None):
        self.script, self.requests, self.ident = list(script), [], ident or {"provider": "double", "model_id": "double-1", "model_version": "0"}

    def identity(self):
        return self.ident

    def complete(self, request):
        self.requests.append(request)
        item = self.script.pop(0)
        if isinstance(item, Exception):
            raise item
        return item(request) if callable(item) else item


def tool(name, args, **kw):
    return {"action": "tool", "tool": name, "args": args, **kw}


class CountingRunner(air.RuntimeDiagnosticRunner):
    pass


class OperationalDownRunner:
    read_only_tests = frozenset({"HC04"})

    def __init__(self):
        self.executed = []

    def catalog(self):
        return [{"test_id": "HC04"}]

    def run(self, test_id, target, params):
        self.executed.append((test_id, target, dict(params)))
        return {"test_id": test_id, "test_version": "1", "target": target,
                "expected": "read-only Layer-1 evidence", "verdict": "INCONCLUSIVE",
                "reason": "fixture worker returned no optic discriminator", "observed_summary": "fixture worker reached",
                "evidence_ids": [], "executed_at": T0.isoformat()}


class Base(TestCase):
    def setUp(self):
        self.tr = Transport(OUT)
        self.deps = deps(self.tr)
        self.case = make_case(key="air")
        rt.run_case(ACTOR, self.case.case_id, self.deps, run_key="s1", now=T0)
        self.case.refresh_from_db()
        self.h = ai.open_handoff(ACTOR, self.case, uncertainty="stage 1 inconclusive; need discriminating optics evidence", agent_identity="agent-9",
                                 special_case_reason="integration test: bypass exhaustion gate to exercise the binding", now=T0)
        self.runner = CountingRunner(ACTOR, self.case.case_id, self.deps, scope_key=self.h.record_id)

    def go(self, prov, **kw):
        return air.continue_handoff(ACTOR, self.h.record_id, provider=prov, runner=kw.pop("runner", self.runner), clock=lambda: T0, **kw)


def concluding(request):
    seen = request["context"]["last_result"]["data"]["evidence_ids"]
    return {"action": "conclude", "conclude": {"outcome": "ROOT_CAUSE_SUPPORTED", "summary": "link flaps explained by LF01 evidence",
            "hypotheses": [{"title": "phy flap", "domain": "L1", "supporting": seen, "confidence": 0.7}]}}


class ContinuationTests(Base):
    def test_AIR001_model_obtains_new_diagnostic_evidence_with_citations(self):
        before_calls = len(self.tr.calls)
        prov = Provider([tool("request_diagnostic_test", {"test_id": "LF01", "target": "R1", "params": FORCE}), concluding])
        res = self.go(prov)
        self.assertEqual((res.status, res.handoff_status), (air.ST_COMPLETED, "COMPLETED"), res.reason)
        self.assertEqual(self.runner.executed, [("LF01", "R1")])
        self.assertGreater(len(self.tr.calls), before_calls)            # extra read-only collection really happened through the runtime
        t = m.TsDiagnosticTest.objects.filter(case=self.case, test_id="LF01").order_by("-attempt").first()
        self.assertEqual(t.attempt, 2)
        self.assertTrue(t.evidence_ids)
        hyp = m.TsHypothesis.objects.get(case=self.case, basis="AI_INFERRED")
        self.assertEqual(hyp.state, "SUPPORTED")
        self.assertEqual(set(hyp.supporting_evidence), set(t.evidence_ids))
        cp = m.TsAIHandoff.objects.get(pk=self.h.pk).checkpoint
        self.assertEqual(cp["model"]["identity"]["model_id"], "double-1")
        self.assertEqual(cp["model"]["requests"], 2)
        self.assertTrue(all(len(e["request"]) == 24 for e in cp["model"]["exchanges"]))
        self.assertEqual(prov.requests[0]["schema"], air.REQUEST_SCHEMA)
        # Owner-authorized contract change (2026-11-17): proposal-only tools are exposed; write tools never are.
        self.assertIn("propose_remediation", prov.requests[0]["tools"])

    def test_AIR002_resume_does_not_duplicate_execution(self):
        req = tool("request_diagnostic_test", {"test_id": "LF01", "target": "R1", "params": FORCE})
        res = self.go(Provider([req, air.ProviderUnavailable("down")]))
        self.assertEqual(res.status, air.ST_PROVIDER_UNAVAILABLE)
        self.assertEqual(m.TsAIHandoff.objects.get(pk=self.h.pk).status, "OPEN")       # checkpointed, resumable
        n_calls, n_tests = len(self.tr.calls), m.TsDiagnosticTest.objects.filter(case=self.case).count()
        runner2 = CountingRunner(ACTOR, self.case.case_id, self.deps, scope_key=self.h.record_id)
        res = self.go(Provider([req, concluding]), runner=runner2)                     # a replacement worker repeats the same request
        self.assertEqual(res.status, air.ST_COMPLETED, res.reason)
        self.assertEqual(runner2.executed, [])
        self.assertEqual(len(self.tr.calls), n_calls)
        self.assertEqual(m.TsDiagnosticTest.objects.filter(case=self.case).count(), n_tests)
        self.assertEqual(m.TsAIHandoff.objects.get(pk=self.h.pk).checkpoint["calls"], 2)   # one real call + the conclude; the replayed request spent no extra tool budget

    def test_AIR003_writes_cli_and_out_of_scope_rejected(self):
        before = len(self.tr.calls)
        script = [tool("propose_remediation", {"addressed_fault": "x", "operations": [], "causal_evidence_ids": [], "rollback_plan": {}}),
                  tool("request_diagnostic_test", {"test_id": "LF01", "target": "R1", "command": "configure terminal"}),
                  tool("request_diagnostic_test", {"test_id": "LF01", "target": "R9"}),
                  tool("request_diagnostic_test", {"test_id": "LF01", "target": "R1", "params": {"op": "shutdown interface"}}),
                  tool("run_cli", {"cmd": "reload"}),
                  {"action": "conclude", "conclude": {"outcome": "INCONCLUSIVE", "summary": "could not test"}}]
        res = self.go(Provider(script))
        self.assertEqual(self.runner.executed, [])
        self.assertEqual(len(self.tr.calls), before)
        self.assertEqual(m.TsRemediationPlan.objects.filter(case=self.case).count(), 0)
        denied = m.TsAuditEvent.objects.filter(case=self.case, action="MCP_DENIED").count()
        self.assertGreaterEqual(denied, 5)
        self.assertEqual(res.status, air.ST_ESCALATED)            # 3 consecutive tool failures escalate before the model can conclude

    def test_AIR004_provider_unavailable_fails_closed(self):
        res = air.continue_handoff(ACTOR, self.h.record_id, runner=self.runner, clock=lambda: T0)
        self.assertEqual(res.status, air.ST_PROVIDER_UNAVAILABLE)
        self.assertEqual(m.TsAIHandoff.objects.get(pk=self.h.pk).status, "OPEN")
        out = io.StringIO()
        with self.assertRaises(CommandError) as cm:
            call_command("troubleshooting_ai", "continue", "--handoff", self.h.record_id, "--tenant", "acme", "--actor", "alice", stdout=out)
        self.assertIn("PROVIDER_UNAVAILABLE", str(cm.exception))
        self.assertEqual(json.loads(out.getvalue())["status"], "PROVIDER_UNAVAILABLE")

    def test_AIR005_invalid_model_output_retried_then_escalated(self):
        res = self.go(Provider([{"action": "run", "x": 1}] * 3))
        self.assertEqual(res.status, air.ST_ESCALATED)
        self.assertEqual(self.runner.executed, [])
        self.assertEqual(m.TsAIHandoff.objects.get(pk=self.h.pk).checkpoint["model"]["failures"], 3)

    def test_AIR006_authorization_and_closed_handoff(self):
        other = repo.Actor("mallory", "user", tenant="other")
        self.assertEqual(air.continue_handoff(other, self.h.record_id, provider=Provider([])).status, air.ST_NOT_AUTHORIZED)
        self.assertEqual(air.continue_handoff(ai.agent_actor(self.h), self.h.record_id, provider=Provider([])).status, air.ST_NOT_AUTHORIZED)
        ai.close_handoff(repo.Actor("nmas-system", "system", tenant="acme"), self.h.record_id, status="ESCALATED", reason="manual close for test", now=T0)
        self.assertEqual(self.go(Provider([])).status, air.ST_NOT_OPEN)

    def test_AIR007_unregistered_test_id_refused_by_adapter(self):
        res = self.go(Provider([tool("request_diagnostic_test", {"test_id": "ZZ99", "target": "R1"}),
                                {"action": "conclude", "conclude": {"outcome": "INCONCLUSIVE", "summary": "no usable test available"}}]))
        self.assertEqual(self.runner.executed, [])
        self.assertEqual(res.status, air.ST_ESCALATED)

    def test_operational_down_runs_one_idempotent_worker_test_before_model(self):
        self.case.service_intent = {**self.case.service_intent, "fault_category": "OPERATIONAL_LINK_DOWN"}
        self.case.save(update_fields=["service_intent"])
        runner = OperationalDownRunner()
        prov = Provider([{"action": "conclude", "conclude": {"outcome": "INCONCLUSIVE", "summary": "physical cause remains uncertain"}}])
        result = self.go(prov, runner=runner)
        self.assertEqual(result.status, air.ST_ESCALATED)
        self.assertEqual(runner.executed, [("HC04", "R1", FORCE)])
        self.assertEqual(m.TsDiagnosticTest.objects.filter(case=self.case, test_id="HC04").count(), 1)
        checkpoint = m.TsAIHandoff.objects.get(pk=self.h.pk).checkpoint
        self.assertIn(f"system-op-down-hc04-{self.h.record_id}", checkpoint["results"])


class LockedOnceRunner(OperationalDownRunner):
    """First call fails exactly like SQLite writer contention in the dispatcher (TS-20261117-84ED42B7); then succeeds."""

    def run(self, test_id, target, params):
        from django.db import OperationalError

        if not self.executed:
            self.executed.append(("LOCKED", target, dict(params)))
            raise OperationalError("database is locked")
        return super().run(test_id, target, params)


class PreModelLockRetryTests(Base):
    def test_a_lock_refusal_is_retried_once_under_a_distinct_nonce_and_never_reaches_the_device_twice(self):
        from unittest import mock

        self.case.service_intent = {**self.case.service_intent, "fault_category": "OPERATIONAL_LINK_DOWN"}
        self.case.save(update_fields=["service_intent"])
        runner = LockedOnceRunner()
        prov = Provider([{"action": "conclude", "conclude": {"outcome": "INCONCLUSIVE", "summary": "physical cause remains uncertain"}}])
        with mock.patch.object(air.time, "sleep"):
            self.go(prov, runner=runner)
        self.assertEqual(runner.executed, [("LOCKED", "R1", FORCE), ("HC04", "R1", FORCE)])      # one refusal, one real collection
        results = m.TsAIHandoff.objects.get(pk=self.h.pk).checkpoint["results"]
        first, retry = f"system-op-down-hc04-{self.h.record_id}", f"system-op-down-hc04-{self.h.record_id}-lockretry1"
        self.assertEqual(results[first]["error_code"], "TOOL_FAILED")                              # the refusal stays recorded
        self.assertTrue(results[retry]["ok"])

    def test_admission_acceptance_collects_on_every_delegated_target(self):
        self.case.service_intent = {**self.case.service_intent, "fault_category": air.ADMISSION_ACCEPTANCE}
        self.case.save(update_fields=["service_intent"])
        runner = OperationalDownRunner()
        prov = Provider([{"action": "conclude", "conclude": {"outcome": "INCONCLUSIVE", "summary": "acceptance evidence reviewed"}}])
        self.go(prov, runner=runner)
        self.assertEqual([t for _x, t, _p in runner.executed], sorted(self.h.allowed_targets)[:5])
        self.assertIn(f"system-acceptance-hc04-{self.h.record_id}-{sorted(self.h.allowed_targets)[0]}",
                      m.TsAIHandoff.objects.get(pk=self.h.pk).checkpoint["results"])
