"""Global lease bound to real handoff continuations over three real authenticated broker sockets.

Each of Codex, ClaudeA and ClaudeB is a real ``UnixWorkerServer`` + ``ModelHandler`` on its own socket and key; only
the provider behind each broker is a scripted double (provider errors are mocked, never induced on live accounts).
Device collection uses the simulated transport from the runtime tests.  This is not live-model or live-device
evidence.
"""

from __future__ import annotations

import json
import os
import socket
import tempfile
import threading
import time
from pathlib import Path
from unittest.mock import patch

from django.test import TransactionTestCase

from core import models as m
from core.services.troubleshooting import agent_dispatch as dispatch
from core.services.troubleshooting import agent_orchestrator as orch
from core.services.troubleshooting import ai, ai_runtime as air
from core.services.troubleshooting import model_broker as mb
from core.services.troubleshooting import model_provider as mp
from core.services.troubleshooting import runtime as rt
from core.services.troubleshooting.worker_ipc import ServerConfig, UnixWorkerServer
from core.tests.test_troubleshooting_runtime import ACTOR, OUT, T0, Transport, deps, make_case

FORCE = {"force_refresh": True}
LF01 = {"action": "tool", "tool": "request_diagnostic_test", "args": {"test_id": "LF01", "target": "R1", "params": FORCE}}
SUMMARY = {"action": "tool", "tool": "get_case_summary", "args": {}}


def concluding(prompt):
    seen = json.loads(prompt)["context"]["last_result"]["data"].get("evidence_ids") or []
    return {"action": "conclude", "conclude": {"outcome": "ROOT_CAUSE_SUPPORTED", "summary": "link flaps explained by LF01 evidence",
            "hypotheses": [{"title": "phy flap", "domain": "L1", "supporting": seen, "confidence": 0.7}]}}


class Scripted:
    credential_configured = True

    def __init__(self):
        self.script, self.prompts = [], []

    def complete(self, system, prompt):
        self.prompts.append(prompt)
        item = self.script.pop(0) if self.script else mb.BackendError(mb.PROVIDER_ERROR)
        if isinstance(item, Exception):
            raise item
        if callable(item):
            item = item(prompt)
        return (item if isinstance(item, str) else json.dumps(item)), {"input_tokens": 1, "output_tokens": 1}


class Fleet:
    """Three independent brokers, each with its own socket, key, identity, replay ledger and audit log."""

    IDENT = {"Codex": ("openai", "codex-double"), "ClaudeA": ("anthropic", "claude-a-double"), "ClaudeB": ("anthropic", "claude-b-double")}

    def __init__(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.sockets = {name: str(self.root / f"{name}.sock") for name in orch.AGENTS}
        self.keys = {name: (name.lower() + "-ipc-key-").ljust(40, "k").encode() for name in orch.AGENTS}
        self.backends = {name: Scripted() for name in orch.AGENTS}
        self.threads, self.stops = {}, {}
        for name in orch.AGENTS:
            self.start(name)

    def start(self, name):
        provider, model = self.IDENT[name]
        handler = mb.ModelHandler(agent=name, identity={"provider": provider, "model_id": model, "model_version": "1"},
                                  backend=self.backends[name])
        server = UnixWorkerServer(ServerConfig(
            kind="model", socket_path=self.sockets[name], allowed_uid=os.getuid(), key=self.keys[name],
            replay_path=str(self.root / f"{name}.replay.sqlite3"), audit_path=str(self.root / f"{name}.audit.jsonl")), handler)
        stop = {"value": False}
        thread = threading.Thread(target=server.serve, kwargs={"stop": lambda: stop["value"]}, daemon=True)
        thread.start()
        for _ in range(200):
            if os.path.exists(self.sockets[name]):
                break
            time.sleep(0.01)
        self.threads[name], self.stops[name] = thread, stop

    def kill(self, name):
        self.stops[name]["value"] = True
        try:
            wake = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            wake.connect(self.sockets[name])
            wake.close()
        except OSError:
            pass
        self.threads[name].join(3)

    def factories(self, keys=None):
        keys = keys or self.keys

        def make(name):
            provider, model = self.IDENT[name]
            return lambda: mp.CompletionOnlyUnixProvider(socket_path=self.sockets[name], key=keys[name], provider=provider,
                                                         model_id=model, model_version="1", timeout_seconds=3)
        return {name: make(name) for name in orch.AGENTS}

    def close(self):
        for name in list(self.threads):
            self.kill(name)
        self.tmp.cleanup()


class DispatchTests(TransactionTestCase):
    def setUp(self):
        self.fleet = Fleet()
        patcher = patch.dict(mp.MODEL_SOCKETS, self.fleet.sockets)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.addCleanup(self.fleet.close)
        self.tr = Transport(OUT)
        self.deps = deps(self.tr)
        self.case = make_case(key="dispatch")
        rt.run_case(ACTOR, self.case.case_id, self.deps, run_key="s1", now=T0)
        self.case.refresh_from_db()
        self.h = ai.open_handoff(ACTOR, self.case, uncertainty="stage 1 inconclusive", agent_identity="",
                                 special_case_reason="integration test: bypass exhaustion gate to exercise the binding", now=T0)
        self.runner = air.RuntimeDiagnosticRunner(ACTOR, self.case.case_id, self.deps, scope_key=self.h.record_id)

    def script(self, **scripts):
        for name, items in scripts.items():
            self.fleet.backends[name].script = list(items)

    def go(self, **kw):
        return dispatch.dispatch(ACTOR, self.h.record_id, factories=kw.pop("factories", self.fleet.factories()),
                                 runner=kw.pop("runner", self.runner), clock=lambda: T0, **kw)

    def lease(self):
        return m.TsGlobalAgentLease.objects.get(singleton_key=1)

    def handoff(self):
        return m.TsAIHandoff.objects.get(pk=self.h.pk)

    def events(self):
        return [(e["event"], e.get("from", e.get("agent", "")), e.get("to", "")) for e in self.lease().history]

    def test_healthy_codex_completes_and_releases_the_lease(self):
        self.script(Codex=[LF01, concluding])
        result = self.go()
        self.assertEqual((result.status, result.agent, result.transfers), (air.ST_COMPLETED, "Codex", []), result.reason)
        lease = self.lease()
        self.assertEqual((lease.state, lease.active_agent, lease.fencing_token), ("IDLE", "", 2))
        self.assertEqual(self.events(), [("ACQUIRED", "Codex", ""), ("RELEASED", "Codex", "")])
        self.assertEqual(self.runner.executed, [("LF01", "R1")])
        model = self.handoff().checkpoint["model"]
        self.assertEqual(model["identity"]["model_id"], "codex-double")
        self.assertEqual(model["exchanges"][0]["usage"], {"input_units": 1, "output_units": 1})   # real usage persisted
        self.assertEqual(self.fleet.backends["ClaudeA"].prompts, [])

    def test_codex_quota_then_claude_a_rate_limit_then_claude_b_finishes_without_duplicate_tool_execution(self):
        # Codex does real work then exhausts quota mid-task; ClaudeA repeats the same request (replayed, not re-run)
        # and is rate limited; ClaudeB repeats it again and concludes.
        self.script(Codex=[LF01, mb.BackendError(mb.QUOTA_EXHAUSTED)],
                    ClaudeA=[LF01, mb.BackendError(mb.RATE_LIMITED, retry_after=30)], ClaudeB=[LF01, concluding])
        collected = len(self.tr.calls)
        result = self.go()
        self.assertEqual((result.status, result.agent), (air.ST_COMPLETED, "ClaudeB"), result.reason)
        self.assertEqual([(t["from"], t["to"], t["reason"]) for t in result.transfers],
                         [("Codex", "ClaudeA", "quota exhausted"), ("ClaudeA", "ClaudeB", "rate limited")])
        self.assertEqual(self.runner.executed, [("LF01", "R1")])                    # exactly one real diagnostic execution
        self.assertGreater(len(self.tr.calls), collected)
        once = len(self.tr.calls)
        self.assertEqual(m.TsDiagnosticTest.objects.filter(case=self.case, test_id="LF01", attempt=2).count(), 1)
        checkpoint = self.handoff().checkpoint
        self.assertEqual(checkpoint["calls"], 2)                                    # one tool call + the conclusion
        self.assertEqual(self.events(), [("ACQUIRED", "Codex", ""), ("TRANSFERRED", "Codex", "ClaudeA"),
                                         ("TRANSFERRED", "ClaudeA", "ClaudeB"), ("RELEASED", "ClaudeB", "")])
        fences = [e["fence"] for e in self.lease().history]
        self.assertEqual(fences, sorted(set(fences)))                               # strictly monotonic
        self.assertEqual(len(self.tr.calls), once)
        hyp = m.TsHypothesis.objects.get(case=self.case, basis="AI_INFERRED")
        self.assertTrue(hyp.supporting_evidence)

    def test_context_exhaustion_and_provider_refusal_fail_over(self):
        self.script(Codex=[mb.BackendError(mb.CONTEXT_EXHAUSTED)], ClaudeA=[mb.BackendError(mb.PROVIDER_REFUSED)],
                    ClaudeB=[SUMMARY, {"action": "conclude", "conclude": {"outcome": "INCONCLUSIVE", "summary": "no discriminating test"}}])
        result = self.go()
        self.assertEqual((result.status, result.agent), (air.ST_ESCALATED, "ClaudeB"), result.reason)
        self.assertEqual([t["reason"] for t in result.transfers], ["context exhausted", "provider refused"])

    def test_broker_process_crash_fails_over_and_unconfigured_agent_is_never_selected(self):
        self.fleet.kill("Codex")                                                    # crashed broker: no socket
        factories = self.fleet.factories()
        factories["ClaudeA"] = lambda: mp.claude_a_provider()                       # no key in the environment
        self.script(ClaudeB=[SUMMARY, {"action": "conclude", "conclude": {"outcome": "INCONCLUSIVE", "summary": "x"}}])
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("NMAS_TS_CLAUDEA_MODEL_IPC_KEY", None)
            result = self.go(factories=factories)
        self.assertEqual((result.status, result.agent, result.transfers), (air.ST_ESCALATED, "ClaudeB", []), result.reason)

    def test_crash_mid_task_transfers_at_the_checkpoint(self):
        def crash(_prompt):
            self.fleet.stops["Codex"]["value"] = True                               # the broker dies after this answer
            return LF01
        self.script(Codex=[crash], ClaudeA=[LF01, concluding])
        result = self.go()
        self.assertEqual((result.status, result.agent), (air.ST_COMPLETED, "ClaudeA"), result.reason)
        self.assertEqual(result.transfers[0]["from"], "Codex")
        self.assertEqual(self.runner.executed, [("LF01", "R1")])

    def test_all_agents_unavailable_pauses_with_handoff_open_then_recovers_after_restart(self):
        self.script(Codex=[LF01, mb.BackendError(mb.QUOTA_EXHAUSTED)], ClaudeA=[mb.BackendError(mb.QUOTA_EXHAUSTED)],
                    ClaudeB=[mb.BackendError(mb.PROVIDER_ERROR)])
        result = self.go()
        self.assertEqual(result.status, dispatch.ST_PAUSED, result.reason)
        lease = self.lease()
        self.assertEqual((lease.state, lease.active_agent, lease.lease_expires_at), ("PAUSED", "", None))
        self.assertEqual(self.handoff().status, "OPEN")
        paused_fence = lease.fencing_token
        # No tool authority exists while paused: the last owner's fence is stale.
        actor = ai.agent_actor(self.handoff())
        denied = ai.call_tool(actor, self.h.record_id, "get_case_summary", {}, nonce="paused-attempt",
                              rt=ai.Runtime(fencing_token=paused_fence - 1), now=T0)
        self.assertFalse(denied["ok"])
        # Orchestrator restart: a new dispatcher process with fresh brokers resumes from the durable checkpoint.
        for name in orch.AGENTS:
            self.fleet.kill(name)
            self.fleet.backends[name] = Scripted()
            self.fleet.start(name)
        self.script(Codex=[LF01, concluding])
        runner2 = air.RuntimeDiagnosticRunner(ACTOR, self.case.case_id, self.deps, scope_key=self.h.record_id)
        result = self.go(runner=runner2)
        self.assertEqual((result.status, result.agent), (air.ST_COMPLETED, "Codex"), result.reason)
        self.assertEqual(runner2.executed, [])                                       # replayed from the checkpoint
        self.assertGreater(self.lease().fencing_token, paused_fence)

    def test_second_dispatch_is_refused_while_the_lease_is_held_and_stale_owner_is_fenced(self):
        statuses, _providers = dispatch.probe_all(self.fleet.factories())
        grant = orch.acquire(self.h.record_id, statuses, dispatch.DEFAULT_ESTIMATE, lease_seconds=300)
        busy = self.go()
        self.assertEqual(busy.status, dispatch.ST_BUSY)
        self.assertEqual(self.fleet.backends["Codex"].prompts, [])
        # The owner stalls; the watchdog moves the lease.  The stalled owner's late completion is discarded and
        # its tool request refused.
        later = self.lease().progress_at + orch.timedelta(seconds=400)
        moved = orch.watchdog(statuses, dispatch.DEFAULT_ESTIMATE, now=later)
        self.assertEqual((moved.action, moved.grant.agent), ("TRANSFERRED", "ClaudeA"))
        stale = dispatch._LeasedProvider(self.fleet.factories()["Codex"](), grant)
        with self.assertRaises(air.ProviderUnavailable):
            stale.complete({"schema": mp.MODEL_REQUEST_SCHEMA})
        self.assertEqual(self.fleet.backends["Codex"].prompts, [])
        old = ai.call_tool(ai.agent_actor(self.handoff()), self.h.record_id, "get_case_summary", {}, nonce="stale-owner",
                           rt=ai.Runtime(fencing_token=grant.fencing_token,
                                         lease_validator=lambda hid, token: orch.assert_lease(hid, "Codex", token)), now=T0)
        self.assertEqual((old["ok"], old["error_code"]), (False, "STALE_EXECUTION_LEASE"))

    def test_invalid_model_output_spends_retry_budget_not_a_failover(self):
        self.script(Codex=["not json", SUMMARY, {"action": "conclude", "conclude": {"outcome": "INCONCLUSIVE", "summary": "x"}}])
        result = self.go()
        self.assertEqual((result.agent, result.transfers), ("Codex", []), result.reason)

    def test_wrong_ipc_key_cannot_obtain_a_completion(self):
        wrong = {name: b"w" * 40 for name in orch.AGENTS}
        result = self.go(factories=self.fleet.factories(wrong))
        self.assertEqual(result.status, dispatch.ST_PAUSED)
        self.assertEqual(set(result.rejected), set(orch.AGENTS))
        self.assertTrue(all(not b.prompts for b in self.fleet.backends.values()))
        self.assertFalse(m.TsGlobalAgentLease.objects.filter(state="ACTIVE").exists())


from django.test import override_settings  # noqa: E402


@override_settings(NMAS_TS_AI_PROVIDER_POOL=("Codex",))
class CodexOnlyPoolTests(DispatchTests):
    """Owner policy 2026-11-16: Codex is the only production provider.  Healthy ClaudeA/ClaudeB brokers exist in this
    fixture on purpose: they must never be probed, selected or failed over to."""

    def go(self, **kw):
        if "factories" in kw:
            return super().go(**kw)
        with patch.dict(mp.PROVIDER_FACTORIES, self.fleet.factories()):
            return dispatch.dispatch(ACTOR, self.h.record_id, runner=kw.pop("runner", self.runner), clock=lambda: T0, **kw)

    def claude_untouched(self):
        self.assertEqual(self.fleet.backends["ClaudeA"].prompts + self.fleet.backends["ClaudeB"].prompts, [])
        for name in ("ClaudeA", "ClaudeB"):
            audit = self.fleet.root / f"{name}.audit.jsonl"
            self.assertFalse(audit.exists() and audit.read_text().strip(), f"{name} broker was contacted")

    def test_pool_is_exactly_codex(self):
        self.assertEqual(dispatch.provider_pool(), ("Codex",))

    def test_healthy_codex_completes_and_releases_the_lease(self):
        super().test_healthy_codex_completes_and_releases_the_lease()
        self.claude_untouched()

    def test_quota_exhaustion_mid_task_pauses_with_checkpoint_and_never_fails_over(self):
        self.script(Codex=[LF01, mb.BackendError(mb.QUOTA_EXHAUSTED)], ClaudeA=[LF01, concluding], ClaudeB=[LF01, concluding])
        result = self.go()
        self.assertEqual(result.status, dispatch.ST_PAUSED, result.reason)
        self.assertIn("awaiting provider recovery: Codex quota exhausted", result.reason)
        self.assertIn("no other agent is in the provider pool", result.reason)
        self.assertEqual(set(result.rejected) - {"Codex"}, set())
        self.claude_untouched()
        lease, handoff = self.lease(), self.handoff()
        self.assertEqual((lease.state, lease.active_agent, lease.lease_expires_at), ("PAUSED", "", None))
        self.assertEqual(handoff.status, "OPEN")
        self.assertEqual(handoff.checkpoint["calls"], 1)                              # validated work is preserved
        self.assertEqual(handoff.checkpoint["execution_lease"]["state"], "PAUSED")
        self.assertEqual(self.runner.executed, [("LF01", "R1")])
        evidence = m.TsDiagnosticTest.objects.filter(case=self.case).count()
        # A request from the paused owner's old fence is refused; deterministic work needs no model and still runs.
        stale = ai.call_tool(ai.agent_actor(handoff), self.h.record_id, "get_case_summary", {}, nonce="after-pause",
                             rt=ai.Runtime(fencing_token=lease.fencing_token - 1), now=T0)
        self.assertEqual((stale["ok"], stale["error_code"]), (False, "STALE_EXECUTION_LEASE"))
        rt.run_case(ACTOR, self.case.case_id, self.deps, run_key="deterministic-while-paused", now=T0)
        self.assertGreaterEqual(m.TsDiagnosticTest.objects.filter(case=self.case).count(), evidence)
        # Codex recovers: the same handoff resumes from its checkpoint under a higher fence, without re-running the tool.
        self.fleet.kill("Codex"); self.fleet.backends["Codex"] = Scripted(); self.fleet.start("Codex")
        self.script(Codex=[LF01, concluding])
        runner2 = air.RuntimeDiagnosticRunner(ACTOR, self.case.case_id, self.deps, scope_key=self.h.record_id)
        resumed = self.go(runner=runner2)
        self.assertEqual((resumed.status, resumed.agent), (air.ST_COMPLETED, "Codex"), resumed.reason)
        self.assertEqual(runner2.executed, [])
        self.assertGreater(self.lease().fencing_token, lease.fencing_token)
        self.claude_untouched()

    def test_codex_down_before_start_records_a_safe_pause_reason_and_resumes(self):
        self.fleet.kill("Codex")
        result = self.go()
        self.assertEqual(result.status, dispatch.ST_PAUSED)
        self.assertEqual(set(result.rejected), {"Codex"})
        lease = self.lease()
        self.assertEqual((lease.state, lease.active_agent), ("PAUSED", ""))
        event = lease.history[-1]
        self.assertEqual((event["event"], set(event["rejected"])), ("PAUSED_ALL_UNAVAILABLE", {"Codex"}))
        self.assertIn("awaiting provider recovery", event["reason"])
        self.assertEqual(self.handoff().status, "OPEN")
        self.claude_untouched()
        self.fleet.backends["Codex"] = Scripted(); self.fleet.start("Codex")
        self.script(Codex=[LF01, concluding])
        self.assertEqual(self.go().status, air.ST_COMPLETED)

    def test_crash_outage_refusal_and_context_exhaustion_all_pause_instead_of_failing_over(self):
        def crash(_prompt):
            self.fleet.stops["Codex"]["value"] = True
            return LF01
        for script in ([crash], [mb.BackendError(mb.PROVIDER_ERROR)], [mb.BackendError(mb.PROVIDER_REFUSED)],
                       [mb.BackendError(mb.CONTEXT_EXHAUSTED)], [mb.BackendError(mb.PROVIDER_TIMEOUT)]):
            if not self.fleet.threads["Codex"].is_alive():
                self.fleet.backends["Codex"] = Scripted(); self.fleet.start("Codex")
            self.script(Codex=script, ClaudeA=[SUMMARY], ClaudeB=[SUMMARY])
            result = self.go()
            self.assertEqual(result.status, dispatch.ST_PAUSED, (script, result.reason))
            self.assertEqual((self.lease().state, self.handoff().status), ("PAUSED", "OPEN"))
            self.claude_untouched()

    # Three-agent scenarios inherited from the full-pool suite do not apply to a one-provider pool.
    test_codex_quota_then_claude_a_rate_limit_then_claude_b_finishes_without_duplicate_tool_execution = None
    test_context_exhaustion_and_provider_refusal_fail_over = None
    test_broker_process_crash_fails_over_and_unconfigured_agent_is_never_selected = None
    test_crash_mid_task_transfers_at_the_checkpoint = None
    test_all_agents_unavailable_pauses_with_handoff_open_then_recovers_after_restart = None
    test_second_dispatch_is_refused_while_the_lease_is_held_and_stale_owner_is_fenced = None
    test_wrong_ipc_key_cannot_obtain_a_completion = None
