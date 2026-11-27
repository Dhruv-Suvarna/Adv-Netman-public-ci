"""Direct tests for AI agent orchestration, dispatch and the completion-only model broker
(troubleshooting/agent_orchestrator.py, agent_dispatch.py, model_broker.py, model_provider.py, model_backend_openai.py).

One global execution lease is fenced: a stale grant can neither release it nor drive a provider; agent health comes only
from what a broker reports; untrusted model text is reduced to one valid response object; and a broker whose identity
differs from the configured one is refused.  Providers, brokers and the OpenAI SDK are fakes: no model is called.
"""

from __future__ import annotations

import os
import sys
import tempfile
from types import SimpleNamespace
from unittest import mock

from django.test import SimpleTestCase, TestCase

from core import models as m
from core.services.troubleshooting import agent_dispatch as dispatch
from core.services.troubleshooting import agent_orchestrator as orch
from core.services.troubleshooting import model_broker as mb
from core.services.troubleshooting import model_provider as mp
from core.services.troubleshooting.worker_ipc import IpcRefused
from core.tests import test_troubleshooting_agent_orchestrator as O
from core.tests import test_troubleshooting_model_broker as MB

IDENTITY = {"provider": "openai", "model_id": "codex-double", "model_version": "1"}


class EchoProvider:
    def __init__(self):
        self.requests = []

    def identity(self):
        return dict(IDENTITY)

    def complete(self, request):
        self.requests.append(request)
        return {"action": "conclude", "conclude": {"outcome": "INCONCLUSIVE", "summary": "s"}}


# ================================================================================================== orchestrator
class CapacityValueTests(SimpleTestCase):
    def test_required_tokens_returns_work_plus_checkpoint_reserve(self):
        self.assertEqual((orch.WorkEstimate(12_000, 2_000).required_tokens, orch.WorkEstimate(-5, 1_000).required_tokens), (14_000, 1_000))

    def test_quota_label_returns_a_bounded_percentage_or_unknown(self):
        self.assertEqual((O.health("Codex", 140.0).quota_label(), O.health("Codex", None).quota_label()), ("100.0%", "UNKNOWN"))


class LeaseUnitTests(TestCase):
    setUp = O.LeaseAndFailoverTests.setUp
    # set by LeaseAndFailoverTests.setUp
    handoff: m.TsAIHandoff

    def acquire(self):
        return orch.acquire(self.handoff.record_id, O.fleet(), O.LONG)

    def test_fenced_broker_returns_the_provider_identity_and_completion(self):
        grant, provider = self.acquire(), EchoProvider()
        broker = orch.FencedProviderBroker(provider, grant)
        self.assertEqual((broker.identity(), broker.complete({"seq": 1})["action"]), (IDENTITY, "conclude"))
        self.assertEqual(provider.requests, [{"seq": 1}])

    def test_assert_lease_of_a_stale_fence_or_another_agent_is_refused(self):
        grant = self.acquire()
        self.assertFalse(orch.assert_lease(grant.handoff_id, grant.agent, grant.fencing_token - 1))
        self.assertFalse(orch.assert_lease(grant.handoff_id, "ClaudeB", grant.fencing_token))

    def test_pause_unassigned_records_the_pause_with_a_higher_fence(self):
        fence = orch.pause_unassigned(self.handoff.record_id, reason="all agents below quota", rejected={"Codex": "QUOTA_BELOW_10_PERCENT"})
        row = m.TsGlobalAgentLease.objects.get(singleton_key=1)
        self.assertEqual((row.state, row.fencing_token, row.active_agent), ("PAUSED", fence, ""))

    def test_pause_unassigned_refuses_while_a_live_lease_is_held(self):
        self.acquire()
        with self.assertRaisesRegex(orch.OrchestrationRefused, "GLOBAL_LEASE_BUSY"):
            orch.pause_unassigned(self.handoff.record_id, reason="x")

    def test_release_returns_the_lease_to_idle_and_advances_the_fence(self):
        grant = self.acquire()
        orch.release(grant, reason="investigation complete")
        row = m.TsGlobalAgentLease.objects.get(singleton_key=1)
        self.assertEqual((row.state, row.fencing_token), ("IDLE", grant.fencing_token + 1))

    def test_release_of_a_stale_grant_is_refused(self):
        grant = self.acquire()
        orch.release(grant, reason="done")
        with self.assertRaises(orch.StaleExecutionLease):
            orch.release(grant, reason="replayed")


# ======================================================================================================= dispatch
def healthy(**over):
    return {"authenticated": True, "restricted_interface": True, "quota_reliable": True, "remaining_quota_pct": 55,
            "recent_error": "", "cooldown_until": 0, **over}


class ProbeTests(SimpleTestCase):
    def test_probe_returns_health_reported_by_the_broker(self):
        provider = SimpleNamespace(health=lambda: healthy(cooldown_until=1_800_000_000))
        status, found = dispatch.probe("Codex", lambda: provider)
        self.assertIs(found, provider)
        self.assertEqual((status.authenticated, status.remaining_quota_pct, status.cooldown_until.year), (True, 55.0, 2027))

    def test_probe_of_a_missing_refusing_or_unreliable_broker_is_down_or_unknown(self):
        def missing():
            raise IpcRefused("IPC_KEY_UNAVAILABLE")

        def refusing():
            raise IpcRefused("MODEL_IDENTITY_MISMATCH")

        for label, factory, error in (("a missing key", missing, "IPC_KEY_UNAVAILABLE"),
                                      ("an identity mismatch", lambda: SimpleNamespace(health=refusing), "MODEL_IDENTITY_MISMATCH"),
                                      ("no health interface", lambda: object(), "")):
            with self.subTest(f"{label} is down"):
                status, found = dispatch.probe("Codex", factory)
                self.assertEqual((status.authenticated, status.process_alive, found, status.recent_error), (False, False, None, error))
        with self.subTest("an unreliable quota is unknown"):
            status, _ = dispatch.probe("Codex", lambda: SimpleNamespace(health=lambda: healthy(quota_reliable=False)))
            self.assertIsNone(status.remaining_quota_pct)

    def test_probe_all_returns_only_configured_agents(self):
        statuses, providers = dispatch.probe_all({"Codex": lambda: SimpleNamespace(health=healthy)})
        self.assertEqual(([s.name for s in statuses], sorted(providers)), (["Codex"], ["Codex"]))

    def test_dispatch_result_as_dict_returns_every_field(self):
        out = dispatch.DispatchResult("ASSIGNED", "TSAI-1", agent="Codex", fencing_token=3).as_dict()
        self.assertEqual((out["status"], out["fencing_token"], out["continuation"]), ("ASSIGNED", 3, None))


class LeasedProviderTests(TestCase):
    setUp = O.LeaseAndFailoverTests.setUp
    handoff: m.TsAIHandoff

    def test_leased_provider_completes_and_records_progress(self):
        grant = orch.acquire(self.handoff.record_id, O.fleet(), O.LONG)
        leased = dispatch._LeasedProvider(EchoProvider(), grant)      # pylint: disable=protected-access  # the fenced adapter under test
        self.assertEqual((leased.identity(), leased.complete({"seq": 1})["action"], leased.error), (IDENTITY, "conclude", ""))
        self.assertTrue(orch.assert_lease(grant.handoff_id, grant.agent, leased.grant.fencing_token))


# ================================================================================================= model broker
class BrokerTests(SimpleTestCase):
    def test_encode_request_returns_canonical_ascii(self):
        self.assertEqual(mb.encode_request({"b": "é", "a": 1}), '{"a":1,"b":"\\u00e9"}')

    def test_encode_request_refuses_an_oversized_request(self):
        with self.assertRaises(IpcRefused) as caught:
            mb.encode_request({"blob": "x" * (mb.MAX_MODEL_REQUEST_BYTES + 1)})
        self.assertEqual(caught.exception.code, "MODEL_REQUEST_TOO_LARGE")

    def test_parse_model_output_returns_one_valid_response(self):
        out = mb.parse_model_output('```json\n{"action":"tool","tool":"get_case_summary","conclude":{"x":1},"extra":"dropped"}\n```')
        self.assertEqual(out, {"schema": mb.MODEL_RESPONSE_SCHEMA, "action": "tool", "tool": "get_case_summary", "args": {}})

    def test_parse_model_output_rejects_malformed_or_unbounded_text(self):
        for label, text in (("empty text", "  "), ("not JSON", "I think the link is down"), ("an unknown action", '{"action":"exec"}'),
                            ("a nameless tool", '{"action":"tool","tool":""}'), ("a conclusion without summary", '{"action":"conclude","conclude":{}}'),
                            ("oversized text", "x" * (mb.MAX_MODEL_OUTPUT_BYTES + 1))):
            with self.subTest(f"{label} is rejected"), self.assertRaises(mb.BackendError):
                mb.parse_model_output(text)

    def test_main_returns_zero_after_a_clean_serve(self):
        with mock.patch.object(mb, "server_from_environment", return_value=SimpleNamespace(serve=lambda: None)):
            self.assertEqual(mb.main(), 0)

    def test_server_from_environment_builds_the_fixed_backend_and_drops_the_credential(self):
        sdk = MB.fake_sdk("openai")
        sdk.OpenAI = lambda **kw: SimpleNamespace(kw=kw)
        with tempfile.TemporaryDirectory() as tmp:
            env = {"NMAS_TS_MODEL_AGENT": "Codex", "NMAS_TS_MODEL_BACKEND": "openai", "NMAS_TS_MODEL_PROVIDER": "openai",
                   "NMAS_TS_MODEL_ID": "codex-double", "NMAS_TS_MODEL_VERSION": "1", "NMAS_TS_MODEL_CLIENT_UID": str(os.getuid()),
                   "NMAS_TS_MODEL_IPC_KEY": "k" * 40, "NMAS_TS_MODEL_REPLAY_DB": f"{tmp}/replay.sqlite3",
                   "NMAS_TS_MODEL_AUDIT_LOG": f"{tmp}/audit.jsonl", "NMAS_TS_MODEL_SOCKET_GROUP": "",
                   "NMAS_TS_MODEL_PROVIDER_CREDENTIAL": "fixture-not-a-credential"}
            with mock.patch.dict(os.environ, env), mock.patch.dict(sys.modules, {"openai": sdk}):
                server = mb.server_from_environment()
                self.assertNotIn("NMAS_TS_MODEL_PROVIDER_CREDENTIAL", os.environ)
        self.assertEqual((server.config.socket_path, server.handler.backend.model), (mb.MODEL_SOCKETS["Codex"], "codex-double"))


class OpenAIBackendUnitTests(SimpleTestCase):
    def test_openai_backend_returns_plain_text_and_usage(self):
        reply = SimpleNamespace(status="completed", output_text='{"action":"conclude"}', output=[],
                                usage=SimpleNamespace(input_tokens=4, output_tokens=2))
        backend, seen = MB.OpenAIBackendTests.backend(None, reply)
        self.assertTrue(backend.credential_configured)
        self.assertEqual(backend.complete("SYSTEM", "PROMPT"), ('{"action":"conclude"}', {"input_tokens": 4, "output_tokens": 2}))
        self.assertIs(seen["store"], False)


# =============================================================================================== model provider
def health_result(**over):
    return {"schema": mp.MODEL_HEALTH_RESULT_SCHEMA, "agent": "Codex", **IDENTITY, "credential_configured": True, "authenticated": True,
            "restricted_interface": True, "quota_reliable": False, "remaining_quota_pct": None, "recent_error": "", "cooldown_until": 0,
            "completions": 0, "failures": 0, "last_success_at": 0, "server_time": 0, **over}


class ProviderHealthTests(SimpleTestCase):
    def provider(self):
        return mp.CompletionOnlyUnixProvider(socket_path=mp.MODEL_SOCKETS["Codex"], key=b"k" * 40, **IDENTITY)

    def call_returning(self, result):
        client = mock.Mock()
        client.return_value.call.return_value = result
        return mock.patch.object(mp, "UnixWorkerClient", client)

    def test_health_returns_the_broker_status_for_the_configured_identity(self):
        provider = self.provider()
        with self.call_returning(health_result()):
            self.assertTrue(provider.health()["authenticated"])

    def test_health_refuses_another_identity_or_a_malformed_result(self):
        provider = self.provider()
        for label, result, code in (("another identity", health_result(model_id="other"), "MODEL_IDENTITY_MISMATCH"),
                                    ("an extra field", {**health_result(), "credential": "x"}, "INVALID_MODEL_RESULT")):
            with self.subTest(f"{label} is refused"), self.call_returning(result), self.assertRaises(IpcRefused) as caught:
                provider.health()
            self.assertEqual(caught.exception.code, code)
