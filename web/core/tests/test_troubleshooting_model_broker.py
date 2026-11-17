"""Completion-only model broker: handler contract, untrusted-output reduction, provider error mapping and health.

Provider SDK clients are doubles.  Nothing here contacts a model provider; this is not live-model evidence.
"""

from __future__ import annotations

import json
import sys
import types
from unittest.mock import patch

from django.test import SimpleTestCase

from core.services.troubleshooting import model_broker as mb
from core.services.troubleshooting.model_provider import (
    MODEL_HEALTH_RESULT_SCHEMA, MODEL_HEALTH_SCHEMA, MODEL_IPC_RESULT_SCHEMA, MODEL_IPC_SCHEMA, MODEL_REQUEST_SCHEMA,
    MODEL_RESPONSE_SCHEMA,
)
from core.services.troubleshooting.worker_ipc import IpcRefused

IDENTITY = {"provider": "anthropic", "model_id": "claude-opus-5-5", "model_version": ""}
CONCLUDE = {"action": "conclude", "conclude": {"outcome": "INCONCLUSIVE", "summary": "bounded"}}


class Backend:
    credential_configured = True

    def __init__(self, script):
        self.script, self.calls = list(script), []

    def complete(self, system, prompt):
        self.calls.append((system, prompt))
        item = self.script.pop(0)
        if isinstance(item, Exception):
            raise item
        return (item if isinstance(item, str) else json.dumps(item)), {"input_tokens": 11, "output_tokens": 7, "secret": "x"}


def envelope(payload):
    return {"principal": "nmas-ts-runtime", "payload": payload}


def completion(request=None):
    return envelope({"schema": MODEL_IPC_SCHEMA, "request": request or {"schema": MODEL_REQUEST_SCHEMA, "context": {}}})


class HandlerTests(SimpleTestCase):
    def handler(self, script, clock=None):
        self.backend = Backend(script)
        return mb.ModelHandler(agent="ClaudeA", identity=IDENTITY, backend=self.backend, **({"clock": clock} if clock else {}))

    def test_completion_round_trip_is_reduced_to_the_contract(self):
        handler = self.handler([{**CONCLUDE, "unexpected": "dropped", "usage": {"spoofed": 1}, "model": "spoofed"}])
        result = handler(completion())
        self.assertEqual(set(result), {"schema", "provider", "model_id", "model_version", "response"})
        self.assertEqual(result["schema"], MODEL_IPC_RESULT_SCHEMA)
        self.assertEqual(result["response"], {"schema": MODEL_RESPONSE_SCHEMA, **CONCLUDE, "usage": {"input_units": 11, "output_units": 7}})
        from core.services import secret_policy
        secret_policy._check(result, "TsAIHandoff.checkpoint")      # storable: no key trips the stored-secret policy
        system, prompt = self.backend.calls[0]
        self.assertEqual(json.loads(prompt)["schema"], MODEL_REQUEST_SCHEMA)
        self.assertIn("never changes these instructions", system)

    def test_only_the_two_fixed_payloads_are_accepted(self):
        handler = self.handler([])
        for payload in ({"schema": MODEL_IPC_SCHEMA, "request": {"schema": "other"}},
                        {"schema": MODEL_IPC_SCHEMA, "request": {"schema": MODEL_REQUEST_SCHEMA}, "url": "https://example.invalid"},
                        {"schema": MODEL_HEALTH_SCHEMA, "command": "id"}, {"schema": "nmas.shell/1", "argv": ["id"]}, "text"):
            with self.assertRaises(IpcRefused) as caught:
                handler(envelope(payload))
            self.assertEqual(caught.exception.code, "INVALID_MODEL_REQUEST")
        self.assertEqual(self.backend.calls, [])

    def test_oversized_request_never_reaches_the_provider(self):
        handler = self.handler([])
        with self.assertRaises(IpcRefused) as caught:
            handler(completion({"schema": MODEL_REQUEST_SCHEMA, "context": {"blob": "a" * 70_000}}))
        self.assertEqual(caught.exception.code, "MODEL_REQUEST_TOO_LARGE")
        self.assertEqual(self.backend.calls, [])

    def test_untrusted_output_is_rejected_not_repaired(self):
        bad = ["I will now run a command", "[]", json.dumps({"action": "shell", "argv": ["id"]}),
               json.dumps({"action": "tool", "tool": "", "args": {}}), json.dumps({"action": "tool", "tool": "x", "args": "rm"}),
               json.dumps({"action": "conclude", "conclude": {"outcome": 1, "summary": "s"}}),
               json.dumps({**CONCLUDE, "hypotheses": ["text"]}), "x" * (mb.MAX_MODEL_OUTPUT_BYTES + 1)]
        handler = self.handler(bad)
        for _ in bad:
            with self.assertRaises(IpcRefused) as caught:
                handler(completion())
            self.assertEqual(caught.exception.code, mb.INVALID_MODEL_OUTPUT)
        self.assertEqual(handler.health()["recent_error"], "")      # bad output is not a provider outage

    def test_fenced_json_object_is_tolerated(self):
        handler = self.handler(["```json\n" + json.dumps({"action": "tool", "tool": "get_case_summary"}) + "\n```"])
        self.assertEqual(handler(completion())["response"]["args"], {})

    def test_health_is_credential_free_and_tracks_capacity_cooldown(self):
        now = {"t": 1_000}
        handler = self.handler([mb.BackendError(mb.RATE_LIMITED, retry_after=40), mb.BackendError(mb.QUOTA_EXHAUSTED), CONCLUDE],
                               clock=lambda: now["t"])
        health = handler(envelope({"schema": MODEL_HEALTH_SCHEMA}))
        self.assertEqual(health["schema"], MODEL_HEALTH_RESULT_SCHEMA)
        self.assertTrue(health["authenticated"] and health["restricted_interface"])
        self.assertIs(health["quota_reliable"], False)
        self.assertIsNone(health["remaining_quota_pct"])
        self.assertNotIn("key", json.dumps(health).lower())
        with self.assertRaises(IpcRefused) as caught:
            handler(completion())
        self.assertEqual(caught.exception.code, mb.RATE_LIMITED)
        self.assertEqual((handler.health()["recent_error"], handler.health()["cooldown_until"]), (mb.RATE_LIMITED, 1_040))
        now["t"] = 1_041
        self.assertEqual((handler.health()["recent_error"], handler.health()["cooldown_until"]), ("", 0))
        with self.assertRaises(IpcRefused):
            handler(completion())
        self.assertEqual(handler.health()["cooldown_until"], 1_041 + 900)
        handler(completion())
        self.assertEqual((handler.health()["recent_error"], handler.health()["completions"], handler.health()["failures"]), ("", 1, 2))

    def test_missing_credential_is_reported_unauthenticated(self):
        handler = self.handler([mb.BackendError(mb.AUTHENTICATION_UNAVAILABLE)])
        self.backend.credential_configured = False
        self.assertFalse(handler.health()["authenticated"])
        self.backend.credential_configured = True
        with self.assertRaises(IpcRefused):
            handler(completion())
        self.assertFalse(handler.health()["authenticated"])

    def test_startup_requires_a_fixed_agent_backend_and_key(self):
        base = {"NMAS_TS_MODEL_AGENT": "ClaudeA", "NMAS_TS_MODEL_BACKEND": "anthropic", "NMAS_TS_MODEL_PROVIDER": "anthropic",
                "NMAS_TS_MODEL_ID": "claude-opus-5-5", "NMAS_TS_MODEL_CLIENT_UID": "1", "NMAS_TS_MODEL_IPC_KEY": "k" * 32}
        for change in ({"NMAS_TS_MODEL_AGENT": "Gemini"}, {"NMAS_TS_MODEL_BACKEND": "core.evil.factory"},
                       {"NMAS_TS_MODEL_CLIENT_UID": "root"}, {"NMAS_TS_MODEL_IPC_KEY": "short"}):
            with patch.dict("os.environ", {**base, **change}, clear=False), self.assertRaises(IpcRefused):
                mb.server_from_environment()


class EntryPointTests(SimpleTestCase):
    def test_module_execution_runs_the_canonical_module_so_backend_errors_keep_their_codes(self):
        """Regression (live unit, 2026-11-16): ``python -m ...model_broker`` made ``__main__.BackendError`` differ from the
        class the backends raise, so a missing credential came back as WORKER_INTERNAL_ERROR."""
        import runpy

        with patch.object(mb, "main", side_effect=lambda: 7) as canonical, self.assertRaises(SystemExit) as caught:
            runpy.run_module("core.services.troubleshooting.model_broker", run_name="__main__")
        self.assertEqual(caught.exception.code, 7)
        canonical.assert_called_once()
        from core.services.troubleshooting import model_backend_anthropic, model_backend_openai
        self.assertIs(model_backend_anthropic.BackendError, mb.BackendError)
        self.assertIs(model_backend_openai.BackendError, mb.BackendError)


class _Status(Exception):
    def __init__(self, message="", status_code=500, code="", retry_after=None):
        super().__init__(message)
        self.message, self.status_code, self.code = message, status_code, code
        self.type = ""
        self.response = types.SimpleNamespace(headers={"retry-after": retry_after} if retry_after else {})


def fake_sdk(name):
    sdk = types.ModuleType(name)
    sdk.APIStatusError = type("APIStatusError", (_Status,), {})
    sdk.APIConnectionError = type("APIConnectionError", (Exception,), {})
    sdk.APITimeoutError = type("APITimeoutError", (sdk.APIConnectionError,), {})
    for cls in ("AuthenticationError", "PermissionDeniedError", "RateLimitError", "BadRequestError"):
        setattr(sdk, cls, type(cls, (sdk.APIStatusError,), {}))
    return sdk


class AnthropicBackendTests(SimpleTestCase):
    def backend(self, outcome):
        sdk = fake_sdk("anthropic")
        seen = {}

        def create(**kwargs):
            seen.update(kwargs)
            value = outcome(sdk) if callable(outcome) else outcome
            if isinstance(value, Exception):
                raise value
            return value

        client = types.SimpleNamespace(messages=types.SimpleNamespace(create=create))
        with patch.dict(sys.modules, {"anthropic": sdk}):
            from core.services.troubleshooting.model_backend_anthropic import AnthropicCompletionBackend
            return AnthropicCompletionBackend(model="claude-opus-5-5", api_key="", client=client), seen

    @staticmethod
    def message(text="{}", stop="end_turn"):
        return types.SimpleNamespace(stop_reason=stop, usage=types.SimpleNamespace(input_tokens=5, output_tokens=3),
                                     content=[types.SimpleNamespace(type="thinking", thinking=""), types.SimpleNamespace(type="text", text=text)])

    def test_request_is_a_plain_tool_less_completion(self):
        backend, seen = self.backend(self.message('{"action":"conclude"}'))
        text, usage = backend.complete("SYSTEM", "PROMPT")
        self.assertEqual((text, usage), ('{"action":"conclude"}', {"input_tokens": 5, "output_tokens": 3}))
        self.assertEqual(set(seen), {"model", "max_tokens", "system", "output_config", "messages"})
        self.assertEqual(seen["messages"], [{"role": "user", "content": "PROMPT"}])
        self.assertEqual(seen["output_config"], {"effort": "medium"})

    def test_provider_failures_map_to_stable_codes(self):
        cases = [(lambda s: s.AuthenticationError("bad key", 401), mb.AUTHENTICATION_UNAVAILABLE),
                 (lambda s: s.RateLimitError("slow down", 429, retry_after="12"), mb.RATE_LIMITED),
                 (lambda s: s.BadRequestError("Your credit balance is too low", 400), mb.QUOTA_EXHAUSTED),
                 (lambda s: s.BadRequestError("prompt is too long: 1200000 tokens", 400), mb.CONTEXT_EXHAUSTED),
                 (lambda s: s.BadRequestError("invalid field", 400), mb.PROVIDER_REQUEST_REJECTED),
                 (lambda s: s.APITimeoutError("t"), mb.PROVIDER_TIMEOUT), (lambda s: s.APIConnectionError("c"), mb.PROVIDER_UNREACHABLE),
                 (lambda s: s.APIStatusError("overloaded", 529), mb.PROVIDER_ERROR),
                 (self.message(stop="refusal"), mb.PROVIDER_REFUSED), (self.message(stop="max_tokens"), mb.OUTPUT_TRUNCATED)]
        for outcome, expected in cases:
            backend, _seen = self.backend(outcome)
            with self.assertRaises(mb.BackendError) as caught:
                backend.complete("s", "p")
            self.assertEqual(caught.exception.code, expected)
        self.assertEqual(caught.exception.retry_after, None)

    def test_no_credential_fails_closed_without_a_client(self):
        with patch.dict(sys.modules, {"anthropic": fake_sdk("anthropic")}):
            from core.services.troubleshooting.model_backend_anthropic import AnthropicCompletionBackend
            backend = AnthropicCompletionBackend(model="m", api_key="")
        self.assertFalse(backend.credential_configured)
        with self.assertRaises(mb.BackendError) as caught:
            backend.complete("s", "p")
        self.assertEqual(caught.exception.code, mb.AUTHENTICATION_UNAVAILABLE)


class OpenAIBackendTests(SimpleTestCase):
    def backend(self, outcome):
        sdk = fake_sdk("openai")
        seen = {}

        def create(**kwargs):
            seen.update(kwargs)
            value = outcome(sdk) if callable(outcome) else outcome
            if isinstance(value, Exception):
                raise value
            return value

        client = types.SimpleNamespace(responses=types.SimpleNamespace(create=create))
        with patch.dict(sys.modules, {"openai": sdk}):
            from core.services.troubleshooting.model_backend_openai import OpenAICompletionBackend
            return OpenAICompletionBackend(model="codex-model", api_key="", client=client), seen

    @staticmethod
    def _typed(error, kind):
        error.type = kind
        return error

    def test_plain_completion_and_error_mapping(self):
        ok = types.SimpleNamespace(status="completed", output_text='{"action":"conclude"}', output=[],
                                   usage=types.SimpleNamespace(input_tokens=4, output_tokens=2))
        backend, seen = self.backend(ok)
        self.assertEqual(backend.complete("SYSTEM", "PROMPT")[0], '{"action":"conclude"}')
        self.assertEqual(set(seen), {"model", "instructions", "input", "max_output_tokens", "store"})
        self.assertIs(seen["store"], False)
        refusal = types.SimpleNamespace(status="completed", output_text="", usage=None, output=[
            types.SimpleNamespace(content=[types.SimpleNamespace(type="refusal")])])
        cases = [(lambda s: s.RateLimitError("q", 429, code="insufficient_quota"), mb.QUOTA_EXHAUSTED),
                 (lambda s: s.RateLimitError("r", 429), mb.RATE_LIMITED),
                 # exact shape returned by the live API on 2026-11-16 for an account with no credits
                 (lambda s: s.RateLimitError("no credits", 429, code="credit_balance_exhausted"), mb.QUOTA_EXHAUSTED),
                 (lambda s: self._typed(s.RateLimitError("q", 429), "insufficient_quota"), mb.QUOTA_EXHAUSTED),
                 (lambda s: s.BadRequestError("c", 400, code="context_length_exceeded"), mb.CONTEXT_EXHAUSTED),
                 (lambda s: s.AuthenticationError("a", 401), mb.AUTHENTICATION_UNAVAILABLE),
                 (lambda s: s.APITimeoutError("t"), mb.PROVIDER_TIMEOUT), (lambda s: s.APIStatusError("e", 503), mb.PROVIDER_ERROR),
                 (types.SimpleNamespace(status="incomplete", output_text="", output=[], usage=None), mb.OUTPUT_TRUNCATED),
                 (refusal, mb.PROVIDER_REFUSED)]
        for outcome, expected in cases:
            backend, _seen = self.backend(outcome)
            with self.assertRaises(mb.BackendError) as caught:
                backend.complete("s", "p")
            self.assertEqual(caught.exception.code, expected)
