"""Adversarial tests for the completion-only model-provider Unix adapter."""

from __future__ import annotations

import os
import socket
import tempfile
import threading
import time
from pathlib import Path
from unittest.mock import patch

from django.test import SimpleTestCase

from core.services.troubleshooting.model_provider import (
    MODEL_IPC_RESULT_SCHEMA, MODEL_REQUEST_SCHEMA, MODEL_SOCKETS, CompletionOnlyUnixProvider,
    claude_a_provider, claude_b_provider, codex_provider, completion_only_provider,
)
from core.services.troubleshooting.worker_ipc import IpcRefused, ServerConfig, UnixWorkerServer


KEY = b"test-only-model-key-material-32-bytes-minimum"
IDENTITY = {"provider": "test-broker", "model_id": "test-model", "model_version": "1"}


class ModelProviderTests(SimpleTestCase):
    def fixture(self, handler, *, kind="model", key=KEY):
        tmp = tempfile.TemporaryDirectory()
        root = Path(tmp.name)
        stop = {"value": False}
        server = UnixWorkerServer(ServerConfig(
            kind=kind, socket_path=str(root / "provider.sock"), allowed_uid=os.getuid(), key=key,
            replay_path=str(root / "replay.sqlite3"), audit_path=str(root / "audit.jsonl"),
        ), handler)
        thread = threading.Thread(target=server.serve, kwargs={"stop": lambda: stop["value"]}, daemon=True)
        thread.start()
        for _ in range(100):
            if (root / "provider.sock").exists():
                break
            time.sleep(0.01)
        return tmp, root, stop, thread

    @staticmethod
    def close(tmp, root, stop, thread):
        stop["value"] = True
        try:
            wake = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            wake.connect(str(root / "provider.sock"))
            wake.close()
        except OSError:
            pass
        thread.join(2)
        tmp.cleanup()

    def test_authenticated_completion_only_round_trip(self):
        def handler(envelope):
            self.assertEqual(set(envelope["payload"]), {"schema", "request"})
            self.assertEqual(envelope["payload"]["request"]["schema"], MODEL_REQUEST_SCHEMA)
            return {"schema": MODEL_IPC_RESULT_SCHEMA, **IDENTITY,
                    "response": {"action": "conclude", "conclude": {"outcome": "INCONCLUSIVE", "summary": "bounded"}}}

        tmp, root, stop, thread = self.fixture(handler)
        try:
            with patch("core.services.troubleshooting.model_provider.MODEL_SOCKET", str(root / "provider.sock")):
                provider = CompletionOnlyUnixProvider(socket_path=str(root / "provider.sock"), key=KEY, **IDENTITY, timeout_seconds=2)
                response = provider.complete({"schema": MODEL_REQUEST_SCHEMA, "context": {}, "tools": {}})
            self.assertEqual(response["action"], "conclude")
            self.assertEqual(provider.identity(), IDENTITY)
            audit = (root / "audit.jsonl").read_text()
            self.assertNotIn("context", audit)
            self.assertNotIn("signature", audit)
        finally:
            self.close(tmp, root, stop, thread)

    def test_research_kind_wrong_key_and_identity_cannot_supply_completion(self):
        result = {"schema": MODEL_IPC_RESULT_SCHEMA, **IDENTITY,
                  "response": {"action": "conclude", "conclude": {"outcome": "INCONCLUSIVE", "summary": "bounded"}}}
        for kind, key, expected in (("research", KEY, "RESPONSE_MISMATCH"), ("model", b"x" * 32, "AUTHENTICATION_FAILED")):
            tmp, root, stop, thread = self.fixture(lambda _envelope: result, kind=kind)
            try:
                with patch("core.services.troubleshooting.model_provider.MODEL_SOCKET", str(root / "provider.sock")):
                    provider = CompletionOnlyUnixProvider(socket_path=str(root / "provider.sock"), key=key, **IDENTITY, timeout_seconds=2)
                    with self.assertRaises(IpcRefused) as caught:
                        provider.complete({"schema": MODEL_REQUEST_SCHEMA})
                self.assertEqual(caught.exception.code, expected)
            finally:
                self.close(tmp, root, stop, thread)

        tmp, root, stop, thread = self.fixture(lambda _envelope: {**result, "model_id": "substituted"})
        try:
            with patch("core.services.troubleshooting.model_provider.MODEL_SOCKET", str(root / "provider.sock")):
                provider = CompletionOnlyUnixProvider(socket_path=str(root / "provider.sock"), key=KEY, **IDENTITY, timeout_seconds=2)
                with self.assertRaises(IpcRefused) as caught:
                    provider.complete({"schema": MODEL_REQUEST_SCHEMA})
            self.assertEqual(caught.exception.code, "MODEL_IDENTITY_MISMATCH")
        finally:
            self.close(tmp, root, stop, thread)

    def test_factory_requires_exact_socket_key_and_identity(self):
        env = {"NMAS_TS_MODEL_SOCKET": "/run/nmas-ts-model/provider.sock", "NMAS_TS_MODEL_IPC_KEY": KEY.decode(),
               "NMAS_TS_MODEL_PROVIDER": "broker", "NMAS_TS_MODEL_ID": "model", "NMAS_TS_MODEL_VERSION": "1"}
        with patch.dict(os.environ, env, clear=False):
            provider = completion_only_provider()
        self.assertEqual(provider.identity()["model_id"], "model")
        with self.assertRaises(IpcRefused):
            CompletionOnlyUnixProvider(socket_path="/run/arbitrary.sock", key=KEY, **IDENTITY)

    def test_three_agents_use_distinct_fixed_completion_only_sockets_and_keys(self):
        env = {
            "NMAS_TS_CODEX_MODEL_IPC_KEY": KEY.decode(), "NMAS_TS_CODEX_MODEL_PROVIDER": "openai",
            "NMAS_TS_CODEX_MODEL_ID": "codex", "NMAS_TS_CLAUDEA_MODEL_IPC_KEY": KEY.decode(),
            "NMAS_TS_CLAUDEA_MODEL_PROVIDER": "anthropic", "NMAS_TS_CLAUDEA_MODEL_ID": "claude-a",
            "NMAS_TS_CLAUDEB_MODEL_IPC_KEY": KEY.decode(), "NMAS_TS_CLAUDEB_MODEL_PROVIDER": "anthropic",
            "NMAS_TS_CLAUDEB_MODEL_ID": "claude-b",
        }
        with patch.dict(os.environ, env, clear=False):
            providers = {"Codex": codex_provider(), "ClaudeA": claude_a_provider(), "ClaudeB": claude_b_provider()}
        self.assertEqual({p.ipc.socket_path for p in providers.values()}, set(MODEL_SOCKETS.values()))
        self.assertEqual({p.identity()["model_id"] for p in providers.values()}, {"codex", "claude-a", "claude-b"})
