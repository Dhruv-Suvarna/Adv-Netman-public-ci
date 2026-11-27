"""Completion-only Unix adapter for the isolated Troubleshooter runtime.

The runtime never loads a network SDK or provider credential.  It sends one
bounded, already-redacted ``ai-model-request/1`` object to a separately owned
Unix broker and accepts only one authenticated ``ai-model-response/1`` object
back.  The broker has a dedicated key and socket; it receives no diagnostic or
research key and this adapter exposes no shell, filesystem, destination or
generic RPC surface.
"""

from __future__ import annotations

import json
import os
import secrets

from .worker_ipc import IpcRefused, UnixWorkerClient, load_key

MODEL_REQUEST_SCHEMA = "nmas.troubleshooting.ai-model-request/1"
MODEL_RESPONSE_SCHEMA = "nmas.troubleshooting.ai-model-response/1"
MODEL_IPC_SCHEMA = "nmas.troubleshooting.model-completion/1"
MODEL_IPC_RESULT_SCHEMA = "nmas.troubleshooting.model-completion-result/1"
MODEL_HEALTH_SCHEMA = "nmas.troubleshooting.model-health/1"
MODEL_HEALTH_RESULT_SCHEMA = "nmas.troubleshooting.model-health-result/1"
_HEALTH_FIELDS = frozenset({"schema", "agent", "provider", "model_id", "model_version", "credential_configured", "authenticated",
                            "restricted_interface", "quota_reliable", "remaining_quota_pct", "recent_error", "cooldown_until",
                            "completions", "failures", "last_success_at", "server_time"})
MAX_MODEL_REQUEST_BYTES = 64_000
MODEL_SOCKET = "/run/nmas-ts-model/provider.sock"
MODEL_SOCKETS = {
    "Codex": "/run/nmas-ts-model/codex.sock",
    "ClaudeA": "/run/nmas-ts-model/claude-a.sock",
    "ClaudeB": "/run/nmas-ts-model/claude-b.sock",
}


class CompletionOnlyUnixProvider:
    """Narrow ``complete(request)`` implementation over authenticated IPC."""

    def __init__(self, *, socket_path: str, key: bytes, provider: str, model_id: str,
                 model_version: str = "", timeout_seconds: float = 60.0):
        if socket_path not in ({MODEL_SOCKET} | set(MODEL_SOCKETS.values())):
            raise IpcRefused("MODEL_SOCKET_REFUSED")
        identity = {"provider": str(provider).strip(), "model_id": str(model_id).strip(),
                    "model_version": str(model_version).strip()}
        if not identity["provider"] or not identity["model_id"] \
                or len(identity["provider"]) > 64 or len(identity["model_id"]) > 96 \
                or len(identity["model_version"]) > 64:
            raise IpcRefused("MODEL_IDENTITY_UNAVAILABLE")
        self._identity = identity
        self.ipc = UnixWorkerClient(kind="model", socket_path=socket_path, key=key,
                                    principal="nmas-ts-runtime", timeout_seconds=timeout_seconds)

    def identity(self) -> dict[str, str]:
        return dict(self._identity)

    def health(self, *, timeout_seconds: float = 3.0) -> dict:
        """Credential-free broker status.  Raises ``IpcRefused`` when the broker is absent or answers for another identity."""
        probe = UnixWorkerClient(kind="model", socket_path=self.ipc.socket_path, key=self.ipc.key,
                                 principal=self.ipc.principal, timeout_seconds=timeout_seconds)
        result = probe.call({"schema": MODEL_HEALTH_SCHEMA}, request_id=secrets.token_hex(16))
        if not isinstance(result, dict) or set(result) != _HEALTH_FIELDS or result.get("schema") != MODEL_HEALTH_RESULT_SCHEMA:
            raise IpcRefused("INVALID_MODEL_RESULT")
        if {key: str(result.get(key) or "") for key in ("provider", "model_id", "model_version")} != self._identity:
            raise IpcRefused("MODEL_IDENTITY_MISMATCH")
        return result

    def complete(self, request: dict) -> dict:
        if not isinstance(request, dict) or request.get("schema") != MODEL_REQUEST_SCHEMA:
            raise IpcRefused("INVALID_MODEL_REQUEST")
        try:
            encoded = json.dumps(request, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
        except (TypeError, ValueError, UnicodeEncodeError) as exc:
            raise IpcRefused("INVALID_MODEL_REQUEST") from exc
        if len(encoded) > MAX_MODEL_REQUEST_BYTES:
            raise IpcRefused("MODEL_REQUEST_TOO_LARGE")
        result = self.ipc.call({"schema": MODEL_IPC_SCHEMA, "request": request}, request_id=secrets.token_hex(16))
        expected = {"schema", "provider", "model_id", "model_version", "response"}
        if not isinstance(result, dict) or set(result) != expected or result.get("schema") != MODEL_IPC_RESULT_SCHEMA:
            raise IpcRefused("INVALID_MODEL_RESULT")
        returned = {key: str(result.get(key) or "") for key in ("provider", "model_id", "model_version")}
        if not secrets.compare_digest(json.dumps(returned, sort_keys=True), json.dumps(self._identity, sort_keys=True)):
            raise IpcRefused("MODEL_IDENTITY_MISMATCH")
        response = result.get("response")
        if not isinstance(response, dict) or response.get("schema", MODEL_RESPONSE_SCHEMA) != MODEL_RESPONSE_SCHEMA:
            raise IpcRefused("INVALID_MODEL_RESULT")
        return response


def completion_only_provider() -> CompletionOnlyUnixProvider:
    """Deployment factory used by ``TROUBLESHOOTING_AI_PROVIDER``."""
    return CompletionOnlyUnixProvider(
        socket_path=os.environ.get("NMAS_TS_MODEL_SOCKET", ""),
        key=load_key("NMAS_TS_MODEL_IPC_KEY"),
        provider=os.environ.get("NMAS_TS_MODEL_PROVIDER", ""),
        model_id=os.environ.get("NMAS_TS_MODEL_ID", ""),
        model_version=os.environ.get("NMAS_TS_MODEL_VERSION", ""),
        timeout_seconds=float(os.environ.get("NMAS_TS_MODEL_TIMEOUT", "60")),
    )


def _named_provider(agent: str, env_prefix: str) -> CompletionOnlyUnixProvider:
    """Build one fixed-identity adapter; each agent has a distinct socket/key."""
    return CompletionOnlyUnixProvider(
        socket_path=MODEL_SOCKETS[agent],
        key=load_key(f"{env_prefix}_IPC_KEY"),
        provider=os.environ.get(f"{env_prefix}_PROVIDER", ""),
        model_id=os.environ.get(f"{env_prefix}_ID", ""),
        model_version=os.environ.get(f"{env_prefix}_VERSION", ""),
        timeout_seconds=float(os.environ.get(f"{env_prefix}_TIMEOUT", "60")),
    )


PROVIDER_FACTORIES = {}


def codex_provider() -> CompletionOnlyUnixProvider:
    return _named_provider("Codex", "NMAS_TS_CODEX_MODEL")


def claude_a_provider() -> CompletionOnlyUnixProvider:
    return _named_provider("ClaudeA", "NMAS_TS_CLAUDEA_MODEL")


def claude_b_provider() -> CompletionOnlyUnixProvider:
    return _named_provider("ClaudeB", "NMAS_TS_CLAUDEB_MODEL")


PROVIDER_FACTORIES.update({"Codex": codex_provider, "ClaudeA": claude_a_provider, "ClaudeB": claude_b_provider})
