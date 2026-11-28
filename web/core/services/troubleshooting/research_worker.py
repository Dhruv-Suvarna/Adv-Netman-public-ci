"""Standalone public-document research worker and narrow application client."""

from __future__ import annotations

import json
import grp
import os
import secrets
from dataclasses import asdict
from urllib.parse import urlsplit

from .research import ResearchBroker, ResearchRefused, ResearchResult
from .worker_ipc import AuditLog, IpcRefused, ServerConfig, UnixWorkerClient, UnixWorkerServer, load_key

RESEARCH_SCHEMA = "nmas.troubleshooting.research-request/1"
RESEARCH_RESULT_SCHEMA = "nmas.troubleshooting.research-result/1"
_FIELDS = frozenset({"schema", "url", "purpose", "method"})


class ResearchHandler:
    def __init__(self, broker: ResearchBroker):
        self.broker = broker

    def __call__(self, envelope: dict) -> dict:
        value = envelope.get("payload")
        if not isinstance(value, dict) or set(value) != _FIELDS or value.get("schema") != RESEARCH_SCHEMA:
            raise IpcRefused("INVALID_RESEARCH_REQUEST")
        url, purpose, method = value.get("url"), value.get("purpose"), value.get("method")
        if not isinstance(url, str) or len(url) > 2048 or not isinstance(purpose, str) or len(purpose) > 300 \
                or method not in {"GET", "HEAD"}:
            raise IpcRefused("INVALID_RESEARCH_REQUEST")
        try:
            result = self.broker.fetch(url, purpose=purpose, principal=envelope["principal"], method=method)
        except ResearchRefused as exc:
            raise IpcRefused(exc.code) from exc
        return {"schema": RESEARCH_RESULT_SCHEMA, **asdict(result)}


class ResearchWorkerClient:
    """AI runtime adapter; no direct HTTP fallback exists."""

    def __init__(self, *, socket_path: str, key: bytes, principal: str, timeout_seconds: float = 12.0):
        self.ipc = UnixWorkerClient(kind="research", socket_path=socket_path, key=key,
                                    principal=principal, timeout_seconds=timeout_seconds)

    def fetch(self, url: str, *, purpose: str, principal: str, method: str = "GET") -> ResearchResult:
        # The runtime-supplied principal must match the identity authenticated
        # in the IPC envelope; it cannot delegate a different identity.
        if principal != self.ipc.principal:
            raise ResearchRefused("PRINCIPAL_MISMATCH")
        try:
            value = self.ipc.call({"schema": RESEARCH_SCHEMA, "url": url, "purpose": purpose, "method": method},
                                  request_id=secrets.token_hex(16))
        except IpcRefused as exc:
            raise ResearchRefused(exc.code) from exc
        if not isinstance(value, dict) or value.pop("schema", None) != RESEARCH_RESULT_SCHEMA:
            raise ResearchRefused("INVALID_RESEARCH_RESULT")
        try:
            result = ResearchResult(**value)
        except (TypeError, ValueError) as exc:
            raise ResearchRefused("INVALID_RESEARCH_RESULT") from exc
        if not result.untrusted_external_content or not 0 <= result.bytes_read <= 2_000_000 \
                or len(result.sha256) != 64:
            raise ResearchRefused("INVALID_RESEARCH_RESULT")
        return result


def _allowed_destinations() -> dict[str, tuple[str, ...]]:
    raw = os.environ.get("NMAS_TS_RESEARCH_ALLOWED_DESTINATIONS", "")
    try:
        values = json.loads(raw)
    except json.JSONDecodeError:
        values = None
    if not isinstance(values, dict) or not values or any(
        not isinstance(host, str) or not isinstance(addresses, list) or not addresses
        or any(not isinstance(address, str) for address in addresses)
        for host, addresses in values.items()
    ):
        raise IpcRefused("RESEARCH_ALLOWLIST_UNAVAILABLE")
    return {host: tuple(addresses) for host, addresses in values.items()}


def server_from_environment() -> UnixWorkerServer:
    key = load_key("NMAS_TS_RESEARCH_IPC_KEY")
    try:
        uid = int(os.environ["NMAS_TS_RESEARCH_CLIENT_UID"])
        timeout = float(os.environ.get("NMAS_TS_RESEARCH_TIMEOUT", "8"))
        max_bytes = int(os.environ.get("NMAS_TS_RESEARCH_MAX_BYTES", "262144"))
        redirects = int(os.environ.get("NMAS_TS_RESEARCH_MAX_REDIRECTS", "3"))
    except (KeyError, ValueError) as exc:
        raise IpcRefused("RESEARCH_CONFIGURATION_INVALID") from exc
    audit_path = os.environ.get("NMAS_TS_RESEARCH_AUDIT_LOG", "/var/log/nmas-ts-research/audit.jsonl")
    audit = AuditLog(audit_path)

    def research_audit(event: dict) -> None:
        parsed = urlsplit(str(event.get("destination") or ""))
        audit.write({"event": "research_egress", "kind": "research",
                     "principal": str(event.get("principal") or "")[:128],
                     "purpose": str(event.get("purpose") or "")[:160],
                     "host": str(parsed.hostname or "")[:253],
                     "decision": str(event.get("decision") or "")[:32],
                     "code": str(event.get("result") or "")[:64]})

    broker = ResearchBroker(allowed_destinations=_allowed_destinations(), timeout=timeout, max_bytes=max_bytes,
                            max_redirects=redirects, audit=research_audit)
    group_name = os.environ.get("NMAS_TS_RESEARCH_SOCKET_GROUP", "")
    config = ServerConfig(
        kind="research", key=key, allowed_uid=uid,
        socket_path=os.environ.get("NMAS_TS_RESEARCH_SOCKET", "/run/nmas-ts-research/worker.sock"),
        replay_path=os.environ.get("NMAS_TS_RESEARCH_REPLAY_DB", "/var/lib/nmas-ts-research/replay.sqlite3"),
        audit_path=audit_path, socket_gid=grp.getgrnam(group_name).gr_gid if group_name else None,
    )
    return UnixWorkerServer(config, ResearchHandler(broker))


def main() -> int:
    try:
        server_from_environment().serve()
    except KeyboardInterrupt:
        return 0
    except Exception as exc:  # pylint: disable=broad-exception-caught  # startup refusal of any kind reports only the exception class
        # Startup diagnostics disclose only the exception class, never a key,
        # URL, configuration value, or response content.
        print(f"research worker refused startup: {type(exc).__name__}", file=os.sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
