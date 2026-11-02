"""The website's side of the traffic runner IPC: one structured request over a local Unix socket, one structured reply.

This is ALL the website can do towards a traffic test: it starts no process and touches no container runtime (a contract test enforces
it).  The request names endpoint IDS and bounded integers; the runner decides what they mean.  The reply is checked before it is used:
it must be the runner's protocol version and must answer THIS run id, so evidence of one run can never be recorded on another.
"""

from __future__ import annotations

import json
import socket

from django.conf import settings

from . import limits

PROTOCOL_VERSION = 1
MAX_REPLY_BYTES = 524_288
RUNNER_OVERHEAD_SECONDS = 25        # endpoint resolution, address discovery, iperf3 server start and cleanup, on top of the tool budget


class ClientError(Exception):
    """A sanitized IPC failure: only ``code`` is recorded."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def document(run) -> dict:
    """The closed request of one TrafficRun.  Nothing here is free text: ids, enumerations and the already-bounded integers."""
    return {"v": PROTOCOL_VERSION, "run_id": str(run.run_id), "source_endpoint_id": run.source, "destination_endpoint_id": run.destination,
            "address_family": run.address_family, "test_type": run.family, "protocol": run.protocol, "parameters": dict(run.parameters)}


def check(reply, run) -> dict:
    """A reply is usable only if it is the runner's answer to THIS run."""
    if not isinstance(reply, dict) or reply.get("v") != PROTOCOL_VERSION or not isinstance(reply.get("ok"), bool):
        raise ClientError("RUNNER_PROTOCOL_ERROR")
    refused_unread = reply["ok"] is False and reply.get("run_id") == "" and reply.get("refused") is True     # refused before it was parsed
    if reply.get("run_id") != str(run.run_id) and not refused_unread:
        raise ClientError("RUNNER_PROTOCOL_ERROR")
    if reply["ok"] is False and not isinstance(reply.get("code"), str):
        raise ClientError("RUNNER_PROTOCOL_ERROR")
    return reply


def submit(run) -> dict:
    """Ask the runner to execute ``run`` and wait for its reply.  Raises ClientError; never returns an unchecked document."""
    payload = json.dumps(document(run), separators=(",", ":")).encode("utf-8") + b"\n"
    budget = limits.run_timeout_seconds(run.family, run.parameters) + RUNNER_OVERHEAD_SECONDS
    data = b""
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.settimeout(budget)
            connection.connect(str(settings.NMAS_TRAFFIC_RUNNER_SOCKET))
            connection.sendall(payload)
            while len(data) <= MAX_REPLY_BYTES:
                chunk = connection.recv(65536)
                if not chunk:
                    break
                data += chunk
    except socket.timeout as exc:
        raise ClientError("RUNNER_TIMEOUT") from exc
    except OSError as exc:                   # no socket, not permitted, nobody listening, connection reset
        raise ClientError("RUNNER_UNAVAILABLE") from exc
    if not data or len(data) > MAX_REPLY_BYTES:
        raise ClientError("RUNNER_PROTOCOL_ERROR")
    try:
        reply = json.loads(data.decode("utf-8"))
    except ValueError as exc:
        raise ClientError("RUNNER_PROTOCOL_ERROR") from exc
    return check(reply, run)
