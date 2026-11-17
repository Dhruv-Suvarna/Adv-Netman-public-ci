"""Authenticated, bounded Unix IPC used by the isolated Troubleshooter workers.

The protocol is deliberately small.  It is not JSON-RPC and has no method that
can name a command, executable, socket address, or filesystem path.  Callers
sign a versioned request with a worker-specific key; the server additionally
checks the kernel supplied Unix peer uid.  Nonces are claimed in a durable
SQLite replay ledger before a request is dispatched, so a worker restart does
not make an already accepted request executable again.

Response bodies are signed too.  This prevents a process that can replace a
user-writable socket path from manufacturing diagnostic or research results.
The deployment units make the socket directories root-created and non-writable
by clients; response authentication is defence in depth.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import socket
import sqlite3
import stat
import struct
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlsplit

PROTOCOL_VERSION = 1
MAX_REQUEST_BYTES = 512 * 1024  # must carry model_provider.MAX_MODEL_REQUEST_BYTES (64 000) after JSON escaping
MAX_RESPONSE_BYTES = 768 * 1024
MAX_VALIDITY_SECONDS = 60
MAX_CLOCK_SKEW_SECONDS = 5
REQUEST_ID = re.compile(r"^[a-f0-9]{32,64}$")
SIGNATURE = re.compile(r"^[a-f0-9]{64}$")
KINDS = frozenset({"diagnostic", "research", "model"})
_REQUEST_FIELDS = frozenset({"version", "kind", "request_id", "issued_at", "expires_at", "principal", "payload", "signature"})
_RESPONSE_FIELDS = frozenset({"version", "kind", "request_id", "server_time", "ok", "result", "error", "signature"})


class IpcRefused(RuntimeError):
    """A stable, non-sensitive IPC refusal."""

    def __init__(self, code: str, detail: str = ""):
        super().__init__(code)
        self.code = str(code)[:64]
        self.detail = str(detail)[:160]


def _canonical(value: dict) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def _unsigned(value: dict) -> dict:
    return {key: item for key, item in value.items() if key != "signature"}


def sign(value: dict, key: bytes) -> str:
    return hmac.new(key, _canonical(_unsigned(value)), hashlib.sha256).hexdigest()


def verify_signature(value: dict, key: bytes) -> None:
    supplied = value.get("signature")
    if not isinstance(supplied, str) or not SIGNATURE.fullmatch(supplied):
        raise IpcRefused("AUTHENTICATION_FAILED")
    if not hmac.compare_digest(supplied, sign(value, key)):
        raise IpcRefused("AUTHENTICATION_FAILED")


def load_key(env_name: str) -> bytes:
    """Load a dedicated IPC key.  Values must be 32+ bytes and are never logged."""
    value = os.environ.get(env_name, "")
    raw = value.encode("utf-8")
    if len(raw) < 32 or len(raw) > 256:
        raise IpcRefused("IPC_KEY_UNAVAILABLE")
    return raw


def make_request(*, kind: str, principal: str, payload: dict, key: bytes,
                 request_id: str, now: int | None = None, ttl_seconds: int = 30) -> dict:
    when = int(time.time() if now is None else now)
    if kind not in KINDS or not REQUEST_ID.fullmatch(request_id):
        raise ValueError("invalid IPC request identity")
    if not isinstance(principal, str) or not principal or len(principal) > 128:
        raise ValueError("invalid IPC principal")
    if not isinstance(payload, dict) or not 1 <= int(ttl_seconds) <= MAX_VALIDITY_SECONDS:
        raise ValueError("invalid IPC request payload or lifetime")
    request = {"version": PROTOCOL_VERSION, "kind": kind, "request_id": request_id,
               "issued_at": when, "expires_at": when + int(ttl_seconds),
               "principal": principal, "payload": payload}
    request["signature"] = sign(request, key)
    if len(_canonical(request)) > MAX_REQUEST_BYTES:
        raise ValueError("IPC request is too large")
    return request


def validate_request(value: Any, *, kind: str, key: bytes, now: int | None = None) -> dict:
    when = int(time.time() if now is None else now)
    if not isinstance(value, dict) or set(value) != _REQUEST_FIELDS:
        raise IpcRefused("INVALID_ENVELOPE")
    if value.get("version") != PROTOCOL_VERSION or value.get("kind") != kind:
        raise IpcRefused("PROTOCOL_MISMATCH")
    if not isinstance(value.get("request_id"), str) or not REQUEST_ID.fullmatch(value["request_id"]):
        raise IpcRefused("INVALID_REQUEST_ID")
    if not isinstance(value.get("principal"), str) or not value["principal"] or len(value["principal"]) > 128:
        raise IpcRefused("INVALID_PRINCIPAL")
    if not isinstance(value.get("payload"), dict):
        raise IpcRefused("INVALID_PAYLOAD")
    issued, expires = value.get("issued_at"), value.get("expires_at")
    if isinstance(issued, bool) or not isinstance(issued, int) or isinstance(expires, bool) or not isinstance(expires, int):
        raise IpcRefused("INVALID_TIME_WINDOW")
    if expires <= issued or expires - issued > MAX_VALIDITY_SECONDS:
        raise IpcRefused("INVALID_TIME_WINDOW")
    if issued > when + MAX_CLOCK_SKEW_SECONDS or expires < when:
        raise IpcRefused("REQUEST_EXPIRED")
    verify_signature(value, key)
    return value


def make_response(*, kind: str, request_id: str, key: bytes, ok: bool,
                  result: Any = None, error: dict | None = None, now: int | None = None) -> dict:
    response = {"version": PROTOCOL_VERSION, "kind": kind, "request_id": request_id,
                "server_time": int(time.time() if now is None else now), "ok": bool(ok),
                "result": result if ok else None, "error": None if ok else (error or {"code": "WORKER_REFUSED"})}
    response["signature"] = sign(response, key)
    if len(_canonical(response)) > MAX_RESPONSE_BYTES:
        raise IpcRefused("RESPONSE_TOO_LARGE")
    return response


def validate_response(value: Any, *, kind: str, request_id: str, key: bytes) -> dict:
    if not isinstance(value, dict) or set(value) != _RESPONSE_FIELDS:
        raise IpcRefused("INVALID_RESPONSE")
    if value.get("version") != PROTOCOL_VERSION or value.get("kind") != kind:
        raise IpcRefused("RESPONSE_MISMATCH")
    if not isinstance(value.get("ok"), bool) or not isinstance(value.get("server_time"), int):
        raise IpcRefused("INVALID_RESPONSE")
    verify_signature(value, key)
    # Peer-credential and framing refusals happen before the server trusts or
    # even parses a caller-supplied request id.  A signed all-zero id is the
    # only permitted pre-parse refusal marker.
    if value.get("request_id") != request_id and not (value.get("request_id") == "0" * 32 and not value["ok"]):
        raise IpcRefused("RESPONSE_MISMATCH")
    return value


class ReplayLedger:
    """Durable, fail-closed nonce claims shared by worker threads/restarts."""

    def __init__(self, path: str):
        self.path = str(path)
        self._lock = threading.Lock()
        parent = Path(self.path).parent
        parent.mkdir(mode=0o750, parents=True, exist_ok=True)
        with self._connect() as db:
            db.execute("CREATE TABLE IF NOT EXISTS accepted (kind TEXT NOT NULL, request_id TEXT NOT NULL, digest TEXT NOT NULL, expires_at INTEGER NOT NULL, accepted_at INTEGER NOT NULL, PRIMARY KEY(kind, request_id))")
            db.execute("CREATE INDEX IF NOT EXISTS accepted_expiry ON accepted(expires_at)")

    def _connect(self):
        return sqlite3.connect(self.path, timeout=2.0, isolation_level=None)

    def claim(self, *, kind: str, request_id: str, digest: str, expires_at: int, now: int | None = None) -> None:
        when = int(time.time() if now is None else now)
        with self._lock, self._connect() as db:
            try:
                db.execute("BEGIN IMMEDIATE")
                db.execute("DELETE FROM accepted WHERE expires_at < ?", (when - MAX_CLOCK_SKEW_SECONDS,))
                db.execute("INSERT INTO accepted(kind, request_id, digest, expires_at, accepted_at) VALUES(?,?,?,?,?)",
                           (kind, request_id, digest, int(expires_at), when))
                db.execute("COMMIT")
            except sqlite3.IntegrityError as exc:
                db.execute("ROLLBACK")
                raise IpcRefused("REPLAY_REFUSED") from exc
            except Exception:
                try:
                    db.execute("ROLLBACK")
                except sqlite3.Error:
                    pass
                raise


class AuditLog:
    """Append sanitized JSON records without following a replacement symlink."""

    _ALLOWED = frozenset({"event", "kind", "request_id", "peer_uid", "principal", "operation_id", "device",
                          "decision", "code", "duration_ms", "bytes", "endpoint_hash", "purpose", "host"})

    def __init__(self, path: str):
        self.path = str(path)

    def write(self, event: dict) -> None:
        clean = {key: event[key] for key in self._ALLOWED if key in event and event[key] is not None}
        clean["at"] = int(time.time())
        data = _canonical(clean) + b"\n"
        flags = os.O_APPEND | os.O_CREAT | os.O_WRONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        fd = os.open(self.path, flags, 0o640)
        try:
            os.write(fd, data)
        finally:
            os.close(fd)


def peer_credentials(conn: socket.socket) -> tuple[int, int, int]:
    if not hasattr(socket, "SO_PEERCRED"):
        raise IpcRefused("PEER_CREDENTIALS_UNAVAILABLE")
    raw = conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
    return struct.unpack("3i", raw)  # pid, uid, gid


@dataclass(frozen=True)
class ServerConfig:
    kind: str
    socket_path: str
    allowed_uid: int
    key: bytes
    replay_path: str
    audit_path: str
    socket_mode: int = 0o660
    socket_gid: int | None = None


class UnixWorkerServer:
    """Small sequential Unix server.  Every accepted connection serves one request."""

    def __init__(self, config: ServerConfig, handler: Callable[[dict], Any]):
        if config.kind not in KINDS or config.allowed_uid < 0:
            raise ValueError("invalid worker server configuration")
        self.config, self.handler = config, handler
        self.replay = ReplayLedger(config.replay_path)
        self.audit = AuditLog(config.audit_path)
        self._socket: socket.socket | None = None

    def _prepare_socket(self) -> socket.socket:
        path = Path(self.config.socket_path)
        path.parent.mkdir(mode=0o750, parents=True, exist_ok=True)
        if self.config.socket_gid is not None:
            # Only the IPC group may traverse the runtime directory.  Replay
            # state and logs live in different private directories.
            os.chown(path.parent, -1, self.config.socket_gid)
            os.chmod(path.parent, 0o750)
        try:
            mode = os.lstat(path).st_mode
        except FileNotFoundError:
            pass
        else:
            if not stat.S_ISSOCK(mode):
                raise IpcRefused("UNSAFE_SOCKET_PATH")
            path.unlink()
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        server.bind(str(path))
        os.chmod(path, self.config.socket_mode)
        if self.config.socket_gid is not None:
            os.chown(path, -1, self.config.socket_gid)
        server.listen(32)
        server.settimeout(1.0)
        return server

    @staticmethod
    def _read(conn: socket.socket, limit: int) -> dict:
        chunks, total = [], 0
        while True:
            chunk = conn.recv(min(65536, limit + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > limit:
                raise IpcRefused("REQUEST_TOO_LARGE")
            if b"\n" in chunk:
                break
        raw = b"".join(chunks)
        if not raw.endswith(b"\n") or raw.count(b"\n") != 1:
            raise IpcRefused("INVALID_FRAMING")
        try:
            value = json.loads(raw[:-1].decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise IpcRefused("INVALID_JSON") from exc
        return value

    def serve(self, *, stop: Callable[[], bool] | None = None) -> None:
        self._socket = self._prepare_socket()
        try:
            while not (stop and stop()):
                try:
                    conn, _ = self._socket.accept()
                except socket.timeout:
                    continue
                with conn:
                    conn.settimeout(10.0)
                    self._serve_one(conn)
        finally:
            self._socket.close()
            self._socket = None
            try:
                Path(self.config.socket_path).unlink()
            except FileNotFoundError:
                pass

    def _serve_one(self, conn: socket.socket) -> None:
        started = time.monotonic()
        request_id = "0" * 32
        peer_uid = -1
        principal = ""
        audit_detail: dict[str, Any] = {}
        try:
            _pid, peer_uid, _gid = peer_credentials(conn)
            if peer_uid != self.config.allowed_uid:
                raise IpcRefused("PEER_UID_REFUSED")
            request = self._read(conn, MAX_REQUEST_BYTES)
            request_id = str(request.get("request_id") or request_id)
            principal = str(request.get("principal") or "")[:128]
            validate_request(request, kind=self.config.kind, key=self.config.key)
            payload = request["payload"]
            audit_detail.update({"operation_id": str(payload.get("operation_id") or "")[:96],
                                 "device": str(payload.get("device") or "")[:128],
                                 "purpose": str(payload.get("purpose") or "")[:160]})
            if self.config.kind == "research":
                audit_detail["host"] = str(urlsplit(str(payload.get("url") or "")).hostname or "")[:253]
            digest = hashlib.sha256(_canonical(request)).hexdigest()
            self.replay.claim(kind=self.config.kind, request_id=request_id, digest=digest, expires_at=request["expires_at"])
            result = self.handler(request)
            if isinstance(result, dict):
                evidence = result.get("evidence") if isinstance(result.get("evidence"), dict) else {}
                audit_detail["endpoint_hash"] = evidence.get("endpoint_hash")
                audit_detail["bytes"] = evidence.get("bytes", result.get("bytes_read"))
            response = make_response(kind=self.config.kind, request_id=request_id, key=self.config.key, ok=True, result=result)
            code, decision = "OK", "allowed"
        except IpcRefused as exc:
            response = make_response(kind=self.config.kind, request_id=request_id if REQUEST_ID.fullmatch(request_id) else "0" * 32,
                                     key=self.config.key, ok=False, error={"code": exc.code, "detail": exc.detail})
            code, decision = exc.code, "refused"
        except Exception as exc:  # fail closed; exception text is not returned
            response = make_response(kind=self.config.kind, request_id=request_id if REQUEST_ID.fullmatch(request_id) else "0" * 32,
                                     key=self.config.key, ok=False, error={"code": "WORKER_INTERNAL_ERROR"})
            code, decision = type(exc).__name__[:64], "error"
        self.audit.write({"event": "worker_request", "kind": self.config.kind, "request_id": request_id,
                          "peer_uid": peer_uid, "principal": principal, "decision": decision, "code": code,
                          "duration_ms": int((time.monotonic() - started) * 1000), **audit_detail})
        try:
            conn.sendall(_canonical(response) + b"\n")
        except OSError:
            pass


class UnixWorkerClient:
    def __init__(self, *, kind: str, socket_path: str, key: bytes, principal: str, timeout_seconds: float = 10.0):
        if kind not in KINDS:
            raise ValueError("invalid worker kind")
        self.kind, self.socket_path, self.key, self.principal = kind, socket_path, key, principal
        self.timeout_seconds = min(max(float(timeout_seconds), 0.1), 60.0)

    def call(self, payload: dict, *, request_id: str) -> Any:
        request = make_request(kind=self.kind, principal=self.principal, payload=payload, key=self.key, request_id=request_id,
                               ttl_seconds=max(1, min(int(self.timeout_seconds) + 5, MAX_VALIDITY_SECONDS)))
        deadline = time.monotonic() + self.timeout_seconds
        sock = None
        try:
            while True:
                sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                sock.settimeout(max(0.05, deadline - time.monotonic()))
                try:
                    sock.connect(self.socket_path)
                    break
                except OSError as exc:
                    sock.close()
                    sock = None
                    if exc.errno not in {2, 111} or time.monotonic() >= deadline:  # ENOENT / ECONNREFUSED during bounded startup
                        raise
                    time.sleep(min(0.02, max(0.0, deadline - time.monotonic())))
            sock.sendall(_canonical(request) + b"\n")
            response = UnixWorkerServer._read(sock, MAX_RESPONSE_BYTES)
        except (OSError, socket.timeout) as exc:
            raise IpcRefused("WORKER_UNAVAILABLE", type(exc).__name__) from exc
        finally:
            if sock is not None:
                sock.close()
        value = validate_response(response, kind=self.kind, request_id=request_id, key=self.key)
        if not value["ok"]:
            error = value.get("error") or {}
            raise IpcRefused(str(error.get("code") or "WORKER_REFUSED"), str(error.get("detail") or ""))
        return value["result"]
