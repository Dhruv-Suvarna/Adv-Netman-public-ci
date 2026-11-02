"""The runner's front end: one request per connection on a Unix stream socket.

    client -> one JSON object + "\n" (at most ``policy.MAX_REQUEST_BYTES``)
    runner -> one JSON object + "\n", then closes

Who may ask is decided twice: the socket's owner / group / mode (0660, group = the website's group; set by the systemd socket unit), and
the kernel-reported peer credentials of each connection (``SO_PEERCRED``), whose uid must be one the configuration allows.  Anything
else -- wrong peer, oversized or slow request, not JSON, not an object -- gets a refusal and nothing is executed.

One line per request goes to the journal: run id, endpoint ids, test type, timing, outcome.  Never tool output, an environment or a
credential (the runner holds none).
"""

from __future__ import annotations

import json
import socket
import struct
import threading

from . import PROTOCOL_VERSION, RUNNER_VERSION
from .policy import MAX_REQUEST_BYTES

READ_TIMEOUT_SECONDS = 5
MAX_CONNECTIONS = 8
_UCRED = struct.Struct("3i")       # pid, uid, gid


def peer_uid(connection) -> int:
    _pid, uid, _gid = _UCRED.unpack(connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, _UCRED.size))
    return uid


def _refusal(code: str) -> dict:
    return {"v": PROTOCOL_VERSION, "ok": False, "run_id": "", "runner": RUNNER_VERSION, "code": code, "refused": True}


def read_request(connection):
    """-> the decoded JSON object, or None when the bytes are not one bounded JSON object."""
    connection.settimeout(READ_TIMEOUT_SECONDS)
    data = b""
    try:
        while b"\n" not in data:
            chunk = connection.recv(MAX_REQUEST_BYTES + 1 - len(data))
            if not chunk:
                break
            data += chunk
            if len(data) > MAX_REQUEST_BYTES:
                return None
        document = json.loads(data.split(b"\n", 1)[0].decode("utf-8"))
    except (OSError, ValueError):
        return None
    return document if isinstance(document, dict) else None


def handle_connection(connection, engine, allowed_uids, log, peer=peer_uid) -> None:
    try:
        try:
            uid = peer(connection)
        except (OSError, struct.error):
            uid = None
        if uid is None or uid not in allowed_uids:
            log({"event": "traffic_run", "run_id": "", "peer_uid": uid, "outcome": "UNAUTHORIZED", "refused": True})
            reply = _refusal("UNAUTHORIZED")
        else:
            document = read_request(connection)
            if document is None:
                log({"event": "traffic_run", "run_id": "", "peer_uid": uid, "outcome": "MALFORMED_REQUEST", "refused": True})
                reply = _refusal("MALFORMED_REQUEST")
            else:
                reply = engine.handle(document, peer_uid=uid)
        connection.settimeout(READ_TIMEOUT_SECONDS)
        connection.sendall(json.dumps(reply, separators=(",", ":")).encode("utf-8") + b"\n")
        # Finish politely: closing with unread request bytes would reset the connection and could cost the peer its refusal.
        connection.shutdown(socket.SHUT_WR)
        connection.settimeout(0.5)
        for _ in range(64):
            if not connection.recv(4096):
                break
    except OSError:
        pass                        # the client went away; the run (if any) was already cleaned up and logged by the engine
    finally:
        try:
            connection.close()
        except OSError:
            pass


def serve(listener, engine, allowed_uids, log, *, stop: threading.Event) -> None:
    """Accept until ``stop`` is set, then let the requests in flight finish (their cleanup is part of the request)."""
    listener.settimeout(0.5)
    gate, workers = threading.BoundedSemaphore(MAX_CONNECTIONS), []
    while not stop.is_set():
        try:
            connection, _address = listener.accept()
        except socket.timeout:
            continue
        except OSError:
            break
        if not gate.acquire(blocking=False):
            connection.close()
            continue

        def work(connection=connection):
            try:
                handle_connection(connection, engine, allowed_uids, log)
            finally:
                gate.release()

        worker = threading.Thread(target=work, name="traffic-request")
        worker.start()
        workers = [w for w in workers if w.is_alive()] + [worker]
    for worker in workers:
        worker.join()
