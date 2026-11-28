"""Direct tests for the signed worker IPC envelope (troubleshooting/worker_ipc.py).

The envelope is HMAC-signed, time-bounded, replay-claimed and peer-uid checked; every refusal is a stable code and no
key or exception text ever leaves the process.  Servers run on a private temporary socket in this process.
"""

from __future__ import annotations

import json
import os
import socket
import tempfile
import threading
from pathlib import Path
from unittest import mock

from django.test import SimpleTestCase

from core.services.troubleshooting import worker_ipc as ipc
from core.tests.test_troubleshooting_workers import KEY, _ServerFixture

RID = "a" * 32
NOW = 1_800_000_000


def request(**over):
    base = dict(kind="diagnostic", principal="agent-1", payload={"operation_id": "op"}, key=KEY, request_id=RID, now=NOW)
    return ipc.make_request(**{**base, **over})


class EnvelopeTests(SimpleTestCase):
    def test_ipc_exception_keeps_a_bounded_code_and_detail(self):
        err = ipc.IpcRefused("X" * 100, "d" * 400)
        self.assertEqual((len(err.code), len(err.detail), str(err)), (64, 160, "X" * 100))

    def test_ipc_exception_without_detail_has_an_empty_detail(self):
        self.assertEqual(ipc.IpcRefused("AUTHENTICATION_FAILED").detail, "")

    def test_sign_and_verify_signature_accept_an_untampered_envelope(self):
        value = {"a": 1, "b": [2]}
        value["signature"] = ipc.sign(value, KEY)
        self.assertIsNone(ipc.verify_signature(value, KEY))
        self.assertEqual(ipc.sign({"b": [2], "a": 1}, KEY), value["signature"])        # canonical: key order is irrelevant

    def test_verify_signature_refuses_tampered_missing_or_foreign_signatures(self):
        value = {"a": 1}
        value["signature"] = ipc.sign(value, KEY)
        for label, candidate, key in (("a tampered body", {**value, "a": 2}, KEY), ("a missing signature", {"a": 1}, KEY),
                                      ("a malformed signature", {**value, "signature": "zz"}, KEY), ("another key", value, KEY + b"x")):
            with self.subTest(f"{label} is refused"):
                with self.assertRaises(ipc.IpcRefused):
                    ipc.verify_signature(candidate, key)

    def test_load_key_returns_a_dedicated_key(self):
        with mock.patch.dict(os.environ, {"NMAS_TEST_IPC_KEY": "k" * 40}):
            self.assertEqual(ipc.load_key("NMAS_TEST_IPC_KEY"), b"k" * 40)

    def test_load_key_refuses_short_long_or_missing_keys(self):
        for label, value in (("a short key", "k" * 31), ("an oversized key", "k" * 257), ("an unset key", None)):
            env = {} if value is None else {"NMAS_TEST_IPC_KEY": value}
            with self.subTest(f"{label} is refused"), mock.patch.dict(os.environ, env, clear=False):
                if value is None:
                    os.environ.pop("NMAS_TEST_IPC_KEY", None)
                with self.assertRaises(ipc.IpcRefused):
                    ipc.load_key("NMAS_TEST_IPC_KEY")

    def test_make_and_validate_request_roundtrip(self):
        req = request()
        self.assertEqual((req["expires_at"] - req["issued_at"], req["principal"]), (30, "agent-1"))
        self.assertIs(ipc.validate_request(req, kind="diagnostic", key=KEY, now=NOW + 1), req)

    def test_make_request_refuses_invalid_identity_principal_or_lifetime(self):
        for label, over in (("an unknown kind", {"kind": "shell"}), ("a short request id", {"request_id": "abc"}),
                            ("an empty principal", {"principal": ""}), ("an unbounded lifetime", {"ttl_seconds": 3600}),
                            ("an oversized payload", {"payload": {"x": "y" * (ipc.MAX_REQUEST_BYTES + 1)}})):
            with self.subTest(f"{label} is refused"):
                with self.assertRaises(ValueError):
                    request(**over)

    def test_validate_request_refuses_every_malformed_or_stale_envelope(self):
        req = request()
        cases = (("a non-dict", "x", "INVALID_ENVELOPE"), ("an extra field", {**req, "extra": 1}, "INVALID_ENVELOPE"),
                 ("another kind", {**req, "kind": "research"}, "PROTOCOL_MISMATCH"),
                 ("a bad request id", {**req, "request_id": "Z"}, "INVALID_REQUEST_ID"),
                 ("an empty principal", {**req, "principal": ""}, "INVALID_PRINCIPAL"),
                 ("a non-dict payload", {**req, "payload": []}, "INVALID_PAYLOAD"),
                 ("a boolean time", {**req, "issued_at": True}, "INVALID_TIME_WINDOW"),
                 ("an over-long window", {**req, "expires_at": req["issued_at"] + 61}, "INVALID_TIME_WINDOW"),
                 ("a tampered principal", {**req, "principal": "agent-2"}, "AUTHENTICATION_FAILED"))
        for label, value, code in cases:
            with self.subTest(f"{label} is refused"):
                with self.assertRaises(ipc.IpcRefused) as caught:
                    ipc.validate_request(value, kind="diagnostic", key=KEY, now=NOW)
                self.assertEqual(caught.exception.code, code)
        with self.subTest("an expired request is refused"):
            with self.assertRaises(ipc.IpcRefused) as caught:
                ipc.validate_request(req, kind="diagnostic", key=KEY, now=NOW + 31)
            self.assertEqual(caught.exception.code, "REQUEST_EXPIRED")

    def test_make_and_validate_response_roundtrip(self):
        res = ipc.make_response(kind="diagnostic", request_id=RID, key=KEY, ok=True, result={"x": 1}, now=NOW)
        self.assertEqual((res["result"], res["error"]), ({"x": 1}, None))
        self.assertIs(ipc.validate_response(res, kind="diagnostic", request_id=RID, key=KEY), res)
        refused = ipc.make_response(kind="diagnostic", request_id="0" * 32, key=KEY, ok=False, now=NOW)
        self.assertEqual(ipc.validate_response(refused, kind="diagnostic", request_id=RID, key=KEY)["error"], {"code": "WORKER_REFUSED"})

    def test_make_response_refuses_an_oversized_result(self):
        with self.assertRaises(ipc.IpcRefused) as caught:
            ipc.make_response(kind="diagnostic", request_id=RID, key=KEY, ok=True, result="x" * (ipc.MAX_RESPONSE_BYTES + 1))
        self.assertEqual(caught.exception.code, "RESPONSE_TOO_LARGE")

    def test_validate_response_refuses_mismatched_or_forged_responses(self):
        res = ipc.make_response(kind="diagnostic", request_id=RID, key=KEY, ok=True, result={}, now=NOW)
        zero_ok = ipc.make_response(kind="diagnostic", request_id="0" * 32, key=KEY, ok=True, result={}, now=NOW)
        cases = (("a non-dict", None, RID, "INVALID_RESPONSE"), ("another kind", {**res, "kind": "model"}, RID, "RESPONSE_MISMATCH"),
                 ("a non-boolean ok", {**res, "ok": 1}, RID, "INVALID_RESPONSE"), ("a forged result", {**res, "result": {"x": 1}}, RID, "AUTHENTICATION_FAILED"),
                 ("another request id", res, "b" * 32, "RESPONSE_MISMATCH"), ("an ok zero marker", zero_ok, RID, "RESPONSE_MISMATCH"))
        for label, value, rid, code in cases:
            with self.subTest(f"{label} is refused"):
                with self.assertRaises(ipc.IpcRefused) as caught:
                    ipc.validate_response(value, kind="diagnostic", request_id=rid, key=KEY)
                self.assertEqual(caught.exception.code, code)


class LedgerAndAuditTests(SimpleTestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def test_replay_ledger_refuses_a_second_claim_of_the_same_request(self):
        ledger = ipc.ReplayLedger(str(self.root / "state" / "replay.sqlite3"))
        ledger.claim(kind="diagnostic", request_id=RID, digest="d", expires_at=NOW + 30, now=NOW)
        with self.assertRaises(ipc.IpcRefused) as caught:
            ipc.ReplayLedger(str(self.root / "state" / "replay.sqlite3")).claim(kind="diagnostic", request_id=RID, digest="d",
                                                                                 expires_at=NOW + 30, now=NOW + 1)
        self.assertEqual(caught.exception.code, "REPLAY_REFUSED")

    def test_audit_log_constructs_and_writes_only_allowlisted_fields(self):
        log = ipc.AuditLog(str(self.root / "audit.jsonl"))
        log.write({"event": "worker_request", "code": "OK", "password": "never", "payload": {"x": 1}, "device": None})
        row = json.loads((self.root / "audit.jsonl").read_text())
        self.assertEqual(sorted(row), ["at", "code", "event"])

    def test_audit_log_constructed_on_a_symlink_refuses_to_follow_it(self):
        target = self.root / "elsewhere"
        target.write_text("")
        (self.root / "audit.jsonl").symlink_to(target)
        with self.assertRaises(OSError):
            ipc.AuditLog(str(self.root / "audit.jsonl")).write({"event": "x"})
        self.assertEqual(target.read_text(), "")


class PeerAndServerTests(SimpleTestCase):
    def test_peer_credentials_returns_this_process_identity(self):
        a, b = socket.socketpair(socket.AF_UNIX)
        self.addCleanup(a.close)
        self.addCleanup(b.close)
        _pid, uid, gid = ipc.peer_credentials(a)
        self.assertEqual((uid, gid), (os.getuid(), os.getgid()))

    def test_peer_credentials_unavailable_is_refused(self):
        with mock.patch.object(ipc, "socket", mock.Mock(spec=[])), self.assertRaises(ipc.IpcRefused) as caught:
            ipc.peer_credentials(None)
        self.assertEqual(caught.exception.code, "PEER_CREDENTIALS_UNAVAILABLE")

    def worker_client(self, fixture, kind="diagnostic"):
        return ipc.UnixWorkerClient(kind=kind, socket_path=str(fixture.root / "worker.sock"), key=KEY, principal="agent-1", timeout_seconds=2)

    def test_serve_answers_a_signed_request_and_audits_it(self):
        fixture = _ServerFixture("diagnostic", lambda req: {"echo": req["payload"]["operation_id"]})
        self.addCleanup(fixture.close)
        self.assertEqual(self.worker_client(fixture).call({"operation_id": "op-1"}, request_id=RID), {"echo": "op-1"})
        audit = [json.loads(line) for line in (fixture.root / "audit.jsonl").read_text().splitlines()]
        self.assertEqual([(a["decision"], a["operation_id"]) for a in audit], [("allowed", "op-1")])

    def test_serve_refuses_a_replay_a_foreign_uid_and_a_failing_handler(self):
        fixture = _ServerFixture("diagnostic", lambda req: {"ok": True})
        self.addCleanup(fixture.close)
        req = ipc.make_request(kind="diagnostic", principal="agent-1", payload={}, key=KEY, request_id="c" * 32)

        def send(raw):
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
                s.settimeout(2)
                s.connect(str(fixture.root / "worker.sock"))
                s.sendall(raw)
                return ipc.UnixWorkerServer._read(s, ipc.MAX_RESPONSE_BYTES)  # pylint: disable=protected-access  # the framing reader the client uses
        line = json.dumps(req, sort_keys=True, separators=(",", ":")).encode() + b"\n"
        with self.subTest("a replayed request is refused"):
            self.assertTrue(send(line)["ok"])
            self.assertEqual(send(line)["error"]["code"], "REPLAY_REFUSED")
        with self.subTest("unframed json is refused"):
            self.assertEqual(send(b"not json\n")["error"]["code"], "INVALID_JSON")
        foreign = _ServerFixture("diagnostic", lambda req: {}, allowed_uid=os.getuid() + 1)
        self.addCleanup(foreign.close)
        with self.subTest("a foreign peer uid is refused"):
            with self.assertRaises(ipc.IpcRefused) as caught:
                self.worker_client(foreign).call({}, request_id="d" * 32)
            self.assertEqual(caught.exception.code, "PEER_UID_REFUSED")

        def broken(req):
            raise RuntimeError("secret detail")
        failing = _ServerFixture("diagnostic", broken)
        self.addCleanup(failing.close)
        with self.subTest("a failing handler is refused without its text"):
            with self.assertRaises(ipc.IpcRefused) as caught:
                self.worker_client(failing).call({}, request_id="e" * 32)
            self.assertEqual((caught.exception.code, caught.exception.detail), ("WORKER_INTERNAL_ERROR", ""))


class DirectServeTests(SimpleTestCase):
    """``serve`` driven from the test thread itself; the caller is the background thread."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        self.config = ipc.ServerConfig(kind="model", socket_path=str(root / "run" / "worker.sock"), allowed_uid=os.getuid(), key=KEY,
                                       replay_path=str(root / "state" / "replay.sqlite3"), audit_path=str(root / "audit.jsonl"))

    def test_serve_answers_until_stopped_and_removes_its_socket(self):
        done, answers = threading.Event(), []

        def caller():
            try:
                answers.append(ipc.UnixWorkerClient(kind="model", socket_path=self.config.socket_path, key=KEY, principal="broker",
                                                    timeout_seconds=5).call({"purpose": "x"}, request_id="f" * 32))
            finally:
                done.set()
        thread = threading.Thread(target=caller, daemon=True)
        thread.start()
        ipc.UnixWorkerServer(self.config, lambda req: {"served": True}).serve(stop=done.is_set)
        thread.join(2)
        self.assertEqual(answers, [{"served": True}])
        self.assertFalse(Path(self.config.socket_path).exists())

    def test_serve_refuses_to_replace_a_non_socket_path(self):
        path = Path(self.config.socket_path)
        path.parent.mkdir(parents=True)
        path.write_text("not a socket")
        with self.assertRaises(ipc.IpcRefused) as caught:
            ipc.UnixWorkerServer(self.config, lambda req: {}).serve(stop=lambda: True)
        self.assertEqual(caught.exception.code, "UNSAFE_SOCKET_PATH")
        self.assertEqual(path.read_text(), "not a socket")
