"""No-network adversarial tests for isolated worker IPC and typed adapters."""

from __future__ import annotations

import json
import os
import socket
import tempfile
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from django.test import SimpleTestCase

from core.services.troubleshooting.diagnostic_worker import (
    DIAGNOSTIC_SCHEMA, DiagnosticCliTransport, DiagnosticHandler, _diagnostic_auth_material,
)
from core.services.troubleshooting.research import ResearchBroker, ResearchRefused
from core.services.troubleshooting.research_worker import RESEARCH_SCHEMA, ResearchHandler, ResearchWorkerClient
from core.services.troubleshooting.worker_ipc import (
    IpcRefused, ReplayLedger, ServerConfig, UnixWorkerClient, UnixWorkerServer,
    make_request, sign, validate_request,
)
from core.management.commands.troubleshooting_ai import _TroubleshootingSqlBoundary
from core.management.commands.troubleshooting_device_worker import _ReadOnlySql


KEY = b"test-only-worker-key-material-32-bytes-minimum"


class _ServerFixture:
    def __init__(self, kind, handler, *, allowed_uid=None):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.stop = False
        self.server = UnixWorkerServer(ServerConfig(
            kind=kind, socket_path=str(root / "worker.sock"), allowed_uid=os.getuid() if allowed_uid is None else allowed_uid,
            key=KEY, replay_path=str(root / "replay.sqlite3"), audit_path=str(root / "audit.jsonl"),
        ), handler)
        self.thread = threading.Thread(target=self.server.serve, kwargs={"stop": lambda: self.stop}, daemon=True)
        self.thread.start()
        for _ in range(100):
            if (root / "worker.sock").exists():
                break
            time.sleep(0.01)
        self.root = root

    def close(self):
        self.stop = True
        # Wake accept so shutdown is prompt.
        try:
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.connect(str(self.root / "worker.sock"))
            sock.close()
        except OSError:
            pass
        self.thread.join(2)
        self.tmp.cleanup()


class WorkerIpcTests(SimpleTestCase):
    def test_database_boundaries_refuse_policy_identity_and_path_writes(self):
        called = []
        execute = lambda sql, params, many, context: called.append(sql) or "ok"
        boundary = _TroubleshootingSqlBoundary()
        self.assertEqual(boundary(execute, 'SELECT * FROM "core_manageddevice"', (), False, {}), "ok")
        self.assertEqual(boundary(execute, 'UPDATE "core_tscase" SET "state"=%s', (), False, {}), "ok")
        for sql in ('UPDATE "core_managementpath" SET "is_active"=1',
                    'UPDATE "core_manageddevice" SET "identity_state"=\'VERIFIED\'',
                    'PRAGMA writable_schema=ON', 'ATTACH DATABASE \'x\' AS other'):
            with self.assertRaises(RuntimeError):
                boundary(execute, sql, (), False, {})
        read_only = _ReadOnlySql()
        self.assertEqual(read_only(execute, "SELECT 1", (), False, {}), "ok")
        with self.assertRaises(RuntimeError):
            read_only(execute, 'DELETE FROM "core_tscase"', (), False, {})

    def test_authenticated_round_trip_socket_mode_and_sanitized_audit(self):
        fixture = _ServerFixture("research", lambda req: {"echo": req["payload"]["value"]})
        try:
            client = UnixWorkerClient(kind="research", socket_path=str(fixture.root / "worker.sock"), key=KEY,
                                      principal="agent-a", timeout_seconds=2)
            self.assertEqual(client.call({"value": "safe"}, request_id="a" * 32), {"echo": "safe"})
            self.assertEqual(os.stat(fixture.root / "worker.sock").st_mode & 0o777, 0o660)
            audit = (fixture.root / "audit.jsonl").read_text()
            self.assertIn('"decision":"allowed"', audit)
            self.assertNotIn("safe", audit)
            self.assertNotIn("signature", audit)
        finally:
            fixture.close()

    def test_peer_uid_is_required_even_with_a_valid_hmac(self):
        fixture = _ServerFixture("research", lambda _req: {"bad": True}, allowed_uid=os.getuid() + 1)
        try:
            client = UnixWorkerClient(kind="research", socket_path=str(fixture.root / "worker.sock"), key=KEY,
                                      principal="agent-a", timeout_seconds=2)
            with self.assertRaises(IpcRefused) as caught:
                client.call({"value": "safe"}, request_id="b" * 32)
            self.assertEqual(caught.exception.code, "PEER_UID_REFUSED")
        finally:
            fixture.close()

    def test_tampering_expiry_and_operation_substitution_fail_authentication(self):
        request = make_request(kind="diagnostic", principal="agent-a", payload={"operation_id": "cli:version"},
                               key=KEY, request_id="c" * 32, now=100, ttl_seconds=10)
        request["payload"]["operation_id"] = "cli:running_config"
        with self.assertRaises(IpcRefused) as caught:
            validate_request(request, kind="diagnostic", key=KEY, now=101)
        self.assertEqual(caught.exception.code, "AUTHENTICATION_FAILED")
        request["signature"] = sign(request, KEY)
        with self.assertRaises(IpcRefused) as caught:
            validate_request(request, kind="diagnostic", key=KEY, now=111)
        self.assertEqual(caught.exception.code, "REQUEST_EXPIRED")

    def test_replay_ledger_survives_a_new_instance(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = str(Path(tmp) / "replay.sqlite3")
            ReplayLedger(path).claim(kind="diagnostic", request_id="d" * 32, digest="1" * 64, expires_at=999, now=100)
            with self.assertRaises(IpcRefused) as caught:
                ReplayLedger(path).claim(kind="diagnostic", request_id="d" * 32, digest="2" * 64, expires_at=999, now=101)
            self.assertEqual(caught.exception.code, "REPLAY_REFUSED")

    def test_worker_loss_never_falls_back(self):
        client = UnixWorkerClient(kind="diagnostic", socket_path="/no/such/nmas-worker.sock", key=KEY,
                                  principal="agent-a", timeout_seconds=0.1)
        with self.assertRaises(IpcRefused) as caught:
            client.call({"operation_id": "cli:version"}, request_id="e" * 32)
        self.assertEqual(caught.exception.code, "WORKER_UNAVAILABLE")


class DiagnosticWorkerTests(SimpleTestCase):
    def request(self, **changes):
        payload = {"schema": DIAGNOSTIC_SCHEMA, "topology_id": "lab-one", "tenant": "tenant-a", "agent": "agent-a",
                   "authorization_ref": "handoff:handoff-123", "authorization_expires_at": (datetime.now(timezone.utc) + timedelta(seconds=30)).isoformat(),
                   "device": "R6", "operation_id": "cli:version", "params": {}}
        payload.update(changes)
        return {"principal": "agent-a", "payload": payload}

    def path(self):
        return SimpleNamespace(pk=7, version=4, endpoint_address="192.0.2.6", port=22, expected_host_key="SHA256:test",
                               device=SimpleNamespace(name="R6", platform="arista_ceos"))

    def test_handler_authorizes_derived_endpoint_and_revalidates_around_execution(self):
        events = []

        class Policy:
            topology_id = "lab-one"
            def authorize(self, request):
                events.append(("authorize", request.endpoint, request.operation_id, request.device))
                return SimpleNamespace()
            def revalidate(self, _grant, **kwargs):
                events.append(("revalidate", kwargs["endpoint"], kwargs["operation_id"]))

        class Executor:
            def execute(self, *, path, command, revalidate):
                revalidate()
                events.append(("execute", path.endpoint_address, command))
                return "version output", {"path_id": "MPATH-000007", "bytes": 14}

        path = self.path()
        with patch("core.services.troubleshooting.diagnostic_worker._active_path", return_value=path):
            result = DiagnosticHandler(policy_factory=Policy, executor=Executor())(self.request())
        self.assertEqual(result["device"], "R6")
        self.assertEqual(events[0], ("authorize", "192.0.2.6", "cli:version", "R6"))
        self.assertEqual([event[0] for event in events].count("revalidate"), 2)

    def test_arbitrary_destination_shell_config_and_operation_substitution_have_no_interface(self):
        path = self.path()
        handler = DiagnosticHandler(policy_factory=lambda: None, executor=None)
        for changes in (
            {"endpoint": "10.0.0.9"},
            {"command": "bash -c id"},
            {"operation_id": "cli:running_config"},
            {"operation_id": "docker:exec"},
        ):
            request = self.request()
            request["payload"].update(changes)
            with patch("core.services.troubleshooting.diagnostic_worker._active_path", return_value=path), self.assertRaises(IpcRefused):
                handler(request)

    def test_collector_adapter_refuses_untyped_and_rendered_substitution(self):
        client = SimpleNamespace(execute=lambda **_kwargs: "ok")
        transport = DiagnosticCliTransport(device="R6", platform="arista_ceos", client=client)
        with self.assertRaises(IpcRefused):
            transport.execute("show version")
        with self.assertRaises(IpcRefused):
            transport.execute_operation("version", {}, "show running-config")
        with self.assertRaises(IpcRefused):
            transport.execute_operation("running_config", {}, "show running-config")

    def test_dedicated_diagnostic_identity_is_exact_and_fail_closed(self):
        path = self.path()
        credential = SimpleNamespace(
            username="nmas-diag", account_kind="SERVICE", auth_method="PASSWORD",
            account_role="network-operator", privilege_level=1,
            secret_ref="runtime://device-credentials/r6-nmas-diag", ssh_key_ref="",
        )
        provider = SimpleNamespace(candidates=lambda _ref: (SimpleNamespace(value="fixture-only"),))
        username, methods = _diagnostic_auth_material(path, credential_lookup=lambda _device: credential, provider=provider)
        self.assertEqual(username, "nmas-diag")
        self.assertEqual(methods, [{"password": "fixture-only"}])

        for field, value in (("account_role", "network-admin"), ("privilege_level", 15),
                             ("secret_ref", "runtime://device-credentials/r2-nmas-diag")):
            invalid = SimpleNamespace(**vars(credential))
            setattr(invalid, field, value)
            with self.assertRaises(Exception) as caught:
                _diagnostic_auth_material(path, credential_lookup=lambda _device, row=invalid: row, provider=provider)
            self.assertEqual(type(caught.exception).__name__, "CredentialUnavailable")


class ResearchWorkerTests(SimpleTestCase):
    class Transport:
        def request(self, **_kwargs):
            return 200, {"content-type": "text/plain"}, b"documentation"

    def test_research_worker_round_trip_is_distinct_and_untrusted(self):
        broker = ResearchBroker(allowed_destinations={"docs.example": ("93.184.216.34",)},
                                resolver=lambda _host: ("93.184.216.34",), transport=self.Transport())
        fixture = _ServerFixture("research", ResearchHandler(broker))
        try:
            client = ResearchWorkerClient(socket_path=str(fixture.root / "worker.sock"), key=KEY, principal="agent-a", timeout_seconds=2)
            result = client.fetch("https://docs.example/guide", purpose="diagnose protocol behavior", principal="agent-a")
            self.assertEqual(result.body, "documentation")
            self.assertTrue(result.untrusted_external_content)
        finally:
            fixture.close()

    def test_research_ipc_has_no_device_command_or_credential_fields(self):
        broker = ResearchBroker(allowed_destinations={"docs.example": ("93.184.216.34",)},
                                resolver=lambda _host: ("93.184.216.34",), transport=self.Transport())
        handler = ResearchHandler(broker)
        for extra in ({"device": "R6"}, {"command": "show version"}, {"credential": "secret"}):
            payload = {"schema": RESEARCH_SCHEMA, "url": "https://docs.example/", "purpose": "diagnose protocol behavior", "method": "GET", **extra}
            with self.assertRaises(IpcRefused):
                handler({"principal": "agent-a", "payload": payload})

    def test_research_principal_cannot_be_substituted(self):
        client = ResearchWorkerClient(socket_path="/unused", key=KEY, principal="agent-a")
        with self.assertRaises(ResearchRefused) as caught:
            client.fetch("https://docs.example/", purpose="diagnose protocol behavior", principal="agent-b")
        self.assertEqual(caught.exception.code, "PRINCIPAL_MISMATCH")
