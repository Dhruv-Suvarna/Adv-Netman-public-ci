"""Direct tests for the isolated diagnostic worker's request parsing, typed client/transport adapters, pinned executor
and environment-built server (troubleshooting/diagnostic_worker.py).

A request carries no address or command; a result whose digest does not match its output is refused; the collector
adapter cannot substitute a command; and the executor re-reads the active path immediately before connecting.  The SSH
transport, credential broker and path resolver are fakes: nothing connects.
"""

from __future__ import annotations

import os
import tempfile
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest import mock

from django.test import SimpleTestCase

from core.services.management import probes
from core.services.troubleshooting import collectors
from core.services.troubleshooting import diagnostic_worker as dw
from core.services.troubleshooting.worker_ipc import IpcRefused
from core.tests import test_troubleshooting_workers as W

EXPIRES = datetime.now(timezone.utc) + timedelta(minutes=5)
VERSION = collectors.render_command(collectors.COMMAND_CATALOG["ceos"]["version"], {})


def request(**changes):
    return W.DiagnosticWorkerTests.request(None, **changes)


def client():
    return dw.DiagnosticWorkerClient(socket_path="/run/nmas-unit/worker.sock", key=W.KEY, agent="agent-a", tenant="tenant-a",
                                     topology_id="lab-one", authorization_ref="handoff:handoff-123", authorization_expires_at=EXPIRES)


def result_for(payload, output="version output", digest=None):
    return {"schema": dw.DIAGNOSTIC_RESULT_SCHEMA, "device": payload["device"], "operation_id": payload["operation_id"], "output": output,
            "output_sha256": digest if digest is not None else dw.hashlib.sha256(output.encode()).hexdigest()}


class RequestAndCommandTests(SimpleTestCase):
    def test_parse_returns_a_typed_request(self):
        parsed = dw.DiagnosticRequest.parse(request())
        self.assertEqual((parsed.device, parsed.operation_id, parsed.authorization_expires_at.tzinfo), ("R6", "cli:version", timezone.utc))

    def test_parse_refuses_an_address_a_foreign_principal_or_a_naive_expiry(self):
        extra = request()
        extra["payload"]["endpoint"] = "10.0.0.9"
        foreign = request()
        foreign["principal"] = "agent-b"
        for label, envelope in (("an extra endpoint field", extra), ("another principal", foreign),
                                ("a naive expiry", request(authorization_expires_at="2026-11-27T06:00:00")),
                                ("a non-handoff authorization", request(authorization_ref="web:session-1"))):
            with self.subTest(f"{label} is refused"), self.assertRaises(IpcRefused):
                dw.DiagnosticRequest.parse(envelope)

    def test_broker_command_returns_the_exact_quoted_argv(self):
        self.assertEqual(dw.broker_command(("vtysh", "-c", "show ip ospf neighbor json")), "vtysh -c 'show ip ospf neighbor json'")

    def test_broker_command_refuses_an_empty_or_multiline_argv(self):
        for label, argv in (("an empty argv", ()), ("an embedded newline", ("vtysh", "-c", "show\nreload")), ("a non-string token", ("ip", 4))):
            with self.subTest(f"{label} is refused"), self.assertRaises(IpcRefused):
                dw.broker_command(argv)


class ClientAndTransportTests(SimpleTestCase):
    def test_client_execute_returns_a_digest_verified_output(self):
        worker = client()
        worker.ipc = SimpleNamespace(call=lambda payload, request_id: result_for(payload))
        self.assertEqual(worker.execute(device="R6", operation_id="cli:version"), "version output")

    def test_client_execute_refuses_a_tampered_or_mismatched_result(self):
        worker = client()
        for label, fake, code in (("a tampered output", lambda p, request_id: result_for(p, digest="0" * 64), "DIAGNOSTIC_RESULT_TAMPERED"),
                                  ("another device", lambda p, request_id: {**result_for(p), "device": "R7"}, "INVALID_DIAGNOSTIC_RESULT")):
            worker.ipc = SimpleNamespace(call=fake)
            with self.subTest(f"{label} is refused"), self.assertRaises(IpcRefused) as caught:
                worker.execute(device="R6", operation_id="cli:version")
            self.assertEqual(caught.exception.code, code)

    def test_client_never_waits_beyond_the_ipc_timeout_bound(self):
        worker = dw.DiagnosticWorkerClient(socket_path="/run/x.sock", key=W.KEY, agent="agent-a", tenant="t", topology_id="lab-one",
                                           authorization_ref="handoff:h", authorization_expires_at=EXPIRES, timeout_seconds=3600)
        self.assertEqual((worker.ipc.timeout_seconds, worker.ipc.principal, worker.ipc.kind), (60.0, "agent-a", "diagnostic"))

    def test_transport_execute_operation_returns_the_typed_operation_output(self):
        calls = []
        worker = SimpleNamespace(execute=lambda **kw: calls.append(kw) or "ok")
        transport = dw.DiagnosticCliTransport(device="R6", platform="arista_ceos", client=worker)
        self.assertEqual(transport.execute_operation("version", {}, VERSION), "ok")
        self.assertEqual(calls, [{"device": "R6", "operation_id": "cli:version", "params": {}}])
        self.assertEqual(transport.provenance()["arbitrary_command_api"], False)


class ExecutorTests(SimpleTestCase):
    def path(self, version=4):
        return SimpleNamespace(pk=7, version=version, path_id="MPATH-000007", endpoint_address="192.0.2.6", port=22, expected_host_key="SHA256:test",
                               device=SimpleNamespace(name="R6", platform="arista_ceos"),
                               nmas_attachment=SimpleNamespace(source_address="192.168.200.100", host_interface="nmas-mgmt"))

    def run_with(self, current, output="version output"):
        class Transport:
            def run(self, **kw):
                kw["report"].presented_host_key = kw["expected_host_key"]
                return {kw["commands"][0]: output}

        revalidations = []
        with mock.patch.object(dw, "_active_path", return_value=current), \
                mock.patch.object(dw, "_diagnostic_auth_material", return_value=("nmas-diag", [{"password": "fixture-only"}])), \
                mock.patch.object(probes, "ParamikoTransport", Transport), \
                mock.patch("core.services.management.policy.effective", return_value=SimpleNamespace(probe_timeout_seconds=5)), \
                mock.patch.dict(os.environ, {"NMAS_TS_DIAGNOSTIC_BIND_SOURCE": "", "NMAS_TS_DIAGNOSTIC_BIND_INTERFACE": ""}):
            out = dw.NmasSshExecutor().execute(path=self.path(), command=VERSION, revalidate=lambda: revalidations.append(1))
        return out, revalidations

    def test_executor_returns_pinned_output_with_hashed_endpoint_evidence(self):
        (output, evidence), revalidations = self.run_with(self.path())
        self.assertEqual((output, evidence["host_key_verified"], evidence["path_version"], len(revalidations)), ("version output", True, 4, 2))
        self.assertNotIn("192.0.2.6", str(evidence))

    def test_executor_refuses_a_replaced_path_or_oversized_output(self):
        with self.subTest("a replaced path is refused"), self.assertRaises(IpcRefused) as caught:
            self.run_with(self.path(version=5))
        self.assertEqual(caught.exception.code, "MANAGEMENT_PATH_CHANGED")
        with self.subTest("oversized output is refused"), self.assertRaises(IpcRefused):
            self.run_with(self.path(), output="x" * (dw.MAX_OUTPUT_BYTES + 1))


class ServerFromEnvironmentTests(SimpleTestCase):
    def test_server_from_environment_returns_a_configured_diagnostic_server(self):
        with tempfile.TemporaryDirectory() as tmp:
            env = {"NMAS_TS_DIAGNOSTIC_IPC_KEY": W.KEY.decode(), "NMAS_TS_DIAGNOSTIC_CLIENT_UID": str(os.getuid()),
                   "NMAS_TS_DIAGNOSTIC_SOCKET": f"{tmp}/worker.sock", "NMAS_TS_DIAGNOSTIC_REPLAY_DB": f"{tmp}/replay.sqlite3",
                   "NMAS_TS_DIAGNOSTIC_AUDIT_LOG": f"{tmp}/audit.jsonl", "NMAS_TS_DIAGNOSTIC_SOCKET_GROUP": ""}
            with mock.patch.dict(os.environ, env):
                server = dw.server_from_environment()
        self.assertEqual((server.config.kind, server.config.allowed_uid), ("diagnostic", os.getuid()))
        self.assertIsInstance(server.handler, dw.DiagnosticHandler)
