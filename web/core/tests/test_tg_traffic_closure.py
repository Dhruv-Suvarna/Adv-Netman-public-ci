"""Lab 7 closure -- the traffic workbench and its runner, each function called directly.

Nothing is spawned and no socket is opened: ``runtime._docker`` (THE one process boundary) is replaced by a recorder, the website
client's ``socket`` module is replaced by an in-memory fake, the server is handed fake connections / listeners whose ``SO_PEERCRED``
answer is scripted, and full runs go through the scripted container runtime (``helpers.traffic.World``).  The git head read is faked.

POSITIVE: the exact argv, reply, bound, job, container name, configuration and run row.  NEGATIVE: invalid images / tools / names /
instances, malformed or oversized requests, unauthorised peers, unknown endpoints, out-of-bounds integers, an unreachable runner and
a second concurrent run are refused with a stable code -- and nothing is executed.
"""

from __future__ import annotations

import io
import json
import os
import socket
import struct
import tempfile
import threading
import uuid
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from django.test import SimpleTestCase, TestCase, override_settings

from core import models
from core.services import traffic_service
from core.services.traffic import client, endpoints, limits, service
from core.services.traffic.runner import PROTOCOL_VERSION, RUNNER_VERSION, config, engine, policy, runtime, server
from core.services.traffic.runner import __main__ as entry
from core.tests.helpers import traffic as t

RID = "3f2b8c1e-5a4d-4e6f-8a9b-0c1d2e3f4a5b"
NAME = f"nmas-traffic-{RID.replace('-', '')}-tool"
NETNS = "1" * 64
S = models.TrafficRunStatus
_AF_UNIX, _SOCK_STREAM, _SOCKET_TIMEOUT = socket.AF_UNIX, socket.SOCK_STREAM, socket.timeout


def doc(**overrides) -> dict:
    document = {"v": PROTOCOL_VERSION, "run_id": RID, "source_endpoint_id": "H1", "destination_endpoint_id": "H2", "address_family": "IPV4",
                "test_type": "ICMP", "protocol": "ICMP", "parameters": {"count": 3, "size": 56}}
    document.update(overrides)
    return document


class Docker:
    """Records every ``_docker`` call and answers from a script: ``replies`` is consumed in order (default rc 0, empty output)."""

    def __init__(self, *replies):
        self.calls, self.replies = [], list(replies)

    def __call__(self, args, *, timeout):
        self.calls.append((list(args), timeout))
        return self.replies.pop(0) if self.replies else runtime.Completed(0, "", "")


class FakeConnection:
    def __init__(self, data=b"", *, uid=t.PEER_UID, recv_error=None, peer_error=None):
        self.chunks, self.uid, self.recv_error, self.peer_error = [data] if data else [], uid, recv_error, peer_error
        self.sent, self.closed, self.shut, self.timeouts = b"", False, False, []

    def getsockopt(self, level, option, size):
        if self.peer_error:
            raise self.peer_error
        return struct.pack("3i", 99, self.uid, 99)

    def settimeout(self, value):
        self.timeouts.append(value)

    def recv(self, size):
        if self.recv_error:
            raise self.recv_error
        return self.chunks.pop(0)[:size] if self.chunks else b""

    def sendall(self, data):
        self.sent += data

    def shutdown(self, how):
        self.shut = True

    def close(self):
        self.closed = True

    def reply(self):
        return json.loads(self.sent)


class FakeSocketModule:
    """Stands in for the ``socket`` module inside ``traffic.client``: one in-memory connection."""

    AF_UNIX, SOCK_STREAM, timeout = _AF_UNIX, _SOCK_STREAM, _SOCKET_TIMEOUT

    def __init__(self, reply=b"", *, connect_error=None, recv_error=None):
        self.reply, self.connect_error, self.recv_error = [reply] if reply else [], connect_error, recv_error
        self.sent, self.path, self.budget = b"", None, None

    def socket(self, family, kind):
        return self

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def settimeout(self, value):
        self.budget = value

    def connect(self, path):
        if self.connect_error:
            raise self.connect_error
        self.path = path

    def sendall(self, data):
        self.sent += data

    def recv(self, size):
        if self.recv_error:
            raise self.recv_error
        return self.reply.pop(0) if self.reply else b""


def fake_engine(reply=None):
    calls = []

    def handle(document, *, peer_uid):
        calls.append((document, peer_uid))
        return reply or {"v": PROTOCOL_VERSION, "ok": True, "run_id": document.get("run_id", "")}

    return SimpleNamespace(handle=handle, calls=calls)


# --- the website side ------------------------------------------------------------------------------------------------------------
class LimitsTests(SimpleTestCase):
    def test_bounds_exception_builds_the_field_and_range_message(self):
        error = limits.BoundsError("count", 1, 5)
        self.assertEqual((str(error), error.field, error.low, error.high), ("count must be between 1 and 5.", "count", 1, 5))

    def test_bounds_error_is_a_value_error_raised_for_a_negative_range_breach(self):
        with self.assertRaises(ValueError):
            raise limits.BoundsError("port", 1, 65535)

    def test_bounded_int_accepts_plain_integers_and_the_default(self):
        self.assertEqual((limits.bounded_int(" 3 ", "count", (1, 5)), limits.bounded_int("", "count", (1, 5), default=2)), (3, 2))

    def test_bounded_int_refuses_flags_units_out_of_range_and_missing_values(self):
        for raw in ("-1", "3s", "--flood", "6", "0", "1234567890", None, "2.5"):
            with self.subTest("refused", raw=raw), self.assertRaises(limits.BoundsError):
                limits.bounded_int(raw, "count", (1, 5))

    def test_run_timeout_seconds_returns_each_family_budget(self):
        F = models.TrafficTestFamily
        self.assertEqual([limits.run_timeout_seconds(F.ICMP, {"count": 3}), limits.run_timeout_seconds(F.TRACEROUTE, {"max_hops": 10}),
                          limits.run_timeout_seconds(F.UDP_PROBE, {"timeout": 2, "count": 3}), limits.run_timeout_seconds(F.TCP_CONNECT, {"timeout": 2}),
                          limits.run_timeout_seconds(F.IPERF3, {"duration": 4})], [11, 25, 11, 7, 19])


class ClientTests(TestCase):
    def setUp(self):
        self.run = models.TrafficRun(run_id=uuid.UUID(RID), operator="t", source="H1", destination="H2", address_family="IPV4",
                                     family="ICMP", protocol="ICMP", parameters={"count": 3, "size": 56})

    def submit(self, fake):
        with mock.patch.object(client, "socket", fake), override_settings(NMAS_TRAFFIC_RUNNER_SOCKET="/run/nmas/traffic.sock"):
            return client.submit(self.run)

    def test_submit_sends_the_closed_request_and_returns_the_checked_reply(self):
        reply = {"v": 1, "ok": True, "run_id": RID, "exit_code": 0}
        fake = FakeSocketModule(json.dumps(reply).encode() + b"\n")
        self.assertEqual(self.submit(fake), reply)
        self.assertEqual((fake.path, fake.budget), ("/run/nmas/traffic.sock", 11 + client.RUNNER_OVERHEAD_SECONDS))
        self.assertEqual(json.loads(fake.sent), client.document(self.run))

    def test_submit_refuses_an_unreachable_silent_or_malformed_runner(self):
        cases = (("unavailable", FakeSocketModule(connect_error=FileNotFoundError()), "RUNNER_UNAVAILABLE"),
                 ("timeout", FakeSocketModule(recv_error=socket.timeout()), "RUNNER_TIMEOUT"),
                 ("empty reply", FakeSocketModule(b""), "RUNNER_PROTOCOL_ERROR"),
                 ("not json", FakeSocketModule(b"{oops"), "RUNNER_PROTOCOL_ERROR"),
                 ("another run's reply", FakeSocketModule(json.dumps({"v": 1, "ok": True, "run_id": str(uuid.uuid4())}).encode()), "RUNNER_PROTOCOL_ERROR"))
        for label, fake, code in cases:
            with self.subTest(label), self.assertRaises(client.ClientError) as caught:
                self.submit(fake)
            self.assertEqual(caught.exception.code, code)


class ServiceTests(TestCase):
    def setUp(self):
        patcher = mock.patch.object(service, "repository_head", return_value="c" * 40)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_validate_returns_a_request_and_validation_reports_ok(self):
        checked = service.validate(t.request())
        self.assertTrue(checked.ok)
        self.assertEqual(checked.codes, [])
        self.assertEqual((checked.request.source, checked.request.destination, checked.request.parameters["count"]), ("H1", "H2", 3))

    def test_validate_refuses_unknown_endpoints_and_validation_lists_the_codes(self):
        checked = service.validate(t.request(source="10.0.0.1", destination="clab-srlceos01-H2"))
        self.assertFalse(checked.ok)
        self.assertEqual(checked.codes, ["SOURCE_NOT_AN_ENDPOINT", "DESTINATION_NOT_AN_ENDPOINT"])

    def test_create_run_creates_the_row_and_audits_it(self):
        run, refusal = service.create_run(service.validate(t.request()).request, operator="op")
        self.assertIsNone(refusal)
        self.assertEqual((run.status, run.repository_head, run.engine_version), (S.CREATED, "c" * 40, limits.ENGINE_VERSION))
        self.assertTrue(models.AuditEvent.objects.filter(event_type=models.AuditEventType.TRAFFIC_RUN_STARTED, object_id=str(run.run_id)).exists())

    def test_create_run_refuses_a_second_active_run(self):
        request = service.validate(t.request()).request
        first, _ = service.create_run(request, operator="op")
        second, refusal = service.create_run(request, operator="op")
        self.assertIsNone(second)
        self.assertEqual(refusal["code"], "TEST_ALREADY_RUNNING")
        self.assertEqual(list(models.TrafficRun.objects.values_list("pk", flat=True)), [first.pk])

    def test_execute_runs_the_test_through_the_scripted_runner_and_passes(self):
        run, _ = service.create_run(service.validate(t.request()).request, operator="op")
        with t.wired() as wiring:
            finished = service.execute(run)
        self.assertEqual((finished.status, finished.failure_reason, finished.source_address), (S.PASSED, "", "192.168.10.102"))
        self.assertEqual(wiring.containers, {})

    def test_endpoint_get_of_an_unknown_or_empty_name_is_none(self):
        self.assertIsNone(endpoints.get("clab-srlceos01-H1"))
        self.assertIsNone(endpoints.get(None))

    def test_traffic_facade_get_run_and_list_runs_return_rows(self):
        run, _ = service.create_run(service.validate(t.request()).request, operator="op")
        self.assertEqual((traffic_service.get_run(run.run_id), traffic_service.list_runs()), (run, [run]))
        self.assertEqual(traffic_service.form_limits()["iperf_ports"], limits.IPERF_PORTS)

    def test_traffic_facade_get_run_of_a_malformed_or_unknown_id_and_an_empty_list_are_none(self):
        self.assertIsNone(traffic_service.get_run("not-a-uuid"))
        self.assertIsNone(traffic_service.get_run(uuid.uuid4()))
        self.assertEqual(traffic_service.list_runs(limit=0), [])


class RepositoryHeadTests(SimpleTestCase):
    def test_repository_head_returns_the_truncated_commit(self):
        with mock.patch.object(service.subprocess, "run", return_value=SimpleNamespace(stdout="d" * 40 + "\n")) as run:
            self.assertEqual(service.repository_head(), "d" * 40)
        self.assertEqual(run.call_args.args[0], ["git", "rev-parse", "HEAD"])


# --- the runner ------------------------------------------------------------------------------------------------------------------
class RuntimeTests(SimpleTestCase):
    BASE = dict(name=NAME, instance="nmas", run_id=RID, netns=NETNS, image=t.IMAGE)

    def docker(self, *replies):
        fake = Docker(*replies)
        patcher = mock.patch.object(runtime, "_docker", fake)
        patcher.start()
        self.addCleanup(patcher.stop)
        return fake

    def test_image_available_returns_the_inspect_verdict(self):
        fake = self.docker(runtime.Completed(0, "sha256:x", ""), runtime.Completed(1, "", "No such image"))
        self.assertEqual((runtime.image_available(t.IMAGE), runtime.image_available(t.IMAGE)), (True, False))
        self.assertEqual(fake.calls[0], (["image", "inspect", "--format", "{{.Id}}", t.IMAGE], 10))

    def test_image_available_refuses_a_tag_never_inspecting_it(self):
        fake = self.docker()
        with self.assertRaises(runtime.RuntimeFailure) as caught:
            runtime.image_available("nmas-traffic-tools:latest")
        self.assertEqual((caught.exception.code, fake.calls), ("OPERATION_NOT_ALLOWED", []))

    def test_run_tool_and_start_server_build_the_hardened_argv(self):
        fake = self.docker()
        runtime.run_tool(**self.BASE, tool="ping", args=["-c", 3], timeout=11)
        runtime.start_server(**{**self.BASE, "name": NAME[:-4] + "server"}, tool="iperf3", args=["-s", "-1"])
        (tool_argv, tool_timeout), (server_argv, server_timeout) = fake.calls
        self.assertEqual((tool_argv[:2], tool_timeout, tool_argv[-3:]), (["run", "--rm"], 11, [t.IMAGE, "-c", "3"]))
        self.assertEqual((server_argv[:2], server_timeout, server_argv[-2:]), (["run", "--detach"], 20, ["-s", "-1"]))

    def test_run_tool_and_start_server_refuse_unknown_tools_or_foreign_names(self):
        fake = self.docker()
        with self.assertRaises(runtime.RuntimeFailure):
            runtime.run_tool(**self.BASE, tool="bash", args=[], timeout=5)
        with self.assertRaises(runtime.RuntimeFailure):
            runtime.start_server(**{**self.BASE, "name": "clab-srlceos01-H1"}, tool="iperf3", args=["-s"])
        self.assertEqual(fake.calls, [])

    def test_container_state_and_logs_return_the_runtime_answer(self):
        self.docker(runtime.Completed(0, '{"Running": false, "ExitCode": 3}', ""), runtime.Completed(1, "", "No such container"),
                    runtime.Completed(0, "out\n", "err\n"))
        self.assertEqual(runtime.container_state(NAME), {"running": False, "exit_code": 3})
        self.assertIsNone(runtime.container_state(NAME))
        self.assertEqual(runtime.logs(NAME), "out\nerr\n")

    def test_owned_refuses_a_bad_instance_or_an_unavailable_runtime(self):
        fake = self.docker(runtime.Completed(1, "", "Cannot connect"))
        with self.assertRaises(runtime.RuntimeFailure) as bad:
            runtime.owned("NMAS; rm")
        with self.assertRaises(runtime.RuntimeFailure) as down:
            runtime.owned("nmas")
        self.assertEqual((bad.exception.code, down.exception.code, len(fake.calls)), ("OPERATION_NOT_ALLOWED", "RUNTIME_UNAVAILABLE", 1))


class PolicyTests(SimpleTestCase):
    def setUp(self):
        self.catalogue = t.runner_configuration().endpoints

    def test_validate_returns_the_job(self):
        job = policy.validate(doc(), self.catalogue)
        self.assertEqual((job.run_id, job.source, job.parameters), (uuid.UUID(RID), "H1", {"count": 3, "size": 56}))

    def test_validate_refuses_an_extra_key_never_ignoring_it(self):
        with self.assertRaises(policy.Refusal) as caught:
            policy.validate({**doc(), "image": "busybox"}, self.catalogue)
        self.assertEqual(caught.exception.code, "MALFORMED_REQUEST")

    def test_container_name_returns_the_run_scoped_name(self):
        self.assertEqual(policy.validate(doc(), self.catalogue).container_name("tool"), NAME)

    def test_container_name_of_two_runs_never_collides(self):
        other = policy.validate(doc(run_id=str(uuid.uuid4())), self.catalogue)
        self.assertNotEqual(other.container_name("tool"), NAME)

    def test_policy_exception_keeps_the_code_and_field(self):
        refusal = policy.Refusal("PARAMETER_OUT_OF_BOUNDS", "count")
        self.assertEqual((str(refusal), refusal.code, refusal.field), ("PARAMETER_OUT_OF_BOUNDS", "PARAMETER_OUT_OF_BOUNDS", "count"))

    def test_refusal_without_a_field_has_an_empty_field(self):
        self.assertEqual(policy.Refusal("BUSY").field, "")

    def test_parameter_bounds_returns_the_family_bounds_with_udp_length(self):
        self.assertEqual(policy.parameter_bounds("IPERF3", "UDP")["length"], policy.IPERF_UDP_LENGTH)
        self.assertNotIn("length", policy.parameter_bounds("IPERF3", "TCP"))

    def test_parameter_bounds_of_an_unknown_test_type_raises(self):
        with self.assertRaises(KeyError):
            policy.parameter_bounds("NMAP", "TCP")

    def test_tool_timeout_seconds_without_its_parameter_raises(self):
        with self.assertRaises(KeyError):
            policy.tool_timeout_seconds("ICMP", {})


class EngineTests(SimpleTestCase):
    def setUp(self):
        self.config = t.runner_configuration()
        self.job = policy.validate(doc(), self.config.endpoints)

    def test_engine_outcome_exception_keeps_the_code_and_extra(self):
        failure = engine._Failure("SERVER_NOT_LISTENING", port=5201)
        self.assertEqual((failure.code, failure.extra), ("SERVER_NOT_LISTENING", {"port": 5201}))

    def test_failure_without_extra_has_no_details(self):
        self.assertEqual(engine._Failure("ENDPOINT_LOST").extra, {})

    def test_run_common_returns_the_tool_container_identity(self):
        run = engine._Run(self.job, self.config)
        run.identity["H1"] = NETNS
        self.assertEqual(run.common("tool", "H1"), {"name": NAME, "instance": "nmas", "run_id": RID, "netns": NETNS, "image": t.IMAGE})
        self.assertEqual(run.created, [NAME])

    def test_new_run_has_no_containers_and_common_refuses_an_unresolved_endpoint(self):
        run = engine._Run(self.job, self.config)
        self.assertEqual((run.created, run.identity), ([], {}))
        with self.assertRaises(KeyError):
            run.common("tool", "H2")

    def test_parse_addresses_returns_global_data_addresses_sorted(self):
        text = json.dumps([{"ifname": "eth0", "addr_info": [{"local": "172.20.20.2", "scope": "global"}]},
                           {"ifname": "eth1", "addr_info": [{"local": "192.168.10.9", "scope": "global"}, {"local": "192.168.10.2", "scope": "global"},
                                                           {"local": "2001:db8::1", "scope": "global"}, {"local": "fe80::1", "scope": "link"}]}])
        self.assertEqual(engine.parse_addresses(text), {"IPV4": ["192.168.10.2", "192.168.10.9"], "IPV6": ["2001:db8::1"]})


class ServerTests(SimpleTestCase):
    def test_peer_uid_returns_the_kernel_reported_uid(self):
        self.assertEqual(server.peer_uid(FakeConnection(uid=1001)), 1001)

    def test_peer_uid_raises_when_credentials_are_unavailable(self):
        with self.assertRaises(OSError):
            server.peer_uid(FakeConnection(peer_error=OSError("not a unix socket")))

    def test_read_request_returns_the_first_json_line(self):
        self.assertEqual(server.read_request(FakeConnection(json.dumps(doc()).encode() + b"\ntrailing")), doc())

    def test_read_request_refuses_oversized_non_json_non_object_or_broken_input(self):
        for label, connection in (("oversized", FakeConnection(b"x" * (policy.MAX_REQUEST_BYTES + 1))), ("not json", FakeConnection(b"{nope\n")),
                                  ("not an object", FakeConnection(b"[1, 2]\n")), ("broken", FakeConnection(recv_error=ConnectionResetError()))):
            with self.subTest(label):
                self.assertIsNone(server.read_request(connection))

    def test_handle_connection_answers_an_allowed_peer(self):
        connection, broker, log = FakeConnection(json.dumps(doc()).encode() + b"\n"), fake_engine(), []
        server.handle_connection(connection, broker, {t.PEER_UID}, log.append)
        self.assertEqual(connection.reply(), {"v": PROTOCOL_VERSION, "ok": True, "run_id": RID})
        self.assertEqual((broker.calls, connection.shut, connection.closed, log), ([(doc(), t.PEER_UID)], True, True, []))

    def test_handle_connection_refuses_an_unauthorized_or_unknown_peer_never_reading_it(self):
        for label, connection in (("unauthorized uid", FakeConnection(json.dumps(doc()).encode() + b"\n", uid=0)),
                                  ("credentials unavailable", FakeConnection(peer_error=OSError()))):
            with self.subTest(label):
                broker, log = fake_engine(), []
                server.handle_connection(connection, broker, {t.PEER_UID}, log.append)
                self.assertEqual(connection.reply(), {"v": PROTOCOL_VERSION, "ok": False, "run_id": "", "runner": RUNNER_VERSION,
                                                      "code": "UNAUTHORIZED", "refused": True})
                self.assertEqual((broker.calls, log[0]["outcome"]), ([], "UNAUTHORIZED"))

    def test_serve_handles_an_accepted_connection_then_stops(self):
        stop, connection, broker = threading.Event(), FakeConnection(json.dumps(doc()).encode() + b"\n"), fake_engine()
        accepted = [(connection, None)]

        def accept():
            if accepted:
                return accepted.pop()
            stop.set()
            raise socket.timeout()

        server.serve(SimpleNamespace(settimeout=lambda v: None, accept=accept), broker, {t.PEER_UID}, lambda r: None, stop=stop)
        self.assertEqual((connection.reply()["ok"], connection.closed, len(broker.calls)), (True, True, 1))

    def test_serve_stops_on_a_broken_listener_without_handling_anything(self):
        broker = fake_engine()

        def accept():
            raise OSError("listener closed")

        server.serve(SimpleNamespace(settimeout=lambda v: None, accept=accept), broker, {t.PEER_UID}, lambda r: None, stop=threading.Event())
        self.assertEqual(broker.calls, [])


class RunnerEntryTests(SimpleTestCase):
    def config_file(self, root):
        path = Path(root) / "traffic-runner.json"
        path.write_text(json.dumps(endpoints.runner_config(tools_image=t.IMAGE, allowed_peer_uids=[1001])))
        path.chmod(0o600)
        return str(path)

    def test_load_returns_the_parsed_configuration(self):
        with tempfile.TemporaryDirectory() as root:
            loaded = config.load(self.config_file(root))
        self.assertEqual((loaded.lab, loaded.tools_image, loaded.allowed_peer_uids), ("srlceos01", t.IMAGE, frozenset({1001})))
        self.assertEqual(loaded.endpoints["H1"].container, "clab-srlceos01-H1")

    def test_main_starts_reconciles_serves_and_stops(self):
        broker = SimpleNamespace(reconcile=lambda: ["nmas-traffic-x-tool"])
        out = io.StringIO()
        with tempfile.TemporaryDirectory() as root, \
                mock.patch.object(entry, "_listener", return_value="LISTENER") as listener, \
                mock.patch.object(entry.engine, "Engine", return_value=broker), \
                mock.patch.object(entry.server, "serve") as serve, \
                mock.patch.object(entry.signal, "signal") as handlers, \
                mock.patch("sys.stdout", out):
            self.assertEqual(entry.main(["--config", self.config_file(root), "--socket", os.path.join(root, "runner.sock")]), 0)
        listener.assert_called_once_with(os.path.join(root, "runner.sock"))
        self.assertEqual((serve.call_args.args[:3], len(handlers.call_args_list)), (("LISTENER", broker, frozenset({1001})), 2))
        events = [json.loads(line) for line in out.getvalue().splitlines()]
        self.assertEqual([e["event"] for e in events], ["started", "stopped"])
        self.assertEqual((events[0]["abandoned_removed"], events[0]["runner"]), (1, RUNNER_VERSION))
