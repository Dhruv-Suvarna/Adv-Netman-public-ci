"""Direct tests for the read-only CLI transports (troubleshooting/adapters/transports.py).

Each transport refuses anything outside its own kind or allowlist before touching its session, maps session failures to
sanitized collector errors, and reports only gateway evidence sequence numbers as provenance.  Sessions, Netmiko
connections and the gateway client are fakes; nothing connects.
"""

from __future__ import annotations

import sys
from types import ModuleType, SimpleNamespace
from unittest import mock

from django.test import SimpleTestCase

from core.services.health import live
from core.services.troubleshooting import collectors as col
from core.services.troubleshooting.adapters import transports as tr

SHOW = live.CEOS_COMMANDS["interfaces"]


class FakeSession:
    def __init__(self, error=None):
        self.ran, self.closed, self.error = [], False, error

    def run(self, key):
        if self.error:
            raise live.LiveError(self.error)
        self.ran.append(key)
        return f"out:{key}"

    def close(self):
        self.closed = True


def health(platform="ceos", session=None):
    session = session or FakeSession()
    return tr.HealthLiveTransport({"name": "R1", "platform": platform}, session_factory=lambda device: session), session


class HealthLiveTransportTests(SimpleTestCase):
    def test_health_live_transport_runs_an_allowlisted_command_and_closes(self):
        transport, session = health()
        self.assertEqual(transport.execute(SHOW), "out:interfaces")
        argv_transport, argv_session = health("linux")
        self.assertEqual(argv_transport.execute(list(live.LINUX_COMMANDS["addr"])), "out:addr")
        transport.close()
        self.assertEqual((session.closed, argv_session.ran), (True, ["addr"]))

    def test_health_live_transport_refuses_commands_outside_the_allowlist(self):
        transport, session = health()
        with self.assertRaises(col.CommandNotAllowed):
            transport.execute("show spanning-tree")
        self.assertEqual(session.ran, [])

    def test_health_live_transport_maps_session_failures(self):
        for code, expected in (("AUTH_FAILED", col.PermissionDenied), ("TIMEOUT", TimeoutError), ("CONNECTION_FAILED", col.TransportError)):
            transport, _ = health(session=FakeSession(code))
            with self.subTest(f"{code} raises"), self.assertRaises(expected):
                transport.execute(SHOW)


class NetmikoLikeTransportTests(SimpleTestCase):
    def test_netmiko_like_transport_returns_output_and_evidence_provenance(self):
        conn = mock.Mock(send_command=mock.Mock(return_value="ok"), last_evidence=[4, 5])
        transport = tr.NetmikoLikeTransport(conn)
        self.assertEqual((transport.execute("show version"), transport.provenance()), ("ok", {"gateway_evidence_seqs": [4, 5]}))
        self.assertIsNone(tr.NetmikoLikeTransport(SimpleNamespace(send_command=lambda c: c)).provenance())

    def test_netmiko_like_transport_refuses_argv_and_sanitizes_failures(self):
        class AuthenticationException(Exception):
            pass

        conn = mock.Mock(send_command=mock.Mock(side_effect=AuthenticationException("password=secret")))
        transport = tr.NetmikoLikeTransport(conn)
        with self.subTest("argv is refused"), self.assertRaises(col.CommandNotAllowed):
            transport.execute(["ip", "addr"])
        with self.subTest("an authentication failure raises PermissionDenied"), self.assertRaises(col.PermissionDenied) as caught:
            transport.execute("show version")
        self.assertNotIn("secret", str(caught.exception))


class ArgvRunnerTransportTests(SimpleTestCase):
    def test_argv_runner_transport_refuses_a_string_or_a_failed_empty_run(self):
        transport = tr.ArgvRunnerTransport(lambda argv: SimpleNamespace(stdout="", returncode=1))
        with self.subTest("a string command is refused"), self.assertRaises(col.CommandNotAllowed):
            transport.execute("ip addr")
        with self.subTest("a failed run with no output is refused"), self.assertRaises(col.TransportError):
            transport.execute(["ip", "addr"])


class FakeGatewayError(Exception):
    pass


class FakeAdapter:
    def __init__(self, gateway, fixture_id, node, *, pin_id=None, label=None):
        self.args, self.last_evidence = (gateway, fixture_id, node, pin_id, label), []

    def send_command(self, command):
        if command == "show forbidden":
            raise FakeGatewayError("command not allowed by allowlist")
        self.last_evidence.append(len(self.last_evidence) + 10)
        return f"eos:{command}"


class FakePeerRunner:
    def __init__(self, gateway, fixture_id, node):
        self.args = (gateway, fixture_id, node)

    def __call__(self, argv):
        return SimpleNamespace(stdout="frr:" + " ".join(argv), evidence_seq=77)


class GatewayTransportTests(SimpleTestCase):
    def setUp(self):
        client = ModuleType("aiorch_gw")
        client.GatewayError, client.NetmikoAdapter, client.PeerRunner = FakeGatewayError, FakeAdapter, FakePeerRunner
        patcher = mock.patch.dict(sys.modules, {"aiorch_gw": client})
        patcher.start()
        self.addCleanup(patcher.stop)
        path = mock.patch.object(sys, "path", list(sys.path))
        path.start()
        self.addCleanup(path.stop)

    def test_gateway_transport_builds_the_platform_client(self):
        eos = tr.GatewayTransport("gw", "fx-1", "r1", "ceos", pin_id="pin-1")
        frr = tr.GatewayTransport("gw", "fx-1", "r3", "linux")
        self.assertIsInstance(eos._conn, FakeAdapter)           # pylint: disable=protected-access  # the selected client under test
        self.assertIsInstance(frr._peer, FakePeerRunner)        # pylint: disable=protected-access  # the selected client under test

    def test_gateway_transport_execute_returns_output_with_live_provenance(self):
        eos = tr.GatewayTransport("gw", "fx-1", "r1", "ceos", pin_id="pin-1")
        frr = tr.GatewayTransport("gw", "fx-1", "r3", "linux")
        self.assertEqual((eos.execute("show version"), frr.execute(["vtysh", "-c", "show bgp"])), ("eos:show version", "frr:vtysh -c show bgp"))
        self.assertEqual(eos.provenance(), {"live": True, "fixture_id": "fx-1", "node": "r1", "pin_id": "pin-1", "gateway_evidence_seqs": [10]})
        self.assertEqual(frr.provenance()["gateway_evidence_seqs"], [77])

    def test_gateway_transport_refuses_the_wrong_kind_or_a_gateway_refusal(self):
        eos = tr.GatewayTransport("gw", "fx-1", "r1", "ceos")
        frr = tr.GatewayTransport("gw", "fx-1", "r3", "linux")
        for label, transport, command, expected in (("argv to EOS", eos, ["ip"], col.CommandNotAllowed),
                                                    ("a string to FRR", frr, "show bgp", col.CommandNotAllowed),
                                                    ("a gateway allowlist refusal", eos, "show forbidden", col.PermissionDenied)):
            with self.subTest(f"{label} is refused"), self.assertRaises(expected):
                transport.execute(command)
        self.assertEqual(eos.provenance()["gateway_evidence_seqs"], [])
