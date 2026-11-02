"""Lab 7 closure -- the Linux/FRR NETCONF telemetry adapter (``monitoring/scripts/linux_netconf_server.py``), each
function called directly.

Hermetic: the script is loaded as a module, ``ETC`` / ``LOG_PATH`` point into a temporary directory, metric readers
are patched, SSH channels and the paramiko transport are in-memory fakes, and no socket is opened.  ``main`` is an
unbounded accept loop that can only exit by raising, so its POSITIVE case is documented debt, not faked here.
POSITIVE: exact framed hello / replies, filtered get data, a full session and an accepted connection.  NEGATIVE:
malformed XML and unsupported operations get rpc-errors, a client without a base capability or a closed channel ends
the session, wrong passwords / non-session channels / other subsystems are refused, and transport errors are logged.
"""
from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path
from unittest import mock

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


nc = load("tg_linux_netconf_server", SCRIPTS / "linux_netconf_server.py")
paramiko = nc.paramiko
EOM = nc.EOM
NS = 'xmlns="urn:ietf:params:xml:ns:netconf:base:1.0"'
CLIENT_HELLO = f"<hello {NS}><capabilities><capability>urn:ietf:params:netconf:base:1.0</capability></capabilities></hello>"
CREDS = {"TELEMETRY_USERNAME": "tele", "TELEMETRY_PASSWORD": "fake-Tele-Pass-2"}


class FakeChannel:
    """recv() hands out queued byte chunks (b"" = peer closed); sendall() records frames."""

    def __init__(self, *chunks, error=None):
        self.chunks, self.error, self.sent, self.closed = list(chunks), error, [], False

    def recv(self, _size):
        if self.error is not None and not self.chunks:
            raise self.error
        return self.chunks.pop(0) if self.chunks else b""

    def sendall(self, payload):
        self.sent.append(payload)

    def close(self):
        self.closed = True


def framed(text):
    return text.encode() + EOM


class AdapterBase(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.etc, self.log = Path(tmp.name), Path(tmp.name) / "netconf.log"
        for target, value in ((nc, ("ETC", self.etc)), (nc, ("LOG_PATH", self.log)), (nc.metrics, ("hostname", lambda: "R4")),
                              (nc.metrics, ("interfaces", lambda: {"eth2": {}, "eth1": {}, "lo": {}}))):
            patcher = mock.patch.object(target, *value)
            patcher.start()
            self.addCleanup(patcher.stop)


class HelperTests(AdapterBase):
    def test_log_appends_a_timestamped_line(self):
        nc.log("session start")
        self.assertRegex(self.log.read_text(), r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d session start\n$")

    def test_log_to_an_unwritable_path_is_ignored_without_error(self):
        with mock.patch.object(nc, "LOG_PATH", self.etc / "missing" / "x.log"):
            self.assertIsNone(nc.log("x"))

    def test_load_env_returns_key_values(self):
        (self.etc / "credentials.env").write_text("TELEMETRY_USERNAME=tele\nnoise\nTELEMETRY_PASSWORD=a=b\n")
        self.assertEqual(nc.load_env("credentials.env"), {"TELEMETRY_USERNAME": "tele", "TELEMETRY_PASSWORD": "a=b"})

    def test_load_env_of_a_missing_file_raises(self):
        with self.assertRaises(FileNotFoundError):
            nc.load_env("absent.env")

    def test_load_or_create_host_key_creates_a_protected_key_then_reuses_it(self):
        fake_key = mock.Mock()
        fake_key.write_private_key_file.side_effect = lambda path: Path(path).write_text("fake-key")
        with mock.patch.object(paramiko.RSAKey, "generate", return_value=fake_key) as generate, \
                mock.patch.object(paramiko.RSAKey, "from_private_key_file", return_value="loaded") as loaded:
            self.assertIs(nc.load_or_create_host_key(), fake_key)
            self.assertEqual(oct((self.etc / "netconf_host_key").stat().st_mode & 0o777), "0o600")
            self.assertEqual(nc.load_or_create_host_key(), "loaded")
        generate.assert_called_once_with(2048)
        loaded.assert_called_once_with(str(self.etc / "netconf_host_key"))

    def test_rpc_reply_returns_the_quoted_message_id(self):
        self.assertEqual(nc.rpc_reply('7"x', "<ok/>"),
                         b'<?xml version="1.0" encoding="UTF-8"?>\n<rpc-reply xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" message-id=\'7"x\'><ok/></rpc-reply>\n')

    def test_rpc_reply_never_lets_a_message_id_break_the_attribute(self):
        found = nc.rpc_reply('1" injected="x', "")
        self.assertIn(b"message-id='1\" injected=\"x'>", found)
        self.assertNotIn(b'message-id="1" injected', found)

    def test_error_reply_returns_an_rpc_error_with_the_tag(self):
        found = nc.error_reply("5", tag="malformed-message")
        self.assertIn(b"<error-tag>malformed-message</error-tag><error-severity>error</error-severity>", found)

    def test_error_reply_without_a_tag_falls_back_to_the_unsupported_tag(self):
        self.assertIn(b"<error-tag>operation-not-supported</error-tag>", nc.error_reply("6"))

    def test_build_system_and_interfaces_data_return_live_values(self):
        self.assertEqual(nc.build_system_data(), '<data><system xmlns="http://openconfig.net/yang/system"><state><hostname>R4</hostname></state></system></data>')
        self.assertEqual(nc.build_interfaces_data(), '<data><interfaces xmlns="http://openconfig.net/yang/interfaces"><interface><name>eth1</name></interface>'
                                                     '<interface><name>eth2</name></interface><interface><name>lo</name></interface></interfaces></data>')

    def test_local_name_returns_the_unqualified_tag(self):
        self.assertEqual((nc.local_name("{urn:x}get"), nc.local_name("get")), ("get", "get"))

    def test_local_name_of_an_empty_tag_is_empty(self):
        self.assertEqual(nc.local_name(""), "")


class RpcTests(AdapterBase):
    def test_parse_rpc_returns_id_and_operation_for_any_prefix(self):
        message_id, name, operation = nc.parse_rpc('<nc:rpc xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0" nc:message-id="9"><nc:get/></nc:rpc>')
        self.assertEqual((message_id, name, nc.local_name(operation.tag)), ("9", "get", "get"))

    def test_parse_rpc_of_malformed_or_empty_rpc_has_no_operation(self):
        self.assertEqual(nc.parse_rpc("<rpc"), ("0", None, None))
        self.assertEqual(nc.parse_rpc(f"<rpc {NS}/>"), ("0", None, None))

    def test_handle_get_returns_the_filtered_block(self):
        _id, _name, system = nc.parse_rpc(f'<rpc {NS} message-id="1"><get><filter><system xmlns="http://openconfig.net/yang/system"/></filter></get></rpc>')
        _id, _name, interfaces = nc.parse_rpc(f'<rpc {NS} message-id="2"><get><filter><interfaces/></filter></get></rpc>')
        self.assertIn(b"<hostname>R4</hostname>", nc.handle_get("1", system))
        self.assertNotIn(b"<hostname>", nc.handle_get("2", interfaces))
        self.assertIn(b"<name>eth1</name>", nc.handle_get("2", interfaces))

    def test_handle_get_without_a_recognizable_filter_never_guesses_and_sends_both(self):
        _id, _name, bare = nc.parse_rpc(f'<rpc {NS} message-id="3"><get/></rpc>')
        found = nc.handle_get("3", bare)
        self.assertIn(b"<data><system", found)
        self.assertIn(b"<name>lo</name></interface></interfaces></data>", found)

    def test_dispatch_refuses_malformed_and_unsupported_operations(self):
        for raw, tag in (("not xml", b"malformed-message"), (f'<rpc {NS} message-id="4"><edit-config/></rpc>', b"operation-not-supported")):
            with self.subTest(case=f"refused {tag.decode()}"):
                reply, close = nc.dispatch(raw)
                self.assertEqual((close, tag in reply), (False, True))


class FramingTests(AdapterBase):
    def test_read_framed_returns_the_first_message_across_chunks(self):
        self.assertEqual(nc.read_framed(FakeChannel(b"<a>", b"</a>]]>", b"]]><b/>")), "<a></a>")

    def test_read_framed_of_a_closed_channel_is_empty(self):
        self.assertEqual(nc.read_framed(FakeChannel(b"<partial")), "")

    def test_write_framed_returns_after_sending_one_terminated_frame(self):
        channel = FakeChannel()
        self.assertIsNone(nc.write_framed(channel, b"<x/>"))
        self.assertEqual(channel.sent, [b"<x/>" + EOM])

    def test_write_framed_on_a_broken_channel_raises(self):
        channel = mock.Mock(sendall=mock.Mock(side_effect=OSError("broken pipe")))
        with self.assertRaises(OSError):
            nc.write_framed(channel, b"<x/>")


class SessionTests(AdapterBase):
    def test_serve_session_returns_after_hello_get_and_close(self):
        channel = FakeChannel(framed(CLIENT_HELLO), framed(f'<rpc {NS} message-id="11"><get/></rpc>'),
                              framed(f'<rpc {NS} message-id="12"><close-session/></rpc>'))
        self.assertIsNone(nc.serve_session(channel, "peer1"))
        self.assertEqual(channel.sent[0], nc.SERVER_HELLO + EOM)
        self.assertIn(b'message-id="11"><data><system', channel.sent[1])
        self.assertTrue(channel.sent[2].endswith(b'message-id="12"><ok/></rpc-reply>\n' + EOM))
        self.assertTrue(channel.closed)
        self.assertEqual(len(channel.sent), 3)

    def test_serve_session_without_a_base_capability_or_after_errors_ends_without_replies(self):
        for label, channel, logged in (("no base capability", FakeChannel(framed("<hello/>")), "no compatible base capability"),
                                       ("broken channel", FakeChannel(error=EOFError("gone")), "session error EOFError('gone')")):
            with self.subTest(case=f"refused {label}"):
                nc.serve_session(channel, "peer2")
                self.assertEqual((channel.sent, channel.closed), ([nc.SERVER_HELLO + EOM], True))
                self.assertIn(logged, self.log.read_text())


class InterfaceTests(unittest.TestCase):
    def setUp(self):
        self.server = nc.NetconfServerInterface(CREDS)

    def test_server_interface_init_keeps_the_credentials_and_a_clear_subsystem_flag(self):
        server = nc.NetconfServerInterface(CREDS)
        self.assertEqual((server._creds, server.subsystem_ok.is_set()), (CREDS, False))

    def test_server_interface_init_without_credentials_never_authenticates(self):
        server = nc.NetconfServerInterface({})
        self.assertEqual(server.check_auth_password("", ""), paramiko.AUTH_FAILED)

    def test_check_auth_password_accepts_the_configured_password(self):
        self.assertEqual(self.server.check_auth_password("tele", "fake-Tele-Pass-2"), paramiko.AUTH_SUCCESSFUL)

    def test_check_auth_password_refuses_a_wrong_user_or_password(self):
        self.assertEqual({self.server.check_auth_password("tele", "x"), self.server.check_auth_password("root", "fake-Tele-Pass-2")}, {paramiko.AUTH_FAILED})

    def test_get_allowed_auths_returns_password_only(self):
        self.assertEqual(self.server.get_allowed_auths("tele"), "password")

    def test_check_channel_request_accepts_a_session(self):
        self.assertEqual(self.server.check_channel_request("session", 1), paramiko.OPEN_SUCCEEDED)

    def test_check_channel_request_refuses_other_channel_kinds(self):
        self.assertEqual(self.server.check_channel_request("direct-tcpip", 1), paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED)

    def test_check_channel_subsystem_request_accepts_netconf(self):
        self.assertTrue(self.server.check_channel_subsystem_request(None, "netconf"))
        self.assertTrue(self.server.subsystem_ok.is_set())

    def test_check_channel_subsystem_request_refuses_other_subsystems(self):
        self.assertFalse(self.server.check_channel_subsystem_request(None, "sftp"))
        self.assertFalse(self.server.subsystem_ok.is_set())


class FakeTransport:
    def __init__(self, sock, *, channel=None, subsystem=True, error=None):
        self.sock, self.channel, self.subsystem, self.error, self.keys, self.closed = sock, channel, subsystem, error, [], False

    def add_server_key(self, key):
        self.keys.append(key)

    def start_server(self, server):
        if self.error is not None:
            raise self.error
        if self.subsystem:
            server.check_channel_subsystem_request(self.channel, "netconf")

    def accept(self, _timeout):
        return self.channel

    def close(self):
        self.closed = True


class ConnectionTests(AdapterBase):
    def connect(self, **kwargs):
        made = []

        def transport(sock):
            made.append(FakeTransport(sock, **kwargs))
            return made[-1]

        with mock.patch.object(paramiko, "Transport", side_effect=transport), mock.patch.object(nc, "serve_session") as serve:
            self.assertIsNone(nc.handle_connection("sock", ("192.0.2.5", 4000), "host-key", CREDS))
        return made[0], serve

    def test_handle_connection_serves_an_authenticated_netconf_subsystem(self):
        transport, serve = self.connect(channel="chan")
        serve.assert_called_once_with("chan", ("192.0.2.5", 4000))
        self.assertEqual((transport.keys, transport.closed), (["host-key"], True))

    def test_handle_connection_never_serves_without_a_channel_subsystem_or_on_error(self):
        for label, kwargs, logged in (("no channel", {"channel": None}, ""),
                                      ("no subsystem", {"channel": "chan", "subsystem": False}, "no netconf subsystem request within timeout"),
                                      ("transport error", {"error": paramiko.SSHException("negotiation failed")}, "transport error SSHException")):
            with self.subTest(case=f"refused {label}"), mock.patch("threading.Event.wait", return_value=False):
                transport, serve = self.connect(**kwargs)
                serve.assert_not_called()
                self.assertTrue(transport.closed)
                if logged:
                    self.assertIn(logged, self.log.read_text())


if __name__ == "__main__":
    unittest.main()
