"""Lab 7 closure -- the Health live-read layer: session adapters, ping, raw capture, config signatures, the routing
config facts and the connectivity target menu, each called directly.

No device is contacted: ``subprocess.run`` is patched (it records the argv it would have spawned), Netmiko / gNMI
connections are in-memory fakes, and inventory lookups are patched.  POSITIVE: the exact fixed argv / command string,
parsed rows, raw text of allowlisted keys and the closed ping-target menu.  NEGATIVE: an invalid destination or count
never reaches a transport, a missing container / target is NOT_CONFIGURED, unsupported or unknown platforms are never
read, a secret never survives a config signature, and an empty or unrelated history has no connectivity run.
"""

from __future__ import annotations

import subprocess
from unittest import mock

from django.test import SimpleTestCase, TestCase

from core.services.execution.executors import iosxe
from core.services.execution.executors.base import ExecutorError
from core.services.execution.writers import srlinux_gnmi
from core.services.health import connectivity, inventory, live, persistence, results, routing_config
from core.services.health.codes import CheckStatus as S, Health, Mode
from core.tests.helpers import health as h

PING_TEXT = h.ping_output()


class FakeSpawn:
    """Stands in for ``subprocess.run``: records each argv; answers with canned stdout / stderr / return code."""

    def __init__(self, stdout="", returncode=0, stderr="", error=None):
        self.stdout, self.returncode, self.stderr, self.error, self.argv = stdout, returncode, stderr, error, []

    def __call__(self, argv, **kwargs):
        self.argv.append(list(argv))
        assert kwargs["shell"] is False
        if self.error is not None:
            raise self.error
        return subprocess.CompletedProcess(argv, self.returncode, stdout=self.stdout, stderr=self.stderr)


class FakeConn:
    def __init__(self, outputs=None, error=None):
        self.outputs, self.error, self.sent, self.disconnected = outputs or {}, error, [], False

    def send_command(self, command, read_timeout=None):
        self.sent.append(command)
        if self.error is not None:
            raise self.error
        return self.outputs.get(command, PING_TEXT)

    def get(self, path, datastore):
        self.sent.append((path, datastore))
        if self.error is not None:
            raise self.error
        return {"path": path, "datastore": datastore}

    def disconnect(self):
        self.disconnected = True


class ReadTimeout(Exception):
    pass


def eos_session(conn):
    session = object.__new__(live.EosSession)
    session._conn, session._timeout = conn, 5
    return session


class DockerSessionTests(SimpleTestCase):
    def spawn(self, fake, call):
        with mock.patch.object(live.subprocess, "run", fake):
            return call()

    def test_docker_eos_ping_returns_output_of_the_fixed_cli_argv(self):
        fake = FakeSpawn(PING_TEXT)
        session = live.DockerEosSession({"name": "R5", "container": "clab-R5"})
        self.assertEqual(self.spawn(fake, lambda: session.ping(" 10.0.0.2 ", count=2)), PING_TEXT)
        self.assertEqual(fake.argv, [["docker", "exec", "clab-R5", "Cli", "-p", "15", "-c", "ping 10.0.0.2 repeat 2 timeout 1"]])
        self.assertIsNone(session.close())

    def test_docker_eos_ping_refused_destination_or_count_never_spawns(self):
        fake = FakeSpawn(PING_TEXT)
        session = live.DockerEosSession({"name": "R5", "container": "clab-R5"})
        for dest, count, code in (("10.0.0.2; reload", 3, "INVALID_DESTINATION"), ("example.com", 3, "INVALID_DESTINATION"),
                                  ("10.0.0.2", 9, "COMMAND_NOT_ALLOWED")):
            with self.subTest(case=f"refused {dest} x{count}"), self.assertRaises(live.LiveError) as caught:
                self.spawn(fake, lambda d=dest, c=count: session.ping(d, count=c))
            self.assertEqual(caught.exception.code, code)
        self.assertEqual(fake.argv, [])

    def test_docker_eos_ping_failure_and_missing_runtime_are_sanitized(self):
        session = live.DockerEosSession({"name": "R5", "container": "clab-R5"})
        for fake, code in ((FakeSpawn("", returncode=1, stderr="% unreachable"), "COMMAND_FAILED"),
                           (FakeSpawn(error=FileNotFoundError("docker")), "DOCKER_UNAVAILABLE"),
                           (FakeSpawn(error=subprocess.TimeoutExpired("docker", 5)), "TIMEOUT")):
            with self.subTest(case=f"failed {code}"), self.assertRaises(live.LiveError) as caught:
                self.spawn(fake, lambda: session.ping("10.0.0.2"))
            self.assertEqual(caught.exception.code, code)

    def test_linux_session_without_a_container_is_not_configured(self):
        for device in ({"name": "R3"}, {"name": "R3", "container": ""}):
            with self.subTest(case=f"missing container {device}"), self.assertRaises(live.LiveError) as caught:
                live.LinuxSession(device)
            self.assertEqual(caught.exception.code, "NOT_CONFIGURED")


class EosSessionPingTests(SimpleTestCase):
    def test_eos_ping_refused_destination_never_sends_a_command(self):
        conn = FakeConn()
        for dest in ("10.0.0.2 repeat 1; write", "", "300.1.1.1"):
            with self.subTest(case=f"refused {dest!r}"), self.assertRaises(live.LiveError) as caught:
                eos_session(conn).ping(dest)
            self.assertEqual(caught.exception.code, "INVALID_DESTINATION")
        self.assertEqual(conn.sent, [])

    def test_eos_ping_transport_errors_are_sanitized_codes(self):
        for error, code in ((ReadTimeout("10.9.9.9 secret"), "TIMEOUT"), (OSError("socket closed by 10.9.9.9"), "COMMAND_FAILED")):
            with self.subTest(case=f"failed {code}"), self.assertRaises(live.LiveError) as caught:
                eos_session(FakeConn(error=error)).ping("10.0.0.2")
            self.assertEqual((caught.exception.code, str(caught.exception)), (code, code))


class SrLinuxSessionTests(SimpleTestCase):
    def test_srlinux_run_returns_the_allowlisted_gnmi_get_as_json_and_close_disconnects_owned(self):
        conn = FakeConn()
        with mock.patch.object(srlinux_gnmi, "inventory_session", return_value=conn) as opened:
            session = live.SrLinuxSession({"name": "SRL1"})
        self.assertEqual(session.run("route_table"), '{"path": "/network-instance[name=default]/route-table", "datastore": "state"}')
        session.close()
        self.assertEqual((opened.call_count, conn.sent, conn.disconnected), (1, [("/network-instance[name=default]/route-table", "state")], True))

    def test_srlinux_borrowed_session_is_never_disconnected_and_unknown_keys_are_refused(self):
        conn = FakeConn()
        session = live.SrLinuxSession({"name": "SRL1"}, gnmi=conn)
        with self.assertRaises(live.LiveError) as caught:
            session.run("set_interface")
        session.close()
        self.assertEqual((caught.exception.code, conn.sent, conn.disconnected), ("COMMAND_NOT_ALLOWED", [], False))

    def test_srlinux_init_without_a_target_is_not_configured(self):
        with mock.patch("core.services.nsot_live.get_live_target", return_value=None), self.assertRaises(live.LiveError) as caught:
            live.SrLinuxSession({"name": "SRL1"})
        self.assertEqual(caught.exception.code, "NOT_CONFIGURED")

    def test_srlinux_run_errors_are_refused_with_sanitized_codes(self):
        session = live.SrLinuxSession({"name": "SRL1"}, gnmi=FakeConn(error=srlinux_gnmi.GnmiError("TIMEOUT")))
        for key, code in (("interfaces", "CONNECTION_FAILED"), ("route_table", "TIMEOUT")):
            with self.subTest(case=f"refused {key}"), self.assertRaises(live.LiveError) as caught:
                session.run(key)
            self.assertEqual(caught.exception.code, code)


class IosXeSessionTests(SimpleTestCase):
    def test_iosxe_run_returns_the_allowlisted_show_output_and_close_disconnects_owned(self):
        conn = FakeConn({"show ip interface": "GigabitEthernet1 is up, line protocol is up"})
        with mock.patch.object(iosxe, "netmiko_connection", return_value=conn):
            session = live.IosXeSession({"name": "C8K"})
        self.assertEqual(session.run("ip_interfaces"), "GigabitEthernet1 is up, line protocol is up")
        session.close()
        self.assertEqual((conn.sent, conn.disconnected), (["show ip interface"], True))

    def test_iosxe_init_refused_target_codes_and_invalid_input(self):
        for code in ("NOT_CONFIGURED", "AUTH_FAILED", "TIMEOUT"):
            with self.subTest(case=f"refused {code}"), mock.patch.object(iosxe, "netmiko_connection", side_effect=ExecutorError(code)), \
                    self.assertRaises(live.LiveError) as caught:
                live.IosXeSession({"name": "C8K"})
            self.assertEqual(caught.exception.code, code)
        conn = FakeConn({"show ipv6 interface": "% Invalid input detected at '^' marker."})
        session = live.IosXeSession({"name": "C8K"}, conn=conn)
        for key, code in (("ipv6_interfaces", "COMMAND_FAILED"), ("startup_config", "COMMAND_NOT_ALLOWED")):
            with self.subTest(case=f"refused {key}"), self.assertRaises(live.LiveError) as caught:
                session.run(key)
            self.assertEqual(caught.exception.code, code)
        session.close()
        self.assertEqual((conn.sent, conn.disconnected), (["show ipv6 interface"], False))


class HelperTests(SimpleTestCase):
    def test_get_capability_refuses_unknown_platforms_and_never_shares_its_table(self):
        for platform in ("junos", "", "CEOS"):
            with self.subTest(case=f"refused unknown {platform!r}"):
                self.assertEqual(live.get_capability(platform), {"status": "UNKNOWN", "transport": "", "groups": (),
                                                                 "evidence": "Platform not recognised by the health engine."})
        copy = live.get_capability("ceos")
        copy["status"] = "UNKNOWN"
        self.assertEqual(live.get_capability("ceos")["status"], "SUPPORTED")

    def test_norm_ip_returns_canonical_addresses(self):
        self.assertEqual([live.norm_ip(t) for t in (" 10.0.0.1 ", "2001:DB8:0::1", "10.0.0.1/24")], ["10.0.0.1", "2001:db8::1", None])

    def test_parse_linux_addr_returns_states_and_global_addresses(self):
        text = ('[{"ifname":"lo","flags":["LOOPBACK","UP","LOWER_UP"],"operstate":"UNKNOWN","addr_info":[{"local":"127.0.0.1","prefixlen":8,"scope":"host"}]},'
                '{"ifname":"eth1","flags":["BROADCAST"],"operstate":"DOWN","addr_info":[{"local":"fe80::1","prefixlen":64,"scope":"link"},'
                '{"local":"2001:DB8::1","prefixlen":64,"scope":"global"}]}]')
        self.assertEqual(live.parse_linux_addr(text), ({"lo": {"admin": "UP", "oper": "UP"}, "eth1": {"admin": "DOWN", "oper": "DOWN"}},
                                                       {"lo": ["127.0.0.1/8"], "eth1": ["2001:db8::1/64"]}))

    def test_config_path_signatures_returns_sorted_header_qualified_paths(self):
        self.assertEqual(live.config_path_signatures("interface Ethernet1\n   description x\nhostname R1\n"),
                         ["hostname R1", "interface Ethernet1", "interface Ethernet1 > description x"])

    def test_config_path_signatures_never_keep_a_secret_and_empty_is_none(self):
        found = live.config_path_signatures("username admin secret 0 fake-Secret-9\n")
        self.assertEqual(found, ["username admin secret <REDACTED>"])
        self.assertNotIn("fake-Secret-9", str(found))
        self.assertEqual((live.config_path_signatures(""), live.config_path_signatures(None)), ([], []))


class ReadDeviceWithRawTests(SimpleTestCase):
    def test_read_device_with_raw_returns_evidence_and_the_requested_raw_text(self):
        factory = h.session_factory(default=h.eos_outputs(config="hostname R1\n"))
        found, raw, errors = live.read_device_with_raw({"name": "R1", "platform": "ceos"}, ("running_config",), session_factory=factory, now=h.NOW)
        self.assertEqual((found.live_attempted, found.live_error, found.group("interfaces").available), (True, "", True))
        self.assertEqual((raw, errors), ({"running_config": "hostname R1\n"}, {}))
        self.assertEqual(factory.created[0][1].ran.count("running_config"), 1)
        self.assertTrue(factory.created[0][1].closed)

    def test_read_device_with_raw_failures_never_return_raw_text(self):
        unsupported = live.read_device_with_raw({"name": "X", "platform": "sonic"}, ("running_config",), session_factory=h.session_factory())
        self.assertEqual((unsupported[0].live_attempted, unsupported[0].live_error, unsupported[1], unsupported[2]),
                         (False, "NOT_SUPPORTED", {}, {"running_config": "NOT_SUPPORTED"}))
        refused = live.read_device_with_raw({"name": "R1", "platform": "ceos"}, ("running_config",),
                                            session_factory=h.session_factory(fail={"R1": live.LiveError("AUTH_FAILED")}))
        self.assertEqual((refused[0].live_error, refused[1], refused[2]), ("AUTH_FAILED", {}, {"running_config": "AUTH_FAILED"}))
        outputs = {**h.eos_outputs(), "running_config": live.LiveError("TIMEOUT")}
        partial = live.read_device_with_raw({"name": "R1", "platform": "ceos"}, ("running_config",), session_factory=h.session_factory(default=outputs), now=h.NOW)
        self.assertEqual((partial[1], partial[2], partial[0].group("config").available), ({}, {"running_config": "TIMEOUT"}, False))


class RoutingConfigTests(SimpleTestCase):
    def test_routing_config_of_empty_config_has_no_instances(self):
        self.assertEqual((routing_config.eos(""), routing_config.frr("", "[]")), ([], []))

    def test_routing_config_frr_with_malformed_addresses_never_binds_networks(self):
        (row,) = routing_config.frr("router ospf\n network 10.0.0.0/24 area 0\n", "not json")
        self.assertEqual((row["protocol"], row["networks"], row["network_bindings"]), ("ospf", [{"prefix": "10.0.0.0/24", "area": "0"}], []))

    def test_routing_config_eos_without_a_router_id_has_empty_router_id(self):
        (row,) = routing_config.eos("router bgp 65001\n")
        self.assertEqual((row["protocol"], row["local_asn"], row["router_id"], row["neighbors"]), ("bgp", 65001, "", []))


MANAGED = {"R1": {"name": "R1", "platform": "ceos", "address": "192.168.200.1", "address_v6": "2001:db8:200::1"},
           "R5": {"name": "R5", "platform": "ceos", "address": "", "address_v6": "", "container": "clab-R5"},
           "S1": {"name": "S1", "platform": "ceos", "address": "192.168.200.11", "address_v6": ""}}


class ConnectivityTests(TestCase):
    def setUp(self):
        for target, value in (("managed_devices", MANAGED), ("load_inventory", {"management": {"nmas_ipv4": "192.168.200.100/24", "nmas_ipv6": "bogus"}})):
            patcher = mock.patch.object(inventory, target, return_value=value)
            patcher.start()
            self.addCleanup(patcher.stop)

    def test_ping_targets_returns_nmas_and_other_addressed_devices(self):
        self.assertEqual(connectivity.ping_targets("R1"), [
            {"name": "nmas", "label": "NMAS (monitoring host)", "address": "192.168.200.100", "address_v6": ""},
            {"name": "S1", "label": "S1", "address": "192.168.200.11", "address_v6": ""},
        ])

    def test_latest_connectivity_run_of_empty_or_unrelated_history_is_none(self):
        self.assertIsNone(connectivity.latest_connectivity_run("R1"))
        row = results.CheckResult("DEVICE_REACHABLE", S.PASS, "R1", "m", "LIVE")
        persistence.record_run(mode=Mode.DEVICE_DEEP, status=Health.HEALTHY, results=[row], device="R1")
        persistence.record_run(mode=Mode.DEVICE_DEEP, status=Health.HEALTHY, results=[row], device="S1",
                               extra={"summary": {"check_type": connectivity.CHECK_TYPE}})
        self.assertIsNone(connectivity.latest_connectivity_run("R1"))
        self.assertEqual(connectivity.latest_connectivity_run("S1").device, "S1")   # the tag filter is what excluded R1's run
