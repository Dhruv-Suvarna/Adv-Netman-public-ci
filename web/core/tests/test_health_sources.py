"""Health source adapters: Fleet Quick (existing telemetry), the live read-only adapters, Deep Health, and failure handling.

External systems are always faked: no test contacts a device, InfluxDB, NetBox, Grafana, Docker or the topology service.
Pure evaluator logic is in ``test_health_engine``; plan-level precheck / postcheck in ``test_change_precheck``.
"""

from __future__ import annotations

import json
import socket
import subprocess
from unittest import mock

from django.test import SimpleTestCase, TestCase

from core import models
from core.services import health_service as hs, topology_service
from core.services.health import connectivity, device as device_module, fleet, inventory, live, telemetry
from core.services.health.codes import CheckStatus as S, Health
from core.tests.helpers import health as h
from core.tests.helpers.fakes import netbox_unreachable

FLEET = dict(include_sources=False, now=h.NOW)


def row_of(fleet_health, name="R1"):
    return next(r for r in fleet_health.devices if r["device"] == name)


def codes_of(row, status=None):
    return {c["check_code"] for c in row["checks"] if status is None or c["status"] == status}


class FleetQuickTests(SimpleTestCase):
    def test_device_health_matrix_from_telemetry(self):
        link = lambda status: [h.edge("R1", "R2", status)]  # noqa: E731
        rows = [  # label, topology kwargs, R1 health, a code that must be present with the given status
            ("fresh", {}, Health.HEALTHY, ("DEVICE_TELEMETRY_FRESH", S.PASS)),
            ("stale (61-120 s)", {"ages": {"R1": 90}}, Health.DEGRADED, ("DEVICE_TELEMETRY_STALE", S.WARN)),
            ("expired (>120 s)", {"ages": {"R1": 300}}, Health.UNHEALTHY, ("DEVICE_TELEMETRY_STALE", S.FAIL)),
            ("no timestamp at all", {"ages": {"R1": None}}, Health.UNKNOWN, ("DEVICE_TELEMETRY_UNAVAILABLE", S.UNKNOWN)),
            ("not monitored", {"unmonitored": ("R1",)}, Health.UNKNOWN, ("DEVICE_TELEMETRY_UNAVAILABLE", S.UNKNOWN)),
            ("cpu warning", {"cpu": {"R1": 75}}, Health.DEGRADED, ("CPU_HIGH", S.WARN)),
            ("cpu critical", {"cpu": {"R1": 95}}, Health.UNHEALTHY, ("CPU_HIGH", S.FAIL)),
            ("memory warning", {"memory": {"R1": 80}}, Health.DEGRADED, ("MEMORY_HIGH", S.WARN)),
            ("memory critical", {"memory": {"R1": 95}}, Health.UNHEALTHY, ("MEMORY_HIGH", S.FAIL)),
            ("cpu metric absent is UNKNOWN, not zero", {"cpu": {"R1": None}}, Health.HEALTHY, ("CPU_HIGH", S.UNKNOWN)),
            ("critical events", {"events": {"R1": 3}}, Health.DEGRADED, ("CRITICAL_EVENTS_RECENT", S.WARN)),
            ("link down", {"links": link("DOWN")}, Health.UNHEALTHY, ("LINK_HEALTH_DEGRADED", S.FAIL)),
            ("link degraded", {"links": link("DEGRADED")}, Health.DEGRADED, ("LINK_HEALTH_DEGRADED", S.WARN)),
            ("all links up", {"links": link("UP")}, Health.HEALTHY, ("LINK_HEALTH_DEGRADED", S.PASS)),
            ("a stale device with a hot CPU is unhealthy, not merely degraded", {"ages": {"R1": 90}, "cpu": {"R1": 99}}, Health.UNHEALTHY, ("CPU_HIGH", S.FAIL)),
        ]
        for label, kwargs, expected, (code, status) in rows:
            with self.subTest(case=label):
                snap = h.snapshot(**kwargs)
                row = row_of(fleet.get_fleet_health(snapshot=snap, **FLEET))
                self.assertEqual(row["health"], expected)
                self.assertIn(code, codes_of(row, status))

    def test_source_outages_make_devices_unknown_never_unhealthy(self):
        rows = [("influxdb error behind the topology service", h.snapshot(backend="ERROR")), ("topology service down", h.snapshot(summary=h.unavailable_topology()))]
        for label, snap in rows:
            with self.subTest(case=label):
                result = fleet.get_fleet_health(snapshot=snap, **FLEET)
                self.assertEqual({r["health"] for r in result.devices}, {Health.UNKNOWN})
                self.assertEqual((result.overall, result.counts["unhealthy"], result.counts["unknown"]), (Health.UNKNOWN, 0, 10))
                pipeline = next(c for c in result.conditions if c.check_code == "MONITORING_PIPELINE_UNHEALTHY")
                self.assertEqual(pipeline.status, S.UNKNOWN if not snap.available else S.FAIL)

    def test_fleet_quick_reads_existing_telemetry_only_and_never_a_device(self):
        with mock.patch.object(socket.socket, "connect", side_effect=AssertionError("socket")), \
                mock.patch.object(subprocess, "run", side_effect=AssertionError("subprocess")), \
                mock.patch.object(subprocess, "Popen", side_effect=AssertionError("popen")), \
                mock.patch.object(live, "read_device", side_effect=AssertionError("live read")), \
                mock.patch.object(topology_service, "get_topology_summary", return_value=h.topology_summary()) as once:
            result = fleet.get_fleet_health(include_sources=False, now=h.NOW)
        once.assert_called_once()
        self.assertEqual(set(r["device"] for r in result.devices), set(inventory.managed_devices()))
        self.assertTrue(all(r["routing_issues"] is None for r in result.devices), "routing state is NOT available, and never shown as 0")
        self.assertEqual((result.overall, result.counts["healthy"]), (Health.HEALTHY, 10))

    def test_fleet_conditions_are_reported_beside_not_inside_device_health(self):
        snap = h.snapshot()
        result = fleet.get_fleet_health(snapshot=snap, netbox=False, grafana=False, now=h.NOW)
        by_code = {c.check_code: c for c in result.conditions}
        self.assertEqual((by_code["NETBOX_SOURCE_UNAVAILABLE"].status, by_code["GRAFANA_UNAVAILABLE"].status), (S.WARN, S.WARN))
        self.assertEqual(result.overall, Health.HEALTHY, "NetBox / Grafana being down is not a network fault")
        silent = fleet.get_fleet_health(snapshot=h.snapshot(default_age=900), netbox=True, grafana=True, now=h.NOW)
        self.assertEqual(next(c for c in silent.conditions if c.check_code == "TELEMETRY_COLLECTOR_SILENT").status, S.WARN)
        self.assertEqual(silent.overall, Health.UNHEALTHY)
        # the passive service calls NetBox / Grafana only when asked (a test that forgets the fake would wait on the network)
        with netbox_unreachable(), mock.patch.object(telemetry, "grafana_available", return_value=None):
            self.assertIsNotNone(fleet.get_fleet_health(snapshot=snap, now=h.NOW))


# --- real-format samples (trimmed from output captured read-only on the live cEOS / FRR devices) ----------------------
EOS_INTERFACES = '{"interfaces": {"Ethernet2": {"name": "Ethernet2", "interfaceStatus": "connected", "lineProtocolStatus": "up"}, "Ethernet3": {"interfaceStatus": "disabled", "lineProtocolStatus": "down"}}}'
FRR_OSPF = '{"neighbors": {"192.168.255.1": [{"priority": 1, "nbrState": "Full\\/DR", "ifaceName": "Vlan101:192.168.100.1"}]}}'
FRR_OSPF6 = '{"neighbors": [{"neighborId": "192.168.255.1", "state": "Full", "interfaceName": "Vlan101"}]}'
FRR_BGP = '{"ipv4Unicast": {"peers": {"172.20.5.1": {"remoteAs": 65005, "state": "Established", "pfxRcd": 3, "pfxSnt": 2}}}, "ipv6Unicast": {"peers": {"2001:db8:205:1::2": {"remoteAs": 65005, "state": "Idle"}}}}'
IP_ADDR = json.dumps([{"ifname": "lo", "flags": ["LOOPBACK", "UP", "LOWER_UP"], "operstate": "UNKNOWN",
                       "addr_info": [{"local": "192.168.255.3", "prefixlen": 32, "scope": "global"}, {"local": "127.0.0.1", "prefixlen": 8, "scope": "host"}]},
                      {"ifname": "eth9", "flags": ["BROADCAST"], "operstate": "DOWN", "addr_info": [{"local": "fe80::1", "prefixlen": 64, "scope": "link"}]}])
NFT = 'table ip EDGE_PAT {\n\tchain postrouting {\n\t\ttype nat hook postrouting priority srcnat; policy accept;\n\t\toifname "eth2" ip saddr 10.0.0.0/8 masquerade\n\t}\n}\n'
EOS_CONFIG = """hostname R1
username admin secret sha512 $6$notreal
ip access-list EDGE-IN
   10 permit ip any any
interface Vlan10
   ip access-group EDGE-IN in
   ip helper-address 192.168.200.100
   snmp trap link-status
"""


class LiveParserTests(SimpleTestCase):
    def test_parsers_normalize_real_device_output(self):
        eos_addr = ('{"interfaces": {"Vlan10": {"interfaceAddress": {"primaryIp": {"address": "192.168.10.11", "maskLen": 24}, "secondaryIpsOrderedList": [], '
                    '"virtualIp": {"address": "192.168.10.1", "maskLen": 24}, "virtualSecondaryIpsOrderedList": []}}, '
                    '"Management0": {"interfaceAddress": {"primaryIp": {"address": "0.0.0.0", "maskLen": 0}}}}}')
        eos_v6 = '{"interfaces": {"Ethernet2": {"addresses": [{"address": "2001:db8:110:1::1", "subnet": "2001:db8:110:1::/64"}]}}}'
        eos_route = '{"vrfs": {"default": {"routes": {"10.9.0.0/24": {"routeType": "static", "vias": [{"nexthopAddr": "192.0.2.1", "interface": "Ethernet1"}]}}}}}'
        eos_ospf = '{"vrfs": {"default": {"instList": {"10": {"ospfNeighborEntries": [{"routerId": "1.1.1.1", "interfaceName": "Vlan101", "adjacencyState": "twoWay"}]}}}}}'
        eos_bgp = '{"vrfs": {"default": {"peers": {"172.20.5.0": {"asn": "65003", "peerState": "Established"}}}}}'
        rows = [
            ("eos interfaces: disabled is admin down", lambda: live.parse_eos_interfaces(EOS_INTERFACES),
             {"Ethernet2": {"admin": "UP", "oper": "UP"}, "Ethernet3": {"admin": "DOWN", "oper": "DOWN"}}),
            ("eos addresses: primary, v6, virtual; 0.0.0.0 ignored", lambda: live.parse_eos_addresses(eos_addr, eos_v6),
             ({"Vlan10": ["192.168.10.11/24"], "Management0": [], "Ethernet2": ["2001:db8:110:1::1/64"]}, {"Vlan10": ["192.168.10.1"]})),
            ("eos routes", lambda: live.parse_eos_routes(eos_route, '{"vrfs": {"default": {"routes": {}}}}'),
             [{"prefix": "10.9.0.0/24", "type": "static", "next_hops": ["192.0.2.1"], "interfaces": ["Ethernet1"]}]),
            ("eos ospf state names", lambda: live.parse_eos_ospf(eos_ospf, '{"vrfs": {}}'),
             [{"family": "OSPFV2", "neighbor_id": "1.1.1.1", "interface": "Vlan101", "state": "TWO_WAY"}]),
            ("eos bgp", lambda: live.parse_eos_bgp(eos_bgp, '{"errors": ["BGP inactive"]}'),
             [{"peer": "172.20.5.0", "remote_as": "65003", "state": "ESTABLISHED", "family": 4}]),
            ("eos bgp inactive is 'no peers', not an error", lambda: live.parse_eos_bgp('{"errors": ["BGP inactive"]}', '{"errors": ["BGP inactive"]}'), []),
            ("eos config facts only", lambda: live.parse_eos_config(EOS_CONFIG),
             {"acl_definitions": ["EDGE-IN"], "acl_attachments": [{"interface": "Vlan10", "acl": "EDGE-IN", "direction": "IN"}],
              "dhcp_relays": [{"interface": "Vlan10", "destination": "192.168.200.100"}]}),
            ("linux ip addr: link-local excluded, UNKNOWN+LOWER_UP is up", lambda: live.parse_linux_addr(IP_ADDR),
             ({"lo": {"admin": "UP", "oper": "UP"}, "eth9": {"admin": "DOWN", "oper": "DOWN"}}, {"lo": ["127.0.0.1/8", "192.168.255.3/32"], "eth9": []})),
            ("linux routes: default and nexthops", lambda: live.parse_linux_routes('[{"dst": "default", "gateway": "172.20.20.1", "dev": "eth0"}]',
                                                                                 '[{"dst": "2001:db8::/64", "nexthops": [{"gateway": "fe80::1", "dev": "Vlan101"}]}]'),
             [{"prefix": "0.0.0.0/0", "type": "", "next_hops": ["172.20.20.1"], "interfaces": ["eth0"]},
              {"prefix": "2001:db8::/64", "type": "", "next_hops": ["fe80::1"], "interfaces": ["Vlan101"]}]),
            ("frr ospf v2 + v3", lambda: live.parse_frr_ospf(FRR_OSPF, FRR_OSPF6),
             [{"family": "OSPFV2", "neighbor_id": "192.168.255.1", "interface": "Vlan101", "state": "FULL"},
              {"family": "OSPFV3", "neighbor_id": "192.168.255.1", "interface": "Vlan101", "state": "FULL"}]),
            ("frr ospf not running ('%' answer) is 'no neighbors'", lambda: live.parse_frr_ospf("% OSPF instance not found", "% no ospf6"), []),
            ("frr bgp both families", lambda: live.parse_frr_bgp(FRR_BGP),
             [{"peer": "172.20.5.1", "remote_as": "65005", "state": "ESTABLISHED", "family": 4, "prefixes": {"IPV4": {"received": 3, "sent": 2}}},
              {"peer": "2001:db8:205:1::2", "remote_as": "65005", "state": "IDLE", "family": 6, "prefixes": {"IPV6": {"received": None, "sent": None}}}]),
            ("nft: only NAT facts", lambda: live.parse_nft(NFT), {"tables": ["EDGE_PAT"], "rules": [{"table": "EDGE_PAT", "oif": "eth2", "action": "masquerade"}]}),
        ]
        for label, parse, expected in rows:
            with self.subTest(parser=label):
                self.assertEqual(parse(), expected)
        for label, parse in (("not json", lambda: live.parse_eos_interfaces("Traceback ...")), ("wrong shape", lambda: live.parse_linux_addr('{"a": 1}'))):
            with self.subTest(malformed=label):
                with self.assertRaises(live.LiveError) as raised:
                    parse()
                self.assertEqual(raised.exception.code, "PARSE_ERROR")

    def test_platform_health_capability_matrix_is_independent_of_configuration_support(self):
        rows = [("ceos", "SUPPORTED"), ("linux", "SUPPORTED"), ("nokia_srlinux", "SUPPORTED"),
                ("cisco_c8000v_iosxe", "SUPPORTED"), ("cisco_iosxr", "NOT_IMPLEMENTED"),
                ("sonic", "NOT_IMPLEMENTED"), ("something_else", "UNKNOWN")]
        for platform, status in rows:
            with self.subTest(platform=platform):
                self.assertEqual(live.get_capability(platform)["status"], status)
        factory = h.session_factory(default={})
        for platform in ("cisco_iosxr", "sonic", "something_else"):
            with self.subTest(not_probed=platform):
                evidence = live.read_device({"name": "X1", "platform": platform, "container": "c"}, session_factory=factory)
                self.assertEqual((evidence.live_attempted, evidence.live_error), (False, "NOT_SUPPORTED"))
        self.assertEqual(factory.created, [], "an unsupported platform is never contacted")

    def test_live_sessions_send_only_fixed_read_only_commands(self):
        # Linux/FRR: docker exec with a fixed argv list, no shell, a timeout
        completed = mock.Mock(returncode=0, stdout="[]", stderr="")
        session = live.LinuxSession({"name": "R3", "container": "clab-srlceos01-R3"})
        with mock.patch.object(subprocess, "run", return_value=completed) as run:
            session.run("addr")
            session.run("bgp")
        commands = [c.args[0] for c in run.call_args_list]
        self.assertEqual(commands, [["docker", "exec", "clab-srlceos01-R3", "ip", "-j", "addr", "show"],
                                    ["docker", "exec", "clab-srlceos01-R3", "vtysh", "-c", "show bgp summary json"]])
        self.assertTrue(all(c.kwargs["shell"] is False and c.kwargs["timeout"] > 0 for c in run.call_args_list))
        for bad in ("reload", "addr; reboot", "../../etc/passwd", ""):
            with self.subTest(refused=bad):
                with self.assertRaises(live.LiveError) as raised:
                    session.run(bad)
                self.assertEqual(raised.exception.code, "COMMAND_NOT_ALLOWED")
        for error, code in ((FileNotFoundError(), "DOCKER_UNAVAILABLE"), (subprocess.TimeoutExpired("docker", 8), "TIMEOUT")):
            with self.subTest(error=code), mock.patch.object(subprocess, "run", side_effect=error):
                with self.assertRaises(live.LiveError) as raised:
                    session.run("addr")
                self.assertEqual(raised.exception.code, code)

        # cEOS: Netmiko, privileged EXEC only; a connection whose config-entering methods explode proves none is ever called
        conn = mock.MagicMock()
        conn.check_enable_mode.return_value = True
        conn.send_command.return_value = "{}"
        for forbidden in ("config_mode", "send_config_set", "send_config_from_file", "save_config", "commit", "exit_config_mode"):
            getattr(conn, forbidden).side_effect = AssertionError(f"{forbidden} must never be called")
        target = {"platform": "ceos", "address": "192.0.2.1", "username": "test-user", "password": "TEST_ONLY_HEALTH_SECRET"}
        with mock.patch.object(live.nsot_live, "get_live_target", return_value=target), mock.patch("netmiko.ConnectHandler", return_value=conn) as connect:
            eos = live.EosSession({"name": "R1"})
            for key in live.CEOS_COMMANDS:
                eos.run(key)
            with self.assertRaises(live.LiveError):
                eos.run("configure terminal")
            eos.close()
        self.assertEqual(connect.call_args.kwargs["username"], "test-user")
        sent = {c.args[0] for c in conn.send_command.call_args_list}
        self.assertEqual(sent, set(live.CEOS_COMMANDS.values()))
        conn.disconnect.assert_called_once()

    def test_parse_ping_output(self):
        rows = [
            ("no loss", h.ping_output(transmitted=3, received=3), {"transmitted": 3, "received": 3, "loss_percent": 0.0,
                                                                    "rtt_min_ms": 0.037, "rtt_avg_ms": 0.041, "rtt_max_ms": 0.045}),
            ("partial loss", h.ping_output(transmitted=3, received=1), {"transmitted": 3, "received": 1, "loss_percent": 67.0}),
            ("100% loss, no rtt line", "PING x\n3 packets transmitted, 0 received, 100% packet loss, time 2000ms",
             {"transmitted": 3, "received": 0, "loss_percent": 100.0, "rtt_min_ms": None, "rtt_avg_ms": None, "rtt_max_ms": None}),
            ("host unreachable errors", "PING x\n3 packets transmitted, 0 received, +3 errors, 100% packet loss, time 2000ms",
             {"transmitted": 3, "received": 0, "loss_percent": 100.0}),
        ]
        for label, text, expected in rows:
            with self.subTest(case=label):
                stats = live.parse_ping_output(text)
                for key, value in expected.items():
                    self.assertEqual(stats[key], value)
        with self.assertRaises(live.LiveError) as raised:
            live.parse_ping_output("not ping output at all")
        self.assertEqual(raised.exception.code, "PARSE_ERROR")

    def test_health_tries_r1_identity_then_rollback_identity(self):
        from netmiko.exceptions import NetmikoAuthenticationException

        conn = mock.MagicMock()
        conn.check_enable_mode.return_value = True
        target = {
            "platform": "ceos", "address": "192.0.2.1", "username": "nmas-automation", "password": "primary",
            "auth_candidates": (
                {"username": "nmas-automation", "password": "primary", "ssh_auth": {}},
                {"username": "admin", "password": "rollback", "ssh_auth": {}},
            ),
        }
        with mock.patch.object(live.nsot_live, "get_live_target", return_value=target), \
                mock.patch("netmiko.ConnectHandler", side_effect=[NetmikoAuthenticationException("fixture"), conn]) as connect:
            session = live.EosSession({"name": "R1"})
            session.close()
        self.assertEqual([call.kwargs["username"] for call in connect.call_args_list], ["nmas-automation", "admin"])

    def test_validate_ping_destination_accepts_only_bare_ip_literals(self):
        self.assertEqual(live.validate_ping_destination("192.168.200.100"), "192.168.200.100")
        self.assertEqual(live.validate_ping_destination(" 2001:db8:200::100 "), "2001:db8:200::100")
        self.assertEqual(live.validate_ping_destination("192.168.200.100", family=4), "192.168.200.100")
        for hostile in ("192.168.200.100; reload", "8.8.8.8 vrf mgmt", "$(reboot)", "`id`", "not-an-ip", "", "2001:db8::1 && show run"):
            with self.subTest(hostile=hostile):
                with self.assertRaises(live.LiveError) as raised:
                    live.validate_ping_destination(hostile)
                self.assertEqual(raised.exception.code, "INVALID_DESTINATION")
        with self.assertRaises(live.LiveError) as raised:
            live.validate_ping_destination("2001:db8::1", family=4)  # v6 literal, v4 requested
        self.assertEqual(raised.exception.code, "INVALID_DESTINATION")

    def test_ping_sessions_send_only_a_validated_read_only_command(self):
        completed = mock.Mock(returncode=0, stdout=h.ping_output(), stderr="")
        session = live.LinuxSession({"name": "R3", "container": "clab-srlceos01-R3"})
        with mock.patch.object(subprocess, "run", return_value=completed) as run:
            session.ping("192.168.200.100")
            session.ping("2001:db8:200::100")
        commands = [c.args[0] for c in run.call_args_list]
        self.assertEqual(commands, [["docker", "exec", "clab-srlceos01-R3", "ping", "-4", "-c", "3", "-W", "2", "192.168.200.100"],
                                    ["docker", "exec", "clab-srlceos01-R3", "ping", "-6", "-c", "3", "-W", "2", "2001:db8:200::100"]])
        with self.assertRaises(live.LiveError) as raised:
            session.ping("192.168.200.100; reload")
        self.assertEqual(raised.exception.code, "INVALID_DESTINATION")

        conn = mock.MagicMock()
        conn.check_enable_mode.return_value = True
        conn.send_command.return_value = h.ping_output()
        for forbidden in ("config_mode", "send_config_set", "save_config", "commit"):
            getattr(conn, forbidden).side_effect = AssertionError(f"{forbidden} must never be called")
        target = {"platform": "ceos", "address": "192.0.2.1", "username": "test-user", "password": "TEST_ONLY_HEALTH_SECRET"}
        with mock.patch.object(live.nsot_live, "get_live_target", return_value=target), mock.patch("netmiko.ConnectHandler", return_value=conn):
            eos = live.EosSession({"name": "R1"})
            eos.ping("192.168.200.1")
            eos.close()
        conn.send_command.assert_called_once_with("ping 192.168.200.1 repeat 3 timeout 1", read_timeout=mock.ANY)


class DeepHealthTests(TestCase):
    def deep(self, name="R1", outputs=None, *, ages=None, factory=None, **kwargs):
        factory = factory or h.session_factory({name: outputs if outputs is not None else h.eos_outputs()})
        snap = h.snapshot(ages=ages or {})
        return device_module.run_device_health(name, actor="tester", snapshot=snap, session_factory=factory, now=h.NOW, **kwargs), factory

    def statuses(self, report, code):
        return [r["status"] for r in report["results"] if r["check_code"] == code]

    def test_live_evidence_takes_precedence_and_only_allowlisted_commands_run(self):
        outputs = h.eos_outputs(interfaces={"Ethernet1": ("connected", "up"), "Ethernet2": ("connected", "down")}, ipv4={"Ethernet1": ["192.0.2.0/31"], "Ethernet2": ["10.0.0.1/24"]},
                                ospf=[("Ethernet1", "10.0.0.2", "full")], bgp=[("192.0.2.1", 65002, "Established")], routes=[("10.9.0.0/24", "192.0.2.1", "Ethernet1")])
        (run, report), factory = self.deep(outputs=outputs, ages={"R1": 400})  # telemetry is EXPIRED, but the device answers live
        self.assertEqual(self.statuses(report, "DEVICE_REACHABLE"), [S.PASS])
        self.assertEqual(self.statuses(report, "DEVICE_TELEMETRY_STALE"), [S.WARN], "expired telemetry only warns when live proves the device is up")
        self.assertEqual(self.statuses(report, "INTERFACE_OPER_DOWN"), [S.FAIL])  # Ethernet2: addressed, admin up, oper down
        self.assertEqual((run.mode, run.device, run.status), ("DEVICE_DEEP", "R1", Health.UNHEALTHY))
        self.assertEqual(self.statuses(report, "OSPF_EXPECTED_FULL") + self.statuses(report, "BGP_EXPECTED_ESTABLISHED"), [S.PASS, S.PASS])
        (_, session), = factory.created
        self.assertTrue(set(session.ran) <= set(live.CEOS_COMMANDS) and session.closed)
        self.assertEqual(report["facts"]["groups"]["interfaces"]["source"], "LIVE")
        self.assertEqual(report["facts"]["groups"]["telemetry"]["source"], "TELEMETRY")

    def test_routing_failures_are_reported_from_live_state(self):
        outputs = h.eos_outputs(ospf=[("Ethernet1", "10.0.0.2", "exStart")], bgp=[("192.0.2.1", 65002, "Idle")])
        (_, report), _ = self.deep(outputs=outputs)
        self.assertEqual((self.statuses(report, "OSPF_ADJACENCY_DOWN"), self.statuses(report, "BGP_SESSION_DOWN")), ([S.FAIL], [S.FAIL]))
        (run, _), _ = self.deep(outputs=outputs)
        self.assertEqual(run.status, Health.UNHEALTHY)

    def test_device_failure_is_unknown_and_sanitized_and_other_checks_continue(self):
        secret = "hunter2-SECRET-ssh-rsa-AAAAB3Nza"
        rows = [
            ("a raw exception carrying a secret", {"R1": RuntimeError(f"auth failed password={secret}")}, "CONNECTION_FAILED", 300, S.FAIL),
            ("timeout, telemetry still fresh", {"R1": live.LiveError("TIMEOUT")}, "TIMEOUT", 5, S.UNKNOWN),
            ("timeout AND expired telemetry corroborate", {"R1": live.LiveError("TIMEOUT")}, "TIMEOUT", 300, S.FAIL),
            ("authentication refused", {"R1": live.LiveError("AUTH_FAILED")}, "AUTH_FAILED", 5, S.UNKNOWN),
        ]
        for label, fail, code, age, status in rows:
            with self.subTest(case=label):
                (run, report), _ = self.deep(factory=h.session_factory(fail=fail), ages={"R1": age})
                unreachable = next(r for r in report["results"] if r["check_code"] == "DEVICE_UNREACHABLE")
                self.assertEqual((unreachable["status"], unreachable["observed"]["reason_code"]), (status, code))
                self.assertIn("DEVICE_TELEMETRY_STALE" if age > 120 else "DEVICE_TELEMETRY_FRESH", {r["check_code"] for r in report["results"]}, "telemetry checks still ran")
                everything = json.dumps(report) + json.dumps(list(models.AuditEvent.objects.values_list("metadata", "summary")), default=str)
                self.assertNotIn(secret, everything)
                self.assertNotIn("password=", everything)
                self.assertNotEqual(run.status, "")

    def test_a_command_that_fails_after_connecting_only_loses_its_own_group(self):
        outputs = h.eos_outputs()
        outputs["ip_routes"] = live.LiveError("TIMEOUT")
        outputs["bgp"] = "Traceback (most recent call last): password=hunter2"
        (_, report), _ = self.deep(outputs=outputs)
        groups = report["facts"]["groups"]
        self.assertEqual((groups["routes"]["available"], groups["routes"]["error"]), (False, "TIMEOUT"))
        self.assertEqual(groups["bgp"]["error"], "PARSE_ERROR")
        self.assertTrue(groups["interfaces"]["available"], "the other groups are unaffected")
        self.assertEqual(self.statuses(report, "DEVICE_REACHABLE"), [S.PASS])
        self.assertNotIn("hunter2", json.dumps(report))

    def test_linux_frr_device_uses_its_own_adapter_and_nat_facts(self):
        outputs = h.linux_outputs(interfaces={"eth1": ["10.0.0.1/24"], "eth2": ["203.0.113.2/24"]}, nft=NFT, routes=[("10.9.0.0/24", "10.0.0.2", "eth1")])
        (_, report), factory = self.deep("R3", outputs)
        (_, session), = factory.created
        self.assertTrue(set(session.ran) <= set(live.LINUX_COMMANDS))
        self.assertEqual(report["capability"]["transport"], "docker-exec")
        self.assertEqual(self.statuses(report, "INTERFACE_EXPECTED_UP"), [S.PASS])

    def test_dhcp_service_state_reuses_the_existing_verifier_and_uses_its_semantics(self):
        from netbox.scripts import verify_dhcp_servers as verifier

        with mock.patch.object(verifier, "nmas_status", return_value={"server": "NMAS", "ipv4": "active", "ipv6": "inactive"}), \
                mock.patch.object(verifier, "r2_status", return_value={"server": "R2", "ipv4": "inactive", "ipv6": "active"}):
            state = live.dhcp_service_state()
        self.assertEqual((state["nmas"]["ipv4"], state["r2"]["ipv6"], state["error"]), ("active", "active", ""))
        both, one_dead, error = state, {**state, "r2": {"ipv4": "inactive", "ipv6": "inactive"}}, {"nmas": None, "r2": None, "error": "INSPECTION_FAILED"}
        for label, value, status in (("at least one family per server is healthy", both, S.PASS), ("a server with no active family", one_dead, S.FAIL), ("cannot inspect", error, S.UNKNOWN)):
            with self.subTest(case=label):
                self.assertEqual(device_module.dhcp_state_check(value).status, status)
        with mock.patch.object(verifier, "nmas_status", side_effect=OSError("boom password=x")), mock.patch.object(verifier, "r2_status", return_value={"ipv4": "active", "ipv6": "active"}):
            self.assertEqual(live.dhcp_service_state()["error"], "INSPECTION_FAILED")
        # Deep Health of the DHCP secondary host (R2, derived from inventory) includes the service check; other devices do not
        (_, report), _ = self.deep("R2", h.eos_outputs(), dhcp_state=one_dead)
        self.assertEqual(self.statuses(report, "DHCP_SERVICE_UNHEALTHY"), [S.FAIL])
        (_, other), _ = self.deep("R1", h.eos_outputs(), dhcp_state=one_dead)
        self.assertEqual(self.statuses(other, "DHCP_SERVICE_UNHEALTHY"), [])

    def test_only_managed_devices_can_be_probed(self):
        factory = h.session_factory(default=h.eos_outputs())
        with self.assertRaises(hs.UnknownDeviceError):
            device_module.run_device_health("R9", snapshot=h.snapshot(), session_factory=factory)
        with self.assertRaises(hs.UnknownDeviceError):
            device_module.run_device_health("R1; reload", snapshot=h.snapshot(), session_factory=factory)
        self.assertEqual((factory.created, models.OperationalCheckRun.objects.count()), ([], 0))


class ConnectivityCheckTests(TestCase):
    """Phase 22: the read-only IP connectivity (ping) check.  The destination is always resolved from the closed
    inventory menu (``ping_targets``), never a free-text address; ``live.py`` sessions are faked exactly like the
    Deep Health tests above -- no device, network or subprocess is ever touched."""

    def run_ping(self, device="R1", destination="nmas", family="4", *, ping_outputs=None, fail=None):
        factory = h.session_factory(default=h.eos_outputs(), ping_by_device={device: ping_outputs} if ping_outputs is not None else None, fail=fail)
        return connectivity.run_connectivity(device, destination, family, actor="tester", session_factory=factory, now=h.NOW), factory

    def statuses(self, report, code):
        return [r["status"] for r in report["results"] if r["check_code"] == code]

    def test_ping_targets_are_nmas_and_other_managed_devices_never_self(self):
        targets = {t["name"] for t in connectivity.ping_targets("R1")}
        self.assertIn("nmas", targets)
        self.assertIn("R2", targets)
        self.assertNotIn("R1", targets, "a device is never offered as its own ping destination")
        self.assertNotIn("R5", targets, "R5's Containerlab-assigned address is unknown at inventory time")
        nmas = next(t for t in connectivity.ping_targets("R1") if t["name"] == "nmas")
        self.assertEqual((nmas["address"], nmas["address_v6"]), ("192.168.200.100", "2001:db8:200::100"))

    def test_successful_ping_is_reachable_and_persisted_as_an_operational_check_run(self):
        before = models.OperationalCheckRun.objects.count()
        (run, report), factory = self.run_ping(ping_outputs={"192.168.200.100": h.ping_output(transmitted=3, received=3)})
        self.assertEqual(self.statuses(report, "CONNECTIVITY_REACHABLE"), [S.PASS])
        self.assertEqual((run.mode, run.device, run.status), ("DEVICE_DEEP", "R1", Health.HEALTHY))
        self.assertEqual(run.summary["check_type"], "CONNECTIVITY")
        self.assertEqual(models.OperationalCheckRun.objects.count(), before + 1)
        (_, session), = factory.created
        self.assertEqual(session.pinged, [("192.168.200.100", connectivity.PING_COUNT)])

    def test_partial_loss_is_degraded_and_full_loss_is_unreachable(self):
        (_, degraded), _ = self.run_ping(ping_outputs={"192.168.200.100": h.ping_output(transmitted=3, received=1)})
        self.assertEqual(self.statuses(degraded, "CONNECTIVITY_DEGRADED"), [S.WARN])
        (run, unreachable), _ = self.run_ping(ping_outputs={"192.168.200.100": h.ping_output(transmitted=3, received=0)})
        self.assertEqual(self.statuses(unreachable, "CONNECTIVITY_UNREACHABLE"), [S.FAIL])
        self.assertEqual(run.status, Health.UNHEALTHY)

    def test_ipv6_destination_uses_the_v6_address(self):
        (_, report), factory = self.run_ping(destination="R2", family="6", ping_outputs={"2001:db8:200::2": h.ping_output()})
        self.assertEqual(self.statuses(report, "CONNECTIVITY_REACHABLE"), [S.PASS])
        (_, session), = factory.created
        self.assertEqual(session.pinged, [("2001:db8:200::2", connectivity.PING_COUNT)])

    def test_missing_address_family_is_unknown_and_never_opens_a_session(self):
        v4_only = {"name": "v4only", "label": "v4-only target", "address": "192.168.200.99", "address_v6": ""}
        factory = h.session_factory(default=h.eos_outputs())
        with mock.patch.object(connectivity, "ping_targets", return_value=[connectivity._nmas_target(), v4_only]):
            (_run, report), factory = self.run_ping(destination="v4only", family="6", ping_outputs={})
        self.assertEqual(self.statuses(report, "CONNECTIVITY_CHECK_UNAVAILABLE"), [S.UNKNOWN])
        self.assertEqual(factory.created, [], "no session is opened when the destination has no address for the requested family")

    def test_unsupported_platform_is_unknown_and_never_opens_a_session(self):
        factory = h.session_factory(default=h.eos_outputs())
        with mock.patch.object(inventory, "get_managed_device", return_value={"name": "R1", "platform": "sonic", "address": "", "container": ""}):
            (_run, report), _ = self.run_ping()
        self.assertEqual(self.statuses(report, "CONNECTIVITY_CHECK_UNAVAILABLE"), [S.UNKNOWN])
        self.assertEqual(factory.created, [])

    def test_session_open_failure_is_reported_as_unknown_not_a_crash(self):
        (_run, report), factory = self.run_ping(fail={"R1": live.LiveError("AUTH_FAILED")})
        self.assertEqual(self.statuses(report, "CONNECTIVITY_CHECK_UNAVAILABLE"), [S.UNKNOWN])

    def test_unknown_device_or_destination_never_touches_a_session(self):
        factory = h.session_factory(default=h.eos_outputs())
        with self.assertRaises(hs.UnknownDeviceError):
            connectivity.run_connectivity("R9", "nmas", "4", session_factory=factory)
        with self.assertRaises(connectivity.UnknownDestinationError):
            connectivity.run_connectivity("R1", "not-a-real-target", "4", session_factory=factory)
        with self.assertRaises(connectivity.UnknownDestinationError):
            connectivity.run_connectivity("R1", "R1", "4", session_factory=factory)  # a device is never its own destination
        self.assertEqual(factory.created, [])

    def test_latest_connectivity_run_ignores_deep_health_runs(self):
        device_module.run_device_health("R1", snapshot=h.snapshot(), session_factory=h.session_factory(default=h.eos_outputs()), now=h.NOW)
        self.assertIsNone(connectivity.latest_connectivity_run("R1"))
        (run, _), _ = self.run_ping(ping_outputs={"192.168.200.100": h.ping_output()})
        self.assertEqual(connectivity.latest_connectivity_run("R1").run_id, run.run_id)
