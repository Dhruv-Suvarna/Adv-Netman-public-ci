"""Platform executors, the capability model and the shared state model -- against REAL rendered Configlet lines.

The Configlet specs below are built from a real validated plan (so the executor grammars are proven against what the planner
actually emits), while every device is a fake: a fake Netmiko connection, a fake ``docker`` runner and canned evidence.
"""

from __future__ import annotations

import inspect
import subprocess
from unittest import mock

from django.test import SimpleTestCase, TestCase

from core import models
from core.services import execution_service as es
from core.services.execution import capability
from core.services.execution.executors import ceos, iosxe, linux, registry, srlinux, state
from core.services.execution.executors.base import APPLY, REFUSE, SKIP_SATISFIED, ConfigletSpec, ExecutorError
from core.tests.helpers import health as h
from core.tests.helpers.validation import Dev, simple_pass_change, validate
from core.services import change_plan_service as cps

SECRET = "hunter2-SECRET"


class RealSpecs(TestCase):
    """One plan holding cEOS interface/address/static-route Configlets and Ubuntu/FRR interface/address Configlets."""

    @classmethod
    def setUpTestData(cls):
        f = simple_pass_change()
        f.r1.static_route("10.9.0.0/24", next_hop="192.0.2.1")
        r3 = Dev(f.change, "R3", platform=models.Platform.UBUNTU_FRR)
        r3.address(r3.iface("eth1"), "192.0.2.4/31")
        validate(f.change, f.sources)
        plan, _ = cps.build_change_plan(f.change, actor="t", sources=f.sources)
        cls.specs = {}
        for configlet in plan.configlets.order_by("sequence"):
            spec = ConfigletSpec.from_configlet(configlet)
            cls.specs.setdefault((spec.device, spec.object_type), spec)

    def spec(self, device, object_type):
        return self.specs[(device, object_type)]


class FakeConnection:
    """A fake Netmiko session: records what was sent; can return a rejection or raise."""

    def __init__(self, output="", raises=None):
        self.output, self.raises, self.sent, self.modes, self.disconnected = output, raises, [], [], False
        self._in_config = False

    def config_mode(self, **kwargs):
        self._in_config = True
        self.modes.append("config")

    def send_config_set(self, commands, **kwargs):
        self.sent.append(list(commands))
        if self.raises:
            raise self.raises
        return self.output

    def check_config_mode(self):
        return self._in_config

    def exit_config_mode(self):
        self._in_config = False
        self.modes.append("exit")

    def disconnect(self):
        self.disconnected = True


def reader_for(*worlds):
    """A reader returning the given evidence in order (the last one repeats): pre-state, then read-back."""
    queue = list(worlds)
    return lambda device: queue.pop(0) if len(queue) > 1 else queue[0]


def ev(interfaces=None, addresses=None, routes=None, *, reachable=True):
    evidence = h.device_evidence("R1", interfaces=interfaces if interfaces is not None else {}, addresses=addresses if addresses is not None else {},
                                 routes=routes if routes is not None else [], live_ok=reachable)
    return evidence


class CeosExecutorTests(RealSpecs):
    device = {"name": "R1", "platform": "ceos"}

    def executor(self, conn=None, reader=None):
        executor = ceos.CeosExecutor(self.device, connection_factory=lambda device: conn or FakeConnection(), reader=reader or reader_for(ev()))
        executor.connect()
        return executor

    def test_apply_uses_the_master_py_push_mechanism_and_never_persists(self):
        spec = self.spec("R1", "address")
        conn = FakeConnection()
        outcome = self.executor(conn).apply(spec, mock.Mock())
        self.assertTrue(outcome.ok)
        self.assertEqual(conn.sent, [["interface Ethernet1", "ip address 192.0.2.0/31", "exit"]], "eos_commands flattening: explicit exit, no blank / comment lines")
        self.assertEqual(conn.modes, ["config", "exit"], "configuration mode is entered and always left")
        for command in conn.sent[0]:
            self.assertFalse(command.startswith(("write", "copy", "reload", "commit")), "the run changes the RUNNING config only (no write memory)")

    def test_every_device_failure_is_reduced_to_a_fixed_code_and_never_relays_text(self):
        rows = [
            ("command rejected by EOS", FakeConnection(output="% Invalid input (at token 1)"), "COMMAND_REJECTED"),
            ("command unavailable on the platform", FakeConnection(output="% Unavailable command (not supported on this hardware platform)"),
             "COMMAND_REJECTED"),
            ("timeout", FakeConnection(raises=type("ReadTimeout", (Exception,), {})(f"password {SECRET}")), "TIMEOUT"),
            ("any other transport error", FakeConnection(raises=RuntimeError(f"login as admin password {SECRET}")), "TRANSPORT_ERROR"),
        ]
        for label, conn, code in rows:
            with self.subTest(case=label):
                outcome = self.executor(conn).apply(self.spec("R1", "address"), mock.Mock())
                self.assertEqual((outcome.ok, outcome.error_code, outcome.partial_effects), (False, code, True))
                self.assertNotIn(SECRET, repr(outcome))
                self.assertEqual(conn.modes, ["config", "exit"], "even after a failure the session is not left in configuration mode")

    def test_connection_errors_never_echo_connection_parameters(self):
        auth = type("NetmikoAuthenticationException", (Exception,), {})
        timeout = type("NetmikoTimeoutException", (Exception,), {})
        rows = [("auth", auth, "AUTH_FAILED"), ("timeout", timeout, "TIMEOUT"), ("other", RuntimeError, "CONNECTION_FAILED")]
        for label, exc, code in rows:
            with self.subTest(case=label), mock.patch.object(ceos.nsot_live, "get_live_target", return_value={"platform": "ceos", "address": "192.0.2.9", "username": "u", "password": SECRET}), \
                    mock.patch("netmiko.ConnectHandler", side_effect=exc(f"could not log in with {SECRET}")), \
                    mock.patch("netmiko.exceptions.NetmikoAuthenticationException", auth), mock.patch("netmiko.exceptions.NetmikoTimeoutException", timeout):
                with self.assertRaises(ExecutorError) as raised:
                    ceos.netmiko_connection(self.device)
                self.assertEqual(raised.exception.code, code)
                self.assertNotIn(SECRET, str(raised.exception) + repr(raised.exception.args))
        with mock.patch.object(ceos.nsot_live, "get_live_target", return_value=None), self.assertRaises(ExecutorError) as raised:
            ceos.netmiko_connection(self.device)
        self.assertEqual(raised.exception.code, "NOT_CONFIGURED")

    def test_connection_tries_per_device_identity_then_rollback_identity(self):
        conn = mock.MagicMock()
        conn.check_enable_mode.return_value = True
        target = {
            "platform": "ceos", "address": "192.0.2.9", "username": "nmas-automation", "password": "primary",
            "auth_candidates": (
                {"username": "nmas-automation", "password": "primary", "ssh_auth": {}},
                {"username": "admin", "password": "rollback", "ssh_auth": {}},
            ),
        }
        auth = type("NetmikoAuthenticationException", (Exception,), {})
        with mock.patch.object(ceos.nsot_live, "get_live_target", return_value=target), \
                mock.patch("netmiko.ConnectHandler", side_effect=[auth("fixture failure"), conn]) as connect, \
                mock.patch("netmiko.exceptions.NetmikoAuthenticationException", auth):
            self.assertIs(ceos.netmiko_connection(self.device), conn)
        self.assertEqual([call.kwargs["username"] for call in connect.call_args_list], ["nmas-automation", "admin"])

    def test_inverse_is_exact_and_only_provable_for_additive_configlets(self):
        self.assertEqual(ceos.inverse_lines(self.spec("R1", "address")), ["interface Ethernet1", "   no ip address 192.0.2.0/31"])
        self.assertEqual(ceos.inverse_lines(self.spec("R1", "static_route")), ["no ip route 10.9.0.0/24 192.0.2.1"])
        interface = self.spec("R1", "interface")
        self.assertEqual(ceos.inverse_lines(interface), ["no interface Ethernet1"])
        odd = ConfigletSpec(**{**interface.__dict__, "lines": ("vlan 10", "interface Vlan10", "   mtu 1500")})
        self.assertIsNone(ceos.inverse_lines(odd), "a Configlet that also creates a VLAN cannot be proven restored by the read groups")
        self.assertIsNone(ceos.inverse_lines(ConfigletSpec(**{**interface.__dict__, "object_type": "routing_ospf"})))

    def test_assess_and_compensate_follow_the_captured_state_and_verify_by_read_back(self):
        spec = self.spec("R1", "address")
        empty, present = ev(interfaces={"Ethernet1": {"admin": "UP", "oper": "UP"}}), ev(interfaces={"Ethernet1": {"admin": "UP", "oper": "UP"}}, addresses={"Ethernet1": ["192.0.2.0/31"]})
        # assessment: addition on an empty interface is additive; an existing primary would be REPLACED (not provable); present = satisfied
        self.assertEqual((self.executor(reader=reader_for(empty)).assess(spec).action, self.executor(reader=reader_for(empty)).assess(spec).restorable), (APPLY, True))
        replaced = ev(interfaces={"Ethernet1": {"admin": "UP", "oper": "UP"}}, addresses={"Ethernet1": ["198.51.100.1/24"]})
        self.assertFalse(self.executor(reader=reader_for(replaced)).assess(spec).restorable)
        self.assertEqual(self.executor(reader=reader_for(present)).assess(spec).action, SKIP_SATISFIED)
        assessment = self.executor(reader=reader_for(empty)).assess(spec)
        # compensation rows: (label, reads seen by the executor, expected status, commands sent)
        rows = [
            ("nothing left to undo", [empty], "COMPENSATED", 0),
            ("undone and verified", [present, empty], "COMPENSATED", 1),
            ("commands accepted but state not restored", [present, present], "COMPENSATION_FAILED", 1),
            ("cannot read back", [present, ev(reachable=False)], "COMPENSATION_UNVERIFIED", 1),
        ]
        for label, reads, status, sent in rows:
            with self.subTest(case=label):
                conn = FakeConnection()
                outcome = self.executor(conn, reader_for(*reads)).compensate(spec, assessment)
                self.assertEqual(outcome.status, status)
                self.assertEqual(len(conn.sent), sent)
                if sent:
                    self.assertEqual(conn.sent[0], ["interface Ethernet1", "no ip address 192.0.2.0/31", "exit"])


class LinuxExecutorTests(RealSpecs):
    device = {"name": "R3", "platform": "linux", "container": "clab-lab-R3"}

    def runner(self, *, fail_on=None, raises=None):
        calls = []

        def run(container, argv, timeout):
            calls.append((container, list(argv)))
            if raises:
                raise raises
            return 1 if (fail_on and argv[:3] == fail_on) else 0

        run.calls = calls
        return run

    def executor(self, runner, reader=None):
        return linux.LinuxExecutor(self.device, runner=runner, reader=reader or reader_for(ev()))

    def test_real_rendered_lines_parse_and_become_validated_argv_lists(self):
        interface, address = self.spec("R3", "interface"), self.spec("R3", "address")
        self.assertIsNotNone(linux.parse_lines(interface.lines), interface.lines)
        self.assertIsNotNone(linux.parse_lines(address.lines), address.lines)
        runner = self.runner()
        outcome = self.executor(runner).apply(address, mock.Mock())
        self.assertTrue(outcome.ok)
        self.assertEqual(runner.calls, [("clab-lab-R3", ["ip", "addr", "replace", "192.0.2.4/31", "dev", "eth1"])])
        for _container, argv in runner.calls:
            self.assertIsInstance(argv, list)
            self.assertTrue(all(isinstance(token, str) and token.isascii() and not any(ch in token for ch in ";&|`$<>() \\n") for token in argv))

    def test_any_line_outside_the_strict_grammar_refuses_the_configlet(self):
        hostile = [
            "ip addr replace 10.0.0.1/24 dev eth1; rm -rf /", "ip addr replace 10.0.0.1/24 dev eth1 && reboot", "ip addr replace $(id)/24 dev eth1",
            "ip link set dev eth1 up `reboot`", "ip link show dev eth1 >/dev/null 2>&1 || ip link add link eth1 name eth2 type vlan id 5",
            "ip link show dev a >/dev/null 2>&1 || ip link add b type bridge", "vtysh -c 'configure terminal'", "nft flush ruleset",
            "table ip DEVICE_BUILDER_PAT {", "router ospf", "curl http://x | sh", "ip route replace default via 10.0.0.1",
        ]
        for line in hostile:
            with self.subTest(line=line):
                self.assertIsNone(linux.parse_lines(["ip link set dev eth1 up", line]), "ONE bad line refuses the whole Configlet")
        spec = ConfigletSpec(**{**self.spec("R3", "address").__dict__, "lines": ("ip addr replace 10.0.0.1/24 dev eth1; reboot",)})
        self.assertEqual(self.executor(self.runner()).assess(spec).action, REFUSE)
        runner = self.runner()
        self.assertFalse(self.executor(runner).apply(spec, mock.Mock()).ok)
        self.assertEqual(runner.calls, [], "nothing is ever executed for a refused Configlet")

    def test_guarded_create_only_adds_when_the_interface_is_absent_and_failures_are_coded(self):
        vlan = ConfigletSpec("CFG-1", 1, "R3", "ubuntu_frr", "interface", "CREATE_DEFINE",
                             ("ip link show dev eth1.100 >/dev/null 2>&1 || ip link add link eth1 name eth1.100 type vlan id 100", "ip link set dev eth1.100 up"),
                             {"interface": "eth1.100"})
        runner = self.runner()  # `ip link show` exits 0 => the interface exists => the add is skipped
        self.assertTrue(self.executor(runner).apply(vlan, mock.Mock()).ok)
        self.assertEqual([argv[:3] for _c, argv in runner.calls], [["ip", "link", "show"], ["ip", "link", "set"]])
        runner = self.runner(fail_on=["ip", "link", "show"])  # absent => the add runs
        self.assertTrue(self.executor(runner).apply(vlan, mock.Mock()).ok)
        self.assertIn(["ip", "link", "add", "link", "eth1", "name", "eth1.100", "type", "vlan", "id", "100"], [argv for _c, argv in runner.calls])
        rejected = self.executor(self.runner(fail_on=["ip", "link", "set"])).apply(vlan, mock.Mock())
        self.assertEqual((rejected.ok, rejected.error_code), (False, "COMMAND_REJECTED"))
        missing = self.executor(self.runner(raises=ExecutorError("DOCKER_UNAVAILABLE"))).apply(vlan, mock.Mock())
        self.assertEqual((missing.ok, missing.error_code), (False, "DOCKER_UNAVAILABLE"))

    def test_guarded_dummy_loopback_is_strictly_parsed_created_and_invertible(self):
        loopback = ConfigletSpec(
            "CFG-LB", 1, "R3", "ubuntu_frr", "interface", "CREATE_DEFINE",
            ("ip link show dev loopback44 >/dev/null 2>&1 || ip link add loopback44 type dummy",
             "ip link set dev loopback44 mtu 1500", "ip link set dev loopback44 up"),
            {"interface": "loopback44"},
        )
        runner = self.runner(fail_on=["ip", "link", "show"])
        outcome = self.executor(runner).apply(loopback, mock.Mock())
        self.assertTrue(outcome.ok)
        self.assertIn(
            ["ip", "link", "add", "loopback44", "type", "dummy"],
            [argv for _container, argv in runner.calls],
        )
        self.assertEqual(linux.inverse_operations(loopback), [["ip", "link", "delete", "loopback44"]])
        mismatched = ("ip link show dev loopback44 >/dev/null 2>&1 || ip link add other type dummy",)
        self.assertIsNone(linux.parse_lines(mismatched))

    def test_docker_run_is_the_only_spawn_a_list_with_shell_false(self):
        with mock.patch.object(linux.subprocess, "run", return_value=subprocess.CompletedProcess([], 0)) as spawned:
            linux.docker_run("clab-lab-R3", ["ip", "link", "set", "dev", "eth1", "up"], 5)
        args, kwargs = spawned.call_args
        self.assertEqual(args[0], ["docker", "exec", "clab-lab-R3", "ip", "link", "set", "dev", "eth1", "up"])
        self.assertIs(kwargs["shell"], False)
        with mock.patch.object(linux.subprocess, "run", side_effect=FileNotFoundError), self.assertRaises(ExecutorError) as raised:
            linux.docker_run("c", ["ip"], 1)
        self.assertEqual(raised.exception.code, "DOCKER_UNAVAILABLE")
        with mock.patch.object(linux.subprocess, "run", side_effect=subprocess.TimeoutExpired("docker", 1)), self.assertRaises(ExecutorError) as raised:
            linux.docker_run("c", ["ip"], 1)
        self.assertEqual(raised.exception.code, "TIMEOUT")

    def test_compensation_is_an_exact_inverse_verified_by_read_back(self):
        address = self.spec("R3", "address")
        absent = ev(interfaces={"eth1": {"admin": "UP", "oper": "UP"}}, addresses={"eth1": []})
        present = ev(interfaces={"eth1": {"admin": "UP", "oper": "UP"}}, addresses={"eth1": ["192.0.2.4/31"]})
        assessment = self.executor(self.runner(), reader_for(absent)).assess(address)
        self.assertEqual((assessment.action, assessment.restorable), (APPLY, True))
        runner = self.runner()
        outcome = self.executor(runner, reader_for(present, absent)).compensate(address, assessment)
        self.assertEqual(outcome.status, "COMPENSATED")
        self.assertEqual(runner.calls, [("clab-lab-R3", ["ip", "addr", "del", "192.0.2.4/31", "dev", "eth1"])])
        self.assertEqual(self.executor(self.runner(), reader_for(present, present)).compensate(address, assessment).error_code, "STATE_NOT_RESTORED")
        self.assertEqual(linux.inverse_operations(self.spec("R3", "interface")), [["ip", "link", "delete", "eth1"]])


class CapabilityAndStateModelTests(SimpleTestCase):
    def test_linux_static_route_grammar_and_exact_inverse(self):
        for line, command in (
            ("ip route 203.0.113.0/24 198.18.0.2 200", "no ip route 203.0.113.0/24 198.18.0.2 200"),
            ("ipv6 route 2001:db8:113::/64 2001:db8:44::2 200", "no ipv6 route 2001:db8:113::/64 2001:db8:44::2 200"),
        ):
            with self.subTest(line=line):
                spec = ConfigletSpec("TEST", 1, "R3", "ubuntu_frr", "static_route", "CREATE_DEFINE",
                                     (line,), {"prefix": line.split()[2], "next_hop": line.split()[3]})
                self.assertEqual(linux.parse_lines(spec.lines)[0]["kind"], "route")
                self.assertEqual(linux.inverse_operations(spec),
                                 [["vtysh", "-c", "configure terminal", "-c", command]])
        for unsafe in ("ip route 203.0.113.0/24 2001:db8::1", "ip route 203.0.113.1/24 198.18.0.2",
                       "ip route 203.0.113.0/24 198.18.0.2 999", "ip route 203.0.113.0/24 198.18.0.2; id"):
            with self.subTest(unsafe=unsafe):
                self.assertIsNone(linux.parse_lines((unsafe,)))

    def test_capability_is_evidence_based_per_platform_and_object_type(self):
        S, N, K = "SUPPORTED", "NOT_IMPLEMENTED", "UNKNOWN"
        rows = [
            ("arista_ceos", "address", S, S), ("arista_ceos", "static_route", S, S), ("arista_ceos", "interface", S, S),
            ("arista_ceos", "routing_ospf", S, S), ("arista_ceos", "bgp_neighbor", S, S), ("arista_ceos", "acl_attachment", S, S),
            ("arista_ceos", "device_identity", N, N), ("arista_ceos", "nat_rule", N, N),
            ("ubuntu_frr", "address", S, S), ("ubuntu_frr", "interface", S, S), ("ubuntu_frr", "static_route", S, S),
            ("ubuntu_frr", "routing_ospf", S, S), ("ubuntu_frr", "nat_rule", S, S), ("ubuntu_frr", "routing_bgp", S, S), ("ubuntu_frr", "routing_rip", S, S), ("ubuntu_frr", "nat_pool", N, N),
            ("nokia_srlinux", "interface", S, S), ("nokia_srlinux", "address", S, S), ("nokia_srlinux", "static_route", S, S),
            ("nokia_srlinux", "routing_bgp", N, N), ("nokia_srlinux", "acl", N, N), ("cisco_c8000v_iosxe", "interface", S, S), ("cisco_c8000v_iosxe", "address", S, S),
            ("cisco_c8000v_iosxe", "static_route", S, S), ("cisco_c8000v_iosxe", "routing_ospf", N, N),
            ("cisco_iosxr", "interface", N, N), ("sonic", "address", N, N), ("mystery", "interface", K, K),
        ]
        for platform, kind, apply_status, compensation in rows:
            with self.subTest(platform=platform, object_type=kind):
                cap = capability.capability_for(platform, kind)
                self.assertEqual((cap.apply, cap.compensation), (apply_status, compensation))
        self.assertEqual({r["platform"] for r in capability.capability_matrix()}, set(capability.PLATFORM_EVIDENCE))

    def test_registry_selects_by_platform_and_refuses_unsupported_platforms(self):
        self.assertIsInstance(registry.executor_for({"name": "R1", "platform": "ceos"}), ceos.CeosExecutor)
        self.assertIsInstance(registry.executor_for({"name": "R3", "platform": "linux", "container": "c"}), linux.LinuxExecutor)
        self.assertIsInstance(registry.executor_for({"name": "SRL1", "platform": "nokia_srlinux"}), srlinux.SrLinuxExecutor)
        self.assertIsInstance(registry.executor_for({"name": "XE1", "platform": "cisco_c8000v_iosxe"}), iosxe.IosXeExecutor)
        for platform in ("cisco_iosxr", "sonic", "nonsense"):      # IOS XR never inherits the IOS XE executor
            with self.subTest(platform=platform), self.assertRaises(ExecutorError) as raised:
                registry.executor_for({"name": "X", "platform": platform})
            self.assertEqual(raised.exception.code, "UNSUPPORTED")
        self.assertEqual(sorted(registry.EXECUTORS), ["ceos", "cisco_c8000v_iosxe", "linux", "nokia_srlinux"])

    def test_state_model_decisions(self):
        def spec(kind, **expected):
            return ConfigletSpec("CFG-1", 1, "R1", "arista_ceos", kind, "CREATE_DEFINE", ("x",), expected)

        iface = {"Ethernet1": {"admin": "UP", "oper": "UP"}}
        rows = [
            ("new interface is additive", spec("interface", interface="Loopback9"), ev(interfaces=iface), True, (APPLY, True)),
            ("existing interface is not exactly restorable", spec("interface", interface="Ethernet1"), ev(interfaces=iface), True, (APPLY, False)),
            ("address on an empty interface", spec("address", interface="Ethernet1", address="192.0.2.0/31"), ev(interfaces=iface), True, (APPLY, True)),
            ("address already present", spec("address", interface="Ethernet1", address="192.0.2.0/31"), ev(iface, {"Ethernet1": ["192.0.2.0/31"]}), True, (SKIP_SATISFIED, True)),
            ("IPv6 address is always additive", spec("address", interface="Ethernet1", address="2001:db8::1/64"), ev(iface, {"Ethernet1": ["192.0.2.0/31"]}), True, (APPLY, True)),
            ("route already present", spec("static_route", prefix="10.9.0.0/24", next_hop="192.0.2.1"), ev(routes=[{"prefix": "10.9.0.0/24", "type": "static", "next_hops": ["192.0.2.1"], "interfaces": []}]), True, (SKIP_SATISFIED, True)),
            ("same prefix learned dynamically is not a static route", spec("static_route", prefix="10.9.0.0/24", next_hop="192.0.2.1"), ev(routes=[{"prefix": "10.9.0.0/24", "type": "ospf", "next_hops": ["192.0.2.1"], "interfaces": []}]), True, (APPLY, True)),
            ("an unmodelled type proves nothing", spec("routing_ospf"), ev(), True, (APPLY, False)),
            ("unreadable evidence refuses", spec("address", interface="Ethernet1", address="192.0.2.0/31"), h.device_evidence("R1", interfaces=None, addresses=None), True, (REFUSE, False)),
        ]
        for label, s, evidence, overwrites, (action, restorable) in rows:
            with self.subTest(case=label):
                found = state.assess(s, evidence, additive_overwrites_primary=overwrites)
                self.assertEqual((found.action, found.restorable), (action, restorable))
        self.assertFalse(state.assess(spec("address", interface="Ethernet1", address="192.0.2.0/31"), ev(iface, {"Ethernet1": ["198.51.100.1/24"]}), additive_overwrites_primary=True).restorable)
        self.assertTrue(state.assess(spec("address", interface="Ethernet1", address="192.0.2.0/31"), ev(iface, {"Ethernet1": ["198.51.100.1/24"]}), additive_overwrites_primary=False).restorable)

    def test_the_only_engine_entry_point_is_execute_change(self):
        self.assertEqual(list(inspect.signature(es.execute_change).parameters)[:2], ["change", "actor"])
        self.assertNotIn("command", inspect.signature(es.execute_change).parameters)
        self.assertNotIn("rendered_config", inspect.signature(es.execute_change).parameters)
