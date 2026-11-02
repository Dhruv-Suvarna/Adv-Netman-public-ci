"""Lab 7 -- Ubuntu/FRR (Linux) executor: the device-read helpers, NAT helpers and connect / compensate, positive + negative.

This executor is a device-write path, so every negative case proves it FAILS CLOSED: an unreachable container, a timeout,
a non-zero exit, unparsable output or a foreign nftables shape becomes ``ExecutorError("PREVIOUS_STATE_UNAVAILABLE")``,
``None`` / ``False`` or an unverified compensation -- never a guessed state.

No process is ever spawned: ``subprocess.run`` is replaced in every test, and no device, container or lab is contacted.
"""

from __future__ import annotations

import json
import subprocess
from types import SimpleNamespace
from unittest import mock

from django.test import SimpleTestCase

from core.services.execution.executors import linux
from core.services.execution.executors.base import Assessment, ConfigletSpec, ExecutorError

RUN = "core.services.execution.executors.linux.subprocess.run"
NAT_LINES = ['table ip NMAS_NAT {', ' chain postrouting {', '  type nat hook postrouting priority srcnat; policy accept;',
             '  oifname "eth0" ip saddr 10.0.0.0/24 masquerade', ' }', '}']
LINKS = [{"ifname": "eth1", "mtu": 1500, "flags": ["BROADCAST", "UP"], "addr_info": [{"local": "192.0.2.4", "prefixlen": 31}]}]


def done(stdout="", returncode=0):
    return subprocess.CompletedProcess(["docker"], returncode, stdout=stdout, stderr="")


class DockerReadTests(SimpleTestCase):
    def test_docker_exec_returns_the_completed_process_of_a_list_argv(self):
        with mock.patch(RUN, return_value=done("ok")) as run:
            self.assertEqual(linux.docker_exec("clab-R3", ["ip", "-j", "addr", "show"], 5).stdout, "ok")
        argv = run.call_args.args[0]
        self.assertEqual(argv, ["docker", "exec", "clab-R3", "ip", "-j", "addr", "show"])
        self.assertEqual((run.call_args.kwargs["shell"], run.call_args.kwargs["timeout"]), (False, 5))

    def test_docker_exec_raises_when_docker_cannot_start(self):
        with mock.patch(RUN, side_effect=OSError("no docker")), self.assertRaises(OSError):
            linux.docker_exec("clab-R3", ["true"], 5)

    def test_read_frr_daemons_returns_the_answering_daemons(self):
        with mock.patch(RUN, return_value=done("zebra ospfd staticd\n")):
            self.assertEqual(linux.read_frr_daemons("c", 5), {"zebra", "ospfd", "staticd"})

    def test_read_frr_daemons_fails_closed_or_empty_when_vtysh_is_unavailable(self):
        with mock.patch(RUN, side_effect=subprocess.TimeoutExpired("docker", 5)), self.assertRaises(ExecutorError) as caught:
            linux.read_frr_daemons("c", 5)
        self.assertEqual(caught.exception.code, "PREVIOUS_STATE_UNAVAILABLE")
        with mock.patch(RUN, return_value=done("Failed to connect to any daemons.")):
            self.assertEqual(linux.read_frr_daemons("c", 5), set())
        with mock.patch(RUN, return_value=done("zebra", returncode=1)):
            self.assertEqual(linux.read_frr_daemons("c", 5), set())

    def test_read_frr_config_returns_the_running_configuration(self):
        with mock.patch(RUN, return_value=done("frr version 9\nrouter ospf\n")):
            self.assertIn("router ospf", linux.read_frr_config("c", 5))

    def test_read_frr_config_fails_closed_on_error_timeout_or_unreachable_daemons(self):
        for label, effect in (("timeout", subprocess.TimeoutExpired("docker", 5)), ("oserror", OSError("x")),
                              ("exit 1", done("", returncode=1)), ("daemons unreachable", done("failed to connect to any daemons"))):
            with self.subTest(case=f"invalid {label}"):
                patch = mock.patch(RUN, side_effect=effect) if isinstance(effect, BaseException) else mock.patch(RUN, return_value=effect)
                with patch, self.assertRaises(ExecutorError) as caught:
                    linux.read_frr_config("c", 5)
                self.assertEqual(caught.exception.code, "PREVIOUS_STATE_UNAVAILABLE")

    def test_read_nft_ruleset_returns_the_listed_ruleset(self):
        with mock.patch(RUN, return_value=done("\n".join(NAT_LINES))):
            self.assertTrue(linux.read_nft_ruleset("c", 5).startswith("table ip NMAS_NAT {"))

    def test_read_nft_ruleset_fails_closed_without_nft_or_permission(self):
        for label, effect in (("exit 1", done("", returncode=1)), ("timeout", subprocess.TimeoutExpired("docker", 5))):
            with self.subTest(case=f"invalid {label}"):
                patch = mock.patch(RUN, side_effect=effect) if isinstance(effect, BaseException) else mock.patch(RUN, return_value=effect)
                with patch, self.assertRaises(ExecutorError):
                    linux.read_nft_ruleset("c", 5)

    def test_read_links_returns_the_parsed_link_list(self):
        with mock.patch(RUN, return_value=done(json.dumps(LINKS))):
            self.assertEqual(linux.read_links("c", 5), LINKS)

    def test_read_links_fails_closed_on_malformed_or_unexpected_output(self):
        for label, result in (("malformed json", done("{not json")), ("object not list", done("{}")), ("exit 1", done("[]", returncode=1))):
            with self.subTest(case=f"invalid {label}"), mock.patch(RUN, return_value=result), self.assertRaises(ExecutorError) as caught:
                linux.read_links("c", 5)
            self.assertEqual(caught.exception.code, "PREVIOUS_STATE_UNAVAILABLE")


class StateDigestTests(SimpleTestCase):
    def test_link_state_returns_the_semantic_state_of_a_link(self):
        self.assertEqual(linux.link_state(LINKS, "eth1"), {"mtu": 1500, "up": True, "master": "", "addresses": ["192.0.2.4/31"]})

    def test_link_state_of_an_unknown_link_is_none(self):
        self.assertIsNone(linux.link_state(LINKS, "eth9"))
        self.assertIsNone(linux.link_state([], "eth1"))

    def test_frr_config_digest_ignores_comments_and_headers(self):
        a = "Building configuration...\nCurrent configuration:\n!\nrouter ospf\n ospf router-id 1.1.1.1\nend\n"
        b = "router ospf\n  ospf router-id 1.1.1.1  \n"
        self.assertEqual(linux.frr_config_digest(a), linux.frr_config_digest(b))

    def test_frr_config_digest_mismatch_for_a_different_configuration(self):
        self.assertNotEqual(linux.frr_config_digest("router ospf\n"), linux.frr_config_digest("router rip\n"))

    def test_nft_digest_ignores_volatile_counters(self):
        self.assertEqual(linux.nft_digest("rule counter packets 5 bytes 300\n"), linux.nft_digest("  rule counter packets 9 bytes 1\n"))

    def test_nft_digest_mismatch_for_a_different_rule(self):
        self.assertNotEqual(linux.nft_digest("oifname eth0 masquerade"), linux.nft_digest("oifname eth1 masquerade"))


class NatHelperTests(SimpleTestCase):
    def test_nat_statement_round_trips_through_the_strict_parser(self):
        nat = linux.parse_nat_table(NAT_LINES)
        self.assertEqual(linux.parse_nat_table(linux.nat_statement(nat).splitlines()), nat)

    def test_nat_statement_refuses_a_malformed_nat_mapping(self):
        with self.assertRaises(KeyError):
            linux.nat_statement({"rules": []})
        with self.assertRaises(ValueError):
            linux.nat_statement({"table": "T", "rules": [("eth0", "10.0.0.0/24")]})

    def test_nat_rule_tokens_returns_the_nft_tokens(self):
        self.assertEqual(linux.nat_rule_tokens(("eth0", "10.0.0.0/24", 'comment "nmas-nat44-stateful"')),
                         ["oifname", '"eth0"', "ip", "saddr", "10.0.0.0/24", "masquerade", "comment", '"nmas-nat44-stateful"'])

    def test_nat_rule_tokens_refuses_a_malformed_rule(self):
        with self.assertRaises(ValueError):
            linux.nat_rule_tokens(("eth0", "10.0.0.0/24"))

    def test_nat_rule_conflict_accepts_disjoint_or_identical_rules(self):
        rule = ("eth0", "10.0.0.0/24", "")
        self.assertFalse(linux.nat_rule_conflict([rule], [rule]))
        self.assertFalse(linux.nat_rule_conflict([rule], [("eth1", "10.0.1.0/24", "")]))

    def test_nat_rule_conflict_detects_a_conflicting_rule(self):
        self.assertTrue(linux.nat_rule_conflict([("eth0", "10.0.0.0/24", "")], [("eth0", "10.0.0.0/24", 'comment "nmas-nat44-stateful"')]))

    def test_nat_table_rules_returns_the_rules_of_the_nmas_table(self):
        ruleset = "table ip filter {\n}\n" + "\n".join(NAT_LINES) + "\n"
        self.assertEqual(linux.nat_table_rules(ruleset, "NMAS_NAT"), [("eth0", "10.0.0.0/24", "")])

    def test_nat_table_rules_absent_table_is_none_and_foreign_shape_is_false(self):
        self.assertIsNone(linux.nat_table_rules("table ip filter {\n}\n", "NMAS_NAT"))
        foreign = "table ip NMAS_NAT {\n chain postrouting {\n  type filter hook forward priority 0;\n  accept\n }\n}\n"
        self.assertIs(linux.nat_table_rules(foreign, "NMAS_NAT"), False)


class LinuxExecutorBoundaryTests(SimpleTestCase):
    device = {"name": "R3", "platform": "linux", "container": "clab-lab-R3"}

    def test_connect_accepts_a_configured_reachable_container(self):
        reader = mock.Mock(return_value=SimpleNamespace(live_reachable=True))
        linux.LinuxExecutor(self.device, runner=mock.Mock(), reader=reader).connect()
        reader.assert_called_once_with(self.device)

    def test_compensate_of_an_unreadable_device_is_unverified_and_never_sends_a_command(self):
        runner = mock.Mock(return_value=0)
        executor = linux.LinuxExecutor(self.device, runner=runner, reader=mock.Mock(return_value=SimpleNamespace(live_reachable=False)))
        spec = ConfigletSpec("CFG-1", 1, "R3", "ubuntu_frr", "address", "CREATE_DEFINE", ("ip addr replace 192.0.2.4/31 dev eth1",),
                             {"interface": "eth1", "address": "192.0.2.4/31"})
        outcome = executor.compensate(spec, Assessment("APPLY", True, {"kind": "address"}))
        self.assertEqual((outcome.status, outcome.error_code), ("COMPENSATION_UNVERIFIED", "PREVIOUS_STATE_UNAVAILABLE"))
        runner.assert_not_called()
