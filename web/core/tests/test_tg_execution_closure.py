"""Lab 7 closure -- device-write execution primitives, each public function called directly, positive + negative.

Every executor here runs against a fake session object (``send_command`` / ``send_config_set`` recorders) or a pure function:
no connection is opened, nothing is sent to a device.  The NEGATIVE cases prove the fail-closed contract of the write path:
an inverse that cannot be proven is ``None`` (the caller refuses to apply), a rejected or failed command is a fixed error
code with ``partial_effects`` where a change may remain, an unreadable previous state raises ``ExecutorError`` and a
compensation that cannot prove the restored state is never reported COMPENSATED.
"""

from __future__ import annotations

from datetime import timedelta
from types import SimpleNamespace
from unittest import mock

from django.test import SimpleTestCase, TestCase, override_settings
from django.utils import timezone

from core import models
from core.services.execution import codes, locking
from core.services.execution.codes import Outcome, Status
from core.services.execution.executors import ceos, frr_routing as frr, iosxe, srlinux
from core.services.execution.executors.base import ConfigletSpec, ExecutorError
from core.services.execution.writers import srlinux_gnmi
from core.services.raw_configlets import adapters, sandbox, text as raw_text
from core.services.execution.scope import resolve_scope
from core.tests.helpers import execution as x


def spec(lines, *, object_type="interface", platform="arista_ceos", cfg_id="CFG-1") -> ConfigletSpec:
    return ConfigletSpec(cfg_id, 1, "DUT", platform, object_type, "CREATE_DEFINE", tuple(lines), {})


class FakeSession:
    """A recorder standing in for a Netmiko / gNMI session: scripted answers, every call kept, nothing sent anywhere."""

    def __init__(self, answers=None, *, fail=None):
        self.answers, self.fail, self.calls, self.disconnected = dict(answers or {}), fail, [], 0

    def send_command(self, command, **_kwargs):
        self.calls.append(command)
        if self.fail is not None:
            raise self.fail
        return self.answers.get(command, "")

    def send_config_set(self, lines, **_kwargs):
        self.calls.append(tuple(lines))
        if self.fail is not None:
            raise self.fail
        return self.answers.get("config", "")

    def disconnect(self):
        self.disconnected += 1
        if self.fail is not None:
            raise self.fail


# -- execution codes ------------------------------------------------------------------------------------------------------
class ExecutionCodesTests(SimpleTestCase):
    def test_blocker_returns_message_remediation_and_details(self):
        code = sorted(codes.BLOCKERS)[0]
        message, remediation = codes.BLOCKERS[code]
        self.assertEqual(codes.blocker(code), {"code": code, "message": message, "remediation": remediation})
        self.assertEqual(codes.blocker(code, device="R1")["details"], {"device": "R1"})

    def test_blocker_refuses_an_unknown_code(self):
        with self.assertRaises(KeyError):
            codes.blocker("NOT_A_REAL_BLOCKER")

    def test_error_message_returns_the_category_text(self):
        code = next(c for c in codes.ERROR_CATEGORIES if c != "INTERNAL_ERROR")
        self.assertEqual(codes.error_message(code), codes.ERROR_CATEGORIES[code])

    def test_error_message_for_an_unknown_code_is_the_internal_error_text_never_the_raw_code(self):
        self.assertEqual(codes.error_message("SOMETHING_ELSE <script>"), codes.ERROR_CATEGORIES["INTERNAL_ERROR"])

    def test_timing_settings_default_values(self):
        self.assertEqual((codes.precheck_max_age_seconds(), codes.lease_seconds(), codes.settle_timeout_seconds(),
                          codes.settle_interval_seconds(), codes.device_timeout_seconds()), (900.0, 1800.0, 30.0, 3.0, 20.0))

    @override_settings(EXECUTION_PRECHECK_MAX_AGE_SECONDS=60, EXECUTION_LEASE_SECONDS="120", EXECUTION_SETTLE_TIMEOUT_SECONDS=5,
                       EXECUTION_SETTLE_INTERVAL_SECONDS=1, EXECUTION_DEVICE_TIMEOUT_SECONDS=7)
    def test_timing_settings_follow_configuration_as_floats(self):
        self.assertEqual((codes.precheck_max_age_seconds(), codes.lease_seconds(), codes.settle_timeout_seconds(),
                          codes.settle_interval_seconds(), codes.device_timeout_seconds()), (60.0, 120.0, 5.0, 1.0, 7.0))


# -- locking: lease reaping / heartbeat --------------------------------------------------------------------------------------
class LockingLeaseTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.p = x.prepared()

    def _run(self):
        scope, _ = resolve_scope(self.p.plan, "COMPLETE")
        return locking.acquire(change=self.p.change, plan=self.p.plan, precheck_run=self.p.precheck, mode="COMPLETE", actor="tester",
                               scope=scope, devices=scope.devices)

    def test_lock_exception_carries_code_and_details(self):
        refused = locking.LockRefused("DEVICE_LOCKED", device="R1")
        self.assertEqual((str(refused), refused.code, refused.details), ("DEVICE_LOCKED", "DEVICE_LOCKED", {"device": "R1"}))

    def test_lock_refused_without_details_has_an_empty_mapping(self):
        self.assertEqual(locking.LockRefused("BUSY").details, {})

    def test_reap_expired_interrupts_an_abandoned_run_and_frees_its_locks(self):
        run = self._run()
        self.assertTrue(run.device_locks.exists())
        later = run.lease_expires_at + timedelta(seconds=1)
        self.assertEqual(locking.reap_expired(now=later), [str(run.run_id)])
        run.refresh_from_db()
        self.assertEqual((run.state, run.outcome, run.report["interrupted"]), (models.ExecutionRunState.FINISHED, Outcome.INTERRUPTED,
                                                                                {"reason": "LEASE_EXPIRED"}))
        self.assertFalse(run.device_locks.exists())
        self.assertTrue(models.AuditEvent.objects.filter(object_id=str(run.run_id), metadata__reason="LEASE_EXPIRED").exists())

    def test_reap_expired_never_touches_a_run_whose_lease_is_still_valid(self):
        run = self._run()
        self.assertEqual(locking.reap_expired(now=run.lease_expires_at - timedelta(seconds=1)), [])
        run.refresh_from_db()
        self.assertEqual(run.state, models.ExecutionRunState.RUNNING)
        self.assertTrue(run.device_locks.exists())

    def test_heartbeat_extends_the_lease_of_a_running_run(self):
        run = self._run()
        now = timezone.now() + timedelta(hours=1)
        locking.heartbeat(run, now=now)
        run.refresh_from_db()
        self.assertEqual(run.lease_expires_at, now + timedelta(seconds=codes.lease_seconds()))

    def test_heartbeat_never_revives_a_finished_run(self):
        run = self._run()
        locking.reap_expired(now=run.lease_expires_at + timedelta(seconds=1))
        run.refresh_from_db()
        before = run.lease_expires_at
        locking.heartbeat(run, now=timezone.now() + timedelta(days=1))
        run.refresh_from_db()
        self.assertEqual((run.lease_expires_at, run.state), (before, models.ExecutionRunState.FINISHED))


# -- cEOS executor ---------------------------------------------------------------------------------------------------------
class CeosInverseTests(SimpleTestCase):
    def test_inverse_of_a_new_interface_static_route_and_address(self):
        self.assertEqual(ceos.inverse_lines(spec(["interface Loopback44", "   description x"])), ["no interface Loopback44"])
        self.assertEqual(ceos.inverse_lines(spec(["ip route 198.51.100.0/24 192.0.2.1"], object_type="static_route")),
                         ["no ip route 198.51.100.0/24 192.0.2.1"])
        self.assertEqual(ceos.inverse_lines(spec(["interface Ethernet3", "   ip address 192.0.2.1/31"], object_type="address")),
                         ["interface Ethernet3", "   no ip address 192.0.2.1/31"])

    def test_inverse_is_none_when_no_exact_inverse_is_provable(self):
        for label, lines, kind in (("empty configlet", [], "interface"), ("two top-level headers", ["vlan 44", "interface Vlan44"], "interface"),
                                   ("not an interface header", ["router ospf 1"], "interface"),
                                   ("static route with children", ["ip route 1.0.0.0/8 2.2.2.2", "   x"], "static_route"),
                                   ("address leaf not indented", ["interface Ethernet3", "ip address 1.1.1.1/31"], "address"),
                                   ("unsupported object type", ["hostname X"], "hostname")):
            with self.subTest(case=f"invalid {label}"):
                self.assertIsNone(ceos.inverse_lines(spec(lines, object_type=kind)))


class CeosExecutorSessionTests(SimpleTestCase):
    def executor(self, session):
        executor = ceos.CeosExecutor({"name": "S1"}, connection_factory=lambda device: session, reader=lambda device: None)
        executor.connect()
        return executor

    def test_close_disconnects_once_and_forgets_the_session(self):
        session = FakeSession()
        executor = self.executor(session)
        executor.close()
        executor.close()
        self.assertEqual((session.disconnected, executor._conn), (1, None))

    def test_close_swallows_a_failing_disconnect(self):
        executor = self.executor(FakeSession(fail=OSError("gone")))
        executor.close()
        self.assertIsNone(executor._conn)

    def test_running_and_state_digests_ignore_comment_lines(self):
        session = FakeSession({"show running-config": "! Command: show running-config\nhostname S1\n!\ninterface Ethernet1\n"})
        executor = self.executor(session)
        from core.services.bundles import canonical

        self.assertEqual(len(executor.running_config_digest()), 64)
        self.assertEqual(executor.config_state_digest(), executor.config_state_digest())
        self.assertNotEqual(executor.config_state_digest(), canonical.text_hash("hostname S2"))

    def test_startup_config_text_and_digest_match_a_running_configuration_with_the_same_state(self):
        text = "hostname S1\ninterface Ethernet1\n   description up\n"
        executor = self.executor(FakeSession({"show running-config": "! running\n" + text, "show startup-config": "! startup\n" + text}))
        self.assertEqual(executor.startup_config_text().strip(), text.strip())
        self.assertEqual(executor.startup_state_digest(), executor.config_state_digest())

    def test_startup_config_unreadable_raises_previous_state_unavailable(self):
        executor = self.executor(FakeSession(fail=TimeoutError("read timeout")))
        with self.assertRaises(ExecutorError) as caught:
            executor.startup_config_text()
        self.assertEqual(caught.exception.code, "PREVIOUS_STATE_UNAVAILABLE")

    def test_save_startup_sends_exactly_the_persistence_command(self):
        session = FakeSession({"copy running-config startup-config": "Copy completed successfully."})
        outcome = self.executor(session).save_startup()
        self.assertEqual((outcome.ok, outcome.lines_sent, session.calls), (True, 1, ["copy running-config startup-config"]))

    def test_save_startup_rejected_or_failing_is_a_fixed_error_code_with_partial_effects(self):
        for label, session, code in (("rejected", FakeSession({"copy running-config startup-config": "% Error copying"}), "COMMAND_REJECTED"),
                                     ("timeout", FakeSession(fail=TimeoutError("x")), "TIMEOUT"),
                                     ("transport failure", FakeSession(fail=OSError("x")), "TRANSPORT_ERROR")):
            with self.subTest(case=f"failure {label}"):
                outcome = self.executor(session).save_startup()
                self.assertEqual((outcome.ok, outcome.error_code, outcome.partial_effects), (False, code, True))

    def test_neighbour_answers_when_two_echo_replies_arrive(self):
        session = FakeSession({"ping ipv6 2001:db8::2 interface Ethernet1 repeat 2": "2 packets transmitted, 2 received, 0% packet loss"})
        self.assertTrue(self.executor(session).neighbour_answers("2001:db8::2", "Ethernet1"))
        self.assertEqual(session.calls, ["ping ipv6 2001:db8::2 interface Ethernet1 repeat 2"])

    def test_neighbour_never_answers_for_invalid_input_or_a_failed_ping_and_sends_nothing_for_bad_input(self):
        for label, address, interface in (("invalid address", "not-an-ip", ""), ("ipv4 address", "192.0.2.1", ""),
                                          ("unsafe interface name", "2001:db8::2", "Eth1; reload")):
            with self.subTest(case=f"invalid {label}"):
                session = FakeSession()
                self.assertFalse(self.executor(session).neighbour_answers(address, interface))
                self.assertEqual(session.calls, [])
        self.assertFalse(self.executor(FakeSession({"ping ipv6 2001:db8::2 repeat 2": "2 packets transmitted, 0 received"})).neighbour_answers("2001:db8::2"))
        self.assertFalse(self.executor(FakeSession(fail=OSError("x"))).neighbour_answers("2001:db8::2"))


# -- IOS XE executor -------------------------------------------------------------------------------------------------------
TCP = "Conn  Local Address    Foreign Address  State\n0     10.0.0.1.22    10.0.0.9.51000   ESTAB\n"
RUNNING_XE = "interface GigabitEthernet1\n ip address 10.0.0.1 255.255.255.0\ninterface GigabitEthernet2\n ip address 10.9.9.1 255.255.255.0\n"


class IosXeSessionSafetyTests(SimpleTestCase):
    def test_session_interfaces_finds_the_interface_carrying_the_ssh_session(self):
        self.assertEqual(iosxe.session_interfaces(TCP, RUNNING_XE), {"interface gigabitethernet1"})

    def test_session_interfaces_without_an_established_session_is_empty(self):
        self.assertEqual(iosxe.session_interfaces("", RUNNING_XE), set())
        self.assertEqual(iosxe.session_interfaces(TCP.replace("ESTAB", "LISTEN"), RUNNING_XE), set())

    def test_endangers_session_false_for_an_unrelated_interface_or_a_secondary_address(self):
        protected = {"interface gigabitethernet1"}
        self.assertFalse(iosxe.endangers_session(["interface GigabitEthernet2", " shutdown"], protected))
        self.assertFalse(iosxe.endangers_session(["interface GigabitEthernet1", " ip address 10.1.1.1 255.255.255.0 secondary"], protected))

    def test_endangers_session_refuses_shutdown_readdressing_vrf_or_removal_of_the_session_interface(self):
        protected = {"interface gigabitethernet1"}
        for label, lines in (("shutdown", ["interface GigabitEthernet1", " shutdown"]),
                             ("no ip address", ["interface GigabitEthernet1", " no ip address"]),
                             ("primary readdress", ["interface GigabitEthernet1", " ip address 10.2.2.2 255.255.255.0"]),
                             ("vrf move", ["interface GigabitEthernet1", " vrf forwarding MGMT"]),
                             ("interface removal", ["no interface GigabitEthernet1"])):
            with self.subTest(case=f"refused {label}"):
                self.assertTrue(iosxe.endangers_session(lines, protected))


class IosXeExecutorTests(SimpleTestCase):
    def executor(self, session, *, protected=None):
        executor = iosxe.IosXeExecutor({"name": "R5"}, connection_factory=lambda device: session)
        executor._conn = session
        executor._session_interfaces = protected or set()
        return executor

    def test_close_disconnects_and_forgets_the_session(self):
        session = FakeSession()
        executor = self.executor(session)
        executor.close()
        self.assertEqual((session.disconnected, executor._conn), (1, None))

    def test_close_with_a_failing_disconnect_never_raises(self):
        executor = self.executor(FakeSession(fail=OSError("x")))
        executor.close()
        self.assertIsNone(executor._conn)

    def test_apply_sends_the_configlet_and_records_its_inverse(self):
        session = FakeSession({"show running-config": RUNNING_XE})
        configlet = spec(["interface Loopback9", " ip address 10.99.0.1 255.255.255.255"], platform="cisco_c8000v_iosxe")
        outcome = self.executor(session).apply(configlet, None)
        self.assertTrue(outcome.ok, outcome)
        self.assertEqual([c for c in session.calls if isinstance(c, tuple)], [("interface Loopback9", "ip address 10.99.0.1 255.255.255.255")])

    def test_apply_refuses_without_a_provable_inverse_or_when_it_endangers_the_session_and_sends_nothing(self):
        for label, lines, protected in (("no inverse", ["no interface GigabitEthernet9"], set()),
                                        ("session interface shutdown", ["interface GigabitEthernet1", " shutdown"],
                                         {"interface gigabitethernet1"})):
            with self.subTest(case=f"refused {label}"):
                session = FakeSession({"show running-config": RUNNING_XE})
                outcome = self.executor(session, protected=protected).apply(spec(lines, platform="cisco_c8000v_iosxe"), None)
                self.assertEqual((outcome.ok, outcome.error_code), (False, "COMMAND_REJECTED"))
                self.assertEqual([c for c in session.calls if isinstance(c, tuple)], [])
        failing = self.executor(FakeSession(fail=OSError("x"))).apply(spec(["interface Loopback9"], platform="cisco_c8000v_iosxe"), None)
        self.assertFalse(failing.ok)

    def test_compensate_reports_none_needed_when_the_state_already_matches(self):
        session = FakeSession({"show running-config": RUNNING_XE})
        executor = self.executor(session)
        configlet = spec(["interface Loopback9"], platform="cisco_c8000v_iosxe")
        executor._applied[configlet.cfg_id] = executor.running_config_digest()
        self.assertEqual(executor.compensate(configlet, None).detail, {"action": "NONE_NEEDED"})

    def test_compensate_never_reports_compensated_without_a_proven_restore(self):
        configlet = spec(["interface Loopback9"], platform="cisco_c8000v_iosxe")
        unknown = SimpleNamespace(previous_state={})
        executor = self.executor(FakeSession({"show running-config": RUNNING_XE}))
        self.assertEqual(executor.compensate(configlet, unknown).status, "COMPENSATION_FAILED")      # no captured state at all
        executor._applied[configlet.cfg_id] = "0" * 64
        self.assertEqual((executor.compensate(configlet, unknown).status, executor.compensate(configlet, unknown).error_code),
                         ("COMPENSATION_FAILED", "UNSUPPORTED"))                                       # no inverse recorded
        executor._inverses[configlet.cfg_id] = ["no interface Loopback9"]
        self.assertEqual(executor.compensate(configlet, unknown).error_code, "STATE_NOT_RESTORED")   # sent, still differs
        broken = self.executor(FakeSession(fail=OSError("x")))
        broken._applied[configlet.cfg_id] = "0" * 64
        self.assertEqual(broken.compensate(configlet, unknown).status, "COMPENSATION_UNVERIFIED")


# -- SR Linux executor -----------------------------------------------------------------------------------------------------
class SrLinuxExecutorTests(SimpleTestCase):
    TREE = {"interface": [{"name": "ethernet-1/1", "admin-state": "enable"}]}

    def test_config_inverse_of_an_added_leaf_deletes_exactly_that_leaf(self):
        inverse = srlinux.config_inverse(["set / interface ethernet-1/1 description lab"], self.TREE)
        self.assertEqual(inverse, ["delete / interface ethernet-1/1 description"])

    def test_config_inverse_refuses_statements_outside_the_strict_grammar(self):
        for label, lines in (("not a set statement", ["show interface"]), ("free text", ["reboot now"])):
            with self.subTest(case=f"invalid {label}"):
                self.assertIsNone(srlinux.config_inverse(lines, self.TREE))

    def test_tree_digest_is_deterministic_and_content_sensitive(self):
        self.assertEqual(srlinux.SrLinuxExecutor.tree_digest(self.TREE), srlinux.SrLinuxExecutor.tree_digest(dict(self.TREE)))
        self.assertNotEqual(srlinux.SrLinuxExecutor.tree_digest(self.TREE), srlinux.SrLinuxExecutor.tree_digest({}))

    def test_tree_digest_of_an_empty_tree_never_equals_a_configured_one(self):
        self.assertNotEqual(srlinux.SrLinuxExecutor.tree_digest({}), srlinux.SrLinuxExecutor.tree_digest({"interface": []}))

    def test_close_and_running_digest_through_a_fake_gnmi_session(self):
        executor = srlinux.SrLinuxExecutor({"name": "SRL"})
        session = mock.Mock()
        executor._conn = session
        with mock.patch.object(executor, "config_tree", return_value=self.TREE):
            self.assertEqual(executor.running_config_digest(), srlinux.SrLinuxExecutor.tree_digest(self.TREE))
        executor.close()
        session.disconnect.assert_called_once_with()
        self.assertIsNone(executor._conn)


# -- SR Linux gNMI writer ---------------------------------------------------------------------------------------------------
class GnmiSessionTests(SimpleTestCase):
    def session(self, client):
        s = srlinux_gnmi.GnmiSession.__new__(srlinux_gnmi.GnmiSession)
        s._client = client
        return s

    def test_get_returns_the_client_answer_for_config_and_state(self):
        client = mock.Mock()
        client.get.return_value = {"notification": []}
        self.assertEqual(self.session(client).get("/interface", "state"), {"notification": []})
        client.get.assert_called_once_with(path=["/interface"], datatype="state", encoding="json_ietf")

    def test_get_refuses_an_unknown_datatype_and_maps_failures_to_codes(self):
        with self.assertRaises(srlinux_gnmi.GnmiError) as caught:
            self.session(mock.Mock()).get("/interface", "all")
        self.assertEqual(str(caught.exception), "COMMAND_NOT_ALLOWED")
        client = mock.Mock()
        client.get.side_effect = RuntimeError("boom")
        with self.assertRaises(srlinux_gnmi.GnmiError):
            self.session(client).get("/interface")

    def test_set_cli_commits_one_transaction_and_counts_statements(self):
        client = mock.Mock()
        sent = self.session(client).set_cli(["set /interface ethernet-1/1 description lab", "delete / interface ethernet-1/2"])
        self.assertEqual(sent, 2)
        client.set.assert_called_once_with(update=[("cli:/", "set / interface ethernet-1/1 description lab\ndelete / interface ethernet-1/2")],
                                           encoding="ascii")

    def test_set_cli_refuses_other_verbs_empty_or_multiline_statements_before_sending(self):
        for label, statements in (("other verb", ["tools system reboot"]), ("empty batch", []), ("bare verb", ["set"]),
                                  ("embedded newline", ["set / a\nset / b"])):
            with self.subTest(case=f"refused {label}"):
                client = mock.Mock()
                with self.assertRaises(srlinux_gnmi.GnmiError):
                    self.session(client).set_cli(statements)
                client.set.assert_not_called()

    def test_disconnect_closes_once_and_tolerates_a_failing_close(self):
        client = mock.Mock()
        session = self.session(client)
        session.disconnect()
        session.disconnect()
        client.close.assert_called_once_with()
        failing = mock.Mock()
        failing.close.side_effect = OSError("x")
        self.session(failing).disconnect()

    def test_inventory_session_builds_a_session_for_an_inventory_srlinux_target(self):
        target = {"platform": "nokia_srlinux", "address": "192.0.2.5", "username": "u", "password": "p"}
        with mock.patch("core.services.nsot_live.get_live_target", return_value=target), \
                mock.patch.object(srlinux_gnmi, "GnmiSession") as session:
            srlinux_gnmi.inventory_session({"name": "SRL", "gnmi_port": 6030})
        session.assert_called_once_with(host="192.0.2.5", port=6030, username="u", password="p", timeout=codes.device_timeout_seconds())

    def test_inventory_session_refuses_an_unknown_or_non_srlinux_device(self):
        for label, target in (("unknown device", None), ("wrong platform", {"platform": "ceos"})):
            with self.subTest(case=f"refused {label}"), mock.patch("core.services.nsot_live.get_live_target", return_value=target):
                with self.assertRaises(srlinux_gnmi.GnmiError) as caught:
                    srlinux_gnmi.inventory_session({"name": "X"})
                self.assertEqual(str(caught.exception), "NOT_CONFIGURED")


# -- IOS XE connection -----------------------------------------------------------------------------------------------------
class IosXeConnectionTests(SimpleTestCase):
    def test_netmiko_connection_refuses_a_device_without_an_iosxe_inventory_target(self):
        for target in (None, {"platform": "arista_ceos"}):
            with self.subTest(case=f"refused {target}"), mock.patch("core.services.nsot_live.get_live_target", return_value=target):
                with self.assertRaises(ExecutorError) as caught:
                    iosxe.netmiko_connection({"name": "R5"})
                self.assertEqual(caught.exception.code, "NOT_CONFIGURED")

    def test_netmiko_connection_opens_a_privileged_session_through_the_inventory_target(self):
        target = {"platform": iosxe.PLATFORM, "address": "192.0.2.9", "username": "u", "password": "p"}
        conn = mock.Mock()
        conn.check_enable_mode.return_value = False
        with mock.patch("core.services.nsot_live.get_live_target", return_value=target), \
                mock.patch("netmiko.ConnectHandler", return_value=conn) as handler:
            self.assertIs(iosxe.netmiko_connection({"name": "R5"}), conn)
        self.assertEqual(handler.call_args.kwargs["device_type"], "cisco_xe")
        conn.enable.assert_called_once_with()


# -- FRR routing grammar ---------------------------------------------------------------------------------------------------
OSPF = ["router ospf", " ospf router-id 10.0.0.3", " network 10.3.0.0/24 area 0"]
BGP = ["router bgp 65003", " bgp router-id 10.0.0.3", " neighbor 10.0.0.4 remote-as 65004", " address-family ipv4 unicast",
       "  network 10.3.0.0/24", " exit-address-family"]


class FrrRoutingGrammarTests(SimpleTestCase):
    def test_parse_returns_blocks_with_leaves_and_bgp_families(self):
        blocks = frr.parse([*OSPF, "!", *BGP])
        self.assertEqual([(b.header, b.kind) for b in blocks], [("router ospf", "ospf"), ("router bgp 65003", "bgp")])
        self.assertEqual(blocks[0].leaves, ["ospf router-id 10.0.0.3", "network 10.3.0.0/24 area 0"])
        self.assertEqual(blocks[1].families, {"address-family ipv4 unicast": ["network 10.3.0.0/24"]})

    def test_parse_refuses_unknown_headers_orphan_leaves_or_leaves_outside_the_context(self):
        for label, lines in (("unknown header", ["hostname r3"]), ("orphan leaf", [" ospf router-id 1.1.1.1"]),
                             ("leaf outside context", ["router ospf", " neighbor 1.1.1.1 remote-as 1"])):
            with self.subTest(case=f"invalid {label}"):
                self.assertIsNone(frr.parse(lines))

    def test_commands_replays_the_parsed_sequence(self):
        block = frr.parse(OSPF)[0]
        self.assertEqual(frr.commands(block), ["router ospf", "ospf router-id 10.0.0.3", "network 10.3.0.0/24 area 0"])

    def test_commands_refuses_a_non_block(self):
        with self.assertRaises(AttributeError):
            frr.commands(None)

    def test_required_daemons_include_zebra_and_each_process_daemon(self):
        self.assertEqual(frr.required_daemons(frr.parse([*OSPF, *BGP])), {"zebra", "ospfd", "bgpd"})

    def test_required_daemons_without_routing_blocks_is_zebra_only(self):
        self.assertEqual(frr.required_daemons(frr.parse(["interface eth1", " ip ospf area 0"])), {"zebra"})
        self.assertEqual(frr.required_daemons([]), {"zebra"})

    def test_tree_reads_running_configuration_with_address_families(self):
        running = "frr version 9\n!\nrouter bgp 65003\n bgp router-id 10.0.0.3\n address-family ipv4 unicast\n  network 10.3.0.0/24\n exit-address-family\nexit\n"
        self.assertEqual(frr.tree(running)["router bgp 65003"], {"": ["bgp router-id 10.0.0.3"],
                                                                 "address-family ipv4 unicast": ["network 10.3.0.0/24"]})

    def test_tree_of_empty_or_comment_only_text_is_empty(self):
        self.assertEqual(frr.tree(""), {})
        self.assertEqual(frr.tree("!\n! nothing\n"), {})

    def test_bgp_process_check_passes_for_the_same_or_a_new_autonomous_system(self):
        blocks = frr.parse(BGP)
        self.assertEqual(frr.conflict(blocks, {}), "")
        self.assertEqual(frr.conflict(blocks, {"router bgp 65003": {"": []}}), "")

    def test_conflict_refuses_a_second_bgp_autonomous_system(self):
        self.assertEqual(frr.conflict(frr.parse(BGP), {"router bgp 65099": {"": []}}), "BGP_PROCESS_CONFLICT")

    def test_process_inverse_removes_a_new_process_or_only_the_added_leaves(self):
        block = frr.parse(OSPF)[0]
        self.assertEqual(frr.process_inverse(block, {}), ["no router ospf"])
        existing = {"router ospf": {"": ["ospf router-id 10.0.0.3"]}}
        self.assertEqual(frr.process_inverse(block, existing), ["router ospf", "   no network 10.3.0.0/24 area 0"])

    def test_process_inverse_refuses_removals_or_replacing_an_existing_value(self):
        self.assertIsNone(frr.process_inverse(frr.parse(["no router ospf"])[0], {}))
        changed = {"router ospf": {"": ["ospf router-id 10.9.9.9"]}}
        self.assertIsNone(frr.process_inverse(frr.parse(OSPF)[0], changed))


# -- raw configlet text / adapters ----------------------------------------------------------------------------------------
class RawTextTests(SimpleTestCase):
    TEXT = "! comment\ninterface Ethernet1\n   description lab\n\nip route 10.0.0.0/8 192.0.2.1\n"

    def test_statements_keep_source_line_numbers_without_comments_or_blanks(self):
        self.assertEqual(raw_text.statements(self.TEXT), [(2, "interface Ethernet1"), (3, "   description lab"),
                                                          (5, "ip route 10.0.0.0/8 192.0.2.1")])

    def test_statements_of_comment_only_or_empty_text_is_empty(self):
        self.assertEqual(raw_text.statements("! a\n# b\n\n"), [])

    def test_stats_counts_bytes_lines_and_statements(self):
        self.assertEqual(raw_text.stats(self.TEXT)["lines"], 5)
        self.assertEqual(raw_text.stats(self.TEXT)["bytes"], len(self.TEXT.encode()))

    def test_stats_refuses_non_text(self):
        with self.assertRaises(AttributeError):
            raw_text.stats(None)

    def test_ceos_command_stream_inserts_exits_like_master_py(self):
        stream = raw_text.ceos_command_stream(["interface Ethernet1", "   description lab", "ip route 10.0.0.0/8 192.0.2.1"])
        self.assertEqual(stream, ["interface Ethernet1", "description lab", "exit", "ip route 10.0.0.0/8 192.0.2.1"])

    def test_ceos_command_stream_of_nothing_is_empty(self):
        self.assertEqual(raw_text.ceos_command_stream([]), [])

    def test_stream_sources_maps_each_command_to_its_statement(self):
        items = raw_text.statements(self.TEXT)
        self.assertEqual(raw_text.stream_sources(items, ["interface Ethernet1", "description lab", "exit", "ip route 10.0.0.0/8 192.0.2.1"]),
                         [2, 3, 3, 5])

    def test_stream_sources_never_guesses_when_counts_disagree(self):
        self.assertEqual(raw_text.stream_sources([(1, "a")], ["a", "b"]), [0, 0])


class RawAdapterTests(SimpleTestCase):
    def test_adapter_for_returns_the_registered_verifier(self):
        adapter_id = sorted(adapters.REGISTRY)[0]
        self.assertIs(adapters.adapter_for(adapter_id), adapters.REGISTRY[adapter_id])

    def test_adapter_for_an_unknown_id_is_none(self):
        self.assertIsNone(adapters.adapter_for("no-such-adapter"))

    def test_outcome_add_records_a_finding(self):
        out = adapters.AdapterOutcome()
        out.add("SANDBOX_UNAVAILABLE")
        self.assertEqual([f["code"] for f in out.findings], ["SANDBOX_UNAVAILABLE"])

    def test_outcome_add_refuses_an_unknown_finding_code(self):
        with self.assertRaises(KeyError):
            adapters.AdapterOutcome().add("NOT_A_FINDING_CODE")

    def test_frr_backend_names_the_image(self):
        frr_adapter = next(a for a in adapters.REGISTRY.values() if isinstance(a, adapters.FrrVtyshDryRun))
        self.assertEqual(frr_adapter.backend(SimpleNamespace(frr_image="frr:9")), "docker:frr:9")

    def test_frr_verify_with_a_missing_image_starts_nothing(self):
        frr_adapter = next(a for a in adapters.REGISTRY.values() if isinstance(a, adapters.FrrVtyshDryRun))
        calls = []

        def runner(argv, **_kwargs):
            calls.append(argv)
            return sandbox.ProcessResult(returncode=1, output="Error: No such image: frr:none")

        config = SimpleNamespace(frr_image="frr:none", timeout=5, cleanup_timeout=5, allow_privileged=False, ceos_image="ceos:none")
        out = frr_adapter.verify("router ospf\n", config=config, runner=runner)
        self.assertEqual(([f["code"] for f in out.findings], out.started, out.sandbox["cleanup"]), (["SANDBOX_IMAGE_MISSING"], False, "NOT_NEEDED"))
        self.assertEqual(len(calls), 1)                      # only the image inspection; no container was started

    def test_frr_verify_accepts_valid_syntax_and_cleans_up(self):
        from core.tests.test_raw_sandbox import FakeRunner

        runner = FakeRunner()
        frr_adapter = adapters.FrrVtyshDryRun()
        out = frr_adapter.verify("router ospf\n ospf router-id 192.0.2.1\n", config=sandbox.SandboxConfig("frr:test", "ceos:test", True, 5.0, 5.0, 5.0),
                                 runner=runner, clock=lambda: 0.0, sleep=lambda _s: None)
        self.assertEqual(([f["code"] for f in out.findings], out.started, out.sandbox["cleanup"]),
                         (["SYNTAX_ACCEPTED", "SEMANTICS_NOT_VERIFIED"], True, "OK"))
        self.assertEqual(runner.verbs(), ["image", "run", "rm", "ps"])

    def test_ceos_verify_accepts_a_configuration_session_and_aborts_it(self):
        from core.tests.test_raw_sandbox import FakeRunner

        runner = FakeRunner()
        steps = iter(range(10_000))
        out = adapters.CeosConfigSession().verify("interface Loopback99\n   description x\n",
                                                  config=sandbox.SandboxConfig("frr:test", "ceos:test", True, 5.0, 5.0, 5.0),
                                                  runner=runner, clock=lambda: float(next(steps)), sleep=lambda _s: None)
        self.assertEqual(([f["code"] for f in out.findings], out.started, out.sandbox["cleanup"]),
                         (["SYNTAX_ACCEPTED", "SEMANTICS_NOT_VERIFIED"], True, "OK"))
        script = next(stdin for argv, stdin in runner.calls if argv[1] == "exec" and stdin)
        self.assertIn(b"abort\n", script)                    # the session is always aborted: nothing is committed

    def test_ceos_verify_refuses_to_start_without_privileged_policy(self):
        ceos_adapter = next(a for a in adapters.REGISTRY.values() if isinstance(a, adapters.CeosConfigSession))
        runner = mock.Mock()
        config = SimpleNamespace(allow_privileged=False, ceos_image="ceos:4", timeout=5, cleanup_timeout=5)
        out = ceos_adapter.verify("hostname x\n", config=config, runner=runner)
        self.assertEqual(([f["code"] for f in out.findings], out.started), (["SANDBOX_DISABLED"], False))
        runner.assert_not_called()


# -- eligibility / persistence / scope / spec ------------------------------------------------------------------------------
class ExecutionRecordTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.p = x.prepared()

    def _run(self):
        scope, _ = resolve_scope(self.p.plan, "COMPLETE")
        return locking.acquire(change=self.p.change, plan=self.p.plan, precheck_run=self.p.precheck, mode="COMPLETE", actor="tester",
                               scope=scope, devices=scope.devices), scope

    def test_latest_precheck_and_active_runs(self):
        from core.services.execution import eligibility

        self.assertEqual(eligibility.latest_precheck(self.p.change), self.p.precheck)
        run, _scope = self._run()
        self.assertEqual(list(eligibility.active_runs()), [run])

    def test_latest_precheck_none_and_expired_runs_never_active(self):
        from core.services.execution import eligibility
        from core.tests.helpers.validation import simple_pass_change

        self.assertIsNone(eligibility.latest_precheck(simple_pass_change().change))
        run, _scope = self._run()
        self.assertEqual(list(eligibility.active_runs(now=run.lease_expires_at + timedelta(seconds=1))), [])

    def test_add_not_attempted_records_each_remaining_configlet(self):
        from core.services.execution import persistence

        run, scope = self._run()
        specs = [ConfigletSpec.from_configlet(c) for c in self.p.plan.configlets.order_by("sequence")]
        with self.subTest(case="records each remaining configlet ok"):
            persistence.add_not_attempted(run, specs)
            self.assertEqual(sorted(run.results.values_list("cfg_id", "status")), sorted((s.cfg_id, Status.NOT_ATTEMPTED) for s in specs))

    def test_serialize_run_and_report_json_are_sanitized_documents(self):
        import json

        from core.services.execution import persistence

        run, _scope = self._run()
        run.report = {"api_token": "s3cr3t", "note": "ok"}
        run.save(update_fields=["report"])
        document = persistence.serialize_run(run)
        self.assertEqual((document["run_id"], document["change_id"], document["mode"]), (str(run.run_id), self.p.change.change_id, "COMPLETE"))
        self.assertNotIn("s3cr3t", persistence.report_json(run))
        self.assertEqual(json.loads(persistence.report_json(run))["run_id"], str(run.run_id))

    def test_report_json_refuses_secret_values_and_is_success_false_for_a_failed_run(self):
        from core.services.execution import persistence

        run, _scope = self._run()
        models.ChangeExecutionRun.objects.filter(pk=run.pk).update(report={"password": "hunter2"})   # as if a defect stored one
        locking.reap_expired(now=run.lease_expires_at + timedelta(seconds=1))                         # finished as INTERRUPTED
        run.refresh_from_db()
        with self.subTest(case="secret values refused and an interrupted run never counted"):
            self.assertNotIn("hunter2", persistence.report_json(run))
            self.assertFalse(persistence.is_success(run))

    def test_is_success_for_a_succeeded_outcome(self):
        from core.services.execution import persistence

        run, _scope = self._run()
        run.outcome = sorted(persistence.SUCCESS_OUTCOMES)[0]
        self.assertTrue(persistence.is_success(run))
        self.assertEqual(persistence.SUCCESS_OUTCOMES & {Outcome.INTERRUPTED}, set())

    def test_scope_lists_unselected_configlets_and_serializes(self):
        _run, scope = self._run()
        self.assertEqual(scope.unselected, [])
        self.assertEqual(scope.to_dict()["plan_order"], [c.cfg_id for c in scope.ordered])
        self.assertEqual(scope.to_dict()["mode"], "COMPLETE")

    def test_spec_from_a_structured_configlet_copies_lines_and_expected_facts(self):
        configlet = self.p.plan.configlets.order_by("sequence").first()
        built = ConfigletSpec.from_configlet(configlet)
        self.assertEqual((built.cfg_id, built.device, built.origin, built.pk), (configlet.cfg_id, configlet.target_device, "STRUCTURED", configlet.pk))
        self.assertTrue(built.lines)

    def test_spec_from_a_raw_configlet_without_its_pinned_revision_carries_an_integrity_error(self):
        configlet = SimpleNamespace(desired_state_ref={}, verification_spec={}, origin="RAW", raw_revision=None, metadata={"raw": {}},
                                    cfg_id="CFG-R", sequence=1, target_device="R1", operation_type="RAW_APPLY", platform="arista_ceos", object_type="raw_configlet",
                                    operation="RAW_APPLY", rendered_config="interface X", pk=None, raw_verification=None)
        built = ConfigletSpec.from_configlet(configlet)
        self.assertEqual((built.origin, built.lines, built.integrity_error), ("RAW", (), "RAW_REVISION_INTEGRITY"))

    def test_bounded_lines_truncate_count_and_width(self):
        from core.services.execution.executors.base import bounded_lines

        self.assertEqual(bounded_lines(["a" * 300, "b"], limit=1, width=5), ["aaaaa"])

    def test_bounded_lines_of_nothing_or_non_text_never_raise(self):
        from core.services.execution.executors.base import bounded_lines

        self.assertEqual(bounded_lines([]), [])
        self.assertEqual(bounded_lines([None, 7]), ["None", "7"])

    def test_auto_configlets_select_only_derived_auto_address_rows(self):
        from core.services.execution import auto_recheck

        auto = SimpleNamespace(metadata={"derived": {"kind": "AUTO_ADDRESS"}})
        self.assertEqual(auto_recheck.auto_configlets([auto, SimpleNamespace(metadata={})]), [auto])

    def test_auto_configlets_none_without_derived_metadata(self):
        from core.services.execution import auto_recheck

        self.assertEqual(auto_recheck.auto_configlets([SimpleNamespace(metadata=None), SimpleNamespace(metadata={"derived": {"kind": "X"}})]), [])
