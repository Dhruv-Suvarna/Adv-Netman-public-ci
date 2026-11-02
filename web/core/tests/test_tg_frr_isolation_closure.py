"""Test-governance closure for Ubuntu/FRR trusted-upstream isolation (V2 Phase 9).

Direct positive and negative cases for every public function of ``isolation.frr``, the ``FrrIsolationExecutor``, the
platform helpers in ``isolation.service`` / ``commissioning.admission`` and the ``management.linux_ssh`` session.  The flows in
``test_frr_isolation`` exercise the same code end to end; these pin each unit's own contract.  The in-memory upstream is
``helpers.frr_isolation.FakeFrrUpstream`` (the exact argv the executor sends, nft 1.0.9 output shapes).
"""

from __future__ import annotations

import json
import socket
from types import SimpleNamespace
from unittest import mock

from django.test import SimpleTestCase

from core import models
from core.services.commissioning import admission
from core.services.execution.executors.base import APPLY, ConfigletSpec, ExecutorError
from core.services.execution.executors.frr_isolation import FrrIsolationExecutor, state_digest
from core.services.isolation import frr
from core.services.isolation import service as isolation
from core.services.management import linux_ssh
from core.tests.helpers import frr_isolation as F

BOOT = {"prefix": "10.254.30.0/24", "service_address": F.SERVICE, "http_port": 8080}
TABLE = "nmas_iso_dev000002"
INTENT = {"upstream": {"device": "R4", "interface": F.PORT, "platform": frr.PLATFORM, "vrf": ""}, "bootstrap": BOOT,
          "elements": {"PACKET_FILTER": {"family": "inet", "table": TABLE, "chains": list(frr.CHAINS), "hook_families": ["ip", "ip6"]}}}


def executor(upstream=None):
    return FrrIsolationExecutor({"name": "R4", "platform": "linux"}, runner=upstream or F.FakeFrrUpstream())


def enforced_upstream():
    upstream = F.FakeFrrUpstream()
    upstream.tables[TABLE] = "\n".join(frr.render_table(TABLE, F.PORT, BOOT))
    return upstream


# ===================================================================================================================== frr.py
class FrrRenderClosureTests(SimpleTestCase):
    def test_digest_returns_the_same_value_for_equal_content_in_any_key_order(self):
        self.assertEqual(frr.digest({"a": 1, "b": [2]}), frr.digest({"b": [2], "a": 1}))
        self.assertEqual(len(frr.digest("x")), 64)

    def test_digest_of_different_content_is_a_mismatch(self):
        self.assertNotEqual(frr.digest({"a": 1}), frr.digest({"a": 2}))

    def test_table_name_returns_the_reserved_name_of_a_device_record(self):
        self.assertEqual(frr.table_name("DEV-000123"), "nmas_iso_dev000123")

    def test_chain_rules_returns_exactly_three_chains_scoped_to_the_port(self):
        rules = frr.chain_rules(F.PORT, BOOT)
        self.assertEqual(sorted(rules), ["forward", "input", "output"])
        self.assertTrue(all(f'"{F.PORT}"' in rule for chain in rules.values() for rule in chain))
        self.assertEqual((rules["forward"][-1], rules["input"][-1], rules["output"][-1]),
                         (f'oifname "{F.PORT}" counter drop', f'iifname "{F.PORT}" counter drop', f'oifname "{F.PORT}" counter drop'))

    def test_parse_delete_refuses_anything_but_one_reserved_table_deletion(self):
        self.assertEqual(frr.parse_delete([f"delete table inet {TABLE}"]), TABLE)
        for lines in ([f"delete table inet {TABLE}", "flush ruleset"], ["delete table inet filter"], ["flush ruleset"]):
            self.assertIsNone(frr.parse_delete(lines))

    def test_normalize_listing_returns_lines_with_counters_and_indentation_removed(self):
        text = "table inet t {\n\tchain c {\n\t\tiifname \"eth4\" counter packets 12 bytes 900 drop\n\n\t}\n}\n"
        self.assertEqual(frr.normalize_listing(text), ["table inet t {", "chain c {", 'iifname "eth4" counter drop', "}", "}"])

    def test_normalize_listing_of_missing_text_is_empty(self):
        self.assertEqual(frr.normalize_listing(None), [])
        self.assertEqual(frr.normalize_listing(""), [])

    def test_render_apply_returns_one_atomic_operation_whose_inverse_deletes_exactly_that_table(self):
        op, = frr.render_apply(INTENT)
        self.assertEqual((op["key"], op["kind"], op["inverse"], op["platform"]), ("nft-table", "ADD", [f"delete table inet {TABLE}"], "ubuntu_frr"))
        self.assertEqual(op["lines"], frr.render_table(TABLE, F.PORT, BOOT))

    def test_render_apply_refuses_a_malformed_table_name_or_port(self):
        for intent in ({**INTENT, "elements": {"PACKET_FILTER": {"table": "filter"}}},
                       {**INTENT, "upstream": {**INTENT["upstream"], "interface": "eth4; reboot"}}):
            with self.assertRaises(frr.RenderError):
                frr.render_apply(intent)

    def test_render_release_returns_the_inverse_of_apply_with_apply_as_its_restore(self):
        applied, = frr.render_apply(INTENT)
        released, = frr.render_release(INTENT)
        self.assertEqual((released["key"], released["kind"], released["lines"], released["inverse"]),
                         ("release-nft-table", "REMOVE", applied["inverse"], applied["lines"]))

    def test_render_release_refuses_a_non_ipv4_bootstrap(self):
        with self.assertRaises(frr.RenderError):
            frr.render_release({**INTENT, "bootstrap": {**BOOT, "prefix": "2001:db8::/64"}})


class FrrSnapshotClosureTests(SimpleTestCase):
    def setUp(self):
        self.snap = executor().snapshot((F.NMAS_SOURCE,))

    def test_nft_version_returns_the_numeric_triple(self):
        self.assertEqual(frr.nft_version("nftables v1.0.9 (Old Doc Yak #3)"), (1, 0, 9))

    def test_nft_version_of_unrelated_text_is_none(self):
        self.assertIsNone(frr.nft_version("command not found"))
        self.assertIsNone(frr.nft_version(None))

    def test_link_returns_the_named_interface_row(self):
        self.assertEqual(frr.link(self.snap, F.PORT)["ifname"], F.PORT)

    def test_link_of_a_missing_interface_is_none(self):
        self.assertIsNone(frr.link(self.snap, "eth99"))
        self.assertIsNone(frr.link({}, F.PORT))

    def test_port_facts_returns_exact_addresses_without_link_local(self):
        facts = frr.port_facts(self.snap, F.PORT)
        self.assertEqual((facts["exists"], facts["up"], facts["ipv4"], facts["ipv6"], facts["children"], facts["default_route"]),
                         (True, True, [f"{F.GATEWAY}/24"], ["2001:db8:30::1/64"], [], False))

    def test_port_facts_of_a_missing_port_reports_nothing_present(self):
        facts = frr.port_facts(self.snap, "eth99")
        self.assertEqual((facts["exists"], facts["ipv4"], facts["up"]), (False, [], False))

    def test_relays_for_returns_the_relay_serving_the_port(self):
        self.assertEqual(frr.relays_for(self.snap, F.PORT, F.SERVICE), [f"dhcrelay -4 -d -id {F.PORT} -iu eth2 {F.SERVICE}"])

    def test_relays_for_never_counts_a_relay_of_another_port_or_service(self):
        self.assertEqual(frr.relays_for(self.snap, "eth5", F.SERVICE), [])
        self.assertEqual(frr.relays_for(self.snap, F.PORT, "10.9.9.9"), [])
        self.assertEqual(frr.relays_for({"processes": ["/usr/sbin/sshd -i eth4 10.254.31.2"]}, F.PORT, F.SERVICE), [])

    def test_frr_interface_lines_returns_the_port_stanza(self):
        self.assertEqual(frr.frr_interface_lines(F.FRR_TEXT, F.PORT), ["ip ospf area 0.0.0.10"])

    def test_frr_interface_lines_of_an_unconfigured_port_is_empty(self):
        self.assertEqual(frr.frr_interface_lines(F.FRR_TEXT, "eth9"), [])

    def test_routing_on_port_returns_the_filtered_ip_protocols(self):
        self.assertEqual(frr.routing_on_port(F.FRR_TEXT, F.PORT, [f"{F.GATEWAY}/24"]), {"filtered": ["OSPF"], "unsupported": []})

    def test_routing_on_port_reports_isis_as_unsupported_not_filtered(self):
        text = f"interface {F.PORT}\n ip router isis CORE\nexit\nrouter rip\n network 10.254.30.0/24\nexit\n"
        self.assertEqual(frr.routing_on_port(text, F.PORT, [f"{F.GATEWAY}/24"]), {"filtered": ["RIP"], "unsupported": ["IS-IS"]})

    def test_foreign_references_returns_other_tables_naming_the_port(self):
        ruleset = f'table inet filter {{\n chain input {{\n  iifname "{F.PORT}" accept\n }}\n}}\ntable inet {TABLE} {{\n iifname "{F.PORT}" drop\n}}\n'
        self.assertEqual(frr.foreign_references(ruleset, TABLE, F.PORT), ["inet filter"])

    def test_foreign_references_never_counts_our_own_table_or_other_ports(self):
        ruleset = f'table inet {TABLE} {{\n iifname "{F.PORT}" drop\n}}\ntable ip nat {{\n oifname "eth9" masquerade\n}}\n'
        self.assertEqual(frr.foreign_references(ruleset, TABLE, F.PORT), [])

    def test_route_via_port_returns_learned_routes_as_networks(self):
        snap = {"routes4": [{"dst": "10.254.255.6", "dev": F.PORT, "protocol": "ospf"}], "routes6": []}
        self.assertEqual(frr.route_via_port(snap, F.PORT), ["10.254.255.6/32"])

    def test_route_via_port_never_counts_connected_link_local_or_other_ports(self):
        self.assertEqual(frr.route_via_port(self.snap, F.PORT), [])
        snap = {"routes4": [{"dst": "10.1.0.0/16", "dev": "eth2", "protocol": "ospf"}], "routes6": [{"dst": "fe80::/64", "dev": F.PORT}]}
        self.assertEqual(frr.route_via_port(snap, F.PORT), [])

    def test_lockout_returns_an_nmas_source_routed_through_the_port(self):
        self.assertEqual(frr.lockout({"route_get": {F.NMAS_SOURCE: F.PORT}}, F.PORT), [F.NMAS_SOURCE])

    def test_lockout_is_empty_when_nmas_is_not_routed_via_the_port(self):
        self.assertEqual(frr.lockout(self.snap, F.PORT), [])

    def test_capability_problems_returns_nothing_for_a_capable_upstream(self):
        self.assertEqual(frr.capability_problems(self.snap), [])

    def test_capability_problems_reports_each_missing_primitive(self):
        problems = frr.capability_problems({**self.snap, "nft_version": "nftables v0.9.3", "nft_check_ok": False, "hooks_listable": False})
        self.assertEqual({p["code"] for p in problems}, {"ISOLATION_PLATFORM_NOT_IMPLEMENTED"})
        self.assertEqual(len(problems), 3)


class FrrReadBackClosureTests(SimpleTestCase):
    def setUp(self):
        self.upstream = enforced_upstream()
        self.snap = executor(self.upstream).snapshot()

    def test_hooks_registered_returns_every_chain_in_both_families(self):
        self.assertEqual(frr.hooks_registered(self.snap["hooks"], TABLE), {"ip": ["forward", "input", "output"], "ip6": ["forward", "input", "output"]})

    def test_hooks_registered_of_another_table_is_empty(self):
        self.assertEqual(frr.hooks_registered(self.snap["hooks"], "nmas_iso_dev000099"), {})

    def test_chain_heads_returns_each_base_chain(self):
        heads = frr.chain_heads(self.snap["table_json"][TABLE])
        self.assertEqual(heads["forward"], {"type": "filter", "hook": "forward", "prio": 0, "policy": "accept"})
        self.assertEqual(sorted(heads), ["forward", "input", "output"])

    def test_chain_heads_of_missing_json_is_empty(self):
        self.assertEqual(frr.chain_heads(None), {})

    def test_read_back_accepts_exactly_the_intended_table(self):
        ok, facts = frr.read_back(INTENT, self.snap)
        self.assertTrue(ok)
        self.assertEqual((facts["exact"], facts["extra"], facts["missing"]), (True, [], []))

    def test_read_back_refuses_a_table_missing_one_drop_rule(self):
        self.upstream.tables[TABLE] = self.upstream.tables[TABLE].replace(f'    oifname "{F.PORT}" counter drop\n', "", 1)
        ok, facts = frr.read_back(INTENT, executor(self.upstream).snapshot())
        self.assertFalse(ok)
        self.assertEqual((facts["present"], facts["exact"]), (True, False))      # the same rule text remains in the forward chain

    def test_deny_counters_returns_packets_per_chain(self):
        self.upstream.hit(TABLE, "forward", 5)
        self.assertEqual(frr.deny_counters(json.loads(self.upstream.table_json(TABLE)))["forward"], 5)

    def test_ospf_neighbors_on_returns_ospfd_and_ospf6d_rows_on_the_port(self):
        v2 = json.dumps({"neighbors": {"10.254.255.6": [{"ifaceName": f"{F.PORT}:{F.GATEWAY}", "nbrState": "Full/DR"}]}})
        v3 = json.dumps({"neighbors": [{"interfaceName": F.PORT, "neighborId": "10.254.255.6", "state": "Full"}]})
        self.assertEqual(frr.ospf_neighbors_on(v2, F.PORT), [{"neighbor": "10.254.255.6", "state": "Full/DR"}])
        self.assertEqual(frr.ospf_neighbors_on(v3, F.PORT), [{"neighbor": "10.254.255.6", "state": "Full"}])

    def test_ospf_neighbors_on_reports_unreadable_output_and_never_counts_another_port(self):
        self.assertEqual(frr.ospf_neighbors_on("% not json", F.PORT), [{"neighbor": "?", "state": "UNREADABLE"}])
        self.assertEqual(frr.ospf_neighbors_on(json.dumps({"neighbors": {"1.1.1.1": [{"ifaceName": "eth2:x"}]}}), F.PORT), [])

    def test_routing_findings_refuses_an_unreadable_route_table(self):
        ok, code, _facts = frr.routing_findings(INTENT, {**self.snap, "routes6": None}, F.PORT)
        self.assertEqual((ok, code), (False, "ISOLATION_UPSTREAM_UNREADABLE"))

    def test_neighbor_entry_returns_the_resolved_mac(self):
        rows = [{"dst": "10.254.30.5", "dev": F.PORT, "lladdr": "AA:BB:CC:00:00:01", "state": ["REACHABLE"]}]
        self.assertEqual(frr.neighbor_entry(rows, "10.254.30.5"), {"mac": "aa:bb:cc:00:00:01", "interface": F.PORT})


# ============================================================================================================ the executor
class FrrExecutorClosureTests(SimpleTestCase):
    def test_state_digest_returns_the_same_value_for_the_same_state(self):
        self.assertEqual(state_digest("table inet t {\n}\n", F.FRR_TEXT), state_digest("table inet t {\n}\n", F.FRR_TEXT))

    def test_state_digest_of_a_changed_ruleset_is_a_mismatch(self):
        self.assertNotEqual(state_digest("", F.FRR_TEXT), state_digest("table inet t {\n}\n", F.FRR_TEXT))

    def test_ruleset_and_frr_config_return_the_device_text(self):
        upstream = enforced_upstream()
        ex = executor(upstream)
        self.assertEqual(ex.ruleset(), upstream.ruleset())
        self.assertEqual(ex.frr_config(), F.FRR_TEXT)

    def test_table_listing_and_table_json_return_the_reserved_table(self):
        upstream = enforced_upstream()
        ex = executor(upstream)
        self.assertEqual(ex.table_listing(TABLE), upstream.listing(TABLE))
        self.assertEqual(frr.chain_heads(ex.table_json(TABLE))["input"]["hook"], "input")

    def test_table_listing_and_table_json_of_a_missing_table_are_none(self):
        ex = executor()
        self.assertIsNone(ex.table_listing(TABLE))
        self.assertIsNone(ex.table_json(TABLE))

    def test_neighbors_returns_the_neighbour_rows(self):
        upstream = F.FakeFrrUpstream()
        upstream.neigh = [{"dst": "10.254.30.5", "lladdr": "aa:bb:cc:00:00:01"}]
        self.assertEqual(executor(upstream).neighbors(), upstream.neigh)

    def test_reachable_returns_the_ping_result(self):
        upstream = F.FakeFrrUpstream()
        original = upstream._answer                                                      # pylint: disable=protected-access
        upstream._answer = lambda argv: (0, "") if argv[0] == "ping" else original(argv)  # pylint: disable=protected-access
        self.assertTrue(executor(upstream).reachable("10.254.30.5"))
        self.assertEqual(upstream.calls[-1], ["ping", "-4", "-c", "2", "-W", "1", "10.254.30.5"])

    def test_reachable_refuses_a_malformed_address_without_sending_anything(self):
        upstream = F.FakeFrrUpstream()
        self.assertFalse(executor(upstream).reachable("10.0.0.1; reboot"))
        self.assertEqual(upstream.calls, [])
        self.assertFalse(executor(upstream).reachable("10.254.30.9"))                    # the fake answers ping with status 1

    def test_connect_opens_a_session_through_the_connector_and_probes_nft(self):
        upstream = F.FakeFrrUpstream()
        session = SimpleNamespace(run=upstream, close=mock.Mock())
        connector = mock.Mock(return_value=session)
        ex = FrrIsolationExecutor({"name": "R4", "platform": "linux"}, connector=connector)
        ex.connect()
        self.assertEqual(connector.call_args.args, ("R4",))
        self.assertEqual(upstream.calls, [["nft", "list", "ruleset"]])
        ex.close()
        session.close.assert_called_once_with()

    @staticmethod
    def spec(lines):
        return ConfigletSpec(cfg_id="CFG-001", sequence=1, device="R4", platform=frr.PLATFORM, object_type="isolation", operation="ADD",
                             lines=tuple(lines))

    def test_apply_refuses_when_a_table_appeared_since_the_assessment(self):
        upstream = F.FakeFrrUpstream()
        ex = executor(upstream)
        spec = self.spec(frr.render_table(TABLE, F.PORT, BOOT))
        assessment = ex.assess(spec)
        self.assertEqual(assessment.action, APPLY)
        upstream.tables[TABLE] = "\n".join(frr.render_table(TABLE, F.PORT, BOOT))       # someone else created it meanwhile
        outcome = ex.apply(spec, assessment)
        self.assertEqual((outcome.ok, outcome.error_code), (False, "COMMAND_REJECTED"))
        self.assertNotIn(["nft", "\n".join(frr.render_table(TABLE, F.PORT, BOOT))], upstream.calls)   # never merged into it

    def test_compensate_refuses_without_a_recorded_apply(self):
        ex = executor()
        spec = self.spec(frr.render_table(TABLE, F.PORT, BOOT))
        outcome = ex.compensate(spec, ex.assess(spec))
        self.assertEqual((outcome.status, outcome.error_code), ("COMPENSATION_FAILED", "UNSUPPORTED"))

    def test_close_releases_the_session_once(self):
        session = SimpleNamespace(close=mock.Mock())
        ex = FrrIsolationExecutor({"name": "R4", "platform": "linux"}, connector=lambda name, timeout: session)
        ex._session = session                                                            # pylint: disable=protected-access
        ex.close()
        ex.close()
        session.close.assert_called_once_with()


# ============================================================================================ service / admission helpers
class FrrServiceClosureTests(SimpleTestCase):
    FRR_POLICY = SimpleNamespace(upstream_platform=models.Platform.UBUNTU_FRR, upstream_device="R4", upstream_interface=F.PORT, intent=INTENT)
    CEOS_POLICY = SimpleNamespace(upstream_platform=models.Platform.ARISTA_CEOS, upstream_device="S1", upstream_interface="Ethernet7")

    def test_default_access_returns_the_frr_executor_for_an_ubuntu_frr_upstream(self):
        with mock.patch("core.services.health.inventory.load_inventory", return_value={"management": {"nmas_ipv4": "192.168.200.100/24"}}):
            access = isolation.default_access(models.Platform.UBUNTU_FRR)
        self.assertIs(access.executor_factory, FrrIsolationExecutor)
        self.assertEqual(access.nmas_sources, ("192.168.200.100",))

    def test_default_access_never_uses_the_frr_executor_for_another_platform(self):
        from core.services.execution.executors.ceos import CeosExecutor

        with mock.patch("core.services.health.inventory.load_inventory", return_value={"management": {"nmas_ipv4": "not-an-address"}}):
            access = isolation.default_access("nokia_srlinux")
        self.assertIs(access.executor_factory, CeosExecutor)
        self.assertEqual(access.nmas_sources, ())

    def test_is_frr_returns_true_for_an_ubuntu_frr_policy(self):
        self.assertTrue(isolation.is_frr(self.FRR_POLICY))

    def test_is_frr_is_false_for_ceos_and_for_a_policy_without_a_platform(self):
        self.assertFalse(isolation.is_frr(self.CEOS_POLICY))
        self.assertFalse(isolation.is_frr(SimpleNamespace()))

    def test_read_state_returns_the_frr_snapshot(self):
        access = F.access(F.FakeFrrUpstream())
        snap = isolation.read_state(self.FRR_POLICY, executor(), access)
        self.assertEqual((snap["frr"], snap["route_get"]), (F.FRR_TEXT, {F.NMAS_SOURCE: "Vlan102"}))

    def test_read_state_raises_when_the_frr_upstream_is_unreachable(self):
        ex = FrrIsolationExecutor({"name": "R4", "platform": "linux"})                  # never connected: no session
        with self.assertRaises(ExecutorError) as caught:
            isolation.read_state(self.FRR_POLICY, ex, F.access(F.FakeFrrUpstream()))
        self.assertEqual(caught.exception.code, "CONNECTION_FAILED")

    def test_presence_of_returns_present_for_the_exact_table(self):
        self.assertEqual(isolation.presence_of(self.FRR_POLICY, executor(enforced_upstream()).snapshot()), {"nft-table": "PRESENT"})

    def test_presence_of_reports_absent_and_partial_tables(self):
        self.assertEqual(isolation.presence_of(self.FRR_POLICY, executor().snapshot()), {"nft-table": "ABSENT"})
        upstream = enforced_upstream()
        upstream.tables[TABLE] = upstream.tables[TABLE].replace("tcp dport 8080", "tcp dport 8081")
        self.assertEqual(isolation.presence_of(self.FRR_POLICY, executor(upstream).snapshot()), {"nft-table": "PARTIAL"})

    def test_frr_failures_reports_a_missing_route_and_an_unreadable_table(self):
        found = admission.frr_failures(executor(), self.FRR_POLICY, {"routes_v4": ["10.9.9.0/24"]})
        self.assertEqual(found, [{"check": "routes_v4", "detail": f"10.9.9.0/24 not learned through {F.PORT}"}])
        upstream = F.FakeFrrUpstream()
        upstream.fail = lambda argv: argv == ["ip", "-j", "-6", "route", "show"]
        found = admission.frr_failures(executor(upstream), self.FRR_POLICY, {"routes_v6": ["2001:db8:9::/64"]})
        self.assertEqual(found, [{"check": "routes_v6", "detail": "route table unreadable"}])


# ============================================================================================================= linux_ssh
class Stream:
    def __init__(self, data=b"", status=0):
        self.data, self.channel = data, SimpleNamespace(recv_exit_status=lambda: status)

    def read(self):
        return self.data

    def close(self):
        pass


class LinuxSshClosureTests(SimpleTestCase):
    def test_linux_session_run_returns_status_and_output_of_the_exact_command(self):
        client = mock.Mock()
        client.exec_command.return_value = (Stream(), Stream(b"nftables v1.0.9\n", 0), Stream())
        self.assertEqual(linux_ssh.LinuxSession(client, "nmas-svc").run(["nft", "--version"], 5), (0, "nftables v1.0.9\n"))
        client.exec_command.assert_called_once_with("sudo -n -- nft --version", timeout=5)

    def test_linux_session_run_maps_a_timeout_and_a_lost_transport_to_fixed_codes(self):
        import paramiko

        for raised, code in ((socket.timeout(), "TIMEOUT"), (paramiko.SSHException("closed"), "TRANSPORT_ERROR"), (EOFError(), "TRANSPORT_ERROR")):
            client = mock.Mock()
            client.exec_command.side_effect = raised
            with self.assertRaises(ExecutorError) as caught:
                linux_ssh.LinuxSession(client, "nmas-svc").run(["ip", "-j", "neigh", "show"], 5)
            self.assertEqual(caught.exception.code, code)

    def test_linux_session_close_closes_the_client_once(self):
        client = mock.Mock()
        linux_ssh.LinuxSession(client, "nmas-svc").close()
        client.close.assert_called_once_with()

    def test_linux_session_close_never_raises_when_the_client_is_already_gone(self):
        client = mock.Mock()
        client.close.side_effect = OSError("gone")
        linux_ssh.LinuxSession(client, "nmas-svc").close()
        client.close.assert_called_once_with()

    def test_connect_returns_a_session_opened_key_only_on_the_resolved_target(self):
        import paramiko

        found = {"address": "192.168.200.4", "username": "nmas-svc", "ssh_key_ref": "runtime://x", "host_key": "SHA256:" + "A" * 43, "port": 2222}
        key = object()
        with mock.patch.object(linux_ssh, "target", return_value=found), \
                mock.patch("modules.device_credentials.load_ssh_private_key", return_value=key) as loader, \
                mock.patch.object(paramiko.SSHClient, "connect", autospec=True) as connect:
            session = linux_ssh.connect("R4", timeout=3)
        loader.assert_called_once_with("runtime://x")
        _client, address = connect.call_args.args
        self.assertEqual(address, "192.168.200.4")
        self.assertEqual({k: connect.call_args.kwargs[k] for k in ("port", "username", "pkey", "allow_agent", "look_for_keys", "timeout")},
                         {"port": 2222, "username": "nmas-svc", "pkey": key, "allow_agent": False, "look_for_keys": False, "timeout": 3})
        self.assertIsInstance(session, linux_ssh.LinuxSession)
        self.assertEqual(session.username, "nmas-svc")
