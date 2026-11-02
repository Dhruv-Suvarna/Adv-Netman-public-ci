"""V2 Phase 9: Ubuntu/FRR trusted-upstream isolation -- the nftables renderer and strict parser (``isolation.frr``), the intent
builder's refusals, read-back / drift / routing findings, the executor's assess / apply / compensate against an in-memory upstream
(``helpers.frr_isolation``), the authorized SSH transport (``management.linux_ssh``), and the isolation service end to end on an
Ubuntu/FRR upstream through the governed transaction (plan, precheck, approval, apply, verify, drift, release, fault)."""

from __future__ import annotations

import dataclasses
import json
import shlex
from types import SimpleNamespace
from unittest import mock

from django.test import SimpleTestCase, TestCase

from core import models
from core.services.commissioning import admission
from core.services.execution.executors.base import APPLY, REFUSE, SKIP_SATISFIED, ConfigletSpec, ExecutorError
from core.services.execution.executors.frr_isolation import FrrIsolationExecutor
from core.services.isolation import frr, service as iso
from core.services.management import linux_ssh
from core.tests.helpers import frr_isolation as F
from core.tests.helpers import lifecycle as L
from core.tests.helpers import ztp as Z

St = models.IsolationState
BOOT = {"prefix": "10.254.30.0/24", "service_address": F.SERVICE, "http_port": 8080}
TABLE = "nmas_iso_dev000002"
NETWORK = SimpleNamespace(ipv4_prefix="10.254.30.0/24", gateway=F.GATEWAY, service_address=F.SERVICE, http_port=8080)


def snapshot(upstream: F.FakeFrrUpstream) -> dict:
    return FrrIsolationExecutor({"name": "R4"}, runner=upstream).snapshot((F.NMAS_SOURCE,))


def build(upstream: F.FakeFrrUpstream, device_id="DEV-000002"):
    return frr.build(device_id=device_id, upstream="R4", interface=F.PORT, network=NETWORK, snapshot=snapshot(upstream),
                     nmas_sources=(F.NMAS_SOURCE,))


def spec(lines, *, object_type="isolation", origin="STRUCTURED", removal=None, cfg_id="CFG-001"):
    return ConfigletSpec(cfg_id=cfg_id, sequence=1, device="R4", platform=frr.PLATFORM, object_type=object_type, operation="ADD",
                         lines=tuple(lines), expected={}, origin=origin, removal=removal)


# ===================================================================================================================== renderer
class RenderTests(SimpleTestCase):
    def test_render_table_never_accepts_a_device_source_port_22_outside_an_established_session(self):
        lines = [line.strip() for line in frr.render_table(TABLE, F.PORT, BOOT)]
        replies = [line for line in lines if line.startswith(f'iifname "{F.PORT}"') and "tcp sport 22" in line]
        self.assertEqual(replies, [f'iifname "{F.PORT}" ip saddr {BOOT["prefix"]} ip daddr {BOOT["service_address"]} '
                                   "tcp sport 22 ct state established,related accept"])

    def test_render_table_and_parse_table_round_trip_exactly(self):
        lines = frr.render_table(TABLE, F.PORT, BOOT)
        self.assertEqual(lines[0], f"table inet {TABLE} {{")
        self.assertEqual(frr.parse_table(lines), {"table": TABLE, "port": F.PORT, "bootstrap": BOOT})
        self.assertIn(f'    iifname "{F.PORT}" counter drop', lines)
        self.assertEqual(sum(1 for line in lines if "type filter hook" in line), 3)          # forward, input, output

    def test_parse_table_refuses_any_tampered_or_extra_line(self):
        lines = frr.render_table(TABLE, F.PORT, BOOT)
        widened = [line.replace("tcp dport 8080 accept", "accept") for line in lines]
        extra = [*lines[:-1], '  chain prerouting { type nat hook prerouting priority dstnat; }', lines[-1]]
        for bad in (widened, extra, lines[:-1], [line.replace(TABLE, "nmas_iso_x") for line in lines], []):
            self.assertIsNone(frr.parse_table(bad))

    def test_render_refuses_invalid_interface_table_and_ipv6_bootstrap(self):
        for port in ('eth4" accept', "a" * 16, ""):
            with self.assertRaises(frr.RenderError):
                frr.chain_rules(port, BOOT)
        with self.assertRaises(frr.RenderError):
            frr.render_table("other_table", F.PORT, BOOT)
        with self.assertRaises(frr.RenderError):
            frr.chain_rules(F.PORT, {**BOOT, "prefix": "2001:db8::/64"})
        with self.assertRaises(frr.RenderError):
            frr.table_name("R4")

    def test_render_exception_returns_its_code_as_message_and_keeps_the_detail(self):
        err = frr.RenderError("FRR_PORT_INVALID", "eth4")
        self.assertEqual((str(err), err.code, err.detail), ("FRR_PORT_INVALID", "FRR_PORT_INVALID", "eth4"))

    def test_frr_exception_refusal_bounds_a_long_detail_to_200_characters(self):
        err = frr.RenderError("FRR_TABLE_INVALID", "x" * 500)
        self.assertEqual((err.code, len(err.detail)), ("FRR_TABLE_INVALID", 200))
        self.assertIsInstance(err, ValueError)

    def test_delete_statement_and_parse_delete_accept_only_the_reserved_table(self):
        self.assertEqual(frr.parse_delete(frr.delete_statement(TABLE)), TABLE)
        self.assertIsNone(frr.parse_delete(["delete table inet filter"]))
        self.assertIsNone(frr.parse_delete(["delete table inet nmas_iso_dev000002", "flush ruleset"]))

    def test_render_release_inverts_render_apply(self):
        intent, ops, problems, _facts = build(F.FakeFrrUpstream())
        self.assertEqual(problems, [])
        release = frr.render_release(intent)[0]
        self.assertEqual((release["lines"], release["inverse"]), (ops[0]["inverse"], ops[0]["lines"]))
        self.assertEqual(ops[0]["platform"], frr.PLATFORM)


# ===================================================================================================================== intent
class BuildTests(SimpleTestCase):
    def codes(self, upstream):
        return [p["code"] for p in build(upstream)[2]]

    def test_build_plans_one_atomic_table_for_a_clean_routed_port(self):
        intent, ops, problems, facts = build(F.FakeFrrUpstream())
        self.assertEqual(problems, [])
        self.assertEqual([op["key"] for op in ops], ["nft-table"])
        self.assertEqual(intent["elements"]["PACKET_FILTER"]["table"], TABLE)
        self.assertEqual(intent["elements"]["CONTROL_PLANE"]["filtered_on_port"], ["OSPF"])   # eth4's OSPF hellos are dropped
        self.assertEqual(facts["relays"], [f"dhcrelay -4 -d -id {F.PORT} -iu eth2 {F.SERVICE}"])

    def test_build_refuses_a_port_without_a_relay_to_the_service(self):
        self.assertIn("ISOLATION_BOOTSTRAP_NETWORK_MISMATCH", self.codes(F.FakeFrrUpstream(relay=False)))

    def test_build_refuses_a_port_carrying_routes_or_the_default_route(self):
        learned = F.FakeFrrUpstream(routes4=[{"dst": "10.254.255.6", "dev": F.PORT, "protocol": "ospf"}])
        self.assertIn("ISOLATION_PORT_SHARED", self.codes(learned))
        default = F.FakeFrrUpstream(routes4=[{"dst": "default", "dev": F.PORT, "protocol": "static"}])
        self.assertIn("ISOLATION_PORT_SHARED", self.codes(default))

    def test_build_refuses_bridged_enslaved_or_subinterfaced_ports(self):
        enslaved = F.FakeFrrUpstream(links=[F.link(F.PORT, f"{F.GATEWAY}/24", master="br0")])
        self.assertIn("ISOLATION_PORT_NOT_ROUTED", self.codes(enslaved))
        child = F.FakeFrrUpstream(links=[F.link(F.PORT, f"{F.GATEWAY}/24"), F.link(f"{F.PORT}.10", kind="vlan", parent=F.PORT)])
        self.assertIn("ISOLATION_PORT_SHARED", self.codes(child))
        self.assertEqual(self.codes(F.FakeFrrUpstream(links=[F.link("eth9", "10.0.0.1/24")])), ["ISOLATION_PORT_NOT_FOUND"])

    def test_build_refuses_isis_foreign_tables_collisions_and_nmas_lockout(self):
        isis = F.FakeFrrUpstream(frr_text=F.FRR_TEXT.replace(" ip ospf area 0.0.0.10", " ip router isis CORE"))
        self.assertIn("ISOLATION_ROUTING_UNSUPPORTED", self.codes(isis))
        foreign = F.FakeFrrUpstream(extra_tables={"filter": 'table inet filter {\n chain input {\n  iifname "eth4" accept\n }\n}'})
        foreign.tables = {"filter": foreign.tables["filter"]}
        self.assertIn("ISOLATION_FOREIGN_ACL", self.codes(foreign))
        taken = F.FakeFrrUpstream()
        taken.tables[TABLE] = "\n".join(frr.render_table(TABLE, F.PORT, BOOT))
        self.assertIn("ISOLATION_NAME_COLLISION", self.codes(taken))
        locked = F.FakeFrrUpstream()
        locked.route_get[F.NMAS_SOURCE] = F.PORT
        self.assertIn("ISOLATION_MGMT_PLANE_EXPOSED", self.codes(locked))

    def test_build_refuses_when_the_kernel_capability_is_not_proven(self):
        upstream = F.FakeFrrUpstream()
        upstream.can["check"] = False
        self.assertEqual(set(self.codes(upstream)), {"ISOLATION_PLATFORM_NOT_IMPLEMENTED"})


# ===================================================================================================================== read-back
class FindingTests(SimpleTestCase):
    def enforced(self):
        upstream = F.FakeFrrUpstream()
        intent, ops, _problems, _facts = build(upstream)
        upstream.tables[TABLE] = "\n".join(ops[0]["lines"])
        return upstream, intent

    def test_config_findings_pass_for_the_exact_table_on_its_hooks(self):
        upstream, intent = self.enforced()
        rows = frr.config_findings(intent, snapshot(upstream), F.PORT)
        self.assertTrue(all(ok for ok, _code, _facts in rows.values()), rows)
        self.assertEqual(frr.presence(intent, snapshot(upstream)), {"nft-table": "PRESENT"})

    def test_config_findings_detect_a_deleted_rule_as_drift(self):
        upstream, intent = self.enforced()
        upstream.tables[TABLE] = upstream.tables[TABLE].replace(f'    iifname "{F.PORT}" counter drop\n', "", 1)
        ok, code, facts = frr.config_findings(intent, snapshot(upstream), F.PORT)["READ_BACK"]
        self.assertEqual((ok, code, facts["present"], facts["exact"]), (False, "ISOLATION_DRIFTED", True, False))
        self.assertEqual(frr.presence(intent, snapshot(upstream)), {"nft-table": "PARTIAL"})

    def test_config_findings_refuse_missing_hooks_and_absent_tables(self):
        upstream, intent = self.enforced()
        upstream.can["hooks"] = False
        self.assertFalse(frr.config_findings(intent, snapshot(upstream), F.PORT)["READ_BACK"][0])
        del upstream.tables[TABLE]
        self.assertEqual(frr.presence(intent, snapshot(upstream)), {"nft-table": "ABSENT"})

    def test_routing_findings_pass_without_adjacency_and_fail_on_a_neighbor_or_learned_route(self):
        upstream, intent = self.enforced()
        self.assertTrue(frr.routing_findings(intent, snapshot(upstream), F.PORT)[0])
        upstream.ospf_json = json.dumps({"neighbors": {"10.254.255.6": [{"ifaceName": f"{F.PORT}:10.254.30.1", "nbrState": "Full/DR"}]}})
        self.assertEqual(frr.routing_findings(intent, snapshot(upstream), F.PORT)[:2], (False, "ISOLATION_LEAK"))
        upstream.ospf_json = json.dumps({"neighbors": {}})
        upstream.routes6.append({"dst": "2001:db8:66::/64", "dev": F.PORT, "protocol": "ospf"})
        self.assertFalse(frr.routing_findings(intent, snapshot(upstream), F.PORT)[0])

    def test_deny_counters_and_neighbor_entry_read_the_upstreams_own_evidence(self):
        upstream, _intent = self.enforced()
        upstream.hit(TABLE, "forward", 5)
        upstream.hit(TABLE, "input", 2)
        self.assertEqual(frr.deny_counters(json.loads(upstream.table_json(TABLE))), {"forward": 5, "input": 2, "output": 0})
        rows = [{"dst": "10.254.30.10", "dev": F.PORT, "lladdr": "A2:27:1C:9A:B6:7B", "state": ["REACHABLE"]},
                {"dst": "10.254.30.11", "dev": F.PORT, "state": ["FAILED"]}]
        self.assertEqual(frr.neighbor_entry(rows, "10.254.30.10"), {"mac": "a2:27:1c:9a:b6:7b", "interface": F.PORT})
        self.assertEqual(frr.neighbor_entry(rows, "10.254.30.11"), {})


# ===================================================================================================================== executor
class ExecutorTests(SimpleTestCase):
    def setUp(self):
        self.upstream = F.FakeFrrUpstream()
        self.executor = FrrIsolationExecutor({"name": "R4", "platform": "linux"}, runner=self.upstream)
        self.lines = frr.render_table(TABLE, F.PORT, BOOT)

    def test_executor_apply_creates_the_table_atomically_and_compensation_restores_the_digest(self):
        before = self.executor.config_state_digest()
        add = spec(self.lines)
        assessment = self.executor.assess(add)
        self.assertEqual((assessment.action, assessment.restorable), (APPLY, True))
        self.assertTrue(self.executor.apply(add, assessment).ok)
        sent = [argv for argv in self.upstream.calls if argv[0] == "nft" and len(argv) == 2 and argv[1].startswith("table")]
        self.assertEqual(sent, [["nft", "\n".join(self.lines)]])                               # one argv token, one transaction
        self.assertEqual(self.executor.assess(add).action, SKIP_SATISFIED)                     # read-back: exactly ours
        self.assertEqual(self.executor.compensate(add, assessment).status, "COMPENSATED")
        self.assertEqual(self.executor.config_state_digest(), before)
        self.assertNotIn(TABLE, self.upstream.tables)

    def test_executor_never_merges_into_or_deletes_a_table_it_did_not_render(self):
        self.upstream.tables[TABLE] = "\n".join(self.lines).replace("tcp dport 8080", "tcp dport 8081")
        found = self.executor.assess(spec(self.lines))
        self.assertEqual((found.action, found.restorable), (APPLY, False))                    # never applied (not restorable)
        self.assertFalse(self.executor.apply(spec(self.lines), found).ok)
        removal = spec(frr.delete_statement(TABLE), object_type="config_removal_delete", origin="REMOVAL",
                       removal={"restore_lines": self.lines})
        self.assertEqual(self.executor.assess(removal).action, REFUSE)                         # drifted: its restore path is not the truth

    def test_executor_refuses_any_other_configlet_shape(self):
        for bad in (spec(["flush ruleset"]), spec(self.lines, origin="RAW"), spec(self.lines, object_type="nat_rule"),
                    spec(frr.delete_statement(TABLE), object_type="config_removal_delete", origin="REMOVAL", removal={})):
            self.assertEqual(self.executor.assess(bad).action, REFUSE)

    def test_executor_release_removes_and_its_compensation_recreates_the_exact_table(self):
        self.upstream.tables[TABLE] = "\n".join(self.lines)
        before = self.executor.config_state_digest()
        removal = spec(frr.delete_statement(TABLE), object_type="config_removal_delete", origin="REMOVAL", removal={"restore_lines": self.lines})
        assessment = self.executor.assess(removal)
        self.assertEqual((assessment.action, assessment.restorable), (APPLY, True))
        self.assertTrue(self.executor.apply(removal, assessment).ok)
        self.assertNotIn(TABLE, self.upstream.tables)
        self.assertEqual(self.executor.compensate(removal, assessment).status, "COMPENSATED")
        self.assertEqual(self.executor.config_state_digest(), before)

    def test_executor_connect_opens_the_authorized_session_and_closes_it_on_a_failed_probe(self):
        session = mock.Mock()
        session.run.return_value = (0, "")
        executor = FrrIsolationExecutor({"name": "R4"}, connector=lambda name, timeout: session)
        executor.connect()
        session.run.assert_called_with(["nft", "list", "ruleset"], mock.ANY)
        executor.close()
        session.close.assert_called_once()
        failing = mock.Mock()
        failing.run.return_value = (1, "sudo: a password is required")
        refused = FrrIsolationExecutor({"name": "R4"}, connector=lambda name, timeout: failing)
        with self.assertRaises(ExecutorError) as raised:
            refused.connect()
        self.assertEqual(raised.exception.code, "PREVIOUS_STATE_UNAVAILABLE")
        failing.close.assert_called_once()
        with self.assertRaises(ExecutorError):
            FrrIsolationExecutor({"name": ""}).connect()


# ===================================================================================================================== transport
INVENTORY = {"network_devices": {"R4": {"username": "nmas-svc", "ssh_key_ref": "runtime://device-credentials/r4-svc",
                                        "ssh_host_key": "SHA256:" + "A" * 43,
                                        "monitoring": {"platform": "linux", "address": "192.168.200.4", "source_interface": "Vlan200"}}}}


class TransportTests(SimpleTestCase):
    def test_command_line_quotes_every_token_and_elevates_only_nft_and_vtysh(self):
        self.assertEqual(linux_ssh.command_line(["nft", "table inet x { }"], "nmas-svc"), "sudo -n -- nft 'table inet x { }'")
        self.assertEqual(linux_ssh.command_line(["vtysh", "-c", "show run"], "nmas-svc"), "sudo -n -- vtysh -c 'show run'")
        self.assertEqual(linux_ssh.command_line(["ip", "-j", "neigh", "show"], "nmas-svc"), "ip -j neigh show")
        self.assertEqual(linux_ssh.command_line(["nft", "list", "ruleset"], "root"), "nft list ruleset")
        self.assertEqual(linux_ssh.command_line(["ip", "$(reboot)"], "nmas-svc"), "ip '$(reboot)'")
        # the atomic ruleset is ONE multi-line token (found live: refusing newlines made every capability probe fail)
        ruleset = "table inet t {\n  chain c {\n    iifname \"lo\" drop\n  }\n}"
        line = linux_ssh.command_line(["nft", "-c", ruleset], "nmas-svc")
        self.assertEqual(line, "sudo -n -- nft -c '" + ruleset + "'")
        self.assertEqual(shlex.split(line), ["sudo", "-n", "--", "nft", "-c", ruleset])

    def test_command_line_refuses_empty_argv_nul_bytes_and_non_strings(self):
        for argv in ([], ["nft", "a\x00"], ["nft", 3]):
            with self.assertRaises(ExecutorError):
                linux_ssh.command_line(argv, "nmas-svc")

    def test_frr_show_builds_one_read_only_query(self):
        self.assertEqual(linux_ssh.frr_show("show running-config"), ["vtysh", "-c", "show running-config"])
        self.assertEqual(linux_ssh.frr_show("show ipv6 ospf6 neighbor json"), ["vtysh", "-c", "show ipv6 ospf6 neighbor json"])

    def test_frr_show_refuses_configuration_chaining_and_metacharacters(self):
        for command in ("configure terminal", "show run\nconf t", "show run; reboot", "show run | write", "show $(id)",
                        "show  run", "show", "write memory", "show run\x00", None, ["show run"]):
            with self.subTest(command=command), self.assertRaises(ExecutorError):
                linux_ssh.frr_show(command)

    def test_frr_isolation_executor_spells_no_frr_shell_argv(self):
        """The executor reads FRR only through ``linux_ssh.frr_show``; it never builds a vtysh argv of its own."""
        import inspect

        from core.services.execution.executors import frr_isolation
        self.assertIn("linux_ssh.frr_show(", inspect.getsource(frr_isolation))
        self.assertNotIn("vtysh", inspect.getsource(frr_isolation))

    def meta(self, **overrides):
        return {"device_name": "R4", "platform": "linux", "address": "192.168.200.4", "username": "nmas-svc",
                "ssh_key_ref": "runtime://device-credentials/r4-svc", "management": {"source": "LEGACY"}, **overrides}

    def test_target_resolves_a_writable_linux_device_with_a_pinned_host_key(self):
        with mock.patch("core.services.nsot_live.get_live_target_metadata", return_value=self.meta()), \
                mock.patch("core.services.nsot_live._load_inventory", return_value=INVENTORY):
            found = linux_ssh.target("R4")
        self.assertEqual((found["address"], found["username"], found["host_key"], found["port"]),
                         ("192.168.200.4", "nmas-svc", "SHA256:" + "A" * 43, 22))

    def test_target_refuses_without_a_pin_key_reference_linux_platform_or_legacy_source(self):
        cases = [(self.meta(), {"ssh_host_key": ""}), (self.meta(), {"ssh_host_key": "MD5:aa"}), (self.meta(ssh_key_ref=""), {}),
                 (self.meta(platform="ceos"), {}), (self.meta(management={"source": "PATH"}), {}), (None, {})]
        for meta, entry in cases:
            inventory = {"network_devices": {"R4": {**INVENTORY["network_devices"]["R4"], **entry}}}
            with mock.patch("core.services.nsot_live.get_live_target_metadata", return_value=meta), \
                    mock.patch("core.services.nsot_live._load_inventory", return_value=inventory), self.assertRaises(ExecutorError) as raised:
                linux_ssh.target("R4")
            self.assertEqual(raised.exception.code, "NOT_CONFIGURED")

    def test_connect_maps_a_host_key_mismatch_and_bad_credentials_to_sanitized_codes(self):
        import paramiko

        found = {"address": "192.168.200.4", "username": "nmas-svc", "ssh_key_ref": "runtime://x", "host_key": "SHA256:" + "A" * 43, "port": 22}
        for raised, code in ((paramiko.SSHException("HOST_KEY_MISMATCH"), "CONNECTION_FAILED"),
                             (paramiko.AuthenticationException("no"), "AUTH_FAILED"), (OSError("unreachable"), "CONNECTION_FAILED")):
            with mock.patch.object(linux_ssh, "target", return_value=found), \
                    mock.patch("modules.device_credentials.load_ssh_private_key", return_value=object()), \
                    mock.patch.object(paramiko.SSHClient, "connect", side_effect=raised), self.assertRaises(ExecutorError) as caught:
                linux_ssh.connect("R4", timeout=1)
            self.assertEqual(caught.exception.code, code)

    def test_pinned_policy_refuses_a_different_host_key_before_authentication(self):
        import paramiko

        captured = {}

        def fake_connect(client, *args, **kwargs):
            captured["policy"] = client._policy                     # pylint: disable=protected-access
            raise OSError("stop")

        found = {"address": "192.168.200.4", "username": "nmas-svc", "ssh_key_ref": "runtime://x", "host_key": "SHA256:" + "A" * 43, "port": 22}
        with mock.patch.object(linux_ssh, "target", return_value=found), \
                mock.patch("modules.device_credentials.load_ssh_private_key", return_value=object()), \
                mock.patch.object(paramiko.SSHClient, "connect", autospec=True, side_effect=fake_connect), self.assertRaises(ExecutorError):
            linux_ssh.connect("R4", timeout=1)
        with self.assertRaises(paramiko.SSHException):                         # any key whose SHA256 differs from the pin
            captured["policy"].missing_host_key(None, "192.168.200.4", paramiko.RSAKey.generate(1024))


# ===================================================================================================================== service
class ServiceTests(Z.ZtpTestMixin, TestCase):
    real_isolation_gate = True

    def setUp(self):
        super().setUp()
        self.upstream = F.FakeFrrUpstream()
        self.access = F.access(self.upstream)
        L.adopt("R4", role="router")
        self.device = L.register().device
        result = L.attach(self.device, upstream="R4", port=F.PORT, vlan=None, connectivity=models.AttachmentConnectivity.ROUTED)
        self.assertTrue(result.ok, result.codes)
        self.attachment = result.attachment
        self.network = self.network(relays=[{"relay_address": Z.RELAY, "upstream_device": "R4"}])

    def table(self, policy):
        return policy.intent["elements"]["PACKET_FILTER"]["table"]

    def approved(self):
        required = iso.require(self.device, self.attachment, network=self.network, actor=L.OPERATOR)
        self.assertTrue(required.ok, required.codes)
        self.assertEqual(required.policy.upstream_platform, models.Platform.UBUNTU_FRR)
        planned = iso.plan(required.policy, actor=L.OPERATOR, access=self.access)
        self.assertTrue(planned.ok, (planned.codes, planned.policy.failure))
        self.assertTrue(iso.precheck(planned.policy, actor=L.OPERATOR, access=self.access).ok)
        policy = models.IsolationPolicy.objects.get(pk=planned.policy.pk)
        self.assertIn("ISOLATION_SELF_APPROVAL", iso.approve(policy, actor=L.OPERATOR, confirmation=policy.plan_hash).codes)
        approved = iso.approve(policy, actor=L.APPROVER, confirmation=policy.plan_hash)
        self.assertTrue(approved.ok, approved.codes)
        return approved.policy

    def enforced(self):
        policy = self.approved()
        applied = iso.apply(policy, actor=L.APPROVER, confirmation=policy.plan_hash, access=self.access)
        self.assertTrue(applied.ok, (applied.codes, applied.detail.get("report", {}).get("failure")))
        return applied.policy

    def traffic(self, policy):
        def run(_policy, _with_device):
            self.upstream.hit(self.table(policy), "forward", 4)
            return [{"flow": "device -> production", "expect": "DENY", "observed": "DENY"},
                    {"flow": "device -> bootstrap http", "expect": "PERMIT", "observed": "PERMIT"}]
        return run

    def test_isolation_on_an_frr_upstream_plans_applies_and_verifies_through_the_governed_transaction(self):
        policy = self.enforced()
        self.assertEqual(policy.state, St.ENFORCED)
        self.assertIn(self.table(policy), self.upstream.tables)
        self.assertEqual(iso.upstream_device(policy), {"name": "R4", "platform": "linux"})        # no container anywhere
        verified = iso.verify(policy, actor=L.APPROVER, access=self.access, traffic=self.traffic(policy))
        self.assertTrue(verified.ok, verified.codes)
        self.assertEqual(verified.policy.state, St.VERIFIED)
        counters = models.IsolationCheck.objects.filter(policy=policy, kind=models.IsolationCheckKind.TRAFFIC).latest("id").facts
        self.assertEqual(counters["deny_counter_delta"], {"forward": 4, "input": 0, "output": 0})

    def test_isolation_on_an_frr_upstream_fault_after_the_write_is_compensated_exactly(self):
        policy = self.approved()
        before = dict(self.upstream.tables)

        def observer(event, key):
            if event == "after" and key == "nft-table":
                raise RuntimeError("fault")

        applied = iso.apply(policy, actor=L.APPROVER, confirmation=policy.plan_hash, access=self.access, observer=observer)
        self.assertFalse(applied.ok)
        self.assertEqual((applied.detail["outcome"], applied.policy.state), ("FAILED_ROLLED_BACK", St.REQUIRED))
        self.assertEqual(self.upstream.tables, before)

    def test_isolation_on_an_frr_upstream_drift_is_detected_and_never_reapplied(self):
        policy = self.enforced()
        table = self.table(policy)
        self.upstream.tables[table] = self.upstream.tables[table].replace(f'    oifname "{F.PORT}" counter drop\n', "", 1)
        drifted_listing = self.upstream.tables[table]
        drifted = iso.check_drift(policy, actor=L.APPROVER, access=self.access)
        self.assertFalse(drifted.ok)
        self.assertEqual(drifted.policy.state, St.DRIFTED)
        self.assertEqual(self.upstream.tables[table], drifted_listing)                           # nothing was re-applied
        self.assertFalse(any(argv[:1] == ["nft"] and len(argv) == 2 and argv[1].startswith("table") for argv in self.upstream.calls[-40:]))

    def test_isolation_on_an_frr_upstream_release_with_failed_admission_restores_the_table(self):
        policy = self.enforced()
        verified = iso.verify(policy, actor=L.APPROVER, access=self.access, traffic=self.traffic(policy))
        created = iso.create_release(verified.policy, actor=L.OPERATOR, reference={"test": True})
        self.assertTrue(created.ok, created.codes)
        self.assertTrue(iso.release_precheck(created.policy, actor=L.OPERATOR, access=self.access).ok)
        policy = models.IsolationPolicy.objects.get(pk=policy.pk)
        self.assertTrue(iso.approve_release(policy, actor=L.APPROVER, requested_by=L.OPERATOR, confirmation=created.detail["plan_hash"], extra={}).ok)
        listing = self.upstream.tables[self.table(policy)]
        released = iso.execute_release(policy, actor=L.APPROVER, confirmation=created.detail["plan_hash"], access=self.access,
                                       verify_admission=lambda executor: [{"check": "ospf_adjacency", "detail": "absent"}])
        self.assertFalse(released.ok)
        self.assertEqual(released.policy.state, St.ENFORCED)
        self.assertEqual(self.upstream.tables[self.table(policy)], listing)

    def test_isolation_on_an_frr_upstream_release_with_proven_admission_removes_the_table(self):
        policy = self.enforced()
        verified = iso.verify(policy, actor=L.APPROVER, access=self.access, traffic=self.traffic(policy))
        created = iso.create_release(verified.policy, actor=L.OPERATOR, reference={"test": True})
        self.assertTrue(iso.release_precheck(created.policy, actor=L.OPERATOR, access=self.access).ok)
        policy = models.IsolationPolicy.objects.get(pk=policy.pk)
        self.assertTrue(iso.approve_release(policy, actor=L.APPROVER, requested_by=L.OPERATOR, confirmation=created.detail["plan_hash"], extra={}).ok)
        released = iso.execute_release(policy, actor=L.APPROVER, confirmation=created.detail["plan_hash"], access=self.access,
                                       verify_admission=lambda executor: [])
        self.assertTrue(released.ok, released.codes)
        self.assertEqual(released.policy.state, St.RELEASED)
        self.assertNotIn(self.table(policy), self.upstream.tables)

    def test_require_refuses_an_upstream_platform_without_an_isolation_implementation(self):
        from core.services.devices import resolver

        real = resolver.resolve

        def as_srlinux(*args, **kwargs):
            found = real(*args, **kwargs)
            return dataclasses.replace(found, platform=models.Platform.NOKIA_SRLINUX) if found is not None else None

        with mock.patch.object(resolver, "resolve", side_effect=as_srlinux):
            problems = iso.require_problems(self.device, self.attachment, self.network)
        self.assertIn("ISOLATION_PLATFORM_NOT_IMPLEMENTED", [p["code"] for p in problems])

    def test_frr_failures_reads_admission_adjacency_and_routes_on_the_port(self):
        policy = self.enforced()
        executor = FrrIsolationExecutor({"name": "R4"}, runner=self.upstream)
        wanted = {"routing": "OSPF", "ospf_neighbors": ["10.254.255.6"], "routes_v4": ["10.254.255.6/32"], "routes_v6": ["2001:db8:66::/64"]}
        self.assertEqual({row["check"] for row in admission.frr_failures(executor, policy, wanted)}, {"ospf_adjacency", "routes_v4", "routes_v6"})
        self.upstream.ospf_json = json.dumps({"neighbors": {"10.254.255.6": [{"ifaceName": f"{F.PORT}:{F.GATEWAY}", "nbrState": "Full/DR"}]}})
        self.upstream.routes4.append({"dst": "10.254.255.6", "dev": F.PORT, "protocol": "ospf"})
        self.upstream.routes6.append({"dst": "2001:db8:66::/64", "dev": F.PORT, "protocol": "ospf"})
        self.assertEqual(admission.frr_failures(executor, policy, wanted), [])
        self.assertEqual(admission.failures(executor, policy, wanted), [])

    def test_frr_failures_reads_the_ospf6d_adjacency_for_ospfv3_expectations(self):
        """V2 Phase 9 (D): an OSPFv3 expectation on an Ubuntu/FRR upstream is read from ospf6d (the FRR snapshot), never EOS."""
        policy = self.enforced()
        executor = FrrIsolationExecutor({"name": "R4"}, runner=self.upstream)
        wanted = {"routing": "OSPFV3", "ospfv3_neighbors": ["10.254.255.6"], "routes_v6": ["2001:db8:66::/64"]}
        self.assertEqual({row["check"] for row in admission.failures(executor, policy, wanted)}, {"ospfv3_adjacency", "routes_v6"})
        self.upstream.ospf6_json = json.dumps({"neighbors": [{"neighborId": "10.254.255.6", "interfaceName": F.PORT, "state": "Full"}]})
        self.upstream.routes6.append({"dst": "2001:db8:66::/64", "dev": F.PORT, "protocol": "ospf"})
        self.assertEqual(admission.failures(executor, policy, wanted), [])
        self.upstream.ospf6_json = json.dumps({"neighbors": [{"neighborId": "10.254.255.6", "interfaceName": F.PORT, "state": "ExStart"}]})
        self.assertEqual([row["check"] for row in admission.frr_failures(executor, policy, wanted)], ["ospfv3_adjacency"])
