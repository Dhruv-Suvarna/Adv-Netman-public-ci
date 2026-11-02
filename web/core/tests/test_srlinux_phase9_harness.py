"""V2 Phase 9 -- the isolated SR Linux routing / ACL / DHCP-relay harness (``batch_srlinux_phase9``), each function called
directly with fakes (no Docker, no gNMI, no FRR peer).

POSITIVE: the planner-built Configlets, seeds, intent adjustments, import and preservation checks, peer preparation,
behaviour verdicts and the recorded stages are exactly what the live recording relies on.  NEGATIVE: a missing intent,
an absent seed, a peer that already runs FRR or holds RA routes, a rejected peer command, an unanswered DHCP exchange,
a held route or a non-exact compensation each turn into a False verdict, a raised error or a FAIL stage -- never a pass.
"""

from __future__ import annotations

from types import SimpleNamespace
from unittest import mock

from django.test import SimpleTestCase

from core.services import srlinux_model as model
from core.services.capabilities import batch_frr_routing
from core.services.capabilities import batch_srlinux_phase9 as P
from core.services.execution.executors.base import CompensationOutcome


def _tree(*groups) -> dict:
    """A running tree the way the device builds it: each group of statements merged in order, a leaf-list widened by the
    members already held (what ``SrLinuxExecutor`` sends)."""
    tree: dict = {}
    for lines in groups:
        for op in model.additive(model.operations(lines), tree):
            model.apply_operation(tree, op)
    return tree


def _applied(key: str, seed=True) -> dict:
    prerequisites, specs, _req, _sections = P.plan(key)
    return _tree(prerequisites, P.seeds(key) if seed else (), *(spec.lines for spec in specs))


class _Observed:
    def __init__(self, **facts):
        self._facts, self.live_reachable = facts, True

    def facts(self, name):
        return self._facts.get(name)


class _Lab:
    def __init__(self, peer_text="", pings=None, client=""):
        self.peer_text, self.pings, self.client = peer_text, pings or {}, client
        self.configured, self.pid, self.device, self.session_factory = [], "4242", {"name": "srl"}, None

    def peer_show(self, _command):
        return self.peer_text

    def peer_config(self, *commands):
        self.configured.append(commands)

    def source_ping(self, _target, source):
        return self.pings.get(source, False)

    def peer_ns(self, *_argv, timeout=20):
        return SimpleNamespace(stdout=self.client, returncode=0)


class SrlPhase9FamilyAndSeedTests(SimpleTestCase):
    def test_family_returns_the_address_family_of_each_cell(self):
        self.assertEqual([P.family(k) for k in ("routing.OSPFV2", "routing.OSPFV3", "routing.BGP_IPV6", "service_policy.ACL_IPV4_STANDARD",
                                                 "service_policy.DHCP_RELAY_IPV6")], ["IPV4", "IPV6", "IPV6", "IPV4", "IPV6"])

    def test_family_of_a_key_without_a_feature_code_raises(self):
        with self.assertRaises(IndexError):
            P.family("routing")

    def test_static_returns_a_route_and_its_next_hop_group(self):
        self.assertEqual(P._static("192.0.2.0/24", "198.18.0.2", "g1"),   # pylint: disable=protected-access
                         ("set / network-instance default static-routes route 192.0.2.0/24 next-hop-group g1",
                          "set / network-instance default next-hop-groups group g1 nexthop 1 ip-address 198.18.0.2"))

    def test_static_without_a_group_names_no_other_group_than_the_anchor(self):
        lines = P._static("2001:db8:99::/64", "2001:db8:44::2")   # pylint: disable=protected-access
        self.assertTrue(all(P.ANCHOR_GROUP in line for line in lines))

    def test_seed_loopback_returns_an_ipv6_loopback_bound_to_the_default_instance(self):
        lines = P._seed_loopback("IPV6")   # pylint: disable=protected-access
        self.assertIn("set / interface lo44 subinterface 0 ipv6 address 2001:db8:7::1/128", lines)
        self.assertEqual(lines[-1], "set / network-instance default interface lo44.0")

    def test_seed_loopback_of_a_non_ipv6_family_holds_no_ipv6_address(self):
        lines = P._seed_loopback("IPV4")   # pylint: disable=protected-access
        self.assertIn("set / interface lo44 subinterface 0 ipv4 address 198.18.7.1/32", lines)
        self.assertFalse(any("ipv6" in line for line in lines))

    def test_seed_ospf_returns_a_v3_instance_with_a_passive_loopback(self):
        lines = P._seed_ospf("IPV6")   # pylint: disable=protected-access
        self.assertIn("set / network-instance default protocols ospf instance 44 version ospf-v3", lines)
        self.assertIn("set / network-instance default protocols ospf instance 44 address-family ipv6-unicast", lines)
        self.assertEqual(lines[-1], "set / network-instance default protocols ospf instance 44 area 0.0.0.0 interface lo44.0 passive true")

    def test_seed_ospf_of_ipv4_has_no_address_family_line(self):
        lines = P._seed_ospf("IPV4")   # pylint: disable=protected-access
        self.assertIn("set / network-instance default protocols ospf instance 44 version ospf-v2", lines)
        self.assertFalse(any("address-family" in line for line in lines))

    def test_seed_bgp_returns_an_unrelated_ipv6_peer(self):
        lines = P._seed_bgp("IPV6")   # pylint: disable=protected-access
        self.assertIn("set / network-instance default protocols bgp neighbor 2001:db8:9::9 peer-as 65099", lines)
        self.assertIn("set / network-instance default protocols bgp afi-safi ipv6-unicast admin-state enable", lines)

    def test_seed_bgp_of_ipv4_names_no_ipv6_peer(self):
        lines = P._seed_bgp("IPV4")   # pylint: disable=protected-access
        self.assertIn("set / network-instance default protocols bgp neighbor 198.18.9.9 peer-group legacy", lines)
        self.assertFalse(any("2001:" in line for line in lines))

    def test_seed_acl_returns_an_unrelated_ipv6_filter(self):
        self.assertEqual(P._seed_acl("IPV6"), (   # pylint: disable=protected-access
            "set / acl acl-filter LEGACY type ipv6 entry 10 match ipv6 source-ip prefix 2001:db8:51::/64",
            "set / acl acl-filter LEGACY type ipv6 entry 10 action drop"))

    def test_seed_acl_of_ipv4_holds_no_ipv6_filter(self):
        self.assertFalse(any("ipv6" in line for line in P._seed_acl("IPV4")))   # pylint: disable=protected-access

    def test_seed_dhcp_returns_a_relay_to_another_server(self):
        self.assertEqual(P._seed_dhcp("IPV4")[-1], f"set / interface {P.PORT} subinterface 0 ipv4 dhcp-relay server [ 192.0.2.99 ]")   # pylint: disable=protected-access

    def test_seed_dhcp_of_ipv6_names_no_ipv4_server(self):
        self.assertTrue(P._seed_dhcp("IPV6")[-1].endswith("ipv6 dhcp-relay server [ 2001:db8:99::99 ]"))   # pylint: disable=protected-access

    def test_seeds_returns_the_related_configuration_of_each_feature(self):
        self.assertEqual(P.seeds("routing.OSPFV3"), P._seed_ospf("IPV6"))   # pylint: disable=protected-access
        self.assertEqual(P.seeds("routing.BGP_IPV4"), P._seed_bgp("IPV4"))   # pylint: disable=protected-access
        self.assertEqual(P.seeds("service_policy.ACL_ATTACH_IPV6"), P._seed_acl("IPV6"))   # pylint: disable=protected-access
        self.assertEqual(P.seeds("service_policy.DHCP_RELAY_IPV4"), P._seed_dhcp("IPV4"))   # pylint: disable=protected-access

    def test_seeds_of_a_key_without_a_feature_code_raises(self):
        with self.assertRaises(IndexError):
            P.seeds("service_policy")

    def test_preserved_matches_the_seed_after_the_cell_is_applied(self):
        for key in P.CELLS:
            with self.subTest(key=key):
                self.assertTrue(P.preserved(key, _applied(key)))

    def test_preserved_is_false_without_the_seed(self):
        for key in P.CELLS:
            with self.subTest("seed missing", key=key):
                self.assertFalse(P.preserved(key, _applied(key, seed=False)))


class SrlPhase9IntentAndPlanTests(SimpleTestCase):
    def test_ace_returns_an_entry_with_the_requested_fields(self):
        row = P._ace({"id": "x", "action": "PERMIT"}, 15, protocol="TCP", logging=True)   # pylint: disable=protected-access
        self.assertEqual((row["id"], row["sequence"], row["protocol"], row["logging"], row["action"]),
                         ("ace_0000000000000015", 15, "TCP", True, "PERMIT"))

    def test_ace_without_overrides_has_no_ports_and_no_logging(self):
        row = P._ace({}, 7)   # pylint: disable=protected-access
        self.assertEqual((row["source_port"], row["destination_port"], row["logging"], row["protocol"], row["destination_type"]),
                         ("", "", False, "IP", "ANY"))

    def test_intent_builds_an_extended_acl_with_protocol_port_and_logging_entries(self):
        sections = P.intent("service_policy.ACL_IPV6_EXTENDED")
        acl = next(iter(sections["security"]["acls"].values()))
        entries = sorted(acl["entries"].values(), key=lambda e: e["sequence"])
        self.assertEqual([(e["sequence"], e["action"], e["protocol"]) for e in entries],
                         [(10, "DENY", "ICMPV6"), (15, "DENY", "TCP"), (20, "PERMIT", "IP")])
        self.assertEqual((entries[1]["source_port"], entries[1]["destination_port"], entries[1]["logging"]), ("1024-2048", "80", True))
        (attachment,) = sections["security"]["attachments"].values()
        self.assertEqual((attachment["acl_id"], attachment["direction"]), (acl["id"], "IN"))

    def test_intent_of_a_standard_acl_has_no_protocol_entries(self):
        acl = next(iter(P.intent("service_policy.ACL_IPV4_STANDARD")["security"]["acls"].values()))
        self.assertEqual({e["protocol"] for e in acl["entries"].values()}, {"IP"})
        self.assertEqual(next(iter(acl["entries"].values()))["source_value"], "198.18.0.66")

    def test_intent_points_the_dhcp_relay_at_the_lab_server(self):
        relay = next(iter(P.intent("service_policy.DHCP_RELAY_IPV6")["services"]["dhcp"]["relays"].values()))
        self.assertEqual(relay["destination"], "2001:db8:99::1")

    def test_intent_of_a_routing_cell_adds_no_acl_attachment(self):
        self.assertNotIn("attach_0000000000000003", (P.intent("routing.OSPFV2").get("security") or {}).get("attachments") or {})

    def test_planner_context_builds_a_device_context_over_the_intent(self):
        ctx = P.planner_context(P.intent("routing.BGP_IPV4"))
        self.assertEqual((ctx.name, ctx.platform, ctx.hostname), ("srl", P.PLATFORM, "srl"))
        self.assertTrue(ctx.routing["bgp"])
        self.assertEqual(set(ctx.phase12), {"fhrp", "nat", "services", "security", "policy"})

    def test_planner_context_without_routing_has_empty_routing(self):
        ctx = P.planner_context({"interfaces": {"i": {"id": "i"}}})
        self.assertEqual((ctx.routing, ctx.phase12["security"], ctx.auto), ({}, {}, {}))

    def test_nodes_returns_the_planner_objects_in_engine_order(self):
        sections = P.intent("routing.BGP_IPV6")
        self.assertEqual([n["type"] for n in P._nodes("routing.BGP_IPV6", sections)], ["routing_bgp", "bgp_neighbor", "bgp_network"])   # pylint: disable=protected-access
        self.assertEqual([n["type"] for n in P._nodes("routing.OSPFV2", P.intent("routing.OSPFV2"))], ["routing_ospf", "routing_binding"])   # pylint: disable=protected-access
        self.assertEqual([n["type"] for n in P._nodes("service_policy.ACL_ATTACH_IPV4", P.intent("service_policy.ACL_ATTACH_IPV4"))],   # pylint: disable=protected-access
                         ["acl", "acl_attachment"])

    def test_nodes_of_an_intent_without_relays_is_empty(self):
        self.assertEqual(P._nodes("service_policy.DHCP_RELAY_IPV4", {"services": {"dhcp": {"relays": {}}}}), [])   # pylint: disable=protected-access

    def test_executor_spec_builds_an_srlinux_configlet(self):
        planned = SimpleNamespace(object_type="acl", lines=("set acl acl-filter A type ipv4",), facts={"name": "A"},
                                  object_class=SimpleNamespace(operation=SimpleNamespace(value="CREATE_DEFINE")))
        spec = P._executor_spec(2, planned)   # pylint: disable=protected-access
        self.assertEqual((spec.cfg_id, spec.platform, spec.object_type, spec.operation, spec.lines, spec.expected),
                         ("P9-SRL-acl-2", P.PLATFORM, "acl", "CREATE_DEFINE", ("set acl acl-filter A type ipv4",), {"name": "A"}))

    def test_executor_spec_never_keeps_comment_or_blank_lines(self):
        planned = SimpleNamespace(object_type="dhcp_relay", lines=("! note", "  ", "# hash", "set x y"), facts={},
                                  object_class=SimpleNamespace(operation="ACTIVATE_ATTACH"))
        spec = P._executor_spec(1, planned)   # pylint: disable=protected-access
        self.assertEqual((spec.lines, spec.operation), (("set x y",), "ACTIVATE_ATTACH"))

    def test_plan_returns_the_planner_configlets_and_lab_prerequisites(self):
        prerequisites, specs, requirements, _sections = P.plan("service_policy.DHCP_RELAY_IPV4")
        self.assertEqual(prerequisites[-2:], list(P._static("192.0.2.0/24", "198.18.0.2")))   # pylint: disable=protected-access
        self.assertEqual([s.lines for s in specs], [("set interface ethernet-1/1 subinterface 0 ipv4 dhcp-relay admin-state enable",
                                                     "set interface ethernet-1/1 subinterface 0 ipv4 dhcp-relay server [ 192.0.2.1 ]")])
        self.assertEqual(len(requirements), 1)
        _pre, bgp, _req, _sec = P.plan("routing.BGP_IPV4")
        self.assertEqual([s.object_type for s in bgp], ["routing_bgp", "bgp_neighbor", "bgp_neighbor_af", "bgp_network"])

    def test_plan_of_an_unknown_feature_raises(self):
        with self.assertRaises(KeyError):
            P.plan("routing.HOLOGRAM")


class SrlPhase9ImportTests(SimpleTestCase):
    def test_ace_view_returns_extended_facts_with_any_protocol_unified(self):
        row = {"sequence": "15", "action": "DENY", "source_type": "ANY", "source_value": None, "protocol": "ipv6",
               "destination_type": "HOST", "destination_value": "2001:db8:44::1", "source_port": "1024-2048", "destination_port": 80,
               "logging": 1}
        self.assertEqual(P._ace_view(row, "IPV6", True),   # pylint: disable=protected-access
                         (15, "DENY", "ANY", "", "IP", "HOST", "2001:db8:44::1", "1024-2048", "80", True))
        self.assertEqual(P._ace_view({"protocol": "ICMP"}, "IPV6", True)[4], "ICMPV6")   # pylint: disable=protected-access

    def test_ace_view_of_a_standard_entry_has_no_protocol_or_ports(self):
        self.assertEqual(P._ace_view({"sequence": 10, "action": "PERMIT", "protocol": "TCP", "source_port": "80"}, "IPV4", False),   # pylint: disable=protected-access
                         (10, "PERMIT", None, ""))

    def test_imported_matches_every_cell_applied_to_the_running_tree(self):
        for key in P.CELLS:
            with self.subTest(key=key):
                self.assertTrue(P.imported(key, P.plan(key)[3], _applied(key, seed=False)))

    def test_imported_is_false_when_the_intent_is_missing(self):
        for key in P.CELLS:
            with self.subTest("intent missing", key=key):
                self.assertFalse(P.imported(key, P.plan(key)[3], _tree(P.plan(key)[0])))

    def test_imported_is_false_for_an_acl_attached_in_the_wrong_direction(self):
        key = "service_policy.ACL_IPV4_STANDARD"
        tree = _applied(key, seed=False)
        tree["acl"]["interface"][0]["output"] = tree["acl"]["interface"][0].pop("input")
        self.assertFalse(P.imported(key, P.plan(key)[3], tree))


class SrlPhase9LabTests(SimpleTestCase):
    """``SrlPhase9Lab`` over a mocked base lab and container calls."""

    def _lab(self, alive=False, daemons="zebra ospfd ospf6d bgpd", ra_routes="fe80::/64 proto kernel metric 256", pid=777):
        calls, closed = [], []

        def call(_container, *argv):
            calls.append(argv)
            if argv[:4] == ("ip", "-6", "route", "show"):
                return SimpleNamespace(stdout=ra_routes, returncode=0)
            if argv[:3] == ("ip", "-j", "link"):
                return SimpleNamespace(stdout='[{"mtu": 9500}]', returncode=0)
            if argv[:1] == ("vtysh",) and "show daemons" in argv:
                return SimpleNamespace(stdout=daemons, returncode=0)
            if argv[:1] == ("vtysh",) and argv[-1] == "bad":
                return SimpleNamespace(stdout="% Unknown command", returncode=0)
            return SimpleNamespace(stdout="ok", returncode=0)

        def run(argv, timeout=10):
            calls.append(tuple(argv))
            if argv[:2] == ["docker", "inspect"]:
                return SimpleNamespace(stdout=f'[{{"State": {{"Pid": {pid}}}}}]', returncode=0)
            return SimpleNamespace(stdout="3 packets transmitted, 3 received, 0% packet loss", returncode=0)

        def base_init(self):
            self.peer, self.undo, self.peer_links = "clab-nmas-cap-validation-peer", [], []

        def base_close(_self):
            closed.append(True)
            return True

        patches = [mock.patch.object(P.SrlLab, "__init__", base_init), mock.patch.object(P, "_call", side_effect=call),
                   mock.patch.object(P, "_run", side_effect=run), mock.patch.object(P.SrlLab, "prepare_peer"),
                   mock.patch.object(P.SrlLab, "close", base_close), mock.patch.object(P.FrrPair, "alive", return_value=alive),
                   mock.patch.object(P.FrrPair, "must"), mock.patch.object(P.time, "sleep")]
        for patch in patches:
            patch.start()
            self.addCleanup(patch.stop)
        return calls, closed

    def test_lab_init_starts_the_protocol_daemons_and_close_restores_the_mtu(self):
        calls, closed = self._lab()
        lab = P.SrlPhase9Lab("routing.OSPFV3")
        self.assertEqual((lab.started, lab.mtu, lab.pid), (["zebra", "ospf6d"], "9500", "777"))
        plan = P.SrlLab.prepare_peer.call_args[0][0]
        self.assertIn(("link", "add", P.PEER_DUMMY, "type", "dummy"), plan)
        self.assertTrue(lab.close())
        self.assertIn(("pkill", "-x", "ospf6d"), calls)
        self.assertIn(("ip", "link", "set", "dev", P.PEER_DEV, "mtu", "9500"), calls)
        self.assertEqual((lab.started, closed), ([], [True]))

    def test_lab_init_of_an_acl_cell_adds_the_denied_source_and_starts_no_daemon(self):
        self._lab()
        lab = P.SrlPhase9Lab("service_policy.ACL_IPV6_STANDARD")
        plan = P.SrlLab.prepare_peer.call_args[0][0]
        self.assertEqual((lab.daemons, lab.started), ((), []))
        self.assertIn(("-6", "addr", "add", "2001:db8:44::66/64", "dev", P.PEER_DEV, "nodad"), plan)
        self.assertNotIn(("link", "add", P.PEER_DUMMY, "type", "dummy"), plan)

    def test_lab_init_refuses_a_peer_that_already_runs_frr(self):
        _calls, closed = self._lab(alive=True)
        with self.assertRaisesRegex(RuntimeError, "already runs FRR"):
            P.SrlPhase9Lab("routing.BGP_IPV4")
        self.assertEqual(closed, [True])

    def test_lab_init_refuses_a_peer_holding_router_advertisement_routes(self):
        self._lab(ra_routes="default via fe80::1 proto ra metric 1024")
        with self.assertRaisesRegex(RuntimeError, "router-advertisement"):
            P.SrlPhase9Lab("service_policy.DHCP_RELAY_IPV6")

    def test_lab_init_fails_when_the_peer_daemons_never_answer(self):
        self._lab(daemons="zebra")
        with mock.patch.object(P.time, "monotonic", side_effect=[0, 0, 100, 100, 100]):
            with self.assertRaisesRegex(RuntimeError, "did not answer"):
                P.SrlPhase9Lab("routing.OSPFV2")

    def test_peer_config_and_show_pass_through_vtysh(self):
        calls, _closed = self._lab()
        lab = P.SrlPhase9Lab("service_policy.DHCP_RELAY_IPV4")
        lab.peer_config("router bgp 1", "exit")
        self.assertIn(("vtysh", "-c", "configure terminal", "-c", "router bgp 1", "-c", "exit"), calls)
        self.assertEqual(lab.peer_show("show ip route"), "ok")

    def test_peer_config_raises_when_the_peer_rejects_a_command(self):
        self._lab()
        lab = P.SrlPhase9Lab("service_policy.DHCP_RELAY_IPV4")
        with self.assertRaisesRegex(RuntimeError, "rejected"):
            lab.peer_config("bad")

    def test_peer_show_of_an_unanswered_command_is_empty_text(self):
        self._lab()
        lab = P.SrlPhase9Lab("service_policy.DHCP_RELAY_IPV4")
        with mock.patch.object(P, "_call", return_value=SimpleNamespace(stdout="", returncode=1)):
            self.assertEqual(lab.peer_show("show nothing"), "")

    def test_peer_ns_runs_a_host_tool_in_the_peer_namespace(self):
        calls, _closed = self._lab()
        lab = P.SrlPhase9Lab("service_policy.ACL_IPV4_STANDARD")
        lab.peer_ns("ip", "addr")
        self.assertIn(("sudo", "-n", "nsenter", "-t", "777", "-n", "ip", "addr"), calls)

    def test_peer_ns_without_a_known_namespace_raises(self):
        self._lab()
        lab = P.SrlPhase9Lab("service_policy.ACL_IPV4_STANDARD")
        lab.pid = ""
        with self.assertRaisesRegex(RuntimeError, "unknown"):
            lab.peer_ns("ip", "addr")

    def test_source_ping_passes_when_every_probe_is_answered(self):
        calls, _closed = self._lab()
        lab = P.SrlPhase9Lab("service_policy.ACL_IPV4_STANDARD")
        self.assertTrue(lab.source_ping("198.18.0.1", "198.18.0.66"))
        self.assertIn(("sudo", "-n", "nsenter", "-t", "777", "-n", "ping", "-c", "3", "-W", "1", "-I", "198.18.0.66", "198.18.0.1"), calls)

    def test_source_ping_fails_on_packet_loss(self):
        self._lab()
        lab = P.SrlPhase9Lab("service_policy.ACL_IPV4_STANDARD")
        with mock.patch.object(P, "_run", return_value=SimpleNamespace(stdout="3 transmitted, 0 received, 100% packet loss", returncode=1)):
            self.assertFalse(lab.source_ping("198.18.0.1", "198.18.0.66"))

    def test_close_without_a_captured_mtu_never_sets_the_mtu(self):
        calls, closed = self._lab()
        lab = P.SrlPhase9Lab("service_policy.ACL_IPV4_STANDARD")
        lab.mtu = None
        self.assertTrue(lab.close())
        self.assertFalse(any(call[:3] == ("ip", "link", "set") for call in calls))
        self.assertEqual(closed, [True])


class SrlPhase9PeerAndBehaviourTests(SimpleTestCase):
    def test_configure_peer_sends_each_routing_protocol(self):
        for key, expected in (("routing.OSPFV2", "router ospf"), ("routing.OSPFV3", "router ospf6"),
                              ("routing.BGP_IPV6", "neighbor 2001:db8:44::1 remote-as 65044")):
            with self.subTest(key=key):
                lab = _Lab()
                P.configure_peer(lab, key, P.plan(key)[3])
                self.assertIn(expected, lab.configured[0])

    def test_configure_peer_of_a_non_routing_cell_sends_no_configuration(self):
        lab = _Lab()
        P.configure_peer(lab, "service_policy.ACL_IPV4_STANDARD", P.plan("service_policy.ACL_IPV4_STANDARD")[3])
        self.assertEqual(lab.configured, [])

    def _popen(self, seen, running=False):
        server = mock.Mock()
        server.communicate.return_value = (seen, "")
        server.poll.return_value = None if running else 0
        return server

    def test_dhcp_exchange_returns_what_server_and_client_saw(self):
        server = self._popen("RELAYED 1 198.18.0.1\n")
        with mock.patch.object(P.subprocess, "Popen", return_value=server) as popen:
            self.assertEqual(P.dhcp_exchange(_Lab(client="OFFER 198.18.0.99\n"), "IPV4"), ("RELAYED 1 198.18.0.1", "OFFER 198.18.0.99"))
        argv = popen.call_args[0][0]
        self.assertEqual((argv[:6], argv[-2:]), (["sudo", "-n", "nsenter", "-t", "4242", "-n"], ["192.0.2.1", P.OFFERED]))
        server.kill.assert_not_called()

    def test_dhcp_exchange_kills_the_server_when_the_client_fails(self):
        server = self._popen("", running=True)
        lab = _Lab()
        lab.peer_ns = mock.Mock(side_effect=RuntimeError("timeout"))
        with mock.patch.object(P.subprocess, "Popen", return_value=server), self.assertRaises(RuntimeError):
            P.dhcp_exchange(lab, "IPV6")
        server.kill.assert_called_once()

    def test_dhcp_relayed_passes_for_a_relayed_exchange_of_each_family(self):
        self.assertTrue(P.dhcp_relayed("IPV6", "RELAYED 12 2001:db8:44::1", ""))
        self.assertTrue(P.dhcp_relayed("IPV4", "RELAYED 1 198.18.0.1", "OFFER 198.18.0.99"))

    def test_dhcp_relayed_fails_without_the_offer_or_with_another_link_address(self):
        self.assertFalse(P.dhcp_relayed("IPV4", "RELAYED 1 198.18.0.1", "NONE"))
        self.assertFalse(P.dhcp_relayed("IPV6", "RELAYED 12 2001:db8:44::9", "SENT"))
        self.assertFalse(P.dhcp_relayed("IPV6", "NONE", "SENT"))

    def test_behaviour_passes_when_the_acl_filters_only_its_source(self):
        lab = _Lab(pings={"198.18.0.2": True, "198.18.0.66": False})
        self.assertEqual(P.behaviour(lab, "service_policy.ACL_IPV4_STANDARD", {}, None),
                         (True, "permitted-source ping=True, denied-source ping=False"))
        with mock.patch.object(P, "dhcp_exchange", return_value=("RELAYED 12 2001:db8:44::1", "SENT")):
            self.assertTrue(P.behaviour(_Lab(), "service_policy.DHCP_RELAY_IPV6", {}, None)[0])
        with mock.patch.object(P, "_routing_runtime", return_value=(True, "ok")) as runtime:
            self.assertEqual(P.behaviour(_Lab(), "routing.OSPFV2", {}, "obs"), (True, "ok"))
        runtime.assert_called_once()

    def test_behaviour_fails_when_both_sources_are_answered_or_nothing_is_relayed(self):
        both = _Lab(pings={"2001:db8:44::2": True, "2001:db8:44::66": True})
        self.assertFalse(P.behaviour(both, "service_policy.ACL_IPV6_EXTENDED", {}, None)[0])
        with mock.patch.object(P, "dhcp_exchange", return_value=("NONE", "NONE")):
            self.assertFalse(P.behaviour(_Lab(), "service_policy.DHCP_RELAY_IPV4", {}, None)[0])

    def test_quiet_passes_when_traffic_is_unfiltered_and_nothing_is_relayed(self):
        both = _Lab(pings={"198.18.0.2": True, "198.18.0.66": True})
        self.assertTrue(P.quiet(both, "service_policy.ACL_ATTACH_IPV4", {})[0])
        with mock.patch.object(P, "dhcp_exchange", return_value=("NONE", "")):
            self.assertEqual(P.quiet(_Lab(), "service_policy.DHCP_RELAY_IPV4", {}), (True, "no relay: server saw [NONE], client saw []"))
        with mock.patch.object(P, "_withdrawn", return_value=(True, "gone")):
            self.assertTrue(P.quiet(_Lab(), "routing.BGP_IPV4", {})[0])

    def test_quiet_fails_while_a_source_is_filtered_or_a_relay_is_seen(self):
        self.assertFalse(P.quiet(_Lab(pings={"198.18.0.2": True}), "service_policy.ACL_IPV4_STANDARD", {})[0])
        with mock.patch.object(P, "dhcp_exchange", return_value=("RELAYED 1 198.18.0.1", "")):
            self.assertFalse(P.quiet(_Lab(), "service_policy.DHCP_RELAY_IPV4", {})[0])


class SrlPhase9RoutingVerdictTests(SimpleTestCase):
    def test_routing_runtime_passes_when_both_ends_see_ospf(self):
        observed = _Observed(ospf=[{"family": "OSPFV3", "interface": P.PORT, "state": "FULL", "neighbor_id": "198.18.44.2"}],
                             routes=[{"prefix": "2001:db8:99::/64", "type": "ospf"}])
        ok, detail = P._routing_runtime(_Lab(f"{P.DUT_ROUTER_ID} 1 Full/PointToPoint"), "routing.OSPFV3", {}, observed)   # pylint: disable=protected-access
        self.assertTrue(ok, detail)

    def test_routing_runtime_passes_when_the_bgp_session_exchanges_both_prefixes(self):
        sections = P.plan("routing.BGP_IPV4")[3]
        neighbor = next(iter(next(iter(sections["routing"]["bgp"].values()))["neighbors"].values()))
        observed = _Observed(bgp=[{"peer": neighbor["peer_address"], "remote_as": neighbor["remote_asn"], "state": "ESTABLISHED"}],
                             routes=[{"prefix": "192.0.2.0/24", "type": "bgp"}])
        ok, detail = P._routing_runtime(_Lab('{"paths": [{"nexthops": [{"ip": "198.18.0.1"}]}]}'), "routing.BGP_IPV4", sections, observed)   # pylint: disable=protected-access
        self.assertTrue(ok, detail)

    def test_routing_runtime_fails_without_the_session_route_or_peer_view(self):
        empty = _Observed(ospf=[], bgp=[], routes=[])
        for key in P.ROUTING_CELLS:
            with self.subTest("session and route missing", key=key):
                self.assertFalse(P._routing_runtime(_Lab(), key, P.plan(key)[3], empty)[0])   # pylint: disable=protected-access

    def test_withdrawn_passes_once_the_adjacency_session_and_routes_are_gone(self):
        with mock.patch.object(P.live, "read_device", return_value=_Observed(ospf=[], bgp=[], routes=[])):
            for key in P.ROUTING_CELLS:
                with self.subTest(key=key):
                    self.assertTrue(P._withdrawn(_Lab(), key, P.plan(key)[3])[0])   # pylint: disable=protected-access

    def test_withdrawn_fails_while_a_learned_route_or_the_peer_view_remains(self):
        held = _Observed(ospf=[], bgp=[], routes=[{"prefix": "192.0.2.0/24", "type": "ospf"}])
        with mock.patch.object(P.live, "read_device", return_value=held):
            self.assertFalse(P._withdrawn(_Lab(), "routing.OSPFV2", {})[0])   # pylint: disable=protected-access
        with mock.patch.object(P.live, "read_device", return_value=_Observed(ospf=[], bgp=[], routes=[])):
            self.assertFalse(P._withdrawn(_Lab('{"paths": []}'), "routing.BGP_IPV6", P.plan("routing.BGP_IPV6")[3])[0])   # pylint: disable=protected-access

    def test_settled_passes_once_the_node_goes_quiet(self):
        with mock.patch.object(P, "quiet", side_effect=[(False, "busy"), (True, "quiet")]) as quiet, mock.patch.object(P.time, "sleep"):
            ok, detail = P.settled(_Lab(), "routing.OSPFV2", {})
        self.assertTrue(ok)
        self.assertTrue(detail.startswith("quiet (after "))
        self.assertEqual(quiet.call_count, 2)

    def test_settled_fails_when_the_limit_is_exceeded(self):
        with mock.patch.object(P, "quiet", return_value=(False, "busy")), mock.patch.object(P.time, "sleep"):
            ok, detail = P.settled(_Lab(), "routing.OSPFV2", {}, limit=-1)
        self.assertFalse(ok)
        self.assertTrue(detail.startswith("busy (after "))


class _FakeLab:
    """Stands in for ``SrlPhase9Lab``: an executor over a fixed tree, recorded native writes and safety-net Sets."""

    instances: list = []
    digests = ("d", "d")

    def __init__(self, key):
        self.key, self.native_lines, self.safety = key, [], []
        self.executor = SimpleNamespace(config_tree=lambda: {}, tree_digest=lambda _tree: "d")
        self.gnmi = SimpleNamespace(set_cli=self.safety.append)
        self.device, self.session_factory = {"name": "srl"}, None
        self._digests = list(self.digests)
        _FakeLab.instances.append(self)

    def native(self, lines):
        self.native_lines.append(list(lines))

    def digest(self):
        return self._digests.pop(0) if self._digests else "d"

    def close(self):
        return True


class SrlPhase9ScenarioTests(SimpleTestCase):
    GOOD = {"applied": True, "verified": True, "compensated": True, "statuses": ["COMPENSATED"], "compensation_codes": ["-"],
            "actions": [], "failure": "", "detail": "ok"}

    def _run(self, key, seed=(), transaction=None, digests=("d",)):
        _FakeLab.digests = digests
        with mock.patch.object(P, "SrlPhase9Lab", _FakeLab), mock.patch.object(P, "configure_peer"), \
                mock.patch.object(P, "settled", return_value=(True, "quiet")), \
                mock.patch.object(P, "_transaction", return_value=dict(transaction or self.GOOD)):
            return P._scenario(key, seed)   # pylint: disable=protected-access

    def test_scenario_records_a_compensated_transaction_and_writes_prerequisites_natively(self):
        result = self._run("service_policy.DHCP_RELAY_IPV4")
        self.assertEqual((result["applied"], result["config_restored"], result["after"], result["restored"], result["control"]),
                         (True, True, True, True, True))
        lab = _FakeLab.instances[-1]
        self.assertEqual(lab.native_lines[0], P.plan("service_policy.DHCP_RELAY_IPV4")[0])
        self.assertEqual(lab.safety, [])
        self.assertTrue(result["detail"].startswith("control before apply: quiet; ok; after compensation: quiet"))

    def test_scenario_never_leaves_residue_when_the_configuration_is_not_restored(self):
        result = self._run("service_policy.DHCP_RELAY_IPV4", digests=("other",))
        self.assertFalse(result["config_restored"])
        (safety,) = _FakeLab.instances[-1].safety
        self.assertIn("delete / interface ethernet-1/1", safety)

    def test_scenario_of_a_seed_missing_after_compensation_is_not_preserved(self):
        result = self._run("routing.BGP_IPV4", seed=P.seeds("routing.BGP_IPV4"))
        self.assertFalse(result["preserved"])

    def test_scenario_records_a_failure_when_the_lab_write_raises(self):
        with mock.patch.object(_FakeLab, "native", side_effect=RuntimeError("gNMI refused")):
            result = self._run("routing.OSPFV2")
        self.assertEqual((result["failure"], result["restored"]), ("RuntimeError: gNMI refused", True))

    def test_probe_records_pass_for_every_live_stage(self):
        good = {k: True for k in ("applied", "read_ok", "post_ok", "imported", "verified", "control", "compensated",
                                  "config_restored", "after", "preserved", "restored")} | \
            {"actions": [], "statuses": ["COMPENSATED"], "compensation_codes": ["-"], "detail": "d", "failure": ""}
        cell = SimpleNamespace(probes={}, runtime_version="")
        with mock.patch.object(P, "_scenario", return_value=good) as scenario:
            P.probe_srlinux_phase9(cell, "service_policy.ACL_IPV4_EXTENDED")
        self.assertEqual({p["outcome"] for p in cell.probes.values()}, {"PASS"})
        self.assertEqual(set(cell.probes), {"live_write", "live_read", "live_post_write_validation", "parser_import",
                                            "runtime_validation", "compensation"})
        self.assertEqual(scenario.call_args_list[1].args, ("service_policy.ACL_IPV4_EXTENDED", P.seeds("service_policy.ACL_IPV4_EXTENDED")))
        self.assertIn("codes=['-']", cell.probes["compensation"]["detail"])
        self.assertEqual(cell.runtime_version, P.RUNTIME)

    def test_probe_records_a_failed_stage_when_the_control_or_compensation_does_not_hold(self):
        bad = {k: True for k in ("applied", "read_ok", "post_ok", "imported", "verified", "compensated", "after", "preserved",
                                 "restored")} | {"control": False, "config_restored": False, "actions": [], "statuses": [],
                                                 "detail": "", "failure": ""}
        cell = SimpleNamespace(probes={}, runtime_version="")
        with mock.patch.object(P, "_scenario", return_value=bad):
            P.probe_srlinux_phase9(cell, "routing.OSPFV2")
        self.assertEqual((cell.probes["runtime_validation"]["outcome"], cell.probes["compensation"]["outcome"],
                          cell.probes["live_write"]["outcome"]), ("FAIL", "FAIL", "PASS"))
        self.assertEqual(cell.probes["compensation"]["reason"], "COMPENSATION_ABSENT")


class TransactionCompensationCodeTests(SimpleTestCase):
    """``batch_frr_routing._transaction`` records why each compensation step ended as it did."""

    def _executor(self, compensate):
        preflight = SimpleNamespace(action="APPLY", restorable=True, reason="")
        return SimpleNamespace(assess=lambda spec: preflight, apply=lambda spec, pre: SimpleNamespace(ok=True, error_code=""),
                               compensate=compensate)

    def test_transaction_records_compensation_statuses_and_codes_in_reverse_order(self):
        outcomes = iter([CompensationOutcome("COMPENSATED"), CompensationOutcome("COMPENSATED")])
        specs = [SimpleNamespace(object_type="acl"), SimpleNamespace(object_type="acl_attachment")]
        out = batch_frr_routing._transaction(self._executor(lambda spec, pre: next(outcomes)), specs, lambda: (True, "ok"))   # pylint: disable=protected-access
        self.assertEqual((out["statuses"], out["compensation_codes"], out["compensated"]), (["COMPENSATED"] * 2, ["-", "-"], True))

    def test_transaction_records_the_error_code_of_a_failed_compensation(self):
        failed = CompensationOutcome("COMPENSATION_FAILED", error_code="TRANSPORT_ERROR")
        out = batch_frr_routing._transaction(self._executor(lambda spec, pre: failed), [SimpleNamespace(object_type="acl")],   # pylint: disable=protected-access
                                             lambda: (True, "ok"))
        self.assertEqual((out["statuses"], out["compensation_codes"], out["compensated"]),
                         (["COMPENSATION_FAILED"], ["TRANSPORT_ERROR"], False))
