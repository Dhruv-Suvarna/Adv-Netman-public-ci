"""V2 Phase 9: IOS XE OSPFv2 / OSPFv3 / RIPv2 / BGP -- rendering, nested-section inverse, import, live state readers and
the isolated-lab harness (fakes only; the live evidence is recorded by ``batch_iosxe_routing`` on the Catalyst 8000V).

The show-command and running-configuration texts below were captured from the isolated Catalyst 8000V (IOS XE
17.06.01a) peering with an FRR 8.4.4 neighbor; only management / credential lines were left out."""

from __future__ import annotations

from types import SimpleNamespace
from unittest import mock

from django.test import SimpleTestCase

from core.services import platform_drivers as D
from core.services.capabilities import batch_iosxe_routing as R
from core.services.config_import import parser_iosxe
from core.services.execution import capability
from core.services.execution.executors import iosxe
from core.services.execution.executors.base import ConfigletSpec
from core.services.health import live, routing_config
from core.services.platform_drivers import RoutingProtocol

OSPF_V2 = """
Neighbor ID     Pri   State           Dead Time   Address         Interface
198.18.44.2       0   FULL/  -        00:00:36    198.18.0.2      GigabitEthernet2
"""
OSPF_V3 = """
            OSPFv3 Router with ID (198.18.44.1) (Process ID 46)

Neighbor ID     Pri   State           Dead Time   Interface ID    Interface
N/A               0   INIT/  -        00:00:02    2063            GigabitEthernet2
198.18.44.2       0   FULL/  -        00:00:37    2063            GigabitEthernet2
"""
BGP4 = """BGP router identifier 198.18.44.1, local AS number 65044
BGP table version is 3, main routing table version 3

Neighbor        V           AS MsgRcvd MsgSent   TblVer  InQ OutQ Up/Down  State/PfxRcd
198.18.0.2      4        65045       5       5        3    0    0 00:01:11        1
198.18.9.9      4        65099       0       0        1    0    0 never    Idle
"""
BGP6 = """BGP router identifier 198.18.44.1, local AS number 65044

Neighbor        V           AS MsgRcvd MsgSent   TblVer  InQ OutQ Up/Down  State/PfxRcd
2001:DB8:44::2  4        65045       5       5        3    0    0 00:01:12        1
2001:DB8:1234:5678:9ABC::2
                4        65099       0       0        1    0    0 never    Active
"""
RUNNING = """hostname iosxe
interface GigabitEthernet2
 description NMAS isolated assessment
 ip address 198.18.0.1 255.255.255.252
 ip ospf network point-to-point
 ip ospf 44 area 0
 ip ospf cost 10
 negotiation auto
 ipv6 address 2001:DB8:44::1/64
 ipv6 ospf 46 area 0
 ipv6 ospf network point-to-point
 ipv6 ospf cost 10
router ospf 44
 router-id 198.18.44.1
 network 198.18.0.0 0.0.0.3 area 0
router rip
 version 2
 network 198.18.0.0
router bgp 65044
 bgp router-id 198.18.44.1
 bgp log-neighbor-changes
 neighbor 2001:DB8:44::2 remote-as 65045
 neighbor 198.18.0.2 remote-as 65045
 !
 address-family ipv4
  network 203.0.113.0
  network 10.1.0.0 mask 255.255.0.0
  no neighbor 2001:DB8:44::2 activate
  neighbor 198.18.0.2 activate
 exit-address-family
 !
 address-family ipv6
  network 2001:DB8:113::/64
  neighbor 2001:DB8:44::2 activate
 exit-address-family
ipv6 router ospf 46
 router-id 198.18.44.1
"""
ROUTES4 = """Gateway of last resort is not set

B     192.0.2.0/24 [20/0] via 198.18.0.2, 00:00:12
R     192.0.2.0/24 [120/1] via 198.18.0.2, 00:00:08, GigabitEthernet2
      198.18.0.0/24 is variably subnetted, 2 subnets, 2 masks
C        198.18.0.0/30 is directly connected, GigabitEthernet2
O     198.51.100.0/24 [110/20] via 198.18.0.2, 1d02h, GigabitEthernet2
"""


def _spec(kind, lines):
    return ConfigletSpec("CFG-T", 1, "iosxe", "cisco_c8000v_iosxe", kind, "CREATE_DEFINE", tuple(lines), {})


class IosXeRoutingInverseTests(SimpleTestCase):
    BGP = "hostname x\nrouter bgp 65044\n bgp log-neighbor-changes\n neighbor 198.18.9.9 remote-as 65099\n address-family ipv4\n  network 198.51.100.0\n exit-address-family\n"

    def test_sections_groups_address_family_lines_by_section(self):
        found = iosxe._sections([" bgp router-id 1.1.1.1", "   address-family ipv6", "      network 2001:db8::/64",
                                 "   exit-address-family", "   neighbor 2001:db8::2 remote-as 65045"])
        self.assertEqual(found, {"": ["bgp router-id 1.1.1.1", "neighbor 2001:db8::2 remote-as 65045"],
                                 "address-family ipv6": ["network 2001:db8::/64"]})

    def test_sections_without_an_address_family_hold_no_nested_section(self):
        self.assertEqual(iosxe._sections([" ip ospf 44 area 0", " ip ospf cost 10"]), {"": ["ip ospf 44 area 0", "ip ospf cost 10"]})

    def test_new_lines_returns_only_lines_the_capture_lacks(self):
        self.assertEqual(iosxe._new_lines(["network 10.0.0.0", "version 2", "network 10.0.0.0"], {"version 2"}), ["network 10.0.0.0"])

    def test_new_lines_is_empty_when_every_line_is_already_held(self):
        self.assertEqual(iosxe._new_lines(["version 2", "no auto-summary"], {"version 2"}), [])

    def test_config_inverse_removes_a_routing_process_that_did_not_exist(self):
        self.assertEqual(iosxe.config_inverse(["router ospf 44", " router-id 198.18.44.1"], "hostname x\n"), ["no router ospf 44"])
        self.assertEqual(iosxe.config_inverse(["ipv6 router ospf 44", " router-id 198.18.44.1"], "hostname x\n"), ["no ipv6 router ospf 44"])

    def test_config_inverse_negates_nested_lines_in_their_own_section_then_restores_the_capture(self):
        spec = ["router bgp 65044", "   neighbor 198.18.0.2 remote-as 65045", "   address-family ipv4",
                "      neighbor 198.18.0.2 activate", "      network 203.0.113.0", "   exit-address-family"]
        self.assertEqual(iosxe.config_inverse(spec, self.BGP), [
            "router bgp 65044", " address-family ipv4", " no network 203.0.113.0", " no neighbor 198.18.0.2 activate",
            " exit-address-family", " no neighbor 198.18.0.2 remote-as 65045", " no address-family ipv6",
            " bgp log-neighbor-changes", " neighbor 198.18.9.9 remote-as 65099", " address-family ipv4", " network 198.51.100.0",
            " exit-address-family"])

    def test_new_lines_treats_a_displayed_negation_as_satisfied_only_when_shown(self):
        self.assertEqual(iosxe._new_lines(["no bgp default ipv4-unicast"], set()), ["no bgp default ipv4-unicast"])
        self.assertEqual(iosxe._new_lines(["no bgp default ipv4-unicast"], {"no bgp default ipv4-unicast"}), [])

    def test_config_inverse_restores_the_default_a_displayed_negation_turned_off(self):
        spec = ["router bgp 65044", " no bgp default ipv4-unicast", " bgp router-id 198.18.44.1"]
        self.assertEqual(iosxe.config_inverse(spec, self.BGP)[:4], [
            "router bgp 65044", " no bgp router-id 198.18.44.1", " bgp default ipv4-unicast", " no address-family ipv6"])

    def test_emptied_sections_removes_absent_families_under_explicit_activation(self):
        held = {"": ["no bgp default ipv4-unicast", "neighbor 198.18.0.2 remote-as 65045"]}
        self.assertEqual(iosxe._emptied_sections("router bgp 65044", held), [" no address-family ipv4", " no address-family ipv6"])

    def test_emptied_sections_never_removes_ipv4_under_default_activation_or_a_held_section(self):
        held = {"": ["neighbor 198.18.0.2 remote-as 65045"], "address-family ipv6": ["network 2001:db8::/64"]}
        self.assertEqual(iosxe._emptied_sections("router bgp 65044", held), [])
        self.assertEqual(iosxe._emptied_sections("router ospf 44", {"": []}), [])

    def test_config_inverse_removes_an_address_family_section_the_neighbor_left_behind(self):
        running = "hostname x\nrouter bgp 65044\n bgp router-id 198.18.44.1\n no bgp default ipv4-unicast\n"
        self.assertEqual(iosxe.config_inverse(["router bgp 65044", " neighbor 198.18.0.2 remote-as 65045"], running), [
            "router bgp 65044", " no neighbor 198.18.0.2 remote-as 65045", " no address-family ipv4", " no address-family ipv6",
            " bgp router-id 198.18.44.1", " no bgp default ipv4-unicast"])

    def test_config_inverse_is_empty_when_the_nested_lines_are_already_configured(self):
        spec = ["router bgp 65044", "   address-family ipv4", "      network 198.51.100.0", "   exit-address-family"]
        self.assertEqual(iosxe.config_inverse(spec, self.BGP), [])

    def test_config_inverse_refuses_a_negated_line_inside_a_nested_section(self):
        spec = ["router bgp 65044", "   address-family ipv4", "      no network 198.51.100.0", "   exit-address-family"]
        self.assertIsNone(iosxe.config_inverse(spec, self.BGP))

    def test_config_inverse_undoes_a_global_switch_beside_an_unrelated_line(self):
        self.assertEqual(iosxe.config_inverse(["ipv6 unicast-routing"], "hostname x\nipv6 route ::/0 2001:db8::1\n"),
                         ["no ipv6 unicast-routing"])

    def test_config_inverse_refuses_a_value_that_would_replace_a_configured_one(self):
        self.assertIsNone(iosxe.config_inverse(["ip domain name new.example"], "hostname x\nip domain name old.example\n"))

    def test_routing_types_are_supported_and_compensable_on_iosxe(self):
        for kind in iosxe.ROUTING_TYPES:
            cap = capability.capability_for("cisco_c8000v_iosxe", kind)
            self.assertEqual((cap.apply, cap.compensation), ("SUPPORTED", "SUPPORTED"), kind)

    def test_routing_types_not_proven_on_iosxe_stay_unsupported(self):
        for kind in ("routing_isis", "acl", "dhcp_relay", "fhrp"):
            self.assertEqual(capability.capability_for("cisco_c8000v_iosxe", kind).apply, "NOT_IMPLEMENTED", kind)


class _Conn:
    def __init__(self, text):
        self.text = text

    def send_command(self, command, **_kwargs):
        if command == "show tcp brief numeric":
            return "7F1A2B3C  10.0.0.15.22               10.0.0.2.40122              ESTAB\n"
        return "Building configuration...\n" + self.text + "end\n"


class _SequenceConn:
    def __init__(self, *texts):
        self.texts, self.reads = list(texts), 0

    def send_command(self, _command, **_kwargs):
        self.reads += 1
        return self.texts.pop(0) if len(self.texts) > 1 else self.texts[0]


class IosXeConfigReadTests(SimpleTestCase):
    NOTICE = "Building configuration...\n% Topology global::IPv4 Unicast::base is currently being deconfigured.\nhostname x\ninterface Gi1\nend\n"
    CLEAN = "Building configuration...\nhostname x\ninterface Gi1\nend\n"

    def _executor(self, conn):
        executor = iosxe.IosXeExecutor({"name": "iosxe"}, connection_factory=lambda _d: conn)
        executor.connect()
        return executor

    def test_in_transition_detects_a_device_notice_line(self):
        self.assertTrue(iosxe.in_transition("% BGP context not been initialized properly.\nhostname x"))

    def test_in_transition_is_not_set_by_a_plain_configuration(self):
        self.assertFalse(iosxe.in_transition("hostname x\ninterface Gi1\n description 50% load"))

    def test_config_text_reads_again_until_the_notice_is_gone(self):
        conn = _SequenceConn(self.NOTICE, self.CLEAN)
        with mock.patch.object(iosxe.time, "sleep") as sleep:
            self.assertEqual(self._executor(conn)._config_text(), "hostname x\ninterface Gi1")   # pylint: disable=protected-access
        self.assertEqual((conn.reads, sleep.call_count), (2, 1))

    def test_config_text_refuses_a_notice_that_never_clears(self):
        conn = _SequenceConn(self.NOTICE)
        with mock.patch.object(iosxe.time, "sleep"), self.assertRaises(iosxe.ExecutorError):
            self._executor(conn)._config_text()   # pylint: disable=protected-access
        self.assertEqual(conn.reads, iosxe.READ_ATTEMPTS)


class _RecordingConn:
    """Answers the numeric TCP table and records every command; any other TCP query fails like a timed-out read."""

    def __init__(self):
        self.commands = []

    def send_command(self, command, **_kwargs):
        self.commands.append(command)
        if command.startswith("show tcp"):
            if command != iosxe.TCP_SESSIONS_COMMAND:
                raise TimeoutError("Pattern not detected")
            return "TCB  Local Address  Foreign Address  (state)\n7F1A2B3C  10.0.0.15.22  10.0.0.2.40122  ESTAB\n"
        return "Building configuration...\n" + _RUNNING + "end\n"


_RUNNING = "interface GigabitEthernet1\n ip address 10.0.0.15 255.255.255.0\ninterface GigabitEthernet2\n ip address 198.18.0.1 255.255.255.252\n"


class IosXeManagementSessionTests(SimpleTestCase):
    def test_management_interfaces_read_the_tcp_table_without_name_resolution(self):
        conn = _RecordingConn()
        executor = iosxe.IosXeExecutor({"name": "iosxe"}, connection_factory=lambda _d: conn)
        executor.connect()
        self.assertEqual(executor._management_interfaces(_RUNNING), {"interface gigabitethernet1"})   # pylint: disable=protected-access
        self.assertEqual([c for c in conn.commands if c.startswith("show tcp")], ["show tcp brief numeric"])

    def test_a_failed_tcp_table_read_is_previous_state_unavailable(self):
        class Failing(_RecordingConn):
            def send_command(self, command, **kwargs):
                if command == iosxe.TCP_SESSIONS_COMMAND:
                    raise TimeoutError("Pattern not detected")
                return super().send_command(command, **kwargs)

        executor = iosxe.IosXeExecutor({"name": "iosxe"}, connection_factory=lambda _d: Failing())
        executor.connect()
        with self.assertRaisesRegex(iosxe.ExecutorError, "PREVIOUS_STATE_UNAVAILABLE"):
            executor._management_interfaces(_RUNNING)   # pylint: disable=protected-access


class IosXeRoutingAssessTests(SimpleTestCase):
    def _executor(self, text):
        executor = iosxe.IosXeExecutor({"name": "iosxe"}, connection_factory=lambda _d: _Conn(text))
        executor.connect()
        return executor

    def test_assess_accepts_a_routing_process_with_an_exact_inverse(self):
        found = self._executor("interface GigabitEthernet2\n ip address 198.18.0.1 255.255.255.252\n").assess(
            _spec("routing_ospf", ["router ospf 44", " router-id 198.18.44.1"]))
        self.assertEqual((found.action, found.restorable), ("APPLY", True))

    def test_assess_of_a_nested_negation_is_not_restorable(self):
        text = "interface GigabitEthernet2\n ip address 198.18.0.1 255.255.255.252\n" + IosXeRoutingInverseTests.BGP.split("\n", 1)[1]
        found = self._executor(text).assess(_spec("bgp_network", ["router bgp 65044", " address-family ipv4", "  no network 198.51.100.0",
                                                                  " exit-address-family"]))
        self.assertEqual((found.action, found.restorable), ("APPLY", False))


class IosXeRoutingRendererTests(SimpleTestCase):
    def test_classful_network_display_returns_the_classful_network(self):
        for cidr, wanted in (("198.18.0.1/30", "198.18.0.0"), ("10.1.1.1/30", "10.0.0.0"), ("172.16.5.1/24", "172.16.0.0")):
            iface = {"name": "Gi2", "addresses": {"a": {"cidr": cidr, "family": "IPV4", "sequence": 1, "id": "a"}}}
            self.assertEqual(D._classful_network_display(iface), wanted)   # pylint: disable=protected-access

    def test_classful_network_display_without_an_ipv4_address_keeps_the_marker(self):
        text = D._classful_network_display({"name": "Gi2", "addresses": {}})   # pylint: disable=protected-access
        self.assertTrue(text.startswith("<no IPv4 address"))

    def test_bgp_network_display_omits_a_classful_mask_and_keeps_others(self):
        self.assertEqual(D._iosxe_bgp_network_display("203.0.113.0/24"), "203.0.113.0")   # pylint: disable=protected-access
        self.assertEqual(D._iosxe_bgp_network_display("10.1.0.0/16"), "10.1.0.0 mask 255.255.0.0")   # pylint: disable=protected-access
        self.assertEqual(D._iosxe_bgp_network_display("2001:db8:113::/64"), "2001:db8:113::/64")   # pylint: disable=protected-access

    def test_bgp_network_display_of_an_invalid_prefix_is_a_marker(self):
        self.assertTrue(D._iosxe_bgp_network_display("not-a-prefix").startswith("<invalid"))   # pylint: disable=protected-access

    def _instance(self, networks):
        return {"id": "b", "local_asn": 65044, "router_id": "198.18.44.1",
                "neighbors": {"n": {"id": "n", "peer_address": "198.18.0.2", "remote_asn": 65045, "activate_ipv4": True, "sequence": 1}},
                "networks": networks}

    def test_iosxe_bgp_descriptors_render_the_displayed_address_family_and_network(self):
        lines = [d.get("text") or d["template"].format(value=d["value"]) for d in D._iosxe_bgp_descriptors(   # pylint: disable=protected-access
            self._instance({"x": {"id": "x", "family": "IPV4", "cidr": "203.0.113.0/24", "sequence": 1}}), {})]
        self.assertIn("   address-family ipv4", lines)
        self.assertIn("      network 203.0.113.0", lines)
        self.assertNotIn("   address-family ipv4 unicast", lines)

    def test_iosxe_bgp_descriptors_turn_off_default_ipv4_activation(self):
        lines = [d.get("text") or d["template"].format(value=d["value"]) for d in D._iosxe_bgp_descriptors(   # pylint: disable=protected-access
            self._instance({}), {})]
        self.assertEqual(lines[:2], ["router bgp 65044", " no bgp default ipv4-unicast"])

    def test_bgp_instance_descriptors_without_networks_render_no_network_line(self):
        lines = D._bgp_instance_descriptors(self._instance({}), {}, template_name="iosxe/routing_bgp.j2",   # pylint: disable=protected-access
                                            af_suffix="", close_af=True, network_display=D._iosxe_bgp_network_display)   # pylint: disable=protected-access
        self.assertFalse([d for d in lines if "network" in (d.get("template") or d.get("text") or "")])

    def test_ospf_interface_contributions_render_ospfv3_with_the_ipv6_keyword(self):
        lines = D._iosxe_ospf_interface_contributions({"_scope": {"ospf": [   # pylint: disable=protected-access
            {"version": "OSPFV3", "process_id": 44, "area": "0", "cost": 10, "network_type": "POINT_TO_POINT", "path": "p"}]}})
        rendered = [d.get("text") or d["template"].format(value=d["value"]) for d in lines]
        self.assertEqual(rendered, [" ipv6 ospf 44 area 0", " ipv6 ospf cost 10", " ipv6 ospf network point-to-point"])

    def test_ospf_interface_contributions_are_empty_without_a_binding(self):
        self.assertEqual(D._iosxe_ospf_interface_contributions({"_scope": {}}), [])   # pylint: disable=protected-access

    def test_ospf_interface_contributions_refuse_a_gated_protocol(self):
        interface = {"_scope": {"ospf": [
            {"version": version, "process_id": 44, "area": "0", "cost": 10, "network_type": "POINT_TO_POINT", "path": "p"}
            for version in ("OSPFV2", "OSPFV3")]}}
        with mock.patch.object(D, "is_routing_protocol_selectable", return_value=False) as selectable:
            self.assertEqual(D._iosxe_ospf_interface_contributions(interface), [])   # pylint: disable=protected-access
        self.assertEqual([call.args[1] for call in selectable.call_args_list],
                         [RoutingProtocol.OSPFV2, RoutingProtocol.OSPFV3])

    def test_iosxe_ospfv3_is_selectable(self):
        self.assertTrue(D.is_routing_protocol_selectable("cisco_c8000v_iosxe", RoutingProtocol.OSPFV3))

    def test_iosxe_ripng_is_not_selectable(self):
        self.assertFalse(D.is_routing_protocol_selectable("cisco_c8000v_iosxe", RoutingProtocol.RIPNG))


class IosXeRoutingParserTests(SimpleTestCase):
    def setUp(self):
        self.parsed = parser_iosxe.parse(RUNNING)
        self.rows = {(r.family, r.fields.get("version", "")): r for r in self.parsed.routing_instances}

    def test_parse_imports_ospf_processes_with_their_interface_bindings(self):
        v2, v3 = self.rows[("ospf", "OSPFV2")], self.rows[("ospf", "OSPFV3")]
        self.assertEqual((v2.fields["process_id"], v2.fields["router_id"], v2.networks), (44, "198.18.44.1", [{"prefix": "198.18.0.0/30", "area": "0"}]))
        self.assertEqual(v2.bindings[0]["network_type"], "POINT_TO_POINT")
        self.assertEqual(v3.bindings[0] | {"passive": False}, {"interface_name": "GigabitEthernet2", "version": "OSPFV3", "process_id": 46,
                                                             "area": "0", "network_type": "POINT_TO_POINT", "cost": 10, "passive": False})
        self.assertEqual(self.parsed.parser_version, "iosxe-1.2")

    def test_parse_imports_bgp_neighbors_networks_and_activation(self):
        bgp = self.rows[("bgp", "")]
        self.assertEqual(bgp.fields, {"local_asn": 65044, "router_id": "198.18.44.1"})
        peers = {n["peer_address"]: n for n in bgp.neighbors}
        self.assertTrue(peers["198.18.0.2"]["activate_ipv4"])
        self.assertEqual((peers["2001:db8:44::2"]["activate_ipv4"], peers["2001:db8:44::2"]["activate_ipv6"]), (False, True))
        self.assertEqual(bgp.networks, [{"family": "IPV4", "cidr": "203.0.113.0/24"}, {"family": "IPV4", "cidr": "10.1.0.0/16"},
                                        {"family": "IPV6", "cidr": "2001:db8:113::/64"}])

    def test_parse_imports_rip_with_the_interfaces_inside_its_classful_network(self):
        rip = self.rows[("rip", "")]
        self.assertEqual((rip.fields["rip_version"], rip.networks, rip.bindings),
                         ("2", [{"prefix": "198.18.0.0"}], [{"interface_name": "GigabitEthernet2", "passive": False}]))

    def test_parse_of_an_unnumbered_process_is_unmanaged(self):
        parsed = parser_iosxe.parse("router ospf\n router-id 1.1.1.1\nrouter bgp x\n")
        self.assertFalse(parsed.routing_instances)
        self.assertEqual(len(parsed.unmanaged_blocks), 2)

    def test_parse_ospf_returns_none_without_a_numeric_process(self):
        self.assertIsNone(parser_iosxe._parse_ospf(["router ospf x"]))   # pylint: disable=protected-access

    def test_parse_rip_preserves_unmodelled_lines(self):
        rip = parser_iosxe._parse_rip(["router rip", " version 2", " timers basic 5 15 15 30", " network 10.0.0.0"])   # pylint: disable=protected-access
        self.assertEqual((rip.fields["_networks"], rip.preserved_lines), (["10.0.0.0"], [" timers basic 5 15 15 30"]))

    def test_parse_rip_with_no_network_has_no_networks(self):
        self.assertEqual(parser_iosxe._parse_rip(["router rip"]).fields["_networks"], [])   # pylint: disable=protected-access

    def test_parse_bgp_returns_none_for_a_non_numeric_asn(self):
        self.assertIsNone(parser_iosxe._parse_bgp(["router bgp 65000.1"]))   # pylint: disable=protected-access

    def test_parse_bgp_preserves_a_malformed_network_and_an_activation_outside_a_family(self):
        bgp = parser_iosxe._parse_bgp(["router bgp 1", " neighbor 10.0.0.2 remote-as 2", " neighbor 10.0.0.2 activate",   # pylint: disable=protected-access
                                       " address-family ipv4", "  network 10.0.0.0 bogus", " exit-address-family"])
        self.assertEqual(bgp.networks, [])
        self.assertEqual(bgp.preserved_lines, [" neighbor 10.0.0.2 activate", "  network 10.0.0.0 bogus"])

    def test_parse_bgp_applies_the_default_ipv4_activation_of_a_global_neighbor(self):
        bgp = parser_iosxe._parse_bgp(["router bgp 1", " neighbor 10.0.0.2 remote-as 2"])   # pylint: disable=protected-access
        self.assertEqual((bgp.neighbors[0]["activate_ipv4"], bgp.neighbors[0]["activate_ipv6"]), (True, False))

    def test_parse_bgp_without_default_activation_reads_only_explicit_activations(self):
        bgp = parser_iosxe._parse_bgp(["router bgp 1", " no bgp default ipv4-unicast", " neighbor 10.0.0.2 remote-as 2",   # pylint: disable=protected-access
                                       " neighbor 10.0.0.3 remote-as 2", " address-family ipv4", "  neighbor 10.0.0.3 activate",
                                       " exit-address-family"])
        self.assertEqual({n["peer_address"]: n["activate_ipv4"] for n in bgp.neighbors}, {"10.0.0.2": False, "10.0.0.3": True})
        self.assertNotIn(" no bgp default ipv4-unicast", bgp.preserved_lines)

    def test_parse_bgp_reads_a_displayed_deactivation_and_preserves_one_for_an_unknown_peer(self):
        bgp = parser_iosxe._parse_bgp(["router bgp 1", " neighbor 2001:DB8::2 remote-as 2", " address-family ipv4",   # pylint: disable=protected-access
                                       "  no neighbor 2001:DB8::2 activate", "  no neighbor 10.9.9.9 activate", " exit-address-family",
                                       " address-family ipv6", "  no neighbor 2001:DB8::2 activate", " exit-address-family"])
        self.assertEqual((bgp.neighbors[0]["activate_ipv4"], bgp.neighbors[0]["activate_ipv6"]), (False, False))
        self.assertEqual(bgp.preserved_lines, ["  no neighbor 10.9.9.9 activate"])

    def test_wildcard_prefix_returns_the_cidr(self):
        self.assertEqual(parser_iosxe._wildcard_prefix("198.18.0.0", "0.0.0.3"), "198.18.0.0/30")   # pylint: disable=protected-access

    def test_wildcard_prefix_of_an_invalid_wildcard_raises(self):
        with self.assertRaises(ValueError):
            parser_iosxe._wildcard_prefix("198.18.0.0", "0.0.0.300")   # pylint: disable=protected-access

    def test_classful_length_returns_the_class_length(self):
        self.assertEqual([parser_iosxe.classful_length(a) for a in ("10.0.0.0", "172.16.0.0", "203.0.113.0")], [8, 16, 24])

    def test_classful_length_of_a_non_numeric_address_raises(self):
        with self.assertRaises(ValueError):
            parser_iosxe.classful_length("ten.0.0.0")

    def test_bgp_network_parses_mask_classful_and_ipv6_forms(self):
        self.assertEqual(parser_iosxe._bgp_network("10.1.0.0", ["mask", "255.255.0.0"]), "10.1.0.0/16")   # pylint: disable=protected-access
        self.assertEqual(parser_iosxe._bgp_network("203.0.113.0", []), "203.0.113.0/24")   # pylint: disable=protected-access
        self.assertEqual(parser_iosxe._bgp_network("2001:DB8:113::/64", []), "2001:db8:113::/64")   # pylint: disable=protected-access

    def test_bgp_network_with_an_unknown_keyword_raises(self):
        with self.assertRaises(ValueError):
            parser_iosxe._bgp_network("10.0.0.0", ["route-map", "X"])   # pylint: disable=protected-access

    def test_is_ip_accepts_addresses(self):
        self.assertTrue(parser_iosxe._is_ip("2001:DB8::1") and parser_iosxe._is_ip("198.18.0.2"))   # pylint: disable=protected-access

    def test_is_ip_rejects_a_peer_group_name(self):
        self.assertFalse(parser_iosxe._is_ip("SPINES"))   # pylint: disable=protected-access

    def test_ospf_lines_attach_attributes_printed_before_the_area(self):
        kept, bindings = parser_iosxe._ospf_lines(["interface Gi2", " ip ospf network point-to-point", " ip ospf 44 area 0",   # pylint: disable=protected-access
                                                   " ip ospf cost 10", " negotiation auto"])
        self.assertEqual(kept, ["interface Gi2", " negotiation auto"])
        self.assertEqual(bindings, [{"version": "OSPFV2", "process_id": 44, "area": "0", "network_type": "POINT_TO_POINT", "cost": 10}])

    def test_ospf_lines_without_an_area_line_yield_no_binding(self):
        self.assertEqual(parser_iosxe._ospf_lines(["interface Gi2", " ip ospf cost 10"])[1], [])   # pylint: disable=protected-access

    def test_in_classful_accepts_an_address_inside_the_network(self):
        self.assertTrue(parser_iosxe._in_classful("10.1.1.1/30", "10.0.0.0"))   # pylint: disable=protected-access

    def test_in_classful_rejects_other_networks_and_ipv6(self):
        self.assertFalse(parser_iosxe._in_classful("11.1.1.1/30", "10.0.0.0"))   # pylint: disable=protected-access
        self.assertFalse(parser_iosxe._in_classful("2001:db8::1/64", "10.0.0.0"))   # pylint: disable=protected-access
        self.assertFalse(parser_iosxe._in_classful("bogus", "10.0.0.0"))   # pylint: disable=protected-access

    def test_finalize_binds_rip_and_marks_passive_ospf_interfaces(self):
        parsed = parser_iosxe.parse("interface Gi2\n ip address 10.1.1.1 255.255.255.252\n ip ospf 1 area 0\n"
                                    "router ospf 1\n passive-interface Gi2\nrouter rip\n network 10.0.0.0\n passive-interface Gi2\n")
        ospf, rip = parsed.routing_instances
        self.assertTrue(ospf.bindings[0]["passive"])
        self.assertEqual(rip.bindings, [{"interface_name": "Gi2", "passive": True}])

    def test_finalize_leaves_a_binding_to_a_missing_process_unbound(self):
        parsed = parser_iosxe.parse("interface Gi2\n ip address 10.1.1.1 255.255.255.252\n ip ospf 9 area 0\nrouter ospf 1\n")
        self.assertEqual(parsed.routing_instances[0].bindings, [])


class IosXeRoutingStateReaderTests(SimpleTestCase):
    def test_parse_iosxe_ospf_returns_full_adjacencies_of_both_versions(self):
        self.assertEqual(live.parse_iosxe_ospf(OSPF_V2, OSPF_V3), [
            {"family": "OSPFV2", "neighbor_id": "198.18.44.2", "interface": "GigabitEthernet2", "state": "FULL"},
            {"family": "OSPFV3", "neighbor_id": "198.18.44.2", "interface": "GigabitEthernet2", "state": "FULL"}])

    def test_parse_iosxe_ospf_of_empty_output_has_no_neighbors(self):
        self.assertEqual(live.parse_iosxe_ospf("", "\nNeighbor ID     Pri   State\n"), [])

    def test_parse_iosxe_bgp_returns_sessions_with_wrapped_addresses(self):
        self.assertEqual(live.parse_iosxe_bgp(BGP4, BGP6), [
            {"peer": "198.18.0.2", "remote_as": "65045", "family": 4, "state": "ESTABLISHED", "prefixes_received": 1},
            {"peer": "198.18.9.9", "remote_as": "65099", "family": 4, "state": "IDLE", "prefixes_received": None},
            {"peer": "2001:db8:1234:5678:9abc::2", "remote_as": "65099", "family": 6, "state": "ACTIVE", "prefixes_received": None},
            {"peer": "2001:db8:44::2", "remote_as": "65045", "family": 6, "state": "ESTABLISHED", "prefixes_received": 1}])

    def test_parse_iosxe_bgp_when_bgp_is_not_active_has_no_peers(self):
        self.assertEqual(live.parse_iosxe_bgp("% BGP not active\n", ""), [])

    def test_routing_config_iosxe_returns_semantic_rows(self):
        rows = {(r["protocol"], r["version"]): r for r in routing_config.iosxe(RUNNING)}
        self.assertEqual(rows[("bgp", "")]["local_asn"], 65044)
        self.assertEqual(rows[("ospf", "OSPFV3")]["bindings"][0]["interface_name"], "GigabitEthernet2")
        self.assertEqual(live._routing_config_iosxe(RUNNING), routing_config.iosxe(RUNNING))   # pylint: disable=protected-access

    def test_routing_config_iosxe_of_an_empty_config_has_no_rows(self):
        self.assertEqual(routing_config.iosxe(""), [])
        self.assertEqual(live._routing_config_iosxe("hostname x\n"), [])   # pylint: disable=protected-access

    def test_learned_routes_keep_their_interface_and_drop_the_age(self):
        routes = {(r["prefix"], r["type"]): r for r in live.parse_iosxe_routes(ROUTES4, "")}
        self.assertEqual(routes[("192.0.2.0/24", "bgp")]["interfaces"], [])
        self.assertEqual(routes[("192.0.2.0/24", "rip")]["interfaces"], ["GigabitEthernet2"])
        self.assertEqual(routes[("198.51.100.0/24", "ospf")]["next_hops"], ["198.18.0.2"])

    def test_iosxe_routing_reads_are_read_only_show_commands(self):
        for key in ("ospf", "ospf3", "bgp", "bgp6", "running_config"):
            self.assertTrue(live.IOSXE_COMMANDS[key].startswith("show "), key)


# --- the isolated-lab harness, driven with fakes -----------------------------------------------------------------------

class _Observed:
    def __init__(self, **facts):
        self._facts, self.live_reachable = facts, True

    def facts(self, name):
        return self._facts.get(name)


class _Lab:
    def __init__(self, peer_text=""):
        self.peer_text, self.configured, self.device, self.session_factory = peer_text, [], {"name": "iosxe"}, None

    def peer_show(self, _command):
        return self.peer_text

    def peer_config(self, *commands):
        self.configured.append(commands)


class IosXeRoutingHarnessPlanTests(SimpleTestCase):
    def test_plan_splits_bgp_as_the_planner_does(self):
        _pre, specs, requirements, context = R.plan("routing.BGP_IPV6")
        self.assertEqual([s.object_type for s in specs], ["routing_bgp", "bgp_neighbor", "bgp_neighbor_af", "bgp_network"])
        self.assertEqual(specs[3].lines, ("router bgp 65044", "   address-family ipv6", "      network 2001:db8:113::/64", "   exit-address-family"))
        self.assertEqual(specs[0].lines, ("router bgp 65044", " no bgp default ipv4-unicast", " bgp router-id 198.18.44.1"))
        self.assertEqual((len(requirements) >= 4, context["network"]), (True, "2001:db8:113::/64"))

    def test_plan_splits_ospf_into_process_and_binding(self):
        _pre, specs, _req, _ctx = R.plan("routing.OSPFV3")
        self.assertEqual([(s.object_type, s.lines[0]) for s in specs],
                         [("routing_ospf", "ipv6 router ospf 44"), ("routing_binding", "interface GigabitEthernet2")])
        self.assertEqual([s.object_type for s in R.plan("routing.RIPV2")[1]], ["routing_rip"])

    def test_plan_of_an_unknown_feature_raises(self):
        with self.assertRaises(KeyError):
            R.plan("routing.HOLOGRAM")

    def test_spec_builds_an_iosxe_configlet(self):
        spec = R._spec(3, "bgp_network", ["router bgp 1"])   # pylint: disable=protected-access
        self.assertEqual((spec.cfg_id, spec.platform, spec.lines), ("P9-XE-bgp_network-3", "cisco_c8000v_iosxe", ("router bgp 1",)))

    def test_spec_without_lines_has_no_lines(self):
        self.assertEqual(R._spec(1, "routing_rip", []).lines, ())   # pylint: disable=protected-access

    def test_blocks_returns_header_and_children(self):
        self.assertEqual(R._blocks(["router rip", " version 2", "interface Gi2", " ip ospf 1 area 0"]),   # pylint: disable=protected-access
                         [["router rip", " version 2"], ["interface Gi2", " ip ospf 1 area 0"]])

    def test_blocks_of_empty_input_is_empty(self):
        self.assertEqual(R._blocks([]), [])   # pylint: disable=protected-access

    def test_imported_matches_every_planned_cell(self):
        text = RUNNING.replace("ipv6 router ospf 46", "ipv6 router ospf 44").replace("ipv6 ospf 46 area", "ipv6 ospf 44 area")
        for key in R.CELLS:
            with self.subTest(key=key):
                self.assertTrue(R.imported(key, R.plan(key)[3], text))

    def test_imported_is_false_when_the_intent_is_missing(self):
        for key in R.CELLS:
            with self.subTest("intent missing", key=key):
                self.assertFalse(R.imported(key, R.plan(key)[3], "hostname x\ninterface GigabitEthernet2\n ip address 198.18.0.1 255.255.255.252\n"))


class IosXeRoutingHarnessBehaviourTests(SimpleTestCase):
    def test_configure_peer_sends_the_protocol_configuration(self):
        for key in R.CELLS:
            lab = _Lab()
            R._configure_peer(lab, key, R.plan(key)[3])   # pylint: disable=protected-access
            self.assertTrue(lab.configured and lab.configured[0], key)
        lab = _Lab()
        R._configure_peer(lab, "routing.BGP_IPV4", R.plan("routing.BGP_IPV4")[3])   # pylint: disable=protected-access
        self.assertIn("neighbor 198.18.0.1 remote-as 65044", lab.configured[0])

    def test_configure_peer_raises_when_the_peer_rejects(self):
        lab = _Lab()
        lab.peer_config = mock.Mock(side_effect=RuntimeError("rejected"))
        with self.assertRaises(RuntimeError):
            R._configure_peer(lab, "routing.RIPV2", {})   # pylint: disable=protected-access

    def test_runtime_passes_when_both_ends_see_the_protocol(self):
        ospf = _Observed(ospf=[{"family": "OSPFV2", "interface": "GigabitEthernet2", "state": "FULL"}],
                         routes=[{"prefix": "192.0.2.0/24", "type": "ospf"}])
        self.assertTrue(R._runtime(_Lab("198.18.44.1  Full/-"), "routing.OSPFV2", R.plan("routing.OSPFV2")[3], ospf)[0])   # pylint: disable=protected-access
        rip = _Observed(routes=[{"prefix": "192.0.2.0/24", "type": "rip"}])
        self.assertTrue(R._runtime(_Lab('{"198.18.0.129/32": [{"prefix": "198.18.0.129/32", "protocol": "rip"}]}'), "routing.RIPV2", {}, rip)[0])   # pylint: disable=protected-access
        bgp = _Observed(bgp=[{"peer": "198.18.0.2", "remote_as": "65045", "state": "ESTABLISHED"}],
                        routes=[{"prefix": "192.0.2.0/24", "type": "bgp"}])
        self.assertTrue(R._runtime(_Lab('{"paths": [{"peer": "198.18.0.1"}]}'), "routing.BGP_IPV4", R.plan("routing.BGP_IPV4")[3], bgp)[0])   # pylint: disable=protected-access

    def test_runtime_fails_without_the_learned_route_or_session(self):
        empty = _Observed(routes=[], ospf=[], bgp=[])
        for key in R.CELLS:
            with self.subTest("route and session missing", key=key):
                self.assertFalse(R._runtime(_Lab(), key, R.plan(key)[3], empty)[0])   # pylint: disable=protected-access

    def test_peer_rip_route_finds_the_advertised_loopback_from_rip(self):
        self.assertTrue(R.peer_rip_route(_Lab('{"198.18.0.129/32": [{"prefix": "198.18.0.129/32", "protocol": "rip"}]}')))

    def test_peer_rip_route_rejects_another_protocol_empty_or_invalid_output(self):
        for text in ('{"198.18.0.129/32": [{"protocol": "connected"}]}', "", "% Unknown command"):
            self.assertFalse(R.peer_rip_route(_Lab(text)), text)

    def test_withdrawn_fails_while_the_peer_still_holds_the_advertised_rip_route(self):
        with mock.patch.object(R.live, "read_device", return_value=_Observed(routes=[], ospf=[], bgp=[])):
            self.assertFalse(R._withdrawn(_Lab('{"198.18.0.129/32": [{"prefix": "198.18.0.129/32", "protocol": "rip"}]}'), "routing.RIPV2", {})[0])   # pylint: disable=protected-access

    def test_withdrawn_passes_once_the_route_and_session_are_gone(self):
        with mock.patch.object(R.live, "read_device", return_value=_Observed(routes=[], ospf=[], bgp=[])):
            for key in R.CELLS:
                self.assertTrue(R._withdrawn(_Lab(), key, R.plan(key)[3])[0], key)   # pylint: disable=protected-access

    def test_withdrawn_fails_while_the_learned_route_remains(self):
        held = _Observed(routes=[{"prefix": "192.0.2.0/24", "type": "rip"}, {"prefix": "2001:db8:99::/64", "type": "ospf"},
                                 {"prefix": "192.0.2.0/24", "type": "bgp"}], ospf=[], bgp=[])
        with mock.patch.object(R.live, "read_device", return_value=held):
            for key in R.CELLS:
                self.assertFalse(R._withdrawn(_Lab(), key, R.plan(key)[3])[0], key)   # pylint: disable=protected-access


class _FakeLab:
    """Stands in for ``IosxeRoutingLab``: an executor over fixed text, a recorded native write list."""

    instances = []

    def __init__(self, key, fail=False):
        if fail:
            raise RuntimeError("peer outside the isolated lab")
        self.key, self.native_lines, self.closed = key, [], False
        self.executor = SimpleNamespace(_config_text=lambda: "hostname x\n", running_config_digest=lambda: "d",
                                        assess=None, apply=None, compensate=None)
        self.conn = SimpleNamespace(send_config_set=mock.Mock())
        self.device, self.session_factory = {"name": "iosxe"}, None
        _FakeLab.instances.append(self)

    def native(self, lines):
        self.native_lines.append(list(lines))

    def peer_config(self, *commands):
        pass

    def peer_show(self, _command):
        return ""

    def close(self):
        self.closed = True
        return True


class IosXeRoutingScenarioTests(SimpleTestCase):
    def _run(self, transaction, withdrawn=(True, "gone")):
        with mock.patch.object(R, "IosxeRoutingLab", _FakeLab), \
                mock.patch.object(R, "_transaction", return_value=transaction), \
                mock.patch.object(R, "_withdrawn", return_value=withdrawn):
            return R._scenario("routing.BGP_IPV4", R.SEEDS["routing.BGP_IPV4"])   # pylint: disable=protected-access

    def test_scenario_records_a_compensated_transaction(self):
        result = self._run({"applied": True, "verified": True, "compensated": True, "statuses": ["COMPENSATED"], "actions": [],
                            "failure": "", "detail": "ok"})
        self.assertEqual((result["applied"], result["config_restored"], result["after"], result["restored"]), (True, True, True, True))
        self.assertIn("ip route 203.0.113.0 255.255.255.0 Null0", _FakeLab.instances[-1].native_lines[1])

    def test_scenario_of_rip_writes_the_lab_only_loopback_natively(self):
        done = {"applied": True, "verified": True, "compensated": True, "statuses": [], "actions": [], "failure": "", "detail": ""}
        with mock.patch.object(R, "IosxeRoutingLab", _FakeLab), mock.patch.object(R, "_transaction", return_value=done), \
                mock.patch.object(R, "_withdrawn", return_value=(True, "gone")):
            R._scenario("routing.RIPV2", ())   # pylint: disable=protected-access
        self.assertEqual(_FakeLab.instances[-1].native_lines[1], list(R.DUT_RIP_SOURCE))

    def test_scenario_records_a_failure_when_the_lab_cannot_be_prepared(self):
        with mock.patch.object(R, "IosxeRoutingLab", lambda key: _FakeLab(key, fail=True)):
            with self.assertRaises(RuntimeError):
                R._scenario("routing.RIPV2", ())   # pylint: disable=protected-access

    def test_probe_records_pass_for_every_live_stage(self):
        good = {k: True for k in ("applied", "read_ok", "post_ok", "imported", "verified", "compensated", "config_restored",
                                  "after", "preserved", "restored")} | {"actions": [], "statuses": [], "detail": "", "failure": ""}
        cell = SimpleNamespace(probes={}, runtime_version="")
        with mock.patch.object(R, "_scenario", return_value=good):
            R.probe_iosxe_routing(cell, "routing.OSPFV2")
        self.assertEqual({p["outcome"] for p in cell.probes.values()}, {"PASS"})
        self.assertIn("FRRouting 8.4.4", cell.runtime_version)

    def test_probe_records_a_failed_stage_when_compensation_does_not_restore(self):
        bad = {k: True for k in ("applied", "read_ok", "post_ok", "imported", "verified", "compensated", "after", "preserved",
                                 "restored")} | {"config_restored": False, "actions": [], "statuses": [], "detail": "", "failure": ""}
        cell = SimpleNamespace(probes={}, runtime_version="")
        with mock.patch.object(R, "_scenario", return_value=bad):
            R.probe_iosxe_routing(cell, "routing.RIPV2")
        self.assertEqual((cell.probes["compensation"]["outcome"], cell.probes["live_write"]["outcome"]), ("FAIL", "PASS"))


class IosXeRoutingLabTests(SimpleTestCase):
    """``IosxeRoutingLab`` over a mocked base lab and container calls (no Docker, no router)."""

    def _lab(self, alive=False, daemons="zebra ospfd", ra_routes="fe80::/64 proto kernel metric 256"):
        calls = []

        def call(container, *argv):
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

        def base_init(self):
            self.peer, self.undo, self.peer_links = "clab-nmas-cap-iosxe-peer", [], []

        patches = [mock.patch.object(R.IosxeLab, "__init__", base_init), mock.patch.object(R, "_call", side_effect=call),
                   mock.patch.object(R.IosxeLab, "prepare_peer"), mock.patch.object(R.IosxeLab, "close", return_value=True),
                   mock.patch.object(R.FrrPair, "alive", return_value=alive), mock.patch.object(R.FrrPair, "must"),
                   mock.patch.object(R.time, "sleep")]
        for patch in patches:
            patch.start()
            self.addCleanup(patch.stop)
        return calls

    def test_lab_init_starts_the_protocol_daemons_and_close_restores_the_mtu(self):
        calls = self._lab()
        lab = R.IosxeRoutingLab("routing.OSPFV2")
        self.assertEqual((lab.started, lab.mtu), (["zebra", "ospfd"], "9500"))
        self.assertTrue(lab.close())
        self.assertIn(("ip", "link", "set", "dev", R.PEER_DEV, "mtu", "9500"), calls)

    def test_lab_init_refuses_a_peer_that_already_runs_frr(self):
        self._lab(alive=True)
        with self.assertRaises(RuntimeError):
            R.IosxeRoutingLab("routing.RIPV2")

    def test_lab_init_refuses_a_peer_holding_router_advertisement_routes(self):
        self._lab(ra_routes="default via fe80::1 proto ra metric 1024 expires 300sec")
        with self.assertRaises(RuntimeError):
            R.IosxeRoutingLab("routing.BGP_IPV6")

    def test_peer_config_and_show_pass_through_vtysh(self):
        self._lab()
        lab = R.IosxeRoutingLab("routing.OSPFV2")
        lab.peer_config("router ospf")
        self.assertEqual(lab.peer_show("show ip ospf neighbor"), "ok")

    def test_peer_config_raises_when_the_peer_rejects_a_command(self):
        self._lab()
        lab = R.IosxeRoutingLab("routing.OSPFV2")
        with self.assertRaises(RuntimeError):
            lab.peer_config("bad")

    def test_peer_show_of_an_unanswered_command_is_empty_text(self):
        self._lab(daemons="zebra ospfd")
        lab = R.IosxeRoutingLab("routing.OSPFV2")
        with mock.patch.object(R, "_call", return_value=SimpleNamespace(stdout="", returncode=1)):
            self.assertEqual(lab.peer_show("show ip ospf neighbor"), "")

    def test_close_without_started_daemons_skips_the_mtu_restore(self):
        calls = self._lab()
        lab = R.IosxeRoutingLab("routing.OSPFV2")
        lab.started, lab.mtu = [], None
        calls.clear()
        self.assertTrue(lab.close())
        self.assertFalse([c for c in calls if "mtu" in c])
