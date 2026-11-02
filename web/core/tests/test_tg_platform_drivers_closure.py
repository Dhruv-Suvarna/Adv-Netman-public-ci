"""Lab 7 closure -- the platform renderers (``platform_drivers``), every driver's render methods called directly.

One small accepted intent (Ethernet1 192.0.2.0/31 with an OSPF area binding, a static route, an ACL attached inbound
and a DHCP relay) is rendered by each driver.  Generated object ids are normalised to ``_ID``; every other character
of the rendered lines is asserted exactly.  POSITIVE: each supported object becomes the platform's own syntax.
NEGATIVE: an absent hostname, empty routing / policy, a plain interface and unsupported objects render an honest
"not configured" / "not implemented" / UNSUPPORTED marker -- never invented configuration.  Pure rendering: no device.
"""

from __future__ import annotations

import re

from django.test import SimpleTestCase, TestCase

from core.services import candidate_renderer, platform_drivers as pd
from core.tests.helpers import validation as vh

_ID = re.compile(r"_[0-9a-f]{16}\b")
NOT_IMPLEMENTED = "! candidate rendering for this feature is not implemented yet"
DRIVERS = ("arista_ceos", "ubuntu_frr", "nokia_srlinux", "cisco_c8000v_iosxe", "cisco_iosxr")


def text(descriptors):
    return [_ID.sub("_ID", line) for line in (candidate_renderer.descriptor_text(d) for d in descriptors) if line is not None]


def unsupported(label, status, platform):
    return f"{pd.UNSUPPORTED_OBJECT_MARKER} {label} is {status} for {platform}; intent preserved"


TRAILER = ["! Traffic-impact validation has not run; project validation pending.", "! Policy/PBR: not configured in current candidate"]
EMPTY_POLICY = ["! FHRP: not configured in current candidate", "! NAT: not configured in current candidate",
                "! DHCP/DHCPv6: INHERIT project defaults (NMAS primary / R2 secondary)", "! DNS: INHERIT project / host defaults",
                "! Monitoring: INHERIT project defaults", "! Security/ACL: not configured in current candidate", "! Policy/PBR: not configured in current candidate"]
HEAD = ["! FHRP: not configured in current candidate", "! NAT: not configured in current candidate"]
INHERIT = ["! DNS: INHERIT project / host defaults", "! Monitoring: INHERIT project defaults"]

EXPECTED = {
    "arista_ceos": {
        "identity": ["hostname R1"], "no_identity": [],
        "routing": ["ip route 10.9.0.0/24 192.0.2.1", "!", "router ospf 1", "   router-id 10.0.0.1", "!"],
        "policy": [*HEAD, *INHERIT, "ip access-list EDGE-IN", "   10 permit tcp any any eq 22", "!", *TRAILER],
        "contribution": ["   ip ospf area 0.0.0.0", "   ip access-group EDGE-IN in", "   ip helper-address 203.0.113.200"],
    },
    "ubuntu_frr": {
        "identity": ["hostnamectl set-hostname R1"], "no_identity": [NOT_IMPLEMENTED],
        "routing": ["ip route 10.9.0.0/24 192.0.2.1", "!", "router ospf", "   ospf router-id 10.0.0.1", "!"],
        # one nftables table (V2 Phase 9): the list chain, then its IN jump guarded by family
        "policy": [*HEAD, unsupported("DHCP relay dhcp_ID", "NOT_IMPLEMENTED", "Ubuntu / FRR"), *INHERIT,
                   "table inet DEVICE_BUILDER_ACL {", "    chain acl4_EDGE-IN {", '        tcp dport 22 accept comment "seq 10"',
                   '        drop comment "implicit-deny EXTENDED"', "    }", "    chain filter_in {",
                   "        type filter hook prerouting priority filter; policy accept;",
                   '        iifname "Ethernet1" meta nfproto ipv4 jump acl4_EDGE-IN', "    }", "}", *TRAILER],
        "contribution": ["!", "interface Ethernet1", "   ip ospf area 0.0.0.0"],
    },
    "nokia_srlinux": {
        "identity": ["set system name host-name R1"], "no_identity": [NOT_IMPLEMENTED],
        "routing": ["set network-instance default static-routes route 10.9.0.0/24 admin-state enable",
                    "set network-instance default static-routes route 10.9.0.0/24 next-hop-group nhg-route_ID",
                    "set network-instance default next-hop-groups group nhg-route_ID nexthop 1 ip-address 192.0.2.1", "!",
                    "set network-instance default protocols ospf instance 1 version ospf-v2", "set network-instance default protocols ospf instance 1 admin-state enable",
                    "set network-instance default protocols ospf instance 1 router-id 10.0.0.1", "!"],
        # SR Linux 24.10 grammar, verified by commit on the isolated 24.10.7 node (V2 Phase 9)
        "policy": [*HEAD, *INHERIT, "set acl acl-filter EDGE-IN type ipv4", "set acl acl-filter EDGE-IN type ipv4 entry 10 match ipv4 source-ip prefix 0.0.0.0/0",
                   "set acl acl-filter EDGE-IN type ipv4 entry 10 match ipv4 destination-ip prefix 0.0.0.0/0",
                   "set acl acl-filter EDGE-IN type ipv4 entry 10 match ipv4 protocol tcp",
                   "set acl acl-filter EDGE-IN type ipv4 entry 10 match transport destination-port operator eq",
                   "set acl acl-filter EDGE-IN type ipv4 entry 10 match transport destination-port value 22",
                   "set acl acl-filter EDGE-IN type ipv4 entry 10 action accept", "!", *TRAILER],
        "contribution": ["set network-instance default protocols ospf instance 1 area 0.0.0.0 interface Ethernet1.0",
                         "set acl interface Ethernet1.0 input acl-filter EDGE-IN type ipv4",
                         "set interface Ethernet1 subinterface 0 ipv4 dhcp-relay admin-state enable",
                         "set interface Ethernet1 subinterface 0 ipv4 dhcp-relay server [ 203.0.113.200 ]"],
    },
    "cisco_c8000v_iosxe": {
        "identity": ["hostname R1"], "no_identity": [NOT_IMPLEMENTED],
        "routing": ["ip route 10.9.0.0 255.255.255.0 192.0.2.1", "!", "router ospf 1", " router-id 10.0.0.1", "!"],
        "policy": [*HEAD, unsupported("DHCP relay dhcp_ID", "NOT_IMPLEMENTED", "Cisco Catalyst 8000V / IOS XE"), *INHERIT,
                   unsupported("ACL EDGE-IN", "NOT_IMPLEMENTED", "Cisco Catalyst 8000V / IOS XE"), "!",
                   unsupported("ACL attachment attach_ID", "NOT_IMPLEMENTED", "Cisco Catalyst 8000V / IOS XE"), *TRAILER],
        "contribution": [" ip ospf 1 area 0.0.0.0"],
    },
    "cisco_iosxr": {
        "identity": ["hostname R1"], "no_identity": [NOT_IMPLEMENTED],
        "routing": ["router static", " address-family ipv4 unicast", "  10.9.0.0/24 192.0.2.1", "!", "router ospf 1", " router-id 10.0.0.1", "!"],
        "policy": [*HEAD, "dhcp ipv4", " profile nmas-dhcp_ID relay", "  helper-address vrf default 203.0.113.200", " !",
                   " interface Ethernet1 relay profile nmas-dhcp_ID", "!", *INHERIT, "ipv4 access-list EDGE-IN", " 10 permit tcp any any",
                   "! entry 10: port-range and log-action match are not rendered pending exact IOS XR syntax verification", "!", *TRAILER],
        "contribution": ["!", "router ospf 1", " area 0.0.0.0", "  interface Ethernet1", "!", "interface Ethernet1", " ipv4 access-group EDGE-IN in"],
    },
}
PLAIN = {"id": "x", "name": "Ethernet9", "kind": "ROUTED_PHYSICAL"}


class DriverRenderingTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        dev = vh.Dev(vh.new_change("driver fixture"), "R1")
        e1 = dev.iface("Ethernet1")
        dev.address(e1, "192.0.2.0/31")
        dev.bind("ospf", dev.ospf(router_id="10.0.0.1"), e1, area="0.0.0.0")
        dev.static_route("10.9.0.0/24", next_hop="192.0.2.1")
        rules = dev.acl("EDGE-IN")
        dev.ace(rules, "PERMIT", "TCP", destination_port="22")
        dev.attach_acl(rules, e1)
        dev.relay(e1, "203.0.113.200")
        cls.state = candidate_renderer.hydrate_state(dev.intent, dev.intent.latest_revision(), use_draft=False)

    def kwargs(self):
        return {"field_values": {"device.hostname": "R1"}, "interfaces": self.state["interfaces"], "routing": self.state["routing"], "phase12": self.state["phase12"]}

    def test_identity_descriptors_render_the_hostname(self):
        for platform in DRIVERS:
            with self.subTest(case=f"{platform} hostname ok"):
                self.assertEqual(text(pd.get_driver(platform).identity_descriptors({"device.hostname": "R1"})), EXPECTED[platform]["identity"])
        with self.subTest(case="sonic config db identity ok"):
            self.assertEqual(text(pd.get_driver("sonic").identity_descriptors({"device.hostname": "R1"})), [NOT_IMPLEMENTED])
            self.assertEqual(pd.PlatformDriver.identity_descriptors(pd.get_driver("sonic"), {"device.hostname": "R1"}), [])

    def test_identity_descriptors_without_a_hostname_are_empty_or_not_implemented(self):
        for platform in DRIVERS:
            with self.subTest(case=f"{platform} missing hostname"):
                self.assertEqual(text(pd.get_driver(platform).identity_descriptors({})), EXPECTED[platform]["no_identity"])

    def test_render_routing_renders_the_static_route_and_ospf_process(self):
        for platform in DRIVERS:
            with self.subTest(case=f"{platform} routing ok"):
                found = pd.get_driver(platform).render_routing(self.state["field_values"], self.state["routing"], self.state["interfaces"])
                self.assertEqual(text(found), EXPECTED[platform]["routing"])
        with self.subTest(case="sonic base routing ok"):
            self.assertEqual(text(pd.get_driver("sonic").render_routing({}, {}, [])), ["! Routing: not configured in current candidate"])

    def test_render_routing_of_empty_routing_is_not_configured(self):
        for platform in (*DRIVERS, "sonic"):
            with self.subTest(case=f"{platform} empty routing"):
                self.assertEqual(text(pd.get_driver(platform).render_routing({}, {}, [])), ["! Routing: not configured in current candidate"])

    def test_render_service_policy_renders_the_acl_and_relay(self):
        for platform in DRIVERS:
            with self.subTest(case=f"{platform} policy ok"):
                self.assertEqual(text(pd.get_driver(platform).render_service_policy(self.state["phase12"], self.state["interfaces"])), EXPECTED[platform]["policy"])
        with self.subTest(case="sonic base policy ok"):
            self.assertEqual(text(pd.get_driver("sonic").render_service_policy({}, [])), EMPTY_POLICY)

    def test_render_service_policy_of_an_empty_phase12_inherits_defaults_only(self):
        for platform in (*DRIVERS, "sonic"):
            with self.subTest(case=f"{platform} empty policy"):
                self.assertEqual(text(pd.get_driver(platform).render_service_policy({}, [])), EMPTY_POLICY)

    def test_interface_contribution_descriptors_of_the_bound_interface(self):
        for platform in DRIVERS:
            driver = pd.get_driver(platform)
            interface = next(i for i in driver.compose_candidate(**self.kwargs())["interfaces"] if i["name"] == "Ethernet1")
            with self.subTest(case=f"{platform} contribution ok"):
                self.assertEqual(text(driver.interface_contribution_descriptors(interface)), EXPECTED[platform]["contribution"])
        with self.subTest(case="base contribution ok"):
            self.assertEqual(pd.PlatformDriver.interface_contribution_descriptors(pd.get_driver("sonic"), PLAIN), [])

    def test_interface_contribution_descriptors_of_a_plain_interface_are_empty(self):
        for platform in DRIVERS:
            with self.subTest(case=f"{platform} empty contribution"):
                self.assertEqual(pd.get_driver(platform).interface_contribution_descriptors(PLAIN), [])

    def test_base_render_routing_and_policy_mark_unimplemented_objects(self):
        sonic = pd.get_driver("sonic")
        with self.subTest(case="unimplemented objects refused"):
            self.assertEqual(text(sonic.render_routing({}, {"ospf": self.state["routing"]["ospf"]}, [])), [unsupported("OSPF instance ospf_ID", "NOT_IMPLEMENTED", "SONiC")])
            found = text(sonic.render_service_policy({**self.state["phase12"], "security": {}}, self.state["interfaces"]))
        self.assertEqual(found, [*HEAD, unsupported("DHCP relay dhcp_ID", "UNKNOWN", "SONiC"), *INHERIT, "! Security/ACL: not configured in current candidate",
                                 "! Policy/PBR: not configured in current candidate"])

    def test_compose_and_render_composed_returns_the_full_candidate(self):
        ceos = pd.get_driver("arista_ceos")
        composed = ceos.compose_candidate(**self.kwargs())
        self.assertEqual((sorted(composed), [i["name"] for i in composed["interfaces"]], composed["conflicts"]),
                         (["conflicts", "field_values", "global", "interfaces", "phase12", "routing"], ["Ethernet1"], []))
        self.assertEqual(text(ceos.render_composed(composed)),
                         ["hostname R1", "!", "interface Ethernet1", "   no switchport", "   ! admin intent: ENABLED", "   no shutdown", "   ip address 192.0.2.0/31",
                          *EXPECTED["arista_ceos"]["contribution"], "!", *EXPECTED["arista_ceos"]["routing"], "!", *EXPECTED["arista_ceos"]["policy"]])

    def test_compose_and_render_composed_of_an_empty_candidate_is_not_configured(self):
        ceos = pd.get_driver("arista_ceos")
        with self.subTest(case="empty candidate not configured"):
            empty = ceos.compose_candidate(field_values={})
            found = text(ceos.render_composed(empty))
        self.assertEqual((empty["interfaces"], any(empty["routing"].values()), empty["conflicts"]), ([], False, []))
        self.assertEqual(found,
                         ["!", "! Interfaces: not configured in current candidate", "!", "! Routing: not configured in current candidate", "!", *EMPTY_POLICY])

    def test_sonic_render_composed_returns_config_db_json(self):
        sonic = pd.get_driver("sonic")
        self.assertEqual(text(sonic.render_composed(sonic.compose_candidate(field_values={"device.hostname": "S9"}))),
                         ["{", '  "DEVICE_METADATA": {', '    "localhost": {', '      "hostname": "S9"', "    }", "  }", "}"])

    def test_sonic_render_composed_of_an_empty_candidate_is_not_implemented(self):
        sonic = pd.get_driver("sonic")
        with self.subTest(case="empty candidate not implemented"):
            self.assertEqual(text(sonic.render_composed(sonic.compose_candidate(field_values={}))), [NOT_IMPLEMENTED])


class DriverHelperTests(SimpleTestCase):
    def test_routing_process_scope_key_per_family_and_platform(self):
        ceos, frr = pd.get_driver("arista_ceos"), pd.get_driver("ubuntu_frr")
        self.assertEqual(ceos.routing_process_scope_key("ospf", {"version": "OSPFV3", "process_id": 7}), ("ospf", "OSPFV3", 7))
        self.assertEqual(frr.routing_process_scope_key("ospf", {"version": "OSPFV3", "process_id": 7}), ("ospf", "OSPFV3"))
        self.assertEqual(ceos.routing_process_scope_key("bgp", {"local_asn": 65001}), ("bgp", 65001))
        self.assertEqual(ceos.routing_process_scope_key("isis", {"id": "a"}), ("isis", pd.CEOS_ISIS_TAG))

    def test_routing_process_scope_key_of_missing_fields_or_an_unknown_family(self):
        ceos = pd.get_driver("arista_ceos")
        self.assertEqual(ceos.routing_process_scope_key("rip", {}), ("rip", "IPV4"))
        self.assertEqual(ceos.routing_process_scope_key("ospf", {}), ("ospf", "OSPFV2", None))
        self.assertEqual(pd.get_driver("ubuntu_frr").routing_process_scope_key("isis", {"id": "x"}), ("isis", "x"))
        self.assertEqual(ceos.routing_process_scope_key("unknown", {}), ("unknown", None))

    def test_supported_feature_names_list_the_registry_backed_features(self):
        full = ["device_identity", "interfaces", "addressing", "wan_metadata", "routing", "fhrp", "nat", "services", "security", "policy"]
        self.assertEqual(pd.get_driver("arista_ceos").supported_feature_names(), full)
        self.assertEqual(pd.get_driver("cisco_c8000v_iosxe").supported_feature_names(), full[:5])

    def test_fhrp_feature_name_and_marker_detection_returns_the_rule_value(self):
        self.assertEqual(pd.fhrp_feature_name({"protocol": "VARP", "address_family": "IPV4"}), "FHRP_VARP_IPV4")
        self.assertTrue(pd.is_unsupported_object_descriptor({"kind": "static", "text": unsupported("x", "UNKNOWN", "y")}))

    def test_fhrp_feature_name_of_an_empty_instance_and_descriptors_that_are_not_markers(self):
        self.assertEqual(pd.fhrp_feature_name({}), "FHRP_None_None")
        for descriptor in ({"kind": "field", "text": pd.UNSUPPORTED_OBJECT_MARKER}, {"kind": "static", "text": "! Routing: not configured"}, {"kind": "static"}):
            with self.subTest(case=f"not a marker {descriptor}"):
                self.assertFalse(pd.is_unsupported_object_descriptor(descriptor))

    def test_selectable_checks_refuse_unknown_platforms_kinds_protocols_and_features(self):
        self.assertTrue(pd.is_interface_kind_selectable("arista_ceos", "SVI"))
        for name, check in (("kind", lambda: pd.is_interface_kind_selectable("arista_ceos", "NOPE")), ("platform", lambda: pd.is_interface_kind_selectable("vyos", "SVI")),
                            ("protocol", lambda: pd.is_routing_protocol_selectable("arista_ceos", "NOPE")),
                            ("routing platform", lambda: pd.is_routing_protocol_selectable("vyos", pd.RoutingProtocol.OSPFV2)),
                            ("feature", lambda: pd.is_service_policy_feature_selectable("arista_ceos", "NOPE")),
                            ("feature platform", lambda: pd.is_service_policy_feature_selectable("vyos", "FHRP_VARP_IPV4"))):
            with self.subTest(case=f"unknown {name}"):
                self.assertFalse(check())

    def test_resolve_service_policy_capability_and_routing_object_protocol(self):
        self.assertEqual(pd.resolve_service_policy_capability("arista_ceos", "FHRP_VARP_IPV4").status, pd.CapabilityStatus.SUPPORTED)
        self.assertEqual(pd.routing_object_protocol("ospf", {"version": "OSPFV2"}), pd.RoutingProtocol.OSPFV2)

    def test_resolve_service_policy_capability_is_not_implemented_and_routing_object_protocol_refuses_unknown_input(self):
        self.assertEqual(pd.resolve_service_policy_capability("arista_ceos", "NOPE").status, pd.CapabilityStatus.NOT_IMPLEMENTED)
        self.assertEqual(pd.resolve_service_policy_capability("vyos", "FHRP_VARP_IPV4").status, pd.CapabilityStatus.NOT_IMPLEMENTED)
        with self.assertRaises(ValueError):
            pd.routing_object_protocol("nope", {})
