"""V2 Phase 5: the EOS isolation renderer, the intent builder and the read-back parsers (pure functions, no device)."""

from __future__ import annotations

from types import SimpleNamespace

from django.test import SimpleTestCase

from core.services.execution.executors.ceos import _eos_commands
from core.services.isolation import eos, intent
from core.tests.helpers import isolation as I

NET = SimpleNamespace(ipv4_prefix="10.254.30.0/24", gateway=I.GATEWAY, service_address=I.SERVICE, http_port=8080)


def build(text=None, **kwargs):
    options = dict(device_id="DEV-000002", upstream="S1", interface=I.PORT, network=NET, config_text=text or I.upstream_config(),
                   nmas_sources=["192.168.200.100"])
    options.update(kwargs)
    return intent.build(**options)


def codes(problems):
    return [p["code"] for p in problems]


class RenderTests(SimpleTestCase):
    def test_acl_names_are_per_device_and_validated(self):
        names = eos.acl_names("DEV-000002")
        self.assertEqual(names["in4"], "NMAS-ISO-DEV-000002-V4")
        self.assertEqual(names["out6"], "NMAS-ISO-DEV-000002-V6-OUT")
        self.assertEqual(names["mgmt4"], "NMAS-ISO-DEV-000002-MGMT4")
        with self.assertRaises(eos.RenderError):
            eos.acl_names("R1")

    def test_ipv4_entries_permit_only_dhcp_fetch_and_ssh_return_then_deny(self):
        entries = eos.ipv4_entries({"prefix": "10.254.30.0/24", "service_address": I.SERVICE, "http_port": 80})
        self.assertEqual(entries, ["10 permit udp any eq bootpc any eq bootps", f"20 permit tcp 10.254.30.0/24 host {I.SERVICE} eq www",
                                   f"30 permit tcp 10.254.30.0/24 eq ssh host {I.SERVICE}", "1000 deny ip any any"])
        egress = eos.ipv4_egress_entries({"prefix": "10.254.30.0/24", "service_address": I.SERVICE, "http_port": 8080})
        self.assertEqual(egress[-1], "1000 deny ip any any")
        self.assertIn(f"10 permit tcp host {I.SERVICE} eq 8080 10.254.30.0/24", egress)

    def test_ipv4_entries_refuse_a_host_prefix_with_host_bits(self):
        with self.assertRaises(ValueError):
            eos.ipv4_entries({"prefix": "10.254.30.1/24", "service_address": I.SERVICE, "http_port": 80})

    def test_ipv6_entries_allow_link_local_nd_only(self):
        self.assertEqual(eos.ipv6_entries(), ["10 permit icmpv6 fe80::/10 any", "1000 deny ipv6 any any"])
        self.assertEqual(eos.ipv6_egress_entries(), ["1000 deny ipv6 any any"])

    def test_management_entries_and_denied_prefixes(self):
        denied = eos.management_denied(["10.254.30.1/24"], ["2001:db8:30::1/64"])
        self.assertEqual(denied, {"v4": ["10.254.30.0/24"], "v6": ["2001:db8:30::/64", "fe80::/10"]})
        self.assertEqual(eos.management_denied(["10.254.30.1/24"], []), {"v4": ["10.254.30.0/24"], "v6": []})
        self.assertEqual(eos.management_entries("v6", denied["v6"]),
                         ["10 deny ipv6 2001:db8:30::/64 any", "20 deny ipv6 fe80::/10 any", "30 permit ipv6 any any"])

    def test_locks_out_nmas_source(self):
        denied = {"v4": ["10.254.30.0/24"], "v6": ["fe80::/10"]}
        self.assertTrue(eos.locks_out("10.254.30.9", denied))
        self.assertTrue(eos.locks_out("fe80::1%eth0", denied))
        self.assertFalse(eos.locks_out("192.168.200.100", denied))
        self.assertFalse(eos.locks_out("nmas.example", denied))

    def test_render_apply_orders_definitions_service_ports_then_routing(self):
        _it, ops, problems, _facts = build()
        self.assertEqual(problems, [])
        self.assertEqual([op["key"] for op in ops],
                         ["acl-v4", "acl-v6", "acl-v4-out", "acl-v6-out", "acl-mgmt-v4", "acl-mgmt-v6", "attach-mgmt-v4", "attach-mgmt-v6",
                          "attach-v4", "attach-v6", "attach-v4-out", "attach-v6-out", "ospf-passive-1"])
        attach = next(op for op in ops if op["key"] == "attach-v4-out")
        self.assertEqual(attach["lines"], [f"interface {I.PORT}", "   ip access-group NMAS-ISO-DEV-000002-V4-OUT out"])
        self.assertEqual(attach["inverse"], [f"interface {I.PORT}", "   no ip access-group NMAS-ISO-DEV-000002-V4-OUT out"])
        self.assertEqual(next(op for op in ops if op["key"] == "acl-v4")["inverse"], ["no ip access-list NMAS-ISO-DEV-000002-V4"])

    def test_render_apply_refuses_malformed_interface(self):
        it, _ops, _p, _f = build()
        broken = {**it, "upstream": {**it["upstream"], "interface": "Eth 7; reload"}}
        with self.assertRaises(eos.RenderError):
            eos.render_apply(broken)

    def test_render_release_removes_ports_first_and_restores_exactly(self):
        it, ops, _p, _f = build()
        release = eos.render_release(it)
        self.assertEqual(release[0]["key"], "release-attach-v4")
        self.assertEqual(release[-1]["key"], "release-acl-mgmt-v6")
        self.assertTrue(all(op["kind"] == "REMOVE" for op in release))
        session = I.FakeEosSession(I.upstream_config())
        baseline = session.config.text()
        for op in ops:
            session.send_config_set(_eos_commands(op["lines"]))
        self.assertEqual(set(intent.presence(session.config.text(), ops).values()), {"PRESENT"})
        for op in release:
            session.send_config_set(_eos_commands(op["lines"]))
        self.assertEqual(session.config.text(), baseline)

    def test_render_release_refuses_an_uncovered_operation(self):
        it, _ops, _p, _f = build()
        with self.assertRaises(eos.RenderError) as raised:
            from unittest import mock

            with mock.patch.object(eos, "RELEASE_ORDER", eos.RELEASE_ORDER[:-1]):
                eos.render_release(it)
        self.assertEqual(raised.exception.code, "ISOLATION_PLAN_STALE")


class IntentProblemTests(SimpleTestCase):
    def test_port_not_found(self):
        _it, ops, problems, _f = build(interface="Ethernet9")
        self.assertEqual((codes(problems), ops), (["ISOLATION_PORT_NOT_FOUND"], []))

    def test_switchport_is_refused(self):
        _it, ops, problems, _f = build(I.upstream_config(switchport=True))
        self.assertIn("ISOLATION_PORT_NOT_ROUTED", codes(problems))
        self.assertEqual(ops, [])

    def test_shared_port_is_refused(self):
        text = I.upstream_config(extra=f"interface {I.PORT}.10\n   encapsulation dot1q vlan 10")
        self.assertIn("ISOLATION_PORT_SHARED", codes(build(text)[2]))
        self.assertIn("ISOLATION_PORT_SHARED", codes(build(I.upstream_config(extra_port="channel-group 1 mode active"))[2]))

    def test_network_mismatch_and_missing_helper(self):
        self.assertIn("ISOLATION_BOOTSTRAP_NETWORK_MISMATCH", codes(build(I.upstream_config(helper=""))[2]))
        other = SimpleNamespace(ipv4_prefix="10.254.40.0/24", gateway="10.254.40.1", service_address=I.SERVICE, http_port=80)
        self.assertIn("ISOLATION_BOOTSTRAP_NETWORK_MISMATCH", codes(build(network=other)[2]))

    def test_foreign_acl_on_port_is_never_overwritten(self):
        problems = build(I.upstream_config(extra_port="ip access-group OPERATOR-ACL in"))[2]
        self.assertIn("ISOLATION_FOREIGN_ACL", codes(problems))

    def test_routing_unsupported_rip_isis_ospfv3_bgp(self):
        rip = I.upstream_config(extra="router rip\n   network 10.0.0.0/8")
        self.assertIn("ISOLATION_ROUTING_UNSUPPORTED", codes(build(rip)[2]))
        self.assertIn("ISOLATION_ROUTING_UNSUPPORTED", codes(build(I.upstream_config(extra_port="isis enable CORE"))[2]))
        self.assertIn("ISOLATION_ROUTING_UNSUPPORTED", codes(build(I.upstream_config(extra_port="ipv6 ospf 1 area 0"))[2]))
        bgp = I.upstream_config(extra="router bgp 65000\n   neighbor 10.254.30.10 remote-as 65001")
        self.assertIn("ISOLATION_ROUTING_UNSUPPORTED", codes(build(bgp)[2]))

    def test_ospf_default_passive_with_port_active_is_refused_but_already_passive_is_kept(self):
        active = I.upstream_config(ospf=False, extra=f"router ospf 1\n   passive-interface default\n   no passive-interface {I.PORT}\n"
                                                    "   network 10.0.0.0/8 area 0.0.0.0")
        self.assertIn("ISOLATION_ROUTING_UNSUPPORTED", codes(build(active)[2]))
        passive = I.upstream_config(ospf=False, extra="router ospf 1\n   passive-interface default\n   network 10.0.0.0/8 area 0.0.0.0")
        it, ops, problems, _f = build(passive)
        self.assertEqual(problems, [])
        self.assertEqual(it["elements"]["CONTROL_PLANE"]["already_passive"], [{"process": "1", "vrf": ""}])
        self.assertNotIn("ospf-passive-1", [op["key"] for op in ops])

    def test_no_routing_on_port_renders_no_passive(self):
        it, _ops, problems, _f = build(I.upstream_config(ospf=False))
        self.assertEqual(problems, [])
        self.assertEqual(it["elements"]["CONTROL_PLANE"]["ospf_passive"], [])

    def test_management_plane_exposed_by_other_services_or_nmas_lockout(self):
        eapi = I.upstream_config(extra="management api http-commands\n   no shutdown")
        self.assertIn("ISOLATION_MGMT_PLANE_EXPOSED", codes(build(eapi)[2]))
        self.assertIn("ISOLATION_MGMT_PLANE_EXPOSED", codes(build(nmas_sources=["10.254.30.50"])[2]))

    def test_operator_ssh_acl_verified_or_blocked(self):
        good = ("ip access-list OPS-SSH\n   10 deny ip 10.254.30.0/24 any\n   20 permit ip any any\n"
                "ipv6 access-list OPS-SSH6\n   10 deny ipv6 any any\n"
                "management ssh\n   ip access-group OPS-SSH in\n   ipv6 access-group OPS-SSH6 in")
        it, ops, problems, _f = build(I.upstream_config(mgmt_acl=good))
        self.assertEqual(problems, [])
        self.assertEqual((it["elements"]["MANAGEMENT_PLANE"]["V4"]["mode"], it["elements"]["MANAGEMENT_PLANE"]["V6"]["mode"]), ("VERIFY", "VERIFY"))
        self.assertNotIn("acl-mgmt-v4", [op["key"] for op in ops])
        bad = "ip access-list OPS-SSH\n   10 permit ip any any\nmanagement ssh\n   ip access-group OPS-SSH in"
        self.assertIn("ISOLATION_MGMT_PLANE_EXPOSED", codes(build(I.upstream_config(mgmt_acl=bad))[2]))

    def test_ssh_shutdown_is_closed(self):
        it, _ops, problems, _f = build(I.upstream_config(mgmt_acl="management ssh\n   shutdown"))
        self.assertEqual(problems, [])
        self.assertEqual(it["elements"]["MANAGEMENT_PLANE"]["V4"]["mode"], "CLOSED")

    def test_name_collision_when_our_statement_or_acl_exists(self):
        _it, ops, _p, _f = build()
        session = I.FakeEosSession(I.upstream_config())
        session.send_config_set(_eos_commands(ops[0]["lines"]))
        problems = build(session.config.text())[2]
        self.assertEqual(codes(problems), ["ISOLATION_NAME_COLLISION"])

    def test_acl_exact_detects_extra_or_changed_entries(self):
        it, ops, _p, _f = build()
        session = I.FakeEosSession(I.upstream_config())
        for op in ops:
            session.send_config_set(_eos_commands(op["lines"]))
        self.assertEqual(intent.acl_exact(session.config.text(), it), [])
        session.send_config_set(["ip access-list NMAS-ISO-DEV-000002-V4", "15 permit ip any any"])
        self.assertEqual(intent.acl_exact(session.config.text(), it), ["NMAS-ISO-DEV-000002-V4"])

    def test_presence_reports_partial(self):
        _it, ops, _p, _f = build()
        session = I.FakeEosSession(I.upstream_config())
        session.send_config_set(["ip access-list NMAS-ISO-DEV-000002-V4", "counters per-entry"])
        self.assertEqual(intent.presence(session.config.text(), ops)["acl-v4"], "PARTIAL")
        self.assertEqual(intent.presence(session.config.text(), ops)["acl-v6"], "ABSENT")

    def test_digest_is_canonical(self):
        self.assertEqual(intent.digest({"b": 1, "a": [2]}), intent.digest({"a": [2], "b": 1}))
        self.assertNotEqual(intent.digest({"a": 1}), intent.digest({"a": 2}))


class ParserTests(SimpleTestCase):
    def test_interface_and_routing_facts(self):
        facts = eos.interface_facts(I.upstream_config(), I.PORT)
        self.assertEqual((facts["routed"], facts["ipv4"], facts["helpers"]), (True, ["10.254.30.1/24"], [I.SERVICE]))
        self.assertFalse(eos.interface_facts(I.upstream_config(), "Ethernet99")["exists"])
        self.assertEqual(eos.routing_facts(I.upstream_config(), I.PORT)["ospf"], [{"process": "1", "vrf": ""}])

    def test_acl_entries_and_ssh_denial(self):
        text = "ip access-list A\n   10 deny ip 10.254.30.0/25 any\n   20 deny ip 10.254.30.128/25 any\n   30 permit ip any any\n"
        entries = eos.acl_entries(text, "A")
        # partial denies are not merged: a later permit of the rest counts as exposure (fail closed, never assumed away)
        self.assertFalse(eos.acl_denies_ssh_from(entries, "10.254.30.0/24")[0])
        self.assertTrue(eos.acl_denies_ssh_from(entries[:2], "10.254.30.0/24")[0])       # implicit deny covers the rest
        self.assertIsNone(eos.acl_entries(text, "B"))
        self.assertFalse(eos.acl_denies_ssh_from(None, "10.254.30.0/24")[0])
        self.assertFalse(eos.acl_denies_ssh_from(["10 permit tcp any any eq ssh"], "10.254.30.0/24")[0])
        self.assertTrue(eos.acl_denies_ssh_from(["10 permit tcp any any eq www", "20 deny ip any any"], "10.254.30.0/24")[0])
        self.assertFalse(eos.acl_denies_ssh_from(["10 permit tcp any any range 20 30"], "10.254.30.0/24")[0])
        self.assertFalse(eos.acl_denies_ssh_from(["10 deny ipv6 2001:db8::/32 any"], "10.254.30.0/24")[0])    # other family: unevaluated
        self.assertTrue(eos.acl_denies_ssh_from(["10 deny ipv6 host fe80::1 any", "20 deny ipv6 any any"], "fe80::/10")[0])

    def test_acl_counters(self):
        output = ("IP Access List NMAS-ISO-DEV-000002-V4\n        counters per-entry\n        10 permit udp any eq bootpc any eq bootps [match 4 packets, 0:00:01 ago]\n"
                  "        1000 deny ip any any [match 12 packets, 0:00:02 ago]\n")
        self.assertEqual(eos.acl_counters(output), {10: 4, 1000: 12})
        self.assertEqual(eos.acl_counters(""), {})

    def test_ospf_neighbors_on(self):
        output = I.ospf_neighbors(("10.255.0.9", "FULL/DR", "10.254.30.10", I.PORT), ("10.255.0.2", "FULL/BDR", "10.0.12.1", "Ethernet1"))
        self.assertEqual(eos.ospf_neighbors_on(output, I.PORT), [{"neighbor": "10.255.0.9", "address": "10.254.30.10", "state": "FULL/DR"}])
        self.assertEqual(eos.ospf_neighbors_on("", I.PORT), [])

    def test_routes_via(self):
        self.assertEqual(eos.routes_via(I.routes("10.9.0.0/16", "10.254.30.0/24"), I.PORT, ["10.254.30.1/24"]), ["10.9.0.0/16"])
        self.assertEqual(eos.routes_via(I.routes(), I.PORT, []), [])
        self.assertIsNone(eos.routes_via("not json", I.PORT, []))
        self.assertIsNone(eos.routes_via("[]", I.PORT, []))

    def test_arp_entry(self):
        output = ("Address         Age (sec)  Hardware Addr   Interface\n"
                  "10.254.30.10      0:00:12  a227.1c9a.b67b  Ethernet7, not learned\n")
        self.assertEqual(eos.arp_entry(output, "10.254.30.10"), {"mac": "a2:27:1c:9a:b6:7b", "interface": "Ethernet7"})
        self.assertEqual(eos.arp_entry(output, "10.254.30.11"), {})
        self.assertEqual(eos.arp_entry("", "10.254.30.10"), {})

    def test_management_exposure(self):
        denied = eos.management_denied(["10.254.30.1/24"], [])
        self.assertEqual(eos.management_exposure(I.upstream_config(), denied)[0]["service"], "SSH")
        self.assertEqual(eos.management_exposure(I.upstream_config(mgmt_acl="management ssh\n   shutdown"), denied), [])
