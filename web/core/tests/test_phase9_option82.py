"""V2 Phase 9: DHCP relay option 82 (Arista EOS) -- intent, rendering, validation, read-back, postcheck, compensation and the
ZTP trust gate.  Every new / modified function is called directly with an accepting and a refusing case.  The EOS text below is
the live cEOS 4.36.2F read-back (docs/evidence/v2-phase7-9/phase9/option82-ceos-live.json)."""

from __future__ import annotations

from types import SimpleNamespace

from django.test import SimpleTestCase, TestCase

from core.services import candidate_renderer, dhcp_relay_option82 as o82, platform_drivers
from core.services import service_policy_intent_service as service
from core.services.ztp import dependencies
from core.tests.helpers import ztp as Z
from core.tests.helpers.candidates import add_interface, make_candidate

PRE = """! Command: show running-config
! device: P9RELAY (cEOSLab, EOS-4.36.2F)
hostname P9RELAY
!
interface Ethernet1
   description downstream bootstrap port (client side)
   no switchport
   ip address 10.254.90.1/24
   ip helper-address 10.254.91.2
!
interface Ethernet2
   no switchport
   ip address 10.254.91.1/30
!
end
"""
POST = PRE.replace("hostname P9RELAY\n", "hostname P9RELAY\n!\nip dhcp relay information option\n").replace(
    "   ip helper-address 10.254.91.2\n", "   ip helper-address 10.254.91.2\n   ip dhcp relay information option remote-id P9-R6\n")
NETWORK = SimpleNamespace(name="p9", service_address="10.254.91.2",
                          trusted_relays=[{"relay_address": "10.254.90.1", "upstream_device": "P9RELAY"}])


def attachment(interface="Ethernet1", **extra):
    return SimpleNamespace(upstream_device="P9RELAY", upstream_interface=interface, approval_state="APPROVED",
                           verification_state="VERIFIED", **extra)


class Option82UnitTests(SimpleTestCase):
    def test_option82_error_carries_code_and_detail(self):
        exc = o82.Option82Error("OPTION82_VALUE_INVALID", "bad")
        self.assertEqual((exc.code, exc.detail, str(exc)), ("OPTION82_VALUE_INVALID", "bad", "OPTION82_VALUE_INVALID: bad"))

    def test_option82_error_without_detail_is_code_only(self):
        self.assertEqual(str(o82.Option82Error("OPTION82_EMPTY_CHANGE")), "OPTION82_EMPTY_CHANGE")

    def test_effective_circuit_id_method_defaults_to_interface(self):
        self.assertEqual(o82.Option82Intent("Ethernet1").effective_circuit_id(), "Ethernet1")
        self.assertEqual(o82.Option82Intent("Ethernet1", "R6-Et1").effective_circuit_id(), "R6-Et1")

    def test_effective_circuit_id_method_empty_interface_stays_empty(self):
        self.assertEqual(o82.Option82Intent("").effective_circuit_id(), "")

    def test_validate_intent_accepts_eos_port(self):
        self.assertEqual(o82.validate_intent("arista_ceos", o82.Option82Intent("Ethernet1", "R6-Et1", "P9-R6")), [])

    def test_validate_intent_refuses_other_platform_and_invalid_values(self):
        problems = o82.validate_intent("nokia_srlinux", o82.Option82Intent("eth1", 'x"; drop', "", "yes"))
        self.assertEqual([p["code"] for p in problems], ["OPTION82_PLATFORM_NOT_IMPLEMENTED", "INTERFACE_INVALID",
                                                         "OPTION82_VALUE_INVALID", "OPTION82_VALUE_INVALID"])

    def test_intent_from_relay_reads_stored_option82(self):
        relay = {"family": "IPV4", "option82": {"enabled": True, "circuit_id": "", "remote_id": "P9-R6"}}
        self.assertEqual(o82.intent_from_relay(relay, "Ethernet1"), o82.Option82Intent("Ethernet1", "", "P9-R6", True))

    def test_intent_from_relay_refuses_ipv6_or_missing_option82(self):
        self.assertIsNone(o82.intent_from_relay({"family": "IPV6", "option82": {"enabled": True}}, "Ethernet1"))
        self.assertIsNone(o82.intent_from_relay({"family": "IPV4"}, "Ethernet1"))

    def test_render_eos_emits_global_and_port_lines(self):
        self.assertEqual(o82.render_eos(o82.Option82Intent("Ethernet1", "R6-Et1", "P9-R6")), [
            "ip dhcp relay information option", "interface Ethernet1", "   ip dhcp relay information option circuit-id R6-Et1",
            "   ip dhcp relay information option remote-id P9-R6"])
        self.assertEqual(o82.render_eos(o82.Option82Intent("Ethernet1", enabled=False)), [
            "interface Ethernet1", "   no ip dhcp relay information option circuit-id", "   no ip dhcp relay information option remote-id"])

    def test_render_eos_refuses_invalid_circuit_id(self):
        with self.assertRaises(o82.Option82Error) as ctx:
            o82.render_eos(o82.Option82Intent("Ethernet1", "bad id with spaces"))
        self.assertEqual(ctx.exception.code, "OPTION82_VALUE_INVALID")

    def test_parse_eos_reads_live_running_config(self):
        rb = o82.parse_eos(POST)
        self.assertTrue(rb["enabled"])
        self.assertEqual(rb["interfaces"]["Ethernet1"], {"circuit_id": "", "remote_id": "P9-R6", "helpers": ["10.254.91.2"],
                                                         "addresses": ["10.254.90.1"]})

    def test_parse_eos_empty_text_has_no_option82(self):
        self.assertEqual(o82.parse_eos(""), {"enabled": False, "interfaces": {}})
        self.assertFalse(o82.parse_eos(PRE)["enabled"])

    def test_effective_circuit_id_function_uses_platform_default(self):
        self.assertEqual(o82.effective_circuit_id(o82.parse_eos(POST), "Ethernet1"), "Ethernet1")

    def test_effective_circuit_id_function_empty_when_global_off_or_port_missing(self):
        self.assertEqual(o82.effective_circuit_id(o82.parse_eos(PRE), "Ethernet1"), "")
        self.assertEqual(o82.effective_circuit_id(o82.parse_eos(POST), "Ethernet9"), "")

    def test_postcheck_accepts_applied_intent(self):
        self.assertEqual(o82.postcheck(o82.Option82Intent("Ethernet1", "Ethernet1", "P9-R6"), o82.parse_eos(POST)), [])

    def test_postcheck_reports_mismatch_and_missing_port(self):
        self.assertEqual(o82.postcheck(o82.Option82Intent("Ethernet1", "R6-Et1", "P9-R6"), o82.parse_eos(PRE)),
                         ["OPTION82_GLOBAL_DISABLED", "OPTION82_CIRCUIT_ID_MISMATCH", "OPTION82_REMOTE_ID_MISMATCH"])
        self.assertEqual(o82.postcheck(o82.Option82Intent("Ethernet9"), o82.parse_eos(POST)), ["OPTION82_PORT_MISSING"])

    def test_compensation_eos_is_exact_inverse_from_prior_readback(self):
        intent = o82.Option82Intent("Ethernet1", "", "P9-R6")
        self.assertEqual(o82.compensation_eos(o82.parse_eos(PRE), intent), [
            "interface Ethernet1", "   no ip dhcp relay information option circuit-id", "   no ip dhcp relay information option remote-id",
            "no ip dhcp relay information option"])
        prior = o82.parse_eos(POST)
        self.assertEqual(o82.compensation_eos(prior, o82.Option82Intent("Ethernet1", "X1")), [
            "interface Ethernet1", "   no ip dhcp relay information option circuit-id",
            "   ip dhcp relay information option remote-id P9-R6"])

    def test_compensation_eos_refuses_missing_prior_port(self):
        with self.assertRaises(o82.Option82Error):
            o82.compensation_eos(o82.parse_eos(PRE), o82.Option82Intent("Ethernet9"))

    def test_config_digest_ignores_banner_comments(self):
        self.assertEqual(o82.config_digest(PRE), o82.config_digest(PRE.replace("! device: P9RELAY", "! device: other banner")))

    def test_config_digest_changes_on_config_mismatch(self):
        self.assertNotEqual(o82.config_digest(PRE), o82.config_digest(POST))

    def test_change_payload_wraps_configure_session(self):
        self.assertEqual(o82.change_payload(["interface Ethernet1", "   no ip dhcp relay information option remote-id"]),
                         "configure\ninterface Ethernet1\nno ip dhcp relay information option remote-id\nend")

    def test_change_payload_refuses_empty_change(self):
        with self.assertRaises(o82.Option82Error):
            o82.change_payload([])


class Option82TrustGateTests(SimpleTestCase):
    def test_relay_trust_problems_accepts_verified_routed_relay_port(self):
        self.assertEqual(o82.relay_trust_problems(network=NETWORK, attachment=attachment(), readback=o82.parse_eos(POST)), [])

    def test_relay_trust_problems_refuses_relay_without_option82(self):
        problems = o82.relay_trust_problems(network=NETWORK, attachment=attachment(), readback=o82.parse_eos(PRE))
        self.assertEqual([p["code"] for p in problems], ["RELAY_UNTRUSTED"])

    def test_relay_trust_problems_refuses_forged_circuit_and_shared_giaddr(self):
        """Refused: a custom circuit id the reservation never matches, and an SVI whose giaddr is shared by many ports."""
        custom = o82.parse_eos(POST.replace("remote-id P9-R6", "remote-id P9-R6\n   ip dhcp relay information option circuit-id R6X"))
        self.assertIn("RELAY_UNTRUSTED", [p["code"] for p in o82.relay_trust_problems(network=NETWORK, attachment=attachment(),
                                                                                       readback=custom)])
        svi = {"enabled": True, "interfaces": {"Vlan90": {"circuit_id": "", "remote_id": "", "helpers": ["10.254.91.2"],
                                                          "addresses": ["10.254.90.1"]}}}
        problems = o82.relay_trust_problems(network=NETWORK, attachment=attachment("Vlan90"), readback=svi)
        self.assertTrue(any("giaddr" in p["reason"] for p in problems), problems)

    def test_relay_trust_problems_refuses_unknown_relay_unapproved_attachment_and_missing_port(self):
        other = SimpleNamespace(name="p9", service_address="10.254.99.2", trusted_relays=[])
        pending = SimpleNamespace(upstream_device="P9RELAY", upstream_interface="Ethernet1", approval_state="PENDING",
                                  verification_state="UNVERIFIED")
        codes = [p["code"] for p in o82.relay_trust_problems(network=other, attachment=pending, readback=o82.parse_eos(POST))]
        self.assertEqual(codes[:2], ["ATTACHMENT_MISMATCH", "BOOTSTRAP_PATH_UNAVAILABLE"])
        self.assertIn("BOOTSTRAP_PATH_UNAVAILABLE", codes[2:])          # helper does not reach the other service address
        self.assertEqual(o82.relay_trust_problems(network=NETWORK, attachment=None, readback={})[0]["code"], "ATTACHMENT_MISMATCH")
        missing = o82.relay_trust_problems(network=NETWORK, attachment=attachment("Ethernet5"), readback=o82.parse_eos(POST))
        self.assertIn("INTERFACE_INVALID", [p["code"] for p in missing])


class Option82DeviceBuilderTests(TestCase):
    def _relay(self, platform="arista_ceos", name="Ethernet1"):
        _change, intent, revision = make_candidate(platform=platform)
        interface = add_interface(revision, name=name)
        relay = service.add_dhcp_relay(revision=revision, family="IPV4", interface_id=interface["id"], destination="10.254.91.2")
        return intent, revision, relay

    def test_set_dhcp_relay_option82_stores_intent_and_renders_ceos(self):
        intent, revision, relay = self._relay()
        stored = service.set_dhcp_relay_option82(revision=revision, relay_id=relay["id"], circuit_id="R6-Et1", remote_id="P9-R6")
        self.assertEqual(stored["option82"], {"enabled": True, "circuit_id": "R6-Et1", "remote_id": "P9-R6"})
        text = candidate_renderer.render(intent, revision)["text"]
        self.assertIn("ip dhcp relay information option\n", text + "\n")
        self.assertIn("   ip dhcp relay information option circuit-id R6-Et1", text)
        self.assertIn("   ip dhcp relay information option remote-id P9-R6", text)

    def test_set_dhcp_relay_option82_refuses_invalid_value_and_ipv6_relay(self):
        _intent, revision, relay = self._relay()
        with self.assertRaises(service.CollectionMutationError):
            service.set_dhcp_relay_option82(revision=revision, relay_id=relay["id"], circuit_id="bad id")
        interface = add_interface(revision, name="Ethernet3")
        relay6 = service.add_dhcp_relay(revision=revision, family="IPV6", interface_id=interface["id"], destination="2001:db8::2")
        with self.assertRaises(service.CollectionMutationError):
            service.set_dhcp_relay_option82(revision=revision, relay_id=relay6["id"])

    def test_ceos_option82_interface_lines_render_port_ids(self):
        interface = {"name": "Ethernet1", "_scope": {"dhcp_relays": [
            {"family": "IPV4", "destination": "10.254.91.2", "option82": {"enabled": True, "circuit_id": "", "remote_id": "P9-R6"}}]}}
        self.assertEqual(platform_drivers._ceos_option82_interface_lines(interface, platform="arista_ceos"),
                         [{"kind": "static", "text": "   ip dhcp relay information option remote-id P9-R6"}])
        self.assertEqual([l["text"] for l in platform_drivers._dhcp_interface_contributions(interface, platform="arista_ceos")],
                         ["   ip helper-address 10.254.91.2", "   ip dhcp relay information option remote-id P9-R6"])

    def test_ceos_option82_interface_lines_refuse_other_platform_and_invalid_value(self):
        interface = {"name": "Ethernet1", "_scope": {"dhcp_relays": [
            {"family": "IPV4", "destination": "10.254.91.2", "option82": {"enabled": True, "circuit_id": "bad id"}}]}}
        self.assertEqual(platform_drivers._ceos_option82_interface_lines(interface, platform="nokia_srlinux"), [])
        self.assertIn("OPTION82_VALUE_INVALID",
                      platform_drivers._ceos_option82_interface_lines(interface, platform="arista_ceos")[0]["text"])
        self.assertEqual(platform_drivers._dhcp_interface_contributions({"name": "Ethernet1"}, platform="arista_ceos"), [])

    def test_option82_global_lines_render_once_for_ceos(self):
        relays = [{"family": "IPV4", "option82": {"enabled": True}}, {"family": "IPV4", "option82": {"enabled": True}}]
        self.assertEqual(platform_drivers._option82_global_lines("arista_ceos", "Arista cEOS", relays),
                         [{"kind": "static", "text": "ip dhcp relay information option"}])
        services = {"dhcp": {"mode": "OVERRIDE", "relays": {"a": {"id": "a", "sequence": 1, "family": "IPV4",
                                                                  "option82": {"enabled": True}}}}}
        texts = [l["text"] for l in platform_drivers._render_services("arista_ceos", "Arista cEOS", services, {}, ceos=True)]
        self.assertIn("ip dhcp relay information option", texts)

    def test_option82_global_lines_refuse_other_platform_and_empty(self):
        relays = [{"family": "IPV4", "option82": {"enabled": True}}]
        refused = platform_drivers._option82_global_lines("nokia_srlinux", "Nokia SR Linux", relays)
        self.assertEqual(len(refused), 1)
        self.assertNotIn("ip dhcp relay information option", refused[0].get("text", ""))
        self.assertEqual(platform_drivers._option82_global_lines("arista_ceos", "Arista cEOS", [{"family": "IPV4"}]), [])
        texts = [l["text"] for l in platform_drivers._render_services("arista_ceos", "Arista cEOS", {"dhcp": {"mode": "INHERIT"}}, {},
                                                                       ceos=True)]
        self.assertNotIn("ip dhcp relay information option", texts)


class Option82ZtpDependencyTests(Z.ZtpTestMixin, TestCase):
    READBACK = {"enabled": True, "interfaces": {"Ethernet7": {"circuit_id": "", "remote_id": "", "helpers": ["10.254.31.2"],
                                                             "addresses": [Z.RELAY]}}}

    def test_evaluate_accepts_relay_readback_with_option82(self):
        session = self.open_session()
        checks = {c["check"]: c for c in dependencies.evaluate(session.device, session.authorization.attachment, session.network,
                                                               relay_readback=self.READBACK)}
        self.assertTrue(checks["bootstrap_path_option82"]["ok"], checks["bootstrap_path_option82"])
        self.assertTrue(all(c["ok"] for c in checks.values()), checks)

    def test_evaluate_refuses_relay_readback_without_option82(self):
        session = self.open_session()
        readback = {**self.READBACK, "enabled": False}
        checks = {c["check"]: c for c in dependencies.evaluate(session.device, session.authorization.attachment, session.network,
                                                               relay_readback=readback)}
        self.assertEqual(checks["bootstrap_path_option82"]["code"], "RELAY_UNTRUSTED")
        self.assertIn("RELAY_UNTRUSTED", dependencies.blockers(checks.values()))
        # without an explicit read-back, NMAS's own stored read-back of the relay decides (helpers.ztp records S1's real one)
        stored = {c["check"]: c for c in dependencies.evaluate(session.device, session.authorization.attachment, session.network)}
        self.assertTrue(stored["bootstrap_path_option82"]["ok"], stored["bootstrap_path_option82"])
