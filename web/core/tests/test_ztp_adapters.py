"""V2 Phase 3: the native-ZTP adapter contract -- dispatch, evidence classes, transport policy, minimal bootstrap rendering,
secret / production refusal and verification parsing against the outputs NMAS read from the live cEOS bootstrap."""

from __future__ import annotations

import json

from django.test import SimpleTestCase

from core import models
from core.services.ztp import adapters
from core.services.ztp.adapters import base
from core.services.ztp.adapters.base import HTTP, HTTPS, TFTP, BootstrapContext, TransportPolicy
from core.services.ztp.adapters.cisco_iosxe import cisco_type9_locked_hash
from core.tests.helpers import ztp as Z

PUBLIC_ED25519 = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJ/Iv9voYWeUYAPxyzFQuZPH5XZR4/JrC9An+/A2pa3+ nmas-enroll@DEV-000002"
PUBLIC_RSA = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC7 nmas-enroll@DEV-000002"


def context(**overrides) -> BootstrapContext:
    fields = {"hostname": "ZTPNEW1", "session_id": "ZTP-000001", "auth_id": "BAUTH-000001", "interface": "Ethernet1", "address": "10.254.30.10",
              "prefixlen": 24, "gateway": "10.254.30.1", "service_address": "10.254.31.2", "service_prefix": "10.254.31.0/30",
              "enrollment_user": "nmas-enroll", "enrollment_public_key": PUBLIC_ED25519, "locked_password_hash": "$6$salt$lockedhash"}
    fields.update(overrides)
    return BootstrapContext(**fields)


class DispatchAndEvidenceTests(SimpleTestCase):
    def test_every_required_platform_has_an_adapter_with_a_known_evidence_class(self):
        names = set(adapters.ADAPTERS)
        self.assertTrue({"cisco_iosxe", "arista_eos", "nokia_srlinux", "sonic", "juniper_junos", "ubuntu_cloud_init"} <= names)
        for adapter in adapters.ADAPTERS.values():
            with self.subTest(adapter.capability.adapter):
                self.assertIn(adapter.capability.evidence_status, base.EVIDENCE_CLASSES)

    def test_dispatch_by_catalogue_platform(self):
        self.assertEqual(adapters.for_platform(models.Platform.ARISTA_CEOS).capability.adapter, "arista_eos")
        self.assertEqual(adapters.for_platform(models.Platform.UBUNTU_FRR).capability.adapter, "ubuntu_cloud_init")
        self.assertIsNone(adapters.for_platform("no-such-platform"))
        self.assertIsNone(adapters.get("no-such-adapter"))

    def test_only_live_proven_adapters_claim_support(self):
        supported = {n for n, a in adapters.ADAPTERS.items() if a.capability.evidence_status == base.SUPPORTED_AND_LIVE_VERIFIED}
        self.assertEqual(supported, {"arista_eos"})
        self.assertEqual(adapters.get("arista_eos").capability.evidence, "docs/evidence/v2-phase3-ztp/ceos-live-ztp.md")
        for name in ("sonic", "juniper_junos"):
            self.assertEqual(adapters.get(name).capability.evidence_status, base.NOT_TESTED_NO_IMAGE)

    def test_unimplemented_adapter_refuses_capability(self):
        _cap, codes = adapters.get("cisco_iosxr").detect_native_ztp_capability()
        self.assertEqual(codes, ["ZTP_ADAPTER_UNAVAILABLE"])

    def test_version_support(self):
        eos = adapters.get("arista_eos")
        self.assertEqual(eos.detect_native_ztp_capability("4.36.2F")[1], [])
        self.assertEqual(eos.detect_native_ztp_capability("3.9.0")[1], ["ZTP_VERSION_UNSUPPORTED"])
        self.assertEqual(eos.detect_native_ztp_capability("")[1], [])       # unknown is not refused at open; verification reads it

    def test_capability_report_is_json_and_covers_the_contract(self):
        report = json.loads(json.dumps(adapters.capability_report()))
        eos = next(r for r in report if r["adapter"] == "arista_eos")
        for key in ("retry", "recovery", "ztp_disable", "enrollment_requirements", "transport_decision"):
            self.assertIn(key, eos)
        self.assertFalse(eos["enrollment_requirements"]["bootstrap_plaintext_material"])

    def test_ubuntu_is_cloud_init_not_cisco_style_ztp(self):
        ubuntu = adapters.get("ubuntu_cloud_init")
        self.assertIn("cloud-init", ubuntu.capability.mechanism.lower())
        params = ubuntu.select_discovery_parameters("http://10.254.31.2:8080/ztp/v1/ART-x/user-data", HTTP, "10.254.31.2")
        self.assertEqual(params.options, ())


class TransportTests(SimpleTestCase):
    def test_strongest_served_transport_and_https_gap_is_recorded(self):
        decision = adapters.get("arista_eos").select_bootstrap_transport(TransportPolicy.ISOLATED_LAB)
        self.assertEqual(decision.selected, HTTP)
        self.assertEqual(decision.candidates, (HTTP, TFTP))
        self.assertIn("HTTPS", decision.reason)
        self.assertFalse(decision.as_dict()["integrity_protected"])

    def test_integrity_policy_never_downgrades(self):
        decision = adapters.get("arista_eos").select_bootstrap_transport(TransportPolicy.INTEGRITY_REQUIRED)
        self.assertEqual((decision.selected, decision.blockers), ("", ("ZTP_TRANSPORT_UNAVAILABLE",)))

    def test_https_is_selected_when_served(self):
        decision = adapters.get("arista_eos").select_bootstrap_transport(TransportPolicy.INTEGRITY_REQUIRED, service_transports=(HTTPS, HTTP))
        self.assertEqual(decision.selected, HTTPS)
        self.assertTrue(decision.as_dict()["integrity_protected"])

    def test_unknown_policy_allows_nothing(self):
        self.assertEqual(adapters.get("arista_eos").select_bootstrap_transport("ANYTHING").blockers, ("ZTP_TRANSPORT_UNAVAILABLE",))


class EosRenderTests(SimpleTestCase):
    def setUp(self):
        self.eos = adapters.get("arista_eos")

    def test_minimal_bootstrap_is_management_only_and_secret_free(self):
        rendered, codes = self.eos.prepare_bootstrap_artifact(context())
        self.assertEqual(codes, [])
        text = rendered.content
        self.assertEqual((rendered.filename, rendered.kind), ("startup-config", "startup-config"))
        for expected in ("hostname ZTPNEW1", "no ip routing", "ip address 10.254.30.10/24", "ip route 10.254.31.0/30 10.254.30.1",
                         "permit tcp host 10.254.31.2 any eq ssh", f"ssh-key {PUBLIC_ED25519}", "aaa authorization exec default local"):
            self.assertIn(expected, text)
        for forbidden in ("router ospf", "router bgp", "router rip", "router isis", "vlan ", "\nip routing", "password", "PRIVATE KEY"):
            self.assertNotIn(forbidden, text)
        self.assertEqual(base.secret_findings(text), [])

    def test_discovery_parameters_use_option_67_url_and_vendor_match(self):
        params = self.eos.select_discovery_parameters("http://10.254.31.2:8080/ztp/v1/ART-a/startup-config", HTTP, "10.254.31.2")
        self.assertEqual(params.vendor_class_prefix, "Arista;")
        self.assertEqual(params.options, (("bootfile-name", "http://10.254.31.2:8080/ztp/v1/ART-a/startup-config"),))

    def test_dhcp_claims_from_native_request(self):
        claims, native = self.eos.extract_dhcp_claims({"vendor_class": "Arista;cEOSLab;ZTPP3NEW0001", "client_id": "2:5a:70:0:0:1"})
        self.assertTrue(native)
        self.assertEqual((claims["serial"], claims["base_mac"]), ("ZTPP3NEW0001", "02:5a:70:00:00:01"))
        claims, native = self.eos.extract_dhcp_claims({"vendor_class": "MSFT 5.0", "client_id": "1:2"})
        self.assertFalse(native)
        self.assertNotIn("serial", claims)
        self.assertNotIn("base_mac", claims)

    def test_wrong_enrollment_key_type_is_refused(self):
        self.assertEqual(self.eos.prepare_bootstrap_artifact(context(enrollment_public_key=PUBLIC_RSA.replace("ssh-rsa", "ssh-dss")))[1],
                         ["ZTP_ENROLLMENT_BLOCKED"])

    def test_secret_in_render_is_refused(self):
        with self.subTest("plaintext password"):
            rendered, codes = self.eos.prepare_bootstrap_artifact(context(hostname="R1\nusername admin password 0 hunter2"))
            self.assertEqual((rendered, codes), (None, ["ARTIFACT_SECRET_DETECTED"]))
        with self.subTest("private key"):
            self.assertTrue(base.secret_findings("-----BEGIN OPENSSH " "PRIVATE KEY-----\nabc"))
        with self.subTest("radius shared secret"):
            self.assertTrue(base.secret_findings("radius-server host 10.0.0.1 key 0 s3cret"))

    def test_production_configuration_is_refused(self):
        rendered, codes = self.eos.prepare_bootstrap_artifact(context(hostname="R1\nrouter ospf 1"))
        self.assertEqual((rendered, codes), (None, ["BOOTSTRAP_VERIFICATION_FAILED"]))
        self.assertEqual(self.eos.production_findings("no ip routing\n"), [])
        self.assertEqual(self.eos.production_findings("ip routing\n"), ["ip routing"])


class EosVerificationTests(SimpleTestCase):
    """Against the outputs NMAS read from the NMAS-bootstrapped cEOS 4.36.2F (``fixtures/ztp``)."""

    def setUp(self):
        self.eos = adapters.get("arista_eos")
        capture = Z.eos_capture()
        self.ctx = context(**capture["context"])
        self.outputs = capture["outputs"]

    def test_live_outputs_pass_every_check(self):
        report = self.eos.verify_bootstrap_result(self.outputs, self.ctx)
        self.assertTrue(report.ok, [c for c in report.checks if not c["ok"]])
        self.assertEqual(len(report.checks), 11)
        self.assertTrue(report.ztp_disabled)
        self.assertEqual(report.production_services, [])
        self.assertEqual((report.claims["serial"], report.claims["base_mac"]), ("ZTPP3NEW0001", "02:5a:70:00:00:01"))

    def failed(self, **replace):
        report = self.eos.verify_bootstrap_result({**self.outputs, **replace}, self.ctx)
        self.assertFalse(report.ok)
        return {c["check"] for c in report.checks if not c["ok"]}

    def test_ztp_still_active_is_not_complete(self):
        self.assertEqual(self.failed(**{"show zerotouch | json": json.dumps({"mode": "active"})}), {"native_ztp_completed"})

    def test_routing_enabled_or_extra_routes_fail(self):
        route = json.loads(self.outputs["show ip route | json"][self.outputs["show ip route | json"].index("{"):])
        route["vrfs"]["default"]["routingDisabled"] = False
        route["vrfs"]["default"]["routes"]["0.0.0.0/0"] = {}
        self.assertEqual(self.failed(**{"show ip route | json": json.dumps(route)}), {"routing_disabled", "only_bootstrap_routes"})

    def test_production_service_in_running_config_fails(self):
        running = self.outputs["show running-config"] + "\nrouter bgp 65000\n"
        self.assertEqual(self.failed(**{"show running-config": running}), {"no_production_services"})

    def test_missing_enrollment_key_or_acl_fails(self):
        running = self.outputs["show running-config"].replace("ssh-key", "ssh-kex").replace("ip access-group NMAS-BOOTSTRAP-MGMT in", "")
        self.assertEqual(self.failed(**{"show running-config": running}), {"enrollment_key_installed", "management_acl_applied"})

    def test_wrong_hostname_and_unparseable_output(self):
        self.assertEqual(self.failed(**{"show hostname | json": '{"hostname": "OTHER"}'}), {"hostname"})
        self.assertIn("platform", self.failed(**{"show version | json": "% Invalid input"}))


class OtherAdapterTests(SimpleTestCase):
    def test_iosxe_renders_a_guestshell_script_with_a_locked_secret_and_rsa_key(self):
        iosxe = adapters.get("cisco_iosxe")
        self.assertEqual(iosxe.capability.evidence_status, base.IMPLEMENTED_UNIT_TESTED)
        rendered, codes = iosxe.prepare_bootstrap_artifact(context(interface="GigabitEthernet1", enrollment_public_key=PUBLIC_RSA,
                                                                   locked_password_hash=cisco_type9_locked_hash()))
        self.assertEqual(codes, [])
        self.assertIn("configurep", rendered.content)
        self.assertNotIn("password 0", rendered.content)
        self.assertEqual(iosxe.prepare_bootstrap_artifact(context(enrollment_public_key=PUBLIC_ED25519))[1], ["ZTP_ENROLLMENT_BLOCKED"])
        self.assertTrue(cisco_type9_locked_hash().startswith("$9$"))

    def test_iosxe_claims_from_pnp_client_id(self):
        client_id = ":".join(f"{b:x}" for b in b"\x00cisco-5254.0012.3456-Gi1")      # as ISC's binary-to-ascii writes it
        claims, native = adapters.get("cisco_iosxe").extract_dhcp_claims({"vendor_class": "ciscopnp", "client_id": client_id})
        self.assertTrue(native)
        self.assertEqual(claims.get("base_mac"), "52:54:00:12:34:56")

    def test_partial_and_untested_adapters_render_secret_free_artifacts(self):
        for name, key in (("nokia_srlinux", PUBLIC_ED25519), ("sonic", PUBLIC_ED25519), ("ubuntu_cloud_init", PUBLIC_ED25519)):
            with self.subTest(name):
                rendered, codes = adapters.get(name).prepare_bootstrap_artifact(context(interface="ethernet-1/1", enrollment_public_key=key))
                self.assertEqual(codes, [])
                self.assertEqual(base.secret_findings(rendered.content), [])

    def test_junos_option_43_carries_the_config_file_name(self):
        params = adapters.get("juniper_junos").select_discovery_parameters("tftp://10.254.31.2/ztp/v1/ART-a/juniper.conf", TFTP, "10.254.31.2")
        names = dict(params.options)
        self.assertIn("vendor-encapsulated-options", names)
        self.assertIn("tftp-server-name", names)

    def test_recovery_actions_never_claim_container_restart(self):
        for adapter in adapters.ADAPTERS.values():
            for action in adapter.determine_supported_recovery_actions():
                with self.subTest(adapter.capability.adapter, action=action.label):
                    self.assertNotIn("docker", f"{action.command} {action.label}".lower())
