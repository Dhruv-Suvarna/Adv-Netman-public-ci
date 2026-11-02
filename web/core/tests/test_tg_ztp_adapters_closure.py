"""Lab 7 closure -- the V2 Phase 3 native-ZTP adapter contract, each public operation called directly.

The behavioral adapter tests (``test_ztp_adapters``) drive rendering through ``prepare_bootstrap_artifact`` and verification
through the live cEOS capture; this module calls every contract operation itself, per adapter, so each one is proven at its
own boundary:  POSITIVE -- the exact discovery options, rendered artifact lines, verification checks, retry / recovery /
ZTP-disable facts and serializations.  NEGATIVE -- non-native requests yield no identity claim, malformed keys / addresses /
outputs raise or fail closed, injected lines are never filtered by a renderer (so the prepare step must refuse them), and the
base contract's defaults refuse rather than claim support.

Pure: no database, no device, no network.
"""
from __future__ import annotations

import ast
import base64
import hashlib
import json

from django.test import SimpleTestCase

from core.services.ztp import adapters
from core.services.ztp.adapters import base
from core.services.ztp.adapters.base import HTTP, HTTPS, TFTP, BootstrapContext
from core.services.ztp.adapters.cisco_iosxe import rsa_key_hash
from core.tests.helpers import ztp as Z

ED25519 = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJ/Iv9voYWeUYAPxyzFQuZPH5XZR4/JrC9An+/A2pa3+ nmas-enroll@DEV-000002"
RSA = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC7 nmas-enroll@DEV-000002"
URL = "http://10.254.31.2:8080/ztp/v1/ART-a/startup-config"


def ctx(**overrides) -> BootstrapContext:
    fields = {"hostname": "ZTPNEW1", "session_id": "ZTP-000001", "auth_id": "BAUTH-000001", "interface": "Ethernet1", "address": "10.254.30.10",
              "prefixlen": 24, "gateway": "10.254.30.1", "service_address": "10.254.31.2", "service_prefix": "10.254.31.0/30",
              "enrollment_user": "nmas-enroll", "enrollment_public_key": ED25519, "locked_password_hash": "$6$salt$lockedhash"}
    fields.update(overrides)
    return BootstrapContext(**fields)


def ascii_client_id(text: bytes) -> str:
    return ":".join(f"{b:x}" for b in text)


class BaseContractTests(SimpleTestCase):
    """The base class's own defaults, called on IOS XR (the adapter that overrides nothing) and on SONiC / SR Linux for the
    shared production / verification helpers they inherit."""

    def setUp(self):
        self.xr = adapters.get("cisco_iosxr")
        self.sonic = adapters.get("sonic")

    def test_version_tuple_parses_major_minor_and_patch(self):
        self.assertEqual(base.version_tuple("4.36.2F"), (4, 36, 2))
        self.assertEqual(base.version_tuple(" 17.06"), (17, 6))

    def test_version_tuple_of_unparseable_text_is_empty(self):
        self.assertEqual(base.version_tuple("garbage"), ())
        self.assertEqual(base.version_tuple(None), ())

    def test_secret_findings_returns_the_line_numbers_of_secret_lines(self):
        self.assertEqual(base.secret_findings("hostname R1\nusername a secret 0 x\nradius-server host 1.1.1.1 key s\n"), ["2", "3"])

    def test_secret_findings_of_a_public_key_and_locked_hash_are_empty(self):
        """A public key and a crypt hash of discarded bytes are never reported as secrets."""
        self.assertEqual(base.secret_findings(f"username u ssh-key {ED25519}\nusername u secret sha512 $6$s$h\n"), [])

    def test_network_of_returns_the_containing_network(self):
        self.assertEqual(base.NativeZtpAdapter.network_of("10.254.30.10", 24), "10.254.30.0/24")

    def test_network_of_an_invalid_address_raises(self):
        with self.assertRaises(ValueError):
            base.NativeZtpAdapter.network_of("10.254.30.999", 24)

    def test_base_production_findings_report_routing_statements(self):
        self.assertEqual(self.sonic.production_findings("router bgp 65000\nip routing\n"), ["router bgp 65000", "ip routing"])

    def test_base_production_findings_of_bootstrap_text_are_empty(self):
        """Management-only bootstrap text has no production finding (and None is refused as text, never a crash)."""
        self.assertEqual(self.sonic.production_findings("hostname R1\ninterface Ethernet1\n"), [])
        self.assertEqual(self.sonic.production_findings(None), [])

    def test_base_defaults_describe_a_console_only_adapter(self):
        self.assertEqual(self.xr.verification_commands(), ())
        self.assertEqual(self.xr.inspect_native_bootstrap_status({"show": "x"}), {"known": False})
        self.assertEqual(self.xr.extract_dhcp_claims({"vendor_class": "Cisco"}), ({}, False))
        retry = self.xr.determine_native_retry_behavior()
        self.assertEqual((retry.dhcp_retry_interval_seconds, retry.retries_indefinitely), (None, None))
        self.assertEqual([a.key for a in self.xr.determine_supported_recovery_actions()], ["OPERATOR_CONSOLE"])
        disable = self.xr.determine_ztp_disable_capability()
        self.assertEqual((disable.automatic_after_success, disable.verifiable_over_management), (None, False))

    def test_base_verification_reports_the_unimplemented_check(self):
        report = self.sonic.verify_bootstrap_result({}, ctx())
        self.assertEqual(report.as_dict()["checks"], [{"check": "adapter", "ok": False, "detail": "no verification is implemented for this platform"}])
        self.assertFalse(report.ok)

    def test_enrollment_requirements_list_the_public_key_types(self):
        requirements = adapters.get("arista_eos").identify_enrollment_requirements()
        self.assertEqual(requirements["key_types"], ["ssh-ed25519", "ssh-rsa", "ecdsa-sha2-nistp256"])
        self.assertFalse(requirements["blocked"])
        self.assertFalse(requirements["bootstrap_plaintext_material"])

    def test_enrollment_requirements_of_an_adapter_without_key_types_are_blocked(self):
        self.assertTrue(self.xr.identify_enrollment_requirements()["blocked"])

    def test_describe_returns_every_contract_fact(self):
        eos = adapters.get("arista_eos").describe()
        self.assertEqual(eos["adapter"], "arista_eos")
        self.assertEqual(eos["retry"]["dhcp_retry_interval_seconds"], 30)
        self.assertEqual(eos["transport_decision"]["selected"], HTTP)
        self.assertEqual(adapters.get("cisco_iosxr").describe()["transport_decision"], {})

    def test_capability_and_fact_serializations_round_trip_through_json(self):
        cap = adapters.get("arista_eos").capability.as_dict()
        self.assertEqual(cap["min_version"], [4, 0])
        self.assertEqual(json.loads(json.dumps(cap))["transports"], [HTTPS, HTTP, TFTP])
        self.assertEqual(base.RetryBehavior("d", 5, True, "z", "e").as_dict(),
                         {"dhcp_retry": "d", "dhcp_retry_interval_seconds": 5, "retries_indefinitely": True, "ztp_retry": "z", "evidence": "e"})
        self.assertEqual(base.RecoveryAction("K", "L", True, "r", "c").as_dict(),
                         {"key": "K", "label": "L", "native": True, "requires": "r", "command": "c"})
        self.assertEqual(base.ZtpDisableCapability(True, True, "how").as_dict(),
                         {"automatic_after_success": True, "verifiable_over_management": True, "how": "how", "read_back": ""})

    def test_verification_report_add_records_a_passing_check(self):
        report = base.VerificationReport(ok=True)
        report.add("hostname", True, "R1")
        self.assertEqual(report.as_dict(), {"ok": True, "checks": [{"check": "hostname", "ok": True, "detail": "R1"}], "claims": {},
                                            "ztp_disabled": None, "production_services": []})

    def test_verification_report_add_of_a_failed_check_fails_the_report(self):
        report = base.VerificationReport(ok=True)
        report.add("routing_disabled", False, "x" * 500)
        report.add("hostname", True)
        self.assertFalse(report.ok)                       # a later passing check never restores a failed report
        self.assertEqual(len(report.checks[0]["detail"]), 200)


class AristaEosClosureTests(SimpleTestCase):
    def setUp(self):
        self.eos = adapters.get("arista_eos")

    def test_eos_renders_the_minimal_management_startup_config(self):
        rendered = self.eos.render_minimal_bootstrap(ctx())
        self.assertEqual((rendered.filename, rendered.content_type, rendered.kind), ("startup-config", "text/plain", "startup-config"))
        self.assertIn("username nmas-enroll ssh-key " + ED25519, rendered.content)
        self.assertIn("   ip access-group NMAS-BOOTSTRAP-MGMT in", rendered.content)
        self.assertTrue(rendered.content.endswith("end\n"))

    def test_eos_bootstrap_never_filters_an_injected_line_so_prepare_must_refuse_it(self):
        rendered = self.eos.render_minimal_bootstrap(ctx(hostname="R1\nrouter bgp 65000"))
        self.assertIn("router bgp 65000", rendered.content)
        self.assertEqual(self.eos.production_findings(rendered.content), ["router bgp 65000"])
        self.assertEqual(self.eos.prepare_bootstrap_artifact(ctx(hostname="R1\nrouter bgp 65000"))[1], ["BOOTSTRAP_VERIFICATION_FAILED"])

    def test_eos_discovery_never_offers_a_separate_file_server_option(self):
        """EOS reads a full URL from option 67 for every transport: no option 66 is rendered, even for TFTP."""
        params = self.eos.select_discovery_parameters("tftp://10.254.31.2/ztp/v1/ART-a/startup-config", TFTP, "10.254.31.2")
        self.assertEqual([name for name, _value in params.options], ["bootfile-name"])
        self.assertNotIn("tftp-server-name", dict(params.options))

    def test_eos_non_native_request_yields_no_identity_claim(self):
        claims, native = self.eos.extract_dhcp_claims({"vendor_class": "Arista;cEOSLab;", "client_id": "zz:1"})
        self.assertTrue(native)                           # an Arista request, but no serial and a malformed client id
        self.assertEqual(claims, {"client_id": "zz:1"})
        self.assertEqual(self.eos.extract_dhcp_claims({}), ({}, False))

    def test_eos_inspects_the_disabled_zerotouch_state(self):
        self.assertEqual(self.eos.inspect_native_bootstrap_status({"show zerotouch | json": '{"mode": "disabled"}'}),
                         {"known": True, "mode": "disabled", "disabled": True})

    def test_eos_unparseable_zerotouch_output_is_unknown(self):
        self.assertEqual(self.eos.inspect_native_bootstrap_status({"show zerotouch | json": "% Invalid input"}), {"known": False})
        self.assertEqual(self.eos.inspect_native_bootstrap_status({}), {"known": False})

    def test_eos_production_findings_report_positive_routing_statements(self):
        self.assertEqual(self.eos.production_findings("ip routing\nrouter ospf 1\n"), ["router ospf 1", "ip routing"])

    def test_eos_verification_commands_and_native_facts(self):
        self.assertEqual(set(self.eos.verification_commands()), set(Z.eos_capture()["outputs"]))
        retry = self.eos.determine_native_retry_behavior()
        self.assertEqual((retry.dhcp_retry_interval_seconds, retry.retries_indefinitely), (30, True))
        self.assertEqual([a.key for a in self.eos.determine_supported_recovery_actions()], ["WAIT_NATIVE_RETRY", "ZTP_CANCEL", "RE_ZTP", "RELOAD"])
        disable = self.eos.determine_ztp_disable_capability()
        self.assertEqual((disable.automatic_after_success, disable.verifiable_over_management), (True, True))


class CiscoIosXeClosureTests(SimpleTestCase):
    def setUp(self):
        self.iosxe = adapters.get("cisco_iosxe")
        self.ctx = ctx(interface="GigabitEthernet1", enrollment_public_key=RSA, locked_password_hash="$9$salt$hash")

    def running(self, **extra) -> str:
        key = rsa_key_hash(RSA)
        text = (f"hostname ZTPNEW1\nno ip routing\nip ssh pubkey-chain\n username nmas-enroll\n  key-hash ssh-rsa {key}\n"
                "line vty 0 4\n access-class NMAS-BOOTSTRAP-MGMT in\n")
        return text + "".join(extra.values())

    def outputs(self, running=None) -> dict:
        return {"show version": "Cisco IOS XE Software, Version 17.06.01a\nProcessor board ID 9ABCDEF0123\n",
                "show running-config": running if running is not None else self.running(),
                "show ip interface brief": "Interface IP-Address OK? Method Status Protocol\nGigabitEthernet1 10.254.30.10 YES manual up up\n"}

    def test_rsa_key_hash_is_the_upper_case_md5_of_the_key_blob(self):
        blob = base64.b64decode(RSA.split()[1])
        self.assertEqual(rsa_key_hash(RSA), hashlib.md5(blob, usedforsecurity=False).hexdigest().upper())
        self.assertRegex(rsa_key_hash(RSA), r"^[0-9A-F]{32}$")

    def test_rsa_key_hash_of_a_malformed_key_raises(self):
        with self.assertRaises(IndexError):
            rsa_key_hash("ssh-rsa")
        with self.assertRaises(ValueError):
            rsa_key_hash("ssh-rsa not*base64")

    def test_iosxe_discovery_selects_python_ztp_with_the_script_url(self):
        params = self.iosxe.select_discovery_parameters(URL, HTTP, "10.254.31.2")
        self.assertEqual((params.vendor_class_prefix, params.options), ("ciscopnp", (("bootfile-name", URL),)))

    def test_iosxe_discovery_never_sends_option_43_that_would_trigger_pnp(self):
        params = self.iosxe.select_discovery_parameters(URL, TFTP, "10.254.31.2")
        self.assertNotIn("vendor-encapsulated-options", dict(params.options))

    def test_iosxe_non_native_request_with_malformed_client_id_yields_no_mac_claim(self):
        claims, native = self.iosxe.extract_dhcp_claims({"vendor_class": "MSFT 5.0", "client_id": "zz:ff"})
        self.assertFalse(native)
        self.assertEqual(claims, {"client_id": "zz:ff"})
        claims, _native = self.iosxe.extract_dhcp_claims({"vendor_class": "ciscopnp", "client_id": ascii_client_id(b"juniper-1234")})
        self.assertNotIn("base_mac", claims)

    def test_iosxe_renders_a_guestshell_script_applying_the_bootstrap(self):
        rendered = self.iosxe.render_minimal_bootstrap(self.ctx)
        self.assertEqual((rendered.filename, rendered.content_type, rendered.kind), ("ztp.py", "text/x-python", "python-script"))
        self.assertIn(f"'key-hash ssh-rsa {rsa_key_hash(RSA)}'", rendered.content)
        self.assertIn("'ip address 10.254.30.10 255.255.255.0'", rendered.content)
        ast.parse(rendered.content)                       # the script is valid Python for guest shell

    def test_iosxe_render_of_a_key_without_a_blob_raises(self):
        with self.assertRaises(IndexError):
            self.iosxe.render_minimal_bootstrap(ctx(enrollment_public_key="ssh-rsa"))

    def test_iosxe_production_findings_report_routing_statements(self):
        self.assertEqual(self.iosxe.production_findings("ip routing\nrouter isis\n"), ["router isis", "ip routing"])

    def test_iosxe_production_findings_never_count_the_no_ip_routing_refusal(self):
        self.assertEqual(self.iosxe.production_findings("no ip routing\n"), [])

    def test_iosxe_verification_of_a_bootstrapped_device_passes_every_check(self):
        report = self.iosxe.verify_bootstrap_result(self.outputs(), self.ctx)
        self.assertTrue(report.ok, [c for c in report.checks if not c["ok"]])
        self.assertEqual(report.claims, {"serial": "9ABCDEF0123", "version": "17.06.01a"})
        self.assertIsNone(report.ztp_disabled)

    def test_iosxe_verification_with_routing_enabled_and_missing_key_fails(self):
        running = self.running().replace("no ip routing\n", "ip routing\n").replace(rsa_key_hash(RSA), "0" * 32)
        report = self.iosxe.verify_bootstrap_result(self.outputs(running), self.ctx)
        self.assertFalse(report.ok)
        self.assertEqual({c["check"] for c in report.checks if not c["ok"]},
                         {"routing_disabled", "no_production_services", "enrollment_key_installed"})

    def test_iosxe_verification_commands_and_native_facts(self):
        self.assertIn("show running-config", self.iosxe.verification_commands())
        self.assertIsNone(self.iosxe.determine_native_retry_behavior().dhcp_retry_interval_seconds)
        self.assertEqual([a.key for a in self.iosxe.determine_supported_recovery_actions()], ["WRITE_ERASE_RELOAD", "CONSOLE_ABORT"])
        disable = self.iosxe.determine_ztp_disable_capability()
        self.assertEqual((disable.automatic_after_success, disable.verifiable_over_management), (True, False))


class OtherAdapterClosureTests(SimpleTestCase):
    def test_srlinux_discovery_names_the_provisioning_script(self):
        params = adapters.get("nokia_srlinux").select_discovery_parameters(URL, HTTP, "10.254.31.2")
        self.assertEqual(params.options, (("bootfile-name", URL),))

    def test_srlinux_discovery_never_relies_on_the_vendor_class(self):
        self.assertEqual(adapters.get("nokia_srlinux").select_discovery_parameters(URL, TFTP, "10.254.31.2").vendor_class_prefix, "")

    def test_srlinux_renders_a_provisioning_script_of_cli_statements(self):
        rendered = adapters.get("nokia_srlinux").render_minimal_bootstrap(ctx(interface="ethernet-1/1"))
        self.assertEqual((rendered.filename, rendered.kind), ("provision.py", "python-script"))
        self.assertIn("set / interface ethernet-1/1 subinterface 0 ipv4 address 10.254.30.10/24", rendered.content)

    def test_srlinux_script_never_lets_a_quoted_value_escape_the_statement_list(self):
        rendered = adapters.get("nokia_srlinux").render_minimal_bootstrap(ctx(hostname='R1"]\nimport os  #'))
        tree = ast.parse(rendered.content)
        imports = [n for n in ast.walk(tree) if isinstance(n, ast.Import)]
        self.assertEqual([alias.name for node in imports for alias in node.names], ["subprocess"])

    def test_srlinux_native_retry_and_recovery_facts(self):
        srl = adapters.get("nokia_srlinux")
        self.assertIsNone(srl.determine_native_retry_behavior().retries_indefinitely)
        self.assertEqual([a.key for a in srl.determine_supported_recovery_actions()], ["ZTP_RESTART", "OPERATOR_CONSOLE"])

    def test_sonic_discovery_names_the_option_239_script(self):
        params = adapters.get("sonic").select_discovery_parameters(URL, HTTP, "10.254.31.2")
        self.assertEqual(params.options, (("nmas-sonic-provisioning-script", URL),))

    def test_sonic_discovery_never_uses_the_option_67_json_form(self):
        self.assertNotIn("bootfile-name", dict(adapters.get("sonic").select_discovery_parameters(URL, TFTP, "10.254.31.2").options))

    def test_sonic_renders_a_strict_mode_provisioning_script(self):
        rendered = adapters.get("sonic").render_minimal_bootstrap(ctx())
        self.assertEqual((rendered.filename, rendered.kind), ("provision.sh", "provisioning-script"))
        self.assertTrue(rendered.content.startswith("#!/bin/bash\n"))
        self.assertIn("set -eu", rendered.content)
        self.assertIn(f"echo '{ED25519}' > /home/nmas-enroll/.ssh/authorized_keys", rendered.content)

    def test_sonic_script_never_sets_a_password_and_locks_password_login(self):
        content = adapters.get("sonic").render_minimal_bootstrap(ctx()).content
        self.assertIn("passwd -l nmas-enroll", content)
        self.assertNotIn("chpasswd", content)

    def test_sonic_recovery_and_ztp_disable_facts(self):
        sonic = adapters.get("sonic")
        self.assertEqual([a.command for a in sonic.determine_supported_recovery_actions()], ["ztp run -y", "ztp enable"])
        self.assertEqual(sonic.determine_ztp_disable_capability().read_back, "ztp status")

    def test_junos_renders_key_only_root_authentication(self):
        rendered = adapters.get("juniper_junos").render_minimal_bootstrap(ctx(interface="ge-0/0/0"))
        self.assertEqual((rendered.filename, rendered.kind), ("bootstrap.conf", "junos-config"))
        self.assertIn(f'root-authentication {{ ssh-ed25519 "{ED25519}"; }}', rendered.content)
        self.assertIn("ssh { root-login deny; }", rendered.content)

    def test_junos_render_of_an_unsupported_key_type_raises(self):
        with self.assertRaises(KeyError):
            adapters.get("juniper_junos").render_minimal_bootstrap(ctx(enrollment_public_key="ecdsa-sha2-nistp256 AAAA x"))

    def test_junos_non_http_transport_never_selects_http_transfer_mode(self):
        params = adapters.get("juniper_junos").select_discovery_parameters("tftp://10.254.31.2/ztp/v1/ART-a/j.conf", TFTP, "10.254.31.2")
        option43 = bytes(int(b, 16) for b in dict(params.options)["vendor-encapsulated-options"].split(":"))
        self.assertTrue(option43.endswith(b"\x03\x04tftp"))
        self.assertIn(b"/ztp/v1/ART-a/j.conf", option43)

    def test_ubuntu_seed_url_is_recorded_in_the_notes(self):
        params = adapters.get("ubuntu_cloud_init").select_discovery_parameters("http://10.254.31.2:8080/ztp/v1/ART-x/user-data", HTTP, "x")
        self.assertIn("ds=nocloud-net;s=http://10.254.31.2:8080/ztp/v1/ART-x/", params.notes)

    def test_ubuntu_renders_cloud_config_user_data(self):
        rendered = adapters.get("ubuntu_cloud_init").render_minimal_bootstrap(ctx(interface="eth1"))
        self.assertEqual((rendered.filename, rendered.content_type), ("user-data", "text/cloud-config"))
        self.assertTrue(rendered.content.startswith("#cloud-config\n"))
        self.assertIn("            addresses: [10.254.30.10/24]", rendered.content)
        self.assertIn("ssh_pwauth: false", rendered.content)

    def test_ubuntu_render_of_an_invalid_address_raises(self):
        with self.assertRaises(ValueError):
            adapters.get("ubuntu_cloud_init").render_minimal_bootstrap(ctx(address="10.254.30.300"))

    def test_ubuntu_native_retry_and_recovery_facts(self):
        ubuntu = adapters.get("ubuntu_cloud_init")
        self.assertEqual(ubuntu.determine_native_retry_behavior().ztp_retry, "cloud-init runs once per instance id")
        self.assertEqual([a.command for a in ubuntu.determine_supported_recovery_actions()], ["cloud-init clean --reboot"])
