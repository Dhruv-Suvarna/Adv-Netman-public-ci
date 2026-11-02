"""V2 Phase 3: bootstrap networks and the DHCP provider contract -- ISC (operational) and Kea (rendered and validated only).

Every provider write goes to a temporary isolated root; validate / status commands are a fake runner that records argv."""

from __future__ import annotations

import csv
import io
import json
import shutil
import tempfile
from pathlib import Path

from django.test import SimpleTestCase, TestCase

from core import models
from core.services.ztp import dhcp, policy, workflow
from core.services.ztp.dhcp import base as dhcp_base
from core.services.ztp.dhcp.isc import IscDhcpProvider
from core.services.ztp.dhcp.kea import KeaDhcp4Provider, _circuit_from_hex
from core.tests.helpers import lifecycle as L
from core.tests.helpers import ztp as Z

RES = dhcp.Reservation("ZTP-000001", "NEW1", "10.254.30.10", "10.254.30.1", "Ethernet7", "Arista;",
                       (("bootfile-name", "http://10.254.31.2:8080/ztp/v1/ART-0123456789abcdef01234567/startup-config"),))
POLICY = dhcp.BootstrapPolicy("ztp-test", "10.254.30.0/24", "10.254.30.1", "10.254.31.0/30", (RES,))


class SupervisorRunner(Z.FakeRunner):
    """Like the fixture's supervisor: a status call after a restart request finds dhcpd restarted (marker consumed)."""

    def __init__(self, root, rc=0, status_rc=0):
        super().__init__(rc)
        self.root, self.status_rc = Path(root), status_rc

    def __call__(self, argv):
        self.calls.append(list(argv))
        if argv == Z.STATUS:
            (self.root / "restart").unlink(missing_ok=True)
            return self.status_rc, "1234"
        return self.rc, ""


class IscRenderTests(SimpleTestCase):
    def test_class_matches_trusted_relay_circuit_and_vendor_with_single_address_pool(self):
        text = IscDhcpProvider("/tmp/x").render(POLICY)
        self.assertIn('class "nmas-ZTP-000001"', text)
        self.assertIn('packet(24, 4) = 0a:fe:1e:01 and option agent.circuit-id = "Ethernet7"', text)
        self.assertIn('substring(option vendor-class-identifier, 0, 7) = "Arista;"', text)
        self.assertIn('option bootfile-name "http://10.254.31.2:8080/ztp/v1/', text)
        self.assertIn('allow members of "nmas-ZTP-000001"; range 10.254.30.10 10.254.30.10;', text)
        self.assertNotIn("192.168.200", text)
        self.assertEqual(text.count("range "), 1)               # no dynamic pool: nothing is offered to an unknown client

    def test_empty_policy_offers_no_address(self):
        text = IscDhcpProvider("/tmp/x").render(dhcp.BootstrapPolicy("ztp-test", "10.254.30.0/24", "10.254.30.1", "10.254.31.0/30"))
        self.assertNotIn("range ", text)

    def test_injection_and_out_of_subnet_values_are_refused(self):
        bad_options = dhcp.Reservation("ZTP-000001", "NEW1", "10.254.30.10", "10.254.30.1", "Ethernet7", "",
                                       (("bootfile-name", 'x"; } class "evil'),))
        outside = dhcp.Reservation("ZTP-000001", "NEW1", "10.9.9.9", "10.254.30.1", "Ethernet7")
        for res in (bad_options, outside):
            with self.subTest(res.address), self.assertRaises(dhcp.ProviderError):
                IscDhcpProvider("/tmp/x").render(dhcp.BootstrapPolicy("ztp-test", "10.254.30.0/24", "10.254.30.1", "10.254.31.0/30", (res,)))

    def test_lease_parsing_reads_the_stashed_relay_evidence(self):
        rows = IscDhcpProvider("/tmp/x").parse_leases(Z.lease() + Z.released())
        self.assertEqual(len(rows), 2)
        self.assertEqual((rows[0]["relay_address"], rows[0]["circuit_id"], rows[0]["client_id"], rows[0]["binding_state"]),
                         ("10.254.30.1", "Ethernet7", Z.CLIENT_ID, "active"))
        self.assertEqual((rows[1]["relay_address"], rows[1]["binding_state"]), ("", "free"))
        unrelayed = IscDhcpProvider("/tmp/x").parse_leases(Z.lease(relay="0.0.0.0"))
        self.assertEqual(unrelayed[0]["relay_address"], "")

    def test_the_live_lease_evidence_parses(self):
        evidence = Path(__file__).resolve().parents[3] / "docs/evidence/v2-phase3-ztp/ceos-dhcpd-leases.txt"
        rows = IscDhcpProvider("/tmp/x").parse_leases(evidence.read_text(encoding="utf-8"))
        self.assertEqual(rows[0]["vendor_class"], "Arista;cEOSLab;ZTPP3NEW0001")
        self.assertEqual(rows[0]["client_id"], "2:5a:70:0:0:1")
        self.assertEqual(rows[-1]["binding_state"], "free")


class SafeRootTests(SimpleTestCase):
    def test_production_and_relative_roots_are_refused(self):
        for root in ("/etc/dhcp", "/var/lib/dhcp", "/var/lib/kea", "/run/x", "relative/dir", "", "/tmp/../etc/dhcp"):
            with self.subTest(root), self.assertRaises(dhcp.ProviderError) as caught:
                dhcp_base.safe_root(root)
            self.assertEqual(caught.exception.code, "DHCP_CONFIG_ROOT_UNSAFE")

    def test_default_provider_roots_exclude_the_protected_checkouts(self):
        roots = dhcp_base.provider_roots()
        self.assertTrue(roots)
        for root in roots:
            with self.subTest(str(root)):
                self.assertTrue(str(root).endswith(("labs/ztp-isolated/runtime", "var/ztp")))
        for protected in ("/home/student/Scripts/clab_dualstack_lab", "/home/student/Scripts/clab_dualstack_lab-deploy/web/var",
                          "/home/student/clab-quickstart"):
            with self.subTest(protected), self.assertRaises(dhcp.ProviderError):
                dhcp_base.safe_root(protected)

    def test_check_value_refuses_quotes_and_backslashes(self):
        for value in ('a"b', "a\\b", "a\nb", "x" * 300):
            with self.subTest(value[:10]), self.assertRaises(dhcp.ProviderError):
                dhcp_base.check_value(value)


class KeaTests(SimpleTestCase):
    def test_kea_renders_the_same_policy_contract(self):
        config = json.loads(KeaDhcp4Provider("/tmp/x").render(POLICY))["Dhcp4"]
        klass = config["client-classes"][0]
        self.assertEqual(klass["name"], "nmas-ZTP-000001")
        self.assertIn("pkt4.giaddr == 10.254.30.1", klass["test"])
        self.assertIn("relay4[1].text == 'Ethernet7'", klass["test"])
        self.assertEqual(klass["option-data"][0]["name"], "boot-file-name")
        self.assertEqual(config["subnet4"][0]["pools"], [{"pool": "10.254.30.10 - 10.254.30.10", "client-class": "nmas-ZTP-000001"}])
        self.assertEqual(config["subnet4"][0]["relay"], {"ip-addresses": ["10.254.30.1"]})
        self.assertTrue(config["store-extended-info"])

    def test_kea_is_not_operational(self):
        provider = KeaDhcp4Provider("/tmp/x")
        self.assertFalse(provider.operational)
        for call in (lambda: provider.apply(POLICY), provider.rollback, provider.read_back):
            with self.assertRaises(dhcp.ProviderError) as caught:
                call()
            self.assertEqual(caught.exception.code, "DHCP_PROVIDER_UNSUPPORTED")

    def test_kea_memfile_parsing_and_circuit_id(self):
        self.assertEqual(_circuit_from_hex("0x010945746865726e657437"), "Ethernet7")
        self.assertEqual(_circuit_from_hex("zz"), "")
        buffer = io.StringIO()
        writer = csv.writer(buffer)
        writer.writerow(["address", "hwaddr", "client_id", "valid_lifetime", "expire", "subnet_id", "fqdn_fwd", "fqdn_rev", "hostname", "state",
                         "user_context"])
        writer.writerow(["10.254.30.10", "a2:27:1c:9a:b6:7b", "01:02", "600", "2000000000", "1", "0", "0", "", "0",
                         json.dumps({"ISC": {"relay-agent-info": {"sub-options": "0x010945746865726E657437"}}})])
        rows = KeaDhcp4Provider("/tmp/x").parse_leases(buffer.getvalue())
        self.assertEqual((rows[0]["address"], rows[0]["circuit_id"], rows[0]["binding_state"]), ("10.254.30.10", "Ethernet7", "active"))
        self.assertEqual(rows[0]["relay_address"], "")      # the memfile carries no giaddr: Kea leases never prove a trusted relay


class NetworkPolicyTests(Z.ZtpTestMixin, TestCase):
    def setUp(self):
        super().setUp()
        L.adopt()

    def problems(self, **overrides):
        fields = {**Z.NET, "config_root": str(self.root / "dhcp"), "trusted_relays": [{"relay_address": Z.RELAY, "upstream_device": "S1"}]}
        fields.update(overrides)
        return [p["code"] for p in policy.network_problems(**fields)]

    def test_valid_network(self):
        self.assertEqual(self.problems(), [])

    def test_vlan_200_and_protected_prefixes_are_refused(self):
        self.assertIn("VLAN200_PURPOSE_FORBIDDEN", self.problems(vlan=200))
        self.assertIn("BOOTSTRAP_NETWORK_INVALID", self.problems(ipv4_prefix="192.168.200.0/24", gateway="192.168.200.1",
                                                                 pool_start="192.168.200.10", pool_end="192.168.200.20"))
        self.assertIn("BOOTSTRAP_NETWORK_INVALID", self.problems(ipv4_prefix="172.20.20.0/24", gateway="172.20.20.1",
                                                                 pool_start="172.20.20.10", pool_end="172.20.20.20"))

    def test_invalid_pools_and_layout(self):
        cases = {"gateway in pool": {"pool_start": "10.254.30.1"}, "pool reversed": {"pool_start": "10.254.30.20", "pool_end": "10.254.30.10"},
                 "pool outside": {"pool_end": "10.254.31.20"}, "service overlaps": {"service_prefix": "10.254.30.0/30", "service_address": "10.254.30.2"},
                 "too large": {"ipv4_prefix": "10.0.0.0/8"}, "bad address": {"gateway": "not-an-ip"}}
        for label, overrides in cases.items():
            with self.subTest(label):
                self.assertIn("BOOTSTRAP_NETWORK_INVALID", self.problems(**overrides))

    def test_relays_are_required_and_must_be_trusted_upstreams(self):
        self.assertIn("BOOTSTRAP_NETWORK_INVALID", self.problems(trusted_relays=[]))
        self.assertIn("UPSTREAM_UNKNOWN", self.problems(trusted_relays=[{"relay_address": Z.RELAY, "upstream_device": "NOPE"}]))
        self.assertIn("BOOTSTRAP_NETWORK_INVALID", self.problems(trusted_relays=[{"relay_address": "10.9.9.9", "upstream_device": "S1"}]))

    def test_unsafe_config_root(self):
        self.assertIn("DHCP_CONFIG_ROOT_UNSAFE", self.problems(config_root="/etc/dhcp"))

    def test_config_root_outside_the_provider_roots_is_refused(self):
        """Review regression: an absolute, non-system directory outside the configured provider roots (e.g. a checkout or a
        home directory) must never become a provider directory NMAS writes into."""
        outside = Path(tempfile.mkdtemp(prefix="nmas-ztp-outside-"))
        self.addCleanup(shutil.rmtree, outside, True)
        self.assertIn("DHCP_CONFIG_ROOT_UNSAFE", self.problems(config_root=str(outside)))
        self.assertIn("DHCP_CONFIG_ROOT_UNSAFE", self.problems(config_root=str(Path(__file__).resolve().parents[2])))
        self.assertIn("DHCP_CONFIG_ROOT_UNSAFE", self.problems(config_root=str(self.root) + "-sibling"))
        self.assertEqual(self.problems(config_root=str(self.root / "dhcp" / "nested")), [])

    def test_create_records_and_audits_and_refuses_duplicates(self):
        self.network()
        self.assertTrue(models.AuditEvent.objects.filter(object_id="ztp-test", event_type=models.AuditEventType.DHCP_POLICY_APPLIED).exists())
        _row, problems = policy.create_network(actor=L.APPROVER, trusted_relays=[{"relay_address": Z.RELAY, "upstream_device": "S1"}],
                                               config_root=str(self.root / "dhcp"), **Z.NET)
        self.assertIn("NAME_COLLISION", [p["code"] for p in problems])

    def test_network_cannot_be_vlan_200_or_deleted_at_the_database(self):
        network = self.network()
        with self.assertRaises(Exception):
            network.delete()


class ApplyTests(Z.ZtpTestMixin, TestCase):
    def test_validate_apply_read_back_and_rollback(self):
        session = self.open_session()
        network = session.network
        runner = SupervisorRunner(self.root / "dhcp")
        row, problems = policy.validate_policy(network, actor=L.OPERATOR, runner=runner)
        self.assertEqual((row.state, problems, row.sessions), ("VALIDATED", [], [session.session_id]))
        self.assertIn(str(self.root / "dhcp" / "dhcpd.conf.candidate"), runner.calls[0])
        self.assertFalse((self.root / "dhcp" / "dhcpd.conf").exists())          # validation applies nothing

        row, problems = policy.apply_policy(network, actor="erin", runner=runner)
        self.assertEqual((row.state, problems), ("APPLIED", []))
        self.assertTrue(row.read_back["service"]["running"])
        live = (self.root / "dhcp" / "dhcpd.conf").read_text()
        self.assertEqual(row.config_sha256, dhcp_base.sha256_text(live))
        self.assertIn(f'class "nmas-{session.session_id}"', live)
        self.assertTrue(policy.policy_current(network))
        self.assertTrue(session.device.lifecycle_events.filter(action="ZTP_DHCP_POLICY").exists())

        policy.apply_policy(network, actor="erin", runner=runner)                # a second apply keeps the previous as recovery
        row, problems = policy.rollback_policy(network, actor="erin", runner=runner)
        self.assertEqual((row.state, problems), ("ROLLED_BACK", []))

    def test_invalid_candidate_is_never_applied(self):
        session = self.open_session()
        row, problems = policy.apply_policy(session.network, actor="erin", runner=SupervisorRunner(self.root / "dhcp", rc=1))
        self.assertEqual(row.state, "FAILED")
        self.assertEqual([p["code"] for p in problems], ["DHCP_PROVIDER_ERROR"])
        self.assertFalse((self.root / "dhcp" / "dhcpd.conf").exists())

    def test_service_not_running_after_apply_is_a_failure(self):
        session = self.open_session()
        provider = IscDhcpProvider(str(self.root / "dhcp"), validate_command=Z.VALIDATE, status_command=Z.STATUS,
                                   runner=SupervisorRunner(self.root / "dhcp", status_rc=1))
        provider.settle_seconds = 0
        result = provider.apply(policy.build_policy(session.network))
        self.assertEqual((result.ok, result.state), (False, "FAILED"))
        self.assertFalse(result.read_back["service"]["running"])

    def test_failed_read_back_restores_the_previous_configuration(self):
        """Review regression: a read-back failure after the write must not leave the unverified candidate live."""
        session = self.open_session()
        good, _ = policy.apply_policy(session.network, actor="erin", runner=SupervisorRunner(self.root / "dhcp"))
        live = self.root / "dhcp" / "dhcpd.conf"
        before = live.read_text()
        workflow.cancel_session(session, actor=L.APPROVER, reason="change the policy")   # the next render differs
        provider = IscDhcpProvider(str(self.root / "dhcp"), validate_command=Z.VALIDATE, status_command=Z.STATUS,
                                   runner=SupervisorRunner(self.root / "dhcp", status_rc=1))
        provider.settle_seconds = 0
        result = provider.apply(policy.build_policy(session.network))
        self.assertEqual((good.state, result.ok, result.state), ("APPLIED", False, "FAILED"))
        self.assertNotEqual(result.config_sha256, dhcp_base.sha256_text(before))
        self.assertEqual(live.read_text(), before)
        self.assertTrue(result.read_back["restored_previous"])
        self.assertTrue((self.root / "dhcp" / "restart").exists())                  # the service is asked to reload the restored file

    def test_failed_first_apply_leaves_no_unverified_configuration(self):
        session = self.open_session()
        provider = IscDhcpProvider(str(self.root / "dhcp"), validate_command=Z.VALIDATE, status_command=Z.STATUS,
                                   runner=SupervisorRunner(self.root / "dhcp", status_rc=1))
        provider.settle_seconds = 0
        result = provider.apply(policy.build_policy(session.network))
        self.assertEqual(result.state, "FAILED")
        self.assertFalse((self.root / "dhcp" / "dhcpd.conf").exists())

    def test_apply_without_a_status_command_is_never_reported_applied(self):
        session = self.open_session()
        provider = IscDhcpProvider(str(self.root / "dhcp"), validate_command=Z.VALIDATE, runner=SupervisorRunner(self.root / "dhcp"))
        result = provider.apply(policy.build_policy(session.network))
        self.assertEqual((result.ok, result.state), (False, "FAILED"))
        self.assertIsNone(result.read_back["service"]["running"])
        self.assertFalse((self.root / "dhcp" / "dhcpd.conf").exists())

    def test_no_validator_configured_means_nothing_is_applied(self):
        session = self.open_session()
        with self.settings(NMAS_ZTP_DHCP_COMMANDS={}):
            _row, problems = policy.apply_policy(session.network, actor="erin")
        self.assertEqual([p["code"] for p in problems], ["DHCP_PROVIDER_ERROR"])
        self.assertFalse((self.root / "dhcp" / "dhcpd.conf").exists())

    def test_kea_network_cannot_be_applied(self):
        L.adopt()
        network = self.network(provider="KEA")
        _row, problems = policy.apply_policy(network, actor="erin", runner=SupervisorRunner(self.root / "dhcp"))
        self.assertEqual([p["code"] for p in problems], ["DHCP_PROVIDER_UNSUPPORTED"])

    def test_rollback_without_previous_is_refused(self):
        L.adopt()
        _row, problems = policy.rollback_policy(self.network(), actor="erin", runner=SupervisorRunner(self.root / "dhcp"))
        self.assertEqual([p["code"] for p in problems], ["DHCP_PROVIDER_ERROR"])

    def test_closed_session_leaves_the_policy(self):
        session = self.open_session()
        workflow.cancel_session(session, actor=L.APPROVER, reason="test")
        self.assertEqual(policy.build_policy(session.network).reservations, ())
