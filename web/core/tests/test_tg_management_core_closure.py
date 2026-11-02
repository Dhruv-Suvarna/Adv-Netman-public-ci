"""Lab 7 closure -- V2 Phase 4 management multihoming, each new public function called directly.

The behavioural suites (``test_management_paths``, ``test_management_views``) drive these functions through the selector,
the probe and the pages; this module calls every one of them itself so each is proven at its own boundary:

* ``eos_facts``: the running-configuration facts management verification reads (VLAN carriage, address holding, the
  management-VLAN ports, hostname / serial extraction);
* ``guard`` / ``nmas_side`` / ``paths`` / ``policy`` / ``resolve``: target refusal, read-only host observation, the SPOF
  report, ordering, registry reads and the bounded policy;
* ``probes``: the paramiko transport over a REAL key-only SSH server on 127.0.0.1 (the loopback allowance exists for this
  test server only), the L2 configuration check, the credential resolution and the report accessors;
* ``selector``: health accounting, the pure decision, deactivation, recovery and the status document;
* ``ssh.PinnedCli``: pinned-host-key, key-only exec and interactive configuration against the same loopback server;
* the new models' guards (append-only evidence, immutable history, selector-only fields).

NEGATIVE cases: forbidden / malformed addresses, invalid interface names, unknown switches, unverified attachments,
mismatched host keys, failed authentication, unreachable ports, CLI rejections, unusable paths, stray in-memory paths and
every model guard.  No device and no production network is contacted; the test database is disposable.
"""

from __future__ import annotations

import io
import socket
import tempfile
from pathlib import Path
from unittest import mock

import paramiko
from django.db import transaction
from django.test import SimpleTestCase, TestCase, override_settings
from django.utils import timezone

from core import models
from core.services.management import eos_facts, guard, nmas_side, paths, policy, probes, resolve, selector, ssh
from core.services.ztp import workflow
from core.tests.helpers import management as M

T = models.ManagementPathType
H = models.ManagementPathHealth

VRF_CONFIG = M.eos_config(ports={"Ethernet3": "access200", "Ethernet4": "vrf:MGMT:10.30.0.1/30"}, vrfs=("MGMT",))


def keypair():
    private, public, fp = workflow.generate_enrollment_key(("ssh-ed25519",), "nmas@test")
    return paramiko.Ed25519Key.from_private_key(io.StringIO(private)), public, fp


def passing_report(path_id="MPATH-000001"):
    report = probes.ProbeReport(path_id=path_id)
    for layer in range(1, 7):
        report.set(layer, True)
    return report


def free_port() -> int:
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


# --- eos_facts ------------------------------------------------------------------------------------------------------------------
class EosFactsTests(SimpleTestCase):
    def setUp(self):
        self.facts = eos_facts.parse(M.eos_config(ports={"Ethernet3": "access200", "Ethernet5": "trunk200", "Ethernet6": "trunk101",
                                                         "Ethernet7": "routed:10.1.0.1/31", "Ethernet8": "shutdown"}, stp="mstp"))

    def test_parse_returns_interfaces_vrfs_and_services(self):
        facts = eos_facts.parse(VRF_CONFIG + "username nmas-svc privilege 15 role network-admin ssh-key ssh-ed25519 AAAA\n")
        self.assertEqual(facts.hostname, "R1")
        self.assertEqual(facts.interfaces["Ethernet4"].vrf, "MGMT")
        self.assertIn("MGMT", facts.vrfs)
        self.assertIn("MGMT", facts.ip_routing)
        self.assertTrue(facts.services["ssh"]["MGMT"])
        self.assertEqual(facts.usernames["nmas-svc"], {"has_ssh_key": True})

    def test_parse_of_empty_or_unknown_text_yields_no_facts(self):
        for text in ("", None, "% Invalid input\nfoo bar baz\n"):
            facts = eos_facts.parse(text)
            self.assertEqual((facts.hostname, facts.interfaces, facts.vrfs, facts.routes), ("", {}, {}, []))

    def test_carries_vlan_access_untagged_and_trunk_tagged(self):
        self.assertEqual(self.facts.interfaces["Ethernet3"].carries_vlan(200), (True, False))
        self.assertEqual(self.facts.interfaces["Ethernet5"].carries_vlan(200), (True, True))

    def test_carries_vlan_not_on_other_trunk_or_routed_port(self):
        self.assertEqual(self.facts.interfaces["Ethernet6"].carries_vlan(200), (False, True))
        self.assertEqual(self.facts.interfaces["Ethernet7"].carries_vlan(200), (False, False))

    def test_holds_the_configured_address(self):
        self.assertTrue(self.facts.interfaces["Ethernet7"].holds("10.1.0.1"))

    def test_holds_no_other_address(self):
        self.assertFalse(self.facts.interfaces["Ethernet7"].holds("10.1.0.0"))
        self.assertFalse(self.facts.interfaces["Ethernet3"].holds("10.1.0.1"))

    def test_interface_holding_returns_the_svi(self):
        self.assertEqual(self.facts.interface_holding("192.168.200.1").name, "Vlan200")

    def test_interface_holding_unknown_address_is_none(self):
        self.assertIsNone(self.facts.interface_holding("192.0.2.77"))

    def test_management_vlan_ports_returns_access_and_trunk_carriers(self):
        self.assertEqual(self.facts.management_vlan_ports(200), ["Ethernet3", "Ethernet5"])

    def test_management_vlan_ports_none_for_an_unused_vlan(self):
        self.assertEqual(self.facts.management_vlan_ports(3999), [])

    def test_hostname_from_show_returns_the_hostname(self):
        self.assertEqual(eos_facts.hostname_from_show("Hostname: R1\nFQDN:     R1\n"), "R1")

    def test_hostname_from_show_of_empty_output_is_blank_not_guessed(self):
        self.assertEqual(eos_facts.hostname_from_show(""), "")
        self.assertEqual(eos_facts.hostname_from_show("FQDN: R1\n"), "")

    def test_serial_from_show_version_returns_the_serial(self):
        self.assertEqual(eos_facts.serial_from_show_version("Arista cEOSLab\nSerial number: SN-R1\n"), "SN-R1")

    def test_serial_from_show_version_without_serial_line_is_blank(self):
        self.assertEqual(eos_facts.serial_from_show_version("Arista cEOSLab\n"), "")


# --- guard / policy / resolve (pure) --------------------------------------------------------------------------------------------
class GuardPolicyTests(SimpleTestCase):
    def test_address_problems_accepts_a_management_address_inside_its_network(self):
        self.assertEqual(guard.address_problems("192.168.200.1", network="192.168.200.0/24", layer2=True), [])
        self.assertEqual(guard.address_problems("10.30.0.1"), [])

    def test_address_problems_refuses_forbidden_and_outside_addresses(self):
        for address, network, code in (("127.0.0.1", "", "MGMT_ENDPOINT_FORBIDDEN"), ("169.254.1.1", "", "MGMT_ENDPOINT_FORBIDDEN"),
                                       ("224.0.0.5", "", "MGMT_ENDPOINT_FORBIDDEN"), ("0.0.0.0", "", "MGMT_ENDPOINT_FORBIDDEN"),
                                       ("172.20.20.5", "", "MGMT_ENDPOINT_FORBIDDEN"), ("not-an-ip", "", "MGMT_ENDPOINT_FORBIDDEN"),
                                       ("10.9.9.9", "192.168.200.0/24", "MGMT_ENDPOINT_OUTSIDE_NETWORK"),
                                       ("192.168.200.255", "192.168.200.0/24", "MGMT_ENDPOINT_FORBIDDEN")):
            with self.subTest(address):
                self.assertEqual([b["code"] for b in guard.address_problems(address, network=network, layer2=bool(network))], [code])

    def test_policy_as_dict_returns_every_bounded_value(self):
        self.assertEqual(policy.effective().as_dict(), {"failure_threshold": 3, "restore_threshold": 3, "hold_down_seconds": 120,
                                                        "probe_timeout_seconds": 5, "min_probe_interval_seconds": 5})

    def test_policy_bounds_returns_min_max_and_default(self):
        bounds = policy.bounds()
        self.assertEqual(bounds["hold_down_seconds"], {"min": 30, "max": 3600, "default": 120})
        self.assertEqual(bounds["failure_threshold"]["min"], 2)

    def test_endpoint_as_dict_returns_codes_not_blocker_objects(self):
        endpoint = resolve.Endpoint(resolve.PATH, address="10.30.0.1", path_id="MPATH-000002", path_type=T.ROUTED_VRF, preference_class=3, vrf="MGMT")
        self.assertEqual(endpoint.as_dict()["class"], 3)
        self.assertEqual(resolve.Endpoint(resolve.BLOCKED, blockers=({"code": "MGMT_NO_USABLE_PATH"},)).as_dict()["codes"], ["MGMT_NO_USABLE_PATH"])

    def test_probe_report_failure_code_and_highest_layer_returns_the_first_failure(self):
        report = probes.ProbeReport(path_id="MPATH-000001")
        report.set(1, True)
        report.set(2, True)
        report.set(3, False, "L3_UNREACHABLE")
        self.assertEqual((report.failure_code, report.highest_layer), ("L3_UNREACHABLE", 2))
        self.assertEqual((passing_report().failure_code, passing_report().highest_layer), ("", 6))

    def test_eos_link_connected_returns_true_for_a_connected_port(self):
        self.assertTrue(probes.eos_link_connected(M.eos_outputs(links={"Ethernet3": "connected"}), "Ethernet3"))

    def test_eos_link_connected_down_or_unknown_port_is_not_true(self):
        self.assertFalse(probes.eos_link_connected(M.eos_outputs(links={"Ethernet3": "notconnect"}), "Ethernet3"))
        self.assertIsNone(probes.eos_link_connected(M.eos_outputs(), "Ethernet9"))
        self.assertIsNone(probes.eos_link_connected({}, "Ethernet3"))

    def test_fingerprint_matches_the_openssh_sha256_form(self):
        key, _public, fp = keypair()
        self.assertEqual(probes.fingerprint(key), fp)

    def test_fingerprint_of_another_key_differs_never_collides(self):
        first, _p, _f = keypair()
        second, _p2, _f2 = keypair()
        self.assertNotEqual(probes.fingerprint(first), probes.fingerprint(second))

    def test_evaluation_as_dict_returns_codes(self):
        doc = selector.Evaluation(device="R1", status="NO_PATH", decision="LOST", blockers=[{"code": "MGMT_NO_USABLE_PATH"}]).as_dict()
        self.assertEqual((doc["decision"], doc["codes"]), ("LOST", ["MGMT_NO_USABLE_PATH"]))


# --- registry / NMAS side / probes / selector (database) -------------------------------------------------------------------------
@override_settings(NMAS_MGMT_MIN_PROBE_INTERVAL_SECONDS=0)
class _Lab(TestCase):
    def setUp(self):
        self.lab = M.lab()
        self.r1 = self.lab["devices"]["R1"]
        self.nmas = self.lab["nmas"]
        patcher = M.fake_credentials()
        patcher.start()
        self.addCleanup(patcher.stop)

    def oob(self, **kwargs):
        return M.path(self.r1, self.nmas, attachment=self.lab["oob"], **kwargs)

    def routed(self):
        return M.path(self.r1, self.nmas, path_type=T.ROUTED_VRF, vrf="MGMT", endpoint="10.30.0.1")

    def healthy(self, path):
        selector._path_write(path, health_state=H.HEALTHY)
        return path


class RegistryClosureTests(_Lab):
    def second_attachment(self, verify=True):
        return M.nmas_attachment(name="nmas-b", interface="nmas-b", upstream="S1", port="Ethernet9", source="10.77.0.10",
                                 network="10.77.0.0/24", domain="rack-b", verify=verify)

    def test_approve_nmas_attachment_by_a_second_person_succeeds(self):
        result = paths.register_nmas_attachment(name="nmas-c", host_interface="nmas-c", upstream_device="S1", source_address="10.78.0.10",
                                                network="10.78.0.0/24", actor=M.OPERATOR)
        approved = paths.approve_nmas_attachment(result.attachment, actor=M.APPROVER)
        self.assertTrue(approved.ok, approved.codes)
        self.assertEqual(approved.attachment.approval_state, models.ManagementApproval.APPROVED)

    def test_record_nmas_observation_up_and_holding_the_source_is_verified(self):
        attachment = self.second_attachment(verify=False)
        result = paths.record_nmas_observation(attachment, {"interface": "nmas-b", "exists": True, "oper_up": True,
                                                            "addresses": ["10.77.0.10/24"], "holds_source": True}, actor="nmas-observer")
        self.assertTrue(result.ok)
        self.assertEqual(result.attachment.verification_state, models.AttachmentVerification.VERIFIED)

    def test_revoke_nmas_attachment_without_live_paths_succeeds(self):
        attachment = self.second_attachment()
        result = paths.revoke_nmas_attachment(attachment, actor=M.APPROVER, reason="rewired")
        self.assertTrue(result.ok, result.codes)
        self.assertEqual(result.attachment.approval_state, models.ManagementApproval.REVOKED)

    def test_revoke_nmas_attachment_used_by_a_live_path_or_without_reason_refused(self):
        self.oob()
        self.assertEqual(paths.revoke_nmas_attachment(self.nmas, actor=M.APPROVER, reason="x").codes, ["MGMT_PATH_ACTIVE"])
        self.assertEqual(paths.revoke_nmas_attachment(self.nmas, actor=M.APPROVER, reason="").codes, ["REASON_REQUIRED"])

    def test_revoke_path_without_reason_or_twice_refused(self):
        path = self.oob()
        self.assertEqual(paths.revoke_path(path, actor=M.APPROVER, reason="").codes, ["REASON_REQUIRED"])
        self.assertTrue(paths.revoke_path(path, actor=M.APPROVER, reason="rewire").ok)
        path.refresh_from_db()
        self.assertEqual(paths.revoke_path(path, actor=M.APPROVER, reason="again").codes, ["MGMT_PATH_REVOKED"])

    def test_live_and_approved_paths_returns_the_registered_path(self):
        path = self.oob()
        self.assertEqual([p.pk for p in paths.live_paths(self.r1)], [path.pk])
        self.assertEqual([p.pk for p in paths.approved_paths(self.r1)], [path.pk])

    def test_live_paths_empty_for_a_device_without_paths(self):
        self.assertEqual(list(paths.live_paths(self.lab["devices"]["S3"])), [])

    def test_approved_paths_excludes_a_pending_path_empty(self):
        self.oob(approve=False)
        self.assertEqual(paths.approved_paths(self.r1), [])

    def test_management_vlan_attachments_returns_the_access_attachment(self):
        self.assertEqual([a.pk for a in paths.management_vlan_attachments(self.r1)], [self.lab["oob"].pk])

    def test_management_vlan_attachments_none_for_a_device_without_management_attachment(self):
        self.assertEqual(paths.management_vlan_attachments(self.lab["devices"]["mgmt_swt"]), [])

    def test_priority_key_returns_class_then_switch_identity(self):
        oob, routed = self.oob(), self.routed()
        self.assertEqual(paths.priority_key(oob)[0], 1)
        self.assertLess(paths.priority_key(oob), paths.priority_key(routed))

    def test_priority_key_of_an_unsaved_path_has_zero_identity(self):
        unsaved = models.ManagementPath(path_type=T.ROUTED_VRF, preference_class=3)
        self.assertEqual(paths.priority_key(unsaved), (3, ((), 0), 0))

    def test_switch_identity_unknown_switch_sorts_last(self):
        self.assertEqual(paths.switch_identity("S99")[1], 10 ** 9)

    def test_natural_key_and_ordered_of_empty_input_is_empty(self):
        self.assertEqual(paths.natural_key(None), ())
        self.assertEqual(paths.natural_key(""), ())
        self.assertEqual(paths.ordered([]), [])

    def test_vlan_chain_unknown_switch_is_none(self):
        self.assertIsNone(paths.vlan_chain("S99", "mgmt_swt"))
        self.assertIsNone(paths.vlan_chain("S1", "S99"))         # no verified attachment leads to an unknown goal

    def test_topology_problems_of_a_verified_oob_path_returns_empty(self):
        self.assertEqual(paths.topology_problems(self.oob()), [])

    def test_topology_problems_without_attachment_or_unverified_nmas_blocks(self):
        bare = models.ManagementPath(device=self.r1, path_type=T.DIRECT_OOB, preference_class=1, nmas_attachment=self.nmas)
        self.assertEqual([b["code"] for b in paths.topology_problems(bare)], ["L1_TOPOLOGY_UNVERIFIED"])
        unverified = M.nmas_attachment(name="nmas-unverified", interface="nmas-unverified", upstream="R1",
                                       source="10.30.0.2", network="10.30.0.0/30", domain="unverified", verify=False)
        routed = models.ManagementPath(device=self.r1, path_type=T.ROUTED_VRF, preference_class=3, nmas_attachment=unverified,
                                       endpoint_address="10.30.0.1", vrf="MGMT")
        self.assertEqual([b["code"] for b in paths.topology_problems(routed)], ["L1_NMAS_ATTACHMENT_DOWN"])

    def test_authorized_target_returns_the_stored_path(self):
        path = self.oob()
        stored, refusals = guard.authorized_target(path)
        self.assertEqual((stored.pk, refusals), (path.pk, []))


class NmasSideClosureTests(_Lab):
    def sysfs(self, interface="nmas-b", operstate="up"):
        root = Path(tempfile.mkdtemp(prefix="nmas-sysnet-"))
        self.addCleanup(lambda: __import__("shutil").rmtree(root, True))
        (root / interface).mkdir()
        (root / interface / "operstate").write_text(operstate + "\n", encoding="utf-8")
        return root

    def test_observe_interface_reads_operstate_and_addresses_only(self):
        facts = nmas_side.observe_interface("nmas-b", "10.77.0.10", sys_net=self.sysfs(), read_addresses=lambda name: ["10.77.0.10/24"])
        self.assertEqual((facts["exists"], facts["oper_up"], facts["holds_source"]), (True, True, True))
        self.assertEqual(facts["source"], "sysfs+iproute2 (read-only)")

    def test_observe_interface_invalid_name_or_missing_interface_is_not_up(self):
        facts = nmas_side.observe_interface("bad name;rm", "10.77.0.10")
        self.assertEqual((facts["exists"], facts["source"]), (False, "invalid-name"))
        missing = nmas_side.observe_interface("nmas-zz", "10.77.0.10", sys_net=self.sysfs(), read_addresses=lambda name: ["x"])
        self.assertEqual((missing["exists"], missing["oper_up"], missing["addresses"]), (False, False, []))
        down = nmas_side.observe_interface("nmas-b", "10.77.0.11", sys_net=self.sysfs(operstate="down"), read_addresses=lambda n: ["10.77.0.10/24"])
        self.assertEqual((down["oper_up"], down["holds_source"]), (False, False))

    def test_observe_and_record_verifies_an_up_interface_holding_the_source(self):
        attachment = M.nmas_attachment(name="nmas-b", interface="nmas-b", upstream="S1", source="10.77.0.10", network="10.77.0.0/24",
                                       domain="rack-b", verify=False)
        result = nmas_side.observe_and_record(attachment, actor="nmas-observer", sys_net=self.sysfs(), read_addresses=lambda n: ["10.77.0.10/24"])
        self.assertTrue(result.ok)
        self.assertEqual(result.attachment.verification_state, models.AttachmentVerification.VERIFIED)

    def test_observe_and_record_of_a_revoked_attachment_refused(self):
        attachment = M.nmas_attachment(name="nmas-b", interface="nmas-b", upstream="S1", source="10.77.0.10", network="10.77.0.0/24")
        paths.revoke_nmas_attachment(attachment, actor=M.APPROVER, reason="gone")
        attachment.refresh_from_db()
        result = nmas_side.observe_and_record(attachment, actor="nmas-observer", sys_net=self.sysfs(), read_addresses=lambda n: [])
        self.assertEqual(result.codes, ["MGMT_PATH_REVOKED"])

    def test_path_dependencies_of_an_oob_path_returns_switch_link_and_attachment(self):
        deps = nmas_side.path_dependencies(self.oob())
        self.assertTrue({"switch:mgmt_swt", "link:R1:Ethernet3", f"nmas-attachment:{self.nmas.attachment_id}"} <= deps)

    def test_path_dependencies_of_a_routed_path_has_no_link_or_adjacent_switch(self):
        deps = nmas_side.path_dependencies(self.routed())
        self.assertFalse([d for d in deps if d.startswith("link:")])
        self.assertEqual({d for d in deps if d.startswith("switch:")}, set())

    def test_path_dependencies_of_a_direct_attachment_never_name_the_device_itself_a_switch(self):
        direct = M.nmas_attachment(name="nmas-d", interface="nmas-d", upstream="R1", source="10.78.0.2", network="10.78.0.0/30", domain="direct")
        deps = nmas_side.path_dependencies(M.path(self.r1, direct, path_type=T.ROUTED_VRF, vrf="MGMT", endpoint="10.78.0.1"))
        self.assertEqual({d for d in deps if d.startswith("switch:")}, set())
        self.assertIn(f"nmas-attachment:{direct.attachment_id}", deps)

    def test_spof_report_two_verified_attachments_in_separate_domains_is_tolerant(self):
        M.nmas_attachment(name="nmas-b", interface="nmas-b", upstream="S1", source="10.77.0.10", network="10.77.0.0/24", domain="rack-b")
        report = nmas_side.spof_report()
        self.assertTrue(report["management_switch_failure_tolerant"])
        self.assertEqual(report["blockers"], [])
        self.assertEqual(report["failure_domains"], ["mgmt_swt", "rack-b"])

    def test_spof_report_requires_distinct_upstream_switches(self):
        M.nmas_attachment(name="nmas-b", interface="nmas-b", upstream="mgmt_swt", source="10.77.0.10",
                          network="10.77.0.0/24", domain="rack-b")
        report = nmas_side.spof_report()
        self.assertFalse(report["management_switch_failure_tolerant"])
        self.assertEqual(report["blockers"][0]["code"], "NMAS_SHARED_FAILURE_DOMAIN")

    def test_spof_report_requires_a_pair_with_disjoint_dependencies(self):
        first = self.oob()
        second = self.routed()
        third = M.path(self.r1, self.nmas, path_type=T.ROUTED_VRF, vrf="MGMT2", endpoint="10.79.0.1")
        deps = {first.pk: {"a", "b"}, second.pk: {"b", "c"}, third.pk: {"a", "c"}}
        with mock.patch.object(nmas_side.selector, "usable", return_value=True), \
                mock.patch.object(nmas_side, "path_dependencies", side_effect=lambda p: deps[p.pk]):
            report = nmas_side.spof_report()
        self.assertEqual(report["devices"]["R1"]["shared_dependencies"], [])
        self.assertFalse(report["devices"]["R1"]["path_redundant"])


class ProbeClosureTests(_Lab):
    def test_eos_config_problems_routed_vrf_path_matches_returns_empty(self):
        path = models.ManagementPath(path_type=T.ROUTED_VRF, endpoint_address="10.30.0.1", vrf="MGMT")
        self.assertEqual(probes.eos_config_problems(path, eos_facts.parse(VRF_CONFIG)), [])

    def test_eos_config_problems_unconfigured_endpoint_or_missing_vrf_blocks(self):
        facts = eos_facts.parse(VRF_CONFIG)
        missing = models.ManagementPath(path_type=T.ROUTED_VRF, endpoint_address="10.31.0.1", vrf="MGMT")
        self.assertEqual([b["code"] for b in probes.eos_config_problems(missing, facts)], ["L2_CONFIG_MISMATCH"])
        wrong_vrf = models.ManagementPath(path_type=T.ROUTED_VRF, endpoint_address="10.30.0.1", vrf="OTHER")
        self.assertTrue(probes.eos_config_problems(wrong_vrf, facts))
        layer2_in_vrf = models.ManagementPath(path_type=T.DIRECT_OOB, endpoint_address="10.30.0.1")
        self.assertEqual([b["code"] for b in probes.eos_config_problems(layer2_in_vrf, facts)], ["L2_CONFIG_MISMATCH"])


class AuthMaterialClosureTests(TestCase):
    """``probes.auth_material`` unpatched (the lab fixture above replaces it)."""

    def setUp(self):
        self.r1 = M.lab()["devices"]["R1"]

    def test_auth_material_device_credential_returns_the_service_key(self):
        key, public, fp = keypair()
        credential = models.DeviceCredential.objects.create(
            device_name="R1", platform="arista_ceos", username="nmas-svc", account_kind=models.AccountKind.SERVICE,
            auth_method=models.DeviceAuthMethod.PUBLICKEY, ssh_key_ref="runtime://device-credentials/nmas-svc-key",
            ssh_public_key=public, ssh_public_key_fingerprint=fp)
        path = models.ManagementPath(device=self.r1, credential_source=models.ManagementCredentialSource.DEVICE_CREDENTIAL,
                                     device_credential=credential)
        with mock.patch("modules.device_credentials.load_ssh_private_key", return_value=key):
            self.assertEqual(probes.auth_material(path), ("nmas-svc", [{"pkey": key}]))

    def test_auth_material_missing_enrollment_session_unavailable(self):
        path = models.ManagementPath(device=self.r1, credential_source=models.ManagementCredentialSource.ZTP_ENROLLMENT,
                                     credential_reference="ZTP-000999")
        with self.assertRaises(probes.CredentialUnavailable):
            probes.auth_material(path)


@override_settings(NMAS_MGMT_ALLOW_LOOPBACK_TARGETS=True)
class LoopbackSshTests(SimpleTestCase):
    """The real paramiko transport and PinnedCli against a key-only SSH server on 127.0.0.1."""

    def setUp(self):
        self.key, public, _fp = keypair()
        self.server = M.KeyOnlySshServer(username="nmas-svc", authorized_public=public, reject={"bogus command"},
                                         stall={"commit timer 00:10:00"},
                                         outputs={command: f"output of {command}\n" for command in probes.EOS_COMMANDS})
        self.addCleanup(self.server.close)

    def run_transport(self, **overrides):
        fields = dict(source="127.0.0.1", interface="lo", address="127.0.0.1", port=self.server.port, timeout=5,
                      expected_host_key=self.server.fingerprint,
                      username="nmas-svc", methods=[{"pkey": self.key}], commands=probes.EOS_COMMANDS,
                      report=probes.ProbeReport(path_id="MPATH-000001"))
        fields.update(overrides)
        return probes.ParamikoTransport().run(**fields), fields["report"]

    def test_paramiko_transport_run_returns_outputs_with_layers_3_to_5_passed(self):
        outputs, report = self.run_transport()
        self.assertEqual(outputs["show hostname | json"], "output of show hostname | json\n")
        self.assertEqual([report.layers[n]["ok"] for n in (3, 4, 5)], [True, True, True])
        self.assertEqual(report.presented_host_key, self.server.fingerprint)

    def test_paramiko_transport_run_mismatched_key_failed_auth_and_unreachable_port(self):
        with self.assertRaises(probes.ProbeFailure) as caught:
            self.run_transport(expected_host_key=M.OTHER_HOST_KEY)
        self.assertEqual((caught.exception.layer, caught.exception.code), (5, "L5_HOST_KEY_MISMATCH"))
        self.assertEqual(self.server.auth_attempts, [])          # no credential offered to the impostor
        with self.assertRaises(probes.ProbeFailure) as caught:
            self.run_transport(username="intruder")
        self.assertEqual(caught.exception.code, "L5_AUTH_FAILED")
        with self.assertRaises(probes.ProbeFailure) as caught:
            self.run_transport(port=free_port())
        self.assertEqual(caught.exception.code, "L3_UNREACHABLE")

    def cli(self, **overrides):
        fields = dict(address="127.0.0.1", port=self.server.port, username="nmas-svc", pkey=self.key, expected_host_key=self.server.fingerprint)
        fields.update(overrides)
        return ssh.PinnedCli(**fields)

    def test_pinned_cli_init_show_configure_and_close_succeeds(self):
        cli = self.cli()
        self.assertEqual(cli.host_key, self.server.fingerprint)
        self.assertEqual(cli.show("show version | json"), "output of show version | json\n")
        text = cli.configure(["configure session nmas-test", "commit"], settle=0.2)
        self.assertIn("commit", text)
        self.assertEqual(self.server.shell_lines, ["terminal length 0", "configure session nmas-test", "commit"])
        cli.close()

    def test_pinned_cli_init_mismatched_key_unreachable_or_failed_auth_refused(self):
        for overrides, code in (({"expected_host_key": M.OTHER_HOST_KEY}, "HOST_KEY_MISMATCH"), ({"expected_host_key": ""}, "HOST_KEY_MISMATCH"),
                                ({"port": free_port()}, "UNREACHABLE"), ({"username": "intruder"}, "AUTH_FAILED")):
            with self.subTest(code=code, overrides=list(overrides)), self.assertRaises(ssh.CliError) as caught:
                self.cli(**overrides)
            self.assertEqual(caught.exception.code, code)

    def test_pinned_cli_configure_rejected_line_fails(self):
        cli = self.cli()
        self.addCleanup(cli.close)
        with self.assertRaises(ssh.CliError) as caught:
            cli.configure(["bogus command"], settle=0.2)
        self.assertEqual(caught.exception.code, "COMMAND_REJECTED")

    def test_pinned_cli_configure_without_a_returning_prompt_fails_and_sends_nothing_more(self):
        # live finding: silence is not completion -- a slow commit whose channel was closed early left the session pending
        cli = self.cli()
        self.addCleanup(cli.close)
        with self.assertRaises(ssh.CliError) as caught:
            cli.configure(["configure session nmas-test", "commit timer 00:10:00", "show configuration sessions"], settle=0.2, timeout=1.5)
        self.assertEqual((caught.exception.code, caught.exception.detail), ("TRANSPORT_ERROR", "no CLI prompt before the timeout"))
        self.assertEqual(self.server.shell_lines, ["terminal length 0", "configure session nmas-test", "commit timer 00:10:00"])

    def test_pinned_cli_show_after_close_is_a_transport_error(self):
        cli = self.cli()
        cli.close()
        with self.assertRaises(ssh.CliError) as caught:
            cli.show("show version")
        self.assertEqual(caught.exception.code, "TRANSPORT_ERROR")

    def test_connect_returns_a_pinned_session(self):
        cli = ssh.connect(address="127.0.0.1", port=self.server.port, username="nmas-svc", pkey=self.key,
                          expected_host_key=self.server.fingerprint)
        self.addCleanup(cli.close)
        self.assertIsInstance(cli, ssh.PinnedCli)

    def test_connect_to_an_impostor_refused(self):
        with self.assertRaises(ssh.CliError) as caught:
            ssh.connect(address="127.0.0.1", port=self.server.port, username="nmas-svc", pkey=self.key, expected_host_key=M.OTHER_HOST_KEY)
        self.assertEqual(caught.exception.code, "HOST_KEY_MISMATCH")


class SelectorClosureTests(_Lab):
    def test_apply_probe_passing_report_returns_healthy(self):
        path = self.oob()
        self.assertEqual(selector.apply_probe(path, passing_report(path.path_id)), H.HEALTHY)
        path.refresh_from_db()
        self.assertEqual((path.consecutive_successes, path.last_failure_code), (1, ""))

    def test_apply_probe_host_key_mismatch_fails_immediately(self):
        path = self.healthy(self.oob())
        report = probes.ProbeReport(path_id=path.path_id)
        report.set(5, False, "L5_HOST_KEY_MISMATCH")
        self.assertEqual(selector.apply_probe(path, report), H.FAILED)
        unreachable = probes.ProbeReport(path_id=path.path_id)
        unreachable.set(3, False, "L3_UNREACHABLE")
        routed = self.healthy(self.routed())
        self.assertEqual(selector.apply_probe(routed, unreachable), H.DEGRADED)   # below the failure threshold

    def test_usable_and_still_serving_accept_a_healthy_approved_path(self):
        path = self.healthy(self.oob())
        self.assertTrue(selector.usable(path))
        self.assertTrue(selector.still_serving(path))

    def test_usable_and_still_serving_refuse_failed_or_pending_paths(self):
        path = self.oob(approve=False)
        self.assertFalse(selector.usable(path))
        self.assertFalse(selector.still_serving(path))
        failed = self.routed()
        selector._path_write(failed, health_state=H.FAILED)
        self.assertFalse(selector.usable(failed))
        self.assertFalse(selector.still_serving(failed))
        degraded = self.healthy(M.path(self.r1, self.nmas, path_type=T.ROUTED_VRF, vrf="MGMT2", endpoint="10.31.0.1"))
        selector._path_write(degraded, health_state=H.DEGRADED)
        self.assertFalse(selector.usable(degraded))       # degraded keeps serving but is never chosen

    def test_decide_activates_the_preferred_usable_path(self):
        oob, routed = self.healthy(self.oob()), self.healthy(self.routed())
        state = selector.state_for(self.r1)
        self.assertEqual(selector.decide(self.r1, state, [routed, oob]), ("ACTIVATE", oob, "PATH_VERIFIED"))

    def test_decide_without_usable_path_or_while_busy_never_switches(self):
        failed = self.routed()
        state = selector.state_for(self.r1)
        self.assertEqual(selector.decide(self.r1, state, [failed]), ("LOST", None, "MGMT_NO_USABLE_PATH"))
        usable_path = self.healthy(self.oob())
        self.assertEqual(selector.decide(self.r1, state, [usable_path], busy={"kind": "EXECUTION"})[0], "DEFERRED")

    def test_deactivate_the_active_path_clears_the_selection(self):
        path = self.healthy(self.oob())
        selector.evaluate(self.r1, transport=M.FakeTransport(outputs=M.eos_outputs()))
        path.refresh_from_db()
        self.assertTrue(path.is_active)
        with transaction.atomic():
            selector.deactivate(path, actor=M.APPROVER, reason_code="MGMT_PATH_REVOKED")
        state = selector.state_for(self.r1)
        self.assertEqual((state.status, state.active_path_id), (models.ManagementStatus.NO_PATH, None))

    def test_deactivate_of_a_path_not_active_keeps_the_state(self):
        active = self.healthy(self.oob())
        selector.evaluate(self.r1, transport=M.FakeTransport(outputs=M.eos_outputs()))
        standby = self.routed()
        with transaction.atomic():
            selector.deactivate(standby, actor=M.APPROVER, reason_code="MGMT_PATH_REVOKED")
        self.assertEqual(selector.state_for(self.r1).active_path_id, active.pk)
        self.assertTrue(models.ManagementPathTransition.objects.filter(kind="DEACTIVATE", from_path=standby).exists())

    def test_device_status_returns_paths_in_priority_order(self):
        routed, oob = self.routed(), self.oob()
        doc = selector.device_status(self.r1)
        self.assertEqual([p["id"] for p in doc["paths"]], [oob.path_id, routed.path_id])
        self.assertEqual((doc["device"], doc["platform"]), ("R1", "arista_ceos"))

    def test_device_status_without_state_or_paths_is_legacy(self):
        doc = selector.device_status(self.lab["devices"]["S3"])
        self.assertEqual((doc["status"], doc["active_path"], doc["paths"], doc["reconciliation_required"]), ("LEGACY", "", [], False))

    def test_in_flight_without_lock_or_open_transition_is_empty(self):
        self.assertEqual(selector.in_flight(self.r1), {})

    def test_recover_without_any_state_repairs_nothing_empty(self):
        self.assertEqual(selector.recover(), [])

    def test_state_for_without_create_is_none_for_an_unevaluated_device(self):
        self.assertIsNone(selector.state_for(self.r1, create=False))
        self.assertFalse(models.DeviceManagementState.objects.filter(device=self.r1).exists())


class ModelGuardClosureTests(_Lab):
    def probe_row(self, path, **overrides):
        fields = dict(path=path, device=self.r1, purpose=models.ProbePurpose.VERIFY, passed=False, highest_layer=2,
                      failure_code="L3_UNREACHABLE", layers=[], actor="tester")
        fields.update(overrides)
        return models.ManagementPathProbe(**fields)

    def test_nmas_attachment_save_refuses_a_failure_domain_update(self):
        self.nmas.failure_domain = "rack-a"
        with self.assertRaises(ValueError):
            self.nmas.save()

    def test_nmas_attachment_save_of_immutable_or_malformed_fields_refused(self):
        for field, value in (("source_address", "192.168.200.101"), ("host_interface", "bad name"), ("failure_domain", "has space"),
                             ("approval_state", "MAYBE")):
            fresh = models.NmasManagementAttachment.objects.get(pk=self.nmas.pk)
            setattr(fresh, field, value)
            with self.subTest(field), self.assertRaises(ValueError):
                fresh.save()

    def test_history_and_evidence_rows_raise_on_delete(self):
        path = self.oob()
        probe = self.probe_row(path)
        probe.save()
        transition = models.ManagementPathTransition(device=self.r1, kind="ACTIVATE", to_path=path, reason_code="PATH_VERIFIED",
                                                     actor="tester", actor_kind="AUTOMATION")
        transition.save()
        state = selector.state_for(self.r1)
        for row in (self.nmas, path, probe, transition, state):
            with self.subTest(type(row).__name__), self.assertRaises(ValueError):
                row.delete()
        self.assertTrue(models.ManagementPathProbe.objects.filter(pk=probe.pk).exists())

    def test_management_path_save_accepts_a_reason_update(self):
        path = self.oob()
        path.reason = "documented"
        path.save()
        self.assertEqual(models.ManagementPath.objects.get(pk=path.pk).reason, "documented")

    def test_management_path_probe_save_appends_one_row(self):
        path = self.oob()
        self.probe_row(path).save()
        self.probe_row(path, passed=True, highest_layer=6, failure_code="").save()
        self.assertEqual(models.ManagementPathProbe.objects.filter(path=path).count(), 2)

    def test_management_path_probe_save_of_inconsistent_or_existing_row_refused(self):
        path = self.oob()
        for overrides in ({"passed": True, "highest_layer": 5, "failure_code": ""}, {"failure_code": ""}, {"purpose": "GUESS"},
                          {"highest_layer": 7}):
            with self.subTest(overrides), self.assertRaises(ValueError):
                self.probe_row(path, **overrides).save()
        row = self.probe_row(path)
        row.save()
        row.failure_code = "L4_RETURN_PATH_FAILED"
        with self.assertRaises(ValueError):
            row.save()

    def test_management_path_transition_save_appends_one_row(self):
        path = self.oob()
        models.ManagementPathTransition(device=self.r1, kind="ACTIVATE", to_path=path, reason_code="PATH_VERIFIED", actor="tester",
                                        actor_kind="AUTOMATION").save()
        self.assertEqual(models.ManagementPathTransition.objects.filter(device=self.r1).count(), 1)

    def test_management_path_transition_save_of_unknown_kind_or_actor_refused(self):
        for kind, actor_kind in (("TELEPORT", "AUTOMATION"), ("ACTIVATE", "ROBOT")):
            with self.subTest(kind=kind, actor_kind=actor_kind), self.assertRaises(ValueError):
                models.ManagementPathTransition(device=self.r1, kind=kind, reason_code="X", actor="tester", actor_kind=actor_kind).save()

    def test_device_management_state_save_through_the_selector_flag_succeeds(self):
        row = models.DeviceManagementState(device=self.r1, status=models.ManagementStatus.UNKNOWN)
        row._selector_write = True
        row.save()
        self.assertEqual(models.DeviceManagementState.objects.get(device=self.r1).status, "UNKNOWN")

    def test_device_management_state_save_outside_the_selector_refused(self):
        row = models.DeviceManagementState(device=self.r1, status=models.ManagementStatus.UNKNOWN)
        with self.assertRaises(ValueError):
            row.save()
        row._selector_write = True
        row.status = "BOGUS"
        with self.assertRaises(ValueError):
            row.save()
