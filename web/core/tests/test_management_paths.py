"""V2 Phase 4 -- the management-path registry, layered probes, the selector and the shared resolver.

Everything runs against the test database with a fake transport (no device, no network).  The frozen lab's shape is used:
R1's only eligible path is its direct out-of-band link to mgmt_swt; its VLAN-200-through-S1/S3 alternatives are registered
here only to prove they are refused or found ineligible for the reasons the lab really has (S1 link routed, S3 trunk without
VLAN 200, STP mode none).

NEGATIVE cases: self-approval, foreign / routed / non-management attachments, VLAN other than 200, forbidden endpoints
(loopback, link-local, Containerlab), addresses outside the attachment network, human credentials, missing host keys,
unverified platforms, duplicates, unapproved / tampered probe targets, every probe layer failing, hysteresis below the
threshold, hold-down, in-flight deferral and the fail-closed resolver.
"""

from __future__ import annotations

from datetime import timedelta
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from unittest import mock

from django.test import SimpleTestCase, TestCase, override_settings
from django.utils import timezone

from core import models
from core.services import nsot_live
from core.services.management import guard, paths, policy, probes, resolve, selector, ssh_transport
from core.services.execution.device_mutex import DeviceBusy, DeviceMutex
from core.tests.helpers import management as M

T = models.ManagementPathType
H = models.ManagementPathHealth


@override_settings(NMAS_MGMT_MIN_PROBE_INTERVAL_SECONDS=0)
class _Base(TestCase):
    def setUp(self):
        self.lab = M.lab()
        self.r1 = self.lab["devices"]["R1"]
        self.nmas = self.lab["nmas"]
        patcher = M.fake_credentials()
        patcher.start()
        self.addCleanup(patcher.stop)


class RegistryTests(_Base):
    def test_routed_path_requires_on_link_verified_nmas_neighbor(self):
        missing_neighbor = paths.register_path(
            self.r1, path_type=T.ROUTED_VRF, vrf="MGMT", endpoint_address="10.30.0.1",
            nmas_attachment_id=self.nmas.pk, credential_source="INVENTORY", expected_host_key=M.HOST_KEY, actor=M.OPERATOR)
        self.assertIn("L1_TOPOLOGY_UNVERIFIED", missing_neighbor.codes)
        direct = M.nmas_attachment(name="nmas-vrf", interface="nmas-vrf", upstream="R1", source="10.30.0.2",
                                   network="10.30.0.0/30", domain="direct-vrf")
        off_link = paths.register_path(
            self.r1, path_type=T.ROUTED_VRF, vrf="MGMT", endpoint_address="10.31.0.1",
            nmas_attachment_id=direct.pk, credential_source="INVENTORY", expected_host_key=M.HOST_KEY, actor=M.OPERATOR)
        self.assertIn("MGMT_ENDPOINT_OUTSIDE_NETWORK", off_link.codes)
        forged_hop = paths.register_path(
            self.r1, path_type=T.ROUTED_VRF, vrf="MGMT", endpoint_address="10.30.0.1", via_device="S1",
            nmas_attachment_id=direct.pk, credential_source="INVENTORY", expected_host_key=M.HOST_KEY, actor=M.OPERATOR)
        self.assertIn("MGMT_PATH_ATTACHMENT_INVALID", forged_hop.codes)
        allowed = paths.register_path(
            self.r1, path_type=T.ROUTED_VRF, vrf="MGMT", endpoint_address="10.30.0.1",
            nmas_attachment_id=direct.pk, credential_source="INVENTORY", expected_host_key=M.HOST_KEY, actor=M.OPERATOR)
        self.assertTrue(allowed.ok, allowed.codes)

    def test_register_direct_oob_path_records_pending_class_1(self):
        result = paths.register_path(self.r1, path_type=T.DIRECT_OOB, endpoint_address="192.168.200.1", nmas_attachment_id=self.nmas.pk,
                                     attachment_id=self.lab["oob"].pk, credential_source=models.ManagementCredentialSource.INVENTORY,
                                     expected_host_key=M.HOST_KEY, actor=M.OPERATOR)
        self.assertTrue(result.ok, result.blockers)
        self.assertEqual((result.path.preference_class, result.path.approval_state), (1, "PENDING"))
        self.assertEqual((result.path.via_device, result.path.local_interface, result.path.vlan), ("mgmt_swt", "Ethernet3", 200))
        self.assertEqual(result.path.credential_reference, "R1")
        self.assertTrue(result.path.path_id.startswith("MPATH-"))

    def test_register_refused_without_attachment_records_refusal(self):
        result = paths.register_path(self.r1, path_type=T.DIRECT_OOB, endpoint_address="192.168.200.1", nmas_attachment_id=self.nmas.pk,
                                     credential_source="INVENTORY", expected_host_key=M.HOST_KEY, actor=M.OPERATOR)
        self.assertFalse(result.ok)
        self.assertIn("MGMT_PATH_ATTACHMENT_REQUIRED", result.codes)
        self.assertEqual(result.event.outcome, "REFUSED")

    def test_register_refuses_forbidden_endpoints(self):
        for address, code in (("127.0.0.1", "MGMT_ENDPOINT_FORBIDDEN"), ("169.254.1.1", "MGMT_ENDPOINT_FORBIDDEN"),
                              ("172.20.20.5", "MGMT_ENDPOINT_FORBIDDEN"), ("10.9.9.9", "MGMT_ENDPOINT_OUTSIDE_NETWORK"),
                              ("192.168.200.0", "MGMT_ENDPOINT_FORBIDDEN"), ("not-an-ip", "MGMT_ENDPOINT_FORBIDDEN")):
            with self.subTest(address=address):
                result = paths.register_path(self.r1, path_type=T.DIRECT_OOB, endpoint_address=address, nmas_attachment_id=self.nmas.pk,
                                             attachment_id=self.lab["oob"].pk, credential_source="INVENTORY",
                                             expected_host_key=M.HOST_KEY, actor=M.OPERATOR)
                self.assertFalse(result.ok)
                self.assertIn(code, result.codes)

    def test_register_refuses_missing_host_key(self):
        result = paths.register_path(self.r1, path_type=T.DIRECT_OOB, endpoint_address="192.168.200.1", nmas_attachment_id=self.nmas.pk,
                                     attachment_id=self.lab["oob"].pk, credential_source="INVENTORY", actor=M.OPERATOR)
        self.assertIn("MGMT_HOST_KEY_REQUIRED", result.codes)

    def test_register_refuses_transport_without_a_verified_consumer(self):
        result = paths.register_path(self.r1, path_type=T.DIRECT_OOB, endpoint_address="192.168.200.1",
                                     nmas_attachment_id=self.nmas.pk, attachment_id=self.lab["oob"].pk,
                                     credential_source="INVENTORY", expected_host_key=M.HOST_KEY,
                                     transport=models.ManagementTransport.EAPI, actor=M.OPERATOR)
        self.assertIn("MGMT_PATH_TYPE_INVALID", result.codes)

    def test_register_refuses_unverified_platform(self):
        from core.services.devices import lifecycle

        r3 = lifecycle.adopt_existing("R3", role="router", actor=M.APPROVER).device
        result = paths.register_path(r3, path_type=T.ROUTED_VRF, vrf="MGMT", endpoint_address="10.1.1.1", nmas_attachment_id=self.nmas.pk,
                                     credential_source="INVENTORY", expected_host_key=M.HOST_KEY, actor=M.OPERATOR)
        self.assertIn("L2_PLATFORM_NOT_IMPLEMENTED", result.codes)

    def test_register_refuses_human_credential(self):
        credential = models.DeviceCredential.objects.create(device_name="R1", platform="ceos", username="olivia",
                                                            account_kind=models.AccountKind.HUMAN,
                                                            auth_method=models.DeviceAuthMethod.PASSWORD_AND_TOTP)
        result = paths.register_path(self.r1, path_type=T.DIRECT_OOB, endpoint_address="192.168.200.1", nmas_attachment_id=self.nmas.pk,
                                     attachment_id=self.lab["oob"].pk, credential_source="DEVICE_CREDENTIAL",
                                     device_credential_id=credential.pk, expected_host_key=M.HOST_KEY, actor=M.OPERATOR)
        self.assertIn("MGMT_CREDENTIAL_HUMAN", result.codes)

    def test_register_vlan_path_with_wrong_vlan_refused(self):
        trunk = M.management_attachment(self.r1, upstream="S3", port="Ethernet3", local="Ethernet1",
                                        connectivity=models.AttachmentConnectivity.TRUNK)
        result = paths.register_path(self.r1, path_type=T.VLAN_ADJACENT_SWITCH, endpoint_address="192.168.200.1", vlan=101,
                                     nmas_attachment_id=self.nmas.pk, attachment_id=trunk.pk, credential_source="INVENTORY",
                                     expected_host_key=M.HOST_KEY, actor=M.OPERATOR)
        self.assertIn("MGMT_VLAN_INVALID", result.codes)

    def test_register_oob_type_on_adjacent_switch_attachment_refused(self):
        trunk = M.management_attachment(self.r1, upstream="S3", port="Ethernet3", local="Ethernet1",
                                        connectivity=models.AttachmentConnectivity.TRUNK)
        result = paths.register_path(self.r1, path_type=T.DIRECT_OOB, endpoint_address="192.168.200.1", nmas_attachment_id=self.nmas.pk,
                                     attachment_id=trunk.pk, credential_source="INVENTORY", expected_host_key=M.HOST_KEY, actor=M.OPERATOR)
        self.assertIn("MGMT_PATH_ATTACHMENT_INVALID", result.codes)

    def test_register_duplicate_refused(self):
        M.path(self.r1, self.nmas, attachment=self.lab["oob"], approve=False)
        result = paths.register_path(self.r1, path_type=T.DIRECT_OOB, endpoint_address="192.168.200.1", nmas_attachment_id=self.nmas.pk,
                                     attachment_id=self.lab["oob"].pk, credential_source="INVENTORY", expected_host_key=M.HOST_KEY,
                                     actor=M.OPERATOR)
        self.assertIn("MGMT_PATH_DUPLICATE", result.codes)

    def test_approve_path_by_second_person(self):
        pending = M.path(self.r1, self.nmas, attachment=self.lab["oob"], approve=False)
        result = paths.approve_path(pending, actor=M.APPROVER)
        self.assertTrue(result.ok)
        self.assertEqual(result.path.approval_state, "APPROVED")

    def test_approve_path_self_approval_refused(self):
        pending = M.path(self.r1, self.nmas, attachment=self.lab["oob"], approve=False)
        result = paths.approve_path(pending, actor=M.OPERATOR)
        self.assertIn("MGMT_PATH_SELF_APPROVAL", result.codes)

    def test_revoke_active_path_requires_acknowledgement(self):
        active = M.path(self.r1, self.nmas, attachment=self.lab["oob"])
        selector.evaluate(self.r1, transport=M.FakeTransport())
        active.refresh_from_db()
        self.assertTrue(active.is_active)
        refused = paths.revoke_path(active, actor=M.APPROVER, reason="decommission link")
        self.assertIn("MGMT_PATH_ACTIVE", refused.codes)
        done = paths.revoke_path(active, actor=M.APPROVER, reason="decommission link", acknowledge_active=True)
        self.assertTrue(done.ok)
        state = selector.state_for(self.r1)
        self.assertEqual((state.status, state.active_path_id), ("NO_PATH", None))

    def test_nmas_attachment_self_approval_refused(self):
        result = paths.register_nmas_attachment(name="second", host_interface="eth9", upstream_device="S1", source_address="10.0.0.2",
                                                network="10.0.0.0/24", actor=M.OPERATOR)
        self.assertTrue(result.ok, result.blockers)
        self.assertIn("MGMT_PATH_SELF_APPROVAL", paths.approve_nmas_attachment(result.attachment, actor=M.OPERATOR).codes)

    def test_nmas_attachment_source_outside_network_refused(self):
        result = paths.register_nmas_attachment(name="bad", host_interface="eth9", upstream_device="S1", source_address="10.0.1.2",
                                                network="10.0.0.0/24", actor=M.OPERATOR)
        self.assertIn("NMAS_ATTACHMENT_INVALID", result.codes)

    def test_natural_switch_order_s1_before_s3_before_s10(self):
        self.assertLess(paths.natural_key("S1"), paths.natural_key("S3"))
        self.assertLess(paths.natural_key("S3"), paths.natural_key("S10"))
        self.assertLess(paths.switch_identity("S1"), paths.switch_identity("S3"))


class ModelGuardTests(_Base):
    def test_path_is_never_created_active(self):
        with self.assertRaises(ValueError):
            models.ManagementPath(device=self.r1, path_type=T.ROUTED_VRF, preference_class=3, vrf="MGMT", endpoint_address="10.0.0.1",
                                  credential_source="INVENTORY", nmas_attachment=self.nmas, created_by="x", is_active=True).save()

    def test_path_class_must_match_type(self):
        with self.assertRaises(ValueError):
            models.ManagementPath(device=self.r1, path_type=T.ROUTED_VRF, preference_class=1, vrf="MGMT", endpoint_address="10.0.0.1",
                                  credential_source="INVENTORY", nmas_attachment=self.nmas, created_by="x").save()

    def test_selector_fields_not_writable_outside_selector(self):
        row = M.path(self.r1, self.nmas, attachment=self.lab["oob"])
        row.health_state = H.HEALTHY
        with self.assertRaises(ValueError):
            row.save()

    def test_path_immutable_fields_and_delete_refused(self):
        row = M.path(self.r1, self.nmas, attachment=self.lab["oob"])
        row.endpoint_address = "192.168.200.9"
        with self.assertRaises(ValueError):
            row.save()
        row.refresh_from_db()
        row.expected_host_key = M.OTHER_HOST_KEY
        with self.assertRaises(ValueError):
            row.save()
        row.refresh_from_db()
        row.policy = {"failure_threshold": 99}
        with self.assertRaises(ValueError):
            row.save()
        row.refresh_from_db()
        row.expected_topology = {"hops": ["fabric"]}
        with self.assertRaises(ValueError):
            row.save()
        row.refresh_from_db()
        with self.assertRaises(ValueError):
            row.delete()

    def test_state_row_not_writable_outside_selector(self):
        with self.assertRaises(ValueError):
            models.DeviceManagementState(device=self.r1).save()

    def test_probe_rows_are_append_only(self):
        row = M.path(self.r1, self.nmas, attachment=self.lab["oob"])
        _report, probe, _ = probes.probe(row, transport=M.FakeTransport())
        with self.assertRaises(ValueError):
            probe.save()
        with self.assertRaises(ValueError):
            models.ManagementPathProbe.objects.all().delete()


class ProbeTests(_Base):
    def test_routed_path_corrupted_to_unverified_neighbor_never_contacts_device(self):
        path = M.path(self.r1, self.nmas, path_type=T.ROUTED_VRF, vrf="MGMT", endpoint="10.30.0.1")
        models.ManagementPath.objects.filter(pk=path.pk).update(nmas_attachment=self.nmas)
        path.refresh_from_db()
        transport = M.FakeTransport()
        _report, row, refusals = probes.probe(path, transport=transport)
        self.assertEqual(([r["code"] for r in refusals], row, transport.calls),
                         (["L1_TOPOLOGY_UNVERIFIED"], None, []))

    def setUp(self):
        super().setUp()
        self.oob = M.path(self.r1, self.nmas, attachment=self.lab["oob"])

    def test_probe_passes_every_layer(self):
        report, row, refusals = probes.probe(self.oob, transport=M.FakeTransport())
        self.assertEqual(refusals, [])
        self.assertTrue(report.passed, report.as_list())
        self.assertEqual((row.highest_layer, row.failure_code), (6, ""))

    def test_probe_binds_nmas_source_address(self):
        transport = M.FakeTransport()
        probes.probe(self.oob, transport=transport)
        self.assertEqual(transport.calls[0]["source"], "192.168.200.100")
        self.assertEqual(transport.calls[0]["interface"], "nmas-mgmt")
        self.assertEqual(transport.calls[0]["address"], "192.168.200.1")


    def test_probe_unapproved_path_never_contacted(self):
        pending = M.path(self.r1, self.nmas, path_type=T.ROUTED_VRF, vrf="MGMT", endpoint="10.20.0.1", approve=False)
        transport = M.FakeTransport()
        _report, row, refusals = probes.probe(pending, transport=transport)
        self.assertEqual(([r["code"] for r in refusals], row, transport.calls), (["PROBE_TARGET_FORBIDDEN"], None, []))

    def test_probe_tampered_in_memory_address_refused(self):
        self.oob.endpoint_address = "192.168.200.77"
        transport = M.FakeTransport()
        _report, _row, refusals = probes.probe(self.oob, transport=transport)
        self.assertEqual(refusals[0]["code"], "PROBE_TARGET_FORBIDDEN")
        self.assertEqual(transport.calls, [])

    def test_probe_non_path_object_refused(self):
        _report, _row, refusals = guard.authorized_target(object()), None, None
        self.assertEqual(_report[1][0]["code"], "PROBE_TARGET_FORBIDDEN")

    def test_probe_layer_failures_are_reported_with_stable_codes(self):
        for layer, code in ((3, "L3_UNREACHABLE"), (3, "L3_SOURCE_UNAVAILABLE"), (4, "L4_RETURN_PATH_FAILED"), (5, "L5_AUTH_FAILED"),
                            (6, "L6_SERVICE_UNAVAILABLE")):
            with self.subTest(code=code):
                report, row, _ = probes.probe(self.oob, transport=M.FakeTransport(lambda a, s, l=layer, c=code: (l, c)))
                self.assertFalse(report.passed)
                self.assertEqual(row.failure_code, code)
                self.assertEqual(row.highest_layer, 1)

    def test_probe_host_key_mismatch_fails_layer_5(self):
        report, _row, _ = probes.probe(self.oob, transport=M.FakeTransport(host_key=M.OTHER_HOST_KEY))
        self.assertEqual(report.failure_code, "L5_HOST_KEY_MISMATCH")

    def test_probe_identity_mismatch_fails_layer_6(self):
        report, _row, _ = probes.probe(self.oob, transport=M.FakeTransport(outputs=M.eos_outputs(hostname="R2", config=M.eos_config(hostname="R2"))))
        self.assertEqual(report.failure_code, "L6_IDENTITY_MISMATCH")

    def test_probe_local_link_down_fails_layer_1(self):
        report, row, _ = probes.probe(self.oob, transport=M.FakeTransport(outputs=M.eos_outputs(links={"Ethernet3": "notconnect"})))
        self.assertEqual((report.failure_code, row.highest_layer), ("L1_LINK_DOWN", 0))

    def test_probe_vlan_not_carried_fails_layer_2(self):
        outputs = M.eos_outputs(config=M.eos_config(ports={"Ethernet3": "trunk101,102"}))
        report, _row, _ = probes.probe(self.oob, transport=M.FakeTransport(outputs=outputs))
        self.assertEqual(report.failure_code, "L2_CONFIG_MISMATCH")

    def test_probe_unverified_attachment_fails_layer_1_without_contact(self):
        models.DeviceAttachment.objects.filter(pk=self.lab["oob"].pk).update(verification_state="UNVERIFIED")
        transport = M.FakeTransport()
        report, _row, _ = probes.probe(self.oob, transport=transport)
        self.assertEqual((report.failure_code, transport.calls), ("L1_TOPOLOGY_UNVERIFIED", []))

    def test_probe_credential_unavailable_fails_layer_5(self):
        with mock.patch.object(probes, "auth_material", side_effect=probes.CredentialUnavailable("x")):
            report, _row, _ = probes.probe(self.oob, transport=M.FakeTransport())
        self.assertEqual(report.failure_code, "L5_AUTH_FAILED")

    @override_settings(NMAS_MGMT_MIN_PROBE_INTERVAL_SECONDS=60)
    def test_probe_rate_limited_for_operator_verification(self):
        selector.evaluate(self.r1, transport=M.FakeTransport())
        self.oob.refresh_from_db()
        _report, row, refusals = probes.probe(self.oob, transport=M.FakeTransport())
        self.assertEqual((refusals[0]["code"], row), ("PROBE_RATE_LIMITED", None))


class LabIneligibilityTests(_Base):
    """R1's VLAN-200 alternatives through S1 and S3 exist on paper only; the lab's real configuration makes them ineligible."""

    def test_r1_vlan_path_through_s3_is_ineligible_vlan_200_not_carried(self):
        trunk = M.management_attachment(self.r1, upstream="S3", port="Ethernet3", local="Ethernet1",
                                        connectivity=models.AttachmentConnectivity.TRUNK)
        via_s3 = M.path(self.r1, self.nmas, path_type=T.VLAN_ADJACENT_SWITCH, attachment=trunk)
        outputs = M.eos_outputs(links={"Ethernet1": "connected", "Ethernet3": "connected"},
                                config=M.eos_config(ports={"Ethernet3": "access200", "Ethernet1": "trunk101,102"}))
        report, _row, _ = probes.probe(via_s3, transport=M.FakeTransport(outputs=outputs))
        self.assertEqual(report.failure_code, "L2_CONFIG_MISMATCH")

    def test_r1_vlan_path_through_s3_with_vlan_200_and_stp_none_is_loop_risk(self):
        trunk = M.management_attachment(self.r1, upstream="S3", port="Ethernet3", local="Ethernet1",
                                        connectivity=models.AttachmentConnectivity.TRUNK)
        via_s3 = M.path(self.r1, self.nmas, path_type=T.VLAN_ADJACENT_SWITCH, attachment=trunk)
        outputs = M.eos_outputs(links={"Ethernet1": "connected"},
                                config=M.eos_config(ports={"Ethernet3": "access200", "Ethernet1": "trunk101,102,200"}, stp="none"))
        report, _row, _ = probes.probe(via_s3, transport=M.FakeTransport(outputs=outputs))
        self.assertEqual(report.failure_code, "MGMT_VLAN_LOOP_RISK")

    def test_r1_vlan_path_through_s1_refused_routed_attachment(self):
        routed = M.management_attachment(self.r1, upstream="S1", port="Ethernet1", local="Ethernet2",
                                         connectivity=models.AttachmentConnectivity.TRUNK)
        outputs = M.eos_outputs(links={"Ethernet2": "connected"},
                                config=M.eos_config(ports={"Ethernet3": "access200", "Ethernet2": "routed:10.0.12.1/30"}))
        via_s1 = M.path(self.r1, self.nmas, path_type=T.VLAN_ADJACENT_SWITCH, attachment=routed)
        report, _row, _ = probes.probe(via_s1, transport=M.FakeTransport(outputs=outputs))
        self.assertEqual(report.failure_code, "L2_CONFIG_MISMATCH")

    def test_vlan_chain_requires_verified_switch_uplink(self):
        self.assertEqual(paths.vlan_chain("S1", "mgmt_swt"), ["S1", "mgmt_swt"])
        models.DeviceAttachment.objects.filter(device__name="S3").update(verification_state="UNVERIFIED")
        self.assertIsNone(paths.vlan_chain("S3", "mgmt_swt"))

    def test_class_2_paths_ordered_s1_before_s3(self):
        via_s3 = M.path(self.r1, self.nmas, path_type=T.VLAN_ADJACENT_SWITCH,
                        attachment=M.management_attachment(self.r1, upstream="S3", port="Ethernet3", local="Ethernet1",
                                                           connectivity=models.AttachmentConnectivity.TRUNK))
        via_s1 = M.path(self.r1, self.nmas, path_type=T.VLAN_ADJACENT_SWITCH,
                        attachment=M.management_attachment(self.r1, upstream="S1", port="Ethernet1", local="Ethernet2",
                                                           connectivity=models.AttachmentConnectivity.TRUNK))
        oob = M.path(self.r1, self.nmas, attachment=self.lab["oob"])
        vrf = M.path(self.r1, self.nmas, path_type=T.ROUTED_VRF, vrf="MGMT", endpoint="10.30.0.1")
        self.assertEqual([p.pk for p in paths.ordered([vrf, via_s3, oob, via_s1])], [oob.pk, via_s1.pk, via_s3.pk, vrf.pk])


class SelectorTests(_Base):
    def setUp(self):
        super().setUp()
        self.oob = M.path(self.r1, self.nmas, attachment=self.lab["oob"])
        self.vrf = M.path(self.r1, self.nmas, path_type=T.ROUTED_VRF, vrf="MGMT", endpoint="10.30.0.1")
        self.config = M.eos_config(ports={"Ethernet3": "access200", "Ethernet4": "vrf:MGMT:10.30.0.1/30"}, vrfs=("MGMT",))
        self.down = set()

    def transport(self):
        outputs = M.eos_outputs(config=self.config, links={"Ethernet3": "connected"})
        return M.FakeTransport(lambda address, source: (3, "L3_UNREACHABLE") if address in self.down else outputs)

    def test_initial_activation_selects_class_1(self):
        result = selector.evaluate(self.r1, transport=self.transport())
        self.assertEqual((result.decision, result.status, result.active_path), ("ACTIVATE", "ACTIVE", self.oob.path_id))

    def test_execution_claim_arriving_before_selection_commit_defers_switch(self):
        with mock.patch.object(selector, "in_flight", side_effect=[{}, {"kind": "EXECUTION", "holder": "late-worker"}]):
            result = selector.evaluate(self.r1, transport=self.transport())
        self.assertEqual((result.decision, result.active_path), ("DEFERRED", ""))
        self.assertEqual(result.reason, "MGMT_EXECUTION_IN_FLIGHT")
        self.assertFalse(models.ManagementPath.objects.filter(device=self.r1, is_active=True).exists())

    def test_stale_instance_cannot_revoke_a_newly_active_path_without_acknowledgement(self):
        selector.evaluate(self.r1, transport=self.transport())
        self.assertFalse(self.oob.is_active)  # this instance predates activation
        result = paths.revoke_path(self.oob, actor=M.APPROVER, reason="stale browser request")
        self.assertEqual(result.codes, ["MGMT_PATH_ACTIVE"])
        self.oob.refresh_from_db()
        self.assertTrue(self.oob.is_active)
        self.assertEqual(self.oob.approval_state, models.ManagementApproval.APPROVED)

    def test_single_failure_does_not_fail_over_hysteresis(self):
        selector.evaluate(self.r1, transport=self.transport())
        self.down.add("192.168.200.1")
        for _ in range(policy.effective().failure_threshold - 1):
            result = selector.evaluate(self.r1, transport=self.transport())
            self.assertEqual((result.decision, result.status, result.active_path), ("NONE", "DEGRADED", self.oob.path_id))

    def test_degraded_selection_blocks_new_consumers_until_verified_failover(self):
        from core.services.execution.executors import ceos

        selector.evaluate(self.r1, transport=self.transport())
        self.down.add("192.168.200.1")
        selector.evaluate(self.r1, transport=self.transport())
        self.assertEqual(resolve.endpoint("R1").source, resolve.BLOCKED)
        with mock.patch.object(ssh_transport, "connect_eos") as connector:
            with self.assertRaises(ceos.ExecutorError):
                ceos.netmiko_connection({"name": "R1"})
            connector.assert_not_called()
        for _ in range(policy.effective().failure_threshold):
            selector.evaluate(self.r1, transport=self.transport())
        self.assertEqual(resolve.endpoint("R1").path_id, self.vrf.path_id)

    def test_failover_after_threshold_to_routed_vrf(self):
        selector.evaluate(self.r1, transport=self.transport())
        self.down.add("192.168.200.1")
        for _ in range(policy.effective().failure_threshold):
            result = selector.evaluate(self.r1, transport=self.transport())
        self.assertEqual((result.decision, result.active_path), ("FAILOVER", self.vrf.path_id))
        transition = models.ManagementPathTransition.objects.filter(device=self.r1, kind="FAILOVER").get()
        self.assertEqual((transition.from_path_id, transition.to_path_id), (self.oob.pk, self.vrf.pk))

    def test_failback_waits_for_restore_threshold_and_hold_down(self):
        selector.evaluate(self.r1, transport=self.transport())
        self.down.add("192.168.200.1")
        for _ in range(policy.effective().failure_threshold):
            selector.evaluate(self.r1, transport=self.transport())
        self.down.clear()
        first = selector.evaluate(self.r1, transport=self.transport())
        self.assertEqual(first.active_path, self.vrf.path_id)            # one success restores nothing (FAILED path)
        for _ in range(policy.effective().restore_threshold):
            held = selector.evaluate(self.r1, transport=self.transport())
        self.assertEqual((held.decision, held.active_path), ("HOLD_DOWN", self.vrf.path_id))
        later = timezone.now() + timedelta(seconds=policy.effective().hold_down_seconds + 1)
        back = selector.evaluate(self.r1, transport=self.transport(), now=later)
        self.assertEqual((back.decision, back.active_path), ("FAILBACK", self.oob.path_id))

    def test_all_paths_lost_fails_closed(self):
        selector.evaluate(self.r1, transport=self.transport())
        self.down.update({"192.168.200.1", "10.30.0.1"})
        for _ in range(policy.effective().failure_threshold):
            result = selector.evaluate(self.r1, transport=self.transport())
        self.assertEqual((result.decision, result.status), ("LOST", "NO_PATH"))
        self.assertIn("MGMT_NO_USABLE_PATH", [b["code"] for b in result.blockers])
        self.assertFalse(resolve.endpoint("R1", legacy_address="192.168.200.1").usable)

    def test_in_flight_execution_defers_failover_and_requires_reconciliation(self):
        selector.evaluate(self.r1, transport=self.transport())
        self.down.add("192.168.200.1")
        with mock.patch.object(selector, "in_flight", return_value={"kind": "EXECUTION", "holder": "run-1"}):
            for _ in range(policy.effective().failure_threshold):
                result = selector.evaluate(self.r1, transport=self.transport())
        self.assertEqual((result.decision, result.active_path), ("DEFERRED", self.oob.path_id))
        state = selector.state_for(self.r1)
        self.assertTrue(state.reconciliation_required)
        self.assertFalse(resolve.endpoint("R1", purpose=resolve.WRITE).usable)
        self.assertEqual(models.ManagementPathTransition.objects.filter(kind="DEFERRED").count(), 1)
        after = selector.evaluate(self.r1, transport=self.transport())
        self.assertEqual((after.decision, after.active_path), ("FAILOVER", self.vrf.path_id))
        self.assertFalse(resolve.endpoint("R1", purpose=resolve.WRITE).usable)       # still blocked until reconciled
        self.assertTrue(resolve.endpoint("R1", purpose=resolve.READ).usable)
        self.assertTrue(selector.acknowledge_reconciliation(self.r1, actor=M.APPROVER, reason="running config read back")["ok"])
        self.assertTrue(resolve.endpoint("R1", purpose=resolve.WRITE).usable)

    def test_in_flight_reads_the_device_lock(self):
        self.assertEqual(selector.in_flight(self.r1), {})

    def test_reconciliation_acknowledgement_refused_while_in_flight(self):
        with mock.patch.object(selector, "in_flight", return_value={"kind": "EXECUTION", "holder": "run-1"}):
            result = selector.acknowledge_reconciliation(self.r1, actor=M.APPROVER, reason="x")
        self.assertFalse(result["ok"])

    def test_security_failure_is_immediate(self):
        selector.evaluate(self.r1, transport=self.transport())
        outputs = M.eos_outputs(config=self.config)
        result = selector.evaluate(self.r1, transport=M.FakeTransport(
            lambda address, source: outputs, host_key=M.OTHER_HOST_KEY))
        self.assertEqual(result.decision, "LOST")      # both paths present the wrong key: never fail over to an impostor

    def test_restart_recovery_repairs_crash_window(self):
        selector.evaluate(self.r1, transport=self.transport())
        selector._path_write(models.ManagementPath.objects.get(pk=self.oob.pk), is_active=False)   # crash between the two halves
        repaired = selector.recover()
        self.assertEqual(repaired[0]["device"], "R1")
        self.assertTrue(models.ManagementPath.objects.get(pk=self.oob.pk).is_active)
        self.assertTrue(models.ManagementPathTransition.objects.filter(kind="RESTART_RECOVERY").exists())

    def test_recover_with_consistent_state_changes_nothing(self):
        selector.evaluate(self.r1, transport=self.transport())
        self.assertEqual(selector.recover(), [])

    def test_concurrent_evaluation_conflict_switches_nothing(self):
        real = selector._cas_state
        with mock.patch.object(selector, "_cas_state", side_effect=lambda row, version, **f: False):
            result = selector.evaluate(self.r1, transport=self.transport())
        self.assertEqual(result.decision, "CONFLICT")
        self.assertFalse(models.ManagementPath.objects.filter(is_active=True).exists())
        self.assertTrue(callable(real))


class ResolverTests(_Base):
    def test_pending_registration_blocks_inventory_until_an_approved_path_is_verified(self):
        M.path(self.r1, self.nmas, attachment=self.lab["oob"], approve=False)
        self.assertEqual(resolve.endpoint("R1", legacy_address="192.168.200.1").source, resolve.BLOCKED)
        result = selector.evaluate(self.r1)
        self.assertEqual(result.status, models.ManagementStatus.NO_PATH)
        self.assertEqual([b["code"] for b in result.blockers], ["MGMT_NO_USABLE_PATH"])
        self.assertIsNone(nsot_live.get_live_target_metadata("R1"))

    def test_revoking_the_last_path_does_not_restore_inventory_or_consumer_access(self):
        from core.services.execution.executors import ceos

        path = M.path(self.r1, self.nmas, attachment=self.lab["oob"])
        self.assertTrue(paths.revoke_path(path, actor=M.APPROVER, reason="remove management authorization").ok)
        self.assertEqual(resolve.endpoint("R1", legacy_address="192.168.200.1").source, resolve.BLOCKED)
        self.assertEqual(selector.evaluate(self.r1).status, models.ManagementStatus.NO_PATH)
        self.assertIsNone(nsot_live.get_live_target_metadata("R1"))
        with mock.patch.object(ssh_transport, "connect_eos") as connector:
            with self.assertRaises(ceos.ExecutorError):
                ceos.netmiko_connection({"name": "R1"})
            connector.assert_not_called()

    def test_unreadable_path_registry_never_falls_back_to_inventory(self):
        from django.db import DatabaseError

        with mock.patch.object(models.ManagedDevice.objects, "filter", side_effect=DatabaseError("offline")):
            found = resolve.endpoint("R1", legacy_address="192.168.200.1")
        self.assertEqual((found.source, found.address), ("BLOCKED", ""))

    def test_no_paths_keeps_legacy_inventory_address(self):
        found = resolve.endpoint("R1", legacy_address="192.168.200.1")
        self.assertEqual((found.source, found.address), ("LEGACY", "192.168.200.1"))
        self.assertEqual(nsot_live.get_live_target_metadata("R1")["management"]["source"], "LEGACY")

    def test_unknown_device_is_legacy(self):
        self.assertEqual(resolve.endpoint("S4", legacy_address="192.168.200.14").source, "LEGACY")

    def test_approved_but_unevaluated_paths_fail_closed(self):
        M.path(self.r1, self.nmas, attachment=self.lab["oob"])
        self.assertEqual(resolve.endpoint("R1", legacy_address="192.168.200.1").source, "BLOCKED")
        self.assertIsNone(nsot_live.get_live_target_metadata("R1"))

    def test_active_path_endpoint_is_used_by_nsot_live(self):
        vrf = M.path(self.r1, self.nmas, path_type=T.ROUTED_VRF, vrf="MGMT", endpoint="10.30.0.1")
        config = M.eos_config(ports={"Ethernet4": "vrf:MGMT:10.30.0.1/30"}, vrfs=("MGMT",), svi="")
        selector.evaluate(self.r1, transport=M.FakeTransport(outputs=M.eos_outputs(config=config, links={})))
        found = nsot_live.get_live_target_metadata("R1", purpose="WRITE")
        self.assertEqual((found["address"], found["management"]["path_id"], found["management"]["vrf"]), ("10.30.0.1", vrf.path_id, "MGMT"))

    def test_active_path_returns_selected_credential(self):
        vrf = M.path(self.r1, self.nmas, path_type=T.ROUTED_VRF, vrf="MGMT", endpoint="10.30.0.1")
        config = M.eos_config(ports={"Ethernet4": "vrf:MGMT:10.30.0.1/30"}, vrfs=("MGMT",), svi="")
        selector.evaluate(self.r1, transport=M.FakeTransport(outputs=M.eos_outputs(config=config, links={})))
        with mock.patch.object(probes, "auth_material", return_value=("path-user", [{"password": "path-secret"}])):
            target = nsot_live.get_live_target("R1", purpose="WRITE")
        self.assertEqual((target["username"], target["password"], target["management"]["path_id"]),
                         ("path-user", "path-secret", vrf.path_id))
        self.assertEqual(ssh_transport.active_path(target).pk, vrf.pk)

    def test_active_path_refuses_changed_target_or_unverified_attachment(self):
        vrf = M.path(self.r1, self.nmas, path_type=T.ROUTED_VRF, vrf="MGMT", endpoint="10.30.0.1")
        config = M.eos_config(ports={"Ethernet4": "vrf:MGMT:10.30.0.1/30"}, vrfs=("MGMT",), svi="")
        selector.evaluate(self.r1, transport=M.FakeTransport(outputs=M.eos_outputs(config=config, links={})))
        target = nsot_live.get_live_target_metadata("R1", purpose="WRITE")
        changed = {**target, "address": "192.168.200.1"}
        with self.assertRaises(ssh_transport.ManagedConnectionRejected):
            ssh_transport.active_path(changed)
        changed = {**target, "management": {**target["management"], "port": 2222}}
        with self.assertRaises(ssh_transport.ManagedConnectionRejected):
            ssh_transport.active_path(changed)
        models.NmasManagementAttachment.objects.filter(pk=vrf.nmas_attachment_id).update(verification_state="UNVERIFIED")
        with self.assertRaises(ssh_transport.ManagedConnectionRejected):
            ssh_transport.active_path(target)

    def test_telemetry_targets_states_phase_8_limitation(self):
        rows = resolve.telemetry_targets()
        self.assertTrue(all(row["telemetry_follows_failover"] is False for row in rows))


class NmasAttachmentGuardTests(TestCase):
    def test_register_nmas_attachment_containerlab_or_loopback_refused(self):
        from core.services.devices import lifecycle

        lifecycle.adopt_existing("mgmt_swt", role="switch", actor=M.APPROVER)
        for source, network in (("172.20.20.1", "172.20.20.0/24"), ("127.0.0.5", "127.0.0.0/8"), ("169.254.1.1", "169.254.0.0/16"),
                                ("10.0.0.5", "0.0.0.0/0")):
            with self.subTest(source):
                result = paths.register_nmas_attachment(name="x", host_interface="eth9", upstream_device="mgmt_swt", source_address=source,
                                                        network=network, actor=M.OPERATOR)
                self.assertFalse(result.ok)
                self.assertIn("MGMT_ENDPOINT_FORBIDDEN", result.codes)
        self.assertFalse(models.NmasManagementAttachment.objects.exists())


class HealthIntegrationTests(TestCase):
    def test_health_live_session_blocked_reports_management_unreachable(self):
        from core.services.health import live

        lab = M.lab()
        M.path(lab["devices"]["R1"], lab["nmas"], attachment=lab["oob"])        # approved, never selected -> BLOCKED
        with self.assertRaises(live.LiveError) as raised:
            live.EosSession({"name": "R1"})
        self.assertEqual(raised.exception.code, "MANAGEMENT_UNREACHABLE")

    def test_health_live_session_without_paths_not_management_unreachable(self):
        from core.services.health import live

        with mock.patch.object(nsot_live, "get_live_target", return_value=None), \
                mock.patch.object(nsot_live, "get_live_target_metadata", return_value=None):
            with self.assertRaises(live.LiveError) as raised:
                live.EosSession({"name": "R1"})
        self.assertEqual(raised.exception.code, "NOT_CONFIGURED")


@override_settings(NMAS_MGMT_MIN_PROBE_INTERVAL_SECONDS=0)
class ExecutionIntegrationTests(TestCase):
    @override_settings(NMAS_MGMT_MIN_PROBE_INTERVAL_SECONDS=0)
    def test_legacy_docker_rotation_refuses_an_active_management_path(self):
        from types import SimpleNamespace

        from core.services.credentials.ceos_transaction import CeosRotationTransactionController, CeosTransactionRejected
        from core.services.credentials.platforms import CeosPasswordAdapter, PlatformNotImplemented

        lab = M.lab()
        M.path(lab["devices"]["R1"], lab["nmas"], attachment=lab["oob"])
        with M.fake_credentials():
            selector.evaluate(lab["devices"]["R1"], transport=M.FakeTransport())
        credential = SimpleNamespace(device_name="R1", platform="arista_ceos")
        with self.assertRaises(PlatformNotImplemented):
            CeosPasswordAdapter().preflight(credential)
        with self.assertRaises(CeosTransactionRejected):
            CeosRotationTransactionController._target(credential)

    def test_execution_blocked_management_fails_before_any_mutation(self):
        from core.tests.helpers import execution as x

        lab = M.lab()
        M.path(lab["devices"]["R1"], lab["nmas"], attachment=lab["oob"])         # approved, not selected -> BLOCKED for WRITE
        p = x.prepared()
        world = x.FakeWorld()
        result = x.run(p, world)
        self.assertEqual(result.outcome, models.ExecutionOutcome.FAILED_NO_MUTATION)
        self.assertEqual(world.mutating_calls(), [])
        self.assertEqual(result.run.report["error"]["code"], "MGMT_NO_USABLE_PATH")
        self.assertIn("R1", result.run.report["preparation"]["management"])

    def test_execution_without_paths_report_has_no_management_section(self):
        from core.tests.helpers import execution as x

        p = x.prepared()
        result = x.run(p, x.FakeWorld())
        self.assertNotIn("management", result.run.report["preparation"])

class BoundSshTransportTests(SimpleTestCase):
    def test_bound_socket_connects_with_selected_interface_and_source(self):
        import socket
        from types import SimpleNamespace

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen(1)
            attachment = SimpleNamespace(host_interface="lo", source_address="127.0.0.1")
            path = SimpleNamespace(endpoint_address="127.0.0.1", port=listener.getsockname()[1], nmas_attachment=attachment)
            with ssh_transport.bound_socket(path, 5) as bound:
                with listener.accept()[0]:
                    self.assertEqual((bound.getsockname()[0], bound.getpeername()[1]),
                                     ("127.0.0.1", listener.getsockname()[1]))

    def test_missing_selected_host_interface_fails_closed(self):
        from types import SimpleNamespace

        attachment = SimpleNamespace(host_interface="nmas-no-such-interface", source_address="127.0.0.1")
        path = SimpleNamespace(endpoint_address="127.0.0.1", port=22, nmas_attachment=attachment)
        with self.assertRaises(ssh_transport.ManagedConnectionRejected):
            ssh_transport.bound_socket(path, 1)

    def test_real_ssh_connection_uses_bound_socket_and_pinned_key(self):
        import io
        from types import SimpleNamespace

        import paramiko

        from core.services.ztp import workflow

        private, public, _fingerprint = workflow.generate_enrollment_key(("ssh-ed25519",), "nmas@test")
        key = paramiko.Ed25519Key.from_private_key(io.StringIO(private))
        server = M.KeyOnlySshServer(username="nmas-automation", authorized_public=public, outputs={})
        self.addCleanup(server.close)
        attachment = SimpleNamespace(host_interface="lo", source_address="127.0.0.1")
        path = SimpleNamespace(endpoint_address="127.0.0.1", port=server.port, nmas_attachment=attachment,
                               expected_host_key=server.fingerprint)
        target = {"address": "127.0.0.1", "management": {"source": "PATH"}}
        auth = {"username": "nmas-automation", "password": "", "ssh_auth": {"use_keys": True, "pkey": key}}
        with mock.patch.object(ssh_transport, "active_path", return_value=path):
            conn = ssh_transport.connect_eos(target, auth, 5)
            try:
                self.assertIn("nmas-automation", server.auth_attempts)
                self.assertEqual(conn.find_prompt(), "DUT#")
            finally:
                conn.disconnect()

    def test_legacy_inventory_key_account_connects_with_the_in_memory_pkey(self):
        """A key-only cEOS inventory account (legacy branch) hands Paramiko the pkey and does not ask Netmiko for a key file."""
        key = object()
        target = {"address": "192.0.2.1", "management": {"source": "LEGACY"}}
        auth = {"username": "nmas-svc", "password": "", "ssh_auth": {"use_keys": True, "pkey": key, "allow_agent": False}}
        with mock.patch("netmiko.ConnectHandler", return_value="session") as handler:
            self.assertEqual(ssh_transport.connect_eos(target, auth, 5), "session")
        kwargs = handler.call_args.kwargs
        self.assertIs(kwargs["pkey"], key)
        self.assertFalse(kwargs["use_keys"])
        self.assertEqual((kwargs["host"], kwargs["username"], kwargs["device_type"]), ("192.0.2.1", "nmas-svc", "arista_eos"))

    def test_wrong_host_key_is_refused_before_authentication(self):
        import io
        from types import SimpleNamespace

        import paramiko

        from core.services.ztp import workflow

        private, public, _fingerprint = workflow.generate_enrollment_key(("ssh-ed25519",), "nmas@test")
        key = paramiko.Ed25519Key.from_private_key(io.StringIO(private))
        server = M.KeyOnlySshServer(username="nmas-automation", authorized_public=public, outputs={})
        self.addCleanup(server.close)
        attachment = SimpleNamespace(host_interface="lo", source_address="127.0.0.1")
        path = SimpleNamespace(endpoint_address="127.0.0.1", port=server.port, nmas_attachment=attachment,
                               expected_host_key=M.OTHER_HOST_KEY)
        target = {"address": "127.0.0.1", "management": {"source": "PATH"}}
        auth = {"username": "nmas-automation", "password": "", "ssh_auth": {"use_keys": True, "pkey": key}}
        with mock.patch.object(ssh_transport, "active_path", return_value=path):
            with self.assertRaises(ssh_transport.ManagedConnectionRejected) as caught:     # never reported as a timeout
                ssh_transport.connect_eos(target, auth, 5)
        self.assertEqual(str(caught.exception), "HOST_KEY_MISMATCH")
        self.assertEqual(server.auth_attempts, [])


class DockerFallbackGuardTests(SimpleTestCase):
    def test_container_address_never_uses_docker_when_a_managed_path_exists(self):
        from core.services.health import live

        device = {"name": "R5", "platform": "ceos", "address": "", "container": "clab-test-R5"}
        with mock.patch.object(resolve, "endpoint", return_value=resolve.Endpoint(resolve.PATH, address="10.0.0.5")):
            self.assertIs(live.default_session_factory(device), live.EosSession)
        with mock.patch.object(resolve, "endpoint", return_value=resolve.Endpoint(resolve.BLOCKED)):
            self.assertIs(live.default_session_factory(device), live.EosSession)
        with mock.patch.object(resolve, "endpoint", return_value=resolve.Endpoint(resolve.LEGACY)):
            self.assertIs(live.default_session_factory(device), live.DockerEosSession)


class DeviceMutexTests(TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        override = self.settings(BASE_DIR=self.root)
        override.enable()
        self.addCleanup(override.disable)

    def test_busy_refusal_reports_a_fixed_code_and_device_names(self):
        with self.subTest(case="positive valid device list"):
            error = DeviceBusy(["R1"])
            self.assertEqual((str(error), error.devices), ("DEVICE_LOCKED", ("R1",)))
        with self.subTest(case="negative invalid device list"):
            with self.assertRaises(TypeError):
                DeviceBusy(None)

    def test_credential_claim_excludes_another_process_and_releases_after_exit(self):
        script = (
            "import fcntl,os,sys\n"
            "fd=os.open(sys.argv[1],os.O_RDWR)\n"
            "try: fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)\n"
            "except BlockingIOError: sys.exit(23)\n"
        )
        with DeviceMutex(["R1"]) as claim:
            path = os.readlink(f"/proc/self/fd/{claim._fds[0]}")
            with DeviceMutex(["R2"]):
                child = subprocess.run([sys.executable, "-c", script, str(path)], check=False, timeout=5, capture_output=True)
                self.assertEqual(child.returncode, 23)
        child = subprocess.run([sys.executable, "-c", script, str(path)], check=False, timeout=5, capture_output=True)
        self.assertEqual(child.returncode, 0)

    def test_partial_acquisition_releases_every_earlier_device(self):
        with DeviceMutex(["R2"]):
            with self.assertRaises(DeviceBusy):
                with DeviceMutex(["R2", "R1"]):
                    self.fail("overlapping device claims entered")
            with DeviceMutex(["R1"]):
                pass

    def test_exception_releases_the_process_claim(self):
        with self.assertRaises(RuntimeError):
            with DeviceMutex(["R1"]):
                raise RuntimeError("interrupted worker")
        with DeviceMutex(["R1"]):
            pass

    def test_database_error_during_acquisition_does_not_leak_fds(self):
        from django.db import DatabaseError

        claim = DeviceMutex(["R1"])
        with mock.patch.object(models.BootstrapCredentialTransition.objects, "filter", side_effect=DatabaseError):
            with self.assertRaises(DatabaseError):
                claim.__enter__()
        self.assertEqual(claim._fds, [])
        with DeviceMutex(["R1"]):
            pass

    def test_unprotected_directory_and_symlink_are_refused(self):
        with DeviceMutex(["R1"]) as claim:
            path = Path(os.readlink(f"/proc/self/fd/{claim._fds[0]}"))
        directory = path.parent
        directory.chmod(0o777)
        with self.assertRaises(DeviceBusy):
            DeviceMutex(["R1"]).__enter__()
        directory.chmod(0o700)
        path.unlink()
        path.symlink_to(directory / "not-a-lock")
        with self.assertRaises(DeviceBusy):
            DeviceMutex(["R1"]).__enter__()

    def test_unsupported_database_backend_fails_closed(self):
        from core.services.execution import device_mutex

        with mock.patch.object(device_mutex.connection, "vendor", "postgresql"):
            with self.assertRaises(DeviceBusy):
                DeviceMutex(["R1"]).__enter__()
