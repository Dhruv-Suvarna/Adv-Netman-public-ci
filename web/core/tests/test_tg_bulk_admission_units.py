"""Direct tests for the restart-safe bulk admission batch (services/devices/bulk_admission.py, nmas_bulk_admission).

The batch must never report a failure as success and every phase must leave a device exactly as restricted as before when
it fails.  The device-side reads (console host key, ``ssh-keyscan``, the topology service, the diagnostic-account RBAC
proof, the path selector, ``device_observe``) are replaced by fakes; every governed write goes through the real services
against the test database, starting from the same single-admin lab fixture the exception tests use (mgmt_swt + R2 adopted,
R2's management attachment observed by the topology source).
"""

from __future__ import annotations

import base64
import io
import json
import subprocess
import tempfile
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from django.core.management import CommandError, call_command
from django.test import TestCase

from core import models
from core.services.devices import bulk_admission as ba, host_key_pins
from core.services.management import paths
from core.tests.test_single_admin_lab_exception import SingleAdminExceptionTests

KEY = "ssh-ed25519 " + base64.b64encode(b"\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20" + bytes(range(32))).decode()
OTHER = "ssh-ed25519 " + base64.b64encode(b"\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20" + bytes(range(1, 33))).decode()
PIN = host_key_pins.fingerprint(KEY)[0]


def completed(stdout="", rc=0):
    return subprocess.CompletedProcess([], rc, stdout, "")


class BatchTests(TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def test_members_and_batch_checkpoint_round_trip(self):
        self.assertTrue(ba.BY_NAME["R3"].frr)
        self.assertTrue(ba.BY_NAME["mgmt_swt"].self_switch)
        batch = ba.Batch.open(self.tmp.name)
        batch.state["ticket"] = "T-1"
        batch.save()
        row = batch.mark("R1", "EVIDENCE", "DONE", pin=PIN)
        ref = batch.evidence("doc.json", {"a": 1})
        again = ba.Batch.open(self.tmp.name)
        self.assertEqual((row["status"], again.state["ticket"], again.done("R1", "EVIDENCE")), ("DONE", "T-1", True))
        self.assertTrue(ref.startswith("local-unattested:doc.json#sha256="))
        self.assertEqual(json.loads((Path(self.tmp.name) / "doc.json").read_text()), {"a": 1})

    def test_evidence_into_a_removed_directory_is_refused(self):
        batch = ba.Batch.open(Path(self.tmp.name) / "batch")
        (Path(self.tmp.name) / "batch" / "state.json").unlink(missing_ok=True)
        Path(self.tmp.name, "batch").rmdir()
        with self.assertRaises(FileNotFoundError):
            batch.evidence("doc.json", {"a": 1})

    def test_admitted_refuses_a_row_missing_any_gate(self):
        row = {"identity": "VERIFIED", "path_state": "APPROVED/ACTIVE/HEALTHY", "diag_credential": "network-operator/PASSWORD",
               "phases": {"CREDENTIAL": "DONE"}}
        for key, bad in (("identity", "UNVERIFIED"), ("diag_credential", "")):
            with self.subTest(f"a row without {key} is not admitted"):
                self.assertFalse(ba.admitted({**row, key: bad}))


class HostKeyEvidenceTests(TestCase):
    setUp = SingleAdminExceptionTests.setUp
    # set by SingleAdminExceptionTests.setUp
    device: models.ManagedDevice
    attachment: models.DeviceAttachment
    observation: models.DeviceObservation
    nmas: models.NmasManagementAttachment

    def batch(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        return ba.Batch.open(tmp.name)

    def test_console_and_network_keys_return_the_ed25519_key(self):
        with mock.patch.object(ba, "_run", return_value=completed(KEY + " root@R2\n")):
            self.assertEqual(ba.console_public_key(ba.BY_NAME["R2"]), KEY)
        with mock.patch.object(ba, "_run", return_value=completed(KEY + "\n")) as run:
            ba.console_public_key(ba.BY_NAME["R3"])
            self.assertIn("/etc/ssh/ssh_host_ed25519_key.pub", run.call_args.args[0])
        with mock.patch.object(ba, "_run", return_value=completed(f"# 192.168.200.2 SSH-2.0\n192.168.200.2 {KEY}\n")):
            self.assertEqual(ba.network_public_key(ba.BY_NAME["R2"]), KEY)

    def test_unparseable_key_output_yields_no_key(self):
        for label, out in (("an error message", "% Invalid input\n"), ("an rsa key", "ssh-rsa AAAA\n"), ("no output", "")):
            with mock.patch.object(ba, "_run", return_value=completed(out)):
                with self.subTest(f"{label} is no console key"):
                    self.assertEqual(ba.console_public_key(ba.BY_NAME["R2"]), "")
                with self.subTest(f"{label} is no network key"):
                    self.assertEqual(ba.network_public_key(ba.BY_NAME["R2"]), "")
        with mock.patch.object(ba, "_run", return_value=completed(f"192.168.200.9 {KEY}\n")):
            with self.subTest("a key from another address is no network key"):
                self.assertEqual(ba.network_public_key(ba.BY_NAME["R2"]), "")

    def test_phase_evidence_returns_done_when_both_channels_agree(self):
        batch = self.batch()
        with mock.patch.object(ba, "console_public_key", return_value=KEY), mock.patch.object(ba, "network_public_key", return_value=KEY):
            row = ba.phase_evidence(batch, ba.BY_NAME["R2"])
        self.assertEqual((row["status"], row["pin"], row["codes"]), ("DONE", PIN, []))

    def test_phase_evidence_refuses_a_cross_channel_mismatch_or_no_key(self):
        batch = self.batch()
        with mock.patch.object(ba, "console_public_key", return_value=KEY), mock.patch.object(ba, "network_public_key", return_value=OTHER):
            with self.subTest("a different network key is refused"):
                row = ba.phase_evidence(batch, ba.BY_NAME["R2"])
                self.assertEqual((row["status"], row["pin"]), ("FAILED", ""))
                self.assertIn("CROSS_CHANNEL_MISMATCH", row["codes"])
        with mock.patch.object(ba, "console_public_key", return_value=""), mock.patch.object(ba, "network_public_key", return_value=""):
            with self.subTest("no console key is refused"):
                self.assertEqual(ba.phase_evidence(batch, ba.BY_NAME["R2"])["status"], "FAILED")


class GovernedPhaseTests(TestCase):
    setUp = SingleAdminExceptionTests.setUp
    # set by SingleAdminExceptionTests.setUp
    device: models.ManagedDevice
    attachment: models.DeviceAttachment
    observation: models.DeviceObservation
    nmas: models.NmasManagementAttachment

    def batch(self, phases=None):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        batch = ba.Batch.open(tmp.name)
        for (device, phase), row in (phases or {}).items():
            batch.state["devices"][device]["phases"][phase] = row
        return batch

    def test_phase_adopt_returns_done_for_existing_and_new_devices(self):
        batch = self.batch()
        self.assertEqual(ba.phase_adopt(batch, ba.BY_NAME["R2"])["changed"], False)
        row = ba.phase_adopt(batch, ba.BY_NAME["S2"])
        self.assertEqual((row["status"], row["changed"]), ("DONE", True))

    def test_phase_adopt_records_a_refused_adoption(self):
        refused = SimpleNamespace(ok=False, codes=["DEVICE_NOT_IN_INVENTORY"], device=None, changed=False)
        with mock.patch("core.services.devices.lifecycle.adopt_existing", return_value=refused):
            row = ba.phase_adopt(self.batch(), ba.BY_NAME["S3"])
        self.assertEqual((row["status"], row["codes"]), ("FAILED", ["DEVICE_NOT_IN_INVENTORY"]))

    def topology(self, edges):
        handle = mock.MagicMock()
        handle.__enter__.return_value.read.return_value = json.dumps({"graph": {"edges": edges}, "backend": "gnmi", "generated_at": "t"}).encode()
        return mock.patch("urllib.request.urlopen", return_value=handle)

    def test_topology_edge_returns_the_named_edge(self):
        with self.topology([{"id": "R2:eth3--mgmt_swt:eth2", "status": "UP"}]):
            self.assertEqual(ba.topology_edge("R2:eth3--mgmt_swt:eth2")["edge"]["status"], "UP")

    def test_topology_edge_unknown_to_the_service_is_none(self):
        with self.topology([{"id": "other"}]):
            self.assertIsNone(ba.topology_edge("R2:eth3--mgmt_swt:eth2"))

    def test_phase_attach_returns_done_for_the_switch_and_an_observed_attachment(self):
        batch = self.batch()
        self.assertEqual(ba.phase_attach(batch, ba.BY_NAME["mgmt_swt"])["attachment"], None)
        row = ba.phase_attach(batch, ba.BY_NAME["R2"])
        self.assertEqual((row["attachment"], row["observation"]), (self.attachment.pk, self.observation.pk))

    def test_phase_attach_refuses_an_unverified_topology_edge(self):
        batch = self.batch()
        ba.phase_adopt(batch, ba.BY_NAME["S2"])
        with self.topology([{"id": "S2:eth5--mgmt_swt:eth6", "status": "DOWN", "plane": "management"}]):
            row = ba.phase_attach(batch, ba.BY_NAME["S2"])
        self.assertEqual((row["status"], row["codes"]), ("FAILED", ["TOPOLOGY_EDGE_NOT_VERIFIED_UP"]))
        self.assertFalse(models.DeviceObservation.objects.filter(device__name="S2", kind=models.ObservationKind.ATTACHMENT).exists())

    def probe(self, passed=True):
        return SimpleNamespace(login=True, passed=passed, write_denied=True, details={}, as_dict=lambda: {"passed": passed})

    def test_phase_credential_returns_done_after_a_proven_rbac(self):
        batch = self.batch({("R2", "EVIDENCE"): {"status": "DONE", "pin": PIN}})
        with mock.patch("modules.diagnostic_accounts.ensure_password", return_value=("unit-test-secret", True)), \
                mock.patch("modules.diagnostic_accounts.verify_ceos", return_value=self.probe()), \
                mock.patch("modules.diagnostic_accounts.verify_ceos_escalation", return_value={"passed": True}):
            row = ba.phase_credential(batch, ba.BY_NAME["R2"])
        self.assertEqual(row["status"], "DONE")
        cred = models.DeviceCredential.objects.get(pk=row["credential_id"])
        self.assertEqual((cred.account_role, cred.privilege_level), ("network-operator", 1))

    def test_phase_credential_refuses_without_pin_or_rbac_proof(self):
        with self.subTest("no verified host key is refused"):
            self.assertEqual(ba.phase_credential(self.batch(), ba.BY_NAME["R2"])["codes"], ["NO_VERIFIED_HOST_KEY"])
        batch = self.batch({("R2", "EVIDENCE"): {"status": "DONE", "pin": PIN}})
        with mock.patch("modules.diagnostic_accounts.ensure_password", return_value=("unit-test-secret", False)), \
                mock.patch("modules.diagnostic_accounts.verify_ceos", return_value=self.probe(passed=False)):
            with self.subTest("an unproven rbac stores no credential"):
                before = list(models.DeviceCredential.objects.filter(device_name="R2").values_list("pk", "last_result_code"))
                row = ba.phase_credential(batch, ba.BY_NAME["R2"])
                self.assertEqual(row["codes"], ["DIAGNOSTIC_RBAC_NOT_PROVEN"])
                self.assertEqual(list(models.DeviceCredential.objects.filter(device_name="R2").values_list("pk", "last_result_code")), before)

    def switch_path(self):
        self.assertTrue(paths.approve_nmas_attachment(self.nmas, actor="bootstrap-admin").ok)
        switch = models.ManagedDevice.objects.get(name="mgmt_swt")
        return paths.register_path(switch, path_type=models.ManagementPathType.DIRECT_OOB, endpoint_address="192.168.200.10",
                                   nmas_attachment_id=self.nmas.pk, credential_source=models.ManagementCredentialSource.INVENTORY,
                                   credential_reference="mgmt_swt", actor="dhruv", vlan=200, expected_host_key=PIN).path

    def test_phase_path_returns_the_existing_path(self):
        path = self.switch_path()
        row = ba.phase_path(self.batch(), ba.BY_NAME["mgmt_swt"])
        self.assertEqual((row["status"], row["path"]), ("DONE", path.path_id))

    def test_phase_path_refuses_a_device_without_an_approved_nmas_attachment(self):
        row = ba.phase_path(self.batch(), ba.BY_NAME["R2"])
        self.assertEqual(row["status"], "FAILED")
        self.assertTrue(row["codes"])

    def test_exception_document_and_matrix_return_the_batch_scope(self):
        self.switch_path()
        batch = self.batch({("R2", "ATTACH"): {"status": "DONE", "attachment": self.attachment.pk, "observation": self.observation.pk,
                                               "evidence_sha256": "b" * 64}})
        batch.state["ticket"] = "T-1"
        doc = ba.exception_document(batch, minutes=10)
        target = f"{self.device.device_id}:{self.attachment.pk}"
        self.assertEqual(doc["scope"]["ATTACHMENT_APPROVE"], [target])
        self.assertEqual(doc["attachment_observations"], {target: self.observation.pk})
        self.assertIn("MGMT_PATH_APPROVE", doc["scope"])
        rows = {r["device"]: r for r in ba.matrix(batch)}
        self.assertEqual(len(rows), len(ba.MEMBERS))
        self.assertEqual(rows["mgmt_swt"]["attachment"], "self (NMA-000001)")

    def test_exception_document_without_targets_or_grant_has_no_scope(self):
        batch = self.batch()
        with self.subTest("no pending records leave no attachment scope"):
            self.assertNotIn("ATTACHMENT_APPROVE", ba.exception_document(batch)["scope"])
        with self.subTest("no grant is issued when the window excludes it"):
            self.assertNotIn("OBSERVATION_AUTHORIZATION_GRANT", ba.exception_document(batch, grant=False)["scope"])
        with self.subTest("unregistered devices are not admitted in the matrix"):
            rows = {r["device"]: r for r in ba.matrix(batch)}
            self.assertEqual((rows["S4"]["identity"], rows["S4"]["attachment"]), ("UNREGISTERED", "none"))
            self.assertFalse(ba.admitted(rows["R2"]))

    def test_activate_returns_done_for_an_active_healthy_path(self):
        path = self.switch_path()
        models.ManagementPath.objects.filter(pk=path.pk).update(approval_state=models.ManagementApproval.APPROVED, is_active=True,
                                                                health_state=models.ManagementPathHealth.HEALTHY)
        with mock.patch("core.services.management.selector.evaluate", return_value=SimpleNamespace(decision="ACTIVE")):
            row = ba.activate(self.batch(), ba.BY_NAME["mgmt_swt"])
        self.assertEqual((row["status"], row["path"]), ("DONE", path.path_id))

    def test_activate_without_an_approved_path_is_refused(self):
        with mock.patch("core.services.management.selector.evaluate", return_value=SimpleNamespace(decision="NO_PATH")):
            row = ba.activate(self.batch(), ba.BY_NAME["R2"])
        self.assertEqual((row["status"], row["codes"]), ("FAILED", ["PATH_NOT_ACTIVE"]))

    def test_observe_identity_returns_done_for_a_verified_device(self):
        verified = SimpleNamespace(identity_state=models.IdentityVerificationState.VERIFIED, verified_host_key=PIN)
        with mock.patch.object(ba, "_device", return_value=verified):     # identity fields change only through lifecycle
            row = ba.observe_identity(self.batch(), ba.BY_NAME["R2"], authorization_ref="OBS-1", source_id="src", evidence_dir="/nonexistent")
        self.assertEqual((row["status"], row["changed"], row["verified_host_key"]), ("DONE", False, PIN))

    def test_observe_identity_refuses_a_failed_or_mismatched_observation(self):
        batch = self.batch({("R2", "EVIDENCE"): {"status": "DONE", "pin": PIN}})
        with mock.patch("django.core.management.call_command", side_effect=CommandError("OBSERVATION_AUTHORIZATION_MISSING")):
            with self.subTest("a failed device_observe is refused with its code"):
                row = ba.observe_identity(batch, ba.BY_NAME["R2"], authorization_ref="OBS-1", source_id="src", evidence_dir="/nonexistent")
                self.assertEqual(row["codes"], ["OBSERVATION_AUTHORIZATION_MISSING"])
        with mock.patch("django.core.management.call_command", return_value=None):
            with self.subTest("no identity observation is refused"):
                row = ba.observe_identity(batch, ba.BY_NAME["R2"], authorization_ref="OBS-1", source_id="src", evidence_dir="/nonexistent")
                self.assertEqual(row["codes"], ["OBSERVED_HOST_KEY_NOT_THE_EVIDENCE_PIN"])


class BulkAdmissionCommandTests(TestCase):
    def test_status_returns_the_admission_matrix(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = io.StringIO()
            call_command("nmas_bulk_admission", "status", "--dir", tmp, "--json", stdout=out)
            self.assertEqual(len(json.loads(out.getvalue())), len(ba.MEMBERS))

    def test_empty_window_and_missing_arguments_are_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.subTest("a window with nothing to approve is refused"):
                with self.assertRaises(CommandError) as caught:
                    call_command("nmas_bulk_admission", "exception-document", "--dir", tmp, "--window", "B", "--out", f"{tmp}/x.json")
                self.assertIn("nothing to approve", str(caught.exception))
            with self.subTest("an unknown window is refused"):
                with self.assertRaises(CommandError):
                    call_command("nmas_bulk_admission", "exception-document", "--dir", tmp, "--window", "Z", "--out", f"{tmp}/x.json")
