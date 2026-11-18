"""Bulk topology admission (owner-authorized single-admin windows) and the platform work it depends on.

* bulk exception evidence: each attachment target is bound to ITS OWN retained observation; no shared evidence
* DIRECT_OOB for NMAS's own management switch (mgmt_swt): L1 provenance is the approved + VERIFIED NMAS attachment
* Ubuntu/FRR paths: Linux L2/L6 probe checks through the restricted broker; worker transport is the broker, never a shell
* diagnostic accounts IaC: the forced-command broker refuses everything outside its allowlist; sshd admits nmas-diag only
  by key from NMAS; the drift-check form of the drop-in is the deployed Phase 26B file
* the batch checkpoint is restart-safe
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from datetime import timedelta
from pathlib import Path
from types import SimpleNamespace

from django.test import SimpleTestCase, TestCase

from core import models
from core.services.credentials import linux_mfa
from core.services.devices import attachments, bulk_admission as ba, lifecycle
from core.services.identity import single_admin_exception as exception
from core.services.management import paths, probes
from core.services.troubleshooting import diagnostic_worker as worker
from core.tests.test_single_admin_lab_exception import SingleAdminExceptionTests
from modules import diagnostic_accounts as da

PIN = "SHA256:" + "A" * 43


class BulkExceptionEvidenceTests(TestCase):
    setUp = SingleAdminExceptionTests.setUp
    activate = SingleAdminExceptionTests.activate
    uses = SingleAdminExceptionTests.uses

    def _second(self):
        s2 = lifecycle.adopt_existing("S2", role="switch", actor="bootstrap-admin").device
        att = attachments.register_attachment(
            s2, upstream_device="mgmt_swt", upstream_interface="Ethernet6", local_interface="Ethernet5",
            purpose=models.AttachmentPurpose.MANAGEMENT, connectivity=models.AttachmentConnectivity.ACCESS, vlan=200, actor="dhruv").attachment
        seen = lifecycle.record_observation(
            s2, kind=models.ObservationKind.ATTACHMENT, source=models.ObservationSource.TRUSTED_UPSTREAM_INTERFACE,
            actor="source:nmas-topology", upstream_device="mgmt_swt", upstream_interface="Ethernet6", local_interface="Ethernet5")
        return s2, models.DeviceAttachment.objects.get(pk=att.pk), seen.observation

    def _cap(self, targets, observations):
        from django.utils import timezone
        now = timezone.now() - timedelta(seconds=5)
        doc = {"schema": exception.SCHEMA, "marker": exception.MARKER, "mode": exception.MODE, "exception_id": "OWNER-LAB-BULK-TEST-A",
               "actor": "dhruv", "lab_id": "srlceos01", "issued_at": now.isoformat(), "expires_at": (now + timedelta(minutes=25)).isoformat(),
               "max_uses": len(targets), "scope": {"ATTACHMENT_APPROVE": targets},
               "evidence": {"attachment_observations": observations, "attachment_evidence_sha256s": {t: "b" * 64 for t in targets}}}
        cap = exception.parse(doc).capability
        self.activate(cap)
        return cap

    def test_each_target_is_approved_only_with_its_own_observation(self):
        s2, att2, obs2 = self._second()
        t1, t2 = f"{self.device.device_id}:{self.attachment.pk}", f"{s2.device_id}:{att2.pk}"
        cap = self._cap([t1, t2], {t1: self.observation.pk, t2: obs2.pk})
        self.assertTrue(attachments.approve_attachment(self.device, self.attachment.pk, actor="dhruv", exception=cap).ok)
        self.assertTrue(attachments.approve_attachment(s2, att2.pk, actor="dhruv", exception=cap).ok)
        uses = self.uses(cap)
        self.assertEqual(len(uses), 2)
        self.assertEqual({u.metadata["evidence"]["observation"] for u in uses}, {self.observation.pk, obs2.pk})
        self.assertTrue(all(u.metadata["separation_of_duties_satisfied"] is False for u in uses))

    def test_a_target_borrowing_another_devices_observation_is_refused_and_consumes_nothing(self):
        s2, att2, _obs2 = self._second()
        t1, t2 = f"{self.device.device_id}:{self.attachment.pk}", f"{s2.device_id}:{att2.pk}"
        cap = self._cap([t1, t2], {t1: self.observation.pk, t2: self.observation.pk})     # S2 points at R2's evidence
        refused = attachments.approve_attachment(s2, att2.pk, actor="dhruv", exception=cap)
        self.assertFalse(refused.ok)
        self.assertIn("APPROVAL_SELF", refused.codes)
        self.assertEqual(self.uses(cap), [])
        att2.refresh_from_db()
        self.assertEqual(att2.approval_state, "PENDING")


class NmasSwitchSelfPathTests(TestCase):
    setUp = SingleAdminExceptionTests.setUp

    def _approve_nma(self):
        self.assertTrue(paths.approve_nmas_attachment(self.nmas, actor="bootstrap-admin").ok)
        self.nmas.refresh_from_db()

    def test_mgmt_switch_direct_oob_without_device_attachment(self):
        self._approve_nma()
        switch = models.ManagedDevice.objects.get(name="mgmt_swt")
        r = paths.register_path(switch, path_type=models.ManagementPathType.DIRECT_OOB, endpoint_address="192.168.200.10",
                                nmas_attachment_id=self.nmas.pk, credential_source=models.ManagementCredentialSource.INVENTORY,
                                credential_reference="mgmt_swt", actor="dhruv", vlan=200, expected_host_key=PIN)
        self.assertTrue(r.ok, r.codes)
        self.assertIsNone(r.path.attachment)
        self.assertTrue(paths.is_nmas_switch_self(switch, r.path.path_type, None, self.nmas, r.path.via_device))
        # L1 provenance is the NMAS attachment; it must still be VERIFIED
        self.assertEqual(paths.topology_problems(r.path), [])
        self.nmas.verification_state = models.AttachmentVerification.UNVERIFIED
        self.nmas.save(update_fields=["verification_state"])
        self.assertTrue(paths.topology_problems(models.ManagementPath.objects.get(pk=r.path.pk)))

    def test_any_other_device_still_needs_its_own_attachment(self):
        self._approve_nma()
        r = paths.register_path(self.device, path_type=models.ManagementPathType.DIRECT_OOB, endpoint_address="192.168.200.2",
                                nmas_attachment_id=self.nmas.pk, credential_source=models.ManagementCredentialSource.INVENTORY,
                                credential_reference="R2", actor="dhruv", vlan=200, expected_host_key=PIN)
        self.assertFalse(r.ok)
        self.assertIn("MGMT_PATH_ATTACHMENT_REQUIRED", r.codes)


LINUX_ADDR = [
    {"ifname": "lo", "flags": ["LOOPBACK", "UP", "LOWER_UP"], "addr_info": [{"local": "127.0.0.1", "scope": "host"}]},
    {"ifname": "eth3", "flags": ["BROADCAST", "MULTICAST", "UP", "LOWER_UP"], "master": "Vlan200", "addr_info": []},
    {"ifname": "Vlan200", "flags": ["BROADCAST", "MULTICAST", "UP", "LOWER_UP"],
     "addr_info": [{"local": "192.168.200.3", "prefixlen": 24, "scope": "global"}]},
]


class LinuxProbeTests(SimpleTestCase):
    path = SimpleNamespace(endpoint_address="192.168.200.3", vlan=200, local_interface="eth3")

    def outputs(self, links=LINUX_ADDR, hostname="R3\n"):
        return {"hostname": hostname, "ip -j addr show": json.dumps(links)}

    def test_live_shape_passes(self):
        self.assertEqual(probes.linux_config_problems(self.path, self.outputs()), ([], True))
        self.assertEqual(probes.linux_identity_problems(SimpleNamespace(name="R3"), self.outputs()), [])

    def test_wrong_host_moved_address_member_down_and_not_bridged(self):
        self.assertEqual(probes.linux_identity_problems(SimpleNamespace(name="R4"), self.outputs())[0]["code"], "L6_IDENTITY_MISMATCH")
        moved = [dict(LINUX_ADDR[0]), dict(LINUX_ADDR[1]), {**LINUX_ADDR[2], "addr_info": []}]
        self.assertEqual(probes.linux_config_problems(self.path, self.outputs(moved))[0][0]["code"], "L2_CONFIG_MISMATCH")
        down = [LINUX_ADDR[0], {**LINUX_ADDR[1], "flags": ["BROADCAST", "UP"]}, LINUX_ADDR[2]]
        self.assertEqual(probes.linux_config_problems(self.path, self.outputs(down)), ([probes.codes.blocker("L1_LINK_DOWN", reason="eth3")], False))
        unbridged = [LINUX_ADDR[0], {**LINUX_ADDR[1], "master": "br9"}, LINUX_ADDR[2]]
        self.assertEqual(probes.linux_config_problems(self.path, self.outputs(unbridged))[0][0]["code"], "L2_CONFIG_MISMATCH")

    def test_probe_commands_are_in_the_broker_allowlist(self):
        self.assertTrue(set(probes.LINUX_COMMANDS) <= set(worker.broker_allowlist()))


class WorkerLinuxTransportTests(SimpleTestCase):
    def test_broker_allowlist_is_read_only_and_exact(self):
        allow = worker.broker_allowlist()
        self.assertIn("vtysh -c 'show ip ospf neighbor json'", allow)
        self.assertNotIn("vtysh -c 'show running-config'", allow)              # config kind is never brokered
        for row in allow:
            self.assertFalse(any(word in row.split() for word in ("configure", "conf", "set", "del", "flush", "sudo", "bash", "sh")), row)

    def test_operation_maps_catalogue_argv_to_one_broker_string(self):
        path = SimpleNamespace(device=SimpleNamespace(platform=models.Platform.UBUNTU_FRR))
        req = SimpleNamespace(operation_id="cli:ospf_neighbors", params={})
        spec, command = worker._operation(path, req)  # pylint: disable=protected-access
        self.assertEqual(command, "vtysh -c 'show ip ospf neighbor json'")
        with self.assertRaises(worker.IpcRefused):
            worker._operation(path, SimpleNamespace(operation_id="cli:frr_config", params={}))   # config kind refused

    def test_frr_never_falls_back_to_the_automation_account(self):
        path = SimpleNamespace(device=SimpleNamespace(name="R3", platform=models.Platform.UBUNTU_FRR))
        from core.services.management import probes as p
        with self.assertRaises(p.CredentialUnavailable):
            worker._diagnostic_auth_material(path, credential_lookup=lambda d: None)  # pylint: disable=protected-access
        wrong = SimpleNamespace(account_kind=models.AccountKind.SERVICE, auth_method=models.DeviceAuthMethod.PUBLICKEY,
                                account_role="machine-read", privilege_level=None, ssh_key_ref=da.key_ref("R3"), secret_ref="")
        with self.assertRaises(p.CredentialUnavailable):
            worker._diagnostic_auth_material(path, credential_lookup=lambda d: wrong)  # pylint: disable=protected-access


class DiagnosticAccountsTests(SimpleTestCase):
    def run_broker(self, requested: str, allow: list[str]) -> subprocess.CompletedProcess:
        with tempfile.TemporaryDirectory() as tmp:
            allowlist = Path(tmp) / "allowlist"
            allowlist.write_text(da.allowlist_text(allow))
            script = Path(tmp) / "broker.py"
            script.write_text(da.BROKER_SCRIPT.replace(da.ALLOWLIST_PATH, str(allowlist)))
            return subprocess.run([sys.executable, "-I", str(script)], capture_output=True, text=True,
                                  env={"SSH_ORIGINAL_COMMAND": requested, "PATH": os.environ.get("PATH", "")}, timeout=30)

    def test_broker_runs_only_exact_allowlisted_commands_without_a_shell(self):
        ok = self.run_broker("echo nmas-ok", ["echo nmas-ok"])
        self.assertEqual((ok.returncode, ok.stdout.strip()), (0, "nmas-ok"))
        for bad in ("id", "echo nmas-ok; id", "echo nmas-ok && id", "echo  nmas-ok", "", "vtysh -c 'configure terminal'"):
            r = self.run_broker(bad, ["echo nmas-ok"])
            self.assertEqual(r.returncode, 126, bad)
            self.assertIn(da.REFUSED_MARKER, r.stderr)
        injected = self.run_broker("echo $(id)", ["echo $(id)"])            # even an allowlisted metachar is never shell-expanded
        self.assertEqual(injected.stdout.strip(), "$(id)")

    def test_authorized_key_is_restricted_to_the_broker(self):
        line = da.authorized_key_line("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOrNmasTestKeyOnly0000000000000000000000000 x")
        self.assertTrue(line.startswith(f'restrict,command="{da.BROKER_PATH}" ssh-ed25519 '))
        with self.assertRaises(da.DiagnosticAccountError):
            da.authorized_key_line("ssh-rsa AAAA x")

    def test_ceos_template_is_network_operator_only(self):
        text = da.render_ceos("not-a-real-secret")
        self.assertIn("username nmas-diag role network-operator secret not-a-real-secret", text)
        self.assertNotIn("privilege 15", text)
        self.assertNotIn("network-admin", text)

    def test_sshd_dropin_admits_nmas_diag_only_by_key_from_nmas(self):
        target = SimpleNamespace(source_address="192.168.200.100", breakglass_username="r3-breakglass")
        legacy, current = linux_mfa.sshd_dropin(target, include_diagnostic=False), linux_mfa.sshd_dropin(target)
        self.assertNotIn("nmas-diag", legacy)
        self.assertIn("AllowUsers nmas-admin@192.168.200.100 nmas-automation@192.168.200.100 r3-breakglass@192.168.200.100 "
                      "nmas-diag@192.168.200.100\n", current)
        block = current.split("Match User nmas-diag Address 192.168.200.100\n", 1)[1].split("\n\n", 1)[0]
        self.assertIn("AuthenticationMethods publickey", block)
        self.assertIn("PasswordAuthentication no", block)
        self.assertIn("PermitTTY no", block)


class BatchCheckpointTests(SimpleTestCase):
    def test_checkpoint_survives_restart_and_failure_is_recorded_not_hidden(self):
        with tempfile.TemporaryDirectory() as tmp:
            batch = ba.Batch.open(tmp)
            batch.mark("R1", "EVIDENCE", "DONE", pin=PIN)
            batch.mark("R3", "CREDENTIAL", "FAILED", codes=["DIAGNOSTIC_RBAC_NOT_PROVEN"])
            again = ba.Batch.open(tmp)
            self.assertTrue(again.done("R1", "EVIDENCE"))
            self.assertFalse(again.done("R3", "CREDENTIAL"))
            self.assertEqual(again.state["log"][-1]["codes"], ["DIAGNOSTIC_RBAC_NOT_PROVEN"])
            self.assertEqual(oct(os.stat(Path(tmp) / "state.json").st_mode & 0o777), "0o600")
            self.assertEqual({m.name for m in ba.MEMBERS}, {"R1", "R2", "R3", "R4", "S1", "S2", "S3", "S4", "mgmt_swt"})
            self.assertNotIn("R5", ba.BY_NAME)

    def test_admitted_requires_every_gate(self):
        row = {"identity": "VERIFIED", "path_state": "APPROVED/ACTIVE/HEALTHY", "diag_credential": "network-operator/PASSWORD",
               "phases": {"CREDENTIAL": "DONE"}}
        self.assertTrue(ba.admitted(row))
        for key, bad in (("identity", "UNVERIFIED"), ("path_state", "APPROVED/inactive/UNKNOWN"), ("diag_credential", "")):
            self.assertFalse(ba.admitted({**row, key: bad}), key)
        self.assertFalse(ba.admitted({**row, "phases": {"CREDENTIAL": "FAILED"}}))


class FrrObservationIdentityTests(TestCase):
    def test_frr_observation_uses_the_dedicated_broker_account_and_no_sudo(self):
        from core.services.devices import observation_connections as oc
        from core.services.management import linux_ssh

        found = {"address": "192.168.200.3", "port": 22, "username": "nmas-automation", "host_key": PIN,
                 "ssh_key_ref": "runtime://device-credentials/r3-nmas-automation-sshkey"}
        self.assertEqual(oc._frr_diagnostic_identity("R3", found), found)          # no broker credential: unchanged
        models.DeviceCredential.objects.create(device_name="R3", platform="ubuntu_frr", username="nmas-diag",
                                               account_kind=models.AccountKind.SERVICE, auth_method=models.DeviceAuthMethod.PUBLICKEY,
                                               account_role="diagnostic-broker", ssh_key_ref=da.key_ref("R3"),
                                               ssh_public_key_fingerprint=PIN, ssh_public_key="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFixtureOnlyPublicKey000000000000000000000")
        chosen = oc._frr_diagnostic_identity("R3", found)
        self.assertEqual((chosen["username"], chosen["ssh_key_ref"], chosen["host_key"], chosen["address"]),
                         ("nmas-diag", da.key_ref("R3"), PIN, "192.168.200.3"))
        self.assertEqual(linux_ssh.command_line(["vtysh", "-c", "show version"], "nmas-diag"), "vtysh -c 'show version'")
        self.assertIn("vtysh -c 'show version'", worker.broker_allowlist())
        self.assertTrue(linux_ssh.command_line(["vtysh", "-c", "show version"], "nmas-automation").startswith("sudo -n -- "))

    def test_a_broker_row_with_the_wrong_contract_is_ignored(self):
        from core.services.devices import observation_connections as oc

        models.DeviceCredential.objects.create(device_name="R4", platform="ubuntu_frr", username="nmas-diag",
                                               account_kind=models.AccountKind.SERVICE, auth_method=models.DeviceAuthMethod.PUBLICKEY,
                                               account_role="machine-read", ssh_key_ref=da.key_ref("R4"),
                                               ssh_public_key_fingerprint=PIN, ssh_public_key="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFixtureOnlyPublicKey000000000000000000000")
        found = {"username": "nmas-automation", "ssh_key_ref": "x"}
        self.assertEqual(oc._frr_diagnostic_identity("R4", found), found)


class Hc04ScopeTests(SimpleTestCase):
    def test_hc04_without_a_path_link_is_inconclusive_not_an_index_error(self):
        """Admission acceptance (TS-20261117-0A0F9944): single-device scope, no forwarding path -> HC04 raised IndexError."""
        from core.services.troubleshooting.runbooks import hc

        ctx = SimpleNamespace(intent={}, path_fwd=[], opt=lambda *a: None)
        result = hc.hc04(ctx)
        self.assertEqual(result.verdict, "INCONCLUSIVE")
        self.assertIn("no path link", result.reason)
