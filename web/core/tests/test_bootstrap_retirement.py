"""V2 Phase 4 -- governed bootstrap (ZTP enrollment) credential replacement and retirement (BCRED).

A natively bootstrapped test device (the Phase-3 flow, fake DHCP provider and fake verification outputs) and an in-memory
EOS account model stand in for the device: no network.  The enrollment key lives in a temporary isolated provider store.
"""

from __future__ import annotations

import ipaddress
import json

from django.test import TestCase

from core import models
from core.services.management import bootstrap_credentials as B, selector, ssh
from core.services.ztp import artifacts, management as ztp_management, workflow
from core.tests.helpers import lifecycle as L
from core.tests.helpers import ztp as Z

S = models.BootstrapCredentialState
REPLACEMENT_PUBLIC = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIReplacementKeyBlobForTestsOnly000000000000 nmas-svc@nmas"
REPLACEMENT_FP = "SHA256:" + "R" * 43


class _Key:
    def __init__(self, blob):
        self.blob = blob


class FakeKeys:
    """In-memory stand-ins for the provider-held private keys: each 'key' carries the public blob it proves."""

    def __init__(self, bootstrap_blob):
        self.bootstrap_blob = bootstrap_blob

    def bootstrap(self, transition):
        return _Key(self.bootstrap_blob)

    def replacement(self, transition):
        return _Key(REPLACEMENT_PUBLIC.split()[1])


class FakeEos:
    """Local accounts of one EOS device: {username: ssh-key blob or None}, configure sessions and ``commit timer``."""

    def __init__(self, host_key, bootstrap_blob, **fail):
        self.host_key, self.users, self.fail = host_key, {"nmas-enroll": bootstrap_blob}, dict(fail)
        self.pending_restore, self.sent, self.connects = None, [], []

    def connect(self, *, address, port, username, pkey, expected_host_key):
        self.connects.append(username)
        if expected_host_key != self.host_key:
            raise ssh.CliError("HOST_KEY_MISMATCH")
        if self.fail.get("unreachable"):
            raise ssh.CliError("UNREACHABLE")
        accepted = self.users.get(username)
        if username == "nmas-enroll" and self.fail.get("phantom_bootstrap") and "nmas-enroll" not in self.users:
            accepted = pkey.blob                     # a device that still authenticates a removed account (cached AAA)
        if accepted is None or accepted != pkey.blob:
            raise ssh.CliError("AUTH_FAILED")
        return _Cli(self)

    def expire_timer(self):
        if self.pending_restore is not None:
            self.users, self.pending_restore = self.pending_restore, None


class _Cli:
    def __init__(self, device):
        self.device = device

    def show(self, command):
        assert command == B.USERS, command
        lines = []
        for name, blob in sorted(self.device.users.items()):
            lines.append(f"username {name} privilege 15 role network-admin secret sha512 $6$hashed")
            if blob:
                lines.append(f"username {name} ssh-key ssh-ed25519 {blob} comment")
        return "\n".join(lines) + "\n"

    def configure(self, lines):
        device = self.device
        device.sent.append(list(lines))
        if device.fail.pop("reject_next", False):
            raise ssh.CliError("COMMAND_REJECTED")
        staged = dict(device.users)
        for line in lines:
            parts = line.split()
            if line.startswith("configure session ") and line.endswith(" commit"):
                device.pending_restore = None
            elif line.startswith("configure session ") and line.endswith(" abort"):
                if device.pending_restore is not None:
                    device.users, device.pending_restore = device.pending_restore, None
                return ""
            elif line.startswith("configure session "):
                continue
            elif parts[:1] == ["username"] and "ssh-key" in parts:
                blob = parts[parts.index("ssh-key") + 2]
                staged[parts[1]] = "CORRUPTED" if device.fail.get("corrupt_key") else blob
            elif parts[:1] == ["username"]:
                staged.setdefault(parts[1], None)
            elif parts[:2] == ["no", "username"]:
                if not device.fail.get("ignore_revoke"):
                    staged.pop(parts[2], None)
            elif line == "commit":
                device.users = staged
            elif line.startswith("commit timer "):
                device.pending_restore, device.users = dict(device.users), staged
        return ""

    def close(self):
        pass


def served(session):
    artifact = session.artifacts.get(state=models.BootstrapArtifactState.ACTIVE)
    decision = artifacts.authorize(f"/ztp/v1/{artifact.artifact_id}/{artifact.filename}", session.reserved_address, "HTTP")
    assert decision.ok, decision.code
    artifacts.record(decision, client_address=session.reserved_address, transport="HTTP", outcome="SERVED", bytes_sent=len(decision.content))
    session.refresh_from_db()
    return session


class BcredMixin(Z.ZtpTestMixin):
    def setUp(self):
        super().setUp()
        session = served(self.discovered())
        assert workflow.contact_management(session, actor=L.OPERATOR, observe=lambda address: L.HOST_KEY).ok
        session.refresh_from_db()
        assert workflow.enroll_host_key(session, fingerprint=L.HOST_KEY, actor=L.APPROVER, basis="console show management ssh hostkey").ok
        session.refresh_from_db()
        result = workflow.verify_management(session, actor="erin", run=Z.fake_run(Z.eos_outputs(session), L.HOST_KEY))
        assert result.ok, result.codes
        self.session = workflow.get_session(session.session_id)
        self.device = self.session.device
        blob = self.session.enrollment_public_key.split()[1]
        self.keys = FakeKeys(blob)
        self.eos = FakeEos(L.HOST_KEY, blob)
        self.credential = self.service_credential()

    def service_credential(self, username="nmas-svc", **overrides):
        fields = dict(device_name=self.device.name, platform="arista_ceos", username=username, account_kind=models.AccountKind.SERVICE,
                      auth_method=models.DeviceAuthMethod.PUBLICKEY, ssh_key_ref=f"runtime://device-credentials/{username}-key",
                      ssh_public_key=REPLACEMENT_PUBLIC, ssh_public_key_fingerprint=REPLACEMENT_FP)
        fields.update(overrides)
        return models.DeviceCredential.objects.create(**fields)

    def approved(self):
        planned = B.plan(self.device, replacement_credential_id=self.credential.pk, actor=L.OPERATOR, reason="retire bootstrap")
        assert planned.ok, planned.codes
        approved = B.approve(planned.transition, actor=L.APPROVER, digest=planned.transition.binding_digest)
        assert approved.ok, approved.codes
        return approved.transition

    def execute(self, transition, **kwargs):
        transition.refresh_from_db()
        return B.execute(transition, actor="nmas-automation", connect=self.eos.connect, keys=self.keys, **kwargs)

    def secret_present(self):
        return B._bootstrap_secret_present(self.session)

    def approved_management_path(self):
        address = ipaddress.ip_address(self.session.reserved_address)
        network = ipaddress.ip_network(f"{address}/30", strict=False)
        source = next(str(ip) for ip in network.hosts() if ip != address)
        attachment = models.NmasManagementAttachment.objects.create(
            name="nmas-test", host_interface="nmas-test0", upstream_device=self.device.name, source_address=source,
            network=str(network), failure_domain="test-a", created_by=L.OPERATOR,
            approval_state=models.ManagementApproval.APPROVED, verification_state=models.AttachmentVerification.VERIFIED)
        return models.ManagementPath.objects.create(
            device=self.device, path_type=models.ManagementPathType.ROUTED_VRF, preference_class=3,
            vrf="MGMT", endpoint_address=self.session.reserved_address, nmas_attachment=attachment,
            credential_source=models.ManagementCredentialSource.DEVICE_CREDENTIAL, device_credential=self.credential,
            expected_host_key=self.session.enrolled_host_key, approval_state=models.ManagementApproval.APPROVED,
            created_by=L.OPERATOR)

    def selected_management_path(self):
        path = self.approved_management_path()
        models.ManagementPath.objects.filter(pk=path.pk).update(is_active=True, health_state=models.ManagementPathHealth.HEALTHY)
        state = models.DeviceManagementState(device=self.device, status=models.ManagementStatus.ACTIVE, active_path=path)
        state._selector_write = True
        state.save()
        path.refresh_from_db()
        return path


class PlanTests(BcredMixin, TestCase):
    def test_plan_on_selected_replacement_path(self):
        path = self.selected_management_path()
        self.assertEqual(B.plan(self.device, replacement_credential_id=self.credential.pk, actor=L.OPERATOR).codes,
                         ["MGMT_NO_USABLE_PATH"])
        result = B.plan(self.device, replacement_credential_id=self.credential.pk, path_id=path.pk, actor=L.OPERATOR)
        self.assertTrue(result.ok, result.codes)
        self.assertEqual(result.transition.path_id, path.pk)

    def test_plan_without_selected_path_refused_after_approval(self):
        self.approved_management_path()
        result = B.plan(self.device, replacement_credential_id=self.credential.pk, actor=L.OPERATOR)
        self.assertEqual(result.codes, ["MGMT_NO_USABLE_PATH"])
        self.assertFalse(models.BootstrapCredentialTransition.objects.filter(device=self.device).exists())

    def test_plan_and_approve_bound_to_digest(self):
        planned = B.plan(self.device, replacement_credential_id=self.credential.pk, actor=L.OPERATOR)
        self.assertTrue(planned.ok, planned.codes)
        row = planned.transition
        self.assertEqual((row.state, row.bootstrap_username, row.replacement_username), (S.PLANNED, "nmas-enroll", "nmas-svc"))
        self.assertEqual(row.bootstrap_key_fingerprint, self.session.enrollment_key_fingerprint)
        self.assertNotIn("PRIVATE", json.dumps(B.status(row)))
        approved = B.approve(row, actor=L.APPROVER, digest=row.binding_digest)
        self.assertTrue(approved.ok, approved.codes)
        self.assertEqual(approved.transition.state, S.APPROVED)

    def test_plan_human_or_password_credential_refused(self):
        human = self.service_credential("alice", account_kind=models.AccountKind.HUMAN, auth_method=models.DeviceAuthMethod.PASSWORD_AND_TOTP,
                                        ssh_key_ref="", ssh_public_key="", ssh_public_key_fingerprint="")
        self.assertEqual(B.plan(self.device, replacement_credential_id=human.pk, actor=L.OPERATOR).codes, ["BCRED_REPLACEMENT_HUMAN"])
        password = self.service_credential("pwsvc", auth_method=models.DeviceAuthMethod.PASSWORD, secret_ref="runtime://device-credentials/pwsvc",
                                           ssh_key_ref="", ssh_public_key="", ssh_public_key_fingerprint="")
        self.assertEqual(B.plan(self.device, replacement_credential_id=password.pk, actor=L.OPERATOR).codes, ["BCRED_REPLACEMENT_INVALID"])
        other = models.DeviceCredential.objects.create(device_name="OTHER1", platform="arista_ceos", username="nmas-svc",
                                                       account_kind=models.AccountKind.SERVICE, auth_method=models.DeviceAuthMethod.PUBLICKEY,
                                                       ssh_key_ref="runtime://device-credentials/other-key", ssh_public_key=REPLACEMENT_PUBLIC,
                                                       ssh_public_key_fingerprint=REPLACEMENT_FP)
        self.assertEqual(B.plan(self.device, replacement_credential_id=other.pk, actor=L.OPERATOR).codes, ["BCRED_REPLACEMENT_INVALID"])

    def test_plan_reserved_username_refused(self):
        reserved = self.service_credential("admin")
        self.assertEqual(B.plan(self.device, replacement_credential_id=reserved.pk, actor=L.OPERATOR).codes, ["BCRED_RESERVED_USERNAME"])

    def test_plan_without_bootstrap_secret_refused(self):
        provider = ztp_management.secret_provider()
        provider.retire(self.session.enrollment_key_ref, provider.current(self.session.enrollment_key_ref).version)
        self.assertEqual(B.plan(self.device, replacement_credential_id=self.credential.pk, actor=L.OPERATOR).codes, ["BCRED_NO_BOOTSTRAP"])

    def test_plan_other_platform_not_implemented(self):
        self.device.platform = models.Platform.NOKIA_SRLINUX          # in memory only: the field is immutable
        self.assertEqual(B.plan(self.device, replacement_credential_id=self.credential.pk, actor=L.OPERATOR).codes,
                         ["BCRED_PLATFORM_NOT_IMPLEMENTED"])

    def test_plan_second_open_transition_refused(self):
        self.assertTrue(B.plan(self.device, replacement_credential_id=self.credential.pk, actor=L.OPERATOR).ok)
        self.assertEqual(B.plan(self.device, replacement_credential_id=self.credential.pk, actor=L.OPERATOR).codes, ["BCRED_OPEN_EXISTS"])

    def test_approve_self_or_wrong_digest_refused(self):
        row = B.plan(self.device, replacement_credential_id=self.credential.pk, actor=L.OPERATOR).transition
        self.assertEqual(B.approve(row, actor=L.OPERATOR, digest=row.binding_digest).codes, ["BCRED_SELF_APPROVAL"])
        self.assertEqual(B.approve(row, actor=L.APPROVER, digest="0" * 64).codes, ["BCRED_DIGEST_MISMATCH"])

    def test_execute_unapproved_refused_and_nothing_sent(self):
        row = B.plan(self.device, replacement_credential_id=self.credential.pk, actor=L.OPERATOR).transition
        self.assertEqual(self.execute(row).codes, ["BCRED_STATE_INVALID"])
        self.assertEqual(self.eos.connects, [])

    def test_cancel_before_execution_only(self):
        row = self.approved()
        self.assertTrue(B.cancel(row, actor=L.OPERATOR, reason="not now").ok)
        row.refresh_from_db()
        self.assertEqual(row.state, S.CANCELLED)
        self.assertEqual(B.cancel(row, actor=L.OPERATOR, reason="again").codes, ["BCRED_STATE_INVALID"])


class ExecuteTests(BcredMixin, TestCase):
    def test_execute_selected_replacement_path_retires_bootstrap(self):
        path = self.selected_management_path()
        planned = B.plan(self.device, replacement_credential_id=self.credential.pk, path_id=path.pk, actor=L.OPERATOR)
        self.assertTrue(planned.ok, planned.codes)
        row = B.approve(planned.transition, actor=L.APPROVER, digest=planned.transition.binding_digest).transition
        result = self.execute(row)
        self.assertTrue(result.ok, result.codes)
        self.assertEqual(row.path_id, path.pk)
        self.assertFalse(self.secret_present())

    def test_execute_refuses_changed_selected_path_before_authentication(self):
        path = self.selected_management_path()
        row = B.plan(self.device, replacement_credential_id=self.credential.pk, path_id=path.pk, actor=L.OPERATOR).transition
        self.assertTrue(B.approve(row, actor=L.APPROVER, digest=row.binding_digest).ok)
        state = models.DeviceManagementState.objects.get(device=self.device)
        state.reconciliation_required = True
        state._selector_write = True
        state.save()
        result = self.execute(row)
        self.assertEqual(result.codes, ["MGMT_RECONCILIATION_REQUIRED"])
        self.assertEqual(self.eos.connects, [])
        self.assertTrue(self.secret_present())

    def test_execute_legacy_transition_refused_when_approved_path_appears(self):
        row = self.approved()
        self.approved_management_path()
        result = self.execute(row)
        self.assertEqual(result.codes, ["MGMT_NO_USABLE_PATH"])
        self.assertEqual(self.eos.connects, [])
        self.assertTrue(self.secret_present())

    def test_execute_full_transition_complete_only_after_proof(self):
        row = self.approved()
        result = self.execute(row)
        self.assertTrue(result.ok, result.codes)
        row.refresh_from_db()
        self.assertEqual(row.state, S.COMPLETE)
        self.assertNotIn("nmas-enroll", self.eos.users)
        self.assertEqual(self.eos.users["nmas-svc"], REPLACEMENT_PUBLIC.split()[1])
        self.assertIsNone(self.eos.pending_restore)                    # the timed commit was confirmed
        self.assertFalse(self.secret_present())                       # retired from the provider, proven absent
        self.assertEqual([s["step"] for s in row.steps],
                         ["execution_started", "preflight", "before_install", "install", "verify_replacement",
                          "before_revoke", "revoke", "confirm_revocation", "retire_secret"])
        # the unusable password sent to the device appears in no record
        password = next(line.split("secret ", 1)[1] for batch in self.eos.sent for line in batch if " secret " in line)
        stored = json.dumps([row.steps, row.failure, list(self.device.lifecycle_events.values_list("evidence", flat=True))], default=str)
        self.assertNotIn(password, stored)
        actions = list(self.device.lifecycle_events.values_list("action", flat=True))
        self.assertIn("BCRED_COMPLETE", actions)

    def test_execute_install_rejected_uncertain_then_reconciled_and_resumed(self):
        row = self.approved()
        self.eos.fail["reject_next"] = True
        result = self.execute(row)
        self.assertEqual(result.codes, ["BCRED_INSTALL_FAILED"])
        row.refresh_from_db()
        self.assertEqual(row.state, S.UNCERTAIN)
        self.assertIn("nmas-enroll", self.eos.users)                  # bootstrap untouched
        self.assertTrue(self.execute(row).ok)                          # reconcile proves bootstrap intact -> install again
        row.refresh_from_db()
        self.assertEqual(row.state, S.COMPLETE)

    def test_execute_replacement_unverified_removed_and_failed_bootstrap_intact(self):
        row = self.approved()
        self.eos.fail["corrupt_key"] = True
        result = self.execute(row)
        self.assertEqual(result.codes, ["BCRED_REPLACEMENT_UNVERIFIED"])
        row.refresh_from_db()
        self.assertEqual(row.state, S.FAILED)
        self.assertNotIn("nmas-svc", self.eos.users)
        self.assertIn("nmas-enroll", self.eos.users)
        self.assertTrue(self.secret_present())

    def test_execute_bootstrap_still_accepted_never_confirmed_not_complete(self):
        row = self.approved()
        self.eos.fail["phantom_bootstrap"] = True
        result = self.execute(row)
        self.assertEqual(result.codes, ["BCRED_BOOTSTRAP_STILL_ACCEPTED"])
        row.refresh_from_db()
        self.assertEqual(row.state, S.REVOCATION_PENDING)
        self.assertIsNotNone(self.eos.pending_restore)                 # not confirmed: the device will restore by itself
        self.assertTrue(self.secret_present())                         # the secret is NOT retired without proof
        self.eos.expire_timer()
        self.assertIn("nmas-enroll", self.eos.users)

    def test_execute_revocation_ignored_not_complete(self):
        row = self.approved()
        self.eos.fail["ignore_revoke"] = True
        self.assertEqual(self.execute(row).codes, ["BCRED_REVOCATION_FAILED"])
        row.refresh_from_db()
        self.assertNotEqual(row.state, S.COMPLETE)
        self.assertTrue(self.secret_present())
        # the uncommitted revoke session is aborted so a half-run revocation cannot be committed later
        self.assertEqual(self.eos.sent[-1], [f"configure session nmas-bcred-{row.pk}-{row.binding_digest[:8]}-revoke abort"])
        self.assertEqual(row.steps[-1]["facts"]["uncommitted_session"], "ABORTED")
        self.assertIsNone(self.eos.pending_restore)
        self.assertIn("nmas-enroll", self.eos.users)

    def test_execute_host_key_mismatch_preflight_failed_nothing_sent(self):
        row = self.approved()
        self.eos.host_key = "SHA256:" + "Z" * 43
        self.assertEqual(self.execute(row).codes, ["BCRED_PREFLIGHT_FAILED"])
        row.refresh_from_db()
        self.assertEqual((row.state, self.eos.sent), (S.FAILED, []))

    def test_execute_retirement_failure_stays_pending_then_resumes(self):
        from modules.device_credentials import SecretProviderError

        class Broken:
            def current(self, reference):
                return ztp_management.secret_provider().current(reference)

            def retire(self, reference, version):
                raise SecretProviderError("locked")

        row = self.approved()
        self.assertEqual(self.execute(row, provider=Broken()).codes, ["BCRED_RETIREMENT_FAILED"])
        row.refresh_from_db()
        self.assertEqual(row.state, S.RETIREMENT_PENDING)
        self.assertNotIn("nmas-enroll", self.eos.users)               # revoked and proven; only the secret remains
        self.assertTrue(self.execute(row).ok)
        row.refresh_from_db()
        self.assertEqual(row.state, S.COMPLETE)

    def test_in_flight_reports_bootstrap_credential_while_installing(self):
        row = self.approved()
        models.BootstrapCredentialTransition.objects.filter(pk=row.pk).update(state=S.REPLACEMENT_INSTALLED)
        self.assertEqual(selector.in_flight(self.device)["kind"], "BOOTSTRAP_CREDENTIAL")

    def test_execute_while_execution_lock_held_refused(self):
        row = self.approved()
        with self.settings():
            from unittest import mock

            with mock.patch.object(models.ExecutionDeviceLock.objects, "filter") as locked:
                locked.return_value.exists.return_value = True
                self.assertEqual(self.execute(row).codes, ["MGMT_EXECUTION_IN_FLIGHT"])
        self.assertEqual(self.eos.connects, [])


class ConcurrentRetirementTests(BcredMixin, TestCase):
    def test_competing_retirement_is_refused_before_device_io(self):
        from unittest import mock

        transition = self.approved()
        original, attempted, nested = _Cli.configure, [], []

        def losing_connect(**_kwargs):
            attempted.append("device I/O")
            raise ssh.CliError("UNREACHABLE")

        def inject(cli, lines):
            if not nested:
                fresh = models.BootstrapCredentialTransition.objects.get(pk=transition.pk)
                nested.append(B.execute(fresh, actor="other-worker", connect=losing_connect, keys=self.keys))
            return original(cli, lines)

        with mock.patch.object(_Cli, "configure", inject):
            self.assertTrue(self.execute(transition).ok)
        self.assertEqual(attempted, [])
        self.assertEqual(nested[0].codes, ["MGMT_EXECUTION_IN_FLIGHT"])

    def test_change_and_maintenance_lock_acquisition_cannot_overlap_retirement(self):
        from unittest import mock
        from core.services.execution import locking
        from core.services.maintenance_mode import service as maintenance

        transition = self.approved()
        original, checked = _Cli.configure, []

        def inject(cli, lines):
            if not checked:
                checked.append(True)
                self.assertEqual(selector.in_flight(self.device)["kind"], "BOOTSTRAP_CREDENTIAL")
                with self.assertRaises(locking.LockRefused) as caught:
                    locking.acquire(change=None, plan=None, precheck_run=None, mode="FULL", actor="other-worker",
                                    scope=None, devices=[self.device.name])
                self.assertEqual(caught.exception.code, "DEVICE_LOCKED")
                findings = maintenance._lock(None, [self.device.name])
                self.assertEqual([f.code for f in findings], ["DEVICE_LOCKED"])
            return original(cli, lines)

        with mock.patch.object(_Cli, "configure", inject):
            self.assertTrue(self.execute(transition).ok)
        self.assertTrue(checked)
        self.assertFalse(models.ExecutionDeviceLock.objects.filter(device=self.device.name).exists())
        self.assertFalse(self.device.lifecycle_events.filter(action="BCRED_FAILED").exists())
        before = self.device.lifecycle_events.filter(action="BCRED_STEP", evidence__step="before_install").get()
        self.assertEqual((before.actor, before.actor_kind), ("nmas-automation", "AUTOMATION"))

    def test_started_retirement_cannot_be_cancelled_during_preflight(self):
        transition, attempts = self.approved(), []

        def connect(**kwargs):
            if not attempts:
                fresh = models.BootstrapCredentialTransition.objects.get(pk=transition.pk)
                attempts.append(B.cancel(fresh, actor=L.APPROVER, reason="competing cancellation"))
            return self.eos.connect(**kwargs)

        self.assertTrue(B.execute(transition, actor="worker", connect=connect, keys=self.keys).ok)
        self.assertEqual(attempts[0].codes, ["BCRED_STATE_INVALID"])

    def test_accepted_write_then_worker_crash_reconciles_without_install_replay(self):
        from unittest import mock
        from core.services.execution.device_mutex import DeviceBusy, DeviceMutex

        transition = self.approved()
        original = _Cli.configure

        def crash_after_write(cli, lines):
            original(cli, lines)
            raise RuntimeError("worker lost after device accepted the write")

        with mock.patch.object(_Cli, "configure", crash_after_write):
            with self.assertRaises(RuntimeError):
                self.execute(transition)
        transition.refresh_from_db()
        self.assertEqual(transition.state, S.UNCERTAIN)
        self.assertEqual(transition.steps[-1]["step"], "before_install")
        with self.assertRaises(DeviceBusy):
            DeviceMutex([self.device.name]).__enter__()
        self.assertTrue(self.execute(transition).ok)
        self.assertEqual(sum(any("ssh-key" in line for line in lines) for lines in self.eos.sent), 1)
