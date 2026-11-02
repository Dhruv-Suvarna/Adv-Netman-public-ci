from __future__ import annotations

import inspect
import io
import json
import sys
import tempfile
import traceback
from datetime import timedelta
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parents[3]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from django.core.management import call_command
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from modules.device_credentials import FileSecretProvider, SecretProviderError, make_reference

from core.models import (
    AccountKind,
    CredentialRotationPhase,
    CredentialRotationRun,
    CredentialStatus,
    DeviceAuthMethod,
    DeviceCredential,
    DeviceLoginMfaPolicy,
    RotationTrigger,
)
from core.services.credentials import passwords, policy
from core.services.credentials.ceos_transaction import (
    CeosOperationalValidationFailed,
    CeosRotationTransactionController,
    SafeDeviceTransaction,
)
from core.services.credentials.engine import (
    RECOVERY_RETRY_DELAY,
    _claim,
    reconcile_credential,
    rotate_credential,
    rotate_due_credentials,
)
from core.services.credentials.platforms import (
    CeosPasswordAdapter,
    CredentialAuthenticationRejected,
    DeviceChangeRejected,
    DeviceChangeUncertain,
    NewLoginVerificationFailed,
    OldCredentialStillAccepted,
    OperationalValidationFailed,
    PersistenceFailed,
    PlatformNotImplemented,
    ceos_password_command,
)


FAKE_SECRET = "TEST_ONLY_ROTATION_SECRET_NEVER_REAL"
OLD_SECRET = "old-test-credential-value"
NEW_SECRET = "new-test-credential-value"


TX = SafeDeviceTransaction(
    session_name="NMAS-CR-R1-0123456789",
    checkpoint_file="flash:nmas-credrot-r1-0123456789.cfg",
    checkpoint_sha256="a" * 64,
    checkpoint_md5="b" * 32,
    pre_change_digest="c" * 64,
    post_change_digest="d" * 64,
    commit_timer="00:10:00",
    baseline={"other_identities": {"R2": ["nmas-automation", "admin"]}},
)


class FakeSafeAdapter:
    """Stateful EOS transaction model; values never leave this test object."""

    def __init__(
        self, *, arm_error=None, verify_error=None, old_error=None,
        validation_error=None, confirmation_error=None, persistence_error=None,
    ):
        self.arm_error = arm_error
        self.verify_error = verify_error
        self.old_error = old_error
        self.validation_error = validation_error
        self.confirmation_error = confirmation_error
        self.persistence_error = persistence_error
        self.device_password = OLD_SECRET
        self.startup_password = OLD_SECRET
        self.previous_password = OLD_SECRET
        self.timer_pending = False
        self.changed = []
        self.verified = []
        self.old_probes = []
        self.calls = []

    def preflight(self, credential):
        self.calls.append("preflight")

    def arm_transaction(self, credential, current, replacement, run_id):
        self.calls.append("arm")
        self.changed.append((credential.device_name, current, replacement))
        if self.arm_error:
            raise self.arm_error
        self.previous_password = current
        self.device_password = replacement
        self.timer_pending = True
        return TX

    def verify_password(self, credential, replacement):
        self.calls.append("verify_new")
        self.verified.append((credential.device_name, replacement))
        if self.verify_error:
            raise self.verify_error
        if replacement != self.device_password:
            raise NewLoginVerificationFailed()

    def verify_old_rejected(self, credential, previous):
        self.calls.append("verify_old")
        self.old_probes.append((credential.device_name, previous))
        if self.old_error:
            raise self.old_error
        if previous == self.device_password:
            raise OldCredentialStillAccepted()

    def operational_validate(self, credential, transaction, **kwargs):
        self.calls.append("validate")
        if self.validation_error:
            raise self.validation_error
        return {"passed": True, "checks": {"health": True, "nsot": True, "config_retrieval": True}}

    def confirm_transaction(self, credential, transaction):
        self.calls.append("confirm")
        if self.confirmation_error:
            raise self.confirmation_error
        self.timer_pending = False
        return transaction.post_change_digest

    def persist_transaction(self, credential, transaction):
        self.calls.append("persist")
        if self.persistence_error:
            raise self.persistence_error
        self.startup_password = self.device_password
        return {"running_digest": transaction.post_change_digest, "startup_matches_running": True, "no_open_sessions": True}

    def probe_password(self, credential, candidate):
        return "ACCEPT" if candidate == self.device_password else "REJECT"

    def inspect_recovery(self, credential, transaction):
        return {
            "timer_pending": self.timer_pending,
            "pre_change_matches": self.device_password == self.previous_password,
            "post_change_matches": self.device_password != self.previous_password,
            "startup_matches_running": self.startup_password == self.device_password,
            "no_open_sessions": not self.timer_pending,
            "running_digest": transaction.post_change_digest if self.device_password != self.previous_password else transaction.pre_change_digest,
        }

    def complete_recovery(self, credential, transaction):
        self.calls.append("complete_recovery")
        if self.validation_error:
            raise self.validation_error
        self.startup_password = self.device_password
        return {
            "validation": {"passed": True},
            "persistence": {"startup_matches_running": True, "no_open_sessions": True},
        }

    def expire_timer(self):
        if self.timer_pending:
            self.device_password = self.previous_password
            self.timer_pending = False


class FailOncePromoteProvider(FileSecretProvider):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.failures = 1

    def promote(self, reference, version):
        if self.failures:
            self.failures -= 1
            raise SecretProviderError("synthetic provider failure")
        return super().promote(reference, version)


class RotationFixtures:
    def setUp(self):
        DeviceCredential.objects.all().delete()
        self.temp = tempfile.TemporaryDirectory()
        self.store = Path(self.temp.name) / "device-credentials.json"

    def tearDown(self):
        self.temp.cleanup()

    def credential(self, *, device="R1", ref_key="r1-dedicated", enabled=True, due=True, status=CredentialStatus.NEVER):
        now = timezone.now()
        return DeviceCredential.objects.create(
            device_name=device, platform="arista_ceos", username="nmas-rotation",
            auth_method="PASSWORD", secret_ref=make_reference(ref_key),
            account_role="network-admin", privilege_level=15,
            rotation_enabled=enabled, rotation_interval_days=90,
            next_due_at=(now - timedelta(minutes=1)) if due else (now + timedelta(days=1)),
            last_status=status,
        )

    def provider_for(self, credential, cls=FileSecretProvider):
        provider = cls(self.store)
        provider.initialize(credential.secret_ref, OLD_SECRET)
        return provider


class CredentialRotationTests(RotationFixtures, TestCase):
    def test_successful_safe_ceos_transaction_has_required_order_and_evidence(self):
        credential = self.credential()
        provider = self.provider_for(credential)
        adapter = FakeSafeAdapter()
        outcome = rotate_credential(credential.pk, provider=provider, adapter=adapter, password_factory=lambda: NEW_SECRET)
        credential.refresh_from_db()
        run = CredentialRotationRun.objects.get()

        self.assertEqual((outcome.status, outcome.code), (CredentialStatus.SUCCESS, "ROTATION_SUCCESS"))
        self.assertEqual(adapter.calls, ["preflight", "arm", "verify_new", "verify_old", "validate", "confirm", "persist"])
        self.assertEqual(provider.current(credential.secret_ref).value, NEW_SECRET)
        self.assertFalse(provider.has_pending(credential.secret_ref))
        self.assertEqual(adapter.startup_password, NEW_SECRET)
        self.assertEqual(run.phase, CredentialRotationPhase.COMPLETE)
        self.assertEqual(run.old_login_verification_result, "REJECTED")
        self.assertEqual(run.operational_validation_result, "SUCCESS")
        self.assertEqual(run.transaction_confirmation_result, "SUCCESS")
        self.assertEqual(run.startup_verification_result, "SUCCESS")
        self.assertEqual(run.provider_promotion_result, "SUCCESS")
        self.assertEqual(run.session_name, TX.session_name)
        self.assertGreater(credential.next_due_at, credential.last_rotated_at)

    def test_pending_staged_but_device_command_rejected_discards_pending(self):
        credential = self.credential()
        provider = self.provider_for(credential)
        adapter = FakeSafeAdapter(arm_error=DeviceChangeRejected())
        outcome = rotate_credential(credential.pk, provider=provider, adapter=adapter, password_factory=lambda: NEW_SECRET)
        credential.refresh_from_db()
        self.assertEqual(outcome.status, CredentialStatus.FAILED)
        self.assertEqual([m.value for m in provider.candidates(credential.secret_ref)], [OLD_SECRET])
        self.assertEqual(adapter.device_password, OLD_SECRET)
        self.assertGreater(credential.next_due_at, timezone.now())

    def test_replacement_must_be_distinct_before_provider_or_device_mutation(self):
        credential = self.credential()
        provider = self.provider_for(credential)
        adapter = FakeSafeAdapter()
        outcome = rotate_credential(
            credential.pk, provider=provider, adapter=adapter,
            password_factory=lambda: OLD_SECRET,
        )
        credential.refresh_from_db()
        self.assertEqual((outcome.status, outcome.code), (CredentialStatus.FAILED, "REPLACEMENT_NOT_DISTINCT"))
        self.assertFalse(provider.has_pending(credential.secret_ref))
        self.assertEqual(adapter.calls, ["preflight"])
        self.assertGreater(credential.next_due_at, timezone.now())

    def test_device_changed_but_new_login_failure_keeps_both_and_timer(self):
        credential = self.credential()
        provider = self.provider_for(credential)
        adapter = FakeSafeAdapter(verify_error=NewLoginVerificationFailed())
        outcome = rotate_credential(credential.pk, provider=provider, adapter=adapter, password_factory=lambda: NEW_SECRET)
        self.assertEqual(outcome.status, CredentialStatus.UNCERTAIN)
        self.assertTrue(adapter.timer_pending)
        self.assertEqual([m.value for m in provider.candidates(credential.secret_ref)], [OLD_SECRET, NEW_SECRET])

    def test_new_login_passes_but_old_still_authenticates_never_confirms(self):
        credential = self.credential()
        provider = self.provider_for(credential)
        adapter = FakeSafeAdapter(old_error=OldCredentialStillAccepted())
        outcome = rotate_credential(credential.pk, provider=provider, adapter=adapter, password_factory=lambda: NEW_SECRET)
        run = CredentialRotationRun.objects.get()
        self.assertEqual((outcome.status, outcome.code), (CredentialStatus.UNCERTAIN, "OLD_CREDENTIAL_STILL_ACCEPTED"))
        self.assertTrue(adapter.timer_pending)
        self.assertNotIn("confirm", adapter.calls)
        self.assertEqual(run.old_login_verification_result, "ACCEPTED")

    def test_health_nsot_and_config_failures_prevent_confirmation(self):
        cases = (
            "HEALTH_VALIDATION_FAILED", "NSOT_VALIDATION_FAILED", "CONFIG_RETRIEVAL_VALIDATION_FAILED",
        )
        for index, code in enumerate(cases):
            with self.subTest(code=code):
                credential = self.credential(device=("R1", "R2", "S1")[index], ref_key=f"validation-{index}")
                provider = self.provider_for(credential)
                error = OperationalValidationFailed(code, evidence={"checks": {code: False}})
                adapter = FakeSafeAdapter(validation_error=error)
                outcome = rotate_credential(credential.pk, provider=provider, adapter=adapter, password_factory=lambda: NEW_SECRET)
                self.assertEqual((outcome.status, outcome.code), (CredentialStatus.UNCERTAIN, code))
                self.assertTrue(adapter.timer_pending)
                self.assertNotIn("confirm", adapter.calls)

    def test_timer_rollback_reconciliation_restores_prior_and_defers_retry(self):
        credential = self.credential()
        provider = self.provider_for(credential)
        adapter = FakeSafeAdapter(verify_error=NewLoginVerificationFailed())
        rotate_credential(credential.pk, provider=provider, adapter=adapter, password_factory=lambda: NEW_SECRET)
        adapter.expire_timer()
        adapter.verify_error = None
        outcome = reconcile_credential(credential.pk, provider=provider, adapter=adapter)
        credential.refresh_from_db()
        self.assertEqual((outcome.status, outcome.code), (CredentialStatus.FAILED, "RECONCILED_PRIOR_STATE_RETAINED"))
        self.assertEqual(provider.current(credential.secret_ref).value, OLD_SECRET)
        self.assertFalse(provider.has_pending(credential.secret_ref))
        self.assertGreaterEqual(credential.next_due_at, timezone.now() + RECOVERY_RETRY_DELAY - timedelta(seconds=5))

    def test_reconcile_refuses_while_commit_timer_is_still_armed(self):
        credential = self.credential()
        provider = self.provider_for(credential)
        adapter = FakeSafeAdapter(verify_error=NewLoginVerificationFailed())
        rotate_credential(credential.pk, provider=provider, adapter=adapter, password_factory=lambda: NEW_SECRET)
        outcome = reconcile_credential(credential.pk, provider=provider, adapter=adapter)
        self.assertEqual((outcome.status, outcome.code), (CredentialStatus.UNCERTAIN, "TIMER_REVERT_PENDING"))
        self.assertTrue(provider.has_pending(credential.secret_ref))

    def test_persistence_failure_never_promotes_provider(self):
        credential = self.credential()
        provider = self.provider_for(credential)
        adapter = FakeSafeAdapter(persistence_error=PersistenceFailed("STARTUP_VERIFICATION_FAILED"))
        outcome = rotate_credential(credential.pk, provider=provider, adapter=adapter, password_factory=lambda: NEW_SECRET)
        run = CredentialRotationRun.objects.get()
        self.assertEqual((outcome.status, outcome.code), (CredentialStatus.UNCERTAIN, "STARTUP_VERIFICATION_FAILED"))
        self.assertEqual(provider.current(credential.secret_ref).value, OLD_SECRET)
        self.assertTrue(provider.has_pending(credential.secret_ref))
        self.assertEqual(run.phase, CredentialRotationPhase.DEVICE_CONFIRMED)
        self.assertEqual(run.provider_promotion_result, "NOT_ATTEMPTED")

    def test_provider_promotion_failure_is_recoverable_after_device_success(self):
        credential = self.credential()
        provider = self.provider_for(credential, FailOncePromoteProvider)
        adapter = FakeSafeAdapter()
        first = rotate_credential(credential.pk, provider=provider, adapter=adapter, password_factory=lambda: NEW_SECRET)
        self.assertEqual((first.status, first.code), (CredentialStatus.UNCERTAIN, "SECRET_FINALIZE_FAILED"))
        self.assertEqual(adapter.startup_password, NEW_SECRET)
        second = reconcile_credential(credential.pk, provider=provider, adapter=adapter)
        self.assertEqual((second.status, second.code), (CredentialStatus.SUCCESS, "RECONCILED_PROMOTED_PENDING"))
        self.assertEqual(provider.current(credential.secret_ref).value, NEW_SECRET)

    def test_post_promotion_crash_reconciliation_finalizes_success_not_failed(self):
        credential = self.credential(status=CredentialStatus.IN_PROGRESS)
        provider = self.provider_for(credential)
        prior, new = provider.stage(credential.secret_ref, NEW_SECRET)
        provider.promote(credential.secret_ref, new)
        adapter = FakeSafeAdapter()
        adapter.device_password = NEW_SECRET
        adapter.startup_password = NEW_SECRET
        adapter.timer_pending = False
        source = CredentialRotationRun.objects.create(
            credential=credential, trigger_reason=RotationTrigger.SCHEDULED, started_at=timezone.now(),
            prior_secret_version=prior, new_secret_version=new,
            phase=CredentialRotationPhase.STARTUP_PERSISTED,
            session_name=TX.session_name, checkpoint_file=TX.checkpoint_file,
            checkpoint_sha256=TX.checkpoint_sha256, checkpoint_md5=TX.checkpoint_md5,
            pre_change_digest=TX.pre_change_digest, post_change_digest=TX.post_change_digest,
            transaction_metadata=TX.metadata(), old_login_verification_result="REJECTED",
            operational_validation_result="SUCCESS", transaction_confirmation_result="SUCCESS",
            persistence_result="SUCCESS", startup_verification_result="SUCCESS",
        )
        self.assertEqual(source.final_status, "STARTED")
        outcome = reconcile_credential(credential.pk, provider=provider, adapter=adapter)
        credential.refresh_from_db()
        self.assertEqual((outcome.status, outcome.code), (CredentialStatus.SUCCESS, "RECONCILED_POST_PROMOTION"))
        self.assertEqual(credential.last_status, CredentialStatus.SUCCESS)
        self.assertIsNotNone(credential.last_rotated_at)

    def test_claim_only_crash_reconciliation_is_safe_and_deferred(self):
        credential = self.credential(status=CredentialStatus.IN_PROGRESS)
        provider = self.provider_for(credential)
        CredentialRotationRun.objects.create(
            credential=credential, trigger_reason=RotationTrigger.SCHEDULED,
            started_at=timezone.now(), phase=CredentialRotationPhase.CLAIMED,
        )
        outcome = reconcile_credential(credential.pk, provider=provider, adapter=FakeSafeAdapter())
        credential.refresh_from_db()
        self.assertEqual((outcome.status, outcome.code), (CredentialStatus.FAILED, "RECONCILED_CLAIM_ONLY"))
        self.assertGreater(credential.next_due_at, timezone.now())
        self.assertEqual(provider.current(credential.secret_ref).value, OLD_SECRET)

    def test_scheduler_and_concurrent_claim_select_only_one_due_credential(self):
        due = self.credential(device="R1", ref_key="due")
        other = self.credential(device="R2", ref_key="later", due=False)
        provider = self.provider_for(due)
        adapter = FakeSafeAdapter()
        outcomes = rotate_due_credentials(
            at=timezone.now(), provider=provider, adapter_factory=lambda credential: adapter,
            password_factory=lambda: NEW_SECRET,
        )
        self.assertEqual([(o.credential_id, o.status) for o in outcomes], [(due.pk, CredentialStatus.SUCCESS)])
        other.refresh_from_db()
        self.assertEqual(other.last_status, CredentialStatus.NEVER)

        claimed = self.credential(device="S1", ref_key="claim")
        self.assertTrue(_claim(claimed.pk, timezone.now()))
        self.assertFalse(_claim(claimed.pk, timezone.now()))

    def test_secret_never_reaches_output_audit_or_traceback(self):
        credential = self.credential()
        provider = self.provider_for(credential)
        error = DeviceChangeUncertain("SYNTHETIC_UNCERTAIN")
        adapter = FakeSafeAdapter(arm_error=error)
        outcome = rotate_credential(credential.pk, provider=provider, adapter=adapter, password_factory=lambda: FAKE_SECRET)
        output = io.StringIO()
        call_command("rotate_due_credentials", "--json", stdout=output)
        run_blob = json.dumps(list(CredentialRotationRun.objects.values()), default=str)
        rendered = "".join(traceback.format_exception(error))
        for surface in (repr(outcome), output.getvalue(), run_blob, rendered):
            self.assertNotIn(FAKE_SECRET, surface)

    def test_model_ui_and_generator_contracts_remain_secret_free(self):
        names = {field.name for field in DeviceCredential._meta.get_fields()}
        self.assertFalse(names & {"password", "secret", "private_key", "token"})
        value = passwords.generate_password()
        self.assertEqual(len(value), 32)
        self.assertTrue(set(value) <= set(passwords.ALPHABET))
        self.assertIn("secrets.choice", inspect.getsource(passwords.generate_password))
        html = self.client.get(reverse("core:credential_status")).content.decode()
        payload = self.client.get(reverse("core:credential_status_json")).content.decode()
        self.assertNotIn(FAKE_SECRET, html + payload)

    def test_shared_reference_is_blocked_before_provider_or_device_access(self):
        first = self.credential(device="R1", ref_key="shared")
        self.credential(device="R2", ref_key="shared", enabled=False)
        adapter = FakeSafeAdapter()
        outcome = rotate_credential(first.pk, provider=mock.Mock(), adapter=adapter, password_factory=lambda: NEW_SECRET)
        self.assertEqual((outcome.status, outcome.code), (CredentialStatus.BLOCKED, "SHARED_SECRET_REF"))
        self.assertEqual(adapter.calls, [])

    def test_unsupported_target_blocks_before_provider_stage(self):
        credential = self.credential()

        class Adapter(FakeSafeAdapter):
            def preflight(self, credential):
                raise PlatformNotImplemented("TARGET_NOT_CONFIGURED")

        provider = self.provider_for(credential)
        outcome = rotate_credential(credential.pk, provider=provider, adapter=Adapter(), password_factory=lambda: NEW_SECRET)
        self.assertEqual((outcome.status, outcome.code), (CredentialStatus.BLOCKED, "TARGET_NOT_CONFIGURED"))
        self.assertFalse(provider.has_pending(credential.secret_ref))

    def test_ceos_command_generation_is_platform_specific(self):
        credential = self.credential()
        self.assertEqual(
            ceos_password_command(credential, NEW_SECRET),
            f"username nmas-rotation privilege 15 role network-admin secret {NEW_SECRET}",
        )
        with self.assertRaises(DeviceChangeRejected):
            ceos_password_command(credential, "unsafe value")

    def test_old_credential_proof_requires_explicit_authentication_rejection(self):
        credential = self.credential()

        class Conn:
            def disconnect(self):
                pass

        def rejected(_target, _username, password, **_kwargs):
            if password == OLD_SECRET:
                raise CredentialAuthenticationRejected()
            return Conn()

        adapter = CeosPasswordAdapter(connection_factory=rejected, transaction_controller=mock.Mock())
        with mock.patch("core.services.nsot_live.get_live_target_metadata", return_value={
            "platform": "ceos", "address": "192.0.2.1", "access_profiles": (),
        }):
            adapter.verify_old_rejected(credential, OLD_SECRET)

        adapter.connection_factory = lambda *_args, **_kwargs: Conn()
        with mock.patch("core.services.nsot_live.get_live_target_metadata", return_value={
            "platform": "ceos", "address": "192.0.2.1", "access_profiles": (),
        }):
            with self.assertRaises(OldCredentialStillAccepted) as caught:
                adapter.verify_old_rejected(credential, OLD_SECRET)
        self.assertNotIn(OLD_SECRET, "".join(traceback.format_exception(caught.exception)))


class CeosTransactionControllerTests(TestCase):
    """Live-like in-memory EOS test: no container, production provider or DB row is touched."""

    def test_timer_change_failure_and_automatic_revert_then_successful_persist(self):
        from core.tests.test_r1_mfa_pilot import FakeEos, _hash
        from core.services.credentials import r1_pilot as eos

        config = """! Command: show running-config
hostname R1
username nmas-automation privilege 15 role network-admin secret sha512 {old_hash}
interface Vlan200
   ip address 192.168.200.1/24
end""".format(old_hash=_hash(OLD_SECRET))
        fake = FakeEos(config)
        original = list(fake.running)
        credential = DeviceCredential.objects.create(
            device_name="R1", platform="arista_ceos", username="nmas-automation",
            secret_ref=make_reference("r1-transaction-test"), account_role="network-admin", privilege_level=15,
        )
        controller = CeosRotationTransactionController(
            transport_factory=lambda target: eos.EosCliTransport(container=target.container, runner=fake),
            read_paths=lambda device: {}, reachable=lambda address: True,
        )
        command = ceos_password_command(credential, NEW_SECRET)
        tx = controller.arm(credential, command, OLD_SECRET, NEW_SECRET, "0123456789abcdef0123456789abcdef")
        armed = controller.inspect(credential, tx)
        self.assertTrue(armed["timer_pending"])
        self.assertTrue(armed["post_change_matches"])
        self.assertNotEqual(fake.running, original)

        fake.expire_timer(original)
        reverted = controller.inspect(credential, tx)
        self.assertFalse(reverted["timer_pending"])
        self.assertTrue(reverted["pre_change_matches"])
        self.assertEqual(fake.running, original)

        tx = controller.arm(credential, command, OLD_SECRET, NEW_SECRET, "fedcba9876543210fedcba9876543210")
        controller.read_paths = lambda device: {
            "health": True, "health_blocking": [], "health_status": "HEALTHY",
            "health_tolerated_warnings": [], "nsot": True, "config_retrieval": True,
            "target_identities": ["nmas-automation", "admin"],
            "other_identities": tx.baseline["other_identities"],
        }
        validation = controller.validate(
            credential, tx, new_verified=True, old_rejected=True, expect_timer=True,
        )
        self.assertTrue(validation["passed"])

        controller.read_paths = lambda device: {
            "health": True, "health_blocking": [], "health_status": "DEGRADED",
            "health_tolerated_warnings": [{"check_code": "CRITICAL_EVENTS_RECENT"}],
            "nsot": True, "config_retrieval": True,
            "target_identities": ["nmas-automation", "admin"],
            "other_identities": tx.baseline["other_identities"],
        }
        self.assertTrue(controller.validate(
            credential, tx, new_verified=True, old_rejected=True, expect_timer=True,
        )["passed"])
        controller.read_paths = lambda device: {
            "health": True, "health_blocking": [], "health_status": "DEGRADED",
            "health_tolerated_warnings": [{"check_code": "CPU_HIGH"}],
            "nsot": True, "config_retrieval": True,
            "target_identities": ["nmas-automation", "admin"],
            "other_identities": tx.baseline["other_identities"],
        }
        with self.assertRaisesRegex(CeosOperationalValidationFailed, "HEALTH_VALIDATION_FAILED"):
            controller.validate(
                credential, tx, new_verified=True, old_rejected=True, expect_timer=True,
            )

        controller.read_paths = lambda device: {
            "health": True, "health_blocking": [], "health_status": "HEALTHY",
            "health_tolerated_warnings": [], "nsot": True, "config_retrieval": True,
            "target_identities": ["nmas-automation", "admin"],
            "other_identities": tx.baseline["other_identities"],
        }
        controller.confirm(credential, tx)
        persisted = controller.persist(credential, tx)
        self.assertTrue(persisted["startup_matches_running"])
        self.assertFalse(controller.inspect(credential, tx)["timer_pending"])

        # Secret-bearing EOS command traveled only in stdin, never argv/env/output.
        secret_calls = [call for call in fake.calls if NEW_SECRET in str(call.get("input") or "")]
        self.assertTrue(secret_calls)
        for call in secret_calls:
            self.assertNotIn(NEW_SECRET, " ".join(call["argv"]))
            self.assertNotIn(NEW_SECRET, "\n".join(call["env"].values()))


class ModelGuardTests(TestCase):
    def test_model_guards_for_factor_ownership(self):
        base = dict(device_name="R1", platform="arista_ceos", username="ops-alice", secret_ref="")
        with self.assertRaises(ValueError):
            DeviceCredential(**base, account_kind=AccountKind.HUMAN, ssh_key_ref=make_reference("alice-key")).save()
        with self.assertRaises(ValueError):
            DeviceCredential(**base, account_kind=AccountKind.HUMAN, auth_method=DeviceAuthMethod.PUBLICKEY_AND_PASSWORD).save()
        with self.assertRaises(ValueError):
            DeviceCredential(**base, account_kind=AccountKind.HUMAN, rotation_enabled=True, next_due_at=timezone.now()).save()


class SeededScopeTests(TestCase):
    def test_seed_contains_references_only_and_nothing_is_rotation_enabled(self):
        rows = list(DeviceCredential.objects.all())
        self.assertEqual({r.device_name for r in rows}, {"R1", "R2", "R3", "R4", "R5", "S1", "S2", "S3", "S4", "mgmt_swt"})
        self.assertFalse(any(r.rotation_enabled for r in rows))
        self.assertTrue(all(r.secret_ref.startswith("runtime://device-credentials/") for r in rows))

    def test_r5_and_linux_scope_remain_blocked(self):
        self.assertEqual(DeviceCredential.objects.get(device_name="R5").last_status, CredentialStatus.BLOCKED)
        self.assertEqual(DeviceCredential.objects.get(device_name="R3").last_result_code, "ROOT_ACCOUNT_OUT_OF_SCOPE")

    def test_mfa_policy_seed_is_unchanged(self):
        policies = list(DeviceLoginMfaPolicy.objects.all())
        self.assertEqual(len(policies), 10)
        self.assertTrue(all(p.required for p in policies))
