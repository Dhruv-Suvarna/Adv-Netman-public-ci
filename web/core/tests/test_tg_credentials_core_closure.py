"""Lab 7 closure -- device-credential core: the protected secret provider's pending path, rotation scheduling policy,
password generation bounds, SSH-key / MFA candidate helpers and the offline TOTP contract, each called directly.

Secrets live in a private temporary store; every value used here is fake.  No device is contacted and nothing is
printed.  POSITIVE: the exact pending material, due dates and selections, key parse / fingerprint, the reviewed
candidate text and accepted factor combinations.  NEGATIVE: a missing or conflicting pending version, a disabled /
blocked / future credential, out-of-range lengths, malformed or private keys, foreign devices, unprotected references,
and every incomplete factor combination are refused -- and no secret value appears in an error.
"""

from __future__ import annotations

import tempfile
from datetime import timedelta
from pathlib import Path
from types import SimpleNamespace

from django.test import SimpleTestCase, TestCase
from django.utils import timezone

from core.models import AccountKind, CredentialStatus, DeviceAuthMethod, DeviceCredential
from core.services import credential_service
from core.services.credentials import engine, mfa, passwords, policy, totp_contract as tc
from modules.device_credentials import FileSecretProvider, SecretConflict, SecretNotFound, SecretProviderError, load_password_candidates, \
    load_ssh_private_key, make_reference, ssh_auth_kwargs

OLD, NEW = "Old-fake-device-password-0001", "New-fake-device-password-0002"
REF = make_reference("tg-closure")


class ProviderTests(SimpleTestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.store = Path(self.temp.name) / "device-credentials.json"
        self.provider = FileSecretProvider(self.store)
        self.provider.initialize(REF, OLD)

    def test_pending_returns_the_staged_replacement_and_discard_removes_it(self):
        _current, version = self.provider.stage(REF, NEW)
        self.assertEqual((self.provider.pending(REF).value, self.provider.pending(REF, version).version), (NEW, version))
        self.assertEqual(load_password_candidates(REF, path=self.store), (OLD, NEW))
        self.provider.discard_pending(REF, version)
        self.assertEqual((self.provider.has_pending(REF), load_password_candidates(REF, path=self.store)), (False, (OLD,)))

    def test_pending_and_discard_refuse_a_missing_or_changed_version_without_echoing_values(self):
        with self.assertRaises(SecretNotFound):
            self.provider.pending(REF)
        _current, version = self.provider.stage(REF, NEW)
        for name, call in (("pending", lambda: self.provider.pending(REF, "0" * 24)), ("discard", lambda: self.provider.discard_pending(REF, "0" * 24))):
            with self.subTest(case=f"conflict {name}"), self.assertRaises(SecretConflict) as caught:
                call()
            self.assertNotIn(NEW, str(caught.exception))
        self.assertEqual(self.provider.pending(REF, version).value, NEW)
        self.assertIsNone(self.provider.discard_pending(make_reference("tg-other"), version))   # nothing pending: no-op
        with self.assertRaises(SecretNotFound):
            load_password_candidates(make_reference("tg-unknown"), path=self.store)

    def test_ssh_private_key_and_auth_kwargs_of_an_enrolled_key(self):
        private, _public, _fingerprint = mfa.generate_service_keypair("nmas-automation")
        key_ref = make_reference("tg-ssh-key")
        self.provider.initialize(key_ref, private)
        key = load_ssh_private_key(key_ref, path=self.store)
        self.assertEqual(key.get_name(), "ssh-ed25519")
        kwargs = ssh_auth_kwargs(key_ref, path=self.store)
        self.assertEqual((kwargs["use_keys"], kwargs["allow_agent"], kwargs["pkey"].get_base64()), (True, False, key.get_base64()))
        self.assertEqual((ssh_auth_kwargs(None), ssh_auth_kwargs("")), ({}, {}))

    def test_ssh_private_key_of_a_malformed_record_is_refused_without_echoing_it(self):
        bad_ref = make_reference("tg-bad-key")
        self.provider.initialize(bad_ref, "-----BEGIN " "OPENSSH PRIVATE KEY-----\nnot-a-key\n-----END OPENSSH PRIVATE KEY-----")
        with self.assertRaises(SecretProviderError) as caught:
            load_ssh_private_key(bad_ref, path=self.store)
        self.assertNotIn("not-a-key", str(caught.exception))


class RotationPolicyTests(TestCase):
    def setUp(self):
        DeviceCredential.objects.all().delete()
        self.now = timezone.now()

    def credential(self, username, *, due=True, enabled=True, status=CredentialStatus.NEVER):
        return DeviceCredential.objects.create(device_name="R1", platform="arista_ceos", username=username, auth_method="PASSWORD",
                                               secret_ref=make_reference(f"tg-{username}"), account_role="network-admin", privilege_level=15,
                                               rotation_enabled=enabled, rotation_interval_days=90, last_status=status,
                                               next_due_at=self.now + (timedelta(minutes=-1) if due else timedelta(days=1)))

    def test_next_due_at_is_due_and_due_credentials_select_runnable_due_rows(self):
        self.assertEqual(policy.next_due_at(self.now, 90), self.now + timedelta(days=90))
        due = self.credential("svc-a")
        self.assertTrue(policy.is_due(due, at=self.now))
        self.assertEqual(list(policy.due_credentials(at=self.now)), [due])

    def test_next_due_at_is_due_and_due_credentials_refuse_disabled_blocked_or_future_rows(self):
        with self.assertRaises(ValueError):
            policy.next_due_at(self.now, 0)
        rows = [self.credential("svc-off", enabled=False), self.credential("svc-later", due=False),
                self.credential("svc-blocked", status=CredentialStatus.BLOCKED), self.credential("svc-uncertain", status=CredentialStatus.UNCERTAIN)]
        for row in rows:
            with self.subTest(case=f"not due {row.username}"):
                self.assertFalse(policy.is_due(row, at=self.now))
        self.assertEqual(list(policy.due_credentials(at=self.now)), [])
        self.assertEqual(engine.rotate_due_credentials(at=self.now, adapter_factory=lambda c: (_ for _ in ()).throw(AssertionError("adapter built"))), [])

    def test_generate_password_refuses_lengths_outside_the_policy(self):
        for length in (23, 65, 0):
            with self.subTest(case=f"invalid length {length}"), self.assertRaises(ValueError):
                passwords.generate_password(length)

    def test_credential_status_context_lists_safe_fields_only(self):
        row = self.credential("svc-ctx")
        context = credential_service.get_credential_status_context()
        found = next(c for c in context["credentials"] if c["username"] == "svc-ctx")
        self.assertEqual(found["device_name"], row.device_name)
        self.assertNotIn("secret_value", found)
        self.assertEqual(context["live_status"], "NOT LIVE VERIFIED")


def row(username, kind, method, **extra):
    return SimpleNamespace(username=username, account_kind=kind, auth_method=method, ssh_public_key=extra.pop("ssh_public_key", ""),
                           account_role="network-admin", privilege_level=15, secret_ref=extra.pop("secret_ref", ""), **extra)


class MfaHelperTests(SimpleTestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        _private, cls.public, cls.fingerprint = mfa.generate_service_keypair("nmas-automation")

    def test_parse_public_key_and_fingerprint_of_a_valid_key(self):
        key_type, blob, comment = mfa.parse_public_key(self.public)
        self.assertEqual((key_type, comment), ("ssh-ed25519", "nmas-automation"))
        self.assertEqual(mfa.public_key_fingerprint(self.public), self.fingerprint)
        self.assertRegex(self.fingerprint, r"^SHA256:[A-Za-z0-9+/]{43}$")
        self.assertTrue(blob)

    def test_public_key_fingerprint_refuses_private_malformed_or_mismatched_keys(self):
        _type, blob, _comment = mfa.parse_public_key(self.public)
        for name, line in (("private", "-----BEGIN " "OPENSSH PRIVATE KEY-----"), ("malformed", "ssh-ed25519"), ("empty", ""),
                           ("mismatched", f"ssh-rsa {blob}"), ("not base64", "ssh-ed25519 !!!!")):
            with self.subTest(case=f"refused {name}"), self.assertRaises(mfa.MfaConfigError):
                mfa.public_key_fingerprint(line)

    def test_legacy_accounts_and_openssh_candidate_of_key_and_password_rows(self):
        rows = [row("nmas-automation", AccountKind.SERVICE, DeviceAuthMethod.PUBLICKEY_AND_PASSWORD, ssh_public_key=self.public + "\n"),
                row("ops", AccountKind.HUMAN, DeviceAuthMethod.PASSWORD)]
        accounts = mfa.legacy_accounts_from_credentials(rows)
        self.assertEqual([(a.username, a.kind, a.public_key, a.create_account) for a in accounts], [("nmas-automation", AccountKind.SERVICE, self.public, True)])
        candidate = mfa.render_legacy_openssh_candidate("R3", accounts, root_only=False)
        self.assertEqual(candidate.lines[1:], ["PubkeyAuthentication yes", "PasswordAuthentication yes", "KbdInteractiveAuthentication no",
                                               "AuthenticationMethods publickey,password"])
        self.assertEqual((candidate.platform, candidate.supported), ("ubuntu_frr", True))

    def test_legacy_accounts_skip_rows_without_a_key_or_the_two_factor_method(self):
        rows = [row("a", AccountKind.SERVICE, DeviceAuthMethod.PUBLICKEY_AND_PASSWORD), row("b", AccountKind.SERVICE, DeviceAuthMethod.PASSWORD, ssh_public_key=self.public)]
        self.assertEqual(mfa.legacy_accounts_from_credentials(rows), [])

    def test_render_linux_radius_totp_candidate_of_a_complete_r3_inventory(self):
        rows = [row("nmas-automation", AccountKind.SERVICE, DeviceAuthMethod.PUBLICKEY, ssh_key_ref=make_reference("tg-r3-automation-key"), ssh_public_key=self.public,
                    ssh_public_key_fingerprint=self.fingerprint),
                row("nmas-admin", AccountKind.HUMAN, DeviceAuthMethod.PASSWORD_AND_TOTP),
                row("r3-breakglass", AccountKind.BREAK_GLASS, DeviceAuthMethod.PASSWORD, secret_ref=make_reference("tg-r3-breakglass")),
                row("root", AccountKind.LEGACY_SHARED, DeviceAuthMethod.PASSWORD)]
        candidate = mfa.render_linux_radius_totp_candidate(SimpleNamespace(device_name="R3", radius_secret_ref="runtime://human-mfa/radius/r3"), rows)
        self.assertEqual((candidate.device, candidate.blockers, candidate.prepare_lines[-1]), ("R3", [], "account r3-breakglass (local emergency password)"))
        self.assertEqual(candidate.lines, [*candidate.prepare_lines, *candidate.activation_lines])

    def test_render_linux_radius_totp_candidate_refuses_foreign_devices_unprotected_secrets_or_missing_identities(self):
        with self.subTest(case="refused foreign device unprotected secret and missing identities"):
            with self.assertRaisesRegex(mfa.MfaConfigError, "restricted to R3 and R4"):
                mfa.render_linux_radius_totp_candidate(SimpleNamespace(device_name="R1", radius_secret_ref="runtime://human-mfa/radius/r1"), [])
            with self.assertRaisesRegex(mfa.MfaConfigError, "protected runtime reference"):
                mfa.render_linux_radius_totp_candidate(SimpleNamespace(device_name="R3", radius_secret_ref="plain-secret"), [])
            empty = mfa.render_linux_radius_totp_candidate(SimpleNamespace(device_name="R4", radius_secret_ref="runtime://human-mfa/radius/r4"), [])
        self.assertEqual([b.split(":")[0] for b in empty.blockers], ["NO_LINUX_PUBLICKEY_SERVICE_IDENTITY", "NO_CENTRAL_TOTP_HUMAN",
                                                                     "NO_SEALED_BREAK_GLASS_IDENTITY", "NO_ROOT_RECOVERY_METADATA"])


class TotpContractTests(SimpleTestCase):
    def oracle(self, available=True):
        return tc.FixtureAuthenticator(humans={"alice": tc.HumanFixture("alice", "fake-pass", {7: "123456", 6: "654321"})},
                                       machines={"nmas-automation": tc.MachineFixture("nmas-automation", "fake-svc", frozenset({"192.168.200.100"}))},
                                       available=available)

    def test_authenticate_human_and_machine_accept_the_correct_factors(self):
        oracle = self.oracle()
        self.assertEqual(oracle.authenticate_human("alice", "fake-pass123456", counter=7), (tc.ACCEPT, "HUMAN_PASSWORD_AND_TOTP_ACCEPTED"))
        self.assertEqual(oracle.authenticate_machine("nmas-automation", "fake-svc", source="192.168.200.100"),
                         (tc.ACCEPT, "APPROVED_MACHINE_IDENTITY_ACCEPTED_WITHOUT_OTP"))

    def test_human_probe_matrix_refuses_every_incomplete_factor_combination(self):
        found = tc.human_probe_matrix(self.oracle(), "alice", "fake-pass", "123456", counter=7)
        self.assertEqual(found, {"correct_password_only": tc.REJECT, "otp_only": tc.REJECT, "wrong_password_correct_otp": tc.REJECT,
                                 "correct_password_wrong_otp": tc.REJECT, "correct_password_correct_otp": tc.ACCEPT})
        oracle = self.oracle()
        oracle.authenticate_human("alice", "fake-pass123456", counter=7)
        self.assertEqual(oracle.authenticate_human("alice", "fake-pass123456", counter=7), (tc.REJECT, "OTP_REPLAYED"))
        self.assertEqual(oracle.authenticate_human("alice", "fake-pass654321", counter=7), (tc.REJECT, "OTP_EXPIRED"))
        self.assertEqual(self.oracle(available=False).authenticate_human("alice", "x", counter=7), (tc.UNAVAILABLE, "CENTRAL_AAA_UNAVAILABLE"))
        self.assertEqual(oracle.authenticate_machine("nmas-automation", "fake-svc", source="10.0.0.9"), (tc.REJECT, "MACHINE_SOURCE_NOT_ALLOWED"))
