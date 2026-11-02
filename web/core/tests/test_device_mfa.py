"""Phase 24 Microsoft Authenticator human 2FA and retained legacy helpers.

Fixture/mock only: no test contacts a device or changes live AAA.
"""
from __future__ import annotations

import io
import json
import sys
import tempfile
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parents[3]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import paramiko
from django.core.management import call_command
from django.core.management.base import CommandError
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from modules.device_credentials import FileSecretProvider, SecretProviderError, ceos_access_profile, ceos_access_profiles, make_reference

from core.models import AccountKind, DeviceAuthMethod, DeviceCredential, DeviceLoginMfaPolicy, MfaMechanism
from core.services import nsot_live
from core.services.credentials import mfa
from core.services.credentials.totp_contract import (
    ACCEPT,
    REJECT,
    UNAVAILABLE,
    FixtureAuthenticator,
    HumanFixture,
    MachineFixture,
    human_probe_matrix,
)

FAKE_PASSWORD = "TEST_ONLY_ROTATION_SECRET_NEVER_REAL"
FAKE_SEED_LIKE = "TEST_ONLY_TOTP_SEED_NEVER_REAL"


def _keypair(comment="ops@test"):
    return mfa.generate_service_keypair(comment)


class _FakeTransport:
    """Models an SSH server's method policy without a network."""

    def __init__(self, server, username):
        self.server, self.username = server, username
        self.key_ok = False
        self.authenticated = False

    def auth_publickey(self, username, pkey):
        if pkey.get_base64() != self.server["key"]:
            raise paramiko.AuthenticationException()
        self.key_ok = True
        if self.server["policy"] == "key":
            self.authenticated = True
            return []
        if self.server["policy"] == "key+password":
            return ["password"]  # partial success
        raise paramiko.BadAuthenticationType("", ["password"])

    def auth_password(self, username, password):
        policy = self.server["policy"]
        if policy == "key":
            raise paramiko.BadAuthenticationType("", ["publickey"])
        if policy == "key+password" and not self.key_ok:
            raise paramiko.BadAuthenticationType("", ["publickey"])
        if password != self.server["password"]:
            raise paramiko.AuthenticationException()
        self.authenticated = True
        return []

    def is_authenticated(self):
        return self.authenticated

    def close(self):
        pass


class PublicKeyTests(TestCase):
    def test_fingerprint_matches_paramiko_and_keys_are_distinct(self):
        private, public, fingerprint = _keypair()
        key = paramiko.Ed25519Key.from_private_key(io.StringIO(private))
        self.assertEqual(fingerprint, key.fingerprint)
        self.assertEqual(mfa.public_key_fingerprint(public), fingerprint)
        self.assertNotEqual(_keypair()[2], fingerprint)

    def test_private_or_malformed_keys_are_rejected_without_echo(self):
        private, public, _ = _keypair()
        for bad in (private, "ssh-ed25519 not*base64", "ssh-rsa " + public.split()[1], FAKE_SEED_LIKE):
            with self.assertRaises(mfa.MfaConfigError) as caught:
                mfa.parse_public_key(bad)
            self.assertNotIn(FAKE_SEED_LIKE, str(caught.exception))
            self.assertNotIn("PRIVATE", str(caught.exception).upper().replace("A PRIVATE KEY WAS SUPPLIED", ""))


class CandidateRenderingTests(TestCase):
    def setUp(self):
        self.service_pub = _keypair("nmas-automation@nmas")[1]
        self.human_pub = _keypair("alice@laptop")[1]
        self.accounts = [
            mfa.MfaAccount("ops-alice", AccountKind.HUMAN, self.human_pub, role="network-admin", privilege=15),
            mfa.MfaAccount("nmas-automation", AccountKind.SERVICE, self.service_pub, role="network-admin", privilege=15,
                           secret_ref=make_reference("r1-nmas-automation"), create_account=True),
        ]

    def test_ceos_candidate_is_deterministic_and_parser_validated_shape(self):
        first = mfa.render_legacy_ceos_candidate("R1", self.accounts)
        second = mfa.render_legacy_ceos_candidate("R1", list(reversed(self.accounts)))
        self.assertEqual(first.lines, second.lines)
        self.assertEqual(first.digest, second.digest)
        self.assertEqual(first.blockers, [])
        self.assertEqual(first.lines[0], "aaa authentication login console local")
        self.assertIn("   authentication protocol multi-factor public-key password", first.lines)
        self.assertIn("username nmas-automation privilege 15 role network-admin secret <provider:runtime://device-credentials/r1-nmas-automation>", first.lines)
        self.assertIn(f"username ops-alice ssh-key {self.human_pub}", first.lines)
        self.assertEqual(first.lines[-2:], ["management api http-commands", "   shutdown"])  # closes the eAPI password-only bypass
        self.assertIn("   default authentication protocol", first.rollback_lines)
        self.assertIn("no username nmas-automation", first.rollback_lines)

    def test_candidate_carries_references_never_values(self):
        with mock.patch("modules.device_credentials.DEFAULT_STORE", Path(tempfile.mkdtemp()) / "store.json"):
            FileSecretProvider().initialize(make_reference("r1-nmas-automation"), FAKE_PASSWORD)
            payload = json.dumps(mfa.render_legacy_ceos_candidate("R1", self.accounts).as_dict())
        self.assertNotIn(FAKE_PASSWORD, payload)
        self.assertNotIn("PRIVATE KEY", payload)

    def test_lockout_blockers_without_service_or_human_accounts(self):
        only_human = mfa.render_legacy_ceos_candidate("R1", self.accounts[:1])
        only_service = mfa.render_legacy_ceos_candidate("R1", self.accounts[1:])
        self.assertTrue(any(b.startswith("NO_ENROLLED_SERVICE_ACCOUNT") for b in only_human.blockers))
        self.assertTrue(any(b.startswith("NO_ENROLLED_HUMAN_OR_BREAK_GLASS_ACCOUNT") for b in only_service.blockers))

    def test_openssh_candidate_and_root_only_blocker(self):
        candidate = mfa.render_legacy_openssh_candidate("R3", self.accounts, root_only=True)
        self.assertIn("AuthenticationMethods publickey,password", candidate.lines)
        self.assertTrue(candidate.blockers[0].startswith("ROOT_ONLY_ACCOUNT"))

    def test_unsupported_platform_is_not_falsely_enabled(self):
        policy = DeviceLoginMfaPolicy(device_name="X1", platform="sonic", mechanism=MfaMechanism.UNSUPPORTED)
        candidate = mfa.render_candidate(policy, [])
        self.assertFalse(candidate.supported)
        self.assertEqual(candidate.lines, [])
        policy.enforcement_state = "ENFORCED"
        with self.assertRaises(ValueError):
            policy.save()


class ProbeVerdictTests(TestCase):
    def setUp(self):
        private, public, _ = _keypair()
        self.pkey = paramiko.Ed25519Key.from_private_key(io.StringIO(private))
        self.server = {"key": self.pkey.get_base64(), "password": FAKE_PASSWORD, "policy": "key+password"}

    def probe(self, policy):
        self.server["policy"] = policy
        return mfa.probe_two_factor_login(lambda: _FakeTransport(self.server, "svc"), "svc", password=FAKE_PASSWORD, pkey=self.pkey)

    def test_enforced_two_factor_refuses_each_single_factor_and_a_wrong_second_factor(self):
        results = self.probe("key+password")
        self.assertEqual(results, {"password_only": "REJECTED", "key_only": "PARTIAL",
                                   "key_and_wrong_password": "REJECTED", "key_and_password": "ACCEPTED"})
        self.assertEqual(mfa.evaluate_probe(results), (True, "TWO_FACTOR_ENFORCED"))
        self.assertNotIn(FAKE_PASSWORD, json.dumps(results))

    def test_single_factor_servers_are_never_reported_as_two_factor(self):
        self.assertEqual(mfa.evaluate_probe(self.probe("password")), (False, "PASSWORD_ALONE_ACCEPTED"))
        self.assertEqual(mfa.evaluate_probe(self.probe("key")), (False, "KEY_ALONE_ACCEPTED"))

    def test_unreachable_service_is_an_error_not_a_pass(self):
        def broken():
            raise OSError("connection refused")
        results = mfa.probe_two_factor_login(broken, "svc", password=FAKE_PASSWORD, pkey=self.pkey)
        self.assertEqual(set(results.values()), {"ERROR"})
        self.assertEqual(mfa.evaluate_probe(results), (False, "PROBE_ERROR"))
        self.assertEqual(mfa.evaluate_probe({}), (False, "INCOMPLETE_PROBE"))


class RadiusTotpContractTests(TestCase):
    COUNTER = 12345
    HUMAN_PASSWORD = "TEST_ONLY_HUMAN_PASSWORD"
    HUMAN_OTP = "482901"
    MACHINE_PASSWORD = "TEST_ONLY_MACHINE_PASSWORD"

    def authenticator(self, *, available=True, enabled=True):
        return FixtureAuthenticator(
            humans={
                "ops-alice": HumanFixture(
                    "ops-alice", self.HUMAN_PASSWORD,
                    {self.COUNTER - 1: "173205", self.COUNTER: self.HUMAN_OTP},
                    enabled=enabled,
                )
            },
            machines={
                "nmas-automation": MachineFixture(
                    "nmas-automation", self.MACHINE_PASSWORD, frozenset({"192.168.200.100"}),
                )
            },
            available=available,
        )

    def test_required_human_factor_matrix(self):
        results = human_probe_matrix(
            self.authenticator(), "ops-alice", self.HUMAN_PASSWORD, self.HUMAN_OTP, counter=self.COUNTER,
        )
        self.assertEqual(results, {
            "correct_password_only": REJECT,
            "otp_only": REJECT,
            "wrong_password_correct_otp": REJECT,
            "correct_password_wrong_otp": REJECT,
            "correct_password_correct_otp": ACCEPT,
        })
        self.assertNotIn(self.HUMAN_PASSWORD, json.dumps(results))
        self.assertNotIn(self.HUMAN_OTP, json.dumps(results))

    def test_expired_replayed_malformed_disabled_and_unavailable_are_rejected(self):
        auth = self.authenticator()
        self.assertEqual(
            auth.authenticate_human("ops-alice", self.HUMAN_PASSWORD + "173205", counter=self.COUNTER),
            (REJECT, "OTP_EXPIRED"),
        )
        good = self.HUMAN_PASSWORD + self.HUMAN_OTP
        self.assertEqual(auth.authenticate_human("ops-alice", good, counter=self.COUNTER)[0], ACCEPT)
        self.assertEqual(auth.authenticate_human("ops-alice", good, counter=self.COUNTER), (REJECT, "OTP_REPLAYED"))
        self.assertEqual(auth.authenticate_human("ops-alice", "not-an-otp", counter=self.COUNTER)[0], REJECT)
        self.assertEqual(
            self.authenticator(enabled=False).authenticate_human("ops-alice", good, counter=self.COUNTER),
            (REJECT, "HUMAN_DISABLED"),
        )
        self.assertEqual(
            self.authenticator(available=False).authenticate_human("ops-alice", good, counter=self.COUNTER),
            (UNAVAILABLE, "CENTRAL_AAA_UNAVAILABLE"),
        )

    def test_machine_exemption_is_noninteractive_source_restricted_and_not_available_to_humans(self):
        auth = self.authenticator()
        self.assertEqual(
            auth.authenticate_machine("nmas-automation", self.MACHINE_PASSWORD, source="192.168.200.100")[0], ACCEPT,
        )
        self.assertEqual(
            auth.authenticate_machine("nmas-automation", self.MACHINE_PASSWORD, source="192.0.2.55"),
            (REJECT, "MACHINE_SOURCE_NOT_ALLOWED"),
        )
        self.assertEqual(
            auth.authenticate_machine("ops-alice", self.HUMAN_PASSWORD, source="192.168.200.100"),
            (REJECT, "NOT_AN_APPROVED_MACHINE_IDENTITY"),
        )


class RadiusTotpCandidateTests(TestCase):
    def policy(self, **overrides):
        values = {
            "device_name": "R1",
            "platform": "arista_ceos",
            "mechanism": MfaMechanism.RADIUS_TOTP,
            "radius_server": "192.168.200.100",
            "radius_secret_ref": "runtime://human-mfa/radius/r1",
            "radius_source_interface": "Vlan200",
        }
        values.update(overrides)
        return DeviceLoginMfaPolicy(**values)

    def accounts(self):
        return [
            DeviceCredential(device_name="R1", platform="arista_ceos", username="nmas-automation",
                             account_kind=AccountKind.SERVICE, secret_ref=make_reference("r1-nmas-automation"),
                             account_role="network-admin", privilege_level=15),
            DeviceCredential(device_name="R1", platform="arista_ceos", username="r1-breakglass",
                             account_kind=AccountKind.BREAK_GLASS, secret_ref=make_reference("r1-breakglass"),
                             account_role="network-admin", privilege_level=15),
            DeviceCredential(device_name="R1", platform="arista_ceos", username="ops-alice",
                             account_kind=AccountKind.HUMAN, auth_method=DeviceAuthMethod.PASSWORD_AND_TOTP),
            DeviceCredential(device_name="R1", platform="arista_ceos", username="admin",
                             account_kind=AccountKind.LEGACY_SHARED, secret_ref=make_reference("ceos-admin-shared"),
                             account_role="network-admin", privilege_level=15),
        ]

    def test_exact_eos_radius_candidate_is_deterministic_and_secret_free(self):
        first = mfa.render_ceos_radius_totp_candidate(self.policy(), self.accounts())
        second = mfa.render_ceos_radius_totp_candidate(self.policy(), list(reversed(self.accounts())))
        self.assertEqual(first.lines, second.lines)
        self.assertEqual(first.blockers, [])
        self.assertEqual(first.lines, first.prepare_lines + first.activation_lines)
        self.assertIn(
            "username nmas-automation privilege 15 role network-admin secret "
            "<provider:runtime://device-credentials/r1-nmas-automation>", first.prepare_lines,
        )
        self.assertIn(
            "username r1-breakglass privilege 15 role network-admin secret "
            "<provider:runtime://device-credentials/r1-breakglass>", first.prepare_lines,
        )
        self.assertEqual(first.activation_lines[0], "no username admin")
        self.assertIn("radius-server host 192.168.200.100 key 0 <provider:runtime://human-mfa/radius/r1>", first.lines)
        self.assertIn("aaa authentication login default local group NMAS-HUMAN-MFA", first.lines)
        self.assertIn("aaa authentication login console local", first.lines)
        self.assertIn("aaa authorization exec default local none", first.lines)
        self.assertIn("no aaa authorization exec default", first.rollback_lines)
        self.assertIn("   authentication protocol password", first.lines)
        self.assertNotIn(FAKE_PASSWORD, json.dumps(first.as_dict()))
        self.assertNotIn(FAKE_SEED_LIKE, json.dumps(first.as_dict()))
        self.assertIn(
            "username admin privilege 15 role network-admin secret "
            "<provider:runtime://device-credentials/ceos-admin-shared>", first.rollback_lines,
        )
        self.assertIn("no username r1-breakglass", first.rollback_lines)
        self.assertIn("no username nmas-automation", first.rollback_lines)

    def test_missing_breakglass_is_a_lockout_blocker(self):
        rows = [row for row in self.accounts() if row.account_kind != AccountKind.BREAK_GLASS]
        candidate = mfa.render_ceos_radius_totp_candidate(self.policy(), rows)
        self.assertTrue(any(item.startswith("NO_SEALED_BREAK_GLASS_IDENTITY") for item in candidate.blockers))

    def test_missing_legacy_admin_metadata_blocks_an_incomplete_rollback(self):
        rows = [row for row in self.accounts() if row.account_kind != AccountKind.LEGACY_SHARED]
        candidate = mfa.render_ceos_radius_totp_candidate(self.policy(), rows)
        self.assertTrue(any(item.startswith("NO_EXACT_LEGACY_ADMIN_ROLLBACK") for item in candidate.blockers))

    def test_multiple_humans_or_breakglass_accounts_are_lockout_blockers(self):
        rows = self.accounts() + [
            DeviceCredential(device_name="R1", platform="arista_ceos", username="ops-bob",
                             account_kind=AccountKind.HUMAN, auth_method=DeviceAuthMethod.PASSWORD_AND_TOTP),
            DeviceCredential(device_name="R1", platform="arista_ceos", username="r1-breakglass-2",
                             account_kind=AccountKind.BREAK_GLASS, secret_ref=make_reference("r1-breakglass-2")),
        ]
        candidate = mfa.render_ceos_radius_totp_candidate(self.policy(), rows)
        self.assertTrue(any(item.startswith("NO_CENTRAL_TOTP_HUMAN") for item in candidate.blockers))
        self.assertTrue(any(item.startswith("NO_SEALED_BREAK_GLASS_IDENTITY") for item in candidate.blockers))

    def test_linux_radius_totp_requires_separated_identities(self):
        policy = self.policy(device_name="R3", platform="ubuntu_frr", radius_secret_ref="runtime://human-mfa/radius/r3")
        candidate = mfa.render_candidate(policy, [])
        self.assertTrue(candidate.supported)
        self.assertTrue(any(item.startswith("NO_LINUX_PUBLICKEY_SERVICE_IDENTITY") for item in candidate.blockers))
        self.assertTrue(any(item.startswith("NO_CENTRAL_TOTP_HUMAN") for item in candidate.blockers))
        self.assertTrue(any(item.startswith("NO_SEALED_BREAK_GLASS_IDENTITY") for item in candidate.blockers))
        self.assertTrue(any(item.startswith("NO_ROOT_RECOVERY_METADATA") for item in candidate.blockers))

    def test_central_aaa_bundle_is_isolated_fail_closed_and_secret_free(self):
        repo = Path(__file__).resolve().parents[3]
        bundle = repo / "monitoring" / "human_mfa"
        compose = (bundle / "docker-compose.yml").read_text()
        site = (bundle / "freeradius" / "sites-available" / "nmas-human-mfa").read_text()
        rest = (bundle / "freeradius" / "mods-available" / "privacyidea").read_text()
        clients = (bundle / "freeradius" / "clients.conf.example").read_text()

        self.assertIn('profiles: ["human-2fa"]', compose)
        self.assertIn("monitoring/runtime/human-mfa", (bundle / "README.md").read_text())
        self.assertIn('if (&User-Name == "nmas-automation")', site)
        self.assertIn("reject", site)
        self.assertIn("check_cert = yes", rest)
        self.assertIn("check_cert_cn = yes", rest)
        self.assertIn("ca_info_file = /run/secrets/privacyidea-ca.pem", rest)
        self.assertNotIn("\n        ca_file =", rest)
        self.assertNotIn("auth_badpass = yes", rest + site)
        secret_lines = [line.strip() for line in clients.splitlines() if line.strip().startswith("secret =")]
        self.assertTrue(secret_lines)
        self.assertTrue(all("TEST_ONLY_REPLACE_" in line for line in secret_lines))

    def test_live_verified_requires_verified_central_aaa(self):
        policy = self.policy(enforcement_state="LIVE_VERIFIED", last_verified_at=timezone.now())
        with self.assertRaises(ValueError):
            policy.save()

    def test_retained_legacy_verifier_does_not_require_radius_state(self):
        policy = self.policy(
            device_name="X9",
            mechanism=MfaMechanism.LEGACY_EOS_SSH_KEY_PASSWORD,
            enforcement_state="LIVE_VERIFIED",
            last_verified_at=timezone.now(),
            radius_secret_ref="",
        )
        policy.save()


class ConsumerFailClosedTests(TestCase):
    def test_per_device_access_profile_is_required_for_every_device(self):
        inventory = {
            "ceos_username": "admin",
            "ceos_credential_ref": make_reference("ceos-admin-shared"),
            "network_devices": {
                "R1": {"username": "nmas-automation", "credential_ref": make_reference("r1-nmas-automation")},
                "R2": {},
            },
        }
        r1 = ceos_access_profile(inventory, "R1")
        self.assertEqual((r1.username, r1.credential_ref), ("nmas-automation", make_reference("r1-nmas-automation")))
        with self.assertRaises(SecretProviderError):
            ceos_access_profile(inventory, "R2")
        self.assertEqual([item.username for item in ceos_access_profiles(inventory, "R1")], ["nmas-automation"])

    def test_nsot_health_and_execution_resolver_returns_r1_override(self):
        inventory = {
            "ceos_username": "admin",
            "ceos_credential_ref": make_reference("ceos-admin-shared"),
            "network_devices": {
                "R1": {
                    "username": "nmas-automation",
                    "credential_ref": make_reference("r1-nmas-automation"),
                    "monitoring": {"platform": "ceos", "address": "192.0.2.1"},
                },
                "R2": {"monitoring": {"platform": "ceos", "address": "192.0.2.2"}},
            },
        }
        with mock.patch.object(nsot_live, "_load_inventory", return_value=inventory):
            self.assertEqual(nsot_live.get_live_target_metadata("R1")["username"], "nmas-automation")
            self.assertEqual(nsot_live.get_live_target_metadata("R1")["credential_ref"], make_reference("r1-nmas-automation"))
            self.assertIsNone(nsot_live.get_live_target_metadata("R2"))

    def test_shared_resolver_never_supplies_the_fleet_identity(self):
        store = Path(tempfile.mkdtemp()) / "store.json"
        FileSecretProvider(store).initialize(make_reference("r1-nmas-automation"), "TEST_ONLY_R1_PASSWORD")
        FileSecretProvider(store).initialize(make_reference("ceos-admin-shared"), "TEST_ONLY_FLEET_PASSWORD")
        inventory = {
            "ceos_username": "admin",
            "ceos_credential_ref": make_reference("ceos-admin-shared"),
            "network_devices": {"R1": {
                "username": "nmas-automation",
                "credential_ref": make_reference("r1-nmas-automation"),
                "monitoring": {"platform": "ceos", "address": "192.0.2.1"},
            }},
        }
        with mock.patch.object(nsot_live, "_load_inventory", return_value=inventory), \
                mock.patch("modules.device_credentials.DEFAULT_STORE", store):
            target = nsot_live.get_live_target("R1")
        self.assertEqual([item["username"] for item in target["auth_candidates"]], ["nmas-automation"])
        self.assertEqual(target["username"], "nmas-automation")

    def test_live_target_is_refused_when_an_enrolled_key_cannot_be_loaded(self):
        store = Path(tempfile.mkdtemp()) / "store.json"
        FileSecretProvider(store).initialize(make_reference("ceos-admin-shared"), FAKE_PASSWORD)
        inventory = {
            "ceos_username": "nmas-automation",
            "ceos_credential_ref": make_reference("ceos-admin-shared"),
            "ceos_ssh_key_ref": make_reference("absent-key"),
            "network_devices": {"R1": {
                "username": "nmas-automation",
                "credential_ref": make_reference("ceos-admin-shared"),
                "ssh_key_ref": make_reference("absent-key"),
                "monitoring": {"platform": "ceos", "address": "192.0.2.1"},
            }},
        }
        with mock.patch.object(nsot_live, "_load_inventory", return_value=inventory), \
                mock.patch("modules.device_credentials.DEFAULT_STORE", store):
            self.assertIsNone(nsot_live.get_live_target("R1"))  # no password-only downgrade
            self.assertEqual(nsot_live.get_live_target_metadata("R1")["ssh_key_ref"], make_reference("absent-key"))

    def test_running_config_tries_r1_identity_then_rollback_identity(self):
        from netmiko.exceptions import NetmikoAuthenticationException

        connection = mock.MagicMock()
        connection.check_enable_mode.return_value = True
        connection.send_command.return_value = "hostname R1"
        target = {
            "platform": "ceos", "address": "192.0.2.1", "username": "nmas-automation", "password": "primary",
            "auth_candidates": (
                {"username": "nmas-automation", "password": "primary", "ssh_auth": {}},
                {"username": "admin", "password": "rollback", "ssh_auth": {}},
            ),
        }
        with mock.patch.object(nsot_live, "get_live_target", return_value=target), \
                mock.patch("netmiko.ConnectHandler", side_effect=[NetmikoAuthenticationException("fixture"), connection]) as connect:
            result = nsot_live.fetch_running_config("R1")
        self.assertEqual(result["status"], "available")
        self.assertEqual([call.kwargs["username"] for call in connect.call_args_list], ["nmas-automation", "admin"])


class EnrollmentAndSurfaceTests(TestCase):
    def setUp(self):
        self.store = Path(tempfile.mkdtemp()) / "store.json"
        self.patch = mock.patch("modules.device_credentials.DEFAULT_STORE", self.store)
        self.patch.start()
        FileSecretProvider().initialize(make_reference("r1-nmas-automation"), FAKE_PASSWORD)
        self.service = DeviceCredential.objects.create(
            device_name="R1", platform="arista_ceos", username="nmas-automation", account_kind=AccountKind.SERVICE,
            secret_ref=make_reference("r1-nmas-automation"), account_role="network-admin", privilege_level=15,
        )

    def tearDown(self):
        self.patch.stop()

    def test_service_key_enrollment_keeps_private_key_in_provider_only(self):
        out = io.StringIO()
        call_command("enroll_service_ssh_key", "--credential-id", str(self.service.pk),
                     "--key-ref", make_reference("r1-nmas-automation-sshkey"), stdout=out)
        self.service.refresh_from_db()
        self.assertEqual(self.service.auth_method, DeviceAuthMethod.PUBLICKEY_AND_PASSWORD)
        self.assertNotIn("PRIVATE KEY", out.getvalue())
        self.assertNotIn("PRIVATE KEY", self.service.ssh_public_key)
        self.assertIn("PRIVATE KEY", FileSecretProvider().current(self.service.ssh_key_ref).value)
        self.assertEqual(self.store.stat().st_mode & 0o777, 0o600)

    def test_human_accounts_cannot_get_nmas_held_keys(self):
        human = DeviceCredential.objects.create(device_name="R1", platform="arista_ceos", username="ops-alice",
                                                account_kind=AccountKind.HUMAN)
        with self.assertRaises(CommandError):
            call_command("enroll_service_ssh_key", "--credential-id", str(human.pk), "--key-ref", make_reference("alice-key"))

    def test_operator_public_key_registration_and_candidate_command(self):
        pub_file = Path(tempfile.mkdtemp()) / "alice.pub"
        pub_file.write_text(_keypair("alice@laptop")[1] + "\n")
        call_command("register_operator_ssh_key", "--device", "R1", "--username", "ops-alice", "--public-key-file", str(pub_file),
                     stdout=io.StringIO())
        # The retained registration command is legacy metadata. Simulate the
        # later privacyIDEA enrollment state without creating a TOTP seed.
        human = DeviceCredential.objects.get(device_name="R1", username="ops-alice")
        human.auth_method = DeviceAuthMethod.PASSWORD_AND_TOTP
        human.save()
        DeviceCredential.objects.create(
            device_name="R1", platform="arista_ceos", username="r1-breakglass",
            account_kind=AccountKind.BREAK_GLASS, secret_ref=make_reference("r1-breakglass"),
            account_role="network-admin", privilege_level=15,
        )
        call_command("enroll_service_ssh_key", "--credential-id", str(self.service.pk),
                     "--key-ref", make_reference("r1-nmas-automation-sshkey"), stdout=io.StringIO())
        out = io.StringIO()
        call_command("render_device_mfa_candidate", "--device", "R1", "--json", "--record-digest", stdout=out)
        payload = json.loads(out.getvalue())
        self.assertEqual(payload["blockers"], [])
        self.assertIn("no username admin", payload["activation_lines"])
        self.assertEqual(DeviceLoginMfaPolicy.objects.get(device_name="R1").candidate_digest, payload["digest"])
        self.assertNotIn(FAKE_PASSWORD, out.getvalue())
        self.assertNotIn("PRIVATE KEY", out.getvalue())

    def test_private_key_file_is_refused_as_an_operator_key(self):
        key_file = Path(tempfile.mkdtemp()) / "id_ed25519"
        key_file.write_text(_keypair()[0])
        with self.assertRaises(CommandError) as caught:
            call_command("register_operator_ssh_key", "--device", "R1", "--username", "ops-bob", "--public-key-file", str(key_file))
        self.assertNotIn("PRIVATE KEY-----", str(caught.exception))

    def test_live_verifier_refuses_until_an_authorized_activation(self):
        with self.assertRaises(CommandError):
            call_command("verify_device_mfa", "--device", "R1")

    def test_ui_and_json_show_required_2fa_metadata_but_no_secret_material(self):
        call_command("enroll_service_ssh_key", "--credential-id", str(self.service.pk),
                     "--key-ref", make_reference("r1-nmas-automation-sshkey"), stdout=io.StringIO())
        html = self.client.get(reverse("core:credential_status")).content.decode()
        payload = self.client.get(reverse("core:credential_status_json")).content.decode()
        for surface in (html, payload):
            self.assertIn("REQUIRED BY PROJECT OWNER", surface)
            self.assertNotIn("EXTRA CREDIT", surface)
            self.assertNotIn(FAKE_PASSWORD, surface)
            self.assertNotIn("PRIVATE KEY", surface)
            self.assertIn("RADIUS_TOTP", surface)
            self.assertIn("Microsoft Authenticator", surface)
            self.assertIn("NOT CONFIGURED, ENFORCED, OR LIVE VERIFIED", surface)
        self.assertIn('data-section="device-login-2fa"', html)


class R1RolloutMetadataCommandTests(TestCase):
    def test_command_is_idempotent_and_creates_no_secret_or_live_state(self):
        out = io.StringIO()
        call_command("prepare_r1_mfa_rollout_metadata", "--human-username", "ops-alice", "--json", stdout=out)
        first = json.loads(out.getvalue())
        call_command("prepare_r1_mfa_rollout_metadata", "--human-username", "ops-alice", stdout=io.StringIO())
        self.assertFalse(first["live_device_changed"])
        self.assertFalse(first["totp_enrolled"])
        self.assertEqual(DeviceCredential.objects.filter(device_name="R1", username="nmas-automation").count(), 1)
        self.assertEqual(DeviceCredential.objects.filter(device_name="R1", username="r1-breakglass").count(), 1)
        self.assertEqual(
            DeviceCredential.objects.get(device_name="R1", username="ops-alice").auth_method,
            DeviceAuthMethod.PASSWORD_AND_TOTP,
        )
        rendered = mfa.render_ceos_radius_totp_candidate(
            DeviceLoginMfaPolicy.objects.get(device_name="R1"), DeviceCredential.objects.filter(device_name="R1"),
        )
        self.assertEqual(rendered.blockers, [])
        self.assertIn("no username admin", rendered.activation_lines)

    def test_command_rejects_placeholder_reserved_and_incompatible_names(self):
        for username in ("<NAMED_OPERATOR>", "admin", "nmas-automation"):
            with self.subTest(username=username), self.assertRaises(CommandError):
                call_command("prepare_r1_mfa_rollout_metadata", "--human-username", username)

    def test_command_refuses_a_second_human_operator(self):
        call_command("prepare_r1_mfa_rollout_metadata", "--human-username", "ops-alice", stdout=io.StringIO())
        with self.assertRaises(CommandError):
            call_command("prepare_r1_mfa_rollout_metadata", "--human-username", "ops-bob", stdout=io.StringIO())

    def test_command_preserves_separately_enrolled_service_key_metadata(self):
        service = DeviceCredential.objects.create(
            device_name="R1", platform="arista_ceos", username="nmas-automation",
            account_kind=AccountKind.SERVICE, secret_ref=make_reference("r1-old-password"),
            ssh_key_ref=make_reference("r1-machine-key"),
            ssh_public_key_fingerprint="SHA256:TESTONLY", ssh_public_key="ssh-ed25519 TESTONLY fixture",
        )
        call_command("prepare_r1_mfa_rollout_metadata", "--human-username", "ops-alice", stdout=io.StringIO())
        service.refresh_from_db()
        self.assertEqual(service.ssh_key_ref, make_reference("r1-machine-key"))
        self.assertEqual(service.ssh_public_key_fingerprint, "SHA256:TESTONLY")
