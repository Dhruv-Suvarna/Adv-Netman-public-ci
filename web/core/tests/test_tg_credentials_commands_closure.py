"""Lab 7 closure -- the credential / MFA management commands, each invoked through ``call_command``.

The rollout runners, the secret provider, the rotation engine and every login probe are replaced, so no command here
reaches a device, a terminal or the real runtime secret store.  POSITIVE: each operation dispatches to exactly one
runner step and prints its JSON, an import reports only the non-secret version, prepared R3 metadata satisfies the
reviewed candidate, a passing legacy probe marks the policy LIVE_VERIFIED.  NEGATIVE: an unknown device or missing
``--name`` / ``--phase`` / ``--token``, a lower-case or empty environment variable, a runner error, a FAIL verdict,
an unknown credential and a policy-less device are each refused -- and no fake secret ever reaches stdout.
"""

from __future__ import annotations

import io
import json
import re
import tempfile
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from django.core.management import call_command
from django.core.management.base import CommandError
from django.test import TestCase
from django.utils import timezone

from core.management.commands import (ceos_mfa_rollout, import_device_credential, linux_mfa_rollout,
                                      reconcile_device_credential, render_device_mfa_candidate, rotate_due_credentials,
                                      verify_device_mfa)
from core.models import (AccountKind, CentralAaaState, DeviceAuthMethod, DeviceCredential, DeviceLoginMfaPolicy,
                         MfaEnforcementState, MfaMechanism)
from core.services.credentials import linux_mfa as lm
from core.services.credentials import mfa
from core.services.credentials import r1_pilot as rollout
from core.services.credentials.engine import RotationOutcome
from core.services.credentials.mfa import MfaConfigError
from modules import device_credentials
from modules.device_credentials import FileSecretProvider, SecretProviderError, make_reference

FAKE_VALUE = "fake-Imported-value-83"
CEOS_METHODS = {"precheck": "precheck", "validate": "validate", "status": "status", "checkpoint": "checkpoint", "stage1": "stage1",
                "verify-logins": "verify", "stage2": "stage2", "confirm": "confirm", "persist": "persist", "replace": "replace",
                "verify-positive": "verify_positive", "record-verification": "record_verification"}
LINUX_METHODS = {"stage-radius": "stage_radius", "install-module": "install_module", "precheck": "precheck", "backup": "backup",
                 "arm": "arm", "activate": "activate", "verify-machine-recovery": "verify_machine_recovery",
                 "verify-operational": "verify_operational", "verify-human": "verify_human", "finalize": "finalize", "status": "status"}


def run(command, *args, **options):
    out = io.StringIO()
    call_command(command, *args, stdout=out, **options)
    return out.getvalue()


class CeosRolloutCommandTests(TestCase):
    def test_every_operation_dispatches_to_exactly_one_runner_step(self):
        target = rollout.target_for("R1")
        self.assertEqual(set(CEOS_METHODS), set(ceos_mfa_rollout.OPERATIONS))
        for operation, method in CEOS_METHODS.items():
            with self.subTest(case=f"dispatches {operation} ok"), mock.patch.object(ceos_mfa_rollout, "R1PilotRunner") as runner_class:
                runner = runner_class.return_value
                getattr(runner, method).return_value = {"PASS": True, "step": operation}
                out = run("ceos_mfa_rollout", operation, device="R1", name=target.checkpoints[0], phase="post-stage1")
                self.assertEqual(json.loads(out), {"PASS": True, "step": operation})
                runner_class.assert_called_once_with(device="R1", target=target)
                self.assertEqual(runner.deps.actor, "manage.py ceos_mfa_rollout")
                called = [name for name in set(CEOS_METHODS.values()) if getattr(runner, name).called]
                self.assertEqual(called, [method])

    def test_ceos_rollout_refuses_bad_arguments_runner_errors_and_fail_verdicts(self):
        target = rollout.target_for("R1")
        with mock.patch.object(ceos_mfa_rollout, "R1PilotRunner") as runner_class:
            runner_class.return_value.stage1.side_effect = rollout.PilotError("stage1 refused")
            runner_class.return_value.precheck.return_value = {"ok": False}
            for name, args, options, message in (
                    ("unknown device", ("status",), {"device": "R9"}, ""),
                    ("missing name", ("checkpoint",), {"device": "R1"}, "^--name is required for checkpoint/replace.$"),
                    ("foreign name", ("replace",), {"device": "R1", "name": "other"}, re.escape(f"--name must be one of {list(target.checkpoints)}")),
                    ("missing phase", ("verify-logins",), {"device": "R1"}, "^--phase is required for verify-logins.$"),
                    ("runner error", ("stage1",), {"device": "R1"}, "^stage1 refused$"),
                    ("fail verdict", ("precheck",), {"device": "R1"}, r"^precheck: FAIL \(see the redacted evidence above\).$")):
                with self.subTest(case=f"refused {name}"), self.assertRaisesRegex(CommandError, message):
                    run("ceos_mfa_rollout", *args, **options)
        self.assertEqual(runner_class.call_count, 2)


class LinuxRolloutCommandTests(TestCase):
    def test_every_operation_dispatches_with_the_token_and_human_factor_reader(self):
        self.assertEqual(set(LINUX_METHODS), set(linux_mfa_rollout.OPERATIONS))
        token = "e" * 24
        for operation, method in LINUX_METHODS.items():
            with self.subTest(case=f"dispatches {operation} ok"), mock.patch.object(linux_mfa_rollout, "LinuxMfaRunner") as runner_class:
                runner = runner_class.return_value
                getattr(runner, method).return_value = {"PASS": True, "step": operation}
                self.assertEqual(json.loads(run("linux_mfa_rollout", operation, device="R3", token=token)), {"PASS": True, "step": operation})
                runner_class.assert_called_once_with("R3")
                expected = {"verify-human": (token, linux_mfa_rollout.human_factors)}.get(
                    operation, (token,) if operation in ("arm", "activate", "verify-machine-recovery", "verify-operational", "finalize") else ())
                self.assertEqual(getattr(runner, method).call_args.args, expected)

    def test_linux_rollout_refuses_missing_token_runner_errors_and_fail_verdicts(self):
        with mock.patch.object(linux_mfa_rollout, "LinuxMfaRunner") as runner_class:
            runner_class.return_value.backup.side_effect = lm.LinuxMfaError("backup refused")
            runner_class.return_value.precheck.return_value = {"PASS": False}
            for name, args, message in ((("missing token", ("arm",), "^--token is required for this timer-window operation.$")),
                                        ("runner error", ("backup",), "^backup refused$"),
                                        ("fail verdict", ("precheck",), "^precheck: FAIL; leave the automatic rollback timer armed.$")):
                with self.subTest(case=f"refused {name}"), self.assertRaisesRegex(CommandError, message):
                    run("linux_mfa_rollout", *args, device="R3")
        self.assertEqual(runner_class.call_count, 2)
        with self.assertRaises(CommandError):
            run("linux_mfa_rollout", "status", device="R1")

    def test_human_factors_returns_the_two_hidden_answers(self):
        with mock.patch("getpass.getpass", side_effect=[FAKE_VALUE, "123456"]) as prompt:
            self.assertEqual(linux_mfa_rollout.human_factors(), (FAKE_VALUE, "123456"))
        self.assertEqual([c.args[0] for c in prompt.call_args_list],
                         ["nmas-admin password (not echoed): ", "Current Microsoft Authenticator code (not echoed): "])

    def test_human_factors_without_a_terminal_is_refused(self):
        with mock.patch("getpass.getpass", side_effect=EOFError()), \
                self.assertRaisesRegex(lm.LinuxMfaError, "^An interactive terminal is required for the human factor proof.$"):
            linux_mfa_rollout.human_factors()


class ImportAndReconcileCommandTests(TestCase):
    def test_import_device_credential_reports_only_the_non_secret_version(self):
        provider = mock.Mock()
        provider.initialize.return_value = 3
        with mock.patch.dict("os.environ", {"NMAS_TG_FAKE_VALUE": FAKE_VALUE}), \
                mock.patch.object(import_device_credential, "FileSecretProvider", return_value=provider):
            out = run("import_device_credential", ref="runtime://device-credentials/tg-fake", env_var="NMAS_TG_FAKE_VALUE", replace=True)
        self.assertEqual(out, "Imported runtime://device-credentials/tg-fake as non-secret version 3.\n")
        provider.initialize.assert_called_once_with("runtime://device-credentials/tg-fake", FAKE_VALUE, replace=True)
        self.assertNotIn(FAKE_VALUE, out)

    def test_import_device_credential_refuses_bad_names_empty_values_and_provider_errors(self):
        provider = mock.Mock()
        provider.initialize.side_effect = SecretProviderError("Reference already exists.")
        with mock.patch.dict("os.environ", {"NMAS_TG_EMPTY": "", "NMAS_TG_FAKE_VALUE": FAKE_VALUE}), \
                mock.patch.object(import_device_credential, "FileSecretProvider", return_value=provider):
            for name, env_var, message in (("lower case", "nmas_tg_fake_value", "uppercase environment-variable name"),
                                           ("not identifier", "NMAS-TG", "uppercase environment-variable name"),
                                           ("empty", "NMAS_TG_EMPTY", "missing or empty"),
                                           ("unset", "NMAS_TG_UNSET_NAME", "missing or empty"),
                                           ("provider", "NMAS_TG_FAKE_VALUE", "^Reference already exists.$")):
                with self.subTest(case=f"refused {name}"), self.assertRaisesRegex(CommandError, message):
                    run("import_device_credential", ref="runtime://device-credentials/tg-fake", env_var=env_var)
        provider.initialize.assert_called_once()

    def credential(self):
        return DeviceCredential.objects.filter(device_name="R1").first()

    def test_reconcile_device_credential_prints_the_terminal_outcome(self):
        row = self.credential()
        outcome = RotationOutcome(row.pk, "run-1", "SUCCESS", "CURRENT_VERIFIED")
        with mock.patch.object(reconcile_device_credential, "reconcile_credential", return_value=outcome) as reconcile:
            out = run("reconcile_device_credential", credential_id=row.pk)
        reconcile.assert_called_once_with(row.pk)
        self.assertEqual(json.loads(out), {"credential_id": row.pk, "run_id": "run-1", "status": "SUCCESS", "code": "CURRENT_VERIFIED"})

    def test_reconcile_device_credential_refuses_unknown_ids_and_exits_on_uncertain(self):
        with mock.patch.object(reconcile_device_credential, "reconcile_credential") as reconcile:
            with self.assertRaisesRegex(CommandError, "^Unknown credential id.$"):
                run("reconcile_device_credential", credential_id=999999)
            reconcile.assert_not_called()
            reconcile.return_value = RotationOutcome(self.credential().pk, None, "UNCERTAIN", "BOTH_REJECTED")
            with self.assertRaises(SystemExit) as raised:
                run("reconcile_device_credential", credential_id=self.credential().pk)
        self.assertEqual(raised.exception.code, 1)


class RotateDueCommandTests(TestCase):
    def test_rotate_due_credentials_reports_each_outcome_as_json_and_text(self):
        outcomes = [RotationOutcome(4, "run-4", "SUCCESS", "ROTATED"), RotationOutcome(5, None, "SKIPPED", "NOT_DUE")]
        with mock.patch.object(rotate_due_credentials, "rotate_due_credentials", return_value=outcomes):
            as_json = json.loads(run("rotate_due_credentials", json=True))
            text = run("rotate_due_credentials")
        self.assertEqual(as_json, {"selected": 2, "outcomes": [
            {"credential_id": 4, "run_id": "run-4", "status": "SUCCESS", "code": "ROTATED"},
            {"credential_id": 5, "run_id": None, "status": "SKIPPED", "code": "NOT_DUE"}]})
        self.assertEqual(text, "Selected 2 due credential(s).\ncredential=4 run=run-4 SUCCESS ROTATED\ncredential=5 run=- SKIPPED NOT_DUE\n")

    def test_rotate_due_credentials_exits_non_zero_on_a_failed_rotation(self):
        for status in ("FAILED", "UNCERTAIN", "BLOCKED"):
            with self.subTest(case=f"refused {status}"), \
                    mock.patch.object(rotate_due_credentials, "rotate_due_credentials", return_value=[RotationOutcome(4, "r", status, "X")]), \
                    self.assertRaises(SystemExit) as raised:
                run("rotate_due_credentials", json=True)
            self.assertEqual(raised.exception.code, 1)


class RenderAndVerifyCommandTests(TestCase):
    def test_render_device_mfa_candidate_refuses_unknown_devices_and_renderer_errors(self):
        with self.subTest(case="refused unknown device"), self.assertRaisesRegex(CommandError, "^No two-factor policy for that device.$"):
            run("render_device_mfa_candidate", device="NOPE")
        before = DeviceLoginMfaPolicy.objects.get(device_name="R1").candidate_digest
        with self.subTest(case="refused renderer error"), \
                mock.patch.object(render_device_mfa_candidate, "render_candidate", side_effect=MfaConfigError("unsupported platform")), \
                self.assertRaisesRegex(CommandError, "^unsupported platform$"):
            run("render_device_mfa_candidate", device="R1", record_digest=True)
        self.assertEqual(DeviceLoginMfaPolicy.objects.get(device_name="R1").candidate_digest, before)

    def legacy_policy(self, state=MfaEnforcementState.ENFORCED):
        policy = DeviceLoginMfaPolicy.objects.get(device_name="R1")
        policy.mechanism, policy.enforcement_state = MfaMechanism.LEGACY_EOS_SSH_KEY_PASSWORD, state
        policy.last_verified_at = timezone.now() if state == MfaEnforcementState.LIVE_VERIFIED else None
        policy.save()
        private, public, fingerprint = mfa.generate_service_keypair("nmas-automation@r1")
        del private
        DeviceCredential.objects.filter(device_name="R1", username="nmas-automation").delete()
        DeviceCredential.objects.create(device_name="R1", platform="arista_ceos", username="nmas-automation", account_kind=AccountKind.SERVICE,
                                        auth_method=DeviceAuthMethod.PUBLICKEY_AND_PASSWORD, secret_ref=make_reference("tg-r1-service"),
                                        ssh_key_ref=make_reference("tg-r1-service-key"), ssh_public_key=public,
                                        ssh_public_key_fingerprint=fingerprint)
        return policy

    def probe(self, ok):
        provider = mock.Mock()
        provider.current.return_value = SimpleNamespace(value=FAKE_VALUE)
        return (mock.patch.object(verify_device_mfa.nsot_live, "get_live_target_metadata", return_value={"address": "192.0.2.1"}),
                mock.patch.object(verify_device_mfa, "FileSecretProvider", return_value=provider),
                mock.patch.object(verify_device_mfa, "load_ssh_private_key", return_value=object()),
                mock.patch.object(verify_device_mfa, "probe_two_factor_login", return_value={"key_only": "REJECT", "both": "ACCEPT" if ok else "REJECT"}),
                mock.patch.object(verify_device_mfa, "evaluate_probe", return_value=(ok, "PASS two-factor" if ok else "FAIL both rejected")))

    def test_verify_device_mfa_marks_a_passing_legacy_probe_live_verified(self):
        self.legacy_policy()
        patches = self.probe(True)
        with patches[0], patches[1], patches[2], patches[3] as probe, patches[4]:
            out = run("verify_device_mfa", device="R1", json=True)
        self.assertEqual(json.loads(out), {"device": "R1", "results": {"key_only": "REJECT", "both": "ACCEPT"}, "verdict": "PASS two-factor"})
        self.assertEqual(probe.call_args.args[1], "nmas-automation")
        self.assertNotIn(FAKE_VALUE, out)
        policy = DeviceLoginMfaPolicy.objects.get(device_name="R1")
        self.assertEqual((policy.enforcement_state, policy.last_verification_result), (MfaEnforcementState.LIVE_VERIFIED, "PASS two-factor"))
        self.assertIsNotNone(policy.last_verified_at)

    def test_verify_device_mfa_demotes_a_failed_probe_and_refuses_unready_policies(self):
        self.legacy_policy(MfaEnforcementState.LIVE_VERIFIED)
        patches = self.probe(False)
        with patches[0], patches[1], patches[2], patches[3], patches[4], self.assertRaises(SystemExit):
            run("verify_device_mfa", device="R1")
        self.assertEqual(DeviceLoginMfaPolicy.objects.get(device_name="R1").enforcement_state, MfaEnforcementState.ENFORCED)
        self.legacy_policy(MfaEnforcementState.PLANNED)
        with self.assertRaisesRegex(CommandError, "^Policy is not ENFORCED"):
            run("verify_device_mfa", device="R1")
        policy = DeviceLoginMfaPolicy.objects.get(device_name="R1")
        policy.mechanism = MfaMechanism.RADIUS_TOTP
        policy.save()
        with self.assertRaisesRegex(CommandError, "intentionally unavailable before controlled live rollout"):
            run("verify_device_mfa", device="R1")


class PrepareLinuxMetadataCommandTests(TestCase):
    def test_prepare_linux_metadata_creates_protected_items_and_a_valid_r3_candidate(self):
        with tempfile.TemporaryDirectory() as root:
            with mock.patch.object(device_credentials, "DEFAULT_STORE", Path(root, "store.json")):
                root_ref = make_reference("linux-root-shared")
                FileSecretProvider().initialize(root_ref, FAKE_VALUE)
                legacy = DeviceCredential.objects.get(device_name="R3", username="root")
                legacy.platform, legacy.account_kind, legacy.secret_ref = "ubuntu_frr", AccountKind.LEGACY_SHARED, root_ref
                legacy.save()
                with mock.patch("core.management.commands.prepare_linux_mfa_rollout_metadata.radius_secret_path",
                                return_value=Path(root, "radius_r3_secret")):
                    payload = json.loads(run("prepare_linux_mfa_rollout_metadata", device="R3", json=True))
                self.assertEqual(Path(root, "radius_r3_secret").stat().st_mode & 0o777, 0o600)
        self.assertEqual((payload["device"], payload["device_changed"], payload["created_protected_items"], payload["blockers"]),
                         ("R3", False, ["breakglass_password", "radius_secret", "service_key"], []))
        self.assertNotIn(FAKE_VALUE, json.dumps(payload))
        policy = DeviceLoginMfaPolicy.objects.get(device_name="R3")
        self.assertEqual((policy.mechanism, policy.enforcement_state, policy.central_aaa_state, policy.candidate_digest, policy.automation_exempt),
                         (MfaMechanism.RADIUS_TOTP, MfaEnforcementState.PLANNED, CentralAaaState.PLANNED, payload["candidate_digest"], True))
        self.assertEqual(sorted(DeviceCredential.objects.filter(device_name="R3").values_list("username", flat=True)),
                         ["nmas-admin", "nmas-automation", "r3-breakglass", "root"])
