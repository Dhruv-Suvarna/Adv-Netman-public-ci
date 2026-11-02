"""Lab 7 closure -- Linux (R3/R4) MFA rollout helpers (``credentials/linux_mfa.py``), each called directly.

Nothing reaches a device: docker / systemd commands go to a recording runner, paramiko and the socket are mocked, and
protected runtime files live in a private temporary directory.  POSITIVE: exact rendered PAM / sshd / sudoers text,
backup and hash evidence, timer identities and login outcomes.  NEGATIVE: a malformed token, a non-zero exit, unsafe
or missing protected material, an authentication rejection or an unknown diagnostic each fail closed, the protected
response or password never reaches argv or an error message, and the service account is never granted sudo.
"""

from __future__ import annotations

import shutil
import subprocess
import tempfile
from pathlib import Path
from unittest import mock

import paramiko
from django.test import SimpleTestCase, TestCase

from core.models import DeviceCredential, DeviceLoginMfaPolicy
from core.services.credentials import linux_mfa as lm
from core.tests import test_linux_mfa_rollout as lr

R3 = lm.TARGETS["R3"]
TOKEN = "0123456789abcdef01234567"
PROTECTED = "Zx9-protected-response-value"                 # fake


class Runner:
    def __init__(self, stdout="", returncode=0):
        self.stdout, self.returncode, self.calls = stdout, returncode, []

    def __call__(self, argv, **kw):
        self.calls.append((list(argv), kw))
        return subprocess.CompletedProcess(argv, self.returncode, self.stdout, "")


class ActivationDiagnosticsTests(SimpleTestCase):
    def test_sanitize_activation_trace_keeps_known_stage_status_and_timing(self):
        trace = [{"stage": "reload_sshd", "status": "completed", "at": 3, "return_code": 0, "stderr": PROTECTED}]
        self.assertEqual(lm.sanitize_activation_trace(trace), [{"stage": "reload_sshd", "status": "completed", "at": 3.0, "return_code": 0}])

    def test_sanitize_activation_trace_drops_unknown_or_malformed_events(self):
        for label, value in (("not a list", {"stage": "reload_sshd"}), ("unknown stage", [{"stage": "rm -rf", "status": "completed"}]),
                             ("unknown status", [{"stage": "reload_sshd", "status": PROTECTED}]), ("not a mapping", ["reload_sshd"])):
            with self.subTest(case=f"invalid {label}"):
                self.assertEqual(lm.sanitize_activation_trace(value), [])

    def test_activation_error_with_unknown_values_falls_back_to_fixed_categories(self):
        error = lm.LinuxMfaActivationError(stage=PROTECTED, return_code="1", exception_class=PROTECTED, stage_trace=None, helper_return_code="x")
        self.assertEqual((error.stage, error.return_code, error.exception_class, error.helper_return_code, error.stage_trace),
                         ("post_reload_configuration_inspection", None, "ActivationError", None, []))
        self.assertNotIn(PROTECTED, str(error))


class RenderedPolicyTests(SimpleTestCase):
    def test_target_for_a_managed_linux_router(self):
        self.assertEqual((lm.target_for("R4").address, lm.target_for("R4").breakglass_username), ("192.168.200.4", "r4-breakglass"))

    def test_pam_sshd_sends_only_the_human_through_radius(self):
        text = lm.pam_sshd()
        self.assertIn("auth [success=2 default=ignore] pam_succeed_if.so quiet user = nmas-admin", text)
        self.assertIn("auth required pam_radius_auth.so conf=/etc/pam_radius_auth.conf client_id=nmas-linux-ssh", text)

    def test_sshd_dropin_separates_human_service_and_recovery_logins(self):
        text = lm.sshd_dropin(R3)
        self.assertIn(f"AllowUsers nmas-admin@{lm.NMAS_ADDRESS} nmas-automation@{lm.NMAS_ADDRESS} r3-breakglass@{lm.NMAS_ADDRESS}", text)
        self.assertIn("PermitRootLogin no", text)
        self.assertIn(f"Match User nmas-admin Address {lm.NMAS_ADDRESS}\n    AuthenticationMethods keyboard-interactive:pam", text)

    def test_sudoers_grants_the_human_and_recovery_accounts(self):
        self.assertEqual(lm.sudoers(R3), "# Interactive privilege follows a successful MFA/emergency SSH login.\n"
                                         "nmas-admin ALL=(ALL:ALL) NOPASSWD: ALL\nr3-breakglass ALL=(ALL:ALL) NOPASSWD: ALL\n")

    def test_sudoers_never_grants_the_service_account(self):
        self.assertNotIn(lm.SERVICE_USERNAME, lm.sudoers(lm.TARGETS["R4"]))


class ProtectedMaterialTests(SimpleTestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.root)

    def test_radius_secret_path_is_the_device_store_under_the_runtime_tree(self):
        self.assertEqual(lm.radius_secret_path("R3", self.root), self.root / "monitoring/runtime/human-mfa/secrets/radius_r3_secret")

    def test_radius_secret_path_never_touches_the_store(self):
        path = lm.radius_secret_path("R4", self.root)
        self.assertFalse(path.exists() or path.parent.exists())

    def test_private_runtime_value_reads_a_private_single_token_file(self):
        path = self.root / "value"
        path.write_text(PROTECTED + "\n")
        path.chmod(0o600)
        self.assertEqual(lm.private_runtime_value(path), PROTECTED)

    def test_private_runtime_value_refuses_missing_unsafe_or_malformed_material(self):
        public, spaced, link = self.root / "public", self.root / "spaced", self.root / "link"
        public.write_text(PROTECTED)
        public.chmod(0o644)
        spaced.write_text("two words")
        spaced.chmod(0o600)
        link.symlink_to(spaced)
        for label, path, message in (("missing", self.root / "absent", "Protected runtime material is missing."),
                                     ("world readable", public, "Protected runtime material has unsafe permissions."),
                                     ("symlink", link, "Protected runtime material has unsafe permissions."),
                                     ("whitespace", spaced, "Protected runtime material is invalid.")):
            with self.subTest(case=f"refused {label}"), self.assertRaises(lm.LinuxMfaError) as caught:
                lm.private_runtime_value(path)
            self.assertEqual(str(caught.exception), message)


class ReviewedCandidateTests(TestCase):
    def test_reviewed_candidate_renders_the_stored_policy_and_accounts(self):
        helper = lr.LinuxMfaModelAndRenderTests()
        DeviceLoginMfaPolicy.objects.filter(device_name="R3").delete()
        DeviceCredential.objects.filter(device_name="R3").delete()
        helper.policy().save()
        for row in helper.rows():
            row.save()
        candidate = lm.reviewed_candidate(R3)
        self.assertEqual((candidate.supported, candidate.blockers), (True, []))

    def test_reviewed_candidate_refuses_a_device_without_a_stored_policy(self):
        DeviceLoginMfaPolicy.objects.filter(device_name="R3").delete()
        with self.assertRaises(DeviceLoginMfaPolicy.DoesNotExist):
            lm.reviewed_candidate(R3)


class TransportTests(SimpleTestCase):
    def test_run_and_python_execute_in_the_target_container(self):
        runner = Runner(stdout="ok\n")
        transport = lm.DockerTransport(R3, runner=runner)
        self.assertEqual(transport.run(["id", "-un"]).stdout, "ok\n")
        transport.python("print(1)", "arg", secret_input=PROTECTED)
        self.assertEqual(runner.calls[0][0], ["docker", "exec", "-i", "clab-srlceos01-R3", "id", "-un"])
        self.assertEqual(runner.calls[1][0], ["docker", "exec", "-i", "clab-srlceos01-R3", "python3", "-c", "print(1)", "arg"])

    def test_run_and_python_never_put_protected_input_in_argv(self):
        runner = Runner(returncode=1)
        result = lm.DockerTransport(R3, runner=runner).python("print(1)", secret_input=PROTECTED)
        self.assertEqual(result.returncode, 1)
        self.assertNotIn(PROTECTED, " ".join(runner.calls[0][0]))
        self.assertEqual((runner.calls[0][1]["input"], runner.calls[0][1]["check"]), (PROTECTED, False))
        self.assertIsNone(lm.DockerTransport(R3, runner=runner).run(["true"]).stderr or None)

    def test_backup_records_its_root_and_evidence(self):
        runner = Runner(stdout='{"files": 3}')
        self.assertEqual(lm.backup(lm.DockerTransport(R3, runner=runner), TOKEN), {"root": f"/run/nmas-linux-mfa/r3/{TOKEN}", "files": 3})
        self.assertEqual(runner.calls[0][0][-1], "r3-breakglass")

    def test_backup_refuses_a_bad_token_a_failed_copy_or_invalid_evidence(self):
        for label, runner, token, message in (("bad token", Runner(), "../../etc", "Invalid rollback token."),
                                              ("failed copy", Runner(returncode=1), TOKEN, "Device-local configuration backup failed."),
                                              ("invalid evidence", Runner(stdout="not json"), TOKEN, "Device-local backup evidence was invalid.")):
            with self.subTest(case=f"failure {label}"), self.assertRaises(lm.LinuxMfaError) as caught:
                lm.backup(lm.DockerTransport(R3, runner=runner), token)
            self.assertEqual(str(caught.exception), message)
            if label == "bad token":
                self.assertEqual(runner.calls, [])

    def test_config_hashes_parse_the_device_report(self):
        found = lm.config_hashes(lm.DockerTransport(R3, runner=Runner(stdout='{"sshd_valid": true}')))
        self.assertEqual(found, {"sshd_valid": True})

    def test_config_hashes_of_an_unreadable_device_raise(self):
        with self.assertRaises(lm.LinuxMfaError):
            lm.config_hashes(lm.DockerTransport(R3, runner=Runner(returncode=2)))


class TimerTests(SimpleTestCase):
    def test_timer_unit_names_device_and_token(self):
        self.assertEqual(lm.timer_unit("R4", TOKEN), f"nmas-linux-mfa-r4-{TOKEN}")

    def test_arm_timer_refuses_a_bad_identity_or_a_failed_systemd_run(self):
        runner = Runner()
        with self.assertRaises(lm.LinuxMfaError):
            lm.arm_timer("R5", TOKEN, runner=runner)
        self.assertEqual(runner.calls, [])
        with self.assertRaises(lm.LinuxMfaError):
            lm.arm_timer("R3", TOKEN, runner=Runner(returncode=1))

    def test_timer_active_and_cancel_timer_on_a_running_timer(self):
        runner = Runner()
        self.assertTrue(lm.timer_active("R3", TOKEN, runner=runner))
        lm.cancel_timer("R3", TOKEN, runner=runner)
        self.assertEqual(runner.calls[1][0], ["systemctl", "--user", "stop", f"nmas-linux-mfa-r3-{TOKEN}.timer"])

    def test_timer_active_false_and_cancel_timer_raises_when_systemd_refuses(self):
        self.assertFalse(lm.timer_active("R3", TOKEN, runner=Runner(returncode=3)))
        with self.assertRaises(lm.LinuxMfaError):
            lm.cancel_timer("R3", TOKEN, runner=Runner(returncode=5))


def ssh_client(output=b"nmas-automation\n", connect_error=None):
    client = mock.MagicMock()
    client.connect.side_effect = connect_error
    stdout = mock.MagicMock()
    stdout.read.return_value = output
    client.exec_command.return_value = (None, stdout, None)
    return client


class SshLoginTests(SimpleTestCase):
    def test_ssh_key_and_password_logins_accept_the_expected_identity(self):
        client = ssh_client()
        with mock.patch("paramiko.SSHClient", return_value=client), mock.patch.object(lm, "load_ssh_private_key", return_value="key"):
            self.assertEqual(lm.ssh_key_login(R3), {"login": "ACCEPT"})
        with mock.patch("paramiko.SSHClient", return_value=ssh_client(b"0\n")):
            self.assertEqual(lm.ssh_password_login(R3, "r3-breakglass", PROTECTED, privileged=True), {"login": "ACCEPT", "privileged": True})
        client.close.assert_called_once_with()

    def test_ssh_key_and_password_logins_report_reject_or_error_never_the_secret(self):
        for label, error, expected in (("rejected", paramiko.AuthenticationException("no"), {"login": "REJECT"}),
                                       ("unreachable", OSError(PROTECTED), {"login": "ERROR", "error": "OSError"})):
            with self.subTest(case=f"failure {label}"):
                client = ssh_client(connect_error=error)
                with mock.patch("paramiko.SSHClient", return_value=client), mock.patch.object(lm, "load_ssh_private_key", return_value="key"):
                    self.assertEqual(lm.ssh_key_login(R3), expected)
                    self.assertEqual(lm.ssh_password_login(R3, "nmas-admin", PROTECTED), expected)
                self.assertNotIn(PROTECTED, str(expected))
                self.assertEqual(client.close.call_count, 2)

    def transport(self, authenticated=True, output=b"0\n"):
        transport = mock.MagicMock()
        transport.is_authenticated.return_value = authenticated
        transport.open_session.return_value.makefile.return_value.read.return_value = output
        return transport

    def test_ssh_keyboard_login_answers_the_first_prompt_once(self):
        transport = self.transport()
        with mock.patch("socket.create_connection", return_value=mock.MagicMock()), mock.patch("paramiko.Transport", return_value=transport):
            self.assertEqual(lm.ssh_keyboard_login(R3, PROTECTED), {"login": "ACCEPT", "privileged": True})
        user, handler = transport.auth_interactive.call_args[0]
        self.assertEqual((user, handler("", "", [("Password:", False), ("OTP:", False)])), ("nmas-admin", [PROTECTED, ""]))
        self.assertEqual(handler("", "", [("Password:", False)]), [""])                      # answered once only
        transport.close.assert_called_once_with()

    def test_ssh_keyboard_login_rejected_or_unreachable(self):
        with mock.patch("socket.create_connection", return_value=mock.MagicMock()), mock.patch("paramiko.Transport", return_value=self.transport(False)):
            self.assertEqual(lm.ssh_keyboard_login(R3, PROTECTED), {"login": "REJECT"})
        with mock.patch("socket.create_connection", side_effect=OSError("timeout")):
            self.assertEqual(lm.ssh_keyboard_login(R3, PROTECTED), {"login": "ERROR", "error": "OSError"})
