"""Lab 7 closure -- the cEOS MFA rollout runner's I/O helpers (``credentials/r1_pilot_runner.py``), each called directly.

No terminal, socket, SSH session or device is used: ``/dev/tty`` opens, ``getpass``, ``paramiko`` and the socket are
replaced, and the NSOT / config / Health reads are patched.  Every credential below is fake.  POSITIVE: the exact
approval line, the human factors, an accepted login with its privilege banner and command class, the read-path
summary and a target-bound dependency set.  NEGATIVE: no terminal, a rejected or failed login, an unreachable host,
unavailable reads and a device outside the reviewed set each fail closed -- and a password never reaches a result.
"""

from __future__ import annotations

from types import SimpleNamespace
from unittest import mock

import paramiko
from django.test import SimpleTestCase, TestCase

from core.models import DeviceCredential, DeviceLoginMfaPolicy
from core.services.credentials import r1_pilot as p
from core.services.credentials import mfa
from core.services.credentials import r1_pilot_runner as rr
from core.tests import test_r1_mfa_pilot as pilot

FAKE_PASSWORD = "fake-Password-value-77"


class FakeStream:
    def __init__(self, data=b""):
        self.data = data

    def read(self):
        return self.data


class FakeClient:
    def __init__(self, *, fail=None, banner=b"Current privilege level is 15\n"):
        self.fail, self.banner, self.connected, self.closed = fail, banner, None, 0

    def set_missing_host_key_policy(self, _policy):
        return None

    def connect(self, address, **kwargs):
        self.connected = (address, kwargs["username"], kwargs["look_for_keys"], kwargs["allow_agent"])
        if self.fail is not None:
            raise self.fail

    def exec_command(self, command, timeout=None):
        return None, FakeStream(self.banner), None

    def close(self):
        self.closed += 1


class TerminalTests(SimpleTestCase):
    def test_tty_readers_return_the_typed_line_and_factors(self):
        with mock.patch.object(rr, "_read_tty_line", return_value="APPLY R1 MFA ROLLOUT") as read:
            self.assertEqual(rr.tty_approval_reader("APPLY R1 MFA ROLLOUT"), "APPLY R1 MFA ROLLOUT")
        self.assertEqual(read.call_args.args[0], 'Type exactly "APPLY R1 MFA ROLLOUT" to proceed: ')
        with mock.patch("getpass.getpass", side_effect=[FAKE_PASSWORD, "123456"]):
            self.assertEqual(rr.tty_human_factor_reader(), (FAKE_PASSWORD, "123456"))

    def test_tty_approval_reader_without_a_terminal_is_refused(self):
        with mock.patch("os.open", side_effect=OSError("no tty")), self.assertRaisesRegex(p.PilotError, "interactive terminal is required"):
            rr.tty_approval_reader()


class LoginTests(SimpleTestCase):
    def test_paramiko_login_returns_the_privilege_banner_of_an_accepted_login(self):
        client = FakeClient()
        with mock.patch.object(paramiko, "SSHClient", return_value=client):
            found = rr.paramiko_login("nmas-automation", FAKE_PASSWORD, address="192.0.2.10")
        self.assertEqual(found, {"login": rr.ACCEPT, "privilege_level": 15, "privilege": "PASS"})
        self.assertEqual((client.connected, client.closed), (("192.0.2.10", "nmas-automation", False, False), 1))

    def test_paramiko_login_reports_a_rejection_or_failure_without_details(self):
        for name, error, expected in (("rejected", paramiko.AuthenticationException(FAKE_PASSWORD), {"login": rr.REJECT}),
                                      ("unreachable", OSError(FAKE_PASSWORD), {"login": "ERROR OSError"})):
            client = FakeClient(fail=error)
            with self.subTest(case=f"refused {name}"), mock.patch.object(paramiko, "SSHClient", return_value=client):
                found = rr.paramiko_login("nmas-automation", FAKE_PASSWORD)
                self.assertEqual((found, client.closed), (expected, 1))
                self.assertNotIn(FAKE_PASSWORD, str(found))

    def transport(self, *, authenticated=True, auth_error=None, output=b"Current privilege level is 15\n"):
        channel = mock.Mock()
        channel.makefile.return_value = FakeStream(output)
        channel.makefile_stderr.return_value = FakeStream(b"")
        transport = mock.Mock()
        transport.is_authenticated.return_value = authenticated
        transport.auth_password.side_effect = auth_error
        transport.open_session.return_value = channel
        return transport, channel

    def test_single_password_login_runs_one_read_only_command(self):
        transport, channel = self.transport()
        with mock.patch("socket.create_connection", return_value=object()), mock.patch.object(paramiko, "Transport", return_value=transport):
            found = rr.single_password_login("nmas-admin", FAKE_PASSWORD, address="192.0.2.10")
        self.assertEqual(found, {"login": rr.ACCEPT, "stage": "command", "command": "OK", "privilege_level": 15})
        transport.auth_password.assert_called_once_with("nmas-admin", FAKE_PASSWORD, fallback=False)
        channel.exec_command.assert_called_once_with("show privilege")
        transport.close.assert_called_once_with()

    def test_single_password_login_of_an_unreachable_host_or_rejected_password(self):
        with mock.patch("socket.create_connection", side_effect=ConnectionRefusedError()):
            self.assertEqual(rr.single_password_login("nmas-admin", FAKE_PASSWORD), {"login": "UNREACHABLE", "stage": "connect", "error": "ConnectionRefusedError"})
        rejected, _channel = self.transport(auth_error=paramiko.AuthenticationException())
        with mock.patch("socket.create_connection", return_value=object()), mock.patch.object(paramiko, "Transport", return_value=rejected):
            self.assertEqual(rr.single_password_login("nmas-admin", FAKE_PASSWORD), {"login": rr.REJECT, "stage": "auth"})
        rejected.open_session.assert_not_called()


class ReadPathAndTargetTests(TestCase):
    def reads(self, *, available=True):
        report = {"status": "PASS" if available else "FAIL", "results": [{"status": "PASS" if available else "FAIL", "check_code": "REACHABILITY"}]}
        return (mock.patch("core.services.nsot_live.get_live_target_metadata", return_value={"access_profiles": [{"username": "nmas-automation"}]}),
                mock.patch("core.services.nsot_live.fetch_running_config", return_value={"status": "available" if available else "unavailable"}),
                mock.patch("core.services.config_import.service.fetch_sanitized_running_config", return_value=({"sections": []} if available else None, "")),
                mock.patch("core.services.health.device.run_device_health", return_value=(None, report)))

    def test_nmas_read_paths_summarise_available_reads(self):
        patches = self.reads()
        with patches[0], patches[1], patches[2], patches[3]:
            found = rr.nmas_read_paths("R1")
        self.assertEqual((found["target_identities"], found["nsot"], found["config_retrieval"], found["health"], found["health_blocking"]),
                         (["nmas-automation"], True, True, True, []))
        self.assertEqual(set(found["other_identities"]), set(p.MANAGED_CEOS_MFA_DEVICES) - {"R1"})

    def test_nmas_read_paths_report_unavailable_reads_as_false(self):
        patches = self.reads(available=False)
        with patches[0], patches[1], patches[2], patches[3]:
            found = rr.nmas_read_paths("R1")
        self.assertEqual((found["nsot"], found["config_retrieval"], found["health"]), (False, False, False))
        self.assertEqual(found["health_blocking"], [{"check_code": "REACHABILITY", "status": "FAIL", "message": ""}])

    def test_reviewed_candidate_and_runner_bind_to_one_target(self):
        target = p.target_for("R1")
        DeviceCredential.objects.filter(device_name="R1").delete()
        DeviceLoginMfaPolicy.objects.filter(device_name="R1").delete()
        pilot._policy().save()
        for account in pilot._accounts():
            account.save()
        candidate = rr.reviewed_candidate(target)
        expected = p.staged_candidate(mfa.render_candidate(pilot._policy(), pilot._accounts()), target)
        self.assertEqual((candidate.digest, candidate.stage1, candidate.stage2), (expected.digest, expected.stage1, expected.stage2))
        self.assertEqual([line.split()[1] for line in candidate.stage1], ["nmas-automation", "r1-breakglass"])
        runner = rr.R1PilotRunner(device="R1")
        self.assertEqual((runner.device, runner.target, runner.deps.transport.container, runner.deps.evidence.device), ("R1", target, target.container, "R1"))
        with mock.patch.object(p, "management_reachable", return_value=True) as reachable:
            deps = rr.dependencies_for(target)
            self.assertTrue(deps.reachable())
        reachable.assert_called_once_with(target.management_address)

    def test_reviewed_candidate_and_dependencies_refuse_a_device_without_policy_or_outside_the_set(self):
        target = p.target_for("R1")
        with self.assertRaisesRegex(p.PilotError, "^Renderer blockers: NO_LOCAL_NMAS_SERVICE_IDENTITY"):
            rr.reviewed_candidate(target)                                       # the seeded R1 has no reviewed identities yet
        DeviceLoginMfaPolicy.objects.filter(device_name="R1").delete()
        with self.assertRaises(DeviceLoginMfaPolicy.DoesNotExist):
            rr.reviewed_candidate(target)
        with self.assertRaises(p.PilotError):
            rr.dependencies_for(p.target_for("R3"))
        deps = rr.dependencies_for(target)
        with mock.patch.object(rr, "paramiko_login", return_value={"login": rr.REJECT}) as login:
            self.assertEqual(deps.ssh_login("nmas-automation", FAKE_PASSWORD), {"login": rr.REJECT})
        login.assert_called_once_with("nmas-automation", FAKE_PASSWORD, address=target.management_address)
