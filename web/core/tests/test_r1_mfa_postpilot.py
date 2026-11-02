"""Post-pilot R1 2FA operations: ``verify-positive`` and ``record-verification``.

Fixture/simulator only (see ``test_r1_mfa_pilot``): an in-memory EOS model, a fake
privacyIDEA metadata runner and a simulated SSH -> RADIUS -> privacyIDEA path.  No test
contacts a device, a container or a real secret; every secret is a fake TEST-ONLY value.
"""
from __future__ import annotations

import ast
import datetime
import io
import json
import re
import subprocess
from unittest import mock

from django.core.management import call_command
from django.core.management.base import CommandError
from django.test import SimpleTestCase

from core.models import (AuditEvent, CentralAaaState, DeviceLoginMfaPolicy, MfaEnforcementState,
                         MfaMechanism)
from core.services.credentials import r1_pilot as p
from core.services.credentials import r1_pilot_runner as runner_module
from core.services.credentials.r1_pilot_runner import PilotEvidence, R1PilotRunner

from .test_r1_mfa_pilot import FAKE, HUMAN_OTP, HUMAN_PASSWORD, PilotHarness

R = p.PositiveResult


class FakePrivacyIdea:
    """Stands in for `docker exec -i <privacyIDEA> python -`: answers the fixed metadata script."""

    def __init__(self):
        self.token = {"serial": p.HUMAN_TOKEN_SERIAL, "type": "totp", "owner": p.HUMAN_USERNAME, "active": True,
                      "locked": False, "revoked": False, "failcount": 0, "maxfail": 10}
        self.audit: list[dict] = [{"id": 1088, "success": True, "authentication": "ACCEPT", "serial": p.HUMAN_TOKEN_SERIAL,
                                   "policies": "nmas-human-password-totp", "info": "matching 1 tokens"}]
        self.calls: list[dict] = []
        self.fail = False

    def __call__(self, argv, input=None, env=None, **kwargs):
        self.calls.append({"argv": list(argv), "input": input, "env": dict(env or {})})
        assert argv == ["docker", "exec", "-i", p.PRIVACYIDEA_APP_CONTAINER, p.PRIVACYIDEA_PYTHON, "-"], argv
        if self.fail:
            return subprocess.CompletedProcess(argv, 1, "", "boom")
        params = json.loads(ast.literal_eval(re.search(r"PARAMS = json\.loads\((.*)\)\n", input).group(1)))
        if params["kind"] == "token":
            out = dict(self.token)
        else:
            after = params["after_id"]
            out = {"max_id": max(r["id"] for r in self.audit),
                   "rows": [] if after is None else [r for r in self.audit if r["id"] > after]}
        return subprocess.CompletedProcess(argv, 0, "[INFO] loading users\nNMAS-JSON:" + json.dumps(out) + "\n", "")

    def add_row(self, accept: bool, info: str):
        self.audit.append({"id": self.audit[-1]["id"] + 1, "success": accept, "authentication": "ACCEPT" if accept else "REJECT",
                           "serial": p.HUMAN_TOKEN_SERIAL if accept else "", "policies": "nmas-human-password-totp", "info": info})
        if accept:
            self.token["failcount"] = 0
        else:
            self.token["failcount"] += 1


class CentralAuthPath:
    """Simulated SSH -> EOS -> FreeRADIUS -> privacyIDEA for ONE human attempt per scenario."""

    def __init__(self, eos, pi, scenario="success"):
        self.eos, self.pi, self.scenario = eos, pi, scenario
        self.attempts: list[tuple[str, str]] = []

    def _radius(self, **changes):
        for key, value in changes.items():
            self.eos.radius[key] += value

    def __call__(self, user: str, supplied: str) -> dict:
        self.attempts.append((user, supplied))
        s = self.scenario
        if s == "unreachable":
            return {"login": "UNREACHABLE", "stage": "connect", "error": "ConnectionRefusedError"}
        if s == "local_accept":  # accepted without touching RADIUS (e.g. an unexpected local nmas-admin)
            return {"login": "ACCEPT", "stage": "command", "command": "UNEXPECTED_LEVEL", "privilege_level": 1}
        if s == "radius_timeout":
            self._radius(**{"Messages sent": 1, "Requests timeout": 1})
            return {"login": "REJECT", "stage": "auth"}
        if s == "freeradius_no_privacyidea":
            self._radius(**{"Messages sent": 1, "Messages received": 1, "Requests rejected": 1})
            return {"login": "REJECT", "stage": "auth"}
        if s == "duplicate":
            self._radius(**{"Messages sent": 2, "Messages received": 2, "Requests rejected": 2})
            self.pi.add_row(False, "wrong otp pin")
            self.pi.add_row(False, "wrong otp pin")
            return {"login": "REJECT", "stage": "auth"}
        good = user == p.HUMAN_USERNAME and supplied == HUMAN_PASSWORD + HUMAN_OTP
        if s == "pi_reject" or not good:
            self._radius(**{"Messages sent": 1, "Messages received": 1, "Requests rejected": 1})
            self.pi.add_row(False, "wrong otp pin")
            return {"login": "REJECT", "stage": "auth"}
        self._radius(**{"Messages sent": 1, "Messages received": 1, "Requests accepted": 1})
        self.pi.add_row(True, "matching 1 tokens")
        if s == "eos_reject":
            return {"login": "REJECT", "stage": "auth"}
        if s == "denied":
            return {"login": "ACCEPT", "stage": "command", "command": "DENIED", "privilege_level": None}
        if s == "privilege_mismatch":
            return {"login": "ACCEPT", "stage": "command", "command": "UNEXPECTED_LEVEL", "privilege_level": 1}
        return {"login": "ACCEPT", "stage": "command", "command": "OK", "privilege_level": 15}


class PostPilotHarness(PilotHarness):
    def setUp(self):
        super().setUp()
        self.pi = FakePrivacyIdea()
        self.path = CentralAuthPath(self.eos, self.pi)
        self.deps.privacyidea = p.PrivacyIdeaReader(runner=self.pi)
        self.deps.human_login = self.path
        self.factor_calls = 0

        def factors():
            self.factor_calls += 1
            return HUMAN_PASSWORD, HUMAN_OTP

        self.deps.human_factors = factors

    def secrets_anywhere(self) -> list[str]:
        places = [" ".join(c["argv"]) for c in self.eos.calls + self.pi.calls]
        places += [json.dumps(c["env"]) for c in self.eos.calls + self.pi.calls]
        places += [c["input"] or "" for c in self.pi.calls]
        places += [json.dumps(e.metadata) + e.summary for e in AuditEvent.objects.all()]
        secrets = [*FAKE.values(), HUMAN_PASSWORD, HUMAN_PASSWORD + HUMAN_OTP]
        return [text for text in places for secret in secrets if secret in text]

    def confirmed_pilot(self):
        """Full reviewed pilot to a confirmed, persisted state (the live R1 shape)."""
        self.run_to_stage2()
        self.assertTrue(self.runner.verify("post-stage2")["PASS"])
        self.assertTrue(self.runner.confirm()["ok"])
        self.eos.startup = list(self.eos.running)  # `write memory`

    def policy(self):
        return DeviceLoginMfaPolicy.objects.get(device_name="R1")


# --------------------------------------------------------------------------- verify-positive
class VerifyPositiveTests(PostPilotHarness):
    def setUp(self):
        super().setUp()
        self.deps.ssh_login = mock.Mock(side_effect=AssertionError("verify-positive must not use the negative-test login path"))

    def _run(self, scenario):
        self.path.scenario = scenario
        return self.runner.verify_positive()

    def test_success_sends_exactly_one_attempt_and_no_negative_case(self):
        result = self._run("success")
        self.assertEqual(result["result"], R.AUTH_SUCCESS)
        self.assertTrue(result["PASS"])
        self.assertEqual(self.path.attempts, [(p.HUMAN_USERNAME, HUMAN_PASSWORD + HUMAN_OTP)])
        self.assertEqual(self.factor_calls, 1)
        self.deps.ssh_login.assert_not_called()  # no admin, no password-only, no wrong/expired/replayed OTP
        self.assertEqual(result["attempts"], 1)
        self.assertEqual(result["token_after"]["failcount"], 0)

    def test_command_denied_after_login_is_authentication_success(self):
        result = self._run("denied")
        self.assertEqual(result["result"], R.AUTH_SUCCESS_COMMAND_DENIED)
        self.assertTrue(result["PASS"])

    def test_authenticated_level_one_session_is_not_privileged_success(self):
        result = self._run("privilege_mismatch")
        self.assertEqual(result["result"], R.AUTH_SUCCESS_PRIVILEGE_MISMATCH)
        self.assertFalse(result["PASS"])

    def test_privacyidea_reject_is_attributed_with_sanitized_reason(self):
        result = self._run("pi_reject")
        self.assertEqual(result["result"], R.PRIVACYIDEA_REJECT)
        self.assertIn("wrong otp pin", result["reason"])
        self.assertFalse(result["PASS"])
        self.assertEqual(len(self.path.attempts), 1)

    def test_radius_transport_failures(self):
        self.assertEqual(self._run("radius_timeout")["result"], R.RADIUS_TRANSPORT_FAILURE)
        self.assertEqual(self._run("freeradius_no_privacyidea")["result"], R.RADIUS_TRANSPORT_FAILURE)

    def test_eos_reject_after_radius_accept(self):
        self.assertEqual(self._run("eos_reject")["result"], R.EOS_REJECT_AFTER_RADIUS_ACCEPT)

    def test_ssh_unreachable(self):
        result = self._run("unreachable")
        self.assertEqual(result["result"], R.R1_SSH_UNREACHABLE)
        self.assertFalse(result["PASS"])

    def test_unknown_when_evidence_cannot_attribute(self):
        self.assertEqual(self._run("duplicate")["result"], R.UNKNOWN)
        self.assertEqual(self._run("local_accept")["result"], R.UNKNOWN)  # never "success" without central evidence

    def test_unknown_when_post_attempt_audit_is_unreadable(self):
        fake = self.pi

        def audit_down_after_attempt(argv, input=None, **kw):
            if self.path.attempts and '"kind": "audit"' in input and '"after_id": null' not in input:
                return subprocess.CompletedProcess(argv, 1, "", "down")
            return fake(argv, input=input, **kw)

        self.deps.privacyidea = p.PrivacyIdeaReader(runner=audit_down_after_attempt)
        result = self._run("success")
        self.assertEqual(result["result"], R.UNKNOWN)
        self.assertEqual(len(self.path.attempts), 1)

    def _refused(self, pattern):
        before = AuditEvent.objects.count()
        with self.assertRaisesRegex(p.PilotError, pattern):
            self.runner.verify_positive()
        self.assertEqual(self.path.attempts, [], "a refused guard must send NO login attempt")
        self.assertEqual(self.factor_calls, 0, "factors are only requested after every guard passed")
        self.assertEqual(AuditEvent.objects.count(), before)

    def test_lockout_guard_prevents_attempt(self):
        self.pi.token["failcount"] = p.POSITIVE_FAILCOUNT_LIMIT
        self._refused("token_failcount_below_limit")

    def test_locked_revoked_inactive_or_foreign_token_prevents_attempt(self):
        for key, value, gate in (("locked", True, "token_not_locked"), ("revoked", True, "token_not_revoked"),
                                 ("active", False, "token_active"), ("owner", "fixture-mfa", "token_identity")):
            with self.subTest(key=key):
                original = self.pi.token[key]
                self.pi.token[key] = value
                self._refused(gate)
                self.pi.token[key] = original

    def test_unhealthy_freeradius_prevents_attempt(self):
        self.deps.infrastructure = lambda: (False, [p.FREERADIUS_CONTAINER])
        self._refused("freeradius_healthy")

    def test_unhealthy_privacyidea_prevents_attempt(self):
        self.deps.infrastructure = lambda: (False, ["nmas-human-mfa-pi-privacyidea-1"])
        self._refused("privacyidea_healthy")
        self.pi.fail = True
        self.deps.infrastructure = lambda: (True, [])
        self._refused("token_readable")

    def test_unreachable_r1_prevents_attempt(self):
        self.deps.reachable = lambda: False
        self._refused("r1_management_reachability")

    def test_malformed_factors_send_nothing(self):
        self.deps.human_factors = lambda: (HUMAN_PASSWORD, "12345")
        with self.assertRaisesRegex(p.PilotError, "NO login attempt"):
            self.runner.verify_positive()
        self.assertEqual(self.path.attempts, [])

    def test_factors_never_reach_argv_environment_output_or_evidence(self):
        result = self._run("success")
        self.assertEqual(self.secrets_anywhere(), [])
        rendered = json.dumps(result, default=str)
        self.assertNotIn(HUMAN_PASSWORD, rendered)
        self.assertNotIn(HUMAN_OTP, rendered)
        evidence = PilotEvidence().latest("verify:positive")
        self.assertEqual(evidence["result"], R.AUTH_SUCCESS)
        self.assertNotIn(HUMAN_OTP, json.dumps(evidence))
        self.assertNotIn(HUMAN_PASSWORD, json.dumps(evidence))

    def test_command_output_is_secret_free_and_policy_is_untouched(self):
        before = self.policy()
        out = io.StringIO()
        with mock.patch("core.management.commands.r1_mfa_pilot.R1PilotRunner", return_value=self.runner):
            call_command("r1_mfa_pilot", "verify-positive", stdout=out)
        self.assertNotIn(HUMAN_PASSWORD, out.getvalue())
        self.assertNotIn(HUMAN_OTP, out.getvalue())
        self.assertEqual(json.loads(out.getvalue())["result"], R.AUTH_SUCCESS)
        after = self.policy()
        self.assertEqual((before.enforcement_state, before.central_aaa_state, before.last_verified_at),
                         (after.enforcement_state, after.central_aaa_state, after.last_verified_at))

    def test_failed_attempt_makes_the_command_exit_nonzero(self):
        self.path.scenario = "pi_reject"
        with mock.patch("core.management.commands.r1_mfa_pilot.R1PilotRunner", return_value=self.runner):
            with self.assertRaises(CommandError):
                call_command("r1_mfa_pilot", "verify-positive", stdout=io.StringIO())


class AttributionTableTests(SimpleTestCase):
    ZERO = dict.fromkeys(("messages_sent", "messages_received", "requests_accepted", "requests_rejected",
                          "requests_timeout", "requests_retransmitted", "bad_responses", "connection_errors"), 0)

    def delta(self, **kw):
        return {**self.ZERO, **kw}

    def test_retransmission_is_not_a_second_request(self):
        row = {"authentication": "ACCEPT", "success": True}
        result, _ = p.attribute_positive_attempt({"login": "ACCEPT", "command": "OK"},
                                                 self.delta(messages_sent=2, requests_retransmitted=1, messages_received=1,
                                                            requests_accepted=1), [row])
        self.assertEqual(result, R.AUTH_SUCCESS)

    def test_privacyidea_accept_without_reply_on_r1_is_transport(self):
        row = {"authentication": "ACCEPT", "success": True}
        result, _ = p.attribute_positive_attempt({"login": "REJECT"}, self.delta(messages_sent=1, requests_timeout=1), [row])
        self.assertEqual(result, R.RADIUS_TRANSPORT_FAILURE)

    def test_missing_evidence_or_no_request_is_unknown(self):
        self.assertEqual(p.attribute_positive_attempt({"login": "REJECT"}, None, [])[0], R.UNKNOWN)
        self.assertEqual(p.attribute_positive_attempt({"login": "REJECT"}, self.delta(), [])[0], R.UNKNOWN)
        self.assertEqual(p.attribute_positive_attempt({"login": "ERROR SSHException"}, self.delta(), [])[0], R.UNKNOWN)

    def test_radius_counter_parser_matches_live_layout(self):
        text = ("RADIUS server             : 192.168.200.100, authentication port 1812, accounting port 1813\n"
                "             Messages sent:          9\n         Messages received:          9\n"
                "         Requests accepted:          2\n         Requests rejected:          7\n"
                "       Requests challenged:          0\n          Requests timeout:          0\n"
                "    Requests retransmitted:          0\n             Bad responses:          0\n"
                "         Connection errors:          0\n                DNS errors:          0\n"
                "RADIUS server-group: NMAS-HUMAN-MFA\n")
        counters = p.parse_radius_counters(text)
        self.assertEqual((counters["messages_sent"], counters["requests_accepted"], counters["requests_rejected"]), (9, 2, 7))
        with self.assertRaises(p.PilotError):
            p.parse_radius_counters("RADIUS server : none\n")

    def test_command_output_classification(self):
        self.assertEqual(p.classify_command_output("% Authorization denied for command 'show privilege'"), "DENIED")
        self.assertEqual(p.classify_command_output("Current privilege level is 15"), "OK")
        self.assertEqual(p.classify_command_output("Current privilege level is 1"), "UNEXPECTED_LEVEL")
        self.assertEqual(p.classify_command_output(""), "OTHER")


class SinglePasswordLoginTests(SimpleTestCase):
    """The real transport function: exactly one password auth, never a fallback or retry."""

    def _transport(self, *, auth_error=None, output=b"Current privilege level is 15\n"):
        import paramiko

        transport = mock.MagicMock()
        if auth_error:
            transport.auth_password.side_effect = auth_error
        transport.is_authenticated.return_value = auth_error is None
        channel = transport.open_session.return_value
        channel.makefile.return_value.read.return_value = output
        channel.makefile_stderr.return_value.read.return_value = b""
        return transport, paramiko

    def _login(self, transport, connect=None):
        with mock.patch("socket.create_connection", side_effect=connect, return_value=mock.MagicMock()) as conn, \
                mock.patch("paramiko.Transport", return_value=transport) as factory:
            result = runner_module.single_password_login("nmas-admin", "TESTONLYhumanPassword5123456")
        return result, conn, factory

    def test_exactly_one_password_auth_without_fallback(self):
        transport, _ = self._transport()
        result, _, _ = self._login(transport)
        transport.auth_password.assert_called_once_with("nmas-admin", "TESTONLYhumanPassword5123456", fallback=False)
        transport.auth_interactive.assert_not_called()
        self.assertEqual((result["login"], result["command"]), ("ACCEPT", "OK"))
        transport.close.assert_called_once()

    def test_rejected_auth_is_not_retried(self):
        import paramiko

        transport, _ = self._transport(auth_error=paramiko.AuthenticationException("no"))
        result, _, _ = self._login(transport)
        self.assertEqual(result["login"], "REJECT")
        self.assertEqual(transport.auth_password.call_count, 1)
        transport.open_session.assert_not_called()

    def test_authorization_denied_after_login(self):
        transport, _ = self._transport(output=b"% Authorization denied for command 'show privilege'\n")
        result, _, _ = self._login(transport)
        self.assertEqual((result["login"], result["command"]), ("ACCEPT", "DENIED"))

    def test_unreachable_sends_no_authentication(self):
        transport, _ = self._transport()
        result, _, factory = self._login(transport, connect=ConnectionRefusedError())
        self.assertEqual(result["login"], "UNREACHABLE")
        factory.assert_not_called()
        self.assertNotIn("TESTONLY", json.dumps(result))


# --------------------------------------------------------------------------- record-verification
class RecordVerificationTests(PostPilotHarness):
    def setUp(self):
        super().setUp()
        for name in ("R2", "S1"):
            DeviceLoginMfaPolicy.objects.update_or_create(device_name=name, defaults={
                "platform": "arista_ceos", "mechanism": MfaMechanism.RADIUS_TOTP,
                "radius_secret_ref": "runtime://human-mfa/radius/r1"})
        self.confirmed_pilot()
        self.fleet_before = list(DeviceLoginMfaPolicy.objects.exclude(device_name="R1").values())

    def _verification_evidence(self):
        return PilotEvidence().latest_entry("verify:post-stage2", ok=True)

    def test_transition_uses_the_evidence_timestamp_and_touches_only_r1(self):
        before = self.policy()
        self.assertEqual((before.enforcement_state, before.central_aaa_state), (MfaEnforcementState.ENFORCED, CentralAaaState.PLANNED))
        evidence_id, evidence = self._verification_evidence()
        self.clock.now += 86_400  # wall clock far from the evidence: it must not be substituted
        record = self.runner.record_verification()
        after = self.policy()
        self.assertEqual(after.central_aaa_state, CentralAaaState.VERIFIED)
        self.assertEqual(after.enforcement_state, MfaEnforcementState.LIVE_VERIFIED)
        self.assertEqual(after.last_verified_at, datetime.datetime.fromtimestamp(evidence["at"], tz=datetime.timezone.utc))
        self.assertNotEqual(after.last_verified_at.timestamp(), self.clock.now)
        self.assertEqual(after.last_verification_result, f"verify:post-stage2 PASS evidence#{evidence_id}")
        self.assertEqual(record["verification_evidence_id"], evidence_id)
        self.assertEqual(list(DeviceLoginMfaPolicy.objects.exclude(device_name="R1").values()), self.fleet_before)
        self.assertEqual(self.secrets_anywhere(), [])
        self.approval.assert_called()

    def _refused(self, gate):
        before = list(DeviceLoginMfaPolicy.objects.values())
        events = AuditEvent.objects.count()
        with self.assertRaisesRegex(p.PilotError, gate):
            self.runner.record_verification()
        self.assertEqual(list(DeviceLoginMfaPolicy.objects.values()), before, "a failed gate must not change any row")
        self.assertEqual(AuditEvent.objects.count(), events, "a failed gate must not write anything")

    # Evidence is append-only, so each gate is exercised by APPENDING a realistic newer record.
    def _append(self, step, at, **data):
        PilotEvidence().record(step, ok=True, known=p.SecretSet(), at=at, **data)

    def test_gate_missing_verification(self):
        self._append("stage2-armed", self.clock())  # re-armed Stage 2, never verified since
        self._refused("post_stage2_verification_passed")

    def test_gate_required_subcheck_false(self):
        _, verified = self._verification_evidence()
        confirm_at = PilotEvidence().latest("confirm", ok=True)["at"]
        for check in ("human_password_only_rejected", "admin_remote_login_rejected", "human_password_plus_totp_accepted"):
            with self.subTest(check=check):
                self._append("verify:post-stage2", confirm_at - 0.5, checks={**verified["checks"], check: False})
                self._refused("post_stage2_required_checks")
                self._append("verify:post-stage2", confirm_at - 0.5, checks=dict(verified["checks"]))

    def test_gate_missing_confirm(self):
        _, verified = self._verification_evidence()
        self._append("verify:post-stage2", self.clock(), checks=dict(verified["checks"]))  # no confirm after it
        self._refused("confirm_after_verification")

    def test_gate_confirm_digest_differs_from_current(self):
        self.eos.running.insert(-1, "ntp server 192.0.2.1")
        self.eos.startup = list(self.eos.running)
        self._refused("confirm_digest_is_current")

    def test_gate_timer_not_confirmed(self):
        self.eos.timer = (p.STAGE2_SESSION, 2_000_000.0)
        self._refused("timer_confirmed")

    def test_gate_not_persisted(self):
        self.eos.startup = list(self.original_lines)
        self._refused("startup_matches_running")

    def test_gate_open_config_session(self):
        self.eos.sessions["SOMEONE-ELSE"] = {"lines": list(self.eos.running), "state": "pending"}
        self._refused("no_open_config_session")

    def test_gate_policy_not_enforced(self):
        DeviceLoginMfaPolicy.objects.filter(device_name="R1").update(enforcement_state=MfaEnforcementState.PLANNED)
        self._refused("policy_enforced")

    def test_gate_rollback_after_confirm(self):
        PilotEvidence().record(f"replace:{p.CHECKPOINT_ORIGINAL}", ok=True, known=p.SecretSet(), at=self.clock())
        self._refused("no_rollback_since_confirm")

    def test_approval_is_required(self):
        self.approval.return_value = "yes"
        before = list(DeviceLoginMfaPolicy.objects.values())
        with self.assertRaisesRegex(p.PilotError, "Approval phrase"):
            self.runner.record_verification()
        self.assertEqual(list(DeviceLoginMfaPolicy.objects.values()), before)

    def test_other_devices_are_refused(self):
        with self.assertRaisesRegex(p.PilotError, "only targets"):
            R1PilotRunner(self.deps, device="R2").record_verification()
        with self.assertRaises(CommandError):
            call_command("r1_mfa_pilot", "record-verification", "--device", "R2", stdout=io.StringIO())

    def test_refused_evidence_write_rolls_back_the_row(self):
        with mock.patch.object(PilotEvidence, "record", side_effect=p.PilotError("secret")):
            with self.assertRaises(p.PilotError):
                self.runner.record_verification()
        self.assertEqual(self.policy().central_aaa_state, CentralAaaState.PLANNED)
        self.assertEqual(self.policy().enforcement_state, MfaEnforcementState.ENFORCED)

    def test_replace_resets_stale_verification_metadata(self):
        self.runner.record_verification()
        self.assertEqual(self.policy().central_aaa_state, CentralAaaState.VERIFIED)
        restored = self.runner.replace(p.CHECKPOINT_ORIGINAL)
        self.assertTrue(restored["ok"], restored)
        policy = self.policy()
        self.assertEqual((policy.enforcement_state, policy.central_aaa_state, policy.last_verified_at, policy.last_verification_result),
                         (MfaEnforcementState.PLANNED, CentralAaaState.PLANNED, None, ""))
        self.assertEqual(list(DeviceLoginMfaPolicy.objects.exclude(device_name="R1").values()), self.fleet_before)
        self.eos.startup = list(self.eos.running)
        self._refused("confirm_digest_is_current")  # cannot be re-marked after a rollback

    def test_status_reports_the_policy_row(self):
        self.runner.record_verification()
        status = self.runner.status()["policy"]
        self.assertEqual((status["enforcement_state"], status["central_aaa_state"]),
                         (MfaEnforcementState.LIVE_VERIFIED, CentralAaaState.VERIFIED))
        self.assertTrue(status["last_verified_at"])


class CommandSurfaceTests(SimpleTestCase):
    def test_new_operations_take_no_secret_or_approval_arguments(self):
        from core.management.commands.r1_mfa_pilot import OPERATIONS, Command

        self.assertIn("verify-positive", OPERATIONS)
        self.assertIn("record-verification", OPERATIONS)
        parser = Command().create_parser("manage.py", "r1_mfa_pilot")
        options = {a for action in parser._actions for a in action.option_strings}
        self.assertFalse(options & {"--approval", "--password", "--secret", "--otp", "--code", "--timestamp"})
