"""Lab 7 closure -- cEOS credential rotation: the password adapter (``credentials/platforms.py``) and the commit-timer
transaction controller (``credentials/ceos_transaction.py``), each public method called directly.

Nothing reaches a device: the adapter gets a recording fake controller and a fake connection factory; the controller
drives the in-memory EOS model of ``test_r1_mfa_pilot`` through an injected runner.  POSITIVE: each step returns the
controller's / device's exact result.  NEGATIVE: every controller error is translated to the adapter's fail-closed
class with its code and evidence, an open session / unreachable management / unreadable state refuses the step
BEFORE any write, and no credential value ever appears in an exception.
"""

from __future__ import annotations

import subprocess
import traceback
from types import SimpleNamespace
from unittest import mock

from django.test import SimpleTestCase, TestCase

from core.models import DeviceCredential
from core.services.credentials import ceos_transaction as ct
from core.services.credentials import platforms as pf
from core.services.credentials import r1_pilot as eos
from modules.device_credentials import SecretProviderError, make_reference

OLD, NEW = "old-test-credential-value", "new-test-credential-value"          # fakes
CRED = SimpleNamespace(device_name="R1", platform="arista_ceos", username="nmas-automation", ssh_key_ref="", privilege_level=15, account_role="network-admin")
TARGET = {"platform": "ceos", "address": "192.0.2.1", "access_profiles": ()}
TX = ct.SafeDeviceTransaction("NMAS-CR-R1-0123456789", "/mnt/flash/c.cfg", "s", "m", "pre", "post", ct.COMMIT_TIMER, {})


class FakeController:
    """Records each call; returns a tagged value or raises the configured error."""

    def __init__(self, error=None):
        self.error, self.calls = error, []

    def __getattr__(self, name):
        def call(*args, **kw):
            self.calls.append(name)
            if self.error is not None:
                raise self.error
            return {"step": name}

        return call


def live_target(value=TARGET):
    return mock.patch("core.services.nsot_live.get_live_target_metadata", return_value=value)


class Conn:
    def __init__(self, hostname="R1", error=None):
        self.hostname, self.error, self.closed = hostname, error, False

    def send_command(self, command, **kw):
        if self.error:
            raise self.error
        return f"Hostname: {self.hostname}\nFQDN: {self.hostname}\n"

    def disconnect(self):
        self.closed = True


class AdapterDelegationTests(SimpleTestCase):
    def test_each_transaction_step_returns_the_controller_result(self):
        controller = FakeController()
        adapter = pf.CeosPasswordAdapter(transaction_controller=controller)
        with live_target():
            self.assertIsNone(adapter.preflight(CRED))
        self.assertEqual(adapter.arm_transaction(CRED, OLD, NEW, "0123456789abcdef"), {"step": "arm"})
        self.assertEqual(adapter.operational_validate(CRED, TX), {"step": "validate"})
        self.assertEqual(adapter.confirm_transaction(CRED, TX), {"step": "confirm"})
        self.assertEqual(adapter.persist_transaction(CRED, TX), {"step": "persist"})
        self.assertEqual(adapter.inspect_recovery(CRED, TX), {"step": "inspect"})
        self.assertEqual(adapter.complete_recovery(CRED, TX), {"step": "complete_recovery"})
        self.assertEqual(controller.calls, ["preflight", "arm", "validate", "confirm", "persist", "inspect", "complete_recovery"])

    def test_each_controller_error_is_translated_with_its_code_and_evidence(self):
        evidence = {"stage": "x"}
        cases = (("arm_transaction", (CRED, OLD, NEW, "0123456789abcdef"), ct.CeosTransactionRejected("OPEN_CONFIGURATION_SESSION", evidence=evidence), pf.DeviceChangeRejected),
                 ("operational_validate", (CRED, TX), ct.CeosOperationalValidationFailed("HEALTH_VALIDATION_FAILED", evidence=evidence), pf.OperationalValidationFailed),
                 ("confirm_transaction", (CRED, TX), ct.CeosConfirmationFailed("COMMIT_TIMER_NOT_ARMED", evidence=evidence), pf.TransactionConfirmationFailed),
                 ("persist_transaction", (CRED, TX), ct.CeosPersistenceFailed("PERSISTENCE_STATE_MISMATCH", evidence=evidence), pf.PersistenceFailed),
                 ("inspect_recovery", (CRED, TX), ct.CeosTransactionUncertain("RECOVERY_STATE_UNAVAILABLE", evidence=evidence), pf.DeviceChangeUncertain),
                 ("complete_recovery", (CRED, TX), ct.CeosPersistenceFailed("PERSISTENCE_NOT_VERIFIED", evidence=evidence), pf.PersistenceFailed))
        for method, args, error, translated in cases:
            adapter = pf.CeosPasswordAdapter(transaction_controller=FakeController(error))
            with self.subTest(case=f"failure {method}"), self.assertRaises(translated) as caught:
                getattr(adapter, method)(*args)
            self.assertEqual((caught.exception.code, caught.exception.evidence), (error.code, evidence))
            self.assertNotIn(NEW, "".join(traceback.format_exception(caught.exception)))

    def test_preflight_refuses_a_target_that_is_not_ceos_before_the_controller(self):
        controller = FakeController()
        with live_target({"platform": "linux"}), self.assertRaises(pf.PlatformNotImplemented):
            pf.CeosPasswordAdapter(transaction_controller=controller).preflight(CRED)
        self.assertEqual(controller.calls, [])

    def test_adapter_for_a_ceos_credential(self):
        self.assertIsInstance(pf.adapter_for(CRED, connection_factory=None), pf.CeosPasswordAdapter)

    def test_adapter_for_an_unsupported_platform_raises(self):
        with self.assertRaises(pf.PlatformNotImplemented):
            pf.adapter_for(SimpleNamespace(platform="ubuntu_frr"))


class AdapterLoginTests(SimpleTestCase):
    def adapter(self, factory):
        return pf.CeosPasswordAdapter(connection_factory=factory, transaction_controller=FakeController())

    def test_ssh_auth_kwargs_load_an_enrolled_key(self):
        found = pf.ssh_auth_kwargs(SimpleNamespace(ssh_key_ref="runtime://device-credentials/r1-key"), key_loader=lambda ref: "PKEY")
        self.assertEqual(found, {"use_keys": True, "pkey": "PKEY", "allow_agent": False})

    def test_ssh_auth_kwargs_none_without_a_key_and_refused_when_the_key_is_unavailable(self):
        self.assertEqual(pf.ssh_auth_kwargs(SimpleNamespace(ssh_key_ref="")), {})

        def missing(_ref):
            raise SecretProviderError("gone")

        with self.assertRaises(pf.CurrentLoginFailed) as caught:
            pf.ssh_auth_kwargs(SimpleNamespace(ssh_key_ref="runtime://device-credentials/r1-key"), key_loader=missing)
        self.assertEqual(caught.exception.code, "SSH_KEY_UNAVAILABLE")

    def test_verify_password_and_probe_password_with_the_new_login(self):
        conn = Conn()
        with live_target():
            self.assertIsNone(self.adapter(lambda *a, **k: conn).verify_password(CRED, NEW))
            self.assertEqual(self.adapter(lambda *a, **k: Conn()).probe_password(CRED, NEW), "ACCEPT")
        self.assertTrue(conn.closed)

    def test_verify_password_and_probe_password_never_trust_a_rejected_or_wrong_login(self):
        def rejected(*_a, **_k):
            raise pf.CredentialAuthenticationRejected()

        def broken(*_a, **_k):
            raise OSError(NEW)

        with live_target():
            for label, factory, code in (("wrong device", lambda *a, **k: Conn("R2"), "NEW_LOGIN_IDENTITY_MISMATCH"),
                                         ("rejected login", rejected, pf.NewLoginVerificationFailed.code),
                                         ("broken session", lambda *a, **k: Conn(error=OSError(NEW)), pf.NewLoginVerificationFailed.code)):
                with self.subTest(case=f"failure {label}"), self.assertRaises(pf.NewLoginVerificationFailed) as caught:
                    self.adapter(factory).verify_password(CRED, NEW)
                self.assertEqual(caught.exception.code, code)
                self.assertNotIn(NEW, "".join(traceback.format_exception(caught.exception)))
            self.assertEqual((self.adapter(rejected).probe_password(CRED, OLD), self.adapter(broken).probe_password(CRED, OLD)), ("REJECT", "ERROR"))


R1_CONFIG = """! Command: show running-config
hostname R1
username nmas-automation privilege 15 role network-admin secret sha512 {old_hash}
interface Vlan200
   ip address 192.168.200.1/24
end"""


class TransactionValueTests(SimpleTestCase):
    def test_transaction_exception_carries_code_and_evidence(self):
        error = ct.CeosTransactionRejected("OPEN_CONFIGURATION_SESSION", evidence={"open": ["X"]})
        self.assertEqual((error.code, error.evidence, str(error)), ("OPEN_CONFIGURATION_SESSION", {"open": ["X"]}, "OPEN_CONFIGURATION_SESSION"))

    def test_transaction_error_without_a_code_uses_the_class_default_and_no_evidence(self):
        error = ct.CeosPersistenceFailed()
        self.assertEqual((error.code, error.evidence), ("PERSISTENCE_FAILED", {}))

    def test_from_run_reads_columns_then_metadata(self):
        run = SimpleNamespace(session_name="S", checkpoint_file="", checkpoint_sha256="a", checkpoint_md5="b", pre_change_digest="p", post_change_digest="q",
                              transaction_metadata={"checkpoint_file": "/mnt/flash/c.cfg", "commit_timer": "00:05:00", "baseline": {"x": 1}})
        self.assertEqual(ct.SafeDeviceTransaction.from_run(run), ct.SafeDeviceTransaction("S", "/mnt/flash/c.cfg", "a", "b", "p", "q", "00:05:00", {"x": 1}))

    def test_from_run_without_any_recorded_state_is_blank_with_the_default_timer(self):
        run = SimpleNamespace(session_name="", checkpoint_file="", checkpoint_sha256="", checkpoint_md5="", pre_change_digest="", post_change_digest="", transaction_metadata=None)
        self.assertEqual(ct.SafeDeviceTransaction.from_run(run), ct.SafeDeviceTransaction("", "", "", "", "", "", ct.COMMIT_TIMER, {}))

    def test_normalized_digest_ignores_volatile_headers_and_command_echo(self):
        self.assertEqual(ct.normalized_digest("! Command: show running-config\nhostname R1\n"), ct.normalized_digest("> show running-config\nhostname R1"))

    def test_normalized_digest_of_a_tampered_config_differs(self):
        self.assertNotEqual(ct.normalized_digest("hostname R1\n"), ct.normalized_digest("hostname R1\nusername x\n"))


class TransactionControllerTests(TestCase):
    def setUp(self):
        from core.tests.test_r1_mfa_pilot import FakeEos, _hash

        self.fake = FakeEos(R1_CONFIG.format(old_hash=_hash(OLD)))
        self.credential = DeviceCredential.objects.create(device_name="R1", platform="arista_ceos", username="nmas-automation",
                                                          secret_ref=make_reference("r1-transaction-closure"), account_role="network-admin", privilege_level=15)
        self.reachable = True
        self.controller = ct.CeosRotationTransactionController(transport_factory=lambda target: eos.EosCliTransport(container=target.container, runner=self.runner),
                                                               read_paths=lambda device: {}, reachable=lambda address: self.reachable)
        self.broken = False

    def runner(self, argv, **kw):
        if self.broken:
            raise OSError("docker unavailable")
        return self.fake(argv, **kw)

    def writes(self):
        return [c for c in self.fake.calls if c["argv"][-3:] == ["Cli", "-p", "15"]]

    def healthy_paths(self, tx):
        return lambda device: {"health": True, "health_blocking": [], "health_status": "HEALTHY", "health_tolerated_warnings": [], "nsot": True,
                               "config_retrieval": True, "target_identities": ["nmas-automation", "admin"], "other_identities": tx.baseline["other_identities"]}

    def test_controller_without_injected_readers_never_constructs_a_transport(self):
        controller = ct.CeosRotationTransactionController()
        self.assertIs(controller.read_paths, ct.nmas_read_paths)
        self.assertIs(controller.reachable, eos.management_reachable)
        self.assertEqual(self.fake.calls, [])

    def test_preflight_holds_on_a_quiet_reachable_device(self):
        self.assertIsNone(self.controller.preflight(self.credential))
        self.assertEqual(self.writes(), [])

    def test_preflight_refuses_an_open_session_unreachable_management_or_unreadable_state(self):
        for label, setup, code in (("open session", lambda: self.fake.sessions.update({"X": {"state": "pending"}}), "OPEN_CONFIGURATION_SESSION"),
                                   ("unreachable", lambda: setattr(self, "reachable", False), "MANAGEMENT_UNREACHABLE"),
                                   ("unreadable", lambda: setattr(self, "broken", True), "TRANSACTION_PREFLIGHT_FAILED")):
            self.fake.sessions.clear()
            self.reachable, self.broken = True, False
            setup()
            with self.subTest(case=f"refused {label}"), self.assertRaises(ct.CeosTransactionRejected) as caught:
                self.controller.preflight(self.credential)
            self.assertEqual(caught.exception.code, code)
        self.assertEqual(self.writes(), [])

    def test_arm_refuses_an_open_session_or_a_malformed_run_id_before_any_write(self):
        command = pf.ceos_password_command(self.credential, NEW)
        with self.assertRaises(ct.CeosTransactionRejected) as caught:
            self.controller.arm(self.credential, command, OLD, NEW, "not-hex!")
        self.assertEqual(caught.exception.code, "INVALID_TRANSACTION_METADATA")
        self.fake.sessions["X"] = {"state": "pending"}
        with self.assertRaises(ct.CeosTransactionRejected) as caught:
            self.controller.arm(self.credential, command, OLD, NEW, "0123456789abcdef")
        self.assertEqual((caught.exception.code, self.writes()), ("OPEN_CONFIGURATION_SESSION", []))

    def test_confirm_persist_and_inspect_refuse_a_state_that_is_not_the_armed_one(self):
        wrong = ct.SafeDeviceTransaction("NMAS-CR-R1-0000000000", "/mnt/flash/x.cfg", "", "", "pre", "not-the-device-digest", ct.COMMIT_TIMER, {})
        with self.assertRaises(ct.CeosConfirmationFailed) as caught:
            self.controller.confirm(self.credential, wrong)
        self.assertEqual(caught.exception.code, "COMMIT_TIMER_NOT_ARMED")
        with self.assertRaises(ct.CeosPersistenceFailed) as caught:
            self.controller.persist(self.credential, wrong)
        self.assertEqual(caught.exception.code, "PERSISTENCE_STATE_MISMATCH")
        self.assertEqual(self.writes(), [])
        self.broken = True
        for call, error, code in ((self.controller.confirm, ct.CeosConfirmationFailed, "TRANSACTION_CONFIRM_READ_FAILED"),
                                  (self.controller.persist, ct.CeosPersistenceFailed, "PERSISTENCE_PREFLIGHT_FAILED"),
                                  (self.controller.inspect, ct.CeosTransactionUncertain, "RECOVERY_STATE_UNAVAILABLE")):
            with self.subTest(case=f"unreadable {call.__name__}"), self.assertRaises(error) as caught:
                call(self.credential, wrong)
            self.assertEqual(caught.exception.code, code)

    def test_complete_recovery_validates_and_persists_a_confirmed_change(self):
        tx = self.controller.arm(self.credential, pf.ceos_password_command(self.credential, NEW), OLD, NEW, "0123456789abcdef0123")
        self.controller.read_paths = self.healthy_paths(tx)
        self.controller.confirm(self.credential, tx)
        found = self.controller.complete_recovery(self.credential, tx)
        self.assertTrue(found["validation"]["passed"])
        self.assertTrue(found["persistence"]["startup_matches_running"])

    def test_complete_recovery_refuses_an_unhealthy_network(self):
        tx = self.controller.arm(self.credential, pf.ceos_password_command(self.credential, NEW), OLD, NEW, "abcdef0123456789abcd")
        self.controller.read_paths = lambda device: {**self.healthy_paths(tx)(device), "health": False, "health_status": "CRITICAL"}
        with self.assertRaises(ct.CeosOperationalValidationFailed):
            self.controller.complete_recovery(self.credential, tx)
