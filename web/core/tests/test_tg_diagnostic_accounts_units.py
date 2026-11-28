"""Direct tests for the dedicated read-only diagnostic account IaC (modules/diagnostic_accounts.py).

The account is the Troubleshooter's least-privilege identity: cEOS ``network-operator`` with a generated secret, FRR a
broker-forced key.  Secrets live only in the injected provider (an in-memory fake here, never a real store); the device
side is faked at the ``docker`` / SSH-session boundary, so nothing touches a container or a network.  A proof is a pass
only when login, read, refused configuration AND refused shell are all observed.
"""

from __future__ import annotations

import subprocess
from types import SimpleNamespace
from unittest import mock

from django.test import SimpleTestCase

from modules import diagnostic_accounts as da
from modules.device_credentials import SecretNotFound


class MemoryProvider:
    """The FileSecretProvider interface the module uses, in memory."""

    def __init__(self, values=None):
        self.values, self.staged = dict(values or {}), {}

    def current(self, ref):
        if ref not in self.values:
            raise SecretNotFound(ref)
        return SimpleNamespace(value=self.values[ref], version="v1")

    def initialize(self, ref, value, *, replace=False):
        self.values[ref] = value
        return "v1"

    def stage(self, ref, value):
        self.staged[ref] = value
        return ref, "v2"

    def has_pending(self, ref):
        return ref in self.staged

    def pending(self, ref, version=None):
        return SimpleNamespace(value=self.staged[ref], version="v2")

    def promote(self, ref, version):
        self.values[ref] = self.staged.pop(ref)
        return ref, version


class Transport:
    def __init__(self):
        self.closed = False

    def close(self):
        self.closed = True


def session(answers: dict):
    """Patch ``_connect`` + ``_exec``: each command answers (exit, stdout, stderr)."""
    transport = Transport()
    connect = mock.patch.object(da, "_connect", return_value=(transport, "SHA256:pin"))
    execute = mock.patch.object(da, "_exec", side_effect=lambda t, command, timeout=20.0: answers.get(command, (1, "", "")))
    return transport, connect, execute


class ReferenceAndBrokerTests(SimpleTestCase):
    def test_references_and_container_names(self):
        self.assertEqual(da.secret_ref("R2"), "runtime://device-credentials/r2-nmas-diag")
        self.assertEqual(da.key_ref("R3"), "runtime://device-credentials/r3-nmas-diag-sshkey")
        self.assertEqual(da.container("R2"), "clab-srlceos01-R2")

    def test_references_never_carry_the_device_case_or_another_prefix(self):
        with self.subTest("a mixed-case name is not a distinct secret"):
            self.assertEqual(da.secret_ref("mgmt_SWT"), da.secret_ref("MGMT_swt"))
        with self.subTest("a container is never outside the lab prefix"):
            self.assertTrue(da.container("x").startswith(da.CONTAINER_PREFIX))

    def test_allowlist_text_refuses_empty_or_multiline_commands(self):
        for label, commands in (("an empty allowlist", []), ("a multi-line command", ["hostname", "id\nrm -rf /"]), ("a blank command", ["  "])):
            with self.subTest(f"{label} is refused"):
                with self.assertRaises(da.DiagnosticAccountError):
                    da.allowlist_text(commands)

    def test_render_ceos_never_grants_more_than_network_operator(self):
        with self.subTest("a rendered account is never above network-operator and never without its secret"):
            text = da.render_ceos("unit-test-secret")
            self.assertNotIn("network-admin", text)
            self.assertIn(f"username {da.USERNAME} role network-operator secret unit-test-secret", text)


class SecretProvisioningTests(SimpleTestCase):
    def test_ensure_password_creates_then_reuses_and_rotation_stages(self):
        provider = MemoryProvider()
        value, created = da.ensure_password("R2", provider=provider)
        self.assertEqual((created, len(value) >= 24), (True, True))
        self.assertEqual(da.ensure_password("R2", provider=provider), (value, False))
        staged, created = da.ensure_password("R2", provider=provider, rotate=True)
        self.assertEqual((created, provider.values[da.secret_ref("R2")]), (True, value))       # current is unchanged until promoted
        da.promote_if_staged("R2", provider=provider)
        self.assertEqual(provider.values[da.secret_ref("R2")], staged)

    def test_existing_secrets_are_not_replaced_and_nothing_pending_promotes_nothing(self):
        provider = MemoryProvider({da.secret_ref("R2"): "kept"})
        with self.subTest("an existing password is not regenerated"):
            self.assertEqual(da.ensure_password("R2", provider=provider), ("kept", False))
        with self.subTest("no staged secret promotes nothing"):
            da.promote_if_staged("R2", provider=provider)
            self.assertEqual(provider.values[da.secret_ref("R2")], "kept")

    def test_ensure_keypair_and_load_pkey_return_the_same_ed25519_key(self):
        provider = MemoryProvider()
        public, created = da.ensure_keypair("R3", provider=provider)
        self.assertTrue(public.startswith("ssh-ed25519 ") and created)
        self.assertEqual(da.ensure_keypair("R3", provider=provider), (public, False))
        key = da.load_pkey("R3", provider=provider)
        self.assertEqual(f"{key.get_name()} {key.get_base64()}", public)

    def test_missing_or_corrupt_private_keys_are_refused(self):
        with self.subTest("a missing key is refused"):
            with self.assertRaises(SecretNotFound):
                da.load_pkey("R4", provider=MemoryProvider())
        with self.subTest("a corrupt stored key is refused"):
            with self.assertRaises(Exception):
                da.ensure_keypair("R4", provider=MemoryProvider({da.key_ref("R4"): "not a key"}))


class ApplyTests(SimpleTestCase):
    def docker(self, rc=0, out="", err=""):
        return mock.patch.object(da, "_docker", return_value=subprocess.CompletedProcess([], rc, out, err))

    def test_apply_ceos_and_frr_return_after_an_accepted_configuration(self):
        with self.docker(out="R2(config)#") as docker:
            self.assertIsNone(da.apply_ceos("R2", "unit-test-secret"))
            self.assertIn("role network-operator", docker.call_args.kwargs["stdin"])
        public = da.ensure_keypair("R3", provider=MemoryProvider())[0]
        with self.docker(out='{"changed": ["broker", "allowlist"]}\n'):
            self.assertEqual(da.apply_frr("R3", public, ["hostname"], dropin="d", expected_previous_dropin="p"), ["broker", "allowlist"])

    def test_rejected_configuration_is_refused(self):
        with self.docker(out="% Invalid input"), self.subTest("an eos error is refused"):
            with self.assertRaises(da.DiagnosticAccountError):
                da.apply_ceos("R2", "unit-test-secret")
        public = da.ensure_keypair("R3", provider=MemoryProvider())[0]
        with self.docker(rc=1, err='{"code": "DROPIN_DRIFT"}'), self.subTest("a failed frr apply is refused with its code"):
            with self.assertRaises(da.DiagnosticAccountError) as caught:
                da.apply_frr("R3", public, ["hostname"], dropin="d", expected_previous_dropin="p")
            self.assertIn("DROPIN_DRIFT", str(caught.exception))
        with self.subTest("a non-ed25519 key is refused before docker"):
            with self.docker() as docker, self.assertRaises(da.DiagnosticAccountError):
                da.apply_frr("R3", "ssh-rsa AAAA", ["hostname"], dropin="d", expected_previous_dropin="p")
            docker.assert_not_called()


class VerificationTests(SimpleTestCase):
    DENIED = (1, "", "% Authorization denied for command")

    def test_verification_passed_and_as_dict(self):
        v = da.Verification("R2", login=True, read_ok=True, write_denied=True, shell_denied=True)
        self.assertTrue(v.passed)
        self.assertEqual(v.as_dict()["passed"], True)

    def test_verify_ceos_passes_only_a_least_privilege_account(self):
        transport, connect, execute = session({"show version | json": (0, '{"version": "4.36.2F"}', ""), "configure terminal": self.DENIED,
                                               "bash id": self.DENIED})
        with connect, execute:
            result = da.verify_ceos("R2", "192.168.200.2", pin="SHA256:pin", password="unit-test-secret")
        self.assertTrue(result.passed)
        self.assertTrue(transport.closed)

    def test_verify_ceos_refuses_an_account_that_can_configure_or_cannot_log_in(self):
        _t, connect, execute = session({"show version | json": (0, '{"version": "4.36.2F"}', ""), "configure terminal": (0, "R2(config)#", ""),
                                        "bash id": self.DENIED})
        with connect, execute, self.subTest("an account allowed to configure is refused"):
            self.assertFalse(da.verify_ceos("R2", "a", pin="p", password="s").passed)
        with mock.patch.object(da, "_connect", side_effect=da.DiagnosticAccountError("HOST_KEY_MISMATCH")), \
                self.subTest("a host key mismatch is refused as no login"):
            result = da.verify_ceos("R2", "a", pin="p", password="s")
            self.assertEqual((result.login, result.details["login_error"]), (False, "HOST_KEY_MISMATCH"))

    def test_verify_frr_passes_only_a_broker_restricted_key(self):
        refused = (126, "", da.REFUSED_MARKER)
        _t, connect, execute = session({"hostname": (0, "R3\n", ""), "vtysh -c 'show ip ospf neighbor json'": (0, "{}", ""),
                                        "vtysh -c 'configure terminal'": refused, "id": refused, "ip link set dev lo down": refused})
        with connect, execute:
            self.assertTrue(da.verify_frr("R3", "192.168.200.3", pin="SHA256:pin", pkey=object()).passed)

    def test_verify_frr_refuses_a_shell_or_a_failed_login(self):
        refused = (126, "", da.REFUSED_MARKER)
        _t, connect, execute = session({"hostname": (0, "R3\n", ""), "vtysh -c 'show ip ospf neighbor json'": (0, "{}", ""),
                                        "vtysh -c 'configure terminal'": refused, "id": (0, "uid=1000", ""), "ip link set dev lo down": refused})
        with connect, execute, self.subTest("an account with a shell is refused"):
            self.assertFalse(da.verify_frr("R3", "a", pin="p", pkey=object()).passed)
        with mock.patch.object(da, "_connect", side_effect=OSError("unreachable")), self.subTest("an unreachable device is refused as no login"):
            self.assertEqual(da.verify_frr("R3", "a", pin="p", pkey=object()).details["login_error"], "OSError")

    def channel(self, output):
        channel = mock.MagicMock()
        chunks = [b"Last login: banner\n", output.encode()]      # the first read after invoke_shell drains the banner
        channel.recv_ready.side_effect = lambda: bool(chunks)
        channel.recv.side_effect = lambda n: chunks.pop(0) if chunks else b""
        transport = mock.MagicMock()
        transport.open_session.return_value = channel
        return mock.patch.object(da, "_connect", return_value=(transport, "SHA256:pin"))

    def test_verify_ceos_escalation_passes_when_configure_is_denied(self):
        with self.channel("R2#\n% Authorization denied for command 'configure terminal'\n"), mock.patch("time.sleep"):
            self.assertEqual(da.verify_ceos_escalation("R2", "a", pin="p", password="s"),
                             {"enable_prompt": True, "configure_denied": True, "passed": True})

    def test_verify_ceos_escalation_refuses_an_entered_config_mode(self):
        with self.channel("R2#\nR2(config)#\n"), mock.patch("time.sleep"):
            self.assertFalse(da.verify_ceos_escalation("R2", "a", pin="p", password="s")["passed"])
