from __future__ import annotations

import io
import inspect
import json
import subprocess
import tempfile
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from django.core.management import call_command
from django.test import TestCase

from modules import device_credentials
from modules.device_credentials import FileSecretProvider, make_reference
from monitoring.scripts import linux_mfa_rollback

from core.models import (AccountKind, CentralAaaState, DeviceAuthMethod, DeviceCredential,
                         DeviceLoginMfaPolicy, MfaEnforcementState, MfaMechanism)
from core.services.credentials import linux_mfa as lm
from core.services.credentials import mfa
from core.services.credentials.linux_mfa_runner import (
    CEOS_POSITIVE_EVIDENCE_STEP, Dependencies, LinuxMfaRunner,
    normalize_ospf_v4_neighbors, normalize_ospf_v6_neighbors, ospf_adjacencies_healthy,
)
from core.services.credentials.r1_pilot import PilotError, SecretSet
from core.services.credentials.r1_pilot_runner import PilotEvidence
from core.services.credentials.totp_contract import FixtureAuthenticator, HumanFixture, REJECT, UNAVAILABLE


def completed(argv=(), rc=0, stdout=""):
    return subprocess.CompletedProcess(argv, rc, stdout=stdout, stderr="")


def v4_neighbors(*, neighbor_id="192.0.2.1", address="198.51.100.1", interface="Vlan10",
                 state="Full", dead=39000, uptime=1000, counter=0):
    return {"neighbors": {neighbor_id: [{
        "converged": state, "state": f"{state}/DR", "address": address,
        "ifaceName": f"{interface}:198.51.100.2", "deadTimeMsecs": dead,
        "upTimeInMsec": uptime, "retransmitCounter": counter,
    }]}}


def v4_interfaces(*, interface="Vlan10", area="0.0.0.0"):
    return {"interfaces": {interface: {"area": area, "timerHelloInMsecs": 9999}}}


def v6_neighbors(*, neighbor_id="192.0.2.1", interface="Vlan10", state="Full",
                 dead="00:00:39", duration="1d00:00:00", counter=0):
    return {"neighbors": [{
        "neighborId": neighbor_id, "interfaceName": interface, "state": state,
        "deadTime": dead, "duration": duration, "ignoredCounter": counter,
    }]}


def v6_interfaces(*, interface="Vlan10", area="0.0.0.0"):
    return {interface: {"areaId": area, "pendingLsaLsUpdateCount": 99}}


class StableOspfNormalizationTests(TestCase):
    def test_ipv4_dead_timer_uptime_and_counters_do_not_drift(self):
        first = normalize_ospf_v4_neighbors(v4_neighbors(), v4_interfaces())
        later = normalize_ospf_v4_neighbors(
            v4_neighbors(dead=12000, uptime=900000, counter=27), v4_interfaces(),
        )
        self.assertEqual(first, later)
        self.assertEqual(first[0]["address_family"], "ipv4")

    def test_ipv6_dead_timer_duration_and_counters_do_not_drift(self):
        first = normalize_ospf_v6_neighbors(v6_neighbors(), v6_interfaces())
        later = normalize_ospf_v6_neighbors(
            v6_neighbors(dead="00:00:12", duration="9d12:00:00", counter=30), v6_interfaces(),
        )
        self.assertEqual(first, later)
        self.assertEqual(first[0]["address_family"], "ipv6")

    def test_neighbor_disappearance_and_unexpected_addition_are_drift(self):
        baseline = normalize_ospf_v4_neighbors(v4_neighbors(), v4_interfaces())
        self.assertNotEqual(baseline, normalize_ospf_v4_neighbors({"neighbors": {}}, v4_interfaces()))
        added = v4_neighbors()
        added["neighbors"]["192.0.2.2"] = [dict(added["neighbors"]["192.0.2.1"][0], address="198.51.100.3")]
        self.assertNotEqual(baseline, normalize_ospf_v4_neighbors(added, v4_interfaces()))

    def test_full_to_non_full_is_drift_and_unhealthy(self):
        baseline = normalize_ospf_v4_neighbors(v4_neighbors(), v4_interfaces())
        changed = normalize_ospf_v4_neighbors(v4_neighbors(state="Init"), v4_interfaces())
        self.assertNotEqual(baseline, changed)
        self.assertFalse(ospf_adjacencies_healthy({"ospf_neighbors": {"ipv4": changed, "ipv6": changed}}))

    def test_interface_change_is_drift(self):
        baseline = normalize_ospf_v4_neighbors(v4_neighbors(), v4_interfaces())
        changed = normalize_ospf_v4_neighbors(v4_neighbors(interface="Vlan20"), v4_interfaces(interface="Vlan20"))
        self.assertNotEqual(baseline, changed)

    def test_router_neighbor_id_change_is_drift(self):
        baseline = normalize_ospf_v6_neighbors(v6_neighbors(), v6_interfaces())
        changed = normalize_ospf_v6_neighbors(v6_neighbors(neighbor_id="192.0.2.99"), v6_interfaces())
        self.assertNotEqual(baseline, changed)

    def test_area_change_is_drift_for_both_families(self):
        self.assertNotEqual(
            normalize_ospf_v4_neighbors(v4_neighbors(), v4_interfaces()),
            normalize_ospf_v4_neighbors(v4_neighbors(), v4_interfaces(area="0.0.0.1")),
        )
        self.assertNotEqual(
            normalize_ospf_v6_neighbors(v6_neighbors(), v6_interfaces()),
            normalize_ospf_v6_neighbors(v6_neighbors(), v6_interfaces(area="0.0.0.1")),
        )

    def test_json_and_field_order_do_not_matter(self):
        rows = v4_neighbors(); row = rows["neighbors"]["192.0.2.1"][0]
        rows["neighbors"]["192.0.2.2"] = [dict(row, address="198.51.100.3")]
        reordered = {"neighbors": {
            "192.0.2.2": [{key: rows["neighbors"]["192.0.2.2"][0][key]
                             for key in reversed(list(rows["neighbors"]["192.0.2.2"][0]))}],
            "192.0.2.1": [{key: row[key] for key in reversed(list(row))}],
        }}
        self.assertEqual(
            normalize_ospf_v4_neighbors(rows, v4_interfaces()),
            normalize_ospf_v4_neighbors(reordered, {"interfaces": {"Vlan10": {"timerHelloInMsecs": 1, "area": "0.0.0.0"}}}),
        )

    def test_expected_healthy_ipv4_and_ipv6_sets_pass(self):
        snapshot = {"ospf_neighbors": {
            "ipv4": normalize_ospf_v4_neighbors(v4_neighbors(), v4_interfaces()),
            "ipv6": normalize_ospf_v6_neighbors(v6_neighbors(), v6_interfaces()),
        }}
        self.assertTrue(ospf_adjacencies_healthy(snapshot))


class LinuxMfaModelAndRenderTests(TestCase):
    def rows(self, device="R3"):
        private, public, fingerprint = mfa.generate_service_keypair(f"nmas-automation@{device.lower()}")
        del private
        return [
            DeviceCredential(device_name=device, platform="ubuntu_frr", username="root",
                             account_kind=AccountKind.LEGACY_SHARED, secret_ref=make_reference("linux-root-shared")),
            DeviceCredential(device_name=device, platform="ubuntu_frr", username="nmas-automation",
                             account_kind=AccountKind.SERVICE, auth_method=DeviceAuthMethod.PUBLICKEY,
                             ssh_key_ref=make_reference(f"{device.lower()}-nmas-automation-sshkey"),
                             ssh_public_key=public, ssh_public_key_fingerprint=fingerprint),
            DeviceCredential(device_name=device, platform="ubuntu_frr", username="nmas-admin",
                             account_kind=AccountKind.HUMAN, auth_method=DeviceAuthMethod.PASSWORD_AND_TOTP),
            DeviceCredential(device_name=device, platform="ubuntu_frr", username=f"{device.lower()}-breakglass",
                             account_kind=AccountKind.BREAK_GLASS, secret_ref=make_reference(f"{device.lower()}-breakglass")),
        ]

    def policy(self, device="R3"):
        return DeviceLoginMfaPolicy(device_name=device, platform="ubuntu_frr", mechanism=MfaMechanism.RADIUS_TOTP,
                                    radius_secret_ref=f"runtime://human-mfa/radius/{device.lower()}")

    def test_safe_linux_candidate_is_supported_and_secret_free(self):
        candidate = mfa.render_candidate(self.policy(), self.rows())
        self.assertTrue(candidate.supported)
        self.assertEqual(candidate.blockers, [])
        surface = json.dumps(candidate.as_dict())
        self.assertIn("pam_radius_auth.so", surface)
        self.assertIn("/etc/ssh/sshd_config.d/60-nmas-human-mfa.conf", surface)
        self.assertNotIn("/etc/ssh/sshd_config.d/60-nmas-two-factor.conf", surface)
        self.assertIn(mfa.LINUX_MFA_OPENSSH_DROPIN_PATH, lm.CONFIG_PATHS)
        self.assertNotIn("PRIVATE KEY", surface)
        self.assertNotIn("password-value", surface)

    def test_linux_candidate_is_r3_r4_only(self):
        with self.assertRaises(mfa.MfaConfigError):
            mfa.render_candidate(self.policy("R5"), self.rows("R5"))

    def test_publickey_service_needs_key_but_no_password(self):
        row = self.rows()[1]
        row.save()
        self.assertEqual(DeviceCredential.objects.get(pk=row.pk).secret_ref, "")
        row.ssh_key_ref = ""
        with self.assertRaisesRegex(ValueError, "private key"):
            row.save()
        row = self.rows()[1]
        row.ssh_public_key = ""
        with self.assertRaisesRegex(ValueError, "SSH public key"):
            row.save()

    def test_pam_stack_is_human_only_and_radius_unavailable_fails_closed(self):
        stack = lm.pam_sshd()
        self.assertLess(stack.index("pam_succeed_if.so"), stack.index("substack common-auth"))
        self.assertLess(stack.index("substack common-auth"), stack.index("pam_radius_auth.so"))
        self.assertNotIn("localifdown", stack)
        fixture = FixtureAuthenticator(humans={"nmas-admin": HumanFixture("nmas-admin", "pw", {1: "123456"})},
                                       machines={}, available=False)
        self.assertEqual(fixture.authenticate_human("nmas-admin", "pw123456", counter=1),
                         (UNAVAILABLE, "CENTRAL_AAA_UNAVAILABLE"))

    def test_sshd_policy_separates_human_machine_breakglass_and_denies_root(self):
        text = lm.sshd_dropin(lm.target_for("R3"))
        self.assertIn("PermitRootLogin no", text)
        self.assertIn("AuthenticationMethods keyboard-interactive:pam", text)
        self.assertIn("AuthenticationMethods publickey", text)
        self.assertIn("Match User r3-breakglass", text)
        self.assertIn("PasswordAuthentication yes", text)
        self.assertIn("AllowUsers nmas-admin@192.168.200.100", text)
        self.assertTrue(text.rstrip().endswith("Match all"))


class LinuxMfaProtectedTransportTests(TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = Path(self.tmp.name) / "store.json"
        self.provider = FileSecretProvider(self.store)
        self.target = lm.target_for("R3")
        private, public, fingerprint = mfa.generate_service_keypair("nmas-automation@r3")
        self.provider.initialize(self.target.service_key_ref, private)
        self.provider.initialize(self.target.breakglass_ref, "TEST_ONLY_BREAKGLASS_PASSWORD")
        self.credential = DeviceCredential.objects.create(
            device_name="R3", platform="ubuntu_frr", username="nmas-automation",
            account_kind=AccountKind.SERVICE, auth_method=DeviceAuthMethod.PUBLICKEY,
            ssh_key_ref=self.target.service_key_ref, ssh_public_key=public,
            ssh_public_key_fingerprint=fingerprint,
        )
        self.radius = Path(self.tmp.name) / "radius_r3_secret"
        self.radius.write_text("TEST_ONLY_RADIUS_SECRET\n"); self.radius.chmod(0o600)

    def tearDown(self):
        self.tmp.cleanup()

    def test_activation_places_secrets_only_on_stdin(self):
        calls = []
        def fake_run(argv, **kwargs):
            calls.append((argv, kwargs))
            return completed(argv, stdout='{"applied": true, "sshd_valid": true, "users": ["nmas-admin"]}')
        transport = lm.DockerTransport(self.target, runner=fake_run)
        with mock.patch.object(lm, "radius_secret_path", return_value=self.radius):
            result = lm.apply(transport, self.provider)
        self.assertTrue(result["applied"])
        argv, kwargs = calls[0]
        rendered_argv = " ".join(argv)
        self.assertNotIn("TEST_ONLY_BREAKGLASS_PASSWORD", rendered_argv)
        self.assertNotIn("TEST_ONLY_RADIUS_SECRET", rendered_argv)
        self.assertNotIn("TEST_ONLY_BREAKGLASS_PASSWORD", kwargs.get("env", {}) or {})
        self.assertIn("TEST_ONLY_BREAKGLASS_PASSWORD", kwargs["input"])
        self.assertNotIn("TEST_ONLY_BREAKGLASS_PASSWORD", result.__repr__())

    def test_timer_argv_contains_only_device_and_opaque_token(self):
        calls = []
        def fake(argv, **kwargs):
            calls.append(argv); return completed(argv)
        with mock.patch.object(lm.settings, "REPO_ROOT", Path("/safe/repo")):
            unit = lm.arm_timer("R3", "a" * 24, runner=fake, seconds=60)
        self.assertEqual(unit, "nmas-linux-mfa-r3-" + "a" * 24)
        command = " ".join(calls[0])
        self.assertIn("linux_mfa_rollback.py", command)
        self.assertNotIn("password", command.lower())
        self.assertNotIn("secret", command.lower())

    def test_bad_timer_or_target_is_rejected(self):
        for device, token in (("R1", "a" * 24), ("R3", "bad")):
            with self.subTest(device=device, token=token), self.assertRaises(lm.LinuxMfaError):
                lm.timer_unit(device, token)

    def test_timer_rollback_uses_fixed_target_stdin_program_and_restoration_primitives(self):
        seen = {}
        def fake(argv, **kwargs):
            seen["argv"] = argv; seen.update(kwargs); return completed(argv)
        with mock.patch.object(linux_mfa_rollback.subprocess, "run", side_effect=fake):
            self.assertEqual(linux_mfa_rollback.rollback("R3", "c" * 24), 0)
        self.assertEqual(seen["argv"][:4], ["docker", "exec", "-i", "clab-srlceos01-R3"])
        self.assertIn("shutil.copy2", seen["input"])
        self.assertIn("os.replace", seen["input"])
        self.assertIn("userdel", seen["input"])
        self.assertIn("SIGHUP", seen["input"])
        self.assertNotIn("TEST_ONLY_BREAKGLASS_PASSWORD", " ".join(seen["argv"]))

    def test_protected_radius_file_never_gets_an_evidence_hash(self):
        self.assertIn('name != "/etc/pam_radius_auth.conf"', lm.BACKUP_PROGRAM)
        self.assertIn('item["protected"] = True', lm.BACKUP_PROGRAM)
        self.assertIn('name == "/etc/pam_radius_auth.conf"', inspect.getsource(lm.config_hashes))
        source = inspect.getsource(LinuxMfaRunner.stage_radius)
        self.assertNotIn("config_sha256", source)
        self.assertNotIn("hashlib.sha256", source)

    def activation_failure(self, stage, *, return_code=23, exception_class="StageCommandError", raw_extra=None):
        trace = [{"stage": stage, "status": "started", "at": 10.0},
                 {"stage": stage, "status": "failed", "at": 11.0, "return_code": return_code}]
        payload = {"applied": False, "failed_stage": stage, "return_code": return_code,
                   "exception_class": exception_class, "stage_trace": trace}
        payload.update(raw_extra or {})
        transport = lm.DockerTransport(
            self.target,
            runner=lambda argv, **kwargs: completed(argv, rc=40, stdout=json.dumps(payload)),
        )
        with mock.patch.object(lm, "radius_secret_path", return_value=self.radius):
            with self.assertRaises(lm.LinuxMfaActivationError) as raised:
                lm.apply(transport, self.provider)
        return raised.exception

    def test_failure_before_pam_installation_identifies_account_stage(self):
        error = self.activation_failure("ensure_accounts")
        self.assertEqual(error.stage, "ensure_accounts")
        self.assertEqual(error.command_category, "account_management")
        self.assertFalse(error.as_dict()["sshd_reload_started"])

    def test_failure_during_pam_installation_identifies_exact_stage(self):
        error = self.activation_failure("deploy_pam_stack")
        self.assertEqual(error.stage, "deploy_pam_stack")
        self.assertEqual(error.command_category, "pam_config_install")

    def test_sshd_validation_and_reload_failures_are_distinct(self):
        validation = self.activation_failure("validate_sshd_config", return_code=30)
        reload = self.activation_failure("reload_sshd", exception_class="OSError", return_code=1)
        self.assertEqual(validation.stage, "validate_sshd_config")
        self.assertEqual(reload.stage, "reload_sshd")
        self.assertTrue(reload.as_dict()["sshd_reload_started"])
        self.assertFalse(reload.as_dict()["sshd_reload_completed"])

    def test_device_diagnostic_fields_are_allowlisted_not_trusted(self):
        leaked = "TEST_ONLY_PASSWORD TEST_ONLY_RADIUS_SECRET 654321 protected-pam-contents"
        error = self.activation_failure(
            "validate_sshd_config",
            raw_extra={"stderr_summary": leaked, "command": ["chpasswd", leaked], "environment": leaked},
        )
        evidence = json.dumps(error.as_dict())
        self.assertNotIn("TEST_ONLY_PASSWORD", evidence)
        self.assertNotIn("TEST_ONLY_RADIUS_SECRET", evidence)
        self.assertNotIn("654321", evidence)
        self.assertNotIn("protected-pam-contents", evidence)
        self.assertEqual(error.stderr_summary, "sshd validation did not complete")

    def test_embedded_helper_captures_child_output_and_never_places_factors_on_argv(self):
        self.assertIn("capture_output=True", lm.APPLY_PROGRAM)
        self.assertIn('protected_input=factors', lm.APPLY_PROGRAM)
        self.assertNotIn('data["breakglass_password"]]', lm.APPLY_PROGRAM)

    def test_validate_sudoers_remains_between_install_and_sshd_validation(self):
        install = lm.APPLY_PROGRAM.index('operation("deploy_sudoers_policy"')
        validate = lm.APPLY_PROGRAM.index('operation("validate_sudoers"')
        sshd = lm.APPLY_PROGRAM.index('operation("validate_sshd_config"')
        self.assertLess(install, validate)
        self.assertLess(validate, sshd)
        failure = self.activation_failure("validate_sudoers", return_code=1)
        self.assertEqual(failure.stage, "validate_sudoers")
        self.assertEqual(failure.command_category, "sudoers_validation")


class LinuxMfaDependencyTests(TestCase):
    def setUp(self):
        self.evidence = mock.MagicMock()
        self.runner = LinuxMfaRunner("R3", Dependencies(provider=mock.MagicMock(), evidence=self.evidence))
        self.runner._record = mock.MagicMock()

    @staticmethod
    def satisfied_state(**overrides):
        state = {
            "pam_radius_installed": True,
            "sudo_package_installed": True,
            "visudo_available": True,
            "visudo_executable": True,
        }
        state.update(overrides)
        return state

    def package_transport(self, state, *, update_rc=0, install_rc=0, leave_visudo_missing=False):
        calls = []

        def fake(argv, *, timeout=30):
            calls.append(list(argv))
            if argv[0] == "sha256sum":
                return completed(argv, stdout="unchanged-pam-hashes\n")
            if argv[:2] == ["test", "-f"]:
                return completed(argv, rc=0 if state["pam_radius_installed"] else 1)
            if argv[0] == "dpkg-query":
                return completed(argv, rc=0 if state["sudo_package_installed"] else 1,
                                 stdout="install ok installed\n" if state["sudo_package_installed"] else "")
            if argv[:2] == ["sh", "-c"]:
                return completed(argv, rc=0 if state["visudo_available"] else 127)
            if argv[:2] == ["visudo", "-V"]:
                return completed(argv, rc=0 if state["visudo_executable"] else 127)
            if argv[:2] == ["apt-get", "update"]:
                return completed(argv, rc=update_rc)
            if argv[:3] == ["env", "DEBIAN_FRONTEND=noninteractive", "apt-get"]:
                if install_rc == 0:
                    if "libpam-radius-auth" in argv:
                        state["pam_radius_installed"] = True
                    if "sudo" in argv:
                        state["sudo_package_installed"] = True
                        if not leave_visudo_missing:
                            state["visudo_available"] = state["visudo_executable"] = True
                return completed(argv, rc=install_rc)
            raise AssertionError(f"unexpected command category: {argv[0]}")

        return fake, calls

    def run_precheck(self, state):
        self.evidence.latest.return_value = {"at": 10.0}
        self.runner.deps.runner = mock.MagicMock(return_value=completed(stdout="true\n"))
        with mock.patch.object(self.runner, "_dependency_state", return_value=state), \
             mock.patch.object(self.runner, "_container", side_effect=[
                 completed(stdout="0\n"), completed(), completed(rc=2, stdout=""),
             ]), \
             mock.patch.object(self.runner, "_reads", return_value={
                 "health": True, "health_status": "HEALTHY", "health_blocking": [],
                 "health_tolerated_warnings": [], "config_retrieval": True, "nsot": True,
                 "identity": "nmas-automation", "ssh_key_ref": self.runner.target.service_key_ref,
             }), \
             mock.patch.object(self.runner, "_operational_snapshot", return_value={
                 "digests": {}, "ospf_neighbors": {"ipv4": [{"state": "Full"}], "ipv6": [{"state": "Full"}]},
                 "errors": [], "ospf_healthy": True,
             }), \
             mock.patch.object(lm, "reviewed_candidate", return_value=SimpleNamespace(
                 supported=True, blockers=[], digest="a" * 64,
             )), \
             mock.patch.object(PilotEvidence, "latest", return_value={"ok": True}):
            return self.runner.precheck()

    def test_sudo_absent_is_detected_and_install_path_adds_only_sudo(self):
        state = self.satisfied_state(sudo_package_installed=False, visudo_available=False, visudo_executable=False)
        fake, calls = self.package_transport(state)
        with mock.patch.object(self.runner, "_container", side_effect=fake):
            result = self.runner.install_module()
        self.assertTrue(result["PASS"])
        self.assertEqual(result["packages_requested"], ["sudo"])
        install = next(argv for argv in calls if argv[:3] == ["env", "DEBIAN_FRONTEND=noninteractive", "apt-get"])
        self.assertEqual(install[-1], "sudo")
        self.assertNotIn("upgrade", install)
        self.assertTrue(result["dependency_state"]["visudo_available"])

    def test_successful_install_makes_visudo_executable(self):
        state = self.satisfied_state(sudo_package_installed=False, visudo_available=False, visudo_executable=False)
        fake, _calls = self.package_transport(state)
        with mock.patch.object(self.runner, "_container", side_effect=fake):
            result = self.runner.install_module()
        self.assertTrue(result["dependency_state"]["sudo_package_installed"])
        self.assertTrue(result["dependency_state"]["visudo_executable"])

    def test_install_failure_is_bounded_and_activation_is_not_reached(self):
        state = self.satisfied_state(sudo_package_installed=False, visudo_available=False, visudo_executable=False)
        fake, _calls = self.package_transport(state, install_rc=100)
        with mock.patch.object(self.runner, "_container", side_effect=fake), \
             self.assertRaisesRegex(lm.LinuxMfaError, "REQUIRED_DEPENDENCY_MISSING: visudo"):
            self.runner.install_module()
        evidence = self.runner._record.call_args.kwargs
        self.assertFalse(evidence["ok"])
        self.assertIn("REQUIRED_DEPENDENCY_MISSING: visudo", evidence["dependency_errors"])

    def test_visudo_missing_after_install_fails_closed(self):
        state = self.satisfied_state(sudo_package_installed=False, visudo_available=False, visudo_executable=False)
        fake, _calls = self.package_transport(state, leave_visudo_missing=True)
        with mock.patch.object(self.runner, "_container", side_effect=fake), \
             self.assertRaisesRegex(lm.LinuxMfaError, "REQUIRED_DEPENDENCY_MISSING: visudo"):
            self.runner.install_module()

    def test_satisfied_dependencies_do_not_run_apt(self):
        state = self.satisfied_state()
        fake, calls = self.package_transport(state)
        with mock.patch.object(self.runner, "_container", side_effect=fake):
            result = self.runner.install_module()
        self.assertTrue(result["PASS"])
        self.assertFalse(result["package_install_invoked"])
        self.assertFalse(any("apt-get" in argv for argv in calls))

    def test_missing_visudo_precheck_is_structured_and_fails(self):
        result = self.run_precheck(self.satisfied_state(
            sudo_package_installed=False, visudo_available=False, visudo_executable=False,
        ))
        self.assertFalse(result["PASS"])
        self.assertIn("sudo_dependency_satisfied", result["failures"])
        self.assertIn("REQUIRED_DEPENDENCY_MISSING: visudo", result["dependency_errors"])
        self.assertNotIn("TEST_ONLY_PASSWORD", json.dumps(result))

    def test_satisfied_dependencies_allow_normal_precheck(self):
        result = self.run_precheck(self.satisfied_state())
        self.assertTrue(result["PASS"])
        self.assertEqual(result["dependency_errors"], [])

    def test_failed_or_stale_dependency_precheck_blocks_backup_timer_and_activation(self):
        self.evidence.latest_entry.return_value = (1, {"ok": False, "checks": {"sudo_dependency_satisfied": False}})
        with mock.patch.object(lm, "backup") as backup, self.assertRaises(lm.LinuxMfaError):
            self.runner.backup()
        backup.assert_not_called()
        with mock.patch.object(lm, "arm_timer") as arm, self.assertRaises(lm.LinuxMfaError):
            self.runner.arm("b" * 24)
        arm.assert_not_called()

        self.evidence.latest.return_value = {"rollback_token": "b" * 24}
        with mock.patch.object(lm, "timer_active", return_value=True), \
             mock.patch.object(self.runner, "_dependency_state", return_value=self.satisfied_state(
                 sudo_package_installed=False, visudo_available=False, visudo_executable=False,
             )), mock.patch.object(lm, "apply") as apply, \
             self.assertRaisesRegex(lm.LinuxMfaError, "REQUIRED_DEPENDENCY_MISSING: visudo"):
            self.runner.activate("b" * 24)
        apply.assert_not_called()

    def test_live_dependency_loss_after_passing_precheck_blocks_backup_and_timer(self):
        self.evidence.latest_entry.return_value = (1, {
            "ok": True, "checks": {"sudo_dependency_satisfied": True},
        })
        missing = self.satisfied_state(sudo_package_installed=False, visudo_available=False, visudo_executable=False)
        with mock.patch.object(self.runner, "_dependency_state", return_value=missing), \
             mock.patch.object(lm, "backup") as backup, self.assertRaisesRegex(
                 lm.LinuxMfaError, "REQUIRED_DEPENDENCY_MISSING: visudo",
             ):
            self.runner.backup()
        backup.assert_not_called()
        with mock.patch.object(self.runner, "_dependency_state", return_value=missing), \
             mock.patch.object(lm, "arm_timer") as arm, self.assertRaisesRegex(
                 lm.LinuxMfaError, "REQUIRED_DEPENDENCY_MISSING: visudo",
             ):
            self.runner.arm("b" * 24)
        arm.assert_not_called()

    def test_dependency_evidence_is_boolean_only_and_secret_free(self):
        state = self.satisfied_state(sudo_package_installed=False, visudo_available=False, visudo_executable=False)
        fake, _calls = self.package_transport(state, install_rc=100)
        with mock.patch.object(self.runner, "_container", side_effect=fake), self.assertRaises(lm.LinuxMfaError):
            self.runner.install_module()
        evidence = json.dumps(self.runner._record.call_args.kwargs, sort_keys=True)
        self.assertNotIn("TEST_ONLY_PASSWORD", evidence)
        self.assertNotIn("TEST_ONLY_RADIUS_SECRET", evidence)
        self.assertNotIn("stdout", evidence)
        self.assertNotIn("stderr", evidence)


class LinuxMfaRunnerSafetyTests(TestCase):
    def setUp(self):
        self.policy = DeviceLoginMfaPolicy.objects.get(device_name="R3")
        self.policy.platform = "ubuntu_frr"; self.policy.mechanism = MfaMechanism.RADIUS_TOTP
        self.policy.radius_secret_ref = "runtime://human-mfa/radius/r3"; self.policy.automation_exempt = True
        self.policy.save()
        privacyidea = mock.MagicMock()
        privacyidea.token.return_value = {"serial": "TOTP0001522E", "owner": "nmas-admin", "active": True,
                                          "locked": False, "revoked": False}
        privacyidea.audit.side_effect = [
            {"max_id": 100, "rows": []},
            {"max_id": 103, "rows": [
                {"id": 101, "success": False, "serial": "", "policies": "nmas-human-password-totp"},
                {"id": 102, "success": False, "serial": "", "policies": "nmas-human-password-totp"},
                {"id": 103, "success": True, "serial": "TOTP0001522E", "policies": "nmas-human-password-totp"},
            ]},
        ]
        self.runner = LinuxMfaRunner("R3", Dependencies(provider=mock.MagicMock(), privacyidea=privacyidea))
        self.runner._dependency_state = mock.MagicMock(return_value={
            "pam_radius_installed": True,
            "sudo_package_installed": True,
            "visudo_available": True,
            "visudo_executable": True,
        })
        self.token = "b" * 24

    def record(self, step, **extra):
        return PilotEvidence(device="R3").record(step, ok=True, known=SecretSet(), at=10.0,
                                                  actor="test", rollback_token=self.token, **extra)

    def test_precheck_uses_the_actual_ceos_positive_evidence_step(self):
        self.assertEqual(CEOS_POSITIVE_EVIDENCE_STEP, "verify:positive")
        self.assertIn("CEOS_POSITIVE_EVIDENCE_STEP", inspect.getsource(LinuxMfaRunner.precheck))
        PilotEvidence(device="R1").record(
            CEOS_POSITIVE_EVIDENCE_STEP, ok=True, known=SecretSet(), at=11.0, actor="test",
        )
        self.assertIsNotNone(PilotEvidence(device="R1").latest(
            CEOS_POSITIVE_EVIDENCE_STEP, ok=True, since=10.0,
        ))

    def test_activation_refuses_without_live_timer(self):
        self.record("linux-timer-armed")
        with mock.patch.object(lm, "timer_active", return_value=False), self.assertRaises(lm.LinuxMfaError):
            self.runner.activate(self.token)

    def test_activation_failure_records_exact_stage_and_leaves_rollback_armed(self):
        self.record("linux-timer-armed")
        forbidden = "TEST_ONLY_PASSWORD TEST_ONLY_RADIUS_SECRET 654321 protected-pam-contents"
        failure = lm.LinuxMfaActivationError(
            stage="reload_sshd", return_code=1, exception_class="OSError",
            stage_trace=[{"stage": "reload_sshd", "status": "started", "at": 12.0,
                          "diagnostic": forbidden, "protected_file_contents": forbidden}],
        )
        with mock.patch.object(lm, "timer_active", return_value=True), \
             mock.patch.object(lm, "apply", side_effect=failure), \
             mock.patch.object(self.runner, "_known", return_value=SecretSet()), \
             self.assertRaises(lm.LinuxMfaError):
            self.runner.activate(self.token)
        evidence = PilotEvidence(device="R3").latest("linux-activation-failed", ok=False)
        self.assertEqual(evidence["failed_stage"], "reload_sshd")
        self.assertTrue(evidence["rollback_timer_armed"])
        self.assertFalse(evidence["sshd_reload_completed"])
        blob = json.dumps(evidence)
        for value in forbidden.split():
            self.assertNotIn(value, blob)

    def test_post_reload_inspection_failure_is_structured_and_timer_stays_armed(self):
        self.record("linux-timer-armed")
        applied = {"applied": True, "users": ["nmas-admin"], "stage_trace": [
            {"stage": "reload_sshd", "status": "started", "at": 10.0},
            {"stage": "reload_sshd", "status": "completed", "at": 11.0},
        ]}
        with mock.patch.object(lm, "timer_active", return_value=True), \
             mock.patch.object(lm, "apply", return_value=applied), \
             mock.patch.object(lm, "config_hashes", side_effect=lm.LinuxMfaError("TEST_ONLY_RADIUS_SECRET")), \
             mock.patch.object(self.runner, "_known", return_value=SecretSet()), \
             self.assertRaises(lm.LinuxMfaError):
            self.runner.activate(self.token)
        evidence = PilotEvidence(device="R3").latest("linux-activation-failed", ok=False)
        self.assertEqual(evidence["failed_stage"], "post_reload_configuration_inspection")
        self.assertTrue(evidence["sshd_reload_completed"])
        self.assertNotIn("TEST_ONLY_RADIUS_SECRET", json.dumps(evidence))

    def test_successful_activation_records_stage_trace_without_secrets(self):
        self.record("linux-timer-armed")
        trace = [{"stage": "reload_sshd", "status": "completed", "at": 11.0}]
        hashes = {path: {"exists": True, "sha256": "a" * 64} for path in lm.CONFIG_PATHS}
        hashes["sshd_valid"] = True
        with mock.patch.object(lm, "timer_active", return_value=True), \
             mock.patch.object(lm, "apply", return_value={"applied": True, "users": ["nmas-admin"], "stage_trace": trace}), \
             mock.patch.object(lm, "config_hashes", return_value=hashes), \
             mock.patch.object(self.runner, "_known", return_value=SecretSet()):
            result = self.runner.activate(self.token)
        self.assertTrue(result["PASS"])
        evidence = PilotEvidence(device="R3").latest("linux-activated", ok=True)
        self.assertEqual(evidence["activation_stage_trace"], trace)

    def test_human_password_only_and_wrong_totp_must_reject(self):
        with mock.patch.object(lm, "timer_active", return_value=True), \
             mock.patch.object(lm, "ssh_keyboard_login", side_effect=[
                 {"login": "REJECT"}, {"login": "REJECT"}, {"login": "ACCEPT", "privileged": True},
             ]):
            result = self.runner.verify_human(self.token, lambda: ("TEST_ONLY_HUMAN_PASSWORD", "123456"))
        self.assertTrue(result["PASS"])
        blob = json.dumps(PilotEvidence(device="R3").latest("linux-human"))
        self.assertNotIn("TEST_ONLY_HUMAN_PASSWORD", blob)
        self.assertNotIn("123456", blob)

    def test_old_bypass_acceptance_fails_human_gate(self):
        with mock.patch.object(lm, "timer_active", return_value=True), \
             mock.patch.object(lm, "ssh_keyboard_login", side_effect=[
                 {"login": "ACCEPT"}, {"login": "REJECT"}, {"login": "ACCEPT", "privileged": True},
             ]):
            result = self.runner.verify_human(self.token, lambda: ("TEST_ONLY_HUMAN_PASSWORD", "123456"))
        self.assertFalse(result["PASS"])

    def test_operational_drift_blocks_finalization_path(self):
        neighbors = {"ipv4": [{"state": "Full"}], "ipv6": [{"state": "Full"}]}
        self.record("linux-precheck", operational_baseline={"digests": {"frr": "old"},
                                                             "ospf_neighbors": neighbors})
        with mock.patch.object(lm, "timer_active", return_value=True), \
             mock.patch.object(self.runner, "_reads", return_value={"health": True, "nsot": True,
                                                                    "config_retrieval": True, "identity": "nmas-automation"}), \
             mock.patch.object(self.runner, "_operational_snapshot", return_value={
                 "digests": {"frr": "new"}, "ospf_neighbors": neighbors,
                 "ospf_healthy": True, "errors": [],
             }):
            result = self.runner.verify_operational(self.token)
        self.assertFalse(result["PASS"])

    def test_only_volatile_ospf_changes_do_not_block_operational_gate(self):
        neighbors = {"ipv4": [{"state": "Full"}], "ipv6": [{"state": "Full"}]}
        baseline = {"digests": {"frr": "same"}, "ospf_neighbors": neighbors}
        self.record("linux-precheck", operational_baseline=baseline)
        with mock.patch.object(lm, "timer_active", return_value=True), \
             mock.patch.object(self.runner, "_reads", return_value={"health": True, "nsot": True,
                                                                    "config_retrieval": True, "identity": "nmas-automation"}), \
             mock.patch.object(self.runner, "_operational_snapshot", return_value={
                 "digests": {"frr": "same"}, "ospf_neighbors": neighbors,
                 "ospf_healthy": True, "errors": [],
             }):
            result = self.runner.verify_operational(self.token)
        self.assertTrue(result["PASS"])
        self.assertTrue(result["ospf_semantic_state_unchanged"])

    def test_finalize_requires_every_gate_and_cancels_only_after_integrity(self):
        hashes = {path: {"exists": True, "sha256": "a" * 64} for path in lm.CONFIG_PATHS}
        self.record("linux-activated", config_hashes=hashes)
        for step in ("linux-machine-recovery", "linux-operational", "linux-human"):
            self.record(step)
        hashes["sshd_valid"] = True
        with mock.patch.object(lm, "timer_active", side_effect=[True, False]), \
             mock.patch.object(lm, "cancel_timer") as cancel, \
             mock.patch.object(lm, "config_hashes", return_value=hashes):
            result = self.runner.finalize(self.token)
        cancel.assert_called_once()
        self.assertTrue(result["rollback_canceled"])
        self.policy.refresh_from_db()
        self.assertEqual(self.policy.enforcement_state, MfaEnforcementState.LIVE_VERIFIED)
        self.assertEqual(self.policy.central_aaa_state, CentralAaaState.VERIFIED)

    def test_finalize_reconciles_crash_after_timer_cancel_only_with_matching_ready_hashes(self):
        stored = {path: {"exists": True, "sha256": "d" * 64} for path in lm.CONFIG_PATHS}
        self.record("linux-activated", config_hashes=stored)
        for step in ("linux-machine-recovery", "linux-operational", "linux-human"):
            self.record(step)
        self.record("linux-finalize-ready", configuration_hashes=stored)
        observed = {**stored, "sshd_valid": True}
        with mock.patch.object(lm, "timer_active", return_value=False), \
             mock.patch.object(lm, "cancel_timer") as cancel, \
             mock.patch.object(lm, "config_hashes", return_value=observed):
            result = self.runner.finalize(self.token)
        cancel.assert_not_called()
        self.assertTrue(result["reconciled_after_cancel"])


class LinuxMfaMetadataIsolationTests(TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.root = Path(self.tmp.name)
        self.store = self.root / "store.json"
        self.provider_patch = mock.patch.object(device_credentials, "DEFAULT_STORE", self.store)
        self.provider_patch.start()
        root_ref = make_reference("linux-root-shared")
        FileSecretProvider().initialize(root_ref, "TEST_ONLY_ROOT_RECOVERY")
        for device in ("R3", "R4"):
            root = DeviceCredential.objects.get(device_name=device, username="root")
            root.platform = "ubuntu_frr"; root.account_kind = AccountKind.LEGACY_SHARED; root.secret_ref = root_ref; root.save()
            policy = DeviceLoginMfaPolicy.objects.get(device_name=device)
            policy.platform = "ubuntu_frr"; policy.mechanism = MfaMechanism.RADIUS_TOTP
            policy.radius_secret_ref = f"runtime://human-mfa/radius/{device.lower()}"
            policy.blocked_reason = "ROOT_ONLY_ACCOUNT_AND_PAM_NOT_IMPLEMENTED"; policy.save()

    def tearDown(self):
        self.provider_patch.stop(); self.tmp.cleanup()

    def test_prepare_r3_does_not_touch_r4_rows(self):
        before = list(DeviceCredential.objects.filter(device_name="R4").values())
        with mock.patch("core.management.commands.prepare_linux_mfa_rollout_metadata.radius_secret_path",
                        return_value=self.root / "radius_r3_secret"):
            out = io.StringIO(); call_command("prepare_linux_mfa_rollout_metadata", "--device", "R3", "--json", stdout=out)
        payload = json.loads(out.getvalue())
        self.assertFalse(payload["device_changed"])
        self.assertEqual(DeviceCredential.objects.filter(device_name="R3").count(), 4)
        self.assertEqual(list(DeviceCredential.objects.filter(device_name="R4").values()), before)
        self.assertFalse(DeviceCredential.objects.exclude(device_name="R3").filter(rotation_enabled=True).exists())
