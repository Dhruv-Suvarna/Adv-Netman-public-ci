"""Lab 7 closure -- the Ubuntu/FRR MFA rollout runner (``credentials/linux_mfa_runner.py``), each step called directly.

Nothing reaches a device, Docker or systemd: every ``docker exec`` / ``systemd-run`` / ``systemctl`` call goes to an
in-memory ``FakeRunner`` that records the argv, SSH probes are patched, the FreeRADIUS runtime directory is a temp dir
and every credential is a fake value.  POSITIVE: a bound R3 target, a recorded backup, an armed timer, accepted
recovery / operational / human gates, a staged RADIUS client file and the status summary.  NEGATIVE: a device outside
R3/R4, a missing precheck or backup, an inactive timer, a missing legacy-root row, a drifted network, malformed human
factors, incomplete or drifted finalize evidence and a failed FreeRADIUS validation each fail closed -- and no fake
secret reaches recorded evidence.
"""

from __future__ import annotations

import json
import stat
import tempfile
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from django.test import SimpleTestCase, TestCase

from core.models import (AccountKind, CentralAaaState, DeviceCredential, DeviceLoginMfaPolicy, MfaEnforcementState,
                         MfaMechanism)
from core.services.credentials import linux_mfa as lm
from core.services.credentials import r1_pilot as ceos
from core.services.credentials import linux_mfa_runner as lr
from core.services.credentials.r1_pilot import SecretSet
from core.services.credentials.r1_pilot_runner import PilotEvidence
from modules.device_credentials import SecretProviderError
from monitoring.human_mfa import render_radius_clients

TOKEN = "c" * 24
CONTAINER = "clab-srlceos01-R3"
FAKE_BREAKGLASS = "fake-Breakglass-value-31"
FAKE_ROOT = "fake-Root-value-47"
FAKE_HUMAN = "fake-Human-value-59"
FAKE_RADIUS = "fake-Radius-value-61"

V4_NEIGHBORS = {"neighbors": {"10.0.0.1": [{"ifaceName": "eth1:10.0.0.2", "address": "10.0.0.1", "state": "Full/DR"}]}}
V4_INTERFACES = {"interfaces": {"eth1": {"area": "0.0.0.0"}}}
V6_NEIGHBORS = {"neighbors": [{"neighborId": "1.1.1.1", "interfaceName": "eth1", "state": "Full"}]}
V6_INTERFACES = {"eth1": {"areaId": "0.0.0.0"}}


class FakeRunner:
    """Stands in for ``subprocess.run``: answers by command, records every argv, never spawns a process."""

    def __init__(self, *, timer=True, routes4="[]", freeradius=0, backup_rc=0):
        self.calls, self.timer, self.routes4, self.freeradius, self.backup_rc = [], timer, routes4, freeradius, backup_rc

    def __call__(self, argv, **_kwargs):
        self.calls.append(list(argv))
        done = lambda rc=0, out="": SimpleNamespace(returncode=rc, stdout=out, stderr="")  # noqa: E731
        if argv[:2] == ["systemctl", "--user"]:
            if argv[2] == "stop":
                self.timer = False
                return done()
            return done(0 if self.timer else 3)
        if argv[0] == "systemd-run":
            return done()
        if argv[:2] == ["docker", "restart"]:
            return done()
        if argv[:3] == ["docker", "exec", "human_mfa-human-mfa-radius-1"]:
            return done(self.freeradius)
        command = argv[4:] if argv[:3] == ["docker", "exec", "-i"] else argv
        if command[:2] == ["python3", "-c"]:
            return done(self.backup_rc, json.dumps({"files": [{"path": p, "existed": True} for p in lm.CONFIG_PATHS]}))
        if command == ["id", "-u"]:
            return done(0, "0\n")
        replies = {"show running-config": "frr version 8.4\n", "show ip ospf neighbor json": json.dumps(V4_NEIGHBORS),
                   "show ip ospf interface json": json.dumps(V4_INTERFACES), "show ipv6 ospf6 neighbor json": json.dumps(V6_NEIGHBORS),
                   "show ipv6 ospf6 interface json": json.dumps(V6_INTERFACES)}
        if command[:2] == ["vtysh", "-c"]:
            return done(0, replies[command[2]])
        if command[:2] == ["ip", "-j"]:
            return done(0, self.routes4 if command[2:4] == ["-4", "route"] else "[]")
        raise AssertionError(f"unexpected command {argv}")


class FakeProvider:
    VALUES = {"runtime://device-credentials/r3-breakglass": FAKE_BREAKGLASS, "runtime://device-credentials/linux-root-shared": FAKE_ROOT,
              "runtime://device-credentials/r3-nmas-automation-sshkey": "fake-key-material"}

    def current(self, ref):
        if ref not in self.VALUES:
            raise SecretProviderError("missing")
        return SimpleNamespace(value=self.VALUES[ref])


class OspfHealthTests(SimpleTestCase):
    def test_ospf_adjacencies_healthy_when_both_families_are_full(self):
        self.assertTrue(lr.ospf_adjacencies_healthy({"ospf_neighbors": {"ipv4": [{"state": "Full"}], "ipv6": [{"state": "full"}]}}))

    def test_ospf_adjacencies_are_false_without_a_family_or_with_a_non_full_neighbor(self):
        for name, snapshot in (("missing ipv6", {"ospf_neighbors": {"ipv4": [{"state": "Full"}], "ipv6": []}}),
                               ("init neighbor", {"ospf_neighbors": {"ipv4": [{"state": "Init"}], "ipv6": [{"state": "Full"}]}}),
                               ("no snapshot", {})):
            with self.subTest(case=f"refused {name}"):
                self.assertFalse(lr.ospf_adjacencies_healthy(snapshot))


class RunnerFixture(TestCase):
    def setUp(self):
        policy = DeviceLoginMfaPolicy.objects.get(device_name="R3")
        policy.platform, policy.mechanism = "ubuntu_frr", MfaMechanism.RADIUS_TOTP
        policy.radius_secret_ref, policy.automation_exempt = "runtime://human-mfa/radius/r3", True
        policy.save()
        DeviceCredential.objects.filter(device_name="R3").delete()
        DeviceCredential.objects.create(device_name="R3", platform="ubuntu_frr", username="root", account_kind=AccountKind.LEGACY_SHARED,
                                        secret_ref="runtime://device-credentials/linux-root-shared")
        radius = mock.patch.object(lm, "private_runtime_value", return_value=FAKE_RADIUS)
        radius.start()
        self.addCleanup(radius.stop)
        self.privacyidea = mock.MagicMock()
        self.privacyidea.token.return_value = {"serial": ceos.HUMAN_TOKEN_SERIAL, "owner": lm.HUMAN_USERNAME, "active": True,
                                               "locked": False, "revoked": False, "failcount": 0}
        self.privacyidea.audit.side_effect = [
            {"max_id": 100, "rows": []},
            {"max_id": 103, "rows": [{"id": 101, "success": False, "serial": "", "policies": "nmas-human-password-totp"},
                                     {"id": 103, "success": True, "serial": ceos.HUMAN_TOKEN_SERIAL, "policies": "nmas-human-password-totp"}]},
        ]

    def deps(self, **runner):
        self.fake = FakeRunner(**runner)
        return lr.Dependencies(runner=self.fake, clock=lambda: 20.0, provider=FakeProvider(), privacyidea=self.privacyidea, actor="tester")

    def record(self, step, ok=True, **extra):
        return PilotEvidence(device="R3").record(step, ok=ok, known=SecretSet(), at=10.0, actor="test", rollback_token=TOKEN, **extra)

    def precheck(self, satisfied=True):
        return self.record("linux-precheck", checks={"sudo_dependency_satisfied": satisfied})

    def healthy_dependencies(self, vrun):
        vrun._dependency_state = mock.Mock(return_value={"pam_radius_installed": True, "sudo_package_installed": True,
                                                         "visudo_available": True, "visudo_executable": True})
        return vrun

    def runner(self, **fake):
        return self.healthy_dependencies(lr.LinuxMfaRunner("R3", self.deps(**fake)))

    def latest(self, step, ok=True):
        return PilotEvidence(device="R3").latest(step, ok=ok)


class ConstructionAndStatusTests(RunnerFixture):
    def test_runner_binds_the_r3_target_transport_and_evidence(self):
        vrun = lr.LinuxMfaRunner("R3", self.deps())
        self.assertEqual((vrun.device, vrun.target, vrun.transport.target, vrun.transport.runner, vrun.deps.evidence.device),
                         ("R3", lm.TARGETS["R3"], lm.TARGETS["R3"], self.fake, "R3"))
        self.assertEqual(vrun.target.container, CONTAINER)

    def test_runner_refuses_a_device_outside_r3_and_r4(self):
        for device in ("R1", "S1", ""):
            with self.subTest(case=f"refused {device or 'blank'}"), self.assertRaisesRegex(lm.LinuxMfaError, "^Linux MFA rollout is restricted to R3 and R4.$"):
                lr.LinuxMfaRunner(device, self.deps())

    def test_status_returns_policy_configuration_and_latest_finalization(self):
        hashes = {path: {"exists": True, "sha256": "a" * 64} for path in lm.CONFIG_PATHS}
        self.record("linux-finalized", PASS=True)
        with mock.patch.object(lm, "config_hashes", return_value=hashes):
            found = self.runner().status()
        self.assertEqual((found["device"], found["configuration"], found["finalized"]["step"], found["finalized"]["rollback_token"]),
                         ("R3", hashes, "linux-finalized", TOKEN))
        policy = DeviceLoginMfaPolicy.objects.get(device_name="R3")
        self.assertEqual(found["policy"], {"central_aaa_state": policy.central_aaa_state, "enforcement_state": policy.enforcement_state,
                                           "last_verified_at": None if policy.last_verified_at is None else policy.last_verified_at.isoformat(),
                                           "last_verification_result": policy.last_verification_result})


class BackupAndArmTests(RunnerFixture):
    def test_backup_records_the_device_local_backup_after_a_passing_precheck(self):
        self.precheck()
        vrun = self.runner()
        found = vrun.backup()
        token = found["rollback_token"]
        self.assertRegex(token, r"^[0-9a-f]{24}$")
        self.assertEqual((found["PASS"], found["backup_root"], [f["path"] for f in found["files"]]),
                         (True, f"/run/nmas-linux-mfa/r3/{token}", list(lm.CONFIG_PATHS)))
        self.assertEqual(self.fake.calls[0][:6], ["docker", "exec", "-i", CONTAINER, "python3", "-c"])
        self.assertEqual(self.fake.calls[0][-1], "r3-breakglass")
        self.assertEqual(self.latest("linux-backup")["rollback_token"], token)

    def test_backup_is_refused_without_a_passing_precheck_or_sudo_dependency(self):
        with self.assertRaisesRegex(lm.LinuxMfaError, "latest passing Linux MFA precheck is required"):
            self.runner().backup()
        self.precheck(satisfied=False)
        with self.assertRaisesRegex(lm.LinuxMfaError, f"^{lr.VISUDO_MISSING}$"):
            self.runner().backup()
        self.assertEqual(self.fake.calls, [])
        self.assertIsNone(self.latest("linux-backup"))

    def test_arm_creates_a_timer_bound_to_the_backup_token(self):
        self.precheck()
        self.record("linux-backup", PASS=True)
        found = self.runner().arm(TOKEN)
        unit = f"nmas-linux-mfa-r3-{TOKEN}"
        self.assertEqual(found, {"device": "R3", "PASS": True, "rollback_token": TOKEN, "unit": unit, "deadline_seconds": 600})
        self.assertEqual(self.fake.calls[0][:5], ["systemd-run", "--user", f"--unit={unit}", "--on-active=600s", "--collect"])
        self.assertEqual(self.fake.calls[0][-4:], ["--device", "R3", "--token", TOKEN])
        self.assertEqual(self.fake.calls[1], ["systemctl", "--user", "is-active", "--quiet", f"{unit}.timer"])
        self.assertTrue(self.latest("linux-timer-armed")["PASS"])

    def test_arm_is_refused_for_an_unknown_token_or_an_inactive_timer(self):
        self.precheck()
        self.record("linux-backup", PASS=True)
        vrun = self.runner(timer=False)
        with self.assertRaisesRegex(lm.LinuxMfaError, "no matching successful backup"):
            vrun.arm("d" * 24)
        self.assertEqual(self.fake.calls, [])
        with self.assertRaisesRegex(lm.LinuxMfaError, "^Automatic rollback timer was not active after creation.$"):
            vrun.arm(TOKEN)
        self.assertFalse(self.latest("linux-timer-armed", ok=False)["PASS"])


class RecoveryAndOperationalTests(RunnerFixture):
    def logins(self, breakglass="ACCEPT", root="REJECT"):
        def password_login(target, username, password, *, privileged=False):
            self.seen.append((username, privileged))
            if username == "r3-breakglass":
                return {"login": breakglass, "privileged": True}
            return {"login": root if username == "root" else "REJECT"}
        self.seen = []
        return (mock.patch.object(lm, "ssh_key_login", return_value={"login": "ACCEPT"}),
                mock.patch.object(lm, "ssh_password_login", side_effect=password_login))

    def test_verify_machine_recovery_passes_with_key_breakglass_and_rejected_legacy_logins(self):
        key, password = self.logins()
        with key, password:
            found = self.runner().verify_machine_recovery(TOKEN)
        self.assertEqual(found, {"device": "R3", "PASS": True, "rollback_token": TOKEN, "automation_login": "ACCEPT",
                                 "automation_totp_required": False, "breakglass_login": "ACCEPT", "breakglass_privileged": True,
                                 "legacy_root_ssh": "REJECT", "legacy_ubuntu_ssh": "REJECT", "docker_exec_privileged": True})
        self.assertEqual(self.seen, [("r3-breakglass", True), ("root", False), ("ubuntu", False)])
        blob = json.dumps(self.latest("linux-machine-recovery"))
        for value in (FAKE_BREAKGLASS, FAKE_ROOT, FAKE_RADIUS):
            self.assertNotIn(value, blob)

    def test_verify_machine_recovery_fails_when_legacy_root_is_still_accepted(self):
        key, password = self.logins(root="ACCEPT")
        with key, password:
            found = self.runner().verify_machine_recovery(TOKEN)
        self.assertEqual((found["PASS"], found["legacy_root_ssh"]), (False, "ACCEPT"))
        self.assertIsNotNone(self.latest("linux-machine-recovery", ok=False))

    def test_verify_machine_recovery_is_refused_without_timer_or_legacy_root_row(self):
        key, password = self.logins()
        with key as key_login, password, self.assertRaisesRegex(lm.LinuxMfaError, "^Rollback timer is not active during verification.$"):
            self.runner(timer=False).verify_machine_recovery(TOKEN)
        key_login.assert_not_called()
        DeviceCredential.objects.filter(device_name="R3", username="root").delete()
        key, password = self.logins()
        with key, password, self.assertRaisesRegex(lm.LinuxMfaError, "^Protected legacy-root rejection probe could not be prepared.$"):
            self.runner().verify_machine_recovery(TOKEN)
        self.assertIsNone(self.latest("linux-machine-recovery", ok=None))

    def reads(self):
        return mock.patch.object(lr.LinuxMfaRunner, "_reads", return_value={"health": True, "nsot": True, "config_retrieval": True,
                                                                            "identity": lm.SERVICE_USERNAME})

    def test_verify_operational_passes_when_the_fake_frr_state_matches_the_baseline(self):
        baseline = self.runner()._operational_snapshot()
        self.assertEqual((baseline["errors"], baseline["ospf_healthy"], sorted(baseline["digests"])),
                         ([], True, ["addresses", "frr", "routes4", "routes6"]))
        self.assertEqual(baseline["ospf_neighbors"]["ipv4"], [{"address_family": "ipv4", "neighbor_id": "10.0.0.1", "neighbor_address": "10.0.0.1",
                                                               "interface": "eth1", "area": "0.0.0.0", "state": "Full"}])
        self.record("linux-precheck", operational_baseline=baseline)
        with self.reads():
            found = self.runner().verify_operational(TOKEN)
        self.assertEqual((found["PASS"], found["network_state_unchanged"], found["ospf_semantic_state_unchanged"], found["ospf_adjacencies_healthy"]),
                         (True, True, True, True))

    def test_verify_operational_fails_on_route_drift_and_is_refused_without_baseline(self):
        with self.reads(), self.assertRaisesRegex(lm.LinuxMfaError, "passing pre-change operational baseline is required"):
            self.runner().verify_operational(TOKEN)
        self.record("linux-precheck", operational_baseline=self.runner()._operational_snapshot())
        with self.reads():
            found = self.runner(routes4='[{"dst": "203.0.113.0/24"}]').verify_operational(TOKEN)
        self.assertEqual((found["PASS"], found["network_state_unchanged"], found["ospf_semantic_state_unchanged"]), (False, False, True))


class HumanAndFinalizeTests(RunnerFixture):
    def keyboard(self):
        def login(_target, response):
            return {"login": "ACCEPT", "privileged": True} if response == FAKE_HUMAN + "123456" else {"login": "REJECT"}
        return mock.patch.object(lm, "ssh_keyboard_login", side_effect=login)

    def test_verify_human_passes_only_password_plus_totp_and_records_no_factor(self):
        with self.keyboard() as login:
            found = self.runner().verify_human(TOKEN, lambda: (FAKE_HUMAN, "123456"))
        self.assertEqual((found["PASS"], found["password_only"], found["incorrect_totp"], found["password_plus_totp"], found["privacyidea_audit_ids"]),
                         (True, "REJECT", "REJECT", "ACCEPT", [101, 103]))
        self.assertEqual([c.args[1] for c in login.call_args_list], [FAKE_HUMAN, FAKE_HUMAN + "123457", FAKE_HUMAN + "123456"])
        blob = json.dumps(self.latest("linux-human"))
        for value in (FAKE_HUMAN, "123456", "123457"):
            self.assertNotIn(value, blob)

    def test_verify_human_is_refused_for_malformed_factors_or_an_inactive_timer(self):
        for name, factors in (("short otp", (FAKE_HUMAN, "12345")), ("letters", (FAKE_HUMAN, "12a456")), ("no password", ("", "123456"))):
            self.privacyidea.audit.side_effect = None
            self.privacyidea.audit.return_value = {"max_id": 1, "rows": []}
            with self.subTest(case=f"refused {name}"), self.keyboard() as login, \
                    self.assertRaisesRegex(lm.LinuxMfaError, "^Human factors were not supplied in the required protected format.$"):
                self.runner().verify_human(TOKEN, lambda f=factors: f)
            login.assert_not_called()
        with self.assertRaisesRegex(lm.LinuxMfaError, "not active during human verification"):
            self.runner(timer=False).verify_human(TOKEN, lambda: (FAKE_HUMAN, "123456"))
        self.assertIsNone(self.latest("linux-human", ok=None))

    def gates(self, hashes, skip=()):
        self.record("linux-activated", config_hashes=hashes)
        for step in ("linux-machine-recovery", "linux-operational", "linux-human"):
            if step not in skip:
                self.record(step)

    def test_finalize_is_refused_with_missing_evidence_or_drifted_configuration(self):
        hashes = {path: {"exists": True, "sha256": "a" * 64} for path in lm.CONFIG_PATHS}
        self.gates(hashes, skip=("linux-human",))
        with self.assertRaisesRegex(lm.LinuxMfaError, "^All passing verification evidence from this rollback window is required.$"):
            self.runner().finalize(TOKEN)
        self.record("linux-human")
        drifted = {**hashes, lm.CONFIG_PATHS[1]: {"exists": True, "sha256": "b" * 64}, "sshd_valid": True}
        with mock.patch.object(lm, "config_hashes", return_value=drifted), \
                self.assertRaisesRegex(lm.LinuxMfaError, "differs from the verified activation"):
            self.runner().finalize(TOKEN)
        invalid = {**hashes, "sshd_valid": False}
        with mock.patch.object(lm, "config_hashes", return_value=invalid), self.assertRaisesRegex(lm.LinuxMfaError, "integrity check failed"):
            self.runner().finalize(TOKEN)
        with mock.patch.object(lm, "config_hashes", return_value={**hashes, "sshd_valid": True}), \
                self.assertRaisesRegex(lm.LinuxMfaError, "no matching finalize-ready evidence"):
            self.runner(timer=False).finalize(TOKEN)
        self.assertEqual([c for c in self.fake.calls if "stop" in c], [])
        policy = DeviceLoginMfaPolicy.objects.get(device_name="R3")
        self.assertNotEqual(policy.enforcement_state, MfaEnforcementState.LIVE_VERIFIED)


class StageRadiusTests(RunnerFixture):
    def setUp(self):
        super().setUp()
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.destination = Path(self.tmp.name, "freeradius", "clients.conf")
        for patch in (mock.patch.object(render_radius_clients, "RUNTIME", Path(self.tmp.name)),
                      mock.patch.object(render_radius_clients, "render", side_effect=lambda devices: "clients:" + ",".join(devices) + "\n"),
                      mock.patch.object(ceos, "mfa_infrastructure_healthy", return_value=(True, []))):
            patch.start()
            self.addCleanup(patch.stop)

    def test_stage_radius_writes_the_client_file_and_marks_central_aaa_configured(self):
        found = self.runner().stage_radius()
        selected = [*render_radius_clients.CEOS_ELIGIBLE, "R3"]
        self.assertEqual(found, {"device": "R3", "PASS": True, "clients": selected + ["local_fixture"], "protected_config_replaced": True,
                                 "prior_config_present": False, "freeradius_config_valid": True, "freeradius_restarted": True,
                                 "mfa_infrastructure_healthy": True, "ceos_regression_required_after": True})
        self.assertEqual(self.destination.read_text(), "clients:" + ",".join(selected) + "\n")
        self.assertEqual(stat.S_IMODE(self.destination.stat().st_mode), 0o600)
        self.assertEqual(self.fake.calls, [["docker", "exec", "human_mfa-human-mfa-radius-1", "freeradius", "-XC"],
                                           ["docker", "restart", "human_mfa-human-mfa-radius-1"]])
        self.assertEqual(DeviceLoginMfaPolicy.objects.get(device_name="R3").central_aaa_state, CentralAaaState.CONFIGURED)

    def test_stage_radius_failure_restores_the_prior_file_and_is_refused(self):
        render_radius_clients.write_atomic("prior clients\n", self.destination)
        before = DeviceLoginMfaPolicy.objects.get(device_name="R3").central_aaa_state
        with self.assertRaisesRegex(lm.LinuxMfaError, "^FreeRADIUS client staging failed and the prior protected file was restored.$"):
            self.runner(freeradius=1).stage_radius()
        self.assertEqual(self.destination.read_text(), "prior clients\n")
        self.assertEqual(self.fake.calls[-1], ["docker", "restart", "human_mfa-human-mfa-radius-1"])
        self.assertEqual(DeviceLoginMfaPolicy.objects.get(device_name="R3").central_aaa_state, before)
        self.assertIsNone(self.latest("linux-radius-staged", ok=None))


class RadiusClientRendererTests(SimpleTestCase):
    def inventory(self, root, **overrides):
        devices = {name: {"monitoring": {"platform": "linux" if name in render_radius_clients.LINUX_ELIGIBLE else "ceos",
                                         "address": f"192.0.2.{index}"}} for index, name in enumerate(render_radius_clients.ELIGIBLE, start=1)}
        devices.update(overrides)
        path = Path(root, "inventory.yml")
        path.write_text(json.dumps({"network_devices": devices}))
        return path

    def test_client_addresses_returns_every_eligible_static_address(self):
        with tempfile.TemporaryDirectory() as root:
            found = render_radius_clients.client_addresses(self.inventory(root))
        self.assertEqual(found, {name: f"192.0.2.{index}" for index, name in enumerate(render_radius_clients.ELIGIBLE, start=1)})

    def test_client_addresses_refuse_a_wrong_platform_an_auto_address_or_a_missing_inventory(self):
        with tempfile.TemporaryDirectory() as root:
            for name, override, message in (("platform", {"R3": {"monitoring": {"platform": "ceos", "address": "192.0.2.9"}}}, "^R3 is not Linux in inventory.$"),
                                            ("ceos platform", {"R1": {"monitoring": {"platform": "linux", "address": "192.0.2.9"}}}, "^R1 is not cEOS in inventory.$"),
                                            ("auto", {"S1": {"monitoring": {"platform": "ceos", "address": "auto"}}}, "^S1 has no static management address.$")):
                with self.subTest(case=f"refused {name}"), self.assertRaisesRegex(render_radius_clients.RadiusClientError, message):
                    render_radius_clients.client_addresses(self.inventory(root, **override))
            with self.assertRaisesRegex(render_radius_clients.RadiusClientError, "^Inventory is unavailable or invalid.$"):
                render_radius_clients.client_addresses(Path(root, "missing.yml"))

    def test_main_renders_the_selected_devices_to_the_output_path(self):
        with tempfile.TemporaryDirectory() as root, \
                mock.patch.object(render_radius_clients, "render", return_value="client R3 {}\n") as render, \
                mock.patch("sys.argv", ["render_radius_clients.py", "--device", "R3", "--device", "R4", "--output", f"{root}/clients.conf"]), \
                mock.patch("builtins.print") as printed:
            self.assertEqual(render_radius_clients.main(), 0)
            self.assertEqual(Path(root, "clients.conf").read_text(), "client R3 {}\n")
        render.assert_called_once_with(["R3", "R4"])
        printed.assert_called_once_with("Rendered protected RADIUS clients for: R3, R4")

    def test_write_atomic_failure_leaves_the_prior_file_and_no_temporary(self):
        with tempfile.TemporaryDirectory() as root:
            destination = Path(root, "freeradius", "clients.conf")
            render_radius_clients.write_atomic("prior\n", destination)
            with mock.patch("os.replace", side_effect=OSError("disk full")), self.assertRaises(OSError):
                render_radius_clients.write_atomic(f"secret = {FAKE_RADIUS}\n", destination)
            self.assertEqual((destination.read_text(), sorted(p.name for p in destination.parent.iterdir())), ("prior\n", ["clients.conf"]))
