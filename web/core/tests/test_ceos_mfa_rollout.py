"""Generic cEOS MFA rollout contracts; simulator/fake secrets only."""
from __future__ import annotations

import tempfile
from pathlib import Path

import yaml
from django.core.management import call_command
from django.core.management.base import CommandError
from django.test import SimpleTestCase, TestCase

from modules.device_credentials import FileSecretProvider

from core.models import (AccountKind, CentralAaaState, DeviceAuthMethod, DeviceCredential,
                         DeviceLoginMfaPolicy, MfaEnforcementState, MfaMechanism)
from core.services.credentials import mfa
from core.services.credentials import r1_pilot as p
from core.services.credentials.r1_pilot_runner import PilotDependencies, PilotEvidence, R1PilotRunner
from core.tests.test_r1_mfa_pilot import FakeEos, HUMAN_OTP, HUMAN_PASSWORD, _Clock


class TargetSelectionTests(SimpleTestCase):
    def test_authoritative_eligible_set_and_device_specific_routes(self):
        for device in p.MANAGED_CEOS_MFA_DEVICES:
            target = p.target_for(device)
            self.assertEqual(target.device, device)
            self.assertEqual(target.container, f"clab-srlceos01-{device}")
        r2 = p.target_for("R2")
        self.assertEqual(r2.automation_ref, "runtime://device-credentials/r2-nmas-automation")
        self.assertEqual(r2.breakglass_account, "r2-breakglass")
        self.assertEqual(r2.radius_ref, "runtime://human-mfa/radius/r2")

    def test_linux_r5_unknown_and_wrong_platform_are_refused(self):
        for device in ("R3", "R4", "R5", "NOPE"):
            with self.subTest(device=device), self.assertRaises(p.PilotError):
                p.target_for(device)
        fixture = {
            "network_devices": {"R2": {"monitoring": {"platform": "linux", "address": "192.0.2.2"}}},
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "inventory.yml"
            path.write_text(yaml.safe_dump(fixture))
            with self.assertRaisesRegex(p.PilotError, "not classified as cEOS"):
                p.target_for("R2", inventory_path=path)


class GenericMetadataTests(TestCase):
    def setUp(self):
        DeviceCredential.objects.filter(device_name="R2").delete()
        DeviceCredential.objects.create(
            device_name="R2", platform="arista_ceos", username="admin",
            account_kind=AccountKind.LEGACY_SHARED, auth_method=DeviceAuthMethod.PASSWORD,
            secret_ref="runtime://device-credentials/ceos-admin-shared",
            account_role="network-admin", privilege_level=15,
        )
        DeviceLoginMfaPolicy.objects.update_or_create(device_name="R2", defaults={
            "platform": "arista_ceos", "mechanism": MfaMechanism.RADIUS_TOTP,
            "enforcement_state": MfaEnforcementState.PLANNED,
            "central_aaa_state": CentralAaaState.PLANNED,
            "radius_secret_ref": "runtime://human-mfa/radius/r2", "radius_source_interface": "Vlan200",
        })

    def test_generic_command_is_idempotent_and_records_reviewed_digest(self):
        r1_before = list(DeviceCredential.objects.filter(device_name="R1").values())
        for _ in range(2):
            call_command("prepare_ceos_mfa_rollout_metadata", "--device", "R2",
                         "--human-username", "nmas-admin")
        rows = DeviceCredential.objects.filter(device_name="R2")
        self.assertEqual(rows.count(), 4)
        self.assertEqual(rows.get(account_kind=AccountKind.BREAK_GLASS).username, "r2-breakglass")
        policy = DeviceLoginMfaPolicy.objects.get(device_name="R2")
        candidate = mfa.render_candidate(policy, list(rows))
        self.assertFalse(candidate.blockers)
        self.assertEqual(policy.candidate_digest, candidate.digest)
        self.assertEqual(list(DeviceCredential.objects.filter(device_name="R1").values()), r1_before)

    def test_generic_command_refuses_deferred_devices(self):
        for device in ("R3", "R4", "R5"):
            with self.subTest(device=device), self.assertRaises(CommandError):
                call_command("prepare_ceos_mfa_rollout_metadata", "--device", device,
                             "--human-username", "nmas-admin")


class GenericR2RolloutTests(TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.target = p.target_for("R2")
        self.provider = FileSecretProvider(root / "device-credentials" / "store.json")
        values = {
            self.target.automation_ref: "TESTONLYr2AutomationSecret001",
            self.target.breakglass_ref: "TESTONLYr2BreakglassSecret002",
            self.target.legacy_ref: "TSTadm3",
        }
        for ref, value in values.items():
            self.provider.initialize(ref, value)
        radius = root / "radius"
        radius.mkdir(mode=0o700)
        (radius / "radius_r2_secret").write_text("TESTONLY+r2/Radius=Secret003\n")
        (radius / "radius_r2_secret").chmod(0o600)
        self.eos = FakeEos()
        self.original = self.eos.text()
        self.clock = _Clock()
        DeviceCredential.objects.filter(device_name="R2").delete()
        for kwargs in (
            dict(username="nmas-automation", account_kind=AccountKind.SERVICE,
                 secret_ref=self.target.automation_ref),
            dict(username="r2-breakglass", account_kind=AccountKind.BREAK_GLASS,
                 secret_ref=self.target.breakglass_ref),
            dict(username="nmas-admin", account_kind=AccountKind.HUMAN, secret_ref="",
                 auth_method=DeviceAuthMethod.PASSWORD_AND_TOTP),
            dict(username="admin", account_kind=AccountKind.LEGACY_SHARED,
                 secret_ref=self.target.legacy_ref),
        ):
            DeviceCredential.objects.create(
                device_name="R2", platform="arista_ceos", auth_method=kwargs.pop("auth_method", DeviceAuthMethod.PASSWORD),
                account_role="network-admin", privilege_level=15, **kwargs)
        policy, _ = DeviceLoginMfaPolicy.objects.update_or_create(device_name="R2", defaults={
            "platform": "arista_ceos", "mechanism": MfaMechanism.RADIUS_TOTP,
            "enforcement_state": MfaEnforcementState.PLANNED,
            "central_aaa_state": CentralAaaState.PLANNED,
            "radius_secret_ref": self.target.radius_ref, "radius_source_interface": "Vlan200",
        })
        candidate = p.staged_candidate(
            mfa.render_candidate(policy, list(DeviceCredential.objects.filter(device_name="R2"))), self.target)
        policy.candidate_digest = candidate.digest
        policy.save(update_fields=["candidate_digest", "updated_at"])
        self.reads = {
            "target_identities": ["nmas-automation", "admin"],
            "other_identities": {"R1": ["nmas-automation", "admin"], "S1": ["nmas-automation", "admin"]},
            "nsot": True, "config_retrieval": True, "health": True, "health_status": "HEALTHY",
        }
        resolver = p.PilotSecretResolver(provider=self.provider, radius_root=radius)
        deps = PilotDependencies(
            transport=p.EosCliTransport(self.target.container, runner=self.eos,
                                        scanner_factory=lambda known: p.ProcessTableScanner(known, proc_root=root / "noproc")),
            resolver=resolver, evidence=PilotEvidence("R2"), candidate=lambda: candidate,
            infrastructure=lambda: (True, []), reachable=lambda: True, ssh_login=self.eos.ssh_login,
            nmas_reads=lambda: dict(self.reads), human_factors=lambda: (HUMAN_PASSWORD, HUMAN_OTP),
            approval=lambda: self.target.approval_phrase, clock=self.clock,
        )
        self.runner = R1PilotRunner(deps, device="R2", target=self.target)

    def tearDown(self):
        self.tmp.cleanup()

    def test_full_generic_lifecycle_is_atomic_persistent_and_metadata_scoped(self):
        self.assertTrue(self.runner.validate()["PASS"])
        precheck = self.runner.precheck()
        self.assertTrue(precheck["PASS"], precheck)
        self.runner.checkpoint(self.target.checkpoint_original)
        self.runner.stage1()
        self.runner.checkpoint(self.target.checkpoint_stage2)
        self.runner.stage2()
        self.assertTrue(self.runner.verify("post-stage2")["PASS"])
        self.assertTrue(self.runner.confirm()["ok"])
        self.assertTrue(self.runner.persist()["ok"])
        recorded = self.runner.record_verification()
        self.assertTrue(recorded["ok"])
        policy = DeviceLoginMfaPolicy.objects.get(device_name="R2")
        self.assertEqual((policy.central_aaa_state, policy.enforcement_state),
                         (CentralAaaState.VERIFIED, MfaEnforcementState.LIVE_VERIFIED))
        self.assertEqual(p._normalized_config(self.eos.text()), p._normalized_config(self.eos.text(self.eos.startup)))
        self.assertNotIn("username admin ", self.eos.text())
        restored = self.runner.replace(self.target.checkpoint_original)
        self.assertTrue(restored["ok"])
        policy.refresh_from_db()
        self.assertEqual((policy.central_aaa_state, policy.enforcement_state),
                         (CentralAaaState.PLANNED, MfaEnforcementState.PLANNED))
        self.assertIsNone(policy.last_verified_at)

    def test_stage1_failure_cleans_only_selected_device_state(self):
        self.runner.validate()
        self.runner.precheck()
        self.runner.checkpoint(self.target.checkpoint_original)
        self.reads["health"] = False
        with self.assertRaisesRegex(p.PilotError, "removed"):
            self.runner.stage1()
        self.assertEqual(self.eos.text(), self.original)

    def test_other_device_routing_change_blocks_selected_device(self):
        self.runner.validate()
        self.runner.precheck()
        self.runner.checkpoint(self.target.checkpoint_original)
        self.reads["other_identities"]["S1"] = ["admin"]
        with self.assertRaisesRegex(p.PilotError, "removed"):
            self.runner.stage1()
        self.assertEqual(self.eos.text(), self.original)

    def test_wrong_approval_blocks_before_mutation(self):
        self.runner.validate()
        self.runner.precheck()
        self.runner.deps.approval = lambda: "wrong"
        with self.assertRaises(p.PilotError):
            self.runner.checkpoint(self.target.checkpoint_original)
        self.assertEqual(self.eos.text(), self.original)

    def test_precheck_is_read_only_and_generic_command_has_no_secret_arguments(self):
        result = self.runner.precheck()
        self.assertTrue(result["PASS"])
        stdin = "\n".join(str(call.get("input") or "") for call in self.eos.calls)
        self.assertNotIn("copy running-config", stdin)
        self.assertNotIn(" commit", stdin)
        from core.management.commands.ceos_mfa_rollout import Command
        parser = Command().create_parser("manage.py", "ceos_mfa_rollout")
        options = {name for action in parser._actions for name in action.option_strings}
        self.assertFalse(options & {"--approval", "--password", "--secret", "--otp"})
