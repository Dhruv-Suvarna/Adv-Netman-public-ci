"""Lab 7 closure -- ``manage.py legacy_bootstrap``: every ``Command.do_*`` action called directly, success and refusal.

Hermetic: device reads, the topology snapshot and the DHCP inspection go through ``helpers.bootstrap.wired`` (the simulated ``World``); the
observation driver is replaced for ``observe`` so no real time passes; the readiness probe is a canned report for ``probe``; Slack is never
configured.  No device, NetBox, Slack or socket is reached and no real sleep happens.  POSITIVE: the exact printed outcome and the rows each
action creates.  NEGATIVE: unknown / missing candidates and runs raise ``CommandError``; a blocked probe, an incomplete capture, an unstarted
observation, a failed or interrupted observe, an unconfirmed approval and a tampered Golden all exit non-zero and create nothing.
"""
from __future__ import annotations

import io
from types import SimpleNamespace
from unittest import mock

from django.core.management.base import CommandError
from django.test import TestCase

from core import models
from core.management.commands import legacy_bootstrap
from core.services import bootstrap_service as bs, slack_service
from core.tests.helpers import bootstrap as bh, bundles as bundle_helper

OPTIONS = {"actor": "operator", "candidate": "", "run": "", "confirm": False, "reason": "", "json": False}


def options(**overrides):
    return {**OPTIONS, **overrides}


PROBE = {"generated_at": "2026-10-19T12:00:00Z", "ready": True, "managed_devices": ["R1", "R2"], "unreachable": [], "monitoring": {"pipeline": "OK"},
         "devices": [{"device": "R1", "platform": "ceos", "capability": "FULL", "reachable": True, "telemetry_freshness": "FRESH",
                      "sections": [{"name": "running-config"}], "section_problems": []}],
         "assessment": {"result": "PASS", "counts": {"pass": 3}, "findings": []}, "blockers": []}


class LegacyBootstrapCommandTests(TestCase):
    def setUp(self):
        patcher = mock.patch.object(slack_service, "is_configured", return_value=False)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.out = io.StringIO()
        self.cmd = legacy_bootstrap.Command(stdout=self.out)

    def captured(self, world=None):
        world = world or bh.World()
        with bh.wired(world):
            self.cmd.do_capture(options())
        return models.ConfigurationBundle.objects.get(kind=models.BundleKind.LEGACY_BASELINE), world

    # --- probe ---------------------------------------------------------------------------------------------------------------
    def test_do_probe_prints_the_ready_report(self):
        with mock.patch.object(bs, "readiness_probe", return_value=PROBE):
            self.assertIsNone(self.cmd.do_probe(options()))
        text = self.out.getvalue()
        self.assertIn("readiness probe at 2026-10-19T12:00:00Z: READY", text)
        self.assertIn("unreachable: none", text)
        self.assertIn("assessment: PASS", text)

    def test_do_probe_of_a_blocked_network_exits_1(self):
        blocked = dict(PROBE, ready=False, unreachable=["R2"], blockers=[{"code": "BASELINE_UNHEALTHY", "message": "m", "remediation": "r"}])
        with mock.patch.object(bs, "readiness_probe", return_value=blocked), self.assertRaises(SystemExit) as exit_:
            self.cmd.do_probe(options(json=False))
        self.assertEqual(exit_.exception.code, 1)
        self.assertIn("BASELINE_UNHEALTHY: m r", self.out.getvalue())

    # --- capture / start ------------------------------------------------------------------------------------------------------
    def test_do_capture_creates_one_sanitized_candidate(self):
        candidate, _world = self.captured()
        text = self.out.getvalue()
        self.assertIn(f"captured {candidate.bundle_id}: {len(bh.MANAGED)} devices", text)
        self.assertIn("integrity INTACT", text)
        for secret in bh.SECRETS:
            self.assertNotIn(secret, text)

    def test_do_capture_of_an_unreachable_device_exits_1_and_creates_nothing(self):
        world = bh.World()
        world.take_down("R1")
        with bh.wired(world), self.assertRaises(SystemExit) as exit_:
            self.cmd.do_capture(options())
        self.assertEqual(exit_.exception.code, 1)
        self.assertIn("BASELINE NOT CAPTURED (nothing was created)", self.out.getvalue())
        self.assertFalse(models.ConfigurationBundle.objects.exists())

    def test_do_start_starts_the_observation_of_the_newest_candidate(self):
        candidate, _world = self.captured()
        self.cmd.do_start(options())
        run = models.LegacyBootstrapRun.objects.get()
        self.assertEqual((run.candidate_id, run.duration_seconds), (candidate.pk, 1800))
        self.assertIn(f"started {run.run_id}:", self.out.getvalue())

    def test_do_start_without_a_candidate_or_with_an_unknown_one_raises(self):
        for label, opts in (("missing candidate", options()), ("unknown candidate", options(candidate="BND-LEGACY-999999"))):
            with self.subTest(label), self.assertRaises(CommandError):
                self.cmd.do_start(opts)
        self.assertFalse(models.LegacyBootstrapRun.objects.exists())

    # --- observe / status -----------------------------------------------------------------------------------------------------
    def test_do_observe_reports_a_technically_passed_observation(self):
        self.captured()
        self.cmd.do_start(options())
        run = models.LegacyBootstrapRun.objects.get()
        finished = SimpleNamespace(run_id=run.run_id, state="COMPLETED", result="PASS", terminal_reason="TECHNICAL_PASS", is_technical_pass=True)
        with mock.patch.object(bs, "drive", return_value=finished) as drive:
            self.assertIsNone(self.cmd.do_observe(options()))
        self.assertEqual(drive.call_args.args[0].pk, run.pk)
        self.assertIn(f"{run.run_id} finished: COMPLETED/PASS reason=TECHNICAL_PASS", self.out.getvalue())

    def test_do_observe_interrupted_or_failed_exits_non_zero_and_never_fabricates(self):
        self.captured()
        self.cmd.do_start(options())
        failed = SimpleNamespace(run_id="BOOT-000001", state="COMPLETED", result="FAIL", terminal_reason="EXPECTED_STATE_FAILED", is_technical_pass=False)
        for label, effect, code in (("refused interrupted", KeyboardInterrupt(), 130), ("refused failed", None, 1)):
            with self.subTest(label), mock.patch.object(bs, "drive", side_effect=effect, return_value=failed), self.assertRaises(SystemExit) as exit_:
                self.cmd.do_observe(options())
            self.assertEqual(exit_.exception.code, code)
        self.assertEqual(models.LegacyBootstrapRun.objects.get().state, models.SoakState.RUNNING)
        self.assertEqual(models.LegacyBootstrapRun.objects.get().samples.count(), 0)

    def test_do_status_prints_the_running_observation_as_json(self):
        self.captured()
        self.cmd.do_start(options())
        run = models.LegacyBootstrapRun.objects.get()
        self.cmd.do_status(options(json=True, run=run.run_id))
        self.assertIn(f'"run_id": "{run.run_id}"', self.out.getvalue())
        self.assertIn('"approved": false', self.out.getvalue())

    def test_do_status_of_an_unknown_or_missing_observation_raises(self):
        for label, opts in (("unknown run", options(run="BOOT-999999")), ("missing run", options())):
            with self.subTest(label), self.assertRaises(CommandError):
                self.cmd.do_status(opts)

    # --- approve / verify -----------------------------------------------------------------------------------------------------
    def test_do_approve_and_do_verify_seal_and_report_the_initial_golden(self):
        run, candidate, world = bh.passed()
        with bh.wired(world):
            self.cmd.do_approve(options(run=run.run_id, confirm=True, reason="adopt the running network"))
        golden = models.ConfigurationBundle.objects.get(kind=models.BundleKind.GOLDEN)
        self.assertIn(f"approved: {golden.bundle_id} provenance=LEGACY_BOOTSTRAP", self.out.getvalue())
        self.assertIsNone(self.cmd.do_verify(options(json=True)))
        self.assertIn(f'"initial_golden": "{golden.bundle_id}"', self.out.getvalue())
        self.assertIn('"golden_integrity": "INTACT"', self.out.getvalue())

    def test_do_approve_without_confirm_or_with_a_failed_observation_is_refused(self):
        with self.subTest("refused without --confirm"), self.assertRaisesRegex(CommandError, "Refusing to approve without --confirm"):
            self.cmd.do_approve(options(run="BOOT-000001"))
        self.captured()
        self.cmd.do_start(options())
        with self.subTest("refused running observation"), self.assertRaises(SystemExit) as exit_:
            self.cmd.do_approve(options(confirm=True))
        self.assertEqual(exit_.exception.code, 1)
        self.assertIn("APPROVAL REFUSED (nothing was created)", self.out.getvalue())
        self.assertFalse(models.ConfigurationBundle.objects.filter(kind=models.BundleKind.GOLDEN).exists())

    def test_do_verify_of_a_tampered_initial_golden_exits_1(self):
        run, candidate, world = bh.passed()
        with bh.wired(world):
            self.cmd.do_approve(options(run=run.run_id, confirm=True))
        golden = models.ConfigurationBundle.objects.get(kind=models.BundleKind.GOLDEN)
        bundle_helper.oob(models.ConfigurationBundle).filter(pk=golden.pk).update(bundle_digest="0" * 64)
        with self.assertRaises(SystemExit) as exit_:
            self.cmd.do_verify(options())
        self.assertEqual(exit_.exception.code, 1)
        self.assertIn("golden_integrity: FAILED", self.out.getvalue())
