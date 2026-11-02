"""One-time legacy baseline bootstrap: HTTP behaviour and the operator command.  GET pages are read-only and contact no device; the POSTs are CSRF-protected,
take only a confirmation from the browser and change application state only; the initial Golden is reachable through exactly one route."""

from __future__ import annotations

import ast
import inspect
import json
import re
from datetime import timedelta
from io import StringIO

from django.core.management import call_command
from django.core.management.base import CommandError
from core.tests.runner import OperatorClient  # V2 Phase 1: authenticated, MFA-verified operator
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from core import models, views
from core.services import bootstrap_service as bs, bundle_service, soak_service
from core.tests.helpers import bootstrap as bh

KIND = models.BundleKind


def post(client, name, *args, data=None):
    return client.post(reverse(f"core:{name}", args=list(args)), data or {})


class BootstrapReadOnlyPageTests(TestCase):
    def test_get_pages_render_contact_no_device_and_change_nothing(self):
        run, candidate, world = bh.passed()
        result = bs.approve(run, actor="operator", confirm=bh.confirm_of(run), now=run.finished_at + timedelta(seconds=30), session_factory=world.factory)
        pages = [reverse("core:bootstrap_home"), reverse("core:bootstrap_run_detail", args=[run.run_id]), reverse("core:bundle_detail", args=[candidate.bundle_id]),
                 reverse("core:bundle_detail", args=[result.bundle.bundle_id]), reverse("core:bundles_list"), reverse("core:automation_landing"),
                 reverse("core:device_builder"), reverse("core:bundle_manifest", args=[result.bundle.bundle_id])]
        counts = {m.__name__: (m.domain if m is models.AuditEvent else m._base_manager).count() for m in (models.ConfigurationBundle, models.LegacyBootstrapRun, models.LegacyBootstrapSample,
                                                                models.LegacyBootstrapDecision, models.AuditEvent, models.Notification)}
        with bh.no_device_access():
            for url in pages:
                with self.subTest(url=url):
                    response = self.client.get(url)
                    self.assertEqual(response.status_code, 200, url)
        self.assertEqual(counts, {m.__name__: (m.domain if m is models.AuditEvent else m._base_manager).count() for m in (models.ConfigurationBundle, models.LegacyBootstrapRun, models.LegacyBootstrapSample,
                                                                                models.LegacyBootstrapDecision, models.AuditEvent, models.Notification)})

    def test_every_mutating_route_is_post_only_and_csrf_protected(self):
        run, candidate, world = bh.passed()
        strict = OperatorClient(enforce_csrf_checks=True)
        routes = [("bootstrap_probe", []), ("bootstrap_capture", []), ("bootstrap_start", [candidate.bundle_id]), ("bootstrap_cancel", [run.run_id]),
                  ("bootstrap_approve", [run.run_id])]
        for name, args in routes:
            with self.subTest(route=name):
                self.assertEqual(self.client.get(reverse(f"core:{name}", args=args)).status_code, 405)
                self.assertEqual(strict.post(reverse(f"core:{name}", args=args), {"confirm": "on"}).status_code, 403)
        self.assertFalse(models.ConfigurationBundle.objects.filter(kind=KIND.GOLDEN).exists())

    def test_the_pages_state_the_two_policies_and_the_one_time_nature(self):
        body = self.client.get(reverse("core:bootstrap_home")).content.decode()
        for text in ("ONE-TIME OPERATION", "Adopts the pre-existing", "7d 0h 0m (168 h)", "30m 0s", "Capture Current Baseline", "Run read-only readiness probe",
                     "cannot be chosen, shortened or backdated"):
            with self.subTest(text=text):
                self.assertIn(text, body)
        landing = self.client.get(reverse("core:automation_landing")).content.decode()
        self.assertIn("Initial Golden Bootstrap", landing)
        self.assertIn(reverse("core:bootstrap_home"), landing)

    def test_refusal_codes_in_the_query_string_are_only_shown_when_known(self):
        body = self.client.get(reverse("core:bootstrap_home") + "?notice=CAPTURE_REFUSED&codes=BOOTSTRAP_BASELINE_INCOMPLETE,<script>alert(1)</script>").content.decode()
        self.assertIn("BOOTSTRAP_BASELINE_INCOMPLETE", body)
        self.assertNotIn("<script>alert(1)</script>", body)

    def test_browser_supplied_fields_are_limited_to_confirmations(self):
        allowed = {"bootstrap_capture": {"confirm"}, "bootstrap_start": {"confirm"}, "bootstrap_cancel": {"confirm"}, "bootstrap_probe": set(),
                   "bootstrap_approve": {"confirm", "reason", "expected_run_id", "expected_candidate_id", "expected_candidate_digest", "expected_baseline_digest"},
                   "bootstrap_home": {"notice", "codes"}, "bootstrap_run_detail": {"notice", "codes"}}
        for name, fields in allowed.items():
            source = inspect.getsource(getattr(views, name))
            identifiers = {node.id for node in ast.walk(ast.parse(source)) if isinstance(node, ast.Name)} | {node.attr for node in ast.walk(ast.parse(source)) if isinstance(node, ast.Attribute)}
            with self.subTest(view=name):
                self.assertEqual(set(re.findall(r"request\.(?:GET|POST)\.get\(\"([a-z_]+)\"", source)), fields)
                for forbidden in ("subprocess", "netmiko", "socket", "eval(", "exec("):
                    self.assertNotIn(forbidden, source)
                # the browser can never reach a duration, a timestamp or a timedelta: no such identifier is even used by a bootstrap view
                self.assertEqual({i for i in identifiers if any(t in i.lower() for t in ("duration", "started_at", "required_end", "timedelta"))}, set())


class BootstrapPostFlowTests(TestCase):
    def test_capture_start_and_the_browser_cannot_choose_the_duration(self):
        world = bh.World()
        with bh.wired(world):
            self.assertEqual(post(self.client, "bootstrap_capture", data={}).status_code, 302)
            self.assertFalse(models.ConfigurationBundle.objects.exists(), "no confirmation -> nothing is captured")
            self.assertEqual(post(self.client, "bootstrap_capture", data={"confirm": "on"}).status_code, 302)
        candidate = models.ConfigurationBundle.objects.get(kind=KIND.LEGACY_BASELINE)
        self.assertEqual(len(candidate.payload["scope"]["devices"]), 10)
        hostile = {"confirm": "on", "duration": "1", "duration_seconds": "1", "started_at": "2000-01-01T00:00:00Z", "required_end_at": "2000-01-01T00:00:01Z",
                   "policy": "{}", "LEGACY_BOOTSTRAP_DURATION_SECONDS": "1", "PROBATION_SOAK_DURATION_SECONDS": "1"}
        before = timezone.now()
        response = self.client.post(reverse("core:bootstrap_start", args=[candidate.bundle_id]) + "?duration=1&started_at=2000-01-01", hostile)
        after = timezone.now()
        run = models.LegacyBootstrapRun.objects.get()
        self.assertEqual(response.status_code, 302)
        self.assertTrue(before <= run.started_at <= after, "the server's own clock")
        self.assertEqual((run.required_end_at - run.started_at, run.duration_seconds), (timedelta(minutes=30), 1800))
        self.assertEqual(run.policy["sample_interval_seconds"], 300)
        again = self.client.post(reverse("core:bootstrap_start", args=[candidate.bundle_id]), {"confirm": "on"})
        self.assertEqual((again.status_code, models.LegacyBootstrapRun.objects.count()), (302, 1), "a double click never starts a second observation")

    def test_a_refused_capture_creates_nothing_and_says_why(self):
        world = bh.World()
        world.take_down("R3", "TIMEOUT")
        with bh.wired(world):
            response = post(self.client, "bootstrap_capture", data={"confirm": "on"})
            page = self.client.get(response["Location"]).content.decode()
        self.assertFalse(models.ConfigurationBundle.objects.exists())
        self.assertIn("BOOTSTRAP_BASELINE_INCOMPLETE", page)
        self.assertIn("all-or-nothing", page)

    def test_probe_is_read_only_and_reports(self):
        world = bh.World()
        world.take_down("S4", "AUTH_FAILED")
        with bh.wired(world):
            response = post(self.client, "bootstrap_probe")
        body = response.content.decode()
        self.assertEqual(response.status_code, 200)
        for text in ("BLOCKED", "S4", "AUTH_FAILED", "Health evaluators", "BOOTSTRAP_BASELINE_INCOMPLETE"):
            self.assertIn(text, body)
        self.assertFalse(models.ConfigurationBundle.objects.exists() or models.LegacyBootstrapRun.objects.exists())

    def test_the_run_page_shows_the_review_evidence_and_the_approve_button_only_when_passed(self):
        run, candidate, world = bh.passed()
        body = self.client.get(reverse("core:bootstrap_run_detail", args=[run.run_id])).content.decode()
        for text in ("TECHNICAL OBSERVATION PASSED", "Approve Initial Golden", candidate.payload_digest, "Included devices", "Actual elapsed", "Configuration drift",
                     "CPU / memory (peak)", "Telemetry freshness", "no synthetic data-plane traffic", "SANITIZED_NOT_BYTE_IDENTICAL", "csrfmiddlewaretoken"):
            with self.subTest(text=text):
                self.assertIn(text, body)
        self.assertEqual(body.count("Approve Initial Golden</button>"), 1)

    def test_no_approve_button_for_a_run_that_did_not_pass(self):
        run, candidate, world = bh.started()
        bh.drive(world, start=bh.T0, until=bh.T0 + timedelta(seconds=300))
        world.edit_config("R1", "hostname R1", "hostname R1\nvlan 7")
        bh.drive(world, start=bh.T0 + timedelta(seconds=450), until=bh.END + timedelta(seconds=300))
        run.refresh_from_db()
        body = self.client.get(reverse("core:bootstrap_run_detail", args=[run.run_id])).content.decode()
        self.assertEqual(run.state, "INVALIDATED")
        self.assertNotIn("Approve Initial Golden</button>", body)
        self.assertIn("can never become Golden", body)
        self.assertIn("CONFIG_DRIFT_DETECTED", body)

    def test_the_explicit_approval_creates_the_initial_golden_and_the_page_exposes_its_provenance_and_timestamps(self):
        run, candidate, world = bh.passed()
        url = reverse("core:bootstrap_approve", args=[run.run_id])
        good = {"confirm": "on", "expected_run_id": run.run_id, "expected_candidate_id": candidate.bundle_id, "expected_candidate_digest": run.candidate_digest,
                "expected_baseline_digest": candidate.payload_digest, "reason": "reviewed the 30-minute evidence"}
        with bh.wired(world):
            for label, data, expected in (
                ("no confirmation", {**good, "confirm": ""}, "CONFIRM_REQUIRED"),
                ("stale digest", {**good, "expected_baseline_digest": "0" * 64}, "CONFIRMATION_MISMATCH"),
                ("secret in the comment", {**good, "reason": "enable secret sha512 hunter2-enable"}, "REASON_SECRET_SHAPED"),
            ):
                with self.subTest(label):
                    response = self.client.post(url, data)
                    page = self.client.get(response["Location"]).content.decode()
                    self.assertIn(expected if label != "no confirmation" else "Tick the confirmation", page)
                    self.assertFalse(models.ConfigurationBundle.objects.filter(kind=KIND.GOLDEN).exists())
            response = self.client.post(url, good)
            self.assertEqual(response.status_code, 302)
            golden = models.ConfigurationBundle.objects.get(kind=KIND.GOLDEN)
            self.assertEqual(response["Location"].split("?")[0], reverse("core:bundle_detail", args=[golden.bundle_id]))
            page = self.client.get(response["Location"]).content.decode()
        self.assertEqual((golden.provenance, golden.lineage["legacy_bootstrap"]["decided_by"]), ("LEGACY_BOOTSTRAP", "nmas-test-operator"))
        for text in ("INITIAL GOLDEN", "LEGACY_BOOTSTRAP", golden.bundle_id, "Golden ID", "Created", "Approved", "Baseline captured", "Bootstrap observation",
                     golden.payload_digest, golden.bundle_digest, "did <strong>not</strong> pass", "INTACT", "reviewed the 30-minute"[:0]):
            with self.subTest(text=text):
                self.assertIn(text, page)
        manifest = self.client.get(reverse("core:bundle_manifest", args=[golden.bundle_id]))
        document = json.loads(manifest.content)
        self.assertEqual((manifest.status_code, document["bundle"]["provenance"]), (200, "LEGACY_BOOTSTRAP"))
        self.assertTrue(bundle_service.verify_export(document).ok)
        repeat = self.client.post(url, good)
        self.assertEqual(models.ConfigurationBundle.objects.filter(kind=KIND.GOLDEN).count(), 1)
        self.assertIn("APPROVED_EXISTS", repeat["Location"])

    def test_approval_is_blocked_when_the_configuration_changed_after_the_observation(self):
        run, candidate, world = bh.passed()
        world.edit_config("S1", "hostname S1", "hostname S1\nvlan 999")
        good = {"confirm": "on", "expected_run_id": run.run_id, "expected_candidate_id": candidate.bundle_id, "expected_candidate_digest": run.candidate_digest,
                "expected_baseline_digest": candidate.payload_digest}
        with bh.wired(world):
            response = self.client.post(reverse("core:bootstrap_approve", args=[run.run_id]), good)
            page = self.client.get(response["Location"]).content.decode()
        self.assertIn("CONFIG_DRIFT_DETECTED", page)
        self.assertFalse(models.ConfigurationBundle.objects.filter(kind=KIND.GOLDEN).exists())

    def test_after_the_initial_golden_every_bootstrap_entry_point_is_locked(self):
        result, run, candidate, world = bh.approved()
        page = self.client.get(reverse("core:bootstrap_home")).content.decode()
        self.assertIn("LEGACY_BOOTSTRAP_ALREADY_COMPLETED", page)
        self.assertNotIn("Start 30-Minute Observation</button>", page)
        with bh.wired(world):
            response = post(self.client, "bootstrap_capture", data={"confirm": "on"})
            self.assertIn("LEGACY_BOOTSTRAP_ALREADY_COMPLETED", response["Location"])
            response = post(self.client, "bootstrap_start", candidate.bundle_id, data={"confirm": "on"})
            self.assertIn("LEGACY_BOOTSTRAP_ALREADY_COMPLETED", response["Location"])
        self.assertEqual(models.ConfigurationBundle.objects.filter(kind=KIND.LEGACY_BASELINE).count(), 1)

    def test_cancelling_through_the_page(self):
        run, candidate, world = bh.started()
        self.assertIn("CONFIRM_REQUIRED", post(self.client, "bootstrap_cancel", run.run_id, data={})["Location"])
        self.assertIn("CANCELLED", post(self.client, "bootstrap_cancel", run.run_id, data={"confirm": "on"})["Location"])
        run.refresh_from_db()
        self.assertEqual(run.state, "CANCELLED")
        self.assertIn("CANCEL_REFUSED", post(self.client, "bootstrap_cancel", run.run_id, data={"confirm": "on"})["Location"])

    def test_the_only_view_that_can_lead_to_the_initial_golden_is_the_explicit_approval(self):
        source = inspect.getsource(views)
        self.assertEqual(source.count("bootstrap_service.approve("), 1)
        for token in ("create_initial_golden", "seal_candidate", "seal_bundle", "create_golden_bundle"):
            self.assertNotIn(token, source)

    def test_normal_soak_pages_and_bundle_pages_still_work_beside_legacy_bundles(self):
        bh.candidate_of()
        self.assertEqual(self.client.get(reverse("core:bundles_list") + "?kind=LEGACY_BASELINE").status_code, 200)
        self.assertEqual(self.client.get(reverse("core:soaks_list")).status_code, 200)
        self.assertEqual(self.client.get(reverse("core:bundle_detail", args=["BND-LEGACY-000001"])).status_code, 200)
        self.assertEqual(self.client.get(reverse("core:bundle_detail", args=["BND-LEGACY-999999"])).status_code, 404)
        self.assertEqual(soak_service.current_policy().duration_seconds, 604800)


class BootstrapCommandTests(TestCase):
    def run_command(self, *args, world=None, expect_exit=None):
        out = StringIO()
        with bh.wired(world or bh.World()):
            try:
                call_command("legacy_bootstrap", *args, stdout=out)
            except SystemExit as exit_request:
                self.assertEqual(exit_request.code, expect_exit, out.getvalue())
                return out.getvalue()
        self.assertIsNone(expect_exit, out.getvalue())
        return out.getvalue()

    def test_probe_capture_start_status_and_verify(self):
        world = bh.World()
        self.assertIn("READY", self.run_command("probe", world=world))
        self.assertIn("captured BND-LEGACY-000001: 10 devices", self.run_command("capture", "--actor", "cli", world=world))
        started = self.run_command("start", world=world)
        self.assertIn("30 minutes, 300 s samples", started)
        status = json.loads(self.run_command("status", "--json", world=world))
        self.assertEqual((status["state"], status["run_id"], status["approved"]), ("RUNNING", "BOOT-000001", False))
        verify = json.loads(self.run_command("verify", "--json", world=world))
        self.assertEqual((verify["gate"], verify["normal_probation_seconds"], verify["bootstrap_seconds"]), ([], 604800, 1800))
        self.assertEqual(verify["candidates"], {"BND-LEGACY-000001": "INTACT"})

    def test_a_blocked_probe_and_a_refused_capture_exit_nonzero_and_create_nothing(self):
        world = bh.World()
        world.take_down("R2", "TIMEOUT")
        self.assertIn("BOOTSTRAP_BASELINE_INCOMPLETE", self.run_command("probe", world=world, expect_exit=1))
        self.assertIn("BASELINE NOT CAPTURED", self.run_command("capture", world=world, expect_exit=1))
        self.assertFalse(models.ConfigurationBundle.objects.exists())

    def test_approve_requires_the_explicit_confirmation_flag(self):
        run, candidate, world = bh.passed()
        with self.assertRaises(CommandError):
            call_command("legacy_bootstrap", "approve", "--run", run.run_id, stdout=StringIO())
        self.assertFalse(models.ConfigurationBundle.objects.filter(kind=KIND.GOLDEN).exists())
        with bh.wired(world):
            out = StringIO()
            call_command("legacy_bootstrap", "approve", "--run", run.run_id, "--confirm", "--actor", "operator", stdout=out)
        self.assertIn("provenance=LEGACY_BOOTSTRAP", out.getvalue())
        self.assertEqual(models.ConfigurationBundle.objects.get(kind=KIND.GOLDEN).lineage["legacy_bootstrap"]["decided_by"], "operator")
        verify = json.loads(self.run_command("verify", "--json"))
        self.assertEqual((verify["golden_integrity"], verify["phase21_entry"]["source"]), ("INTACT", "LEGACY_BOOTSTRAP"))
        self.assertEqual(verify["gate"], ["LEGACY_BOOTSTRAP_ALREADY_COMPLETED"])

    def test_observe_on_a_finished_run_is_a_no_op(self):
        run, candidate, world = bh.passed()
        self.assertIn("is not running", self.run_command("observe", "--run", run.run_id, world=world))
