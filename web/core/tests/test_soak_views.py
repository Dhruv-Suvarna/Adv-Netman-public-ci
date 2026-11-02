"""Phase-20 views and scheduler commands: read-only GETs, explicit CSRF POSTs, no browser authority over time / duration / evidence, and the
command entry points.  Representative tests only (the decision logic itself is in test_soak_decision)."""

from __future__ import annotations

import inspect
import io
import json
import re
from datetime import timedelta
from unittest import mock

from django.core.management import call_command
from core.tests.runner import OperatorClient  # V2 Phase 1: authenticated, MFA-verified operator
from django.urls import reverse
from django.utils import timezone

from core import models, views
from core.services import bundle_service as bs, soak_service as ss
from core.tests.helpers import bundles as bh, soak as sh

SoakFixture = sh.SoakFixture
SS = models.SoakState


class ViewFixture(SoakFixture):
    def url(self, name, *args):
        return reverse(f"core:{name}", args=args)

    def bundle_page(self):
        return self.client.get(self.url("bundle_detail", self.f.prob.bundle_id))

    def real_time_pass(self):
        """A soak whose whole (short, simulated) window ended a few minutes ago in REAL time, so the decision window is open for the views."""
        start = timezone.now() - timedelta(seconds=sh.DURATION + 600)
        sh.passed(self.f, start=start)
        return self.run_row()

    def detail(self, run=None, query=""):
        return self.client.get(self.url("soak_detail", (run or self.run_row()).soak_id) + query)


class StartSoakViewTests(ViewFixture):
    def test_the_probation_page_offers_start_only_as_a_csrf_form_and_starts_nothing_on_get(self):
        before = bh.table_counts()
        with bh.no_device_or_network():
            page = self.bundle_page()
            get_start = self.client.get(self.url("bundle_soak_start", self.f.prob.bundle_id))
        self.assertEqual(get_start.status_code, 405)
        self.assertContains(page, "Start Probation Soak (2h 0m (2 h))")
        self.assertContains(page, "NOT A PRODUCTION DURATION")      # the short (test) policy is never mistaken for production
        self.assertContains(page, "csrfmiddlewaretoken")
        self.assertContains(page, "you cannot change it")
        self.assertEqual(bh.count_changes(before, bh.table_counts()), {}, "GET bundle / GET start mutate nothing")

    def test_start_needs_the_confirmation_and_the_server_alone_decides_start_end_and_duration(self):
        url = self.url("bundle_soak_start", self.f.prob.bundle_id)
        unconfirmed = self.client.post(url)
        self.assertTrue(unconfirmed["Location"].endswith("?notice=SOAK_CONFIRM_REQUIRED"))
        self.assertFalse(models.ProbationSoakRun.objects.exists())
        forged = {"confirm": "on", "duration": "60", "duration_seconds": "1", "started_at": "2001-01-01T00:00:00Z", "required_end_at": "2001-01-01T00:01:00Z",
                  "policy": "{}", "PROBATION_SOAK_DURATION_SECONDS": "1", "bundle_digest": "0" * 64, "evidence": "PASS", "state": "COMPLETED", "result": "PASS"}
        before = timezone.now()
        with bh.no_device_or_network(), self.assertLogs("core.services.soak.lifecycle", "ERROR"):
            done = self.client.post(url + "?duration=60&PROBATION_SOAK_DURATION_SECONDS=1", forged)
        after = timezone.now()
        run = models.ProbationSoakRun.objects.get()
        self.assertEqual(done["Location"], f"{self.url('soak_detail', run.soak_id)}?notice=STARTED")
        self.assertTrue(before <= run.started_at <= after, "the start is the SERVER's clock")
        self.assertEqual(run.required_end_at - run.started_at, timedelta(seconds=7200), "the duration is the pinned server policy, not the browser's")
        self.assertEqual((run.state, run.result, run.bundle_digest, run.started_by), (SS.RUNNING, "", self.f.prob.bundle_digest, "nmas-test-operator"))  # V2 Phase 1: the authenticated user, not a hard-coded label
        again = self.client.post(url, {"confirm": "on"})
        self.assertTrue(again["Location"].endswith("?notice=ACTIVE"))
        self.assertEqual(models.ProbationSoakRun.objects.count(), 1, "a double click never creates a second soak")

    def test_an_ineligible_candidate_lists_blockers_and_a_refused_start_creates_nothing(self):
        sh.history_run(self.f.prob, ["R1"])
        page = self.bundle_page()
        self.assertContains(page, "A soak can not start")
        self.assertContains(page, "SUPERSEDED")
        self.assertNotContains(page, "Start Probation Soak")
        refused = self.client.post(self.url("bundle_soak_start", self.f.prob.bundle_id), {"confirm": "on"})
        self.assertTrue(refused["Location"].endswith("?notice=SOAK_START_REFUSED"))
        self.assertFalse(models.ProbationSoakRun.objects.exists())

    def test_uat_and_unknown_bundles_are_not_soakable_endpoints(self):
        self.assertTrue(self.client.post(self.url("bundle_soak_start", self.f.uat.bundle_id), {"confirm": "on"})["Location"].endswith("SOAK_START_REFUSED"))
        self.assertEqual(self.client.post(self.url("bundle_soak_start", "BND-PROB-999999"), {"confirm": "on"}).status_code, 404)
        self.assertFalse(models.ProbationSoakRun.objects.exists())


class SoakDetailAndDecisionViewTests(ViewFixture):
    def test_the_running_soak_page_is_server_side_read_only_and_has_no_client_clock(self):
        self.start()
        sh.drive(self.f.world, start=sh.T0, until=sh.T0 + timedelta(seconds=1200))
        before = bh.table_counts()
        with bh.no_device_or_network():
            page = self.detail()
        self.assertContains(page, "Observation in progress")
        self.assertContains(page, "Sample timeline")
        self.assertContains(page, "Cancel this soak")
        self.assertNotContains(page, "Approve Golden")
        body = page.content.decode()
        for token in ("setInterval", "setTimeout", "Date.now", "new Date"):
            self.assertNotIn(token, body, "nothing counts down on the browser's clock")
        self.assertEqual(bh.count_changes(before, bh.table_counts()), {}, "GET soak page mutates nothing")
        listing = self.client.get(self.url("soaks_list"))
        self.assertContains(listing, self.f.run.soak_id)
        self.assertEqual(self.client.get(self.url("soak_detail", "SOAK-999999")).status_code, 404)
        self.assertEqual(self.client.get(self.url("soak_detail", "nonsense")).status_code, 404)

    def test_a_technically_passed_soak_offers_the_decision_and_get_never_decides(self):
        run = self.real_time_pass()
        page = self.detail(run)
        self.assertContains(page, "TECHNICAL SOAK PASSED")
        self.assertContains(page, "Operator Golden decision required")
        self.assertContains(page, "Approve Golden")
        self.assertContains(page, run.bundle_digest)
        self.assertContains(page, 'name="expected_bundle_digest"')
        self.assertContains(page, "csrfmiddlewaretoken")
        self.assertEqual(self.client.get(self.url("soak_decision", run.soak_id)).status_code, 405)
        self.assertFalse(models.ConfigurationBundle.objects.filter(kind="GOLDEN").exists())

    def decide(self, run, **fields):
        data = {"decision": "APPROVE", "confirm": "on", "expected_soak_id": run.soak_id, "expected_bundle_id": run.bundle.bundle_id,
                "expected_bundle_digest": run.bundle_digest, "reason": ""}
        data.update(fields)
        return self.client.post(self.url("soak_decision", run.soak_id), data)

    def test_approve_creates_golden_once_and_the_bundle_page_shows_the_full_lineage(self):
        run = self.real_time_pass()
        with self.assertLogs("core.services.soak.lifecycle", "ERROR"), bh.no_device_or_network():
            approved = self.decide(run, reason="Reviewed; healthy for the whole window.", timestamp="2001-01-01", digest="0" * 64, manifest="{}")
        golden = models.ConfigurationBundle.objects.get(kind="GOLDEN")
        self.assertEqual(approved["Location"], f"{self.url('bundle_detail', golden.bundle_id)}?notice=APPROVED")
        self.assertEqual(models.GoldenDecision.objects.get().reason, "Reviewed; healthy for the whole window.")
        again = self.decide(run)
        self.assertTrue(again["Location"].endswith("?notice=APPROVED_EXISTS"))
        self.assertEqual(models.ConfigurationBundle.objects.filter(kind="GOLDEN").count(), 1, "a double click never creates a second Golden")
        page = self.client.get(self.url("bundle_detail", golden.bundle_id))
        for text in ("successful soak", run.soak_id, "operator decision", "APPROVE", run.evidence_digest, "same configuration payload", "startup configuration"):
            self.assertContains(page, text)
        self.assertContains(self.client.get(self.url("bundle_detail", self.f.prob.bundle_id)), golden.bundle_id)
        soak_page = self.detail(run)
        self.assertContains(soak_page, golden.bundle_id)
        self.assertNotContains(soak_page, "Approve Golden")

    def test_reject_records_the_decision_creates_no_golden_and_a_later_approval_is_refused_with_its_reason(self):
        run = self.real_time_pass()
        rejected = self.decide(run, decision="REJECT", reason="Not now.")
        self.assertTrue(rejected["Location"].endswith("?notice=REJECTED"))
        self.assertFalse(models.ConfigurationBundle.objects.filter(kind="GOLDEN").exists())
        refused = self.decide(run)
        self.assertIn("DECISION_REFUSED", refused["Location"])
        self.assertIn("DECISION_ALREADY_RECORDED", refused["Location"])
        page = self.client.get(refused["Location"])
        self.assertContains(page, "DECISION_ALREADY_RECORDED")
        self.assertContains(page, "REJECT")
        self.assertNotContains(page, "Approve Golden")

    def test_the_decision_needs_the_acknowledgement_the_exact_artifact_and_a_technical_pass(self):
        run = self.real_time_pass()
        cases = {
            "no acknowledgement": (dict(confirm=""), "CONFIRM_REQUIRED"),
            "a stale / replaced digest": (dict(expected_bundle_digest="0" * 64), "CONFIRMATION_MISMATCH"),
            "another bundle id": (dict(expected_bundle_id="BND-PROB-000042"), "CONFIRMATION_MISMATCH"),
            "an unknown decision": (dict(decision="PROMOTE"), "DECISION_INVALID"),
        }
        for label, (fields, expected) in cases.items():
            with self.subTest(case=label):
                response = self.decide(run, **fields)
                self.assertIn(expected, response["Location"])
        self.assertFalse(models.ConfigurationBundle.objects.filter(kind="GOLDEN").exists())
        self.assertFalse(models.GoldenDecision.objects.exists())

    def test_an_ineligible_soak_cannot_be_approved_and_refusal_codes_are_never_reflected_as_text(self):
        self.start()
        run = self.run_row()
        response = self.decide(run)
        self.assertIn("SOAK_NOT_PASSED", response["Location"])
        self.assertFalse(models.ConfigurationBundle.objects.filter(kind="GOLDEN").exists())
        page = self.detail(run, "?notice=DECISION_REFUSED&codes=SOAK_NOT_PASSED,<script>alert(1)</script>,%00")
        self.assertContains(page, "SOAK_NOT_PASSED")
        self.assertNotContains(page, "<script>alert(1)</script>")
        self.assertNotContains(self.detail(run, "?notice=<b>x</b>"), "<b>x</b>")

    def test_cancel_is_an_explicit_post_and_leaves_the_bundle_and_evidence_alone(self):
        self.start()
        sh.drive(self.f.world, start=sh.T0, until=sh.T0 + timedelta(seconds=600))
        run = self.run_row()
        self.assertEqual(self.client.get(self.url("soak_cancel", run.soak_id)).status_code, 405)
        self.assertTrue(self.client.post(self.url("soak_cancel", run.soak_id))["Location"].endswith("CONFIRM_REQUIRED"))
        self.assertTrue(self.run_row().is_running)
        done = self.client.post(self.url("soak_cancel", run.soak_id), {"confirm": "on"})
        self.assertTrue(done["Location"].endswith("?notice=CANCELLED"))
        self.assertEqual((self.run_row().state, self.run_row().samples.count()), (SS.CANCELLED, 2))
        self.assertTrue(self.client.post(self.url("soak_cancel", run.soak_id), {"confirm": "on"})["Location"].endswith("CANCEL_REFUSED"))
        self.assertTrue(bs.verify_bundle_integrity(self.f.prob).ok)

    def test_every_mutating_endpoint_is_post_only_and_csrf_protected(self):
        self.start()
        strict = OperatorClient(enforce_csrf_checks=True)
        targets = [self.url("bundle_soak_start", self.f.prob.bundle_id), self.url("soak_cancel", self.f.run.soak_id), self.url("soak_decision", self.f.run.soak_id)]
        before = bh.table_counts()
        for target in targets:
            with self.subTest(endpoint=target):
                self.assertEqual(strict.post(target, {"confirm": "on", "decision": "APPROVE"}).status_code, 403)
                for method in ("get", "put", "delete", "patch"):
                    self.assertEqual(getattr(self.client, method)(target).status_code, 405)
        self.assertEqual(bh.count_changes(before, bh.table_counts()), {})
        self.assertEqual(models.ProbationSoakRun.objects.filter(state=SS.RUNNING).count(), 1)

    def test_the_soak_views_are_thin_and_read_only_named_fields_from_the_browser(self):
        allowed = {"soaks_list": set(), "soak_detail": {"notice", "codes"}, "bundle_soak_start": {"confirm"}, "soak_cancel": {"confirm"},
                   "soak_decision": {"confirm", "decision", "reason", "expected_soak_id", "expected_bundle_id", "expected_bundle_digest"}}
        for name, fields in allowed.items():
            source = re.sub(r'""".*?"""', "", inspect.getsource(getattr(views, name)), count=1, flags=re.S)   # code only: a docstring may describe what is forbidden
            with self.subTest(view=name):
                self.assertEqual(set(re.findall(r"request\.(?:GET|POST)\.get\(\"([a-z_]+)\"", source)), fields)
                for forbidden in ("subprocess", "netmiko", "socket", "eval(", "exec(", "timezone", "datetime", "started_at", "duration", "manifest=", "digest=", "payload"):
                    self.assertNotIn(forbidden, source)


class SoakCommandTests(SoakFixture):
    def run_command(self, *args):
        out = io.StringIO()
        with sh.simulated(self.f.world):
            try:
                call_command(*args, stdout=out)
            except SystemExit as exit_:
                return out.getvalue(), exit_.code
        return out.getvalue(), 0

    def test_the_tick_command_reports_and_collects_only_through_the_service(self):
        text, code = self.run_command("probation_soak_tick")
        self.assertEqual((code, "0 running soak(s)" in text), (0, True))
        self.start(now=timezone.now() - timedelta(seconds=30))
        dry, _ = self.run_command("probation_soak_tick", "--dry-run", "--json")
        self.assertEqual([r["action"] for r in json.loads(dry)["runs"]], ["WOULD_SAMPLE"])
        self.assertEqual(self.run_row().samples.count(), 0)
        with mock.patch("core.services.health.telemetry.collect", return_value=sh.h.snapshot(now=timezone.now())):
            done, code = self.run_command("probation_soak_tick", "--json", "--soak", self.f.run.soak_id)
        report = json.loads(done)
        self.assertEqual((code, [r["action"] for r in report["runs"]], report["dry_run"]), (0, ["SAMPLED"], False))
        self.assertEqual(self.run_row().samples.count(), 1)
        again, _ = self.run_command("probation_soak_tick", "--json")
        self.assertEqual([r["action"] for r in json.loads(again)["runs"]], ["NOT_DUE"], "running the command twice never duplicates a sample")

    def test_the_probe_reports_evidence_and_blockers_and_persists_nothing(self):
        before = bh.table_counts()
        with mock.patch("core.services.health.telemetry.collect", return_value=sh.h.snapshot(now=timezone.now())):
            text, code = self.run_command("probation_soak_probe", self.f.prob.bundle_id, "--json")
        document = json.loads(text)
        self.assertEqual((code, document["start_eligible"], document["sample"]["result"]), (0, True, "PASS"))
        self.assertEqual(set(document["sample"]["devices"]), {"R1", "R2"})
        self.assertEqual(bh.count_changes(before, bh.table_counts()), {}, "the probe starts nothing and persists nothing")
        plain, _ = self.run_command("probation_soak_probe", self.f.prob.bundle_id, "--no-live")
        self.assertIn("a soak CAN start now", plain)
        with self.assertRaises(Exception):
            call_command("probation_soak_probe", "BND-PROB-999999")
