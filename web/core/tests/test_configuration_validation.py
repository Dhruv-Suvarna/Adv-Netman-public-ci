"""Configuration Validation: the automatic GitHub Actions test of a validated Configuration Change candidate.

Dispatch after a passing Tier-2 run, the sanitized hash-bound bundle, tracking and refresh, staleness, the execution
gate, the candidate-specific CI checks, the workflow file and the page.  GitHub is a fake: no test reaches the network,
and nothing here contacts a device."""

from __future__ import annotations

import copy
import io
import json
import os
import tempfile
import uuid
from contextlib import redirect_stdout
from datetime import timedelta
from importlib import util as importlib_util
from pathlib import Path
from unittest import mock
from urllib.error import HTTPError

import yaml
from django.conf import settings
from django.test import SimpleTestCase, TestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from core import models
from core.services import execution_service as es
from core.services.configuration_validation import bundle as bundle_module
from core.services.configuration_validation import checks, github, service
from core.tests.helpers import execution as x
from core.tests.helpers.validation import clone_run, simple_pass_change, validate

S = models.ConfigurationValidationStatus
ROOT = Path(settings.REPO_ROOT)
ENABLED = override_settings(NMAS_CONFIGURATION_VALIDATION_ENABLED=True)
GATE = "CONFIGURATION_VALIDATION_NOT_PASSING"


class FakeGitHub:
    """Stands in for ``configuration_validation.github``: remembers every dispatch and answers run lookups from ``runs``."""

    NOT_CONFIGURED, GitHubError = github.NOT_CONFIGURED, github.GitHubError

    def __init__(self):
        self.dispatches, self.runs, self.foreign, self.fail_with, self.lookups = [], {}, [], None, 0

    def is_configured(self):
        return True

    def repository(self):
        return "example/nmas"

    def dispatch(self, event_type, payload):
        if self.fail_with is not None:
            raise self.fail_with
        self.dispatches.append((event_type, copy.deepcopy(payload)))

    is_validation_run = staticmethod(github.is_validation_run)

    def dispatch_runs(self):
        self.lookups += 1
        if self.fail_with is not None:
            raise self.fail_with
        return [run for run in [*self.runs.values(), *self.foreign] if github.is_validation_run(run)]

    def find_runs(self, correlation_id, runs=None):
        found = self.dispatch_runs() if runs is None else runs
        return [run for run in found if str(correlation_id) in str(run.get("display_title") or "")]

    def get_run(self, run_id):
        self.lookups += 1
        if self.fail_with is not None:
            raise self.fail_with
        return next(run for run in [*self.runs.values(), *self.foreign] if run["id"] == run_id)

    def failed_steps(self, run_id):
        return ["Configuration Validation: Validate the Configuration Change candidate"]

    def run(self, row, conclusion="success", status="completed", run_id=4242, **overrides):
        return {"id": run_id, "status": status, "conclusion": conclusion if status == "completed" else None,
                "html_url": f"https://github.com/example/nmas/actions/runs/{run_id}", "head_sha": "c" * 40, "event": "repository_dispatch",
                "path": github.WORKFLOW_PATH, "updated_at": "2026-10-13T04:30:00Z",
                "display_title": f"NMAS Configuration Validation | {row.change.change_id} | {row.correlation_id}", **overrides}

    def finish(self, row, conclusion="success", status="completed", run_id=4242):
        self.runs[str(row.correlation_id)] = self.run(row, conclusion, status, run_id)


class Base(TestCase):
    def setUp(self):
        self.gh = FakeGitHub()
        patch = mock.patch.object(service, "github", self.gh)
        patch.start()
        self.addCleanup(patch.stop)

    def bundle(self, row_or_index=-1):
        _event, payload = self.gh.dispatches[row_or_index]
        return bundle_module.decode(payload), payload


@ENABLED
class DispatchTests(Base):
    def test_a_passing_tier2_validation_dispatches_exactly_that_snapshot(self):
        f = simple_pass_change()
        run = validate(f.change, f.sources)
        row = service.latest(f.change)
        self.assertEqual((row.status, row.validation_run_id, row.snapshot_hash, row.demonstration), (S.QUEUED, run.pk, run.input_hash, False))
        self.assertIsNotNone(row.triggered_at)
        (event, payload), = self.gh.dispatches
        self.assertEqual(event, "nmas_configuration_validation")
        self.assertEqual(set(payload), {"correlation_id", "change_id", "snapshot_hash", "candidate_hash", "bundle_sha256", "bundle"})
        self.assertEqual((payload["change_id"], payload["correlation_id"], payload["snapshot_hash"]), (f.change.change_id, str(row.correlation_id), run.input_hash))
        self.assertEqual(uuid.UUID(payload["correlation_id"]).version, 4)
        bundle = bundle_module.decode(payload)
        self.assertEqual((bundle["validation"]["run_id"], bundle["validation"]["repository_sha"], bundle["validation"]["status"]), (str(run.run_id), "test-head", run.status))
        self.assertEqual(([d["device"] for d in bundle["devices"]], {d["platform"] for d in bundle["devices"]}), (["R1", "R2"], {"arista_ceos"}))
        self.assertEqual(bundle["devices"][0]["features"], ["interface.ROUTED_PHYSICAL"])
        self.assertIn("192.0.2.0/31", bundle["devices"][0]["candidate"])
        self.assertEqual((row.candidate_hash, row.bundle_sha256), (bundle["candidate_hash"], payload["bundle_sha256"]))
        self.assertEqual(bundle["matrix"][0], {"platform": "arista_ceos", "feature": "interface.ROUTED_PHYSICAL", "status": "SUPPORTED"})
        self.assertTrue(models.AuditEvent.objects.filter(object_type="ConfigurationValidationRun", object_id=str(row.correlation_id)).exists())

    def test_a_validation_that_does_not_pass_dispatches_nothing(self):
        f = simple_pass_change()
        run = validate(f.change, f.sources)
        self.gh.dispatches.clear()
        failed = clone_run(run, status="BLOCKED")
        self.assertIsNone(service.on_validation(failed, actor="tester"))
        self.assertEqual((self.gh.dispatches, f.change.configuration_validation_runs.count()), ([], 1))

    def test_every_correlation_id_is_new_and_a_newer_dispatch_makes_the_older_result_stale(self):
        f = simple_pass_change()
        validate(f.change, f.sources)
        first = service.latest(f.change)
        self.gh.finish(first)
        self.assertEqual(service.refresh(first).status, S.PASS)
        f.r1.set(f"interfaces.{f.a['id']}.description", "edited after the pass")
        self.assertEqual(service.effective_status(first), S.STALE)             # before anyone validates again
        validate(f.change, f.sources)
        second = service.latest(f.change)
        first.refresh_from_db()
        self.assertNotEqual(first.correlation_id, second.correlation_id)
        self.assertNotEqual(first.candidate_hash, second.candidate_hash)
        self.assertEqual((first.status, second.status, len(self.gh.dispatches)), (S.STALE, S.QUEUED, 2))

    def test_a_github_failure_is_recorded_and_never_breaks_the_validation(self):
        f = simple_pass_change()
        self.gh.fail_with = github.GitHubError(github.REFUSED, "HTTP 403")
        run = validate(f.change, f.sources)
        row = service.latest(f.change)
        self.assertEqual((run.status, row.status, row.failure_summary), ("PASS", S.ERROR, "GITHUB_REFUSED: HTTP 403"))
        self.gh.fail_with = github.GitHubError(github.NOT_CONFIGURED, "no GitHub token is provisioned for this NMAS instance")
        validate(f.change, f.sources)
        self.assertEqual(service.latest(f.change).status, S.NOT_TRIGGERED)

    def test_a_bundle_that_does_not_fit_is_refused_whole_never_truncated(self):
        f = simple_pass_change()
        with mock.patch.object(bundle_module, "MAX_ENCODED_BYTES", 200):
            validate(f.change, f.sources)
        row = service.latest(f.change)
        self.assertEqual((row.status, self.gh.dispatches), (S.ERROR, []))
        self.assertTrue(row.failure_summary.startswith("CONFIG_VALIDATION_BUNDLE_TOO_LARGE"))

    def test_secrets_never_leave_nmas(self):
        f = simple_pass_change()
        rendered = {"text": "hostname R1\nusername admin privilege 15 secret 0 hunter2-not-for-github\nsnmp-server community s3cr3tcommunity ro\n"
                            "interface Ethernet1\n   ip address 192.0.2.0/31\n", "composition_conflicts": []}
        with mock.patch.object(service.candidate_renderer, "render", return_value=rendered):
            validate(f.change, f.sources)
        text = json.dumps(self.bundle()[0])
        self.assertNotIn("hunter2-not-for-github", text)
        self.assertNotIn("s3cr3tcommunity", text)
        self.assertIn("<REDACTED>", text)
        self.assertIn("192.0.2.0/31", text)
        self.gh.dispatches.clear()
        token = {"text": "hostname R1\ndescription ghp_" + "a" * 36 + "\n", "composition_conflicts": []}      # a credential FORMAT the sanitizer left
        with mock.patch.object(service.candidate_renderer, "render", return_value=token), mock.patch.object(service, "sanitize_config", lambda raw: mock.Mock(text=raw)):
            validate(f.change, f.sources)
        row = service.latest(f.change)
        self.assertEqual((row.status, self.gh.dispatches), (S.ERROR, []))
        self.assertTrue(row.failure_summary.startswith("CONFIG_VALIDATION_BUNDLE_NOT_SANITIZED"))
        self.assertNotIn("ghp_", row.failure_summary)

    def test_a_routing_transition_is_the_one_exemption(self):
        f = simple_pass_change()
        f.change.metadata = {"transition": {"kind": "BASELINE_STATIC_IPV6_TO_ISIS"}}
        f.change.save(update_fields=["metadata"])
        validate(f.change, f.sources)
        self.assertEqual((self.gh.dispatches, service.gate(f.change)), ([], None))
        self.assertIn("routing transition", service.exempt(f.change))
        self.assertEqual(service.exempt(simple_pass_change().change), "")


class DisabledTests(Base):
    def test_the_automated_test_environment_dispatches_nothing_and_gates_nothing(self):
        f = simple_pass_change()
        validate(f.change, f.sources)
        self.assertEqual((self.gh.dispatches, f.change.configuration_validation_runs.count(), service.gate(f.change)), ([], 0, None))


@ENABLED
class RefreshTests(Base):
    def setUp(self):
        super().setUp()
        self.f = simple_pass_change()
        validate(self.f.change, self.f.sources)
        self.row = service.latest(self.f.change)

    def test_the_run_is_found_by_its_correlation_id_and_followed_to_its_result(self):
        self.assertEqual((service.refresh(self.row).status, self.row.github_run_id), (S.QUEUED, None))       # GitHub has not started it yet
        self.gh.finish(self.row, status="in_progress")
        row = service.refresh(self.row)
        self.assertEqual((row.status, row.github_run_id, row.run_url, row.tested_sha, row.completed_at),
                         (S.IN_PROGRESS, 4242, "https://github.com/example/nmas/actions/runs/4242", "c" * 40, None))
        self.gh.finish(self.row)
        row = service.refresh(row)
        self.assertEqual(row.status, S.PASS)
        self.assertIsNotNone(row.completed_at)
        lookups = self.gh.lookups
        service.refresh(row)                                                   # a finished run is never asked about again
        self.assertEqual(self.gh.lookups, lookups)

    def test_a_failed_run_keeps_a_concise_reason_and_other_endings_are_errors(self):
        self.gh.finish(self.row, conclusion="failure")
        row = service.refresh(self.row)
        self.assertEqual((row.status, row.failure_summary), (S.FAIL, "Failed: Configuration Validation: Validate the Configuration Change candidate"))
        other = simple_pass_change()
        validate(other.change, other.sources)
        row = service.latest(other.change)
        self.gh.finish(row, conclusion="cancelled", run_id=4343)
        self.assertEqual(service.refresh(row).status, S.ERROR)

    def test_an_api_outage_changes_no_status_and_a_run_that_never_appears_becomes_an_error(self):
        self.gh.fail_with = github.GitHubError(github.UNREACHABLE)
        row = service.refresh(self.row)
        self.assertEqual((row.status, row.failure_summary), (S.QUEUED, "Status not refreshed: GITHUB_UNREACHABLE"))
        self.gh.fail_with = None
        row = service.refresh(row, now=timezone.now() + timedelta(minutes=16))
        self.assertEqual(row.status, S.ERROR)
        self.assertIn("CONFIG_VALIDATION_RUN_NOT_FOUND", row.failure_summary)


@ENABLED
class GateTests(Base):
    def codes(self, p, **kwargs):
        return {b["code"] for b in es.check_execution_eligibility(p.change, confirm_mode="COMPLETE", sources=p.sources, **kwargs).blockers}

    def test_only_a_pass_for_the_current_candidate_permits_execution(self):
        p = x.prepared()
        row = service.latest(p.change)
        gate = es.check_execution_eligibility(p.change, confirm_mode="COMPLETE", sources=p.sources)
        self.assertEqual([b["code"] for b in gate.blockers], [GATE])                                # every other gate holds: this is the only refusal
        self.assertIn("QUEUED", gate.blockers[0]["message"])
        self.gh.finish(row, status="in_progress")
        self.assertIn("IN_PROGRESS", es.check_execution_eligibility(p.change, confirm_mode="COMPLETE", sources=p.sources).blockers[0]["message"])
        self.gh.finish(row)
        self.assertEqual(self.codes(p), set())
        self.assertTrue(es.check_execution_eligibility(p.change, confirm_mode="COMPLETE", sources=p.sources).eligible)

    def test_fail_error_not_triggered_and_missing_all_refuse(self):
        for conclusion, word in (("failure", "FAIL"), ("timed_out", "ERROR")):
            with self.subTest(conclusion=conclusion):
                p = x.prepared()
                self.gh.finish(service.latest(p.change), conclusion=conclusion, run_id=5000 + len(conclusion))
                gate = es.check_execution_eligibility(p.change, confirm_mode="COMPLETE", sources=p.sources)
                self.assertEqual([b["code"] for b in gate.blockers], [GATE])
                self.assertIn(f"is {word}", gate.blockers[0]["message"])
        self.gh.fail_with = github.GitHubError(github.NOT_CONFIGURED, "no token")
        p = x.prepared()
        self.assertIn("NOT_TRIGGERED", es.check_execution_eligibility(p.change, confirm_mode="COMPLETE", sources=p.sources).blockers[0]["message"])
        p.change.configuration_validation_runs.all().delete()
        self.assertIn(GATE, self.codes(p))

    def test_a_pass_for_an_older_candidate_never_authorizes_a_newer_one(self):
        p = x.prepared()
        old = service.latest(p.change)
        self.gh.finish(old)
        self.assertEqual(self.codes(p), set())
        p.f.r1.set(f"interfaces.{p.f.a['id']}.description", "edited after the pass")
        gate = es.check_execution_eligibility(p.change, confirm_mode="COMPLETE", sources=p.sources)
        self.assertIn(GATE, {b["code"] for b in gate.blockers})
        self.assertIn("STALE", next(b["message"] for b in gate.blockers if b["code"] == GATE))
        validate(p.change, p.sources)                                                               # a new snapshot, a new run, still not PASS
        new = service.latest(p.change)
        self.assertNotEqual(new.pk, old.pk)
        self.assertIn("QUEUED", service.gate(p.change)["reason"].upper())
        self.gh.finish(new, run_id=4300)
        self.assertIsNone(service.gate(p.change))
        old.refresh_from_db()
        self.assertEqual(old.status, S.STALE)

    def test_a_demonstration_run_never_counts(self):
        p = x.prepared()
        real = service.latest(p.change)
        demo = service.dispatch(real.validation_run, actor="tester", demonstration=True)
        self.gh.finish(demo, run_id=4400)                                                           # even a "success" of a demonstration bundle
        self.assertEqual(service.refresh(demo).status, S.PASS)
        self.assertIn(GATE, self.codes(p))
        real.refresh_from_db()
        self.assertEqual((real.status, demo.demonstration), (S.QUEUED, True))                       # and it did not make the real one stale


@ENABLED
class ReconciliationTests(Base):
    """NMAS reads the result back from GitHub (outbound only).  The live defect: a run that finished on GitHub stayed
    QUEUED in NMAS because nothing an operator opened asked GitHub about it."""

    def setUp(self):
        super().setUp()
        self.f = simple_pass_change()
        validate(self.f.change, self.f.sources)
        self.row = service.latest(self.f.change)
        self.hashes = (self.row.snapshot_hash, self.row.candidate_hash, self.row.bundle_sha256)

    def reload(self, row=None):
        return models.ConfigurationValidationRun.objects.get(pk=(row or self.row).pk)

    def test_a_queued_run_that_succeeded_on_github_becomes_pass_with_its_evidence(self):
        self.gh.finish(self.row)
        service.reconcile(self.f.change)
        row = self.reload()
        self.assertEqual((row.status, row.github_run_id, row.run_url, row.tested_sha), (S.PASS, 4242, "https://github.com/example/nmas/actions/runs/4242", "c" * 40))
        self.assertEqual(row.completed_at.isoformat(), "2026-10-13T04:30:00+00:00")            # GitHub's own completion time
        self.assertEqual((row.snapshot_hash, row.candidate_hash, row.bundle_sha256), self.hashes)
        self.assertEqual(models.ConfigurationValidationRun.objects.count(), 1)                 # the same row, never a replacement
        self.assertEqual(self.gh.dispatches.__len__(), 1)                                      # and nothing was dispatched again

    def test_a_run_that_finished_long_ago_is_still_reconciled_after_a_restart(self):
        self.gh.finish(self.row)
        fresh = self.reload()                                                                  # nothing but the stored row
        self.assertEqual(service.refresh(fresh, now=timezone.now() + timedelta(days=3)).status, S.PASS)

    def test_failure_and_every_other_ending_never_become_pass(self):
        self.gh.finish(self.row, conclusion="failure")
        service.reconcile(self.f.change)
        self.assertEqual((self.reload().status, self.reload().failure_summary), (S.FAIL, "Failed: Configuration Validation: Validate the Configuration Change candidate"))
        for conclusion in ("cancelled", "timed_out", "action_required", "skipped", "neutral", "stale", "something_new", ""):
            with self.subTest(conclusion=conclusion):
                other = simple_pass_change()
                validate(other.change, other.sources)
                row = service.latest(other.change)
                self.gh.finish(row, conclusion=conclusion, run_id=9000 + len(conclusion))
                self.assertEqual(service.refresh(row).status, S.ERROR)
                self.assertIsNotNone(service.gate(other.change))

    def test_a_run_that_has_not_finished_stays_non_terminal(self):
        for status, expected in (("queued", S.QUEUED), ("in_progress", S.IN_PROGRESS), ("waiting", S.QUEUED), ("requested", S.QUEUED), ("pending", S.QUEUED)):
            self.gh.finish(self.row, status=status)
            row = service.refresh(self.reload())
            self.assertEqual((row.status, row.completed_at, row.github_run_id), (expected, None, 4242), status)
        self.assertEqual(service.gate(self.f.change)["status"], S.QUEUED)

    def test_a_run_of_another_correlation_change_workflow_trigger_or_repository_is_never_taken(self):
        other = simple_pass_change()
        validate(other.change, other.sources)
        stranger = service.latest(other.change)
        title = f"NMAS Configuration Validation | {self.row.change.change_id} | {self.row.correlation_id}"
        self.gh.foreign = [
            self.gh.run(stranger, run_id=1),                                                                       # another correlation
            self.gh.run(self.row, run_id=2, display_title=f"NMAS Configuration Validation | {other.change.change_id} | {self.row.correlation_id}"),   # another Change
            self.gh.run(self.row, run_id=3, path=".github/workflows/tier3-validation.yml"),                        # another workflow, same name
            self.gh.run(self.row, run_id=4, event="workflow_dispatch"),                                            # not dispatched by NMAS
            self.gh.run(self.row, run_id=5, repository={"full_name": "someone/else"}),                             # another repository
            {"id": 6, "status": "completed", "conclusion": "success", "display_title": title, "event": "push", "path": ".github/workflows/x.yml"},
        ]
        service.reconcile(self.f.change)
        row = self.reload()
        self.assertEqual((row.status, row.github_run_id), (S.QUEUED, None))
        self.assertIsNotNone(service.gate(self.f.change))
        self.gh.finish(self.row, run_id=7)                                                     # its own run, among all of those
        service.reconcile(self.f.change)
        self.assertEqual((self.reload().status, self.reload().github_run_id), (S.PASS, 7))

    def test_two_runs_with_the_same_identity_fail_closed(self):
        self.gh.finish(self.row, run_id=7)
        self.gh.foreign = [self.gh.run(self.row, run_id=8)]
        service.reconcile(self.f.change)
        row = self.reload()
        self.assertEqual((row.status, row.github_run_id), (S.ERROR, None))
        self.assertTrue(row.failure_summary.startswith(service.AMBIGUOUS))
        self.assertEqual(service.gate(self.f.change)["status"], S.ERROR)

    def test_a_known_run_id_is_never_swapped_for_another_run(self):
        self.gh.finish(self.row, status="in_progress", run_id=7)
        service.reconcile(self.f.change)
        self.gh.runs.clear()
        self.gh.foreign = [self.gh.run(self.row, run_id=8), self.gh.run(self.row, status="in_progress", run_id=7)]      # a second, "successful" run appears
        service.reconcile(self.f.change)
        self.assertEqual((self.reload().status, self.reload().github_run_id), (S.IN_PROGRESS, 7))

    def test_a_superseded_run_records_its_result_and_stays_stale(self):
        self.f.r1.set(f"interfaces.{self.f.a['id']}.description", "edited before the result was read")
        validate(self.f.change, self.f.sources)                                               # the first row is now STALE, result unread
        new = service.latest(self.f.change)
        self.gh.finish(self.row, run_id=7)                                                    # GitHub passed the OLD candidate
        service.reconcile(self.f.change)
        old = self.reload()
        self.assertEqual((old.status, old.github_run_id, service.effective_status(old)), (S.STALE, 7, S.STALE))
        self.assertEqual(old.failure_summary, "Superseded before its result was read. GitHub result: PASS.")
        self.assertIsNotNone(old.completed_at)
        self.assertEqual((old.snapshot_hash, old.candidate_hash), self.hashes[:2])
        self.assertEqual((service.gate(self.f.change)["status"], self.reload(new).status), (S.QUEUED, S.QUEUED))     # the old PASS authorizes nothing
        lookups = self.gh.lookups
        service.reconcile(self.f.change)                                                      # recorded once, not asked about again
        self.assertEqual(self.reload().failure_summary, old.failure_summary)
        self.gh.finish(new, run_id=8)
        service.reconcile(self.f.change)
        self.assertEqual((self.reload(new).status, service.gate(self.f.change)), (S.PASS, None))
        self.assertGreater(self.gh.lookups, lookups)

    def test_a_github_outage_leaves_the_run_non_authorizing(self):
        self.gh.finish(self.row)
        self.gh.fail_with = github.GitHubError(github.REFUSED, "HTTP 403")
        service.reconcile(self.f.change)
        row = self.reload()
        self.assertEqual((row.status, row.failure_summary), (S.QUEUED, "Status not refreshed: GITHUB_REFUSED: HTTP 403"))
        self.assertEqual(service.gate(self.f.change)["status"], S.QUEUED)
        self.gh.fail_with = None
        service.reconcile(self.f.change)
        self.assertEqual((self.reload().status, self.reload().failure_summary), (S.PASS, ""))

    def test_the_execution_gate_reconciles_before_it_judges(self):
        p = x.prepared()
        row = service.latest(p.change)
        self.gh.finish(row, run_id=4500)
        self.assertEqual(self.reload(row).status, S.QUEUED)                                   # nobody opened a page
        gate = es.check_execution_eligibility(p.change, confirm_mode="COMPLETE", sources=p.sources)
        self.assertTrue(gate.eligible, gate.blockers)
        self.assertEqual((self.reload(row).status, self.reload(row).github_run_id), (S.PASS, 4500))

    def test_the_change_page_the_evidence_page_and_the_refresh_action_all_reconcile(self):
        detail = reverse("core:device_builder_change_detail", args=[self.f.change.change_id])
        evidence = reverse("core:change_configuration_validation", args=[self.f.change.change_id])
        refresh = reverse("core:change_configuration_validation_refresh", args=[self.f.change.change_id])
        page = self.client.get(detail)
        for wanted in ("Configuration Validation", "separate from Tier-2 Change Validation", "QUEUED", str(self.row.correlation_id), "Refresh from GitHub", evidence):
            self.assertContains(page, wanted)
        self.assertEqual(self.client.get(refresh).status_code, 405)                           # reading GitHub on demand is an explicit POST
        self.gh.finish(self.row, conclusion="failure")
        self.assertRedirects(self.client.post(refresh, {"status": "PASS", "candidate_hash": "0" * 64}), evidence, fetch_redirect_response=False)
        row = self.reload()
        self.assertEqual((row.status, row.candidate_hash), (S.FAIL, self.hashes[1]))          # no posted field is believed
        page = self.client.get(evidence)
        for wanted in ('badge--danger">FAIL', "#4242", "https://github.com/example/nmas/actions/runs/4242", "c" * 12, row.candidate_hash[:12],
                       "Failed: Configuration Validation: Validate the Configuration Change candidate", str(row.validation_run.run_id)[:8]):
            self.assertContains(page, wanted)
        other = simple_pass_change()
        validate(other.change, other.sources)
        self.gh.finish(service.latest(other.change), run_id=4600)
        self.assertContains(self.client.get(reverse("core:device_builder_change_detail", args=[other.change.change_id])), 'badge--success">PASS')

    def test_the_reconcile_command_recovers_every_run_that_owes_a_result(self):
        from django.core.management import call_command

        self.gh.finish(self.row)
        out = io.StringIO()
        call_command("nmas_configuration_validation", "reconcile", stdout=out)
        self.assertEqual(self.reload().status, S.PASS)
        self.assertIn(str(self.row.correlation_id), out.getvalue())
        out = io.StringIO()
        call_command("nmas_configuration_validation", "reconcile", stdout=out)                # nothing owes a result any more
        self.assertEqual(out.getvalue(), "")


def rehash(bundle: dict) -> dict:
    """Re-seal a bundle after a test edited it (as NMAS would have, had the edit been real intent)."""
    from core.services.validation import snapshot as snapshot_module

    for device in bundle["devices"]:
        device["candidate_sha256"] = bundle_module.digest(device["candidate"])
    bundle["snapshot_hash"] = bundle["validation"]["input_hash"] = snapshot_module.hash_snapshot(bundle["intent"])
    bundle["candidate_hash"] = bundle_module.candidate_hash(bundle["devices"], bundle["removals"])
    return bundle


@ENABLED
class ValidatorTests(Base):
    """The checks the workflow runs, on a bundle NMAS really produced."""

    def setUp(self):
        super().setUp()
        self.f = simple_pass_change()
        self.f.r1.static_route("10.9.0.0/24", next_hop="192.0.2.1")
        validate(self.f.change, self.f.sources)
        self.good, self.payload = self.bundle()

    def results(self, bundle, payload=None):
        return {c.key: c for c in checks.run_static(bundle, repo_root=ROOT, payload=payload)}

    def failed(self, bundle):
        return {key: [check["name"] for check in category.checks if check["status"] == checks.FAIL] for key, category in self.results(bundle).items()
                if category.status == checks.FAIL}

    def test_the_real_candidate_passes_every_category(self):
        found = self.results(self.good, self.payload)
        self.assertEqual({key: c.status for key, c in found.items()}, {key: checks.PASS for key in "ABCDE"}, [c.as_dict() for c in found.values()])
        self.assertIn("R1: routing.STATIC_IPV4 on arista_ceos", [check["name"] for check in found["C"].checks])

    def test_integrity_binds_the_snapshot_the_candidate_and_the_envelope(self):
        bundle = copy.deepcopy(self.good)
        bundle["devices"][0]["candidate"] += "ip route 0.0.0.0/0 192.0.2.99\n"
        self.assertEqual(list(self.failed(bundle)), ["A"])                                           # nothing else is examined
        bundle = copy.deepcopy(self.good)
        bundle["intent"]["devices"][0]["identity"]["description"] = "changed after hashing"
        self.assertIn("snapshot hash matches the intent", self.failed(bundle)["A"])
        self.assertIn("dispatch envelope names this bundle", [c["name"] for c in self.results(self.good, {**self.payload, "candidate_hash": "0" * 64})["A"].checks
                                                              if c["status"] == checks.FAIL])
        bundle = copy.deepcopy(self.good)
        bundle["validation"]["status"] = "BLOCKED"
        self.assertIn("Tier-2 validation passed for this snapshot", self.failed(bundle)["A"])
        bundle = copy.deepcopy(self.good)
        bundle["schema_version"] = 99
        self.assertEqual(self.failed(bundle), {"A": ["schema and required fields"]})
        with self.assertRaises(bundle_module.BundleError):
            bundle_module.decode({**self.payload, "bundle_sha256": "0" * 64})

    def test_an_unsupported_feature_fails_closed(self):
        bundle = copy.deepcopy(self.good)
        interface = next(iter(bundle["intent"]["devices"][0]["interfaces"].values()))
        interface["kind"] = "LAG"                                                                    # the platform has it, the project does not
        bundle["devices"][0]["features"] = bundle_module.features_of(bundle["intent"]["devices"][0])
        self.assertEqual(self.failed(rehash(bundle))["C"], ["R1: interface.LAG on arista_ceos"])
        bundle = copy.deepcopy(self.good)
        next(iter(bundle["intent"]["devices"][0]["interfaces"].values()))["kind"] = "HOLOGRAM"       # not in any matrix: unknown is not supported
        bundle["devices"][0]["features"] = bundle_module.features_of(bundle["intent"]["devices"][0])
        self.assertIn("R1: interface.HOLOGRAM on arista_ceos", self.failed(rehash(bundle))["C"])
        bundle = copy.deepcopy(self.good)
        bundle["devices"][0]["features"] = []                                                        # a bundle cannot under-declare what its intent asks for
        self.assertIn("R1: requested features are the ones in the intent", self.failed(rehash(bundle))["C"])
        self.assertEqual((checks.matrix_status("ubuntu_frr", "routing.ISIS"), checks.matrix_status("arista_ceos", "routing.EIGRP_IPV4")), ("NOT_IMPLEMENTED", "UNSUPPORTED"))

    def production_shaped_r1(self):
        """A bundle whose R1 intent holds what the live R1 imports to: RIP, OSPFv2, OSPFv3, IS-IS, both static families."""
        bundle = copy.deepcopy(self.good)
        device = bundle["intent"]["devices"][0]
        device["routing"] = {
            "static_routes": {"route-1": {"family": "IPV4"}, "route-2": {"family": "IPV6"}},
            "rip": {"rip-1": {"id": "rip-1", "address_family": "IPV4", "enabled": True}},
            "ospf": {"ospf-1": {"id": "ospf-1", "version": "OSPFV2"}, "ospf-2": {"id": "ospf-2", "version": "OSPFV3"}},
            "isis": {"isis-1": {"id": "isis-1", "net": "49.0110.1921.6825.5001.00", "address_family_ipv6": True}},
            "eigrp": {}, "bgp": {},
        }
        bundle["devices"][0]["features"] = bundle_module.features_of(device)
        return rehash(bundle)

    def test_a_rip_instance_is_ripv2_or_ripng_not_an_address_family(self):
        # Live failure of CHG-20261013-0001: the RIP instance of R1 (address_family IPV4) was named "routing.IPV4", which no
        # capability matrix contains, and the candidate failed platform support although every protocol on R1 is implemented.
        bundle = self.production_shaped_r1()
        self.assertEqual(bundle["devices"][0]["features"], ["interface.ROUTED_PHYSICAL", "routing.ISIS", "routing.OSPFV2", "routing.OSPFV3", "routing.RIPV2",
                                                           "routing.STATIC_IPV4", "routing.STATIC_IPV6"])
        self.assertEqual(self.failed(bundle), {})
        checked = {check["name"]: check["detail"] for check in self.results(bundle)["C"].checks}
        for leaf in ("RIPV2", "ISIS", "OSPFV2", "OSPFV3", "STATIC_IPV4", "STATIC_IPV6"):             # every leaf is still looked up, none is skipped
            self.assertEqual(checked[f"R1: routing.{leaf} on arista_ceos"], "SUPPORTED")
        self.assertFalse([name for name in checked if "routing.IPV4" in name or "routing.IPV6" in name])

    def test_every_routing_family_maps_to_the_leaf_the_intent_model_uses(self):
        from core.services import routing_intent_service

        for family, fields in (("rip", {"address_family": "IPV4"}), ("rip", {"address_family": "IPV6"}), ("ospf", {"version": "OSPFV2"}), ("ospf", {"version": "OSPFV3"}),
                               ("isis", {}), ("eigrp", {"address_family": "IPV4"}), ("eigrp", {"address_family": "IPV6"})):
            self.assertEqual(bundle_module.routing_leaves(family, fields), {routing_intent_service._routing_protocol_for(family, fields).value}, (family, fields))
        bgp = {"neighbors": {"n1": {"family": "IPV4"}, "n2": {"family": "IPV6"}}, "networks": {"w1": {"family": "IPV4"}}}
        self.assertEqual(bundle_module.routing_leaves("bgp", bgp), {routing_intent_service._bgp_protocol("IPV4").value, routing_intent_service._bgp_protocol("IPV6").value})
        self.assertEqual(bundle_module.routing_leaves("bgp", {"neighbors": {}, "networks": {}}), set())
        from core.services import platform_drivers

        known = {protocol.value for protocol in platform_drivers.RoutingProtocol}
        self.assertTrue(set(bundle_module._LEAVES.values()) | set(bundle_module._BGP_LEAVES.values()) | {"ISIS"} <= known)

    def test_real_leaves_that_are_not_implemented_still_fail_and_unknown_ones_fail_closed(self):
        bundle = self.production_shaped_r1()
        bundle["intent"]["devices"][0]["routing"]["rip"]["rip-1"]["address_family"] = "IPV6"         # RIPng: the platform has it, the project does not
        bundle["devices"][0]["features"] = bundle_module.features_of(bundle["intent"]["devices"][0])
        self.assertEqual(self.failed(rehash(bundle))["C"], ["R1: routing.RIPNG on arista_ceos"])
        bundle = self.production_shaped_r1()
        bundle["intent"]["devices"][0]["routing"]["eigrp"] = {"eigrp-1": {"id": "eigrp-1", "address_family": "IPV4"}}     # unsupported on cEOS
        bundle["devices"][0]["features"] = bundle_module.features_of(bundle["intent"]["devices"][0])
        self.assertEqual(self.failed(rehash(bundle))["C"], ["R1: routing.EIGRP_IPV4 on arista_ceos"])
        for family, instance, name in (("rip", {"address_family": "IPX"}, "routing.RIP:IPX"), ("ospf", {}, "routing.OSPF:None"),
                                       ("babel", {"id": "b1"}, "routing.BABEL:None"), ("bgp", {"neighbors": {"n": {"family": "L2VPN"}}}, "routing.BGP:L2VPN")):
            bundle = self.production_shaped_r1()
            bundle["intent"]["devices"][0]["routing"][family] = {"x-1": instance}
            bundle["devices"][0]["features"] = bundle_module.features_of(bundle["intent"]["devices"][0])
            self.assertIn(f"R1: {name} on arista_ceos", self.failed(rehash(bundle))["C"], name)       # never skipped, never assumed supported
        bundle = self.production_shaped_r1()
        bundle["devices"][0]["platform"] = bundle["intent"]["devices"][0]["platform"] = "ubuntu_frr"
        self.assertIn("R1: routing.ISIS on ubuntu_frr", self.failed(rehash(bundle))["C"])            # IS-IS support is still judged per platform

    def test_the_protected_vlan_the_managed_scope_and_the_authority_boundaries_are_enforced(self):
        bundle = copy.deepcopy(self.good)
        bundle["devices"][0]["candidate"] += "no interface Vlan200\n"
        self.assertEqual(self.failed(rehash(bundle))["D"], ["protected VLAN 200 is not changed"])
        bundle = copy.deepcopy(self.good)
        bundle["devices"][0]["candidate"] += "interface Vlan200\n   ip address dhcp\n"
        self.assertIn("protected VLAN 200 is not changed", self.failed(rehash(bundle))["D"])
        for name in ("R5", "X9"):                                                                    # in the inventory but out of scope / unknown
            bundle = copy.deepcopy(self.good)
            bundle["devices"][0]["device"] = bundle["intent"]["devices"][0]["device_name"] = name
            self.assertIn("every target is inside the managed scope", self.failed(rehash(bundle))["D"], name)
        bundle = copy.deepcopy(self.good)
        bundle["intent"]["devices"][0]["target_type"] = "NEW_DEVICE"                                 # not a provisioning Change
        self.assertIn("authority boundaries hold", self.failed(rehash(bundle))["D"])
        bundle = copy.deepcopy(self.good)
        bundle["dependencies"] = {"nodes": [{"id": "a"}], "edges": [{"from": "a", "to": "missing", "type": "X", "status": "OK"}], "cycles": [], "truncated": False}
        self.assertIn("dependency graph is internally consistent", self.failed(bundle)["D"])

    def test_rendering_and_syntax_defects_are_found_without_a_device(self):
        bundle = copy.deepcopy(self.good)
        bundle["devices"][0]["candidate"] += "interface Ethernet1\n   description twice\n"
        self.assertEqual(self.failed(rehash(bundle))["B"], ["R1: interface blocks are consolidated"])
        bundle = copy.deepcopy(self.good)
        bundle["devices"][0]["candidate"] = "interface Ethernet9\n   description one\n   description two\n   ip address 192.0.2.300/31\nvlan 5000\n"
        failed = self.failed(rehash(bundle))
        self.assertEqual((failed["B"], failed["E"]), (["R1: no conflicting stanza"], ["R1: statements are well formed"]))
        bundle = copy.deepcopy(self.good)
        bundle["devices"][0]["candidate"] += "router ospf <process-id-required>\n"
        self.assertIn("R1: no unrendered placeholder", self.failed(rehash(bundle))["B"])

    def test_a_removal_only_change_is_judged_on_its_removal_and_an_empty_change_fails(self):
        bundle = copy.deepcopy(self.good)
        bundle["devices"], bundle["intent"]["devices"], bundle["matrix"] = [], [], []
        bundle["removals"] = [{"device": "R1", "platform": "arista_ceos", "mode": "LINES", "status": "READY", "content_hash": "a" * 64, "features": []}]
        bundle["intent"]["config_removals"] = {"schema_version": 1, "items": [{"device": "R1", "platform": "arista_ceos"}]}
        self.assertEqual(self.failed(rehash(bundle)), {})
        bundle["removals"], bundle["intent"]["config_removals"] = [], {"schema_version": 1, "items": []}
        self.assertEqual(self.failed(rehash(bundle))["B"], ["the Change has a candidate"])

    def test_the_tests_selected_are_the_narrow_ones_for_this_candidate(self):
        labels = checks.select_tests(self.good, repo_root=ROOT)
        self.assertEqual(labels, [f"core.tests.test_{name}" for name in ("configuration_validation", "network_config_validation", "candidate_renderer", "parser_ceos",
                                                                         "interface_renderer", "candidate_composition", "routing_renderer", "phase13_routing")])
        frr = {"devices": [{"platform": "ubuntu_frr", "features": []}], "removals": [], "change": {"workflow": "REMOVE_CONFIGURATION", "category": "CONFIGURATION_CHANGE"}}
        self.assertEqual([label.rsplit("test_", 1)[1] for label in checks.select_tests(frr, repo_root=ROOT)],
                         ["configuration_validation", "network_config_validation", "parser_frr", "frr_routing_executor", "config_workbench"])
        self.assertLess(len(labels), 12)                                                             # never the whole suite

    def _script(self):
        spec = importlib_util.spec_from_file_location("validate_configuration_change", ROOT / "scripts" / "ci" / "validate_configuration_change.py")
        module = importlib_util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def test_the_ci_entry_point_passes_the_real_bundle_and_fails_the_demonstration_with_a_readable_summary(self):
        script = self._script()
        demo = service.dispatch(service.latest(self.f.change).validation_run, actor="tester", demonstration=True)
        self.assertEqual((demo.status, demo.demonstration), (S.QUEUED, True))
        with tempfile.TemporaryDirectory() as folder:
            for index, expected in ((0, 0), (-1, 1)):
                event, summary, report = (os.path.join(folder, f"{name}{index}") for name in ("event", "summary", "report"))
                Path(event).write_text(json.dumps({"action": "nmas_configuration_validation", "client_payload": self.gh.dispatches[index][1]}))
                with redirect_stdout(io.StringIO()):
                    self.assertEqual(script.main(["--event", event, "--summary-md", summary, "--json", report, "--skip-tests"]), expected)
                text, data = Path(summary).read_text(), json.loads(Path(report).read_text())
                self.assertIn(self.f.change.change_id, text)
                self.assertIn("**PASS**" if expected == 0 else "**FAIL**", text)
                self.assertEqual(data["overall"], "PASS" if expected == 0 else "FAIL")
                for wanted in ("Target device(s) | R1, R2", "arista_ceos", "interface.ROUTED_PHYSICAL", data["bundle"]["candidate_hash"], data["bundle"]["validation_run_id"]):
                    self.assertIn(wanted, text)
            self.assertEqual([c["status"] for c in data["categories"]], ["PASS", "PASS", "PASS", "FAIL", "PASS"])
            self.assertIn("no interface Vlan200", json.dumps(data))
            Path(event).write_text(json.dumps({"client_payload": {"change_id": "CHG-20261013-0001", "correlation_id": "x", "bundle": "not a bundle"}}))
            with redirect_stdout(io.StringIO()):
                self.assertEqual(script.main(["--event", event, "--skip-tests"]), 1)


class GitHubClientTests(SimpleTestCase):
    def call(self, function, *args, response=b"{}", error=None):
        seen = {}

        class Reply:
            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

            def read(self, _limit):
                return response

        def urlopen(request, timeout):
            seen.update(url=request.full_url, method=request.get_method(), headers=dict(request.header_items()), body=request.data, timeout=timeout)
            if error is not None:
                raise error
            return Reply()

        with mock.patch.object(github, "urlopen", urlopen), mock.patch.dict(os.environ, {"NMAS_GITHUB_TOKEN": "test-token-value"}), \
                override_settings(NMAS_GITHUB_REPOSITORY="example/nmas"):
            return function(*args), seen

    def test_dispatch_is_one_bounded_authenticated_post(self):
        _result, seen = self.call(github.dispatch, "nmas_configuration_validation", {"correlation_id": "abc"})
        self.assertEqual((seen["url"], seen["method"], seen["timeout"]), ("https://api.github.com/repos/example/nmas/dispatches", "POST", github.TIMEOUT_SECONDS))
        self.assertEqual(seen["headers"]["Authorization"], "Bearer test-token-value")
        self.assertEqual(json.loads(seen["body"]), {"event_type": "nmas_configuration_validation", "client_payload": {"correlation_id": "abc"}})

    def test_only_dispatched_runs_of_the_configuration_validation_workflow_are_candidates(self):
        ours = {"path": github.WORKFLOW_PATH, "event": "repository_dispatch"}
        runs = {"workflow_runs": [
            {"id": 1, "display_title": "NMAS Configuration Validation | CHG-20261013-0001 | other", **ours},
            {"id": 2, "display_title": "NMAS Configuration Validation | CHG-20261013-0002 | abc-123", **ours},
            {"id": 3, "display_title": "NMAS Configuration Validation | CHG-20261013-0002 | abc-123", "path": ".github/workflows/tier3-validation.yml", "event": "repository_dispatch"},
            {"id": 4, "display_title": "NMAS Configuration Validation | CHG-20261013-0002 | abc-123", "path": github.WORKFLOW_PATH, "event": "workflow_dispatch"},
            {"id": 5, "display_title": "NMAS Configuration Validation | CHG-20261013-0002 | abc-123", **ours, "repository": {"full_name": "someone/else"}},
            {"id": 6, "display_title": "NMAS Configuration Validation | CHG-20261013-0002 | abc-123", **ours, "repository": {"full_name": "Example/NMAS"}}]}
        found, seen = self.call(github.find_runs, "abc-123", response=json.dumps(runs).encode())
        self.assertEqual(([run["id"] for run in found], seen["method"]), ([2, 6], "GET"))
        self.assertIn("event=repository_dispatch", seen["url"])
        self.assertEqual(self.call(github.find_runs, "nothing", response=json.dumps(runs).encode())[0], [])

    def test_failures_are_fixed_codes_that_never_carry_the_token_or_a_response_body(self):
        with self.assertRaises(github.GitHubError) as caught:
            self.call(github.dispatch, "e", {}, error=HTTPError("u", 403, "Forbidden: test-token-value", {}, io.BytesIO(b"secret body")))
        self.assertEqual((caught.exception.code, str(caught.exception)), (github.REFUSED, "GITHUB_REFUSED: HTTP 403"))
        with self.assertRaises(github.GitHubError) as caught:
            self.call(github.dispatch, "e", {}, error=TimeoutError())
        self.assertEqual(caught.exception.code, github.UNREACHABLE)
        with mock.patch.dict(os.environ, {"NMAS_GITHUB_TOKEN": ""}):
            self.assertFalse(github.is_configured())
            with self.assertRaises(github.GitHubError) as caught:
                github.dispatch("e", {})
        self.assertEqual(caught.exception.code, github.NOT_CONFIGURED)


@ENABLED
class PageTests(Base):
    def test_the_validation_page_shows_the_result_against_the_change(self):
        f = simple_pass_change()
        url = reverse("core:change_validation", args=[f.change.change_id])
        self.assertContains(self.client.get(url), "NOT TRIGGERED")
        validate(f.change, f.sources)
        row = service.latest(f.change)
        page = self.client.get(url)
        self.assertContains(page, "Configuration Validation")
        self.assertContains(page, "QUEUED")
        self.gh.finish(row, status="in_progress")
        self.assertContains(self.client.get(url), "IN PROGRESS")
        self.gh.finish(row)
        page = self.client.get(url)                                                                  # the page view itself refreshes the status
        for wanted in ('badge--success">PASS', "#4242", row.candidate_hash[:12], "c" * 12, "View GitHub Actions Run", "https://github.com/example/nmas/actions/runs/4242"):
            self.assertContains(page, wanted)
        f.r1.set(f"interfaces.{f.a['id']}.description", "edited after the pass")
        self.assertContains(self.client.get(url), "candidate changed; new validation required")

    def test_a_failure_shows_its_reason(self):
        f = simple_pass_change()
        validate(f.change, f.sources)
        self.gh.finish(service.latest(f.change), conclusion="failure")
        page = self.client.get(reverse("core:change_validation", args=[f.change.change_id]))
        self.assertContains(page, 'badge--danger">FAIL')
        self.assertContains(page, "Failed: Configuration Validation: Validate the Configuration Change candidate")


class WorkflowFileTests(SimpleTestCase):
    def test_workflows_are_distinct_and_configuration_one_only_validates(self):
        folder = ROOT / ".github" / "workflows"
        names = {path.name: yaml.safe_load(path.read_text())["name"] for path in folder.glob("*.yml")}
        expected = {
            "configuration-validation.yml": "Configuration Validation",
            "secret-scanning.yml": "Secret scanning",
            "tier3-validation.yml": "Tier-3 validation",
            "repository-integrity.yml": "Repository integrity",
        }
        self.assertEqual(names, expected)
        text = (folder / "configuration-validation.yml").read_text()
        workflow = yaml.safe_load(text)
        triggers = workflow[True]                                                                   # YAML reads the key ``on`` as a boolean
        self.assertEqual(triggers, {"repository_dispatch": {"types": [bundle_module.EVENT_TYPE]}})
        self.assertEqual(workflow["permissions"], {"contents": "read"})
        self.assertIn("client_payload.change_id", workflow["run-name"])
        self.assertIn("client_payload.correlation_id", workflow["run-name"])
        self.assertTrue(workflow["run-name"].startswith("NMAS Configuration Validation | "))
        self.assertNotIn("secrets.", text)
        steps = workflow["jobs"]["configuration-validation"]["steps"]
        commands = " ".join(step.get("run", "") for step in steps)
        self.assertIn("scripts/ci/validate_configuration_change.py --event \"$GITHUB_EVENT_PATH\"", commands)
        self.assertNotIn("client_payload", commands)                                                 # no payload value reaches a shell
        for forbidden in ("ssh ", "docker exec", "nmas_isis_migration", "manage.py migrate", "netbox", "execute"):
            self.assertNotIn(forbidden, commands)

    def test_the_validator_package_imports_no_device_or_execution_code(self):
        for name in ("bundle.py", "checks.py", "github.py", "service.py"):
            source = (ROOT / "web" / "core" / "services" / "configuration_validation" / name).read_text()
            for forbidden in ("netmiko", "paramiko", "execution_service", "executors", "health.live", "nsot_netbox", "subprocess"):
                self.assertNotIn(forbidden, source, f"{name} mentions {forbidden}")
