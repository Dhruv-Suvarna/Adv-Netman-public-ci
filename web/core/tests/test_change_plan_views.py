"""Plan page / Build Plan / JSON report: representative HTTP behavior.

Method, CSRF, unknown-Change and read-only rules for these endpoints are in ``test_view_boundaries``;
plan semantics (eligibility, ordering, dependencies) are in ``test_change_plan_service``.
"""

from __future__ import annotations

import json
import uuid
from unittest import mock

from django.test import TestCase
from django.urls import reverse

from core import models
from core.services import change_plan_service as cps
from core.tests.helpers.validation import change_in_state, make_sources, new_change, simple_pass_change, validate


class PlanViewBase(TestCase):
    def setUp(self):
        # Build Plan reads the (faked) validation sources for a freshness check; nothing reaches a real NetBox.
        patcher = mock.patch("core.services.validation.sources.build_source_bundle", side_effect=lambda: make_sources())
        self.build_sources = patcher.start()
        self.addCleanup(patcher.stop)

    def url(self, change, name, *args):
        return reverse(f"core:{name}", args=[change.change_id, *args])


class PlanPageTests(PlanViewBase):
    def test_get_is_read_only_and_explains_why_no_plan_can_be_built_yet(self):
        change, _ = change_in_state("NEVER_RUN")
        response = self.client.get(self.url(change, "change_plan"))
        self.assertEqual(response.status_code, 200)
        for text in ("NO PLAN", "NEVER RUN", "VALIDATION_NEVER_RUN", "Build Plan", "No plans generated yet"):
            self.assertContains(response, text)
        self.assertContains(response, 'disabled aria-disabled="true"')
        self.assertFalse(models.ChangePlan.objects.exists())
        self.assertEqual(self.build_sources.call_count, 0, "loading the page reads no source and builds nothing")

    def test_post_builds_one_plan_idempotently_and_the_page_shows_everything_the_operator_needs(self):
        change, _ = change_in_state("PASS_WITH_WARNINGS")
        page = self.url(change, "change_plan")
        self.assertRedirects(self.client.post(self.url(change, "change_plan_build")), page, fetch_redirect_response=False)
        self.client.post(self.url(change, "change_plan_build"), {"path": "/etc/passwd", "sources": "x", "plan_id": "1"})
        plan = cps.get_latest_plan(change)
        self.assertEqual(models.ChangePlan.objects.filter(change=change).count(), 1)  # repeating returns the existing plan
        response = self.client.get(page)
        self.assertEqual(response.status_code, 200)
        for text in (
            change.change_id, "Draft", "CURRENT", str(plan.validation_run.run_id), "PASS_WITH_WARNINGS", "Configlets", "Devices",
            "Dependencies", "Warnings", "VALIDATION_WARNINGS_CARRIED_FORWARD", "Download JSON plan", "requires:",
            "CFG-001", "DEFINE", "ACTIVATE / ATTACH" if plan.configlets.filter(operation_type="ACTIVATE_ATTACH").exists() else "DEFINE",
            "Verification requirement", "UNKNOWN_DEFERRED",
        ):
            with self.subTest(text=text):
                self.assertContains(response, text)
        for label in ("Foundation / access", "Interface construction", "Addressing", "Basic forwarding", "Dynamic routing",
                      "Higher-level services", "Traffic-affecting policy", "Monitoring / mirroring", "Persistence"):
            with self.subTest(stage=label):
                self.assertContains(response, label)
        self.assertContains(response, "none (normal)")  # empty stages are marked, not hidden or invented
        body = response.content.decode()
        self.assertEqual(body.count('action="' + self.url(change, "change_plan_build") + '"'), 1)
        self.assertNotIn("<textarea", body)  # Configlets are shown, never editable
        self.assertNotIn("contenteditable", body)
        change.refresh_from_db()
        self.assertEqual(change.lifecycle_state, models.ChangeLifecycleState.DRAFT)

    def test_a_refused_build_redirects_with_a_fixed_reason_and_persists_nothing(self):
        for state, code in (("NEVER_RUN", "VALIDATION_NEVER_RUN"), ("STALE", "VALIDATION_STALE"),
                            ("BLOCKED", "VALIDATION_BLOCKED"), ("INCOMPLETE", "VALIDATION_INCOMPLETE")):
            with self.subTest(validation=state):
                change, sources = change_in_state(state)
                self.build_sources.side_effect = lambda served=sources: served  # the sources validation itself saw
                response = self.client.post(self.url(change, "change_plan_build"))
                self.assertRedirects(response, self.url(change, "change_plan") + f"?refused={code}", fetch_redirect_response=False)
                page = self.client.get(response["Location"])
                self.assertContains(page, "Plan not built")
                self.assertContains(page, cps.ERROR_MESSAGES[code])
                self.assertFalse(models.ChangePlan.objects.filter(change=change).exists())

    def test_the_refused_query_value_is_matched_against_known_codes_and_never_echoed(self):
        change = new_change()
        page = self.url(change, "change_plan")
        hostile = self.client.get(page, {"refused": "<script>alert(1)</script>"})
        self.assertNotContains(hostile, "<script>alert(1)</script>")
        self.assertNotContains(hostile, "Plan not built")

    def test_a_stale_plan_is_flagged_and_a_historical_plan_is_read_only(self):
        f = simple_pass_change()
        validate(f.change, f.sources)
        self.client.post(self.url(f.change, "change_plan_build"))
        plan = cps.get_latest_plan(f.change)
        f.r1.set(f"interfaces.{f.a['id']}.description", "edited after planning")
        page = self.client.get(self.url(f.change, "change_plan"))
        for text in ("STALE", "must not be treated as executable", "ACCEPTED_INTENT_CHANGED"):
            self.assertContains(page, text)
        detail = self.client.get(self.url(f.change, "change_plan_detail", str(plan.plan_id)))
        self.assertContains(detail, str(plan.plan_id))
        self.assertContains(detail, "STALE")

    def test_untrusted_plan_content_is_escaped(self):
        f = simple_pass_change()
        validate(f.change, f.sources)
        self.client.post(self.url(f.change, "change_plan_build"))
        plan = cps.get_latest_plan(f.change)
        hostile = "<script>alert(1)</script>"
        # simulate a manually edited row (a queryset update bypasses the model's immutability guard on purpose)
        models.Configlet.objects.filter(plan=plan).update(rendered_config=hostile, description=hostile)
        response = self.client.get(self.url(f.change, "change_plan"))
        self.assertNotContains(response, hostile)
        self.assertContains(response, "&lt;script&gt;alert(1)&lt;/script&gt;")


class PlanReportTests(PlanViewBase):
    def test_the_json_report_is_safe_structured_and_has_a_fixed_filename(self):
        f = simple_pass_change()
        validate(f.change, f.sources)
        self.client.post(self.url(f.change, "change_plan_build"))
        plan = cps.get_latest_plan(f.change)
        response = self.client.get(self.url(f.change, "change_plan_report", str(plan.plan_id)) + "?file=../../etc/passwd")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response["Content-Type"], "application/json; charset=utf-8")
        self.assertEqual(response["Content-Disposition"], f'attachment; filename="{cps.plan_report_filename(plan)}"')
        self.assertEqual(response["X-Content-Type-Options"], "nosniff")
        document = json.loads(response.content)
        for key in ("plan", "validation", "summary", "stages", "configlets", "dependencies", "warnings", "limitations"):
            self.assertIn(key, document)
        self.assertEqual(document["plan"]["currency"], "CURRENT")
        self.assertEqual(document["plan"]["change_lifecycle_state"], "DRAFT")
        self.assertEqual(len(document["configlets"]), plan.configlets.count())
        self.assertNotRegex(response.content.decode().lower(), r'"(password|secret|token|community|webhook)"')

    def test_plans_are_only_addressable_through_their_own_change(self):
        f = simple_pass_change()
        validate(f.change, f.sources)
        self.client.post(self.url(f.change, "change_plan_build"))
        plan = cps.get_latest_plan(f.change)
        other = new_change("other")
        cases = {
            "detail via another change": reverse("core:change_plan_detail", args=[other.change_id, str(plan.plan_id)]),
            "report via another change": reverse("core:change_plan_report", args=[other.change_id, str(plan.plan_id)]),
            "detail, bad id": self.url(f.change, "change_plan_detail", "not-a-uuid"),
            "detail, unknown plan": self.url(f.change, "change_plan_detail", str(uuid.uuid4())),
            "report, unknown plan": self.url(f.change, "change_plan_report", str(uuid.uuid4())),
        }
        for label, url in cases.items():
            with self.subTest(case=label):
                self.assertEqual(self.client.get(url).status_code, 404)
