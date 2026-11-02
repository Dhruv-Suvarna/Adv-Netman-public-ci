"""Phase-17 HTTP surface: GET is read-only, the single POST is explicit + CSRF, and the browser can supply no command.

The real engine runs against a SIMULATED network (``helpers.execution.FakeWorld``) injected at the service boundary; no test
contacts a device, NetBox, Slack or the network.
"""

from __future__ import annotations

import functools
import json
from unittest import mock

from core.tests.runner import OperatorClient  # V2 Phase 1: authenticated, MFA-verified operator
from django.test import TestCase
from django.urls import reverse

from core import models
from core.services import execution_service as es
from core.services.execution import engine
from core.tests.helpers import execution as x
from core.tests.helpers.validation import simple_pass_change

O = models.ExecutionOutcome
FIELDS = {name for name, _ in es.UAT_ACK_FIELDS}


def counts():
    return {m.__name__: (m.domain if m is models.AuditEvent else m.objects).count() for m in (models.ChangeExecutionRun, models.ConfigletExecutionResult, models.AuditEvent, models.ChangePlan,
                                                    models.ChangeValidationRun, models.OperationalCheckRun, models.Notification)}


def wired(p, world):
    """The service call as the view makes it, with the simulated network + capturing notifier injected."""
    return functools.partial(engine.execute_change, executor_factory=world.factory, evidence_provider=world.evidence_provider,
                             notifier=x.Notifications(), sources=p.sources, sleep=lambda s: None, clock=x.stepping_clock())


class ExecutionViewTests(TestCase):
    def url(self, name, p, *extra):
        return reverse(f"core:{name}", args=[p.change.change_id, *extra])

    def post(self, p, world, data, client=None):
        with mock.patch("core.views.execution_service.execute_change", wired(p, world)):
            return (client or self.client).post(self.url("change_execute_run", p), data)

    def test_get_pages_never_execute_validate_plan_or_touch_a_device(self):
        p = x.prepared()
        world = x.FakeWorld()
        first = self.post(p, world, {"confirm_mode": "COMPLETE"})
        run = p.change.execution_runs.get()
        urls = [self.url("change_execute", p), self.url("change_executions", p), self.url("change_execution_detail", p, run.run_id),
                self.url("change_execution_report", p, run.run_id), reverse("core:device_builder_change_detail", args=[p.change.change_id])]
        self.assertEqual(first.status_code, 302)
        before = counts()
        with mock.patch.object(engine, "execute_change", side_effect=AssertionError("GET must never execute")), \
                mock.patch("core.services.execution.executors.registry.executor_for", side_effect=AssertionError("GET must never open a device")):
            for url in urls:
                with self.subTest(url=url):
                    self.assertEqual(self.client.get(url).status_code, 200)
        self.assertEqual(counts(), before)
        self.assertContains(self.client.get(urls[-1]), reverse("core:change_execute", args=[p.change.change_id]))

    def test_execute_page_shows_eligibility_scope_and_offers_no_way_to_enter_a_command(self):
        p = x.prepared()
        html = self.client.get(self.url("change_execute", p)).content.decode()
        for expected in (p.change.change_id, "Complete", "compensates what THIS run applied", "CFG-001", "CFG-004", "csrfmiddlewaretoken", "CURRENT", "Execution history"):
            self.assertIn(expected, html)
        self.assertNotIn("disabled", html.split('<button type="submit"')[1].split(">")[0], "an eligible Change enables the button (the server still re-checks)")
        for forbidden in ("<textarea", 'name="command"', 'name="config', 'name="cli', 'name="vtysh', 'type="file"'):
            self.assertNotIn(forbidden, html)
        # ineligible => the button is disabled AND every blocker is listed with its remediation (never a bare red banner)
        p.f.r1.set(f"interfaces.{p.f.a['id']}.description", "edited after validation")
        blocked = self.client.get(self.url("change_execute", p)).content.decode()
        self.assertIn("VALIDATION_STALE", blocked)
        self.assertIn("Re-run Change Validation", blocked)
        self.assertIn("disabled", blocked.split('<button type="submit"')[1].split(">")[0])

    def test_partial_uat_page_surfaces_all_five_unchecked_acknowledgements_and_an_explicit_scope(self):
        p = x.prepared(mode=models.ExecutionMode.PARTIAL_UAT)
        html = self.client.get(self.url("change_execute", p)).content.decode()
        for name in FIELDS:
            self.assertIn(f'name="{name}"', html)
        self.assertNotIn("checked", html.replace("checkbox", ""), "acknowledgements are never pre-ticked")
        self.assertIn('name="through_cfg_id"', html)
        self.assertIn("never rolled back automatically", html)

    def test_post_needs_csrf_and_only_the_documented_fields_reach_the_engine(self):
        p = x.prepared()
        strict = OperatorClient(enforce_csrf_checks=True)
        before = counts()
        self.assertEqual(strict.post(self.url("change_execute_run", p), {"confirm_mode": "COMPLETE"}).status_code, 403)
        self.assertEqual(self.client.get(self.url("change_execute_run", p)).status_code, 405)
        self.assertEqual(counts(), before)
        spy = mock.Mock(wraps=wired(p, x.FakeWorld()))
        with mock.patch("core.views.execution_service.execute_change", spy):
            response = self.client.post(self.url("change_execute_run", p), {
                "confirm_mode": "COMPLETE", "command": "reload", "rendered_config": "no router bgp", "device": "R9", "actor": "root",
                "target": "R1", "vtysh": "-c 'write erase'",
            })
        kwargs = spy.call_args.kwargs
        self.assertEqual(set(kwargs), {"actor", "through_cfg_id", "acknowledgements", "confirm_mode"})
        self.assertEqual((kwargs["actor"], kwargs["confirm_mode"]), ("nmas-test-operator", "COMPLETE"))
        self.assertEqual(set(kwargs["acknowledgements"]), FIELDS)
        run = p.change.execution_runs.get()
        self.assertEqual((response.status_code, run.outcome), (302, O.SUCCEEDED))
        self.assertEqual(response["Location"], self.url("change_execution_detail", p, run.run_id))

    def test_an_ineligible_post_is_refused_recorded_and_never_reaches_a_device(self):
        p = x.prepared()
        with mock.patch("core.services.execution.executors.registry.executor_for", side_effect=AssertionError("no device")):
            response = self.client.post(self.url("change_execute_run", p), {})   # mode not confirmed
            run = p.change.execution_runs.get()
            self.assertEqual((response.status_code, run.outcome), (302, O.BLOCKED))
            self.assertIn("MODE_CONFIRMATION_MISMATCH", [b["code"] for b in run.report["blockers"]])
            self.assertContains(self.client.get(self.url("change_execution_detail", p, run.run_id)), "MODE_CONFIRMATION_MISMATCH")
            # no plan at all: nothing to link a run to, so the refusal is audited and the operator returns to the gate page
            fresh = simple_pass_change()
            refused = self.client.post(reverse("core:change_execute_run", args=[fresh.change.change_id]), {"confirm_mode": "COMPLETE"})
            self.assertEqual(refused["Location"], f"{reverse('core:change_execute', args=[fresh.change.change_id])}?refused=1")
            self.assertTrue(models.AuditEvent.objects.filter(change=fresh.change, metadata__stage="BLOCKED").exists())

    def test_each_failure_family_is_presented_distinctly_through_the_real_pipeline(self):
        def complete_failure(world):
            world.fail_apply["CFG-004"] = ("COMMAND_REJECTED", True)

        def incomplete_compensation(world):
            world.fail_apply["CFG-004"] = ("COMMAND_REJECTED", True)
            world.fail_compensation["CFG-001"] = ("COMPENSATION_FAILED", "STATE_NOT_RESTORED")

        rows = [
            ("execution succeeded", models.ExecutionMode.COMPLETE, {"confirm_mode": "COMPLETE"}, lambda w: None, O.SUCCEEDED, ("Every planned Configlet was applied",)),
            ("failed, compensation succeeded", models.ExecutionMode.COMPLETE, {"confirm_mode": "COMPLETE"}, complete_failure, O.FAILED_ROLLED_BACK,
             ("compensated and the prior state was verified restored", "Compensation (reverse order)")),
            ("failed, compensation incomplete", models.ExecutionMode.COMPLETE, {"confirm_mode": "COMPLETE"}, incomplete_compensation, O.FAILED_COMPENSATION_INCOMPLETE,
             ("compensation is INCOMPLETE or unproven", "COMPENSATION_FAILED")),
            ("failed before any change", models.ExecutionMode.COMPLETE, {"confirm_mode": "COMPLETE"}, lambda w: w.fail_connect.update(R1="CONNECTION_FAILED"),
             O.FAILED_NO_MUTATION, ("before any device configuration was changed",)),
            ("partial: prefix preserved", models.ExecutionMode.PARTIAL_UAT, {"confirm_mode": "PARTIAL_UAT", "through_cfg_id": "CFG-004", **{n: "on" for n in FIELDS}},
             lambda w: w.fail_apply.update({"CFG-003": ("COMMAND_REJECTED", False)}), O.FAILED_PARTIAL_APPLIED,
             ("PRESERVED (Partial UAT)", "Outside the requested scope", "NOT_ATTEMPTED")),
        ]
        seen = set()
        for label, mode, data, arrange, outcome, expected in rows:
            with self.subTest(case=label):
                p = x.prepared(mode=mode)
                world = x.FakeWorld()
                arrange(world)
                self.post(p, world, data)
                run = p.change.execution_runs.get()
                self.assertEqual(run.outcome, outcome)
                html = self.client.get(self.url("change_execution_detail", p, run.run_id)).content.decode()
                for text in expected:
                    self.assertIn(text, html)
                seen.add(es.OUTCOME_PRESENTATION[outcome][1])
        self.assertEqual(len(seen), len(rows), "every outcome family has its own explanation")

    def test_report_download_is_a_sanitized_attachment_addressed_only_through_its_change(self):
        p = x.prepared()
        self.post(p, x.FakeWorld(), {"confirm_mode": "COMPLETE"})
        run = p.change.execution_runs.get()
        response = self.client.get(self.url("change_execution_report", p, run.run_id))
        self.assertEqual(response["X-Content-Type-Options"], "nosniff")
        self.assertEqual(response["Content-Disposition"], f'attachment; filename="{p.change.change_id}-execution-{str(run.run_id)[:8]}.json"')
        document = json.loads(response.content)
        self.assertEqual((document["outcome"], document["plan_hash"]), (O.SUCCEEDED, p.plan.plan_hash))
        # a secret-shaped key that somehow reached a stored record is replaced on the way out
        models.ChangeExecutionRun.objects.filter(pk=run.pk).update(report={**run.report, "api_token": "leak", "nested": {"password": "leak"}})
        text = self.client.get(self.url("change_execution_report", p, run.run_id)).content.decode()
        self.assertNotIn("leak", text)
        self.assertIn("[REDACTED]", text)
        other = x.prepared()
        for name in ("change_execution_detail", "change_execution_report"):
            with self.subTest(route=name):
                self.assertEqual(self.client.get(self.url(name, other, run.run_id)).status_code, 404, "a run is only reachable through its own Change")
        self.assertEqual(self.client.get(self.url("change_execution_detail", p, "00000000-0000-0000-0000-000000000000")).status_code, 404)
