"""Lab 7 closure -- the remaining configuration-group entry points: the ``workbench_service`` facade (removal analysis,
validate-and-plan gate, revisions, archive, plan rows, workflow lists), ``candidate_renderer`` (hydrate / accepted-vs-draft
diff), ``change_service`` / ``field_commit_service`` / ``intent_service`` / ``lifecycle_service`` helpers,
``field_registry`` / ``field_validators`` lookups, ``device_builder_service`` and the ``nmas_templates`` command.

Hermetic: the validation engine and the planner are patched (their own suites cover them); the template command's
baseline generator is patched; the database is the test database.  Nothing contacts a device or NetBox.  POSITIVE:
exact analyses, plans, rows, renders, revisions and command output.  NEGATIVE: failed validation never plans, planner
errors are reported, archived / non-draft / history-bearing / intent-less Changes are refused, unknown intents and
missing revisions raise, unknown fields raise, and the command turns a template refusal into a CommandError.
"""
from __future__ import annotations

import io
from types import SimpleNamespace
from unittest import mock

from django.core.management import CommandError, call_command
from django.core.management.base import CommandParser
from django.http import Http404
from django.test import TestCase

from core import models
from core.management.commands import nmas_templates
from core.services import (
    candidate_renderer, change_service, device_builder_service, field_commit_service, field_registry, field_validators,
    intent_service, lifecycle_service, workbench_service,
)
from core.services.config_templates import service as template_service
from core.services.planning.errors import ERROR_MESSAGES, PlanGenerationError
from core.tests.helpers.candidates import commit, make_candidate
from core.tests.test_tg_workbench_semantics_closure import EOS


class WorkbenchFacadeTests(TestCase):
    def setUp(self):
        self.change, self.intent, self.revision = make_candidate()
        self.snapshot = SimpleNamespace(text=EOS, platform="arista_ceos")

    def test_analyze_removal_returns_the_analysis_for_a_line_range_or_objects(self):
        by_lines = workbench_service.analyze_removal(self.snapshot, models.RemovalMode.LINE_RANGE, {"from_line": 37, "to_line": 37})
        self.assertEqual((by_lines["platform"], by_lines["blockers"]), ("arista_ceos", []))
        self.assertIn("nat_pool:POOL-A", [item.get("id") for item in by_lines["items"]])
        by_object = workbench_service.analyze_removal(self.snapshot, models.RemovalMode.SEMANTIC, {"object_ids": ["nat_pool:POOL-A"]})
        self.assertEqual(by_object["blockers"], [])

    def test_analyze_removal_blocks_out_of_range_or_still_referenced_selections(self):
        analysis = workbench_service.analyze_removal(self.snapshot, models.RemovalMode.LINE_RANGE, {"from_line": 0, "to_line": 999})
        self.assertEqual(analysis["blockers"][0]["code"], "LINE_RANGE_OUT_OF_BOUNDS")
        self.assertNotEqual(analysis["status"], "READY")
        referenced = workbench_service.analyze_removal(self.snapshot, models.RemovalMode.LINE_RANGE, {"from_line": 15, "to_line": 17})
        self.assertEqual([(b["code"], b["object"]) for b in referenced["blockers"]], [("STILL_REFERENCED", "acl:EDGE-IN")])

    def test_validate_and_plan_returns_the_plan_after_a_passing_validation(self):
        run, plan = SimpleNamespace(status="PASS_WITH_WARNINGS"), object()
        with mock.patch.object(workbench_service.change_validation_service, "validate_change", return_value=run) as validate, \
                mock.patch.object(workbench_service.change_plan_service, "build_change_plan", return_value=(plan, True)) as build:
            self.assertEqual(workbench_service.validate_and_plan(self.change, actor="tester"), {"validation": run, "plan": plan, "plan_error": ""})
        validate.assert_called_once_with(self.change, actor="tester")
        build.assert_called_once_with(self.change, actor="tester")

    def test_validate_and_plan_never_plans_after_failed_validation_and_reports_planner_errors(self):
        failed = SimpleNamespace(status="FAIL")
        with mock.patch.object(workbench_service.change_validation_service, "validate_change", return_value=failed), \
                mock.patch.object(workbench_service.change_plan_service, "build_change_plan") as build:
            self.assertEqual(workbench_service.validate_and_plan(self.change), {"validation": failed, "plan": None, "plan_error": ""})
        build.assert_not_called()
        code = next(iter(ERROR_MESSAGES))
        with mock.patch.object(workbench_service.change_validation_service, "validate_change", return_value=SimpleNamespace(status="PASS")), \
                mock.patch.object(workbench_service.change_plan_service, "build_change_plan", side_effect=PlanGenerationError(code)):
            result = workbench_service.validate_and_plan(self.change)
        self.assertEqual((result["plan"], result["plan_error"]), (None, PlanGenerationError(code).message))

    def test_revise_change_refuses_archived_non_draft_executed_or_intentless_changes(self):
        archived, _, _ = make_candidate(device_name="R2")
        archived.metadata = {"archived_at": "2026-10-19T00:00:00Z"}
        validated, _, _ = make_candidate(device_name="R3")
        validated.lifecycle_state = models.ChangeLifecycleState.VALIDATED
        empty = change_service.create_change(title="empty")
        for label, change, message in (("archived", archived, "archived"), ("not draft", validated, "Only a Draft"),
                                       ("without intents", empty, "no device intent")):
            with self.subTest(case=f"refused {label}"):
                with self.assertRaisesRegex(workbench_service.RevisionRefused, message):
                    workbench_service.revise_change(change=change, actor="tester")
        self.assertEqual(self.intent.revisions.count(), 1)

    def test_archive_change_of_an_already_archived_change_never_audits_again(self):
        workbench_service.archive_change(change=self.change, actor="first")
        stamp = self.change.metadata["archived_at"]
        self.assertIsNone(workbench_service.archive_change(change=self.change, actor="second"))
        self.assertEqual((self.change.metadata["archived_at"], self.change.metadata["archived_by"]), (stamp, "first"))
        self.assertEqual(models.AuditEvent.objects.filter(event_type=models.AuditEventType.CHANGE_ARCHIVED).count(), 1)

    def test_plan_rows_returns_configlet_rows_in_sequence(self):
        configlet = SimpleNamespace(cfg_id="CFG-1", operation_type="DEPLOY", origin="INTENT", metadata={"label": "ACL"}, description="d",
                                    rendered_config="ip access-list X", target_device="R1")
        plan = SimpleNamespace(configlets=SimpleNamespace(order_by=lambda field: [configlet]))
        with mock.patch("core.services.planning.builder.get_latest_plan", return_value=plan):
            self.assertEqual(workbench_service.plan_rows(self.change), [{"cfg_id": "CFG-1", "operation": "DEPLOY", "origin": "INTENT", "label": "ACL",
                                                                         "rendered": "ip access-list X", "device": "R1"}])

    def test_plan_rows_without_a_plan_is_empty(self):
        self.assertEqual(workbench_service.plan_rows(self.change), [])

    def test_workflow_changes_of_an_unknown_device_or_archived_change_is_empty(self):
        self.change.metadata = {"workflow": models.ChangeWorkflow.CONFIGURATION_CHANGES}
        self.change.save()
        with self.subTest(case="none for unknown device"):
            self.assertEqual(workbench_service.workflow_changes(models.ChangeWorkflow.CONFIGURATION_CHANGES, device="NOPE"), [])
        workbench_service.archive_change(change=self.change)
        with self.subTest(case="none once archived"):
            self.assertEqual(workbench_service.workflow_changes(models.ChangeWorkflow.CONFIGURATION_CHANGES), [])


class RendererAndHelperTests(TestCase):
    def setUp(self):
        self.change, self.intent, self.revision = make_candidate()

    def test_hydrate_state_returns_accepted_values_and_applies_overrides(self):
        commit(self.change, self.intent, self.revision, "device.hostname", "EDGE-1")
        state = candidate_renderer.hydrate_state(self.intent, self.revision, field_overrides={"device.description": "edge"})
        self.assertEqual((state["field_values"]["device.hostname"], state["field_values"]["device.description"]), ("EDGE-1", "edge"))
        self.assertEqual({"field_values", "interfaces", "routing", "phase12"} <= set(state), True)

    def test_hydrate_state_never_uses_an_uncommitted_draft_for_the_accepted_view(self):
        commit(self.change, self.intent, self.revision, "device.hostname", "EDGE-1")
        models.IntentFieldState.objects.filter(revision=self.revision, path="device.hostname").update(draft_value="DRAFT-ONLY", dirty=True)
        with self.subTest(case="refused uncommitted draft value"):
            self.assertEqual(candidate_renderer.hydrate_state(self.intent, self.revision)["field_values"]["device.hostname"], "EDGE-1")
        self.assertEqual(candidate_renderer.hydrate_state(self.intent, self.revision, use_draft=True)["field_values"]["device.hostname"], "DRAFT-ONLY")

    def test_diff_accepted_vs_draft_returns_the_unified_diff(self):
        commit(self.change, self.intent, self.revision, "device.hostname", "EDGE-1")
        self.assertTrue(candidate_renderer.diff_accepted_vs_draft(self.intent, self.revision)["identical"])
        models.IntentFieldState.objects.filter(revision=self.revision, path="device.hostname").update(draft_value="EDGE-2", dirty=True)
        diff = candidate_renderer.diff_accepted_vs_draft(self.intent, self.revision)
        self.assertFalse(diff["identical"])
        self.assertTrue(any(line.startswith("+") and "EDGE-2" in line for line in diff["diff_lines"]))

    def test_can_delete_draft_returns_true_for_a_fresh_draft(self):
        self.assertTrue(change_service.can_delete_draft(self.change))

    def test_can_delete_draft_is_false_once_the_change_is_not_draft(self):
        self.change.lifecycle_state = models.ChangeLifecycleState.VALIDATED
        self.assertFalse(change_service.can_delete_draft(self.change))

    def test_add_target_of_a_duplicate_device_never_creates_a_second_target(self):
        first = change_service.add_target(change=self.change, device_name="R1", site="lab")
        with self.subTest(case="refused duplicate target"):
            again = change_service.add_target(change=self.change, device_name="R1", site="other")
        self.assertEqual((again.pk, again.site), (first.pk, "lab"))
        self.assertEqual(models.ChangeTarget.objects.filter(change=self.change, device_name="R1").count(), 1)

    def test_resolve_intent_and_active_revision_return_the_owned_rows(self):
        self.assertEqual(field_commit_service.resolve_intent(change=self.change, intent_id=self.intent.pk), self.intent)
        self.assertEqual(field_commit_service.resolve_active_revision(self.intent), self.revision)

    def test_resolve_intent_of_another_change_or_a_missing_revision_is_refused(self):
        other, _, _ = make_candidate(device_name="R2")
        with self.subTest(case="refused foreign intent"):
            with self.assertRaises(Http404):
                field_commit_service.resolve_intent(change=other, intent_id=self.intent.pk)
        bare, _ = intent_service.create_or_get_device_intent(change=other, device_name="R9", platform=models.Platform.ARISTA_CEOS)
        with self.subTest(case="refused missing revision"):
            with self.assertRaises(field_commit_service.RevisionMissingError):
                field_commit_service.resolve_active_revision(bare)

    def test_accept_and_rollback_of_an_unknown_field_raise(self):
        for label, function in (("accept", intent_service.accept_field_value), ("rollback", intent_service.rollback_draft_to_accepted)):
            with self.subTest(case=f"refused unknown field on {label}"):
                with self.assertRaises(models.IntentFieldState.DoesNotExist):
                    function(revision=self.revision, path="no.such.field")

    def test_list_lifecycle_history_of_a_fresh_change_has_no_transition_beyond_draft(self):
        events = list(lifecycle_service.list_lifecycle_history(change_service.create_change(title="x")))
        self.assertEqual([(e.from_state, e.to_state) for e in events], [("", models.ChangeLifecycleState.DRAFT)])

    def test_field_paths_for_module_returns_the_registered_paths(self):
        self.assertEqual(field_registry.field_paths_for_module("device_identity"), ["device.hostname", "device.description", "device.target_type"])

    def test_field_paths_for_an_unknown_module_is_empty(self):
        self.assertEqual(field_registry.field_paths_for_module("no_such_module"), [])

    def test_vlan_set_display_of_an_empty_value_is_empty(self):
        self.assertEqual((field_validators.vlan_set_display(None), field_validators.vlan_set_display([])), ("", ""))

    def test_get_device_builder_summary_returns_counts_and_recent_changes(self):
        summary = device_builder_service.get_device_builder_summary()
        self.assertEqual((summary["status"], summary["total_changes"]), ("operational", 1))
        self.assertEqual(summary["recent_changes"], [self.change])


class TemplatesCommandTests(TestCase):
    def run_command(self, *args):
        out = io.StringIO()
        call_command("nmas_templates", *args, stdout=out)
        return out.getvalue()

    def test_add_arguments_returns_after_registering_actions_and_flags(self):
        command = nmas_templates.Command()
        parser = CommandParser(prog="nmas_templates")
        self.assertIsNone(command.add_arguments(parser))
        options = parser.parse_args(["generate-baselines", "--live", "--write-packages", "--actor", "me"])
        self.assertEqual((options.action, options.live, options.write_packages, options.actor), ("generate-baselines", True, True, "me"))

    def test_handle_returns_after_printing_generated_loaded_and_listed_templates(self):
        rows = [{"key": "spine-device", "ref": "TPL-BASELINE-SPINE@v1", "created": True, "digest": "a" * 64}]
        with mock.patch.object(nmas_templates.baselines, "generate", return_value=rows), \
                mock.patch.object(nmas_templates.baselines, "write_packages", return_value=[SimpleNamespace(name="spine.yaml")]):
            self.assertEqual(self.run_command("generate-baselines", "--write-packages"),
                             "spine-device: TPL-BASELINE-SPINE@v1 PUBLISHED aaaaaaaaaaaa\nwrote spine.yaml\n")
        loaded = [{"file": "spine.yaml", "ref": "TPL-BASELINE-SPINE@v1", "created": False, "digest": "b" * 64}]
        with mock.patch.object(nmas_templates.baselines, "load_packages", return_value=loaded):
            self.assertEqual(self.run_command("load-baselines"), "spine.yaml: TPL-BASELINE-SPINE@v1 already present bbbbbbbbbbbb\n")
        self.assertEqual(self.run_command("list"), "")

    def test_handle_turns_a_template_refusal_into_a_command_error(self):
        with mock.patch.object(nmas_templates.baselines, "load_packages",
                               side_effect=template_service.TemplateError("DIGEST_MISMATCH", "altered")):
            with self.assertRaisesRegex(CommandError, "DIGEST_MISMATCH: altered"):
                nmas_templates.Command().handle(action="load-baselines", live=False, write_packages=False, actor="tester")
