"""Lab 7 closure -- CI / governance: the Tier-3 engine pieces (catalog, change set, impact expansion, CLI parser, execution, GitHub event,
git helpers, planner records, redaction, report, runner, service, static checks), the configuration-validation CI script, and the test
governance helpers (cases, cells, inventory, policy, presentation, schema, session, summary, symbols, traced_unittest, tracer, and the
``baseline`` command), each called directly.

Hermetic: git runs only against a throw-away ``helpers.tier3.TempRepo``; every Tier-3 command goes through ``FakeRunner``; the only real
processes are ``bash -n`` on a temporary script and the current interpreter printing one word (``default_runner``).  The governance report is
built in memory from a temporary inventory; ``baseline`` is run WITHOUT ``--write`` so the tracked baseline is never touched.  No device,
NetBox, network or GitHub API is reached.  POSITIVE: exact commands, dicts, renders, figures.  NEGATIVE: invalid labels / revisions / events,
secret-shaped text, a crashed check, an empty change, a non-repository, an unreadable event and a failed category are refused or reported.
"""
from __future__ import annotations

import importlib.util
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from django.test import SimpleTestCase

from core.management.commands import nmas_test_governance
from core.services.ci import catalog, classify, cli, execute, github_context, gitio, planner, redact, report, rules, runner, service, static_checks
from core.services.ci.changes import ChangeSet, added_lines
from core.services.ci.constants import CheckStatus
from core.services.test_governance import (
    cases, cells, inventory as tg_inventory, policy as tg_policy, presentation, schema, session, summary, symbols, traced_unittest,
)
from core.services.test_governance.constants import CaseState
from core.services.test_governance.tracer import DirectCallTracer
from core.tests.helpers.tier3 import FakeRunner, TempRepo, change_set
from core.tests.test_test_governance import SERVICE, SOURCE, _report, make_inventory, trace

REPO_ROOT = Path(__file__).resolve().parents[3]
TOKEN = "gh" + "p_" + "A1b2C3d4E5" * 4          # assembled at runtime: this file never contains a credential-shaped literal


class TempRepoCase(SimpleTestCase):
    def setUp(self):
        self.repo = TempRepo()
        self.addCleanup(self.repo.cleanup)
        self.repo.write("README.md", "hello\n")
        self.base = self.repo.commit("base")
        self.repo.write("web/core/services/health/probe.py", "VALUE = 1\n")
        self.head = self.repo.commit("head")

    def planned(self):
        return service.plan_change_effect(service.Tier3Request(repo=self.repo.path, base=self.base, head=self.head))


# ------------------------------------------------------------------------------------------------------------------- Tier-3
class Tier3EngineTests(TempRepoCase):
    def test_catalog_command_for_builds_the_traced_django_suite(self):
        command = catalog.command_for("django.tests", python="py", params={"labels": ["core.tests.test_x"], "governance": True})
        self.assertEqual(command.argv[:3], ("py", "-m", "coverage"))
        self.assertEqual((command.argv[-5:], command.cwd), (("manage.py", "test", "--verbosity", "2", "core.tests.test_x"), "web"))

    def test_catalog_refuses_an_invalid_test_module_label(self):
        self.assertFalse(catalog.valid_test_module("x; rm -rf /"))
        with self.assertRaisesMessage(ValueError, "refusing unexpected Django test label"):
            catalog.command_for("django.tests", python="py", params={"labels": ["core.tests.x;y"]})

    def test_git_helpers_resolve_the_temporary_repository(self):
        self.assertTrue(gitio.valid_revision("main~1"))
        self.assertEqual(gitio.repository_root(self.repo.path).resolve(), self.repo.path.resolve())
        self.assertEqual(gitio.resolve_commit(self.repo.path, "HEAD"), self.head)

    def test_git_helpers_refuse_invalid_revisions_and_a_non_repository(self):
        self.assertFalse(gitio.valid_revision("a..b"))
        with tempfile.TemporaryDirectory() as plain, self.assertRaises(gitio.GitError):
            gitio.repository_root(Path(plain))

    def test_change_set_with_files_and_planner_records_to_dict(self):
        cs, plan = self.planned()
        self.assertFalse(cs.empty)
        check = plan.required[0]
        self.assertEqual(set(check.to_dict()) - {"params"}, {"id", "gate", "title", "required", "reasons"})
        warning = planner.PlanWarning("CODE", "message", ["a", "b"])
        self.assertEqual(warning.to_dict(), {"code": "CODE", "message": "message", "paths": ["a", "b"]})
        self.assertEqual(service.provenance_for(service.Tier3Request(repo=self.repo.path), cs, plan)["head_sha"], self.head)

    def test_plan_change_effect_selects_checks_for_a_health_change(self):
        cs, plan = self.planned()
        self.assertEqual([f.path for f in cs.files], ["web/core/services/health/probe.py"])
        self.assertIn("health", plan.direct)

    def test_provenance_without_a_github_context_has_no_event(self):
        cs, plan = self.planned()
        provenance = service.provenance_for(service.Tier3Request(repo=self.repo.path), cs, plan)
        self.assertEqual((provenance["event"], provenance["run_id"], provenance["lab_gate_requested"]), (None, None, False))

    def test_added_lines_of_an_unchanged_tree_is_empty(self):
        same = ChangeSet(self.head, self.head, self.head, "merge-base", ())
        self.assertEqual(added_lines(self.repo.path, same), ([], False))

    def test_expand_impact_of_no_change_is_empty(self):
        self.assertEqual(classify.expand_impact(set()), {})

    def test_build_parser_reads_the_full_mode_flags(self):
        args = cli.build_parser().parse_args(["--mode", "full", "--format", "json", "--plan-only"])
        self.assertEqual((args.mode, args.format, args.plan_only, args.head), ("full", "json", True, "HEAD"))

    def test_execute_plan_and_the_report_record_every_required_check(self):
        cs, plan = self.planned()
        fake = FakeRunner()
        results = execute.execute_plan(plan, self.repo.path, cs, runner=fake, shell_runner=lambda path: (True, ""))
        self.assertEqual([r.id for r in results if r.required], [c.id for c in plan.required])
        self.assertEqual(results[0].to_dict(include_timing=False)["status"], results[0].status)
        rep = report.Tier3Report(provenance=service.provenance_for(service.Tier3Request(repo=self.repo.path), cs, plan), plan=plan, results=results)
        counts = rep.summary_counts()
        self.assertEqual((counts["selected"], counts["errored"]), (len(plan.required) + len(plan.optional), 0))
        self.assertEqual(json.loads(rep.to_json(include_timing=False))["result"], rep.result)
        self.assertEqual(set(report.coverage(results).values()) - {"EXECUTED", "NOT_SELECTED", "NOT_RUN"}, set())

    def test_execute_plan_refuses_a_crashed_check_as_incomplete(self):
        cs, plan = self.planned()
        results = execute.execute_plan(plan, self.repo.path, cs, runner=FakeRunner({"": RuntimeError("boom")}), shell_runner=lambda path: (True, ""))
        crashed = [r for r in results if r.status == CheckStatus.ERROR]
        self.assertTrue(crashed)
        self.assertEqual(crashed[0].to_dict()["summary"], "check crashed: RuntimeError")
        rep = report.Tier3Report(provenance={"engine_version": "x"}, plan=plan, results=results)
        self.assertIn("INCOMPLETE", report.coverage(results).values())
        self.assertIn("INCOMPLETE", report.render_text(rep).splitlines()[0])
        self.assertIn("❌", report.render_markdown(rep))
        self.assertNotEqual(json.loads(rep.to_json())["result"], "PASS")

    def test_load_event_reads_the_event_payload(self):
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as handle:
            json.dump({"pull_request": {"number": 61}}, handle)
        self.addCleanup(os.unlink, handle.name)
        self.assertEqual(github_context.load_event({"GITHUB_EVENT_PATH": handle.name}), {"pull_request": {"number": 61}})

    def test_load_event_refuses_a_missing_or_unreadable_event(self):
        for label, env in (("refused missing path", {}), ("refused unreadable", {"GITHUB_EVENT_PATH": "/nonexistent/event.json"})):
            with self.subTest(label), self.assertRaises(github_context.GitHubContextError):
                github_context.load_event(env)

    def test_glob_match_refuses_a_path_outside_the_pattern(self):
        self.assertFalse(rules.glob_match("web/core/services/ci/**", "web/core/services/health/probe.py"))


class RedactionRunnerTests(SimpleTestCase):
    def test_redaction_helpers_keep_ordinary_text(self):
        self.assertEqual((redact.scan_line("ok line"), redact.redact_text("password_ref=vault:x")), ([], "password_ref=vault:x"))
        self.assertEqual(redact.bound_output("a\nb\nc", max_lines=2), "b\nc")
        self.assertEqual(redact.bound_string("short"), "short")

    def test_redaction_helpers_mask_secret_shaped_text(self):
        with self.subTest("refused token scan"):
            self.assertTrue(redact.scan_line(f"token {TOKEN}"))
        for label, call in (("refused token", lambda: redact.redact_text(f"t={TOKEN}")), ("refused assignment", lambda: redact.redact_text("password=hunter2")),
                            ("refused output", lambda: redact.bound_output(f"x\n{TOKEN}")), ("refused string", lambda: redact.bound_string(f"{TOKEN}", limit=500))):
            with self.subTest(label):
                text = call()
                self.assertNotIn(TOKEN, text)
                self.assertNotIn("hunter2", text)
        self.assertEqual(len(redact.bound_string("x" * 50, limit=10)), 10)

    def test_build_env_and_default_runner_run_a_catalogue_command(self):
        command = catalog.Command((sys.executable, "-c", "print('tier3')"), env_extra={"NMAS_X": "1"})
        self.assertEqual(runner.build_env(command)["NMAS_X"], "1")
        result = runner.default_runner(command, REPO_ROOT, 30)
        self.assertEqual((result.returncode, result.output.strip()), (0, "tier3"))

    def test_default_runner_refuses_a_missing_program(self):
        result = runner.default_runner(catalog.Command(("/nonexistent/nmas-tool",)), REPO_ROOT, 5)
        self.assertEqual((result.returncode, result.error), (None, "FileNotFoundError: could not start '/nonexistent/nmas-tool'"))

    def test_default_runner_keeps_partial_bytes_when_a_suite_times_out(self):
        command = catalog.Command((sys.executable, "-c", "print('test')"))
        expired = subprocess.TimeoutExpired(command.argv, 1, output=b"last completed test\n", stderr=b"still running\n")
        with mock.patch.object(runner.subprocess, "run", side_effect=expired):
            result = runner.default_runner(command, REPO_ROOT, 1)
        self.assertTrue(result.timed_out)
        self.assertIn("last completed test", result.output)
        self.assertIn("still running", result.output)

    def test_shell_syntax_parses_a_valid_script(self):
        with tempfile.TemporaryDirectory() as root:
            Path(root, "ok.sh").write_text("echo ok\n", encoding="utf-8")
            self.assertEqual(runner.shell_syntax(Path(root), "ok.sh"), (True, ""))

    def test_shell_syntax_refuses_an_unbalanced_script(self):
        with tempfile.TemporaryDirectory() as root:
            Path(root, "bad.sh").write_text("if true; then\n", encoding="utf-8")
            ok, message = runner.shell_syntax(Path(root), "bad.sh")
        self.assertFalse(ok)
        self.assertIn("syntax error", message)

    def test_check_syntax_parses_valid_files_and_error_records_carry_the_line(self):
        with tempfile.TemporaryDirectory() as root:
            Path(root, "a.py").write_text("x = 1\n", encoding="utf-8")
            Path(root, "b.json").write_text("{}", encoding="utf-8")
            outcome = static_checks.check_syntax(Path(root), ["a.py", "b.json"])
        self.assertEqual((outcome.status, outcome.counts["files_checked"]), (CheckStatus.PASS, 2))
        template, yaml_error = static_checks._TemplateError("unexpected end", 3), static_checks._YamlError("bad indent", 7)
        self.assertEqual(((template.message, template.line), (yaml_error.message, yaml_error.line)), (("unexpected end", 3), ("bad indent", 7)))

    def test_parse_error_records_of_an_unknown_line(self):
        with self.subTest("refused template without a line"):
            self.assertIsNone(static_checks._TemplateError("x", None).line)
        with self.subTest("refused yaml without a line"):
            self.assertIsNone(static_checks._YamlError("x", None).line)

    def test_change_set_without_files_is_empty(self):
        self.assertTrue(change_set().empty)


# ----------------------------------------------------------------------------------------------- configuration validation CI
def _script():
    spec = importlib.util.spec_from_file_location("validate_configuration_change_tg", REPO_ROOT / "scripts" / "ci" / "validate_configuration_change.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class ValidationScriptTests(SimpleTestCase):
    REPORT = {"overall": "PASS", "bundle": {"change_id": "CHG-1", "devices": ["R1"]}, "tested_sha": "a" * 40,
              "categories": [{"category": "A", "title": "Bundle integrity", "status": "PASS", "checks": [{"name": "hash", "status": "PASS", "detail": ""}]}]}

    def test_summary_renders_a_passing_report(self):
        text = _script().summary(self.REPORT)
        self.assertIn("**PASS**", text)
        self.assertIn("| A. Bundle integrity | PASS |", text)

    def test_summary_and_main_report_an_unreadable_event_as_failed(self):
        module = _script()
        failed = {**self.REPORT, "overall": "FAIL", "categories": [{**self.REPORT["categories"][0], "status": "FAIL",
                                                                      "checks": [{"name": "hash", "status": "FAIL", "detail": "mismatch"}]}]}
        self.assertIn("- **FAIL** hash (mismatch)", module.summary(failed))
        with mock.patch.object(sys, "stdout", io.StringIO()) as out:
            self.assertEqual(module.main(["--event", "/nonexistent/event.json", "--skip-tests"]), 1)
        self.assertIn("**FAIL**", out.getvalue())


# --------------------------------------------------------------------------------------------------------- test governance
class GovernanceHelperTests(SimpleTestCase):
    def report(self):
        sym = f"{SERVICE}::validate_port"
        return _report({SERVICE: SOURCE}, trace(**{"django:t.test_accepts_valid_port": ("PASS", {sym: [1, 0, 0, 0]}, ())}))

    def test_shape_errors_of_a_well_formed_case_is_empty_list(self):
        good = cases.Case("GOOD_CASE", SERVICE + "::validate_port", cases.POSITIVE, "a valid port", "accepted")
        with self.subTest("well formed case accepted"):
            self.assertEqual(cases.shape_errors(good), [])

    def test_default_cells_policy_and_schema_load_the_tracked_files(self):
        cells.default_cells.cache_clear()
        tg_policy.default_policy.cache_clear()
        self.assertTrue(cells.default_cells())                  # cleared first: the cached wrapper would not run the loader
        self.assertEqual(tg_policy.default_policy(), tg_policy.load_policy())
        self.assertEqual(schema.load_schema()["type"], "object")

    def test_cell_ids_artifact_ids_symbol_ids_and_platforms_of_unsupported_cells(self):
        self.assertEqual(cells.cell_case_id("sonic", "routing.BGP", "RENDER", "NEGATIVE"), "CELL:sonic:routing.BGP:RENDER:NEGATIVE")
        self.assertEqual(cells.supported_platforms(()), frozenset())
        self.assertEqual(tg_inventory.artifact_id("PY", "web/x.py"), "PY:web/x.py")
        self.assertEqual(symbols.symbol_id("web/x.py", "f"), "web/x.py::f")

    def test_symbol_requirements_and_dict(self):
        _root, _inv, modules = make_inventory({SERVICE: SOURCE})
        symbol = next(s for m in modules.values() for s in m.symbols if s.qualname == "validate_port")
        self.assertEqual((symbol.positive_required, symbol.negative_required), (True, True))
        self.assertEqual(symbol.to_dict()["qualname"], "validate_port")

    def test_trace_output_reads_the_environment(self):
        with mock.patch.dict(os.environ, {session.TRACE_ENV: "  /tmp/trace.json "}):
            self.assertEqual(session.trace_output(), "/tmp/trace.json")

    def test_case_view_of_a_negative_symbol_case_refuses(self):
        data = self.report()
        item = next(c for c in data["cases"] if c["kind"] == "SYMBOL" and c["polarity"] == "NEGATIVE")
        view = presentation.case_view(data, item)
        self.assertTrue(view["title"].startswith("validate_port() refuses "))
        self.assertEqual(view["state"], CaseState.MISSING)

    def test_figures_and_gap_markdown_of_an_excluded_group_count_nothing_missing(self):
        data = self.report()
        excluded = summary.figures(data, exclude_groups=("device_builder", "configuration"))
        self.assertEqual((excluded["positive"]["required"], excluded["negative"]["missing"]), (0, 0))
        text = summary.gap_markdown(data, exclude_groups=())
        self.assertIn("| Negative cases PASS / required | 0 / ", text)

    def test_traced_unittest_main_of_an_empty_discovery_fails(self):
        # unittest's shared default loader remembers the top-level directory of an earlier discover() in this process; reset it here
        # so the result does not depend on which tests ran first.
        with tempfile.TemporaryDirectory() as empty, mock.patch.object(traced_unittest, "trace_output", return_value=""), \
                mock.patch.object(sys, "stderr", io.StringIO()), mock.patch.object(unittest.defaultTestLoader, "_top_level_dir", None):
            self.assertEqual(traced_unittest.main(["discover", "-s", empty, "-p", "test_*.py"]), 1)

    def test_tracer_test_id_never_keeps_the_web_prefix(self):
        tracer = DirectCallTracer(REPO_ROOT, {}, test_roots=("web/core/tests",), suite="django")
        self.assertEqual(tracer.test_id(mock.Mock(id=lambda: "web.core.tests.test_x.T.test_y")), "django:core.tests.test_x.T.test_y")

    def test_do_baseline_summarizes_a_verified_report(self):
        data = self.report()
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as handle:
            json.dump(data, handle)
        self.addCleanup(os.unlink, handle.name)
        out = io.StringIO()
        with mock.patch.object(nmas_test_governance.gate, "write_baseline") as write:
            nmas_test_governance.Command(stdout=out).do_baseline(source=handle.name)
        write.assert_not_called()
        self.assertIn(f"baseline from {'a' * 40}:", out.getvalue())
