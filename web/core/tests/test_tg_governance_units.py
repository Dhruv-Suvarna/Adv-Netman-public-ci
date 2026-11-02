"""Lab 7 -- direct positive / negative cases for the test-governance package's own helpers.

test_test_governance.py proves the governance *behaviour* end to end (catalog, gate, freshness) with fixtures; this
module closes the remaining per-function cases of the package itself: each public helper is called directly once with
valid input (POSITIVE) and once with invalid / hostile input (NEGATIVE: malformed data, missing files, tampered
evidence, secrets in the environment, a missing executable). Nothing here runs a real test suite, Pylint or GitHub.
"""

from __future__ import annotations

import gzip
import io
import json
import tempfile
import zipfile
from pathlib import Path
from unittest import mock

from django.test import SimpleTestCase

from core.services.test_governance import (
    catalog, catalog_check, cells as cells_module, coverage_data, evidence as evidence_module, gate, github_evidence, inventory,
    pylint_data, report as report_module, runner, summary, tracer as tracer_module,
)
from core.services.test_governance.cases import Case
from core.services.test_governance.constants import REPO_ROOT, ArtifactType, CellStatus, Freshness, PylintStatus
from core.services.test_governance.policy import default_policy

POLICY = default_policy()
SUPPORTED_ROW = {"platform": "arista_ceos", "feature": "routing.OSPFV2", "final_status": "SUPPORTED",
                 **{p: "PASS" for p in ("semantic", "field_validation", "renderer", "parser", "validator", "executor", "compensation")}}


def _tmp() -> Path:
    return Path(tempfile.mkdtemp(prefix="tg-units-"))


def _mini_repo() -> Path:
    root = _tmp()
    (root / "web/core/services").mkdir(parents=True)
    (root / "web/core/services/field_validators.py").write_text("def check(value):\n    return bool(value)\n", encoding="utf-8")
    (root / "web/core/migrations").mkdir(parents=True)
    (root / "web/core/migrations/0001_initial.py").write_text("X = 1\n", encoding="utf-8")
    return root


def _signed_report() -> dict:
    data = {"schema_version": 1, "payload_sha256": "", "generated_at": "2026-10-18T00:00:00Z", "summary": {"positive": {"pass": 1}}}
    data["payload_sha256"] = report_module.payload_hash(data)
    return data


# --------------------------------------------------------------------------------------------- cases.py / cells.py
class CaseAndCellHelperTests(SimpleTestCase):
    def test_case_from_dict_round_trips_a_valid_declaration(self):
        item = Case("X_OK", "web/core/views.py::home", "POSITIVE", "valid", "returns 200")
        self.assertEqual(Case.from_dict(item.to_dict()), item)
        self.assertEqual((item.artifact_path, item.symbol), ("web/core/views.py", "web/core/views.py::home"))

    def test_case_decorator_attaches_a_valid_declaration(self):
        from core.services.test_governance.cases import case, declared_on

        decorate = case("X_VALID_DECLARATION", target="web/core/views.py::home", polarity="POSITIVE", condition="valid", expected="returns 200")

        def subject():
            return 7

        self.assertIs(decorate(subject), subject)
        self.assertEqual([c.case_id for c in declared_on(subject)], ["X_VALID_DECLARATION"])
        self.assertEqual(subject(), 7)

    def test_case_from_dict_malformed_values_become_empty_strings_never_raise(self):
        item = Case.from_dict({"case_id": None, "target": 5, "polarity": None})
        self.assertEqual((item.case_id, item.target, item.polarity, item.condition), ("", "5", "", ""))

    def test_cell_key_and_case_id_are_stable_for_a_valid_cell(self):
        cell = cells_module.parse_ledger({"cells": [SUPPORTED_ROW]})[0]
        self.assertEqual(cell.key, "arista_ceos|routing.OSPFV2")
        self.assertEqual(cells_module.cell_case_id("arista_ceos", "routing.OSPFV2", "MODEL", "POSITIVE"),
                         "CELL:arista_ceos:routing.OSPFV2:MODEL:POSITIVE")

    def test_load_cells_accepts_the_repository_ledger(self):
        loaded = cells_module.load_cells()
        self.assertEqual(loaded, cells_module.default_cells())
        self.assertEqual(len(cells_module.supported_cells(loaded)), 68)
        self.assertIn("arista_ceos", cells_module.supported_platforms(loaded))

    def test_load_cells_refuses_a_missing_or_malformed_ledger(self):
        root = _tmp()
        with self.assertRaises(cells_module.LedgerError):
            cells_module.load_cells(root / "absent.json")
        (root / "bad.json").write_text("{not json", encoding="utf-8")
        with self.assertRaises(cells_module.LedgerError):
            cells_module.load_cells(root / "bad.json")

    def test_supported_platforms_is_empty_when_no_cell_is_supported(self):
        rows = cells_module.parse_ledger({"cells": [{**SUPPORTED_ROW, "final_status": "UNSUPPORTED"}]})
        self.assertEqual(cells_module.supported_platforms(rows), frozenset())


# --------------------------------------------------------------------------------------------- coverage_data.py
class CoverageDataHelperTests(SimpleTestCase):
    def test_file_coverage_counts_statements_and_branches(self):
        fc = coverage_data.FileCoverage("a.py", frozenset({1, 2}), frozenset({3}), ((1, 2),), ((1, 3), (2, 4)))
        self.assertEqual((fc.statements, fc.branches), (3, 3))

    def test_compress_returns_ranges_for_valid_line_lists(self):
        self.assertEqual(coverage_data.compress([9, 1, 2, 3, 7, 10]), ["1-3", "7", "9-10"])
        self.assertEqual(coverage_data.pct(1, 3), 33.33)

    def test_compress_empty_and_overflowing_inputs_are_bounded(self):
        self.assertEqual(coverage_data.compress([]), [])
        many = coverage_data.compress(list(range(0, 400, 2)))
        self.assertEqual(len(many), coverage_data.MAX_RANGES + 1)
        self.assertTrue(many[-1].startswith("... "))

    def test_pct_of_zero_total_is_none_not_a_division_error(self):
        self.assertIsNone(coverage_data.pct(0, 0))

    def test_unmeasured_counts_statements_of_a_valid_file_as_uncovered(self):
        root = _mini_repo()
        fc = coverage_data.unmeasured("web/core/services/field_validators.py", root)
        self.assertEqual((fc.measured, fc.error, len(fc.executed)), (False, "", 0))
        self.assertGreater(fc.statements, 0)


# --------------------------------------------------------------------------------------------- evidence.py
class EvidenceHelperTests(SimpleTestCase):
    def test_evidence_dir_returns_the_configured_directory(self):
        with mock.patch.dict("os.environ", {"NMAS_TEST_GOVERNANCE_DIR": "/tmp/tg-x"}), self.settings(NMAS_TEST_GOVERNANCE_DIR=None):
            self.assertEqual(evidence_module.evidence_dir(), Path("/tmp/tg-x"))

    def test_verify_report_accepts_a_signed_report(self):
        data = _signed_report()
        with mock.patch.object(evidence_module.schema, "validate", return_value=[]):
            self.assertEqual(evidence_module.verify_report(json.dumps(data).encode())["payload_sha256"], data["payload_sha256"])
        self.assertEqual(evidence_module.EvidenceError("X_CODE", "detail").code, "X_CODE")

    def test_candidates_returns_accepted_then_bundled_reports(self):
        root = _tmp()
        (root / "accepted").mkdir()
        (root / "accepted/r1.json").write_text("{}", encoding="utf-8")
        (root / "accepted/r1.meta.json").write_text(json.dumps({"source": "tier3", "accepted_at": "t"}), encoding="utf-8")
        bundled = root / "bundled.json"
        bundled.write_text("{}", encoding="utf-8")
        found = evidence_module.candidates(root, bundled=bundled)
        self.assertEqual([(c.path.name, c.source) for c in found], [("r1.json", "tier3"), ("bundled.json", "repository (docs/evidence/lab7)")])

    def test_candidates_skips_corrupt_metadata_and_missing_reports(self):
        root = _tmp()
        (root / "accepted").mkdir()
        (root / "accepted/bad.meta.json").write_text("{corrupt", encoding="utf-8")
        (root / "accepted/orphan.meta.json").write_text("{}", encoding="utf-8")
        self.assertEqual(evidence_module.candidates(root, bundled=root / "absent.json"), [])

    def test_load_verified_returns_a_valid_report_and_caches_it(self):
        path = _tmp() / "r.json"
        path.write_text(json.dumps(_signed_report()), encoding="utf-8")
        with mock.patch.object(evidence_module.schema, "validate", return_value=[]):
            first = evidence_module.load_verified(path)
            self.assertIs(evidence_module.load_verified(path), first)

    def test_load_verified_refuses_a_tampered_report(self):
        data = _signed_report()
        data["summary"]["positive"]["pass"] = 999
        path = _tmp() / "r.json"
        path.write_text(json.dumps(data), encoding="utf-8")
        with mock.patch.object(evidence_module.schema, "validate", return_value=[]), self.assertRaises(evidence_module.EvidenceError):
            evidence_module.load_verified(path)

    def test_deployed_state_returns_sha_and_fingerprint(self):
        repo = _tmp()
        with mock.patch.object(evidence_module.inventory_module, "head_sha", return_value="c" * 40), \
             mock.patch.object(evidence_module.inventory_module, "build_inventory", return_value=None), \
             mock.patch.object(evidence_module.report_module, "evidence_fingerprint", return_value="f" * 64) as fp:
            self.assertEqual(evidence_module.deployed_state(repo, now=1000.0), {"sha": "c" * 40, "fingerprint": "f" * 64})
            evidence_module.deployed_state(repo, now=1001.0)
        self.assertEqual(fp.call_count, 1)   # served from the short cache the second time

    def test_deployed_state_unreadable_checkout_gives_empty_fingerprint_never_raises(self):
        repo = _tmp()
        with mock.patch.object(evidence_module.inventory_module, "head_sha", return_value=""), \
             mock.patch.object(evidence_module.inventory_module, "build_inventory", side_effect=OSError("unreadable")):
            self.assertEqual(evidence_module.deployed_state(repo, now=5.0), {"sha": "", "fingerprint": ""})

    def test_freshness_is_current_for_the_deployed_sha(self):
        state, _reason = evidence_module.freshness({"repository_sha": "a" * 40, "source_fingerprint": "x"}, {"sha": "a" * 40, "fingerprint": "y"})
        self.assertEqual(state, Freshness.CURRENT)


# --------------------------------------------------------------------------------------------- gate.py
class BaselineFileTests(SimpleTestCase):
    def test_write_then_load_baseline_returns_the_same_valid_data(self):
        path = _tmp() / "baseline.json"
        gate.write_baseline({"schema_version": 1, "case_debt": ["A"]}, path)
        self.assertEqual(gate.load_baseline(path), {"schema_version": 1, "case_debt": ["A"]})

    def test_load_baseline_refuses_a_wrong_schema_version(self):
        path = _tmp() / "baseline.json"
        path.write_text(json.dumps({"schema_version": 99}), encoding="utf-8")
        with self.assertRaises(ValueError):
            gate.load_baseline(path)
        self.assertEqual(gate.load_baseline(path.with_name("absent.json")), {})

    def test_write_baseline_fails_for_a_missing_directory(self):
        with self.assertRaises(OSError):
            gate.write_baseline({"schema_version": 1}, _tmp() / "no-such-dir" / "baseline.json")


# --------------------------------------------------------------------------------------------- inventory.py
class InventoryHelperTests(SimpleTestCase):
    def test_artifact_type_and_role_are_returned_for_valid_paths(self):
        self.assertEqual(inventory.artifact_type("templates/R1.cfg.j2"), ArtifactType.JINJA)
        self.assertEqual(inventory.artifact_type("docker/web.Dockerfile"), ArtifactType.DOCKERFILE)
        self.assertEqual(inventory.role_for("web/core/services/field_validators.py"), "backend service")
        self.assertEqual(inventory.artifact_id("PY", "a.py"), "PY:a.py")

    def test_artifact_type_and_role_of_unknown_paths(self):
        self.assertIsNone(inventory.artifact_type("README.txt"))
        self.assertEqual(inventory.role_for("nowhere/unknown.bin"), "repository file")

    def test_is_test_file_accepts_files_under_the_test_roots(self):
        self.assertTrue(inventory.is_test_file("web/core/tests/test_x.py"))

    def test_is_test_file_rejects_source_and_non_python_files(self):
        self.assertFalse(inventory.is_test_file("web/core/views.py"))
        self.assertFalse(inventory.is_test_file("web/core/tests/fixtures/x.json"))

    def test_template_variables_returns_sorted_undeclared_names(self):
        self.assertEqual(inventory.template_variables("{{ b }} {% for i in items %}{{ i }}{% endfor %} {{ a }}"), ("a", "b", "items"))

    def test_template_variables_of_a_malformed_template_is_empty(self):
        self.assertEqual(inventory.template_variables("{% for %}"), ())

    def test_head_sha_returns_the_checkout_commit(self):
        sha = inventory.head_sha(REPO_ROOT)
        self.assertRegex(sha, r"^[0-9a-f]{40}$")

    def test_head_sha_outside_a_git_checkout_is_empty(self):
        self.assertEqual(inventory.head_sha(_tmp()), "")

    def test_list_repository_files_returns_tracked_files(self):
        files = inventory.list_repository_files(REPO_ROOT)
        self.assertIn("web/manage.py", files)
        self.assertNotIn(".git/config", files)

    def test_list_repository_files_without_git_walks_the_tree_but_never_git_metadata(self):
        root = _tmp()
        (root / ".git").mkdir()
        (root / ".git/config").write_text("x", encoding="utf-8")
        (root / "a.py").write_text("x = 1\n", encoding="utf-8")
        self.assertEqual(inventory.list_repository_files(root), ["a.py"])

    def test_inventory_lookup_classification_and_fingerprint_are_consistent(self):
        root = _mini_repo()
        files = ["web/core/services/field_validators.py"]
        inv = inventory.build_inventory(root, files=files, policy=POLICY, cells=())
        artifact = inv.by_id()["PY:web/core/services/field_validators.py"]
        self.assertEqual(artifact.to_dict()["path"], "web/core/services/field_validators.py")
        again = inventory.classify_artifact(artifact.path, artifact.type, policy=POLICY, supported=frozenset(), supported_platforms=frozenset(),
                                            sha256=artifact.sha256)
        self.assertEqual((again.scope, again.group), (artifact.scope, artifact.group))
        before = inventory.fingerprint(inv, root)
        (root / files[0]).write_text("def check(value):\n    return value\n", encoding="utf-8")
        changed = inventory.build_inventory(root, files=files, policy=POLICY, cells=())
        self.assertNotEqual(inventory.fingerprint(changed, root), before)


# --------------------------------------------------------------------------------------------- policy.py
class PolicyLookupTests(SimpleTestCase):
    def test_policy_lookups_return_the_matching_rules(self):
        self.assertIsNotNone(POLICY.excluded("docs/anything.md"))
        self.assertIsNotNone(POLICY.exemption("web/core/migrations/0001_initial.py"))
        self.assertEqual(POLICY.group_for("web/core/services/test_governance/report.py", ()).id, "test_governance")
        self.assertTrue(POLICY.pylint_false_positive("monitoring/scripts/linux_gnmi_server.py", "import-error"))
        self.assertTrue(any(POLICY.external_consumer(r.pattern.replace("**", "x").replace("*", "x")) for r in POLICY.external_consumers))

    def test_policy_lookups_of_unknown_paths_return_no_rule(self):
        self.assertIsNone(POLICY.excluded("web/core/views.py"))
        self.assertIsNone(POLICY.exemption("web/core/views.py"))
        self.assertIsNone(POLICY.external_consumer("web/core/views.py"))
        self.assertEqual(POLICY.pylint_false_positive("web/core/views.py", "import-error"), "")
        self.assertEqual(POLICY.group_for("nowhere/unknown.py", ("no-such-subsystem",)).id, "unclassified")


# --------------------------------------------------------------------------------------------- pylint_data.py
class PylintDataHelperTests(SimpleTestCase):
    def test_is_critical_accepts_errors_and_correctness_symbols(self):
        self.assertTrue(pylint_data.is_critical({"type": "error", "symbol": "no-member"}))
        self.assertTrue(pylint_data.is_critical({"type": "warning", "symbol": "dangerous-default-value"}))

    def test_is_critical_rejects_style_warnings(self):
        self.assertFalse(pylint_data.is_critical({"type": "warning", "symbol": "unused-import"}))
        self.assertFalse(pylint_data.is_critical({}))

    def test_lint_over_the_tracked_baseline_fails(self):
        lint = pylint_data.ArtifactLint("a.py", counts={"unused-import": 2})
        self.assertEqual(lint.over_baseline({"unused-import": 1}), {"unused-import": 1})
        self.assertEqual(lint.status({"unused-import": 1}), PylintStatus.FAIL)
        self.assertEqual(lint.status({"unused-import": 2}), PylintStatus.WARN)
        self.assertEqual(pylint_data.ArtifactLint("b.py", critical=1).status(None), PylintStatus.FAIL)


# --------------------------------------------------------------------------------------------- report.py
class ReportFileTests(SimpleTestCase):
    def test_canonical_excludes_non_canonical_fields(self):
        a = {"x": 1, "generated_at": "t1", "payload_sha256": "h1"}
        b = {"x": 1, "generated_at": "t2", "payload_sha256": "h2"}
        self.assertEqual(report_module.canonical(a), report_module.canonical(b))

    def test_canonical_refuses_values_that_are_not_json(self):
        with self.assertRaises(TypeError):
            report_module.canonical({"x": {1, 2}})

    def test_write_report_then_load_traces_round_trip(self):
        out = _tmp()
        report_module.write_report({"suite": "django", "tests": {"django:t.test_ok": {"outcome": "PASS"}}}, out / "sub" / "trace.json")
        evidence = report_module.load_traces([out / "sub" / "trace.json"])
        self.assertEqual(evidence.tests["django:t.test_ok"]["outcome"], "PASS")
        merged = catalog.Evidence.from_traces([{"suite": "a", "tests": {"t1": {}}}, {"suite": "b", "tests": {"t2": {}}}])
        self.assertEqual(sorted(merged.tests), ["t1", "t2"])

    def test_load_traces_refuses_a_malformed_trace_file(self):
        path = _tmp() / "trace.json"
        path.write_text("{broken", encoding="utf-8")
        with self.assertRaises(ValueError):
            report_module.load_traces([path])
        self.assertEqual(catalog.Evidence.from_traces([{"suite": "x", "tests": None}]).tests, {})

    def test_write_report_onto_a_directory_fails(self):
        target = _tmp() / "is-a-dir"
        target.mkdir()
        with self.assertRaises(OSError):
            report_module.write_report({"x": 1}, target)

    def test_assemble_builds_a_report_from_files_on_disk(self):
        repo = _mini_repo()
        trace = repo / "trace.json"
        trace.write_text(json.dumps({"suite": "django", "tests": {"django:t.test_ok": {"outcome": "PASS", "links": {}, "declared": []}}}),
                         encoding="utf-8")
        data = report_module.assemble(trace_paths=[trace], coverage_json=None, pylint_json=None, baseline={}, repo=repo,
                                      provenance={"repository_sha": "a" * 40})
        self.assertIn("PY:web/core/services/field_validators.py", {a["id"] for a in data["artifacts"]})
        self.assertEqual(data["summary"]["tests"]["total"], 1)
        self.assertRegex(report_module.evidence_fingerprint(inventory.build_inventory(repo), repo), r"^[0-9a-f]{64}$")

    def test_assemble_refuses_malformed_coverage_data(self):
        repo = _mini_repo()
        bad = repo / "coverage.json"
        bad.write_text(json.dumps({"meta": {}}), encoding="utf-8")
        with self.assertRaises(coverage_data.CoverageDataError):
            report_module.assemble(trace_paths=[], coverage_json=bad, pylint_json=None, baseline={}, repo=repo,
                                   provenance={"repository_sha": "a" * 40})

    def test_evidence_fingerprint_missing_config_files_are_skipped_without_error(self):
        repo = _mini_repo()
        inv = inventory.build_inventory(repo)
        self.assertEqual(report_module.evidence_fingerprint(inv, repo), report_module.evidence_fingerprint(inv, repo))


# --------------------------------------------------------------------------------------------- runner.py
class RunnerHelperTests(SimpleTestCase):
    def test_child_env_passes_only_safe_keys_plus_requested_extras(self):
        with mock.patch.dict("os.environ", {"PATH": "/usr/bin"}, clear=False):
            env = runner.child_env({"NMAS_TG_REPO": "/r"})
        self.assertEqual((env["PATH"], env["NMAS_TG_REPO"], env["DJANGO_DEBUG"]), ("/usr/bin", "/r", "true"))

    def test_child_env_never_forwards_secrets(self):
        with mock.patch.dict("os.environ", {"NMAS_GITHUB_TOKEN": "ghp_secret", "AWS_SECRET_ACCESS_KEY": "x", "DATABASE_URL": "y"}):
            env = runner.child_env()
        self.assertFalse({"NMAS_GITHUB_TOKEN", "AWS_SECRET_ACCESS_KEY", "DATABASE_URL"} & set(env))
        self.assertNotIn("ghp_secret", json.dumps(env))

    def test_provenance_from_env_returns_github_run_facts(self):
        prov = runner.provenance_from_env({"GITHUB_RUN_ID": "42", "GITHUB_SHA": "a" * 40, "GITHUB_REPOSITORY": "o/r"})
        self.assertEqual((prov["run_id"], prov["sha"], prov["repository"]), ("42", "a" * 40, "o/r"))

    def test_provenance_from_env_never_copies_tokens_and_bounds_values(self):
        prov = runner.provenance_from_env({"GITHUB_TOKEN": "ghs_secret", "GITHUB_REF_NAME": "x" * 500})
        self.assertNotIn("token", prov)
        self.assertNotIn("ghs_secret", json.dumps(prov))
        self.assertEqual(len(prov["ref_name"]), 200)

    def test_suite_commands_returns_the_two_traced_suites(self):
        out = _tmp()
        commands = runner.suite_commands(out, python="/py", labels=("core",), repo=Path("/repo"))
        self.assertEqual([c[0] for c in commands], ["django.tests", "monitoring.unit"])
        self.assertEqual(commands[0][1][:3], ["/py", "-m", "coverage"])
        self.assertEqual(commands[0][3]["NMAS_TG_TRACE_OUT"], str(out / "django-trace.json"))

    def test_suite_commands_keep_an_unsafe_label_as_one_argument_never_a_shell_string(self):
        commands = runner.suite_commands(_tmp(), python="/py", labels=("core; rm -rf /",), repo=Path("/repo"))
        self.assertIn("core; rm -rf /", commands[0][1])
        self.assertTrue(all(isinstance(arg, str) for arg in commands[0][1]))

    def test_lint_paths_returns_python_artifacts(self):
        self.assertIn("web/core/services/field_validators.py", runner.lint_paths(_mini_repo()))

    def test_lint_paths_never_lints_exempt_artifacts(self):
        self.assertNotIn("web/core/migrations/0001_initial.py", runner.lint_paths(_mini_repo()))

    def test_run_pylint_records_the_linted_paths(self):
        out = _tmp()
        with mock.patch.object(runner, "_run", return_value=runner.StepResult("pylint", 0)) as run:
            result = runner.run_pylint(out, python="/py", paths=["a.py"], repo=Path("/repo"))
        self.assertEqual(result.returncode, 0)
        self.assertIn("--output-format=json2", run.call_args.args[1])
        self.assertEqual(json.loads((out / "pylint-paths.json").read_text()), ["a.py"])

    def test_run_pylint_with_a_missing_interpreter_fails_as_a_step_not_an_exception(self):
        result = runner.run_pylint(_tmp(), python="/nonexistent/python", paths=["a.py"], repo=Path("/repo"))
        self.assertIsNone(result.returncode)
        self.assertIn("could not start", result.tail)

    def test_combine_coverage_runs_combine_json_and_xml_on_existing_parts(self):
        out = _tmp()
        (out / ".coverage.django").write_text("", encoding="utf-8")
        with mock.patch.object(runner, "_run", side_effect=lambda name, argv, **kw: runner.StepResult(name, 0, " ".join(argv))) as run:
            steps = runner.combine_coverage(out, python="/py", repo=Path("/repo"))
        self.assertEqual([s.name for s in steps], ["coverage.combine", "coverage.json", "coverage.xml"])
        self.assertIn(str(out / ".coverage.django"), run.call_args_list[0].args[1])
        self.assertNotIn(str(out / ".coverage.monitoring"), run.call_args_list[0].args[1])

    def test_combine_coverage_with_a_missing_interpreter_or_no_data_reports_failed_steps(self):
        out = _tmp()
        (out / ".coverage.django").write_text("", encoding="utf-8")
        steps = runner.combine_coverage(out, python="/nonexistent/python", repo=Path("/repo"))
        self.assertEqual([s.returncode for s in steps], [None, None, None])
        with mock.patch.object(runner, "_run", side_effect=lambda name, argv, **kw: runner.StepResult(name, 0)):
            empty = runner.combine_coverage(_tmp(), python="/py", repo=Path("/repo"))
        self.assertEqual((empty[0].name, empty[0].returncode), ("coverage.combine", 1))

    def test_combine_coverage_reuses_already_combined_data(self):
        out = _tmp()
        (out / ".coverage").write_text("", encoding="utf-8")
        with mock.patch.object(runner, "_run", side_effect=lambda name, argv, **kw: runner.StepResult(name, 0)) as run:
            steps = runner.combine_coverage(out, python="/py", repo=Path("/repo"))
        self.assertEqual([(s.name, s.returncode) for s in steps], [("coverage.combine", 0), ("coverage.json", 0), ("coverage.xml", 0)])
        self.assertEqual([c.args[0] for c in run.call_args_list], ["coverage.json", "coverage.xml"])

    def test_run_evidence_returns_every_step_and_its_traces(self):
        out = _tmp()
        (out / "django-trace.json").write_text("{}", encoding="utf-8")
        with mock.patch.object(runner, "_run", side_effect=lambda name, argv, **kw: runner.StepResult(name, 0)):
            run = runner.run_evidence(out, python="/py", repo=_mini_repo())
        self.assertEqual([s.name for s in run.steps], ["django.tests", "monitoring.unit", "coverage.combine", "coverage.json", "coverage.xml", "pylint"])
        self.assertEqual(run.traces, [out.resolve() / "django-trace.json"])

    def test_run_evidence_with_a_missing_interpreter_fails_every_step_without_raising(self):
        run = runner.run_evidence(_tmp(), python="/nonexistent/python", repo=_mini_repo(), skip_pylint=True)
        self.assertTrue(run.steps)
        self.assertTrue(all(step.returncode != 0 for step in run.steps))   # could not start (None) or no data (1); never success

    def test_build_and_gate_writes_a_schema_valid_gated_report(self):
        repo, out = _mini_repo(), _tmp()
        (out / "django-trace.json").write_text(json.dumps({"suite": "django", "tests": {}}), encoding="utf-8")
        data = runner.build_and_gate(out, baseline={}, repo=repo, mode="full", env={"GITHUB_RUN_ID": "7"})
        self.assertEqual((data["provenance"]["mode"], data["provenance"]["run_id"]), ("full", "7"))
        self.assertIn(data["gate"]["result"], ("PASS", "PASS_WITH_DEBT", "FAIL"))
        self.assertTrue((out / "test-governance-report.json").is_file())

    def test_build_and_gate_refuses_a_malformed_trace(self):
        repo, out = _mini_repo(), _tmp()
        (out / "django-trace.json").write_text("{broken", encoding="utf-8")
        with self.assertRaises(ValueError):
            runner.build_and_gate(out, baseline={}, repo=repo)


# --------------------------------------------------------------------------------------------- github_evidence.py
class GitHubEvidenceHelperTests(SimpleTestCase):
    @staticmethod
    def _zip(members: dict) -> bytes:
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as zf:
            for name, data in members.items():
                zf.writestr(name, data)
        return buffer.getvalue()

    def test_extract_report_returns_the_report_member(self):
        self.assertEqual(github_evidence.extract_report(self._zip({"test-governance-report.json": b"{}"})), b"{}")

    def test_extract_report_refuses_archives_without_a_report_or_corrupt(self):
        for label, archive in (("missing member", self._zip({"other.txt": b"x"})), ("corrupt zip", b"not a zip")):
            with self.subTest(case=f"invalid {label}"), self.assertRaises(evidence_module.EvidenceError) as caught:
                github_evidence.extract_report(archive)
            self.assertEqual(caught.exception.code, github_evidence.NO_ARTIFACT)
        with self.assertRaises(evidence_module.EvidenceError):
            github_evidence.extract_report(b"x" * (github_evidence.MAX_ZIP_BYTES + 1))

    def test_runs_for_returns_runs_of_the_requested_commit(self):
        sha = "a" * 40
        with mock.patch.object(github_evidence.github, "_call", return_value={"workflow_runs": [{"id": 1, "head_sha": sha}]}):
            self.assertEqual(github_evidence.runs_for(sha), [{"id": 1, "head_sha": sha}])

    def test_runs_for_rejects_runs_of_another_commit_and_malformed_rows(self):
        sha = "a" * 40
        rows = [{"id": 1, "head_sha": "b" * 40}, "garbage", None, {"id": 2}]
        with mock.patch.object(github_evidence.github, "_call", return_value={"workflow_runs": rows}):
            self.assertEqual(github_evidence.runs_for(sha), [])
        with mock.patch.object(github_evidence.github, "_call", return_value={}):
            self.assertEqual(github_evidence.runs_for(sha), [])

    def test_redirect_request_hands_the_redirect_back_to_the_caller(self):
        handler = github_evidence._NoRedirect()
        self.assertIsNone(handler.redirect_request(mock.Mock(), None, 302, "Found", {}, "https://storage.example/x"))

    def test_redirect_request_never_follows_even_an_https_location_with_the_token(self):
        request = mock.Mock(headers={"Authorization": "Bearer ghp_secret"})
        self.assertIsNone(github_evidence._NoRedirect().redirect_request(request, None, 307, "Temporary", {}, "https://evil.example/"))


# --------------------------------------------------------------------------------------------- catalog_check.py
class CatalogCheckHelperTests(SimpleTestCase):
    def test_generated_requirements_returns_template_config_and_cell_cases(self):
        root = _tmp()
        (root / "templates").mkdir()
        (root / "templates/R1.cfg.j2").write_text("hostname {{ name }}\n", encoding="utf-8")
        (root / "inventory.yml").write_text("R1: {template: R1.cfg.j2}\n", encoding="utf-8")
        inv = inventory.build_inventory(root, files=["templates/R1.cfg.j2", "inventory.yml"], policy=POLICY, cells=())
        rows = cells_module.parse_ledger({"cells": [SUPPORTED_ROW]})
        required = catalog_check.generated_requirements(inv, rows, POLICY)
        self.assertIn("TPL:templates/R1.cfg.j2:RENDER:POSITIVE", required)
        self.assertIn("TPL:templates/R1.cfg.j2:STRICT_UNDEFINED:NEGATIVE", required)
        self.assertIn("CELL:arista_ceos:routing.OSPFV2:MODEL:NEGATIVE", required)

    def test_generated_requirements_never_include_unsupported_cells_or_out_of_scope_files(self):
        root = _tmp()
        (root / "docs").mkdir()
        (root / "docs/x.yml").write_text("a: 1\n", encoding="utf-8")
        inv = inventory.build_inventory(root, files=["docs/x.yml"], policy=POLICY, cells=())
        rows = cells_module.parse_ledger({"cells": [{**SUPPORTED_ROW, "final_status": "NOT_IMPLEMENTED"}]})
        self.assertEqual(catalog_check.generated_requirements(inv, rows, POLICY), set())

    def test_collect_declared_returns_the_declared_cases_of_a_test_module(self):
        found = catalog_check.collect_declared(("core.tests.test_tg_field_validators",))
        ids = {item.case_id for _tid, item in found}
        self.assertIn("F1_DESCRIPTION_LINE_BREAK_REFUSED_AT_TIER1", ids)
        self.assertEqual(len(found), len({(tid, item.case_id) for tid, item in found}))   # no duplicates

    def test_collect_declared_of_a_module_without_declarations_is_empty(self):
        self.assertEqual(catalog_check.collect_declared(("core.tests.test_tier3_selection",)), [])

    def test_validate_catalog_reports_broken_targets_and_unknown_cells(self):
        bad = [("t.test_x", Case("X_BROKEN", "web/core/nowhere.py::f", "POSITIVE", "c", "e")),
               ("t.test_y", Case("Y_CELL", "web/core/views.py", "NEGATIVE", "c", "e", platform="junos", feature="routing.OSPFV2"))]
        result = catalog_check.validate_catalog(declared=bad, baseline={})
        self.assertTrue(any(e.startswith("BROKEN_TARGET X_BROKEN") for e in result["errors"]))
        self.assertTrue(any(e.startswith("UNKNOWN_CELL Y_CELL") for e in result["errors"]))


# --------------------------------------------------------------------------------------------- summary.py
class SummaryFigureTests(SimpleTestCase):
    def test_figures_returns_zero_totals_for_an_empty_report(self):
        empty = {"artifacts": [], "cases": [], "cells": [], "groups": [], "summary": {"pylint": {"status": "PASS", "critical": 0, "messages": 0},
                                                                                     "tests": {"total": 0}}}
        f = summary.figures(empty)
        self.assertEqual((f["functions"], f["lines"], f["cells"]), ((0, 0), (0, 0), (0, 0)))

    def test_results_markdown_refuses_a_report_without_required_sections(self):
        with self.assertRaises(KeyError):
            summary.results_markdown({"artifacts": []})


# --------------------------------------------------------------------------------------------- bundled evidence files
class BundledEvidenceTests(SimpleTestCase):
    def test_the_bundled_baseline_report_verifies(self):
        path = REPO_ROOT / "docs/evidence/lab7/baseline-report.json.gz"
        if not path.is_file():
            self.skipTest("baseline report not bundled in this checkout")
        data = evidence_module.verify_report(gzip.decompress(path.read_bytes()))
        self.assertEqual(data["repository_sha"], "18d7972ab2d3d0f3263054060d0d1fdbb0e71d42")
        self.assertEqual(summary.figures(data, exclude_groups=("test_governance",))["cells"][0], 0)
        self.assertNotIn(CellStatus.CLOSED, {c["status"] for c in data["cells"]})


# --------------------------------------------------------------------------------------------- management command
class ManagementCommandTests(SimpleTestCase):
    """Each subcommand handler called directly: valid arguments print the result; invalid input / refused evidence /
    a failing gate exits non-zero or raises CommandError (never a silent success)."""

    def setUp(self):
        from core.management.commands import nmas_test_governance as module

        self.module = module
        self.out, self.err = io.StringIO(), io.StringIO()
        self.cmd = module.Command(stdout=self.out, stderr=self.err)

    def test_add_arguments_accepts_every_subcommand(self):
        import argparse

        parser = argparse.ArgumentParser()
        self.cmd.add_arguments(parser)
        for argv in (["inventory", "--json"], ["validate-catalog", "--ci"], ["run", "--out", "x"], ["report", "--dir", "x"], ["pylint"],
                     ["status"], ["accept", "r.json"], ["baseline", "--from", "r.json"], ["refresh"], ["summarize", "r.json", "--gap"]):
            self.assertEqual(parser.parse_args(argv).action, argv[0])

    def test_handle_dispatches_a_valid_action(self):
        with mock.patch.object(self.module.Command, "do_status") as status:
            self.cmd.handle(action="status", json=True)
        status.assert_called_once_with(action="status", json=True)

    def test_handle_refuses_an_unknown_action(self):
        with self.assertRaises(AttributeError):
            self.cmd.handle(action="drop-database")

    def test_do_inventory_prints_artifacts_and_symbols(self):
        repo = _mini_repo()
        inv = inventory.build_inventory(repo, files=["web/core/services/field_validators.py"], policy=POLICY, cells=())
        with mock.patch.object(self.module.inventory, "build_inventory", return_value=inv), \
             mock.patch.object(self.module.symbols, "inventory_symbols", return_value={}):
            self.cmd.do_inventory(json=False, scope="all")
            self.cmd.do_inventory(json=True, scope="current")
        self.assertIn("deployed artifacts: 1", self.out.getvalue())
        self.assertIn('"path": "web/core/services/field_validators.py"', self.out.getvalue())

    def test_do_inventory_prints_inventory_errors(self):
        broken = inventory.Inventory([], [], ["UNCLASSIFIED_ARTIFACT PY:x.py: no rule"])
        with mock.patch.object(self.module.inventory, "build_inventory", return_value=broken), \
             mock.patch.object(self.module.symbols, "inventory_symbols", return_value={}):
            self.cmd.do_inventory(json=False, scope="all")
        self.assertIn("ERROR UNCLASSIFIED_ARTIFACT", self.out.getvalue())

    def test_do_validate_catalog_prints_a_valid_catalog(self):
        ok = {"errors": [], "warnings": ["w"], "artifacts": 3, "symbols": 9, "declared": 2}
        with mock.patch.object(self.module.catalog_check, "validate_catalog", return_value=ok):
            self.cmd.do_validate_catalog(ci=True)
        self.assertIn("catalog: 3 artifacts, 9 symbols, 2 declared case(s), 0 error(s)", self.out.getvalue())

    def test_do_validate_catalog_with_errors_fails_in_ci(self):
        bad = {"errors": ["BROKEN_TARGET X"], "warnings": [], "artifacts": 0, "symbols": 0, "declared": 1}
        with mock.patch.object(self.module.catalog_check, "validate_catalog", return_value=bad), self.assertRaises(SystemExit) as caught:
            self.cmd.do_validate_catalog(ci=True, json=True)
        self.assertEqual(caught.exception.code, 1)

    def test_do_run_prints_the_gated_summary(self):
        run = runner.EvidenceRun(_tmp(), [runner.StepResult("django.tests", 0)])
        with mock.patch.object(self.module.runner, "run_evidence", return_value=run), \
             mock.patch.object(self.module.runner, "build_and_gate", return_value={"gate": {"result": "PASS"}}), \
             mock.patch.object(self.module.gate, "load_baseline", return_value={}), \
             mock.patch.object(self.module.Command, "_print_summary") as printed:
            self.cmd.do_run(out=str(_tmp()), labels=["core"], ci=True)
        printed.assert_called_once()
        self.assertIn("django.tests: exit 0", self.err.getvalue())

    def test_do_run_with_a_failing_gate_fails_in_ci(self):
        run = runner.EvidenceRun(_tmp(), [])
        with mock.patch.object(self.module.runner, "run_evidence", return_value=run), \
             mock.patch.object(self.module.runner, "build_and_gate", return_value={"gate": {"result": gate.FAIL}}), \
             mock.patch.object(self.module.gate, "load_baseline", return_value={}), \
             mock.patch.object(self.module.Command, "_print_summary"), self.assertRaises(SystemExit):
            self.cmd.do_run(out=str(_tmp()), labels=["core"], ci=True)

    def test_do_report_assembles_from_traced_output(self):
        target = _tmp()
        (target / "django-trace.json").write_text("{}", encoding="utf-8")
        (target / "pylint.json").write_text("{}", encoding="utf-8")
        with mock.patch.object(self.module.runner, "combine_coverage", return_value=[runner.StepResult("coverage.combine", 0)]), \
             mock.patch.object(self.module.runner, "build_and_gate", return_value={"gate": {"result": "PASS_WITH_DEBT"}}) as built, \
             mock.patch.object(self.module.gate, "load_baseline", return_value={}), mock.patch.object(self.module.Command, "_print_summary"):
            self.cmd.do_report(dir=str(target), ci=True, mode="full")
        self.assertEqual(built.call_args.kwargs["mode"], "full")

    def test_do_report_refuses_a_directory_without_traced_suites(self):
        from django.core.management.base import CommandError

        with self.assertRaises(CommandError):
            self.cmd.do_report(dir=str(_tmp()))
        target = _tmp()
        (target / "django-trace.json").write_text("{}", encoding="utf-8")
        with mock.patch.object(self.module.runner, "combine_coverage", return_value=[runner.StepResult("coverage.combine", 1, "boom")]), \
             self.assertRaises(SystemExit) as caught:
            self.cmd.do_report(dir=str(target))
        self.assertEqual(caught.exception.code, 3)

    def test_do_pylint_prints_counts_for_deployed_files(self):
        repo, out = _mini_repo(), _tmp()
        inv = inventory.build_inventory(repo, files=["web/core/services/field_validators.py"], policy=POLICY, cells=())

        def fake_run(target, *, python, paths):
            (target / "pylint.json").write_text(json.dumps({"messages": [], "statistics": {}}), encoding="utf-8")
            return runner.StepResult("pylint", 0)

        with mock.patch.object(self.module.inventory, "build_inventory", return_value=inv), \
             mock.patch.object(self.module.runner, "run_pylint", side_effect=fake_run), \
             mock.patch.object(self.module.gate, "load_baseline", return_value={}):
            self.cmd.do_pylint(paths=None, ci=True, out=str(out))
        self.assertIn("pylint: 1 file(s); 0 critical", self.out.getvalue())

    def test_do_pylint_refuses_paths_outside_the_deployed_scope(self):
        from django.core.management.base import CommandError

        repo = _mini_repo()
        inv = inventory.build_inventory(repo, files=["web/core/services/field_validators.py"], policy=POLICY, cells=())
        with mock.patch.object(self.module.inventory, "build_inventory", return_value=inv):
            self.cmd.do_pylint(paths=["/etc/passwd"], out=str(_tmp()))
            self.assertIn("no deployed Python artifact in scope", self.out.getvalue())
            with mock.patch.object(self.module.runner, "run_pylint", return_value=runner.StepResult("pylint", None, "could not start")), \
                 self.assertRaises(CommandError):
                self.cmd.do_pylint(paths=None, out=str(_tmp()))

    def test_do_status_prints_the_selected_evidence(self):
        chosen = {"report": {"repository_sha": "a" * 40, "generated_at": "t", "payload_sha256": "h", "summary": {}, "gate": {"result": "PASS"}},
                  "freshness": "CURRENT", "reason": "same commit", "deployed": {"sha": "a" * 40}, "source": "repository"}
        with mock.patch.object(self.module.evidence, "select", return_value=chosen):
            self.cmd.do_status(json=True)
        self.assertEqual(json.loads(self.out.getvalue())["freshness"], "CURRENT")

    def test_do_status_without_evidence_says_so(self):
        chosen = {"report": None, "freshness": "NONE", "reason": "no verified evidence", "deployed": {"sha": "a" * 40}, "source": ""}
        with mock.patch.object(self.module.evidence, "select", return_value=chosen):
            self.cmd.do_status(json=False)
        self.assertIn("evidence: NONE -- no verified evidence", self.out.getvalue())

    def test_do_accept_stores_a_verified_report(self):
        path = _tmp() / "r.json"
        path.write_text("{}", encoding="utf-8")
        with mock.patch.object(self.module.evidence, "accept", return_value={"payload_sha256": "h" * 64, "repository_sha": "a" * 40}) as accepted:
            self.cmd.do_accept(report=str(path))
        self.assertIn("accepted " + "h" * 64, self.out.getvalue())
        self.assertIn("local evidence run", accepted.call_args.kwargs["source"])

    def test_do_accept_refuses_unverifiable_evidence(self):
        from django.core.management.base import CommandError

        path = _tmp() / "r.json"
        path.write_text("{not json", encoding="utf-8")
        with self.assertRaises(CommandError) as caught:
            self.cmd.do_accept(report=str(path))
        self.assertIn("refused", str(caught.exception))

    def test_do_baseline_derives_the_ratchet_without_writing_by_default(self):
        report = {"repository_sha": "a" * 40, "payload_sha256": "h", "cases": [], "artifacts": [], "cells": []}
        path = _tmp() / "r.json"
        path.write_text("{}", encoding="utf-8")
        with mock.patch.object(self.module.evidence, "verify_report", return_value=report), \
             mock.patch.object(self.module.gate, "write_baseline") as written:
            self.cmd.do_baseline(source=str(path), write=False)
        written.assert_not_called()
        self.assertIn("0 debt case(s)", self.out.getvalue())

    def test_do_baseline_refuses_a_tampered_report(self):
        data = _signed_report()
        data["summary"]["positive"]["pass"] = 7
        path = _tmp() / "r.json"
        path.write_text(json.dumps(data), encoding="utf-8")
        with mock.patch.object(self.module.gate, "write_baseline") as written, self.assertRaises(evidence_module.EvidenceError):
            self.cmd.do_baseline(source=str(path), write=True)
        written.assert_not_called()

    def test_do_refresh_reports_the_accepted_run(self):
        meta = {"run_id": 9, "conclusion": "success", "payload_sha256": "f" * 64}
        with mock.patch.object(self.module.evidence, "deployed_state", return_value={"sha": "a" * 40}), \
             mock.patch("core.services.test_governance.github_evidence.refresh", return_value=meta):
            self.cmd.do_refresh()
        self.assertIn("accepted Tier-3 run 9 (success)", self.out.getvalue())

    def test_do_refresh_refused_evidence_raises_command_error(self):
        from django.core.management.base import CommandError

        with mock.patch.object(self.module.evidence, "deployed_state", return_value={"sha": "a" * 40}), \
             mock.patch("core.services.test_governance.github_evidence.refresh",
                        side_effect=evidence_module.EvidenceError("EVIDENCE_HASH_MISMATCH")), self.assertRaises(CommandError):
            self.cmd.do_refresh()

    def test_do_summarize_renders_the_bundled_baseline(self):
        path = REPO_ROOT / "docs/evidence/lab7/baseline-report.json.gz"
        if not path.is_file():
            self.skipTest("baseline report not bundled in this checkout")
        self.cmd.do_summarize(report=str(path), gap=True)
        self.assertIn("# Lab 7 baseline gap assessment", self.out.getvalue())

    def test_do_summarize_refuses_a_tampered_report(self):
        data = _signed_report()
        data["summary"]["positive"]["pass"] = 3
        path = _tmp() / "r.json.gz"
        path.write_bytes(gzip.compress(json.dumps(data).encode()))
        with self.assertRaises(evidence_module.EvidenceError):
            self.cmd.do_summarize(report=str(path))


# --------------------------------------------------------------------------------------------- presentation.py
class PresentationModelTests(SimpleTestCase):
    """Page models built from one fixture report: valid ids / filters give the expected rows; unknown ids, hostile filter
    values and absent evidence give an explicit empty / None model (the view turns None into 404)."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        from core.tests.test_test_governance import SERVICE, SOURCE, SYM, _report, ledger, trace

        cls.service, cls.sym = SERVICE, SYM
        cls.report = _report({SERVICE: SOURCE, "templates/R1.cfg.j2": "x\n"},
                             trace(**{"django:t.test_accepts_valid_port": ("PASS", {SYM: [1, 0, 0, 0]}, ())}),
                             cell_rows=ledger(("arista_ceos", "routing.OSPFV2", "SUPPORTED"), ("sonic", "routing.OSPFV2", "NOT_IMPLEMENTED")))
        cls.selected = {"report": cls.report, "deployed": {"sha": "a" * 40, "fingerprint": "b" * 64}, "freshness": "CURRENT",
                        "reason": "same commit", "source": "repository"}

    def _p(self):
        from core.services.test_governance import presentation

        return presentation

    def test_badge_and_pct_return_values_for_known_states(self):
        p = self._p()
        self.assertEqual((p.badge("PASS"), p.badge("CLOSED_CURRENT_SCOPE")), ("success", "success"))
        self.assertEqual(p.pct(1, 4), 25.0)

    def test_badge_and_pct_of_unknown_or_zero_input(self):
        p = self._p()
        self.assertEqual(p.badge("<script>"), "neutral")
        self.assertIsNone(p.pct(3, 0))

    def test_header_returns_tested_and_deployed_sha(self):
        head = self._p().header(self.selected)
        self.assertEqual((head["tested_sha"], head["deployed_sha"], head["freshness_badge"], head["fingerprint_match"]),
                         ("a" * 40, "a" * 40, "success", True))

    def test_header_without_evidence_has_no_match_and_no_run_link(self):
        head = self._p().header({})
        self.assertEqual((head["freshness"], head["fingerprint_match"], head["run_url"]), (Freshness.NONE, False, ""))

    def test_refresh_message_returns_the_text_of_a_known_outcome(self):
        self.assertIn("verified and accepted", self._p().refresh_message("ACCEPTED"))

    def test_refresh_message_of_unknown_or_oversized_codes_is_generic_and_bounded(self):
        p = self._p()
        self.assertEqual(p.refresh_message(""), "")
        text = p.refresh_message("X" * 500)
        self.assertIn("no newer evidence accepted", text)
        self.assertLess(len(text), 200)

    def test_summary_cards_returns_percentages(self):
        cards = self._p().summary_cards(self.report)
        self.assertEqual(cards["positive"]["pct"], self._p().pct(cards["positive"]["pass"], cards["positive"]["required"]))
        self.assertIn("debt", cards)

    def test_summary_cards_refuses_a_report_without_a_summary(self):
        with self.assertRaises(KeyError):
            self._p().summary_cards({})

    def test_case_view_returns_generic_wording_and_test_rows(self):
        item = next(c for c in self.report["cases"] if c["symbol"] == self.sym and c["polarity"] == "POSITIVE")
        view = self._p().case_view(self.report, item)
        self.assertTrue(view["title"].startswith("validate_port() accepts "))
        self.assertEqual(view["tests"][0]["id"], "django:t.test_accepts_valid_port")

    def test_case_view_drops_out_of_range_evidence_and_labels_exempt_cases(self):
        item = {"id": "SYM:x::f:EXEMPT", "kind": "SYMBOL", "symbol": "x::f", "state": "EXEMPT", "polarity": "POSITIVE",
                "evidence": [[999, "DIRECT_RETURN"], [-1, "DIRECT_RETURN"]]}
        view = self._p().case_view(self.report, item)
        self.assertEqual((view["title"], view["tests"]), ("f() -- exempt", []))

    def test_filter_options_returns_the_report_dimensions(self):
        options = self._p().filter_options(self.report)
        self.assertIn("PY", options["types"])
        self.assertIn("CLOSED_CURRENT_SCOPE", options["statuses"])

    def test_filter_options_of_an_empty_report_are_empty(self):
        options = self._p().filter_options({"artifacts": []})
        self.assertEqual((options["types"], options["platforms"], options["groups"]), ([], [], []))

    def test_clean_filters_accepts_known_filters(self):
        self.assertEqual(self._p().clean_filters({"type": "PY", "scope": "all"}), {"type": "PY", "scope": "all"})

    def test_clean_filters_drops_unknown_keys_and_invalid_scope_and_bounds_values(self):
        cleaned = self._p().clean_filters({"evil": "1", "scope": "everything", "q": "x" * 500})
        self.assertEqual((sorted(cleaned), cleaned["scope"], len(cleaned["q"])), (["q", "scope"], "current", 120))

    def test_unit_matrix_returns_rows_for_matching_artifacts(self):
        page = self._p().unit_matrix(self.selected, {"type": "PY"})
        self.assertEqual([r["artifact"]["path"] for r in page["rows"]], [self.service])
        self.assertTrue(page["report"])

    def test_unit_matrix_without_evidence_or_with_no_match_has_no_rows(self):
        p = self._p()
        self.assertNotIn("rows", p.unit_matrix({}, {}))
        self.assertEqual(p.unit_matrix(self.selected, {"q": "no-such-file"})["rows"], [])

    def test_examples_returns_badges_for_each_target(self):
        report = {"examples": [{"requirement": "R", "targets": [{"target": "a::f", "states": {"POSITIVE": "PASS", "NEGATIVE": "MISSING"}}]}]}
        target = self._p().examples(report)[0]["targets"][0]
        self.assertEqual((target["positive_badge"], target["negative_badge"]), ("success", "warning"))

    def test_examples_of_a_report_without_examples_is_empty(self):
        self.assertEqual(self._p().examples({}), [])

    def test_artifact_detail_returns_symbols_and_cases(self):
        detail = self._p().artifact_detail(self.selected, f"PY:{self.service}")
        self.assertTrue(detail["is_python"])
        self.assertIn(self.sym, [s["id"] for s in detail["symbols"]])

    def test_artifact_detail_of_unknown_id_or_absent_evidence_is_none(self):
        p = self._p()
        self.assertIsNone(p.artifact_detail(self.selected, "PY:../../etc/passwd"))
        self.assertIsNone(p.artifact_detail({}, f"PY:{self.service}"))

    def test_coverage_matrix_returns_supported_feature_rows(self):
        page = self._p().coverage_matrix(self.selected)
        self.assertEqual([r["feature"] for r in page["rows"]], ["routing.OSPFV2"])
        self.assertEqual(page["platforms"], ["arista_ceos", "sonic"])

    def test_coverage_matrix_without_evidence_has_no_grid(self):
        page = self._p().coverage_matrix({}, show_all=True)
        self.assertEqual((page["report"], "rows" in page), (False, False))

    def test_cell_detail_returns_stages_for_a_supported_cell(self):
        detail = self._p().cell_detail(self.selected, "arista_ceos", "routing.OSPFV2")
        self.assertEqual(detail["cell"]["status"], CellStatus.MISSING)
        self.assertTrue(all(s["implemented"] for s in detail["stages"]))

    def test_cell_detail_of_unknown_cell_or_absent_evidence_is_none(self):
        p = self._p()
        self.assertIsNone(p.cell_detail(self.selected, "junos", "routing.OSPFV2"))
        self.assertIsNone(p.cell_detail({}, "arista_ceos", "routing.OSPFV2"))


# --------------------------------------------------------------------------------------------- tracer / session / symbols
class TracerHelperTests(SimpleTestCase):
    def _tracer(self):
        from core.services.test_governance.tracer import DirectCallTracer

        return DirectCallTracer(REPO_ROOT, {}, test_roots=("web/core/tests",), suite="django", tool_id=2,
                                negative_words=frozenset({"refuses"}), positive_words=frozenset({"accepts"}))

    def test_intent_and_test_id_are_derived_from_valid_names(self):
        tracer = self._tracer()
        self.assertEqual((tracer.intent_of("test_accepts_value"), tracer.intent_of("test_refuses_value")), (tracer_module.POSITIVE_INTENT, tracer_module.NEGATIVE_INTENT))
        self.assertEqual(tracer.test_id(mock.Mock(id=lambda: "web.core.tests.test_x.T.test_a")), "django:core.tests.test_x.T.test_a")

    def test_intent_of_unknown_or_conflicting_wording_is_mixed(self):
        tracer = self._tracer()
        self.assertEqual(tracer.intent_of("test_something"), tracer_module.MIXED)
        self.assertEqual(tracer.intent_of("accepts then refuses"), tracer_module.MIXED)

    def test_dump_writes_the_trace_file(self):
        tracer = self._tracer()
        path = _tmp() / "deep" / "trace.json"
        tracer.dump(path, meta={"tests": 0})
        self.assertEqual(json.loads(path.read_text())["meta"], {"tests": 0})

    def test_dump_onto_a_directory_fails_and_leaves_it_untouched(self):
        target = _tmp() / "dir"
        target.mkdir()
        with self.assertRaises(OSError):
            self._tracer().dump(target)
        self.assertTrue(target.is_dir())

    def test_symbol_id_and_disposition_for_a_public_function_with_parameters(self):
        import ast

        from core.services.test_governance import symbols

        node = ast.parse("def check(value):\n    return value\n").body[0]
        self.assertEqual(symbols.symbol_id("a.py", "check"), "a.py::check")
        self.assertEqual(symbols.disposition_for("check", node, qualname="check", path="a.py", method=False, decorators=[], params=("value",),
                                                 policy=POLICY)[:2], ("POSITIVE_AND_NEGATIVE", "R8"))

    def test_disposition_for_private_and_dunder_names_is_never_required(self):
        import ast

        from core.services.test_governance import symbols

        node = ast.parse("def _x(v):\n    return v\n").body[0]
        self.assertEqual(symbols.disposition_for("_x", node, qualname="_x", path="a.py", method=False, decorators=[], params=("v",),
                                                 policy=POLICY)[1], "R2")
        self.assertEqual(symbols.disposition_for("__repr__", node, qualname="T.__repr__", path="a.py", method=True, decorators=[], params=(),
                                                 policy=POLICY)[1], "R3")

    def test_all_symbol_ids_returns_the_symbols_of_a_valid_checkout(self):
        from core.services.test_governance import session

        self.assertEqual(session.all_symbol_ids(_mini_repo()), ["web/core/services/field_validators.py::check"])

    def test_all_symbol_ids_of_an_empty_checkout_is_empty(self):
        from core.services.test_governance import session

        self.assertEqual(session.all_symbol_ids(_tmp()), [])

    def test_traced_session_writes_a_trace_with_meta(self):
        from core.services.test_governance import session

        out = _tmp() / "trace.json"
        with mock.patch.object(session.DirectCallTracer, "install"), mock.patch.object(session.DirectCallTracer, "uninstall"):
            with session.traced_session(str(out), suite="unit", repo=_mini_repo()) as tracer:
                self.assertEqual(tracer.suite, "unit")
        self.assertEqual(json.loads(out.read_text())["suite"], "unit")

    def test_traced_session_still_writes_the_trace_when_the_suite_raises(self):
        from core.services.test_governance import session

        out = _tmp() / "trace.json"
        with mock.patch.object(session.DirectCallTracer, "install"), mock.patch.object(session.DirectCallTracer, "uninstall"):
            with self.assertRaises(RuntimeError):
                with session.traced_session(str(out), suite="unit", repo=_mini_repo()):
                    raise RuntimeError("suite crashed")
        self.assertTrue(out.is_file())


class TracedUnittestLauncherTests(SimpleTestCase):
    def _main(self):
        from core.services.test_governance import traced_unittest

        return traced_unittest.main

    def test_main_returns_zero_for_a_passing_suite(self):
        root = _tmp()
        (root / "test_ok.py").write_text("import unittest\nclass T(unittest.TestCase):\n    def test_ok(self):\n        pass\n", encoding="utf-8")
        with mock.patch.dict("os.environ", {"NMAS_TG_TRACE_OUT": ""}), mock.patch("sys.stderr", io.StringIO()):
            self.assertEqual(self._main()(["discover", "-s", str(root), "-t", str(root), "-p", "test_*.py"]), 0)

    def test_main_returns_one_for_a_failing_or_empty_suite(self):
        root = _tmp()
        (root / "test_bad.py").write_text("import unittest\nclass T(unittest.TestCase):\n    def test_bad(self):\n        self.fail('x')\n", encoding="utf-8")
        empty = _tmp()
        with mock.patch.dict("os.environ", {"NMAS_TG_TRACE_OUT": ""}), mock.patch("sys.stderr", io.StringIO()):
            self.assertEqual(self._main()(["discover", "-s", str(root), "-t", str(root), "-p", "test_*.py"]), 1)
            self.assertEqual(self._main()(["discover", "-s", str(empty), "-t", str(empty), "-p", "test_*.py"]), 1)
