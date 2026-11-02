"""Tier-3 execution, reporting, CLI, and the side-effect / boundary / workflow contracts.

Every validation command is FAKED (``helpers.tier3.FakeRunner``): these tests can never start Django, the monitoring
suite, a lab verifier or a device connection.  Real ``git`` runs only against a temporary repository.
"""

from __future__ import annotations

import ast
import contextlib
import io
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from unittest import mock

import yaml
from django.test import SimpleTestCase

from core.services import secret_policy
from core.services.ci import catalog, cli, execute, gitio, redact, report, runner, static_checks
from core.services.ci.changes import ScanLine
from core.services.ci.constants import MAX_OUTPUT_LINES, MAX_REPORT_BYTES, CheckStatus, ExitCode, Result
from core.services.ci.runner import CommandResult
from core.services.ci.service import Tier3Request, run_tier3
from core.tests.helpers.tier3 import FakeRunner, TempRepo

WEB_ROOT = Path(__file__).resolve().parents[2]
REPO_ROOT = WEB_ROOT.parent
CI_DIR = WEB_ROOT / "core" / "services" / "ci"
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "tier3-validation.yml"

# Credential-shaped samples are assembled at runtime so this file itself never contains one.
TOKEN = "gh" + "p_" + "A1b2C3d4E5" * 4
WEBHOOK = "https://hooks.slack.com/" + "services/T00000000/B00000000/" + "X" * 24
PRIVATE = "-----BEGIN " + "RSA PRIVATE KEY-----"
AWS = "AK" + "IA" + "ABCDEFGHIJKLMNOP"
MARKER = "<" * 7 + " HEAD"


class RepoCase(SimpleTestCase):
    def setUp(self):
        self.repo = TempRepo()
        self.addCleanup(self.repo.cleanup)

    def make_change(self, path="web/core/services/health/probe.py", text="VALUE = 1\n"):
        self.repo.write("README.md", "hello\n")
        base = self.repo.commit("base")
        self.repo.write(path, text)
        return base, self.repo.commit("head")

    def result(self, rep, check_id):
        return next(r for r in rep.results if r.id == check_id)


class ExecutionSemanticsTests(RepoCase):
    def test_command_outcomes_map_to_truthful_statuses(self):
        ok = "Ran 5 tests in 0.100s\n\nOK\n"
        rows = [
            ("clean run", CommandResult(0, ok), CheckStatus.PASS, Result.PASS, ExitCode.OK),
            ("test failure", CommandResult(1, "Ran 5 tests in 0.1s\n\nFAILED (failures=2)\n"), CheckStatus.FAIL, Result.FAIL, ExitCode.FAIL),
            ("timeout", CommandResult(None, "", timed_out=True), CheckStatus.ERROR, Result.INCOMPLETE, ExitCode.INCOMPLETE),
            ("could not start", CommandResult(None, error="OSError: could not start 'python'"), CheckStatus.ERROR, Result.INCOMPLETE, ExitCode.INCOMPLETE),
            ("no exit status", CommandResult(None, ""), CheckStatus.ERROR, Result.INCOMPLETE, ExitCode.INCOMPLETE),
            ("exit 0 but zero tests ran", CommandResult(0, "Ran 0 tests in 0.0s\n\nNO TESTS RAN\n"), CheckStatus.ERROR, Result.INCOMPLETE, ExitCode.INCOMPLETE),
            ("runner crashed", RuntimeError("boom"), CheckStatus.ERROR, Result.INCOMPLETE, ExitCode.INCOMPLETE),
        ]
        for case, response, status, overall, code in rows:
            with self.subTest(case=case):
                repo = TempRepo()
                self.addCleanup(repo.cleanup)
                repo.write("README.md")
                base = repo.commit()
                repo.write("web/core/services/health/probe.py", "VALUE = 1\n")
                head = repo.commit()
                rep = run_tier3(Tier3Request(repo.path, base, head), runner=FakeRunner({"manage.py test": response}))
                self.assertEqual(self.result(rep, "django.tests").status, status)
                self.assertEqual((rep.result, rep.exit_code), (overall, code))
                if status == CheckStatus.ERROR:
                    self.assertIn("django.tests", rep.to_dict()["blocking_checks"])  # an unreliable check is blocking, never a pass

    def test_overall_result_aggregation(self):
        def res(status, required=True):
            return execute.CheckResult("x", "static", "x", required, status, "")
        rows = [
            ("all pass", [res("PASS")], 0, Result.PASS, 0),
            ("check warning", [res("WARN")], 0, Result.PASS_WITH_WARNINGS, 0),
            ("plan warning only", [res("PASS")], 1, Result.PASS_WITH_WARNINGS, 0),
            ("failure", [res("PASS"), res("FAIL")], 0, Result.FAIL, 1),
            ("error", [res("PASS"), res("ERROR")], 0, Result.INCOMPLETE, 3),
            ("failure beats error", [res("ERROR"), res("FAIL")], 0, Result.FAIL, 1),
            ("optional lab NOT_RUN is not a pass and not a failure", [res("PASS"), res("NOT_RUN", required=False)], 0, Result.PASS, 0),
            ("required check not run", [res("NOT_RUN")], 0, Result.INCOMPLETE, 3),
        ]
        for case, results, warnings, overall, code in rows:
            with self.subTest(case=case):
                self.assertEqual(report.aggregate(results, warnings), (overall, code))

    def test_static_checks_parse_but_never_execute_and_never_echo_content(self):
        for rel, text in {"bad.py": "def x(:\n", "bad.json": "{", "bad.yml": "a: [1\n", "bad.j2": "{% if %}\n", "ok.py": "x = 1\n",
                          "ok.yml": "a: 1\n", "ok.j2": "{{ a }}\n", "notes.txt": "x ("}.items():
            self.repo.write(rel, text)
        self.repo.write("boom.py", "raise SystemExit('executed!')\n")  # syntactically valid; must only be PARSED
        outcome = static_checks.check_syntax(self.repo.path, ["bad.py", "bad.json", "bad.yml", "bad.j2", "ok.py", "ok.yml", "ok.j2", "notes.txt", "boom.py", "gone.py"])
        self.assertEqual(outcome.status, CheckStatus.FAIL)
        self.assertEqual({f["code"] for f in outcome.findings}, {"SYNTAX_PYTHON", "SYNTAX_JSON", "SYNTAX_YAML", "SYNTAX_JINJA"})
        self.assertEqual(outcome.counts["files_checked"], 8)  # notes.txt (unknown type) and gone.py (missing) are skipped
        clean = static_checks.check_syntax(self.repo.path, ["ok.py", "ok.yml", "ok.j2", "boom.py"])
        self.assertEqual(clean.status, CheckStatus.PASS)
        shell = static_checks.check_syntax(self.repo.path, ["a.sh"], shell_runner=lambda p: (False, "unexpected end of file")) if (self.repo.path / "a.sh").exists() else None
        self.assertIsNone(shell)
        self.repo.write("a.sh", "echo hi\n")
        self.assertEqual(static_checks.check_syntax(self.repo.path, ["a.sh"], shell_runner=lambda p: (False, "bad")).findings[0]["code"], "SYNTAX_SHELL")

    def test_hygiene_flags_credential_formats_markers_and_credential_files_without_echoing_values(self):
        lines = [ScanLine("a.py", 1, f"x = '{TOKEN}'"), ScanLine("b.md", 2, f"hook {WEBHOOK}"), ScanLine("c.txt", 3, PRIVATE), ScanLine("d.txt", 4, AWS),
                 ScanLine("e.txt", 5, MARKER), ScanLine("ok.txt", 6, "password_ref = vault/path"), ScanLine("ok2.txt", 7, "an ordinary line")]
        outcome = static_checks.check_hygiene(lines, False, [("a.py", "added")])
        self.assertEqual(outcome.status, CheckStatus.FAIL)
        self.assertEqual({(f["path"], f["code"]) for f in outcome.findings}, {
            ("a.py", "HYGIENE_CREDENTIAL_PATTERN"), ("b.md", "HYGIENE_CREDENTIAL_PATTERN"), ("c.txt", "HYGIENE_CREDENTIAL_PATTERN"),
            ("d.txt", "HYGIENE_CREDENTIAL_PATTERN"), ("e.txt", "HYGIENE_CONFLICT_MARKER")})
        dumped = json.dumps(outcome.findings)
        for secret in (TOKEN, WEBHOOK, AWS, "A1b2C3d4E5"):
            self.assertNotIn(secret, dumped)
        rows = [("netbox/.env", "added", True), ("netbox/.env.example", "added", False), ("monitoring/runtime/snmp.json", "modified", True),
                ("monitoring/runtime/.gitkeep", "added", False), ("keys/server.pem", "added", True), ("keys/server.pem", "deleted", False), ("docs/a.md", "added", False)]
        for path, status, flagged in rows:
            with self.subTest(path=path, status=status):
                got = static_checks.check_hygiene([], False, [(path, status)])
                self.assertEqual(got.status == CheckStatus.FAIL, flagged)
        self.assertEqual(static_checks.check_hygiene([], True, []).status, CheckStatus.WARN)  # an incomplete scan is never a silent pass

    def test_hygiene_blocks_low_entropy_legacy_password_assignments_without_echoing_values(self):
        # Assemble names and values at runtime so this test cannot become a
        # scanner finding itself.  These are intentionally low entropy: the
        # public-history incident proved token-format rules alone are not enough.
        key_rows = [
            ("ceos_" + "password", ": ", "short"),
            ("ROOT_" + "PASSWORD", " = ", "tinyword"),
            ("linux_root_" + "password", ": ", "ordinary"),
        ]
        lines = [ScanLine("inventory.yml", i, key + sep + value) for i, (key, sep, value) in enumerate(key_rows, 1)]
        outcome = static_checks.check_hygiene(lines, False, [("inventory.yml", "modified")])
        self.assertEqual(outcome.status, CheckStatus.FAIL)
        self.assertEqual({f["message"] for f in outcome.findings}, {
            "credential format NMAS_LEGACY_PASSWORD_ASSIGNMENT detected (value not shown)"
        })
        dumped = json.dumps(outcome.findings)
        for _key, _sep, value in key_rows:
            self.assertNotIn(value, dumped)

        safe = [
            ScanLine("inventory.yml", 1, "ceos_credential_ref: runtime://device-credentials/device"),
            ScanLine("module.py", 2, "root_password = FileSecretProvider().current(ref).value"),
            ScanLine("example.yml", 3, "linux_root_password: CHANGEME"),
        ]
        self.assertEqual(static_checks.check_hygiene(safe, False, []).status, CheckStatus.PASS)


class OfflineGateContractTests(SimpleTestCase):
    def test_offline_gates_never_receive_the_callers_environment_and_commands_are_fixed(self):
        hostile = {"PATH": os.environ.get("PATH", ""), "HOME": "/h", "GITHUB_TOKEN": "t", "SLACK_WEBHOOK_URL": "w", "NETBOX_TOKEN": "n",
                   "DJANGO_SECRET_KEY": "k", "AWS_SECRET_ACCESS_KEY": "a", "SNMP_AUTH_PASSWORD": "p"}
        with mock.patch.dict(os.environ, hostile, clear=True):
            for check_id, definition in catalog.CHECKS.items():
                if definition.kind != "command":
                    continue
                command = catalog.command_for(check_id, python=sys.executable)
                env = runner.build_env(command)
                with self.subTest(check=check_id):
                    if definition.gate == "lab":
                        self.assertTrue(command.inherit_env)  # the explicit, operator-opted gate needs their context
                        self.assertIn("NETBOX_TOKEN", env)
                    else:
                        self.assertFalse(command.inherit_env)
                        self.assertEqual(set(env) - {"PYTHONDONTWRITEBYTECODE", "DJANGO_DEBUG"}, {"PATH", "HOME"})
                    self.assertIn(command.argv[0], (sys.executable, "bash"))
                    line = " ".join(command.argv[1:])
                    for forbidden in ("containerlab", "deploy", "destroy", "netmiko", "ssh", "vtysh", "configure", "--apply", "push", "rollback"):
                        self.assertNotIn(forbidden, line)
        for bad in (["core.tests.test_x; rm -rf /"], ["core.tests.../etc"], ["../../x"], ["os.system"], ["core.tests.Test_Upper"]):
            with self.subTest(label=bad):
                with self.assertRaises(ValueError):
                    catalog.command_for("django.tests", python="python", params={"labels": bad})
        self.assertEqual(catalog.command_for("django.tests", python="p", params={"labels": ["core"]}).argv[-1], "core")
        with self.assertRaises(KeyError):
            catalog.command_for("anything.else", python="p")


class ReportingAndCliTests(RepoCase):
    def test_report_is_stable_secret_safe_bounded_and_presentable(self):
        noisy = "\n".join([f"line {i}" for i in range(200)] + [f"token: {TOKEN}", f"password=hunter2 {WEBHOOK}", PRIVATE, "AssertionError: boom"])
        failing = FakeRunner({"manage.py test": CommandResult(1, "Ran 4 tests in 0.2s\n\n" + noisy + "\n\nFAILED (failures=1)\n")})
        rep = self.go(failing)
        doc = rep.to_dict()
        dumped = json.dumps(doc)
        for leaked in (TOKEN, WEBHOOK, "hunter2", PRIVATE):
            self.assertNotIn(leaked, dumped)
        self.assertIn("[REDACTED", dumped)
        secret_policy.assert_no_secret_shaped_keys(doc, context="tier3 report")  # the project-wide key denylist applies to the report
        self.assertLessEqual(len(dumped), MAX_REPORT_BYTES)
        tail = self.result(rep, "django.tests").output_tail
        self.assertLessEqual(len(tail.splitlines()), MAX_OUTPUT_LINES)
        self.assertEqual(doc["result"], Result.FAIL)
        self.assertEqual(doc["provenance"]["engine_version"], report.ENGINE_VERSION)
        self.assertEqual(len(doc["provenance"]["head_sha"]), 40)
        self.assertEqual(doc["coverage"], {"static": "EXECUTED", "repository": "EXECUTED", "lab": "NOT_SELECTED"})
        text, markdown = report.render_text(rep), report.render_markdown(rep)
        for shown in ("TIER-3 VALIDATION: FAIL", "BLOCKING: django.tests", "[FAIL"):
            self.assertIn(shown, text)
        self.assertIn("### Blocking", markdown)
        self.assertNotIn("hunter2", text + markdown)
        # identical inputs -> identical deterministic digest (durations and tool output are excluded from it)
        digest = [self.run_repeat().semantic_digest() for _ in range(2)]
        self.assertEqual(digest[0], digest[1])
        self.assertNotIn("duration_seconds", json.dumps(self.run_repeat().to_dict(include_timing=False)))

    def go(self, fake, **request):
        return run_tier3(Tier3Request(self.repo.path, self._base, self._head, **request), runner=fake)

    def run_repeat(self):
        return self.go(FakeRunner())

    def setUp(self):
        super().setUp()
        self._base, self._head = self.make_change()

    def test_lab_gate_is_opt_in_and_reported_honestly(self):
        path = "monitoring/scripts/ingest_probe.py"
        self.repo.write(path, "X = 1\n")
        head = self.repo.commit("monitoring change")
        default_runner = FakeRunner()
        default = run_tier3(Tier3Request(self.repo.path, self._head, head), runner=default_runner)
        self.assertEqual([r.status for r in default.results if r.id.startswith("lab.")], [CheckStatus.NOT_RUN] * 2)
        self.assertEqual(default.to_dict()["coverage"]["lab"], "NOT_RUN")  # absence is reported as absence
        self.assertEqual(default.result, Result.PASS)
        self.assertFalse(any("verify_" in line for line in default_runner.lines))
        lab_runner = FakeRunner({"verify_grafana.py": CommandResult(1, "connection refused"), "verify_nmas_infrastructure.sh": CommandResult(None, error="OSError: could not start 'bash'")})
        lab = run_tier3(Tier3Request(self.repo.path, self._head, head, include_lab=True), runner=lab_runner)
        self.assertEqual(self.result(lab, "lab.grafana").status, CheckStatus.FAIL)
        self.assertEqual(self.result(lab, "lab.nmas").status, CheckStatus.ERROR)
        self.assertEqual((lab.result, lab.to_dict()["coverage"]["lab"]), (Result.FAIL, "INCOMPLETE"))
        self.assertTrue(all(c.inherit_env for c in lab_runner.calls if "verify_" in " ".join(c.argv)))

    def test_cli_exit_codes_and_artifacts(self):
        base, head = self._base, self._head
        self.repo.write("templates/R1.cfg.j2", "hostname R1\n")
        frozen = self.repo.commit("frozen lab template")
        out_dir = self.repo.path / "out"
        cases = [
            ("pass", ["--base", base, "--head", head], FakeRunner(), ExitCode.OK),
            ("warning only is not blocking", ["--base", head, "--head", frozen], FakeRunner(), ExitCode.OK),
            ("required check fails", ["--base", base, "--head", head], FakeRunner({"manage.py test": CommandResult(1, "Ran 1 tests in 0.1s\nFAILED (failures=1)")}), ExitCode.FAIL),
            ("required check cannot run", ["--base", base, "--head", head], FakeRunner({"manage.py test": CommandResult(None, timed_out=True)}), ExitCode.INCOMPLETE),
            ("bad revision", ["--base", "does-not-exist", "--head", head], FakeRunner(), ExitCode.USAGE),
            ("option-shaped revision", ["--base", "--output=x", "--head", head], FakeRunner(), ExitCode.USAGE),
            ("targeted without a base", [], FakeRunner(), ExitCode.USAGE),
            ("--working-tree without a base", ["--working-tree", "--mode", "full"], FakeRunner(), ExitCode.USAGE),
        ]
        for case, args, fake, expected in cases:
            with self.subTest(case=case):
                out, err = io.StringIO(), io.StringIO()
                try:
                    with contextlib.redirect_stderr(io.StringIO()):
                        code = cli.main(["--repo", str(self.repo.path), *args], env={}, runner=fake, stdout=out, stderr=err)
                except SystemExit as exc:  # argparse rejects an option-shaped value itself: still a usage error
                    code = exc.code
                self.assertEqual(code, expected)
        warn = io.StringIO()
        self.assertEqual(cli.main(["--repo", str(self.repo.path), "--base", head, "--head", frozen], env={}, runner=FakeRunner(), stdout=warn, stderr=io.StringIO()), 0)
        self.assertIn("PASS_WITH_WARNINGS", warn.getvalue())
        self.assertIn("FROZEN_LAB_PATH_CHANGED", warn.getvalue())
        # --plan-only executes nothing; a repository that is not a git checkout is a usage error
        never = FakeRunner()
        planned = io.StringIO()
        self.assertEqual(cli.main(["--repo", str(self.repo.path), "--base", base, "--head", head, "--plan-only"], env={}, runner=never, stdout=planned, stderr=io.StringIO()), 0)
        self.assertEqual(never.calls, [])
        self.assertIn("required_checks", json.loads(planned.getvalue()))
        self.assertEqual(cli.main(["--repo", "/nonexistent-tier3-dir", "--mode", "full"], env={}, runner=never, stdout=io.StringIO(), stderr=io.StringIO()), ExitCode.USAGE)
        # artifacts: the JSON report is written; the Markdown summary is APPENDED (it may be a shared $GITHUB_STEP_SUMMARY)
        summary = self.repo.path / "summary.md"
        summary.write_text("earlier step\n")
        stdout = io.StringIO()
        self.assertEqual(cli.main(["--repo", str(self.repo.path), "--base", base, "--head", head, "--json", str(out_dir / "r.json"), "--summary-md", str(summary),
                                   "--format", "json"], env={}, runner=FakeRunner(), stdout=stdout, stderr=io.StringIO()), 0)
        self.assertEqual(json.loads((out_dir / "r.json").read_text())["result"], "PASS")
        self.assertEqual(json.loads(stdout.getvalue())["schema_version"], 1)
        self.assertTrue(summary.read_text().startswith("earlier step\n"))
        self.assertIn("Tier-3 validation", summary.read_text())

    def test_github_launcher_derives_the_comparison_from_event_data(self):
        base, head = self._base, self._head
        event = self.repo.path / "event.json"
        env = {"GITHUB_EVENT_NAME": "pull_request", "GITHUB_EVENT_PATH": str(event), "GITHUB_SHA": head, "GITHUB_REPOSITORY": "o/r", "GITHUB_RUN_ID": "7"}
        event.write_text(json.dumps({"pull_request": {"base": {"sha": base, "ref": "main"}, "head": {"sha": head, "ref": "f"}}}))
        out = io.StringIO()
        self.assertEqual(cli.main(["--repo", str(self.repo.path), "--from-github", "--format", "json"], env=env, runner=FakeRunner(), stdout=out, stderr=io.StringIO()), 0)
        doc = json.loads(out.getvalue())
        self.assertEqual((doc["provenance"]["base_sha"], doc["provenance"]["head_sha"], doc["provenance"]["event"]), (base, head, "pull_request"))
        self.assertEqual(doc["provenance"]["strategy"], "merge-base")
        # a force-pushed / shallow-checkout base this clone cannot resolve broadens to FULL and says so
        event.write_text(json.dumps({"before": "e" * 40, "after": head, "ref": "refs/heads/f", "repository": {"default_branch": "main"}}))
        out = io.StringIO()
        code = cli.main(["--repo", str(self.repo.path), "--from-github", "--format", "json"], env={**env, "GITHUB_EVENT_NAME": "push"}, runner=FakeRunner(), stdout=out, stderr=io.StringIO())
        doc = json.loads(out.getvalue())
        self.assertEqual((code, doc["mode"]["effective"], doc["result"]), (0, "full", "PASS_WITH_WARNINGS"))
        self.assertIn("BASE_FALLBACK", [w["code"] for w in doc["warnings"]])
        for args, env_ in ((["--from-github", "--base", base], env), (["--from-github"], {})):
            with self.subTest(args=args):
                self.assertEqual(cli.main(["--repo", str(self.repo.path), *args], env=env_, runner=FakeRunner(), stdout=io.StringIO(), stderr=io.StringIO()), ExitCode.USAGE)


class SideEffectAndBoundaryContractTests(RepoCase):
    def test_a_tier3_run_leaves_the_repository_untouched_and_uses_only_read_only_git(self):
        base, head = self.make_change()
        self.repo.write("untracked.py", "Y = 2\n")  # a dirty tree stays exactly as it was
        before = self.repo.snapshot()
        fake = FakeRunner()
        real_run = subprocess.run
        with mock.patch.object(gitio.subprocess, "run", wraps=real_run) as spy:
            run_tier3(Tier3Request(self.repo.path, base, head, mode="full", include_lab=True), runner=fake)
            run_tier3(Tier3Request(self.repo.path, base, "HEAD", working_tree=True), runner=fake)
        self.assertEqual(self.repo.snapshot(), before)
        git_verbs = {call.args[0][4] for call in spy.call_args_list if call.args and call.args[0][:1] == ["git"]}
        self.assertTrue(git_verbs and git_verbs <= gitio.READ_ONLY_GIT_COMMANDS, git_verbs)
        allowed = ("manage.py check", "makemigrations --check --dry-run", "manage.py test", "unittest discover", "build_grafana_dashboards.py --check", "verify_", "populate_netbox.py --check",
                   # Lab 7 governance: read-only catalog / Pylint / report commands and the traced monitoring suite
                   "manage.py nmas_test_governance validate-catalog", "manage.py nmas_test_governance pylint", "manage.py nmas_test_governance report",
                   "traced_unittest.py discover")
        for line in fake.lines:
            with self.subTest(command=line):
                self.assertTrue(any(token in line for token in allowed))

    def test_the_engine_stays_pure_python_with_no_device_netbox_or_deployment_surface(self):
        forbidden_imports = {"netmiko", "paramiko", "pynetbox", "requests", "urllib", "http", "socket", "influxdb", "ncclient", "pygnmi", "docker", "django"}
        writers = {"write_text", "write_bytes", "unlink", "rmtree", "rename", "mkdir", "touch", "chmod"}
        deployment_text = ("containerlab deploy", "containerlab destroy", "containerlab cleanup", "configure terminal", "write memory", "copy running",
                           "commit confirmed", "send_config", "rollback", "golden")
        sources = {p.name: p.read_text() for p in sorted(CI_DIR.glob("*.py"))}
        sources["ci_service.py"] = (CI_DIR.parent / "ci_service.py").read_text()
        for name, text in sources.items():
            tree = ast.parse(text)
            imports = set()
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    imports.update(a.name.split(".")[0] for a in node.names)
                elif isinstance(node, ast.ImportFrom):
                    imports.add((node.module or "").split(".")[0])
                    if node.level == 2:  # ``from .. import x`` may only reach the shared secret policy
                        self.assertEqual({a.name for a in node.names}, {"secret_policy"}, name)
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr in writers:
                    self.assertIn(name, {"cli.py"}, f"{name} writes to disk outside the CLI's report artifacts")
                if isinstance(node, ast.keyword) and node.arg == "shell":
                    self.assertFalse(getattr(node.value, "value", None), f"{name}: shell=True")
                if isinstance(node, ast.Call) and getattr(node.func, "id", "") in {"eval", "exec", "__import__"}:
                    self.fail(f"{name}: dynamic execution")
            with self.subTest(module=name):
                self.assertFalse(imports & forbidden_imports, imports & forbidden_imports)
                if "subprocess" in imports:
                    self.assertIn(name, {"gitio.py", "runner.py"}, "subprocess is confined to the two audited modules")
                self.assertNotIn("os.system", text)
                self.assertNotIn("Popen", text)
                for token in deployment_text:
                    self.assertNotIn(token, text.lower())
        self.assertIn("catalog", {p.stem for p in CI_DIR.glob("*.py")})

    def test_workflow_is_thin_least_privilege_and_untrusted_pr_safe(self):
        text = WORKFLOW.read_text()
        doc = yaml.safe_load(text)
        triggers = doc.get("on", doc.get(True))
        self.assertEqual(set(triggers), {"pull_request", "push", "workflow_dispatch"})
        self.assertEqual(doc["permissions"], {"contents": "read"})
        job = next(iter(doc["jobs"].values()))
        self.assertNotIn("permissions", job)  # a job may not widen the workflow-level grant
        self.assertIn("timeout-minutes", job)
        self.assertGreaterEqual(job["timeout-minutes"], 100)
        self.assertLess(catalog.CHECKS["django.tests"].timeout, job["timeout-minutes"] * 60)
        self.assertNotIn("self-hosted", str(job.get("runs-on")))
        for forbidden in ("pull_request_target", "secrets.", "GITHUB_TOKEN", "containerlab", "netmiko", "vtysh", "ssh ", "docker ", "--lab", "--apply"):
            self.assertNotIn(forbidden, text, forbidden)
        steps = job["steps"]
        for step in steps:
            if "uses" in step:
                self.assertRegex(step["uses"], r"@\S+", "actions must be version-pinned")
            for value in (step.get("run", ""), *map(str, (step.get("env") or {}).values())):
                # event data must never be interpolated into a shell: Python reads the event file itself
                self.assertNotRegex(value, r"\$\{\{\s*(github\.(event|head_ref|base_ref)|inputs)", step.get("name"))
        checkout = next(s for s in steps if s.get("uses", "").startswith("actions/checkout"))
        self.assertEqual((checkout["with"]["fetch-depth"], checkout["with"]["persist-credentials"]), (0, False))
        commands = " ".join(s.get("run", "") for s in steps)
        self.assertIn("tier3.py --from-github", commands)
        self.assertEqual(len([s for s in steps if "tier3.py" in s.get("run", "")]), 1)  # exactly one invocation: the workflow holds no logic
        upload = next(s for s in steps if s.get("uses", "").startswith("actions/upload-artifact"))
        self.assertNotIn("logs", str(upload["with"]["path"]).lower().replace("tier3-report", ""))
        self.assertLess(len(text.splitlines()), 90)  # thin by construction
        doc_text = (REPO_ROOT / "docs" / "GITHUB_ACTIONS_TIER3_VALIDATION.md").read_text()
        for phrase in ("pull_request_target", "INCOMPLETE", "--lab"):
            self.assertIn(phrase, doc_text)
