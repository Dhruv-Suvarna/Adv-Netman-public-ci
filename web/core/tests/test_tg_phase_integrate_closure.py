"""Lab 7 closure -- ``tools/phase_integrate.py``: every ``Integrator`` step, the ``Shell`` allowlist wrapper, the ``Reporter`` and the small
records / helpers, each called directly (the existing ``test_phase_integrate`` drives most of them only through ``main``).

Hermetic: real ``git`` runs only inside the throw-away ``Sandbox`` of ``test_phase_integrate`` (a bare origin and two clones under a temporary
directory, with a temporary HOME and no global git configuration); ``gh`` and ``tier3.py`` are the ``FakeGitHub`` stand-ins, so no PR is created,
nothing is pushed anywhere near GitHub and no validation runs.  POSITIVE: exact branches, SHAs, PR records, labels and printed lines.  NEGATIVE:
unsafe commands, a detached HEAD, unknown refs, staged or dirty trees, suspicious files, whitespace errors, a failed validation, a staging
mismatch, a diverged push, a mismatched PR base, a pending check and an unexpected local state are refused or reported.
"""
from __future__ import annotations

import argparse
import io
import json

from core.tests.test_phase_integrate import BRANCH, MESSAGE, REPO_ROOT, PhaseIntegrateCase, check_run, pi
from django.test import SimpleTestCase


def args(**overrides):
    values = {"phase": "18", "slug": "raw-configlets", "message": MESSAGE, "adopt_working_tree": True, "full": False, "pr_title": None,
              "pr_footer": None, "trailer": None}
    values.update(overrides)
    return argparse.Namespace(**values)


# --------------------------------------------------------------------------------------------------- records and helpers
class RecordTests(SimpleTestCase):
    def test_blocked_entry_proc_and_tree_records(self):
        with self.subTest("records hold their values"):
            blocked = pi.Blocked("CODE", "message", ("detail",))
            self.assertEqual((blocked.code, blocked.message, blocked.details, str(blocked)), ("CODE", "message", ["detail"], "message"))
            self.assertEqual((pi.Entry("M ", "a").staged, pi.Entry("??", "b").untracked, pi.Entry(" D", "c").deleted, pi.Entry("UU", "d").unmerged),
                             (True, True, True, True))
            self.assertTrue(pi.Proc(("git",), 0).ok)
            tree = pi.WorkingTree((pi.Entry("??", "b"), pi.Entry("M ", "a")))
            self.assertEqual(tree.signature(), (("??", "b"), ("M ", "a")))

    def test_blocked_without_details_has_an_empty_list(self):
        self.assertEqual(pi.Blocked("CODE", "message").details, [])

    def test_short_check_state_parser_and_default_repo(self):
        self.assertEqual(pi.short("abcdef1234"), "abcdef1")
        state = pi.normalize_check(check_run())
        self.assertEqual(state, {"name": "Tier-3 validation", "workflow": "Tier-3 validation", "state": "SUCCESS"})
        self.assertEqual(pi.tier3_state([state]), "SUCCESS")
        self.assertEqual(vars(pi.build_parser().parse_args(["status", "--phase", "18"]))["phase"], "18")
        self.assertEqual(pi.default_repo(), REPO_ROOT)

    def test_short_check_state_and_names_of_missing_failed_or_invalid_input(self):
        self.assertEqual(pi.short(None), "-")
        self.assertEqual(pi.normalize_check({"__typename": "StatusContext", "state": "ERROR", "context": "ci"})["state"], "FAILURE")
        self.assertEqual(pi.tier3_state([]), "MISSING")
        self.assertIsNone(pi.parse_branch("topic"))
        self.assertIsNotNone(pi.suspicious_reason(".env"))
        with self.assertRaises(pi.UsageError):
            pi.branch_name(18, "Not_A_Slug")

    def test_reporter_prints_lines_items_and_the_result(self):
        out, err = io.StringIO(), io.StringIO()
        rep = pi.Reporter(False, out, err)
        rep.line("[start]")
        rep.kv("branch", BRANCH)
        rep.items("candidates", ["a", "b", "c"], limit=2)
        rep.finish("READY", command="start")
        self.assertEqual(out.getvalue().splitlines(), ["[start]", f"  branch          {BRANCH}", "  candidates:", "    a", "    b", "    ... and 1 more", "READY"])
        self.assertEqual((rep.doc, err.getvalue()), ({"command": "start", "result": "READY"}, ""))

    def test_reporter_in_json_mode_never_prints_progress_on_stdout(self):
        out, err = io.StringIO(), io.StringIO()
        rep = pi.Reporter(True, out, err)
        rep.line("[status]")
        rep.kv("PR", "#1")
        rep.items("blockers", ["x"])
        rep.finish("BLOCKED", show=False, reason="NO_PR")
        self.assertEqual(json.loads(out.getvalue()), {"reason": "NO_PR", "result": "BLOCKED"})
        self.assertIn("[status]", err.getvalue())


# ---------------------------------------------------------------------------------------------------------------- shell
class ShellTests(PhaseIntegrateCase):
    def test_shell_runs_allowlisted_git_and_gh(self):
        sb, gh = self.sandbox()
        sh = pi.Shell(sb.work, gh)
        self.assertEqual(sh.git("rev-parse", "HEAD").stdout.strip(), sb.base)
        self.assertTrue(sh.gh("--version").ok)
        self.assertTrue(sh.run(["git", "status", "--porcelain=v1"]).ok)

    def test_shell_refuses_unsafe_commands_and_a_dry_run_never_mutates(self):
        sb, gh = self.sandbox()
        sh = pi.Shell(sb.work, gh)
        for label, call in (("refused executable", lambda: sh.run(["rm", "-rf", "x"])), ("refused reset", lambda: sh.git("reset", "--hard")),
                            ("refused repo delete", lambda: sh.gh("repo", "delete", "x"))):
            with self.subTest(label), self.assertRaises(pi.UnsafeCommand):
                call()
        with self.assertRaises(pi.CommandFailed):
            sh.git("rev-parse", "--verify", "no-such-ref")
        dry = pi.Shell(sb.work, gh, dry_run=True)
        self.assertEqual(dry.git("switch", "-c", "phase19-golden").returncode, 0)
        self.assertEqual((dry.would_run, sb.branches()), ([("git", *pi.GIT_GLOBAL_OPTIONS, "switch", "-c", "phase19-golden")], ["main"]))


# ----------------------------------------------------------------------------------------------------------- integrator
class IntegratorCase(PhaseIntegrateCase):
    def tool(self, sb, gh, *, dry_run=False):
        self.out, self.err = io.StringIO(), io.StringIO()
        return pi.Integrator(pi.Shell(sb.work, gh, dry_run=dry_run), pi.Reporter(False, self.out, self.err), sleep=lambda _s: None)

    def on_branch_with_commit(self):
        sb, gh = self.sandbox()
        sb.git("switch", "-q", "-c", BRANCH)
        sb.write("app.py", "print('v2')\n")
        sb.git("add", "--", "app.py")
        sb.git("commit", "-q", "-m", "phase")
        return sb, gh, sb.rev("HEAD")


class IntegratorReadTests(IntegratorCase):
    def test_reads_and_preconditions_of_a_clean_synchronised_main(self):
        sb, gh = self.sandbox()
        tool = self.tool(sb, gh)
        self.assertEqual((tool.current_branch(), tool.rev("HEAD"), tool.remote_head("main")), ("main", sb.base, sb.base))
        self.assertTrue(tool.local_branch_exists("main") and tool.has_commit(sb.base) and tool.is_ancestor(sb.base, "HEAD"))
        self.assertIsNone(tool.require_no_staged(tool.working_tree()))
        self.assertEqual(tool.require_base_in_sync(), sb.base)
        self.assertIsNone(tool.require_branch_free(BRANCH))
        self.assertIsNone(tool.check_gh_ready())
        self.assertEqual(tool.tier3_argv(full=True)[-2:], ["--mode", "full"])

    def test_reads_of_unknown_refs_and_refusals_of_staged_detached_or_existing_branches(self):
        sb, gh = self.sandbox()
        tool = self.tool(sb, gh)
        self.assertEqual((tool.rev("no-such-ref"), tool.remote_head("phase99-none")), (None, None))
        self.assertFalse(tool.local_branch_exists("phase99-none") or tool.has_commit("0" * 40))
        sb.write("later.txt", "x\n")
        sb.git("add", "--", "later.txt")
        with self.subTest("refused staged"), self.assertRaises(pi.Blocked) as staged:
            tool.require_no_staged(tool.working_tree())
        self.assertEqual(staged.exception.code, "STAGED_CHANGES")
        sb.git("commit", "-q", "-m", "later")
        self.assertFalse(tool.is_ancestor("HEAD", sb.base))
        with self.subTest("refused existing branch"), self.assertRaises(pi.Blocked) as exists:
            tool.require_branch_free("main")
        self.assertEqual(exists.exception.code, "BRANCH_EXISTS")
        self.assertNotIn("--mode", tool.tier3_argv(full=False))
        sb.git("switch", "-q", "--detach")
        with self.assertRaises(pi.Blocked) as detached:
            tool.current_branch()
        self.assertEqual(detached.exception.code, "DETACHED_HEAD")


class IntegratorPrepareTests(IntegratorCase):
    def test_start_creates_the_phase_branch_from_clean_main(self):
        sb, gh = self.sandbox()
        sb.dirty_runtime()
        self.assertEqual(self.tool(sb, gh).start(19, "golden"), pi.EXIT_OK)
        self.assertEqual(sb.git("branch", "--show-current"), "phase19-golden")

    def test_start_refuses_a_dirty_source_tree(self):
        sb, gh = self.sandbox()
        sb.write("app.py", "changed\n")
        with self.assertRaises(pi.Blocked) as refused:
            self.tool(sb, gh).start(19, "golden")
        self.assertEqual((refused.exception.code, sb.branches()), ("SOURCE_DIRTY", ["main"]))

    def test_prepare_adopts_commits_pushes_and_opens_the_pr(self):
        sb, gh = self.sandbox()
        sb.dirty_phase()
        self.assertEqual(self.tool(sb, gh).prepare(args()), pi.EXIT_OK)
        self.assertIn("PR #1  https://github.test/pull/1", self.out.getvalue())
        self.assertEqual((sb.git("branch", "--show-current"), gh.prs[0]["headRefName"]), (BRANCH, BRANCH))

    def test_prepare_refuses_work_on_main_without_adoption(self):
        sb, gh = self.sandbox()
        sb.dirty_phase()
        with self.assertRaises(pi.Blocked) as refused:
            self.tool(sb, gh).prepare(args(adopt_working_tree=False))
        self.assertEqual((refused.exception.code, gh.prs), ("WRONG_BRANCH", []))

    def test_gate_and_source_diff_accept_ordinary_source_changes(self):
        sb, gh = self.sandbox()
        sb.dirty_phase()
        tool = self.tool(sb, gh)
        candidates = tool.working_tree().candidates
        self.assertIsNone(tool.gate_suspicious(candidates))
        self.assertIsNone(tool.check_source_diff(candidates))
        self.assertIn("  source diff: 1 deleted, 1 modified, 2 untracked", self.out.getvalue())

    def test_gate_and_source_diff_refuse_a_secret_file_or_whitespace_errors(self):
        sb, gh = self.sandbox()
        sb.write(".env", "TOKEN=x\n")
        tool = self.tool(sb, gh)
        with self.subTest("refused suspicious"), self.assertRaises(pi.Blocked) as suspicious:
            tool.gate_suspicious(tool.working_tree().candidates)
        self.assertEqual(suspicious.exception.code, "SUSPICIOUS_FILES")
        (sb.work / ".env").unlink()
        sb.write("app.py", "print('app')   \n")
        with self.subTest("refused whitespace"), self.assertRaises(pi.Blocked) as whitespace:
            tool.check_source_diff(tool.working_tree().candidates)
        self.assertEqual(whitespace.exception.code, "SOURCE_DIFF_CHECK")

    def test_run_validation_records_a_passing_tier3_run(self):
        sb, gh = self.sandbox()
        tool = self.tool(sb, gh)
        validation = tool.run_validation(tool.tier3_argv(full=False), full=False)
        self.assertEqual((validation["mode"], validation["result"], validation["exit_code"]), ("targeted", "PASS_WITH_WARNINGS", 0))

    def test_run_validation_refuses_a_failed_tier3_run(self):
        sb, gh = self.sandbox()
        gh.tier3 = (1, {"result": "FAIL", "blocking_checks": ["static.hygiene"]}, False)
        tool = self.tool(sb, gh)
        with self.assertRaises(pi.Blocked) as refused:
            tool.run_validation(tool.tier3_argv(full=True), full=True)
        self.assertEqual(refused.exception.code, "VALIDATION_FAILED")
        self.assertIn("blocking checks: static.hygiene", refused.exception.details)

    def test_stage_and_commit_verify_staged_and_unstage_the_exact_source_set(self):
        sb, gh = self.sandbox()
        sb.git("switch", "-q", "-c", BRANCH)
        sb.dirty_phase()
        tool = self.tool(sb, gh)
        sb.git("add", "--", "app.py")
        tool.unstage(["app.py"])
        self.assertEqual(sb.staged(), [])
        sha = tool.stage_and_commit(tool.working_tree().candidates, MESSAGE, ["Co-Authored-By: T <t@example.test>"])
        self.assertEqual(sha, sb.rev("HEAD"))
        self.assertEqual(sb.git("log", "-1", "--format=%(trailers:key=Co-Authored-By,valueonly)").strip(), "T <t@example.test>")
        self.assertEqual(tool.working_tree().runtime, ["Run_Logs.log", "logs/R2.log"])

    def test_verify_staged_of_exactly_the_intended_paths(self):
        sb, gh = self.sandbox()
        sb.write("app.py", "print('v2')\n")
        sb.git("add", "--", "app.py")
        tool = self.tool(sb, gh)
        self.assertIsNone(tool.verify_staged(["app.py"]))
        self.assertIn("  staged: 1 file changed", self.out.getvalue())

    def test_staging_refuses_a_mismatch_or_a_missing_path_and_unstages_its_own_work(self):
        sb, gh = self.sandbox()
        sb.write("app.py", "print('v2')\n")
        sb.write("other.py", "x\n")
        sb.git("add", "--", "app.py", "other.py")
        tool = self.tool(sb, gh)
        with self.subTest("refused staging mismatch"), self.assertRaises(pi.Blocked) as mismatch:
            tool.verify_staged(["app.py"])
        self.assertEqual(mismatch.exception.code, "STAGING_MISMATCH")
        with self.subTest("refused unstage of a path never staged"):
            tool.unstage(["README.md"])
        self.assertEqual(sb.staged(), ["app.py", "other.py"])
        sb.git("restore", "--staged", "--", "app.py", "other.py")
        with self.subTest("refused missing path"), self.assertRaises(pi.CommandFailed):
            tool.stage_and_commit([pi.Entry("??", "ghost.py")], MESSAGE, [])
        self.assertEqual(sb.staged(), [])

    def test_push_sets_the_remote_branch_to_the_phase_commit(self):
        sb, gh, sha = self.on_branch_with_commit()
        tool = self.tool(sb, gh)
        tool.push(BRANCH, sha)
        self.assertEqual(tool.remote_head(BRANCH), sha)

    def test_push_refuses_when_the_remote_does_not_end_at_the_expected_commit(self):
        sb, gh, _sha = self.on_branch_with_commit()
        with self.assertRaises(pi.Blocked) as refused:
            self.tool(sb, gh).push(BRANCH, "f" * 40)
        self.assertEqual(refused.exception.code, "PUSH_VERIFY_FAILED")

    def test_dry_run_plan_lists_every_step_it_would_take(self):
        sb, gh = self.sandbox()
        sb.dirty_phase()
        tool = self.tool(sb, gh, dry_run=True)
        candidates = tool.working_tree().candidates
        self.assertEqual(tool.dry_run_plan(18, BRANCH, True, sb.base, candidates, tool.tier3_argv(full=False), MESSAGE, args()), pi.EXIT_OK)
        text = self.out.getvalue()
        self.assertIn(f"    would: git switch -c {BRANCH}", text)
        self.assertIn("    would stage 4 explicit path(s)", text)

    def test_dry_run_plan_without_candidates_never_validates_or_stages(self):
        sb, gh = self.sandbox()
        tool = self.tool(sb, gh, dry_run=True)
        tool.dry_run_plan(18, BRANCH, False, sb.base, [], tool.tier3_argv(full=False), "", args(trailer=None))
        self.assertNotIn("would validate", self.out.getvalue())
        self.assertNotIn("would stage", self.out.getvalue())


class IntegratorPullRequestTests(IntegratorCase):
    def test_pr_lookups_view_and_hosted_state_of_a_prepared_branch(self):
        sb, gh = self.prepared()
        gh.set_checks(check_run())
        tool = self.tool(sb, gh)
        self.assertEqual([p["number"] for p in tool.list_prs(BRANCH)], [1])
        self.assertEqual(tool.find_pr_for(BRANCH, None)["number"], 1)
        self.assertEqual(tool.view_pr(1)["headRefOid"], sb.rev("HEAD"))
        state = tool.hosted_state(1, BRANCH)
        self.assertEqual((state["label"], state["tier3"], state["merge_allowed"]), ("MERGE_ALLOWED", "SUCCESS", True))
        self.assertEqual(tool.resolve_phase(None), (BRANCH, 18, None))

    def test_pr_lookups_of_an_unknown_branch_and_a_failed_check(self):
        sb, gh = self.prepared()
        gh.set_checks(check_run(conclusion="FAILURE"))
        tool = self.tool(sb, gh)
        self.assertEqual((tool.list_prs("phase99-none"), tool.find_pr_for("phase99-none", None)), ([], None))
        self.assertEqual(tool.hosted_state(1, BRANCH)["label"], "BLOCKED")
        sb.git("switch", "-q", "main")
        with self.assertRaises(pi.Blocked) as refused:
            tool.resolve_phase(None)
        self.assertEqual(refused.exception.code, "NOT_A_PHASE_BRANCH")

    def test_view_pr_of_an_unknown_mergeability_retries_then_returns_it(self):
        sb, gh = self.prepared()
        gh.prs[0].update(mergeable="UNKNOWN", mergeStateStatus="UNKNOWN")
        slept = []
        tool = pi.Integrator(pi.Shell(sb.work, gh), pi.Reporter(False, io.StringIO(), io.StringIO()), sleep=slept.append)
        with self.subTest("refused unknown mergeability is returned unchanged"):
            self.assertEqual(tool.view_pr(1)["mergeable"], "UNKNOWN")
        self.assertEqual(slept, [2, 2])

    def test_ensure_pr_creates_one_pr_and_pr_body_records_the_validation(self):
        sb, gh = self.prepared()
        gh.prs.clear()
        tool = self.tool(sb, gh)
        pr, created = tool.ensure_pr(BRANCH, 18, "Phase 18", sb.base, sb.rev("HEAD"), {"mode": "targeted", "result": "PASS"}, "footer text")
        self.assertEqual((pr["number"], created), (1, True))
        body = pi.Integrator.pr_body(18, sb.base, "abc", {"mode": "full", "result": "PASS"}, "footer text")
        self.assertIn("Tier-3 full (working tree vs `main`) -> **PASS**", body)
        self.assertTrue(body.endswith("footer text"))

    def test_ensure_pr_refuses_a_pr_against_another_base_and_pr_body_of_a_resumed_run_names_no_validation(self):
        sb, gh = self.prepared()
        gh.prs[0]["baseRefName"] = "develop"
        with self.assertRaises(pi.Blocked) as refused:
            self.tool(sb, gh).ensure_pr(BRANCH, 18, "t", sb.base, None, {"mode": None}, None)
        self.assertEqual(refused.exception.code, "BASE_MISMATCH")
        self.assertIn("- Local validation: not run by this invocation (resumed)", pi.Integrator.pr_body(18, sb.base, None, {"mode": None}, None))

    def test_status_and_report_evaluation_of_a_green_pr(self):
        sb, gh = self.prepared()
        gh.set_checks(check_run())
        tool = self.tool(sb, gh)
        self.assertEqual(tool.status(None), pi.EXIT_OK)
        self.assertIn("MERGE_ALLOWED", self.out.getvalue())
        pr, tree = tool.view_pr(1), tool.working_tree()
        tool.report_evaluation(pr, pi.evaluate_pr(pr, branch=BRANCH, local_sha=sb.rev("HEAD"), remote_sha=sb.rev("HEAD"), tree=tree), tree)
        self.assertIn("  Tier-3          SUCCESS", self.out.getvalue())

    def test_status_without_a_pr_and_report_evaluation_of_a_failed_check(self):
        sb, gh, _sha = self.on_branch_with_commit()
        tool = self.tool(sb, gh)
        self.assertEqual(tool.status(None), pi.EXIT_BLOCKED)
        self.assertIn("no pull request exists for this branch yet", self.out.getvalue())
        pr = {"number": 7, "state": "OPEN", "baseRefName": "main", "headRefName": BRANCH, "headRefOid": "e" * 40, "mergeable": "MERGEABLE",
              "mergeStateStatus": "CLEAN", "statusCheckRollup": [check_run(conclusion="FAILURE")]}
        tree = tool.working_tree()
        tool.report_evaluation(pr, pi.evaluate_pr(pr, branch=BRANCH, local_sha=None, remote_sha=None, tree=tree), tree)
        self.assertIn("  BLOCKER:", self.out.getvalue())

    def test_merge_merges_a_green_pr_and_synchronises_main(self):
        sb, gh = self.prepared()
        gh.set_checks(check_run())
        self.assertEqual(self.tool(sb, gh).merge(None), pi.EXIT_OK)
        self.assertEqual((gh.prs[0]["state"], sb.git("branch", "--show-current"), sb.rev("HEAD")), ("MERGED", "main", gh.prs[0]["mergeCommit"]["oid"]))

    def test_merge_refuses_a_pending_check(self):
        sb, gh = self.prepared()
        gh.set_checks(check_run("IN_PROGRESS", ""))
        with self.assertRaises(pi.Blocked) as refused:
            self.tool(sb, gh).merge(None)
        self.assertEqual((refused.exception.code, gh.pr_calls("merge")), ("MERGE_REFUSED", []))

    def test_finish_merge_synchronises_main_after_an_earlier_merge(self):
        sb, gh = self.prepared()
        gh.set_checks(check_run())
        head = gh.refresh(gh.prs[0])["headRefOid"]
        gh(("gh", "pr", "merge", "1", "--merge", "--match-head-commit", head), cwd=sb.work, timeout=30)
        self.assertEqual(self.tool(sb, gh).finish_merge(gh.refresh(gh.prs[0]), BRANCH, 18, already=True), pi.EXIT_OK)
        self.assertEqual(sb.rev("HEAD"), gh.prs[0]["mergeCommit"]["oid"])

    def test_finish_merge_reports_an_unexpected_dirty_tree(self):
        sb, gh = self.prepared()
        gh.set_checks(check_run())
        head = gh.refresh(gh.prs[0])["headRefOid"]
        gh(("gh", "pr", "merge", "1", "--merge", "--match-head-commit", head), cwd=sb.work, timeout=30)
        sb.write("stray.py", "x\n")
        with self.subTest("refused unexpected dirty tree"):
            self.assertEqual(self.tool(sb, gh).finish_merge(gh.refresh(gh.prs[0]), BRANCH, 18, already=True), pi.EXIT_BLOCKED)
        self.assertIn("PROBLEM: unexpected dirty: ?? stray.py", self.out.getvalue())
