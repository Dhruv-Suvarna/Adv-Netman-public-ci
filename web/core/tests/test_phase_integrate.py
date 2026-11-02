"""tools/phase_integrate.py: the Git/GitHub phase-integration helper (developer source-control tooling).

Real ``git`` runs against throw-away repositories (a bare "origin" plus a working clone), so the status parser,
staging, commit, push and fast-forward sync are exercised for real.  Only ``gh`` and ``tier3.py`` are faked, so
no test creates a real PR or pushes anywhere near GitHub.  Matrices (subTest) keep the suite small.
"""

from __future__ import annotations

import ast
import contextlib
import importlib.util
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from unittest import mock

from django.test import SimpleTestCase

REPO_ROOT = Path(__file__).resolve().parents[3]
TOOL_PATH = REPO_ROOT / "tools" / "phase_integrate.py"


def _load_tool():
    spec = importlib.util.spec_from_file_location("phase_integrate", TOOL_PATH)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


pi = _load_tool()
BRANCH = "phase18-raw-configlets"
MESSAGE = "Phase 18: add Raw Configlets and isolated verifier sandbox"
TIER3_CHECK = {"__typename": "CheckRun", "name": "Tier-3 validation", "workflowName": "Tier-3 validation"}


def check_run(status="COMPLETED", conclusion="SUCCESS", **over):
    return {**TIER3_CHECK, "status": status, "conclusion": conclusion, **over}


class Sandbox:
    """A bare origin, a working clone and a second clone used to play GitHub's merge button."""

    def __init__(self, tmp: Path):
        self.tmp, self.origin, self.work, self.merger = tmp, tmp / "origin.git", tmp / "work", tmp / "merger"
        self.git("init", "-q", "--bare", "-b", "main", str(self.origin), cwd=tmp)
        self.git("clone", "-q", str(self.origin), str(self.work), cwd=tmp)
        self.git("symbolic-ref", "HEAD", "refs/heads/main")
        for rel, text in {"README.md": "readme\n", "app.py": "print('app')\n", "docs/notes.md": "notes\n", "Run_Logs.log": "run log\n",
                          "logs/R1.log": "r1\n", "logs/R2.log": "r2\n"}.items():
            self.write(rel, text)
        self.git("add", "--", ".")
        self.git("commit", "-q", "-m", "initial")
        self.git("push", "-q", "-u", "origin", "main")
        self.git("clone", "-q", str(self.origin), str(self.merger), cwd=tmp)
        self.base = self.rev("HEAD")

    def git(self, *args, cwd=None, check=True):
        proc = subprocess.run(["git", *args], cwd=str(cwd or self.work), capture_output=True, text=True)
        if check and proc.returncode != 0:
            raise AssertionError(f"git {' '.join(args)} failed: {proc.stderr}")
        return proc.stdout.strip()

    def write(self, rel, text):
        target = self.work / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text)

    def rev(self, ref, cwd=None):
        return self.git("rev-parse", ref, cwd=cwd)

    def ok(self, *args):
        return subprocess.run(["git", *args], cwd=str(self.work), capture_output=True).returncode == 0

    def entries(self):
        raw = subprocess.run(["git", "status", "--porcelain=v1", "-z", "--untracked-files=all", "--no-renames"], cwd=str(self.work), capture_output=True, text=True).stdout
        return {(e.xy, e.path) for e in pi.parse_status(raw)}

    def dirty_runtime(self):
        self.write("Run_Logs.log", "run log\nnoise  \n")   # trailing whitespace: must never fail the source gate
        self.write("logs/R2.log", "r2\nmore noise \n")

    def dirty_phase(self):
        """Phase-18-shaped work: modified, untracked (nested dir) and deleted source, plus the runtime logs."""
        self.write("app.py", "print('app v2')\n")
        self.write("lib/raw.py", "VALUE = 1\n")
        self.write("lib/sub/deep.py", "DEEP = 2\n")
        (self.work / "docs/notes.md").unlink()
        self.dirty_runtime()

    def staged(self):
        return sorted(p for p in self.git("diff", "--cached", "--name-only").splitlines() if p)

    def branches(self):
        return self.git("branch", "--format=%(refname:short)").split()


class FakeGitHub:
    """gh + tier3.py stand-ins; everything else runs the REAL git.  Records every argv."""

    def __init__(self, sb: Sandbox):
        self.sb = sb
        self.calls: list[tuple[str, ...]] = []
        self.prs: list[dict] = []
        self.authenticated = True
        self.tier3 = (0, {"result": "PASS_WITH_WARNINGS", "blocking_checks": [], "summary": {"selected": 5}}, False)
        self.new_pr_checks = [check_run("IN_PROGRESS", "")]
        self.hook = None  # called with argv before a real command runs (lets a test interfere realistically)

    # -- the runner protocol used by pi.Shell --
    def __call__(self, argv, *, cwd, timeout, stream_stderr=False):
        argv = tuple(argv)
        self.calls.append(argv)
        if self.hook and argv[0] == "git":
            self.hook(argv)
        if argv[0] == "gh":
            return self.gh(argv)
        if argv[0] == sys.executable:
            code, doc, timed_out = self.tier3
            return pi.Proc(argv, None if timed_out else code, json.dumps(doc), "[tier3] running static.hygiene ...\n", timed_out=timed_out)
        return pi.subprocess_runner(argv, cwd=cwd, timeout=timeout)

    def gh(self, argv):
        args = list(argv[1:])
        if args == ["--version"]:
            return pi.Proc(argv, 0, "gh version test\n")
        if args == ["auth", "status"]:
            return pi.Proc(argv, 0 if self.authenticated else 1, "", "" if self.authenticated else "not logged in")
        if args[:2] == ["pr", "list"]:
            head = args[args.index("--head") + 1] if "--head" in args else None
            found = [self.refresh(p) for p in self.prs if head is None or p["headRefName"] == head]
            return pi.Proc(argv, 0, json.dumps(found))
        if args[:2] == ["pr", "view"]:
            return pi.Proc(argv, 0, json.dumps(self.refresh(self.by_number(int(args[2])))))
        if args[:2] == ["pr", "create"]:
            opts = {args[i]: args[i + 1] for i in range(2, len(args), 2)}
            number = len(self.prs) + 1
            self.prs.append({"number": number, "url": f"https://github.test/pull/{number}", "title": opts["--title"], "_body": opts["--body"], "state": "OPEN",
                             "headRefName": opts["--head"], "baseRefName": opts["--base"], "isDraft": False, "isCrossRepository": False, "mergedAt": None,
                             "mergeable": "MERGEABLE", "mergeStateStatus": "CLEAN", "mergeCommit": None, "statusCheckRollup": list(self.new_pr_checks)})
            return pi.Proc(argv, 0, self.prs[-1]["url"] + "\n")
        if args[:2] == ["pr", "merge"]:
            pr = self.by_number(int(args[2]))
            if args[3:5] != ["--merge", "--match-head-commit"] or args[5] != self.refresh(pr)["headRefOid"]:
                return pi.Proc(argv, 1, "", "head commit mismatch")
            self.sb.git("fetch", "-q", "origin", cwd=self.sb.merger)
            self.sb.git("merge", "-q", "--no-ff", "-m", f"Merge pull request #{pr['number']}", f"origin/{pr['headRefName']}", cwd=self.sb.merger)
            self.sb.git("push", "-q", "origin", "main", cwd=self.sb.merger)
            pr.update(state="MERGED", mergeCommit={"oid": self.sb.rev("HEAD", cwd=self.sb.merger)}, mergedAt="2026-09-21T00:00:00Z")
            return pi.Proc(argv, 0, "")
        return pi.Proc(argv, 1, "", "unexpected gh call in test")

    def by_number(self, number):
        return next(p for p in self.prs if p["number"] == number)

    def refresh(self, pr):
        if pr["state"] == "OPEN":  # the PR head follows the pushed branch, like GitHub
            head = self.sb.git("rev-parse", "--verify", "--quiet", f"refs/heads/{pr['headRefName']}", cwd=self.sb.origin, check=False)
            pr["headRefOid"] = pr.get("_sha_override") or head
        return {k: v for k, v in pr.items() if not k.startswith("_")}

    def set_checks(self, *checks, **pr_fields):
        for pr in self.prs:
            pr["statusCheckRollup"] = list(checks)
            pr.update(pr_fields)

    def verbs(self):
        out = []
        for argv in self.calls:
            rest = [a for a in argv[1:] if a not in pi.GIT_GLOBAL_OPTIONS] if argv[0] == "git" else list(argv[1:])
            out.append((argv[0], rest[0] if rest else "", rest))
        return out

    def called(self, tool, verb):
        return [rest for t, v, rest in self.verbs() if t == tool and v == verb]

    def pr_calls(self, sub):
        return [rest for rest in self.called("gh", "pr") if rest[1] == sub]

    def mutating(self):
        return [c for c in self.calls if pi.classify_argv(c, self.sb.work) != pi.READ and c[0] != sys.executable]


class Result:
    def __init__(self, code, out, err):
        self.code, self.out, self.err = code, out, err

    @property
    def doc(self):
        return json.loads(self.out)


class PhaseIntegrateCase(SimpleTestCase):
    def setUp(self):
        home = Path(tempfile.mkdtemp(prefix="phase-integrate-home-"))
        env = {"HOME": str(home), "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_AUTHOR_NAME": "T", "GIT_AUTHOR_EMAIL": "t@example.test",
               "GIT_COMMITTER_NAME": "T", "GIT_COMMITTER_EMAIL": "t@example.test"}
        patcher = mock.patch.dict(os.environ, env)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.addCleanup(shutil.rmtree, home, ignore_errors=True)
        self._tmps: list[Path] = []
        self.addCleanup(lambda: [shutil.rmtree(p, ignore_errors=True) for p in self._tmps])

    def sandbox(self):
        tmp = Path(tempfile.mkdtemp(prefix="phase-integrate-")).resolve()
        self._tmps.append(tmp)
        sb = Sandbox(tmp)
        return sb, FakeGitHub(sb)

    def cli(self, sb, gh, *argv, json_mode=False):
        out, err = io.StringIO(), io.StringIO()
        args = [*argv, "--repo", str(sb.work)] + (["--json"] if json_mode else [])
        return Result(pi.main(args, runner=gh, out=out, err=err, sleep=lambda _s: None), out.getvalue(), err.getvalue())

    def adopt(self, sb, gh, *extra, json_mode=False):
        return self.cli(sb, gh, "prepare", "--phase", "18", "--slug", "raw-configlets", "--message", MESSAGE, "--adopt-working-tree", *extra, json_mode=json_mode)

    def prepared(self):
        sb, gh = self.sandbox()
        sb.dirty_phase()
        result = self.adopt(sb, gh)
        self.assertEqual(result.code, 0, result.out + result.err)
        return sb, gh


class StartTests(PhaseIntegrateCase):
    def test_start_matrix(self):
        def dirty_source(sb, _gh): sb.write("app.py", "changed\n")
        def untracked_source(sb, _gh): sb.write("new.py", "x\n")
        def staged(sb, _gh): sb.write("app.py", "changed\n"); sb.git("add", "--", "app.py")
        def wrong_branch(sb, _gh): sb.git("switch", "-q", "-c", "topic")
        def local_branch(sb, _gh): sb.git("branch", "phase19-golden")
        def remote_branch(sb, _gh):
            sb.git("switch", "-q", "-c", "phase19-golden", cwd=sb.merger)
            sb.git("push", "-q", "origin", "phase19-golden", cwd=sb.merger)
        def behind(sb, _gh):
            (sb.merger / "later.txt").write_text("later\n")
            sb.git("add", "--", "later.txt", cwd=sb.merger)
            sb.git("commit", "-q", "-m", "later", cwd=sb.merger)
            sb.git("push", "-q", "origin", "main", cwd=sb.merger)
        rows = [
            ("clean main + runtime logs", lambda sb, _g: sb.dirty_runtime(), 0, "READY"),
            ("source dirty", dirty_source, 1, "SOURCE_DIRTY"),
            ("untracked source", untracked_source, 1, "SOURCE_DIRTY"),
            ("staged content", staged, 1, "STAGED_CHANGES"),
            ("wrong branch", wrong_branch, 1, "WRONG_BRANCH"),
            ("existing local branch", local_branch, 1, "BRANCH_EXISTS"),
            ("existing remote branch", remote_branch, 1, "BRANCH_EXISTS_REMOTE"),
            ("local main behind origin", behind, 1, "BASE_OUT_OF_SYNC"),
        ]
        for name, setup, code, expected in rows:
            with self.subTest(name):
                sb, gh = self.sandbox()
                setup(sb, gh)
                before, branch_before = sb.entries(), sb.git("branch", "--show-current")
                result = self.cli(sb, gh, "start", "--phase", "19", "--slug", "golden", json_mode=True)
                self.assertEqual(result.code, code, result.out)
                doc = result.doc
                self.assertEqual(doc["result"] if code == 0 else doc["reason"], expected)
                self.assertEqual(sb.entries(), before, "the working tree (including runtime logs) is preserved")
                if code == 0:
                    self.assertEqual(sb.git("branch", "--show-current"), "phase19-golden")
                    self.assertEqual(doc["base_head"], sb.base)
                    self.assertEqual(sb.rev("HEAD"), sb.base, "start commits nothing")
                    self.assertNotIn("phase19-golden", sb.git("ls-remote", "--heads", "origin"), "start does not push")
                else:
                    self.assertEqual(sb.git("branch", "--show-current"), branch_before, "a refusal changes nothing")

    def test_start_dry_run_creates_nothing(self):
        sb, gh = self.sandbox()
        sb.dirty_runtime()
        result = self.cli(sb, gh, "start", "--phase", "19", "--slug", "golden", "--dry-run", json_mode=True)
        self.assertEqual((result.code, result.doc["result"]), (0, "DRY_RUN"))
        self.assertEqual(sb.branches(), ["main"])
        self.assertEqual(gh.mutating(), [])


class CandidateTests(PhaseIntegrateCase):
    def test_status_parser_and_candidate_derivation(self):
        raw = " M web/models.py\0?? new dir/with space.py\0 D old.py\0MM both.py\0?? Run_Logs.log\0 M logs/R2.log\0"
        tree = pi.WorkingTree(tuple(pi.parse_status(raw)))
        self.assertEqual([e.path for e in tree.candidates], ["new dir/with space.py", "old.py", "web/models.py"])
        self.assertEqual([e.path for e in tree.staged], ["both.py"])
        self.assertEqual(tree.runtime, ["Run_Logs.log", "logs/R2.log"])

    def test_real_git_candidates_modified_untracked_deleted_and_exact_runtime_exclusion(self):
        sb, gh = self.sandbox()
        sb.dirty_phase()
        sb.write("logs/R1.log", "r1 changed\n")  # a DIFFERENT tracked log is not a permitted runtime artifact
        tree = pi.Integrator(pi.Shell(sb.work, gh), pi.Reporter()).working_tree()
        by_path = {e.path: e.xy for e in tree.candidates}
        self.assertEqual(by_path, {"app.py": " M", "docs/notes.md": " D", "lib/raw.py": "??", "lib/sub/deep.py": "??", "logs/R1.log": " M"})
        self.assertEqual(tree.runtime, ["Run_Logs.log", "logs/R2.log"])
        result = self.adopt(sb, gh, json_mode=True)  # ... so preparing must refuse rather than quietly commit it
        self.assertEqual((result.code, result.doc["reason"]), (1, "SUSPICIOUS_FILES"))
        self.assertIn("logs/R1.log", result.out)

    def test_suspicious_path_matrix(self):
        rows = [
            (".env", True), ("web/.env.production", True), (".env.example", False), ("keys/server.pem", True), ("a/b.key", True), ("id_rsa", True),
            ("id_ed25519", True), ("id_rsa.pub", False), ("secrets.yml", True), ("secret_policy.py", False), ("web/db.sqlite3", True), ("backup/dump.sql", True),
            ("x.db", True), (".venv/lib/python3.12/site.py", True), ("venv/bin/activate", True), ("node_modules/a/index.js", True), ("pyvenv.cfg", True),
            ("release.tar.gz", True), ("bundle.zip", True), ("app.py.swp", True), ("notes.md~", True), (".#app.py", True), ("#app.py#", True),
            ("run/docker.sock", True), ("logs/R3.log", True), ("notes.log", True), ("monitoring/runtime/snmp.env", True), ("monitoring/runtime/.gitkeep", False),
            ("nested/repo/", True), ("web/core/models.py", False), ("docs/PHASE_INTEGRATION_WORKFLOW.md", False), ("templates/R1.cfg.j2", False),
            ("web/core/services/raw_configlets/images/frr.Dockerfile", False), ("tools/phase_integrate.py", False),
        ]
        for path, suspicious in rows:
            with self.subTest(path=path):
                self.assertEqual(pi.suspicious_reason(path) is not None, suspicious)
        self.assertIsNotNone(pi.suspicious_reason("big.bin", size=pi.MAX_CANDIDATE_BYTES + 1))
        self.assertIsNotNone(pi.suspicious_reason("link.py", symlink=True))

    def test_suspicious_file_refuses_prepare_and_is_not_deleted_or_staged(self):
        sb, gh = self.sandbox()
        sb.dirty_phase()
        sb.write(".env", "TOKEN=abc\n")
        before = sb.entries()
        result = self.adopt(sb, gh, json_mode=True)
        self.assertEqual((result.code, result.doc["reason"]), (1, "SUSPICIOUS_FILES"))
        self.assertTrue((sb.work / ".env").exists())
        self.assertEqual(sb.entries(), before)
        self.assertEqual((sb.git("branch", "--show-current"), sb.staged()), ("main", []))
        self.assertEqual(gh.mutating(), [])


class AdoptionAndPrepareTests(PhaseIntegrateCase):
    def test_adoption_creates_branch_commits_only_source_pushes_and_opens_pr_without_merging(self):
        sb, gh = self.sandbox()
        sb.dirty_phase()
        result = self.adopt(sb, gh, "--pr-title", "Phase 18: Raw Configlets and isolated verifier sandbox", "--trailer", "Co-Authored-By: Helper <helper@example.test>", json_mode=True)
        self.assertEqual(result.code, 0, result.out + result.err)
        doc = result.doc
        self.assertEqual((doc["result"], doc["branch"], doc["base_head"]), ("PR_CREATED", BRANCH, sb.base))
        self.assertEqual(sb.git("branch", "--show-current"), BRANCH)
        self.assertEqual(sb.rev("main"), sb.base, "main itself is untouched")
        committed = sorted(sb.git("diff", "--name-only", sb.base, "HEAD").splitlines())
        self.assertEqual(committed, ["app.py", "docs/notes.md", "lib/raw.py", "lib/sub/deep.py"])
        self.assertEqual(sb.git("log", "-1", "--format=%s"), MESSAGE)
        self.assertIn("Co-Authored-By: Helper <helper@example.test>", sb.git("log", "-1", "--format=%B"))
        self.assertEqual(sb.entries(), {(" M", "Run_Logs.log"), (" M", "logs/R2.log")}, "runtime logs survive: dirty, unstaged")
        self.assertEqual(sb.staged(), [])
        self.assertEqual(sb.rev(BRANCH), sb.rev(f"refs/heads/{BRANCH}", cwd=sb.origin), "pushed to origin")
        self.assertEqual(sb.git("rev-parse", f"{BRANCH}@{{upstream}}"), sb.rev("HEAD"), "upstream tracking is set")
        pr = gh.prs[0]
        self.assertEqual((pr["baseRefName"], pr["headRefName"], pr["title"], pr["state"]), ("main", BRANCH, "Phase 18: Raw Configlets and isolated verifier sandbox", "OPEN"))
        for needle in (sb.base, sb.rev("HEAD"), "PASS_WITH_WARNINGS", "Tier-3 validation", "Run_Logs.log", "logs/R2.log"):
            self.assertIn(needle, pr["_body"])
        self.assertEqual(gh.pr_calls("merge"), [], "prepare never merges")
        self.assertEqual(len(gh.pr_calls("create")), 1)
        self.assertEqual(doc["hosted_state"], "WAITING_FOR_CI")
        self.assertFalse(doc["merge_allowed"])

    def test_adoption_preconditions(self):
        def staged(sb): sb.git("add", "--", "app.py")
        def on_topic(sb): sb.git("switch", "-q", "-c", "topic")
        def branch_taken(sb): sb.git("branch", BRANCH)
        rows = [
            ("staged content", staged, 1, "STAGED_CHANGES"),
            ("not on main", on_topic, 1, "WRONG_BRANCH"),
            ("branch already exists", branch_taken, 1, "BRANCH_EXISTS"),
        ]
        for name, prep, code, reason in rows:
            with self.subTest(name):
                sb, gh = self.sandbox()
                sb.dirty_phase()
                prep(sb)
                before = sb.entries()
                result = self.adopt(sb, gh, json_mode=True)
                self.assertEqual((result.code, result.doc["reason"]), (code, reason))
                self.assertEqual(sb.entries(), before)
                self.assertEqual(gh.called("git", "commit") + gh.called("git", "push"), [])
        with self.subTest("no source changes (runtime logs only)"):
            sb, gh = self.sandbox()
            sb.dirty_runtime()
            result = self.adopt(sb, gh, json_mode=True)
            self.assertEqual((result.code, result.doc["reason"]), (1, "NO_SOURCE_CHANGES"))
        with self.subTest("adoption needs an explicit slug"):
            sb, gh = self.sandbox()
            sb.dirty_phase()
            result = self.cli(sb, gh, "prepare", "--phase", "18", "--message", MESSAGE, "--adopt-working-tree")
            self.assertEqual(result.code, 2)

    def test_staging_uses_only_explicit_source_paths(self):
        sb, gh = self.prepared()
        adds = gh.called("git", "add")
        self.assertEqual(sorted(rest[-1] for rest in adds), ["app.py", "docs/notes.md", "lib/raw.py", "lib/sub/deep.py"])
        for rest in adds:
            self.assertEqual(rest[:2], ["add", "--"])
            self.assertEqual(len(rest), 3)
            self.assertNotIn(rest[-1], pi.RUNTIME_ARTIFACTS)
        self.assertEqual(gh.called("git", "commit")[0][:2], ["commit", "-m"])
        self.assertNotIn("-a", gh.called("git", "commit")[0])

    def test_staging_mismatch_aborts_before_commit_and_unstages_only_our_paths(self):
        def foreign_file(sb):  # a non-candidate path gets modified and staged behind the tool's back
            sb.write("README.md", "changed by someone else\n")
            sb.git("add", "--", "README.md")

        def runtime_log(sb):
            sb.git("add", "--", "Run_Logs.log")

        for name, sneak, foreign in (("an extra foreign file", foreign_file, "README.md"), ("a runtime log", runtime_log, "Run_Logs.log")):
            with self.subTest(name):
                sb, gh = self.sandbox()
                sb.dirty_phase()
                fired = []

                def hook(argv, sneak=sneak, sb=sb, fired=fired):
                    if "add" in argv and not fired:
                        fired.append(1)
                        sneak(sb)
                gh.hook = hook
                head = sb.rev("HEAD")
                result = self.adopt(sb, gh, json_mode=True)
                self.assertEqual((result.code, result.doc["reason"]), (1, "STAGING_MISMATCH"), result.out)
                self.assertEqual(sb.rev("HEAD"), head, "aborted before commit")
                self.assertEqual(gh.called("git", "commit") + gh.called("git", "push") + gh.pr_calls("create"), [])
                self.assertEqual(sb.staged(), [foreign], "only the tool's own staging is rolled back; foreign state is not touched")
                self.assertEqual((sb.work / "app.py").read_text(), "print('app v2')\n", "working-tree content is never lost")
                self.assertTrue((sb.work / "lib/sub/deep.py").exists())

    def test_validation_gate(self):
        with self.subTest("pass with warnings continues; targeted by default"):
            sb, gh = self.prepared()
            argv = next(c for c in gh.calls if c[0] == sys.executable)
            self.assertEqual(argv[1:], (str(sb.work / "tier3.py"), "--base", "main", "--working-tree", "--format", "json"))
        with self.subTest("--full requests the full regression"):
            sb, gh = self.sandbox()
            sb.dirty_phase()
            self.adopt(sb, gh, "--full")
            argv = next(c for c in gh.calls if c[0] == sys.executable)
            self.assertEqual(argv[-2:], ("--mode", "full"))
        failures = {
            "FAIL": (1, {"result": "FAIL", "blocking_checks": ["django.tests"]}, False),
            "INCOMPLETE": (3, {"result": "INCOMPLETE", "blocking_checks": ["django.check"]}, False),
            "timeout": (0, {}, True),
        }
        for name, tier3 in failures.items():
            with self.subTest(f"validation {name} -> no branch, stage, commit, push or PR"):
                sb, gh = self.sandbox()
                sb.dirty_phase()
                gh.tier3 = tier3
                before = sb.entries()
                result = self.adopt(sb, gh, json_mode=True)
                self.assertEqual((result.code, result.doc["reason"]), (1, "VALIDATION_FAILED"))
                self.assertEqual(sb.entries(), before, "the operator's working tree is left intact")
                self.assertEqual((sb.git("branch", "--show-current"), sb.branches(), sb.staged()), ("main", ["main"], []))
                self.assertEqual(gh.mutating(), [])
                self.assertEqual(gh.prs, [])
        with self.subTest("commit happens strictly after validation, push after commit, PR after push"):
            sb, gh = self.prepared()
            first = {name: next(i for i, c in enumerate(gh.calls) if pred(c)) for name, pred in {
                "tier3": lambda c: c[0] == sys.executable, "commit": lambda c: c[0] == "git" and "commit" in c, "push": lambda c: c[0] == "git" and "push" in c,
                "pr": lambda c: c[:3] == ("gh", "pr", "create")}.items()}
            self.assertLess(first["tier3"], first["commit"])
            self.assertLess(first["commit"], first["push"])
            self.assertLess(first["push"], first["pr"])

    def test_push_is_explicit_never_forced_and_correct_branch(self):
        sb, gh = self.prepared()
        pushes = gh.called("git", "push")
        self.assertEqual(pushes, [["push", "-u", "origin", BRANCH]])
        for argv in gh.calls:
            for token in argv:
                self.assertFalse(token.startswith("--force") or token == "-f", argv)

    def test_existing_or_diverged_remote_branch_is_never_overwritten(self):
        def someone_else_pushed(sb):
            sb.git("switch", "-q", "-c", BRANCH, cwd=sb.merger)
            (sb.merger / "other.txt").write_text("someone else\n")
            sb.git("add", "--", "other.txt", cwd=sb.merger)
            sb.git("commit", "-q", "-m", "other", cwd=sb.merger)
            sb.git("push", "-q", "origin", BRANCH, cwd=sb.merger)

        with self.subTest("adoption refuses an existing remote branch outright"):
            sb, gh = self.sandbox()
            sb.dirty_phase()
            someone_else_pushed(sb)
            result = self.adopt(sb, gh, json_mode=True)
            self.assertEqual((result.code, result.doc["reason"]), (1, "BRANCH_EXISTS_REMOTE"))
            self.assertEqual(gh.called("git", "push"), [])
        with self.subTest("a normal prepare stops before pushing over diverged history"):
            sb, gh = self.sandbox()
            self.assertEqual(self.cli(sb, gh, "start", "--phase", "18", "--slug", "raw-configlets").code, 0)
            sb.dirty_phase()
            someone_else_pushed(sb)
            result = self.cli(sb, gh, "prepare", "--phase", "18", "--message", MESSAGE, json_mode=True)
            self.assertEqual((result.code, result.doc["reason"]), (1, "REMOTE_DIVERGED"))
            self.assertEqual(gh.called("git", "push") + gh.pr_calls("create"), [], "no push, no force, no PR")

    def test_github_cli_must_be_authenticated_before_anything_is_committed(self):
        sb, gh = self.sandbox()
        sb.dirty_phase()
        gh.authenticated = False
        before = sb.entries()
        result = self.adopt(sb, gh, json_mode=True)
        self.assertEqual((result.code, result.doc["reason"]), (1, "GH_UNAUTHENTICATED"))
        self.assertEqual((sb.entries(), sb.branches(), sb.rev("HEAD")), (before, ["main"], sb.base))
        self.assertEqual(gh.mutating(), [])

    def test_rerun_reuses_the_pr_and_a_follow_up_commit_is_pushed_to_it(self):
        sb, gh = self.prepared()
        head = sb.rev("HEAD")
        again = self.cli(sb, gh, "prepare", "--phase", "18", json_mode=True)
        self.assertEqual((again.code, again.doc["result"], len(gh.prs), sb.rev("HEAD")), (0, "PR_REUSED", 1, head), "resume: no new commit, no duplicate PR")
        sb.write("app.py", "print('app v3')\n")
        follow = self.cli(sb, gh, "prepare", "--phase", "18", "--message", "Phase 18: address review", json_mode=True)
        self.assertEqual((follow.code, follow.doc["result"], len(gh.prs)), (0, "PR_REUSED", 1))
        self.assertNotEqual(sb.rev("HEAD"), head)
        self.assertEqual(sb.rev(BRANCH), sb.rev(f"refs/heads/{BRANCH}", cwd=sb.origin))
        self.assertEqual(gh.pr_calls("merge"), [])
        self.assertEqual(len(gh.pr_calls("create")), 1)

    def test_pr_with_the_wrong_base_is_not_reused(self):
        sb, gh = self.prepared()
        gh.prs[0]["baseRefName"] = "develop"
        self.assertEqual(self.cli(sb, gh, "prepare", "--phase", "18", json_mode=True).doc["reason"], "BASE_MISMATCH")

    def test_merged_pr_blocks_reopening_the_same_branch(self):
        sb, gh = self.prepared()
        gh.prs[0]["state"] = "MERGED"
        result = self.cli(sb, gh, "prepare", "--phase", "18", json_mode=True)
        self.assertEqual((result.code, result.doc["reason"]), (1, "PR_ALREADY_MERGED"))

    def test_prepare_requires_the_matching_phase_branch(self):
        sb, gh = self.sandbox()
        sb.dirty_phase()
        self.assertEqual(self.cli(sb, gh, "prepare", "--phase", "18", "--message", MESSAGE, json_mode=True).doc["reason"], "WRONG_BRANCH")
        sb.git("switch", "-q", "-c", BRANCH)
        self.assertEqual(self.cli(sb, gh, "prepare", "--phase", "19", "--message", MESSAGE, json_mode=True).doc["reason"], "BRANCH_MISMATCH")

    def test_prepare_dry_run_reads_only(self):
        sb, gh = self.sandbox()
        sb.dirty_phase()
        before = sb.entries()
        result = self.adopt(sb, gh, "--dry-run", json_mode=True)
        self.assertEqual((result.code, result.doc["result"]), (0, "DRY_RUN"))
        self.assertEqual(result.doc["candidates"], ["app.py", "docs/notes.md", "lib/raw.py", "lib/sub/deep.py"])
        self.assertEqual(result.doc["excluded"], ["Run_Logs.log", "logs/R2.log"])
        self.assertEqual(gh.mutating(), [])
        self.assertFalse([c for c in gh.calls if c[0] == sys.executable], "dry run runs no validation (documented boundary)")
        self.assertEqual((sb.entries(), sb.branches(), sb.rev("HEAD")), (before, ["main"], sb.base))


class HostedStatusTests(PhaseIntegrateCase):
    @staticmethod
    def pr(rollup, **over):
        sha = "a" * 40
        return {"state": "OPEN", "baseRefName": "main", "headRefName": BRANCH, "headRefOid": sha, "isDraft": False, "isCrossRepository": False,
                "mergeable": "MERGEABLE", "mergeStateStatus": "CLEAN", "statusCheckRollup": rollup, **over}

    def evaluate(self, pr, **over):
        kwargs = {"branch": BRANCH, "local_sha": "a" * 40, "remote_sha": "a" * 40, "tree": pi.WorkingTree(())}
        kwargs.update(over)
        return pi.evaluate_pr(pr, **kwargs)

    def test_tier3_state_matrix(self):
        rows = [
            ("success", [check_run()], "SUCCESS", "allowed"),
            ("in progress", [check_run("IN_PROGRESS", "")], "PENDING", "waiting"),
            ("queued", [check_run("QUEUED", "")], "PENDING", "waiting"),
            ("failure", [check_run(conclusion="FAILURE")], "FAILURE", "blocked"),
            ("cancelled", [check_run(conclusion="CANCELLED")], "CANCELLED", "blocked"),
            ("timed out", [check_run(conclusion="TIMED_OUT")], "TIMED_OUT", "blocked"),
            ("skipped", [check_run(conclusion="SKIPPED")], "SKIPPED", "blocked"),
            ("action required", [check_run(conclusion="ACTION_REQUIRED")], "ACTION_REQUIRED", "blocked"),
            ("stale / unrecognised conclusion", [check_run(conclusion="STALE")], "UNKNOWN", "blocked"),
            ("neutral is not success", [check_run(conclusion="NEUTRAL")], "NEUTRAL", "blocked"),
            ("not reported yet", [], "MISSING", "waiting"),
            ("only an unrelated check", [check_run(name="lint", workflowName="Lint")], "MISSING", "waiting"),
            ("same name, other workflow (spoof)", [check_run(workflowName="Somebody else")], "MISSING", "waiting"),
            ("worst run wins over an older success", [check_run(), check_run(conclusion="FAILURE")], "FAILURE", "blocked"),
            ("success but another check fails", [check_run(), check_run(name="lint", workflowName="Lint", conclusion="FAILURE")], "SUCCESS", "blocked"),
            ("success, another check pending", [check_run(), check_run("IN_PROGRESS", "", name="lint", workflowName="Lint")], "SUCCESS", "waiting"),
            ("success, optional checks neutral / skipped", [check_run(), check_run(name="a", workflowName="A", conclusion="NEUTRAL"), check_run(name="b", workflowName="B", conclusion="SKIPPED")], "SUCCESS", "allowed"),
            ("status context failure", [check_run(), {"__typename": "StatusContext", "context": "ci/x", "state": "FAILURE"}], "SUCCESS", "blocked"),
        ]
        for name, rollup, tier3, expected in rows:
            with self.subTest(name):
                ev = self.evaluate(self.pr(rollup))
                self.assertEqual(ev.tier3, tier3)
                actual = "allowed" if ev.merge_allowed else ("blocked" if ev.blockers else "waiting")
                self.assertEqual(actual, expected, (ev.blockers, ev.waiting))

    def test_pr_identity_and_merge_state_matrix(self):
        ok = [check_run()]
        rows = [
            ("closed PR", self.pr(ok, state="CLOSED"), {}, "PR_NOT_OPEN"),
            ("wrong base", self.pr(ok, baseRefName="develop"), {}, "BASE_MISMATCH"),
            ("wrong head", self.pr(ok, headRefName="phase19-other"), {}, "HEAD_MISMATCH"),
            ("fork PR", self.pr(ok, isCrossRepository=True), {}, "CROSS_REPOSITORY"),
            ("draft", self.pr(ok, isDraft=True), {}, "DRAFT"),
            ("PR head != local", self.pr(ok, headRefOid="b" * 40), {}, "SHA_MISMATCH"),
            ("local != remote", self.pr(ok), {"remote_sha": "c" * 40}, "SHA_MISMATCH"),
            ("no local branch", self.pr(ok), {"local_sha": None}, "LOCAL_BRANCH_MISSING"),
            ("conflicts", self.pr(ok, mergeable="CONFLICTING", mergeStateStatus="DIRTY"), {}, "NOT_MERGEABLE"),
            ("behind", self.pr(ok, mergeStateStatus="BEHIND"), {}, "MERGE_STATE_BEHIND"),
            ("blocked by policy", self.pr(ok, mergeStateStatus="BLOCKED"), {}, "MERGE_STATE_BLOCKED"),
            ("new source edits", self.pr(ok), {"tree": pi.WorkingTree((pi.Entry(" M", "app.py"),))}, "SOURCE_MODIFIED"),
            ("staged edits", self.pr(ok), {"tree": pi.WorkingTree((pi.Entry("M ", "app.py"),))}, "STAGED_CHANGES"),
        ]
        for name, pr, over, code in rows:
            with self.subTest(name):
                ev = self.evaluate(pr, **over)
                self.assertFalse(ev.merge_allowed)
                self.assertTrue(any(b.startswith(code) for b in ev.blockers), ev.blockers)
        for name, pr in (("mergeable unknown", self.pr(ok, mergeable="UNKNOWN")), ("merge state unknown", self.pr(ok, mergeStateStatus="UNKNOWN"))):
            with self.subTest(name):
                ev = self.evaluate(pr)
                self.assertEqual((ev.merge_allowed, ev.blockers), (False, []))
        with self.subTest("runtime logs dirty do not matter"):
            tree = pi.WorkingTree((pi.Entry(" M", "Run_Logs.log"), pi.Entry(" M", "logs/R2.log")))
            self.assertTrue(self.evaluate(self.pr(ok), tree=tree).merge_allowed)

    def test_status_command_is_read_only_and_reports_the_hosted_state(self):
        sb, gh = self.prepared()
        gh.calls.clear()
        cases = [([check_run("IN_PROGRESS", "")], "WAITING_FOR_CI", 0), ([check_run()], "MERGE_ALLOWED", 0), ([check_run(conclusion="FAILURE")], "BLOCKED", 1), ([], "WAITING_FOR_CI", 0)]
        for rollup, label, code in cases:
            with self.subTest(label=label, rollup=[c.get("conclusion") or c.get("status") for c in rollup]):
                gh.set_checks(*rollup)
                result = self.cli(sb, gh, "status", json_mode=True)
                doc = result.doc
                self.assertEqual((result.code, doc["result"]), (code, label))
                self.assertEqual((doc["pr_number"], doc["branch"], doc["phase"], doc["base"], doc["head"]), (1, BRANCH, 18, "main", BRANCH))
                self.assertEqual(doc["phase_head"], sb.rev("HEAD"))
                self.assertEqual(doc["merge_allowed"], label == "MERGE_ALLOWED")
        for argv in gh.calls:
            self.assertEqual(pi.classify_argv(argv, sb.work), pi.READ, argv)
        human = self.cli(sb, gh, "status")
        self.assertIn("phase 18", human.out)
        self.assertIn(BRANCH, human.out)

    def test_status_from_main_finds_the_phase_pr_and_no_pr_is_reported(self):
        sb, gh = self.prepared()
        gh.set_checks(check_run())
        sb.git("switch", "-q", "main")
        self.assertEqual(self.cli(sb, gh, "status", json_mode=True).doc["reason"], "NOT_A_PHASE_BRANCH")
        found = self.cli(sb, gh, "status", "--phase", "18", json_mode=True)
        self.assertEqual((found.code, found.doc["result"], found.doc["branch"]), (0, "MERGE_ALLOWED", BRANCH))
        gh.prs.clear()
        none = self.cli(sb, gh, "status", "--phase", "18", json_mode=True)
        self.assertEqual((none.code, none.doc["reason"]), (1, "NO_PR"))


class MergeTests(PhaseIntegrateCase):
    def refuse(self, sb, gh, *, reason="MERGE_REFUSED"):
        head = sb.rev("HEAD")
        result = self.cli(sb, gh, "merge", json_mode=True)
        self.assertEqual((result.code, result.doc["reason"]), (1, reason), result.out)
        self.assertEqual(gh.pr_calls("merge"), [], "refused: gh pr merge was never invoked")
        self.assertEqual(sb.rev("HEAD"), head)
        return result

    def test_merge_is_refused_unless_every_condition_holds(self):
        def tweak(**fields):
            return lambda sb, gh: (gh.set_checks(check_run(), **fields))
        def sha_mismatch(sb, gh): gh.set_checks(check_run()); gh.prs[0]["_sha_override"] = "d" * 40
        def dirty_source(sb, gh): gh.set_checks(check_run()); sb.write("app.py", "edited after prepare\n")
        def untracked_source(sb, gh): gh.set_checks(check_run()); sb.write("new_after.py", "x\n")
        def unpushed_commit(sb, gh):
            gh.set_checks(check_run())
            sb.write("app.py", "later\n")
            sb.git("add", "--", "app.py")
            sb.git("commit", "-q", "-m", "local only")
        rows = [
            ("pending check", lambda sb, gh: gh.set_checks(check_run("IN_PROGRESS", "")), "TIER3_PENDING"),
            ("queued check", lambda sb, gh: gh.set_checks(check_run("QUEUED", "")), "TIER3_PENDING"),
            ("failed check", lambda sb, gh: gh.set_checks(check_run(conclusion="FAILURE")), "TIER3_FAILURE"),
            ("cancelled check", lambda sb, gh: gh.set_checks(check_run(conclusion="CANCELLED")), "TIER3_CANCELLED"),
            ("skipped check", lambda sb, gh: gh.set_checks(check_run(conclusion="SKIPPED")), "TIER3_SKIPPED"),
            ("no check reported", lambda sb, gh: gh.set_checks(), "TIER3_MISSING"),
            ("wrong base", tweak(baseRefName="develop"), "BASE_MISMATCH"),
            ("PR belongs to another head branch", tweak(headRefName="phase19-other"), "NO_PR"),
            ("SHA mismatch", sha_mismatch, "SHA_MISMATCH"),
            ("local commit not on the PR", unpushed_commit, "SHA_MISMATCH"),
            ("modified source after prepare", dirty_source, "SOURCE_MODIFIED"),
            ("untracked source after prepare", untracked_source, "SOURCE_MODIFIED"),
            ("merge conflicts", tweak(mergeable="CONFLICTING", mergeStateStatus="DIRTY"), "NOT_MERGEABLE"),
        ]
        for name, prep, expected in rows:
            with self.subTest(name):
                sb, gh = self.prepared()
                prep(sb, gh)
                result = self.refuse(sb, gh, reason="NO_PR" if expected == "NO_PR" else "MERGE_REFUSED")
                self.assertIn(expected, result.doc["message"] if expected != "NO_PR" else "NO_PR")

    def test_successful_merge_uses_a_merge_commit_pinned_to_the_head_and_syncs_main(self):
        sb, gh = self.prepared()
        phase_head = sb.rev("HEAD")
        gh.set_checks(check_run())
        result = self.cli(sb, gh, "merge", json_mode=True)
        self.assertEqual(result.code, 0, result.out + result.err)
        merges = gh.pr_calls("merge")
        self.assertEqual(merges, [["pr", "merge", "1", "--merge", "--match-head-commit", phase_head]])
        for banned in ("--squash", "--rebase", "--auto", "--admin", "--delete-branch"):
            self.assertNotIn(banned, merges[0])
        doc = result.doc
        origin_main = sb.rev("refs/heads/main", cwd=sb.origin)
        self.assertEqual((doc["result"], doc["already_merged"]), ("MERGED", False))
        self.assertEqual((sb.git("branch", "--show-current"), sb.rev("HEAD"), doc["final_main_head"], doc["merge_commit"]), ("main", origin_main, origin_main, origin_main))
        self.assertEqual(len(sb.git("rev-list", "--parents", "-n", "1", "HEAD").split()), 3, "a real merge commit (two parents)")
        self.assertTrue(sb.ok("merge-base", "--is-ancestor", phase_head, "HEAD"), "the phase commit is preserved in history")
        self.assertEqual(sb.entries(), {(" M", "Run_Logs.log"), (" M", "logs/R2.log")}, "runtime logs survive the merge and the sync")
        self.assertIn(BRANCH, sb.branches(), "branches are not deleted")
        self.assertIn(("pull", "--ff-only", "origin", "main"), [tuple(r) for r in gh.called("git", "pull")])
        self.assertEqual(gh.called("git", "reset") + gh.called("git", "rebase") + gh.called("git", "clean") + gh.called("git", "stash"), [])

    def test_merge_from_main_by_phase_and_rerun_is_idempotent(self):
        sb, gh = self.prepared()
        gh.set_checks(check_run())
        sb.git("switch", "-q", "main")
        first = self.cli(sb, gh, "merge", "--phase", "18", json_mode=True)
        self.assertEqual((first.code, first.doc["result"]), (0, "MERGED"))
        again = self.cli(sb, gh, "merge", "--phase", "18", json_mode=True)
        self.assertEqual((again.code, again.doc["result"], again.doc["already_merged"]), (0, "MERGED", True))
        self.assertEqual(len(gh.pr_calls("merge")), 1, "an already merged PR is never merged twice")
        self.assertEqual(again.doc["final_main_head"], sb.rev("refs/heads/main", cwd=sb.origin))

    def test_merge_dry_run_verifies_but_merges_nothing(self):
        sb, gh = self.prepared()
        gh.set_checks(check_run())
        result = self.cli(sb, gh, "merge", "--dry-run", json_mode=True)
        self.assertEqual((result.code, result.doc["result"]), (0, "DRY_RUN"))
        self.assertEqual(sb.git("branch", "--show-current"), BRANCH)
        self.assertEqual(gh.pr_calls("merge") + gh.called("git", "pull") + gh.called("git", "switch")[1:], [])
        gh.set_checks(check_run("IN_PROGRESS", ""))
        self.assertEqual(self.cli(sb, gh, "merge", "--dry-run", json_mode=True).code, 1, "a dry run still refuses what a real merge would refuse")

    def test_unexpected_dirty_source_after_merge_is_reported_not_cleaned(self):
        sb, gh = self.prepared()
        gh.prs[0]["state"] = "MERGED"  # merged on GitHub earlier
        sb.git("switch", "-q", "main")
        sb.write("stray.py", "left behind\n")
        merged = self.cli(sb, gh, "merge", "--phase", "18", json_mode=True)
        self.assertEqual((merged.code, merged.doc["result"]), (1, "MERGED_LOCAL_STATE_UNEXPECTED"))
        self.assertTrue((sb.work / "stray.py").exists(), "nothing is silently cleaned")
        self.assertEqual(sb.entries() - {(" M", "Run_Logs.log"), (" M", "logs/R2.log")}, {("??", "stray.py")})


class SecurityTests(PhaseIntegrateCase):
    def test_slug_and_phase_grammar(self):
        bad_slugs = ["", "-lead", "Upper", "a b", "a;rm -rf /", "$(id)", "a/b", "../x", "a--b", "trail-", "x" * 61, "a\nb", "a`b`", "é"]
        for slug in bad_slugs:
            with self.subTest(slug=slug):
                with self.assertRaises(pi.UsageError):
                    pi.validate_slug(slug)
        for good in ("raw-configlets", "a", "golden-probation-bundles", "x1-y2"):
            self.assertEqual(pi.validate_slug(good), good)
        for phase in ("0", "01", "abc", "-1", "1000", "1;ls", "", " 18", "1.0", "1.01", "1.1000", "1.2.3"):
            with self.subTest(phase=phase):
                with self.assertRaises(pi.UsageError):
                    pi.validate_phase(phase)
        self.assertEqual(pi.branch_name(19, "golden-probation-bundles"), "phase19-golden-probation-bundles")
        self.assertEqual(pi.validate_phase("20.5"), "20.5")
        self.assertEqual(pi.branch_name("20.5", "device-builder-nsot"), "phase20.5-device-builder-nsot")
        self.assertEqual(pi.parse_branch("phase20.5-device-builder-nsot"), ("20.5", "device-builder-nsot"))
        sb, gh = self.sandbox()
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as raised:  # argparse itself refuses an option-shaped value
                self.cli(sb, gh, "start", "--phase", "19", "--slug", "-rf")
        self.assertEqual(raised.exception.code, 2)
        for slug in ("--slug=-rf", "--slug=a;touch PWNED", "--slug=Upper"):
            with self.subTest(slug=slug), contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(self.cli(sb, gh, "start", "--phase", "19", slug).code, 2)
        self.assertEqual(gh.calls, [], "invalid input is rejected before any command runs")

    def test_shell_metacharacters_in_message_and_title_never_reach_a_shell(self):
        sb, gh = self.sandbox()
        sb.dirty_phase()
        nasty = 'Phase 18: "quoted"; touch PWNED $(touch PWNED2) `touch PWNED3` && echo x'
        result = self.cli(sb, gh, "prepare", "--phase", "18", "--slug", "raw-configlets", "--message", nasty, "--adopt-working-tree", "--pr-title", nasty, json_mode=True)
        self.assertEqual(result.code, 0, result.out + result.err)
        self.assertEqual(sb.git("log", "-1", "--format=%s"), nasty)
        self.assertEqual(gh.prs[0]["title"], nasty)
        for marker in ("PWNED", "PWNED2", "PWNED3"):
            self.assertFalse((sb.work / marker).exists() or (Path.cwd() / marker).exists())

    def test_allowlist_accepts_the_workflow_and_rejects_everything_else(self):
        repo = Path("/repo")
        G = ("git", "--no-pager", "--literal-pathspecs")
        allowed = [
            (G + ("status", "--porcelain=v1"), pi.READ), (G + ("add", "--", "web/core/models.py"), pi.MUTATE), (G + ("restore", "--staged", "--", "a.py"), pi.MUTATE),
            (G + ("switch", "-c", BRANCH), pi.MUTATE), (G + ("switch", "main"), pi.MUTATE), (G + ("commit", "-m", "msg"), pi.MUTATE),
            (G + ("commit", "-m", "msg", "--trailer", "Co-Authored-By: A <a@b.c>"), pi.MUTATE), (G + ("push", "-u", "origin", BRANCH), pi.MUTATE),
            (G + ("pull", "--ff-only", "origin", "main"), pi.MUTATE), (("gh", "pr", "list", "--json", "number"), pi.READ),
            (("gh", "pr", "create", "--base", "main", "--head", BRANCH, "--title", "T", "--body", "B"), pi.MUTATE),
            (("gh", "pr", "merge", "7", "--merge", "--match-head-commit", "a" * 40), pi.MUTATE),
            ((sys.executable, str(repo / "tier3.py"), "--base", "main", "--working-tree", "--format", "json", "--mode", "full"), pi.VALIDATE),
        ]
        for argv, kind in allowed:
            with self.subTest(argv=argv):
                self.assertEqual(pi.classify_argv(argv, repo), kind)
        forbidden = [
            G + ("add", "."), G + ("add", "-A"), G + ("add", "--all"), G + ("add", "-u"), G + ("add", "--", "."), G + ("add", "--", "Run_Logs.log"),
            G + ("add", "--", "logs/R2.log"), G + ("add", "--", "a.py", "b.py"), G + ("add", "--", "../x"), G + ("add", "--", "/etc/passwd"),
            G + ("commit", "-a", "-m", "x"), G + ("commit", "-am", "x"), G + ("commit", "--amend", "-m", "x"), G + ("commit", "--no-verify", "-m", "x"),
            G + ("push", "--force", "origin", BRANCH), G + ("push", "-f", "origin", BRANCH), G + ("push", "--force-with-lease", "origin", BRANCH),
            G + ("push", "-u", "origin", "main"), G + ("push", "-u", "origin", BRANCH, "--force"), G + ("push", "origin", f"+{BRANCH}"),
            G + ("reset", "--hard"), G + ("clean", "-fd"), G + ("stash",), G + ("checkout", "main"), G + ("rebase", "main"), G + ("merge", BRANCH),
            G + ("branch", "-D", BRANCH), G + ("restore", "--", "a.py"), G + ("pull", "origin", "main"), G + ("pull", "--rebase", "origin", "main"),
            G + ("switch", "-C", BRANCH), G + ("switch", "topic"), G + ("config", "user.name", "x"),
            ("gh", "pr", "merge", "7", "--squash"), ("gh", "pr", "merge", "7", "--rebase"), ("gh", "pr", "merge", "7", "--auto"), ("gh", "pr", "merge", "7", "--merge"),
            ("gh", "pr", "merge", "7", "--merge", "--match-head-commit", "a" * 40, "--admin"), ("gh", "pr", "merge", "7", "--merge", "--match-head-commit", "a" * 40, "--delete-branch"),
            ("gh", "pr", "create", "--base", "develop", "--head", BRANCH, "--title", "T", "--body", "B"), ("gh", "pr", "close", "7"), ("gh", "api", "-X", "DELETE", "x"),
            ("gh", "auth", "login"), ("gh", "repo", "delete", "x"), ("rm", "-rf", "."), ("bash", "-c", "git add ."), ("python", "master.py"),
            (sys.executable, str(repo / "master.py")), (sys.executable, str(repo / "tier3.py"), "--lab"), (sys.executable, str(repo / "tier3.py"), "--base", "HEAD~1"),
        ]
        for argv in forbidden:
            with self.subTest(argv=argv):
                with self.assertRaises(pi.UnsafeCommand):
                    pi.classify_argv(argv, repo)

    def test_every_command_of_a_full_prepare_and_merge_passes_an_independent_safety_predicate(self):
        sb, gh = self.prepared()
        gh.set_checks(check_run())
        self.assertEqual(self.cli(sb, gh, "merge").code, 0)
        banned_verbs = {"reset", "clean", "stash", "checkout", "rebase", "merge", "cherry-pick", "revert", "rm", "gc", "fetch"}
        for argv in gh.calls:
            with self.subTest(argv=argv):
                self.assertIn(argv[0], ("git", "gh", sys.executable))
                tokens = set(argv[1:])
                self.assertFalse(tokens & {"-A", "--all", "-a", "--amend", "--squash", "--rebase", "--auto", "--admin", "--delete-branch", "--no-verify"}, argv)
                self.assertFalse(any(t.startswith("--force") or t == "-f" for t in argv), argv)
                if argv[0] == "git":
                    verb = next(a for a in argv[1:] if a not in pi.GIT_GLOBAL_OPTIONS)
                    self.assertNotIn(verb, banned_verbs)
                    if verb == "add":
                        self.assertNotEqual(argv[-1], ".")
                        self.assertNotIn(argv[-1], pi.RUNTIME_ARTIFACTS)

    def test_source_contract_no_shell_no_device_or_network_automation(self):
        source = TOOL_PATH.read_text(encoding="utf-8")
        tree = ast.parse(source)
        docstrings = {id(n.body[0].value) for n in ast.walk(tree) if isinstance(n, (ast.Module, ast.FunctionDef, ast.ClassDef)) and n.body
                      and isinstance(n.body[0], ast.Expr) and isinstance(getattr(n.body[0], "value", None), ast.Constant)}
        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported |= {a.name.split(".")[0] for a in node.names}
            elif isinstance(node, ast.ImportFrom):
                imported.add((node.module or "").split(".")[0])
        self.assertLessEqual(imported, {"__future__", "argparse", "json", "os", "re", "shlex", "subprocess", "sys", "time", "dataclasses", "pathlib", "typing"})
        run_calls = 0
        for node in ast.walk(tree):
            if isinstance(node, ast.keyword) and node.arg == "shell":
                self.assertIsInstance(node.value, ast.Constant)
                self.assertFalse(node.value.value, "shell=True is forbidden")
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                if isinstance(node.func.value, ast.Name) and node.func.value.id == "os":
                    self.assertNotIn(node.func.attr, {"system", "popen", "execv", "execvp", "spawnv", "spawnl"})
                if isinstance(node.func.value, ast.Name) and node.func.value.id == "subprocess":
                    run_calls += 1
                    self.assertIn(node.func.attr, {"run", "TimeoutExpired", "PIPE", "DEVNULL"})
        self.assertEqual(run_calls, 1, "one audited subprocess call site (the runner)")
        constants = [n.value for n in ast.walk(tree) if isinstance(n, ast.Constant) and isinstance(n.value, str) and id(n) not in docstrings]
        forbidden = ("master.py", "containerlab", "netmiko", "paramiko", "execute_change", "execution_service", "raw_verifier", "snmp", "netbox", "clab ", "docker run", "docker exec")
        for text in constants:
            for token in forbidden:
                self.assertNotIn(token, text.lower(), f"string constant {text!r} references {token}")
        never = {"--force", "-f", "--force-with-lease", "-A", "--all", "-a", "--amend", "--squash", "--rebase", "--auto", "--admin", "--delete-branch",
                 "reset", "clean", "stash", "checkout", "rebase", "cherry-pick", "revert", "fetch", "-C"}
        self.assertEqual(never & set(constants), set(), "the tool has no way to even spell these commands")

    def test_runtime_artifact_policy_is_centralised(self):
        self.assertEqual(pi.RUNTIME_ARTIFACTS, ("Run_Logs.log", "logs/R2.log"))
        tree = ast.parse(TOOL_PATH.read_text(encoding="utf-8"))
        for path in pi.RUNTIME_ARTIFACTS:
            hits = [n for n in ast.walk(tree) if isinstance(n, ast.Constant) and n.value == path]
            self.assertEqual(len(hits), 1, f"{path!r} is defined once, not scattered")

    def test_documentation_covers_the_workflow(self):
        text = (REPO_ROOT / "docs" / "PHASE_INTEGRATION_WORKFLOW.md").read_text(encoding="utf-8")
        for needle in ("start", "prepare", "status", "merge", "--adopt-working-tree", "--dry-run", "--full", "--json", "Run_Logs.log", "logs/R2.log", "merge commit",
                       "Tier-3 validation", "gh auth status", "git pull --ff-only", "never", "force"):
            with self.subTest(needle=needle):
                self.assertIn(needle, text)
