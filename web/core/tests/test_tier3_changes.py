"""Tier-3 change collection: git range semantics, revision safety, and GitHub event resolution.

Real ``git`` runs against a throw-away repository only.  Nothing here starts a validation command.
"""

from __future__ import annotations

from django.test import SimpleTestCase

from core.services.ci import changes, github_context, gitio
from core.services.ci.constants import FileStatus, Mode
from core.services.ci.service import Tier3InputError, Tier3Request, plan_change_effect
from core.tests.helpers.tier3 import TempRepo


class RangeCollectionTests(SimpleTestCase):
    def setUp(self):
        self.repo = TempRepo()
        self.addCleanup(self.repo.cleanup)

    def _base_and_head(self):
        for name in ("a.py", "b.py", "c.py", "d.py"):
            self.repo.write(name, f"# {name}\n" * 5)
        base = self.repo.commit("base")
        self.repo.write("a.py", "# a.py\n" * 5 + "# changed\n")
        (self.repo.path / "b.py").unlink()
        self.repo.write("e.py", "# new\n")
        self.repo.git("mv", "c.py", "c2.py")
        return base, self.repo.commit("head")

    def test_status_matrix_covers_modify_delete_add_and_rename(self):
        base, head = self._base_and_head()
        result = changes.collect_changes(self.repo.path, base, head)
        got = {(f.path, f.status, f.old_path) for f in result.files}
        expected = {
            ("a.py", FileStatus.MODIFIED, None), ("b.py", FileStatus.DELETED, None), ("e.py", FileStatus.ADDED, None),
            ("c2.py", FileStatus.RENAMED, "c.py"),
        }
        for row in sorted(expected):
            with self.subTest(case=row):
                self.assertIn(row, got)
        self.assertEqual(got, expected)  # d.py is untouched
        self.assertEqual([f.path for f in result.files], sorted(f.path for f in result.files))  # deterministic order
        self.assertEqual(set(next(f for f in result.files if f.old_path).paths()), {"c2.py", "c.py"})  # a rename touches both sides

    def test_identical_revisions_are_an_empty_change_not_an_error(self):
        base, _head = self._base_and_head()
        result = changes.collect_changes(self.repo.path, base, base)
        self.assertTrue(result.empty)
        self.assertEqual(result.head_sha, result.base_sha)

    def test_merge_base_ignores_later_base_movement_and_direct_does_not(self):
        self.repo.write("shared.py")
        fork = self.repo.commit("fork point")
        self.repo.git("checkout", "-q", "-b", "feature")
        self.repo.write("feature.py", "# only on the feature branch\n" * 4)
        feature = self.repo.commit("feature")
        self.repo.git("checkout", "-q", "main")
        self.repo.write("main_only.py", "# only on main after the fork\n" * 4)
        main = self.repo.commit("main moved on")
        merge_based = changes.collect_changes(self.repo.path, main, feature, merge_base=True)
        direct = changes.collect_changes(self.repo.path, main, feature, merge_base=False)
        self.assertEqual([f.path for f in merge_based.files], ["feature.py"])
        self.assertEqual(merge_based.compare_from_sha, fork)
        self.assertEqual({f.path for f in direct.files}, {"feature.py", "main_only.py"})  # base..head sees main's file as removed
        self.assertEqual(direct.strategy, changes.STRATEGY_DIRECT)

    def test_no_base_treats_every_tracked_file_as_changed(self):
        self.repo.write("a.py")
        self.repo.write("docs/x.md")
        head = self.repo.commit()
        result = changes.collect_changes(self.repo.path, None, head)
        self.assertEqual(result.strategy, changes.STRATEGY_ALL_TRACKED)
        self.assertEqual({(f.path, f.status) for f in result.files}, {("a.py", FileStatus.ADDED), ("docs/x.md", FileStatus.ADDED)})

    def test_working_tree_comparison_includes_uncommitted_and_untracked_files(self):
        self.repo.write("a.py")
        self.repo.write("b.py")
        base = self.repo.commit()
        self.repo.write("a.py", "changed\n")
        self.repo.write("new_untracked.py", "print(1)\n")
        result = changes.collect_changes(self.repo.path, base, "HEAD", working_tree=True)
        self.assertEqual({(f.path, f.status) for f in result.files}, {("a.py", FileStatus.MODIFIED), ("new_untracked.py", FileStatus.ADDED)})
        with self.assertRaises(gitio.GitError):
            changes.collect_changes(self.repo.path, None, "HEAD", working_tree=True)

    def test_added_lines_are_only_what_the_change_adds_with_line_numbers(self):
        self.repo.write("a.txt", "one\ntwo\nthree\n")
        base = self.repo.commit()
        self.repo.write("a.txt", "one\nTWO-NEW\ntwo\nthree\nFOUR-NEW\n")
        self.repo.write("brand_new.txt", "n1\nn2\n")
        head = self.repo.commit()
        change_set = changes.collect_changes(self.repo.path, base, head)
        lines, truncated = changes.added_lines(self.repo.path, change_set)
        self.assertFalse(truncated)
        self.assertEqual({(l.path, l.line, l.text) for l in lines}, {
            ("a.txt", 2, "TWO-NEW"), ("a.txt", 5, "FOUR-NEW"), ("brand_new.txt", 1, "n1"), ("brand_new.txt", 2, "n2")})

    def test_invalid_revisions_are_refused_before_git_is_asked(self):
        head = self.repo.commit()
        rows = ("", "--output=/tmp/x", "-h", "HEAD..HEAD", "a b", "x;rm -rf y", "$(id)", "does-not-exist", "0" * 40)
        for revision in rows:
            with self.subTest(revision=revision):
                with self.assertRaises(gitio.GitError):
                    gitio.resolve_commit(self.repo.path, revision)
        self.assertEqual(gitio.resolve_commit(self.repo.path, "HEAD"), head)
        self.assertEqual(gitio.resolve_commit(self.repo.path, head[:12]), head)

    def test_only_read_only_git_verbs_are_allowed(self):
        self.repo.commit()
        for verb in ("add", "commit", "reset", "clean", "stash", "checkout", "push", "fetch", "restore", "rm", "config", "gc"):
            with self.subTest(verb=verb):
                with self.assertRaises(gitio.UnsafeGitCommand):
                    gitio.run_git(self.repo.path, [verb, "-A"])
        for verb in gitio.READ_ONLY_GIT_COMMANDS:
            with self.subTest(verb=verb):
                self.assertNotIn(verb, {"add", "commit", "reset", "clean", "stash", "checkout", "push", "fetch"})


class GitHubContextTests(SimpleTestCase):
    SHA_BASE, SHA_HEAD, SHA_CHECKOUT = "1" * 40, "2" * 40, "3" * 40
    ZERO = "0" * 40

    def env(self, event: str, **extra):
        return {"GITHUB_EVENT_NAME": event, "GITHUB_SHA": self.SHA_CHECKOUT, "GITHUB_REF_NAME": "feature/x", "GITHUB_REPOSITORY": "o/r", **extra}

    def test_event_matrix(self):
        main = {"repository": {"default_branch": "main"}}
        rows = [
            ("pull_request", {"pull_request": {"base": {"sha": self.SHA_BASE, "ref": "main"}, "head": {"sha": self.SHA_HEAD, "ref": "f"}}},
             (self.SHA_BASE, self.SHA_HEAD, True, Mode.TARGETED)),
            ("push default branch", {"before": self.SHA_BASE, "after": self.SHA_HEAD, "ref": "refs/heads/main", **main},
             (self.SHA_BASE, self.SHA_HEAD, False, Mode.FULL)),
            ("push feature branch", {"before": self.SHA_BASE, "after": self.SHA_HEAD, "ref": "refs/heads/f", **main},
             (self.SHA_BASE, self.SHA_HEAD, False, Mode.TARGETED)),
            ("push new branch", {"before": self.ZERO, "after": self.SHA_HEAD, "ref": "refs/heads/f", **main}, (None, self.SHA_HEAD, False, Mode.FULL)),
            ("dispatch with base", {"inputs": {"base": "origin/main"}}, ("origin/main", self.SHA_CHECKOUT, True, Mode.TARGETED)),
            ("dispatch with base, forced full", {"inputs": {"base": "origin/main", "mode": "full"}}, ("origin/main", self.SHA_CHECKOUT, True, Mode.FULL)),
            ("dispatch without base", {"inputs": {}}, (None, self.SHA_CHECKOUT, False, Mode.FULL)),
            ("schedule (unsupported)", {}, (None, self.SHA_CHECKOUT, False, Mode.FULL)),
        ]
        for label, payload, expected in rows:
            event = label.split()[0].replace("dispatch", "workflow_dispatch")
            with self.subTest(case=label):
                got = github_context.resolve_from_environment(self.env(event), payload)
                self.assertEqual((got.base, got.head, got.merge_base, got.mode), expected)

    def test_malformed_or_hostile_event_data_is_refused(self):
        rows = [
            ("pull_request", {"pull_request": {"base": {"sha": "--upload-pack=x"}, "head": {"sha": self.SHA_HEAD}}}),
            ("pull_request", {}),
            ("push", {"before": "--evil", "after": self.SHA_HEAD}),
            ("workflow_dispatch", {"inputs": {"base": "x; rm -rf /"}}),
            ("workflow_dispatch", {"inputs": {"base": "origin/main", "mode": "everything"}}),
        ]
        for event, payload in rows:
            with self.subTest(event=event, payload=str(payload)[:60]):
                with self.assertRaises(github_context.GitHubContextError):
                    github_context.resolve_from_environment(self.env(event), payload)
        with self.assertRaises(github_context.GitHubContextError):
            github_context.resolve_from_environment({}, {})
        with self.assertRaises(github_context.GitHubContextError):
            github_context.resolve_from_environment({"GITHUB_EVENT_NAME": "push"})  # no event file

    def test_provenance_context_is_bounded_and_label_safe(self):
        env = self.env("push", GITHUB_REF_NAME="bad name; $(x)", GITHUB_SHA="not-a-sha")
        got = github_context.resolve_from_environment(env, {"before": self.SHA_BASE, "after": self.SHA_HEAD})
        self.assertIsNone(got.context["ref_name"])
        self.assertIsNone(got.context["checkout_sha"])
        self.assertEqual(got.context["repository"], "o/r")


class DerivedBaseFallbackTests(SimpleTestCase):
    def setUp(self):
        self.repo = TempRepo()
        self.addCleanup(self.repo.cleanup)
        self.repo.write("a.py")
        self.head = self.repo.commit()

    def test_ci_derived_unusable_base_broadens_but_an_explicit_one_is_an_error(self):
        missing = "f" * 40
        _changes, plan = plan_change_effect(Tier3Request(self.repo.path, missing, self.head, derived=True))
        self.assertEqual(plan.mode_effective, Mode.FULL)
        self.assertIn("BASE_FALLBACK", [w.code for w in plan.warnings])
        with self.assertRaises(Tier3InputError):
            plan_change_effect(Tier3Request(self.repo.path, missing, self.head, derived=False))
        with self.assertRaises(Tier3InputError):
            plan_change_effect(Tier3Request(self.repo.path, "HEAD", "nope", derived=True))  # an unusable HEAD is never papered over
