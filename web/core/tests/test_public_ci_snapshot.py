"""Sanitized public-CI snapshot builder and fail-closed verifier."""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
from pathlib import Path
from unittest import mock

import yaml
from django.test import SimpleTestCase

from core.services.test_governance.cases import POSITIVE, case


REPO_ROOT = Path(__file__).resolve().parents[3]
BUILD = REPO_ROOT / "scripts" / "ci" / "build_public_ci_snapshot.py"
VERIFY = REPO_ROOT / "scripts" / "ci" / "verify_public_ci_snapshot.py"
GITLEAKS_RANGE = REPO_ROOT / "scripts" / "ci" / "run_gitleaks_range.py"
TRACKED_SCAN = REPO_ROOT / "scripts" / "ci" / "scan_tracked_secrets.py"


def load_script(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


BUILD_MODULE = load_script("nmas_build_public_ci", BUILD)
VERIFY_MODULE = load_script("nmas_verify_public_ci", VERIFY)
GITLEAKS_MODULE = load_script("nmas_run_gitleaks_range", GITLEAKS_RANGE)
SCAN_MODULE = load_script("nmas_scan_tracked_secrets", TRACKED_SCAN)


class PublicCiSnapshotTests(SimpleTestCase):
    def fixture(self, root: Path) -> tuple[Path, str]:
        source = root / "source"
        source.mkdir()
        subprocess.run(["git", "init", "-b", "main", str(source)], check=True, capture_output=True)
        subprocess.run(["git", "-C", str(source), "config", "user.name", "Fixture"], check=True)
        subprocess.run(["git", "-C", str(source), "config", "user.email", "fixture@invalid.example"], check=True)
        (source / "scripts" / "ci").mkdir(parents=True)
        (source / "scripts" / "ci" / "scan_tracked_secrets.py").write_text("print('safe')\n")
        (source / "safe.py").write_text("print('safe')\n")
        (source / "address_report.csv").write_text("generated\n")
        (source / "logs").mkdir()
        (source / "logs" / "device.log").write_text("generated runtime evidence\n")
        subprocess.run(["git", "-C", str(source), "add", "--all"], check=True)
        subprocess.run(["git", "-C", str(source), "commit", "-m", "fixture"], check=True, capture_output=True)
        revision = subprocess.check_output(["git", "-C", str(source), "rev-parse", "HEAD"], text=True).strip()
        return source, revision

    def test_builder_creates_one_root_commit_and_exact_verified_manifest(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, revision = self.fixture(root)
            output = root / "public"
            built = subprocess.run([
                sys.executable, str(BUILD), "--source", str(source),
                "--revision", revision, "--output", str(output),
            ], text=True, capture_output=True)
            self.assertEqual(built.returncode, 0, built.stderr)
            data = json.loads((output / "PUBLIC_CI_SNAPSHOT.json").read_text())
            self.assertEqual(data["source_revision"], revision)
            self.assertEqual(len(data["excluded_tracked_files"]), 2)
            self.assertFalse((output / "address_report.csv").exists())
            self.assertFalse((output / "logs" / "device.log").exists())
            self.assertEqual(
                subprocess.check_output(["git", "-C", str(output), "rev-list", "--all", "--count"], text=True).strip(),
                "1",
            )
            verified = subprocess.run([
                sys.executable, str(VERIFY), "--root", str(output),
            ], text=True, capture_output=True)
            self.assertEqual(verified.returncode, 0, verified.stdout + verified.stderr)

    def test_verifier_fails_closed_without_echoing_tampered_content(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, revision = self.fixture(root)
            output = root / "public"
            subprocess.run([
                sys.executable, str(BUILD), "--source", str(source),
                "--revision", revision, "--output", str(output),
            ], check=True, capture_output=True)
            sentinel = "TEST_ONLY_TAMPERED_CONTENT"
            (output / "safe.py").write_text(sentinel)
            failed = subprocess.run([
                sys.executable, str(VERIFY), "--root", str(output),
            ], text=True, capture_output=True)
            self.assertNotEqual(failed.returncode, 0)
            self.assertNotIn(sentinel, failed.stdout + failed.stderr)

    def test_initial_push_scans_root_commit_without_requiring_a_parent(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, revision = self.fixture(root)
            event = root / "push.json"
            event.write_text(json.dumps({"before": "0" * 40, "after": revision}))
            self.assertEqual(GITLEAKS_MODULE.event_range(event, source), revision)

    def test_existing_branch_push_scans_only_new_commit_range(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, before = self.fixture(root)
            (source / "safe.py").write_text("print('still safe')\n")
            subprocess.run(["git", "-C", str(source), "commit", "-am", "second"], check=True, capture_output=True)
            after = subprocess.check_output(["git", "-C", str(source), "rev-parse", "HEAD"], text=True).strip()
            event = root / "push.json"
            event.write_text(json.dumps({"before": before, "after": after}))
            self.assertEqual(GITLEAKS_MODULE.event_range(event, source), f"{before}..{after}")

    def test_builder_primitives_fail_closed_and_build_from_tracked_blobs(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, revision = self.fixture(root)
            self.assertEqual(BUILD_MODULE.run(source, "rev-parse", "HEAD", text=True).strip(), revision)
            with self.assertRaises(subprocess.CalledProcessError):
                BUILD_MODULE.run(root / "missing", "rev-parse", "HEAD")
            self.assertEqual(BUILD_MODULE.safe_path("safe.py").as_posix(), "safe.py")
            with self.assertRaises(RuntimeError):
                BUILD_MODULE.safe_path("../unsafe")
            self.assertTrue(BUILD_MODULE.is_excluded("logs/device.log"))
            with self.assertRaises(TypeError):
                BUILD_MODULE.is_excluded(None)
            self.assertEqual(len(BUILD_MODULE.digest(b"safe")), 64)
            with self.assertRaises(TypeError):
                BUILD_MODULE.digest(None)
            self.assertEqual(len(BUILD_MODULE.canonical_digest({"safe": True})), 64)
            with self.assertRaises(TypeError):
                BUILD_MODULE.canonical_digest({"unsafe"})
            self.assertTrue(BUILD_MODULE.entries(source, revision))
            (source / "unsafe-link").symlink_to("safe.py")
            subprocess.run(["git", "-C", str(source), "add", "unsafe-link"], check=True)
            subprocess.run(["git", "-C", str(source), "commit", "-m", "symlink"], check=True, capture_output=True)
            with self.assertRaises(RuntimeError):
                BUILD_MODULE.entries(source, "HEAD")
            copied = root / "copied"
            BUILD_MODULE.write_blob(copied, "safe/file.py", "100644", b"safe\n")
            self.assertEqual((copied / "safe" / "file.py").read_bytes(), b"safe\n")
            with self.assertRaises(RuntimeError):
                BUILD_MODULE.write_blob(copied, "../unsafe", "100644", b"unsafe")
            output = root / "snapshot"
            manifest = BUILD_MODULE.build(source, revision, output)
            self.assertEqual(manifest["source_revision"], revision)
            with self.assertRaises(RuntimeError):
                BUILD_MODULE.build(source, revision, output)

    def test_builder_initialization_and_cli_are_bounded(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, revision = self.fixture(root)
            output = root / "manual"
            output.mkdir()
            (output / "safe.py").write_text("print('safe')\n")
            manifest = {
                "source_tree_oid": subprocess.check_output(
                    ["git", "-C", str(source), "rev-parse", f"{revision}^{{tree}}"], text=True,
                ).strip(),
                "source_manifest_sha256": "0" * 64,
            }
            commit = BUILD_MODULE.initialize_git(output, source, revision, manifest)
            self.assertEqual(len(commit), 40)
            with self.assertRaises(subprocess.CalledProcessError):
                BUILD_MODULE.initialize_git(output, source, revision, manifest)
            cli_output = root / "cli"
            with mock.patch.object(sys, "argv", [
                "build_public_ci_snapshot.py", "--source", str(source),
                "--revision", revision, "--output", str(cli_output),
            ]):
                self.assertEqual(BUILD_MODULE.main(), 0)

    def test_builder_primitives_accept_safe_inputs(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, revision = self.fixture(root)
            self.assertEqual(BUILD_MODULE.run(source, "rev-parse", "HEAD", text=True).strip(), revision)
            self.assertEqual(BUILD_MODULE.safe_path("safe.py").as_posix(), "safe.py")
            self.assertTrue(BUILD_MODULE.is_excluded("logs/device.log"))
            self.assertEqual(len(BUILD_MODULE.digest(b"safe")), 64)
            self.assertEqual(len(BUILD_MODULE.canonical_digest({"safe": True})), 64)
            self.assertTrue(BUILD_MODULE.entries(source, revision))
            copied = root / "copied"
            BUILD_MODULE.write_blob(copied, "safe/file.py", "100644", b"safe\n")
            self.assertEqual((copied / "safe" / "file.py").read_bytes(), b"safe\n")

    def test_verifier_primitives_accept_exact_records_and_reject_tampering(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, revision = self.fixture(root)
            output = root / "snapshot"
            BUILD_MODULE.build(source, revision, output)
            data = json.loads((output / "PUBLIC_CI_SNAPSHOT.json").read_text())
            self.assertEqual(len(VERIFY_MODULE.digest(output / "safe.py")), 64)
            with self.assertRaises(OSError):
                VERIFY_MODULE.digest(output / "missing")
            self.assertEqual(len(VERIFY_MODULE.canonical_digest({"safe": True})), 64)
            with self.assertRaises(TypeError):
                VERIFY_MODULE.canonical_digest({"unsafe"})
            self.assertEqual(VERIFY_MODULE.safe_path(output, "safe.py"), output / "safe.py")
            with self.assertRaises(RuntimeError):
                VERIFY_MODULE.safe_path(output, "../unsafe")
            self.assertIn("safe.py", VERIFY_MODULE.tracked(output))
            with self.assertRaises(subprocess.CalledProcessError):
                VERIFY_MODULE.tracked(root / "missing")
            record = next(item for item in data["source_files"] if item["path"] == "safe.py")
            VERIFY_MODULE.verify_record(output, record)
            with self.assertRaises(RuntimeError):
                VERIFY_MODULE.verify_record(output, {**record, "sha256": "0" * 64})
            self.assertEqual(VERIFY_MODULE.verify(output, output / "PUBLIC_CI_SNAPSHOT.json")["source_revision"], revision)
            with mock.patch.object(sys, "argv", ["verify_public_ci_snapshot.py", "--root", str(output)]):
                self.assertEqual(VERIFY_MODULE.main(), 0)
            (output / "safe.py").write_text("tampered\n")
            with self.assertRaises(RuntimeError):
                VERIFY_MODULE.verify(output, output / "PUBLIC_CI_SNAPSHOT.json")

    def test_tracked_scanner_and_range_helpers_fail_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, revision = self.fixture(root)
            self.assertIn("safe.py", SCAN_MODULE.tracked_paths(source))
            with self.assertRaises(subprocess.CalledProcessError):
                SCAN_MODULE.tracked_paths(root / "missing")
            self.assertEqual(SCAN_MODULE.scan_text("safe.py", "print('safe')"), [])
            with self.assertRaises(AttributeError):
                SCAN_MODULE.scan_text("unsafe.py", None)
            findings, counts = SCAN_MODULE.scan(source)
            self.assertEqual((findings, counts["tracked"]), ([], 4))
            with self.assertRaises(subprocess.CalledProcessError):
                SCAN_MODULE.scan(root / "missing")
            with mock.patch.object(sys, "argv", ["scan_tracked_secrets.py", "--repo", str(source)]):
                self.assertEqual(SCAN_MODULE.main(), 0)
            self.assertEqual(GITLEAKS_MODULE.checked_sha(revision, "head"), revision)
            with self.assertRaises(SystemExit):
                GITLEAKS_MODULE.checked_sha("not-a-commit", "head")
            bad_event = root / "bad-event.json"
            bad_event.write_text(json.dumps({"before": "bad", "after": revision}))
            with self.assertRaises(SystemExit):
                GITLEAKS_MODULE.event_range(bad_event, source)
            with mock.patch.object(sys, "argv", [
                "run_gitleaks_range.py", "--gitleaks", "/bin/true", "--repo", str(source),
            ]):
                self.assertEqual(GITLEAKS_MODULE.main(), 0)

    def test_tracked_scanner_and_range_helpers_accept_safe_inputs(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, revision = self.fixture(root)
            self.assertIn("safe.py", SCAN_MODULE.tracked_paths(source))
            self.assertEqual(SCAN_MODULE.scan_text("safe.py", "print('safe')"), [])
            findings, counts = SCAN_MODULE.scan(source)
            self.assertEqual((findings, counts["tracked"]), ([], 4))
            with mock.patch.object(sys, "argv", ["scan_tracked_secrets.py", "--repo", str(source)]):
                self.assertEqual(SCAN_MODULE.main(), 0)
            self.assertEqual(GITLEAKS_MODULE.checked_sha(revision, "head"), revision)
            with mock.patch.object(sys, "argv", [
                "run_gitleaks_range.py", "--gitleaks", "/bin/true", "--repo", str(source),
            ]):
                self.assertEqual(GITLEAKS_MODULE.main(), 0)

    @case(
        "CFG:.github/workflows/secret-scanning.yml:LOAD:POSITIVE",
        target=".github/workflows/secret-scanning.yml",
        polarity=POSITIVE,
        condition="the tracked secret-scanning workflow",
        expected="read-only permissions, pinned checkout, and local redacted scanners",
    )
    @case(
        "CFG:.pre-commit-config.yaml:LOAD:POSITIVE",
        target=".pre-commit-config.yaml",
        polarity=POSITIVE,
        condition="the tracked local secret-scanning hook configuration",
        expected="only fixed repository-local scanner commands are configured",
    )
    def test_security_workflow_and_local_hooks_are_least_privilege(self):
        workflow = yaml.safe_load((REPO_ROOT / ".github" / "workflows" / "secret-scanning.yml").read_text())
        self.assertEqual(workflow["permissions"], {"contents": "read"})
        steps = workflow["jobs"]["scan"]["steps"]
        checkout = next(step for step in steps if str(step.get("uses", "")).startswith("actions/checkout@"))
        self.assertFalse(checkout["with"]["persist-credentials"])
        self.assertTrue(all("@" not in step.get("uses", "") or len(step["uses"].rsplit("@", 1)[1].split()[0]) == 40 for step in steps))
        hooks = yaml.safe_load((REPO_ROOT / ".pre-commit-config.yaml").read_text())
        entries = {hook["id"]: hook["entry"] for repo in hooks["repos"] for hook in repo["hooks"]}
        self.assertEqual(entries, {
            "nmas-new-commit-gitleaks": "python scripts/ci/run_gitleaks_range.py",
            "nmas-tracked-secret-scan": "python scripts/ci/scan_tracked_secrets.py",
        })


SNAPSHOT_GIT = ["-c", "user.name=NMAS Public CI Snapshot", "-c", "user.email=nmas-public-ci@invalid.example"]


class PublicCiLinearHistoryTests(SimpleTestCase):
    """The mirror is an append-only chain: one root, single-parent snapshots, no imported history."""

    @staticmethod
    def git(repo: Path, *args: str) -> str:
        return subprocess.check_output(["git", "-C", str(repo), *args], text=True, stderr=subprocess.DEVNULL).strip()

    def chain(self, root: Path) -> tuple[Path, Path, Path, str]:
        source, first = PublicCiSnapshotTests.fixture(self, root)
        published = root / "published"
        BUILD_MODULE.build(source, first, published)
        (source / "safe.py").write_text("print('safe, revised')\n")
        subprocess.run(["git", "-C", str(source), "commit", "-qam", "revise"], check=True)
        second = self.git(source, "rev-parse", "HEAD")
        return source, published, root / "appended", second

    def test_appended_snapshot_is_a_single_parent_commit_on_the_published_root(self):
        with tempfile.TemporaryDirectory() as temporary:
            source, published, appended, second = self.chain(Path(temporary))
            published_head = self.git(published, "rev-parse", "HEAD")
            self.assertEqual(BUILD_MODULE.parent_snapshot(published, published_head), published_head)
            manifest = BUILD_MODULE.build(source, second, appended, published, published_head)
            self.assertEqual(self.git(appended, "rev-parse", "HEAD^"), published_head)
            self.assertEqual(self.git(appended, "rev-list", "--count", "--all"), "2")
            self.assertEqual(self.git(appended, "remote"), "")
            self.assertEqual((manifest["mirror_root_commit"], manifest["mirror_parent_commit"]),
                             (published_head, published_head))
            self.assertEqual(VERIFY_MODULE.verify_history(appended, published_head),
                             [published_head, manifest["mirror_commit"]])
            self.assertEqual(BUILD_MODULE.verify_history(appended, published_head), published_head)
            VERIFY_MODULE.verify_commit(appended, manifest["mirror_commit"], published_head)
            self.assertEqual(VERIFY_MODULE.git(appended, "rev-parse", "HEAD").strip(), manifest["mirror_commit"])
            workflow = (appended / ".github" / "workflows" / "public-ci-integrity.yml").read_text()
            self.assertIn(f"--history --expected-root {published_head}", workflow)
            self.assertEqual(VERIFY_MODULE.verify(appended, appended / "PUBLIC_CI_SNAPSHOT.json")["source_revision"], second)
            with mock.patch.object(sys, "argv", ["verify_public_ci_snapshot.py", "--root", str(appended),
                                                 "--history", "--expected-root", published_head]):
                self.assertEqual(VERIFY_MODULE.main(), 0)
            with mock.patch.object(sys, "argv", [
                "build_public_ci_snapshot.py", "--source", str(source), "--revision", second,
                "--output", str(Path(temporary) / "cli"), "--parent-mirror", str(published),
                "--parent-commit", published_head,
            ]):
                self.assertEqual(BUILD_MODULE.main(), 0)

    def test_builder_refuses_an_unapproved_or_unverified_parent(self):
        with tempfile.TemporaryDirectory() as temporary:
            source, published, appended, second = self.chain(Path(temporary))
            published_head = self.git(published, "rev-parse", "HEAD")
            with self.assertRaisesRegex(RuntimeError, "full commit ID"):
                BUILD_MODULE.parent_snapshot(published, published_head[:12])
            with self.assertRaisesRegex(RuntimeError, "not the approved parent"):
                BUILD_MODULE.parent_snapshot(published, "0" * 40)
            with self.assertRaisesRegex(RuntimeError, "given together"):
                BUILD_MODULE.build(source, second, appended, published, None)
            with self.assertRaisesRegex(RuntimeError, "history verification failed"):
                BUILD_MODULE.verify_history(published, "0" * 40)
            manifest = {"source_tree_oid": "0" * 40, "source_manifest_sha256": "0" * 64,
                        "mirror_parent_commit": "0" * 40}
            target = Path(temporary) / "mismatch"
            target.mkdir()
            (target / "safe.py").write_text("print('safe')\n")
            with self.assertRaisesRegex(RuntimeError, "does not match the approved parent"):
                BUILD_MODULE.initialize_git(target, source, second, manifest, published)
            self.assertFalse(appended.exists())

    def test_history_verifier_rejects_imported_merged_foreign_or_mislabelled_commits(self):
        with tempfile.TemporaryDirectory() as temporary:
            source, published, _appended, second = self.chain(Path(temporary))
            head = self.git(published, "rev-parse", "HEAD")
            with self.assertRaisesRegex(RuntimeError, "published root"):
                VERIFY_MODULE.verify_history(published, "0" * 40)
            with self.assertRaises(subprocess.CalledProcessError):
                VERIFY_MODULE.git(Path(temporary) / "missing", "rev-parse", "HEAD")

            # A commit outside the chain on another ref.
            subprocess.run(["git", "-C", str(published), "fetch", "-q", str(source), "main:refs/heads/imported"], check=True)
            with self.assertRaisesRegex(RuntimeError, "outside the linear snapshot chain"):
                VERIFY_MODULE.verify_history(published)
            # The same imported source history merged in: second root plus a merge commit.
            subprocess.run(["git", *SNAPSHOT_GIT, "-C", str(published), "merge", "-q", "--no-edit", "-s", "ours",
                            "--allow-unrelated-histories", "imported"], check=True, capture_output=True)
            with self.assertRaisesRegex(RuntimeError, "strictly linear"):
                VERIFY_MODULE.verify_history(published)
            subprocess.run(["git", "-C", str(published), "reset", "-q", "--hard", head], check=True)
            subprocess.run(["git", "-C", str(published), "branch", "-q", "-D", "imported"], check=True)
            self.assertEqual(len(VERIFY_MODULE.verify_history(published, head)), 1)

            # A commit by any identity other than the snapshot builder.
            (published / "safe.py").write_text("print('hand edit')\n")
            subprocess.run(["git", "-c", "user.name=Someone", "-c", "user.email=someone@invalid.example",
                            "-C", str(published), "commit", "-qam", "hand edit"], check=True)
            with self.assertRaisesRegex(RuntimeError, "snapshot builder identity"):
                VERIFY_MODULE.verify_history(published)
            subprocess.run(["git", "-C", str(published), "reset", "-q", "--hard", head], check=True)

            # Snapshot identity but trailers that disagree with the commit's own manifest.
            body = self.git(published, "show", "-s", "--format=%B", head).replace(
                f"Source-Commit: {self.git(source, 'rev-parse', 'HEAD^')}", f"Source-Commit: {second}")
            subprocess.run(["git", *SNAPSHOT_GIT, "-C", str(published), "commit", "-q", "--allow-empty", "-m", body], check=True)
            with self.assertRaisesRegex(RuntimeError, "Source-Commit does not match"):
                VERIFY_MODULE.verify_history(published)
            with mock.patch.object(sys, "argv", ["verify_public_ci_snapshot.py", "--root", str(published), "--history"]), \
                    mock.patch("builtins.print"):
                self.assertEqual(VERIFY_MODULE.main(), 1)
            subprocess.run(["git", "-C", str(published), "reset", "-q", "--hard", head], check=True)

            # Snapshot identity and trailers, but a path the manifest does not list.
            (published / "unreviewed.py").write_text("print('unreviewed')\n")
            subprocess.run(["git", "-C", str(published), "add", "unreviewed.py"], check=True)
            body = self.git(published, "show", "-s", "--format=%B", head)
            subprocess.run(["git", *SNAPSHOT_GIT, "-C", str(published), "commit", "-q", "-m", body], check=True)
            with self.assertRaisesRegex(RuntimeError, "path set does not match"):
                VERIFY_MODULE.verify_commit(published, self.git(published, "rev-parse", "HEAD"), head)
