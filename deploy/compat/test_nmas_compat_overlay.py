"""Tests for the compatibility overlay tool (CO01-CO18).  Standard library only:

    python3 -I -B deploy/compat/test_nmas_compat_overlay.py -v

Every test works on synthetic git repositories in a temporary directory; nothing reads or writes the deployed tree.
"""

from __future__ import annotations

import io
import json
import os
import sqlite3
import stat
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
import nmas_compat_overlay as tool  # noqa: E402

RULES_BASE = "A = 1\nPUBLIC_ONLY = 1\nLIFECYCLE = ('x',)\nZ = 9\n"
RULES_PROD = "A = 1\nPROD_ONLY = 2\nLIFECYCLE = ('x',)\nZ = 9\n"           # public-only line absent, production-only line present
RULES_OURS = "A = 1\nPUBLIC_ONLY = 1\nLIFECYCLE = ('x', 'device_observe')\nZ = 9\nNEW = 3\n"


def git(repo: Path, *args: str) -> None:
    subprocess.run(["git", "-C", str(repo), "-c", "user.name=t", "-c", "user.email=t@example.invalid", *args],
                   check=True, capture_output=True)


def write(root: Path, rel: str, text: str, mode: int = 0o664) -> Path:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    os.chmod(path, mode)
    return path


class OverlayTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="overlay-test-"))
        self.addCleanup(subprocess.run, ["rm", "-rf", str(self.tmp)])
        self.pub, self.prod = self.tmp / "public", self.tmp / "prod"
        for root in (self.pub, self.prod):
            root.mkdir()
            git(root, "init", "-q")
        # public HEAD: shared files at their public-HEAD content
        write(self.pub, "web/core/models.py", "class A: pass\n")
        write(self.pub, "web/core/services/ci/rules.py", RULES_BASE)
        for rel in tool.REPLACE[1:]:
            write(self.pub, rel, f"# {rel}\n")
        git(self.pub, "add", "-A")
        git(self.pub, "commit", "-qm", "base")
        # reviewed worktree edits
        write(self.pub, "web/core/models.py", "class A: pass\nclass B: pass\n")
        write(self.pub, "web/core/services/ci/rules.py", RULES_OURS)
        write(self.pub, "web/core/checks.py", "CHECKS = 1\n")
        write(self.pub, "web/core/services/troubleshooting/deep/mod.py", "X = 1\n")
        write(self.pub, "web/core/unrelated.py", "not in the overlay\n")
        # production: legacy lineage with its own content
        write(self.prod, "web/core/models.py", "class A: pass\n")
        write(self.prod, "web/core/services/ci/rules.py", RULES_PROD)
        for rel in tool.REPLACE[1:]:
            write(self.prod, rel, f"# {rel}\n")
        write(self.prod, "web/core/prod_only.py", "KEEP = True\n")
        write(self.prod, "web/var/device-locks/x.lock", "")
        write(self.prod, "monitoring/runtime/secret.env", "S=1\n")
        git(self.prod, "add", "-A")
        git(self.prod, "commit", "-qm", "prod")
        self.pkg = self.tmp / "pkg"

    def build(self):
        base = subprocess.run(["git", "-C", str(self.pub), "rev-list", "--max-parents=0", "HEAD"], check=True,
                              capture_output=True, text=True).stdout.strip()
        with redirect_stdout(io.StringIO()):
            return tool.build(self.pub, self.prod, self.pkg, merge_base=base)

    def scratch(self, name="scratch") -> Path:
        target = self.tmp / name
        subprocess.run(["cp", "-a", str(self.prod), str(target)], check=True)
        subprocess.run(["rm", "-rf", str(target / ".git"), str(target / "web" / "var")], check=True)
        return target

    def entry(self, manifest, path):
        return next(e for e in manifest["entries"] if e["path"] == path)

    # CO01
    def test_build_classifies_and_freezes(self):
        m = self.build()
        self.assertEqual(m["problems"], [])
        actions = {e["path"]: e["action"] for e in m["entries"]}
        self.assertEqual(actions["web/core/checks.py"], "ADD")
        self.assertEqual(actions["web/core/services/troubleshooting/deep/mod.py"], "ADD")
        self.assertEqual(actions["web/core/models.py"], "REPLACE")
        self.assertEqual(actions["web/core/services/ci/rules.py"], "MERGE")
        self.assertNotIn("web/core/unrelated.py", actions)
        for e in m["entries"]:
            self.assertEqual(tool.sha256_file(self.pkg / "payload" / e["path"]), e["post_sha256"])

    # CO02
    def test_merge_transplants_only_overlay_hunks(self):
        self.build()
        merged = (self.pkg / "payload" / "web/core/services/ci/rules.py").read_text()
        self.assertEqual(merged, "A = 1\nPROD_ONLY = 2\nLIFECYCLE = ('x', 'device_observe')\nZ = 9\nNEW = 3\n")

    # CO03
    def test_build_reports_collisions_and_unanchored_hunks(self):
        write(self.prod, "web/core/checks.py", "PROD = 1\n")
        write(self.prod, "web/core/services/ci/rules.py", "A = 1\nLIFECYCLE = ('y',)\n")
        m = self.build()
        self.assertIn("ADD target already exists in production: web/core/checks.py", m["problems"])
        self.assertTrue(any(p.startswith("MERGE web/core/services/ci/rules.py") for p in m["problems"]), m["problems"])
        with self.assertRaises(SystemExit):
            tool.load(self.pkg)

    # CO04
    def test_load_refuses_tampering(self):
        self.build()
        (self.pkg / "payload" / "web/core/checks.py").write_text("EVIL = 1\n")
        with self.assertRaisesRegex(SystemExit, "payload"):
            tool.load(self.pkg)
        self.build_fresh()
        manifest = json.loads((self.pkg / "manifest.json").read_text())
        manifest["entries"][0]["post_sha256"] = "0" * 64
        (self.pkg / "manifest.json").write_text(json.dumps(manifest))
        with self.assertRaisesRegex(SystemExit, "entries_sha256"):
            tool.load(self.pkg)
        self.build_fresh()
        with open(self.pkg / "nmas_compat_overlay.py", "a") as fh:
            fh.write("\n# changed\n")
        with self.assertRaisesRegex(SystemExit, "tool"):
            tool.load(self.pkg)

    def build_fresh(self):
        subprocess.run(["rm", "-rf", str(self.pkg)], check=True)
        return self.build()

    # CO05
    def test_stage_overlays_a_copy_and_excludes_runtime_state(self):
        self.build()
        out = self.tmp / "staged"
        tool.stage(self.pkg, self.prod, out)
        manifest, _ = tool.load(self.pkg)
        self.assertEqual(tool.verify(manifest["entries"], out, "post"), [])
        self.assertEqual((out / "web/core/prod_only.py").read_text(), "KEEP = True\n")
        for excluded in (".git", "web/var", "monitoring/runtime"):
            self.assertFalse((out / excluded).exists(), excluded)
        self.assertEqual(tool.verify(manifest["entries"], self.prod, "pre"), [])      # the source tree is untouched

    # CO06
    def test_apply_refuses_without_exact_confirmation_or_with_active_units(self):
        self.build()
        target = self.scratch()
        _, mid = tool.load(self.pkg)
        with self.assertRaisesRegex(SystemExit, "--confirm"):
            tool.apply(self.pkg, target, self.tmp / "b1", "CHG-1", "deadbeef0000")
        with mock.patch.object(tool, "_services_active", return_value=["nmas-web.service=active"]):
            with self.assertRaisesRegex(SystemExit, "stop the NMAS units"):
                tool.apply(self.pkg, target, self.tmp / "b1", "CHG-1", mid[:12])
        with self.assertRaisesRegex(SystemExit, "change-id"):
            tool.apply(self.pkg, target, self.tmp / "b1", " ", mid[:12], scratch_target=True)
        self.assertFalse((self.tmp / "b1").exists())
        self.assertFalse((target / "web/core/checks.py").exists())

    # CO07
    def test_scratch_mode_is_refused_for_a_real_tree(self):
        self.build()
        _, mid = tool.load(self.pkg)
        with self.assertRaisesRegex(SystemExit, "disposable copy"):
            tool.apply(self.pkg, self.prod, self.tmp / "b", "CHG-1", mid[:12], scratch_target=True)
        with self.assertRaisesRegex(SystemExit, "disposable copy"):
            tool.apply(self.pkg, Path(tool.PRODUCTION_DEFAULT), self.tmp / "b", "CHG-1", mid[:12], scratch_target=True)

    # CO08
    def test_apply_refuses_drifted_production_and_writes_nothing(self):
        self.build()
        target = self.scratch()
        (target / "web/core/models.py").write_text("class A: pass\n# hotfix\n")
        _, mid = tool.load(self.pkg)
        with self.assertRaisesRegex(SystemExit, "preconditions"):
            tool.apply(self.pkg, target, self.tmp / "b", "CHG-1", mid[:12], scratch_target=True)
        self.assertFalse((self.tmp / "b").exists())
        self.assertFalse((target / "web/core/checks.py").exists())

    # CO09
    def test_apply_then_rollback_restores_the_exact_pre_state(self):
        self.build()
        target = self.scratch()
        os.chmod(target / "web/core/urls.py", 0o640)
        before = {p.relative_to(target).as_posix(): (p.read_bytes(), stat.S_IMODE(p.stat().st_mode))
                  for p in target.rglob("*") if p.is_file()}
        dirs_before = sorted(p.relative_to(target).as_posix() for p in target.rglob("*") if p.is_dir())
        manifest, mid = tool.load(self.pkg)
        backup = self.tmp / "backup"
        with redirect_stdout(io.StringIO()):
            tool.apply(self.pkg, target, backup, "CHG-1", mid[:12], scratch_target=True)
        self.assertEqual(tool.verify(manifest["entries"], target, "post"), [])
        self.assertEqual(stat.S_IMODE(backup.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE((target / "web/core/urls.py").stat().st_mode), 0o640)       # production mode preserved
        self.assertEqual(stat.S_IMODE((target / "web/core/services/troubleshooting").stat().st_mode), 0o775)
        journal = json.loads((backup / "journal.json").read_text())
        self.assertEqual((journal["status"], journal["change_id"]), ("APPLIED", "CHG-1"))
        self.assertIn("web/core/services/troubleshooting/deep", journal["created_dirs"])
        (target / "web/core/services/troubleshooting/deep/__pycache__").mkdir()                 # the service ran
        (target / "web/core/services/troubleshooting/deep/__pycache__/mod.cpython-312.pyc").write_bytes(b"x")
        with redirect_stdout(io.StringIO()):
            tool.rollback(backup / "journal.json", None, skip_db_check=True)
        after = {p.relative_to(target).as_posix(): (p.read_bytes(), stat.S_IMODE(p.stat().st_mode))
                 for p in target.rglob("*") if p.is_file()}
        self.assertEqual(after, before)
        self.assertEqual(sorted(p.relative_to(target).as_posix() for p in target.rglob("*") if p.is_dir()), dirs_before)
        self.assertEqual(json.loads((backup / "journal.json").read_text())["status"], "ROLLED_BACK")

    # CO10
    def test_rollback_refuses_while_overlay_migrations_are_applied(self):
        self.build()
        target = self.scratch()
        _, mid = tool.load(self.pkg)
        with redirect_stdout(io.StringIO()):
            tool.apply(self.pkg, target, self.tmp / "backup", "CHG-1", mid[:12], scratch_target=True)
        db = self.tmp / "db.sqlite3"
        con = sqlite3.connect(db)
        con.execute("create table django_migrations (id integer primary key, app text, name text, applied text)")
        con.executemany("insert into django_migrations (app, name, applied) values ('core', ?, '')",
                        [("0035_v2_phase7_9_decommission_dynamic",), ("0039_observation_authorizations",)])
        con.commit()
        con.close()
        journal = self.tmp / "backup" / "journal.json"
        with self.assertRaisesRegex(SystemExit, "--db"):
            tool.rollback(journal, None, skip_db_check=False)
        with self.assertRaisesRegex(SystemExit, "0039_observation_authorizations"):
            tool.rollback(journal, db, skip_db_check=False)
        self.assertTrue((target / "web/core/checks.py").exists())                    # nothing was rolled back
        con = sqlite3.connect(db)
        con.execute("delete from django_migrations where name like '0039%'")
        con.commit()
        con.close()
        with redirect_stdout(io.StringIO()):
            tool.rollback(journal, db, skip_db_check=False)
        self.assertFalse((target / "web/core/checks.py").exists())

    # CO11
    def test_rollback_refuses_a_corrupt_backup_before_changing_anything(self):
        self.build()
        target = self.scratch()
        _, mid = tool.load(self.pkg)
        with redirect_stdout(io.StringIO()):
            tool.apply(self.pkg, target, self.tmp / "backup", "CHG-1", mid[:12], scratch_target=True)
        (self.tmp / "backup/files/web/core/models.py").write_text("corrupt\n")
        with self.assertRaisesRegex(SystemExit, "corrupt"):
            tool.rollback(self.tmp / "backup" / "journal.json", None, skip_db_check=True)
        self.assertTrue((target / "web/core/checks.py").exists())

    # CO12
    def test_apply_refuses_an_existing_backup_directory(self):
        self.build()
        target = self.scratch()
        (self.tmp / "backup").mkdir()
        _, mid = tool.load(self.pkg)
        with self.assertRaisesRegex(SystemExit, "already exists"):
            tool.apply(self.pkg, target, self.tmp / "backup", "CHG-1", mid[:12], scratch_target=True)
        self.assertFalse((target / "web/core/checks.py").exists())

    # CO13
    def test_review_identity_is_reproducible(self):
        first = self.build()["entries_sha256"]
        write(self.pub, "web/core/unrelated.py", "dirty state outside the overlay changes nothing\n")
        second = self.build_fresh()["entries_sha256"]
        self.assertEqual(first, second)
        write(self.pub, "web/core/checks.py", "CHECKS = 2\n")
        self.assertNotEqual(self.build_fresh()["entries_sha256"], first)

    # CO14
    def test_db_backup_and_guarded_restore(self):
        live = self.tmp / "live.sqlite3"
        con = sqlite3.connect(live)
        con.execute("create table django_migrations (id integer primary key, app text, name text, applied text)")
        con.execute("insert into django_migrations (app, name, applied) values ('core', '0035_v2_phase7_9_decommission_dynamic', '')")
        con.execute("create table t (x)")
        con.execute("insert into t values (1)")
        con.commit()
        con.close()
        before = tool.sha256_file(live)
        record = tool.db_backup(live, self.tmp / "bk" / "db.sqlite3")
        self.assertEqual(tool.sha256_file(live), before)                                  # the source is only read
        self.assertEqual((record["integrity_check"], record["core_migration_head"]),
                         ("ok", "0035_v2_phase7_9_decommission_dynamic"))
        self.assertEqual(stat.S_IMODE((self.tmp / "bk" / "db.sqlite3").stat().st_mode), 0o600)
        with self.assertRaisesRegex(SystemExit, "exists"):
            tool.db_backup(live, self.tmp / "bk" / "db.sqlite3")
        con = sqlite3.connect(live)                                                       # the service kept writing
        con.execute("insert into t values (2)")
        con.commit()
        con.close()
        backup = self.tmp / "bk" / "db.sqlite3"
        with self.assertRaisesRegex(SystemExit, "--confirm"):
            tool.db_restore(backup, live, "0" * 12, scratch_target=True)
        with mock.patch.object(tool, "_services_active", return_value=["nmas-web.service=active"]):
            with self.assertRaisesRegex(SystemExit, "stop the NMAS units"):
                tool.db_restore(backup, live, record["sha256"][:12])
        with self.assertRaisesRegex(SystemExit, "deployed tree"):
            tool.db_restore(backup, Path(tool.PRODUCTION_DEFAULT) / "web" / "db.sqlite3", record["sha256"][:12], scratch_target=True)
        result = tool.db_restore(backup, live, record["sha256"][:12], scratch_target=True)
        self.assertEqual(tool.sha256_file(live), record["sha256"])
        kept = Path(result["previous_kept_at"])
        self.assertEqual(sqlite3.connect(kept).execute("select count(*) from t").fetchone()[0], 2)
        backup.write_bytes(backup.read_bytes() + b"x")
        with self.assertRaisesRegex(SystemExit, "recorded SHA-256"):
            tool.db_restore(backup, live, record["sha256"][:12], scratch_target=True)

    # CO15
    def test_source_archive_keeps_dirty_source_and_never_runtime_secrets(self):
        import tarfile

        write(self.prod, "web/core/prod_only.py", "KEEP = 'dirty edit'\n")
        write(self.prod, "web/db.sqlite3", "db")
        write(self.prod, "netbox/.env", "TOKEN=x\n")
        record = tool.source_archive(self.prod, self.tmp / "src.tar.gz")
        with tarfile.open(self.tmp / "src.tar.gz") as tar:
            names = set(tar.getnames())
            self.assertEqual(tar.extractfile("web/core/prod_only.py").read(), b"KEEP = 'dirty edit'\n")
        self.assertIn(".git/HEAD", names)
        for secret in ("web/db.sqlite3", "netbox/.env", "monitoring/runtime/secret.env", "web/var/device-locks/x.lock"):
            self.assertNotIn(secret, names)
        self.assertEqual(record["sha256"], tool.sha256_file(self.tmp / "src.tar.gz"))
        self.assertEqual(stat.S_IMODE((self.tmp / "src.tar.gz").stat().st_mode), 0o600)

    # CO16
    def test_review_evidence_is_not_deployed(self):
        write(self.pub, "docs/troubleshooting/guide.md", "operator guide\n")
        write(self.pub, "docs/troubleshooting/validation/report.md", "cites the package hash\n")
        paths = {e["path"] for e in self.build()["entries"]}
        self.assertIn("docs/troubleshooting/guide.md", paths)
        self.assertNotIn("docs/troubleshooting/validation/report.md", paths)

    # CO17
    def test_merge_result_is_unchanged_after_the_overlay_is_committed(self):
        before = self.build()["entries_sha256"]
        git(self.pub, "add", "-A")
        git(self.pub, "commit", "-qm", "overlay committed")
        self.assertEqual(self.build_fresh()["entries_sha256"], before)

    # CO18
    def test_deployment_diff_is_exactly_what_apply_writes(self):
        self.build()
        text = tool.deployment_diff(self.pkg)
        self.assertIn("new file mode 100644\n--- /dev/null\n+++ b/web/core/checks.py\n@@ -0,0 +1 @@\n+CHECKS = 1\n", text)
        self.assertIn("-LIFECYCLE = ('x',)\n+LIFECYCLE = ('x', 'device_observe')\n", text)
        self.assertNotIn("PUBLIC_ONLY", text)                       # public-only lines are never part of the production change
        target = self.scratch()
        _, mid = tool.load(self.pkg)
        with redirect_stdout(io.StringIO()):
            tool.apply(self.pkg, target, self.tmp / "backup", "CHG-1", mid[:12], scratch_target=True)
        result = subprocess.run(["git", "-C", str(self.prod), "apply", "--check", "-"], input=text.split("\n", 2)[2].encode(),
                                capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)        # the diff applies cleanly to the untouched production tree
        summary = tool.deployment_diff(self.pkg, summary=True)
        self.assertEqual(len(summary.splitlines()) - 2, len(tool.load(self.pkg)[0]["entries"]))


if __name__ == "__main__":
    unittest.main()
