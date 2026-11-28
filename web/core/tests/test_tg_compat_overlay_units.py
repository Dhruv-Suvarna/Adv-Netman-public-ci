"""Direct tests for the NMAS compatibility overlay tool (deploy/compat/nmas_compat_overlay.py).

The overlay adds the reviewed troubleshooting files to the production tree and changes only hash-guarded shared files; it
never replaces the production lineage, never writes in place without an exact review confirmation and journal, and rolls
back only while the database records no overlay migration.  The fixture is the standalone suite's (CO01-CO18): two
synthetic git repositories in a temporary directory.  Nothing reads or writes the deployed tree or its database.
"""

from __future__ import annotations

import importlib.util
import io
import json
import re
import sqlite3
import stat
import sys
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

from django.test import SimpleTestCase

_spec = importlib.util.spec_from_file_location(
    "nmas_compat_overlay_suite", Path(__file__).resolve().parents[3] / "deploy" / "compat" / "test_nmas_compat_overlay.py")
suite = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(suite)
tool = suite.tool
CORE_HEAD = "0035_v2_phase7_9_decommission_dynamic"


def make_db(path: Path, *migrations: str) -> Path:
    con = sqlite3.connect(path)
    con.execute("create table django_migrations (id integer primary key, app text, name text, applied text)")
    con.executemany("insert into django_migrations (app, name, applied) values ('core', ?, '')", [(m,) for m in migrations])
    con.execute("create table t (x)")
    con.execute("insert into t values (1)")
    con.commit()
    con.close()
    return path


class Fixture(SimpleTestCase):
    """Public worktree + legacy production tree, exactly as the standalone suite builds them."""

    tmp: Path                     # created by the suite's setUp
    pub: Path
    prod: Path
    pkg: Path
    setUp = suite.OverlayTests.setUp
    build_package = suite.OverlayTests.build
    scratch = suite.OverlayTests.scratch

    def merge_base(self):
        return suite.subprocess.run(["git", "-C", str(self.pub), "rev-list", "--max-parents=0", "HEAD"], check=True,
                                    capture_output=True, text=True).stdout.strip()

    def applied(self):
        self.build_package()
        target = self.scratch()
        _manifest, mid = tool.load(self.pkg)
        with redirect_stdout(io.StringIO()):
            tool.apply(self.pkg, target, self.tmp / "backup", "CHG-NMAS-TEST-1", mid[:12], scratch_target=True)
        return target, self.tmp / "backup" / "journal.json"


class HashTests(SimpleTestCase):
    def test_now_returns_a_utc_timestamp(self):
        self.assertRegex(tool.now(), r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$")

    def test_sha256_bytes_returns_the_hex_digest(self):
        self.assertEqual(tool.sha256_bytes(b"abc"), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")

    def test_sha256_bytes_refuses_text(self):
        with self.assertRaises(TypeError):
            tool.sha256_bytes("abc")

    def test_sha256_file_returns_the_digest_of_a_regular_file(self):
        self.assertEqual(tool.sha256_file(Path(sys.executable).resolve()), tool.sha256_bytes(Path(sys.executable).resolve().read_bytes()))

    def test_sha256_file_of_a_missing_directory_or_symlink_is_none(self):
        for label, path in (("a missing file", Path("/nonexistent/nmas")), ("a directory", Path("/usr"))):
            with self.subTest(f"{label} has no digest"):
                self.assertIsNone(tool.sha256_file(path))


class BuildAndLoadTests(Fixture):
    def test_build_freezes_reviewed_entries_and_load_returns_the_review_identity(self):
        manifest = tool.build(self.pub, self.prod, self.pkg, merge_base=self.merge_base())
        self.assertEqual(manifest["problems"], [])
        self.assertEqual({e["path"]: e["action"] for e in manifest["entries"]}["web/core/models.py"], "REPLACE")
        loaded, identity = tool.load(self.pkg)
        self.assertEqual((identity, len(loaded["entries"])), (manifest["entries_sha256"], len(manifest["entries"])))

    def test_build_refuses_an_existing_package_and_reports_add_collisions(self):
        self.pkg.mkdir()
        with self.subTest("an existing package directory is refused"), self.assertRaises(SystemExit):
            tool.build(self.pub, self.prod, self.pkg, merge_base=self.merge_base())
        self.pkg.rmdir()
        suite.write(self.prod, "web/core/checks.py", "PROD = 1\n")
        manifest = tool.build(self.pub, self.prod, self.pkg, merge_base=self.merge_base())
        self.assertIn("ADD target already exists in production: web/core/checks.py", manifest["problems"])

    def test_load_refuses_a_package_with_problems_or_tampered_payload(self):
        self.build_package()
        (self.pkg / "payload" / "web/core/checks.py").write_text("EVIL = 1\n")
        with self.assertRaises(SystemExit):
            tool.load(self.pkg)

    def test_verify_returns_no_finding_for_matching_phases(self):
        self.build_package()
        manifest, _ = tool.load(self.pkg)
        self.assertEqual(tool.verify(manifest["entries"], self.prod, "pre"), [])

    def test_verify_refuses_a_drifted_precondition_with_its_finding(self):
        self.build_package()
        manifest, _ = tool.load(self.pkg)
        (self.prod / "web/core/models.py").write_text("class A: pass\n# hotfix\n")
        bad = tool.verify(manifest["entries"], self.prod, "pre")
        self.assertEqual(len(bad), 1)
        self.assertTrue(bad[0].startswith("pre:REPLACE:web/core/models.py: expected"))

    def test_deployment_diff_renders_the_exact_production_change(self):
        self.build_package()
        text = tool.deployment_diff(self.pkg)
        self.assertIn("+++ b/web/core/checks.py", text)
        self.assertNotIn("PUBLIC_ONLY", text)
        self.assertEqual(len(tool.deployment_diff(self.pkg, summary=True).splitlines()) - 2, len(tool.load(self.pkg)[0]["entries"]))

    def test_deployment_diff_refuses_an_edited_manifest(self):
        self.build_package()
        manifest = json.loads((self.pkg / "manifest.json").read_text())
        manifest["entries"][0]["post_sha256"] = "0" * 64
        (self.pkg / "manifest.json").write_text(json.dumps(manifest))
        with self.assertRaises(SystemExit):
            tool.deployment_diff(self.pkg)


class StageApplyRollbackTests(Fixture):
    def test_stage_overlays_a_reviewed_copy_of_production(self):
        self.build_package()
        out = self.tmp / "staged"
        tool.stage(self.pkg, self.prod, out)
        self.assertEqual(tool.verify(tool.load(self.pkg)[0]["entries"], out, "post"), [])
        self.assertFalse((out / "monitoring/runtime").exists() or (out / ".git").exists())

    def test_stage_refuses_an_existing_output(self):
        self.build_package()
        with self.assertRaises(SystemExit):
            tool.stage(self.pkg, self.prod, self.tmp)

    def test_apply_journals_and_writes_the_reviewed_overlay(self):
        target, journal = self.applied()
        self.assertEqual(json.loads(journal.read_text())["status"], "APPLIED")
        self.assertEqual(tool.verify(tool.load(self.pkg)[0]["entries"], target, "post"), [])
        self.assertEqual(stat.S_IMODE(journal.parent.stat().st_mode), 0o700)

    def test_apply_refuses_unconfirmed_active_or_real_targets(self):
        self.build_package()
        target = self.scratch()
        _manifest, mid = tool.load(self.pkg)
        with self.subTest("a wrong confirmation is refused"), self.assertRaises(SystemExit):
            tool.apply(self.pkg, target, self.tmp / "b1", "CHG-1", "deadbeef0000")
        with self.subTest("active NMAS units are refused"), \
                mock.patch.object(tool, "_services_active", return_value=["nmas-web.service=active"]), self.assertRaises(SystemExit):
            tool.apply(self.pkg, target, self.tmp / "b1", "CHG-1", mid[:12])
        with self.subTest("scratch mode for a real tree is refused"), self.assertRaises(SystemExit):
            tool.apply(self.pkg, self.prod, self.tmp / "b1", "CHG-1", mid[:12], scratch_target=True)
        self.assertFalse((self.tmp / "b1").exists() or (target / "web/core/checks.py").exists())

    def test_applied_overlay_migrations_returns_recorded_overlay_migrations(self):
        db = make_db(self.tmp / "db.sqlite3", CORE_HEAD, "0039_observation_authorizations")
        self.assertEqual(tool.applied_overlay_migrations(db, tool.OVERLAY_MIGRATIONS), ["0039_observation_authorizations"])

    def test_applied_overlay_migrations_of_a_database_without_the_table_is_missing_nothing(self):
        db = self.tmp / "empty.sqlite3"
        sqlite3.connect(db).close()
        self.assertEqual(tool.applied_overlay_migrations(db, tool.OVERLAY_MIGRATIONS), [])

    def test_rollback_restores_the_exact_pre_state(self):
        target, journal = self.applied()
        db = make_db(self.tmp / "db.sqlite3", CORE_HEAD)
        with redirect_stdout(io.StringIO()):
            tool.rollback(journal, db, skip_db_check=False)
        self.assertEqual(tool.verify(tool.load(self.pkg)[0]["entries"], target, "pre"), [])
        self.assertEqual(json.loads(journal.read_text())["status"], "ROLLED_BACK")

    def test_rollback_refuses_applied_migrations_or_a_corrupt_backup(self):
        target, journal = self.applied()
        db = make_db(self.tmp / "db.sqlite3", CORE_HEAD, "0039_observation_authorizations")
        with self.subTest("an applied overlay migration is refused"), self.assertRaises(SystemExit):
            tool.rollback(journal, db, skip_db_check=False)
        (journal.parent / "files/web/core/models.py").write_text("corrupt\n")
        with self.subTest("a corrupt backup is refused"), self.assertRaises(SystemExit):
            tool.rollback(journal, None, skip_db_check=True)
        self.assertTrue((target / "web/core/checks.py").exists())                  # nothing was rolled back


class DatabaseAndArchiveTests(Fixture):
    def test_db_backup_and_db_restore_round_trip_a_consistent_copy(self):
        live = make_db(self.tmp / "live.sqlite3", CORE_HEAD)
        record = tool.db_backup(live, self.tmp / "bk" / "db.sqlite3")
        self.assertEqual((record["integrity_check"], record["core_migration_head"]), ("ok", CORE_HEAD))
        con = sqlite3.connect(live)
        con.execute("insert into t values (2)")
        con.commit()
        con.close()
        result = tool.db_restore(self.tmp / "bk" / "db.sqlite3", live, record["sha256"][:12], scratch_target=True)
        self.assertEqual(tool.sha256_file(live), record["sha256"])
        self.assertEqual(sqlite3.connect(result["previous_kept_at"]).execute("select count(*) from t").fetchone()[0], 2)

    def test_db_backup_and_db_restore_refuse_overwrites_unconfirmed_or_deployed_targets(self):
        live = make_db(self.tmp / "live.sqlite3", CORE_HEAD)
        record = tool.db_backup(live, self.tmp / "bk" / "db.sqlite3")
        backup = self.tmp / "bk" / "db.sqlite3"
        with self.subTest("an existing backup file is refused"), self.assertRaises(SystemExit):
            tool.db_backup(live, backup)
        with self.subTest("a missing source database is refused"), self.assertRaises(SystemExit):
            tool.db_backup(self.tmp / "nope.sqlite3", self.tmp / "bk2" / "db.sqlite3")
        with self.subTest("a wrong confirmation is refused"), self.assertRaises(SystemExit):
            tool.db_restore(backup, live, "0" * 12, scratch_target=True)
        with self.subTest("a database inside the deployed tree is refused"), self.assertRaises(SystemExit):
            tool.db_restore(backup, Path(tool.PRODUCTION_DEFAULT) / "web" / "db.sqlite3", record["sha256"][:12], scratch_target=True)

    def test_source_archive_keeps_source_and_omits_runtime_secrets(self):
        import tarfile

        suite.write(self.prod, "netbox/.env", "TOKEN=placeholder\n")
        record = tool.source_archive(self.prod, self.tmp / "src.tar.gz")
        with tarfile.open(self.tmp / "src.tar.gz") as tar:
            names = set(tar.getnames())
        self.assertIn("web/core/prod_only.py", names)
        self.assertFalse(names & {"netbox/.env", "monitoring/runtime/secret.env", "web/var/device-locks/x.lock"})
        self.assertEqual(record["sha256"], tool.sha256_file(self.tmp / "src.tar.gz"))

    def test_source_archive_refuses_an_existing_archive(self):
        (self.tmp / "src.tar.gz").write_bytes(b"")
        with self.assertRaises(SystemExit):
            tool.source_archive(self.prod, self.tmp / "src.tar.gz")


class CommandLineTests(Fixture):
    def test_main_returns_zero_for_a_verified_tree(self):
        self.build_package()
        out = io.StringIO()
        with redirect_stdout(out):
            self.assertEqual(tool.main(["verify", "--package", str(self.pkg), "--tree", str(self.prod), "--phase", "pre"]), 0)
        self.assertTrue(re.match(r"VERIFIED \(pre\): all \d+ entries match", out.getvalue()))

    def test_main_fails_a_drifted_tree_verification(self):
        self.build_package()
        (self.prod / "web/core/models.py").write_text("drift\n")
        with redirect_stdout(io.StringIO()):
            self.assertEqual(tool.main(["verify", "--package", str(self.pkg), "--tree", str(self.prod), "--phase", "pre"]), 1)
