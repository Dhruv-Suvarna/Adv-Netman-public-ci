"""Direct tests for the approval-gated worker runtime installer (deploy/sandbox/worker_runtime.py).

The installer copies only manifest-reviewed application files and RECORD-verified dependencies, never adopts a
foreign runtime, and detects any drift of the installed tree.  Every fixture is disposable: a fake source tree with
the same secret/database/generated-file traps as the standalone suite, and a one-package virtual environment whose
wheel RECORD hashes are real.  Installation runs in ``--test-mode`` below a temporary directory.
"""

from __future__ import annotations

import argparse
import base64
import csv
import hashlib
import importlib.util
import io
import json
import sys
import tempfile
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

from django.test import SimpleTestCase

SANDBOX = Path(__file__).resolve().parents[3] / "deploy" / "sandbox"
_spec = importlib.util.spec_from_file_location("worker_runtime", SANDBOX / "worker_runtime.py")
wr = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(wr)

PACKAGE, METADATA = b"VALUE = 1\n", b"Name: demo-dependency\nVersion: 1.0\n"


def write(path: Path, data: bytes) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return path


def record_value(data: bytes) -> str:
    return "sha256=" + base64.urlsafe_b64encode(hashlib.sha256(data).digest()).decode().rstrip("=")


class Fixture(SimpleTestCase):
    """A reviewed source tree, a one-dependency venv, its lock and a reviewed overlay."""

    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix="nmas-worker-runtime-unit-")
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.source = self.root / "source"
        write(self.source / "web/manage.py", b"print('worker help')\n")
        write(self.source / "web/var/device-locks/transient.lock", b"runtime-only\n")
        write(self.source / "netbox/.env", b"PLACEHOLDER=not-a-secret\n")
        write(self.source / "web/core/__pycache__/x.cpython-312.pyc", b"\0")
        write(self.source / "inventory.yml", b"network_devices: {}\n")
        self.venv = self.root / "source-venv"
        self.site = self.venv / "lib/python3.12/site-packages"
        write(self.site / "demo_dependency/__init__.py", PACKAGE)
        write(self.site / "demo_dependency-1.0.dist-info/METADATA", METADATA)
        self.write_record()
        self.lock = write(self.root / "lock", b"demo-dependency==1.0\n")
        self.manifest_path = self.root / "manifest.json"
        self.manifest = wr.build_manifest(self.source, self.manifest_path, "TEST-RELEASE-0001")
        self.overlay = self.root / "overlay"
        write(self.overlay / "web/manage.py", b"print('overlay worker help')\n")
        self.overlay_path = self.root / "overlay.json"
        self.overlay_manifest = wr.build_overlay_manifest(self.overlay, self.overlay_path, "TEST-OVERLAY-0001", ["web/manage.py"])

    def write_record(self, package_hash=None):
        record = self.site / "demo_dependency-1.0.dist-info/RECORD"
        with record.open("w", newline="", encoding="utf-8") as stream:
            csv.writer(stream).writerows([("demo_dependency/__init__.py", package_hash or record_value(PACKAGE), str(len(PACKAGE))),
                                          ("demo_dependency-1.0.dist-info/METADATA", record_value(METADATA), str(len(METADATA))),
                                          ("demo_dependency-1.0.dist-info/RECORD", "", ""),
                                          ("../../../bin/demo", record_value(b"x"), "1")])

    def args(self, **over):
        base = {"source": self.source, "source_manifest": self.manifest_path, "overlay_root": self.overlay,
                "overlay_manifest": self.overlay_path, "source_venv": self.venv, "lock": self.lock, "python": Path(sys.executable),
                "runtime": self.root / "opt/nmas", "state_root": self.root / "state", "test_mode": True}
        return argparse.Namespace(**{**base, **over})

    def installed(self):
        with mock.patch.object(wr, "smoke"):
            return wr.install(self.args())


# ================================================================================================== primitives
class PrimitiveTests(Fixture):
    def test_digest_returns_the_file_sha256(self):
        self.assertEqual(wr.digest(self.lock), hashlib.sha256(b"demo-dependency==1.0\n").hexdigest())

    def test_digest_of_a_missing_file_raises(self):
        with self.assertRaises(FileNotFoundError):
            wr.digest(self.root / "nope")

    def test_safe_regular_returns_a_regular_file(self):
        self.assertEqual(wr.safe_regular(self.lock, label="lock").st_size, len(b"demo-dependency==1.0\n"))

    def test_safe_regular_refuses_a_symlink_directory_or_missing_file(self):
        (self.root / "link").symlink_to(self.lock)
        for label, path in (("a symlink", self.root / "link"), ("a directory", self.root), ("a missing file", self.root / "nope")):
            with self.subTest(f"{label} is refused"), self.assertRaises(wr.Refused):
                wr.safe_regular(path, label=label)

    def test_canonical_name_folds_separators_and_case(self):
        self.assertEqual(wr.canonical_name("Demo_Dependency.Core"), "demo-dependency-core")

    def test_canonical_name_never_accepts_a_non_text_name(self):
        with self.assertRaises(TypeError):
            wr.canonical_name(None)

    def test_excluded_omits_secrets_database_and_generated_files(self):
        for path in ("netbox/.env", "web/db.sqlite3", "web/db.sqlite3-wal", ".git/config", "web/core/__pycache__/x.pyc",
                     "web/var/locks/x", "monitoring/runtime/store.json", "deploy/sandbox/stage-b/dispatch-source-manifest.json"):
            with self.subTest(path=path):
                self.assertTrue(wr.excluded(path))

    def test_excluded_never_omits_reviewed_application_source(self):
        self.assertFalse(wr.excluded("web/core/models.py"))
        self.assertFalse(wr.excluded("deploy/sandbox/worker_runtime.py"))

    def test_write_json_exclusive_creates_a_private_file(self):
        target = self.root / "out" / "x.json"
        wr.write_json_exclusive(target, {"a": 1})
        self.assertEqual((json.loads(target.read_text()), oct(target.stat().st_mode & 0o777)), ({"a": 1}, "0o600"))

    def test_write_json_exclusive_refuses_to_replace_an_existing_file(self):
        with self.assertRaises(FileExistsError):
            wr.write_json_exclusive(self.lock, {"a": 1})

    def test_state_path_returns_the_install_state_receipt(self):
        self.assertEqual(wr.state_path(Path("/var/lib/nmas-worker-runtime")), Path("/var/lib/nmas-worker-runtime/install-state.json"))

    def test_state_path_never_leaves_the_state_root(self):
        self.assertNotEqual(wr.state_path(self.root / "a").parent, self.root / "b")
        self.assertEqual(wr.state_path(self.root / "a").parent, self.root / "a")

    def test_record_hash_decodes_a_wheel_record_hash(self):
        self.assertEqual(wr.record_hash(record_value(PACKAGE)), ("sha256", hashlib.sha256(PACKAGE).digest()))

    def test_record_hash_of_a_missing_or_malformed_hash_is_refused(self):
        with self.subTest("a missing hash is none"):
            self.assertIsNone(wr.record_hash(""))
        with self.subTest("a hash without an algorithm is refused"), self.assertRaises(ValueError):
            wr.record_hash("deadbeef")

    def test_metadata_value_reads_the_named_field(self):
        self.assertEqual(wr.metadata_value(self.site / "demo_dependency-1.0.dist-info/METADATA", "version"), "1.0")

    def test_metadata_value_of_a_missing_field_is_empty(self):
        self.assertEqual(wr.metadata_value(self.site / "demo_dependency-1.0.dist-info/METADATA", "License"), "")


# ============================================================================================ reviewed inputs
class ManifestTests(Fixture):
    def test_source_files_and_build_manifest_list_reviewed_files_only(self):
        paths = [row["path"] for row in wr.source_files(self.source)]
        self.assertEqual(paths, ["inventory.yml", "web/manage.py"])
        built = wr.build_manifest(self.source, self.root / "again.json", "TEST-RELEASE-0003")
        self.assertEqual((built["release_id"], [row["path"] for row in built["files"]]), ("TEST-RELEASE-0003", paths))
        self.assertEqual(json.loads((self.root / "again.json").read_text()), built)

    def test_source_files_and_build_manifest_refuse_symlinks_or_a_malformed_release(self):
        with self.subTest("a malformed release id is refused"), self.assertRaises(wr.Refused):
            wr.build_manifest(self.source, self.root / "m2.json", "bad id")
        (self.source / "bad-link").symlink_to("web/manage.py")
        with self.subTest("a source symlink is refused"), self.assertRaises(wr.Refused):
            wr.source_files(self.source)
        with self.subTest("a source without manage.py is refused"), self.assertRaises(wr.Refused):
            wr.source_files(self.overlay.parent / "source-venv")

    def test_build_overlay_manifest_records_each_reviewed_replacement(self):
        built = wr.build_overlay_manifest(self.overlay, self.root / "overlay2.json", "TEST-OVERLAY-0003", ["web/manage.py", "web/manage.py"])
        self.assertEqual([row["path"] for row in built["files"]], ["web/manage.py"])
        self.assertEqual(built["files"][0]["sha256"], hashlib.sha256(b"print('overlay worker help')\n").hexdigest())

    def test_build_overlay_manifest_refuses_escaping_or_excluded_paths(self):
        for path in ("../etc/passwd", "/etc/passwd", "netbox/.env"):
            with self.subTest(f"{path} is refused"), self.assertRaises(wr.Refused):
                wr.build_overlay_manifest(self.overlay, self.root / f"o-{abs(hash(path))}.json", "TEST-OVERLAY-0002", [path])

    def test_load_json_and_load_lock_return_reviewed_inputs(self):
        self.assertEqual(wr.load_json(self.manifest_path, wr.SOURCE_SCHEMA)["release_id"], "TEST-RELEASE-0001")
        self.assertEqual(wr.load_lock(self.lock), {"demo-dependency": ("demo-dependency", "1.0")})

    def test_load_json_and_load_lock_refuse_wrong_schema_or_duplicate_pins(self):
        with self.subTest("another schema is refused"), self.assertRaises(wr.Refused):
            wr.load_json(self.manifest_path, wr.OVERLAY_SCHEMA)
        for label, text in (("a duplicate pin", b"demo-dependency==1.0\ndemo_dependency==1.0\n"), ("an unpinned line", b"demo-dependency>=1\n"),
                            ("an empty lock", b"# nothing\n")):
            with self.subTest(f"{label} is refused"), self.assertRaises(wr.Refused):
                wr.load_lock(write(self.root / "bad.lock", text))

    def test_verify_source_and_overlay_accept_the_reviewed_trees(self):
        self.assertIsNone(wr.verify_source(self.manifest, self.source))
        self.assertIsNone(wr.verify_overlay(self.overlay_manifest, self.overlay, self.manifest))

    def test_verify_source_and_overlay_refuse_changed_or_new_files(self):
        write(self.overlay / "web/manage.py", b"print('changed')\n")
        with self.subTest("a changed overlay is refused"), self.assertRaises(wr.Refused):
            wr.verify_overlay(self.overlay_manifest, self.overlay, self.manifest)
        with self.subTest("an overlay of an unreviewed path is refused"), self.assertRaises(wr.Refused):
            wr.verify_overlay({**self.overlay_manifest, "files": [{"path": "web/new.py"}]}, self.overlay, self.manifest)
        write(self.source / "web/new.py", b"x = 1\n")
        with self.subTest("a new source file is refused"), self.assertRaises(wr.Refused):
            wr.verify_source(self.manifest, self.source)


class DependencyTests(Fixture):
    def test_site_packages_and_distribution_records_return_verified_files(self):
        self.assertEqual(wr.site_packages(self.venv), self.site)
        copied = sorted(relative.as_posix() for _source, relative in wr.distribution_records(self.venv, wr.load_lock(self.lock)))
        self.assertEqual(copied, ["demo_dependency-1.0.dist-info/METADATA", "demo_dependency-1.0.dist-info/RECORD",
                                  "demo_dependency/__init__.py"])

    def test_site_packages_and_distribution_records_refuse_mismatched_dependencies(self):
        with self.subTest("an ambiguous venv is refused"), self.assertRaises(wr.Refused):
            wr.site_packages(self.root)
        with self.subTest("a different pinned version is refused"), self.assertRaises(wr.Refused):
            wr.distribution_records(self.venv, {"demo-dependency": ("demo-dependency", "2.0")})
        self.write_record(package_hash=record_value(b"tampered"))
        with self.subTest("a RECORD hash mismatch is refused"), self.assertRaises(wr.Refused):
            wr.distribution_records(self.venv, wr.load_lock(self.lock))

    def test_reject_symlink_components_accepts_a_real_path(self):
        self.assertIsNone(wr.reject_symlink_components(self.site, Path("demo_dependency/__init__.py")))

    def test_reject_symlink_components_refuses_a_symlinked_directory(self):
        (self.site / "linked").symlink_to(self.site / "demo_dependency")
        with self.assertRaises(wr.Refused):
            wr.reject_symlink_components(self.site, Path("linked/__init__.py"))


# ======================================================================================== copy & installed tree
class TreeTests(Fixture):
    def test_copy_source_and_overlay_build_the_reviewed_application(self):
        destination = self.root / "copy"
        wr.copy_source(self.manifest, self.source, destination)
        wr.copy_overlay(self.overlay_manifest, self.overlay, destination)
        self.assertEqual((destination / "web/manage.py").read_text(), "print('overlay worker help')\n")
        self.assertFalse((destination / "netbox/.env").exists())
        self.assertEqual((destination / "web/db.sqlite3").stat().st_mode & 0o777, 0)      # inert placeholder only

    def test_copy_source_and_overlay_refuse_existing_or_missing_destinations(self):
        with self.subTest("an existing destination is refused"), self.assertRaises(FileExistsError):
            wr.copy_source(self.manifest, self.source, self.root)
        with self.subTest("an overlay without its base file is refused"), self.assertRaises(wr.Refused):
            wr.copy_overlay(self.overlay_manifest, self.overlay, self.root / "empty")

    def test_allowed_venv_symlink_and_tree_manifest_accept_interpreter_links(self):
        runtime = self.root / "rt"
        (runtime / "venv/bin").mkdir(parents=True)
        (runtime / "venv/bin/python").symlink_to(sys.executable)
        (runtime / "venv/lib64").symlink_to("lib")
        self.assertTrue(wr.allowed_venv_symlink(runtime / "venv/bin/python", runtime))
        self.assertTrue(wr.allowed_venv_symlink(runtime / "venv/lib64", runtime))
        rows = {row["path"]: row["type"] for row in wr.tree_manifest(runtime)}
        self.assertEqual(rows, {"venv": "directory", "venv/bin": "directory", "venv/bin/python": "symlink", "venv/lib64": "symlink"})

    def test_allowed_venv_symlink_and_tree_manifest_refuse_other_links(self):
        runtime = self.root / "rt"
        (runtime / "venv").mkdir(parents=True)
        (runtime / "venv/lib64").symlink_to("/etc")
        (runtime / "escape").symlink_to("/etc/passwd")
        with self.subTest("a retargeted lib64 is refused"):
            self.assertFalse(wr.allowed_venv_symlink(runtime / "venv/lib64", runtime))
        with self.subTest("an arbitrary symlink is refused"):
            self.assertFalse(wr.allowed_venv_symlink(runtime / "escape", runtime))
            with self.assertRaises(wr.Refused):
                wr.tree_manifest(runtime)

    def runtime_for_smoke(self, manage: bytes):
        runtime = self.root / "smoke"
        write(runtime / "current/web/manage.py", manage)
        python = write(runtime / "venv/bin/python", f'#!/bin/sh\nexec "{sys.executable}" "$@"\n'.encode())
        python.chmod(0o755)
        return runtime

    def test_smoke_passes_a_runnable_worker_runtime(self):
        self.assertIsNone(wr.smoke(self.runtime_for_smoke(b"print('help')\n")))

    def test_smoke_refuses_a_worker_that_cannot_start(self):
        with self.assertRaises(wr.Refused):
            wr.smoke(self.runtime_for_smoke(b"raise SystemExit('broken worker')\n"))


# ============================================================================================ lifecycle
class LifecycleTests(Fixture):
    def test_plan_returns_a_read_only_plan(self):
        out = wr.plan(self.args())
        self.assertEqual((out["result"], out["source_files"], out["overlay_files"], out["mutations"]), ("plan-valid", 2, 1, 0))
        self.assertFalse((self.root / "opt/nmas").exists())

    def test_plan_refuses_a_drifted_source(self):
        write(self.source / "web/manage.py", b"print('drift')\n")
        with self.assertRaises(wr.Refused):
            wr.plan(self.args())

    def test_install_and_verify_build_then_confirm_the_owned_runtime(self):
        self.assertEqual(self.installed()["result"], "installed")
        runtime = self.root / "opt/nmas"
        self.assertEqual((runtime / "current/web/manage.py").read_text(), "print('overlay worker help')\n")
        self.assertEqual(runtime.stat().st_mode & 0o777, 0o755)
        self.assertTrue(next(runtime.glob("venv/lib/python*/site-packages/demo_dependency/__init__.py")).is_file())
        with mock.patch.object(wr, "smoke"):
            self.assertEqual(wr.verify(self.args())["result"], "verified")
            self.assertEqual(wr.install(self.args())["result"], "already-installed")

    def test_install_and_verify_refuse_foreign_runtimes_or_drift(self):
        (self.root / "opt/nmas").mkdir(parents=True)
        with self.subTest("a foreign runtime is never adopted"), self.assertRaises(wr.Refused):
            self.installed()
        (self.root / "opt/nmas").rmdir()
        self.installed()
        write(self.root / "opt/nmas/current/foreign", b"not owned")
        with self.subTest("installed drift is refused"), mock.patch.object(wr, "smoke"), self.assertRaises(wr.Refused):
            wr.verify(self.args())

    def test_uninstall_removes_the_owned_runtime_once(self):
        self.installed()
        with mock.patch.object(wr, "smoke"):
            self.assertEqual(wr.uninstall(self.args())["result"], "uninstalled")
        self.assertFalse((self.root / "opt/nmas").exists())
        self.assertEqual(wr.uninstall(self.args())["result"], "already-absent")

    def test_uninstall_refuses_a_foreign_runtime_or_active_workers(self):
        (self.root / "opt/nmas").mkdir(parents=True)
        with self.subTest("a runtime without ownership state is never removed"), self.assertRaises(wr.Refused):
            wr.uninstall(self.args())
        self.assertTrue((self.root / "opt/nmas").exists())
        with self.subTest("a live worker namespace blocks production removal"), \
                mock.patch.object(wr, "NAMESPACES", (str(self.lock),)), self.assertRaises(wr.Refused):
            wr.uninstall(self.args(test_mode=False))

    def test_active_guard_passes_with_no_worker_namespace_or_unit(self):
        self.assertIsNone(wr.active_guard(True))
        with mock.patch.object(wr, "NAMESPACES", (str(self.root / "absent"),)), mock.patch.object(wr, "UNITS", ()):
            self.assertIsNone(wr.active_guard(False))

    def test_active_guard_refuses_an_active_worker_unit(self):
        active = mock.Mock(returncode=0)
        with mock.patch.object(wr, "NAMESPACES", ()), mock.patch.object(wr.subprocess, "run", return_value=active), \
                self.assertRaises(wr.Refused):
            wr.active_guard(False)


class CommandLineTests(Fixture):
    def test_parse_returns_reviewed_defaults(self):
        args = wr.parse(["plan", "--source-manifest", "m.json"])
        self.assertEqual((args.action, args.runtime, args.test_mode), ("plan", Path("/opt/nmas"), False))

    def test_parse_refuses_an_unknown_action(self):
        with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            wr.parse(["adopt"])

    def test_main_returns_zero_for_a_valid_plan(self):
        out = io.StringIO()
        argv = ["plan", "--source", str(self.source), "--source-manifest", str(self.manifest_path), "--source-venv", str(self.venv),
                "--lock", str(self.lock)]
        with redirect_stdout(out):
            self.assertEqual(wr.main(argv), 0)
        self.assertEqual(json.loads(out.getvalue())["result"], "plan-valid")

    def test_main_refuses_unpaired_overlay_or_unprivileged_install(self):
        err = io.StringIO()
        cases = (("an overlay root without its manifest", ["plan", "--source-manifest", str(self.manifest_path), "--overlay-root", str(self.overlay)]),
                 ("a missing source manifest", ["verify"]),
                 ("an unprivileged production install", ["install", "--source-manifest", str(self.manifest_path)]))
        for label, argv in cases:
            with self.subTest(f"{label} is refused"), redirect_stderr(err), mock.patch.object(wr.os, "geteuid", return_value=1000):
                self.assertEqual(wr.main(argv), 65)
        self.assertIn("REFUSED", err.getvalue())
