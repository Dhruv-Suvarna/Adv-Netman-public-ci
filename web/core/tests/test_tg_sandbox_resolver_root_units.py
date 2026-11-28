"""Direct tests for the /etc/netns resolver-root ownership controller (deploy/sandbox/resolver_root.py).

The controller creates the resolver root only with an exclusive ownership receipt, never adopts a foreign path, and
removes only the exact empty directory its receipt names.  Test mode (the caller's own uid/gid) is confined to a
disposable ``/tmp/nmas-resolver-root-test-*`` fixture, exactly as the controller's argument parser demands.
"""

from __future__ import annotations

import importlib.util
import io
import json
import os
import shutil
import tempfile
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

from django.test import SimpleTestCase

_spec = importlib.util.spec_from_file_location(
    "resolver_root", Path(__file__).resolve().parents[3] / "deploy" / "sandbox" / "resolver_root.py")
rr = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(rr)
CHANGE = "CHG-NMAS-TEST-RESOLVER-0001"


class Fixture(SimpleTestCase):
    def setUp(self):
        self.base = Path(tempfile.mkdtemp(prefix="nmas-resolver-root-test-", dir="/tmp"))
        self.addCleanup(shutil.rmtree, self.base, True)
        (self.base / "etc").mkdir(mode=0o755)
        (self.base / "var").mkdir(mode=0o700)
        self.root, self.state = self.base / "etc" / "netns", self.base / "var" / "resolver-root.json"
        self.uid, self.gid = os.geteuid(), os.getegid()

    def args(self, action="plan", change=CHANGE):
        return rr.parse([action, "--change-id", change, "--root", str(self.root), "--state", str(self.state), "--test-mode"])

    def fd(self, path):
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
        self.addCleanup(os.close, fd)
        return fd


class PrimitiveTests(Fixture):
    def test_context_returns_the_caller_identity_in_test_mode(self):
        self.assertEqual(rr.context(self.args()), (self.uid, self.gid))

    def test_context_never_trusts_the_caller_identity_in_production(self):
        self.assertEqual(rr.context(mock.Mock(test_mode=False)), (0, 0))

    def test_trusted_directory_returns_an_open_verified_directory(self):
        fd, info = rr.trusted_directory(self.base / "etc", self.uid, self.gid, "parent")
        os.close(fd)
        self.assertEqual(info.st_ino, (self.base / "etc").stat().st_ino)

    def test_trusted_directory_refuses_writable_foreign_or_symlinked_directories(self):
        loose = self.base / "loose"
        loose.mkdir()
        loose.chmod(0o777)
        (self.base / "link").symlink_to(self.base / "etc")
        for label, path, uid in (("a world-writable directory", loose, self.uid), ("a symlink", self.base / "link", self.uid),
                                 ("another owner", self.base / "etc", self.uid + 1), ("a missing directory", self.base / "nope", self.uid)):
            with self.subTest(f"{label} is refused"), self.assertRaises(rr.Refused):
                rr.trusted_directory(path, uid, self.gid, label)

    def test_entry_exists_and_target_info_see_an_existing_entry(self):
        self.root.mkdir()
        parent = self.fd(self.base / "etc")
        self.assertTrue(rr.entry_exists(parent, "netns"))
        self.assertEqual(rr.target_info(parent).st_ino, self.root.stat().st_ino)

    def test_entry_exists_and_target_info_of_a_missing_entry_are_empty(self):
        parent = self.fd(self.base / "etc")
        with self.subTest("a missing entry does not exist"):
            self.assertFalse(rr.entry_exists(parent, "netns"))
        with self.subTest("a missing resolver root has no info"):
            self.assertIsNone(rr.target_info(parent))

    def test_write_state_and_safe_state_roundtrip_a_private_receipt(self):
        var = self.fd(self.base / "var")
        rr.write_state(var, self.state.name, {"schema": rr.SCHEMA, "change_id": CHANGE}, self.uid)
        self.assertEqual(oct(self.state.stat().st_mode & 0o777), "0o600")
        self.assertEqual(rr.safe_state(var, self.state.name, self.uid)["change_id"], CHANGE)

    def test_write_state_and_safe_state_refuse_existing_unsafe_or_foreign_receipts(self):
        var = self.fd(self.base / "var")
        self.state.write_text(json.dumps({"schema": "someone-else/1"}))
        self.state.chmod(0o600)
        with self.subTest("an existing receipt is never overwritten"), self.assertRaises(FileExistsError):
            rr.write_state(var, self.state.name, {"schema": rr.SCHEMA}, self.uid)
        with self.subTest("a foreign schema is refused"), self.assertRaises(rr.Refused):
            rr.safe_state(var, self.state.name, self.uid)
        self.state.chmod(0o644)
        with self.subTest("a readable receipt is refused"), self.assertRaises(rr.Refused):
            rr.safe_state(var, self.state.name, self.uid)
        with self.subTest("a missing receipt is refused"), self.assertRaises(rr.Refused):
            rr.safe_state(var, "absent.json", self.uid)

    def test_validate_target_accepts_the_owned_directory(self):
        self.root.mkdir(mode=0o755)
        self.root.chmod(0o755)
        info = self.root.stat()
        parent = self.fd(self.base / "etc")
        self.assertEqual(rr.validate_target(parent, {"directory_dev": info.st_dev, "directory_ino": info.st_ino}, self.uid, self.gid).st_ino,
                         info.st_ino)

    def test_validate_target_refuses_a_replaced_or_loosened_directory(self):
        self.root.mkdir(mode=0o755)
        self.root.chmod(0o755)
        info = self.root.stat()
        parent = self.fd(self.base / "etc")
        with self.subTest("another inode is refused"), self.assertRaises(rr.Refused):
            rr.validate_target(parent, {"directory_dev": info.st_dev, "directory_ino": info.st_ino + 1}, self.uid, self.gid)
        self.root.chmod(0o775)
        with self.subTest("a changed mode is refused"), self.assertRaises(rr.Refused):
            rr.validate_target(parent, {"directory_dev": info.st_dev, "directory_ino": info.st_ino}, self.uid, self.gid)

    def test_inspect_returns_both_trusted_parents(self):
        parent_fd, parent, state_fd, state_parent, uid, _gid = rr.inspect(self.args())
        os.close(parent_fd)
        os.close(state_fd)
        self.assertEqual((parent.st_ino, state_parent.st_ino, uid), ((self.base / "etc").stat().st_ino, (self.base / "var").stat().st_ino, self.uid))

    def test_inspect_refuses_a_writable_state_parent(self):
        (self.base / "var").chmod(0o777)
        with self.assertRaises(rr.Refused):
            rr.inspect(self.args())


class LifecycleTests(Fixture):
    def test_plan_install_verify_and_rollback_own_exactly_one_directory(self):
        self.assertEqual(rr.plan(self.args())["result"], "ready-to-create")
        self.assertEqual(rr.install(self.args("install"))["result"], "created")
        self.assertEqual(rr.plan(self.args())["result"], "already-owned")
        self.assertEqual(rr.install(self.args("install"))["result"], "already-owned")
        self.assertEqual(rr.verify(self.args("verify"))["change_id"], CHANGE)
        self.assertEqual(rr.verify_owned(self.args("verify"))["path"], str(self.root))
        self.assertEqual(rr.rollback(self.args("rollback"))["result"], "removed")
        self.assertFalse(self.root.exists() or self.state.exists())
        self.assertEqual(rr.rollback(self.args("rollback"))["result"], "already-absent")

    def test_plan_and_install_refuse_a_foreign_resolver_root(self):
        self.root.mkdir()
        with self.subTest("planning over a foreign root is refused"), self.assertRaises(rr.Refused):
            rr.plan(self.args())
        with self.subTest("installing over a foreign root is refused"), self.assertRaises(rr.Refused):
            rr.install(self.args("install"))
        self.assertFalse(self.state.exists())

    def test_verify_and_verify_owned_refuse_another_change(self):
        rr.install(self.args("install"))
        with self.subTest("verify for another change is refused"), self.assertRaises(rr.Refused):
            rr.verify(self.args("verify", change="CHG-NMAS-SOMEONE-ELSE"))
        with self.subTest("ownership for another change is refused"), self.assertRaises(rr.Refused):
            rr.verify_owned(self.args("verify", change="CHG-NMAS-SOMEONE-ELSE"))

    def test_rollback_refuses_a_non_empty_or_unreceipted_root(self):
        rr.install(self.args("install"))
        (self.root / "nmas-ts-research").mkdir()
        with self.subTest("a non-empty root is never removed"), self.assertRaises(rr.Refused):
            rr.rollback(self.args("rollback"))
        (self.root / "nmas-ts-research").rmdir()
        self.state.unlink()
        with self.subTest("a root without its receipt is never removed"), self.assertRaises(rr.Refused):
            rr.rollback(self.args("rollback"))
        self.assertTrue(self.root.is_dir())

    def test_install_and_rollback_refuse_unprivileged_production_mutation(self):
        production = mock.Mock(test_mode=False)
        with mock.patch.object(rr.os, "geteuid", return_value=1000):
            for name, call in (("install", rr.install), ("rollback", rr.rollback)):
                with self.subTest(f"production {name} is refused"), self.assertRaises(rr.Refused):
                    call(production)


class CommandLineTests(Fixture):
    def test_parse_returns_contained_test_paths(self):
        args = self.args("verify")
        self.assertEqual((args.action, args.root, args.test_mode), ("verify", self.root, True))

    def test_parse_refuses_malformed_ids_or_uncontained_paths(self):
        cases = (("a malformed change id", ["plan", "--change-id", "x", "--root", str(self.root), "--state", str(self.state), "--test-mode"]),
                 ("a test root outside the fixture", ["plan", "--change-id", CHANGE, "--root", "/var/tmp/netns", "--state", str(self.state), "--test-mode"]),
                 ("a moved production root", ["plan", "--change-id", CHANGE, "--root", "/srv/netns"]))
        for label, argv in cases:
            with self.subTest(f"{label} is refused"), redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                rr.parse(argv)

    def argv(self, action):
        return [action, "--change-id", CHANGE, "--root", str(self.root), "--state", str(self.state), "--test-mode"]

    def test_main_returns_zero_and_prints_the_result(self):
        out = io.StringIO()
        with redirect_stdout(out):
            self.assertEqual(rr.main(self.argv("plan")), 0)
        self.assertEqual(json.loads(out.getvalue())["result"], "ready-to-create")

    def test_main_refuses_verification_without_ownership(self):
        err = io.StringIO()
        with redirect_stderr(err):
            self.assertEqual(rr.main(self.argv("verify")), 65)
        self.assertIn("REFUSED", err.getvalue())
