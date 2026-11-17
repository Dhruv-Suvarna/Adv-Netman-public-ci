import getpass
import json
import os
import tempfile
import unittest

import sync_worker_credential as s

FULL = {"schema_version": 3, "secrets": {"r2-nmas-automation": {"current": {"password": "A"}, "pending": None},
                                         "s2-nmas-diag": {"current": {"password": "D"}, "pending": None},
                                         "r1-breakglass": {"current": {"password": "X"}, "pending": None}}}


class SyncTests(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.TemporaryDirectory()
        self.full, self.copy = os.path.join(self.d.name, "store.json"), os.path.join(self.d.name, "copy.json")
        self.write(FULL)
        self.restarts = 0

    def tearDown(self):
        self.d.cleanup()

    def write(self, data):
        with open(self.full, "w") as fh:
            json.dump(data, fh)

    def run_sync(self):
        return s.sync(self.full, self.copy, ["r2-nmas-automation", "s2-nmas-diag"], getpass.getuser(),
                      lambda: setattr(self, "restarts", self.restarts + 1))

    def test_copies_only_the_allowlisted_secret_with_0600(self):
        self.assertEqual(self.run_sync(), "SYNCED")
        with open(self.copy, encoding="utf-8") as stream:
            data = json.load(stream)
        self.assertEqual(sorted(data["secrets"]), ["r2-nmas-automation", "s2-nmas-diag"])  # never the rest of the store
        self.assertEqual(os.stat(self.copy).st_mode & 0o777, 0o600)
        self.assertEqual(self.restarts, 1)

    def test_unchanged_store_means_no_write_and_no_restart(self):
        self.run_sync()
        self.assertEqual(self.run_sync(), "UNCHANGED")
        self.assertEqual(self.restarts, 1)

    def test_rotation_is_propagated_and_worker_restarted(self):
        self.run_sync()
        rotated = json.loads(json.dumps(FULL))
        rotated["secrets"]["r2-nmas-automation"]["current"] = {"password": "B"}
        self.write(rotated)
        self.assertEqual(self.run_sync(), "SYNCED")
        with open(self.copy, encoding="utf-8") as stream:
            copied = json.load(stream)
        self.assertEqual(copied["secrets"]["r2-nmas-automation"]["current"], {"password": "B"})
        self.assertEqual(self.restarts, 2)

    def test_missing_allowlisted_secret_fails_closed_without_touching_the_copy(self):
        self.run_sync()
        self.write({"schema_version": 3, "secrets": {"r1-breakglass": {"current": {}}}})
        with self.assertRaises(s.SyncError):
            self.run_sync()
        with open(self.copy, encoding="utf-8") as stream:
            copied = json.load(stream)
        self.assertEqual(sorted(copied["secrets"]), ["r2-nmas-automation", "s2-nmas-diag"])

    def test_cli_never_prints_secret_values(self):
        import contextlib, io
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            rc = s.main(["--full", self.full, "--copy", self.copy, "--owner", getpass.getuser(), "--no-restart"])
        self.assertEqual(rc, 0)
        self.assertNotIn('"A"', out.getvalue() + err.getvalue())
        self.assertNotIn("password", out.getvalue() + err.getvalue())


if __name__ == "__main__":
    unittest.main()
