"""Local evidence sink: containment, atomicity, no overwrite, digest-verifiable references (local storage only, never attestation)."""

from __future__ import annotations

import hashlib
import os
import stat
import tempfile
from pathlib import Path
from unittest import mock

from django.test import SimpleTestCase

from core.services.devices import observation_evidence as ev

REC = {"device": "S1", "output": "RAW", "nonce": "ab" * 16, "captured_at": "2026-11-12T10:00:00+00:00"}


class SinkTests(SimpleTestCase):
    def setUp(self):
        t = tempfile.TemporaryDirectory()
        self.addCleanup(t.cleanup)
        self.root = Path(t.name).resolve()
        self.dir = self.root / "evidence"
        self.dir.mkdir(mode=0o700)
        self.sink = ev.LocalEvidenceSink(self.dir, approved_roots=[self.root])

    def test_write_is_private_digest_verifiable_and_independent(self):
        ref = self.sink(REC)
        self.assertTrue(ref.startswith("local-unattested:") and len(ref) <= 200)
        files = list(self.dir.iterdir())
        self.assertEqual(len(files), 1)                       # no temp leftovers
        self.assertEqual(stat.S_IMODE(files[0].stat().st_mode), 0o600)
        self.assertEqual(ref.split("sha256=")[1], hashlib.sha256(files[0].read_bytes()).hexdigest())
        self.assertEqual(ev.verify_reference(self.dir, ref, [self.root])["output"], "RAW")

    def test_tamper_detected(self):
        ref = self.sink(REC)
        f = next(self.dir.iterdir())
        f.write_bytes(f.read_bytes().replace(b"RAW", b"BAD"))
        with self.assertRaises(ev.EvidenceError) as cm:
            ev.verify_reference(self.dir, ref, [self.root])
        self.assertEqual(cm.exception.code, "DIGEST_MISMATCH")

    def test_no_overwrite(self):
        self.sink(REC)
        before = next(self.dir.iterdir()).read_bytes()
        with self.assertRaises(ev.EvidenceError) as cm:
            self.sink({**REC, "output": "OTHER"})
        self.assertEqual(cm.exception.code, "EVIDENCE_EXISTS")
        self.assertEqual(next(self.dir.iterdir()).read_bytes(), before)
        self.assertEqual(len(list(self.dir.iterdir())), 1)

    def test_hostile_device_name_cannot_traverse(self):
        ref = self.sink({**REC, "device": "../../etc/passwd", "nonce": "../x"})
        name = ref.split(":", 1)[1].split("#")[0]
        self.assertNotIn("/", name)
        self.assertEqual([p.name for p in self.dir.iterdir()], [name])
        self.assertEqual(list(self.root.iterdir()), [self.dir])

    def test_directory_refusals(self):
        outside = tempfile.mkdtemp()
        self.addCleanup(os.rmdir, outside)
        cases = {"DIRECTORY_NOT_ABSOLUTE": "rel/dir", "DIRECTORY_MISSING": str(self.root / "nope"),
                 "DIRECTORY_OUTSIDE_APPROVED_ROOTS": outside, "DIRECTORY_NOT_ABSOLUTE ": ""}
        for code, path in cases.items():
            with self.subTest(code), self.assertRaises(ev.EvidenceError) as cm:
                ev.validate_directory(path, [self.root])
            self.assertEqual(cm.exception.code, code.strip())
        link = self.root / "link"
        link.symlink_to(outside)                              # symlink escaping the root is resolved and refused
        with self.assertRaises(ev.EvidenceError):
            ev.validate_directory(link, [self.root])
        loose = self.root / "loose"
        loose.mkdir()
        loose.chmod(0o777)
        with self.assertRaises(ev.EvidenceError) as cm:
            ev.validate_directory(loose, [self.root])
        self.assertEqual(cm.exception.code, "DIRECTORY_TOO_PERMISSIVE")

    def test_default_roots_are_development_roots_only(self):
        self.assertEqual(ev.APPROVED_ROOTS, ("/home/student/Scripts", "/home/student/clab-quickstart"))
        with self.assertRaises(ev.EvidenceError):
            ev.LocalEvidenceSink(self.dir)                    # tmp dir is outside the real approved roots

    def test_write_failure_raises_and_leaves_nothing(self):
        with mock.patch("os.fsync", side_effect=OSError("disk")), self.assertRaises(ev.EvidenceError) as cm:
            self.sink(REC)
        self.assertEqual(cm.exception.code, "EVIDENCE_WRITE_FAILED")
        self.assertEqual(list(self.dir.iterdir()), [])

    def test_invalid_reference_refused(self):
        for bad in ("", "x", "local-unattested:../a.json#sha256=" + "0" * 64, "gateway:abc"):
            with self.subTest(bad), self.assertRaises(ev.EvidenceError):
                ev.verify_reference(self.dir, bad, [self.root])
