"""Direct tests for the Stage B research activation-release validator (deploy/sandbox/research_release.py).

The committed release (``research-activation-release.json``, COMPLETE-11) is a historical record: its inputs have since
changed, so the validator must refuse it as drifted, and it is never re-hashed in place.  The positive fixture copies
the release graph to a temporary root and re-binds every file, overlay and identity hash consistently.  The host-policy,
config-digest and historical-receipt checks then still run unmodified against the current controller.
"""

from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import shutil
import sys
import tempfile
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

from django.test import SimpleTestCase

ROOT = Path(__file__).resolve().parents[3]
_spec = importlib.util.spec_from_file_location("research_release", ROOT / "deploy" / "sandbox" / "research_release.py")
rr = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(rr)
MANIFEST = ROOT / "deploy/sandbox/stage-b/research-activation-release.json"
OVERLAY = "deploy/sandbox/stage-b/worker-overlay-manifest.json.legacy-receipt-review"
BINDINGS = {"overlay_sha256": OVERLAY, "controller_sha256": "deploy/sandbox/namespace_activation.py",
            "host_policy_sha256": "deploy/sandbox/stage-b/research-host-egress.nft.activation-review",
            "resolver_root_sha256": "deploy/sandbox/resolver_root.py",
            "namespace_config_sha256": "deploy/sandbox/stage-b/research-namespace.env.activation-review",
            "nft_policy_sha256": "deploy/sandbox/stage-b/research-egress.nft.proposed"}


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class Fixture(SimpleTestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix="nmas-research-release-unit-")
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
        for item in self.manifest["files"]:
            (self.root / item["path"]).parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / item["path"], self.root / item["path"])
        self.rebind()

    def rebind(self):
        overlay = json.loads((self.root / OVERLAY).read_text(encoding="utf-8"))
        for entry in overlay["files"]:
            data = (self.root / entry["path"]).read_bytes()
            entry["sha256"], entry["size"] = sha(data), len(data)
        (self.root / OVERLAY).write_text(json.dumps(overlay, sort_keys=True), encoding="utf-8")
        for item in self.manifest["files"]:
            data = (self.root / item["path"]).read_bytes()
            item["sha256"], item["size"] = sha(data), len(data)
        files = {item["path"]: item["sha256"] for item in self.manifest["files"]}
        self.manifest["identities"] = {name: files[path] for name, path in BINDINGS.items()}
        self.path = self.root / "release.json"
        self.path.write_text(json.dumps(self.manifest, sort_keys=True), encoding="utf-8")


class PrimitiveTests(SimpleTestCase):
    def test_digest_returns_the_hex_sha256(self):
        self.assertEqual(rr.digest(b"abc"), sha(b"abc"))

    def test_digest_refuses_text(self):
        with self.assertRaises(TypeError):
            rr.digest("abc")

    def test_load_regular_returns_file_bytes(self):
        self.assertEqual(rr.load_regular(MANIFEST), MANIFEST.read_bytes())

    def test_load_regular_refuses_a_symlink_or_directory(self):
        with tempfile.TemporaryDirectory() as d:
            link = Path(d) / "link"
            link.symlink_to(MANIFEST)
            for label, path in (("a symlink", link), ("a directory", Path(d))):
                with self.subTest(f"{label} is refused"), self.assertRaises(ValueError):
                    rr.load_regular(path)

    def test_parse_env_returns_key_values(self):
        self.assertEqual(rr.parse_env(b"# reviewed\nA=1\n\nB=x=y\n"), {"A": "1", "B": "x=y"})

    def test_parse_env_refuses_duplicate_or_bare_lines(self):
        for label, data in (("a duplicate key", b"A=1\nA=2\n"), ("a bare line", b"A\n")):
            with self.subTest(f"{label} is refused"), self.assertRaises(ValueError):
                rr.parse_env(data)


class ReleaseTests(Fixture):
    def test_controller_policy_returns_the_reviewed_host_policy(self):
        config_path = self.root / BINDINGS["namespace_config_sha256"]
        policy = (self.root / BINDINGS["nft_policy_sha256"]).read_bytes()
        config, generated = rr.controller_policy(self.root, config_path, policy)
        reviewed = (self.root / BINDINGS["host_policy_sha256"]).read_text(encoding="utf-8").splitlines()
        self.assertEqual(generated, "\n".join(reviewed[2:]) + "\n")
        self.assertEqual((config["kind"], config["ipv6"]), ("research", None))

    def test_controller_policy_refuses_a_policy_that_differs_from_the_approved_digest(self):
        config_path = self.root / BINDINGS["namespace_config_sha256"]
        with self.assertRaises(Exception) as caught:                 # the controller's own Refused type
            rr.controller_policy(self.root, config_path, b"table inet tampered {}\n")
        self.assertEqual(type(caught.exception).__name__, "Refused")

    def test_validate_returns_valid_for_a_consistently_bound_release(self):
        out = rr.validate(self.path, self.root)
        self.assertEqual((out["result"], out["files"]), ("valid", 18))
        self.assertEqual(out["host_policy_sha256"], self.manifest["identities"]["host_policy_sha256"])

    def test_validate_refuses_the_drifted_historical_release_and_tampered_graphs(self):
        with self.subTest("the committed historical release is refused as drifted"), self.assertRaisesRegex(ValueError, "release input drift"):
            rr.validate(MANIFEST, ROOT)
        host = self.root / BINDINGS["host_policy_sha256"]
        host.write_text(host.read_text(encoding="utf-8").replace("fd0198911915325e", "d0ce9ede30c97bc8"), encoding="utf-8")
        self.rebind()
        with self.subTest("a rehashed stale host policy is refused"), self.assertRaisesRegex(ValueError, "reviewed host policy differs"):
            rr.validate(self.path, self.root)
        self.manifest["identities"]["controller_sha256"] = "0" * 64
        self.path.write_text(json.dumps(self.manifest), encoding="utf-8")
        with self.subTest("an unbound identity is refused"), self.assertRaisesRegex(ValueError, "not bound"):
            rr.validate(self.path, self.root)

    def test_main_returns_zero_and_prints_the_validation(self):
        out = io.StringIO()
        with mock.patch.object(sys, "argv", ["research_release.py", str(self.path), "--root", str(self.root)]), redirect_stdout(out):
            self.assertEqual(rr.main(), 0)
        self.assertEqual(json.loads(out.getvalue())["result"], "valid")
