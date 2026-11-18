#!/usr/bin/env python3
"""Regression checks for the complete Stage B research release graph."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import shutil
import tempfile

import research_release


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
MANIFEST = HERE / "stage-b/research-activation-release.json"


def main() -> int:
    result = research_release.validate(MANIFEST, ROOT)
    assert result["result"] == "valid" and result["files"] == 18
    with tempfile.TemporaryDirectory(prefix="nmas-research-release-") as temporary:
        fixture = Path(temporary)
        manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
        for item in manifest["files"]:
            destination = fixture / item["path"]
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / item["path"], destination)
        manifest_path = fixture / "release.json"
        host_path = fixture / "deploy/sandbox/stage-b/research-host-egress.nft.activation-review"
        host_path.write_text(host_path.read_text(encoding="utf-8").replace("fd0198911915325e", "d0ce9ede30c97bc8"),
                             encoding="utf-8")
        stale_hash = hashlib.sha256(host_path.read_bytes()).hexdigest()
        manifest["identities"]["host_policy_sha256"] = stale_hash
        for item in manifest["files"]:
            if item["path"].endswith("research-host-egress.nft.activation-review"):
                item["sha256"] = stale_hash
                item["size"] = host_path.stat().st_size
        manifest_path.write_text(json.dumps(manifest, sort_keys=True), encoding="utf-8")
        try:
            research_release.validate(manifest_path, fixture)
        except ValueError as exc:
            assert "reviewed host policy differs" in str(exc)
        else:
            raise AssertionError("internally rehashed stale host-policy artifact passed release validation")
    print("PASS: complete release graph and stale-marker recurrence rejection")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
