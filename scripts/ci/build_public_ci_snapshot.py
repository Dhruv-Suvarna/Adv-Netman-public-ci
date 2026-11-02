#!/usr/bin/env python3
"""Build a sanitized public CI snapshot from one reviewed Git commit.

Legacy import tool: it produced the sanitized snapshot chain that ends at the
import boundary of the authoritative repository (docs/AUTHORITATIVE_REPOSITORY.md).
It is not part of the development workflow.

The first snapshot is a single root commit. Each later snapshot is appended as
one single-parent commit on top of the last approved public snapshot
(``--parent-mirror``/``--parent-commit``); only that sanitized mirror history is
fetched, never the source repository's history.

Only blobs named by ``git ls-tree`` are copied. Untracked files, the source
repository's ``.git`` directory, ignored runtime secrets, databases, and local
deployment state cannot enter the output. The output path must not exist.
"""

from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path, PurePosixPath


SOURCE_REPOSITORY = "Dhruv-Suvarna/Adv-Netman"
MANIFEST_NAME = "PUBLIC_CI_SNAPSHOT.json"
INTEGRITY_WORKFLOW = ".github/workflows/public-ci-integrity.yml"
EXCLUSIONS = {
    "address_report.csv": "generated lab address report; not required by CI",
    "logs/**": "generated device session logs; not required by CI",
}
ALLOWED_MODES = {"100644", "100755"}
OID_RE = re.compile(r"[0-9a-f]{40}")
VERIFY = Path(__file__).resolve().with_name("verify_public_ci_snapshot.py")

WORKFLOW = """name: Public CI snapshot integrity

on:
  pull_request:
  push:
    branches: [main]
  workflow_dispatch:

permissions:
  contents: read

concurrency:
  group: public-ci-integrity-${{ github.workflow }}-${{ github.ref }}
  cancel-in-progress: ${{ github.event_name == 'pull_request' }}

jobs:
  integrity:
    name: Immutable source snapshot and secret scan
    runs-on: ubuntu-24.04
    timeout-minutes: 15
    steps:
      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4
        with:
          fetch-depth: 0
          persist-credentials: false

      - uses: actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065 # v5
        with:
          python-version: "3.12"

      - name: Require a linear sanitized snapshot history
        if: github.event_name != 'pull_request'
        run: python scripts/ci/verify_public_ci_snapshot.py --root . --history@EXPECTED_ROOT@

      - name: Verify immutable source linkage
        run: python scripts/ci/verify_public_ci_snapshot.py --root . --manifest PUBLIC_CI_SNAPSHOT.json

      - name: Scan tracked files without uploading source
        env:
          PYTHONDONTWRITEBYTECODE: "1"
        run: python scripts/ci/scan_tracked_secrets.py
"""


def run(repo: Path, *args: str, text: bool = False) -> bytes | str:
    return subprocess.check_output(
        ["git", "-C", str(repo), *args],
        stderr=subprocess.DEVNULL,
        text=text,
    )


def safe_path(raw: str) -> PurePosixPath:
    path = PurePosixPath(raw)
    if path.is_absolute() or not path.parts or any(part in {"", ".", ".."} for part in path.parts):
        raise RuntimeError("Source tree contains an unsafe path.")
    return path


def is_excluded(path: str) -> str:
    for pattern, reason in EXCLUSIONS.items():
        if fnmatch.fnmatchcase(path, pattern):
            return reason
    return ""


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_digest(value: object) -> str:
    return digest(json.dumps(value, sort_keys=True, separators=(",", ":")).encode())


def entries(repo: Path, revision: str) -> list[tuple[str, str, str, str]]:
    raw = run(repo, "ls-tree", "-rz", "--full-tree", revision)
    result = []
    for record in raw.split(b"\0"):
        if not record:
            continue
        metadata, encoded_path = record.split(b"\t", 1)
        mode, kind, oid = metadata.decode("ascii").split()
        path = encoded_path.decode("utf-8")
        safe_path(path)
        if kind != "blob" or mode not in ALLOWED_MODES:
            raise RuntimeError("Submodules, symlinks, and special Git modes are not allowed in the public snapshot.")
        result.append((mode, kind, oid, path))
    return sorted(result, key=lambda item: item[3])


def write_blob(output: Path, path: str, mode: str, data: bytes) -> None:
    target = output.joinpath(*safe_path(path).parts)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(data)
    target.chmod(0o755 if mode == "100755" else 0o644)


def verify_history(repo: Path, expected_root: str | None = None) -> str:
    """Run the fail-closed history verifier; return the chain's root commit."""
    argv = [sys.executable, "-I", "-B", str(VERIFY), "--root", str(repo), "--history"]
    if expected_root:
        argv += ["--expected-root", expected_root]
    result = subprocess.run(argv, capture_output=True, text=True, check=False)
    if result.returncode:
        raise RuntimeError("Snapshot history verification failed: " + result.stdout.strip())
    return result.stdout.split("root=", 1)[1].split()[0]


def parent_snapshot(parent_mirror: Path, parent_commit: str) -> str:
    """Prove the parent is the approved, linear public snapshot; return its root commit."""
    if not OID_RE.fullmatch(parent_commit):
        raise RuntimeError("The parent snapshot must be named by a full commit ID.")
    if run(parent_mirror, "rev-parse", "HEAD", text=True).strip() != parent_commit:
        raise RuntimeError("The parent mirror HEAD is not the approved parent snapshot.")
    return verify_history(parent_mirror)


def initialize_git(output: Path, source_repo: Path, revision: str, manifest: dict,
                   parent_mirror: Path | None = None) -> str:
    subprocess.run(["git", "init", "-b", "main", str(output)], check=True, capture_output=True, text=True)
    subprocess.run(["git", "-C", str(output), "config", "user.name", "NMAS Public CI Snapshot"], check=True)
    subprocess.run(["git", "-C", str(output), "config", "user.email", "nmas-public-ci@invalid.example"], check=True)
    if parent_mirror is not None:
        # Only the sanitized mirror chain is fetched; the index stays empty, so the new tree is exactly the output.
        subprocess.run(["git", "-C", str(output), "fetch", "--quiet", "--no-tags", "--update-head-ok",
                        str(parent_mirror), "refs/heads/main:refs/heads/main"], check=True, capture_output=True)
        if run(output, "rev-parse", "HEAD", text=True).strip() != manifest["mirror_parent_commit"]:
            raise RuntimeError("Fetched parent snapshot does not match the approved parent commit.")
    subprocess.run(["git", "-C", str(output), "add", "--all"], check=True)
    timestamp = run(source_repo, "show", "-s", "--format=%cI", revision, text=True).strip()
    message = (
        "NMAS sanitized public CI snapshot\n\n"
        f"Source-Repository: {SOURCE_REPOSITORY}\n"
        f"Source-Commit: {revision}\n"
        f"Source-Tree: {manifest['source_tree_oid']}\n"
        f"Source-Manifest-SHA256: {manifest['source_manifest_sha256']}\n"
    )
    env = {**os.environ, "GIT_AUTHOR_DATE": timestamp, "GIT_COMMITTER_DATE": timestamp}
    subprocess.run(["git", "-C", str(output), "commit", "-m", message], check=True, env=env, capture_output=True, text=True)
    return subprocess.check_output(["git", "-C", str(output), "rev-parse", "HEAD"], text=True).strip()


def build(source: Path, revision_arg: str, output: Path,
          parent_mirror: Path | None = None, parent_commit: str | None = None) -> dict:
    source = Path(run(source, "rev-parse", "--show-toplevel", text=True).strip())
    revision = run(source, "rev-parse", f"{revision_arg}^{{commit}}", text=True).strip()
    if not OID_RE.fullmatch(revision):
        raise RuntimeError("Source revision did not resolve to a full commit ID.")
    if output.exists():
        raise RuntimeError("Output path already exists; refusing to overwrite it.")
    if (parent_mirror is None) != (parent_commit is None):
        raise RuntimeError("--parent-mirror and --parent-commit must be given together.")
    root_commit = parent_snapshot(parent_mirror, parent_commit) if parent_mirror is not None else None
    output.mkdir(mode=0o700, parents=True)

    source_files = []
    excluded = []
    for mode, _kind, oid, path in entries(source, revision):
        data = run(source, "cat-file", "blob", oid)
        reason = is_excluded(path)
        record = {"mode": mode, "path": path, "sha256": digest(data), "size": len(data)}
        if reason:
            excluded.append({**record, "reason": reason})
            continue
        write_blob(output, path, mode, data)
        source_files.append(record)

    workflow_data = WORKFLOW.replace("@EXPECTED_ROOT@", f" --expected-root {root_commit}" if root_commit else "").encode()
    write_blob(output, INTEGRITY_WORKFLOW, "100644", workflow_data)
    additions = [{
        "mode": "100644",
        "path": INTEGRITY_WORKFLOW,
        "sha256": digest(workflow_data),
        "size": len(workflow_data),
        "reason": "mirror-only immutable-source verification",
    }]
    manifest = {
        "schema_version": 1,
        "source_repository": SOURCE_REPOSITORY,
        "source_revision": revision,
        "source_tree_oid": run(source, "rev-parse", f"{revision}^{{tree}}", text=True).strip(),
        "source_file_count": len(source_files),
        "source_files": source_files,
        "source_manifest_sha256": canonical_digest(source_files),
        "excluded_tracked_files": excluded,
        "mirror_additions": additions,
        "history_policy": "linear append-only snapshot chain from one root commit; no source-repository ancestry",
    }
    if root_commit:
        manifest["mirror_root_commit"] = root_commit
        manifest["mirror_parent_commit"] = parent_commit
    manifest_data = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode()
    write_blob(output, MANIFEST_NAME, "100644", manifest_data)
    mirror_commit = initialize_git(output, source, revision, manifest, parent_mirror)
    verify_history(output, root_commit)
    manifest["mirror_commit"] = mirror_commit
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--parent-mirror", type=Path, help="local clone of the last approved public snapshot")
    parser.add_argument("--parent-commit", help="full commit ID of the last approved public snapshot")
    args = parser.parse_args()
    manifest = build(
        args.source.resolve(), args.revision, args.output.resolve(),
        args.parent_mirror.resolve() if args.parent_mirror else None, args.parent_commit,
    )
    print(
        f"public-ci-snapshot: PASS source={manifest['source_revision']} "
        f"files={manifest['source_file_count']} excluded={len(manifest['excluded_tracked_files'])} "
        f"mirror_commit={manifest['mirror_commit']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
