#!/usr/bin/env python3
"""Verify that a public CI tree exactly matches its reviewed source manifest.

With ``--history`` it also proves the mirror history is a strictly linear,
append-only chain of sanitized snapshot commits: one root, single-parent
commits only, no other refs, the snapshot identity on every commit, and
provenance trailers that agree with each commit's own manifest and path set.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
from pathlib import Path, PurePosixPath


OID_RE = re.compile(r"[0-9a-f]{40}")
SOURCE_REPOSITORY = "Dhruv-Suvarna/Adv-Netman"
MANIFEST_NAME = "PUBLIC_CI_SNAPSHOT.json"
SNAPSHOT_IDENTITY = "NMAS Public CI Snapshot <nmas-public-ci@invalid.example>"
ALLOWED_MODES = {"100644", "100755"}
PROVENANCE = (
    ("Source-Commit", "source_revision"),
    ("Source-Tree", "source_tree_oid"),
    ("Source-Manifest-SHA256", "source_manifest_sha256"),
)


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def canonical_digest(value: object) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def safe_path(root: Path, raw: str) -> Path:
    path = PurePosixPath(raw)
    if path.is_absolute() or not path.parts or any(part in {"", ".", ".."} for part in path.parts):
        raise RuntimeError("Manifest contains an unsafe path.")
    target = root.joinpath(*path.parts)
    if target.is_symlink():
        raise RuntimeError("Snapshot contains a symlink.")
    return target


def tracked(root: Path) -> set[str]:
    raw = subprocess.check_output(["git", "-C", str(root), "ls-files", "-z"])
    return {item.decode("utf-8") for item in raw.split(b"\0") if item}


def verify_record(root: Path, record: dict) -> None:
    target = safe_path(root, record["path"])
    if not target.is_file():
        raise RuntimeError(f"Missing snapshot path: {record['path']}")
    if target.stat().st_size != record["size"] or digest(target) != record["sha256"]:
        raise RuntimeError(f"Snapshot digest mismatch: {record['path']}")
    executable = bool(target.stat().st_mode & 0o100)
    if executable != (record["mode"] == "100755"):
        raise RuntimeError(f"Snapshot mode mismatch: {record['path']}")


def verify(root: Path, manifest_path: Path) -> dict:
    data = json.loads(manifest_path.read_text(encoding="utf-8"))
    if data.get("schema_version") != 1:
        raise RuntimeError("Unsupported public CI manifest schema.")
    if not OID_RE.fullmatch(str(data.get("source_revision") or "")):
        raise RuntimeError("Invalid source revision in public CI manifest.")
    if not OID_RE.fullmatch(str(data.get("source_tree_oid") or "")):
        raise RuntimeError("Invalid source tree in public CI manifest.")
    source_files = data.get("source_files")
    additions = data.get("mirror_additions")
    if not isinstance(source_files, list) or not isinstance(additions, list):
        raise RuntimeError("Public CI manifest file lists are invalid.")
    if data.get("source_file_count") != len(source_files):
        raise RuntimeError("Public CI source file count is invalid.")
    if data.get("source_manifest_sha256") != canonical_digest(source_files):
        raise RuntimeError("Public CI source manifest digest is invalid.")

    expected = {record["path"] for record in source_files + additions}
    expected.add(manifest_path.relative_to(root).as_posix())
    actual = tracked(root)
    if actual != expected:
        raise RuntimeError("Tracked snapshot path set does not match the reviewed manifest.")
    for record in source_files + additions:
        verify_record(root, record)
    for record in data.get("excluded_tracked_files", []):
        if safe_path(root, record["path"]).exists():
            raise RuntimeError(f"Excluded source path is present: {record['path']}")
    return data


def git(root: Path, *args: str) -> str:
    return subprocess.check_output(["git", "-C", str(root), *args], text=True, stderr=subprocess.DEVNULL)


def verify_commit(root: Path, oid: str, parent: str | None) -> None:
    author, committer, body = git(root, "show", "-s", "--format=%an <%ae>%x00%cn <%ce>%x00%B", oid).split("\0", 2)
    if author != SNAPSHOT_IDENTITY or committer != SNAPSHOT_IDENTITY:
        raise RuntimeError(f"Commit {oid} was not created by the snapshot builder identity.")
    trailers = dict(line.split(": ", 1) for line in body.splitlines() if ": " in line)
    manifest = json.loads(git(root, "show", f"{oid}:{MANIFEST_NAME}"))
    if trailers.get("Source-Repository") != SOURCE_REPOSITORY or manifest.get("source_repository") != SOURCE_REPOSITORY:
        raise RuntimeError(f"Commit {oid} has invalid source-repository provenance.")
    for trailer, key in PROVENANCE:
        value = trailers.get(trailer)
        if not value or value != manifest.get(key):
            raise RuntimeError(f"Commit {oid} provenance trailer {trailer} does not match its manifest.")
    if not OID_RE.fullmatch(manifest["source_revision"]) or manifest["source_revision"] == oid:
        raise RuntimeError(f"Commit {oid} is not a sanitized snapshot of a source revision.")
    if manifest["source_manifest_sha256"] != canonical_digest(manifest["source_files"]):
        raise RuntimeError(f"Commit {oid} manifest digest is invalid.")
    if "mirror_parent_commit" in manifest and manifest["mirror_parent_commit"] != parent:
        raise RuntimeError(f"Commit {oid} manifest names a different mirror parent.")
    tree = {}
    for record in git(root, "ls-tree", "-r", "-z", "--full-tree", oid).split("\0"):
        if record:
            metadata, path = record.split("\t", 1)
            tree[path] = metadata.split()[0]
    if any(mode not in ALLOWED_MODES for mode in tree.values()):
        raise RuntimeError(f"Commit {oid} contains a submodule, symlink, or special mode.")
    expected = {item["path"] for item in manifest["source_files"] + manifest["mirror_additions"]} | {MANIFEST_NAME}
    if set(tree) != expected:
        raise RuntimeError(f"Commit {oid} path set does not match its reviewed manifest.")


def verify_history(root: Path, expected_root: str | None = None) -> list[str]:
    chain: list[str] = []
    for line in git(root, "rev-list", "--reverse", "--parents", "HEAD").splitlines():
        oid, *parents = line.split()
        if parents != chain[-1:]:
            raise RuntimeError("Snapshot history is not a strictly linear single-parent chain from one root.")
        chain.append(oid)
    if not chain:
        raise RuntimeError("Snapshot history is empty.")
    for index, oid in enumerate(chain):
        verify_commit(root, oid, chain[index - 1] if index else None)
    if expected_root is not None and chain[0] != expected_root:
        raise RuntimeError("Snapshot history does not start at the published root commit.")
    if set(git(root, "rev-list", "--all").split()) != set(chain):
        raise RuntimeError("A ref outside the linear snapshot chain is present.")
    return chain


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument("--manifest", type=Path, default=Path(MANIFEST_NAME))
    parser.add_argument("--history", action="store_true", help="verify the linear snapshot history instead of the tree")
    parser.add_argument("--expected-root", help="the published root commit the chain must start at")
    args = parser.parse_args()
    root = args.root.resolve()
    manifest = args.manifest if args.manifest.is_absolute() else root / args.manifest
    try:
        if args.history:
            chain = verify_history(root, args.expected_root)
            print(f"public-ci-history: PASS commits={len(chain)} root={chain[0]} head={chain[-1]}")
            return 0
        data = verify(root, manifest)
    except (OSError, ValueError, KeyError, subprocess.CalledProcessError, RuntimeError) as exc:
        print(f"public-ci-integrity: FAIL {exc}")
        return 1
    print(
        f"public-ci-integrity: PASS source={data['source_revision']} "
        f"tree={data['source_tree_oid']} digest={data['source_manifest_sha256']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
