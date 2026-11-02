#!/usr/bin/env python3
"""Verify that a public CI tree exactly matches its reviewed source manifest."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
from pathlib import Path, PurePosixPath


OID_RE = re.compile(r"[0-9a-f]{40}")


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


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument("--manifest", type=Path, default=Path("PUBLIC_CI_SNAPSHOT.json"))
    args = parser.parse_args()
    root = args.root.resolve()
    manifest = args.manifest if args.manifest.is_absolute() else root / args.manifest
    try:
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
