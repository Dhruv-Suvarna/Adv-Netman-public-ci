#!/usr/bin/env python3
"""Verify the sanitized import and the linear history of the NMAS repository.

``Adv-Netman-public-ci`` began as a CI-only mirror: a strictly linear chain of
sanitized snapshot commits, each built from one reviewed commit of the private
legacy repository.  It is now the authoritative development repository.  The
snapshot chain ends at the *import boundary* commit; after it, ordinary
reviewed commits land on ``main``.

Modes:

* default: the tree exactly matches its snapshot manifest (a snapshot itself).
* ``--history``: a strictly linear chain of snapshot commits only (one root,
  single-parent commits, no other refs, builder identity, provenance trailers
  that agree with each commit's own manifest and path set).
* ``--history --import-boundary B``: the snapshot rules above hold up to and
  including ``B`` (whose blobs must match its manifest); every later commit
  must stay on the same single-parent chain, keep the import manifest
  unchanged, and contain no special mode or excluded legacy path.
* ``--roots``: every commit reachable from ``--rev`` (or ``--all-refs``)
  descends only from the published root -- no imported legacy history.
* ``--tree-policy --import-boundary B``: the checked-out tree contains no
  special mode or excluded legacy path, keeps the import manifest unchanged,
  and descends from ``B``.
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


def checked_rev(value: str) -> str:
    """``HEAD`` or a full commit ID -- never an option-like or abbreviated revision."""
    if value != "HEAD" and not OID_RE.fullmatch(value or ""):
        raise RuntimeError("A revision must be HEAD or a full 40-character commit ID.")
    return value


def tree_entries(root: Path, oid: str) -> dict[str, tuple[str, str]]:
    """{path: (mode, blob id)} for every entry of a commit's tree."""
    entries = {}
    for record in git(root, "ls-tree", "-r", "-z", "--full-tree", oid).split("\0"):
        if record:
            metadata, path = record.split("\t", 1)
            mode, _kind, blob = metadata.split()
            entries[path] = (mode, blob)
    return entries


def verify_snapshot_blobs(root: Path, oid: str) -> int:
    """Every blob of a snapshot commit matches its own manifest's mode, size and SHA-256; return the count."""
    manifest = json.loads(git(root, "show", f"{oid}:{MANIFEST_NAME}"))
    entries = tree_entries(root, oid)
    records = manifest["source_files"] + manifest["mirror_additions"]
    request = "".join(f"{entries[record['path']][1]}\n" for record in records if record["path"] in entries).encode()
    output = subprocess.run(["git", "-C", str(root), "cat-file", "--batch"], input=request,
                            capture_output=True, check=True).stdout
    offset = 0
    for record in records:
        if record["path"] not in entries:
            raise RuntimeError(f"Commit {oid} is missing snapshot path {record['path']}.")
        if entries[record["path"]][0] != record["mode"]:
            raise RuntimeError(f"Commit {oid} snapshot mode mismatch: {record['path']}")
        header_end = output.index(b"\n", offset)
        size = int(output[offset:header_end].split()[2])
        data = output[header_end + 1:header_end + 1 + size]
        offset = header_end + 1 + size + 1
        if size != record["size"] or hashlib.sha256(data).hexdigest() != record["sha256"]:
            raise RuntimeError(f"Commit {oid} snapshot digest mismatch: {record['path']}")
    return len(records)


def verify_development_commit(root: Path, oid: str, manifest_blob: str, excluded: set[str]) -> None:
    """A post-import commit: allowed modes only, no excluded legacy path, and the import manifest unchanged."""
    entries = tree_entries(root, oid)
    if any(mode not in ALLOWED_MODES for mode, _blob in entries.values()):
        raise RuntimeError(f"Commit {oid} contains a submodule, symlink, or special mode.")
    if excluded & set(entries):
        raise RuntimeError(f"Commit {oid} contains a path excluded from the sanitized import.")
    if entries.get(MANIFEST_NAME, ("", ""))[1] != manifest_blob:
        raise RuntimeError(f"Commit {oid} changes or removes the immutable import manifest.")


def linear_chain(root: Path, rev: str) -> list[str]:
    """The commits reachable from ``rev``, oldest first, proven to be one single-parent chain from one root."""
    chain: list[str] = []
    for line in git(root, "rev-list", "--reverse", "--parents", checked_rev(rev)).splitlines():
        oid, *parents = line.split()
        if parents != chain[-1:]:
            raise RuntimeError("History is not a strictly linear single-parent chain from one root.")
        chain.append(oid)
    if not chain:
        raise RuntimeError("History is empty.")
    return chain


def verify_development_history(root: Path, expected_root: str, import_boundary: str, rev: str = "HEAD") -> tuple[list[str], int]:
    """Snapshot chain up to the import boundary, then linear reviewed development; return (chain, boundary index)."""
    if not OID_RE.fullmatch(expected_root or "") or not OID_RE.fullmatch(import_boundary or ""):
        raise RuntimeError("The published root and import boundary must be full commit IDs.")
    chain = linear_chain(root, rev)
    if chain[0] != expected_root:
        raise RuntimeError("History does not start at the published root commit.")
    if import_boundary not in chain:
        raise RuntimeError("History does not contain the import boundary commit.")
    boundary = chain.index(import_boundary)
    for index, oid in enumerate(chain[:boundary + 1]):
        verify_commit(root, oid, chain[index - 1] if index else None)
    verify_snapshot_blobs(root, import_boundary)
    manifest = json.loads(git(root, "show", f"{import_boundary}:{MANIFEST_NAME}"))
    manifest_blob = git(root, "rev-parse", f"{import_boundary}:{MANIFEST_NAME}").strip()
    excluded = {record["path"] for record in manifest.get("excluded_tracked_files", [])}
    for oid in chain[boundary + 1:]:
        verify_development_commit(root, oid, manifest_blob, excluded)
    return chain, boundary


def verify_roots(root: Path, expected_root: str, revs: list[str] | None = None) -> list[str]:
    """Every commit reachable from ``revs`` (all refs when None) descends only from the published root."""
    if not OID_RE.fullmatch(expected_root or ""):
        raise RuntimeError("The published root must be a full commit ID.")
    selection = ["--all"] if revs is None else [checked_rev(rev) for rev in revs]
    if not selection:
        raise RuntimeError("No revision was given for the root check.")
    roots = sorted(set(git(root, "rev-list", "--max-parents=0", *selection).split()))
    if roots != [expected_root]:
        raise RuntimeError("History reachable from the checked refs has a root other than the published root.")
    return roots


def verify_tree_policy(root: Path, import_boundary: str) -> int:
    """The checked-out tree: allowed modes only, no excluded legacy path, unchanged import manifest; return the path count."""
    if not OID_RE.fullmatch(import_boundary or ""):
        raise RuntimeError("The import boundary must be a full commit ID.")
    if subprocess.run(["git", "-C", str(root), "merge-base", "--is-ancestor", import_boundary, "HEAD"],
                      capture_output=True, check=False).returncode:
        raise RuntimeError("The checked-out tree does not descend from the import boundary.")
    staged = {}
    for record in git(root, "ls-files", "-s", "-z").split("\0"):
        if record:
            metadata, path = record.split("\t", 1)
            staged[path] = metadata.split()[0]
    if any(mode not in ALLOWED_MODES for mode in staged.values()):
        raise RuntimeError("The tree contains a submodule, symlink, or special mode.")
    manifest = json.loads(git(root, "show", f"{import_boundary}:{MANIFEST_NAME}"))
    for record in manifest.get("excluded_tracked_files", []):
        if record["path"] in staged or safe_path(root, record["path"]).exists():
            raise RuntimeError(f"Excluded legacy path is present: {record['path']}")
    current = root / MANIFEST_NAME
    expected = git(root, "rev-parse", f"{import_boundary}:{MANIFEST_NAME}").strip()
    if not current.is_file() or git(root, "hash-object", "--", str(current)).strip() != expected:
        raise RuntimeError("The immutable import manifest was changed or removed.")
    return len(staged)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument("--manifest", type=Path, default=Path(MANIFEST_NAME))
    parser.add_argument("--history", action="store_true", help="verify the linear history instead of the tree")
    parser.add_argument("--expected-root", help="the published root commit the chain must start at")
    parser.add_argument("--import-boundary", help="the last sanitized snapshot commit; later commits are development")
    parser.add_argument("--rev", action="append", help="HEAD or a full commit ID (default HEAD)")
    parser.add_argument("--roots", action="store_true", help="prove every reachable commit descends from the published root")
    parser.add_argument("--all-refs", action="store_true", help="with --roots: check every ref")
    parser.add_argument("--tree-policy", action="store_true", help="verify the checked-out development tree policy")
    args = parser.parse_args()
    root = args.root.resolve()
    manifest = args.manifest if args.manifest.is_absolute() else root / args.manifest
    try:
        if args.roots:
            verify_roots(root, args.expected_root, None if args.all_refs else (args.rev or ["HEAD"]))
            print(f"repository-roots: PASS root={args.expected_root}")
            return 0
        if args.tree_policy:
            count = verify_tree_policy(root, args.import_boundary)
            print(f"repository-tree: PASS paths={count} import_boundary={args.import_boundary}")
            return 0
        if args.history and args.import_boundary:
            revs = args.rev or ["HEAD"]
            if len(revs) != 1:
                raise RuntimeError("History verification takes exactly one revision.")
            chain, boundary = verify_development_history(root, args.expected_root, args.import_boundary, revs[0])
            print(f"repository-history: PASS commits={len(chain)} snapshots={boundary + 1} "
                  f"development={len(chain) - boundary - 1} root={chain[0]} head={chain[-1]}")
            return 0
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
