#!/usr/bin/env python3
"""Install/verify/remove the approval-gated NMAS worker runtime.

No package index is used.  Dependencies are copied from a reviewed production
virtual environment only after exact version and wheel RECORD hashes verify.
The application copy is driven by a reviewed SHA-256 source manifest and omits
the production database, runtime secrets, Git metadata and generated files.
"""

from __future__ import annotations

import argparse
import base64
import csv
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile


SCHEMA = "nmas.worker-runtime/1"
SOURCE_SCHEMA = "nmas.worker-source-manifest/1"
OVERLAY_SCHEMA = "nmas.worker-overlay-manifest/1"
LOCK_RE = re.compile(r"^([A-Za-z0-9_.-]+)==([A-Za-z0-9_.+!-]+)$")
EXCLUDED_PARTS = frozenset({".git", "__pycache__"})
EXCLUDED_PREFIXES = ("monitoring/runtime/", "web/var/")
EXCLUDED_PATHS = frozenset({"deploy/sandbox/stage-b/dispatch-source-manifest.json"})
PLACEHOLDERS = ("web/db.sqlite3", "monitoring/runtime/device-credentials/store.json")
UNITS = ("nmas-troubleshooter-device-worker.service", "nmas-research-broker.service")
NAMESPACES = ("/run/netns/nmas-ts-diagnostic", "/run/netns/nmas-ts-research")


class Refused(RuntimeError):
    pass


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def safe_regular(path: Path, *, label: str) -> os.stat_result:
    try:
        info = path.lstat()
    except OSError as exc:
        raise Refused(f"{label} is unavailable: {type(exc).__name__}") from exc
    if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode):
        raise Refused(f"{label} must be a regular non-symlink file")
    return info


def canonical_name(value: str) -> str:
    return re.sub(r"[-_.]+", "-", value).lower()


def excluded(relative: str) -> bool:
    parts = Path(relative).parts
    return (relative in EXCLUDED_PATHS or Path(relative).name == ".env" or any(part in EXCLUDED_PARTS for part in parts)
            or relative.endswith((".pyc", ".pyo"))
            or relative.startswith(EXCLUDED_PREFIXES) or relative.startswith("web/db.sqlite3"))


def source_files(root: Path) -> list[dict]:
    if root.is_symlink() or not root.is_dir():
        raise Refused("source root must be a real directory")
    rows = []
    for directory, names, files in os.walk(root, followlinks=False):
        here = Path(directory)
        for name in names:
            candidate = here / name
            if candidate.is_symlink():
                raise Refused(f"source directory must not be a symlink: {candidate.relative_to(root)}")
        names[:] = sorted(name for name in names if not excluded((here / name).relative_to(root).as_posix()))
        for name in sorted(files):
            path = here / name
            relative = path.relative_to(root).as_posix()
            if excluded(relative):
                continue
            info = safe_regular(path, label=f"source {relative}")
            rows.append({"path": relative, "size": info.st_size, "mode": stat.S_IMODE(info.st_mode) & 0o755,
                         "sha256": digest(path)})
    if not rows or not any(row["path"] == "web/manage.py" for row in rows):
        raise Refused("source does not contain web/manage.py")
    return rows


def write_json_exclusive(path: Path, value: dict) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write("\n")


def build_manifest(source: Path, output: Path, release_id: str) -> dict:
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{7,79}", release_id):
        raise Refused("release id is malformed")
    manifest = {"schema": SOURCE_SCHEMA, "release_id": release_id, "source_root": str(source.resolve()),
                "files": source_files(source)}
    write_json_exclusive(output, manifest)
    return manifest


def build_overlay_manifest(root: Path, output: Path, release_id: str, paths: list[str]) -> dict:
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{7,79}", release_id):
        raise Refused("release id is malformed")
    if root.is_symlink() or not root.is_dir() or not paths:
        raise Refused("overlay needs a real root and explicit paths")
    rows = []
    for value in sorted(set(paths)):
        relative = Path(value)
        if relative.is_absolute() or ".." in relative.parts or excluded(relative.as_posix()):
            raise Refused(f"overlay path is forbidden: {value}")
        path = root / relative
        info = safe_regular(path, label=f"overlay {value}")
        rows.append({"path": relative.as_posix(), "size": info.st_size,
                     "mode": stat.S_IMODE(info.st_mode) & 0o755, "sha256": digest(path)})
    manifest = {"schema": OVERLAY_SCHEMA, "release_id": release_id,
                "overlay_root": str(root.resolve()), "files": rows}
    write_json_exclusive(output, manifest)
    return manifest


def load_json(path: Path, schema: str) -> dict:
    safe_regular(path, label=str(path))
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise Refused(f"invalid JSON: {path.name}") from exc
    if not isinstance(value, dict) or value.get("schema") != schema:
        raise Refused(f"unexpected schema in {path.name}")
    return value


def load_lock(path: Path) -> dict[str, tuple[str, str]]:
    safe_regular(path, label="dependency lock")
    locked = {}
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        match = LOCK_RE.fullmatch(line)
        if not match:
            raise Refused(f"invalid dependency lock line: {line}")
        key = canonical_name(match.group(1))
        if key in locked:
            raise Refused(f"duplicate dependency: {key}")
        locked[key] = (match.group(1), match.group(2))
    if not locked:
        raise Refused("dependency lock is empty")
    return locked


def site_packages(venv: Path) -> Path:
    matches = sorted(venv.glob("lib/python*/site-packages"))
    if len(matches) != 1 or matches[0].is_symlink() or not matches[0].is_dir():
        raise Refused("virtual environment site-packages is ambiguous")
    return matches[0]


def metadata_value(path: Path, key: str) -> str:
    prefix = key.lower() + ":"
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.lower().startswith(prefix):
            return line.split(":", 1)[1].strip()
    return ""


def record_hash(value: str) -> tuple[str, bytes] | None:
    if not value:
        return None
    algorithm, encoded = value.split("=", 1)
    return algorithm, base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))


def reject_symlink_components(root: Path, relative: Path) -> None:
    current = root
    for part in relative.parts:
        current = current / part
        if current.is_symlink():
            raise Refused(f"dependency path contains a symlink: {relative}")


def distribution_records(source_venv: Path, lock: dict[str, tuple[str, str]]) -> list[tuple[Path, Path]]:
    site = site_packages(source_venv)
    found = {}
    for info in site.glob("*.dist-info"):
        if info.is_symlink() or not info.is_dir():
            raise Refused("dependency metadata contains a symlink")
        metadata = info / "METADATA"
        safe_regular(metadata, label="distribution metadata")
        name, version = metadata_value(metadata, "Name"), metadata_value(metadata, "Version")
        found[canonical_name(name)] = (version, info)
    copies: dict[str, tuple[Path, Path]] = {}
    for key, (_name, expected_version) in lock.items():
        actual = found.get(key)
        if actual is None or actual[0] != expected_version:
            raise Refused(f"production dependency mismatch: {key}=={expected_version}")
        record = actual[1] / "RECORD"
        safe_regular(record, label=f"{key} RECORD")
        with record.open(newline="", encoding="utf-8") as stream:
            for row in csv.reader(stream):
                if len(row) < 3:
                    raise Refused(f"malformed RECORD for {key}")
                relative = Path(row[0])
                candidate = actual[1].parent / relative
                try:
                    inside = candidate.resolve(strict=True).relative_to(site.resolve(strict=True))
                except (OSError, ValueError):
                    continue  # console scripts outside site-packages are deliberately not installed
                reject_symlink_components(site, inside)
                source = site / inside
                safe_regular(source, label=f"dependency file {inside}")
                expected = record_hash(row[1])
                if expected:
                    algorithm, wanted = expected
                    if algorithm != "sha256" or hashlib.sha256(source.read_bytes()).digest() != wanted:
                        raise Refused(f"production dependency RECORD mismatch: {inside}")
                previous = copies.get(inside.as_posix())
                if previous and digest(previous[0]) != digest(source):
                    raise Refused(f"dependency file collision: {inside}")
                copies[inside.as_posix()] = (source, inside)
    return list(copies.values())


def verify_source(manifest: dict, source: Path) -> None:
    if str(source.resolve()) != manifest.get("source_root"):
        raise Refused("source root differs from the reviewed manifest")
    expected = {row["path"]: row for row in manifest.get("files", []) if isinstance(row, dict)}
    observed = {row["path"]: row for row in source_files(source)}
    if expected != observed:
        raise Refused("deployed application source differs from the reviewed manifest")


def verify_overlay(manifest: dict, root: Path, source_manifest: dict) -> None:
    if str(root.resolve()) != manifest.get("overlay_root"):
        raise Refused("overlay root differs from the reviewed manifest")
    base_paths = {row["path"] for row in source_manifest.get("files", []) if isinstance(row, dict)}
    for row in manifest.get("files", []):
        if not isinstance(row, dict) or row.get("path") not in base_paths:
            raise Refused("overlay may replace only a reviewed deployed-source file")
        relative = Path(row["path"])
        if relative.is_absolute() or ".." in relative.parts:
            raise Refused("overlay manifest contains an unsafe path")
        path = root / relative
        info = safe_regular(path, label=f"overlay {relative}")
        observed = {"path": relative.as_posix(), "size": info.st_size,
                    "mode": stat.S_IMODE(info.st_mode) & 0o755, "sha256": digest(path)}
        if observed != row:
            raise Refused(f"reviewed overlay changed: {relative}")


def copy_source(manifest: dict, source: Path, destination: Path) -> None:
    destination.mkdir(mode=0o755)
    for row in manifest["files"]:
        relative = Path(row["path"])
        target = destination / relative
        target.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
        if target.exists() or target.is_symlink():
            raise Refused(f"unexpected destination object: {relative}")
        shutil.copyfile(source / relative, target, follow_symlinks=False)
        target.chmod(int(row["mode"]) & 0o755 & ~0o022)
    for relative in PLACEHOLDERS:
        target = destination / relative
        target.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
        fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o000)
        os.close(fd)


def copy_overlay(manifest: dict, root: Path, destination: Path) -> None:
    for row in manifest.get("files", []):
        relative = Path(row["path"])
        target = destination / relative
        safe_regular(target, label=f"overlay destination {relative}")
        shutil.copyfile(root / relative, target, follow_symlinks=False)
        target.chmod(int(row["mode"]) & 0o755 & ~0o022)


def allowed_venv_symlink(path: Path, root: Path) -> bool:
    relative = path.relative_to(root).as_posix()
    target = os.readlink(path)
    if relative == "venv/lib64":
        return target == "lib"
    return relative in {"venv/bin/python", "venv/bin/python3",
                        f"venv/bin/python{sys.version_info.major}.{sys.version_info.minor}"}


def tree_manifest(root: Path) -> list[dict]:
    rows = []
    for directory, names, files in os.walk(root, followlinks=False):
        here = Path(directory)
        for name in sorted(names + files):
            path = here / name
            relative = path.relative_to(root).as_posix()
            info = path.lstat()
            if stat.S_ISLNK(info.st_mode):
                if not allowed_venv_symlink(path, root):
                    raise Refused(f"unexpected installed symlink: {relative}")
                rows.append({"path": relative, "type": "symlink", "target": os.readlink(path),
                             "mode": stat.S_IMODE(info.st_mode)})
            elif stat.S_ISREG(info.st_mode):
                mode = stat.S_IMODE(info.st_mode)
                rows.append({"path": relative, "type": "file", "size": info.st_size,
                             "sha256": digest(path) if mode & 0o444 else "", "mode": mode})
            elif stat.S_ISDIR(info.st_mode):
                rows.append({"path": relative, "type": "directory", "mode": stat.S_IMODE(info.st_mode)})
            else:
                raise Refused(f"unexpected installed object: {relative}")
    return rows


def smoke(runtime: Path) -> None:
    env = {"PATH": "/usr/bin:/bin", "DJANGO_DEBUG": "1", "DJANGO_SETTINGS_MODULE": "config.settings",
           "PYTHONDONTWRITEBYTECODE": "1"}
    command = [str(runtime / "venv/bin/python"), str(runtime / "current/web/manage.py"),
               "help", "troubleshooting_device_worker"]
    result = subprocess.run(command, cwd=runtime / "current/web", env=env, text=True, capture_output=True, check=False)
    if result.returncode:
        raise Refused(f"worker runtime smoke test failed: {result.stderr.splitlines()[-1:]}")
    imports = subprocess.run([str(runtime / "venv/bin/python"), "-c",
                              "import django,yaml,paramiko,cryptography,pyotp"], env=env,
                             text=True, capture_output=True, check=False)
    if imports.returncode:
        raise Refused("worker dependency import smoke failed")


def state_path(state_root: Path) -> Path:
    return state_root / "install-state.json"


def active_guard(test_mode: bool) -> None:
    if test_mode:
        return
    if any(Path(path).exists() for path in NAMESPACES):
        raise Refused("worker namespaces must be rolled back before runtime removal")
    for unit in UNITS:
        if subprocess.run(["/usr/bin/systemctl", "is-active", "--quiet", unit], check=False).returncode == 0:
            raise Refused(f"worker unit is active: {unit}")


def install(args) -> dict:
    manifest = load_json(args.source_manifest, SOURCE_SCHEMA)
    overlay = load_json(args.overlay_manifest, OVERLAY_SCHEMA) if args.overlay_manifest else None
    lock = load_lock(args.lock)
    verify_source(manifest, args.source)
    if overlay:
        verify_overlay(overlay, args.overlay_root, manifest)
    records = distribution_records(args.source_venv, lock)
    state_file = state_path(args.state_root)
    if state_file.exists():
        report = verify(args)
        return {**report, "result": "already-installed", "mutations": 0}
    if args.runtime.exists() or args.runtime.is_symlink():
        raise Refused("runtime root already exists without NMAS ownership state")
    if args.state_root.exists() and any(args.state_root.iterdir()):
        raise Refused("state root already contains foreign objects")
    args.runtime.parent.mkdir(parents=True, exist_ok=True)
    args.state_root.mkdir(mode=0o700, parents=True, exist_ok=True)
    temporary = Path(tempfile.mkdtemp(prefix=".nmas-worker-runtime-", dir=args.runtime.parent))
    try:
        copy_source(manifest, args.source, temporary / "current")
        if overlay:
            copy_overlay(overlay, args.overlay_root, temporary / "current")
        subprocess.run([str(args.python), "-m", "venv", "--without-pip", str(temporary / "venv")], check=True)
        destination_site = site_packages(temporary / "venv")
        for source, relative in records:
            target = destination_site / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            if target.exists() or target.is_symlink():
                if target.is_file() and digest(target) == digest(source):
                    continue
                raise Refused(f"unexpected dependency destination: {relative}")
            shutil.copyfile(source, target, follow_symlinks=False)
            target.chmod(stat.S_IMODE(source.stat().st_mode) & ~0o022)
        # mkdtemp stages the tree 0700.  The worker units run as unprivileged service accounts that must traverse the
        # runtime root to reach their interpreter and working directory, exactly like the 0755 trees beneath it.
        temporary.chmod(0o755)
        temporary.rename(args.runtime)
        smoke(args.runtime)
        state = {"schema": SCHEMA, "release_id": manifest["release_id"],
                 "source_manifest_sha256": digest(args.source_manifest), "lock_sha256": digest(args.lock),
                 "overlay_manifest_sha256": digest(args.overlay_manifest) if overlay else "",
                 "runtime": str(args.runtime), "tree": tree_manifest(args.runtime)}
        write_json_exclusive(state_file, state)
        return {"schema": SCHEMA, "result": "installed", "release_id": manifest["release_id"],
                "runtime": str(args.runtime)}
    except BaseException:
        if temporary.exists():
            shutil.rmtree(temporary)
        if args.runtime.exists() and not state_file.exists():
            shutil.rmtree(args.runtime)
        raise


def plan(args) -> dict:
    manifest = load_json(args.source_manifest, SOURCE_SCHEMA)
    overlay = load_json(args.overlay_manifest, OVERLAY_SCHEMA) if args.overlay_manifest else None
    lock = load_lock(args.lock)
    verify_source(manifest, args.source)
    if overlay:
        verify_overlay(overlay, args.overlay_root, manifest)
    records = distribution_records(args.source_venv, lock)
    return {"schema": SCHEMA, "result": "plan-valid", "release_id": manifest["release_id"],
            "source_files": len(manifest["files"]), "dependencies": len(lock),
            "overlay_files": len(overlay["files"]) if overlay else 0,
            "dependency_files": len(records), "mutations": 0}


def verify(args) -> dict:
    state = load_json(state_path(args.state_root), SCHEMA)
    if state.get("runtime") != str(args.runtime) or not args.runtime.is_dir() or args.runtime.is_symlink():
        raise Refused("runtime ownership state mismatch")
    if state.get("source_manifest_sha256") != digest(args.source_manifest) or state.get("lock_sha256") != digest(args.lock):
        raise Refused("reviewed input digest changed")
    expected_overlay = digest(args.overlay_manifest) if args.overlay_manifest else ""
    if state.get("overlay_manifest_sha256", "") != expected_overlay:
        raise Refused("reviewed overlay input digest changed")
    if state.get("tree") != tree_manifest(args.runtime):
        raise Refused("installed runtime drift detected")
    smoke(args.runtime)
    return {"schema": SCHEMA, "result": "verified", "release_id": state["release_id"],
            "runtime": str(args.runtime)}


def uninstall(args) -> dict:
    active_guard(args.test_mode)
    state_file = state_path(args.state_root)
    if not state_file.exists():
        if args.runtime.exists() or args.runtime.is_symlink():
            raise Refused("foreign runtime exists without ownership state")
        return {"schema": SCHEMA, "result": "already-absent", "mutations": 0}
    state = load_json(state_file, SCHEMA)
    verify(args)
    shutil.rmtree(args.runtime)
    state_file.unlink()
    try:
        args.state_root.rmdir()
    except OSError:
        pass
    return {"schema": SCHEMA, "result": "uninstalled", "release_id": state["release_id"]}


def parse(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("build-manifest", "build-overlay-manifest", "plan", "install", "verify", "uninstall"))
    parser.add_argument("--source", type=Path, default=Path("/home/student/Scripts/clab_dualstack_lab-deploy"))
    parser.add_argument("--source-manifest", type=Path)
    parser.add_argument("--overlay-root", type=Path)
    parser.add_argument("--overlay-manifest", type=Path)
    parser.add_argument("--overlay-path", action="append", default=[])
    parser.add_argument("--release-id", default="")
    parser.add_argument("--source-venv", type=Path, default=Path("/home/student/Scripts/.venv"))
    parser.add_argument("--lock", type=Path, default=Path(__file__).with_name("worker-runtime.lock"))
    parser.add_argument("--python", type=Path, default=Path("/usr/bin/python3"))
    parser.add_argument("--runtime", type=Path, default=Path("/opt/nmas"))
    parser.add_argument("--state-root", type=Path, default=Path("/var/lib/nmas-worker-runtime"))
    parser.add_argument("--output", type=Path)
    parser.add_argument("--test-mode", action="store_true", help=argparse.SUPPRESS)
    return parser.parse_args(argv)


def main(argv=None) -> int:
    args = parse(argv)
    try:
        if args.action == "build-manifest":
            if not args.output or not args.release_id:
                raise Refused("build-manifest requires --output and --release-id")
            report = build_manifest(args.source, args.output, args.release_id)
            print(json.dumps({"schema": report["schema"], "release_id": report["release_id"],
                              "files": len(report["files"]), "output": str(args.output)}, sort_keys=True))
            return 0
        if args.action == "build-overlay-manifest":
            if not args.output or not args.release_id or not args.overlay_root:
                raise Refused("build-overlay-manifest requires --output, --release-id and --overlay-root")
            report = build_overlay_manifest(args.overlay_root, args.output, args.release_id, args.overlay_path)
            print(json.dumps({"schema": report["schema"], "release_id": report["release_id"],
                              "files": len(report["files"]), "output": str(args.output)}, sort_keys=True))
            return 0
        if not args.source_manifest:
            raise Refused("--source-manifest is required")
        if bool(args.overlay_root) != bool(args.overlay_manifest):
            raise Refused("--overlay-root and --overlay-manifest must be supplied together")
        if args.action in {"install", "uninstall"} and os.geteuid() != 0 and not args.test_mode:
            raise Refused("runtime mutation requires root")
        function = {"plan": plan, "install": install, "verify": verify, "uninstall": uninstall}[args.action]
        print(json.dumps(function(args), sort_keys=True))
        return 0
    except (Refused, subprocess.CalledProcessError) as exc:
        print(f"REFUSED: {exc}", file=sys.stderr)
        return 65


if __name__ == "__main__":
    raise SystemExit(main())
