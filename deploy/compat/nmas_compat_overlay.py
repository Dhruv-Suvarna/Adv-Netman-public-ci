#!/usr/bin/env python3
"""NMAS troubleshooting + device-observation compatibility overlay: build, stage, verify, apply and roll back.

The production NMAS tree (legacy lineage, with reviewed uncommitted production edits) is NOT replaced.  This tool adds the
public-lineage troubleshooting / observation files to it and changes only a short, reviewed list of shared files, each guarded by
the exact SHA-256 the production file had when the package was reviewed.  Every production-only behaviour (Lab 8 cutover, the
uncommitted commissioning / isolation / ZTP / traffic / health / provisioning edits, ``settings_demo.py``) stays byte-identical.

    build    --public <worktree> --production <tree> --package <new dir>
             read-only on both trees; writes <package>/manifest.json, payload/ (frozen post-content), patches/ (review diffs)
    stage    --package P --production <tree> --out <new dir>       copy production to <dir> and overlay it there (never in place)
    verify   --package P --tree <dir> [--phase pre|post]            check every precondition (pre) or result (post) hash
    apply    --package P --production <tree> --backup-dir <new dir> --change-id <ID> --confirm <entries_sha256 prefix>
             the ONLY in-place writer: operator-run, refuses while any NMAS unit that imports the tree is active, journaled
    rollback --journal <backup-dir>/journal.json --db <sqlite file>
             refuses while the DB still records an overlay migration (reverse them to 0035 first); restores every replaced
             file, removes every added file and created directory, and re-verifies the pre-state
    db-backup      --db <live sqlite> --out <new file>          read-consistent copy (SQLite backup API, source opened read-only),
                                                               0600, integrity_check, SHA-256 + migration head in <out>.json
    db-restore     --backup <file> --db <sqlite> --confirm <sha256 prefix>   refuses while units are active; verifies the backup,
                                                               keeps the replaced file as <db>.pre-restore-<utc>, atomic swap
    diff     --package P [--summary]                             the exact production diff: the shared-file patches and every
                                                               added file against /dev/null (or a per-file summary)
    source-archive --production <tree> --out <new .tar.gz>      source tree (tracked, dirty and untracked files; never the DB,
                                                               web/var, monitoring/runtime or netbox/.env), 0600, SHA-256 sidecar

Standard library only; run with ``python3 -I``.  It never reads credentials and never restarts a service; the only database writer
is the operator-run ``db-restore``.  Actions:
  ADD      the path must be absent in production; the reviewed public content is added.
  REPLACE  the production file must have exactly ``pre_sha256``; it becomes the reviewed public file (``post_sha256``).  The
           production -> public difference is recorded (``removed_text``) and must be reviewed in the deployment diff.
  MERGE    the production file must have ``pre_sha256``; only the overlay's own hunks (MERGE_BASE -> reviewed tree) are
           transplanted onto it at BUILD time, each at a unique anchor; the result is frozen as ``post_sha256``.
"""

from __future__ import annotations

import argparse
import difflib
import fnmatch
import hashlib
import json
import os
import shutil
import sqlite3
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path

SCHEMA = "nmas.compat-overlay/1"
PRODUCTION_DEFAULT = "/home/student/Scripts/clab_dualstack_lab-deploy"
# Every unit that imports the production Django tree: the website, the three manage.py timers (and the oneshots they start) and
# the Lab 8 telemetry poller, which shells out to ``manage.py nmas_infrastructure``.  apply refuses while any of them is active.
SERVICES = ("nmas-web.service", "nmas-maintenance-tick.timer", "nmas-maintenance-tick.service", "nmas-probation-soak-tick.timer",
            "nmas-probation-soak-tick.service", "nmas-credential-rotation.timer", "nmas-credential-rotation.service",
            "nmas-demo-telemetry.timer", "nmas-demo-telemetry.service")
OVERLAY_MIGRATIONS = ("0036_v2_phase9_relay_option82_readback", "0037_troubleshooting", "0038_device_observations",
                      "0039_observation_authorizations")

# ----------------------------------------------------------------------------------------------------------------- the overlay
ADD_GLOBS = (
    "web/core/services/troubleshooting/**",
    "web/core/services/devices/observations.py", "web/core/services/devices/observation_*.py",
    "web/core/services/devices/reconciliation.py", "web/core/services/devices/host_key_pins.py",
    "web/core/services/management/linux_ssh.py",
    "web/core/management/commands/device_observe.py", "web/core/management/commands/observation_authorize.py",
    "web/core/management/commands/host_key_pin_check.py", "web/core/management/commands/nmas_reconcile_inventory.py",
    "web/core/management/commands/troubleshooting_*.py",
    *(f"web/core/migrations/{name}.py" for name in OVERLAY_MIGRATIONS),
    "web/core/templates/core/troubleshooting/**", "web/core/troubleshooting_urls.py", "web/core/troubleshooting_views.py",
    "web/core/checks.py",
    "web/core/tests/test_troubleshooting_*.py", "web/core/tests/fixtures/troubleshooting_collectors/**",
    "web/core/tests/fixtures/troubleshooting_runbooks/**", "web/core/tests/helpers/troubleshooting.py",
    "web/core/tests/test_device_observations.py", "web/core/tests/test_device_observe.py", "web/core/tests/test_observation_*.py",
    "web/core/tests/test_reconcile_inventory.py", "web/core/tests/test_host_key_pins.py", "web/core/tests/test_deploy_bindings.py",
    "deploy/sandbox/**",
    "break.py",
    "docs/troubleshooting/**",
)
REPLACE = (
    "web/core/models.py", "web/core/urls.py", "web/core/middleware.py", "web/core/apps.py", "web/config/settings.py",
    "web/core/services/identity/policy.py", "web/core/services/devices/lifecycle.py",
    "web/core/tests/runner.py",
)
MERGE = ("web/core/services/ci/rules.py",)
# The public commit the overlay was developed on.  MERGE transplants the hunks MERGE_BASE -> reviewed tree, so the result is the same
# before and after the overlay itself is committed (a moving HEAD base would silently drop the hunks once they are in HEAD).
MERGE_BASE = "4f950b36f97188f4d7b2c879006c472d9607bace"
EXCLUDE = ("*/__pycache__/*", "*.pyc")
# Review evidence (which cites this package's own hashes) is not deployed.
ADD_EXCLUDE = ("docs/troubleshooting/validation/**",)


def now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str | None:
    try:
        return sha256_bytes(path.read_bytes()) if path.is_file() and not path.is_symlink() else None
    except OSError:
        return None


def _git(repo: Path, *args: str) -> bytes:
    return subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True).stdout


def _public_files(public: Path) -> list[str]:
    out = _git(public, "ls-files", "-z", "--cached", "--others", "--exclude-standard").decode().split("\0")
    return sorted({p for p in out if p and (public / p).is_file() and not any(fnmatch.fnmatch(p, x) for x in EXCLUDE)})


def _match(path: str, pattern: str) -> bool:
    return path.startswith(pattern[:-2]) if pattern.endswith("/**") else fnmatch.fnmatchcase(path, pattern)


def _find_unique(lines: list[str], block: list[str]) -> int | None:
    hits = [i for i in range(len(lines) - len(block) + 1) if lines[i:i + len(block)] == block]
    return hits[0] if len(hits) == 1 else None


def _merge(current: bytes, base: bytes, other: bytes) -> tuple[bytes, list[str]]:
    """Transplant ONLY the overlay's own hunks (base -> other) onto ``current``.

    Each changed region is located in ``current`` by its exact base text (replacements / deletions) or by the base line next to
    it (pure insertions: the line before, else the line after); the anchor must occur exactly once or the hunk is refused.  Unlike a
    plain three-way merge this never imports, and never conflicts on, unrelated public-only lines adjacent to an overlay hunk."""
    cur, old, new = current.decode().splitlines(True), base.decode().splitlines(True), other.decode().splitlines(True)
    problems = []
    for tag, i1, i2, j1, j2 in reversed(difflib.SequenceMatcher(None, old, new, autojunk=False).get_opcodes()):
        if tag == "equal":
            continue
        if i2 > i1:
            at = _find_unique(cur, old[i1:i2])
            if at is None:
                problems.append(f"hunk at base line {i1 + 1}: replaced text not found exactly once")
                continue
            cur[at:at + (i2 - i1)] = new[j1:j2]
            continue
        before = _find_unique(cur, old[i1 - 1:i1]) if i1 > 0 else None
        if before is not None:
            cur[before + 1:before + 1] = new[j1:j2]
            continue
        after = _find_unique(cur, old[i1:i1 + 1]) if i1 < len(old) else None
        if after is None:
            problems.append(f"insertion at base line {i1 + 1}: no unique anchor")
            continue
        cur[after:after] = new[j1:j2]
    return "".join(cur).encode(), problems


def _diff(path: str, before: bytes, after: bytes) -> tuple[str, int, list[str]]:
    lines = list(difflib.unified_diff(before.decode().splitlines(True), after.decode().splitlines(True),
                                      fromfile=f"a/{path}", tofile=f"b/{path}"))
    added = sum(1 for line in lines if line.startswith("+") and not line.startswith("+++"))
    removed = [line[1:].rstrip("\n") for line in lines if line.startswith("-") and not line.startswith("---")]
    return "".join(lines), added, removed


# ----------------------------------------------------------------------------------------------------------------------- build
def build(public: Path, production: Path, package: Path, merge_base: str = MERGE_BASE) -> dict:
    if package.exists():
        raise SystemExit(f"REFUSED: {package} exists")
    payload, patches = package / "payload", package / "patches"
    entries, problems, frozen = [], [], {}
    for path in _public_files(public):
        if path in REPLACE or path in MERGE or not any(_match(path, g) for g in ADD_GLOBS) \
                or any(_match(path, g) for g in ADD_EXCLUDE):
            continue
        data = (public / path).read_bytes()
        if (production / path).exists():
            problems.append(f"ADD target already exists in production: {path}")
        frozen[path] = data
        entries.append({"action": "ADD", "path": path, "pre_sha256": None, "post_sha256": sha256_bytes(data),
                        "mode": "0775" if os.access(public / path, os.X_OK) else "0664"})
    for path in (*REPLACE, *MERGE):
        prod = production / path
        if not prod.is_file():
            problems.append(f"target missing in production: {path}")
            continue
        before = prod.read_bytes()
        if path in MERGE:
            after, issues = _merge(before, _git(public, "show", f"{merge_base}:{path}"), (public / path).read_bytes())
            problems.extend(f"MERGE {path}: {issue}" for issue in issues)
        else:
            after = (public / path).read_bytes()
        text, added, removed = _diff(path, before, after)
        frozen[path] = after
        name = path.replace("/", "__") + ".patch"
        patches.mkdir(parents=True, exist_ok=True)
        (patches / name).write_text(text)
        entries.append({"action": "MERGE" if path in MERGE else "REPLACE", "path": path, "pre_sha256": sha256_bytes(before),
                        "post_sha256": sha256_bytes(after), "added_lines": added, "removed_lines": len(removed),
                        "removed_text": removed, "patch": f"patches/{name}", "mode": "%04o" % stat.S_IMODE(prod.stat().st_mode)})
    for path, data in frozen.items():
        (payload / path).parent.mkdir(parents=True, exist_ok=True)
        (payload / path).write_bytes(data)
    shutil.copy2(Path(__file__).resolve(), package / "nmas_compat_overlay.py")
    entries.sort(key=lambda e: (e["action"], e["path"]))
    manifest = {"schema": SCHEMA, "public_head": _git(public, "rev-parse", "HEAD").decode().strip(), "merge_base": merge_base,
                "public_dirty": bool(_git(public, "status", "--porcelain").strip()),
                "production_head": _git(production, "rev-parse", "HEAD").decode().strip() if (production / ".git").exists() else "",
                "built_at": now(), "problems": problems, "services": list(SERVICES), "overlay_migrations": list(OVERLAY_MIGRATIONS),
                "tool_sha256": sha256_file(package / "nmas_compat_overlay.py"), "entries": entries,
                "entries_sha256": sha256_bytes(json.dumps(entries, sort_keys=True).encode())}
    (package / "manifest.json").write_text(json.dumps(manifest, indent=1, sort_keys=True) + "\n")
    lines = [f"{sha256_file(package / 'manifest.json')}  manifest.json", f"{manifest['tool_sha256']}  nmas_compat_overlay.py"]
    (package / "SHA256SUMS").write_text("\n".join(lines) + "\n")
    return manifest


# ------------------------------------------------------------------------------------------------------------- shared checks
def load(package: Path) -> tuple[dict, str]:
    """The manifest and its review identity (``entries_sha256``), refusing a package whose entries, payload or tool changed.

    ``entries_sha256`` covers every path, action, pre/post SHA-256, mode and removed line, and does not depend on build time or on
    the worktree's dirty flag, so a rebuild from the reviewed commit against the same production tree reproduces it exactly."""
    manifest = json.loads((package / "manifest.json").read_bytes())
    if manifest.get("schema") != SCHEMA or manifest.get("problems"):
        raise SystemExit(f"REFUSED: manifest invalid or carries build problems: {manifest.get('problems')}")
    if sha256_bytes(json.dumps(manifest["entries"], sort_keys=True).encode()) != manifest.get("entries_sha256"):
        raise SystemExit("REFUSED: manifest entries do not match entries_sha256 (edited after review)")
    if sha256_file(package / "nmas_compat_overlay.py") != manifest.get("tool_sha256"):
        raise SystemExit("REFUSED: packaged tool differs from the reviewed tool")
    for e in manifest["entries"]:
        if sha256_file(package / "payload" / e["path"]) != e["post_sha256"]:
            raise SystemExit(f"REFUSED: payload for {e['path']} is not the reviewed content")
    return manifest, manifest["entries_sha256"]


def verify(entries: list[dict], tree: Path, phase: str) -> list[str]:
    bad = []
    for e in entries:
        actual = sha256_file(tree / e["path"])
        wanted = e["pre_sha256"] if phase == "pre" else e["post_sha256"]
        if actual != wanted:
            bad.append(f"{phase}:{e['action']}:{e['path']}: expected {wanted or 'absent'} found {actual or 'absent'}")
    return bad


def _missing_dirs(directory: Path, root: Path) -> list[Path]:
    missing = []
    while not directory.exists() and directory != root:
        missing.append(directory)
        directory = directory.parent
    return missing


def _write_atomic(path: Path, data: bytes, mode: str) -> None:
    for d in reversed(_missing_dirs(path.parent, Path("/"))):
        d.mkdir()
        os.chmod(d, 0o775)                    # the production tree's directory mode, independent of the caller's umask
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".nmas-overlay-")
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(tmp, int(mode, 8))
        os.replace(tmp, path)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise


def _overlay(manifest: dict, package: Path, tree: Path) -> list[str]:
    """Write every entry into ``tree``; returns the directories it created (deepest first)."""
    pre = verify(manifest["entries"], tree, "pre")
    if pre:
        raise SystemExit("REFUSED: preconditions do not hold (the tree changed since review):\n  " + "\n  ".join(pre))
    created: set[Path] = set()
    for e in manifest["entries"]:
        created.update(_missing_dirs((tree / e["path"]).parent, tree))
    for e in manifest["entries"]:
        target = tree / e["path"]
        mode = e["mode"] if e["action"] == "ADD" else "%04o" % stat.S_IMODE(target.stat().st_mode)   # keep a shared file's live mode
        _write_atomic(target, (package / "payload" / e["path"]).read_bytes(), mode)
    post = verify(manifest["entries"], tree, "post")
    if post:
        raise SystemExit("FAILED: post-conditions do not hold:\n  " + "\n  ".join(post))
    return [str(d.relative_to(tree)) for d in sorted(created, key=lambda d: len(d.parts), reverse=True)]


# -------------------------------------------------------------------------------------------------------------- stage / apply
def stage(package: Path, production: Path, out: Path) -> None:
    manifest, _ = load(package)
    if out.exists():
        raise SystemExit(f"REFUSED: {out} exists")
    shutil.copytree(production, out, symlinks=True, ignore=_stage_ignore(production))
    _overlay(manifest, package, out)


# Never copied into a staged tree: the repository, the live database and its backups, runtime state and every secret-bearing
# runtime directory (device locks, credential-rotation env, MFA keys, NetBox env).  Matched by path relative to the tree root.
STAGE_EXCLUDE = (".git", "web/db.sqlite3*", "web/var", "monitoring/runtime", "netbox/.env", "__pycache__", "*/__pycache__", "*.pyc")


def _stage_ignore(root: Path):
    def ignore(directory: str, names: list[str]) -> set[str]:
        rel = Path(directory).relative_to(root)
        paths = {n: (n if rel == Path(".") else f"{rel.as_posix()}/{n}") for n in names}
        return {n for n, path in paths.items() if any(fnmatch.fnmatchcase(path, x) for x in STAGE_EXCLUDE)}
    return ignore


def _services_active(units) -> list[str]:
    try:
        res = subprocess.run(["systemctl", "is-active", *units], capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.TimeoutExpired):
        return ["systemctl-unavailable"]
    states = res.stdout.split()
    if len(states) != len(units):
        return ["systemctl-unavailable"]
    return [f"{unit}={state}" for unit, state in zip(units, states) if state not in ("inactive", "failed")]


def _write_journal(backup_dir: Path, journal: dict) -> None:
    tmp = backup_dir / "journal.json.tmp"
    tmp.write_text(json.dumps(journal, indent=1, sort_keys=True))
    os.replace(tmp, backup_dir / "journal.json")


def apply(package: Path, production: Path, backup_dir: Path, change_id: str, confirm: str, scratch_target: bool = False) -> None:
    manifest, mid = load(package)
    if scratch_target and (production.resolve() == Path(PRODUCTION_DEFAULT).resolve() or (production / "web" / "var").exists()
                           or (production / ".git").exists()):
        raise SystemExit("REFUSED: --scratch-target may only name a disposable copy (no .git, no web/var), never the deployed tree")
    if len(confirm) < 12 or not mid.startswith(confirm.lower()):
        raise SystemExit("REFUSED: --confirm must be a prefix (>= 12 hex) of the reviewed entries_sha256")
    if not change_id.strip():
        raise SystemExit("REFUSED: --change-id is required")
    active = [] if scratch_target else _services_active(manifest["services"])
    if active:
        raise SystemExit(f"REFUSED: stop the NMAS units that import the tree first ({', '.join(active)})")
    if backup_dir.exists():
        raise SystemExit(f"REFUSED: backup directory {backup_dir} already exists")
    pre = verify(manifest["entries"], production, "pre")
    if pre:
        raise SystemExit("REFUSED: preconditions do not hold:\n  " + "\n  ".join(pre))
    old_umask = os.umask(0o077)
    try:
        (backup_dir / "files").mkdir(parents=True)
    finally:
        os.umask(old_umask)
    os.chmod(backup_dir, 0o700)
    saved = []
    for e in manifest["entries"]:
        if e["action"] == "ADD":
            continue
        src, dst = production / e["path"], backup_dir / "files" / e["path"]
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)
        if sha256_file(dst) != e["pre_sha256"]:
            raise SystemExit(f"REFUSED: backup copy of {e['path']} does not verify")
        saved.append({"path": e["path"], "sha256": e["pre_sha256"], "mode": "%04o" % stat.S_IMODE(src.stat().st_mode)})
    created = sorted({str(d.relative_to(production)) for e in manifest["entries"]
                      for d in _missing_dirs((production / e["path"]).parent, production)},
                     key=lambda d: d.count("/"), reverse=True)
    journal = {"schema": SCHEMA + "/journal", "change_id": change_id, "entries_sha256": mid,
               "manifest_sha256": sha256_file(package / "manifest.json"), "package": str(package.resolve()),
               "production": str(production.resolve()), "started_at": now(), "saved": saved,
               "added": [e["path"] for e in manifest["entries"] if e["action"] == "ADD"], "created_dirs": created,
               "entries": manifest["entries"], "overlay_migrations": manifest["overlay_migrations"], "status": "APPLYING"}
    _write_journal(backup_dir, journal)
    try:
        _overlay(manifest, package, production)
    except BaseException:
        journal["status"] = "FAILED_NEEDS_ROLLBACK"
        _write_journal(backup_dir, journal)
        raise
    journal["status"], journal["finished_at"] = "APPLIED", now()
    _write_journal(backup_dir, journal)
    print(f"APPLIED {len(manifest['entries'])} entries (change {change_id}); journal {backup_dir / 'journal.json'}")


# ---------------------------------------------------------------------------------------------------------------- rollback
def applied_overlay_migrations(db: Path, names) -> list[str]:
    """Overlay migrations the database still records (read-only open; a missing table means none)."""
    con = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    try:
        rows = con.execute("SELECT name FROM django_migrations WHERE app = 'core'").fetchall()
    except sqlite3.OperationalError:
        return []
    finally:
        con.close()
    return sorted(set(names) & {r[0] for r in rows})


def rollback(journal_path: Path, db: Path | None, skip_db_check: bool) -> None:
    journal = json.loads(journal_path.read_text())
    if journal.get("schema") != SCHEMA + "/journal":
        raise SystemExit("REFUSED: not an overlay journal")
    if not skip_db_check:
        if db is None or not db.is_file():
            raise SystemExit("REFUSED: --db <sqlite file> is required (the service database that ran with this overlay)")
        still = applied_overlay_migrations(db, journal["overlay_migrations"])
        if still:
            raise SystemExit("REFUSED: reverse the overlay migrations first (manage.py migrate core 0035); still applied: "
                             + ", ".join(still))
    production, backup = Path(journal["production"]), journal_path.parent / "files"
    for item in journal["saved"]:                      # verify every backup before touching anything
        if sha256_file(backup / item["path"]) != item["sha256"]:
            raise SystemExit(f"FAILED: backup of {item['path']} is corrupt; nothing changed; restore from the tree archive")
    for path in journal["added"]:
        target = production / path
        if target.is_file() or target.is_symlink():
            target.unlink()
    for rel in journal["created_dirs"]:                 # deepest first; only directories this overlay created
        d = production / rel
        if d.is_dir():
            shutil.rmtree(d / "__pycache__", ignore_errors=True)
            try:
                d.rmdir()
            except OSError:
                pass
    for item in journal["saved"]:
        _write_atomic(production / item["path"], (backup / item["path"]).read_bytes(), item["mode"])
    remaining = verify(journal["entries"], production, "pre")
    leftovers = [rel for rel in journal["created_dirs"] if (production / rel).exists()]
    if remaining:
        raise SystemExit("FAILED: tree is not back at its pre-state:\n  " + "\n  ".join(remaining))
    journal["status"], journal["rolled_back_at"], journal["leftover_dirs"] = "ROLLED_BACK", now(), leftovers
    _write_journal(journal_path.parent, journal)
    print(f"ROLLED BACK: {len(journal['added'])} added files removed, {len(journal['saved'])} files restored; pre-state verified"
          + (f"; non-empty directories kept: {leftovers}" if leftovers else ""))


# --------------------------------------------------------------------------------------------------- database and source backups
def _integrity(db: Path) -> tuple[str, list]:
    con = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    try:
        return con.execute("PRAGMA integrity_check").fetchone()[0], con.execute("PRAGMA foreign_key_check").fetchall()
    finally:
        con.close()


def _migration_head(db: Path) -> str:
    con = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    try:
        row = con.execute("SELECT name FROM django_migrations WHERE app = 'core' ORDER BY name DESC LIMIT 1").fetchone()
        return row[0] if row else ""
    except sqlite3.OperationalError:
        return ""
    finally:
        con.close()


def db_backup(db: Path, out: Path) -> dict:
    """Read-consistent copy of ``db`` (the source is opened read-only; the backup API holds a read transaction)."""
    if out.exists() or Path(str(out) + ".json").exists():
        raise SystemExit(f"REFUSED: {out} exists")
    if not db.is_file():
        raise SystemExit(f"REFUSED: {db} is not a file")
    old = os.umask(0o077)
    try:
        out.parent.mkdir(parents=True, exist_ok=True)
        src = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
        dst = sqlite3.connect(out)
        try:
            src.backup(dst)
        finally:
            dst.close()
            src.close()
        os.chmod(out, 0o600)
        integrity, fk = _integrity(out)
        if integrity != "ok" or fk:
            out.unlink()
            raise SystemExit(f"FAILED: backup integrity_check={integrity} foreign_key_check={len(fk)} rows; backup removed")
        record = {"schema": SCHEMA + "/db-backup", "source": str(db.resolve()), "file": out.name, "sha256": sha256_file(out),
                  "bytes": out.stat().st_size, "integrity_check": integrity, "core_migration_head": _migration_head(out),
                  "taken_at": now()}
        Path(str(out) + ".json").write_text(json.dumps(record, indent=1, sort_keys=True) + "\n")
    finally:
        os.umask(old)
    return record


def db_restore(backup: Path, db: Path, confirm: str, scratch_target: bool = False) -> dict:
    record = json.loads(Path(str(backup) + ".json").read_text())
    digest = sha256_file(backup)
    if record.get("schema") != SCHEMA + "/db-backup" or digest != record.get("sha256"):
        raise SystemExit("REFUSED: backup does not match its recorded SHA-256")
    if len(confirm) < 12 or not digest.startswith(confirm.lower()):
        raise SystemExit("REFUSED: --confirm must be a prefix (>= 12 hex) of the backup's SHA-256")
    if scratch_target and db.resolve().is_relative_to(Path(PRODUCTION_DEFAULT).resolve()):
        raise SystemExit("REFUSED: --scratch-target may not name a database inside the deployed tree")
    active = [] if scratch_target else _services_active(SERVICES)
    if active:
        raise SystemExit(f"REFUSED: stop the NMAS units first ({', '.join(active)})")
    for suffix in ("-journal", "-wal", "-shm"):
        if Path(str(db) + suffix).exists():
            raise SystemExit(f"REFUSED: {db}{suffix} exists (a writer is or was active); resolve it before restoring")
    integrity, fk = _integrity(backup)
    if integrity != "ok" or fk:
        raise SystemExit("REFUSED: backup fails integrity_check / foreign_key_check")
    kept = None
    if db.exists():
        kept = Path(f"{db}.pre-restore-{time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())}")
        shutil.copy2(db, kept)
        os.chmod(kept, 0o600)
    mode = "%04o" % stat.S_IMODE(db.stat().st_mode) if db.exists() else "0600"
    _write_atomic(db, backup.read_bytes(), mode)
    if sha256_file(db) != digest:
        raise SystemExit(f"FAILED: restored file does not match the backup; the replaced database is kept at {kept}")
    return {"restored": str(db), "sha256": digest, "core_migration_head": _migration_head(db), "previous_kept_at": str(kept or "")}


def source_archive(production: Path, out: Path) -> dict:
    import tarfile

    if out.exists() or Path(str(out) + ".json").exists():
        raise SystemExit(f"REFUSED: {out} exists")
    ignore = _stage_ignore(production)
    members = 0
    old = os.umask(0o077)
    try:
        out.parent.mkdir(parents=True, exist_ok=True)
        with tarfile.open(out, "w:gz") as tar:
            for directory, dirs, files in os.walk(production):
                skipped = ignore(directory, dirs + files) - {".git"}          # keep the worktree's .git pointer, never runtime state
                dirs[:] = sorted(d for d in dirs if d not in skipped)
                for name in sorted(f for f in files if f not in skipped):
                    path = Path(directory) / name
                    tar.add(path, arcname=str(path.relative_to(production)), recursive=False)
                    members += 1
        os.chmod(out, 0o600)
        with tarfile.open(out, "r:gz") as tar:
            listed = sum(1 for m in tar.getmembers() if not m.isdir())
        if listed != members:
            raise SystemExit(f"FAILED: archive lists {listed} files, wrote {members}")
        record = {"schema": SCHEMA + "/source-archive", "source": str(production.resolve()), "file": out.name, "files": members,
                  "sha256": sha256_file(out), "excluded": list(STAGE_EXCLUDE), "taken_at": now()}
        Path(str(out) + ".json").write_text(json.dumps(record, indent=1, sort_keys=True) + "\n")
    finally:
        os.umask(old)
    return record


def deployment_diff(package: Path, summary: bool = False) -> str:
    """The exact change ``apply`` makes, rendered from the frozen package (production is not read)."""
    manifest, ident = load(package)
    out = [f"# nmas compatibility overlay: entries_sha256 {ident}\n# production {manifest['production_head']} + uncommitted state "
           f"(pre_sha256 per file); public {manifest['public_head']} (merge base {manifest.get('merge_base', '')})\n"]
    for e in manifest["entries"]:
        if summary:
            extra = (f" +{e['added_lines']} -{e['removed_lines']}" if e["action"] != "ADD" else
                     f" {len((package / 'payload' / e['path']).read_bytes().splitlines())} lines")
            out.append(f"{e['action']:7} {e['mode']} {e['post_sha256']} {e['path']}{extra}\n")
        elif e["action"] == "ADD":
            data = (package / "payload" / e["path"]).read_bytes()
            try:
                lines = data.decode().splitlines(True)
            except UnicodeDecodeError:
                out.append(f"Binary file /dev/null and b/{e['path']} differ (sha256 {e['post_sha256']})\n")
                continue
            git_mode = "100755" if int(e["mode"], 8) & 0o111 else "100644"     # git records only these; apply sets e["mode"]
            out.append(f"diff --git a/{e['path']} b/{e['path']}\nnew file mode {git_mode}\n")
            out.extend(difflib.unified_diff([], lines, fromfile="/dev/null", tofile=f"b/{e['path']}"))
            if lines and not lines[-1].endswith("\n"):
                out.append("\n\\ No newline at end of file\n")
        elif (patch := (package / e["patch"]).read_text()):
            out.append(f"diff --git a/{e['path']} b/{e['path']}\n{patch}")
    return "".join(out)


# ------------------------------------------------------------------------------------------------------------------------- cli
def main(argv=None) -> int:
    here = Path(__file__).resolve().parents[2]
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = p.add_subparsers(dest="cmd", required=True)
    b = sub.add_parser("build")
    b.add_argument("--public", type=Path, default=here)
    b.add_argument("--production", type=Path, default=Path(PRODUCTION_DEFAULT))
    b.add_argument("--package", type=Path, required=True)
    b.add_argument("--merge-base", default=MERGE_BASE, help="public commit the MERGE hunks are computed from (default: %(default)s)")
    s = sub.add_parser("stage")
    s.add_argument("--package", type=Path, required=True)
    s.add_argument("--production", type=Path, default=Path(PRODUCTION_DEFAULT))
    s.add_argument("--out", type=Path, required=True)
    v = sub.add_parser("verify")
    v.add_argument("--package", type=Path, required=True)
    v.add_argument("--tree", type=Path, required=True)
    v.add_argument("--phase", choices=("pre", "post"), default="post")
    a = sub.add_parser("apply")
    a.add_argument("--package", type=Path, required=True)
    a.add_argument("--production", type=Path, default=Path(PRODUCTION_DEFAULT))
    a.add_argument("--backup-dir", type=Path, required=True)
    a.add_argument("--change-id", required=True)
    a.add_argument("--confirm", required=True)
    a.add_argument("--scratch-target", action="store_true",
                   help="rehearsal on a disposable copy: skips the unit check, refused for the deployed tree or any tree with .git/web/var")
    r = sub.add_parser("rollback")
    r.add_argument("--journal", type=Path, required=True)
    r.add_argument("--db", type=Path)
    r.add_argument("--skip-db-check", action="store_true", help="only for a staged copy that never served a database")
    df = sub.add_parser("diff")
    df.add_argument("--package", type=Path, required=True)
    df.add_argument("--summary", action="store_true")
    db = sub.add_parser("db-backup")
    db.add_argument("--db", type=Path, required=True)
    db.add_argument("--out", type=Path, required=True)
    dr = sub.add_parser("db-restore")
    dr.add_argument("--backup", type=Path, required=True)
    dr.add_argument("--db", type=Path, required=True)
    dr.add_argument("--confirm", required=True)
    dr.add_argument("--scratch-target", action="store_true", help="rehearsal on a database outside the deployed tree")
    sa = sub.add_parser("source-archive")
    sa.add_argument("--production", type=Path, default=Path(PRODUCTION_DEFAULT))
    sa.add_argument("--out", type=Path, required=True)
    args = p.parse_args(argv)
    if args.cmd == "diff":
        sys.stdout.write(deployment_diff(args.package, args.summary))
        return 0
    if args.cmd in ("db-backup", "db-restore", "source-archive"):
        result = (db_backup(args.db, args.out) if args.cmd == "db-backup" else
                  db_restore(args.backup, args.db, args.confirm, args.scratch_target) if args.cmd == "db-restore" else
                  source_archive(args.production, args.out))
        print(json.dumps(result, indent=1, sort_keys=True))
        return 0
    if args.cmd == "build":
        m = build(args.public, args.production, args.package, args.merge_base)
        counts = {k: sum(1 for e in m["entries"] if e["action"] == k) for k in ("ADD", "REPLACE", "MERGE")}
        print(json.dumps({"entries": counts, "problems": m["problems"], "entries_sha256": m["entries_sha256"],
                          "manifest_sha256": sha256_file(args.package / "manifest.json")}))
        return 1 if m["problems"] else 0
    if args.cmd == "stage":
        stage(args.package, args.production, args.out)
        print(f"STAGED {args.out}")
        return 0
    if args.cmd == "verify":
        manifest, _ = load(args.package)
        bad = verify(manifest["entries"], args.tree, args.phase)
        print("\n".join(bad) if bad else f"VERIFIED ({args.phase}): all {len(manifest['entries'])} entries match")
        return 1 if bad else 0
    if args.cmd == "apply":
        apply(args.package, args.production, args.backup_dir, args.change_id, args.confirm, args.scratch_target)
        return 0
    rollback(args.journal, args.db, args.skip_db_check)
    return 0


if __name__ == "__main__":
    sys.exit(main())
