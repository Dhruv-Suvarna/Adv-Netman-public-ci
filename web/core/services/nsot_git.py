"""
Read-only Git adapter for NSOT.

This module is the ONLY place in the codebase that shells out to `git`. All
arguments are fixed, server-generated argument arrays (never shell=True,
never browser text passed through); the repository path is pinned to
REPO_ROOT; every call has a finite timeout. Views never call `subprocess`
directly (enforced by core/tests/test_architecture.py); this module is only
ever imported from core/services/nsot_service.py.

The "Templates / Code" catalogue is intentionally allowlisted to a fixed set
of project-root directories -- there is no way to reach an arbitrary
filesystem path from a browser-supplied value.
"""

from __future__ import annotations

import subprocess
from datetime import datetime, timezone

from django.conf import settings

SOURCE = "GIT"

REPO_ROOT = settings.REPO_ROOT

# Known runtime-log deltas that are expected to be dirty at any given time
# (see AGENTS.md / docs/CURRENT_STATE.md) -- distinct from real project
# source drift.
KNOWN_RUNTIME_LOG_PATHS = frozenset({"Run_Logs.log", "logs/R2.log"})

# Allowlisted catalogue roots + extensions. Nothing outside these
# directories, and nothing without one of these extensions, is ever listed
# or readable through this module.
CATALOGUE_ROOTS = (
    "templates",
    "modules",
    "netbox/scripts",
    "dhcp",
    "monitoring/config",
)
CATALOGUE_EXTENSIONS = frozenset({".j2", ".py", ".yml", ".yaml"})
MAX_FILE_BYTES = 200_000


class GitUnavailableError(RuntimeError):
    """git could not be invoked or the repository state could not be read."""


def _run_git(args: list[str]) -> str:
    try:
        result = subprocess.run(
            ["git", *args],
            cwd=str(REPO_ROOT),
            capture_output=True,
            text=True,
            timeout=settings.NSOT_GIT_TIMEOUT_SECONDS,
            shell=False,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise GitUnavailableError(str(exc.__class__.__name__)) from exc
    if result.returncode != 0:
        raise GitUnavailableError(f"git {' '.join(args)} exited {result.returncode}")
    return result.stdout


def get_repo_state() -> dict:
    """Branch, HEAD commit, message, timestamp, and classified dirty state."""
    try:
        branch = _run_git(["rev-parse", "--abbrev-ref", "HEAD"]).strip()
        head_full = _run_git(["rev-parse", "HEAD"]).strip()
        head_short = _run_git(["rev-parse", "--short", "HEAD"]).strip()
        log_line = _run_git(
            ["log", "-1", "--format=%s%x1f%cI"]
        ).strip()
        message, _, commit_timestamp = log_line.partition("\x1f")
        status_raw = _run_git(["status", "--porcelain"])
    except GitUnavailableError as exc:
        return {
            "status": "unavailable",
            "message": f"Git repository metadata temporarily unavailable ({exc}).",
            "source": SOURCE,
        }

    dirty_paths = sorted(
        {line[3:].strip() for line in status_raw.splitlines() if line.strip()}
    )
    runtime_log_modifications = sorted(p for p in dirty_paths if p in KNOWN_RUNTIME_LOG_PATHS)
    project_source_drift = sorted(p for p in dirty_paths if p not in KNOWN_RUNTIME_LOG_PATHS)

    return {
        "status": "available",
        "source": SOURCE,
        "fetched_at": _now_iso(),
        "branch": branch,
        "head_commit": head_short,
        "head_commit_full": head_full,
        "head_message": message,
        "head_commit_time": commit_timestamp or None,
        "dirty": bool(dirty_paths),
        "dirty_file_count": len(dirty_paths),
        "project_source_drift": project_source_drift,
        "known_runtime_log_modifications": runtime_log_modifications,
    }


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _iter_allowlisted_paths():
    for root in CATALOGUE_ROOTS:
        base = (REPO_ROOT / root).resolve()
        if not base.is_relative_to(REPO_ROOT) or not base.is_dir():
            continue
        for path in sorted(base.rglob("*")):
            if not path.is_file():
                continue
            if path.suffix not in CATALOGUE_EXTENSIONS:
                continue
            resolved = path.resolve()
            if not resolved.is_relative_to(REPO_ROOT):
                continue
            yield resolved.relative_to(REPO_ROOT).as_posix()


def _file_git_status(rel_path: str, dirty_set: set[str]) -> str:
    if rel_path in dirty_set:
        return "tracked_modified"
    try:
        tracked = _run_git(["ls-files", "--error-unmatch", rel_path])
    except GitUnavailableError:
        return "untracked"
    return "tracked_clean" if tracked.strip() else "untracked"


def list_catalogued_files() -> dict:
    """Allowlisted project-root file catalogue with per-file Git status."""
    try:
        status_raw = _run_git(["status", "--porcelain"])
        untracked_raw = _run_git(["ls-files", "--others", "--exclude-standard"])
    except GitUnavailableError as exc:
        return {
            "status": "unavailable",
            "message": f"Git catalogue temporarily unavailable ({exc}).",
            "source": SOURCE,
            "data": [],
        }
    dirty_set = {line[3:].strip() for line in status_raw.splitlines() if line.strip()}
    untracked_set = {line.strip() for line in untracked_raw.splitlines() if line.strip()}

    rows = []
    for rel_path in _iter_allowlisted_paths():
        if rel_path in untracked_set:
            file_status = "untracked"
        elif rel_path in dirty_set:
            file_status = "tracked_modified"
        else:
            file_status = "tracked_clean"
        rows.append({"path": rel_path, "status": file_status})

    return {
        "status": "available",
        "source": SOURCE,
        "fetched_at": _now_iso(),
        "data": rows,
    }


def read_catalogued_file(rel_path: str) -> dict:
    """Return file text only if it is in the fixed allowlisted catalogue."""
    allowlisted = {row["path"] for row in list_catalogued_files().get("data", [])}
    if rel_path not in allowlisted:
        return {"status": "unavailable", "message": "File is not in the allowlisted catalogue.", "source": SOURCE}
    full_path = (REPO_ROOT / rel_path).resolve()
    if not full_path.is_relative_to(REPO_ROOT) or not full_path.is_file():
        return {"status": "unavailable", "message": "File is not in the allowlisted catalogue.", "source": SOURCE}
    try:
        data = full_path.read_bytes()
    except OSError as exc:
        return {"status": "unavailable", "message": f"File could not be read ({exc.__class__.__name__}).", "source": SOURCE}
    truncated = len(data) > MAX_FILE_BYTES
    text = data[:MAX_FILE_BYTES].decode("utf-8", errors="replace")
    return {
        "status": "available",
        "source": SOURCE,
        "fetched_at": _now_iso(),
        "path": rel_path,
        "content": text,
        "truncated": truncated,
    }
