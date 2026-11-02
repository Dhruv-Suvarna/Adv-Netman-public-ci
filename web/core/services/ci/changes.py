"""Deterministic changed-file collection for a base/head comparison.

Nothing here is GitHub-specific.  Callers (the CLI, the GitHub context helper, tests, Django)
supply explicit revisions; this module only reads git metadata and repository files.

Range semantics (documented in docs/GITHUB_ACTIONS_TIER3_VALIDATION.md):

* ``merge_base=True``  (pull requests, local default): the diff is ``merge-base(base, head)..head``
  -- exactly the change a branch introduces, unaffected by later movement of ``base``.
* ``merge_base=False`` (pushes): the diff is ``base..head`` -- exactly what the push introduced.
* ``base is None``: no usable base (new branch, unresolvable force-push, full manual run).  Every
  tracked file at ``head`` is treated as added, which classifies broadly -- never "nothing changed".
* ``working_tree=True``: ``base`` versus the current working tree (staged + unstaged + untracked),
  so a developer can run Tier 3 before committing.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from . import gitio
from .constants import FileStatus

MAX_SCAN_LINES = 50_000
MAX_SCAN_FILE_BYTES = 1_000_000

STRATEGY_MERGE_BASE = "merge-base"
STRATEGY_DIRECT = "direct"
STRATEGY_WORKING_TREE = "working-tree"
STRATEGY_ALL_TRACKED = "all-tracked"


@dataclass(frozen=True)
class ChangedFile:
    path: str
    status: str
    old_path: str | None = None  # renames only

    def paths(self) -> tuple[str, ...]:
        """Every path this change touches (a rename touches both sides)."""
        return (self.path,) if self.old_path is None else (self.path, self.old_path)


@dataclass(frozen=True)
class ChangeSet:
    head_sha: str
    base_sha: str | None
    compare_from_sha: str | None  # the commit actually diffed from (merge-base or base)
    strategy: str
    files: tuple[ChangedFile, ...]
    notes: tuple[str, ...] = ()
    working_tree: bool = False

    @property
    def empty(self) -> bool:
        return not self.files


@dataclass(frozen=True)
class ScanLine:
    path: str
    line: int
    text: str


def collect_changes(repo: Path, base: str | None, head: str = "HEAD", *, merge_base: bool = True, working_tree: bool = False) -> ChangeSet:
    """Collect the changed files for a comparison.  Raises ``gitio.GitError`` on a bad revision."""
    head_sha = gitio.resolve_commit(repo, head)
    if base is None:
        if working_tree:
            raise gitio.GitError("a working-tree comparison needs an explicit base revision")
        return _all_tracked(repo, head_sha, "no base revision supplied; every tracked file is treated as changed")
    base_sha = gitio.resolve_commit(repo, base)
    notes: list[str] = []
    if working_tree:
        # base versus the working tree: head is HEAD by definition, uncommitted work is included
        compare_from = gitio.run_git(repo, ["merge-base", base_sha, head_sha]).strip() if merge_base else base_sha
        files = _parse_name_status(gitio.run_git(repo, ["diff", "--name-status", "-z", "-M", "--no-ext-diff", "--no-color", compare_from]))
        files += _untracked(repo, {f.path for f in files})
        notes.append("working-tree comparison: uncommitted and untracked files are included")
        return ChangeSet(head_sha, base_sha, compare_from, STRATEGY_WORKING_TREE, _sorted(files), tuple(notes), working_tree=True)
    if merge_base:
        compare_from = gitio.run_git(repo, ["merge-base", base_sha, head_sha]).strip()
        strategy = STRATEGY_MERGE_BASE
        if not re.fullmatch(r"[0-9a-f]{40}", compare_from):
            raise gitio.GitError("base and head share no merge-base")
    else:
        compare_from, strategy = base_sha, STRATEGY_DIRECT
    out = gitio.run_git(repo, ["diff", "--name-status", "-z", "-M", "--no-ext-diff", "--no-color", compare_from, head_sha])
    return ChangeSet(head_sha, base_sha, compare_from, strategy, _sorted(_parse_name_status(out)), tuple(notes))


def _all_tracked(repo: Path, head_sha: str, note: str) -> ChangeSet:
    out = gitio.run_git(repo, ["ls-tree", "-r", "-z", "--name-only", head_sha])
    files = [ChangedFile(path, FileStatus.ADDED) for path in out.split("\0") if path]
    return ChangeSet(head_sha, None, None, STRATEGY_ALL_TRACKED, _sorted(files), (note,))


def _sorted(files: list[ChangedFile]) -> tuple[ChangedFile, ...]:
    return tuple(sorted(files, key=lambda f: (f.path, f.status, f.old_path or "")))


def _parse_name_status(raw: str) -> list[ChangedFile]:
    """Parse ``git diff --name-status -z`` (status, path[, new path] as NUL-separated tokens)."""
    tokens = raw.split("\0")
    files: list[ChangedFile] = []
    i = 0
    while i < len(tokens):
        status = tokens[i]
        if not status:
            i += 1
            continue
        kind = status[0]
        if kind in "RC":  # rename / copy: old path then new path
            old, new = tokens[i + 1], tokens[i + 2]
            i += 3
            files.append(ChangedFile(new, FileStatus.RENAMED if kind == "R" else FileStatus.ADDED, old if kind == "R" else None))
            continue
        path = tokens[i + 1]
        i += 2
        files.append(ChangedFile(path, {"A": FileStatus.ADDED, "D": FileStatus.DELETED}.get(kind, FileStatus.MODIFIED)))
    return files


def _untracked(repo: Path, already: set[str]) -> list[ChangedFile]:
    out = gitio.run_git(repo, ["ls-files", "-o", "--exclude-standard", "-z"])
    return [ChangedFile(p, FileStatus.ADDED) for p in out.split("\0") if p and p not in already]


# --- added-line source for the hygiene scan ---------------------------------------------------

_HUNK_RE = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@")


def added_lines(repo: Path, changes: ChangeSet) -> tuple[list[ScanLine], bool]:
    """Lines ADDED by the comparison (or every line of tracked text files for an all-tracked set).

    Returns ``(lines, truncated)``.  Only added lines are scanned so pre-existing content never
    makes an unrelated change fail.
    """
    lines: list[ScanLine] = []
    if changes.strategy == STRATEGY_ALL_TRACKED:
        for changed in changes.files:
            lines.extend(_read_file_lines(repo, changed.path))
            if len(lines) > MAX_SCAN_LINES:
                return lines[:MAX_SCAN_LINES], True
        return lines, False
    args = ["diff", "-U0", "--no-color", "--no-ext-diff", "-M", changes.compare_from_sha or ""]
    if not changes.working_tree:
        args.append(changes.head_sha)
    out = gitio.run_git(repo, args)
    path = None
    lineno = 0
    for raw in out.split("\n"):
        if raw.startswith("+++ "):
            target = raw[4:].split("\t")[0]
            path = None if target == "/dev/null" else (target[2:] if target.startswith("b/") else target)
        elif raw.startswith("@@"):
            m = _HUNK_RE.match(raw)
            lineno = int(m.group(1)) if m else 0
        elif raw.startswith("+") and not raw.startswith("+++") and path:
            lines.append(ScanLine(path, lineno, raw[1:]))
            lineno += 1
            if len(lines) > MAX_SCAN_LINES:
                return lines[:MAX_SCAN_LINES], True
    if changes.working_tree:  # untracked files are wholly "added"
        for changed in changes.files:
            if changed.status == FileStatus.ADDED and not _tracked_in_diff(out, changed.path):
                lines.extend(_read_file_lines(repo, changed.path))
    return lines[:MAX_SCAN_LINES], len(lines) > MAX_SCAN_LINES


def _tracked_in_diff(diff_output: str, path: str) -> bool:
    return f"+++ b/{path}" in diff_output


def _read_file_lines(repo: Path, path: str) -> list[ScanLine]:
    target = (repo / path)
    try:
        if not target.is_file() or target.is_symlink() or target.stat().st_size > MAX_SCAN_FILE_BYTES:
            return []
        data = target.read_bytes()
    except OSError:
        return []
    if b"\0" in data[:4096]:  # binary
        return []
    return [ScanLine(path, n, text) for n, text in enumerate(data.decode("utf-8", errors="replace").split("\n"), start=1)]
