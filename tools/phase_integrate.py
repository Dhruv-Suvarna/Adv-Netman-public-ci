#!/usr/bin/env python3
"""Phase integration helper: the repetitive Git / GitHub source-integration workflow, automated safely.

    python tools/phase_integrate.py start   --phase 19 --slug golden-probation-bundles
    python tools/phase_integrate.py prepare --phase 19 --message "Phase 19: ..."
    python tools/phase_integrate.py status
    python tools/phase_integrate.py merge

One-time adoption of work that already exists uncommitted on main:

    python tools/phase_integrate.py prepare --phase 18 --slug raw-configlets --message "..." --adopt-working-tree

This is SOURCE-CONTROL tooling only.  It runs git, the GitHub CLI and the repository's own local
Tier-3 validator (``tier3.py``).  Nothing here touches a device, NetBox or the lab.  Every command it
may ever run passes through ``classify_argv`` below: a fixed allowlist of argument shapes, so a bug
here cannot stage everything, force-push, reset, stash or merge by any method but the one approved.
See docs/PHASE_INTEGRATION_WORKFLOW.md.

Exit status: 0 success | 1 blocked (a safety refusal or a failed gate) | 2 usage | 3 a git/gh command failed.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shlex
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Sequence

# --- project policy (small, deliberate, centralised) ------------------------------------------------

BASE_BRANCH = "main"
REMOTE = "origin"
BRANCH_PREFIX = "phase"
# The ONLY paths permitted to stay dirty.  Exact paths, never a glob: future expansion is a deliberate edit.
RUNTIME_ARTIFACTS: tuple[str, ...] = ("Run_Logs.log", "logs/R2.log")
TIER3_LAUNCHER = "tier3.py"
# Identity of the hosted required check (.github/workflows/tier3-validation.yml: workflow name and job name).
TIER3_WORKFLOW_NAME = "Tier-3 validation"
TIER3_CHECK_NAME = "Tier-3 validation"
TIER3_TIMEOUT_SECONDS = 3600
GIT_TIMEOUT_SECONDS = 120
NETWORK_TIMEOUT_SECONDS = 180
MAX_CANDIDATE_BYTES = 5 * 1024 * 1024

PHASE_RE = re.compile(r"[1-9][0-9]{0,2}(?:\.[1-9][0-9]{0,2})?")
SLUG_RE = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*")
BRANCH_RE = re.compile(
    rf"{BRANCH_PREFIX}([1-9][0-9]{{0,2}}(?:\.[1-9][0-9]{{0,2}})?)-([a-z0-9]+(?:-[a-z0-9]+)*)"
)
SHA_RE = re.compile(r"[0-9a-f]{40}")
TRAILER_RE = re.compile(r"[A-Za-z][A-Za-z0-9-]*: \S.*")
MAX_SLUG = 60

EXIT_OK, EXIT_BLOCKED, EXIT_USAGE, EXIT_COMMAND_FAILED = 0, 1, 2, 3


class Blocked(Exception):
    """A safety refusal or a failed gate.  Nothing irreversible has happened past what the message says."""

    def __init__(self, code: str, message: str, details: Sequence[str] = ()):
        super().__init__(message)
        self.code, self.message, self.details = code, message, list(details)


class UsageError(Exception):
    pass


class UnsafeCommand(Exception):
    """A programming error: this tool tried to run a command outside its own allowlist."""


class CommandFailed(Exception):
    def __init__(self, proc: "Proc"):
        super().__init__(f"command failed ({proc.returncode}): {shlex.join(proc.argv)}")
        self.proc = proc


# --- validated names ---------------------------------------------------------------------------------

PhaseId = int | str


def validate_phase(value) -> PhaseId:
    text = str(value)
    if not PHASE_RE.fullmatch(text):
        raise UsageError(
            f"invalid phase {value!r}: expected N or N.M without leading zeros (each component 1-999)"
        )
    return text if "." in text else int(text)


def validate_slug(value: str) -> str:
    if not isinstance(value, str) or len(value) > MAX_SLUG or not SLUG_RE.fullmatch(value):
        raise UsageError(f"invalid slug {value!r}: lowercase letters, digits and single hyphens only, starting with a letter or digit, at most {MAX_SLUG} characters")
    return value


def branch_name(phase: PhaseId, slug: str) -> str:
    return f"{BRANCH_PREFIX}{validate_phase(phase)}-{validate_slug(slug)}"


def parse_branch(name: str) -> tuple[PhaseId, str] | None:
    match = BRANCH_RE.fullmatch(name or "")
    return (validate_phase(match.group(1)), match.group(2)) if match else None


# --- command execution: allowlist policy + one subprocess wrapper -----------------------------------

READ, MUTATE, VALIDATE = "read", "mutate", "validate"
GIT_GLOBAL_OPTIONS = ("--no-pager", "--literal-pathspecs")
GIT_READ_VERBS = frozenset({"status", "rev-parse", "rev-list", "show-ref", "ls-remote", "diff", "log", "merge-base", "cat-file"})


@dataclass(frozen=True)
class Proc:
    argv: tuple[str, ...]
    returncode: int | None
    stdout: str = ""
    stderr: str = ""
    timed_out: bool = False

    @property
    def ok(self) -> bool:
        return self.returncode == 0 and not self.timed_out


Runner = Callable[..., Proc]


def classify_argv(argv: Sequence[str], repo: Path) -> str:
    """READ, MUTATE or VALIDATE for an allowed argv; raise ``UnsafeCommand`` for anything else.

    Deliberately narrow: ``git add`` takes exactly one explicit non-runtime path, ``git commit`` only
    ``-m`` / ``--trailer``, ``git push`` only ``-u origin <phase branch>``, ``gh pr merge`` only
    ``--merge --match-head-commit``.  There is no way to express add-all, commit-all, force,
    reset, clean, stash, squash, rebase, auto-merge or branch deletion.
    """
    argv = [str(a) for a in argv]
    if not argv:
        raise UnsafeCommand("empty command")
    if argv[0] == "git":
        return _classify_git(argv[1:])
    if argv[0] == "gh":
        return _classify_gh(argv[1:])
    if argv[0] == sys.executable and len(argv) >= 2 and argv[1] == str(repo / TIER3_LAUNCHER):
        return _classify_tier3(argv[2:])
    raise UnsafeCommand(f"executable not allowed: {argv[0]!r}")


def _classify_git(args: list[str]) -> str:
    while args and args[0] in GIT_GLOBAL_OPTIONS:
        args = args[1:]
    if not args:
        raise UnsafeCommand("git without a verb")
    verb, rest = args[0], args[1:]
    if verb in GIT_READ_VERBS:
        return READ
    if verb == "branch" and rest == ["--show-current"]:
        return READ
    if verb == "add" and len(rest) == 2 and rest[0] == "--" and _stageable_path(rest[1]):
        return MUTATE
    if verb == "restore" and len(rest) == 3 and rest[:2] == ["--staged", "--"] and _stageable_path(rest[2]):
        return MUTATE
    if verb == "switch" and (
        (len(rest) == 2 and rest[0] == "-c" and BRANCH_RE.fullmatch(rest[1])) or rest == [BASE_BRANCH]
    ):
        return MUTATE
    if verb == "commit" and _commit_shape(rest):
        return MUTATE
    if verb == "push" and len(rest) == 3 and rest[:2] == ["-u", REMOTE] and BRANCH_RE.fullmatch(rest[2]):
        return MUTATE
    if verb == "pull" and rest == ["--ff-only", REMOTE, BASE_BRANCH]:
        return MUTATE
    raise UnsafeCommand(f"git command not allowed: git {' '.join([verb, *rest])[:80]}")


def _stageable_path(path: str) -> bool:
    parts = path.split("/")
    return bool(path) and path not in RUNTIME_ARTIFACTS and not path.startswith("/") and "" not in parts and "." not in parts and ".." not in parts


def _commit_shape(rest: list[str]) -> bool:
    if len(rest) < 2 or rest[0] != "-m" or not rest[1].strip():
        return False
    tail = rest[2:]
    return len(tail) % 2 == 0 and all(tail[i] == "--trailer" and TRAILER_RE.fullmatch(tail[i + 1]) for i in range(0, len(tail), 2))


def _classify_gh(args: list[str]) -> str:
    if args == ["--version"] or args == ["auth", "status"]:
        return READ
    if args[:2] in (["pr", "list"], ["pr", "view"]):
        return READ
    if args[:2] == ["pr", "create"] and _gh_create_shape(args[2:]):
        return MUTATE
    if args[:2] == ["pr", "merge"] and len(args) == 6 and args[2].isdigit() and args[3] == "--merge" and args[4] == "--match-head-commit" and SHA_RE.fullmatch(args[5]):
        return MUTATE
    raise UnsafeCommand(f"gh command not allowed: gh {' '.join(args)[:80]}")


def _gh_create_shape(rest: list[str]) -> bool:
    if len(rest) != 8:
        return False
    given = {rest[i]: rest[i + 1] for i in range(0, 8, 2)}
    return (
        set(given) == {"--base", "--head", "--title", "--body"}
        and given["--base"] == BASE_BRANCH and bool(BRANCH_RE.fullmatch(given["--head"])) and bool(given["--title"].strip())
    )


def _classify_tier3(rest: list[str]) -> str:
    allowed_flags = {"--working-tree"}
    allowed_pairs = {("--base", BASE_BRANCH), ("--mode", "full"), ("--format", "json")}
    i = 0
    while i < len(rest):
        if rest[i] in allowed_flags:
            i += 1
        elif i + 1 < len(rest) and (rest[i], rest[i + 1]) in allowed_pairs:
            i += 2
        else:
            raise UnsafeCommand(f"tier3 argument not allowed: {rest[i]!r}")
    return VALIDATE


_ENV_OVERRIDES = {"GIT_TERMINAL_PROMPT": "0", "GIT_OPTIONAL_LOCKS": "0", "GH_PROMPT_DISABLED": "1", "GH_NO_UPDATE_NOTIFIER": "1", "NO_COLOR": "1", "GH_PAGER": "cat", "PAGER": "cat"}


def subprocess_runner(argv: Sequence[str], *, cwd: Path, timeout: int, stream_stderr: bool = False) -> Proc:
    env = dict(os.environ)
    env.update(_ENV_OVERRIDES)
    try:
        done = subprocess.run(  # noqa: S603 - argv list from classify_argv, shell=False, no prompts
            list(argv), cwd=str(cwd), env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=None if stream_stderr else subprocess.PIPE, text=True, errors="replace", timeout=timeout, shell=False,
        )
    except subprocess.TimeoutExpired as exc:
        return Proc(tuple(argv), None, _text(exc.stdout), _text(exc.stderr), timed_out=True)
    except OSError as exc:
        return Proc(tuple(argv), None, "", f"{type(exc).__name__}: cannot start {argv[0]!r}")
    return Proc(tuple(argv), done.returncode, done.stdout or "", done.stderr or "")


def _text(value) -> str:
    return value.decode("utf-8", "replace") if isinstance(value, bytes) else (value or "")


class Shell:
    """Every external command goes through ``run``: allowlist first, then dry-run gate, then the runner."""

    def __init__(self, repo: Path, runner: Runner = subprocess_runner, *, dry_run: bool = False):
        self.repo, self.runner, self.dry_run = repo, runner, dry_run
        self.would_run: list[tuple[str, ...]] = []

    def run(self, argv: Sequence[str], *, check: bool = True, timeout: int = GIT_TIMEOUT_SECONDS, stream_stderr: bool = False) -> Proc:
        argv = tuple(str(a) for a in argv)
        kind = classify_argv(argv, self.repo)
        if self.dry_run and kind != READ:  # defence in depth: a dry run can never mutate, whatever the caller forgot
            self.would_run.append(argv)
            return Proc(argv, 0)
        proc = self.runner(argv, cwd=self.repo, timeout=timeout, stream_stderr=stream_stderr)
        if check and not proc.ok:
            raise CommandFailed(proc)
        return proc

    def git(self, *args: str, check: bool = True, timeout: int = GIT_TIMEOUT_SECONDS) -> Proc:
        return self.run(["git", *GIT_GLOBAL_OPTIONS, *args], check=check, timeout=timeout)

    def gh(self, *args: str, check: bool = True) -> Proc:
        return self.run(["gh", *args], check=check, timeout=NETWORK_TIMEOUT_SECONDS)


# --- working tree model -----------------------------------------------------------------------------

@dataclass(frozen=True)
class Entry:
    xy: str
    path: str

    @property
    def staged(self) -> bool:
        return self.xy[0] not in " ?!"

    @property
    def untracked(self) -> bool:
        return self.xy == "??"

    @property
    def deleted(self) -> bool:
        return "D" in self.xy

    @property
    def unmerged(self) -> bool:
        return self.xy in {"DD", "AU", "UD", "UA", "DU", "AA", "UU"}


def parse_status(raw: str) -> list[Entry]:
    """Parse ``git status --porcelain=v1 -z --no-renames`` (NUL-terminated ``XY path`` records)."""
    entries: list[Entry] = []
    for token in raw.split("\0"):
        if len(token) > 3 and token[2] == " ":
            entries.append(Entry(token[:2], token[3:]))
    return entries


@dataclass(frozen=True)
class WorkingTree:
    entries: tuple[Entry, ...]

    @property
    def staged(self) -> list[Entry]:
        return [e for e in self.entries if e.staged or e.unmerged]

    @property
    def runtime(self) -> list[str]:
        return sorted(e.path for e in self.entries if e.path in RUNTIME_ARTIFACTS)

    @property
    def candidates(self) -> list[Entry]:
        """Source paths: everything dirty that is not one of the exact permitted runtime artifacts."""
        return sorted((e for e in self.entries if e.path not in RUNTIME_ARTIFACTS and not e.staged and not e.unmerged), key=lambda e: e.path)

    def signature(self) -> tuple[tuple[str, str], ...]:
        return tuple(sorted((e.xy, e.path) for e in self.entries))


# --- conservative suspicious-path gate ---------------------------------------------------------------

_BLOCKED_DIRS = frozenset({".venv", "venv", "virtualenv", "node_modules", ".git", "__pycache__", ".tox", ".mypy_cache", ".pytest_cache"})
_EXACT_NAMES = {
    "id_rsa": "private key", "id_dsa": "private key", "id_ecdsa": "private key", "id_ed25519": "private key", "pyvenv.cfg": "Python virtual environment",
    ".netrc": "credential file", ".pgpass": "credential file", ".htpasswd": "credential file", ".git-credentials": "credential file",
    "credentials": "credential file", "credentials.json": "credential file", ".ds_store": "editor / OS temporary file",
}
_SUFFIX_REASONS = (
    ((".pem", ".key", ".p12", ".pfx", ".jks", ".ppk", ".keystore", ".kdbx"), "key / certificate store"),
    ((".sqlite", ".sqlite3", ".db", ".sql", ".dump", ".mdb"), "database file or dump"),
    ((".zip", ".tar", ".tgz", ".gz", ".bz2", ".xz", ".7z", ".rar", ".jar", ".whl", ".deb", ".iso", ".img"), "generated archive / binary bundle"),
    ((".swp", ".swo", ".swn", ".orig", ".rej", ".bak", ".tmp", "~", ".sock"), "editor swap / temporary file or socket"),
)


def suspicious_reason(path: str, *, size: int | None = None, symlink: bool = False) -> str | None:
    """Why a candidate must not be staged automatically (None = acceptable).  Path/name based: file CONTENT is
    scanned by the repository's own Tier-3 ``static.hygiene`` check, which prepare runs before committing."""
    if path.endswith("/"):
        return "directory entry (nested repository?)"
    parts = path.split("/")
    name = parts[-1].lower()
    if symlink:
        return "symbolic link"
    for segment in parts[:-1]:
        if segment in _BLOCKED_DIRS:
            return f"inside {segment}/ (environment / VCS / cache directory)"
    if path.startswith("monitoring/runtime/") and path != "monitoring/runtime/.gitkeep":
        return "monitoring/runtime holds runtime secrets"
    if name == ".env" or (name.startswith(".env.") and name != ".env.example"):
        return "environment / credential file"
    if re.fullmatch(r"secrets?\.[a-z]+", name):
        return "credential file"
    if name in _EXACT_NAMES:
        return _EXACT_NAMES[name]
    if (name.startswith("#") and name.endswith("#")) or name.startswith(".#"):
        return "editor swap / temporary file"
    if name.endswith(".log") or parts[0] == "logs":
        return "unexpected runtime log (only the exact permitted runtime artifacts may stay dirty)"
    if "docker.sock" in name:
        return "Docker socket reference"
    for suffixes, reason in _SUFFIX_REASONS:
        if name.endswith(suffixes):
            return reason
    if size is not None and size > MAX_CANDIDATE_BYTES:
        return f"large file ({size // (1024 * 1024)} MiB)"
    return None


# --- hosted check / PR evaluation (pure) -------------------------------------------------------------

_PENDING_RUN_STATUS = {"QUEUED", "IN_PROGRESS", "WAITING", "PENDING", "REQUESTED"}
_STATE_PRECEDENCE = ("FAILURE", "TIMED_OUT", "CANCELLED", "ACTION_REQUIRED", "UNKNOWN", "SKIPPED", "NEUTRAL", "PENDING", "SUCCESS")
_OK_FOR_OTHER_CHECKS = {"SUCCESS", "NEUTRAL", "SKIPPED"}
_MERGE_OK_STATES = {"CLEAN", "HAS_HOOKS"}


def normalize_check(entry: dict) -> dict:
    """One rollup item -> ``{name, workflow, state}`` with state in SUCCESS|PENDING|FAILURE|CANCELLED|SKIPPED|TIMED_OUT|ACTION_REQUIRED|NEUTRAL|UNKNOWN."""
    if entry.get("__typename") == "StatusContext":
        state = {"SUCCESS": "SUCCESS", "PENDING": "PENDING", "EXPECTED": "PENDING", "FAILURE": "FAILURE", "ERROR": "FAILURE"}.get(str(entry.get("state", "")).upper(), "UNKNOWN")
        return {"name": entry.get("context", ""), "workflow": "", "state": state}
    if str(entry.get("status", "")).upper() != "COMPLETED":
        state = "PENDING" if str(entry.get("status", "")).upper() in _PENDING_RUN_STATUS else "UNKNOWN"
    else:
        state = {"SUCCESS": "SUCCESS", "FAILURE": "FAILURE", "STARTUP_FAILURE": "FAILURE", "CANCELLED": "CANCELLED", "SKIPPED": "SKIPPED",
                 "TIMED_OUT": "TIMED_OUT", "ACTION_REQUIRED": "ACTION_REQUIRED", "NEUTRAL": "NEUTRAL"}.get(str(entry.get("conclusion", "")).upper(), "UNKNOWN")
    return {"name": entry.get("name", ""), "workflow": entry.get("workflowName", ""), "state": state}


def tier3_state(checks: list[dict]) -> str:
    """The required hosted check: ``MISSING`` if not reported yet, otherwise the WORST state among its runs."""
    mine = [c["state"] for c in checks if c["name"] == TIER3_CHECK_NAME and c["workflow"] == TIER3_WORKFLOW_NAME]
    if not mine:
        return "MISSING"
    return next(state for state in _STATE_PRECEDENCE if state in mine)


@dataclass
class Evaluation:
    tier3: str = "MISSING"
    checks: list[dict] = field(default_factory=list)
    blockers: list[str] = field(default_factory=list)  # hard: merge is refused and will not become allowed by waiting
    waiting: list[str] = field(default_factory=list)   # soft: not yet, re-check later
    @property
    def merge_allowed(self) -> bool:
        return not self.blockers and not self.waiting


def evaluate_pr(pr: dict, *, branch: str, local_sha: str | None, remote_sha: str | None, tree: WorkingTree | None) -> Evaluation:
    """Every condition ``merge`` requires, as data.  ``status`` prints it; ``merge`` refuses unless ``merge_allowed``."""
    ev = Evaluation()
    if pr.get("state") != "OPEN":
        ev.blockers.append(f"PR_NOT_OPEN: state is {pr.get('state')}")
        return ev
    if pr.get("baseRefName") != BASE_BRANCH:
        ev.blockers.append(f"BASE_MISMATCH: PR base is {pr.get('baseRefName')!r}, expected {BASE_BRANCH!r}")
    if pr.get("headRefName") != branch:
        ev.blockers.append(f"HEAD_MISMATCH: PR head is {pr.get('headRefName')!r}, expected {branch!r}")
    if pr.get("isCrossRepository"):
        ev.blockers.append("CROSS_REPOSITORY: the PR head is in another repository")
    if pr.get("isDraft"):
        ev.blockers.append("DRAFT: the PR is a draft")
    head_sha = pr.get("headRefOid")
    if local_sha is None:
        ev.blockers.append(f"LOCAL_BRANCH_MISSING: no local branch {branch}; the expected phase commit cannot be verified")
    if remote_sha is None:
        ev.blockers.append(f"REMOTE_BRANCH_MISSING: {REMOTE}/{branch} not found")
    if not SHA_RE.fullmatch(head_sha or "") or not (head_sha == local_sha == remote_sha):
        if local_sha is not None and remote_sha is not None:
            ev.blockers.append(f"SHA_MISMATCH: PR head {(head_sha or '-')[:12]}, local {(local_sha or '-')[:12]}, remote {(remote_sha or '-')[:12]}")

    ev.checks = [normalize_check(item) for item in pr.get("statusCheckRollup") or []]
    ev.tier3 = tier3_state(ev.checks)
    if ev.tier3 in ("PENDING", "MISSING"):
        ev.waiting.append(f"TIER3_{ev.tier3}: required hosted check '{TIER3_CHECK_NAME}' " + ("has not reported yet" if ev.tier3 == "MISSING" else "is still running"))
    elif ev.tier3 != "SUCCESS":
        ev.blockers.append(f"TIER3_{ev.tier3}: required hosted check '{TIER3_CHECK_NAME}' did not succeed")
    for check in ev.checks:
        if check["name"] == TIER3_CHECK_NAME and check["workflow"] == TIER3_WORKFLOW_NAME:
            continue
        if check["state"] == "PENDING":
            ev.waiting.append(f"CHECK_PENDING: {check['name']}")
        elif check["state"] not in _OK_FOR_OTHER_CHECKS:
            ev.blockers.append(f"CHECK_{check['state']}: {check['name']}")

    mergeable, merge_state = str(pr.get("mergeable", "UNKNOWN")).upper(), str(pr.get("mergeStateStatus", "UNKNOWN")).upper()
    if mergeable == "CONFLICTING":
        ev.blockers.append("NOT_MERGEABLE: GitHub reports merge conflicts")
    elif mergeable != "MERGEABLE":
        ev.waiting.append(f"MERGEABLE_UNKNOWN: GitHub reports mergeable={mergeable}")
    if merge_state == "UNKNOWN":
        ev.waiting.append("MERGE_STATE_UNKNOWN: GitHub has not computed the merge state yet")
    elif merge_state not in _MERGE_OK_STATES and not (merge_state in ("BLOCKED", "UNSTABLE") and (ev.waiting or ev.blockers)):
        ev.blockers.append(f"MERGE_STATE_{merge_state}: GitHub does not consider the PR cleanly mergeable")

    if tree is not None:
        if tree.staged:
            ev.blockers.append(f"STAGED_CHANGES: {len(tree.staged)} staged path(s)")
        if tree.candidates:
            ev.blockers.append(f"SOURCE_MODIFIED: {len(tree.candidates)} source path(s) changed after prepare: " + ", ".join(e.path for e in tree.candidates[:5]))
    return ev


# --- output -----------------------------------------------------------------------------------------

def short(sha: str | None) -> str:
    return sha[:7] if sha else "-"


class Reporter:
    """Human lines go to stdout, or to stderr when ``--json`` reserves stdout for the one JSON document."""

    def __init__(self, json_mode: bool = False, out=None, err=None):
        self.json_mode = json_mode
        self.out, self.err = out or sys.stdout, err or sys.stderr
        self.doc: dict = {}

    def line(self, text: str = "") -> None:
        print(text, file=self.err if self.json_mode else self.out)

    def kv(self, key: str, value) -> None:
        self.line(f"  {key:<15} {value}")

    def items(self, header: str, values: Sequence[str], limit: int = 12) -> None:
        self.line(f"  {header}:")
        for value in list(values)[:limit]:
            self.line(f"    {value}")
        if len(values) > limit:
            self.line(f"    ... and {len(values) - limit} more")

    def finish(self, result: str, *, show: bool = True, **fields) -> None:
        self.doc.update(fields)
        self.doc["result"] = result
        if self.json_mode:
            print(json.dumps(self.doc, indent=2, sort_keys=True), file=self.out)
        elif show:
            self.line(result)


# --- the integrator ---------------------------------------------------------------------------------

PR_LIST_FIELDS = "number,url,title,state,headRefName,baseRefName,headRefOid,isDraft,isCrossRepository,mergedAt"
PR_VIEW_FIELDS = PR_LIST_FIELDS + ",mergeable,mergeStateStatus,mergeCommit,statusCheckRollup"


class Integrator:
    def __init__(self, sh: Shell, rep: Reporter, *, sleep: Callable[[float], None] = time.sleep):
        self.sh, self.rep, self.sleep = sh, rep, sleep

    # ---- git reads ----
    def current_branch(self) -> str:
        name = self.sh.git("branch", "--show-current").stdout.strip()
        if not name:
            raise Blocked("DETACHED_HEAD", "HEAD is detached; switch to a branch first")
        return name

    def rev(self, ref: str) -> str | None:
        proc = self.sh.git("rev-parse", "--verify", "--quiet", f"{ref}^{{commit}}", check=False)
        return proc.stdout.strip() if proc.ok and SHA_RE.fullmatch(proc.stdout.strip()) else None

    def remote_head(self, branch: str) -> str | None:
        out = self.sh.run(["git", *GIT_GLOBAL_OPTIONS, "ls-remote", "--heads", REMOTE, f"refs/heads/{branch}"], timeout=NETWORK_TIMEOUT_SECONDS).stdout.split()
        return out[0] if out and SHA_RE.fullmatch(out[0]) else None

    def local_branch_exists(self, branch: str) -> bool:
        return self.sh.git("show-ref", "--verify", "--quiet", f"refs/heads/{branch}", check=False).ok

    def has_commit(self, sha: str) -> bool:
        return self.sh.git("cat-file", "-e", f"{sha}^{{commit}}", check=False).ok

    def is_ancestor(self, older: str, newer: str) -> bool:
        return self.sh.git("merge-base", "--is-ancestor", older, newer, check=False).ok

    def working_tree(self) -> WorkingTree:
        raw = self.sh.git("status", "--porcelain=v1", "-z", "--untracked-files=all", "--no-renames").stdout
        return WorkingTree(tuple(parse_status(raw)))

    # ---- shared preconditions ----
    def require_no_staged(self, tree: WorkingTree) -> None:
        if tree.staged:
            raise Blocked("STAGED_CHANGES", "staged (or unmerged) changes exist; this tool starts from an empty index and never unstages your work",
                          [f"{e.xy} {e.path}" for e in tree.staged[:10]])

    def require_base_in_sync(self) -> str:
        """Local main must equal origin/main.  Nothing is fetched, merged, rebased or reset: this only compares."""
        local, remote = self.rev(BASE_BRANCH), self.remote_head(BASE_BRANCH)
        if local is None:
            raise Blocked("BASE_MISSING", f"local branch {BASE_BRANCH} does not exist")
        if remote is None:
            raise Blocked("REMOTE_BASE_MISSING", f"{REMOTE}/{BASE_BRANCH} was not found on the remote")
        if local != remote:
            if not self.has_commit(remote):
                why = f"local {BASE_BRANCH} ({short(local)}) is behind {REMOTE}/{BASE_BRANCH} ({short(remote)})"
            elif self.is_ancestor(remote, local):
                why = f"local {BASE_BRANCH} ({short(local)}) is ahead of {REMOTE}/{BASE_BRANCH} ({short(remote)})"
            else:
                why = f"local {BASE_BRANCH} ({short(local)}) and {REMOTE}/{BASE_BRANCH} ({short(remote)}) have diverged"
            raise Blocked("BASE_OUT_OF_SYNC", why, [f"reconcile manually (for example: git pull --ff-only {REMOTE} {BASE_BRANCH}); this tool never merges, rebases or resets"])
        return local

    def require_branch_free(self, branch: str) -> None:
        if self.local_branch_exists(branch):
            raise Blocked("BRANCH_EXISTS", f"branch {branch} already exists locally",
                          [f"to continue that work: git switch {branch}, then run prepare (without --adopt-working-tree)"])
        if self.remote_head(branch) is not None:
            raise Blocked("BRANCH_EXISTS_REMOTE", f"branch {branch} already exists on {REMOTE}", ["fetch and inspect it; this tool will not overwrite or reuse it silently"])

    # ---- start ----
    def start(self, phase: PhaseId, slug: str) -> int:
        branch = branch_name(phase, slug)
        self.rep.line(f"[start] phase {phase}  ->  {branch}")
        current = self.current_branch()
        if current != BASE_BRANCH:
            raise Blocked("WRONG_BRANCH", f"start must run on {BASE_BRANCH} (currently on {current})")
        tree = self.working_tree()
        self.require_no_staged(tree)
        if tree.candidates:
            raise Blocked("SOURCE_DIRTY", "source files are already modified; start needs a clean tree apart from the permitted runtime artifacts",
                          [f"{e.xy} {e.path}" for e in tree.candidates[:10]])
        base_head = self.require_base_in_sync()
        self.require_branch_free(branch)
        self.rep.kv("base branch", BASE_BRANCH)
        self.rep.kv("base HEAD", base_head)
        self.rep.kv("phase branch", branch)
        self.rep.kv("dirty runtime", ", ".join(tree.runtime) or "(none)")
        self.rep.kv("allowed dirty", ", ".join(RUNTIME_ARTIFACTS))
        if self.sh.dry_run:
            self.rep.line("  DRY RUN: would run: git switch -c " + branch + " (nothing created, nothing pushed)")
            self.rep.finish("DRY_RUN", command="start", phase=phase, branch=branch, base_head=base_head, dry_run=True)
            return EXIT_OK
        self.sh.git("switch", "-c", branch)
        if self.current_branch() != branch or self.working_tree().signature() != tree.signature():
            raise Blocked("START_VERIFY_FAILED", "the branch was created but the working tree is not as expected", ["inspect: git status"])
        self.rep.line("  branch created; nothing committed, nothing pushed")
        self.rep.finish("READY", command="start", phase=phase, branch=branch, base_head=base_head, dry_run=False)
        return EXIT_OK

    # ---- prepare ----
    def prepare(self, a: argparse.Namespace) -> int:
        phase = validate_phase(a.phase)
        current = self.current_branch()
        adopt = bool(a.adopt_working_tree)
        if adopt:
            if not a.slug:
                raise UsageError("--adopt-working-tree needs an explicit --slug")
            if current != BASE_BRANCH:
                raise Blocked("WRONG_BRANCH", f"--adopt-working-tree adopts work from {BASE_BRANCH} (currently on {current})")
            branch = branch_name(phase, a.slug)
        else:
            parsed = parse_branch(current)
            if parsed is None:
                raise Blocked("WRONG_BRANCH", f"not on a phase branch ({current}); run 'start', or pass --adopt-working-tree --slug for work already made on {BASE_BRANCH}")
            if parsed[0] != phase or (a.slug and validate_slug(a.slug) != parsed[1]):
                raise Blocked("BRANCH_MISMATCH", f"current branch {current} does not match --phase {phase}" + (f" --slug {a.slug}" if a.slug else ""))
            branch = current
        message = (a.message or "").strip()
        self.rep.line(f"[prepare] phase {phase}  branch {branch}" + ("  (adopting the working tree from " + BASE_BRANCH + ")" if adopt else ""))

        tree = self.working_tree()
        self.require_no_staged(tree)
        candidates = tree.candidates
        base_head = self.require_base_in_sync() if adopt else (self.rev(BASE_BRANCH) or "")
        if adopt:
            self.require_branch_free(branch)
        ahead = 0 if adopt else int(self.sh.git("rev-list", "--count", f"{BASE_BRANCH}..HEAD").stdout.strip() or 0)
        if not candidates and ahead == 0:
            raise Blocked("NO_SOURCE_CHANGES", "there are no source changes to integrate" + (" (only permitted runtime artifacts are dirty)" if tree.runtime else ""))

        self.rep.kv("base", f"{BASE_BRANCH} @ {short(base_head)}")
        self.rep.kv("dirty runtime", ", ".join(tree.runtime) or "(none)")
        self.rep.kv("excluded", ", ".join(RUNTIME_ARTIFACTS) + "  (never staged)")
        self.rep.items(f"source candidates ({len(candidates)})", [f"{e.xy} {e.path}" for e in candidates])
        self.check_gh_ready()

        validation: dict = {"result": "NOT_RUN_THIS_INVOCATION", "mode": None}
        phase_sha = self.rev("HEAD")
        if candidates:
            self.gate_suspicious(candidates)
            if not message:
                raise UsageError("--message is required when there are source changes to commit")
            self.check_source_diff(candidates)
            argv = self.tier3_argv(full=a.full)
            if self.sh.dry_run:
                return self.dry_run_plan(phase, branch, adopt, base_head, candidates, argv, message, a)
            validation = self.run_validation(argv, full=a.full)
            if adopt:
                self.sh.git("switch", "-c", branch)
                if self.current_branch() != branch or self.working_tree().signature() != tree.signature():
                    raise Blocked("ADOPT_VERIFY_FAILED", "the phase branch was created but the working tree differs from before; nothing was staged", ["inspect: git status"])
                self.rep.line(f"  adopted: created {branch} from {BASE_BRANCH}; working tree preserved")
            phase_sha = self.stage_and_commit(candidates, message, a.trailer or [])
        else:
            self.rep.line(f"  no uncommitted source changes; {ahead} commit(s) already on {branch}: resuming at push / PR")
            if self.sh.dry_run:
                return self.dry_run_plan(phase, branch, adopt, base_head, [], self.tier3_argv(full=a.full), message, a)

        self.push(branch, phase_sha)
        merge_base = self.sh.git("merge-base", BASE_BRANCH, "HEAD").stdout.strip() or base_head
        title = (a.pr_title or message or self.sh.git("log", "-1", "--format=%s").stdout.strip()).splitlines()[0]
        pr, created = self.ensure_pr(branch, phase, title, merge_base, phase_sha, validation, a.pr_footer)
        state = self.hosted_state(pr["number"], branch)
        result = "PR_CREATED" if created else "PR_REUSED"
        self.rep.line(f"  PR #{pr['number']}  {pr['url']}")
        self.rep.line(f"  hosted validation: {state['label']}  (Tier-3: {state['tier3']})")
        self.rep.line("  NOT merged: run 'python tools/phase_integrate.py status', then 'merge' once Tier-3 is green")
        self.rep.finish(result, command="prepare", phase=phase, branch=branch, base_head=merge_base, phase_head=phase_sha, pr_number=pr["number"], pr_url=pr["url"],
                        checks=state["checks"], tier3=state["tier3"], merge_allowed=state["merge_allowed"], hosted_state=state["label"], validation=validation, dry_run=False)
        return EXIT_OK

    def check_gh_ready(self) -> None:
        if not self.sh.gh("--version", check=False).ok:
            raise Blocked("GH_MISSING", "the GitHub CLI (gh) is not available", ["install gh; this tool does not implement its own GitHub client"])
        if not self.sh.gh("auth", "status", check=False).ok:
            raise Blocked("GH_UNAUTHENTICATED", "the GitHub CLI is not authenticated", ["run: gh auth login  (this tool never handles tokens); nothing was committed or pushed"])

    def gate_suspicious(self, candidates: list[Entry]) -> None:
        problems = []
        for entry in candidates:
            if entry.deleted:
                continue
            target = self.sh.repo / entry.path
            try:
                info = os.lstat(target)
                size, symlink = info.st_size, target.is_symlink()
            except OSError:
                size, symlink = None, False
            reason = suspicious_reason(entry.path, size=size, symlink=symlink)
            if reason:
                problems.append(f"{entry.path}: {reason}")
        if problems:
            raise Blocked("SUSPICIOUS_FILES", f"{len(problems)} path(s) look unsafe to commit; nothing was staged and nothing was deleted", problems[:20])

    def check_source_diff(self, candidates: list[Entry]) -> None:
        """``git diff --check`` scoped to the intended SOURCE paths (the runtime logs are not evaluated)."""
        tracked = [e.path for e in candidates if not e.untracked]
        kinds = ["untracked" if e.untracked else ("deleted" if e.deleted else "modified") for e in candidates]
        self.rep.line("  source diff: " + ", ".join(f"{kinds.count(k)} {k}" for k in sorted(set(kinds))))
        if not tracked:
            return
        proc = self.sh.git("diff", "--check", "--", *tracked, check=False)
        if proc.returncode != 0:
            raise Blocked("SOURCE_DIFF_CHECK", "git diff --check found whitespace / conflict-marker problems in source changes", (proc.stdout or proc.stderr).strip().splitlines()[:15])
        stat = self.sh.git("diff", "--stat", "--", *tracked).stdout.strip().splitlines()
        if stat:
            self.rep.line("  " + stat[-1].strip())

    def tier3_argv(self, *, full: bool) -> list[str]:
        argv = [sys.executable, str(self.sh.repo / TIER3_LAUNCHER), "--base", BASE_BRANCH, "--working-tree", "--format", "json"]
        return argv + (["--mode", "full"] if full else [])

    def run_validation(self, argv: list[str], *, full: bool) -> dict:
        mode = "full" if full else "targeted"
        self.rep.line(f"  local validation: Tier-3 {mode} against {BASE_BRANCH} (working tree) ...")
        proc = self.sh.run(argv, check=False, timeout=TIER3_TIMEOUT_SECONDS, stream_stderr=True)
        report: dict = {}
        try:
            report = json.loads(proc.stdout) if proc.stdout.strip() else {}
        except ValueError:
            report = {}
        result = report.get("result") or ("PASS" if proc.ok else "UNKNOWN")
        validation = {"mode": mode, "result": result, "exit_code": proc.returncode, "blocking_checks": report.get("blocking_checks", []), "summary": report.get("summary", {})}
        if not proc.ok:
            detail = [f"command: {shlex.join(argv)}", f"exit code: {proc.returncode}" + (" (timed out)" if proc.timed_out else ""), f"result: {result}"]
            if validation["blocking_checks"]:
                detail.append("blocking checks: " + ", ".join(validation["blocking_checks"]))
            detail += (proc.stderr or "").strip().splitlines()[-8:]
            raise Blocked("VALIDATION_FAILED", "local Tier-3 validation did not pass; nothing was staged, committed, pushed or opened as a PR", detail)
        self.rep.line(f"  local validation: {result}")
        return validation

    def stage_and_commit(self, candidates: list[Entry], message: str, trailers: list[str]) -> str:
        paths = [e.path for e in candidates]
        staged_by_us: list[str] = []
        try:
            for path in paths:
                self.sh.git("add", "--", path)
                staged_by_us.append(path)
            self.verify_staged(paths)
        except (Blocked, CommandFailed):
            self.unstage(staged_by_us)
            raise
        previous = self.rev("HEAD")
        argv = ["commit", "-m", message]
        for trailer in trailers:
            argv += ["--trailer", trailer]
        self.sh.git(*argv)
        new = self.rev("HEAD")
        if not new or new == previous:
            raise Blocked("COMMIT_NOT_CREATED", "git commit reported success but HEAD did not move")
        committed = sorted(p for p in self.sh.git("diff", "--name-only", "-z", previous, new).stdout.split("\0") if p)
        after = self.working_tree()
        if committed != sorted(paths) or after.staged or after.candidates:
            raise Blocked("COMMIT_VERIFY_FAILED", "the commit does not match the intended source set (nothing was pushed)",
                          [f"committed {len(committed)} path(s), intended {len(paths)}", *(f"still dirty: {e.xy} {e.path}" for e in after.candidates[:5])])
        self.rep.line(f"  committed {short(new)}: {len(committed)} path(s); runtime artifacts remain dirty and unstaged: {', '.join(after.runtime) or '(none)'}")
        return new

    def verify_staged(self, intended: list[str]) -> None:
        # The manifest comes first: a wrongly staged path (above all a runtime log) must be named as such, not surface as noise from --check.
        staged = sorted(p for p in self.sh.git("diff", "--cached", "--name-only", "-z").stdout.split("\0") if p)
        tree = self.working_tree()
        leftovers = [e for e in tree.candidates] + [e for e in tree.staged if e.path in intended and e.xy[1] != " "]
        if staged != sorted(intended) or any(p in RUNTIME_ARTIFACTS for p in staged) or leftovers:
            extra = sorted(set(staged) - set(intended))
            missing = sorted(set(intended) - set(staged))
            raise Blocked("STAGING_MISMATCH", "the staged set does not exactly match the derived source candidates; aborting before commit", [
                *(f"unexpected staged: {p}" for p in extra[:10]), *(f"not staged: {p}" for p in missing[:10]),
                *(f"changed while preparing: {e.xy} {e.path}" for e in leftovers[:10])])
        check = self.sh.git("diff", "--cached", "--check", check=False)
        if check.returncode != 0:
            raise Blocked("STAGED_DIFF_CHECK", "git diff --cached --check failed", (check.stdout or check.stderr).strip().splitlines()[:15])
        stat = self.sh.git("diff", "--cached", "--stat").stdout.strip().splitlines()
        if stat:
            self.rep.line("  staged: " + stat[-1].strip())

    def unstage(self, paths: list[str]) -> None:
        """Undo only this tool's own staging (index only; the working tree is never touched)."""
        for path in paths:
            self.sh.git("restore", "--staged", "--", path, check=False)

    def push(self, branch: str, sha: str | None) -> None:
        remote = self.remote_head(branch)
        if remote and remote != sha:
            if not self.has_commit(remote) or not self.is_ancestor(remote, "HEAD"):
                raise Blocked("REMOTE_DIVERGED", f"{REMOTE}/{branch} ({short(remote)}) is not an ancestor of the local branch; this tool never force-pushes",
                              ["inspect the remote branch and reconcile manually"])
        self.sh.git("push", "-u", REMOTE, branch, timeout=NETWORK_TIMEOUT_SECONDS)
        if self.remote_head(branch) != sha:
            raise Blocked("PUSH_VERIFY_FAILED", f"after the push {REMOTE}/{branch} does not point at {short(sha)}")
        self.rep.line(f"  pushed {branch} -> {REMOTE} (tracking set; no force)")

    # ---- GitHub PR ----
    def list_prs(self, branch: str | None = None) -> list[dict]:
        """PRs (any state, ANY base) for a head branch, or all recent PRs: a wrong base must surface as a refusal, not as 'no PR'."""
        argv = ["pr", "list", "--state", "all", "--limit", "50", "--json", PR_LIST_FIELDS]
        if branch:
            argv += ["--head", branch]
        found = json.loads(self.sh.gh(*argv).stdout or "[]")
        return [p for p in found if branch is None or p.get("headRefName") == branch]

    def ensure_pr(self, branch: str, phase: PhaseId, title: str, base_head: str, phase_sha: str | None, validation: dict, footer: str | None) -> tuple[dict, bool]:
        prs = self.list_prs(branch)
        open_prs = [p for p in prs if p.get("state") == "OPEN"]
        if len(open_prs) > 1:
            raise Blocked("PR_AMBIGUOUS", f"{len(open_prs)} open PRs exist for {branch}", [f"#{p['number']} {p['url']}" for p in open_prs])
        if open_prs:
            if open_prs[0].get("baseRefName") != BASE_BRANCH:
                raise Blocked("BASE_MISMATCH", f"open PR #{open_prs[0]['number']} for {branch} targets {open_prs[0].get('baseRefName')!r}, not {BASE_BRANCH!r}; not reusing it")
            self.rep.line(f"  PR already exists: reusing #{open_prs[0]['number']} (no duplicate created)")
            return open_prs[0], False
        if any(p.get("state") == "MERGED" for p in prs):
            raise Blocked("PR_ALREADY_MERGED", f"a PR for {branch} was already merged; start a new phase branch instead of re-opening this one")
        self.sh.gh("pr", "create", "--base", BASE_BRANCH, "--head", branch, "--title", title, "--body", self.pr_body(phase, base_head, phase_sha, validation, footer))
        created = [p for p in self.list_prs(branch) if p.get("state") == "OPEN"]
        if len(created) != 1:
            raise Blocked("PR_LOOKUP_FAILED", "the PR was created but could not be found afterwards", ["check GitHub manually"])
        return created[0], True

    @staticmethod
    def pr_body(phase: PhaseId, base_head: str, phase_sha: str | None, validation: dict, footer: str | None) -> str:
        lines = [
            f"## Phase {phase} integration", "",
            f"- Base: `{BASE_BRANCH}` @ `{base_head}`",
            f"- Phase commit: `{phase_sha}`",
            "- Local validation: " + (f"Tier-3 {validation['mode']} (working tree vs `{BASE_BRANCH}`) -> **{validation['result']}**" if validation.get("mode") else "not run by this invocation (resumed)"),
            f"- Excluded runtime artifacts (never committed): {', '.join(f'`{p}`' for p in RUNTIME_ARTIFACTS)}",
            "", f"**Hosted `{TIER3_CHECK_NAME}` validation must succeed before merge.** Merge is an explicit operator step: `python tools/phase_integrate.py merge` (merge commit).",
        ]
        if footer:
            lines += ["", footer]
        return "\n".join(lines)

    def view_pr(self, number: int) -> dict:
        pr: dict = {}
        for attempt in range(3):
            pr = json.loads(self.sh.gh("pr", "view", str(number), "--json", PR_VIEW_FIELDS).stdout or "{}")
            if pr.get("state") != "OPEN" or (pr.get("mergeable") != "UNKNOWN" and pr.get("mergeStateStatus") != "UNKNOWN"):
                break
            if attempt < 2:
                self.sleep(2)
        return pr

    def hosted_state(self, number: int, branch: str) -> dict:
        pr = self.view_pr(number)
        ev = evaluate_pr(pr, branch=branch, local_sha=self.rev(f"refs/heads/{branch}"), remote_sha=self.remote_head(branch), tree=self.working_tree())
        label = "MERGE_ALLOWED" if ev.merge_allowed else ("WAITING_FOR_CI" if ev.waiting and not ev.blockers else "BLOCKED")
        return {"label": label, "tier3": ev.tier3, "checks": ev.checks, "merge_allowed": ev.merge_allowed, "blockers": ev.blockers, "waiting": ev.waiting, "pr": pr}

    def dry_run_plan(self, phase, branch, adopt, base_head, candidates, argv, message, a) -> int:
        self.rep.line("  DRY RUN (read-only checks were performed; nothing below was executed):")
        if adopt:
            self.rep.line(f"    would: git switch -c {branch}   (working tree preserved)")
        if candidates:
            self.rep.line("    would validate: " + shlex.join(argv))
            self.rep.line(f"    would stage {len(candidates)} explicit path(s) with: git add -- <path>   (never '.', -A or -a)")
            self.rep.line(f"    would commit: {message!r}" + "".join(f"  --trailer {t!r}" for t in a.trailer or []))
        self.rep.line(f"    would push: git push -u {REMOTE} {branch}   (never forced)")
        self.rep.line(f"    would open PR: base {BASE_BRANCH} <- head {branch} (or reuse an existing open PR); never merged by prepare")
        self.rep.finish("DRY_RUN", command="prepare", phase=phase, branch=branch, base_head=base_head, candidates=[e.path for e in candidates],
                        excluded=list(RUNTIME_ARTIFACTS), validation_command=argv, dry_run=True)
        return EXIT_OK

    # ---- status / merge ----
    def resolve_phase(self, phase: PhaseId | None) -> tuple[str, PhaseId, dict | None]:
        """The phase branch this command is about: the current phase branch, or (from main) the PR of --phase N."""
        current = self.current_branch()
        parsed = parse_branch(current)
        if parsed:
            if phase is not None and parsed[0] != phase:
                raise Blocked("BRANCH_MISMATCH", f"current branch {current} is phase {parsed[0]}, not --phase {phase}")
            return current, parsed[0], None
        if phase is None:
            raise Blocked("NOT_A_PHASE_BRANCH", f"current branch {current} is not a phase branch; switch to it or pass --phase N")
        mine = [p for p in self.list_prs() if (parse_branch(p.get("headRefName", "")) or (0,))[0] == phase]
        open_prs = [p for p in mine if p.get("state") == "OPEN"]
        chosen = open_prs or sorted(mine, key=lambda p: p["number"])[-1:]
        if len(open_prs) > 1:
            raise Blocked("PR_AMBIGUOUS", f"several open PRs exist for phase {phase}", [f"#{p['number']} {p['headRefName']}" for p in open_prs])
        if not chosen:
            raise Blocked("NO_PR", f"no pull request found for phase {phase}")
        return chosen[0]["headRefName"], phase, chosen[0]

    def find_pr_for(self, branch: str, hint: dict | None) -> dict | None:
        prs = self.list_prs(branch)
        open_prs = [p for p in prs if p.get("state") == "OPEN"]
        if len(open_prs) > 1:
            raise Blocked("PR_AMBIGUOUS", f"{len(open_prs)} open PRs exist for {branch}", [f"#{p['number']} {p['url']}" for p in open_prs])
        if open_prs:
            return open_prs[0]
        return sorted(prs, key=lambda p: p["number"])[-1] if prs else hint

    def status(self, phase: PhaseId | None) -> int:
        branch, number, hint = self.resolve_phase(phase)
        pr_ref = self.find_pr_for(branch, hint)
        local, remote = self.rev(f"refs/heads/{branch}"), self.remote_head(branch)
        base_head = self.sh.git("merge-base", BASE_BRANCH, branch, check=False).stdout.strip() if local else ""
        self.rep.line(f"[status] phase {number}  branch {branch}")
        self.rep.kv("phase commit", f"local {short(local)}  remote {short(remote)}")
        if pr_ref is None:
            self.rep.line("  no pull request exists for this branch yet (run 'prepare')")
            self.rep.finish("NO_PR", command="status", phase=number, branch=branch, base_head=base_head or None, phase_head=local, merge_allowed=False, pr_number=None, pr_url=None, checks=[])
            return EXIT_BLOCKED
        pr = self.view_pr(pr_ref["number"])
        tree = self.working_tree()
        ev = evaluate_pr(pr, branch=branch, local_sha=local, remote_sha=remote, tree=tree)
        self.report_evaluation(pr, ev, tree)
        if pr.get("state") == "MERGED":
            label = "MERGED"
        else:
            label = "MERGE_ALLOWED" if ev.merge_allowed else ("WAITING_FOR_CI" if ev.waiting and not ev.blockers else "BLOCKED")
        self.rep.finish(label, command="status", phase=number, branch=branch, base_head=base_head or None, phase_head=local, pr_number=pr.get("number"), pr_url=pr.get("url"),
                        pr_state=pr.get("state"), base=pr.get("baseRefName"), head=pr.get("headRefName"), mergeable=pr.get("mergeable"), merge_state=pr.get("mergeStateStatus"),
                        checks=ev.checks, tier3=ev.tier3, merge_allowed=ev.merge_allowed, blockers=ev.blockers, waiting=ev.waiting)
        return EXIT_OK if label in ("MERGE_ALLOWED", "WAITING_FOR_CI", "MERGED") else EXIT_BLOCKED

    def report_evaluation(self, pr: dict, ev: Evaluation, tree: WorkingTree) -> None:
        self.rep.kv("PR", f"#{pr.get('number')} {pr.get('state')}  {pr.get('url')}")
        self.rep.kv("base <- head", f"{pr.get('baseRefName')} <- {pr.get('headRefName')}  (PR head {short(pr.get('headRefOid'))})")
        self.rep.kv("mergeable", f"{pr.get('mergeable')} / {pr.get('mergeStateStatus')}")
        self.rep.kv("Tier-3", f"{ev.tier3}  ('{TIER3_CHECK_NAME}')")
        for check in ev.checks:
            self.rep.line(f"    check {check['name']!r}: {check['state']}")
        self.rep.kv("working tree", ("source clean" if not tree.candidates and not tree.staged else "SOURCE DIRTY") + f"; runtime dirty: {', '.join(tree.runtime) or '(none)'}")
        for item in ev.blockers:
            self.rep.line(f"  BLOCKER: {item}")
        for item in ev.waiting:
            self.rep.line(f"  waiting: {item}")

    def merge(self, phase: PhaseId | None) -> int:
        branch, number, hint = self.resolve_phase(phase)
        pr_ref = self.find_pr_for(branch, hint)
        if pr_ref is None:
            raise Blocked("NO_PR", f"no pull request exists for {branch}")
        self.rep.line(f"[merge] phase {number}  branch {branch}  PR #{pr_ref['number']}")
        pr = self.view_pr(pr_ref["number"])
        if pr.get("state") == "MERGED":
            if pr.get("baseRefName") != BASE_BRANCH or pr.get("headRefName") != branch:
                raise Blocked("PR_MISMATCH", "the merged PR does not match the expected base / head")
            self.rep.line("  PR is already merged; not merging again - synchronising local main")
            return self.finish_merge(pr, branch, number, already=True)
        local, remote = self.rev(f"refs/heads/{branch}"), self.remote_head(branch)
        tree = self.working_tree()
        ev = evaluate_pr(pr, branch=branch, local_sha=local, remote_sha=remote, tree=tree)
        self.report_evaluation(pr, ev, tree)
        if not ev.merge_allowed:
            raise Blocked("MERGE_REFUSED", "merge refused: " + ("; ".join(ev.blockers + ev.waiting)), [])
        head_sha = pr["headRefOid"]
        argv = ["pr", "merge", str(pr["number"]), "--merge", "--match-head-commit", head_sha]
        if self.sh.dry_run:
            self.rep.line("  DRY RUN: would run: gh " + " ".join(argv) + "  (merge commit; then git switch main; git pull --ff-only origin main)")
            self.rep.finish("DRY_RUN", command="merge", phase=number, branch=branch, phase_head=head_sha, pr_number=pr["number"], pr_url=pr["url"], checks=ev.checks, tier3=ev.tier3, merge_allowed=True, dry_run=True)
            return EXIT_OK
        self.rep.line("  MERGE_ALLOWED: merging with a merge commit (pinned to the verified head)")
        self.sh.gh(*argv)
        merged = self.view_pr(pr["number"])
        for _ in range(3):
            if merged.get("state") == "MERGED":
                break
            self.sleep(2)
            merged = self.view_pr(pr["number"])
        if merged.get("state") != "MERGED":
            raise Blocked("MERGE_NOT_CONFIRMED", "gh reported success but the PR is not shown as MERGED yet; run 'merge' again to synchronise", [])
        return self.finish_merge(merged, branch, number, already=False)

    def finish_merge(self, pr: dict, branch: str, number: PhaseId, *, already: bool) -> int:
        merge_commit = (pr.get("mergeCommit") or {}).get("oid")
        if self.sh.dry_run:
            self.rep.line(f"  DRY RUN: would run: git switch {BASE_BRANCH} (if needed); git pull --ff-only {REMOTE} {BASE_BRANCH}")
            self.rep.finish("DRY_RUN", command="merge", phase=number, branch=branch, pr_number=pr.get("number"), already_merged=already, dry_run=True)
            return EXIT_OK
        if self.current_branch() != BASE_BRANCH:
            self.sh.git("switch", BASE_BRANCH)
        self.sh.git("pull", "--ff-only", REMOTE, BASE_BRANCH, timeout=NETWORK_TIMEOUT_SECONDS)
        final = self.rev("HEAD")
        tree = self.working_tree()
        log = self.sh.git("log", "-5", "--oneline").stdout.strip().splitlines()
        self.rep.line("  recent history:")
        for row in log:
            self.rep.line(f"    {row}")
        self.rep.line(f"  runtime dirty: {', '.join(tree.runtime) or '(none)'}")
        problems = []
        if merge_commit and final != merge_commit and not self.is_ancestor(merge_commit, "HEAD"):
            problems.append(f"local {BASE_BRANCH} ({short(final)}) does not contain the merge commit {short(merge_commit)}")
        problems += [f"unexpected dirty: {e.xy} {e.path}" for e in tree.candidates + tree.staged]
        fields = dict(command="merge", phase=number, branch=branch, pr_number=pr.get("number"), pr_url=pr.get("url"), merge_commit=merge_commit, final_main_head=final,
                      already_merged=already, dry_run=False, merge_allowed=True)
        self.rep.line(f"  *** {BASE_BRANCH} is now at {final} ***")
        if problems:
            for item in problems:
                self.rep.line(f"  PROBLEM: {item}   (not cleaned automatically)")
            self.rep.finish("MERGED_LOCAL_STATE_UNEXPECTED", problems=problems, **fields)
            return EXIT_BLOCKED
        self.rep.finish("MERGED", **fields)
        return EXIT_OK


# --- CLI --------------------------------------------------------------------------------------------

def default_repo() -> Path:
    return Path(__file__).resolve().parent.parent


def build_parser() -> argparse.ArgumentParser:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--repo", default=str(default_repo()), help="repository path (default: this repository)")
    common.add_argument("--json", action="store_true", help="print one machine-readable JSON document on stdout (progress goes to stderr)")
    parser = argparse.ArgumentParser(prog="phase_integrate.py", description="Safe Git/GitHub phase integration (source control only: never touches devices or the lab).")
    sub = parser.add_subparsers(dest="command", required=True)

    start = sub.add_parser("start", parents=[common], help="create phase<N>-<slug> from a clean main")
    start.add_argument("--phase", required=True)
    start.add_argument("--slug", required=True)
    start.add_argument("--dry-run", action="store_true", help="run the read-only checks and print the plan; create nothing")

    prepare = sub.add_parser("prepare", parents=[common], help="validate, stage source only, commit, push and open (or reuse) the PR; never merges")
    prepare.add_argument("--phase", required=True)
    prepare.add_argument("--slug", help="required with --adopt-working-tree; otherwise checked against the current branch")
    prepare.add_argument("--message", help="commit message (required when there are source changes)")
    prepare.add_argument("--adopt-working-tree", action="store_true", help=f"one-time: move uncommitted work from {BASE_BRANCH} onto the new phase branch")
    prepare.add_argument("--full", action="store_true", help="run the full local Tier-3 regression instead of the targeted gate")
    prepare.add_argument("--pr-title", help="PR title (default: the commit subject)")
    prepare.add_argument("--pr-footer", help="text appended to the PR body")
    prepare.add_argument("--trailer", action="append", type=_trailer, help="commit trailer 'Key: value' (repeatable)")
    prepare.add_argument("--dry-run", action="store_true", help="run the read-only checks and print the plan; change nothing, run no validation")

    status = sub.add_parser("status", parents=[common], help="read-only: PR, hosted Tier-3 and merge permission")
    status.add_argument("--phase", help="phase number (needed when not on the phase branch)")

    merge = sub.add_parser("merge", parents=[common], help="merge the PR with a merge commit once hosted Tier-3 succeeded; then sync main")
    merge.add_argument("--phase", help="phase number (needed when not on the phase branch)")
    merge.add_argument("--dry-run", action="store_true", help="verify everything and print the merge command; merge nothing")
    return parser


def _trailer(value: str) -> str:
    if not TRAILER_RE.fullmatch(value):
        raise argparse.ArgumentTypeError("trailer must look like 'Key: value'")
    return value


def main(argv: Sequence[str] | None = None, *, runner: Runner = subprocess_runner, out=None, err=None, sleep: Callable[[float], None] = time.sleep) -> int:
    args = build_parser().parse_args(argv)
    rep = Reporter(args.json, out, err)
    rep.doc["command"] = args.command
    shell = Shell(Path(args.repo).resolve(), runner, dry_run=getattr(args, "dry_run", False))
    tool = Integrator(shell, rep, sleep=sleep)
    phase = None
    try:
        phase = validate_phase(args.phase) if getattr(args, "phase", None) is not None else None
        if args.command == "start":
            return tool.start(phase, validate_slug(args.slug))
        if args.command == "prepare":
            return tool.prepare(args)
        if args.command == "status":
            return tool.status(phase)
        return tool.merge(phase)
    except Blocked as exc:
        rep.line(f"BLOCKED {exc.code}: {exc.message}")
        for detail in exc.details:
            rep.line(f"  - {detail}")
        rep.finish("BLOCKED", show=False, reason=exc.code, message=exc.message, details=exc.details, phase=phase)
        return EXIT_BLOCKED
    except UsageError as exc:
        print(f"phase_integrate.py: error: {exc}", file=err or sys.stderr)
        return EXIT_USAGE
    except CommandFailed as exc:
        proc = exc.proc
        rep.line(f"FAILED: {shlex.join(proc.argv)}")
        rep.line(f"  exit code: {proc.returncode}" + (" (timed out)" if proc.timed_out else ""))
        for row in ((proc.stderr or proc.stdout).strip().splitlines()[-6:]):
            rep.line(f"  {row}")
        rep.finish("FAILED", reason="COMMAND_FAILED", command_argv=list(proc.argv), exit_code=proc.returncode)
        return EXIT_COMMAND_FAILED


if __name__ == "__main__":
    raise SystemExit(main())
