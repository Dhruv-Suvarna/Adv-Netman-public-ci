"""The ONLY place Tier 3 talks to git -- read-only verbs, fixed argument vectors, no shell.

Reading git metadata is expected; anything that could change the repository (add, commit,
reset, clean, stash, checkout, fetch, push ...) is refused here, in one place, so a contract
test can prove it rather than every caller having to be trusted.
"""

from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path

READ_ONLY_GIT_COMMANDS = frozenset({"rev-parse", "merge-base", "diff", "ls-files", "ls-tree"})

# A revision may be a SHA, branch, tag or relative form -- never option-shaped, never whitespace/control.
_REVISION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/@^~{}+-]{0,199}$")
NULL_SHA_RE = re.compile(r"^0{40}$")

GIT_TIMEOUT_SECONDS = 60


class GitError(RuntimeError):
    """A git read failed (bad revision, not a repository, git missing)."""


class UnsafeGitCommand(GitError):
    """A caller asked for a git verb outside the read-only allowlist (a programming error)."""


def valid_revision(text: str) -> bool:
    return bool(text) and bool(_REVISION_RE.match(text)) and ".." not in text


def run_git(repo: Path, args: list[str], *, check: bool = True) -> str:
    """Run one read-only git command and return stdout.  ``args[0]`` must be allowlisted."""
    if not args or args[0] not in READ_ONLY_GIT_COMMANDS:
        raise UnsafeGitCommand(f"git verb {args[:1]!r} is not in the Tier-3 read-only allowlist")
    argv = ["git", "-C", str(repo), "--no-pager", *args]
    try:
        proc = subprocess.run(  # noqa: S603 - fixed argv, shell=False, allowlisted verb
            argv, capture_output=True, text=True, timeout=GIT_TIMEOUT_SECONDS, shell=False,
            env=_git_env(),
        )
    except FileNotFoundError as exc:
        raise GitError("git executable not found") from exc
    except subprocess.TimeoutExpired as exc:
        raise GitError(f"git {args[0]} timed out") from exc
    if check and proc.returncode != 0:
        raise GitError(f"git {args[0]} failed: {proc.stderr.strip()[:200]}")
    return proc.stdout


def _git_env() -> dict[str, str]:
    """Minimal environment: nothing secret-shaped is forwarded to git."""
    env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"), "LC_ALL": "C", "GIT_TERMINAL_PROMPT": "0",
        "GIT_OPTIONAL_LOCKS": "0",  # a read must not even refresh the index
        # core.quotepath=false via environment config, so the verb stays args[0] and paths are not C-quoted.
        "GIT_CONFIG_COUNT": "1", "GIT_CONFIG_KEY_0": "core.quotepath", "GIT_CONFIG_VALUE_0": "false",
    }
    if os.environ.get("HOME"):
        env["HOME"] = os.environ["HOME"]  # lets git honour safe.directory in the user's gitconfig
    return env


def resolve_commit(repo: Path, revision: str) -> str:
    """Resolve a revision to a full commit SHA, or raise GitError (used for both base and head)."""
    if not valid_revision(revision):
        raise GitError(f"revision {revision!r} is not a valid revision name")
    out = run_git(repo, ["rev-parse", "--verify", "--quiet", "--end-of-options", f"{revision}^{{commit}}"], check=False).strip()
    if not re.fullmatch(r"[0-9a-f]{40}", out):
        raise GitError(f"revision {revision!r} does not resolve to a commit in this repository")
    return out


def repository_root(start: Path) -> Path:
    out = run_git(start, ["rev-parse", "--show-toplevel"]).strip()
    return Path(out)
