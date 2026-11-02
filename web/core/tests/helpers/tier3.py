"""Shared fixtures for the Tier-3 (ci) tests: a throw-away git repository and a scriptable command runner.

The real ``git`` binary is used against a temporary repository only (never the project checkout); every
Tier-3 *command* is faked, so a test can never start Django, the monitoring suite or a lab verifier.
"""

from __future__ import annotations

import os
import subprocess
import tempfile
from pathlib import Path

from core.services.ci.catalog import Command
from core.services.ci.changes import ChangedFile, ChangeSet
from core.services.ci.runner import CommandResult

A, B = "a" * 40, "b" * 40


class TempRepo:
    """A disposable git repository with a fixed identity and no global/system configuration."""

    def __init__(self):
        self._tmp = tempfile.TemporaryDirectory(prefix="tier3-test-")
        self.path = Path(self._tmp.name)
        self.env = {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": self._tmp.name, "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_SYSTEM": os.devnull,
            "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.invalid", "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.invalid",
        }
        self.git("init", "-q", "-b", "main")

    def cleanup(self):
        self._tmp.cleanup()

    def git(self, *args: str) -> str:
        proc = subprocess.run(["git", "-C", str(self.path), *args], capture_output=True, text=True, env=self.env, check=True)
        return proc.stdout.strip()

    def write(self, rel: str, text: str = "x\n") -> None:
        target = self.path / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")

    def commit(self, message: str = "c") -> str:
        self.git("add", "-A")
        self.git("commit", "-q", "--allow-empty", "-m", message)
        return self.git("rev-parse", "HEAD")

    def snapshot(self) -> dict:
        """Everything a read-only tool must leave alone: HEAD, refs, index/worktree status and file contents."""
        files = {str(p.relative_to(self.path)): p.read_bytes() for p in sorted(self.path.rglob("*")) if p.is_file() and ".git" not in p.parts}
        return {"head": self.git("rev-parse", "HEAD"), "refs": self.git("for-each-ref"), "status": self.git("status", "--porcelain"), "files": files}


def change_set(*files: tuple[str, str] | tuple[str, str, str], strategy: str = "merge-base") -> ChangeSet:
    """A synthetic ChangeSet -- ``("modified", path)`` or ``("renamed", new, old)`` -- for planner tests with no git."""
    changed = tuple(ChangedFile(f[1], f[0], f[2] if len(f) == 3 else None) for f in files)
    return ChangeSet(A, None if strategy == "all-tracked" else B, None if strategy == "all-tracked" else B, strategy, changed)


class FakeRunner:
    """Replaces the subprocess runner: records every Command and answers from a small script."""

    def __init__(self, responses: dict[str, CommandResult] | None = None):
        self.calls: list[Command] = []
        self.responses = responses or {}

    def __call__(self, command: Command, repo, timeout) -> CommandResult:
        self.calls.append(command)
        line = " ".join(command.argv)
        for needle, result in self.responses.items():
            if needle in line:
                if isinstance(result, BaseException):
                    raise result
                return result
        suite = "manage.py test" in line or "unittest" in line
        return CommandResult(0, "Ran 3 tests in 0.010s\n\nOK\n" if suite else "ok\n")

    @property
    def lines(self) -> list[str]:
        return [" ".join(c.argv) for c in self.calls]
