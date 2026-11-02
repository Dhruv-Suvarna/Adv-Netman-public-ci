"""Subprocess execution for catalogue commands (one of only two modules that may use ``subprocess``).

Bounded (timeout, redacted + truncated output), no shell, allowlisted environment.  The offline
gates never receive the caller's environment: only a fixed set of harmless variables plus what the
catalogue adds, so no token, webhook, credential or lab address in the runner's environment can
reach a test process.  Only the explicit lab gate inherits the environment (the real verifiers need
the operator's docker/NetBox/monitoring context).
"""

from __future__ import annotations

import os
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path

from .catalog import Command

# DISPLAY / XAUTHORITY name an X display and the path of its cookie file (never a credential value): the Tk console tests need a
# display, which Tier-3 provides with xvfb-run.  Without one they skip and their cases stay MISSING, so the gate reports it.
SAFE_ENV_KEYS = ("PATH", "HOME", "LANG", "LC_ALL", "LC_CTYPE", "TZ", "TMPDIR", "VIRTUAL_ENV", "SYSTEMROOT", "DISPLAY", "XAUTHORITY")
RAW_CAPTURE_LIMIT = 2_000_000


@dataclass
class CommandResult:
    returncode: int | None
    output: str = ""
    timed_out: bool = False
    error: str | None = None
    duration: float = 0.0


def build_env(command: Command) -> dict[str, str]:
    if command.inherit_env:
        env = dict(os.environ)
    else:
        env = {key: os.environ[key] for key in SAFE_ENV_KEYS if key in os.environ}
        env["PYTHONDONTWRITEBYTECODE"] = "1"  # never rewrite the (tracked) __pycache__ files
        env.update({key: os.environ[key][:200] for key in command.forward_env if os.environ.get(key)})
    env.update(command.env_extra)
    return env


def default_runner(command: Command, repo: Path, timeout: int) -> CommandResult:
    started = time.monotonic()
    try:
        proc = subprocess.run(  # noqa: S603 - fixed catalogue argv, shell=False
            list(command.argv), cwd=str(repo / command.cwd), env=build_env(command), capture_output=True, text=True,
            timeout=timeout, shell=False, errors="replace",
        )
    except subprocess.TimeoutExpired as exc:
        # TimeoutExpired may return bytes even with text=True.  Preserve the
        # last completed test name for diagnosis instead of dropping the trace.
        stdout = exc.stdout.decode("utf-8", "replace") if isinstance(exc.stdout, bytes) else (exc.stdout or "")
        stderr = exc.stderr.decode("utf-8", "replace") if isinstance(exc.stderr, bytes) else (exc.stderr or "")
        partial = stdout + stderr
        return CommandResult(None, partial[-RAW_CAPTURE_LIMIT:], timed_out=True, duration=time.monotonic() - started)
    except OSError as exc:
        return CommandResult(None, error=f"{type(exc).__name__}: could not start {command.argv[0]!r}", duration=time.monotonic() - started)
    text = (proc.stdout or "") + ("\n" if proc.stdout and proc.stderr else "") + (proc.stderr or "")
    return CommandResult(proc.returncode, text[-RAW_CAPTURE_LIMIT:], duration=time.monotonic() - started)


def shell_syntax(repo: Path, relative_path: str) -> tuple[bool, str]:
    """``bash -n`` (parse only, never executes the script)."""
    try:
        proc = subprocess.run(  # noqa: S603, S607 - fixed argv, parse-only flag
            ["bash", "-n", relative_path], cwd=str(repo), capture_output=True, text=True, timeout=30, shell=False,
            env={key: os.environ[key] for key in SAFE_ENV_KEYS if key in os.environ},
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return False, f"bash -n could not run: {type(exc).__name__}"
    return proc.returncode == 0, (proc.stderr or "").strip()[:200]
