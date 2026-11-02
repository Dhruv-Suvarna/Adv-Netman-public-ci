#!/usr/bin/env python3
"""Run a redacted Gitleaks scan over the current tree and new commit range."""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
from pathlib import Path


SHA_RE = re.compile(r"[0-9a-f]{40}")
ZERO_SHA = "0" * 40


def checked_sha(value: object, label: str) -> str:
    if not isinstance(value, str) or not SHA_RE.fullmatch(value):
        raise SystemExit(f"Invalid {label} commit identifier in the GitHub event.")
    return value


def event_range(event_path: Path | None, repo: Path) -> str:
    if event_path is None:
        head = subprocess.check_output(["git", "-C", str(repo), "rev-parse", "HEAD"], text=True).strip()
        return f"{head}^..{head}"
    event = json.loads(event_path.read_text(encoding="utf-8"))
    if isinstance(event.get("pull_request"), dict):
        pull = event["pull_request"]
        base = checked_sha((pull.get("base") or {}).get("sha"), "pull-request base")
        head = checked_sha((pull.get("head") or {}).get("sha"), "pull-request head")
        return f"{base}..{head}"
    before = checked_sha(event.get("before", ZERO_SHA), "push before")
    after = checked_sha(event.get("after") or os.environ.get("GITHUB_SHA"), "push after")
    # A zero ``before`` value is used for a new branch and for the first push
    # to a root-only mirror.  ``after^..after`` is invalid when ``after`` has
    # no parent.  Scanning from ``after`` includes its complete ancestry,
    # which is both valid for a root commit and fail-closed for a new branch.
    return after if before == ZERO_SHA else f"{before}..{after}"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--gitleaks", type=Path)
    parser.add_argument("--repo", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument("--event", type=Path)
    args = parser.parse_args()
    repo = args.repo.resolve()
    discovered = str(args.gitleaks) if args.gitleaks is not None else shutil.which("gitleaks")
    if not discovered:
        raise SystemExit("Gitleaks is required; install it or pass --gitleaks /absolute/path.")
    binary = Path(discovered).resolve()
    common = [str(binary), "--no-banner", "--redact=100", "--no-color"]
    # Use a relative target so exact reviewed fingerprints in
    # ``.gitleaksignore`` remain stable locally and in CI.
    current = subprocess.run([*common, "dir", ".", "--max-archive-depth=2"], cwd=repo).returncode
    commit_range = event_range(args.event, repo)
    history = subprocess.run(
        [*common, "git", str(repo), f"--log-opts={commit_range}"],
        cwd=repo,
    ).returncode
    return 1 if current or history else 0


if __name__ == "__main__":
    raise SystemExit(main())
