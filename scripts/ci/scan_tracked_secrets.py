#!/usr/bin/env python3
"""Scan the current tracked tree without ever printing matched values.

This complements Gitleaks with NMAS-specific low-entropy assignment rules.  It
is intentionally a current-tree gate; the GitHub workflow separately scans the
new commit range so add-then-delete leaks are also rejected.
"""

from __future__ import annotations

import argparse
import gzip
import subprocess
import sys
from pathlib import Path


REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "web"))

from core.services.ci import redact  # noqa: E402
from core.services.ci.static_checks import (  # noqa: E402
    SECRET_DIR_ALLOW,
    SECRET_DIR_PREFIX,
    SECRET_FILE_ALLOW,
    SECRET_FILE_RE,
)


MAX_FILE_BYTES = 20_000_000


def tracked_paths(repo: Path) -> list[str]:
    output = subprocess.check_output(["git", "-C", str(repo), "ls-files", "-z"])
    return sorted(part.decode("utf-8", "surrogateescape") for part in output.split(b"\0") if part)


def scan_text(path: str, text: str) -> list[tuple[str, int, str]]:
    findings = []
    for line_number, line in enumerate(text.splitlines(), 1):
        for category in redact.scan_line(line):
            findings.append((path, line_number, category))
    return findings


def scan(repo: Path) -> tuple[list[tuple[str, int | None, str]], dict[str, int]]:
    findings: list[tuple[str, int | None, str]] = []
    counts = {"tracked": 0, "text": 0, "gzip": 0, "binary_skipped": 0, "oversize_skipped": 0}
    for relative in tracked_paths(repo):
        counts["tracked"] += 1
        target = repo / relative
        if (SECRET_FILE_RE.search(relative) and not SECRET_FILE_ALLOW.search(relative)) or (
            relative.startswith(SECRET_DIR_PREFIX) and relative not in SECRET_DIR_ALLOW
        ):
            findings.append((relative, None, "CREDENTIAL_FILE_PATH"))
        try:
            size = target.stat().st_size
            if size > MAX_FILE_BYTES:
                counts["oversize_skipped"] += 1
                continue
            data = target.read_bytes()
        except OSError:
            findings.append((relative, None, "UNREADABLE_TRACKED_FILE"))
            continue
        if data.startswith(b"\x1f\x8b"):
            try:
                data = gzip.decompress(data)
                counts["gzip"] += 1
            except (OSError, EOFError):
                findings.append((relative, None, "INVALID_GZIP"))
                continue
        if b"\x00" in data[:4096]:
            counts["binary_skipped"] += 1
            continue
        # Replacement decoding keeps ASCII credential patterns visible even
        # in an otherwise damaged/non-UTF-8 evidence file.  NUL-bearing binary
        # files remain excluded above.
        text = data.decode("utf-8", errors="replace")
        counts["text"] += 1
        findings.extend(scan_text(relative, text))
    return findings, counts


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=REPO)
    args = parser.parse_args()
    findings, counts = scan(args.repo.resolve())
    for path, line, category in findings:
        location = f"{path}:{line}" if line is not None else path
        print(f"{location}: {category} (value withheld)")
    print(
        "tracked-secret-scan:",
        "FAIL" if findings else "PASS",
        f"tracked={counts['tracked']}",
        f"text={counts['text']}",
        f"gzip={counts['gzip']}",
        f"binary_skipped={counts['binary_skipped']}",
        f"oversize_skipped={counts['oversize_skipped']}",
        f"findings={len(findings)}",
    )
    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
