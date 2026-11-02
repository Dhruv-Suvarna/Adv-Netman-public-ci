"""Run the planned checks and turn each outcome into a truthful ``CheckResult``.

A crash, timeout, missing tool or a test run that executed zero tests is ``ERROR`` -- never ``PASS``.
Optional (lab) checks that were not requested are reported ``NOT_RUN`` and never counted as a pass.
"""

from __future__ import annotations

import re
import sys
import time
from dataclasses import dataclass, field
from functools import partial
from pathlib import Path
from typing import Callable

from . import catalog, changes as changes_module, redact, runner as runner_module, static_checks
from .constants import MAX_LIST, CheckStatus
from .planner import PlannedCheck, ValidationPlan

_RAN_RE = re.compile(r"^Ran (\d+) tests? in ([0-9.]+)s", re.MULTILINE)
_FAILED_RE = re.compile(r"^FAILED \((.*)\)\s*$", re.MULTILINE)
NOT_RUN_REASON = "lab-backed verifier: not executed by the offline gate (run with --lab from a lab-connected machine)"


@dataclass
class CheckResult:
    id: str
    gate: str
    title: str
    required: bool
    status: str
    summary: str
    reasons: list[str] = field(default_factory=list)
    counts: dict = field(default_factory=dict)
    duration_seconds: float = 0.0
    findings: list[dict] = field(default_factory=list)
    output_tail: str = ""

    def to_dict(self, *, include_timing: bool = True) -> dict:
        out = {
            "id": self.id, "gate": self.gate, "title": self.title, "required": self.required, "status": self.status,
            "summary": self.summary, "reasons": sorted(set(self.reasons)), "counts": self.counts,
        }
        if self.findings:
            out["findings"] = self.findings[:MAX_LIST]
        if self.output_tail:
            out["output_tail"] = self.output_tail
        if include_timing:
            out["duration_seconds"] = round(self.duration_seconds, 3)
        return out


def execute_plan(
    plan: ValidationPlan, repo: Path, change_set: changes_module.ChangeSet, *,
    runner: Callable = runner_module.default_runner, python: str | None = None, on_event: Callable | None = None,
    shell_runner: Callable | None = None,
) -> list[CheckResult]:
    python = python or sys.executable
    emit = on_event or (lambda *_: None)
    cache: dict = {}
    results: list[CheckResult] = []

    for check in plan.required:
        emit("start", check.id, None)
        started = time.monotonic()
        try:
            result = _run_one(check, plan, repo, change_set, runner, python, cache, shell_runner)
        except Exception as exc:  # a crashed check is a result, never a pass and never a traceback in the report
            result = _result(check, CheckStatus.ERROR, f"check crashed: {type(exc).__name__}")
        result.duration_seconds = time.monotonic() - started
        results.append(result)
        emit("finish", check.id, result)

    for check in plan.optional:
        results.append(_result(check, CheckStatus.NOT_RUN, NOT_RUN_REASON))
    return results


def _result(check: PlannedCheck, status: str, summary: str, **extra) -> CheckResult:
    return CheckResult(check.id, check.gate, check.title, check.required, status, redact.bound_string(summary, 300), list(check.reasons), **extra)


def _run_one(check, plan, repo, change_set, runner, python, cache, shell_runner) -> CheckResult:
    if check.id == "static.hygiene":
        if "lines" not in cache:
            cache["lines"] = changes_module.added_lines(repo, change_set)
        lines, truncated = cache["lines"]
        files = [(f.path, f.status) for f in change_set.files]
        return _from_static(check, static_checks.check_hygiene(lines, truncated, files))
    if check.id == "static.syntax":
        shell = shell_runner or partial(runner_module.shell_syntax, repo)
        return _from_static(check, static_checks.check_syntax(repo, plan.scope_paths, shell_runner=shell))

    command = catalog.command_for(check.id, python=python, params=check.params)
    timeout = catalog.CHECKS[check.id].timeout
    raw = runner(command, repo, timeout)
    tail = redact.bound_output(raw.output)
    if raw.timed_out:
        return _result(check, CheckStatus.ERROR, f"timed out after {timeout}s (result unknown)", output_tail=tail)
    if raw.error or raw.returncode is None:
        return _result(check, CheckStatus.ERROR, raw.error or "the command did not report an exit status", output_tail=tail)

    counts = _parse_counts(raw.output)
    is_suite = check.id in ("django.tests", "monitoring.unit")
    if raw.returncode == 0:
        if is_suite and not counts.get("tests_run"):
            return _result(check, CheckStatus.ERROR, "exit 0 but no tests were executed (unreliable)", counts=counts, output_tail=tail)
        summary = f"{counts['tests_run']} test(s) passed" if counts.get("tests_run") else "passed"
        return _result(check, CheckStatus.PASS, summary, counts=counts)
    summary = f"exit status {raw.returncode}"
    if counts.get("tests_run") is not None:
        summary += f"; {counts['tests_run']} run, {counts.get('failures', 0)} failure(s), {counts.get('errors', 0)} error(s)"
    return _result(check, CheckStatus.FAIL, summary, counts=counts, output_tail=tail)


def _from_static(check: PlannedCheck, outcome: static_checks.StaticOutcome) -> CheckResult:
    return _result(check, outcome.status, outcome.summary, counts=outcome.counts, findings=outcome.findings)


def _parse_counts(output: str) -> dict:
    counts: dict = {}
    ran = _RAN_RE.search(output)
    if ran:
        counts["tests_run"] = int(ran.group(1))
    failed = _FAILED_RE.search(output)
    if failed:
        for part in failed.group(1).split(","):
            key, _, value = part.strip().partition("=")
            if key in ("failures", "errors", "skipped") and value.isdigit():
                counts[key] = int(value)
    return counts
