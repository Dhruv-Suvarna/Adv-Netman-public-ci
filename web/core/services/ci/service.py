"""Tier-3 orchestration: request -> change collection -> plan -> execution -> report.

This is the reusable API.  The CLI, the GitHub launcher, Django code and tests all call it; none of
them contains classification or selection logic.  Nothing here deploys, writes NetBox/Git, contacts a
device, executes a Configlet or touches a Change: it reads git metadata and repository files and runs
the fixed catalogue commands.
"""

from __future__ import annotations

import platform
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Mapping

from . import changes as changes_module, execute, gitio, planner, runner as runner_module
from .constants import ENGINE_VERSION, Mode
from .planner import PlanWarning, ValidationPlan
from .report import Tier3Report
from .rules import WARN_BASE_FALLBACK


class Tier3InputError(ValueError):
    """Bad revision / not a git repository / inconsistent options: a usage error, not a validation result."""


@dataclass(frozen=True)
class Tier3Request:
    repo: Path
    base: str | None = None
    head: str = "HEAD"
    mode: str = Mode.TARGETED
    merge_base: bool = True
    working_tree: bool = False
    include_lab: bool = False
    derived: bool = False            # base/head came from CI event data: an unresolvable base broadens instead of failing
    context: Mapping = field(default_factory=dict)
    notes: tuple[str, ...] = ()


def _collect(request: Tier3Request) -> tuple[changes_module.ChangeSet, list[PlanWarning], list[str]]:
    warnings: list[PlanWarning] = []
    notes = list(request.notes)
    try:
        return changes_module.collect_changes(
            request.repo, request.base, request.head, merge_base=request.merge_base, working_tree=request.working_tree), warnings, notes
    except gitio.GitError as exc:
        if not (request.derived and request.base and not request.working_tree):
            raise Tier3InputError(str(exc)) from exc
        # CI gave us a base this clone cannot use (force-push, shallow checkout): broaden, never skip.
        try:
            fallback = changes_module.collect_changes(request.repo, None, request.head)
        except gitio.GitError as inner:
            raise Tier3InputError(str(inner)) from inner
        warnings.append(PlanWarning(WARN_BASE_FALLBACK, f"comparison base unusable ({str(exc)[:160]}); full validation was used instead", []))
        return fallback, warnings, notes


def plan_change_effect(request: Tier3Request) -> tuple[changes_module.ChangeSet, ValidationPlan]:
    """Analysis only: collect changes, classify, expand impact, select checks.  Executes nothing."""
    if request.mode not in Mode.ALL:
        raise Tier3InputError(f"mode must be one of {', '.join(Mode.ALL)}")
    try:
        gitio.repository_root(request.repo)
    except gitio.GitError as exc:
        raise Tier3InputError(f"{request.repo} is not a usable git repository: {exc}") from exc
    change_set, warnings, _notes = _collect(request)
    all_tracked = lambda: [p for p in gitio.run_git(request.repo, ["ls-files", "-z"]).split("\0") if p]  # noqa: E731
    plan = planner.build_plan(change_set, mode=request.mode, include_lab=request.include_lab, all_tracked=all_tracked)
    plan.warnings.extend(warnings)
    return change_set, plan


def run_tier3(
    request: Tier3Request, *, runner: Callable = runner_module.default_runner, on_event: Callable | None = None,
    python: str | None = None, shell_runner: Callable | None = None,
) -> Tier3Report:
    change_set, plan = plan_change_effect(request)
    results = execute.execute_plan(plan, request.repo, change_set, runner=runner, python=python, on_event=on_event, shell_runner=shell_runner)
    return Tier3Report(provenance_for(request, change_set, plan), plan, results, list(change_set.notes) + list(request.notes))


def provenance_for(request: Tier3Request, change_set: changes_module.ChangeSet, plan: ValidationPlan) -> dict:
    ctx = request.context
    return {
        "engine_version": ENGINE_VERSION,
        "base_sha": change_set.base_sha,
        "compare_from_sha": change_set.compare_from_sha,
        "head_sha": change_set.head_sha,
        "strategy": change_set.strategy,
        "working_tree": change_set.working_tree,
        "event": ctx.get("event"),
        "ref_name": ctx.get("ref_name"),
        "repository": ctx.get("repository"),
        "run_id": ctx.get("run_id"),
        "checkout_sha": ctx.get("checkout_sha"),
        "python_version": platform.python_version(),
        "lab_gate_requested": request.include_lab,
    }
