"""Phase-16 Tier-3 validation -- the reusable service API (facade over ``core.services.ci``).

Callable from the CLI (``tier3.py``), GitHub Actions, Django code and tests.  Tier 3 is repository-level
change-effect / integration / regression validation; it is not Tier 1 (Device Builder field syntax) or
Tier 2 (Phase-13 whole-Change validation) and it never deploys, writes NetBox/Git, contacts a device,
executes a Configlet, advances a Change lifecycle or persists anything.

    plan_change_effect(request)   collect changes, classify, expand impact, select checks -- executes nothing
    run_tier3(request, ...)       plan + execute the selected checks + build the report
    classify_path(path)           the subsystem(s) a repository path belongs to
    Tier3Request                  base / head / mode / range semantics
"""

from __future__ import annotations

from .ci.classify import classify_path, expand_impact
from .ci.constants import ENGINE_VERSION, REPORT_SCHEMA_VERSION, CheckStatus, ExitCode, Gate, Mode, Result
from .ci.github_context import resolve_from_environment
from .ci.report import Tier3Report, render_markdown, render_text
from .ci.service import Tier3InputError, Tier3Request, plan_change_effect, run_tier3

__all__ = [
    "ENGINE_VERSION", "REPORT_SCHEMA_VERSION", "CheckStatus", "ExitCode", "Gate", "Mode", "Result", "Tier3InputError", "Tier3Report",
    "Tier3Request", "classify_path", "expand_impact", "plan_change_effect", "render_markdown", "render_text", "resolve_from_environment",
    "run_tier3",
]
