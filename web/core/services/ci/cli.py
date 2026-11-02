"""Tier-3 command line (used locally and by the thin GitHub workflow).

Exit status:
    0  PASS or PASS_WITH_WARNINGS (warnings are non-blocking)
    1  FAIL        a required check failed
    2  usage       bad arguments, unresolvable revision, not a git repository
    3  INCOMPLETE  a required check could not be executed (crash / timeout / no tests ran); never treated as a pass
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path
from typing import Callable, Sequence

from . import github_context
from .constants import ENGINE_VERSION, ExitCode, Mode
from .report import render_markdown, render_text
from .service import Tier3InputError, Tier3Request, plan_change_effect, run_tier3


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="tier3.py", description="Tier-3 change-effect / integration / regression validation (validation only: nothing is deployed or written to the lab).")
    parser.add_argument("--repo", default=".", help="repository path (default: current directory)")
    parser.add_argument("--base", help="base revision (SHA, branch, tag); required unless --mode full or --from-github")
    parser.add_argument("--head", default="HEAD", help="head revision (default: HEAD)")
    parser.add_argument("--mode", choices=Mode.ALL, help="targeted (default) selects checks from the change effect; full runs the whole regression surface")
    parser.add_argument("--no-merge-base", action="store_true", help="diff base..head directly instead of merge-base(base, head)..head")
    parser.add_argument("--working-tree", action="store_true", help="compare --base with the working tree (uncommitted + untracked files included)")
    parser.add_argument("--from-github", action="store_true", help="derive base/head/mode from GitHub Actions event data (GITHUB_EVENT_NAME / GITHUB_EVENT_PATH / GITHUB_SHA)")
    parser.add_argument("--plan-only", action="store_true", help="print the change-effect plan; execute nothing")
    parser.add_argument("--lab", action="store_true", help="ALSO run the real lab verifiers selected for this change (needs a lab-connected machine)")
    parser.add_argument("--format", choices=("text", "json"), default="text", help="stdout format (default: text)")
    parser.add_argument("--json", metavar="PATH", help="also write the machine-readable report to PATH")
    parser.add_argument("--summary-md", metavar="PATH", help="append a Markdown summary to PATH (e.g. $GITHUB_STEP_SUMMARY)")
    parser.add_argument("--version", action="version", version=f"tier3 engine {ENGINE_VERSION}")
    return parser


def _request(args: argparse.Namespace, env) -> Tier3Request:
    repo = Path(args.repo).resolve()
    if args.from_github:
        if args.base or args.working_tree:
            raise Tier3InputError("--from-github cannot be combined with --base / --working-tree")
        try:
            derived = github_context.resolve_from_environment(env)
        except github_context.GitHubContextError as exc:
            raise Tier3InputError(str(exc)) from exc
        return Tier3Request(repo, derived.base, derived.head, args.mode or derived.mode, derived.merge_base and not args.no_merge_base,
                            False, args.lab, True, derived.context, derived.notes)
    mode = args.mode or Mode.TARGETED
    if not args.base and mode != Mode.FULL:
        raise Tier3InputError("supply --base REV (targeted validation needs a comparison), or use --mode full")
    if args.working_tree and not args.base:
        raise Tier3InputError("--working-tree needs --base")
    return Tier3Request(repo, args.base, args.head, mode, not args.no_merge_base, args.working_tree, args.lab, False, {}, ())


def main(argv: Sequence[str] | None = None, *, env=None, runner: Callable | None = None, stdout=None, stderr=None) -> int:
    out, err = stdout or sys.stdout, stderr or sys.stderr
    env = os.environ if env is None else env
    args = build_parser().parse_args(argv)
    try:
        request = _request(args, env)
        if args.plan_only:
            import json

            _changes, plan = plan_change_effect(request)
            out.write(json.dumps(plan.to_dict(), sort_keys=True, indent=2) + "\n")
            return ExitCode.OK

        def progress(kind: str, check_id: str, result) -> None:
            if kind == "start":
                err.write(f"[tier3] running {check_id} ...\n")
            else:
                err.write(f"[tier3] {check_id}: {result.status} ({result.duration_seconds:.1f}s)\n")
            err.flush()

        kwargs = {"runner": runner} if runner is not None else {}
        report = run_tier3(request, on_event=progress, **kwargs)
    except Tier3InputError as exc:
        err.write(f"tier3: error: {exc}\n")
        return ExitCode.USAGE

    if args.json:
        path = Path(args.json)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(report.to_json(), encoding="utf-8")
    if args.summary_md:
        with open(args.summary_md, "a", encoding="utf-8") as handle:
            handle.write(render_markdown(report))
    out.write(report.to_json() + "\n" if args.format == "json" else render_text(report))
    return report.exit_code
