"""The Tier-3 report: overall result, stable serialization, and safe human / GitHub presentation."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field

from . import redact
from .constants import (
    ENGINE_VERSION, MAX_REPORT_BYTES, REPORT_SCHEMA_VERSION, CheckStatus, ExitCode, Gate, Result,
)
from .execute import CheckResult
from .planner import ValidationPlan


def aggregate(results: list[CheckResult], warning_count: int) -> tuple[str, int]:
    """FAIL beats INCOMPLETE beats warnings.  A required check that could not run is never a pass."""
    required = [r for r in results if r.required]
    if any(r.status == CheckStatus.FAIL for r in required):
        return Result.FAIL, ExitCode.FAIL
    if any(r.status in (CheckStatus.ERROR, CheckStatus.NOT_RUN) for r in required):
        return Result.INCOMPLETE, ExitCode.INCOMPLETE
    if warning_count or any(r.status == CheckStatus.WARN for r in required):
        return Result.PASS_WITH_WARNINGS, ExitCode.OK
    return Result.PASS, ExitCode.OK


def coverage(results: list[CheckResult]) -> dict[str, str]:
    """Per gate: was it actually exercised?  Absence of evidence is reported as such, never as PASS."""
    out: dict[str, str] = {}
    for gate in Gate.ALL:
        mine = [r for r in results if r.gate == gate]
        required = [r for r in mine if r.required]
        if required:
            out[gate] = "INCOMPLETE" if any(r.status in (CheckStatus.ERROR, CheckStatus.NOT_RUN) for r in required) else "EXECUTED"
        else:
            out[gate] = "NOT_RUN" if mine else "NOT_SELECTED"
    return out


@dataclass
class Tier3Report:
    provenance: dict
    plan: ValidationPlan
    results: list[CheckResult]
    notes: list[str] = field(default_factory=list)

    @property
    def result(self) -> str:
        return aggregate(self.results, len(self.plan.warnings))[0]

    @property
    def exit_code(self) -> int:
        return aggregate(self.results, len(self.plan.warnings))[1]

    def summary_counts(self) -> dict:
        def n(status: str) -> int:
            return sum(1 for r in self.results if r.status == status)
        return {
            "selected": len(self.plan.required) + len(self.plan.optional), "executed": sum(1 for r in self.results if r.status != CheckStatus.NOT_RUN),
            "passed": n(CheckStatus.PASS), "warned": n(CheckStatus.WARN), "failed": n(CheckStatus.FAIL), "errored": n(CheckStatus.ERROR),
            "not_run": n(CheckStatus.NOT_RUN),
        }

    def to_dict(self, *, include_timing: bool = True) -> dict:
        plan = self.plan.to_dict()
        result, code = aggregate(self.results, len(self.plan.warnings))
        doc = {
            "schema_version": REPORT_SCHEMA_VERSION,
            "engine_version": ENGINE_VERSION,
            "result": result,
            "exit_code": code,
            "blocking_checks": [r.id for r in self.results if r.required and r.status in (CheckStatus.FAIL, CheckStatus.ERROR, CheckStatus.NOT_RUN)],
            "provenance": self.provenance,
            "coverage": coverage(self.results),
            "summary": self.summary_counts(),
            "changed_files_total": plan["changed_files_total"],
            "changed_files_truncated": plan["changed_files_truncated"],
            "changed_files": plan["changed_files"],
            "affected_subsystems": plan["affected_subsystems"],
            "unclassified_paths": plan["unclassified_paths"],
            "mode": {"requested": plan["mode_requested"], "effective": plan["mode_effective"], "reasons": plan["mode_reasons"]},
            "plan": {
                "plan_hash": plan["plan_hash"], "required_checks": plan["required_checks"], "optional_checks": plan["optional_checks"],
                "test_selection": plan["test_selection"],
            },
            "warnings": plan["warnings"],
            "notes": self.notes,
            "checks": [r.to_dict(include_timing=include_timing) for r in self.results],
        }
        return _bound(doc)

    def to_json(self, *, include_timing: bool = True) -> str:
        return json.dumps(self.to_dict(include_timing=include_timing), sort_keys=True, indent=2)

    def semantic_digest(self) -> str:
        """SHA-256 of the deterministic part (no durations, no output tails): equal inputs give equal digests."""
        doc = self.to_dict(include_timing=False)
        for check in doc["checks"]:
            check.pop("output_tail", None)  # tool output can embed timings
        return hashlib.sha256(json.dumps(doc, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _bound(doc: dict) -> dict:
    """Keep the artifact small: shrink the two unbounded lists before dropping anything else."""
    if len(json.dumps(doc)) <= MAX_REPORT_BYTES:
        return doc
    doc["changed_files"] = doc["changed_files"][:50]
    doc["changed_files_truncated"] = True
    for check in doc["checks"]:
        check.pop("output_tail", None)
    doc["notes"] = [*doc["notes"], "report truncated to stay within the artifact size bound"]
    return doc


# --- presentation -------------------------------------------------------------------------------

def _sha(value: str | None) -> str:
    return value[:12] if value else "-"


def render_text(report: Tier3Report) -> str:
    doc = report.to_dict()
    prov = doc["provenance"]
    lines = [
        f"TIER-3 VALIDATION: {doc['result']}   (engine {doc['engine_version']}, plan {doc['plan']['plan_hash'][:12]})",
        f"  base {_sha(prov.get('base_sha'))}  compare-from {_sha(prov.get('compare_from_sha'))}  head {_sha(prov.get('head_sha'))}  "
        f"strategy {prov.get('strategy')}{' +working-tree' if prov.get('working_tree') else ''}",
        f"  mode requested={doc['mode']['requested']} effective={doc['mode']['effective']}: {'; '.join(doc['mode']['reasons'])}",
        f"  changed files: {doc['changed_files_total']}   direct: {', '.join(doc['affected_subsystems']['direct']) or '-'}",
    ]
    if doc["affected_subsystems"]["impacted"]:
        lines.append("  impacted: " + "; ".join(f"{i['id']} (via {' -> '.join(i['via'])})" for i in doc["affected_subsystems"]["impacted"]))
    lines.append("  coverage: " + "  ".join(f"{gate}={state}" for gate, state in doc["coverage"].items()))
    lines.append("CHECKS")
    for check in doc["checks"]:
        flag = "" if check["required"] else " (optional)"
        lines.append(f"  [{check['status']:<7}] {check['id']}{flag}: {check['summary']}")
        for finding in check.get("findings", [])[:10]:
            where = f"{finding['path']}:{finding['line']}" if finding.get("line") else finding["path"]
            lines.append(f"      - {finding['code']} {where}: {finding['message']}")
        if check["status"] in (CheckStatus.FAIL, CheckStatus.ERROR) and check.get("output_tail"):
            lines.extend("      | " + row for row in check["output_tail"].splitlines()[-15:])
    if doc["warnings"]:
        lines.append("WARNINGS")
        for warning in doc["warnings"]:
            lines.append(f"  - {warning['code']}: {warning['message']} ({', '.join(warning['paths'][:5])}{'…' if len(warning['paths']) > 5 else ''})")
    if doc["blocking_checks"]:
        lines.append("BLOCKING: " + ", ".join(doc["blocking_checks"]))
    for note in doc["notes"]:
        lines.append(f"note: {note}")
    return "\n".join(lines) + "\n"


def render_markdown(report: Tier3Report) -> str:
    """GitHub job summary: bounded, no secrets, no raw command output."""
    doc = report.to_dict()
    prov = doc["provenance"]
    icon = {"PASS": "✅", "PASS_WITH_WARNINGS": "⚠️", "FAIL": "❌", "INCOMPLETE": "❌"}[doc["result"]]
    out = [
        f"## Tier-3 validation: {icon} {doc['result']}", "",
        f"- **base** `{_sha(prov.get('base_sha'))}` · **head** `{_sha(prov.get('head_sha'))}` · **strategy** {prov.get('strategy')}"
        f" · **event** {prov.get('event') or 'local'}",
        f"- **mode** requested `{doc['mode']['requested']}`, effective `{doc['mode']['effective']}` — {'; '.join(doc['mode']['reasons'])}",
        f"- **changed files** {doc['changed_files_total']} · **direct** {', '.join(doc['affected_subsystems']['direct']) or '—'}",
    ]
    if doc["affected_subsystems"]["impacted"]:
        out.append("- **impacted** " + ", ".join(f"{i['id']}" for i in doc["affected_subsystems"]["impacted"]))
    out.append("- **coverage** " + " · ".join(f"{gate}: {state}" for gate, state in doc["coverage"].items()))
    out += ["", "| Check | Status | Why it ran / result |", "|---|---|---|"]
    for check in doc["checks"]:
        why = check["summary"]
        reason = (check["reasons"][0] if check["reasons"] else "")[:120]
        out.append(f"| `{check['id']}`{'' if check['required'] else ' (optional)'} | {check['status']} | {_cell(why)}<br><sub>{_cell(reason)}</sub> |")
    if doc["warnings"]:
        out += ["", "### Warnings"]
        out += [f"- **{w['code']}** — {w['message']} (`{'`, `'.join(w['paths'][:5])}`)" for w in doc["warnings"]]
    failing = [c for c in doc["checks"] if c["status"] in (CheckStatus.FAIL, CheckStatus.ERROR)]
    if failing:
        out += ["", "### Blocking"]
        for check in failing:
            out.append(f"- `{check['id']}` — {check['status']}: {_cell(check['summary'])}")
            for finding in check.get("findings", [])[:10]:
                out.append(f"  - {finding['code']} `{finding['path']}`{(':' + str(finding['line'])) if finding.get('line') else ''}")
    return "\n".join(out) + "\n"


def _cell(text: str) -> str:
    return redact.bound_string(text, 200).replace("|", "\\|").replace("\n", " ")
