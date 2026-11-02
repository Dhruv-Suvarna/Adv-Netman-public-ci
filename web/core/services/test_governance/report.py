"""Assemble the immutable test-governance evidence report (``test-governance-report.json``).

Inputs are files produced by ONE evidence run (trace JSON per suite, coverage JSON, Pylint json2) plus the repository
itself (inventory, AST symbols, capability ledger, policy, baseline).  The report is deterministic: the canonical
payload (everything except wall-clock timestamps and run identifiers) is hashed into ``payload_sha256``, so the same
source + tests + environment produce the same hash.
"""

from __future__ import annotations

import hashlib
import json
import time
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

from . import catalog as catalog_module, cells as cells_module, coverage_data, inventory as inventory_module, symbols as symbols_module
from .constants import (
    GENERATOR_VERSION, POLICY_FILE, BASELINE_FILE, REPO_ROOT, REPORT_SCHEMA_VERSION, ArtifactStatus, ArtifactType, CaseState,
    CellStatus, Disposition, Polarity, PylintStatus, Scope,
)
from .policy import Policy, default_policy
from .pylint_data import ArtifactLint

UNIT_KINDS = ("SYMBOL", "DECLARED", "TEMPLATE", "STRUCTURED", "EXECUTABLE")
COUNTED = (CaseState.PASS, CaseState.FAIL, CaseState.MISSING, CaseState.BROKEN_REFERENCE)
NON_CANONICAL = ("generated_at", "payload_sha256", "provenance")
COVERAGE_ONLY = "COVERAGE_ONLY"


def _tally(cases: list[dict]) -> dict:
    states = Counter(c["state"] for c in cases)
    required = sum(states[s] for s in COUNTED)
    return {"required": required, "pass": states[CaseState.PASS], "fail": states[CaseState.FAIL],
            "missing": states[CaseState.MISSING], "broken": states[CaseState.BROKEN_REFERENCE],
            "exempt": states[CaseState.EXEMPT], "not_current": states[CaseState.NOT_CURRENT_SCOPE],
            "debt": sum(1 for c in cases if c.get("debt"))}


def _status(pos: dict, neg: dict) -> str:
    required = pos["required"] + neg["required"]
    if not required:
        return COVERAGE_ONLY
    if pos["fail"] + neg["fail"] + pos["broken"] + neg["broken"]:
        return ArtifactStatus.FAILING
    passed = pos["pass"] + neg["pass"]
    if passed == required:
        return ArtifactStatus.CLOSED
    return ArtifactStatus.PARTIAL if passed else ArtifactStatus.MISSING


def _sum_cov(rows: list[dict]) -> dict:
    statements = sum(r["statements"] for r in rows)
    covered = sum(r["covered"] for r in rows)
    branches = sum(r["branches"] for r in rows)
    covered_b = sum(r["covered_branches"] for r in rows)
    return {"statements": statements, "covered": covered, "line_pct": coverage_data.pct(covered, statements),
            "branches": branches, "covered_branches": covered_b, "branch_pct": coverage_data.pct(covered_b, branches)}


def build_report(*, inventory, modules, cells, evidence, coverage_files: dict | None, lint: dict[str, ArtifactLint] | None,
                 baseline: dict | None = None, policy: Policy | None = None, provenance: dict | None = None,
                 repo: Path = REPO_ROOT, lint_ran: bool = True, coverage_ran: bool = True) -> dict:
    policy = policy or default_policy()
    baseline = baseline or {}
    result = catalog_module.build_catalog(inventory, modules, cells, evidence, baseline=baseline, policy=policy)
    tests, cases = result.tests, result.cases
    case_by_symbol: dict[str, list[dict]] = defaultdict(list)
    case_by_artifact: dict[str, list[dict]] = defaultdict(list)
    for item in cases:
        if item["symbol"]:
            case_by_symbol[item["symbol"]].append(item)
        if item["artifact"]:
            case_by_artifact[item["artifact"]].append(item)
    pylint_baseline = baseline.get("pylint") or {}

    artifacts_out = []
    for artifact in inventory.artifacts:
        row = artifact.to_dict()
        own = [c for c in case_by_artifact.get(artifact.id, []) if c["kind"] in UNIT_KINDS]
        pos = _tally([c for c in own if c["polarity"] == Polarity.POSITIVE])
        neg = _tally([c for c in own if c["polarity"] == Polarity.NEGATIVE])
        row["positive"], row["negative"] = pos, neg
        if artifact.scope == Scope.EXEMPT:
            row["status"] = ArtifactStatus.EXEMPT
        elif artifact.scope == Scope.NOT_CURRENT_SCOPE:
            row["status"] = ArtifactStatus.NOT_CURRENT_SCOPE
        else:
            row["status"] = _status(pos, neg)
        row["functions"] = {"required": 0, "tested": 0, "internal": 0, "internal_direct": 0, "exempt": 0}
        row["symbols"] = []
        row["coverage"] = None
        if artifact.type == ArtifactType.PYTHON:
            module = modules.get(artifact.path)
            fc = None
            if coverage_files is not None:
                fc = coverage_files.get(artifact.path) or coverage_data.unmeasured(artifact.path, repo)
                row["coverage"] = {**fc.figures(), "measured": fc.measured}
            for symbol in (module.symbols if module else []):
                own_cases = case_by_symbol.get(symbol.id, [])
                states = {c["polarity"]: c["state"] for c in own_cases if c["state"] != CaseState.EXEMPT}
                direct = any(c["state"] == CaseState.PASS for c in own_cases)
                sym_row = {**symbol.to_dict(), "positive": states.get(Polarity.POSITIVE, ""), "negative": states.get(Polarity.NEGATIVE, ""),
                           "tested": direct}
                if fc is not None:
                    figs = fc.figures(symbol.line_start, symbol.line_end)
                    sym_row["coverage"] = {k: figs[k] for k in ("statements", "covered", "line_pct", "branches", "covered_branches", "branch_pct")}
                row["symbols"].append(sym_row)
                if symbol.disposition == Disposition.EXEMPT:
                    row["functions"]["exempt"] += 1
                elif symbol.disposition == Disposition.INTERNAL:
                    row["functions"]["internal"] += 1
                elif artifact.scope == Scope.CURRENT:
                    row["functions"]["required"] += 1
                    row["functions"]["tested"] += int(direct)
            if lint is not None and artifact.scope != Scope.EXEMPT:
                entry = lint.get(artifact.path) or ArtifactLint(artifact.path)
                allowed = pylint_baseline.get(artifact.path)
                row["pylint"] = {"status": entry.status(allowed), "critical": entry.critical, "counts": dict(sorted(entry.counts.items())),
                                 "baseline": dict(sorted((allowed or {}).items())), "over_baseline": entry.over_baseline(allowed),
                                 "false_positives": entry.false_positives, "messages": entry.messages}
            else:
                row["pylint"] = {"status": PylintStatus.NOT_RUN if not lint_ran else PylintStatus.NOT_APPLICABLE}
        else:
            row["pylint"] = {"status": PylintStatus.NOT_APPLICABLE}
        artifacts_out.append(row)

    by_id = {a["id"]: a for a in artifacts_out}
    current_py = [a for a in artifacts_out if a["type"] == ArtifactType.PYTHON and a["scope"] == Scope.CURRENT and a["coverage"]]

    # -- generic groups -------------------------------------------------------------------------
    groups = []
    for group in [*policy.generic_groups]:
        members = [a for a in artifacts_out if a["group"] == group.id and a["scope"] == Scope.CURRENT]
        if not members:
            continue
        unit = [c for a in members for c in case_by_artifact.get(a["id"], []) if c["kind"] in UNIT_KINDS]
        statuses = Counter(a["status"] for a in members)
        counted = [a for a in members if a["status"] != COVERAGE_ONLY]
        groups.append({
            "id": group.id, "title": group.title, "artifacts": len(members), "artifacts_counted": len(counted),
            "artifacts_closed": statuses[ArtifactStatus.CLOSED], "statuses": dict(sorted(statuses.items())),
            "functions": {"required": sum(a["functions"]["required"] for a in members), "tested": sum(a["functions"]["tested"] for a in members)},
            "positive": _tally([c for c in unit if c["polarity"] == Polarity.POSITIVE]),
            "negative": _tally([c for c in unit if c["polarity"] == Polarity.NEGATIVE]),
            "coverage": _sum_cov([a["coverage"] for a in members if a["coverage"]]),
            "artifact_ids": [a["id"] for a in members],
        })

    # -- platform x feature cells ---------------------------------------------------------------
    cell_cases: dict[str, list[dict]] = defaultdict(list)
    for item in cases:
        if item["kind"] == "CELL":
            cell_cases[f"{item['platform']}|{item['feature']}"].append(item)
    cells_out = []
    for cell in cells:
        own = cell_cases.get(cell.key, [])
        sources = [a for a in artifacts_out if a["platform"] == cell.platform and (not a["features"] or cell.feature in a["features"])
                   and a["scope"] != Scope.EXEMPT]
        shared = [a for a in artifacts_out if a["path"] == "web/core/services/platform_drivers.py"]
        pos = _tally([c for c in own if c["polarity"] == Polarity.POSITIVE])
        neg = _tally([c for c in own if c["polarity"] == Polarity.NEGATIVE])
        if not cell.supported:
            status = CellStatus.UNSUPPORTED if any("PLATFORM_DOES_NOT_SUPPORT" == r for r in cell.reasons) else CellStatus.NOT_IMPLEMENTED
        else:
            status = {ArtifactStatus.CLOSED: CellStatus.CLOSED, ArtifactStatus.PARTIAL: CellStatus.PARTIAL,
                      ArtifactStatus.FAILING: CellStatus.FAILING}.get(_status(pos, neg), CellStatus.MISSING)
        code_rows = [a for a in sources + shared if a["type"] == ArtifactType.PYTHON and a["coverage"]]
        cells_out.append({
            "platform": cell.platform, "feature": cell.feature, "final_status": cell.final_status, "status": status,
            "stages": list(cell.stages), "positive": pos, "negative": neg, "case_ids": [c["id"] for c in own],
            "artifacts": [a["id"] for a in sources + shared],
            "functions": {"required": sum(a["functions"]["required"] for a in code_rows), "tested": sum(a["functions"]["tested"] for a in code_rows)},
            "coverage": _sum_cov([a["coverage"] for a in code_rows]) if code_rows else None,
            "reasons": list(cell.reasons)[:6],
        })

    # -- summary --------------------------------------------------------------------------------
    unit_cases = [c for c in cases if c["kind"] in UNIT_KINDS]
    outcomes = Counter(t["outcome"] for t in tests)
    current_artifacts = [a for a in artifacts_out if a["scope"] == Scope.CURRENT]
    art_status = Counter(a["status"] for a in artifacts_out)
    supported = [c for c in cells_out if c["final_status"] == cells_module.SUPPORTED]
    pylint_rows = [a["pylint"] for a in artifacts_out if a["type"] == ArtifactType.PYTHON and a["scope"] != Scope.EXEMPT]
    pylint_status = Counter(p["status"] for p in pylint_rows)
    summary = {
        "tests": {"total": len(tests), **{k.lower(): v for k, v in sorted(outcomes.items())}},
        "positive": _tally([c for c in unit_cases if c["polarity"] == Polarity.POSITIVE]),
        "negative": _tally([c for c in unit_cases if c["polarity"] == Polarity.NEGATIVE]),
        "artifacts": {
            "discovered": len(artifacts_out), "current": len(current_artifacts),
            "counted": sum(1 for a in current_artifacts if a["status"] != COVERAGE_ONLY),
            "closed": art_status[ArtifactStatus.CLOSED], "partial": art_status[ArtifactStatus.PARTIAL],
            "missing": art_status[ArtifactStatus.MISSING], "failing": art_status[ArtifactStatus.FAILING],
            "coverage_only": art_status[COVERAGE_ONLY], "exempt": art_status[ArtifactStatus.EXEMPT],
            "not_current": art_status[ArtifactStatus.NOT_CURRENT_SCOPE],
            "by_type": dict(sorted(Counter(a["type"] for a in artifacts_out).items())),
        },
        "functions": {"required": sum(a["functions"]["required"] for a in current_artifacts),
                      "tested": sum(a["functions"]["tested"] for a in current_artifacts),
                      "internal": sum(a["functions"]["internal"] for a in current_artifacts),
                      "exempt": sum(a["functions"]["exempt"] for a in current_artifacts),
                      "symbols": sum(len(a["symbols"]) for a in artifacts_out if a["type"] == ArtifactType.PYTHON)},
        "coverage": _sum_cov([a["coverage"] for a in current_py]) if coverage_ran else None,
        "cells": {"total": len(cells_out), "supported": len(supported),
                  "closed": sum(c["status"] == CellStatus.CLOSED for c in supported),
                  "partial": sum(c["status"] == CellStatus.PARTIAL for c in supported),
                  "missing": sum(c["status"] == CellStatus.MISSING for c in supported),
                  "failing": sum(c["status"] == CellStatus.FAILING for c in supported),
                  "positive": _tally([c for c in cases if c["kind"] == "CELL" and c["polarity"] == Polarity.POSITIVE]),
                  "negative": _tally([c for c in cases if c["kind"] == "CELL" and c["polarity"] == Polarity.NEGATIVE])},
        "pylint": {"ran": lint_ran, "status": (PylintStatus.FAIL if pylint_status[PylintStatus.FAIL] else PylintStatus.WARN
                                                 if pylint_status[PylintStatus.WARN] else PylintStatus.PASS) if lint_ran else PylintStatus.NOT_RUN,
                   "artifacts": dict(sorted(pylint_status.items())),
                   "critical": sum(p.get("critical", 0) for p in pylint_rows),
                   "messages": sum(sum((p.get("counts") or {}).values()) for p in pylint_rows)},
        "catalog_errors": len(result.errors),
    }
    report = {
        "schema_version": REPORT_SCHEMA_VERSION, "generator_version": GENERATOR_VERSION,
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "provenance": dict(provenance or {}),
        "repository_sha": (provenance or {}).get("repository_sha", ""),
        "source_fingerprint": (provenance or {}).get("source_fingerprint", ""),
        "summary": summary, "artifacts": artifacts_out, "cases": cases, "tests": tests, "cells": cells_out, "groups": groups,
        "examples": _examples(policy, by_id, cases),
        "catalog_errors": result.errors, "sessions": evidence.sessions,
        "inputs": {"policy_sha256": _file_sha(POLICY_FILE), "baseline_sha256": _file_sha(BASELINE_FILE),
                   "ledger_sha256": _file_sha(cells_module.CAPABILITY_LEDGER)},
    }
    report["payload_sha256"] = payload_hash(report)
    return report


def _file_sha(path: Path) -> str:
    try:
        return hashlib.sha256(Path(path).read_bytes()).hexdigest()
    except OSError:
        return ""


def _examples(policy: Policy, by_id: dict, cases: list[dict]) -> list[dict]:
    """The Lab 7 assignment examples (IP validation, connectivity, ...) mapped to the real NMAS symbols (policy.yml)."""
    out = []
    by_symbol: dict[str, list[dict]] = defaultdict(list)
    for item in cases:
        if item["symbol"]:
            by_symbol[item["symbol"]].append(item)
    for example in policy.assignment_examples:
        rows = []
        for target in example["targets"]:
            own = by_symbol.get(target, [])
            artifact_path = target.split("::", 1)[0]
            artifact = next((a for a in by_id.values() if a["path"] == artifact_path), None)
            rows.append({"target": target, "artifact": artifact["id"] if artifact else "",
                         "states": {c["polarity"]: c["state"] for c in own}, "cases": [c["id"] for c in own],
                         "exists": artifact is not None})
        out.append({"requirement": example["requirement"], "description": example["description"], "targets": rows})
    return out


def canonical(report: dict) -> bytes:
    core = {k: v for k, v in report.items() if k not in NON_CANONICAL}
    return json.dumps(core, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def payload_hash(report: dict) -> str:
    return hashlib.sha256(canonical(report)).hexdigest()


def write_report(report: dict, path: Path) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(report, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
    tmp.replace(path)


def load_traces(paths: list[Path]) -> catalog_module.Evidence:
    traces = []
    for path in paths:
        traces.append(json.loads(Path(path).read_text(encoding="utf-8")))
    return catalog_module.Evidence.from_traces(traces)


def assemble(*, trace_paths: list[Path], coverage_json: Path | None, pylint_json: Path | None, baseline: dict | None,
             provenance: dict | None = None, repo: Path = REPO_ROOT, linted: list[str] | None = None) -> dict:
    """Everything from files on disk: the one entry point used by the management command and Tier-3."""
    from .pylint_data import parse_pylint

    policy = default_policy()
    inv = inventory_module.build_inventory(repo, policy=policy)
    py_paths = [a.path for a in inv.artifacts if a.type == ArtifactType.PYTHON]
    modules = symbols_module.inventory_symbols(py_paths, repo, policy=policy)
    cell_rows = cells_module.load_cells()
    evidence = load_traces(trace_paths)
    coverage_files = None
    if coverage_json is not None:
        coverage_files = coverage_data.parse_coverage_json(json.loads(Path(coverage_json).read_text(encoding="utf-8")), repo=repo)
    lint = None
    if pylint_json is not None:
        lint = parse_pylint(json.loads(Path(pylint_json).read_text(encoding="utf-8")), policy=policy, repo=repo, linted=linted)
    provenance = dict(provenance or {})
    provenance.setdefault("repository_sha", inventory_module.head_sha(repo))
    provenance.setdefault("source_fingerprint", evidence_fingerprint(inv, repo))
    provenance.setdefault("generated_unix", int(time.time()))
    return build_report(inventory=inv, modules=modules, cells=cell_rows, evidence=evidence, coverage_files=coverage_files, lint=lint,
                        baseline=baseline, policy=policy, provenance=provenance, repo=repo, lint_ran=lint is not None,
                        coverage_ran=coverage_files is not None)


def evidence_fingerprint(inv, repo: Path = REPO_ROOT) -> str:
    return inventory_module.fingerprint(inv, repo, extra=(POLICY_FILE, BASELINE_FILE, cells_module.CAPABILITY_LEDGER,
                                                          repo / ".pylintrc", repo / ".coveragerc"))
