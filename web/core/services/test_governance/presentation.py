"""Page models for the read-only NMAS governance pages, built from ONE verified evidence report (no I/O beyond evidence).

    unit_matrix(selected, filters)   Unit Test Matrix: summary cards + artifact rows (Negative | Positive) with expansions
    artifact_detail(selected, id)    one artifact: classification, Pylint, symbols, coverage, every case with its tests
    coverage_matrix(selected)        Code Coverage: platform x feature grid + the generic / control-plane groups
    cell_detail(selected, p, f)      one capability cell: stages, cases, source artifacts, functions, coverage

Nothing here runs a test, an AST scan, coverage.py or Pylint: those happened in Tier-3 / the evidence command.
"""

from __future__ import annotations

from collections import defaultdict

from . import coverage_data
from .catalog import SYMBOL_TEXT
from .constants import CELL_STAGES, ArtifactStatus, ArtifactType, Basis, CaseState, CellStatus, Freshness, Polarity, Scope

BASIS_LABELS = {
    Basis.DECLARED: "declared case", Basis.DIRECT_RETURN: "direct call returned", Basis.DIRECT_RAISE: "direct call raised (refusal)",
    Basis.DIRECT_REFUSAL: "direct call, refusal context", Basis.STATIC: "static check",
}
STATE_BADGE = {
    CaseState.PASS: "success", CaseState.FAIL: "danger", CaseState.MISSING: "warning", CaseState.BROKEN_REFERENCE: "danger",
    CaseState.EXEMPT: "neutral", CaseState.NOT_CURRENT_SCOPE: "not-implemented",
}
STATUS_BADGE = {
    ArtifactStatus.CLOSED: "success", ArtifactStatus.PARTIAL: "warning", ArtifactStatus.MISSING: "danger", ArtifactStatus.FAILING: "critical",
    ArtifactStatus.EXEMPT: "neutral", ArtifactStatus.NOT_CURRENT_SCOPE: "not-implemented", "COVERAGE_ONLY": "info",
    CellStatus.NOT_IMPLEMENTED: "not-implemented", CellStatus.UNSUPPORTED: "neutral",
}
FILTERS = ("subsystem", "group", "type", "platform", "feature", "status", "polarity_missing", "pylint", "scope", "q")
REFRESH_TEXT = {
    "ACCEPTED": "Refreshed: the Tier-3 evidence for the deployed commit was verified and accepted.",
    "TIER3_RUN_NOT_FOUND": "Refresh: GitHub has no completed Tier-3 run for the deployed commit yet.",
    "EVIDENCE_ARTIFACT_NOT_FOUND": "Refresh: the Tier-3 runs for the deployed commit carry no test-governance artifact (only full runs produce one).",
    "EVIDENCE_RUN_MISMATCH": "Refresh refused: the artifact does not belong to that run / commit.",
    "EVIDENCE_HASH_MISMATCH": "Refresh refused: the artifact's payload hash does not verify.",
    "GITHUB_NOT_CONFIGURED": "Refresh: no GitHub token is provisioned for this NMAS instance.",
    "GITHUB_UNREACHABLE": "Refresh: GitHub is unreachable. The last accepted evidence is still shown.",
}
MAX_ROWS = 800


def badge(state: str) -> str:
    return STATE_BADGE.get(state) or STATUS_BADGE.get(state) or "neutral"


def pct(x: int, y: int) -> float | None:
    return round(100.0 * x / y, 1) if y else None


def header(selected: dict) -> dict:
    report = selected.get("report") or {}
    deployed = selected.get("deployed") or {}
    provenance = report.get("provenance") or {}
    run_id = provenance.get("run_id") or ""
    repository = provenance.get("repository") or ""
    return {
        "freshness": selected.get("freshness", Freshness.NONE), "reason": selected.get("reason", ""),
        "freshness_badge": {"CURRENT": "success", "STALE": "danger", "UNKNOWN": "warning"}.get(selected.get("freshness"), "neutral"),
        "tested_sha": report.get("repository_sha", ""), "deployed_sha": deployed.get("sha", ""),
        "fingerprint_match": bool(report) and report.get("source_fingerprint") == deployed.get("fingerprint"),
        "generated_at": report.get("generated_at", ""), "payload_sha256": report.get("payload_sha256", ""),
        "source": selected.get("source", ""), "accepted_at": selected.get("accepted_at", ""),
        "run_id": run_id, "run_url": f"https://github.com/{repository}/actions/runs/{run_id}" if run_id and repository else "",
        "mode": provenance.get("mode", ""), "gate": (report.get("gate") or {}).get("result", ""),
        "generator": report.get("generator_version", ""), "schema": report.get("schema_version", ""),
        "refused": selected.get("refused") or [],
    }


def refresh_message(code: str) -> str:
    code = str(code or "")[:60]
    if not code:
        return ""
    return REFRESH_TEXT.get(code, f"Refresh: no newer evidence accepted ({code}). The last accepted evidence is still shown.")


def summary_cards(report: dict) -> dict:
    s = report["summary"]
    pos, neg, art, fn, cov, cells, lint = s["positive"], s["negative"], s["artifacts"], s["functions"], s.get("coverage") or {}, s["cells"], s["pylint"]
    return {
        "positive": {**pos, "pct": pct(pos["pass"], pos["required"])},
        "negative": {**neg, "pct": pct(neg["pass"], neg["required"])},
        "artifacts": {**art, "pct": pct(art["closed"], art["counted"])},
        "functions": {**fn, "pct": pct(fn["tested"], fn["required"])},
        "coverage": cov,
        "cells": {**cells, "pct": pct(cells["closed"], cells["supported"])},
        "pylint": lint, "tests": s["tests"], "catalog_errors": s.get("catalog_errors", 0),
        "debt": pos["debt"] + neg["debt"],
    }


def _test_rows(report: dict, entries: list) -> list[dict]:
    tests = report["tests"]
    out = []
    for index, basis in entries:
        if 0 <= int(index) < len(tests):
            test = tests[int(index)]
            out.append({"id": test["id"], "outcome": test["outcome"], "basis": BASIS_LABELS.get(basis, basis), "file": test.get("file", ""),
                        "line": test.get("line", 0)})
    return out


def case_view(report: dict, item: dict, symbols: dict | None = None) -> dict:
    condition, expected = item.get("condition", ""), item.get("expected", "")
    title = item.get("title", "")
    if item["kind"] == "SYMBOL":
        qualname = item["symbol"].split("::", 1)[-1] if item["symbol"] else ""
        if item["state"] == CaseState.EXEMPT:
            title = f"{qualname}() -- exempt"
        else:
            condition, expected = SYMBOL_TEXT[item["polarity"]]
            title = f"{qualname}() {'accepts ' + condition if item['polarity'] == Polarity.POSITIVE else 'refuses ' + condition}"
    return {**item, "title": title or item["id"], "condition": condition, "expected": expected, "badge": badge(item["state"]),
            "tests": _test_rows(report, item.get("evidence") or [])}


def _index(report: dict):
    by_artifact = defaultdict(list)
    for item in report["cases"]:
        if item["artifact"] and item["kind"] != "CELL":
            by_artifact[item["artifact"]].append(item)
    return by_artifact


def filter_options(report: dict) -> dict:
    arts = report["artifacts"]
    return {
        "subsystems": sorted({s for a in arts for s in a["subsystems"]}),
        "groups": sorted({(a["group"], a["group_title"]) for a in arts}),
        "types": sorted({a["type"] for a in arts}),
        "platforms": sorted({a["platform"] for a in arts if a["platform"]}),
        "features": sorted({f for a in arts for f in a["features"]}),
        "statuses": [ArtifactStatus.CLOSED, ArtifactStatus.PARTIAL, ArtifactStatus.MISSING, ArtifactStatus.FAILING, "COVERAGE_ONLY",
                     ArtifactStatus.EXEMPT, ArtifactStatus.NOT_CURRENT_SCOPE],
    }


def _matches(artifact: dict, filters: dict) -> bool:
    if filters.get("scope", "current") == "current" and artifact["scope"] != Scope.CURRENT:
        return False
    if filters.get("subsystem") and filters["subsystem"] not in artifact["subsystems"]:
        return False
    if filters.get("group") and artifact["group"] != filters["group"]:
        return False
    if filters.get("type") and artifact["type"] != filters["type"]:
        return False
    if filters.get("platform") and artifact["platform"] != filters["platform"]:
        return False
    if filters.get("feature") and filters["feature"] not in artifact["features"]:
        return False
    status = filters.get("status")
    if status == "INCOMPLETE" and artifact["status"] not in (ArtifactStatus.PARTIAL, ArtifactStatus.MISSING, ArtifactStatus.FAILING):
        return False
    if status and status != "INCOMPLETE" and artifact["status"] != status:
        return False
    missing = filters.get("polarity_missing")
    if missing == "positive" and not (artifact["positive"]["missing"] + artifact["positive"]["fail"]):
        return False
    if missing == "negative" and not (artifact["negative"]["missing"] + artifact["negative"]["fail"]):
        return False
    pylint = filters.get("pylint")
    if pylint and (artifact.get("pylint") or {}).get("status") != pylint:
        return False
    query = (filters.get("q") or "").strip().lower()
    return not query or query in artifact["path"].lower()


def clean_filters(raw) -> dict:
    out = {}
    for key in FILTERS:
        value = str(raw.get(key, "") or "").strip()[:120]
        if value:
            out[key] = value
    out.setdefault("scope", "current")
    if out["scope"] not in ("current", "all"):
        out["scope"] = "current"
    return out


_STATE_ORDER = {CaseState.FAIL: 0, CaseState.BROKEN_REFERENCE: 0, CaseState.MISSING: 1, CaseState.PASS: 2, CaseState.EXEMPT: 3}


def _case_order(view: dict) -> tuple:
    """Failing first, then missing, passing, exempt; ties by title."""
    return (_STATE_ORDER.get(view["state"], 4), view["title"])


def unit_matrix(selected: dict, raw_filters) -> dict:
    report = selected.get("report")
    page = {"header": header(selected), "filters": clean_filters(raw_filters), "report": bool(report)}
    if not report:
        return page
    by_artifact = _index(report)
    rows = []
    for artifact in report["artifacts"]:
        if not _matches(artifact, page["filters"]):
            continue
        own = by_artifact.get(artifact["id"], [])
        pos = [case_view(report, c) for c in own if c["polarity"] == Polarity.POSITIVE]
        neg = [case_view(report, c) for c in own if c["polarity"] == Polarity.NEGATIVE]
        pos.sort(key=_case_order)
        neg.sort(key=_case_order)
        rows.append({"artifact": artifact, "status_badge": badge(artifact["status"]), "positive": pos, "negative": neg,
                     "pos": artifact["positive"], "neg": artifact["negative"]})
    severity = {ArtifactStatus.FAILING: 0, ArtifactStatus.MISSING: 1, ArtifactStatus.PARTIAL: 2, "COVERAGE_ONLY": 3, ArtifactStatus.CLOSED: 4}
    rows.sort(key=lambda r: (severity.get(r["artifact"]["status"], 5), r["artifact"]["path"]))
    page.update({"cards": summary_cards(report), "rows": rows[:MAX_ROWS], "rows_total": len(rows), "truncated": len(rows) > MAX_ROWS,
                 "options": filter_options(report), "gate": report.get("gate") or {}, "examples": examples(report)})
    return page


def examples(report: dict) -> list[dict]:
    out = []
    for example in report.get("examples") or []:
        targets = []
        for target in example["targets"]:
            states = target.get("states") or {}
            targets.append({**target, "positive": states.get(Polarity.POSITIVE, ""), "negative": states.get(Polarity.NEGATIVE, ""),
                            "positive_badge": badge(states.get(Polarity.POSITIVE, "")), "negative_badge": badge(states.get(Polarity.NEGATIVE, ""))})
        out.append({**example, "targets": targets})
    return out


def artifact_detail(selected: dict, artifact_id: str) -> dict | None:
    report = selected.get("report")
    if not report:
        return None
    artifact = next((a for a in report["artifacts"] if a["id"] == artifact_id), None)
    if artifact is None:
        return None
    own = [case_view(report, c) for c in _index(report).get(artifact_id, [])]
    by_symbol = defaultdict(list)
    for item in own:
        if item["symbol"]:
            by_symbol[item["symbol"]].append(item)
    symbols = [{**s, "cases": by_symbol.get(s["id"], []), "disposition_label": s["disposition"].replace("_", " ").title()}
               for s in artifact.get("symbols") or []]
    return {"header": header(selected), "artifact": artifact, "status_badge": badge(artifact["status"]),
            "positive": [c for c in own if c["polarity"] == Polarity.POSITIVE],
            "negative": [c for c in own if c["polarity"] == Polarity.NEGATIVE],
            "missing": [c for c in own if c["state"] in (CaseState.MISSING, CaseState.FAIL, CaseState.BROKEN_REFERENCE)],
            "exempt": [c for c in own if c["state"] == CaseState.EXEMPT],
            "symbols": symbols, "is_python": artifact["type"] == ArtifactType.PYTHON,
            "cells": [c for c in report["cells"] if artifact_id in (c.get("artifacts") or ())][:60]}


PLATFORM_SCOPE_NOTE = ("Runtime coverage figures are aggregated across the platform's Python production artifacts recorded for its "
                       "supported cells -- its parser and executor modules and the shared platform driver module. They are not "
                       "isolated coverage for any individual feature.")


def platform_coverage(report: dict) -> dict:
    """{platform: functions / statements / branches} over the union of the Python artifacts of its SUPPORTED cells.

    Each figure is the platform's aggregate runtime coverage, never a feature's own: every supported cell of a platform
    draws on the same parser / executor / shared-driver modules.  Values come from the report's artifact rows only.
    """
    by_id = {a["id"]: a for a in report.get("artifacts") or ()}
    members: dict[str, set] = defaultdict(set)
    for cell in report.get("cells") or ():
        if cell.get("final_status") == "SUPPORTED":
            members[cell["platform"]].update(cell.get("artifacts") or ())
    out = {}
    for platform, ids in members.items():
        rows = [by_id[i] for i in sorted(ids) if i in by_id and by_id[i]["type"] == ArtifactType.PYTHON and by_id[i].get("coverage")]
        statements, covered = sum(r["coverage"]["statements"] for r in rows), sum(r["coverage"]["covered"] for r in rows)
        branches, covered_b = sum(r["coverage"]["branches"] for r in rows), sum(r["coverage"]["covered_branches"] for r in rows)
        out[platform] = {"artifacts": len(rows),
                         "functions": {"tested": sum(r["functions"]["tested"] for r in rows),
                                       "required": sum(r["functions"]["required"] for r in rows)},
                         "line_pct": coverage_data.pct(covered, statements) if rows else None,
                         "branch_pct": coverage_data.pct(covered_b, branches) if rows else None}
    return out


def coverage_matrix(selected: dict, *, show_all: bool = False) -> dict:
    report = selected.get("report")
    page = {"header": header(selected), "report": bool(report), "show_all": show_all}
    if not report:
        return page
    cells = report["cells"]
    platforms = sorted({c["platform"] for c in cells})
    features = sorted({c["feature"] for c in cells}, key=lambda f: (f.split(".")[0] != "interface", f.split(".")[0] != "routing", f))
    grid = {(c["platform"], c["feature"]): c for c in cells}
    rows = []
    for feature in features:
        row_cells = []
        for platform in platforms:
            cell = grid.get((platform, feature))
            if cell is None:
                row_cells.append(None)
                continue
            pos, neg = cell["positive"], cell["negative"]
            required = pos["required"] + neg["required"]
            row_cells.append({**cell, "badge": badge(cell["status"]), "cases_pct": pct(pos["pass"] + neg["pass"], required),
                              "line_pct": (cell.get("coverage") or {}).get("line_pct")})
        supported = any(c and c["final_status"] == "SUPPORTED" for c in row_cells)
        if supported or show_all:   # by default only features with at least one currently implemented cell
            rows.append({"feature": feature, "cells": row_cells, "supported": supported})
    totals = platform_coverage(report)
    page.update({"platforms": platforms, "rows": rows, "groups": report.get("groups") or [], "cards": summary_cards(report),
                 "stages": [title for _k, title in CELL_STAGES],
                 "platform_columns": [{"platform": p, "coverage": totals.get(p)} for p in platforms],
                 "platform_scope_note": PLATFORM_SCOPE_NOTE})
    return page


def cell_detail(selected: dict, platform: str, feature: str) -> dict | None:
    report = selected.get("report")
    if not report:
        return None
    cell = next((c for c in report["cells"] if c["platform"] == platform and c["feature"] == feature), None)
    if cell is None:
        return None
    cases = [case_view(report, c) for c in report["cases"] if c["kind"] == "CELL" and c["platform"] == platform and c["feature"] == feature]
    stage_titles = dict(CELL_STAGES)
    stages = []
    for stage, title in CELL_STAGES:
        own = [c for c in cases if c["stage"] == stage]
        stages.append({"stage": stage, "title": title, "implemented": stage in cell["stages"],
                       "positive": next((c for c in own if c["polarity"] == Polarity.POSITIVE), None),
                       "negative": next((c for c in own if c["polarity"] == Polarity.NEGATIVE), None)})
    by_id = {a["id"]: a for a in report["artifacts"]}
    artifacts = [by_id[i] for i in cell.get("artifacts") or () if i in by_id]
    pos, neg = cell["positive"], cell["negative"]
    return {"header": header(selected), "cell": cell, "badge": badge(cell["status"]), "stages": stages, "artifacts": artifacts,
            "stage_titles": stage_titles, "closure_pct": pct(pos["pass"] + neg["pass"], pos["required"] + neg["required"]),
            "platform_coverage": platform_coverage(report).get(platform), "platform_scope_note": PLATFORM_SCOPE_NOTE}
