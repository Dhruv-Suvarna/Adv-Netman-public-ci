"""Current-scope closure gate and the tracked baseline (ratchet).

The gate FAILS when (current scope only):

    CASE_FAILED          a required positive / negative case's test failed or errored
    CASE_MISSING_NEW     a required case is missing and is NOT recorded debt (new code cannot add silent debt)
    BROKEN_REFERENCE     a locked declared case is no longer declared by any test
    CATALOG_ERROR        malformed declaration, broken target, unclassified artifact, duplicate case id
    ARTIFACT_DISAPPEARED a deployed artifact recorded in the baseline no longer exists (update the baseline deliberately)
    CLOSED_REGRESSION    an artifact / cell the baseline records as closed is no longer closed
    PYLINT_CRITICAL      any critical Pylint message
    PYLINT_NEW_DEBT      an artifact has more non-critical Pylint messages than its baseline
    NO_TESTS             the evidence run executed no test
    NO_COVERAGE          coverage collection produced no data

It WARNS (non-blocking) when recorded debt has been paid (``DEBT_RESOLVED``: tighten the baseline) or when known
debt remains (``KNOWN_DEBT``: shown with the exact count so it stays visible).
"""

from __future__ import annotations

import json
from pathlib import Path

from .constants import BASELINE_FILE, ArtifactStatus, CaseState, CellStatus, PylintStatus, Scope

PASS, PASS_WITH_DEBT, FAIL = "PASS", "PASS_WITH_DEBT", "FAIL"
BASELINE_SCHEMA = 1
MAX_IDS = 40


def load_baseline(path: Path | None = None) -> dict:
    target = Path(path or BASELINE_FILE)
    if not target.is_file():
        return {}
    data = json.loads(target.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or data.get("schema_version") != BASELINE_SCHEMA:
        raise ValueError("baseline.json schema_version must be 1")
    return data


def baseline_from_report(report: dict) -> dict:
    """The ratchet: today's measured state becomes the allowance.  Debt can only shrink from here."""
    cases = report["cases"]
    return {
        "schema_version": BASELINE_SCHEMA,
        "from_repository_sha": report.get("repository_sha", ""),
        "from_payload_sha256": report.get("payload_sha256", ""),
        "artifacts": sorted(a["id"] for a in report["artifacts"]),
        "closed_artifacts": sorted(a["id"] for a in report["artifacts"] if a["status"] == ArtifactStatus.CLOSED),
        "closed_cells": sorted(f"{c['platform']}|{c['feature']}" for c in report["cells"] if c["status"] == CellStatus.CLOSED),
        "case_debt": sorted(c["id"] for c in cases if c["state"] == CaseState.MISSING and c["scope"] == Scope.CURRENT),
        # generated requirements (TPL / CFG / EXE / CELL / SYM) are re-derived on every run; only explicit declarations are locked
        "declared_cases": {c["id"]: (c["symbol"] or c["artifact"].split(":", 1)[-1]) for c in cases if c["kind"] == "DECLARED"},
        "pylint": {a["path"]: a["pylint"]["counts"] for a in report["artifacts"]
                   if a.get("pylint", {}).get("counts")},
    }


def write_baseline(baseline: dict, path: Path | None = None) -> None:
    target = Path(path or BASELINE_FILE)
    target.write_text(json.dumps(baseline, sort_keys=True, indent=1) + "\n", encoding="utf-8")


def evaluate(report: dict, baseline: dict) -> dict:
    findings: list[dict] = []

    def add(code: str, severity: str, message: str, ids: list[str] | None = None) -> None:
        ids = sorted(ids or [])
        findings.append({"code": code, "severity": severity, "message": message, "count": len(ids), "ids": ids[:MAX_IDS]})

    current = [c for c in report["cases"] if c["scope"] == Scope.CURRENT]
    failed = [c["id"] for c in current if c["state"] == CaseState.FAIL]
    if failed:
        add("CASE_FAILED", "FAIL", f"{len(failed)} required case(s) are proven only by failing tests", failed)
    missing = [c for c in current if c["state"] == CaseState.MISSING]
    new = [c["id"] for c in missing if not c["debt"]]
    if new:
        add("CASE_MISSING_NEW", "FAIL", f"{len(new)} required case(s) have no passing test and are not recorded debt", new)
    debt = [c["id"] for c in missing if c["debt"]]
    if debt:
        add("KNOWN_DEBT", "WARN", f"{len(debt)} required case(s) are known, tracked debt (baseline.json)", debt)
    broken = [c["id"] for c in current if c["state"] == CaseState.BROKEN_REFERENCE]
    if broken:
        add("BROKEN_REFERENCE", "FAIL", f"{len(broken)} locked declared case(s) are no longer declared by any test", broken)
    if report.get("catalog_errors"):
        add("CATALOG_ERROR", "FAIL", f"{len(report['catalog_errors'])} catalog error(s)", report["catalog_errors"])
    if baseline:
        present = {a["id"] for a in report["artifacts"]}
        gone = sorted(set(baseline.get("artifacts") or ()) - present)
        if gone:
            add("ARTIFACT_DISAPPEARED", "FAIL", f"{len(gone)} baseline artifact(s) no longer exist", gone)
        status = {a["id"]: a["status"] for a in report["artifacts"]}
        regressed = [a for a in baseline.get("closed_artifacts") or () if a in status and status[a] != ArtifactStatus.CLOSED]
        if regressed:
            add("CLOSED_REGRESSION", "FAIL", f"{len(regressed)} previously closed artifact(s) are no longer closed", regressed)
        cell_status = {f"{c['platform']}|{c['feature']}": c["status"] for c in report["cells"]}
        cells_regressed = [c for c in baseline.get("closed_cells") or () if cell_status.get(c) != CellStatus.CLOSED]
        if cells_regressed:
            add("CLOSED_REGRESSION", "FAIL", f"{len(cells_regressed)} previously closed capability cell(s) are no longer closed", cells_regressed)
        paid = sorted(set(baseline.get("case_debt") or ()) & {c["id"] for c in report["cases"] if c["state"] == CaseState.PASS})
        if paid:
            add("DEBT_RESOLVED", "WARN", f"{len(paid)} recorded debt case(s) now pass: tighten the baseline", paid)
    pylint_summary = report["summary"].get("pylint") or {}
    if pylint_summary.get("ran"):
        critical = [a["id"] for a in report["artifacts"] if (a.get("pylint") or {}).get("critical")]
        if critical:
            add("PYLINT_CRITICAL", "FAIL", f"{len(critical)} artifact(s) have critical Pylint messages", critical)
        over = [a["id"] for a in report["artifacts"] if (a.get("pylint") or {}).get("over_baseline")]
        if over:
            add("PYLINT_NEW_DEBT", "FAIL", f"{len(over)} artifact(s) exceed their tracked Pylint baseline", over)
        warn = [a["id"] for a in report["artifacts"] if (a.get("pylint") or {}).get("status") == PylintStatus.WARN]
        if warn:
            add("PYLINT_KNOWN_DEBT", "WARN", f"{len(warn)} artifact(s) carry tracked non-critical Pylint messages", warn)
    if not report["summary"]["tests"]["total"]:
        add("NO_TESTS", "FAIL", "the evidence run executed no test")
    if report["summary"].get("coverage") is None or not report["summary"]["coverage"].get("statements"):
        add("NO_COVERAGE", "FAIL", "coverage collection produced no statement data")
    result = FAIL if any(f["severity"] == "FAIL" for f in findings) else PASS_WITH_DEBT if debt or any(
        f["code"] == "PYLINT_KNOWN_DEBT" for f in findings) else PASS
    return {"result": result, "findings": findings}
