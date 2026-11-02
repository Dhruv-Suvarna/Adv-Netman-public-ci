"""Batch assessment of whole platforms / feature families of the capability matrix.

One execution deliberately assesses every selected cell:

1. the real offline application probes run for the cell (``offline_verify``);
2. the prerequisite gate inspects the NMAS layers an operator-driven live write
   needs (model, renderer, candidate, registered executor).  If one is missing
   the live stages are recorded BLOCKED with that exact reason and a ``gate:``
   reference to the cell's own offline evidence.  No runtime is contacted merely
   to re-prove an absent renderer or executor;
3. a cell that survives the gate is only assessed by a registered isolated live
   probe (``--isolated-live --allow-write``); otherwise it stays unassessed.

Already complete assessments are kept unless a re-assessment is requested, so a
batch never replaces live evidence with a weaker offline record.
"""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from dataclasses import dataclass, field

from . import assessment, features, vocabulary
from .offline_verify import verify_cell

KEPT, GATED, LIVE, PENDING_LIVE, LIVE_ERROR = "KEPT", "GATED", "LIVE", "PENDING_LIVE", "LIVE_ERROR"
FINAL_FORBIDDEN = frozenset({"UNKNOWN", "NOT_TESTED", "NOT_ASSESSED", "PENDING", ""})


def select(platform="all", feature="all", *, family="", match="") -> tuple[tuple[str, ...], tuple[str, ...]]:
    """Resolve a platform / feature / family / substring selection to matrix axes."""
    plats = features.platforms() if platform == "all" else (platform,)
    catalogue = features.by_key()
    keys = tuple(catalogue) if feature == "all" else (feature,)
    if family:
        keys = tuple(k for k in keys if catalogue[k].family == family)
    if match:
        keys = tuple(k for k in keys if match.upper() in k.upper())
    if not keys or any(p not in features.platforms() for p in plats) or any(k not in catalogue for k in keys):
        raise ValueError("Selection does not name any current matrix cell.")
    return plats, keys


def last_observed_runtime(latest: dict) -> dict[str, str]:
    """Most recent runtime version actually contacted per platform (context only)."""
    seen: dict[str, str] = {}
    for (platform, _), cell in sorted(latest.items(), key=lambda item: item[1].assessed_at):
        if cell.runtime_version and not cell.gated and any(
                r.get("test_type") == "LIVE" for r in cell.probes.values()):
            seen[platform] = cell.runtime_version
    return seen


def apply_gate(cell: assessment.CellAssessment, *, observed_runtime: str = "") -> bool:
    """Resolve the live stages of a cell whose prerequisite layer is missing.

    Returns False (and leaves the cell untouched) when every prerequisite passed:
    such a cell must be exercised against an isolated runtime.
    """
    blockers = cell.blockers
    if not blockers:
        return False
    first = cell.probes[blockers[0]]
    digest = hashlib.sha256(json.dumps(
        {name: cell.probes[name] for name in assessment.PROBES if name not in assessment.LIVE_PROBES},
        sort_keys=True).encode()).hexdigest()[:16]
    reference = f"{assessment.GATE_PREFIX}{cell.platform}/{cell.feature}@{cell.repository_head[:12]}#{digest}"
    chain = ", ".join(f"{name}={cell.probes[name]['reason']}" for name in blockers)
    for name in assessment.LIVE_PROBES:
        cell.probes[name] = assessment.probe(
            "BLOCKED",
            f"Not attempted: NMAS prerequisite layer(s) failed their deliberate probe ({chain}). "
            f"First blocker {blockers[0]}: {first['detail']} No device was contacted for this stage.",
            reason=first["reason"], test_type="STATIC", reference=reference)
    cell.runtime_version = "not contacted (prerequisite gate)" + (
        f"; platform runtime last observed: {observed_runtime}" if observed_runtime else "")
    return True


@dataclass
class BatchResult:
    actions: dict = field(default_factory=dict)       # (platform, feature) -> action
    errors: dict = field(default_factory=dict)        # (platform, feature) -> exception class
    cells: list = field(default_factory=list)         # cells newly recorded by this run

    def counts(self) -> dict:
        return dict(sorted(Counter(self.actions.values()).items()))


def assess_batch(platforms, keys, *, head: str, actor: str, reassess: bool = False, record: bool = True,
                 live_probes: dict | None = None, progress=None) -> BatchResult:
    """Assess each selected cell individually; see the module docstring."""
    if not head:
        raise ValueError("Repository HEAD is required before any evidence can be recorded.")
    catalogue = features.by_key()
    latest = assessment.latest_assessments()
    observed = last_observed_runtime(latest)
    result = BatchResult()
    for platform in platforms:
        for key in keys:
            current = latest.get((platform, key))
            if current is not None and current.complete and not reassess:
                result.actions[platform, key] = KEPT
                continue
            cell = verify_cell(platform, catalogue[key], head=head)
            if apply_gate(cell, observed_runtime=observed.get(platform, "")):
                action = GATED
            elif live_probes and (platform, key) in live_probes:
                try:
                    live_probes[platform, key](cell)
                    action = LIVE if cell.complete else PENDING_LIVE
                except Exception as exc:  # noqa: BLE001 - a failed probe must not abort the batch; it stays unassessed
                    result.errors[platform, key] = type(exc).__name__ + ": " + str(exc)[:200]
                    cell = verify_cell(platform, catalogue[key], head=head)
                    action = LIVE_ERROR
            else:
                action = PENDING_LIVE
            if action in {GATED, LIVE} and (not cell.complete or cell.status not in {"SUPPORTED", "UNSUPPORTED"}):
                raise AssertionError(f"{platform} {key}: batch produced an inconsistent assessment.")
            if record and (action in {GATED, LIVE} or current is None):
                assessment.persist(cell, actor=actor)
            result.actions[platform, key] = action
            result.cells.append(cell)
        if progress:
            progress(platform, Counter(a for (p, _), a in result.actions.items() if p == platform))
    return result


def matrix_report(platforms=None, keys=None) -> dict:
    """The structured ledger from the latest persisted assessment of every cell."""
    plats = tuple(platforms or features.platforms())
    keys = tuple(keys or features.by_key())
    latest = assessment.latest_assessments()
    cells = [latest[p, k] for p in plats for k in keys if (p, k) in latest]
    report = assessment.report(cells, selected_platforms=plats, selected_features=keys)
    check_report(report)
    return report


def check_report(report: dict) -> None:
    """Machine-enforced invariants of every generated ledger (complete or not)."""
    cells = report["cells"]
    assessed = [c for c in cells if c["assessment_complete"]]
    supported = [c for c in cells if c["final_status"] == "SUPPORTED"]
    if report["assessed"] != len(assessed) or report["unassessed"] != report["total"] - len(assessed) \
            or report["supported"] != len(supported) or report["unsupported"] != report["total"] - len(supported):
        raise ValueError("Ledger totals do not match its cells.")
    for cell in cells:
        name = f"{cell['platform']} {cell['feature']}"
        if cell["final_status"] not in {"SUPPORTED", "UNSUPPORTED"}:
            raise ValueError(f"{name}: non-binary final status.")
        if "capability_status" in cell and (cell["capability_status"], cell.get("feasibility")) != tuple(
                vocabulary.classify_cell(cell).values()):
            raise ValueError(f"{name}: capability status disagrees with the binary ledger.")
        if cell["final_status"] == "SUPPORTED" and (
                not cell["assessment_complete"] or cell["unsupported_reasons"] or cell["strongest_test_type"] != "LIVE"
                or any(r["outcome"] != "PASS" for r in cell["probes"].values())
                or any(cell["probes"][n]["test_type"] != "LIVE" or not cell["probes"][n]["reference"].startswith("live:")
                       for n in assessment.LIVE_PROBES)):
            raise ValueError(f"{name}: SUPPORTED without the mandatory live evidence.")
        if cell["assessment_complete"] and cell["final_status"] == "UNSUPPORTED":
            if not cell["unsupported_reasons"] or set(cell["unsupported_reasons"]) - assessment.REASONS:
                raise ValueError(f"{name}: UNSUPPORTED without a classified reason.")
            if any(str(r["outcome"]).upper() in FINAL_FORBIDDEN for r in cell["probes"].values()):
                raise ValueError(f"{name}: an unresolved probe escaped into a completed assessment.")


def summary_markdown(report: dict) -> str:
    """Human summary generated only from the structured ledger."""
    lines = [
        "# Capability matrix assessment summary", "",
        "Generated from `progress-ledger.json` by `nmas_capabilities verify-matrix` / `report-matrix`; do not edit by hand.", "",
        f"**{'COMPLETE' if not report['unassessed'] else 'INCOMPLETE'}** — total {report['total']}, "
        f"assessed {report['assessed']}, unassessed {report['unassessed']}, supported {report['supported']}, "
        f"unsupported {report['unsupported']} (unassessed cells are fail-closed unsupported).", "",
        "| Platform | Total | Assessed | Unassessed | Supported | Runtime-investigated | Prerequisite-gated |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    cells = report["cells"]
    for platform, row in report["per_platform"].items():
        mine = [c for c in cells if c["platform"] == platform]
        lines.append(f"| {platform} | {row['total']} | {row['assessed']} | {row['total'] - row['assessed']} | {row['supported']} | "
                     f"{sum(c['assessment_basis'] == 'RUNTIME_INVESTIGATION' for c in mine)} | "
                     f"{sum(c['assessment_basis'] == 'PREREQUISITE_GATE' for c in mine)} |")
    status_counts = report.get("capability_counts") or vocabulary.counts(cells)
    lines += ["", "## Capability status", "",
              "Derived from the binary ledger: SUPPORTED is unchanged; UNSUPPORTED means a demonstrated platform limitation; "
              "every other unsupported cell is NOT_IMPLEMENTED (an NMAS gap, unknown feasibility, or unassessed).", "",
              "| Status | Cells |", "| --- | ---: |"]
    lines += [f"| {status} | {count} |" for status, count in status_counts.items()]
    lines += ["", "## Supported cells", ""]
    lines += [f"- `{c['platform']}` `{c['feature']}`" for c in cells if c["final_status"] == "SUPPORTED"] or ["- none"]
    lines += ["", "## Unsupported reason groups (completed assessments)", "",
              "A cell is listed under every reason one of its probes recorded.", "",
              "| Platform | Reason | Cells |", "| --- | --- | ---: |"]
    groups = Counter((c["platform"], reason) for c in cells
                     if c["assessment_complete"] and c["final_status"] == "UNSUPPORTED" for reason in c["unsupported_reasons"])
    lines += [f"| {platform} | {reason} | {count} |" for (platform, reason), count in sorted(groups.items())]
    lines += ["", "## Live-stage blocker of prerequisite-gated cells", "",
              "| Platform | First missing NMAS layer | Cells |", "| --- | --- | ---: |"]
    gates = Counter((c["platform"], c["probes"]["live_write"]["reason"]) for c in cells if c["assessment_basis"] == "PREREQUISITE_GATE")
    lines += [f"| {platform} | {reason} | {count} |" for (platform, reason), count in sorted(gates.items())]
    lines += ["", "## Unassessed cells", ""]
    lines += [f"- `{c['platform']}` `{c['feature']}` — outstanding: {', '.join(c['remaining_probes'])}"
              for c in report["remaining_cells"]] or ["- none"]
    return "\n".join(lines) + "\n"
