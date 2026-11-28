"""Versioned executable runbooks RB01-RB07 and their synchronisation with the human-readable documents.

``REGISTRY`` maps a runbook id to its ``Runbook`` (typed hypothesis/test DAG).  The plain-English documents live in
``docs/troubleshooting/runbooks/<doc>``; the block between ``<!-- DAG:BEGIN -->`` and ``<!-- DAG:END -->`` is *generated* from the DAG by
``render_dag_block`` (``python -m core.services.troubleshooting.runbooks write`` rewrites it) and ``check_sync`` proves the document and the DAG
agree on version, test ids, titles and hypotheses (UT-054).  Test ids, versions and strategy names are therefore single-sourced.
"""

from __future__ import annotations

import re
from pathlib import Path

from .base import Runbook
from .hc import HC_HYPOTHESES, HC_ORDERS, HC_TESTS, select_strategy as _hc_strategy
from .rb01_link_flap import RB01
from .rb03_neighbor import RB03
from .rb04_stp import RB04
from .rb05_dns import RB05
from .rb06_mtu import RB06
from .rb07_layer1 import RB07

RB02 = Runbook(
    id="RB02", name="reachability-host-connectivity", version="1.0.0", title="Reachability / host connectivity (HC01-HC28)", doc="RB02-reachability.md", test_prefixes=("HC",),
    purpose="Decide whether a production service is really impaired, where on the path, and why, using the 28-test host-connectivity catalogue with forward and return path checks.",
    tests=HC_TESTS, hypotheses=HC_HYPOTHESES, orders=HC_ORDERS, select_strategy=_hc_strategy,
    impact_tests=("HC22", "HC27"),
    remediations={
        "F-acl-deny": {"tier": 2, "action": "narrowly scoped correction of the denying ACL entry (never a blanket permit)", "approvals": ["operator approval", "dry-run + precheck", "continuous production-flow guard"],
                       "pre_tests": ["HC18", "HC02", "HC28"], "post_tests": ["HC22", "HC27", "HC18"], "rollback": "remove the added/restore the removed ACL line, readback + flow verification",
                       "never": ["auto-revert to golden because of drift alone", "traffic reroute without a verified alternate path"]},
        "F-qos-drop": {"tier": 2, "action": "adjust policer/queue after capacity review", "approvals": ["operator approval"], "pre_tests": ["HC19", "HC20"], "post_tests": ["HC22", "HC27"], "rollback": "restore previous policy", "never": ["rolling back solely for golden conformity"]},
        "F-fib": {"tier": 2, "action": "escalate with hardware-programming evidence; clearing routes requires approval", "approvals": ["operator approval"], "pre_tests": ["HC15", "HC16"], "post_tests": ["HC16", "HC22"], "rollback": "n/a", "never": ["clear ip route *"]},
        "F-rib": {"tier": 2, "action": "restore the missing route/adjacency per RB03 evidence", "approvals": ["operator approval"], "pre_tests": ["HC14", "HC15"], "post_tests": ["HC15", "HC16", "HC22"], "rollback": "remove added route", "never": ["metric changes without path-impact assessment"]},
        "F-maintenance": {"tier": 1, "action": "none: intentional maintenance", "approvals": [], "pre_tests": ["HC12"], "post_tests": ["HC22"], "rollback": "n/a", "never": ["remediating an intentional drain"]},
        "F-diag-unexplained": {"tier": 1, "action": "none: record intent as an operator-confirmed scoped exception", "approvals": ["owner confirmation"], "pre_tests": ["HC22", "HC23"], "post_tests": ["HC23"], "rollback": "n/a", "never": ["remediating while production is healthy"]},
    },
)

REGISTRY: dict[str, Runbook] = {r.id: r for r in (RB01, RB02, RB03, RB04, RB05, RB06, RB07)}
DOCS_DIR = Path(__file__).resolve().parents[5] / "docs" / "troubleshooting" / "runbooks"
BEGIN, END = "<!-- DAG:BEGIN -->", "<!-- DAG:END -->"


def get(runbook_id: str) -> Runbook:
    try:
        return REGISTRY[runbook_id]
    except KeyError:
        raise KeyError(f"unknown runbook {runbook_id!r}; known: {sorted(REGISTRY)}") from None


def render_dag_block(rb: Runbook) -> str:
    """Markdown generated from the executable DAG (the only text that is generated; the rest of the document is hand-written)."""
    lines = [BEGIN, f"Runbook-Id: {rb.id}", f"Runbook-Version: {rb.version}", f"Strategies: {', '.join(sorted(rb.orders))}", "",
             "| Step | Test | Title | Layer | Hypothesis | Class | Hard prerequisite | Expected (healthy) |", "|---|---|---|---|---|---|---|---|"]
    order = rb.order(sorted(rb.orders)[0])
    for i, tid in enumerate(order, 1):
        t = rb.by_id[tid]
        lines.append(f"| {i} | {t.id} v{t.version} | {t.title} | {t.layer} | {t.hypothesis} | {t.cls} | {', '.join(t.requires) or '-'} | {t.expected} |")
    lines += ["", "| Hypothesis | Statement | Domain | Tests |", "|---|---|---|---|"]
    for h in sorted(rb.hypotheses, key=lambda h: (h.rank, h.id)):
        lines.append(f"| {h.id} | {h.title} | {h.domain} | {', '.join(h.tests)} |")
    lines += ["", END]
    return "\n".join(lines)


def doc_path(rb: Runbook) -> Path:
    return DOCS_DIR / rb.doc


def check_sync(rb: Runbook, path: Path | None = None) -> list[str]:
    """Differences between the human-readable document and the DAG (empty list == synchronized)."""
    p = path or doc_path(rb)
    if not p.exists():
        return [f"{p.name}: document missing"]
    text = p.read_text()
    problems = []
    m = re.search(re.escape(BEGIN) + r".*?" + re.escape(END), text, re.S)
    if not m:
        return [f"{p.name}: DAG block markers missing"]
    if m.group(0) != render_dag_block(rb):
        problems.append(f"{p.name}: generated DAG block is out of date (run `python -m core.services.troubleshooting.runbooks write`)")
    doc_ids = set(re.findall(r"\|\s*(" + "|".join(rb.test_prefixes) + r")(\d\d)\s+v", m.group(0)))
    want = {(t.id[:len(t.id) - 2], t.id[-2:]) for t in rb.tests}
    if {a + b for a, b in doc_ids} != {a + b for a, b in want}:
        problems.append(f"{p.name}: test ids differ from DAG")
    # every test id mentioned in the hand-written prose must exist in the DAG
    prose = text.replace(m.group(0), "")
    known = {t.id for t in rb.tests}
    stray = {x for x in re.findall(r"\b(?:" + "|".join(rb.test_prefixes) + r")\d\d\b", prose) if x not in known}
    if stray:
        problems.append(f"{p.name}: prose references test ids that are not in the DAG: {sorted(stray)}")
    for needed in ("## Symptoms", "## Triggering signals", "## Production contracts", "## Worked before / what changed", "## Scope", "## Collectors and permissions",
                   "## Baselines", "## Hypothesis tree", "## Tests and expected outcomes", "## Platform adaptations", "## Causal isolation", "## Alternative explanations",
                   "## Safe stopping criteria", "## AI handoff gate", "## Proposed remediations", "## Pre- and post-tests", "## Rollback", "## Soak", "## Documentation example"):
        if needed not in text:
            problems.append(f"{p.name}: required section {needed!r} missing")
    return problems


def write_dag_blocks() -> list[str]:
    changed = []
    for rb in REGISTRY.values():
        p = doc_path(rb)
        if not p.exists():
            continue
        text = p.read_text()
        new = re.sub(re.escape(BEGIN) + r".*?" + re.escape(END), lambda _m, rb=rb: render_dag_block(rb), text, flags=re.S)
        if new != text:
            p.write_text(new)
            changed.append(p.name)
    return changed


if __name__ == "__main__":  # pragma: no cover
    import sys
    if sys.argv[1:] == ["write"]:
        print("updated:", write_dag_blocks())
    else:
        for rb in REGISTRY.values():
            print(rb.id, rb.version, rb.validate() or "DAG ok", check_sync(rb) or "doc in sync")
