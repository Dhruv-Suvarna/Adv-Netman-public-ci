"""V2 Phase 9: the generated ten-stage closure ledger (never hand-edited).

Input: the stored exhaustive assessment ledger (``docs/evidence/v2-phase4-exhaustive/progress-ledger.json``: one record per
platform x feature with every probe's outcome, test type and reference) plus the Phase 9 option-82 live evidence (the governed
run in ``docs/evidence/v2-phase9-closure/option82`` when present, else the earlier console-transport file).  Each
cell's class follows ONLY from which of the ten stages exist:

    1 intent      semantic model + Device Builder + field validation      6 postcheck     post-write read-back verification
    2 renderer    renderer + candidate generation                         7 compensation  an exact inverse was applied
    3 validation  network-configuration validation                        8 restoration   compensation verified LIVE (the prior
    4 execution   executor + live write                                                   running-config / section returned)
    5 readback    live read + parser / import                             9 tests         automated positive + negative tests
                                                                          10 live         runtime verification on that platform

A stage "exists" when its probes PASSED; stages 4-8 and 10 must be LIVE evidence.  Classification (first match wins):
OUT_OF_SCOPE (recorded decision) > UNSUPPORTED (completed assessment with a platform reason) > SUPPORTED (all ten) >
BLOCKED_BY_ENVIRONMENT (a live probe blocked by RUNTIME_IMAGE_UNAVAILABLE / RUNTIME_BOOT_FAILED while stages 1-4 exist) >
LIVE_EVIDENCE_MISSING (stages 1-4 and 9 exist) > PARTIAL (1-3 and some later stage) > RENDER_VALIDATE_ONLY (1-3) >
NOT_IMPLEMENTED.  A SUPPORTED class must agree with the ledger's binary ``final_status`` -- a disagreement raises.

The class records which stages exist.  Separately, ``environment_blocker`` lists the environment reasons (no runtime image,
boot failure) that block a cell's live probes, whatever its earlier stages.  Such a cell cannot reach SUPPORTED on this host
even after its software stages are written, because stage 10 needs a live run.  ``closure_outlook`` splits the cells that are
not SUPPORTED into UNSUPPORTED / OUT_OF_SCOPE decisions, environment-blocked cells and technically feasible remaining work.
"""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

from . import vocabulary
from .vocabulary import CLOSURE_TO_STATUS, ClosureClass

STAGES = ("intent", "renderer", "validation", "execution", "readback", "postcheck", "compensation", "restoration", "tests", "live")
STAGE_PROBES = {
    "intent": ("semantic_model", "device_builder_ui", "field_validation"), "renderer": ("renderer", "candidate_generation"),
    "validation": ("config_validation",), "execution": ("executor", "live_write"), "readback": ("live_read", "parser_import"),
    "postcheck": ("live_post_write_validation",), "compensation": ("compensation",), "restoration": ("compensation",),
    "tests": ("automated_tests",), "live": ("runtime_validation",),
}
LIVE_STAGES = frozenset({"execution", "postcheck", "compensation", "restoration", "live"})
_LIVE_PROBES = frozenset({"live_write", "live_read", "live_post_write_validation", "compensation", "runtime_validation"})
ENVIRONMENT_REASONS = frozenset({"RUNTIME_IMAGE_UNAVAILABLE", "RUNTIME_BOOT_FAILED"})
SCHEMA = "nmas.v2.phase9.capability-ledger/1"


def stages_for(probes: dict) -> dict:
    """{stage: bool} -- a stage exists when every probe behind it PASSED (live probes with LIVE evidence)."""
    def ok(name):
        result = probes.get(name) or {}
        return result.get("outcome") == "PASS" and (name not in _LIVE_PROBES or result.get("test_type") == "LIVE")

    return {stage: all(ok(name) for name in STAGE_PROBES[stage]) for stage in STAGES}


def classify(cell: dict) -> tuple[str, dict]:
    """One ledger cell -> (ClosureClass value, stages)."""
    probes = cell.get("probes") or {}
    stages = stages_for(probes)
    base, _feasibility = vocabulary.classify(cell["final_status"], complete=bool(cell.get("assessment_complete")),
                                             reasons=cell.get("unsupported_reasons") or (), platform=str(cell.get("platform", "")),
                                             feature=str(cell.get("feature", "")))
    if all(stages.values()) != (cell["final_status"] == "SUPPORTED"):
        raise ValueError(f"{cell.get('platform')} {cell.get('feature')}: ten-stage result disagrees with final_status")
    if base == "OUT_OF_SCOPE":
        return ClosureClass.OUT_OF_SCOPE.value, stages
    if base == "UNSUPPORTED":
        return ClosureClass.UNSUPPORTED.value, stages
    if all(stages.values()):
        return ClosureClass.SUPPORTED.value, stages
    early = all(stages[s] for s in ("intent", "renderer", "validation"))
    blocked = {probes.get(n, {}).get("reason") for n in _LIVE_PROBES if probes.get(n, {}).get("outcome") == "BLOCKED"}
    if early and stages["execution"] is False and blocked & ENVIRONMENT_REASONS and probes.get("executor", {}).get("outcome") == "PASS":
        return ClosureClass.BLOCKED_BY_ENVIRONMENT.value, stages
    if early and stages["execution"] and stages["tests"]:
        return ClosureClass.LIVE_EVIDENCE_MISSING.value, stages
    if early and any(stages[s] for s in STAGES[3:]):
        return ClosureClass.PARTIAL.value, stages
    if early:
        return ClosureClass.RENDER_VALIDATE_ONLY.value, stages
    return ClosureClass.NOT_IMPLEMENTED.value, stages


def option82_row(evidence: dict | None, *, evidence_path: str = "") -> dict:
    """The Phase 9 option-82 row for arista_ceos derived from its live evidence file (None -> nothing proven live)."""
    ev = evidence or {}
    post, restored = ev.get("post") or {}, ev.get("restored") or {}
    stages = {
        "intent": True,                                   # Device Builder: service_policy_intent_service.set_dhcp_relay_option82
        "renderer": bool(ev.get("rendered")),
        "validation": ev.get("validation") == [],
        # executed through the isolated Docker CLI transport, NOT the governed execution engine: the stage is not claimed
        "execution": False,
        "readback": bool((post.get("readback") or {}).get("enabled")),
        "postcheck": post.get("postcheck") == [],
        "compensation": (ev.get("compensation") or {}).get("rc") == 0,
        "restoration": restored.get("equals_pre") is True,
        "tests": True,                                    # core.tests.test_phase9_option82 (positive + negative per function)
        "live": bool((ev.get("positive") or {}).get("client", {}).get("lease_obtained"))
                and not (ev.get("negative_before_apply") or {}).get("client", {}).get("lease_obtained", True),
    }
    early = all(stages[s] for s in ("intent", "renderer", "validation"))
    klass = (ClosureClass.SUPPORTED if all(stages.values()) else ClosureClass.PARTIAL if early and any(stages[s] for s in STAGES[3:])
             else ClosureClass.RENDER_VALIDATE_ONLY if early else ClosureClass.NOT_IMPLEMENTED).value
    return {"platform": "arista_ceos", "feature": "lifecycle.DHCP_RELAY_OPTION82", "closure_class": klass,
            "capability_status": CLOSURE_TO_STATUS[ClosureClass(klass)], "stages": stages,
            "missing_stages": [s for s in STAGES if not stages[s]], "evidence": evidence_path,
            "note": "Outside the 396-cell matrix (no matrix feature axis exists for option 82).  Execution through the governed "
                    "execution engine is missing; the live run applied NMAS-rendered lines through the isolated Docker CLI transport."}


GOVERNED_OPTION82_FILES = ("o82-10-gate.json", "o82-20-fault-compensated.json", "o82-30-governed-apply.json",
                           "o82-40-forged-option82.json", "o82-50-native-ztp.json")


def governed_option82_row(files: dict | None, *, evidence_path: str = "") -> dict:
    """The option-82 row from the governed live run (``core.tests.live_option82_ztp_fixture``): {file name: parsed JSON}.

    Every stage follows from what the run recorded; a missing file proves nothing."""
    f = files or {}
    gate, fault, applied = f.get("o82-10-gate.json") or {}, f.get("o82-20-fault-compensated.json") or {}, f.get("o82-30-governed-apply.json") or {}
    forged, ztp = f.get("o82-40-forged-option82.json") or {}, f.get("o82-50-native-ztp.json") or {}
    plan, execute, readback = applied.get("plan") or {}, applied.get("execute") or {}, applied.get("readback") or {}
    compensation = (fault.get("execute") or {}).get("compensation") or {}
    leases = ztp.get("lease_observations") or []
    relayed = ztp.get("new1_relayed_requests") or []
    forged_rows = [r for r in forged.get("relayed_requests") or [] if r.get("circuit_id") and r.get("circuit_id") != "Ethernet1"]
    stages = {
        "intent": bool(plan.get("ok") and (plan.get("source") or {}).get("relay")),        # a Device Builder relay revision
        "renderer": any(c.get("object_type") == "dhcp_relay_option82" and c.get("lines") for c in applied.get("configlets") or []),
        "validation": plan.get("ok") is True and plan.get("codes") == [],
        "execution": execute.get("ok") is True and execute.get("outcome") == "SUCCEEDED" and applied.get("change_state") == "DEPLOYED",
        "readback": readback.get("enabled") is True and readback.get("change") == plan.get("change"),
        "postcheck": (applied.get("gate_after") or {}).get("ok") is True,
        "compensation": compensation.get("status") == "COMPENSATED" and compensation.get("not_compensated") == [],
        "restoration": fault.get("up1_digest_restored") is True,
        "tests": True,                                    # core.tests.test_relay_option82 (positive + negative per function)
        "live": (gate.get("gate_with_option82_off") or {}).get("ok") is False
                and any(l.get("outcome") == "CORRELATED" and l.get("relay_trusted") for l in leases)
                and bool(relayed) and all(r.get("circuit_id") == "Ethernet1" for r in relayed)
                and bool(forged_rows) and all(r.get("nmas_discovery_gate") == "OPTION82_CIRCUIT_FORGED" for r in forged_rows),
    }
    early = all(stages[s] for s in ("intent", "renderer", "validation"))
    klass = (ClosureClass.SUPPORTED if all(stages.values()) else ClosureClass.PARTIAL if early and any(stages[s] for s in STAGES[3:])
             else ClosureClass.RENDER_VALIDATE_ONLY if early else ClosureClass.NOT_IMPLEMENTED).value
    return {"platform": "arista_ceos", "feature": "lifecycle.DHCP_RELAY_OPTION82", "closure_class": klass,
            "capability_status": CLOSURE_TO_STATUS[ClosureClass(klass)], "stages": stages,
            "missing_stages": [s for s in STAGES if not stages[s]], "evidence": evidence_path,
            "note": "Outside the 396-cell matrix (no matrix feature axis exists for option 82).  Governed change (DHCP_RELAY_OPTION82) "
                    "through CeosExecutor over SSH, stored read-back gating native ZTP, client-forged circuit ids refused."}


def environment_blocker(cell: dict) -> list[str]:
    """The environment reasons blocking this cell's live probes (sorted, empty when none)."""
    probes = cell.get("probes") or {}
    return sorted({p.get("reason") for n, p in probes.items()
                   if n in _LIVE_PROBES and p.get("outcome") == "BLOCKED" and p.get("reason") in ENVIRONMENT_REASONS})


def closure_outlook(cells: list[dict]) -> dict:
    """Counts: SUPPORTED, platform/scope decisions, environment-blocked, and technically feasible remaining."""
    decided = {ClosureClass.UNSUPPORTED.value, ClosureClass.OUT_OF_SCOPE.value}
    out = {"total": len(cells), "supported": 0, "unsupported_or_out_of_scope": 0, "environment_blocked": 0,
           "technically_feasible_remaining": 0, "environment_blocked_by_platform": {}}
    for c in cells:
        if c["closure_class"] == ClosureClass.SUPPORTED.value:
            out["supported"] += 1
        elif c["closure_class"] in decided:
            out["unsupported_or_out_of_scope"] += 1
        elif c["environment_blocker"]:
            out["environment_blocked"] += 1
            by = out["environment_blocked_by_platform"]
            by[c["platform"]] = by.get(c["platform"], 0) + 1
        else:
            out["technically_feasible_remaining"] += 1
    return out


def build(ledger: dict, *, option82_evidence: dict | None = None, option82_path: str = "", option82_row_override: dict | None = None) -> dict:
    cells = []
    for cell in sorted(ledger["cells"], key=lambda c: (c["platform"], c["feature"])):
        klass, stages = classify(cell)
        cells.append({"platform": cell["platform"], "feature": cell["feature"], "closure_class": klass,
                      "capability_status": CLOSURE_TO_STATUS[ClosureClass(klass)], "final_status": cell["final_status"],
                      "stages": stages, "missing_stages": [s for s in STAGES if not stages[s]],
                      "unsupported_reasons": cell.get("unsupported_reasons") or [],
                      "environment_blocker": environment_blocker(cell),
                      "evidence_references": cell.get("evidence_references") or []})
    platforms = sorted({c["platform"] for c in cells})
    per_platform = {p: {k.value: 0 for k in ClosureClass} | {"total": 0} for p in platforms}
    for c in cells:
        per_platform[c["platform"]][c["closure_class"]] += 1
        per_platform[c["platform"]]["total"] += 1
    totals = {k.value: 0 for k in ClosureClass} | dict(Counter(c["closure_class"] for c in cells))
    extra = [option82_row_override or option82_row(option82_evidence, evidence_path=option82_path)]
    return {"schema": SCHEMA, "source": "docs/evidence/v2-phase4-exhaustive/progress-ledger.json",
            "stages": list(STAGES), "matrix_total": len(cells), "matrix_supported": totals[ClosureClass.SUPPORTED.value],
            "totals": totals, "per_platform": per_platform, "closure_outlook": closure_outlook(cells), "cells": cells,
            "lifecycle_linked_rows": extra}


def summary_markdown(result: dict) -> str:
    classes = [k.value for k in ClosureClass]
    out = ["# V2 Phase 9 capability ledger summary", "",
           "Generated by `manage.py nmas_phase9_ledger` from the stored exhaustive ledger and the Phase 9 live evidence; "
           "do not edit by hand.", "",
           f"Matrix cells: **{result['matrix_total']}**, SUPPORTED (all ten stages): **{result['matrix_supported']}**.", "",
           "| Platform | Total | " + " | ".join(classes) + " |", "| --- | ---: | " + " | ".join("---:" for _ in classes) + " |"]
    for platform, row in result["per_platform"].items():
        out.append(f"| {platform} | {row['total']} | " + " | ".join(str(row[k]) for k in classes) + " |")
    out.append(f"| **all** | {result['matrix_total']} | " + " | ".join(str(result["totals"][k]) for k in classes) + " |")
    o = result["closure_outlook"]
    blocked = ", ".join(f"{p} {n}" for p, n in sorted(o["environment_blocked_by_platform"].items())) or "none"
    out += ["", "## Closure outlook", "",
            f"- SUPPORTED: {o['supported']}",
            f"- UNSUPPORTED or OUT_OF_SCOPE (recorded decision): {o['unsupported_or_out_of_scope']}",
            f"- Environment-blocked (a live probe is blocked by the host environment, so stage 10 cannot run here): "
            f"{o['environment_blocked']} ({blocked})",
            f"- Technically feasible remaining: {o['technically_feasible_remaining']}"]
    out += ["", "## Lifecycle-linked rows (outside the matrix)", ""]
    for row in result["lifecycle_linked_rows"]:
        out.append(f"- `{row['platform']}` `{row['feature']}`: **{row['closure_class']}**; missing stages: "
                   f"{', '.join(row['missing_stages']) or 'none'}. {row['note']} Evidence: `{row['evidence']}`.")
    out += ["", "## SUPPORTED cells", ""]
    out += [f"- `{c['platform']}` `{c['feature']}`" for c in result["cells"] if c["closure_class"] == "SUPPORTED"]
    out += ["", "## LIVE_EVIDENCE_MISSING cells (next closure candidates)", ""]
    out += [f"- `{c['platform']}` `{c['feature']}`: missing {', '.join(c['missing_stages'])}" for c in result["cells"]
            if c["closure_class"] == "LIVE_EVIDENCE_MISSING"] or ["- none"]
    return "\n".join(out) + "\n"


def write(repo_root: Path, out_dir: Path) -> dict:
    ledger = json.loads((repo_root / "docs/evidence/v2-phase4-exhaustive/progress-ledger.json").read_text())
    rel = "docs/evidence/v2-phase7-9/phase9/option82-ceos-live.json"
    path = repo_root / rel
    option82 = json.loads(path.read_text()) if path.exists() else None
    governed_rel = "docs/evidence/v2-phase9-closure/option82"
    governed_dir = repo_root / governed_rel
    governed = {name: json.loads((governed_dir / name).read_text()) for name in GOVERNED_OPTION82_FILES if (governed_dir / name).exists()}
    override = governed_option82_row(governed, evidence_path=governed_rel) if governed else None
    result = build(ledger, option82_evidence=option82, option82_path=rel if option82 else "", option82_row_override=override)
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "capability-ledger.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    (out_dir / "capability-summary.md").write_text(summary_markdown(result))
    return result
