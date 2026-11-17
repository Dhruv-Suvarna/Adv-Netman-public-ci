"""Structured operator-facing case report (spec 7.1): eleven mandatory sections as typed tables.

``build_report`` reads ONLY through the repository (tenant/device scoped), never renders raw evidence, labels every row's
statement basis (observed / derived / AI-inferred / operator-confirmed), and keeps pass, fail, inconclusive, skipped, unavailable,
missing-data, stale and broken-link items visible.  A stage with no records renders an explicit NOT PERFORMED row rather than
vanishing, so "no data" is never mistaken for "healthy".  ``to_markdown`` / ``to_html`` render the same dict; both apply a final
redaction pass.
"""

from __future__ import annotations

import html
import json
from datetime import datetime, timezone
from typing import Any

from core import models as m

from . import contracts as c
from . import repository as repo

SECTION_TITLES = {
    "incident_summary": "1. Incident summary",
    "collection": "2. Collection",
    "normalization": "3. Normalization",
    "baseline": "4. Baseline",
    "correlation": "5. Correlation",
    "test_matrix": "6. Sequential test matrix",
    "deterministic_diagnosis": "7. Deterministic diagnosis",
    "ai_investigation": "8. AI investigation",
    "remediation_governance": "9. Remediation governance",
    "verification_soak": "10. Verification & soak",
    "final_disposition": "11. Final disposition and next actions",
}


def _val(v: Any, limit: int = 140) -> str:
    if v is None:
        return "—"
    text = v if isinstance(v, str) else json.dumps(v, sort_keys=True, default=str)
    text = c.redact_text(text)[0]
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _links(ids: list[str], index: dict[str, dict]) -> list[dict]:
    out = []
    for i in ids:
        e = index.get(i)
        out.append({"evidence_id": i, "operator_url": e["operator_url"] if e else "", "link_status": e["link_status"] if e else "BROKEN",
                    "note": "" if e else "evidence record not found"})
    return out


def _table(columns: list[str], rows: list[dict], *, empty: str) -> dict[str, Any]:
    if not rows:
        rows = [{columns[0]: "NOT PERFORMED / NO RECORDS", **{k: "—" for k in columns[1:]}, "_placeholder": empty}]
    return {"columns": columns, "rows": rows, "row_count": 0 if rows and "_placeholder" in rows[0] else len(rows)}


def _in_window(dt: datetime | None, since, until) -> bool:
    if dt is None:
        return True
    return (since is None or dt >= since) and (until is None or dt <= until)


def build_report(actor: repo.Actor, case: m.TsCase, *, now: datetime | None = None, device: str | None = None,
                 verdict: str | None = None, basis: str | None = None, since: datetime | None = None,
                 until: datetime | None = None) -> dict[str, Any]:
    now = now or datetime.now(timezone.utc)
    case = repo.get_case(actor, case.case_id)
    def visible(dev):
        return actor.can_see_device(dev) and (device is None or dev == device)

    refs = [r for r in m.TsEvidenceRef.objects.filter(case=case) if actor.can_see_device(r.device)]
    index = {r.evidence_id: {
        "source_type": r.source_type, "device": r.device, "command_or_api": r.command_or_api, "adapter": r.adapter,
        "adapter_version": r.adapter_version, "parser": r.parser, "parser_version": r.parser_version,
        "collected_at": c.iso(r.collected_at), "raw_sha256": r.raw_sha256, "raw_pointer": r.raw_pointer,
        "raw_size_bytes": r.raw_size_bytes, "redaction_status": r.redaction_status, "operator_url": r.operator_url,
        "link_status": r.link_status, "quality": r.quality} for r in refs}  # never includes raw content
    limitations: list[str] = []
    bad_links = [i for i, e in index.items() if e["link_status"] in ("MISSING", "BROKEN")]
    for i in bad_links:
        limitations.append(f"Evidence {i}: operator link is {index[i]['link_status']} (shown as-is; no URL was invented).")

    # 1 ---------------------------------------------------------------------------------------------------- summary
    def yn(v):
        return "UNKNOWN" if v is None else ("yes" if v else "no")
    summary_rows = [{"field": f, "value": _val(v), "basis": b, "evidence": []} for f, v, b in [
        ("case_id", case.case_id, "OBSERVED"), ("title / symptom", f"{case.title} {case.symptom}".strip() or "—", "OPERATOR_CONFIRMED"),
        ("trigger", f"{case.trigger_source} {case.trigger_ref}".strip(), "OBSERVED"),
        ("service intent", case.service_intent, "OPERATOR_CONFIRMED"), ("production-flow scope", case.flow_scope, "OPERATOR_CONFIRMED"),
        ("affected devices", [d for d in case.affected_scope.get("devices", []) if actor.can_see_device(d)], "OBSERVED"),
        ("severity", case.severity, "OPERATOR_CONFIRMED"), ("state", case.state, "DERIVED"),
        ("opened", c.iso(case.opened_at), "OBSERVED"), ("first detected", c.iso(case.first_detected_at) or "UNKNOWN", "OBSERVED"),
        ("closed", c.iso(case.closed_at) or "open", "OBSERVED"),
        ("worked before?", yn(case.worked_before), "OPERATOR_CONFIRMED"), ("changed?", yn(case.changed_recently), "OPERATOR_CONFIRMED"),
        ("last known good", f"{c.iso(case.last_known_good_at) or 'UNKNOWN'} {case.last_known_good_ref}".strip(), "OBSERVED"),
        ("change-window references", case.change_window_refs or "none recorded", "OPERATOR_CONFIRMED"),
        ("isolation strategy", f"{case.isolation_strategy or 'not yet chosen'} — {case.strategy_rationale}".strip(" —"), "DERIVED"),
        ("confidence", case.confidence if case.confidence is not None else "UNKNOWN", "DERIVED"), ("owner", case.owner, "OBSERVED")]]
    sec = {"incident_summary": _table(["field", "value", "basis", "evidence"], summary_rows, empty="no case")}

    # 2 --------------------------------------------------------------------------------------------------- collection
    runs = [r for r in m.TsCollectionRun.objects.filter(case=case) if all(visible(t) for t in r.targets or [""])
            and _in_window(r.started_at, since, until)]
    sec["collection"] = _table(
        ["seq", "stage", "collector / adapter", "targets", "command / API", "window", "attempts", "status", "quality", "error", "evidence"],
        [{"seq": r.seq, "stage": r.stage, "collector / adapter": f"{r.collector} / {r.adapter} {r.adapter_version}".strip(),
          "targets": ", ".join(r.targets), "command / API": _val(r.command_or_api), "window": f"{c.iso(r.started_at) or '—'} → {c.iso(r.finished_at) or '—'}",
          "attempts": f"{r.attempts}/{r.max_attempts}", "status": r.status,
          "quality": "OK" if r.status == "SUCCEEDED" else ("DEGRADED" if r.status == "PARTIAL" else "NO DATA"),
          "error": _val(r.error), "evidence": _links([r.raw_ref.evidence_id] if r.raw_ref else [], index), "basis": r.basis} for r in runs],
        empty="no collection run has been recorded for this case")
    for r in runs:
        if r.status in ("DENIED", "UNAVAILABLE", "FAILED", "SKIPPED"):
            limitations.append(f"Collection #{r.seq} ({r.collector}) {r.status}: {_val(r.error or 'no detail')} — absence of data is not evidence of absence.")

    # 3 ----------------------------------------------------------------------------------------------- normalization
    obs = [o for o in m.TsObservation.objects.filter(case=case).select_related("evidence") if visible(o.target)
           and _in_window(o.observed_at, since, until) and (basis is None or o.basis == basis)]
    norm_rows = []
    for o in obs:
        fr = repo.evaluate_observation(o, now)
        raw_field = (o.evidence.command_or_api if o.evidence else "") or o.source
        norm_rows.append({"raw field": _val(raw_field), "standardized metric": o.key, "target": o.target, "value": _val(o.value),
                          "unit": o.unit or "—", "observed at": c.iso(o.observed_at), "freshness": fr, "parser": o.parser_version or "—",
                          "quality": o.quality, "confidence": o.confidence,
                          "missing / ambiguous": o.missing_reason if o.is_missing_data else ("ambiguous" if o.quality == "AMBIGUOUS" else "no"),
                          "basis": o.basis, "evidence": _links(o.evidence_ids, index)})
        if fr in (c.STALE, c.UNTRUSTED):
            limitations.append(f"Observation {o.record_id} ({o.key} on {o.target}) is {fr}; reported state is UNKNOWN, not live.")
        if o.is_missing_data:
            limitations.append(f"Missing data: {o.key} on {o.target} — {o.missing_reason}.")
    sec["normalization"] = _table(
        ["raw field", "standardized metric", "target", "value", "unit", "observed at", "freshness", "parser", "quality", "confidence",
         "missing / ambiguous"], norm_rows, empty="no normalized observation exists")

    # 4 ------------------------------------------------------------------------------------------------------ baseline
    base_rows = []
    for b in m.TsBaselineReference.objects.filter(case=case):
        valid = "valid" if (b.valid_until is None or b.valid_until >= now) and (b.valid_from is None or b.valid_from <= now) else "EXPIRED/NOT YET VALID"
        base_rows.append({"type": b.baseline_type, "subject": b.subject, "revision": b.revision or "—", "hash": b.revision_hash[:16] or "—",
                          "validity": valid, "valid interval": f"{c.iso(b.valid_from) or '—'} → {c.iso(b.valid_until) or 'open'}",
                          "operator URL": b.operator_url or "MISSING", "link": b.link_status, "approved change": b.approved_change_id or "—",
                          "soak state": b.soak_state or "—", "basis": b.basis, "evidence": _links(b.evidence_ids, index)})
        if b.baseline_type == "GOLDEN_CONFIG" and (not b.operator_url or b.link_status in ("MISSING", "BROKEN")):
            limitations.append(f"Golden baseline {b.record_id} ({b.revision}): direct page link is {b.link_status}; not replaced with an invented URL.")
    sec["baseline"] = _table(["type", "subject", "revision", "hash", "validity", "valid interval", "operator URL", "link", "approved change", "soak state"],
                             base_rows, empty="no baseline (intent / golden / live-normal / SLO) has been attached")

    # 5 --------------------------------------------------------------------------------------------------- correlation
    cor_rows = []
    for d in m.TsDriftAssessment.objects.filter(case=case):
        cor_rows.append({"kind": "drift", "subject": d.subject, "observed": _val(d.observed), "baseline": _val(d.expected),
                         "drift": d.drift_kind, "approved change": d.approved_change_id or "—", "production impact": d.production_impact,
                         "role": "—", "conclusion": _val(d.conclusion), "basis": d.basis, "evidence": _links(d.evidence_ids, index)})
    for k in m.TsCorrelationRecord.objects.filter(case=case):
        cor_rows.append({"kind": "alarm group", "subject": k.common_fault_candidate or "—", "observed": _val(k.observed_value),
                         "baseline": _val(k.baseline_value), "drift": k.drift_kind or "—", "approved change": "—",
                         "production impact": "—", "role": f"{k.role} ({len(k.alert_ids)} alerts, conf {k.confidence:.2f})",
                         "conclusion": _val(k.conclusion), "basis": k.basis, "evidence": _links(k.evidence_ids, index)})
    for p in m.TsTopologyPath.objects.filter(case=case):
        cor_rows.append({"kind": "path", "subject": f"{p.source} → {p.destination}", "observed": _val(p.observed_hops),
                         "baseline": _val(p.intended_hops), "drift": "divergent" if p.divergence else "none",
                         "approved change": "—", "production impact": "—", "role": f"vrf={p.vrf or '—'} af={p.address_family or '—'}",
                         "conclusion": _val(p.divergence) if p.divergence else "observed path matches intent", "basis": p.basis,
                         "evidence": _links(p.evidence_ids, index)})
    sec["correlation"] = _table(["kind", "subject", "observed", "baseline", "drift", "approved change", "production impact", "role", "conclusion"],
                                cor_rows, empty="no drift, alarm grouping or path correlation recorded")

    # 6 ---------------------------------------------------------------------------------------------------- test matrix
    tests = [t for t in m.TsDiagnosticTest.objects.filter(case=case) if visible(t.target.split(":")[0])
             and (verdict is None or t.verdict == verdict) and (basis is None or t.basis == basis) and _in_window(t.executed_at, since, until)]
    sec["test_matrix"] = _table(
        ["seq", "test", "target", "hypothesized condition", "expected", "actual (summary)", "verdict", "reason", "interpretation", "next action"],
        [{"seq": t.seq, "test": f"{t.test_id} v{t.test_version}" + (f" (attempt {t.attempt})" if t.attempt > 1 else ""), "target": t.target,
          "hypothesized condition": t.hypothesized_condition or "—", "expected": t.expected, "actual (summary)": _val(t.observed_summary or t.observed),
          "verdict": t.verdict, "reason": _val(t.reason), "interpretation": _val(t.interpretation), "next action": _val(t.next_action),
          "basis": t.basis, "evidence": _links(t.evidence_ids, index)} for t in tests],
        empty="no deterministic test has been executed or deliberately skipped")
    counts = {v: sum(1 for t in tests if t.verdict == v) for v in c.VERDICTS}
    for t in tests:
        if t.verdict == "UNAVAILABLE":
            limitations.append(f"Test {t.test_id} UNAVAILABLE: {_val(t.reason)}.")

    # 7 ---------------------------------------------------------------------------------------------------- diagnosis
    hyps = list(m.TsHypothesis.objects.filter(case=case).order_by("ranking", "id"))
    diag_rows = [{"hypothesis": h.title, "domain": h.failure_domain or "—", "state": h.state, "confidence": h.confidence,
                  "supporting": _links(h.supporting_evidence, index), "contradicting": _links(h.contradicting_evidence, index),
                  "tests": ", ".join(h.test_ids) or "—", "elimination / discriminating rationale": _val(h.elimination_rationale),
                  "basis": h.basis, "evidence": _links(h.evidence_ids, index)} for h in hyps]
    sec["deterministic_diagnosis"] = _table(
        ["hypothesis", "domain", "state", "confidence", "tests", "elimination / discriminating rationale"], diag_rows,
        empty="no hypothesis has been recorded")
    for h in hyps:
        if h.state == "UNVERIFIED":
            limitations.append(f"Hypothesis {h.record_id} is UNVERIFIED (no supporting evidence cited).")
    diagnosis_summary = {
        "strategy": case.isolation_strategy or "not recorded", "strategy_rationale": case.strategy_rationale or "not recorded",
        "tests_executed": len(tests), "verdict_counts": counts,
        "eliminated": [h.record_id for h in hyps if h.state == "ELIMINATED"],
        "candidate_root_causes": [h.record_id for h in hyps if h.state in ("SUPPORTED", "CONFIRMED")],
        "confirmed_root_causes": [h.record_id for h in hyps if h.state == "CONFIRMED"],
        "exhaustiveness": ("complete: no inconclusive/unavailable tests" if tests and not counts["INCONCLUSIVE"] and not counts["UNAVAILABLE"]
                           else "INCOMPLETE: inconclusive/unavailable or no tests — see limitations" if tests else "no tests executed"),
    }
    sec["deterministic_diagnosis"]["summary"] = diagnosis_summary

    # 8 ------------------------------------------------------------------------------------------------------------ AI
    handoffs = list(m.TsAIHandoff.objects.filter(case=case))
    ai_rows = []
    for hnd in handoffs:
        log = hnd.reasoning_log or [{}]
        for i, step in enumerate(log, 1):
            ai_rows.append({"handoff": hnd.record_id, "reason": _val(hnd.trigger_uncertainty), "agent": hnd.agent_identity or "—", "iteration": i,
                            "hypothesis": _val(step.get("hypothesis")), "tool": _val(step.get("tool")), "rationale": _val(step.get("rationale")),
                            "result": _val(step.get("result")), "updated conclusion": _val(step.get("conclusion")),
                            "budget": _val(hnd.budget), "basis": "AI_INFERRED", "evidence": _links(step.get("evidence_ids", hnd.evidence_ids), index)})
    sec["ai_investigation"] = _table(["handoff", "reason", "agent", "iteration", "hypothesis", "tool", "rationale", "result", "updated conclusion", "budget"],
                                     ai_rows, empty="AI investigation not used for this case (deterministic stage only)")

    # 9 ---------------------------------------------------------------------------------------------------- remediation
    plans = list(m.TsRemediationPlan.objects.filter(case=case))
    rem_rows = []
    for p in plans:
        execs = list(p.executions.all()) or [None]
        for e in execs:
            rem_rows.append({"plan": p.record_id, "tier": p.tier, "plan status": p.status, "operations": _val(p.operations), "risk": p.risk,
                             "blast radius": _val(p.blast_radius), "impacted flows": _val(p.impacted_flows), "dry-run": _val(p.dry_run),
                             "approval": _val(p.approval), "rollback plan": _val(p.rollback_plan),
                             "execution": e.record_id if e else "not executed", "execution status": e.status if e else "—",
                             "post-action observations": _val(e.observed_effect) if e else "—", "stop reason": (e.stop_reason or "—") if e else "—",
                             "basis": p.basis, "evidence": _links(p.evidence_ids, index)})
    sec["remediation_governance"] = _table(["plan", "tier", "plan status", "operations", "risk", "blast radius", "impacted flows", "dry-run", "approval",
                                            "rollback plan", "execution", "execution status", "post-action observations", "stop reason"],
                                           rem_rows, empty="no remediation planned; case remained read-only")

    # 10 ---------------------------------------------------------------------------------------------- verification
    ver_rows = [{"kind": "verification", "subject": _val(v.original_symptom), "before → after": _val(v.before_after), "steps": len(v.test_steps),
                 "soak": v.soak_status or "—", "regressions": _val(v.regressions) if v.regressions else "none observed",
                 "outcome": v.outcome, "residual": _val(v.residual_impact), "basis": v.basis, "evidence": _links(v.evidence_ids, index)}
                for v in m.TsVerificationRecord.objects.filter(case=case)]
    ver_rows += [{"kind": "production flow", "subject": _val(f.selector), "before → after": f"baseline {_val(f.baseline)} → loss {f.current_loss_pct if f.current_loss_pct is not None else 'UNKNOWN'}%",
                  "steps": "—", "soak": "—", "regressions": "—", "outcome": f.classification, "residual": _val(f.uncertainty),
                  "basis": f.basis, "evidence": _links(f.evidence_ids, index)} for f in m.TsProductionFlowMonitor.objects.filter(case=case)]
    sec["verification_soak"] = _table(["kind", "subject", "before → after", "steps", "soak", "regressions", "outcome", "residual"], ver_rows,
                                      empty="no post-action verification or flow monitoring recorded; the case cannot be reported as resolved")

    # 11 ------------------------------------------------------------------------------------------------- disposition
    chain = repo.verify_audit_chain(case)
    last = m.TsAuditEvent.objects.filter(case=case).order_by("-seq").first()
    disp = case.disposition or {}
    fin_rows = [{"item": k, "status": _val(disp.get(k, "not recorded")), "owner": case.owner, "audit / evidence": ""} for k in
                ("resolved", "unchanged_or_expected", "remaining_to_fix", "externally_blocked")]
    fin_rows.append({"item": "final state", "status": case.state, "owner": case.owner,
                     "audit / evidence": f"{m.TsAuditEvent.objects.filter(case=case).count()} audit events; head {(last.event_hash[:16] if last else '—')}; "
                                         f"chain {'VERIFIED' if not chain else 'BROKEN'}"})
    sec["final_disposition"] = _table(["item", "status", "owner", "audit / evidence"], fin_rows, empty="")
    for p in chain:
        limitations.append(f"AUDIT INTEGRITY: {p}")

    report = c.with_schema("incident_report/1", {
        "case_id": case.case_id, "generated_at": c.iso(now), "section_order": list(c.REPORT_SECTION_KEYS),
        "sections": {k: {"title": SECTION_TITLES[k], **sec[k]} for k in c.REPORT_SECTION_KEYS},
        "limitations": list(dict.fromkeys(limitations)), "evidence_index": index,
        "filters": {k: v for k, v in {"device": device, "verdict": verdict, "basis": basis, "since": c.iso(since) if since else None,
                                       "until": c.iso(until) if until else None}.items() if v},
        "freshness": {"generated_at": c.iso(now), "stale_observations": sum(1 for r in norm_rows if r["freshness"] == c.STALE),
                      "note": "Stale/missing data is reported as UNKNOWN; this report is not a live-status claim."},
    })
    c.assert_valid(report, "incident_report/1")
    return report


# ----------------------------------------------------------------------------------------------------------- renderers
def _cell_text(v: Any, fmt: str) -> str:
    if isinstance(v, list) and v and isinstance(v[0], dict) and "evidence_id" in v[0]:
        parts = []
        for link in v:
            label, url, status = link["evidence_id"], link["operator_url"], link["link_status"]
            if status == "OK" and url:
                parts.append(f"[{label}]({url})" if fmt == "md" else f'<a href="{html.escape(url, quote=True)}">{html.escape(label)}</a>')
            elif url:  # unverified / broken but a URL was supplied: show the label with its status, never hide it
                parts.append(f"{label} (link {status}: {url})")
            else:
                parts.append(f"{label} (link {status})")
        return "<br>".join(parts) if fmt == "html" else "; ".join(parts)
    if isinstance(v, list):
        return "—" if not v else ", ".join(str(x) for x in v)
    return "—" if v is None or v == "" else str(v)


def _columns(section: dict) -> list[str]:
    cols = list(section["columns"])
    extra = [k for k in ("basis", "evidence") if k not in cols and any(k in r for r in section["rows"])]
    return cols + extra


def to_markdown(report: dict[str, Any]) -> str:
    out = [f"# Troubleshooting case report — {report['case_id']}", f"_Generated {report['generated_at']}. {report['freshness']['note']}_", ""]
    for key in report["section_order"]:
        sec = report["sections"][key]
        cols = _columns(sec)
        out += [f"## {sec['title']}", "", "| " + " | ".join(cols) + " |", "|" + "---|" * len(cols)]
        for row in sec["rows"]:
            cells = []
            for col in cols:
                v = row.get(col, "—")
                text = _cell_text(v, "md")
                if col == "operator URL" and row.get("link") == "OK" and v not in ("MISSING", "—"):
                    text = f"[{v}]({v})"
                if col == "basis" and v in c.BASIS_LABEL:
                    text = c.BASIS_LABEL[v]
                cells.append(text.replace("|", "\\|").replace("\n", " "))
            out.append("| " + " | ".join(cells) + " |")
        if "_placeholder" in sec["rows"][0]:
            out += ["", f"_{sec['rows'][0]['_placeholder']}_"]
        if "summary" in sec:
            out += ["", "**Summary:** " + c.redact_text(json.dumps(sec["summary"], sort_keys=True))[0]]
        out.append("")
    out += ["## Limitations and evidence gaps", ""] + ([f"- {x}" for x in report["limitations"]] or ["- none recorded"])
    return c.redact_text("\n".join(out))[0] + "\n"


def to_html(report: dict[str, Any]) -> str:
    e = html.escape
    out = [f"<h1>Troubleshooting case report — {e(report['case_id'])}</h1>", f"<p><em>Generated {e(report['generated_at'])}. {e(report['freshness']['note'])}</em></p>"]
    for key in report["section_order"]:
        sec = report["sections"][key]
        cols = _columns(sec)
        out.append(f"<section id=\"{key}\"><h2>{e(sec['title'])}</h2><table><thead><tr>" + "".join(f"<th>{e(x)}</th>" for x in cols) + "</tr></thead><tbody>")
        for row in sec["rows"]:
            cells = []
            for col in cols:
                v = row.get(col, "—")
                if isinstance(v, list) and v and isinstance(v[0], dict) and "evidence_id" in v[0]:
                    cells.append(f"<td>{_cell_text(v, 'html')}</td>")
                elif col == "operator URL" and row.get("link") == "OK" and v not in ("MISSING", "—"):
                    cells.append(f'<td><a href="{e(v, quote=True)}">{e(v)}</a></td>')
                else:
                    cells.append(f"<td>{e(c.BASIS_LABEL.get(v, _cell_text(v, 'html')) if col == 'basis' else _cell_text(v, 'html'))}</td>")
            out.append("<tr>" + "".join(cells) + "</tr>")
        out.append("</tbody></table>")
        if "_placeholder" in sec["rows"][0]:
            out.append(f"<p><em>{e(sec['rows'][0]['_placeholder'])}</em></p>")
        out.append("</section>")
    out.append("<h2>Limitations and evidence gaps</h2><ul>" + "".join(f"<li>{e(x)}</li>" for x in report["limitations"]) + "</ul>")
    return c.redact_text("\n".join(out))[0] + "\n"
