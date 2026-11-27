"""Engineer reconciliation of an escalated route-source (``RSRC``) monitoring case against fresh live evidence.

Intake never auto-closes ``RSRC`` cases: a learned route-count collapse can only be cleared by an engineer.  This module is
that engineer's step, held to the same evidence bar intake applies to link cases (``Intake._close_cleared``):

- the case is open, was opened by monitoring, carries ``RSRC:<device>:<af>:<source>``, and was not ``AUTO_REMEDIATE``;
- no AI handoff is OPEN, no remediation plan is in flight, no execution lock is held on the device, no maintenance is active;
- two fresh read-only route-summary reads, ``confirm_seconds`` apart, both show the source back at or above the baseline count
  recorded in the case's own deterministic classification;
- when route intent is bound on the running intake, a fresh route-intent pass is HEALTHY for every expectation on the device;
- every protected flow is measured at 0 % loss.

Age is never a reason to close.  When every check passes, the case closes ``UNRESOLVED`` with ``cleared_externally=true`` and
``nmas_performed_repair=false``.  It is never ``RESOLVED_VERIFIED``, because NMAS did not repair it.  Any failed check retains the
case.  A still-present or unreadable condition is escalated to the engineer by email, with coded reasons.  A dry run writes nothing.
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable

from ... import models
from . import faults
from . import intake
from . import notify
from . import repository as repo

ACTOR_NAME = "nmas-engineer-reconcile"
SCHEMA = "nmas.troubleshooting.case-reconciliation/1"


@dataclass
class ReconcileDeps:
    route_sources: Callable[[str, Any], dict | None] = intake.read_route_sources
    route_intent: Callable[[], dict | None] | None = None        # -> route_intent_pass record, or None when unbound
    flows: Callable[[], list[dict]] = intake._protected_flows     # pylint: disable=protected-access
    measure: Callable[[list[dict]], dict] = intake._measure_flows  # pylint: disable=protected-access
    maintenance: Callable[[list[str]], str] = intake.maintenance_reason
    notify: Callable[[str, str], Any] = notify.send
    sleep: Callable[[float], None] = time.sleep
    now: Callable[[], datetime] = lambda: datetime.now(timezone.utc)
    confirm_seconds: float = 30.0


@dataclass
class Verdict:
    case_id: str
    outcome: str = "RETAIN"                  # CLOSE_CLEARED_EXTERNALLY | RETAIN | ESCALATE | REFUSED
    reasons: list[str] = field(default_factory=list)
    checks: dict = field(default_factory=dict)
    applied: bool = False
    closed_state: str = ""

    def as_dict(self) -> dict:
        return {"schema": SCHEMA, "case": self.case_id, "outcome": self.outcome, "reasons": self.reasons,
                "checks": self.checks, "applied": self.applied, "closed_state": self.closed_state}


def default_route_intent_check() -> dict | None:
    """One fresh route-intent pass bound exactly as the running intake unit is (``None`` when the unit binds no intent)."""
    binding = intake.unit_route_intent_binding()
    if not binding.get("bound"):
        return None
    cfg = intake.IntakeConfig.from_settings()
    cfg.route_intent_path = binding["intent_file"]
    cfg.topology_revision = binding["topology_revision"]
    try:
        cfg.route_intent_max_age_seconds = int(binding.get("max_age_seconds") or cfg.route_intent_max_age_seconds)
    except ValueError:
        pass
    engine = intake.Intake(cfg=cfg)
    _incidents, records = engine._intent_route_incidents(datetime.now(timezone.utc))   # pylint: disable=protected-access
    return records[0] if records else {"state": "ERROR", "error_code": "NO_ROUTE_INTENT_RECORD"}


def _baseline(case: models.TsCase) -> tuple[int | None, str]:
    ev = case.evidence_refs.filter(source_type="deterministic_classification").order_by("created_at").first()
    if ev is None or ev.raw_blob is None:
        return None, "BASELINE_EVIDENCE_MISSING"
    try:
        doc = json.loads(ev.raw_blob.content)
        return int(doc["classification"]["evidence"]["baseline_count"]), ev.evidence_id
    except (ValueError, KeyError, TypeError):
        return None, "BASELINE_EVIDENCE_UNPARSEABLE"


def reconcile(case_id: str, *, apply: bool = False, cause_case: str = "", note: str = "",
              deps: ReconcileDeps | None = None) -> Verdict:
    deps = deps or ReconcileDeps(route_intent=default_route_intent_check)
    v = Verdict(case_id)
    case = models.TsCase.objects.filter(case_id=case_id).first()
    if case is None:
        v.outcome, v.reasons = "REFUSED", ["CASE_NOT_FOUND"]
        return v
    if case.state in models.TS_TERMINAL_CASE_STATES:
        v.outcome, v.reasons = "REFUSED", [f"CASE_ALREADY_TERMINAL {case.state}"]
        return v
    parts = (case.trigger_ref or "").split(":")
    if case.trigger_source != intake.TRIGGER_SOURCE or len(parts) != 4 or parts[0] != "RSRC":
        v.outcome, v.reasons = "REFUSED", [f"UNSUPPORTED_CASE {case.trigger_source}/{case.trigger_ref or '-'} (RSRC monitoring cases only)"]
        return v
    _, device, af, source = parts
    decision = models.TsAuditEvent.objects.filter(case=case, action="REMEDIATION_DECISION").order_by("seq").first()
    if decision is None or decision.result == faults.AUTO_REMEDIATE:
        v.outcome, v.reasons = "REFUSED", ["NOT_AN_ESCALATED_CASE (policy recovery owns AUTO cases)"]
        return v

    blockers = []
    if models.TsAIHandoff.objects.filter(case=case, status="OPEN").exists():
        blockers.append("AI_HANDOFF_OPEN")
    if models.TsRemediationPlan.objects.filter(case=case, status__in=intake.IN_FLIGHT_PLAN_STATES).exists():
        blockers.append("REMEDIATION_PLAN_IN_FLIGHT")
    if models.ExecutionDeviceLock.objects.filter(device=device).exists():
        blockers.append("DEVICE_EXECUTION_LOCK_HELD")
    maintenance = deps.maintenance([device])
    if maintenance:
        blockers.append(f"MAINTENANCE_ACTIVE ({maintenance})")
    cause = None
    if cause_case:
        cause = models.TsCase.objects.filter(case_id=cause_case).first()
        if cause is None:
            blockers.append("CAUSE_CASE_NOT_FOUND")
        elif cause.state not in models.TS_TERMINAL_CASE_STATES:
            blockers.append(f"CAUSE_CASE_STILL_OPEN {cause.state}")
    v.checks["blockers"] = blockers

    baseline, baseline_ref = _baseline(case)
    v.checks["baseline"] = {"count": baseline, "evidence": baseline_ref, "kind": "LEARNED_BASELINE recorded at case open"}
    cfg = intake.IntakeConfig.from_settings()
    reads = []
    for i in range(2):
        if i:
            deps.sleep(deps.confirm_seconds)
        doc = deps.route_sources(device, cfg)
        count = ((doc or {}).get(af) or {}).get(source) if doc else None
        reads.append({"at": deps.now().isoformat(), "count": count, "readable": count is not None})
    v.checks["route_source_reads"] = reads
    restored = baseline is not None and all(r["count"] is not None and r["count"] >= baseline for r in reads)
    unreadable = any(not r["readable"] for r in reads) or baseline is None

    intent = deps.route_intent() if deps.route_intent else None
    if intent is None:
        v.checks["route_intent"] = {"state": "NOT_BOUND"}
        intent_ok = True
    else:
        device_items = [i for i in intent.get("items") or [] if i.get("device") == device]
        v.checks["route_intent"] = {"state": intent.get("state"), "pass_id": intent.get("pass_id"),
                                    "error_code": intent.get("error_code"), "routes": intent.get("routes"),
                                    "device_items": device_items}
        intent_ok = intent.get("state") == "HEALTHY" and not device_items

    flows = deps.flows() or []
    measured = deps.measure(flows) if flows else {}
    flows_ok = bool(measured) and all(m.get("loss_pct") == 0.0 for m in measured.values())
    v.checks["protected_flows"] = {k: {"loss_pct": m.get("loss_pct")} for k, m in measured.items()}

    if blockers:
        v.outcome, v.reasons = "RETAIN", blockers
    elif unreadable:
        v.outcome, v.reasons = "ESCALATE", ["INSUFFICIENT_EVIDENCE: route source unreadable or baseline missing"]
    elif not restored:
        v.outcome, v.reasons = "ESCALATE", [f"CONDITION_PRESENT: {device} {af} {source} below baseline {baseline}"]
    elif not intent_ok:
        v.outcome, v.reasons = "ESCALATE", [f"ROUTE_INTENT_NOT_HEALTHY: {v.checks['route_intent']['state']}"]
    elif not flows_ok:
        v.outcome, v.reasons = "ESCALATE", ["PROTECTED_FLOWS_NOT_VERIFIED"]
    else:
        v.outcome = "CLOSE_CLEARED_EXTERNALLY"
        v.reasons = [f"{device} {af} {source} restored to >= baseline {baseline} on two reads {deps.confirm_seconds:.0f}s apart",
                     "route intent healthy" if intent is not None else "route intent not bound",
                     "protected flows 0% loss"]
    if not apply:
        return v

    now = deps.now()
    actor = repo.Actor(ACTOR_NAME, "user", tenant=case.tenant, devices=frozenset(repo._case_devices(case)))  # pylint: disable=protected-access
    evidence_doc = {"schema": SCHEMA, "case": case.case_id, "fingerprint": case.trigger_ref, "checks": v.checks,
                    "outcome": v.outcome, "reasons": v.reasons, "cause_case": cause_case or None, "note": note[:500]}
    ev = repo.store_evidence(actor, case, source_type="engineer_reconciliation", device=device,
                             command_or_api="read-only route summary x2; route-intent pass; protected-flow probes",
                             adapter=ACTOR_NAME, parser="reconcile", parser_version="1", collected_at=now,
                             raw=json.dumps(evidence_doc, sort_keys=True, default=str))
    if v.outcome == "CLOSE_CLEARED_EXTERNALLY":
        disposition = {"outcome": "SAFE_NON_REMEDIATION", "remediation_decision": decision.result,
                       "fault_category": (case.service_intent or {}).get("fault_category", ""),
                       "cleared_externally": True, "nmas_performed_repair": False, "verified_at": now.isoformat(),
                       "closed_by": "engineer reconciliation (nmas_ts_reconcile_case)",
                       "route_source": {"device": device, "af": af, "source": source, "baseline": baseline,
                                        "observed": [r["count"] for r in reads]},
                       "route_intent": v.checks["route_intent"].get("state"),
                       "route_intent_pass_id": v.checks["route_intent"].get("pass_id"),
                       "protected_flows": v.checks["protected_flows"], "protected_flows_baseline_ok": True,
                       "cause_case": cause_case or None,
                       "root_cause_status": "EXTERNAL_CAUSE_CORRELATED" if cause is not None else "UNDETERMINED",
                       "note": note[:500], "evidence_ids": [ev.evidence_id]}
        repo.audit(actor, case, "FAULT_CLEARED_VERIFIED", decision=v.reasons[0][:200], result="VERIFIED",
                   rationale=json.dumps(disposition, default=str)[:3000], evidence_ids=[ev.evidence_id], now=now)
        repo.close_case(actor, case, "UNRESOLVED", disposition=disposition, now=now)
        v.closed_state = "UNRESOLVED"
        deps.notify(f"[NMAS] {case.case_id}: route-source fault cleared externally (no NMAS change)",
                    f"{case.trigger_ref} is back at or above its baseline; route intent and protected flows verified.\n"
                    f"Closed UNRESOLVED with cleared_externally=true by engineer reconciliation. Cause case: {cause_case or 'none'}.\n")
    else:
        repo.audit(actor, case, "ENGINEER_RECONCILIATION", decision=f"{v.outcome}: {'; '.join(v.reasons)}"[:200],
                   result=v.outcome, rationale=json.dumps(evidence_doc, default=str)[:3000], evidence_ids=[ev.evidence_id], now=now)
        if v.outcome == "ESCALATE":
            deps.notify(f"[NMAS] {case.case_id}: reconciliation escalated ({v.reasons[0][:80]})",
                        f"{case.trigger_ref} was re-verified and is NOT cleared: {'; '.join(v.reasons)}.\nThe case stays open for an engineer.\n")
    v.applied = True
    return v
