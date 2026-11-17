"""M5 remediation governance (spec section 6): tiering, risk/blast radius, dry-run, approval, locks, idempotency, traffic guard,
compensation with readback, honest outcomes.

NMAS stays the single policy authority.  This module never writes to a device itself: every write goes through an injected
``Ports.executor``.  In production that is ``ChangeEngineExecutor``, a hand-off to the existing change workflow: it runs the
read-only execution-eligibility gate, and the referenced Change is executed only from its Change page (the change engine keeps
exactly one caller, the explicit execution POST view -- core.tests.test_contracts).  Everything else
(maintenance, redundancy proof, production-flow sampling, step-up/MFA) is a port that FAILS CLOSED when unconfigured.

Plan status machine (``TsRemediationPlan.status``)::

    PROPOSED -> RISK_ASSESSED -> DRY_RUN_PASS -> APPROVED|PREAUTHORIZED -> PRECHECK_PASS -> EXECUTING -> VERIFYING
              -> SOAKING -> RESOLVED
    any pre-execution state -> REJECTED | BLOCKED | EXPIRED ;  EXECUTING -> ABORTED_RESTORED | ABORTED_UNRESTORED | INTERRUPTED
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Callable

from django.db import IntegrityError, transaction

from core import models as m

from . import contracts as c
from . import repository as repo

# ------------------------------------------------------------------------------------------------------------- constants
OP_KINDS = {
    # kind: (traffic_affecting, base_risk)
    "config_hotfix": (True, "HIGH"), "acl_change": (True, "HIGH"), "qos_change": (True, "HIGH"),
    "routing_metric_change": (True, "HIGH"), "path_preference_change": (True, "HIGH"), "traffic_drain": (True, "HIGH"),
    "interface_bounce": (True, "HIGH"), "interface_shutdown": (True, "HIGH"), "neighbor_reset": (True, "HIGH"),
    "process_restart": (True, "HIGH"), "config_rollback": (True, "HIGH"), "mtu_change": (True, "MEDIUM"),
    "mss_clamp": (False, "MEDIUM"), "dns_record_update": (False, "MEDIUM"), "dns_cache_flush": (False, "LOW"),
    "counter_clear": (False, "LOW"), "debounce_config": (False, "MEDIUM"),
    # Restore an interface's administrative state to its intended UP.  Bringing a link into service reconverges forwarding,
    # so it is traffic-affecting with the same base risk as interface_shutdown/bounce; it is never blanket Tier 3.
    "interface_enable": (True, "HIGH"),
}
# Operation kinds that need extra structured fields (validated with the schema; no configuration text is ever accepted).
OP_REQUIRED_FIELDS = {"interface_enable": {"interface": None, "intended_state": "admin_up"}}
# The ONE remediation-operation contract.  The model-facing tool schema (ai.TOOLS["propose_remediation"]["schema"]) is this
# object, and propose() enforces it server-side, so the AI-facing and server-side contracts cannot diverge.  Operations are
# structured intent only: no configuration text is accepted.  The exact configuration lives in the referenced NMAS Change
# (change_id), which only the Change page executes.
_OP_NAME = r"^[A-Za-z][A-Za-z0-9/._:-]{0,63}$"
OPERATION_SCHEMA = {
    "type": "object", "additionalProperties": False, "required": ["kind", "device"],
    "properties": {
        "kind": {"type": "string", "enum": sorted(OP_KINDS)},
        "device": {"type": "string", "pattern": _OP_NAME, "description": "managed device in case scope"},
        "interface": {"type": "string", "pattern": _OP_NAME, "description": "interface the operation concerns, if any"},
        "intended_state": {"type": "string", "enum": ["admin_up", "admin_down"],
                           "description": "intended state the operation restores, from configuration intent"},
        "summary": {"type": "string", "maxLength": 200, "description": "human-readable intent of the operation"},
        "change_id": {"type": "string", "pattern": r"^CHG-[A-Za-z0-9-]{1,40}$",
                      "description": "NMAS Change that carries the exact configuration; required before dry-run"},
    },
}
ROLLBACK_SCHEMA = {
    "type": "object", "required": ["steps"],
    "properties": {"steps": {"type": "array", "minItems": 1, "items": {"type": "string", "maxLength": 300}}},
}


def validate_operation(op: Any) -> str:
    """'' when ``op`` satisfies OPERATION_SCHEMA, else the first violation (mirrors the schema exactly)."""
    import re as _re
    if not isinstance(op, dict):
        return "operation must be an object"
    props = OPERATION_SCHEMA["properties"]
    extra = sorted(set(op) - set(props))
    if extra:
        return f"unsupported operation field(s): {', '.join(extra)}"
    for k in OPERATION_SCHEMA["required"]:
        if k not in op:
            return f"operation is missing required field {k!r}"
    for k, want in OP_REQUIRED_FIELDS.get(op.get("kind"), {}).items():
        if k not in op:
            return f"operation kind {op.get('kind')!r} requires field {k!r}"
        if want is not None and op.get(k) != want:
            return f"operation kind {op.get('kind')!r} requires {k}={want!r}"
    for k, v in op.items():
        spec = props[k]
        if not isinstance(v, str):
            return f"operation field {k!r} must be a string"
        if "enum" in spec and v not in spec["enum"]:
            return f"operation field {k!r} value {v!r} is not supported"
        if "maxLength" in spec and len(v) > spec["maxLength"]:
            return f"operation field {k!r} is too long"
        if "pattern" in spec and not _re.fullmatch(spec["pattern"], v):
            return f"operation field {k!r} is malformed"
    return ""


DRAIN_LIKE = {"traffic_drain", "routing_metric_change", "path_preference_change", "interface_shutdown", "interface_bounce"}
STATES = ("PROPOSED", "RISK_ASSESSED", "DRY_RUN_PASS", "APPROVED", "PREAUTHORIZED", "PRECHECK_PASS", "EXECUTING", "VERIFYING",
          "SOAKING", "RESOLVED", "REJECTED", "BLOCKED", "EXPIRED", "ABORTED_RESTORED", "ABORTED_UNRESTORED", "INTERRUPTED")
_NEXT = {
    "PROPOSED": {"RISK_ASSESSED", "BLOCKED", "REJECTED", "EXPIRED"},
    "RISK_ASSESSED": {"DRY_RUN_PASS", "BLOCKED", "REJECTED", "EXPIRED"},
    "DRY_RUN_PASS": {"APPROVED", "PREAUTHORIZED", "BLOCKED", "REJECTED", "EXPIRED"},
    "APPROVED": {"PRECHECK_PASS", "BLOCKED", "EXPIRED", "REJECTED"},
    "PREAUTHORIZED": {"PRECHECK_PASS", "BLOCKED", "EXPIRED", "REJECTED"},
    "PRECHECK_PASS": {"EXECUTING", "BLOCKED", "EXPIRED"},
    "EXECUTING": {"VERIFYING", "ABORTED_RESTORED", "ABORTED_UNRESTORED", "INTERRUPTED"},
    "VERIFYING": {"SOAKING", "RESOLVED", "ABORTED_RESTORED", "ABORTED_UNRESTORED"},
    "SOAKING": {"RESOLVED", "ABORTED_RESTORED", "ABORTED_UNRESTORED"},
    "INTERRUPTED": {"BLOCKED", "ABORTED_RESTORED", "ABORTED_UNRESTORED"},
}
ACTIVE_LEASE_STATES = ("EXECUTING",)
DEFAULT_LEASE_SECONDS = 600
DEFAULT_ABORT = {"max_loss_increase_pct": 1.0, "min_coverage": 0.8}
DEFAULT_RATE = {"window_seconds": 3600, "per_device": 3, "per_case": 5}


class GovernanceRefused(Exception):
    """A guard refused the request.  ``code`` is stable; ``details`` carry the reasons (never secrets)."""

    def __init__(self, code: str, message: str = "", **details):
        super().__init__(f"{code}: {message}" if message else code)
        self.code, self.details = code, details


def _now() -> datetime:
    return datetime.now(timezone.utc)


# ---------------------------------------------------------------------------------------------------------------- ports
class UnconfiguredExecutor:
    """Fail-closed default: no write path configured => nothing is supported and nothing is executed."""
    configured = False

    def supports(self, op: dict) -> bool:
        return False

    def dry_run(self, plan: dict) -> dict:
        return {"ok": False, "errors": ["no executor configured"]}

    def apply(self, op: dict) -> dict:
        raise GovernanceRefused("EXECUTOR_UNCONFIGURED", "no change-workflow executor is wired")

    def readback(self, plan: dict) -> dict:
        raise GovernanceRefused("EXECUTOR_UNCONFIGURED")

    def compensate(self, plan: dict, applied: list[dict]) -> dict:
        raise GovernanceRefused("EXECUTOR_UNCONFIGURED")


def _unknown_device(_d: str) -> dict:
    return {"admission": "UNKNOWN", "maintenance": None, "lifecycle": "UNKNOWN"}


def _no_alternate(_plan: dict, _op: dict) -> dict:
    return {"verified": False, "capacity_ok": False, "lossless_demonstrated": False, "evidence_ids": []}


def _no_samples(flows: list) -> dict:
    return {}


@dataclass
class Ports:
    executor: Any = field(default_factory=UnconfiguredExecutor)
    device_state: Callable[[str], dict] = _unknown_device
    alternate_paths: Callable[[dict, dict], dict] = _no_alternate
    flow_sample: Callable[[list], dict] = _no_samples
    step_up: Callable[[repo.Actor, m.TsRemediationPlan], bool] | None = None   # NMAS has no MFA service; see governance.md
    require_step_up: bool = False
    preauthorizations: Callable[[dict], dict | None] = lambda op: None          # NMAS policy store lookup (Tier 3)
    exception_status: Callable[[m.TsExceptionPolicy], str] | None = None
    clock: Callable[[], datetime] = _now
    lease_seconds: int = DEFAULT_LEASE_SECONDS
    rate_limit: dict = field(default_factory=lambda: dict(DEFAULT_RATE))


class ChangeEngineExecutor:
    """Production binding: a hand-off to the EXISTING change workflow, never a second path into the change engine.

    The plan must reference a ``Change`` (``operations[*].change_id``) that has gone through Device Builder validation, planning
    and precheck.  ``dry_run`` calls the real, read-only execution-eligibility gate.  Execution itself is not available from
    troubleshooting: the public platform's change engine has exactly one caller, the explicit Change execution POST view, which
    owns device locks, ordering, postchecks and rollback.  ``supports()`` is therefore False (nothing reaches EXECUTING), the
    plan shows ``HANDOFF_REASON``, and ``apply`` refuses as defence in depth.  Widening that boundary needs separate approval.
    """
    configured = True
    HANDOFF_CODE = "EXECUTION_VIA_CHANGE_WORKFLOW"
    HANDOFF_REASON = "execute the referenced Change from its Change page; troubleshooting does not call the change engine"

    def __init__(self, change_loader: Callable[[str], Any], *, actor: str = "troubleshooting",
                 readback_provider: Callable[[dict], dict] | None = None,
                 rollback_runner: Callable[[str], dict] | None = None):
        self.load, self.actor = change_loader, actor
        self.readback_provider, self.rollback_runner = readback_provider, rollback_runner

    def references_change(self, op: dict) -> bool:
        return bool(op.get("change_id")) and self.load(op["change_id"]) is not None

    def supports(self, op: dict) -> bool:   # pylint: disable=unused-argument
        return False

    def dry_run(self, plan: dict) -> dict:
        from core.services.execution import eligibility
        errors = []
        for cid in {o.get("change_id") for o in plan["operations"]}:
            change = self.load(cid) if cid else None
            if change is None:
                errors.append(f"change {cid!r} not found")
                continue
            report = eligibility.check_execution_eligibility(change, for_submission=False)
            if not report.eligible:
                errors.append(f"{cid}: {', '.join(report.codes)}")
        return {"ok": not errors, "errors": errors, "mode": "eligibility-gate (read-only)"}

    def apply(self, op: dict) -> dict:
        raise GovernanceRefused(self.HANDOFF_CODE, f"{op.get('change_id') or 'change'}: {self.HANDOFF_REASON}")

    def readback(self, plan: dict) -> dict:
        if self.readback_provider is None:
            raise GovernanceRefused("READBACK_UNAVAILABLE", "no read-back provider configured")
        return self.readback_provider(plan)

    def compensate(self, plan: dict, applied: list[dict]) -> dict:
        if self.rollback_runner is None:
            raise GovernanceRefused("COMPENSATION_UNAVAILABLE", "no rollback runner configured")
        return {"results": [self.rollback_runner(o["change_id"]) for o in applied]}


# ------------------------------------------------------------------------------------------------- risk / tier assessment
def assess(operations: list[dict], *, flows: list[dict] | None = None, ports: Ports | None = None) -> dict[str, Any]:
    """Pure-ish risk evaluation.  Tier 1 = read-only; anything that can change state is Tier 2 unless a stored, unexpired,
    narrowly-scoped pre-authorization (Tier 3) covers EVERY operation and none of them is traffic-affecting."""
    ports = ports or Ports()
    if not operations:
        return {"tier": 1, "risk": "NONE", "traffic_affecting": False, "reasons": ["read-only: no operations"], "preauth": []}
    reasons, traffic, rank, preauth = [], False, 0, []
    order = {"LOW": 1, "MEDIUM": 2, "HIGH": 3}
    all_pre = True
    for op in operations:
        kind = op.get("kind")
        if kind not in OP_KINDS:
            raise GovernanceRefused("UNKNOWN_OPERATION", f"operation kind {kind!r} is not registered")
        affecting, base = OP_KINDS[kind]
        traffic |= affecting
        rank = max(rank, order[base])
        reasons.append(f"{kind}@{op.get('device', '?')}: base risk {base}{' traffic-affecting' if affecting else ''}")
        pa = ports.preauthorizations(op)
        if pa and not affecting and pa.get("expires_at") and c.parse_time(pa["expires_at"]) > ports.clock() \
                and pa.get("devices") and op.get("device") in pa["devices"] and pa.get("idempotent") is True:
            preauth.append(pa.get("id", "?"))
        else:
            all_pre = False
    tier = 3 if (all_pre and preauth and not traffic and rank <= 1) else 2   # "bounce/clear/restart" are never blanket Tier 3
    if flows and traffic:
        rank = 3
    return {"tier": tier, "risk": {1: "LOW", 2: "MEDIUM", 3: "HIGH"}[max(rank, 1)], "traffic_affecting": traffic,
            "reasons": reasons, "preauth": preauth if tier == 3 else []}


# ------------------------------------------------------------------------------------------------------------ transitions
def _set_status(actor: repo.Actor, plan: m.TsRemediationPlan, new: str, why: str = "", *, now: datetime | None = None, **fields) -> m.TsRemediationPlan:
    plan = m.TsRemediationPlan.objects.get(pk=plan.pk)
    if new == plan.status:
        return plan
    if new not in _NEXT.get(plan.status, set()):
        raise GovernanceRefused("ILLEGAL_TRANSITION", f"{plan.status} -> {new}")
    old = plan.status
    plan.status = new
    for k, v in fields.items():
        setattr(plan, k, v)
    plan.save()
    repo.audit(actor, plan.case, "REMEDIATION_STATE", decision=f"{plan.record_id}: {old} -> {new}", result=new, risk=plan.risk,
               rationale=why, operation=plan.record_id, now=now)
    return plan


def _plan(actor: repo.Actor, plan_id: str) -> m.TsRemediationPlan:
    plan = m.TsRemediationPlan.objects.filter(record_id=plan_id).select_related("case").first()
    if plan is None or plan.case.tenant != actor.tenant:
        raise repo.AccessDenied("plan not found in the caller's tenant/project scope")
    return plan


def get_plan(actor: repo.Actor, plan_id: str) -> m.TsRemediationPlan:
    plan = _plan(actor, plan_id)
    for dev in {o.get("device") for o in plan.operations}:
        if dev and not actor.can_see_device(dev):
            raise repo.AccessDenied("plan touches a device outside the caller's authorization")
    return plan


def _expire_if_due(actor, plan, now):
    if plan.expires_at and plan.expires_at <= now and plan.status in ("PROPOSED", "RISK_ASSESSED", "DRY_RUN_PASS", "APPROVED", "PREAUTHORIZED", "PRECHECK_PASS"):
        _set_status(actor, plan, "EXPIRED", "plan/approval window elapsed", now=now)
        raise GovernanceRefused("PLAN_EXPIRED", plan.record_id)
    return plan


# ---------------------------------------------------------------------------------------------------------------- propose
def propose(actor: repo.Actor, case: m.TsCase, *, operations: list[dict], causal_evidence_ids: list[str], rollback_plan: dict,
            impacted_flows: list[dict] | None = None, addressed_fault: str = "", abort_thresholds: dict | None = None,
            soak_required: bool | None = None, expected_dataplane_effect: str = "", ttl: timedelta = timedelta(hours=4),
            ports: Ports | None = None, now: datetime | None = None) -> m.TsRemediationPlan:
    """Create a PROPOSED plan.  Agents may propose; they can never approve or self-authorize a tier (UT-063/066)."""
    ports = ports or Ports()
    now = now or ports.clock()
    case = repo.get_case(actor, case.case_id)
    repo._check_open(case)
    if not addressed_fault.strip():
        raise GovernanceRefused("FAULT_NOT_IDENTIFIED", "a plan must name the fault it addresses")
    ids = repo._validate_evidence_ids(case, causal_evidence_ids)
    if not ids:
        raise GovernanceRefused("NO_CAUSAL_EVIDENCE", "a plan needs causal evidence from this case")
    if not operations:
        raise GovernanceRefused("NO_OPERATIONS", "a plan needs at least one exact operation")
    if not isinstance(rollback_plan, dict) or not rollback_plan.get("steps"):
        raise GovernanceRefused("NO_ROLLBACK_PLAN", "a rollback/compensation plan is mandatory")
    if not isinstance(operations, list):
        raise GovernanceRefused("INVALID_OPERATION", "operations must be a list of operation objects")
    for op in operations:
        problem = validate_operation(op)
        if problem:
            raise GovernanceRefused("INVALID_OPERATION", problem)
    for op in operations:
        dev = op.get("device")
        if not dev or not actor.can_see_device(dev):
            raise repo.AccessDenied(f"device {dev!r} is outside the caller's authorization")
        if dev not in repo._case_devices(case):
            raise repo.AccessDenied(f"device {dev!r} is not in case scope")
    _expected_deviation_guard(case, addressed_fault, operations, ports, now)
    risk = assess(operations, flows=impacted_flows, ports=ports)
    tier = 2 if actor.actor_type == "agent" else risk["tier"]  # an agent's proposal is never auto-Tier 3 (tier 3 = pre-authorized)
    plan = repo.record(
        actor, case, "remediation_plan", basis="AI_INFERRED" if actor.actor_type == "agent" else "DERIVED", evidence_ids=ids,
        stage_decision=f"proposed {len(operations)} op(s), tier {tier}, risk {risk['risk']}", now=now,
        tier=tier, operations=operations, risk=risk["risk"],
        blast_radius={"devices": sorted({o["device"] for o in operations}), "traffic_affecting": risk["traffic_affecting"],
                      "reasons": risk["reasons"]},
        impacted_flows=list(impacted_flows or []), preconditions=[], alternative_paths=[], dry_run={}, causal_proof=ids,
        rollback_plan=rollback_plan,
        approval={"proposed_by": actor.name, "proposer_type": actor.actor_type, "addressed_fault": addressed_fault,
                  "expected_dataplane_effect": expected_dataplane_effect, "preauth": risk["preauth"],
                  "abort_thresholds": {**DEFAULT_ABORT, **(abort_thresholds or {})},
                  "soak_required": risk["traffic_affecting"] if soak_required is None else bool(soak_required),
                  "approved_by": "", "approved_at": ""},
        expires_at=now + ttl, status="PROPOSED")
    plan = _set_status(actor, plan, "RISK_ASSESSED", "; ".join(risk["reasons"]), now=now)
    return plan


def _expected_deviation_guard(case, addressed_fault, operations, ports, now):
    """UT-078: an operator-confirmed expected non-production deviation (e.g. ICMP denied) never justifies remediation unless
    the production flow itself is measurably impaired.  Real production loss is NEVER masked by an exception (UT-034)."""
    for exc in m.TsExceptionPolicy.objects.filter(case=case):
        status = ports.exception_status(exc) if ports.exception_status else repo.exception_status(exc, dict(exc.bound_revisions), now)
        if status != "ACTIVE":
            continue
        proto = str(exc.scope.get("protocol", "")).lower()
        if proto and proto in addressed_fault.lower():
            prod_loss = [f for f in m.TsProductionFlowMonitor.objects.filter(case=case, classification="PRODUCTION")
                         if (f.current_loss_pct or 0) > 0]
            if not prod_loss:
                raise GovernanceRefused("EXPECTED_DEVIATION_NO_PRODUCTION_IMPACT",
                                        f"fault concerns {proto!r}, covered by active exception {exc.record_id}; no production loss measured")


# --------------------------------------------------------------------------------------------------------------- dry-run
def dry_run(actor: repo.Actor, plan_id: str, ports: Ports, *, now: datetime | None = None) -> m.TsRemediationPlan:
    plan = get_plan(actor, plan_id)
    now = now or ports.clock()
    _expire_if_due(actor, plan, now)
    if plan.status != "RISK_ASSESSED":
        raise GovernanceRefused("ILLEGAL_TRANSITION", f"dry-run needs RISK_ASSESSED, plan is {plan.status}")
    unsupported = [o for o in plan.operations if not ports.executor.supports(o)]
    if unsupported:
        out = {"ok": False, "errors": [f"unsupported operation {o.get('kind')}@{o.get('device')}" for o in unsupported]}
    else:
        out = ports.executor.dry_run({"operations": plan.operations, "case": plan.case.case_id})
    doc = c.redact_value({"ok": bool(out.get("ok")), "errors": list(out.get("errors", [])), "ran_at": c.iso(now),
                          "mode": out.get("mode", "executor")})
    plan.dry_run = doc
    plan.save()
    if not doc["ok"]:
        _set_status(actor, plan, "BLOCKED", "dry-run failed: " + "; ".join(doc["errors"])[:300], now=now)
        raise GovernanceRefused("DRY_RUN_FAILED", "; ".join(doc["errors"]))
    return _set_status(actor, plan, "DRY_RUN_PASS", "dry-run passed", now=now)


# -------------------------------------------------------------------------------------------------------------- approval
def approve(actor: repo.Actor, plan_id: str, ports: Ports, *, acknowledgements: list[str] | None = None,
            reason: str = "", now: datetime | None = None) -> m.TsRemediationPlan:
    plan = get_plan(actor, plan_id)
    now = now or ports.clock()
    _expire_if_due(actor, plan, now)
    if actor.actor_type != "user":
        repo.audit(actor, plan.case, "APPROVAL_DENIED", decision="non-human actors cannot approve", result="DENIED", risk=plan.risk, operation=plan.record_id, now=now)
        raise GovernanceRefused("AGENT_CANNOT_APPROVE", "approval is a human NMAS decision")
    if actor.name == plan.approval.get("proposed_by"):
        repo.audit(actor, plan.case, "APPROVAL_DENIED", decision="proposer cannot approve own plan", result="DENIED", risk=plan.risk, operation=plan.record_id, now=now)
        raise GovernanceRefused("SELF_APPROVAL", "a different human must approve")
    if plan.status != "DRY_RUN_PASS":
        raise GovernanceRefused("ILLEGAL_TRANSITION", f"approval needs DRY_RUN_PASS, plan is {plan.status}")
    needed = ["I understand this may affect production traffic"] if plan.blast_radius.get("traffic_affecting") else []
    if set(needed) - set(acknowledgements or []):
        raise GovernanceRefused("ACK_MISSING", "required acknowledgement not given", required=needed)
    if len(reason.strip()) < 8:
        raise GovernanceRefused("REASON_REQUIRED", "approval needs a recorded rationale")
    if ports.require_step_up and not (ports.step_up and ports.step_up(actor, plan)):
        repo.audit(actor, plan.case, "APPROVAL_DENIED", decision="step-up authentication failed/unavailable", result="DENIED", risk=plan.risk, operation=plan.record_id, now=now)
        raise GovernanceRefused("STEP_UP_REQUIRED", "step-up/MFA verification missing or unavailable")
    approval = {**plan.approval, "approved_by": actor.name, "approved_at": c.iso(now), "reason": c.redact_text(reason)[0],
                "acknowledgements": list(acknowledgements or [])}
    plan = _set_status(actor, plan, "APPROVED", reason, now=now, approval=approval)
    repo.audit(actor, plan.case, "APPROVAL_GRANTED", decision=f"tier {plan.tier} {plan.record_id}", result="APPROVED", risk=plan.risk,
               approver=actor.name, operation=plan.record_id, rationale=reason, now=now)
    return plan


def preauthorize(actor: repo.Actor, plan_id: str, ports: Ports, *, now: datetime | None = None) -> m.TsRemediationPlan:
    """Tier 3 only: every operation must still be covered by an unexpired stored pre-authorization at this instant."""
    plan = get_plan(actor, plan_id)
    now = now or ports.clock()
    _expire_if_due(actor, plan, now)
    risk = assess(plan.operations, ports=ports)
    if plan.tier != 3 or risk["tier"] != 3 or plan.approval.get("proposer_type") == "agent":
        raise GovernanceRefused("NOT_PREAUTHORIZED", "plan is not Tier 3 / not covered by a valid pre-authorization")
    plan = _set_status(actor, plan, "PREAUTHORIZED", "tier 3 preauthorization " + ",".join(risk["preauth"]), now=now,
                       approval={**plan.approval, "approved_by": "preauthorization:" + ",".join(risk["preauth"]), "approved_at": c.iso(now)})
    repo.audit(actor, plan.case, "PREAUTHORIZATION_APPLIED", decision=",".join(risk["preauth"]), result="OK", risk=plan.risk, operation=plan.record_id, now=now)
    return plan


def reject(actor: repo.Actor, plan_id: str, *, reason: str, ports: Ports | None = None, now: datetime | None = None) -> m.TsRemediationPlan:
    plan = get_plan(actor, plan_id)
    if actor.actor_type != "user":
        raise GovernanceRefused("AGENT_CANNOT_APPROVE")
    return _set_status(actor, plan, "REJECTED", reason, now=now)


# ---------------------------------------------------------------------------------------------------------------- precheck
def precheck(actor: repo.Actor, plan_id: str, ports: Ports, *, now: datetime | None = None) -> m.TsRemediationPlan:
    """Maintenance/lifecycle/admission, verified-redundancy and traffic-guard preconditions (UT-069..071).  A failed
    precheck BLOCKS the plan with every reason recorded; nothing is attempted."""
    plan = get_plan(actor, plan_id)
    now = now or ports.clock()
    _expire_if_due(actor, plan, now)
    if plan.status not in ("APPROVED", "PREAUTHORIZED"):
        raise GovernanceRefused("NOT_AUTHORIZED", f"plan is {plan.status}; approval is required before precheck")
    problems, checks, alternatives = [], [], []
    for dev in sorted({o["device"] for o in plan.operations}):
        st = ports.device_state(dev)
        adm = st.get("admission") if st.get("admission") != "UNKNOWN" else plan.case.target_states.get(dev, "UNKNOWN")
        checks.append({"device": dev, "admission": adm, "maintenance": st.get("maintenance"), "lifecycle": st.get("lifecycle")})
        if adm != "VERIFIED":
            problems.append(f"{dev}: admission/lifecycle is {adm}, not VERIFIED")
        if st.get("lifecycle") in ("DECOMMISSIONED", "WITHDRAWN", "DECOMMISSIONING"):
            problems.append(f"{dev}: lifecycle {st.get('lifecycle')} forbids changes")
        if st.get("maintenance") is None:
            problems.append(f"{dev}: maintenance state UNKNOWN")
        elif st.get("maintenance") and not plan.approval.get("maintenance_window_ack"):
            problems.append(f"{dev}: device is in a maintenance/isolation state not covered by this plan")
        if _device_locked(dev, exclude_plan=plan):
            problems.append(f"{dev}: LOCK_CONFLICT with another change/execution")
    traffic = plan.blast_radius.get("traffic_affecting")
    flows = plan.impacted_flows
    if traffic:
        sample = ports.flow_sample(flows) if flows else {}
        for f in flows:
            s = sample.get(f.get("key"), {})
            if s.get("loss_pct") is None or (s.get("coverage") or 0) < plan.approval["abort_thresholds"]["min_coverage"]:
                problems.append(f"flow {f.get('key')}: production flow not measurable (coverage {s.get('coverage')}); cannot guard traffic")
        if not flows:
            problems.append("traffic-affecting plan names no impacted production flows; blast radius cannot be assessed")
        for op in plan.operations:
            if op["kind"] in DRAIN_LIKE or OP_KINDS[op["kind"]][0]:
                alt = ports.alternate_paths({"flows": flows, "case": plan.case.case_id}, op)
                alternatives.append({"op": op["kind"], "device": op["device"], **{k: alt.get(k) for k in ("verified", "capacity_ok", "lossless_demonstrated", "evidence_ids")}})
                if op["kind"] in DRAIN_LIKE:
                    if not (alt.get("verified") and alt.get("capacity_ok")):
                        problems.append(f"{op['kind']}@{op['device']}: NO_VERIFIED_ALTERNATE_PATH (existing redundancy not demonstrated with capacity)")
                    elif not alt.get("lossless_demonstrated"):
                        plan_ack = plan.approval.get("loss_accepted_by")
                        if not plan_ack:
                            problems.append(f"{op['kind']}@{op['device']}: losslessness not demonstrated; explicit traffic-stop approval required")
    problems += _rate_problems(plan, ports, now)
    plan.preconditions, plan.alternative_paths = checks, alternatives
    plan.save()
    if problems:
        _set_status(actor, plan, "BLOCKED", "; ".join(problems)[:500], now=now)
        raise GovernanceRefused("PRECHECK_FAILED", "; ".join(problems), problems=problems)
    return _set_status(actor, plan, "PRECHECK_PASS", "all preconditions satisfied", now=now)


def _device_locked(dev: str, *, exclude_plan=None) -> bool:
    if m.ExecutionDeviceLock.objects.filter(device=dev).exists():
        return True
    for ex in m.TsActionExecution.objects.filter(status__in=ACTIVE_LEASE_STATES):
        if exclude_plan is not None and ex.plan_id == exclude_plan.pk:
            continue
        if dev in ex.command_or_intent.get("devices", []):
            return True
    # The legacy Phase-21 rollback engine (and its RollbackDeviceLock) is not part of this repository.  Device writes go through
    # the execution engine, which takes ExecutionDeviceLock (checked above) and the host-level DeviceMutex itself.
    return False


def _rate_problems(plan, ports, now):
    rl, out = ports.rate_limit, []
    since = now - timedelta(seconds=rl["window_seconds"])
    recent = m.TsActionExecution.objects.filter(executed_at__gte=since)
    if recent.filter(case=plan.case).count() >= rl["per_case"]:
        out.append("RATE_LIMIT: per-case execution budget exhausted")
    for dev in {o["device"] for o in plan.operations}:
        if sum(1 for e in recent if dev in e.command_or_intent.get("devices", [])) >= rl["per_device"]:
            out.append(f"RATE_LIMIT: device {dev} change budget exhausted")
    return out


# ------------------------------------------------------------------------------------------------------------------ execute
def execute(actor: repo.Actor, plan_id: str, ports: Ports, *, idempotency_key: str, now: datetime | None = None) -> m.TsActionExecution:
    """Run the plan.  Replays with the same key return the stored execution WITHOUT touching a device (UT-067).

    Never raises for an operational failure: loss/failed op => bounded abort, compensation, readback, honest status.
    """
    if not idempotency_key:
        raise GovernanceRefused("IDEMPOTENCY_KEY_REQUIRED")
    plan = get_plan(actor, plan_id)
    now = now or ports.clock()
    prior = m.TsActionExecution.objects.filter(idempotency_key=idempotency_key).first()
    if prior is not None:
        if prior.plan_id != plan.pk:
            raise GovernanceRefused("IDEMPOTENCY_KEY_REUSED", "key belongs to another plan")
        return prior
    if plan.tier > 1 and actor.actor_type == "agent":
        raise GovernanceRefused("AGENT_CANNOT_EXECUTE", "agents propose; NMAS executes after approval")
    _expire_if_due(actor, plan, now)
    if plan.status != "PRECHECK_PASS":
        raise GovernanceRefused("NOT_READY", f"plan is {plan.status}; precheck must pass first")
    thresholds = plan.approval["abort_thresholds"]
    devices = sorted({o["device"] for o in plan.operations})
    for dev in devices:
        if _device_locked(dev, exclude_plan=plan):
            raise GovernanceRefused("LOCK_CONFLICT", f"{dev} is locked by another change")
    flows = plan.impacted_flows
    before = ports.flow_sample(flows) if flows else {}
    pre_state = _safe_readback(ports, plan)
    lease = f"lease:{uuid.uuid4().hex[:12]}:{c.iso(now + timedelta(seconds=ports.lease_seconds))}"
    try:
        with transaction.atomic():
            ex = m.TsActionExecution.objects.create(
                record_id=repo._rid("ACT"), case=plan.case, basis="DERIVED", stage="REMEDIATE", stage_decision="executing",
                evidence_ids=plan.evidence_ids, plan=plan, pre_state=c.redact_value(pre_state),
                command_or_intent={"devices": devices, "operations": [{k: v for k, v in o.items() if k != "acknowledgements"} for o in plan.operations],
                                   "baseline_flows": before},
                idempotency_key=idempotency_key, lock_lease=lease, executed_at=now, status="EXECUTING")
            plan = _set_status(actor, plan, "EXECUTING", "lock acquired " + lease.split(":")[1], now=now)
            if plan.case.state in ("TESTING", "AI_INVESTIGATING"):
                repo.transition_case(actor, plan.case, "REMEDIATING", reason="governed remediation started", now=now)
            repo.audit(actor, plan.case, "ACTION_STARTED", decision=idempotency_key, result="EXECUTING", risk=plan.risk,
                       approver=plan.approval.get("approved_by", ""), operation=plan.record_id, now=now)
    except IntegrityError:
        return m.TsActionExecution.objects.get(idempotency_key=idempotency_key)
    return _drive(actor, plan, ex, ports, before, thresholds, now)


def _safe_readback(ports, plan):
    try:
        return ports.executor.readback({"operations": plan.operations, "case": plan.case.case_id})
    except Exception as exc:  # pylint: disable=broad-exception-caught  # noqa: BLE001
        return {"unavailable": str(exc)[:200]}


def _breach(before: dict, after: dict, th: dict) -> str:
    for key, s in after.items():
        base = (before.get(key) or {}).get("loss_pct")
        cur = s.get("loss_pct")
        if cur is None or (s.get("coverage") or 0) < th["min_coverage"]:
            return f"flow {key}: production loss unmeasurable during change (coverage {s.get('coverage')})"
        if cur - (base or 0.0) > th["max_loss_increase_pct"]:
            return f"flow {key}: loss {cur}% vs pre-change {base or 0.0}% exceeds +{th['max_loss_increase_pct']}%"
    return ""


def _drive(actor, plan, ex, ports, before, th, now):
    applied, stop = [], ""
    effects = []
    for op in plan.operations:
        try:
            eff = ports.executor.apply(op)
        except Exception as exc:  # pylint: disable=broad-exception-caught  # noqa: BLE001
            eff = {"ok": False, "error": str(exc)[:200]}
        effects.append({"op": op["kind"], "device": op["device"], **c.redact_value(eff)})
        if not eff.get("ok"):
            stop = f"operation {op['kind']}@{op['device']} failed: {eff.get('error') or eff.get('outcome') or eff.get('blockers')}"
            if eff.get("partial", True):
                applied.append(op)   # a failed apply may be partial; compensate it too
            break
        applied.append(op)
        if plan.impacted_flows:
            stop = _breach(before, ports.flow_sample(plan.impacted_flows), th)
            if stop:
                break
    ex = m.TsActionExecution.objects.get(pk=ex.pk)
    ex.observed_effect = {"effects": effects}
    if not stop:
        ex.status, ex.stop_reason = "APPLIED", ""
        ex.save()
        repo.audit(actor, plan.case, "ACTION_APPLIED", decision=ex.idempotency_key, result="APPLIED", risk=plan.risk, operation=plan.record_id,
                   approver=plan.approval.get("approved_by", ""), now=now)
        _set_status(actor, plan, "VERIFYING", "applied; verification pending", now=now)
        if repo.get_case(actor, plan.case.case_id).state == "REMEDIATING":
            repo.transition_case(actor, plan.case, "VERIFYING", reason="action applied", now=now)
        return ex
    return _abort(actor, plan, ex, ports, before, applied, stop, now)


def _abort(actor, plan, ex, ports, before, applied, stop, now):
    """Bounded abort -> compensation -> read-back AND traffic verification; only then may it be called RESTORED (UT-073/075/076)."""
    comp, restored, notes = {}, False, []
    try:
        comp = ports.executor.compensate({"operations": plan.operations, "case": plan.case.case_id, "rollback_plan": plan.rollback_plan}, applied)
        post = _safe_readback(ports, plan)
        pre = ex.pre_state
        readback_ok = "unavailable" not in pre and "unavailable" not in post and post == pre
        if not readback_ok:
            notes.append("config read-back does not match pre-change state" if "unavailable" not in post else "read-back unavailable")
        traffic_ok = True
        if plan.impacted_flows:
            now_s = ports.flow_sample(plan.impacted_flows)
            bad = _breach(before, now_s, plan.approval["abort_thresholds"])
            traffic_ok = not bad
            if bad:
                notes.append("traffic not restored: " + bad)
        restored = readback_ok and traffic_ok
    except Exception as exc:  # pylint: disable=broad-exception-caught  # noqa: BLE001
        notes.append(f"compensation failed: {str(exc)[:200]}")
    rollback = {"attempted": True, "result": c.redact_value(comp), "verified": restored, "notes": notes}
    ex = m.TsActionExecution.objects.get(pk=ex.pk)
    ex.rollback, ex.stop_reason = rollback, c.redact_text(stop)[0][:255]
    ex.status = "ABORTED_RESTORED" if restored else "ABORTED_UNRESTORED"
    ex.save()
    final = ex.status
    repo.audit(actor, plan.case, "ACTION_ABORTED", decision=stop, result=final, risk=plan.risk, operation=plan.record_id,
               approver=plan.approval.get("approved_by", ""), rationale="; ".join(notes), now=now)
    _set_status(actor, plan, final, stop, now=now)
    outcome = "REMEDIATION_FAILED_RESTORED" if restored else "REMEDIATION_FAILED_UNRESTORED"
    disp = {"outcome": outcome, "stop_reason": ex.stop_reason, "rollback_verified": restored, "service_impact_remaining": not restored,
            "notes": notes, "plan": plan.record_id}
    state = repo.get_case(actor, plan.case.case_id).state
    if not restored and state in ("REMEDIATING", "TESTING"):
        # Unrestored: case is unresolved, impact stays visible; never claim the rollback worked.
        repo.transition_case(actor, plan.case, "UNRESOLVED", reason=outcome, disposition=disp, now=now)
    elif restored and state == "REMEDIATING":
        repo.transition_case(actor, plan.case, "TESTING", reason=outcome, now=now)
    return ex


# ----------------------------------------------------------------------------------------------------------- restart recovery
def recover(actor: repo.Actor, case: m.TsCase, ports: Ports, *, now: datetime | None = None) -> list[dict]:
    """After a crash an EXECUTING row with an expired lease is INTERRUPTED; state is UNKNOWN until read-back proves otherwise.
    It is never silently retried: a human or a new idempotency key + fresh approval is required."""
    now = now or ports.clock()
    case = repo.get_case(actor, case.case_id)
    out = []
    for ex in m.TsActionExecution.objects.filter(case=case, status="EXECUTING"):
        # lease string = lease:<token>:<iso>; the ISO timestamp itself contains ':'
        expiry = c.parse_time(ex.lock_lease.split(":", 2)[2]) if ex.lock_lease.count(":") >= 2 else None
        if expiry and expiry > now:
            out.append({"execution": ex.record_id, "action": "LEASE_STILL_HELD"})
            continue
        post = _safe_readback(ports, ex.plan)
        matches = "unavailable" not in post and post == ex.pre_state
        ex.status, ex.stop_reason = "INTERRUPTED", "worker/process lost during execution (lease expired)"
        ex.rollback = {"attempted": False, "verified": False, "readback_matches_pre_state": matches}
        ex.save()
        plan = _set_status(actor, ex.plan, "INTERRUPTED", "lease expired", now=now)
        repo.audit(actor, case, "ACTION_INTERRUPTED", decision=ex.record_id, result="INTERRUPTED", operation=plan.record_id,
                   rationale=f"read-back matches pre-state: {matches}", now=now)
        _set_status(actor, plan, "BLOCKED", "interrupted execution requires explicit re-approval", now=now)
        out.append({"execution": ex.record_id, "action": "INTERRUPTED", "readback_matches_pre_state": matches})
    return out


# ------------------------------------------------------------------------------------------------------ UI/API availability
def action_availability(plan: m.TsRemediationPlan, *, can_approve: bool, ports: Ports, now: datetime | None = None) -> dict[str, dict]:
    """Server-computed truth for the UI (UT-089): an action is enabled ONLY when it would currently be accepted."""
    now = now or ports.clock()
    st = plan.status
    supported = all(ports.executor.supports(o) for o in plan.operations) if getattr(ports.executor, "configured", False) else False
    expired = bool(plan.expires_at and plan.expires_at <= now)
    why_unsupported = "" if supported else str(getattr(ports.executor, "unsupported_reason", "") or "")
    def row(ok, why):
        return {"enabled": bool(ok), "reason": "" if ok else why}
    return {
        "dry_run": row(st == "RISK_ASSESSED" and supported and not expired,
                       why_unsupported or "needs RISK_ASSESSED, a configured executor supporting every op, and an unexpired plan"),
        "approve": row(st == "DRY_RUN_PASS" and can_approve and not expired, "needs DRY_RUN_PASS, approver role and unexpired plan"),
        "reject": row(st in ("RISK_ASSESSED", "DRY_RUN_PASS", "APPROVED", "PREAUTHORIZED") and can_approve, "not rejectable in this state or no approver role"),
        "precheck": row(st in ("APPROVED", "PREAUTHORIZED") and not expired, "needs approval first"),
        "execute": row(st == "PRECHECK_PASS" and supported and can_approve and not expired,
                       why_unsupported or "needs passed precheck, supported executor, approver role"),
    }


# ------------------------------------------------------------------------------------------- standing automated recovery policy
# Owner-approved design change (2026-11-17): an owner-created standing policy may authorize ONE exact traffic-affecting recovery
# operation without incident-time human approval.  It is not an approver: its decision record is PREAUTHORIZED_AUTOMATED_RECOVERY,
# the assessed risk is retained (never downgraded), and every gate below must hold or automation stops and escalates.
# Disabled by default; nothing in production consults it until the Change Engine entry point is wired.
AUTOMATED_RECOVERY = "PREAUTHORIZED_AUTOMATED_RECOVERY"
RECOVERY_OPERATIONS = frozenset({"interface_enable"})      # the only kinds a standing policy may ever cover


@dataclass(frozen=True)
class RecoveryPolicy:
    id: str
    owner_authorization: str
    device: str
    interface: str
    kind: str
    intended_state: str
    expires_at: datetime
    max_executions: int
    cooldown_seconds: int
    enabled: bool = False
    max_evidence_age_seconds: int = 300


@dataclass(frozen=True)
class RecoveryContext:
    """Facts re-verified immediately before execution (never taken from the model)."""
    now: datetime
    executions: tuple[datetime, ...]          # prior executions under this policy
    authoritative_intent: str | None          # re-read from the authoritative intent source; None = unknown
    observed_admin_state: str | None
    observed_at: datetime | None
    maintenance_active: bool
    conflicting_change: bool
    management_path_healthy: bool
    protected_flows_healthy: bool
    rollback_ready: bool


def evaluate_recovery_policy(policy: RecoveryPolicy | None, op: dict, ctx: RecoveryContext, *, risk: str) -> dict[str, Any]:
    """Decide whether ``op`` may run unattended under ``policy``.  Returns every failed gate; authorized only if none fail.
    ``noop`` is True when the target is already in its intended state (idempotent: nothing must be applied)."""
    reasons: list[str] = []
    problem = validate_operation(op)
    if problem:
        reasons.append(f"INVALID_OPERATION: {problem}")
    if policy is None or not policy.enabled:
        reasons.append("POLICY_NOT_ACTIVE")
    else:
        if policy.kind not in RECOVERY_OPERATIONS:
            reasons.append("POLICY_OPERATION_NOT_RECOVERABLE")
        if (op.get("kind"), op.get("device"), op.get("interface"), op.get("intended_state")) != \
                (policy.kind, policy.device, policy.interface, policy.intended_state):
            reasons.append("POLICY_SCOPE_MISMATCH")
        if not policy.owner_authorization:
            reasons.append("OWNER_AUTHORIZATION_MISSING")
        if policy.expires_at <= ctx.now:
            reasons.append("POLICY_EXPIRED")
        if len(ctx.executions) >= policy.max_executions:
            reasons.append("EXECUTION_LIMIT_EXHAUSTED")
        if ctx.executions and (ctx.now - max(ctx.executions)).total_seconds() < policy.cooldown_seconds:
            reasons.append("COOLDOWN_ACTIVE")
        if ctx.observed_at is None or (ctx.now - ctx.observed_at).total_seconds() > policy.max_evidence_age_seconds:
            reasons.append("EVIDENCE_STALE")
    if ctx.authoritative_intent is None:
        reasons.append("INTENT_UNAVAILABLE")
    elif ctx.authoritative_intent != op.get("intended_state"):
        reasons.append("INTENT_DOES_NOT_REQUIRE_STATE")        # e.g. intentionally disabled: never "recover" it
    if ctx.maintenance_active:
        reasons.append("MAINTENANCE_ACTIVE")
    if ctx.conflicting_change:
        reasons.append("CONFLICTING_CHANGE")
    if not ctx.management_path_healthy:
        reasons.append("MANAGEMENT_PATH_NOT_HEALTHY")
    if not ctx.protected_flows_healthy:
        reasons.append("PROTECTED_FLOWS_NOT_HEALTHY")
    if not ctx.rollback_ready:
        reasons.append("ROLLBACK_NOT_READY")
    wanted = {"admin_up": "up", "admin_down": "down"}.get(str(op.get("intended_state")))
    noop = ctx.observed_admin_state is not None and wanted is not None and str(ctx.observed_admin_state).lower() == wanted
    if ctx.observed_admin_state is None:
        reasons.append("OBSERVED_STATE_UNAVAILABLE")
    return {"authorized": not reasons and not noop, "noop": noop and not reasons, "authorization_type": AUTOMATED_RECOVERY,
            "policy_id": policy.id if policy else "", "owner_authorization": policy.owner_authorization if policy else "",
            "risk": risk, "reasons": reasons}
