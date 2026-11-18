"""Operator UI + versioned JSON API for the troubleshooting subsystem (spec section 8, M6).

Security model
  * Authentication/tenancy come from a pluggable ``principal resolver`` (``settings.NMAS_TS_PRINCIPAL_RESOLVER``).  The default
    maps a Django-authenticated user: groups ``ts-viewer|ts-operator|ts-approver|ts-admin`` give roles, ``ts-tenant:<name>``
    gives the tenant, ``ts-device:<name>`` limits device scope.  Unauthenticated requests are refused (401 API / 403 page):
    NMAS has no login UI of its own yet, so this surface stays closed until one is configured.
  * Every read/write goes through ``services.troubleshooting.repository`` (tenant + device scoped) or ``governance``.
  * Cross-tenant ids look exactly like missing ids (404).  UI buttons are rendered from ``governance.action_availability``,
    and the same checks are re-run server side on POST.
"""

from __future__ import annotations

import json
import os
import stat
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from functools import wraps
from typing import Callable

from django.conf import settings
from django.http import Http404, HttpResponse, JsonResponse
from django.shortcuts import render
from django.urls import reverse
from django.utils.module_loading import import_string
from django.views.decorators.http import require_http_methods

from . import models as m
from .services.troubleshooting import ai as ts_ai
from .services.troubleshooting import contracts as c
from .services.troubleshooting import governance as gov
from .services.troubleshooting import reporting
from .services.troubleshooting import runtime as ts_runtime
from .services.troubleshooting import repository as repo
from .services.troubleshooting import intake_scope
from .services.identity import policy as nmas_policy
from .services.troubleshooting import verification as ver
from .services.troubleshooting.model_provider import MODEL_SOCKETS

API_SCHEMA = "nmas.troubleshooting.api/1"
API_VERSION = "v1"
ROLE_ORDER = {"viewer": 1, "operator": 2, "approver": 3, "admin": 4}
STAGE_LABEL = {
    "OPEN": "intake", "SCOPING": "scoping", "COLLECTING": "collecting", "ANALYSING": "normalizing / baselining / correlating",
    "TESTING": "testing", "AI_INVESTIGATING": "AI investigating", "REMEDIATING": "remediating", "VERIFYING": "verifying",
    "RESOLVED_VERIFIED": "terminal: resolved (verified)", "NO_FAULT_FOUND": "terminal: no fault found",
    "UNRESOLVED": "terminal: unresolved", "EXTERNALLY_BLOCKED": "terminal: externally blocked",
}
MAX_EXCEPTION_DAYS = 30
# The NMAS permission each remediation plan action needs.  core.services.identity.policy classifies the per-action routes with
# the same values (a contract test keeps the two equal); here it also disables the matching button (UT-089).
PLAN_ACTION_PERMISSION = {
    "dry_run": nmas_policy.Action.VALIDATE, "precheck": nmas_policy.Action.VALIDATE,
    "approve": nmas_policy.Action.APPROVE, "reject": nmas_policy.Action.APPROVE, "execute": nmas_policy.Action.EXECUTE,
}


@dataclass(frozen=True)
class Principal:
    actor: repo.Actor
    roles: frozenset
    # NMAS action permissions the signed-in user holds (``None`` only for a custom resolver that does not report them).
    nmas_actions: frozenset | None = None

    def allows(self, role: str) -> bool:
        return any(ROLE_ORDER.get(r, 0) >= ROLE_ORDER[role] for r in self.roles)


def default_principal(request) -> Principal | None:
    user = getattr(request, "user", None)
    if user is None or not user.is_authenticated or not user.is_active:
        return None
    groups = set(user.groups.values_list("name", flat=True))
    roles = {g[3:] for g in groups if g in ("ts-viewer", "ts-operator", "ts-approver", "ts-admin")}
    if user.is_superuser:
        roles.add("admin")
    tenants = sorted(g.split(":", 1)[1] for g in groups if g.startswith("ts-tenant:"))
    devices = frozenset(g.split(":", 1)[1] for g in groups if g.startswith("ts-device:"))
    if not roles:
        return None
    nmas_actions = frozenset(a for a in nmas_policy.Action if nmas_policy.user_can(user, a))
    return Principal(repo.Actor(user.get_username(), "user", tenant=tenants[0] if tenants else "default",
                                devices=devices or None), frozenset(roles), nmas_actions)


def _principal(request) -> Principal | None:
    resolver = getattr(settings, "NMAS_TS_PRINCIPAL_RESOLVER", "")
    return (import_string(resolver) if resolver else default_principal)(request)


def _ports() -> gov.Ports:
    factory = getattr(settings, "NMAS_TS_PORTS_FACTORY", "")
    return import_string(factory)() if factory else gov.Ports()   # default fails closed: no executor => no enabled write action


def _runtime_deps() -> ts_runtime.RuntimeDeps:
    factory = getattr(settings, "NMAS_TS_RUNTIME_FACTORY", "")
    return import_string(factory)() if factory else ts_runtime.RuntimeDeps()   # default: inventory admission, no transports => all device evidence UNAVAILABLE


def _envelope(data, *, status=200, kind="result"):
    return JsonResponse({"schema": API_SCHEMA, "version": API_VERSION, "kind": kind, "data": data}, status=status, json_dumps_params={"default": str})


def _error(status: int, code: str, message: str, **details):
    return JsonResponse({"schema": API_SCHEMA, "version": API_VERSION, "kind": "error",
                         "error": {"code": code, "message": c.redact_text(message)[0], "details": c.redact_value(details)}}, status=status)


def api(role: str, methods=("GET",)):
    """Auth + role + uniform error mapping.  Cross-tenant => 404, never 403 (no existence oracle)."""
    def deco(fn: Callable):
        @wraps(fn)
        @require_http_methods(list(methods))
        def wrapper(request, *args, **kwargs):
            p = _principal(request)
            if p is None:
                return _error(401, "UNAUTHENTICATED", "authentication with a troubleshooting role is required")
            if not p.allows(role):
                return _error(403, "FORBIDDEN", f"role {role!r} required")
            try:
                return fn(request, p, *args, **kwargs)
            except repo.AccessDenied:
                return _error(404, "NOT_FOUND", "not found in your tenant/project scope")
            except repo.TargetRefused as exc:
                return _error(403, "TARGET_REFUSED", str(exc))
            except repo.IntegrityError_ as exc:
                return _error(409, "INTEGRITY_FAILURE", str(exc))
            except gov.GovernanceRefused as exc:
                return _error(409, exc.code, str(exc), **{k: v for k, v in exc.details.items() if k != "problems"}, problems=exc.details.get("problems", []))
            except ts_ai.AiRefused as exc:
                return _error(409, exc.code, str(exc), gaps=exc.details.get("gaps", []))
            except (ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
                return _error(400, "BAD_REQUEST", str(exc))
        return wrapper
    return deco


def _body(request) -> dict:
    if request.content_type and "json" in request.content_type:
        data = json.loads(request.body or b"{}")
    else:
        data = request.POST.dict()
    if not isinstance(data, dict):
        raise ValueError("request body must be an object")
    return data


def _case(p: Principal, case_id: str) -> m.TsCase:
    return repo.get_case(p.actor, case_id)


def _case_row(case: m.TsCase) -> dict:
    return {"case_id": case.case_id, "title": case.title, "state": case.state, "stage": STAGE_LABEL.get(case.state, case.state),
            "severity": case.severity, "runbook": case.runbook, "opened_at": c.iso(case.opened_at), "closed_at": c.iso(case.closed_at),
            "devices": case.affected_scope.get("devices", []), "outcome": case.disposition.get("outcome", ""),
            "worked_before": case.worked_before, "changed_recently": case.changed_recently, "owner": case.owner,
            "tenant": case.tenant, "schema_version": case.schema_version}


def _socket_state(path: str) -> str:
    """Truthful, non-connecting status for a configured fixed Unix socket."""
    if not path:
        return "NOT_CONFIGURED"
    try:
        return "SOCKET_PRESENT" if stat.S_ISSOCK(os.stat(path, follow_symlinks=False).st_mode) else "PATH_NOT_SOCKET"
    except FileNotFoundError:
        return "SOCKET_ABSENT"
    except OSError:
        return "STATUS_UNAVAILABLE"


_SERVICE_UNITS = {"diagnostic": "nmas-troubleshooter-device-worker.service", "research": "nmas-research-broker.service",
                  "Codex": "nmas-ts-model-broker@codex.service", "ClaudeA": "nmas-ts-model-broker@claude-a.service",
                  "ClaudeB": "nmas-ts-model-broker@claude-b.service"}


def _unit_state(name: str) -> str:
    """systemd's own answer for one fixed NMAS worker unit.  The worker socket directories are private to their IPC
    groups, so the unprivileged website cannot see a running worker's socket; the unit state is the truthful signal."""
    unit = _SERVICE_UNITS.get(name)
    if not unit:
        return "UNKNOWN"
    try:
        import subprocess
        done = subprocess.run(["/usr/bin/systemctl", "is-active", unit], capture_output=True, text=True, timeout=3, check=False)
    except Exception:  # noqa: BLE001 - no systemd access from this process: say so rather than guess
        return "UNKNOWN"
    state = (done.stdout or "").strip().upper()
    return state if state in {"ACTIVE", "INACTIVE", "FAILED", "ACTIVATING", "DEACTIVATING"} else "UNKNOWN"


def _operational_status() -> dict:
    diagnostic = getattr(settings, "NMAS_TS_DIAGNOSTIC_WORKER", {}) or {}
    research = getattr(settings, "NMAS_TS_RESEARCH_WORKER", {}) or {}
    # The workers' reviewed Unix paths are fixed even when the web process is
    # intentionally not given their IPC keys.  Observing socket existence does
    # not grant access, but it lets the operator dashboard report a later
    # activation truthfully without coupling that status to secret-bearing web
    # configuration.
    diagnostic_socket = diagnostic.get("socket") or "/run/nmas-ts-diagnostic/worker.sock"
    research_socket = research.get("socket") or "/run/nmas-ts-research/worker.sock"
    eligible_paths = m.ManagementPath.objects.filter(
        approval_state=m.ManagementApproval.APPROVED,
        health_state=m.ManagementPathHealth.HEALTHY,
        is_active=True,
    ).count()
    lease = m.TsGlobalAgentLease.objects.filter(singleton_key=1).first()
    pool = tuple(getattr(settings, "NMAS_TS_AI_PROVIDER_POOL", tuple(MODEL_SOCKETS)))
    agents = []
    for name, path in MODEL_SOCKETS.items():
        if name not in pool:
            # A provider outside the owner-selected pool is not probed and is never shown as failed or awaiting a key.
            agents.append({"name": name, "enabled": False, "status": "Disabled by owner", "state": "", "service": ""})
            continue
        service, socket_state = _unit_state(name), _socket_state(path)
        running = service == "ACTIVE" or socket_state == "SOCKET_PRESENT"
        agents.append({"name": name, "enabled": True, "state": socket_state, "service": service,
                       "status": "Enabled, broker running" if running else "Enabled, unavailable (broker not running)"})
    brokers_present = sum(1 for agent in agents if agent["enabled"] and agent["status"] == "Enabled, broker running")
    enabled = [agent["name"] for agent in agents if agent["enabled"]]
    history = [{"at": e.get("at", ""), "event": e.get("event", ""), "from": e.get("from", e.get("agent", "")), "to": e.get("to", ""),
                "fence": e.get("fence", ""), "handoff": e.get("handoff", ""), "reason": e.get("reason", "")}
               for e in reversed(list((lease.history if lease else None) or [])[-12:]) if isinstance(e, dict)]
    return {
        "admission_binding": "CONFIGURED" if getattr(settings, "NMAS_TS_DEPLOYMENT", {}) else "NOT_CONFIGURED",
        "eligible_management_paths": eligible_paths,
        "diagnostic": {"state": _socket_state(diagnostic_socket), "service": _unit_state("diagnostic"),
                       "reason": "ready for admitted paths" if eligible_paths else "no ACTIVE, HEALTHY, approved ManagementPath"},
        "research": {"state": _socket_state(research_socket), "service": _unit_state("research"),
                     "approved_hosts": len((getattr(settings, "NMAS_TS_RESEARCH", {}) or {}).get("allowed_hosts", ()))},
        "agents": agents,
        "brokers_present": brokers_present,
        "provider_pool": enabled,
        "failover": ("single provider: when it is unavailable AI work pauses at its checkpoint; there is no failover"
                     if len(enabled) == 1 else f"failover order: {' -> '.join(enabled)}" if enabled else "no provider enabled"),
        "ai_prerequisite": "" if brokers_present else (
            f"no enabled model broker is running ({', '.join(enabled) or 'the provider pool is empty'}): an escalated case "
            "stays OPEN and paused until the broker is available"),
        "lease": {"state": lease.state if lease else "IDLE", "active_agent": lease.active_agent if lease else "",
                  "fencing_token": lease.fencing_token if lease else 0,
                  "handoff_id": lease.handoff.record_id if lease and lease.handoff_id else "",
                  "expires_at": lease.lease_expires_at if lease else None, "history": history,
                  "pause_reason": (history[0]["reason"] if lease and lease.state == "PAUSED" and history else "")},
        # Fault campaigns are recorded only by an authorized live break.py run; fixture simulations are never listed.
        "fault_campaigns": [],
    }


# ----------------------------------------------------------------------------------------------------------------- data
def _stages(p: Principal, case: m.TsCase) -> dict:
    journal = repo.stage_journal(p.actor, case)
    by_stage = {s: [j for j in journal if j["stage"] == s] for s in c.STAGES}
    return {"case_id": case.case_id, "current_state": case.state, "current_stage": STAGE_LABEL.get(case.state, case.state),
            "stages": [{"stage": s, "records": len(by_stage[s]), "items": by_stage[s][:200]} for s in c.STAGES]}


def _evidence_rows(p: Principal, case: m.TsCase) -> list[dict]:
    return [{"evidence_id": r.evidence_id, "source_type": r.source_type, "device": r.device, "command_or_api": r.command_or_api,
             "collected_at": c.iso(r.collected_at), "raw_sha256": r.raw_sha256, "operator_url": r.operator_url, "link_status": r.link_status,
             "quality": r.quality, "redaction_status": r.redaction_status, "adapter": r.adapter, "parser": r.parser}
            for r in m.TsEvidenceRef.objects.filter(case=case).order_by("id") if p.actor.can_see_device(r.device)]


def _plans(p: Principal, case: m.TsCase, ports: gov.Ports) -> list[dict]:
    rows = []
    for plan in m.TsRemediationPlan.objects.filter(case=case).order_by("id"):
        if any(o.get("device") and not p.actor.can_see_device(o["device"]) for o in plan.operations):
            continue
        avail = gov.action_availability(plan, can_approve=p.allows("approver"), ports=ports)
        if not p.allows("operator"):
            avail = {k: {"enabled": False, "reason": "role"} for k in avail}
        if p.nmas_actions is not None:
            avail = {k: (v if not v["enabled"] or PLAN_ACTION_PERMISSION.get(k) in p.nmas_actions else
                         {"enabled": False, "reason": f"NMAS permission {nmas_policy.permission_name(PLAN_ACTION_PERMISSION[k])} required"
                          if k in PLAN_ACTION_PERMISSION else "unknown action"})
                     for k, v in avail.items()}
        execs = [{"record_id": e.record_id, "status": e.status, "stop_reason": e.stop_reason, "idempotency_key": e.idempotency_key,
                  "rollback": e.rollback, "executed_at": c.iso(e.executed_at)} for e in plan.executions.all()]
        rows.append({"plan_id": plan.record_id, "status": plan.status, "tier": plan.tier, "risk": plan.risk, "basis": plan.basis,
                     "operations": plan.operations, "blast_radius": plan.blast_radius, "impacted_flows": plan.impacted_flows,
                     "dry_run": plan.dry_run, "causal_proof": plan.causal_proof, "rollback_plan": plan.rollback_plan,
                     "approval": {k: v for k, v in plan.approval.items()}, "alternative_paths": plan.alternative_paths,
                     "expires_at": c.iso(plan.expires_at), "executions": execs, "actions": avail,
                     "supported": bool(getattr(ports.executor, "configured", False))})
    return c.redact_value(rows)


def _ai(p: Principal, case: m.TsCase) -> list[dict]:
    out = []
    for h in m.TsAIHandoff.objects.filter(case=case).order_by("id"):
        out.append({"handoff_id": h.record_id, "status": h.status, "agent": h.agent_identity, "uncertainty": h.trigger_uncertainty,
                    "allowed_tools": h.allowed_tools, "allowed_targets": [t for t in h.allowed_targets if p.actor.can_see_device(t)],
                    "budget": h.budget, "usage": {k: h.checkpoint.get(k) for k in ("calls", "bytes", "iteration", "failures")},
                    "coverage": {"executed": h.coverage_manifest.get("executed"), "justified_skips": h.coverage_manifest.get("justified_skips"),
                                 "gaps": h.coverage_manifest.get("gaps", [])},
                    "iterations": h.reasoning_log, "return_reason": h.checkpoint.get("closed_reason", ""),
                    "lease": {k: (h.checkpoint.get("execution_lease") or {}).get(k) for k in ("agent", "fence", "state", "reason", "updated_at")}
                    if isinstance(h.checkpoint.get("execution_lease"), dict) else None,
                    "model": {"identity": (h.checkpoint.get("model") or {}).get("identity"),
                              "requests": (h.checkpoint.get("model") or {}).get("requests", 0),
                              "failures": (h.checkpoint.get("model") or {}).get("failures", 0),
                              "last_failure": (h.checkpoint.get("model") or {}).get("last_failure", "")}})
    hyps = [{"record_id": x.record_id, "title": x.title, "state": x.state, "confidence": x.confidence, "basis": x.basis,
             "supporting": x.supporting_evidence, "contradicting": x.contradicting_evidence, "proposed_by": x.proposed_by}
            for x in m.TsHypothesis.objects.filter(case=case).order_by("id")]
    return {"handoffs": c.redact_value(out), "hypotheses": c.redact_value(hyps)}


def _exceptions(case: m.TsCase, now: datetime) -> list[dict]:
    rows = []
    for e in m.TsExceptionPolicy.objects.filter(case=case).order_by("id"):
        rows.append({"exception_id": e.record_id, "scope": e.scope, "reason": e.reason, "requested_by": e.requested_by,
                     "approvals": e.approvals, "expires_at": c.iso(e.expires_at), "status": repo.exception_status(e, dict(e.bound_revisions), now),
                     "basis": e.basis})
    return c.redact_value(rows)


def _detail(p: Principal, case: m.TsCase, ports: gov.Ports, now: datetime) -> dict:
    return {"case": _case_row(case), "service_intent": case.service_intent, "flow_scope": case.flow_scope,
            "symptom": case.symptom, "stages": _stages(p, case), "evidence_count": m.TsEvidenceRef.objects.filter(case=case).count(),
            "ai": _ai(p, case), "remediation": _plans(p, case, ports), "exceptions": _exceptions(case, now),
            "disposition": c.redact_value(case.disposition),
            "drift_vs_live_impact": {
                "config_drift_records": m.TsDriftAssessment.objects.filter(case=case).count(),
                "production_flows": [{"selector": f.selector, "classification": f.classification, "loss_pct": f.current_loss_pct}
                                     for f in m.TsProductionFlowMonitor.objects.filter(case=case)],
                "note": "configuration drift is NOT live service impact; judge impact only from production-flow rows"}}


# ------------------------------------------------------------------------------------------------------------------ API
@api("viewer", ("GET", "POST"))
def api_cases(request, p):
    if request.method == "POST":
        if not p.allows("operator"):
            return _error(403, "FORBIDDEN", "role 'operator' required")
        b = _body(request)
        case = repo.open_case(
            p.actor, trigger_source=b.get("trigger_source") or "operator", trigger_ref=b.get("trigger_ref", ""),
            service_intent=b.get("service_intent"), flow_scope=b.get("flow_scope"),
            affected_scope=b.get("affected_scope") or {"devices": [d for d in str(b.get("devices", "")).split(",") if d.strip()]},
            target_states=b.get("target_states") or {}, severity=b.get("severity", "MEDIUM"),
            idempotency_key=b.get("idempotency_key", ""), title=b.get("title", ""), symptom=b.get("symptom", ""), runbook=b.get("runbook", ""),
            worked_before=b.get("worked_before"), changed_recently=b.get("changed_recently"))
        return _envelope(_case_row(case), status=201, kind="case")
    cases = repo.list_cases(p.actor, state=request.GET.get("state") or None, device=request.GET.get("device") or None)
    q = (request.GET.get("q") or "").lower()
    rows = [_case_row(x) for x in cases if not q or q in (x.title + x.symptom + x.case_id + x.runbook).lower()]
    return _envelope({"cases": rows, "count": len(rows)}, kind="case_list")


@api("viewer")
def api_case(request, p, case_id):
    case = _case(p, case_id)
    return _envelope(_detail(p, case, _ports(), datetime.now(timezone.utc)), kind="case")


@api("operator", ("POST",))
def api_run(request, p, case_id):
    """Explicit, authenticated Stage-1 run.  Body: {runbook?, run_key?, budget?}.  ``target_states`` in the body is ignored: admission is resolved
    from the authoritative inventory.  Budgets are clamped to server caps; the same run_key is idempotent and restart-safe."""
    b = _body(request)
    if not isinstance(b.get("budget", {}), dict):
        raise ValueError("budget must be an object")
    _case(p, case_id)
    result = ts_runtime.run_case(p.actor, case_id, _runtime_deps(), runbook=b.get("runbook") or None, run_key=str(b.get("run_key") or ""),
                                 budget=b.get("budget") or None)
    result["ignored_client_fields"] = sorted(k for k in ("target_states",) if k in b)
    return _envelope(result, kind="runtime_run")


@api("viewer")
def api_stages(request, p, case_id):
    return _envelope(_stages(p, _case(p, case_id)), kind="stages")


@api("viewer")
def api_evidence(request, p, case_id):
    rows = _evidence_rows(p, _case(p, case_id))
    for key in ("device", "source_type"):
        if request.GET.get(key):
            rows = [r for r in rows if r[key] == request.GET[key]]
    return _envelope({"evidence": rows, "count": len(rows), "note": "raw evidence is never returned here; see evidence detail"}, kind="evidence_list")


@api("viewer")
def api_evidence_item(request, p, case_id, evidence_id):
    case = _case(p, case_id)
    ref = m.TsEvidenceRef.objects.filter(case=case, evidence_id=evidence_id).first()
    if ref is None or not p.actor.can_see_device(ref.device):
        raise repo.AccessDenied("evidence")
    row = next(r for r in _evidence_rows(p, case) if r["evidence_id"] == evidence_id)
    if request.GET.get("raw") == "1":
        if not p.allows("admin"):
            return _error(403, "FORBIDDEN", "raw (already-redacted) evidence needs role 'admin'; access is audited")
        row["raw_redacted"] = repo.read_raw_evidence(p.actor, evidence_id, privileged=True)
    return _envelope(row, kind="evidence")


@api("viewer")
def api_report(request, p, case_id):
    case = _case(p, case_id)
    since = c.parse_time(request.GET.get("since")) if request.GET.get("since") else None
    until = c.parse_time(request.GET.get("until")) if request.GET.get("until") else None
    report = reporting.build_report(p.actor, case, device=request.GET.get("device") or None, verdict=request.GET.get("verdict") or None,
                                    basis=request.GET.get("basis") or None, since=since, until=until)
    fmt = request.GET.get("format", "json")
    if fmt == "md":
        return HttpResponse(reporting.to_markdown(report), content_type="text/markdown; charset=utf-8")
    if fmt == "html":
        return HttpResponse(reporting.to_html(report), content_type="text/html; charset=utf-8")
    return _envelope(report, kind="incident_report")


@api("viewer")
def api_ai(request, p, case_id):
    return _envelope(_ai(p, _case(p, case_id)), kind="ai_investigation")


@api("viewer")
def api_remediation(request, p, case_id):
    return _envelope({"plans": _plans(p, _case(p, case_id), _ports())}, kind="remediation")


@api("viewer")
def api_audit(request, p, case_id):
    case = _case(p, case_id)
    events = [{"seq": e.seq, "actor": e.actor, "actor_type": e.actor_type, "tool_id": e.tool_id, "action": e.action, "decision": e.decision,
               "result": e.result, "risk": e.risk, "approver": e.approver, "operation": e.operation, "occurred_at": c.iso(e.occurred_at),
               "event_hash": e.event_hash} for e in m.TsAuditEvent.objects.filter(case=case).order_by("seq")]
    problems = repo.verify_audit_chain(case)
    return _envelope({"events": c.redact_value(events), "chain_ok": not problems, "problems": problems}, kind="audit")


@api("operator")
def api_export(request, p, case_id):
    return _envelope(repo.export_case(p.actor, _case(p, case_id)), kind="export")


@api("operator", ("POST",))
def api_exception(request, p, case_id):
    """Scoped, expiring, operator-confirmed expected anomaly (spec 6.3/8).  Narrow scope + future expiry are mandatory."""
    case = _case(p, case_id)
    b = _body(request)
    scope = b.get("scope")
    if not isinstance(scope, dict) or not {"protocol", "src", "dst"} <= set(scope) and not {"protocol", "path"} <= set(scope):
        raise ValueError("scope must name protocol plus src/dst (or path); blanket exceptions are refused")
    now = datetime.now(timezone.utc)
    expires = c.parse_time(b.get("expires_at"))
    if expires is None or expires <= now or expires > now + timedelta(days=MAX_EXCEPTION_DAYS):
        raise ValueError(f"expires_at must be in the future and within {MAX_EXCEPTION_DAYS} days")
    if len(str(b.get("reason", "")).strip()) < 12:
        raise ValueError("a justification of at least 12 characters is required")
    exc = repo.record(p.actor, case, "exception", basis="OPERATOR_CONFIRMED", stage_decision="operator-confirmed expected deviation",
                      scope=scope, reason=b["reason"], expires_at=expires, bound_revisions=b.get("bound_revisions") or {},
                      approvals=[{"by": p.actor.name, "at": c.iso(now)}], status="ACTIVE")
    repo.audit(p.actor, case, "EXCEPTION_CREATED", decision=exc.record_id, result="ACTIVE", rationale=b["reason"], now=now)
    return _envelope({"exception_id": exc.record_id, "expires_at": c.iso(expires), "scope": scope}, status=201, kind="exception")


def _run_plan_action(p: Principal, case_id: str, plan_id: str, action: str, b: dict) -> tuple[int, str, dict]:
    """Shared by API and UI.  Re-checks availability SERVER-SIDE; a disabled action can never be forced by a crafted POST."""
    case = _case(p, case_id)
    plan = gov.get_plan(p.actor, plan_id)
    if plan.case_id != case.pk:
        raise repo.AccessDenied("plan")
    ports = _ports()
    avail = gov.action_availability(plan, can_approve=p.allows("approver"), ports=ports)
    if action not in avail:
        raise ValueError(f"unknown action {action!r}")
    if p.nmas_actions is not None and PLAN_ACTION_PERMISSION.get(action) not in p.nmas_actions:
        raise gov.GovernanceRefused("ACTION_DISABLED", f"NMAS permission for {action!r} required", action=action, plan_status=plan.status)
    if not avail[action]["enabled"]:
        raise gov.GovernanceRefused("ACTION_DISABLED", avail[action]["reason"] or "action not currently permitted", action=action, plan_status=plan.status)
    if action == "dry_run":
        out = gov.dry_run(p.actor, plan_id, ports)
    elif action == "approve":
        out = gov.approve(p.actor, plan_id, ports, acknowledgements=b.get("acknowledgements") or [], reason=b.get("reason", ""))
    elif action == "reject":
        out = gov.reject(p.actor, plan_id, reason=b.get("reason", "rejected by approver"))
    elif action == "precheck":
        out = gov.precheck(p.actor, plan_id, ports)
    else:
        ex = gov.execute(p.actor, plan_id, ports, idempotency_key=b.get("idempotency_key", ""))
        return 200, "execution", {"execution_id": ex.record_id, "status": ex.status, "stop_reason": ex.stop_reason, "rollback": ex.rollback}
    return 200, "plan", {"plan_id": out.record_id, "status": out.status}


@api("operator", ("POST",))
def api_plan_action(request, p, case_id, plan_id, action):
    status, kind, data = _run_plan_action(p, case_id, plan_id, action, _body(request))
    return _envelope(data, status=status, kind=kind)


@api("viewer")
def api_metrics(request, p):
    return _envelope(ver.metrics(p.actor), kind="metrics")


# ------------------------------------------------------------------------------------------------------------------- UI
def _page(request, template, ctx, status=200):
    # Troubleshooting is an Automation application; keep the established
    # sidebar selected instead of inventing a seventh top-level section.
    return render(request, template, {"page_key": "automation", "page_title": ctx.pop("page_title", "Troubleshooting"), **ctx}, status=status)


def _ui(role: str, methods=("GET",)):
    def deco(fn):
        @wraps(fn)
        @require_http_methods(list(methods))
        def wrapper(request, *args, **kwargs):
            p = _principal(request)
            if p is None or not p.allows(role):
                return HttpResponse("Troubleshooting access requires an authenticated user with a ts-* role.", status=403)
            try:
                return fn(request, p, *args, **kwargs)
            except repo.AccessDenied:
                raise Http404("case not found") from None   # no existence oracle: the denial reason is not chained
        return wrapper
    return deco


@_ui("viewer")
def ui_list(request, p):
    cases = repo.list_cases(p.actor, state=request.GET.get("state") or None, device=request.GET.get("device") or None)
    q = (request.GET.get("q") or "").lower()
    rows = [_case_row(x) for x in cases if not q or q in (x.title + x.symptom + x.case_id + x.runbook).lower()]
    return _page(request, "core/troubleshooting/list.html", {"page_title": "Troubleshooting cases", "cases": rows, "q": request.GET.get("q", ""),
                                                            "can_open": p.allows("operator"), "states": m.TsCaseState.choices,
                                                            "metrics": ver.metrics(p.actor), "operations": _operational_status()})


@_ui("operator", ("GET", "POST"))
def ui_intake(request, p):
    error = ""
    scope_options = intake_scope.options(p.actor)
    if request.method == "POST":
        try:
            b = request.POST
            allowed_devices = {row["name"] for row in scope_options["devices"]}
            devices = [d.strip() for value in b.getlist("devices") for d in value.split(",") if d.strip()]
            if not devices or not set(devices) <= allowed_devices:
                raise ValueError("select at least one current managed device from the displayed scope")
            selected_link = intake_scope.selected_link(scope_options, b.get("link", ""))
            if b.get("link") and selected_link is None:
                raise ValueError("selected link is no longer present in the authoritative topology")
            if selected_link:
                devices = list(dict.fromkeys([*devices, selected_link["a"], selected_link["b"]]))
            proto = b.get("protocol", "").strip()
            ports = [int(x) for x in b.get("ports", "").replace(" ", "").split(",") if x]
            affected_scope = {"devices": devices}
            if selected_link:
                affected_scope["links"] = [selected_link]
            case = repo.open_case(
                p.actor, trigger_source="operator", title=b.get("title", ""), symptom=b.get("symptom", ""), severity=b.get("severity", "MEDIUM"),
                service_intent={"service": b.get("service", "")} if b.get("service") else None,
                flow_scope={"protocol": proto, "ports": ports, "vrf": b.get("vrf", "")} if proto else None,
                affected_scope=affected_scope, target_states={d: "UNKNOWN" for d in devices},
                runbook=b.get("runbook", ""), idempotency_key=b.get("idempotency_key", ""))
            from django.shortcuts import redirect
            return redirect("core:troubleshooting_detail", case_id=case.case_id)
        except (ValueError, repo.AccessDenied) as exc:
            error = str(exc)
    return _page(request, "core/troubleshooting/intake.html", {"page_title": "Open troubleshooting case", "error": error,
                                                              "form": request.POST if request.method == "POST" else {},
                                                              "selected_devices": request.POST.getlist("devices") if request.method == "POST" else [],
                                                              "scope_options": scope_options},
                 status=400 if error else 200)


@_ui("viewer")
def ui_detail(request, p, case_id):
    case = _case(p, case_id)
    now = datetime.now(timezone.utc)
    detail = _detail(p, case, _ports(), now)
    report = reporting.build_report(p.actor, case, now=now)
    return _page(request, "core/troubleshooting/detail.html", {
        "page_title": f"Case {case.case_id}", "d": detail, "report_html": reporting.to_html(report), "evidence": _evidence_rows(p, case),
        "limitations": report["limitations"], "freshness": report["freshness"], "can_operate": p.allows("operator"),
        "terminal": case.state in m.TS_TERMINAL_CASE_STATES, "notice": request.GET.get("notice", "")[:300],
        "operations": _operational_status(), "topology": _topology_view(case)})


def _topology_view(case) -> dict:
    """Topology-aware investigation summary from records already on the case (read-only; nothing is recomputed here)."""
    audits = list(m.TsAuditEvent.objects.filter(case=case, action__in=(
        "REMEDIATION_DECISION", "SECONDARY_SYMPTOM", "TOPOLOGY_PATHS", "TOPOLOGY_PATHS_ERROR", "FAULT_CLEARED_VERIFIED", "INTAKE_DISPATCH",
        "ADMISSION_RESOLVED")).order_by("seq"))
    flows: dict[str, list] = {}
    for row in m.TsTopologyPath.objects.filter(case=case).order_by("id"):
        prov = row.lookup_provenance or {}
        flows.setdefault(row.service or f"{row.source}->{row.destination}", []).append({
            "af": row.address_family, "source": row.source, "destination": row.destination, "branch": prov.get("branch", ""),
            "verdict": prov.get("verdict", ""), "reason": prov.get("reason", ""),
            "hops": " > ".join(f"{h.get('device')}[{h.get('source')} {h.get('prefix')}]" for h in (row.observed_hops or [])),
            "divergence": row.divergence or [], "unreadable": prov.get("unreadable_devices") or []})
    decision = next((a for a in audits if a.action == "REMEDIATION_DECISION"), None)
    return {
        "affected_devices": (case.affected_scope or {}).get("devices") or [],
        "interfaces": (case.affected_scope or {}).get("interfaces") or [],
        "fault_category": (case.service_intent or {}).get("fault_category", ""),
        "decision": decision.result if decision else "", "decision_detail": decision.decision if decision else "",
        "secondary": [a.decision for a in audits if a.action == "SECONDARY_SYMPTOM"],
        "paths_summary": [a.decision for a in audits if a.action in ("TOPOLOGY_PATHS", "TOPOLOGY_PATHS_ERROR")],
        "flows": flows, "admission": [a.decision for a in audits if a.action == "ADMISSION_RESOLVED"],
        "cleared": [a.decision for a in audits if a.action == "FAULT_CLEARED_VERIFIED"],
    }


@_ui("operator", ("POST",))
def ui_escalate(request, p, case_id):
    """Ask NMAS to delegate this case to the AI continuation.  This only opens the governed handoff record: NMAS still
    refuses while deterministic coverage is incomplete, and model execution is started separately by the isolated
    dispatch unit, which is the only process holding the broker IPC keys."""
    from urllib.parse import urlencode

    from django.shortcuts import redirect

    from .services.troubleshooting import ai
    try:
        case = _case(p, case_id)
        handoff = ai.open_handoff(p.actor, case, uncertainty=str(request.POST.get("uncertainty") or ""), agent_identity="")
        status = _operational_status()
        notice = (f"AI handoff {handoff.record_id} is OPEN. " + (
            f"An administrator starts nmas-troubleshooter-dispatch@{handoff.record_id}.service to run it under the global lease."
            if status["brokers_present"] else "It cannot run yet: " + status["ai_prerequisite"] + "."))
    except ai.AiRefused as exc:
        notice = f"AI escalation refused: {exc}"
    except (repo.AccessDenied, ValueError) as exc:
        notice = f"AI escalation refused: {exc}"
    return redirect(reverse("core:troubleshooting_detail", kwargs={"case_id": case_id}) + "?" +
                    urlencode({"notice": c.redact_text(notice)[0][:300]}))


@_ui("operator", ("POST",))
def ui_run(request, p, case_id):
    """HTML counterpart to ``api_run``; it uses the same admission/runtime path."""
    from urllib.parse import urlencode

    from django.shortcuts import redirect
    try:
        _case(p, case_id)
        result = ts_runtime.run_case(
            p.actor,
            case_id,
            _runtime_deps(),
            runbook=request.POST.get("runbook") or None,
            run_key=str(request.POST.get("run_key") or ""),
        )
        notice = f"diagnostic run: {result.get('status', 'completed')}"
    except (repo.AccessDenied, repo.TargetRefused, ValueError) as exc:
        notice = f"diagnostic run refused: {exc}"
    return redirect(reverse("core:troubleshooting_detail", kwargs={"case_id": case_id}) + "?" +
                    urlencode({"notice": c.redact_text(notice)[0][:300]}))


@_ui("operator", ("POST",))
def ui_plan_action(request, p, case_id, plan_id, action):
    from urllib.parse import urlencode

    from django.shortcuts import redirect
    try:
        _s, _k, data = _run_plan_action(p, case_id, plan_id, action, request.POST.dict() | {"acknowledgements": request.POST.getlist("acknowledgements")})
        notice = f"{action}: {data.get('status', 'ok')}"
    except (gov.GovernanceRefused, ValueError) as exc:
        notice = f"{action} refused: {exc}"
    return redirect(reverse("core:troubleshooting_detail", kwargs={"case_id": case_id}) + "?" + urlencode({"notice": c.redact_text(notice)[0][:300]}))
