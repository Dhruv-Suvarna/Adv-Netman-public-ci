"""Policy-authorized automated recovery (PREAUTHORIZED_AUTOMATED_RECOVERY): the exact-scoped second caller of the Change Engine.

A Troubleshooter remediation plan that proposes ``interface_enable`` is executed without incident-time human approval ONLY when
  * a standing, owner-created policy (``settings.NMAS_TS_RECOVERY_POLICY_FILE``; absent file == disabled) covers that exact
    (device, interface, operation, intended state) and every ``governance.evaluate_recovery_policy`` gate passes on facts re-read
    NOW (live running-config snapshot, tracked inventory intent, maintenance, device locks, protected-flow samples, history);
  * the EXISTING Remove Configuration workflow, applied to the live snapshot, yields exactly one parser-validated item whose
    rendering is ``interface <X>`` / ``no shutdown`` and whose restore is the captured pre-change ``shutdown``; and
  * the EXISTING lifecycle passes: Change validation, network-config validation, plan, precheck, execution eligibility.
The Change Engine (``execution_service.execute_change``) is the only writer: locks, apply, compensation, postcheck and audit are
its own.  The model never supplies configuration text: the delta is re-derived here from the live snapshot.  Nothing is recorded
as a human approval; the decision record names the policy, the owner authorization and the non-human policy actor.
"""

from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable

from django.conf import settings

from ... import models
from .. import change_plan_service, change_validation_service, execution_service, health_service, workbench_service
from ..config_workbench import removal, semantics, snapshots
from ..execution import capability, eligibility
from . import governance as gov
from . import notify
from . import repository as repo
from .runbooks import hc

POLICY_ACTOR_PREFIX = "nmas-policy:"       # non-human execution identity: nmas-policy:<policy id>


class RecoveryRefused(Exception):
    def __init__(self, code: str, detail: str = ""):
        self.code, self.detail = code, detail
        super().__init__(f"{code}: {detail}" if detail else code)


@dataclass
class RecoveryDeps:
    """Injectable I/O (tests use fakes; production defaults are live)."""
    snapshot: Callable[[str, str], tuple] = lambda device, actor: snapshots.capture_snapshot(device, actor=actor)
    intent: Callable[[str], dict | None] = hc._intended_admin_states
    flows: Callable[[list], bool] = None            # type: ignore[assignment]
    oper_state: Callable[[dict, str], str | None] = None  # type: ignore[assignment]
    execute: Callable[..., Any] = execution_service.execute_change
    validate: Callable[..., Any] = change_validation_service.validate_change
    plan: Callable[..., Any] = change_plan_service.build_change_plan
    precheck: Callable[..., Any] = health_service.run_change_precheck
    notify: Callable[[str, str], bool] = None       # type: ignore[assignment]
    now: Callable[[], datetime] = lambda: datetime.now(timezone.utc)
    extra: dict = field(default_factory=dict)


# ------------------------------------------------------------------------------------------------------------- policy store
def load_policies(path: str | None = None) -> dict[str, dict]:
    path = path if path is not None else getattr(settings, "NMAS_TS_RECOVERY_POLICY_FILE", "")
    if not path or not Path(path).is_file():
        return {}
    data = json.loads(Path(path).read_text())
    return {p["id"]: p for p in data.get("policies", []) if isinstance(p, dict) and p.get("id")}


def policy_for(op: dict, policies: dict[str, dict]) -> dict | None:
    return next((p for p in policies.values() if (p.get("device"), p.get("interface"), p.get("kind")) ==
                 (op.get("device"), op.get("interface"), op.get("kind"))), None)


def _policy(raw: dict) -> gov.RecoveryPolicy:
    return gov.RecoveryPolicy(
        id=raw["id"], owner_authorization=raw.get("owner_authorization", ""), device=raw["device"], interface=raw["interface"],
        kind=raw["kind"], intended_state=raw["intended_state"],
        expires_at=datetime.fromisoformat(raw["expires_at"].replace("Z", "+00:00")), max_executions=int(raw["max_executions"]),
        cooldown_seconds=int(raw["cooldown_seconds"]), enabled=raw.get("enabled") is True,
        max_evidence_age_seconds=int(raw.get("max_evidence_age_seconds", 300)))


# -------------------------------------------------------------------------------------------------------------- live facts
def sample_flows(flows: list) -> bool:
    """Protected-flow readiness: every configured flow answers with zero loss right now (read-only ping from the flow source)."""
    if not flows:
        return False
    for flow in flows:
        argv = ["docker", "exec", flow["container"], "ping", *(["-6"] if int(flow.get("af", 4)) == 6 else []), "-c", "3", "-W", "1",
                "-q", flow["dst"]]
        try:
            out = subprocess.run(argv, capture_output=True, text=True, timeout=15, check=False).stdout
        except (OSError, subprocess.SubprocessError):
            return False
        if " 0% packet loss" not in out:
            return False
    return True


def read_oper_state(raw: dict, interface: str) -> str | None:
    """Read-only ``show interfaces <X> status`` -> "up" (connected) / "down" / None (unreadable)."""
    argv = ["docker", "exec", raw["device_container"], "Cli", "-p", "15", "-c", f"show interfaces {interface} status"]
    try:
        out = subprocess.run(argv, capture_output=True, text=True, timeout=20, check=False).stdout
    except (OSError, subprocess.SubprocessError):
        return None
    short = interface.replace("Ethernet", "Et")
    row = next((line for line in out.splitlines() if line.split()[:1] == [short]), None)
    if row is None:
        return None
    return "up" if " connected " in f" {row} " else "down"


def shutdown_line(snapshot, interface: str) -> int | None:
    """Line number of a literal admin ``shutdown`` directly under ``interface <X>`` in the snapshot; None if absent."""
    model = semantics.build_model(snapshot.text, snapshot.platform)
    for number, attr in model.attributes.items():
        node = model.tree.node(number)
        if node is not None and node.stripped == "shutdown" and attr.kind == "admin_shutdown" \
                and [n.text for n in node.ancestors()] == [f"interface {interface}"]:
            return number
    return None


def _executions(policy_id: str) -> tuple[datetime, ...]:
    rows = models.TsActionExecution.objects.filter(stage_decision=f"policy {policy_id}").exclude(executed_at=None)
    return tuple(r.executed_at for r in rows)


def _conflicting_change(device: str) -> bool:
    return models.ExecutionDeviceLock.objects.filter(device=device).exists()


def _norm(text: str) -> list[str]:
    return [line.rstrip() for line in (text or "").splitlines() if line.strip() and line.strip() != "!"]


# ---------------------------------------------------------------------------------------------------------- the entry point
def recover(plan_id: str, *, deps: RecoveryDeps | None = None, policy_file: str | None = None) -> dict:
    """Evaluate and (only if every gate holds) execute one Troubleshooter plan through the Change Engine.  Returns a summary."""
    deps = deps or RecoveryDeps()
    deps.flows = deps.flows or sample_flows
    deps.oper_state = deps.oper_state or read_oper_state
    deps.notify = deps.notify or (lambda subject, body: notify.send(subject, body))
    plan = models.TsRemediationPlan.objects.select_related("case").get(record_id=plan_id)
    case = plan.case
    if plan.status != "RISK_ASSESSED" or len(plan.operations or []) != 1:
        raise RecoveryRefused("PLAN_NOT_ELIGIBLE", f"{plan.status}, {len(plan.operations or [])} operation(s)")
    op = dict(plan.operations[0])
    raw = policy_for(op, load_policies(policy_file))
    if raw is None:
        raise RecoveryRefused("NO_POLICY", "no standing policy covers this exact target and operation")
    pol = _policy(raw)
    if plan.created_at < deps.now() - timedelta(seconds=pol.max_evidence_age_seconds):
        raise RecoveryRefused("PLAN_STALE", "the proposal is older than the policy's evidence window")
    actor_name = f"{POLICY_ACTOR_PREFIX}{pol.id}"
    actor = repo.Actor(actor_name, "system", tenant=case.tenant, devices=frozenset({pol.device}))
    device, iface = pol.device, pol.interface
    summary: dict[str, Any] = {"plan": plan.record_id, "case": case.case_id, "policy": pol.id, "actor": actor_name,
                               "owner_authorization": pol.owner_authorization, "authorization_type": gov.AUTOMATED_RECOVERY}

    def refuse(code: str, reasons: list[str], **extra):
        gov._set_status(actor, plan, "BLOCKED", f"{code}: {', '.join(reasons)}"[:250], now=deps.now())
        repo.audit(actor, case, "AUTOMATED_RECOVERY_REFUSED", decision=code, result="REFUSED", risk=plan.risk, operation=plan.record_id,
                   rationale="; ".join(reasons)[:900], evidence_ids=plan.evidence_ids, now=deps.now())
        summary.update(result="REFUSED", code=code, reasons=reasons, **extra)
        deps.notify(f"[NMAS] Automated recovery REFUSED for {case.case_id} ({device} {iface})",
                    f"Policy {pol.id} refused plan {plan.record_id}: {code}\nReasons: {', '.join(reasons)}\nA human must review the case.\n")
        return summary

    def facts(snapshot, line, *, rollback_ready: bool) -> gov.RecoveryContext:
        intents = deps.intent(device) or {}
        intended = {"up": "admin_up", "down": "admin_down"}.get(intents.get(iface, ""))
        return gov.RecoveryContext(
            now=deps.now(), executions=_executions(pol.id), authoritative_intent=intended,
            observed_admin_state=("down" if line else "up") if snapshot is not None else None,
            observed_at=snapshot.captured_at if snapshot is not None else None,
            maintenance_active=bool(eligibility._maintenance_conflicts([device])), conflicting_change=_conflicting_change(device),
            management_path_healthy=snapshot is not None, protected_flows_healthy=deps.flows(raw.get("protected_flows") or []),
            rollback_ready=rollback_ready)

    # 1. fresh evidence through the management path; first evaluation (rollback readiness is proven in step 2)
    snapshot, error = deps.snapshot(device, actor_name)
    line = shutdown_line(snapshot, iface) if snapshot is not None else None
    first = gov.evaluate_recovery_policy(pol, op, facts(snapshot, line, rollback_ready=True), risk=plan.risk)
    if first["noop"]:
        repo.audit(actor, case, "AUTOMATED_RECOVERY_NOOP", decision="already in intended state", result="NOOP", risk=plan.risk,
                   operation=plan.record_id, now=deps.now())
        gov._set_status(actor, plan, "BLOCKED", "NOOP: already in the intended state; nothing applied", now=deps.now())
        summary.update(result="NOOP")
        return summary
    if not first["authorized"]:
        return refuse("POLICY_DENIED", first["reasons"] + ([f"SNAPSHOT: {error}"] if error else []))

    # 2. the exact delta from the EXISTING Remove Configuration workflow; scope + rollback readiness from the pre-change state
    selection = workbench_service.removal_selection(models.RemovalMode.LINE_RANGE, from_line=line, to_line=line)
    analysis = workbench_service.analyze_removal(snapshot, models.RemovalMode.LINE_RANGE, selection)
    items = analysis.get("items") or []
    header = f"interface {iface}"
    exact = (analysis.get("status") == "READY" and len(items) == 1 and items[0]["removal_lines"] == [header, "   no shutdown"]
             and not analysis.get("proposals"))
    if not exact:
        return refuse("SCOPE_VIOLATION", ["the derived delta is not exactly 'interface/no shutdown'"], analysis=analysis.get("status"))
    item = items[0]
    rollback_ready = (item["restorable"] and _norm("\n".join(item["restore_lines"])) == [header, "   shutdown"]
                      and item["support"] == removal.PARSER_VALIDATED
                      and capability.capability_for(snapshot.platform, "config_removal_detach").compensation == "SUPPORTED")
    if not rollback_ready:
        return refuse("ROLLBACK_NOT_READY", ["compensation from the captured pre-change state is unavailable"])

    # 3. a real Change, bound to case, plan, policy and evidence; never a human approval
    change = workbench_service.create_removal_change(
        snapshot=snapshot, mode=models.RemovalMode.LINE_RANGE, selection=selection, actor=actor_name,
        title=f"Automated recovery: {device} {iface} admin up ({case.case_id})")
    change.description = (f"PREAUTHORIZED_AUTOMATED_RECOVERY under standing policy {pol.id} (owner authorization "
                          f"{pol.owner_authorization}); Troubleshooter case {case.case_id}, plan {plan.record_id}. Risk {plan.risk} retained.")
    change.execution_mode = models.ExecutionMode.COMPLETE
    change.metadata = {**(change.metadata or {}), "recovery": {
        "authorization_type": gov.AUTOMATED_RECOVERY, "policy_id": pol.id, "owner_authorization": pol.owner_authorization,
        "policy_actor": actor_name, "case_id": case.case_id, "plan_id": plan.record_id, "evidence_ids": list(plan.evidence_ids),
        "operation": op, "risk": plan.risk, "snapshot_id": str(snapshot.snapshot_id), "pre_state": {"admin": "down", "line": line},
        "human_approval": False}}
    change.save(update_fields=["description", "execution_mode", "metadata", "updated_at"])
    summary["change"] = change.change_id
    models.AuditEvent.objects.create(event_type=models.AuditEventType.CHANGE_CREATED, change=change, object_type="Change",
                                     object_id=change.change_id, actor=actor_name[:150],
                                     summary=f"{gov.AUTOMATED_RECOVERY} Change for {case.case_id}/{plan.record_id} under {pol.id}")

    validation = deps.validate(change, actor=actor_name)
    if validation.status not in ("PASS", "PASS_WITH_WARNINGS"):
        return refuse("VALIDATION_NOT_PASSING", [validation.status], change=change.change_id)
    cplan, _ = deps.plan(change, actor=actor_name)
    configlets = list(cplan.configlets.all())
    if len(configlets) != 1 or configlets[0].target_device != device or _norm(configlets[0].rendered_config) != [header, "   no shutdown"] \
            or _norm(configlets[0].rollback_config) not in ([header, "   shutdown"], []):
        return refuse("SCOPE_VIOLATION", ["the Change plan is broader than the policy permits"], change=change.change_id)
    gov._set_status(actor, plan, "DRY_RUN_PASS", f"Change {change.change_id} validated and planned", now=deps.now(),
                    dry_run={"change_id": change.change_id, "validation": validation.status, "plan_id": str(cplan.plan_id),
                             "configlet": configlets[0].cfg_id, "delta": [header, "   no shutdown"]})
    gov._set_status(actor, plan, "PREAUTHORIZED", f"{gov.AUTOMATED_RECOVERY} {pol.id}", now=deps.now(),
                    approval={"mode": gov.AUTOMATED_RECOVERY, "policy_id": pol.id, "owner_authorization": pol.owner_authorization,
                              "policy_actor": actor_name, "approved_by": "", "human_approval": False, "change_id": change.change_id})
    precheck = deps.precheck(change, actor=actor_name)
    if getattr(precheck, "result", "") not in ("PASS", "PASS_WITH_WARNINGS"):
        return refuse("PRECHECK_NOT_PASSING", [str(getattr(precheck, "result", "?"))], change=change.change_id)
    gov._set_status(actor, plan, "PRECHECK_PASS", f"precheck {precheck.result}", now=deps.now())

    # 4. re-evaluate every gate immediately before the write (fresh flows, locks, history)
    final = gov.evaluate_recovery_policy(pol, op, facts(snapshot, line, rollback_ready=True), risk=plan.risk)
    if not final["authorized"]:
        return refuse("POLICY_DENIED_AT_EXECUTION", final["reasons"], change=change.change_id)
    started = deps.now()
    ex = models.TsActionExecution.objects.create(
        record_id=repo._rid("ACT"), case=case, basis="DERIVED", stage="REMEDIATE", stage_decision=f"policy {pol.id}",
        evidence_ids=plan.evidence_ids, plan=plan, pre_state={"admin": "down", "snapshot_id": str(snapshot.snapshot_id), "line": line},
        command_or_intent={"change_id": change.change_id, "operation": op, "policy_id": pol.id, "authorization_type": gov.AUTOMATED_RECOVERY},
        idempotency_key=f"recovery:{pol.id}:{plan.record_id}", executed_at=started, status="EXECUTING",
        rollback={"restore_lines": item["restore_lines"], "mechanism": "Change Engine compensation (captured pre-change state)"})
    gov._set_status(actor, plan, "EXECUTING", f"Change Engine executing {change.change_id}", now=deps.now())
    result = deps.execute(change, actor=actor_name, confirm_mode=models.ExecutionMode.COMPLETE)
    outcome = str(result.outcome)

    # 5. verify actual state: admin (fresh running config) AND oper
    after, _ = deps.snapshot(device, actor_name)
    admin_up = after is not None and shutdown_line(after, iface) is None
    oper = deps.oper_state(raw, iface)
    verified = outcome == models.ExecutionOutcome.SUCCEEDED and admin_up and oper == "up"
    ex.observed_effect = {"execution_outcome": outcome, "run": str(getattr(result.run, "run_id", "")), "admin": "up" if admin_up else "down",
                          "oper": oper, "verified_at": deps.now().isoformat()}
    ex.status = "SUCCEEDED" if verified else ("ABORTED_RESTORED" if "ROLLED_BACK" in outcome else "FAILED")
    ex.save()
    gov._set_status(actor, plan, "VERIFYING", f"Change Engine outcome {outcome}", now=deps.now()) if verified or "ROLLED_BACK" not in outcome else None
    if verified:
        gov._set_status(actor, plan, "RESOLVED", f"{device} {iface} admin up, oper up", now=deps.now())
    elif "ROLLED_BACK" in outcome:
        gov._set_status(actor, plan, "ABORTED_RESTORED", f"{outcome}: compensated to the captured pre-change state", now=deps.now())
    else:
        gov._set_status(actor, plan, "ABORTED_UNRESTORED", f"{outcome}: admin_up={admin_up} oper={oper}", now=deps.now())
    repo.audit(actor, case, "AUTOMATED_RECOVERY_EXECUTED", decision=f"{change.change_id} {outcome}", result="VERIFIED" if verified else "NOT_VERIFIED",
               risk=plan.risk, operation=plan.record_id, evidence_ids=plan.evidence_ids, now=deps.now(),
               rationale=f"{gov.AUTOMATED_RECOVERY} {pol.id} (owner {pol.owner_authorization}); actor {actor_name}; "
                         f"delta '{header} / no shutdown'; admin={'up' if admin_up else 'down'} oper={oper}")
    summary.update(result="VERIFIED" if verified else "NOT_VERIFIED", change=change.change_id, outcome=outcome,
                   admin="up" if admin_up else "down", oper=oper, execution=ex.record_id)
    deps.notify(f"[NMAS] Automated recovery {'COMPLETED' if verified else 'NOT VERIFIED'}: {device} {iface} ({case.case_id})",
                f"Case: {case.case_id}\nPlan: {plan.record_id}\nChange: {change.change_id} ({outcome})\nPolicy: {pol.id} "
                f"(owner authorization {pol.owner_authorization}; actor {actor_name}; {gov.AUTOMATED_RECOVERY}; risk {plan.risk})\n"
                f"Delta: {header} / no shutdown\nVerified: admin {'up' if admin_up else 'down'}, oper {oper}\n")
    return summary


def pending_plans() -> list[str]:
    """RISK_ASSESSED single-operation plans that some standing policy names by exact target (candidates only; recover() decides)."""
    policies = load_policies()
    if not policies:
        return []
    out = []
    window = max(int(p.get("max_evidence_age_seconds", 300)) for p in policies.values())
    fresh = datetime.now(timezone.utc) - timedelta(seconds=window)
    for plan in models.TsRemediationPlan.objects.filter(status="RISK_ASSESSED", created_at__gte=fresh).order_by("created_at"):
        ops = plan.operations or []
        if len(ops) == 1 and isinstance(ops[0], dict) and policy_for(ops[0], policies):
            out.append(plan.record_id)
    return out
