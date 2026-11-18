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
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable

from django.conf import settings

from ... import models
from .. import change_plan_service, change_validation_service, execution_service, health_service, workbench_service
from ..config_workbench import removal, semantics, snapshots
from ..execution import capability, eligibility
from . import contracts as c
from . import governance as gov
from . import notify
from . import repository as repo
from . import verification
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
    ci_wait: Callable[[Any], str] = None            # type: ignore[assignment]
    flow_measure: Callable[[list], dict] = None     # type: ignore[assignment]
    case_settle_seconds: float = 90.0
    now: Callable[[], datetime] = lambda: datetime.now(timezone.utc)
    extra: dict = field(default_factory=dict)


# ------------------------------------------------------------------------------------------------------------- policy store
def load_policies(path: str | None = None) -> dict[str, dict]:
    path = path if path is not None else getattr(settings, "NMAS_TS_RECOVERY_POLICY_FILE", "")
    if not path or not Path(path).is_file():
        return {}
    data = json.loads(Path(path).read_text())
    return {p["id"]: p for p in data.get("policies", []) if isinstance(p, dict) and p.get("id")}


def policy_active(raw: dict, now: datetime | None = None) -> bool:
    """Enabled, not revoked and not expired (the remaining gates are evaluated at execution time)."""
    now = now or datetime.now(timezone.utc)
    try:
        expires = datetime.fromisoformat(str(raw.get("expires_at", "")).replace("Z", "+00:00"))
    except ValueError:
        return False
    return raw.get("enabled") is True and not raw.get("revoked_at") and expires > now


def policy_for(op: dict, policies: dict[str, dict]) -> dict | None:
    """The policy covering ``op``'s exact target: an active one if any (a successor supersedes an expired/exhausted
    predecessor), otherwise the first match so the refusal names the real reason (expired, revoked, ...)."""
    matches = [p for p in policies.values() if (p.get("device"), p.get("interface"), p.get("kind")) ==
               (op.get("device"), op.get("interface"), op.get("kind"))]
    return next((p for p in matches if policy_active(p)), matches[0] if matches else None)


def scope_executions(raw: dict, policies: dict[str, dict]) -> tuple[datetime, ...]:
    """Executions of OTHER policies for the same exact scope: a successor policy still honours the cooldown."""
    key = (raw.get("device"), raw.get("interface"), raw.get("kind"))
    out: tuple[datetime, ...] = ()
    for pid, p in policies.items():
        if pid != raw["id"] and (p.get("device"), p.get("interface"), p.get("kind")) == key:
            out += _executions(pid)
    return out


def _policy(raw: dict) -> gov.RecoveryPolicy:
    return gov.RecoveryPolicy(
        id=raw["id"], owner_authorization=raw.get("owner_authorization", ""), device=raw["device"], interface=raw["interface"],
        kind=raw["kind"], intended_state=raw["intended_state"],                    # revocation: revoked_at set => inactive
        expires_at=datetime.fromisoformat(raw["expires_at"].replace("Z", "+00:00")), max_executions=int(raw["max_executions"]),
        cooldown_seconds=int(raw["cooldown_seconds"]), enabled=raw.get("enabled") is True and not raw.get("revoked_at"),
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


def measure_flows(flows: list) -> dict:
    """{flow name: {"loss_pct", "coverage", "raw"}} from a read-only 5-probe ping per protected flow (None loss == unmeasurable)."""
    out = {}
    for flow in flows:
        argv = ["docker", "exec", flow["container"], "ping", *(["-6"] if int(flow.get("af", 4)) == 6 else []), "-c", "5", "-W", "1",
                "-q", flow["dst"]]
        try:
            text = subprocess.run(argv, capture_output=True, text=True, timeout=20, check=False).stdout
        except (OSError, subprocess.SubprocessError) as exc:
            text = f"{type(exc).__name__}"
        loss = next((float(tok.rstrip("%")) for line in text.splitlines() if "packet loss" in line
                     for tok in line.replace(",", " ").split() if tok.endswith("%")), None)
        sent = next((int(line.split()[0]) for line in text.splitlines() if "packets transmitted" in line), 0)
        out[flow["name"]] = {"loss_pct": loss, "coverage": 1.0 if sent >= 5 else sent / 5, "raw": text}
    return out


def _case_to(actor, case, state: str, why: str, now):
    """Advance the case only along a legal lifecycle edge; never forces a state."""
    case = repo.get_case(actor, case.case_id)
    if state == case.state or state not in repo._TRANSITIONS.get(case.state, set()):
        return case
    return repo.transition_case(actor, case, state, reason=why[:250], now=now)


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


def wait_configuration_validation(change, *, timeout: float = 180.0, interval: float = 5.0) -> str:
    """The external (GitHub Actions) Configuration Validation is asynchronous: wait (bounded) for its verdict on this exact
    Change instead of meeting the engine gate while it is still QUEUED.  Never bypasses it: the engine re-checks the gate."""
    from ..configuration_validation import service as ci   # noqa: PLC0415

    if not ci.enabled() or ci.exempt(change):
        return "PASS"
    deadline = time.monotonic() + timeout
    while True:
        row = ci.latest(change)
        status = "NOT_TRIGGERED" if row is None else ci.effective_status(ci.refresh(row))
        if status not in ("QUEUED", "IN_PROGRESS") or time.monotonic() >= deadline:
            return status
        time.sleep(interval)


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
    deps.ci_wait = deps.ci_wait or wait_configuration_validation
    deps.flow_measure = deps.flow_measure or measure_flows
    plan = models.TsRemediationPlan.objects.select_related("case").get(record_id=plan_id)
    case = plan.case
    if plan.status != "RISK_ASSESSED" or len(plan.operations or []) != 1:
        raise RecoveryRefused("PLAN_NOT_ELIGIBLE", f"{plan.status}, {len(plan.operations or [])} operation(s)")
    op = dict(plan.operations[0])
    policies = load_policies(policy_file)
    raw = policy_for(op, policies)
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
        ineffective = any(r.startswith(("INEFFECTIVE", "CONTRADICTORY")) for r in reasons)
        repo.audit(actor, case, "REMEDIATION_DECISION", decision=f"{'DIAGNOSE_AND_ESCALATE' if ineffective else 'PROPOSE_FOR_APPROVAL'} {code}"[:255],
                   result="DIAGNOSE_AND_ESCALATE" if ineffective else "PROPOSE_FOR_APPROVAL", operation=plan.record_id,
                   rationale=json.dumps({"stage": "policy-recovery", "denied": reasons, "policy_id": pol.id})[:3000],
                   evidence_ids=plan.evidence_ids, now=deps.now())
        summary.update(result="REFUSED", code=code, reasons=reasons, **extra)
        deps.notify(f"[NMAS] Automated recovery REFUSED for {case.case_id} ({device} {iface})",
                    f"Policy {pol.id} refused plan {plan.record_id}: {code}\nReasons: {', '.join(reasons)}\nA human must review the case.\n")
        return summary

    def facts(snapshot, line, *, rollback_ready: bool) -> gov.RecoveryContext:
        oper = deps.oper_state(raw, iface) if snapshot is not None else None
        intents = deps.intent(device) or {}
        intended = {"up": "admin_up", "down": "admin_down"}.get(intents.get(iface, ""))
        return gov.RecoveryContext(
            now=deps.now(), executions=_executions(pol.id), authoritative_intent=intended,
            observed_admin_state=("down" if line else "up") if snapshot is not None else None,
            observed_at=snapshot.captured_at if snapshot is not None else None,
            maintenance_active=bool(eligibility._maintenance_conflicts([device])), conflicting_change=_conflicting_change(device),
            management_path_healthy=snapshot is not None, protected_flows_healthy=deps.flows(raw.get("protected_flows") or []),
            rollback_ready=rollback_ready, scope_executions=scope_executions(raw, policies), observed_oper_state=oper)

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
                              "policy_actor": actor_name, "approved_by": "", "human_approval": False, "change_id": change.change_id,
                              "abort_thresholds": dict(gov.DEFAULT_ABORT), "soak_required": False,
                              "addressed_fault": f"{device} {iface} administratively down while intent requires admin up"})
    ci_status = deps.ci_wait(change)
    if ci_status != "PASS":
        return refuse("CONFIGURATION_VALIDATION_NOT_PASSING", [ci_status], change=change.change_id)
    precheck = deps.precheck(change, actor=actor_name)
    if getattr(precheck, "result", "") not in ("PASS", "PASS_WITH_WARNINGS"):
        return refuse("PRECHECK_NOT_PASSING", [str(getattr(precheck, "result", "?"))], change=change.change_id)
    gov._set_status(actor, plan, "PRECHECK_PASS", f"precheck {precheck.result}", now=deps.now())

    # 4. let the AI handoff close (its own case transition must not race ours), then re-evaluate every gate before the write
    settle = time.monotonic() + deps.case_settle_seconds
    while repo.get_case(actor, case.case_id).state == "AI_INVESTIGATING" and time.monotonic() < settle:
        time.sleep(2)
    final = gov.evaluate_recovery_policy(pol, op, facts(snapshot, line, rollback_ready=True), risk=plan.risk)
    if not final["authorized"]:
        return refuse("POLICY_DENIED_AT_EXECUTION", final["reasons"], change=change.change_id)
    protected = list(raw.get("protected_flows") or [])
    baseline = deps.flow_measure(protected)
    started = deps.now()
    case = _case_to(actor, case, "REMEDIATING", f"{gov.AUTOMATED_RECOVERY} {pol.id}: Change Engine executing {change.change_id}", started)
    ex = models.TsActionExecution.objects.create(
        record_id=repo._rid("ACT"), case=case, basis="DERIVED", stage="REMEDIATE", stage_decision=f"policy {pol.id}",
        evidence_ids=plan.evidence_ids, plan=plan, pre_state={"admin": "down", "snapshot_id": str(snapshot.snapshot_id), "line": line},
        command_or_intent={"change_id": change.change_id, "operation": op, "policy_id": pol.id, "authorization_type": gov.AUTOMATED_RECOVERY,
                           "baseline_flows": {k: {"loss_pct": v["loss_pct"], "coverage": v["coverage"]} for k, v in baseline.items()}},
        idempotency_key=f"recovery:{pol.id}:{plan.record_id}", executed_at=started, status="EXECUTING",
        rollback={"restore_lines": item["restore_lines"], "mechanism": "Change Engine compensation (captured pre-change state)"})
    gov._set_status(actor, plan, "EXECUTING", f"Change Engine executing {change.change_id}", now=deps.now())
    result = deps.execute(change, actor=actor_name, confirm_mode=models.ExecutionMode.COMPLETE)
    outcome = str(result.outcome)

    # 5. observe actual state (admin from a fresh running config, oper from the device), then the case's own verification
    after, _ = deps.snapshot(device, actor_name)
    admin_up = after is not None and shutdown_line(after, iface) is None
    oper = deps.oper_state(raw, iface)
    applied = outcome == models.ExecutionOutcome.SUCCEEDED
    ex.observed_effect = {"execution_outcome": outcome, "run": str(getattr(result.run, "run_id", "")), "admin": "up" if admin_up else "down",
                          "oper": oper, "observed_at": deps.now().isoformat()}
    ex.status = "APPLIED" if applied else ("ABORTED_RESTORED" if "ROLLED_BACK" in outcome else "ABORTED_UNRESTORED")
    ex.stop_reason = "" if applied else outcome[:255]
    ex.save()
    record = None
    if applied:
        gov._set_status(actor, plan, "VERIFYING", f"Change Engine outcome {outcome}", now=deps.now())
        case = _case_to(actor, case, "VERIFYING", f"Change {change.change_id} applied by the Change Engine; verifying the service", deps.now())
        block = ""
        if after is not None and f"interface {iface}\n" in after.text:
            block = header + "\n" + after.text.split(f"interface {iface}\n", 1)[1].split("\ninterface ", 1)[0]
        ev_admin = repo.store_evidence(actor, case, source_type="cli", device=device, command_or_api="show running-config (sanitized snapshot)",
                                       adapter="nmas-config-workbench", raw=block or "<interface block unavailable>",
                                       collected_at=getattr(after, "captured_at", None))
        ev_oper = repo.store_evidence(actor, case, source_type="cli", device=device, command_or_api=f"show interfaces {iface} status",
                                      adapter="nmas-recovery", raw=f"{iface} oper_state={oper}")
        checks = [
            {"name": f"{device} {iface} admin up (running-config)", "passed": admin_up, "observed": "up" if admin_up else "down",
             "evidence_ids": [ev_admin.evidence_id]},
            {"name": f"{device} {iface} oper up", "passed": oper == "up", "observed": oper, "evidence_ids": [ev_oper.evidence_id]},
        ]
        surrounding = [{**f, "key": f["name"]} for f in protected]

        def flow_sample(defs):
            sampled = deps.flow_measure(protected)
            for name, v in sampled.items():
                repo.store_evidence(actor, case, source_type="cli", command_or_api=f"ping {name}", adapter="nmas-recovery",
                                    raw=v.get("raw") or "")
            return {k: {"loss_pct": v["loss_pct"], "coverage": v["coverage"]} for k, v in sampled.items()}

        ports = gov.Ports(flow_sample=flow_sample, clock=deps.now)
        record = verification.verify(actor, plan.record_id, ports, service_checks=lambda: checks, surrounding_flows=surrounding, now=deps.now())
        if record.outcome == "FAILED":
            verification.abort_failed_verification(actor, plan.record_id, ports, now=deps.now())
    elif "ROLLED_BACK" in outcome:
        gov._set_status(actor, plan, "ABORTED_RESTORED", f"{outcome}: compensated to the captured pre-change state", now=deps.now())
    else:
        gov._set_status(actor, plan, "ABORTED_UNRESTORED", f"{outcome}: admin_up={admin_up} oper={oper}", now=deps.now())
    disposition = verification.finalize(actor, case, now=deps.now())
    verified = record is not None and record.outcome == "VERIFIED"
    repo.audit(actor, case, "AUTOMATED_RECOVERY_EXECUTED", decision=f"{change.change_id} {outcome}", result="VERIFIED" if verified else "NOT_VERIFIED",
               risk=plan.risk, operation=plan.record_id, evidence_ids=plan.evidence_ids, now=deps.now(),
               rationale=f"{gov.AUTOMATED_RECOVERY} {pol.id} (owner {pol.owner_authorization}); actor {actor_name}; "
                         f"delta '{header} / no shutdown'; admin={'up' if admin_up else 'down'} oper={oper}; "
                         f"verification={record.outcome if record else 'not run'}; case outcome={disposition.get('outcome')}")
    final_case = repo.get_case(actor, case.case_id)
    summary.update(result="VERIFIED" if verified else "NOT_VERIFIED", change=change.change_id, outcome=outcome,
                   admin="up" if admin_up else "down", oper=oper, execution=ex.record_id, case_state=final_case.state,
                   verification=record.record_id if record else "")
    deps.notify(f"[NMAS] Automated recovery {'COMPLETED' if verified else 'NOT VERIFIED'}: {device} {iface} ({case.case_id})",
                f"Case: {case.case_id} ({final_case.state})\nPlan: {plan.record_id}\nChange: {change.change_id} ({outcome})\nPolicy: {pol.id} "
                f"(owner authorization {pol.owner_authorization}; actor {actor_name}; {gov.AUTOMATED_RECOVERY}; risk {plan.risk})\n"
                f"Delta: {header} / no shutdown\nVerified: admin {'up' if admin_up else 'down'}, oper {oper}; "
                f"service verification {record.outcome if record else 'not run'}\n")
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


def undecided_plans(*, now: datetime | None = None, policy_file: str | None = None) -> list[str]:
    """Fresh RISK_ASSESSED plans that NO active standing policy covers and that have no recorded remediation decision yet.
    They are never executed; each gets one explicit PROPOSE_FOR_APPROVAL decision instead of being silently ignored."""
    now = now or datetime.now(timezone.utc)
    policies = load_policies(policy_file)
    out = []
    for plan in models.TsRemediationPlan.objects.filter(status="RISK_ASSESSED", created_at__gte=now - timedelta(hours=1)).order_by("created_at"):
        ops = [o for o in (plan.operations or []) if isinstance(o, dict)]
        raw = policy_for(ops[0], policies) if len(ops) == 1 else None
        if raw is not None and policy_active(raw, now):
            continue                                               # pending_plans()/recover() own it
        if models.TsAuditEvent.objects.filter(case=plan.case, action="REMEDIATION_DECISION", operation=plan.record_id).exists():
            continue
        out.append(plan.record_id)
    return out


def record_plan_decision(plan_id: str, *, now: datetime | None = None, policy_file: str | None = None,
                         send: Callable[[str, str], Any] | None = None) -> dict:
    """Record why a proposal cannot run unattended (PROPOSE_FOR_APPROVAL).  Nothing is changed on any device or plan."""
    now = now or datetime.now(timezone.utc)
    plan = models.TsRemediationPlan.objects.select_related("case").get(record_id=plan_id)
    policies = load_policies(policy_file)
    ops = [o for o in (plan.operations or []) if isinstance(o, dict)]
    denied = []
    if len(ops) != 1:
        denied.append(f"MULTI_OPERATION_PLAN: {len(ops)} operations; a standing policy covers exactly one")
    for op in ops:
        kind, target = op.get("kind"), f"{op.get('device')} {op.get('interface') or ''}".strip()
        raw = policy_for(op, policies)
        if kind not in gov.RECOVERY_OPERATIONS:
            denied.append(f"NOT_PREAUTHORIZABLE: {kind} on {target} can never be covered by a standing policy")
        elif raw is None:
            denied.append(f"NO_STANDING_POLICY: no policy authorizes {kind} on {target}")
        elif not policy_active(raw, now):
            denied.append(f"POLICY_NOT_ACTIVE: {raw.get('id')} (expired, revoked or disabled)")
    actor = repo.Actor("nmas-recovery-governance", "system", tenant=plan.case.tenant, devices=frozenset(repo._case_devices(plan.case)))  # pylint: disable=protected-access
    decision = {"outcome": "PROPOSE_FOR_APPROVAL", "plan": plan.record_id, "risk": plan.risk, "operations": ops, "denied": denied}
    repo.audit(actor, plan.case, "REMEDIATION_DECISION", decision=f"PROPOSE_FOR_APPROVAL plan {plan.record_id}"[:255],
               result="PROPOSE_FOR_APPROVAL", risk=plan.risk, operation=plan.record_id,
               rationale=json.dumps({"stage": "proposal-governance", "denied": denied})[:3000], evidence_ids=plan.evidence_ids, now=now)
    (send or notify.send)(f"[NMAS] {plan.case.case_id}: proposal {plan.record_id} needs human approval",
                          f"Plan {plan.record_id} ({plan.risk}) was proposed but cannot run unattended:\n  - " + "\n  - ".join(denied or ["-"])
                          + "\nIt stays RISK_ASSESSED for review; nothing was executed.\n")
    return decision


# ------------------------------------------------------------------------------------------------- operations / restart safety
IN_FLIGHT_PRE_EXECUTION = ("DRY_RUN_PASS", "PREAUTHORIZED", "PRECHECK_PASS")


def policy_status(now: datetime | None = None, policy_file: str | None = None) -> list[dict]:
    """Operator visibility: validity, executions used/remaining, cooldown and warnings for every standing policy."""
    now = now or datetime.now(timezone.utc)
    policies = load_policies(policy_file)
    out = []
    for pid, raw in sorted(policies.items()):
        try:
            pol = _policy(raw)
        except (KeyError, ValueError) as exc:
            out.append({"id": pid, "active": False, "warnings": [f"INVALID_POLICY: {type(exc).__name__}"]})
            continue
        own = _executions(pid)
        recent = own + scope_executions(raw, policies)
        cooldown_left = max(0, int(pol.cooldown_seconds - (now - max(recent)).total_seconds())) if recent else 0
        left = (pol.expires_at - now).total_seconds()
        warnings = [w for w, hit in (("REVOKED", bool(raw.get("revoked_at"))), ("DISABLED", raw.get("enabled") is not True),
                                     ("EXPIRED", left <= 0), ("EXPIRES_WITHIN_24H", 0 < left <= 86400),
                                     ("EXECUTIONS_EXHAUSTED", len(own) >= pol.max_executions),
                                     ("ONE_EXECUTION_LEFT", pol.max_executions - len(own) == 1)) if hit]
        out.append({"id": pid, "scope": f"{pol.device} {pol.interface} {pol.kind} -> {pol.intended_state}", "risk": raw.get("risk", ""),
                    "owner_authorization": pol.owner_authorization, "supersedes": raw.get("supersedes", ""),
                    "active": policy_active(raw, now) and len(own) < pol.max_executions, "expires_at": c.iso(pol.expires_at),
                    "executions_used": len(own), "max_executions": pol.max_executions,
                    "executions_remaining": max(0, pol.max_executions - len(own)), "cooldown_seconds": pol.cooldown_seconds,
                    "cooldown_remaining_seconds": cooldown_left, "last_execution": c.iso(max(recent)) if recent else None,
                    "revoked_at": raw.get("revoked_at") or None, "warnings": warnings})
    return out


def fail_closed(plan_id: str, error: str) -> str:
    """An unexpected error in recover(): never retry silently.  Pre-execution states are BLOCKED; an execution that may have
    started is left for a human (its Change Engine run is the record of what happened).  Returns what was done."""
    plan = models.TsRemediationPlan.objects.select_related("case").get(record_id=plan_id)
    actor = repo.Actor("nmas-recovery-watcher", "system", tenant=plan.case.tenant)
    if plan.status in ("RISK_ASSESSED", *IN_FLIGHT_PRE_EXECUTION):
        gov._set_status(actor, plan, "BLOCKED", f"AUTOMATED_RECOVERY_ERROR: {error}"[:250])
        done = "BLOCKED"
    else:
        done = f"LEFT_{plan.status}"
    repo.audit(actor, plan.case, "AUTOMATED_RECOVERY_ERROR", decision=done, result="ERROR", risk=plan.risk, operation=plan.record_id,
               rationale=error[:900])
    notify.send(f"[NMAS] Automated recovery ERROR for {plan.case.case_id}",
                f"Plan {plan.record_id} hit an unexpected error and was {done}; it will not be retried automatically.\n{error[:500]}\n")
    return done


def sweep_interrupted() -> list[dict]:
    """Run once when the (single) recovery watcher starts: anything it left mid-pipeline was interrupted by a crash/restart.
    Nothing is ever re-executed.  Pre-execution plans are BLOCKED; an EXECUTING action is marked INTERRUPTED -> BLOCKED with the
    Change Engine run outcome recorded; VERIFYING is left for a human.  Every case is audited and the engineer is emailed."""
    out = []
    actor_for = lambda case: repo.Actor("nmas-recovery-watcher", "system", tenant=case.tenant)  # noqa: E731
    plans = models.TsRemediationPlan.objects.select_related("case").filter(
        status__in=(*IN_FLIGHT_PRE_EXECUTION, "EXECUTING", "VERIFYING"), approval__mode=gov.AUTOMATED_RECOVERY)
    for plan in plans:
        actor, prior = actor_for(plan.case), plan.status
        ex = models.TsActionExecution.objects.filter(plan=plan, stage_decision__startswith="policy ").order_by("-id").first()
        run_outcome = ""
        if ex is not None:
            run = models.ChangeExecutionRun.objects.filter(change__change_id=(ex.command_or_intent or {}).get("change_id")).order_by("-started_at").first()
            run_outcome = (run.outcome or run.state) if run else "NO_RUN"
        if prior in IN_FLIGHT_PRE_EXECUTION:
            gov._set_status(actor, plan, "BLOCKED", "recovery watcher restarted before execution; not retried")
        elif prior == "EXECUTING":
            if ex is not None and ex.status == "EXECUTING":
                ex.status, ex.stop_reason = "INTERRUPTED", f"recovery watcher lost during execution; Change Engine run: {run_outcome}"
                ex.save()
            gov._set_status(actor, plan, "INTERRUPTED", f"watcher restart; Change Engine run {run_outcome}")
            gov._set_status(actor, plan, "BLOCKED", "interrupted automated execution requires human review; never re-executed")
        repo.audit(actor, plan.case, "AUTOMATED_RECOVERY_INTERRUPTED", decision=f"{plan.record_id}: {prior}", result="INTERRUPTED",
                   risk=plan.risk, operation=plan.record_id, rationale=f"Change Engine run outcome: {run_outcome or 'none'}")
        notify.send(f"[NMAS] Automated recovery INTERRUPTED for {plan.case.case_id}",
                    f"Plan {plan.record_id} was {prior} when the recovery watcher stopped. Change Engine run: {run_outcome or 'none'}.\n"
                    "Nothing was retried. A human must review the case and the device state.\n")
        out.append({"plan": plan.record_id, "was": prior, "run_outcome": run_outcome})
    return out
