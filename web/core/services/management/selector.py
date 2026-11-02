"""The centralized management-path selector -- the only writer of path health, the active flag and DeviceManagementState.

Rules
    * usable      = APPROVED path whose health is HEALTHY (the last layered probe passed every layer and, after a failure, at
                    least ``restore_threshold`` consecutive probes passed)
    * desired     = the first usable path in priority order (``paths.priority_key``)
    * failover    = the ACTIVE path reached ``failure_threshold`` consecutive failures (hysteresis: one lost probe never
                    switches), or failed a security layer (host key / identity: immediate, never retried onto an impostor)
    * failback    = a more-preferred path is usable again AND the hold-down since the last switch has elapsed
    * no path     = nothing usable: status NO_PATH, the resolver fails closed (writes and reads blocked)
    * in flight   = while the device is locked by an execution or maintenance transaction, or a bootstrap credential step
                    is running, the active path is NEVER switched: the decision is DEFERRED (recorded) and, when the active
                    path failed under the write, ``reconciliation_required`` is set so no further write starts until an
                    operator reconciles.  A run never continues over a second path (the engine never reconnects mid-run).
    * restart     = everything is in the database; ``recover`` re-derives the state and repairs a crash between the two
                    halves of a switch.

Probes happen OUTSIDE any transaction; their results are applied in one transaction under a version compare-and-swap of
the device's state row, so two concurrent evaluations cannot both switch.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import timedelta

from django.db import transaction
from django.db.models import Q
from django.utils import timezone

from ... import models
from ..devices import codes, events
from . import paths, policy, probes

H = models.ManagementPathHealth
K = models.ManagementTransitionKind
ST = models.ManagementStatus
SELECTOR = "nmas-management-selector"
IMMEDIATE_FAILURES = frozenset({"L5_HOST_KEY_MISMATCH", "L6_IDENTITY_MISMATCH"})
CONFIG_FAILURES = frozenset({"L1_TOPOLOGY_UNVERIFIED", "L1_NMAS_ATTACHMENT_DOWN", "MGMT_VLAN_NOT_CONTINUOUS", "L2_CONFIG_MISMATCH",
                             "L2_PLATFORM_NOT_IMPLEMENTED", "MGMT_VLAN_LOOP_RISK", "NMAS_ATTACHMENT_NOT_APPROVED"})
BCRED_EXECUTING = ("REPLACEMENT_INSTALLED", "REPLACEMENT_VERIFIED", "REVOCATION_PENDING", "RETIREMENT_PENDING", "UNCERTAIN")


@dataclass
class Evaluation:
    device: str
    status: str
    active_path: str = ""
    previous_path: str = ""
    decision: str = "NONE"            # NONE | ACTIVATE | FAILOVER | FAILBACK | LOST | RECOVERED | DEFERRED | HOLD_DOWN | CONFLICT
    reason: str = ""
    probes: dict = field(default_factory=dict)     # path_id -> {passed, highest_layer, failure_code, health}
    blockers: list = field(default_factory=list)
    transition: object | None = None

    def as_dict(self) -> dict:
        return {"device": self.device, "status": self.status, "active_path": self.active_path, "previous_path": self.previous_path,
                "decision": self.decision, "reason": self.reason, "probes": self.probes, "codes": codes.codes(self.blockers)}


# --- state row ----------------------------------------------------------------------------------------------------------------
def state_for(device, *, create: bool = True) -> models.DeviceManagementState | None:
    row = models.DeviceManagementState.objects.filter(device=device).first()
    if row is None and create:
        row = models.DeviceManagementState(device=device)
        row._selector_write = True
        row.save()
    return row


def _save_state(row, **fields):
    for name, value in fields.items():
        setattr(row, name, value)
    row.version += 1
    row._selector_write = True
    row.save()


def _cas_state(row, expected_version: int, **fields) -> bool:
    """Compare-and-swap the state row (inside the caller's transaction).  False = another evaluation won."""
    locked = models.DeviceManagementState.objects.select_for_update().filter(pk=row.pk).first()
    if locked is None or locked.version != expected_version:
        return False
    _save_state(locked, **fields)
    row.__dict__.update({k: getattr(locked, k) for k in ("status", "active_path_id", "reconciliation_required", "reconciliation_reason",
                                                         "failback_not_before", "last_transition_at", "last_evaluated_at", "version")})
    return True


def _path_write(path, **fields):
    for name, value in fields.items():
        setattr(path, name, value)
    path.version += 1
    path._selector_write = True
    path.save()


# --- in-flight ----------------------------------------------------------------------------------------------------------------
def in_flight(device) -> dict:
    """What, if anything, is writing to the device right now."""
    lock = models.ExecutionDeviceLock.objects.filter(device=device.name).select_related("run", "maintenance").first()
    if lock is not None:
        holder = str(lock.run.run_id) if lock.run_id else (lock.maintenance.record_id if lock.maintenance_id else "?")
        return {"kind": "EXECUTION" if lock.run_id else "MAINTENANCE", "holder": holder}
    bcred = models.BootstrapCredentialTransition.objects.filter(device=device).filter(
        Q(state__in=BCRED_EXECUTING) | (Q(state=models.BootstrapCredentialState.APPROVED) & ~Q(executed_by=""))).first()
    if bcred is not None:
        return {"kind": "BOOTSTRAP_CREDENTIAL", "holder": bcred.transition_id}
    return {}


# --- health accounting ----------------------------------------------------------------------------------------------------------
def apply_probe(path, report, *, limits=None) -> str:
    """Update one path's counters and health from one probe report (selector write).  -> the new health."""
    limits = limits or policy.effective(path)
    now = timezone.now()
    previous = path.health_state
    if report.passed:
        successes = path.consecutive_successes + 1
        if previous == H.FAILED:
            health = H.HEALTHY if successes >= limits.restore_threshold else H.FAILED
        elif previous == H.INELIGIBLE and path.consecutive_failures == 0 and path.last_success_at is not None:
            health = H.HEALTHY if successes >= limits.restore_threshold else H.INELIGIBLE
        else:
            health = H.HEALTHY
        _path_write(path, consecutive_successes=successes, consecutive_failures=0, last_probe_at=now, last_success_at=now,
                    last_layer_passed=report.highest_layer, health_state=health, last_failure_code="")
        return health
    code = report.failure_code
    failures = path.consecutive_failures + 1
    if code in IMMEDIATE_FAILURES:
        health = H.FAILED
    elif previous in (H.HEALTHY, H.DEGRADED):
        health = (H.INELIGIBLE if code in CONFIG_FAILURES else H.FAILED) if failures >= limits.failure_threshold else H.DEGRADED
    else:
        health = H.INELIGIBLE if code in CONFIG_FAILURES else H.FAILED
    _path_write(path, consecutive_failures=failures, consecutive_successes=0, last_probe_at=now, last_failure_at=now,
                last_failure_code=code[:48], last_layer_passed=report.highest_layer, health_state=health)
    return health


def usable(path) -> bool:
    return path.approval_state == models.ManagementApproval.APPROVED and path.health_state == H.HEALTHY


def still_serving(path) -> bool:
    """The active path keeps serving while below the failure threshold (DEGRADED) -- hysteresis."""
    return path.approval_state == models.ManagementApproval.APPROVED and path.health_state in (H.HEALTHY, H.DEGRADED)


def _transition(device, kind, *, from_path=None, to_path=None, reason_code: str, actor: str, actor_kind: str, evidence=None, probe=None):
    row = models.ManagementPathTransition.objects.create(
        device=device, kind=kind, from_path=from_path, to_path=to_path, reason_code=reason_code[:48], evidence=evidence or {},
        probe=probe, actor=actor[:150], actor_kind=actor_kind)
    events.record(device, f"MGMT_{kind}"[:40], models.DeviceLifecycleEventOutcome.RECORDED, actor=actor, actor_kind=actor_kind,
                  from_state=device.lifecycle_state, to_state=device.lifecycle_state,
                  evidence={"transition": row.pk, "from": from_path.path_id if from_path else "", "to": to_path.path_id if to_path else "",
                            "reason": reason_code, **(evidence or {})})
    return row


# --- the decision -------------------------------------------------------------------------------------------------------------
def decide(device, state, candidates, *, now=None, busy: dict | None = None) -> tuple[str, object | None, str]:
    """Pure decision over already-probed paths.  -> (decision, target path or None, reason code)."""
    now = now or timezone.now()
    active = next((p for p in candidates if p.pk == state.active_path_id), None)
    usable_paths = [p for p in paths.ordered(candidates) if usable(p)]
    desired = usable_paths[0] if usable_paths else None
    if active is not None and still_serving(active):
        if desired is not None and desired.pk != active.pk and paths.priority_key(desired) < paths.priority_key(active):
            if state.failback_not_before and now < state.failback_not_before:
                return "HOLD_DOWN", desired, "MGMT_HOLD_DOWN"
            if busy:
                return "DEFERRED", desired, "MGMT_EXECUTION_IN_FLIGHT"
            return "FAILBACK", desired, "PREFERRED_PATH_RESTORED"
        return "NONE", active, ""
    if desired is None:
        if active is None and state.status == ST.NO_PATH:
            return "NONE", None, "MGMT_NO_USABLE_PATH"
        if busy and active is not None:
            return "DEFERRED", None, "MGMT_EXECUTION_IN_FLIGHT"
        return "LOST", None, "MGMT_NO_USABLE_PATH"
    if busy:
        return "DEFERRED", desired, "MGMT_EXECUTION_IN_FLIGHT"
    if active is None:
        return ("RECOVERED" if state.status == ST.NO_PATH else "ACTIVATE"), desired, "PATH_VERIFIED"
    return "FAILOVER", desired, (active.last_failure_code or "ACTIVE_PATH_FAILED")


def evaluate(device, *, transport=None, actor: str = SELECTOR, actor_kind: str = events.AUTOMATION,
             purpose: str = models.ProbePurpose.MONITOR, now=None) -> Evaluation:
    """Probe every approved path of ``device`` once, account health, and apply at most one switch."""
    state = state_for(device)
    candidates = paths.approved_paths(device)
    result = Evaluation(device=device.name, status=state.status)
    if not candidates:
        return _no_paths(device, state, result, actor=actor, actor_kind=actor_kind)
    version = state.version
    last_probe = {}
    for path in candidates:
        report, row, refusals = probes.probe(path, transport=transport, purpose=purpose, actor=actor)
        if refusals:
            result.probes[path.path_id] = {"refused": codes.codes(refusals)}
            continue
        path.refresh_from_db()
        health = apply_probe(path, report)
        last_probe[path.pk] = row
        result.probes[path.path_id] = {"passed": report.passed, "highest_layer": report.highest_layer,
                                       "failure_code": report.failure_code, "health": health}
    candidates = paths.approved_paths(device)
    busy = in_flight(device)
    now = now or timezone.now()
    decision, target, reason = decide(device, state, candidates, now=now, busy=busy)
    result.decision, result.reason = decision, reason
    active = next((p for p in candidates if p.pk == state.active_path_id), None)
    result.previous_path = active.path_id if active else ""
    hold = policy.effective(target or active).hold_down_seconds
    with transaction.atomic():
        if decision in ("ACTIVATE", "RECOVERED", "FAILOVER", "FAILBACK", "LOST") and not busy:
            # A writer may have claimed the device since the initial decision.
            # Recheck inside the same SQLite transaction that changes selection;
            # concurrent lock insertion cannot commit unnoticed before our write.
            busy = in_flight(device)
            if busy:
                decision, target, reason = decide(device, state, candidates, now=now, busy=busy)
                result.decision, result.reason = decision, reason
        if decision in ("NONE", "HOLD_DOWN"):
            status = ST.ACTIVE if active is not None and active.health_state == H.HEALTHY else (
                ST.DEGRADED if active is not None else ST.NO_PATH)
            if not _cas_state(state, version, status=status, last_evaluated_at=now):
                return _conflict(result)
        elif decision == "DEFERRED":
            failed_under_write = bool(active is not None and not still_serving(active))
            fields = {"status": ST.DEGRADED if active is not None else state.status, "last_evaluated_at": now}
            if failed_under_write:
                fields.update(reconciliation_required=True,
                              reconciliation_reason=f"active path {active.path_id} failed while {busy.get('kind', '').lower()} "
                                                    f"{busy.get('holder', '')} was in flight"[:200])
            if not _cas_state(state, version, **fields):
                return _conflict(result)
            result.transition = _transition(device, K.DEFERRED, from_path=active, to_path=target, reason_code=reason, actor=actor,
                                            actor_kind=actor_kind, evidence={"in_flight": busy, "reconciliation_required": failed_under_write},
                                            probe=last_probe.get(active.pk) if active else None)
        elif decision == "LOST":
            if not _cas_state(state, version, status=ST.NO_PATH, active_path=None, last_transition_at=now, last_evaluated_at=now):
                return _conflict(result)
            if active is not None:
                _path_write(active, is_active=False)
            result.transition = _transition(device, K.LOST, from_path=active, reason_code=reason, actor=actor, actor_kind=actor_kind,
                                            probe=last_probe.get(active.pk) if active else None,
                                            evidence={"paths": {k: v.get("failure_code", "") for k, v in result.probes.items()}})
        else:   # ACTIVATE / RECOVERED / FAILOVER / FAILBACK
            if not _cas_state(state, version, status=ST.ACTIVE, active_path=target, last_transition_at=now, last_evaluated_at=now,
                              failback_not_before=now + timedelta(seconds=hold)):
                return _conflict(result)
            if active is not None:
                _path_write(active, is_active=False)
            _path_write(target, is_active=True, activated_at=now)
            result.transition = _transition(device, getattr(K, decision), from_path=active, to_path=target, reason_code=reason,
                                            actor=actor, actor_kind=actor_kind, probe=last_probe.get(target.pk),
                                            evidence={"class": target.preference_class, "hold_down_seconds": hold})
    state.refresh_from_db()
    result.status = state.status
    result.active_path = state.active_path.path_id if state.active_path_id else ""
    if decision in ("LOST", "NONE") and state.status == ST.NO_PATH:
        result.blockers.append(codes.blocker("MGMT_NO_USABLE_PATH"))
    if decision == "HOLD_DOWN":
        result.blockers.append(codes.blocker("MGMT_HOLD_DOWN", until=state.failback_not_before.isoformat()))
    if decision == "DEFERRED":
        result.blockers.append(codes.blocker("MGMT_EXECUTION_IN_FLIGHT", **busy))
    return result


def _conflict(result: Evaluation) -> Evaluation:
    result.decision, result.reason = "CONFLICT", "MGMT_STATE_CONFLICT"
    result.blockers.append(codes.blocker("MGMT_STATE_CONFLICT"))
    return result


def _no_paths(device, state, result, *, actor, actor_kind) -> Evaluation:
    """No approved candidate: only devices never registered for path management retain legacy access."""
    with transaction.atomic():
        status = ST.NO_PATH if models.ManagementPath.objects.filter(device=device).exists() else ST.LEGACY
        locked = models.DeviceManagementState.objects.select_for_update().get(pk=state.pk)
        if locked.status != status or locked.active_path_id:
            _save_state(locked, status=status, active_path=None, last_evaluated_at=timezone.now())
    result.status = status
    if status == ST.NO_PATH:
        result.reason = "MGMT_NO_USABLE_PATH"
        result.blockers.append(codes.blocker("MGMT_NO_USABLE_PATH"))
    return result


def deactivate(path, *, actor: str, reason_code: str, actor_kind: str = events.HUMAN) -> None:
    """Clear ``path`` as the active path (used when it is revoked).  Call inside the caller's transaction."""
    state = state_for(path.device)
    locked = models.DeviceManagementState.objects.select_for_update().get(pk=state.pk)
    _path_write(path, is_active=False)
    if locked.active_path_id == path.pk:
        _save_state(locked, status=ST.NO_PATH, active_path=None, last_transition_at=timezone.now())
    _transition(path.device, K.DEACTIVATE, from_path=path, reason_code=reason_code, actor=actor, actor_kind=actor_kind)


def acknowledge_reconciliation(device, *, actor: str, reason: str) -> dict:
    """An operator confirms the device was reconciled after a path changed under a write.  Refused while still in flight."""
    from ..devices.identity import clean_text

    text, problems = clean_text(reason, max_length=200)
    if problems or not text:
        return {"ok": False, "blockers": problems or [codes.blocker("REASON_REQUIRED")]}
    busy = in_flight(device)
    if busy:
        return {"ok": False, "blockers": [codes.blocker("MGMT_EXECUTION_IN_FLIGHT", **busy)]}
    with transaction.atomic():
        state = state_for(device)
        locked = models.DeviceManagementState.objects.select_for_update().get(pk=state.pk)
        if not locked.reconciliation_required:
            return {"ok": True, "changed": False, "blockers": []}
        _save_state(locked, reconciliation_required=False, reconciliation_reason="")
        events.record(device, "MGMT_RECONCILED", models.DeviceLifecycleEventOutcome.RECORDED, actor=actor,
                      from_state=device.lifecycle_state, to_state=device.lifecycle_state, evidence={"reason": text})
    return {"ok": True, "changed": True, "blockers": []}


def recover(*, actor: str = SELECTOR) -> list[dict]:
    """Re-derive every device's management state from the database after an NMAS restart.

    Repairs exactly the crash windows a switch can leave: the state names path A but A's active flag is clear (set it); a path
    is flagged active that the state does not name (clear it); the active path is no longer approved (drop to NO_PATH).
    Health counters are durable, so hysteresis and hold-down continue where they stopped.
    """
    repaired = []
    for state in models.DeviceManagementState.objects.select_related("device", "active_path"):
        device = state.device
        actions = []
        with transaction.atomic():
            locked = models.DeviceManagementState.objects.select_for_update().get(pk=state.pk)
            for stray in models.ManagementPath.objects.filter(device=device, is_active=True).exclude(pk=locked.active_path_id or 0):
                _path_write(stray, is_active=False)
                actions.append(f"cleared stray active flag on {stray.path_id}")
            active = locked.active_path
            if active is not None and active.approval_state != models.ManagementApproval.APPROVED:
                if active.is_active:
                    _path_write(active, is_active=False)
                _save_state(locked, status=ST.NO_PATH, active_path=None, last_transition_at=timezone.now())
                actions.append(f"active path {active.path_id} no longer approved")
            elif active is not None and not active.is_active:
                _path_write(active, is_active=True)
                actions.append(f"restored active flag on {active.path_id}")
            if actions:
                _transition(device, K.RESTART_RECOVERY, from_path=None, to_path=locked.active_path, reason_code="RESTART_RECOVERY",
                            actor=actor, actor_kind=events.AUTOMATION, evidence={"actions": actions})
        if actions:
            repaired.append({"device": device.name, "actions": actions})
    return repaired


def device_status(device) -> dict:
    state = models.DeviceManagementState.objects.filter(device=device).first()
    return {
        "device": device.name, "platform": device.platform,
        "status": state.status if state else "LEGACY", "active_path": state.active_path.path_id if state and state.active_path_id else "",
        "reconciliation_required": bool(state and state.reconciliation_required),
        "paths": [{"id": p.path_id, "type": p.path_type, "class": p.preference_class, "via": p.via_device, "vrf": p.vrf,
                   "endpoint": p.endpoint_address, "approval": p.approval_state, "health": p.health_state, "active": p.is_active,
                   "failures": p.consecutive_failures, "successes": p.consecutive_successes, "code": p.last_failure_code}
                  for p in paths.ordered(paths.live_paths(device))],
    }
