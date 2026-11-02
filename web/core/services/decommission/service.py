"""V2 Phase 7: governed decommissioning and restoration of one managed device.

    request   -> REQUESTED                       recorded intent (who, why); a DECOMMISSION_REQUESTED fact for the consumers
    evaluate  -> READY | BLOCKED                 dependencies, a live traffic observation through the maintenance readiness
                                                 engine, a baseline snapshot, the exact plan as a governed Change (validated,
                                                 planned, prechecked)
    approve   -> APPROVED                        a second operator, bound to the plan hash and the readiness digest, with expiry
    execute   -> DECOMMISSIONED | ROLLED_BACK | UNCERTAIN | BLOCKED
                                                 the device enters DECOMMISSION_PENDING; under the device lock the transition
                                                 (OSPF cost-out) runs first and the traffic must be observed off the device; then
                                                 the removal; a continuous measurement must show zero loss of every monitored
                                                 flow; any failure compensates every step newest first, digest-verified
    reconcile -> resolves an UNCERTAIN record from the device's own state; nothing is ever replayed blindly
    plan_recovery / approve_recovery / execute_recovery
              -> ROLLED_BACK                     a record a lost session or a crash left part-way (UNCERTAIN, or TRAFFIC_TRANSITION /
                                                 DECOMMISSIONING with no live run): the inverse of exactly the run's own operations
                                                 whose effect is on the device NOW, as a second governed Change (validated, planned,
                                                 prechecked, approved by another operator), accepted only on the baseline digest
    cancel    -> CANCELLED                       before execution only

Restoration (``request_restore`` / ``check_restore`` / ``approve_restore`` / ``execute_restore``) reapplies the verified baseline
snapshot through the same governed transaction, requires the decommission-time identity to be observed again, and registers a
successor device record (``origin=RESTORED``) only after the postcheck proves the exact pre-decommission configuration digest.
A device whose identity or prior admission cannot be re-established is sent back through ZTP / isolation / commissioning.

Devices that never reached production (BOOTSTRAPPED / ISOLATED / READY_FOR_COMMISSIONING / FAILED) carry no production traffic by
the isolation contract; their decommissioning writes nothing to the device and is a recorded retirement.
"""

from __future__ import annotations

import hashlib
import importlib
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import timedelta

from django.conf import settings
from django.db import IntegrityError, transaction
from django.utils import timezone

from ... import models
from ..devices import events, lifecycle
from ..devices.codes import blocker
from ..isolation import transaction as governed
from ..management import resolve
from . import dependencies, eos, readiness

S, D, R = models.DeviceLifecycleState, models.DecommissionState, models.RestorationState
Outcome = models.DeviceLifecycleEventOutcome
X = governed.Outcome
KIND, RESTORE_KIND, RECOVERY_KIND = "DEVICE_DECOMMISSION", "DEVICE_RESTORE", "DEVICE_DECOMMISSION_RECOVERY"
RECOVERABLE = (D.UNCERTAIN, D.TRAFFIC_TRANSITION, D.DECOMMISSIONING)
EXECUTABLE = (S.IN_SERVICE,)
RETIRE_ONLY = (S.BOOTSTRAPPED, S.ISOLATED, S.READY_FOR_COMMISSIONING, S.FAILED)
READMITTABLE = (models.ProductionAdmissionState.ADMITTED, models.ProductionAdmissionState.LEGACY_PREEXISTING)
CLOSED_DECOMMISSION = (D.DECOMMISSIONED, D.CANCELLED, D.ROLLED_BACK)
CLOSED_RESTORATION = (R.RESTORED, R.CANCELLED, R.ROLLED_BACK, R.REENROLLMENT_REQUIRED)


def approval_ttl_seconds() -> float:
    return float(getattr(settings, "NMAS_DECOMMISSION_APPROVAL_TTL_SECONDS", 3600))


def readiness_max_age_seconds() -> float:
    return float(getattr(settings, "NMAS_DECOMMISSION_READINESS_MAX_AGE_SECONDS", 1800))


# ------------------------------------------------------------------------------------------------------------- runtime
@dataclass
class Runtime:
    """How NMAS reaches one deployment: the device session, the traffic observer, the continuous probe and the identity reader."""

    executor_factory: Callable                     # {"name", "platform"} -> executor (CeosExecutor)
    observer: object                               # .observe(device_name, window_seconds=None) -> readiness.Observation
    management_addresses: Callable                 # device -> [address, ...] NMAS manages it on (never decommissioned)
    probe_factory: Callable | None = None          # () -> probe with .stop() -> {flow: {sent, received}}
    sleep: Callable = time.sleep
    settle_seconds: float = 8.0
    move_timeout_seconds: float = 60.0
    soak_seconds: float = 10.0
    adjacency_timeout_seconds: float = 120.0


def configured_runtime() -> Runtime | None:
    """The deployment's runtime (``settings.NMAS_DECOMMISSION_RUNTIME`` = dotted path of a factory), or None: production
    readiness is never decided without a configured traffic observer."""
    path = str(getattr(settings, "NMAS_DECOMMISSION_RUNTIME", "") or "")
    if not path:
        return None
    module, _, name = path.rpartition(".")
    return getattr(importlib.import_module(module), name)()


@dataclass
class Result:
    ok: bool
    action: str
    record: object | None = None
    blockers: list = field(default_factory=list)
    detail: dict = field(default_factory=dict)

    @property
    def codes(self) -> list[str]:
        return [b["code"] for b in self.blockers]


def get_record(record_id):
    text = str(record_id or "")
    return models.DecommissionRecord.objects.filter(pk=int(text[4:])).first() if text.startswith("DCM-") and text[4:].isdigit() else None


def get_restoration(record_id):
    text = str(record_id or "")
    return models.RestorationRecord.objects.filter(pk=int(text[4:])).first() if text.startswith("RST-") and text[4:].isdigit() else None


def device_dict(device) -> dict:
    return {"name": device.name, "platform": "ceos" if device.platform == models.Platform.ARISTA_CEOS else device.platform}


def _fact(device, fact: str, *, actor: str, detail: dict) -> None:
    from ..commissioning import outbox

    outbox.record_fact(device, fact, actor=actor, detail=detail)


def _event(device, action: str, outcome: str, *, actor: str, evidence: dict, blockers=(), actor_kind: str = events.HUMAN) -> None:
    events.record(device, action, outcome, actor=actor, actor_kind=actor_kind, from_state=device.lifecycle_state,
                  to_state=device.lifecycle_state, evidence=evidence, blockers=list(blockers))


def _audit(record, event_type, actor: str, summary: str, metadata: dict) -> None:
    models.AuditEvent.objects.create(event_type=event_type, object_type=type(record).__name__, object_id=record.record_id, actor=actor[:150],
                                     summary=summary[:255], metadata=metadata)


def _cas(record, expected_version: int, **fields) -> bool:
    """Compare-and-swap ``fields`` onto ``record`` (version check); False when a concurrent writer won."""
    model = type(record)
    closed = CLOSED_DECOMMISSION if model is models.DecommissionRecord else CLOSED_RESTORATION
    updated = model.objects.filter(pk=record.pk, version=expected_version).exclude(state__in=closed).update(version=expected_version + 1, updated_at=timezone.now(), **fields)
    if not updated:
        return False
    record.refresh_from_db()
    return True


def _refuse(action: str, record, codes_: list, *, actor: str, detail: dict | None = None) -> Result:
    blockers = [b if isinstance(b, dict) and "message" in b else blocker(b) if isinstance(b, str) else b for b in codes_]
    if record is not None:
        device = record.device
        with transaction.atomic():
            _event(models.ManagedDevice.objects.get(pk=device.pk), action, Outcome.REFUSED, actor=actor,
                   evidence={"record": record.record_id}, blockers=blockers)
    return Result(False, action, record, blockers, detail or {})


def ops_of(record) -> list[dict]:
    plan = record.plan or {}
    return list(plan.get("transition") or []) + list(plan.get("removal") or [])


def snapshot(device, executor, *, purpose: str, actor: str) -> models.DeviceConfigSnapshot:
    """Capture the sanitized running configuration and the executor's state digest through ``executor``'s own session."""
    from ..isolation.service import read_config

    text = read_config(executor)
    return models.DeviceConfigSnapshot.objects.create(
        device=device, purpose=purpose, platform=device.platform, text=text, sha256=hashlib.sha256(text.encode()).hexdigest(),
        state_digest=executor.config_state_digest(), captured_by=actor[:150], source=f"{type(executor).__name__} session")


def host_key(executor) -> str:
    """The SHA256 fingerprint of the ed25519 host key the device reports over the authenticated session ('' when unreadable)."""
    import base64

    try:
        text = executor.show("show management ssh hostkey ed25519 public")
    except governed.SESSION_ERRORS:  # unreadable identity is no identity
        return ""
    for line in (text or "").splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[0] == "ssh-ed25519":
            try:
                blob = base64.b64decode(parts[1])
            except ValueError:
                return ""
            return "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip("=")
    return ""


# ------------------------------------------------------------------------------------------------------------- request
def request(device, *, actor: str, reason: str) -> Result:
    action = "DECOMMISSION_REQUEST_RECORD"
    text = " ".join(str(reason or "").split())[:300]
    if device is None:
        return Result(False, action, None, [blocker("DECOMMISSION_NOT_ELIGIBLE")])
    if not text:
        return _refuse_device(device, action, ["REASON_REQUIRED"], actor=actor)
    if device.lifecycle_state not in EXECUTABLE + RETIRE_ONLY:
        return _refuse_device(device, action, [blocker("DECOMMISSION_NOT_ELIGIBLE", state=device.lifecycle_state)], actor=actor)
    try:
        with transaction.atomic():
            fresh = models.ManagedDevice.objects.select_for_update().get(pk=device.pk)
            if fresh.decommissions.filter(state__in=tuple(models.DECOMMISSION_OPEN)).exists():
                raise IntegrityError("open")
            record = models.DecommissionRecord.objects.create(device=fresh, reason=text, requested_by=actor[:150])
            _event(fresh, action, Outcome.RECORDED, actor=actor, evidence={"record": record.record_id, "reason": text})
            _audit(record, models.AuditEventType.DECOMMISSION_CHANGED, actor, f"{record.record_id}: {fresh.name} decommission requested",
                   {"device": fresh.device_id, "state": record.state})
            _fact(fresh, "DECOMMISSION_REQUESTED", actor=actor, detail={"record": record.record_id})
    except IntegrityError:
        return _refuse_device(device, action, [blocker("DECOMMISSION_OPEN_EXISTS")], actor=actor)
    return Result(True, action, record)


def _refuse_device(device, action: str, blockers_: list, *, actor: str) -> Result:
    blockers_ = [blocker(b) if isinstance(b, str) else b for b in blockers_]
    with transaction.atomic():
        _event(models.ManagedDevice.objects.get(pk=device.pk), action, Outcome.REFUSED, actor=actor, evidence={}, blockers=blockers_)
    return Result(False, action, None, blockers_)


# ------------------------------------------------------------------------------------------------------------- evaluate
def evaluate(record, *, actor: str, runtime: Runtime | None) -> Result:
    """Dependencies, live traffic readiness, baseline snapshot and the governed plan.  -> READY or BLOCKED (with every reason)."""
    action = "DECOMMISSION_EVALUATE"
    if record is None:
        return Result(False, action, None, [blocker("DECOMMISSION_NOT_FOUND")])
    # READINESS_CHECKING is re-entrant: an evaluation interrupted by a restart wrote nothing to the device
    if record.state not in (D.REQUESTED, D.BLOCKED, D.READY, D.READINESS_CHECKING):
        return _refuse(action, record, [blocker("DECOMMISSION_STATE_INVALID", state=record.state)], actor=actor)
    if not _cas(record, record.version, state=D.READINESS_CHECKING, blockers=[]):
        return _refuse(action, record, [blocker("CONCURRENT_MODIFICATION")], actor=actor)
    device = models.ManagedDevice.objects.get(pk=record.device_id)
    found = dependencies.analyze(device)
    blockers_ = [blocker("DECOMMISSION_DEPENDENCY_BLOCKED", cause=b["code"], detail=b["detail"]) for b in found["blockers"]]
    fields = {"dependencies": found, "readiness": {}, "readiness_mode": models.DecommissionReadiness.UNKNOWN, "plan": {}, "plan_hash": "",
              "change": None, "baseline": None, "readiness_digest": "", "approved_by": "", "approved_at": None, "approval_expires_at": None}
    if device.lifecycle_state in RETIRE_ONLY:
        # never admitted: the isolation contract kept production traffic off it; nothing on the device is written
        fields.update(readiness={"verdict": readiness.QUIESCENT, "basis": f"not admitted ({device.lifecycle_state})", "cells": {}},
                      readiness_mode=models.DecommissionReadiness.QUIESCENT, plan={"transition": [], "removal": [], "facts": {"retire_only": True}})
    elif device.platform != models.Platform.ARISTA_CEOS:
        blockers_.append(blocker("DECOMMISSION_PLATFORM_NOT_IMPLEMENTED", platform=device.platform))
    elif runtime is None:
        blockers_.append(blocker("DECOMMISSION_RUNTIME_UNAVAILABLE"))
    else:
        blockers_ += _evaluate_live(record, device, fields, actor=actor, runtime=runtime)
    state = D.BLOCKED if blockers_ else D.READY
    if state == D.BLOCKED and fields["readiness_mode"] != models.DecommissionReadiness.UNKNOWN:
        fields["readiness_mode"] = models.DecommissionReadiness.BLOCKED
    fields["readiness_digest"] = (fields.get("readiness") or {}).get("digest", "")
    with transaction.atomic():
        if not _cas(record, record.version, state=state, blockers=blockers_, **fields):
            return _refuse(action, record, [blocker("CONCURRENT_MODIFICATION")], actor=actor)
        _event(models.ManagedDevice.objects.get(pk=device.pk), action, Outcome.RECORDED if state == D.READY else Outcome.REFUSED, actor=actor,
               evidence={"record": record.record_id, "state": state, "verdict": (record.readiness or {}).get("verdict", ""),
                         "plan_hash": record.plan_hash}, blockers=blockers_)
        _audit(record, models.AuditEventType.DECOMMISSION_CHANGED, actor, f"{record.record_id}: readiness {state}",
               {"state": state, "codes": [b["code"] for b in blockers_][:10], "mode": record.readiness_mode})
    return Result(state == D.READY, action, record, blockers_)


def _evaluate_live(record, device, fields: dict, *, actor: str, runtime: Runtime) -> list:
    executor = runtime.executor_factory(device_dict(device))
    try:
        executor.connect()
        baseline = snapshot(device, executor, purpose=models.DeviceConfigSnapshot.Purpose.DECOMMISSION_BASELINE, actor=actor)
        identity = host_key(executor)
    except governed.SESSION_ERRORS as exc:  # an unreadable device is reported, never assumed
        return [blocker("DECOMMISSION_EVIDENCE_UNAVAILABLE", error=type(exc).__name__)]
    finally:
        try:
            executor.close()
        except governed.SESSION_ERRORS:  # closing never masks the evaluation
            pass
    fields["baseline"] = baseline
    observation = runtime.observer.observe(device.name)
    verdict = readiness.evaluate(observation, operator=actor, reason=record.reason, now=timezone.now())
    verdict["identity"] = {"host_key": identity, "source": "authenticated session"}
    fields["readiness"] = verdict
    if verdict["verdict"] == readiness.BLOCKED:
        return [blocker("DECOMMISSION_TRAFFIC_BLOCKED", cause=b["code"], cell=f"{b['family']}/{b['direction']}".strip("/"),
                        detail=b["detail"], instruction=b["instruction"]) for b in verdict["blockers"]]
    fields["readiness_mode"] = (models.DecommissionReadiness.REDUNDANT_TRANSITION if verdict["verdict"] == readiness.REDUNDANT_TRANSITION
                                else models.DecommissionReadiness.QUIESCENT)
    try:
        plan = eos.render_decommission(baseline.text, management_addresses=runtime.management_addresses(device),
                                       transition=verdict["verdict"] == readiness.REDUNDANT_TRANSITION)
    except eos.PlanError as exc:
        return [blocker("DECOMMISSION_PLAN_REFUSED", cause=exc.code, detail=exc.detail)]
    ops = plan["transition"] + plan["removal"]
    with transaction.atomic():
        change = governed.create_change(kind=KIND, device=device.name, title=f"Decommission {device.name} ({record.record_id})",
                                        description=record.reason, actor=actor, reference={"decommission": record.record_id})
        governed.validate(change, ops, actor=actor, findings=[], source={"device": device.name, "baseline": baseline.sha256})
        built = governed.build_plan(change, ops, actor=actor, device=device.name, summary={"decommission": record.record_id,
                                                                                         "mode": fields["readiness_mode"]})
        governed.record_precheck(change, built, actor=actor, blockers=[], facts={"decommission": record.record_id,
                                                                                 "readiness_digest": verdict["digest"],
                                                                                 "baseline_digest": baseline.state_digest})
    fields.update(plan=plan, plan_hash=built.plan_hash, change=change)
    return []


# ------------------------------------------------------------------------------------------------------------- approve / cancel
def approve(record, *, actor: str, confirmation: str) -> Result:
    action = "DECOMMISSION_APPROVE"
    if record is None:
        return Result(False, action, None, [blocker("DECOMMISSION_NOT_FOUND")])
    problems = []
    if record.state != D.READY:
        problems.append(blocker("DECOMMISSION_STATE_INVALID", state=record.state))
    if not actor or actor == record.requested_by:
        problems.append(blocker("DECOMMISSION_SELF_APPROVAL"))
    retire_only = bool(((record.plan or {}).get("facts") or {}).get("retire_only"))
    expected = record.plan_hash if not retire_only else record.record_id
    if confirmation != expected:
        problems.append(blocker("DECOMMISSION_CONFIRMATION_MISMATCH"))
    age = (timezone.now() - record.updated_at).total_seconds()
    if not retire_only and age > readiness_max_age_seconds():
        problems.append(blocker("DECOMMISSION_READINESS_STALE", age_seconds=int(age)))
    if problems:
        return _refuse(action, record, problems, actor=actor)
    try:
        with transaction.atomic():
            if not retire_only:
                governed.approve(record.change, ops_of(record), actor=actor, requested_by=record.requested_by, confirmation=confirmation,
                                 device=record.device.name, extra={"decommission": record.record_id, "readiness_digest": record.readiness_digest})
            now = timezone.now()
            if not _cas(record, record.version, state=D.APPROVED, approved_by=actor[:150], approved_at=now,
                        approval_expires_at=now + timedelta(seconds=approval_ttl_seconds())):
                raise governed.TransactionError([governed.blocker("CONCURRENT_MODIFICATION")])
            _event(record.device, action, Outcome.RECORDED, actor=actor, evidence={"record": record.record_id, "plan_hash": record.plan_hash})
            _audit(record, models.AuditEventType.DECOMMISSION_CHANGED, actor, f"{record.record_id}: approved",
                   {"plan_hash": record.plan_hash, "readiness_digest": record.readiness_digest})
    except governed.TransactionError as exc:
        return _refuse(action, record, [blocker("DECOMMISSION_STATE_INVALID", transaction=[b["code"] for b in exc.blockers])], actor=actor)
    return Result(True, action, record)


def cancel(record, *, actor: str, reason: str = "") -> Result:
    action = "DECOMMISSION_CANCEL_RECORD"
    if record is None:
        return Result(False, action, None, [blocker("DECOMMISSION_NOT_FOUND")])
    if record.state not in (D.REQUESTED, D.READINESS_CHECKING, D.BLOCKED, D.READY, D.APPROVED):
        return _refuse(action, record, [blocker("DECOMMISSION_STATE_INVALID", state=record.state)], actor=actor)
    with transaction.atomic():
        if not _cas(record, record.version, state=D.CANCELLED, finished_at=timezone.now(), outcome={"cancelled_by": actor[:150], "reason": reason[:200]}):
            return _refuse(action, record, [blocker("CONCURRENT_MODIFICATION")], actor=actor)
        _event(record.device, action, Outcome.RECORDED, actor=actor, evidence={"record": record.record_id})
        _audit(record, models.AuditEventType.DECOMMISSION_CHANGED, actor, f"{record.record_id}: cancelled", {"reason": reason[:200]})
        _fact(record.device, "DECOMMISSION_CANCELLED", actor=actor, detail={"record": record.record_id})
    return Result(True, action, record)


# ------------------------------------------------------------------------------------------------------------- execute
class TrafficNotMoved(Exception):
    """The transition step ran but production traffic was still observed on the device (the run takes its reverse path)."""


def _lifecycle(device, to_state: str, *, actor: str, record, actor_kind: str = events.HUMAN):
    result = lifecycle.transition(device, to_state, actor=actor, actor_kind=actor_kind, evidence={"decommission": record.record_id})
    if not result.ok:
        raise governed.TransactionError([governed.blocker(code) for code in result.codes])
    return result


def execute(record, *, actor: str, confirmation: str, runtime: Runtime | None) -> Result:
    action = "DECOMMISSION_EXECUTE"
    if record is None:
        return Result(False, action, None, [blocker("DECOMMISSION_NOT_FOUND")])
    problems = []
    if record.state != D.APPROVED:
        problems.append(blocker("DECOMMISSION_STATE_INVALID", state=record.state))
    retire_only = bool(((record.plan or {}).get("facts") or {}).get("retire_only"))
    if confirmation != (record.record_id if retire_only else record.plan_hash):
        problems.append(blocker("DECOMMISSION_CONFIRMATION_MISMATCH"))
    if record.approval_expires_at is not None and timezone.now() > record.approval_expires_at:
        problems.append(blocker("DECOMMISSION_APPROVAL_EXPIRED"))
    if not retire_only and runtime is None:
        problems.append(blocker("DECOMMISSION_RUNTIME_UNAVAILABLE"))
    if problems:
        if any(b["code"] == "DECOMMISSION_APPROVAL_EXPIRED" for b in problems) and record.state == D.APPROVED:
            _cas(record, record.version, state=D.BLOCKED, blockers=problems)
        return _refuse(action, record, problems, actor=actor)
    device = record.device
    if retire_only:
        return _retire(record, device, actor=actor)
    # the traffic is observed again right before the lock: readiness must still be what was approved
    observation = runtime.observer.observe(device.name)
    fresh = readiness.evaluate(observation, operator=actor, reason=record.reason, now=timezone.now())
    if fresh["verdict"] != (record.readiness or {}).get("verdict"):
        _cas(record, record.version, state=D.BLOCKED, blockers=[blocker("DECOMMISSION_READINESS_CHANGED", now=fresh["verdict"])],
             transition={"pre_execution": fresh})
        return _refuse(action, record, [blocker("DECOMMISSION_READINESS_CHANGED", now=fresh["verdict"])], actor=actor)
    try:
        with transaction.atomic():
            _lifecycle(device, S.DECOMMISSION_PENDING, actor=actor, record=record)
            first = D.TRAFFIC_TRANSITION if record.plan.get("transition") else D.DECOMMISSIONING
            if not _cas(record, record.version, state=first, transition={"pre_execution": {"verdict": fresh["verdict"], "digest": fresh["digest"]}}):
                raise governed.TransactionError([governed.blocker("CONCURRENT_MODIFICATION")])
    except governed.TransactionError as exc:
        return _refuse(action, record, [blocker("DECOMMISSION_STATE_INVALID", transaction=[b["code"] for b in exc.blockers])], actor=actor)
    measured = {"transition": record.transition, "moves": [], "probe": None, "probe_started": None}
    probe = runtime.probe_factory() if (runtime.probe_factory and record.readiness_mode == models.DecommissionReadiness.REDUNDANT_TRANSITION) else None
    measured["probe_started"] = timezone.now().isoformat() if probe else None
    transition_keys = [op["key"] for op in record.plan.get("transition") or []]
    removal_keys = [op["key"] for op in record.plan.get("removal") or []]
    captured = {}

    reached: set = set()

    def observer(event, key):
        if event == "after":
            reached.add(key)
        if event == "after" and transition_keys and key == transition_keys[-1]:
            _await_moved(record, device, runtime, measured)
        if event == "before" and removal_keys and key == removal_keys[0]:
            models.DecommissionRecord.objects.filter(pk=record.pk).update(state=D.DECOMMISSIONING, updated_at=timezone.now())
        # Compensation undoes newest first: the removals (links come back), then the cost-out.  The cost-out is undone only once
        # the re-enabled links carry FULL adjacencies again plus one settle period -- the same rule as ``execute_recovery``;
        # undoing it earlier pulls traffic onto a path that is not yet forwarding (observed live: IPv6 loss before OSPFv3 FULL).
        if event == "before" and transition_keys and key == f"compensate:{transition_keys[-1]}" and reached & set(removal_keys):
            observation, missing = await_adjacencies(device.name, eos.ospf_processes(record.baseline.text), runtime)
            measured["adjacencies_before_uncost"] = {"adjacencies": observation.adjacencies, "missing": missing}
            runtime.sleep(runtime.settle_seconds)

    def preflight(executor):
        found = []
        if executor.config_state_digest() != record.baseline.state_digest:
            found.append(governed.blocker("BASELINE_CHANGED", "the device configuration changed since readiness was evaluated"))
        return found

    def final(executor):
        failed = []
        runtime.sleep(runtime.soak_seconds)
        if probe is not None:
            measurement = probe.stop()
            measured["probe"] = measurement
            failed += readiness.loss_findings(measurement)
        after = runtime.observer.observe(device.name, window_seconds=min(runtime.settle_seconds, 5.0))
        still = readiness.traffic_moved(after)
        measured["after"] = {"on_device": still, "paths": after.paths}
        if still:
            failed.append({"check": "traffic", "detail": f"still on the device: {', '.join(still)}"})
        try:
            captured["text"] = governed_read(executor)
            captured["digest"] = executor.config_state_digest()
        except governed.SESSION_ERRORS as exc:  # an unreadable result is a failed postcheck
            failed.append({"check": "read_back", "detail": type(exc).__name__})
        return failed

    result = governed.execute(record.change, ops_of(record), actor=actor, confirmation=confirmation, device=device_dict(device),
                              executor_factory=runtime.executor_factory, preflight=preflight, final=final, observer=observer)
    if probe is not None and measured["probe"] is None:
        try:
            measured["probe"] = probe.stop()
        except Exception:  # pylint: disable=broad-exception-caught  # noqa: BLE001 - the probe's own failure is recorded as absent
            measured["probe"] = {}
    return _finish(record, device, result, measured, captured, actor=actor)


def governed_read(executor) -> str:
    from ..isolation.service import read_config

    return read_config(executor)


def _await_moved(record, device, runtime: Runtime, measured: dict) -> None:
    """After the cost-out: observe until no production flow passes the device, or give up (-> compensation)."""
    deadline = time.monotonic() + runtime.move_timeout_seconds
    runtime.sleep(runtime.settle_seconds)
    while True:
        observation = runtime.observer.observe(device.name, window_seconds=min(runtime.settle_seconds, 5.0))
        still = readiness.traffic_moved(observation)
        measured["moves"].append({"at": timezone.now().isoformat(), "still_on_device": still, "paths": observation.paths})
        if not still:
            return
        if time.monotonic() >= deadline:
            raise TrafficNotMoved(", ".join(still))
        runtime.sleep(runtime.settle_seconds)


def await_adjacencies(name: str, wanted, runtime: Runtime):
    """Poll, bounded by ``adjacency_timeout_seconds``, until every OSPF family in ``wanted`` has a FULL adjacency on ``name``
    (OSPF needs its own election / exchange time).  -> (last observation, families still missing)."""
    deadline = time.monotonic() + runtime.adjacency_timeout_seconds
    while True:
        observation = runtime.observer.observe(name, window_seconds=1.0)
        missing = [f for f in wanted if not ((observation.adjacencies or {}).get(f) or {}).get("device")]
        if not missing or time.monotonic() >= deadline:
            return observation, missing
        runtime.sleep(runtime.settle_seconds)


CREDENTIAL_RETIRED = "DEVICE_DECOMMISSIONED"


def _retire_credentials(name: str) -> list[dict]:
    """A decommissioned device's management accounts are never rotated or used again: rotation is disabled and the account is
    BLOCKED (the secret itself stays in its provider -- deleting it would make an exact restoration impossible).  -> what was
    changed, so a restoration can reinstate exactly that."""
    retired = []
    for credential in models.DeviceCredential.objects.select_for_update().filter(device_name=name).order_by("pk"):
        retired.append({"id": credential.pk, "username": credential.username, "rotation_enabled": credential.rotation_enabled,
                        "last_status": credential.last_status, "last_result_code": credential.last_result_code})
        credential.rotation_enabled, credential.last_status = False, models.CredentialStatus.BLOCKED
        credential.last_result_code = CREDENTIAL_RETIRED
        credential.save(update_fields=["rotation_enabled", "last_status", "last_result_code", "updated_at"])
    return retired


def _reinstate_credentials(name: str, retired: list[dict]) -> list[dict]:
    """Undo ``_retire_credentials`` for a restored successor -- only accounts still exactly as retirement left them."""
    reinstated = []
    for entry in retired or []:
        credential = models.DeviceCredential.objects.select_for_update().filter(pk=entry.get("id"), device_name=name).first()
        if credential is None or credential.last_result_code != CREDENTIAL_RETIRED or credential.last_status != models.CredentialStatus.BLOCKED:
            reinstated.append({"id": entry.get("id"), "reinstated": False})
            continue
        credential.rotation_enabled, credential.last_status = bool(entry["rotation_enabled"]), entry["last_status"]
        credential.last_result_code = entry.get("last_result_code", "")
        credential.save(update_fields=["rotation_enabled", "last_status", "last_result_code", "updated_at"])
        reinstated.append({"id": credential.pk, "reinstated": True})
    return reinstated


def _finish(record, device, result, measured: dict, captured: dict, *, actor: str) -> Result:
    outcome = {"run": str(result.run.run_id) if result.run is not None else "", "outcome": result.outcome,
               "blockers": result.blockers, "restored": result.report.get("restored"), "failure": result.report.get("failure"),
               "baseline_digest": result.report.get("baseline_digest"), "final_digest": result.report.get("final_digest")}
    transition_evidence = {**(record.transition or {}), "moves": measured["moves"][-20:], "probe": measured["probe"],
                           "probe_started": measured["probe_started"], "after": measured.get("after"),
                           "adjacencies_before_uncost": measured.get("adjacencies_before_uncost")}
    with transaction.atomic():
        fresh_device = models.ManagedDevice.objects.get(pk=device.pk)
        if result.succeeded:
            snap = models.DeviceConfigSnapshot.objects.create(
                device=fresh_device, purpose=models.DeviceConfigSnapshot.Purpose.DECOMMISSION_RESULT, platform=fresh_device.platform,
                text=captured.get("text", ""), sha256=hashlib.sha256(captured.get("text", "").encode()).hexdigest(),
                state_digest=captured.get("digest", ""), captured_by=actor[:150], source="postcheck session")
            outcome["credentials_retired"] = _retire_credentials(fresh_device.name)
            _cas(record, record.version, state=D.DECOMMISSIONED, outcome=outcome, transition=transition_evidence, result_snapshot=snap,
                 finished_at=timezone.now())
            _lifecycle(fresh_device, S.DECOMMISSIONED, actor=actor, record=record)
            _fact(fresh_device, "DECOMMISSIONED", actor=actor, detail={"record": record.record_id, "mode": record.readiness_mode})
            state = D.DECOMMISSIONED
        elif result.outcome in (X.BLOCKED, X.FAILED_NO_MUTATION, X.FAILED_ROLLED_BACK, X.POSTCHECK_FAILED_ROLLED_BACK):
            state = D.BLOCKED if result.outcome in (X.BLOCKED, X.FAILED_NO_MUTATION) else D.ROLLED_BACK
            _cas(record, record.version, state=state, outcome=outcome, transition=transition_evidence,
                 blockers=[blocker("DECOMMISSION_STATE_INVALID", outcome=result.outcome)],
                 finished_at=timezone.now() if state == D.ROLLED_BACK else None)
            _lifecycle(fresh_device, S.IN_SERVICE, actor=actor, record=record)
            if state == D.ROLLED_BACK:
                _fact(fresh_device, "DECOMMISSION_CANCELLED", actor=actor, detail={"record": record.record_id, "outcome": result.outcome})
        else:
            state = D.UNCERTAIN
            _cas(record, record.version, state=D.UNCERTAIN, outcome=outcome, transition=transition_evidence,
                 blockers=[blocker("DECOMMISSION_UNCERTAIN", outcome=result.outcome)])
        record.refresh_from_db()
        _audit(record, models.AuditEventType.DECOMMISSION_CHANGED, actor, f"{record.record_id}: execution {result.outcome} -> {state}",
               {"outcome": result.outcome, "state": state, "probe": measured["probe"]})
    return Result(state == D.DECOMMISSIONED, "DECOMMISSION_EXECUTE", record, [] if state == D.DECOMMISSIONED else record.blockers,
                  {"outcome": result.outcome, "report": result.report})


def _retire(record, device, *, actor: str) -> Result:
    """A never-admitted device: no device write; the registry retires it (REQUEST then DECOMMISSION in one transaction)."""
    try:
        with transaction.atomic():
            _lifecycle(device, S.DECOMMISSION_PENDING, actor=actor, record=record)
            _cas(record, record.version, state=D.DECOMMISSIONING)
            _cas(record, record.version, state=D.DECOMMISSIONED, finished_at=timezone.now(),
                 outcome={"outcome": "RETIRED_WITHOUT_DEVICE_WRITE", "credentials_retired": _retire_credentials(device.name)})
            _lifecycle(models.ManagedDevice.objects.get(pk=device.pk), S.DECOMMISSIONED, actor=actor, record=record)
            _fact(models.ManagedDevice.objects.get(pk=device.pk), "DECOMMISSIONED", actor=actor, detail={"record": record.record_id, "mode": "RETIRE_ONLY"})
    except governed.TransactionError as exc:
        return _refuse("DECOMMISSION_EXECUTE", record, [blocker("DECOMMISSION_STATE_INVALID", transaction=[b["code"] for b in exc.blockers])], actor=actor)
    record.refresh_from_db()
    return Result(True, "DECOMMISSION_EXECUTE", record)


def reconcile(record, *, actor: str, runtime: Runtime | None) -> Result:
    """Resolve an UNCERTAIN record from the device's own state: back on the baseline digest -> ROLLED_BACK (device returns to service);
    anything else stays UNCERTAIN with the observed digest recorded.  Nothing is replayed."""
    action = "DECOMMISSION_RECONCILE"
    if record is None:
        return Result(False, action, None, [blocker("DECOMMISSION_NOT_FOUND")])
    if record.state not in (D.UNCERTAIN, D.TRAFFIC_TRANSITION, D.DECOMMISSIONING):
        return _refuse(action, record, [blocker("DECOMMISSION_STATE_INVALID", state=record.state)], actor=actor)
    if runtime is None:
        return _refuse(action, record, [blocker("DECOMMISSION_RUNTIME_UNAVAILABLE")], actor=actor)
    executor = runtime.executor_factory(device_dict(record.device))
    try:
        executor.connect()
        digest = executor.config_state_digest()
    except governed.SESSION_ERRORS as exc:  # unreadable stays uncertain
        return _refuse(action, record, [blocker("DECOMMISSION_EVIDENCE_UNAVAILABLE", error=type(exc).__name__)], actor=actor)
    finally:
        try:
            executor.close()
        except governed.SESSION_ERRORS:  # a failed session never masks the outcome
            pass
    with transaction.atomic():
        if digest == record.baseline.state_digest:
            _cas(record, record.version, state=D.ROLLED_BACK, finished_at=timezone.now(),
                 outcome={**(record.outcome or {}), "reconciled": {"by": actor[:150], "digest": digest, "verdict": "BASELINE"}})
            if record.change is not None:     # the interrupted run no longer blocks the device's next governed transaction
                governed.mark_reconciled(record.change, actor=actor, digest=digest, basis=f"{record.record_id} read-only reconcile")
            device = models.ManagedDevice.objects.get(pk=record.device_id)
            if device.lifecycle_state == S.DECOMMISSION_PENDING:
                _lifecycle(device, S.IN_SERVICE, actor=actor, record=record)
            _fact(device, "DECOMMISSION_CANCELLED", actor=actor, detail={"record": record.record_id, "reconciled": True})
            ok = True
        else:
            _cas(record, record.version, state=D.UNCERTAIN,
                 outcome={**(record.outcome or {}), "reconciled": {"by": actor[:150], "digest": digest, "verdict": "NOT_BASELINE"}})
            ok = False
        _audit(record, models.AuditEventType.DECOMMISSION_CHANGED, actor, f"{record.record_id}: reconciled ({'baseline' if ok else 'not baseline'})",
               {"digest": digest})
    record.refresh_from_db()
    return Result(ok, action, record, [] if ok else [blocker("DECOMMISSION_UNCERTAIN")])


# ------------------------------------------------------------------------------------------------------------- restoration
# ------------------------------------------------------------------------------------------------------------- recovery
def _recovery(record) -> dict:
    return dict((record.outcome or {}).get("recovery") or {})


def _recovery_change(record):
    change_id = _recovery(record).get("change", "")
    return models.Change.objects.filter(change_id=change_id).first() if change_id else None


def _live_run(record) -> bool:
    if record.change is None:
        return False
    from ..execution import locking

    locking.reap_expired(timezone.now())         # a crashed process's run ends INTERRUPTED once its lease has expired
    return record.change.execution_runs.filter(state=models.ExecutionRunState.RUNNING).exists()


def plan_recovery(record, *, actor: str, runtime: Runtime | None) -> Result:
    """Read the device through the run's own transport and plan the inverse of exactly the operations whose effect it holds."""
    action = "DECOMMISSION_RECOVERY_PLAN"
    if record is None:
        return Result(False, action, None, [blocker("DECOMMISSION_NOT_FOUND")])
    problems = []
    if record.state not in RECOVERABLE or record.baseline is None or record.change is None:
        problems.append(blocker("DECOMMISSION_STATE_INVALID", state=record.state))
    elif _live_run(record):
        problems.append(blocker("DECOMMISSION_STATE_INVALID", detail="the decommission run is still running"))
    if runtime is None:
        problems.append(blocker("DECOMMISSION_RUNTIME_UNAVAILABLE"))
    if problems:
        return _refuse(action, record, problems, actor=actor)
    from ..config_workbench.structure import config_paths
    from ..isolation.service import read_config

    device = record.device
    executor = runtime.executor_factory(device_dict(device))
    try:
        executor.connect()
        current = read_config(executor)
        digest = executor.config_state_digest()
    except governed.SESSION_ERRORS as exc:
        return _refuse(action, record, [blocker("DECOMMISSION_EVIDENCE_UNAVAILABLE", error=getattr(exc, "code", type(exc).__name__))], actor=actor)
    finally:
        executor.close()
    if digest == record.baseline.state_digest:
        return _refuse(action, record, [blocker("DECOMMISSION_STATE_INVALID", detail="the device is on its baseline: reconcile it")], actor=actor)
    try:
        plan = eos.render_recovery(ops_of(record), config_paths(current))
    except eos.PlanError as exc:
        return _refuse(action, record, [blocker("DECOMMISSION_RECOVERY_CONFLICT", cause=exc.code, detail=exc.detail)], actor=actor)
    ops = plan["operations"]
    if not ops:
        return _refuse(action, record, [blocker("DECOMMISSION_RECOVERY_CONFLICT", detail="no operation of this run is on the device, yet "
                                                                                          "it is not on its baseline")], actor=actor)
    with transaction.atomic():
        change = governed.create_change(kind=RECOVERY_KIND, device=device.name, title=f"Recover {device.name} ({record.record_id})",
                                        description=f"Undo the part-applied decommission {record.record_id}", actor=actor,
                                        reference={"decommission": record.record_id, "resolves": record.change.change_id})
        governed.validate(change, ops, actor=actor, findings=[], source={"device": device.name, "digest": digest})
        built = governed.build_plan(change, ops, actor=actor, device=device.name, summary={"decommission": record.record_id})
        governed.record_precheck(change, built, actor=actor, blockers=[], facts={"decommission": record.record_id, "current_digest": digest})
        recovery = {"change": change.change_id, "plan_hash": built.plan_hash, "operations": ops, "planned_by": actor[:150],
                    "planned_digest": digest, "state": "PLANNED"}
        if not _cas(record, record.version, outcome={**(record.outcome or {}), "recovery": recovery}):
            raise IntegrityError("concurrent")
        _audit(record, models.AuditEventType.DECOMMISSION_CHANGED, actor, f"{record.record_id}: recovery planned ({len(ops)} operations)",
               {"change": change.change_id, "plan_hash": built.plan_hash})
    return Result(True, action, record, detail={"recovery": recovery})


def approve_recovery(record, *, actor: str, confirmation: str) -> Result:
    action = "DECOMMISSION_RECOVERY_APPROVE"
    if record is None:
        return Result(False, action, None, [blocker("DECOMMISSION_NOT_FOUND")])
    recovery, change = _recovery(record), _recovery_change(record)
    problems = []
    if record.state not in RECOVERABLE or change is None or recovery.get("state") != "PLANNED":
        problems.append(blocker("DECOMMISSION_STATE_INVALID", state=record.state, recovery=recovery.get("state", "")))
    if not actor or actor == recovery.get("planned_by"):
        problems.append(blocker("DECOMMISSION_SELF_APPROVAL"))
    if confirmation != recovery.get("plan_hash"):
        problems.append(blocker("DECOMMISSION_CONFIRMATION_MISMATCH"))
    if problems:
        return _refuse(action, record, problems, actor=actor)
    try:
        with transaction.atomic():
            governed.approve(change, recovery["operations"], actor=actor, requested_by=recovery["planned_by"], confirmation=confirmation,
                             device=record.device.name, extra={"decommission": record.record_id})
            if not _cas(record, record.version, outcome={**(record.outcome or {}), "recovery": {**recovery, "state": "APPROVED",
                                                                                              "approved_by": actor[:150]}}):
                raise governed.TransactionError([governed.blocker("CONCURRENT_MODIFICATION")])
            _audit(record, models.AuditEventType.DECOMMISSION_CHANGED, actor, f"{record.record_id}: recovery approved", {"plan_hash": confirmation})
    except governed.TransactionError as exc:
        return _refuse(action, record, [blocker("DECOMMISSION_STATE_INVALID", transaction=[b["code"] for b in exc.blockers])], actor=actor)
    return Result(True, action, record)


def execute_recovery(record, *, actor: str, confirmation: str, runtime: Runtime | None) -> Result:
    """Run the approved recovery under the device lock; ROLLED_BACK (device back IN_SERVICE) only on the exact baseline digest."""
    action = "DECOMMISSION_RECOVERY_EXECUTE"
    if record is None:
        return Result(False, action, None, [blocker("DECOMMISSION_NOT_FOUND")])
    recovery, change = _recovery(record), _recovery_change(record)
    problems = []
    if record.state not in RECOVERABLE or change is None or recovery.get("state") != "APPROVED":
        problems.append(blocker("DECOMMISSION_STATE_INVALID", state=record.state, recovery=recovery.get("state", "")))
    if confirmation != recovery.get("plan_hash"):
        problems.append(blocker("DECOMMISSION_CONFIRMATION_MISMATCH"))
    if runtime is None:
        problems.append(blocker("DECOMMISSION_RUNTIME_UNAVAILABLE"))
    if problems:
        return _refuse(action, record, problems, actor=actor)
    baseline = record.baseline.state_digest
    measured: dict = {}
    # The run's cost-out is undone LAST and only once the links it re-enabled carry FULL adjacencies again (plus one settle period
    # for forwarding / neighbour discovery): removing the cost-out earlier pulls traffic onto a path that is not yet forwarding.
    transition_undo = {f"undo-{op['key']}" for op in (record.plan or {}).get("transition") or []}
    keys = [op["key"] for op in recovery["operations"]]
    first_uncost = next((key for key in keys if key in transition_undo), None)
    links_first = first_uncost is not None and keys.index(first_uncost) > 0

    def observer(event, key):
        if event == "before" and links_first and key == first_uncost:
            observation, missing = await_adjacencies(record.device.name, eos.ospf_processes(record.baseline.text), runtime)
            measured["adjacencies_before_uncost"] = {"adjacencies": observation.adjacencies, "missing": missing}
            runtime.sleep(runtime.settle_seconds)

    def preflight(executor):
        found = []
        if executor.config_state_digest() != recovery["planned_digest"]:
            found.append(governed.blocker("BASELINE_CHANGED", "the device changed since the recovery was planned"))
        return found

    def final(executor):
        measured["digest"] = executor.config_state_digest()
        if measured["digest"] != baseline:
            return [{"check": "exact_recovery", "detail": "the configuration digest differs from the pre-decommission baseline"}]
        return []

    result = governed.execute(change, recovery["operations"], actor=actor, confirmation=confirmation, device=device_dict(record.device),
                              executor_factory=runtime.executor_factory, preflight=preflight, final=final, observer=observer,
                              resolves=record.change.change_id)
    outcome = {"run": str(result.run.run_id) if result.run is not None else "", "outcome": result.outcome, "blockers": result.blockers,
               "digest": measured.get("digest"), "baseline_digest": baseline,
               "adjacencies_before_uncost": measured.get("adjacencies_before_uncost")}
    with transaction.atomic():
        done = result.succeeded and measured.get("digest") == baseline
        fields = {"outcome": {**(record.outcome or {}), "recovery": {**recovery, "state": "SUCCEEDED" if done else "FAILED", "result": outcome}}}
        if done:
            fields.update(state=D.ROLLED_BACK, finished_at=timezone.now())
        else:
            fields.update(state=D.UNCERTAIN, blockers=[blocker("DECOMMISSION_UNCERTAIN", outcome=result.outcome)])
        _cas(record, record.version, **fields)
        if done:
            governed.mark_reconciled(record.change, actor=actor, digest=measured["digest"], basis=f"{change.change_id} governed recovery")
            device = models.ManagedDevice.objects.get(pk=record.device_id)
            if device.lifecycle_state == S.DECOMMISSION_PENDING:
                _lifecycle(device, S.IN_SERVICE, actor=actor, record=record)
            _fact(device, "DECOMMISSION_CANCELLED", actor=actor, detail={"record": record.record_id, "recovered": change.change_id})
        _audit(record, models.AuditEventType.DECOMMISSION_CHANGED, actor,
               f"{record.record_id}: recovery {result.outcome} -> {D.ROLLED_BACK if done else D.UNCERTAIN}", outcome)
    record.refresh_from_db()
    return Result(done, action, record, [] if done else record.blockers, {"outcome": result.outcome, "report": result.report})


def request_restore(record, *, actor: str) -> Result:
    action = "RESTORE_REQUEST"
    if record is None:
        return Result(False, action, None, [blocker("DECOMMISSION_NOT_FOUND")])
    if record.state != D.DECOMMISSIONED or record.baseline is None:
        return Result(False, action, None, [blocker("RESTORATION_STATE_INVALID", decommission=record.state)])
    try:
        with transaction.atomic():
            row = models.RestorationRecord.objects.create(decommission=record, device=record.device, snapshot=record.baseline, requested_by=actor[:150])
            _audit(row, models.AuditEventType.RESTORATION_CHANGED, actor, f"{row.record_id}: restoration of {record.device.name} requested",
                   {"decommission": record.record_id, "snapshot": record.baseline.snapshot_id})
    except IntegrityError:
        return Result(False, action, None, [blocker("RESTORATION_OPEN_EXISTS")])
    return Result(True, action, row)


def _restoration_refuse(action: str, row, blockers_: list, *, actor: str, state=None) -> Result:
    with transaction.atomic():
        if state is not None:
            _cas(row, row.version, state=state, blockers=blockers_)
        _audit(row, models.AuditEventType.RESTORATION_CHANGED, actor, f"{row.record_id}: {action} refused", {"codes": [b["code"] for b in blockers_]})
    return Result(False, action, row, blockers_)


def check_restore(row, *, actor: str, runtime: Runtime | None) -> Result:
    """Integrity, platform, conflicts, identity, prior admission, then the governed plan (-> PLANNED, BLOCKED or REENROLLMENT_REQUIRED)."""
    action = "RESTORE_CHECK"
    if row is None:
        return Result(False, action, None, [blocker("RESTORATION_NOT_FOUND")])
    if row.state not in (R.REQUESTED, R.BLOCKED):
        return Result(False, action, row, [blocker("RESTORATION_STATE_INVALID", state=row.state)])
    device, snap = row.device, row.snapshot
    checks, problems = {}, []
    checks["integrity"] = hashlib.sha256(snap.text.encode()).hexdigest() == snap.sha256 and snap.device_id == device.pk
    checks["platform"] = snap.platform == device.platform == models.Platform.ARISTA_CEOS
    if not checks["integrity"] or not checks["platform"]:
        problems.append(blocker("RESTORATION_SNAPSHOT_INVALID", integrity=checks["integrity"], platform=checks["platform"]))
    live = models.ManagedDevice.objects.filter(name=device.name).exclude(lifecycle_state__in=tuple(models.DEVICE_LIFECYCLE_TERMINAL)).first()
    if live is not None:
        problems.append(blocker("RESTORATION_CONFLICT", detail=f"{live.device_id} now holds the name"))
    ports = [(a.upstream_device, a.upstream_interface) for a in device.attachments.filter(approval_state=models.AttachmentApproval.APPROVED)]
    taken = [f"{u}:{i}" for u, i in ports if models.DeviceAttachment.objects.filter(upstream_device=u, upstream_interface=i).exclude(
        device=device).exclude(approval_state=models.AttachmentApproval.REVOKED).exists()]
    checks["attachments"] = {"ports": len(ports), "taken": taken}
    if taken:
        problems.append(blocker("RESTORATION_CONFLICT", detail=f"attachment port taken: {taken[0]}"))
    if device.admission_state not in READMITTABLE:
        return _restoration_refuse(action, row, [blocker("RESTORATION_REENROLLMENT_REQUIRED", admission=device.admission_state)],
                                   actor=actor, state=R.REENROLLMENT_REQUIRED)
    if models.ManagementPath.objects.filter(device=device).exists():
        # its management paths, attachments and approvals were retired with it: the successor needs its own, so re-enrollment
        return _restoration_refuse(action, row, [blocker("RESTORATION_REENROLLMENT_REQUIRED", management="paths retired with the device")],
                                   actor=actor, state=R.REENROLLMENT_REQUIRED)
    if runtime is None:
        problems.append(blocker("DECOMMISSION_RUNTIME_UNAVAILABLE"))
    if problems:
        models.RestorationRecord.objects.filter(pk=row.pk).update(checks=checks)
        return _restoration_refuse(action, row, problems, actor=actor, state=R.BLOCKED)
    executor = runtime.executor_factory(device_dict(device))
    with resolve.retired_device_access(device.name):     # the only way NMAS reaches a retired device (management.resolve)
        try:
            executor.connect()
            from ..isolation.service import read_config

            current = read_config(executor)
            digest = executor.config_state_digest()
            observed_key = host_key(executor)
        except governed.SESSION_ERRORS as exc:  # unreadable: credentials / path unavailable
            return _restoration_refuse(action, row, [blocker("DECOMMISSION_EVIDENCE_UNAVAILABLE", error=type(exc).__name__)], actor=actor, state=R.BLOCKED)
        finally:
            try:
                executor.close()
            except governed.SESSION_ERRORS:  # a failed session never masks the outcome
                pass
    expected_key = device.verified_host_key or ((row.decommission.readiness or {}).get("identity") or {}).get("host_key", "")
    checks["identity"] = {"expected_known": bool(expected_key), "observed_known": bool(observed_key), "match": bool(expected_key) and expected_key == observed_key,
                          "basis": "verified identity" if device.verified_host_key else "decommission-time session host key"}
    checks["credentials"] = {"session": "authenticated", "transport": type(executor).__name__}
    if not checks["identity"]["match"]:
        return _restoration_refuse(action, row, [blocker("RESTORATION_REENROLLMENT_REQUIRED", identity="not re-observed")],
                                   actor=actor, state=R.REENROLLMENT_REQUIRED)
    result_snap = row.decommission.result_snapshot
    checks["drift"] = {"since_decommission": bool(result_snap and result_snap.state_digest != digest)}
    try:
        plan = eos.render_restore(snap.text, current, management_addresses=runtime.management_addresses(device))
    except eos.PlanError as exc:
        models.RestorationRecord.objects.filter(pk=row.pk).update(checks=checks)
        return _restoration_refuse(action, row, [blocker("RESTORATION_CONFLICT", cause=exc.code, detail=exc.detail)], actor=actor, state=R.BLOCKED)
    ops = plan["operations"]
    checks["isolation"] = {"required": False, "basis": "identity re-observed in place and prior admission " + device.admission_state}
    with transaction.atomic():
        change = governed.create_change(kind=RESTORE_KIND, device=device.name, title=f"Restore {device.name} ({row.record_id})",
                                        description=f"Restore {device.name} from {snap.snapshot_id}", actor=actor,
                                        reference={"restoration": row.record_id, "decommission": row.decommission.record_id})
        governed.validate(change, ops, actor=actor, findings=[], source={"device": device.name, "snapshot": snap.sha256})
        built = governed.build_plan(change, ops, actor=actor, device=device.name, summary={"restoration": row.record_id})
        governed.record_precheck(change, built, actor=actor, blockers=[], facts={"restoration": row.record_id, "current_digest": digest})
        if not _cas(row, row.version, state=R.PLANNED, checks=checks, blockers=[], plan=plan, plan_hash=built.plan_hash, change=change):
            raise IntegrityError("concurrent")
        _audit(row, models.AuditEventType.RESTORATION_CHANGED, actor, f"{row.record_id}: planned ({len(ops)} operations)",
               {"plan_hash": built.plan_hash, "checks": {k: v for k, v in checks.items() if k != "attachments"}})
    return Result(True, action, row)


def approve_restore(row, *, actor: str, confirmation: str) -> Result:
    action = "RESTORE_APPROVE"
    if row is None:
        return Result(False, action, None, [blocker("RESTORATION_NOT_FOUND")])
    problems = []
    if row.state != R.PLANNED:
        problems.append(blocker("RESTORATION_STATE_INVALID", state=row.state))
    if not actor or actor == row.requested_by:
        problems.append(blocker("RESTORATION_SELF_APPROVAL"))
    if confirmation != row.plan_hash:
        problems.append(blocker("DECOMMISSION_CONFIRMATION_MISMATCH"))
    if problems:
        return _restoration_refuse(action, row, problems, actor=actor)
    try:
        with transaction.atomic():
            governed.approve(row.change, row.plan["operations"], actor=actor, requested_by=row.requested_by, confirmation=confirmation,
                             device=row.device.name, extra={"restoration": row.record_id})
            _cas(row, row.version, state=R.APPROVED, approved_by=actor[:150], approved_at=timezone.now())
            _audit(row, models.AuditEventType.RESTORATION_CHANGED, actor, f"{row.record_id}: approved", {"plan_hash": row.plan_hash})
    except governed.TransactionError as exc:
        return _restoration_refuse(action, row, [blocker("RESTORATION_STATE_INVALID", transaction=[b["code"] for b in exc.blockers])], actor=actor)
    return Result(True, action, row)


def execute_restore(row, *, actor: str, confirmation: str, runtime: Runtime | None) -> Result:
    """Reapply the snapshot; the postcheck requires the exact pre-decommission configuration digest and the routing adjacencies
    back; only then a successor record is registered and readmitted."""
    action = "RESTORE_EXECUTE"
    if row is None:
        return Result(False, action, None, [blocker("RESTORATION_NOT_FOUND")])
    problems = []
    if row.state != R.APPROVED:
        problems.append(blocker("RESTORATION_STATE_INVALID", state=row.state))
    if confirmation != row.plan_hash:
        problems.append(blocker("DECOMMISSION_CONFIRMATION_MISMATCH"))
    if runtime is None:
        problems.append(blocker("DECOMMISSION_RUNTIME_UNAVAILABLE"))
    if problems:
        return _restoration_refuse(action, row, problems, actor=actor)
    _cas(row, row.version, state=R.RESTORING)
    device, snap = row.device, row.snapshot
    expected_digest = snap.state_digest
    measured: dict = {}

    def final(executor):
        failed = []
        runtime.sleep(runtime.soak_seconds)
        digest = executor.config_state_digest()
        measured["digest"] = digest
        if digest != expected_digest:
            failed.append({"check": "exact_restore", "detail": "the configuration digest differs from the pre-decommission baseline"})
        wanted = eos.ospf_processes(snap.text)
        observation, missing = await_adjacencies(device.name, wanted, runtime)
        measured["adjacencies"] = observation.adjacencies
        for family in missing:
            failed.append({"check": "routing", "detail": f"{family}: no FULL adjacency after restoring {wanted[family]}"})
        try:
            measured["text"] = governed_read(executor)
        except governed.SESSION_ERRORS as exc:  # an unreadable result is a failed postcheck
            failed.append({"check": "read_back", "detail": type(exc).__name__})
        return failed

    with resolve.retired_device_access(device.name):     # the only way NMAS reaches a retired device (management.resolve)
        result = governed.execute(row.change, row.plan["operations"], actor=actor, confirmation=confirmation, device=device_dict(device),
                                  executor_factory=runtime.executor_factory, final=final)
    outcome = {"run": str(result.run.run_id) if result.run is not None else "", "outcome": result.outcome, "blockers": result.blockers,
               "digest": measured.get("digest"), "expected_digest": expected_digest, "adjacencies": measured.get("adjacencies")}
    with transaction.atomic():
        if result.succeeded:
            successor = lifecycle.register_restored(models.ManagedDevice.objects.get(pk=device.pk), actor=actor, restoration=row.record_id,
                                                    evidence={"digest": measured.get("digest"), "identity": row.checks.get("identity")})
            text = measured.get("text", "")
            result_snap = models.DeviceConfigSnapshot.objects.create(
                device=successor, purpose=models.DeviceConfigSnapshot.Purpose.RESTORE_RESULT, platform=successor.platform, text=text,
                sha256=hashlib.sha256(text.encode()).hexdigest(), state_digest=measured.get("digest", ""), captured_by=actor[:150],
                source="postcheck session")
            outcome["credentials_reinstated"] = _reinstate_credentials(device.name, (row.decommission.outcome or {}).get("credentials_retired"))
            _cas(row, row.version, state=R.RESTORED, successor=successor, result_snapshot=result_snap, outcome=outcome, finished_at=timezone.now())
            _fact(successor, "RESTORED", actor=actor, detail={"restoration": row.record_id, "predecessor": device.device_id})
            state = R.RESTORED
        elif result.outcome in (X.BLOCKED, X.FAILED_NO_MUTATION, X.FAILED_ROLLED_BACK, X.POSTCHECK_FAILED_ROLLED_BACK):
            state = R.BLOCKED if result.outcome in (X.BLOCKED, X.FAILED_NO_MUTATION) else R.ROLLED_BACK
            _cas(row, row.version, state=state, outcome=outcome, blockers=[blocker("RESTORATION_STATE_INVALID", outcome=result.outcome)],
                 finished_at=timezone.now() if state == R.ROLLED_BACK else None)
        else:
            state = R.UNCERTAIN
            _cas(row, row.version, state=state, outcome=outcome, blockers=[blocker("DECOMMISSION_UNCERTAIN", outcome=result.outcome)])
        _audit(row, models.AuditEventType.RESTORATION_CHANGED, actor, f"{row.record_id}: execution {result.outcome} -> {state}",
               {"outcome": result.outcome, "digest_match": measured.get("digest") == expected_digest})
    row.refresh_from_db()
    return Result(state == R.RESTORED, action, row, [] if state == R.RESTORED else row.blockers, {"outcome": result.outcome, "report": result.report})


def cancel_restore(row, *, actor: str) -> Result:
    action = "RESTORE_CANCEL"
    if row is None:
        return Result(False, action, None, [blocker("RESTORATION_NOT_FOUND")])
    if row.state not in (R.REQUESTED, R.BLOCKED, R.PLANNED, R.APPROVED):
        return Result(False, action, row, [blocker("RESTORATION_STATE_INVALID", state=row.state)])
    with transaction.atomic():
        _cas(row, row.version, state=R.CANCELLED, finished_at=timezone.now())
        _audit(row, models.AuditEventType.RESTORATION_CHANGED, actor, f"{row.record_id}: cancelled", {})
    return Result(True, action, row)
