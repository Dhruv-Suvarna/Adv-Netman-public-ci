"""The execution engine: eligibility -> prepare -> apply -> verify -> (Complete only) compensate -> finalise.

A reusable Python callable, independent of HTTP: a Django view, a CLI or a future orchestrator calls
``execute_change(change, actor=..., ...)`` and gets an ``ExecutionResult``.  Nothing here renders a page, reads a request,
or contains vendor syntax (that lives in the executors and, upstream, the platform drivers).

    1. ELIGIBILITY   ``eligibility.check_execution_eligibility`` -- read-only, blocks with a stable code (BLOCKED run recorded).
    2. LOCK          one RUNNING run + one lock per device, atomically (``locking.acquire``); a refusal changes nothing.
    3. PREPARE       (no mutation yet)  re-check eligibility inside the lock, connect every device, recheck AUTO addresses,
                     ASSESS every Configlet (capture its previous state from the current device state) and -- for Complete --
                     prove exact compensation for the WHOLE scope.  Any failure here means the first mutation never happens.
    4. APPLY         in the plan's own order, one Configlet at a time, each with a write-ahead result row; stop at the first
                     failure; never continue blindly.
    5. VERIFY        the Phase-15 postcheck on the executed scope, with a bounded settling poll for convergence-sensitive checks.
    6. COMPENSATE    Complete only: reverse order, only what THIS run applied, each undo read back and verified.
                     Partial (UAT) NEVER rolls back: it preserves the successful prefix and says exactly where it stopped.
    7. FINALISE      one immutable outcome, device locks released, audit + notification (persist first, Slack second).

Success is never inferred from a command's return status: ``ApplyOutcome.ok`` only means the device accepted the commands.
Complete succeeds only when the postcheck confirms the intended state; missing evidence is never PASS.

This is NOT the Phase-21 rollback workflow: compensation exists only to undo a failed Complete attempt, immediately.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field

from django.utils import timezone

from ... import models
from .. import health_service, network_config_validation
from ..health import inventory
from ..health.codes import CheckStatus
from ..provisioning import gate as provisioning_gate
from . import auto_recheck, eligibility, locking, persistence
from .codes import (
    BLOCKERS, ENGINE_VERSION, POSTCHECK_PERMITS, REPORT_SCHEMA_VERSION, SETTLING_CHECKS, UAT_ACK_FIELDS, Mode, Outcome, Phase, Status, blocker,
    settle_interval_seconds, settle_timeout_seconds,
)
from .executors.base import APPLY, REFUSE, SKIP_SATISFIED, ApplyOutcome, CompensationOutcome, ConfigletSpec, ExecutorError

COMPLETE_MODE, PARTIAL_MODE = Mode.COMPLETE, Mode.PARTIAL_UAT

LIMITATIONS = (
    "Running configuration only: the startup configuration is not written, so restarting a device reverts an unpersisted change. Durable persistence belongs to the later Golden / Probation phases.",
    "Transport acceptance, command acceptance and operational verification are distinct: success is decided by the Phase-15 postcheck, never by a command's return status.",
    "Complete-mode compensation is additive-only (exact inverse of what THIS run added, verified by read-back); it is not the general Phase-21 rollback workflow.",
    "AUTO addresses are rechecked read-only immediately before execution; nothing is reserved or written to NetBox, and the recheck cannot lock NetBox against a concurrent allocator.",
)
# an ambiguous failure: the device may or may not have applied the Configlet
_AMBIGUOUS = frozenset({"TIMEOUT", "TRANSPORT_ERROR", "INTERNAL_ERROR"})


@dataclass
class ExecutionResult:
    run: object | None
    outcome: str | None = None
    blockers: list = field(default_factory=list)
    refused: bool = False          # True when nothing was started (blocked / lock refused)

    @property
    def ran(self) -> bool:
        return self.run is not None and not self.refused


@dataclass
class _Attempt:
    """Mutable working state of one locked run (kept out of the persisted models until finalisation)."""

    specs: list
    assessments: dict = field(default_factory=dict)
    executors: dict = field(default_factory=dict)
    applied: list = field(default_factory=list)          # cfg_ids applied by THIS run (compensation candidates)
    satisfied: list = field(default_factory=list)
    failed: list = field(default_factory=list)
    effects: list = field(default_factory=list)          # cfg_ids that may have changed a device (applied + failed-with-effects)
    compensation: list = field(default_factory=list)     # (cfg_id, status)
    postcheck: dict = field(default_factory=dict)
    postcheck_run: object | None = None
    auto_checked: list = field(default_factory=list)
    error: dict | None = None
    blockers: list = field(default_factory=list)
    management: dict = field(default_factory=dict)       # V2 Phase 4: device -> the management endpoint the run wrote through


def _record_acknowledgements(change, acknowledgements: dict, actor: str, now) -> None:
    for name, _label in UAT_ACK_FIELDS:
        setattr(change, name, bool((acknowledgements or {}).get(name)))
    change.uat_acknowledged_by, change.uat_acknowledged_at = actor, now
    change.save(update_fields=[*(n for n, _ in UAT_ACK_FIELDS), "uat_acknowledged_by", "uat_acknowledged_at", "updated_at"])


def execute_change(
    change, *, actor: str, through_cfg_id: str = "", acknowledgements: dict | None = None, confirm_mode: str | None = None,
    executor_factory=None, evidence_provider=None, notifier=None, sources=None, now=None, sleep=time.sleep, clock=time.monotonic,
) -> ExecutionResult:
    """Explicitly execute a Change's CURRENT plan in the Change's own execution mode.  Never raises for an operational
    failure: the outcome (including every refusal) is recorded and returned.

    ``executor_factory(device_dict) -> DeviceExecutor`` defaults to the platform registry; tests inject fakes.
    ``evidence_provider(plan, cfg_ids) -> EvidenceSet | None`` supplies postcheck evidence (None => live read-only collection).
    """
    now = now or timezone.now()
    mode = change.execution_mode
    locking.reap_expired(now)  # an abandoned run must be finalised (INTERRUPTED) BEFORE the gate judges this plan's history
    gate = eligibility.check_execution_eligibility(
        change, through_cfg_id=through_cfg_id, acknowledgements=acknowledgements, confirm_mode=confirm_mode, sources=sources, now=now,
    )
    if not gate.eligible:
        run = persistence.record_blocked(change, gate.plan, precheck_run=gate.precheck_run, mode=mode, actor=actor, blockers=gate.blockers, scope=gate.scope, now=now)
        return ExecutionResult(run=run, outcome=Outcome.BLOCKED, blockers=gate.blockers, refused=True)

    try:
        run = locking.acquire(change=change, plan=gate.plan, precheck_run=gate.precheck_run, mode=mode, actor=actor, scope=gate.scope,
                              devices=gate.scope.devices, now=now)
    except locking.LockRefused as exc:
        refusal = [blocker(exc.code, **exc.details)]
        run = persistence.record_blocked(change, gate.plan, precheck_run=gate.precheck_run, mode=mode, actor=actor, blockers=refusal, scope=gate.scope, now=now)
        return ExecutionResult(run=run, outcome=Outcome.BLOCKED, blockers=refusal, refused=True)

    attempt = _Attempt(specs=[ConfigletSpec.from_configlet(c) for c in gate.scope.selected])
    outcome = Outcome.INTERRUPTED
    try:
        if mode == PARTIAL_MODE:
            _record_acknowledgements(change, acknowledgements, actor, now)
        outcome = _drive(run, change, gate, attempt, through_cfg_id=through_cfg_id, acknowledgements=acknowledgements,
                         confirm_mode=confirm_mode, executor_factory=executor_factory or _default_factory(),
                         evidence_provider=evidence_provider, sources=sources, sleep=sleep, clock=clock)
    except Exception:  # noqa: BLE001 - an engine defect must leave a visible INTERRUPTED run, never a stuck lock or a false success
        attempt.error = {"code": "INTERNAL_ERROR"}
        outcome = Outcome.INTERRUPTED
    finally:
        for executor in attempt.executors.values():
            try:
                executor.close()
            except Exception:  # noqa: BLE001
                pass

    report = _report(run, gate, attempt, outcome)
    run = persistence.finalize_run(run, outcome=outcome, report=report, postcheck_run=attempt.postcheck_run, now=timezone.now())
    try:   # V2 Phase 5A: a provisioning request records the finalised outcome (or reconciles a failure); never alters the run
        provisioning_gate.after_execution(run)
    except Exception:  # noqa: BLE001 - bookkeeping of a finished run must never turn into an engine failure
        pass
    persistence.notify_outcome(run, notifier)
    return ExecutionResult(run=run, outcome=outcome, blockers=attempt.blockers, refused=False)


def _default_factory():
    from .executors.registry import executor_for

    return executor_for


# --- the locked run --------------------------------------------------------------------------------------------------------
def _drive(run, change, gate, attempt: _Attempt, *, through_cfg_id, acknowledgements, confirm_mode, executor_factory, evidence_provider,
           sources, sleep, clock) -> str:
    plan, scope, mode = gate.plan, gate.scope, run.mode

    # 3a. re-evaluate eligibility INSIDE the lock (closes the window between the gate and the lock; intent-level, no source read)
    again = eligibility.check_execution_eligibility(
        change, through_cfg_id=through_cfg_id, acknowledgements=acknowledgements, confirm_mode=confirm_mode, check_sources=False, exclude_run=run,
    )
    if not again.eligible:
        attempt.blockers = again.blockers
        return Outcome.BLOCKED

    # 3b. connect every device (read-only), recheck AUTO facts, assess every Configlet -- all BEFORE the first mutation
    managed = inventory.managed_devices()
    from ..management import resolve as management_resolve

    for name in scope.devices:
        endpoint = management_resolve.endpoint(name, purpose=management_resolve.WRITE)
        if endpoint.source != management_resolve.LEGACY:
            attempt.management[name] = endpoint.as_dict()
        if endpoint.source == management_resolve.BLOCKED:
            attempt.error = {"phase": "PREPARE", "device": name, "code": "MGMT_NO_USABLE_PATH"}
            attempt.blockers = [blocker("PREPARATION_FAILED", device=name, error=(endpoint.as_dict()["codes"] or ["MGMT_NO_USABLE_PATH"])[0])]
            return Outcome.FAILED_NO_MUTATION
        try:
            executor = executor_factory(managed[name])
            attempt.executors[name] = executor
            executor.connect()
        except ExecutorError as exc:
            attempt.error = {"phase": "PREPARE", "device": name, "code": exc.code}
            attempt.blockers = [blocker("PREPARATION_FAILED", device=name, error=exc.code)]
            return Outcome.FAILED_NO_MUTATION
    stale = _snapshot_guard(change, attempt)
    if stale:
        attempt.blockers = stale
        return Outcome.BLOCKED
    auto_blockers, attempt.auto_checked = auto_recheck.recheck_auto_addresses(plan, scope.selected, sources=sources)
    if auto_blockers:
        attempt.blockers = auto_blockers
        return Outcome.BLOCKED
    for spec in attempt.specs:
        try:
            assessment = attempt.executors[spec.device].assess(spec)
        except ExecutorError as exc:
            attempt.error = {"phase": "ASSESS", "device": spec.device, "cfg_id": spec.cfg_id, "code": exc.code}
            attempt.blockers = [blocker("PREPARATION_FAILED", device=spec.device, error=exc.code)]
            return Outcome.FAILED_NO_MUTATION
        attempt.assessments[spec.cfg_id] = assessment
        if assessment.action == REFUSE:
            attempt.blockers = [blocker(assessment.reason if assessment.reason in BLOCKERS else "PLATFORM_EXECUTION_UNSUPPORTED", cfg_id=spec.cfg_id)]
            return Outcome.BLOCKED
    if mode == COMPLETE_MODE:
        unprovable = [s.cfg_id for s in attempt.specs if attempt.assessments[s.cfg_id].action == APPLY and not attempt.assessments[s.cfg_id].restorable]
        if unprovable:
            attempt.blockers = [blocker("COMPENSATION_NOT_PROVABLE", configlets=unprovable)]
            return Outcome.BLOCKED
    for spec in attempt.specs:
        persistence.record_previous_state(run, spec, attempt.assessments[spec.cfg_id].previous_state,
                                          strategy="RUNNING_CONFIG_PRESENCE" if spec.origin == "REMOVAL" else "EVIDENCE_GROUPS_ADDITIVE")

    # 3c. V2 Phase 5A: a provisioning Change records the device's baseline digest here -- the last step before the first write
    baseline = provisioning_gate.before_first_mutation(change)
    if baseline:
        attempt.blockers = baseline
        return Outcome.BLOCKED

    # 4. apply, in plan order, stopping at the first failure
    failed_spec = _apply_all(run, attempt)
    remaining = [s for s in attempt.specs if s.cfg_id not in {*attempt.applied, *attempt.satisfied, *attempt.failed}]
    persistence.add_not_attempted(run, remaining)

    # 5/6. verify, and (Complete) compensate
    if failed_spec is not None:
        return _after_failure(run, plan, attempt, failed_spec, mode, evidence_provider, sleep, clock)
    return _after_success(run, plan, attempt, mode, evidence_provider, sleep, clock)


def _snapshot_guard(change, attempt: _Attempt) -> list[dict]:
    """Configuration Changes / Remove Configuration: re-read the device and refuse a basis that changed (BEFORE any mutation).

    Line numbers and removal selections were derived from ONE sanitized snapshot; executing them against a different running
    configuration is never safe, so a digest mismatch -- or an executor that cannot re-read -- blocks the whole run.
    """
    guard = (change.metadata or {}).get("workflow_snapshot") or {}
    device, expected = guard.get("device"), guard.get("digest")
    if not device or not expected or device not in attempt.executors:
        return []
    reader = getattr(attempt.executors[device], "running_config_digest", None)
    if reader is None:
        return [blocker("SNAPSHOT_UNVERIFIABLE", device=device)]
    try:
        current = reader()
    except ExecutorError as exc:
        return [blocker("SNAPSHOT_UNVERIFIABLE", device=device, error=exc.code)]
    if current != expected:
        return [blocker("SNAPSHOT_STALE", device=device, snapshot=str(guard.get("snapshot_id", ""))[:36])]
    return []


def _apply_all(run, attempt: _Attempt):
    """Apply every Configlet in order.  Returns the failing spec (after recording it) or None."""
    for spec in attempt.specs:
        assessment = attempt.assessments[spec.cfg_id]
        result = persistence.start_result(run, spec, Phase.APPLY, previous_state=assessment.previous_state)
        locking.heartbeat(run)
        if assessment.action == SKIP_SATISFIED:
            persistence.finish_result(result, Status.ALREADY_SATISFIED, detail={"reason": "the device already holds this state; nothing was sent"})
            attempt.satisfied.append(spec.cfg_id)
            continue
        try:
            outcome = attempt.executors[spec.device].apply(spec, assessment)
        except Exception:  # noqa: BLE001 - an executor defect is an ambiguous failure, never a success
            outcome = ApplyOutcome(False, "INTERNAL_ERROR", partial_effects=True)
        if outcome.ok:
            persistence.finish_result(result, Status.APPLIED, lines_sent=outcome.lines_sent)
            attempt.applied.append(spec.cfg_id)
            attempt.effects.append(spec.cfg_id)
            continue
        status = Status.UNKNOWN if outcome.error_code in _AMBIGUOUS else Status.FAILED
        persistence.finish_result(result, status, error_code=outcome.error_code, partial_effects=outcome.partial_effects, lines_sent=outcome.lines_sent)
        attempt.failed.append(spec.cfg_id)
        if outcome.partial_effects:
            attempt.effects.append(spec.cfg_id)
        return spec
    return None


# --- verification (Phase-15 postcheck, with bounded settling) ---------------------------------------------------------------
def _postcheck(plan, cfg_ids: list[str], *, actor: str, evidence_provider, sleep, clock) -> tuple[dict, object | None]:
    """-> (summary, persisted postcheck run).  Never raises and never returns PASS for missing evidence."""
    timeout, interval = settle_timeout_seconds(), settle_interval_seconds()
    deadline, attempts = clock() + timeout, 0
    evaluation, started = None, timezone.now()
    try:
        while True:
            evidence = evidence_provider(plan, cfg_ids) if evidence_provider is not None else None
            evaluation, _ = health_service.run_plan_postcheck(plan, actor=actor, evidence=evidence, cfg_ids=cfg_ids, persist=False)
            attempts += 1
            waiting = [r for r in evaluation.results if r.status != CheckStatus.PASS and r.status != CheckStatus.NOT_APPLICABLE
                       and (r.requirement in SETTLING_CHECKS or "UNAVAILABLE" in r.check_code)]
            if evaluation.result in POSTCHECK_PERMITS or not waiting or clock() >= deadline:
                break
            sleep(interval)
        run = health_service.record_postcheck_run(plan, evaluation, actor=actor, started_at=started, cfg_ids=cfg_ids)
    except Exception:  # noqa: BLE001 - a postcheck failure is INCOMPLETE evidence, never a pass
        return {"result": "INCOMPLETE", "error": "POSTCHECK_ERROR", "attempts": attempts, "timeout_seconds": timeout}, None
    summary = {
        "result": evaluation.result, "run_id": str(run.run_id), "cfg_ids": list(cfg_ids), "counts": evaluation.counts,
        "unverified": evaluation.summary.get("unverified", []),
        "settle": {"attempts": attempts, "timeout_seconds": timeout, "interval_seconds": interval,
                   "settled": evaluation.result in POSTCHECK_PERMITS or attempts == 1},
    }
    return summary, run


def _after_success(run, plan, attempt: _Attempt, mode, evidence_provider, sleep, clock) -> str:
    cfg_ids = [s.cfg_id for s in attempt.specs]
    attempt.postcheck, attempt.postcheck_run = _postcheck(plan, cfg_ids, actor=run.actor, evidence_provider=evidence_provider, sleep=sleep, clock=clock)
    if attempt.postcheck_run is not None:
        network_config_validation.record_live_validation(run, attempt.postcheck_run, actor=run.actor)
    verdict = attempt.postcheck["result"]
    if mode == PARTIAL_MODE:
        if verdict in POSTCHECK_PERMITS:
            return Outcome.UAT_SCOPE_APPLIED
        return Outcome.UAT_SCOPE_APPLIED_POSTCHECK_FAILED if verdict == "FAIL" else Outcome.UAT_SCOPE_APPLIED_UNVERIFIED
    if verdict in POSTCHECK_PERMITS:
        return Outcome.SUCCEEDED
    if not attempt.effects:  # everything was already satisfied: this run changed nothing, so there is nothing to compensate
        return Outcome.FAILED_NO_MUTATION
    complete = _compensate(run, attempt)
    return Outcome.POSTCHECK_FAILED_ROLLED_BACK if complete else Outcome.POSTCHECK_FAILED_COMPENSATION_INCOMPLETE


def _after_failure(run, plan, attempt: _Attempt, failed_spec, mode, evidence_provider, sleep, clock) -> str:
    if mode == PARTIAL_MODE:
        applied_ids = list(attempt.applied)
        if applied_ids:  # informational evidence of the preserved prefix; it never changes the outcome
            attempt.postcheck, attempt.postcheck_run = _postcheck(plan, applied_ids, actor=run.actor, evidence_provider=evidence_provider, sleep=sleep, clock=clock)
            if attempt.postcheck_run is not None:
                network_config_validation.record_live_validation(run, attempt.postcheck_run, actor=run.actor)
        return Outcome.FAILED_PARTIAL_APPLIED if attempt.effects else Outcome.FAILED_NO_MUTATION
    if not attempt.effects:
        return Outcome.FAILED_NO_MUTATION
    complete = _compensate(run, attempt)
    return Outcome.FAILED_ROLLED_BACK if complete else Outcome.FAILED_COMPENSATION_INCOMPLETE


# --- compensation (Complete only) ---------------------------------------------------------------------------------------------
def _compensate(run, attempt: _Attempt) -> bool:
    """Undo, in REVERSE order, exactly what this run may have changed; verify each.  True only when every undo is proven."""
    by_id = {s.cfg_id: s for s in attempt.specs}
    everything_restored = True
    for cfg_id in reversed(attempt.effects):
        spec, assessment = by_id[cfg_id], attempt.assessments[cfg_id]
        result = persistence.start_result(run, spec, Phase.COMPENSATE, previous_state=assessment.previous_state)
        try:
            outcome = attempt.executors[spec.device].compensate(spec, assessment)
        except Exception:  # noqa: BLE001
            outcome = CompensationOutcome(Status.COMPENSATION_UNVERIFIED, "INTERNAL_ERROR")
        persistence.finish_result(result, outcome.status, error_code=outcome.error_code, detail=outcome.detail)
        attempt.compensation.append((cfg_id, outcome.status))
        everything_restored = everything_restored and outcome.status == Status.COMPENSATED
        locking.heartbeat(run)
    return everything_restored


# --- the persisted report --------------------------------------------------------------------------------------------------
def _report(run, gate, attempt: _Attempt, outcome: str) -> dict:
    scope = gate.scope
    attempted = set(attempt.applied) | set(attempt.satisfied) | set(attempt.failed)
    unapplied = [s.cfg_id for s in attempt.specs if s.cfg_id not in attempted]
    compensated = [cfg for cfg, status in attempt.compensation if status == Status.COMPENSATED]
    not_compensated = [cfg for cfg, status in attempt.compensation if status != Status.COMPENSATED]
    comp_attempted = bool(attempt.compensation)
    report = {
        "report_schema_version": REPORT_SCHEMA_VERSION, "engine_version": ENGINE_VERSION, "mode": run.mode, "outcome": outcome,
        "scope": {**scope.to_dict(), "executed_configlets": sorted(attempted)},
        "state": {
            "applied": list(attempt.applied), "already_satisfied": list(attempt.satisfied), "failed": list(attempt.failed),
            "unapplied": unapplied, "out_of_scope": [c.cfg_id for c in scope.unselected], "compensated": compensated,
        },
        "compensation": {
            "attempted": comp_attempted,
            "status": "NOT_ATTEMPTED" if not comp_attempted else ("SUCCEEDED" if not not_compensated else "INCOMPLETE"),
            "not_compensated": not_compensated,
        },
        "postcheck": attempt.postcheck or {"result": "NOT_RUN"},
        "preparation": {
            "assessments": {cfg: {"action": a.action, "restorable": a.restorable, "reason": a.reason} for cfg, a in attempt.assessments.items()},
            "auto_address_recheck": attempt.auto_checked,
            "configlets": gate.configlet_rows,
        },
        "warnings": gate.warnings, "blockers": attempt.blockers, "limitations": list(LIMITATIONS), "persistence": "RUNNING_CONFIG_ONLY",
        # Phase 18: execution history references the EXACT pinned revision (and verification run) of every raw Configlet in scope
        "raw_configlets": [{"cfg_id": s.cfg_id, **(s.raw or {}), **({"integrity_error": s.integrity_error} if s.integrity_error else {})}
                           for s in attempt.specs if s.origin == "RAW"],
    }
    if attempt.error:
        report["error"] = attempt.error
    if attempt.management:                               # only when a device has registered management paths (else unchanged)
        report["preparation"]["management"] = dict(attempt.management)
    if run.mode == PARTIAL_MODE:
        report["uat"] = {"acknowledged": [name for name, _ in UAT_ACK_FIELDS], "through_cfg_id": scope.through_cfg_id}
    return report
