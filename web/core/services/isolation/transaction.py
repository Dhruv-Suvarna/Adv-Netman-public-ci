"""One governed configuration transaction on ONE device, recorded in the product's own Change records.

The isolation apply and the isolation release (production admission) are both this transaction; only their operations and
their checks differ.  The shape is the route-shield transition's (``route_shield.lifecycle``) on a single device:

    create_change   a Change carrying ``metadata.transition.kind`` -- the general engine refuses it
                    (``TRANSITION_CHANGE_NOT_GENERIC``): it runs only through this module, which holds the reverse path
    validate        an immutable ChangeValidationRun over exactly these operations (input hash = plan hash)
    build_plan      an immutable ChangePlan with one frozen Configlet per operation
    precheck        an OperationalCheckRun (CHANGE_PRECHECK) from the caller's fresh, read-only device facts
    approve         a READY_TO_DEPLOY lifecycle event bound to the plan hash and the precheck, by someone other than the requester
    execute         under the device lock: the caller's in-lock preflight, then per operation assess -> apply -> read back;
                    then the caller's final checks (the postcheck run); any failure compensates every applied operation
                    newest first, each digest-verified against the state it found.  What cannot be undone is reported.

Operations are ``ADD`` (a statement with its exact inverse and presence paths, executor object type ``isolation``) or
``REMOVE`` (an intentional removal whose restore path is the original lines, ``config_removal_delete``).  An observer hook
sees every step (evidence capture, and fault injection in the isolated acceptance run); an exception it raises takes the
reverse path like any other failure.

A lost session never strands an operation.  The step whose call to the device did not return (a dropped session, a
transport exception, any exception after the call began) is recorded as POSSIBLY applied -- its device effect is unknown --
and is compensated with the rest: compensation is idempotent (each inverse is accepted only by the digest or the presence
paths it must restore, and nothing is sent when they already hold).  When the session itself was lost, compensation runs on
ONE fresh session from the same executor factory -- the same transport, identity and host-key pin -- never on a fallback
path.  A step that loses the compensating session is retried once on another fresh session.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from dataclasses import dataclass, field

from django.db import transaction
from django.utils import timezone

from ... import models
from .. import change_service, lifecycle_service
from ..bundles import canonical
from ..execution import locking, persistence
from ..execution.codes import Outcome, Phase, Status, precheck_max_age_seconds
from ..execution.executors.base import APPLY, SKIP_SATISFIED, ApplyOutcome, ConfigletSpec, ExecutorError
from ..execution.scope import resolve_scope
from ..health.codes import ENGINE_VERSION as HEALTH_ENGINE_VERSION

ENGINE_VERSION = "isolation-transaction-1"
PLANNER_VERSION = "isolation-planner-1"
PLATFORM = "arista_ceos"
ADD_OBJECT, REMOVE_OBJECT = "isolation", "config_removal_delete"
# A session that failed under an executor call: the device effect of that call is unknown.  ``ExecutorError`` is the sanitized
# form; the rest is what a raw transport raises before an executor could reduce it (ConnectionResetError, EOFError, ...).
try:  # pragma: no branch - paramiko is a project dependency (netmiko)
    from paramiko import SSHException as _SSHException
except ImportError:  # pragma: no cover
    _SSHException = OSError
SESSION_ERRORS = (ExecutorError, OSError, EOFError, TimeoutError, _SSHException)
SESSION_CODES = frozenset({"TRANSPORT_ERROR", "TIMEOUT", "CONNECTION_FAILED", "PREVIOUS_STATE_UNAVAILABLE"})
MAX_RECONNECTS = 2
RESOLVED = (Outcome.BLOCKED, Outcome.FAILED_NO_MUTATION, Outcome.FAILED_ROLLED_BACK, Outcome.POSTCHECK_FAILED_ROLLED_BACK)


class TransactionError(Exception):
    """A step was requested out of order or without its prerequisites.  Nothing was recorded as passed."""

    def __init__(self, blockers: list):
        super().__init__(", ".join(b["code"] for b in blockers))
        self.blockers = blockers


def blocker(code: str, detail: str = "") -> dict:
    return {"code": code, "message": str(detail or code)[:300]}


def plan_hash(ops) -> str:
    return hashlib.sha256(json.dumps([dict(op) for op in ops], sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def kind_of(change) -> str:
    return str(((change.metadata or {}).get("transition") or {}).get("kind") or "")


def create_change(*, kind: str, device: str, title: str, description: str, actor: str, reference: dict) -> models.Change:
    change = change_service.create_change(
        title=title[:200], description=description[:2000], execution_mode=models.ExecutionMode.COMPLETE, created_by=actor,
        metadata={"transition": {"kind": kind, "schema": 1, **reference}})
    change_service.add_target(change=change, device_name=device)
    return change


def latest_validation(change):
    return change.validation_runs.order_by("-created_at", "-id").first()


def latest_plan(change):
    return change.plans.order_by("-created_at", "-id").first()


def latest_precheck(change, plan):
    return change.operational_runs.filter(mode=models.OperationalRunMode.CHANGE_PRECHECK, plan=plan).order_by("-created_at", "-id").first()


def validate(change, ops, *, actor: str, findings: list, source: dict) -> models.ChangeValidationRun:
    """Record one immutable validation of exactly ``ops``.  ``findings`` are the caller's (empty = PASS)."""
    status = models.ValidationRunStatus.BLOCKED if findings else models.ValidationRunStatus.PASS
    report = {"schema": 1, "kind": kind_of(change), "findings": list(findings), "operations": len(ops),
              "lines": [line for op in ops for line in op["lines"]]}
    with transaction.atomic():
        run = models.ChangeValidationRun.objects.create(
            change=change, status=status, engine_version=ENGINE_VERSION, input_hash=plan_hash(ops),
            source_hash=canonical.text_hash(canonical.canonical_json(source)), created_by=actor,
            summary={"status": status, "findings": len(findings)}, report=report, source_provenance={"device": source})
        change.validation_state = models.ValidationState.FAILED if findings else models.ValidationState.PASSED
        change.save(update_fields=["validation_state", "updated_at"])
        models.AuditEvent.objects.create(
            event_type=models.AuditEventType.VALIDATION_RECORDED, change=change, object_type="ChangeValidationRun", object_id=str(run.run_id),
            actor=actor, summary=f"{change.change_id}: {kind_of(change)} validation {status}"[:255],
            metadata={"status": status, "findings": len(findings)})
    return run


def _configlet_fields(op: dict, sequence: int, device: str) -> dict:
    tag = {"key": op["key"], "kind": op["kind"]}
    metadata, origin = {"transition": tag}, models.ConfigletOrigin.STRUCTURED
    if op["kind"] == "ADD":
        # an ADD names its executor object type when it is not an isolation statement (V2 Phase 9: dhcp_relay_option82); every such
        # type is a declared-inverse configuration block of the executor (exact inverse + presence paths)
        object_type = op.get("object_type", ADD_OBJECT)
        expected = {"present_paths": list(op["paths"]), "inverse_lines": list(op["inverse"])}
        operation = models.ConfigletOperationType.CREATE_DEFINE
    else:
        object_type, expected = REMOVE_OBJECT, {"absent_paths": list(op["paths"])}
        origin, operation = models.ConfigletOrigin.REMOVAL, models.ConfigletOperationType.REMOVE_DELETE
        metadata["removal"] = {"item": op["key"], "absent_paths": list(op["paths"]), "restorable": True, "restore_lines": list(op["inverse"])}
    return dict(
        cfg_id=f"CFG-{sequence:03d}", sequence=sequence, target_device=device,
        feature_namespace=op.get("namespace", models.FeatureNamespace.SECURITY), description=f"{op['description']}"[:400], operation_type=operation,
        deployment_priority=op.get("priority", models.DeploymentPriority.TRAFFIC_AFFECTING_POLICY), rendered_config="\n".join(op["lines"]),
        rollback_config="\n".join(op["inverse"]),
        desired_state_ref={"source": {"platform": op.get("platform", PLATFORM), "object_type": object_type}, "transition": tag},
        verification_spec={"requirements": [{"expected": expected}]}, metadata=metadata, origin=origin)


def build_plan(change, ops, *, actor: str, device: str, summary: dict) -> models.ChangePlan:
    """One immutable plan from the latest PASS validation of exactly ``ops``; building again returns the same plan."""
    validation = latest_validation(change)
    if validation is None or validation.status != models.ValidationRunStatus.PASS or validation.input_hash != plan_hash(ops):
        raise TransactionError([blocker("VALIDATION_NOT_CURRENT", "no current passing validation of these operations")])
    existing = models.ChangePlan.objects.filter(validation_run=validation, planner_version=PLANNER_VERSION).first()
    if existing is not None:
        return existing
    with transaction.atomic():
        plan = models.ChangePlan.objects.create(
            change=change, validation_run=validation, planner_version=PLANNER_VERSION, validation_input_hash=validation.input_hash,
            validation_source_hash=validation.source_hash, validation_engine_version=validation.engine_version, plan_hash=plan_hash(ops),
            created_by=actor, summary={"kind": kind_of(change), "operations": len(ops), "device": device, **summary},
            warnings=["The upstream's running configuration changes; the startup configuration is not written by this transaction."],
            provenance={"design": "docs/V2_TRUSTED_ISOLATION_COMMISSIONING.md",
                        "validation": {"run_id": str(validation.run_id), "input_hash": validation.input_hash}})
        for sequence, op in enumerate(ops, 1):
            models.Configlet.objects.create(change=change, plan=plan, **_configlet_fields(op, sequence, device))
        models.AuditEvent.objects.create(
            event_type=models.AuditEventType.PLAN_BUILT, change=change, object_type="ChangePlan", object_id=str(plan.plan_id), actor=actor,
            summary=f"{change.change_id}: {kind_of(change)} plan built ({len(ops)} operations)"[:255], metadata={"plan_hash": plan.plan_hash})
    return plan


def plan_problems(plan, ops, device: str) -> list[dict]:
    """The frozen plan rows are still exactly ``ops``."""
    rows = list(plan.configlets.order_by("sequence"))
    if plan.plan_hash != plan_hash(ops) or len(rows) != len(ops):
        return [blocker("PLAN_STALE", "the plan no longer matches the policy's operations")]
    for sequence, (row, op) in enumerate(zip(rows, ops), 1):
        wanted = _configlet_fields(op, sequence, device)
        if any(getattr(row, name) != wanted[name] for name in ("cfg_id", "target_device", "rendered_config", "rollback_config",
                                                                 "desired_state_ref", "verification_spec", "origin", "operation_type")):
            return [blocker("PLAN_STALE", f"{row.cfg_id} differs from the policy")]
    return []


def record_precheck(change, plan, *, actor: str, blockers: list, facts: dict, started=None) -> models.OperationalCheckRun:
    status = "BLOCKED" if blockers else "PASS"
    with transaction.atomic():
        run = models.OperationalCheckRun.objects.create(
            mode=models.OperationalRunMode.CHANGE_PRECHECK, status=status, change=change, plan=plan, engine_version=HEALTH_ENGINE_VERSION,
            started_at=started or timezone.now(), finished_at=timezone.now(), created_by=actor,
            summary={"status": status, "blockers": [b["code"] for b in blockers]},
            report={"schema": 1, "engine": ENGINE_VERSION, "blockers": blockers, **facts})
        models.AuditEvent.objects.create(
            event_type=models.AuditEventType.PRECHECK_RECORDED, change=change, object_type="OperationalCheckRun", object_id=str(run.run_id),
            actor=actor, summary=f"{change.change_id}: {kind_of(change)} precheck {status}"[:255],
            metadata={"status": status, "blockers": [b["code"] for b in blockers][:10]})
    return run


def approval(change) -> dict:
    event = change.lifecycle_events.filter(to_state=models.ChangeLifecycleState.READY_TO_DEPLOY).order_by("-occurred_at", "-id").first()
    return dict((event.metadata or {}).get("approval") or {}) if event is not None else {}


def approve(change, ops, *, actor: str, requested_by: str, confirmation: str, device: str, extra: dict | None = None):
    """Approval of exactly this plan and its latest passing precheck by an operator other than the requester."""
    plan = latest_plan(change)
    blockers = []
    precheck = None
    if plan is None:
        blockers.append(blocker("PLAN_MISSING", "build the plan first"))
    else:
        blockers += plan_problems(plan, ops, device)
        precheck = latest_precheck(change, plan)
        if precheck is None or precheck.status != "PASS":
            blockers.append(blocker("PRECHECK_NOT_PASSED", "the latest precheck of this plan did not pass"))
        if confirmation != plan.plan_hash:
            blockers.append(blocker("CONFIRMATION_MISMATCH", "approve the plan hash shown"))
    if not actor or actor == requested_by or actor == change.created_by:
        blockers.append(blocker("SELF_APPROVAL", "the requester cannot approve"))
    if change.lifecycle_state not in (models.ChangeLifecycleState.DRAFT, models.ChangeLifecycleState.READY_TO_DEPLOY):
        blockers.append(blocker("CHANGE_LIFECYCLE_NOT_EXECUTABLE", change.lifecycle_state))
    if blockers:
        raise TransactionError(blockers)
    return lifecycle_service.record_lifecycle_event(
        change=change, to_state=models.ChangeLifecycleState.READY_TO_DEPLOY, actor=actor, reason=f"{kind_of(change)} approved",
        metadata={"approval": {"plan_id": str(plan.plan_id), "plan_hash": plan.plan_hash, "precheck_run": str(precheck.run_id),
                               "approved_by": actor, "requested_by": requested_by, **(extra or {})}})


# V2 Phase 7 shares the guard; V2 Phase 9 DHCP relay option 82 (``ztp.relay_option82``) too
GOVERNED_KINDS = ("TRUSTED_ISOLATION", "DEVICE_DECOMMISSION", "DEVICE_RESTORE", "DHCP_RELAY_OPTION82")


RECONCILED_MARK = "BASELINE"


def reconciled(run) -> bool:
    """A run left unresolved whose device was later PROVEN back on the state it started from (``mark_reconciled``).  A finished run
    is immutable; the proof is its own append-only audit record."""
    return models.AuditEvent.objects.filter(object_type="ChangeExecutionRun", object_id=str(run.run_id),
                                            metadata__reconciliation=RECONCILED_MARK).exists()


def mark_reconciled(change, *, actor: str, digest: str, basis: str) -> list[str]:
    """Record, for every finished unresolved run of ``change``, that its device was proven back on the baseline digest (by a read-only
    reconcile or a governed recovery).  The run itself -- outcome, report, results -- is history and is never rewritten.  -> run ids"""
    marked = []
    for run in change.execution_runs.exclude(outcome__in=[*RESOLVED, Outcome.SUCCEEDED]).exclude(state=models.ExecutionRunState.RUNNING):
        if reconciled(run):
            continue
        models.AuditEvent.objects.create(
            event_type=models.AuditEventType.DEPLOYMENT_RECORDED, change=change, object_type="ChangeExecutionRun", object_id=str(run.run_id),
            actor=actor[:150], summary=f"{change.change_id}: run {str(run.run_id)[:8]} reconciled to its baseline ({basis})"[:255],
            metadata={"run_id": str(run.run_id), "outcome": run.outcome, "reconciliation": RECONCILED_MARK, "digest": digest,
                      "basis": basis[:120]})
        marked.append(str(run.run_id))
    return marked


def unresolved_runs(device: str) -> list[str]:
    """Governed transactions (isolation, decommission, restore) on ``device`` that are running, interrupted or not proven restored."""
    runs = models.ChangeExecutionRun.objects.exclude(outcome__in=[*RESOLVED, Outcome.SUCCEEDED]).select_related("change")
    return sorted({run.change.change_id for run in runs
                   if kind_of(run.change).startswith(GOVERNED_KINDS) and device in (run.devices or []) and not reconciled(run)})


def gate(change, ops, *, device: str, confirmation: str, now, resolves: str = "") -> tuple[object, object, list[dict]]:
    """Everything that must hold before the device lock is taken.  -> (plan, precheck, blockers).  ``resolves``: the change id of the
    one unresolved transaction this Change exists to recover (a decommission recovery); every other one still blocks."""
    plan = latest_plan(change)
    if plan is None:
        return None, None, [blocker("PLAN_MISSING", "build the plan first")]
    blockers = plan_problems(plan, ops, device)
    precheck = latest_precheck(change, plan)
    approved = approval(change)
    if change.lifecycle_state != models.ChangeLifecycleState.READY_TO_DEPLOY or approved.get("plan_hash") != plan.plan_hash:
        blockers.append(blocker("NOT_APPROVED", "the Change is not approved for this plan"))
    if precheck is None or precheck.status != "PASS" or approved.get("precheck_run") != str(precheck.run_id):
        blockers.append(blocker("PRECHECK_NOT_PASSED", "the approved precheck is not the latest passing precheck of this plan"))
    elif (now - precheck.finished_at).total_seconds() > precheck_max_age_seconds():
        blockers.append(blocker("PRECHECK_STALE", "the precheck is too old; run it and approve again"))
    if confirmation != plan.plan_hash:
        blockers.append(blocker("CONFIRMATION_MISMATCH", "confirm the plan hash to execute"))
    if any(not reconciled(run) for run in change.execution_runs.exclude(outcome__in=RESOLVED)):
        blockers.append(blocker("PRIOR_RUN_UNRESOLVED", "an earlier run of this Change succeeded, was interrupted or was not restored"))
    others = [c for c in unresolved_runs(device) if c not in (change.change_id, resolves)]
    if others:
        blockers.append(blocker("PRIOR_TRANSITION_UNRESOLVED", f"{others[0]} left the device unresolved"))
    return plan, precheck, blockers


# ------------------------------------------------------------------------------------------------------------- execution
@dataclass
class Result:
    run: object
    outcome: str
    blockers: list = field(default_factory=list)
    report: dict = field(default_factory=dict)

    @property
    def succeeded(self) -> bool:
        return self.outcome == Outcome.SUCCEEDED

    @property
    def restored(self) -> bool:
        return self.outcome in RESOLVED


def execute(change, ops, *, actor: str, confirmation: str, device: dict, executor_factory, preflight=None, final=None,
            observer=None, resolves: str = "") -> Result:
    """Run the approved plan under the device lock.

    ``preflight(executor) -> blockers``  read-only, in the lock, before the first write (the basis must still be current);
    ``final(executor) -> failed rows``   the postcheck after the last operation (empty = pass);
    ``observer(event, key)``             called before / after each operation and around compensation; may raise."""
    now = timezone.now()
    locking.reap_expired(now)
    name = device["name"]
    mode = models.ExecutionMode.COMPLETE
    plan, precheck, blockers = gate(change, ops, device=name, confirmation=confirmation, now=now, resolves=resolves)
    if blockers:
        run = persistence.record_blocked(change, plan, precheck_run=precheck, mode=mode, actor=actor, blockers=blockers)
        return Result(run, Outcome.BLOCKED, blockers)
    scope, scope_blockers = resolve_scope(plan, mode)
    if scope_blockers:
        run = persistence.record_blocked(change, plan, precheck_run=precheck, mode=mode, actor=actor, blockers=scope_blockers)
        return Result(run, Outcome.BLOCKED, scope_blockers)
    try:
        run = locking.acquire(change=change, plan=plan, precheck_run=precheck, mode=mode, actor=actor, scope=scope, devices=[name], now=now)
    except locking.LockRefused as exc:
        refusal = [blocker(exc.code, str(exc.details))]
        run = persistence.record_blocked(change, plan, precheck_run=precheck, mode=mode, actor=actor, blockers=refusal, scope=scope)
        return Result(run, Outcome.BLOCKED, refusal)
    attempt = _Attempt(run=run, change=change, plan=plan, ops=list(ops), specs=[ConfigletSpec.from_configlet(row) for row in scope.selected],
                       actor=actor, executor=executor_factory(device), preflight=preflight, final=final, observer=observer,
                       executor_factory=executor_factory, device=device)
    outcome = Outcome.INTERRUPTED
    try:
        outcome = attempt.drive()
    except Exception as exc:  # pylint: disable=broad-exception-caught  # noqa: BLE001 - never a stuck lock or a false success
        attempt.fail("INTERNAL_ERROR", type(exc).__name__)
        outcome = Outcome.INTERRUPTED
    try:
        report = attempt.report(outcome)
    finally:
        attempt.close()
    run = persistence.finalize_run(run, outcome=outcome, report=report, postcheck_run=attempt.postcheck_run, now=timezone.now())
    state = {Outcome.SUCCEEDED: models.ChangeLifecycleState.DEPLOYED, Outcome.FAILED_ROLLED_BACK: models.ChangeLifecycleState.ROLLED_BACK,
             Outcome.POSTCHECK_FAILED_ROLLED_BACK: models.ChangeLifecycleState.ROLLED_BACK}.get(outcome)
    if state is None and outcome not in (Outcome.BLOCKED, Outcome.FAILED_NO_MUTATION):
        state = models.ChangeLifecycleState.FAILED
    if state is not None:
        lifecycle_service.record_lifecycle_event(change=change, to_state=state, actor=actor, reason=f"{kind_of(change)} execution {outcome}",
                                                 metadata={"run_id": str(run.run_id), "outcome": outcome})
    return Result(run, outcome, attempt.blockers, report)


@dataclass
class _Attempt:
    run: object
    change: object
    plan: object
    ops: list
    specs: list
    actor: str
    executor: object
    preflight: Callable | None = None
    final: Callable | None = None
    observer: Callable | None = None
    executor_factory: Callable | None = None              # a fresh session after a lost one (same transport and identity)
    device: dict = field(default_factory=dict)
    applied: list = field(default_factory=list)          # (op, spec, assessment, digest before) in apply order
    steps: list = field(default_factory=list)
    blockers: list = field(default_factory=list)
    compensation: list = field(default_factory=list)
    failure: dict = field(default_factory=dict)
    postcheck_run: object = None
    baseline: str = ""
    final_digest: str = ""
    restored: bool | None = None
    connected: bool = False
    session_lost: bool = False
    reconnects: int = 0
    _pending: tuple | None = None                         # the operation whose device call has begun and not returned
    _failed: list = field(default_factory=list)

    def note(self, step: str, status: str, **facts) -> None:
        self.steps.append({"step": step, "at": timezone.now().isoformat(), "status": status, **facts})

    def notify(self, event: str, key: str = "") -> None:
        if self.observer is not None:
            self.observer(event, key)

    def fail(self, code: str, detail: str = "", key: str = "") -> None:
        if not self.failure:
            self.failure = {"code": code, "detail": str(detail)[:300], "operation": key}
            self.blockers.append(blocker(code, detail))
            self.note("abort", code, operation=key, detail=str(detail)[:300])

    def close(self) -> None:
        if self.connected:
            try:
                self.executor.close()
            except Exception:  # pylint: disable=broad-exception-caught  # noqa: BLE001 - closing a session never masks the outcome
                pass
            self.connected = False

    def reconnect(self, reason: str) -> bool:
        """Replace a lost session with ONE fresh session from the run's own executor factory.  -> usable"""
        if self.executor_factory is None or self.reconnects >= MAX_RECONNECTS:
            self.note("reconnect", "REFUSED", reason=reason, reconnects=self.reconnects)
            return False
        self.reconnects += 1
        self.close()
        try:
            self.executor = self.executor_factory(self.device)
            self.executor.connect()
        except SESSION_ERRORS as exc:
            self.note("reconnect", "FAILED", reason=reason, error=getattr(exc, "code", type(exc).__name__))
            return False
        self.connected, self.session_lost = True, False
        self.note("reconnect", "PASS", reason=reason, reconnects=self.reconnects)
        return True

    def drive(self) -> str:
        try:
            self.executor.connect()
            self.connected = True
            found = list(self.preflight(self.executor)) if self.preflight is not None else []
            self.baseline = self.executor.config_state_digest()
        except ExecutorError as exc:
            found = [blocker("EVIDENCE_UNAVAILABLE", exc.code)]
        self.note("preflight", "BLOCKED" if found else "PASS", blockers=[b["code"] for b in found], baseline=self.baseline)
        if found:
            self.blockers = found
            return Outcome.BLOCKED
        try:
            for op, spec in zip(self.ops, self.specs):
                if not self.apply(op, spec):
                    break
            if not self.failure:
                self.postcheck()
        except Exception as exc:  # pylint: disable=broad-exception-caught  # noqa: BLE001 - a hook or engine failure after the first write takes the reverse path
            self.fail("SESSION_LOST" if isinstance(exc, SESSION_ERRORS) else "INTERNAL_ERROR", type(exc).__name__)
            if isinstance(exc, SESSION_ERRORS):
                self.session_lost = True
        if self._pending is not None:                       # the device call never returned: its effect is unknown
            op, spec, assessment, before, row = self._pending
            self._pending = None
            self.applied.append((op, spec, assessment, before, ""))
            self._failed.append(spec.cfg_id)
            persistence.finish_result(row, Status.FAILED, error_code="TRANSPORT_ERROR", partial_effects=True, lines_sent=len(spec.lines))
            self.note(op["key"], "OUTCOME_UNKNOWN", cfg_id=spec.cfg_id)
        attempted = {entry[1].cfg_id for entry in self.applied} | set(self._failed)
        persistence.add_not_attempted(self.run, [spec for spec in self.specs if spec.cfg_id not in attempted])
        if not self.failure:
            return Outcome.SUCCEEDED
        if not self.applied:
            return Outcome.FAILED_NO_MUTATION
        self.compensate()
        after_postcheck = self.failure.get("code") == "POSTCHECK_FAILED"
        if self.restored:
            return Outcome.POSTCHECK_FAILED_ROLLED_BACK if after_postcheck else Outcome.FAILED_ROLLED_BACK
        return Outcome.POSTCHECK_FAILED_COMPENSATION_INCOMPLETE if after_postcheck else Outcome.FAILED_COMPENSATION_INCOMPLETE

    def apply(self, op: dict, spec) -> bool:
        self.notify("before", op["key"])
        before = self.executor.config_state_digest()
        expected = self.applied[-1][4] if self.applied else self.baseline
        if before != expected:
            self.fail("OUT_OF_BAND_CHANGE", "the device changed between two steps of this run", op["key"])
            return False
        assessment = self.executor.assess(spec)
        if assessment.action != APPLY or not assessment.restorable:
            code = "ALREADY_PRESENT" if assessment.action == SKIP_SATISFIED else (assessment.reason or "COMPENSATION_NOT_PROVABLE")
            self.fail(code, f"{op['key']}: {assessment.action}", op["key"])
            return False
        row = persistence.start_result(self.run, spec, Phase.APPLY, previous_state=assessment.previous_state)
        self._pending = (op, spec, assessment, before, row)
        try:
            outcome = self.executor.apply(spec, assessment)
        except SESSION_ERRORS as exc:
            outcome = ApplyOutcome(False, getattr(exc, "code", "TRANSPORT_ERROR"), partial_effects=True, lines_sent=len(spec.lines))
        self._pending = None
        if outcome.error_code in SESSION_CODES:
            self.session_lost = True
        if not outcome.ok:
            if outcome.partial_effects:
                self.applied.append((op, spec, assessment, before, ""))
            persistence.finish_result(row, Status.FAILED, error_code=outcome.error_code, partial_effects=outcome.partial_effects,
                                      lines_sent=outcome.lines_sent)
            self._failed.append(spec.cfg_id)
            self.fail("APPLY_FAILED", f"{op['key']}: {outcome.error_code}", op["key"])
            return False
        read_back = self.executor.assess(spec).action
        after = self.executor.config_state_digest()
        self.applied.append((op, spec, assessment, before, after))
        persistence.finish_result(row, Status.APPLIED, lines_sent=outcome.lines_sent, detail={"operation": op["key"], "read_back": read_back})
        self.note(op["key"], "APPLIED", cfg_id=spec.cfg_id, read_back=read_back, digest=after)
        if read_back != SKIP_SATISFIED:
            self.fail("READ_BACK_MISMATCH", f"{op['key']}: the device does not report the operation as in place", op["key"])
            return False
        self.notify("after", op["key"])
        return True

    def postcheck(self) -> None:
        started = timezone.now()
        self.notify("before", "postcheck")
        failed = list(self.final(self.executor)) if self.final is not None else []
        self.final_digest = self.executor.config_state_digest()
        status = "FAIL" if failed else "PASS"
        self.postcheck_run = models.OperationalCheckRun.objects.create(
            mode=models.OperationalRunMode.CHANGE_POSTCHECK, status=status, change=self.change, plan=self.plan,
            engine_version=HEALTH_ENGINE_VERSION, started_at=started, finished_at=timezone.now(), created_by=self.actor,
            summary={"status": status, "failed": len(failed)}, report={"schema": 1, "engine": ENGINE_VERSION, "failed": failed[:40],
                                                                       "final_digest": self.final_digest})
        self.note("postcheck", status, failed=failed[:10])
        if failed:
            self.fail("POSTCHECK_FAILED", f"{failed[0].get('check', '')}: {failed[0].get('detail', '')}")

    def compensate(self) -> None:
        """Undo, newest first, exactly what this run applied; each step must restore the digest it found."""
        complete = True
        self.notify("before", "compensate")
        pending = list(reversed(self.applied))
        if self.session_lost and not self.reconnect("lost during apply"):
            # no session to compensate through: nothing is sent, nothing is proven; every applied step stays NOT_COMPENSATED
            self.compensation += [{"cfg_id": spec.cfg_id, "operation": op["key"], "status": "NOT_COMPENSATED", "error": "SESSION_UNAVAILABLE"}
                                  for op, spec, _a, _b, _c in pending]
            complete, pending = False, []
        for op, spec, assessment, before, _after in pending:
            entry = {"cfg_id": spec.cfg_id, "operation": op["key"]}
            self._step_hook(op["key"])
            row = persistence.start_result(self.run, spec, Phase.COMPENSATE, previous_state=assessment.previous_state)
            attempts = 0
            while True:
                attempts += 1
                status, error, detail = self._compensate_step(spec, assessment, before)
                if status == Status.COMPENSATED or attempts > 1 or not self.session_lost or not self.reconnect(f"lost compensating {op['key']}"):
                    break
            entry.update(status=status, error=error, attempts=attempts, **({"session": "fresh"} if self.reconnects else {}))
            persistence.finish_result(row, status if status != "NOT_COMPENSATED" else Status.COMPENSATION_UNVERIFIED, error_code=error,
                                      detail={"operation": op["key"], "attempts": attempts, **detail})
            self.compensation.append(entry)
            if entry["status"] != Status.COMPENSATED:
                complete = False
                break
        try:
            restored_digest = self.executor.config_state_digest()
        except SESSION_ERRORS:                               # an unreadable device is never proven restored
            restored_digest = ""
        self.restored = complete and restored_digest == self.baseline
        self.note("restore", "RESTORED" if self.restored else "RESTORE_INCOMPLETE", digest=restored_digest, baseline=self.baseline)
        self.notify("after", "compensate")

    def _step_hook(self, key: str) -> None:
        """``observer("before", "compensate:<key>")`` before each undo (a caller may wait for the network there).  The hook is
        the caller's code: whatever it raises is recorded and the undo still runs -- compensation is never skipped by a hook."""
        try:
            self.notify("before", f"compensate:{key}")
        except Exception as exc:  # pylint: disable=broad-exception-caught  # noqa: BLE001 - arbitrary caller hook; the undo must still run
            self.note("compensate-hook", "FAILED", operation=key, error=type(exc).__name__)

    def _compensate_step(self, spec, assessment, before: str) -> tuple[str, str, dict]:
        """One compensation attempt on the current session.  -> (status, error code, executor detail)"""
        try:
            outcome = self.executor.compensate(spec, assessment)
            status, error, detail = outcome.status, outcome.error_code, dict(outcome.detail or {})
            if status == Status.COMPENSATED and self.executor.config_state_digest() != before:
                status, error = Status.COMPENSATION_FAILED, "STATE_NOT_RESTORED"
        except SESSION_ERRORS as exc:
            status, error, detail = "NOT_COMPENSATED", getattr(exc, "code", type(exc).__name__), {}
        if error in SESSION_CODES or status == "NOT_COMPENSATED":
            self.session_lost = True
        return status, error, detail

    def report(self, outcome: str) -> dict:
        applied = [entry[1].cfg_id for entry in self.applied]
        compensated = [e["cfg_id"] for e in self.compensation if e.get("status") == Status.COMPENSATED]
        return {
            "report_schema_version": 1, "engine_version": ENGINE_VERSION, "mode": models.ExecutionMode.COMPLETE, "outcome": outcome,
            "transition": {"kind": kind_of(self.change)}, "blockers": self.blockers, "failure": self.failure,
            "state": {"applied": applied, "failed": list(self._failed), "compensated": compensated,
                      "unapplied": [spec.cfg_id for spec in self.specs if spec.cfg_id not in applied]},
            "compensation": {"attempted": bool(self.compensation),
                             "status": "NOT_ATTEMPTED" if not self.compensation else "COMPENSATED" if self.restored else "INCOMPLETE",
                             "not_compensated": [e["cfg_id"] for e in self.compensation if e.get("status") != Status.COMPENSATED],
                             "steps": self.compensation},
            "postcheck": {"result": self.postcheck_run.status if self.postcheck_run is not None else "NOT_RUN"},
            "baseline_digest": self.baseline, "final_digest": self.final_digest, "restored": self.restored, "steps": self.steps[-200:],
            "session": {"lost": self.session_lost, "reconnects": self.reconnects},
        }
