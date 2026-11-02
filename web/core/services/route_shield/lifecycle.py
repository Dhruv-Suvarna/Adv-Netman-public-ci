"""The baseline migration as ONE auditable NMAS transaction across S1, S2, R1, R2, R3 and R4.

    create_change      a Change carrying the transition kind (nothing else: the content is the approved design)
    validate_change    an immutable ChangeValidationRun: the plan is checked against the approved design and the inventory
    build_plan         an immutable ChangePlan with one frozen Configlet per operation, PERMANENT or TEMPORARY
    run_precheck       an OperationalCheckRun (CHANGE_PRECHECK) from fresh reads of all six devices
    approve            explicit confirmation and acknowledgements, bound to that plan and that precheck
    execute            the service entry point: refuses unless the transition is READY (``readiness``)

Execution holds one lock on all six devices and walks the plan in order: every operation is assessed, applied, read
back and verified, production probes are read after each one, and any failure walks the same operations backwards, each
by its exact inverse.  The temporary R3/R4 covers are the first thing installed and the last thing removed in both
directions; a run is never reported as restored while one of them, or any shield, remains.

Results are the product's own records (ChangeExecutionRun, ConfigletExecutionResult, the postcheck run, audit and
lifecycle events), so the migration is visible wherever a Change is.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field

from django.db import transaction
from django.utils import timezone

from ... import models
from .. import change_service, lifecycle_service
from ..bundles import canonical
from ..execution import locking, persistence
from ..execution.codes import Outcome, Phase, Status, precheck_max_age_seconds
from ..execution.executors.base import APPLY, SKIP_SATISFIED, ConfigletSpec, ExecutorError
from ..execution.scope import resolve_scope
from ..health.codes import ENGINE_VERSION as HEALTH_ENGINE_VERSION
from . import core_cover, gates, lab, migration, readiness
from .migration import ADD, COVER_INSTALL, COVER_REMOVE, PERMANENT, REMOVE, TEMPORARY

ENGINE_VERSION = "route-shield-lifecycle-3"
ACKNOWLEDGEMENTS = (
    ("window_authorized", "A production maintenance window for this migration is authorized."),
    ("core_kernel_routes", "The migration temporarily writes three kernel routes on each of R3 and R4 and removes them at the end."),
    ("access_routing_configuration", "The migration permanently changes routing configuration on R1, R2, S1 and S2."),
    ("host_quiet", "The host is quiet: no disposable lab, no test run, and only the dedicated migration probes are polling."),
)
CEOS_PLATFORM, CEOS_ADD, CEOS_REMOVE = "arista_ceos", "route_shield", "config_removal_delete"
EXPECTED_PLATFORMS = {"access": "ceos", "core": "linux"}
READINESS_OF = {migration.KIND: readiness.STATIC_IPV6_TO_ISIS, migration.REVERT_KIND: readiness.ISIS_TO_STATIC_IPV6_REVERT}
PERSISTENCE_COMMAND = "copy running-config startup-config"
RESOLVED_OUTCOMES = (Outcome.BLOCKED, Outcome.FAILED_NO_MUTATION, Outcome.FAILED_ROLLED_BACK, Outcome.POSTCHECK_FAILED_ROLLED_BACK)


def plan_max_age_seconds() -> float:
    """How old the validated plan may be when it is executed: a plan from another day is validated and built again."""
    from django.conf import settings

    return float(getattr(settings, "TRANSITION_PLAN_MAX_AGE_SECONDS", 12 * 3600))


def _blocker(code: str, detail: str = "", device: str = "") -> dict:
    return {"code": code, "message": detail or code, "remediation": "See docs/V2_LOSSLESS_ROUTE_SHIELD.md.", **({"device": device} if device else {})}


class LifecycleError(Exception):
    """A lifecycle step was requested out of order.  Carries the blockers; nothing was recorded as passed."""

    def __init__(self, blockers: list):
        super().__init__(", ".join(b["code"] for b in blockers))
        self.blockers = blockers


@dataclass
class Environment:
    """Everything a run needs from outside.  A missing probe source or host gate is a refusal, never a default pass."""

    devices: dict                                  # name -> inventory device dict, for exactly the six devices
    executor_factory: object                       # (device dict) -> an unconnected executor
    read: object                                   # (device dict) -> health DeviceEvidence, fresh
    probes: object = None                          # .healthy() -> (ok, detail);  .lost() -> cumulative lost production probes
    host_gate: object = None                       # () -> (ok, facts)
    observer: object = None                        # (event, operation key) -> None; evidence hooks.  An exception aborts the run
    executors: dict = field(default_factory=dict)
    sleep: object = time.sleep
    clock: object = time.monotonic
    poll_seconds: float = 2.0
    last_change_at: float | None = None
    baseline: dict = field(default_factory=dict)   # what the in-lock precheck recorded: digests and core adjacencies

    def connect(self, names) -> None:
        for name in names:
            if name not in self.executors:
                executor = self.executor_factory(self.devices[name])  # pylint: disable=not-callable  # injected callable (dataclass field annotated object)
                executor.connect()
                self.executors[name] = executor

    def close(self) -> None:
        for executor in self.executors.values():
            try:
                executor.close()
            except Exception:  # noqa: BLE001
                pass
        self.executors.clear()

    def notify(self, event: str, key: str = "") -> None:
        if self.observer is not None:
            self.observer(event, key)  # pylint: disable=not-callable  # injected callable (dataclass field annotated object)


# ----------------------------------------------------------------------------------------------------------- change, validation
def kind_of(change) -> str:
    return str(((change.metadata or {}).get("transition") or {}).get("kind") or "")


def is_transition(change) -> bool:
    return bool(kind_of(change))


def _ops(change, definition) -> list:
    return migration.operations(kind_of(change), definition)


def create_change(*, actor: str, definition: migration.Definition = migration.PRODUCTION):
    change = change_service.create_change(
        title="Baseline IPv6 access routing: static to IS-IS (lossless route shield)",
        description="One controlled transition across S1, S2, R1, R2 with temporary kernel covers on R3 and R4. "
                    "Design and evidence: docs/V2_LOSSLESS_ROUTE_SHIELD.md.",
        execution_mode=models.ExecutionMode.COMPLETE, created_by=actor,
        metadata={"transition": {"kind": migration.KIND, "definition": definition.name, "schema": 1}})
    for name in definition.devices:
        change_service.add_target(change=change, device_name=name)
    return change


def _require_transition(change, definition) -> None:
    meta = (change.metadata or {}).get("transition") or {}
    if meta.get("kind") not in migration.KINDS or meta.get("definition") != definition.name:
        raise LifecycleError([_blocker("NOT_THIS_TRANSITION", "the Change does not carry this transition definition")])


# ------------------------------------------------------------------------------------- revert of a COMPLETED migration
def _migration_run(run_id):
    import uuid

    try:
        return models.ChangeExecutionRun.objects.filter(run_id=uuid.UUID(str(run_id))).select_related("change").first()
    except (ValueError, TypeError, AttributeError):
        return None


def revert_basis(change) -> dict | None:
    """What a revert Change restores, read from the IMMUTABLE record of the migration run it names (never from the
    Change's own metadata): -> {"run", "premigration": digests before the migration, "migrated": digests it ended with}."""
    reference = ((change.metadata or {}).get("transition") or {}).get("reverts") or {}
    run = _migration_run(reference.get("run_id"))
    if run is None or kind_of(run.change) != migration.KIND or run.outcome != Outcome.SUCCEEDED:
        return None
    report = run.report or {}
    premigration, migrated = report.get("baseline_digests") or {}, (report.get("permanent_intent") or {}).get("baseline_digests") or {}
    if not premigration or not migrated or (report.get("persistence") or {}).get("status") != "VERIFIED":
        return None
    return {"run": run, "premigration": premigration, "migrated": migrated}


def create_revert(*, actor: str, migration_run_id: str, definition: migration.Definition = migration.PRODUCTION):
    """REVERT COMPLETED BASELINE MIGRATION: a Change of its own that names one SUCCEEDED migration run.  Creating it
    contacts no device and authorizes nothing; it is validated, planned, prechecked and approved like the migration."""
    run = _migration_run(migration_run_id)
    blockers = []
    if run is None or kind_of(run.change) != migration.KIND or run.outcome != Outcome.SUCCEEDED \
            or ((run.change.metadata or {}).get("transition") or {}).get("definition") != definition.name:
        blockers.append(_blocker("REVERT_SOURCE_NOT_SUCCEEDED", "name the run of a baseline migration that ended SUCCEEDED"))
    else:
        report = run.report or {}
        if not report.get("baseline_digests") or not (report.get("permanent_intent") or {}).get("baseline_digests") \
                or (report.get("persistence") or {}).get("status") != "VERIFIED":
            blockers.append(_blocker("REVERT_BASELINE_UNAVAILABLE", "the migration run did not record its pre-migration baseline and a verified final state"))
        for other in models.Change.objects.filter(metadata__transition__kind=migration.REVERT_KIND, metadata__transition__reverts__run_id=str(run.run_id)):
            if other.execution_runs.exclude(outcome__in=RESOLVED_OUTCOMES).exists():
                blockers.append(_blocker("REVERT_ALREADY_RUN", f"{other.change_id} already reverted this migration, or was interrupted"))
    if blockers:
        raise LifecycleError(blockers)
    change = change_service.create_change(
        title="Revert completed baseline migration: IS-IS back to static IPv6 (lossless route shield)",
        description=f"Operator-initiated revert of {run.change.change_id}, run {run.run_id}. The same shielding and the same "
                    "temporary R3/R4 covers, in the opposite order. Design: docs/V2_LOSSLESS_ROUTE_SHIELD.md, section 10.",
        execution_mode=models.ExecutionMode.COMPLETE, created_by=actor,
        metadata={"transition": {"kind": migration.REVERT_KIND, "definition": definition.name, "schema": 1,
                                 "reverts": {"change": run.change.change_id, "run_id": str(run.run_id)}}})
    for name in definition.devices:
        change_service.add_target(change=change, device_name=name)
    return change


def unresolved_transitions() -> list[str]:
    """Every transition run, of any Change, that is still running, was interrupted or was not fully restored.  Temporary
    state may still be on a device after one of these: nothing else runs until it is resolved."""
    runs = models.ChangeExecutionRun.objects.exclude(outcome__in=[*RESOLVED_OUTCOMES, Outcome.SUCCEEDED]).select_related("change")
    return sorted({f"{run.change.change_id}: {run.outcome or run.state}" for run in runs if is_transition(run.change)})


def _inventory_findings(definition, inventory: dict) -> list[dict]:
    found = []
    for name in definition.devices:
        device = inventory.get(name)
        wanted = EXPECTED_PLATFORMS["core" if name in definition.cores else "access"]
        if device is None:
            found.append({"code": "DEVICE_NOT_MANAGED", "detail": f"{name} is not a managed device"})
        elif device.get("platform") != wanted:
            found.append({"code": "PLATFORM_MISMATCH", "detail": f"{name} is {device.get('platform')}, the design expects {wanted}"})
    return found


def validate_change(change, *, actor: str, definition: migration.Definition = migration.PRODUCTION, inventory: dict | None = None):
    """Check the plan against the approved design and the managed inventory.  Always records one immutable run."""
    _require_transition(change, definition)
    if inventory is None:
        from ..health import inventory as managed

        inventory = managed.managed_devices()
    ops = _ops(change, definition)
    findings = [*migration.validate(definition, ops), *_inventory_findings(definition, inventory)]
    if kind_of(change) == migration.REVERT_KIND and revert_basis(change) is None:
        findings.append({"code": "REVERT_BASELINE_UNAVAILABLE", "detail": "the migration run this Change reverts is not a SUCCEEDED, persisted migration"})
    status = models.ValidationRunStatus.BLOCKED if findings else models.ValidationRunStatus.PASS
    source = {name: {key: (inventory.get(name) or {}).get(key, "") for key in ("platform", "container", "address")} for name in definition.devices}
    report = {
        "schema": 1, "kind": kind_of(change), "definition": definition.name, "findings": findings,
        "reverts": ((change.metadata or {}).get("transition") or {}).get("reverts"),
        "operations": len(ops), "permanent": sum(op.state == PERMANENT for op in ops), "temporary": sum(op.state == TEMPORARY for op in ops),
        "cover_inventory": [cover.to_expected() for cover in definition.covers],
        "temporary_lines": list(migration.temporary_lines(ops)), "readiness": readiness.READINESS.get(READINESS_OF[kind_of(change)]),
        "persistence": {"devices": list(definition.access_devices), "command": PERSISTENCE_COMMAND, "not_persisted": list(definition.cores)},
    }
    with transaction.atomic():
        run = models.ChangeValidationRun.objects.create(
            change=change, status=status, engine_version=ENGINE_VERSION, input_hash=migration.plan_hash(ops),
            source_hash=canonical.text_hash(canonical.canonical_json(source)), created_by=actor,
            summary={"status": status, "findings": len(findings)}, report=report, source_provenance={"inventory": source})
        change.validation_state = models.ValidationState.FAILED if findings else models.ValidationState.PASSED
        change.save(update_fields=["validation_state", "updated_at"])
        models.AuditEvent.objects.create(
            event_type=models.AuditEventType.VALIDATION_RECORDED, change=change, object_type="ChangeValidationRun", object_id=str(run.run_id),
            actor=actor, summary=f"{change.change_id}: transition validation {status}"[:255], metadata={"status": status, "findings": len(findings)})
    return run


# -------------------------------------------------------------------------------------------------------------------------- plan
def _operation_type(op) -> str:
    return models.ConfigletOperationType.CREATE_DEFINE if op.action in (ADD, COVER_INSTALL) else models.ConfigletOperationType.REMOVE_DELETE


def _configlet_fields(op, sequence: int) -> dict:
    """The frozen plan row of one operation: everything ``ConfigletSpec.from_configlet`` needs, and what kind of state it is."""
    tag = {"key": op.key, "stage": op.stage, "state": op.state, "action": op.action}
    metadata, origin = {"transition": tag}, models.ConfigletOrigin.STRUCTURED
    if op.cover is not None:
        platform, object_type, expected = core_cover.PLATFORM, core_cover.OBJECT_TYPE, op.cover.to_expected()
    elif op.action == ADD:
        platform, object_type, expected = CEOS_PLATFORM, CEOS_ADD, {"present_paths": list(op.paths), "inverse_lines": list(op.inverse)}
    else:
        platform, object_type, expected = CEOS_PLATFORM, CEOS_REMOVE, {"absent_paths": list(op.paths)}
        origin = models.ConfigletOrigin.REMOVAL
        metadata["removal"] = {"item": op.key, "absent_paths": list(op.paths), "restorable": True, "restore_lines": list(op.inverse)}
    return dict(
        cfg_id=f"CFG-{sequence:03d}", sequence=sequence, target_device=op.device, feature_namespace=models.FeatureNamespace.ROUTING,
        description=f"[{op.state}] {op.stage}: {op.description or op.key}"[:400], operation_type=_operation_type(op),
        deployment_priority=models.DeploymentPriority.DYNAMIC_ROUTING, rendered_config="\n".join(op.lines), rollback_config="\n".join(op.inverse),
        desired_state_ref={"source": {"platform": platform, "object_type": object_type}, "transition": tag},
        verification_spec={"requirements": [{"expected": expected}], "before": [c.label for c in op.before], "after": [c.label for c in op.after],
                           "undo_before": [c.label for c in op.undo_before], "undo_after": [c.label for c in op.undo_after]},
        metadata=metadata, origin=origin)


def latest_validation(change):
    return change.validation_runs.order_by("-created_at", "-id").first()


def latest_plan(change):
    return change.plans.order_by("-created_at", "-id").first()


def latest_precheck(change, plan):
    return change.operational_runs.filter(mode=models.OperationalRunMode.CHANGE_PRECHECK, plan=plan).order_by("-created_at", "-id").first()


def build_plan(change, *, actor: str, definition: migration.Definition = migration.PRODUCTION):
    """One immutable plan from the latest PASS validation.  Building it again for the same validation returns the same plan."""
    _require_transition(change, definition)
    ops = _ops(change, definition)
    validation = latest_validation(change)
    if validation is None or validation.status != models.ValidationRunStatus.PASS or validation.input_hash != migration.plan_hash(ops):
        raise LifecycleError([_blocker("VALIDATION_NOT_CURRENT", "the Change has no current passing validation of this plan")])
    existing = models.ChangePlan.objects.filter(validation_run=validation, planner_version=migration.PLANNER_VERSION).first()
    if existing is not None:
        return existing
    summary = {
        "kind": kind_of(change), "definition": definition.name, "operations": len(ops), "devices": list(definition.devices),
        "persistence": {"stage": migration.PERSISTENCE, "devices": list(definition.access_devices), "command": PERSISTENCE_COMMAND,
                        "not_persisted": {core: "temporary kernel covers; the boot configuration must stay unchanged" for core in definition.cores}},
        "stages": [stage for stage in migration.STAGES if any(op.stage == stage for op in ops)],
        "permanent": [op.key for op in ops if op.state == PERMANENT], "temporary": [op.key for op in ops if op.state == TEMPORARY],
        "permanent_intent": migration.permanent_lines(ops), "cover_inventory": [cover.to_expected() for cover in definition.covers],
    }
    with transaction.atomic():
        plan = models.ChangePlan.objects.create(
            change=change, validation_run=validation, planner_version=migration.PLANNER_VERSION, validation_input_hash=validation.input_hash,
            validation_source_hash=validation.source_hash, validation_engine_version=validation.engine_version,
            plan_hash=migration.plan_hash(ops), created_by=actor, summary=summary,
            warnings=["Temporary operations are transition state: they are recorded in the execution evidence and are not part of the final desired configuration.",
                      "The startup configuration of R1, R2, S1 and S2 is written once, after the final state is verified, and read back."],
            provenance={"design": "docs/V2_LOSSLESS_ROUTE_SHIELD.md", "proof": "sandbox run proof20kc",
                        "validation": {"run_id": str(validation.run_id), "input_hash": validation.input_hash, "source_hash": validation.source_hash}})
        for sequence, op in enumerate(ops, 1):
            models.Configlet.objects.create(change=change, plan=plan, **_configlet_fields(op, sequence))
        models.AuditEvent.objects.create(
            event_type=models.AuditEventType.PLAN_BUILT, change=change, object_type="ChangePlan", object_id=str(plan.plan_id), actor=actor,
            summary=f"{change.change_id}: transition plan built ({len(ops)} operations)"[:255],
            metadata={"plan_hash": plan.plan_hash, "operations": len(ops), "temporary": len(summary["temporary"])})
    return plan


def _plan_blockers(plan, ops) -> list[dict]:
    """The plan rows are still exactly the operations of the approved design."""
    rows = list(plan.configlets.order_by("sequence"))
    if plan.plan_hash != migration.plan_hash(ops) or len(rows) != len(ops):
        return [_blocker("PLAN_STALE", "the plan no longer matches the approved design; validate and plan again")]
    for sequence, (row, op) in enumerate(zip(rows, ops), 1):
        wanted = _configlet_fields(op, sequence)
        if any(getattr(row, name) != wanted[name] for name in ("cfg_id", "target_device", "rendered_config", "rollback_config", "desired_state_ref",
                                                                 "verification_spec", "origin", "operation_type")):
            return [_blocker("PLAN_STALE", f"{row.cfg_id} differs from the approved design")]
    return []


# ---------------------------------------------------------------------------------------------------------------------- precheck
def _digests(definition, env) -> dict:
    found = {}
    for name in definition.access_devices:
        found[name] = {"config": env.executors[name].config_state_digest(), "startup": env.executors[name].startup_state_digest()}
    for name in definition.cores:
        executor = env.executors[name]
        found[name] = {"static_routes": executor.static_route_digest(), "frr_config": executor.frr_config_digest(),
                       "persistent_config": executor.persistent_config_digest(),
                       "adjacencies": core_cover.adjacencies(env.read(env.devices[name]))}
    return found


def _forwarding_checks(definition, kind: str):
    """Who must own the routes at the END of a transition of ``kind`` (and, for the opposite kind, at its start)."""
    from functools import partial

    from . import checks

    d, source = definition, "isis" if kind == migration.KIND else "static"
    for s_name, r_name in d.sides:
        s, r = d.switches[s_name], d.routers[r_name]
        yield migration.Check(f"{s_name} {lab.AGGREGATE} by {source}", partial(checks.owned, device=s_name, prefix=lab.AGGREGATE, source=source, interface=s.uplink), 20)
        for prefix in lab.CLIENTS:
            yield migration.Check(f"{r_name} {prefix} by {source}", partial(checks.owned, device=r_name, prefix=prefix, source=source, interface=r.access_interface), 20)
        if kind == migration.KIND:
            yield migration.Check(f"{s_name} adjacencies up", partial(checks.adjacencies_up, device=s_name, interfaces=(s.uplink, s.transit)), 20)
            yield migration.Check(f"{r_name} adjacency up", partial(checks.adjacencies_up, device=r_name, interfaces=(r.access_interface,)), 20)


def _settle(check, env) -> tuple[bool, str]:
    deadline = env.clock() + float(check.timeout)
    while True:
        ok, detail = check.run(env)
        if ok or env.clock() >= deadline:
            return bool(ok), str(detail)[:200]
        env.sleep(env.poll_seconds)


def precheck_blockers(definition, ops, env, *, kind: str = migration.KIND, basis: dict | None = None) -> tuple[list[dict], dict]:
    """Everything that must hold on all six devices before the first write.  -> (blockers, facts).
    ``basis``: for a revert, the digests the named migration run recorded (``revert_basis``)."""
    from ..config_workbench.structure import config_paths

    blockers: list[dict] = []
    facts: dict = {}
    if env.probes is None or env.host_gate is None:
        return [_blocker(gates.PROBES_UNHEALTHY if env.probes is None else gates.HOST_GATE, "no probe source / host gate was supplied")], facts
    ok, host = env.host_gate()
    facts["host"] = host
    if not ok:
        blockers.append(_blocker(gates.HOST_GATE, str(host)[:200]))
    ok, detail = env.probes.healthy()
    facts["probes"] = detail
    if not ok:
        blockers.append(_blocker(gates.PROBES_UNHEALTHY, str(detail)[:200]))
    for core in definition.cores:
        for row in core_cover.precheck(definition.covers_of(core), env.executors[core], env.read(env.devices[core])):
            blockers.append(_blocker(row["code"], row["detail"], core))
    if kind == migration.REVERT_KIND:
        # the devices must still be exactly what the migration left: the revert is the inverse of THAT state and of nothing else
        for name in definition.access_devices:
            wanted = ((basis or {}).get("migrated") or {}).get(name)
            if not wanted or env.executors[name].config_state_digest() != wanted:
                blockers.append(_blocker("REVERT_BASIS_DRIFTED", "the running configuration is not the one the migration run recorded", name))
        for check in _forwarding_checks(definition, migration.KIND):
            ok, detail = check.run(env)
            if not ok:
                blockers.append(_blocker(gates.OLD_ROUTE_ABSENT, f"{check.label}: {detail}"))
    for s_name, r_name in definition.sides if kind == migration.KIND else ():
        for transition in (lab.switch_to_isis(definition.switches[s_name]), lab.router_to_isis(definition.routers[r_name])):
            executor = env.executors[transition.device]
            found = gates.precheck(transition, env.read(env.devices[transition.device]),
                                   next_hop_alive=lambda _device, address, executor=executor: executor.neighbour_answers(address),
                                   new_route_available=lambda _t: True)
            for row in found:
                if row["code"] != gates.NEW_PATH_UNAVAILABLE:          # IS-IS does not exist yet: its availability gates the switchover stage
                    blockers.append(_blocker(row["code"], row["detail"], transition.device))
    for name in definition.access_devices:
        try:
            present = config_paths(env.executors[name].show("show running-config"))
        except ExecutorError as exc:
            blockers.append(_blocker(gates.EVIDENCE_UNAVAILABLE, exc.code, name))
            continue
        for op in ops:
            if op.device != name or op.action not in (ADD, REMOVE):
                continue
            found = [path for path in op.paths if path in present]
            if op.action == ADD and found:
                blockers.append(_blocker(gates.OUT_OF_BAND, f"{op.key}: {found[0]} is already configured", name))
            elif op.action == REMOVE and op.state == PERMANENT and len(found) != len(op.paths):
                blockers.append(_blocker(gates.OLD_ROUTE_ABSENT, f"{op.key}: the configuration to be superseded is not all present", name))
    try:
        facts["digests"] = _digests(definition, env)
    except ExecutorError as exc:
        blockers.append(_blocker(gates.EVIDENCE_UNAVAILABLE, exc.code))
    else:
        for name in definition.access_devices:          # persistence at the end, and its recovery, both rely on this
            if facts["digests"][name]["startup"] != facts["digests"][name]["config"]:
                blockers.append(_blocker("STARTUP_NOT_IN_SYNC", "the startup configuration is not the running configuration", name))
    return blockers, facts


def run_precheck(change, *, actor: str, env: Environment, definition: migration.Definition = migration.PRODUCTION):
    """Fresh, read-only precheck of all six devices, recorded against the current plan."""
    _require_transition(change, definition)
    ops = _ops(change, definition)
    plan = latest_plan(change)
    if plan is None or _plan_blockers(plan, ops):
        raise LifecycleError(_plan_blockers(plan, ops) if plan is not None else [_blocker("PLAN_MISSING", "build the plan first")])
    started = timezone.now()
    try:
        env.connect(definition.devices)
        blockers, facts = precheck_blockers(definition, ops, env, kind=kind_of(change), basis=revert_basis(change))
    except ExecutorError as exc:
        blockers, facts = [_blocker(gates.EVIDENCE_UNAVAILABLE, exc.code)], {}
    finally:
        env.close()
    blockers += _record_blockers(change)
    status = "BLOCKED" if blockers else "PASS"
    with transaction.atomic():
        run = models.OperationalCheckRun.objects.create(
            mode=models.OperationalRunMode.CHANGE_PRECHECK, status=status, change=change, plan=plan, engine_version=HEALTH_ENGINE_VERSION,
            started_at=started, finished_at=timezone.now(), created_by=actor, summary={"status": status, "blockers": [b["code"] for b in blockers]},
            report={"schema": 1, "engine": ENGINE_VERSION, "blockers": blockers, **facts})
        models.AuditEvent.objects.create(
            event_type=models.AuditEventType.PRECHECK_RECORDED, change=change, object_type="OperationalCheckRun", object_id=str(run.run_id), actor=actor,
            summary=f"{change.change_id}: transition precheck {status}"[:255], metadata={"status": status, "blockers": [b["code"] for b in blockers][:10]})
    return run


def _record_blockers_for(kind: str) -> list[dict]:
    return [_blocker("PRIOR_TRANSITION_UNRESOLVED", f"{row} left a transition unresolved; resolve it first") for row in unresolved_transitions()]


def _record_blockers(change) -> list[dict]:
    """What NMAS's own records forbid, whatever the devices say."""
    found = _record_blockers_for(kind_of(change))
    if kind_of(change) == migration.REVERT_KIND and revert_basis(change) is None:
        found.append(_blocker("REVERT_BASELINE_UNAVAILABLE", "the migration run this Change reverts is not a SUCCEEDED, persisted migration"))
    return found


# ---------------------------------------------------------------------------------------------------------------------- approval
def _approval(change) -> dict:
    event = change.lifecycle_events.filter(to_state=models.ChangeLifecycleState.READY_TO_DEPLOY).order_by("-occurred_at", "-id").first()
    return dict((event.metadata or {}).get("approval") or {}) if event is not None else {}


def approve(change, *, actor: str, confirmation: str, acknowledgements: dict, definition: migration.Definition = migration.PRODUCTION):
    """Explicit operator approval of exactly this plan and this precheck.  Nothing is pre-acknowledged."""
    _require_transition(change, definition)
    plan = latest_plan(change)
    blockers = []
    if plan is None:
        blockers.append(_blocker("PLAN_MISSING", "build the plan first"))
    else:
        blockers += _plan_blockers(plan, _ops(change, definition))
        precheck = latest_precheck(change, plan)
        if precheck is None or precheck.status != "PASS":
            blockers.append(_blocker("PRECHECK_NOT_PASSED", "the latest precheck of this plan did not pass"))
    if confirmation != change.change_id:
        blockers.append(_blocker("CONFIRMATION_MISMATCH", "type the Change id to approve it"))
    missing = [name for name, _label in ACKNOWLEDGEMENTS if (acknowledgements or {}).get(name) is not True]
    if missing:
        blockers.append(_blocker("ACKNOWLEDGEMENT_MISSING", ", ".join(missing)))
    if change.lifecycle_state not in (models.ChangeLifecycleState.DRAFT, models.ChangeLifecycleState.READY_TO_DEPLOY):
        blockers.append(_blocker("CHANGE_LIFECYCLE_NOT_EXECUTABLE", change.lifecycle_state))
    if blockers:
        raise LifecycleError(blockers)
    return lifecycle_service.record_lifecycle_event(
        change=change, to_state=models.ChangeLifecycleState.READY_TO_DEPLOY, actor=actor, reason="Transition approved",
        metadata={"approval": {"plan_id": str(plan.plan_id), "plan_hash": plan.plan_hash, "precheck_run": str(precheck.run_id),
                               "acknowledged": [name for name, _label in ACKNOWLEDGEMENTS], "approved_by": actor}})


# --------------------------------------------------------------------------------------------------------------------- execution
@dataclass
class ExecutionResult:
    run: object
    outcome: str
    blockers: list = field(default_factory=list)


def _gate(change, definition, confirmation: str, now) -> tuple[object, object, list, list[dict]]:
    """Everything that must hold before a lock is taken.  -> (plan, precheck, ops, blockers)."""
    ops = _ops(change, definition)
    plan = latest_plan(change)
    if plan is None:
        return None, None, ops, [_blocker("PLAN_MISSING", "build the plan first")]
    blockers = _plan_blockers(plan, ops) + _record_blockers(change)
    if (now - plan.created_at).total_seconds() > plan_max_age_seconds():
        blockers.append(_blocker("PLAN_STALE", "the validated plan is too old; validate, plan, precheck and approve again"))
    precheck = latest_precheck(change, plan)
    approval = _approval(change)
    if change.lifecycle_state != models.ChangeLifecycleState.READY_TO_DEPLOY or approval.get("plan_hash") != plan.plan_hash:
        blockers.append(_blocker("NOT_APPROVED", "the Change is not approved for this plan"))
    if precheck is None or precheck.status != "PASS" or approval.get("precheck_run") != str(precheck.run_id):
        blockers.append(_blocker("PRECHECK_NOT_PASSED", "the approved precheck is not the latest passing precheck of this plan"))
    elif (now - precheck.finished_at).total_seconds() > precheck_max_age_seconds():
        blockers.append(_blocker("PRECHECK_STALE", "the precheck is too old; run it and approve again"))
    if confirmation != change.change_id:
        blockers.append(_blocker("CONFIRMATION_MISMATCH", "type the Change id to execute it"))
    if change.execution_runs.exclude(outcome__in=RESOLVED_OUTCOMES).exists():
        blockers.append(_blocker("PRIOR_RUN_UNRESOLVED", "an earlier run of this Change succeeded, was interrupted or was not fully restored"))
    return plan, precheck, ops, blockers


def execute(change, *, actor: str, confirmation: str, env: Environment | None = None) -> ExecutionResult:
    """The service entry point.  Refuses, before any device is contacted, unless the transition is READY
    (``readiness.READINESS``); no argument lifts that.  Only the production definition can be executed from here."""
    _require_transition(change, migration.PRODUCTION)
    refused = readiness.refusal(READINESS_OF[kind_of(change)])
    if refused or env is None:
        blockers = [_blocker(refused.split(":")[0] if refused else "NO_PRODUCTION_ENVIRONMENT", refused or "no execution environment is configured")]
        run = persistence.record_blocked(change, latest_plan(change), precheck_run=None, mode=models.ExecutionMode.COMPLETE, actor=actor, blockers=blockers)
        return ExecutionResult(run, Outcome.BLOCKED, blockers)
    return _execute(change, actor=actor, confirmation=confirmation, env=env, definition=migration.PRODUCTION)


def _execute(change, *, actor: str, confirmation: str, env: Environment, definition: migration.Definition) -> ExecutionResult:
    """Ungated by readiness: for the disposable sandbox and the mechanics tests only.  Every other gate applies."""
    _require_transition(change, definition)
    now = timezone.now()
    locking.reap_expired(now)
    plan, precheck, ops, blockers = _gate(change, definition, confirmation, now)
    mode = models.ExecutionMode.COMPLETE
    if blockers:
        run = persistence.record_blocked(change, plan, precheck_run=precheck, mode=mode, actor=actor, blockers=blockers)
        return ExecutionResult(run, Outcome.BLOCKED, blockers)
    scope, scope_blockers = resolve_scope(plan, mode)
    if scope_blockers:
        run = persistence.record_blocked(change, plan, precheck_run=precheck, mode=mode, actor=actor, blockers=scope_blockers)
        return ExecutionResult(run, Outcome.BLOCKED, scope_blockers)
    try:
        run = locking.acquire(change=change, plan=plan, precheck_run=precheck, mode=mode, actor=actor, scope=scope, devices=list(definition.devices), now=now)
    except locking.LockRefused as exc:
        refusal = [_blocker(exc.code, str(exc.details))]
        run = persistence.record_blocked(change, plan, precheck_run=precheck, mode=mode, actor=actor, blockers=refusal, scope=scope)
        return ExecutionResult(run, Outcome.BLOCKED, refusal)
    attempt = _Attempt(run=run, change=change, plan=plan, precheck=precheck, definition=definition, env=env, ops=ops,
                       specs=[ConfigletSpec.from_configlet(row) for row in scope.selected], actor=actor, kind=kind_of(change),
                       basis=revert_basis(change))
    outcome = Outcome.INTERRUPTED
    try:
        outcome = attempt.drive()
    except Exception as exc:  # noqa: BLE001 - never a stuck lock or a false success
        attempt.failure = attempt.failure or {"code": "INTERNAL_ERROR", "detail": type(exc).__name__}
        outcome = Outcome.INTERRUPTED
    try:
        report = attempt.report(outcome)                    # read while the sessions are still open: what is left is read from the devices
    finally:
        env.close()
    run = persistence.finalize_run(run, outcome=outcome, report=report, postcheck_run=attempt.postcheck_run, now=timezone.now())
    state = {Outcome.SUCCEEDED: models.ChangeLifecycleState.DEPLOYED, Outcome.FAILED_ROLLED_BACK: models.ChangeLifecycleState.ROLLED_BACK,
             Outcome.POSTCHECK_FAILED_ROLLED_BACK: models.ChangeLifecycleState.ROLLED_BACK}.get(outcome)
    if state is None and outcome not in (Outcome.BLOCKED, Outcome.FAILED_NO_MUTATION):
        state = models.ChangeLifecycleState.FAILED
    if state is not None:
        lifecycle_service.record_lifecycle_event(change=change, to_state=state, actor=actor, reason=f"Transition execution {outcome}",
                                                 metadata={"run_id": str(run.run_id), "outcome": outcome})
    return ExecutionResult(run, outcome, attempt.blockers)


@dataclass
class _Attempt:
    run: object
    change: object
    plan: object
    precheck: object
    definition: object
    env: object
    ops: list
    specs: list
    actor: str
    kind: str = migration.KIND
    basis: dict | None = None                          # a revert: the digests of the migration run it reverts
    persisted: list = field(default_factory=list)      # access devices whose startup configuration this run wrote
    persistence: dict = field(default_factory=dict)    # device -> evidence of the persistence stage
    applied: list = field(default_factory=list)        # (op, spec, assessment, digest before) in apply order
    stages: list = field(default_factory=list)
    blockers: list = field(default_factory=list)
    compensation: list = field(default_factory=list)
    failure: dict = field(default_factory=dict)
    postcheck_run: object = None
    lost_at_start: int = 0
    probes_lost: int = 0
    expected: dict = field(default_factory=dict)       # access device -> the configuration digest after our own last step
    baseline: dict = field(default_factory=dict)
    final: dict = field(default_factory=dict)
    restored: bool | None = None
    _failed: list = field(default_factory=list)

    # -- evidence ---------------------------------------------------------------------------------------------------------
    def note(self, stage: str, status: str, **facts) -> None:
        self.stages.append({"stage": stage, "at": timezone.now().isoformat(), "status": status, **facts})

    def lost(self) -> int:
        self.probes_lost = max(self.probes_lost, int(self.env.probes.lost()) - self.lost_at_start)
        return self.probes_lost

    def fail(self, code: str, detail: str = "", key: str = "") -> None:
        if not self.failure:
            self.failure = {"code": code, "detail": str(detail)[:300], "operation": key}
            self.blockers.append(_blocker(code, str(detail)[:300]))
            self.note("abort", code, operation=key, detail=str(detail)[:300])

    def gate(self, checks, key: str, phase: str) -> bool:
        for check in checks:
            ok, detail = _settle(check, self.env)
            if not ok:
                self.fail("GATE_FAILED", f"{phase}: {check.label}: {detail}", key)
                return False
        return True

    def pause(self, seconds: float) -> None:
        if seconds:
            self.env.sleep(seconds)
        locking.heartbeat(self.run)
        maintain = getattr(self.env.probes, "maintain", None)
        if maintain is not None:
            maintain()

    def changed(self, op) -> None:
        """A change on an access device can make the boundary routers re-originate: the cores' quiet period starts again.
        Installing or removing a cover touches no client route and does not."""
        if op.device in self.definition.access_devices:
            self.env.last_change_at = self.env.clock()

    def digest(self, device: str) -> str | None:
        return self.env.executors[device].config_state_digest() if device in self.definition.access_devices else None

    # -- forward ----------------------------------------------------------------------------------------------------------
    def drive(self) -> str:
        env, d = self.env, self.definition
        try:
            env.connect(d.devices)
            blockers, facts = precheck_blockers(d, self.ops, env, kind=self.kind, basis=self.basis)
        except ExecutorError as exc:
            blockers, facts = [_blocker(gates.EVIDENCE_UNAVAILABLE, exc.code)], {}
        self.baseline = facts.get("digests") or {}
        recorded = (self.precheck.report or {}).get("digests") or {}
        if not blockers and canonical.canonical_json(self.baseline) != canonical.canonical_json(recorded):
            blockers.append(_blocker(gates.BASELINE_STALE, "a device changed since the approved precheck"))
        self.note(migration.PRECHECK, "BLOCKED" if blockers else "PASS", blockers=[b["code"] for b in blockers], host=facts.get("host"))
        if blockers:
            self.blockers = blockers
            return Outcome.BLOCKED
        env.baseline = self.baseline
        self.lost_at_start = int(env.probes.lost())
        self.expected = {name: self.baseline[name]["config"] for name in d.access_devices}
        try:
            stage = None
            for op, spec in zip(self.ops, self.specs):
                if op.stage != stage and not self.window_guard(op.stage):      # abort BEFORE the next stage, never inside one
                    break
                stage = op.stage
                if not self.apply(op, spec):
                    break
            if not self.failure and self.window_guard(migration.FINAL_VALIDATION):
                self.final_validation()
        except Exception as exc:  # noqa: BLE001 - an engine or hook failure after the first write takes the reverse path
            self.fail("INTERNAL_ERROR", type(exc).__name__)
        attempted = {entry[1].cfg_id for entry in self.applied} | set(self._failed)
        persistence.add_not_attempted(self.run, [spec for spec in self.specs if spec.cfg_id not in attempted])
        if not self.failure:
            return Outcome.SUCCEEDED
        if not self.applied:
            return Outcome.FAILED_NO_MUTATION
        self.compensate()
        after_postcheck = self.failure.get("code") in ("FINAL_STATE_NOT_VERIFIED", "PERSISTENCE_NOT_VERIFIED")
        if self.restored:
            return Outcome.POSTCHECK_FAILED_ROLLED_BACK if after_postcheck else Outcome.FAILED_ROLLED_BACK
        return Outcome.POSTCHECK_FAILED_COMPENSATION_INCOMPLETE if after_postcheck else Outcome.FAILED_COMPENSATION_INCOMPLETE

    def window_guard(self, stage: str) -> bool:
        """Between two stages: the host is still inside the window's resource condition and every probe flow is still
        delivering samples.  Otherwise the run stops here and takes the reverse path; a busy host or a silent probe
        is never read as "nothing was lost".  The host must fail the policy's number of consecutive samples (a single
        busy sample is a spike); a stalled flow is judged at once."""
        env = self.env
        samples = getattr(env.host_gate, "consecutive_samples", None)
        ok, facts = False, {}
        for _sample in range(max(1, int(samples() if callable(samples) else samples or 1))):
            ok, facts = env.host_gate()
            if ok:
                break
        if not ok:
            self.note("window", "FAIL", before=stage, host=facts)
            self.fail(gates.WINDOW_CONDITION_LOST, f"before {stage}: " + "; ".join((facts or {}).get("failed") or ["host gate failed"]), stage)
            return False
        advancing = getattr(env.probes, "advancing", None)
        ok, detail = advancing() if advancing is not None else (False, {"errors": ["the probe source cannot report progress"]})
        if not ok:
            self.note("window", "FAIL", before=stage, probes=detail)
            self.fail(gates.PROBE_TIMING_UNRELIABLE, f"before {stage}: stalled flows {detail.get('stalled_flows') or detail.get('errors')}", stage)
            return False
        if self.lost():
            self.fail(gates.PACKET_LOSS, f"production probes were lost before {stage}", stage)
            return False
        self.note("window", "PASS", before=stage, cpu_busy_percent=(facts or {}).get("cpu_busy_percent"), load1=(facts or {}).get("load1"), probes=detail)
        return True

    def apply(self, op, spec) -> bool:
        env, executor = self.env, self.env.executors[op.device]
        env.notify("before", op.key)
        if not self.gate(op.before, op.key, "before"):
            return False
        before = self.digest(op.device)
        if before is not None and before != self.expected[op.device]:
            self.fail(gates.OUT_OF_BAND, f"{op.device} changed between two steps of this run", op.key)
            return False
        assessment = executor.assess(spec)
        if assessment.action != APPLY or not assessment.restorable:
            code = gates.OUT_OF_BAND if assessment.action == SKIP_SATISFIED else (assessment.reason or "COMPENSATION_NOT_PROVABLE")
            self.fail(code, f"{op.key}: {assessment.action} ({assessment.reason or 'state is not the planned one'})", op.key)
            return False
        row = persistence.start_result(self.run, spec, Phase.APPLY, previous_state=assessment.previous_state)
        outcome = executor.apply(spec, assessment)
        self.changed(op)
        if outcome.ok or outcome.partial_effects:
            self.applied.append((op, spec, assessment, before))
        if not outcome.ok:
            persistence.finish_result(row, Status.FAILED, error_code=outcome.error_code, partial_effects=outcome.partial_effects, lines_sent=outcome.lines_sent)
            self._failed.append(spec.cfg_id)
            self.fail("APPLY_FAILED", f"{op.key}: {outcome.error_code}", op.key)
            return False
        read_back = executor.assess(spec).action
        after = self.digest(op.device)
        if after is not None:
            self.expected[op.device] = after
        persistence.finish_result(row, Status.APPLIED, lines_sent=outcome.lines_sent,
                                  detail={"operation": op.key, "stage": op.stage, "state": op.state, "read_back": read_back})
        self.note(op.stage, "APPLIED", operation=op.key, device=op.device, state=op.state, cfg_id=spec.cfg_id, read_back=read_back)
        if read_back != SKIP_SATISFIED:
            self.fail("READ_BACK_MISMATCH", f"{op.key}: the device does not report the operation as in place", op.key)
            return False
        if not self.gate(op.after, op.key, "after"):
            return False
        env.notify("after", op.key)
        if self.lost():
            self.fail(gates.PACKET_LOSS, f"production probes were lost at {op.key}", op.key)
            return False
        self.pause(op.pause)
        if self.lost():
            self.fail(gates.PACKET_LOSS, f"production probes were lost after {op.key}", op.key)
            return False
        return True

    # -- final state ------------------------------------------------------------------------------------------------------
    def final_checks(self) -> list[dict]:
        """The final intended state and nothing temporary.  -> failed rows."""
        from ..config_workbench.structure import config_paths

        env, d, failed = self.env, self.definition, []

        def need(ok: bool, label: str, detail: str = "") -> None:
            if not ok:
                failed.append({"check": label, "detail": str(detail)[:200]})

        temporary = set(config_paths("\n".join(migration.temporary_lines(self.ops))))
        for name in d.access_devices:
            present = config_paths(env.executors[name].show("show running-config"))
            need(not (temporary & present), f"{name}: no temporary statement remains", sorted(temporary & present)[:1])
            for op in self.ops:
                if op.device == name and op.state == PERMANENT and op.action == ADD:
                    need(all(path in present for path in op.paths), f"{name}: {op.key} is configured")
                elif op.device == name and op.state == PERMANENT and op.action == REMOVE:
                    need(not any(path in present for path in op.paths), f"{name}: {op.key} is gone")
        for core in d.cores:
            executor = env.executors[core]
            for row in core_cover.postcheck(d.covers_of(core), executor, env.read(env.devices[core]),
                                            adjacencies_before=self.baseline[core]["adjacencies"], present=False):
                need(False, f"{core}: {row['code']}", row["detail"])
            need(executor.static_route_digest() == self.baseline[core]["static_routes"], f"{core}: non-dynamic kernel routes are the baseline ones")
            need(executor.frr_config_digest() == self.baseline[core]["frr_config"], f"{core}: FRR running configuration unchanged")
            need(executor.persistent_config_digest() == self.baseline[core]["persistent_config"], f"{core}: boot configuration unchanged (no cover persisted)")
        for check in _forwarding_checks(d, self.kind):
            ok, detail = _settle(check, env)
            need(ok, check.label, detail)
        if self.kind == migration.REVERT_KIND:          # the revert ends on exactly the configuration the migration started from
            for name in d.access_devices:
                wanted = ((self.basis or {}).get("premigration") or {}).get(name, {}).get("config")
                need(bool(wanted) and self.digest(name) == wanted, f"{name}: running configuration is the pre-migration baseline")
        need(self.lost() == 0, "no production probe was lost", self.probes_lost)
        return failed

    def persist(self) -> list[dict]:
        """The persistence stage: the startup configuration of each access device becomes the running configuration that
        the final validation has just verified, and is read back.  Nothing is written on a core router.  -> failed rows."""
        from ..config_workbench.structure import config_paths

        env, d, failed = self.env, self.definition, []
        temporary = set(config_paths("\n".join(migration.temporary_lines(self.ops))))
        for name in d.access_devices:
            executor, entry = env.executors[name], {"command": PERSISTENCE_COMMAND, "status": "NOT_VERIFIED"}
            self.persistence[name] = entry
            env.notify("before", f"{migration.PERSISTENCE}-{name}")
            if self.digest(name) != self.final[name]:                 # exactly the verified state is persisted, or nothing is
                entry["error"] = "the running configuration changed after the final validation"
                failed.append({"check": f"{name}: persistence", "detail": entry["error"]})
                break
            self.persisted.append(name)                               # recorded BEFORE the write: recovery covers a half-written device
            outcome = executor.save_startup()
            startup = config_paths(executor.startup_config_text())
            entry.update(startup_digest=executor.startup_state_digest(), running_digest=self.digest(name), intended_digest=self.final[name])
            problems = []
            if not outcome.ok:
                problems.append(f"the device rejected the command ({outcome.error_code})")
            if entry["startup_digest"] != self.final[name] or entry["running_digest"] != self.final[name]:
                problems.append("startup, running and intended configuration are not the same state")
            if temporary & startup:
                problems.append(f"a temporary statement was persisted: {sorted(temporary & startup)[0]}")
            for op in self.ops:
                if op.device == name and op.state == PERMANENT and (any(p in startup for p in op.paths) if op.action == REMOVE else not all(p in startup for p in op.paths)):
                    problems.append(f"{op.key} is not reflected in the startup configuration")
            if problems:
                entry["error"] = problems[0]
                failed.append({"check": f"{name}: persistence", "detail": problems[0]})
                break
            entry["status"] = "VERIFIED"
            self.note(migration.PERSISTENCE, "VERIFIED", device=name, startup_digest=entry["startup_digest"])
            env.notify("after", f"{migration.PERSISTENCE}-{name}")
        for core in d.cores:
            same = env.executors[core].persistent_config_digest() == self.baseline[core]["persistent_config"]
            self.persistence[core] = {"status": "UNCHANGED" if same else "CHANGED", "persisted": False}
            if not same:
                failed.append({"check": f"{core}: boot configuration unchanged", "detail": "the boot configuration of a core router changed"})
        return failed

    def restore_startup(self) -> bool:
        """Recovery of the persistence stage: every access device whose startup configuration this run wrote gets the
        restored running configuration written again, and the startup digest must be the pre-run one."""
        ok = True
        for name in self.persisted:
            executor, entry = self.env.executors[name], self.persistence.setdefault(name, {})
            try:
                if self.digest(name) != self.baseline[name]["config"]:
                    entry["recovery"] = "NOT_RESTORED: the running configuration is not the baseline"
                    ok = False
                    continue
                outcome = executor.save_startup()
                restored = outcome.ok and executor.startup_state_digest() == self.baseline[name]["startup"]
            except Exception:  # noqa: BLE001 - reported, never raised past the evidence
                restored = False
            entry["recovery"] = "STARTUP_RESTORED" if restored else "NOT_RESTORED"
            ok = ok and restored
        return ok

    def final_validation(self) -> None:
        started = timezone.now()
        self.env.notify("before", migration.FINAL_VALIDATION)
        failed = self.final_checks()
        code = "FINAL_STATE_NOT_VERIFIED"
        if not failed:
            self.final = {name: self.digest(name) for name in self.definition.access_devices}
            failed = self.persist()
            code = "PERSISTENCE_NOT_VERIFIED" if failed else code
        status = "FAIL" if failed else "PASS"
        self.postcheck_run = models.OperationalCheckRun.objects.create(
            mode=models.OperationalRunMode.CHANGE_POSTCHECK, status=status, change=self.change, plan=self.plan, engine_version=HEALTH_ENGINE_VERSION,
            started_at=started, finished_at=timezone.now(), created_by=self.actor, summary={"status": status, "failed": len(failed)},
            report={"schema": 1, "engine": ENGINE_VERSION, "failed": failed, "permanent_baseline": self.final, "probes_lost": self.probes_lost,
                    "persistence": self.persistence})
        self.note(migration.FINAL_VALIDATION, status, failed=failed[:10], permanent_baseline=self.final)
        if failed:
            self.fail(code, f"{failed[0]['check']}: {failed[0].get('detail', '')}")

    # -- reverse path -----------------------------------------------------------------------------------------------------
    def compensate(self) -> None:
        """Undo, newest first, exactly what this run applied.  Stops at the first step that cannot be proven safe or
        restored: what is left is reported, never hidden.  The core covers are the last thing to go."""
        env, complete = self.env, True
        for op, spec, assessment, before in reversed(self.applied):
            entry = {"cfg_id": spec.cfg_id, "operation": op.key, "device": op.device, "state": op.state}
            try:
                failed_gate = next((c for c in op.undo_before if not _settle(c, env)[0]), None)
                if failed_gate is not None:
                    entry.update(status="NOT_COMPENSATED", error=f"not safe to undo: {failed_gate.label}")
                    self.compensation.append(entry)
                    complete = False
                    break
                row = persistence.start_result(self.run, spec, Phase.COMPENSATE, previous_state=assessment.previous_state)
                outcome = env.executors[op.device].compensate(spec, assessment)
                self.changed(op)
                status, error = outcome.status, outcome.error_code
                if status == Status.COMPENSATED and before is not None and self.digest(op.device) != before:
                    status, error = Status.COMPENSATION_FAILED, "STATE_NOT_RESTORED"
                persistence.finish_result(row, status, error_code=error, detail={"operation": op.key, **(outcome.detail or {})})
                entry.update(status=status, error=error)
                self.compensation.append(entry)
                if status != Status.COMPENSATED:
                    complete = False
                    break
                failed_after = next((c for c in op.undo_after if not _settle(c, env)[0]), None)
                if failed_after is not None:
                    entry.update(status="COMPENSATED_UNVERIFIED", error=f"not verified: {failed_after.label}")
                    complete = False
                    break
                self.lost()
                self.pause(op.undo_pause)
            except Exception as exc:  # noqa: BLE001 - compensation never raises past its own evidence
                entry.update(status="NOT_COMPENSATED", error=type(exc).__name__)
                if entry not in self.compensation:
                    self.compensation.append(entry)
                complete = False
                break
        if self.persisted and complete:          # the startup configuration this run wrote goes back with the running one
            complete = self.restore_startup()
        remaining = self.temporary_remaining()
        try:
            digests = _digests(self.definition, env)
        except Exception:  # noqa: BLE001
            digests = {}
        self.restored = complete and not remaining and digests == self.baseline
        self.lost()
        self.note("restore", "RESTORED" if self.restored else "RESTORE_INCOMPLETE", compensated=sum(e.get("status") == Status.COMPENSATED for e in self.compensation),
                  temporary_remaining=remaining, baseline_restored=digests == self.baseline, probes_lost=self.probes_lost)

    def temporary_remaining(self) -> list[str]:
        """Every temporary statement or cover that is still on a device right now (read from the devices, not from our own records)."""
        from ..config_workbench.structure import config_paths

        env, d, left = self.env, self.definition, []
        temporary = set(config_paths("\n".join(migration.temporary_lines(self.ops))))
        for name in d.access_devices:
            try:
                left += [f"{name}: {path}" for path in sorted(temporary & config_paths(env.executors[name].show("show running-config")))]
            except Exception:  # noqa: BLE001
                left.append(f"{name}: unreadable")
        for cover in d.covers:
            try:
                if env.executors[cover.core].state(cover) != "ABSENT":
                    left.append(f"{cover.core}: {cover.prefix}")
            except Exception:  # noqa: BLE001
                left.append(f"{cover.core}: unreadable")
        return left

    # -- the stored report -------------------------------------------------------------------------------------------------
    def report(self, outcome: str) -> dict:
        applied = [entry[1].cfg_id for entry in self.applied]
        compensated = [e["cfg_id"] for e in self.compensation if e.get("status") == Status.COMPENSATED]
        by_key = {op.key: op for op in self.ops}
        done = [entry[0].key for entry in self.applied]
        probes = getattr(self.env.probes, "report", None)
        return {
            "report_schema_version": 1, "engine_version": ENGINE_VERSION, "mode": models.ExecutionMode.COMPLETE, "outcome": outcome,
            "transition": {"kind": self.kind, "definition": self.definition.name,
                           "reverts": str(self.basis["run"].run_id) if self.basis else None},
            "persistence": {"status": ("VERIFIED" if outcome == Outcome.SUCCEEDED else "NOT_RUN" if not self.persistence else
                                       "RECOVERED" if self.restored else "NOT_VERIFIED"),
                            "command": PERSISTENCE_COMMAND, "written": list(self.persisted), "devices": self.persistence},
            "blockers": self.blockers, "failure": self.failure,
            "state": {"applied": applied, "failed": list(self._failed), "compensated": compensated,
                      "unapplied": [spec.cfg_id for spec in self.specs if spec.cfg_id not in applied]},
            "compensation": {"attempted": bool(self.compensation), "status": ("NOT_ATTEMPTED" if not self.compensation else
                                                                               "COMPENSATED" if self.restored else "INCOMPLETE"),
                             "not_compensated": [e["cfg_id"] for e in self.compensation if e.get("status") != Status.COMPENSATED], "steps": self.compensation},
            "postcheck": {"result": self.postcheck_run.status if self.postcheck_run is not None else "NOT_RUN"},
            "permanent_intent": {"applied": [key for key in done if by_key[key].state == PERMANENT], "baseline_digests": self.final},
            "temporary_state": {"installed": [key for key in done if by_key[key].state == TEMPORARY and by_key[key].action in (ADD, COVER_INSTALL)],
                                "removed": [key for key in done if by_key[key].state == TEMPORARY and by_key[key].action in (REMOVE, COVER_REMOVE)],
                                "remaining": self.temporary_remaining() if self.applied else []},
            "baseline_digests": self.baseline, "restored": self.restored,
            "probes": {"lost": self.probes_lost, **({"flows": probes()} if probes is not None else {})},
            "stages": self.stages[-400:],
        }
