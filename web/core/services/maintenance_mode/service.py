"""The operable Maintenance Mode: request, readiness, plan, approval, entry (drain), exit (restore), the deadline and the
worker that runs every device-contacting step.

    request -> readiness (read-only observation) -> immutable plan (read-only capture, hashed) -> approval of that hash
    -> entry: fresh observation, the plan built again and compared, gates, device locks, drain, proof -> ACTIVE
    -> exit (operator) or the 7-day deadline (worker): restore the captured pre-state -> verify -> RESTORED
                                                       or fail closed -> RESTORE_FAILED_ESCALATED

The lifecycle (``lifecycle.py``) decides every state; this module supplies it with what was observed and executed and
records it: the record's ``snapshot`` is its current state, ``evidence.append`` is the immutable, hash-chained history.

Concurrency.  Every step that contacts a device runs under a CLAIM of the record (a conditional update: one holder, with
a heartbeat), and every write runs under the shared ``ExecutionDeviceLock`` rows of the devices it writes to, so neither
a second worker nor a Change execution can interleave with it.  A claim whose heartbeat stops is recovered by the next
``tick``: an interrupted entry is aborted and restored, an interrupted restore is finished; neither is ever assumed done.

The website never contacts a device for maintenance: it queues an explicit operator request (``queue``) that the worker
(``tick``, run by its systemd timer, or the management command) claims and executes.  A drain takes minutes (settle
times, verification); it must not run inside a web request that a proxy or worker timeout could cut in half.

A maintenance writes to the device's own access switch and router only, with the existing metric mechanisms.  It never
writes to a core router: every environment hands the cores out as ``executor.CoreReader`` (read methods only), and the
final checks prove the cores hold nothing they did not hold before.

Entry writes to a device only when every planned mechanism is READY in ``route_shield.readiness`` (a reviewed constant);
no argument lifts that for the managed network.  The pre-maintenance state is captured and stored before the first
write, and the restore is built from that stored state and from nothing else.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta

from django.db import IntegrityError, transaction

from ..execution.executors.base import ExecutorError
from ..route_shield import gates as shield_gates
from ..route_shield import readiness as shield_readiness
from ..route_shield.migration import Check
from . import collector, drain, evidence, executor, gates, lifecycle, model, plan, policy, protection, readiness, store, topology

READINESS_KEY = {policy.ISIS_NORTHBOUND: shield_readiness.ISIS_METRIC_STEER, policy.OSPFV3_SOUTHBOUND: shield_readiness.OSPFV3_EXTERNAL_METRIC_STEER}
EVALUATE, ENTER, RESTORE, DEADLINE, RECOVER = "EVALUATE", "ENTER", "RESTORE", "DEADLINE", "RECOVER"
QUEUEABLE = (EVALUATE, ENTER, RESTORE)
QUEUE_STATES = {EVALUATE: (lifecycle.REQUESTED, lifecycle.BLOCKED, lifecycle.READY, lifecycle.PLANNED, lifecycle.APPROVED),
                ENTER: (lifecycle.APPROVED,), RESTORE: (lifecycle.ACTIVE, lifecycle.RESTORING, lifecycle.RESTORE_FAILED)}
PLAN_VALIDITY = timedelta(hours=2)                   # an approval stands this long at most; entry also rebuilds the plan from fresh facts
CLAIM_STALE_AFTER = timedelta(minutes=20)            # no heartbeat for this long: the worker that held the record is gone
VERIFY_ATTEMPTS, VERIFY_PAUSE = 3, 10.0              # post-restore verification: protocols may need a few seconds to settle
WORKER = "maintenance-worker"


@dataclass
class Runtime:
    sources: collector.Sources
    environment: object                      # () -> route_shield.lifecycle.Environment (probes and host gate set, nothing connected)
    start_probes: object                     # (env) -> None: the quiet-host gate first, then the probes
    definition: object                       # route_shield.migration.Definition: the tracked access design and the cores (read only)
    gated: bool = True                       # False only on the disposable sandbox: mechanism readiness is then not required
    probe_warmup: float = 25.0
    sleep: object = time.sleep
    writable: object = None                  # () -> names of the writable managed scope; None: every device of the topology (tests, sandbox)
    management_interfaces: dict = field(default_factory=dict)    # device -> its management interface names (never written)

    def scope(self) -> set:
        return set(self.writable() if self.writable is not None else self.sources.topology.devices)  # pylint: disable=not-callable  # injected callable (dataclass field annotated object)


def management_interfaces(inventory: dict, topo: topology.Topology) -> dict:
    """device -> every interface that carries its management: the inventory's management source interface (VLAN 200),
    the port cabled to the management switch, and the out-of-band management port."""
    found = {}
    for name, device in topo.devices.items():
        entry = ((inventory.get("network_devices") or {}).get(name) or {}).get("monitoring") or {}
        ports = {"Management0", "Management1", "eth0"}
        if entry.get("source_interface"):
            ports.add(str(entry["source_interface"]))
        for a, a_if, b, b_if in topo.links:
            if a == name and b in topo.management or b == name and a in topo.management:
                port = a_if if a == name else b_if
                ports.add(port.replace("eth", "Ethernet", 1) if device.get("platform") == "ceos" else port)
        found[name] = tuple(sorted(ports))
    return found


def production_runtime() -> Runtime:
    """The managed network: tracked cabling and inventory, the health engine's reader, the production executors and probes,
    the writable scope of ``config_workbench.scope`` (NetBox-managed and supported; fail closed when NetBox is unreadable)."""
    from pathlib import Path

    import yaml
    from django.conf import settings

    from ..config_workbench import scope as workbench_scope
    from ..health import inventory, live, telemetry
    from ..route_shield import migration, production

    document = inventory.load_inventory()
    with open(Path(settings.REPO_ROOT) / f"{document.get('lab_name', '')}.clab.yml", encoding="utf-8") as handle:
        cabling = yaml.safe_load(handle) or {}
    topo = topology.from_clab(cabling, document, inventory.inventory_devices(), service_host=production.SERVICE_HOST,
                              service_v4=production.SERVICE_V4, service_v6=production.SERVICE_V6)
    ports = management_interfaces(document, topo)
    topo = replace(topo, management_ports=ports)                 # path tracing knows each device's own management ports
    sources = collector.Sources(topo, live.read_device, dhcp_servers=inventory.dhcp_hosts, dhcp_state=live.dhcp_service_state, telemetry=telemetry.collect)
    return Runtime(sources, production.environment, production.start_probes, migration.PRODUCTION,
                   writable=lambda: {row["name"] for row in workbench_scope.workbench_scope().devices},
                   management_interfaces=ports)


def _finding(code: str, detail: str = "") -> model.Finding:
    return model.Finding(code, detail=str(detail)[:300])


def _from_text(text: str) -> model.Finding:
    code, _sep, detail = str(text).partition(": ")
    return _finding(code, detail)


def _findings(findings) -> list[dict]:
    return [store._finding(f) for f in findings]


def _row(record_id):
    from core import models

    key = str(record_id).upper().removeprefix("MNT-")
    row = models.MaintenanceRecord.objects.filter(pk=int(key)).first() if key.isdigit() else None
    if row is None:
        raise model.MaintenanceError("RECORD_NOT_FOUND", str(record_id))
    return row


def current(device: str):
    """The unresolved maintenance row of ``device``, or None."""
    from core import models

    return models.MaintenanceRecord.objects.filter(device_name=device).exclude(state__in=lifecycle.RESOLVED).first()


def _log(row, kind: str, actor: str, at: datetime, payload: dict, *, before: str = "", summary: str = "") -> None:
    evidence.append(row, kind=kind, actor=actor, at=at, payload=payload, state_from=before if before != row.state else "", state_to=row.state,
                    summary=summary or (f"{before} -> {row.state}" if before and before != row.state else kind))


# ------------------------------------------------------------------------------------------------------- claims and locks
def _claim(row, action: str, *, at: datetime) -> str:
    """Take the record for one device-contacting step.  -> the claim token.  Refused while anyone else holds it."""
    from core import models

    token = uuid.uuid4().hex
    if models.MaintenanceRecord.objects.filter(pk=row.pk, claim_token="").update(claim_token=token, claim_action=action, claimed_at=at, heartbeat_at=at) != 1:
        raise model.MaintenanceError("RECORD_BUSY", f"{row.record_id} is being worked on ({row.claim_action or 'claimed'})")
    row.refresh_from_db()
    return token


def _beat(row, token: str) -> None:
    from django.utils import timezone

    from core import models

    models.MaintenanceRecord.objects.filter(pk=row.pk, claim_token=token).update(heartbeat_at=timezone.now())


def _release(row, token: str) -> None:
    from core import models

    models.MaintenanceRecord.objects.filter(pk=row.pk, claim_token=token).update(claim_token="", claim_action="", claimed_at=None, heartbeat_at=None)
    row.refresh_from_db()


def _refuse_if_busy(row) -> None:
    if row.claim_token:
        raise model.MaintenanceError("RECORD_BUSY", f"{row.record_id} is being worked on ({row.claim_action})")


def _lock(row, devices) -> list:
    """The shared device locks of every device this maintenance is about to write to.  -> findings ([] = held).  The same
    table a Change execution locks its devices in: the two can never write to one device at the same time."""
    from core import models

    from ..execution import locking
    from ..execution.device_mutex import DeviceBusy, DeviceMutex

    locking.reap_expired()
    wanted = sorted(set(devices))
    try:
        with DeviceMutex(wanted), transaction.atomic():
            own = set(models.ExecutionDeviceLock.objects.filter(maintenance=row).values_list("device", flat=True))
            for name in wanted:
                if name not in own:
                    models.ExecutionDeviceLock.objects.create(device=name, maintenance=row)
    except DeviceBusy as exc:
        return [model.Finding("DEVICE_LOCKED", workloads=exc.devices, detail="a credential operation is changing a device of this maintenance")]
    except IntegrityError:
        held = sorted(models.ExecutionDeviceLock.objects.filter(device__in=wanted).exclude(maintenance=row).values_list("device", flat=True))
        return [model.Finding("DEVICE_LOCKED", workloads=tuple(held), detail="another execution is changing a device of this maintenance")]
    return []


def _unlock(row) -> None:
    from core import models

    models.ExecutionDeviceLock.objects.filter(maintenance=row).delete()


def _watch(env, row, token: str) -> None:
    """Every executor event refreshes the claim's heartbeat and is written to the record's step journal BEFORE the run
    goes on ("before X" ahead of the write, "after X" once it is verified), so that a worker that dies leaves durable
    evidence of exactly where it stopped.  The environment's own observer (if any) still runs."""
    from django.utils import timezone

    original = env.observer

    def observer(event, key):
        _beat(row, token)
        if event in ("before", "after") and key:
            evidence.append(row, kind=evidence.STEP, actor=WORKER, at=timezone.now(), payload={"event": event, "operation": key},
                            state_from="", state_to=row.state, summary=f"{event} {key}")
        if original is not None:
            original(event, key)

    env.observer = observer


def _start_probes(runtime, env, row) -> None:
    """Start the production probes and journal their run id at once: if this worker dies, the recovery can stop exactly
    the probes it left running (they would otherwise double the probe load and read as loss)."""
    from django.utils import timezone

    runtime.start_probes(env)
    run_id = getattr(env.probes, "run_id", "")
    if run_id:
        evidence.append(row, kind=evidence.STEP, actor=WORKER, at=timezone.now(), payload={"event": "probes", "probe_run": run_id},
                        state_from="", state_to=row.state, summary=f"probes {run_id}")


def _halt_dead_probes(env, runs) -> None:
    halt = getattr(env.probes, "halt_run", None)
    for run_id in runs if halt is not None else ():
        try:
            halt(run_id)
        except Exception:  # noqa: BLE001 - a probe that cannot be stopped shows as loss: the restore then refuses, never passes
            pass


def _close(env) -> None:
    try:
        if env.probes is not None:
            env.probes.stop()
    except Exception:  # noqa: BLE001 - evidence is already recorded
        pass
    env.close()


def _platforms(runtime: Runtime) -> dict:
    return {name: (device or {}).get("platform") for name, device in runtime.sources.topology.devices.items()}


def _guard(runtime: Runtime):
    scope, interfaces, platforms = runtime.scope(), runtime.management_interfaces, _platforms(runtime)

    def check(op) -> str:
        found = protection.violations((op,), writable=scope, management_interfaces=interfaces, platforms=platforms)
        return found[0] if found else ""

    return check


# ------------------------------------------------------------------------------------------------------------ before entry
def request(device: str, operator: str, reason: str, duration: timedelta, *, now: datetime, runtime: Runtime):
    """A new maintenance record.  Only a device of the writable managed scope can be requested (R5 cannot)."""
    from core import models

    if device not in runtime.scope():
        raise model.MaintenanceError(protection.OUTSIDE_SCOPE, f"{device} is not in the writable managed scope")
    if device not in runtime.sources.topology.devices:
        raise model.MaintenanceError("DEVICE_NOT_MANAGED", device)
    existing = [store.load(row) for row in models.MaintenanceRecord.objects.filter(device_name=device).exclude(state__in=lifecycle.RESOLVED)]
    row = store.save(lifecycle.request(device, operator, reason, duration, at=now, existing=existing))
    _log(row, evidence.REQUESTED, operator, now, {"device": device, "reason": reason, "requested_duration_seconds": int(duration.total_seconds())},
         summary=f"requested by {operator}")
    return row


def _cells(record) -> tuple:
    return tuple((step.family, step.direction) for step in record.steps)


def _persist(ops) -> tuple:
    return tuple(sorted({op.device for op in ops}))


def _environment(runtime: Runtime):
    """A fresh environment whose core routers are read-only for this maintenance."""
    env = runtime.environment()
    env.executor_factory = executor.read_only(env.executor_factory, runtime.definition.cores)
    return env


def _restore_guards(access: topology.Access, state: dict, active: dict | None = None) -> tuple:
    targets = {core: tuple(entry["target_hop"]) for core, entry in (state.get("cores") or {}).items()}
    guards = [Check(f"{access.router} is healthy enough to take traffic", lambda e: drain.router_healthy(e, access=access, cores=targets), 30)]
    for name in (access.far_switch, access.peer_router):                      # the path that carries the traffic now must be the one that was verified
        digest = (active or {}).get(name) or (state.get("config") or {}).get(name)    # at ACTIVE; for an aborted entry, before the drain
        guards.append(Check(f"{name} is unchanged since the maintenance became active (or, for an aborted entry, since the pre-state was captured)",
                            lambda e, name=name, digest=digest: (digest is not None and e.executors[name].config_state_digest() == digest, "running configuration differs"), 0))
    return tuple(guards)


def _plan_document(row, request_, report, observation, runtime: Runtime, *, now: datetime, env=None):
    """The plan of ``report`` (READY): -> (document, findings, captured state, drain operations).  Reads the devices
    through executor sessions (``drain.capture``) when something has to move; writes nothing.  ``findings`` non-empty:
    no executable plan exists."""
    steps = plan.build(report)
    cells = [(s.family, s.direction) for s in steps]
    access, definition = observation.access, runtime.definition
    state, ops, back, drain_final, back_final, guards, problems = {}, [], [], (), (), (), []
    if cells and access is None:
        problems.append(_finding("TOPOLOGY_NOT_DERIVED", observation.facts.get("access_not_derived", "")))
    elif cells:
        own = env is None
        env = env or _environment(runtime)
        try:
            if own:
                env.connect(definition.devices)
            state, issues = drain.capture(env, access, definition)
        except ExecutorError as exc:
            issues = [f"LIVE_EVIDENCE_UNAVAILABLE: {exc.code}"]
        finally:
            if own:
                _close(env)
        problems += [_from_text(text) for text in issues]
        if not issues:
            ops = drain.operations(access, definition, state, cells, drain=True)
            back = drain.operations(access, definition, state, cells, drain=False)
            drain_final, back_final = drain.final_checks(access, definition, state, cells, drain=True), drain.final_checks(access, definition, state, cells, drain=False)
            guards = _restore_guards(access, state)
    problems += _not_fresh(observation, now)
    scope = runtime.scope()
    problems += [_from_text(text) for text in protection.violations([*ops, *back], writable=scope, management_interfaces=runtime.management_interfaces,
                                                                    platforms=_platforms(runtime))]
    summary = observation.summary()
    document = plan.document(
        record_id=row.record_id, request=request_, role=observation.role, report=report, steps=steps, observation=summary, state=state,
        drain_ops=ops, drain_final=drain_final, drain_persist=_persist(ops), restore_ops=back, restore_guards=guards, restore_final=back_final,
        restore_persist=(access.switch, access.router) if ops else (), mechanisms=summary["mechanisms"],
        protected={"management_vlan": protection.MANAGEMENT_VLAN, "writable_scope": sorted(scope),
                   "management_interfaces": {name: list(ports) for name, ports in sorted(runtime.management_interfaces.items())}},
        built_at=now, validity=PLAN_VALIDITY)
    return document, problems, state, ops


NOT_FRESH = "OBSERVATION_NOT_FRESH"


def _not_fresh(observation, now: datetime) -> list:
    """The device and every device its traffic depends on must have been read FRESH (``health.thresholds``) at ``now``:
    a plan is never built, nor an entry made, from evidence that is stale, expired or unknown."""
    from ..health import thresholds

    try:
        limits = thresholds.load_thresholds()["freshness"]
    except Exception:  # noqa: BLE001 - no thresholds: freshness is not established
        return [_finding(NOT_FRESH, "the freshness thresholds could not be read")]
    found = collector.freshness(observation.summary(), now=now, thresholds=limits)
    related = sorted({observation.device, *observation.intersects})
    stale = [f"{name} {found.get(name, 'UNKNOWN')}" for name in related if found.get(name) != "FRESH"]
    return [model.Finding(NOT_FRESH, workloads=tuple(name.split()[0] for name in stale), detail=", ".join(stale))] if stale else []


def _report_doc(report) -> dict:
    return {"ready": report.ready, "cells": {f"{f}/{d}": {**cell, "active": list(cell["active"])} for (f, d), cell in report.cells.items()},
            "blockers": _findings(report.blockers), "notes": _findings(report.notes)}


def _refuse_if_queued(row) -> None:
    """A step run directly (the operator's command) is refused while an operator request waits for the worker."""
    if row.queued_action:
        raise model.MaintenanceError("RECORD_BUSY", f"{row.record_id} has a queued {row.queued_action} request; cancel it or let the worker run it")


def evaluate(record_id, actor: str = WORKER, *, now: datetime, runtime: Runtime):
    """Observe the network (read-only), form the readiness verdict and, when ready, the immutable plan (read-only capture)."""
    row = _row(record_id)
    _refuse_if_queued(row)
    token = _claim(row, EVALUATE, at=now)
    try:
        return _evaluate(row, actor, now=now, runtime=runtime)
    finally:
        _release(row, token)


def _evaluate(row, actor: str, *, now: datetime, runtime: Runtime):
    record = store.load(row)
    before = record.state
    observation = collector.observe(record.request.device, runtime.sources)
    summary = observation.summary()
    record.evaluate(observation.flows, observation.dependencies, at=now, alternates=observation.alternates, mechanisms=observation.mechanisms)
    record.evidence = {"observation": summary}
    row.plan_status, row.plan_hash = (plan.SUPERSEDED if row.plan_hash else ""), ""
    store.save(record, row)
    _log(row, evidence.OBSERVED, actor, now, {"observation": summary, "report": _report_doc(record.report)}, before=before,
         summary=f"readiness {'READY' if record.report.ready else 'BLOCKED'}")
    if not record.report.ready:
        return row
    document, problems, _state, _ops = _plan_document(row, record.request, record.report, observation, runtime, now=now)
    if problems:
        record.refuse_plan(problems, at=now)
        store.save(record, row)
        _log(row, evidence.REFUSED, "nmas", now, {"findings": _findings(problems), "plan": document}, before=lifecycle.READY, summary="no executable plan")
        return row
    record.build_plan(at=now)
    record.plan = document
    row.plan_hash, row.plan_status = plan.digest(document), plan.CURRENT
    store.save(record, row)
    _log(row, evidence.PLANNED, "nmas", now, {"plan": document, "plan_hash": row.plan_hash}, before=lifecycle.READY,
         summary=f"plan {row.plan_hash[:12]}: {len(document['drain']['operations'])} drain / {len(document['restore']['operations'])} restore operation(s)")
    return row


def approve(record_id, approver: str, *, now: datetime, plan_hash: str):
    """Approve exactly the plan the approver reviewed: ``plan_hash`` must be the current plan's hash."""
    row = _row(record_id)
    _refuse_if_busy(row)
    record = store.load(row)
    if not plan_hash or plan_hash != row.plan_hash:
        raise model.MaintenanceError("PLAN_HASH_MISMATCH", "the plan was replaced after it was shown; review the current plan")
    if row.plan_status != plan.CURRENT:
        raise model.MaintenanceError("PLAN_NOT_CURRENT", row.plan_status or "no plan")
    if now > datetime.fromisoformat(record.plan["valid_until"]):
        raise model.MaintenanceError(plan.PLAN_EXPIRED, "evaluate readiness again")
    before = record.state
    record.approve(approver, at=now)
    store.save(record, row)
    _log(row, evidence.APPROVED, approver, now, {"plan_hash": row.plan_hash, "approver": approver}, before=before, summary=f"plan {row.plan_hash[:12]} approved by {approver}")
    return row


def cancel(record_id, actor: str, *, now: datetime):
    from core import models

    row = _row(record_id)
    _refuse_if_busy(row)
    record = store.load(row)
    before = record.state
    record.cancel(actor, at=now)
    store.save(record, row)
    models.MaintenanceRecord.objects.filter(pk=row.pk, claim_token="").update(queued_action="", queued_by="", queued_at=None)
    row.refresh_from_db()
    _log(row, evidence.TRANSITION, actor, now, {"reason": "cancelled before entry"}, before=before, summary=f"cancelled by {actor}")
    return row


def queue(record_id, action: str, actor: str, *, now: datetime, plan_hash: str = ""):
    """An explicit operator request for the worker: EVALUATE, ENTER (of exactly the approved plan) or RESTORE.  Nothing
    is contacted here; one request at a time per record."""
    from core import models

    row = _row(record_id)
    if action not in QUEUEABLE:
        raise model.MaintenanceError("ACTION_UNKNOWN", action)
    record = store.load(row)
    if record.state not in QUEUE_STATES[action]:
        raise model.MaintenanceError("STATE_NOT_ALLOWED", f"{record.state}; {action} needs {' or '.join(QUEUE_STATES[action])}")
    if action == ENTER and (not plan_hash or plan_hash != row.plan_hash or row.plan_status != plan.CURRENT):
        raise model.MaintenanceError("PLAN_HASH_MISMATCH", "enter only the plan that was approved")
    if models.MaintenanceRecord.objects.filter(pk=row.pk, queued_action="", claim_token="", state=record.state).update(
            queued_action=action, queued_by=actor[:150], queued_at=now) != 1:
        raise model.MaintenanceError("RECORD_BUSY", f"{row.record_id} already has a queued request or is being worked on")
    row.refresh_from_db()
    _log(row, evidence.QUEUED, actor, now, {"action": action, "plan_hash": plan_hash or row.plan_hash}, summary=f"{action} queued by {actor}")
    return row


# ------------------------------------------------------------------------------------------------------------------- entry
def _verdicts(report) -> dict:
    return {key: (cell["verdict"], cell["mechanism"]) for key, cell in report.cells.items()}


def _moved(observation, cells) -> dict:
    """cell -> every production flow of the cell now avoids the device, on a path that was followed to its end."""
    return {cell: all(flow.on_device is False for flow in observation.flows if flow.cell == cell and flow.traffic_class == model.PRODUCTION)
            for cell in cells}


def _remaining(env, access, cells=None) -> tuple:
    """Every maintenance-only statement on a device right now (read from the devices): the drain metrics and any shield."""
    lines = drain.maintenance_lines(access)
    switch = sorted({*drain.present_lines(env, access.switch, lines[:2]), *drain.present_lines(env, access.switch, drain.shield_lines(access))})
    return tuple([f"{access.switch}: {path}" for path in switch] + [f"{access.router}: {path}" for path in drain.present_lines(env, access.router, lines[2:])])


UNCERTAIN = "INTERRUPTED_STAGE_STATE_PRESENT"


def _uncertain(env, access) -> tuple:
    """The drain's own temporary shield, still on the switch: the drain was interrupted inside a stage.  No restore is
    built for that state; it is escalated with nothing written, never guessed away."""
    return tuple(drain.present_lines(env, access.switch, drain.drain_shield_lines(access)))


def enter(record_id, actor: str, *, now, runtime: Runtime):
    """Drain the device and, only when every planned direction is proven clear with zero loss, mark it ACTIVE.
    ``now`` is a callable: the run takes minutes and every transition carries its own time."""
    row = _row(record_id)
    _refuse_if_queued(row)
    token = _claim(row, ENTER, at=now())
    try:
        return _enter(row, actor, now=now, runtime=runtime, token=token)
    finally:
        _unlock(row)
        _release(row, token)


def _enter(row, actor: str, *, now, runtime: Runtime, token: str):
    record = store.load(row)
    record._require(lifecycle.APPROVED)
    device, cells, approved = record.request.device, _cells(record), dict(record.plan)
    fresh = collector.observe(device, runtime.sources)
    report = readiness.evaluate(record.request, fresh.flows, fresh.dependencies, alternates=fresh.alternates, mechanisms=fresh.mechanisms)
    extra = []
    if runtime.gated:
        for step in record.steps:
            refused = shield_readiness.refusal(READINESS_KEY.get(step.mechanism, ""))
            if refused:
                extra.append(_finding(refused.split(":")[0], f"{step.mechanism} may not be executed on the managed network"))
    if cells and fresh.access is None:
        extra.append(_finding("TOPOLOGY_NOT_DERIVED", fresh.facts.get("access_not_derived", "")))
    env = _environment(runtime)
    _watch(env, row, token)
    state, ops, doc, healthy, lost, out_of_band, run, stale = {}, [], None, None, None, None, None, []
    try:
        if not extra:
            env.connect(runtime.definition.devices if cells else ())
            if report.ready:                                                      # the plan built again, from the facts of this moment
                doc, problems, state, ops = _plan_document(row, record.request, report, fresh, runtime, now=now(), env=env)
                extra += problems
            stale = plan.staleness(approved, doc if doc is not None and not extra else None, now=now())
            extra += stale
            if not extra:
                _start_probes(runtime, env, row)
                runtime.sleep(runtime.probe_warmup)
                healthy, lost = bool(env.probes.healthy()[0]), int(env.probes.lost())
                out_of_band = False
                if cells:
                    out_of_band = bool(_remaining(env, fresh.access))
                    env.baseline = state["cores"]
                    run = executor.Run(env, ops, persist=_persist(ops), final=drain.final_checks(fresh.access, runtime.definition, state, cells, drain=True),
                                       guard=_guard(runtime))
                    extra += [_finding(b["code"], b["detail"]) for b in run.precheck() if b["code"] != shield_gates.PROBES_UNHEALTHY]
                    if not extra:
                        extra += _lock(row, {device} | {op.device for op in ops} | set(run.persist))
                else:                                                             # nothing to write, but the target is still reserved:
                    extra += _lock(row, {device})                                 # a Change that holds it right now refuses the entry
        facts = gates.Facts(
            readiness_current=report.ready and _verdicts(report) == _verdicts(record.report),
            probes_healthy=healthy, probes_lost=lost, out_of_band_change=out_of_band,
            baseline_fresh=doc is not None and not stale and None not in fresh.facts["digests"].values(),
            prior_unresolved=store.prior_unresolved(device, intersects=fresh.intersects))
        try:
            record.begin_enter(facts, at=now(), actor=actor, precheck=extra)
        except model.MaintenanceError:
            if stale:
                row.plan_status = plan.STALE
            record.evidence["refused_entry"] = {"at": now().isoformat(), "codes": sorted({f.code for f in record.findings})}
            store.save(record, row)
            _log(row, evidence.REFUSED, actor, now(), {"findings": _findings(record.findings), "observation": fresh.summary(), "precheck": run.stages if run else [],
                                                        "fresh_plan_hash": plan.digest(doc) if doc else ""}, summary="entry refused")
            raise
        record.evidence.update(prestate=state, entry_observation=fresh.summary())
        store.save(record, row)                                                   # the pre-state is stored before the first write
        _log(row, evidence.TRANSITION, actor, now(), {"plan_hash": row.plan_hash, "prestate": state}, before=lifecycle.APPROVED)
        if run is None:                                                           # nothing has to move: every cell is clear
            record.confirm_active((), at=now())
            store.save(record, row)
            _log(row, evidence.ENTRY, "nmas", now(), {"outcome": "NOTHING_TO_MOVE", "cells": _report_doc(report)["cells"]}, before=lifecycle.ENTERING)
            return row
        outcome = run.drive()
        record.evidence["entry"] = run.report(outcome)
        proofs = []
        if outcome == executor.SUCCEEDED:
            after = collector.observe(device, runtime.sources)
            moved = _moved(after, cells)
            record.evidence["entry"]["after"] = {"paths": after.facts["paths"], "alternates": after.summary()["alternates"]}
            proofs = [model.DrainProof(family, direction, moved[(family, direction)], run.lost(), after.alternates.get((family, direction)),
                                       "" if moved[(family, direction)] else "a production flow still passes the device")
                      for family, direction in cells]
        record.evidence["entry"]["proofs"] = [proof.__dict__ for proof in proofs]
        try:
            record.confirm_active(proofs, at=now(), maintenance_only_state=_remaining(env, fresh.access))
            record.evidence["active_digests"] = {name: env.executors[name].config_state_digest() for name in (fresh.access.switch, fresh.access.far_switch, fresh.access.peer_router)}
            store.save(record, row)
            _log(row, evidence.ENTRY, "nmas", now(), {"run": record.evidence["entry"], "active_digests": record.evidence["active_digests"],
                                                       "maintenance_only_state": list(record.maintenance_only_state)}, before=lifecycle.ENTERING,
                 summary=f"ACTIVE: {len(run.applied)} operation(s), {run.probes_lost} probe(s) lost")
            return row
        except model.MaintenanceError as refused:
            record.evidence["entry"]["aborted"] = str(refused)[:500]
            _log(row, evidence.ENTRY, "nmas", now(), {"run": record.evidence["entry"], "findings": _findings(record.findings)}, summary="entry aborted")
            if outcome == executor.SUCCEEDED:                                     # drained but not proven clear: take it back out, shielded
                store.save(record, row)
                _log(row, evidence.TRANSITION, "nmas", now(), {"trigger": lifecycle.ENTRY_ABORT}, before=lifecycle.ENTERING)
                return _restore(record, row, runtime, now, env=env)
            left = _remaining(env, fresh.access)
            failed = [] if run.restored and not left else [_finding("ENTRY_COMPENSATION_INCOMPLETE", str(run.failure.get("detail", "")))]
            if not failed:
                failed = _verify_restored(record, runtime)
            record.finish_restore(at=now(), restore_findings=failed, remaining=left, baseline_untrusted=any(f.code == "ENTRY_COMPENSATION_INCOMPLETE" for f in failed))
            store.save(record, row)
            _log(row, evidence.RESTORE, "nmas", now(), {"compensation": run.compensation, "findings": _findings(failed), "remaining": list(left),
                                                         "verification": record.evidence.get("restore_verification")}, before=lifecycle.RESTORING)
            raise
    finally:
        _close(env)


# -------------------------------------------------------------------------------------------------------- exit and restore
def leave(record_id, actor: str, *, now, runtime: Runtime):
    """Manual exit: ACTIVE -> RESTORING -> the captured forwarding state restored and validated -> RESTORED.  On an
    escalated record an operator runs the restore again; an interrupted restore is simply run again."""
    row = _row(record_id)
    _refuse_if_queued(row)
    token = _claim(row, RESTORE, at=now())
    try:
        return _leave(row, actor, now=now, runtime=runtime, token=token)
    finally:
        _unlock(row)
        _release(row, token)


def _leave(row, actor: str, *, now, runtime: Runtime, token: str, trigger: str = lifecycle.MANUAL_EXIT):
    record = store.load(row)
    before = record.state
    if record.state == lifecycle.RESTORE_FAILED:
        record.retry_restore(actor, at=now())
    elif record.state == lifecycle.ACTIVE and trigger == DEADLINE:
        if not record.on_deadline(now=now()):
            raise model.MaintenanceError("DEADLINE_NOT_DUE", row.record_id)
    elif record.state != lifecycle.RESTORING:
        record.request_exit(actor, at=now())
    store.save(record, row)
    if before != record.state:
        _log(row, evidence.TRANSITION, actor if trigger != DEADLINE else "nmas", now(), {"trigger": record.restore_trigger}, before=before)
    return _restore(record, row, runtime, now, token=token)


def _restore(record, row, runtime: Runtime, now, env=None, token: str = "", dead_probes=()):
    """Put back exactly what the stored pre-maintenance state says, or fail closed into RESTORE_FAILED_ESCALATED with
    the drained state still in place.  The device is offered traffic only after it is verified healthy, and the record is
    RESTORED only after a fresh observation shows the baseline's adjacencies, interfaces, paths and dependencies back."""
    state, cells = record.evidence.get("prestate") or {}, _cells(record)
    findings, left, report = [], record.maintenance_only_state, None
    if cells and not state:                                                       # steps without a stored pre-state: nothing can be reversed exactly
        findings, left = [_finding("PRE_STATE_MISSING")], record.maintenance_only_state or ("unknown",)
    elif cells:
        access = topology.Access(**{k: tuple(v) if isinstance(v, list) else v for k, v in state["access"].items()})
        definition, own = runtime.definition, env is None
        env = env or _environment(runtime)
        if token:
            _watch(env, row, token)
        try:
            if own:
                env.connect(definition.devices)
                _halt_dead_probes(env, dead_probes)                       # a dead worker's probes would read as loss
                _start_probes(runtime, env, row)
                runtime.sleep(runtime.probe_warmup)
            env.baseline = state["cores"]
            ops = drain.operations(access, definition, state, cells, drain=False)
            run = executor.Run(env, ops, persist=(access.switch, access.router), prechecks=_restore_guards(access, state, record.evidence.get("active_digests")),
                               resume=True, final=drain.final_checks(access, definition, state, cells, drain=False), guard=_guard(runtime),
                               startup_accepted=dict(state.get("startup") or {}))     # an aborted entry: the startup is still the pre-state
            left_mid_stage = _uncertain(env, access)
            blockers = [_finding(UNCERTAIN, f"{access.switch}: {', '.join(left_mid_stage)}; remove it by hand (its exact inverse is in the plan), then restore again")] \
                if left_mid_stage else [_finding(b["code"], b["detail"]) for b in run.precheck()]
            blockers += _lock(row, {op.device for op in ops} | set(run.persist)) if not blockers else []
            if blockers:
                findings = blockers                                               # nothing was written: the drained state stays as it is
                report = {"outcome": executor.BLOCKED, "stages": run.stages, "blockers": [f.text() for f in blockers]}
            else:
                outcome = run.drive()
                report = run.report(outcome)
                if outcome != executor.SUCCEEDED:
                    findings = [_finding(run.failure.get("code", "RESTORE_FAILED"), run.failure.get("detail", ""))]
                    if outcome == executor.INCOMPLETE:
                        findings.append(_finding("RESTORE_COMPENSATION_INCOMPLETE", "the device is neither drained nor restored"))
            left = _remaining(env, access)
        except Exception as exc:  # noqa: BLE001 - a restore that cannot even be assessed is an escalation, never a pass
            findings.append(_finding("RESTORE_NOT_ASSESSED", getattr(exc, "code", type(exc).__name__)))
        finally:
            _close(env)
            _unlock(row)
        record.evidence["restore"] = report
    if not findings and not left:
        findings = _verify_restored(record, runtime)
    record.finish_restore(at=now(), restore_findings=findings, remaining=left,
                          baseline_untrusted=any(f.code in ("RESTORE_COMPENSATION_INCOMPLETE", "RESTORE_NOT_ASSESSED", "PRE_STATE_MISSING") for f in findings))
    store.save(record, row)
    _log(row, evidence.RESTORE, "nmas", now(), {"run": report, "findings": _findings(findings), "remaining": list(left),
                                                 "verification": record.evidence.get("restore_verification"), "trigger": record.restore_trigger},
         before=lifecycle.RESTORING, summary=f"{record.state} ({record.restore_trigger})")
    return row


def _verify_restored(record, runtime: Runtime) -> list:
    """A fresh read-only observation against the pre-maintenance one: every device that was reachable is (management
    reachability), every adjacency is back, every production interface that was up is up, every flow that passed the
    device does again and every path is followed to its end, and no dependency is stranded that was not.  -> findings."""
    base = record.evidence.get("entry_observation") or record.evidence.get("observation") or {}
    found, after = [], None
    for attempt in range(VERIFY_ATTEMPTS):
        try:
            after = collector.observe(record.request.device, runtime.sources)
        except Exception as exc:  # noqa: BLE001 - not verified is never verified
            found = [_finding("RESTORE_NOT_VERIFIED", getattr(exc, "code", type(exc).__name__))]
            after = None
        if after is not None:
            found = _compare(base, after)
        if not found:
            break
        if attempt + 1 < VERIFY_ATTEMPTS:
            runtime.sleep(VERIFY_PAUSE)
    record.evidence["restore_verification"] = {"attempts": attempt + 1, "findings": _findings(found),
                                               "observation": after.summary() if after is not None else None}
    return found


def _compare(base: dict, after) -> list:
    found, facts = [], after.facts
    for name, before in sorted((base.get("protocols") or {}).items()):
        now_ = (facts.get("protocols") or {}).get(name) or {}
        if before.get("reachable") and not now_.get("reachable"):
            found.append(model.Finding("DEVICE_NOT_REACHABLE", workloads=(name,), detail="no longer reachable through its management path"))
            continue
        for key in ("isis_up", "ospfv3_full", "ospfv2_full", "rip_neighbors"):
            if before.get(key) is not None and now_.get(key) != before.get(key):
                found.append(model.Finding("ADJACENCY_NOT_RESTORED", workloads=(name,), detail=f"{key}: {before.get(key)} -> {now_.get(key)}"))
    for name, before in sorted((base.get("interfaces") or {}).items()):
        now_ = (facts.get("interfaces") or {}).get(name) or {}
        for interface, oper in sorted((before or {}).items()):
            if oper == "UP" and now_.get(interface) != "UP":
                found.append(model.Finding("INTERFACE_NOT_RESTORED", workloads=(name,), detail=f"{interface} is {now_.get(interface) or 'unreadable'}"))
    for label, before in sorted((base.get("paths") or {}).items()):
        now_ = (facts.get("paths") or {}).get(label) or {}
        if before.get("on_device") is True and now_.get("on_device") is not True:
            found.append(model.Finding("PATH_NOT_RESTORED", workloads=(label,), detail=f"was {before.get('path')}, now {now_.get('path')}"))
        elif before.get("complete") and not now_.get("complete"):
            found.append(model.Finding("PATH_NOT_RESTORED", workloads=(label,), detail=f"the path cannot be followed: {now_.get('path')}"))
    stranded = {row["name"]: row.get("stranded") for row in base.get("dependencies") or []}
    for dependency in after.dependencies:
        if dependency.critical and stranded.get(dependency.name) is False and dependency.stranded is not False:
            found.append(model.Finding("DEPENDENCY_NOT_RESTORED", workloads=(dependency.name,), detail=dependency.detail or "not established"))
    return found


# ------------------------------------------------------------------------------------------------------------------ worker
def tick(*, now, runtime_factory=None) -> list[dict]:
    """One pass of the maintenance worker.  Idempotent; every item is claimed first, so concurrent ticks never act twice.

    1. recover: an ENTERING / RESTORING record nobody holds any more (a stale claim or none): an interrupted entry is
       aborted and restored, an interrupted restore is run again;
    2. queued operator requests: EVALUATE, ENTER, RESTORE;
    3. the deadline: every ACTIVE maintenance whose 7-day safety deadline has passed gets the restore workflow.
    The end of the requested window starts nothing.  The runtime (NetBox scope, inventory, cabling) is built only when
    there is something to do.  -> one result row per item acted on."""
    from django.db.models import Q

    from core import models

    built, factory = {}, runtime_factory or production_runtime

    def runtime():
        if "rt" not in built:
            built["rt"] = factory()
        return built["rt"]

    results, moment = [], now()
    stale = Q(claim_token="") | Q(heartbeat_at__lt=moment - CLAIM_STALE_AFTER)
    for row in models.MaintenanceRecord.objects.filter(stale, state__in=(lifecycle.ENTERING, lifecycle.RESTORING)).order_by("pk"):
        results.append(_item(row, RECOVER, now=now, runtime=runtime))
    for row in models.MaintenanceRecord.objects.filter(~Q(claim_token=""), heartbeat_at__lt=moment - CLAIM_STALE_AFTER).exclude(
            state__in=(lifecycle.ENTERING, lifecycle.RESTORING)).order_by("pk"):
        if models.MaintenanceRecord.objects.filter(pk=row.pk, claim_token=row.claim_token).update(claim_token="", claim_action="", claimed_at=None, heartbeat_at=None):
            _log(row, evidence.CLAIM, WORKER, now(), {"released": row.claim_action, "heartbeat_at": row.heartbeat_at}, summary=f"stale {row.claim_action} claim released")
            results.append({"record": row.record_id, "item": "STALE_CLAIM", "state": row.state, "outcome": "RELEASED"})
    for row in models.MaintenanceRecord.objects.filter(claim_token="").exclude(queued_action="").order_by("queued_at", "pk"):
        results.append(_item(row, row.queued_action, now=now, runtime=runtime))
    for row in models.MaintenanceRecord.objects.filter(claim_token="", state=lifecycle.ACTIVE, deadline_at__lte=moment).order_by("deadline_at", "pk"):
        results.append(_item(row, DEADLINE, now=now, runtime=runtime))
    return results


def _item(row, item: str, *, now, runtime) -> dict:
    """Claim ``row`` and perform ``item``.  A refusal is a result, never an exception out of the worker."""
    from core import models

    queued_by = row.queued_by
    try:
        if item == RECOVER and row.claim_token:                                   # take over a stale claim, conditionally: only one tick can
            token = uuid.uuid4().hex
            if models.MaintenanceRecord.objects.filter(pk=row.pk, claim_token=row.claim_token, heartbeat_at=row.heartbeat_at).update(
                    claim_token=token, claim_action=RECOVER, claimed_at=now(), heartbeat_at=now()) != 1:
                return {"record": row.record_id, "item": item, "state": row.state, "outcome": "SKIPPED_BUSY"}
            row.refresh_from_db()
        else:
            token = _claim(row, item, at=now())
    except model.MaintenanceError as busy:
        return {"record": row.record_id, "item": item, "state": row.state, "outcome": busy.code}
    try:
        if item in QUEUEABLE:
            models.MaintenanceRecord.objects.filter(pk=row.pk, claim_token=token).update(queued_action="", queued_by="", queued_at=None)
            row.refresh_from_db()
        actor = queued_by or WORKER
        rt = runtime()
        if item == EVALUATE:
            _evaluate(row, actor, now=now(), runtime=rt)
        elif item == ENTER:
            _enter(row, actor, now=now, runtime=rt, token=token)
        elif item == RESTORE:
            _leave(row, actor, now=now, runtime=rt, token=token)
        elif item == DEADLINE:
            _leave(row, WORKER, now=now, runtime=rt, token=token, trigger=DEADLINE)
        elif item == RECOVER:
            record = store.load(row)
            where = evidence.journal(row)
            if record.state == lifecycle.ENTERING:
                record.interrupt(at=now(), detail=f"the worker that held the entry stopped; journal: {where['last'] or 'no step begun'}"
                                                  + (f"; {where['open']} was begun and not finished (unknown completion)" if where["open"] else ""))
                store.save(record, row)
                _log(row, evidence.TRANSITION, WORKER, now(), {"findings": _findings(record.findings), "journal": where}, before=lifecycle.ENTERING,
                     summary="entry interrupted")
            else:
                _log(row, evidence.CLAIM, WORKER, now(), {"recovered": "restore interrupted", "journal": where}, summary="restore interrupted: run again")
            _restore(record, row, rt, now, token=token, dead_probes=where.get("probe_runs") or ())
        row.refresh_from_db()
        return {"record": row.record_id, "item": item, "state": row.state, "outcome": "DONE", "escalated": row.escalated}
    except model.MaintenanceError as refused:
        row.refresh_from_db()
        return {"record": row.record_id, "item": item, "state": row.state, "outcome": refused.code, "detail": str(refused)[:300]}
    finally:
        _unlock(row)
        _release(row, token)


# ------------------------------------------------------------------------------------------------------ conflicting Changes
def conflict(device: str) -> str:
    """Why a Change that targets ``device`` must not be executed now, or ''.

    Refused: any Change on a device that is itself in maintenance (ENTERING, ACTIVE, RESTORING,
    RESTORE_FAILED_ESCALATED), whatever its plan holds: the restore puts back and verifies the state captured at entry, so
    a Change in between would be overwritten or read as a failed restore.  A plan with no step reserves its target all
    the same.  Also refused: any Change on a device that carries another device's drained traffic or its drain statements
    while that maintenance is unresolved.  Every other device is unaffected."""
    for record in store.under_maintenance():
        target = record.request.device
        # only a maintenance that moved traffic leans on other devices
        protecting = ((record.plan.get("baseline") or {}).get("intersects") or (record.evidence.get("entry_observation") or {}).get("intersects") or ()) if record.steps else ()
        if device == target:
            return f"{device} is {record.state} in maintenance; no Change may run on it until it is restored"
        if device != target and device in protecting:
            return f"{device} carries the traffic or the drain state of {target}, which is {record.state} in maintenance"
    return ""


def status(record_id, *, now: datetime) -> dict:
    row = _row(record_id)
    record = store.load(row)
    from . import visibility

    observation = record.evidence.get("observation") or {}
    return {"id": row.record_id, **visibility.status(record, now=now), "plan_hash": row.plan_hash, "plan_status": row.plan_status,
            "queued": {"action": row.queued_action, "by": row.queued_by, "at": row.queued_at} if row.queued_action else None,
            "claimed": {"action": row.claim_action, "at": row.claimed_at, "heartbeat": row.heartbeat_at} if row.claim_token else None,
            "steps": [f"{s.family} {s.direction}: {s.mechanism}" for s in record.steps],
            "cells": {f"{family}/{direction}": cell["verdict"] for (family, direction), cell in (record.report.cells.items() if record.report else ())},
            "flows": readiness.flow_rows(record.report, observation) if record.report and observation else [],
            "history": [f"{entry['at'].isoformat()} {entry['from'] or '-'} -> {entry['to']} ({entry['actor']}) {entry['note']}"[:300] for entry in record.history]}
