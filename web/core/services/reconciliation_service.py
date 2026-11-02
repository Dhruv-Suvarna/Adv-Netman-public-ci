"""Append-only state reconciliation: accept the observed state of a device as NMAS's expected baseline.

NMAS history is true history.  When a device was changed or restored outside NMAS, the result of its last execution runs
no longer describes it -- and nothing here edits a Change, an ExecutionRun, a Configlet, a validation or a postcheck to
pretend otherwise.  A :class:`core.models.StateReconciliation` only states that the resulting state of the named runs is
no longer the accepted baseline, and pins what was observed instead.

Three jobs, each explicit:

* :func:`observe`                read one device (read-only, the soak's own sanitized digests plus the startup configuration)
* :func:`accept`                 record the observed state as the baseline -- one database row and one audit event, no device write
* :func:`project_netbox_status`  set ONE NetBox device status because a reconciliation record says so -- never inferred
                                 from interface state

Only digests and references are stored.  Configuration text is sanitized before hashing and never kept.  This module
has no maintenance state and is not Maintenance Mode.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime

from django.db import IntegrityError, transaction
from django.utils import timezone

from .. import models
from .bundles.legacy_sanitize import SanitizeError, sanitize_config
from .health import inventory, live
from .identity.policy import Action, user_can
from .soak import config_state

SCHEMA = 1
STARTUP_ARGV = ("Cli", "-p", "15", "-c", "show startup-config")   # fixed, read-only
NETBOX_STATUSES = frozenset({"active", "offline", "planned", "staged", "failed", "decommissioning", "inventory"})
_STARTUP_HEADER = ("! Command:", "! Startup-config last modified", "> show ")


class ReconciliationError(Exception):
    """A refused reconciliation.  ``code`` is stable; nothing was written."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def _digest(document) -> str:
    return hashlib.sha256(json.dumps(document, sort_keys=True, default=str).encode()).hexdigest()


def _config_body(text: str) -> str:
    """The configuration without the lines that differ between ``show running-config`` and ``show startup-config`` by construction."""
    return "\n".join(line.rstrip() for line in text.splitlines() if line.strip() and not line.startswith(_STARTUP_HEADER))


def _read_startup(device: dict) -> tuple[str, str]:
    """-> (sanitized text, error code).  cEOS only; the text never leaves :func:`observe`."""
    if device.get("platform") != "ceos" or not device.get("container"):
        return "", "STARTUP_NOT_SUPPORTED"
    try:
        raw = live._docker_exec(device["container"], list(STARTUP_ARGV), timeout=30, probe=False)
        return sanitize_config(str(raw)).text, ""
    except (SanitizeError, ValueError):
        return "", "STARTUP_UNPARSEABLE"
    except Exception:  # noqa: BLE001 - an unreadable startup configuration is missing evidence, never an exception
        return "", "STARTUP_READ_FAILED"


def observe(device_name: str, *, session_factory=None, startup_reader=None, now: datetime | None = None) -> dict:
    """Read one managed device.  Read-only; writes nothing anywhere.

    -> {"device", "state": OK|UNAVAILABLE, "digest", "sections", "startup_digest", "running_matches_startup", "error", "observed_at"}
    """
    now = now or timezone.now()
    device = inventory.get_managed_device(device_name)
    running = config_state.read_device(device_name, session_factory=session_factory, now=now)
    result = {"device": device_name, "state": running["state"], "digest": running["digest"], "sections": running["sections"],
              "startup_digest": "", "running_matches_startup": None, "error": running["error"], "observed_at": now.isoformat()}
    if running["state"] != config_state.OK or device is None:
        return result
    text, error = (startup_reader or _read_startup)(device)
    if error:
        result["evidence_gap"] = error
        return result
    body = _config_body(text)
    result["startup_digest"] = hashlib.sha256(body.encode()).hexdigest()
    running_body = _running_body(device, session_factory=session_factory, now=now)
    result["running_matches_startup"] = None if running_body is None else running_body == body
    return result


def _running_body(device: dict, *, session_factory=None, now=None) -> str | None:
    try:
        _evidence, raw, errors = live.read_device_with_raw(
            device, ("running_config",), session_factory=session_factory or config_state.SESSION_FACTORY, now=now)
        if errors or "running_config" not in raw:
            return None
        return _config_body(sanitize_config(str(raw["running_config"])).text)
    except Exception:  # noqa: BLE001
        return None


def _runs_for(device_name: str, run_ids) -> list[models.ChangeExecutionRun]:
    wanted = [str(item) for item in run_ids or []]
    if len(set(wanted)) != len(wanted):
        raise ReconciliationError("DUPLICATE_RUN", "An execution run is referenced twice.")
    by_id = {}
    for run in models.ChangeExecutionRun.objects.select_related("change").all():
        by_id[str(run.run_id)] = run
        by_id[str(run.run_id).replace("-", "")] = run
    runs = []
    for item in wanted:
        run = by_id.get(item) or by_id.get(item.replace("-", ""))
        if run is None:
            raise ReconciliationError("UNKNOWN_RUN", f"Execution run {item} does not exist.")
        if run.state != models.ExecutionRunState.FINISHED:
            raise ReconciliationError("RUN_NOT_FINISHED", f"Execution run {item} has not finished.")
        if device_name not in [str(name) for name in (run.devices or [])]:
            raise ReconciliationError("RUN_NOT_FOR_DEVICE", f"Execution run {item} did not target {device_name}.")
        runs.append(run)
    return runs


def current_baseline(device_name: str) -> models.StateReconciliation | None:
    """The newest accepted reconciliation of a device, or None when NMAS's own history is still the expectation."""
    return models.StateReconciliation.objects.filter(device_name=device_name).order_by("-id").first()


def previous_expectation(device_name: str, runs) -> tuple[str, dict]:
    """What NMAS expected of the device before this reconciliation: -> (digest, basis).

    NMAS stores no full expected configuration, so the expectation is identified by what produced it: the last accepted
    reconciliation (if any) followed by the finished runs being superseded, each pinned by plan hash and outcome.
    """
    prior = current_baseline(device_name)
    basis = {
        "schema": SCHEMA, "device": device_name,
        "prior_reconciliation": {"record_id": prior.record_id, "accepted_digest": prior.accepted_digest} if prior else None,
        "runs": [{"run_id": str(run.run_id), "change_id": run.change.change_id if run.change_id else None, "mode": run.mode,
                  "outcome": run.outcome, "plan_hash": run.plan_hash,
                  "finished_at": run.finished_at.isoformat() if run.finished_at else None} for run in runs],
    }
    return _digest({"domain": "nmas.reconciliation.expected", "value": basis}), basis


def superseding_records(change) -> list[models.StateReconciliation]:
    """Reconciliation records that supersede the effect of any execution run of ``change`` (oldest first).

    Such a Change is history: what it did really happened, but its result is no longer accepted intent, so it must not
    be executed again as if it were.  Read-only; nothing about the Change or its runs is altered.
    """
    run_ids = {str(run_id) for run_id in models.ChangeExecutionRun.objects.filter(change=change).values_list("run_id", flat=True)}
    if not run_ids:
        return []
    return [record for record in models.StateReconciliation.objects.order_by("id") if run_ids & set(record.execution_run_ids or [])]


def change_devices(change) -> set[str]:
    """Every device a Change addresses: its intents, its Configlets and its execution runs."""
    devices = set(models.DeviceIntent.objects.filter(change=change).values_list("device_name", flat=True))
    devices |= set(models.Configlet.objects.filter(change=change).values_list("target_device", flat=True))
    for run_devices in models.ChangeExecutionRun.objects.filter(change=change).values_list("devices", flat=True):
        devices |= {str(name) for name in run_devices or []}
    return {name for name in devices if name}


def predating_records(change) -> list[models.StateReconciliation]:
    """Newest reconciliation record of each device the Change addresses, when that record was accepted AFTER the Change
    was created.

    Such a Change was authored against an expectation that an accepted baseline has since replaced.  It needs no
    reconciliation of its own -- it may never have executed, or may have been rolled back -- but it is not current
    intent either, and executing it would apply stale intent on top of the accepted state.  Read-only.
    """
    found = []
    for device in sorted(change_devices(change)):
        record = current_baseline(device)
        if record is not None and record.created_at > change.created_at:
            found.append(record)
    return found


HISTORY_NEVER_EXECUTED, HISTORY_ROLLED_BACK = "NEVER_EXECUTED", "EXECUTED_AND_ROLLED_BACK"
HISTORY_APPLIED, HISTORY_UNRESOLVED = "APPLIED_BEFORE_BASELINE", "EXECUTION_UNRESOLVED"
PREDATING_REASONS = {
    HISTORY_NEVER_EXECUTED: "It was never executed",
    HISTORY_ROLLED_BACK: "Its only execution was rolled back and left nothing applied",
    HISTORY_APPLIED: "It was applied before that baseline was accepted, so its effect is already part of the accepted state",
    HISTORY_UNRESOLVED: "An earlier execution of it did not finish cleanly",
}


def predating_history(change) -> str:
    """What became of a predating Change, from its own runs.  Read-only; the runs are never altered."""
    from .execution.codes import CLEAN_OUTCOMES, SUCCESS_OUTCOMES, Outcome

    outcomes = [run.outcome for run in models.ChangeExecutionRun.objects.filter(change=change).order_by("id")
                if run.outcome != Outcome.BLOCKED]
    if not outcomes:
        return HISTORY_NEVER_EXECUTED
    if any(outcome in SUCCESS_OUTCOMES for outcome in outcomes):
        return HISTORY_APPLIED
    if all(outcome in CLEAN_OUTCOMES for outcome in outcomes):
        return HISTORY_ROLLED_BACK
    return HISTORY_UNRESOLVED


BASELINE_IN_SYNC, BASELINE_DRIFT, BASELINE_UNAVAILABLE, BASELINE_NONE = "IN_SYNC", "DRIFT", "UNAVAILABLE", "NO_BASELINE"


def baseline_status(device_name: str, *, session_factory=None, now: datetime | None = None) -> dict:
    """Is the device still at the digest its newest reconciliation accepted?  Read-only.

    A reconciliation defines a baseline AT ONE DIGEST; it never switches drift detection off.  Any configuration
    difference from that digest is DRIFT, an unreadable device is UNAVAILABLE (never in sync), and a device without a
    record has NO_BASELINE (never reported as in sync because another device was reconciled).  ``later_runs`` lists
    finished runs that applied to the device after the acceptance: NMAS's own history has moved on from the baseline.
    """
    record = current_baseline(device_name)
    if record is None:
        return {"device": device_name, "status": BASELINE_NONE, "record_id": None, "accepted": "", "current": "",
                "changed_sections": [], "later_runs": []}
    later = [str(run.run_id) for run in models.ChangeExecutionRun.objects.filter(
        state=models.ExecutionRunState.FINISHED, finished_at__gt=record.created_at).exclude(outcome="BLOCKED").order_by("finished_at")
        if device_name in [str(name) for name in (run.devices or [])]]
    current = config_state.read_device(device_name, session_factory=session_factory, now=now or timezone.now())
    result = {"device": device_name, "record_id": record.record_id, "accepted": record.accepted_digest, "current": current.get("digest", ""),
              "changed_sections": [], "later_runs": later}
    if current.get("state") != config_state.OK:
        return {**result, "status": BASELINE_UNAVAILABLE, "error": current.get("error", "")}
    pinned, seen = record.section_digests or {}, current.get("sections") or {}
    result["changed_sections"] = sorted(name for name in set(pinned) | set(seen) if pinned.get(name) != seen.get(name))
    return {**result, "status": BASELINE_IN_SYNC if current["digest"] == record.accepted_digest else BASELINE_DRIFT}


def acknowledgement_phrase(device_name: str, accepted_digest: str) -> str:
    """The exact phrase an actor must supply: it names the device and the digest being accepted, so it cannot be reused."""
    return f"ACCEPT {device_name} {accepted_digest[:12]}"


def _next_record_id() -> str:
    last = models.StateReconciliation.objects.order_by("-id").first()
    return f"REC-{(last.id if last else 0) + 1:06d}"


def accept(*, device_name: str, actor: str, reason: str, acknowledgement: str, execution_run_ids, affected_sections,
           observation: dict, cause: str = models.ReconciliationCause.OUTSIDE_NMAS_RESTORATION, user=None) -> tuple[models.StateReconciliation, bool]:
    """Record the observed state as the expected baseline.  -> (record, created).

    One row and one audit event; no device, NetBox or Git write.  Idempotent: accepting the same observed digest over the
    same previous expectation returns the existing record and writes nothing.
    """
    if user is not None and not user_can(user, Action.APPROVE):
        raise ReconciliationError("PERMISSION_DENIED", "Accepting a baseline requires the existing approve permission.")
    if inventory.get_managed_device(device_name) is None:
        raise ReconciliationError("NOT_MANAGED", f"{device_name} is not a managed device.")
    if not (actor or "").strip() or not (reason or "").strip():
        raise ReconciliationError("ACTOR_AND_REASON_REQUIRED", "An actor and a reason are required.")
    if observation.get("device") != device_name or observation.get("state") != config_state.OK or not observation.get("digest"):
        raise ReconciliationError("OBSERVATION_INCOMPLETE", "The device was not read completely; an unreadable device is never accepted.")
    if observation.get("running_matches_startup") is not True:
        raise ReconciliationError("RUNNING_STARTUP_UNPROVEN", "Running and startup configuration were not proven identical.")
    if acknowledgement != acknowledgement_phrase(device_name, observation["digest"]):
        raise ReconciliationError("ACKNOWLEDGEMENT_MISMATCH", "The acknowledgement does not name this device and this observed digest.")
    sections = sorted({str(item).strip() for item in affected_sections or [] if str(item).strip()})
    if not sections:
        raise ReconciliationError("AFFECTED_SECTIONS_REQUIRED", "Name the configuration sections the superseded runs touched.")
    runs = _runs_for(device_name, execution_run_ids)
    if not runs:
        raise ReconciliationError("RUNS_REQUIRED", "Name the execution runs whose resulting state is superseded.")
    previous_digest, basis = previous_expectation(device_name, runs)
    existing = models.StateReconciliation.objects.filter(
        device_name=device_name, previous_expected_digest=previous_digest, accepted_digest=observation["digest"]).first()
    if existing is not None:
        return existing, False
    prior = current_baseline(device_name)
    if prior is not None and prior.accepted_digest == observation["digest"] and set(prior.execution_run_ids) >= {str(run.run_id) for run in runs}:
        return prior, False

    payload = {
        "device_name": device_name, "cause": cause, "actor": actor.strip()[:150], "reason": reason.strip()[:500],
        "acknowledgement": acknowledgement, "observed_at": observation["observed_at"],
        "previous_expected_digest": previous_digest, "previous_expected_basis": basis,
        "accepted_digest": observation["digest"], "section_digests": dict(observation.get("sections") or {}),
        "startup_digest": observation.get("startup_digest") or "", "affected_sections": sections,
        "execution_run_ids": [str(run.run_id) for run in runs],
        "evidence": {"schema": SCHEMA, "running_matches_startup": True, "source": "config_state.read_device + show startup-config",
                     "configuration_text_stored": False},
    }
    try:
        with transaction.atomic():
            record = models.StateReconciliation(
                record_id=_next_record_id(), record_digest=_digest({"domain": "nmas.reconciliation.record", "value": payload}),
                **{**payload, "observed_at": datetime.fromisoformat(observation["observed_at"])})
            record.save()
            models.AuditEvent.objects.create(
                event_type=models.AuditEventType.STATE_RECONCILIATION_ACCEPTED, object_type="StateReconciliation",
                object_id=record.record_id, actor=record.actor, actor_user=user if getattr(user, "pk", None) else None,
                summary=f"{record.record_id}: {device_name} current state accepted as the expected baseline"[:255], outcome="SUCCESS",
                metadata={"record_id": record.record_id, "device": device_name, "actor": record.actor, "reason": record.reason,
                          "previous_expected_digest": previous_digest, "accepted_digest": record.accepted_digest,
                          "affected_sections": sections, "execution_run_ids": record.execution_run_ids,
                          "observed_at": observation["observed_at"], "cause": cause},
            )
    except IntegrityError:
        winner = models.StateReconciliation.objects.filter(
            device_name=device_name, previous_expected_digest=previous_digest, accepted_digest=observation["digest"]).first()
        if winner is None:
            raise
        return winner, False
    return record, True


def project_netbox_status(*, record: models.StateReconciliation, status: str, actor: str, client, confirm: bool, user=None) -> dict:
    """Set ONE NetBox device status because ``record`` says the device is in service.  Explicit, audited, never inferred.

    The status is given by the caller; interface state is never read here.  Only ``record.device_name`` is touched and only
    its ``status`` field.  -> {"device", "previous", "status", "action": SET|UNCHANGED}
    """
    if user is not None and not user_can(user, Action.APPROVE):
        raise ReconciliationError("PERMISSION_DENIED", "Projecting a status requires the existing approve permission.")
    if status not in NETBOX_STATUSES:
        raise ReconciliationError("UNKNOWN_STATUS", f"{status!r} is not a NetBox device status.")
    if not confirm:
        raise ReconciliationError("CONFIRMATION_REQUIRED", "A NetBox write needs explicit confirmation.")
    if current_baseline(record.device_name) != record:
        raise ReconciliationError("RECORD_SUPERSEDED", "Only the newest reconciliation of a device may project its status.")
    device = client.dcim.devices.get(name=record.device_name)
    if device is None:
        raise ReconciliationError("NETBOX_DEVICE_MISSING", f"NetBox has no device named {record.device_name}.")
    previous = getattr(device.status, "value", None) or str(device.status)
    action = "UNCHANGED"
    if previous != status:
        if not device.update({"status": status}):
            raise ReconciliationError("NETBOX_WRITE_FAILED", "NetBox did not accept the status update.")
        action = "SET"
    result = {"device": record.device_name, "previous": previous, "status": status, "action": action}
    models.AuditEvent.objects.create(
        event_type=models.AuditEventType.NSOT_STATUS_PROJECTED, object_type="StateReconciliation", object_id=record.record_id,
        actor=(actor or "").strip()[:150], actor_user=user if getattr(user, "pk", None) else None, outcome="SUCCESS",
        summary=f"{record.record_id}: NetBox {record.device_name} status {previous} -> {status} ({action})"[:255],
        metadata={"record_id": record.record_id, "source": "explicit reconciliation", "inferred_from_interfaces": False, **result},
    )
    return result
