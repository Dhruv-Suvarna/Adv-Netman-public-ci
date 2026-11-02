"""The pre-execution eligibility gate.  READ-ONLY: it never validates, plans, prechecks, repairs, or contacts a device.

Every question is answered from the persisted Phase-13/14/15 artifacts and the fixed inventory.  A failed condition is a
BLOCKER carrying a stable code, a fixed message and the concrete refresh the operator must perform -- staleness is never
resolved silently ("Do not silently rerun validation / rebuild a plan / ignore a stale precheck").

Reuse, not reimplementation:  validation currency (``change_validation_service``), plan currency (``change_plan_service``),
precheck evidence (``OperationalCheckRun``, mode CHANGE_PRECHECK, written by ``health_service.run_change_precheck``),
requirement verifiability (``health_service.normalize_plan``) and device resolution (``health.inventory``).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from django.utils import timezone

from ... import models
from .. import change_plan_service, change_validation_service as cvs, health_service, network_config_validation as ncv
from .. import reconciliation_service
from ..configuration_validation import service as configuration_validation
from ..health import inventory
from ..provisioning import gate as provisioning_gate, registry as provisioning_registry
from ..raw_configlets import verification as raw_verification
from ..validation.findings import Currency, Status
from . import capability as capability_module
from .codes import (
    EXECUTABLE_LIFECYCLE_STATES, PRECHECK_PERMITS, UAT_ACK_FIELDS, UNRESOLVED_OUTCOMES, Capability, Mode, Outcome, blocker,
    precheck_max_age_seconds,
)
from .scope import ExecutionScope, resolve_scope

NEW_DEVICE = models.DeviceIntentTargetType.NEW_DEVICE


@dataclass
class EligibilityReport:
    change: object
    mode: str
    eligible: bool = False
    blockers: list = field(default_factory=list)
    warnings: list = field(default_factory=list)
    plan: object = None
    validation_run: object = None
    precheck_run: object = None
    scope: ExecutionScope | None = None
    validation_currency: dict | None = None
    network_config_currency: dict | None = None
    plan_currency: dict | None = None
    configlet_rows: list = field(default_factory=list)   # per selected Configlet: capability + notes (for the execute page)
    checked_sources: bool = False

    @property
    def codes(self) -> list[str]:
        return [b["code"] for b in self.blockers]

    def has(self, code: str) -> bool:
        return code in self.codes


def latest_precheck(change):
    return models.OperationalCheckRun.objects.filter(change=change, mode=models.OperationalRunMode.CHANGE_PRECHECK).order_by("-created_at", "-id").first()


def active_runs(*, now: datetime | None = None):
    """Runs holding a live lease.  An expired lease is NOT active (it is reaped at the next acquisition)."""
    return models.ChangeExecutionRun.objects.filter(state=models.ExecutionRunState.RUNNING, lease_expires_at__gt=now or timezone.now())


def _acks_satisfied(acknowledgements) -> bool:
    given = acknowledgements or {}
    return all(bool(given.get(name)) for name, _label in UAT_ACK_FIELDS)


def _prior_run_blockers(change, plan, precheck, now) -> list[dict]:
    found = []
    runs = list(models.ChangeExecutionRun.objects.filter(change=change))
    for run in runs:
        if run.plan_id != plan.pk:
            continue
        abandoned = run.state == models.ExecutionRunState.RUNNING and run.lease_expires_at <= now  # reaped (INTERRUPTED) at the next acquisition
        if run.outcome == Outcome.SUCCEEDED:
            found.append(blocker("PLAN_ALREADY_APPLIED", run_id=str(run.run_id)))
        elif run.outcome in UNRESOLVED_OUTCOMES or abandoned:
            found.append(blocker("PLAN_STATE_UNRESOLVED", run_id=str(run.run_id), outcome=run.outcome or "INTERRUPTED"))
    finished = [r for r in runs if r.state == models.ExecutionRunState.FINISHED]
    if precheck is not None and any(r.outcome != Outcome.BLOCKED and r.started_at >= precheck.finished_at for r in finished):
        found.append(blocker("PRECHECK_BEFORE_LAST_EXECUTION"))
    return found


def _maintenance_conflicts(devices) -> dict:
    """device -> why a Change on it is unsafe while a maintenance is unresolved (``maintenance_mode.service.conflict``)."""
    from django.db import DatabaseError

    from ..maintenance_mode import service as maintenance

    try:
        return {name: reason for name in devices for reason in [maintenance.conflict(name)] if reason}
    except DatabaseError:                    # a deployment whose database has no maintenance table has no maintenance
        return {}


def _management_interface(device: str) -> str:
    entry = ((inventory.load_inventory().get("network_devices") or {}).get(device) or {}).get("monitoring") or {}
    return str(entry.get("source_interface") or "")


def check_execution_eligibility(
    change, *, through_cfg_id: str = "", acknowledgements: dict | None = None, confirm_mode: str | None = None,
    for_submission: bool = True, check_sources: bool = True, sources=None, now: datetime | None = None, exclude_run=None,
) -> EligibilityReport:
    """Evaluate EVERY gate and return all blockers at once.  ``for_submission=False`` (a page view) skips only the
    operator-input gates (mode confirmation, acknowledgements, scope choice), which cannot exist before a POST."""
    now = now or timezone.now()
    mode = change.execution_mode
    report = EligibilityReport(change=change, mode=mode)
    blockers, warnings = report.blockers, report.warnings

    # 1. lifecycle + mode ------------------------------------------------------------------------------------------------
    if change.lifecycle_state not in EXECUTABLE_LIFECYCLE_STATES:
        blockers.append(blocker("CHANGE_LIFECYCLE_NOT_EXECUTABLE", state=change.lifecycle_state))
    if (change.metadata or {}).get("archived_at"):
        blockers.append(blocker("CHANGE_ARCHIVED"))
    # A routing transition (core/services/route_shield/lifecycle.py) interleaves temporary shields, verification and waits
    # between its Configlets.  Applying its plan as a plain list would drop traffic: no input lifts this.
    if ((change.metadata or {}).get("transition") or {}).get("kind"):
        blockers.append(blocker("TRANSITION_CHANGE_NOT_GENERIC"))
    # A Change whose executed effect a reconciliation record superseded is history, not intent.  No acknowledgement, mode or
    # role changes this: the gate has no input that could lift it.
    superseding = reconciliation_service.superseding_records(change)
    if superseding:
        found = blocker("BLOCKED_SUPERSEDED_BY_RECONCILIATION", records=[record.record_id for record in superseding],
                        devices=sorted({record.device_name for record in superseding}))
        found["message"] = (f"This historical change was superseded by reconciliation {', '.join(record.record_id for record in superseding)} "
                            "and no longer represents current accepted intent.")
        blockers.append(found)
    else:
        # Never executed, or rolled back: nothing of it needed reconciling, but its intent was written against a state an
        # accepted baseline has since replaced.  Same rule: no input lifts it.
        predating = reconciliation_service.predating_records(change)
        if predating:
            history = reconciliation_service.predating_history(change)
            found = blocker("BLOCKED_PREDATES_RECONCILED_BASELINE", records=[record.record_id for record in predating],
                            devices=sorted({record.device_name for record in predating}), history=history)
            found["message"] = (f"This change was created before the baseline accepted by reconciliation "
                                f"{', '.join(record.record_id for record in predating)} and no longer represents current intent. "
                                f"{reconciliation_service.PREDATING_REASONS[history]}.")
            blockers.append(found)
    # V2 Phase 5A: a provisioning Change is executable only while its request is APPROVED for exactly this candidate
    blockers.extend(provisioning_gate.blockers(change))
    if mode not in models.ExecutionMode.values:
        blockers.append(blocker("MODE_CONFIRMATION_MISMATCH", reason="invalid mode"))
    elif for_submission and confirm_mode != mode:
        blockers.append(blocker("MODE_CONFIRMATION_MISMATCH"))

    # 2. validation / plan currency (never re-run, never rebuilt) -------------------------------------------------------
    if sources is None and check_sources:
        sources = cvs.build_source_snapshot(change)  # ONE read-only source snapshot shared by both currency checks
    report.checked_sources = sources is not None
    validation = cvs.get_validation_currency(change, sources=sources, check_sources=check_sources)
    report.validation_currency = validation
    report.validation_run = validation["latest"]
    if validation["state"] == Currency.NEVER_RUN:
        blockers.append(blocker("VALIDATION_NEVER_RUN"))
    elif validation["state"] == Currency.STALE:
        blockers.append(blocker("VALIDATION_STALE", reasons=validation["reasons"]))
    elif validation["last_status"] not in (Status.PASS, Status.PASS_WITH_WARNINGS):
        blockers.append(blocker("VALIDATION_NOT_PASSING", status=validation["last_status"]))

    # Network-device configuration validation is a distinct mandatory gate.  It precedes Tier-2 and has its own
    # immutable currency/result vocabulary; a Tier-2 PASS cannot substitute for it.
    config_validation = ncv.get_currency(change, sources=sources, check_sources=check_sources)
    report.network_config_currency = config_validation
    if config_validation["state"] == "NEVER_RUN":
        blockers.append(blocker("NETWORK_CONFIG_VALIDATION_NEVER_RUN"))
    elif config_validation["state"] == "STALE":
        blockers.append(blocker("NETWORK_CONFIG_VALIDATION_STALE", reasons=config_validation["reasons"]))
    elif config_validation["latest"].status not in (
        models.NetworkConfigValidationStatus.PASS, models.NetworkConfigValidationStatus.WARNING,
    ):
        blockers.append(blocker("NETWORK_CONFIG_VALIDATION_NOT_PASSING", status=config_validation["latest"].status))

    # The external (GitHub Actions) Configuration Validation is ADDITIONAL evidence, bound to the exact snapshot it tested:
    # QUEUED, IN_PROGRESS, FAIL, ERROR, STALE and NOT_TRIGGERED all refuse.  It replaces none of the gates above or below.
    external = configuration_validation.gate(change, current_hash=validation["current_input_hash"])
    if external is not None:
        found = blocker("CONFIGURATION_VALIDATION_NOT_PASSING", **{k: v for k, v in external.items() if k != "reason" and v})
        found["message"] = f"Configuration Validation is {external['status']}: {external['reason']}"
        blockers.append(found)

    plan = change_plan_service.get_latest_plan(change)
    report.plan = plan
    if plan is None:
        blockers.append(blocker("PLAN_MISSING"))
    else:
        plan_currency = change_plan_service.get_plan_currency(plan, sources=sources, check_sources=check_sources)
        report.plan_currency = plan_currency
        if plan_currency["state"] != "CURRENT":
            blockers.append(blocker("PLAN_STALE", reasons=plan_currency["reasons"]))
        run = plan.validation_run
        if (plan.validation_input_hash, plan.validation_source_hash, plan.validation_engine_version) != (run.input_hash, run.source_hash, run.engine_version):
            blockers.append(blocker("PLAN_PROVENANCE_INVALID"))
        elif run.status not in (Status.PASS, Status.PASS_WITH_WARNINGS) and not report.has("VALIDATION_NOT_PASSING"):
            blockers.append(blocker("VALIDATION_NOT_PASSING", status=run.status))
        if run.status == Status.PASS_WITH_WARNINGS:
            warnings.append({"code": "VALIDATION_WARNINGS_CARRIED_FORWARD", "message": "The pinned validation passed with warnings."})

    # 3. precheck: explicitly run FOR THIS plan, permitting, recent, and not superseded by an execution attempt -------------
    if plan is not None:
        precheck = latest_precheck(change)
        report.precheck_run = precheck
        if precheck is None:
            blockers.append(blocker("PRECHECK_MISSING"))
        else:
            provenance = (precheck.report or {}).get("provenance") or {}
            if precheck.plan_id != plan.pk or provenance.get("validation_run_id") != str(plan.validation_run.run_id):
                blockers.append(blocker("PRECHECK_WRONG_PLAN", precheck_plan_id=str(precheck.plan.plan_id) if precheck.plan_id else ""))
            elif precheck.status not in PRECHECK_PERMITS:
                blockers.append(blocker("PRECHECK_NOT_PERMITTING", status=precheck.status))
            else:
                age = (now - precheck.finished_at).total_seconds()
                if age > precheck_max_age_seconds():
                    blockers.append(blocker("PRECHECK_EXPIRED", age_seconds=int(age), max_age_seconds=int(precheck_max_age_seconds())))
                if precheck.status == "PASS_WITH_WARNINGS":
                    warnings.append({"code": "PRECHECK_WARNINGS", "message": "The precheck passed with warnings."})
            blockers.extend(_prior_run_blockers(change, plan, precheck, now))

    # 4. scope, dependencies, devices, capability -------------------------------------------------------------------------
    if plan is not None:
        scope, scope_blockers = resolve_scope(plan, mode if mode in models.ExecutionMode.values else Mode.COMPLETE, through_cfg_id)
        report.scope = scope
        for item in scope_blockers:
            if not for_submission and item["code"] == "UAT_SCOPE_REQUIRED":
                continue
            blockers.append(item)
        if scope is not None and mode == Mode.PARTIAL_UAT and for_submission and not _acks_satisfied(acknowledgements):
            blockers.append(blocker("UAT_ACK_MISSING"))
        if scope is not None and scope.selected:
            _scope_blockers(report, scope, plan, sources=sources)

    # 5. concurrency preview (authoritative enforcement is the DB constraint at acquisition) ------------------------------
    active = active_runs(now=now).filter(change=change)
    if exclude_run is not None:  # the caller's OWN just-acquired run is not a conflict with itself
        active = active.exclude(pk=exclude_run.pk)
    if active.exists():
        blockers.append(blocker("EXECUTION_IN_PROGRESS"))
    if report.scope is not None and report.scope.selected:
        locked = sorted(
            models.ExecutionDeviceLock.objects.filter(device__in=report.scope.devices, run__lease_expires_at__gt=now)
            .exclude(run__change=change).values_list("device", flat=True)
        )
        if locked:
            blockers.append(blocker("DEVICE_LOCKED", devices=locked))
        unsafe = _maintenance_conflicts(report.scope.devices)
        if unsafe:
            blockers.append(blocker("DEVICE_UNDER_MAINTENANCE", devices=sorted(unsafe), reasons=[unsafe[name] for name in sorted(unsafe)]))

    report.eligible = not blockers
    return report


def _scope_blockers(report: EligibilityReport, scope: ExecutionScope, plan, *, sources=None) -> None:
    from .executors.base import ConfigletSpec

    blockers, warnings = report.blockers, report.warnings
    managed = inventory.managed_devices()
    netbox_managed = None
    if sources is not None and sources.netbox.available:
        netbox_managed = (sources.netbox.data or {}).get("managed_devices")
    complete = scope.mode == Mode.COMPLETE
    unsupported, uncompensable, unresolvable, mismatched = [], [], [], []
    raw_complete, raw_problems = [], []
    new_targets = set()
    for configlet in scope.selected:
        spec = ConfigletSpec.from_configlet(configlet)
        device = managed.get(spec.device)
        new_device = getattr(configlet.device_intent, "target_type", "") == NEW_DEVICE
        if new_device:
            new_targets.add(spec.device)
        # V2 Phase 5A: a NEW_DEVICE intent, and any device still ADMITTED (being provisioned), is executable only by the provisioning
        # Change whose run admitted it to the registry.  An ACTIVE provisioned device is an ordinary managed device.
        own = provisioning_registry.admitted_for(spec.device, report.change)
        still_admitted = device is not None and device.get("provisioning_state") == "ADMITTED"
        if device is None or ((new_device or still_admitted) and not own):
            unresolvable.append(spec.device)
        elif inventory.health_platform(spec.platform) != device["platform"]:
            mismatched.append(spec.device)
        cap = capability_module.capability_for(spec.platform, spec.object_type, str(spec.expected.get("service") or "")
                                               if spec.object_type == "mgmt_vrf_service" else "")
        report.configlet_rows.append({
            "cfg_id": spec.cfg_id, "sequence": spec.sequence, "device": spec.device, "object_type": spec.object_type,
            "operation": spec.operation, "apply": cap.apply, "compensation": cap.compensation, "note": cap.note,
            "description": configlet.description, "origin": spec.origin,
        })
        if spec.origin == "RAW":
            # Phase 18: the pinned revision must still hash to what the plan pinned and its pinned verification must still be CURRENT
            # and acceptable (re-read server-side); and opaque text has no provable inverse, so it can never enter Complete mode.
            problem = spec.integrity_error
            if not problem:
                _ok, problem = raw_verification.pinned_verification_state(configlet)
            if problem:
                raw_problems.append({"cfg_id": spec.cfg_id, "reason": problem})
            if complete:
                raw_complete.append(spec.cfg_id)
        if cap.apply != Capability.SUPPORTED:
            unsupported.append({"cfg_id": spec.cfg_id, "platform": spec.platform, "object_type": spec.object_type, "status": cap.apply})
        elif complete and spec.origin != "RAW" and cap.compensation != Capability.SUPPORTED:
            uncompensable.append({"cfg_id": spec.cfg_id, "platform": spec.platform, "object_type": spec.object_type})
        if (spec.derived or {}).get("kind") == "AUTO_ADDRESS" and str(spec.expected.get("interface", "")).lower() == "vlan200":
            blockers.append(blocker("VLAN200_AUTO_FORBIDDEN", cfg_id=spec.cfg_id))
        management = _management_interface(spec.device)
        if management and str(spec.expected.get("interface", "")).lower() == management.lower():
            warnings.append({"code": "TOUCHES_MANAGEMENT_INTERFACE", "cfg_id": spec.cfg_id,
                             "message": f"{spec.cfg_id} configures {spec.device}'s management interface {management}."})
    if unresolvable:
        blockers.append(blocker("TARGET_DEVICE_UNRESOLVABLE", devices=sorted(set(unresolvable))))
    if netbox_managed is not None:
        # a device still being provisioned is reserved in NetBox (``planned``) but joins the managed scope only after NSOT sync
        admitted = {name for name in scope.devices if provisioning_registry.admitted_for(name, report.change)}
        # a natively provisioned device NMAS admitted to production and synchronized to NetBox, targeted as an existing device
        active = {name for name in scope.devices
                  if name not in new_targets and name not in admitted and provisioning_registry.active_managed(name)}
        outside = sorted(set(scope.devices) - set(netbox_managed) - admitted - active)
        if outside:
            blockers.append(blocker("TARGET_DEVICE_OUTSIDE_MANAGED_SCOPE", devices=outside))
    if mismatched:
        blockers.append(blocker("PLATFORM_MISMATCH", devices=sorted(set(mismatched))))
    if unsupported:
        blockers.append(blocker("PLATFORM_EXECUTION_UNSUPPORTED", configlets=unsupported))
    if uncompensable:
        blockers.append(blocker("COMPLETE_COMPENSATION_UNAVAILABLE", configlets=uncompensable))
    if raw_complete:
        blockers.append(blocker("RAW_COMPLETE_FORBIDDEN", configlets=sorted(raw_complete)))
    if raw_problems:
        integrity = [p for p in raw_problems if p["reason"] == "RAW_REVISION_INTEGRITY"]
        if integrity:
            blockers.append(blocker("RAW_REVISION_INTEGRITY", configlets=integrity))
        if len(integrity) != len(raw_problems):
            blockers.append(blocker("RAW_VERIFICATION_NOT_CURRENT", configlets=[p for p in raw_problems if p["reason"] != "RAW_REVISION_INTEGRITY"]))
    if complete:
        chosen = {c.cfg_id for c in scope.selected}
        unverifiable = sorted({
            r.cfg_id for r in health_service.normalize_plan(plan)
            if r.cfg_id in chosen and (r.expected is None or (r.check_types and r.check_types[0] in ("NOT_IMPLEMENTED", "UNKNOWN_TYPE")))
        })
        if unverifiable:
            blockers.append(blocker("COMPLETE_POSTCHECK_UNVERIFIABLE", configlets=unverifiable))
    if any((c.metadata or {}).get("derived", {}) and (c.metadata or {}).get("derived", {}).get("kind") == "AUTO_ADDRESS" for c in scope.selected):
        warnings.append({"code": "AUTO_ADDRESS_NOT_RECORDED_IN_NETBOX", "message": "AUTO addresses are rechecked read-only before execution; applying them writes nothing to NetBox, so they must be recorded in IPAM separately."})
