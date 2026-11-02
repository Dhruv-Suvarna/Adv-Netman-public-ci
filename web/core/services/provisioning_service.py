"""Facade of the new-device provisioning workflow (V2 Phase 5A).  Views and commands import this module only.

See ``provisioning/lifecycle.py`` for the stage machine and docs/V2_PHASE5_PROVISIONING_TRAFFIC_SOAK.md for the operator workflow.
"""

from __future__ import annotations

from .. import models
from .provisioning import bootstrap, capability_gate, codes, ipam, lifecycle, registry

STAGES = codes.STAGES
ROLES = lifecycle.ROLES
StageResult = lifecycle.StageResult

create_request = lifecycle.create_request
define_identity = lifecycle.define_identity
classify_bootstrap = lifecycle.classify_bootstrap
resolve_capabilities = lifecycle.resolve_capabilities
plan_ipam = lifecycle.plan_ipam
generate_candidate = lifecycle.generate_candidate
record_validation = lifecycle.record_validation
build_plan = lifecycle.build_plan
run_precheck = lifecycle.run_precheck
approve = lifecycle.approve
sync_nsot = lifecycle.sync_nsot
start_probation = lifecycle.start_probation
probation_candidate = lifecycle.probation_candidate
cancel = lifecycle.cancel
decommission = lifecycle.decommission
transport_support = bootstrap.transport_support
supported_features = capability_gate.supported_features
provisioned_devices = registry.devices


def get_run(prov_id: str):
    """``PROV-000001`` -> the run, or None (never raises for a malformed id)."""
    text = str(prov_id or "")
    if not text.startswith("PROV-") or not text[5:].isdigit():
        return None
    return models.ProvisioningRun.objects.filter(pk=int(text[5:])).first()


def list_runs(*, limit: int = 100):
    return list(models.ProvisioningRun.objects.select_related("change")[:limit])


def next_stage(run) -> str:
    """The stage the operator performs next, or '' when the run is finished."""
    return "" if run.is_terminal else codes.STAGE_OF_STATUS.get(run.status, "")


def stage_rows(run) -> list[dict]:
    """The whole workflow for the detail page: every stage with its state and latest recorded event."""
    latest = {}
    for event in run.events.all():
        latest[event.stage] = event
    order = [models.ProvisioningStatus.DRAFT, *(target for _name, _source, target in STAGES)]
    reached = order.index(run.status) if run.status in order else None
    rows = []
    for index, (name, _source, target) in enumerate(STAGES, start=1):
        event = latest.get(name)
        if reached is not None and index <= reached:
            state = "DONE"
        elif event is not None and event.outcome in (models.ProvisioningEventOutcome.BLOCKED, models.ProvisioningEventOutcome.FAILED):
            state = event.outcome
        elif reached is not None and index == reached + 1:
            state = "NEXT"
        else:
            state = "PENDING"
        rows.append({"name": name, "label": models.ProvisioningStatus(target).label, "state": state, "event": event})
    return rows
