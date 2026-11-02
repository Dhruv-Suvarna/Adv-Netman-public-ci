"""What depends on a device that is to be decommissioned, and which of those dependencies block it.

Read-only.  Every relation comes from a record that proves it -- never from names or address adjacency:

    downstream     live devices whose APPROVED attachment names this device as their upstream, or whose ACTIVE commissioning
                   dependency points at it, followed recursively.  A dependent that has no other live, approved upstream would
                   lose its required connectivity: DOWNSTREAM_DEPENDENT blocks (decommission or re-home the dependent first).
    management     another device's APPROVED management path ``via`` this device with no other approved path: MANAGEMENT_DEPENDENT
    isolation      this device is the trusted upstream of a live isolation policy (an onboarding device would lose its
                   enforcement point): UPSTREAM_ISOLATION_ACTIVE
    operations     an unresolved maintenance, an open commissioning, an unresolved governed transaction on this device:
                   OPERATION_CONFLICT
    references     monitoring target, NetBox id, credential references, inventory relationships: recorded (they are retired
                   or kept for restoration), never blocking on their own
"""

from __future__ import annotations

from ... import models

LIVE_ISOLATION = ("PLANNED", "APPLYING", "ENFORCED", "VERIFIED", "DRIFTED", "UNCERTAIN", "RELEASE_PENDING")


def _live(queryset):
    return queryset.exclude(lifecycle_state__in=tuple(models.DEVICE_LIFECYCLE_TERMINAL))


def _upstreams(device) -> set[str]:
    names = {a.upstream_device for a in device.attachments.filter(approval_state=models.AttachmentApproval.APPROVED)}
    names |= {d.upstream.name for d in device.commissioning_dependencies.filter(state=models.DependencyState.ACTIVE).select_related("upstream")}
    return names


def downstream(name: str, *, _seen=None) -> list[dict]:
    """Every live managed device that depends on ``name`` (directly or through another dependent), with how."""
    seen = set() if _seen is None else _seen
    rows = []
    attached = _live(models.ManagedDevice.objects.filter(attachments__upstream_device=name,
                                                         attachments__approval_state=models.AttachmentApproval.APPROVED))
    depending = _live(models.ManagedDevice.objects.filter(commissioning_dependencies__upstream__name=name,
                                                          commissioning_dependencies__state=models.DependencyState.ACTIVE))
    for device in list(attached.distinct()) + list(depending.distinct()):
        if device.pk in seen or device.name == name:
            continue
        seen.add(device.pk)
        others = sorted(u for u in _upstreams(device) - {name}
                        if _live(models.ManagedDevice.objects.filter(name=u)).exclude(decommissions__state__in=tuple(models.DECOMMISSION_OPEN)).exists()
                        or not models.ManagedDevice.objects.filter(name=u).exists())
        rows.append({"device_id": device.device_id, "name": device.name, "via": name, "lifecycle_state": device.lifecycle_state,
                     "admission_state": device.admission_state, "other_upstreams": others, "stranded": not others})
        rows += downstream(device.name, _seen=seen)
    return rows


def management_dependents(name: str) -> list[dict]:
    rows = []
    paths = models.ManagementPath.objects.filter(via_device=name, approval_state=models.ManagementApproval.APPROVED).select_related("device")
    for path in paths:
        device = path.device
        if device.is_terminal or device.name == name:
            continue
        others = models.ManagementPath.objects.filter(device=device, approval_state=models.ManagementApproval.APPROVED).exclude(
            via_device=name).count()
        rows.append({"device_id": device.device_id, "name": device.name, "path": path.pk, "other_paths": others, "stranded": others == 0})
    return rows


def analyze(device) -> dict:
    """{"downstream", "management", "isolation", "conflicts", "references", "blockers"} for ``device`` (read-only)."""
    from ..isolation import transaction as governed
    from ..maintenance_mode import service as maintenance

    name = device.name
    found = {"downstream": downstream(name), "management": management_dependents(name), "isolation": [], "conflicts": [], "references": {}}
    for policy in models.IsolationPolicy.objects.filter(upstream_device=name, state__in=LIVE_ISOLATION).select_related("device"):
        found["isolation"].append({"policy": f"ISO-{policy.pk:06d}", "device": policy.device.name, "state": policy.state})
    maintenance_row = maintenance.current(name)
    if maintenance_row is not None:
        found["conflicts"].append({"kind": "MAINTENANCE", "ref": maintenance_row.record_id, "state": maintenance_row.state})
    for record in models.CommissioningRecord.objects.filter(device=device, state__in=tuple(models.COMMISSIONING_OPEN)):
        found["conflicts"].append({"kind": "COMMISSIONING", "ref": f"COM-{record.pk:06d}", "state": record.state})
    for change_id in governed.unresolved_runs(name):
        found["conflicts"].append({"kind": "TRANSACTION", "ref": change_id, "state": "UNRESOLVED"})
    target = models.MonitoringTarget.objects.filter(device=device).first()
    found["references"] = {
        "monitoring": {"state": target.state, "generation": target.generation} if target else None,
        "netbox_device_id": device.netbox_device_id,
        "credential_references": models.DeviceCredential.objects.filter(device_name=name).count(),
        "management_paths": models.ManagementPath.objects.filter(device=device).exclude(approval_state="REVOKED").count(),
        "attachments": device.attachments.exclude(approval_state=models.AttachmentApproval.REVOKED).count(),
    }
    blockers = []
    for row in found["downstream"]:
        if row["stranded"]:
            blockers.append({"code": "DOWNSTREAM_DEPENDENT", "detail": f"{row['name']} depends on {row['via']} and has no other upstream"})
    for row in found["management"]:
        if row["stranded"]:
            blockers.append({"code": "MANAGEMENT_DEPENDENT", "detail": f"{row['name']}'s only approved management path runs via {name}"})
    for row in found["isolation"]:
        blockers.append({"code": "UPSTREAM_ISOLATION_ACTIVE", "detail": f"{row['policy']} isolates {row['device']} on {name} ({row['state']})"})
    for row in found["conflicts"]:
        blockers.append({"code": "OPERATION_CONFLICT", "detail": f"{row['kind']} {row['ref']} is {row['state']}"})
    found["blockers"] = blockers
    return found

