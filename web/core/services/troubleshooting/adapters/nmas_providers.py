"""Authoritative NMAS providers for the troubleshooting deployment bindings (``settings.NMAS_TS_DEPLOYMENT``).

These bind troubleshooting admission to the sources of truth that already exist in NMAS -- nothing here is a parallel registry:

``inventory``   ``core.services.devices.resolver.engine_devices()``: the exact device dictionary the health / execution / soak engines
                consume (tracked ``inventory.yml`` first, then live provisioning-registry entries).  Registered-but-unreachable devices
                are absent, so they can never be probed.
``lifecycle``   the managed-device lifecycle registry (``ManagedDevice``) plus active Maintenance Mode records.  A device is admitted
                for read-only collection only when it is IN_SERVICE, production participation is ADMITTED or LEGACY_PREEXISTING, and its
                identity was VERIFIED from independently observed evidence (the existing identity-verification workflow).  Terminal
                lifecycle states and withdrawn admission are reported as withdrawn.  A device without a registry row answers
                ``UNREGISTERED`` (refused, not assumed healthy): adopt it through the existing *Adopt Existing Device* flow first.

``version``     the authoritative OBSERVED OS version of one device, read lazily from
                ``core.services.devices.observations.observed_version(device_name)`` (persisted read-only session observations with
                timestamp and provenance).  Fails closed: module absent, any error, or an unparseable value -> ``None`` (VERSION_UNKNOWN).
                The inventory/topology image tag and any client value are never used.

Every function is read-only: database reads only, no device, NetBox, credential or network access.
"""

from __future__ import annotations

import hashlib
import json

from core import models

# What troubleshooting may report for a registry row (all strings are upper-case; only IN_SERVICE is in collectors.ADMITTED_STATES)
ADMITTED_PRODUCTION = frozenset({models.ProductionAdmissionState.ADMITTED, models.ProductionAdmissionState.LEGACY_PREEXISTING})
UNREGISTERED = "UNREGISTERED"


def inventory() -> dict:
    """The engines' managed-device dictionary, unchanged (``{name: {"platform": ..., ...}}``)."""
    from core.services.devices import resolver   # lazy: needs Django settings and the inventory document

    return resolver.engine_devices()


def _in_maintenance(device: str) -> bool:
    from core.services.maintenance_mode import lifecycle as mm

    return models.MaintenanceRecord.objects.filter(device_name=device, state__in=mm.IN_MAINTENANCE).exists()


def lifecycle(device: str) -> dict:
    """``{"state", "withdrawn", "maintenance", "source", "detail"}`` for one device name, from the lifecycle registry.

    Never returns a healthier answer than the registry states: missing row -> UNREGISTERED; identity not VERIFIED ->
    ``IDENTITY_<state>``; production participation not admitted -> ``NOT_ADMITTED``; any lifecycle state other than IN_SERVICE
    -> that state.  Maintenance is reported (the collector flags MAINTENANCE_MODE) but does not by itself refuse read-only diagnosis.
    """
    name = str(device)
    maintenance = _in_maintenance(name)
    live = models.ManagedDevice.objects.exclude(lifecycle_state__in=tuple(models.DEVICE_LIFECYCLE_TERMINAL)).filter(name=name).first()
    if live is None:
        retired = models.ManagedDevice.objects.filter(name=name, lifecycle_state__in=tuple(models.DEVICE_LIFECYCLE_TERMINAL)).exists()
        if retired:
            return {"state": "DECOMMISSIONED", "withdrawn": True, "maintenance": maintenance, "source": "lifecycle-registry",
                    "detail": "every registration of this name is decommissioned or withdrawn"}
        return {"state": UNREGISTERED, "withdrawn": False, "maintenance": maintenance, "source": "lifecycle-registry",
                "detail": "no lifecycle registration: adopt the device before troubleshooting may probe it"}
    base = {"maintenance": maintenance, "source": "lifecycle-registry", "device_id": live.device_id,
            "lifecycle_state": live.lifecycle_state, "identity_state": live.identity_state, "admission_state": live.admission_state}
    if live.admission_state == models.ProductionAdmissionState.WITHDRAWN:
        return {**base, "state": "WITHDRAWN", "withdrawn": True, "detail": "production admission withdrawn"}
    if live.lifecycle_state != models.DeviceLifecycleState.IN_SERVICE:
        return {**base, "state": str(live.lifecycle_state), "withdrawn": False, "detail": f"lifecycle state {live.lifecycle_state}"}
    if live.admission_state not in ADMITTED_PRODUCTION:
        return {**base, "state": "NOT_ADMITTED", "withdrawn": False, "detail": f"production admission {live.admission_state}"}
    if live.identity_state != models.IdentityVerificationState.VERIFIED:
        return {**base, "state": f"IDENTITY_{live.identity_state}", "withdrawn": False,
                "detail": f"device identity {live.identity_state}: not verified from independent evidence"}
    return {**base, "state": "IN_SERVICE", "withdrawn": False, "detail": "in service, admitted, identity verified"}


# The documented, complete binding (settings.NMAS_TS_DEPLOYMENT).  Transport/source keys are separate, site-owned and not set here.
RECOMMENDED_BINDING = {
    "inventory": f"{__name__}.inventory",
    "lifecycle_provider": f"{__name__}.lifecycle",
    "version_provider": f"{__name__}.version",
}


def version(device: str, entry: dict | None = None) -> str | None:
    """Current authoritative observed version for ``device`` or ``None`` (fail closed).  Read-only; never contacts a device."""
    from ..normalization import parse_version

    try:
        from core.services.devices import observations   # owned by the identity/version observation mechanism; lazy
        value = observations.observed_version(str(device))
    except Exception:  # pylint: disable=broad-exception-caught  # noqa: BLE001 - missing module / DB error / provider failure => unknown
        return None
    text = str(value or "").strip()
    return text if parse_version(text) else None


def target_policy():
    """Build the exact-target policy from the same inventory/lifecycle/path authorities.

    This performs database and tracked-inventory reads only.  It does not open
    a socket and it does not infer authority from routes, ARP, DNS or discovery.
    The resulting policy is consumed by the staged isolated device worker.
    """
    from django.conf import settings
    from core.services.devices import resolver
    from core.services.health import inventory as health_inventory
    from core.services.management import guard
    from ..target_policy import TargetPolicy, TargetSnapshot

    document = health_inventory.load_inventory()
    topology_id = str(document.get("lab_name") or "").strip()
    if not topology_id:
        raise ValueError("tracked inventory has no exact lab_name")
    management = document.get("management") or {}
    protected = []
    for key in ("nmas_ipv4", "nmas_ipv6", "primary_dhcp_ipv4", "primary_dhcp_ipv6"):
        value = str(management.get(key) or "").split("/", 1)[0]
        if value:
            protected.append(value)
    protected.extend(getattr(settings, "NMAS_TS_PROTECTED_ADDRESSES", ()))
    tenant = str(getattr(settings, "NMAS_TS_TENANT", "default") or "default")

    def snapshot(name: str):
        resolved = resolver.resolve(str(name), document=document)
        live = (models.ManagedDevice.objects.exclude(lifecycle_state__in=tuple(models.DEVICE_LIFECYCLE_TERMINAL))
                .filter(name=str(name)).first())
        if resolved is None or live is None:
            return None
        endpoints = frozenset(candidate.address for candidate in resolved.management_candidates if candidate.address)
        approved = []
        path_rows = []
        for path in models.ManagementPath.objects.filter(device=live, approval_state=models.ManagementApproval.APPROVED):
            stored, problems = guard.authorized_target(path)
            if stored is not None and not problems:
                approved.append(stored.endpoint_address)
                path_rows.append((stored.path_id, stored.version, stored.endpoint_address, stored.transport, stored.port,
                                  stored.approval_state, stored.is_active))
        revision_material = {
            "device_id": live.device_id, "version": live.version, "identity": live.identity_state,
            "lifecycle": live.lifecycle_state, "admission": live.admission_state,
            "scope": resolved.scope, "endpoints": sorted(endpoints), "paths": sorted(path_rows),
        }
        revision = hashlib.sha256(json.dumps(revision_material, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        pin = live.verified_host_key or live.verified_serial or live.verified_base_mac
        return TargetSnapshot(
            topology_id=topology_id, tenant=tenant, device=live.name, platform=live.platform,
            scope=resolved.scope, identity_state=live.identity_state, lifecycle_state=live.lifecycle_state,
            admission_state=live.admission_state, endpoints=endpoints,
            approved_path_endpoints=frozenset(approved), excluded=not resolved.writable or live.name == "R5",
            revoked=live.admission_state == models.ProductionAdmissionState.WITHDRAWN,
            identity_pin=pin, revision=revision,
        )

    def authorization_validator(request, target, now):
        # Autonomous diagnostic workers accept only a live, NMAS-created AI
        # handoff reference.  Human web authorization remains in the web/API
        # boundary and does not turn this worker into a general SSH service.
        from ..target_policy import Capability, PrincipalKind
        if request.capability != Capability.READ_DIAGNOSTIC or request.principal.kind != PrincipalKind.TROUBLESHOOTER_AGENT:
            return False
        prefix, _, record_id = request.authorization_ref.partition(":")
        if prefix != "handoff" or not record_id:
            return False
        handoff = (models.TsAIHandoff.objects.select_related("case")
                   .filter(record_id=record_id, status="OPEN", agent_identity=request.principal.name,
                           case__tenant=request.principal.tenant).first())
        if handoff is None or target.device not in handoff.allowed_targets:
            return False
        if handoff.case.target_states.get(target.device) != "VERIFIED":
            return False
        if handoff.case.state in models.TS_TERMINAL_CASE_STATES:
            return False
        started = handoff.checkpoint.get("started_at")
        if not started:
            return False
        from ..contracts import parse_time
        began = parse_time(started)
        return bool(began and (now - began).total_seconds() <= int(handoff.budget.get("max_wall_seconds", 0)))

    return TargetPolicy(topology_id=topology_id, snapshot=snapshot, protected_addresses=protected,
                        excluded_devices=("R5",), authorization_validator=authorization_validator)
