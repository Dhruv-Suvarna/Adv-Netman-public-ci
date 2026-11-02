"""Dynamic monitoring registration driven by lifecycle facts (``MonitoringTarget``).

Eligibility (all required):
    * lifecycle IN_SERVICE (or DECOMMISSION_PENDING: still carrying production traffic until it is decommissioned)
    * admission ADMITTED or LEGACY_PREEXISTING
    * an authorized management path that the Phase 4 selector made ACTIVE and HEALTHY, as answered by the one management
      resolver (``core.services.management.resolve.endpoint``).  A device without registered paths (LEGACY) is NOT eligible:
      the inventory address is never used for a dynamic target.

State rules
    * first eligible fact                -> ACTIVE, generation + 1, history REGISTERED
    * management path / address changed  -> stays ACTIVE, generation + 1, history PATH_CHANGED (collectors must reconnect)
    * no usable path any more            -> SUSPENDED (history PATH_LOST); PENDING if it was never registered
    * lifecycle / admission not eligible -> BLOCKED if never registered, otherwise SUSPENDED
    * maintenance                        -> stays ACTIVE (visibility matters most during a change); the maintenance flag is
                                            derived live from the maintenance engine and exported with the target
    * DECOMMISSIONED / WITHDRAWN         -> RETIRED (row and history kept)
    * RESTORED / re-eligible             -> ACTIVE, generation + 1 (a restored successor continues its predecessor's generation)

Collectors come from the platform's real, documented capabilities (docs/SNMP_IMPLEMENTATION.md,
docs/STREAMING_TELEMETRY_IMPLEMENTATION.md); an unknown platform gets every collector disabled with a reason.
Credentials are never exported -- only the path's opaque credential reference.
"""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

from django.conf import settings
from django.utils import timezone

from ... import models
from .. import secret_policy
from ..commissioning import outbox
from ..management import resolve
from . import facts

T, S = models.MonitoringTargetState, models.DeviceLifecycleState
CONSUMER = "phase8-monitoring"
HISTORY_MAX = 50
ELIGIBLE_LIFECYCLE = frozenset({S.IN_SERVICE, S.DECOMMISSION_PENDING})
_ON = {"enabled": True, "reason": ""}
PLATFORM_COLLECTORS = {
    models.Platform.ARISTA_CEOS: {"snmp": dict(_ON), "syslog": dict(_ON), "gnmi": {"enabled": True, "reason": "native EOS gNMI (port 6030)"}},
    models.Platform.UBUNTU_FRR: {"snmp": {"enabled": True, "reason": "net-snmp snmpd (NMAS-managed)"}, "syslog": dict(_ON),
                                 "gnmi": {"enabled": True, "reason": "read-only Linux telemetry adapter (no native gNMI)"}},
}
UNSUPPORTED_REASON = "PLATFORM_COLLECTOR_UNVERIFIED"


def collectors_for(platform: str) -> dict:
    """{collector: {enabled, reason}} for ``platform`` -- only what this lab proved; unknown platforms are all disabled."""
    known = PLATFORM_COLLECTORS.get(platform)
    if known is None:
        return {name: {"enabled": False, "reason": UNSUPPORTED_REASON} for name in ("snmp", "syslog", "gnmi")}
    return {name: dict(spec) for name, spec in known.items()}


def eligibility(device) -> dict:
    """{eligible, address, path, path_id, reasons} for ``device`` right now (database only; the resolver never probes)."""
    reasons = []
    if device.lifecycle_state not in ELIGIBLE_LIFECYCLE:
        reasons.append("LIFECYCLE_NOT_IN_SERVICE")
    if device.admission_state not in facts.ADMITTED_STATES:
        reasons.append("NOT_ADMITTED")
    endpoint = resolve.endpoint(device.name) if not reasons else None
    path = None
    if endpoint is not None:
        if endpoint.source == resolve.LEGACY:
            reasons.append("MGMT_PATH_NOT_REGISTERED")
        elif endpoint.source != resolve.PATH:
            reasons.append("MGMT_NO_USABLE_PATH")
        else:
            path = models.ManagementPath.objects.filter(device=device, pk=int(endpoint.path_id.split("-")[-1])).first()
            if path is None:
                reasons.append("MGMT_NO_USABLE_PATH")
    return {"eligible": not reasons, "address": endpoint.address if path else "", "path": path,
            "path_id": path.path_id if path else "", "reasons": reasons}


def _history(target, event: str, **detail) -> None:
    entry = {"at": timezone.now().isoformat(), "event": event, "generation": target.generation, **detail}
    target.history = (list(target.history or []) + [secret_policy.redact(entry)])[-HISTORY_MAX:]


def _predecessor_generation(device) -> int:
    if not device.predecessor_id:
        return 0
    previous = models.MonitoringTarget.objects.filter(device_id=device.predecessor_id).first()
    return previous.generation if previous else 0


def reconcile(device, *, fact: str = "", sequence: int = 0) -> models.MonitoringTarget:
    """Bring ``device``'s target in line with its lifecycle and the selector's active path (idempotent)."""
    target, _created = models.MonitoringTarget.objects.get_or_create(
        device=device, defaults={"name": device.name, "platform": device.platform, "collectors": collectors_for(device.platform),
                                 "generation": _predecessor_generation(device)})
    target.collectors = collectors_for(device.platform)
    if device.lifecycle_state in facts.TERMINAL:
        if target.state != T.RETIRED:
            target.state, target.retired_at = T.RETIRED, timezone.now()
            _history(target, "RETIRED", fact=fact or "LIFECYCLE", lifecycle=device.lifecycle_state)
    else:
        found = eligibility(device)
        if found["eligible"]:
            path, address = found["path"], found["address"]
            moved = target.management_path_id != path.pk or target.address != address
            if target.state != T.ACTIVE:
                kind = "RESTORED" if fact == outbox.RESTORED or target.state in (T.RETIRED, T.SUSPENDED) or device.predecessor_id else "REGISTERED"
                target.generation += 1
                _history(target, kind, fact=fact, path=path.path_id, address=address, reconnect_required=True,
                         predecessor=f"DEV-{device.predecessor_id:06d}" if device.predecessor_id else "")
                target.state, target.retired_at = T.ACTIVE, None
                target.registered_at = target.registered_at or timezone.now()
            elif moved:
                target.generation += 1
                _history(target, "PATH_CHANGED", fact=fact, previous_path=target.management_path.path_id if target.management_path_id else "",
                         path=path.path_id, previous_address=target.address, address=address, reconnect_required=True)
            target.management_path, target.address = path, address
        else:
            lost_path = any(code.startswith("MGMT_") for code in found["reasons"])
            if target.registered_at is None:
                new_state = T.PENDING if lost_path and len(found["reasons"]) == 1 else T.BLOCKED
            else:
                new_state = T.SUSPENDED
            if target.state != new_state:
                _history(target, "PATH_LOST" if lost_path else "SUSPENDED" if new_state == T.SUSPENDED else new_state, fact=fact,
                         reasons=found["reasons"])
                target.state = new_state
    if fact in (outbox.MAINTENANCE_ENTERED, outbox.MAINTENANCE_EXITED):
        _history(target, fact, maintenance=facts.under_maintenance(device.name))
    if sequence:
        target.last_sequence = max(int(target.last_sequence), int(sequence))
    target.save()
    return target


def apply(event, **_context) -> str:
    """Consumer entry point.  -> APPLIED | SUPERSEDED."""
    device = models.ManagedDevice.objects.get(pk=event.device_id)
    target = models.MonitoringTarget.objects.filter(device=device).first()
    if target is not None and facts.superseded(event, target.last_sequence):
        return "SUPERSEDED"
    reconcile(device, fact=facts.fact_of(event), sequence=event.sequence)
    return "APPLIED"


def export_targets() -> list[dict]:
    """The secret-free target list collectors consume: ACTIVE targets only, sorted by name.  Credentials are references."""
    rows = []
    for target in models.MonitoringTarget.objects.select_related("device", "management_path").filter(state=T.ACTIVE).order_by("name"):
        path = target.management_path
        rows.append(secret_policy.redact({
            "device": target.name, "device_id": target.device.device_id, "platform": target.platform, "address": target.address,
            "management_path": path.path_id if path else "", "path_type": path.path_type if path else "",
            "vrf": path.vrf if path else "", "generation": target.generation,
            "collectors": sorted(name for name, spec in (target.collectors or {}).items() if spec.get("enabled")),
            "maintenance": facts.under_maintenance(target.name),
            "credential_ref": f"{path.credential_source}:{path.credential_reference}"[:160] if path else "",
        }))
    return rows


def default_runtime_path() -> Path:
    return Path(settings.REPO_ROOT) / "monitoring" / "runtime" / "nmas-dynamic-targets.json"


def write_runtime_targets(path=None) -> Path:
    """Write ``export_targets()`` atomically (temp file + rename) to ``path`` (default monitoring/runtime/, git-ignored)."""
    target = Path(path) if path else default_runtime_path()
    if not target.parent.is_dir():
        raise FileNotFoundError("runtime directory does not exist")
    body = json.dumps({"generated_at": timezone.now().isoformat(), "targets": export_targets()}, indent=2, sort_keys=True) + "\n"
    handle, temp = tempfile.mkstemp(prefix=".nmas-targets-", dir=str(target.parent))
    try:
        with os.fdopen(handle, "w") as stream:
            stream.write(body)
        os.chmod(temp, 0o640)
        os.replace(temp, target)
    except BaseException:
        if os.path.exists(temp):
            os.unlink(temp)
        raise
    return target


def summary() -> dict:
    counts = {}
    for state in models.MonitoringTarget.objects.values_list("state", flat=True):
        counts[state] = counts.get(state, 0) + 1
    return counts
