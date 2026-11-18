"""Read-only, authoritative scope choices for the Troubleshooter intake UI.

The browser never supplies the inventory.  Device choices come from NMAS's
shared managed-device resolver and link choices come from the tracked
Containerlab topology.  A choice may still be useful for a case when it is not
diagnostically eligible; eligibility is labelled explicitly and is rechecked
by the runtime before any collection.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml
from django.conf import settings

from core import models
from core.services.health import inventory as health_inventory

from . import repository as repo
from .adapters import nmas_providers

_ENDPOINT = re.compile(r"^(?P<device>[A-Za-z0-9_.-]{1,64}):(?P<interface>[A-Za-z][A-Za-z0-9/_.:-]{0,63})$")


def readiness_reason(state: str, detail: str, ready: bool) -> str:
    if ready:
        return "ACTIVE, HEALTHY, approved ManagementPath"
    if state == "IN_SERVICE":
        return "no ACTIVE, HEALTHY, approved ManagementPath"
    return detail or "lifecycle/admission prerequisite is not satisfied"


def _links(allowed_devices: set[str]) -> list[dict]:
    document = health_inventory.load_inventory()
    lab = str(document.get("lab_name") or "").strip()
    if not lab:
        return []
    try:
        topology = yaml.safe_load((Path(settings.REPO_ROOT) / f"{lab}.clab.yml").read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError):
        return []
    rows = []
    for item in ((topology.get("topology") or {}).get("links") or []):
        endpoints = item.get("endpoints") if isinstance(item, dict) else None
        if not isinstance(endpoints, list) or len(endpoints) != 2:
            continue
        matches = [_ENDPOINT.fullmatch(str(value)) for value in endpoints]
        if not all(matches):
            continue
        a, b = (match.groupdict() for match in matches)
        if a["device"] not in allowed_devices or b["device"] not in allowed_devices:
            continue
        value = f'{a["device"]}:{a["interface"]}|{b["device"]}:{b["interface"]}'
        rows.append({"value": value, "label": value.replace("|", " ↔ "),
                     "scope": {"a": a["device"], "a_if": a["interface"],
                               "b": b["device"], "b_if": b["interface"]}})
    return rows


def options(actor: repo.Actor) -> dict:
    """Return device/link choices visible to ``actor`` without contacting a device."""
    inventory = health_inventory.managed_devices()
    names = sorted(name for name in inventory if actor.can_see_device(name))
    live = {row.name: row for row in models.ManagedDevice.objects.filter(name__in=names)
            .exclude(lifecycle_state__in=tuple(models.DEVICE_LIFECYCLE_TERMINAL))}
    ready_path_devices = set(models.ManagementPath.objects.filter(
        device__name__in=names,
        approval_state=models.ManagementApproval.APPROVED,
        health_state=models.ManagementPathHealth.HEALTHY,
        is_active=True,
    ).values_list("device__name", flat=True))
    devices = []
    for name in names:
        try:
            lifecycle = nmas_providers.lifecycle(name)
            state = str(lifecycle.get("state") or "UNKNOWN")
            detail = str(lifecycle.get("detail") or "")
        except Exception:  # noqa: BLE001 - presentation fails closed; runtime still rechecks admission
            state, detail = "STATUS_UNAVAILABLE", "lifecycle status could not be read"
        ready = bool(name in live and state == "IN_SERVICE" and name in ready_path_devices)
        reason = readiness_reason(state, detail, ready)
        devices.append({"name": name, "platform": str((inventory.get(name) or {}).get("platform") or "unknown"),
                        "lifecycle": state, "diagnostic_ready": ready, "reason": reason})
    return {"devices": devices, "links": _links(set(names))}


def selected_link(scope_options: dict, value: str) -> dict | None:
    """Resolve an exact current link token; arbitrary browser input is refused."""
    if not value:
        return None
    return next((dict(row["scope"]) for row in scope_options.get("links", ()) if row.get("value") == value), None)
