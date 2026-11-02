"""The ONE managed-device scope of the automation workbench (Configuration Changes AND Remove Configuration).

A device is selectable -- in the dropdown AND in any POST, however crafted -- only when BOTH hold:

    NetBox     marks it IaC-managed (``netbox_ipam.get_managed_devices``: the ``managed`` tag and ``iac_managed`` agree).
               This is the repository's authoritative management-scope source; R5 / WebServer are unmanaged there.
    inventory  ``inventory.yml`` gives it a platform with a read-only capture transport (cEOS or Ubuntu/FRR).

No device name is hard-coded here.  Fail closed: if NetBox cannot be read, nothing is selectable and a capture is refused as
``MANAGEMENT_SCOPE_UNAVAILABLE`` (never widened to "all of inventory").

``capture.managed_scope()`` is deliberately NOT narrowed: the locked legacy-bootstrap / Golden capture reads every inventory
device (R5 included) and must keep doing so.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field

from django.conf import settings

from ... import models
from .. import nsot_netbox
from ..bootstrap import capture

PLATFORMS = {"ceos": models.Platform.ARISTA_CEOS, "linux": models.Platform.UBUNTU_FRR}

# Tests replace this with a callable returning the managed-name envelope; None means the real NetBox read (briefly cached).
NETBOX_MANAGED = None
_cache: dict = {}


@dataclass(frozen=True)
class WorkbenchScope:
    devices: list = field(default_factory=list)      # [{"name", "platform", "transport"}], sorted by name
    unavailable: str = ""                              # sanitized reason when the authoritative scope could not be read
    out_of_scope: frozenset = frozenset()             # inventory devices NetBox does not mark managed (e.g. R5)

    def get(self, name: str) -> dict | None:
        return next((row for row in self.devices if row["name"] == name), None)


def _netbox_managed() -> dict:
    if NETBOX_MANAGED is not None:
        return NETBOX_MANAGED()
    ttl = float(getattr(settings, "NSOT_CACHE_TTL_SECONDS", 30.0))
    cached = _cache.get("managed")
    if cached and time.monotonic() - cached[0] < ttl:
        return cached[1]
    envelope = nsot_netbox.managed_device_names()
    if envelope.get("status") == "available":
        _cache["managed"] = (time.monotonic(), envelope)
    return envelope


def workbench_scope() -> WorkbenchScope:
    """The selectable devices (server-side; never browser-supplied)."""
    envelope = _netbox_managed()
    if envelope.get("status") != "available":
        return WorkbenchScope(unavailable="The authoritative management scope (NetBox) could not be read; no device is selectable.")
    managed = set(envelope.get("data") or ())
    inventory = capture.managed_scope()
    rows = [
        {"name": name, "platform": PLATFORMS[entry["platform"]], "transport": capture.transport_of(entry)}
        for name, entry in sorted(inventory.items())
        if name in managed and entry.get("platform") in PLATFORMS
    ]
    return WorkbenchScope(devices=rows, out_of_scope=frozenset(set(inventory) - managed))


def resolve(name: str) -> tuple[dict | None, str]:
    """-> (device row, "") or (None, error code): DEVICE_OUT_OF_SCOPE / DEVICE_NOT_FOUND / UNSUPPORTED_PLATFORM /
    MANAGEMENT_SCOPE_UNAVAILABLE."""
    scope = workbench_scope()
    if scope.unavailable:
        return None, "MANAGEMENT_SCOPE_UNAVAILABLE"
    row = scope.get(name)
    if row is not None:
        return row, ""
    if name in scope.out_of_scope:
        return None, "DEVICE_OUT_OF_SCOPE"
    if name in capture.managed_scope():
        return None, "UNSUPPORTED_PLATFORM"   # NetBox-managed, but no read-only capture transport for its platform
    return None, "DEVICE_NOT_FOUND"
