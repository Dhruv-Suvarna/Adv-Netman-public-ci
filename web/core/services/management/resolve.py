"""The ONE management-address resolver used by every NMAS device consumer.

``nsot_live.get_live_target_metadata`` -- the choke point already used by the cEOS / IOS XE / SR Linux executors, live health
sessions, NSOT reads, credential rotation, route-shield dry runs and configuration-workbench snapshots -- asks this module
which address to use.  The answer is deterministic:

    no ManagedDevice, or no REGISTERED path    -> LEGACY: the inventory's declared management address, exactly as before
    an ACTIVE, healthy approved path          -> that path's endpoint (and its identity, for evidence)
    registered paths exist but none is usable -> FAIL CLOSED (None), including pending or revoked-only registrations:
                                                  nothing falls back to the
                                                  legacy address, the Containerlab management network or Docker exec
    WRITE while reconciliation is required     -> FAIL CLOSED for writes only (reads still resolve)
    the name's newest record is RETIRED        -> FAIL CLOSED (DEVICE_RETIRED): a decommissioned / withdrawn device is managed
                                                  by nothing -- health, rotation, executors -- and never falls back to the
                                                  inventory address.  Only a governed restoration reaches it, inside
                                                  ``retired_device_access(name)``, and only if it had no registered paths
                                                  (those were retired with it: re-enrollment is required)

The resolver never probes: probing is the selector's job.  It is a pure database read, so every consumer sees the same
answer for the same state.
"""

from __future__ import annotations

import contextlib
import contextvars
from dataclasses import dataclass, field

from django.db import DatabaseError

from ... import models
from ..devices import codes, identity

READ, WRITE = "READ", "WRITE"
_RETIRED_ACCESS: contextvars.ContextVar = contextvars.ContextVar("nmas_retired_device_access", default=frozenset())
LEGACY, PATH, BLOCKED = "LEGACY", "PATH", "BLOCKED"


@dataclass(frozen=True)
class Endpoint:
    source: str                       # LEGACY | PATH | BLOCKED
    address: str = ""
    port: int = 22
    path_id: str = ""
    path_type: str = ""
    preference_class: int = 0
    vrf: str = ""
    nmas_attachment: str = ""
    blockers: tuple = field(default_factory=tuple)

    @property
    def usable(self) -> bool:
        return self.source != BLOCKED

    def as_dict(self) -> dict:
        return {"source": self.source, "address": self.address, "port": self.port, "path_id": self.path_id,
                "path_type": self.path_type, "class": self.preference_class, "vrf": self.vrf, "nmas_attachment": self.nmas_attachment,
                "codes": codes.codes(self.blockers)}


@contextlib.contextmanager
def retired_device_access(name: str):
    """Restoration only (``decommission.service.check_restore`` / ``execute_restore``): inside this block the retired device
    ``name`` resolves as the legacy device it was before NMAS retired it.  Scoped to the current thread / task."""
    token = _RETIRED_ACCESS.set(_RETIRED_ACCESS.get() | {str(name)})
    try:
        yield
    finally:
        _RETIRED_ACCESS.reset(token)


def _retired(name: str) -> Endpoint | None:
    """BLOCKED when ``name``'s newest record is retired (outside a restoration scope, or with retired paths)."""
    newest = models.ManagedDevice.objects.filter(name=str(name)).order_by("-pk").first()
    if newest is None or newest.lifecycle_state not in models.DEVICE_LIFECYCLE_TERMINAL:
        return None
    if str(name) not in _RETIRED_ACCESS.get():
        return Endpoint(BLOCKED, blockers=(codes.blocker("DEVICE_RETIRED"),))
    if models.ManagementPath.objects.filter(device=newest).exists():
        return Endpoint(BLOCKED, blockers=(codes.blocker("MGMT_NO_USABLE_PATH"),))
    return None


def endpoint(name: str, *, legacy_address: str = "", purpose: str = READ) -> Endpoint:
    """The management endpoint for device ``name``.  ``legacy_address`` is the inventory address the caller already resolved."""
    try:
        device = models.ManagedDevice.objects.filter(identity.LIVE, name=str(name)).order_by("-pk").first()
        if device is None:
            return _retired(name) or Endpoint(LEGACY, address=legacy_address)
        registered = models.ManagementPath.objects.filter(device=device)
        if not registered.exists():
            return Endpoint(LEGACY, address=legacy_address)
        state = models.DeviceManagementState.objects.filter(device=device).select_related("active_path", "active_path__nmas_attachment").first()
    except DatabaseError:
        # A database failure makes it impossible to know whether approved
        # paths exist.  Never substitute the inventory address in that state.
        return Endpoint(BLOCKED, blockers=(codes.blocker("MGMT_NO_USABLE_PATH"),))
    active = state.active_path if state is not None else None
    if active is None or active.approval_state != models.ManagementApproval.APPROVED or not active.is_active \
            or active.health_state != models.ManagementPathHealth.HEALTHY:
        # Hysteresis may retain a DEGRADED selection, but a new connection
        # cannot prove it still follows that path (especially shared L2
        # endpoints).  Block new consumers until verification or failover.
        return Endpoint(BLOCKED, blockers=(codes.blocker("MGMT_NO_USABLE_PATH"),))
    if purpose == WRITE and state.reconciliation_required:
        return Endpoint(BLOCKED, path_id=active.path_id, blockers=(codes.blocker("MGMT_RECONCILIATION_REQUIRED"),))
    return Endpoint(PATH, address=active.endpoint_address, port=active.port, path_id=active.path_id, path_type=active.path_type,
                    preference_class=active.preference_class, vrf=active.vrf, nmas_attachment=active.nmas_attachment.attachment_id)


def telemetry_targets() -> list[dict]:
    """What telemetry WOULD follow per device.  Phase 4 does not move telemetry collection (gNMI / syslog / SNMP collectors
    keep their configured targets until Phase 8 integrates this resolver); this read-only view exists so that limitation is
    visible, never hidden."""
    rows = []
    for device in models.ManagedDevice.objects.filter(identity.LIVE).order_by("name"):
        resolved = endpoint(device.name)
        rows.append({"device": device.name, **resolved.as_dict(), "telemetry_follows_failover": False,
                     "limitation": "Telemetry collectors are not yet driven by the management resolver (Phase 8)."})
    return rows
