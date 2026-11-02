"""The vocabulary of Maintenance Mode.  Plain immutable values; no I/O."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta

IPV4, IPV6 = "IPV4", "IPV6"
FAMILIES = (IPV4, IPV6)
NORTHBOUND, SOUTHBOUND = "NORTHBOUND", "SOUTHBOUND"          # away from the clients / toward the clients
DIRECTIONS = (NORTHBOUND, SOUTHBOUND)
PRODUCTION, MANAGEMENT, CONTROL, TEST = "PRODUCTION", "MANAGEMENT", "CONTROL", "TEST"
TRAFFIC_CLASSES = (PRODUCTION, MANAGEMENT, CONTROL, TEST)
ACTIVE, QUIESCED, UNKNOWN = "ACTIVE", "QUIESCED", "UNKNOWN"   # what was observed of a flow; UNKNOWN is never read as quiet

READY, NOT_READY, NOT_AUTHORIZED = "READY", "NOT_READY", "PROVEN_NOT_AUTHORIZED"   # same words as route_shield.readiness

MAINTENANCE_CYCLE = timedelta(days=7)                         # safety deadline, counted from entry; not a limit on the request


class MaintenanceError(Exception):
    """A request or a lifecycle step that is not allowed.  ``code`` is stable; the message is for the operator."""

    def __init__(self, code: str, message: str = ""):
        super().__init__(f"{code}: {message}" if message else code)
        self.code = code


@dataclass(frozen=True)
class Request:
    """``requested_duration`` is the operator's intended window.  It is information: it never ends a maintenance."""

    device: str
    operator: str
    reason: str
    requested_duration: timedelta
    requested_at: datetime

    def __post_init__(self):
        if not self.device.strip() or not self.operator.strip() or not self.reason.strip():
            raise MaintenanceError("REQUEST_INCOMPLETE", "device, operator and reason are all required")
        if self.requested_duration <= timedelta(0):
            raise MaintenanceError("DURATION_INVALID", "the requested duration must be positive")


@dataclass(frozen=True)
class Flow:
    """One observed traffic relation through or to the device.  ``workload`` is what the operator would recognise."""

    label: str
    workload: str
    family: str
    direction: str
    traffic_class: str = PRODUCTION
    activity: str = UNKNOWN
    evidence: str = ""
    on_device: bool | None = None            # the derived path passes the device (True), avoids it (False), or was not derived

    def __post_init__(self):
        if self.family not in FAMILIES or self.direction not in DIRECTIONS or self.traffic_class not in TRAFFIC_CLASSES \
                or self.activity not in (ACTIVE, QUIESCED, UNKNOWN):
            raise MaintenanceError("FLOW_INVALID", self.label)

    @property
    def cell(self) -> tuple[str, str]:
        return self.family, self.direction


@dataclass(frozen=True)
class Dependency:
    """Something that needs the device while it is in maintenance (a gateway, a DHCP relay, a management path).
    ``stranded`` is None while it has not been established either way, and None is treated as stranded."""

    name: str
    kind: str
    critical: bool = True
    stranded: bool | None = None
    detail: str = ""


@dataclass(frozen=True)
class Mechanism:
    """A named, existing way to move traffic of one family in one direction off the device."""

    key: str
    family: str
    direction: str
    description: str
    state: str = NOT_READY
    needs_alternate: bool = True


@dataclass(frozen=True)
class DrainProof:
    """What was measured after one directional drain step: the cell is clear only with every field in order."""

    family: str
    direction: str
    moved: bool
    probes_lost: int | None                 # None = no packet-loss evidence, which is not the same as zero
    alternate_healthy: bool | None = None
    detail: str = ""


@dataclass(frozen=True)
class Finding:
    code: str
    family: str = ""
    direction: str = ""
    traffic_class: str = ""
    workloads: tuple[str, ...] = ()
    detail: str = ""

    def text(self) -> str:
        where = " ".join(part for part in (self.family, self.direction, self.traffic_class) if part)
        who = f" ({', '.join(self.workloads)})" if self.workloads else ""
        return f"{self.code}{' ' + where if where else ''}{who}{': ' + self.detail if self.detail else ''}"


@dataclass
class Report:
    """Readiness of one request.  ``cells`` holds the verdict per (family, direction); ``blockers`` empty means ready."""

    device: str
    cells: dict = field(default_factory=dict)
    blockers: list = field(default_factory=list)
    notes: list = field(default_factory=list)

    @property
    def ready(self) -> bool:
        return not self.blockers
