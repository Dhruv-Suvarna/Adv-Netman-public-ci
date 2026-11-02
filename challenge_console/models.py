"""Typed records shared by collectors, the state store, the session log and the views.

Everything here is plain data: no widget, no socket, no thread.  An ``Event`` is the single thing a collector may publish; its
``data`` is JSON-serialisable and is what the append-only session log stores.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone

# collector names == state topics == view keys
CONNECTIVITY, SERVICES, NSOT, AUTOMATION, COUNTERS = "connectivity", "services", "nsot", "automation", "counters"
COLLECTORS = (CONNECTIVITY, SERVICES, NSOT, AUTOMATION, COUNTERS)
APP, SUPERVISOR = "app", "supervisor"

# outcomes
OK, FAIL, ERROR, INFO = "OK", "FAIL", "ERROR", "INFO"
PASS = "PASS"
UP, DOWN, DEGRADED, UNKNOWN = "UP", "DOWN", "DEGRADED", "UNKNOWN"

V4, V6 = "IPV4", "IPV6"


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def iso(moment: datetime | None) -> str:
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z" if moment else ""


def parse_time(value) -> datetime | None:
    """ISO-8601 / SQLite ``YYYY-MM-DD HH:MM:SS[.ffffff]`` -> aware UTC datetime; anything else -> None."""
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).strip().replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


@dataclass(frozen=True)
class Event:
    """One timestamped observation or occurrence.  ``kind`` is dotted (``connectivity.sample``, ``collector.error`` ...)."""

    ts: datetime
    collector: str
    kind: str
    target: str = ""
    outcome: str = INFO
    data: dict = field(default_factory=dict)

    def to_record(self) -> dict:
        return {"ts": iso(self.ts), "collector": self.collector, "kind": self.kind, "target": self.target,
                "outcome": self.outcome, "data": self.data}


# --- connectivity -------------------------------------------------------------------------------------------------------
@dataclass(frozen=True)
class ProbeSpec:
    """One required row of the matrix: ``source`` must reach ``destination`` over ``family``."""

    source: str
    family: str
    destination: str

    @property
    def key(self) -> str:
        return f"{self.source}/{self.family}"


@dataclass(frozen=True)
class ProbeSample:
    ts: datetime
    key: str
    source: str
    family: str
    destination: str
    source_address: str
    target_address: str
    success: bool
    rtt_ms: float | None = None
    reason: str = ""               # fixed code when not successful: TIMEOUT, UNREACHABLE, NO_SOURCE_ADDRESS, ...

    def to_dict(self) -> dict:
        row = asdict(self)
        row["ts"] = iso(self.ts)
        return row


@dataclass
class ProbeRow:
    """Current state of one matrix row (the history ring lives beside it in the store)."""

    spec: ProbeSpec
    state: str = UNKNOWN           # UP / DOWN / UNKNOWN (no sample yet)
    source_address: str = ""
    target_address: str = ""
    last_ts: datetime | None = None
    last_rtt_ms: float | None = None
    last_reason: str = ""
    consecutive_failures: int = 0
    failures: int = 0
    samples: int = 0
    last_success: datetime | None = None
    last_failure: datetime | None = None
    last_change: datetime | None = None


# --- services / telemetry -------------------------------------------------------------------------------------------------
@dataclass(frozen=True)
class Check:
    name: str                      # "systemd", "http", "container", "socket", "timer"
    ok: bool | None                # None = could not be determined
    detail: str = ""


@dataclass(frozen=True)
class ServiceObservation:
    ts: datetime
    component: str
    label: str
    state: str                     # UP / DOWN / DEGRADED / UNKNOWN
    checks: tuple[Check, ...] = ()
    latency_ms: float | None = None

    @property
    def detail(self) -> str:
        return "; ".join(f"{c.name}: {c.detail}" for c in self.checks if c.detail)

    def to_dict(self) -> dict:
        return {"component": self.component, "state": self.state, "latency_ms": self.latency_ms,
                "checks": [{"name": c.name, "ok": c.ok, "detail": c.detail} for c in self.checks]}


@dataclass(frozen=True)
class FreshnessRow:
    device: str
    managed: bool
    last_sample: datetime | None
    age_seconds: float | None
    freshness: str                 # the project vocabulary: FRESH / STALE / EXPIRED / UNKNOWN
    health: str = ""
    cpu_percent: float | None = None
    memory_percent: float | None = None

    def to_dict(self) -> dict:
        row = asdict(self)
        row["last_sample"] = iso(self.last_sample)
        return row


# --- interface counters ---------------------------------------------------------------------------------------------------
COUNTER_FIELDS = ("rx_bytes", "tx_bytes", "rx_packets", "tx_packets", "rx_errors", "tx_errors", "rx_drops", "tx_drops")
RATE_FIELDS = ("rx_bps", "tx_bps", "rx_pps", "tx_pps")


@dataclass
class InterfaceCounters:
    """One interface at one instant: raw counters exactly as read (None where the platform exposes none)."""

    device: str
    name: str
    admin: str = UNKNOWN
    oper: str = UNKNOWN
    speed_bps: int | None = None
    description: str = ""
    rx_bytes: int | None = None
    tx_bytes: int | None = None
    rx_packets: int | None = None
    tx_packets: int | None = None
    rx_errors: int | None = None
    tx_errors: int | None = None
    rx_drops: int | None = None
    tx_drops: int | None = None

    def counters(self) -> tuple:
        return tuple(getattr(self, name) for name in COUNTER_FIELDS)


@dataclass
class InterfaceRow:
    """What the view shows: the latest raw sample plus rates derived from the previous one (None until two samples exist)."""

    sample: InterfaceCounters
    ts: datetime
    rx_bps: float | None = None
    tx_bps: float | None = None
    rx_pps: float | None = None
    tx_pps: float | None = None
    counter_reset: bool = False
    error_delta: int = 0           # errors + drops gained since the previous sample
    last_change: datetime | None = None
    change_note: str = ""
    present: bool = True
