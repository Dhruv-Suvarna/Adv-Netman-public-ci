"""Normalized per-device evidence: fact GROUPS with their own source and observation time.

A *fact group* (interfaces, addresses, routes, ospf, bgp, config, nat, telemetry, ...) is either available
(``data`` is not None) or unavailable (``data`` is None -- never an empty stand-in for "zero").  Each group keeps
where it came from (LIVE / TELEMETRY / SYNTHETIC) and when it was observed, so a result can always state its
source time and freshness.  ``complete`` says whether *absence* from the group proves absence on the device: live
groups are complete; the telemetry interface group only covers monitored link endpoints and is not.

Evidence precedence (documented in docs/HEALTH_PRECHECK_POSTCHECK.md):

    LIVE (this run)  >  TELEMETRY.   Per group, an available live group replaces the telemetry group; the two are
    never blended.  When both exist and disagree the live value is used and a conflict is recorded (surfaced as an
    EVIDENCE_CONFLICT WARN).  Fleet Quick has no live evidence and therefore reports telemetry alone.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from .codes import Freshness
from .thresholds import classify_age

GROUPS = ("telemetry", "interfaces", "addresses", "virtual_addresses", "routes", "ospf", "isis", "bgp", "config", "config_paths", "management_services",
          "nat", "routing_config", "rip", "rip_neighbors")


@dataclass
class FactGroup:
    data: object | None
    source: str
    observed_at: datetime | None = None
    complete: bool = True
    error: str = ""

    @property
    def available(self) -> bool:
        return self.data is not None

    def age_seconds(self, now: datetime):
        return None if self.observed_at is None else max(0.0, (now - self.observed_at).total_seconds())

    def freshness(self, now: datetime, thresholds: dict) -> str:
        return classify_age(self.age_seconds(now), thresholds["freshness"])


def unavailable(source: str, error: str = "", observed_at: datetime | None = None) -> FactGroup:
    return FactGroup(data=None, source=source, observed_at=observed_at, complete=False, error=error)


@dataclass
class DeviceEvidence:
    device: str
    platform: str = ""
    groups: dict = field(default_factory=dict)
    live_attempted: bool = False
    live_error: str = ""             # sanitized reason code (TIMEOUT, AUTH_FAILED, ...), never an exception text
    conflicts: list = field(default_factory=list)

    def group(self, name: str) -> FactGroup | None:
        return self.groups.get(name)

    def facts(self, name: str):
        group = self.groups.get(name)
        return group.data if group is not None and group.available else None

    @property
    def live_reachable(self) -> bool:
        return self.live_attempted and not self.live_error


@dataclass
class EvidenceSet:
    """Everything an evaluation may look at, gathered ONCE by the caller (the engine itself does no I/O)."""

    devices: dict
    now: datetime
    thresholds: dict
    pipeline: dict = field(default_factory=lambda: {"available": True, "reason": ""})
    services: dict = field(default_factory=dict)

    def device(self, name: str) -> DeviceEvidence | None:
        return self.devices.get(name)


def merge_precedence(live: DeviceEvidence | None, telemetry: DeviceEvidence | None) -> DeviceEvidence:
    """Combine live + telemetry evidence for one device by the precedence rule above."""
    base = live or telemetry
    merged = DeviceEvidence(
        device=base.device if base else "", platform=(live.platform if live and live.platform else (telemetry.platform if telemetry else "")),
        live_attempted=bool(live and live.live_attempted), live_error=live.live_error if live else "",
    )
    names = set(live.groups if live else ()) | set(telemetry.groups if telemetry else ())
    for name in sorted(names):
        from_live = live.group(name) if live else None
        from_telemetry = telemetry.group(name) if telemetry else None
        if from_live is not None and from_live.available:
            merged.groups[name] = from_live
            if name == "interfaces" and from_telemetry is not None and from_telemetry.available:
                merged.conflicts.extend(_interface_conflicts(from_live.data, from_telemetry.data))
        elif from_telemetry is not None and from_telemetry.available:
            merged.groups[name] = from_telemetry
        else:
            merged.groups[name] = from_live or from_telemetry
    return merged


def _interface_conflicts(live: dict, telemetry: dict) -> list[dict]:
    conflicts = []
    for name in sorted(set(live) & set(telemetry)):
        live_oper, tele_oper = (live[name] or {}).get("oper"), (telemetry[name] or {}).get("oper")
        if live_oper and tele_oper and live_oper != tele_oper:
            conflicts.append({"group": "interfaces", "key": name, "live": live_oper, "telemetry": tele_oper, "used": "LIVE"})
    return conflicts


def group_freshness(group: FactGroup | None, evidence: EvidenceSet) -> str:
    return Freshness.UNKNOWN if group is None else group.freshness(evidence.now, evidence.thresholds)
