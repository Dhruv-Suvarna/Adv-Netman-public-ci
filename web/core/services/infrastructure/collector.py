"""Dynamic, management-path-aware telemetry collection (V2 Phase 8).

The chain this module closes::

    lifecycle fact -> MonitoringTarget (monitoring.reconcile) -> runtime target file (monitoring.write_runtime_targets)
    -> THIS collector -> InfluxDB line protocol (grafana.push) -> Grafana

The collector consumes the exported target FILE -- the secret-free contract every collector reads -- and never trusts it on
its own.  Before any connection each entry is checked against the database:

    * the MonitoringTarget is still ACTIVE, for the same device record                              else TARGET_NOT_ACTIVE
    * its generation, management path and address are the ones the file names                         else STALE_TARGET
    * the one management resolver (``management.resolve.endpoint``, READ) still answers that path     else MGMT_NO_USABLE_PATH / STALE_TARGET
    * the platform has a verified reader (cEOS only, below)                                          else PLATFORM_UNSUPPORTED

A stale file therefore never reaches a device over an old path: after a failover the next export carries the new path and a
new generation, and only that entry is collected.  The session itself is the health engine's ``EosSession`` -- privileged
EXEC, ``show`` commands from the fixed allowlist only, opened through ``nsot_live.get_live_target`` and
``ssh_transport.connect_eos``: the socket is bound to the path's NMAS interface and source, the host key is pinned to the
path's expected key, the credential is the path's own, and a revoked or unapproved path is refused before connecting
(``guard.authorized_target``).  There is no Docker console and no inventory-address fallback.

Measurements (integer fields; tags escaped by ``grafana.line``)
    nmas_dynamic_device     tags device, device_id, platform, management_path, path_type, collector, error (``none`` when collected)
                            fields generation, reachable (0/1)[, uptime_seconds, mem_total_kb, mem_free_kb]
    nmas_dynamic_interface  tags device, device_id, platform, management_path, path_type, collector, interface
                            fields generation, oper_up, admin_up, in_octets, out_octets, in_discards, out_discards,
                            in_ucast_pkts, out_ucast_pkts (each present only where the device reported it)

Every entry yields a ``nmas_dynamic_device`` point -- reachable=0 with an ``error`` code when collection was refused or
failed -- so a dashboard can show a target that stopped answering instead of silently losing its series.

EOS field names are the ones cEOS 4.36.2F returned live (``show version | json``: memTotal, memFree, uptime;
``show interfaces counters | json``: inOctets, outOctets, inDiscards, outDiscards, inUcastPkts, outUcastPkts).
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from django.utils import timezone

from ... import models
from ..health import live
from ..management import resolve
from . import grafana, monitoring

DEVICE_MEASUREMENT, INTERFACE_MEASUREMENT = "nmas_dynamic_device", "nmas_dynamic_interface"
COLLECTOR = "nmas-path-eos"
READERS = {models.Platform.ARISTA_CEOS: "ceos"}          # MonitoringTarget.platform -> health session platform
COUNTERS = {"inOctets": "in_octets", "outOctets": "out_octets", "inDiscards": "in_discards", "outDiscards": "out_discards",
            "inUcastPkts": "in_ucast_pkts", "outUcastPkts": "out_ucast_pkts"}
T = models.MonitoringTargetState


class TargetFileError(ValueError):
    """The target file is unreadable or not the export format.  The message is a fixed code."""


@dataclass
class Outcome:
    device: str
    status: str                     # COLLECTED | REFUSED | FAILED
    code: str = ""
    generation: int = 0
    management_path: str = ""
    points: list = field(default_factory=list)
    interfaces: int = 0

    def as_dict(self) -> dict:
        return {"device": self.device, "status": self.status, "code": self.code, "generation": self.generation,
                "management_path": self.management_path, "points": len(self.points), "interfaces": self.interfaces}


def load_targets(path=None) -> list[dict]:
    """The ``targets`` list of an exported target file (default: the monitoring runtime file)."""
    try:
        value = json.loads(Path(path or monitoring.default_runtime_path()).read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        raise TargetFileError("TARGET_FILE_UNREADABLE") from None
    targets = value.get("targets") if isinstance(value, dict) else None
    if not isinstance(targets, list) or not all(isinstance(t, dict) and t.get("device") for t in targets):
        raise TargetFileError("TARGET_FILE_INVALID")
    return targets


def check(entry: dict):
    """-> (MonitoringTarget | None, refusal code or "").  Pure database reads; never connects."""
    target = next((row for row in models.MonitoringTarget.objects.select_related("device", "management_path")
                   .filter(name=str(entry.get("device", ""))) if row.device.device_id == entry.get("device_id")), None)
    if target is None or target.state != T.ACTIVE:
        return target, "TARGET_NOT_ACTIVE"
    path_id = target.management_path.path_id if target.management_path_id else ""
    if (target.generation != entry.get("generation") or path_id != entry.get("management_path")
            or target.address != entry.get("address")):
        return target, "STALE_TARGET"
    if target.platform not in READERS:
        return target, "PLATFORM_UNSUPPORTED"
    current = resolve.endpoint(target.name, purpose=resolve.READ)
    if current.source != resolve.PATH:
        return target, "MGMT_NO_USABLE_PATH"
    if current.path_id != path_id or current.address != target.address:
        return target, "STALE_TARGET"
    return target, ""


def parse_version(text: str) -> dict:
    data = json.loads(text)
    return {"uptime_seconds": int(float(data["uptime"])), "mem_total_kb": int(data["memTotal"]), "mem_free_kb": int(data["memFree"])}


def parse_counters(text: str) -> dict:
    """{interface: {field: int}} -- only the counters the device reported, never a default."""
    rows = json.loads(text)["interfaces"]
    found = {}
    for name, row in rows.items():
        if not isinstance(row, dict):
            continue
        values = {ours: int(row[theirs]) for theirs, ours in COUNTERS.items() if isinstance(row.get(theirs), (int, float))}
        if values:
            found[str(name)] = values
    return found


def _tags(entry: dict, target) -> dict:
    path = target.management_path if target is not None and target.management_path_id else None
    return {"device": str(entry.get("device", "")), "device_id": str(entry.get("device_id", "")),
            "platform": str(entry.get("platform", "")), "management_path": path.path_id if path else str(entry.get("management_path", "")),
            "path_type": path.path_type if path else str(entry.get("path_type", "")), "collector": COLLECTOR}


def _unreachable(outcome: Outcome, entry: dict, target, status: str, code: str, now: datetime) -> Outcome:
    outcome.status, outcome.code = status, code
    outcome.points = [grafana.line(DEVICE_MEASUREMENT, {**_tags(entry, target), "error": code},
                                   {"generation": int(entry.get("generation") or 0), "reachable": 0}, now)]
    return outcome


def collect_one(entry: dict, *, session_factory=None, now: datetime | None = None) -> Outcome:
    now = now or timezone.now()
    outcome = Outcome(device=str(entry.get("device", "")), generation=int(entry.get("generation") or 0),
                      management_path=str(entry.get("management_path", "")), status="FAILED")
    target, refusal = check(entry)
    if refusal:
        return _unreachable(outcome, entry, target, "REFUSED", refusal, now)
    factory = session_factory or live.EosSession
    try:
        session = factory({"name": target.name, "platform": READERS[target.platform]})
    except live.LiveError as exc:
        return _unreachable(outcome, entry, target, "FAILED", exc.code, now)
    try:
        version = parse_version(session.run("version"))
        counters = parse_counters(session.run("interface_counters"))
        status = live.parse_eos_interfaces(session.run("interfaces"))
    except live.LiveError as exc:
        return _unreachable(outcome, entry, target, "FAILED", exc.code, now)
    except (ValueError, KeyError, TypeError):
        return _unreachable(outcome, entry, target, "FAILED", "PARSE_ERROR", now)
    finally:
        session.close()
    tags = _tags(entry, target)
    # error=none keeps one tag set per series: Grafana's Flux decoder panics on a group mixing tables with and without it
    points = [grafana.line(DEVICE_MEASUREMENT, {**tags, "error": "none"}, {"generation": target.generation, "reachable": 1, **version}, now)]
    for name in sorted(set(counters) | set(status)):
        fields = {"generation": target.generation, **counters.get(name, {})}
        if name in status:
            fields.update(oper_up=int(status[name]["oper"] == "UP"), admin_up=int(status[name]["admin"] == "UP"))
        points.append(grafana.line(INTERFACE_MEASUREMENT, {**tags, "interface": name}, fields, now))
    outcome.status, outcome.points, outcome.interfaces = "COLLECTED", points, len(points) - 1
    return outcome


def collect(entries: list[dict], *, session_factory=None, now: datetime | None = None) -> list[Outcome]:
    now = now or timezone.now()
    return [collect_one(entry, session_factory=session_factory, now=now) for entry in entries]


def run(*, targets_path=None, push: dict | None = None, session_factory=None, now: datetime | None = None) -> dict:
    """Collect every entry of the target file; optionally push to InfluxDB (``push`` = {url, org, bucket[, token]}).
    -> {targets, outcomes, counts, push}.  A push failure is reported as its fixed code, never raised past this point."""
    entries = load_targets(targets_path)
    outcomes = collect(entries, session_factory=session_factory, now=now)
    counts: dict = {}
    for outcome in outcomes:
        counts[outcome.status] = counts.get(outcome.status, 0) + 1
    report = {"targets": len(entries), "outcomes": [o.as_dict() for o in outcomes], "counts": counts, "push": None}
    if push:
        points = [p for o in outcomes for p in o.points]
        try:
            report["push"] = grafana.push(points, **push)
        except grafana.PushError as exc:
            report["push"] = {"error": str(exc)}
    return report
