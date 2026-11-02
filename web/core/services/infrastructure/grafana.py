"""Lifecycle visibility in Grafana: InfluxDB line protocol for REAL monitoring targets only, and a token-safe push.

Measurements
    nmas_device_lifecycle        tags device, device_id, platform, lifecycle_state, monitoring_state, management_path, maintenance
                                 fields generation (int), admitted (0/1), monitored (0/1)
    nmas_device_lifecycle_event  tags device, device_id, event (REGISTERED / PATH_CHANGED / PATH_LOST / RETIRED / RESTORED ...)
                                 fields generation (int)

A device whose only record is the EXPECTED registration (never registered as a monitoring target) yields NO point: Grafana must
never show a device as operational because its expected record exists.  The InfluxDB token is an argument or the environment
(``NMAS_INFLUX_TOKEN`` / ``INFLUXDB_TOKEN``) and is never stored, logged or returned.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime
from pathlib import Path

from django.utils import timezone

from ... import models
from . import facts

MEASUREMENT, EVENT_MEASUREMENT = "nmas_device_lifecycle", "nmas_device_lifecycle_event"
EVENT_KINDS = frozenset({"REGISTERED", "PATH_CHANGED", "PATH_LOST", "SUSPENDED", "RETIRED", "RESTORED", "MAINTENANCE_ENTERED",
                         "MAINTENANCE_EXITED"})
T = models.MonitoringTargetState


DATASOURCE_UID = "nmas-influxdb"
LIFECYCLE_DASHBOARD = Path(__file__).resolve().parents[4] / "monitoring/grafana/provisioning/dashboards/json/device-lifecycle.json"
LIFECYCLE_CONTRACT = {"uid": "nmas-device-lifecycle", "title": "NMAS Device Lifecycle", "variables": {"device"},
                      "panels": {"Lifecycle state", "Monitoring state", "Management path", "Generation / reconnects",
                                 "Decommission / restore events", "Dynamic collection by management path"}}
# Every query reads one of NMAS's own lifecycle measurements: the lifecycle state / events written here, and the path-aware
# collector's readings (core.services.infrastructure.collector).
DASHBOARD_MEASUREMENTS = (MEASUREMENT, EVENT_MEASUREMENT, "nmas_dynamic_device", "nmas_dynamic_interface")


class DashboardError(ValueError):
    """The lifecycle dashboard breaks its contract.  The message is a fixed code."""


def load_lifecycle_dashboard(path=None) -> dict:
    """Load the provisioned lifecycle dashboard and enforce its contract: stable uid / title, not editable, the
    expected panels and variables, every query on the provisioned datasource reading one of ``DASHBOARD_MEASUREMENTS``."""
    try:
        value = json.loads(Path(path or LIFECYCLE_DASHBOARD).read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        raise DashboardError("DASHBOARD_UNREADABLE") from None
    if not isinstance(value, dict) or value.get("uid") != LIFECYCLE_CONTRACT["uid"] or value.get("title") != LIFECYCLE_CONTRACT["title"]:
        raise DashboardError("DASHBOARD_IDENTITY")
    if value.get("editable") is not False:
        raise DashboardError("DASHBOARD_EDITABLE")
    panels = value.get("panels")
    if not isinstance(panels, list) or {p.get("title") for p in panels if isinstance(p, dict)} != LIFECYCLE_CONTRACT["panels"]:
        raise DashboardError("DASHBOARD_PANELS")
    if {v.get("name") for v in (value.get("templating") or {}).get("list", []) if isinstance(v, dict)} != LIFECYCLE_CONTRACT["variables"]:
        raise DashboardError("DASHBOARD_VARIABLES")
    targets = [t for p in panels for t in (p.get("targets") or [])]
    if not targets or any((t.get("datasource") or {}).get("uid") != DATASOURCE_UID
                          or not any(f'r._measurement == "{m}"' in str(t.get("query", "")) for m in DASHBOARD_MEASUREMENTS)
                          for t in targets):
        raise DashboardError("DASHBOARD_QUERY")
    return value


class PushError(Exception):
    """A push failed.  The message is a fixed code (never the token or the server's response body)."""


def _tag(value) -> str:
    text = str(value if value not in (None, "") else "none")
    return text.replace("\\", "\\\\").replace(",", "\\,").replace(" ", "\\ ").replace("=", "\\=")


def _ns(moment: datetime) -> int:
    return int(moment.timestamp() * 1_000_000_000)


def line(measurement: str, tags: dict, fields: dict, at: datetime) -> str:
    """One line-protocol record (integer fields only; tags escaped and sorted)."""
    if not fields:
        raise ValueError("a point needs at least one field")
    tag_text = ",".join(f"{_tag(k)}={_tag(v)}" for k, v in sorted(tags.items()))
    field_text = ",".join(f"{_tag(k)}={int(v)}i" for k, v in sorted(fields.items()))
    return f"{measurement},{tag_text} {field_text} {_ns(at)}"


def real_targets():
    """Targets that were actually registered (``registered_at`` set) -- never an expected-only record.  When a restored
    successor exists, only the newest registration of a name is returned (one series per device name)."""
    rows = models.MonitoringTarget.objects.select_related("device", "management_path").filter(registered_at__isnull=False).order_by("name", "-device__pk")
    latest = {}
    for target in rows:
        latest.setdefault(target.name, target)
    return [latest[name] for name in sorted(latest)]


def lifecycle_points(*, now=None, include_events: bool = True) -> list[str]:
    """Line protocol for every real target (state) and its bounded history (decommission / restore / path events)."""
    now = now or timezone.now()
    points = []
    for target in real_targets():
        device = target.device
        tags = {"device": target.name, "device_id": device.device_id, "platform": target.platform,
                "lifecycle_state": device.lifecycle_state, "monitoring_state": target.state,
                "management_path": target.management_path.path_id if target.management_path_id else "none",
                "maintenance": "true" if facts.under_maintenance(target.name) else "false"}
        fields = {"generation": target.generation, "admitted": int(device.admission_state in facts.ADMITTED_STATES),
                  "monitored": int(target.state == T.ACTIVE)}
        points.append(line(MEASUREMENT, tags, fields, now))
        if include_events:
            history = list(target.history or [])
            if target.device.predecessor_id:
                previous = models.MonitoringTarget.objects.filter(device_id=target.device.predecessor_id).first()
                history = list(previous.history or []) + history if previous else history
            for entry in history:
                kind = str(entry.get("event", ""))
                if kind not in EVENT_KINDS:
                    continue
                try:
                    at = datetime.fromisoformat(str(entry.get("at")))
                except ValueError:
                    continue
                points.append(line(EVENT_MEASUREMENT, {"device": target.name, "device_id": device.device_id, "event": kind},
                                   {"generation": int(entry.get("generation", 0) or 0)}, at))
    return points


def push(points: list[str], *, url: str, org: str, bucket: str, token: str | None = None, timeout: float = 10.0) -> dict:
    """POST ``points`` to InfluxDB v2 (``/api/v2/write``).  -> {status, points}.  Raises PushError with a fixed code."""
    token = token or os.environ.get("NMAS_INFLUX_TOKEN") or os.environ.get("INFLUXDB_TOKEN") or ""
    if not token:
        raise PushError("INFLUX_TOKEN_MISSING")
    if not points:
        return {"status": 0, "points": 0}
    parsed = urllib.parse.urlparse(str(url))
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise PushError("INFLUX_URL_INVALID")
    query = urllib.parse.urlencode({"org": org, "bucket": bucket, "precision": "ns"})
    request = urllib.request.Request(f"{url.rstrip('/')}/api/v2/write?{query}", data=("\n".join(points) + "\n").encode(), method="POST",
                                     headers={"Authorization": f"Token {token}", "Content-Type": "text/plain; charset=utf-8"})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310 - scheme checked above
            return {"status": response.status, "points": len(points)}
    except urllib.error.HTTPError as exc:
        raise PushError(f"INFLUX_HTTP_{exc.code}") from None
    except (urllib.error.URLError, OSError):
        raise PushError("INFLUX_UNREACHABLE") from None
