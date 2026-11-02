"""Telemetry freshness, read from the existing topology service's ``/api/topology`` document.

That document is the project's single telemetry summary (it is what the website's health engine reads too): per node the latest gNMI
sample timestamp, CPU and memory, derived from the existing InfluxDB bucket.  This module adds no second definition of "fresh": the
classes and boundaries are the project's own (``web/core/services/health/thresholds.py``) --

    age <= healthy  -> FRESH        healthy < age <= stale -> STALE        age > stale -> EXPIRED        no sample -> UNKNOWN

with ``healthy`` / ``stale`` taken from the running service's payload, falling back to ``monitoring/config/topology.yml``.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

import yaml

from ..models import FreshnessRow, parse_time
from . import http

FRESH, STALE, EXPIRED, UNKNOWN = "FRESH", "STALE", "EXPIRED", "UNKNOWN"


class TelemetryUnavailable(Exception):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def load_thresholds(policy_path: Path, payload: dict | None = None) -> dict:
    """{"healthy": seconds, "stale": seconds}: the running service's values win, the tracked policy file is the fallback."""
    healthy = stale = None
    try:
        with open(policy_path, encoding="utf-8") as handle:
            policy = yaml.safe_load(handle) or {}
        healthy, stale = policy.get("healthy_seconds"), policy.get("stale_seconds")
    except (OSError, yaml.YAMLError):
        pass
    if isinstance(payload, dict):
        healthy, stale = payload.get("healthy_max", healthy), payload.get("stale_max", stale)
    if healthy is None or stale is None:
        raise TelemetryUnavailable("THRESHOLDS_UNAVAILABLE")
    return {"healthy": float(healthy), "stale": float(stale)}


def classify_age(age_seconds, thresholds: dict) -> str:
    if age_seconds is None:
        return UNKNOWN
    age = max(0.0, float(age_seconds))
    if age <= thresholds["healthy"]:
        return FRESH
    if age <= thresholds["stale"]:
        return STALE
    return EXPIRED


def _number(value):
    return float(value) if isinstance(value, (int, float)) and not isinstance(value, bool) else None


def rows_from_payload(payload: dict, *, now: datetime, thresholds: dict, managed: set[str]) -> list[FreshnessRow]:
    """One row per MONITORED node, plus a row for any managed device the payload does not carry (UNKNOWN: missing, never assumed)."""
    rows, seen = [], set()
    for node in (payload.get("graph") or {}).get("nodes") or []:
        name = str(node.get("id") or "")
        if not name or not (node.get("monitored") or name in managed):
            continue
        seen.add(name)
        last = parse_time(node.get("last_telemetry_timestamp"))
        age = (now - last).total_seconds() if last else None
        rows.append(FreshnessRow(name, name in managed, last, age, classify_age(age, thresholds), str(node.get("health") or ""),
                                 _number(node.get("cpu_percent")), _number(node.get("memory_percent"))))
    for name in sorted(managed - seen):
        rows.append(FreshnessRow(name, True, None, None, UNKNOWN))
    return sorted(rows, key=lambda row: (not row.managed, row.device))


def read(config, *, managed: set[str], now: datetime, getter=http.get) -> dict:
    """{"rows", "thresholds", "backend", "generated_at"}; raises ``TelemetryUnavailable`` with a fixed code."""
    result = getter(config.topology_api_url, timeout=config.http_timeout, max_bytes=4_000_000)
    if result.status is None:
        raise TelemetryUnavailable(result.error or "UNREACHABLE")
    if not result.ok:
        raise TelemetryUnavailable(f"HTTP_{result.status}")
    payload = result.json()
    if not isinstance(payload, dict) or not isinstance(payload.get("graph"), dict):
        raise TelemetryUnavailable("PARSE_ERROR")
    thresholds = load_thresholds(config.topology_policy_path, payload.get("health_thresholds_seconds"))
    backend = str((payload.get("backend") or {}).get("status") or "UNKNOWN").upper()
    return {"rows": rows_from_payload(payload, now=now, thresholds=thresholds, managed=managed), "thresholds": thresholds,
            "backend": backend, "generated_at": parse_time(payload.get("generated_at"))}
