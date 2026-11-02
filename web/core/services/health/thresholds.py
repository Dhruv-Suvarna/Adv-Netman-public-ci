"""Freshness and resource thresholds -- consumed from the EXISTING monitoring definitions, never redefined.

* CPU     ``monitoring/config/cpu_threshold_policy.yml`` (``warning_pct`` / ``critical_pct``): the collector-alert policy.
* Memory  75 / 90 %: mirrors the Grafana "Memory utilization" panel thresholds in
          ``monitoring/scripts/build_grafana_dashboards.py`` (a contract test fails if the two ever drift).
* Freshness ``monitoring/config/topology.yml`` (``healthy_seconds`` / ``stale_seconds``), the same values the topology
          service applies to every node (its payload also carries them, and the payload wins when present).

There is exactly ONE threshold system; this module only reads it.
"""

from __future__ import annotations

from pathlib import Path

import yaml
from django.conf import settings

from .codes import Freshness

MEMORY_WARNING_PCT = 75
MEMORY_CRITICAL_PCT = 90

CPU_POLICY_FILE = "monitoring/config/cpu_threshold_policy.yml"
TOPOLOGY_CONFIG_FILE = "monitoring/config/topology.yml"


def _load(relative: str) -> dict:
    with open(Path(settings.REPO_ROOT) / relative, encoding="utf-8") as handle:
        return yaml.safe_load(handle) or {}


def load_thresholds(payload_seconds: dict | None = None) -> dict:
    """{"cpu": {...}, "memory": {...}, "freshness": {"healthy": s, "stale": s}} -- deterministic, secret-free."""
    cpu = _load(CPU_POLICY_FILE)
    topology = _load(TOPOLOGY_CONFIG_FILE)
    healthy, stale = topology["healthy_seconds"], topology["stale_seconds"]
    if isinstance(payload_seconds, dict):  # the running service's own values are authoritative
        healthy = payload_seconds.get("healthy_max", healthy)
        stale = payload_seconds.get("stale_max", stale)
    return {
        "cpu": {"warning": float(cpu["warning_pct"]), "critical": float(cpu["critical_pct"])},
        "memory": {"warning": float(MEMORY_WARNING_PCT), "critical": float(MEMORY_CRITICAL_PCT)},
        "freshness": {"healthy": float(healthy), "stale": float(stale)},
    }


def classify_age(age_seconds, freshness: dict) -> str:
    """FRESH <= healthy < STALE <= stale < EXPIRED; no age -> UNKNOWN.  Boundaries are inclusive on the lower class."""
    if age_seconds is None:
        return Freshness.UNKNOWN
    age = max(0.0, float(age_seconds))
    if age <= freshness["healthy"]:
        return Freshness.FRESH
    if age <= freshness["stale"]:
        return Freshness.STALE
    return Freshness.EXPIRED


def classify_level(value, band: dict) -> str | None:
    """"CRITICAL" / "WARNING" / "NORMAL" for a metric, or None when the metric does not exist (never treated as 0)."""
    if value is None:
        return None
    if value >= band["critical"]:
        return "CRITICAL"
    if value >= band["warning"]:
        return "WARNING"
    return "NORMAL"
