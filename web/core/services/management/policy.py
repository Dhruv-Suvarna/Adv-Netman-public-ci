"""Bounded selector and probe policy.

Every value has a hard lower AND upper bound: a deployment may tune within them through Django settings, but no setting
can turn hysteresis off (threshold 0), make failback immediate (hold-down 0) or let a probe hang (unbounded timeout).
"""

from __future__ import annotations

from dataclasses import dataclass

from django.conf import settings

_BOUNDS = {
    # name: (setting, default, minimum, maximum)
    "failure_threshold": ("NMAS_MGMT_FAILURE_THRESHOLD", 3, 2, 10),
    "restore_threshold": ("NMAS_MGMT_RESTORE_THRESHOLD", 3, 2, 20),
    "hold_down_seconds": ("NMAS_MGMT_FAILBACK_HOLD_DOWN_SECONDS", 120, 30, 3600),
    "probe_timeout_seconds": ("NMAS_MGMT_PROBE_TIMEOUT_SECONDS", 5, 1, 15),
    "min_probe_interval_seconds": ("NMAS_MGMT_MIN_PROBE_INTERVAL_SECONDS", 5, 0, 300),
}


def _bounded(name: str, override=None) -> int:
    setting, default, low, high = _BOUNDS[name]
    raw = override if override is not None else getattr(settings, setting, default)
    try:
        value = int(raw)
    except (TypeError, ValueError):
        value = default
    return max(low, min(high, value))


@dataclass(frozen=True)
class Policy:
    failure_threshold: int
    restore_threshold: int
    hold_down_seconds: int
    probe_timeout_seconds: int
    min_probe_interval_seconds: int

    def as_dict(self) -> dict:
        return dict(self.__dict__)


def effective(path=None) -> Policy:
    """The policy for ``path`` (its bounded per-path overrides, else the deployment values)."""
    overrides = dict(getattr(path, "policy", None) or {})
    return Policy(**{name: _bounded(name, overrides.get(name)) for name in _BOUNDS})


def bounds() -> dict:
    return {name: {"min": low, "max": high, "default": default} for name, (_s, default, low, high) in _BOUNDS.items()}
