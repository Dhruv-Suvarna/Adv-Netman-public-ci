"""The server-owned soak policy, and its PINNED snapshot.

Every value comes from trusted server configuration (``settings.PROBATION_SOAK_*``, bounded there; the production duration can only be
raised by the environment, never lowered) and from the EXISTING monitoring configuration (CPU consecutive-sample limit, freshness).  A run
copies the values it starts under into ``ProbationSoakRun.policy``; the evaluator only ever reads that snapshot, so changing a setting later
never shortens, extends or re-judges a soak that already started.  A browser can supply none of it.

Explicit rules, no weighted score (see docs/PROBATION_SOAK_AND_PROMOTION.md):

    duration     the window is ``duration_seconds`` of ELAPSED time (timedelta arithmetic on timezone-aware UTC datetimes).
    cadence      one sample per ``sample_interval_seconds`` bucket (default 900 s == the topology service's recent-event window, so consecutive
                 samples tile the timeline and no critical event can fall between two of them).
    max gap      no stretch longer than ``max_gap_seconds`` of the window may lack a usable sample (leading and trailing edges included).
    coverage     at least ``min_coverage_percent`` of the window's sample intervals must be covered by a usable sample.
    resources    a device at a CRITICAL CPU / memory level ends the soak only after ``resource_consecutive_samples`` consecutive samples -- the
                 project's own collector-alert policy (monitoring/config/cpu_threshold_policy.yml ``consecutive_samples``).
    decision     a technically passed soak stays eligible for the operator's decision for ``decision_max_age_seconds`` after it completed.
"""

from __future__ import annotations

import math
from dataclasses import asdict, dataclass
from pathlib import Path

import yaml
from django.conf import settings

from ..health import thresholds
from .codes import POLICY_VERSION


@dataclass(frozen=True)
class SoakPolicy:
    version: str
    duration_seconds: int
    sample_interval_seconds: int
    max_gap_seconds: int
    min_coverage_percent: int
    resource_consecutive_samples: int
    decision_max_age_seconds: int
    freshness_healthy_seconds: float
    freshness_stale_seconds: float
    production_duration_seconds: int

    @property
    def total_buckets(self) -> int:
        """The number of whole sample intervals in the window (the bucket AT this index is the closing sample, taken at / after the end)."""
        return math.ceil(self.duration_seconds / self.sample_interval_seconds)

    @property
    def is_production_duration(self) -> bool:
        return self.duration_seconds >= self.production_duration_seconds

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> "SoakPolicy":
        return cls(**{name: data[name] for name in cls.__dataclass_fields__})  # pylint: disable=no-member  # SoakPolicy is a dataclass


def _cpu_consecutive_samples() -> int:
    with open(Path(settings.REPO_ROOT) / thresholds.CPU_POLICY_FILE, encoding="utf-8") as handle:
        return int((yaml.safe_load(handle) or {})["consecutive_samples"])


def current_policy() -> SoakPolicy:
    """The policy a NEW run would start under (read from trusted server configuration; validated, never partially applied)."""
    freshness = thresholds.load_thresholds()["freshness"]
    policy = SoakPolicy(
        version=POLICY_VERSION, duration_seconds=int(settings.PROBATION_SOAK_DURATION_SECONDS),
        sample_interval_seconds=int(settings.PROBATION_SOAK_SAMPLE_INTERVAL_SECONDS), max_gap_seconds=int(settings.PROBATION_SOAK_MAX_GAP_SECONDS),
        min_coverage_percent=int(settings.PROBATION_SOAK_MIN_COVERAGE_PERCENT), resource_consecutive_samples=_cpu_consecutive_samples(),
        decision_max_age_seconds=int(settings.PROBATION_SOAK_DECISION_MAX_AGE_SECONDS), freshness_healthy_seconds=float(freshness["healthy"]),
        freshness_stale_seconds=float(freshness["stale"]), production_duration_seconds=int(settings.SOAK_PRODUCTION_DURATION_SECONDS),
    )
    if min(policy.duration_seconds, policy.sample_interval_seconds, policy.max_gap_seconds, policy.resource_consecutive_samples) < 1:
        raise ValueError("Soak policy values must be positive.")
    if policy.max_gap_seconds < policy.sample_interval_seconds or not 0 < policy.min_coverage_percent <= 100:
        raise ValueError("Soak policy: the maximum gap must be at least one sample interval and coverage must be 1-100 percent.")
    return policy
