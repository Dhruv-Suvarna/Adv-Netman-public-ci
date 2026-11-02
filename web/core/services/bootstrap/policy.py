"""LEGACY_BOOTSTRAP_POLICY_V1: the server-owned, PINNED policy of the one-time bootstrap observation.

It is a separate policy object of the SAME type the Phase-20 evaluator already consumes (``SoakPolicy``), so the pure evaluator, the coverage
maths and the resource-streak rule are reused unchanged.  The normal seven-day production soak (``soak.policy.current_policy``) is NOT touched:
this module never reads or writes ``PROBATION_SOAK_*``.

    duration       30 minutes of ELAPSED time (timedelta on timezone-aware UTC; never backdated, sleep-skipped or patched)
    cadence        one sample per 300 s bucket  ->  T+0, T+5, ... T+25 and the closing sample at / after T+30
    coverage       at least 80 % of the six intervals covered by a usable sample (i.e. five of six)
    max gap        no stretch longer than 600 s may lack a usable sample (leading and trailing edges included)
    resources      a critical CPU / memory level ends the run only after the project's ``consecutive_samples`` (cpu_threshold_policy.yml)
    decision       a technically passed observation stays approvable for 1 hour

Values come from ``settings.LEGACY_BOOTSTRAP_*`` (bounded there: the duration can only be RAISED above 30 minutes) and are copied into
``LegacyBootstrapRun.policy`` at start; the evaluator only ever reads that pinned copy.  A browser can supply none of it.
"""

from __future__ import annotations

from django.conf import settings

from ..health import thresholds
from ..soak.policy import SoakPolicy, _cpu_consecutive_samples
from .codes import POLICY_VERSION

DEFAULT_DURATION_SECONDS = 30 * 60


def current_policy() -> SoakPolicy:
    freshness = thresholds.load_thresholds()["freshness"]
    policy = SoakPolicy(
        version=POLICY_VERSION, duration_seconds=int(settings.LEGACY_BOOTSTRAP_DURATION_SECONDS),
        sample_interval_seconds=int(settings.LEGACY_BOOTSTRAP_SAMPLE_INTERVAL_SECONDS), max_gap_seconds=int(settings.LEGACY_BOOTSTRAP_MAX_GAP_SECONDS),
        min_coverage_percent=int(settings.LEGACY_BOOTSTRAP_MIN_COVERAGE_PERCENT), resource_consecutive_samples=_cpu_consecutive_samples(),
        decision_max_age_seconds=int(settings.LEGACY_BOOTSTRAP_DECISION_MAX_AGE_SECONDS), freshness_healthy_seconds=float(freshness["healthy"]),
        freshness_stale_seconds=float(freshness["stale"]), production_duration_seconds=int(settings.SOAK_PRODUCTION_DURATION_SECONDS),
    )
    if min(policy.duration_seconds, policy.sample_interval_seconds, policy.max_gap_seconds, policy.resource_consecutive_samples) < 1:
        raise ValueError("Bootstrap policy values must be positive.")
    if policy.max_gap_seconds < policy.sample_interval_seconds or not 0 < policy.min_coverage_percent <= 100:
        raise ValueError("Bootstrap policy: the maximum gap must be at least one sample interval and coverage must be 1-100 percent.")
    return policy


def candidate_max_age_seconds() -> int:
    return int(settings.LEGACY_BOOTSTRAP_CANDIDATE_MAX_AGE_SECONDS)
