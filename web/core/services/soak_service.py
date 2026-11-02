"""Phase-20 probation soak -- the reusable service API.  Views, the scheduler command and later phases call THIS module; no soak logic lives in a
view.  Nothing here executes a Configlet, contacts a device beyond the Phase-15 read-only evidence allowlists, writes NetBox / Git / GitHub,
refreshes telemetry, saves a device configuration or holds a lock for the observation window.

    check_soak_start(bundle)              read-only: may this Probation bundle start a soak?  (blockers with stable codes)
    start_soak(bundle, actor=..)          explicit; the SERVER pins the duration and computes the start / required end; idempotent
    cancel_soak(run, actor=..)            explicit; audited; evidence kept; never resumable
    run_tick(now=.., dry_run=..)          the idempotent, restartable collector (one due sample per running soak; evaluates; finalises once)
    progress(run) / get_run / list_runs   read models
    decide(run, decision=.., actor=..)    the operator's explicit APPROVE / REJECT of a technically passed soak (the ONLY Golden creation path)
    current_policy()                      the policy a new run would start under
"""

from __future__ import annotations

from .. import models
from .soak import codes, decision as _decision, eligibility, evaluator, lifecycle, overview as _overview, policy

check_soak_start = eligibility.check_start
active_run = eligibility.active_run
start_soak = lifecycle.start_soak
cancel_soak = lifecycle.cancel_soak
run_tick = lifecycle.run_tick
progress = lifecycle.progress
get_run = lifecycle.get_run
decide = _decision.decide
current_policy = policy.current_policy
overview = _overview.overview
describe = _overview.describe
verify_run = evaluator.verify_run
START_BLOCKERS = codes.START_BLOCKERS
DECISION_BLOCKERS = codes.DECISION_BLOCKERS
TERMINAL_REASONS = codes.TERMINAL_REASONS
MAX_REASON_CHARS = codes.MAX_REASON_CHARS
MAX_SAMPLE_ROWS_SHOWN = codes.MAX_SAMPLE_ROWS_SHOWN


def list_runs(*, bundle=None, limit: int = 100):
    queryset = models.ProbationSoakRun.objects.select_related("bundle__change")
    if bundle is not None:
        queryset = queryset.filter(bundle=bundle)
    return list(queryset.order_by("-started_at", "-id")[:limit])


def decision_of(run):
    return models.GoldenDecision.objects.filter(run=run).select_related("golden_bundle").first()
