"""The one-time legacy baseline bootstrap -- the reusable service API.  Views and the management command call THIS module.

    readiness_probe()                     read-only dry probe (persists nothing)
    capture_candidate(actor=..)           read-only reads -> sanitized canonical baseline -> immutable LEGACY_BASELINE candidate (all-or-nothing)
    check_start / start_bootstrap         explicit; the server fixes the start, the 30-minute end and the policy
    run_tick / drive                      the read-only collector and the one-time command's wait loop
    approve(run, ..)                      the operator's explicit approval: decision-time configuration re-check, then the initial Golden
    gate_blockers()                       why the shortcut is unavailable (persisted state; permanent once the initial Golden exists)

Nothing here configures a device, NetBox, Git or Containerlab, and nothing here changes the normal seven-day probation policy (``soak_service``).
"""

from __future__ import annotations

from .bootstrap import baseline, capture, codes, decision, evaluator, evidence, interference, lifecycle, policy
from .bundles import legacy

gate_blockers = legacy.gate_blockers
legacy_golden = legacy.legacy_golden
check_initial_golden = legacy.check_initial_golden
readiness_probe = baseline.readiness_probe
capture_candidate = baseline.capture_candidate
CaptureResult = baseline.CaptureResult
active_run = baseline.active_run
current_policy = policy.current_policy
check_start = lifecycle.check_start
start_bootstrap = lifecycle.start_bootstrap
cancel_bootstrap = lifecycle.cancel_bootstrap
run_tick = lifecycle.run_tick
drive = lifecycle.drive
progress = lifecycle.progress
get_run = lifecycle.get_run
list_runs = lifecycle.list_runs
decision_of = lifecycle.decision_of
approve = decision.approve
recheck_configuration = capture.recheck_configuration
verify_run = evaluator.verify_run
BOOTSTRAP_BLOCKERS = codes.BOOTSTRAP_BLOCKERS
TERMINAL_REASONS = codes.TERMINAL_REASONS
MAX_REASON_CHARS = codes.MAX_REASON_CHARS
MAX_SAMPLE_ROWS_SHOWN = codes.MAX_SAMPLE_ROWS_SHOWN
POLICY_VERSION = codes.POLICY_VERSION
find_interference = interference.find_interference
