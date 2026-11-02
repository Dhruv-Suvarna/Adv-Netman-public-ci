"""Phase-17 structured execution -- the reusable service API.

Views, a CLI or a future orchestrator call THIS module; no deployment logic lives in a view.  Execution is always an
EXPLICIT call: nothing here runs on import, on a page view, after validation, after a plan build, after a precheck, or
from GitHub Actions.  The only mutating entry point is ``execute_change``.

    check_execution_eligibility(change, ...)   read-only gate: every blocker with its stable code and remediation
    execute_change(change, actor=..., ...)     the explicit Complete / Partial (UAT) execution of the CURRENT plan
    get_run(change, run_id) / list_runs(change) / latest_run(change)     append-only history (read-only)
    serialize_run(run) / report_filename(run)   sanitized machine-readable run
    capability_for(platform, object_type)       evidence-based execution capability (apply / compensation)
"""

from __future__ import annotations

from .execution import capability, codes, eligibility, engine, persistence

check_execution_eligibility = eligibility.check_execution_eligibility
execute_change = engine.execute_change
ExecutionResult = engine.ExecutionResult
get_run = persistence.get_run
list_runs = persistence.list_runs
latest_run = persistence.latest_run
serialize_run = persistence.serialize_run
report_filename = persistence.report_filename
report_json = persistence.report_json
capability_for = capability.capability_for
capability_matrix = capability.capability_matrix
ENGINE_VERSION = codes.ENGINE_VERSION
BLOCKERS = codes.BLOCKERS
UAT_ACK_FIELDS = codes.UAT_ACK_FIELDS
OUTCOME_PRESENTATION = codes.OUTCOME_PRESENTATION

__all__ = [
    "BLOCKERS", "ENGINE_VERSION", "ExecutionResult", "OUTCOME_PRESENTATION", "UAT_ACK_FIELDS", "capability_for", "capability_matrix",
    "check_execution_eligibility", "execute_change", "get_run", "latest_run", "list_runs", "report_filename", "report_json", "serialize_run",
]
