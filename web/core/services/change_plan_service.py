"""Phase-14 unified priority / dependency plan builder -- the reusable service API.

Views and later phases call THIS module; no planning logic lives in a view.  Nothing here
deploys, contacts a device, writes NetBox/Git, executes a Configlet, sends a notification, or
advances Change.lifecycle_state.

    build_change_plan(change, actor=..)    eligibility -> idempotent, atomic plan build (explicit action)
    check_eligibility(change)              may a plan be built right now? (never runs validation)
    get_current_plan(change)               latest plan iff CURRENT, else None
    get_latest_plan(change)                newest plan (CURRENT or STALE) or None
    get_plan_currency(plan)                CURRENT / STALE with reasons
    get_plan(change, plan_id)              one historical plan (must belong to the Change)
    list_plans(change)                     newest first
    serialize_plan(plan)                   sanitized machine-readable document
"""

from __future__ import annotations

import uuid

from .planning import builder, priorities, serialization
from .planning.errors import ERROR_MESSAGES, PlanGenerationError

MAX_HISTORY = 10
PLANNER_VERSION = priorities.PLANNER_VERSION

build_change_plan = builder.build_change_plan
check_eligibility = builder.check_eligibility
compute_plan = builder.compute_plan
get_plan_currency = builder.get_plan_currency
get_latest_plan = builder.get_latest_plan
get_current_plan = builder.get_current_plan
serialize_plan = serialization.serialize_plan
plan_report_filename = serialization.plan_report_filename
stage_table = priorities.stage_table

__all__ = [
    "ERROR_MESSAGES", "PlanGenerationError", "PLANNER_VERSION", "build_change_plan", "check_eligibility", "compute_plan",
    "get_plan_currency", "get_latest_plan", "get_current_plan", "get_plan", "list_plans", "serialize_plan",
    "plan_report_filename", "stage_table",
]


def get_plan(change, plan_id):
    """A plan is only ever addressed THROUGH its Change (never by a bare id)."""
    try:
        parsed = uuid.UUID(str(plan_id))
    except ValueError:
        return None
    return change.plans.filter(plan_id=parsed).first()


def list_plans(change, *, limit: int = MAX_HISTORY):
    return list(change.plans.order_by("-created_at", "-id")[:limit])
