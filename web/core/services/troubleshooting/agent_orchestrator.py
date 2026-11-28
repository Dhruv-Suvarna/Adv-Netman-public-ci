"""Capacity-aware, globally fenced Troubleshooter model orchestration.

This module grants model *completion* authority only.  It never exposes a
shell, Docker, SSH, credentials, device configuration, or an alternate write
path.  Device/research authority remains in the existing typed workers and
``ai.call_tool``; remediation remains in the governed Change Engine.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable

from django.db import transaction

from core import models as m

from . import contracts as c


AGENTS = ("Codex", "ClaudeA", "ClaudeB")
DEFAULT_LEASE_SECONDS = 90
DEFAULT_STALL_SECONDS = 180
MAX_HISTORY = 200


class OrchestrationRefused(RuntimeError):
    def __init__(self, code: str, message: str = ""):
        super().__init__(f"{code}: {message}" if message else code)
        self.code = code


class StaleExecutionLease(OrchestrationRefused):
    pass


@dataclass(frozen=True)
class WorkEstimate:
    next_tokens: int
    checkpoint_reserve_tokens: int = 2_000
    bounded: bool = True
    short_task: bool = False

    @property
    def required_tokens(self) -> int:
        return max(0, int(self.next_tokens)) + max(0, int(self.checkpoint_reserve_tokens))


@dataclass(frozen=True)
class AgentHealth:
    name: str
    authenticated: bool
    responsive: bool
    restricted_interface: bool
    remaining_quota_pct: float | None = None
    quota_reliable: bool = False
    context_remaining_tokens: int | None = None
    recent_error: str = ""
    cooldown_until: datetime | None = None
    process_alive: bool = True

    def quota_label(self) -> str:
        if self.quota_reliable and self.remaining_quota_pct is not None:
            return f"{max(0.0, min(100.0, self.remaining_quota_pct)):.1f}%"
        return "UNKNOWN"


@dataclass(frozen=True)
class AgentDecision:
    selected: str | None
    eligible: tuple[str, ...]
    rejected: dict[str, str]
    capacity: dict[str, dict[str, Any]]


@dataclass(frozen=True)
class LeaseGrant:
    handoff_id: str
    agent: str
    fencing_token: int
    expires_at: datetime


@dataclass(frozen=True)
class WatchdogResult:
    action: str
    reason: str
    grant: LeaseGrant | None = None


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _digest(value: Any) -> str:
    return hashlib.sha256(c.canonical_json(value).encode("utf-8")).hexdigest()


def _checkpoint_digest(checkpoint: dict) -> str:
    durable = dict(checkpoint or {})
    durable.pop("execution_lease", None)
    return _digest(durable)


def _capacity_snapshot(status: AgentHealth) -> dict[str, Any]:
    return {
        "authenticated": status.authenticated,
        "responsive": status.responsive,
        "restricted_interface": status.restricted_interface,
        "quota": status.quota_label(),
        "quota_reliable": status.quota_reliable,
        "context_remaining_units": status.context_remaining_tokens,
        "recent_error": status.recent_error[:80],
        "process_alive": status.process_alive,
    }


def _reject_reason(status: AgentHealth, estimate: WorkEstimate, now: datetime) -> str:
    if status.name not in AGENTS:
        return "UNREGISTERED_AGENT"
    if not status.authenticated:
        return "AUTHENTICATION_UNAVAILABLE"
    if not status.process_alive:
        return "PROCESS_UNAVAILABLE"
    if not status.responsive:
        return "PROVIDER_UNRESPONSIVE"
    if not status.restricted_interface:
        return "RESTRICTED_COMPLETION_INTERFACE_UNVERIFIED"
    if status.cooldown_until is not None and status.cooldown_until > now:
        return "COOLDOWN_ACTIVE"
    if status.recent_error.upper() in {"QUOTA_EXHAUSTED", "RATE_LIMITED", "CONTEXT_EXHAUSTED"}:
        return status.recent_error.upper()
    if status.context_remaining_tokens is not None and status.context_remaining_tokens < estimate.required_tokens:
        return "INSUFFICIENT_CONTEXT_CAPACITY"
    if status.quota_reliable and status.remaining_quota_pct is not None:
        quota = max(0.0, min(100.0, status.remaining_quota_pct))
        if quota < 10.0:
            return "QUOTA_BELOW_10_PERCENT"
        if quota <= 25.0 and not (estimate.bounded and estimate.short_task):
            return "LOW_QUOTA_REQUIRES_SHORT_BOUNDED_TASK"
    elif not estimate.bounded:
        return "UNKNOWN_QUOTA_REQUIRES_BOUNDED_TASK"
    return ""


def select_agent(statuses: Iterable[AgentHealth], estimate: WorkEstimate, *, exclude: Iterable[str] = (),
                 now: datetime | None = None) -> AgentDecision:
    """Choose a healthy agent without fabricating provider quota.

    Known healthy capacity outranks unknown capacity.  Within the same capacity
    class the stable preference is Codex, ClaudeA, ClaudeB.
    """

    now = now or _now()
    excluded = set(exclude)
    by_name = {s.name: s for s in statuses}
    rejected: dict[str, str] = {}
    eligible: list[AgentHealth] = []
    capacity = {name: _capacity_snapshot(status) for name, status in by_name.items()}
    for name in AGENTS:
        status = by_name.get(name)
        if status is None:
            rejected[name] = "HEALTH_UNKNOWN"
            continue
        if name in excluded:
            rejected[name] = "EXCLUDED_FROM_THIS_TRANSFER"
            continue
        reason = _reject_reason(status, estimate, now)
        if reason:
            rejected[name] = reason
        else:
            eligible.append(status)

    preference = {name: index for index, name in enumerate(AGENTS)}

    def score(status: AgentHealth) -> tuple[int, int]:
        if status.quota_reliable and status.remaining_quota_pct is not None:
            capacity_class = 0 if status.remaining_quota_pct > 25.0 else 1
        else:
            capacity_class = 2
        return (capacity_class, preference[status.name])

    eligible.sort(key=score)
    return AgentDecision(eligible[0].name if eligible else None, tuple(s.name for s in eligible), rejected, capacity)


def _append_history(row: m.TsGlobalAgentLease, event: dict[str, Any]) -> None:
    row.history = (list(row.history or []) + [event])[-MAX_HISTORY:]


def _locked_lease() -> m.TsGlobalAgentLease:
    row, _ = m.TsGlobalAgentLease.objects.select_for_update().get_or_create(singleton_key=1)
    return row


def _grant(row: m.TsGlobalAgentLease) -> LeaseGrant:
    if row.state != "ACTIVE" or row.handoff is None or row.lease_expires_at is None:
        raise OrchestrationRefused("NO_ACTIVE_LEASE")
    return LeaseGrant(row.handoff.record_id, row.active_agent, row.fencing_token, row.lease_expires_at)


def _write_handoff_fence(handoff: m.TsAIHandoff, row: m.TsGlobalAgentLease, now: datetime, *, reason: str) -> None:
    checkpoint = dict(handoff.checkpoint or {})
    checkpoint["execution_lease"] = {
        "agent": row.active_agent,
        "fence": row.fencing_token,
        "state": row.state,
        "expires_at": c.iso(row.lease_expires_at) if row.lease_expires_at else None,
        "checkpoint_digest": row.checkpoint_digest,
        "reason": reason[:160],
        "updated_at": c.iso(now),
    }
    handoff.agent_identity = row.active_agent
    handoff.checkpoint = checkpoint
    handoff.save(update_fields=["agent_identity", "checkpoint"])


def acquire(handoff_id: str, statuses: Iterable[AgentHealth], estimate: WorkEstimate, *, lease_seconds: int = DEFAULT_LEASE_SECONDS,
            now: datetime | None = None) -> LeaseGrant:
    now = now or _now()
    decision = select_agent(statuses, estimate, now=now)
    if decision.selected is None:
        raise OrchestrationRefused("NO_ELIGIBLE_AGENT", c.canonical_json(decision.rejected))
    with transaction.atomic():
        row = _locked_lease()
        if row.state == "ACTIVE" and row.lease_expires_at and row.lease_expires_at > now:
            raise OrchestrationRefused("GLOBAL_LEASE_BUSY", f"owned by {row.active_agent}")
        handoff = m.TsAIHandoff.objects.select_for_update().filter(record_id=handoff_id).first()
        if handoff is None or handoff.status != "OPEN":
            raise OrchestrationRefused("HANDOFF_NOT_OPEN")
        row.fencing_token += 1
        row.handoff = handoff
        row.active_agent = decision.selected
        row.state = "ACTIVE"
        row.lease_expires_at = now + timedelta(seconds=max(10, min(int(lease_seconds), 600)))
        row.heartbeat_at = now
        row.progress_at = now
        row.checkpoint_digest = _checkpoint_digest(handoff.checkpoint)
        row.capacity_snapshot = decision.capacity
        _append_history(row, {"at": c.iso(now), "event": "ACQUIRED", "agent": decision.selected,
                              "handoff": handoff.record_id, "fence": row.fencing_token})
        row.save()
        _write_handoff_fence(handoff, row, now, reason="initial assignment")
        return _grant(row)


def assert_lease(handoff_id: str, agent: str, fencing_token: int, *, now: datetime | None = None) -> bool:
    now = now or _now()
    row = m.TsGlobalAgentLease.objects.filter(singleton_key=1).select_related("handoff").first()
    return bool(row and row.state == "ACTIVE" and row.handoff and row.handoff.record_id == handoff_id
                and row.active_agent == agent and row.fencing_token == fencing_token
                and row.lease_expires_at and row.lease_expires_at > now)


def heartbeat(grant: LeaseGrant, *, useful_progress: bool, checkpoint: dict | None = None,
              lease_seconds: int = DEFAULT_LEASE_SECONDS, now: datetime | None = None) -> LeaseGrant:
    now = now or _now()
    with transaction.atomic():
        row = _locked_lease()
        if not (row.state == "ACTIVE" and row.handoff and row.handoff.record_id == grant.handoff_id
                and row.active_agent == grant.agent and row.fencing_token == grant.fencing_token
                and row.lease_expires_at and row.lease_expires_at > now):
            raise StaleExecutionLease("STALE_EXECUTION_LEASE")
        row.heartbeat_at = now
        row.lease_expires_at = now + timedelta(seconds=max(10, min(int(lease_seconds), 600)))
        if useful_progress:
            row.progress_at = now
            if checkpoint is not None:
                row.handoff.checkpoint = dict(checkpoint)
                row.checkpoint_digest = _checkpoint_digest(checkpoint)
        row.save(update_fields=["heartbeat_at", "lease_expires_at", "progress_at", "checkpoint_digest", "updated_at"])
        _write_handoff_fence(row.handoff, row, now, reason="useful progress" if useful_progress else "liveness only")
        return _grant(row)


def transfer(grant: LeaseGrant, statuses: Iterable[AgentHealth], estimate: WorkEstimate, *, reason: str,
             lease_seconds: int = DEFAULT_LEASE_SECONDS, now: datetime | None = None) -> LeaseGrant | None:
    """Atomically fence the old owner and either transfer or pause safely."""

    now = now or _now()
    with transaction.atomic():
        row = _locked_lease()
        if not (row.state == "ACTIVE" and row.handoff and row.handoff.record_id == grant.handoff_id
                and row.active_agent == grant.agent and row.fencing_token == grant.fencing_token):
            raise StaleExecutionLease("STALE_EXECUTION_LEASE")
        handoff = m.TsAIHandoff.objects.select_for_update().get(pk=row.handoff_id)
        checkpoint = dict(handoff.checkpoint or {})
        inflight_until = c.parse_time(checkpoint.get("inflight_until"))
        if checkpoint.get("inflight") and inflight_until and inflight_until > now:
            raise OrchestrationRefused("INFLIGHT_OPERATION_PENDING", "wait for its bounded deadline before transfer")
        if checkpoint.get("inflight"):
            checkpoint["inflight"] = None
            checkpoint["inflight_until"] = None
            handoff.checkpoint = checkpoint
        decision = select_agent(statuses, estimate, exclude={grant.agent}, now=now)
        old = row.active_agent
        row.fencing_token += 1
        row.checkpoint_digest = _checkpoint_digest(checkpoint)
        row.capacity_snapshot = decision.capacity
        row.heartbeat_at = now
        row.progress_at = now
        if decision.selected is None:
            row.state = "PAUSED"
            row.active_agent = ""
            row.lease_expires_at = None
            _append_history(row, {"at": c.iso(now), "event": "PAUSED_ALL_UNAVAILABLE", "from": old,
                                  "handoff": handoff.record_id, "fence": row.fencing_token, "reason": reason[:160],
                                  "rejected": decision.rejected})
            row.save()
            _write_handoff_fence(handoff, row, now, reason=reason)
            return None
        row.state = "ACTIVE"
        row.active_agent = decision.selected
        row.lease_expires_at = now + timedelta(seconds=max(10, min(int(lease_seconds), 600)))
        _append_history(row, {"at": c.iso(now), "event": "TRANSFERRED", "from": old, "to": decision.selected,
                              "handoff": handoff.record_id, "fence": row.fencing_token, "reason": reason[:160]})
        row.save()
        _write_handoff_fence(handoff, row, now, reason=reason)
        return _grant(row)


def pause_unassigned(handoff_id: str, *, reason: str, rejected: dict | None = None, capacity: dict | None = None,
                     now: datetime | None = None) -> int:
    """Record that an OPEN handoff could not be assigned because no agent in the provider pool is eligible.

    Nothing held the lease, so there is no owner to fence; the singleton still moves to PAUSED with a higher fence so
    the dashboard shows why AI work is waiting and no earlier grant can be replayed.  A later ``acquire`` resumes it.
    """
    now = now or _now()
    with transaction.atomic():
        row = _locked_lease()
        if row.state == "ACTIVE" and row.lease_expires_at and row.lease_expires_at > now:
            raise OrchestrationRefused("GLOBAL_LEASE_BUSY", f"owned by {row.active_agent}")
        handoff = m.TsAIHandoff.objects.select_for_update().filter(record_id=handoff_id).first()
        if handoff is None or handoff.status != "OPEN":
            raise OrchestrationRefused("HANDOFF_NOT_OPEN")
        row.fencing_token += 1
        row.handoff = handoff
        row.state = "PAUSED"
        row.active_agent = ""
        row.lease_expires_at = None
        row.checkpoint_digest = _checkpoint_digest(handoff.checkpoint)
        if capacity is not None:
            row.capacity_snapshot = capacity
        _append_history(row, {"at": c.iso(now), "event": "PAUSED_ALL_UNAVAILABLE", "from": "", "handoff": handoff.record_id,
                              "fence": row.fencing_token, "reason": reason[:160], "rejected": dict(rejected or {})})
        row.save()
        _write_handoff_fence(handoff, row, now, reason=reason)
        return row.fencing_token


def release(grant: LeaseGrant, *, reason: str, now: datetime | None = None) -> None:
    """Return the singleton to IDLE when the owner finishes.  The fence still advances, so the finished owner's grant
    can never be replayed against a later acquisition."""

    now = now or _now()
    with transaction.atomic():
        row = _locked_lease()
        if not (row.state == "ACTIVE" and row.handoff and row.handoff.record_id == grant.handoff_id
                and row.active_agent == grant.agent and row.fencing_token == grant.fencing_token):
            raise StaleExecutionLease("STALE_EXECUTION_LEASE")
        handoff = m.TsAIHandoff.objects.select_for_update().get(pk=row.handoff_id)
        old = row.active_agent
        row.fencing_token += 1
        row.state = "IDLE"
        row.active_agent = ""
        row.lease_expires_at = None
        row.checkpoint_digest = _checkpoint_digest(handoff.checkpoint)
        _append_history(row, {"at": c.iso(now), "event": "RELEASED", "from": old, "handoff": handoff.record_id,
                              "fence": row.fencing_token, "reason": reason[:160]})
        row.save()
        checkpoint = dict(handoff.checkpoint or {})
        checkpoint["execution_lease"] = {"agent": "", "fence": row.fencing_token, "state": "IDLE", "expires_at": None,
                                         "checkpoint_digest": row.checkpoint_digest, "reason": reason[:160],
                                         "updated_at": c.iso(now)}
        handoff.checkpoint = checkpoint
        handoff.save(update_fields=["checkpoint"])


def watchdog(statuses: Iterable[AgentHealth], estimate: WorkEstimate, *, stall_seconds: int = DEFAULT_STALL_SECONDS,
             now: datetime | None = None) -> WatchdogResult:
    """Treat liveness and verified progress separately; fail over only at safe boundaries."""

    now = now or _now()
    row = m.TsGlobalAgentLease.objects.filter(singleton_key=1).select_related("handoff").first()
    if row is None or row.state in {"IDLE", "PAUSED"}:
        return WatchdogResult("NO_ACTIVE_AGENT", row.state if row else "IDLE")
    grant = _grant(row)
    by_name = {s.name: s for s in statuses}
    current = by_name.get(grant.agent)
    reason = ""
    if current is None or not current.process_alive:
        reason = "active process unavailable"
    elif not current.responsive:
        reason = "provider unresponsive"
    elif current.recent_error.upper() in {"QUOTA_EXHAUSTED", "RATE_LIMITED", "CONTEXT_EXHAUSTED"}:
        reason = current.recent_error.lower().replace("_", " ")
    elif row.lease_expires_at and row.lease_expires_at <= now:
        reason = "execution lease expired"
    elif row.progress_at and (now - row.progress_at).total_seconds() > max(30, int(stall_seconds)):
        reason = "process alive but useful progress stalled"
    if not reason:
        return WatchdogResult("HEALTHY", "active agent is live and making bounded progress", grant)
    try:
        replacement = transfer(grant, statuses, estimate, reason=reason, now=now)
    except OrchestrationRefused as exc:
        if exc.code == "INFLIGHT_OPERATION_PENDING":
            return WatchdogResult("WAIT_INFLIGHT", str(exc), grant)
        raise
    return WatchdogResult("TRANSFERRED" if replacement else "PAUSED", reason, replacement)


class FencedProviderBroker:
    """Completion-only provider guard with pre/post-call fencing checks.

    A response that returns after ownership moved is discarded before it can
    drive a tool call.  The wrapped provider still owns its credentials and
    exposes only ``complete(request)``.
    """

    def __init__(self, provider: Any, grant: LeaseGrant):
        if not callable(getattr(provider, "complete", None)):
            raise OrchestrationRefused("INVALID_PROVIDER_INTERFACE")
        self.provider = provider
        self.grant = grant

    def identity(self) -> dict[str, str]:
        identity = getattr(self.provider, "identity", None)
        value = identity() if callable(identity) else (identity or {})
        return {"provider": str(value.get("provider", type(self.provider).__name__))[:64],
                "model_id": str(value.get("model_id", self.grant.agent))[:96],
                "model_version": str(value.get("model_version", ""))[:64]}

    def _assert(self) -> None:
        if not assert_lease(self.grant.handoff_id, self.grant.agent, self.grant.fencing_token):
            raise StaleExecutionLease("STALE_EXECUTION_LEASE")

    def complete(self, request: dict) -> dict:
        self._assert()
        response = self.provider.complete(request)
        self._assert()
        return response

