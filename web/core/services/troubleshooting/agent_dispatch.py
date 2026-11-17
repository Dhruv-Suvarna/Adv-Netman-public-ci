"""Bind the global agent lease to a real handoff continuation (Codex -> ClaudeA -> ClaudeB).

``agent_orchestrator`` owns selection, the singleton lease and fencing; ``ai_runtime`` owns the governed
continuation loop; ``model_provider`` owns the three completion-only socket adapters.  This module is the only place
they meet:

1. probe each fixed broker for a credential-free health object (an absent or unauthenticated broker is simply
   ineligible -- nothing is assumed about a provider that did not answer);
2. acquire the singleton lease for the best eligible agent;
3. run the continuation with that agent's adapter wrapped in ``FencedProviderBroker``, passing the fence to
   ``ai.call_tool`` so a tool request from a superseded owner is refused;
4. on a provider failure the continuation has already checkpointed and left the handoff OPEN, so atomically
   transfer the lease to the next eligible agent and continue from the checkpoint (stored tool results are replayed
   by nonce, never re-executed); and
5. pause safely, with no tool authority, when no agent is eligible.

It grants completion authority only.  It holds no provider credential and adds no device, shell or write path.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable

from . import agent_orchestrator as orch
from . import ai_runtime
from . import repository as repo
from . import runtime as rt
from .worker_ipc import IpcRefused

CAPACITY_ERRORS = frozenset({"QUOTA_EXHAUSTED", "RATE_LIMITED", "CONTEXT_EXHAUSTED"})
DEFAULT_ESTIMATE = orch.WorkEstimate(next_tokens=12_000, checkpoint_reserve_tokens=2_000, bounded=True, short_task=False)
LEASE_SECONDS = 300

ST_PAUSED = "PAUSED_NO_ELIGIBLE_AGENT"
ST_BUSY = "GLOBAL_LEASE_BUSY"
ST_SUPERSEDED = "LEASE_SUPERSEDED"


@dataclass
class DispatchResult:
    status: str
    handoff_id: str
    agent: str = ""
    fencing_token: int = 0
    reason: str = ""
    transfers: list = field(default_factory=list)
    rejected: dict = field(default_factory=dict)
    continuation: dict | None = None

    def as_dict(self) -> dict:
        return {"status": self.status, "handoff_id": self.handoff_id, "agent": self.agent, "fencing_token": self.fencing_token,
                "reason": self.reason, "transfers": self.transfers, "rejected": self.rejected, "continuation": self.continuation}


def _utc(value: Any) -> datetime | None:
    return datetime.fromtimestamp(int(value), timezone.utc) if isinstance(value, int) and value > 0 else None


def provider_pool() -> tuple[str, ...]:
    """The owner-selected production pool, in preference order.  Agents outside it are disabled by policy."""
    from django.conf import settings

    pool = getattr(settings, "NMAS_TS_AI_PROVIDER_POOL", orch.AGENTS)
    return tuple(name for name in orch.AGENTS if name in pool)


def probe(name: str, factory: Callable[[], Any]) -> tuple[orch.AgentHealth, Any]:
    """Health of one fixed agent, derived only from what its broker actually reported."""
    down = orch.AgentHealth(name=name, authenticated=False, responsive=False, restricted_interface=False, process_alive=False)
    try:
        provider = factory()
    except Exception as exc:  # noqa: BLE001 - missing key / identity: the adapter is not configured
        return orch.AgentHealth(name=name, authenticated=False, responsive=False, restricted_interface=False, process_alive=False,
                                recent_error=str(getattr(exc, "code", type(exc).__name__))[:80]), None
    health = getattr(provider, "health", None)
    if not callable(health):
        return down, None
    try:
        value = health()
    except IpcRefused as exc:
        return orch.AgentHealth(name=name, authenticated=False, responsive=False, restricted_interface=False, process_alive=False,
                                recent_error=exc.code[:80]), None
    quota = value.get("remaining_quota_pct")
    reliable = bool(value.get("quota_reliable")) and isinstance(quota, (int, float)) and not isinstance(quota, bool)
    return orch.AgentHealth(
        name=name, authenticated=bool(value.get("authenticated")), responsive=True,
        restricted_interface=value.get("restricted_interface") is True,
        remaining_quota_pct=float(quota) if reliable else None, quota_reliable=reliable,
        recent_error=str(value.get("recent_error") or "")[:80], cooldown_until=_utc(value.get("cooldown_until")),
        process_alive=True), provider


def probe_all(factories: dict[str, Callable[[], Any]]) -> tuple[list[orch.AgentHealth], dict[str, Any]]:
    statuses, providers = [], {}
    for name in orch.AGENTS:
        factory = factories.get(name)
        if factory is None:
            continue
        status, provider = probe(name, factory)
        statuses.append(status)
        if provider is not None:
            providers[name] = provider
    return statuses, providers


class _LeasedProvider:
    """Fenced adapter for one grant.  A broker failure halts the continuation with the handoff OPEN and checkpointed;
    a completed exchange is recorded as verified progress on the lease."""

    def __init__(self, provider: Any, grant: orch.LeaseGrant):
        self.inner = orch.FencedProviderBroker(provider, grant)
        self.grant = grant
        self.error = ""

    def identity(self) -> dict:
        return self.inner.identity()

    def complete(self, request: dict) -> dict:
        try:
            response = self.inner.complete(request)
        except orch.StaleExecutionLease as exc:
            self.error = "STALE_EXECUTION_LEASE"
            raise ai_runtime.ProviderUnavailable(self.error) from exc
        except IpcRefused as exc:
            self.error = exc.code
            if exc.code == "INVALID_MODEL_OUTPUT":
                raise                       # counts against the model-retry budget; not a provider outage
            raise ai_runtime.ProviderUnavailable(exc.code) from exc
        self.grant = orch.heartbeat(self.grant, useful_progress=True, lease_seconds=LEASE_SECONDS)
        return response


def _with_errors(statuses: list[orch.AgentHealth], errors: dict[str, str]) -> list[orch.AgentHealth]:
    """Carry every failure this dispatch observed into the next selection round, so an agent that already failed
    here is not selected again before a later dispatch re-probes it."""
    out = []
    for status in statuses:
        error = errors.get(status.name, "")
        if error:
            status = orch.AgentHealth(
                name=status.name, authenticated=status.authenticated and error != "AUTHENTICATION_UNAVAILABLE",
                responsive=status.responsive and error in CAPACITY_ERRORS,
                restricted_interface=status.restricted_interface, remaining_quota_pct=status.remaining_quota_pct,
                quota_reliable=status.quota_reliable, context_remaining_tokens=status.context_remaining_tokens,
                recent_error=error[:80], cooldown_until=status.cooldown_until, process_alive=status.process_alive)
        out.append(status)
    return out


def dispatch(actor: repo.Actor, handoff_id: str, *, factories: dict[str, Callable[[], Any]] | None = None,
             deps: rt.RuntimeDeps | None = None, runner: Any = None, runbook: str | None = None,
             estimate: orch.WorkEstimate = DEFAULT_ESTIMATE, clock: Callable[[], datetime] | None = None,
             max_transfers: int = len(orch.AGENTS)) -> DispatchResult:
    """Run one handoff under the global lease, failing over between the fixed agents at safe checkpoints."""
    if factories is None:
        from .model_provider import PROVIDER_FACTORIES
        pool = provider_pool()
        # Only pool members are ever probed or selected; a deferred provider is not a failover candidate.
        factories = {name: factory for name, factory in PROVIDER_FACTORIES.items() if name in pool}
    statuses, providers = probe_all(factories)
    try:
        grant = orch.acquire(handoff_id, statuses, estimate, lease_seconds=LEASE_SECONDS)
    except orch.OrchestrationRefused as exc:
        decision = orch.select_agent(statuses, estimate)
        rejected = {name: why for name, why in decision.rejected.items() if name in factories}
        status = {"NO_ELIGIBLE_AGENT": ST_PAUSED, "GLOBAL_LEASE_BUSY": ST_BUSY}.get(exc.code, exc.code)
        reason = str(exc)[:300]
        if exc.code == "NO_ELIGIBLE_AGENT":
            reason = "awaiting provider recovery: " + ", ".join(f"{name} {why.lower().replace('_', ' ')}" for name, why in rejected.items())
            try:
                orch.pause_unassigned(handoff_id, reason=reason, rejected=rejected, capacity=decision.capacity)
            except orch.OrchestrationRefused as nested:
                status, reason = nested.code, str(nested)[:300]
        return DispatchResult(status, handoff_id, reason=reason, rejected=rejected)
    transfers: list[dict] = []
    errors: dict[str, str] = {}
    result = None
    for _ in range(max(1, int(max_transfers)) + 1):
        leased = _LeasedProvider(providers[grant.agent], grant)
        agent, fence = grant.agent, grant.fencing_token
        result = ai_runtime.continue_handoff(
            actor, handoff_id, provider=leased, deps=deps, runner=runner, runbook=runbook, clock=clock, fencing_token=fence,
            lease_validator=lambda hid, token, _agent=agent: orch.assert_lease(hid, _agent, token))
        grant = leased.grant
        if result.status != ai_runtime.ST_PROVIDER_UNAVAILABLE:
            try:
                orch.release(grant, reason=f"continuation {result.status}".lower())
            except orch.StaleExecutionLease:
                return DispatchResult(ST_SUPERSEDED, handoff_id, agent=agent, fencing_token=fence, transfers=transfers,
                                      reason="the lease moved while this continuation was finishing",
                                      continuation=result.as_dict())
            return DispatchResult(result.status, handoff_id, agent=agent, fencing_token=fence, reason=result.reason,
                                  transfers=transfers, continuation=result.as_dict())
        if leased.error == "STALE_EXECUTION_LEASE":
            return DispatchResult(ST_SUPERSEDED, handoff_id, agent=agent, fencing_token=fence, transfers=transfers,
                                  reason="another owner holds the global lease", continuation=result.as_dict())
        statuses, providers = probe_all(factories)
        errors[agent] = leased.error or "PROVIDER_UNAVAILABLE"
        statuses = _with_errors(statuses, errors)
        reason = (leased.error or "provider unavailable").lower().replace("_", " ")
        try:
            replacement = orch.transfer(grant, statuses, estimate, reason=reason, lease_seconds=LEASE_SECONDS)
        except orch.StaleExecutionLease:
            return DispatchResult(ST_SUPERSEDED, handoff_id, agent=agent, fencing_token=fence, transfers=transfers,
                                  reason="another owner holds the global lease", continuation=result.as_dict())
        decision = orch.select_agent(statuses, estimate, exclude={agent})
        if replacement is None:
            transfers.append({"from": agent, "to": "", "reason": reason})
            others = "no other agent is in the provider pool" if len(factories) == 1 else "no other pool agent is eligible"
            return DispatchResult(ST_PAUSED, handoff_id, reason=f"awaiting provider recovery: {agent} {reason}; {others}",
                                  transfers=transfers, rejected={n: w for n, w in decision.rejected.items() if n in factories},
                                  continuation=result.as_dict())
        transfers.append({"from": agent, "to": replacement.agent, "reason": reason, "fence": replacement.fencing_token})
        grant = replacement
    try:        # bounded: stop with the singleton PAUSED rather than leaving an unattended ACTIVE lease
        orch.transfer(grant, [], estimate, reason="transfer budget exhausted")
    except orch.OrchestrationRefused:
        pass
    return DispatchResult(ST_PAUSED, handoff_id, reason="transfer budget exhausted", transfers=transfers,
                          continuation=result.as_dict() if result else None)
