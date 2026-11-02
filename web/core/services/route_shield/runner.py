"""Run one shielded transition: precheck, shield, verify, protected change, verify, unshield, verify -- or restore exactly.

Order of every run:

    validation        the Transition validated itself when it was built
    precheck          gates.precheck on a fresh read; baseline digest; host gate; production probes healthy
    shield install    one Configlet; read back; the shield routes must be installed toward the expected interface
    protected change  each step assessed, applied and read back; production probes are polled after every step
    transition check  the new owner holds every protected prefix; the take-over next hop is resolved
    shield removal    one Configlet; read back
    final check       the new owner still holds the prefixes and no shield route remains

Any refused Configlet, failed check, out-of-band change or lost production probe ABORTS: everything this run applied is
compensated in reverse order (the change first, the shield last, so the restore itself is shielded), the original owner is
verified, and the evidence is kept.  ``executors``, ``read`` and the probes are supplied by the caller: this module
selects no device and opens no connection.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field

from django.utils import timezone

from ..execution.executors.base import APPLY, REFUSE, SKIP_SATISFIED
from ..health.codes import Phase
from ..health.evaluators import evaluate_requirements
from ..health.evidence import EvidenceSet
from ..health.thresholds import load_thresholds
from . import gates, model, readiness

OK_STATUSES = frozenset({"PASS", "NOT_APPLICABLE"})


@dataclass
class Environment:
    """Everything a run needs from outside.  A missing probe or gate is a refusal, never a default pass."""

    executors: dict
    read: object                                  # read(device) -> health DeviceEvidence (fresh)
    probes: object = None                         # .healthy() -> (bool, detail);  .lost() -> cumulative lost production probes
    host_gate: object = None                      # () -> (bool, facts)
    next_hop_alive: object = None                 # (device, address) -> bool
    new_route_available: object = None            # (transition) -> bool
    resolve_takeover: object = None               # (device, transition) -> bool: the new route's next hop is a resolved neighbour
    peer_forwards_onward: object = None           # (transition) -> bool: ``via_peer`` sends the protected prefixes on, not back to us
    upstream_covered: object = None               # (transition) -> bool: EVERY upstream router holds a cover of every protected prefix
    baseline_digests: dict = field(default_factory=dict)   # device -> the running-config digest the plan was built from
    sleep: object = time.sleep
    clock: object = time.monotonic
    poll_seconds: float = 2.0


@dataclass
class Result:
    transition: str
    device: str
    ok: bool = False
    aborted: str = ""                              # the blocker code that stopped the run ('' when it completed)
    blockers: list = field(default_factory=list)
    stages: list = field(default_factory=list)     # ordered evidence: {"stage", "at", "status", ...}
    applied: list = field(default_factory=list)    # [(spec, assessment)] in apply order
    compensation: list = field(default_factory=list)
    restored: bool | None = None                   # None: nothing was applied
    probes_lost: int = 0

    def record(self, stage: str, status: str, **facts) -> None:
        self.stages.append({"stage": stage, "at": timezone.now().isoformat(), "status": status, **facts})


def evaluate(requirements, read, device: str) -> list[dict]:
    """One fresh read, then the health engine's own postcheck evaluation."""
    evidence = EvidenceSet(devices={device: read(device)}, now=timezone.now(), thresholds=load_thresholds())
    evaluation = evaluate_requirements(list(requirements), Phase.POSTCHECK, evidence)
    return [{"check": row.check_code, "status": row.status, "subject": row.subject, "message": row.message} for row in evaluation.results]


def _failed(checks) -> list:
    return [row for row in checks if row["status"] not in OK_STATUSES]


def _settle(requirements, env: Environment, device: str, seconds: float) -> list[dict]:
    deadline = env.clock() + seconds
    while True:
        checks = evaluate(requirements, env.read, device)
        if not _failed(checks) or env.clock() >= deadline:
            return checks
        env.sleep(env.poll_seconds)


def execute(transition: model.Transition, env: Environment) -> Result:
    """The service entry point.  Refuses, before anything is read, a transition whose kind is not ``READY``
    (``readiness.READINESS``); no argument lifts the refusal.  Otherwise as ``_execute``."""
    refused = readiness.refusal(transition.kind)
    if refused:
        result = Result(transition.key, transition.device, aborted=refused.split(":")[0])
        result.blockers.append({"code": refused.split(":")[0], "device": transition.device, "detail": refused})
        result.record("readiness", "REFUSED", detail=refused)
        return result
    return _execute(transition, env)


def _execute(transition: model.Transition, env: Environment) -> Result:
    """Ungated: for the disposable sandbox and the mechanics tests only."""
    result = Result(transition.key, transition.device)
    executor = env.executors[transition.device]
    lost_at_start = 0
    expected = {"digest": env.baseline_digests.get(transition.device)}

    def abort(code: str, detail: str = "", checks=None) -> Result:
        result.aborted = code
        result.blockers.append({"code": code, "device": transition.device, "detail": detail})
        result.record("abort", code, detail=detail, failed=_failed(checks or []))
        if result.applied:
            _restore(transition, env, result)
        return result

    def lost() -> int:
        return int(env.probes.lost()) - lost_at_start

    def digest() -> str:
        return executor.config_state_digest()

    def apply(stage: str, spec) -> str:
        """'' when the Configlet is in (applied or already satisfied) and read back, else the reason."""
        if digest() != expected["digest"]:
            return gates.OUT_OF_BAND                        # the device changed between two of our own steps
        assessment = executor.assess(spec)
        if assessment.action == REFUSE or (assessment.action == APPLY and not assessment.restorable):
            return f"REFUSED:{assessment.reason or assessment.action}"
        if assessment.action == APPLY:
            outcome = executor.apply(spec, assessment)
            result.applied.append((spec, assessment))
            if not outcome.ok:
                return f"APPLY_FAILED:{outcome.error_code}"
        readback = executor.assess(spec)                    # read-back: the device must now report the Configlet as satisfied
        expected["digest"] = digest()
        result.record(stage, "APPLIED" if assessment.action == APPLY else "ALREADY_SATISFIED", cfg_id=spec.cfg_id,
                      read_back=readback.action, probes_lost=lost())
        return "" if readback.action == SKIP_SATISFIED else "READ_BACK_MISMATCH"

    # -- precheck -------------------------------------------------------------------------------------------------------
    if env.probes is None or env.host_gate is None:
        return abort(gates.PROBES_UNHEALTHY if env.probes is None else gates.HOST_GATE, "no probe source / host gate was supplied")
    ok, facts = env.host_gate()
    if not ok:
        return abort(gates.HOST_GATE, str(facts))
    ok, detail = env.probes.healthy()
    if not ok:
        return abort(gates.PROBES_UNHEALTHY, str(detail))
    lost_at_start = int(env.probes.lost())
    baseline = env.baseline_digests.get(transition.device)
    if not baseline or digest() != baseline:
        return abort(gates.BASELINE_STALE, "the running configuration is not the one this transition was planned from")
    blockers = gates.precheck(transition, env.read(transition.device), next_hop_alive=env.next_hop_alive, new_route_available=env.new_route_available)
    if transition.upstream and (env.upstream_covered is None or not env.upstream_covered(transition)):   # never assumed
        blockers.append({"code": gates.UPSTREAM_COVER_UNCONFIRMED, "device": transition.device,
                         "detail": f"not every one of {', '.join(transition.upstream)} holds a cover of the protected prefixes"})
    if transition.via_peer and (env.peer_forwards_onward is None or not env.peer_forwards_onward(transition)):
        blockers.append({"code": gates.NEW_PATH_UNAVAILABLE, "device": transition.device,
                         "detail": f"{transition.via_peer} is not proven to forward the traffic onward: handing it over could loop"})
    if blockers:
        result.blockers.extend(blockers)
        result.aborted = blockers[0]["code"]
        result.record("precheck", "BLOCKED", blockers=[b["code"] for b in blockers])
        return result
    result.record("precheck", "PASS", host=facts, checks=evaluate(transition.old_requirements(), env.read, transition.device))
    if _failed(result.stages[-1]["checks"]):
        return abort(gates.OLD_ROUTE_ABSENT, "the original owner check failed", result.stages[-1]["checks"])

    # -- shield ---------------------------------------------------------------------------------------------------------
    reason = apply("shield-install", transition.install_spec())
    if reason:
        return abort(gates.SHIELD_UNCONFIRMED, reason)
    checks = _settle(transition.shield_requirements(), env, transition.device, 20.0)
    result.record("shield-verify", "FAIL" if _failed(checks) else "PASS", checks=checks, probes_lost=lost())
    if _failed(checks):
        return abort(gates.SHIELD_UNCONFIRMED, "the shield routes are not installed as planned", checks)
    if lost():
        return abort(gates.PACKET_LOSS, "production probes were lost while the shield was installed")

    # -- protected change -----------------------------------------------------------------------------------------------
    for step, spec in zip(transition.steps, transition.step_specs()):
        reason = apply("transition", spec)
        if reason:
            return abort(gates.OUT_OF_BAND if reason == gates.OUT_OF_BAND else "TRANSITION_FAILED", reason)
        if step.wait_new_owner:                             # the next step is only safe once the new owner forwards
            checks = _settle(transition.new_requirements(), env, transition.device, transition.settle_seconds)
            if _failed(checks):
                return abort("TRANSITION_NOT_VERIFIED", f"the new owner did not take over after {spec.cfg_id}", checks)
        if lost():
            return abort(gates.PACKET_LOSS, f"production probes were lost at {spec.cfg_id}")
    checks = _settle(transition.new_requirements(), env, transition.device, transition.settle_seconds)
    result.record("transition-verify", "FAIL" if _failed(checks) else "PASS", checks=checks, probes_lost=lost())
    if _failed(checks):
        return abort("TRANSITION_NOT_VERIFIED", "the new owner does not hold the protected prefixes", checks)
    if env.resolve_takeover is None or not env.resolve_takeover(transition.device, transition):
        return abort(gates.NEW_PATH_UNAVAILABLE, "the take-over next hop is not a resolved neighbour")
    if lost():
        return abort(gates.PACKET_LOSS, "production probes were lost during the protected change")

    # -- shield removal and final state ---------------------------------------------------------------------------------
    reason = apply("shield-remove", transition.remove_spec())
    if reason:
        return abort("SHIELD_REMOVAL_FAILED", reason)
    checks = _settle(transition.new_requirements(), env, transition.device, 20.0)
    routes = env.read(transition.device).facts("routes")
    remaining = routes is None or any(gates._routes(routes, cover) for cover in transition.shield_prefixes)
    result.record("final-verify", "FAIL" if _failed(checks) or remaining else "PASS", checks=checks, shield_remaining=bool(remaining), probes_lost=lost())
    if _failed(checks) or remaining:
        return abort("FINAL_STATE_NOT_VERIFIED", "the final forwarding state is not the planned one", checks)
    if lost():
        return abort(gates.PACKET_LOSS, "production probes were lost while the shield was removed")
    result.ok = True
    return result


def _restore(transition: model.Transition, env: Environment, result: Result) -> None:
    """Compensate in reverse order, then prove the original owner and the original configuration are back."""
    executor = env.executors[transition.device]
    for spec, assessment in reversed(result.applied):
        outcome = executor.compensate(spec, assessment)
        result.compensation.append({"cfg_id": spec.cfg_id, "status": outcome.status, "error": outcome.error_code})
    checks = _settle(transition.old_requirements(), env, transition.device, transition.settle_seconds)
    digest_ok = executor.config_state_digest() == env.baseline_digests.get(transition.device)
    result.restored = all(row["status"] == "COMPENSATED" for row in result.compensation) and not _failed(checks) and digest_ok
    result.probes_lost = int(env.probes.lost()) if env.probes is not None else 0
    result.record("restore", "RESTORED" if result.restored else "RESTORE_FAILED", compensation=list(result.compensation), checks=checks,
                  configuration_restored=digest_ok)
