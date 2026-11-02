"""Fixtures for the Phase-17 execution tests.  A simulated network and nothing else: no device, NetBox, Slack or socket.

* ``FakeWorld``     a mutable in-memory network.  Its executors reuse the PRODUCTION pure state model (``executors.state``) so
                    "was it there before?" / "is it restored?" are decided by the same code a real executor runs; only the
                    device I/O is simulated.  Failures are scripted per Configlet id.
* ``prepared``      a real validated, planned, prechecked Change (the whole Phase-13/14/15 chain, on fakes).
* ``run``           one ``execute_change`` call wired to a world, a capturing notifier and a no-op sleep.
"""

from __future__ import annotations

import itertools
from types import SimpleNamespace

from core import models
from core.services import change_plan_service as cps, execution_service as es, health_service as hs
from core.services.execution.executors import state
from core.services.execution.executors.base import (
    ApplyOutcome, CompensationOutcome, ConfigletSpec, DeviceExecutor, ExecutorError,
)
from core.services.health import live
from core.tests.helpers import health as h
from core.tests.helpers.validation import simple_pass_change, validate


class FakeWorld:
    """A scripted network.  ``fail_apply[cfg_id] = (code, partial_effects)``; ``fail_compensation[cfg_id] = (status, code)``."""

    def __init__(self, devices=("R1", "R2"), *, interfaces=None, addresses=None, routes=None):
        self.state = {
            name: {
                "interfaces": dict((interfaces or {}).get(name, {})),
                "addresses": {k: list(v) for k, v in (addresses or {}).get(name, {}).items()},
                "routes": list((routes or {}).get(name, [])),
            }
            for name in devices
        }
        self.calls: list[tuple] = []         # ("connect"|"assess"|"apply"|"compensate", device, cfg_id)
        self.fail_apply: dict = {}
        self.fail_compensation: dict = {}
        self.fail_connect: dict = {}
        self.fail_assess: dict = {}
        self.overwrites_primary = True
        self.closed: list[str] = []

    # -- simulated device state ---------------------------------------------------------------------------------------------
    def mutate(self, spec: ConfigletSpec) -> None:
        device = self.state[spec.device]
        expected = spec.expected
        if spec.object_type == "interface":
            device["interfaces"][expected["interface"]] = {"admin": "UP" if expected.get("admin_enabled", True) else "DOWN", "oper": "UP"}
        elif spec.object_type == "address":
            device["addresses"].setdefault(expected["interface"], []).append(live.norm_cidr(expected["address"]))
        elif spec.object_type == "static_route":
            device["routes"].append({"prefix": live.norm_prefix(expected["prefix"]), "type": "static",
                                     "next_hops": [expected["next_hop"]] if expected.get("next_hop") else [],
                                     "interfaces": [expected["exit_interface"]] if expected.get("exit_interface") else []})

    def unmutate(self, spec: ConfigletSpec) -> None:
        device = self.state[spec.device]
        expected = spec.expected
        if spec.object_type == "interface":
            device["interfaces"].pop(expected["interface"], None)
        elif spec.object_type == "address":
            cidr = live.norm_cidr(expected["address"])
            device["addresses"][expected["interface"]] = [a for a in device["addresses"].get(expected["interface"], []) if a != cidr]
        elif spec.object_type == "static_route":
            prefix = live.norm_prefix(expected["prefix"])
            device["routes"] = [r for r in device["routes"] if r["prefix"] != prefix]

    def evidence(self, name: str):
        s = self.state[name]
        return h.device_evidence(name, interfaces=s["interfaces"], addresses=s["addresses"], routes=s["routes"])

    def evidence_provider(self, plan, cfg_ids):
        """Postcheck evidence built from the CURRENT simulated state of every device the plan touches."""
        return h.evidence_set(*[self.evidence(name) for name in self.state])

    # -- factories -----------------------------------------------------------------------------------------------------------
    def factory(self, device: dict) -> "FakeExecutor":
        return FakeExecutor(self, device["name"])

    def applied(self) -> list[str]:
        return [cfg for kind, _dev, cfg in self.calls if kind == "apply"]

    def compensated(self) -> list[str]:
        return [cfg for kind, _dev, cfg in self.calls if kind == "compensate"]

    def mutating_calls(self) -> list[tuple]:
        return [c for c in self.calls if c[0] in ("apply", "compensate")]


class FakeExecutor(DeviceExecutor):
    platform = "arista_ceos"

    def __init__(self, world: FakeWorld, device: str):
        self.world, self.device = world, device

    def connect(self):
        self.world.calls.append(("connect", self.device, ""))
        if self.device in self.world.fail_connect:
            raise ExecutorError(self.world.fail_connect[self.device])

    def assess(self, spec):
        self.world.calls.append(("assess", self.device, spec.cfg_id))
        if spec.cfg_id in self.world.fail_assess:
            raise ExecutorError(self.world.fail_assess[spec.cfg_id])
        return state.assess(spec, self.world.evidence(self.device), additive_overwrites_primary=self.world.overwrites_primary)

    def apply(self, spec, assessment):
        self.world.calls.append(("apply", self.device, spec.cfg_id))
        if spec.cfg_id in self.world.fail_apply:
            code, partial = self.world.fail_apply[spec.cfg_id]
            if partial:
                self.world.mutate(spec)
            return ApplyOutcome(False, code, partial_effects=partial, lines_sent=1)
        self.world.mutate(spec)
        return ApplyOutcome(True, lines_sent=len(spec.lines) or 1)

    def compensate(self, spec, assessment):
        self.world.calls.append(("compensate", self.device, spec.cfg_id))
        if spec.cfg_id in self.world.fail_compensation:
            status, code = self.world.fail_compensation[spec.cfg_id]
            return CompensationOutcome(status, code)
        if not state.restored(spec, self.world.evidence(self.device), assessment.previous_state):
            self.world.unmutate(spec)
        verdict = state.restored(spec, self.world.evidence(self.device), assessment.previous_state)
        return CompensationOutcome("COMPENSATED" if verdict else "COMPENSATION_FAILED", "" if verdict else "STATE_NOT_RESTORED")

    def close(self):
        self.world.closed.append(self.device)


# --- prepared Changes ------------------------------------------------------------------------------------------------------
def precheck(change, sources, *, now=h.NOW, snapshot=None, fail=None):
    """An explicit, persisted Phase-15 precheck on fakes.  ``fail={"R1": TimeoutError()}`` makes a device unreachable."""
    session = h.session_factory({n: (h.linux_outputs() if n in ("R3", "R4") else h.eos_outputs()) for n in ("R1", "R2", "R3", "R4")}, fail=fail)
    return hs.run_change_precheck(change, actor="tester", sources=sources, snapshot=snapshot or h.snapshot(), session_factory=session, now=now, persist=True)


def prepared(fixture=None, *, mode=models.ExecutionMode.COMPLETE, require_permit=True):
    """A validated, planned, prechecked Change.  -> namespace(change, sources, plan, precheck, f)"""
    f = fixture or simple_pass_change()
    validate(f.change, f.sources)
    plan, _ = cps.build_change_plan(f.change, actor="tester", sources=f.sources)
    outcome = precheck(f.change, f.sources)
    if require_permit:
        assert outcome.result in ("PASS", "PASS_WITH_WARNINGS"), (outcome.result, [(r.check_code, r.device, r.status) for r in outcome.results if r.status not in ("PASS", "NOT_APPLICABLE")])
    if mode != f.change.execution_mode:
        f.change.execution_mode = mode
        f.change.save(update_fields=["execution_mode"])
    return SimpleNamespace(change=f.change, sources=f.sources, plan=plan, precheck=outcome.run, f=f)


class Notifications:
    """A capturing notifier (never reaches Slack)."""

    def __init__(self):
        self.events: list[dict] = []

    def __call__(self, **kwargs):
        self.events.append(kwargs)


ALL_ACKS = {name: True for name, _ in es.UAT_ACK_FIELDS}


def stepping_clock(step=5.0):
    """A deterministic clock that advances ``step`` seconds per read, so a settling poll reaches its deadline instantly."""
    ticks = itertools.count(0, step)
    return lambda: float(next(ticks))


def run(p, world, *, through="", acks=None, confirm=None, notifier=None, sleep=None, clock=None, **kwargs):
    """One explicit execution of prepared ``p`` against ``world``.  Time is simulated: nothing here ever really sleeps."""
    notifier = notifier if notifier is not None else Notifications()
    clock = clock or stepping_clock()
    options = dict(
        actor="tester", through_cfg_id=through, acknowledgements=acks, confirm_mode=confirm or p.change.execution_mode,
        sources=p.sources, executor_factory=world.factory, evidence_provider=world.evidence_provider, notifier=notifier,
        sleep=sleep or (lambda seconds: None),
    )
    options["clock"] = clock
    options.update(kwargs)
    return es.execute_change(p.change, **options)


def cfg_ids(p) -> list[str]:
    return [c.cfg_id for c in p.plan.configlets.order_by("sequence")]
