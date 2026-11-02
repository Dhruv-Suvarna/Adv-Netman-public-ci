"""Fixtures for the Phase-19 bundle tests.  Real runs from the PRODUCTION execution engine on a simulated network: no device, NetBox,
Slack, Docker or socket, and no hand-made history rows where a real run can be produced.

* ``partial_run`` / ``complete_run`` / ``raw_run``   finished execution runs (through the Phase-17 engine, on the Phase-17 fake world).
* ``uat_of`` / ``probation_of`` / ``golden_from``     bundles.  ``golden_from`` drives a REAL (short, simulated-clock) soak and the explicit APPROVE.
* ``oob``                                             the plain (unguarded) manager: an OUT-OF-BAND write, i.e. what a raw SQL edit or a
                                                      corrupted database would look like.  Used only to prove tampering is DETECTED.
* ``rolled_back``                                     one real run can serve a whole tamper matrix: each row is undone in a savepoint.
* ``no_device_or_network``                            makes any execute / executor / subprocess / socket / notification / credential call fail.
"""

from __future__ import annotations

import copy
from contextlib import contextmanager
from types import SimpleNamespace
from unittest import mock

from django.apps import apps
from django.db import transaction

from core import models
from core.services import bundle_service as bs, execution_service, notification_service, nsot_live
from core.services.bundles import persistence
from core.services.execution import engine
from core.services.execution.executors import registry
from core.tests.helpers import execution as ex, raw as rh

PARTIAL = models.ExecutionMode.PARTIAL_UAT
COMPLETE = models.ExecutionMode.COMPLETE
ADDRESS_ASSERTION = {"kind": "ADDRESS_PRESENT", "interface": "Loopback99", "address": "192.0.2.99/32"}
LOOPBACK_PRESENT = lambda world, spec: world.state["R1"]["addresses"].setdefault("Loopback99", []).append("192.0.2.99/32")  # noqa: E731


def partial_run(*, through: int | str = 1, fixture=None, world=None, fail: dict | None = None):
    """A REAL finished Partial (UAT) run of the standard 4-Configlet plan.  ``through`` is a plan index or a cfg id.
    -> namespace(change, prepared, run, cfgs, world, result)"""
    prepared = ex.prepared(fixture, mode=PARTIAL)
    cfgs = ex.cfg_ids(prepared)
    world = world or ex.FakeWorld()
    for cfg, failure in (fail or {}).items():
        world.fail_apply[cfg] = failure
    target = cfgs[through] if isinstance(through, int) else through
    result = ex.run(prepared, world, through=target, acks=ex.ALL_ACKS)
    return SimpleNamespace(change=prepared.change, prepared=prepared, run=result.run, cfgs=cfgs, world=world, result=result)


def complete_run():
    prepared = ex.prepared(mode=COMPLETE)
    world = ex.FakeWorld()
    result = ex.run(prepared, world)
    return SimpleNamespace(change=prepared.change, prepared=prepared, run=result.run, cfgs=ex.cfg_ids(prepared), world=world, result=result)


def raw_run(*, assertions=(), effect=None, **kwargs):
    """A REAL finished Partial (UAT) run of a plan whose LAST Configlet is a verified Raw Configlet (RAW-001).
    Without an assertion the outcome is honestly UAT_SCOPE_APPLIED_UNVERIFIED.  -> namespace(..., raw)"""
    raw = rh.verified(assertions=list(assertions), **kwargs)
    prepared = ex.prepared(raw, mode=PARTIAL)
    world = rh.RecordingWorld()
    world.raw_effect = effect
    cfgs = ex.cfg_ids(prepared)
    result = ex.run(prepared, world, through=cfgs[-1], acks=ex.ALL_ACKS)
    return SimpleNamespace(change=prepared.change, prepared=prepared, run=result.run, cfgs=cfgs, world=world, result=result, raw=raw)


def uat_of(p, *, actor="tester"):
    result = bs.create_uat_bundle(p.run, actor=actor)
    assert result.bundle is not None, [b["code"] for b in result.blockers]
    return result.bundle


def probation_of(uat, *, actor="tester"):
    result = bs.derive_probation_bundle(uat, actor=actor)
    assert result.bundle is not None, [b["code"] for b in result.blockers]
    return result.bundle


def golden_from(probation):
    """A REAL Golden bundle (Phase 20): a soak is driven through its whole window on a simulated healthy network, then the operator's explicit
    APPROVE goes through the production decision service.  There is no structural shortcut any more."""
    from core.tests.helpers import soak as sh

    return sh.golden_from(probation)


def oob(model):
    """The plain manager: an out-of-band write that bypasses every application guard (what tampering looks like)."""
    return model._base_manager


@contextmanager
def rolled_back():
    """Undo everything inside the block (a savepoint), so one real run can serve a matrix of destructive rows."""
    savepoint = transaction.savepoint()
    try:
        yield
    finally:
        transaction.savepoint_rollback(savepoint)


def table_counts() -> dict:
    """Row counts of every core table.  AuditEvent counts DOMAIN events only: website request / identity evidence
    (V2 Phase 1) is written deliberately for sensitive reads and refusals and is not domain state."""
    return {model.__name__: (model.domain if model.__name__ == "AuditEvent" else model._base_manager).count()
            for model in apps.get_app_config("core").get_models()}


def count_changes(before: dict, after: dict) -> dict:
    return {name: after[name] - before[name] for name in after if after[name] != before[name]}


@contextmanager
def no_device_or_network():
    """Any attempt to execute, reach a device / the network / a shell, notify, or resolve a credential fails the test."""
    forbidden = AssertionError("a bundle action must never execute, reach a device / network / shell, notify or resolve a credential")
    with mock.patch.object(execution_service, "execute_change", side_effect=forbidden), \
            mock.patch.object(engine, "execute_change", side_effect=forbidden), \
            mock.patch.object(registry, "executor_for", side_effect=forbidden), \
            mock.patch.object(notification_service, "publish_event", side_effect=forbidden), \
            mock.patch.object(nsot_live, "get_live_target", side_effect=forbidden), \
            mock.patch("subprocess.run", side_effect=forbidden), mock.patch("subprocess.Popen", side_effect=forbidden), \
            mock.patch("socket.socket.connect", side_effect=forbidden):
        yield
