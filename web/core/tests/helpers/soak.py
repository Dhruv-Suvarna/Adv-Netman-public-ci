"""Fixtures for the Phase-20 soak tests.  A CONTROLLED CLOCK and a simulated network: no real time passes, no device, NetBox, Slack or socket.

* ``short_soak``       ``override_settings`` for a 2-hour window sampled every 10 minutes (12 intervals).  Tests may shorten the policy; the production code
                       path is identical, and production configuration can only RAISE the duration (``settings._bounded_seconds``).
* ``probation``        a REAL Probation bundle: the production Phase-17 engine ran a Partial (UAT) scope on the simulated network, then the production
                       bundle service sealed UAT -> Probation.
* ``simulated``        replaces ONLY the SSH / docker read (``live.read_device``) by the world's current state; the telemetry snapshot, the Phase-15
                       collector merge, the postcheck engine, the classification, the evaluator and the collector are all the production code.
* ``tick`` / ``drive`` one collector tick at an explicit instant / a sequence of ticks, optionally degrading telemetry per instant.
* ``golden_from``      a real soak -> real decision -> real Golden (used by the Phase-19 tests that need a Golden bundle).
"""

from __future__ import annotations

from contextlib import contextmanager
from datetime import timedelta
from types import SimpleNamespace
from unittest import mock

from django.test import TestCase, override_settings

from core import models
from core.services import slack_service, soak_service as ss
from core.services.health import live
from core.tests.helpers import bundles as bh, health as h

T0 = h.NOW                     # 2026-09-21 12:00:00Z
DURATION, INTERVAL, MAX_GAP = 7200, 600, 1800
SHORT = dict(
    PROBATION_SOAK_DURATION_SECONDS=DURATION, PROBATION_SOAK_SAMPLE_INTERVAL_SECONDS=INTERVAL, PROBATION_SOAK_MAX_GAP_SECONDS=MAX_GAP,
    PROBATION_SOAK_MIN_COVERAGE_PERCENT=90, PROBATION_SOAK_DECISION_MAX_AGE_SECONDS=7200,
)
END = T0 + timedelta(seconds=DURATION)


def short_soak(**overrides):
    return override_settings(**{**SHORT, **overrides})


def at(seconds: float):
    """The instant ``seconds`` after T0."""
    return T0 + timedelta(seconds=seconds)


def probation(*, through: int = 1, raw: bool = False):
    """-> namespace(p, uat, prob, world): a real Probation bundle whose devices (R1, R2) the simulated world holds in the applied state."""
    p = bh.raw_run(assertions=[bh.ADDRESS_ASSERTION], effect=bh.LOOPBACK_PRESENT) if raw else bh.partial_run(through=through)
    uat = bh.uat_of(p)
    return SimpleNamespace(p=p, uat=uat, prob=bh.probation_of(uat), world=p.world)


class SatisfiedWorld:
    """A network in which every requirement of a bundle's executed scope holds (built only from the pinned descriptors' own expected facts)."""

    def __init__(self, bundle):
        from core.services.health import requirements

        cfg_ids = {str(i["cfg_id"]) for i in bundle.payload["items"]}
        self.requirements = [r for r in requirements.normalize_plan(bundle.plan) if r.cfg_id in cfg_ids]

    def evidence(self, name, now):
        found = h.satisfied_evidence(self.requirements, now=now).device(name)
        return found if found is not None else h.device_evidence(name, now=now)


def _world_evidence(world, name, now):
    if isinstance(world, SatisfiedWorld):
        return world.evidence(name, now)
    state = world.state.get(name) or {"interfaces": {}, "addresses": {}, "routes": []}
    return h.device_evidence(name, now=now, interfaces=state["interfaces"], addresses=state["addresses"], routes=state["routes"])


@contextmanager
def simulated(world):
    """The device read returns the world's CURRENT state, stamped with the instant of the read (as a live read is)."""
    def read(device, *, session_factory=None, now=None):
        return _world_evidence(world, device["name"], now or T0)
    with mock.patch.object(live, "read_device", side_effect=read) as patched:
        yield patched


def tick(now, world, *, snapshot_now=None, dry_run=False, soak_id="", **telemetry):
    """One collector tick at ``now``.  ``telemetry``: ``ages`` / ``cpu`` / ``memory`` / ``events`` / ``backend`` / ``links`` for that instant."""
    snapshot = h.snapshot(now=snapshot_now or now, **telemetry)
    with simulated(world):
        return ss.run_tick(now=now, snapshot=snapshot, dry_run=dry_run, soak_id=soak_id)


def drive(world, *, start, until, step=INTERVAL // 2, telemetry_at=None, stop_when_idle=True):
    """Tick from ``start`` to ``until`` (inclusive) every ``step`` seconds.  ``telemetry_at(t) -> dict`` degrades telemetry per instant.
    -> the list of TickReports."""
    reports, moment = [], start
    while moment <= until:
        if stop_when_idle and not models.ProbationSoakRun.objects.filter(state=models.SoakState.RUNNING).exists():
            break
        reports.append(tick(moment, world, **((telemetry_at(moment) if telemetry_at else None) or {})))
        moment += timedelta(seconds=step)
    return reports


def started(fixture=None, *, now=T0, actor="tester", **kwargs):
    """A Probation bundle with a RUNNING soak started at ``now``.  -> namespace(p, uat, prob, world, run)"""
    fixture = fixture or probation(**kwargs)
    result = ss.start_soak(fixture.prob, actor=actor, now=now)
    assert result.run is not None, [b["code"] for b in result.blockers]
    fixture.run = result.run
    return fixture


def passed(fixture=None, *, start=T0, **kwargs):
    """A soak driven through its whole window on a healthy network -> COMPLETED / PASS (awaiting the operator's decision)."""
    fixture = started(fixture, now=start, **kwargs)
    drive(fixture.world, start=start, until=start + timedelta(seconds=DURATION + INTERVAL))
    fixture.run.refresh_from_db()
    assert fixture.run.is_technical_pass, (fixture.run.state, fixture.run.result, fixture.run.terminal_reason, fixture.run.evaluation.get("problems"))
    return fixture


def confirm_of(run) -> dict:
    return {"soak_id": run.soak_id, "bundle_id": run.bundle.bundle_id, "bundle_digest": run.bundle_digest}


def golden_from(probation_bundle, *, world=None):
    """A REAL Golden bundle: a real soak driven on a healthy network, then the operator's explicit APPROVE.  Test factory for the Phase-19 tests."""
    fixture = SimpleNamespace(prob=probation_bundle, world=world or SatisfiedWorld(probation_bundle))
    # The Phase-19 fixtures execute several runs on the SAME devices in one database, which the production interference rule would (correctly)
    # refuse.  This factory suppresses ONLY that rule so those tests can hold a Golden bundle; every Phase-20 test uses a single-run fixture.
    with short_soak(), mock.patch("core.services.soak.interference.find_interference", return_value=[]):
        fixture = passed(fixture)
        outcome = ss.decide(fixture.run, decision="APPROVE", actor="operator", confirm=confirm_of(fixture.run), now=fixture.run.finished_at)
    assert outcome.bundle is not None, [b["code"] for b in outcome.blockers]
    return outcome.bundle


def history_run(bundle, devices, *, outcome="SUCCEEDED", state="FINISHED", after=60, mode="COMPLETE"):
    """A LATER execution in the persisted history (the interference check reads only history)."""
    source = bundle.execution_run
    when = source.started_at + timedelta(seconds=after)
    return models.ChangeExecutionRun.objects.create(
        change=bundle.change, plan=bundle.plan, validation_run=bundle.validation_run, mode=mode, state=state, outcome=outcome if state == "FINISHED" else "",
        actor="tester", engine_version="17.0.0", plan_hash=source.plan_hash, validation_input_hash=source.validation_input_hash,
        validation_source_hash=source.validation_source_hash, devices=list(devices), started_at=when, finished_at=when if state == "FINISHED" else None,
        lease_expires_at=when + timedelta(hours=1))


@short_soak()
class SoakFixture(TestCase):
    """One REAL Probation bundle, shared by every test of a subclass (each test starts its own soak inside its own rolled-back transaction).
    Slack is never reached."""

    @classmethod
    def setUpTestData(cls):
        cls.f = probation()

    def setUp(self):
        patcher = mock.patch.object(slack_service, "is_configured", return_value=False)
        patcher.start()
        self.addCleanup(patcher.stop)

    def start(self, now=T0):
        return started(self.f, now=now)

    def run_row(self):
        return models.ProbationSoakRun.objects.get(pk=self.f.run.pk)
