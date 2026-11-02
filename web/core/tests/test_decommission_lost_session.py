"""A lost device session during a governed decommission never strands an operation and never reports a false restore.

Found live (Phases 7-9, evidence 40): the session failed right after the device accepted ``shutdown`` on Ethernet2.  The
transaction did not record that step, compensated only the earlier ones -- each checked against a digest that no longer held
-- and ended FAILED_COMPENSATION_INCOMPLETE / UNCERTAIN with Ethernet2 down and the stub-router cost-out still configured.

Now the step whose call did not return is recorded as possibly applied, and compensation runs on ONE fresh session from the
run's own executor factory (same transport, same identity).  Every step is still digest- or presence-verified.

The sessions below share one in-memory EOS configuration (``helpers.isolation``) behind the REAL CeosExecutor; a session can
die after the device applied a set (lost response) or before (the set never arrived).  A dead session refuses every call.
"""

from __future__ import annotations

import dataclasses
from datetime import timedelta

from django.test import TestCase
from django.utils import timezone

from core import models
from core.services.decommission import service as svc
from core.services.execution.executors.base import ExecutorError
from core.services.isolation import transaction as governed
from core.services.execution.executors.ceos import CeosExecutor
from core.tests.helpers import decommission as H
from core.tests.helpers import isolation as I
from core.tests.helpers import lifecycle as L

D, S = models.DecommissionState, models.DeviceLifecycleState


class Link:
    """One SSH session onto the shared device.  ``plan`` decides, per configuration set, whether this session dies on it."""

    def __init__(self, device, plan, number):
        self.device, self.plan, self.number, self.alive = device, plan, number, True

    def _alive(self):
        if not self.alive:
            raise OSError("Socket is closed")

    def send_command(self, command, **kwargs):
        self._alive()
        return self.device.send_command(command, **kwargs)

    def config_mode(self, **_):
        self._alive()

    def check_config_mode(self):
        self._alive()
        return False

    def exit_config_mode(self):
        self._alive()

    def check_enable_mode(self):
        return True

    def send_config_set(self, commands, **kwargs):
        self._alive()
        verdict = self.plan.verdict(self.number, list(commands))
        if verdict == "drop-before":                   # the set never reached the device
            self.alive = False
            raise ConnectionResetError("connection reset by peer")
        output = self.device.send_config_set(commands, **kwargs)
        if verdict == "drop-after":                    # the device applied it; the response was lost with the session
            self.alive = False
            raise ConnectionResetError("connection reset by peer")
        return output

    def disconnect(self):
        self.alive = False


class Plan:
    """``rules``: [(session number, substring of a set, verdict)] -- each fires once."""

    def __init__(self, *rules, refuse_after=None):
        self.rules, self.sessions, self.refuse_after = list(rules), 0, refuse_after

    def verdict(self, number, commands):
        text = "\n".join(c.strip() for c in commands)
        for rule in self.rules:
            session, needle, verdict = rule
            if session == number and needle in text:
                self.rules.remove(rule)
                return verdict
        return "ok"

    def factory(self, device_session):
        def connect(_device):
            self.sessions += 1
            if self.refuse_after is not None and self.sessions > self.refuse_after:
                raise ExecutorError("CONNECTION_FAILED")
            return Link(device_session, self, self.sessions)

        return lambda device: CeosExecutor(device, connection_factory=connect, reader=I._facts)  # pylint: disable=protected-access


class Base(TestCase):
    def setUp(self):
        self.device = L.adopt("R1", role="router").device
        self.fake = H.session()

    def run_with(self, plan):
        """Evaluate and approve on a healthy runtime, then execute with ``plan``'s sessions.  -> (record, result, baseline)"""
        observer = H.FakeObserver(H.observation(), H.observation(), H.observation(on_device=False))
        healthy = H.runtime(self.fake, observer, probe=H.FakeProbe())
        record = svc.request(self.device, actor=L.OPERATOR, reason="retire R1").record
        self.assertTrue(svc.evaluate(record, actor=L.OPERATOR, runtime=healthy).ok)
        record.refresh_from_db()
        self.assertTrue(svc.approve(record, actor=L.APPROVER, confirmation=record.plan_hash).ok)
        record.refresh_from_db()
        runtime = H.runtime(self.fake, observer, probe=H.FakeProbe(), factory=plan.factory(self.fake))
        result = svc.execute(record, actor=L.APPROVER, confirmation=record.plan_hash, runtime=runtime)
        record.refresh_from_db()
        return record, result, record.baseline.state_digest

    def digest(self):
        executor = H.executor_factory(self.fake)({"name": "R1", "platform": "ceos"})
        executor.connect()
        return executor.config_state_digest()

    def report(self, result):
        return result.detail["report"]


class LostSessionTests(Base):

    # positive ---------------------------------------------------------------------------------------------------------------
    def test_session_lost_after_the_device_accepted_a_step_is_rolled_back_exactly_on_a_fresh_session(self):
        record, result, baseline = self.run_with(Plan((1, "interface Ethernet2\nshutdown", "drop-after")))
        report = self.report(result)
        self.assertEqual(record.state, D.ROLLED_BACK, report.get("failure"))
        self.assertEqual(self.digest(), baseline)
        self.assertNotIn("max-metric", self.fake.config.text())
        self.assertEqual(report["session"]["reconnects"], 1)
        steps = report["compensation"]["steps"]
        self.assertEqual(steps[0]["operation"], "shutdown-Ethernet2")             # the unacknowledged step, compensated first
        self.assertTrue(all(step["status"] == "COMPENSATED" and step.get("session") == "fresh" for step in steps), steps)
        self.device.refresh_from_db()
        self.assertEqual(self.device.lifecycle_state, S.IN_SERVICE)

    def test_session_lost_before_the_step_arrived_needs_no_inverse_for_it(self):
        record, result, baseline = self.run_with(Plan((1, "interface Ethernet2\nshutdown", "drop-before")))
        self.assertEqual(record.state, D.ROLLED_BACK, self.report(result).get("failure"))
        self.assertEqual(self.digest(), baseline)
        compensated = {s["operation"]: s for s in self.report(result)["compensation"]["steps"]}
        self.assertEqual(compensated["shutdown-Ethernet2"]["status"], "COMPENSATED")
        unknown = models.ConfigletExecutionResult.objects.get(run__run_id=result.detail["report"]["run"] if "run" in result.detail["report"]
                                                              else record.outcome["run"], cfg_id=compensated["shutdown-Ethernet2"]["cfg_id"],
                                                              phase=models.ExecutionResultPhase.APPLY)
        self.assertEqual((unknown.status, unknown.error_code, unknown.partial_effects), ("FAILED", "TRANSPORT_ERROR", True))

    def test_session_lost_while_compensating_is_retried_once_on_another_fresh_session(self):
        plan = Plan((1, "interface Ethernet2\nshutdown", "drop-after"), (2, "interface Ethernet1\nno shutdown", "drop-after"))
        record, result, baseline = self.run_with(plan)
        self.assertEqual(record.state, D.ROLLED_BACK, self.report(result).get("failure"))
        self.assertEqual(self.digest(), baseline)
        self.assertEqual(self.report(result)["session"]["reconnects"], 2)

    def test_engine_exception_after_the_device_call_began_records_the_step_as_possibly_applied(self):
        from core.tests.helpers import decommission

        class Raising(CeosExecutor):
            def apply(self, spec, assessment):
                outcome = super().apply(spec, assessment)
                if "interface Ethernet2" in spec.lines and "   shutdown" in spec.lines:
                    raise RuntimeError("engine fault after the device accepted the step")
                return outcome

        observer = H.FakeObserver(H.observation(), H.observation(), H.observation(on_device=False))
        record = svc.request(self.device, actor=L.OPERATOR, reason="retire R1").record
        svc.evaluate(record, actor=L.OPERATOR, runtime=H.runtime(self.fake, observer, probe=H.FakeProbe()))
        record.refresh_from_db()
        svc.approve(record, actor=L.APPROVER, confirmation=record.plan_hash)
        record.refresh_from_db()
        factory = lambda device: Raising(device, connection_factory=lambda _d: self.fake, reader=I._facts)  # noqa: E731  pylint: disable=protected-access
        result = svc.execute(record, actor=L.APPROVER, confirmation=record.plan_hash,
                             runtime=decommission.runtime(self.fake, observer, probe=H.FakeProbe(), factory=factory))
        record.refresh_from_db()
        self.assertEqual(record.state, D.ROLLED_BACK, result.detail["report"].get("failure"))
        self.assertEqual(result.detail["report"]["failure"]["code"], "INTERNAL_ERROR")
        self.assertEqual(result.detail["report"]["session"]["reconnects"], 0)        # the session itself was fine
        self.assertEqual(self.digest(), record.baseline.state_digest)

    # negative ---------------------------------------------------------------------------------------------------------------
    def test_no_fresh_session_leaves_the_record_uncertain_never_restored(self):
        record, result, baseline = self.run_with(Plan((1, "interface Ethernet2\nshutdown", "drop-after"), refuse_after=1))
        report = self.report(result)
        self.assertEqual(record.state, D.UNCERTAIN)
        self.assertFalse(report["restored"])
        self.assertNotEqual(self.digest(), baseline)
        self.assertIn("FAILED", [s["status"] for s in report["steps"] if s["step"] == "reconnect"])
        self.device.refresh_from_db()
        self.assertEqual(self.device.lifecycle_state, S.DECOMMISSION_PENDING)

    def test_reconnects_are_bounded_and_an_exhausted_budget_is_uncertain(self):
        plan = Plan((1, "interface Ethernet2\nshutdown", "drop-after"), (2, "no shutdown", "drop-after"), (3, "no shutdown", "drop-after"))
        record, result, baseline = self.run_with(plan)
        report = self.report(result)
        self.assertEqual(record.state, D.UNCERTAIN)
        self.assertFalse(report["restored"])
        self.assertEqual(report["session"]["reconnects"], 2)
        self.assertIn("REFUSED", [s["status"] for s in report["steps"] if s["step"] == "reconnect"])
        self.assertNotEqual(self.digest(), baseline)

    def test_uncertain_record_is_reconciled_only_from_the_device_state(self):
        record, _result, baseline = self.run_with(Plan((1, "interface Ethernet2\nshutdown", "drop-after"), refuse_after=1))
        healthy = H.runtime(self.fake, H.FakeObserver(H.observation()))
        self.assertFalse(svc.reconcile(record, actor=L.APPROVER, runtime=healthy).ok)    # the device is not on the baseline
        record.refresh_from_db()
        self.assertEqual(record.state, D.UNCERTAIN)
        self.fake.config = I.EosText(record.baseline.text)                               # an operator restores it by hand
        self.fake.config.MODES = I.EosText.MODES + ("ipv6 router ",)
        self.assertEqual(self.digest(), baseline)
        self.assertTrue(svc.reconcile(record, actor=L.APPROVER, runtime=healthy).ok)
        record.refresh_from_db()
        self.assertEqual(record.state, D.ROLLED_BACK)


class Crash(BaseException):
    """The NMAS process dies (not an Exception: nothing in the engine catches it, the run stays RUNNING with its lock)."""


class RecoveryTests(Base):
    """A record left part-way is brought back by a second governed Change built from the run's own inverses."""

    def uncertain(self):
        record, _result, baseline = self.run_with(Plan((1, "interface Ethernet2\nshutdown", "drop-after"), refuse_after=1))
        self.assertEqual(record.state, D.UNCERTAIN)
        return record, baseline

    def healthy(self):
        return H.runtime(self.fake, H.FakeObserver(H.observation()))

    def recover(self, record, *, planner=L.OPERATOR, approver=L.APPROVER):
        planned = svc.plan_recovery(record, actor=planner, runtime=self.healthy())
        self.assertTrue(planned.ok, planned.codes)
        record.refresh_from_db()
        plan_hash = record.outcome["recovery"]["plan_hash"]
        self.assertTrue(svc.approve_recovery(record, actor=approver, confirmation=plan_hash).ok)
        record.refresh_from_db()
        return svc.execute_recovery(record, actor=approver, confirmation=plan_hash, runtime=self.healthy()), plan_hash

    # positive ---------------------------------------------------------------------------------------------------------------
    def test_uncertain_record_is_recovered_by_a_governed_inverse_of_its_own_operations(self):
        record, baseline = self.uncertain()
        planned = svc.plan_recovery(record, actor=L.OPERATOR, runtime=self.healthy())
        self.assertTrue(planned.ok, planned.codes)
        keys = [o["key"] for o in planned.detail["recovery"]["operations"]]
        self.assertEqual(keys, ["undo-shutdown-Ethernet2", "undo-shutdown-Ethernet1", "undo-cost-out-ipv6", "undo-cost-out-ipv4"])
        record.refresh_from_db()
        plan_hash = record.outcome["recovery"]["plan_hash"]
        self.assertEqual(svc.approve_recovery(record, actor=L.OPERATOR, confirmation=plan_hash).codes, ["DECOMMISSION_SELF_APPROVAL"])
        self.assertTrue(svc.approve_recovery(record, actor=L.APPROVER, confirmation=plan_hash).ok)
        record.refresh_from_db()
        result = svc.execute_recovery(record, actor=L.APPROVER, confirmation=plan_hash, runtime=self.healthy())
        record.refresh_from_db()
        self.assertTrue(result.ok, (result.codes, result.detail["report"].get("failure")))
        self.assertEqual((record.state, record.outcome["recovery"]["state"]), (D.ROLLED_BACK, "SUCCEEDED"))
        self.assertEqual(self.digest(), baseline)
        self.device.refresh_from_db()
        self.assertEqual(self.device.lifecycle_state, S.IN_SERVICE)
        self.assertEqual(governed.unresolved_runs("R1"), [])                     # the interrupted run no longer blocks the device
        run = record.change.execution_runs.get()
        self.assertEqual(run.outcome, "FAILED_COMPENSATION_INCOMPLETE")               # history is never rewritten
        self.assertTrue(governed.reconciled(run))

    def test_crashed_run_is_recovered_once_its_lease_expired(self):
        class Dying(CeosExecutor):
            def apply(self, spec, assessment):
                outcome = super().apply(spec, assessment)
                if "interface Ethernet1" in spec.lines and "   shutdown" in spec.lines:
                    raise Crash()
                return outcome

        observer = H.FakeObserver(H.observation(), H.observation(), H.observation(on_device=False))
        record = svc.request(self.device, actor=L.OPERATOR, reason="retire R1").record
        svc.evaluate(record, actor=L.OPERATOR, runtime=H.runtime(self.fake, observer, probe=H.FakeProbe()))
        record.refresh_from_db()
        svc.approve(record, actor=L.APPROVER, confirmation=record.plan_hash)
        record.refresh_from_db()
        factory = lambda device: Dying(device, connection_factory=lambda _d: self.fake, reader=I._facts)  # noqa: E731  pylint: disable=protected-access
        with self.assertRaises(Crash):
            svc.execute(record, actor=L.APPROVER, confirmation=record.plan_hash,
                        runtime=H.runtime(self.fake, observer, probe=H.FakeProbe(), factory=factory))
        record.refresh_from_db()
        self.assertEqual(record.state, D.DECOMMISSIONING)
        refused = svc.plan_recovery(record, actor=L.OPERATOR, runtime=self.healthy())       # the lease is still alive
        self.assertEqual(refused.codes, ["DECOMMISSION_STATE_INVALID"])
        models.ChangeExecutionRun.objects.filter(change=record.change).update(lease_expires_at=timezone.now() - timedelta(seconds=1))
        result, _ = self.recover(record)
        record.refresh_from_db()
        self.assertTrue(result.ok, result.codes)
        self.assertEqual(record.state, D.ROLLED_BACK)
        self.assertEqual(self.digest(), record.baseline.state_digest)
        self.assertEqual(record.change.execution_runs.get().outcome, "INTERRUPTED")
        self.assertEqual(governed.unresolved_runs("R1"), [])

    def test_reconciled_device_can_be_decommissioned_again(self):
        record, baseline = self.uncertain()
        self.fake.config = I.EosText(record.baseline.text)
        self.fake.config.MODES = I.EosText.MODES + ("ipv6 router ",)
        self.assertTrue(svc.reconcile(record, actor=L.APPROVER, runtime=self.healthy()).ok)
        self.assertEqual(governed.unresolved_runs("R1"), [])
        again = svc.request(models.ManagedDevice.objects.get(pk=self.device.pk), actor=L.OPERATOR, reason="retire R1 again")
        self.assertTrue(again.ok, again.codes)
        observer = H.FakeObserver(H.observation(), H.observation(), H.observation(on_device=False))
        evaluated = svc.evaluate(again.record, actor=L.OPERATOR, runtime=H.runtime(self.fake, observer, probe=H.FakeProbe()))
        self.assertTrue(evaluated.ok, evaluated.codes)
        self.assertEqual(self.digest(), baseline)

    # negative ---------------------------------------------------------------------------------------------------------------
    def test_recovery_refused_on_baseline_running_unapproved_or_mismatched(self):
        record, _ = self.uncertain()
        self.assertEqual(svc.execute_recovery(record, actor=L.APPROVER, confirmation="x", runtime=self.healthy()).codes,
                         ["DECOMMISSION_STATE_INVALID", "DECOMMISSION_CONFIRMATION_MISMATCH"])
        self.assertEqual(svc.plan_recovery(record, actor=L.OPERATOR, runtime=None).codes, ["DECOMMISSION_RUNTIME_UNAVAILABLE"])
        svc.plan_recovery(record, actor=L.OPERATOR, runtime=self.healthy())
        record.refresh_from_db()
        self.assertEqual(svc.approve_recovery(record, actor=L.APPROVER, confirmation="wrong").codes, ["DECOMMISSION_CONFIRMATION_MISMATCH"])
        self.fake.config = I.EosText(record.baseline.text)                       # someone restored it meanwhile
        self.fake.config.MODES = I.EosText.MODES + ("ipv6 router ",)
        self.assertEqual(svc.plan_recovery(record, actor=L.OPERATOR, runtime=self.healthy()).codes, ["DECOMMISSION_STATE_INVALID"])
        self.assertEqual(svc.plan_recovery(None, actor=L.OPERATOR, runtime=self.healthy()).codes, ["DECOMMISSION_NOT_FOUND"])

    def test_device_changed_after_planning_blocks_the_recovery_without_writes(self):
        record, _ = self.uncertain()
        svc.plan_recovery(record, actor=L.OPERATOR, runtime=self.healthy())
        record.refresh_from_db()
        plan_hash = record.outcome["recovery"]["plan_hash"]
        svc.approve_recovery(record, actor=L.APPROVER, confirmation=plan_hash)
        record.refresh_from_db()
        self.fake.config.apply(["interface Ethernet1", "description changed out of band", "exit"])
        sets = len(self.fake.sent)
        result = svc.execute_recovery(record, actor=L.APPROVER, confirmation=plan_hash, runtime=self.healthy())
        record.refresh_from_db()
        self.assertFalse(result.ok)
        self.assertEqual((record.state, record.outcome["recovery"]["state"]), (D.UNCERTAIN, "FAILED"))
        self.assertEqual(len(self.fake.sent), sets)
        self.assertTrue(governed.unresolved_runs("R1"))

    def test_partly_present_effect_is_a_conflict(self):
        from core.services.decommission import eos

        ops = [eos.op("cost-out", "ADD", ["router ospf 1", "   max-metric router-lsa"], ["router ospf 1", "   no max-metric router-lsa"],
                      ["router ospf 1 > max-metric router-lsa", "router ospf 1 > max-lsa 12000"], "cost-out")]
        with self.assertRaises(eos.PlanError) as caught:
            eos.render_recovery(ops, {"router ospf 1 > max-metric router-lsa"})
        self.assertEqual(caught.exception.code, "RECOVERY_CONFLICT")
        self.assertEqual(eos.render_recovery(ops, set())["operations"], [])


class RecoveryOrderTests(Base):
    """Found live (evidence 43): removing the cost-out two seconds after ``no shutdown`` lost IPv6 packets -- the re-enabled links
    had no FULL OSPFv3 adjacency yet.  The recovery now waits for the baseline's adjacencies before the first cost-out undo."""

    def uncertain(self):
        record, _result, _baseline = self.run_with(Plan((1, "interface Ethernet2\nshutdown", "drop-after"), refuse_after=1))
        return record

    def execute(self, record, observer):
        healthy = H.runtime(self.fake, H.FakeObserver(H.observation()))
        self.assertTrue(svc.plan_recovery(record, actor=L.OPERATOR, runtime=healthy).ok)
        record.refresh_from_db()
        plan_hash = record.outcome["recovery"]["plan_hash"]
        self.assertTrue(svc.approve_recovery(record, actor=L.APPROVER, confirmation=plan_hash).ok)
        record.refresh_from_db()
        runtime = dataclasses.replace(H.runtime(self.fake, observer), adjacency_timeout_seconds=60.0)   # sleep is a no-op
        return svc.execute_recovery(record, actor=L.APPROVER, confirmation=plan_hash, runtime=runtime)

    def seen(self):
        """What the observer sees: is the cost-out still configured, are both links back up?"""
        text = self.fake.config.text()
        return {"cost_out": "max-metric router-lsa" in text,
                "links_up": "interface Ethernet1\n   shutdown" not in text and "interface Ethernet2\n   shutdown" not in text}

    def test_recovery_waits_for_full_adjacencies_after_links_up_and_before_removing_the_cost_out(self):
        record = self.uncertain()
        states = []

        def observe(full):
            def value(_device):
                states.append({**self.seen(), "full": bool(full)})
                return H.observation(full=full)
            return value

        result = self.execute(record, H.FakeObserver(observe(()), observe(()), observe(("E1", "E2"))))
        self.assertTrue(result.ok, result.codes)
        self.assertEqual(states, [{"cost_out": True, "links_up": True, "full": False}, {"cost_out": True, "links_up": True, "full": False},
                                  {"cost_out": True, "links_up": True, "full": True}])
        record.refresh_from_db()
        self.assertEqual(record.outcome["recovery"]["result"]["adjacencies_before_uncost"]["missing"], [])

    def test_recovery_without_links_to_reenable_never_waits_for_adjacencies(self):
        record, _result, baseline = self.run_with(Plan((1, "ipv6 router ospf 1\nmax-metric router-lsa", "drop-after"), refuse_after=1))
        self.assertEqual(record.state, D.UNCERTAIN)
        observer = H.FakeObserver(H.observation())
        result = self.execute(record, observer)
        self.assertTrue(result.ok, result.codes)
        self.assertEqual(observer.calls, 0)
        self.assertEqual(self.digest(), baseline)
        record.refresh_from_db()
        self.assertIsNone(record.outcome["recovery"]["result"]["adjacencies_before_uncost"])


class AwaitAdjacencyTests(Base):
    """``await_adjacencies`` directly: it polls until every wanted OSPF family is FULL on the device, bounded by the timeout."""

    def test_await_adjacencies_returns_once_every_family_is_full(self):
        observer = H.FakeObserver(H.observation(full=()), H.observation(full=("E1", "E2")))
        runtime = dataclasses.replace(H.runtime(self.fake, observer), adjacency_timeout_seconds=60.0)
        observation, missing = svc.await_adjacencies("T1", ["IPV4", "IPV6"], runtime)
        self.assertEqual((missing, observer.calls), ([], 2))
        self.assertEqual(observation.adjacencies["IPV6"]["device"], ["E1", "E2"])

    def test_await_adjacencies_timeout_reports_the_missing_families(self):
        observer = H.FakeObserver(H.observation(full=()))
        runtime = H.runtime(self.fake, observer)                                   # adjacency timeout 0 s: one observation
        _observation, missing = svc.await_adjacencies("T1", ["IPV4", "IPV6"], runtime)
        self.assertEqual((missing, observer.calls), (["IPV4", "IPV6"], 1))


class CompensationOrderTests(Base):
    """Found live (final run, evidence 40): a fault after the links were shut down rolled back with 74 of 3000 IPv6 probes lost --
    the in-run compensation removed the cost-out before OSPFv3 was FULL on the re-enabled links.  Compensation now waits for the
    baseline's adjacencies (plus one settle period) before the cost-out undo, exactly as ``execute_recovery`` does."""

    def run_observed(self, plan, *observations):
        record = svc.request(self.device, actor=L.OPERATOR, reason="retire R1").record
        healthy = H.runtime(self.fake, H.FakeObserver(H.observation(), H.observation(), H.observation(on_device=False)), probe=H.FakeProbe())
        self.assertTrue(svc.evaluate(record, actor=L.OPERATOR, runtime=healthy).ok)
        record.refresh_from_db()
        self.assertTrue(svc.approve(record, actor=L.APPROVER, confirmation=record.plan_hash).ok)
        record.refresh_from_db()
        observer = H.FakeObserver(*observations)
        runtime = dataclasses.replace(H.runtime(self.fake, observer, probe=H.FakeProbe(), factory=plan.factory(self.fake)),
                                      adjacency_timeout_seconds=60.0)                       # sleep is a no-op
        result = svc.execute(record, actor=L.APPROVER, confirmation=record.plan_hash, runtime=runtime)
        record.refresh_from_db()
        return record, result, observer

    def seen(self):
        text = self.fake.config.text()
        return {"cost_out": "max-metric router-lsa" in text,
                "links_up": "interface Ethernet1\n   shutdown" not in text and "interface Ethernet2\n   shutdown" not in text}

    def test_compensation_waits_for_full_adjacencies_before_undoing_the_cost_out(self):
        states = []

        def observe(full):
            def value(_device):
                states.append({**self.seen(), "full": bool(full)})
                return H.observation(full=full)
            return value

        record, result, _observer = self.run_observed(Plan((1, "interface Ethernet2\nshutdown", "drop-after")),
                                                      H.observation(), H.observation(on_device=False), observe(()), observe(("E1", "E2")))
        self.assertFalse(result.ok)
        self.assertEqual(record.state, D.ROLLED_BACK)
        self.assertEqual(states, [{"cost_out": True, "links_up": True, "full": False}, {"cost_out": True, "links_up": True, "full": True}])
        self.assertEqual(record.transition["adjacencies_before_uncost"]["missing"], [])
        self.assertEqual(self.fake.config.text().count("max-metric router-lsa"), 0)               # undone after the wait
        self.assertEqual(self.digest(), record.baseline.state_digest)

    def test_compensation_without_any_link_shut_down_never_waits(self):
        record, result, observer = self.run_observed(Plan((1, "ipv6 router ospf 1\nmax-metric router-lsa", "drop-after")),
                                                     H.observation(), H.observation(on_device=False))
        self.assertFalse(result.ok)
        self.assertEqual(record.state, D.ROLLED_BACK)
        self.assertEqual(observer.calls, 1)                                                       # the readiness check only
        self.assertIsNone(record.transition["adjacencies_before_uncost"])

    def test_a_failing_compensation_hook_never_skips_an_undo(self):
        governed_observer_calls = []

        def broken(event, key):
            governed_observer_calls.append((event, key))
            if key.startswith("compensate:"):
                raise RuntimeError("hook failed")

        attempt = governed._Attempt(run=None, change=None, plan=None, ops=[], specs=[], actor=L.APPROVER,  # pylint: disable=protected-access
                                    executor=H.executor_factory(self.fake)({"name": "R1"}), observer=broken)
        attempt._step_hook("cost-out-ipv6")                                                        # pylint: disable=protected-access
        self.assertEqual(governed_observer_calls, [("before", "compensate:cost-out-ipv6")])
        self.assertEqual(attempt.steps[-1]["status"], "FAILED")
        self.assertEqual((attempt.steps[-1]["step"], attempt.steps[-1]["operation"]), ("compensate-hook", "cost-out-ipv6"))


class HelperCaseTests(Base):
    """Direct cases for the transaction's session replacement and the append-only reconciliation record."""

    def attempt(self, factory, *, reconnects=0):
        return governed._Attempt(run=None, change=None, plan=None, ops=[], specs=[], actor=L.APPROVER,  # pylint: disable=protected-access
                                 executor=H.executor_factory(self.fake)({"name": "R1"}), executor_factory=factory,
                                 device={"name": "R1", "platform": "ceos"}, reconnects=reconnects)

    def test_reconnect_opens_one_fresh_session_from_the_same_factory(self):
        opened = []

        def factory(device):
            opened.append(device["name"])
            return H.executor_factory(self.fake)(device)
        attempt = self.attempt(factory)
        attempt.session_lost = True
        self.assertTrue(attempt.reconnect("lost"))
        self.assertEqual((opened, attempt.reconnects, attempt.session_lost, attempt.connected), (["R1"], 1, False, True))
        self.assertEqual(attempt.steps[-1]["status"], "PASS")

    def test_reconnect_fails_without_factory_budget_or_reachable_device(self):
        self.assertFalse(self.attempt(None).reconnect("lost"))
        self.assertFalse(self.attempt(H.executor_factory(self.fake), reconnects=governed.MAX_RECONNECTS).reconnect("lost"))

        def unreachable(device):
            return CeosExecutor(device, connection_factory=lambda _d: (_ for _ in ()).throw(ExecutorError("CONNECTION_FAILED")))
        attempt = self.attempt(unreachable)
        self.assertFalse(attempt.reconnect("lost"))
        self.assertEqual((attempt.steps[-1]["status"], attempt.steps[-1]["error"]), ("FAILED", "CONNECTION_FAILED"))

    def test_mark_reconciled_records_each_unresolved_run_once_and_keeps_its_outcome(self):
        record, _result, _baseline = self.run_with(Plan((1, "interface Ethernet2\nshutdown", "drop-after"), refuse_after=1))
        run = record.change.execution_runs.get()
        self.assertEqual(governed.mark_reconciled(record.change, actor=L.APPROVER, digest="d", basis="test"), [str(run.run_id)])
        self.assertEqual(governed.mark_reconciled(record.change, actor=L.APPROVER, digest="d", basis="test"), [])   # once
        run.refresh_from_db()
        self.assertEqual(run.outcome, "FAILED_COMPENSATION_INCOMPLETE")
        self.assertTrue(governed.reconciled(run))

    def test_mark_reconciled_skips_succeeded_and_running_runs_and_reconciled_is_not_true_without_a_record(self):
        record, _result, _baseline = self.run_with(Plan())
        self.assertEqual(record.state, D.DECOMMISSIONED)
        run = record.change.execution_runs.get()
        self.assertEqual(governed.mark_reconciled(record.change, actor=L.APPROVER, digest="d", basis="test"), [])
        self.assertFalse(governed.reconciled(run))

    def test_render_recovery_plans_the_inverse_of_each_present_effect_newest_first(self):
        from core.services.decommission import eos

        ops = [eos.op("cost-out", "ADD", ["router ospf 1", "   max-metric router-lsa"], ["router ospf 1", "   no max-metric router-lsa"],
                      ["router ospf 1 > max-metric router-lsa"], "cost-out"),
               eos.op("remove-ospf", "REMOVE", ["no router ospf 1"], ["router ospf 1", "   router-id 1.1.1.1", "   max-metric router-lsa"],
                      ["router ospf 1"], "remove ospf")]
        planned = eos.render_recovery(ops, {"interface Ethernet1"})          # the routing process is gone, cost-out with it
        self.assertEqual([(o["key"], o["kind"]) for o in planned["operations"]], [("undo-remove-ospf", "ADD"), ("undo-cost-out", "REMOVE")])
        self.assertEqual(planned["operations"][1]["lines"], ["router ospf 1", "   no max-metric router-lsa"])
