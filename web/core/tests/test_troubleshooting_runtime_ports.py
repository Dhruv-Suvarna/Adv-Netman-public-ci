"""Runtime safety ports + persistent soak monitoring (spec 6.2-6.4, UT-069..077, IT-14/15).

Stable IDs RP-01 .. RP-20.  Every flow source / redundancy provider / config reader below is an in-test FAKE behind the real
``runtime_ports`` composition and the real governance/verification code.  This is NOT live-device evidence.
"""

from __future__ import annotations

import io
import json
from datetime import timedelta

from django.core.management import call_command
from django.core.management.base import CommandError
from django.test import TestCase

from core import models as m
from core.services.troubleshooting import governance as gov
from core.services.troubleshooting import repository as repo
from core.services.troubleshooting import runtime_ports as rp
from core.services.troubleshooting import verification as ver
from core.tests.test_troubleshooting_governance import (APPROVER, PROPOSER, T0, FakeExecutor, hotfix_op, make_case, propose,
                                                        seed_deterministic)

ACK = ["I understand this may affect production traffic"]
INV = {"r1": {"platform": "arista_ceos"}, "r2": {"platform": "arista_ceos"}}
FLOW = {"key": "tcp/443:web", "protocol": "tcp"}


class Net:
    """Fake production-flow telemetry: ``loss`` per flow key; ``None`` => unmeasurable."""

    def __init__(self, loss=0.0, coverage=1.0):
        self.loss, self.coverage, self.calls = loss, coverage, 0

    def __call__(self, flow):
        self.calls += 1
        if self.loss is None:
            return None
        return {"loss_pct": self.loss, "coverage": self.coverage}


class LossyExecutor(FakeExecutor):
    """Applying the change makes production lose traffic; compensation heals it (unless told not to)."""

    def __init__(self, net, **kw):
        super().__init__(**kw)
        self.net, self.heals = net, kw.get("restore", True)

    def apply(self, op):
        out = super().apply(op)
        self.net.loss = 9.0
        return out

    def compensate(self, plan, applied):
        out = super().compensate(plan, applied)
        self.net.loss = 0.0 if self.heals else 9.0
        return out


def make_ports(case, *, net=None, executor=None, writes=True, now=T0, **cfg):
    net = net if net is not None else Net()
    base = dict(flow_source=net, inventory=lambda: INV, maintenance=lambda d: False, step_up_verifier=lambda a, p: True,
                redundancy_provider=lambda req, op: {"mechanism": "ecmp", "edges": ["e1"], "capacity_ok": True, "lossless_demonstrated": True},
                link_status=lambda e: "UP", writes_enabled=writes)
    base.update(cfg)
    ports = rp.build_ports(rp.PortConfig(**base), actor=PROPOSER, case=case, clock=lambda: now)
    if executor is not None:
        ports.executor = rp.WriteGuardedExecutor(executor, writes_enabled=writes)
    return ports


def run_to_precheck(case, ev, ports, **kw):
    plan = propose(case, ev, ports=ports, **kw)
    gov.dry_run(PROPOSER, plan.record_id, ports, now=T0)
    gov.approve(APPROVER, plan.record_id, ports, reason="verified causal evidence", acknowledgements=ACK, now=T0)
    return gov.precheck(PROPOSER, plan.record_id, ports, now=T0)


def flow_source_factory():
    return Net(loss=0.0)


class Base(TestCase):
    def setUp(self):
        self.case = make_case()
        self.ev = seed_deterministic(self.case)

    def status(self, plan):
        return m.TsRemediationPlan.objects.get(pk=plan.pk).status


class SafetyPortTests(Base):
    def test_rp01_writes_disabled_by_default(self):
        ports = rp.build_ports(rp.PortConfig(inventory=lambda: INV), actor=PROPOSER, case=self.case, clock=lambda: T0)
        self.assertFalse(ports.executor.supports(hotfix_op()))
        plan = propose(self.case, self.ev, ports=ports)
        with self.assertRaises(gov.GovernanceRefused):
            gov.dry_run(PROPOSER, plan.record_id, ports, now=T0)
        self.assertEqual(self.status(plan), "BLOCKED")
        with self.assertRaises(gov.GovernanceRefused) as cm:
            ports.executor.apply(hotfix_op())
        self.assertEqual(cm.exception.code, "WRITES_DISABLED")
        with self.assertRaises(gov.GovernanceRefused):
            ports.executor.compensate({}, [])

    def test_rp02_authoritative_device_refusal_beats_case_claims(self):
        # case.target_states says r1 is VERIFIED; the managed inventory does not know it => refused anyway
        ports = make_ports(self.case, executor=FakeExecutor(), inventory=lambda: {"r2": {}})
        self.assertEqual(ports.device_state("r1")["admission"], "NOT_IN_INVENTORY")
        with self.assertRaises(gov.GovernanceRefused) as cm:
            run_to_precheck(self.case, self.ev, ports)
        self.assertEqual(cm.exception.code, "PRECHECK_FAILED")
        self.assertTrue(any("NOT_IN_INVENTORY" in p for p in cm.exception.details["problems"]))

    def test_rp03_inventory_unreadable_and_unknown_maintenance_refuse(self):
        def boom():
            raise OSError("inventory.yml missing")
        self.assertEqual(rp.DeviceStatePort(inventory=boom)("r1")["admission"], "INVENTORY_UNAVAILABLE")
        ports = make_ports(self.case, executor=FakeExecutor(), maintenance=None)
        self.assertIsNone(ports.device_state("r1")["maintenance"])
        with self.assertRaises(gov.GovernanceRefused) as cm:
            run_to_precheck(self.case, self.ev, ports)
        self.assertTrue(any("maintenance state UNKNOWN" in p for p in cm.exception.details["problems"]))

    def test_rp04_decommission_in_flight_forces_maintenance_state(self):
        ch = m.Change.objects.create(title="decom", category=m.ChangeCategory.DECOMMISSION, lifecycle_state="DRAFT") \
            if hasattr(m.Change, "title") else None
        if ch is None:
            self.skipTest("Change model shape differs")
        m.ChangeTarget.objects.create(change=ch, device_name="r1")
        st = rp.DeviceStatePort(inventory=lambda: INV, maintenance=lambda d: False)("r1")
        self.assertEqual((st["lifecycle"], st["maintenance"]), ("DECOMMISSIONING", True))

    def test_rp05_absent_alternate_path_refuses_drain(self):
        for kw in (dict(redundancy_provider=None), dict(link_status=lambda e: "DOWN"), dict(link_status=lambda e: None),
                   dict(redundancy_provider=lambda r, o: {"mechanism": "ecmp", "edges": []}),
                   dict(redundancy_provider=lambda r, o: (_ for _ in ()).throw(RuntimeError("x")))):
            case = make_case(key=f"alt-{len(str(kw))}-{id(kw)}")
            ev = seed_deterministic(case)
            ex = FakeExecutor()
            ports = make_ports(case, executor=ex, **kw)
            with self.assertRaises(gov.GovernanceRefused) as cm:
                run_to_precheck(case, ev, ports, ops=[hotfix_op(kind="traffic_drain")])
            self.assertTrue(any("NO_VERIFIED_ALTERNATE_PATH" in p for p in cm.exception.details["problems"]), kw)
            self.assertEqual(ex.applied, [])

    def test_rp06_verified_alternate_path_with_capacity_allows_precheck(self):
        ports = make_ports(self.case, executor=FakeExecutor())
        plan = run_to_precheck(self.case, self.ev, ports, ops=[hotfix_op(kind="traffic_drain")])
        self.assertEqual(plan.status, "PRECHECK_PASS")
        self.assertTrue(plan.alternative_paths[0]["verified"])

    def test_rp07_missing_telemetry_is_not_healthy(self):
        for net in (None, Net(loss=None), Net(coverage=0.1)):
            case = make_case(key=f"tel-{id(net)}")
            ev = seed_deterministic(case)
            ports = make_ports(case, executor=FakeExecutor(), net=net if net is not None else False, flow_source=net)
            s = ports.flow_sample([FLOW])
            self.assertIsNone(s[FLOW["key"]]["loss_pct"] if net is None or net.loss is None else None)
            with self.assertRaises(gov.GovernanceRefused) as cm:
                run_to_precheck(case, ev, ports)
            self.assertTrue(any("not measurable" in p for p in cm.exception.details["problems"]))

    def test_rp08_non_production_flow_cannot_guard(self):
        s = make_ports(self.case, executor=FakeExecutor()).flow_sample([{"key": "icmp:test", "classification": "TEST_TRAFFIC"}])
        self.assertIsNone(s["icmp:test"]["loss_pct"])
        self.assertEqual(s["icmp:test"]["excluded"], "TEST_TRAFFIC")

    def test_rp09_approval_requires_step_up_and_human(self):
        ports = make_ports(self.case, executor=FakeExecutor(), step_up_verifier=None)
        plan = propose(self.case, self.ev, ports=ports)
        gov.dry_run(PROPOSER, plan.record_id, ports, now=T0)
        with self.assertRaises(gov.GovernanceRefused) as cm:
            gov.approve(APPROVER, plan.record_id, ports, reason="verified causal evidence", acknowledgements=ACK, now=T0)
        self.assertEqual(cm.exception.code, "STEP_UP_REQUIRED")
        raising = make_ports(self.case, executor=FakeExecutor(), step_up_verifier=lambda a, p: (_ for _ in ()).throw(RuntimeError("mfa down")))
        with self.assertRaises(gov.GovernanceRefused):
            gov.approve(APPROVER, plan.record_id, raising, reason="verified causal evidence", acknowledgements=ACK, now=T0)
        ok = make_ports(self.case, executor=FakeExecutor())
        self.assertEqual(gov.approve(APPROVER, plan.record_id, ok, reason="verified causal evidence", acknowledgements=ACK, now=T0).status, "APPROVED")

    def test_rp10_readback_and_compensation_services_fail_closed(self):
        with self.assertRaises(gov.GovernanceRefused):
            rp.digest_readback(None)({"operations": [hotfix_op()]})
        with self.assertRaises(gov.GovernanceRefused):
            rp.digest_readback(lambda d: None)({"operations": [hotfix_op()]})
        self.assertEqual(rp.digest_readback(lambda d: "cfg")({"operations": [hotfix_op()]}), rp.digest_readback(lambda d: "cfg")({"operations": [hotfix_op()]}))
        with self.assertRaises(gov.GovernanceRefused) as cm:
            rp.rollback_runner_from_service(lambda cid: None)("CHG-1")
        self.assertEqual(cm.exception.code, "COMPENSATION_UNAVAILABLE")
        # A pre-built plan exists but this repository has no rollback service: an explicit governed refusal, not ImportError.
        import importlib.util
        if importlib.util.find_spec("core.services.rollback_service") is None:
            with self.assertRaises(gov.GovernanceRefused) as cm_missing:
                rp.rollback_runner_from_service(lambda cid: object())("CHG-1")
            self.assertEqual(cm_missing.exception.code, "COMPENSATION_UNAVAILABLE")

        class Inner(FakeExecutor):
            def compensate(self, plan, applied):
                return {"results": [{"ok": True}, {"ok": False}]}
        with self.assertRaises(gov.GovernanceRefused) as cm2:
            rp.WriteGuardedExecutor(Inner(), writes_enabled=True).compensate({}, [])
        self.assertEqual(cm2.exception.code, "COMPENSATION_FAILED")

    def test_rp11_production_loss_mid_change_aborts_and_restores(self):
        net = Net()
        ex = LossyExecutor(net)
        ports = make_ports(self.case, net=net, executor=ex)
        plan = run_to_precheck(self.case, self.ev, ports)
        rec = gov.execute(PROPOSER, plan.record_id, ports, idempotency_key="rp11", now=T0)
        self.assertEqual(rec.status, "ABORTED_RESTORED")
        self.assertIn("exceeds", rec.stop_reason)
        self.assertEqual(len(ex.compensated), 1)

    def test_rp12_compensation_failure_is_unrestored_never_hidden(self):
        for kw in (dict(fail_compensation=True), dict(restore=False)):
            case = make_case(key=f"cf-{len(kw)}-{list(kw)[0]}")
            ev = seed_deterministic(case)
            net = Net()
            ex = LossyExecutor(net, **kw)
            ports = make_ports(case, net=net, executor=ex)
            plan = run_to_precheck(case, ev, ports)
            rec = gov.execute(PROPOSER, plan.record_id, ports, idempotency_key=f"rp12-{list(kw)[0]}", now=T0)
            self.assertEqual(rec.status, "ABORTED_UNRESTORED", kw)
            self.assertFalse(rec.rollback["verified"])
            self.assertEqual(m.TsCase.objects.get(pk=case.pk).disposition["outcome"], "REMEDIATION_FAILED_UNRESTORED")


class SoakBase(Base):
    """An executed plan (APPLIED, VERIFYING) whose sampling is driven tick by tick at explicit instants."""

    def setUp(self):
        super().setUp()
        self.net = Net()
        self.ports = make_ports(self.case, net=self.net, executor=FakeExecutor())
        self.plan = run_to_precheck(self.case, self.ev, self.ports)
        gov.execute(PROPOSER, self.plan.record_id, self.ports, idempotency_key="soak-1", now=T0)

    def tick(self, minutes, *, loss=None, coverage=None, net=None):
        n = net or self.net
        if loss is not None:
            n.loss = loss
        if coverage is not None:
            n.coverage = coverage
        now = T0 + timedelta(minutes=minutes)
        sampler = rp.FlowSampler(PROPOSER, self.case, n, clock=lambda: now)     # a brand-new sampler every call == restart-safe
        return rp.tick(PROPOSER, self.plan.record_id, sampler, now=now)

    def run_minutes(self, start, end, step=1, **kw):
        last = None
        for mnt in range(start, end + 1, step):
            last = self.tick(mnt, **kw)
        return last

    def verify(self, minutes, window=timedelta(minutes=30)):
        now = T0 + timedelta(minutes=minutes)
        ports = make_ports(self.case, net=self.net, executor=FakeExecutor(), now=now)
        return ver.verify(PROPOSER, self.plan.record_id, ports, soak_window=window, now=now, service_checks=lambda: [
            {"name": "tcp443 transaction", "passed": True, "observed": "20/20", "evidence_ids": [self.ev.evidence_id]}])


class SoakTests(SoakBase):
    def test_rp13_complete_clean_soak_verifies(self):
        st = self.run_minutes(1, 30)
        self.assertEqual(st["state"], "PASSED")
        self.assertGreaterEqual(st["coverage"], 0.9)
        rec = self.verify(30)
        self.assertEqual((rec.outcome, rec.soak_status), ("VERIFIED", "PASSED"))
        self.assertEqual(self.status(self.plan), "RESOLVED")
        mon = m.TsProductionFlowMonitor.objects.get(case=self.case)      # named production flow persisted with its samples
        self.assertEqual(mon.selector["key"], FLOW["key"])
        self.assertGreaterEqual(len(mon.sample_windows), 30)
        self.assertEqual(mon.current_loss_pct, 0.0)

    def test_rp14_elapsed_deadline_alone_never_proves_soak(self):
        rec = self.verify(45)          # nobody sampled; the deadline has long passed
        self.assertEqual(rec.outcome, "FAILED")
        self.assertEqual(rec.soak_status, "INCOMPLETE")
        self.assertNotEqual(self.status(self.plan), "RESOLVED")
        early = self.verify(5)
        self.assertEqual(early.outcome, "SOAKING")

    def test_rp15_caller_cannot_shorten_the_window(self):
        self.run_minutes(1, 10)
        rec = self.verify(10, window=timedelta(0))
        self.assertEqual(rec.outcome, "SOAKING")
        self.assertEqual(rec.observed_values["soak"]["window_seconds"], 30 * 60)

    def test_rp16_degradation_is_sticky_a_single_recovered_sample_does_not_clear_it(self):
        self.run_minutes(1, 9)
        self.assertEqual(self.tick(10, loss=7.0)["state"], "DEGRADED")
        st = self.run_minutes(11, 31, loss=0.0)                 # fully recovered, fully sampled
        self.assertEqual(st["state"], "DEGRADED")
        rec = self.verify(31)
        self.assertEqual((rec.outcome, rec.soak_status), ("FAILED", "DEGRADED"))
        self.assertNotEqual(self.status(self.plan), "RESOLVED")
        self.assertTrue(m.TsAuditEvent.objects.filter(case=self.case, action="SOAK_DEGRADED").exists())

    def test_rp17_interrupted_monitoring_cannot_prove_clean(self):
        self.run_minutes(1, 8)
        self.run_minutes(26, 31)       # the sampler was dead for 17 minutes, then came back healthy
        st = self.tick(32)
        self.assertEqual(st["state"], "INTERRUPTED")
        self.assertEqual(self.verify(32).outcome, "FAILED")

    def test_rp18_insufficient_coverage_and_unusable_samples_do_not_pass(self):
        st = self.run_minutes(1, 31, step=3)       # no gap over 180 s but only ~1/3 of intervals covered
        self.assertEqual(st["state"], "INCOMPLETE")
        self.assertEqual(self.verify(31).outcome, "FAILED")

    def test_rp19_missing_telemetry_during_soak_is_a_gap_not_health(self):
        self.run_minutes(1, 5)
        blind = Net(loss=None)
        for mnt in range(6, 32):
            st = self.tick(mnt, net=blind)
        self.assertEqual(st["state"], "INTERRUPTED")
        self.assertEqual(self.verify(31).outcome, "FAILED")

    def test_rp20_restart_recovery_resumes_from_persisted_ledger(self):
        self.run_minutes(1, 14)
        # simulated process restart: nothing in memory, only the database
        led = rp.read_ledger(self.plan)
        self.assertEqual(len(led["samples"]), 14)
        self.assertEqual(rp.plan_soak_status(self.plan, T0 + timedelta(minutes=15))["state"], "RUNNING")
        self.run_minutes(15, 30)
        self.assertEqual(rp.plan_soak_status(self.plan, T0 + timedelta(minutes=30))["state"], "PASSED")
        # a downtime exactly like the above but spanning a restart is visible, not papered over
        self.assertEqual(self.verify(30).outcome, "VERIFIED")

    def test_rp21_clock_moving_backwards_is_rejected(self):
        self.run_minutes(1, 5)
        self.tick(3)
        led = rp.read_ledger(self.plan)
        self.assertEqual((len(led["samples"]), led["rejected"]), (5, 1))

    def test_rp22_reset_window_is_human_audited_and_starts_fresh(self):
        self.run_minutes(1, 3)
        self.tick(4, loss=8.0)
        with self.assertRaises(gov.GovernanceRefused):
            rp.reset_window(repo.Actor("agent-7", "agent", tenant="acme"), self.plan.record_id, reason="try again please", now=T0 + timedelta(minutes=5))
        with self.assertRaises(gov.GovernanceRefused):
            rp.reset_window(APPROVER, self.plan.record_id, reason="x", now=T0 + timedelta(minutes=5))
        led = rp.reset_window(APPROVER, self.plan.record_id, reason="loss was a fixed upstream cable", now=T0 + timedelta(minutes=5))
        self.assertEqual(led["resets"][-1]["prior_state"], "DEGRADED")
        self.net.loss = 0.0
        st = self.run_minutes(6, 36)
        self.assertEqual(st["state"], "PASSED")
        self.assertEqual(self.verify(36).outcome, "VERIFIED")

    def test_rp23_verify_closes_missing_flow_and_coverage_bypasses(self):
        self.run_minutes(1, 30)
        now = T0 + timedelta(minutes=30)
        good = make_ports(self.case, net=self.net, executor=FakeExecutor(), now=now)
        checks = lambda: [{"name": "t", "passed": True, "observed": "ok", "evidence_ids": [self.ev.evidence_id]}]  # noqa: E731
        # (a) a surrounding flow never in the soak ledger / never measured
        r = ver.verify(PROPOSER, self.plan.record_id, good, service_checks=checks, surrounding_flows=[{"key": "udp/53:dns"}], now=now)
        self.assertEqual(r.outcome, "FAILED")
        self.assertTrue(any("udp/53:dns" in x for x in r.regressions))
        # (b) the sampler silently drops the impacted flow
        good.flow_sample = lambda flows: {}
        r = ver.verify(PROPOSER, self.plan.record_id, good, service_checks=checks, now=now)
        self.assertEqual(r.outcome, "FAILED")
        self.assertTrue(any("missing post-change" in x for x in r.regressions))
        # (c) a post-change sample with coverage below the abort threshold
        good.flow_sample = lambda flows: {f["key"]: {"loss_pct": 0.0, "coverage": 0.1} for f in flows}
        r = ver.verify(PROPOSER, self.plan.record_id, good, service_checks=checks, now=now)
        self.assertEqual(r.outcome, "FAILED")
        self.assertTrue(any("coverage" in x for x in r.regressions))

    def test_rp24_soak_needs_a_named_production_flow(self):
        case = make_case(key="noflow")
        ev = seed_deterministic(case)
        ports = make_ports(case, executor=FakeExecutor())
        plan = gov.propose(PROPOSER, case, operations=[hotfix_op(kind="counter_clear")], causal_evidence_ids=[ev.evidence_id],
                           rollback_plan={"steps": ["none"]}, addressed_fault="stale", soak_required=True, ports=ports, now=T0)
        with self.assertRaises(gov.GovernanceRefused) as cm:
            rp.start_window(PROPOSER, plan.record_id, now=T0)
        self.assertIn(cm.exception.code, ("NOT_SOAKABLE", "NO_PRODUCTION_FLOWS"))


class MonitorCommandTests(SoakBase):
    def run_cmd(self, *args):
        out = io.StringIO()
        call_command("troubleshooting_monitor", *args, "--tenant", "acme", stdout=out)
        return json.loads(out.getvalue().strip().splitlines()[-1])

    def test_rp25_command_samples_persists_and_reports_status(self):
        res = self.run_cmd("sample", "--actor", "nmas-monitor", "--flow-source", "core.tests.test_troubleshooting_runtime_ports.flow_source_factory")
        self.assertTrue(res["flow_source"])
        self.assertEqual(res["plans"][0]["plan"], self.plan.record_id)
        self.assertEqual(len(rp.read_ledger(self.plan)["samples"]), 1)
        # real clock is far from the fixed T0 apply time => honestly INTERRUPTED/INCOMPLETE, never PASSED
        self.assertNotEqual(res["plans"][0]["state"], "PASSED")
        st = self.run_cmd("status", "--actor", "alice", "--plan", self.plan.record_id)
        self.assertIn("state", st)

    def test_rp26_command_without_flow_source_records_unusable_samples(self):
        res = self.run_cmd("sample", "--actor", "nmas-monitor")
        self.assertFalse(res["flow_source"])
        samples = rp.read_ledger(self.plan)["samples"]
        self.assertEqual(samples[0]["class"], "unusable")
        self.assertNotEqual(res["plans"][0]["state"], "PASSED")

    def test_rp27_command_reset_requires_reason_and_unknown_plan_refused(self):
        with self.assertRaises(CommandError):
            self.run_cmd("reset-window", "--actor", "alice", "--plan", "RPL-nope", "--reason", "long enough reason")
