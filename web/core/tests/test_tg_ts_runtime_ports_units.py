"""Direct tests for the governance runtime ports (troubleshooting/runtime_ports.py).

Every port fails closed: writes are disabled unless explicitly enabled, a missing redundancy provider / verifier / flow
source / config reader yields "unverified" / False / unmeasurable / READBACK_UNAVAILABLE, and the soak ledger judges only
persisted evidence (a deadline alone never passes).  Fakes stand in for the injected providers; the governance and
soak-ledger code is real.
"""

from __future__ import annotations

from datetime import timedelta
from types import SimpleNamespace

from django.test import SimpleTestCase

from core.services.troubleshooting import governance as gov
from core.services.troubleshooting import repository as repo
from core.services.troubleshooting import runtime_ports as rp
from core.tests.test_troubleshooting_governance import PROPOSER, T0
from core.tests.test_troubleshooting_runtime_ports import FLOW, Net, SoakBase


class Inner:
    configured = True
    HANDOFF_REASON = "execution is a hand-off to the Change page"

    def __init__(self, results=None):
        self.results = results if results is not None else [{"ok": True}]

    def supports(self, op):
        return True

    def dry_run(self, plan):
        return {"ok": True, "errors": []}

    def apply(self, op):
        return {"applied": op}

    def readback(self, plan):
        return {"r1": "digest"}

    def compensate(self, plan, applied):
        return {"results": self.results}


PLAN = {"operations": [{"device": "r2"}, {"device": "r1"}, {"device": "r1"}]}


class WriteGuardTests(SimpleTestCase):
    def test_enabled_executor_delegates_and_reports_the_inner_reason(self):
        ex = rp.WriteGuardedExecutor(Inner(), writes_enabled=True)
        self.assertEqual(ex.unsupported_reason, Inner.HANDOFF_REASON)
        self.assertEqual(ex.dry_run({}), {"ok": True, "errors": []})
        self.assertEqual(ex.apply({"op": 1}), {"applied": {"op": 1}})
        self.assertEqual(ex.readback({}), {"r1": "digest"})
        self.assertEqual(ex.compensate({}, []), {"results": [{"ok": True}]})

    def test_disabled_executor_refuses_writes_by_default(self):
        ex = rp.WriteGuardedExecutor(Inner())
        with self.subTest("a disabled dry run is refused with the reason"):
            self.assertEqual(ex.dry_run({})["ok"], False)
            self.assertIn("disabled", ex.unsupported_reason)
        with self.subTest("a disabled apply raises"):
            with self.assertRaises(gov.GovernanceRefused):
                ex.apply({})
        with self.subTest("a compensation with a failed step raises"):
            with self.assertRaises(gov.GovernanceRefused) as caught:
                rp.WriteGuardedExecutor(Inner([{"ok": True}, {"ok": False}]), writes_enabled=True).compensate({}, [])
            self.assertEqual(caught.exception.code, "COMPENSATION_FAILED")

    def test_readback_failures_propagate(self):
        class Unreadable(Inner):
            def readback(self, plan):
                raise gov.GovernanceRefused("READBACK_UNAVAILABLE", "offline")
        with self.assertRaises(gov.GovernanceRefused):
            rp.WriteGuardedExecutor(Unreadable(), writes_enabled=True).readback({})


class CompensationAndReadbackTests(SimpleTestCase):
    def test_rollback_runner_from_service_returns_a_governed_runner(self):
        run = rp.rollback_runner_from_service(lambda change_id: None)
        self.assertTrue(callable(run))
        with self.assertRaises(gov.GovernanceRefused) as caught:      # no pre-built plan: refused before the service
            run("CHG-1")
        self.assertEqual(caught.exception.code, "COMPENSATION_UNAVAILABLE")

    def test_digest_readback_returns_one_digest_per_device(self):
        out = rp.digest_readback(lambda dev: f"hostname {dev}\n")(PLAN)
        self.assertEqual(sorted(out), ["r1", "r2"])
        self.assertNotEqual(out["r1"], out["r2"])
        self.assertEqual(rp.digest_readback(lambda dev: {"a": 1})(PLAN)["r1"], rp.digest_readback(lambda dev: {"a": 1})(PLAN)["r1"])

    def test_digest_readback_without_a_reader_or_config_is_unavailable(self):
        for label, reader in (("no reader", None), ("an unreadable device", lambda dev: None if dev == "r2" else "x")):
            with self.subTest(f"{label} is unavailable"):
                with self.assertRaises(gov.GovernanceRefused) as caught:
                    rp.digest_readback(reader)(PLAN)
                self.assertEqual(caught.exception.code, "READBACK_UNAVAILABLE")


GOOD_ALT = {"mechanism": "ecmp", "edges": ["e1", "e2"], "capacity_ok": True, "lossless_demonstrated": True, "evidence_ids": ["EV-1"]}


class AlternatePathTests(SimpleTestCase):
    def test_constructed_port_verifies_an_up_existing_redundancy(self):
        port = rp.AlternatePathPort(lambda req, op: GOOD_ALT, link_status=lambda e: "UP")
        out = port({}, {})
        self.assertEqual((out["verified"], out["capacity_ok"], out["mechanism"], out["edges"]), (True, True, "ecmp", ["e1", "e2"]))

    def test_constructed_without_a_provider_nothing_is_verified(self):
        self.assertEqual(rp.AlternatePathPort()({}, {})["verified"], False)

    def test_call_refuses_unproven_redundancy(self):
        def broken(req, op):
            raise RuntimeError("provider down")
        def no_telemetry(edge):
            raise OSError("telemetry down")
        cases = (("a failing provider", broken, lambda e: "UP"), ("a missing mechanism", lambda r, o: {"edges": ["e1"]}, lambda e: "UP"),
                 ("a down edge", lambda r, o: GOOD_ALT, lambda e: "DOWN" if e == "e2" else "UP"),
                 ("unavailable telemetry", lambda r, o: GOOD_ALT, no_telemetry))
        for label, provider, status in cases:
            with self.subTest(f"{label} is never verified"):
                out = rp.AlternatePathPort(provider, link_status=status)({}, {})
                self.assertEqual((out["verified"], out["evidence_ids"]), (False, []))


class StepUpAndSamplingTests(SimpleTestCase):
    PLAN = SimpleNamespace(record_id="RPL-1")
    ACTOR = repo.Actor("alice", "user", tenant="acme")

    def test_step_up_port_accepts_only_a_true_verifier(self):
        self.assertTrue(rp.step_up_port(lambda name, plan: name == "alice" and plan == "RPL-1")(self.ACTOR, self.PLAN))

    def test_step_up_port_without_or_with_a_broken_verifier_is_refused(self):
        def broken(name, plan):
            raise RuntimeError("mfa down")
        for label, verifier in (("no verifier", None), ("a broken verifier", broken), ("a truthy non-true answer", lambda n, p: "yes")):
            with self.subTest(f"{label} is refused"):
                self.assertFalse(rp.step_up_port(verifier)(self.ACTOR, self.PLAN))

    def test_flow_sampler_call_measures_production_and_excludes_test_traffic(self):
        sampler = rp.FlowSampler(None, None, Net(loss=0.5, coverage=0.9), clock=lambda: T0)
        out = sampler([FLOW, {"key": "probe", "classification": "TEST"}, {"protocol": "tcp"}])
        self.assertEqual((out[FLOW["key"]]["loss_pct"], out[FLOW["key"]]["coverage"]), (0.5, 0.9))
        self.assertEqual((out["probe"]["loss_pct"], out["probe"]["excluded"]), (None, "TEST"))
        self.assertEqual(len(out), 2)


LEDGER = {"flows": [{"key": "a"}], "min_flow_coverage": 0.8, "baseline": {"a": 0.0}, "max_loss_increase_pct": 1.0}


def ledger(samples, *, window=600, interval=60, gap=180, cov=0.8):
    return {"started_at": "2026-01-01T00:00:00Z", "window_seconds": window, "interval_seconds": interval, "max_gap_seconds": gap,
            "min_bucket_coverage": cov, "samples": samples}


def usable(minutes):
    return [{"at": f"2026-01-01T00:{m:02d}:00Z", "class": "usable", "reasons": []} for m in minutes]


class SoakLedgerJudgementTests(SimpleTestCase):
    END = T0.replace(year=2026, month=1, day=1, hour=0, minute=10, second=0, microsecond=0)

    def test_sample_issue_classifies_a_clean_reading_as_usable(self):
        self.assertEqual(rp.sample_issue(LEDGER, {"a": {"loss_pct": 0.2, "coverage": 1.0}}), ("usable", []))

    def test_sample_issue_marks_missing_low_coverage_or_lossy_readings(self):
        with self.subTest("a missing flow is unusable"):
            self.assertEqual(rp.sample_issue(LEDGER, {})[0], "unusable")
        with self.subTest("a low coverage reading is unusable"):
            self.assertEqual(rp.sample_issue(LEDGER, {"a": {"loss_pct": 0.0, "coverage": 0.1}})[0], "unusable")
        with self.subTest("loss beyond the threshold is degraded even at low coverage"):
            self.assertEqual(rp.sample_issue(LEDGER, {"a": {"loss_pct": 5.0, "coverage": 0.1}})[0], "degraded")

    def test_assess_ledger_passes_a_complete_clean_window(self):
        st = rp.assess_ledger(ledger(usable(range(1, 11))), self.END + timedelta(minutes=1))
        self.assertEqual((st["state"], st["gaps"]), ("PASSED", 0))

    def test_assess_ledger_refuses_missing_degraded_gapped_or_thin_evidence(self):
        late = self.END + timedelta(minutes=1)
        degraded = usable(range(1, 11)) + [{"at": "2026-01-01T00:05:30Z", "class": "degraded", "reasons": ["a: loss"]}]
        cases = (("no ledger", None, late, "NO_EVIDENCE"), ("a degraded sample", ledger(degraded), late, "DEGRADED"),
                 ("a monitoring gap", ledger(usable([1, 2, 9, 10])), late, "INTERRUPTED"),
                 ("thin coverage", ledger(usable([1, 3, 5, 7, 9, 10]), interval=30, cov=0.9), late, "INCOMPLETE"),
                 ("an open window", ledger(usable([1, 2])), self.END - timedelta(minutes=7), "RUNNING"))
        for label, led, now, state in cases:
            with self.subTest(f"{label} is refused a clean verdict"):
                self.assertEqual(rp.assess_ledger(led, now)["state"], state)


class SoakPersistenceTests(SoakBase):
    def test_start_window_pins_the_ledger_once(self):
        first = rp.start_window(PROPOSER, self.plan.record_id, now=T0)
        again = rp.start_window(PROPOSER, self.plan.record_id, window=timedelta(hours=2), now=T0 + timedelta(minutes=3))
        self.assertEqual(first, again)
        self.assertEqual(first["window_seconds"], int(rp.DEFAULT_WINDOW.total_seconds()))
        self.assertEqual([f["key"] for f in first["flows"]], [FLOW["key"]])

    def test_active_soak_plans_returns_the_verifying_plan_of_the_tenant(self):
        self.assertEqual([p.pk for p in rp.active_soak_plans(self.case.tenant)], [self.plan.pk])

    def test_active_soak_plans_of_another_tenant_is_empty(self):
        self.assertEqual(rp.active_soak_plans("no-such-tenant"), [])

    def test_plan_soak_status_without_samples_is_never_passed(self):
        with self.subTest("an open window with no sample is running"):
            self.assertEqual(rp.plan_soak_status(self.plan, T0 + timedelta(minutes=5))["state"], "RUNNING")
        with self.subTest("an elapsed window with no sample is incomplete"):
            self.assertEqual(rp.plan_soak_status(self.plan, T0 + timedelta(hours=1))["state"], "INCOMPLETE")
        with self.subTest("a ledger shorter than the required window is incomplete"):
            self.run_minutes(1, 30)
            self.assertEqual(rp.plan_soak_status(self.plan, T0 + timedelta(minutes=31), window=timedelta(hours=1))["state"], "INCOMPLETE")

    def test_monitor_once_samples_each_soak_required_plan(self):
        approval = {**self.plan.approval, "soak_required": True}
        type(self.plan).objects.filter(pk=self.plan.pk).update(approval=approval)
        out = rp.monitor_once(PROPOSER, Net(), now=T0 + timedelta(minutes=1))
        self.assertEqual([(o["plan"], o["samples"]) for o in out], [(self.plan.record_id, 1)])

    def test_monitor_once_reports_a_broken_plan_as_error_without_stopping(self):
        approval = {**self.plan.approval, "soak_required": True}
        type(self.plan).objects.filter(pk=self.plan.pk).update(approval=approval)

        def broken_source(flow):
            raise RuntimeError("never reached")
        with self.subTest("a plan without soak required is skipped"):
            type(self.plan).objects.filter(pk=self.plan.pk).update(approval={**approval, "soak_required": False})
            self.assertEqual(rp.monitor_once(PROPOSER, broken_source, now=T0), [])
        with self.subTest("a failing tick is reported as error"):
            type(self.plan).objects.filter(pk=self.plan.pk).update(approval=approval)
            out = rp.monitor_once(PROPOSER, broken_source, now=T0 + timedelta(minutes=1), interval_s="not-a-number")
            self.assertEqual(out[0]["state"], "ERROR")
