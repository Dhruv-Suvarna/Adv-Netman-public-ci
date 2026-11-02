"""Phase-17 structured execution: the eligibility gate, Complete, Partial (UAT), concurrency, history and audit.

Everything runs against a SIMULATED network (``helpers.execution.FakeWorld``) whose executors reuse the production pure
state model; the whole validation -> plan -> precheck chain is real.  No test contacts a device, NetBox, Slack or the network.
"""

from __future__ import annotations

import json
from datetime import timedelta
from types import SimpleNamespace
from unittest import mock

from django.db import IntegrityError, transaction
from django.test import TestCase

from core import models
from core.services import change_plan_service as cps, execution_service as es, health_service as hs
from core.services.execution import auto_recheck, locking
from core.services.execution.scope import resolve_scope
from core.tests.helpers import execution as x, health as h
from core.tests.helpers.validation import Dev, make_sources, nb_prefix, netbox_data, simple_pass_change, validate

ROUTE = ("10.9.0.0/24", "192.0.2.1")
O = models.ExecutionOutcome


def route_change():
    f = simple_pass_change()
    f.r1.static_route(ROUTE[0], next_hop=ROUTE[1])
    return f


def codes(result):
    return {b["code"] for b in result.blockers}


class EligibilityGateTests(TestCase):
    def test_every_gate_blocks_before_any_device_is_touched(self):
        def lifecycle():
            p = x.prepared()
            p.change.lifecycle_state = "DEPLOYED"
            p.change.save(update_fields=["lifecycle_state"])
            return p, {}

        def stale_validation():
            p = x.prepared()
            p.f.r1.set(f"interfaces.{p.f.a['id']}.description", "edited after validation")
            return p, {}

        def superseded():
            p = x.prepared()
            validate(p.change, p.sources)
            return p, {}

        def never_validated():
            f = simple_pass_change()
            return SimpleNamespace(change=f.change, sources=f.sources, plan=None, precheck=None), {}

        def no_plan():
            f = simple_pass_change()
            validate(f.change, f.sources)
            return SimpleNamespace(change=f.change, sources=f.sources, plan=None, precheck=None), {}

        def no_precheck():
            f = simple_pass_change()
            validate(f.change, f.sources)
            plan, _ = cps.build_change_plan(f.change, actor="t", sources=f.sources)
            return SimpleNamespace(change=f.change, sources=f.sources, plan=plan, precheck=None), {}

        def wrong_plan_precheck():
            p = x.prepared()
            validate(p.change, p.sources)
            cps.build_change_plan(p.change, actor="t", sources=p.sources)  # a NEW plan; the precheck belongs to the old one
            return p, {}

        def blocked_precheck():
            p = x.prepared()
            x.precheck(p.change, p.sources, snapshot=h.snapshot(ages={"R1": 500}), fail={"R1": TimeoutError()})
            return p, {}

        def expired_precheck():
            p = x.prepared()
            return p, {"now": p.precheck.finished_at + timedelta(hours=2)}

        def linux_rename():  # a hostname rename has no executor on any platform (FRR routing and single-table PAT now execute)
            f = simple_pass_change()
            r3 = Dev(f.change, "R3", platform=models.Platform.UBUNTU_FRR)
            r3.address(r3.iface("eth1"), "192.0.2.4/31")
            r3.set("device.hostname", "R3-EDGE")
            return x.prepared(f), {}

        def unmanaged_device():
            f = simple_pass_change()
            Dev(f.change, "NEW1", target_type=models.DeviceIntentTargetType.NEW_DEVICE).iface("Ethernet1")
            return x.prepared(f, require_permit=False), {}

        rows = [
            ("lifecycle state does not permit execution", lifecycle, {"CHANGE_LIFECYCLE_NOT_EXECUTABLE"}),
            ("mode not confirmed", lambda: (x.prepared(), {"confirm": "PARTIAL_UAT"}), {"MODE_CONFIRMATION_MISMATCH"}),
            ("validation STALE (accepted intent edited)", stale_validation, {"VALIDATION_STALE", "PLAN_STALE"}),
            ("plan superseded by a newer validation", superseded, {"PLAN_STALE"}),
            ("never validated", never_validated, {"VALIDATION_NEVER_RUN", "PLAN_MISSING"}),
            ("no plan", no_plan, {"PLAN_MISSING"}),
            ("no precheck", no_precheck, {"PRECHECK_MISSING"}),
            ("precheck belongs to another plan", wrong_plan_precheck, {"PRECHECK_WRONG_PLAN"}),
            ("precheck BLOCKED", blocked_precheck, {"PRECHECK_NOT_PERMITTING"}),
            ("precheck expired", expired_precheck, {"PRECHECK_EXPIRED"}),
            ("unsupported platform / object type", linux_rename, {"PLATFORM_EXECUTION_UNSUPPORTED"}),
            ("target device not in the managed inventory", unmanaged_device, {"TARGET_DEVICE_UNRESOLVABLE"}),
        ]
        for label, build, expected in rows:
            with self.subTest(case=label):
                p, kwargs = build()
                world = x.FakeWorld(("R1", "R2", "R3", "NEW1"))
                result = x.run(p, world, **kwargs)
                self.assertEqual(result.outcome, O.BLOCKED)
                self.assertLessEqual(expected, codes(result))
                self.assertEqual(world.calls, [], "a refused execution never reaches an executor -- not even a connection")
                if result.run is not None:
                    self.assertEqual((result.run.state, result.run.outcome), ("FINISHED", O.BLOCKED))
                    self.assertEqual(result.run.results.count(), 0)
                    self.assertEqual(result.run.device_locks.count(), 0)

    def test_a_current_permitted_change_is_eligible_and_the_gate_has_no_side_effects(self):
        p = x.prepared()
        before = {m.__name__: m.objects.count() for m in (models.ChangeExecutionRun, models.ChangeValidationRun, models.ChangePlan,
                                                          models.OperationalCheckRun, models.AuditEvent, models.Configlet)}
        gate = es.check_execution_eligibility(p.change, confirm_mode="COMPLETE", sources=p.sources)
        self.assertTrue(gate.eligible, gate.blockers)
        self.assertEqual(gate.scope.requested_cfg_ids, x.cfg_ids(p))
        self.assertEqual(before, {m.__name__: m.objects.count() for m in (models.ChangeExecutionRun, models.ChangeValidationRun, models.ChangePlan,
                                                                           models.OperationalCheckRun, models.AuditEvent, models.Configlet)})
        # the display gate (no operator input yet) skips only the operator-input gates
        page = es.check_execution_eligibility(p.change, for_submission=False, sources=p.sources)
        self.assertTrue(page.eligible)

    def test_vlan200_auto_addressing_is_refused_even_if_a_plan_somehow_carried_it(self):
        p = x.prepared()
        address = p.plan.configlets.get(cfg_id="CFG-003")
        # queryset update bypasses the frozen-field guard: this simulates a corrupted/forged plan row (defence in depth)
        models.Configlet.objects.filter(pk=address.pk).update(
            metadata={**address.metadata, "derived": {"kind": "AUTO_ADDRESS", "proposed_address": "192.0.2.0/31"}},
            verification_spec={"schema_version": 1, "requirements": [{**address.verification_spec["requirements"][0],
                                                                       "expected": {"interface": "Vlan200", "address": "192.0.2.0/31", "family": 4}}]})
        world = x.FakeWorld()
        result = x.run(p, world)
        self.assertIn("VLAN200_AUTO_FORBIDDEN", codes(result))
        self.assertEqual(world.calls, [])


class CompleteModeTests(TestCase):
    def test_success_is_ordered_verified_persisted_and_leaves_lifecycle_alone(self):
        p = x.prepared()
        world, notes = x.FakeWorld(), x.Notifications()
        result = x.run(p, world, notifier=notes)
        run = result.run
        self.assertEqual(result.outcome, O.SUCCEEDED)
        self.assertEqual(world.applied(), x.cfg_ids(p), "deterministic plan order")
        self.assertEqual(world.compensated(), [])
        self.assertEqual((run.state, run.outcome, run.mode), ("FINISHED", O.SUCCEEDED, "COMPLETE"))
        self.assertEqual(run.report["postcheck"]["result"], "PASS")
        self.assertIsNotNone(run.postcheck_run)
        self.assertEqual(run.report["persistence"], "RUNNING_CONFIG_ONLY")
        # provenance answers: which change / plan / validation / precheck / hash / operator
        self.assertEqual((run.plan_id, run.validation_run_id, run.precheck_run_id, run.plan_hash), (p.plan.pk, p.plan.validation_run_id, p.precheck.pk, p.plan.plan_hash))
        self.assertEqual(run.actor, "tester")
        statuses = list(run.results.order_by("sequence").values_list("cfg_id", "phase", "status"))
        self.assertEqual(statuses, [(c, "APPLY", "APPLIED") for c in x.cfg_ids(p)])
        self.assertEqual(set(models.Configlet.objects.filter(plan=p.plan).values_list("execution_status", flat=True)), {"DEPLOYED"})
        p.change.refresh_from_db()
        self.assertEqual(p.change.lifecycle_state, "DRAFT", "execution never advances the lifecycle (no Golden / Probation / soak)")
        self.assertEqual(run.device_locks.count(), 0)
        self.assertEqual(world.closed.count("R1"), 1)
        self.assertEqual([(n["event_type"], n["severity"]) for n in notes.events], [("DEPLOYMENT_SUCCEEDED", "SUCCESS")])
        previous = models.Configlet.objects.get(plan=p.plan, cfg_id="CFG-003").previous_state_ref
        self.assertEqual((previous["status"], previous["run_id"]), ("CAPTURED", str(run.run_id)))

    def test_first_failure_stops_the_run_and_compensates_in_reverse_order(self):
        p = x.prepared()
        world = x.FakeWorld()
        world.fail_apply["CFG-003"] = ("COMMAND_REJECTED", True)      # the failing Configlet may have partly applied
        result = x.run(p, world)
        self.assertEqual(result.outcome, O.FAILED_ROLLED_BACK)
        self.assertEqual(world.applied(), ["CFG-001", "CFG-002", "CFG-003"], "stopped at the first failure; CFG-004 never attempted")
        self.assertEqual(world.compensated(), ["CFG-003", "CFG-002", "CFG-001"], "reverse order, including the partly-applied Configlet")
        self.assertEqual(world.state["R1"]["addresses"].get("Ethernet1", []), [])
        self.assertEqual((world.state["R1"]["interfaces"], world.state["R2"]["interfaces"]), ({}, {}), "the pre-execution state is restored")
        rows = {(r.cfg_id, r.phase): r.status for r in result.run.results.all()}
        self.assertEqual(rows[("CFG-004", "APPLY")], "NOT_ATTEMPTED")
        self.assertEqual(rows[("CFG-003", "APPLY")], "FAILED")
        self.assertEqual({rows[(c, "COMPENSATE")] for c in ("CFG-001", "CFG-002", "CFG-003")}, {"COMPENSATED"})
        self.assertEqual(result.run.report["compensation"]["status"], "SUCCEEDED")

    def test_incomplete_compensation_is_reported_and_never_becomes_success(self):
        p = x.prepared()
        world, notes = x.FakeWorld(), x.Notifications()
        world.fail_apply["CFG-004"] = ("COMMAND_REJECTED", True)
        world.fail_compensation["CFG-002"] = ("COMPENSATION_UNVERIFIED", "VERIFICATION_UNAVAILABLE")
        result = x.run(p, world, notifier=notes)
        self.assertEqual(result.outcome, O.FAILED_COMPENSATION_INCOMPLETE)
        self.assertEqual(world.compensated(), ["CFG-004", "CFG-003", "CFG-002", "CFG-001"], "one failed undo never stops the remaining undos")
        self.assertEqual(result.run.report["compensation"]["status"], "INCOMPLETE")
        self.assertEqual(result.run.report["compensation"]["not_compensated"], ["CFG-002"])
        self.assertEqual([(n["event_type"], n["severity"]) for n in notes.events], [("ROLLBACK_FAILED", "CRITICAL")])
        # an unresolved plan can never be re-executed until a human resolves it
        again = es.check_execution_eligibility(p.change, confirm_mode="COMPLETE", sources=p.sources)
        self.assertTrue(again.has("PLAN_STATE_UNRESOLVED"))

    def test_a_postcheck_that_does_not_pass_is_a_failed_run_and_triggers_compensation(self):
        def one_requirement_not_met(world):     # the device ACCEPTED the commands but the state never appeared
            original = world.mutate
            world.mutate = lambda spec: None if spec.cfg_id == "CFG-004" else original(spec)
            return world.evidence_provider

        def evidence_missing(world):            # required evidence cannot be read: never a pass
            return lambda plan, cfg_ids: h.evidence_set(*[h.device_evidence(n, interfaces=None, addresses=None, routes=None) for n in world.state])

        for label, arrange in (("a required requirement fails", one_requirement_not_met), ("required evidence is missing", evidence_missing)):
            with self.subTest(case=label):
                p = x.prepared()
                world = x.FakeWorld()
                result = x.run(p, world, evidence_provider=arrange(world))
                self.assertEqual(result.outcome, O.POSTCHECK_FAILED_ROLLED_BACK)
                self.assertNotEqual(result.run.report["postcheck"]["result"], "PASS")
                self.assertEqual(world.compensated(), list(reversed(x.cfg_ids(p))), "everything this run applied is compensated, in reverse")
                self.assertEqual(world.state["R1"]["interfaces"], {})
                self.assertEqual(world.state["R2"]["interfaces"], {})

    def test_preparation_failures_mean_zero_mutation(self):
        def pre_existing_primary(w):   # applying would REPLACE the primary address: not additive, not provably restorable
            w.state["R1"]["addresses"]["Ethernet1"] = ["203.0.113.9/24"]
            w.state["R1"]["interfaces"]["Ethernet1"] = {"admin": "UP", "oper": "UP"}

        def existing_interface(w):     # modifying an existing interface cannot be undone exactly
            w.state["R2"]["interfaces"]["Ethernet1"] = {"admin": "UP", "oper": "UP"}

        rows = [
            ("device unreachable", lambda w: w.fail_connect.update(R2="CONNECTION_FAILED"), O.FAILED_NO_MUTATION, "PREPARATION_FAILED"),
            ("previous state unreadable", lambda w: w.fail_assess.update({"CFG-003": "PREVIOUS_STATE_UNAVAILABLE"}), O.FAILED_NO_MUTATION, "PREPARATION_FAILED"),
            ("apply would overwrite a primary address", pre_existing_primary, O.BLOCKED, "COMPENSATION_NOT_PROVABLE"),
            ("interface already exists", existing_interface, O.BLOCKED, "COMPENSATION_NOT_PROVABLE"),
        ]
        for label, arrange, outcome, code in rows:
            with self.subTest(case=label):
                p = x.prepared()
                world = x.FakeWorld()
                arrange(world)
                result = x.run(p, world)
                self.assertEqual(result.outcome, outcome)
                self.assertIn(code, codes(result))
                self.assertEqual(world.mutating_calls(), [], "the first mutation never happens when preparation cannot prove the contract")
                self.assertEqual(result.run.device_locks.count(), 0)

    def test_state_already_satisfied_is_not_resent_and_never_compensated(self):
        p = x.prepared()
        world = x.FakeWorld(addresses={"R1": {"Ethernet1": ["192.0.2.0/31"]}})
        world.fail_apply["CFG-004"] = ("COMMAND_REJECTED", True)
        result = x.run(p, world)
        self.assertEqual(result.outcome, O.FAILED_ROLLED_BACK)
        self.assertNotIn("CFG-003", world.applied())
        self.assertNotIn("CFG-003", world.compensated(), "this run did not add it, so it must not remove it")
        self.assertEqual(world.state["R1"]["addresses"]["Ethernet1"], ["192.0.2.0/31"])
        self.assertEqual(result.run.results.get(cfg_id="CFG-003", phase="APPLY").status, "ALREADY_SATISFIED")

    def test_static_route_settling_is_bounded_and_evidence_backed(self):
        def flaky(world, converges_after):
            calls = {"n": 0}

            def provider(plan, cfg_ids):
                calls["n"] += 1
                if calls["n"] < converges_after:                     # the route has not been installed yet
                    saved = world.state["R1"]["routes"]
                    world.state["R1"]["routes"] = []
                    try:
                        return world.evidence_provider(plan, cfg_ids)
                    finally:
                        world.state["R1"]["routes"] = saved
                return world.evidence_provider(plan, cfg_ids)

            provider.calls = calls
            return provider

        ticks = iter(range(0, 10_000, 1))  # one simulated second per read
        p = x.prepared(route_change())
        world, sleeps = x.FakeWorld(), []
        provider = flaky(world, converges_after=3)
        result = x.run(p, world, evidence_provider=provider, sleep=sleeps.append, clock=lambda: next(ticks))
        self.assertEqual(result.outcome, O.SUCCEEDED)
        self.assertEqual(result.run.report["postcheck"]["settle"]["attempts"], 3)
        self.assertEqual(len(sleeps), 2)

        # never converges: the poll ends at its deadline (bounded), the run FAILS its postcheck and is compensated
        p = x.prepared(route_change())
        world, sleeps = x.FakeWorld(), []
        ticks = iter(range(0, 100_000, 7))
        result = x.run(p, world, evidence_provider=flaky(world, converges_after=10**9), sleep=sleeps.append, clock=lambda: next(ticks))
        self.assertEqual(result.outcome, O.POSTCHECK_FAILED_ROLLED_BACK)
        self.assertLessEqual(result.run.report["postcheck"]["settle"]["attempts"], 6)
        self.assertLessEqual(len(sleeps), 5)


class PartialUatModeTests(TestCase):
    def prepared_partial(self):
        return x.prepared(mode=models.ExecutionMode.PARTIAL_UAT)

    def test_acknowledgements_scope_and_mode_are_enforced(self):
        p = self.prepared_partial()
        one_missing = {**x.ALL_ACKS, "uat_ack_operator_accepts_risk": False}
        rows = [
            ("no acknowledgements", dict(through="CFG-002", acks={}), {"UAT_ACK_MISSING"}),
            ("one acknowledgement missing", dict(through="CFG-002", acks=one_missing), {"UAT_ACK_MISSING"}),
            ("no explicit scope", dict(through="", acks=x.ALL_ACKS), {"UAT_SCOPE_REQUIRED"}),
            ("scope not in the plan", dict(through="CFG-999", acks=x.ALL_ACKS), {"UAT_SCOPE_INVALID"}),
            ("mode not confirmed", dict(through="CFG-002", acks=x.ALL_ACKS, confirm="COMPLETE"), {"MODE_CONFIRMATION_MISMATCH"}),
        ]
        for label, kwargs, expected in rows:
            with self.subTest(case=label):
                world = x.FakeWorld()
                result = x.run(p, world, **kwargs)
                self.assertEqual(result.outcome, O.BLOCKED)
                self.assertLessEqual(expected, codes(result))
                self.assertEqual(world.calls, [])
        p.change.refresh_from_db()
        self.assertFalse(any(getattr(p.change, name) for name, _ in es.UAT_ACK_FIELDS), "a refused attempt never records acknowledgements")

    def test_success_applies_only_the_requested_prefix_and_verifies_only_it(self):
        p = self.prepared_partial()
        world = x.FakeWorld()
        result = x.run(p, world, through="CFG-002", acks=x.ALL_ACKS)
        run = result.run
        self.assertEqual(result.outcome, O.UAT_SCOPE_APPLIED)
        self.assertEqual(world.applied(), ["CFG-001", "CFG-002"])
        self.assertEqual(run.report["state"]["out_of_scope"], ["CFG-003", "CFG-004"])
        self.assertEqual(run.report["postcheck"]["cfg_ids"], ["CFG-001", "CFG-002"], "future Configlets are not demanded of the postcheck")
        self.assertEqual(run.report["postcheck"]["result"], "PASS")
        p.change.refresh_from_db()
        self.assertTrue(all(getattr(p.change, name) for name, _ in es.UAT_ACK_FIELDS))
        self.assertEqual((p.change.uat_acknowledged_by, bool(p.change.uat_acknowledged_at)), ("tester", True))
        self.assertEqual(p.change.lifecycle_state, "DRAFT")

    def test_failure_preserves_the_successful_prefix_and_records_the_remainder(self):
        p = self.prepared_partial()
        world, notes = x.FakeWorld(), x.Notifications()
        world.fail_apply["CFG-003"] = ("COMMAND_REJECTED", False)
        result = x.run(p, world, through="CFG-004", acks=x.ALL_ACKS, notifier=notes)
        run = result.run
        self.assertEqual(result.outcome, O.FAILED_PARTIAL_APPLIED)
        self.assertEqual(world.compensated(), [], "Partial (UAT) never rolls back automatically")
        self.assertEqual(sorted(world.state["R1"]["interfaces"]) + sorted(world.state["R2"]["interfaces"]), ["Ethernet1", "Ethernet1"], "the successful prefix is preserved")
        self.assertEqual(run.report["state"]["applied"], ["CFG-001", "CFG-002"])
        self.assertEqual(run.report["state"]["failed"], ["CFG-003"])
        self.assertEqual(run.report["state"]["unapplied"], ["CFG-004"])
        self.assertEqual(run.results.get(cfg_id="CFG-004").status, "NOT_ATTEMPTED")
        self.assertEqual(run.report["postcheck"]["cfg_ids"], ["CFG-001", "CFG-002"], "evidence for what was preserved")
        self.assertEqual([(n["event_type"], n["severity"]) for n in notes.events], [("DEPLOYMENT_FAILED", "ERROR")])
        self.assertEqual(run.report["compensation"]["status"], "NOT_ATTEMPTED")

    def test_failure_outcomes_distinguish_no_change_from_partial_state(self):
        rows = [
            ("first Configlet rejected, nothing changed", "CFG-001", False, O.FAILED_NO_MUTATION),
            ("first Configlet rejected but may be partly applied", "CFG-001", True, O.FAILED_PARTIAL_APPLIED),
        ]
        for label, cfg, effects, expected in rows:
            with self.subTest(case=label):
                p = self.prepared_partial()
                world = x.FakeWorld()
                world.fail_apply[cfg] = ("COMMAND_REJECTED", effects)
                result = x.run(p, world, through="CFG-004", acks=x.ALL_ACKS)
                self.assertEqual(result.outcome, expected)
                self.assertEqual(world.compensated(), [])

    def test_a_postcheck_deviation_or_gap_in_the_scope_is_reported_and_never_rolled_back(self):
        for label, make_provider, expected in (
            ("deviation", lambda w: (lambda plan, ids: h.evidence_set(*[h.device_evidence(n, interfaces={}, addresses={}, routes=[]) for n in w.state])), O.UAT_SCOPE_APPLIED_POSTCHECK_FAILED),
            ("evidence unavailable", lambda w: (lambda plan, ids: h.evidence_set(*[h.device_evidence(n, interfaces=None, addresses=None, routes=None) for n in w.state])), O.UAT_SCOPE_APPLIED_UNVERIFIED),
        ):
            with self.subTest(case=label):
                p = self.prepared_partial()
                world = x.FakeWorld()
                result = x.run(p, world, through="CFG-002", acks=x.ALL_ACKS, evidence_provider=make_provider(world))
                self.assertEqual(result.outcome, expected)
                self.assertEqual(world.compensated(), [])

    def test_every_partial_scope_is_a_dependency_closed_prefix(self):
        p = self.prepared_partial()
        order = x.cfg_ids(p)
        for through in order:
            with self.subTest(through=through):
                scope, problems = resolve_scope(p.plan, "PARTIAL_UAT", through)
                self.assertEqual(problems, [])
                self.assertEqual(scope.requested_cfg_ids, order[: order.index(through) + 1])
                chosen = set(scope.requested_cfg_ids)
                for cfg, needs in scope.dependencies.items():
                    if cfg in chosen:
                        self.assertLessEqual(set(needs), chosen)
        # a subset whose prerequisite is not inside it is REFUSED, never guessed: force an earlier Configlet to depend on a later one
        by_id = {c.cfg_id: c for c in p.plan.configlets.all()}
        models.ConfigletDependency.objects.create(configlet=by_id["CFG-001"], depends_on=by_id["CFG-004"])
        scope, problems = resolve_scope(p.plan, "PARTIAL_UAT", "CFG-002")
        self.assertLessEqual({"PLAN_ORDER_INVALID", "UAT_SCOPE_INVALID"}, {b["code"] for b in problems})


class ConcurrencyHistoryAndAuditTests(TestCase):
    def test_a_running_change_and_overlapping_devices_are_refused_at_the_database_level(self):
        a, b = x.prepared(), x.prepared()
        scope_a, _ = resolve_scope(a.plan, "COMPLETE")
        run_a = locking.acquire(change=a.change, plan=a.plan, precheck_run=a.precheck, mode="COMPLETE", actor="t", scope=scope_a, devices=scope_a.devices)
        world = x.FakeWorld()
        # 1. the SAME change again (double click / two requests)
        again = x.run(a, world)
        self.assertEqual((again.outcome, codes(again) & {"EXECUTION_IN_PROGRESS"}), (O.BLOCKED, {"EXECUTION_IN_PROGRESS"}))
        # 2. a DIFFERENT change touching the same devices
        other = x.run(b, world)
        self.assertIn("DEVICE_LOCKED", codes(other))
        self.assertEqual(world.calls, [])
        # the constraints themselves (not just the checks) hold
        with self.assertRaises(IntegrityError), transaction.atomic():
            models.ChangeExecutionRun.objects.create(change=a.change, plan=a.plan, validation_run=a.plan.validation_run, mode="COMPLETE",
                                                     engine_version="t", plan_hash="x", validation_input_hash="x", validation_source_hash="x",
                                                     started_at=run_a.started_at, lease_expires_at=run_a.lease_expires_at)
        with self.assertRaises(IntegrityError), transaction.atomic():
            models.ExecutionDeviceLock.objects.create(device="R1", run=run_a)
        locking.heartbeat(run_a)
        self.assertEqual(run_a.device_locks.count(), 2)

    def test_a_device_in_maintenance_is_not_executed_against_and_every_other_device_is(self):
        from core.services.maintenance_mode import lifecycle

        def maintenance(device, state):
            return models.MaintenanceRecord.objects.create(device_name=device, state=state, requested_by="x", reason="y", requested_at=h.NOW,
                                                           requested_duration_seconds=60)

        for state in (lifecycle.ENTERING, lifecycle.ACTIVE, lifecycle.RESTORING):
            record = maintenance("R1", state)
            p = x.prepared()                                                  # validation, plan and precheck are not affected
            gate = es.check_execution_eligibility(p.change, for_submission=False, check_sources=False)
            self.assertIn("DEVICE_UNDER_MAINTENANCE", {b["code"] for b in gate.blockers}, state)
            world = x.FakeWorld()
            result = x.run(p, world)
            self.assertEqual((result.outcome, "DEVICE_UNDER_MAINTENANCE" in codes(result), world.calls), (O.BLOCKED, True, []), state)
            record.delete()
        maintenance("S3", lifecycle.ACTIVE)                                    # a maintenance elsewhere does not freeze the network
        maintenance("R1", lifecycle.RESTORED)
        p = x.prepared()
        result = x.run(p, x.FakeWorld())
        self.assertNotIn("DEVICE_UNDER_MAINTENANCE", codes(result))
        self.assertEqual(result.outcome, O.SUCCEEDED)

    def test_an_abandoned_run_is_reaped_as_interrupted_and_its_plan_stays_unresolved(self):
        p = x.prepared()
        scope, _ = resolve_scope(p.plan, "COMPLETE")
        stale = locking.acquire(change=p.change, plan=p.plan, precheck_run=p.precheck, mode="COMPLETE", actor="t", scope=scope, devices=scope.devices,
                                now=p.precheck.finished_at - timedelta(hours=3))
        page = es.check_execution_eligibility(p.change, for_submission=False, sources=p.sources)
        self.assertTrue(page.has("PLAN_STATE_UNRESOLVED"), "a read-only view already sees the abandoned run")
        world = x.FakeWorld()
        result = x.run(p, world)
        stale.refresh_from_db()
        self.assertEqual((stale.state, stale.outcome), ("FINISHED", O.INTERRUPTED))
        self.assertEqual(stale.device_locks.count(), 0)
        self.assertIn("PLAN_STATE_UNRESOLVED", codes(result))
        self.assertEqual(world.calls, [])

    def test_history_is_append_only_and_a_retry_is_a_new_attempt_against_current_eligibility(self):
        p = x.prepared()
        world = x.FakeWorld()
        world.fail_apply["CFG-004"] = ("COMMAND_REJECTED", True)
        first = x.run(p, world).run
        self.assertEqual(first.outcome, O.FAILED_ROLLED_BACK)
        snapshot = (first.outcome, first.report, first.finished_at, list(first.results.values_list("status", flat=True)))
        # no silent resume: the old failed run does not authorise anything; a NEW precheck is required first
        blocked = x.run(p, x.FakeWorld())
        self.assertIn("PRECHECK_BEFORE_LAST_EXECUTION", codes(blocked))
        x.precheck(p.change, p.sources)
        retry = x.run(p, x.FakeWorld())
        self.assertEqual(retry.outcome, O.SUCCEEDED)
        self.assertNotEqual(retry.run.pk, first.pk)
        first.refresh_from_db()
        self.assertEqual(snapshot, (first.outcome, first.report, first.finished_at, list(first.results.values_list("status", flat=True))))
        # a successfully applied plan is not executed again
        self.assertIn("PLAN_ALREADY_APPLIED", codes(x.run(p, x.FakeWorld())))
        # finished rows are immutable
        for row, field, value in ((first, "actor", "someone-else"), (first.results.first(), "status", "APPLIED")):
            with self.subTest(model=type(row).__name__), self.assertRaises(ValueError):
                setattr(row, field, value)
                row.save()

    def test_audit_trail_and_notifications_never_break_the_run(self):
        p = x.prepared()
        world = x.FakeWorld()
        world.fail_apply["CFG-004"] = ("COMMAND_REJECTED", True)

        def exploding(**kwargs):
            raise RuntimeError("Slack is down")

        result = x.run(p, world, notifier=exploding)
        self.assertEqual(result.outcome, O.FAILED_ROLLED_BACK, "a notification failure never corrupts the primary record")
        events = list(models.AuditEvent.objects.filter(change=p.change, event_type__in=("DEPLOYMENT_RECORDED", "ROLLBACK_RECORDED")).order_by("id"))
        self.assertEqual([(e.event_type, e.metadata.get("stage") or "COMPENSATION") for e in events], [("DEPLOYMENT_RECORDED", "STARTED"), ("DEPLOYMENT_RECORDED", "FINISHED"), ("ROLLBACK_RECORDED", "COMPENSATION")])
        finish = events[1].metadata
        self.assertEqual((finish["outcome"], finish["applied"], finish["failed"]), (O.FAILED_ROLLED_BACK, ["CFG-001", "CFG-002", "CFG-003"], ["CFG-004"]))
        # a refusal is audited too, but not published
        notes = x.Notifications()
        x.run(p, x.FakeWorld(), notifier=notes)
        self.assertEqual(notes.events, [])
        self.assertTrue(models.AuditEvent.objects.filter(change=p.change, metadata__stage="BLOCKED").exists())

    def test_no_secret_or_device_text_is_ever_persisted(self):
        p = x.prepared()
        world = x.FakeWorld()

        class Leaky(x.FakeExecutor):
            def apply(self, spec, assessment):
                raise RuntimeError("login failed for user admin password hunter2 token=SECRET-TOKEN-XYZ")

        result = x.run(p, world, executor_factory=lambda device: Leaky(world, device["name"]))
        self.assertEqual(result.outcome, O.FAILED_ROLLED_BACK, "an executor defect is an ambiguous failure: compensated, never a success")
        dump = json.dumps([es.serialize_run(result.run), list(models.AuditEvent.objects.values("summary", "metadata")),
                           list(models.ConfigletExecutionResult.objects.values("error_code", "detail", "previous_state"))], default=str)
        for leaked in ("hunter2", "SECRET-TOKEN-XYZ", "login failed"):
            self.assertNotIn(leaked, dump)
        failed = result.run.results.get(cfg_id="CFG-001", phase="APPLY")
        self.assertEqual((failed.error_code, failed.status), ("INTERNAL_ERROR", "UNKNOWN"))


class AutoAddressRecheckTests(TestCase):
    def auto_fixture(self):
        f = simple_pass_change()
        f.sources = make_sources(netbox=netbox_data(prefixes=[nb_prefix("198.51.100.0/29")]))
        f.r1.auto_address(f.r1.iface("Ethernet2"), "198.51.100.0/29")
        return f

    def test_auto_addresses_are_rechecked_read_only_and_a_difference_refuses(self):
        p = x.prepared(self.auto_fixture())
        autos = [c for c in p.plan.configlets.all() if (c.metadata.get("derived") or {}).get("kind") == "AUTO_ADDRESS"]
        self.assertEqual(len(autos), 1)
        planned = autos[0].metadata["derived"]["proposed_address"]
        rows = [
            ("unchanged NetBox", p.sources, []),
            ("the proposed host is now taken in NetBox",
             make_sources(netbox=netbox_data(prefixes=[nb_prefix("198.51.100.0/29")], ip_addresses=[{"cidr": planned, "ip": planned.split("/")[0], "prefix_length": 29,
                                                                                                     "family": 4, "device": "S9", "interface": "Vlan9", "role": None}])),
             ["AUTO_ADDRESS_RECHECK_FAILED"]),
            ("NetBox unavailable", make_sources(netbox=None), ["AUTO_ADDRESS_RECHECK_FAILED"]),
        ]
        for label, sources, expected in rows:
            with self.subTest(case=label):
                before = (models.ChangeValidationRun.objects.count(), models.ChangePlan.objects.count())
                blockers, checked = auto_recheck.recheck_auto_addresses(p.plan, list(p.plan.configlets.all()), sources=sources)
                self.assertEqual([b["code"] for b in blockers], expected)
                self.assertEqual(checked[0]["planned"] if checked else planned, planned)
                self.assertEqual(before, (models.ChangeValidationRun.objects.count(), models.ChangePlan.objects.count()), "read-only: nothing is validated, planned or written")

    def test_a_failed_recheck_blocks_execution_before_the_first_mutation(self):
        p = x.prepared(self.auto_fixture())
        world = x.FakeWorld()
        refusal = [{"code": "AUTO_ADDRESS_RECHECK_FAILED", "message": "m", "remediation": "r"}]
        with mock.patch.object(auto_recheck, "recheck_auto_addresses", return_value=(refusal, [])):
            result = x.run(p, world)
        self.assertEqual((result.outcome, codes(result)), (O.BLOCKED, {"AUTO_ADDRESS_RECHECK_FAILED"}))
        self.assertEqual(world.mutating_calls(), [])
        ok = x.run(p, x.FakeWorld(), confirm="COMPLETE")
        self.assertEqual(ok.outcome, O.SUCCEEDED)
        self.assertEqual(ok.run.report["preparation"]["auto_address_recheck"][0]["planned"], ok.run.report["preparation"]["auto_address_recheck"][0]["current"])
        self.assertIn("AUTO_ADDRESS_NOT_RECORDED_IN_NETBOX", [w["code"] for w in ok.run.report["warnings"]])
