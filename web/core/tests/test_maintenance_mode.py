"""Maintenance Mode foundation: traffic-aware readiness, the directional drain plan, the fail-closed entry gate, the
lifecycle with its deadline, and what an operator is shown.  Everything is mocked evidence; no device, no database."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from django.test import SimpleTestCase, TestCase

from core import context_processors, models
from core.services.maintenance_mode import gates, lifecycle, model, plan, policy, readiness, store, visibility
from core.services.maintenance_mode.model import ACTIVE, IPV4, IPV6, NORTHBOUND, QUIESCED, SOUTHBOUND, UNKNOWN, Flow

T0 = datetime(2026, 10, 13, 12, 0, tzinfo=timezone.utc)
HOUR = timedelta(hours=1)
CYCLE = timedelta(days=7)
GOOD = gates.Facts(readiness_current=True, probes_healthy=True, probes_lost=0, baseline_fresh=True, out_of_band_change=False, prior_unresolved=())
ALL_READY = {key: model.Mechanism(m.key, m.family, m.direction, m.description, model.READY) for key, m in policy.mechanisms("R1").items()}
ALTERNATES = {(family, direction): True for family in model.FAMILIES for direction in model.DIRECTIONS}


def flows(v6_north=QUIESCED, v6_south=QUIESCED, v4_north=QUIESCED, v4_south=QUIESCED, workload="H1"):
    return [Flow(f"{workload}-v6-n", workload, IPV6, NORTHBOUND, activity=v6_north), Flow(f"{workload}-v6-s", workload, IPV6, SOUTHBOUND, activity=v6_south),
            Flow(f"{workload}-v4-n", workload, IPV4, NORTHBOUND, activity=v4_north), Flow(f"{workload}-v4-s", workload, IPV4, SOUTHBOUND, activity=v4_south)]


def request(device="R1", duration=4 * HOUR):
    return model.Request(device, "operator", "replace a line card", duration, T0)


def codes(findings):
    return [finding.code for finding in findings]


class ReadinessTests(SimpleTestCase):
    def test_active_traffic_with_no_safe_drain_blocks_and_names_the_workload(self):
        report = readiness.evaluate(request("S1"), flows(v6_north=ACTIVE, workload="H1"))
        self.assertFalse(report.ready)
        self.assertEqual([(f.code, f.family, f.direction, f.workloads) for f in report.blockers],
                         [(readiness.NO_LOSSLESS_DRAIN, IPV6, NORTHBOUND, ("H1",))])
        self.assertIn("H1", report.blockers[0].text())

    def test_quiesced_traffic_is_ready_without_any_redundancy(self):
        for device in ("S1", "S2", "R1"):
            report = readiness.evaluate(request(device), flows(), alternates={}, mechanisms={})    # no mechanism, no alternate
            self.assertTrue(report.ready, device)
            self.assertEqual({cell["verdict"] for cell in report.cells.values()}, {readiness.CLEAR})

    def test_unknown_traffic_blocks_and_so_does_an_unclassified_cell(self):
        report = readiness.evaluate(request("S1"), flows(v4_south=UNKNOWN))
        self.assertEqual([(f.code, f.family, f.direction) for f in report.blockers], [(readiness.TRAFFIC_UNKNOWN, IPV4, SOUTHBOUND)])
        missing = readiness.evaluate(request("S1"), [f for f in flows() if f.cell != (IPV6, SOUTHBOUND)])
        self.assertEqual([(f.code, f.family, f.direction) for f in missing.blockers], [(readiness.TRAFFIC_UNKNOWN, IPV6, SOUTHBOUND)])
        self.assertFalse(readiness.evaluate(request("S1"), []).ready)

    def test_s1_and_s2_block_on_an_active_single_homed_workload_in_either_family(self):
        for device in ("S1", "S2"):
            report = readiness.evaluate(request(device), flows(v4_north=ACTIVE, v4_south=ACTIVE, workload="H2"), alternates=ALTERNATES)
            self.assertEqual(set(codes(report.blockers)), {readiness.NO_LOSSLESS_DRAIN})      # a healthy alternate does not help: nothing moves a host
            self.assertEqual({f.workloads for f in report.blockers}, {("H2",)})
            self.assertEqual(policy.mechanisms(device), {})

    def test_the_verdict_is_per_family_and_direction_not_per_device(self):
        report = readiness.evaluate(request("R1"), flows(v6_north=ACTIVE), alternates=ALTERNATES, mechanisms=ALL_READY)
        self.assertTrue(report.ready)
        self.assertEqual(report.cells[(IPV6, NORTHBOUND)]["verdict"], readiness.DRAINABLE)
        self.assertEqual(report.cells[(IPV6, SOUTHBOUND)]["verdict"], readiness.CLEAR)

    def test_an_unhealthy_or_unverified_alternate_blocks_only_where_traffic_must_move(self):
        for health in (False, None):
            report = readiness.evaluate(request("R1"), flows(v6_north=ACTIVE), alternates={(IPV6, NORTHBOUND): health}, mechanisms=ALL_READY)
            self.assertEqual(codes(report.blockers), [readiness.ALTERNATE_UNHEALTHY])
        self.assertTrue(readiness.evaluate(request("R1"), flows(), alternates={}, mechanisms=ALL_READY).ready)

    def test_a_stranded_or_unestablished_critical_dependency_blocks(self):
        for stranded, blocked in ((True, True), (None, True), (False, False)):
            deps = [model.Dependency("VLAN10 gateway", "gateway", stranded=stranded), model.Dependency("lab note", "info", critical=False, stranded=True)]
            report = readiness.evaluate(request("S1"), flows(), deps)
            self.assertEqual(codes(report.blockers), [readiness.DEPENDENCY_STRANDED] if blocked else [])

    def test_non_production_traffic_is_noted_and_never_blocks(self):
        extra = [Flow("mgmt", "nmas-poller", IPV4, NORTHBOUND, model.MANAGEMENT, ACTIVE), Flow("probe", "test", IPV6, SOUTHBOUND, model.TEST, UNKNOWN)]
        report = readiness.evaluate(request("S1"), flows() + extra)
        self.assertTrue(report.ready)
        self.assertEqual(len(report.notes), 2)


class BoundaryRouterTests(SimpleTestCase):
    def test_the_drain_has_a_northbound_isis_and_a_southbound_ospfv3_component(self):
        for device in ("R1", "R2"):
            found = policy.mechanisms(device)
            self.assertEqual((found[(IPV6, NORTHBOUND)].key, found[(IPV6, SOUTHBOUND)].key), (policy.ISIS_NORTHBOUND, policy.OSPFV3_SOUTHBOUND))
            self.assertEqual(found[(IPV4, NORTHBOUND)].state, model.NOT_READY)

    def test_today_neither_direction_is_ready_so_active_ipv6_blocks_in_both(self):
        report = readiness.evaluate(request("R1"), flows(v6_north=ACTIVE, v6_south=ACTIVE), alternates=ALTERNATES)
        self.assertEqual([(f.code, f.direction) for f in report.blockers],
                         [(readiness.MECHANISM_NOT_READY, NORTHBOUND), (readiness.MECHANISM_NOT_READY, SOUTHBOUND)])
        self.assertIn("PROVEN_NOT_AUTHORIZED", report.blockers[0].detail)       # the northbound state is read from route_shield.readiness
        self.assertIn("NOT_READY", report.blockers[1].detail)

    def test_northbound_ready_alone_is_not_enough(self):
        north_only = {**policy.mechanisms("R1"), (IPV6, NORTHBOUND): ALL_READY[(IPV6, NORTHBOUND)]}
        report = readiness.evaluate(request("R1"), flows(v6_north=ACTIVE, v6_south=ACTIVE), alternates=ALTERNATES, mechanisms=north_only)
        self.assertEqual([(f.code, f.direction) for f in report.blockers], [(readiness.MECHANISM_NOT_READY, SOUTHBOUND)])

    def test_ipv4_not_ready_blocks_only_when_active_ipv4_traffic_needs_it(self):
        v6_only = {key: (ALL_READY[key] if key[0] == IPV6 else m) for key, m in policy.mechanisms("R1").items()}
        quiet_v4 = readiness.evaluate(request("R1"), flows(v6_north=ACTIVE, v6_south=ACTIVE), alternates=ALTERNATES, mechanisms=v6_only)
        self.assertTrue(quiet_v4.ready)
        active_v4 = readiness.evaluate(request("R1"), flows(v6_north=ACTIVE, v4_north=ACTIVE), alternates=ALTERNATES, mechanisms=v6_only)
        self.assertEqual([(f.code, f.family, f.direction) for f in active_v4.blockers], [(readiness.MECHANISM_NOT_READY, IPV4, NORTHBOUND)])
        self.assertIn(policy.RIP_IPV4, active_v4.blockers[0].detail)

    def test_active_maintenance_needs_both_directions_proven_with_zero_loss(self):
        report = readiness.evaluate(request("R1"), flows(v6_north=ACTIVE, v6_south=ACTIVE), alternates=ALTERNATES, mechanisms=ALL_READY)
        steps = plan.build(report)
        self.assertEqual([(s.direction, s.mechanism) for s in steps], [(NORTHBOUND, policy.ISIS_NORTHBOUND), (SOUTHBOUND, policy.OSPFV3_SOUTHBOUND)])
        north = model.DrainProof(IPV6, NORTHBOUND, moved=True, probes_lost=0, alternate_healthy=True)
        south = model.DrainProof(IPV6, SOUTHBOUND, moved=True, probes_lost=0, alternate_healthy=True)
        self.assertEqual(plan.proof_findings(steps, [north, south]), [])
        self.assertEqual([(f.code, f.direction) for f in plan.proof_findings(steps, [north])], [(plan.PROOF_MISSING, SOUTHBOUND)])
        for bad, code in ((dict(moved=False), plan.NOT_MOVED), (dict(probes_lost=None), plan.LOSS_EVIDENCE_MISSING),
                          (dict(probes_lost=1), plan.PACKET_LOSS), (dict(alternate_healthy=None), plan.ALTERNATE_UNHEALTHY)):
            proof = model.DrainProof(**{**dict(family=IPV6, direction=SOUTHBOUND, moved=True, probes_lost=0, alternate_healthy=True), **bad})
            self.assertEqual(codes(plan.proof_findings(steps, [north, proof])), [code])

    def test_a_blocked_report_has_no_plan(self):
        with self.assertRaises(model.MaintenanceError) as caught:
            plan.build(readiness.evaluate(request("R1"), flows(v6_north=ACTIVE), alternates=ALTERNATES))
        self.assertEqual(caught.exception.code, "NOT_READY")


class EntryGateTests(SimpleTestCase):
    def ready(self):
        return readiness.evaluate(request("S1"), flows())

    def test_every_gate_refuses_on_its_own_and_missing_evidence_is_a_refusal(self):
        self.assertEqual(gates.entry_findings(self.ready(), GOOD), [])
        cases = {gates.READINESS_STALE: dict(readiness_current=False), gates.PROBES_UNHEALTHY: dict(probes_healthy=None),
                 gates.LOSS_EVIDENCE_MISSING: dict(probes_lost=None), gates.PACKET_LOSS: dict(probes_lost=1),
                 gates.BASELINE_STALE: dict(baseline_fresh=False), gates.OUT_OF_BAND: dict(out_of_band_change=None),
                 gates.PRIOR_UNRESOLVED: dict(prior_unresolved=("R2",))}
        for code, change in cases.items():
            facts = gates.Facts(**{**GOOD.__dict__, **change})
            self.assertEqual(codes(gates.entry_findings(self.ready(), facts)), [code])
        self.assertEqual(codes(gates.entry_findings(self.ready(), gates.Facts(**{**GOOD.__dict__, "out_of_band_change": True}))), [gates.OUT_OF_BAND])
        self.assertEqual(codes(gates.entry_findings(self.ready(), gates.Facts(**{**GOOD.__dict__, "prior_unresolved": None}))), [gates.PRIOR_UNRESOLVED])
        self.assertEqual(len(gates.entry_findings(self.ready(), gates.Facts())), 6)          # the defaults are all failing values

    def test_readiness_blockers_carry_into_the_gate(self):
        blocked = readiness.evaluate(request("S1"), flows(v6_north=UNKNOWN), [model.Dependency("gateway", "gateway", stranded=True)])
        self.assertEqual(codes(gates.entry_findings(blocked, GOOD)), [readiness.TRAFFIC_UNKNOWN, readiness.DEPENDENCY_STRANDED])

    def test_there_is_no_override(self):
        import inspect

        for function in (gates.entry_findings, readiness.evaluate, plan.proof_findings, lifecycle.Record.begin_enter, lifecycle.Record.confirm_active):
            for name in inspect.signature(function).parameters:
                self.assertNotRegex(name, r"force|skip|ignore|override")


class LifecycleTests(SimpleTestCase):
    def approved(self, device="S1", duration=4 * HOUR, **flow_kw):
        record = lifecycle.request(device, "operator", "replace a line card", duration, at=T0)
        record.evaluate(flows(**flow_kw), at=T0, alternates=ALTERNATES, mechanisms=ALL_READY if device.startswith("R") else None)
        record.build_plan(at=T0)
        record.approve("approver", at=T0)
        return record

    def active(self, **kw):
        record = self.approved(**kw)
        record.begin_enter(GOOD, at=T0, actor="operator")
        record.confirm_active([model.DrainProof(s.family, s.direction, True, 0, True) for s in record.steps], at=T0, maintenance_only_state=("isis metric 9999",) if record.steps else ())
        return record

    def test_request_metadata_and_its_limits(self):
        record = lifecycle.request("S1", "operator", "replace a line card", 4 * HOUR, at=T0)
        self.assertEqual((record.state, record.request.operator, record.request.reason, record.request.requested_duration), (lifecycle.REQUESTED, "operator", "replace a line card", 4 * HOUR))
        for bad, code in ((dict(reason=" "), "REQUEST_INCOMPLETE"), (dict(operator=""), "REQUEST_INCOMPLETE"), (dict(requested_duration=timedelta(0)), "DURATION_INVALID"),
                          (dict(device="R5"), None)):
            args = {**dict(device="S1", operator="operator", reason="r", requested_duration=HOUR), **bad}
            if code is None:
                with self.assertRaises(model.MaintenanceError) as caught:
                    lifecycle.request(at=T0, **args).evaluate(flows(), at=T0)
                self.assertEqual(caught.exception.code, "DEVICE_NOT_SUPPORTED")
                continue
            with self.assertRaises(model.MaintenanceError) as caught:
                lifecycle.request(at=T0, **args)
            self.assertEqual(caught.exception.code, code)
        long = lifecycle.request("S2", "operator", "r", timedelta(days=30), at=T0)             # the request is intent, not limited by the cycle
        self.assertEqual(long.request.requested_duration, timedelta(days=30))
        with self.assertRaises(model.MaintenanceError) as caught:
            lifecycle.request("S1", "operator", "again", HOUR, at=T0, existing=[record])
        self.assertEqual(caught.exception.code, "MAINTENANCE_ALREADY_OPEN")

    def test_the_whole_path_to_active_and_a_manual_exit(self):
        record = self.active(device="R1", v6_north=ACTIVE, v6_south=ACTIVE)
        self.assertEqual((record.state, record.entered_at, record.requested_until, record.cycle_deadline), (lifecycle.ACTIVE, T0, T0 + 4 * HOUR, T0 + CYCLE))
        record.request_exit("operator", at=T0 + HOUR)
        self.assertEqual((record.state, record.restore_trigger), (lifecycle.RESTORING, lifecycle.MANUAL_EXIT))
        self.assertEqual(record.finish_restore(at=T0 + HOUR, remaining=()), lifecycle.RESTORED)
        self.assertEqual([h["to"] for h in record.history], [lifecycle.REQUESTED, lifecycle.READY, lifecycle.PLANNED, lifecycle.APPROVED,
                                                             lifecycle.ENTERING, lifecycle.ACTIVE, lifecycle.RESTORING, lifecycle.RESTORED])

    def test_a_blocked_request_cannot_be_planned_approved_or_entered_until_it_is_ready(self):
        record = lifecycle.request("S1", "operator", "r", HOUR, at=T0)
        record.evaluate(flows(v6_north=ACTIVE), at=T0)
        self.assertEqual(record.state, lifecycle.BLOCKED)
        for step in (lambda: record.build_plan(at=T0), lambda: record.approve("approver", at=T0), lambda: record.begin_enter(GOOD, at=T0, actor="operator")):
            with self.assertRaises(model.MaintenanceError):
                step()
        record.evaluate(flows(), at=T0 + HOUR)                                                # the workload was quiesced
        self.assertEqual(record.state, lifecycle.READY)

    def test_a_refused_entry_changes_nothing_and_keeps_the_reasons(self):
        record = self.approved()
        with self.assertRaises(model.MaintenanceError) as caught:
            record.begin_enter(gates.Facts(**{**GOOD.__dict__, "probes_lost": None}), at=T0, actor="operator")
        self.assertEqual((caught.exception.code, record.state, codes(record.findings)), ("ENTRY_REFUSED", lifecycle.APPROVED, [gates.LOSS_EVIDENCE_MISSING]))

    def test_loss_during_the_drain_aborts_the_entry_and_the_device_is_restored(self):
        record = self.approved(device="R1", v6_north=ACTIVE, v6_south=ACTIVE)
        record.begin_enter(GOOD, at=T0, actor="operator")
        proofs = [model.DrainProof(IPV6, NORTHBOUND, True, 0, True), model.DrainProof(IPV6, SOUTHBOUND, True, 2, True)]
        with self.assertRaises(model.MaintenanceError) as caught:
            record.confirm_active(proofs, at=T0, maintenance_only_state=("isis metric 9999",))
        self.assertEqual((caught.exception.code, record.state, record.restore_trigger, record.entered_at), ("ENTRY_ABORTED", lifecycle.RESTORING, lifecycle.ENTRY_ABORT, None))
        self.assertEqual(codes(record.findings), [plan.PACKET_LOSS])
        self.assertEqual(record.finish_restore(at=T0, remaining=()), lifecycle.ABORTED_RESTORED)

    def test_the_deadline_starts_the_restore_and_never_returns_blindly(self):
        record = self.active(device="R1", v6_north=ACTIVE, v6_south=ACTIVE)
        self.assertFalse(record.on_deadline(now=T0 + 4 * HOUR))                               # the requested window ended: nothing exits
        self.assertFalse(record.on_deadline(now=T0 + timedelta(days=6)))
        self.assertEqual(record.state, lifecycle.ACTIVE)
        self.assertFalse(record.on_deadline(now=T0 + CYCLE - timedelta(seconds=1)))
        self.assertTrue(record.on_deadline(now=T0 + CYCLE))                                   # the 7-day safety deadline, counted from entry
        self.assertEqual((record.state, record.restore_trigger), (lifecycle.RESTORING, lifecycle.DEADLINE))
        with self.assertRaises(model.MaintenanceError) as caught:                             # what remains must be stated
            record.finish_restore(at=T0 + CYCLE)
        self.assertEqual(caught.exception.code, "REMAINING_STATE_UNDOCUMENTED")
        unhealthy = [model.Finding("DEVICE_UNHEALTHY", detail="not safe to return to service")]
        self.assertEqual(record.finish_restore(at=T0 + CYCLE, restore_findings=unhealthy, remaining=("isis metric 9999",)), lifecycle.RESTORE_FAILED)
        self.assertEqual((record.escalated, record.baseline_untrusted, record.maintenance_only_state), (True, False, ("isis metric 9999",)))
        record.retry_restore("operator", at=T0 + CYCLE + HOUR)
        self.assertEqual(record.finish_restore(at=T0 + CYCLE + HOUR, remaining=()), lifecycle.RESTORED)
        self.assertTrue(record.escalated)

    def test_an_escalated_restore_blocks_the_device_and_what_intersects_it_not_everything(self):
        escalated = self.active(device="R1", v6_north=ACTIVE, v6_south=ACTIVE)
        escalated.request_exit("operator", at=T0 + HOUR)
        escalated.finish_restore(at=T0 + HOUR, remaining=("isis metric 9999",))
        self.assertEqual(lifecycle.unresolved([escalated], device="R1"), ("R1",))             # the affected device
        self.assertEqual(lifecycle.unresolved([escalated], device="R2"), ("R1",))             # R2's traffic would have to move to R1
        self.assertEqual(lifecycle.unresolved([escalated], device="S1"), ("R1",))             # S1 hangs off R1
        self.assertEqual(lifecycle.unresolved([escalated], device="S2"), ())                  # unrelated: may proceed on its own readiness
        self.assertEqual(lifecycle.unresolved([escalated], device="S2", intersects=("R1",)), ("R1",))   # unless its own analysis intersects
        escalated.retry_restore("operator", at=T0 + 2 * HOUR)
        escalated.finish_restore(at=T0 + 2 * HOUR, remaining=("isis metric 9999",), baseline_untrusted=True)
        self.assertEqual(lifecycle.unresolved([escalated], device="S2"), ("R1",))             # an untrustworthy baseline blocks everyone
        active_elsewhere = self.active(device="S2")
        self.assertEqual(lifecycle.unresolved([active_elsewhere], device="R2"), ())           # an ordinary active maintenance elsewhere is not "unresolved"
        self.assertEqual(lifecycle.unresolved([active_elsewhere], device="S2"), ("S2",))

    def test_a_restore_that_leaves_maintenance_only_state_is_not_restored(self):
        record = self.active(device="R1", v6_north=ACTIVE, v6_south=ACTIVE)
        record.request_exit("operator", at=T0 + HOUR)
        self.assertEqual(record.finish_restore(at=T0 + HOUR, remaining=("isis metric 9999",)), lifecycle.RESTORE_FAILED)

    def test_cancel_only_before_entry(self):
        record = self.approved()
        record.cancel("operator", at=T0)
        self.assertEqual(record.state, lifecycle.CANCELLED)
        with self.assertRaises(model.MaintenanceError):
            self.active().cancel("operator", at=T0)


class VisibilityTests(SimpleTestCase):
    def test_status_shows_who_why_how_long_and_why_it_is_blocked(self):
        record = lifecycle.request("S1", "operator", "replace a line card", 4 * HOUR, at=T0)
        record.evaluate(flows(v6_north=ACTIVE, workload="H1"), at=T0)
        row = visibility.status(record, now=T0)
        self.assertEqual((row["device"], row["state"], row["requested_by"], row["reason"], row["requested_duration_seconds"], row["readiness"], row["under_maintenance"]),
                         ("S1", lifecycle.BLOCKED, "operator", "replace a line card", 14400, "BLOCKED", False))
        self.assertEqual(len(row["block_reasons"]), 1)
        self.assertIn("H1", row["block_reasons"][0])
        self.assertEqual(visibility.device_warning([record], "S1"), "")

    def test_active_and_restore_states_and_the_warning_for_pages_that_change_the_device(self):
        record = LifecycleTests().active(device="R1", v6_north=ACTIVE, v6_south=ACTIVE)
        row = visibility.status(record, now=T0 + 5 * HOUR)
        self.assertEqual((row["state"], row["under_maintenance"], row["requested_until"], row["past_requested_window"], row["cycle_deadline"], row["overdue"], row["approved_by"]),
                         (lifecycle.ACTIVE, True, T0 + 4 * HOUR, True, T0 + CYCLE, False, "approver"))
        self.assertTrue(visibility.status(record, now=T0 + CYCLE)["overdue"])
        warning = visibility.device_warning([record], "R1")
        self.assertIn("R1 is under maintenance (ACTIVE), requested by operator: replace a line card.", warning)
        self.assertEqual(visibility.device_warning([record], "R2"), "")
        self.assertIn(f"Requested until {(T0 + 4 * HOUR).isoformat()}; safety deadline {(T0 + CYCLE).isoformat()}.", warning)
        record.on_deadline(now=T0 + CYCLE)
        record.finish_restore(at=T0 + CYCLE, restore_findings=[model.Finding("X")], remaining=("isis metric 9999",))
        row = visibility.status(record, now=T0 + CYCLE)
        self.assertEqual(row["restore"], {"trigger": lifecycle.DEADLINE, "state": lifecycle.RESTORE_FAILED, "escalated": True, "baseline_untrusted": False, "remaining": ["isis metric 9999"]})
        self.assertIn("escalated", visibility.device_warning([record], "R1"))


class StoreTests(TestCase):
    def test_a_record_survives_the_database_at_every_stage(self):
        record = lifecycle.request("R1", "operator", "replace a line card", 4 * HOUR, at=T0)
        row = store.save(record)
        self.assertEqual((row.record_id, row.state, row.requested_by, row.reason, row.requested_duration_seconds), (f"MNT-{row.pk:06d}", lifecycle.REQUESTED, "operator", "replace a line card", 14400))
        record.evaluate(flows(v6_north=ACTIVE, v6_south=ACTIVE), at=T0, alternates=ALTERNATES)            # blocked: neither direction is ready today
        store.save(record, row)
        self.assertEqual(store.load(models.MaintenanceRecord.objects.get(pk=row.pk)), record)
        record.evaluate(flows(v6_north=ACTIVE, v6_south=ACTIVE), at=T0, alternates=ALTERNATES, mechanisms=ALL_READY)
        record.build_plan(at=T0)
        record.approve("approver", at=T0)
        record.begin_enter(GOOD, at=T0, actor="operator")
        record.confirm_active([model.DrainProof(s.family, s.direction, True, 0, True) for s in record.steps], at=T0, maintenance_only_state=("isis metric 9999",))
        store.save(record, row)
        loaded = store.load(models.MaintenanceRecord.objects.get(pk=row.pk))
        self.assertEqual(loaded, record)
        self.assertEqual((row.deadline_at, loaded.cycle_deadline, loaded.requested_until, models.MaintenanceRecord.objects.count()), (T0 + CYCLE, T0 + CYCLE, T0 + 4 * HOUR, 1))

    def test_only_devices_under_maintenance_produce_a_notice_and_only_on_pages_that_change_devices(self):
        from types import SimpleNamespace

        store.save(lifecycle.request("S1", "operator", "requested only", HOUR, at=T0))
        self.assertEqual(store.notices(T0), [])
        active = LifecycleTests().active(device="R1", v6_north=ACTIVE, v6_south=ACTIVE)
        store.save(active)
        notices = store.notices(T0)
        self.assertEqual([(n["device"], n["state"], n["requested_by"], n["reason"]) for n in notices], [("R1", lifecycle.ACTIVE, "operator", "replace a line card")])
        self.assertIn("R1 is under maintenance (ACTIVE)", notices[0]["warning"])

        def page(view_name):
            return context_processors.maintenance_context(SimpleNamespace(resolver_match=SimpleNamespace(view_name=view_name)))["maintenance_notices"]

        self.assertEqual(len(page("core:device_builder")), 1)
        self.assertEqual(len(page("core:template_library")), 1)
        self.assertEqual(page("core:home"), [])
        self.assertEqual(page("core:monitoring_landing"), [])

    def test_the_deadline_sweep_starts_the_restore_once_and_an_escalation_blocks_new_entries(self):
        row = store.save(LifecycleTests().active(device="R1", v6_north=ACTIVE, v6_south=ACTIVE))
        self.assertEqual(store.start_due_restores(T0 + 5 * HOUR), [])                         # past the requested window: nothing starts
        self.assertEqual(store.prior_unresolved("R2"), ())
        self.assertEqual(store.prior_unresolved("R1"), ("R1",))                               # R1 itself is past entry
        self.assertEqual([r.pk for r in store.start_due_restores(T0 + CYCLE)], [row.pk])
        self.assertEqual(store.start_due_restores(T0 + CYCLE + HOUR), [])                     # already restoring: not started twice
        record = store.load(models.MaintenanceRecord.objects.get(pk=row.pk))
        self.assertEqual((record.state, record.restore_trigger), (lifecycle.RESTORING, lifecycle.DEADLINE))
        record.finish_restore(at=T0 + CYCLE, restore_findings=[model.Finding("RESTORE_NOT_PROVEN")], remaining=("isis metric 9999",))
        store.save(record, models.MaintenanceRecord.objects.get(pk=row.pk))
        self.assertEqual((store.prior_unresolved("R2"), store.prior_unresolved("S2")), (("R1",), ()))   # what intersects R1 is blocked, S2 is not
        self.assertIn("escalated", store.notices(T0 + CYCLE)[0]["warning"])
        record.retry_restore("operator", at=T0 + CYCLE)
        record.finish_restore(at=T0 + CYCLE, remaining=("isis metric 9999",), baseline_untrusted=True)
        store.save(record, models.MaintenanceRecord.objects.get(pk=row.pk))
        self.assertEqual(store.prior_unresolved("S2"), ("R1",))                               # stored and read back: the baseline is untrustworthy
