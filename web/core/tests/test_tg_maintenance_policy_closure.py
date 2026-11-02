"""Lab 7 closure -- Maintenance Mode policy, plan, management-plane protection, model and flow rows, each called directly.

These pure functions decide what a maintenance may touch and what an approver signs.  POSITIVE: the exact role, cells,
mechanisms, steps, plan document, basis and rows for the lab.  NEGATIVE: an unmanaged device, an unproven step, a stale or
expired plan and a flow that does not cross the device never produce a step, an approval or a "proven drain".
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from django.test import SimpleTestCase

from core.services.maintenance_mode import model, plan, policy, protection, readiness
from core.services.maintenance_mode.model import ACTIVE, IPV4, IPV6, NORTHBOUND, SOUTHBOUND
from core.services.route_shield import lab
from core.services.route_shield import readiness as shield_readiness
from core.services.route_shield.migration import ADD, Operation

T0 = datetime(2026, 10, 1, 12, tzinfo=timezone.utc)
CELLS = ((IPV4, NORTHBOUND), (IPV4, SOUTHBOUND), (IPV6, NORTHBOUND), (IPV6, SOUTHBOUND))


class PolicyTests(SimpleTestCase):
    def test_role_intersections_and_cells_of_a_boundary_router(self):
        self.assertEqual(policy.role_of("R1"), policy.BOUNDARY_ROUTER)
        self.assertEqual(policy.role_of("S2"), policy.ACCESS_SWITCH)
        self.assertEqual(policy.intersecting("R1"), ("R2", "S1"))
        self.assertEqual(policy.required_cells("S1"), CELLS)

    def test_policy_lookups_refuse_an_unmanaged_device(self):
        for call in (policy.role_of, policy.intersecting, policy.required_cells):
            with self.subTest(case=f"refused {call.__name__}"), self.assertRaises(model.MaintenanceError) as caught:
                call("R3")
            self.assertEqual(caught.exception.code, "DEVICE_NOT_SUPPORTED")

    def test_mechanisms_for_a_boundary_router_carry_the_steering_states(self):
        states = {shield_readiness.ISIS_METRIC_STEER: model.READY, shield_readiness.OSPFV3_EXTERNAL_METRIC_STEER: model.READY}
        found = policy.mechanisms_for(policy.BOUNDARY_ROUTER, states)
        self.assertEqual(set(found), set(CELLS))
        self.assertEqual((found[(IPV6, NORTHBOUND)].key, found[(IPV6, NORTHBOUND)].state), (policy.ISIS_NORTHBOUND, model.READY))
        self.assertEqual((found[(IPV6, SOUTHBOUND)].key, found[(IPV6, SOUTHBOUND)].state), (policy.OSPFV3_SOUTHBOUND, model.READY))
        self.assertEqual(found[(IPV4, NORTHBOUND)].state, model.NOT_READY)            # RIP has no proven drain

    def test_mechanisms_for_a_switch_are_none_and_unread_states_are_not_ready(self):
        self.assertEqual(policy.mechanisms_for(policy.ACCESS_SWITCH, {}), {})
        unread = policy.mechanisms_for(policy.BOUNDARY_ROUTER, {})
        self.assertEqual({m.state for m in unread.values()}, {model.NOT_READY})


def cell(verdict, mechanism=None, active=()):
    return {"verdict": verdict, "mechanism": mechanism, "active": active}


def report(**verdicts):
    cells = {c: cell(readiness.CLEAR) for c in CELLS}
    cells.update(verdicts.get("cells", {}))
    return model.Report("R1", cells=cells, blockers=list(verdicts.get("blockers", ())))


def proof(family=IPV6, direction=NORTHBOUND, moved=True, lost=0, alternate=True):
    return model.DrainProof(family, direction, moved, lost, alternate)


class PlanStepTests(SimpleTestCase):
    def test_build_orders_drainable_cells_and_skips_clear_ones(self):
        found = plan.build(report(cells={(IPV4, NORTHBOUND): cell(readiness.DRAINABLE, "RIP", ("H2",)),
                                         (IPV6, SOUTHBOUND): cell(readiness.DRAINABLE, "OSPF", ("H1",)),
                                         (IPV6, NORTHBOUND): cell(readiness.DRAINABLE, "ISIS", ("H1",))}))
        self.assertEqual(found, (plan.Step(IPV6, NORTHBOUND, "ISIS", ("H1",)), plan.Step(IPV6, SOUTHBOUND, "OSPF", ("H1",)),
                                 plan.Step(IPV4, NORTHBOUND, "RIP", ("H2",))))

    def test_build_refuses_a_blocked_report(self):
        with self.assertRaises(model.MaintenanceError) as caught:
            plan.build(report(blockers=[model.Finding("X", IPV6, NORTHBOUND)]))
        self.assertEqual((caught.exception.code, str(caught.exception)), ("NOT_READY", "NOT_READY: X IPV6 NORTHBOUND"))

    def test_fully_proven_steps_owe_nothing_further(self):
        steps = (plan.Step(IPV6, NORTHBOUND, "ISIS", ("H1",)), plan.Step(IPV6, SOUTHBOUND, "OSPF", ("H1",)))
        self.assertEqual(plan.proof_findings(steps, [proof(), proof(direction=SOUTHBOUND)]), [])

    def test_proof_findings_name_every_unproven_step(self):
        steps = (plan.Step(IPV6, NORTHBOUND, "ISIS", ("H1",)), plan.Step(IPV6, SOUTHBOUND, "OSPF", ("H1",)))
        found = plan.proof_findings(steps, [model.DrainProof(IPV6, NORTHBOUND, False, None, None, "still via R1")])
        self.assertEqual([f.code for f in found], [plan.NOT_MOVED, plan.LOSS_EVIDENCE_MISSING, plan.ALTERNATE_UNHEALTHY, plan.PROOF_MISSING])
        lossy = plan.proof_findings(steps[:1], [proof(lost=3)])
        self.assertEqual([(f.code, f.detail) for f in lossy], [(plan.PACKET_LOSS, "3 lost")])


OP = Operation("drain-metric", "NORTHBOUND", "S1", "MAINTENANCE", ADD, ("interface Ethernet1", "   isis metric 1000"), ("interface Ethernet1", "   isis metric 10"))


def plan_doc(*, built_at=T0, activity=ACTIVE, ops=(OP,), observation=None):
    req = model.Request("R1", "alice", "line card swap", timedelta(hours=4), T0)
    rep = report(cells={(IPV6, NORTHBOUND): cell(readiness.DRAINABLE, "ISIS", ("H1",))})
    obs = observation if observation is not None else {
        "at": built_at.isoformat(), "digests": {"R1": "d1"}, "protocols": {"isis": "up"}, "intersects": ["R2", "S1"], "access": {"switch": "S1"},
        "dependencies": [{"name": "gateway"}], "flows": [{"label": "f1", "workload": "H1 to WebServer", "family": IPV6, "direction": NORTHBOUND,
                                                           "activity": activity, "on_device": True}]}
    return plan.document(record_id="MNT-000009", request=req, role=policy.BOUNDARY_ROUTER, report=rep, steps=plan.build(rep), observation=obs,
                         state={"uplink_metric": 10}, drain_ops=ops, built_at=built_at, validity=timedelta(minutes=30))


class PlanDocumentTests(SimpleTestCase):
    def test_operation_doc_numbers_the_canonical_operation(self):
        self.assertEqual(plan.operation_doc(OP, 3), {"sequence": 3, **OP.canonical()})

    def test_operation_doc_refuses_a_value_that_is_not_an_operation(self):
        with self.assertRaises(AttributeError):
            plan.operation_doc({"key": "x"}, 1)

    def test_document_carries_target_request_steps_and_drain_operations(self):
        doc = plan_doc()
        self.assertEqual((doc["schema"], doc["record"], doc["target"]), (plan.SCHEMA, "MNT-000009", {"device": "R1", "role": policy.BOUNDARY_ROUTER}))
        self.assertEqual(doc["valid_until"], (T0 + timedelta(minutes=30)).isoformat())
        self.assertEqual(doc["request"], {"operator": "alice", "reason": "line card swap", "requested_duration_seconds": 14400})
        self.assertEqual(doc["readiness"]["steps"], [{"family": IPV6, "direction": NORTHBOUND, "mechanism": "ISIS", "workloads": ["H1"]}])
        self.assertEqual(doc["drain"]["operations"], [{"sequence": 1, **OP.canonical()}])
        self.assertEqual(doc["baseline"]["prestate"], {"uplink_metric": 10})

    def test_document_with_no_observation_invents_no_baseline_or_flows(self):
        doc = plan_doc(observation={})
        self.assertEqual(doc["baseline"], {"observed_at": None, "digests": {}, "protocols": {}, "intersects": [], "access": None, "prestate": {"uplink_metric": 10}})
        self.assertEqual(doc["affected"], {"dependencies": [], "flows": []})
        self.assertEqual((doc["mechanisms"], doc["protected"]), ({}, {}))

    def test_basis_drops_the_clock_the_record_and_momentary_activity(self):
        found = plan.basis(plan_doc())
        self.assertFalse({"built_at", "valid_until", "record", "request"} & set(found))
        self.assertEqual(found["affected"]["flows"], [{"label": "f1", "workload": "H1 to WebServer", "family": IPV6, "direction": NORTHBOUND, "on_device": True}])
        self.assertNotIn("observed_at", found["baseline"])
        self.assertEqual(found["readiness"]["steps"], [{"family": IPV6, "direction": NORTHBOUND, "mechanism": "ISIS"}])

    def test_basis_of_an_empty_document_holds_no_facts(self):
        self.assertEqual(plan.basis({}), {"readiness": {"cells": {}, "steps": []}, "affected": {"flows": []}, "baseline": {}})

    def test_basis_digest_is_equal_for_the_same_facts_built_later(self):
        later = plan_doc(built_at=T0 + timedelta(minutes=5), activity=model.QUIESCED)
        self.assertEqual(plan.basis_digest(plan_doc()), plan.basis_digest(later))
        self.assertRegex(plan.basis_digest(later), r"^[0-9a-f]{64}$")

    def test_basis_digest_and_digest_differ_for_a_tampered_plan(self):
        tampered = plan_doc(ops=())
        self.assertNotEqual(plan.basis_digest(plan_doc()), plan.basis_digest(tampered))
        self.assertNotEqual(plan.digest(plan_doc()), plan.digest(tampered))

    def test_staleness_of_a_current_plan_is_nothing(self):
        self.assertEqual(plan.staleness(plan_doc(), plan_doc(built_at=T0 + timedelta(minutes=1)), now=T0 + timedelta(minutes=10)), [])

    def test_staleness_blocks_a_missing_expired_unbuildable_or_changed_plan(self):
        approved = plan_doc()
        for label, args, now, expected in (
                ("missing approval", (None, approved), T0, [(plan.PLAN_STALE, "no approved plan is stored")]),
                ("expired", (approved, approved), T0 + timedelta(hours=1), [(plan.PLAN_EXPIRED, f"the plan was valid until {approved['valid_until']}; evaluate readiness again")]),
                ("fresh facts unavailable", (approved, None), T0, [(plan.PLAN_STALE, "the plan could not be built again from fresh facts")]),
                ("changed facts", (approved, plan_doc(ops=())), T0, [(plan.PLAN_STALE, "the facts the plan was built from have changed: drain")])):
            with self.subTest(case=f"failure {label}"):
                self.assertEqual([(f.code, f.detail) for f in plan.staleness(*args, now=now)], expected)


class ProtectionTests(SimpleTestCase):
    def test_line_violation_of_production_statements_is_blank(self):
        for line in ("interface Ethernet1", "   isis metric 1000", "switchport trunk allowed vlan 10,20,99", "ip route 0.0.0.0/0 dev eth1"):
            with self.subTest(case=f"production {line}"):
                self.assertEqual(protection.line_violation(line, ("Management0",)), "")

    def test_statement_violation_of_drain_primitives_and_shield_halves_is_blank(self):
        halves = sorted(protection.SHIELD_PREFIXES)
        for line in ("interface Ethernet1", "isis metric 1000", "route-map RM-ISIS-TO-OSPF permit 10", "set metric 10000", "no set metric",
                     f"ipv6 route {halves[0]} 2001:db8:110:3::2", f"no ipv6 route {halves[1]} 2001:db8:110:3::2 250"):
            with self.subTest(case=f"primitive {line}"):
                self.assertEqual(protection.statement_violation(line), "")
        self.assertEqual(len(halves), 2)
        self.assertTrue(all(h.endswith("/33") for h in halves) and lab.AGGREGATE.endswith("/32"))


class ModelTextTests(SimpleTestCase):
    def test_flow_cell_is_its_family_and_direction(self):
        self.assertEqual(model.Flow("f1", "H1 to WebServer", IPV6, SOUTHBOUND).cell, (IPV6, SOUTHBOUND))

    def test_finding_text_names_code_cell_class_workloads_and_detail(self):
        self.assertEqual(model.Finding("CODE", IPV6, NORTHBOUND, model.PRODUCTION, ("H1", "H2"), "why").text(), "CODE IPV6 NORTHBOUND PRODUCTION (H1, H2): why")
        self.assertEqual(model.Finding("CODE").text(), "CODE")


def flow(label="f1", workload="H1 to WebServer", direction=NORTHBOUND, on_device=True):
    return {"label": label, "workload": workload, "family": IPV6, "direction": direction, "activity": ACTIVE, "on_device": on_device}


class FlowRowTests(SimpleTestCase):
    def test_flow_rows_show_a_proven_drain_for_a_healthy_alternate(self):
        rep = report(cells={(IPV6, NORTHBOUND): cell(readiness.DRAINABLE, "ISIS", ("H1",))})
        obs = {"flows": [flow()], "paths": {"f1": {"path": "S1 R1 R3", "complete": True}}, "alternates": {"IPV6/NORTHBOUND": True},
               "mechanisms": {"IPV6/NORTHBOUND": {"key": "ISIS", "state": model.READY}}}
        (row,) = readiness.flow_rows(rep, obs)
        self.assertEqual((row["source"], row["destination"], row["path"], row["path_complete"]), ("H1", "WebServer", "S1 R1 R3", True))
        self.assertEqual((row["redundancy"], row["mechanism"], row["proven_drain"], row["verdict"], row["blocking"]),
                         ("alternate path verified healthy", "ISIS", True, readiness.DRAINABLE, []))

    def test_flow_rows_never_prove_a_drain_without_a_healthy_alternate(self):
        blocker = model.Finding(readiness.ALTERNATE_UNHEALTHY, IPV6, SOUTHBOUND, model.PRODUCTION, ("H1 to WebServer",))
        rep = report(cells={(IPV6, SOUTHBOUND): cell(readiness.BLOCKED)}, blockers=[blocker])
        for label, obs, redundancy, verdict, blocking in (
                ("not through the device", {"flows": [flow(on_device=False)]}, "not needed: the flow does not pass the device", readiness.IRRELEVANT, []),
                ("single homed", {"flows": [flow(direction=SOUTHBOUND, workload="WebServer to H1")], "single_homed": ["H1"]},
                 "none: the host is single-homed to this device", readiness.BLOCKED, []),
                ("unhealthy alternate", {"flows": [flow(direction=SOUTHBOUND, workload="H1 to WebServer")], "alternates": {"IPV6/SOUTHBOUND": False}},
                 "alternate path NOT healthy", readiness.BLOCKED, [blocker.text()]),
                ("unknown alternate", {"flows": [flow()]}, "not established", readiness.CLEAR, [])):
            with self.subTest(case=f"failure {label}"):
                (row,) = readiness.flow_rows(rep, obs)
                self.assertEqual((row["redundancy"], row["verdict"], row["blocking"], row["proven_drain"]), (redundancy, verdict, blocking, False))
        self.assertEqual(readiness.flow_rows(rep, {}), [])
