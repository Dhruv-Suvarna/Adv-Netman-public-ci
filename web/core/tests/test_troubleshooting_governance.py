"""M5 remediation governance + verification (spec 10.6): UT-065 .. UT-080 and fault-injection cases IT-13/14/15/16-style.

Every executor / flow sampler / alternate-path / maintenance source below is an in-test FAKE port.  These tests prove the
governance logic only; none of it is live-device evidence (see docs/troubleshooting/governance.md for what remains external).
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from unittest import mock

from django.test import TestCase

from core import models as m
from core.services.troubleshooting import contracts as c
from core.services.troubleshooting import governance as gov
from core.services.troubleshooting import repository as repo
from core.services.troubleshooting import verification as ver
from core.services.troubleshooting import runtime_ports as rp

T0 = datetime(2026, 11, 9, 12, 0, tzinfo=timezone.utc)
PROPOSER = repo.Actor("alice", "user", tenant="acme")
APPROVER = repo.Actor("bob", "user", tenant="acme")
AGENT = repo.Actor("agent-7", "agent", tenant="acme", tool_id="nmas-mcp")
CATALOG = ["HC01", "HC02", "HC15"]
FLOW = {"key": "tcp/443:web", "protocol": "tcp"}


def make_case(key="k1", actor=PROPOSER, **kw):
    args = dict(trigger_source="alert", idempotency_key=key, service_intent={"service": "web"},
                flow_scope={"protocol": "tcp", "ports": [443]}, severity="HIGH", symptom="web slow",
                affected_scope={"devices": ["r1", "r2"]}, target_states={"r1": "VERIFIED", "r2": "VERIFIED", "r3": "WITHDRAWN"},
                worked_before=True, now=T0)
    args.update(kw)
    case = repo.open_case(actor, **args)
    if case.state == "OPEN":   # a case reaches governance from the deterministic/AI stages, never straight from intake
        repo.transition_case(actor, case, "COLLECTING", now=T0)
        case = repo.transition_case(actor, case, "TESTING", now=T0)
    return case


def evidence(case, device="r1", cmd="show x", raw="Gi1 up", actor=PROPOSER):
    return repo.store_evidence(actor, case, source_type="cli", device=device, command_or_api=cmd, adapter="fake", adapter_version="1",
                               collected_at=T0, raw=raw, operator_url=f"/troubleshooting/evidence/{cmd.replace(' ', '_')}")


def seed_deterministic(case, catalog=CATALOG, actor=PROPOSER):
    """A case whose Stage 1 coverage is complete: observations, golden baseline+URL, correlation, every catalog test recorded."""
    ev = evidence(case)
    repo.record_observation(actor, case, key="interface.oper_state", target="r1", observed_at=T0, value="up", source="fake",
                            evidence=ev, quality="GOOD", basis="OBSERVED")
    repo.record(actor, case, "baseline", evidence_ids=[ev.evidence_id], baseline_type="GOLDEN_CONFIG", subject="r1", revision="rev-9",
                revision_hash="a" * 64, operator_url="/device-builder/bundles/BND-GOLD-9/", link_status="OK", soak_state="PASSED", now=T0)
    repo.record(actor, case, "correlation", evidence_ids=[ev.evidence_id], common_fault_candidate="r1:Gi1", role="CAUSE",
                conclusion="no change in window", now=T0)
    for tid in catalog:
        repo.record_test(actor, case, c.with_schema("test_verdict/1", {
            "test_id": tid, "test_version": "1", "target": "r1", "expected": "ok", "verdict": "PASS", "reason": "",
            "evidence_ids": [ev.evidence_id], "observed_summary": "ok"}), now=T0)
    return ev


class FakeExecutor:
    configured = True

    def __init__(self, *, apply_ok=True, fail_compensation=False, restore=True, supported=True):
        self.state = {"r1": "before"}
        self.apply_ok, self.fail_compensation, self.restore, self.supported = apply_ok, fail_compensation, restore, supported
        self.applied, self.compensated, self.dry = [], [], 0

    def supports(self, op):
        return self.supported

    def dry_run(self, plan):
        self.dry += 1
        return {"ok": True, "errors": []}

    def apply(self, op):
        self.applied.append(op)
        if not self.apply_ok:
            return {"ok": False, "error": "device rejected"}
        self.state["r1"] = "after"
        return {"ok": True, "outcome": "SUCCEEDED"}

    def readback(self, plan):
        return dict(self.state)

    def compensate(self, plan, applied):
        self.compensated.append(applied)
        if self.fail_compensation:
            raise RuntimeError("compensation transport error")
        if self.restore:
            self.state["r1"] = "before"
        return {"ok": True}


def make_ports(executor=None, *, alt=None, maintenance=False, loss=None, preauth=None, require_step_up=False, step_up=None, now=T0):
    """``loss`` is a list consumed one sample at a time (last value repeats) -> {flow: loss_pct}."""
    seq = list(loss if loss is not None else [0.0])

    def sample(flows):
        v = seq.pop(0) if len(seq) > 1 else seq[0]
        return {f["key"]: {"loss_pct": v, "coverage": 1.0} for f in flows}

    return gov.Ports(
        executor=executor or FakeExecutor(),
        device_state=lambda d: {"admission": "VERIFIED", "maintenance": maintenance, "lifecycle": "ACTIVE"},
        alternate_paths=lambda plan, op: alt if alt is not None else {"verified": True, "capacity_ok": True, "lossless_demonstrated": True, "evidence_ids": []},
        flow_sample=sample, preauthorizations=preauth or (lambda op: None), require_step_up=require_step_up, step_up=step_up,
        clock=lambda: now)


def hotfix_op(device="r1", kind="acl_change"):
    return {"kind": kind, "device": device, "change_id": "CHG-1", "summary": "permit tcp/443"}


ROLLBACK = {"steps": ["revert CHG-1 through rollback service", "read back running config", "re-sample production flow"]}


def propose(case, ev, *, actor=PROPOSER, ports=None, ops=None, flows=(FLOW,), fault="acl blocks tcp/443", **kw):
    return gov.propose(actor, case, operations=ops or [hotfix_op()], causal_evidence_ids=[ev.evidence_id], rollback_plan=ROLLBACK,
                       impacted_flows=list(flows), addressed_fault=fault, ports=ports or make_ports(), now=T0, **kw)


def to_precheck(case, ev, ports, **kw):
    plan = propose(case, ev, ports=ports, **kw)
    gov.dry_run(PROPOSER, plan.record_id, ports, now=T0)
    gov.approve(APPROVER, plan.record_id, ports, reason="verified causal evidence", acknowledgements=["I understand this may affect production traffic"], now=T0)
    return gov.precheck(PROPOSER, plan.record_id, ports, now=T0)


class GovernanceBase(TestCase):
    def setUp(self):
        self.case = make_case()
        self.ev = seed_deterministic(self.case)


class TierAndPlanTests(GovernanceBase):
    def test_ut065_tier1_read_only_tier2_needs_approval_tier3_needs_preauth(self):
        self.assertEqual(gov.assess([])["tier"], 1)
        self.assertEqual(gov.assess([hotfix_op()])["tier"], 2)
        # bounce / counter clear are NOT blanket tier 3 even with a (mis)matching preauth: bounce is traffic-affecting
        pre = lambda op: {"id": "PA-1", "devices": ["r1"], "idempotent": True, "expires_at": c.iso(T0 + timedelta(days=1))}  # noqa: E731
        ports = make_ports(preauth=pre)
        self.assertEqual(gov.assess([hotfix_op(kind="interface_bounce")], ports=ports)["tier"], 2)
        self.assertEqual(gov.assess([hotfix_op(kind="counter_clear")], ports=ports)["tier"], 3)
        expired = lambda op: {"id": "PA-1", "devices": ["r1"], "idempotent": True, "expires_at": c.iso(T0 - timedelta(days=1))}  # noqa: E731
        self.assertEqual(gov.assess([hotfix_op(kind="counter_clear")], ports=make_ports(preauth=expired))["tier"], 2)
        plan = propose(self.case, self.ev)
        with self.assertRaises(gov.GovernanceRefused) as cm:   # tier 2 cannot run without approval
            gov.execute(PROPOSER, plan.record_id, make_ports(), idempotency_key="x1", now=T0)
        self.assertEqual(cm.exception.code, "NOT_READY")

    def test_ut065_tier3_preauthorization_applies_only_when_covering(self):
        pre = lambda op: {"id": "PA-1", "devices": ["r1"], "idempotent": True, "expires_at": c.iso(T0 + timedelta(days=1))}  # noqa: E731
        ports = make_ports(preauth=pre)
        plan = gov.propose(PROPOSER, self.case, operations=[hotfix_op(kind="counter_clear")], causal_evidence_ids=[self.ev.evidence_id],
                           rollback_plan=ROLLBACK, addressed_fault="stale counters", ports=ports, now=T0)
        self.assertEqual(plan.tier, 3)
        gov.dry_run(PROPOSER, plan.record_id, ports, now=T0)
        self.assertEqual(gov.preauthorize(PROPOSER, plan.record_id, ports, now=T0).status, "PREAUTHORIZED")
        # an agent-proposed plan is never auto Tier 3
        agent_plan = gov.propose(AGENT, self.case, operations=[hotfix_op(kind="counter_clear")], causal_evidence_ids=[self.ev.evidence_id],
                                 rollback_plan=ROLLBACK, addressed_fault="stale counters", ports=ports, now=T0)
        self.assertEqual(agent_plan.tier, 2)

    def test_ut066_plan_requires_causal_proof_scope_rollback_and_names_fault(self):
        P = dict(operations=[hotfix_op()], rollback_plan=ROLLBACK, addressed_fault="f", ports=make_ports(), now=T0)
        for bad, code in ((dict(causal_evidence_ids=[]), "NO_CAUSAL_EVIDENCE"), (dict(causal_evidence_ids=[self.ev.evidence_id], rollback_plan={}), "NO_ROLLBACK_PLAN"),
                          (dict(causal_evidence_ids=[self.ev.evidence_id], operations=[]), "NO_OPERATIONS"),
                          (dict(causal_evidence_ids=[self.ev.evidence_id], addressed_fault=" "), "FAULT_NOT_IDENTIFIED")):
            with self.assertRaises(gov.GovernanceRefused) as cm:
                gov.propose(PROPOSER, self.case, **{**P, **bad})
            self.assertEqual(cm.exception.code, code)
        with self.assertRaises(ValueError):   # evidence from nowhere
            gov.propose(PROPOSER, self.case, **{**P, "causal_evidence_ids": ["EV-nope"]})
        with self.assertRaises(repo.AccessDenied):   # r9 not in case scope
            gov.propose(PROPOSER, self.case, **{**P, "causal_evidence_ids": [self.ev.evidence_id], "operations": [hotfix_op("r9")]})
        plan = propose(self.case, self.ev)
        self.assertEqual((plan.status, plan.causal_proof, plan.rollback_plan), ("RISK_ASSESSED", [self.ev.evidence_id], ROLLBACK))
        self.assertTrue(plan.blast_radius["traffic_affecting"])
        ports = make_ports()
        self.assertEqual(gov.dry_run(PROPOSER, plan.record_id, ports, now=T0).dry_run["ok"], True)

    def test_ut066_dry_run_failure_or_unsupported_blocks(self):
        ports = make_ports(FakeExecutor(supported=False))
        plan = propose(self.case, self.ev, ports=ports)
        with self.assertRaises(gov.GovernanceRefused):
            gov.dry_run(PROPOSER, plan.record_id, ports, now=T0)
        self.assertEqual(m.TsRemediationPlan.objects.get(pk=plan.pk).status, "BLOCKED")
        unconf = gov.Ports()   # fail-closed default: nothing configured
        plan2 = propose(self.case, self.ev, ports=unconf)
        with self.assertRaises(gov.GovernanceRefused):
            gov.dry_run(PROPOSER, plan2.record_id, unconf, now=T0)

    def test_ut063_approval_rules_agent_self_and_ack(self):
        ports = make_ports()
        plan = propose(self.case, self.ev, actor=AGENT, ports=ports)
        self.assertEqual((plan.basis, plan.tier), ("AI_INFERRED", 2))
        gov.dry_run(PROPOSER, plan.record_id, ports, now=T0)
        ACK = ["I understand this may affect production traffic"]
        with self.assertRaises(gov.GovernanceRefused) as cm:
            gov.approve(AGENT, plan.record_id, ports, reason="approve myself please", acknowledgements=ACK, now=T0)
        self.assertEqual(cm.exception.code, "AGENT_CANNOT_APPROVE")
        plan_b = propose(self.case, self.ev, ports=ports)
        gov.dry_run(PROPOSER, plan_b.record_id, ports, now=T0)
        with self.assertRaises(gov.GovernanceRefused) as cm:
            gov.approve(PROPOSER, plan_b.record_id, ports, reason="approve my own plan", acknowledgements=ACK, now=T0)
        self.assertEqual(cm.exception.code, "SELF_APPROVAL")
        with self.assertRaises(gov.GovernanceRefused) as cm:
            gov.approve(APPROVER, plan_b.record_id, ports, reason="looks good enough", acknowledgements=[], now=T0)
        self.assertEqual(cm.exception.code, "ACK_MISSING")
        with self.assertRaises(gov.GovernanceRefused) as cm:   # step-up required but unavailable => denied, audited
            gov.approve(APPROVER, plan_b.record_id, make_ports(require_step_up=True), reason="looks good enough", acknowledgements=ACK, now=T0)
        self.assertEqual(cm.exception.code, "STEP_UP_REQUIRED")
        denied = [e.action for e in m.TsAuditEvent.objects.filter(case=self.case)]
        self.assertEqual(denied.count("APPROVAL_DENIED"), 3)
        ok = gov.approve(APPROVER, plan_b.record_id, make_ports(require_step_up=True, step_up=lambda a, p: True), reason="looks good enough", acknowledgements=ACK, now=T0)
        self.assertEqual((ok.status, ok.approval["approved_by"]), ("APPROVED", "bob"))

    def test_ut072_hotfix_and_metric_change_need_approval_and_path_impact(self):
        for kind in ("config_hotfix", "routing_metric_change"):
            ports = make_ports()
            plan = propose(self.case, self.ev, ports=ports, ops=[hotfix_op(kind=kind)])
            self.assertEqual(plan.tier, 2)
            with self.assertRaises(gov.GovernanceRefused) as cm:   # precheck refuses an unapproved plan
                gov.precheck(PROPOSER, plan.record_id, ports, now=T0)
            self.assertEqual(cm.exception.code, "NOT_AUTHORIZED")
        ports = make_ports(alt={"verified": False, "capacity_ok": False, "lossless_demonstrated": False, "evidence_ids": []})
        with self.assertRaises(gov.GovernanceRefused) as cm:
            to_precheck(self.case, self.ev, ports, ops=[hotfix_op(kind="routing_metric_change")])
        self.assertIn("NO_VERIFIED_ALTERNATE_PATH", str(cm.exception))


class PreconditionTests(GovernanceBase):
    def test_ut069_maintenance_lifecycle_admission_enforced(self):
        with self.assertRaises(gov.GovernanceRefused) as cm:
            to_precheck(self.case, self.ev, make_ports(maintenance=True))
        self.assertIn("maintenance", str(cm.exception))
        ports = make_ports()
        ports.device_state = lambda d: {"admission": "VERIFIED", "maintenance": False, "lifecycle": "DECOMMISSIONING"}
        case2 = make_case("k2")
        ev2 = seed_deterministic(case2)
        with self.assertRaises(gov.GovernanceRefused) as cm:
            to_precheck(case2, ev2, ports)
        self.assertIn("forbids changes", str(cm.exception))
        ports.device_state = lambda d: {"admission": "UNKNOWN", "maintenance": None, "lifecycle": "UNKNOWN"}
        case3 = make_case("k3", target_states={"r1": "UNVERIFIED", "r2": "VERIFIED"})
        ev3 = seed_deterministic(case3)
        with self.assertRaises(gov.GovernanceRefused) as cm:
            to_precheck(case3, ev3, ports)
        self.assertIn("not VERIFIED", str(cm.exception))
        self.assertIn("UNKNOWN", str(cm.exception))   # unknown maintenance state is never assumed safe

    def test_ut070_traffic_drain_refused_without_safe_alternate_path(self):
        ports = make_ports(alt={"verified": False, "capacity_ok": False, "lossless_demonstrated": False, "evidence_ids": []})
        with self.assertRaises(gov.GovernanceRefused) as cm:
            to_precheck(self.case, self.ev, ports, ops=[hotfix_op(kind="traffic_drain")])
        self.assertIn("NO_VERIFIED_ALTERNATE_PATH", str(cm.exception))
        plan = m.TsRemediationPlan.objects.get(case=self.case, status="BLOCKED")
        self.assertEqual(ports.executor.applied, [])   # nothing touched
        self.assertTrue(any("NO_VERIFIED_ALTERNATE_PATH" in e.rationale for e in m.TsAuditEvent.objects.filter(case=self.case, action="REMEDIATION_STATE")))
        self.assertEqual(plan.alternative_paths[0]["verified"], False)

    def test_ut071_redundancy_used_only_after_capacity_and_losslessness_checks(self):
        # exists but capacity unproven -> refused
        with self.assertRaises(gov.GovernanceRefused):
            to_precheck(self.case, self.ev, make_ports(alt={"verified": True, "capacity_ok": False, "lossless_demonstrated": False, "evidence_ids": []}),
                        ops=[hotfix_op(kind="traffic_drain")])
        # verified + capacity but losslessness NOT demonstrated -> still refused (no zero-loss assertion from topology alone)
        case2 = make_case("k2"); ev2 = seed_deterministic(case2)
        with self.assertRaises(gov.GovernanceRefused) as cm:
            to_precheck(case2, ev2, make_ports(alt={"verified": True, "capacity_ok": True, "lossless_demonstrated": False, "evidence_ids": []}),
                        ops=[hotfix_op(kind="traffic_drain")])
        self.assertIn("losslessness not demonstrated", str(cm.exception))
        case3 = make_case("k3"); ev3 = seed_deterministic(case3)
        plan = to_precheck(case3, ev3, make_ports(), ops=[hotfix_op(kind="traffic_drain")])
        self.assertEqual(plan.status, "PRECHECK_PASS")

    def test_unmeasurable_production_flow_blocks_traffic_affecting_change(self):
        ports = make_ports()
        ports.flow_sample = lambda flows: {f["key"]: {"loss_pct": None, "coverage": 0.0} for f in flows}
        with self.assertRaises(gov.GovernanceRefused) as cm:
            to_precheck(self.case, self.ev, ports)
        self.assertIn("not measurable", str(cm.exception))

    def test_ut068_conflicting_lock_refuses_second_writer(self):
        ports = make_ports()
        plan = to_precheck(self.case, self.ev, ports)
        # another NMAS change run holds r1 (existing Phase-17 lock table)
        change = mock.Mock()
        lock = m.ExecutionDeviceLock(device="r1")
        with mock.patch.object(m.ExecutionDeviceLock.objects, "filter") as f:
            f.return_value.exists.return_value = True
            with self.assertRaises(gov.GovernanceRefused) as cm:
                gov.execute(PROPOSER, plan.record_id, ports, idempotency_key="lk-1", now=T0)
        self.assertEqual(cm.exception.code, "LOCK_CONFLICT")
        self.assertEqual(ports.executor.applied, [])
        # and a second troubleshooting execution on the same device conflicts with an EXECUTING lease
        case2 = make_case("k2"); ev2 = seed_deterministic(case2)
        ports2 = make_ports()
        p2 = to_precheck(case2, ev2, ports2)
        m.TsActionExecution.objects.create(record_id="ACT-held", case=self.case, plan=plan, idempotency_key="held", status="EXECUTING",
                                           command_or_intent={"devices": ["r1"]}, lock_lease="lease:t:" + c.iso(T0 + timedelta(minutes=5)))
        with self.assertRaises(gov.GovernanceRefused) as cm:
            gov.execute(PROPOSER, p2.record_id, ports2, idempotency_key="lk-2", now=T0)
        self.assertEqual(cm.exception.code, "LOCK_CONFLICT")

    def test_rate_limit_bounds_repeat_changes(self):
        ports = make_ports()
        ports.rate_limit = {"window_seconds": 3600, "per_device": 1, "per_case": 5}
        plan = to_precheck(self.case, self.ev, ports)
        gov.execute(PROPOSER, plan.record_id, ports, idempotency_key="r-1", now=T0)
        case2 = make_case("k2"); ev2 = seed_deterministic(case2)
        with self.assertRaises(gov.GovernanceRefused) as cm:
            to_precheck(case2, ev2, ports)
        self.assertIn("RATE_LIMIT", str(cm.exception))


class ExecutionTests(GovernanceBase):
    def test_ut067_idempotency_no_second_write_on_duplicate_or_restart(self):
        ports = make_ports()
        plan = to_precheck(self.case, self.ev, ports)
        first = gov.execute(PROPOSER, plan.record_id, ports, idempotency_key="idem-1", now=T0)
        again = gov.execute(PROPOSER, plan.record_id, ports, idempotency_key="idem-1", now=T0)
        self.assertEqual(first.pk, again.pk)
        self.assertEqual(len(ports.executor.applied), 1)
        with self.assertRaises(gov.GovernanceRefused) as cm:   # a NEW key for an already-executed plan is not a replay
            gov.execute(PROPOSER, plan.record_id, ports, idempotency_key="idem-2", now=T0)
        self.assertEqual(cm.exception.code, "NOT_READY")
        self.assertEqual(len(ports.executor.applied), 1)
        with self.assertRaises(gov.GovernanceRefused):
            gov.execute(PROPOSER, plan.record_id, ports, idempotency_key="", now=T0)

    def test_agent_cannot_execute_even_an_approved_plan(self):
        ports = make_ports()
        plan = to_precheck(self.case, self.ev, ports)
        with self.assertRaises(gov.GovernanceRefused) as cm:
            gov.execute(AGENT, plan.record_id, ports, idempotency_key="ag-1", now=T0)
        self.assertEqual(cm.exception.code, "AGENT_CANNOT_EXECUTE")
        self.assertEqual(ports.executor.applied, [])

    def test_expired_approval_cannot_execute(self):
        ports = make_ports()
        plan = to_precheck(self.case, self.ev, ports)
        late = make_ports(ports.executor, now=T0 + timedelta(hours=5))
        with self.assertRaises(gov.GovernanceRefused) as cm:
            gov.execute(PROPOSER, plan.record_id, late, idempotency_key="exp-1", now=T0 + timedelta(hours=5))
        self.assertEqual(cm.exception.code, "PLAN_EXPIRED")
        self.assertEqual(ports.executor.applied, [])

    def test_ut073_unexpected_production_loss_aborts_and_compensates(self):
        # pre-change 0% -> after op 4% (> +1%) -> compensation; post-compensation traffic sample back at 0%
        ex = FakeExecutor()
        ports = make_ports(ex, loss=[0.0, 0.0, 4.0, 0.0])
        plan = to_precheck(self.case, self.ev, ports, ops=[hotfix_op(), hotfix_op("r2")])
        rec = gov.execute(PROPOSER, plan.record_id, ports, idempotency_key="loss-1", now=T0)
        self.assertEqual(rec.status, "ABORTED_RESTORED")
        self.assertIn("exceeds", rec.stop_reason)
        self.assertEqual(len(ex.applied), 1)   # second op never started: bounded abort
        self.assertEqual(len(ex.compensated), 1)
        self.assertTrue(rec.rollback["verified"])
        self.assertEqual(ver.compute_outcome(m.TsCase.objects.get(pk=self.case.pk))[0], "REMEDIATION_FAILED_RESTORED")

    def test_preexisting_loss_is_not_attributed_to_the_change(self):
        ports = make_ports(loss=[2.0])   # 2% before AND after: no increase
        plan = to_precheck(self.case, self.ev, ports)
        rec = gov.execute(PROPOSER, plan.record_id, ports, idempotency_key="pre-1", now=T0)
        self.assertEqual(rec.status, "APPLIED")
        self.assertEqual(rec.command_or_intent["baseline_flows"][FLOW["key"]]["loss_pct"], 2.0)

    def test_ut075_rollback_verified_by_readback_and_traffic(self):
        ex = FakeExecutor(restore=False)   # compensate returns ok but state did NOT go back
        ports = make_ports(ex, loss=[0.0, 0.0, 5.0, 0.0])   # precheck, pre-change, after op, after compensation
        plan = to_precheck(self.case, self.ev, ports)
        rec = gov.execute(PROPOSER, plan.record_id, ports, idempotency_key="rb-1", now=T0)
        self.assertEqual(rec.status, "ABORTED_UNRESTORED")
        self.assertFalse(rec.rollback["verified"])
        self.assertIn("read-back does not match", " ".join(rec.rollback["notes"]))
        # readback fine but traffic still lossy -> also not restored
        case2 = make_case("k2"); ev2 = seed_deterministic(case2)
        ports2 = make_ports(FakeExecutor(), loss=[0.0, 0.0, 5.0, 5.0])
        p2 = to_precheck(case2, ev2, ports2)
        rec2 = gov.execute(PROPOSER, p2.record_id, ports2, idempotency_key="rb-2", now=T0)
        self.assertEqual(rec2.status, "ABORTED_UNRESTORED")
        self.assertIn("traffic not restored", " ".join(rec2.rollback["notes"]))

    def test_ut076_failed_rollback_reported_unresolved_with_impact(self):
        ex = FakeExecutor(fail_compensation=True)
        ports = make_ports(ex, loss=[0.0, 0.0, 6.0])
        plan = to_precheck(self.case, self.ev, ports)
        rec = gov.execute(PROPOSER, plan.record_id, ports, idempotency_key="fail-1", now=T0)
        self.assertEqual(rec.status, "ABORTED_UNRESTORED")
        case = m.TsCase.objects.get(pk=self.case.pk)
        self.assertEqual(case.state, "UNRESOLVED")
        self.assertEqual(case.disposition["outcome"], "REMEDIATION_FAILED_UNRESTORED")
        self.assertTrue(case.disposition["service_impact_remaining"])
        self.assertEqual(m.TsRemediationPlan.objects.get(pk=plan.pk).status, "ABORTED_UNRESTORED")
        with self.assertRaises(ValueError):   # it can never be closed as resolved afterwards
            repo.close_case(PROPOSER, case, "RESOLVED_VERIFIED", disposition={})

    def test_operation_failure_mid_change_is_compensated(self):
        ex = FakeExecutor(apply_ok=False)
        ports = make_ports(ex)
        plan = to_precheck(self.case, self.ev, ports)
        rec = gov.execute(PROPOSER, plan.record_id, ports, idempotency_key="of-1", now=T0)
        self.assertIn("device rejected", rec.stop_reason)
        self.assertEqual(len(ex.compensated), 1)
        self.assertEqual(rec.status, "ABORTED_RESTORED")

    def test_restart_recovery_marks_interrupted_without_retry(self):
        ex = FakeExecutor()
        ports = make_ports(ex)
        plan = to_precheck(self.case, self.ev, ports)
        # simulate a crash: execution row left EXECUTING with a lease that has since expired
        pre = ex.readback({})
        ex_row = m.TsActionExecution.objects.create(
            record_id="ACT-crash", case=self.case, plan=plan, idempotency_key="crash-1", status="EXECUTING", pre_state=pre,
            command_or_intent={"devices": ["r1"]}, lock_lease="lease:tok:" + c.iso(T0 - timedelta(minutes=1)), executed_at=T0 - timedelta(minutes=11))
        p = m.TsRemediationPlan.objects.get(pk=plan.pk)
        p.status = "EXECUTING"
        p.save()
        later = make_ports(ex, now=T0 + timedelta(minutes=5))
        out = gov.recover(PROPOSER, self.case, later, now=T0 + timedelta(minutes=5))
        self.assertEqual(out[0]["action"], "INTERRUPTED")
        self.assertTrue(out[0]["readback_matches_pre_state"])
        self.assertEqual(m.TsActionExecution.objects.get(pk=ex_row.pk).status, "INTERRUPTED")
        self.assertEqual(m.TsRemediationPlan.objects.get(pk=plan.pk).status, "BLOCKED")
        self.assertEqual(ex.applied, [])   # nothing re-applied
        # same key on retry returns the interrupted record, never re-executes
        again = gov.execute(PROPOSER, plan.record_id, later, idempotency_key="crash-1", now=T0 + timedelta(minutes=6))
        self.assertEqual(again.status, "INTERRUPTED")
        self.assertEqual(ex.applied, [])
        # a live (unexpired) lease is left alone
        m.TsActionExecution.objects.create(record_id="ACT-live", case=self.case, plan=plan, idempotency_key="live", status="EXECUTING",
                                           lock_lease="lease:tok:" + c.iso(T0 + timedelta(minutes=30)))
        self.assertEqual(gov.recover(PROPOSER, self.case, later, now=T0 + timedelta(minutes=5))[0]["action"], "LEASE_STILL_HELD")


class VerificationTests(GovernanceBase):
    def _applied(self, ports=None, **kw):
        ports = ports or make_ports()
        plan = to_precheck(self.case, self.ev, ports, **kw)
        gov.execute(PROPOSER, plan.record_id, ports, idempotency_key="v-1", now=T0)
        return plan, ports

    def test_ut074_config_success_but_failed_service_check_is_not_resolved(self):
        plan, ports = self._applied()
        rec = ver.verify(PROPOSER, plan.record_id, ports, service_checks=lambda: [
            {"name": "tcp443 transaction", "passed": False, "observed": "timeout", "evidence_ids": [self.ev.evidence_id]}], now=T0)
        self.assertEqual(rec.outcome, "FAILED")
        case = m.TsCase.objects.get(pk=self.case.pk)
        with self.assertRaises(ValueError):
            repo.close_case(PROPOSER, case, "RESOLVED_VERIFIED", disposition={})
        self.assertEqual(ver.compute_outcome(case)[0], "INCONCLUSIVE_ESCALATED")
        ver.abort_failed_verification(PROPOSER, plan.record_id, ports, now=T0)
        self.assertEqual(m.TsCase.objects.get(pk=self.case.pk).state, "UNRESOLVED")

    def test_unmeasured_check_counts_as_failed(self):
        plan, ports = self._applied()
        rec = ver.verify(PROPOSER, plan.record_id, ports, service_checks=lambda: [{"name": "t", "passed": None, "observed": "no data"}], now=T0)
        self.assertEqual(rec.outcome, "FAILED")

    def test_regression_on_surrounding_flow_fails_verification(self):
        plan, ports = self._applied(make_ports(loss=[0.0, 0.0, 0.0, 3.0]))
        rec = ver.verify(PROPOSER, plan.record_id, ports, service_checks=lambda: [{"name": "t", "passed": True, "observed": "ok", "evidence_ids": [self.ev.evidence_id]}],
                         surrounding_flows=[{"key": "udp/53:dns"}], now=T0)
        self.assertEqual(rec.outcome, "FAILED")
        self.assertTrue(rec.regressions)

    def test_ut077_soak_prevents_premature_success_then_completes(self):
        plan, ports = self._applied()
        rp.tick(PROPOSER, plan.record_id, ports.flow_sample, now=T0 + timedelta(minutes=1))
        checks = lambda: [{"name": "tcp443 transaction", "passed": True, "observed": "20/20", "evidence_ids": [self.ev.evidence_id]}]  # noqa: E731
        rec = ver.verify(PROPOSER, plan.record_id, ports, service_checks=checks, soak_window=timedelta(minutes=30), now=T0 + timedelta(minutes=1))
        self.assertEqual((rec.outcome, rec.soak_status), ("SOAKING", "RUNNING"))
        case = m.TsCase.objects.get(pk=self.case.pk)
        with self.assertRaises(ValueError):
            repo.close_case(PROPOSER, case, "RESOLVED_VERIFIED", disposition={})
        self.assertEqual(ver.compute_outcome(case)[0], "ROOT_CAUSE_IDENTIFIED_REMEDIATION_PENDING")
        self.assertEqual(m.TsRemediationPlan.objects.get(pk=plan.pk).status, "SOAKING")
        # degradation inside the window -> FAILED, not resolved
        bad = make_ports(ports.executor, loss=[9.0], now=T0 + timedelta(minutes=10))
        rp.tick(PROPOSER, plan.record_id, bad.flow_sample, now=T0 + timedelta(minutes=10))
        degraded = ver.verify(PROPOSER, plan.record_id, bad, service_checks=checks, soak_window=timedelta(minutes=30), now=T0 + timedelta(minutes=10))
        self.assertEqual(degraded.outcome, "FAILED")
        # Recovery cannot erase degradation: an operator restarts the window,
        # then persisted minute-by-minute samples prove a full clean soak.
        rp.reset_window(APPROVER, plan.record_id, reason="service recovered; restart monitored soak", now=T0 + timedelta(minutes=10))
        good = make_ports(ports.executor, now=T0 + timedelta(minutes=40))
        for minute in range(10, 41):
            rp.tick(PROPOSER, plan.record_id, good.flow_sample, now=T0 + timedelta(minutes=minute))
        done = ver.verify(PROPOSER, plan.record_id, good, service_checks=checks, soak_window=timedelta(minutes=30), now=T0 + timedelta(minutes=40))
        self.assertEqual(done.outcome, "VERIFIED")
        final = ver.finalize(PROPOSER, self.case, now=T0 + timedelta(minutes=41))
        self.assertEqual((final["outcome"], final["closed"]), ("RESOLVED_VERIFIED", True))
        self.assertEqual(m.TsCase.objects.get(pk=self.case.pk).state, "RESOLVED_VERIFIED")

    def test_ut074_empty_or_unsubstantiated_checks_cannot_resolve(self):
        plan, ports = self._applied_case(self.case, self.ev)
        for checks in ([], [{"name": "unsupported success", "passed": True, "observed": "ok"}]):
            rec = ver.verify(PROPOSER, plan.record_id, ports, service_checks=lambda: checks,
                             soak_window=timedelta(0), now=T0)
            self.assertEqual(rec.outcome, "FAILED")
            self.assertNotEqual(gov.get_plan(PROPOSER, plan.record_id).status, "RESOLVED")

    def test_ut074_missing_postchange_flow_cannot_resolve(self):
        plan, ports = self._applied_case(self.case, self.ev)
        ports.flow_sample = lambda flows: {}
        rec = ver.verify(PROPOSER, plan.record_id, ports, service_checks=lambda: [
            {"name": "transaction", "passed": True, "observed": "ok", "evidence_ids": [self.ev.evidence_id]}],
            soak_window=timedelta(0), now=T0)
        self.assertEqual(rec.outcome, "FAILED")
        self.assertTrue(any("missing post-change" in r for r in rec.regressions))

    def test_ut079_disposition_matches_facts(self):
        case = m.TsCase.objects.get(pk=self.case.pk)
        self.assertEqual(ver.compute_outcome(case)[0], "INCONCLUSIVE_ESCALATED")   # nothing confirmed, nothing fixed
        repo.record(PROPOSER, case, "hypothesis", evidence_ids=[self.ev.evidence_id], title="acl", state="CONFIRMED",
                    supporting_evidence=[self.ev.evidence_id], now=T0)
        self.assertEqual(ver.compute_outcome(case)[0], "ROOT_CAUSE_IDENTIFIED_REMEDIATION_PENDING")
        self.assertEqual(set(ver.OUTCOMES), {"RESOLVED_VERIFIED", "ROOT_CAUSE_IDENTIFIED_REMEDIATION_PENDING", "EXPECTED_BEHAVIOR_CONFIRMED",
                                             "INCONCLUSIVE_ESCALATED", "EXTERNAL_PREREQUISITE_BLOCKED", "REMEDIATION_FAILED_RESTORED",
                                             "REMEDIATION_FAILED_UNRESTORED"})

    def test_ut088_metrics_exclude_unresolved_from_mttr(self):
        c1 = make_case("m1", first_detected_at=T0 - timedelta(minutes=10))
        c2 = make_case("m2", first_detected_at=T0 - timedelta(minutes=20))
        ev = seed_deterministic(c1)
        plan, ports = self._applied_case(c1, ev)
        for minute in range(31):
            rp.tick(PROPOSER, plan.record_id, ports.flow_sample, now=T0 + timedelta(minutes=minute))
        ver.verify(PROPOSER, plan.record_id, ports, service_checks=lambda: [{"name": "t", "passed": True, "observed": "ok", "evidence_ids": [ev.evidence_id]}],
                   soak_window=timedelta(minutes=30), now=T0 + timedelta(minutes=30))
        ver.finalize(PROPOSER, c1, now=T0 + timedelta(minutes=30))
        met = ver.metrics(PROPOSER, now=T0 + timedelta(hours=1))
        self.assertEqual(met["mttr_sample"], 1)
        self.assertAlmostEqual(met["mttr_seconds"], 40 * 60, delta=1)   # first_detected -> closed
        self.assertGreaterEqual(met["censored_unresolved_or_open"], 2)   # c2 + setUp case never counted as resolved
        self.assertEqual(met["outcomes"].get("RESOLVED_VERIFIED"), 1)

    def _applied_case(self, case, ev):
        ports = make_ports()
        plan = to_precheck(case, ev, ports)
        gov.execute(PROPOSER, plan.record_id, ports, idempotency_key=f"v-{case.case_id}", now=T0)
        return plan, ports


class DeviationAndAuditTests(GovernanceBase):
    def test_ut078_expected_icmp_deviation_cannot_trigger_remediation(self):
        repo.record(PROPOSER, self.case, "exception", basis="OPERATOR_CONFIRMED", scope={"protocol": "icmp", "src": "h1", "dst": "web"},
                    reason="icmp denied by approved change", expires_at=T0 + timedelta(days=3), bound_revisions={}, status="ACTIVE", now=T0)
        repo.record(PROPOSER, self.case, "flow_monitor", evidence_ids=[self.ev.evidence_id], selector={"protocol": "tcp", "ports": [443]},
                    classification="PRODUCTION", current_loss_pct=0.0, now=T0)
        with self.assertRaises(gov.GovernanceRefused) as cm:
            propose(self.case, self.ev, fault="icmp echo to web is denied")
        self.assertEqual(cm.exception.code, "EXPECTED_DEVIATION_NO_PRODUCTION_IMPACT")

    def test_ut034_078_real_production_loss_is_never_masked_by_exception(self):
        repo.record(PROPOSER, self.case, "exception", basis="OPERATOR_CONFIRMED", scope={"protocol": "icmp", "src": "h1", "dst": "web"},
                    reason="icmp denied by approved change", expires_at=T0 + timedelta(days=3), bound_revisions={}, status="ACTIVE", now=T0)
        repo.record(PROPOSER, self.case, "flow_monitor", evidence_ids=[self.ev.evidence_id], selector={"protocol": "tcp", "ports": [443]},
                    classification="PRODUCTION", current_loss_pct=7.5, now=T0)
        plan = propose(self.case, self.ev, fault="icmp echo to web is denied and tcp loss")
        self.assertEqual(plan.status, "RISK_ASSESSED")

    def test_ut080_audit_records_risk_approver_operation_tool_time_result_rationale(self):
        ports = make_ports()
        plan = to_precheck(self.case, self.ev, ports)
        gov.execute(PROPOSER, plan.record_id, ports, idempotency_key="aud-1", now=T0)
        events = {e.action: e for e in m.TsAuditEvent.objects.filter(case=self.case)}
        for action in ("REMEDIATION_STATE", "APPROVAL_GRANTED", "ACTION_STARTED", "ACTION_APPLIED"):
            self.assertIn(action, events)
        g = events["APPROVAL_GRANTED"]
        self.assertEqual((g.approver, g.risk, g.operation, g.result, g.occurred_at, g.rationale), ("bob", "HIGH", plan.record_id, "APPROVED", T0, "verified causal evidence"))
        self.assertEqual(events["ACTION_STARTED"].actor, "alice")
        self.assertEqual(repo.verify_audit_chain(self.case), [])
        with self.assertRaises(ValueError):   # append-only: history cannot be edited
            e = m.TsAuditEvent.objects.filter(case=self.case).first()
            e.result = "tampered"
            e.save()

    def test_secrets_in_plan_and_dry_run_are_redacted(self):
        ports = make_ports()
        ports.executor.dry_run = lambda plan: {"ok": True, "errors": [], "mode": "enable secret 5 $1$abc$HASH"}
        plan = propose(self.case, self.ev, ports=ports)
        out = gov.dry_run(PROPOSER, plan.record_id, ports, now=T0)
        self.assertNotIn("$1$abc$HASH", c.canonical_json(out.dry_run))

    def test_cross_tenant_plan_access_denied(self):
        plan = propose(self.case, self.ev)
        other = repo.Actor("mallory", "user", tenant="other")
        with self.assertRaises(repo.AccessDenied):
            gov.get_plan(other, plan.record_id)
        scoped = repo.Actor("carol", "user", tenant="acme", devices=frozenset({"r2"}))
        with self.assertRaises(repo.AccessDenied):
            gov.get_plan(scoped, plan.record_id)   # plan touches r1


class AvailabilityTests(GovernanceBase):
    def test_ut089_actions_enabled_only_when_supported_approved_and_safe(self):
        plan = propose(self.case, self.ev)
        unconf = gov.Ports()
        av = gov.action_availability(plan, can_approve=True, ports=unconf, now=T0)
        self.assertEqual([k for k, v in av.items() if v["enabled"]], ["reject"])   # no executor => no write-path action; rejecting is harmless
        self.assertTrue(all(v["reason"] for k, v in av.items() if k != "reject"))
        ports = make_ports()
        av = gov.action_availability(plan, can_approve=False, ports=ports, now=T0)
        self.assertTrue(av["dry_run"]["enabled"])
        self.assertFalse(av["approve"]["enabled"])
        self.assertFalse(av["execute"]["enabled"])
        late = gov.action_availability(plan, can_approve=True, ports=ports, now=T0 + timedelta(days=1))
        self.assertFalse(late["dry_run"]["enabled"])   # expired plan
        case2 = make_case("k9")
        ready = to_precheck(case2, evidence(case2), ports)
        av = gov.action_availability(ready, can_approve=True, ports=ports, now=T0)
        self.assertEqual([k for k, v in av.items() if v["enabled"]], ["execute"])


class ChangeEngineExecutorTests(TestCase):
    def test_executor_delegates_to_existing_gate_and_refuses_when_ineligible(self):
        change = mock.Mock(execution_mode="LIVE")
        ex = gov.ChangeEngineExecutor(lambda cid: change if cid == "CHG-1" else None)
        self.assertTrue(ex.references_change({"change_id": "CHG-1"}))
        self.assertFalse(ex.references_change({"change_id": "CHG-X"}))
        self.assertFalse(ex.references_change({}))
        report = mock.Mock(eligible=False, codes=["VALIDATION_STALE"])
        with mock.patch("core.services.execution.eligibility.check_execution_eligibility", return_value=report) as gate:
            out = ex.dry_run({"operations": [{"change_id": "CHG-1"}]})
        gate.assert_called_once()
        self.assertFalse(out["ok"])
        self.assertIn("VALIDATION_STALE", out["errors"][0])
        with self.assertRaises(gov.GovernanceRefused):   # no read-back/rollback runner wired => refuses, never guesses
            ex.readback({})
        with self.assertRaises(gov.GovernanceRefused):
            ex.compensate({}, [])

    def test_execution_is_a_hand_off_to_the_change_page_never_a_second_engine_caller(self):
        """The public change engine has exactly one caller (test_contracts): troubleshooting never executes a Change itself."""
        change = mock.Mock(execution_mode="LIVE")
        ex = gov.ChangeEngineExecutor(lambda cid: change)
        self.assertFalse(ex.supports({"change_id": "CHG-1", "device": "r1"}))
        with mock.patch("core.services.execution.engine.execute_change") as run:
            with self.assertRaises(gov.GovernanceRefused) as refused:
                ex.apply({"change_id": "CHG-1", "device": "r1"})
        run.assert_not_called()
        self.assertEqual(refused.exception.code, "EXECUTION_VIA_CHANGE_WORKFLOW")
        # even with writes enabled, the guarded production binding supports nothing, so execute stays disabled with the reason
        from core.services.troubleshooting import runtime_ports as rp
        guarded = rp.WriteGuardedExecutor(ex, writes_enabled=True)
        self.assertFalse(guarded.supports({"change_id": "CHG-1", "device": "r1"}))
        self.assertIn("Change page", guarded.unsupported_reason)
        self.assertIn("writes are disabled", rp.WriteGuardedExecutor(ex).unsupported_reason)
