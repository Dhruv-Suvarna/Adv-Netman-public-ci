"""Engineer reconciliation of escalated RSRC monitoring cases: close only on fresh evidence, never because a case is old."""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

from django.test import TestCase

from core import models
from core.services.troubleshooting import faults, intake, reconcile
from core.services.troubleshooting import repository as repo

T0 = datetime(2026, 11, 17, 22, 37, tzinfo=timezone.utc)
FP = "RSRC:R1:ipv4:ospf"


def make_case(*, fingerprint=FP, baseline=8, decision=faults.DIAGNOSE_AND_ESCALATE, state="TESTING", trigger="monitoring"):
    actor = repo.Actor(intake.ACTOR_NAME, "system")
    case = repo.open_case(actor, trigger_source=trigger, trigger_ref=fingerprint, severity="HIGH",
                          idempotency_key=f"t:{fingerprint}:{baseline}:{decision}:{state}",
                          service_intent={"service": "managed-device interface intent", "source": "nmas-intake",
                                          "fault_category": faults.ROUTE_OR_REACHABILITY_FAILURE},
                          affected_scope={"devices": ["R1"], "interfaces": []}, title="t", symptom="t", runbook="RB02", now=T0)
    doc = {"classification": {"evidence": {"baseline_count": baseline, "observed_count": baseline // 2}}}
    repo.store_evidence(actor, case, source_type="deterministic_classification", device="R1", raw=json.dumps(doc), collected_at=T0)
    repo.audit(actor, case, "REMEDIATION_DECISION", decision=f"{decision} x", result=decision, now=T0)
    for nxt in {"TESTING": ("COLLECTING", "ANALYSING", "TESTING"), "OPEN": ()}[state]:
        case = repo.transition_case(actor, case, nxt, reason="t", now=T0)
    return case


class World:
    def __init__(self):
        self.counts = [8, 8]
        self.intent = {"state": "HEALTHY", "pass_id": "RIP-0123456789ab", "error_code": None, "routes": {"evaluated": 22}, "items": []}
        self.flows = {"H1-H2-v4": {"loss_pct": 0.0}, "H1-H2-v6": {"loss_pct": 0.0}}
        self.maintenance = ""
        self.mail = []
        self.slept = []

    def deps(self):
        reads = iter(self.counts)

        def sources(device, cfg):
            c = next(reads)
            return None if c is None else {"ipv4": {"ospf": c, "rip": 8}, "ipv6": {"ospf3": 4}}
        return reconcile.ReconcileDeps(route_sources=sources, route_intent=lambda: self.intent,
                                       flows=lambda: [{"name": n} for n in self.flows], measure=lambda f: dict(self.flows),
                                       maintenance=lambda devices: self.maintenance,
                                       notify=lambda s, b: self.mail.append(s), sleep=self.slept.append,
                                       now=lambda: T0 + timedelta(days=9), confirm_seconds=30)


class ReconcileTests(TestCase):
    def setUp(self):
        self.world = World()

    def run_(self, case, **kw):
        return reconcile.reconcile(case.case_id, deps=self.world.deps(), **kw)

    def test_dry_run_reads_but_writes_nothing(self):
        case = make_case()
        before = (models.TsAuditEvent.objects.filter(case=case).count(), models.TsEvidenceRef.objects.filter(case=case).count())
        v = self.run_(case)
        self.assertEqual(v.outcome, "CLOSE_CLEARED_EXTERNALLY")
        self.assertFalse(v.applied)
        self.assertEqual(self.world.slept, [30])                       # two reads, one confirmation window apart
        case.refresh_from_db()
        self.assertEqual(case.state, "TESTING")
        self.assertEqual(before, (models.TsAuditEvent.objects.filter(case=case).count(),
                                  models.TsEvidenceRef.objects.filter(case=case).count()))
        self.assertEqual(self.world.mail, [])

    def test_cleared_condition_closes_unresolved_cleared_externally_never_resolved_verified(self):
        cause = make_case(fingerprint="LINK:R2:Ethernet1|S4:Ethernet3")
        repo.close_case(repo.Actor("t", "system"), cause, "UNRESOLVED", disposition={"outcome": "x"}, now=T0)
        case = make_case()
        v = self.run_(case, apply=True, cause_case=cause.case_id, note="upstream R2 Ethernet1 admin shutdown")
        self.assertEqual((v.outcome, v.applied, v.closed_state), ("CLOSE_CLEARED_EXTERNALLY", True, "UNRESOLVED"))
        case.refresh_from_db()
        self.assertEqual(case.state, "UNRESOLVED")
        d = case.disposition
        self.assertEqual((d["cleared_externally"], d["nmas_performed_repair"], d["root_cause_status"], d["cause_case"]),
                         (True, False, "EXTERNAL_CAUSE_CORRELATED", cause.case_id))
        self.assertEqual(d["route_source"]["observed"], [8, 8])
        self.assertEqual(d["route_intent_pass_id"], "RIP-0123456789ab")
        self.assertTrue(models.TsAuditEvent.objects.filter(case=case, action="FAULT_CLEARED_VERIFIED", result="VERIFIED").exists())
        self.assertTrue(models.TsEvidenceRef.objects.filter(case=case, source_type="engineer_reconciliation").exists())
        self.assertFalse(repo.verify_audit_chain(case))               # chain intact
        self.assertEqual(len(self.world.mail), 1)

    def test_age_alone_never_closes_a_still_degraded_case(self):
        self.world.counts = [8, 4]                                     # recovered once, collapsed again inside the window
        case = make_case()
        v = self.run_(case, apply=True)
        self.assertEqual(v.outcome, "ESCALATE")
        self.assertIn("CONDITION_PRESENT", v.reasons[0])
        case.refresh_from_db()
        self.assertEqual(case.state, "TESTING")
        self.assertTrue(models.TsAuditEvent.objects.filter(case=case, action="ENGINEER_RECONCILIATION", result="ESCALATE").exists())
        self.assertEqual(len(self.world.mail), 1)

    def test_unreadable_route_source_is_insufficient_evidence(self):
        self.world.counts = [8, None]
        v = self.run_(make_case(), apply=True)
        self.assertEqual(v.outcome, "ESCALATE")
        self.assertIn("INSUFFICIENT_EVIDENCE", v.reasons[0])

    def test_unhealthy_route_intent_or_flow_loss_retains_the_case(self):
        self.world.intent = {**self.world.intent, "state": "DEGRADED",
                             "items": [{"device": "R1", "category": "ROUTE_OR_REACHABILITY_FAILURE"}]}
        self.assertIn("ROUTE_INTENT_NOT_HEALTHY", self.run_(make_case()).reasons[0])
        self.world = World()
        self.world.flows["H1-H2-v4"] = {"loss_pct": 20.0}
        self.assertEqual(self.run_(make_case()).reasons, ["PROTECTED_FLOWS_NOT_VERIFIED"])

    def test_blockers_retain_without_closing(self):
        self.world.maintenance = "MW-1 active"
        case = make_case()
        v = self.run_(case, apply=True)
        self.assertEqual(v.outcome, "RETAIN")
        self.assertIn("MAINTENANCE_ACTIVE (MW-1 active)", v.reasons)
        case.refresh_from_db()
        self.assertEqual(case.state, "TESTING")
        self.assertEqual(self.world.mail, [])

    def test_open_cause_case_blocks_correlated_closure(self):
        cause = make_case(fingerprint="LINK:R2:Ethernet1|S4:Ethernet3")
        v = self.run_(make_case(), cause_case=cause.case_id)
        self.assertEqual(v.outcome, "RETAIN")
        self.assertTrue(any(r.startswith("CAUSE_CASE_STILL_OPEN") for r in v.reasons))

    def test_refuses_non_rsrc_auto_or_terminal_cases(self):
        self.assertEqual(self.run_(make_case(fingerprint="LINK:R2:Ethernet1|S4:Ethernet3")).outcome, "REFUSED")
        self.assertEqual(self.run_(make_case(decision=faults.AUTO_REMEDIATE)).outcome, "REFUSED")
        self.assertEqual(self.run_(make_case(trigger="operator")).outcome, "REFUSED")
        closed = make_case(baseline=6)
        repo.close_case(repo.Actor("t", "system"), closed, "UNRESOLVED", disposition={"outcome": "x"}, now=T0)
        self.assertEqual(self.run_(closed).outcome, "REFUSED")
        self.assertEqual(reconcile.reconcile("TS-NOPE", deps=self.world.deps()).reasons, ["CASE_NOT_FOUND"])

    def test_unbound_route_intent_is_recorded_not_assumed_healthy(self):
        self.world.intent = None
        v = self.run_(make_case())
        self.assertEqual(v.checks["route_intent"], {"state": "NOT_BOUND"})
        self.assertEqual(v.outcome, "CLOSE_CLEARED_EXTERNALLY")
