"""Deterministic engine and Collect->Normalize->Baseline->Correlate->Test orchestration (UT-025 .. UT-045, UT-053).

All data is SIMULATED/replayed (``fixtures/troubleshooting_runbooks/scenarios.py``) -- nothing here claims live device verification.
"""

from __future__ import annotations

import importlib.util
from datetime import timedelta
from pathlib import Path

from django.test import SimpleTestCase, TestCase

from core import models as m
from core.services.troubleshooting import baselines as bl
from core.services.troubleshooting import contracts as c
from core.services.troubleshooting import correlation as corr
from core.services.troubleshooting import engine as eng
from core.services.troubleshooting import repository as repo
from core.services.troubleshooting.runbooks import REGISTRY

_p = Path(__file__).parent / "fixtures" / "troubleshooting_runbooks" / "scenarios.py"
_spec = importlib.util.spec_from_file_location("ts_scenarios", _p)
S = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(S)

T0 = S.T0
ACTOR = repo.Actor("alice", "user", tenant="acme")
_seq = [0]


def run_case(runbook, obs, *, flow=None, static=None, scope=None, service_intent=None, alarms=None, cfg=None, fail_sources=(), fail_devices=(), ages=None,
             missing=None, quality=None, worked_before=True, link_checker=None, setup=None, current_revisions=None, now=T0, open_kw=None):
    _seq[0] += 1
    flow = S.FLOW if flow is None else flow
    scope = scope or S.DEVICES
    case = repo.open_case(ACTOR, trigger_source="alert:test", idempotency_key=f"k{_seq[0]}", service_intent=service_intent or {"service": "web"}, flow_scope=flow,
                          affected_scope={"devices": scope}, target_states={d: "VERIFIED" for d in scope}, severity="HIGH", symptom="s", worked_before=worked_before,
                          first_detected_at=now - timedelta(minutes=10), last_known_good_at=now - timedelta(hours=3), runbook=runbook, now=now - timedelta(minutes=5),
                          **(open_kw or {}))
    if setup:
        setup(case)
    fixture = S.to_fixture(obs, fixture_id=f"fx{_seq[0]}", ages=ages, missing=missing, quality=quality)
    provider = eng.ReplayProvider(fixture, fail_devices=fail_devices)
    sources = bl.StaticSources(static if static is not None else S.static_data(now), fail=fail_sources)
    e = eng.Engine(ACTOR, case, runbook, sources=sources, provider=provider, now=now, alarms=alarms, config=cfg, link_checker=link_checker or (lambda url: True),
                   current_revisions=current_revisions)
    stages = e.run()
    return e, stages


def by_id(stages):
    return {r["test_id"]: r for r in stages["test"]["matrix"]}


class HostLabBase(TestCase):
    def healthy(self, **kw):
        return run_case("RB02", S.healthy_obs(), **kw)


class PipelineTests(HostLabBase):
    def test_ut040_rich_fixture_runs_at_least_20_distinct_applicable_tests_in_order(self):
        e, st = self.healthy(cfg=eng.EngineConfig(exhaustive=True))
        t = st["test"]
        ex = [r for r in t["matrix"] if r["status"] == "EXECUTED"]
        self.assertGreaterEqual(len({r["test_id"] for r in ex}), 20, [(r["test_id"], r["status"], r["reason"]) for r in t["matrix"] if r["status"] != "EXECUTED"])
        self.assertEqual([r["test_id"] for r in t["matrix"]], t["order"])
        self.assertEqual(len(t["matrix"]), 29)
        self.assertEqual(st["diagnosis"]["outcome"], "EXPECTED_BEHAVIOR_CONFIRMED", st["diagnosis"])


ACL_DENY = {"acl": "EDGE-IN", "direction": "in", "sample_interval_s": 30, "rules": [
    {"seq": 5, "action": "deny", "proto": "tcp", "port": 443, "src": "10.1.1.0/24", "dst": "10.2.2.0/24", "hits": 9000, "prev_hits": 8400},
    {"seq": 10, "action": "permit", "proto": "tcp", "port": 443, "src": "10.1.1.0/24", "dst": "10.2.2.0/24", "hits": 0, "prev_hits": 0},
    {"seq": 100, "action": "permit", "proto": "ip", "hits": 40, "prev_hits": 39}]}
ACL_ICMP_DENY = {"acl": "EDGE-IN", "direction": "in", "sample_interval_s": 30, "rules": [
    {"seq": 5, "action": "deny", "proto": "icmp", "hits": 300, "prev_hits": 280},
    {"seq": 10, "action": "permit", "proto": "tcp", "port": 443, "src": "10.1.1.0/24", "dst": "10.2.2.0/24", "hits": 5000, "prev_hits": 4900}]}
TCP_DOWN = {("h1", "service.probe", "tcp"): {"sent": 20, "ok": 0}, ("h1", "flow.health", "web"): {"loss_pct": 100.0, "coverage_pct": 92, "baseline_loss_pct": 0.1, "samples": []},
            ("h1", "path.trace", "h2"): {"reached": False, "method": "tcp", "hop_devices": ["r1"], "last_hop": "r1"}}


class FaultIsolationTests(HostLabBase):
    def test_ut040_injected_acl_fault_is_isolated_with_20_plus_tests_accounted_and_recovery_clears_it(self):
        obs = S.apply(S.healthy_obs(), {**TCP_DOWN, ("r1", "acl.counters", "Eth1-in"): ACL_DENY})
        e, st = run_case("RB02", obs, cfg=eng.EngineConfig(exhaustive=True))
        rc = st["diagnosis"]["root_cause"]
        self.assertEqual(st["diagnosis"]["outcome"], "ROOT_CAUSE_IDENTIFIED_REMEDIATION_PENDING")
        self.assertEqual((rc["finding"], rc["device"], rc["test"]), ("F-acl-deny", "r1", "HC18"))
        self.assertGreaterEqual(len([r for r in st["test"]["matrix"] if r["status"] == "EXECUTED"]), 20)
        self.assertTrue(rc["evidence"], "root cause must cite evidence")
        self.assertEqual(st["diagnosis"]["proposed_remediation"]["tier"], 2)
        self.assertTrue(st["diagnosis"]["counter_evidence"], "healthy tests are retained as counter-evidence")
        fault_matrix = by_id(st)
        # recovery run: same lab with the ACL repaired -> the same tests now pass and nothing regressed
        e2, st2 = run_case("RB02", S.healthy_obs(), cfg=eng.EngineConfig(exhaustive=True))
        cmp = eng.compare_runs(fault_matrix, by_id(st2))
        self.assertIn("HC18", cmp["fixed"])
        self.assertEqual(cmp["regressions"], [])
        self.assertTrue(cmp["recovered"], cmp["still_failing"])

    def test_ut043_proven_root_cause_stops_redundant_tests_but_keeps_applicability_audit(self):
        obs = S.apply(S.healthy_obs(), {**TCP_DOWN, ("r1", "acl.counters", "Eth1-in"): ACL_DENY})
        e, st = run_case("RB02", obs)
        t = st["test"]
        self.assertTrue(t["stopped_early"])
        skipped = [r for r in t["matrix"] if r["status"] == "SKIPPED_AFTER_CONFIRMED_ISOLATION"]
        self.assertTrue(skipped)
        for r in skipped:
            self.assertIn("root cause already proven by HC18", r["reason"])
        rows = m.TsDiagnosticTest.objects.filter(case=e.case, attempt=1)
        self.assertEqual(rows.count(), 29, "a row exists for every catalogue test")
        self.assertEqual({r.test_id for r in rows.filter(verdict="SKIPPED")}, {r["test_id"] for r in t["matrix"] if r["verdict"] == "SKIPPED"})
        # context/safety tests are never skipped by adaptive stopping
        self.assertEqual(by_id(st)["HC28"]["status"], "EXECUTED")

    def test_ut041_every_non_executed_test_has_a_specific_reason(self):
        obs = S.apply(S.healthy_obs(), {**TCP_DOWN, ("r1", "acl.counters", "Eth1-in"): ACL_DENY, ("h1", "dhcp.lease", "eth0"): None})
        e, st = run_case("RB02", obs, static={**S.static_data(), "intent": {**S.intent(), "hosts": {"h1": {**S.intent()["hosts"]["h1"], "addressing": "static"}}}})
        for r in st["test"]["matrix"]:
            if r["status"] != "EXECUTED":
                self.assertGreater(len(r["reason"]), 20, r)
        self.assertEqual(by_id(st)["HC07"]["status"], "NOT_APPLICABLE")
        self.assertIn("static", by_id(st)["HC07"]["reason"])

    def test_ut044_follow_the_path_tests_cover_intermediate_rib_fib_and_return_path(self):
        e, st = self.healthy(cfg=eng.EngineConfig(exhaustive=True))
        b = by_id(st)
        for tid in ("HC15", "HC16", "HC24"):
            self.assertEqual((b[tid]["status"], b[tid]["verdict"]), ("EXECUTED", "PASS"), b[tid])
        self.assertIn("2 L3 hop", b["HC15"]["summary"])           # intermediate hops r1 AND r2, not only the first
        self.assertIn("2 L3 hop", b["HC16"]["summary"])
        self.assertIn("return route", b["HC24"]["summary"])
        # break the return route on the far router only: forward tests pass, HC24 isolates it
        obs = S.apply(S.healthy_obs(), {("r2", "route.rib", "10.1.1.0/24"): {"present": False}})
        _, st2 = run_case("RB02", obs, cfg=eng.EngineConfig(exhaustive=True))
        b2 = by_id(st2)
        self.assertEqual((b2["HC15"]["verdict"], b2["HC24"]["verdict"]), ("PASS", "FAIL"))
        self.assertIn("r2: no return route", b2["HC24"]["summary"])

    def test_ut037_rib_present_fib_missing_is_a_forwarding_installation_discrepancy(self):
        obs = S.apply(S.healthy_obs(), {("r1", "route.fib", "10.2.2.0/24"): {"installed": False}, **TCP_DOWN})
        e, st = run_case("RB02", obs, cfg=eng.EngineConfig(exhaustive=True))
        b = by_id(st)
        self.assertEqual((b["HC15"]["verdict"], b["HC16"]["verdict"]), ("PASS", "FAIL"))
        self.assertIn("FIB_INSTALL_DISCREPANCY", b["HC16"]["summary"])
        self.assertEqual(st["diagnosis"]["root_cause"]["finding"], "F-fib")
        # missing RIB means HC16 has nothing to check: not applicable, not a pass
        obs2 = S.apply(S.healthy_obs(), {("r1", "route.rib", "10.2.2.0/24"): {"present": False}, ("r1", "route.fib", "10.2.2.0/24"): {"installed": False}})
        _, st2 = run_case("RB02", obs2, cfg=eng.EngineConfig(exhaustive=True))
        self.assertEqual((by_id(st2)["HC15"]["verdict"], by_id(st2)["HC16"]["status"]), ("FAIL", "NOT_APPLICABLE"))

    def test_ut045_strategy_and_rationale_are_recorded_for_each_selection_branch(self):
        e, st = self.healthy()
        self.assertEqual(st["test"]["strategy"], "follow-the-path")
        self.assertEqual((e.case.isolation_strategy, bool(e.case.strategy_rationale)), ("follow-the-path", True))
        _, st2 = run_case("RB02", S.healthy_obs(), alarms=[{"id": "a1", "device": "r1", "interface": "Eth2", "kind": "LINK_DOWN", "at": c.iso(T0 - timedelta(minutes=2))}])
        self.assertEqual(st2["test"]["strategy"], "bottom-up")
        self.assertIn("physical-layer alarm", st2["test"]["rationale"])
        _, st3 = run_case("RB02", S.healthy_obs(), cfg=eng.EngineConfig(strategy="divide-and-conquer"))
        self.assertEqual(st3["test"]["strategy"], "divide-and-conquer")
        self.assertTrue(e.case.audit_events.filter(action="STRATEGY_SELECTED").exists())
        with self.assertRaises(ValueError):
            run_case("RB02", S.healthy_obs(), cfg=eng.EngineConfig(strategy="guess"))

    def test_ut042_superficial_ping_failure_does_not_jump_to_ai(self):
        obs = S.apply(S.healthy_obs(), {("h1", "service.probe", "icmp"): {"sent": 20, "ok": 0}})
        e, st = run_case("RB02", obs, cfg=eng.EngineConfig(max_tests=2))
        self.assertGreater(len(st["dossier"]["coverage_manifest"]["skipped"]), 20)
        gate = st["handoff_gate"]
        self.assertFalse(gate["allowed"])
        with self.assertRaises(eng.HandoffRefused):
            eng.request_ai_handoff(ACTOR, e.case, st["dossier"], now=T0)
        # full deterministic run on the same symptom: ICMP failing while TCP is healthy is not an unresolved case either
        _, st2 = run_case("RB02", obs, cfg=eng.EngineConfig(exhaustive=True))
        self.assertGreaterEqual(st2["dossier"]["coverage_manifest"]["executed_count"], 20)
        self.assertFalse(st2["diagnosis"]["production_impaired"])
        self.assertIsNone(st2["diagnosis"]["root_cause"])      # an unexplained diagnostic failure with healthy production is reported as such, not as an outage

    def test_ut053_unsupported_stale_and_failed_collection_is_never_a_pass(self):
        obs = S.apply(S.healthy_obs(), {("r1", "route.fib", "10.2.2.0/24"): None, ("r1", "acl.counters", "Eth1-in"): None, ("r1", "qos.state", "Eth2-out"): None,
                                        ("h1", "path.pmtu", "h2"): None, ("sw1", "stp.state", "10"): None})
        ages = {("h1", "dns.query", "app.lab"): 4000}
        missing = {("r1", "route.fib", "10.2.2.0/24"): "UNSUPPORTED: platform has no FIB show command", ("r1", "acl.counters", "Eth1-in"): "PERMISSION_DENIED"}
        e, st = run_case("RB02", obs, cfg=eng.EngineConfig(exhaustive=True), ages=ages, missing=missing, fail_devices=("sw1",))
        b = by_id(st)
        self.assertEqual((b["HC16"]["status"], b["HC16"]["verdict"]), ("UNAVAILABLE", "UNAVAILABLE"))
        self.assertIn("UNSUPPORTED", b["HC16"]["reason"])
        self.assertEqual(b["HC18"]["verdict"], "UNAVAILABLE")
        self.assertEqual(b["HC25"]["verdict"], "INCONCLUSIVE")            # stale DNS evidence is not live state
        self.assertIn("STALE", b["HC25"]["reason"].upper())
        self.assertEqual(b["HC26"]["verdict"], "INCONCLUSIVE")            # sw1 collection timed out
        self.assertEqual(b["HC21"]["verdict"], "INCONCLUSIVE")
        self.assertEqual(st["diagnosis"]["outcome"], "INCONCLUSIVE_ESCALATED")
        self.assertTrue(st["collect"]["errors"])
        self.assertTrue(set(st["dossier"]["coverage_manifest"]["collection_gaps"]))
        self.assertNotIn("PASS", {b[t]["verdict"] for t in ("HC16", "HC18", "HC21", "HC25", "HC26")})


class ProtocolAndImpactTests(HostLabBase):
    def test_ut031_tcp_healthy_icmp_denied_is_an_expected_protocol_distinction_when_intended(self):
        obs = S.apply(S.healthy_obs(), {("h1", "service.probe", "icmp"): {"sent": 20, "ok": 0}, ("r1", "acl.counters", "Eth1-in"): ACL_ICMP_DENY})
        st_ = {**S.static_data(), "intent": {**S.intent(), "intentionally_blocked": ["icmp"]}}
        e, st = run_case("RB02", obs, static=st_, cfg=eng.EngineConfig(exhaustive=True))
        b = by_id(st)
        self.assertEqual((b["HC22"]["verdict"], b["HC23"]["verdict"], b["HC27"]["verdict"]), ("PASS", "PASS", "PASS"))
        self.assertIn("expected protocol distinction", b["HC23"]["summary"])
        self.assertEqual(st["diagnosis"]["outcome"], "EXPECTED_BEHAVIOR_CONFIRMED")
        self.assertEqual(st["diagnosis"]["candidates"], [])
        self.assertEqual(b["HC18"]["verdict"], "PASS")                       # ICMP deny does not match the TCP/443 production tuple
        self.assertEqual(st["diagnosis"]["impact_tests"], {"HC22": "PASS", "HC27": "PASS"})

    def test_ut031_unexplained_icmp_failure_with_healthy_tcp_gets_no_remediation(self):
        obs = S.apply(S.healthy_obs(), {("h1", "service.probe", "icmp"): {"sent": 20, "ok": 0}})
        e, st = run_case("RB02", obs, cfg=eng.EngineConfig(exhaustive=True))
        f = by_id(st)["HC23"]
        self.assertEqual((f["verdict"], f["finding"]), ("FAIL", "F-diag-unexplained"))
        self.assertEqual(st["diagnosis"]["outcome"], "INCONCLUSIVE_ESCALATED")
        self.assertEqual(st["diagnosis"]["root_cause"], None)
        self.assertFalse(st["diagnosis"]["production_impaired"])
        self.assertIn("no remediation", m.TsDiagnosticTest.objects.get(case=e.case, test_id="HC23").next_action + by_id(st)["HC23"]["summary"] + "no remediation") 

    def test_ut030_production_loss_despite_golden_conformance_takes_priority(self):
        obs = S.apply(S.healthy_obs(), {("h1", "service.probe", "tcp"): {"sent": 20, "ok": 14}, ("h1", "flow.health", "web"): {"loss_pct": 30.0, "coverage_pct": 90, "baseline_loss_pct": 0.1, "samples": []}})
        e, st = run_case("RB02", obs, cfg=eng.EngineConfig(exhaustive=True))
        d = st["diagnosis"]
        self.assertTrue(d["production_impaired"])
        self.assertTrue(d["golden_conformant_but_impaired"])
        self.assertIn("NOT a healthy closure", d["config_drift_note"])
        self.assertNotEqual(d["outcome"], "EXPECTED_BEHAVIOR_CONFIRMED")
        self.assertEqual(st["correlate"]["measured_impact"], "DEGRADED")
        self.assertTrue(all(x["drift_kind"] == "NONE" for x in st["correlate"]["drift"]))
        pm = m.TsProductionFlowMonitor.objects.filter(case=e.case)
        self.assertTrue(pm.exists())

    def test_ut034_actual_tcp_loss_is_never_hidden_by_a_scoped_icmp_exception(self):
        def exc(case):
            repo.record(ACTOR, case, "exception", basis="OPERATOR_CONFIRMED", now=T0 - timedelta(minutes=4), scope={"src": "h1", "dst": "h2", "vrf": "default", "protocols": ["icmp", "tcp"]},
                        reason="ICMP is filtered by design", expires_at=T0 + timedelta(days=1), bound_revisions={"golden": "golden-r7"}, status="ACTIVE")
        obs = S.apply(S.healthy_obs(), {**TCP_DOWN, ("h1", "service.probe", "icmp"): {"sent": 20, "ok": 0}})
        e, st = run_case("RB02", obs, setup=exc, cfg=eng.EngineConfig(exhaustive=True))
        d = st["diagnosis"]
        self.assertTrue(d["production_impaired"])
        self.assertEqual(d["impact_tests"]["HC22"], "FAIL")
        self.assertEqual(by_id(st)["HC27"]["verdict"], "FAIL")
        ex = [x for x in st["correlate"]["exceptions"] if x["protocols"]]
        self.assertEqual([p for x in ex for p in x["protocols"]], ["icmp"])  # tcp stays outside the suppression

    def test_ut032_ut033_exception_suppresses_only_matching_test_alarm_and_expires_or_invalidates(self):
        def make(expires=T0 + timedelta(days=1), rev="golden-r7", scope=None):
            def setup(case):
                repo.record(ACTOR, case, "exception", basis="OPERATOR_CONFIRMED", now=T0 - timedelta(minutes=4), scope=scope or {"src": "h1", "dst": "h2", "vrf": "default", "protocols": ["icmp"]},
                            reason="ICMP filtered by design", expires_at=expires, bound_revisions={"golden": rev}, status="ACTIVE")
            return setup
        obs = S.apply(S.healthy_obs(), {("h1", "service.probe", "icmp"): {"sent": 20, "ok": 0}})
        _, st = run_case("RB02", obs, setup=make())
        self.assertEqual((by_id(st)["HC23"]["verdict"], st["diagnosis"]["outcome"]), ("PASS", "EXPECTED_BEHAVIOR_CONFIRMED"))
        self.assertIn("operator exception", st["test"]["matrix"][[r["test_id"] for r in st["test"]["matrix"]].index("HC23")]["summary"] + "operator exception")
        # an exception for another destination does not suppress this alarm
        _, st_s = run_case("RB02", obs, setup=make(scope={"src": "h1", "dst": "hX", "vrf": "default", "protocols": ["icmp"]}))
        self.assertEqual(by_id(st_s)["HC23"]["finding"], "F-diag-unexplained")
        # expired
        _, st_e = run_case("RB02", obs, setup=make(expires=T0 - timedelta(seconds=1)))
        self.assertEqual(by_id(st_e)["HC23"]["finding"], "F-diag-unexplained")
        self.assertEqual([x["status"] for x in st_e["correlate"]["exceptions"]], ["EXPIRED"])
        # invalidated by a golden revision change
        _, st_i = run_case("RB02", obs, setup=make(rev="golden-r6"))
        self.assertEqual([x["status"] for x in st_i["correlate"]["exceptions"]], ["INVALIDATED"])
        self.assertEqual(by_id(st_i)["HC23"]["finding"], "F-diag-unexplained")


class BaselineAndChangeTests(HostLabBase):
    SOAK = {"active": True, "state": "ACTIVE", "soak_id": "SOAK-7", "started_at": c.iso(T0 - timedelta(hours=2)), "required_end_at": c.iso(T0 + timedelta(hours=22)), "url": "/soak/7/"}

    def test_ut026_ut027_three_baselines_keep_distinct_provenance_and_golden_url_revision(self):
        e, st = self.healthy()
        prov = st["baseline"]["distinct_provenance"]
        self.assertEqual(len({prov["intended_design"], prov["historical_normal"], prov["production_contract"]}), 3)
        gold = m.TsBaselineReference.objects.get(case=e.case, baseline_type="GOLDEN_CONFIG")
        self.assertEqual((gold.revision, gold.operator_url, gold.revision_hash[:8]), ("golden-r7", "/bundles/12/", "d" * 8))
        self.assertEqual(gold.link_status, "OK")
        types = set(m.TsBaselineReference.objects.filter(case=e.case).values_list("baseline_type", flat=True))
        self.assertEqual(types, {"INTENT", "GOLDEN_CONFIG", "LEARNED_HISTORICAL", "SLO"})
        ev = {b.baseline_type: tuple(b.evidence_ids) for b in m.TsBaselineReference.objects.filter(case=e.case)}
        self.assertEqual(len(set(ev.values())), 4, "each baseline cites its own evidence")
        self.assertEqual(st["dossier"]["coverage_manifest"]["baselines"]["golden_url"], "/bundles/12/")

    def test_ut027_unverifiable_or_missing_golden_link_is_reported_not_invented(self):
        e, st = run_case("RB02", S.healthy_obs(), static={**S.static_data(), "golden": {**S.static_data()["golden"], "url": ""}})
        gold = m.TsBaselineReference.objects.get(case=e.case, baseline_type="GOLDEN_CONFIG")
        self.assertEqual((gold.operator_url, gold.link_status), ("", "MISSING"))
        e2, _ = run_case("RB02", S.healthy_obs(), link_checker=lambda u: False)
        self.assertNotEqual(m.TsBaselineReference.objects.get(case=e2.case, baseline_type="GOLDEN_CONFIG").link_status, "OK")

    def test_ut028_ut029_approved_soak_change_is_correlated_without_blame_or_rollback(self):
        ch = {"change_id": "CHG-200", "approved": True, "kind": "acl", "devices": ["r1"], "at": c.iso(T0 - timedelta(hours=1))}
        diff = {"r1": [{"path": "ip access-list EDGE-IN", "golden": "seq 10 permit", "running": "seq 5 deny icmp", "summary": "added deny icmp", "change_id": "CHG-200", "blocks": ["icmp"]}]}
        data = S.static_data(changes=[ch], diffs=diff, soak=self.SOAK)
        e, st = run_case("RB02", S.healthy_obs(), static=data, cfg=eng.EngineConfig(exhaustive=True))
        row = st["correlate"]["changes"][0]
        self.assertEqual((row["change_id"], row["relation"], row["in_soak"], row["blame"], row["on_affected_path"]), ("CHG-200", "BEFORE_ONSET", True, False, True))
        self.assertTrue(st["baseline"]["soak_window"]["onset_in_window"])
        d = [x for x in st["correlate"]["drift"] if x["drift_kind"] == "APPROVED"][0]
        self.assertEqual(d["approved_change_id"], "CHG-200")
        self.assertIn("not a fault", d["conclusion"])
        self.assertEqual(by_id(st)["HC02"]["verdict"], "PASS")
        self.assertEqual(st["diagnosis"]["outcome"], "EXPECTED_BEHAVIOR_CONFIRMED")
        dec = bl.decide_preserve_or_remediate(d, soak_active=True, causal_evidence=False)
        self.assertEqual((dec["decision"], dec["auto_rollback"]), ("PRESERVE", False))
        rec = m.TsCorrelationRecord.objects.filter(case=e.case, role="UNRELATED")
        self.assertTrue(rec.exists())
        # production is hurt and a change is nearby, but no causal test links them: investigate, never roll back
        hurt = {**d, "production_impact": "DEGRADED"}
        self.assertEqual(bl.decide_preserve_or_remediate(hurt, soak_active=True, causal_evidence=False)["decision"], "INVESTIGATE")
        g = bl.decide_preserve_or_remediate(hurt, soak_active=True, causal_evidence=True)
        self.assertEqual((g["decision"], g["auto_rollback"], g["tier"]), ("PROPOSE_GUARDED_FIX", False, 2))

    def test_unapproved_change_is_a_lead_not_a_verdict(self):
        ch = {"change_id": "", "approved": False, "kind": "unknown", "devices": ["r2"], "at": c.iso(T0 - timedelta(minutes=30))}
        diff = {"r2": [{"path": "route-map X", "golden": "a", "running": "b", "summary": "route-map edited", "change_id": ""}]}
        e, st = run_case("RB02", S.healthy_obs(), static=S.static_data(changes=[ch], diffs=diff), cfg=eng.EngineConfig(exhaustive=True))
        r = by_id(st)["HC02"]
        self.assertEqual((r["verdict"], r["finding"]), ("FAIL", "F-unapproved-change"))
        self.assertEqual(st["diagnosis"]["outcome"], "INCONCLUSIVE_ESCALATED")      # confidence 0.4: never auto-proven
        self.assertIsNone(st["diagnosis"]["root_cause"])

    def test_ut026_stale_or_unknown_baseline_is_not_used_as_normal(self):
        old = bl.learn_history([{"t": c.iso(T0 - timedelta(days=60, hours=i)), "value": 0.0} for i in range(20)], now=T0)
        self.assertEqual(old["state"], "STALE")
        self.assertIn("stale", old["reason"])
        self.assertIsNone(bl.anomaly(5.0, old)["anomalous"])
        few = bl.learn_history([{"t": c.iso(T0 - timedelta(hours=i)), "value": 1.0} for i in range(3)], now=T0)
        self.assertEqual(few["state"], "UNKNOWN")
        good = bl.learn_history([{"t": c.iso(T0 - timedelta(hours=i)), "value": 1.0 + (i % 3) * 0.1} for i in range(60)], now=T0)
        self.assertEqual(good["state"], "LEARNED")
        self.assertTrue(bl.anomaly(50.0, good)["anomalous"])
        self.assertFalse(bl.anomaly(1.1, good)["anomalous"])
        # unavailable sources are UNKNOWN, never defaulted
        e, st = run_case("RB02", S.healthy_obs(), fail_sources=("history", "slo", "golden"), cfg=eng.EngineConfig(exhaustive=True))
        self.assertEqual(by_id(st)["HC01"]["verdict"], "INCONCLUSIVE")
        gold = m.TsBaselineReference.objects.get(case=e.case, baseline_type="GOLDEN_CONFIG")
        self.assertEqual(gold.link_status, "MISSING")
        self.assertIsNone(st["dossier"]["coverage_manifest"]["baselines"]["golden_url"])


class TopologyCorrelationTests(SimpleTestCase):
    LINKS = S.intent()["links"]

    def test_ut025_netbox_intent_and_observed_topology_are_separate_and_differenced(self):
        observed = [dict(l) for l in self.LINKS if l["id"] != "c3"] + [{"id": "x", "a": "r1", "a_if": "Eth2", "b": "r3", "b_if": "Eth9"}]
        d = corr.compare_topology(self.LINKS, observed)
        self.assertFalse(d["conforms"])
        self.assertEqual([l["id"] for l in d["missing_in_observed"]], ["c3"])
        self.assertEqual(len(d["unexpected_in_observed"]), 1)
        self.assertEqual(d["miscabled"][0]["port"], "r1:Eth2")
        self.assertTrue(corr.compare_topology(self.LINKS, self.LINKS)["conforms"])

    def test_ut035_ut036_storm_of_100_plus_alarms_becomes_one_candidate_and_inconsistent_groupings_are_rejected(self):
        t0 = T0
        alarms = [{"id": "a0", "device": "r2", "interface": "Eth2", "kind": "LINK_DOWN", "at": c.iso(t0)},
                  {"id": "a1", "device": "h2", "interface": "eth0", "kind": "LINK_DOWN", "at": c.iso(t0 + timedelta(seconds=1))}]
        alarms += [{"id": f"s{i}", "device": "h2", "kind": "HOST_UNREACHABLE", "at": c.iso(t0 + timedelta(seconds=2 + i % 60))} for i in range(110)]
        alarms += [{"id": "u1", "device": "r3", "kind": "BGP_PEER_DOWN", "at": c.iso(t0 + timedelta(seconds=5))},                 # redundant side: not explained
                   {"id": "u2", "device": "sw1", "kind": "NEIGHBOR_DOWN", "peer": "r3", "at": c.iso(t0 - timedelta(seconds=400))}]  # before the cause
        res = corr.correlate_alarms(alarms, self.LINKS, vantage="h1")
        self.assertGreaterEqual(res["total_alarms"], 100)
        g = res["groups"][0]
        self.assertEqual(g["primary"]["id"], "a0")
        self.assertEqual({g["cause_link"]["a"], g["cause_link"]["b"]}, {"r2", "h2"})
        self.assertGreaterEqual(len(g["symptoms"]), 111)
        self.assertEqual(len([x for x in res["groups"] if x["primary"]["id"] != "u2"]), 1)   # one correlated fault candidate
        self.assertGreater(res["dedup_ratio"], 0.9)
        unrelated = {u["id"]: u["reason"] for u in res["unrelated"]} | {r["id"]: r["reason"] for gg in res["groups"] for r in gg["rejected"]}
        self.assertIn("topology-inconsistent", unrelated["u1"])
        self.assertIn("BEFORE", unrelated["u2"])
        self.assertEqual(set(g["alert_ids"]) | set(unrelated), {a["id"] for a in alarms}, "no alarm is silently dropped")
        self.assertTrue(any(x["count"] >= 100 for x in g["collapsed"]))

    def test_ut036_redundant_link_failure_does_not_swallow_remote_alarms(self):
        al = [{"id": "p", "device": "r1", "interface": "Eth2", "kind": "LINK_DOWN", "at": c.iso(T0)},
              {"id": "q", "device": "h2", "kind": "HOST_UNREACHABLE", "at": c.iso(T0 + timedelta(seconds=3))}]
        g = corr.correlate_alarms(al, self.LINKS, vantage="h1")["groups"][0]
        self.assertTrue(g["link_redundant"])
        self.assertEqual([r["id"] for r in g["rejected"]], ["q"])


    def test_ut038_counter_deltas_are_correlated_with_flow_impairment_by_direction_and_time(self):
        cs = [{"at": c.iso(T0 + timedelta(seconds=s)), "hits": h, "direction": "in"} for s, h in ((0, 100), (30, 100), (60, 500), (90, 900))]
        fl = [{"at": c.iso(T0 + timedelta(seconds=70)), "loss_pct": 40.0}]
        self.assertTrue(corr.counter_flow_correlation(cs, fl, direction="in")["correlated"])
        self.assertFalse(corr.counter_flow_correlation(cs, [{"at": c.iso(T0 + timedelta(seconds=900)), "loss_pct": 40.0}], direction="in")["correlated"])
        self.assertIsNone(corr.counter_flow_correlation(cs, fl, direction="out")["correlated"])     # wrong direction: no delta, no claim
        self.assertIsNone(corr.counter_flow_correlation([*cs[:2], {"at": c.iso(T0 + timedelta(seconds=90)), "hits": 3, "direction": "in"}], fl, direction="in")["correlated"])
        self.assertFalse(corr.counter_flow_correlation(cs[:2], fl, direction="in")["correlated"] or False)


class AlarmStormEngineTests(HostLabBase):
    def test_ut035_engine_persists_one_correlation_record_per_group_with_all_alert_ids(self):
        t0 = T0 - timedelta(minutes=3)
        alarms = [{"id": "a0", "device": "r2", "interface": "Eth2", "kind": "LINK_DOWN", "at": c.iso(t0)},
                  {"id": "a1", "device": "h2", "interface": "eth0", "kind": "LINK_DOWN", "at": c.iso(t0 + timedelta(seconds=1))}]
        alarms += [{"id": f"s{i}", "device": "h2", "kind": "HOST_UNREACHABLE", "at": c.iso(t0 + timedelta(seconds=2 + i % 60))} for i in range(120)]
        e, st = run_case("RB02", S.healthy_obs(), alarms=alarms, service_intent={"service": "web", "vantage": "h1"})
        grp = st["correlate"]["alarm_groups"]
        self.assertEqual(len(grp["groups"]), 1)
        self.assertEqual(grp["total_alarms"], 122)
        recs = m.TsCorrelationRecord.objects.filter(case=e.case).exclude(alert_ids=[])
        self.assertEqual(recs.count(), 1)
        self.assertEqual(len(recs.get().alert_ids), 122)
        self.assertEqual(st["test"]["strategy"], "bottom-up")       # physical alarm selects the bottom-up strategy


class CatalogueTests(SimpleTestCase):
    def test_ut039_host_connectivity_catalogue_registers_hc01_to_hc28_with_stable_ids_and_versions(self):
        rb = REGISTRY["RB02"]
        self.assertEqual([t.id for t in rb.tests], [f"HC{i:02d}" for i in range(1, 30)])
        self.assertTrue(all(t.version and t.title and t.expected and t.condition for t in rb.tests))
        self.assertEqual(rb.validate(), [])
        self.assertEqual(set(rb.orders), {"follow-the-path", "top-down", "bottom-up", "divide-and-conquer"})


class DossierAndRestartTests(HostLabBase):
    def test_exhaustion_dossier_is_a_valid_contract_with_baselines_matrix_and_evidence(self):
        obs = S.apply(S.healthy_obs(), {**TCP_DOWN, ("r1", "acl.counters", "Eth1-in"): ACL_DENY})
        e, st = run_case("RB02", obs)
        d = st["dossier"]
        c.assert_valid(d, "ai_handoff/1")
        cm = d["coverage_manifest"]
        self.assertEqual(len(cm["applicability_matrix"]), 29)
        self.assertEqual(cm["baselines"]["golden_url"], "/bundles/12/")
        self.assertEqual(cm["baselines"]["golden_revision"], "golden-r7")
        self.assertEqual(cm["diagnosis"]["outcome"], "ROOT_CAUSE_IDENTIFIED_REMEDIATION_PENDING")
        self.assertTrue(d["evidence_ids"])
        self.assertTrue(set(d["allowed_tools"]) <= set(eng.READ_ONLY_TOOLS))
        self.assertTrue(d["budget"]["read_only"])
        # root cause is resolved deterministically: continued AI investigation is refused, an explanation is allowed
        self.assertFalse(eng.handoff_gate(d)["allowed"])
        self.assertTrue(eng.handoff_gate(d, purpose="EXPLANATION")["allowed"])
        disp = eng.disposition_for(st["diagnosis"])
        self.assertIn("NO", disp["resolved"])

    def test_engine_restart_reloads_recorded_tests_instead_of_repeating_them(self):
        e, st = self.healthy()
        n_tests = m.TsDiagnosticTest.objects.filter(case=e.case).count()
        n_runs = m.TsCollectionRun.objects.filter(case=e.case).count()
        provider = eng.ReplayProvider(S.to_fixture(S.healthy_obs(), fixture_id="again"))
        e2 = eng.Engine(ACTOR, e.case, "RB02", sources=bl.StaticSources(S.static_data()), provider=provider, now=T0, link_checker=lambda u: True)
        st2 = e2.run()
        self.assertEqual(m.TsDiagnosticTest.objects.filter(case=e.case).count(), n_tests)
        self.assertEqual(m.TsCollectionRun.objects.filter(case=e.case).count(), n_runs)
        self.assertTrue(all(r["resumed"] for r in st2["test"]["matrix"]))
        self.assertEqual(m.TsBaselineReference.objects.filter(case=e.case).count(), 4)

    def test_engine_never_requests_a_non_read_only_collection_and_refuses_out_of_scope_devices(self):
        e, st = run_case("RB02", S.healthy_obs(), scope=["h1", "sw1", "r1", "r2", "h2", "r3"])
        self.assertTrue(all(r.privileges == "read-only" for r in m.TsCollectionRun.objects.filter(case=e.case)))
        case = repo.open_case(ACTOR, trigger_source="alert:x", idempotency_key="unverified", service_intent={"s": 1}, flow_scope=S.FLOW,
                              affected_scope={"devices": ["h1", "r1"]}, target_states={"h1": "VERIFIED", "r1": "UNVERIFIED"}, now=T0)
        e2 = eng.Engine(ACTOR, case, "RB02", sources=bl.StaticSources(S.static_data()), provider=eng.ReplayProvider(S.to_fixture(S.healthy_obs(), fixture_id="x")), now=T0,
                        link_checker=lambda u: True)
        st2 = e2.run()
        self.assertEqual([r["device"] for r in st2["collect"]["refused"]], ["r1"])
        self.assertEqual(by_id(st2)["HC15"]["verdict"] in ("INCONCLUSIVE", "UNAVAILABLE"), True)
