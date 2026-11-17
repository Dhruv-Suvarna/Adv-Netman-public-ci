"""Stage 1 deterministic engine: Collect -> Normalize -> Baseline -> Correlate -> Test (spec 3).

``Engine.run()`` drives one case end to end through the persistent M1 substrate (``repository``) and the s2 collectors (via an injected
``EvidenceProvider``), the baselines/correlation modules and a typed runbook DAG.  Nothing here writes to a device: collection is read-only
by construction (providers return ``collection_bundle/1`` documents; ``repository.begin_collection_run`` refuses any non-read-only privilege and
gates every target) and tests only read normalized observations.

Guarantees (each covered by tests):
* every stage leaves records: collection runs/evidence/observations, baseline + drift + path + correlation + flow-monitor records,
  hypotheses, one test row for EVERY catalogue test (executed, not applicable, unavailable, unsafe, skipped-after-isolation) and audit events;
* unsupported / stale / untrusted / missing evidence yields INCONCLUSIVE or UNAVAILABLE, never an invented PASS or FAIL;
* adaptive stopping only after a *proven* causal finding (causal, confidence >= PROOF_CONFIDENCE, and not contradicted by the impact tests);
  skipped tests keep their applicability row with the exact reason;
* restart-safe: collection runs are idempotent by key; already-recorded tests are reloaded, not repeated;
* the exhaustion dossier (``ai_handoff/1``) is built from persisted records and a gate refuses handoff while safe applicable tests are unexamined.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Callable, Iterable, Protocol

from core import models as m

from . import baselines as bl
from . import contracts as c
from . import correlation as corr
from . import repository as repo
from .runbooks import REGISTRY
from .runbooks.base import DISCRIMINATING, Ctx, EvidenceView, Finding, Gap, Obs, Result, Runbook, TestSpec, join_key, split_key

ENGINE_VERSION = "1.0.0"
PROOF_CONFIDENCE = 0.85
EXPECTED_FINDINGS = {"F-planned", "F-maintenance"}          # intentional disruption: confirmed, but nothing to remediate
OUTCOMES = ("RESOLVED_VERIFIED", "ROOT_CAUSE_IDENTIFIED_REMEDIATION_PENDING", "EXPECTED_BEHAVIOR_CONFIRMED", "INCONCLUSIVE_ESCALATED",
            "EXTERNAL_PREREQUISITE_BLOCKED", "REMEDIATION_FAILED_RESTORED", "REMEDIATION_FAILED_UNRESTORED")
READ_ONLY_TOOLS = ("get_case_summary", "get_normalized_observations", "get_baseline_and_golden_link", "get_change_and_soak_history", "get_topology_and_paths",
                   "get_test_matrix", "request_diagnostic_test", "get_evidence", "get_production_flow_health", "get_capability_and_maintenance_state",
                   "propose_remediation", "submit_investigation_result")


class HandoffRefused(RuntimeError):
    """Deterministic coverage is not demonstrably exhausted (or the case is not actually unresolved)."""


class EvidenceProvider(Protocol):
    def collect(self, case_id: str, device: str, wanted: Iterable[str], now: datetime) -> list[dict]: ...


@dataclass
class EngineConfig:
    exhaustive: bool = False                 # run every applicable test even after a proven root cause
    strategy: str | None = None              # override the runbook's selection
    max_tests: int = 80
    max_collection_runs: int = 60
    min_flow_coverage_pct: float = 50.0
    tcp_loss_threshold_pct: float = 1.0
    alarm_window_seconds: int = 180


# ----------------------------------------------------------------------------------------------------------------- replay provider
class ReplayProvider:
    """Replays recorded/simulated collections (fixture ``collections``) as ``collection_bundle/1`` documents.

    ``provenance`` is carried into every bundle's raw header so that simulated data is never mistaken for live evidence."""

    def __init__(self, fixture: dict, *, fail_devices: Iterable[str] = ()):
        self.fixture, self.fail = fixture, set(fail_devices)
        self.calls: list[tuple[str, tuple]] = []

    def collect(self, case_id: str, device: str, wanted: Iterable[str], now: datetime) -> list[dict]:
        self.calls.append((device, tuple(sorted(wanted))))
        if device in self.fail:
            raise TimeoutError(f"{device}: collector timeout")
        prov = self.fixture.get("provenance", "SIMULATED")
        out = []
        for col in self.fixture.get("collections", []):
            if col["device"] != device:
                continue
            collected = now - timedelta(seconds=col.get("age_s", 5))
            obs = []
            for o in col["observations"]:
                age = o.get("age_s", col.get("age_s", 5))
                at = now - timedelta(seconds=age)
                key = join_key(o["key"], o.get("subject", ""))
                base = {"key": key, "target": device, "observed_at": c.iso(at), "source": f"{col.get('source_type', 'cli')}:{col.get('adapter', 'replay')}",
                        "basis": "OBSERVED", "max_age_seconds": o.get("max_age_s", 300), "parser_version": col.get("parser", "replay@1"),
                        "dedupe_key": hashlib.sha256(f"{case_id}|{device}|{key}|{c.iso(at)}".encode()).hexdigest()[:32]}
                if o.get("missing"):
                    base.update({"quality": "MISSING", "is_missing_data": True, "missing_reason": o["missing"], "stage_decision": "UNKNOWN"})
                else:
                    base.update({"quality": o.get("quality", "GOOD"), "value": o.get("value"), "unit": o.get("unit", "")})
                obs.append(base)
            out.append({"schema": "collection_bundle/1", "case_id": case_id, "collector": col.get("collector", f"{col.get('source_type', 'cli')}-collector"),
                        "adapter": col.get("adapter", "replay"), "adapter_version": col.get("adapter_version", "1"),
                        "idempotency_key": hashlib.sha256(f"{case_id}|{device}|{col['command']}|{col.get('age_s', 5)}".encode()).hexdigest()[:40],
                        "targets": [device], "command_or_api": col["command"], "status": col.get("status", "SUCCEEDED"), "observations": obs,
                        "started_at": c.iso(collected - timedelta(seconds=1)), "finished_at": c.iso(collected), "privileges": "read-only",
                        "timeout_seconds": 30, "rate_budget": {"max_commands": 1, "min_interval_s": 1},
                        "raw": {"source_type": col.get("source_type", "cli"), "text": f"[{prov}] {col.get('raw', '')}", "parser": col.get("parser", "replay"),
                                "parser_version": "1", "pointer": f"fixture:{self.fixture.get('fixture_id', '?')}#{device}/{col['command']}"}})
        return out


# ------------------------------------------------------------------------------------------------------------------- helpers
def case_target(case) -> str:
    return (case.affected_scope.get("devices") or [""])[0]


def _obs_from_row(o) -> Obs:
    key, subject = split_key(o.key)
    return Obs(key=key, device=o.target, subject=subject, value=o.value, observed_at=o.observed_at, quality=o.quality, max_age_seconds=o.max_age_seconds,
               record_id=o.record_id, evidence_ids=tuple(o.evidence_ids), is_missing=o.is_missing_data, missing_reason=o.missing_reason, unit=o.unit)


def load_view(actor: repo.Actor, case, now: datetime) -> EvidenceView:
    repo.get_case(actor, case.case_id)
    rows = [o for o in m.TsObservation.objects.filter(case=case) if actor.can_see_device(o.target)]
    return EvidenceView([_obs_from_row(o) for o in rows], now)


def _result_from_row(t) -> Result:
    obs = dict(t.observed or {})
    status = obs.pop("_applicability", "EXECUTED")
    fd = obs.pop("_finding", None)
    return Result(t.verdict, status=status, reason=t.reason, summary=t.observed_summary, observed=obs, interpretation=t.interpretation, next_action=t.next_action,
                  evidence_ids=list(t.evidence_ids), finding=Finding(**fd) if fd else None, target=t.target, command=t.command_or_api)


def intended_flow_paths(intent: dict, flow: dict) -> tuple[list[dict], list[dict]]:
    if not flow or not intent.get("links"):
        return [], []
    paths = corr.intended_paths(intent["links"], flow["src"], flow["dst"], limit=1)
    if not paths:
        return [], []
    fwd = paths[0]
    rev = [{"device": h["device"], "in_if": h["out_if"], "out_if": h["in_if"]} for h in reversed(fwd)]
    return fwd, rev


# ---------------------------------------------------------------------------------------------------------------------- engine
class Engine:
    def __init__(self, actor: repo.Actor, case, runbook: Runbook | str, *, sources: bl.BaselineSources, provider: EvidenceProvider, now: datetime,
                 alarms: list[dict] | None = None, config: EngineConfig | None = None, link_checker: Callable[[str], bool] | None = None,
                 current_revisions: dict[str, str] | None = None):
        self.actor, self.case = actor, case
        self.rb = REGISTRY[runbook] if isinstance(runbook, str) else runbook
        self.sources, self.provider, self.now = sources, provider, now
        self.alarms, self.cfg, self.link_checker = list(alarms or []), config or EngineConfig(), link_checker
        self.current_revisions = dict(current_revisions or {})
        self.stages: dict[str, Any] = {}
        self.ev_ids: dict[str, str] = {}
        self.results: dict[str, Result] = {}
        self.matrix: list[dict] = []

    # --------------------------------------------------------------------------------------------------------------------- run
    def run(self) -> dict[str, Any]:
        problems = self.rb.validate()
        if problems:
            raise ValueError(f"runbook {self.rb.id} DAG invalid: {problems}")
        self._enter("COLLECTING")
        self.stages["collect"] = self.collect()
        self._enter("ANALYSING")
        self.stages["normalize"] = self.normalize()
        self.stages["baseline"] = self.baseline()
        self.stages["correlate"] = self.correlate()
        self._enter("TESTING")
        self.stages["test"] = self.test()
        self.stages["diagnosis"] = self.diagnose()
        self.stages["dossier"] = self.exhaustion_dossier()
        self.stages["handoff_gate"] = handoff_gate(self.stages["dossier"])
        repo.audit(self.actor, self.case, "STAGE1_COMPLETE", decision=self.stages["diagnosis"]["outcome"], result="OK", now=self.now,
                   rationale=f"{self.rb.id} v{self.rb.version}; engine {ENGINE_VERSION}")
        return self.stages

    def _enter(self, state: str) -> None:
        self.case = repo.get_case(self.actor, self.case.case_id)
        if self.case.state != state and state in {"COLLECTING", "ANALYSING", "TESTING"}:
            order = ["OPEN", "SCOPING", "COLLECTING", "ANALYSING", "TESTING"]
            if self.case.state in order and order.index(self.case.state) < order.index(state):
                try:
                    self.case = repo.transition_case(self.actor, self.case, state, reason=f"{self.rb.id} stage", now=self.now)
                except ValueError:
                    pass

    # ------------------------------------------------------------------------------------------------------------------ collect
    def plan(self) -> dict[str, list[str]]:
        wanted = sorted({k for t in self.rb.tests for k in t.sources})
        devices = list(self.case.affected_scope.get("devices", []))
        return {d: wanted for d in devices}

    def collect(self) -> dict[str, Any]:
        plan = self.plan()
        runs, refused, errors = [], [], []
        budget = self.cfg.max_collection_runs
        for device, wanted in plan.items():
            try:
                repo.authorize_probe(self.actor, self.case, device, now=self.now)
            except repo.TargetRefused as exc:
                refused.append({"device": device, "reason": str(exc)})
                repo.record_missing_data(self.actor, self.case, key="collection.refused", target=device, reason=f"REFUSED: {exc}", observed_at=self.now,
                                         source="engine:admission", dedupe_key=f"refused|{self.case.case_id}|{device}")
                continue
            try:
                bundles = self.provider.collect(self.case.case_id, device, wanted, self.now)
            except Exception as exc:  # pylint: disable=broad-exception-caught  # noqa: BLE001 - collector failure is a recorded gap, not a crash and not an invented value
                errors.append({"device": device, "error": f"{type(exc).__name__}: {exc}"})
                repo.record_missing_data(self.actor, self.case, key="collection.error", target=device, reason=f"TIMEOUT/TRANSPORT_ERROR: {type(exc).__name__}",
                                         observed_at=self.now, source="engine:collector", dedupe_key=f"err|{self.case.case_id}|{device}")
                continue
            for b in bundles:
                if budget <= 0:
                    errors.append({"device": device, "error": "BUDGET_EXCEEDED: collection run budget exhausted"})
                    break
                budget -= 1
                run = repo.ingest_collection_bundle(self.actor, b, now=self.now)
                runs.append({"run": run.record_id, "device": device, "command": b["command_or_api"], "status": run.status, "observations": len(b["observations"])})
        if self.alarms:
            runs.append(self._ingest_alarms())
        self.case = repo.get_case(self.actor, self.case.case_id)
        return {"plan": plan, "runs": runs, "refused": refused, "errors": errors, "budget_left": budget}

    def _ingest_alarms(self) -> dict:
        dev = case_target(self.case)
        ref = repo.store_evidence(self.actor, self.case, source_type="alarm_feed", device=dev, command_or_api="alarm_feed:syslog+snmp-trap+gnmi-events",
                                  adapter="troubleshooting.engine", adapter_version=ENGINE_VERSION, collected_at=self.now,
                                  raw=c.canonical_json(self.alarms), quality="GOOD")
        self.ev_ids["alarms"] = ref.evidence_id
        return {"run": "alarm-feed", "device": dev, "command": "alarm_feed", "status": "SUCCEEDED", "observations": len(self.alarms), "evidence": ref.evidence_id}

    # --------------------------------------------------------------------------------------------------------------- normalize
    def normalize(self) -> dict[str, Any]:
        rows = list(m.TsObservation.objects.filter(case=self.case))
        by_fresh: dict[str, int] = {}
        untrusted, missing, stale = [], [], []
        for o in rows:
            fr = repo.evaluate_observation(o, self.now)
            by_fresh[fr] = by_fresh.get(fr, 0) + 1
            if fr == c.UNTRUSTED:
                untrusted.append(o.record_id)
            if fr == c.STALE:
                stale.append(f"{o.key}@{o.target}")
            if o.is_missing_data:
                missing.append({"key": o.key, "target": o.target, "reason": o.missing_reason})
        # cross-source consistency (portable invariants): oper up while admin down is impossible; negative counters are not data
        inconsistent = []
        view = EvidenceView([_obs_from_row(o) for o in rows], self.now)
        for adm in view.each("interface.admin_state"):
            op = view.latest("interface.oper_state", adm.device, adm.subject)
            if op is not None and not op.is_missing and adm.value == "down" and op.value == "up":
                inconsistent.append(f"{adm.device}:{adm.subject} admin down but oper up (parser or clock inconsistency)")
        summary = {"observations": len(rows), "freshness": by_fresh, "untrusted": untrusted, "stale": stale[:50], "missing": missing, "inconsistent": inconsistent,
                   "diagnosis_blocked_on": untrusted}
        repo.audit(self.actor, self.case, "NORMALIZATION_ASSESSED", decision=f"{len(rows)} observations; fresh={by_fresh.get('FRESH', 0)} stale={len(stale)} "
                   f"untrusted={len(untrusted)} missing={len(missing)} inconsistent={len(inconsistent)}"[:255], result="OK", now=self.now)
        return summary

    # ---------------------------------------------------------------------------------------------------------------- baseline
    def baseline(self) -> dict[str, Any]:
        flow = dict(self.case.flow_scope or {})
        devices = list(self.case.affected_scope.get("devices", []))
        onset = self.case.first_detected_at or self.case.opened_at
        existing = m.TsBaselineReference.objects.filter(case=self.case)
        bs = bl.gather(self.sources, devices=devices, flow=flow, now=self.now, onset=onset)
        if existing.exists():  # restart: do not duplicate; rebuild evidence-id map from the stored records
            for b in existing:
                self.ev_ids[{"INTENT": "intent", "GOLDEN_CONFIG": "golden", "LEARNED_HISTORICAL": "history", "SLO": "slo"}[b.baseline_type]] = b.evidence_ids[0]
        else:
            _, ev = bl.persist_baselines(self.actor, self.case, bs, now=self.now, link_checker=self.link_checker)
            self.ev_ids.update({k: v.evidence_id for k, v in ev.items()})
        # evidence for change facts and config diffs (cited by HC02 and drift records)
        for name, doc in (("changes", bs["changes"]), ("configs", bs["configs"])):
            ref = repo.store_evidence(self.actor, self.case, source_type=f"{name}_snapshot", device=case_target(self.case), command_or_api=f"baseline:{name}",
                                      adapter="troubleshooting.baselines", adapter_version="1", collected_at=self.now, raw=c.canonical_json(bl._brief(doc)),
                                      quality="GOOD" if doc.get("status") == "available" else "MISSING")
            self.ev_ids[name] = ref.evidence_id
        self.ev_ids["golden"] = self.ev_ids.get("golden", "")
        self.bs = bs
        return {"distinct_provenance": bl.distinct_provenance(bs), "golden": {k: bs["golden"].get(k) for k in ("status", "revision", "url", "link_ok", "digest", "soak")},
                "soak_window": bs["soak_window"], "history_state": bs["history"].get("status"), "slo": bs["slo"].get("contract"), "changes": len(bs["classified_changes"]),
                "intent_status": bs["intent"].get("status")}

    # --------------------------------------------------------------------------------------------------------------- correlate
    def correlate(self) -> dict[str, Any]:
        bs, flow = self.bs, dict(self.case.flow_scope or {})
        intent = bs["intent"] if bs["intent"].get("status") == "available" else {"nodes": [], "links": []}
        fwd, rev = intended_flow_paths(intent, flow)
        view = load_view(self.actor, self.case, self.now)
        onset = self.case.first_detected_at or self.case.opened_at
        out: dict[str, Any] = {"paths": [], "drift": [], "changes": [], "alarm_groups": None, "exceptions": [], "flow_monitor": None}
        done = {k: model.objects.filter(case=self.case).exists() for k, model in
                (("drift", m.TsDriftAssessment), ("path", m.TsTopologyPath), ("corr", m.TsCorrelationRecord), ("flow", m.TsProductionFlowMonitor))}
        iev = self.ev_ids.get("intent")
        # path --------------------------------------------------------------------------------------------------------
        if fwd:
            tr = view.latest("path.trace", flow["src"], flow["dst"])
            observed = (tr.value.get("hop_devices", []) if tr and not tr.is_missing else [])
            roles = {n["name"]: n.get("role", "") for n in intent.get("nodes", [])}
            d = corr.diff_path(corr.l3_view(fwd, roles, flow["src"]), observed) if observed else {"conforms": None, "first_divergence": None}
            out["paths"].append({"intended": [h["device"] for h in fwd], "intended_l3_view": [h["device"] for h in corr.l3_view(fwd, roles, flow["src"])], "observed": observed, "diff": d})
            if not done["path"] and iev:
                ev = [iev] + (list(tr.evidence_ids) if tr and not tr.is_missing else [])
                repo.record(self.actor, self.case, "topology_path", basis="DERIVED", evidence_ids=ev, now=self.now, source=flow["src"], destination=flow["dst"],
                            vrf=flow.get("vrf", ""), address_family=flow.get("af", ""), service=flow.get("name", ""),
                            intended_hops=[h["device"] for h in fwd], observed_hops=observed, links=[f"{h['device']}:{h['out_if']}" for h in fwd if h["out_if"]],
                            next_hops=[], adjacency=[], lookup_provenance={"intended": intent.get("source"), "observed": "path.trace" if tr else "none (UNKNOWN)"},
                            divergence=([d["first_divergence"]] if d.get("conforms") is False else []),
                            stage_decision="intended path from NetBox/topology; observed from trace (UNKNOWN when absent)")
        # changes -----------------------------------------------------------------------------------------------------
        path_devs = [h["device"] for h in fwd] or list(self.case.affected_scope.get("devices", []))
        ch_rows = corr.change_correlation(bs["classified_changes"], onset=onset, path_devices=path_devs, links=intent.get("links", []), now=self.now)
        out["changes"] = ch_rows
        # drift -------------------------------------------------------------------------------------------------------
        impact = self._measured_impact(view, flow)
        drift_rows = bl.assess_drift(bs["configs"], changes=bs["classified_changes"], production_impact=impact)
        out["drift"], out["measured_impact"] = drift_rows, impact
        gold_rec = m.TsBaselineReference.objects.filter(case=self.case, baseline_type="GOLDEN_CONFIG").first()
        if not done["drift"]:
            for d in drift_rows:
                repo.record(self.actor, self.case, "drift", basis="DERIVED", evidence_ids=[self.ev_ids["configs"]], now=self.now, baseline=gold_rec, subject=d["subject"],
                            expected=d["expected"], observed=d["observed"], delta=d["delta"], drift_kind=d["drift_kind"], approved_change_id=d["approved_change_id"],
                            production_impact=d["production_impact"], materiality=d["materiality"], conclusion=d["conclusion"][:255],
                            stage_decision="intent vs running; measured production impact takes priority over conformity")
        # changes as correlation records (never blame) ---------------------------------------------------------------
        if not done["corr"]:
            for r in ch_rows:
                if r["relation"] == "BEFORE_ONSET":
                    repo.record(self.actor, self.case, "correlation", basis="DERIVED", evidence_ids=[self.ev_ids["changes"]], now=self.now, alert_ids=[],
                                common_fault_candidate=f"change {r['change_id']}", topology_edge={"distance_to_path": r["topology_distance"], "devices": r["devices"]},
                                time_window={"seconds_before_onset": r["seconds_before_onset"], "in_soak": r["in_soak"]},
                                rules=["change before onset", "topology distance to path"], metrics={"score": r["score"], "approved": r["approved"]},
                                role="UNRELATED", drift_kind="APPROVED" if r["approved"] else "UNAPPROVED", confidence=r["score"],
                                conclusion=f"candidate only ({'approved' if r['approved'] else 'unapproved'}); no causal link established: {r['note']}"[:255],
                                stage_decision="change/time correlation; proximity is not blame")
        # alarm storm -------------------------------------------------------------------------------------------------
        if self.alarms and intent.get("links"):
            vantage = self.case.service_intent.get("vantage") or case_target(self.case)
            grp = corr.correlate_alarms(self.alarms, intent["links"], vantage=vantage, window_seconds=self.cfg.alarm_window_seconds)
            out["alarm_groups"] = grp
            if not done["corr"]:
                aev = self.ev_ids.get("alarms") or self.ev_ids["changes"]
                for g in grp["groups"]:
                    repo.record(self.actor, self.case, "correlation", basis="DERIVED", evidence_ids=[aev], now=self.now, alert_ids=g["alert_ids"],
                                common_fault_candidate=f"{g['cause_link']['a']}:{g['cause_link']['a_if']} <-> {g['cause_link']['b']}:{g['cause_link']['b_if']} ({g['primary']['kind']})",
                                topology_edge=g["cause_link"], time_window=g["time_window"], rules=g["rules"],
                                metrics={"symptoms": g["symptoms"], "rejected": len(g["rejected"]), "downstream_devices": g["downstream_devices"], "collapsed": g["collapsed"],
                                         "link_redundant": g["link_redundant"], "false_positive_risk": g["false_positive_risk"]},
                                role="CAUSE", confidence=g["confidence"], observed_value={"alerts": len(g["alert_ids"])}, baseline_value={"expected_alerts": 1},
                                conclusion=f"1 candidate fault explains {len(g['alert_ids'])} of {grp['total_alarms']} alarms; all alert ids preserved. {g['caveat']}"[:255],
                                stage_decision="topology- and time-aware alarm grouping")
                if grp["unrelated"]:
                    repo.record(self.actor, self.case, "correlation", basis="DERIVED", evidence_ids=[aev], now=self.now, alert_ids=[u["id"] for u in grp["unrelated"]],
                                common_fault_candidate="no common upstream fault", topology_edge={}, time_window={}, rules=["topology inconsistent or outside window"],
                                metrics={"reasons": {u["id"]: u["reason"] for u in grp["unrelated"][:200]}}, role="UNRELATED", confidence=0.0,
                                conclusion=f"{len(grp['unrelated'])} alarms not explained by any candidate; kept separate, not silently merged",
                                stage_decision="rejected from grouping")
        # scoped exceptions -------------------------------------------------------------------------------------------
        out["exceptions"] = self._evaluate_exceptions(view, flow)
        # production flow monitor -------------------------------------------------------------------------------------
        if flow:
            fh = view.latest("flow.health", flow.get("src", ""), flow.get("name", "svc"))
            if fh is not None and not fh.is_missing:
                v = fh.value
                out["flow_monitor"] = {"loss_pct": v.get("loss_pct"), "coverage_pct": v.get("coverage_pct")}
                if not done["flow"]:
                    repo.record(self.actor, self.case, "flow_monitor", basis="OBSERVED", evidence_ids=list(fh.evidence_ids), now=self.now,
                                selector={k: flow.get(k) for k in ("protocol", "port", "src", "dst", "vrf", "name")}, criticality=flow.get("criticality", "UNKNOWN"),
                                baseline={"loss_pct": v.get("baseline_loss_pct"), "slo": (bs["slo"].get("contract") or {})}, sample_windows=[{"window_s": v.get("window_s"), "samples": v.get("samples_n")}],
                                current_loss_pct=v.get("loss_pct"), uncertainty={"coverage_pct": v.get("coverage_pct"), "note": "unsampled flows are unknown, not healthy"},
                                coverage={"coverage_pct": v.get("coverage_pct")}, classification="PRODUCTION", stage_decision="production flow measured before/during investigation")
        self.ctx_parts = {"fwd": fwd, "rev": rev, "correlation": {"changes": ch_rows, "drift": drift_rows, "exceptions": out["exceptions"]}}
        alarm_groups = out["alarm_groups"] or {}
        repo.audit(self.actor, self.case, "CORRELATION_COMPLETE", decision=f"paths={len(out['paths'])} drift={len(drift_rows)} changes={len(ch_rows)} "
                   f"alarm_groups={len(alarm_groups.get('groups') or [])}", result="OK", now=self.now)
        return out

    def _measured_impact(self, view: EvidenceView, flow: dict) -> str:
        fh = view.latest("flow.health", flow.get("src", ""), flow.get("name", "svc")) if flow else None
        if fh is None or fh.is_missing or fh.freshness != c.FRESH:
            return "UNKNOWN"
        if fh.value.get("coverage_pct", 0) < self.cfg.min_flow_coverage_pct:
            return "UNKNOWN"
        slo = (self.bs["slo"].get("contract") or {}).get("max_loss_pct", 1.0)
        loss = fh.value.get("loss_pct", 0)
        return "NONE" if loss <= slo else ("OUTAGE" if loss >= 50 else "DEGRADED")

    def _evaluate_exceptions(self, view: EvidenceView, flow: dict) -> list[dict]:
        pol = list(m.TsExceptionPolicy.objects.filter(case=self.case))
        out = []
        if not pol or not flow:
            return out
        revs = {**self.current_revisions}
        revs.setdefault("golden", self.bs["golden"].get("revision", ""))
        for p in pol:
            status = repo.exception_status(p, revs, self.now)
            scope = p.scope or {}
            item = {"policy": p.record_id, "scope": scope, "status": status, "protocols": [], "suppressed": False, "reason": "", "expires_at": c.iso(p.expires_at)}
            for proto in scope.get("protocols", []):
                probe = view.latest("service.probe", flow.get("src", ""), proto)
                failing = bool(probe and not probe.is_missing and probe.value["ok"] < probe.value["sent"])
                sig = {"src": flow.get("src"), "dst": flow.get("dst"), "vrf": flow.get("vrf", "default"), "protocol": proto, "kind": "TEST_FAILURE", "production": proto == flow.get("protocol")}
                r = corr.exception_matches({"id": p.record_id, "scope": scope, "expires_at": c.iso(p.expires_at), "bound_revisions": p.bound_revisions,
                                            "status": "ACTIVE" if p.status == "ACTIVE" else p.status}, sig, current_revisions=revs, now=self.now)
                if r["suppressed"] and failing:
                    item["protocols"].append(proto)
                    item["suppressed"] = True
                item["reason"] = r["reason"]
                item["status"] = r["status"]
            out.append(item)
        return out

    # ------------------------------------------------------------------------------------------------------------------- test
    def _context(self) -> Ctx:
        bs = self.bs
        view = load_view(self.actor, self.case, self.now)
        intent = bs["intent"] if bs["intent"].get("status") == "available" else {"nodes": [], "links": []}
        cp = self.ctx_parts
        ctx = Ctx(view=view, now=self.now, case={"target": dict(self.case.service_intent.get("target", {})), "worked_before": self.case.worked_before,
                  "last_known_good_at": c.iso(self.case.last_known_good_at), "first_detected_at": c.iso(self.case.first_detected_at)},
                  flow=dict(self.case.flow_scope or {}), intent=intent, baselines=bs, changes=bs["classified_changes"], path_fwd=cp["fwd"], path_ret=cp["rev"],
                  results=self.results, intent_evidence_ids={**self.ev_ids}, alarms=self.alarms, correlation=cp["correlation"])
        return ctx

    def _hypothesis_records(self) -> dict[str, Any]:
        existing = {h.title: h for h in m.TsHypothesis.objects.filter(case=self.case)}
        out = {}
        for h in sorted(self.rb.hypotheses, key=lambda x: (x.rank, x.id)):
            title = f"[{self.rb.id}/{h.id}] {h.title}"
            if title in existing:
                out[h.id] = existing[title]
            else:
                out[h.id] = repo.record(self.actor, self.case, "hypothesis", basis="DERIVED", now=self.now, title=title, failure_domain=h.domain, ranking=h.rank,
                                        confidence=0.0, state="OPEN", test_ids=list(h.tests), proposed_by=f"engine@{ENGINE_VERSION}",
                                        stage_decision=f"runbook {self.rb.id} v{self.rb.version} hypothesis")
        return out

    def test(self) -> dict[str, Any]:
        ctx = self._context()
        strategy, why = (self.cfg.strategy, "strategy forced by configuration") if self.cfg.strategy else self.rb.select_strategy(ctx)
        if strategy not in self.rb.orders:
            raise ValueError(f"strategy {strategy!r} not defined for {self.rb.id}")
        if not self.case.isolation_strategy:
            self.case.isolation_strategy, self.case.strategy_rationale = strategy, why
            self.case.save()
            repo.audit(self.actor, self.case, "STRATEGY_SELECTED", decision=strategy, result="OK", rationale=why, now=self.now)
        else:
            strategy = self.case.isolation_strategy
        hyps = self._hypothesis_records()
        order = self.rb.order(strategy)
        recorded = {t.test_id: t for t in m.TsDiagnosticTest.objects.filter(case=self.case, attempt=1)}
        by_id = self.rb.by_id
        isolated: Finding | None = None
        isolated_by = ""
        executed = 0
        self.matrix = []
        for tid in order:
            spec = by_id[tid]
            if tid in recorded:                       # restart: reload, never repeat
                res = _result_from_row(recorded[tid])
                self.results[tid] = res
                if res.finding and res.verdict == "FAIL" and self._is_proof(res.finding):
                    isolated, isolated_by = isolated or res.finding, isolated_by or tid
                self.matrix.append(self._matrix_row(spec, res, resumed=True))
                continue
            ctx.used = []
            ctx.gaps = []
            na = self._applicability(spec, ctx)
            if na is not None:
                res = na
            elif executed >= self.cfg.max_tests:
                res = Result("SKIPPED", status="UNSAFE_TO_EXECUTE", reason=f"per-case test budget ({self.cfg.max_tests}) exhausted", summary="budget exhausted")
            elif isolated and not self.cfg.exhaustive and spec.cls == DISCRIMINATING:
                res = Result("SKIPPED", status="SKIPPED_AFTER_CONFIRMED_ISOLATION",
                             reason=f"root cause already proven by {isolated_by} ({isolated.id}, confidence {isolated.confidence}); this {spec.layer} test could not change the isolation",
                             summary="skipped after confirmed isolation")
            else:
                res = self._execute(spec, ctx)
                executed += res.status == "EXECUTED"
            self.results[tid] = res
            self._record(spec, res, ctx, hyps)
            self.matrix.append(self._matrix_row(spec, res))
            if res.verdict == "FAIL" and res.finding and self._is_proof(res.finding) and isolated is None:
                isolated, isolated_by = res.finding, tid
        self._update_hypotheses(hyps)
        counts = {v: sum(1 for r in self.results.values() if r.verdict == v) for v in c.VERDICTS}
        return {"strategy": strategy, "rationale": why, "order": order, "matrix": self.matrix, "counts": counts, "isolated_by": isolated_by,
                "applicable": sum(1 for r in self.matrix if r["applicable"]), "executed": sum(1 for r in self.matrix if r["status"] == "EXECUTED"),
                "stopped_early": bool(isolated and any(r["status"] == "SKIPPED_AFTER_CONFIRMED_ISOLATION" for r in self.matrix))}

    def _is_proof(self, f: Finding) -> bool:
        if not (f.causal and f.confidence >= PROOF_CONFIDENCE):
            return False
        # a finding that claims to explain the symptom is contradicted if the impact tests say the service is healthy
        for tid in self.rb.impact_tests:
            r = self.results.get(tid)
            if r is not None and r.verdict == "PASS" and f.id not in EXPECTED_FINDINGS and f.domain not in ("ops",):
                return False
        return True

    def _applicability(self, spec: TestSpec, ctx: Ctx) -> Result | None:
        for dep in spec.requires:
            r = self.results.get(dep)
            if r is not None and r.status == "NOT_APPLICABLE":
                return Result("SKIPPED", status="NOT_APPLICABLE", reason=f"prerequisite {dep} is not applicable: {r.reason}", summary="prerequisite not applicable")
            if r is None or r.status != "EXECUTED" or r.verdict not in ("PASS", "FAIL"):
                return Result("SKIPPED", status="NOT_APPLICABLE", reason=f"hard prerequisite {dep} did not produce a usable result ({r.verdict + '/' + r.status if r else 'not run'})",
                              summary="prerequisite unusable")
        if spec.applies is not None:
            try:
                ok_, why = spec.applies(ctx)
            except Gap as g:
                return Result("INCONCLUSIVE", reason=g.reason, summary=g.reason)
            except Exception as exc:  # pylint: disable=broad-exception-caught  # noqa: BLE001
                return Result("INCONCLUSIVE", reason=f"applicability check failed: {type(exc).__name__}: {exc}", summary="applicability error")
            if not ok_:
                return Result("SKIPPED", status="NOT_APPLICABLE", reason=why or "not applicable", summary=why)
        return None

    def _proven(self) -> list[tuple[str, Result, float, list[str]]]:
        """Root-cause candidates that meet the proof standard: a single causal finding >= PROOF_CONFIDENCE (not contradicted by the impact tests) or
        a CORROBORATED hypothesis group (>=2 causal FAILs >= 0.75, or 1 causal + >=2 non-causal FAILs >= 0.6), confidence max + 0.05 per extra FAIL."""
        out = []
        for tid, r in self.results.items():
            if r.verdict == "FAIL" and r.finding and self._is_proof(r.finding):
                out.append((tid, r, r.finding.confidence, [tid]))
        for h in self.rb.hypotheses:
            fails = [(t, self.results[t]) for t in h.tests if t in self.results and self.results[t].verdict == "FAIL" and self.results[t].finding]
            causal = [(t, r) for t, r in fails if r.finding.causal and r.finding.confidence >= 0.75]
            weak = [(t, r) for t, r in fails if not r.finding.causal and r.finding.confidence >= 0.6]
            if (len(causal) >= 2 or (len(causal) >= 1 and len(weak) >= 2)) and not any(t == o[0] for o in out for t, _ in causal[:1]):
                best_t, best = max(causal, key=lambda x: x[1].finding.confidence)
                if best.finding.id in EXPECTED_FINDINGS or not any(self.results.get(i) is not None and self.results[i].verdict == "PASS" and best.finding.domain != "ops" for i in self.rb.impact_tests):
                    out.append((best_t, best, round(min(0.95, best.finding.confidence + 0.05 * (len(fails) - 1)), 2), [t for t, _ in fails]))
        return sorted(out, key=lambda x: -x[2])

    def _execute(self, spec: TestSpec, ctx: Ctx) -> Result:
        try:
            res = spec.fn(ctx)
        except Gap as g:
            res = Result("UNAVAILABLE" if g.status == "UNAVAILABLE" else "INCONCLUSIVE", status="UNAVAILABLE" if g.status == "UNAVAILABLE" else "EXECUTED", reason=g.reason, summary=g.reason)
        except Exception as exc:  # pylint: disable=broad-exception-caught  # noqa: BLE001 - a buggy/unsupported test must not crash the pipeline nor fake a verdict
            res = Result("INCONCLUSIVE", reason=f"test raised {type(exc).__name__}: {exc}", summary="test error")
        res.evidence_ids = list(dict.fromkeys([*res.evidence_ids, *ctx.used]))
        if res.verdict in ("PASS", "FAIL") and not res.evidence_ids:
            res = Result("INCONCLUSIVE", reason=f"{spec.id} produced a {res.verdict} without citing evidence; downgraded", summary=res.summary, observed=res.observed)
        if res.verdict == "UNAVAILABLE":
            res.status = "UNAVAILABLE"
        if res.verdict == "SKIPPED" and res.status == "EXECUTED":
            res.status = "NOT_APPLICABLE"
        return res

    def _record(self, spec: TestSpec, res: Result, ctx: Ctx, hyps: dict) -> None:
        verdict = res.verdict if res.verdict in c.VERDICTS else "INCONCLUSIVE"
        reason = res.reason or (res.summary if verdict != "PASS" else "")
        if verdict != "PASS" and len(reason.strip()) < 8:
            reason = f"{res.status}: {res.summary or 'no detail'}"
        observed = {**res.observed, "_applicability": res.status}
        if res.finding:
            observed["_finding"] = res.finding.__dict__
        if ctx.gaps:
            observed["_gaps"] = list(ctx.gaps)
        target = res.target or case_target(self.case)
        doc = c.with_schema("test_verdict/1", {
            "test_id": spec.id, "test_version": spec.version, "target": target, "expected": spec.expected, "verdict": verdict, "reason": reason or "healthy expectation held",
            "hypothesis": hyps[spec.hypothesis].record_id, "hypothesized_condition": spec.condition, "preconditions": list(spec.requires),
            "command_or_api": spec.command or "normalized observations", "observed": json.loads(c.canonical_json(observed)),
            "observed_summary": res.summary, "interpretation": res.interpretation, "next_action": res.next_action, "evidence_ids": res.evidence_ids,
            "executed_at": c.iso(self.now), "basis": "DERIVED" if res.status == "EXECUTED" else "DERIVED"})
        repo.record_test(self.actor, self.case, doc, now=self.now)

    def _matrix_row(self, spec: TestSpec, res: Result, resumed: bool = False) -> dict:
        return {"test_id": spec.id, "version": spec.version, "title": spec.title, "layer": spec.layer, "class": spec.cls, "status": res.status, "verdict": res.verdict,
                "applicable": res.status not in ("NOT_APPLICABLE",), "reason": res.reason or "", "summary": res.summary, "hypothesis": spec.hypothesis,
                "evidence": list(res.evidence_ids), "resumed": resumed, "finding": res.finding.id if res.finding else ""}

    def _update_hypotheses(self, hyps: dict) -> None:
        for h in self.rb.hypotheses:
            rec = m.TsHypothesis.objects.get(pk=hyps[h.id].pk)
            if rec.state in ("CONFIRMED", "ELIMINATED"):
                continue
            rs = [(tid, self.results[tid]) for tid in h.tests if tid in self.results and self.results[tid].status == "EXECUTED"]
            fails = [(t, r) for t, r in rs if r.verdict == "FAIL"]
            passes = [(t, r) for t, r in rs if r.verdict == "PASS"]
            unresolved = [t for t, r in rs if r.verdict in ("INCONCLUSIVE", "UNAVAILABLE")]
            if fails:
                sup = list(dict.fromkeys(e for _, r in fails for e in r.evidence_ids))
                con = list(dict.fromkeys(e for _, r in passes for e in r.evidence_ids))
                proven_tests = {t for _, _, _, ts in self._proven() for t in ts}
                proven = any(t in proven_tests for t, _ in fails if self.results[t].finding.causal)
                conf = max((r.finding.confidence for _, r in fails if r.finding), default=0.5)
                repo.update_hypothesis(self.actor, rec, state="CONFIRMED" if proven else "SUPPORTED", rationale=f"failing: {', '.join(t for t, _ in fails)}",
                                       supporting=sup, contradicting=con, confidence=conf, now=self.now)
            elif passes and not unresolved and len(passes) == len([1 for t in h.tests if t in self.results and self.results[t].status in ("EXECUTED",)]):
                skipped_after = [t for t in h.tests if t in self.results and self.results[t].status == "SKIPPED_AFTER_CONFIRMED_ISOLATION"]
                if skipped_after:
                    continue                           # not fully examined: stays OPEN, never claimed eliminated
                repo.update_hypothesis(self.actor, rec, state="ELIMINATED", rationale=f"all applicable tests passed: {', '.join(t for t, _ in passes)}",
                                       contradicting=[e for _, r in passes for e in r.evidence_ids], confidence=0.0, now=self.now)

    # ---------------------------------------------------------------------------------------------------------------- diagnose
    def diagnose(self) -> dict[str, Any]:
        res = self.results
        fails = [(t, r) for t, r in res.items() if r.verdict == "FAIL" and r.finding]
        proven_full = self._proven()
        proven = [(t, r) for t, r, _, _ in proven_full]
        unresolved = sorted(t for t, r in res.items() if r.verdict in ("INCONCLUSIVE", "UNAVAILABLE") and r.status in ("EXECUTED", "UNAVAILABLE"))
        impact_status = {t: res[t].verdict for t in self.rb.impact_tests if t in res}
        golden_conf = [d for d in self.stages.get("correlate", {}).get("drift", []) if d["drift_kind"] == "NONE"]
        impaired = any(v == "FAIL" for v in impact_status.values())
        out: dict[str, Any] = {"impact_tests": impact_status, "production_impaired": impaired, "golden_conformant_but_impaired": bool(impaired and golden_conf and not any(
            d["drift_kind"] in ("APPROVED", "UNAPPROVED") for d in self.stages["correlate"]["drift"])),
            "inconclusive_tests": unresolved, "candidates": [{"test": t, "finding": r.finding.id, "title": r.finding.title, "confidence": r.finding.confidence,
                                                                "causal": r.finding.causal} for t, r in sorted(fails, key=lambda x: -x[1].finding.confidence)]}
        if proven:
            t, r = proven[0]
            f = r.finding
            pconf, ptests = proven_full[0][2], proven_full[0][3]
            expected = f.id in EXPECTED_FINDINGS
            out.update(outcome="EXPECTED_BEHAVIOR_CONFIRMED" if expected else "ROOT_CAUSE_IDENTIFIED_REMEDIATION_PENDING",
                       root_cause={"finding": f.id, "title": f.title, "device": f.device, "test": t, "confidence": pconf, "corroborating_tests": ptests, "evidence": list(dict.fromkeys(e for tt in ptests for e in self.results[tt].evidence_ids)),
                                   "remediation_hint": f.remediation_hint, "interpretation": r.interpretation},
                       counter_evidence=[{"test": tt, "summary": rr.summary} for tt, rr in res.items() if rr.verdict == "PASS" and rr.status == "EXECUTED"][:40])
            out["proposed_remediation"] = self.rb.remediations.get(f.id) if not expected else self.rb.remediations.get(f.id) or {"tier": 1, "action": "none"}
        elif not fails and not unresolved and res:
            out.update(outcome="EXPECTED_BEHAVIOR_CONFIRMED", root_cause=None, counter_evidence=[{"test": tt, "summary": rr.summary} for tt, rr in res.items() if rr.verdict == "PASS"][:40],
                       note="no applicable test found a fault; observed behaviour matches intent/contract")
        else:
            out.update(outcome="INCONCLUSIVE_ESCALATED", root_cause=None,
                       reason=("no causal finding reached proof confidence" if fails else "no fault found but evidence gaps remain") + f"; candidates={[f[1].finding.id for f in fails]}, gaps={unresolved}")
        out["config_drift_note"] = ("configuration conforms to golden yet the production service is impaired: conformity is NOT a healthy closure" if out["golden_conformant_but_impaired"] else "")
        self.case = repo.get_case(self.actor, self.case.case_id)
        self.case.confidence = (out.get("root_cause") or {}).get("confidence")
        self.case.save()
        repo.audit(self.actor, self.case, "DETERMINISTIC_DIAGNOSIS", decision=out["outcome"], result="OK", now=self.now,
                   rationale=((out.get("root_cause") or {}).get("title") or out.get("reason") or out.get("note") or "")[:400],
                   evidence_ids=list(((out.get("root_cause") or {}).get("evidence") or []))[:10])
        return out

    # --------------------------------------------------------------------------------------------------------------------- dossier
    def exhaustion_dossier(self) -> dict[str, Any]:
        rows = self.matrix
        applicable = [r for r in rows if r["applicable"]]
        examined = [r for r in applicable if r["status"] in ("EXECUTED", "UNAVAILABLE", "SKIPPED_AFTER_CONFIRMED_ISOLATION", "UNSAFE_TO_EXECUTE")]
        unexamined = [r["test_id"] for r in applicable if r not in examined]
        hyps = list(m.TsHypothesis.objects.filter(case=self.case))
        bs = self.bs
        diag = self.stages.get("diagnosis", {})
        refs = {r.evidence_id for r in m.TsEvidenceRef.objects.filter(case=self.case)}
        manifest = {
            "runbook": {"id": self.rb.id, "version": self.rb.version, "engine": ENGINE_VERSION},
            "strategy": {"name": self.case.isolation_strategy, "rationale": self.case.strategy_rationale},
            "applicability_matrix": rows, "applicable_count": len(applicable), "executed_count": sum(1 for r in rows if r["status"] == "EXECUTED"),
            "unexamined_applicable": unexamined,
            "skipped": [{"test_id": r["test_id"], "status": r["status"], "reason": r["reason"]} for r in rows if r["status"] not in ("EXECUTED",)],
            "hypotheses": {"eliminated": [h.title for h in hyps if h.state == "ELIMINATED"], "remaining": [h.title for h in hyps if h.state in ("OPEN", "UNVERIFIED")],
                           "supported": [h.title for h in hyps if h.state in ("SUPPORTED", "CONFIRMED")]},
            "normalized_observation_count": m.TsObservation.objects.filter(case=self.case).count(),
            "baselines": {"golden_revision": bs["golden"].get("revision"), "golden_url": bs["golden"].get("url"), "golden_link_ok": bs["golden"].get("link_ok"),
                          "soak_window": bs["soak_window"], "provenance": bl.distinct_provenance(bs)},
            "production_flow": {"measured_impact": self.stages.get("correlate", {}).get("measured_impact"), "monitor": self.stages.get("correlate", {}).get("flow_monitor"),
                                "impact_tests": diag.get("impact_tests")},
            "correlations": {"changes": [{k: r[k] for k in ("change_id", "approved", "relation", "topology_distance", "in_soak", "blame")} for r in self.stages.get("correlate", {}).get("changes", [])],
                             "drift": [{"subject": d["subject"], "kind": d["drift_kind"], "impact": d["production_impact"]} for d in self.stages.get("correlate", {}).get("drift", [])],
                             "alarm_groups": len((self.stages.get("correlate", {}).get("alarm_groups") or {}).get("groups", []))},
            "topology_path": self.stages.get("correlate", {}).get("paths", []),
            "collection_gaps": sorted({g for r in self.results.values() for g in r.observed.get("_gaps", [])} | {f"{x['key']}@{x['target']}: {x['reason']}" for x in self.stages.get("normalize", {}).get("missing", [])}),
            "diagnosis": {k: diag.get(k) for k in ("outcome", "root_cause", "candidates", "inconclusive_tests", "reason", "note")},
        }
        uncertainty = diag.get("reason") or ("; ".join(f"{t}" for t in diag.get("inconclusive_tests", [])) or "none")
        return c.assert_valid(c.with_schema("ai_handoff/1", {
            "case_id": self.case.case_id, "coverage_manifest": json.loads(c.canonical_json(manifest)), "trigger_uncertainty": c.redact_text(uncertainty)[0],
            "allowed_tools": list(READ_ONLY_TOOLS), "allowed_targets": list(self.case.affected_scope.get("devices", [])),
            "budget": {"max_tool_calls": 25, "max_wall_clock_s": 900, "max_devices": len(self.case.affected_scope.get("devices", [])), "max_bytes": 262144, "concurrency": 1,
                       "read_only": True},
            "evidence_ids": sorted(refs), "return_conditions": ["root cause established with evidence", "budget exhausted", "permission or fixture unavailable (explicit case state)",
                                                                  "a write is needed (proposal only: NMAS governance decides)"],
            "agent_identity": ""}), "ai_handoff/1")


# ------------------------------------------------------------------------------------------------------------- handoff gate / API
def handoff_gate(dossier: dict, *, purpose: str = "CONTINUED_INVESTIGATION") -> dict[str, Any]:
    """Pure policy: is AI handoff permitted?  Refuses while safe applicable tests are unexamined or the case is not actually unresolved."""
    cm = dossier["coverage_manifest"]
    reasons = []
    if cm["unexamined_applicable"]:
        reasons.append(f"safe applicable tests not examined: {cm['unexamined_applicable']}")
    m_ = {r["test_id"]: r for r in cm["applicability_matrix"]}
    superficial = cm["executed_count"] < 3
    if superficial:
        reasons.append(f"only {cm['executed_count']} test(s) executed; a failed ping or a single check never justifies handoff")
    outcome = (cm["diagnosis"] or {}).get("outcome")
    if purpose == "CONTINUED_INVESTIGATION" and outcome != "INCONCLUSIVE_ESCALATED":
        reasons.append(f"deterministic outcome is {outcome}; continued AI investigation is only for unresolved cases (use purpose=EXPLANATION for an explanation)")
    if not cm["baselines"].get("provenance"):
        reasons.append("baseline provenance missing")
    for r in cm["applicability_matrix"]:
        if r["status"] in ("NOT_APPLICABLE", "UNAVAILABLE", "UNSAFE_TO_EXECUTE", "SKIPPED_AFTER_CONFIRMED_ISOLATION") and len((r["reason"] or "").strip()) < 8:
            reasons.append(f"{r['test_id']}: skip without a specific reason")
    del m_
    return {"allowed": not reasons, "purpose": purpose, "reasons": reasons}


def request_ai_handoff(actor: repo.Actor, case, dossier: dict, *, purpose: str = "CONTINUED_INVESTIGATION", now: datetime | None = None):
    gate = handoff_gate(dossier, purpose=purpose)
    if not gate["allowed"]:
        repo.audit(actor, case, "AI_HANDOFF_REFUSED", decision="; ".join(gate["reasons"])[:250], result="REFUSED", now=now)
        raise HandoffRefused("; ".join(gate["reasons"]))
    c.assert_valid(dossier, "ai_handoff/1")
    return repo.record(actor, case, "ai_handoff", basis="DERIVED", evidence_ids=dossier["evidence_ids"][:50], now=now, coverage_manifest=dossier["coverage_manifest"],
                       trigger_uncertainty=dossier["trigger_uncertainty"], allowed_tools=dossier["allowed_tools"], allowed_targets=dossier["allowed_targets"],
                       budget=dossier["budget"], return_conditions=dossier["return_conditions"], status="OPEN",
                       stage_decision=f"handoff permitted ({purpose}) after deterministic coverage")


def disposition_for(diag: dict) -> dict[str, Any]:
    """Honest disposition payload for ``close_case`` / the report: never 'resolved' without service verification (spec 0.1)."""
    out = diag["outcome"]
    rc = diag.get("root_cause") or {}
    return {"outcome": out,
            "resolved": "NO: no remediation executed or verified" if out != "RESOLVED_VERIFIED" else "yes",
            "unchanged_or_expected": rc.get("title") if out == "EXPECTED_BEHAVIOR_CONFIRMED" else "—",
            "remaining_to_fix": (f"{rc.get('title')} — {rc.get('remediation_hint')}" if out == "ROOT_CAUSE_IDENTIFIED_REMEDIATION_PENDING" else "unknown: " + str(diag.get("reason", ""))
                                 if out == "INCONCLUSIVE_ESCALATED" else "nothing"),
            "externally_blocked": "—"}


def proposed_remediations(rb: Runbook, diag: dict) -> list[dict]:
    """Governed-remediation SKELETONS for s5: never executed here, always Tier 2+ approval; includes explicit 'never' list."""
    rc = diag.get("root_cause")
    if not rc:
        return []
    sk = rb.remediations.get(rc["finding"])
    return [{"finding": rc["finding"], "device": rc["device"], "executed": False, **(sk or {"tier": 2, "action": "no runbook remediation defined: manual analysis", "approvals": ["operator"], "never": []})}]


def compare_runs(before: dict[str, Result | dict], after: dict[str, Result | dict]) -> dict[str, Any]:
    """Pre/post verdict table for verification (fault vs recovery run).  Accepts engine ``matrix`` rows keyed by test id."""
    rows, regress = [], []
    for tid in sorted(set(before) | set(after)):
        b, a = before.get(tid), after.get(tid)
        bv, av = (b or {}).get("verdict", "-"), (a or {}).get("verdict", "-")
        rows.append({"test": tid, "before": bv, "after": av, "changed": bv != av})
        if bv == "PASS" and av == "FAIL":
            regress.append(tid)
    fixed = [r["test"] for r in rows if r["before"] == "FAIL" and r["after"] == "PASS"]
    still = [r["test"] for r in rows if r["after"] == "FAIL"]
    return {"rows": rows, "fixed": fixed, "regressions": regress, "still_failing": still, "recovered": bool(fixed) and not still and not regress}
