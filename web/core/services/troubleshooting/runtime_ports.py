"""Runtime bindings of the governance ``Ports`` onto EXISTING NMAS services, plus persistent soak monitoring (spec 6.2-6.4).

Nothing here invents capability.  Every port FAILS CLOSED:

=====================  ======================================================  =====================================================
governance port        existing NMAS service composed                          when that service cannot answer
=====================  ======================================================  =====================================================
``device_state``       health.inventory (authoritative managed devices),       ``NOT_IN_INVENTORY`` / maintenance ``None`` -> the
                       Change/ChangeTarget decommission lifecycle, optional    precheck BLOCKS (case-supplied target_states can no
                       injected maintenance + golden-comparison providers      longer substitute for the authority)
``alternate_paths``    an injected, already-configured redundancy provider     ``verified=False`` -> NO_VERIFIED_ALTERNATE_PATH
                       (ECMP/MLAG/FHRP/IGP backup evidence) cross-checked      (redundancy is never inferred from topology alone)
                       against health.telemetry link state
``flow_sample``        an injected production-flow source (monitoring/NetFlow) ``loss_pct=None, coverage=0`` (never "0% loss")
``step_up``            an injected verifier (NMAS has no MFA service)          returns False -> STEP_UP_REQUIRED
``executor``           ``governance.ChangeEngineExecutor`` (read-only          writes DISABLED unless ``writes_enabled=True``;
                       eligibility gate; execution is a hand-off to the       ``supports()`` is False so nothing reaches EXECUTING;
                       Change page) wrapped by ``WriteGuardedExecutor``        the hand-off executor never supports execution
read-back              injected config reader -> canonical digest              ``READBACK_UNAVAILABLE`` -> restoration unprovable
compensation           rollback_service.execute_rollback on a PRE-BUILT        ``COMPENSATION_UNAVAILABLE`` -> ABORTED_UNRESTORED
                       rollback plan (``rollback_runner_from_service``)
=====================  ======================================================  =====================================================

Persistent soak ledger
----------------------
After an applied plan, ``tick()`` appends production-flow samples to ``TsRemediationPlan.approval["soak_ledger"]`` (a mutable JSON column
on an existing table) and to the named ``TsProductionFlowMonitor`` rows.  The ledger pins the window/cadence/thresholds at start and is
re-assessed from persisted data on every call, so a restart loses nothing and a late sampler cannot rewrite history:

* ``DEGRADED`` (sticky): any sample with production-loss increase, or a required flow missing/unmeasurable-with-data, ends the window.
  A later recovered sample does NOT clear it; only an explicit audited ``reset_window`` starts a fresh window.
* ``INTERRUPTED`` (sticky): a stretch longer than ``max_gap_seconds`` without a usable sample (incl. leading edge from the applied time and
  the live trailing edge) means monitoring was blind, so the window cannot prove cleanliness.
* ``PASSED`` needs: elapsed >= window, no degraded sample, no gap, bucket coverage >= ``min_coverage``.  A deadline alone never passes.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Callable

from django.db import transaction

from core import models as m

from . import contracts as c
from . import governance as gov
from . import repository as repo

LEDGER_SCHEMA = "nmas.troubleshooting.soak_ledger/1"
DEFAULT_WINDOW = timedelta(minutes=30)
MIN_WINDOW = DEFAULT_WINDOW
DEFAULT_INTERVAL_S = 60
DEFAULT_MAX_GAP_S = 180
DEFAULT_MIN_COVERAGE = 0.8
MAX_SAMPLES = 2000
MAX_WINDOW_SAMPLES = 500
ACTIVE_PLAN_STATES = ("VERIFYING", "SOAKING")
DECOMMISSION_BLOCKING_LIFECYCLE = ("DRAFT", "VALIDATED", "CI_PENDING", "READY_TO_DEPLOY", "DEPLOYING", "DEPLOYED", "UAT", "PROBATION")


def _now() -> datetime:
    return datetime.now(timezone.utc)


# ===================================================================================================== write guard / executor
class WriteGuardedExecutor:
    """Writes are DISABLED by default.  ``supports()`` is False while disabled, so dry-run BLOCKS the plan long before EXECUTING;
    ``apply``/``compensate`` additionally refuse (defence in depth).  Read-only dry-run/readback are delegated."""
    configured = True

    def __init__(self, inner: Any, *, writes_enabled: bool = False):
        self.inner, self.writes_enabled = inner, bool(writes_enabled)

    def supports(self, op: dict) -> bool:
        return self.writes_enabled and bool(getattr(self.inner, "configured", False)) and self.inner.supports(op)

    @property
    def unsupported_reason(self) -> str:
        if not self.writes_enabled:
            return "production writes are disabled (writes_enabled=False)"
        return str(getattr(self.inner, "HANDOFF_REASON", "") or "")

    def dry_run(self, plan: dict) -> dict:
        if not self.writes_enabled:
            return {"ok": False, "errors": ["production writes are disabled (writes_enabled=False)"]}
        return self.inner.dry_run(plan)

    def apply(self, op: dict) -> dict:
        if not self.writes_enabled:
            raise gov.GovernanceRefused("WRITES_DISABLED", "production writes are disabled")
        return self.inner.apply(op)

    def readback(self, plan: dict) -> dict:
        return self.inner.readback(plan)

    def compensate(self, plan: dict, applied: list[dict]) -> dict:
        if not self.writes_enabled:
            raise gov.GovernanceRefused("WRITES_DISABLED", "production writes are disabled")
        out = self.inner.compensate(plan, applied)
        bad = [r for r in (out.get("results") or []) if not (r or {}).get("ok")]
        if bad:                                   # a compensation that did not report success is a failure, never "probably fine"
            raise gov.GovernanceRefused("COMPENSATION_FAILED", f"{len(bad)} rollback step(s) did not succeed")
        return out


def rollback_runner_from_service(plan_lookup: Callable[[str], Any], *, actor: str = "troubleshooting", executor_factory=None) -> Callable[[str], dict]:
    """Compensation through the EXISTING rollback service.  ``plan_lookup(change_id)`` must return a PRE-BUILT, operator-reviewed
    ``RollbackPlan`` (this never builds one on the fly); ``None`` -> refuse.  Success only when the service reports SUCCEEDED."""
    def run(change_id: str) -> dict:
        plan = plan_lookup(change_id)
        if plan is None:
            raise gov.GovernanceRefused("COMPENSATION_UNAVAILABLE", f"no pre-built rollback plan for {change_id}")
        try:
            # The operator-driven rollback service (legacy Phase-21 work) has not been ported to this repository yet.  Until it
            # is, compensation through it is UNAVAILABLE -- an explicit governed refusal, never an import crash mid-abort.
            from core.services import rollback_service
            succeeded = m.RollbackOutcome.SUCCEEDED
        except (ImportError, AttributeError):
            raise gov.GovernanceRefused("COMPENSATION_UNAVAILABLE", "the rollback service is not available in this deployment") from None
        res = rollback_service.execute_rollback(plan, actor=actor, executor_factory=executor_factory)
        ok = bool(res.ran) and not res.refused and str(res.outcome) == str(succeeded)
        return {"ok": ok, "outcome": str(res.outcome), "refused": bool(res.refused), "blockers": [b.get("code") for b in (res.blockers or [])]}
    return run


def digest_readback(config_reader: Callable[[str], Any] | None) -> Callable[[dict], dict]:
    """Read-back = per-device digest of the live/running config from an injected reader.  Any failure/None -> raise (unavailable)."""
    def read(plan: dict) -> dict:
        if config_reader is None:
            raise gov.GovernanceRefused("READBACK_UNAVAILABLE", "no config reader configured")
        out = {}
        for dev in sorted({o["device"] for o in plan["operations"]}):
            cfg = config_reader(dev)
            if cfg is None:
                raise gov.GovernanceRefused("READBACK_UNAVAILABLE", f"{dev}: configuration not readable")
            out[dev] = c.sha256_text(cfg if isinstance(cfg, str) else c.canonical_json(cfg))
        return out
    return read


# ========================================================================================================== device state port
class DeviceStatePort:
    """Authoritative per-device admission: managed inventory first, then Change lifecycle (decommission in flight), then maintenance.

    ``maintenance(device) -> bool | None`` and ``golden(device) -> {"match": bool|None, "revision": str}`` are optional providers; absent
    maintenance is UNKNOWN (``None``) and the governance precheck blocks on it."""

    def __init__(self, *, inventory: Callable[[], dict] | None = None, maintenance: Callable[[str], bool | None] | None = None,
                 golden: Callable[[str], dict | None] | None = None):
        self._inventory, self._maintenance, self._golden = inventory, maintenance, golden

    def _inv(self) -> dict:
        if self._inventory is not None:
            return self._inventory()
        from core.services.health import inventory
        return inventory.managed_devices()

    def __call__(self, device: str) -> dict:
        try:
            known = self._inv()
        except Exception as exc:  # pylint: disable=broad-exception-caught  # noqa: BLE001 - unreadable inventory admits nobody
            return {"admission": "INVENTORY_UNAVAILABLE", "maintenance": None, "lifecycle": "UNKNOWN", "reason": type(exc).__name__}
        if device not in known:
            # NOT "UNKNOWN": governance falls back to case.target_states for UNKNOWN, which would let the case bypass the authority.
            return {"admission": "NOT_IN_INVENTORY", "maintenance": None, "lifecycle": "UNKNOWN", "reason": "device not in authoritative inventory"}
        lifecycle, maint = "ACTIVE", None
        decom = m.Change.objects.filter(category=m.ChangeCategory.DECOMMISSION, targets__device_name=device,
                                        lifecycle_state__in=DECOMMISSION_BLOCKING_LIFECYCLE).exists()
        if decom:
            lifecycle = "DECOMMISSIONING"
        if self._maintenance is not None:
            try:
                maint = self._maintenance(device)
            except Exception:  # pylint: disable=broad-exception-caught  # noqa: BLE001
                maint = None
        if decom:
            maint = True
        out = {"admission": "VERIFIED", "maintenance": maint, "lifecycle": lifecycle}
        if self._golden is not None:
            try:
                g = self._golden(device)
            except Exception:  # pylint: disable=broad-exception-caught  # noqa: BLE001
                g = None
            out["golden"] = {"match": (g or {}).get("match"), "revision": (g or {}).get("revision", "")} if g else {"match": None, "revision": ""}
        return out


# ======================================================================================================== alternate path port
class AlternatePathPort:
    """Existing redundancy only.  ``provider(request, op) -> {"mechanism", "edges": [edge ids], "capacity_ok", "lossless_demonstrated",
    "evidence_ids"} | None``.  No provider / no answer / any edge not UP in current telemetry => ``verified=False``."""

    def __init__(self, provider: Callable[[dict, dict], dict | None] | None = None, *, link_status: Callable[[str], str | None] | None = None):
        self.provider, self._link_status = provider, link_status

    @staticmethod
    def _refuse(reason: str) -> dict:
        return {"verified": False, "capacity_ok": False, "lossless_demonstrated": False, "evidence_ids": [], "reason": reason}

    def _status(self, edge_id: str) -> str | None:
        if self._link_status is not None:
            return self._link_status(edge_id)
        from core.services.health import telemetry
        snap = telemetry.collect()
        if not snap.available:
            return None
        for e in snap.edges:
            if e.get("id") == edge_id:
                return str(e.get("status") or "UNKNOWN").upper()
        return None

    def __call__(self, request: dict, op: dict) -> dict:
        if self.provider is None:
            return self._refuse("no redundancy provider configured")
        try:
            alt = self.provider(request, op)
        except Exception as exc:  # pylint: disable=broad-exception-caught  # noqa: BLE001
            return self._refuse(f"redundancy provider failed: {type(exc).__name__}")
        if not alt or not alt.get("mechanism") or not alt.get("edges"):
            return self._refuse("no existing redundancy mechanism/path reported")
        try:
            down = [e for e in alt["edges"] if self._status(e) != "UP"]
        except Exception:  # pylint: disable=broad-exception-caught  # noqa: BLE001
            return self._refuse("telemetry unavailable; alternate path liveness unknown")
        if down:
            return self._refuse(f"alternate path edge(s) not UP in telemetry: {','.join(map(str, down))}")
        return {"verified": True, "capacity_ok": alt.get("capacity_ok") is True, "lossless_demonstrated": alt.get("lossless_demonstrated") is True,
                "evidence_ids": list(alt.get("evidence_ids") or []), "mechanism": alt["mechanism"], "edges": list(alt["edges"])}


# ========================================================================================================= step-up / approval
def step_up_port(verifier: Callable[[str, str], bool] | None) -> Callable[[repo.Actor, Any], bool]:
    """NMAS has no MFA service; a verifier(actor_name, plan_id) must be injected.  Missing/erroring verifier => False (fail closed)."""
    def check(actor: repo.Actor, plan) -> bool:
        if verifier is None:
            return False
        try:
            return verifier(actor.name, plan.record_id) is True
        except Exception:  # pylint: disable=broad-exception-caught  # noqa: BLE001
            return False
    return check


# ============================================================================================================== flow sampling
def _loss_of(raw: dict | None) -> tuple[float | None, float]:
    """Normalise a source reading to (loss_pct|None, coverage 0..1).  Missing numbers are NEVER treated as zero loss."""
    if not isinstance(raw, dict):
        return None, 0.0
    cov = raw.get("coverage")
    loss = raw.get("loss_pct")
    sent, lost = raw.get("sent"), raw.get("lost")
    if loss is None and isinstance(sent, (int, float)) and isinstance(lost, (int, float)) and sent > 0:
        loss = 100.0 * lost / sent
        if cov is None and isinstance(raw.get("expected"), (int, float)) and raw["expected"] > 0:
            cov = min(1.0, sent / raw["expected"])
    if not isinstance(loss, (int, float)) or isinstance(loss, bool) or math.isnan(loss) or loss < 0:
        return None, 0.0
    if not isinstance(cov, (int, float)) or isinstance(cov, bool) or not (0.0 <= cov <= 1.0):
        return None, 0.0
    return float(loss), float(cov)


class FlowSampler:
    """``governance.Ports.flow_sample`` binding.  ``source(flow) -> {"loss_pct","coverage"} | {"sent","lost","expected"} | None``.
    Only PRODUCTION flows are measurable guards: test traffic / intentionally blocked flows are reported ``excluded`` (loss None)."""

    def __init__(self, actor: repo.Actor | None, case: m.TsCase | None, source: Callable[[dict], dict | None] | None, *,
                 clock: Callable[[], datetime] = _now, persist: bool = True):
        self.actor, self.case, self.source, self.clock, self.persist = actor, case, source, clock, persist and case is not None and actor is not None

    def __call__(self, flows: list[dict]) -> dict:
        now, out = self.clock(), {}
        for f in flows:
            key = f.get("key")
            if not key:
                continue
            cls = str(f.get("classification") or "PRODUCTION")
            if cls != "PRODUCTION":
                out[key] = {"loss_pct": None, "coverage": 0.0, "excluded": cls, "sampled_at": c.iso(now)}
                continue
            if self.source is None:
                loss, cov, why = None, 0.0, "no production-flow source configured"
            else:
                try:
                    loss, cov = _loss_of(self.source(f))
                    why = "" if loss is not None else "source returned no usable measurement"
                except Exception as exc:  # pylint: disable=broad-exception-caught  # noqa: BLE001
                    loss, cov, why = None, 0.0, f"source error {type(exc).__name__}"
            out[key] = {"loss_pct": loss, "coverage": cov, "sampled_at": c.iso(now), **({"reason": why} if why else {})}
            if self.persist:
                self._persist(f, out[key], now)
        return out

    def _persist(self, flow: dict, sample: dict, now: datetime) -> None:
        try:
            case = m.TsCase.objects.get(pk=self.case.pk)
            mon = next((x for x in m.TsProductionFlowMonitor.objects.filter(case=case) if (x.selector or {}).get("key") == flow["key"]), None)
            if mon is None:
                mon = repo.record(self.actor, case, "flow_monitor", basis="OBSERVED", selector={k: v for k, v in flow.items() if k != "classification"},
                                  criticality=str(flow.get("criticality", "UNKNOWN")), classification=str(flow.get("classification") or "PRODUCTION"),
                                  stage_decision=f"monitor {flow['key']}", now=now)
            windows = list(mon.sample_windows or [])
            windows.append({"at": sample["sampled_at"], "loss_pct": sample["loss_pct"], "coverage": sample["coverage"]})
            dropped = max(0, len(windows) - MAX_WINDOW_SAMPLES)
            mon.sample_windows = windows[-MAX_WINDOW_SAMPLES:]
            mon.current_loss_pct = sample["loss_pct"]
            mon.coverage = {"latest": sample["coverage"], "samples": len(windows) + (mon.coverage or {}).get("truncated", 0), "truncated": (mon.coverage or {}).get("truncated", 0) + dropped}
            mon.uncertainty = {"measurable": sample["loss_pct"] is not None, "note": "" if sample["loss_pct"] is not None else sample.get("reason", "unmeasured")}
            mon.save()
        except Exception:  # pylint: disable=broad-exception-caught  # noqa: BLE001 - persistence trouble must not turn into a healthy-looking sample; the ledger is the authority
            pass


# ======================================================================================================= soak ledger (pure part)
def _p(ts: str) -> datetime:
    return c.parse_time(ts)


def _new_ledger(plan, execution, now: datetime, window: timedelta, flows: list[dict], *, interval_s: int, max_gap_s: int, min_coverage: float) -> dict:
    started = execution.executed_at or now
    th = plan.approval.get("abort_thresholds") or gov.DEFAULT_ABORT
    return {"schema": LEDGER_SCHEMA, "started_at": c.iso(started), "window_seconds": int(window.total_seconds()), "interval_seconds": int(interval_s),
            "max_gap_seconds": int(max_gap_s), "min_bucket_coverage": float(min_coverage), "max_loss_increase_pct": float(th["max_loss_increase_pct"]),
            "min_flow_coverage": float(th["min_coverage"]), "flows": [{"key": f["key"], **({"classification": f["classification"]} if f.get("classification") else {})}
                                                                       for f in flows if f.get("key")],
            "baseline": {k: (v or {}).get("loss_pct") for k, v in (execution.command_or_intent.get("baseline_flows") or {}).items()},
            "execution": execution.record_id, "samples": [], "rejected": 0, "resets": []}


def sample_issue(ledger: dict, flows: dict) -> tuple[str, list[str]]:
    """Classify one reading -> ('usable'|'unusable'|'degraded', reasons).  Degraded beats unusable: observed loss is never forgiven."""
    degraded, unusable = [], []
    for f in ledger["flows"]:
        key, s = f["key"], (flows.get(f["key"]) or {})
        loss = s.get("loss_pct")
        if loss is None:
            unusable.append(f"{key}: not measurable ({s.get('reason') or s.get('excluded') or 'missing from sample'})")
            continue
        if (s.get("coverage") or 0) < ledger["min_flow_coverage"]:
            unusable.append(f"{key}: coverage {s.get('coverage')} < {ledger['min_flow_coverage']}")
        base = (ledger["baseline"].get(key) or 0.0)
        if loss - base > ledger["max_loss_increase_pct"]:
            degraded.append(f"{key}: loss {loss}% vs {base}% before (> +{ledger['max_loss_increase_pct']}%)")
    if degraded:
        return "degraded", degraded
    return ("unusable", unusable) if unusable else ("usable", [])


def assess_ledger(ledger: dict | None, now: datetime) -> dict:
    """Pure, deterministic judgement of a persisted ledger.  See module docstring for the rules."""
    if not ledger:
        return {"state": "NO_EVIDENCE", "reasons": ["no soak ledger: the monitoring sampler never recorded this window"], "samples": 0, "coverage": 0.0}
    start, window = _p(ledger["started_at"]), timedelta(seconds=ledger["window_seconds"])
    end, gap = start + window, timedelta(seconds=ledger["max_gap_seconds"])
    interval = ledger["interval_seconds"]
    samples = sorted(ledger["samples"], key=lambda s: s["at"])
    reasons: list[str] = []
    degraded = [s for s in samples if s["class"] == "degraded"]
    for s in degraded:
        reasons += [f"{s['at']}: {r}" for r in s["reasons"]]
    usable = [_p(s["at"]) for s in samples if s["class"] == "usable"]
    # gaps are judged over [start, min(now, end)]: leading edge, interior, and (live) trailing edge
    horizon, gaps, prev = min(now, end), [], start
    for t in usable:
        t = min(t, horizon) if t > horizon else t
        if t - prev > gap:
            gaps.append((prev, t))
        prev = max(prev, t)
    if horizon - prev > gap:
        gaps.append((prev, horizon))
    for a, b in gaps:
        reasons.append(f"monitoring gap {c.iso(a)} -> {c.iso(b)} ({int((b - a).total_seconds())}s > {ledger['max_gap_seconds']}s)")
    total_buckets = max(1, math.ceil(ledger["window_seconds"] / interval))
    covered = len({min(int((t - start).total_seconds() // interval), total_buckets - 1) for t in usable if start <= t <= end + gap})
    cov = round(covered / total_buckets, 3)
    out = {"samples": len(samples), "usable_samples": len(usable), "coverage": cov, "started_at": ledger["started_at"], "ends_at": c.iso(end),
           "elapsed_seconds": int(max(0.0, (min(now, end) - start).total_seconds())), "gaps": len(gaps), "degraded_samples": len(degraded)}
    if degraded:
        return {**out, "state": "DEGRADED", "reasons": reasons}
    if gaps:
        return {**out, "state": "INTERRUPTED", "reasons": reasons}
    if now < end:
        return {**out, "state": "RUNNING", "reasons": ["window still open"]}
    if cov < ledger["min_bucket_coverage"]:
        return {**out, "state": "INCOMPLETE", "reasons": reasons + [f"sample coverage {cov} < required {ledger['min_bucket_coverage']}"]}
    return {**out, "state": "PASSED", "reasons": []}


# ================================================================================================== soak ledger (persistence)
def read_ledger(plan: m.TsRemediationPlan) -> dict | None:
    return (m.TsRemediationPlan.objects.get(pk=plan.pk).approval or {}).get("soak_ledger")


def plan_soak_status(plan: m.TsRemediationPlan, now: datetime, *, window: timedelta | None = None) -> dict:
    """Used by ``verification.verify``: judgement of the PERSISTED ledger.  No ledger => NO_EVIDENCE (RUNNING-equivalent until the
    deadline derived from the applied time, INCOMPLETE after it) -- the deadline alone never produces PASSED."""
    ledger = read_ledger(plan)
    st = assess_ledger(ledger, now)
    if st["state"] == "NO_EVIDENCE":
        ex = m.TsActionExecution.objects.filter(plan=plan, status="APPLIED").order_by("-id").first()
        started = (ex.executed_at if ex and ex.executed_at else now)
        ends = started + (window or DEFAULT_WINDOW)
        st.update({"started_at": c.iso(started), "ends_at": c.iso(ends)})
        if now >= ends:
            st["state"], st["reasons"] = "INCOMPLETE", st["reasons"] + ["soak window elapsed with no sampled production evidence"]
        else:
            st["state"], st["reasons"] = "RUNNING", ["window open; no production sample recorded yet (deadline alone cannot pass)"]
    elif window is not None and int(window.total_seconds()) > ledger["window_seconds"] and st["state"] in ("RUNNING", "PASSED"):
        # a verifier may never shorten the pinned window, and a short ledger cannot vouch for a longer one
        st = {**st, "state": "INCOMPLETE", "reasons": st["reasons"] + [f"pinned soak window {ledger['window_seconds']}s is shorter than the required {int(window.total_seconds())}s"]}
    return st


def start_window(actor: repo.Actor, plan_id: str, *, window: timedelta = DEFAULT_WINDOW,
                 surrounding_flows: list[dict] | None = None, interval_s: int = DEFAULT_INTERVAL_S, max_gap_s: int = DEFAULT_MAX_GAP_S,
                 min_coverage: float = DEFAULT_MIN_COVERAGE, now: datetime | None = None) -> dict:
    """Idempotently pin the ledger for an applied plan (first call wins).  Does not take a sample."""
    now = now or _now()
    with transaction.atomic():
        plan = gov.get_plan(actor, plan_id)
        plan = m.TsRemediationPlan.objects.select_for_update().get(pk=plan.pk)
        if plan.status not in ACTIVE_PLAN_STATES:
            raise gov.GovernanceRefused("NOT_SOAKABLE", f"plan is {plan.status}")
        ex = m.TsActionExecution.objects.filter(plan=plan, status="APPLIED").order_by("-id").first()
        if ex is None:
            raise gov.GovernanceRefused("NO_APPLIED_EXECUTION", "no applied execution to soak")
        if (plan.approval or {}).get("soak_ledger"):
            return plan.approval["soak_ledger"]
        flows = list(plan.impacted_flows) + [f for f in (surrounding_flows or []) if f.get("key") not in {x.get("key") for x in plan.impacted_flows}]
        if not flows:
            raise gov.GovernanceRefused("NO_PRODUCTION_FLOWS", "a soak needs at least one named production flow to monitor")
        ledger = _new_ledger(plan, ex, now, window, flows, interval_s=interval_s, max_gap_s=max_gap_s, min_coverage=min_coverage)
        plan.approval = {**plan.approval, "soak_ledger": ledger}
        plan.save()
        repo.audit(actor, plan.case, "SOAK_WINDOW_STARTED", decision=f"{plan.record_id} {int(window.total_seconds())}s", result="OK", risk=plan.risk,
                   operation=plan.record_id, now=now)
        return ledger


def tick(actor: repo.Actor, plan_id: str, sampler: Callable[[list], dict], *, window: timedelta = DEFAULT_WINDOW,
         surrounding_flows: list[dict] | None = None, now: datetime | None = None, **pin) -> dict:
    """Take ONE sample for an active soak, append it durably and return the assessment.  Safe to call after any restart: all state
    is read from the database; a clock that moved backwards is rejected, never fabricated into continuity."""
    now = now or _now()
    ledger = start_window(actor, plan_id, window=window, surrounding_flows=surrounding_flows, now=now, **pin)
    plan = gov.get_plan(actor, plan_id)
    reading = sampler([{**f, "key": f["key"]} for f in _flow_defs(plan, ledger)]) if ledger["flows"] else {}
    cls, why = sample_issue(ledger, reading)
    with transaction.atomic():
        plan = m.TsRemediationPlan.objects.select_for_update().get(pk=plan.pk)
        led = dict(plan.approval["soak_ledger"])
        samples = list(led["samples"])
        if samples and now < _p(max(s["at"] for s in samples)):
            led["rejected"] = led.get("rejected", 0) + 1
        else:
            samples.append({"at": c.iso(now), "class": cls, "reasons": [c.redact_text(r)[0][:200] for r in why],
                            "flows": {k: {"loss_pct": v.get("loss_pct"), "coverage": v.get("coverage")} for k, v in reading.items()}})
            led["samples"] = samples[-MAX_SAMPLES:]
        plan.approval = {**plan.approval, "soak_ledger": led}
        plan.save()
        if cls == "degraded":
            repo.audit(actor, plan.case, "SOAK_DEGRADED", decision="; ".join(why)[:255], result="DEGRADED", risk=plan.risk, operation=plan.record_id, now=now)
    return assess_ledger(read_ledger(plan), now)


def _flow_defs(plan, ledger: dict) -> list[dict]:
    known = {f.get("key"): f for f in plan.impacted_flows}
    return [{**known.get(f["key"], {}), **f} for f in ledger["flows"]]


def reset_window(actor: repo.Actor, plan_id: str, *, reason: str, now: datetime | None = None) -> dict:
    """The ONLY way past a DEGRADED/INTERRUPTED window: an explicit, audited human restart that keeps the failed history."""
    now = now or _now()
    if actor.actor_type != "user":
        raise gov.GovernanceRefused("AGENT_CANNOT_RESET", "restarting a failed soak window is a human decision")
    if len((reason or "").strip()) < 8:
        raise gov.GovernanceRefused("REASON_REQUIRED", "a reset needs a recorded rationale")
    with transaction.atomic():
        plan = m.TsRemediationPlan.objects.select_for_update().get(pk=gov.get_plan(actor, plan_id).pk)
        old = (plan.approval or {}).get("soak_ledger")
        if not old:
            raise gov.GovernanceRefused("NO_LEDGER", "nothing to reset")
        prior = assess_ledger(old, now)
        new = {**old, "started_at": c.iso(now), "samples": [], "rejected": 0,
               "resets": [*old.get("resets", []), {"at": c.iso(now), "by": actor.name, "reason": c.redact_text(reason)[0][:200],
                                                    "prior_state": prior["state"], "prior_reasons": prior["reasons"][:5]}][-20:]}
        plan.approval = {**plan.approval, "soak_ledger": new}
        plan.save()
        repo.audit(actor, plan.case, "SOAK_WINDOW_RESET", decision=f"{plan.record_id} after {prior['state']}", result="OK", risk=plan.risk,
                   operation=plan.record_id, rationale=reason, now=now)
    return new


def active_soak_plans(tenant: str) -> list[m.TsRemediationPlan]:
    return list(m.TsRemediationPlan.objects.filter(case__tenant=tenant, status__in=ACTIVE_PLAN_STATES).select_related("case").order_by("id"))


def monitor_once(actor: repo.Actor, flow_source: Callable[[dict], dict | None] | None, *, window: timedelta = DEFAULT_WINDOW,
                 now: datetime | None = None, **pin) -> list[dict]:
    """One sampling pass over every active soak plan of the actor's tenant.  One broken plan never stops the others."""
    out = []
    for plan in active_soak_plans(actor.tenant):
        if not plan.approval.get("soak_required"):
            continue
        try:
            sampler = FlowSampler(actor, plan.case, flow_source, clock=lambda n=now: n or _now())
            st = tick(actor, plan.record_id, sampler, window=window, now=now, **pin)
            out.append({"plan": plan.record_id, "state": st["state"], "coverage": st["coverage"], "samples": st["samples"], "reasons": st["reasons"][:5]})
        except Exception as exc:  # pylint: disable=broad-exception-caught  # noqa: BLE001
            out.append({"plan": plan.record_id, "state": "ERROR", "reasons": [f"{type(exc).__name__}: {str(exc)[:150]}"]})
    return out


# ========================================================================================================== composition
@dataclass
class PortConfig:
    flow_source: Callable[[dict], dict | None] | None = None
    redundancy_provider: Callable[[dict, dict], dict | None] | None = None
    link_status: Callable[[str], str | None] | None = None
    maintenance: Callable[[str], bool | None] | None = None
    golden: Callable[[str], dict | None] | None = None
    inventory: Callable[[], dict] | None = None
    step_up_verifier: Callable[[str, str], bool] | None = None
    change_loader: Callable[[str], Any] | None = None
    config_reader: Callable[[str], Any] | None = None
    rollback_plan_lookup: Callable[[str], Any] | None = None
    writes_enabled: bool = False
    require_step_up: bool = True


def build_ports(cfg: PortConfig | None = None, *, actor: repo.Actor | None = None, case: m.TsCase | None = None,
                clock: Callable[[], datetime] = _now) -> gov.Ports:
    """Compose the governance Ports from existing services.  Defaults: writes disabled, step-up required, everything unproven = refused."""
    cfg = cfg or PortConfig()
    if cfg.change_loader is not None:
        inner: Any = gov.ChangeEngineExecutor(
            cfg.change_loader, readback_provider=digest_readback(cfg.config_reader),
            rollback_runner=rollback_runner_from_service(cfg.rollback_plan_lookup) if cfg.rollback_plan_lookup else None)
    else:
        inner = gov.UnconfiguredExecutor()
    return gov.Ports(
        executor=WriteGuardedExecutor(inner, writes_enabled=cfg.writes_enabled),
        device_state=DeviceStatePort(inventory=cfg.inventory, maintenance=cfg.maintenance, golden=cfg.golden),
        alternate_paths=AlternatePathPort(cfg.redundancy_provider, link_status=cfg.link_status),
        flow_sample=FlowSampler(actor, case, cfg.flow_source, clock=clock, persist=case is not None),
        step_up=step_up_port(cfg.step_up_verifier), require_step_up=cfg.require_step_up, clock=clock)
