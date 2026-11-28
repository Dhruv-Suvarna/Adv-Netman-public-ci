"""Managed AI continuation bound to the runtime diagnostic adapter (spec section 5, M4 binding).

This module adds NO orchestrator and reads NO credentials.  It connects three existing pieces:

* ``ai`` -- the governed MCP-style tool gateway (nonce/idempotency, budgets, scope, audit, checkpoints, ``investigate`` loop);
* ``runtime`` / ``engine`` -- the Stage-1 collectors and typed runbook tests, exposed as ``RuntimeDiagnosticRunner`` (the ``Runtime.runner``
  that ``ai.request_diagnostic_test`` calls); a model-requested test performs a bounded read-only collection through the same
  ``CollectorProvider`` and evaluates the registered ``TestSpec`` against persisted observations;
* a *model provider* -- any object with ``complete(request: dict) -> dict``.  The provider is configured by the deployment
  (``settings.TROUBLESHOOTING_AI_PROVIDER`` = dotted path to a zero-arg factory, or passed explicitly).  Nothing is configured
  by default, so the default state is ``PROVIDER_UNAVAILABLE`` and the continuation fails closed (handoff stays OPEN, resumable).

Typed model I/O: ``ai_model_request/1`` and ``ai_model_response/1`` (validated here).  The model can only name a registered tool and typed
arguments; raw CLI, tiers, approvals, idempotency keys are rejected by ``ai.call_tool``; write-capable tools (``propose_remediation``)
are not exposed to the model by this binding at all.  Every model exchange is persisted in the handoff checkpoint (model identity, digests,
cited evidence, retries) and every tool call by ``ai`` (results keyed by a content-derived nonce, so a resumed run replays instead of
re-executing).  Provider doubles used in tests are NOT live-model evidence.
"""

from __future__ import annotations

import time

import hashlib
import importlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Callable

from django.conf import settings

from core import models as m

from . import ai
from . import baselines as bl
from . import contracts as c
from . import engine as eng
from . import repository as repo
from . import runtime as rt
from .runbooks import REGISTRY

REQUEST_SCHEMA = "nmas.troubleshooting.ai-model-request/1"
RESPONSE_SCHEMA = "nmas.troubleshooting.ai-model-response/1"
# Proposal-only tools are exposed: propose_remediation creates a PROPOSED plan; dry-run, approval, precheck and execution stay with
# NMAS governance and the Change page (the change engine's single caller).  Tools that write are never exposed.
MODEL_TOOLS = tuple(t for t, s in ai.TOOLS.items() if s["read_only"] or s.get("terminal") or s.get("proposal_only"))
MAX_REQUEST_BYTES = 64_000
MAX_MODEL_LOG = 200

# accurate continuation statuses
ST_PROVIDER_UNAVAILABLE = "PROVIDER_UNAVAILABLE"
ST_NOT_AUTHORIZED = "NOT_AUTHORIZED"
ST_NOT_OPEN = "HANDOFF_NOT_OPEN"
ST_COMPLETED = "COMPLETED"
ST_ESCALATED = "ESCALATED"
ST_EXHAUSTED = "EXHAUSTED"
ST_BLOCKED = "BLOCKED"


class ProviderUnavailable(Exception):
    """No model provider is configured/reachable/permitted.  Fails the continuation closed (the handoff stays OPEN)."""


class _Halt(BaseException):
    """Raised through ``ai.investigate`` (which only catches ``Exception``) so an unavailable provider does not burn retries or escalate."""


class ModelResponseInvalid(ValueError):
    pass


# ----------------------------------------------------------------------------------------------------------------- provider
def load_provider(path: str | None = None) -> Any:
    """Resolve the deployment-configured provider factory.  Never inspects credentials; the factory owns its own configuration."""
    path = path or getattr(settings, "TROUBLESHOOTING_AI_PROVIDER", "") or ""
    if not path:
        raise ProviderUnavailable("no model provider configured (settings.TROUBLESHOOTING_AI_PROVIDER is empty)")
    mod, _, attr = path.replace(":", ".").rpartition(".")
    try:
        factory = getattr(importlib.import_module(mod), attr)
        provider = factory() if callable(factory) and not hasattr(factory, "complete") else factory
    except Exception as exc:  # noqa: BLE001
        raise ProviderUnavailable(f"model provider {path!r} could not be loaded: {type(exc).__name__}") from exc
    if not callable(getattr(provider, "complete", None)):
        raise ProviderUnavailable(f"model provider {path!r} has no complete(request) method")
    return provider


def load_research_broker(principal: str = "nmas-troubleshooter") -> Any | None:
    """Load only the isolated research-worker client; never fetch in-process."""
    cfg = getattr(settings, "NMAS_TS_RESEARCH_WORKER", {}) or {}
    if not isinstance(cfg, dict) or not cfg.get("socket") or not cfg.get("key_env"):
        return None
    from .research_worker import ResearchWorkerClient
    from .worker_ipc import load_key
    return ResearchWorkerClient(socket_path=str(cfg["socket"]), key=load_key(str(cfg["key_env"])), principal=principal,
                                timeout_seconds=float(cfg.get("timeout", 12)))


def provider_identity(provider: Any) -> dict[str, str]:
    ident = getattr(provider, "identity", None)
    ident = ident() if callable(ident) else (ident or {})
    return {"provider": str(ident.get("provider", type(provider).__name__))[:64], "model_id": str(ident.get("model_id", "unknown"))[:96],
            "model_version": str(ident.get("model_version", ""))[:64]}


# --------------------------------------------------------------------------------------------------------------- typed I/O
def build_request(context: dict, *, identity: dict, catalog: list[dict], seq: int) -> dict:
    tools = {t: {"required": ai.TOOLS[t]["required"], "optional": ai.TOOLS[t]["optional"],
                 **({"schema": ai.TOOLS[t]["schema"]} if "schema" in ai.TOOLS[t] else {})} for t in MODEL_TOOLS}
    req = {"schema": REQUEST_SCHEMA, "seq": seq, "model": identity,
           "instructions": ("Read-only investigation. Choose ONE registered tool per turn, or conclude. You cannot run raw commands, change "
                            "configuration, approve anything or contact hosts outside allowed_targets. Cite evidence_ids from tool results. "
                            "Remediation selection: propose the MINIMAL operation set that restores the authoritative intent the evidence "
                            "shows is violated. Change history fields are distinct: 'approved'/'human_approved' is human approval only; "
                            "'authorized' with 'authorization_mode' (HUMAN_APPROVAL or PREAUTHORIZED_AUTOMATED_RECOVERY) says what "
                            "permitted an execution; 'execution_outcome' and 'service_verification' say what it did. A policy-authorized "
                            "recovery is an authorized change, not an unapproved one. Propose config_rollback of a change ONLY when evidence "
                            "shows that change caused the current fault, its rollback is supported, and it would restore intent; temporal "
                            "proximity alone is not causation, and a state that conflicts with current intent is corrected toward intent, "
                            "not by rolling back an earlier change. Workflow: when a root cause is supported and a registered corrective operation "
                            "applies, call propose_remediation BEFORE submit_investigation_result; a conclusion without a proposal leaves the "
                            "incident unremediated for a human. Proposing never executes anything: NMAS governance decides. "
                            "Fault discrimination: administrative DOWN (configured shutdown), operational DOWN with admin UP (no carrier: "
                            "medium, optic, peer, negotiation), repeated link transitions (flapping), error/discard degradation, routing "
                            "adjacency failure and route/reachability failure are different faults. Reason in order: define the symptom, "
                            "establish the affected scope, form competing evidence-backed hypotheses, test them, name the most likely "
                            "fault domain, then decide whether a registered corrective operation is supported by the evidence. An "
                            "administrative enable corrects ONLY an interface observed administratively down; never propose it for an "
                            "interface that is administratively up, and never propose interface bounce/shutdown, routing, neighbor or "
                            "process changes speculatively. A context.deterministic_classification or a 'Deterministic pre-classification' "
                            "in the uncertainty is NMAS's model-free reading of the evidence: confirm or refute it with live tests. When no "
                            "safe registered correction applies, do not invent a change: submit an evidence-backed escalation (fault domain, "
                            "evidence ids, what was ruled out, what remains uncertain); NMAS records it as safe non-remediation."),
           "tools": tools, "diagnostic_tests": catalog, "context": context,
           "response_schema": {"action": "tool|conclude", "tool": "str", "args": "dict", "why_informative": "str", "rationale": "str",
                               "hypotheses": "list[{title,domain,supporting,contradicting,confidence: number 0..1}]",
                               "conclude": "{outcome: ROOT_CAUSE_SUPPORTED|INCONCLUSIVE|EXTERNAL_PREREQUISITE_BLOCKED, summary, hypotheses}"}}
    req = c.redact_value(req)
    if len(c.canonical_json(req)) > MAX_REQUEST_BYTES:       # bounded prompt: shrink the volatile parts, never the rules
        ctx = dict(req["context"])
        ctx["recent_tests"] = ctx.get("recent_tests", [])[:10]
        ctx["last_result"] = None if ctx.get("last_result") is None else {"ok": ctx["last_result"].get("ok"), "error_code": ctx["last_result"].get("error_code"),
                                                                          "data": "truncated"}
        req["context"] = ctx
    return req


def _is_str(v: Any) -> bool:
    return isinstance(v, str)


def validate_response(resp: Any) -> dict:
    """Structural validation of ``ai_model_response/1``.  Semantic authority (scope, writes, budgets) stays with ``ai.call_tool``."""
    if not isinstance(resp, dict):
        raise ModelResponseInvalid("response must be an object")
    if resp.get("schema", RESPONSE_SCHEMA) != RESPONSE_SCHEMA:
        raise ModelResponseInvalid(f"unsupported response schema {resp.get('schema')!r}")
    allowed = {"schema", "action", "tool", "args", "why_informative", "rationale", "hypotheses", "conclude", "usage", "model"}
    extra = set(resp) - allowed
    if extra:
        raise ModelResponseInvalid(f"unexpected response fields: {sorted(extra)}")
    action = resp.get("action")
    if action == "tool":
        if not _is_str(resp.get("tool")) or not resp["tool"]:
            raise ModelResponseInvalid("tool action needs a tool name")
        if not isinstance(resp.get("args", {}), dict):
            raise ModelResponseInvalid("args must be an object")
    elif action == "conclude":
        concl = resp.get("conclude")
        if not isinstance(concl, dict) or not _is_str(concl.get("summary")) or not _is_str(concl.get("outcome")):
            raise ModelResponseInvalid("conclude needs outcome and summary strings")
        if not isinstance(concl.get("hypotheses", []), list):
            raise ModelResponseInvalid("hypotheses must be a list")
    else:
        raise ModelResponseInvalid("action must be 'tool' or 'conclude'")
    if not isinstance(resp.get("hypotheses", []), list) or not all(isinstance(h, dict) for h in resp.get("hypotheses", [])):
        raise ModelResponseInvalid("hypotheses must be a list of objects")
    return resp


def _digest(obj: Any) -> str:
    return hashlib.sha256(c.canonical_json(obj).encode()).hexdigest()[:24]


def content_nonce(tool: str, args: dict) -> str:
    """Deterministic nonce: an identical request replays the stored result (no duplicate execution) across retries and restarts."""
    return "ai-" + _digest({"tool": tool, "args": args})


# -------------------------------------------------------------------------------------------------- runtime diagnostic runner
class RuntimeDiagnosticRunner:
    """``ai.Runtime.runner`` backed by the runtime.  Only registered runbook tests are runnable; each run does a bounded read-only collection
    of exactly the evidence the ``TestSpec`` declares (``spec.sources``) for the one target, then evaluates the spec on persisted observations.
    Missing transports/inventory yield UNAVAILABLE/INCONCLUSIVE with a reason, never an invented PASS/FAIL."""

    def __init__(self, actor: repo.Actor, case_id: str, deps: rt.RuntimeDeps | None = None, *, runbook: str | None = None, scope_key: str = "",
                 budget: dict | rt.RuntimeBudget | None = None, sources: bl.BaselineSources | None = None,
                 worker_context: dict | None = None):
        self.actor, self.case_id = actor, case_id
        self.deps = deps or rt.RuntimeDeps()
        case = repo.get_case(actor, case_id)
        rb = runbook or case.runbook
        if rb not in REGISTRY:
            raise ValueError(f"unknown or missing runbook {rb!r}")
        self.rb = REGISTRY[rb]
        self.scope_key = scope_key or case_id
        self.budget = budget if isinstance(budget, rt.RuntimeBudget) else rt.RuntimeBudget.clamp(budget)
        self.sources = sources or self.deps.sources or bl.DjangoBaselineSources()
        self.read_only_tests = frozenset(t.id for t in self.rb.tests)
        self.executed: list[tuple[str, str]] = []        # (test_id, target) actually collected+evaluated by this instance
        self.worker_context = dict(worker_context or {})
        self._engine: eng.Engine | None = None

    def catalog(self) -> list[dict]:
        return [{"test_id": t.id, "title": t.title, "layer": t.layer, "expected": t.expected} for t in self.rb.tests]

    def _prepare(self, now: datetime) -> eng.Engine:
        case = repo.get_case(self.actor, self.case_id)
        e = eng.Engine(self.actor, case, self.rb, sources=self.sources, provider=None, now=now)  # type: ignore[arg-type]
        e.baseline()
        e.correlate()
        self._engine = e
        return e

    def run(self, test_id: str, target: str, params: dict) -> dict:
        if test_id not in self.read_only_tests:
            raise ai.AiRefused("TEST_NOT_READ_ONLY_ALLOWLISTED", f"{test_id!r} is not a registered read-only test")
        spec = self.rb.by_id[test_id]
        now = self.deps.now()
        case = repo.get_case(self.actor, self.case_id)
        repo.authorize_probe(self.actor, case, target, now=now)
        n = m.TsDiagnosticTest.objects.filter(case=case, test_id=test_id, target=target).count() + 1
        run_key = f"ai-{_digest([self.scope_key, test_id, target, n])}"[:64]
        collected, gap = 0, ""
        admissions = rt.resolve_admission(self.actor, case, self.deps, self.budget, now)
        info = admissions.get(target)
        if info is None or not info.admitted:
            gap = f"target {target} is not an admitted device ({info.state if info else 'not in scope'}); no collection performed"
        elif spec.sources:
            provider = rt.CollectorProvider(self.actor, repo.get_case(self.actor, self.case_id), self.deps, admissions, self.budget, run_key,
                                            worker_context=self.worker_context)
            try:
                for bundle in provider.collect(self.case_id, target, list(spec.sources), now):
                    repo.ingest_collection_bundle(self.actor, bundle, now=now)
                    collected += 1
            except Exception as exc:  # pylint: disable=broad-exception-caught  # noqa: BLE001 - collection failure is a recorded gap
                gap = f"collection failed: {type(exc).__name__}: {exc}"[:300]
        self.executed.append((test_id, target))
        e = self._prepare(now)
        case = repo.get_case(self.actor, self.case_id)
        e.case = case
        for t in m.TsDiagnosticTest.objects.filter(case=case).order_by("seq", "attempt"):
            e.results[t.test_id] = eng._result_from_row(t)
        ctx = e._context()
        ctx.used, ctx.gaps = [], []
        res = e._applicability(spec, ctx)
        if res is None:
            res = e._execute(spec, ctx)
        if gap and res.verdict in ("PASS", "FAIL") and not collected:
            pass            # evaluated on previously persisted observations; the gap is noted in the observed block
        verdict = res.verdict if res.verdict in c.VERDICTS else "INCONCLUSIVE"
        reason = res.reason or (res.summary if verdict != "PASS" else "")
        if verdict != "PASS" and len(reason.strip()) < 8:
            reason = f"{res.status}: {res.summary or 'no detail'}"
        if verdict != "PASS" and gap:
            reason = f"{reason}; {gap}"[:500]
        observed = {**res.observed, "_applicability": res.status, "_collected_units": collected}
        if res.finding:
            observed["_finding"] = res.finding.__dict__
        if ctx.gaps:
            observed["_gaps"] = list(ctx.gaps)
        return {"test_id": spec.id, "test_version": spec.version, "target": target, "expected": spec.expected, "verdict": verdict,
                "reason": reason or "healthy expectation held", "hypothesized_condition": spec.condition, "preconditions": list(spec.requires),
                "command_or_api": spec.command or "normalized observations", "observed": json.loads(c.canonical_json(observed)),
                "observed_summary": res.summary, "interpretation": res.interpretation, "next_action": res.next_action,
                "evidence_ids": res.evidence_ids, "executed_at": c.iso(now)}


# ------------------------------------------------------------------------------------------------------------- continuation
@dataclass
class ContinuationResult:
    status: str
    handoff_id: str
    handoff_status: str = ""
    reason: str = ""
    model: dict = field(default_factory=dict)
    model_requests: int = 0
    iterations: int = 0
    tool_calls: int = 0

    def as_dict(self) -> dict:
        return dict(self.__dict__)


def _persist_model(handoff_id: str, system: repo.Actor, identity: dict, entry: dict | None = None, *, failure: str = "") -> None:
    h = ai._handoff(system, handoff_id)
    cp = h.checkpoint
    mm = cp.setdefault("model", {"identity": identity, "requests": 0, "failures": 0, "exchanges": []})
    mm["identity"] = identity
    if entry:
        mm["requests"] += 1
        mm["exchanges"] = (mm["exchanges"] + [entry])[-MAX_MODEL_LOG:]
    if failure:
        mm["failures"] += 1
        mm["last_failure"] = failure[:200]
    h.checkpoint = cp
    h.save()


ADMISSION_ACCEPTANCE = "ADMISSION_ACCEPTANCE"
PREMODEL_LOCK_RETRIES = 2
PREMODEL_LOCK_BACKOFF_S = 2.0


def continue_handoff(actor: repo.Actor, handoff_id: str, *, provider: Any = None, provider_path: str | None = None, runner: Any = None,
                     deps: rt.RuntimeDeps | None = None, runbook: str | None = None, run_budget: dict | None = None,
                     clock: Callable[[], datetime] | None = None, fencing_token: int | None = None,
                     lease_validator: Callable[[str, int], bool] | None = None) -> ContinuationResult:
    """Continue an existing, authorized, OPEN handoff with a model.  Fails closed with an accurate status; never opens handoffs."""
    system = repo.Actor("nmas-system", "system", tenant=actor.tenant)
    if actor.actor_type == ai.HANDOFF_ACTOR_TYPE:
        return ContinuationResult(ST_NOT_AUTHORIZED, handoff_id, reason="the agent cannot start its own continuation")
    try:
        h = ai._handoff(system, handoff_id)
        repo.get_case(actor, h.case.case_id)              # caller must see the case (tenant) ...
        if h.allowed_targets and not any(actor.can_see_device(d) for d in h.allowed_targets):
            raise repo.AccessDenied("caller sees none of the delegated targets")
    except repo.AccessDenied as exc:
        return ContinuationResult(ST_NOT_AUTHORIZED, handoff_id, reason=str(exc))
    if h.status != "OPEN":
        return ContinuationResult(ST_NOT_OPEN, handoff_id, h.status, reason=f"handoff is {h.status}; only OPEN handoffs can be continued")
    wasted = [t for t in h.allowed_tools if t not in MODEL_TOOLS]
    clock_fn = clock or (lambda: datetime.now(timezone.utc))
    try:
        if provider is None:
            provider = load_provider(provider_path)
        identity = provider_identity(provider)
    except ProviderUnavailable as exc:
        repo.audit(system, h.case, "AI_PROVIDER_UNAVAILABLE", decision=str(exc)[:255], result="PROVIDER_UNAVAILABLE", now=clock_fn())
        return ContinuationResult(ST_PROVIDER_UNAVAILABLE, handoff_id, h.status, reason=str(exc))
    if runner is None:
        began = c.parse_time(h.checkpoint.get("started_at"))
        wall = int(h.budget.get("max_wall_seconds", 0))
        expires = (began + timedelta(seconds=wall)) if began and wall > 0 else clock_fn()
        runner = RuntimeDiagnosticRunner(actor, h.case.case_id, deps, runbook=runbook, scope_key=handoff_id, budget=run_budget,
                                         worker_context={"agent": h.agent_identity, "tenant": h.case.tenant,
                                                         "authorization_ref": f"handoff:{h.record_id}",
                                                         "authorization_expires_at": expires})
    catalog = runner.catalog() if hasattr(runner, "catalog") else [{"test_id": t} for t in sorted(runner.read_only_tests)]
    try:
        research_broker = load_research_broker(h.agent_identity)
    except Exception as exc:  # pylint: disable=broad-exception-caught  # fail closed; diagnostics remain usable
        repo.audit(system, h.case, "RESEARCH_BROKER_UNAVAILABLE", decision=type(exc).__name__, result="UNAVAILABLE", now=clock_fn())
        research_broker = None
    # ``fencing_token`` / ``lease_validator`` are supplied only by the global agent dispatcher; every governed tool
    # request then fails closed unless this continuation still owns the singleton execution lease.
    ai_rt = ai.Runtime(runner=runner, research=research_broker, clock=clock_fn, fencing_token=fencing_token,
                       lease_validator=lease_validator)
    ag = ai.agent_actor(h)

    # An operational-down incident must not let a fast model conclusion bypass
    # the restricted device worker.  Perform one exact, registered, read-only
    # Layer-1 test under the same handoff, scope, budget and fencing token before
    # the first model turn.  The deterministic nonce makes dispatcher retries
    # replay the stored result instead of touching the device twice.  Failure is
    # evidence (and remains safe); it never falls back to a privileged transport.
    fault_category = str((h.case.service_intent or {}).get("fault_category") or "")
    if ("request_diagnostic_test" in h.allowed_tools and "HC04" in set(getattr(runner, "read_only_tests", ()))
            and h.allowed_targets):
        if fault_category == "OPERATIONAL_LINK_DOWN":
            premodel = [(h.allowed_targets[0], f"system-op-down-hc04-{h.record_id}")]          # unchanged since campaign 017
        elif fault_category == ADMISSION_ACCEPTANCE:
            # Topology admission acceptance: one genuine restricted-worker collection on EVERY delegated target (bounded by the
            # handoff's own device budget) before any model turn -- proof that each admitted device answers through its approved
            # path with its dedicated read-only identity.  Deterministic nonces make retries replay instead of re-collecting.
            limit = int(h.budget.get("max_devices", 5))
            premodel = [(t, f"system-acceptance-hc04-{h.record_id}-{t}") for t in sorted(h.allowed_targets)[:limit]]
        else:
            premodel = []
        for target, nonce in premodel:
            for attempt in range(PREMODEL_LOCK_RETRIES + 1):
                # A SQLite writer-lock refusal never touched the device; its result is stored under its nonce (a replay would
                # return the same failure), so a bounded retry uses a distinct deterministic nonce.  Any other outcome stops.
                result = ai.call_tool(
                    ag,
                    h.record_id,
                    "request_diagnostic_test",
                    {
                        "test_id": "HC04",
                        "target": target,
                        "params": {"force_refresh": True},
                        "why": "Collect current Layer-1 evidence through the restricted worker before the first model turn.",
                    },
                    nonce=nonce if attempt == 0 else f"{nonce}-lockretry{attempt}",
                    rt=ai_rt,
                    now=clock_fn(),
                )
                if not (isinstance(result, dict) and result.get("error_code") == "TOOL_FAILED"
                        and "database is locked" in str(result.get("error") or "")):
                    break
                time.sleep(PREMODEL_LOCK_BACKOFF_S * (attempt + 1))
    state = {"seq": 0}
    max_model = h.budget["max_iterations"] + h.budget["max_model_retries"] * 2

    def agent(context: dict) -> dict:
        hh = ai._handoff(system, handoff_id)
        used = hh.checkpoint.get("model", {}).get("requests", 0)
        if used >= max_model:
            raise _Halt(ST_EXHAUSTED)                    # model request budget spent: handled below
        state["seq"] += 1
        req = build_request(context, identity=identity, catalog=catalog, seq=used + 1)
        try:
            raw = provider.complete(req)
        except ProviderUnavailable as exc:
            _persist_model(handoff_id, system, identity, failure=f"unavailable: {exc}")
            raise _Halt(ST_PROVIDER_UNAVAILABLE) from exc
        except Exception as exc:  # noqa: BLE001 - counts against ai's model-retry budget
            _persist_model(handoff_id, system, identity, failure=type(exc).__name__)
            raise
        try:
            resp = validate_response(raw)
        except ModelResponseInvalid as exc:
            _persist_model(handoff_id, system, identity, {"seq": used + 1, "request": _digest(req), "response": _digest(raw) if raw is not None else "",
                                                          "valid": False, "error": str(exc)[:160]}, failure=str(exc))
            raise
        if resp["action"] == "conclude":
            cited = sorted({e for hyp in resp["conclude"].get("hypotheses", []) if isinstance(hyp, dict)
                            for e in list(hyp.get("supporting", [])) + list(hyp.get("contradicting", [])) if isinstance(e, str)})
            step = {"conclude": resp["conclude"], "hypotheses": resp.get("hypotheses", []), "rationale": resp.get("rationale", ""),
                    "nonce": "ai-c-" + _digest(resp["conclude"])}
            tool = "submit_investigation_result"
        else:
            tool, args = resp["tool"], resp.get("args", {})
            cited = []
            if tool not in MODEL_TOOLS and tool in ai.TOOLS:      # registered but write/proposal capable: never reachable from the model
                repo.audit(ag, hh.case, "MCP_DENIED", decision=f"{tool}: not exposed to the model", result="WRITE_TOOL_NOT_PERMITTED", operation=tool,
                           now=clock_fn(), rationale="model requested a non-read-only tool")
                tool_out = "blocked:" + tool
            else:
                tool_out = tool
            step = {"tool": tool_out, "args": args, "hypotheses": resp.get("hypotheses", []), "rationale": resp.get("rationale", ""),
                    "why_informative": resp.get("why_informative", ""), "nonce": content_nonce(tool_out, args)}
        _persist_model(handoff_id, system, identity, {"seq": used + 1, "request": _digest(req), "response": _digest(resp), "valid": True,
                                                       "tool": tool, "nonce": step.get("nonce"), "cited_evidence": cited,
                                                       "usage": resp.get("usage") if isinstance(resp.get("usage"), dict) else {},
                                                       "at": c.iso(clock_fn())})
        return step

    try:
        final = ai.investigate(system, handoff_id, agent, ai_rt)
    except _Halt as halt:
        h = ai._handoff(system, handoff_id)
        cause = str(halt.args[0]) if halt.args else ST_PROVIDER_UNAVAILABLE
        if cause == ST_EXHAUSTED:
            final = ai.close_handoff(system, handoff_id, status="EXHAUSTED", reason="model request budget exhausted", now=clock_fn())
        else:
            repo.audit(system, h.case, "AI_PROVIDER_UNAVAILABLE", decision="provider became unavailable mid-investigation; handoff left OPEN for resume",
                       result="PROVIDER_UNAVAILABLE", now=clock_fn())
            return _result(ST_PROVIDER_UNAVAILABLE, h, identity, "model provider unavailable; progress checkpointed, handoff still OPEN")
    status = {"COMPLETED": ST_COMPLETED, "ESCALATED": ST_ESCALATED, "EXHAUSTED": ST_EXHAUSTED, "BLOCKED": ST_BLOCKED}.get(final.status, final.status)
    res = _result(status, final, identity, final.checkpoint.get("closed_reason", ""))
    if wasted:
        res.reason = (res.reason + f" (tools not exposed to the model: {', '.join(wasted)})").strip()
    return res


def _result(status: str, h: m.TsAIHandoff, identity: dict, reason: str) -> ContinuationResult:
    h = m.TsAIHandoff.objects.get(pk=h.pk)
    mm = h.checkpoint.get("model", {})
    return ContinuationResult(status, h.record_id, h.status, reason, identity, mm.get("requests", 0), h.checkpoint.get("iteration", 0), h.checkpoint.get("calls", 0))
