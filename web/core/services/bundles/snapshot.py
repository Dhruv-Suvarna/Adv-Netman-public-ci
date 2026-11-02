"""Reconstruct the frozen payload of a UAT bundle from a finished execution run's PINNED historical records.

Read-only.  Nothing here contacts a device, NetBox, Git, a sandbox or the network, re-runs a validation / plan / precheck /
postcheck / raw verification, or looks at the CURRENT state of the Change.  The exact scope, order, plan, validation, Configlet
payloads, raw revisions, execution results and postcheck evidence all come from what the run itself pinned, so a newer edit, plan or
raw revision can never leak into an old bundle.

Only the plan Configlet's FROZEN fields (``Configlet.PLAN_FROZEN_FIELDS``) and its dependency edge rows are read: fields the execution
engine rewrites afterwards (``previous_state_ref``, ``execution_status``, ``metadata``) are deliberately never part of a payload.

EVERY applicable blocker is collected (not just the first), each with a stable code, so the operator sees the whole picture.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ... import models
from .. import secret_policy
from ..raw_configlets import codes as raw_codes, static_gate, text as raw_text
from . import canonical
from .codes import (
    ACCEPTABLE_POSTCHECK, ACCEPTABLE_VALIDATION, APPLIED_RESULT_STATUSES, BUNDLEABLE_OUTCOMES, DEPLOYED_OUTCOMES, MAX_ITEMS, MAX_MANIFEST_BYTES,
    UAT_BLOCKERS, UNKNOWN, UNVERIFIED, VERIFIED, blocker,
)

PAYLOAD_SCHEMA_VERSION = 1


@dataclass
class Snapshot:
    blockers: list = field(default_factory=list)
    payload: dict | None = None
    item_specs: list = field(default_factory=list)   # [{"record", "configlet", "raw_revision", "raw_verification", "execution_result"}]
    verification_state: str = ""

    @property
    def ok(self) -> bool:
        return not self.blockers and self.payload is not None


def _active_execution(run) -> bool:
    """An execution of this Change, or of one of the run's devices, is still active (its state may be changing)."""
    running = models.ChangeExecutionRun.objects.filter(change_id=run.change_id, state=models.ExecutionRunState.RUNNING).exclude(pk=run.pk)
    locks = models.ExecutionDeviceLock.objects.filter(device__in=list(run.devices or [])).exclude(run_id=run.pk)
    return running.exists() or locks.exists()


def _complete_scope_of(run) -> dict | None:
    """The recorded scope of a Complete run: the WHOLE plan, in plan order, nothing unselected.  None when it is anything else."""
    scope = run.scope if isinstance(run.scope, dict) else {}
    requested, order, unselected = scope.get("requested"), scope.get("plan_order"), scope.get("unselected")
    if not (isinstance(requested, list) and requested and requested == order and len(set(requested)) == len(requested)
            and all(isinstance(item, str) and item for item in requested) and unselected == []):
        return None
    executed = ((run.report or {}).get("scope") or {}).get("requested")
    if executed is not None and executed != requested:
        return None
    return {"requested": list(requested), "plan_order": list(order), "through_cfg_id": str(scope.get("through_cfg_id") or ""), "unselected": []}


def _scope_of(run) -> dict | None:
    """The run's recorded Partial (UAT) scope, or None when it is missing / inconsistent (nothing is ever guessed)."""
    scope = run.scope if isinstance(run.scope, dict) else {}
    requested, order, through, unselected = scope.get("requested"), scope.get("plan_order"), scope.get("through_cfg_id"), scope.get("unselected")

    def strings(value):
        return isinstance(value, list) and all(isinstance(item, str) and item for item in value) and len(set(value)) == len(value)

    if not (strings(requested) and requested and strings(order) and isinstance(through, str) and isinstance(unselected, list)):
        return None
    if requested[-1] != through or order[: len(requested)] != requested or unselected != order[len(requested):]:
        return None   # a Partial (UAT) scope is exactly an ordered PREFIX of the plan up to the selected Configlet
    executed = ((run.report or {}).get("scope") or {}).get("requested")
    if executed is not None and executed != requested:
        return None
    return {"requested": list(requested), "plan_order": list(order), "through_cfg_id": through, "unselected": list(unselected)}


def _postcheck_facts(run, plan, add) -> tuple[dict | None, list]:
    """-> (pinned postcheck summary or None, unverified entries).  A verified scope needs its persisted, acceptable postcheck run."""
    pinned = run.postcheck_run
    recorded = (run.report or {}).get("postcheck") or {}
    result = recorded.get("result")
    unverified = [
        {k: str(entry.get(k, "")) for k in ("cfg_id", "code", "requirement")}
        for entry in (recorded.get("unverified") or []) if isinstance(entry, dict)
    ]
    unverified.sort(key=lambda e: (e["cfg_id"], e["requirement"], e["code"]))
    linked = pinned is not None and pinned.mode == models.OperationalRunMode.CHANGE_POSTCHECK and pinned.plan_id == plan.pk \
        and str(pinned.run_id) == recorded.get("run_id") and recorded.get("result") == pinned.status
    if run.outcome in (models.ExecutionOutcome.UAT_SCOPE_APPLIED, models.ExecutionOutcome.SUCCEEDED):
        valid = linked and pinned.status in ACCEPTABLE_POSTCHECK and not unverified
    else:  # UAT_SCOPE_APPLIED_UNVERIFIED: the postcheck could not confirm everything -- INCOMPLETE, and a run may exist or (on an engine error) not
        valid = result == "INCOMPLETE" and (pinned is None or (linked and pinned.status == "INCOMPLETE"))
    if not valid:
        add("POSTCHECK_EVIDENCE_INVALID", outcome=run.outcome)
        return None, unverified
    if pinned is None:
        return {"run_id": "", "result": result, "engine_version": "", "counts": dict(recorded.get("counts") or {}), "cfg_ids": list(recorded.get("cfg_ids") or [])}, unverified
    return {
        "run_id": str(pinned.run_id), "result": pinned.status, "engine_version": pinned.engine_version,
        "counts": {str(k): int(v) for k, v in (recorded.get("counts") or {}).items()},
        "cfg_ids": [str(c) for c in (recorded.get("cfg_ids") or [])],
    }, unverified


def _raw_record(configlet, run, add) -> tuple[dict | None, str | None, object, object]:
    """-> (raw record, payload, revision, verification).  Pins the EXACT immutable revision the plan pinned -- never 'latest'."""
    desired = configlet.desired_state_ref or {}
    pins = desired.get("raw") or {}
    revision, verification = configlet.raw_revision, configlet.raw_verification
    if revision is None or verification is None or not pins:
        add("RAW_PROVENANCE_MISSING", cfg_id=configlet.cfg_id, reason="MISSING_PIN")
        return None, None, None, None
    reported = next((r for r in (run.report or {}).get("raw_configlets") or [] if r.get("cfg_id") == configlet.cfg_id), None) or {}
    facts = (revision.raw.raw_id, revision.revision, revision.content_hash, str(verification.run_id))
    agree = revision.raw.change_id == run.change_id and all(
        (pins.get(k), reported.get(k)) == (v, v) for k, v in zip(("raw_id", "revision", "content_hash", "verification_run_id"), facts)
    )
    if not agree:
        add("RAW_PROVENANCE_MISSING", cfg_id=configlet.cfg_id, reason="PIN_MISMATCH")
        return None, None, None, None
    if raw_text.content_hash(revision.content) != revision.content_hash:
        add("RAW_REVISION_INTEGRITY", cfg_id=configlet.cfg_id)
        return None, None, None, None
    if not (verification.revision_id == revision.pk and verification.state == models.RawVerificationState.FINISHED
            and verification.content_hash == revision.content_hash and verification.result in raw_codes.Result.ACCEPTABLE):
        add("RAW_VERIFICATION_INVALID", cfg_id=configlet.cfg_id)
        return None, None, None, None
    record = {
        "raw_id": revision.raw.raw_id, "revision": revision.revision, "revision_content_hash": revision.content_hash,
        "assertions": [dict(a) if isinstance(a, dict) else a for a in (revision.assertions or [])], "priority": int(revision.priority),
        # Sandbox verification is SYNTAX ONLY: it is recorded as exactly that and is never presented as operational verification.
        "verification": {
            "run_id": str(verification.run_id), "result": verification.result, "policy_version": verification.policy_version,
            "verifier": f"{verification.adapter_id}@{verification.adapter_version}", "backend": verification.backend,
            "scope": "SYNTAX_ONLY", "semantics_verified": False,
        },
    }
    return record, revision.content, revision, verification


def _secret_hits(configlet_cfg: str, payload: str, descriptor: dict) -> list[dict]:
    """Defence in depth: the payload was hygiene-checked when it was authored / planned; it is checked AGAIN here.  Findings carry
    pattern NAMES and line numbers, never the matched text.  Nothing is redacted and then presented as the executed configuration."""
    hits = []
    for number, line in enumerate(str(payload).splitlines(), start=1):
        names = static_gate.secret_patterns(line)
        if names:
            hits.append({"cfg_id": configlet_cfg, "line": number, "patterns": names})
    try:
        secret_policy.assert_no_secret_shaped_keys(descriptor, context=f"Bundle item {configlet_cfg}")
    except ValueError:
        hits.append({"cfg_id": configlet_cfg, "line": 0, "patterns": ["SECRET_SHAPED_KEY"]})
    return hits


def collect(run, *, kind: str = models.BundleKind.UAT) -> Snapshot:
    """Evaluate a finished run and, when eligible, build the frozen payload.  Read-only.

    ``kind`` UAT: a Partial (UAT) run.  ``kind`` DEPLOYED (V2 Phase 5): a SUCCEEDED Complete run of ANY Change -- an ordinary
    configuration Change or a new-device provisioning Change; the Change's category is not part of the rule.
    """
    snap = Snapshot()
    deployed = kind == models.BundleKind.DEPLOYED

    def add(code, **details):
        snap.blockers.append(blocker(UAT_BLOCKERS, code, **details))

    # 1. the run itself ---------------------------------------------------------------------------------------------------
    if run.state != models.ExecutionRunState.FINISHED:
        add("RUN_NOT_FINISHED")
        return snap
    if deployed:
        if run.mode != models.ExecutionMode.COMPLETE:
            add("MODE_NOT_COMPLETE", mode=run.mode)
        if run.outcome not in DEPLOYED_OUTCOMES:
            add("OUTCOME_NOT_DEPLOYED", outcome=run.outcome)
    else:
        if run.mode != models.ExecutionMode.PARTIAL_UAT:
            add("MODE_NOT_PARTIAL_UAT", mode=run.mode)
        if run.outcome not in BUNDLEABLE_OUTCOMES:
            add("OUTCOME_NOT_BUNDLEABLE", outcome=run.outcome)
    if snap.blockers:   # a wrong mode / outcome is the whole explanation: no structural noise about a run that is not a UAT candidate
        return snap
    if _active_execution(run):
        add("ACTIVE_EXECUTION")

    # 2. pinned provenance (the run, its plan and its validation must still agree) ----------------------------------------
    plan, validation = run.plan, run.validation_run
    consistent = (
        plan.change_id == run.change_id and validation.change_id == run.change_id and plan.validation_run_id == validation.pk
        and run.plan_hash == plan.plan_hash
        and (run.validation_input_hash, run.validation_source_hash) == (validation.input_hash, validation.source_hash)
        and (plan.validation_input_hash, plan.validation_source_hash, plan.validation_engine_version)
        == (validation.input_hash, validation.source_hash, validation.engine_version)
    )
    if not consistent:
        add("PLAN_PROVENANCE_INVALID")
    if len(plan.plan_hash or "") != 64:
        add("PLAN_HASH_MISSING")
    if validation.status not in ACCEPTABLE_VALIDATION:
        add("VALIDATION_NOT_PASSING", status=validation.status)

    # 3. the exact scope and the historical plan -------------------------------------------------------------------------
    scope = _complete_scope_of(run) if deployed else _scope_of(run)
    if scope is None:
        add("SCOPE_UNKNOWN", reason="SCOPE_RECORD")
        return snap
    configlets = list(plan.configlets.select_related("raw_revision__raw", "raw_verification").order_by("sequence"))
    by_cfg = {c.cfg_id: c for c in configlets}
    if [c.cfg_id for c in configlets] != scope["plan_order"] or len(by_cfg) != len(configlets):
        add("PLAN_CONFIGLETS_MISSING", expected=len(scope["plan_order"]), found=len(configlets))
        return snap
    requested = scope["requested"]
    position = {cfg: index for index, cfg in enumerate(requested)}
    depends: dict[str, list[str]] = {}
    edges = models.ConfigletDependency.objects.filter(configlet__plan=plan).select_related("configlet", "depends_on")
    for edge in edges:
        depends.setdefault(edge.configlet.cfg_id, []).append(edge.depends_on.cfg_id)
    for cfg in requested:
        missing = sorted(need for need in depends.get(cfg, []) if need not in position or position[need] >= position[cfg])
        if missing:
            add("DEPENDENCY_SCOPE_INCONSISTENT", cfg_id=cfg, prerequisites=missing)

    # 4. execution results: every requested Configlet finished as applied; nothing outside the scope was applied ---------
    results = {r.cfg_id: r for r in run.results.filter(phase=models.ExecutionResultPhase.APPLY)}
    for cfg in requested:
        found, planned = results.get(cfg), by_cfg[cfg]
        if found is None or (found.sequence, found.device) != (planned.sequence, planned.target_device):
            add("RESULT_MISSING", cfg_id=cfg)
        elif found.status not in APPLIED_RESULT_STATUSES:
            add("RESULT_NOT_APPLIED", cfg_id=cfg, status=found.status)
    outside = sorted(cfg for cfg, r in results.items() if cfg not in position and r.status in APPLIED_RESULT_STATUSES)
    if outside:
        add("RESULT_OUT_OF_SCOPE", configlets=outside)
    state = (run.report or {}).get("state") or {}
    if state.get("failed") or state.get("unapplied"):
        add("RESULT_NOT_APPLIED", reason="REPORT_STATE")

    # 5. postcheck evidence -----------------------------------------------------------------------------------------------
    postcheck, unverified = _postcheck_facts(run, plan, add)

    # 6. the ordered items ------------------------------------------------------------------------------------------------
    if len(requested) > MAX_ITEMS:
        add("BUNDLE_TOO_LARGE", items=len(requested))
        return snap
    specs, secrets = [], []
    for order, cfg in enumerate(requested, start=1):
        configlet = by_cfg[cfg]
        desired = configlet.desired_state_ref or {}
        source = desired.get("source") or {}
        raw = revision = verification = None
        payload = configlet.rendered_config
        if configlet.origin == models.ConfigletOrigin.RAW:
            raw, payload, revision, verification = _raw_record(configlet, run, add)
            if raw is None:
                continue
        elif configlet.raw_revision_id or configlet.raw_verification_id:
            add("RAW_PROVENANCE_MISSING", cfg_id=cfg, reason="STRUCTURED_WITH_RAW_PIN")
            continue
        result = results.get(cfg)
        platform = revision.platform if revision is not None else str(source.get("platform", ""))
        record = {
            "order": order, "cfg_id": cfg, "plan_sequence": configlet.sequence, "device": configlet.target_device,
            "platform": platform, "origin": configlet.origin, "operation": configlet.operation_type, "namespace": configlet.feature_namespace,
            "priority": int(configlet.deployment_priority), "description": configlet.description,
            "source": {k: str(source.get(k, "")) for k in ("node_id", "object_type", "object_id")},
            "payload": payload, "payload_hash": canonical.text_hash(payload),
            "depends_on": sorted(depends.get(cfg, [])),
            "expected_state": (configlet.verification_spec or {}).get("requirements", []),
            "raw": raw,
            "execution": (
                {"phase": result.phase, "status": result.status, "error_code": result.error_code, "partial_effects": bool(result.partial_effects),
                 "lines_sent": int(result.lines_sent)} if result is not None else None
            ),
        }
        secrets.extend(_secret_hits(cfg, payload, {"source": record["source"], "expected_state": record["expected_state"], "raw": raw}))
        specs.append({"record": record, "configlet": configlet, "raw_revision": revision, "raw_verification": verification, "execution_result": result})
    if secrets:
        add("SECRET_SHAPED_PAYLOAD", findings=secrets[:20])
    if snap.blockers:
        return snap
    devices = sorted({spec["record"]["device"] for spec in specs})
    if devices != sorted(run.devices or []):
        add("SCOPE_UNKNOWN", reason="DEVICES_MISMATCH")
        return snap

    # 7. the payload ------------------------------------------------------------------------------------------------------
    state_name = VERIFIED if run.outcome in (models.ExecutionOutcome.UAT_SCOPE_APPLIED, models.ExecutionOutcome.SUCCEEDED) else UNVERIFIED
    warning_codes = sorted({str(w.get("code", "")) for w in ((run.report or {}).get("warnings") or []) if isinstance(w, dict)} - {""})
    edges_in_scope = sorted(
        ({"configlet": cfg, "depends_on": need} for cfg in requested for need in depends.get(cfg, [])),
        key=lambda e: (position[e["configlet"]], position[e["depends_on"]]),
    )
    payload = {
        "payload_schema_version": PAYLOAD_SCHEMA_VERSION,
        "source": {
            "change_id": run.change.change_id,
            "validation": {"run_id": str(validation.run_id), "status": validation.status, "input_hash": validation.input_hash, "source_hash": validation.source_hash},
            "plan": {"plan_id": str(plan.plan_id), "plan_hash": plan.plan_hash, "planner_version": plan.planner_version},
            "execution": {
                "run_id": str(run.run_id), "mode": run.mode, "outcome": run.outcome, "plan_hash": run.plan_hash,
                "precheck_run_id": str(run.precheck_run.run_id) if run.precheck_run_id else "",
            },
            # Only what was PERSISTED at validation time; never today's HEAD.  A missing value is UNKNOWN, not a guess.
            "git": {"repository_head": validation.repository_head or UNKNOWN},
            "engines": {
                "validation": validation.engine_version, "planner": plan.planner_version, "execution": run.engine_version,
                "postcheck": (postcheck or {}).get("engine_version") or UNKNOWN,
            },
        },
        "scope": {
            "mode": run.mode, "through_cfg_id": scope["through_cfg_id"], "requested": list(requested), "plan_order": list(scope["plan_order"]),
            "out_of_scope": list(scope["unselected"]), "devices": devices,
        },
        "verification": {
            "state": state_name, "execution_outcome": run.outcome, "postcheck": postcheck, "unverified": unverified,
            "unverified_count": len({e["cfg_id"] for e in unverified}),
            "raw_cfg_ids": [s["record"]["cfg_id"] for s in specs if s["record"]["origin"] == models.ConfigletOrigin.RAW],
            "execution_warning_codes": warning_codes,
        },
        "items": [s["record"] for s in specs],
        "dependencies": edges_in_scope,
    }
    if len(canonical.canonical_json(payload)) > MAX_MANIFEST_BYTES:
        add("BUNDLE_TOO_LARGE", bytes=len(canonical.canonical_json(payload)))
        return snap
    snap.payload, snap.item_specs, snap.verification_state = payload, specs, state_name
    return snap


__all__ = ["PAYLOAD_SCHEMA_VERSION", "Snapshot", "collect"]
