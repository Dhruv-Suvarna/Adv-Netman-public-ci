"""Plan eligibility, deterministic plan computation, atomic persistence and plan currency.

    check_eligibility(change)      -> which validation run (if any) a plan may be built from
    compute_plan(change, run)      -> the plan as a PURE document (no DB writes, no network)
    persist_plan(change, run, doc) -> ONE transaction: ChangePlan + Configlets + dependencies + audit
    build_change_plan(change)      -> eligibility -> (idempotent) compute -> persist
    get_plan_currency(plan)        -> CURRENT / STALE with machine-readable reasons

A plan is built ONLY from the latest validation when it is CURRENT and PASS or
PASS_WITH_WARNINGS.  Validation is never re-run here.  Nothing below contacts a
device, NetBox, Git or GitHub, executes a Configlet, or changes Change.lifecycle_state.
"""

from __future__ import annotations

from django.db import IntegrityError, transaction

from ... import models
from .. import change_validation_service as cvs, secret_policy
from ..raw_configlets import codes as raw_codes, text as raw_text, verification as raw_verification
from ..validation import snapshot as snapshot_module
from ..validation.findings import Currency, Status, sha256_of
from . import configlet_factory, dependency_mapping, ordering, priorities
from .errors import PlanGenerationError

PLANNER_VERSION = priorities.PLANNER_VERSION
PLAN_CURRENT = "CURRENT"
PLAN_STALE = "STALE"

PREVIOUS_STATE = {
    "status": "UNKNOWN_DEFERRED",
    "note": "Phase 14 performs no live retrieval. The real pre-change state is captured at execution "
            "preparation (Phase 17); no rollback text is fabricated here.",
}

_ELIGIBLE_STATUSES = (Status.PASS, Status.PASS_WITH_WARNINGS)
_REFUSAL_BY_STATUS = {Status.BLOCKED: "VALIDATION_BLOCKED", Status.INCOMPLETE: "VALIDATION_INCOMPLETE"}


# --- eligibility -------------------------------------------------------------------------------
def check_eligibility(change, *, sources=None, check_sources: bool = False) -> dict:
    """{"eligible", "code", "reason", "run", "currency"}.  Never runs validation; never writes."""
    currency = cvs.get_validation_currency(change, sources=sources, check_sources=check_sources)
    state, run = currency["state"], currency["latest"]
    code = None
    if state == Currency.NEVER_RUN:
        code = "VALIDATION_NEVER_RUN"
    elif state == Currency.STALE:
        code = "VALIDATION_STALE"
    elif run.status not in _ELIGIBLE_STATUSES:
        code = _REFUSAL_BY_STATUS[run.status]
    if code is not None:
        return {"eligible": False, "code": code, "reason": PlanGenerationError(code).message, "run": run, "currency": currency}
    return {"eligible": True, "code": "", "reason": "", "run": run, "currency": currency}


def _raw_inputs(change, snapshot: dict) -> dict:
    """Load every pinned Raw Configlet revision + verification run and RE-CHECK them (the plan never trusts the snapshot alone).

    -> {raw graph node id: (snapshot item, revision, verification run)}.  Read-only; raises PlanGenerationError.
    """
    found = {}
    for item in (snapshot.get("raw_configlets") or {}).get("items") or []:
        revision = models.RawConfigletRevision.objects.filter(
            raw__change=change, raw__raw_id=item["raw_id"], revision=item["revision"]
        ).select_related("raw").first()
        if revision is None or revision.content_hash != item["content_hash"] or raw_text.content_hash(revision.content) != revision.content_hash:
            raise PlanGenerationError("RAW_REVISION_MISMATCH", raw_id=item["raw_id"])
        run = models.RawConfigletVerificationRun.objects.filter(run_id=item["verification"]["run_id"] or None, revision=revision).first()
        status = raw_verification.currency(revision)
        if run is None or status["state"] != raw_codes.Currency.CURRENT or status["run"] is None or status["run"].pk != run.pk \
                or run.result not in raw_codes.Result.ACCEPTABLE:
            raise PlanGenerationError("RAW_VERIFICATION_NOT_CURRENT", raw_id=item["raw_id"])
        found[item["node_id"]] = (item, revision, run)
    return found


# --- pure plan computation ---------------------------------------------------------------------
def _removal_inputs(change, snapshot: dict) -> dict:
    """{removal graph node id: (snapshot entry, removal item)} -- RE-DERIVED from the hashed snapshot text (never the page's copy)."""
    from ..validation.dependency_graph import node_id, removal_node_object_id
    from ..validation.removals import analysis_for

    found = {}
    for entry in ((snapshot.get("config_removals") or {}).get("items")) or []:
        result = analysis_for(entry)
        if result["status"] != "READY":
            raise PlanGenerationError("DEPENDENCY_MISSING", device=entry["device"], reason="removal analysis is not READY")
        for item in result["items"]:
            found[node_id(entry["device"], "config_removal", removal_node_object_id(item["id"]))] = (entry, item)
    return found


def _exclude_contribution_context(snapshot: dict, specs: list, node_to_key: dict) -> tuple[list, set, list[dict]]:
    """Configuration Changes: objects imported from the live device are CONTEXT (they already exist there), never re-deployed.

    Only structured Configlets whose object id was NOT in the recorded import baseline survive, so the plan is exactly the
    operator's incremental contribution.  Child snippets keep their own block headers (``interface Ethernet1`` + the new
    line), so nothing outside the requested patch is sent.
    """
    baseline = snapshot.get("contribution_baseline") or {}
    ids, device = set(baseline.get("object_ids") or ()), baseline.get("device")
    if not ids:
        return specs, set(), []
    context = [spec for spec in specs if spec.device == device and spec.origin == "STRUCTURED" and spec.object_id in ids]
    context_keys = {spec.key for spec in context}
    kept = [spec for spec in specs if spec.key not in context_keys]
    for spec in kept:
        if spec.parent_key in context_keys:
            spec.parent_key = None      # the parent already exists on the device
    skipped = {spec.node_id for spec in context}
    for node in list(node_to_key):
        if node_to_key[node] in context_keys:
            del node_to_key[node]
    warnings = [{
        "code": "CONTRIBUTION_CONTEXT_EXCLUDED",
        "message": f"{len(context)} object(s) imported from the running configuration are context only and are not re-deployed; "
                   "the plan contains only the requested contribution.",
        "details": {"device": device, "context_objects": len(context)},
    }] if context else []
    return kept, skipped, warnings


def _validation_provenance(run) -> dict:
    findings = (run.report or {}).get("findings", [])
    return {
        "run_id": str(run.run_id), "status": run.status, "input_hash": run.input_hash, "source_hash": run.source_hash,
        "engine_version": run.engine_version,
        "warning_count": int((run.summary or {}).get("warnings", 0)),
        "warning_codes": sorted({f["code"] for f in findings if f.get("severity") == "WARNING"}),
    }


def compute_plan(change, run) -> dict:
    """Build the whole plan document from ACCEPTED intent + the pinned run's facts.  Raises PlanGenerationError."""
    snapshot = snapshot_module.build_change_snapshot(change)
    if snapshot_module.hash_snapshot(snapshot) != run.input_hash:
        raise PlanGenerationError("INPUT_HASH_MISMATCH", run_input_hash=run.input_hash[:16])
    graph = run.dependency_graph or {}
    if (graph.get("summary") or {}).get("truncated"):
        raise PlanGenerationError("GRAPH_TRUNCATED")

    derived_addresses = {
        (fact["device"], fact["object_id"]): fact for fact in (run.derived_facts or []) if fact.get("type") == "AUTO_ADDRESS"
    }
    contexts = {}
    for intent in change.device_intents.order_by("device_name"):
        revision = intent.latest_revision()
        if revision is not None:
            contexts[intent.device_name] = configlet_factory.DeviceContext(intent, revision, derived_addresses)

    specs, node_to_key, warnings = configlet_factory.build_specs(contexts, graph, _raw_inputs(change, snapshot), _removal_inputs(change, snapshot))
    skipped = {w["details"]["node"] for w in warnings if w["code"] == "NO_DEPLOYABLE_CONFIG"}
    specs, context_nodes, context_warnings = _exclude_contribution_context(snapshot, specs, node_to_key)
    skipped |= context_nodes
    warnings.extend(context_warnings)
    edges = dependency_mapping.map_dependencies(graph, specs, node_to_key, skipped_nodes=skipped)

    by_key = {spec.key: spec for spec in specs}
    order = ordering.topological_order({key: spec.sort_key for key, spec in by_key.items()}, set(edges))
    cfg_ids = {key: f"CFG-{position:03d}" for position, key in enumerate(order, start=1)}

    dependencies_of: dict[str, list[dict]] = {key: [] for key in order}
    flat_dependencies: list[dict] = []
    for (dependent, dependency), info in edges.items():
        record = {"cfg_id": cfg_ids[dependency], "edge_types": info["edge_types"], "reasons": info["reasons"]}
        dependencies_of[dependent].append(record)
        flat_dependencies.append({"configlet": cfg_ids[dependent], "depends_on": cfg_ids[dependency], **info})
        if by_key[dependency].object_class.priority > by_key[dependent].object_class.priority:
            warnings.append({
                "code": "PRIORITY_DEPENDENCY_INVERSION",
                "message": f"{cfg_ids[dependent]} (priority {int(by_key[dependent].object_class.priority)}) depends on "
                           f"{cfg_ids[dependency]} (priority {int(by_key[dependency].object_class.priority)}); "
                           "the dependency wins and the dependency is ordered first.",
                "details": {"configlet": cfg_ids[dependent], "depends_on": cfg_ids[dependency]},
            })
    flat_dependencies.sort(key=lambda edge: (edge["configlet"], edge["depends_on"]))

    configlets = []
    for position, key in enumerate(order, start=1):
        spec = by_key[key]
        cls = spec.object_class
        record_warnings = []
        if spec.derived:
            record_warnings.append("AUTO_ADDRESS_RECHECK_REQUIRED")
        if any(w["code"] == "PRIORITY_DEPENDENCY_INVERSION" and w["details"]["configlet"] == cfg_ids[key] for w in warnings):
            record_warnings.append("PRIORITY_DEPENDENCY_INVERSION")
        if spec.origin == "RAW":
            record_warnings.append("RAW_OPAQUE_CONFIGLET")
        configlets.append({
            "cfg_id": cfg_ids[key], "sequence": position, "key": key, "node_id": spec.node_id, "device": spec.device,
            "platform": spec.platform, "priority": int(cls.priority), "stage": priorities.STAGE_KEYS[cls.priority],
            "operation": str(cls.operation), "namespace": str(cls.namespace),
            "object_type": spec.source_type, "object_id": spec.object_id, "label": spec.label,
            "capability_feature": spec.capability_feature,
            "description": f"{cls.noun}: {spec.label}",
            "rendered_config": "\n".join(spec.lines),
            "dependencies": sorted(dependencies_of[key], key=lambda d: d["cfg_id"]),
            "verification": configlet_factory.verification_requirements(spec),
            "previous_state": dict(PREVIOUS_STATE),
            "derived": spec.derived,
            "warnings": record_warnings,
            "origin": spec.origin,
            "raw": spec.raw,
            "removal": spec.removal,
        })

    auto_configlets = [c["cfg_id"] for c in configlets if c["derived"]]
    if auto_configlets:
        warnings.append({
            "code": "AUTO_ADDRESS_RECHECK_REQUIRED",
            "message": "AUTO addresses use the validation-derived PROPOSED value (not reserved, not written to NetBox). "
                       "Recheck them immediately before deployment.",
            "details": {"configlets": auto_configlets},
        })
    raw_configlets = [c["cfg_id"] for c in configlets if c["origin"] == "RAW"]
    if raw_configlets:
        warnings.append({
            "code": "RAW_CONFIGLETS_OPAQUE",
            "message": "Raw Configlets are opaque, operator-authored and verified for SYNTAX only. They have no proven compensation, so this plan "
                       "cannot run in Complete mode, and their effect is not verified unless the operator declared postcheck assertions.",
            "details": {"configlets": raw_configlets},
        })
    provenance_validation = _validation_provenance(run)
    if run.status == Status.PASS_WITH_WARNINGS:
        warnings.append({
            "code": "VALIDATION_WARNINGS_CARRIED_FORWARD",
            "message": f"The pinned validation passed with {provenance_validation['warning_count']} warning(s); they are carried forward.",
            "details": {"count": provenance_validation["warning_count"], "codes": provenance_validation["warning_codes"]},
        })
    if configlets:
        warnings.append({"code": "PREVIOUS_STATE_DEFERRED", "message": PREVIOUS_STATE["note"], "details": {}})
        warnings.append({
            "code": "VERIFICATION_REQUIREMENT_DEFERRED",
            "message": "Verification requirements are declarative descriptors only; Phase 15 owns real prechecks and postchecks.",
            "details": {},
        })
    warnings.sort(key=lambda w: (w["code"], sha256_of(w["details"])))

    stages = [{**stage, "cfg_ids": [c["cfg_id"] for c in configlets if c["priority"] == stage["priority"]]}
              for stage in priorities.stage_table()]
    summary = {
        "configlets": len(configlets),
        "devices": len({c["device"] for c in configlets}),
        "dependencies": len(flat_dependencies),
        "warnings": len(warnings),
        "by_stage": {stage["key"]: len(stage["cfg_ids"]) for stage in stages},
        "by_operation": {op: sum(1 for c in configlets if c["operation"] == op) for op in sorted({c["operation"] for c in configlets})},
    }
    semantic = {
        "planner_version": PLANNER_VERSION, "input_hash": run.input_hash, "source_hash": run.source_hash,
        "engine_version": run.engine_version,
        "configlets": [
            {k: c[k] for k in ("cfg_id", "key", "device", "priority", "operation", "namespace", "rendered_config")}
            | {"depends_on": [d["cfg_id"] for d in c["dependencies"]]}
            | ({"raw": {k: c["raw"][k] for k in ("raw_id", "revision", "content_hash", "verification_run_id")}} if c["raw"] else {})
            for c in configlets
        ],
    }
    return {
        "planner_version": PLANNER_VERSION, "schema_version": priorities.PLAN_SCHEMA_VERSION,
        "configlets": configlets, "dependencies": flat_dependencies, "stages": stages, "warnings": warnings,
        "summary": summary, "provenance": {"validation": provenance_validation, "planner": {"version": PLANNER_VERSION}},
        "plan_hash": sha256_of(semantic),
    }


# --- persistence (one transaction) -------------------------------------------------------------
def persist_plan(change, run, document: dict, *, actor: str = "") -> models.ChangePlan:
    intents = {intent.device_name: intent for intent in change.device_intents.all()}
    with transaction.atomic():
        plan = models.ChangePlan.objects.create(
            change=change, validation_run=run, planner_version=document["planner_version"],
            validation_input_hash=run.input_hash, validation_source_hash=run.source_hash,
            validation_engine_version=run.engine_version, plan_hash=document["plan_hash"], created_by=actor,
            summary=document["summary"], warnings=document["warnings"], provenance=document["provenance"],
        )
        created = {}
        for record in document["configlets"]:
            desired = {
                "source": {"node_id": record["node_id"], "object_type": record["object_type"],
                           "object_id": record["object_id"], "device": record["device"], "platform": record["platform"],
                           "capability_feature": record.get("capability_feature") or ""},
                "validation_run_id": str(run.run_id),
            }
            raw_revision = raw_run = None
            if record["origin"] == "RAW":
                pins = record["raw"]
                raw_revision = models.RawConfigletRevision.objects.get(raw__change=change, raw__raw_id=pins["raw_id"], revision=pins["revision"])
                raw_run = models.RawConfigletVerificationRun.objects.get(run_id=pins["verification_run_id"], revision=raw_revision)
                desired["raw"] = pins
            verification = {"schema_version": 1, "requirements": record["verification"]}
            metadata = {
                "plan_id": str(plan.plan_id), "planner_version": document["planner_version"], "stage": record["stage"],
                "label": record["label"], "dependencies": record["dependencies"], "warnings": record["warnings"],
                "validation": {"run_id": str(run.run_id), "input_hash": run.input_hash, "source_hash": run.source_hash},
                "derived": record["derived"], "previous_state": "UNKNOWN_DEFERRED",
            }
            if record["origin"] == "RAW":
                metadata["raw"] = record["raw"]
            if record["origin"] == "REMOVAL":
                metadata["removal"] = record["removal"]
                metadata["previous_state"] = "CAPTURED_AT_EXECUTION"
            for context, value in (("desired_state_ref", desired), ("verification_spec", verification), ("metadata", metadata)):
                secret_policy.assert_no_secret_shaped_keys(value, context=f"Configlet {context}")
            created[record["cfg_id"]] = models.Configlet.objects.create(
                change=change, plan=plan, cfg_id=record["cfg_id"], sequence=record["sequence"], target_device=record["device"],
                device_intent=intents.get(record["device"]), feature_namespace=record["namespace"],
                description=record["description"], operation_type=record["operation"], deployment_priority=record["priority"],
                previous_state_ref=record["previous_state"], desired_state_ref=desired, rendered_config=record["rendered_config"],
                verification_spec=verification, metadata=metadata,
                origin=record["origin"], raw_revision=raw_revision, raw_verification=raw_run,
            )
        for edge in document["dependencies"]:
            models.ConfigletDependency.objects.create(
                configlet=created[edge["configlet"]], depends_on=created[edge["depends_on"]]
            )
        models.AuditEvent.objects.create(
            event_type=models.AuditEventType.PLAN_BUILT, change=change, object_type="ChangePlan", object_id=str(plan.plan_id),
            actor=actor,
            summary=f"{change.change_id}: plan built ({document['summary']['configlets']} Configlets)",
            metadata={
                "plan_id": str(plan.plan_id), "validation_run_id": str(run.run_id), "configlets": document["summary"]["configlets"],
                "warnings": document["summary"]["warnings"], "plan_hash": document["plan_hash"],
            },
        )
    return plan


def build_change_plan(change, *, actor: str = "", sources=None, check_sources: bool = False) -> tuple[models.ChangePlan, bool]:
    """-> (plan, created).  Idempotent: the same validation run + planner version never yields a second plan."""
    eligibility = check_eligibility(change, sources=sources, check_sources=check_sources)
    if not eligibility["eligible"]:
        raise PlanGenerationError(eligibility["code"], validation_status=getattr(eligibility["run"], "status", None),
                                  reasons=eligibility["currency"]["reasons"])
    run = eligibility["run"]
    existing = plan_for_run(run)
    if existing is not None:
        return existing, False
    document = compute_plan(change, run)
    try:
        return persist_plan(change, run, document, actor=actor), True
    except IntegrityError:  # a concurrent build won the (run, planner version) uniqueness race
        existing = plan_for_run(run)
        if existing is None:
            raise
        return existing, False


def plan_for_run(run) -> models.ChangePlan | None:
    return run.plans.filter(planner_version=PLANNER_VERSION).first()


# --- currency ----------------------------------------------------------------------------------
def get_plan_currency(plan: models.ChangePlan, *, sources=None, check_sources: bool = False) -> dict:
    """CURRENT only while the pinned validation is still the CURRENT latest run for unchanged accepted intent."""
    change = plan.change
    reasons: list[str] = []
    latest = cvs.get_latest_validation(change)
    if latest is None or latest.pk != plan.validation_run_id:
        reasons.append("VALIDATION_SUPERSEDED")
    currency = cvs.get_validation_currency(change, sources=sources, check_sources=check_sources)
    reasons.extend(reason for reason in currency["reasons"] if reason not in reasons)
    if plan.planner_version != PLANNER_VERSION:
        reasons.append("PLANNER_VERSION_CHANGED")
    return {
        "state": PLAN_STALE if reasons else PLAN_CURRENT, "reasons": reasons,
        "validation_currency": currency["state"], "sources_checked": currency["sources_checked"],
    }


def get_latest_plan(change) -> models.ChangePlan | None:
    return change.plans.order_by("-created_at", "-id").first()


def get_current_plan(change, *, sources=None, check_sources: bool = False) -> models.ChangePlan | None:
    plan = get_latest_plan(change)
    if plan is None or get_plan_currency(plan, sources=sources, check_sources=check_sources)["state"] != PLAN_CURRENT:
        return None
    return plan
