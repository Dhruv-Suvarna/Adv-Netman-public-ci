"""The drain plan: one step per (family, direction) that carries active production traffic, in a fixed order, and the
proof each step owes before the device may be called ACTIVE in maintenance.  A plan is a description; nothing runs it.
"""

from __future__ import annotations

from dataclasses import dataclass

from . import model, readiness

ORDER = ((model.IPV6, model.NORTHBOUND), (model.IPV6, model.SOUTHBOUND), (model.IPV4, model.NORTHBOUND), (model.IPV4, model.SOUTHBOUND))

PROOF_MISSING = "DRAIN_PROOF_MISSING"
NOT_MOVED = "TRAFFIC_NOT_MOVED"
LOSS_EVIDENCE_MISSING = "PACKET_LOSS_EVIDENCE_MISSING"
PACKET_LOSS = "PRODUCTION_PACKET_LOSS"
ALTERNATE_UNHEALTHY = readiness.ALTERNATE_UNHEALTHY


@dataclass(frozen=True)
class Step:
    family: str
    direction: str
    mechanism: str
    workloads: tuple[str, ...]


def build(report: model.Report) -> tuple[Step, ...]:
    """Steps for a ready report.  A clear cell needs no step; a blocked report has no plan."""
    if not report.ready:
        raise model.MaintenanceError("NOT_READY", "; ".join(finding.text() for finding in report.blockers))
    return tuple(Step(family, direction, report.cells[(family, direction)]["mechanism"], report.cells[(family, direction)]["active"])
                 for family, direction in ORDER if report.cells[(family, direction)]["verdict"] == readiness.DRAINABLE)


def proof_findings(steps, proofs) -> list:
    """Why the device may NOT be entered as ACTIVE yet.  Every step of every direction must be proven; empty = proven."""
    by_cell = {(proof.family, proof.direction): proof for proof in proofs}
    findings = []
    for step in steps:
        proof = by_cell.get((step.family, step.direction))
        if proof is None:
            findings.append(model.Finding(PROOF_MISSING, step.family, step.direction, model.PRODUCTION, step.workloads))
            continue
        if not proof.moved:
            findings.append(model.Finding(NOT_MOVED, step.family, step.direction, model.PRODUCTION, step.workloads, proof.detail))
        if proof.probes_lost is None:
            findings.append(model.Finding(LOSS_EVIDENCE_MISSING, step.family, step.direction, model.PRODUCTION, step.workloads))
        elif proof.probes_lost > 0:
            findings.append(model.Finding(PACKET_LOSS, step.family, step.direction, model.PRODUCTION, step.workloads, f"{proof.probes_lost} lost"))
        if proof.alternate_healthy is not True:
            findings.append(model.Finding(ALTERNATE_UNHEALTHY, step.family, step.direction, model.PRODUCTION, step.workloads))
    return findings


# ---------------------------------------------------------------------------------------------------------- plan document
# The reviewable, immutable plan.  Built once from what was observed and captured (read-only), hashed, shown to the
# approver and bound to the approval by its hash.  At entry the same document is built again from fresh facts: any
# difference in its basis makes the approved plan STALE and refuses the entry before anything is written.
SCHEMA = 1
CURRENT, STALE, SUPERSEDED = "CURRENT", "STALE", "SUPERSEDED"
PLAN_STALE = "PLAN_STALE"
PLAN_EXPIRED = "PLAN_EXPIRED"


def operation_doc(op, sequence: int) -> dict:
    """One operation as the approver reads it: what is sent, to which device, how it is proven, how it is undone."""
    return {"sequence": sequence, **op.canonical()}


def document(*, record_id: str, request: model.Request, role: str, report: model.Report, steps, observation: dict, state: dict,
             drain_ops=(), drain_final=(), drain_persist=(), restore_ops=(), restore_guards=(), restore_final=(), restore_persist=(),
             mechanisms: dict | None = None, protected: dict | None = None, built_at, validity) -> dict:
    """The plan of one maintenance.  ``observation`` is the stored observation summary (its provenance included);
    ``state`` the captured pre-maintenance state the restore reproduces.  Every list is in execution order."""
    cells = {f"{family}/{direction}": {"verdict": cell["verdict"], "mechanism": cell["mechanism"], "preventive": bool(cell.get("preventive")),
                                       "active": list(cell["active"])} for (family, direction), cell in report.cells.items()}
    return {
        "schema": SCHEMA, "record": record_id, "built_at": built_at.isoformat(), "valid_until": (built_at + validity).isoformat(),
        "target": {"device": request.device, "role": role},
        "request": {"operator": request.operator, "reason": request.reason, "requested_duration_seconds": int(request.requested_duration.total_seconds())},
        "deadline": {"maintenance_cycle_seconds": int(model.MAINTENANCE_CYCLE.total_seconds()), "rule": "entry time + maintenance cycle; then the restore workflow",
                     "requested_duration_ends_nothing": True},
        "readiness": {"cells": cells, "steps": [{"family": s.family, "direction": s.direction, "mechanism": s.mechanism, "workloads": list(s.workloads)} for s in steps]},
        "mechanisms": mechanisms or {},
        "baseline": {"observed_at": observation.get("at"), "digests": observation.get("digests") or {}, "protocols": observation.get("protocols") or {},
                     "intersects": observation.get("intersects") or [], "access": observation.get("access"), "prestate": state},
        "affected": {"dependencies": observation.get("dependencies") or [], "flows": [
            {key: flow.get(key) for key in ("label", "workload", "family", "direction", "activity", "on_device")} for flow in observation.get("flows") or []]},
        "drain": {"operations": [operation_doc(op, n) for n, op in enumerate(drain_ops, 1)], "final_verification": [c.label for c in drain_final],
                  "persist": list(drain_persist),
                  "compensation": "on any failure every applied drain operation is undone newest first by its own inverse, each undo gated by its "
                                  "undo_before checks and proven by its undo_after checks; the startup configuration follows the restored running one"},
        "restore": {"guards": [c.label for c in restore_guards], "operations": [operation_doc(op, n) for n, op in enumerate(restore_ops, 1)],
                    "final_verification": [c.label for c in restore_final], "persist": list(restore_persist),
                    "post_verification": ["routing adjacencies equal the baseline", "management reachability of every device read",
                                          "every production flow's path is followed to its end", "no production probe lost"]},
        "protected": protected or {},
    }


def basis(doc: dict) -> dict:
    """The facts an approval stands on: target, verdicts and mechanisms per cell, the operations with their checks, the
    captured pre-state, the configuration digests, the protocol state, the dependencies and the protected scope.  Not
    the clock, and not the momentary packet activity of each flow (entry evaluates readiness again on its own): a plan
    built again from the same facts has the same basis."""
    cells = {key: {k: v for k, v in cell.items() if k != "active"} for key, cell in ((doc.get("readiness") or {}).get("cells") or {}).items()}
    steps = [{k: v for k, v in step.items() if k != "workloads"} for step in (doc.get("readiness") or {}).get("steps") or []]
    flows = [{k: v for k, v in flow.items() if k != "activity"} for flow in (doc.get("affected") or {}).get("flows") or []]
    return {key: value for key, value in doc.items() if key not in ("built_at", "valid_until", "record", "request")} | {
        "readiness": {"cells": cells, "steps": steps},
        "affected": {**(doc.get("affected") or {}), "flows": flows},
        "baseline": {key: value for key, value in (doc.get("baseline") or {}).items() if key != "observed_at"}}


def digest(doc: dict) -> str:
    from ..bundles import canonical

    return canonical._digest("nmas.maintenance.plan", SCHEMA, doc)


def basis_digest(doc: dict) -> str:
    from ..bundles import canonical

    return canonical._digest("nmas.maintenance.plan.basis", SCHEMA, basis(doc))


def staleness(approved: dict | None, fresh: dict | None, *, now) -> list:
    """Why an approved plan may not be executed now.  Empty = it is still the plan the facts produce."""
    from datetime import datetime

    if not approved:
        return [model.Finding(PLAN_STALE, detail="no approved plan is stored")]
    found = []
    if now > datetime.fromisoformat(approved["valid_until"]):
        found.append(model.Finding(PLAN_EXPIRED, detail=f"the plan was valid until {approved['valid_until']}; evaluate readiness again"))
    if fresh is None:
        found.append(model.Finding(PLAN_STALE, detail="the plan could not be built again from fresh facts"))
    elif basis_digest(approved) != basis_digest(fresh):
        changed = sorted(key for key in basis(approved) if basis(approved).get(key) != basis(fresh).get(key))
        found.append(model.Finding(PLAN_STALE, detail=f"the facts the plan was built from have changed: {', '.join(changed)}"))
    return found
