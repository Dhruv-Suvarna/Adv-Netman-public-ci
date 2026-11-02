"""Platform safety: provisioning fails closed on anything the Phase-4 matrix does not prove.

"A renderer exists" is never support.  A feature is usable only when its (platform, feature) cell is terminally SUPPORTED -- every mandatory axis,
including the empirical live write / post-write / compensation / runtime axes -- and the cell's exhaustive assessment is complete.  The blocking
cell and its first unsupported reason are reported verbatim from ``capabilities.registry``.
"""

from __future__ import annotations

from ..capabilities import assessment as assessment_module, evidence as evidence_module, features, registry
from ..capabilities.axes import TerminalStatus
from . import bootstrap
from .codes import blocker


def _cell(platform: str, key: str, evidence, assessments) -> dict:
    if key not in features.by_key():
        return {"feature": key, "status": TerminalStatus.UNSUPPORTED.value, "reason": "Not a feature of the capability catalogue."}
    record = registry.capability_record(platform, key, evidence=evidence, assessment=assessments.get((platform, key)))
    return {"feature": key, "status": record.status.value, "reason": record.unsupported_reason}


def supported_features(platform: str) -> list[str]:
    evidence, assessments = evidence_module.latest_evidence(), assessment_module.latest_assessments()
    return [key for key in features.by_key() if _cell(platform, key, evidence, assessments)["status"] == TerminalStatus.SUPPORTED.value]


def resolve_platform(platform: str, transport: str) -> tuple[dict, list[dict]]:
    """Stage CAPABILITY: can this platform be provisioned at all?  -> (resolution, blockers)"""
    transport_ok, transport_reason = bootstrap.transport_support(platform, transport)
    supported = supported_features(platform) if platform in features.platforms() else []
    resolution = {"platform": platform, "transport": {"name": transport, "supported": transport_ok, "evidence": transport_reason},
                  "supported_features": supported, "supported_count": len(supported)}
    blockers = []
    if not transport_ok:
        blockers.append(blocker("BOOTSTRAP_TRANSPORT_UNSUPPORTED", platform=platform, transport=transport, reason=transport_reason))
    if not supported:
        blockers.append(blocker("CAPABILITY_UNSUPPORTED", platform=platform, reason="No capability cell of this platform is fully supported."))
    return resolution, blockers


def resolve_plan(platform: str, plan) -> tuple[dict, list[dict]]:
    """Stage PLAN: every Configlet of the plan must carry an exact, fully SUPPORTED Phase-4 feature.  -> (resolution, blockers)"""
    evidence, assessments = evidence_module.latest_evidence(), assessment_module.latest_assessments()
    cells, unclassified, unsupported = {}, [], []
    for configlet in plan.configlets.order_by("sequence"):
        source = (configlet.desired_state_ref or {}).get("source") or {}
        key = str(source.get("capability_feature") or "")
        if not key:
            unclassified.append({"cfg_id": configlet.cfg_id, "object_type": str(source.get("object_type") or "")})
            continue
        cell = cells.setdefault(key, {**_cell(platform, key, evidence, assessments), "configlets": []})
        cell["configlets"].append(configlet.cfg_id)
        if cell["status"] != TerminalStatus.SUPPORTED.value and key not in [u["feature"] for u in unsupported]:
            unsupported.append({"feature": key, "platform": platform, "reason": cell["reason"]})
    blockers = []
    if unclassified:
        blockers.append(blocker("CAPABILITY_UNCLASSIFIED", configlets=unclassified))
    for item in unsupported:
        blockers.append(blocker("CAPABILITY_UNSUPPORTED", **item))
    return {"platform": platform, "cells": [cells[key] for key in sorted(cells)], "unclassified": unclassified}, blockers
