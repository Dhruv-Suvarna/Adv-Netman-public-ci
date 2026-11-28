"""Mapping of s2 collection results onto the s1 contracts (``core.services.troubleshooting.contracts``).

* observation (s2) -> ``observation/1``: quality OK->GOOD, PARTIAL->PARTIAL, STALE->PARTIAL, UNTRUSTED_PARSE->UNTRUSTED, UNKNOWN->MISSING;
  basis OBSERVED for operational/snapshot data, DERIVED for intent inputs and computed rates (intent is not proof of state).
  ``target`` is the sorted ``k=v`` rendering of the s2 target dict; the full s2 observation stays recoverable via ``evidence_id``.
* missing-data record -> ``observation/1`` with ``is_missing_data=true`` (quality MISSING, no value): the contract's own representation.
* s2 bundle -> one ``collection_bundle/1`` per run; the s2 evidence list and missing records travel in ``raw`` (redacted).
The s1 module is imported lazily so these adapters stay usable (and testable) when it is absent; a missing s1 module is reported, not faked.
"""

from __future__ import annotations

from .. import normalization as nz

QUALITY_MAP = {"OK": "GOOD", "PARTIAL": "PARTIAL", "STALE": "PARTIAL", "UNTRUSTED_PARSE": "UNTRUSTED", "UNKNOWN": "MISSING"}
RUN_STATUS_MAP = {"COMPLETE": "SUCCEEDED", "PARTIAL": "PARTIAL", "FAILED": "FAILED", "REFUSED": "DENIED"}


def target_string(target: dict) -> str:
    return ",".join(f"{k}={target[k]}" for k in sorted(target) if target[k] not in (None, ""))


def to_contract_observation(obs: dict) -> dict:
    src = obs["source"]
    out = {
        "key": obs["key"], "target": target_string(obs["target"]), "observed_at": obs["observed_at"] or obs["collected_at"] or "1970-01-01T00:00:00Z",
        "source": f"{src.get('source_type')}:{src.get('transport')}", "quality": QUALITY_MAP[obs["quality"]],
        "basis": "DERIVED" if obs["evidence_class"] == nz.EvidenceClass.INTENT or obs["key"].startswith("interface.rate.") else "OBSERVED",
        "value": obs["value"], "unit": obs["unit"], "max_age_seconds": int(obs["freshness"]["max_age_s"]), "confidence": float(obs["confidence"]),
        "parser_version": f"{obs['parser'].get('id', '')}@{obs['parser'].get('version', '')}", "redaction_status": obs["redaction_status"],
        "evidence_id": src.get("evidence_id") or "", "dedupe_key": obs["observation_id"],
    }
    if obs.get("raw_hash"):
        out["raw_hash"] = obs["raw_hash"]
    return out


def to_contract_missing(record: dict) -> dict:
    return {"key": f"missing.{record['source_type'].lower()}", "target": f"device={record['device']}", "observed_at": record["recorded_at"],
            "source": record["source_type"], "quality": "MISSING", "basis": "OBSERVED", "is_missing_data": True, "missing_reason": record["reason"],
            "evidence_id": record.get("evidence_id") or "", "stage_decision": "UNKNOWN", "redaction_status": "NOT_APPLICABLE"}


def to_contract_bundle(bundle: dict, *, case_id: str, idempotency_key: str | None = None) -> dict:
    """One ``collection_bundle/1`` payload for a collector run bundle (validated by the caller with ``contracts.validate``)."""
    run = bundle["run"]
    observations = [to_contract_observation(o) for o in bundle["observations"]] + [to_contract_missing(m) for m in bundle["missing"]]
    return {
        "schema": "collection_bundle/1", "case_id": case_id, "collector": run["collector"], "adapter": run["adapter"], "adapter_version": run["collector_version"],
        "idempotency_key": idempotency_key or nz.sha256_json([case_id, run["run_id"], run["started_at"]]),
        "targets": [run["device"]], "command_or_api": "; ".join(run["command_or_api"])[:2000] or run["source_type"], "status": RUN_STATUS_MAP[run["status"]],
        "observations": observations, "started_at": run["started_at"], "finished_at": run["finished_at"], "attempts": 1 + run["retries"],
        "timeout_seconds": int(run["timeout_s"]), "rate_budget": run["rate_budget"], "privileges": run["privileges"],
        "raw": {"evidence": bundle["evidence"], "missing": bundle["missing"], "flags": run["flags"], "gateway": run["gateway"], "budget": run["budget"]},
    }
