"""The immutable start-time baseline of a probation soak (V2 Phase 5C): exactly what entered probation, as digests and references.

Built once, when the soak starts, and pinned on the run (``ProbationSoakRun.baseline`` + ``baseline_digest``).  It answers, later and without
trusting anyone's memory: which configuration was running on each observed device when the clock started, which Change / validation /
execution / postcheck produced it, what the health and topology looked like at that instant, and under which policy and code version the
observation began.  It stores digests and identifiers -- never configuration text -- and references the existing immutable evidence rows
rather than copying them.  PURE: every device / telemetry read is done by the caller and passed in.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

from django.conf import settings

from ... import models
from ..health.results import iso
from .codes import COLLECTOR_VERSION

SCHEMA = 1
SCHEDULER_UNIT = "nmas-probation-soak-tick.timer"
_SHA = re.compile(r"[0-9a-f]{40}")


def repository_head() -> str:
    """The checked-out commit of the running code, read from the Git metadata FILES (no process is spawned: the soak package never shells
    out).  Handles a linked worktree (``.git`` is a pointer file) and packed refs.  '' when it cannot be determined -- never a guess."""
    try:
        git = Path(settings.REPO_ROOT) / ".git"
        if git.is_file():
            git = (Path(settings.REPO_ROOT) / git.read_text().split("gitdir:", 1)[1].strip()).resolve()
        head = (git / "HEAD").read_text().strip()
        if not head.startswith("ref:"):
            return head[:40] if _SHA.fullmatch(head[:40]) else ""
        ref = head.split("ref:", 1)[1].strip()
        common = git
        if (git / "commondir").is_file():
            common = (git / (git / "commondir").read_text().strip()).resolve()
        for base in (git, common):
            if (base / ref).is_file():
                value = (base / ref).read_text().strip()[:40]
                return value if _SHA.fullmatch(value) else ""
        packed = common / "packed-refs"
        if packed.is_file():
            for line in packed.read_text().splitlines():
                if line.endswith(" " + ref) and _SHA.fullmatch(line[:40]):
                    return line[:40]
    except (OSError, IndexError, ValueError):
        pass
    return ""


def _change_digests(bundle) -> dict:
    """The pre / post change configuration digests the lineage already recorded -- or an honest ``None`` with the reason."""
    provisioning = models.ProvisioningRun.objects.filter(change_id=bundle.change_id).first() if bundle.change_id else None
    if provisioning is not None:
        return {"source": "PROVISIONING_RUN", "prov_id": provisioning.prov_id, "pre_change": provisioning.pre_config_digest or None,
                "post_change": provisioning.post_config_digest or None}
    snapshot = ((bundle.change.metadata or {}).get("workflow_snapshot") or {}) if bundle.change_id else {}
    if snapshot.get("digest"):
        return {"source": "WORKBENCH_SNAPSHOT", "snapshot_id": str(snapshot.get("snapshot_id", ""))[:36], "pre_change": snapshot["digest"], "post_change": None}
    return {"source": "NOT_RECORDED", "pre_change": None, "post_change": None,
            "note": "This Change's lineage recorded no pre-change configuration digest; the device digests at probation start below are authoritative."}


def build(bundle, *, policy, started_at, required_end_at, device_digests: dict, start_assessment=None, snapshot=None, actor: str = "") -> dict:
    root = bundle.source_uat or bundle.parent
    execution, validation, postcheck = bundle.execution_run, bundle.validation_run, bundle.postcheck_run
    provisioning = models.ProvisioningRun.objects.filter(change_id=bundle.change_id).first() if bundle.change_id else None
    health = None
    if start_assessment is not None:
        health = {"sample_result": start_assessment.result, "device_health": start_assessment.device_health,
                  "expected_state": start_assessment.expected_state_result, "telemetry_freshness": start_assessment.telemetry_freshness,
                  "monitoring": start_assessment.monitoring_state, "findings": len(start_assessment.findings),
                  "devices": (start_assessment.evidence or {}).get("devices", {})}
    topology = None
    if snapshot is not None:
        topology = {"available": bool(getattr(snapshot, "available", False)), "backend_status": str(getattr(snapshot, "backend_status", "")),
                    "generated_at": iso(getattr(snapshot, "generated_at", None)) if getattr(snapshot, "generated_at", None) else None,
                    "nodes": len(getattr(snapshot, "nodes", {}) or {}), "edges": len(getattr(snapshot, "edges", []) or [])}
    return {
        "schema": SCHEMA,
        "probation": {"bundle_id": bundle.bundle_id, "bundle_digest": bundle.bundle_digest, "payload_digest": bundle.payload_digest,
                      "root_bundle_id": root.bundle_id if root else "", "root_kind": root.kind if root else ""},
        "change": {"change_id": bundle.change.change_id if bundle.change_id else "",
                   "provisioning": provisioning.prov_id if provisioning else None},
        "evidence": {
            "validation": {"run_id": str(validation.run_id), "status": validation.status} if validation else None,
            "plan": {"plan_id": str(bundle.plan.plan_id), "plan_hash": bundle.plan.plan_hash} if bundle.plan_id else None,
            "execution": {"run_id": str(execution.run_id), "mode": execution.mode, "outcome": execution.outcome} if execution else None,
            "postcheck": {"run_id": str(postcheck.run_id), "result": postcheck.status} if postcheck else None,
        },
        "configuration": {"change": _change_digests(bundle), "devices": device_digests},   # also read by the collector as ``baseline["devices"]``
        "devices": device_digests,
        "health": health,
        "topology": topology,
        "nsot": {"repository_head": repository_head(), "netbox_device_id": (provisioning.netbox or {}).get("device_id") if provisioning else None,
                 "validation_source_hash": validation.source_hash if validation else ""},
        "policy": {"version": policy.version, "duration_seconds": policy.duration_seconds, "duration_days": policy.duration_seconds / 86400,
                   "sample_interval_seconds": policy.sample_interval_seconds, "is_production_duration": policy.is_production_duration},
        "window": {"started_at": iso(started_at), "required_end_at": iso(required_end_at)},
        "deployment": {"repository_root": str(settings.REPO_ROOT), "repository_head": repository_head()},
        "collector": {"version": COLLECTOR_VERSION, "scheduler_unit": SCHEDULER_UNIT, "status_at_start": "NO_SAMPLE_YET",
                      "first_sample_due_at": iso(started_at)},
        "started_by": actor,
    }


def digest(document: dict) -> str:
    return hashlib.sha256(json.dumps({"domain": "clab.soak.baseline", "value": document}, sort_keys=True, default=str).encode()).hexdigest()
