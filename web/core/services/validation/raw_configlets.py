"""Raw Configlet validation (Phase 18): opaque, verified artifacts -- this validator NEVER parses vendor CLI.

For every ENABLED Raw Configlet in the accepted snapshot it checks the structured METADATA and the verification STATUS the snapshot
already carries (the engine is pure: no DB, no sandbox, no device).  A Change with an unverified, stale, blocked or incomplete Raw
Configlet therefore cannot produce a deployable plan: BLOCKED / INCOMPLETE validation refuses plan building.  Missing / cyclic
dependencies are reported by the shared dependency graph (``dependency_graph``), which contains the raw nodes and their EXPLICIT
edges.  Whether the CLI is *semantically* right is never claimed here: syntax verification is the sandbox's job, and network
semantics are checked by the operational postcheck after Partial (UAT) execution.
"""

from __future__ import annotations

from ... import models
from ..raw_configlets import capability
from ..raw_configlets.codes import Currency, Result
from .findings import Code, Severity


def validate_raw_configlets(ctx) -> None:
    items = ((ctx.snapshot.get("raw_configlets") or {}).get("items")) or []
    ctx.checked["raw_configlets"] = len(items)
    for item in items:
        where = dict(device=item["device"], object_type="raw_configlet", object_id=item["raw_id"], source="RAW_CONFIGLET")
        label = f"{item['raw_id']} ({item['name']}) rev {item['revision']}"
        verification = item["verification"]

        if item["device"] not in ctx.model.devices:
            ctx.add(Code.RAW_TARGET_UNKNOWN, f"{label} targets {item['device']}, which has no Device Intent in this Change.", **where,
                    remediation="Add a Device Intent for the device or retarget the Raw Configlet in a new revision.")
        elif item.get("current_platform") and item["current_platform"] != item["platform"]:
            ctx.add(Code.RAW_PLATFORM_MISMATCH,
                    f"{label} was authored for {item['platform']} but {item['device']} is now {item['current_platform']}.", **where,
                    evidence={"revision_platform": item["platform"], "device_platform": item["current_platform"]},
                    remediation="Save a new revision for the current platform and verify it.")

        verify_cap = capability.verification_capability(item["platform"])
        if verify_cap.status != "SUPPORTED":
            ctx.add(Code.RAW_VERIFIER_UNAVAILABLE, f"{label}: raw verification is {verify_cap.status} for {item['platform']}.", **where,
                    evidence={"platform": item["platform"], "status": verify_cap.status})

        currency, result = verification["currency"], verification["result"]
        evidence = {"currency": currency, "result": result, "run_id": verification["run_id"], "reasons": verification["reasons"]}
        if currency == Currency.NEVER_RUN:
            ctx.add(Code.RAW_NOT_VERIFIED, f"{label} has never been verified.", **where, evidence=evidence,
                    remediation="Run Verify on this revision, then re-validate.")
        elif currency == Currency.STALE:
            ctx.add(Code.RAW_VERIFICATION_STALE, f"{label}: the verification is STALE ({', '.join(verification['reasons'])}).", **where, evidence=evidence,
                    remediation="Verify this revision again, then re-validate.")
        elif result == Result.BLOCKED:
            ctx.add(Code.RAW_VERIFICATION_BLOCKED, f"{label}: the verification is BLOCKED.", **where, evidence=evidence,
                    remediation="Fix the reported findings in a new revision and verify it.")
        elif result == Result.INCOMPLETE:
            ctx.add(Code.RAW_VERIFICATION_INCOMPLETE, f"{label}: the verification is INCOMPLETE; nothing was verified.", **where, evidence=evidence,
                    remediation="Resolve the sandbox problem and verify again.")
        elif result == Result.PASS_WITH_WARNINGS:
            ctx.add(Code.RAW_VERIFICATION_WARNINGS, f"{label}: the verification passed with warnings.", **where, evidence=evidence)

        if item["priority"] not in models.DeploymentPriority.values:
            ctx.add(Code.RAW_PRIORITY_INVALID, f"{label} has an invalid priority {item['priority']!r}.", **where)
        if item["node_id"] in item["dependencies"]:
            ctx.add(Code.RAW_DEPENDENCY_SELF, f"{label} depends on itself.", **where, related_objects=[item["node_id"]])

        execution = capability.execution_capability(item["platform"])
        if execution.apply != "SUPPORTED":
            ctx.add(Code.RAW_EXECUTION_NOT_SUPPORTED,
                    f"{label}: raw execution is {execution.apply} for {item['platform']}; it can be verified and planned but not executed.", **where,
                    severity=Severity.WARNING, evidence={"platform": item["platform"], "status": execution.apply})
