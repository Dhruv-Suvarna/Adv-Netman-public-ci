"""Validation engine: run every independent validator, aggregate, never fake a PASS.

    run_validation(snapshot, sources) -> report dict     (pure: no DB, no I/O)

Best-effort by design: a source outage or an unexpected validator exception
is recorded as a finding and the remaining validators still run.  The
overall status is derived from the findings alone (BLOCKED > INCOMPLETE >
PASS_WITH_WARNINGS > PASS), so a gap can never surface as PASS.
"""

from __future__ import annotations

import logging

from . import acl, addressing, capabilities, composition, dependency_graph, fhrp, management_vrf, raw_configlets, removals, routing, services_policy, topology
from .context import ProjectModel, ValidationContext
from .findings import (
    ENGINE_VERSION, MAX_FINDINGS, REPORT_SCHEMA_VERSION, Code, Finding, Severity,
    canonical_json, derive_status, sha256_of,
)
from .snapshot import snapshot_stats

logger = logging.getLogger(__name__)

# (name, callable) -- order matters only for derived facts (AUTO addresses are
# derived by `addressing` before the link/routing checks read them).
VALIDATORS = (
    ("platform_identity", capabilities.validate_platform_identity),
    ("capabilities", capabilities.validate_capabilities),
    ("composition", composition.validate_composition),
    ("dependencies", dependency_graph.validate_dependencies),
    ("raw_configlets", raw_configlets.validate_raw_configlets),
    ("config_removals", removals.validate_removals),
    ("addressing", addressing.validate_addressing),
    ("topology", topology.validate_topology),
    ("routing", routing.validate_routing),
    ("fhrp", fhrp.validate_fhrp),
    ("services_policy", services_policy.validate_services_policy),
    ("acl", acl.validate_acls),
    ("management_vrf", management_vrf.validate_management_vrf),
)

LIMITATIONS = (
    "Project validation uses committed/accepted intent only; uncommitted browser drafts are not part of any run.",
    "This result does not prove that deployment will succeed; no device was contacted and no running configuration was read.",
    "AUTO addresses are read-only PROPOSALS: not reserved, not written to NetBox, and must be rechecked immediately before deployment.",
    "Routing and NAT behavior are not simulated; only cross-device consistency that concrete evidence supports is checked.",
    "ACL analysis is conservative: structured entries against a fixed required-flow catalogue, first-match order, three-valued matching.",
    "The dependency graph is semantic only and is not a deployment plan (no order, stages, or Configlets: Phase 14).",
)

_SOURCE_CODES = {
    "NETBOX": Code.SOURCE_NETBOX_UNAVAILABLE,
    "TOPOLOGY": Code.SOURCE_TOPOLOGY_UNAVAILABLE,
    "INVENTORY": Code.SOURCE_INVENTORY_UNAVAILABLE,
}


def compute_requirements(model: ProjectModel) -> dict:
    """Which external sources this Change genuinely needs (drives INCOMPLETE)."""
    devices = list(model.devices.values())
    needs_netbox = bool(
        model.addresses or model.auto_addresses or model.invalid_addresses
        or any(d.fhrp_instances or d.dhcp.get("relays") or d.dhcp.get("clients")
               or d.nat.get("pools") or d.nat.get("rules") for d in devices)
    )
    return {
        "NETBOX": "addresses, DHCP or NAT objects need NetBox collision/pool evidence" if needs_netbox else "",
        "TOPOLOGY": "interfaces need link evidence" if model.has_any_interface() else "",
        "INVENTORY": "existing-device intents are checked against project inventory"
        if any(d.target_type == "EXISTING_DEVICE" for d in devices) else "",
    }


def _source_findings(ctx: ValidationContext, requirements: dict) -> None:
    for result in (ctx.sources.netbox, ctx.sources.topology, ctx.sources.inventory):
        if result.available:
            continue
        required = bool(requirements.get(result.name))
        ctx.add(
            _SOURCE_CODES[result.name],
            f"{result.message} "
            + ("Evidence this Change needs is missing, so the result is INCOMPLETE."
               if required else "This Change does not depend on it; checks that need it were skipped."),
            severity=Severity.ERROR if required else Severity.WARNING,
            incomplete=required, blocking=False,
            source=result.name, object_type="source", object_id=result.name,
            evidence={"source": result.name, "required": required, "reason": requirements.get(result.name, "")},
            remediation="Restore the source and re-run validation; nothing was assumed in its place.",
        )


def _dedupe_and_bound(findings: list[Finding]) -> tuple[list[Finding], int]:
    unique = {}
    for finding in findings:
        unique.setdefault((finding.finding_id(), finding.message), finding)
    ordered = sorted(unique.values(), key=lambda f: f.sort_key())
    dropped = max(0, len(ordered) - MAX_FINDINGS)
    if dropped:
        ordered = ordered[:MAX_FINDINGS]
        ordered.append(Finding(
            code=Code.REPORT_TRUNCATED,
            message=f"{dropped} lower-priority findings were omitted to keep the report bounded.",
            object_type="report", object_id="findings", source="ENGINE", evidence={"omitted": dropped},
        ))
        ordered.sort(key=lambda f: f.sort_key())
    return ordered, dropped


def run_validation(snapshot: dict, sources) -> dict:
    model = ProjectModel(snapshot)
    ctx = ValidationContext(snapshot=snapshot, model=model, sources=sources)
    requirements = compute_requirements(model)
    _source_findings(ctx, requirements)

    completed, failed = [], []
    for name, validator in VALIDATORS:
        try:
            validator(ctx)
            completed.append(name)
        except Exception as exc:  # noqa: BLE001 - engine boundary: a validator bug must never look like PASS
            failed.append(name)
            logger.error("Change validator %r failed unexpectedly (%s).", name, exc.__class__.__name__)
            ctx.add(
                Code.INTERNAL_VALIDATION_ERROR,
                f"Validator '{name}' failed unexpectedly; its checks did not complete.",
                object_type="validator", object_id=name, source="ENGINE",
                evidence={"validator": name, "error_type": exc.__class__.__name__},
                remediation="Report this defect; the result cannot be trusted as PASS.",
            )

    findings, omitted = _dedupe_and_bound(ctx.findings)
    status = derive_status(findings)
    counts = {sev: sum(1 for f in findings if f.severity == sev) for sev in Severity.ALL}
    stats = snapshot_stats(snapshot)
    facts = sorted(ctx.derived, key=canonical_json)
    summary = {
        "status": status,
        "errors": counts[Severity.ERROR],
        "warnings": counts[Severity.WARNING],
        "info": counts[Severity.INFO],
        "blocking_findings": sum(1 for f in findings if f.blocking),
        "incomplete_findings": sum(1 for f in findings if f.incomplete),
        "devices_checked": stats["devices"],
        "objects_checked": stats["objects"],
        "sources_available": {item.name: item.available for item in sources.all()},
        "sources_required": {key: bool(value) for key, value in requirements.items()},
        "validators_completed": completed,
        "validators_failed": failed,
        "derived_facts": len(facts),
        "omitted_findings": omitted,
        "checked": dict(sorted(ctx.checked.items())),
    }
    return {
        "report_schema_version": REPORT_SCHEMA_VERSION,
        "engine_version": ENGINE_VERSION,
        "status": status,
        "summary": summary,
        "findings": [f.to_dict() for f in findings],
        "derived_facts": facts,
        "dependency_graph": ctx.graph or {"schema_version": 1, "nodes": [], "edges": [], "cycles": [], "summary": {}},
        "limitations": list(LIMITATIONS),
    }


def semantic_digest(report: dict) -> str:
    """Hash of everything semantic (status, findings, facts, graph) -- no timestamps or run IDs."""
    return sha256_of({
        "status": report["status"],
        "summary": {k: v for k, v in report["summary"].items()},
        "findings": report["findings"],
        "derived_facts": report["derived_facts"],
        "dependency_graph": report["dependency_graph"],
    })
