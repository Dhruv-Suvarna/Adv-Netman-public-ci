"""Validate the normalized candidate scope model before planning."""

from __future__ import annotations

from .. import platform_drivers
from .findings import Code


def validate_composition(ctx) -> None:
    checked = 0
    for name in sorted(ctx.model.devices):
        device = ctx.model.devices[name]
        driver = platform_drivers.get_driver(device.platform)
        entry = device.entry
        normalized = driver.compose_candidate(
            field_values={
                "device.hostname": (entry.get("identity") or {}).get("hostname") or name,
                "device.description": (entry.get("identity") or {}).get("description") or "",
            },
            interfaces=list(device.interfaces.values()),
            routing=device.routing,
            phase12={
                key: entry.get(key) or {}
                for key in ("fhrp", "nat", "services", "security", "policy")
            },
        )
        for conflict in normalized["conflicts"]:
            checked += 1
            ctx.add(
                Code.CANDIDATE_COMPOSITION_CONFLICT,
                (
                    f"{name}: incompatible contributions claim {conflict['scope_kind']} "
                    f"{conflict['scope_id']} property {conflict['field']}."
                ),
                device=name,
                object_type="candidate_scope",
                object_id=f"{conflict['scope_kind']}:{conflict['scope_id']}",
                field_path=conflict["field"],
                related_objects=[conflict["existing_source"], conflict["incoming_source"]],
                source="NORMALIZED_CANDIDATE",
                evidence={
                    "scope_kind": conflict["scope_kind"],
                    "scope_id": conflict["scope_id"],
                    "property": conflict["field"],
                    "existing": conflict["existing"],
                    "incoming": conflict["incoming"],
                },
                remediation="Remove one contribution or make both contributions semantically identical.",
            )
    ctx.checked["composition_conflicts"] = checked
