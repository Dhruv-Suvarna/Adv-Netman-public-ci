"""Remove Configuration validation: re-derive every removal from the persisted, sanitized snapshot text (pure).

The browser's selection is only an INPUT (a line range or object ids).  What will be removed, whether it is safe and whether
anything that stays still depends on it is recomputed here by ``config_workbench.removal`` -- the page's own copy of the
analysis is presentation, never authority.  A blocked, fixture-only or unproven removal makes validation BLOCKED, so no plan
(and therefore no execution) can be built from it.
"""

from __future__ import annotations

from ..config_workbench import removal
from .findings import Code


def analysis_for(item: dict) -> dict:
    selection = item.get("selection") or {}
    line_range = (selection.get("from_line"), selection.get("to_line")) if item["mode"] == "LINE_RANGE" else None
    return removal.analyze(
        item["text"], item["platform"], mode=item["mode"], line_range=line_range,
        object_ids=selection.get("object_ids") or (), accepted_proposals=selection.get("accepted_proposals") or (),
    ).to_dict()


def validate_removals(ctx) -> None:
    items = ((ctx.snapshot.get("config_removals") or {}).get("items")) or []
    ctx.checked["config_removals"] = len(items)
    targets = set(ctx.snapshot.get("targets") or [])
    for item in items:
        where = dict(device=item["device"], object_type="config_removal", object_id=item["snapshot_id"][:8], source="REMOVE_CONFIGURATION")
        if item["device"] not in targets:
            ctx.add(Code.REMOVAL_TARGET_UNKNOWN, f"The removal on {item['device']} is not a target of this Change.", **where)
            continue
        result = analysis_for(item)
        for blocker in result["blockers"]:
            code = Code.REMOVAL_EMPTY if blocker["code"] == removal.EMPTY_SELECTION else Code.REMOVAL_BLOCKED
            ctx.add(code, blocker["message"], **where, evidence={k: v for k, v in blocker.items() if k != "message"},
                    remediation="Adjust the selection (extend it to whole objects, include or change the dependents) and save again.")
        if not result["items"] and not result["blockers"]:
            ctx.add(Code.REMOVAL_EMPTY, f"The removal on {item['device']} resolves to nothing.", **where)
        for entry in result["items"]:
            kind = removal.item_support_kind(entry)
            if not removal.executable(item["platform"], kind):
                ctx.add(Code.REMOVAL_NOT_EXECUTABLE, f"{entry['label']}: the {item['platform']} removal form is {entry['support']}.", **where,
                        evidence={"object": entry["id"], "support": entry["support"]},
                        remediation="Remove it through another reviewed path; this form is not proven on this platform.")
            if not entry["restorable"]:
                ctx.add(Code.REMOVAL_NOT_RESTORABLE, f"{entry['label']} carries redacted values; its compensation is not provable.", **where,
                        evidence={"object": entry["id"]})
        for warning in result["warnings"]:
            if warning["code"] in ("POLICY_CHANGES", "ROUTE_MAP_POLICY_CHANGES"):
                ctx.add(Code.REMOVAL_POLICY_CHANGES, warning["message"], **where, evidence={"object": warning.get("object", "")})
        for proposal in result["proposals"]:
            ctx.add(Code.REMOVAL_PROPOSAL_AVAILABLE, proposal["message"], **where, evidence={"object": proposal["object"]})
