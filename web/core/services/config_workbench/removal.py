"""Dependency-aware removal analysis (Remove Configuration workflow).  Pure: text in, analysis out.

    selection (line range | semantic object ids) + explicitly accepted proposals
      -> resolve to whole semantic objects / individually removable attribute lines
         (a range that cuts through a stanza's context is BLOCKED -- never guessed)
      -> dependency check: anything still referenced by configuration that stays is BLOCKED
      -> proposals: named objects the removal leaves UNUSED (e.g. the VLAN of a removed SVI) are PROPOSED, never added
      -> deterministic items (removal lines, restore lines, verification paths) in a safe order (detach before delete)

The analysis is re-derived by the validator from the persisted snapshot text; nothing here trusts browser text.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field

from .semantics import ANY_ACL, ALL_VLANS, DEACTIVATE_DETACH, REMOVE_DELETE, ConfigModel, build_model

SCHEMA_VERSION = 1

# Evidence classes (honest support status of each removal form).
PARSER_VALIDATED = "PARSER_VALIDATED"   # accepted by the live cEOS 4.36.2F parser in an ABORTED session (nothing committed)
FIXTURE_ONLY = "FIXTURE_ONLY"           # rendered and unit-tested; syntax NOT proven on a device -> not executable
NOT_IMPLEMENTED = "NOT_IMPLEMENTED"

# Every form below was ACCEPTED by the live cEOS 4.36.2F parser inside a configuration session that was aborted or deleted
# uncommitted (running-config SHA-256 identical before and after; see docs/AUTOMATION_CONFIGURATION_WORKFLOWS.md "Syntax
# evidence").  Anything else renders for preview but is never executable.
CEOS_PARSER_VALIDATED: frozenset[str] = frozenset({
    "svi", "vlan", "loopback", "subinterface", "port_channel", "static_route", "secondary_address", "primary_address",
    "ipv6_address", "vlan_access_membership", "acl_attachment", "dhcp_relay", "fhrp_vip", "vrrp_group", "ospf_interface_attachment",
    "redistribution", "rip_network", "ospf_network", "ospf_process", "ospf3_process", "rip_process", "bgp_neighbor", "bgp_peer_group",
    "bgp_neighbor_af", "bgp_network", "bgp_process", "acl", "acl_entry", "route_map_entry", "prefix_list_entry", "prefix_list",
    "pbr_class", "pbr_policy", "pbr_sequence", "pbr_attachment",
    # attribute lines (``no <line>`` in context), by attribute kind
    "attribute:description", "attribute:mtu", "attribute:native_vlan", "attribute:neighbor_attribute",
    "attribute:passive_interface", "attribute:ip_ospf", "attribute:route_map_clause",
})
EXECUTABLE_PLATFORMS = frozenset({"arista_ceos"})

# blocker codes
EMPTY_SELECTION = "EMPTY_SELECTION"
OUT_OF_RANGE = "LINE_RANGE_OUT_OF_BOUNDS"
PARTIAL_CONTEXT = "PARTIAL_CONTEXT_SELECTED"
NOT_REMOVABLE = "NOT_REMOVABLE"
PROTECTED = "PROTECTED_OBJECT"
REFERENCED = "STILL_REFERENCED"
UNKNOWN_OBJECT = "UNKNOWN_OBJECT"
UNSUPPORTED_PLATFORM = "UNSUPPORTED_PLATFORM"


def support_status(platform: str, kind: str) -> str:
    if platform == "arista_ceos":
        return PARSER_VALIDATED if kind in CEOS_PARSER_VALIDATED else FIXTURE_ONLY
    if platform == "ubuntu_frr":
        return FIXTURE_ONLY
    return NOT_IMPLEMENTED


def executable(platform: str, kind: str) -> bool:
    return platform in EXECUTABLE_PLATFORMS and support_status(platform, kind) == PARSER_VALIDATED


@dataclass
class Analysis:
    platform: str
    status: str = "READY"
    items: list[dict] = field(default_factory=list)
    blockers: list[dict] = field(default_factory=list)
    proposals: list[dict] = field(default_factory=list)
    warnings: list[dict] = field(default_factory=list)
    highlight: list[int] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {"schema_version": SCHEMA_VERSION, "platform": self.platform, "status": self.status, "items": self.items,
                "blockers": self.blockers, "proposals": self.proposals, "warnings": self.warnings, "highlight": self.highlight}


def _blocker(code: str, message: str, **details) -> dict:
    return {"code": code, "message": message, **details}


# --- selection resolution ------------------------------------------------------------------------------------------
def resolve_line_range(model: ConfigModel, start: int, end: int) -> tuple[list[str], list[int], list[dict]]:
    """-> (whole object ids, individually removable attribute line numbers, blockers)."""
    if start < 1 or end < start or end > model.tree.line_count:
        return [], [], [_blocker(OUT_OF_RANGE, f"Lines {start}-{end} are outside the snapshot (1-{model.tree.line_count}).")]
    selected = {n for n in range(start, end + 1) if model.tree.node(n) is not None}
    if not selected:
        return [], [], [_blocker(EMPTY_SELECTION, "The selected range contains no configuration.")]
    concrete = [o for o in model.objects.values() if o.node is not None and o.lines]
    full = {o.id for o in concrete if set(o.lines) <= selected}
    # keep only maximal objects (a fully selected parent implies its children)
    maximal = [oid for oid in sorted(full) if model.objects[oid].parent_id not in full]
    covered = {n for oid in full for n in model.objects[oid].lines}
    attributes, blockers = [], []
    for number in sorted(selected - covered):
        node = model.tree.node(number)
        if node.terminator:
            continue
        header_of = [o for o in concrete if o.node is node and o.id not in full]
        if header_of:
            obj = header_of[0]
            blockers.append(_blocker(PARTIAL_CONTEXT, f"Line {number} opens {obj.label} (lines {obj.lines[0]}-{obj.lines[-1]}) but the selection "
                                     "does not include the whole object. Extend the selection or use Smart removal.",
                                     line=number, object=obj.id, needed=[obj.lines[0], obj.lines[-1]]))
            continue
        attr = model.attributes.get(number)
        if attr is not None and attr.removable:
            attributes.append(number)
            continue
        reason = attr.reason if attr is not None else "UNMANAGED_CONFIGURATION"
        blockers.append(_blocker(NOT_REMOVABLE, f"Line {number} ({node.stripped}) cannot be removed on its own: {reason}.", line=number, reason=reason))
    return maximal, attributes, blockers


def _expand(model: ConfigModel, object_ids) -> list[str]:
    """Virtual named objects (a route-map, an FRR ACL) stand for all their concrete members."""
    result = []
    for oid in object_ids:
        obj = model.objects.get(oid)
        if obj is not None and obj.node is None and obj.members:
            result.extend(obj.members)
        else:
            result.append(oid)
    return list(dict.fromkeys(result))


# --- analysis ------------------------------------------------------------------------------------------------------
def analyze(text: str, platform: str, *, mode: str, line_range: tuple[int, int] | None = None, object_ids=(), accepted_proposals=()) -> Analysis:
    model = build_model(text, platform)
    analysis = Analysis(platform=platform)
    if platform not in ("arista_ceos", "ubuntu_frr"):
        analysis.blockers.append(_blocker(UNSUPPORTED_PLATFORM, f"Removal analysis is not implemented for {platform}."))
        analysis.status = "BLOCKED"
        return analysis

    if mode == "LINE_RANGE":
        start, end = line_range or (0, -1)
        targets, attributes, blockers = resolve_line_range(model, int(start), int(end))
        analysis.blockers.extend(blockers)
    else:
        targets, attributes = [], []
        for oid in object_ids:
            if oid not in model.objects:
                analysis.blockers.append(_blocker(UNKNOWN_OBJECT, f"{oid} is not present in this snapshot.", object=oid))
            else:
                targets.append(oid)
    targets = _expand(model, [*targets, *(p for p in accepted_proposals if p in model.objects)])
    if not targets and not attributes and not analysis.blockers:
        analysis.blockers.append(_blocker(EMPTY_SELECTION, "Nothing was selected for removal."))

    for oid in targets:
        obj = model.objects[oid]
        if obj.protected:
            analysis.blockers.append(_blocker(PROTECTED, f"{obj.label} is protected ({obj.reason or 'management plane'}) and cannot be removed here.",
                                              object=oid, lines=obj.lines))
        elif not obj.removable:
            analysis.blockers.append(_blocker(NOT_REMOVABLE, f"{obj.label} cannot be removed: {obj.reason}.", object=oid, reason=obj.reason, lines=obj.lines))

    # everything that disappears: the targets, their descendants, and the attribute lines
    closure = set(targets)
    for oid in targets:
        closure |= model.descendants_of(oid)
    gone_lines = {n for oid in closure for n in model.objects[oid].lines} | set(attributes)
    releasing = {f"attr:{n}" for n in attributes}

    def outside(ref: str) -> bool:
        return ref not in closure and ref not in releasing and not set(model.lines_of(ref)) <= gone_lines

    for oid in targets:
        obj = model.objects[oid]
        holders = [r for r in model.referrers(oid) if outside(r)]
        if obj.kind == "route_map_entry":
            name = oid.split(":", 1)[1].split("/", 1)[0]
            siblings = [m for m in model.objects[f"route_map:{name}"].members if m not in closure]
            if siblings:   # the route-map survives; policy semantics change but nothing dangles
                if [r for r in model.referrers(f"route_map:{name}") if outside(r)]:
                    analysis.warnings.append({"code": "ROUTE_MAP_POLICY_CHANGES", "message": f"route-map {name} stays referenced; removing "
                                              f"{obj.label} changes its policy.", "object": oid})
                continue
            holders = [r for r in model.referrers(f"route_map:{name}") if outside(r)]
        for member_kind in ("acl_entry", "prefix_list_entry"):
            if obj.kind == member_kind:
                name = oid.split(":", 1)[1].split("/", 1)[0]
                parent = f"{'acl' if member_kind == 'acl_entry' else 'prefix_list'}:{name}"
                siblings = [m for m in (model.objects[parent].members if parent in model.objects and model.objects[parent].node is None else
                                        [c for c in model.objects if model.objects[c].parent_id == parent]) if m not in closure]
                parent_holders = [r for r in model.referrers(parent) if outside(r)]
                if any(model.objects.get(r) is not None and model.objects[r].protected for r in parent_holders):
                    analysis.blockers.append(_blocker(PROTECTED, f"{obj.label} belongs to {parent.split(':', 1)[1]}, which the protected management "
                                                      "plane uses; its entries cannot be changed here.", object=oid, lines=obj.lines))
                    holders = []
                elif siblings:
                    holders = []
                    if parent_holders:
                        analysis.warnings.append({"code": "POLICY_CHANGES", "object": oid,
                                                  "message": f"{parent.split(':', 1)[1]} stays in use; removing {obj.label} changes what it matches."})
                else:
                    holders = parent_holders
        if holders:
            analysis.blockers.append(_blocker(
                REFERENCED, f"{obj.label} is still used by: " + "; ".join(model.label_of(r) for r in holders[:6])
                + (" ..." if len(holders) > 6 else "") + ". Remove or change those first (or include them in this removal).",
                object=oid, referrers=holders, referrer_lines=sorted({n for r in holders for n in model.lines_of(r)})))

    # proposals: named objects the removal leaves with no remaining user
    referenced = set()
    for oid in closure:
        referenced |= {r for r in model.objects[oid].references if r not in (ALL_VLANS, ANY_ACL)}
    for n, attr in model.attributes.items():
        if n in gone_lines:   # attribute lines inside removed objects, and individually selected ones
            referenced |= attr.references - {ALL_VLANS, ANY_ACL}
    for ref in sorted(referenced):
        candidate = model.objects.get(ref)
        if candidate is None or ref in closure or candidate.protected or not candidate.removable:
            continue
        if candidate.kind not in ("vlan", "acl", "route_map", "prefix_list", "bgp_peer_group", "pbr_policy", "pbr_class", "nat_pool"):
            continue
        if not [r for r in model.referrers(ref) if outside(r)]:
            analysis.proposals.append({"object": ref, "label": candidate.label, "kind": candidate.kind, "lines": candidate.lines,
                                       "message": f"{candidate.label} would be left unused by this removal. Include it only if you also want it removed."})

    analysis.items = _items(model, targets, attributes, platform)
    analysis.highlight = sorted(gone_lines)
    for item in analysis.items:
        if not executable(platform, item_support_kind(item)):
            analysis.warnings.append({"code": "NOT_EXECUTABLE", "object": item["id"],
                                      "message": f"{item['label']}: removal syntax is {item['support']} on {platform}; it can be previewed but not executed."})
    analysis.status = "BLOCKED" if analysis.blockers else "READY"
    return analysis


def item_support_kind(item: dict) -> str:
    return f"attribute:{item.get('attribute_kind', 'other')}" if item["kind"] == "attribute" else item["kind"]


def _items(model: ConfigModel, targets: list[str], attributes: list[int], platform: str) -> list[dict]:
    items = []
    for oid in targets:
        obj = model.objects[oid]
        items.append({
            "id": oid, "kind": obj.kind, "label": obj.label, "operation": obj.operation, "lines": obj.lines,
            "removal_lines": list(obj.removal_lines), "restore_lines": obj.restore_lines, "restorable": obj.restorable,
            "absent_paths": obj.absent_paths, "references": sorted(obj.references - {ALL_VLANS, ANY_ACL}),
            "support": support_status(platform, obj.kind),
        })
    for number in attributes:
        attr = model.attributes[number]
        node = model.tree.node(number)
        restore = [*(n.text for n in node.ancestors()), node.text]
        items.append({
            "id": f"attribute:{number}", "kind": "attribute", "label": f"line {number}: {node.stripped}", "operation": DEACTIVATE_DETACH,
            "lines": [number], "removal_lines": list(attr.removal_lines), "restore_lines": restore,
            "restorable": not any(m in node.text for m in ("<REDACTED", "********")), "absent_paths": [node.path()],
            "references": sorted(attr.references - {ALL_VLANS, ANY_ACL}), "support": support_status(platform, f"attribute:{attr.kind}"),
            "attribute_kind": attr.kind,
        })
    # order: an item that references another removed item goes first (detach before delete), then by line
    ids = {item["id"] for item in items}
    for item in items:
        # whatever still references this item (and is itself being removed) must be removed FIRST
        item["depends_on"] = sorted(r for r in ids if r != item["id"] and r in _referrer_ids(model, item["id"]))
    ordered, placed = [], set()
    pending = sorted(items, key=lambda i: (0 if i["operation"] == DEACTIVATE_DETACH else 1, i["lines"][0] if i["lines"] else 0))
    while pending:
        progress = False
        for item in list(pending):
            if set(item["depends_on"]) <= placed:
                ordered.append(item)
                placed.add(item["id"])
                pending.remove(item)
                progress = True
        if not progress:   # a reference cycle cannot be ordered safely; keep line order (the validator reports it)
            ordered.extend(pending)
            break
    return ordered


def _referrer_ids(model: ConfigModel, target: str) -> set[str]:
    refs = set(model.referrers(target))
    return refs | {f"attribute:{r.split(':', 1)[1]}" for r in refs if r.startswith("attr:")}


def content_hash(analysis_dict: dict) -> str:
    return hashlib.sha256(json.dumps(analysis_dict, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def object_catalogue(text: str, platform: str) -> list[dict]:
    """Every semantic object for the Smart-removal navigator (removable or not, with the reason)."""
    model = build_model(text, platform)
    rows = []
    for obj in sorted(model.objects.values(), key=lambda o: ((o.lines or [0])[0], o.id)):
        if obj.kind == "unmanaged":
            continue
        rows.append({"id": obj.id, "kind": obj.kind, "label": obj.label, "lines": obj.lines, "removable": obj.removable and not obj.protected,
                     "reason": obj.reason or ("PROTECTED" if obj.protected else ""), "parent": obj.parent_id or "",
                     "operation": obj.operation, "support": support_status(platform, obj.kind)})
    return rows


__all__ = ["Analysis", "analyze", "content_hash", "executable", "object_catalogue", "support_status", "REMOVE_DELETE"]
