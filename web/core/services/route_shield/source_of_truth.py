"""PERMANENT INTENT after a successful baseline migration: what the tracked sources must say so that the next
deploy or rebuild produces the IS-IS baseline and not the superseded static IPv6 routing.

Derived from the plan itself, never typed twice: the PERMANENT additions are what a tracked template gains, the lines a
PERMANENT removal restores are what it loses, and no TEMPORARY statement (shield, floating static, core cover) can
appear because nothing here reads one.  R3 and R4 have no entry: a cover is execution evidence, never intent.

Nothing here writes a tracked file.  ``intent_template`` returns text; the reviewed copies live in
``docs/evidence/v2-route-shield/intent/templates/`` and are promoted by a normal pull request after the migration
has SUCCEEDED (docs/V2_ISIS_LIVE_MIGRATION_RUNBOOK.md, section 7).
"""

from __future__ import annotations

from pathlib import Path

from django.conf import settings

from ..config_workbench.structure import config_paths
from . import migration
from .migration import ADD, PERMANENT, REMOVE, TEMPORARY

PRE_MIGRATION, POST_MIGRATION, MIXED = "PRE_MIGRATION", "POST_MIGRATION", "MIXED"
MARKER = "! Baseline IS-IS access routing (NMAS baseline migration; docs/V2_LOSSLESS_ROUTE_SHIELD.md)"
REVIEWED_COPIES = "docs/evidence/v2-route-shield/intent/templates"


def template_path(device: str) -> Path:
    return Path(settings.REPO_ROOT) / "templates" / f"{device}.cfg.j2"


def _blocks(lines) -> list[tuple[str, list[str]]]:
    found: list[tuple[str, list[str]]] = []
    for line in lines:
        if line.startswith(" ") and found:
            found[-1][1].append(line.strip())
        elif line.strip():
            found.append((line.strip(), []))
    return found


def _device_ops(definition, device: str):
    return [op for op in migration.forward_operations(definition) if op.device == device]


def intent_template(device: str, text: str, definition: migration.Definition = migration.PRODUCTION) -> str:
    """The tracked template of ``device`` as it must read once the migration has SUCCEEDED."""
    ops = _device_ops(definition, device)
    superseded = [block for op in ops if op.state == PERMANENT and op.action == REMOVE for block in _blocks(op.inverse)]
    leaves = {header for header, children in superseded if not children}
    children_of: dict[str, set[str]] = {}
    for header, children in superseded:
        if children:
            children_of.setdefault(header, set()).update(children)
    out: list[str] = []
    source = text.splitlines()
    index = 0
    while index < len(source):
        line = source[index]
        if line.startswith(" ") or not line.strip():
            out.append(line)
            index += 1
            continue
        end = index + 1
        while end < len(source) and source[end].startswith(" "):
            end += 1
        header, body = line.strip(), source[index + 1:end]
        if header in leaves and not body:
            pass                                                   # a superseded statement: gone
        elif header in children_of:
            kept = [child for child in body if child.strip() not in children_of[header]]
            if kept:
                out += [line, *kept]                               # an existing section loses only the superseded child
        else:
            out += [line, *body]
        index = end
    while out and out[-1].strip() in ("", "!"):
        out.pop()
    out += ["!", MARKER]
    for op in ops:
        if op.state == PERMANENT and op.action == ADD:
            out += [*op.lines, "!"]
    return "\n".join(out) + "\n"


def _state(text: str, device: str, definition) -> dict:
    ops, present = _device_ops(definition, device), config_paths(text)
    gained = [path for op in ops if op.state == PERMANENT and op.action == ADD for path in op.paths]
    lost = [path for op in ops if op.state == PERMANENT and op.action == REMOVE for path in op.paths]
    temporary = [path for op in ops if op.state == TEMPORARY and op.action == ADD for path in op.paths]
    has_new, has_old = [p for p in gained if p in present], [p for p in lost if p in present]
    state = POST_MIGRATION if len(has_new) == len(gained) and not has_old else PRE_MIGRATION if not has_new and len(has_old) == len(lost) else MIXED
    return {"state": state, "permanent_present": len(has_new), "permanent_expected": len(gained), "superseded_present": len(has_old),
            "superseded_expected": len(lost), "temporary_present": sorted(p for p in temporary if p in present)}


def tracked_state(definition: migration.Definition = migration.PRODUCTION) -> dict:
    """device -> what the tracked template says today.  Before the migration every template must be PRE_MIGRATION,
    after the source-of-truth update every one POST_MIGRATION; a temporary statement in either is a defect."""
    found = {}
    for device in definition.access_devices:
        try:
            found[device] = _state(template_path(device).read_text(encoding="utf-8"), device, definition)
        except OSError:
            found[device] = {"state": "UNREADABLE"}
    return found


def required_updates(definition: migration.Definition = migration.PRODUCTION) -> list[dict]:
    """The exact source updates that follow a SUCCEEDED migration, in order.  Each names its own verification."""
    rows = [{"target": f"templates/{device}.cfg.j2", "kind": "PERMANENT_INTENT",
             "update": f"replace with {REVIEWED_COPIES}/{device}.cfg.j2 (generated by source_of_truth.intent_template)",
             "verify": "nmas_isis_migration dry-run reports tracked_intent state POST_MIGRATION with no temporary statement"}
            for device in definition.access_devices]
    rows.append({"target": "NetBox IPAM", "kind": "PERMANENT_INTENT",
                 "update": "the prefix 2001:db8:110:3::/64 on VLAN 99 is already recorded; add the interface addresses S1 Vlan99 2001:db8:110:3::1/64 "
                           "and S2 Vlan99 2001:db8:110:3::2/64 to netbox/ipam.yml and NetBox in the same pull request as the templates "
                           "(they are deliberately absent until a device holds them)",
                 "verify": "nmas_isis_migration dry-run: netbox_vlan99_ipv6.state is POST_MIGRATION and conflicts is empty"})
    rows.append({"target": "startup-config of R1, R2, S1, S2", "kind": "PERMANENT_INTENT",
                 "update": "written and read back by the migration run itself (persistence stage)",
                 "verify": "run report: persistence.status VERIFIED; startup digest equals the recorded permanent baseline digest"})
    rows.append({"target": "NMAS Golden bundle", "kind": "PERMANENT_INTENT",
                 "update": "capture a new Golden from the migrated devices with the existing Golden workflow; the pre-migration Golden stays as history",
                 "verify": "the Golden's configuration digests equal permanent_intent.baseline_digests of the run"})
    rows.append({"target": "R3, R4 (kernel covers), shields and floating statics on R1, R2, S1, S2", "kind": "TEMPORARY_EXECUTION_EVIDENCE",
                 "update": "none, ever: recorded in the run report (temporary_state) and nowhere else",
                 "verify": "temporary_state.remaining is empty; R3/R4 boot configuration digest unchanged"})
    return rows
