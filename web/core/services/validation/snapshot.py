"""Deterministic accepted-intent snapshot of an entire Change + its SHA-256.

The snapshot is built from the SAME hydrated accepted state the one Python
candidate renderer uses (candidate_renderer.hydrate_state(use_draft=False)),
never from browser drafts.  It contains no secret values: keys that look
secret-shaped (and are not ``*_ref`` references) are replaced by a redaction
marker, so a manual database edit cannot leak into a report.

Canonicalization rules
    * devices ordered by device_name, stable object IDs kept (they are the
      reference identity everywhere);
    * dict key order is irrelevant (hashing uses sorted-key JSON);
    * ``sequence`` is display ordering and is dropped, EXCEPT where order is
      semantic (ACL entries, PBR sequences);
    * VLAN sets are sorted (set semantics), other lists keep their order.
"""

from __future__ import annotations

from .. import candidate_renderer
from ..raw_configlets import codes as raw_codes, store as raw_store
from .findings import ENGINE_VERSION, _secret_key, sha256_of

SNAPSHOT_SCHEMA_VERSION = 1
_ORDER_SEMANTIC_PARENTS = {"entries", "sequences"}
_SET_LISTS = {"trunk_allowed_vlans"}
REDACTED = "[REDACTED]"


def _canonical(value, *, parent_key: str = "", row_keeps_sequence: bool = False):
    if isinstance(value, dict):
        # Children of an order-semantic collection are rows that keep `sequence`.
        children_are_ordered_rows = parent_key in _ORDER_SEMANTIC_PARENTS
        out = {}
        for key, item in value.items():
            if _secret_key(key):
                out[str(key)] = REDACTED
                continue
            if key == "sequence" and not row_keeps_sequence:
                continue
            out[str(key)] = _canonical(
                item, parent_key=str(key), row_keeps_sequence=children_are_ordered_rows
            )
        return out
    if isinstance(value, (list, tuple)):
        items = [_canonical(item, parent_key=parent_key) for item in value]
        if parent_key in _SET_LISTS:
            try:
                return sorted(items)
            except TypeError:
                return items
        return items
    return value


def _device_entry(intent) -> dict:
    revision = intent.latest_revision()
    entry = {
        "device_name": intent.device_name,
        "target_type": intent.target_type,
        "platform": intent.platform,
        "image_reference": intent.image_reference or "",
        "has_revision": revision is not None,
        "identity": {"hostname": intent.device_name, "description": ""},
        "interfaces": {},
        "routing": {},
        "fhrp": {},
        "nat": {},
        "services": {},
        "security": {},
        "policy": {},
    }
    if revision is None:
        return entry
    state = candidate_renderer.hydrate_state(intent, revision, use_draft=False)
    values = state["field_values"]
    entry["identity"] = {
        "hostname": values.get("device.hostname") or intent.device_name,
        "description": values.get("device.description") or "",
    }
    entry["interfaces"] = {row["id"]: _canonical(row) for row in state["interfaces"] if row.get("id")}
    entry["routing"] = _canonical(state["routing"])
    phase12 = state["phase12"]
    for key in ("fhrp", "nat", "services", "security", "policy"):
        entry[key] = _canonical(phase12.get(key) or {})
    # V2 Phase 4: management VRF intent -- the key exists ONLY when the revision holds an object (historical hashes unchanged)
    if phase12.get("management"):
        entry["management"] = _canonical(phase12["management"])
    return entry


def build_change_snapshot(change) -> dict:
    """Return the deterministic accepted snapshot (the hashed content)."""
    intents = list(change.device_intents.order_by("device_name"))
    snapshot = {
        "schema_version": SNAPSHOT_SCHEMA_VERSION,
        "targets": sorted(change.targets.values_list("device_name", flat=True)),
        "devices": [_device_entry(intent) for intent in intents],
    }
    # Phase 18: enabled Raw Configlets (latest revision + verification status) are part of the EFFECTIVE Change input.  The key
    # exists ONLY when there is at least one, so the canonical hash of every Change without a Raw Configlet is unchanged
    # (historical validation runs and plans keep their exact input hash) while any raw add / edit / disable / re-verify changes it.
    raw_items = raw_store.snapshot_entries(change)
    if raw_items:
        snapshot["raw_configlets"] = {"schema_version": raw_codes.SCHEMA_VERSION, "items": raw_items}
    # Remove Configuration: same "key only when present" rule, so every other Change keeps its exact historical input hash.  The
    # sanitized snapshot TEXT is part of the input: the validator re-derives the removal from it (pure, no DB).
    removals = [
        {"device": r.device_name, "platform": r.platform, "mode": r.mode, "selection": r.selection,
         "snapshot_id": str(r.snapshot.snapshot_id), "snapshot_digest": r.snapshot.digest, "text": r.snapshot.text}
        for r in change.config_removals.select_related("snapshot").order_by("device_name")
    ]
    if removals:
        snapshot["config_removals"] = {"schema_version": 1, "items": removals}
    contribution = (change.metadata or {}).get("contribution_baseline")
    if contribution:
        snapshot["contribution_baseline"] = contribution
    return snapshot


def hash_snapshot(snapshot: dict) -> str:
    """SHA-256 of the canonical accepted snapshot (the primary intent fingerprint)."""
    return sha256_of(snapshot)


def revision_map(change) -> dict:
    """Provenance only (not hashed): which revision of each intent was read."""
    result = {}
    for intent in change.device_intents.order_by("device_name"):
        revision = intent.latest_revision()
        result[intent.device_name] = (
            {"revision": revision.revision, "schema_version": revision.schema_version} if revision else None
        )
    return result


def snapshot_stats(snapshot: dict) -> dict:
    objects = 0
    for device in snapshot["devices"]:
        objects += len(device["interfaces"])
        objects += sum(len(iface.get("addresses") or {}) for iface in device["interfaces"].values())
        routing = device["routing"] or {}
        for family, group in routing.items():
            objects += len(group or {})
        objects += len((device["fhrp"] or {}).get("instances") or {})
        nat = device["nat"] or {}
        objects += len(nat.get("pools") or {}) + len(nat.get("rules") or {})
        dhcp = (device["services"] or {}).get("dhcp") or {}
        objects += len(dhcp.get("relays") or {}) + len(dhcp.get("clients") or {})
        security = device["security"] or {}
        objects += len(security.get("acls") or {}) + len(security.get("attachments") or {})
        pbr = (device["policy"] or {}).get("pbr") or {}
        objects += len(pbr.get("policies") or {}) + len(pbr.get("attachments") or {})
        management = device.get("management") or {}
        objects += sum(len(management.get(key) or {}) for key in ("vrfs", "bindings", "routes", "services"))
    objects += len((snapshot.get("raw_configlets") or {}).get("items") or [])
    return {"devices": len(snapshot["devices"]), "objects": objects, "engine_version": ENGINE_VERSION}
