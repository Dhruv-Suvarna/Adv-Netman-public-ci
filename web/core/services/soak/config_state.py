"""Read-only configuration digests of the devices a soak observes (V2 Phase 5C).

A soak proves that ONE exact configuration stayed healthy.  The postcheck engine proves the candidate's own requirements still hold; this
module proves the rest of the device's configuration did not change underneath it.  It composes sources that already exist and are already
read-only and allowlisted -- ``health.live.read_device_with_raw`` (the fixed ``show running-config`` / ``vtysh`` / ``nft`` / ``ip -j`` reads) and
the legacy-bootstrap sanitizer -- and adds no device client, command or credential of its own.

Only DIGESTS leave this module.  The configuration text is sanitized (secret-bearing lines redacted) before it is hashed, and it is never
stored, logged or returned.  A device that cannot be read completely is UNAVAILABLE -- never a match and never a drift.
"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime

from ..bundles.legacy_sanitize import SanitizeError, sanitize_config
from ..health import inventory, live
from ..health.results import iso

SCHEMA = 1
OK, UNAVAILABLE, MATCH, DRIFT = "OK", "UNAVAILABLE", "MATCH", "DRIFT"
# health platform -> ordered (section, allowlist key).  Linux adds the kernel link/address table: NMAS configures Linux interfaces and
# addresses with iproute2, which the FRR running configuration does not show.
SECTIONS = {
    "ceos": (("running-config", "running_config"),),
    "linux": (("frr-running-config", "frr_config"), ("nft-ruleset", "nft"), ("kernel-addresses", "addr")),
}
_MAY_BE_EMPTY = frozenset({"nft"})
_NFT_COUNTER = re.compile(r"packets \d+ bytes \d+")
# Session-level reader override.  None selects the real read-only session of each device; a test environment installs a factory here so
# that no unit test can ever open a device session by accident.
SESSION_FACTORY = None


def _normalize(key: str, text: str) -> str:
    """Remove what changes without a configuration change: nft packet counters, and the volatile fields of ``ip -j addr``."""
    if key == "nft":
        return _NFT_COUNTER.sub("packets N bytes N", text)
    if key == "addr":
        rows = []
        for link in json.loads(text or "[]"):
            addresses = sorted(f"{a.get('local')}/{a.get('prefixlen')}" for a in (link.get("addr_info") or []) if a.get("scope") == "global")
            rows.append([str(link.get("ifname")), addresses])
        return json.dumps(sorted(rows), sort_keys=True)
    return text


def read_device(name: str, *, session_factory=None, now: datetime | None = None) -> dict:
    """-> {"state": OK|UNAVAILABLE, "digest", "sections": {name: sha256}, "error", "read_at"} for one managed device.  Never raises."""
    device = inventory.get_managed_device(name)
    if device is None:
        return {"state": UNAVAILABLE, "digest": "", "sections": {}, "error": "NOT_MANAGED", "read_at": iso(now) if now else None}
    plan = SECTIONS.get(device["platform"])
    if not plan:
        return {"state": UNAVAILABLE, "digest": "", "sections": {}, "error": "PLATFORM_NOT_SUPPORTED", "read_at": iso(now) if now else None}
    keys = tuple(key for _section, key in plan)
    try:
        _evidence, raw, errors = live.read_device_with_raw(device, keys, session_factory=session_factory or SESSION_FACTORY, now=now)
    except Exception:  # noqa: BLE001 - an unreadable device is missing evidence, never an exception
        raw, errors = {}, {key: "READ_FAILED" for key in keys}
    sections, error = {}, ""
    for section, key in plan:
        if key in errors or key not in raw:
            error = error or f"{section}:{errors.get(key, 'NOT_READ')}"
            continue
        try:
            text = _normalize(key, sanitize_config(str(raw[key])).text if key != "addr" else str(raw[key]))
        except (SanitizeError, ValueError):
            error = error or f"{section}:UNPARSEABLE"
            continue
        if not text.strip() and key not in _MAY_BE_EMPTY:
            error = error or f"{section}:EMPTY"
            continue
        sections[section] = hashlib.sha256(text.encode()).hexdigest()
    if error:
        return {"state": UNAVAILABLE, "digest": "", "sections": {}, "error": error[:120], "read_at": iso(now) if now else None}
    digest = hashlib.sha256(json.dumps({"schema": SCHEMA, "device": name, "sections": sections}, sort_keys=True).encode()).hexdigest()
    return {"state": OK, "digest": digest, "sections": sections, "error": "", "read_at": iso(now) if now else None}


def read(devices, *, session_factory=None, now: datetime | None = None) -> dict:
    return {name: read_device(name, session_factory=session_factory, now=now) for name in sorted(devices)}


def compare(baseline: dict, current: dict) -> dict:
    """{device: {"state": MATCH|DRIFT|UNAVAILABLE, "baseline", "current", "changed_sections"}} for every device the baseline pinned.

    A device the baseline could not read is skipped (nothing to compare against); a device that cannot be read NOW is UNAVAILABLE.
    """
    result = {}
    for name, pinned in sorted((baseline or {}).items()):
        if not pinned.get("digest"):
            continue
        now = (current or {}).get(name) or {"state": UNAVAILABLE, "error": "NOT_READ"}
        if now.get("state") != OK:
            result[name] = {"state": UNAVAILABLE, "baseline": pinned["digest"], "current": "", "changed_sections": [], "error": now.get("error", "")}
            continue
        changed = sorted(s for s in set(pinned.get("sections") or {}) | set(now["sections"]) if (pinned.get("sections") or {}).get(s) != now["sections"].get(s))
        result[name] = {"state": MATCH if now["digest"] == pinned["digest"] else DRIFT, "baseline": pinned["digest"], "current": now["digest"],
                        "changed_sections": changed}
    return result
