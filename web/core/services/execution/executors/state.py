"""Pure state model shared by every executor: assessment and verification from the Phase-15 EVIDENCE GROUPS.

No I/O and no vendor syntax here.  The groups are exactly what ``health.live.read_device`` already produces for cEOS and
Linux (``interfaces``: {name: {admin, oper}}, ``addresses``: {interface: [cidr]}, ``routes``: [{prefix, type, next_hops,
interfaces}]), so "was it there before?" and "is it restored?" are answered with the SAME evidence the postcheck uses --
no second reader, no second parser.

Compensation is ADDITIVE-ONLY (see ``capability``): the inverse of what a Configlet adds is exact, and its restoration
provable, only when the Configlet added something that was absent.  When the captured state shows that applying would
overwrite or modify existing state, the assessment says ``restorable=False`` and Complete mode is refused before any
mutation.
"""

from __future__ import annotations

from ...health import live
from .base import APPLY, REFUSE, SKIP_SATISFIED, Assessment, ConfigletSpec

COMPENSATION_NOT_PROVABLE = "COMPENSATION_NOT_PROVABLE"
STATE_TYPES = frozenset({"interface", "address", "static_route"})


def _groups(evidence) -> tuple[dict | None, dict | None, list | None]:
    return evidence.facts("interfaces"), evidence.facts("addresses"), evidence.facts("routes")


def _address_family(cidr: str) -> int:
    return 6 if ":" in cidr else 4


def _is_secondary(spec: ConfigletSpec) -> bool:
    return any(line.strip().endswith(" secondary") for line in spec.lines)


def _route_matches(routes, expected: dict) -> bool:
    prefix = live.norm_prefix(expected.get("prefix"))
    hop = live.norm_ip(expected.get("next_hop")) if expected.get("next_hop") else None
    exit_interface = expected.get("exit_interface") or None
    for route in routes or []:
        if route.get("prefix") != prefix or str(route.get("type", "")).lower() != "static":
            continue
        if hop and hop not in route.get("next_hops", []):
            continue
        if exit_interface and exit_interface not in route.get("interfaces", []):
            continue
        return True
    return False


def assess(spec: ConfigletSpec, evidence, *, additive_overwrites_primary: bool) -> Assessment:
    """Decide APPLY / SKIP_SATISFIED / REFUSE and whether exact compensation is provable, from the CURRENT device state.

    ``additive_overwrites_primary``: True for platforms where adding a non-secondary IPv4 address REPLACES an existing
    primary (cEOS); such an apply is not additive and therefore not provably restorable.
    """
    interfaces, addresses, routes = _groups(evidence)
    kind = spec.object_type
    if kind not in STATE_TYPES:
        # Partial-only object types: applied, but no state is modelled, so nothing is provable and nothing is "satisfied".
        return Assessment(APPLY, False, {"modelled": False}, COMPENSATION_NOT_PROVABLE)
    if interfaces is None or addresses is None or (kind == "static_route" and routes is None):
        return Assessment(REFUSE, False, {}, "PREPARATION_FAILED")
    expected = spec.expected
    if kind == "interface":
        name = expected.get("interface")
        exists = name in interfaces
        return Assessment(APPLY, not exists, {"kind": "interface", "interface": name, "exists": exists},
                          COMPENSATION_NOT_PROVABLE if exists else "")
    if kind == "address":
        name, cidr = expected.get("interface"), live.norm_cidr(expected.get("address"))
        present = cidr in (addresses.get(name) or [])
        if present:
            return Assessment(SKIP_SATISFIED, True, {"kind": "address", "interface": name, "address": cidr, "present": True})
        existing = list(addresses.get(name) or [])
        overwrites = additive_overwrites_primary and cidr and _address_family(cidr) == 4 and not _is_secondary(spec) \
            and any(_address_family(a) == 4 for a in existing)
        return Assessment(APPLY, not overwrites, {"kind": "address", "interface": name, "address": cidr, "present": False,
                                                  "existing_addresses": existing[:10]},
                          COMPENSATION_NOT_PROVABLE if overwrites else "")
    present = _route_matches(routes, expected)
    facts = {"kind": "static_route", "prefix": live.norm_prefix(expected.get("prefix")), "next_hop": expected.get("next_hop") or "", "present": present}
    return Assessment(SKIP_SATISFIED if present else APPLY, True, facts)


def restored(spec: ConfigletSpec, evidence, previous_state: dict) -> bool | None:
    """True when the state captured BEFORE apply holds again; False when it does not; None when it cannot be read back."""
    interfaces, addresses, routes = _groups(evidence)
    if interfaces is None or addresses is None or (spec.object_type == "static_route" and routes is None):
        return None
    if spec.object_type == "interface":
        return (spec.expected.get("interface") in interfaces) == bool(previous_state.get("exists"))
    if spec.object_type == "address":
        cidr = live.norm_cidr(spec.expected.get("address"))
        return (cidr in (addresses.get(spec.expected.get("interface")) or [])) == bool(previous_state.get("present"))
    if spec.object_type == "static_route":
        return _route_matches(routes, spec.expected) == bool(previous_state.get("present"))
    return None
