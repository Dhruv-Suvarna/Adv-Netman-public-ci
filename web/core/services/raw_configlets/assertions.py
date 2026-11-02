"""The bounded catalogue of structured, server-owned postcheck ASSERTIONS for a Raw Configlet.

Arbitrary raw CLI has no automatically derivable expected state, and this module does NOT invent one.  An operator may DECLARE
what they expect to be true afterwards, but only from this closed catalogue; each kind maps onto an EXISTING Phase-15 evaluator
(interface state, address presence, route presence, OSPF adjacency, BGP adjacency) and each field is strictly validated.  There is
no free-form command, no ``show`` string, no path and no URL anywhere: the browser never chooses what is read from a device.

An assertion PASS confirms ONLY the declared facts -- never that the whole raw configuration took effect.  A Raw Configlet with no
assertion has exactly one requirement, ``RAW_CONFIG_APPLIED``, which the Phase-15 engine reports as NOT verified (a Partial (UAT)
run then ends ``UAT_SCOPE_APPLIED_UNVERIFIED``): missing evidence is never PASS.
"""

from __future__ import annotations

import ipaddress
import re

from . import codes

_IFACE_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_./-]{0,39}$")
_TOKEN_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=\S{1,120}$")
_TRUE, _FALSE = {"true", "yes", "up", "1"}, {"false", "no", "down", "0"}
RAW_REQUIREMENT = "RAW_CONFIG_APPLIED"


def _interface(value: str) -> str:
    if not _IFACE_RE.match(value):
        raise ValueError("interface name")
    return value


def _cidr(value: str) -> str:
    return str(ipaddress.ip_interface(value))


def _prefix(value: str) -> str:
    return str(ipaddress.ip_network(value, strict=False))


def _ip(value: str) -> str:
    return str(ipaddress.ip_address(value))


def _bool(value: str) -> bool:
    lowered = value.lower()
    if lowered in _TRUE:
        return True
    if lowered in _FALSE:
        return False
    raise ValueError("boolean")


def _ospf_version(value: str) -> str:
    upper = value.upper()
    if upper not in ("OSPFV2", "OSPFV3"):
        raise ValueError("ospf version")
    return upper


def _family(text: str) -> int:
    return 6 if ":" in str(text) else 4


# kind -> (Phase-14 requirement kind, {field: (validator, required)}, fixed facts added to ``expected``)
CATALOGUE = {
    "INTERFACE_STATE": ("INTERFACE_PRESENT", {"interface": (_interface, True), "admin_enabled": (_bool, False)}, {}),
    "ADDRESS_PRESENT": ("ADDRESS_PRESENT", {"interface": (_interface, True), "address": (_cidr, True)}, {}),
    "ROUTE_PRESENT": ("ROUTE_INTENDED", {"prefix": (_prefix, True), "next_hop": (_ip, False), "exit_interface": (_interface, False)}, {}),
    "OSPF_ADJACENCY": ("ROUTING_INTERFACE_ENABLED", {"interface": (_interface, True), "version": (_ospf_version, False)}, {"protocol": "ospf", "passive": False}),
    "BGP_ADJACENCY": ("BGP_PEER_INTENDED", {"peer": (_ip, True)}, {"shutdown": False}),
}


def parse_lines(text: str) -> tuple[list[dict], list[str]]:
    """``KIND key=value key=value`` per line -> (assertions, error messages).  Blank lines and ``#`` comments are ignored."""
    assertions, errors = [], []
    for number, raw in enumerate(str(text or "").splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        tokens = line.split()
        kind, pairs = tokens[0].upper(), tokens[1:]
        if kind not in CATALOGUE:
            errors.append(f"line {number}: unknown assertion kind (allowed: {', '.join(sorted(CATALOGUE))})")
            continue
        bad = [p for p in pairs if not _TOKEN_RE.match(p)]
        if bad:
            errors.append(f"line {number}: arguments must be key=value")
            continue
        assertions.append({"kind": kind, **dict(pair.split("=", 1) for pair in pairs)})
    if len(assertions) > codes.MAX_ASSERTIONS:
        errors.append(f"at most {codes.MAX_ASSERTIONS} assertions are allowed")
    return assertions, errors


def normalize(assertions) -> tuple[list[dict], list[str]]:
    """Validate and canonicalize assertions (deterministic order and field values).  Returns (normalized, errors)."""
    normalized, errors = [], []
    for index, item in enumerate(assertions or [], start=1):
        kind = str((item or {}).get("kind") or "").upper()
        if kind not in CATALOGUE:
            errors.append(f"assertion {index}: unknown kind")
            continue
        _requirement, fields, _fixed = CATALOGUE[kind]
        unknown = sorted(set(item) - {"kind"} - set(fields))
        if unknown:
            errors.append(f"assertion {index} ({kind}): unknown field(s) {', '.join(unknown)}")
            continue
        clean = {"kind": kind}
        try:
            for name, (validator, required) in fields.items():
                value = item.get(name)
                if value in (None, ""):
                    if required:
                        raise ValueError(f"{name} is required")
                    continue
                clean[name] = validator(value) if isinstance(value, str) else validator(str(value))
        except ValueError as exc:
            errors.append(f"assertion {index} ({kind}): invalid value ({exc})")
            continue
        normalized.append(clean)
    normalized.sort(key=lambda a: (a["kind"], sorted(a.items())))
    return normalized, errors


def descriptors(assertions, *, device: str, label: str, raw_id: str) -> list[dict]:
    """Phase-14 verification descriptors (schema 2) for the plan Configlet.

    With assertions: ONE descriptor per assertion (the declared, verifiable facts).  Without: the single, honestly unverifiable
    ``RAW_CONFIG_APPLIED`` marker.
    """
    if not assertions:
        return [{
            "schema_version": 2, "requirement": RAW_REQUIREMENT, "device": device,
            "subject": {"object_type": "raw_configlet", "object_id": raw_id, "label": label},
            "expected": {}, "status": "DEFERRED", "owner": "PHASE_15",
        }]
    rows = []
    for item in assertions:
        requirement, fields, fixed = CATALOGUE[item["kind"]]
        expected = {name: item[name] for name in fields if name in item}
        expected.update(fixed)
        if item["kind"] == "INTERFACE_STATE":
            expected["interface"], expected["admin_enabled"] = item["interface"], item.get("admin_enabled", True)
        if item["kind"] == "ADDRESS_PRESENT":
            expected["family"] = _family(item["address"])
        if item["kind"] == "ROUTE_PRESENT":
            expected["family"] = _family(item["prefix"])
            expected.setdefault("next_hop", "")
            expected.setdefault("exit_interface", "")
        if item["kind"] == "OSPF_ADJACENCY":
            expected["version"] = item.get("version", "OSPFV2")
        if item["kind"] == "BGP_ADJACENCY":
            expected["family"] = _family(item["peer"])
        rows.append({
            "schema_version": 2, "requirement": requirement, "device": device,
            "subject": {"object_type": "raw_configlet", "object_id": raw_id, "label": f"{label} [{item['kind']}]"},
            "expected": expected, "status": "DEFERRED", "owner": "PHASE_15", "declared_by": "OPERATOR_ASSERTION",
        })
    return rows
