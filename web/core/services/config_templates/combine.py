"""The Multilayer Switch template: a SEMANTIC combination of the Access Layer and Default Gateway Router templates.

Nothing here touches CLI.  Both inputs are template intents (name-keyed semantic objects with parameters); the result is
one intent expressing a device that both switches (access / trunk ports, VLAN SVIs, first-hop redundancy, DHCP relay) and
routes (routed uplinks, IGP, static routing).  Every collision is decided by an explicit rule and reported:

    DUPLICATE_MANAGEMENT        one management SVI / management port / hostname -- the device has one management plane
    DUPLICATE_INTERFACE         the same port name in both roles: the access role keeps the name (it owns the edge ports),
                                the gateway role's port moves to the next free port and every reference follows it
    OVERLAPPING_ADDRESSING      the same L3 interface addressed by both roles: the access role (the VLAN's gateway) wins
    LOOPBACK_ROUTER_ID          one loopback; router ids are tied to it through one shared parameter set
    ROUTING_PROCESS_COLLISION   the same protocol in both roles becomes ONE process (bindings / networks / neighbors united)
    DEFAULT_GATEWAY_ROLE        the same static destination via different next hops: the gateway role's route wins
    VLAN_WITHOUT_SVI / SVI_WITHOUT_PORT   VLAN / SVI relationship findings (reported, not silently "fixed")
    PARAMETER_COLLISION         same parameter name, different meaning: the gateway role's parameter is renamed ``gw_*``
"""

from __future__ import annotations

import re
from copy import deepcopy

from . import schema
from .normalize import LOOPBACK_NAMES, MANAGEMENT_SVI, _identities

# Parameters that deliberately mean the SAME thing in both roles (one device identity).
SHARED_PARAMETERS = re.compile(r"^(hostname|mgmt_ipv[46](_\d+)?|loopback_ipv[46](_\d+)?|[a-z]+_router_id)$")
_PORT_RE = re.compile(r"^(Ethernet)(\d+)$")
_INTERFACE_REFERENCE_KEYS = ("interface_name", "next_hop_interface", "outside_interface", "parent_name", "update_source_interface")


def _rename_parameters(value, mapping: dict):
    if isinstance(value, dict):
        return {k: (mapping.get(v, v) if k == schema.WHEN else _rename_parameters(v, mapping)) for k, v in value.items()}
    if isinstance(value, list):
        return [_rename_parameters(v, mapping) for v in value]
    if isinstance(value, str) and "{{" in value:
        return schema.PLACEHOLDER_RE.sub(lambda m: "{{ " + mapping.get(m.group(1), m.group(1)) + " }}", value)
    return value


def _rename_interface(value, old: str, new: str):
    if isinstance(value, dict):
        return {k: (new if k in _INTERFACE_REFERENCE_KEYS and v == old else _rename_interface(v, old, new)) for k, v in value.items()}
    if isinstance(value, list):
        return [_rename_interface(v, old, new) for v in value]
    return value


def _is_l3(row: dict) -> bool:
    return bool(row.get("addresses")) or row.get("kind") in ("SVI", "LOOPBACK")


def _union_rows(section: str, first: list, second: list) -> list:
    """Union of two keyed child lists by semantic identity (first wins on an identical identity)."""
    seen = set(_identities(section, first)) if section not in ("neighbors", "addresses", "fhrp", "entries") else set()
    out = deepcopy(first)
    for identity, row in zip(_identities(section, second), second):
        if section in ("neighbors", "addresses", "fhrp", "entries"):
            if row not in out:
                out.append(deepcopy(row))
        elif identity not in seen:
            out.append(deepcopy(row))
    return out


def combine(access: dict, gateway: dict) -> dict:
    """``access`` / ``gateway``: {"intent", "parameters"} of the two source template versions.
    -> {"intent", "parameters", "conflicts": [{"code", "subject", "resolution"}], "notes": [...]}"""
    conflicts: list[dict] = []
    a_intent, g_intent = deepcopy(access["intent"]), deepcopy(gateway["intent"])
    a_params, g_params = deepcopy(access["parameters"]), deepcopy(gateway["parameters"])

    def conflict(code, subject, resolution):
        conflicts.append({"code": code, "subject": subject, "resolution": resolution})

    # 1. duplicate interface identities: decide names BEFORE parameters, since parameter names follow interface names
    a_ports = {row["name"]: row for row in a_intent.get("interfaces", [])}
    used = set(a_ports) | {row["name"] for row in g_intent.get("interfaces", [])}
    renames: dict[str, str] = {}
    for row in g_intent.get("interfaces", []):
        name = row["name"]
        match = _PORT_RE.match(name)
        if name in a_ports and match and {k: v for k, v in row.items() if k != "description"} != {k: v for k, v in a_ports[name].items() if k != "description"}:
            number = 1
            while f"{match.group(1)}{number}" in used:
                number += 1
            new = f"{match.group(1)}{number}"
            used.add(new)
            renames[name] = new
            if row.get("access_vlan") == 200 and a_ports[name].get("access_vlan") != 200 and any(
                    p.get("access_vlan") == 200 for p in a_ports.values()):
                renames[name] = ""      # a second management access port: dropped below, not moved
                used.discard(new)
    param_moves: dict[str, str] = {}
    for old, new in renames.items():
        if not new:
            continue
        for name in list(g_params):
            if name.startswith(f"{old.lower()}_"):
                param_moves[name] = f"{new.lower()}_{name[len(old) + 1:]}"
    # 2. parameters: shared identity parameters stay; a colliding name with another meaning is renamed gw_*
    for name in list(g_params):
        target = param_moves.get(name, name)
        if target in a_params and not SHARED_PARAMETERS.match(target):
            param_moves[name] = f"gw_{target}"
            conflict("PARAMETER_COLLISION", target, f"The gateway role's parameter was renamed gw_{target}.")
    g_intent = _rename_parameters(g_intent, param_moves)
    g_params = {param_moves.get(name, name): spec for name, spec in g_params.items()}
    for old, new in renames.items():
        if new:
            g_intent = _rename_interface(g_intent, old, new)
            conflict("DUPLICATE_INTERFACE", old, f"Both roles define {old}; the access role keeps it and the gateway role's port moves to {new}.")

    # 3. interfaces
    interfaces = deepcopy(a_intent.get("interfaces", []))
    by_name = {row["name"]: row for row in interfaces}
    for row in g_intent.get("interfaces", []):
        name = renames.get(row["name"]) if row["name"] in renames else row["name"]
        if name == "":
            conflict("DUPLICATE_MANAGEMENT", row["name"], "A second management access port is not needed; the access role's management port is kept.")
            continue
        row = {**row, "name": name}
        existing = by_name.get(name)
        if existing is None:
            interfaces.append(row)
            by_name[name] = row
            continue
        if name == MANAGEMENT_SVI:
            conflict("DUPLICATE_MANAGEMENT", name, "One static management SVI is kept (shared mgmt_ipv4 / mgmt_ipv6 parameters).")
        elif name in LOOPBACK_NAMES:
            before = len(existing.get("addresses", []))
            existing["addresses"] = _union_rows("addresses", existing.get("addresses", []), row.get("addresses", []))
            conflict("LOOPBACK_ROUTER_ID", name, f"One loopback is kept ({len(existing['addresses']) - before} address famil(ies) added from the gateway role); "
                                                 "router ids reference it through the shared router-id parameters.")
        elif _is_l3(existing) and _is_l3(row) and existing.get("addresses") != row.get("addresses"):
            conflict("OVERLAPPING_ADDRESSING", name, "Both roles address this interface; the access role's addressing (the VLAN gateway) is kept.")
        for key in ("dhcp_relays", "fhrp", "acl_attachments"):
            if row.get(key):
                existing[key] = _union_rows(key, existing.get(key, []), row[key])

    # 4. routing processes: one process per protocol
    routing = deepcopy(a_intent.get("routing", []))
    for identity, row in zip(_identities("routing", g_intent.get("routing", [])), g_intent.get("routing", [])):
        existing = next((r for i, r in zip(_identities("routing", routing), routing) if i == identity), None)
        if existing is None:
            routing.append(deepcopy(row))
            continue
        differing = sorted(k for k in set(existing.get("fields", {})) | set(row.get("fields", {}))
                           if existing.get("fields", {}).get(k) != row.get("fields", {}).get(k))
        existing["fields"] = {**existing.get("fields", {}), **row.get("fields", {})}
        for key in ("bindings", "neighbors", "networks"):
            if existing.get(key) or row.get(key):
                existing[key] = _union_rows(key, existing.get(key, []), row.get(key, []))
        conflict("ROUTING_PROCESS_COLLISION", identity, "Both roles run this protocol; they are merged into ONE process"
                 + (f" (gateway-role values kept for: {', '.join(differing)})." if differing else " (process fields agree)."))

    # 5. static routes
    routes = deepcopy(g_intent.get("static_routes", []))
    g_keys = dict(zip(_identities("static_routes", routes), routes))
    for identity, row in zip(_identities("static_routes", a_intent.get("static_routes", [])), a_intent.get("static_routes", [])):
        if identity not in g_keys:
            routes.append(deepcopy(row))
        elif g_keys[identity] != row:
            conflict("DEFAULT_GATEWAY_ROLE", identity, "Both roles route this destination differently; the gateway role's route is kept.")

    intent = {"device": {"hostname": "{{ hostname }}"}, "interfaces": interfaces, "static_routes": routes, "routing": routing,
              "acls": _union_rows("acls", a_intent.get("acls", []), g_intent.get("acls", [])),
              "nat_rules": deepcopy(a_intent.get("nat_rules", [])) + [r for r in g_intent.get("nat_rules", []) if r not in a_intent.get("nat_rules", [])]}
    intent = {k: v for k, v in intent.items() if v not in ([], {})}

    # 6. VLAN / SVI relationships (reported, never silently repaired)
    literal = lambda v: v if isinstance(v, int) and not isinstance(v, bool) else None   # noqa: E731
    port_vlans = set()
    for row in interfaces:
        port_vlans |= {v for v in (literal(row.get("access_vlan")), literal(row.get("native_vlan"))) if v}
        if isinstance(row.get("trunk_allowed_vlans"), list):
            port_vlans |= {v for v in row["trunk_allowed_vlans"] if literal(v)}
    svi_vlans = {literal(row.get("vlan_id")) for row in interfaces if row.get("kind") == "SVI"} - {None}
    for vlan in sorted(port_vlans - svi_vlans):
        conflict("VLAN_WITHOUT_SVI", f"VLAN {vlan}", "Carried on a port but has no SVI: it stays a pure layer-2 VLAN on the multilayer switch.")
    for vlan in sorted(svi_vlans - port_vlans):
        conflict("SVI_WITHOUT_PORT", f"Vlan{vlan}", "SVI has no literal port membership in the template; assign a port or trunk it when cloning.")

    used_names = schema.placeholders(intent) | schema.when_flags(intent)
    parameters = {name: spec for name, spec in sorted({**g_params, **a_params}.items()) if name in used_names}
    return {"intent": intent, "parameters": parameters, "conflicts": conflicts}
