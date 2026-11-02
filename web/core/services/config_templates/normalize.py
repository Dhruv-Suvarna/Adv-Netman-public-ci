"""Normalization and parameterization of extracted intent.  Pure functions; the source device is never touched.

``clean``       removes what must not be reused: Containerlab runtime management plumbing, kernel/MAC-derived link-local
                addresses, secret-shaped values.  Every removal is recorded as an exclusion.
``generalize``  turns the intent of one or more SOURCE DEVICES of the same role into one template:

    * identity-class values (hostname, management SVI addresses, loopback, router ids, BGP AS, BGP peers, descriptions
      naming the device) always become parameters -- they must never be reused literally on another device;
    * any other value that DIFFERS between the source devices becomes a parameter; a value they share stays a literal
      baseline default (common role behaviour);
    * an object only SOME source devices have is kept, guarded by a boolean ``_when`` parameter, and reported as a
      difference -- role-specific behaviour is documented, not erased.

Each source device's own values are kept as a named ``parameter set``, so the template reproduces every source exactly.
"""

from __future__ import annotations

import hashlib
import ipaddress
import re
from copy import deepcopy

from . import schema, secret_scan

# Lab runtime plumbing that is assigned by Containerlab, not by intent (platform -> predicate on an interface row).
RUNTIME_MANAGEMENT = {
    "arista_ceos": lambda row: row.get("kind") == "MANAGEMENT" or str(row.get("name", "")).startswith("Management"),
    "ubuntu_frr": lambda row: row.get("name") == "eth0",
}
MANAGEMENT_SVI = "Vlan200"
LOOPBACK_NAMES = ("Loopback0", "lo")
# identity functions for the keyed lists of the intent: (row, ordinal-within-group) -> stable identity
_FAMILY = lambda row: str(row.get("family") or row.get("address_family") or "").lower()  # noqa: E731


def _slug(text) -> str:
    return re.sub(r"[^a-z0-9]+", "_", str(text).lower()).strip("_")


def _identities(section: str, rows: list) -> list[str]:
    counters: dict[str, int] = {}

    def ordinal(prefix):
        counters[prefix] = counters.get(prefix, 0) + 1
        return f"{prefix}_{counters[prefix]}"

    keys = []
    for row in rows:
        if section in ("interfaces", "acls"):
            keys.append(str(row.get("name")))
        elif section == "bindings":
            keys.append(str(row.get("interface_name")))
        elif section == "static_routes":
            keys.append(f"{_FAMILY(row)}_{row.get('destination')}")
        elif section == "routing":
            keys.append(ordinal(str(row.get("family"))).removesuffix("_1"))
        elif section == "networks":
            keys.append(str(row.get("cidr") or f"{row.get('prefix')}_area_{row.get('area')}"))
        elif section == "dhcp_relays":
            keys.append(f"{_FAMILY(row)}_{row.get('destination')}")
        elif section == "acl_attachments":
            keys.append(f"{_FAMILY(row)}_{row.get('name')}_{row.get('direction')}")
        elif section == "neighbors":
            keys.append(ordinal(f"peer_{_FAMILY(row) or 'ip'}"))
        elif section == "addresses":
            keys.append(ordinal(_FAMILY(row) or "ip"))
        else:                                   # fhrp, entries, nat_rules: positional
            keys.append(ordinal(section.rstrip("s")))
    return keys


KEYED_LISTS = frozenset({"interfaces", "acls", "bindings", "static_routes", "routing", "networks", "dhcp_relays", "acl_attachments",
                         "neighbors", "addresses", "fhrp", "entries", "nat_rules"})


# --- clean -------------------------------------------------------------------------------------------------------------
def clean(intent: dict, platform: str) -> tuple[dict, list[dict]]:
    """-> (intent without runtime plumbing / link-local / secret-shaped values, exclusions)."""
    intent = deepcopy(intent)
    exclusions: list[dict] = []
    is_runtime = RUNTIME_MANAGEMENT.get(platform, lambda row: False)
    runtime_networks, kept = [], []
    for row in intent.get("interfaces", []):
        if is_runtime(row):
            for address in row.get("addresses", []):
                try:
                    runtime_networks.append(ipaddress.ip_interface(address["cidr"]).network)
                except (KeyError, ValueError):
                    pass
            exclusions.append({"category": "RUNTIME_MANAGEMENT", "label": f"Interface {row.get('name')}",
                               "reason": "Containerlab-assigned out-of-band management interface; not reusable intent."})
            continue
        link_local = [a for a in row.get("addresses", []) if str(a.get("cidr", "")).lower().startswith("fe80:")]
        if link_local:
            row["addresses"] = [a for a in row["addresses"] if a not in link_local]
            exclusions.append({"category": "DEVICE_IDENTITY", "label": f"Link-local address on {row.get('name')}",
                               "reason": "Derived from the interface MAC address; never reused on another device."})
            if not row["addresses"]:
                row.pop("addresses")
        if row.get("kind") == "ROUTED_PHYSICAL" and row.get("access_vlan") and not row.get("addresses"):
            # A switched access port whose (platform-default) access mode is not shown in the running configuration.
            row["kind"] = "ACCESS"
            exclusions.append({"category": "NORMALIZED", "label": f"Interface {row.get('name')}",
                               "reason": "Access VLAN without layer-3 addressing: normalized to an ACCESS port (the platform omits its default switchport mode)."})
        kept.append(row)
    if "interfaces" in intent:
        intent["interfaces"] = kept
    routes = []
    for route in intent.get("static_routes", []):
        hop = route.get("next_hop_address")
        try:
            via_runtime = bool(hop) and any(ipaddress.ip_address(hop) in net for net in runtime_networks)
        except ValueError:
            via_runtime = False
        if via_runtime:
            exclusions.append({"category": "RUNTIME_MANAGEMENT", "label": f"Static route {route.get('destination')}",
                               "reason": "Next hop is on the Containerlab management network; not reusable intent."})
        else:
            routes.append(route)
    if "static_routes" in intent:
        intent["static_routes"] = routes
    intent, findings = secret_scan.redact(intent, "intent")
    exclusions.extend({"category": "SECRET_REDACTED", "label": f["path"], "pattern": f["pattern"],
                       "reason": "Secret-shaped value removed; credentials never enter a template."} for f in findings)
    return {k: v for k, v in intent.items() if v not in ([], {})}, exclusions


# --- generalize --------------------------------------------------------------------------------------------------------
class _Generalizer:
    def __init__(self, devices: list[str]):
        self.devices = devices
        self.parameters: dict[str, dict] = {}
        self.sets: dict[str, dict] = {d: {} for d in devices}
        self.differences: list[dict] = []

    def _name(self, path: tuple, forced: str = "") -> str:
        name = forced or _slug("_".join(p for p in path if p not in ("interfaces", "addresses", "fields", "routing", "device", "cidr")))
        if len(name) > 56:
            name = f"{name[:44]}_{hashlib.sha256(name.encode()).hexdigest()[:8]}"
        return name or "value"

    def parameter(self, path: tuple, key: str, values: dict, *, forced: str = "", kind: str = "", description: str = "",
                  required: bool = True, default=None) -> str:
        sample = next(iter(values.values()))
        name = self._name((*path, key), forced)
        spec = {"type": kind or schema.infer_type(key, sample), "description": description or f"{' / '.join(path)} {key}".strip(),
                "required": required}
        if default is not None:
            spec["default"] = default
        suffix = 1
        base = name
        while name in self.parameters and (self.parameters[name]["type"] != spec["type"] or any(
                self.sets[d].get(name, v) != v for d, v in values.items())):
            suffix += 1
            name = f"{base}_{suffix}"
        self.parameters[name] = spec
        for device, value in values.items():
            self.sets[device][name] = value
        return "{{ " + name + " }}"

    def _forced(self, path: tuple, key: str, values: dict):
        """Identity-class leaves: -> kwargs for ``parameter`` or None."""
        if path == ("device",) and key == "hostname":
            return {"forced": "hostname", "kind": "hostname", "description": "Device hostname"}
        if len(path) >= 4 and path[0] == "interfaces" and path[2] == "addresses" and key == "cidr":
            interface, slot = path[1], path[3]
            family = "ipv6" if slot.startswith("ipv6") else "ipv4"
            ordinal = slot.rsplit("_", 1)[-1]
            suffix = "" if ordinal == "1" else f"_{ordinal}"
            if interface == MANAGEMENT_SVI:
                return {"forced": f"mgmt_{family}{suffix}", "kind": f"{family}_interface",
                        "description": f"Static {family.upper()} management address on {MANAGEMENT_SVI} (VLAN 200 stays static)"}
            if interface in LOOPBACK_NAMES:
                return {"forced": f"loopback_{family}{suffix}", "kind": f"{family}_interface", "description": f"Loopback {family.upper()} address"}
        if path[:1] == ("routing",) and path[-1:] == ("fields",):
            if key == "router_id":
                return {"forced": f"{path[1]}_router_id", "kind": "ipv4_address", "description": f"{path[1].upper()} router ID"}
            if key == "local_asn":
                return {"forced": f"{path[1]}_asn", "kind": "asn", "description": "Local BGP autonomous system number"}
        if len(path) >= 4 and path[0] == "routing" and path[2] == "neighbors" and key in ("peer_address", "remote_asn"):
            return {"forced": f"{path[1]}_{path[3]}_{'address' if key == 'peer_address' else 'asn'}",
                    "description": f"BGP {path[3].replace('_', ' ')} {key.replace('_', ' ')}"}
        if key == "description":
            for device, value in values.items():
                if isinstance(value, str) and re.search(rf"(?<![A-Za-z0-9]){re.escape(device)}(?![A-Za-z0-9])", value):
                    return {"kind": "string", "required": False, "default": "", "description": f"Description of {' / '.join(path[1:]) or 'device'} (names the device)"}
        return None

    def node(self, nodes: dict, path: tuple):
        """``nodes``: {device: dict} for the devices that HAVE this object."""
        out: dict = {}
        keys: list[str] = []
        for node in nodes.values():
            keys.extend(k for k in node if k not in keys)
        for key in keys:
            present = {d: n[key] for d, n in nodes.items() if key in n}
            if key in KEYED_LISTS and all(isinstance(v, list) and all(isinstance(r, dict) for r in v) for v in present.values()):
                out[key] = self.keyed_list(key, {d: present.get(d, []) for d in nodes}, (*path, key) if key != "interfaces" else ("interfaces",))
            elif all(isinstance(v, dict) for v in present.values()):
                out[key] = self.node({d: present.get(d, {}) for d in nodes}, (*path, key))
            else:
                forced = self._forced(path, key, present) if len(present) == len(nodes) else None
                values = list(present.values())
                same = len(present) == len(nodes) and all(v == values[0] for v in values)
                if forced is not None:
                    out[key] = self.parameter(path, key, present, **forced)
                elif same:
                    out[key] = deepcopy(values[0])
                else:
                    filled = {d: present.get(d, [] if isinstance(values[0], list) else "") for d in nodes}
                    out[key] = self.parameter(path, key, filled, required=len(present) == len(nodes),
                                              default=None if len(present) == len(nodes) else ([] if isinstance(values[0], list) else ""))
                    self.differences.append({"path": "/".join((*path, key)), "kind": "VALUE_DIFFERS", "values": {d: filled[d] for d in sorted(filled)}})
        return out

    def keyed_list(self, section: str, lists: dict, path: tuple) -> list:
        keyed = {d: dict(zip(_identities(section, rows), rows)) for d, rows in lists.items()}
        order: list[str] = []
        for device in lists:
            order.extend(k for k in keyed[device] if k not in order)
        out = []
        for identity in order:
            owners = {d: keyed[d][identity] for d in lists if identity in keyed[d]}
            row = self.node(owners, (*path, identity))
            if len(owners) < len(lists):
                flag = self._name((*path, identity), f"enable_{self._name((*path, identity))}")
                self.parameters[flag] = {"type": "boolean", "required": False, "default": False,
                                         "description": f"Include {' / '.join((*path, identity))} (present only on {', '.join(sorted(owners))})"}
                for device in lists:
                    self.sets.setdefault(device, {})[flag] = device in owners
                row = {schema.WHEN: flag, **row}
                self.differences.append({"path": "/".join((*path, identity)), "kind": "ONLY_ON_SOME_SOURCES", "present_on": sorted(owners)})
            out.append(row)
        return out


def generalize(per_device: dict) -> dict:
    """{device: cleaned intent} -> {"intent", "parameters", "parameter_sets", "differences"} (deterministic for a given input order)."""
    devices = list(per_device)
    if not devices:
        raise ValueError("At least one source intent is required.")
    worker = _Generalizer(devices)
    intent = worker.node({d: per_device[d] for d in devices}, ())
    used = schema.placeholders(intent) | schema.when_flags(intent)
    parameters = {name: spec for name, spec in sorted(worker.parameters.items()) if name in used}
    sets = {d: {k: v for k, v in sorted(values.items()) if k in parameters} for d, values in worker.sets.items()}
    return {"intent": intent, "parameters": parameters, "parameter_sets": sets, "differences": worker.differences}
