"""SONiC config_db.json -> vendor-neutral parsed import records.

SONiC's authoritative configuration representation is config_db (the same
Redis-backed table/key/field store ``platform_drivers.SonicDriver`` renders),
never a `show running-config`-style CLI -- so this parser reads the identical
JSON shape the renderer produces (INTERFACE/LOOPBACK_INTERFACE/MGMT_INTERFACE,
STATIC_ROUTE, BGP_GLOBALS/BGP_NEIGHBOR/BGP_NEIGHBOR_AF, ACL_TABLE/ACL_RULE),
not a CLI parser forced onto a JSON-native platform.

No SONiC node is deployed in this lab, so this parser is exercised only
against fixture config_db JSON (either hand-built or produced by rendering a
candidate) -- see docs/PHASE_20_5_PLATFORM_CAPABILITY_AUDIT.md "Evidence
boundary". Any table/key this parser does not recognize is preserved as an
:class:`UnmanagedBlock`, never silently dropped.
"""

from __future__ import annotations

import json
import ipaddress

from .schema import ParsedAcl, ParsedConfig, ParsedInterface, ParsedRoutingInstance, ParsedStaticRoute, UnmanagedBlock

PARSER_VERSION = "sonic-configdb-1.0"

_KNOWN_TABLES = {
    "DEVICE_METADATA", "INTERFACE", "LOOPBACK_INTERFACE", "MGMT_INTERFACE",
    "VLAN", "VLAN_MEMBER", "VLAN_INTERFACE",
    "STATIC_ROUTE", "BGP_GLOBALS", "BGP_NEIGHBOR", "BGP_NEIGHBOR_AF",
    "ACL_TABLE", "ACL_RULE",
}
_INTERFACE_TABLE_KIND = {
    "INTERFACE": "ROUTED_PHYSICAL", "LOOPBACK_INTERFACE": "LOOPBACK", "MGMT_INTERFACE": "MANAGEMENT",
    "VLAN_INTERFACE": "SVI",
}


def _split_key(key: str) -> list[str]:
    return key.split("|")


def _preserve(result: ParsedConfig, label: str, value, classification: str = "RECOGNIZED_UNSUPPORTED") -> None:
    result.unmanaged_blocks.append(UnmanagedBlock(label, classification, [json.dumps(value, indent=2, sort_keys=True)]))


def _preserve_extra_fields(result: ParsedConfig, label: str, fields, supported: set[str]) -> None:
    if not isinstance(fields, dict):
        _preserve(result, f"{label} (entry is not an object)", fields, "UNKNOWN")
        return
    extra = {key: value for key, value in fields.items() if key not in supported}
    if extra:
        _preserve(result, f"{label} (unmodeled fields)", extra)


def _interface_entries(
    doc: dict, table: str, kind: str, interfaces: dict[str, ParsedInterface], result: ParsedConfig
) -> None:
    for key, fields in (doc.get(table) or {}).items():
        parts = _split_key(key)
        if len(parts) not in (1, 2) or not parts[0]:
            _preserve(result, f"{table} (unrecognized key {key!r})", {key: fields}, "UNKNOWN")
            continue
        base_name = parts[0]
        if kind == "SVI":
            vlan_text = base_name[4:] if base_name.lower().startswith("vlan") else ""
            if not vlan_text.isdigit():
                _preserve(result, f"{table} (unrecognized SVI key {key!r})", {key: fields}, "UNKNOWN")
                continue
            interface = interfaces.setdefault(base_name, ParsedInterface(
                name=base_name, kind="SVI", vlan_id=int(vlan_text),
            ))
        elif "." in base_name and kind == "ROUTED_PHYSICAL":
            parent_name, vlan = base_name.split(".", 1)
            interface = interfaces.setdefault(base_name, ParsedInterface(
                name=base_name, kind="SUBINTERFACE", parent_name=parent_name,
                encapsulation_vlan=int(vlan) if vlan.isdigit() else None,
            ))
        else:
            interface = interfaces.setdefault(base_name, ParsedInterface(name=base_name, kind=kind))
        _preserve_extra_fields(result, f"{table} {key}", fields, set())
        if len(parts) == 1:
            continue  # bare "<name>": {} -- the interface exists; no scalar fields to apply here
        cidr = parts[1]
        try:
            ipaddress.ip_interface(cidr)
        except ValueError:
            _preserve(result, f"{table} {key} (invalid address key)", {key: fields}, "UNKNOWN")
            continue
        family = "IPV6" if ":" in cidr else "IPV4"
        interface.addresses.append({"family": family, "cidr": cidr, "role": "PRIMARY"})


def _vlans(doc: dict, result: ParsedConfig, interfaces: dict[str, ParsedInterface]) -> None:
    vlan_ids: dict[str, int] = {}
    vlan_fields: dict[str, dict] = {}
    for name, fields in (doc.get("VLAN") or {}).items():
        if not isinstance(fields, dict):
            _preserve(result, f"VLAN {name} (entry is not an object)", fields, "UNKNOWN")
            continue
        text = name[4:] if name.lower().startswith("vlan") else ""
        try:
            vlan_id = int(fields.get("vlanid", text))
        except (TypeError, ValueError):
            _preserve(result, f"VLAN {name} (invalid vlanid)", fields, "UNKNOWN")
            continue
        if not 1 <= vlan_id <= 4094 or (text.isdigit() and int(text) != vlan_id):
            _preserve(result, f"VLAN {name} (inconsistent vlanid)", fields, "UNKNOWN")
            continue
        vlan_ids[name] = vlan_id
        vlan_fields[name] = fields
        _preserve_extra_fields(result, f"VLAN {name}", fields, {"vlanid"})

    memberships: dict[str, list[tuple[int, str, str, dict]]] = {}
    for key, fields in (doc.get("VLAN_MEMBER") or {}).items():
        parts = _split_key(key)
        if len(parts) != 2 or not isinstance(fields, dict):
            _preserve(result, f"VLAN_MEMBER (unrecognized key {key!r})", {key: fields}, "UNKNOWN")
            continue
        vlan_name, port = parts
        vlan_id = vlan_ids.get(vlan_name)
        if vlan_id is None:
            text = vlan_name[4:] if vlan_name.lower().startswith("vlan") else ""
            if not text.isdigit() or not 1 <= int(text) <= 4094:
                _preserve(result, f"VLAN_MEMBER {key} (unknown VLAN)", fields, "UNKNOWN")
                continue
            vlan_id = int(text)
        mode = fields.get("tagging_mode")
        if mode not in {"tagged", "untagged"}:
            _preserve(result, f"VLAN_MEMBER {key} (unsupported tagging_mode)", fields)
            continue
        _preserve_extra_fields(result, f"VLAN_MEMBER {key}", fields, {"tagging_mode"})
        memberships.setdefault(port, []).append((vlan_id, mode, key, fields))

    for port, rows in memberships.items():
        existing = interfaces.get(port)
        if existing is not None:
            _preserve(result, f"VLAN membership for routed interface {port} (L2/L3 conflict)",
                      {key: fields for _, _, key, fields in rows})
            continue
        untagged = sorted(vlan for vlan, mode, _, _ in rows if mode == "untagged")
        tagged = sorted(vlan for vlan, mode, _, _ in rows if mode == "tagged")
        if len(untagged) > 1:
            _preserve(result, f"VLAN membership for {port} (multiple untagged VLANs)",
                      {key: fields for _, _, key, fields in rows})
            continue
        if untagged and not tagged and len(rows) == 1:
            interfaces[port] = ParsedInterface(name=port, kind="ACCESS", access_vlan=untagged[0])
        else:
            allowed = sorted(set(tagged + untagged))
            interfaces[port] = ParsedInterface(
                name=port, kind="TRUNK", trunk_allowed_vlans=allowed,
                native_vlan=untagged[0] if untagged else None,
            )

    represented = set()
    for interface in interfaces.values():
        if interface.kind == "ACCESS" and interface.access_vlan:
            represented.add(interface.access_vlan)
        elif interface.kind == "TRUNK":
            represented.update(interface.trunk_allowed_vlans or [])
            if interface.native_vlan:
                represented.add(interface.native_vlan)
        elif interface.kind == "SVI" and interface.vlan_id:
            represented.add(interface.vlan_id)
    for name, vlan_id in vlan_ids.items():
        if vlan_id not in represented:
            _preserve(
                result,
                f"VLAN {name} (standalone VLAN has no canonical object)",
                {name: vlan_fields[name]},
            )


def _static_routes(doc: dict, result: ParsedConfig) -> None:
    for key, fields in (doc.get("STATIC_ROUTE") or {}).items():
        parts = _split_key(key)
        if len(parts) != 2 or parts[0] != "default":
            result.unmanaged_blocks.append(UnmanagedBlock(f"STATIC_ROUTE (unrecognized key {key!r})", "UNKNOWN", [json.dumps({key: fields})]))
            continue
        if not isinstance(fields, dict):
            _preserve(result, f"STATIC_ROUTE {key} (entry is not an object)", fields, "UNKNOWN")
            continue
        _vrf, prefix = parts
        try:
            ipaddress.ip_network(prefix, strict=False)
        except ValueError:
            _preserve(result, f"STATIC_ROUTE {key} (invalid prefix)", fields, "UNKNOWN")
            continue
        nexthop = fields.get("nexthop")
        try:
            ipaddress.ip_address(str(nexthop))
        except ValueError:
            result.unmanaged_blocks.append(UnmanagedBlock(f"STATIC_ROUTE {key} (no nexthop; ECMP/interface next-hop not modeled)", "RECOGNIZED_UNSUPPORTED", [json.dumps(fields)]))
            continue
        family = "IPV6" if ":" in prefix else "IPV4"
        route = ParsedStaticRoute(family=family, destination=prefix, next_hop_address=nexthop, lines=[json.dumps({key: fields})])
        if "distance" in fields:
            try:
                route.distance = int(fields["distance"])
            except (TypeError, ValueError):
                _preserve(result, f"STATIC_ROUTE {key} (invalid distance)", {"distance": fields["distance"]}, "UNKNOWN")
        _preserve_extra_fields(result, f"STATIC_ROUTE {key}", fields, {"nexthop", "distance"})
        result.static_routes.append(route)


def _bgp(doc: dict, result: ParsedConfig) -> None:
    globals_table = doc.get("BGP_GLOBALS") or {}
    if not globals_table:
        return
    if not isinstance(globals_table, dict):
        _preserve(result, "BGP_GLOBALS (table is not an object)", globals_table, "UNKNOWN")
        return
    for other_vrf, other_fields in globals_table.items():
        if other_vrf != "default":
            _preserve(result, f"BGP_GLOBALS {other_vrf!r} (non-default VRF is not modeled)", other_fields)
    gfields = globals_table.get("default")
    if not isinstance(gfields, dict):
        _preserve(result, "BGP_GLOBALS default (missing or invalid entry)", gfields, "UNKNOWN")
        return
    try:
        local_asn = int(gfields.get("local_asn"))
    except (TypeError, ValueError):
        result.unmanaged_blocks.append(UnmanagedBlock("BGP_GLOBALS (missing/invalid local_asn)", "UNKNOWN", [json.dumps(gfields)]))
        return
    _preserve_extra_fields(result, "BGP_GLOBALS default", gfields, {"local_asn", "router_id"})
    fields = {"local_asn": local_asn, "router_id": gfields.get("router_id") or ""}
    neighbors = []
    af_by_neighbor: dict[str, set[str]] = {}
    for key, afields in (doc.get("BGP_NEIGHBOR_AF") or {}).items():
        parts = _split_key(key)
        if not isinstance(afields, dict) or len(parts) != 3 or parts[0] != "default" or parts[2] not in {"ipv4_unicast", "ipv6_unicast"}:
            _preserve(result, f"BGP_NEIGHBOR_AF (unrecognized key {key!r})", {key: afields}, "UNKNOWN")
            continue
        _preserve_extra_fields(result, f"BGP_NEIGHBOR_AF {key}", afields, {"admin_status"})
        if afields.get("admin_status") in ("true", True):
            af_by_neighbor.setdefault(parts[1], set()).add(parts[2])
        else:
            _preserve(result, f"BGP_NEIGHBOR_AF {key} (disabled AF is not represented canonically)", afields)
    for key, nfields in (doc.get("BGP_NEIGHBOR") or {}).items():
        parts = _split_key(key)
        if len(parts) != 2 or parts[0] != "default" or not isinstance(nfields, dict):
            _preserve(result, f"BGP_NEIGHBOR (unrecognized key {key!r})", {key: nfields}, "UNKNOWN")
            continue
        peer = parts[1]
        try:
            remote_asn = int(nfields.get("asn"))
        except (TypeError, ValueError):
            result.unmanaged_blocks.append(UnmanagedBlock(f"BGP_NEIGHBOR {key} (missing/invalid asn)", "UNKNOWN", [json.dumps(nfields)]))
            continue
        _preserve_extra_fields(result, f"BGP_NEIGHBOR {key}", nfields, {"asn", "name"})
        activate = af_by_neighbor.get(peer, set())
        neighbors.append({
            "peer_address": peer, "remote_asn": remote_asn, "description": nfields.get("name") or "",
            "activate_ipv4": "ipv4_unicast" in activate, "activate_ipv6": "ipv6_unicast" in activate,
            "update_source_interface": "", "ebgp_multihop": None, "next_hop_self": False,
            "route_reflector_client": False, "shutdown": False,
        })
    known_peers = {neighbor["peer_address"] for neighbor in neighbors}
    for peer, families in af_by_neighbor.items():
        if peer not in known_peers:
            _preserve(
                result,
                f"BGP_NEIGHBOR_AF for {peer} (neighbor entry is missing)",
                sorted(families),
            )
    result.routing_instances.append(ParsedRoutingInstance(family="bgp", fields=fields, neighbors=neighbors, networks=[]))


def _acl_match_back(value) -> tuple[str, str]:
    if value is None:
        return "ANY", ""
    text = str(value)
    if text.endswith("/32") or text.endswith("/128"):
        return "HOST", text.rsplit("/", 1)[0]
    return "PREFIX", text


def _acls(doc: dict, result: ParsedConfig, interfaces: dict[str, ParsedInterface]) -> None:
    ports_by_acl: dict[str, list[str]] = {}
    stage_by_acl: dict[str, str] = {}
    for name, tfields in (doc.get("ACL_TABLE") or {}).items():
        if not isinstance(tfields, dict):
            _preserve(result, f"ACL_TABLE {name} (entry is not an object)", tfields, "UNKNOWN")
            continue
        table_type = tfields.get("type", "L3")
        if table_type not in {"L3", "L3V6"} or tfields.get("stage", "ingress") not in {"ingress", "egress"} or not isinstance(tfields.get("ports", []), list):
            _preserve(result, f"ACL_TABLE {name} (unsupported table shape)", tfields)
            continue
        if tfields.get("policy_desc") not in (None, name):
            _preserve(result, f"ACL_TABLE {name} (noncanonical policy_desc)", {"policy_desc": tfields["policy_desc"]})
        _preserve_extra_fields(result, f"ACL_TABLE {name}", tfields, {"type", "policy_desc", "ports", "stage"})
        family = "IPV4" if table_type == "L3" else "IPV6"
        acl = ParsedAcl(name=name, family=family, acl_type="EXTENDED")
        result.acls.append(acl)
        ports_by_acl[name] = list(tfields.get("ports") or [])
        stage_by_acl[name] = tfields.get("stage", "ingress")
    acls_by_name = {acl.name: acl for acl in result.acls}
    for key, rfields in (doc.get("ACL_RULE") or {}).items():
        parts = _split_key(key)
        if len(parts) != 2 or parts[0] not in acls_by_name or not isinstance(rfields, dict):
            result.unmanaged_blocks.append(UnmanagedBlock(f"ACL_RULE (unrecognized key {key!r})", "UNKNOWN", [json.dumps(rfields)]))
            continue
        acl = acls_by_name[parts[0]]
        try:
            sequence = int(str(rfields.get("PRIORITY", "0")))
        except (TypeError, ValueError):
            _preserve(result, f"ACL_RULE {key} (invalid priority)", rfields, "UNKNOWN")
            continue
        if rfields.get("PACKET_ACTION") not in {"FORWARD", "DROP"}:
            _preserve(result, f"ACL_RULE {key} (unsupported packet action)", rfields)
            continue
        _preserve_extra_fields(
            result, f"ACL_RULE {key}", rfields,
            {"PRIORITY", "PACKET_ACTION", "SRC_IP", "SRC_IPV6", "DST_IP", "DST_IPV6", "IP_PROTOCOL"},
        )
        action = "PERMIT" if rfields.get("PACKET_ACTION") == "FORWARD" else "DENY"
        source_type, source_value = _acl_match_back(rfields.get("SRC_IP") or rfields.get("SRC_IPV6"))
        destination_type, destination_value = _acl_match_back(rfields.get("DST_IP") or rfields.get("DST_IPV6"))
        acl.entries.append({
            "sequence": sequence, "action": action, "protocol": rfields.get("IP_PROTOCOL", "IP"),
            "source_type": source_type, "source_value": source_value,
            "destination_type": destination_type, "destination_value": destination_value, "logging": False,
        })
    for acl_name, ports in ports_by_acl.items():
        direction = "OUT" if stage_by_acl.get(acl_name) == "egress" else "IN"
        for port in ports:
            interface = interfaces.get(port)
            if interface is not None:
                interface.acl_attachments.append({"family": acls_by_name[acl_name].family, "name": acl_name, "direction": direction})
            else:
                _preserve(
                    result,
                    f"ACL_TABLE {acl_name} attachment (interface {port!r} is missing)",
                    {"port": port, "stage": stage_by_acl.get(acl_name, "ingress")},
                )


def parse(source) -> ParsedConfig:
    """``source`` is either a config_db JSON string or an already-decoded dict."""
    doc = json.loads(source) if isinstance(source, str) else source
    result = ParsedConfig(parser_version=PARSER_VERSION)
    metadata = doc.get("DEVICE_METADATA") or {}
    localhost = metadata.get("localhost") if isinstance(metadata, dict) else None
    if isinstance(localhost, dict):
        result.hostname = localhost.get("hostname", "")
        _preserve_extra_fields(result, "DEVICE_METADATA localhost", localhost, {"hostname"})
        for key, value in metadata.items():
            if key != "localhost":
                _preserve(result, f"DEVICE_METADATA {key!r} (unmodeled entry)", value)
    elif metadata:
        _preserve(result, "DEVICE_METADATA (invalid table shape)", metadata, "UNKNOWN")

    interfaces: dict[str, ParsedInterface] = {}
    for table, kind in _INTERFACE_TABLE_KIND.items():
        _interface_entries(doc, table, kind, interfaces, result)
    _vlans(doc, result, interfaces)
    result.interfaces = list(interfaces.values())

    _static_routes(doc, result)
    _bgp(doc, result)
    _acls(doc, result, interfaces)

    for table, entries in doc.items():
        if table in _KNOWN_TABLES:
            continue
        result.unmanaged_blocks.append(UnmanagedBlock(
            f"Unrecognized config_db table {table!r} (no structured parser for it yet)",
            "UNKNOWN", [json.dumps({table: entries}, indent=2)],
        ))
    return result
