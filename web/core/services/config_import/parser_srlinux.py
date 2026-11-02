"""Nokia SR Linix structured configuration (`info ... json` shape) -> vendor-
neutral parsed import records.

SR Linix is model-driven, not CLI-driven, so this parser reads the same kind
of nested JSON tree the SR Linix CLI's own `info from state json` / `info
json` output uses (interface/subinterface/ipv4/ipv6, network-instance
static-routes/next-hop-groups/protocols, acl) -- the JSON-tree counterpart of
the exact `set` paths ``platform_drivers.SrLinuxDriver`` renders, verified
against Nokia's SR Linix Configuration Basics Guide and the srl_nokia-acl
data model. This is NOT a CLI parser forced onto a model-driven platform.

Three source forms reach the same tree through ``srlinux_model``: the CLI's
``info | as json`` document, a gNMI JSON_IETF configuration read (module
qualifiers removed), and rendered ``set`` statements (a candidate, or
``info flat``).  The gNMI form is verified against an isolated SR Linux
24.10.7 node; no SR Linix node exists in the approved Labs 2/3 baseline.
Any subtree this parser does not recognize is preserved as an
:class:`UnmanagedBlock`, never silently dropped.
"""

from __future__ import annotations

import json

from .. import srlinux_model
from .schema import ParsedAcl, ParsedConfig, ParsedInterface, ParsedRoutingInstance, ParsedStaticRoute, UnmanagedBlock

PARSER_VERSION = "srlinux-json-1.0"

_KNOWN_TOP_KEYS = {"system", "interface", "network-instance", "acl"}


def _preserve(result: ParsedConfig, label: str, value, classification: str = "RECOGNIZED_UNSUPPORTED") -> None:
    result.unmanaged_blocks.append(UnmanagedBlock(label, classification, [json.dumps(value, indent=2, sort_keys=True)]))


def _extra(result: ParsedConfig, label: str, value, allowed: set[str]) -> None:
    if not isinstance(value, dict):
        _preserve(result, f"{label} (entry is not an object)", value, "UNKNOWN")
        return
    extra = {key: item for key, item in value.items() if key not in allowed}
    if extra:
        _preserve(result, f"{label} (unmodeled fields)", extra)


def _mgmt_interface_names(network_instances: list[dict]) -> set[str]:
    names: set[str] = set()
    for ni in network_instances:
        if ni.get("name") != "mgmt":
            continue
        for entry in ni.get("interface") or []:
            names.add((entry.get("name") or "").split(".", 1)[0])
    return names


def _subinterface_addresses(sub: dict) -> list[dict]:
    addresses = []
    for family, leaf in (("IPV4", "ipv4"), ("IPV6", "ipv6")):
        for addr in ((sub.get(leaf) or {}).get("address") or []):
            prefix = addr.get("ip-prefix")
            if prefix:
                addresses.append({"family": family, "cidr": prefix, "role": "PRIMARY"})
    return addresses


def _subinterface_acl_attachments(sub: dict) -> list[dict]:
    attachments = []
    acl_cfg = sub.get("acl") or {}
    for direction_key, direction in (("input", "IN"), ("output", "OUT")):
        for filter_kind, family in (("ipv4-filter", "IPV4"), ("ipv6-filter", "IPV6")):
            acl_name = (acl_cfg.get(direction_key) or {}).get(filter_kind)
            if acl_name:
                attachments.append({"family": family, "name": acl_name, "direction": direction})
    return attachments


def _subinterface_dhcp_relays(sub: dict, result: ParsedConfig, name: str, index) -> list[dict]:
    relays: list[dict] = []
    for family, leaf in (("IPV4", "ipv4"), ("IPV6", "ipv6")):
        family_cfg = sub.get(leaf) or {}
        relay = family_cfg.get("dhcp-relay") or {} if isinstance(family_cfg, dict) else {}
        if not relay:
            continue
        _extra(result, f"interface {name}.{index} {leaf} dhcp-relay", relay, {"server"})
        servers = relay.get("server") if isinstance(relay, dict) else None
        if not isinstance(servers, list):
            _preserve(result, f"interface {name}.{index} {leaf} dhcp-relay (invalid server list)", relay, "UNKNOWN")
            continue
        for destination in servers:
            if isinstance(destination, str) and destination:
                relays.append({"family": family, "destination": destination})
            else:
                _preserve(result, f"interface {name}.{index} {leaf} dhcp-relay (invalid server)", destination, "UNKNOWN")
    return relays


def _parse_interfaces(doc: dict, mgmt_names: set[str], result: ParsedConfig) -> dict[str, ParsedInterface]:
    """Every SR Linix physical/loopback/mgmt interface exists as its own
    object (with its own admin-state/description/mtu) independently of
    whether it carries a plain index-0 subinterface -- e.g. a port with only
    a single tagged subinterface still has a real, addressable parent. The
    base object is therefore always created here, never only synthesized
    when a bare index-0 subinterface happens to be present."""
    interfaces: dict[str, ParsedInterface] = {}
    for name, ifields in (doc.get("interface") or {}).items():
        if not isinstance(ifields, dict):
            _preserve(result, f"interface {name} (invalid object)", ifields, "UNKNOWN")
            continue
        _extra(result, f"interface {name}", ifields, {"admin-state", "description", "mtu", "vlan-tagging", "subinterface"})
        base_kind = "MANAGEMENT" if name in mgmt_names else ("LOOPBACK" if name.startswith("lo") else "ROUTED_PHYSICAL")
        base = ParsedInterface(
            name=name, kind=base_kind,
            description=ifields.get("description", ""),
            mtu=ifields.get("mtu"),
            admin_state="ENABLED" if ifields.get("admin-state", "enable") == "enable" else "DISABLED",
        )
        interfaces[name] = base
        for sub in ifields.get("subinterface") or []:
            if not isinstance(sub, dict) or sub.get("type", "routed") != "routed":
                _preserve(result, f"interface {name} subinterface (unsupported shape)", sub)
                continue
            _extra(result, f"interface {name} subinterface {sub.get('index', 0)}", sub,
                   {"index", "type", "admin-state", "description", "ip-mtu", "vlan", "ipv4", "ipv6", "acl"})
            index = sub.get("index", 0)
            vlan_cfg = ((sub.get("vlan") or {}).get("encap") or {}).get("single-tagged") or {}
            vlan_id = vlan_cfg.get("vlan-id")
            addresses = _subinterface_addresses(sub)
            attachments = _subinterface_acl_attachments(sub)
            relays = _subinterface_dhcp_relays(sub, result, name, index)
            vlan = sub.get("vlan") or {}
            encap = vlan.get("encap") or {} if isinstance(vlan, dict) else {}
            tagged = encap.get("single-tagged") or {} if isinstance(encap, dict) else {}
            _extra(result, f"interface {name}.{index} vlan", vlan, {"encap"})
            _extra(result, f"interface {name}.{index} vlan encap", encap, {"single-tagged"})
            _extra(result, f"interface {name}.{index} single-tagged", tagged, {"vlan-id"})
            for leaf in ("ipv4", "ipv6"):
                family = sub.get(leaf) or {}
                _extra(result, f"interface {name}.{index} {leaf}", family, {"address", "dhcp-relay", "admin-state"})
                for address in family.get("address") or [] if isinstance(family, dict) else []:
                    _extra(result, f"interface {name}.{index} {leaf} address", address, {"ip-prefix"})
            acl = sub.get("acl") or {}
            _extra(result, f"interface {name}.{index} acl", acl, {"input", "output"})
            for direction in ("input", "output"):
                _extra(result, f"interface {name}.{index} acl {direction}", acl.get(direction) or {},
                       {"ipv4-filter", "ipv6-filter"})
            if index == 0 and not vlan_id:
                # index-0, untagged: this IS the base interface's own routed subinterface.  The canonical MTU is the
                # L3 MTU, which SR Linux holds as the subinterface ``ip-mtu`` (the port ``mtu`` is the L2 frame size).
                if sub.get("ip-mtu") is not None:
                    base.mtu = sub["ip-mtu"]
                base.addresses.extend(addresses)
                base.acl_attachments.extend(attachments)
                base.dhcp_relays.extend(relays)
                continue
            key = f"{name}.{index}"
            subif = ParsedInterface(
                name=key, kind="SUBINTERFACE", parent_name=name, encapsulation_vlan=vlan_id or index,
                description=sub.get("description", ""), mtu=sub.get("ip-mtu"),
                admin_state="ENABLED" if sub.get("admin-state", "enable") == "enable" else "DISABLED",
            )
            subif.addresses = addresses
            subif.acl_attachments = attachments
            subif.dhcp_relays = relays
            interfaces[key] = subif
    return interfaces


def _parse_static_routes(ni: dict, result: ParsedConfig) -> None:
    groups = {g.get("name"): g for g in ((ni.get("next-hop-groups") or {}).get("group") or [])}
    for route in ((ni.get("static-routes") or {}).get("route") or []):
        _extra(result, f"static route {route.get('prefix') if isinstance(route, dict) else '(invalid)'}", route,
               {"prefix", "next-hop-group", "preference", "admin-state"})
        if not isinstance(route, dict):
            continue
        prefix = route.get("prefix")
        if not prefix:
            continue
        family = "IPV6" if ":" in prefix else "IPV4"
        parsed = ParsedStaticRoute(family=family, destination=prefix, lines=[json.dumps(route)])
        group = groups.get(route.get("next-hop-group"))
        # 24.10 names the list ``nexthop``; ``next-hop`` is kept for documents written by earlier releases.
        next_hops = (group or {}).get("nexthop") or (group or {}).get("next-hop") or []
        if len(next_hops) == 1 and next_hops[0].get("ip-address"):
            parsed.next_hop_address = next_hops[0].get("ip-address", "")
        else:
            _preserve(result, f"static route {prefix} (next-hop group is missing, empty, or multipath)", route)
            continue
        if "preference" in route:
            parsed.distance = route["preference"]
        result.static_routes.append(parsed)


def _parse_ospf(ni: dict, result: ParsedConfig, interface_names: set[str]) -> None:
    for instance in ((ni.get("protocols") or {}).get("ospf") or {}).get("instance") or []:
        _extra(result, f"OSPF instance {instance.get('name') if isinstance(instance, dict) else '(invalid)'}", instance,
               {"name", "version", "router-id", "area"})
        if not isinstance(instance, dict):
            continue
        version = "OSPFV3" if instance.get("version") == "ospf-v3" else "OSPFV2"
        process_id = instance.get("name")
        fields = {"version": version, "process_id": process_id, "router_id": instance.get("router-id", ""), "_passive_interfaces": set()}
        parsed = ParsedRoutingInstance(family="ospf", fields=fields)
        for area in instance.get("area") or []:
            _extra(result, f"OSPF area {area.get('area-id') if isinstance(area, dict) else '(invalid)'}", area,
                   {"area-id", "interface"})
            if not isinstance(area, dict):
                continue
            for iface_ref in area.get("interface") or []:
                _extra(result, f"OSPF interface {iface_ref.get('interface-name') if isinstance(iface_ref, dict) else '(invalid)'}",
                       iface_ref, {"interface-name", "metric", "interface-type"})
                if not isinstance(iface_ref, dict):
                    continue
                interface_name = iface_ref.get("interface-name", "")
                # Canonical intent represents an untagged index-0 routed
                # subinterface on its physical parent object.  SR Linux refers
                # to that same object as ``parent.0`` in the network-instance.
                # Tagged subinterfaces retain their full ``parent.index`` key.
                if interface_name.endswith(".0") and interface_name[:-2] in interface_names:
                    interface_name = interface_name[:-2]
                binding = {"interface_name": interface_name, "area": area.get("area-id", ""),
                           "process_id": process_id, "version": version}
                if "metric" in iface_ref:
                    binding["cost"] = iface_ref["metric"]
                if iface_ref.get("interface-type") == "point-to-point":
                    binding["network_type"] = "POINT_TO_POINT"
                parsed.bindings.append(binding)
        result.routing_instances.append(parsed)


def _parse_bgp(ni: dict, result: ParsedConfig) -> None:
    bgp = (ni.get("protocols") or {}).get("bgp")
    if not bgp:
        return
    _extra(result, "BGP process", bgp, {"autonomous-system", "router-id", "group", "neighbor"})
    fields = {"local_asn": bgp.get("autonomous-system"), "router_id": bgp.get("router-id", "")}
    groups = {g.get("name"): g for g in bgp.get("group") or []}
    for group in bgp.get("group") or []:
        _extra(result, f"BGP group {group.get('name') if isinstance(group, dict) else '(invalid)'}", group,
               {"name", "ipv4-unicast", "ipv6-unicast", "admin-state"})
    neighbors = []
    for neighbor in bgp.get("neighbor") or []:
        _extra(result, f"BGP neighbor {neighbor.get('peer-address') if isinstance(neighbor, dict) else '(invalid)'}", neighbor,
               {"peer-address", "peer-group", "peer-as", "description", "admin-state"})
        if not isinstance(neighbor, dict):
            continue
        group = groups.get(neighbor.get("peer-group")) or {}
        neighbors.append({
            "peer_address": neighbor.get("peer-address", ""), "remote_asn": neighbor.get("peer-as"),
            "description": neighbor.get("description", ""),
            "activate_ipv4": (group.get("ipv4-unicast") or {}).get("admin-state") == "enable",
            "activate_ipv6": (group.get("ipv6-unicast") or {}).get("admin-state") == "enable",
            "update_source_interface": "", "ebgp_multihop": None, "next_hop_self": False,
            "route_reflector_client": False, "shutdown": neighbor.get("admin-state") == "disable",
        })
    result.routing_instances.append(ParsedRoutingInstance(family="bgp", fields=fields, neighbors=neighbors, networks=[]))


def _match_back(match: dict) -> tuple[str, str]:
    prefix = match.get("prefix")
    if prefix is None:
        return "ANY", ""
    if prefix.endswith("/32") or prefix.endswith("/128"):
        return "HOST", prefix.rsplit("/", 1)[0]
    return "PREFIX", prefix


def _parse_acls(doc: dict, result: ParsedConfig) -> None:
    acl_doc = doc.get("acl") or {}
    _extra(result, "acl", acl_doc, {"ipv4-filter", "ipv6-filter"})
    for filter_kind, family in (("ipv4-filter", "IPV4"), ("ipv6-filter", "IPV6")):
        for entry in acl_doc.get(filter_kind) or []:
            _extra(result, f"{filter_kind} {entry.get('name') if isinstance(entry, dict) else '(invalid)'}", entry,
                   {"name", "entry"})
            if not isinstance(entry, dict):
                continue
            acl = ParsedAcl(name=entry.get("name", ""), family=family, acl_type="EXTENDED")
            for ace in entry.get("entry") or []:
                _extra(result, f"ACL {entry.get('name')} entry {ace.get('sequence-id') if isinstance(ace, dict) else '(invalid)'}",
                       ace, {"sequence-id", "match", "action"})
                if not isinstance(ace, dict):
                    continue
                match = ace.get("match") or {}
                _extra(result, f"ACL {entry.get('name')} entry {ace.get('sequence-id')} match", match,
                       {"source-ip", "destination-ip", "protocol"})
                action_obj = ace.get("action") or {}
                _extra(result, f"ACL {entry.get('name')} entry {ace.get('sequence-id')} action", action_obj,
                       {"accept", "drop"})
                source_type, source_value = _match_back(match.get("source-ip") or {})
                destination_type, destination_value = _match_back(match.get("destination-ip") or {})
                action = "PERMIT" if "accept" in (ace.get("action") or {}) else "DENY"
                acl.entries.append({
                    "sequence": ace.get("sequence-id", 0), "action": action, "protocol": match.get("protocol", "IP"),
                    "source_type": source_type, "source_value": source_value,
                    "destination_type": destination_type, "destination_value": destination_value, "logging": False,
                })
            result.acls.append(acl)


def parse(source) -> ParsedConfig:
    """``source`` is a JSON string, an already-decoded dict, or rendered ``set`` statements."""
    if isinstance(source, str) and srlinux_model.looks_like_set_lines(source):
        doc = srlinux_model.tree_from_set_lines(source.splitlines())
    else:
        doc = srlinux_model.normalize(json.loads(source) if isinstance(source, str) else source)
    result = ParsedConfig(parser_version=PARSER_VERSION)
    # `sr_cli info interface ... | as json` on 24.10 emits a YANG list,
    # whereas earlier saved-config fixtures represented the keyed collection
    # as a mapping. Normalize the live form at the import boundary.
    if isinstance(doc, dict) and isinstance(doc.get("interface"), list):
        normalized = {}
        for row in doc["interface"]:
            if isinstance(row, dict) and isinstance(row.get("name"), str) and row["name"]:
                normalized[row["name"]] = {key: value for key, value in row.items() if key != "name"}
            else:
                _preserve(result, "interface entry without a valid name", row, "UNKNOWN")
        doc = {**doc, "interface": normalized}
    system = doc.get("system") or {}
    name = system.get("name") or {} if isinstance(system, dict) else {}
    result.hostname = name.get("host-name", "") if isinstance(name, dict) else ""
    _extra(result, "system", system, {"name"})
    _extra(result, "system name", name, {"host-name"})

    network_instances = doc.get("network-instance") or []
    mgmt_names = _mgmt_interface_names(network_instances)
    interfaces = _parse_interfaces(doc, mgmt_names, result)
    result.interfaces = list(interfaces.values())

    for ni in network_instances:
        if ni.get("name") == "mgmt":
            _extra(result, "network-instance mgmt", ni, {"name", "interface"})
            continue
        if ni.get("name") != "default":
            _preserve(result, f"network-instance {ni.get('name')!r} (non-default VRF is not modeled)", ni)
            continue
        _extra(result, "network-instance default", ni,
               {"name", "interface", "static-routes", "next-hop-groups", "protocols"})
        protocols = ni.get("protocols") or {}
        _extra(result, "network-instance default protocols", protocols, {"ospf", "bgp"})
        _parse_static_routes(ni, result)
        _parse_ospf(ni, result, set(interfaces))
        _parse_bgp(ni, result)

    _parse_acls(doc, result)

    for key, value in doc.items():
        if key not in _KNOWN_TOP_KEYS:
            result.unmanaged_blocks.append(UnmanagedBlock(
                f"Unrecognized top-level configuration {key!r} (no structured parser for it yet)",
                "UNKNOWN", [json.dumps({key: value}, indent=2)],
            ))
    return result
