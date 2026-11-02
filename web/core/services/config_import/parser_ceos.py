"""Arista cEOS running-config -> vendor-neutral parsed import records.

The parser recognizes the feature vocabulary that the cEOS Device Builder
driver can validate and render. Unknown stanzas and unsupported subcommands
remain verbatim immutable/unmanaged configuration; unfamiliar EOS syntax is
never guessed into intent.
"""

from __future__ import annotations

import ipaddress
import re

from . import ceos_port_names
from .schema import ParsedAcl, ParsedConfig, ParsedInterface, ParsedRoutingInstance, ParsedStaticRoute, UnmanagedBlock

PARSER_VERSION = "ceos-2.1"

_KNOWN_UNSUPPORTED_LABELS = {
    "router isis": "IS-IS routing process", "spanning-tree": "Spanning-tree configuration",
    "ntp": "NTP configuration", "aaa": "AAA configuration", "username": "Local user account",
    "logging": "Syslog configuration", "snmp-server": "SNMP configuration",
    "management": "Management API / access configuration", "route-map": "Route map",
    "ip prefix-list": "Prefix list", "ipv6 prefix-list": "IPv6 prefix list",
    "ip dhcp": "DHCP server configuration", "banner": "Banner text",
    "class-map": "QoS class map", "policy-map": "QoS policy map", "vlan": "VLAN definition",
}


def _blocks(text: str) -> list[list[str]]:
    blocks: list[list[str]] = []
    current: list[str] | None = None
    for raw_line in text.splitlines():
        line = raw_line.rstrip()
        if not line.strip() or line.strip() == "!":
            continue
        if line[0] not in (" ", "\t"):
            current = [line]
            blocks.append(current)
        elif current is not None:
            current.append(line)
    return blocks


def _classify_unmanaged(first_line: str) -> tuple[str, str]:
    words = first_line.lower().split()
    for length in (2, 1):
        candidate = " ".join(words[:length])
        if candidate in _KNOWN_UNSUPPORTED_LABELS:
            return _KNOWN_UNSUPPORTED_LABELS[candidate], "RECOGNIZED_UNSUPPORTED"
    return f"Unrecognized configuration ({words[0] if words else '(empty)'})", "UNKNOWN"


def _vlan_set(value: str) -> list[int]:
    result: set[int] = set()
    for token in value.split(","):
        token = token.strip()
        try:
            if "-" in token:
                start, end = (int(part) for part in token.split("-", 1))
                result.update(range(start, end + 1))
            elif token:
                result.add(int(token))
        except ValueError:
            return []
    return sorted(result)


def _interface_kind(name: str, lines: list[str]) -> tuple[str | None, dict]:
    lower = name.lower()
    extras: dict = {}
    if lower.startswith(("port-channel", "vxlan")):
        return None, extras
    if lower.startswith("management"):
        return "MANAGEMENT", extras
    if lower.startswith("loopback"):
        return "LOOPBACK", extras
    match = re.fullmatch(r"vlan(\d+)", name, re.I)
    if match:
        extras["vlan_id"] = int(match.group(1))
        return "SVI", extras
    if "." in name:
        extras["parent_name"] = name.split(".", 1)[0]
        return "SUBINTERFACE", extras
    commands = {line.strip().lower() for line in lines[1:]}
    if "no switchport" in commands:
        # EOS keeps the switchport lines of a port that was made routed; they are dormant and do not define its kind
        return "ROUTED_PHYSICAL", extras
    if "switchport mode access" in commands or any(command.startswith("switchport access vlan ") for command in commands):
        return "ACCESS", extras
    if "switchport mode trunk" in commands or any(command.startswith("switchport trunk allowed vlan ") for command in commands):
        return "TRUNK", extras
    return "ROUTED_PHYSICAL", extras


_INTERFACE_HEADER_RE = re.compile(r"^interface\s+(\S+)\s*$", re.I)
_HOSTNAME_RE = re.compile(r"^hostname\s+(\S+)\s*$", re.I)
_IPV4_ADDR_RE = re.compile(r"^ip address\s+(\d+\.\d+\.\d+\.\d+/\d+)(?:\s+secondary)?$", re.I)
_IPV6_ADDR_RE = re.compile(r"^ipv6 address\s+([0-9A-Fa-f:]+/\d+)$", re.I)


def _parse_interface_block(lines: list[str]) -> ParsedInterface | None:
    header = _INTERFACE_HEADER_RE.match(lines[0])
    if not header:
        return None
    name = header.group(1)
    kind, extras = _interface_kind(name, lines)
    if kind is None:
        return None
    parsed = ParsedInterface(name=name, kind=kind, **extras)
    for line in lines[1:]:
        command = line.strip()
        lower = command.lower()
        if lower == "shutdown":
            parsed.admin_state = "DISABLED"
        elif lower == "no shutdown":
            parsed.admin_state = "ENABLED"
        elif lower.startswith("description "):
            parsed.description = command.split(None, 1)[1]
        elif re.fullmatch(r"mtu\s+\d+", lower):
            parsed.mtu = int(command.split()[1])
        elif (match := _IPV4_ADDR_RE.match(command)):
            parsed.addresses.append({"family": "IPV4", "cidr": match.group(1),
                                     "role": "SECONDARY" if lower.endswith(" secondary") else "PRIMARY"})
        elif (match := _IPV6_ADDR_RE.match(command)):
            parsed.addresses.append({"family": "IPV6", "cidr": match.group(1), "role": "PRIMARY"})
        elif (match := re.fullmatch(r"switchport access vlan\s+(\d+)", lower)):
            parsed.access_vlan = int(match.group(1))
        elif (match := re.fullmatch(r"switchport trunk allowed vlan\s+(.+)", lower)):
            parsed.trunk_allowed_vlans = _vlan_set(match.group(1))
        elif (match := re.fullmatch(r"switchport trunk native vlan\s+(\d+)", lower)):
            parsed.native_vlan = int(match.group(1))
        elif lower in {"switchport", "switchport mode access", "switchport mode trunk"}:
            pass
        elif (match := re.fullmatch(r"encapsulation dot1q\s+(?:vlan\s+)?(\d+)", lower)):
            parsed.encapsulation_vlan = int(match.group(1))
        elif (match := re.fullmatch(r"ip ospf area\s+(\S+)", lower)):
            parsed.ospf_bindings.append({"version": "OSPFV2", "process_id": None, "area": match.group(1)})
        elif (match := re.fullmatch(r"ipv6 ospf\s+(\d+)\s+area\s+(\S+)", lower)):
            parsed.ospf_bindings.append({"version": "OSPFV3", "process_id": int(match.group(1)), "area": match.group(2)})
        elif (match := re.fullmatch(r"(ip|ipv6) ospf cost\s+(\d+)", lower)):
            for binding in parsed.ospf_bindings[-1:]:
                if binding["version"] == ("OSPFV3" if match.group(1) == "ipv6" else "OSPFV2"):
                    binding["cost"] = int(match.group(2))
        elif lower in {"ip ospf network point-to-point", "ipv6 ospf network point-to-point"}:
            for binding in parsed.ospf_bindings[-1:]:
                if binding["version"] == ("OSPFV3" if lower.startswith("ipv6") else "OSPFV2"):
                    binding["network_type"] = "POINT_TO_POINT"
        elif command == f"isis enable {ISIS_TAG}":
            parsed.isis_bindings.append({"passive": False, "metric": None})
        elif lower == "isis passive" and parsed.isis_bindings:
            parsed.isis_bindings[-1]["passive"] = True
        elif (match := re.fullmatch(r"isis metric\s+(\d+)", lower)) and parsed.isis_bindings:
            parsed.isis_bindings[-1]["metric"] = int(match.group(1))
        elif (match := re.fullmatch(r"ip helper-address\s+(\S+)", lower)):
            parsed.dhcp_relays.append({"family": "IPV4", "destination": match.group(1)})
        elif (match := re.fullmatch(r"ipv6 dhcp relay destination\s+(\S+)", lower)):
            parsed.dhcp_relays.append({"family": "IPV6", "destination": match.group(1)})
        elif (match := re.fullmatch(r"(ip|ipv6) virtual-router address\s+(\S+)", lower)):
            parsed.fhrp.append({"protocol": "VARP", "address_family": "IPV4" if match.group(1) == "ip" else "IPV6",
                                "address": match.group(2)})
        elif (match := re.fullmatch(r"(ip|ipv6) access-group\s+(\S+)\s+(in|out)", command, re.I)):
            # ACL names are case-sensitive on EOS: keep the configured spelling so the attachment matches its list.
            parsed.acl_attachments.append({"family": "IPV4" if match.group(1).lower() == "ip" else "IPV6",
                                           "name": match.group(2), "direction": match.group(3).upper()})
        else:
            parsed.preserved_lines.append(line)
    return parsed


def _parse_static_route(block: list[str], family: str) -> ParsedStaticRoute | None:
    tokens = block[0].split(); offset = 2
    if len(tokens) < offset + 2: return None
    destination, next_hop = tokens[offset], tokens[offset + 1]
    try: ipaddress.ip_network(destination, strict=False)
    except ValueError: return None
    route = ParsedStaticRoute(family=family, destination=destination, lines=block)
    try: ipaddress.ip_address(next_hop); route.next_hop_address = next_hop
    except ValueError: route.next_hop_interface = next_hop
    rest = tokens[offset + 2:]
    if rest and rest[0].isdigit(): route.distance = int(rest.pop(0))
    if "tag" in rest:
        idx = rest.index("tag")
        if idx + 1 < len(rest) and rest[idx + 1].isdigit(): route.tag = int(rest[idx + 1])
    return route


def _parse_ospf(block: list[str]) -> ParsedRoutingInstance:
    header = block[0].split()
    version = "OSPFV3" if header[:3] == ["ipv6", "router", "ospf"] or header[1].lower() == "ospfv3" else "OSPFV2"
    process_token = header[3] if header[:3] == ["ipv6", "router", "ospf"] and len(header) > 3 else header[2] if len(header) > 2 else ""
    process_id = int(process_token) if process_token.isdigit() else None
    fields = {"version": version, "process_id": process_id, "router_id": "", "_passive_interfaces": set()}
    preserved, networks = [], []
    for line in block[1:]:
        command = line.strip()
        if (match := re.fullmatch(r"router-id\s+(\S+)", command, re.I)): fields["router_id"] = match.group(1)
        elif (match := re.fullmatch(r"passive-interface\s+(\S+)", command, re.I)): fields["_passive_interfaces"].add(match.group(1))
        elif version == "OSPFV2" and (match := re.fullmatch(r"network\s+(\S+)\s+area\s+(\S+)", command, re.I)):
            try:
                networks.append({"prefix": str(ipaddress.ip_network(match.group(1), strict=False)), "area": match.group(2)})
            except ValueError:
                preserved.append(line)
        else: preserved.append(line)
    return ParsedRoutingInstance(family="ospf", fields=fields, networks=networks, preserved_lines=preserved)


# The one IS-IS instance tag the cEOS renderer emits (platform_drivers.CEOS_ISIS_TAG).  A process under any other tag
# is not this model's process and stays an unmanaged block, so it is never re-rendered under a different name.
ISIS_TAG = "NMAS"
_ISIS_LEVELS = {"level-1": "LEVEL_1", "level-2": "LEVEL_2", "level-1-2": "LEVEL_1_2"}


def _parse_isis(block: list[str]) -> ParsedRoutingInstance:
    """``router isis NMAS``: NET, level and address families.  Everything else (redistribution, nested address-family
    lines) is preserved verbatim, never interpreted."""
    fields = {"net": "", "level": "LEVEL_1_2", "address_family_ipv4": False, "address_family_ipv6": False}
    preserved = []
    for line in block[1:]:
        command = line.strip(); lower = command.lower()
        if (match := re.fullmatch(r"net\s+(\S+)", command, re.I)): fields["net"] = match.group(1)
        elif (match := re.fullmatch(r"is-type\s+(\S+)", lower)) and match.group(1) in _ISIS_LEVELS: fields["level"] = _ISIS_LEVELS[match.group(1)]
        elif lower == "address-family ipv4 unicast": fields["address_family_ipv4"] = True
        elif lower == "address-family ipv6 unicast": fields["address_family_ipv6"] = True
        else: preserved.append(line)
    return ParsedRoutingInstance(family="isis", fields=fields, preserved_lines=preserved)


def _parse_rip(block: list[str]) -> ParsedRoutingInstance:
    networks, passive, preserved, enabled = [], set(), [], True
    for line in block[1:]:
        command = line.strip()
        if (match := re.fullmatch(r"network\s+(\S+)", command, re.I)): networks.append(match.group(1))
        elif (match := re.fullmatch(r"passive-interface\s+(\S+)", command, re.I)): passive.add(match.group(1))
        elif command.lower() == "shutdown": enabled = False
        elif command.lower() == "no shutdown": enabled = True
        else: preserved.append(line)
    return ParsedRoutingInstance(family="rip", fields={"address_family": "IPV4", "enabled": enabled,
        "_networks": networks, "_passive_interfaces": passive}, preserved_lines=preserved)


def _neighbor_defaults(peer: str, remote_asn: int) -> dict:
    return {"peer_address": peer, "remote_asn": remote_asn, "description": "",
        "activate_ipv4": "." in peer, "activate_ipv6": ":" in peer, "update_source_interface": "",
        "ebgp_multihop": None, "next_hop_self": False, "route_reflector_client": False, "shutdown": False}


def _parse_bgp(block: list[str]) -> ParsedRoutingInstance | None:
    header = block[0].split()
    if len(header) < 3 or not header[2].isdigit(): return None
    fields = {"local_asn": int(header[2]), "router_id": ""}; neighbors = {}; networks = []; preserved = []; current_af = ""
    for line in block[1:]:
        command = line.strip(); lower = command.lower()
        if (match := re.fullmatch(r"router-id\s+(\S+)", command, re.I)): fields["router_id"] = match.group(1)
        elif (match := re.fullmatch(r"address-family\s+(ipv4|ipv6)(?:\s+unicast)?", lower)): current_af = match.group(1).upper()
        elif lower in {"exit-address-family", "exit"}: current_af = ""
        elif (match := re.fullmatch(r"neighbor\s+(\S+)\s+remote-as\s+(\d+)", command, re.I)):
            neighbors[match.group(1)] = _neighbor_defaults(match.group(1), int(match.group(2)))
        elif (match := re.fullmatch(r"neighbor\s+(\S+)\s+description\s+(.+)", command, re.I)) and match.group(1) in neighbors:
            neighbors[match.group(1)]["description"] = match.group(2)
        elif (match := re.fullmatch(r"neighbor\s+(\S+)\s+update-source\s+(\S+)", command, re.I)) and match.group(1) in neighbors:
            neighbors[match.group(1)]["update_source_interface"] = match.group(2)
        elif (match := re.fullmatch(r"neighbor\s+(\S+)\s+ebgp-multihop\s+(\d+)", command, re.I)) and match.group(1) in neighbors:
            neighbors[match.group(1)]["ebgp_multihop"] = int(match.group(2))
        elif (match := re.fullmatch(r"neighbor\s+(\S+)\s+(activate|next-hop-self|route-reflector-client|shutdown)", command, re.I)) and match.group(1) in neighbors:
            peer, action = match.group(1), match.group(2).lower()
            if action == "activate" and current_af:
                neighbors[peer]["activate_ipv4"] = current_af == "IPV4"; neighbors[peer]["activate_ipv6"] = current_af == "IPV6"
            else: neighbors[peer][action.replace("-", "_")] = True
        elif (match := re.fullmatch(r"network\s+(\S+)", command, re.I)) and current_af:
            networks.append({"family": current_af, "cidr": match.group(1)})
        else: preserved.append(line)
    return ParsedRoutingInstance(family="bgp", fields=fields, neighbors=list(neighbors.values()), networks=networks,
                                 preserved_lines=preserved)


def _match_term(value: str) -> tuple[str, str]:
    if value == "any": return "ANY", ""
    if value.startswith("host "): return "HOST", value.split(None, 1)[1]
    return "PREFIX", value


def _parse_acl(block: list[str]) -> ParsedAcl | None:
    match = re.fullmatch(r"(ip|ipv6) access-list(?:\s+(standard|extended))?\s+(\S+)", block[0], re.I)
    if not match: return None
    acl = ParsedAcl(name=match.group(3), family="IPV4" if match.group(1).lower() == "ip" else "IPV6",
                    acl_type=(match.group(2) or "extended").upper())
    for line in block[1:]:
        tokens = line.strip().split()
        if len(tokens) < 3 or not tokens[0].isdigit() or tokens[1].lower() not in {"permit", "deny"}:
            acl.preserved_lines.append(line); continue
        sequence, action = int(tokens[0]), tokens[1].upper()
        if acl.acl_type == "STANDARD":
            source_end = 4 if tokens[2].lower() == "host" else 3
            if len(tokens) < source_end or [t.lower() for t in tokens[source_end:]] not in ([], ["log"]):
                acl.preserved_lines.append(line); continue
            source = " ".join(tokens[2:source_end])
            source_type, source_value = _match_term(source.lower())
            acl.entries.append({"sequence": sequence, "action": action, "protocol": "IP", "source_type": source_type,
                "source_value": source_value, "destination_type": "ANY", "destination_value": "",
                "logging": len(tokens) > source_end}); continue
        entry = _extended_entry(sequence, action, tokens)
        if entry is None: acl.preserved_lines.append(line); continue
        acl.entries.append(entry)
    return acl


def _term(tokens: list[str], cursor: int) -> tuple[str, int] | None:
    """An address term at ``cursor`` (``any`` / ``host A`` / a prefix) -> (its text, the next cursor)."""
    if cursor >= len(tokens): return None
    if tokens[cursor].lower() == "host":
        return (" ".join(tokens[cursor:cursor + 2]), cursor + 2) if cursor + 1 < len(tokens) else None
    return tokens[cursor], cursor + 1


def _port_clause(protocol: str, tokens: list[str], cursor: int) -> tuple[str, int] | None:
    """An optional ``eq P`` / ``range A B`` clause at ``cursor`` -> (the intent port text "80" / "1024-2048" / "", the next
    cursor).  EOS prints well-known ports by name (``eq www``); a name outside the verified table, or another operator
    (gt / lt / neq), is not modelled: None."""
    operator = tokens[cursor].lower() if cursor < len(tokens) else ""
    if operator == "eq" and cursor + 1 < len(tokens):
        number = ceos_port_names.port_number(protocol, tokens[cursor + 1])
        return (str(number), cursor + 2) if number is not None else None
    if operator == "range" and cursor + 2 < len(tokens):
        start, end = (ceos_port_names.port_number(protocol, t) for t in tokens[cursor + 1:cursor + 3])
        return (f"{start}-{end}", cursor + 3) if start is not None and end is not None else None
    if operator in ("gt", "lt", "neq", "eq", "range"):
        return None
    return "", cursor


def _extended_entry(sequence: int, action: str, tokens: list[str]) -> dict | None:
    """One extended entry ``SEQ ACTION PROTO SRC [PORTS] DST [PORTS] [log]`` -> its intent facts; None when any part is
    outside the model (the caller preserves the line verbatim)."""
    protocol = tokens[2].upper()
    if (source := _term(tokens, 3)) is None: return None
    if (source_port := _port_clause(protocol, tokens, source[1])) is None: return None
    if (destination := _term(tokens, source_port[1])) is None: return None
    if (destination_port := _port_clause(protocol, tokens, destination[1])) is None: return None
    rest = [t.lower() for t in tokens[destination_port[1]:]]
    if rest not in ([], ["log"]): return None
    source_type, source_value = _match_term(source[0].lower()); destination_type, destination_value = _match_term(destination[0].lower())
    return {"sequence": sequence, "action": action, "protocol": protocol, "source_type": source_type,
            "source_value": source_value, "source_port": source_port[0], "destination_type": destination_type,
            "destination_value": destination_value, "destination_port": destination_port[0], "logging": rest == ["log"]}


def _interface_for_network(interfaces: list[ParsedInterface], value: str) -> str:
    try: wanted = ipaddress.ip_network(value, strict=False)
    except ValueError: return ""
    for interface in interfaces:
        for address in interface.addresses:
            try:
                if ipaddress.ip_interface(address["cidr"]).network == wanted: return interface.name
            except ValueError: pass
    return ""


def _finalize_bindings(result: ParsedConfig, virtual_mac: str) -> None:
    ospf_by_key = {(i.fields["version"], i.fields.get("process_id")): i for i in result.routing_instances if i.family == "ospf"}
    for interface in result.interfaces:
        for binding in interface.ospf_bindings:
            instance = ospf_by_key.get((binding["version"], binding.get("process_id")))
            if instance is None and binding["version"] == "OSPFV2":
                instance = next((row for (version, _), row in ospf_by_key.items() if version == "OSPFV2"), None)
            if instance: instance.bindings.append({"interface_name": interface.name, **binding})
        isis = next((row for row in result.routing_instances if row.family == "isis"), None)
        for binding in interface.isis_bindings:
            if isis: isis.bindings.append({"interface_name": interface.name, **binding})
        for fhrp in interface.fhrp: fhrp["virtual_mac"] = virtual_mac
    for instance in result.routing_instances:
        passive = instance.fields.pop("_passive_interfaces", set())
        if instance.family == "rip":
            for network in instance.fields.pop("_networks", []):
                name = _interface_for_network(result.interfaces, network)
                if name: instance.bindings.append({"interface_name": name, "passive": name in passive})
        else:
            for binding in instance.bindings:
                if instance.family != "isis": binding["passive"] = binding.get("interface_name") in passive


def parse(text: str) -> ParsedConfig:
    result = ParsedConfig(parser_version=PARSER_VERSION); virtual_mac = ""
    for block in _blocks(text):
        first = block[0]; lower = first.lower()
        if (match := _HOSTNAME_RE.match(first)): result.hostname = match.group(1)
        elif lower.startswith("interface "):
            interface = _parse_interface_block(block)
            if interface is None:
                result.unmanaged_blocks.append(UnmanagedBlock(f"Interface {first.split(None, 1)[1]}", "RECOGNIZED_UNSUPPORTED", block))
            else: result.interfaces.append(interface)
        elif lower.startswith(("ip route ", "ipv6 route ")):
            route = _parse_static_route(block, "IPV6" if lower.startswith("ipv6") else "IPV4")
            if route: result.static_routes.append(route)
            else:
                label, classification = _classify_unmanaged(first); result.unmanaged_blocks.append(UnmanagedBlock(label, classification, block))
        elif lower.startswith(("router ospf", "ipv6 router ospf ")): result.routing_instances.append(_parse_ospf(block))
        elif lower == "router rip": result.routing_instances.append(_parse_rip(block))
        elif first.strip() == f"router isis {ISIS_TAG}" and not any(row.family == "isis" for row in result.routing_instances):
            result.routing_instances.append(_parse_isis(block))
        elif lower.startswith("router bgp "):
            parsed_bgp = _parse_bgp(block)
            if parsed_bgp: result.routing_instances.append(parsed_bgp)
            else: result.unmanaged_blocks.append(UnmanagedBlock("BGP routing process", "RECOGNIZED_UNSUPPORTED", block))
        elif lower.startswith(("ip access-list ", "ipv6 access-list ")):
            acl = _parse_acl(block)
            if acl: result.acls.append(acl)
            else: result.unmanaged_blocks.append(UnmanagedBlock("ACL definition", "RECOGNIZED_UNSUPPORTED", block))
        elif (match := re.fullmatch(r"ip virtual-router mac-address\s+(\S+)", first, re.I)): virtual_mac = match.group(1)
        else:
            label, classification = _classify_unmanaged(first); result.unmanaged_blocks.append(UnmanagedBlock(label, classification, block))
    _finalize_bindings(result, virtual_mac)
    _extract_management(result)
    return result


# --- V2 Phase 4: management VRF ------------------------------------------------------------------------------------------
_MGMT_VRF_NAME = re.compile(r"^[A-Za-z][A-Za-z0-9_-]{0,31}$")
_SERVICE_HEADERS = {"management ssh": "SSH", "management api http-commands": "EAPI", "management api gnmi": "GNMI"}
MAX_MANAGEMENT_VRFS = 2


def _children(block: list[str]) -> list[list[str]]:
    """Direct sub-blocks of ``block`` (each: first line + deeper lines), by indentation."""
    groups: list[list[str]] = []
    base = None
    for line in block[1:]:
        indent = len(line) - len(line.lstrip())
        if base is None or indent <= base:
            base = indent
            groups.append([line])
        else:
            groups[-1].append(line)
    return groups


def _service_vrfs(header: str, block: list[str]) -> dict[str, list[str]]:
    """{vrf: consumed sub-block lines} for sub-blocks that are exactly what the renderer emits; anything else stays."""
    found = {}
    for group in _children(block):
        head, rest = group[0].strip(), [line.strip() for line in group[1:]]
        if header == "management api gnmi":
            match = re.fullmatch(r"transport grpc (\S+)", head)
            if match and rest == [f"vrf {match.group(1)}"]:
                found[match.group(1)] = group
        else:
            match = re.fullmatch(r"vrf (\S+)", head)
            if match and rest == ["no shutdown"]:
                found[match.group(1)] = group
    return found


def _extract_management(result: ParsedConfig) -> None:
    """Lift management VRFs out of the unmanaged blocks: a VRF is a MANAGEMENT VRF only when a management access service
    (SSH / eAPI / gNMI) runs in it, it is defined (``vrf instance``) with nothing but a description, and ``ip routing vrf``
    is configured.  Data VRFs and every partially recognised line stay exactly where they were."""
    blocks = result.unmanaged_blocks
    services: dict[str, list[tuple[str, int, list[str]]]] = {}
    for index, block in enumerate(blocks):
        header = block.lines[0].strip()
        if header in _SERVICE_HEADERS:
            for name, group in _service_vrfs(header, block.lines).items():
                services.setdefault(name, []).append((_SERVICE_HEADERS[header], index, group))
    definitions, routing, routing6 = {}, {}, {}
    for index, block in enumerate(blocks):
        first = block.lines[0].strip()
        if (match := re.fullmatch(r"vrf instance (\S+)", first)):
            rest = [line.strip() for line in block.lines[1:]]
            if all(line.startswith("description ") for line in rest) and len(rest) <= 1:
                definitions[match.group(1)] = (index, rest[0].split(None, 1)[1] if rest else "")
        elif len(block.lines) == 1 and (match := re.fullmatch(r"ip routing vrf (\S+)", first)):
            routing[match.group(1)] = index
        elif len(block.lines) == 1 and (match := re.fullmatch(r"ipv6 unicast-routing vrf (\S+)", first)):
            routing6[match.group(1)] = index
    names = sorted(name for name in services if name in definitions and name in routing and _MGMT_VRF_NAME.fullmatch(name)
                   and name.lower() not in ("default", "global", "mgmt-default"))
    if not names or len(names) > MAX_MANAGEMENT_VRFS:
        return
    consumed: set[int] = set()
    trimmed: dict[int, list[str]] = {}
    management = {"vrfs": [], "bindings": [], "routes": [], "services": []}
    for name in names:
        index, description = definitions[name]
        consumed.update({index, routing[name]})
        management["vrfs"].append({"name": name, "description": description, "lines": list(blocks[index].lines)})
        for kind, block_index, group in services[name]:
            trimmed.setdefault(block_index, list(blocks[block_index].lines))
            trimmed[block_index] = [line for line in trimmed[block_index] if line not in group]
            management["services"].append({"vrf": name, "service": kind, "lines": [blocks[block_index].lines[0], *group]})
    for index, block in enumerate(blocks):
        if index in consumed or len(block.lines) != 1:
            continue
        match = re.fullmatch(r"(ip|ipv6) route vrf (\S+) (\S+) (\S+)", block.lines[0].strip())
        if not match or match.group(2) not in names:
            continue
        family = "IPV6" if match.group(1) == "ipv6" else "IPV4"
        if family == "IPV6" and match.group(2) not in routing6:
            continue
        try:
            network = ipaddress.ip_network(match.group(3), strict=True)
            hop = ipaddress.ip_address(match.group(4))
        except ValueError:
            continue
        if network.version != hop.version or network.version != (6 if family == "IPV6" else 4):
            continue
        consumed.add(index)
        management["routes"].append({"vrf": match.group(2), "family": family, "destination": str(network), "next_hop": str(hop),
                                     "lines": list(block.lines)})
    for name in names:
        if name in routing6 and any(r["vrf"] == name and r["family"] == "IPV6" for r in management["routes"]):
            consumed.add(routing6[name])            # the renderer emits it exactly when an IPv6 VRF route exists
    for interface in result.interfaces:
        for line in list(interface.preserved_lines):
            match = re.fullmatch(r"vrf (\S+)", line.strip())
            if match and match.group(1) in names:
                interface.preserved_lines.remove(line)
                management["bindings"].append({"vrf": match.group(1), "interface": interface.name, "lines": [f"interface {interface.name}", line]})
    kept = []
    for index, block in enumerate(blocks):
        if index in consumed:
            continue
        if index in trimmed:
            if len(trimmed[index]) <= 1:
                continue                             # nothing but the header remained
            block = UnmanagedBlock(block.label, block.classification, trimmed[index])
        kept.append(block)
    result.unmanaged_blocks = kept
    result.management = management
