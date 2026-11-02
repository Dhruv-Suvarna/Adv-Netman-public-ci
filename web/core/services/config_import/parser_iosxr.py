"""Cisco IOS XR running-config -> vendor-neutral parsed import records.

Parses the same real, documented IOS XR CLI syntax
``platform_drivers.IosXrDriver`` renders (verified against Cisco's IOS XR
Interfaces / IP Addresses and Services / Implementing OSPF / Implementing BGP
/ Access Lists configuration guides): dotted-decimal IPv4 interface masks,
CIDR IPv6/static-route prefixes, `router ospf`/`router ospfv3` as distinct
process types with area/interface nested under the process (not the
interface stanza), and the mandatory address-family activation BGP requires.

No IOS XR node is deployed in this lab, so this parser is exercised only
against fixture running-config text (either hand-written or produced by
rendering a candidate) -- see
docs/PHASE_20_5_PLATFORM_CAPABILITY_AUDIT.md "Evidence boundary". Unknown
stanzas and unrecognized subcommands remain immutable/unmanaged; unfamiliar
IOS XR syntax is never guessed into intent.
"""

from __future__ import annotations

import ipaddress
import re

from .schema import ParsedAcl, ParsedConfig, ParsedInterface, ParsedRoutingInstance, ParsedStaticRoute, UnmanagedBlock

PARSER_VERSION = "iosxr-1.0"

_KNOWN_UNSUPPORTED_LABELS = {
    "router isis": "IS-IS routing process",
    "ntp": "NTP configuration", "aaa": "AAA configuration", "username": "Local user account",
    "logging": "Syslog configuration", "snmp-server": "SNMP configuration",
    "route-policy": "Route policy", "prefix-set": "Prefix set", "vrf": "VRF definition",
    "class-map": "QoS class map", "policy-map": "QoS policy map", "telemetry": "Telemetry configuration",
    "grpc": "gRPC/management-plane configuration", "netconf-yang": "NETCONF-yang agent configuration",
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


_INTERFACE_HEADER_RE = re.compile(r"^interface\s+(\S+)\s*$", re.I)
_HOSTNAME_RE = re.compile(r"^hostname\s+(\S+)\s*$", re.I)
_IPV4_ADDR_RE = re.compile(r"^ipv4 address\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)$", re.I)
_IPV6_ADDR_RE = re.compile(r"^ipv6 address\s+([0-9A-Fa-f:]+/\d+)$", re.I)


def _mask_to_prefixlen(mask: str) -> int | None:
    try:
        return ipaddress.ip_network(f"0.0.0.0/{mask}", strict=False).prefixlen
    except ValueError:
        return None


def _interface_kind(name: str) -> tuple[str | None, dict]:
    lower = name.lower()
    extras: dict = {}
    if lower.startswith(("bundle-ether", "port-channel")):
        return None, extras
    if lower.startswith("mgmteth"):
        return "MANAGEMENT", extras
    if lower.startswith("loopback"):
        return "LOOPBACK", extras
    if "." in name:
        parent, vlan = name.split(".", 1)
        extras["parent_name"] = parent
        if vlan.isdigit():
            extras["encapsulation_vlan"] = int(vlan)
        return "SUBINTERFACE", extras
    return "ROUTED_PHYSICAL", extras


def _parse_interface_block(lines: list[str]) -> ParsedInterface | None:
    header = _INTERFACE_HEADER_RE.match(lines[0])
    if not header:
        return None
    name = header.group(1)
    kind, extras = _interface_kind(name)
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
            prefixlen = _mask_to_prefixlen(match.group(2))
            if prefixlen is not None:
                parsed.addresses.append({"family": "IPV4", "cidr": f"{match.group(1)}/{prefixlen}", "role": "PRIMARY"})
            else:
                parsed.preserved_lines.append(line)
        elif (match := _IPV6_ADDR_RE.match(command)):
            parsed.addresses.append({"family": "IPV6", "cidr": match.group(1), "role": "PRIMARY"})
        elif (match := re.fullmatch(r"encapsulation dot1q\s+(\d+)", lower)):
            parsed.encapsulation_vlan = int(match.group(1))
        elif (match := re.fullmatch(r"(ipv4|ipv6) access-group\s+(\S+)\s+(in|out)", command, re.I)):
            parsed.acl_attachments.append({"family": "IPV4" if match.group(1).lower() == "ipv4" else "IPV6",
                                           "name": match.group(2), "direction": match.group(3).upper()})
        else:
            parsed.preserved_lines.append(line)
    return parsed


def _parse_static_route_af(block: list[str]) -> tuple[list[ParsedStaticRoute], list[str]]:
    routes: list[ParsedStaticRoute] = []
    preserved: list[str] = []
    family = ""
    for line in block[1:]:
        command = line.strip()
        if (match := re.fullmatch(r"address-family\s+(ipv4|ipv6)\s+unicast", command, re.I)):
            family = match.group(1).upper()
            continue
        tokens = command.split()
        if not family or len(tokens) < 2:
            preserved.append(line)
            continue
        destination, next_hop = tokens[0], tokens[1]
        try:
            ipaddress.ip_network(destination, strict=False)
        except ValueError:
            preserved.append(line)
            continue
        route = ParsedStaticRoute(family=family, destination=destination, lines=[line])
        try:
            ipaddress.ip_address(next_hop)
            route.next_hop_address = next_hop
        except ValueError:
            route.next_hop_interface = next_hop
        rest = tokens[2:]
        if rest and rest[0].isdigit():
            route.distance = int(rest[0])
            rest = rest[1:]
        if len(rest) == 2 and rest[0].lower() == "tag" and rest[1].isdigit():
            route.tag = int(rest[1])
            rest = []
        if rest:
            preserved.append(line)
        routes.append(route)
    return routes, preserved


def _parse_ospf(block: list[str], *, v3: bool) -> ParsedRoutingInstance:
    header = block[0].split()
    process_id = int(header[2]) if len(header) > 2 and header[2].isdigit() else None
    fields = {"version": "OSPFV3" if v3 else "OSPFV2", "process_id": process_id, "router_id": "", "_passive_interfaces": set()}
    bindings: list[dict] = []
    preserved: list[str] = []
    current_area = None
    current_interface = None
    for line in block[1:]:
        command = line.strip()
        if (match := re.fullmatch(r"router-id\s+(\S+)", command, re.I)):
            fields["router_id"] = match.group(1)
        elif (match := re.fullmatch(r"area\s+(\S+)", command, re.I)):
            current_area = match.group(1)
            current_interface = None
        elif (match := re.fullmatch(r"interface\s+(\S+)", command, re.I)) and current_area is not None:
            current_interface = {"interface_name": match.group(1), "version": fields["version"],
                                  "process_id": process_id, "area": current_area}
            bindings.append(current_interface)
        elif command.lower() == "network point-to-point" and current_interface is not None:
            current_interface["network_type"] = "POINT_TO_POINT"  # pylint: disable=unsupported-assignment-operation  # guarded: current_interface is not None
        elif (match := re.fullmatch(r"metric\s+(\d+)", command, re.I)) and current_interface is not None:
            current_interface["cost"] = int(match.group(1))  # pylint: disable=unsupported-assignment-operation  # guarded: current_interface is not None
        elif (match := re.fullmatch(r"passive-interface\s+(\S+)", command, re.I)):
            fields["_passive_interfaces"].add(match.group(1))
        else:
            preserved.append(line)
    instance = ParsedRoutingInstance(family="ospf", fields=fields, preserved_lines=preserved)
    instance.bindings = bindings
    return instance


def _parse_rip(block: list[str]) -> ParsedRoutingInstance:
    """Parse the default-VRF RIPv2 subset rendered by IosXrDriver."""
    parsed = ParsedRoutingInstance(
        family="rip", fields={"address_family": "IPV4", "enabled": True}
    )
    current: dict | None = None
    for line in block[1:]:
        command = line.strip()
        if match := re.fullmatch(r"interface\s+(\S+)", command, re.I):
            current = {"interface_name": match.group(1), "passive": False}
            parsed.bindings.append(current)
        elif command.lower() == "passive-interface" and current is not None:
            current["passive"] = True  # pylint: disable=unsupported-assignment-operation  # guarded: current is not None
        else:
            parsed.preserved_lines.append(line)
    return parsed


def _neighbor_defaults(peer: str, remote_asn: int) -> dict:
    return {"peer_address": peer, "remote_asn": remote_asn, "description": "",
        "activate_ipv4": False, "activate_ipv6": False, "update_source_interface": "",
        "ebgp_multihop": None, "next_hop_self": False, "route_reflector_client": False, "shutdown": False}


def _parse_bgp(block: list[str]) -> ParsedRoutingInstance | None:
    header = block[0].split()
    if len(header) < 3 or not header[2].isdigit():
        return None
    fields = {"local_asn": int(header[2]), "router_id": ""}
    neighbors: dict[str, dict] = {}
    networks: list[dict] = []
    preserved: list[str] = []
    current_neighbor = None
    current_af = ""
    for line in block[1:]:
        indent = len(line) - len(line.lstrip(" "))
        command = line.strip()
        if (match := re.fullmatch(r"bgp router-id\s+(\S+)", command, re.I)):
            fields["router_id"] = match.group(1)
        elif indent == 1 and (match := re.fullmatch(r"address-family\s+(ipv4|ipv6)\s+unicast", command, re.I)):
            current_af = match.group(1).upper()
            current_neighbor = None
        elif indent == 1 and (match := re.fullmatch(r"neighbor\s+(\S+)", command, re.I)):
            current_neighbor = match.group(1)
            current_af = ""
            neighbors.setdefault(current_neighbor, _neighbor_defaults(current_neighbor, 0))
        elif current_af and indent == 2 and (match := re.fullmatch(r"network\s+(\S+)", command, re.I)):
            networks.append({"family": current_af, "cidr": match.group(1)})
        elif current_neighbor and (match := re.fullmatch(r"remote-as\s+(\d+)", command, re.I)):
            neighbors[current_neighbor]["remote_asn"] = int(match.group(1))
        elif current_neighbor and (match := re.fullmatch(r"description\s+(.+)", command, re.I)):
            neighbors[current_neighbor]["description"] = match.group(1)
        elif current_neighbor and (match := re.fullmatch(r"update-source\s+(\S+)", command, re.I)):
            neighbors[current_neighbor]["update_source_interface"] = match.group(1)
        elif current_neighbor and (match := re.fullmatch(r"ebgp-multihop\s+(\d+)", command, re.I)):
            neighbors[current_neighbor]["ebgp_multihop"] = int(match.group(1))
        elif current_neighbor and command.lower() == "shutdown":
            neighbors[current_neighbor]["shutdown"] = True
        elif current_neighbor and (match := re.fullmatch(r"address-family\s+(ipv4|ipv6)\s+unicast", command, re.I)):
            fam = match.group(1).upper()
            neighbors[current_neighbor]["activate_ipv4"] = neighbors[current_neighbor]["activate_ipv4"] or fam == "IPV4"
            neighbors[current_neighbor]["activate_ipv6"] = neighbors[current_neighbor]["activate_ipv6"] or fam == "IPV6"
        else:
            preserved.append(line)
    return ParsedRoutingInstance(family="bgp", fields=fields, neighbors=list(neighbors.values()), networks=networks,
                                 preserved_lines=preserved)


def _match_term(value: str) -> tuple[str, str]:
    if value == "any":
        return "ANY", ""
    if value.endswith("/32") or value.endswith("/128"):
        return "HOST", value.rsplit("/", 1)[0]
    return "PREFIX", value


def _parse_acl(block: list[str]) -> ParsedAcl | None:
    match = re.fullmatch(r"(ipv4|ipv6) access-list\s+(\S+)", block[0], re.I)
    if not match:
        return None
    acl = ParsedAcl(name=match.group(2), family="IPV4" if match.group(1).lower() == "ipv4" else "IPV6", acl_type="EXTENDED")
    for line in block[1:]:
        tokens = line.strip().split()
        if len(tokens) < 3 or not tokens[0].isdigit() or tokens[1].lower() not in {"permit", "deny"}:
            acl.preserved_lines.append(line)
            continue
        sequence, action = int(tokens[0]), tokens[1].upper()
        if len(tokens) == 3:
            # IOS XR standard ACL: "<seq> permit|deny <source-prefix|any>".
            acl.acl_type = "STANDARD"
            source_type, source_value = _match_term(tokens[2].lower())
            acl.entries.append({"sequence": sequence, "action": action, "protocol": "IP", "source_type": source_type,
                "source_value": source_value, "destination_type": "ANY", "destination_value": "", "logging": False})
            continue
        if len(tokens) != 5:
            # Port operators and log actions are not in the verified renderer
            # subset; preserve the complete entry instead of partially and
            # misleadingly importing it.
            acl.preserved_lines.append(line)
            continue
        protocol = tokens[2].upper()
        source_type, source_value = _match_term(tokens[3].lower())
        destination_type, destination_value = _match_term(tokens[4].lower())
        acl.entries.append({"sequence": sequence, "action": action, "protocol": protocol, "source_type": source_type,
            "source_value": source_value, "destination_type": destination_type, "destination_value": destination_value,
            "logging": False})
    return acl


def _parse_dhcp(block: list[str], *, family: str) -> tuple[list[tuple[str, dict]], list[str]]:
    """Parse the documented IOS XR relay profile + interface attachment model."""
    profiles: dict[str, list[str]] = {}
    attachments: list[tuple[str, str]] = []
    preserved: list[str] = []
    current_profile = ""
    for line in block[1:]:
        indent = len(line) - len(line.lstrip(" "))
        command = line.strip()
        if indent == 1 and (match := re.fullmatch(r"profile\s+(\S+)\s+relay", command, re.I)):
            current_profile = match.group(1)
            profiles.setdefault(current_profile, [])
        elif indent >= 2 and current_profile and (
            match := re.fullmatch(r"helper-address\s+vrf\s+default\s+(\S+)", command, re.I)
        ):
            profiles[current_profile].append(match.group(1))
        elif indent == 1 and (
            match := re.fullmatch(r"interface\s+(\S+)\s+relay\s+profile\s+(\S+)", command, re.I)
        ):
            attachments.append((match.group(1), match.group(2)))
            current_profile = ""
        else:
            preserved.append(line)
    relays: list[tuple[str, dict]] = []
    for interface_name, profile in attachments:
        destinations = profiles.get(profile)
        if not destinations:
            preserved.append(f" interface {interface_name} relay profile {profile}")
            continue
        relays.extend(
            (interface_name, {"family": family, "destination": destination})
            for destination in destinations
        )
    attached_profiles = {profile for _, profile in attachments}
    for profile, destinations in profiles.items():
        if profile not in attached_profiles:
            preserved.extend(
                [f" profile {profile} relay", *(f"  helper-address vrf default {item}" for item in destinations)]
            )
    return relays, preserved


def parse(text: str) -> ParsedConfig:
    result = ParsedConfig(parser_version=PARSER_VERSION)
    pending_relays: list[tuple[str, dict]] = []
    for block in _blocks(text):
        first = block[0]
        lower = first.lower()
        if (match := _HOSTNAME_RE.match(first)):
            result.hostname = match.group(1)
        elif lower.startswith("interface "):
            interface = _parse_interface_block(block)
            if interface is None:
                result.unmanaged_blocks.append(UnmanagedBlock(f"Interface {first.split(None, 1)[1]}", "RECOGNIZED_UNSUPPORTED", block))
            else:
                result.interfaces.append(interface)
        elif lower == "router static":
            routes, preserved = _parse_static_route_af(block)
            result.static_routes.extend(routes)
            if preserved:
                result.unmanaged_blocks.append(UnmanagedBlock("Additional router static configuration", "UNKNOWN", preserved))
        elif lower == "router rip":
            result.routing_instances.append(_parse_rip(block))
        elif lower.startswith("router ospfv3 "):
            result.routing_instances.append(_parse_ospf(block, v3=True))
        elif lower.startswith("router ospf "):
            result.routing_instances.append(_parse_ospf(block, v3=False))
        elif lower.startswith("router bgp "):
            parsed_bgp = _parse_bgp(block)
            if parsed_bgp:
                result.routing_instances.append(parsed_bgp)
            else:
                result.unmanaged_blocks.append(UnmanagedBlock("BGP routing process", "RECOGNIZED_UNSUPPORTED", block))
        elif lower.startswith(("ipv4 access-list ", "ipv6 access-list ")):
            acl = _parse_acl(block)
            if acl:
                result.acls.append(acl)
            else:
                result.unmanaged_blocks.append(UnmanagedBlock("ACL definition", "RECOGNIZED_UNSUPPORTED", block))
        elif lower in {"dhcp ipv4", "dhcp ipv6"}:
            family = "IPV4" if lower.endswith("ipv4") else "IPV6"
            relays, preserved = _parse_dhcp(block, family=family)
            pending_relays.extend(relays)
            if preserved:
                result.unmanaged_blocks.append(UnmanagedBlock(
                    f"Additional DHCP {family} configuration", "RECOGNIZED_UNSUPPORTED", preserved
                ))
        else:
            label, classification = _classify_unmanaged(first)
            result.unmanaged_blocks.append(UnmanagedBlock(label, classification, block))

    interfaces_by_name = {interface.name: interface for interface in result.interfaces}
    for interface_name, relay in pending_relays:
        interface = interfaces_by_name.get(interface_name)
        if interface is None:
            result.unmanaged_blocks.append(UnmanagedBlock(
                f"DHCP relay attachment references missing interface {interface_name}",
                "RECOGNIZED_UNSUPPORTED",
                [f"{relay['family']} helper-address {relay['destination']}"],
            ))
        else:
            interface.dhcp_relays.append(relay)

    for instance in result.routing_instances:
        if instance.family != "ospf":
            continue
        passive = instance.fields.pop("_passive_interfaces", set())
        for binding in instance.bindings:
            binding["passive"] = binding.get("interface_name") in passive
    return result
