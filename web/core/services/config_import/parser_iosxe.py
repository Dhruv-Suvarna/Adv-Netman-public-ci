"""Catalyst 8000V / IOS XE running-config parser for the verified NMAS subset.

IOS XE is intentionally separate from IOS XR.  This parser covers identity,
routed/sub/loopback/management interfaces, IPv4/IPv6 addressing, static
routes and (V2 Phase 9, live-verified on Catalyst 8000V 17.06.01a) the OSPFv2,
OSPFv3, RIPv2 and BGP processes NMAS renders, with their interface bindings.
Other stanzas are preserved as unmanaged until fixture or live evidence
justifies a semantic importer.
"""

from __future__ import annotations

import ipaddress
import re

from . import parser_iosxr
from .schema import ParsedConfig, ParsedRoutingInstance, ParsedStaticRoute, UnmanagedBlock

PARSER_VERSION = "iosxe-1.2"
_OSPF_INTERFACE = re.compile(r"^\s*(ip|ipv6) ospf\s+(\d+)\s+area\s+(\S+)\s*$", re.I)
_OSPF_COST = re.compile(r"^\s*(ip|ipv6) ospf cost\s+(\d+)\s*$", re.I)
_OSPF_P2P = re.compile(r"^\s*(ip|ipv6) ospf network point-to-point\s*$", re.I)


def _blocks(text: str) -> list[list[str]]:
    blocks: list[list[str]] = []
    current: list[str] | None = None
    for raw in text.splitlines():
        line = raw.rstrip()
        if not line.strip() or line.strip() == "!":
            continue
        if line[0] not in (" ", "\t"):
            current = [line]
            blocks.append(current)
        elif current is not None:
            current.append(line)
    return blocks


def _static_route(line: str) -> ParsedStaticRoute | None:
    tokens = line.split()
    if tokens[:2] == ["ip", "route"] and len(tokens) >= 5:
        try:
            destination = str(ipaddress.ip_network(f"{tokens[2]}/{tokens[3]}", strict=False))
        except ValueError:
            return None
        family, hop, rest = "IPV4", tokens[4], tokens[5:]
    elif tokens[:2] == ["ipv6", "route"] and len(tokens) >= 4:
        try:
            destination = str(ipaddress.ip_network(tokens[2], strict=False))
        except ValueError:
            return None
        family, hop, rest = "IPV6", tokens[3], tokens[4:]
    else:
        return None
    route = ParsedStaticRoute(family=family, destination=destination, lines=[line])
    try:
        ipaddress.ip_address(hop)
        route.next_hop_address = hop
    except ValueError:
        route.next_hop_interface = hop
    if rest and rest[0].isdigit():
        route.distance = int(rest.pop(0))
    if len(rest) == 2 and rest[0].lower() == "tag" and rest[1].isdigit():
        route.tag = int(rest[1])
        rest = []
    return route if not rest else None


def _wildcard_prefix(address: str, wildcard: str) -> str:
    mask = ".".join(str(255 - int(octet)) for octet in wildcard.split("."))
    return str(ipaddress.ip_network(f"{address}/{mask}", strict=False))


def _parse_ospf(block: list[str]) -> ParsedRoutingInstance | None:
    """``router ospf N`` (OSPFv2) or ``ipv6 router ospf N`` (OSPFv3, the IOS XE form NMAS renders)."""
    header = block[0].split()
    v3 = [token.lower() for token in header[:3]] == ["ipv6", "router", "ospf"]
    token = header[3] if v3 and len(header) > 3 else header[2] if len(header) > 2 else ""
    if not token.isdigit():
        return None
    fields = {"version": "OSPFV3" if v3 else "OSPFV2", "process_id": int(token), "router_id": "", "_passive_interfaces": set()}
    networks, preserved = [], []
    for line in block[1:]:
        command = line.strip()
        if (match := re.fullmatch(r"router-id\s+(\S+)", command, re.I)):
            fields["router_id"] = match.group(1)
        elif (match := re.fullmatch(r"passive-interface\s+(\S+)", command, re.I)):
            fields["_passive_interfaces"].add(match.group(1))
        elif not v3 and (match := re.fullmatch(r"network\s+(\S+)\s+(\S+)\s+area\s+(\S+)", command, re.I)):
            try:
                networks.append({"prefix": _wildcard_prefix(match.group(1), match.group(2)), "area": match.group(3)})
            except ValueError:
                preserved.append(line)
        else:
            preserved.append(line)
    return ParsedRoutingInstance(family="ospf", fields=fields, networks=networks, preserved_lines=preserved)


def _parse_rip(block: list[str]) -> ParsedRoutingInstance:
    networks, passive, preserved, version = [], set(), [], ""
    for line in block[1:]:
        command = line.strip()
        if (match := re.fullmatch(r"network\s+(\d+\.\d+\.\d+\.\d+)", command, re.I)):
            networks.append(match.group(1))
        elif (match := re.fullmatch(r"passive-interface\s+(\S+)", command, re.I)):
            passive.add(match.group(1))
        elif (match := re.fullmatch(r"version\s+(\d)", command, re.I)):
            version = match.group(1)
        else:
            preserved.append(line)
    return ParsedRoutingInstance(family="rip", fields={"address_family": "IPV4", "enabled": True, "rip_version": version,
                                                       "_networks": networks, "_passive_interfaces": passive},
                                 preserved_lines=preserved)


def classful_length(address: str) -> int:
    first = int(address.split(".")[0])
    return 8 if first < 128 else 16 if first < 192 else 24


def _bgp_network(value: str, rest: list[str]) -> str:
    """IOS XE omits ``mask`` when it equals the classful mask (``network 203.0.113.0`` is a /24)."""
    if len(rest) == 2 and rest[0].lower() == "mask":
        return str(ipaddress.ip_network(f"{value}/{rest[1]}", strict=False))
    if not rest:
        return str(ipaddress.ip_network(value if "/" in value or ":" in value else f"{value}/{classful_length(value)}", strict=False))
    raise ValueError(value)


def _parse_bgp(block: list[str]) -> ParsedRoutingInstance | None:
    header = block[0].split()
    if len(header) < 3 or not header[2].isdigit():
        return None
    fields = {"local_asn": int(header[2]), "router_id": ""}
    neighbors: dict[str, dict] = {}
    networks, preserved, current = [], [], ""
    # ``bgp default ipv4-unicast`` is IOS XE's default: a neighbor is active for IPv4 unless the process says
    # ``no bgp default ipv4-unicast`` or its IPv4 section holds ``no neighbor X activate`` (displayed for an IPv6 peer).
    default_v4 = not any(line.strip().lower() == "no bgp default ipv4-unicast" for line in block[1:])
    explicit_v4: dict[str, bool] = {}
    for line in block[1:]:
        command = re.sub(r"^(neighbor\s+)(\S+)", lambda m: m.group(1) + (str(ipaddress.ip_address(m.group(2)))
                         if _is_ip(m.group(2)) else m.group(2)), line.strip(), flags=re.I)
        lower = command.lower()
        tokens = command.split()
        if (match := re.fullmatch(r"bgp router-id\s+(\S+)", command, re.I)):
            fields["router_id"] = match.group(1)
        elif (match := re.fullmatch(r"address-family\s+(ipv4|ipv6)(?:\s+unicast)?", lower)):
            current = match.group(1).upper()
        elif lower == "exit-address-family":
            current = ""
        elif (match := re.fullmatch(r"neighbor\s+(\S+)\s+remote-as\s+(\d+)", command, re.I)):
            peer = str(ipaddress.ip_address(match.group(1))) if _is_ip(match.group(1)) else match.group(1)
            neighbors[peer] = {"peer_address": peer, "remote_asn": int(match.group(2)), "description": "",
                               "activate_ipv4": False, "activate_ipv6": False, "update_source_interface": "",
                               "ebgp_multihop": None, "next_hop_self": False, "route_reflector_client": False, "shutdown": False}
        elif (match := re.fullmatch(r"neighbor\s+(\S+)\s+description\s+(.+)", command, re.I)) and match.group(1) in neighbors:
            neighbors[match.group(1)]["description"] = match.group(2)
        elif (match := re.fullmatch(r"neighbor\s+(\S+)\s+update-source\s+(\S+)", command, re.I)) and match.group(1) in neighbors:
            neighbors[match.group(1)]["update_source_interface"] = match.group(2)
        elif (match := re.fullmatch(r"neighbor\s+(\S+)\s+ebgp-multihop\s+(\d+)", command, re.I)) and match.group(1) in neighbors:
            neighbors[match.group(1)]["ebgp_multihop"] = int(match.group(2))
        elif lower == "no bgp default ipv4-unicast":
            continue
        elif (match := re.fullmatch(r"no\s+neighbor\s+(\S+)\s+activate", command, re.I)) and current:
            peer = str(ipaddress.ip_address(match.group(1))) if _is_ip(match.group(1)) else match.group(1)
            if peer in neighbors:
                if current == "IPV4":
                    explicit_v4[peer] = False
                else:
                    neighbors[peer]["activate_ipv6"] = False
            else:
                preserved.append(line)
        elif (match := re.fullmatch(r"neighbor\s+(\S+)\s+(activate|next-hop-self|route-reflector-client|shutdown)", command, re.I)) \
                and match.group(1) in neighbors:
            peer, action = match.group(1), match.group(2).lower()
            if action == "activate" and current == "IPV4":
                explicit_v4[peer] = True
            elif action == "activate" and current:
                neighbors[peer][f"activate_{current.lower()}"] = True
            elif action != "activate":
                neighbors[peer][action.replace("-", "_")] = True
            else:
                preserved.append(line)
        elif tokens[:1] == ["network"] and current and len(tokens) >= 2:
            try:
                networks.append({"family": current, "cidr": _bgp_network(tokens[1], tokens[2:])})
            except ValueError:
                preserved.append(line)
        else:
            preserved.append(line)
    for peer, neighbor in neighbors.items():
        neighbor["activate_ipv4"] = explicit_v4.get(peer, default_v4)
    return ParsedRoutingInstance(family="bgp", fields=fields, neighbors=list(neighbors.values()), networks=networks,
                                 preserved_lines=preserved)


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def _ospf_lines(block: list[str]) -> tuple[list[str], list[dict]]:
    """Split an interface block into the lines the interface parser reads and its OSPF bindings.

    IOS XE prints ``ip ospf network point-to-point`` BEFORE ``ip ospf N area A``: the cost / network type of a version
    belong to that version's binding wherever they appear in the block."""
    kept, bindings, attributes = [], [], {"OSPFV2": {}, "OSPFV3": {}}
    for line in block:
        if (match := _OSPF_INTERFACE.match(line)):
            bindings.append({"version": "OSPFV3" if match.group(1).lower() == "ipv6" else "OSPFV2",
                             "process_id": int(match.group(2)), "area": match.group(3)})
        elif (match := _OSPF_COST.match(line)):
            attributes["OSPFV3" if match.group(1).lower() == "ipv6" else "OSPFV2"]["cost"] = int(match.group(2))
        elif (match := _OSPF_P2P.match(line)):
            attributes["OSPFV3" if match.group(1).lower() == "ipv6" else "OSPFV2"]["network_type"] = "POINT_TO_POINT"
        else:
            kept.append(line)
    for binding in bindings:
        binding.update(attributes[binding["version"]])
    return kept, bindings


def _in_classful(cidr: str, network: str) -> bool:
    try:
        address = ipaddress.ip_interface(cidr)
        first = int(network.split(".")[0])
        length = 8 if first < 128 else 16 if first < 192 else 24
        return address.version == 4 and address.ip in ipaddress.ip_network(f"{network}/{length}", strict=False)
    except ValueError:
        return False


def _finalize(result: ParsedConfig) -> None:
    ospf = {(i.fields["version"], i.fields["process_id"]): i for i in result.routing_instances if i.family == "ospf"}
    for interface in result.interfaces:
        for binding in interface.ospf_bindings:
            instance = ospf.get((binding["version"], binding["process_id"]))
            if instance is not None:
                instance.bindings.append({"interface_name": interface.name, **binding})
    for instance in result.routing_instances:
        passive = instance.fields.pop("_passive_interfaces", set())
        if instance.family == "rip":
            for network in instance.fields.pop("_networks", []):
                instance.networks.append({"prefix": network})
                for interface in result.interfaces:
                    if any(_in_classful(a["cidr"], network) for a in interface.addresses) \
                            and not any(b["interface_name"] == interface.name for b in instance.bindings):
                        instance.bindings.append({"interface_name": interface.name, "passive": interface.name in passive})
        else:
            for binding in instance.bindings:
                binding["passive"] = binding.get("interface_name") in passive


def parse(text: str) -> ParsedConfig:
    result = ParsedConfig(parser_version=PARSER_VERSION)
    for block in _blocks(text):
        first, lower = block[0], block[0].lower()
        if lower.startswith("hostname "):
            result.hostname = first.split(None, 1)[1]
            continue
        if lower.startswith("interface "):
            # The interface hierarchy is shared with the XR subset except for
            # IOS XE's `ip address` keyword.  Reuse that strict parser after an
            # exact lexical translation; no routing syntax is conflated.
            block, ospf_bindings = _ospf_lines(block)
            translated = [block[0]]
            for line in block[1:]:
                translated.append(re.sub(r"^(\s*)ip address\s+", r"\1ipv4 address ", line, flags=re.I))
            parsed = parser_iosxr.parse("\n".join(translated))
            if parsed.interfaces:
                parsed.interfaces[0].ospf_bindings.extend(ospf_bindings)
                result.interfaces.extend(parsed.interfaces)
            else:
                result.unmanaged_blocks.append(UnmanagedBlock(f"Interface {first.split(None, 1)[1]}", "RECOGNIZED_UNSUPPORTED", block))
            continue
        route = _static_route(first)
        if route is not None:
            result.static_routes.append(route)
            continue
        instance = None
        if re.fullmatch(r"(ipv6 )?router ospf \d+", lower):
            instance = _parse_ospf(block)
        elif lower == "router rip":
            instance = _parse_rip(block)
        elif re.fullmatch(r"router bgp \d+", lower):
            instance = _parse_bgp(block)
        if instance is not None:
            result.routing_instances.append(instance)
            continue
        label = "IOS XE configuration outside the verified import subset"
        result.unmanaged_blocks.append(UnmanagedBlock(label, "RECOGNIZED_UNSUPPORTED", block))
    _finalize(result)
    return result
