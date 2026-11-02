"""Ubuntu/FRR 8.4 running state -> parsed Device Builder import records.

FRR's hierarchical ``vtysh`` configuration, Linux's JSON address inventory,
and nftables are separate authoritative representations.  They are parsed by
this platform-specific module and merged by interface name; EOS parsing is
not reused.  Unknown FRR/nft content remains immutable unmanaged text.
"""

from __future__ import annotations

import ipaddress
import json
import re

from .schema import ParsedConfig, ParsedInterface, ParsedNatRule, ParsedRoutingInstance, ParsedStaticRoute, UnmanagedBlock

PARSER_VERSION = "ubuntu-frr-1.0"
ISIS_TAG = "NMAS44"  # platform_drivers.FRR_ISIS_TAG: only NMAS's named process is imported
_ISIS_LEVELS = {"level-1": "LEVEL_1", "level-2-only": "LEVEL_2", "level-1-2": "LEVEL_1_2"}


def _blocks(text: str) -> list[list[str]]:
    blocks: list[list[str]] = []
    current = None
    for raw in text.splitlines():
        line = raw.rstrip()
        if not line.strip() or line.strip() == "!":
            continue
        if line[0] not in " \t":
            current = [line]
            blocks.append(current)
        elif current is not None:
            current.append(line)
    return blocks


def _kind(name: str) -> tuple[str, dict]:
    if name == "lo" or name.lower().startswith("loopback"):
        return "LOOPBACK", {}
    if match := re.fullmatch(r"vlan(\d+)", name, re.I):
        return "SVI", {"vlan_id": int(match.group(1))}
    if "." in name:
        return "SUBINTERFACE", {"parent_name": name.split(".", 1)[0]}
    if name.lower().startswith("br"):
        return "BRIDGE", {}
    if name.lower().startswith("bond"):
        return "BOND", {}
    return "ROUTED_PHYSICAL", {}


def _linux_interfaces(addr_json: str) -> dict[str, ParsedInterface]:
    try:
        rows = json.loads(addr_json or "[]")
    except (TypeError, json.JSONDecodeError):
        return {}
    result = {}
    for row in rows if isinstance(rows, list) else []:
        name = str(row.get("ifname") or "")
        if not name:
            continue
        kind, extras = _kind(name)
        interface = ParsedInterface(
            name=name, kind=kind, admin_state="ENABLED" if "UP" in (row.get("flags") or []) else "DISABLED",
            mtu=int(row["mtu"]) if str(row.get("mtu", "")).isdigit() else None, **extras,
        )
        for address in row.get("addr_info") or []:
            local, prefixlen = address.get("local"), address.get("prefixlen")
            if local is None or prefixlen is None:
                continue
            interface.addresses.append({
                "family": "IPV6" if ":" in str(local) else "IPV4",
                "cidr": f"{local}/{prefixlen}", "role": "PRIMARY",
            })
        result[name] = interface
    return result


def _parse_interface(block: list[str], interfaces: dict[str, ParsedInterface]) -> None:
    name = block[0].split(None, 1)[1]
    if name not in interfaces:
        kind, extras = _kind(name)
        interfaces[name] = ParsedInterface(name=name, kind=kind, **extras)
    interface = interfaces[name]
    for line in block[1:]:
        command = line.strip(); lower = command.lower()
        if lower == "exit":
            continue
        if lower == "shutdown": interface.admin_state = "DISABLED"
        elif lower == "no shutdown": interface.admin_state = "ENABLED"
        elif lower.startswith("description "): interface.description = command.split(None, 1)[1]
        elif (match := re.fullmatch(r"ip address\s+(\S+)", command, re.I)):
            address = {"family": "IPV4", "cidr": match.group(1), "role": "PRIMARY"}
            if address not in interface.addresses:
                interface.addresses.append(address)
        elif (match := re.fullmatch(r"ipv6 address\s+(\S+)", command, re.I)):
            address = {"family": "IPV6", "cidr": match.group(1), "role": "PRIMARY"}
            if address not in interface.addresses:
                interface.addresses.append(address)
        elif (match := re.fullmatch(r"ip ospf area\s+(\S+)", command, re.I)):
            interface.ospf_bindings.append({"version": "OSPFV2", "process_id": None, "area": match.group(1)})
        elif (match := re.fullmatch(r"ipv6 ospf6 area\s+(\S+)", command, re.I)):
            interface.ospf_bindings.append({"version": "OSPFV3", "process_id": None, "area": match.group(1)})
        elif (match := re.fullmatch(r"ip ospf cost\s+(\d+)", command, re.I)):
            for binding in interface.ospf_bindings[-1:]: binding["cost"] = int(match.group(1))
        elif (match := re.fullmatch(r"ipv6 ospf6 cost\s+(\d+)", command, re.I)):
            for binding in interface.ospf_bindings[-1:]: binding["cost"] = int(match.group(1))
        elif command in {f"ip router isis {ISIS_TAG}", f"ipv6 router isis {ISIS_TAG}"}:
            if not interface.isis_bindings:
                interface.isis_bindings.append({"passive": False, "metric": None,
                                                "address_family_ipv4": False, "address_family_ipv6": False})
            interface.isis_bindings[0]["address_family_ipv6" if command.startswith("ipv6 ") else "address_family_ipv4"] = True
        elif lower == "isis passive" and interface.isis_bindings:
            interface.isis_bindings[0]["passive"] = True
        elif (match := re.fullmatch(r"isis metric\s+(\d+)", lower)) and interface.isis_bindings:
            interface.isis_bindings[0]["metric"] = int(match.group(1))
        elif lower in {"isis network point-to-point", "isis circuit-type level-2-only", "isis circuit-type level-1",
                       "isis circuit-type level-1-2"} and interface.isis_bindings:
            pass
        else:
            interface.preserved_lines.append(line)


def _parse_ospf(block: list[str], version: str) -> ParsedRoutingInstance:
    fields = {"version": version, "process_id": None, "router_id": ""}; preserved, networks = [], []
    prefix = "ospf6" if version == "OSPFV3" else "ospf"
    for line in block[1:]:
        command = line.strip()
        if command.lower() == "exit": continue
        if match := re.fullmatch(prefix + r" router-id\s+(\S+)", command, re.I): fields["router_id"] = match.group(1)
        elif version == "OSPFV2" and (match := re.fullmatch(r"network\s+(\S+)\s+area\s+(\S+)", command, re.I)):
            try: networks.append({"prefix": str(ipaddress.ip_network(match.group(1), strict=False)), "area": match.group(2)})
            except ValueError: preserved.append(line)
        else: preserved.append(line)
    return ParsedRoutingInstance(family="ospf", fields=fields, networks=networks, preserved_lines=preserved)


def _parse_rip(block: list[str], family: str) -> ParsedRoutingInstance:
    bindings = []
    by_name = {}
    preserved = []
    for line in block[1:]:
        command = line.strip()
        if command.lower() in {"exit", "version 2"}:
            continue
        if match := re.fullmatch(r"network\s+(\S+)", command, re.I):
            name = match.group(1)
            # Prefix/network statements do not map safely to the canonical
            # interface binding model; retain those verbatim.
            if "/" in name or re.match(r"^\d+\.\d+\.\d+\.\d+$", name):
                preserved.append(line)
            else:
                binding = {"interface_name": name, "passive": False}
                bindings.append(binding); by_name[name] = binding
        elif match := re.fullmatch(r"passive-interface\s+(\S+)", command, re.I):
            if match.group(1) in by_name:
                by_name[match.group(1)]["passive"] = True
            else:
                preserved.append(line)
        else:
            preserved.append(line)
    return ParsedRoutingInstance(
        family="rip", fields={"address_family": family, "enabled": True},
        bindings=bindings, preserved_lines=preserved,
    )


def _parse_isis(block: list[str]) -> ParsedRoutingInstance:
    fields = {"net": "", "level": "LEVEL_1_2", "address_family_ipv4": False, "address_family_ipv6": False}
    preserved = []
    for line in block[1:]:
        command = line.strip().lower()
        if match := re.fullmatch(r"net\s+(\S+)", command):
            fields["net"] = match.group(1)
        elif match := re.fullmatch(r"is-type\s+(\S+)", command):
            if match.group(1) in _ISIS_LEVELS:
                fields["level"] = _ISIS_LEVELS[match.group(1)]
            else:
                preserved.append(line)
        elif command == "metric-style wide":
            continue
        else:
            preserved.append(line)
    return ParsedRoutingInstance(family="isis", fields=fields, preserved_lines=preserved)


def _parse_bgp(block: list[str]) -> ParsedRoutingInstance | None:
    header = block[0].split()
    if len(header) < 3 or not header[2].isdigit(): return None
    fields = {"local_asn": int(header[2]), "router_id": ""}; neighbors = {}; networks = []; preserved = []; af = ""
    explicit = set(); default_v4 = True
    for line in block[1:]:
        command = line.strip(); lower = command.lower()
        if lower == "exit": continue
        if match := re.fullmatch(r"bgp router-id\s+(\S+)", command, re.I): fields["router_id"] = match.group(1)
        elif lower == "no bgp default ipv4-unicast": default_v4 = False; preserved.append(line)
        elif match := re.fullmatch(r"neighbor\s+(\S+)\s+remote-as\s+(\d+)", command, re.I):
            peer = match.group(1); neighbors[peer] = {"peer_address": peer, "remote_asn": int(match.group(2)),
                "description": "", "activate_ipv4": False, "activate_ipv6": False, "update_source_interface": "",
                "ebgp_multihop": None, "next_hop_self": False, "route_reflector_client": False, "shutdown": False}
        elif match := re.fullmatch(r"address-family\s+(ipv4|ipv6)\s+unicast", lower): af = match.group(1).upper()
        elif lower == "exit-address-family": af = ""
        elif match := re.fullmatch(r"neighbor\s+(\S+)\s+activate", command, re.I):
            if match.group(1) in neighbors and af:
                neighbors[match.group(1)][f"activate_{af.lower()}"] = True; explicit.add((match.group(1), af))
        elif match := re.fullmatch(r"no neighbor\s+(\S+)\s+activate", command, re.I):
            if match.group(1) in neighbors and af:
                neighbors[match.group(1)][f"activate_{af.lower()}"] = False; explicit.add((match.group(1), af))
            else: preserved.append(line)
        elif match := re.fullmatch(r"neighbor\s+(\S+)\s+next-hop-self", command, re.I):
            if match.group(1) in neighbors: neighbors[match.group(1)]["next_hop_self"] = True
        elif match := re.fullmatch(r"network\s+(\S+)", command, re.I):
            if af: networks.append({"family": af, "cidr": match.group(1)})
            else: preserved.append(line)
        else: preserved.append(line)
    # FRR activates every neighbor for IPv4 unicast unless the process says otherwise; running-config omits the default.
    for peer, row in neighbors.items():
        if default_v4 and (peer, "IPV4") not in explicit: row["activate_ipv4"] = True
    return ParsedRoutingInstance(family="bgp", fields=fields, neighbors=list(neighbors.values()), networks=networks,
                                 preserved_lines=preserved)


def _parse_static(block: list[str], family: str) -> ParsedStaticRoute | None:
    tokens = block[0].split()
    if len(tokens) < 4: return None
    route = ParsedStaticRoute(family=family, destination=tokens[2], lines=block)
    next_hop = tokens[3]
    if re.fullmatch(r"[0-9A-Fa-f:.]+", next_hop): route.next_hop_address = next_hop
    else: route.next_hop_interface = next_hop
    if len(tokens) > 4 and tokens[4].isdigit(): route.distance = int(tokens[4])
    return route


NAT_STATEFUL_COMMENT = "nmas-nat44-stateful"   # platform_drivers.NAT_STATEFUL_COMMENT (kept equal by test)


def _static_nat_pairs(text: str) -> list:
    """Static NAT44 mappings of every exact NMAS static table (executor shape) in a listed ruleset."""
    from ..execution.executors.linux import parse_static_nat_table   # the one definition of the shape

    lines, found = text.splitlines(), []
    for start, line in enumerate(lines):
        if re.fullmatch(r"table ip [A-Za-z0-9_]{1,32} \{", line):
            end = next((i for i in range(start + 1, len(lines)) if lines[i].startswith("}")), None)
            table = parse_static_nat_table(lines[start:end + 1]) if end is not None else None
            if table:
                found.extend((rule, lines[start:end + 1]) for rule in table["rules"])
    return found


def _parse_nft(text: str, result: ParsedConfig) -> None:
    recognized = []
    for (oif, inside, glob), block in _static_nat_pairs(text):
        result.nat_rules.append(ParsedNatRule(mode="STATIC", original_source=inside, translated_source=glob,
                                              outside_interface=oif, lines=[line for line in block if inside in line]))
    for line in text.splitlines():
        match = re.search(r'oifname\s+"([^"]+)"\s+ip saddr\s+(\S+)\s+masquerade(?:\s+comment\s+"([^"]*)")?\s*$', line.strip())
        if match and match.group(3) in (None, NAT_STATEFUL_COMMENT):   # a foreign comment is not an NMAS rule shape
            result.nat_rules.append(ParsedNatRule(mode="STATEFUL" if match.group(3) else "PAT", original_source=match.group(2),
                                                  outside_interface=match.group(1), lines=[line]))
            recognized.append(line)
    # nft often contains Docker-owned rules alongside the managed EDGE_PAT
    # table. Preserve the complete source when any text remains so no direct
    # nft/iptables change can disappear during supported-intent editing.
    if text.strip():
        result.unmanaged_blocks.append(UnmanagedBlock(
            "Complete nftables ruleset (immutable source; recognized PAT rules imported separately)",
            "RECOGNIZED_UNSUPPORTED", text.splitlines(),
        ))


def _classify_management(interfaces: dict[str, ParsedInterface], management_addresses) -> None:
    """The plain physical interface that carries the address the device is managed through is its management port.

    Linux has no management interface type, so the name says nothing.  Only an interface that would otherwise be an
    ordinary routed physical port is reclassified: an SVI, subinterface, bridge, bond or loopback that happens to hold the
    management address (the in-band VLAN200 model of the production routers) keeps its kind.
    """
    wanted = set()
    for value in management_addresses or ():
        try:
            wanted.add(ipaddress.ip_address(str(value).split("/")[0]))
        except ValueError:
            continue
    for interface in interfaces.values():
        if interface.kind != "ROUTED_PHYSICAL":
            continue
        held = set()
        for address in interface.addresses:
            try:
                held.add(ipaddress.ip_interface(address["cidr"]).ip)
            except ValueError:
                continue
        if wanted & held:
            interface.kind = "MANAGEMENT"


def parse(frr_text: str, *, addr_json: str = "", nft_text: str = "", management_addresses=()) -> ParsedConfig:
    result = ParsedConfig(parser_version=PARSER_VERSION)
    interfaces = _linux_interfaces(addr_json)
    _classify_management(interfaces, management_addresses)
    for block in _blocks(frr_text):
        first = block[0]; lower = first.lower()
        if match := re.fullmatch(r"hostname\s+(\S+)", first, re.I): result.hostname = match.group(1)
        elif lower.startswith("interface "): _parse_interface(block, interfaces)
        elif lower == "router ospf": result.routing_instances.append(_parse_ospf(block, "OSPFV2"))
        elif lower == "router ospf6": result.routing_instances.append(_parse_ospf(block, "OSPFV3"))
        elif lower == f"router isis {ISIS_TAG.lower()}": result.routing_instances.append(_parse_isis(block))
        elif lower == "router rip": result.routing_instances.append(_parse_rip(block, "IPV4"))
        elif lower == "router ripng": result.routing_instances.append(_parse_rip(block, "IPV6"))
        elif lower.startswith("router bgp "):
            bgp = _parse_bgp(block)
            if bgp: result.routing_instances.append(bgp)
        elif lower.startswith(("ip route ", "ipv6 route ")):
            route = _parse_static(block, "IPV6" if lower.startswith("ipv6") else "IPV4")
            if route: result.static_routes.append(route)
        elif lower in {"building configuration...", "current configuration:", "end"}:
            continue
        else:
            result.unmanaged_blocks.append(UnmanagedBlock(
                f"Unmanaged FRR configuration ({first.split()[0] if first.split() else 'empty'})", "UNKNOWN", block,
            ))
    result.interfaces = sorted(interfaces.values(), key=lambda row: row.name)
    ospf = {(row.fields["version"], row.fields.get("process_id")): row for row in result.routing_instances if row.family == "ospf"}
    for interface in result.interfaces:
        for binding in interface.ospf_bindings:
            instance = ospf.get((binding["version"], binding.get("process_id")))
            if instance: instance.bindings.append({"interface_name": interface.name, **binding})
        for binding in interface.isis_bindings:
            instance = next((row for row in result.routing_instances if row.family == "isis"), None)
            if instance:
                instance.bindings.append({"interface_name": interface.name, **binding})
                instance.fields["address_family_ipv4"] |= binding["address_family_ipv4"]
                instance.fields["address_family_ipv6"] |= binding["address_family_ipv6"]
    _parse_nft(nft_text, result)
    return result
