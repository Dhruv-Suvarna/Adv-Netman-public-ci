"""Catalyst 8000V / IOS XE running-config parser for the verified NMAS subset.

IOS XE is intentionally separate from IOS XR.  This parser covers identity,
routed/sub/loopback/management interfaces, IPv4/IPv6 addressing, and static
routes.  Other stanzas are preserved as unmanaged until fixture or live
evidence justifies a semantic importer.
"""

from __future__ import annotations

import ipaddress
import re

from . import parser_iosxr
from .schema import ParsedConfig, ParsedStaticRoute, UnmanagedBlock

PARSER_VERSION = "iosxe-1.0"


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
            translated = [block[0]]
            for line in block[1:]:
                translated.append(re.sub(r"^(\s*)ip address\s+", r"\1ipv4 address ", line, flags=re.I))
            parsed = parser_iosxr.parse("\n".join(translated))
            if parsed.interfaces:
                result.interfaces.extend(parsed.interfaces)
            else:
                result.unmanaged_blocks.append(UnmanagedBlock(f"Interface {first.split(None, 1)[1]}", "RECOGNIZED_UNSUPPORTED", block))
            continue
        route = _static_route(first)
        if route is not None:
            result.static_routes.append(route)
            continue
        label = "IOS XE configuration outside the verified import subset"
        result.unmanaged_blocks.append(UnmanagedBlock(label, "RECOGNIZED_UNSUPPORTED", block))
    return result
