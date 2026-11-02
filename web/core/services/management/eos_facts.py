"""Arista EOS running-configuration FACTS for management verification (L2) and management-VRF import / read-back.

Indentation-aware (EOS nests ``management ssh / vrf X / no shutdown`` three levels deep).  Only the facts management needs
are extracted; user secrets are never read (a ``username`` line yields the account NAME and whether it has an ssh-key, never
the secret or key material).  Unknown syntax is ignored, never guessed.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field

ALL_VLANS = frozenset(range(1, 4095))


@dataclass
class InterfaceFacts:
    name: str
    mode: str = "ACCESS"                 # ACCESS | TRUNK | ROUTED | SVI | MANAGEMENT | LOOPBACK | SUBINTERFACE
    access_vlan: int = 1
    trunk_vlans: frozenset = ALL_VLANS
    vrf: str = ""
    addresses: list = field(default_factory=list)    # CIDR strings, IPv4 and IPv6
    shutdown: bool = False
    lines: list = field(default_factory=list)

    def carries_vlan(self, vlan: int) -> tuple[bool, bool]:
        """-> (carried, tagged)."""
        if self.mode == "ACCESS":
            return self.access_vlan == vlan, False
        if self.mode == "TRUNK":
            return vlan in self.trunk_vlans, True
        return False, False

    def holds(self, address: str) -> bool:
        return any(str(ipaddress.ip_interface(cidr).ip) == str(ipaddress.ip_address(address)) for cidr in self.addresses)


@dataclass
class EosFacts:
    hostname: str = ""
    spanning_tree_mode: str = "mstp"      # EOS default when no ``spanning-tree mode`` line is present
    interfaces: dict = field(default_factory=dict)
    vrfs: dict = field(default_factory=dict)          # name -> {"description": str, "lines": [...]}
    ip_routing: set = field(default_factory=set)      # VRF names with ``ip routing vrf X`` ("default" for plain ``ip routing``)
    ipv6_routing: set = field(default_factory=set)
    routes: list = field(default_factory=list)        # {"vrf", "family", "prefix", "next_hop", "line"}
    services: dict = field(default_factory=dict)      # {"ssh": {vrf: enabled}, "http-commands": {...}, "gnmi": {...}}
    logging_vrfs: list = field(default_factory=list)  # {"vrf", "host", "line"}
    ntp_vrfs: list = field(default_factory=list)
    snmp_vrfs: list = field(default_factory=list)
    usernames: dict = field(default_factory=dict)     # name -> {"has_ssh_key": bool}

    def interface_holding(self, address: str) -> InterfaceFacts | None:
        return next((iface for iface in self.interfaces.values() if iface.holds(address)), None)

    def management_vlan_ports(self, vlan: int) -> list[str]:
        return sorted(name for name, iface in self.interfaces.items()
                      if iface.mode in ("ACCESS", "TRUNK") and not iface.shutdown and iface.carries_vlan(vlan)[0])


def _tree(text: str) -> list[dict]:
    """[{"line": str, "indent": int, "children": [...]}] -- EOS nests with spaces; '!' and blank lines are separators."""
    root: list[dict] = []
    stack: list[tuple[int, list]] = [(-1, root)]
    for raw in (text or "").splitlines():
        if not raw.strip() or raw.strip().startswith("!"):
            continue
        indent = len(raw) - len(raw.lstrip(" "))
        node = {"line": raw.strip(), "indent": indent, "children": []}
        while stack and stack[-1][0] >= indent:
            stack.pop()
        stack[-1][1].append(node)
        stack.append((indent, node["children"]))
    return root


def _vlan_set(value: str) -> frozenset:
    value = value.strip().lower()
    if value in ("all", ""):
        return ALL_VLANS
    if value == "none":
        return frozenset()
    result: set[int] = set()
    for token in value.split(","):
        token = token.strip()
        if "-" in token:
            start, end = token.split("-", 1)
            if start.isdigit() and end.isdigit():
                result.update(range(int(start), int(end) + 1))
        elif token.isdigit():
            result.add(int(token))
    return frozenset(result)


def _interface(node: dict) -> InterfaceFacts:
    name = node["line"].split(None, 1)[1].strip()
    lower = name.lower()
    facts = InterfaceFacts(name=name, lines=[child["line"] for child in node["children"]])
    if lower.startswith("management"):
        facts.mode = "MANAGEMENT"
    elif lower.startswith("loopback"):
        facts.mode = "LOOPBACK"
    elif re.fullmatch(r"vlan\d+", lower):
        facts.mode = "SVI"
    elif "." in name:
        facts.mode = "SUBINTERFACE"
    commands = [line.lower() for line in facts.lines]
    if facts.mode == "ACCESS":
        if "no switchport" in commands:
            facts.mode = "ROUTED"
        elif "switchport mode trunk" in commands:
            facts.mode = "TRUNK"
    for command, original in zip(commands, facts.lines):
        if command == "shutdown":
            facts.shutdown = True
        elif command == "no shutdown":
            facts.shutdown = False
        elif (match := re.fullmatch(r"switchport access vlan (\d+)", command)):
            facts.access_vlan = int(match.group(1))
        elif (match := re.fullmatch(r"switchport trunk allowed vlan (?:add )?(.+)", command)):
            facts.trunk_vlans = _vlan_set(match.group(1))
        elif (match := re.fullmatch(r"vrf (?:forwarding )?(\S+)", command)):
            facts.vrf = original.split()[-1]
        elif (match := re.fullmatch(r"(?:ip|ipv6) address (\S+)(?: secondary)?", command)) and "/" in match.group(1):
            try:
                facts.addresses.append(str(ipaddress.ip_interface(match.group(1))))
            except ValueError:
                pass
    return facts


def _service_vrfs(node: dict) -> dict:
    """``management ssh`` / ``management api http-commands`` / ``management api gnmi`` -> {vrf: enabled}.

    ssh: enabled in the default VRF unless ``shutdown``; in VRF X when ``vrf X`` holds ``no shutdown``.
    http-commands: enabled in the default VRF only with ``no shutdown``; in VRF X when ``vrf X`` holds ``no shutdown``.
    gnmi: ``transport grpc <name>`` is enabled in its ``vrf X`` (or the default VRF) unless ``shutdown``.
    """
    kind = node["line"].lower().split()[-1]
    children = node["children"]
    top = [c["line"].lower() for c in children]
    result: dict = {}
    if kind == "ssh":
        result["default"] = "shutdown" not in top
    elif kind == "http-commands":
        result["default"] = "no shutdown" in top
    for child in children:
        lower = child["line"].lower()
        inner = [g["line"].lower() for g in child["children"]]
        if lower.startswith("vrf ") and kind in ("ssh", "http-commands"):
            result[child["line"].split()[1]] = "no shutdown" in inner
        elif lower.startswith("transport grpc ") and kind == "gnmi":
            vrf = next((g["line"].split()[1] for g in child["children"] if g["line"].lower().startswith("vrf ")), "default")
            result[vrf] = "shutdown" not in inner
    return result


def parse(text: str) -> EosFacts:
    facts = EosFacts()
    for node in _tree(text):
        line = node["line"]
        lower = line.lower()
        if (match := re.fullmatch(r"hostname (\S+)", line)):
            facts.hostname = match.group(1)
        elif (match := re.fullmatch(r"spanning-tree mode (\S+)", lower)):
            facts.spanning_tree_mode = match.group(1)
        elif lower.startswith("interface "):
            iface = _interface(node)
            facts.interfaces[iface.name] = iface
        elif (match := re.fullmatch(r"vrf instance (\S+)", line)):
            facts.vrfs[match.group(1)] = {"lines": [c["line"] for c in node["children"]],
                                          "description": next((c["line"].split(None, 1)[1] for c in node["children"]
                                                               if c["line"].lower().startswith("description ")), "")}
        elif lower == "ip routing":
            facts.ip_routing.add("default")
        elif (match := re.fullmatch(r"ip routing vrf (\S+)", line)):
            facts.ip_routing.add(match.group(1))
        elif lower == "ipv6 unicast-routing":
            facts.ipv6_routing.add("default")
        elif (match := re.fullmatch(r"ipv6 unicast-routing vrf (\S+)", line)):
            facts.ipv6_routing.add(match.group(1))
        elif (match := re.fullmatch(r"(ip|ipv6) route (?:vrf (\S+) )?(\S+) (\S+).*", line)):
            facts.routes.append({"vrf": match.group(2) or "default", "family": "IPV6" if match.group(1) == "ipv6" else "IPV4",
                                 "prefix": match.group(3), "next_hop": match.group(4), "line": line})
        elif lower in ("management ssh", "management api http-commands", "management api gnmi"):
            facts.services[lower.split()[-1]] = _service_vrfs(node)
        elif (match := re.fullmatch(r"logging vrf (\S+) host (\S+).*", line)):
            facts.logging_vrfs.append({"vrf": match.group(1), "host": match.group(2), "line": line})
        elif (match := re.fullmatch(r"ntp server vrf (\S+) (\S+).*", line)):
            facts.ntp_vrfs.append({"vrf": match.group(1), "server": match.group(2), "line": line})
        elif (match := re.fullmatch(r"snmp-server vrf (\S+).*", line)):
            facts.snmp_vrfs.append({"vrf": match.group(1), "line": line})
        elif (match := re.fullmatch(r"username (\S+)(.*)", line)):
            entry = facts.usernames.setdefault(match.group(1), {"has_ssh_key": False})
            if " ssh-key " in f" {match.group(2)} " or match.group(2).strip().startswith("ssh-key"):
                entry["has_ssh_key"] = True
    return facts


def hostname_from_show(text: str) -> str:
    """``show hostname`` -> the hostname (``Hostname: R1`` / ``FQDN: R1``)."""
    for line in (text or "").splitlines():
        match = re.match(r"\s*Hostname:\s*(\S+)", line)
        if match:
            return match.group(1)
    return ""


def serial_from_show_version(text: str) -> str:
    for line in (text or "").splitlines():
        match = re.match(r"\s*Serial number:\s*(\S+)", line, re.I)
        if match:
            return match.group(1)
    return ""
