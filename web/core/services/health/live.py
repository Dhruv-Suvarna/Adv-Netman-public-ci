"""Deep-Health live adapters: SAFE, READ-ONLY, allowlisted, server-owned.

This is the ONLY health module that may open a device session or spawn a process.  Guarantees (each is asserted by a
contract test and by ``_assert_read_only`` at import time):

* The commands are the fixed tables ``CEOS_COMMANDS`` / ``LINUX_COMMANDS`` below.  Nothing from a browser, a plan or
  a Configlet is ever concatenated into a command; a session runs a command only by its allowlist KEY.
* Every cEOS command is a ``show`` command; every Linux/FRR command is ``ip -j ... show|route show``, ``vtysh -c
  "show ..."`` or ``nft list ruleset``.  No configuration mode, write, clear, reload, restart, save, commit or shell
  is ever entered (no ``send_config*``, ``config_mode``, ``save_config``, ``shell=True``).
* cEOS reuses the Phase-7 pattern of ``nsot_live`` (Netmiko, inventory-sourced target, privileged-EXEC only).  Linux/FRR
  routers use ``docker exec <container> <fixed argv>`` -- the credential-free read pattern the monitoring layer
  (``modules/snmp.py``) and ``netbox/scripts/verify_dhcp_servers.py`` already use.
* Every connection/command has a finite timeout and is always closed; failures become a SANITIZED reason code
  (never an exception text, which could echo connection parameters).
* Raw output is parsed in memory into normalized facts and then dropped: it is never persisted or logged.
"""

from __future__ import annotations

import ipaddress
import json
import re
import subprocess
from datetime import datetime
from types import MappingProxyType

from django.conf import settings

from .. import nsot_live
from ..management.eos_facts import parse as parse_management_config
from .codes import Capability
from .evidence import DeviceEvidence, FactGroup, unavailable
from .results import utcnow

SOURCE = "LIVE"
MAX_OUTPUT_BYTES = 2_000_000

LIVE_ERRORS = MappingProxyType({
    "NOT_SUPPORTED": "Live read-only queries are not implemented for this platform.",
    "NOT_CONFIGURED": "No live access target is configured for this device.",
    "CREDENTIAL_NOT_CONFIGURED": "No usable automation credential for this device is available to the server.",
    "MANAGEMENT_UNREACHABLE": "Management paths are registered for this device but none is currently usable (V2 Phase 4 selector).",
    "TIMEOUT": "The device did not respond within the timeout.",
    "AUTH_FAILED": "The device rejected the configured credentials.",
    "CONNECTION_FAILED": "The device could not be reached.",
    "DOCKER_UNAVAILABLE": "The container runtime is not available to the server.",
    "COMMAND_FAILED": "A read-only command did not complete.",
    "PARSE_ERROR": "A command's output could not be interpreted.",
    "OUTPUT_TOO_LARGE": "A command's output exceeded the size bound.",
    "COMMAND_NOT_ALLOWED": "The requested command is not in the read-only allowlist.",
    "INVALID_DESTINATION": "The requested destination is not a valid IP address.",
})


class LiveError(Exception):
    """A sanitized live-read failure: only ``code`` ever leaves this module."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code if code in LIVE_ERRORS else "COMMAND_FAILED"


# --- platform capability (independent of configuration support) --------------------------------------------------
HEALTH_CAPABILITIES = MappingProxyType({
    "ceos": {"status": Capability.SUPPORTED, "transport": "netmiko-ssh",
             "evidence": "Phase-7 nsot_live pattern; master.py verify_eos() show commands; live-verified on the approved baseline.",
             "groups": ("interfaces", "addresses", "virtual_addresses", "routes", "ospf", "isis", "rip_neighbors", "bgp", "config", "config_paths",
                        "routing_config", "management_services")},
    "linux": {"status": Capability.SUPPORTED, "transport": "docker-exec",
              "evidence": "modules/snmp.py + verify_dhcp_servers.py docker-exec pattern; master.py verify_linux_router() reads.",
              "groups": ("interfaces", "addresses", "routes", "ospf", "isis", "bgp", "rip", "nat", "routing_config")},
    "nokia_srlinux": {"status": Capability.SUPPORTED, "transport": "gnmi-get",
                      "evidence": "gNMI Get of structured state, verified on an isolated SR Linux 24.10.7 node (not part of the approved Labs 2/3 baseline).",
                      "groups": ("interfaces", "addresses", "routes", "ospf", "bgp", "routing_config", "config")},
    "cisco_c8000v_iosxe": {"status": Capability.SUPPORTED, "transport": "netmiko-ssh",
                           "evidence": "Allowlisted show commands, verified on an isolated Catalyst 8000V / IOS XE 17.06.01a (not part of the approved Labs 2/3 baseline).",
                           "groups": ("interfaces", "addresses", "routes")},
    "cisco_iosxr": {"status": Capability.NOT_IMPLEMENTED, "transport": "", "evidence": "No repository evidence of an IOS XR read-only session.", "groups": ()},
    "sonic": {"status": Capability.NOT_IMPLEMENTED, "transport": "", "evidence": "No repository evidence of a read-only session for SONiC.", "groups": ()},
})


def get_capability(platform: str) -> dict:
    """The health capability of a platform key; an unrecognised platform is UNKNOWN, never assumed supported."""
    found = HEALTH_CAPABILITIES.get(platform)
    if found is None:
        return {"status": Capability.UNKNOWN, "transport": "", "evidence": "Platform not recognised by the health engine.", "groups": ()}
    return dict(found)


# --- the fixed command allowlists (the ONLY commands this module can send) ---------------------------------------
CEOS_COMMANDS = MappingProxyType({
    "interfaces": "show interfaces | json",
    "ip_interfaces": "show ip interface | json",
    "ipv6_interfaces": "show ipv6 interface | json",
    "ip_routes": "show ip route | json",
    "ipv6_routes": "show ipv6 route | json",
    "ospf": "show ip ospf neighbor | json",
    "ospf3": "show ipv6 ospf neighbor | json",
    "isis": "show isis neighbors | json",
    "rip_neighbors": "show ip rip neighbors",   # text only: cEOS 4.36.2F answers "unconverted command" to "| json"
    "bgp": "show ip bgp summary | json",
    "bgp6": "show ipv6 bgp summary | json",
    "running_config": "show running-config",
    "version": "show version | json",                       # V2 Phase 8 dynamic telemetry (memTotal / memFree / uptime)
    "interface_counters": "show interfaces counters | json",  # V2 Phase 8 dynamic telemetry (in/out octets, discards)
})
LINUX_COMMANDS = MappingProxyType({
    "addr": ("ip", "-j", "addr", "show"),
    "route4": ("ip", "-j", "-4", "route", "show"),
    "route6": ("ip", "-j", "-6", "route", "show"),
    "ospf": ("vtysh", "-c", "show ip ospf neighbor json"),
    "ospf6": ("vtysh", "-c", "show ipv6 ospf6 neighbor json"),
    "isis": ("vtysh", "-c", "show isis neighbor json"),
    "bgp": ("vtysh", "-c", "show bgp summary json"),
    "rip": ("vtysh", "-c", "show ip rip"),
    "ripng": ("vtysh", "-c", "show ipv6 ripng"),
    "nft": ("nft", "list", "ruleset"),
    "frr_config": ("vtysh", "-c", "show running-config"),   # legacy bootstrap capture (read-only, like every other ``vtysh -c "show ..."`` here)
})
# SR Linux is read through gNMI Get only: key -> (path, datastore).  Structured state, never CLI text.
SRLINUX_QUERIES = MappingProxyType({
    "interfaces": ("/interface", "state"),
    "route_table": ("/network-instance[name=default]/route-table", "state"),
    "ospf": ("/network-instance[name=default]/protocols/ospf", "state"),            # V2 Phase 9 routing reads
    "bgp": ("/network-instance[name=default]/protocols/bgp/neighbor", "state"),
    "running_config": ("/", "config"),        # only ever reduced to secret-free semantic facts through parser_srlinux
})
# IOS XE 17.6 has no ``| json``: the same fixed show commands, parsed from their documented text layout.
IOSXE_COMMANDS = MappingProxyType({
    "ip_interfaces": "show ip interface",
    "ipv6_interfaces": "show ipv6 interface",
    "ip_routes": "show ip route",
    "ipv6_routes": "show ipv6 route",
    "ospf": "show ip ospf neighbor",                 # V2 Phase 9 routing reads (text layout of IOS XE 17.6)
    "ospf3": "show ipv6 ospf neighbor",
    "bgp": "show bgp ipv4 unicast summary",
    "bgp6": "show bgp ipv6 unicast summary",
    "running_config": "show running-config",         # only ever reduced to secret-free semantic routing facts
})
ALLOWLISTS = MappingProxyType({"ceos": CEOS_COMMANDS, "linux": LINUX_COMMANDS, "nokia_srlinux": SRLINUX_QUERIES,
                               "cisco_c8000v_iosxe": IOSXE_COMMANDS})
PROBE_KEY = MappingProxyType({"ceos": "interfaces", "linux": "addr", "nokia_srlinux": "interfaces",
                              "cisco_c8000v_iosxe": "ip_interfaces"})  # its failure => the device is unreachable

# Any of these tokens in an allowlisted command would make it a mutation; ``_assert_read_only`` refuses them at import.
FORBIDDEN_COMMAND_TOKENS = (
    "configure", "conf t", "commit", "write", "copy", "clear", "reload", "reboot", "restart", "shutdown", "delete", "erase",
    "save", "set ", "add ", "del ", "flush", "replace", "systemctl", "service ", "kill", "rm ", "sudo", "|| ",
    "&&", ";", "`", "$(", ">", "<",
)


def _assert_read_only() -> None:
    for command in CEOS_COMMANDS.values():
        head, _, tail = command.partition(" | ")
        if not head.startswith("show ") or (tail and tail != "json"):
            raise RuntimeError(f"cEOS allowlist entry is not a read-only show command: {command!r}")
        if any(token in command.lower() for token in FORBIDDEN_COMMAND_TOKENS):
            raise RuntimeError(f"cEOS allowlist entry contains a forbidden token: {command!r}")
    for argv in LINUX_COMMANDS.values():
        text = " ".join(argv).lower()
        if argv[0] in ("sh", "bash", "dash", "zsh", "env", "sudo", "su"):  # the executable itself must never be a shell
            raise RuntimeError(f"Linux allowlist entry starts a shell: {argv!r}")
        ok = (
            (argv[0] == "ip" and argv[1] == "-j" and argv[-1] in ("show",))
            or (argv[0] == "vtysh" and argv[1] == "-c" and argv[2].startswith("show ") and len(argv) == 3)
            or argv == ("nft", "list", "ruleset")
        )
        if not ok or any(token in text for token in FORBIDDEN_COMMAND_TOKENS):
            raise RuntimeError(f"Linux allowlist entry is not a read-only command: {argv!r}")


_assert_read_only()


# --- normalization helpers ---------------------------------------------------------------------------------------
def norm_cidr(text) -> str | None:
    """Canonical interface-style CIDR (host bits kept); None for anything that is not an address."""
    try:
        return str(ipaddress.ip_interface(str(text).strip()))
    except ValueError:
        return None


def norm_prefix(text) -> str | None:
    """Canonical network prefix; a bare host address becomes /32 or /128."""
    try:
        return str(ipaddress.ip_network(str(text).strip(), strict=False))
    except ValueError:
        return None


def norm_ip(text) -> str | None:
    try:
        return str(ipaddress.ip_address(str(text).strip()))
    except ValueError:
        return None


# --- IP connectivity (ping): the ONLY health command family that takes a parameter ---------------------------------
# ``validate_ping_destination`` is the sole gate a destination must pass before it reaches a session/argv: a strict
# ``ipaddress.ip_address`` parse (never a hostname, never free browser text) makes injection structurally impossible
# regardless of transport (Netmiko command string or ``docker exec`` argv list). Callers (``connectivity.py``) never
# accept a destination string from the browser either -- only a closed inventory key is browser-supplied, resolved
# server-side to an address (see ``connectivity.ping_targets``).
PING_COUNT_BOUNDS = (1, 5)


def validate_ping_destination(text, *, family: int | None = None) -> str:
    try:
        address = ipaddress.ip_address(str(text).strip())
    except ValueError as exc:
        raise LiveError("INVALID_DESTINATION") from exc
    if family is not None and address.version != family:
        raise LiveError("INVALID_DESTINATION")
    return str(address)


def _validate_ping_count(count: int) -> int:
    count = int(count)
    lo, hi = PING_COUNT_BOUNDS
    if not (lo <= count <= hi):
        raise LiveError("COMMAND_NOT_ALLOWED")
    return count


def _assert_ping_command_safe(command: str) -> None:
    """Defense in depth: even though ``validate_ping_destination`` already makes injection impossible, the built
    command is still required to look exactly like a read-only ping and to carry none of the forbidden tokens."""
    if not re.match(r"^ping\s+\S+\s+repeat\s+[1-5]\s+timeout\s+1$", command):
        raise RuntimeError(f"Constructed ping command failed the read-only safety assertion: {command!r}")
    if any(token in command.lower() for token in FORBIDDEN_COMMAND_TOKENS):
        raise RuntimeError(f"Constructed ping command contains a forbidden token: {command!r}")


_PING_STATS = re.compile(r"(\d+)\s+packets transmitted,\s+(\d+)\s+(?:packets\s+)?received,.*?(\d+(?:\.\d+)?)%\s+packet loss", re.S)
_PING_RTT = re.compile(r"(?:rtt|round-trip) min/avg/max(?:/mdev)? = ([\d.]+)/([\d.]+)/([\d.]+)(?:/[\d.]+)? ms")


def parse_ping_output(text: str) -> dict:
    """{"transmitted", "received", "loss_percent", "rtt_min_ms", "rtt_avg_ms", "rtt_max_ms"} from standard
    iputils-style ping statistics text (cEOS is Linux-based and uses the same summary format as Ubuntu/FRR)."""
    match = _PING_STATS.search(text or "")
    if not match:
        raise LiveError("PARSE_ERROR")
    transmitted, received, loss = int(match.group(1)), int(match.group(2)), float(match.group(3))
    rtt = _PING_RTT.search(text or "")
    return {
        "transmitted": transmitted, "received": received, "loss_percent": loss,
        "rtt_min_ms": float(rtt.group(1)) if rtt else None,
        "rtt_avg_ms": float(rtt.group(2)) if rtt else None,
        "rtt_max_ms": float(rtt.group(3)) if rtt else None,
    }


def _state_name(value) -> str:
    """"twoWay" -> "TWO_WAY", "Full" -> "FULL", "Full/DR" -> "FULL"."""
    text = str(value or "").split("/")[0].strip()
    return re.sub(r"(?<=[a-z])(?=[A-Z])", "_", text).upper()


def _json(text: str, *, tolerate_absent: bool = False):
    """Parse a command's JSON.  ``tolerate_absent``: a vtysh '%' / EOS 'inactive' answer means "protocol not running"."""
    text = (text or "").strip()
    if not text:
        if tolerate_absent:
            return {}
        raise LiveError("PARSE_ERROR")
    try:
        return json.loads(text)
    except ValueError as exc:
        if tolerate_absent and text.startswith("%"):
            return {}
        raise LiveError("PARSE_ERROR") from exc


# --- cEOS parsers ------------------------------------------------------------------------------------------------
def parse_eos_interfaces(text: str) -> dict:
    """{name: {"admin": UP|DOWN, "oper": UP|DOWN}} from ``show interfaces | json`` (disabled == administratively down)."""
    rows = (_json(text).get("interfaces")) or {}
    return {
        str(name): {
            "admin": "DOWN" if str(row.get("interfaceStatus", "")).lower() == "disabled" else "UP",
            "oper": "UP" if str(row.get("lineProtocolStatus", "")).lower() == "up" else "DOWN",
        }
        for name, row in rows.items() if isinstance(row, dict)
    }


def _eos_ip(entry) -> str | None:
    if not isinstance(entry, dict) or entry.get("address") in (None, "", "0.0.0.0"):
        return None
    return norm_cidr(f"{entry['address']}/{entry.get('maskLen', 32)}")


def parse_eos_addresses(v4_text: str, v6_text: str) -> tuple[dict, dict]:
    """(addresses {iface: [cidr]}, virtual {iface: [address]}) from ``show ip[v6] interface | json``."""
    addresses: dict[str, list] = {}
    virtual: dict[str, list] = {}
    for name, row in ((_json(v4_text).get("interfaces")) or {}).items():
        block = row.get("interfaceAddress") or {}
        found = [_eos_ip(block.get("primaryIp"))] + [_eos_ip(x) for x in block.get("secondaryIpsOrderedList", [])]
        vips = [_eos_ip(block.get("virtualIp"))] + [_eos_ip(x) for x in block.get("virtualSecondaryIpsOrderedList", [])]
        addresses.setdefault(str(name), []).extend(x for x in found if x)
        if any(vips):
            virtual.setdefault(str(name), []).extend(x.split("/")[0] for x in vips if x)
    for name, row in ((_json(v6_text).get("interfaces")) or {}).items():
        for entry in row.get("addresses", []) or []:
            prefix = str(entry.get("subnet", "")).split("/")[-1]
            found = norm_cidr(f"{entry.get('address')}/{prefix}") if prefix.isdigit() else None
            if found:
                addresses.setdefault(str(name), []).append(found)
    return ({k: sorted(set(v)) for k, v in addresses.items()}, {k: sorted(set(v)) for k, v in virtual.items()})


def parse_eos_routes(v4_text: str, v6_text: str) -> list:
    routes = []
    for text in (v4_text, v6_text):
        vrf = ((_json(text).get("vrfs")) or {}).get("default") or {}
        for prefix, row in (vrf.get("routes") or {}).items():
            vias = row.get("vias") or []
            routes.append({
                "prefix": norm_prefix(prefix) or str(prefix), "type": str(row.get("routeType", "")),
                "next_hops": sorted({norm_ip(v["nexthopAddr"]) for v in vias if v.get("nexthopAddr") and norm_ip(v["nexthopAddr"])}),
                "interfaces": sorted({str(v["interface"]) for v in vias if v.get("interface")}),
            })
    return sorted(routes, key=lambda r: r["prefix"])


def parse_eos_ospf(v2_text: str, v3_text: str) -> list:
    neighbors = []
    for family, text, key in (("OSPFV2", v2_text, "ospfNeighborEntries"), ("OSPFV3", v3_text, "ospf3NeighborEntries")):
        vrf = ((_json(text, tolerate_absent=True).get("vrfs")) or {}).get("default") or {}
        for instance in (vrf.get("instList") or {}).values():
            for row in instance.get(key, []) or []:
                neighbors.append({"family": family, "neighbor_id": str(row.get("routerId", "")),
                                  "interface": str(row.get("interfaceName", "")), "state": _state_name(row.get("adjacencyState"))})
    return sorted(neighbors, key=lambda n: (n["family"], n["interface"], n["neighbor_id"]))


def parse_eos_isis(text: str) -> list:
    """``show isis neighbors | json`` -> [{"instance", "system_id", "hostname", "interface", "level", "state"}].
    A device with no IS-IS instance answers ``{"vrfs": {}}``: no adjacencies, not a failure."""
    vrf = ((_json(text, tolerate_absent=True).get("vrfs")) or {}).get("default") or {}
    rows = []
    for instance, body in (vrf.get("isisInstances") or {}).items():
        for system_id, neighbor in (body.get("neighbors") or {}).items():
            for adjacency in neighbor.get("adjacencies") or []:
                rows.append({"instance": str(instance), "system_id": str(system_id), "hostname": str(adjacency.get("hostname", "")),
                             "interface": str(adjacency.get("interfaceName", "")), "level": str(adjacency.get("level", "")),
                             "state": str(adjacency.get("state", "")).upper()})
    return sorted(rows, key=lambda n: (n["interface"], n["system_id"], n["level"]))


_EOS_RIP_NEIGHBOR = re.compile(r"^(\d+\.\d+\.\d+\.\d+)\s+\S+\s+\d+\s+(\d+)\s+\d+\s+(.*)$")


def parse_eos_rip_neighbors(text: str, v4_text: str, v6_text: str) -> list:
    """``show ip rip neighbors`` -> [{"peer", "interface", "routes", "accepted"}].

    The table names a peer ADDRESS, not an interface.  The interface is the one whose connected IPv4 subnet holds the
    peer, which is what distinguishes an adjacency over a client SVI from one over the transit; a peer on no connected
    subnet keeps an empty interface rather than a guess.  This says where RIP has a PEER -- it says nothing about
    which connected prefixes are advertised."""
    addresses, _virtual = parse_eos_addresses(v4_text, v6_text)
    rows = []
    for line in (text or "").splitlines():
        found = _EOS_RIP_NEIGHBOR.match(line.strip())
        if not found:
            continue
        peer = ipaddress.ip_address(found.group(1))
        interface = ""
        for name, cidrs in sorted(addresses.items()):
            if any(":" not in cidr and peer in ipaddress.ip_interface(cidr).network for cidr in cidrs):
                interface = name
                break
        rows.append({"peer": str(peer), "interface": interface, "routes": int(found.group(2)), "accepted": "ACCEPTED" in found.group(3)})
    return sorted(rows, key=lambda n: (n["interface"], n["peer"]))


def parse_eos_bgp(v4_text: str, v6_text: str) -> list:
    peers = []
    for family, text in ((4, v4_text), (6, v6_text)):
        data = _json(text, tolerate_absent=True)  # {"errors": ["BGP inactive"]} -> no peers, not a failure
        vrf = ((data.get("vrfs")) or {}).get("default") or {}
        for address, row in (vrf.get("peers") or {}).items():
            peers.append({"peer": norm_ip(address) or str(address), "remote_as": str(row.get("asn", "")),
                          "state": str(row.get("peerState", "")).upper(), "family": family})
    return sorted(peers, key=lambda p: (p["family"], p["peer"]))


_IFACE_LINE = re.compile(r"^interface\s+(\S+)\s*$", re.I)
_ACCESS_GROUP = re.compile(r"^\s+(?:ip|ipv6)\s+access-group\s+(\S+)\s+(in|out)\b", re.I)
_HELPER = re.compile(r"^\s+ip\s+helper-address\s+(\S+)", re.I)
_RELAY6 = re.compile(r"^\s+ipv6\s+dhcp\s+relay\s+destination\s+(\S+)", re.I)
_ACL_DEF = re.compile(r"^(?:ip|ipv6)\s+access-list\s+(?:(?:standard|extended)\s+)?(\S+)\s*$", re.I)


_VARP = re.compile(r"^\s+(?:ip|ipv6)\s+virtual-router\s+address\s+(\S+)", re.I)


def parse_eos_varp(text: str) -> dict:
    """{interface: [address]} of VARP ``virtual-router address`` statements.  ``show ip interface`` only reports
    ``ip address virtual``; a VARP address is visible in the running configuration alone (verified on cEOS 4.36.2F)."""
    virtual: dict[str, list] = {}
    interface = ""
    for line in (text or "").splitlines():
        if not line.startswith(" ") and line.strip():
            match = _IFACE_LINE.match(line)
            interface = match.group(1) if match else ""
        elif interface and (found := _VARP.match(line)) and norm_ip(found.group(1).split("/")[0]):
            virtual.setdefault(interface, []).append(norm_ip(found.group(1).split("/")[0]))
    return virtual


def _merge_virtual(*sources: dict) -> dict:
    merged: dict[str, set] = {}
    for source in sources:
        for name, values in source.items():
            merged.setdefault(name, set()).update(values)
    return {name: sorted(values) for name, values in merged.items()}


def parse_eos_config(text: str) -> dict:
    """Facts ONLY from ``show running-config`` (the raw text is dropped by the caller): ACL definitions and
    attachments and DHCP relay destinations.  No other line, and no secret-bearing line, is retained."""
    acl_definitions, attachments, relays = set(), [], []
    interface = ""
    for line in (text or "").splitlines():
        if not line.startswith(" ") and line.strip():
            match = _IFACE_LINE.match(line)
            interface = match.group(1) if match else ""
            acl = _ACL_DEF.match(line)
            if acl:
                acl_definitions.add(acl.group(1))
            continue
        if not interface:
            continue
        for pattern in (_ACCESS_GROUP,):
            found = pattern.match(line)
            if found:
                attachments.append({"interface": interface, "acl": found.group(1), "direction": found.group(2).upper()})
        for pattern in (_HELPER, _RELAY6):
            found = pattern.match(line)
            if found and norm_ip(found.group(1)):
                relays.append({"interface": interface, "destination": norm_ip(found.group(1))})
    return {"acl_definitions": sorted(acl_definitions),
            "acl_attachments": sorted(attachments, key=lambda a: (a["interface"], a["acl"], a["direction"])),
            "dhcp_relays": sorted(relays, key=lambda r: (r["interface"], r["destination"]))}


# --- Linux / FRR parsers -----------------------------------------------------------------------------------------
_XE_IFACE = re.compile(r"^(\S+) is (administratively down|up|down|deleted),? line protocol is (up|down)", re.I)
_XE_V4 = re.compile(r"^\s+(?:Internet address is|Secondary address) (\d+\.\d+\.\d+\.\d+/\d+)")
_XE_V6 = re.compile(r"^\s+([0-9A-Fa-f:]+), subnet is [0-9A-Fa-f:]+/(\d+)")
# A learned route reads ``via <hop>[, <age>][, <interface>]``; the age (``00:00:12``, ``1d02h``) is never an interface.
_XE_ROUTE4 = re.compile(r"^([A-Za-z][A-Za-z0-9*+ ]{0,7}?)\s+(\d+\.\d+\.\d+\.\d+)(/\d+)? (?:\[\d+/\d+\] via (\S+?)"
                        r"(?:,\s*\d[\dywdhm:]*)?(?:,\s*([A-Za-z]\S*))?$|is directly connected, (\S+))")
_XE_SUBNETTED = re.compile(r"^\s+\d+\.\d+\.\d+\.\d+(/\d+) is subnetted")
_XE_ROUTE6 = re.compile(r"^([A-Za-z][A-Za-z0-9 ]{0,3}?)\s+([0-9A-Fa-f:]+/\d+) \[\d+/\d+\]")
_XE_VIA6 = re.compile(r"^\s+via ([0-9A-Fa-f:]+|\S+?)(?:,\s*(\S+))?(?:,|$)")
_XE_TYPES = {"S": "static", "C": "connected", "L": "local", "O": "ospf", "B": "bgp", "R": "rip", "D": "eigrp", "i": "isis"}


def parse_iosxe_interfaces(v4_text: str, v6_text: str) -> tuple[dict, dict]:
    """IOS XE ``show ip interface`` / ``show ipv6 interface`` -> ({name: {admin, oper}}, {name: [cidr]}).

    ``show ip interface`` lists every interface (also those without IPv4), so it is the presence source; a deleted
    subinterface that IOS XE still remembers is not an interface.  Link-local addresses are not configuration."""
    interfaces, addresses, current = {}, {}, None
    for text, pattern in ((v4_text, _XE_V4), (v6_text, _XE_V6)):
        current = None
        for line in (text or "").splitlines():
            head = _XE_IFACE.match(line)
            if head:
                current = None if head.group(2).lower() == "deleted" else head.group(1)
                if current and pattern is _XE_V4:
                    interfaces[current] = {"admin": "DOWN" if head.group(2).lower() == "administratively down" else "UP",
                                           "oper": "UP" if head.group(3).lower() == "up" else "DOWN"}
                    addresses.setdefault(current, [])
                continue
            found = pattern.match(line) if current in interfaces else None
            if found:
                cidr = norm_cidr("/".join(found.groups()) if pattern is _XE_V6 else found.group(1))
                if cidr and cidr not in addresses[current]:
                    addresses[current].append(cidr)
    return interfaces, addresses


def parse_iosxe_routes(v4_text: str, v6_text: str) -> list:
    """IOS XE ``show ip route`` / ``show ipv6 route`` (default VRF RIB) -> [{prefix, type, next_hops, interfaces}]."""
    routes, mask = [], ""
    for line in (v4_text or "").splitlines():
        subnetted = _XE_SUBNETTED.match(line)
        if subnetted:
            mask = subnetted.group(1)
            continue
        if line and not line.startswith(" "):
            found = _XE_ROUTE4.match(line)
            prefix = norm_prefix(found.group(2) + (found.group(3) or mask)) if found else None
            if prefix:
                routes.append({"prefix": prefix, "type": _XE_TYPES.get(found.group(1).strip()[:1], found.group(1).strip()),
                               "next_hops": [hop] if (hop := norm_ip(found.group(4))) else [],
                               "interfaces": [name for name in (found.group(5), found.group(6)) if name]})
    row = None
    for line in (v6_text or "").splitlines():
        found = _XE_ROUTE6.match(line)
        if found and (prefix := norm_prefix(found.group(2))):
            row = {"prefix": prefix, "type": _XE_TYPES.get(found.group(1).strip()[:1], found.group(1).strip()),
                   "next_hops": [], "interfaces": []}
            routes.append(row)
            continue
        via = _XE_VIA6.match(line) if row is not None else None
        if via:
            hop = norm_ip(via.group(1))
            row["next_hops"].extend([hop] if hop else [])
            row["interfaces"].extend(name for name in ((via.group(1) if not hop else None), via.group(2)) if name and name != "receive")
    return routes


_XE_OSPF_NEIGHBOR = re.compile(r"^(\S+)\s+\d+\s+([A-Z0-9-]+)/\s*\S*\s+\d\d:\d\d:\d\d\s+\S+\s+(\S+)\s*$")


def parse_iosxe_ospf(v2_text: str, v3_text: str) -> list:
    """IOS XE ``show ip ospf neighbor`` / ``show ipv6 ospf neighbor`` -> [{family, neighbor_id, interface, state}].

    The state column reads ``FULL/  -`` (role after the slash); a row whose neighbor id is ``N/A`` is a hello seen before
    the router id is learned and is not an adjacency.  A router without OSPF answers with no table: no neighbors."""
    neighbors = []
    for family, text in (("OSPFV2", v2_text), ("OSPFV3", v3_text)):
        for line in (text or "").splitlines():
            found = _XE_OSPF_NEIGHBOR.match(line.strip())
            if not found or found.group(1) == "N/A" or not norm_ip(found.group(1)):
                continue
            neighbors.append({"family": family, "neighbor_id": found.group(1), "interface": found.group(3),
                              "state": found.group(2).replace("-", "_")})
    return sorted(neighbors, key=lambda n: (n["family"], n["interface"], n["neighbor_id"]))


_XE_BGP_ROW = re.compile(r"^(\S+)?\s+4\s+(\d+)\s+\d+\s+\d+\s+\d+\s+\d+\s+\d+\s+(\S+)\s+(.+?)\s*$")


def parse_iosxe_bgp(v4_text: str, v6_text: str) -> list:
    """IOS XE ``show bgp ipv4|ipv6 unicast summary`` -> [{peer, remote_as, state, family, prefixes_received}].

    The last column is the received-prefix count once the session is Established, otherwise the session state.  A
    neighbor address too long for its column is printed on a line of its own; ``% BGP not active`` means no peers."""
    peers = []
    for family, text in ((4, v4_text), (6, v6_text)):
        pending = ""
        for line in (text or "").splitlines():
            stripped = line.strip()
            if stripped and " " not in stripped and norm_ip(stripped):
                pending = stripped
                continue
            found = _XE_BGP_ROW.match(line if line[:1].strip() else line)
            if not found:
                pending = ""
                continue
            peer = norm_ip(found.group(1) or pending)
            pending = ""
            if not peer:
                continue
            last = found.group(4).strip()
            established = last.isdigit()
            peers.append({"peer": peer, "remote_as": found.group(2), "family": family,
                          "state": "ESTABLISHED" if established else last.split()[0].upper(),
                          "prefixes_received": int(last) if established else None})
    return sorted(peers, key=lambda p: (p["family"], p["peer"]))


def _srl_tree(text: str) -> dict:
    from .. import srlinux_model
    return srlinux_model.tree_from_gnmi(json.loads(text or "{}"))


def parse_srl_interfaces(text: str) -> tuple[dict, dict]:
    """SR Linux gNMI interface state -> ({name: {admin, oper}}, {name: [cidr]}).

    SR Linux carries L3 state on numbered subinterfaces.  The untagged index-0 subinterface IS its parent's routed
    personality (the same convention the import parser uses), so its addresses are reported on the parent name and the
    parent is only operationally up when that subinterface is; every other subinterface is its own ``parent.index``.
    Link-local addresses the node derives itself are not configuration and are left out.
    """
    interfaces, addresses = {}, {}
    for row in _srl_tree(text).get("interface") or []:
        name = row.get("name")
        if not name:
            continue
        admin = row.get("admin-state") == "enable"
        oper = row.get("oper-state") == "up"
        for sub in row.get("subinterface") or []:
            index = sub.get("index")
            cidrs = [norm_cidr(a.get("ip-prefix")) for family in ("ipv4", "ipv6")
                     for a in ((sub.get(family) or {}).get("address") or [])
                     if a.get("ip-prefix") and a.get("origin", "static") != "link-layer" and a.get("type") != "link-local-unicast"]
            sub_admin = admin and sub.get("admin-state") == "enable"
            sub_oper = oper and sub.get("oper-state") == "up"
            tagged = bool((((sub.get("vlan") or {}).get("encap") or {}).get("single-tagged") or {}))
            if index == 0 and not tagged:
                addresses[name] = [c for c in cidrs if c]
                admin, oper = sub_admin, sub_oper
                continue
            key = f"{name}.{index}"
            interfaces[key] = {"admin": "UP" if sub_admin else "DOWN", "oper": "UP" if sub_oper else "DOWN"}
            addresses[key] = [c for c in cidrs if c]
        interfaces[name] = {"admin": "UP" if admin else "DOWN", "oper": "UP" if oper else "DOWN"}
        addresses.setdefault(name, [])
    return interfaces, addresses


# SR Linux names an OSPF route by version; the health model names the protocol (as on every other platform).
_SRL_ROUTE_TYPES = {"ospfv2": "ospf", "ospfv3": "ospf"}


def _srl_interface(reference: str) -> str:
    """``ethernet-1/1.0`` (an untagged index-0 subinterface) is its parent's routed personality: report the parent name."""
    return reference[:-2] if reference.endswith(".0") else reference


def parse_srl_ospf(text: str) -> list:
    """SR Linux gNMI OSPF state -> [{family, neighbor_id, interface, state}] (state as the health model spells it: FULL)."""
    neighbors = []
    ni = (_srl_tree(text).get("network-instance") or [{}])[0]
    for instance in ((ni.get("protocols") or {}).get("ospf") or {}).get("instance") or []:
        family = "OSPFV3" if instance.get("version") == "ospf-v3" else "OSPFV2"
        for area in instance.get("area") or []:
            for interface in area.get("interface") or []:
                for neighbor in interface.get("neighbor") or []:
                    if not neighbor.get("router-id"):
                        continue
                    neighbors.append({"family": family, "neighbor_id": neighbor["router-id"],
                                      "interface": _srl_interface(interface.get("interface-name") or ""),
                                      "state": str(neighbor.get("adjacency-state") or "").upper().replace("-", "_")})
    return sorted(neighbors, key=lambda n: (n["family"], n["interface"], n["neighbor_id"]))


def parse_srl_bgp(text: str) -> list:
    """SR Linux gNMI BGP neighbor state -> [{peer, remote_as, state, family, prefixes_received}].  The family is the peer
    address family; ``prefixes_received`` counts that family's received routes once the session is established."""
    peers = []
    ni = (_srl_tree(text).get("network-instance") or [{}])[0]
    for row in ((ni.get("protocols") or {}).get("bgp") or {}).get("neighbor") or []:
        peer = norm_ip(row.get("peer-address"))
        if not peer:
            continue
        v6 = ":" in peer
        state = str(row.get("session-state") or "").upper()
        afi = next((a for a in row.get("afi-safi") or [] if a.get("afi-safi-name") == ("ipv6-unicast" if v6 else "ipv4-unicast")), {})
        peers.append({"peer": peer, "remote_as": str(row.get("peer-as") or ""), "family": 6 if v6 else 4, "state": state,
                      "prefixes_received": afi.get("received-routes") if state == "ESTABLISHED" else None})
    return sorted(peers, key=lambda p: (p["family"], p["peer"]))


def parse_srl_config(text: str) -> dict:
    """ACL definitions / attachments and DHCP relays of the SR Linux running configuration (via ``parser_srlinux``)."""
    from ..config_import import parser_srlinux

    parsed = parser_srlinux.parse(_srl_tree(text))
    attachments = [{"interface": interface.name, "acl": row["name"], "direction": row["direction"]}
                   for interface in parsed.interfaces for row in interface.acl_attachments]
    relays = [{"interface": interface.name, "destination": norm_ip(row["destination"])}
              for interface in parsed.interfaces for row in interface.dhcp_relays]
    return {"acl_definitions": sorted(acl.name for acl in parsed.acls),
            "acl_attachments": sorted(attachments, key=lambda a: (a["interface"], a["acl"], a["direction"])),
            "dhcp_relays": sorted(relays, key=lambda r: (r["interface"], r["destination"]))}


def _routing_config_srl(text: str) -> list:
    from .routing_config import srlinux
    return srlinux(_srl_tree(text))


def parse_srl_routes(text: str) -> list:
    """Active RIB entries of the SR Linux default network-instance with their resolved next hops."""
    table = (((_srl_tree(text).get("network-instance") or [{}])[0]).get("route-table") or {})
    hops = {str(h.get("index")): h for h in table.get("next-hop") or []}
    groups = {str(g.get("index")): [hops.get(str(n.get("next-hop")), {}) for n in g.get("next-hop") or []]
              for g in table.get("next-hop-group") or []}
    routes = []
    for family, leaf in (("ipv4-unicast", "ipv4-prefix"), ("ipv6-unicast", "ipv6-prefix")):
        for row in (table.get(family) or {}).get("route") or []:
            prefix = norm_prefix(row.get(leaf))
            if not prefix or not row.get("active"):
                continue
            resolved = groups.get(str(row.get("next-hop-group")), [])
            interfaces = []
            for hop in resolved:
                sub = str(hop.get("subinterface") or "")
                if sub:
                    interfaces.append(sub[:-2] if sub.endswith(".0") else sub)
            routes.append({"prefix": prefix, "type": _SRL_ROUTE_TYPES.get(str(row.get("route-type") or ""), str(row.get("route-type") or "")),
                           "next_hops": [ip for hop in resolved if (ip := norm_ip(hop.get("ip-address")))],
                           "interfaces": interfaces})
    return routes


def parse_linux_addr(text: str) -> tuple[dict, dict]:
    """(interfaces {name: {admin, oper}}, addresses {name: [cidr]}) from ``ip -j addr show`` (link-local excluded)."""
    interfaces, addresses = {}, {}
    rows = _json(text)
    if not isinstance(rows, list):
        raise LiveError("PARSE_ERROR")
    for row in rows:
        name = str(row.get("ifname", ""))
        flags = row.get("flags") or []
        interfaces[name] = {"admin": "UP" if "UP" in flags else "DOWN",
                            "oper": "UP" if (row.get("operstate") == "UP" or (row.get("operstate") == "UNKNOWN" and "LOWER_UP" in flags)) else "DOWN"}
        found = [norm_cidr(f"{a['local']}/{a['prefixlen']}") for a in row.get("addr_info", []) if a.get("scope") != "link"]
        addresses[name] = sorted({x for x in found if x})
    return interfaces, addresses


def parse_linux_routes(v4_text: str, v6_text: str) -> list:
    routes = []
    for family, text in ((4, v4_text), (6, v6_text)):
        rows = _json(text)
        if not isinstance(rows, list):
            raise LiveError("PARSE_ERROR")
        for row in rows:
            dst = row.get("dst", "")
            prefix = ("0.0.0.0/0" if family == 4 else "::/0") if dst == "default" else norm_prefix(dst)
            if not prefix:
                continue
            hops = [row.get("gateway")] + [n.get("gateway") for n in row.get("nexthops", []) or []]
            devs = [row.get("dev")] + [n.get("dev") for n in row.get("nexthops", []) or []]
            routes.append({"prefix": prefix, "type": str(row.get("protocol", "")),
                           "next_hops": sorted({norm_ip(h) for h in hops if h and norm_ip(h)}),
                           "interfaces": sorted({str(d) for d in devs if d})})
    return sorted(routes, key=lambda r: r["prefix"])


def parse_frr_ospf(v2_text: str, v3_text: str) -> list:
    neighbors = []
    for router_id, rows in ((_json(v2_text, tolerate_absent=True).get("neighbors")) or {}).items():
        for row in rows if isinstance(rows, list) else []:
            neighbors.append({"family": "OSPFV2", "neighbor_id": str(router_id),
                              "interface": str(row.get("ifaceName", "")).split(":")[0], "state": _state_name(row.get("nbrState") or row.get("state"))})
    v3 = (_json(v3_text, tolerate_absent=True).get("neighbors")) or []
    for row in v3 if isinstance(v3, list) else []:
        neighbors.append({"family": "OSPFV3", "neighbor_id": str(row.get("neighborId", "")),
                          "interface": str(row.get("interfaceName", "")), "state": _state_name(row.get("state"))})
    return sorted(neighbors, key=lambda n: (n["family"], n["interface"], n["neighbor_id"]))


def parse_frr_isis(text: str) -> list:
    neighbors = []
    data = _json(text, tolerate_absent=True)
    for area in data.get("areas") or []:
        for circuit in area.get("circuits") or []:
            neighbors.append({"instance": str(area.get("area") or ""), "system_id": str(circuit.get("adj") or ""),
                              "hostname": str(circuit.get("adj") or ""), "interface": str(circuit.get("interface") or ""),
                              "level": str(circuit.get("level") or ""), "state": str(circuit.get("state") or "").upper()})
    return sorted(neighbors, key=lambda n: (n["instance"], n["interface"], n["system_id"]))


def parse_frr_bgp(text: str) -> list:
    peers = []
    data = _json(text, tolerate_absent=True)
    for key, family in (("ipv4Unicast", 4), ("ipv6Unicast", 6)):
        for address, row in ((data.get(key) or {}).get("peers") or {}).items():
            peers.append({"peer": norm_ip(address) or str(address), "remote_as": str(row.get("remoteAs", "")),
                          "state": str(row.get("state", "")).upper(), "family": family,
                          "prefixes": {f"IPV{family}": {"received": row.get("pfxRcd"), "sent": row.get("pfxSnt")}}})
    unique: dict = {}   # a dual-family peer is listed once per family in FRR; keep one row per peer, counters per family
    for peer in peers:
        kept = unique.setdefault(peer["peer"], peer)
        if kept is not peer:
            unique[peer["peer"]] = {**peer, "prefixes": {**kept["prefixes"], **peer["prefixes"]}}
    return sorted(unique.values(), key=lambda p: (p["family"], p["peer"]))


_RIP_ROW = re.compile(r"^([A-Z])\((\w)\)\s+(\S+)")


def parse_frr_rip(v4_text: str, v6_text: str) -> list:
    """RIP/RIPng table rows from ``show ip rip`` / ``show ipv6 ripng``; ``learned`` marks a route received from a neighbor."""
    rows = []
    for family, text in (("IPV4", v4_text), ("IPV6", v6_text)):
        for line in (text or "").splitlines():
            found = _RIP_ROW.match(line.strip())
            prefix = norm_prefix(found.group(3)) if found else None
            if prefix:
                rows.append({"family": family, "prefix": prefix, "learned": found.group(1) == "R" and found.group(2) == "n"})
    return sorted(rows, key=lambda r: (r["family"], r["prefix"]))


_NFT_TABLE = re.compile(r"^table\s+(ip6?|inet)\s+(\S+)\s*\{")
_NFT_OIF = re.compile(r'oifname\s+"([^"]+)"')
_NFT_ACTION = re.compile(r"\b(masquerade|snat)\b")


def parse_nft(text: str) -> dict:
    """{"tables": [names], "rules": [{"table", "oif", "action"}]} -- only NAT-relevant facts."""
    tables, rules, current = [], [], ""
    for line in (text or "").splitlines():
        match = _NFT_TABLE.match(line)
        if match:
            current = match.group(2)
            tables.append(current)
            continue
        action = _NFT_ACTION.search(line)
        if current and action:
            oif = _NFT_OIF.search(line)
            rules.append({"table": current, "oif": oif.group(1) if oif else "", "action": action.group(1)})
    return {"tables": sorted(set(tables)), "rules": sorted(rules, key=lambda r: (r["table"], r["oif"], r["action"]))}


# --- sessions ----------------------------------------------------------------------------------------------------
class EosSession:
    """One Netmiko session, privileged EXEC only, ``show`` commands only (see module docstring)."""

    def __init__(self, device: dict):
        target = nsot_live.get_live_target(device["name"], platform="ceos")
        if target is None:
            from ..management import resolve as management_resolve

            if management_resolve.endpoint(device["name"]).source == management_resolve.BLOCKED:
                raise LiveError("MANAGEMENT_UNREACHABLE")      # registered paths exist, none usable: never the legacy address
            # A valid cEOS target whose credential reference cannot be resolved on THIS server (e.g. no runtime credential
            # store in this checkout) is a credential problem, not an absent target.
            metadata = nsot_live.get_live_target_metadata(device["name"])
            raise LiveError("CREDENTIAL_NOT_CONFIGURED" if metadata and metadata.get("platform") == "ceos" else "NOT_CONFIGURED")
        if target.get("platform") != "ceos":
            raise LiveError("NOT_CONFIGURED")
        self._timeout = settings.HEALTH_LIVE_TIMEOUT_SECONDS
        self._conn = None
        try:
            from ..management.ssh_transport import connect_eos
            from netmiko.exceptions import NetmikoAuthenticationException, NetmikoTimeoutException
        except ImportError as exc:  # pragma: no cover - netmiko is a project dependency
            raise LiveError("CONNECTION_FAILED") from exc
        try:
            auth_error = None
            for auth in target.get("auth_candidates", ({
                "username": target["username"], "password": target["password"], "ssh_auth": target.get("ssh_auth", {}),
            },)):
                try:
                    self._conn = connect_eos(target, auth, self._timeout)
                    break
                except NetmikoAuthenticationException as exc:
                    auth_error = exc
            if self._conn is None:
                raise auth_error or NetmikoAuthenticationException("authentication failed")
            if not self._conn.check_enable_mode():
                self._conn.enable()  # privileged EXEC only -- never configuration mode
        except NetmikoAuthenticationException as exc:
            self.close()
            raise LiveError("AUTH_FAILED") from exc
        except NetmikoTimeoutException as exc:
            self.close()
            raise LiveError("TIMEOUT") from exc
        except Exception as exc:  # noqa: BLE001 - never relay connection details
            self.close()
            raise LiveError("CONNECTION_FAILED") from exc

    def run(self, key: str) -> str:
        command = CEOS_COMMANDS.get(key)
        if command is None:
            raise LiveError("COMMAND_NOT_ALLOWED")
        try:
            output = self._conn.send_command(command, read_timeout=self._timeout * 2)
        except Exception as exc:  # noqa: BLE001
            raise LiveError("TIMEOUT" if "imeout" in exc.__class__.__name__ else "COMMAND_FAILED") from exc
        return _bounded(output)

    def ping(self, dest: str, count: int = 3) -> str:
        address = validate_ping_destination(dest)
        command = f"ping {address} repeat {_validate_ping_count(count)} timeout 1"
        _assert_ping_command_safe(command)
        try:
            output = self._conn.send_command(command, read_timeout=self._timeout * 2)
        except Exception as exc:  # noqa: BLE001
            raise LiveError("TIMEOUT" if "imeout" in exc.__class__.__name__ else "COMMAND_FAILED") from exc
        return _bounded(output)

    def close(self) -> None:
        if self._conn is not None:
            try:
                self._conn.disconnect()
            except Exception:  # noqa: BLE001
                pass


def _docker_exec(container: str, argv, *, timeout: float, probe: bool) -> str:
    """THE one process spawn of the health engine: ``docker exec <container> <fixed argv>`` (a list, ``shell=False``, no credentials).  ``argv`` always
    comes from a fixed allowlist table, never from a browser, a plan or a Configlet.  ``probe``: this is the reachability probe (its failure means the
    device is unreachable, not that one command failed)."""
    try:
        done = subprocess.run(  # noqa: S603 - fixed argv list, shell=False, allowlisted
            ["docker", "exec", container, *argv], capture_output=True, text=True, timeout=timeout, shell=False, check=False,
        )
    except FileNotFoundError as exc:
        raise LiveError("DOCKER_UNAVAILABLE") from exc
    except subprocess.TimeoutExpired as exc:
        raise LiveError("TIMEOUT") from exc
    except OSError as exc:
        raise LiveError("DOCKER_UNAVAILABLE") from exc
    if done.returncode != 0 and not done.stdout.strip():
        if not probe and argv[0] == "vtysh" and re.fullmatch(r"\w+ is not running", done.stderr.strip()):
            return ""   # that FRR protocol daemon is not enabled: the protocol has no state (parsers read "absent")
        raise LiveError("CONNECTION_FAILED" if probe else "COMMAND_FAILED")
    return _bounded(done.stdout)


class LinuxSession:
    """``docker exec <container> <fixed argv>`` (no shell, no credentials, read-only commands only)."""

    def __init__(self, device: dict):
        if not device.get("container"):
            raise LiveError("NOT_CONFIGURED")
        self._container = device["container"]
        self._timeout = settings.HEALTH_LIVE_TIMEOUT_SECONDS

    def run(self, key: str) -> str:
        argv = LINUX_COMMANDS.get(key)
        if argv is None:
            raise LiveError("COMMAND_NOT_ALLOWED")
        return _docker_exec(self._container, argv, timeout=self._timeout, probe=key == PROBE_KEY["linux"])

    def ping(self, dest: str, count: int = 3) -> str:
        address = validate_ping_destination(dest)
        count = _validate_ping_count(count)
        flag = "-6" if ipaddress.ip_address(address).version == 6 else "-4"
        argv = ("ping", flag, "-c", str(count), "-W", "2", address)
        return _docker_exec(self._container, argv, timeout=self._timeout, probe=False)

    def close(self) -> None:
        return None


class DockerEosSession:
    """cEOS read-only session through ``docker exec <container> Cli -p 15 -c "<allowlisted show command>"`` (argv list, no shell, no credentials).

    This is the repository's own credential-free read pattern for cEOS (``netbox/scripts/verify_dhcp_servers.py`` reads R2 exactly this way).  It is
    used ONLY for a cEOS device whose management address is Containerlab-assigned (``address: auto`` in inventory.yml, i.e. R5): such a device has
    no SSH target, so ``EosSession`` cannot open it and the read used to end as ``NOT_CONFIGURED``.  The allowlist is the same ``CEOS_COMMANDS``
    table: only ``show`` commands, addressed by KEY."""

    def __init__(self, device: dict):
        if not device.get("container"):
            raise LiveError("NOT_CONFIGURED")
        self._container = device["container"]
        self._timeout = settings.HEALTH_LIVE_TIMEOUT_SECONDS

    def run(self, key: str) -> str:
        command = CEOS_COMMANDS.get(key)
        if command is None:
            raise LiveError("COMMAND_NOT_ALLOWED")
        return _docker_exec(self._container, ["Cli", "-p", "15", "-c", command], timeout=self._timeout * 2, probe=key == PROBE_KEY["ceos"])

    def ping(self, dest: str, count: int = 3) -> str:
        address = validate_ping_destination(dest)
        command = f"ping {address} repeat {_validate_ping_count(count)} timeout 1"
        _assert_ping_command_safe(command)
        return _docker_exec(self._container, ["Cli", "-p", "15", "-c", command], timeout=self._timeout * 2, probe=False)

    def close(self) -> None:
        return None


def _bounded(output) -> str:
    text = output if isinstance(output, str) else str(output or "")
    if len(text) > MAX_OUTPUT_BYTES:
        raise LiveError("OUTPUT_TOO_LARGE")
    return text


class SrLinuxSession:
    """SR Linux read-only session: allowlisted gNMI Get only (``SRLINUX_QUERIES``), answered as JSON text.

    ``gnmi`` is an already-open ``GnmiSession`` owned by the caller (the isolated capability lab); without it the
    target and credential come from the trusted inventory lookup, exactly as for the SR Linux executor."""

    def __init__(self, device: dict, *, gnmi=None):
        from ..execution.writers import srlinux_gnmi

        self._errors = srlinux_gnmi.GnmiError
        self._owned = gnmi is None
        try:
            self._gnmi = gnmi if gnmi is not None else srlinux_gnmi.inventory_session(device)
        except self._errors as exc:
            raise LiveError(exc.code) from None

    def run(self, key: str) -> str:
        query = SRLINUX_QUERIES.get(key)
        if query is None:
            raise LiveError("COMMAND_NOT_ALLOWED")
        try:
            return _bounded(json.dumps(self._gnmi.get(*query)))
        except self._errors as exc:
            raise LiveError("CONNECTION_FAILED" if key == PROBE_KEY["nokia_srlinux"] else exc.code) from None

    def close(self) -> None:
        if self._owned:
            self._gnmi.disconnect()


class IosXeSession:
    """IOS XE read-only session: allowlisted ``show`` commands (``IOSXE_COMMANDS``) over a privileged-EXEC Netmiko session.

    ``conn`` is an already-open session owned by the caller (the isolated capability lab); without it the target and
    credential come from the trusted inventory lookup, exactly as for the IOS XE executor."""

    def __init__(self, device: dict, *, conn=None):
        from ..execution.executors import iosxe
        from ..execution.executors.base import ExecutorError

        self._owned = conn is None
        try:
            self._conn = conn if conn is not None else iosxe.netmiko_connection(device)
        except ExecutorError as exc:
            raise LiveError(exc.code) from None

    def run(self, key: str) -> str:
        command = IOSXE_COMMANDS.get(key)
        if command is None:
            raise LiveError("COMMAND_NOT_ALLOWED")
        try:
            output = self._conn.send_command(command, read_timeout=60)
        except Exception:  # noqa: BLE001 - never relay session details
            raise LiveError("CONNECTION_FAILED" if key == PROBE_KEY["cisco_c8000v_iosxe"] else "COMMAND_FAILED") from None
        if "% Invalid input" in (output or ""):
            raise LiveError("COMMAND_FAILED")
        return _bounded(output)

    def close(self) -> None:
        if self._owned:
            try:
                self._conn.disconnect()
            except Exception:  # noqa: BLE001
                pass


SESSION_FACTORIES = MappingProxyType({"ceos": EosSession, "linux": LinuxSession, "nokia_srlinux": SrLinuxSession,
                                      "cisco_c8000v_iosxe": IosXeSession})


def default_session_factory(device: dict):
    """The session class for a managed device: the SSH ``EosSession`` for a cEOS device with an inventory address, ``DockerEosSession`` for a cEOS
    device whose address is Containerlab-assigned (no SSH target exists), ``LinuxSession`` for Ubuntu / FRR."""
    platform = device.get("platform", "")
    if platform == "ceos" and not device.get("address") and device.get("container"):
        from ..management import resolve as management_resolve

        if management_resolve.endpoint(device.get("name", "")).source != management_resolve.LEGACY:
            return EosSession  # an approved path never degrades to Docker exec
        return DockerEosSession
    return SESSION_FACTORIES[platform]


# --- read a device -----------------------------------------------------------------------------------------------
def _group(source_fn, *, now: datetime) -> FactGroup:
    try:
        return FactGroup(data=source_fn(), source=SOURCE, observed_at=now, complete=True)
    except LiveError as exc:
        return unavailable(SOURCE, exc.code, observed_at=now)
    except (ValueError, KeyError, TypeError, AttributeError):
        return unavailable(SOURCE, "PARSE_ERROR", observed_at=now)
    except Exception:  # noqa: BLE001 - never relay an arbitrary exception text (it could echo connection parameters)
        return unavailable(SOURCE, "COMMAND_FAILED", observed_at=now)


def read_device(device: dict, *, session_factory=None, now: datetime | None = None) -> DeviceEvidence:
    """Explicit, bounded, read-only query of ONE managed device -> normalized evidence.  Never raises.

    ``device`` is an inventory entry (from ``inventory.managed_devices``), never browser input.  ``session_factory``
    is injectable for tests (a fake returns canned command output).
    """
    return read_device_with_raw(device, session_factory=session_factory, now=now)[0]


def read_device_with_raw(device: dict, raw_keys=(), *, session_factory=None, now: datetime | None = None) -> tuple[DeviceEvidence, dict, dict]:
    """``read_device`` that ALSO returns the raw text of the requested allowlisted commands: -> (evidence, {key: text}, {key: error_code}).

    ``raw_keys`` are allowlist KEYS only (never a command, never browser input): each is fetched through the same fixed read-only session as
    every other read, in the same session.  The raw text is handed to the CALLER (the one-time legacy-bootstrap capture, which sanitizes it
    before anything is stored); this module still never persists or logs it.  Never raises; a failed key is reported by its sanitized code."""
    now = now or utcnow()
    platform = device.get("platform", "")
    evidence = DeviceEvidence(device=device["name"], platform=platform)
    raw: dict = {}
    raw_errors: dict = {}
    if get_capability(platform)["status"] != Capability.SUPPORTED:
        evidence.live_error = "NOT_SUPPORTED"
        return evidence, raw, {key: "NOT_SUPPORTED" for key in raw_keys}
    evidence.live_attempted = True
    factory = session_factory or default_session_factory(device)
    try:
        session = factory(device)
    except LiveError as exc:
        evidence.live_error = exc.code
        return evidence, raw, {key: exc.code for key in raw_keys}
    except Exception:  # noqa: BLE001 - sanitized: only the reason code ever leaves this module
        evidence.live_error = "CONNECTION_FAILED"
        return evidence, raw, {key: "CONNECTION_FAILED" for key in raw_keys}
    try:
        try:
            probe = session.run(PROBE_KEY[platform])
        except LiveError as exc:
            evidence.live_error = exc.code if exc.code in ("TIMEOUT", "AUTH_FAILED", "DOCKER_UNAVAILABLE", "CONNECTION_FAILED") else "CONNECTION_FAILED"
            return evidence, raw, {key: evidence.live_error for key in raw_keys}
        except Exception:  # noqa: BLE001
            evidence.live_error = "CONNECTION_FAILED"
            return evidence, raw, {key: "CONNECTION_FAILED" for key in raw_keys}
        outputs = {PROBE_KEY[platform]: probe}

        def fetch(key):
            if key not in outputs:
                outputs[key] = session.run(key)
            return outputs[key]

        groups = {"ceos": _EOS_GROUPS, "nokia_srlinux": _SRL_GROUPS, "cisco_c8000v_iosxe": _IOSXE_GROUPS}.get(platform, _LINUX_GROUPS)
        for name, builder in groups.items():
            evidence.groups[name] = _group(lambda builder=builder: builder(fetch), now=now)
        for key in raw_keys:
            try:
                raw[key] = fetch(key)
            except LiveError as exc:
                raw_errors[key] = exc.code
            except Exception:  # noqa: BLE001
                raw_errors[key] = "COMMAND_FAILED"
    finally:
        session.close()
    return evidence, raw, raw_errors


_EOS_GROUPS = {
    "interfaces": lambda f: parse_eos_interfaces(f("interfaces")),
    "addresses": lambda f: parse_eos_addresses(f("ip_interfaces"), f("ipv6_interfaces"))[0],
    "virtual_addresses": lambda f: _merge_virtual(parse_eos_addresses(f("ip_interfaces"), f("ipv6_interfaces"))[1],
                                                   parse_eos_varp(f("running_config"))),
    "routes": lambda f: parse_eos_routes(f("ip_routes"), f("ipv6_routes")),
    "ospf": lambda f: parse_eos_ospf(f("ospf"), f("ospf3")),
    "isis": lambda f: parse_eos_isis(f("isis")),
    "rip_neighbors": lambda f: parse_eos_rip_neighbors(f("rip_neighbors"), f("ip_interfaces"), f("ipv6_interfaces")),
    "bgp": lambda f: parse_eos_bgp(f("bgp"), f("bgp6")),
    "config": lambda f: parse_eos_config(f("running_config")),
    "routing_config": lambda f: _routing_config_eos(f("running_config")),
    # Remove Configuration verification: header-qualified statement signatures of the SANITIZED running config (no secret value
    # survives sanitization; the raw text itself is never retained).  Reuses the ``running_config`` output already fetched above.
    "config_paths": lambda f: config_path_signatures(f("running_config")),
    "management_services": lambda f: parse_management_config(f("running_config")).services,
}


def config_path_signatures(text: str) -> list[str]:
    from ..bundles.legacy_sanitize import sanitize_config
    from ..config_workbench.structure import config_paths

    return sorted(config_paths(sanitize_config(text or "").text))
_SRL_GROUPS = {
    "interfaces": lambda f: parse_srl_interfaces(f("interfaces"))[0],
    "addresses": lambda f: parse_srl_interfaces(f("interfaces"))[1],
    "routes": lambda f: parse_srl_routes(f("route_table")),
    "ospf": lambda f: parse_srl_ospf(f("ospf")),
    "bgp": lambda f: parse_srl_bgp(f("bgp")),
    "routing_config": lambda f: _routing_config_srl(f("running_config")),
    "config": lambda f: parse_srl_config(f("running_config")),
}

_IOSXE_GROUPS = {
    "interfaces": lambda f: parse_iosxe_interfaces(f("ip_interfaces"), f("ipv6_interfaces"))[0],
    "addresses": lambda f: parse_iosxe_interfaces(f("ip_interfaces"), f("ipv6_interfaces"))[1],
    "routes": lambda f: parse_iosxe_routes(f("ip_routes"), f("ipv6_routes")),
    "ospf": lambda f: parse_iosxe_ospf(f("ospf"), f("ospf3")),
    "bgp": lambda f: parse_iosxe_bgp(f("bgp"), f("bgp6")),
    "routing_config": lambda f: _routing_config_iosxe(f("running_config")),
}

_LINUX_GROUPS = {
    "interfaces": lambda f: parse_linux_addr(f("addr"))[0],
    "addresses": lambda f: parse_linux_addr(f("addr"))[1],
    "routes": lambda f: parse_linux_routes(f("route4"), f("route6")),
    "ospf": lambda f: parse_frr_ospf(f("ospf"), f("ospf6")),
    "isis": lambda f: parse_frr_isis(f("isis")),
    "bgp": lambda f: parse_frr_bgp(f("bgp")),
    "rip": lambda f: parse_frr_rip(f("rip"), f("ripng")),
    "nat": lambda f: parse_nft(f("nft")),
    "routing_config": lambda f: _routing_config_frr(f("frr_config"), f("addr")),
}


def _routing_config_eos(text):
    from .routing_config import eos
    return eos(text)


def _routing_config_iosxe(text):
    from .routing_config import iosxe
    return iosxe(text)


def _routing_config_frr(text, addr_json):
    from .routing_config import frr
    return frr(text, addr_json)


# --- DHCP service state: REUSES netbox/scripts/verify_dhcp_servers.py (no second implementation) ------------------
def dhcp_service_state() -> dict:
    """{"nmas": {...}|None, "r2": {...}|None, "error": ""} -- the verifier's own read-only ``nmas_status``/``r2_status``."""
    import sys

    root = str(settings.REPO_ROOT)
    if root not in sys.path:
        sys.path.insert(0, root)
    from netbox.scripts import verify_dhcp_servers as verifier  # noqa: E402  (the existing read-only verifier)

    state = {"nmas": None, "r2": None, "error": ""}
    for name, function in (("nmas", verifier.nmas_status), ("r2", verifier.r2_status)):
        try:
            state[name] = function()
        except Exception:  # noqa: BLE001 - sanitized: only that the inspection failed
            state["error"] = "INSPECTION_FAILED"
    return state
