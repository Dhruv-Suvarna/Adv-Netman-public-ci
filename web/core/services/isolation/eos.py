"""Arista EOS: the isolation renderer and the read-back parsers.  Pure functions (text in, facts out); no device access.

Every rendered statement was exercised on cEOS 4.36.2F in a disposable namespace before it was written here
(docs/V2_TRUSTED_ISOLATION_COMMISSIONING.md, "Platform findings"):

* ``ip access-group <acl> in`` / ``ipv6 access-group <acl> in`` on a routed port drops FORWARDED IPv4 / IPv6 traffic
  that enters the port; ``counters per-entry`` gives per-entry match counters.
* The ingress ACL does NOT filter traffic addressed to the switch itself.  The upstream's own services are therefore a
  separate concern (``management_exposure``) and routing protocols are suppressed separately: an OSPF adjacency stays
  FULL through ``deny ip any any`` and leaks the device's routes, ``router ospf N / passive-interface <port>`` removes
  both.  RIP has no ``passive-interface`` on 4.36.2F; IS-IS, OSPFv3 and BGP on the port are refused, never guessed.
* ``ip access-group <acl> out`` / ``ipv6 access-group <acl> out`` drops FORWARDED traffic leaving the port towards the
  device; traffic the upstream originates itself (its DHCP relay replies, ND / RA, its own pings) is not filtered.
* ``management ssh / ip access-group <acl> in`` and ``ipv6 access-group <acl> in`` close the upstream's SSH service to
  the denied sources.  The device reaches that service over IPv4, its SLAAC / static IPv6 address AND link-local, so the
  IPv6 service ACL also denies fe80::/10 while the port is isolated (link-local SSH to the upstream is closed for all).

Nothing else is assumed: a construct this module does not recognise makes the policy BLOCKED, never "probably fine".
"""

from __future__ import annotations

import ipaddress
import json
import re

ACL_PREFIX = "NMAS-ISO-"
DENY_SEQUENCE = 1000
# EOS prints well-known ports by name in the running configuration (observed: 22 -> ssh, 67 -> bootps, 68 -> bootpc)
PORT_NAMES = {22: "ssh", 67: "bootps", 68: "bootpc", 69: "tftp", 80: "www", 443: "https"}
NAME_PORTS = {name: port for port, name in PORT_NAMES.items()}
_INTERFACE = re.compile(r"^[A-Za-z][A-Za-z0-9/.:-]{0,63}$")


class RenderError(ValueError):
    def __init__(self, code: str, detail: str = ""):
        super().__init__(code)
        self.code, self.detail = code, str(detail)[:200]


def acl_names(device_id: str) -> dict:
    """The reserved ACL names of one device's policy (unique per device record, never reused).

    in4/in6 filter what the device sends, out4/out6 what is forwarded to it, mgmt4/mgmt6 close the upstream's own SSH."""
    if not re.fullmatch(r"DEV-\d{6}", device_id or ""):
        raise RenderError("ISOLATION_DEVICE_INELIGIBLE", "malformed device id")
    base = f"{ACL_PREFIX}{device_id}"
    return {"in4": f"{base}-V4", "in6": f"{base}-V6", "out4": f"{base}-V4-OUT", "out6": f"{base}-V6-OUT",
            "mgmt4": f"{base}-MGMT4", "mgmt6": f"{base}-MGMT6"}


def _port(value: int) -> str:
    return PORT_NAMES.get(int(value), str(int(value)))


# ---------------------------------------------------------------------------------------------------------------- rendering
def ipv4_entries(bootstrap: dict) -> list[str]:
    """The IPv4 ingress entries: DHCP to the relay, the artifact fetch, the return path of NMAS's own SSH session, then deny."""
    prefix = str(ipaddress.ip_network(bootstrap["prefix"], strict=True))
    service = str(ipaddress.ip_address(bootstrap["service_address"]))
    entries = ["10 permit udp any eq bootpc any eq bootps",
               f"20 permit tcp {prefix} host {service} eq {_port(bootstrap['http_port'])}",
               f"30 permit tcp {prefix} eq ssh host {service}"]
    return [*entries, f"{DENY_SEQUENCE} deny ip any any"]


def ipv4_egress_entries(bootstrap: dict) -> list[str]:
    """The IPv4 egress entries (traffic FORWARDED towards the device): only the service's replies and NMAS's own SSH.

    DHCP relay replies are originated by the upstream itself and are not subject to an egress ACL (observed on 4.36.2F)."""
    prefix = str(ipaddress.ip_network(bootstrap["prefix"], strict=True))
    service = str(ipaddress.ip_address(bootstrap["service_address"]))
    return [f"10 permit tcp host {service} eq {_port(bootstrap['http_port'])} {prefix}",
            f"20 permit tcp host {service} {prefix} eq ssh",
            f"{DENY_SEQUENCE} deny ip any any"]


def ipv6_entries() -> list[str]:
    """IPv6 ingress: neighbour discovery on the link only (a router never forwards a link-local source), then deny."""
    return ["10 permit icmpv6 fe80::/10 any", f"{DENY_SEQUENCE} deny ipv6 any any"]


def ipv6_egress_entries() -> list[str]:
    """IPv6 egress: nothing is forwarded to the device (the upstream's own ND / RA is not subject to an egress ACL)."""
    return [f"{DENY_SEQUENCE} deny ipv6 any any"]


def management_entries(family: str, prefixes: list[str]) -> list[str]:
    """The upstream's SSH service ACL NMAS installs when the service has none: deny the bootstrap side, keep the rest.

    It replaces "no ACL" (everything permitted), so ``permit any`` preserves every existing source except the denied ones."""
    keyword = "ip" if family == "v4" else "ipv6"
    entries, sequence = [], 10
    for prefix in prefixes:
        entries.append(f"{sequence} deny {keyword} {ipaddress.ip_network(prefix, strict=True)} any")
        sequence += 10
    return [*entries, f"{sequence} permit {keyword} any any"]


def management_denied(port_ipv4: list[str], port_ipv6: list[str]) -> dict:
    """The source prefixes the upstream's SSH service must refuse while the port is untrusted (per family).

    IPv6 includes fe80::/10: the device reaches the upstream over link-local whenever IPv6 is on (observed)."""
    v4 = sorted({str(ipaddress.ip_interface(a).network) for a in port_ipv4})
    v6 = sorted({str(ipaddress.ip_interface(a).network) for a in port_ipv6})
    return {"v4": v4, "v6": [*v6, "fe80::/10"] if v6 else []}


def locks_out(address: str, denied: dict) -> bool:
    """Would the management ACL deny NMAS's own session to the upstream (connected from ``address``)?"""
    try:
        ip = ipaddress.ip_address(str(address).split("%", 1)[0])
    except ValueError:
        return False                                      # a host name: the precheck read-back proves the session survives
    return any(ip in ipaddress.ip_network(p) for p in denied["v4" if ip.version == 4 else "v6"])


def _paths(lines) -> list[str]:
    """Header-qualified paths of an indented block, in the form ``config_workbench.structure.config_paths`` yields."""
    paths, header = [], ""
    for line in lines:
        if not line.startswith(" "):
            header = line.strip()
            paths.append(header)
        else:
            paths.append(f"{header} > {line.strip()}")
    return paths


def _op(key: str, kind: str, lines: list[str], inverse: list[str], paths: list[str], description: str) -> dict:
    return {"key": key, "kind": kind, "lines": list(lines), "inverse": list(inverse), "paths": list(paths), "description": description}


def _acl(key: str, family: str, name: str, entries: list[str], description: str) -> dict:
    keyword = "ip" if family == "v4" else "ipv6"
    lines = [f"{keyword} access-list {name}", "   counters per-entry", *[f"   {e}" for e in entries]]
    return _op(key, "ADD", lines, [f"no {keyword} access-list {name}"], _paths(lines), description)


def _child(key: str, header: str, line: str, description: str, *, undo: str = "") -> dict:
    """One statement added under a block that already exists (or is implicit): only the line is undone, never the block."""
    return _op(key, "ADD", [header, f"   {line}"], [header, f"   {undo or 'no ' + line}"], [f"{header} > {line}"], description)


def render_apply(intent: dict) -> list[dict]:
    """The ordered operations that enforce ``intent`` on the upstream, each with its exact inverse and presence paths.

    Definitions first (inert until attached), then the upstream's own SSH service is closed to the bootstrap side, then
    the port filters are attached, then routing is suppressed."""
    interface = intent["upstream"]["interface"]
    if not _INTERFACE.fullmatch(interface or ""):
        raise RenderError("INTERFACE_INVALID", interface)
    v4, v6 = intent["elements"]["IPV4"], intent["elements"]["IPV6"]
    mgmt = intent["elements"]["MANAGEMENT_PLANE"]
    ops = [_acl("acl-v4", "v4", v4["acl"], v4["entries"], "IPv4 isolation ACL (from the device)"),
           _acl("acl-v6", "v6", v6["acl"], v6["entries"], "IPv6 isolation ACL (from the device)"),
           _acl("acl-v4-out", "v4", v4["out_acl"], v4["out_entries"], "IPv4 isolation ACL (towards the device)"),
           _acl("acl-v6-out", "v6", v6["out_acl"], v6["out_entries"], "IPv6 isolation ACL (towards the device)")]
    attach_mgmt = []
    for family in ("V4", "V6"):
        element = mgmt.get(family)
        if not element or element["mode"] != "ADD":
            continue
        tag = family.lower()
        ops.append(_acl(f"acl-mgmt-{tag}", tag, element["acl"], element["entries"], f"upstream SSH service ACL ({family})"))
        keyword = "ip" if tag == "v4" else "ipv6"
        attach_mgmt.append(_child(f"attach-mgmt-{tag}", "management ssh", f"{keyword} access-group {element['acl']} in",
                                  f"upstream SSH service closed to the bootstrap side ({family})"))
    ops.extend(attach_mgmt)
    header = f"interface {interface}"
    for key, keyword, acl, direction in (("attach-v4", "ip", v4["acl"], "in"), ("attach-v6", "ipv6", v6["acl"], "in"),
                                         ("attach-v4-out", "ip", v4["out_acl"], "out"),
                                         ("attach-v6-out", "ipv6", v6["out_acl"], "out")):
        ops.append(_child(key, header, f"{keyword} access-group {acl} {direction}",
                          f"{'IPv4' if keyword == 'ip' else 'IPv6'} isolation ACL attached {direction}bound on {interface}"))
    for process in intent["elements"]["CONTROL_PLANE"]["ospf_passive"]:
        router = f"router ospf {process['process']}" + (f" vrf {process['vrf']}" if process.get("vrf") else "")
        # cEOS 4.36.2F keeps ``no passive-interface X`` as an explicit line: ``default`` restores the process byte for byte
        ops.append(_child(f"ospf-passive-{process['process']}", router, f"passive-interface {interface}",
                          f"OSPF process {process['process']}: no adjacency on {interface}", undo=f"default passive-interface {interface}"))
    for process in intent["elements"]["CONTROL_PLANE"].get("ospf6_passive", []):
        router = f"ipv6 router ospf {process['process']}" + (f" vrf {process['vrf']}" if process.get("vrf") else "")
        ops.append(_child(f"ospf6-passive-{process['process']}", router, f"passive-interface {interface}",
                          f"OSPFv3 process {process['process']}: no adjacency on {interface}", undo=f"default passive-interface {interface}"))
    return ops


RELEASE_ORDER = ("attach-v4", "attach-v6", "attach-v4-out", "attach-v6-out", "ospf-passive-", "ospf6-passive-", "attach-mgmt-v4",
                 "attach-mgmt-v6", "acl-v4", "acl-v6", "acl-v4-out", "acl-v6-out", "acl-mgmt-v4", "acl-mgmt-v6")


def render_release(intent: dict) -> list[dict]:
    """The removal of exactly what ``render_apply`` added: port filters first, then routing, then the upstream's SSH
    service, then the definitions.  Each removal carries the original lines as its restore path (a failed admission
    puts them back)."""
    applied = {op["key"]: op for op in render_apply(intent)}
    order = []
    for prefix in RELEASE_ORDER:
        order.extend(key for key in applied if (key.startswith(prefix) if prefix.endswith("-") else key == prefix))
    missing = set(applied) - set(order)
    if missing:
        raise RenderError("ISOLATION_PLAN_STALE", f"release order does not cover {sorted(missing)}")
    return [_op(f"release-{key}", "REMOVE", applied[key]["inverse"], applied[key]["lines"], applied[key]["paths"],
                f"release: {applied[key]['description']}") for key in order]


# ------------------------------------------------------------------------------------------------------------- read-back
def _blocks(text: str) -> list[tuple[str, list[str]]]:
    """Top-level blocks: (header, raw child lines with their indentation)."""
    blocks: list[tuple[str, list[str]]] = []
    for raw in (text or "").splitlines():
        line = raw.rstrip()
        if not line.strip() or line.strip().startswith("!"):
            continue
        if not line.startswith(" "):
            blocks.append((line.strip(), []))
        elif blocks:
            blocks[-1][1].append(line)
    return blocks


def _children(block: list[str]) -> list[str]:
    """Direct children (the shallowest indentation) of a block, stripped."""
    if not block:
        return []
    depth = min(len(line) - len(line.lstrip(" ")) for line in block)
    return [line.strip() for line in block if len(line) - len(line.lstrip(" ")) == depth]


def interface_facts(text: str, interface: str) -> dict:
    """Bounded facts of one interface and its neighbourhood in the running configuration."""
    header = f"interface {interface}"
    blocks = _blocks(text)
    found = next((children for name, children in blocks if name == header), None)
    facts = {"exists": found is not None, "routed": False, "ipv4": [], "ipv6": [], "access_groups": {}, "helpers": [], "vrf": "",
             "channel_group": False, "shutdown": False, "isis": False, "ospfv3": False, "ospfv3_process": "", "ospf_area": "", "subinterfaces": []}
    facts["subinterfaces"] = sorted(name.split(" ", 1)[1] for name, _ in blocks if name.startswith(f"{header}."))
    if found is None:
        return facts
    for line in _children(found):
        if line == "no switchport":
            facts["routed"] = True
        elif line.startswith("ip address ") and not line.endswith(" secondary"):
            facts["ipv4"].append(line.split()[2])
        elif line.startswith("ipv6 address ") and "link-local" not in line:
            facts["ipv6"].append(line.split()[2])
        elif re.fullmatch(r"(ip|ipv6) access-group \S+ (in|out)", line):
            family, _, name, direction = line.split()
            facts["access_groups"][f"{'v4' if family == 'ip' else 'v6'}_{direction}"] = name
        elif line.startswith("ip helper-address "):
            facts["helpers"].append(line.split()[2])
        elif line.startswith("vrf "):
            facts["vrf"] = line.split()[1]
        elif line.startswith("channel-group "):
            facts["channel_group"] = True
        elif line == "shutdown":
            facts["shutdown"] = True
        elif line.startswith("isis enable"):
            facts["isis"] = True
        elif line.startswith("ipv6 ospf "):
            facts["ospfv3"] = True
            participation = re.fullmatch(r"ipv6 ospf (\d+) area \S+", line)
            if participation:
                facts["ospfv3_process"] = participation.group(1)
        elif line.startswith("ip ospf area "):
            facts["ospf_area"] = line.split()[3]
    if not any(line == "no switchport" for line in _children(found)) and not interface.lower().startswith(("ethernet", "port-channel")):
        facts["routed"] = True          # SVIs / loopbacks are layer 3 by nature (bootstrap ports are physical: see validation)
    return facts


def _covers(network_text: str, addresses: list[str]) -> bool:
    try:
        network = ipaddress.ip_network(network_text, strict=False)
    except ValueError:
        return True                                  # unparseable: assume it covers (the caller refuses)
    for address in addresses:
        try:
            iface = ipaddress.ip_interface(address)
        except ValueError:
            continue
        if iface.version == network.version and iface.ip in network:
            return True
    return False


def routing_facts(text: str, interface: str) -> dict:
    """Which routing processes run on ``interface`` and whether NMAS can suppress them by a verified procedure."""
    port = interface_facts(text, interface)
    facts = {"ospf": [], "unsupported": [], "already_passive": [], "ospf6": [], "already_passive6": []}
    handled_v3 = False
    for header, children in _blocks(text):
        words = header.split()
        lines = _children(children)
        if header.startswith("router ospf ") and len(words) in (3, 5) and (len(words) == 3 or words[3] == "vrf"):
            process, vrf = words[2], (words[4] if len(words) == 5 else "")
            if (vrf or "") != (port["vrf"] or ""):
                continue
            covered = bool(port["ospf_area"]) or any(
                line.startswith("network ") and _covers(line.split()[1], port["ipv4"]) for line in lines)
            if not covered:
                continue
            default_passive = "passive-interface default" in lines
            if default_passive:
                if f"no passive-interface {interface}" in lines:
                    facts["unsupported"].append({"protocol": "OSPF", "process": process, "reason": "active under passive-interface default"})
                else:
                    facts["already_passive"].append({"process": process, "vrf": vrf})
            elif f"passive-interface {interface}" in lines:
                facts["already_passive"].append({"process": process, "vrf": vrf})
            else:
                facts["ospf"].append({"process": process, "vrf": vrf})
        elif header == "router rip" or header.startswith("router rip "):
            if "shutdown" not in lines and any(line.startswith("network ") and _covers(line.split()[1], port["ipv4"]) for line in lines):
                facts["unsupported"].append({"protocol": "RIP", "reason": "no verified passive-interface on this platform"})
        elif header.startswith("router isis ") and port["isis"]:
            facts["unsupported"].append({"protocol": "IS-IS", "reason": "IS-IS enabled on the port"})
        elif header.startswith("router bgp "):
            for line in lines:
                parts = line.split()
                if len(parts) >= 3 and parts[0] == "neighbor":
                    try:
                        neighbor = ipaddress.ip_address(parts[1])
                    except ValueError:
                        continue
                    if any(neighbor in ipaddress.ip_interface(a).network for a in port["ipv4"] + port["ipv6"]):
                        facts["unsupported"].append({"protocol": "BGP", "reason": "a BGP neighbour on the port subnet"})
                        break
        elif header.startswith("ipv6 router ospf ") and len(words) in (4, 6) and (len(words) == 4 or words[4] == "vrf") \
                and port["ospfv3_process"] == words[3] and (words[5] if len(words) == 6 else "") == (port["vrf"] or ""):
            # the cEOS OSPFv3 form NMAS renders (``ipv6 router ospf N`` + ``ipv6 ospf N area A`` on the port): suppressed exactly
            # like OSPFv2, by ``passive-interface <port>`` under the process
            handled_v3 = True
            process, vrf = words[3], (words[5] if len(words) == 6 else "")
            if "passive-interface default" in lines:
                if f"no passive-interface {interface}" in lines:
                    facts["unsupported"].append({"protocol": "OSPFv3", "process": process, "reason": "active under passive-interface default"})
                else:
                    facts["already_passive6"].append({"process": process, "vrf": vrf})
            elif f"passive-interface {interface}" in lines:
                facts["already_passive6"].append({"process": process, "vrf": vrf})
            else:
                facts["ospf6"].append({"process": process, "vrf": vrf})
        elif header.startswith(("router ospfv3", "ipv6 router ospf")) and port["ospfv3"]:
            facts["unsupported"].append({"protocol": "OSPFv3", "reason": "OSPFv3 enabled on the port"})
    if port["ospfv3"] and not handled_v3 and not any(u["protocol"] == "OSPFv3" for u in facts["unsupported"]):
        facts["unsupported"].append({"protocol": "OSPFv3", "reason": "OSPFv3 enabled on the port"})
    if port["isis"] and not any(u["protocol"] == "IS-IS" for u in facts["unsupported"]):
        facts["unsupported"].append({"protocol": "IS-IS", "reason": "IS-IS enabled on the port"})
    return facts


def acl_entries(text: str, name: str, family: str = "ip") -> list[str] | None:
    """The configured entries of one ACL (stripped child lines), or None when it is not defined."""
    for header, children in _blocks(text):
        if header == f"{family} access-list {name}":
            return _children(children)
    return None


# ------------------------------------------------------------------------------------------------ upstream management plane
_ACE = re.compile(r"^(?P<seq>\d+)\s+(?P<action>permit|deny)\s+(?P<proto>ip|ipv6|tcp)\s+(?P<rest>.+)$")


def _address(tokens: list[str]):
    """Consume one address spec (any | host A | A/len) and an optional ``eq <port>``; -> (network | None for any, port, rest)."""
    if not tokens:
        raise ValueError("missing address")
    if tokens[0] == "any":
        network, tokens = None, tokens[1:]
    elif tokens[0] == "host" and len(tokens) > 1:
        network, tokens = ipaddress.ip_network(tokens[1]), tokens[2:]
    else:
        network, tokens = ipaddress.ip_network(tokens[0], strict=False), tokens[1:]
    port = None
    if len(tokens) >= 2 and tokens[0] == "eq":
        port = NAME_PORTS.get(tokens[1]) or (int(tokens[1]) if tokens[1].isdigit() else -1)
        tokens = tokens[2:]
    elif tokens and tokens[0] in ("range", "gt", "lt", "neq"):
        raise ValueError("port operator not evaluated")
    return network, port, tokens


def acl_denies_ssh_from(entries: list[str] | None, prefix: str) -> tuple[bool, str]:
    """Does this service ACL deny SSH from every address of ``prefix`` (IPv4 or IPv6)?  First match wins, implicit deny.

    -> (denied, reason).  An entry this evaluator cannot read, or a permit that may match part of the prefix before the
    whole prefix is denied, makes the answer False: exposure is never assumed away."""
    if entries is None:
        return False, "the service ACL is not defined"
    bootstrap = ipaddress.ip_network(prefix)
    for entry in entries:
        if entry.startswith(("remark", "counters", "statistics")):
            continue
        match = _ACE.match(entry)
        if not match:
            return False, f"unevaluated entry: {entry[:60]}"
        try:
            src, src_port, rest = _address(match["rest"].split())
            dst, dst_port, rest = _address(rest)
        except ValueError:
            return False, f"unevaluated entry: {entry[:60]}"
        if rest and rest != ["log"]:
            return False, f"unevaluated entry: {entry[:60]}"
        if src is not None and src.version != bootstrap.version:
            return False, f"unevaluated entry: {entry[:60]}"
        if src_port is not None or (dst_port is not None and dst_port != 22) or (match["proto"] != "tcp" and dst_port is not None):
            continue                                      # cannot match an SSH connection from the bootstrap prefix
        del dst                                           # every upstream address counts: the destination does not narrow it
        if src is not None and not src.overlaps(bootstrap):
            continue
        whole = src is None or bootstrap.subnet_of(src)
        if match["action"] == "permit":
            return False, f"entry {match['seq']} permits (part of) {bootstrap}"
        if whole:
            return True, f"entry {match['seq']} denies {bootstrap}"
        # a deny of only part of the prefix: keep looking for the rest
    return True, "implicit deny"


def _ssh_service(text: str, vrf: str) -> dict:
    """The upstream SSH service as configured: shut down?  which ACL guards each family in ``vrf``?"""
    blocks = dict(_blocks(text))
    raw = blocks.get("management ssh")
    children = _children(raw) if raw is not None else []
    found = {"shutdown": "shutdown" in children, "v4": None, "v6": None}
    pattern = re.compile(r"(ip|ipv6) access-group (\S+) in")
    if not vrf:
        lines = children
    else:
        lines, inside, depth = [], False, None
        for line in raw or []:
            stripped, indent = line.strip(), len(line) - len(line.lstrip(" "))
            if stripped == f"vrf {vrf}":
                inside, depth = True, indent
            elif inside and indent <= depth:
                inside = False
            elif inside:
                lines.append(stripped)
    for line in lines:
        match = pattern.fullmatch(line)
        if match:
            found["v4" if match.group(1) == "ip" else "v6"] = match.group(2)
    return found


def _other_services(text: str) -> list[dict]:
    exposed = []
    blocks = dict(_blocks(text))
    for header, label in (("management api http-commands", "EAPI"), ("management telnet", "TELNET")):
        if header in blocks and "no shutdown" in _children(blocks.get(header) or []):
            exposed.append({"service": label, "family": "", "acl": "", "reason": "enabled; its access control is not verified by NMAS"})
    gnmi = blocks.get("management api gnmi")
    if gnmi is not None and any(line.strip().startswith("transport grpc") for line in gnmi):
        exposed.append({"service": "GNMI", "family": "", "acl": "", "reason": "enabled; its access control is not verified by NMAS"})
    if any(name.startswith(("snmp-server community", "snmp-server user")) for name in blocks):
        exposed.append({"service": "SNMP", "family": "", "acl": "", "reason": "enabled; its access control is not verified by NMAS"})
    return exposed


def management_exposure(text: str, denied: dict, vrf: str = "") -> list[dict]:
    """Upstream services reachable from the bootstrap side ([] = closed).  ``denied`` is ``management_denied(...)``.

    Only the SSH service ACL is a verified protection; every other enabled management service is reported."""
    exposed = []
    ssh = _ssh_service(text, vrf)
    if not ssh["shutdown"]:
        for family, keyword in (("v4", "ip"), ("v6", "ipv6")):
            for prefix in denied.get(family) or []:
                acl = ssh[family]
                ok, reason = acl_denies_ssh_from(acl_entries(text, acl, keyword) if acl else None, prefix)
                if not ok:
                    exposed.append({"service": "SSH", "family": family, "acl": acl or "", "reason": reason})
    return [*exposed, *_other_services(text)]


def management_plan(text: str, denied: dict, vrf: str, names: dict) -> dict:
    """How each family of the upstream's SSH service is closed to the bootstrap side.

    -> {"V4": element | None, "V6": element | None, "blocked": [reasons]}; element mode is ADD (NMAS installs and later
    removes its own service ACL: the service had none), VERIFY (an operator ACL already denies every prefix) or CLOSED
    (the service is shut down).  An operator ACL that does not deny is never edited: the policy is BLOCKED."""
    ssh = _ssh_service(text, vrf)
    plan: dict = {"V4": None, "V6": None, "blocked": [item["service"] + ": " + item["reason"] for item in _other_services(text)]}
    for family, keyword in (("v4", "ip"), ("v6", "ipv6")):
        prefixes = denied.get(family) or []
        if not prefixes:
            continue
        if ssh["shutdown"]:
            plan[family.upper()] = {"mode": "CLOSED", "acl": "", "entries": [], "prefixes": prefixes}
            continue
        acl = ssh[family]
        if acl is None:
            if vrf:
                plan["blocked"].append(f"SSH ({family}): no service ACL in VRF {vrf}; NMAS installs one only in the default VRF")
                continue
            plan[family.upper()] = {"mode": "ADD", "acl": names[f"mgmt{family[1]}"], "prefixes": prefixes,
                                    "entries": management_entries(family, prefixes)}
            continue
        failures = [reason for ok, reason in (acl_denies_ssh_from(acl_entries(text, acl, keyword), p) for p in prefixes) if not ok]
        if failures:
            plan["blocked"].append(f"SSH ({family}): operator ACL {acl} does not deny the bootstrap side ({failures[0]})")
        else:
            plan[family.upper()] = {"mode": "VERIFY", "acl": acl, "entries": [], "prefixes": prefixes}
    return plan


# ------------------------------------------------------------------------------------------------------- operational state
_COUNTER = re.compile(r"^\s*(\d+)\s+(permit|deny)\s.*\[match (\d+) packets")


def acl_counters(show_output: str) -> dict:
    """``show ip access-lists <acl>`` -> {sequence: matched packets} (entries that never matched are absent)."""
    found = {}
    for line in (show_output or "").splitlines():
        match = _COUNTER.match(line)
        if match:
            found[int(match.group(1))] = int(match.group(3))
    return found


def ospf_neighbors_on(show_output: str, interface: str) -> list[dict]:
    """``show ip ospf neighbor`` rows whose interface is ``interface``."""
    rows = []
    for line in (show_output or "").splitlines():
        parts = line.split()
        if len(parts) >= 6 and parts[-1] == interface and re.fullmatch(r"\d+\.\d+\.\d+\.\d+", parts[0]):
            state = next((p for p in parts if "/" in p or p.upper() in ("FULL", "INIT", "2WAYS", "EXSTART", "EXCHANGE", "LOADING")), "")
            rows.append({"neighbor": parts[0], "address": parts[-2], "state": state[:24]})
    return rows


def ospf6_neighbors_on(json_text: str, interface: str) -> list[dict] | None:
    """``show ipv6 ospf neighbor | json`` rows whose interface is ``interface`` -> [{neighbor, state}] (every VRF and instance).
    cEOS answers ``{"vrfs": {}}`` when no OSPFv3 process runs (an empty table); None when the output cannot be read."""
    try:
        data = json.loads(json_text or "")
    except ValueError:
        return None
    vrfs = data.get("vrfs") if isinstance(data, dict) else None
    if not isinstance(vrfs, dict):
        return None
    rows = []
    for vrf in vrfs.values():
        for instance in ((vrf or {}).get("instList") or {}).values():
            for entry in (instance or {}).get("ospf3NeighborEntries") or []:
                if isinstance(entry, dict) and entry.get("interfaceName") == interface:
                    rows.append({"neighbor": str(entry.get("routerId", "")), "state": str(entry.get("adjacencyState", ""))[:24]})
    return rows


def routes_via(json_text: str, interface: str, connected: list[str]) -> list[str] | None:
    """Prefixes whose next hop is ``interface`` in ``show ip(v6) route | json``, other than the port's own connected subnets.
    None when the output cannot be read (never an empty, i.e. passing, answer)."""
    try:
        data = json.loads(json_text or "")
    except ValueError:
        return None
    own = set()
    for address in connected:
        try:
            own.add(str(ipaddress.ip_interface(address).network))
        except ValueError:
            continue
    vrfs = data.get("vrfs") if isinstance(data, dict) else None
    if not isinstance(vrfs, dict):
        return None
    leaked = []
    for vrf in vrfs.values():
        for prefix, route in ((vrf or {}).get("routes") or {}).items():
            vias = (route or {}).get("vias") or []
            if any(isinstance(via, dict) and via.get("interface") == interface for via in vias) and prefix not in own:
                leaked.append(prefix)
    return sorted(leaked)


def arp_entry(show_output: str, address: str) -> dict:
    """The upstream's ARP entry for ``address`` (``show ip arp <address>``) -> {mac (aa:bb:..), interface}; {} if none."""
    for line in (show_output or "").splitlines():
        parts = line.split()
        if not parts or parts[0] != address:
            continue
        mac = next((p for p in parts[1:] if re.fullmatch(r"[0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\.[0-9a-fA-F]{4}", p)), "")
        if not mac:
            continue
        digits = mac.replace(".", "").lower()
        interface = parts[parts.index(mac) + 1].rstrip(",") if parts.index(mac) + 1 < len(parts) else ""
        return {"mac": ":".join(digits[i:i + 2] for i in range(0, 12, 2)), "interface": interface}
    return {}
