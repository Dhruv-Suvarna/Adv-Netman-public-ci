"""Ubuntu / FRR trusted-upstream isolation: one NMAS-owned nftables table on the upstream, scoped to the bootstrap port.

Pure functions (snapshot in, facts out); the device reads and writes live in ``execution.executors.frr_isolation``.

Why this is real enforcement on a Linux/FRR router (verified on FRR 8.4.4 + nftables 1.0.9, the production R4 build, in the
disposable fixture ``labs/frr-isolation-isolated``; docs/V2_FRR_TRUSTED_ISOLATION.md):

* The upstream forwards in its kernel.  Every packet the device sends either is FORWARDED (``forward`` hook) or is addressed
  to the upstream itself (``input`` hook); every packet the upstream sends the device leaves through ``forward`` or
  ``output``.  One ``inet`` table (IPv4 and IPv6 together) with a base chain on each of those three hooks, every rule matched
  on the port's name, therefore covers all IP traffic of the port and nothing else.
* Each chain has ``policy accept`` and only rules that match the port, so traffic of every other interface (the OSPF core
  links, VLAN 200, the eBGP uplink, the Containerlab management interface) is untouched.  An accept in this table cannot
  override a drop elsewhere, so other filtering is never weakened.
* ``forward``: the device may reach only the bootstrap service's HTTP port and answer SSH from the service host; everything
  else forwarded from or to the port (IPv4 and IPv6, any protocol) is counted and dropped.  That is the production and
  lateral denial.
* ``input`` / ``output``: only DHCP to / from the relay and IPv6 neighbour discovery.  OSPF / OSPFv3 hellos (IP protocol
  89), RIP, BGP, SSH, SNMP and every other service of the upstream are counted and dropped in both directions, so no
  adjacency can form before admission (premature OSPF) and the upstream's management plane is closed to the device.
* IS-IS is not IP: nftables ``inet`` cannot filter it, so IS-IS on the port is refused, never assumed suppressed.
* ISC dhcrelay sends and receives on the client side with a packet socket, which is below netfilter: the relay works whether
  or not the DHCP rules exist, and the device can always talk DHCP to the relay (the one flow that is meant to be open).

Re-sending ``table inet X { ... }`` to nft MERGES (it duplicates every rule; observed), so the table is created only when it
is absent, and an exact listing is "already enforced".  Anything this module cannot prove becomes a blocker; nothing is
guessed.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re

PLATFORM = "ubuntu_frr"
TABLE_PREFIX = "nmas_iso_"
FAMILY = "inet"
CHAINS = ("forward", "input", "output")
HOOK_FAMILIES = ("ip", "ip6")
MIN_NFT = (1, 0, 0)
SSH_PORT = 22
_INTERFACE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,14}$")          # Linux IFNAMSIZ (15) and no quoting characters
_TABLE = re.compile(rf"^{TABLE_PREFIX}dev\d{{6}}$")
_COUNTER = re.compile(r"counter packets \d+ bytes \d+")
RELAY_PROGRAMS = ("dhcrelay",)
REFUSED_KINDS = ("bridge", "bond", "vlan", "vrf", "macvlan", "ipvlan", "team", "vxlan", "gre", "gretap", "ip6gre", "ipip", "sit", "wireguard")
UNSUPPORTED_PORT_PROTOCOLS = {"ip router isis": "IS-IS", "ipv6 router isis": "IS-IS", "ip router openfabric": "OpenFabric",
                              "isis circuit-type": "IS-IS"}


class RenderError(ValueError):
    def __init__(self, code: str, detail: str = ""):
        super().__init__(code)
        self.code, self.detail = code, str(detail)[:200]


def _problem(code: str, detail: str = "") -> dict:
    return {"code": code, "detail": str(detail)[:200]}


def digest(value) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode()).hexdigest()


def table_name(device_id: str) -> str:
    """The reserved table of one device's policy: ``nmas_iso_dev000123`` (unique per device record, never reused)."""
    if not re.fullmatch(r"DEV-\d{6}", device_id or ""):
        raise RenderError("ISOLATION_DEVICE_INELIGIBLE", "malformed device id")
    return f"{TABLE_PREFIX}dev{device_id[4:]}"


# ---------------------------------------------------------------------------------------------------------------- rendering
def chain_rules(port: str, bootstrap: dict) -> dict:
    """{chain: [rule, ...]} in the exact form ``nft list`` prints them (counter values aside)."""
    if not _INTERFACE.fullmatch(port or ""):
        raise RenderError("INTERFACE_INVALID", port)
    prefix = str(ipaddress.ip_network(bootstrap["prefix"], strict=True))
    service = str(ipaddress.ip_address(bootstrap["service_address"]))
    http = int(bootstrap["http_port"])
    if ipaddress.ip_network(prefix).version != 4 or ipaddress.ip_address(service).version != 4 or not 0 < http < 65536:
        raise RenderError("ISOLATION_BOOTSTRAP_NETWORK_MISMATCH", "an IPv4 bootstrap prefix, service and HTTP port are required")
    q = f'"{port}"'
    return {
        "forward": [f"iifname {q} ip saddr {prefix} ip daddr {service} tcp dport {http} accept",
                    # only REPLIES of an NMAS-initiated SSH session: a bare "tcp sport 22" let a device that forges its
                    # source port reach any port of the service host (found live, V2 Phase 9)
                    f"iifname {q} ip saddr {prefix} ip daddr {service} tcp sport {SSH_PORT} ct state established,related accept",
                    f"iifname {q} counter drop",
                    f"oifname {q} ip saddr {service} ip daddr {prefix} tcp sport {http} accept",
                    f"oifname {q} ip saddr {service} ip daddr {prefix} tcp dport {SSH_PORT} accept",
                    f"oifname {q} counter drop"],
        "input": [f"iifname {q} udp sport 68 udp dport 67 accept",
                  f"iifname {q} ip6 saddr fe80::/10 icmpv6 type {{ nd-router-solicit, nd-neighbor-solicit, nd-neighbor-advert }} accept",
                  f"iifname {q} counter drop"],
        "output": [f"oifname {q} udp sport 67 udp dport 68 accept",
                   f"oifname {q} icmpv6 type {{ nd-router-advert, nd-neighbor-solicit, nd-neighbor-advert }} accept",
                   f"oifname {q} counter drop"],
    }


def render_table(table: str, port: str, bootstrap: dict) -> list[str]:
    """The whole table as one nft statement (created in a single atomic kernel transaction)."""
    if not _TABLE.fullmatch(table or ""):
        raise RenderError("ISOLATION_DEVICE_INELIGIBLE", "malformed table name")
    lines = [f"table {FAMILY} {table} {{"]
    for chain, rules in chain_rules(port, bootstrap).items():
        lines += [f"  chain {chain} {{", f"    type filter hook {chain} priority filter; policy accept;", *[f"    {r}" for r in rules], "  }"]
    return [*lines, "}"]


def delete_statement(table: str) -> list[str]:
    if not _TABLE.fullmatch(table or ""):
        raise RenderError("ISOLATION_DEVICE_INELIGIBLE", "malformed table name")
    return [f"delete table {FAMILY} {table}"]


_FIRST_RULE = re.compile(r'^iifname "(?P<port>[^"]+)" ip saddr (?P<prefix>[0-9./]+) ip daddr (?P<service>[0-9.]+) tcp dport (?P<http>\d+) accept$')


def parse_table(lines) -> dict | None:
    """The executor's strict gate: ``lines`` must be EXACTLY ``render_table`` of the parameters they name, else None."""
    body = [str(line).rstrip() for line in lines if str(line).strip()]
    if len(body) < 5:
        return None
    head = re.fullmatch(rf"table {FAMILY} ({TABLE_PREFIX}dev\d{{6}}) \{{", body[0])
    first = _FIRST_RULE.fullmatch(body[3].strip()) if head else None
    if not first:
        return None
    params = {"table": head.group(1), "port": first["port"],
              "bootstrap": {"prefix": first["prefix"], "service_address": first["service"], "http_port": int(first["http"])}}
    try:
        if render_table(params["table"], params["port"], params["bootstrap"]) != body:
            return None
    except (RenderError, ValueError):
        return None
    return params


def parse_delete(lines) -> str | None:
    body = [str(line).strip() for line in lines if str(line).strip()]
    match = re.fullmatch(rf"delete table {FAMILY} ({TABLE_PREFIX}dev\d{{6}})", body[0]) if len(body) == 1 else None
    return match.group(1) if match else None


def normalize_listing(text: str) -> list[str]:
    """``nft list table`` text -> comparable lines: indentation, blank lines and counter values removed."""
    return [_COUNTER.sub("counter", line.strip()) for line in (text or "").splitlines() if line.strip()]


def _op(key: str, kind: str, lines: list[str], inverse: list[str], paths: list[str], description: str) -> dict:
    return {"key": key, "kind": kind, "lines": list(lines), "inverse": list(inverse), "paths": list(paths), "description": description,
            "platform": PLATFORM}


def render_apply(intent: dict) -> list[dict]:
    """One operation: the whole NMAS table, atomically.  Its inverse deletes exactly that table (nothing else is touched)."""
    element = intent["elements"]["PACKET_FILTER"]
    lines = render_table(element["table"], intent["upstream"]["interface"], intent["bootstrap"])
    return [_op("nft-table", "ADD", lines, delete_statement(element["table"]), [f"nft table {FAMILY} {element['table']}"],
                f"nftables isolation of {intent['upstream']['interface']} (forward, input, output; IPv4 and IPv6)")]


def render_release(intent: dict) -> list[dict]:
    """The removal of exactly what ``render_apply`` added; its restore path re-creates the table (a failed admission)."""
    applied = render_apply(intent)[0]
    return [_op("release-nft-table", "REMOVE", applied["inverse"], applied["lines"], applied["paths"], f"release: {applied['description']}")]


# ------------------------------------------------------------------------------------------------------------- snapshot facts
def nft_version(text: str) -> tuple[int, ...] | None:
    match = re.search(r"nftables v(\d+)\.(\d+)\.(\d+)", text or "")
    return tuple(int(x) for x in match.groups()) if match else None


def link(snapshot: dict, name: str) -> dict | None:
    return next((row for row in snapshot.get("links") or [] if row.get("ifname") == name), None)


def _kind(row: dict) -> str:
    return str(((row or {}).get("linkinfo") or {}).get("info_kind") or "")


def port_facts(snapshot: dict, port: str) -> dict:
    row = link(snapshot, port)
    facts = {"exists": row is not None, "kind": _kind(row), "master": "", "children": [], "ipv4": [], "ipv6": [], "up": False,
             "default_route": False}
    if row is None:
        return facts
    facts["master"] = str(row.get("master") or "")
    facts["up"] = "UP" in (row.get("flags") or [])
    facts["children"] = sorted(r.get("ifname") for r in snapshot.get("links") or [] if r.get("link") == port and r.get("ifname") != port)
    for address in row.get("addr_info") or []:
        local, family = address.get("local"), address.get("family")
        if not local:
            continue
        text = f"{local}/{address.get('prefixlen')}"
        if family == "inet":
            facts["ipv4"].append(text)
        elif family == "inet6" and not ipaddress.ip_address(local).is_link_local:
            facts["ipv6"].append(text)
    facts["ipv4"].sort()
    facts["ipv6"].sort()
    facts["default_route"] = any(r.get("dst") == "default" and r.get("dev") == port for r in (snapshot.get("routes4") or []) + (snapshot.get("routes6") or []))
    return facts


def relays_for(snapshot: dict, port: str, service: str) -> list[str]:
    """Running relay processes that serve ``port`` (``-i`` / ``-id``) and forward to ``service``."""
    found = []
    for cmdline in snapshot.get("processes") or []:
        argv = str(cmdline).split()
        if not argv or argv[0].rsplit("/", 1)[-1] not in RELAY_PROGRAMS:
            continue
        ports = {argv[i + 1] for i, token in enumerate(argv[:-1]) if token in ("-i", "-id")}
        if port in ports and service in argv[1:]:
            found.append(" ".join(argv)[:160])
    return found


def frr_interface_lines(frr_text: str, port: str) -> list[str]:
    lines, inside = [], False
    for raw in (frr_text or "").splitlines():
        if not raw.strip() or raw.strip().startswith("!"):
            continue
        if not raw.startswith(" "):
            inside = raw.strip() in (f"interface {port}", f"interface {port} vrf default")
            continue
        if inside:
            lines.append(raw.strip())
    return lines


def _covers(network_text: str, addresses: list[str]) -> bool:
    try:
        network = ipaddress.ip_network(network_text, strict=False)
    except ValueError:
        return True
    return any(ipaddress.ip_interface(a).ip in network for a in addresses if ipaddress.ip_interface(a).version == network.version)


def routing_on_port(frr_text: str, port: str, addresses: list[str]) -> dict:
    """Routing configured on the port: IP protocols (dropped by the filter) and non-IP ones (refused)."""
    facts = {"filtered": [], "unsupported": []}
    for line in frr_interface_lines(frr_text, port):
        for prefix, protocol in UNSUPPORTED_PORT_PROTOCOLS.items():
            if line.startswith(prefix) and protocol not in facts["unsupported"]:
                facts["unsupported"].append(protocol)
        if line.startswith("ip ospf area"):
            facts["filtered"].append("OSPF")
        elif line.startswith("ipv6 ospf6 area"):
            facts["filtered"].append("OSPFv3")
        elif line.startswith("ip rip") or line.startswith("ipv6 ripng"):
            facts["filtered"].append("RIP")
    header = ""
    for raw in (frr_text or "").splitlines():
        if raw and not raw.startswith(" "):
            header = raw.strip()
            continue
        line = raw.strip()
        if header.startswith(("router ospf", "router rip")) and line.startswith("network ") and len(line.split()) >= 2 \
                and _covers(line.split()[1], addresses):
            facts["filtered"].append("OSPF" if header.startswith("router ospf") else "RIP")
    facts["filtered"] = sorted(set(facts["filtered"]))
    return facts


def foreign_references(ruleset_text: str, table: str, port: str) -> list[str]:
    """Other nftables tables that already name the port (their interplay with ours is not evaluated: refused)."""
    found, current = [], ""
    for line in (ruleset_text or "").splitlines():
        head = re.match(r"^table (\S+) (\S+) \{", line)
        if head:
            current = f"{head.group(1)} {head.group(2)}"
            continue
        if current and current != f"{FAMILY} {table}" and f'"{port}"' in line:
            found.append(current)
    return sorted(set(found))


def route_via_port(snapshot: dict, port: str) -> list[str]:
    """Routes whose next hop leaves through the port, other than the port's own connected / link-local / multicast routes."""
    leaked = []
    for row in (snapshot.get("routes4") or []) + (snapshot.get("routes6") or []):
        if row.get("dev") != port and not any((nh or {}).get("dev") == port for nh in row.get("nexthops") or []):
            continue
        dst = str(row.get("dst") or "")
        if row.get("protocol") == "kernel" or dst.startswith(("fe80:", "ff00:", "multicast")) or row.get("type") in ("multicast", "local", "broadcast"):
            continue
        try:
            leaked.append(str(ipaddress.ip_network(dst, strict=False)))       # ``ip -j route`` prints host routes without /32
        except ValueError:
            leaked.append(dst)
    return sorted(set(leaked))


def lockout(snapshot: dict, port: str) -> list[str]:
    """NMAS sources whose route on the upstream leaves through the port (the filter would cut NMAS off)."""
    return sorted(source for source, dev in (snapshot.get("route_get") or {}).items() if dev in (port, ""))


# ------------------------------------------------------------------------------------------------------------- capabilities
def capability_problems(snapshot: dict) -> list[dict]:
    """The primitives this enforcement needs, each proven on the upstream (never inferred from the platform name)."""
    missing = []
    version = nft_version(snapshot.get("nft_version") or "")
    if version is None or version < MIN_NFT:
        missing.append(f"nftables >= {'.'.join(map(str, MIN_NFT))} (found: {(snapshot.get('nft_version') or 'none')[:40]})")
    if not snapshot.get("nft_check_ok"):
        missing.append("the kernel refused an inet filter table on the forward / input / output hooks (nft --check)")
    if not snapshot.get("hooks_listable"):
        missing.append("nft list hooks (the active-hook proof)")
    if snapshot.get("nft_json") is None:
        missing.append("nft JSON listing")
    if not snapshot.get("frr"):
        missing.append("vtysh running configuration")
    if snapshot.get("links") is None:
        missing.append("iproute2 JSON link listing")
    return [_problem("ISOLATION_PLATFORM_NOT_IMPLEMENTED", f"capability missing: {item}") for item in missing]


# ------------------------------------------------------------------------------------------------------------- intent
def build(*, device_id: str, upstream: str, interface: str, network, snapshot: dict, nmas_sources=()) -> tuple[dict, list, list, dict]:
    """-> (intent, apply operations, problems, facts) for an Ubuntu/FRR upstream, from one read-only snapshot."""
    problems = capability_problems(snapshot)
    port = port_facts(snapshot, interface)
    facts = {"port": port, "capabilities": {"nft_version": (snapshot.get("nft_version") or "")[:40], "nft_check_ok": bool(snapshot.get("nft_check_ok")),
                                            "hooks_listable": bool(snapshot.get("hooks_listable"))}}
    if problems:
        return {}, [], problems, facts
    if not _INTERFACE.fullmatch(interface or "") or not port["exists"]:
        return {}, [], [_problem("ISOLATION_PORT_NOT_FOUND", interface)], facts
    if interface == "lo" or port["kind"] in REFUSED_KINDS or port["master"]:
        problems.append(_problem("ISOLATION_PORT_NOT_ROUTED", f"{interface} is {port['kind'] or 'a link'}"
                                                              f"{' enslaved to ' + port['master'] if port['master'] else ''}: a dedicated routed port is required"))
    if port["children"]:
        problems.append(_problem("ISOLATION_PORT_SHARED", f"subinterfaces on {interface}: {port['children'][:4]}"))
    if port["default_route"]:
        problems.append(_problem("ISOLATION_PORT_SHARED", f"the upstream's default route leaves through {interface}"))
    if not port["ipv4"]:
        problems.append(_problem("ISOLATION_PORT_NO_ADDRESS", interface))
    prefix = str(ipaddress.ip_network(network.ipv4_prefix, strict=False))
    on_port = {str(ipaddress.ip_interface(a).network) for a in port["ipv4"]}
    gateways = {str(ipaddress.ip_interface(a).ip) for a in port["ipv4"]}
    if prefix not in on_port or network.gateway not in gateways:
        problems.append(_problem("ISOLATION_BOOTSTRAP_NETWORK_MISMATCH", f"{interface} is not {network.gateway} on {prefix}"))
    other = sorted(a for a in port["ipv4"] if str(ipaddress.ip_interface(a).network) != prefix)   # IPv6 on the port is dropped by the filter
    if other:
        problems.append(_problem("ISOLATION_PORT_SHARED", f"{interface} carries other addresses: {other[:4]}"))
    relays = relays_for(snapshot, interface, network.service_address)
    facts["relays"] = relays
    if not relays:
        problems.append(_problem("ISOLATION_BOOTSTRAP_NETWORK_MISMATCH", f"no DHCP relay on {interface} forwards to {network.service_address}"))
    table = table_name(device_id)
    foreign = foreign_references(snapshot.get("nft_text") or "", table, interface)
    if foreign:
        problems.append(_problem("ISOLATION_FOREIGN_ACL", f"{interface} is already filtered by {foreign[:3]}"))
    if (snapshot.get("table_listing") or {}).get(table) is not None:
        problems.append(_problem("ISOLATION_NAME_COLLISION", f"table {FAMILY} {table} already exists"))
    routing = routing_on_port(snapshot.get("frr") or "", interface, port["ipv4"] + port["ipv6"])
    facts["routing"] = routing
    for protocol in routing["unsupported"]:
        problems.append(_problem("ISOLATION_ROUTING_UNSUPPORTED", f"{protocol} on {interface} is not IP and cannot be filtered by nftables"))
    leaked = route_via_port(snapshot, interface)
    if leaked:
        problems.append(_problem("ISOLATION_PORT_SHARED", f"routes already leave through {interface}: {leaked[:4]}"))
    cut = lockout(snapshot, interface)
    facts["management"] = {"nmas_sources": list(nmas_sources), "routed_via_port": cut}
    if cut:
        problems.append(_problem("ISOLATION_MGMT_PLANE_EXPOSED", f"NMAS's own source {cut[0]} is routed through {interface}"))
    bootstrap = {"prefix": prefix, "service_address": network.service_address, "http_port": int(network.http_port)}
    intent = {
        "schema": 1, "device": device_id,
        "upstream": {"device": upstream, "interface": interface, "platform": PLATFORM, "vrf": ""},
        "bootstrap": bootstrap,
        "elements": {
            "L2": {"mode": "VERIFY", "routed_port": True, "kind": port["kind"]},
            "PACKET_FILTER": {"family": FAMILY, "table": table, "chains": list(CHAINS), "hook_families": list(HOOK_FAMILIES)},
            "IPV4": {"forward": "service HTTP + service SSH only, then drop", "input": "DHCP to the relay only, then drop"},
            "IPV6": {"forward": "drop", "input": "neighbour discovery from link-local only, then drop"},
            "CONTROL_PLANE": {"mode": "PACKET_FILTER", "filtered_on_port": routing["filtered"]},
            "MANAGEMENT_PLANE": {"mode": "INPUT_FILTER", "nmas_sources": sorted(nmas_sources)},
        },
    }
    if problems:
        return intent, [], problems, facts
    try:
        ops = render_apply(intent)
    except RenderError as exc:
        return intent, [], [_problem(exc.code if exc.code.startswith("ISOLATION_") else "ISOLATION_PLATFORM_NOT_IMPLEMENTED", exc.detail)], facts
    return intent, ops, [], facts


# ------------------------------------------------------------------------------------------------------------- read-back
def hooks_registered(hooks_text: str, table: str) -> dict:
    """{family: sorted chains} of this table's chains the kernel lists on their hooks (``nft list hooks``)."""
    found: dict = {}
    family = ""
    for line in (hooks_text or "").splitlines():
        head = re.match(r"^family (\S+) \{", line)
        if head:
            family = head.group(1)
            continue
        match = re.search(rf"chain {FAMILY} {re.escape(table)} (\S+) \[nf_tables\]", line)
        if match and family:
            found.setdefault(family, set()).add(match.group(1))
    return {k: sorted(v) for k, v in found.items()}


def chain_heads(table_json) -> dict:
    """{chain: {type, hook, prio, policy}} from ``nft -j list table``."""
    heads = {}
    for item in (table_json or {}).get("nftables") or []:
        chain = item.get("chain") if isinstance(item, dict) else None
        if chain:
            heads[chain.get("name")] = {k: chain.get(k) for k in ("type", "hook", "prio", "policy")}
    return heads


def read_back(intent: dict, snapshot: dict) -> tuple[bool, dict]:
    """Is EXACTLY the intended table in place, with each base chain on its hook in both families?"""
    table = intent["elements"]["PACKET_FILTER"]["table"]
    listing = (snapshot.get("table_listing") or {}).get(table)
    wanted = normalize_listing("\n".join(render_table(table, intent["upstream"]["interface"], intent["bootstrap"])))
    got = normalize_listing(listing) if listing is not None else None
    heads = chain_heads((snapshot.get("table_json") or {}).get(table))
    hooks = hooks_registered(snapshot.get("hooks") or "", table)
    heads_ok = all(heads.get(c) == {"type": "filter", "hook": c, "prio": 0, "policy": "accept"} for c in CHAINS) and len(heads) == len(CHAINS)
    hooks_ok = all(hooks.get(f) == sorted(CHAINS) for f in HOOK_FAMILIES)
    facts = {"present": got is not None, "exact": got == wanted, "chains": heads, "hooks": hooks,
             "extra": sorted(set(got or []) - set(wanted))[:10], "missing": sorted(set(wanted) - set(got or []))[:10]}
    return bool(got == wanted and heads_ok and hooks_ok), facts


def presence(intent: dict, snapshot: dict) -> dict:
    """{operation key: PRESENT | ABSENT | PARTIAL} -- PARTIAL is a table of the reserved name that is not exactly ours."""
    table = intent["elements"]["PACKET_FILTER"]["table"]
    listing = (snapshot.get("table_listing") or {}).get(table)
    if listing is None:
        return {"nft-table": "ABSENT"}
    exact = normalize_listing(listing) == normalize_listing("\n".join(render_table(table, intent["upstream"]["interface"], intent["bootstrap"])))
    return {"nft-table": "PRESENT" if exact else "PARTIAL"}


def deny_counters(table_json) -> dict:
    """{chain: packets} of the table's drop rules (the enforcement point's own evidence of denied traffic)."""
    found = {}
    for item in (table_json or {}).get("nftables") or []:
        rule = item.get("rule") if isinstance(item, dict) else None
        if not rule:
            continue
        exprs = rule.get("expr") or []
        if any(isinstance(e, dict) and "drop" in e for e in exprs):
            packets = sum(int((e.get("counter") or {}).get("packets") or 0) for e in exprs if isinstance(e, dict) and "counter" in e)
            found[rule.get("chain")] = found.get(rule.get("chain"), 0) + packets
    return found


def ospf_neighbors_on(neighbors_json: str, port: str) -> list[dict]:
    """``show ip ospf neighbor json`` / ``show ipv6 ospf6 neighbor json`` rows on ``port`` (FRR 8.4 shapes)."""
    try:
        data = json.loads(neighbors_json or "{}")
    except ValueError:
        return [{"neighbor": "?", "state": "UNREADABLE"}]
    rows = []
    groups = data.get("neighbors") if isinstance(data, dict) else None
    if isinstance(groups, dict):                                     # ospfd: {"neighbors": {rid: [ {...} ]}}
        for rid, entries in groups.items():
            for entry in entries if isinstance(entries, list) else [entries]:
                if str((entry or {}).get("ifaceName") or "").split(":", 1)[0] == port:
                    rows.append({"neighbor": rid, "state": str(entry.get("nbrState") or "")[:24]})
    elif isinstance(groups, list):                                   # ospf6d: {"neighbors": [ {...} ]}
        for entry in groups:
            if (entry or {}).get("interfaceName") == port:
                rows.append({"neighbor": entry.get("neighborId", ""), "state": str(entry.get("state") or "")[:24]})
    return rows


def config_findings(intent: dict, snapshot: dict, port: str) -> dict:
    """{kind: (ok, code, facts)} for READ_BACK, L2 and MANAGEMENT_PLANE of an enforced FRR policy."""
    ok, facts = read_back(intent, snapshot)
    current = port_facts(snapshot, port)
    l2_ok = current["exists"] and not current["master"] and not current["children"] and current["kind"] not in REFUSED_KINDS \
        and not current["default_route"]
    foreign = foreign_references(snapshot.get("nft_text") or "", intent["elements"]["PACKET_FILTER"]["table"], port)
    cut = lockout(snapshot, port)
    input_ok = facts["exact"] and "input" in (facts["hooks"].get("ip") or []) and "input" in (facts["hooks"].get("ip6") or [])
    return {"READ_BACK": (ok and not foreign, "ISOLATION_DRIFTED", {**facts, "foreign": foreign}),
            "L2": (l2_ok, "ISOLATION_DRIFTED", {"kind": current["kind"], "master": current["master"], "children": current["children"]}),
            "MANAGEMENT_PLANE": (input_ok and not cut, "ISOLATION_MGMT_PLANE_EXPOSED",
                                 {"input_chain_enforced": input_ok, "nmas_routed_via_port": cut})}


def routing_findings(intent: dict, snapshot: dict, port: str) -> tuple[bool, str, dict]:
    """No adjacency on the port, no route learned through it, and nothing on it that nftables cannot filter."""
    routing = routing_on_port(snapshot.get("frr") or "", port, port_facts(snapshot, port)["ipv4"])
    neighbors = ospf_neighbors_on(snapshot.get("ospf_neighbors") or "", port) + ospf_neighbors_on(snapshot.get("ospf6_neighbors") or "", port)
    leaked = route_via_port(snapshot, port)
    readable = snapshot.get("routes4") is not None and snapshot.get("routes6") is not None
    facts = {"filtered_on_port": routing["filtered"], "unsupported": routing["unsupported"], "neighbors": neighbors, "leaked": leaked}
    ok = readable and not routing["unsupported"] and not neighbors and not leaked
    return ok, ("ISOLATION_LEAK" if readable else "ISOLATION_UPSTREAM_UNREADABLE"), facts


def neighbor_entry(neigh_json, address: str) -> dict:
    """The upstream's neighbour entry for ``address`` (``ip -j neigh``) -> {mac, interface}; {} if none or not resolved."""
    for row in neigh_json or []:
        if row.get("dst") == address and row.get("lladdr") and "FAILED" not in (row.get("state") or []):
            return {"mac": str(row["lladdr"]).lower(), "interface": row.get("dev", "")}
    return {}
