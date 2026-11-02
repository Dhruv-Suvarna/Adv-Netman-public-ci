"""NMAS ACL intent realised as nftables on Ubuntu/FRR (V2 Phase 9): the one grammar the renderer, the Linux executor, the
health read and the import parser share.

One dedicated table holds everything NMAS writes:

    table inet DEVICE_BUILDER_ACL {
        chain acl4_<NAME> {                 # one regular chain per ACL; ``acl6_`` for an IPv6 list
            ip saddr 198.18.0.66 drop comment "seq 10"
            accept comment "seq 20"
            drop comment "implicit-deny STANDARD"
        }
        chain filter_in {                   # attachments IN: every packet received on the interface
            type filter hook prerouting priority filter; policy accept;
            iifname "eth1" meta nfproto ipv4 jump acl4_<NAME>
        }
        chain filter_out {                  # attachments OUT: every packet sent out of the interface
            type filter hook postrouting priority filter; policy accept;
            oifname "eth1" meta nfproto ipv4 jump acl4_<NAME>
        }
    }

Semantics follow the router-ACL convention the other platforms use: entries are evaluated in sequence order, the first
match decides, and an unmatched packet is dropped by the explicit final ``implicit-deny`` rule (which also records the
list type, so import recovers it).  An IPv6 list permits neighbour solicitation / advertisement just before that
final drop, as IOS-style IPv6 ACLs do, so attaching a list cannot silently break neighbour discovery on the link.  The
family guard lives on the jump (``meta nfproto``), never inside the list: nftables 1.0.9 drops a redundant
``meta nfproto`` from some rules when it lists them, so a rule carrying one would not read back as written.

Rules are rendered only in forms that nftables lists back unchanged, except that the protocol of ``meta l4proto`` is
listed by name when ``/etc/protocols`` exists and as a number when it does not; ``normalize_rule`` folds both.  A rule
is accepted on read only if re-rendering the entry parsed from it gives the same text, so the grammar is exact.
"""

from __future__ import annotations

import ipaddress
import re

TABLE = "DEVICE_BUILDER_ACL"
TABLE_HEADER = f"table inet {TABLE} {{"
# direction -> (hook chain, netfilter hook, interface match)
HOOKS = {"IN": ("filter_in", "prerouting", "iifname"), "OUT": ("filter_out", "postrouting", "oifname")}
_HOOK_DIRECTION = {chain: direction for direction, (chain, _hook, _match) in HOOKS.items()}
# family -> (chain-name digit, address keyword, meta nfproto value)
FAMILIES = {"IPV4": ("4", "ip", "ipv4"), "IPV6": ("6", "ip6", "ipv6")}
_FAMILY_OF = {"ipv4": "IPV4", "ipv6": "IPV6"}
_PROTOCOL_NUMBER = {"IPV4": {"TCP": "6", "UDP": "17", "ICMP": "1", "ICMPV6": "1"},
                    "IPV6": {"TCP": "6", "UDP": "17", "ICMP": "58", "ICMPV6": "58"}}
_ANY_PROTOCOL = {"IPV4": "IP", "IPV6": "IPV6"}
_PROTOCOL_NAMES = {"tcp": "6", "udp": "17", "icmp": "1", "ipv6-icmp": "58"}
ND_RULE = 'icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert } accept comment "implicit-nd"'
NAME = re.compile(r"[A-Za-z][A-Za-z0-9_.-]{0,63}")
INTERFACE = re.compile(r"[A-Za-z0-9_.-]{1,15}")
_PORT = re.compile(r"(\d{1,5})(?:-(\d{1,5}))?")
_CHAIN = re.compile(r"chain (\S+) \{")
_ACL_CHAIN = re.compile(r"acl([46])_(" + NAME.pattern + ")")
_RULE = re.compile(
    r"(?:(?P<sl3>ip6?) saddr (?P<src>\S+) )?(?:(?P<dl3>ip6?) daddr (?P<dst>\S+) )?(?:meta l4proto (?P<proto>\d+) )?"
    r"(?:(?P<sl4>tcp|udp) sport (?P<sport>\S+) )?(?:(?P<dl4>tcp|udp) dport (?P<dport>\S+) )?"
    r'(?P<log>log )?(?P<verdict>accept|drop) comment "seq (?P<seq>\d{1,9})"')
_JUMP = re.compile(r'(iifname|oifname) "(' + INTERFACE.pattern + r')" meta nfproto (ipv4|ipv6) jump (\S+)')
_DENY = re.compile(r'drop comment "implicit-deny (STANDARD|EXTENDED)"')


class AclRenderError(ValueError):
    """The ACL intent has no exact nftables realisation; the message says why (shown in the refusal marker)."""


def chain_name(family: str, name: str) -> str:
    return f"acl{FAMILIES[family][0]}_{name}"


def implicit_deny(acl_type: str) -> str:
    return f'drop comment "implicit-deny {acl_type}"'


def hook_header(direction: str) -> str:
    chain, hook, _match = HOOKS[direction]
    return f"chain {chain} {{", f"type filter hook {hook} priority filter; policy accept;"


def jump_rule(direction: str, interface: str, family: str, chain: str) -> str:
    return f'{HOOKS[direction][2]} "{interface}" meta nfproto {FAMILIES[family][2]} jump {chain}'


def _address(family: str, kind, value) -> str:
    kind = str(kind or "ANY").upper()
    if kind == "ANY":
        return ""
    version = 4 if family == "IPV4" else 6
    try:
        if kind == "HOST":
            address = ipaddress.ip_address(str(value or "").strip())
            if address.version == version:
                return str(address)
        elif kind == "PREFIX":
            network = ipaddress.ip_network(str(value or "").strip(), strict=False)
            if network.version == version:
                # nft lists a full-length prefix as the bare address
                return str(network.network_address) if network.prefixlen == network.max_prefixlen else str(network)
    except ValueError:
        pass
    raise AclRenderError(f"{kind.lower()} {value!r} is not an {family} {'address' if kind == 'HOST' else 'prefix'}")


def _port(value) -> str:
    text = str(value if value is not None else "").strip()
    if not text:
        return ""
    match = _PORT.fullmatch(text)
    start, end = (int(match.group(1)), int(match.group(2) or match.group(1))) if match else (1, 0)
    if not 0 < start <= end <= 65535:
        raise AclRenderError(f"port {text!r} is not a port or ascending port range")
    return str(start) if start == end else f"{start}-{end}"


def entry_rule(family: str, acl_type: str, entry: dict) -> str:
    """One ACL entry as the nft rule NMAS writes (raises ``AclRenderError`` when no exact realisation exists)."""
    action = {"PERMIT": "accept", "DENY": "drop"}.get(str(entry.get("action") or "").upper())
    try:
        sequence = int(entry.get("sequence"))
    except (TypeError, ValueError):
        sequence = -1
    if action is None or not 0 <= sequence <= 999_999_999:
        raise AclRenderError("an entry needs PERMIT or DENY and a sequence number")
    keyword = FAMILIES[family][1]
    parts = []
    source = _address(family, entry.get("source_type"), entry.get("source_value"))
    if source:
        parts.append(f"{keyword} saddr {source}")
    if acl_type == "EXTENDED":
        destination = _address(family, entry.get("destination_type"), entry.get("destination_value"))
        if destination:
            parts.append(f"{keyword} daddr {destination}")
        protocol = str(entry.get("protocol") or "IP").upper()
        sport, dport = _port(entry.get("source_port")), _port(entry.get("destination_port"))
        if protocol not in ("IP", "IPV6") and protocol not in _PROTOCOL_NUMBER[family]:
            raise AclRenderError(f"protocol {protocol} is not an ACL protocol")
        if (sport or dport) and protocol not in ("TCP", "UDP"):
            raise AclRenderError("a port match needs protocol TCP or UDP")
        layer4 = protocol.lower()
        if sport:
            parts.append(f"{layer4} sport {sport}")
        if dport:
            parts.append(f"{layer4} dport {dport}")
        if not (sport or dport) and protocol in _PROTOCOL_NUMBER[family]:
            parts.append(f"meta l4proto {_PROTOCOL_NUMBER[family][protocol]}")
    if entry.get("logging"):
        parts.append("log")
    parts.append(f'{action} comment "seq {sequence}"')
    return " ".join(parts)


def acl_rules(acl: dict) -> list[str]:
    """Every rule of one ACL's chain, in order, ending with the implicit deny (raises ``AclRenderError``)."""
    family, acl_type = acl.get("family"), acl.get("acl_type")
    if family not in FAMILIES or acl_type not in ("STANDARD", "EXTENDED"):
        raise AclRenderError("unknown ACL family or type")
    if not NAME.fullmatch(str(acl.get("name") or "")):
        raise AclRenderError("the ACL name is not a valid chain name")
    entries = sorted((acl.get("entries") or {}).values(), key=lambda row: (int(row.get("sequence") or 0), row.get("id", "")))
    sequences = [int(row.get("sequence") or 0) for row in entries]
    if len(set(sequences)) != len(sequences):
        raise AclRenderError("two entries share a sequence number, so their order is ambiguous")
    rules = [entry_rule(family, acl_type, row) for row in entries]
    if family == "IPV6":
        rules.append(ND_RULE)
    rules.append(implicit_deny(acl_type))
    return rules


def refusal(acl: dict) -> str:
    """Why this ACL cannot be rendered exactly ("" when it can)."""
    try:
        acl_rules(acl)
    except AclRenderError as exc:
        return str(exc)
    return ""


def normalize_rule(text: str) -> str:
    """A listed rule in the rendered spelling: whitespace collapsed, ``meta l4proto`` names folded to numbers."""
    text = " ".join(str(text).split())
    return re.sub(r"\bmeta l4proto (tcp|udp|icmp|ipv6-icmp)\b", lambda m: f"meta l4proto {_PROTOCOL_NAMES[m.group(1)]}", text)


def parse_rule(family: str, acl_type: str, text: str) -> dict | None:
    """The intent entry of one listed rule, or None when the rule is not exactly what NMAS renders for that entry."""
    rule = normalize_rule(text)
    match = _RULE.fullmatch(rule)
    if not match:
        return None
    by_number = {number: name for name, number in _PROTOCOL_NUMBER[family].items() if name in ("TCP", "UDP")}
    by_number[_PROTOCOL_NUMBER[family]["ICMP"]] = "ICMP" if family == "IPV4" else "ICMPV6"
    protocol = match.group("sl4") or match.group("dl4") or by_number.get(match.group("proto") or "", "")
    if match.group("proto") and match.group("proto") not in by_number:
        return None

    def term(value):
        return ("ANY", "") if value is None else (("PREFIX" if "/" in value else "HOST"), value)

    source_type, source_value = term(match.group("src"))
    destination_type, destination_value = term(match.group("dst"))
    entry = {"sequence": int(match.group("seq")), "action": "PERMIT" if match.group("verdict") == "accept" else "DENY",
             "protocol": protocol.upper() or _ANY_PROTOCOL[family], "source_type": source_type, "source_value": source_value,
             "destination_type": destination_type, "destination_value": destination_value,
             "source_port": match.group("sport") or "", "destination_port": match.group("dport") or "",
             "logging": bool(match.group("log"))}
    try:
        return entry if entry_rule(family, acl_type, entry) == rule else None
    except AclRenderError:
        return None


def _acl_chain(chain: str, body: list[str]) -> dict | None:
    match = _ACL_CHAIN.fullmatch(chain)
    family = {"4": "IPV4", "6": "IPV6"}[match.group(1)] if match else ""
    deny = _DENY.fullmatch(normalize_rule(body[-1])) if match and body else None
    if not deny:
        return None
    acl_type, rules = deny.group(1), [normalize_rule(line) for line in body[:-1]]
    if family == "IPV6":
        if not rules or rules[-1] != ND_RULE:
            return None
        rules = rules[:-1]
    entries = [parse_rule(family, acl_type, line) for line in rules]
    if not all(entries) or [e["sequence"] for e in entries] != sorted({e["sequence"] for e in entries}):
        return None
    return {"name": match.group(2), "family": family, "acl_type": acl_type, "entries": entries,
            "rules": [*rules, *((ND_RULE,) if family == "IPV6" else ()), implicit_deny(acl_type)]}


def _hook_chain(chain: str, body: list[str]) -> list | None:
    direction = _HOOK_DIRECTION.get(chain)
    if direction is None or tuple(normalize_rule(line) for line in body[:1]) != hook_header(direction)[1:]:
        return None
    jumps = []
    for line in body[1:]:
        match = _JUMP.fullmatch(normalize_rule(line))
        if not match or match.group(1) != HOOKS[direction][2] or not _ACL_CHAIN.fullmatch(match.group(4)) \
                or match.group(4)[3] != FAMILIES[_FAMILY_OF[match.group(3)]][0]:
            return None
        jump = (match.group(2), _FAMILY_OF[match.group(3)], match.group(4))
        if any(other[:2] == jump[:2] for other in jumps):
            return None                      # two lists of one family on one interface and direction: ambiguous
        jumps.append(jump)
    return jumps


def parse_table(lines, *, snippet: bool = False) -> dict | None:
    """The NMAS ACL table -> {"acls": {chain: {...}}, "hooks": {"IN": [(interface, family, chain)], "OUT": [...]}}, or None.

    ``snippet`` accepts what a Configlet carries: the table header and its closing brace are optional (a planner diff
    repeats the header, the offline fixture diff does not) and a jump may name a chain defined elsewhere.  Comment
    lines (``#`` / ``!``) are ignored; anything else that is not exactly the NMAS shape refuses the whole table."""
    body = [line.strip() for line in lines if line.strip() and not line.lstrip().startswith(("#", "!"))]
    if body[:1] == [TABLE_HEADER]:
        body = body[1:]
        if body[-1:] == ["}"] and (len(body) < 2 or body[-2] == "}"):
            body = body[:-1]
        elif not snippet:
            return None
    elif not snippet:
        return None
    model = {"acls": {}, "hooks": {"IN": [], "OUT": []}, "hook_chains": []}
    cursor = 0
    while cursor < len(body):
        header = _CHAIN.fullmatch(body[cursor])
        try:
            end = body.index("}", cursor + 1)
        except ValueError:
            return None
        if not header or header.group(1) in model["acls"] or header.group(1) in model["hook_chains"]:
            return None
        chain, block = header.group(1), body[cursor + 1:end]
        if chain in _HOOK_DIRECTION:
            jumps = _hook_chain(chain, block)
            if jumps is None:
                return None
            model["hook_chains"].append(chain)
            model["hooks"][_HOOK_DIRECTION[chain]].extend(jumps)
        else:
            acl = _acl_chain(chain, block)
            if acl is None:
                return None
            model["acls"][chain] = acl
        cursor = end + 1
    if not snippet and any(jump[2] not in model["acls"] for jumps in model["hooks"].values() for jump in jumps):
        return None
    return model


def table_from_ruleset(ruleset: str):
    """The NMAS ACL table in a listed ruleset: None when absent, False when a table of that name is not the NMAS shape."""
    lines = (ruleset or "").splitlines()
    start = next((i for i, line in enumerate(lines) if line.rstrip() == TABLE_HEADER), None)
    if start is None:
        return None
    end = next((i for i in range(start + 1, len(lines)) if lines[i].startswith("}")), None)
    model = parse_table(lines[start:end + 1]) if end is not None else None
    return model if model is not None else False


# --- nft transactions (built only from parsed, validated tokens) -----------------------------------------------------
def create_chain_commands(chain: str, rules) -> str:
    return f"create chain inet {TABLE} {chain}\n" + "".join(f"add rule inet {TABLE} {chain} {rule}\n" for rule in rules)


def replace_chain_commands(chain: str, rules) -> str:
    return f"flush chain inet {TABLE} {chain}\n" + "".join(f"add rule inet {TABLE} {chain} {rule}\n" for rule in rules)


def create_hook_commands(direction: str) -> str:
    chain, hook, _match = HOOKS[direction]
    return f"create chain inet {TABLE} {chain} {{ type filter hook {hook} priority filter; policy accept; }}\n"


def jump_commands(direction: str, jumps) -> str:
    return "".join(f"add rule inet {TABLE} {HOOKS[direction][0]} {jump_rule(direction, *jump)}\n" for jump in jumps)
