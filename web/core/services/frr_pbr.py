"""NMAS policy-based routing realised as FRR ``pbrd`` configuration (V2 Phase 9): the one grammar the renderer, the import
parser and the tests share.

A policy is one ``pbr-map`` whose sequences each select traffic by source and/or destination prefix and send it to one
next-hop address; an attachment applies the map to the traffic received on one interface (``pbr-policy``, IN only):

    pbr-map CAP_PBR seq 10
       match src-ip 198.51.100.0/24
       set nexthop 198.18.7.2
    !
    interface eth3
       pbr-policy CAP_PBR

Rendered only in forms FRR 8.4.4 lists back unchanged and installs (``show pbr map``: valid / installed).  Refused with
the reason, never approximated: an ``ip-protocol`` match (FRR 8.4.4 cannot resolve a protocol name without
``/etc/protocols`` and the lab runtime has none, so it is not proven), a next-hop interface, a sequence with no match
(``pbrd`` never installs it), and an address of the other family.  A sequence is accepted on read only if re-rendering
the entry parsed from it gives the same lines, so the grammar is exact.
"""

from __future__ import annotations

import ipaddress
import re

NAME = re.compile(r"[A-Za-z0-9_.-]{1,32}")           # frr_routing._NAME: what the executor grammar accepts
INTERFACE = re.compile(r"[A-Za-z0-9_.-]{1,15}")
MAX_SEQUENCE = 700                                   # FRR: pbr-map seq 1-700
INDENT = "   "
_ANY_PROTOCOL = {"", "IP", "IPV6", "ANY"}
_HEADER = re.compile(r"pbr-map (" + NAME.pattern + r") seq (\d{1,3})")
_LEAF = re.compile(r"(match src-ip|match dst-ip|set nexthop) (\S+)")


class PbrRenderError(ValueError):
    """The policy has no exact ``pbrd`` realisation; the message says why (shown in the refusal marker)."""


def _version(family: str) -> int:
    if family not in ("IPV4", "IPV6"):
        raise PbrRenderError("unknown PBR family")
    return 4 if family == "IPV4" else 6


def _prefix(family: str, value) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    try:
        network = ipaddress.ip_network(text, strict=False)
    except ValueError:
        network = None
    if network is None or network.version != _version(family):
        raise PbrRenderError(f"prefix {text!r} is not an {family} prefix")
    return str(network)


def sequence_lines(family: str, entry: dict) -> list[str]:
    """The leaves of one sequence (``match`` then ``set``), 3-space indented; raises ``PbrRenderError``."""
    try:
        sequence = int(entry.get("sequence"))
    except (TypeError, ValueError):
        sequence = 0
    if not 1 <= sequence <= MAX_SEQUENCE:
        raise PbrRenderError(f"a sequence number must be 1-{MAX_SEQUENCE}")
    if str(entry.get("protocol") or "").upper() not in _ANY_PROTOCOL:
        raise PbrRenderError("an ip-protocol match is not proven on this runtime")
    if entry.get("output_interface_id"):
        raise PbrRenderError("a next-hop interface is not supported")
    source = _prefix(family, entry.get("source_prefix"))
    destination = _prefix(family, entry.get("destination_prefix"))
    if not (source or destination):
        raise PbrRenderError("a sequence needs a source or destination prefix (pbrd never installs one without)")
    try:
        next_hop = ipaddress.ip_address(str(entry.get("next_hop") or "").strip())
    except ValueError:
        next_hop = None
    if next_hop is None or next_hop.version != _version(family):
        raise PbrRenderError(f"next hop {entry.get('next_hop')!r} is not an {family} address")
    lines = [f"{INDENT}match src-ip {source}"] if source else []
    if destination:
        lines.append(f"{INDENT}match dst-ip {destination}")
    return [*lines, f"{INDENT}set nexthop {next_hop}"]


def sequences(policy: dict) -> list[tuple[int, list[str]]]:
    """[(sequence number, leaves)] of one policy in order; raises ``PbrRenderError`` (an empty policy is valid here)."""
    family = policy.get("family")
    _version(family)
    if not NAME.fullmatch(str(policy.get("name") or "")):
        raise PbrRenderError("the policy name is not a valid pbr-map name")
    rows = sorted((policy.get("sequences") or {}).values(), key=lambda row: (int(row.get("sequence") or 0), row.get("id", "")))
    numbers = [int(row.get("sequence") or 0) for row in rows]
    if len(set(numbers)) != len(numbers):
        raise PbrRenderError("two sequences share a number, so their order is ambiguous")
    return [(number, sequence_lines(family, row)) for number, row in zip(numbers, rows)]


def refusal(policy: dict) -> str:
    """Why this policy cannot be rendered exactly ("" when it can)."""
    try:
        sequences(policy)
    except PbrRenderError as exc:
        return str(exc)
    return ""


def attachment_lines(interface: str, name: str) -> list[str]:
    """The interface block applying policy ``name``; raises ``PbrRenderError`` for an invalid interface or policy name."""
    if not INTERFACE.fullmatch(str(interface or "")) or not NAME.fullmatch(str(name or "")):
        raise PbrRenderError("an attachment needs a valid interface name and policy name")
    return [f"interface {interface}", f"{INDENT}pbr-policy {name}"]


def parse_block(block) -> tuple[str, dict] | None:
    """One running-configuration ``pbr-map NAME seq N`` block -> (name, entry), or None when it is not exactly the shape
    NMAS renders (any other leaf, a duplicate leaf, mixed families)."""
    lines = [line.strip() for line in block if line.strip() and line.strip() not in ("!", "exit")]
    found = _HEADER.fullmatch(lines[0]) if lines else None
    if not found:
        return None
    leaves = {}
    for line in lines[1:]:
        match = _LEAF.fullmatch(line)
        if not match or match.group(1) in leaves:
            return None
        leaves[match.group(1)] = match.group(2)
    hop = leaves.get("set nexthop", "")
    family = "IPV6" if ":" in hop else "IPV4"
    entry = {"sequence": int(found.group(2)), "source_prefix": leaves.get("match src-ip", ""),
             "destination_prefix": leaves.get("match dst-ip", ""), "protocol": "IP", "next_hop": hop,
             "output_interface_id": "", "family": family}
    try:
        rendered = sequence_lines(family, entry)
    except PbrRenderError:
        return None
    return (found.group(1), entry) if [line.strip() for line in rendered] == lines[1:] else None
