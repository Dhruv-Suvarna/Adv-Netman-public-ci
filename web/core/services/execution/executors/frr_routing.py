"""Reusable FRR routing-operation primitives shared by OSPF, RIP/RIPng and BGP.

One strict grammar, one running-configuration reader and one inverse generator serve every FRR routing process, so a
protocol is a table row rather than a separate executor:

* ``parse``     Configlet lines -> ``Block`` objects (process or interface header, leaves, BGP address-family leaves).
                Anything outside the per-context leaf patterns refuses the whole Configlet.
* ``commands``  a Block -> the ordered ``vtysh -c`` command list (process enter/create, leaves, AF enter/exit).
* ``tree``      ``show running-config`` -> the captured semantic state the inverse is derived from.
* ``conflict``  why an operation must be refused outright (FRR runs a single default-VRF BGP autonomous system).
* ``process_inverse``  captured-state inverse: a process absent before apply is removed as a whole; under an existing
                process only provably additive leaves are removed, each by its own ``no`` form.  A leaf that would
                replace an existing value (router-id, RIP version, a neighbor's remote AS) or change how unrelated
                sessions behave has no safe inverse and returns ``None`` (the caller fails closed).

Platform semantics kept explicit: FRR activates a new neighbor for IPv4 unicast by default, so an IPv4 ``activate``
under an existing neighbor is already satisfied unless the configuration says otherwise; ``no neighbor X remote-as``
removes the neighbor with all of its address-family leaves.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

_NAME = r"[A-Za-z0-9_.-]{1,32}"
_IP4 = r"\d{1,3}(?:\.\d{1,3}){3}"
_ADDR = r"[0-9A-Fa-f:.]{2,45}"
_PREFIX = r"[0-9A-Fa-f:.]{2,45}/\d{1,3}"
_ASN = r"[1-9]\d{0,9}"

EXIT_AF = "exit-address-family"
# Process-wide BGP settings the feature template renders (as the tracked R3/R4 configurations do).  They change how
# EVERY neighbor of the process behaves, so they are only ever applied together with a process this plan creates.
PROCESS_SETTINGS = ("no bgp default ipv4-unicast", "no bgp ebgp-requires-policy")
_AF = re.compile(r"^address-family (ipv4|ipv6) unicast$")
_INTERFACE = re.compile(rf"^(?:no )?interface {_NAME}$")
_PROCESS = re.compile(rf"^(?:no )?router (?:(ospf6?|rip|ripng)|(bgp) {_ASN}|(?P<isis>isis {_NAME}))$")
_NEIGHBOR = re.compile(rf"^neighbor ({_ADDR}) (.+)$")

# context -> the only leaves the Jinja feature templates and their captured-state inverses may emit there
_LEAVES = {
    "interface": re.compile(r"^(?:no )?(?:ip ospf (?:area [0-9.]+|cost \d+|network point-to-point)|"
                            rf"ipv6 ospf6 (?:area [0-9.]+|cost \d+|network point-to-point)|"
                            rf"(?:ip|ipv6) router isis {_NAME}|"
                            r"isis (?:network point-to-point|circuit-type (?:level-1|level-2-only|level-1-2)|metric \d+|passive))$"),
    "ospf": re.compile(rf"^(?:no )?(?:ospf router-id {_IP4}|network {_PREFIX} area [0-9.]+)$"),
    "ospf6": re.compile(rf"^(?:no )?ospf6 router-id {_IP4}$"),
    "rip": re.compile(rf"^(?:no )?(?:version 2|network {_NAME}|passive-interface {_NAME})$"),
    "ripng": re.compile(rf"^(?:no )?(?:network {_NAME}|passive-interface {_NAME})$"),
    "isis": re.compile(r"^(?:no )?(?:net 49\.[0-9.]+|is-type (?:level-1|level-2-only|level-1-2)|metric-style wide)$"),
    "bgp": re.compile(rf"^(?:{'|'.join(map(re.escape, PROCESS_SETTINGS))}|(?:no )?(?:bgp router-id {_IP4}|"
                      rf"neighbor {_ADDR} (?:remote-as {_ASN}|update-source {_NAME}|ebgp-multihop \d{{1,3}}|shutdown)))$"),
    "bgp-af": re.compile(rf"^(?:no )?(?:neighbor {_ADDR} (?:activate|next-hop-self|route-reflector-client)|"
                         rf"network {_PREFIX})$"),
}
# single-valued leaves: a different configured value means the Configlet REPLACES state another object depends on
_SCALARS = ("bgp router-id ", "ospf router-id ", "ospf6 router-id ", "version ", "net ", "is-type ", "metric-style ")
_NEIGHBOR_SCALARS = ("update-source ", "ebgp-multihop ")
DAEMONS = {"ospf": "ospfd", "ospf6": "ospf6d", "rip": "ripd", "ripng": "ripngd", "bgp": "bgpd", "isis": "isisd"}


@dataclass
class Block:
    header: str
    kind: str                                              # interface | ospf | ospf6 | rip | ripng | bgp
    leaves: list[str] = field(default_factory=list)
    families: dict[str, list[str]] = field(default_factory=dict)   # "address-family ipv4 unicast" -> leaves
    sequence: list[str] = field(default_factory=list)      # the vtysh commands in Configlet order, context included


def _kind(header: str) -> str | None:
    if _INTERFACE.fullmatch(header):
        return "interface"
    found = _PROCESS.fullmatch(header)
    return (found.group(1) or found.group(2) or ("isis" if found.group("isis") else None)) if found else None


def parse(lines) -> list[Block] | None:
    """Strict grammar: every line must be a known header, a leaf of that header's context, or a BGP AF bracket."""
    blocks: list[Block] = []
    family = ""
    for raw in lines:
        line = raw.strip()
        if not line or line == "!":
            continue
        if not raw.startswith(" "):
            kind = _kind(line)
            if kind is None:
                return None
            if family:                                     # a differential may omit the closing bracket
                blocks[-1].sequence.append(EXIT_AF)
                family = ""
            blocks.append(Block(line, kind, sequence=[line]))
            continue
        if not blocks:
            return None
        block = blocks[-1]
        if block.kind == "bgp" and _AF.fullmatch(line):
            if family:
                block.sequence.append(EXIT_AF)
            family = line
            block.families.setdefault(family, [])
        elif line == EXIT_AF:
            if not family:
                return None
            family = ""
        elif family:
            if not _LEAVES["bgp-af"].fullmatch(line):
                return None
            block.families[family].append(line)
        elif not _LEAVES[block.kind].fullmatch(line):
            return None
        else:
            block.leaves.append(line)
        block.sequence.append(line)
    if family:
        blocks[-1].sequence.append(EXIT_AF)
    return blocks or None


def commands(block: Block) -> list[str]:
    """The vtysh command sequence of one block; every block re-enters its own context (process enter/create)."""
    return list(block.sequence)


def required_daemons(blocks) -> set[str]:
    return {"zebra", *(DAEMONS[b.kind] for b in blocks if b.kind in DAEMONS)}


def tree(running_text: str) -> dict[str, dict[str, list[str]]]:
    """``show running-config`` -> {top-level header: {"": leaves, "address-family ...": leaves}} (lenient reader)."""
    result: dict[str, dict[str, list[str]]] = {}
    current, family = None, ""
    for raw in running_text.splitlines():
        line = raw.strip()
        if not line or line.startswith("!"):
            continue
        if not raw.startswith(" "):
            family = ""
            current = None if line in {"exit", "end"} else result.setdefault(line, {"": []})
        elif current is not None:
            if _AF.fullmatch(line):
                family = line
                current.setdefault(family, [])
            elif line == EXIT_AF:
                family = ""
            elif line != "exit":
                current[family].append(line)
    return result


def conflict(blocks, running: dict) -> str:
    """A fixed reason when the operation cannot be attempted at all, else ''."""
    for block in blocks:
        if block.kind == "bgp" and block.header not in running and any(
                re.fullmatch(rf"router bgp {_ASN}", header) for header in running):
            return "BGP_PROCESS_CONFLICT"       # FRR refuses a second default-VRF autonomous system
    return ""


def _neighbor_exists(address: str, leaves) -> bool:
    return any(leaf.startswith(f"neighbor {address} remote-as ") for leaf in leaves)


def process_inverse(block: Block, running: dict, *, pending_ok: bool = False) -> list[str] | None:
    """Captured-state inverse of one routing-process block (Configlet form), [] when already satisfied, None if unprovable.

    ``pending_ok``: a neighbor leaf may name a neighbor another Configlet of the same plan is about to create (preflight
    runs before any apply).  The caller must derive the inverse again, strictly, right before it applies the block.
    """
    wanted = [*block.leaves, *(leaf for leaves in block.families.values() for leaf in leaves)]
    if block.header.startswith("no ") or any(leaf.startswith("no ") and leaf not in PROCESS_SETTINGS for leaf in wanted):
        return None
    if block.header not in running:
        return [f"no {block.header}"]                      # process removal: it did not exist before apply
    existing = running[block.header]
    top = existing[""]
    created = set()                                        # neighbors this block creates; removed with all their leaves
    for leaf in block.leaves:
        found = _NEIGHBOR.fullmatch(leaf)
        if found and found.group(2).startswith("remote-as ") and leaf not in top:
            if any(other.startswith(f"neighbor {found.group(1)} ") for other in top):
                return None                                # would change an existing neighbor's remote AS
            created.add(found.group(1))
    undo = Block(block.header, block.kind)
    for leaf in block.leaves:
        if leaf in top:
            continue
        if leaf in PROCESS_SETTINGS:
            return None                                    # would change how every existing neighbor behaves
        if any(leaf.startswith(stem) and any(other.startswith(stem) for other in top) for stem in _SCALARS):
            return None
        found = _NEIGHBOR.fullmatch(leaf)
        if found and not found.group(2).startswith("remote-as "):
            address, attribute = found.groups()
            if address in created:
                continue
            if (not _neighbor_exists(address, top) and not pending_ok) or any(
                    attribute.startswith(stem) and any(other.startswith(f"neighbor {address} {stem}") for other in top)
                    for stem in _NEIGHBOR_SCALARS):
                return None
        undo.leaves.insert(0, f"no {leaf}")
    default_v4 = "no bgp default ipv4-unicast" not in top
    for family, leaves in block.families.items():
        have = existing.get(family, [])
        for leaf in leaves:
            if leaf in have:
                continue
            found = _NEIGHBOR.fullmatch(leaf)
            if found:
                address, attribute = found.groups()
                if address in created:
                    continue
                if not _neighbor_exists(address, top):
                    if not pending_ok:
                        return None
                elif attribute == "activate" and family.startswith("address-family ipv4") and default_v4 \
                        and f"no neighbor {address} activate" not in have:
                    continue                               # implicit FRR default: already active, nothing to undo
            undo.families.setdefault(family, []).insert(0, f"no {leaf}")
    if not undo.leaves and not any(undo.families.values()):
        return []
    # address-family leaves are removed before the process-level objects they reference
    result = [undo.header]
    for family, leaves in undo.families.items():
        if leaves:
            result += [f"   {family}", *(f"      {leaf}" for leaf in leaves), f"   {EXIT_AF}"]
    return result + [f"   {leaf}" for leaf in undo.leaves]
