"""Semantic objects over the line index: what each line IS, what it references, and whether it may be removed.

Pure.  Every recognised construct becomes a :class:`ConfigObject` with a stable id (``kind:key``), the line numbers
it owns, the objects it references, and an explicit removability verdict with a reason.  Anything not recognised is
UNMANAGED and protected -- the workbench never removes configuration it cannot safely understand.

Management-plane protection is structural, not a denylist of text: the management SVI / interfaces, VLAN 200, and
static routes towards the management networks are PROTECTED, and every unmanaged top-level stanza (users, AAA,
management APIs, SNMP, logging ...) is PROTECTED, so an ACL they reference can never be removed out from under them.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field

from . import structure
from .structure import Node

REMOVE_DELETE = "REMOVE_DELETE"
DEACTIVATE_DETACH = "DEACTIVATE_DETACH"
REDACTION_MARKERS = ("<REDACTED", "********")

MANAGEMENT_INTERFACES = frozenset({"vlan200"})
MANAGEMENT_VLANS = frozenset({1, 200})
MANAGEMENT_NETWORKS = (ipaddress.ip_network("192.168.200.0/24"), ipaddress.ip_network("2001:db8:200::/64"))
ALL_VLANS = "vlan:*"
ANY_ACL = "acl:*"      # a redacted ``snmp-server community`` line may name an ACL we cannot see

# Removability reasons (stable codes shown to the operator)
PROTECTED_MANAGEMENT = "PROTECTED_MANAGEMENT_PLANE"
UNMANAGED = "UNMANAGED_CONFIGURATION"
PHYSICAL = "PHYSICAL_INTERFACE_NOT_DELETABLE"
NEGATED = "NEGATED_LINE_NOT_REMOVABLE"
WIDENS = "REMOVAL_WOULD_WIDEN_TRUNK_TO_ALL_VLANS"
PRIMARY_WITH_SECONDARIES = "PRIMARY_ADDRESS_HAS_SECONDARIES"
REDACTED = "REDACTED_VALUE_NOT_REMOVABLE"
IDENTITY = "IDENTITY_LINE_REMOVE_WHOLE_OBJECT"
UNRECOGNISED_ATTRIBUTE = "UNRECOGNISED_ATTRIBUTE"


@dataclass
class ConfigObject:
    id: str
    kind: str
    label: str
    node: Node | None                 # header / identity line (None for a virtual named object such as a route-map)
    lines: list[int]                  # every line this object owns (children included)
    parent_id: str | None = None
    operation: str = REMOVE_DELETE
    removable: bool = True
    reason: str = ""
    protected: bool = False
    references: set[str] = field(default_factory=set)
    removal_lines: list[str] = field(default_factory=list)
    members: list[str] = field(default_factory=list)   # virtual objects: the ids of their concrete parts
    owned_nodes: list[Node] = field(default_factory=list, repr=False)

    @property
    def restore_lines(self) -> list[str]:
        """Enclosing headers + every original line the object owns (the exact text to re-add for compensation).

        Sibling-grouped objects (a BGP neighbor's several ``neighbor X ...`` lines, a VRRP group) own lines that are
        not descendants of the identity line, so the owned nodes are recorded explicitly.
        """
        if self.node is None:
            return []
        headers = [n.text for n in self.node.ancestors()]
        return [*headers, *(n.text for n in sorted(self.owned_nodes, key=lambda n: n.number))]

    @property
    def restorable(self) -> bool:
        return bool(self.restore_lines) and not any(m in line for line in self.restore_lines for m in REDACTION_MARKERS)

    @property
    def absent_paths(self) -> list[str]:
        if self.kind == "vlan":
            return [f"vlan {self.id.split(':', 1)[1]}"]
        return [self.node.path()] if self.node is not None else []


_ATTRIBUTE_KINDS = (
    (re.compile(r"^description "), "description"), (re.compile(r"^mtu "), "mtu"),
    (re.compile(r"^switchport trunk native vlan "), "native_vlan"), (re.compile(r"^neighbor \S+ "), "neighbor_attribute"),
    (re.compile(r"^passive-interface "), "passive_interface"), (re.compile(r"^ip ospf "), "ip_ospf"),
    (re.compile(r"^(match|set) "), "route_map_clause"), (re.compile(r"^ip rip "), "ip_rip"),
)


def attribute_kind(statement: str) -> str:
    for pattern, kind in _ATTRIBUTE_KINDS:
        if pattern.match(statement):
            return kind
    return "other"


@dataclass
class Attribute:
    """A removable-or-not child line that is not an object of its own (line-range granular removal)."""

    number: int
    owner_id: str
    removable: bool
    reason: str = ""
    removal_lines: list[str] = field(default_factory=list)
    references: set[str] = field(default_factory=set)
    kind: str = "other"


@dataclass
class ConfigModel:
    platform: str
    tree: structure.Tree
    objects: dict[str, ConfigObject]
    attributes: dict[int, Attribute]
    owner_of_line: dict[int, str]       # line -> most specific object id owning it

    @staticmethod
    def _refers(references: set[str], target_id: str) -> bool:
        return (target_id in references or (target_id.startswith("vlan:") and ALL_VLANS in references)
                or (target_id.startswith("acl:") and ANY_ACL in references))

    def referrers(self, target_id: str) -> list[str]:
        found = []
        for obj in self.objects.values():
            if obj.id != target_id and self._refers(obj.references, target_id):
                found.append(obj.id)
        for attr in self.attributes.values():
            if self._refers(attr.references, target_id):
                found.append(f"attr:{attr.number}")
        return sorted(set(found))

    def label_of(self, ref: str) -> str:
        if ref.startswith("attr:"):
            node = self.tree.node(int(ref.split(":", 1)[1]))
            return f"line {node.number}: {node.stripped}" if node else ref
        obj = self.objects.get(ref)
        return obj.label if obj else ref

    def lines_of(self, ref: str) -> list[int]:
        if ref.startswith("attr:"):
            return [int(ref.split(":", 1)[1])]
        obj = self.objects.get(ref)
        return list(obj.lines) if obj else []

    def descendants_of(self, object_id: str) -> set[str]:
        found, frontier = set(), [object_id]
        while frontier:
            current = frontier.pop()
            for obj in self.objects.values():
                if obj.parent_id == current and obj.id not in found:
                    found.add(obj.id)
                    frontier.append(obj.id)
        return found


# --------------------------------------------------------------------------------------------------------------------
_IFACE = re.compile(r"^interface (\S+)$")
_VLAN = re.compile(r"^vlan ([\d,\-]+)$")
_ROUTE = re.compile(r"^(ip|ipv6) route (\S+)(?: (\S+))?")
_BGP = re.compile(r"^router bgp (\d+(?:\.\d+)?)$")
_OSPF = re.compile(r"^router ospf(?: (\d+))?$")
_OSPF6 = re.compile(r"^(?:ipv6 router ospf (\d+)|router ospf6)$")
_RIP = re.compile(r"^router (rip|ripng)$")
_ACL = re.compile(r"^(ip|ipv6) access-list (?:(standard) )?(\S+)$")
_FRR_ACL_LINE = re.compile(r"^access-list (\S+) (?:seq (\d+) )?(permit|deny|remark)\b")
_ROUTE_MAP = re.compile(r"^route-map (\S+) (permit|deny) (\d+)$")
_PREFIX_LIST = re.compile(r"^(ip|ipv6) prefix-list (\S+)$")
_PREFIX_LINE = re.compile(r"^(ip|ipv6) prefix-list (\S+) seq (\d+) ")
_PBR_POLICY = re.compile(r"^policy-map type pbr (\S+)$")
_PBR_CLASS = re.compile(r"^class-map type pbr match-(?:any|all) (\S+)$")
_NAT_POOL = re.compile(r"^ip nat pool (\S+)\b")

_MGMT_IF = re.compile(r"^management\d", re.I)


def _is_ip(text: str) -> bool:
    try:
        ipaddress.ip_address(text)
        return True
    except ValueError:
        return False


def _touches_management(text: str) -> bool:
    for token in str(text).split():
        try:
            value = ipaddress.ip_interface(token) if "/" in token else ipaddress.ip_address(token)
        except ValueError:
            continue
        network = value.network if hasattr(value, "network") else None
        address = value.ip if hasattr(value, "ip") else value
        for mgmt in MANAGEMENT_NETWORKS:
            if address.version == mgmt.version and (address in mgmt or (network is not None and network.overlaps(mgmt))):
                return True
    return False


def _indent_unit(platform: str) -> str:
    return " " if platform == "ubuntu_frr" else "   "


def _child_removal(node: Node, statement: str) -> list[str]:
    """Enclosing headers + ``no <statement>`` at the child's own indentation."""
    return [*(n.text for n in node.ancestors()), " " * node.indent + "no " + statement]


class _Builder:
    def __init__(self, text: str, platform: str):
        self.platform = platform
        self.tree = structure.parse(text)
        self.objects: dict[str, ConfigObject] = {}
        self.attributes: dict[int, Attribute] = {}
        self.owner: dict[int, str] = {}
        self.named: dict[str, set[str]] = {"acl": set(), "route_map": set(), "prefix_list": set(), "pbr_policy": set(), "pbr_class": set()}

    # -- registration -----------------------------------------------------------------------------------------------
    def add(self, obj: ConfigObject) -> ConfigObject:
        if obj.id in self.objects:  # duplicate identity (e.g. a repeated stanza): keep the first, fold the lines in
            existing = self.objects[obj.id]
            existing.lines = sorted(set(existing.lines) | set(obj.lines))
            existing.owned_nodes = [self.tree.node(n) for n in existing.lines if self.tree.node(n) is not None]
            return existing
        self.objects[obj.id] = obj
        obj.owned_nodes = [self.tree.node(n) for n in obj.lines if self.tree.node(n) is not None]
        for number in obj.lines:
            current = self.owner.get(number)
            # the most specific owner wins: a child object's lines override its parent's
            if current is None or len(self.objects[current].lines) >= len(obj.lines):
                self.owner[number] = obj.id
        return obj

    def attribute(self, node: Node, owner_id: str, *, removable: bool, reason: str = "", references=(), statement: str | None = None):
        if removable and any(m in node.text for m in REDACTION_MARKERS):
            removable, reason = False, REDACTED
        if removable and node.stripped.startswith("no "):
            removable, reason = False, NEGATED
        self.attributes[node.number] = Attribute(
            number=node.number, owner_id=owner_id, removable=removable, reason=reason,
            removal_lines=_child_removal(node, statement or node.stripped) if removable else [], references=set(references),
            kind=attribute_kind(node.stripped),
        )
        self.owner.setdefault(node.number, owner_id)

    def virtual(self, kind: str, name: str, member_id: str, label: str) -> None:
        vid = f"{kind}:{name}"
        obj = self.objects.get(vid)
        if obj is None:
            obj = self.objects[vid] = ConfigObject(id=vid, kind=kind, label=label, node=None, lines=[])
        obj.members.append(member_id)
        obj.lines = sorted(set(obj.lines) | set(self.objects[member_id].lines))
        self.named.setdefault(kind, set()).add(name)

    # -- top level --------------------------------------------------------------------------------------------------
    def build(self) -> ConfigModel:
        for root in self.tree.roots:
            self.top(root)
        self.protect_management_routes()
        self.scan_named_references()
        self.finish_virtual()
        return ConfigModel(self.platform, self.tree, self.objects, self.attributes, self.owner)

    def top(self, node: Node) -> None:
        text = node.stripped
        span = node.span()
        if node.terminator:
            return
        if (m := _IFACE.match(text)):
            return self.interface(node, m.group(1))
        if (m := _VLAN.match(text)):
            for vid in structure.vlan_ids(m.group(1)):
                protected = vid in MANAGEMENT_VLANS
                self.add(ConfigObject(
                    id=f"vlan:{vid}", kind="vlan", label=f"VLAN {vid}", node=node, lines=span,
                    removable=not protected, reason=PROTECTED_MANAGEMENT if protected else "", protected=protected,
                    removal_lines=[f"no vlan {vid}"],
                ))
            for child in node.children:
                self.attribute(child, self.owner.get(node.number, ""), removable=False, reason=UNRECOGNISED_ATTRIBUTE)
            return
        if (m := _ROUTE.match(text)):
            protected = _touches_management(text)
            self.add(ConfigObject(
                id=f"static_route:{structure.normalize(text)}", kind="static_route", label=text, node=node, lines=span,
                removable=not protected, reason=PROTECTED_MANAGEMENT if protected else "", protected=protected,
                removal_lines=[f"no {text}"],
            ))
            return
        if (m := _BGP.match(text)):
            return self.router_bgp(node, m.group(1))
        if (m := _OSPF.match(text)):
            return self.router_simple(node, "ospf_process", f"ospf_process:{m.group(1) or '0'}", f"OSPF process {m.group(1) or ''}".strip())
        if (m := _OSPF6.match(text)):
            return self.router_simple(node, "ospf3_process", f"ospf3_process:{m.group(1) or '0'}", f"OSPFv3 process {m.group(1) or ''}".strip())
        if (m := _RIP.match(text)):
            return self.router_simple(node, "rip_process", f"rip_process:{m.group(1)}", "RIP" if m.group(1) == "rip" else "RIPng")
        if (m := _ACL.match(text)):
            return self.acl(node, m.group(3), m.group(1), standard=bool(m.group(2)))
        if (m := _FRR_ACL_LINE.match(text)):
            name, seq = m.group(1), m.group(2) or str(node.number)
            obj = self.add(ConfigObject(id=f"acl_entry:{name}/{seq}", kind="acl_entry", label=f"ACL {name} entry {seq}", node=node,
                                        lines=span, removal_lines=[f"no {text}"]))
            self.virtual("acl", name, obj.id, f"ACL {name}")
            return
        if (m := _ROUTE_MAP.match(text)):
            name, action, seq = m.groups()
            obj = self.add(ConfigObject(id=f"route_map_entry:{name}/{seq}", kind="route_map_entry", label=f"route-map {name} {action} {seq}",
                                        node=node, lines=span, removal_lines=[f"no route-map {name} {action} {seq}"]))
            for child in node.children:
                refs = self.match_references(child.stripped)
                self.attribute(child, obj.id, removable=True, references=refs)
                obj.references |= refs
            self.virtual("route_map", name, obj.id, f"route-map {name}")
            return
        if (m := _PREFIX_LIST.match(text)):
            family, name = m.groups()
            self.named["prefix_list"].add(name)
            for child in node.children:
                seq = re.match(r"^seq (\d+) ", child.stripped)
                if not seq:
                    self.attribute(child, "", removable=False, reason=UNRECOGNISED_ATTRIBUTE)
                    continue
                obj = self.add(ConfigObject(id=f"prefix_list_entry:{name}/{seq.group(1)}", kind="prefix_list_entry",
                                            label=f"prefix-list {name} seq {seq.group(1)}", node=child, lines=child.span(),
                                            removal_lines=_child_removal(child, f"seq {seq.group(1)}")))
                self.virtual("prefix_list", name, obj.id, f"prefix-list {name}")
            if not node.children:
                self.add(ConfigObject(id=f"prefix_list:{name}", kind="prefix_list", label=f"prefix-list {name} (empty)", node=node,
                                      lines=span, removal_lines=[f"no {family} prefix-list {name}"]))
            else:
                self.owner[node.number] = f"prefix_list:{name}"
            return
        if (m := _PREFIX_LINE.match(text)):
            name, seq = m.group(2), m.group(3)
            obj = self.add(ConfigObject(id=f"prefix_list_entry:{name}/{seq}", kind="prefix_list_entry", label=f"prefix-list {name} seq {seq}",
                                        node=node, lines=span, removal_lines=[f"no {text}"]))
            self.virtual("prefix_list", name, obj.id, f"prefix-list {name}")
            return
        if (m := _PBR_POLICY.match(text)):
            return self.pbr_policy(node, m.group(1))
        if (m := _PBR_CLASS.match(text)):
            name = m.group(1)
            obj = self.add(ConfigObject(id=f"pbr_class:{name}", kind="pbr_class", label=f"PBR class-map {name}", node=node, lines=span,
                                        removal_lines=[f"no {text}"]))
            self.named["pbr_class"].add(name)
            for child in node.children:
                refs = self.match_references(child.stripped)
                obj.references |= refs
                self.attribute(child, obj.id, removable=False, reason=UNRECOGNISED_ATTRIBUTE, references=refs)
            return
        if (m := _NAT_POOL.match(text)):
            self.add(ConfigObject(id=f"nat_pool:{m.group(1)}", kind="nat_pool", label=f"NAT pool {m.group(1)}", node=node, lines=span,
                                  removal_lines=[f"no ip nat pool {m.group(1)}"]))
            return
        # Anything else is unmanaged and protected; it may still REFERENCE named objects (found by the token scan).
        self.add(ConfigObject(id=f"unmanaged:{node.number}", kind="unmanaged", label=text, node=node, lines=span,
                              removable=False, reason=UNMANAGED, protected=True))
        for child in node.descendants():
            self.attribute(child, f"unmanaged:{node.number}", removable=False, reason=UNMANAGED)

    # -- interfaces -------------------------------------------------------------------------------------------------
    def interface(self, node: Node, name: str) -> None:
        lower = name.lower()
        svi = re.fullmatch(r"vlan(\d+)", lower)
        protected = lower in MANAGEMENT_INTERFACES or bool(_MGMT_IF.match(lower))
        if svi:
            kind = "svi"
        elif lower.startswith("loopback") or (self.platform == "ubuntu_frr" and lower.startswith("dummy")):
            kind = "loopback"
        elif "." in name:
            kind = "subinterface"
        elif lower.startswith("port-channel"):
            kind = "port_channel"
        elif protected:
            kind = "management_interface"
        else:
            kind = "physical_interface"
        removable = kind in ("svi", "loopback", "subinterface", "port_channel") and not protected
        reason = PROTECTED_MANAGEMENT if protected else ("" if removable else PHYSICAL)
        iface = self.add(ConfigObject(
            id=f"interface:{name}", kind=kind, label=f"interface {name}", node=node, lines=node.span(),
            removable=removable, reason=reason, protected=protected, removal_lines=[f"no interface {name}"],
        ))
        if svi:
            iface.references.add(f"vlan:{svi.group(1)}")
        secondaries = [c for c in node.children if re.match(r"^ip address \S+ secondary$", c.stripped)]
        trunk, allowed_seen = False, False
        vrrp: dict[str, list[Node]] = {}
        for child in node.children:
            text = child.stripped
            if child.terminator:
                continue
            if (m := re.match(r"^ip address (\S+) secondary$", text)):
                self.child_object(child, iface, "secondary_address", f"secondary_address:{name}/{m.group(1)}", f"{name} secondary {m.group(1)}",
                                  f"ip address {m.group(1)} secondary")
            elif (m := re.match(r"^ip address (\S+)$", text)):
                obj = self.child_object(child, iface, "primary_address", f"primary_address:{name}/{m.group(1)}", f"{name} primary {m.group(1)}",
                                        f"ip address {m.group(1)}")
                if secondaries:
                    obj.removable, obj.reason = False, PRIMARY_WITH_SECONDARIES
            elif (m := re.match(r"^ipv6 address (\S+)", text)):
                self.child_object(child, iface, "ipv6_address", f"ipv6_address:{name}/{m.group(1)}", f"{name} IPv6 {m.group(1)}", text)
            elif (m := re.match(r"^switchport access vlan (\d+)$", text)):
                obj = self.child_object(child, iface, "vlan_access_membership", f"vlan_access:{name}", f"{name} access VLAN {m.group(1)}",
                                        "switchport access vlan")
                obj.references.add(f"vlan:{m.group(1)}")
            elif re.match(r"^switchport mode trunk$", text):
                trunk = True
                self.attribute(child, iface.id, removable=False, reason=UNRECOGNISED_ATTRIBUTE)
            elif (m := re.match(r"^switchport trunk allowed vlan (.+)$", text)):
                allowed_seen = True
                value = m.group(1).strip()
                refs = {ALL_VLANS} if value == "all" else set() if value == "none" else {
                    f"vlan:{v}" for v in structure.vlan_ids(value.removeprefix("add ").removeprefix("remove "))}
                self.attribute(child, iface.id, removable=False, reason=WIDENS, references=refs)
            elif (m := re.match(r"^switchport trunk native vlan (\d+)$", text)):
                self.attribute(child, iface.id, removable=True, references={f"vlan:{m.group(1)}"}, statement="switchport trunk native vlan")
            elif (m := re.match(r"^(ip|ipv6) access-group (\S+) (in|out)$", text)):
                obj = self.child_object(child, iface, "acl_attachment", f"acl_attachment:{name}/{m.group(2)}/{m.group(3)}",
                                        f"{name} {m.group(1)} access-group {m.group(2)} {m.group(3)}", text)
                obj.references.add(f"acl:{m.group(2)}")
            elif (m := re.match(r"^service-policy type pbr input (\S+)$", text)):
                obj = self.child_object(child, iface, "pbr_attachment", f"pbr_attachment:{name}/{m.group(1)}", f"{name} PBR {m.group(1)}", text)
                obj.references.add(f"pbr_policy:{m.group(1)}")
            elif (m := re.match(r"^(ip helper-address|ipv6 dhcp relay destination) (\S+)", text)):
                self.child_object(child, iface, "dhcp_relay", f"dhcp_relay:{name}/{m.group(2)}", f"{name} DHCP relay {m.group(2)}", text)
            elif (m := re.match(r"^(ip|ipv6) virtual-router address (\S+)$", text)):
                obj = self.child_object(child, iface, "fhrp_vip", f"fhrp_vip:{name}/{m.group(2)}", f"{name} virtual address {m.group(2)}", text)
                family = "primary_address" if m.group(1) == "ip" else "ipv6_address"
                obj.references |= {f"{family}:{name}/*"}
            elif (m := re.match(r"^vrrp (\d+) ", text)):
                vrrp.setdefault(m.group(1), []).append(child)
            elif (m := re.match(r"^ip ospf area (\S+)$", text)):
                obj = self.child_object(child, iface, "ospf_interface_attachment", f"ospf_attach:{name}", f"{name} OSPF area {m.group(1)}", text)
                obj.references.add("ospf_process:*")
            elif (m := re.match(r"^ipv6 ospf (\d+) area (\S+)$", text)):
                obj = self.child_object(child, iface, "ospf_interface_attachment", f"ospf3_attach:{name}", f"{name} OSPFv3 area {m.group(2)}", text)
                obj.references.add(f"ospf3_process:{m.group(1)}")
            elif (m := re.match(r"^channel-group (\d+) ", text)):
                self.attribute(child, iface.id, removable=False, reason=UNRECOGNISED_ATTRIBUTE, references={f"interface:Port-Channel{m.group(1)}"})
            elif re.match(r"^ip nat (source|destination) ", text):
                obj = self.child_object(child, iface, "nat_rule", f"nat_rule:{name}/{child.number}", f"{name} {text}", text)
                obj.references |= self.match_references(text)
            elif re.match(r"^(description|mtu|(?:ip|ipv6) ospf (cost|network|priority|hello-interval|dead-interval)|ip rip )", text):
                self.attribute(child, iface.id, removable=True)
            else:
                self.attribute(child, iface.id, removable=False, reason=NEGATED if text.startswith("no ") else UNRECOGNISED_ATTRIBUTE)
        for group, members in vrrp.items():
            obj = self.add(ConfigObject(
                id=f"vrrp_group:{name}/{group}", kind="vrrp_group", label=f"{name} VRRP group {group}", node=members[0],
                lines=sorted(n.number for m in members for n in [m, *m.descendants()]), parent_id=iface.id,
                operation=DEACTIVATE_DETACH, removal_lines=_child_removal(members[0], f"vrrp {group}"),
            ))
            obj.references.add(f"primary_address:{name}/*")
        if trunk and not allowed_seen:
            iface.references.add(ALL_VLANS)   # a trunk with no allowed-list carries EVERY VLAN
        if protected:
            for obj in self.objects.values():
                if obj.parent_id == iface.id:
                    obj.protected, obj.removable, obj.reason = True, False, PROTECTED_MANAGEMENT

    def child_object(self, child: Node, parent: ConfigObject, kind: str, oid: str, label: str, statement: str,
                     operation: str = DEACTIVATE_DETACH) -> ConfigObject:
        removable, reason = True, ""
        if any(m in child.text for m in REDACTION_MARKERS):
            removable, reason = False, REDACTED
        return self.add(ConfigObject(id=oid, kind=kind, label=label, node=child, lines=child.span(), parent_id=parent.id,
                                     operation=operation, removable=removable, reason=reason,
                                     removal_lines=_child_removal(child, statement)))

    # -- routing ----------------------------------------------------------------------------------------------------
    def router_simple(self, node: Node, kind: str, oid: str, label: str) -> None:
        proc = self.add(ConfigObject(id=oid, kind=kind, label=label, node=node, lines=node.span(), removal_lines=[f"no {node.stripped}"]))
        self.router_children(node, proc)

    def router_children(self, node: Node, proc: ConfigObject) -> None:
        for child in node.children:
            text = child.stripped
            if child.terminator:
                continue
            if (m := re.match(r"^network (\S+)(?: area (\S+))?$", text)) and proc.kind != "bgp_process":
                kind = {"ospf_process": "ospf_network", "ospf3_process": "ospf_network", "rip_process": "rip_network"}.get(proc.kind, "network")
                self.child_object(child, proc, kind, f"{kind}:{proc.id.split(':', 1)[1]}/{m.group(1)}", f"{proc.label} network {m.group(1)}", text)
            elif (m := re.match(r"^redistribute (\S+)", text)):
                obj = self.child_object(child, proc, "redistribution", f"redistribute:{proc.id}/{m.group(1)}", f"{proc.label} redistribute {m.group(1)}",
                                        text)
                obj.references |= self.match_references(text)
            elif re.match(r"^passive-interface (\S+)$", text):
                self.attribute(child, proc.id, removable=True)
            else:
                self.attribute(child, proc.id, removable=False, reason=UNRECOGNISED_ATTRIBUTE)

    def router_bgp(self, node: Node, asn: str) -> None:
        proc = self.add(ConfigObject(id=f"bgp_process:{asn}", kind="bgp_process", label=f"BGP AS {asn}", node=node, lines=node.span(),
                                     removal_lines=[f"no router bgp {asn}"]))
        groups: dict[str, list[Node]] = {}
        for child in node.children:
            text = child.stripped
            if child.terminator:
                continue
            if (m := re.match(r"^neighbor (\S+) ", text)):
                groups.setdefault(m.group(1), []).append(child)
            elif (m := re.match(r"^network (\S+)", text)):
                self.child_object(child, proc, "bgp_network", f"bgp_network:{asn}/{m.group(1)}", f"BGP {asn} network {m.group(1)}", text)
            elif re.match(r"^address-family ", text):
                self.bgp_address_family(child, proc, asn)
            elif re.match(r"^redistribute ", text):
                obj = self.child_object(child, proc, "redistribution", f"redistribute:{proc.id}/{text.split()[1]}",
                                        f"BGP {asn} {text}", text)
                obj.references |= self.match_references(text)
            else:
                self.attribute(child, proc.id, removable=False, reason=UNRECOGNISED_ATTRIBUTE)
        for peer, members in groups.items():
            is_group = not _is_ip(peer)
            kind = "bgp_peer_group" if is_group else "bgp_neighbor"
            oid = f"peer_group:{asn}/{peer}" if is_group else f"bgp_neighbor:{asn}/{peer}"
            identity = next((n for n in members if re.search(r" (remote-as|peer[ -]group)\b", n.stripped)), members[0])
            lines = sorted(n.number for m in members for n in [m, *m.descendants()])
            removal = f"neighbor {peer} peer group" if is_group and self.platform != "ubuntu_frr" else f"neighbor {peer}"
            obj = self.add(ConfigObject(id=oid, kind=kind, label=f"BGP {asn} {'peer group' if is_group else 'neighbor'} {peer}", node=identity,
                                        lines=lines, parent_id=proc.id, removal_lines=_child_removal(identity, removal)))
            for member in members:
                refs = self.neighbor_references(asn, member.stripped)
                if member is identity:
                    obj.references |= refs   # attribute lines carry their own references (reported by exact line)
                    continue
                self.attribute(member, obj.id, removable=True, references=refs)
                self.owner[member.number] = obj.id
            if not is_group and any(re.search(r" peer[ -]group (\S+)$", n.stripped) for n in members):
                identity_is_membership = re.search(r" peer[ -]group (\S+)$", identity.stripped)
                if identity_is_membership:
                    obj.references.add(f"peer_group:{asn}/{identity_is_membership.group(1)}")

    def bgp_address_family(self, node: Node, proc: ConfigObject, asn: str) -> None:
        self.attribute(node, proc.id, removable=False, reason=IDENTITY)
        for child in node.children:
            text = child.stripped
            if child.terminator:
                continue
            if (m := re.match(r"^neighbor (\S+) activate$", text)):
                obj = self.child_object(child, proc, "bgp_neighbor_af", f"bgp_neighbor_af:{asn}/{m.group(1)}/{node.stripped}",
                                        f"BGP {asn} {node.stripped} activate {m.group(1)}", text)
                obj.references.add(f"bgp_neighbor:{asn}/{m.group(1)}" if _is_ip(m.group(1)) else f"peer_group:{asn}/{m.group(1)}")
            elif (m := re.match(r"^network (\S+)", text)):
                self.child_object(child, proc, "bgp_network", f"bgp_network:{asn}/{m.group(1)}", f"BGP {asn} network {m.group(1)}", text)
            elif (m := re.match(r"^neighbor (\S+) ", text)):
                refs = self.neighbor_references(asn, text)
                self.attribute(child, proc.id, removable=True, references=refs)
            elif re.match(r"^redistribute ", text):
                obj = self.child_object(child, proc, "redistribution", f"redistribute:{proc.id}/{node.stripped}/{text.split()[1]}", f"BGP {asn} {text}", text)
                obj.references |= self.match_references(text)
            else:
                self.attribute(child, proc.id, removable=False, reason=UNRECOGNISED_ATTRIBUTE)

    def neighbor_references(self, asn: str, text: str) -> set[str]:
        refs = set()
        if (m := re.search(r" route-map (\S+) (in|out)$", text)):
            refs.add(f"route_map:{m.group(1)}")
        if (m := re.search(r" prefix-list (\S+) (in|out)$", text)):
            refs.add(f"prefix_list:{m.group(1)}")
        if (m := re.search(r" peer[ -]group (\S+)$", text)) and not text.endswith(" peer group") and not text.endswith(" peer-group"):
            refs.add(f"peer_group:{asn}/{m.group(1)}")
        if (m := re.search(r" update-source (\S+)$", text)):
            refs.add(f"interface:{m.group(1)}")
        return refs

    def match_references(self, text: str) -> set[str]:
        refs = set()
        if (m := re.search(r"\bprefix-list (\S+)", text)):
            refs.add(f"prefix_list:{m.group(1)}")
        if (m := re.search(r"\broute-map (\S+)", text)):
            refs.add(f"route_map:{m.group(1)}")
        if (m := re.search(r"\b(?:access-list|access-group) (\S+)", text)):
            refs.add(f"acl:{m.group(1)}")
        if (m := re.search(r"\bpool (\S+)", text)):
            refs.add(f"nat_pool:{m.group(1)}")
        return refs

    # -- ACL / PBR --------------------------------------------------------------------------------------------------
    def acl(self, node: Node, name: str, family: str, *, standard: bool) -> None:
        header = f"no {family} access-list {'standard ' if standard else ''}{name}"
        acl = self.add(ConfigObject(id=f"acl:{name}", kind="acl", label=f"ACL {name}", node=node, lines=node.span(), removal_lines=[header]))
        self.named["acl"].add(name)
        for child in node.children:
            if (m := re.match(r"^(\d+) (permit|deny|remark)\b", child.stripped)):
                self.child_object(child, acl, "acl_entry", f"acl_entry:{name}/{m.group(1)}", f"ACL {name} entry {m.group(1)}", m.group(1),
                                  operation=REMOVE_DELETE)
            else:
                self.attribute(child, acl.id, removable=False, reason=UNRECOGNISED_ATTRIBUTE)

    def pbr_policy(self, node: Node, name: str) -> None:
        policy = self.add(ConfigObject(id=f"pbr_policy:{name}", kind="pbr_policy", label=f"PBR policy {name}", node=node, lines=node.span(),
                                       removal_lines=[f"no policy-map type pbr {name}"]))
        self.named["pbr_policy"].add(name)
        for child in node.children:
            if (m := re.match(r"^(\d+) class (\S+)$", child.stripped)):
                obj = self.child_object(child, policy, "pbr_sequence", f"pbr_sequence:{name}/{m.group(1)}", f"PBR {name} sequence {m.group(1)}",
                                        m.group(1), operation=REMOVE_DELETE)
                obj.references.add(f"pbr_class:{m.group(2)}")
            else:
                self.attribute(child, policy.id, removable=False, reason=UNRECOGNISED_ATTRIBUTE)

    def protect_management_routes(self) -> None:
        """Routes into a management interface's OWN subnet (e.g. Management0 on the Containerlab network) keep NMAS reachability."""
        networks = list(MANAGEMENT_NETWORKS)
        for obj in self.objects.values():
            if obj.kind in ("primary_address", "ipv6_address") and obj.protected:
                try:
                    networks.append(ipaddress.ip_interface(obj.id.split("/", 1)[1]).network)
                except ValueError:
                    continue
        for obj in self.objects.values():
            if obj.kind != "static_route" or obj.protected:
                continue
            for token in obj.node.stripped.split()[2:]:
                try:
                    value = ipaddress.ip_interface(token) if "/" in token else ipaddress.ip_address(token)
                except ValueError:
                    continue
                address = value.ip if hasattr(value, "ip") else value
                if any(address.version == net.version and address in net for net in networks):
                    obj.protected, obj.removable, obj.reason = True, False, PROTECTED_MANAGEMENT
                    break

    # -- references from unmanaged / generic lines ------------------------------------------------------------------
    def scan_named_references(self) -> None:
        """A named ACL / route-map / prefix-list mentioned anywhere else (SNMP, management APIs, NAT ...) is referenced.

        Conservative by design: an over-reported reference only BLOCKS a removal; it can never cause one.
        """
        names = {(kind, name) for kind, values in self.named.items() for name in values}
        for node in self.tree.by_number.values():
            owner = self.owner.get(node.number)
            obj = self.objects.get(owner) if owner else None
            if obj is None or obj.kind not in ("unmanaged",):
                continue
            tokens = set(node.stripped.split())
            for kind, name in names:
                if name in tokens:
                    obj.references.add(f"{kind}:{name}")
            if node.stripped.startswith("snmp-server community") and any(m in node.text for m in REDACTION_MARKERS):
                obj.references.add(ANY_ACL)

    def finish_virtual(self) -> None:
        for obj in self.objects.values():
            if obj.node is None:
                members = [self.objects[m] for m in obj.members]
                obj.removal_lines = [line for member in members for line in member.removal_lines]
                blocked = next((m for m in members if not m.removable), None)
                obj.removable, obj.reason = blocked is None, (blocked.reason if blocked else "")
                obj.protected = any(m.protected for m in members)
                obj.operation = REMOVE_DELETE
        # a reference to "<kind>:<iface>/*" means "any address of that family on the interface"
        for obj in list(self.objects.values()):
            wild = {ref for ref in obj.references if ref.endswith("/*") and not ref.startswith("vlan")}
            for ref in wild:
                prefix = ref[:-1]
                obj.references.discard(ref)
                obj.references |= {oid for oid in self.objects if oid.startswith(prefix)}
            if "ospf_process:*" in obj.references:
                obj.references.discard("ospf_process:*")
                obj.references |= {oid for oid in self.objects if oid.startswith("ospf_process:")}


def build_model(text: str, platform: str) -> ConfigModel:
    """Index + classify a SANITIZED running configuration for ``platform`` (arista_ceos / ubuntu_frr)."""
    return _Builder(text, platform).build()
