"""Vendor-neutral parsed configuration records used only at the import edge.

These records are not a second intent model: parsers populate them in memory
and ``config_import.service`` immediately applies them through the same
Device Builder mutation/field-commit services used by the UI.  Anything a
parser cannot represent is an :class:`UnmanagedBlock` and remains immutable.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class UnmanagedBlock:
    label: str
    classification: str
    lines: list[str]


@dataclass
class ParsedInterface:
    name: str
    kind: str = "ROUTED_PHYSICAL"
    description: str = ""
    mtu: int | None = None
    admin_state: str = "ENABLED"
    access_vlan: int | None = None
    trunk_allowed_vlans: list[int] = field(default_factory=list)
    native_vlan: int | None = None
    parent_name: str = ""
    encapsulation_vlan: int | None = None
    vlan_id: int | None = None
    addresses: list[dict] = field(default_factory=list)
    ospf_bindings: list[dict] = field(default_factory=list)
    isis_bindings: list[dict] = field(default_factory=list)
    dhcp_relays: list[dict] = field(default_factory=list)
    fhrp: list[dict] = field(default_factory=list)
    acl_attachments: list[dict] = field(default_factory=list)
    pbr_attachments: list[dict] = field(default_factory=list)     # {"name", "direction"} (FRR ``pbr-policy``)
    preserved_lines: list[str] = field(default_factory=list)


@dataclass
class ParsedStaticRoute:
    family: str
    destination: str
    next_hop_address: str = ""
    next_hop_interface: str = ""
    distance: int | None = None
    tag: int | None = None
    lines: list[str] = field(default_factory=list)


@dataclass
class ParsedRoutingInstance:
    family: str
    fields: dict
    bindings: list[dict] = field(default_factory=list)
    neighbors: list[dict] = field(default_factory=list)
    networks: list[dict] = field(default_factory=list)
    preserved_lines: list[str] = field(default_factory=list)


@dataclass
class ParsedAcl:
    name: str
    family: str
    acl_type: str
    entries: list[dict] = field(default_factory=list)
    preserved_lines: list[str] = field(default_factory=list)


@dataclass
class ParsedPbr:
    name: str
    family: str
    sequences: list[dict] = field(default_factory=list)          # {"sequence", "source_prefix", "destination_prefix", "next_hop"}


@dataclass
class ParsedNatRule:
    family: str = "NAT44"
    mode: str = "PAT"
    original_source: str = ""
    outside_interface: str = ""
    translated_source: str = ""           # static NAT: the outside (global) host address
    lines: list[str] = field(default_factory=list)


@dataclass
class ParsedConfig:
    hostname: str = ""
    interfaces: list[ParsedInterface] = field(default_factory=list)
    static_routes: list[ParsedStaticRoute] = field(default_factory=list)
    routing_instances: list[ParsedRoutingInstance] = field(default_factory=list)
    acls: list[ParsedAcl] = field(default_factory=list)
    pbr_policies: list[ParsedPbr] = field(default_factory=list)
    nat_rules: list[ParsedNatRule] = field(default_factory=list)
    unmanaged_blocks: list[UnmanagedBlock] = field(default_factory=list)
    parser_version: str = ""
    # V2 Phase 4: management-VRF records {"vrfs": [...], "bindings": [...], "routes": [...], "services": [...]} -- empty
    # unless a VRF carries a management access service, so every other import is unchanged.
    management: dict = field(default_factory=dict)
