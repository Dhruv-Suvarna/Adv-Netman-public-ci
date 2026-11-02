"""Platform capability and candidate-renderer registry.

Only ``SUPPORTED`` interface combinations are selectable. ``NOT_IMPLEMENTED``
means the platform supports the concept but this project lacks a safe
renderer; ``UNSUPPORTED`` is a known mismatch; ``UNKNOWN`` means repository
evidence is insufficient.
"""

from __future__ import annotations

import ipaddress
import json
from dataclasses import dataclass
from enum import StrEnum

from .management import vrf as management_vrf
from . import (
    candidate_composition,
    feature_template_renderer,
    field_validators,
    interface_intent_service,
    service_policy_intent_service,
)

NOT_IMPLEMENTED_LINE = {"kind": "static", "text": "! candidate rendering for this feature is not implemented yet"}

# Every renderer path that preserves-but-does not-render an object emits one
# static descriptor beginning with this marker.  Phase-13 validation reads it
# through is_unsupported_object_descriptor() so it can prove registry/renderer
# agreement without parsing vendor CLI.
UNSUPPORTED_OBJECT_MARKER = "! UNSUPPORTED CANDIDATE OBJECT:"


def is_unsupported_object_descriptor(descriptor: dict) -> bool:
    return descriptor.get("kind") == "static" and str(descriptor.get("text", "")).startswith(UNSUPPORTED_OBJECT_MARKER)


class CapabilityStatus(StrEnum):
    SUPPORTED = "SUPPORTED"
    NOT_IMPLEMENTED = "NOT_IMPLEMENTED"
    UNSUPPORTED = "UNSUPPORTED"
    UNKNOWN = "UNKNOWN"


CAPABILITY_STATUS_LABELS = {
    CapabilityStatus.SUPPORTED: "Implemented",
    CapabilityStatus.NOT_IMPLEMENTED: "Platform supports; project not implemented",
    CapabilityStatus.UNSUPPORTED: "Unsupported / known limitation",
    CapabilityStatus.UNKNOWN: "Unknown / not verified",
}


@dataclass(frozen=True)
class PlatformCapability:
    status: CapabilityStatus
    evidence: str


def _caps(mapping: dict[str, tuple[CapabilityStatus, str]]) -> dict[str, PlatformCapability]:
    return {
        kind: PlatformCapability(*mapping.get(kind, (CapabilityStatus.UNKNOWN, "No repository evidence.")))
        for kind in interface_intent_service.INTERFACE_KINDS
    }


_EOS = "Tracked cEOS 4.36.2F templates under templates/*.cfg.j2; additive feature templates are Phase-10-only."
_LINUX = "Tracked Ubuntu 24.04 R3/R4 scripts use iproute2 VLAN, bridge, address, MTU, and link-state commands."
_SRL = "Historical generated SR Linux v24.10.7 config.json shows interface/subinterface/address structures; no approved live SR Linux baseline."
_IOSXR = "No IOS XR configuration artifact or live node exists in this repository baseline."
_IOSXE = "Catalyst 8000V 17.06.01a qcow2 boot identity was observed in an isolated snapshot; NMAS has no live transport or executor."
_SONIC = "Existing driver records SONiC as structured config_db-style configuration; no safe Phase-10 serializer exists."

# Phase 20.5: SR Linux has no deployed lab node (see docs/PHASE_20_5_PLATFORM_CAPABILITY_AUDIT.md
# "Evidence boundary"), so every SR Linux cell below is IMPLEMENTED/FIXTURE TESTED against
# authoritative Nokia SR Linix documentation, never LIVE TESTED. Cited verbatim `set` command
# shapes come from Nokia SR Linux Configuration Basics Guide (interfaces, network-instances,
# OSPF, BGP) and the srl_nokia-acl data-model reference -- not invented CLI.
_SRL_IMPL = (
    "No deployed SR Linux node exists in this lab (fixture-tested only, not live-verified). "
    "Modeled on Nokia SR Linix Configuration Basics Guide 'Interfaces' chapter: a physical "
    "interface's admin-state/description/mtu plus one or more numbered subinterfaces "
    "(`set interface <name> subinterface <index> ...`), each explicitly bound into an owning "
    "network-instance (`set network-instance default|mgmt interface <name>.<index>`) -- SR "
    "Linix has no implicit default-VRF membership the way cEOS/FRR do."
)
_SRL_STATIC = (
    "No deployed SR Linux node (fixture-tested only). Modeled on the documented "
    "static-routes/next-hop-groups indirection: a route names a next-hop-group "
    "(`route <prefix> next-hop-group <name>`) and the group holds the actual next-hop "
    "IP address(es) (`next-hop-groups group <name> next-hop <n> ip-address <addr>`); "
    "there is no direct route-level next-hop leaf."
)
_SRL_NO_RIP = "Nokia SR Linix does not implement RIP/RIPng in any documented release; this is a genuine platform limitation, not a project gap."
_SRL_OSPF = (
    "No deployed SR Linux node (fixture-tested only). Modeled on the documented "
    "`network-instance default protocols ospf instance <name> version ospf-v2|ospf-v3 "
    "router-id <id>` plus per-area interface assignment."
)
_SRL_BGP = (
    "No deployed SR Linux node (fixture-tested only). Modeled on the documented mandatory "
    "group/neighbor structure: `network-instance default protocols bgp autonomous-system <asn>`, "
    "`... group <name> admin-state enable`, `... neighbor <addr> peer-group <name>`, "
    "`... neighbor <addr> peer-as <asn>` -- SR Linix requires every BGP neighbor to reference "
    "a peer-group; there is no group-less neighbor statement."
)
_SRL_ACL = (
    "No deployed SR Linux node (fixture-tested only). Modeled on the srl_nokia-acl data model: "
    "`acl ipv4-filter|ipv6-filter <name> entry <seq> match source-ip prefix <cidr>` / "
    "`match destination-ip prefix <cidr>` / `action accept|drop`, attached to a subinterface "
    "via `interface <name> subinterface <idx> acl input|output ipv4-filter|ipv6-filter <name>`. "
    "Port-range and log-action matches are intentionally not rendered pending exact model "
    "verification (see the in-candidate comment) rather than fabricated."
)
_SRL_DHCP_RELAY = (
    "No deployed SR Linux node (fixture-tested only). Nokia SR Linux 24.10's "
    "srl_nokia-interfaces model defines IPv4 and IPv6 `dhcp-relay server` leaf-lists "
    "under an interface subinterface; canonical relay intent supplies the server and "
    "interface reference. Optional gi/source addresses, options, and non-default network "
    "instances remain unmanaged because canonical intent does not model them."
)

# Historical Phase 20.5 Cisco behavior is IOS XR -- never silently
# reclassified as classic IOS/IOL or Catalyst 8000V/IOS XE. No deployed XR
# node exists (fixture-tested only). Cited
# command shapes are verified against Cisco's published IOS XR configuration guides
# (Interfaces, IP Addresses and Services, Implementing OSPF/BGP, Access Lists).
_IOSXR_IMPL = (
    "No deployed IOS XR node exists in this lab (fixture-tested only, not live-verified). "
    "Modeled on the Cisco IOS XR Interface / IP Addresses and Services Configuration Guides: "
    "`interface <name>` with `ipv4 address <ip> <mask>` (IOS XR uses a dotted-decimal mask "
    "for IPv4, unlike this project's other platforms, which is why addresses are converted "
    "from the canonical CIDR value) and `ipv6 address <cidr>`; subinterfaces use "
    "`interface <parent>.<vlan> ... encapsulation dot1q <vlan>`."
)
_IOSXR_STATIC = (
    "No deployed IOS XR node (fixture-tested only). Modeled on the documented "
    "`router static / address-family ipv4|ipv6 unicast <prefix> <next-hop>` hierarchy "
    "(unlike interface addressing, the static-route prefix itself is CIDR, matching the "
    "'Comparison of Static Route Configuration between Cisco IOS and IOS XR' guide)."
)
_IOSXR_RIP = (
    "No deployed IOS XR node exists in this lab (fixture-tested only). Cisco's Cisco 8000 "
    "Routing Configuration Guide documents default-VRF RIPv2 as `router rip` with nested "
    "`interface <name>` and optional `passive-interface`; IOS XR sends/receives RIPv2 by "
    "default."
)
_IOSXR_RIPNG_BLOCKED = (
    "Cisco documents RIPng for Cisco 8000 only from IOS XR 7.5.2 and demonstrates it under "
    "`router rip / vrf <name> / address-family ipv6`; this project has no pinned IOS XR "
    "release and its canonical RIP intent has no VRF field, so an exact RIPng renderer is "
    "not yet implementable without extending the model."
)
_IOSXR_OSPF = (
    "No deployed IOS XR node (fixture-tested only). Modeled on the documented "
    "`router ospf <name> / router-id <id> / area <id> / interface <name>` hierarchy, where "
    "network-type (e.g. `network point-to-point`) is configured under the area/interface "
    "block, not on the interface itself as in classic IOS."
)
_IOSXR_BGP = (
    "No deployed IOS XR node (fixture-tested only). Modeled on the documented "
    "`router bgp <asn> / bgp router-id <id> / address-family ipv4|ipv6 unicast / "
    "neighbor <addr> / remote-as <asn> / address-family ipv4|ipv6 unicast` (address-family "
    "must be explicitly activated at both the global and neighbor level; IOS XR enables "
    "none by default, unlike classic IOS)."
)
_IOSXR_ACL = (
    "No deployed IOS XR node (fixture-tested only). Modeled on the documented "
    "`ipv4|ipv6 access-list <name> / <seq> permit|deny <proto> <src> <dst>` syntax, which "
    "(per Cisco's own example output) accepts prefix/host notation directly rather than "
    "requiring a classic-IOS inverse wildcard mask."
)
_IOSXR_DHCP_RELAY = (
    "No deployed IOS XR node (fixture-tested only). Cisco 8000 IP Addresses and Services "
    "documentation defines `dhcp ipv4|ipv6`, a named `profile <name> relay` containing "
    "`helper-address vrf default <address>`, and `interface <name> relay profile <name>`. "
    "Canonical relay intent contains the required family, destination, and interface."
)

# Phase 20.5: SONiC's authoritative configuration representation is config_db (a Redis-backed
# table/key/field store), applied via `config load <file>.json` / `config reload`, NOT a
# `show running-config`-style CLI -- see docs/EXISTING_CONFIG_IMPORT.md "Boundaries" and this
# module's docstring. No deployed node exists (fixture-tested only). Cited table/field names
# are verified against sonic-net/SONiC's own HLDs and Cisco/Edgecore/Netberg SONiC
# documentation (INTERFACE/LOOPBACK_INTERFACE/MGMT_INTERFACE, STATIC_ROUTE, BGP_GLOBALS/
# BGP_NEIGHBOR/BGP_NEIGHBOR_AF, ACL_TABLE/ACL_RULE).
_SONIC_IMPL = (
    "No deployed SONiC node exists in this lab (fixture-tested only, not live-verified). "
    "Modeled on config_db's INTERFACE/LOOPBACK_INTERFACE/MGMT_INTERFACE tables, where an "
    "interface and each of its addresses are separate keys "
    "(`\"<name>\": {}`, `\"<name>|<address>\": {}`) -- there is no CLI line to render, so the "
    "candidate is the config_db JSON fragment itself, not translated vendor CLI."
)
_SONIC_VLAN = (
    "No deployed SONiC node exists in this lab (fixture-tested only). Modeled on sonic-net/SONiC's "
    "ConfigDB/YANG documentation: VLAN defines `Vlan<id>`/`vlanid`, VLAN_MEMBER keys "
    "`Vlan<id>|<port>` with `tagging_mode` tagged or untagged, and VLAN_INTERFACE owns "
    "the SVI plus its address keys."
)
_SONIC_STATIC = (
    "No deployed SONiC node (fixture-tested only). Modeled on the documented "
    "`STATIC_ROUTE` table, keyed `<vrf>|<prefix>` with `nexthop`/`distance` fields "
    "(sonic-net/SONiC 'SONiC_static_route_hdl.md')."
)
_SONIC_OSPF_UNCERTAIN = (
    "SONiC's routing stack is FRR-based and FRR itself supports OSPF, but this project found "
    "no stable, well-documented config_db table for OSPF the way BGP_GLOBALS/BGP_NEIGHBOR and "
    "STATIC_ROUTE are documented -- OSPF is commonly configured via direct vtysh/FRR unified "
    "config on real SONiC deployments instead. Rather than fabricate an unverified config_db "
    "OSPF schema, this is classified NOT_IMPLEMENTED (image/config-model dependent) until a "
    "concrete, cited schema can be verified."
)
_SONIC_BGP = (
    "No deployed SONiC node (fixture-tested only). Modeled on the documented "
    "`BGP_GLOBALS` (`\"<vrf>\": {\"local_asn\": ...}`), `BGP_NEIGHBOR` "
    "(`\"<vrf>|<neighbor>\": {\"asn\": ..., ...}`), and `BGP_NEIGHBOR_AF` "
    "(`\"<vrf>|<neighbor>|<af>\": {\"admin_status\": ...}`) tables."
)
_SONIC_ACL = (
    "No deployed SONiC node (fixture-tested only). Modeled on the documented `ACL_TABLE` "
    "(`\"<name>\": {\"type\": \"L3\", \"ports\": [...], \"stage\": \"ingress\"|\"egress\"}`) and "
    "`ACL_RULE` (`\"<table>|<rule>\": {\"PRIORITY\": ..., \"PACKET_ACTION\": \"FORWARD\"|\"DROP\", "
    "\"SRC_IP\"/\"DST_IP\": ...}`) tables."
)

PLATFORM_CAPABILITIES: dict[str, dict[str, PlatformCapability]] = {
    "arista_ceos": _caps({
        **{kind: (CapabilityStatus.SUPPORTED, _EOS) for kind in (
            "ROUTED_PHYSICAL", "ACCESS", "TRUNK", "SUBINTERFACE", "SVI", "MANAGEMENT", "LOOPBACK"
        )},
        **{kind: (CapabilityStatus.NOT_IMPLEMENTED, _EOS) for kind in ("LAG", "MLAG", "TUNNEL", "GRE", "VXLAN_VTEP")},
        "BOND": (CapabilityStatus.UNSUPPORTED, "Linux bond is not an EOS interface construct."),
        "BRIDGE": (CapabilityStatus.UNSUPPORTED, "Linux bridge is not an EOS interface construct."),
        "VIRTUAL": (CapabilityStatus.UNKNOWN, "No project-specific virtual-interface contract is defined."),
        "RADIO_WLAN": (CapabilityStatus.UNSUPPORTED, "Not a capability of the cEOS lab image."),
    }),
    "nokia_srlinux": _caps({
        **{kind: (CapabilityStatus.SUPPORTED, _SRL_IMPL) for kind in (
            "ROUTED_PHYSICAL", "SUBINTERFACE", "LOOPBACK", "MANAGEMENT",
        )},
        **{kind: (CapabilityStatus.NOT_IMPLEMENTED, _SRL) for kind in (
            "ACCESS", "TRUNK", "SVI", "LAG", "MLAG", "TUNNEL", "GRE", "VXLAN_VTEP",
        )},
        "BOND": (CapabilityStatus.UNSUPPORTED, "Linux bond is not the SR Linux LAG model."),
        "BRIDGE": (CapabilityStatus.UNSUPPORTED, "Linux bridge is not the SR Linux network-instance model."),
        "VIRTUAL": (CapabilityStatus.UNKNOWN, _SRL),
        "RADIO_WLAN": (CapabilityStatus.UNKNOWN, _SRL),
    }),
    "ubuntu_frr": _caps({
        **{kind: (CapabilityStatus.SUPPORTED, _LINUX) for kind in (
            "ROUTED_PHYSICAL", "SUBINTERFACE", "SVI", "MANAGEMENT", "LOOPBACK"
        )},
        **{kind: (CapabilityStatus.NOT_IMPLEMENTED, _LINUX) for kind in (
            "ACCESS", "TRUNK", "BOND", "BRIDGE", "TUNNEL", "GRE", "VXLAN_VTEP", "VIRTUAL", "RADIO_WLAN"
        )},
        "LAG": (CapabilityStatus.UNSUPPORTED, "Use the separately modeled Linux bond concept, not Port-Channel syntax."),
        "MLAG": (CapabilityStatus.UNKNOWN, "No Linux/FRR MLAG implementation exists in this repository."),
    }),
    "cisco_c8000v_iosxe": _caps({
        **{kind: (CapabilityStatus.SUPPORTED, _IOSXE) for kind in (
            "ROUTED_PHYSICAL", "SUBINTERFACE", "LOOPBACK", "MANAGEMENT",
        )},
        **{kind: (CapabilityStatus.NOT_IMPLEMENTED, _IOSXE) for kind in (
            "ACCESS", "TRUNK", "SVI", "LAG", "TUNNEL", "GRE", "VXLAN_VTEP", "MLAG", "VIRTUAL", "RADIO_WLAN",
        )},
        "BOND": (CapabilityStatus.UNSUPPORTED, "Linux bond is not an IOS XE interface construct."),
        "BRIDGE": (CapabilityStatus.UNSUPPORTED, "Linux bridge is not an IOS XE interface construct."),
    }),
    "cisco_iosxr": _caps({
        **{kind: (CapabilityStatus.SUPPORTED, _IOSXR_IMPL) for kind in (
            "ROUTED_PHYSICAL", "SUBINTERFACE", "LOOPBACK", "MANAGEMENT",
        )},
        **{kind: (CapabilityStatus.NOT_IMPLEMENTED, _IOSXR) for kind in (
            "ACCESS", "TRUNK", "SVI", "LAG", "TUNNEL", "GRE", "VXLAN_VTEP",
        )},
        "BOND": (CapabilityStatus.UNSUPPORTED, "Linux bond is not an IOS interface construct."),
        "BRIDGE": (CapabilityStatus.UNSUPPORTED, "Linux bridge is not an IOS interface construct."),
        "MLAG": (CapabilityStatus.UNKNOWN, _IOSXR),
        "VIRTUAL": (CapabilityStatus.UNKNOWN, _IOSXR),
        "RADIO_WLAN": (CapabilityStatus.UNKNOWN, _IOSXR),
    }),
    "sonic": _caps({
        **{kind: (CapabilityStatus.SUPPORTED, _SONIC_IMPL) for kind in (
            "ROUTED_PHYSICAL", "SUBINTERFACE", "LOOPBACK", "MANAGEMENT",
        )},
        **{kind: (CapabilityStatus.SUPPORTED, _SONIC_VLAN) for kind in (
            "ACCESS", "TRUNK", "SVI",
        )},
        **{kind: (CapabilityStatus.NOT_IMPLEMENTED, _SONIC) for kind in (
            "LAG", "VXLAN_VTEP",
        )},
        "MLAG": (CapabilityStatus.UNKNOWN, _SONIC),
        "BOND": (CapabilityStatus.UNSUPPORTED, "Linux bond is not exposed as a SONiC candidate object here."),
        "BRIDGE": (CapabilityStatus.UNSUPPORTED, "Linux bridge is not exposed as a SONiC candidate object here."),
        "TUNNEL": (CapabilityStatus.UNKNOWN, _SONIC),
        "GRE": (CapabilityStatus.UNKNOWN, _SONIC),
        "VIRTUAL": (CapabilityStatus.UNKNOWN, _SONIC),
        "RADIO_WLAN": (CapabilityStatus.UNKNOWN, _SONIC),
    }),
}


def capability_for(platform: str, kind: str) -> PlatformCapability:
    if platform not in PLATFORM_CAPABILITIES or kind not in interface_intent_service.INTERFACE_KINDS:
        raise ValueError(f"Unknown platform/interface capability combination: {platform!r}/{kind!r}")
    return PLATFORM_CAPABILITIES[platform][kind]


def is_interface_kind_selectable(platform: str, kind: str) -> bool:
    try:
        return capability_for(platform, kind).status == CapabilityStatus.SUPPORTED
    except ValueError:
        return False


def implemented_interface_choices(platform: str, *, preserve_kind: str | None = None) -> list[dict]:
    if platform not in PLATFORM_CAPABILITIES:
        return []
    choices = [
        {"value": kind, "label": interface_intent_service.INTERFACE_KIND_LABELS[kind], "compatible": True}
        for kind in interface_intent_service.INTERFACE_KINDS
        if is_interface_kind_selectable(platform, kind)
    ]
    if preserve_kind and preserve_kind not in {item["value"] for item in choices}:
        choices.append({
            "value": preserve_kind,
            "label": f"{interface_intent_service.INTERFACE_KIND_LABELS.get(preserve_kind, preserve_kind)} (incompatible; preserved)",
            "compatible": False,
        })
    return choices


def capability_matrix() -> dict:
    return {
        "platforms": list(PLATFORM_DRIVERS.values()),
        "rows": [
            {
                "kind": kind,
                "label": interface_intent_service.INTERFACE_KIND_LABELS[kind],
                "cells": [
                    {
                        "platform": platform,
                        "status": PLATFORM_CAPABILITIES[platform][kind].status.value,
                        "label": CAPABILITY_STATUS_LABELS[PLATFORM_CAPABILITIES[platform][kind].status],
                        "evidence": PLATFORM_CAPABILITIES[platform][kind].evidence,
                    }
                    for platform in PLATFORM_CAPABILITIES
                ],
            }
            for kind in interface_intent_service.INTERFACE_KINDS
        ],
    }


class RoutingProtocol(StrEnum):
    STATIC_IPV4 = "STATIC_IPV4"
    STATIC_IPV6 = "STATIC_IPV6"
    RIPV2 = "RIPV2"
    RIPNG = "RIPNG"
    OSPFV2 = "OSPFV2"
    OSPFV3 = "OSPFV3"
    ISIS = "ISIS"
    EIGRP_IPV4 = "EIGRP_IPV4"
    EIGRP_IPV6 = "EIGRP_IPV6"
    BGP_IPV4 = "BGP_IPV4"
    BGP_IPV6 = "BGP_IPV6"


ROUTING_PROTOCOL_LABELS = {
    RoutingProtocol.STATIC_IPV4: "Static routing (IPv4)",
    RoutingProtocol.STATIC_IPV6: "Static routing (IPv6)",
    RoutingProtocol.RIPV2: "RIPv2",
    RoutingProtocol.RIPNG: "RIPng",
    RoutingProtocol.OSPFV2: "OSPFv2",
    RoutingProtocol.OSPFV3: "OSPFv3",
    RoutingProtocol.ISIS: "IS-IS",
    RoutingProtocol.EIGRP_IPV4: "EIGRP (IPv4)",
    RoutingProtocol.EIGRP_IPV6: "EIGRP (IPv6)",
    RoutingProtocol.BGP_IPV4: "BGP (IPv4)",
    RoutingProtocol.BGP_IPV6: "BGP (IPv6)",
}

# Evidence strings: grep across templates/*.cfg.j2 and logs/*.log (tracked,
# live-applied) -- see docs/DEVICE_BUILDER_ROUTING.md "Platform support
# matrix" for the full audit trail behind every cell below.
_EOS_RIP = "Tracked R1/R2/S1/S2 templates run 'router rip' / 'network' (RIPv2 only; no RIPv1 keyword exists anywhere in the repo)."
_EOS_OSPF = "Tracked R1/R2 templates run 'router ospf 10' + 'ipv6 router ospf 10' with per-interface 'ip ospf area'/'ipv6 ospf ... area'."
_EOS_BGP = "Tracked R5 template runs 'router bgp 65005' with 'neighbor ... remote-as', 'address-family ipv4'/'ipv6' (no 'unicast' keyword on cEOS), 'network'."
_EOS_STATIC = "Tracked R1/R2/R5 templates contain verified 'ip route'/'ipv6 route' static entries."
_EOS_NO_EVIDENCE = "No 'ripng'/'router eigrp' token exists anywhere in this repository's tracked cEOS configuration."
_EOS_ISIS = ("Disposable cEOS 4.36.2F sandbox (docs/V2_IPV6_ISIS_ACCESS_REDUNDANCY.md): 'router isis <tag>' with 'net', 'is-type' and "
             "'address-family ipv4|ipv6 unicast', per-interface 'isis enable <tag>' / 'isis passive' / 'isis metric', adjacencies over a "
             "routed port and an SVI, IPv6-only operation with IPv4 outside the address family.")
_FRR_OSPF = "Tracked R3/R4 FRR configs (vtysh-applied) run 'router ospf' / 'ospf router-id' and 'router ospf6' / 'ospf6 router-id'."
_FRR_BGP = "Tracked R3/R4 FRR configs run 'router bgp 65003/65004' with 'address-family ipv4/ipv6 unicast' + 'exit-address-family' (FRR requires the 'unicast' keyword cEOS omits)."
_FRR_STATIC = "Standard FRR staticd 'ip route'/'ipv6 route' global syntax, applied via the same vtysh path this repo's verified OSPF/BGP FRR config uses; R3/R4's own tracked templates carry no static route (dynamic-only), so this is general verified FRR syntax, not a repo-specific artifact."
_FRR_RIP = "FRR 8.4 documentation defines router rip/router ripng with interface network activation; the live R3/R4 daemons remain an independently checked runtime prerequisite."
_FRR_NO_EVIDENCE = "No enabled isisd/eigrpd configuration exists for R3/R4; this project has no safe process model/renderer for it."
_EIGRP_CISCO_ONLY = "EIGRP is a Cisco-proprietary protocol; not a capability of this platform."
_SRL_ROUTING = "Historical generated SR Linux config.json shows interface/subinterface structures only; no approved live SR Linux routing baseline exists in this repository."
_IOSXR_ROUTING = "No IOS XR configuration artifact or live node exists in this repository baseline."
_SONIC_ROUTING = "No SONiC routing daemon configuration or serializer exists in this repository baseline."


def _routing_caps(mapping: dict[str, tuple[CapabilityStatus, str]]) -> dict[str, PlatformCapability]:
    return {
        protocol: PlatformCapability(*mapping.get(protocol, (CapabilityStatus.UNKNOWN, "No repository evidence.")))
        for protocol in RoutingProtocol
    }


ROUTING_CAPABILITIES: dict[str, dict[str, PlatformCapability]] = {
    "arista_ceos": _routing_caps({
        RoutingProtocol.STATIC_IPV4: (CapabilityStatus.SUPPORTED, _EOS_STATIC),
        RoutingProtocol.STATIC_IPV6: (CapabilityStatus.SUPPORTED, _EOS_STATIC),
        RoutingProtocol.RIPV2: (CapabilityStatus.SUPPORTED, _EOS_RIP),
        RoutingProtocol.RIPNG: (CapabilityStatus.NOT_IMPLEMENTED, _EOS_NO_EVIDENCE),
        RoutingProtocol.OSPFV2: (CapabilityStatus.SUPPORTED, _EOS_OSPF),
        RoutingProtocol.OSPFV3: (CapabilityStatus.SUPPORTED, _EOS_OSPF),
        RoutingProtocol.ISIS: (CapabilityStatus.SUPPORTED, _EOS_ISIS),
        RoutingProtocol.EIGRP_IPV4: (CapabilityStatus.UNSUPPORTED, _EIGRP_CISCO_ONLY),
        RoutingProtocol.EIGRP_IPV6: (CapabilityStatus.UNSUPPORTED, _EIGRP_CISCO_ONLY),
        RoutingProtocol.BGP_IPV4: (CapabilityStatus.SUPPORTED, _EOS_BGP),
        RoutingProtocol.BGP_IPV6: (CapabilityStatus.SUPPORTED, _EOS_BGP),
    }),
    "nokia_srlinux": _routing_caps({
        RoutingProtocol.STATIC_IPV4: (CapabilityStatus.SUPPORTED, _SRL_STATIC),
        RoutingProtocol.STATIC_IPV6: (CapabilityStatus.SUPPORTED, _SRL_STATIC),
        RoutingProtocol.RIPV2: (CapabilityStatus.UNSUPPORTED, _SRL_NO_RIP),
        RoutingProtocol.RIPNG: (CapabilityStatus.UNSUPPORTED, _SRL_NO_RIP),
        RoutingProtocol.OSPFV2: (CapabilityStatus.SUPPORTED, _SRL_OSPF),
        RoutingProtocol.OSPFV3: (CapabilityStatus.SUPPORTED, _SRL_OSPF),
        RoutingProtocol.ISIS: (CapabilityStatus.NOT_IMPLEMENTED, _SRL_ROUTING),
        RoutingProtocol.EIGRP_IPV4: (CapabilityStatus.UNSUPPORTED, _EIGRP_CISCO_ONLY),
        RoutingProtocol.EIGRP_IPV6: (CapabilityStatus.UNSUPPORTED, _EIGRP_CISCO_ONLY),
        RoutingProtocol.BGP_IPV4: (CapabilityStatus.SUPPORTED, _SRL_BGP),
        RoutingProtocol.BGP_IPV6: (CapabilityStatus.SUPPORTED, _SRL_BGP),
    }),
    "ubuntu_frr": _routing_caps({
        RoutingProtocol.STATIC_IPV4: (CapabilityStatus.SUPPORTED, _FRR_STATIC),
        RoutingProtocol.STATIC_IPV6: (CapabilityStatus.SUPPORTED, _FRR_STATIC),
        RoutingProtocol.RIPV2: (CapabilityStatus.SUPPORTED, _FRR_RIP),
        RoutingProtocol.RIPNG: (CapabilityStatus.SUPPORTED, _FRR_RIP),
        RoutingProtocol.OSPFV2: (CapabilityStatus.SUPPORTED, _FRR_OSPF),
        RoutingProtocol.OSPFV3: (CapabilityStatus.SUPPORTED, _FRR_OSPF),
        RoutingProtocol.ISIS: (CapabilityStatus.SUPPORTED, "FRR 8.4.4 isisd: bounded NMAS44 process and per-interface IPv4/IPv6 activation; isolated live closure in progress."),
        RoutingProtocol.EIGRP_IPV4: (CapabilityStatus.NOT_IMPLEMENTED, "FRR 8.4.4 (this project's tracked version) ships no supported eigrpd in this project's evidence; not implemented."),
        RoutingProtocol.EIGRP_IPV6: (CapabilityStatus.NOT_IMPLEMENTED, "FRR 8.4.4 (this project's tracked version) ships no supported eigrpd in this project's evidence; not implemented."),
        RoutingProtocol.BGP_IPV4: (CapabilityStatus.SUPPORTED, _FRR_BGP),
        RoutingProtocol.BGP_IPV6: (CapabilityStatus.SUPPORTED, _FRR_BGP),
    }),
    "cisco_c8000v_iosxe": _routing_caps({
        RoutingProtocol.STATIC_IPV4: (CapabilityStatus.SUPPORTED, _IOSXE),
        RoutingProtocol.STATIC_IPV6: (CapabilityStatus.SUPPORTED, _IOSXE),
        RoutingProtocol.RIPV2: (CapabilityStatus.SUPPORTED, _IOSXE),
        RoutingProtocol.RIPNG: (CapabilityStatus.NOT_IMPLEMENTED, _IOSXE),
        RoutingProtocol.OSPFV2: (CapabilityStatus.SUPPORTED, _IOSXE),
        RoutingProtocol.OSPFV3: (CapabilityStatus.NOT_IMPLEMENTED, _IOSXE),
        RoutingProtocol.ISIS: (CapabilityStatus.NOT_IMPLEMENTED, _IOSXE),
        RoutingProtocol.EIGRP_IPV4: (CapabilityStatus.NOT_IMPLEMENTED, _IOSXE),
        RoutingProtocol.EIGRP_IPV6: (CapabilityStatus.NOT_IMPLEMENTED, _IOSXE),
        RoutingProtocol.BGP_IPV4: (CapabilityStatus.SUPPORTED, _IOSXE),
        RoutingProtocol.BGP_IPV6: (CapabilityStatus.SUPPORTED, _IOSXE),
    }),
    "cisco_iosxr": _routing_caps({
        RoutingProtocol.STATIC_IPV4: (CapabilityStatus.SUPPORTED, _IOSXR_STATIC),
        RoutingProtocol.STATIC_IPV6: (CapabilityStatus.SUPPORTED, _IOSXR_STATIC),
        RoutingProtocol.RIPV2: (CapabilityStatus.SUPPORTED, _IOSXR_RIP),
        RoutingProtocol.RIPNG: (CapabilityStatus.NOT_IMPLEMENTED, _IOSXR_RIPNG_BLOCKED),
        RoutingProtocol.OSPFV2: (CapabilityStatus.SUPPORTED, _IOSXR_OSPF),
        RoutingProtocol.OSPFV3: (CapabilityStatus.SUPPORTED, _IOSXR_OSPF),
        RoutingProtocol.ISIS: (CapabilityStatus.NOT_IMPLEMENTED, _IOSXR_ROUTING),
        RoutingProtocol.EIGRP_IPV4: (CapabilityStatus.NOT_IMPLEMENTED, "IOS XR documents EIGRP support; this project has no renderer/tests for it yet."),
        RoutingProtocol.EIGRP_IPV6: (CapabilityStatus.NOT_IMPLEMENTED, "IOS XR documents EIGRP support; this project has no renderer/tests for it yet."),
        RoutingProtocol.BGP_IPV4: (CapabilityStatus.SUPPORTED, _IOSXR_BGP),
        RoutingProtocol.BGP_IPV6: (CapabilityStatus.SUPPORTED, _IOSXR_BGP),
    }),
    "sonic": _routing_caps({
        RoutingProtocol.STATIC_IPV4: (CapabilityStatus.SUPPORTED, _SONIC_STATIC),
        RoutingProtocol.STATIC_IPV6: (CapabilityStatus.SUPPORTED, _SONIC_STATIC),
        RoutingProtocol.RIPV2: (CapabilityStatus.NOT_IMPLEMENTED, _SONIC_ROUTING),
        RoutingProtocol.RIPNG: (CapabilityStatus.NOT_IMPLEMENTED, _SONIC_ROUTING),
        RoutingProtocol.OSPFV2: (CapabilityStatus.NOT_IMPLEMENTED, _SONIC_OSPF_UNCERTAIN),
        RoutingProtocol.OSPFV3: (CapabilityStatus.NOT_IMPLEMENTED, _SONIC_OSPF_UNCERTAIN),
        RoutingProtocol.ISIS: (CapabilityStatus.NOT_IMPLEMENTED, _SONIC_ROUTING),
        RoutingProtocol.EIGRP_IPV4: (CapabilityStatus.UNSUPPORTED, _EIGRP_CISCO_ONLY),
        RoutingProtocol.EIGRP_IPV6: (CapabilityStatus.UNSUPPORTED, _EIGRP_CISCO_ONLY),
        RoutingProtocol.BGP_IPV4: (CapabilityStatus.SUPPORTED, _SONIC_BGP),
        RoutingProtocol.BGP_IPV6: (CapabilityStatus.SUPPORTED, _SONIC_BGP),
    }),
}


def capability_for_routing(platform: str, protocol) -> PlatformCapability:
    if platform not in ROUTING_CAPABILITIES or protocol not in RoutingProtocol:
        raise ValueError(f"Unknown platform/routing-protocol combination: {platform!r}/{protocol!r}")
    return ROUTING_CAPABILITIES[platform][protocol]


def is_routing_protocol_selectable(platform: str, protocol) -> bool:
    try:
        return capability_for_routing(platform, protocol).status == CapabilityStatus.SUPPORTED
    except ValueError:
        return False


def routing_capability_matrix() -> dict:
    return {
        "platforms": list(PLATFORM_DRIVERS.values()),
        "rows": [
            {
                "protocol": protocol.value,
                "label": ROUTING_PROTOCOL_LABELS[protocol],
                "cells": [
                    {
                        "platform": platform,
                        "status": ROUTING_CAPABILITIES[platform][protocol].status.value,
                        "label": CAPABILITY_STATUS_LABELS[ROUTING_CAPABILITIES[platform][protocol].status],
                        "evidence": ROUTING_CAPABILITIES[platform][protocol].evidence,
                    }
                    for platform in ROUTING_CAPABILITIES
                ],
            }
            for protocol in RoutingProtocol
        ],
    }


class ServicePolicyFeature(StrEnum):
    FHRP_HSRP_IPV4 = "FHRP_HSRP_IPV4"
    FHRP_HSRP_IPV6 = "FHRP_HSRP_IPV6"
    FHRP_VRRP_IPV4 = "FHRP_VRRP_IPV4"
    FHRP_VRRP_IPV6 = "FHRP_VRRP_IPV6"
    FHRP_VARP_IPV4 = "FHRP_VARP_IPV4"
    FHRP_VARP_IPV6 = "FHRP_VARP_IPV6"
    FHRP_GLBP_IPV4 = "FHRP_GLBP_IPV4"
    FHRP_GLBP_IPV6 = "FHRP_GLBP_IPV6"
    FHRP_ANYCAST_GATEWAY_IPV4 = "FHRP_ANYCAST_GATEWAY_IPV4"
    FHRP_ANYCAST_GATEWAY_IPV6 = "FHRP_ANYCAST_GATEWAY_IPV6"
    NAT_POOL_NAT44 = "NAT_POOL_NAT44"
    NAT_NAT44_STATIC = "NAT_NAT44_STATIC"
    NAT_NAT44_DYNAMIC = "NAT_NAT44_DYNAMIC"
    NAT_NAT44_PAT = "NAT_NAT44_PAT"
    NAT_NAT44_STATEFUL = "NAT_NAT44_STATEFUL"
    NAT_NAT64_STATIC = "NAT_NAT64_STATIC"
    NAT_NAT66_STATIC = "NAT_NAT66_STATIC"
    NAT_NPTV6_STATIC = "NAT_NPTV6_STATIC"
    NAT_NAT_PT_STATIC = "NAT_NAT_PT_STATIC"
    NAT_NAT44_TWICE_NAT = "NAT_NAT44_TWICE_NAT"
    NAT_NAT44_POLICY_NAT = "NAT_NAT44_POLICY_NAT"
    DHCP_OVERRIDE = "DHCP_OVERRIDE"
    DHCP_RELAY_IPV4 = "DHCP_RELAY_IPV4"
    DHCP_RELAY_IPV6 = "DHCP_RELAY_IPV6"
    DHCP_CLIENT_IPV4 = "DHCP_CLIENT_IPV4"
    DHCP_CLIENT_IPV6 = "DHCP_CLIENT_IPV6"
    DHCP_LOCAL_SERVER = "DHCP_LOCAL_SERVER"
    DNS_OVERRIDE = "DNS_OVERRIDE"
    MONITORING_OVERRIDE = "MONITORING_OVERRIDE"
    ACL_IPV4_STANDARD = "ACL_IPV4_STANDARD"
    ACL_IPV4_EXTENDED = "ACL_IPV4_EXTENDED"
    ACL_IPV6_STANDARD = "ACL_IPV6_STANDARD"
    ACL_IPV6_EXTENDED = "ACL_IPV6_EXTENDED"
    ACL_ATTACH_IPV4 = "ACL_ATTACH_IPV4"
    ACL_ATTACH_IPV6 = "ACL_ATTACH_IPV6"
    PBR_IPV4 = "PBR_IPV4"
    PBR_IPV6 = "PBR_IPV6"
    PBR_ATTACH_IPV4 = "PBR_ATTACH_IPV4"
    PBR_ATTACH_IPV6 = "PBR_ATTACH_IPV6"


SERVICE_POLICY_FEATURE_LABELS = {
    feature: feature.value.replace("_", " ").title() for feature in ServicePolicyFeature
}

_P12_NO_EVIDENCE = "No approved repository configuration or live-platform syntax evidence exists for this feature."
_P12_PLATFORM_UNVERIFIED = (
    "No deployed target/image and no feature-specific model mapping has been verified for this "
    "platform/feature combination; this is UNKNOWN, not a claim of platform support or denial."
)
_P12_CEOS_VARP = "Tracked S1/S2 cEOS 4.36.2F templates and logs use ip/ipv6 virtual-router address and a global virtual-router MAC."
_P12_CEOS_RELAY = "Tracked S1/S2 cEOS templates and logs use ip helper-address and ipv6 dhcp relay destination."
_P12_CEOS_ACL = "Tracked cEOS monitoring template uses ip access-list standard; tracked backup lab template uses named ip access-list entries."
_P12_CEOS_ACL6 = ("V2 Phase 9: ipv6 access-list [standard] NAME / ipv6 access-group NAME in|out, live-verified on the isolated "
                  "cEOS 4.36.2F (filtering by source, protocol and port, exact compensation). EOS accepts but does not "
                  "act on 'log' in an IPv6 entry ('ipv6 logging not supported'), so IPv6 logging is refused.")
_P12_LINUX_PAT = "Tracked live R3/R4 Ubuntu templates use nftables table ip EDGE_PAT with IPv4 source-prefix masquerade rules."
_P12_NAT_PT = "NAT-PT is deprecated/obsolete and is intentionally unsupported; it is not mapped to NAT64."


def _service_caps(
    mapping, *, default_status=CapabilityStatus.NOT_IMPLEMENTED,
    default_evidence=_P12_NO_EVIDENCE,
):
    return {
        feature: PlatformCapability(*mapping.get(feature, (default_status, default_evidence)))
        for feature in ServicePolicyFeature
    }


SERVICE_POLICY_CAPABILITIES = {
    "arista_ceos": _service_caps({
        ServicePolicyFeature.FHRP_VARP_IPV4: (CapabilityStatus.SUPPORTED, _P12_CEOS_VARP),
        ServicePolicyFeature.FHRP_VARP_IPV6: (CapabilityStatus.SUPPORTED, _P12_CEOS_VARP),
        ServicePolicyFeature.DHCP_OVERRIDE: (CapabilityStatus.SUPPORTED, _P12_CEOS_RELAY),
        ServicePolicyFeature.DHCP_RELAY_IPV4: (CapabilityStatus.SUPPORTED, _P12_CEOS_RELAY),
        ServicePolicyFeature.DHCP_RELAY_IPV6: (CapabilityStatus.SUPPORTED, _P12_CEOS_RELAY),
        ServicePolicyFeature.ACL_IPV4_STANDARD: (CapabilityStatus.SUPPORTED, _P12_CEOS_ACL),
        ServicePolicyFeature.ACL_IPV4_EXTENDED: (CapabilityStatus.SUPPORTED, _P12_CEOS_ACL),
        ServicePolicyFeature.ACL_ATTACH_IPV4: (CapabilityStatus.SUPPORTED, _P12_CEOS_ACL),
        ServicePolicyFeature.ACL_IPV6_STANDARD: (CapabilityStatus.SUPPORTED, _P12_CEOS_ACL6),
        ServicePolicyFeature.ACL_IPV6_EXTENDED: (CapabilityStatus.SUPPORTED, _P12_CEOS_ACL6),
        ServicePolicyFeature.ACL_ATTACH_IPV6: (CapabilityStatus.SUPPORTED, _P12_CEOS_ACL6),
        ServicePolicyFeature.NAT_NAT_PT_STATIC: (CapabilityStatus.UNSUPPORTED, _P12_NAT_PT),
    }),
    "ubuntu_frr": _service_caps({
        ServicePolicyFeature.NAT_NAT44_PAT: (CapabilityStatus.SUPPORTED, _P12_LINUX_PAT),
        ServicePolicyFeature.NAT_NAT44_STATEFUL: (CapabilityStatus.SUPPORTED, _P12_LINUX_PAT),
        ServicePolicyFeature.NAT_NAT_PT_STATIC: (CapabilityStatus.UNSUPPORTED, _P12_NAT_PT),
    }),
    "nokia_srlinux": _service_caps({
        ServicePolicyFeature.ACL_IPV4_STANDARD: (CapabilityStatus.SUPPORTED, _SRL_ACL),
        ServicePolicyFeature.ACL_IPV4_EXTENDED: (CapabilityStatus.SUPPORTED, _SRL_ACL),
        ServicePolicyFeature.ACL_IPV6_STANDARD: (CapabilityStatus.SUPPORTED, _SRL_ACL),
        ServicePolicyFeature.ACL_IPV6_EXTENDED: (CapabilityStatus.SUPPORTED, _SRL_ACL),
        ServicePolicyFeature.ACL_ATTACH_IPV4: (CapabilityStatus.SUPPORTED, _SRL_ACL),
        ServicePolicyFeature.ACL_ATTACH_IPV6: (CapabilityStatus.SUPPORTED, _SRL_ACL),
        ServicePolicyFeature.DHCP_OVERRIDE: (CapabilityStatus.SUPPORTED, _SRL_DHCP_RELAY),
        ServicePolicyFeature.DHCP_RELAY_IPV4: (CapabilityStatus.SUPPORTED, _SRL_DHCP_RELAY),
        ServicePolicyFeature.DHCP_RELAY_IPV6: (CapabilityStatus.SUPPORTED, _SRL_DHCP_RELAY),
        ServicePolicyFeature.NAT_NAT_PT_STATIC: (CapabilityStatus.UNSUPPORTED, _P12_NAT_PT),
    }, default_status=CapabilityStatus.UNKNOWN, default_evidence=_P12_PLATFORM_UNVERIFIED),
    "cisco_c8000v_iosxe": _service_caps({
        ServicePolicyFeature.NAT_NAT_PT_STATIC: (CapabilityStatus.UNSUPPORTED, _P12_NAT_PT),
    }, default_status=CapabilityStatus.NOT_IMPLEMENTED, default_evidence=_IOSXE),
    "cisco_iosxr": _service_caps({
        ServicePolicyFeature.ACL_IPV4_STANDARD: (CapabilityStatus.SUPPORTED, _IOSXR_ACL),
        ServicePolicyFeature.ACL_IPV4_EXTENDED: (CapabilityStatus.SUPPORTED, _IOSXR_ACL),
        ServicePolicyFeature.ACL_IPV6_STANDARD: (CapabilityStatus.SUPPORTED, _IOSXR_ACL),
        ServicePolicyFeature.ACL_IPV6_EXTENDED: (CapabilityStatus.SUPPORTED, _IOSXR_ACL),
        ServicePolicyFeature.ACL_ATTACH_IPV4: (CapabilityStatus.SUPPORTED, _IOSXR_ACL),
        ServicePolicyFeature.ACL_ATTACH_IPV6: (CapabilityStatus.SUPPORTED, _IOSXR_ACL),
        ServicePolicyFeature.DHCP_OVERRIDE: (CapabilityStatus.SUPPORTED, _IOSXR_DHCP_RELAY),
        ServicePolicyFeature.DHCP_RELAY_IPV4: (CapabilityStatus.SUPPORTED, _IOSXR_DHCP_RELAY),
        ServicePolicyFeature.DHCP_RELAY_IPV6: (CapabilityStatus.SUPPORTED, _IOSXR_DHCP_RELAY),
        ServicePolicyFeature.NAT_NAT_PT_STATIC: (CapabilityStatus.UNSUPPORTED, _P12_NAT_PT),
    }, default_status=CapabilityStatus.UNKNOWN, default_evidence=_P12_PLATFORM_UNVERIFIED),
    "sonic": _service_caps({
        ServicePolicyFeature.ACL_IPV4_STANDARD: (CapabilityStatus.SUPPORTED, _SONIC_ACL),
        ServicePolicyFeature.ACL_IPV4_EXTENDED: (CapabilityStatus.SUPPORTED, _SONIC_ACL),
        ServicePolicyFeature.ACL_IPV6_STANDARD: (CapabilityStatus.SUPPORTED, _SONIC_ACL),
        ServicePolicyFeature.ACL_IPV6_EXTENDED: (CapabilityStatus.SUPPORTED, _SONIC_ACL),
        ServicePolicyFeature.ACL_ATTACH_IPV4: (CapabilityStatus.SUPPORTED, _SONIC_ACL),
        ServicePolicyFeature.ACL_ATTACH_IPV6: (CapabilityStatus.SUPPORTED, _SONIC_ACL),
        ServicePolicyFeature.NAT_NAT_PT_STATIC: (CapabilityStatus.UNSUPPORTED, _P12_NAT_PT),
    }, default_status=CapabilityStatus.UNKNOWN, default_evidence=_P12_PLATFORM_UNVERIFIED),
}


def capability_for_service_policy(platform: str, feature) -> PlatformCapability:
    try:
        feature = ServicePolicyFeature(feature)
    except (ValueError, TypeError):
        raise ValueError(f"Unknown service/policy feature {feature!r}") from None
    if platform not in SERVICE_POLICY_CAPABILITIES:
        raise ValueError(f"Unknown platform {platform!r}")
    return SERVICE_POLICY_CAPABILITIES[platform][feature]


def is_service_policy_feature_selectable(platform: str, feature) -> bool:
    try:
        return capability_for_service_policy(platform, feature).status == CapabilityStatus.SUPPORTED
    except ValueError:
        return False


def resolve_service_policy_capability(platform: str, feature) -> PlatformCapability:
    """Public form of the renderer's own lookup (NOT_IMPLEMENTED for a valid
    vocabulary combination without a registry row)."""
    return _service_policy_capability_or_not_implemented(platform, feature)


def _service_policy_capability_or_not_implemented(platform: str, feature) -> PlatformCapability:
    """Preserved intent may contain a valid vocabulary combination for which
    the project deliberately has no renderer/capability row."""
    try:
        return capability_for_service_policy(platform, feature)
    except ValueError:
        return PlatformCapability(CapabilityStatus.NOT_IMPLEMENTED, _P12_NO_EVIDENCE)


def service_policy_capability_matrix() -> dict:
    return {
        "platforms": list(PLATFORM_DRIVERS.values()),
        "rows": [
            {
                "feature": feature.value,
                "label": SERVICE_POLICY_FEATURE_LABELS[feature],
                "deprecated": feature == ServicePolicyFeature.NAT_NAT_PT_STATIC,
                "cells": [
                    {
                        "platform": platform,
                        "status": SERVICE_POLICY_CAPABILITIES[platform][feature].status.value,
                        "label": CAPABILITY_STATUS_LABELS[SERVICE_POLICY_CAPABILITIES[platform][feature].status],
                        "evidence": SERVICE_POLICY_CAPABILITIES[platform][feature].evidence,
                    }
                    for platform in SERVICE_POLICY_CAPABILITIES
                ],
            }
            for feature in ServicePolicyFeature
        ],
    }


def _path(interface_id: str, field: str) -> str:
    return f"interfaces.{interface_id}.{field}"


def _wan_path(interface_id: str, field: str) -> str:
    return f"interfaces.{interface_id}.wan.{field}"


def _display(value) -> str:
    if value is None:
        return ""
    if isinstance(value, list):
        return field_validators.vlan_set_display(value)
    return str(value)


def _interface_template_descriptors(platform: str, interface: dict, interfaces_by_id: dict) -> list[dict]:
    kind = interface["kind"]
    template_name = f"{platform}/interface_{kind.lower()}.j2"
    interface_id = interface["id"]
    parent = interfaces_by_id.get(interface.get("parent_id") or "", {})
    fields = {
        field: {
            "path": _path(interface_id, field),
            "value": _display(interface.get(field)),
            "omit_if_empty": field in {"description", "mtu", "native_vlan"},
        }
        for field in (
            "name", "description", "admin_state", "mtu", "access_vlan", "trunk_allowed_vlans",
            "native_vlan", "encapsulation_vlan", "vlan_id"
        )
    }
    fields["parent_name"] = {
        "path": _path(interface_id, "parent_id"),
        "value": parent.get("name") or interface.get("parent_id") or "",
        "omit_if_empty": False,
    }
    flags = {
        "admin_disabled": interface.get("admin_state") == "DISABLED",
        "ceos_subinterface_mtu_requested": platform == "ceos" and kind == "SUBINTERFACE" and interface.get("mtu") not in (None, ""),
        "accepted_name": interface.get("name") or "<interface-name-required>",
        "accepted_parent_name": parent.get("name") or "<parent-required>",
        "accepted_encapsulation_vlan": interface.get("encapsulation_vlan") or "<vlan-required>",
        # SR Linux refuses an untagged routed subinterface 0 on a port with ``vlan-tagging true`` ("vlan tagging true
        # inconsistent with subinterface 0", isolated 24.10.7): a port that carries tagged subinterfaces is a carrier only.
        "srl_tagged_carrier": platform == "srlinux" and kind == "ROUTED_PHYSICAL" and any(
            other.get("kind") == "SUBINTERFACE" and other.get("parent_id") == interface_id
            for other in interfaces_by_id.values()),
    }
    return feature_template_renderer.render_descriptors(template_name=template_name, fields=fields, flags=flags)


def _address_descriptors(platform: str, interface: dict, interfaces_by_id: dict | None = None) -> list[dict]:
    result = []
    interface_id = interface["id"]
    addresses = sorted((interface.get("addresses") or {}).values(), key=lambda item: (int(item.get("sequence") or 0), item.get("id", "")))
    for address in addresses:
        address_id = address["id"]
        source_interface_id = address.get("_source_interface_id") or interface_id
        prefix = f"interfaces.{source_interface_id}.addresses.{address_id}"
        if address.get("source") == "AUTO":
            result.append({
                "kind": "field", "path": f"{prefix}.ipam_prefix",
                "template": "! AUTO IPAM prefix {value}: allocation unresolved and unreserved",
                "value": address.get("ipam_prefix") or "(not selected)",
            })
            continue
        cidr = address.get("cidr") or ""
        if platform == "ceos":
            command = "ip address {value}" if address.get("family") == "IPV4" else "ipv6 address {value}"
            if address.get("family") == "IPV4" and address.get("role") == "SECONDARY":
                command += " secondary"
            template = "   " + command
        elif platform == "srlinux":
            if interface.get("kind") == "SUBINTERFACE":
                parent = (interfaces_by_id or {}).get(interface.get("parent_id") or "", {})
                base_name = parent.get("name") or "<parent-required>"
                subif_index = interface.get("encapsulation_vlan") or "<vlan-required>"
            else:
                base_name = interface.get("name") or "<interface-name-required>"
                subif_index = 0
            family_kw = "ipv4" if address.get("family") == "IPV4" else "ipv6"
            template = f"set interface {base_name} subinterface {subif_index} {family_kw} address " + "{value}"
            # SR Linux 24.10 leaves an address family administratively disabled until it is enabled explicitly; an
            # address alone keeps the subinterface oper-down ("no-ip-config").  Proven on the isolated 24.10.7 node.
            enable = f"set interface {base_name} subinterface {subif_index} {family_kw} admin-state enable"
            if cidr and not any(row.get("text") == enable for row in result):
                result.append({"kind": "static", "text": enable})
        elif platform in ("iosxe", "iosxr"):
            if address.get("family") == "IPV4":
                command = ("ip" if platform == "iosxe" else "ipv4") + " address {value}"
                cidr = _cidr_to_address_mask(cidr) if cidr else cidr
            else:
                command = "ipv6 address {value}"
            template = " " + command
        else:
            flag = "-6 " if address.get("family") == "IPV6" else ""
            template = f"ip {flag}addr replace {{value}} dev {interface.get('name') or '<interface-name-required>'}"
        result.append({
            "kind": "field", "path": f"{prefix}.cidr", "template": template,
            "value": cidr, "omit_if_empty": True,
        })
    return result


def _wan_descriptors(interface: dict) -> list[dict]:
    wan = interface.get("wan") or {}
    if wan.get("state") != "ENABLED":
        return []
    interface_id = interface["id"]
    descriptors = [{"kind": "static", "text": "! WAN metadata only - no route or routing protocol is generated"}]
    for field, label in (
        ("provider_name", "provider"), ("peer_label", "peer"), ("peer_ipv4", "peer IPv4"),
        ("peer_ipv6", "peer IPv6"), ("gateway_ipv4", "next-hop IPv4"),
        ("gateway_ipv6", "next-hop IPv6"), ("mtu", "WAN MTU"), ("description", "WAN description"),
    ):
        descriptors.append({
            "kind": "field", "path": _wan_path(interface_id, field),
            "template": f"! WAN {label}: {{value}}", "value": _display(wan.get(field)), "omit_if_empty": True,
        })
    return descriptors


_ROUTING_FAMILIES = ("static_routes", "rip", "ospf", "isis", "eigrp", "bgp")


def _seq_key(obj: dict):
    return (int(obj.get("sequence") or 0), obj.get("id", ""))


def _routing_object_protocol(family: str, obj: dict) -> RoutingProtocol:
    if family == "static_routes":
        return RoutingProtocol.STATIC_IPV4 if obj.get("family") == "IPV4" else RoutingProtocol.STATIC_IPV6
    if family == "rip":
        return RoutingProtocol.RIPV2 if obj.get("address_family") == "IPV4" else RoutingProtocol.RIPNG
    if family == "ospf":
        return RoutingProtocol.OSPFV2 if obj.get("version") == "OSPFV2" else RoutingProtocol.OSPFV3
    if family == "isis":
        return RoutingProtocol.ISIS
    if family == "eigrp":
        return RoutingProtocol.EIGRP_IPV4 if obj.get("address_family") == "IPV4" else RoutingProtocol.EIGRP_IPV6
    raise ValueError(f"{family!r} has no single routing protocol.")


def routing_object_protocol(family: str, obj: dict) -> RoutingProtocol:
    """Public form of the renderer's own object -> RoutingProtocol rule."""
    return _routing_object_protocol(family, obj)


def _routing_object_label(family: str, obj: dict) -> str:
    if family == "static_routes":
        return f"static route {obj.get('destination') or obj.get('id')}"
    if family == "bgp":
        return f"BGP AS{obj.get('local_asn')} ({obj.get('id')})"
    return f"{family.upper()} instance {obj.get('id')}"


def _unsupported_line(display_name: str, label: str, status: str) -> dict:
    return {
        "kind": "static",
        "text": f"{UNSUPPORTED_OBJECT_MARKER} {label} is {status} for {display_name}; intent preserved",
    }


def _render_family_objects(platform, display_name, family, objects, interfaces_by_id, renderer) -> list[dict]:
    lines: list[dict] = []
    for obj in sorted(objects, key=_seq_key):
        capability = capability_for_routing(platform, _routing_object_protocol(family, obj))
        if capability.status != CapabilityStatus.SUPPORTED or renderer is None:
            lines.append(_unsupported_line(display_name, _routing_object_label(family, obj), capability.status.value))
            continue
        lines.extend(renderer(obj, interfaces_by_id))
        lines.append({"kind": "static", "text": "!"})
    return lines


def _render_routing_generic(
    *, platform, display_name, routing, interfaces, static_renderer, rip_renderer, ospf_renderer, bgp_renderer,
    isis_renderer=None,
) -> list[dict]:
    routing = routing or {}
    if not any(routing.get(family) for family in _ROUTING_FAMILIES):
        return [{"kind": "static", "text": "! Routing: not configured in current candidate"}]
    interfaces_by_id = {item["id"]: item for item in (interfaces or [])}

    lines: list[dict] = []
    lines.extend(_render_family_objects(
        platform, display_name, "static_routes", (routing.get("static_routes") or {}).values(),
        interfaces_by_id, static_renderer,
    ))
    for family, renderer in (("rip", rip_renderer), ("ospf", ospf_renderer), ("isis", isis_renderer), ("eigrp", None)):
        lines.extend(_render_family_objects(
            platform, display_name, family, (routing.get(family) or {}).values(), interfaces_by_id, renderer,
        ))
    for instance in sorted((routing.get("bgp") or {}).values(), key=_seq_key):
        supported = is_routing_protocol_selectable(platform, RoutingProtocol.BGP_IPV4) or is_routing_protocol_selectable(
            platform, RoutingProtocol.BGP_IPV6
        )
        if not supported or bgp_renderer is None:
            lines.append(_unsupported_line(display_name, _routing_object_label("bgp", instance), CapabilityStatus.NOT_IMPLEMENTED.value))
            continue
        lines.extend(bgp_renderer(instance, interfaces_by_id))
        lines.append({"kind": "static", "text": "!"})
    return lines or [{"kind": "static", "text": "! Routing: not configured in current candidate"}]


def _unsupported_routing_lines(platform: str, display_name: str, routing: dict) -> list[dict]:
    """Base-driver fallback: every object is honestly reported unsupported."""
    lines: list[dict] = []
    for family in _ROUTING_FAMILIES:
        if family == "bgp":
            for instance in sorted((routing.get("bgp") or {}).values(), key=_seq_key):
                lines.append(_unsupported_line(display_name, _routing_object_label("bgp", instance), CapabilityStatus.NOT_IMPLEMENTED.value))
            continue
        lines.extend(_render_family_objects(platform, display_name, family, (routing.get(family) or {}).values(), {}, None))
    return lines or [{"kind": "static", "text": "! Routing: not configured in current candidate"}]


def _route_next_hop_display(route: dict, interfaces_by_id: dict) -> str:
    if route.get("next_hop_type") == "INTERFACE":
        interface = interfaces_by_id.get(route.get("next_hop_interface_id") or "", {})
        return interface.get("name") or "<next-hop-interface-required>"
    return route.get("next_hop_address") or "<next-hop-address-required>"


def _static_route_descriptors(route: dict, interfaces_by_id: dict, *, template_platform: str) -> list[dict]:
    """Shared syntax file (routing_static_route.j2) for cEOS and FRR: 'ip
    route'/'ipv6 route' is identical vtysh/EOS CLI syntax on both platforms
    for this project's evidence -- see docs/DEVICE_BUILDER_ROUTING.md."""
    if not route.get("enabled", True):
        return [{"kind": "static", "text": f"! static route {route.get('destination') or route.get('id')} disabled in intent; not rendered"}]
    keyword = "ipv6 route" if route.get("family") == "IPV6" else "ip route"
    next_hop = _route_next_hop_display(route, interfaces_by_id)
    suffix = ""
    if route.get("distance") is not None:
        suffix += f" {route['distance']}"
    if route.get("tag") is not None:
        suffix += f" tag {route['tag']}"
    return feature_template_renderer.render_descriptors(
        template_name=f"{template_platform}/routing_static_route.j2",
        fields={"destination": {
            "path": f"routing.static_routes.{route['id']}.destination",
            "value": route.get("destination") or "", "omit_if_empty": True,
        }},
        flags={"keyword": keyword, "next_hop": next_hop, "suffix": suffix},
    )


def _connected_network_display(interface: dict) -> str:
    addresses = [
        address for address in (interface.get("addresses") or {}).values()
        if address.get("cidr") and address.get("family") == "IPV4"
    ]
    if not addresses:
        return f"<no IPv4 address configured on {interface.get('name') or interface.get('id') or 'interface'}>"
    best = sorted(addresses, key=lambda item: (int(item.get("sequence") or 0), item.get("id", "")))[0]
    try:
        network = ipaddress.ip_interface(best["cidr"]).network
    except ValueError:
        return "<invalid address>"
    return str(network)


def _ceos_rip_descriptors(instance: dict, interfaces_by_id: dict) -> list[dict]:
    """RIPv2 only -- no RIPv1 field/keyword exists anywhere in this module.

    A disabled instance is rendered, administratively shut down: EOS keeps ``router rip`` with ``shutdown`` (its own
    default), which is exactly what ``parser_ceos`` imports as ``enabled: False``.  Rendering nothing instead dropped the
    instance on a round trip and left a running RIP process untouched by a plan (V2 Phase 9; live-verified, cEOS 4.36.2F)."""
    lines = feature_template_renderer.render_descriptors(template_name="ceos/routing_rip.j2", fields={}, flags={})
    lines.append({"kind": "static", "text": "   no shutdown" if instance.get("enabled", True) else "   shutdown"})
    for binding in sorted((instance.get("interfaces") or {}).values(), key=_seq_key):
        interface = interfaces_by_id.get(binding.get("interface_id") or "", {})
        lines.append({"kind": "static", "text": f"   network {_connected_network_display(interface)}"})
        if binding.get("passive"):
            lines.append({"kind": "static", "text": f"{UNSUPPORTED_OBJECT_MARKER} cEOS RIP passive binding on {interface.get('name') or binding.get('interface_id')} has no supported EOS command; intent preserved"})
    return lines


# cEOS names the IS-IS instance; the intent model carries no tag field, so one fixed tag is rendered.  EOS runs one
# instance per VRF, which is also why a second IS-IS instance in the same candidate merges into this scope.
CEOS_ISIS_TAG = "NMAS"
_CEOS_ISIS_LEVELS = {"LEVEL_1": "level-1", "LEVEL_2": "level-2", "LEVEL_1_2": "level-1-2"}


def _ceos_isis_descriptors(instance: dict, interfaces_by_id: dict) -> list[dict]:
    """The IS-IS process only.  Interface activation is rendered inside each owning interface
    (``_ceos_isis_interface_contributions``), never as a second copy of the interface context."""
    return feature_template_renderer.render_descriptors(
        template_name="ceos/routing_isis.j2",
        fields={"net": {"path": f"routing.isis.{instance['id']}.net", "value": instance.get("net") or "", "omit_if_empty": True}},
        flags={"tag": CEOS_ISIS_TAG, "level": _CEOS_ISIS_LEVELS.get(instance.get("level") or "LEVEL_2", "level-2"),
               "af_ipv4": bool(instance.get("address_family_ipv4")), "af_ipv6": bool(instance.get("address_family_ipv6"))},
    )


def _ceos_isis_interface_contributions(interface: dict, *, platform: str = "arista_ceos") -> list[dict]:
    """``isis enable`` and its options inside the owning interface.  A passive binding advertises the connected
    prefix without forming an adjacency; ``isis metric`` is the single-topology metric that steers both families.
    Nothing is rendered unless the capability registry reports IS-IS SUPPORTED on ``platform``."""
    result: list[dict] = []
    if not is_routing_protocol_selectable(platform, RoutingProtocol.ISIS):
        return result
    for binding in (interface.get("_scope") or {}).get("isis", []):
        path = binding.get("path") or "routing.isis"
        result.append({"kind": "static", "text": f"   isis enable {CEOS_ISIS_TAG}"})
        if binding.get("metric") is not None:
            result.append({"kind": "field", "path": f"{path}.metric", "template": "   isis metric {value}", "value": binding["metric"]})
        if binding.get("passive"):
            result.append({"kind": "static", "text": "   isis passive"})
    return result


FRR_ISIS_TAG = "NMAS44"
_FRR_ISIS_LEVELS = {"LEVEL_1": "level-1", "LEVEL_2": "level-2-only", "LEVEL_1_2": "level-1-2"}


def _frr_isis_descriptors(instance: dict, interfaces_by_id: dict) -> list[dict]:
    """FRR's named IS-IS process; address-family enablement lives on interfaces."""
    return feature_template_renderer.render_descriptors(
        template_name="ubuntu_frr/routing_isis.j2",
        fields={"net": {"path": f"routing.isis.{instance['id']}.net", "value": instance.get("net") or "", "omit_if_empty": True}},
        flags={"tag": FRR_ISIS_TAG, "level": _FRR_ISIS_LEVELS.get(instance.get("level") or "LEVEL_2", "level-2-only")},
    )


def _frr_isis_interface_contributions(interface: dict) -> list[dict]:
    if not is_routing_protocol_selectable("ubuntu_frr", RoutingProtocol.ISIS):
        return []
    lines: list[dict] = []
    for binding in (interface.get("_scope") or {}).get("isis", []):
        path = binding.get("path") or "routing.isis"
        if binding.get("address_family_ipv4"):
            lines.append({"kind": "static", "text": f"   ip router isis {FRR_ISIS_TAG}"})
        if binding.get("address_family_ipv6"):
            lines.append({"kind": "static", "text": f"   ipv6 router isis {FRR_ISIS_TAG}"})
        if not (binding.get("address_family_ipv4") or binding.get("address_family_ipv6")):
            continue
        lines.append({"kind": "static", "text": "   isis network point-to-point"})
        lines.append({"kind": "static", "text": f"   isis circuit-type {_FRR_ISIS_LEVELS.get(binding.get('level') or 'LEVEL_2', 'level-2-only')}"})
        if binding.get("metric") is not None:
            lines.append({"kind": "field", "path": f"{path}.metric", "template": "   isis metric {value}", "value": binding["metric"]})
        if binding.get("passive"):
            lines.append({"kind": "static", "text": "   isis passive"})
    return lines


def _frr_rip_descriptors(instance: dict, interfaces_by_id: dict) -> list[dict]:
    """FRR ripd/ripngd syntax; activation is by interface name."""
    if not instance.get("enabled", True):
        # ripd / ripngd have no administrative shutdown: refuse instead of silently leaving a running process in place
        return [{"kind": "static", "text": f"{UNSUPPORTED_OBJECT_MARKER} a disabled RIP instance has no FRR form (ripd has no "
                                         "shutdown); remove the instance to remove the process"}]
    ipv6 = instance.get("address_family") == "IPV6"
    lines = feature_template_renderer.render_descriptors(
        template_name="ubuntu_frr/routing_rip.j2", fields={}, flags={"ipv6": ipv6}
    )
    if not ipv6:
        lines.append({"kind": "static", "text": "   version 2"})
    for binding in sorted((instance.get("interfaces") or {}).values(), key=_seq_key):
        interface = interfaces_by_id.get(binding.get("interface_id") or "", {})
        name = interface.get("name") or "<interface-required>"
        lines.append({"kind": "static", "text": f"   network {name}"})
        if binding.get("passive"):
            lines.append({"kind": "static", "text": f"   passive-interface {name}"})
    return lines


def _ospf_descriptors(instance: dict, interfaces_by_id: dict, *, v2_template: str, v3_template: str) -> list[dict]:
    is_v3 = instance.get("version") == "OSPFV3"
    process = instance.get("process_id")
    process_display = str(process) if process not in (None, "") else "<process-id-required>"
    bindings = sorted((instance.get("interfaces") or {}).values(), key=_seq_key)
    passive_lines = [
        interfaces_by_id.get(binding.get("interface_id") or "", {}).get("name") or binding.get("interface_id")
        for binding in bindings if binding.get("passive")
    ]

    lines = feature_template_renderer.render_descriptors(
        template_name=v3_template if is_v3 else v2_template,
        fields={"router_id": {
            "path": f"routing.ospf.{instance['id']}.router_id",
            "value": instance.get("router_id") or "", "omit_if_empty": True,
        }},
        flags={"process_display": process_display, "passive_lines": passive_lines},
    )
    if not is_v3:
        for network in sorted((instance.get("networks") or {}).values(), key=_seq_key):
            lines.append({
                "kind": "field", "path": f"routing.ospf.{instance['id']}.networks.{network['id']}.prefix",
                "template": "   network {value} area " + str(network.get("area") or "0.0.0.0"),
                "value": network.get("prefix") or "", "omit_if_empty": True,
            })
    return lines


def _ceos_ospf_descriptors(instance: dict, interfaces_by_id: dict) -> list[dict]:
    return _ospf_descriptors(
        instance, interfaces_by_id,
        v2_template="ceos/routing_ospfv2.j2", v3_template="ceos/routing_ospfv3.j2",
    )


def _frr_ospf_descriptors(instance: dict, interfaces_by_id: dict) -> list[dict]:
    lines = _ospf_descriptors(
        instance, interfaces_by_id,
        v2_template="ubuntu_frr/routing_ospfv2.j2", v3_template="ubuntu_frr/routing_ospfv3.j2",
    )
    bound = set(instance.get("_bound_networks") or [])
    for binding in (instance.get("interfaces") or {}).values():
        interface = interfaces_by_id.get(binding.get("interface_id") or "", {})
        bound.add(_connected_network_display(interface))
    return [line for line in lines if not (line.get("path", "").endswith(".prefix") and line.get("value") in bound)]


def _ospf_interface_contributions(interface: dict, *, ceos: bool, platform: str) -> list[dict]:
    """Render normalized OSPF attachment intent inside its owning interface -- only for an OSPF version the capability
    registry reports SUPPORTED on ``platform`` (otherwise the routing renderer's refusal marker stands alone)."""
    result: list[dict] = []
    for binding in (interface.get("_scope") or {}).get("ospf", []):
        is_v3 = binding.get("version") == "OSPFV3"
        if not is_routing_protocol_selectable(platform, RoutingProtocol.OSPFV3 if is_v3 else RoutingProtocol.OSPFV2):
            continue
        process = binding.get("process_id")
        process_display = str(process) if process not in (None, "") else "<process-id-required>"
        if is_v3:
            area_template = (
                f"   ipv6 ospf {process_display} area {{value}}"
                if ceos else "   ipv6 ospf6 area {value}"
            )
        else:
            area_template = "   ip ospf area {value}"
        path = binding.get("path") or "routing.ospf"
        result.append({
            "kind": "field", "path": f"{path}.area", "template": area_template,
            "value": binding.get("area") or "", "omit_if_empty": True,
        })
        if binding.get("cost") is not None:
            result.append({
                "kind": "field", "path": f"{path}.cost",
                "template": ("   ipv6 ospf cost {value}" if ceos and is_v3 else
                             "   ipv6 ospf6 cost {value}" if is_v3 else "   ip ospf cost {value}"),
                "value": binding["cost"],
            })
        if binding.get("network_type") == "POINT_TO_POINT":
            result.append({
                "kind": "static",
                "text": ("   ipv6 ospf network point-to-point" if ceos and is_v3 else
                         "   ipv6 ospf6 network point-to-point" if is_v3 else "   ip ospf network point-to-point"),
            })
    return result


def _bgp_instance_descriptors(instance: dict, interfaces_by_id: dict, *, template_name: str, af_suffix: str, close_af: bool) -> list[dict]:
    lines = feature_template_renderer.render_descriptors(
        template_name=template_name,
        fields={"router_id": {
            "path": f"routing.bgp.{instance['id']}.router_id",
            "value": instance.get("router_id") or "", "omit_if_empty": True,
        }},
        flags={"local_asn": instance.get("local_asn")},
    )
    neighbors = sorted((instance.get("neighbors") or {}).values(), key=_seq_key)
    for neighbor in neighbors:
        peer = neighbor.get("peer_address")
        lines.append({
            "kind": "field", "path": f"routing.bgp.{instance['id']}.neighbors.{neighbor['id']}.remote_asn",
            "template": f"   neighbor {peer} remote-as " + "{value}", "value": neighbor.get("remote_asn"),
        })
        if neighbor.get("description"):
            lines.append({
                "kind": "field", "path": f"routing.bgp.{instance['id']}.neighbors.{neighbor['id']}.description",
                "template": f"   neighbor {peer} description " + "{value}",
                "value": neighbor.get("description"), "omit_if_empty": True,
            })
        if neighbor.get("update_source_interface_id"):
            source = interfaces_by_id.get(neighbor["update_source_interface_id"], {})
            lines.append({"kind": "static", "text": f"   neighbor {peer} update-source {source.get('name') or neighbor['update_source_interface_id']}"})
        if neighbor.get("ebgp_multihop") is not None:
            lines.append({
                "kind": "field", "path": f"routing.bgp.{instance['id']}.neighbors.{neighbor['id']}.ebgp_multihop",
                "template": f"   neighbor {peer} ebgp-multihop " + "{value}", "value": neighbor["ebgp_multihop"],
            })
        if neighbor.get("password_ref"):
            lines.append({"kind": "static", "text": f"   ! neighbor {peer} authentication reference present ({neighbor['password_ref']}); unresolved for deployment"})
        if neighbor.get("shutdown"):
            lines.append({"kind": "static", "text": f"   neighbor {peer} shutdown"})
    lines.append({"kind": "static", "text": "!"})

    for family, activate_key in (("IPV4", "activate_ipv4"), ("IPV6", "activate_ipv6")):
        active_neighbors = [n for n in neighbors if n.get(activate_key)]
        active_networks = sorted(
            (n for n in (instance.get("networks") or {}).values() if n.get("family") == family), key=_seq_key,
        )
        if not active_neighbors and not active_networks:
            continue
        lines.append({"kind": "static", "text": f"   address-family {family.lower()}{af_suffix}"})
        for neighbor in active_neighbors:
            peer = neighbor.get("peer_address")
            lines.append({"kind": "static", "text": f"      neighbor {peer} activate"})
            if neighbor.get("next_hop_self"):
                lines.append({"kind": "static", "text": f"      neighbor {peer} next-hop-self"})
            if neighbor.get("route_reflector_client"):
                lines.append({"kind": "static", "text": f"      neighbor {peer} route-reflector-client"})
        for network in active_networks:
            lines.append({
                "kind": "field", "path": f"routing.bgp.{instance['id']}.networks.{network['id']}.cidr",
                "template": "      network {value}", "value": network.get("cidr") or "", "omit_if_empty": True,
            })
        if close_af:
            lines.append({"kind": "static", "text": "   exit-address-family"})
        lines.append({"kind": "static", "text": "!"})
    return lines


def _ceos_bgp_descriptors(instance: dict, interfaces_by_id: dict) -> list[dict]:
    return _bgp_instance_descriptors(
        instance, interfaces_by_id, template_name="ceos/routing_bgp.j2", af_suffix="", close_af=False
    )


def _frr_bgp_descriptors(instance: dict, interfaces_by_id: dict) -> list[dict]:
    return _bgp_instance_descriptors(
        instance, interfaces_by_id, template_name="ubuntu_frr/routing_bgp.j2", af_suffix=" unicast", close_af=True
    )


# --- SR Linux (Phase 20.5): model-driven `set` syntax, verified against Nokia SR Linix
# Configuration Basics Guide (interfaces, network-instances, OSPF, BGP) and the
# srl_nokia-acl data-model reference. No deployed node exists in this lab -- see
# docs/PHASE_20_5_PLATFORM_CAPABILITY_AUDIT.md -- so this is fixture-tested, not live-tested.

def _srl_static_route_descriptors(route: dict, interfaces_by_id: dict) -> list[dict]:
    if not route.get("enabled", True):
        return [{"kind": "static", "text": f"! static route {route.get('destination') or route.get('id')} disabled in intent; not rendered"}]
    route_id = route["id"]
    group_name = f"nhg-{route_id}"
    lines = [{
        "kind": "field", "path": f"routing.static_routes.{route_id}.destination",
        "template": "set network-instance default static-routes route {value} admin-state enable",
        "value": route.get("destination") or "", "omit_if_empty": True,
    }]
    if route.get("distance") is not None:
        lines.append({
            "kind": "field", "path": f"routing.static_routes.{route_id}.distance",
            "template": f"set network-instance default static-routes route {route.get('destination') or '<destination-required>'} preference " + "{value}",
            "value": route["distance"],
        })
    if route.get("tag") is not None:
        lines.append({"kind": "static", "text": "! route tag has no SR Linix static-route equivalent; preserved in intent only"})
    if route.get("next_hop_type") == "INTERFACE":
        interface = interfaces_by_id.get(route.get("next_hop_interface_id") or "", {})
        lines.append({"kind": "static", "text": (
            f"! next-hop interface {interface.get('name') or route.get('next_hop_interface_id') or '<next-hop-interface-required>'}: "
            "SR Linix next-hop-groups require an IP next-hop address in this project's model; not rendered"
        )})
        return lines
    dest = route.get("destination") or "<destination-required>"
    lines.append({
        "kind": "field", "path": f"routing.static_routes.{route_id}.destination",
        "template": f"set network-instance default static-routes route {{value}} next-hop-group {group_name}",
        "value": route.get("destination") or "", "omit_if_empty": True,
    })
    lines.append({
        "kind": "field", "path": f"routing.static_routes.{route_id}.next_hop_address",
        "template": f"set network-instance default next-hop-groups group {group_name} nexthop 1 ip-address " + "{value}",
        "value": route.get("next_hop_address") or "", "omit_if_empty": True,
    })
    return lines


def _srl_area(value) -> str:
    """An OSPF area as SR Linux requires it: dotted-quad ("0" -> "0.0.0.0"); anything else is left for validation to refuse."""
    text = str(value if value is not None else "").strip()
    try:
        return str(ipaddress.IPv4Address(int(text) if text.isdigit() else text))
    except (ipaddress.AddressValueError, ValueError):
        return text or "<area-required>"


def _srl_ospf_descriptors(instance: dict, interfaces_by_id: dict) -> list[dict]:
    """OSPF instance in SR Linux 24.10 form (verified by ``commit validate`` and live adjacency on 24.10.7).

    SR Linux enables OSPF per interface only (``area A interface X``); it has no ``network`` statement.  A network the
    instance's own interface bindings already cover is redundant and omitted (as for FRR); any other network has no SR Linux
    form and is refused with the explicit marker rather than dropped.  Passive bindings render ``passive true`` on their
    area interface (the interface contribution renders the area, cost and network type).
    """
    is_v3 = instance.get("version") == "OSPFV3"
    process = instance.get("process_id")
    process_display = str(process) if process not in (None, "") else "<process-id-required>"
    lines = feature_template_renderer.render_descriptors(
        template_name="srlinux/routing_ospfv3.j2" if is_v3 else "srlinux/routing_ospfv2.j2",
        fields={"router_id": {
            "path": f"routing.ospf.{instance['id']}.router_id",
            "value": instance.get("router_id") or "", "omit_if_empty": True,
        }},
        flags={"process_display": process_display},
    )
    bound = set(instance.get("_bound_networks") or [])
    for binding in sorted((instance.get("interfaces") or {}).values(), key=_seq_key):
        interface = interfaces_by_id.get(binding.get("interface_id") or "")
        if interface is None:
            continue
        bound.add(_connected_network_display(interface))
        if binding.get("passive"):
            lines.append({
                "kind": "field", "path": f"routing.ospf.{instance['id']}.interfaces.{binding['id']}.passive",
                "template": (f"set network-instance default protocols ospf instance {process_display} area "
                             f"{_srl_area(binding.get('area'))} interface {_srl_subinterface_ref(interface)} passive {{value}}"),
                "value": "true",
            })
    if not is_v3:
        for network in sorted((instance.get("networks") or {}).values(), key=_seq_key):
            if network.get("prefix") in bound:
                continue
            lines.append({"kind": "static", "text": (
                f"{UNSUPPORTED_OBJECT_MARKER} OSPF network {network.get('prefix') or network.get('id')} area "
                f"{network.get('area') or '0'} has no SR Linux form (OSPF is enabled per interface); bind its interfaces instead"
            )})
    return lines


def _srl_interface_context(interface: dict) -> tuple[str, object]:
    """Return the physical interface name and subinterface index."""
    name = interface.get("name") or "<interface-name-required>"
    if interface.get("kind") != "SUBINTERFACE":
        return name, 0
    index = interface.get("encapsulation_vlan")
    if index in (None, ""):
        return name, "<encapsulation-vlan-required>"
    suffix = f".{index}"
    parent_name = name[:-len(suffix)] if name.endswith(suffix) else name
    return parent_name, index


def _srl_subinterface_ref(interface: dict) -> str:
    """Return the SR Linux network-instance ``<parent>.<index>`` reference.

    A canonical SUBINTERFACE's display name commonly already contains its VLAN
    suffix (for example ``ethernet-1/2.100``).  Appending the encapsulation VLAN
    to that display name produced the invalid ``ethernet-1/2.100.100`` in OSPF
    and ACL attachment paths.  Interface/address rendering already resolves the
    physical parent; these flat contributors need the equivalent deterministic
    spelling without access to the parent map.
    """
    parent_name, index = _srl_interface_context(interface)
    return f"{parent_name}.{index}"


def _srl_ospf_interface_contributions(interface: dict) -> list[dict]:
    """OSPF area/interface assignment: SR Linux attaches interfaces to an OSPF area at the protocol-instance level, not
    inside an interface CLI block, so this renders as its own flat `set` line rather than nested text.  The area is the
    dotted-quad form SR Linux requires."""
    lines: list[dict] = []
    subif = _srl_subinterface_ref(interface)
    for binding in (interface.get("_scope") or {}).get("ospf", []):
        protocol = RoutingProtocol.OSPFV3 if binding.get("version") == "OSPFV3" else RoutingProtocol.OSPFV2
        if not is_routing_protocol_selectable("nokia_srlinux", protocol):
            continue
        process = binding.get("process_id")
        process_display = str(process) if process not in (None, "") else "<process-id-required>"
        path = binding.get("path") or "routing.ospf"
        area = _srl_area(binding.get("area")) if binding.get("area") not in (None, "") else ""
        prefix = f"set network-instance default protocols ospf instance {process_display} area {area or '<area-required>'} interface {subif}"
        if area:
            lines.append({
                "kind": "field", "path": f"{path}.area",
                "template": f"set network-instance default protocols ospf instance {process_display} area {{value}} interface {subif}",
                "value": area,
            })
        if binding.get("cost") is not None:
            lines.append({"kind": "field", "path": f"{path}.cost", "template": f"{prefix} metric {{value}}", "value": binding["cost"]})
        if binding.get("network_type") == "POINT_TO_POINT":
            lines.append({"kind": "static", "text": f"{prefix} interface-type point-to-point"})
    return lines


_SRL_AFI = (("IPV4", "ipv4-unicast"), ("IPV6", "ipv6-unicast"))


def srl_bgp_policy_name(instance: dict) -> str:
    """The NMAS-owned routing-policy (and prefix-set) that advertises one BGP instance's networks."""
    return f"nmas-bgp-{instance.get('id') or 'instance'}"


def _srl_local_address(source: dict, peer: str) -> str:
    """The update-source interface's address of the peer's family: SR Linux ``transport local-address`` takes an IP."""
    family = "IPV6" if ":" in str(peer or "") else "IPV4"
    for address in sorted((source.get("addresses") or {}).values(), key=_seq_key):
        if address.get("family") == family and address.get("cidr"):
            try:
                return str(ipaddress.ip_interface(address["cidr"]).ip)
            except ValueError:
                break
    return f"<{family.lower()}-address-of-{source.get('name') or 'update-source'}-required>"


def _srl_bgp_descriptors(instance: dict, interfaces_by_id: dict) -> list[dict]:
    """BGP in SR Linux 24.10 form (verified by ``commit validate`` and live sessions on 24.10.7).

    * SR Linux refuses a BGP instance without an enabled address family, and every Configlet commits on its own: the
      instance therefore enables IPv4 and IPv6 unicast itself, and each neighbor's group states BOTH families explicitly
      (enable when the neighbor activates it, disable otherwise), so no group inherits an activation it was not given.
    * Every neighbor references a mandatory peer-group; one group per neighbor (this model has no peer-group object).
    * An enabled group / neighbor must have an enabled family: one that activates none is rendered administratively
      disabled (and enabled again by the address-family activation that gives it a family).
    * A ``network`` is advertised the SR Linux way: an NMAS-owned prefix-set (exact match) and an accepting policy statement,
      exported at BGP level so it applies to every peer like a network statement does.
    * SR Linux applies RFC 8212 by default (an eBGP route is neither imported nor exported without a policy; observed:
      received-routes 1, active-routes 0).  The NMAS BGP model carries no import/export policy, so -- exactly like the FRR
      rendering's ``no bgp ebgp-requires-policy`` -- the instance turns that default off.
    """
    instance_id = instance["id"]
    lines = [
        {"kind": "static", "text": f"set network-instance default protocols bgp autonomous-system {instance.get('local_asn')}"},
        {"kind": "static", "text": "set network-instance default protocols bgp admin-state enable"},
        {
            "kind": "field", "path": f"routing.bgp.{instance_id}.router_id",
            "template": "set network-instance default protocols bgp router-id {value}",
            "value": instance.get("router_id") or "", "omit_if_empty": True,
        },
        *({"kind": "static", "text": f"set network-instance default protocols bgp afi-safi {afi} admin-state enable"}
          for _family, afi in _SRL_AFI),
        {"kind": "static", "text": "set network-instance default protocols bgp ebgp-default-policy import-reject-all false"},
        {"kind": "static", "text": "set network-instance default protocols bgp ebgp-default-policy export-reject-all false"},
    ]
    neighbors = sorted((instance.get("neighbors") or {}).values(), key=_seq_key)
    for neighbor in neighbors:
        peer = neighbor.get("peer_address")
        neighbor_id = neighbor["id"]
        group = f"peer-{neighbor_id}"
        base = "set network-instance default protocols bgp"
        # 24.10.7 refuses an ENABLED group or neighbor without an enabled family ("One of the address families must be
        # enabled"): a neighbor that activates no family yet -- the planner's definition Configlet -- is held disabled.
        activated = any(neighbor.get(f"activate_{family.lower()}") for family, _afi in _SRL_AFI)
        state = "disable" if neighbor.get("shutdown") or not activated else "enable"
        lines.append({"kind": "static", "text": f"{base} group {group} admin-state {state}"})
        for family, afi in _SRL_AFI:
            active = "enable" if neighbor.get(f"activate_{family.lower()}") else "disable"
            lines.append({"kind": "static", "text": f"{base} group {group} afi-safi {afi} admin-state {active}"})
        lines.append({"kind": "static", "text": f"{base} neighbor {peer} peer-group {group}"})
        lines.append({"kind": "static", "text": f"{base} neighbor {peer} admin-state {state}"})
        lines.append({
            "kind": "field", "path": f"routing.bgp.{instance_id}.neighbors.{neighbor_id}.remote_asn",
            "template": f"{base} neighbor {peer} peer-as " + "{value}",
            "value": neighbor.get("remote_asn"),
        })
        if neighbor.get("description"):
            lines.append({
                "kind": "field", "path": f"routing.bgp.{instance_id}.neighbors.{neighbor_id}.description",
                "template": f"{base} neighbor {peer} description " + "{value}",
                "value": neighbor.get("description"), "omit_if_empty": True,
            })
        if neighbor.get("update_source_interface_id"):
            source = interfaces_by_id.get(neighbor["update_source_interface_id"], {"name": neighbor["update_source_interface_id"]})
            lines.append({"kind": "static", "text": f"{base} neighbor {peer} transport local-address {_srl_local_address(source, peer)}"})
        if neighbor.get("ebgp_multihop") is not None:
            lines.append({"kind": "static", "text": f"{base} neighbor {peer} multihop admin-state enable"})
            lines.append({
                "kind": "field", "path": f"routing.bgp.{instance_id}.neighbors.{neighbor_id}.ebgp_multihop",
                "template": f"{base} neighbor {peer} multihop maximum-hops " + "{value}",
                "value": neighbor["ebgp_multihop"],
            })
        if neighbor.get("password_ref"):
            lines.append({"kind": "static", "text": f"! neighbor {peer} authentication reference present ({neighbor['password_ref']}); unresolved for deployment"})
    networks = sorted((instance.get("networks") or {}).values(), key=_seq_key)
    if networks:
        policy = srl_bgp_policy_name(instance)
        for network in networks:
            lines.append({
                "kind": "field", "path": f"routing.bgp.{instance_id}.networks.{network['id']}.cidr",
                "template": f"set routing-policy prefix-set {policy} prefix {{value}} mask-length-range exact",
                "value": network.get("cidr") or "", "omit_if_empty": True,
            })
        lines.extend([
            {"kind": "static", "text": f"set routing-policy policy {policy} statement 10 match prefix-set {policy}"},
            {"kind": "static", "text": f"set routing-policy policy {policy} statement 10 action policy-result accept"},
            {"kind": "static", "text": f"set network-instance default protocols bgp export-policy [ {policy} ]"},
        ])
    return lines


def _srl_acl_match(match_type: str, value: str, family: str) -> str:
    if match_type == "ANY":
        return "0.0.0.0/0" if family == "IPV4" else "::/0"
    if match_type == "HOST":
        suffix = "/32" if family == "IPV4" else "/128"
        return f"{value}{suffix}" if value else "<host-required>"
    return value or "<prefix-required>"


# Canonical ACL protocol -> SR Linux ``match ipv4 protocol`` / ``match ipv6 next-header`` value (24.10.7 ``commit validate``).
_SRL_ACL_PROTOCOLS = {"IPV4": {"TCP": "tcp", "UDP": "udp", "ICMP": "icmp"},
                      "IPV6": {"TCP": "tcp", "UDP": "udp", "ICMP": "icmp6", "ICMPV6": "icmp6"}}


def _srl_port_lines(prefix: str, which: str, value) -> list[dict]:
    """``match transport <which>`` for a single port (operator eq) or a ``low-high`` range."""
    text = str(value or "").strip()
    if not text:
        return []
    if "-" in text:
        low, high = text.split("-", 1)
        return [{"kind": "static", "text": f"{prefix} match transport {which} range start {low}"},
                {"kind": "static", "text": f"{prefix} match transport {which} range end {high}"}]
    return [{"kind": "static", "text": f"{prefix} match transport {which} operator eq"},
            {"kind": "static", "text": f"{prefix} match transport {which} value {text}"}]


def _render_srl_acl(acl: dict) -> list[dict]:
    """ACL as an SR Linux 24.10 ``acl-filter`` (keyed by name AND type; ``ipv4-filter`` does not exist on 24.10)."""
    family = acl.get("family") or "IPV4"
    afi = "ipv4" if family == "IPV4" else "ipv6"
    template_name = "srlinux/acl_ipv4.j2" if family == "IPV4" else "srlinux/acl_ipv6.j2"
    acl_name = acl.get("name") or "<acl-name-required>"
    lines = feature_template_renderer.render_descriptors(
        template_name=template_name, fields={}, flags={"name": acl_name}
    )
    for ace in sorted((acl.get("entries") or {}).values(), key=lambda row: (int(row.get("sequence") or 0), row.get("id", ""))):
        seq = int(ace.get("sequence") or 0)
        action = "accept" if str(ace.get("action") or "DENY").upper() == "PERMIT" else "drop"
        prefix = f"set acl acl-filter {acl_name} type {afi} entry {seq}"
        source = _srl_acl_match(ace.get("source_type"), ace.get("source_value"), family)
        lines.append({"kind": "static", "text": f"{prefix} match {afi} source-ip prefix {source}"})
        if acl.get("acl_type") != "STANDARD":
            destination = _srl_acl_match(ace.get("destination_type"), ace.get("destination_value"), family)
            lines.append({"kind": "static", "text": f"{prefix} match {afi} destination-ip prefix {destination}"})
            protocol = str(ace.get("protocol") or "IP").upper()
            if protocol not in ("IP", "IPV6"):
                keyword = _SRL_ACL_PROTOCOLS[family].get(protocol)
                field = "protocol" if family == "IPV4" else "next-header"
                lines.append({"kind": "static", "text": f"{prefix} match {afi} {field} {keyword}" if keyword else (
                    f"{UNSUPPORTED_OBJECT_MARKER} ACL {acl_name} entry {seq} protocol {protocol} has no SR Linux {afi} match")})
            lines.extend(_srl_port_lines(prefix, "source-port", ace.get("source_port")))
            lines.extend(_srl_port_lines(prefix, "destination-port", ace.get("destination_port")))
        lines.append({"kind": "static", "text": f"{prefix} action {action}"})
        if ace.get("logging"):
            lines.append({"kind": "static", "text": f"{prefix} action log true"})
    return lines


def _srl_acl_interface_contributions(interface: dict) -> list[dict]:
    """ACL attachment on SR Linux 24.10: ``acl interface <subif> input|output acl-filter NAME type ipv4|ipv6``."""
    lines: list[dict] = []
    subif = _srl_subinterface_ref(interface)
    for attachment in (interface.get("_scope") or {}).get("acl_attachments", []):
        family = attachment.get("family")
        if family not in ("IPV4", "IPV6") or not _service_policy_supported("nokia_srlinux", f"ACL_ATTACH_{family}"):
            continue
        afi = "ipv4" if family == "IPV4" else "ipv6"
        direction = "input" if str(attachment.get("direction") or "IN").upper() == "IN" else "output"
        lines.append({"kind": "static",
                      "text": f"set acl interface {subif} {direction} acl-filter {attachment.get('acl_name')} type {afi}"})
    return lines


def _srl_dhcp_interface_contributions(interface: dict) -> list[dict]:
    parent_name, index = _srl_interface_context(interface)
    lines: list[dict] = []
    relays = (interface.get("_scope") or {}).get("dhcp_relays", [])
    for family in ("IPV4", "IPV6"):
        servers = sorted({
            relay.get("destination") for relay in relays
            if relay.get("family") == family and relay.get("destination")
        })
        if not servers:
            continue
        if not _service_policy_supported("nokia_srlinux", f"DHCP_RELAY_{family}"):
            continue
        family_kw = "ipv4" if family == "IPV4" else "ipv6"
        relay = f"set interface {parent_name} subinterface {index} {family_kw} dhcp-relay"
        lines.append({"kind": "static", "text": f"{relay} admin-state enable"})
        lines.append({"kind": "static", "text": f"{relay} server [ {' '.join(servers)} ]"})
    return lines


def _phase12_seq(values):
    return sorted(values, key=lambda item: (int(item.get("sequence") or 0), item.get("id", "")))


def _phase12_unsupported(display_name: str, label: str, status: str) -> dict:
    return {"kind": "static", "text": f"{UNSUPPORTED_OBJECT_MARKER} {label} is {status} for {display_name}; intent preserved"}


def _fhrp_feature(instance):
    return f"FHRP_{instance.get('protocol')}_{instance.get('address_family')}"


def fhrp_feature_name(instance: dict) -> str:
    """Public form of the renderer's own FHRP instance -> feature-name rule."""
    return _fhrp_feature(instance)


def _service_policy_supported(platform: str, feature: str) -> bool:
    """The single gate for interface-level service/policy contributions: the same registry lookup the object renderers use."""
    return _service_policy_capability_or_not_implemented(platform, feature).status == CapabilityStatus.SUPPORTED


def _fhrp_interface_contributions(interface: dict, *, platform: str = "arista_ceos") -> list[dict]:
    lines: list[dict] = []
    for instance in (interface.get("_scope") or {}).get("fhrp", []):
        # cEOS VARP is the only FHRP syntax currently backed by repository and
        # live-platform evidence. Other protocols remain structured intent and
        # are reported by the global capability renderer below.
        if instance.get("protocol") != "VARP" or not _service_policy_supported(platform, _fhrp_feature(instance)):
            continue
        path = instance.get("path") or f"fhrp.instances.{instance.get('id')}"
        for vip in _phase12_seq((instance.get("virtual_ips") or {}).values()):
            keyword = "ip virtual-router address" if instance.get("address_family") == "IPV4" else "ipv6 virtual-router address"
            lines.append({
                "kind": "field", "path": f"{path}.virtual_ips.{vip['id']}.address",
                "template": f"   {keyword} {{value}}", "value": vip.get("address") or "", "omit_if_empty": True,
            })
        if instance.get("auth_secret_ref"):
            lines.append({"kind": "static", "text": "   ! FHRP authentication reference present; unresolved and intentionally not rendered"})
    return lines


def _render_fhrp(platform: str, display_name: str, fhrp: dict, interfaces_by_id: dict, *, ceos=False) -> list[dict]:
    instances = _phase12_seq((fhrp.get("instances") or {}).values())
    if not instances:
        return [{"kind": "static", "text": "! FHRP: not configured in current candidate"}]
    lines = []
    for instance in instances:
        capability = _service_policy_capability_or_not_implemented(platform, _fhrp_feature(instance))
        if capability.status != CapabilityStatus.SUPPORTED or not (ceos and instance.get("protocol") == "VARP"):
            lines.append(_phase12_unsupported(display_name, f"{instance.get('protocol')} {instance.get('id')}", capability.status.value))
            lines.append({"kind": "static", "text": "!"})
    return lines


def _acl_interface_contributions(interface: dict, *, platform: str = "arista_ceos") -> list[dict]:
    lines: list[dict] = []
    for attachment in (interface.get("_scope") or {}).get("acl_attachments", []):
        family = attachment.get("family")
        if family not in ("IPV4", "IPV6") or not _service_policy_supported(platform, f"ACL_ATTACH_{family}"):
            continue
        keyword = "ip" if family == "IPV4" else "ipv6"
        lines.append({
            "kind": "static",
            "text": f"   {keyword} access-group {attachment.get('acl_name')} {str(attachment.get('direction') or 'IN').lower()}",
        })
    return lines


def _dhcp_interface_contributions(interface: dict, *, platform: str = "arista_ceos") -> list[dict]:
    lines: list[dict] = []
    for relay in (interface.get("_scope") or {}).get("dhcp_relays", []):
        if not _service_policy_supported(platform, f"DHCP_RELAY_{relay.get('family')}"):
            continue
        keyword = "ip helper-address" if relay.get("family") == "IPV4" else "ipv6 dhcp relay destination"
        lines.append({
            "kind": "static",
            "text": f"   {keyword} {relay.get('destination') or '<destination-required>'}",
        })
    lines.extend(_ceos_option82_interface_lines(interface, platform=platform))
    return lines


def _ceos_option82_interface_lines(interface: dict, *, platform: str) -> list[dict]:
    """V2 Phase 9: per-port option 82 ids of the first enabled IPv4 relay on this interface (Arista EOS only)."""
    from . import dhcp_relay_option82

    if platform not in dhcp_relay_option82.PLATFORMS:
        return []
    for relay in (interface.get("_scope") or {}).get("dhcp_relays", []):
        intent = dhcp_relay_option82.intent_from_relay(relay, str(interface.get("name") or ""))
        if intent is not None and intent.enabled:
            try:
                rendered = dhcp_relay_option82.render_eos(intent)
            except dhcp_relay_option82.Option82Error as exc:
                return [{"kind": "static", "text": f"   ! DHCP relay option 82 not rendered: {exc.code}"}]
            return [{"kind": "static", "text": line} for line in rendered[2:] if not line.strip().startswith("no ")]
    return []


def _option82_global_lines(platform: str, display_name: str, relays: list[dict]) -> list[dict]:
    """The global ``ip dhcp relay information option`` when any IPv4 relay enables option 82; refusal text elsewhere."""
    from . import dhcp_relay_option82

    wanted = [r for r in relays if isinstance(r.get("option82"), dict) and r["option82"].get("enabled") is True]
    if not wanted:
        return []
    if platform not in dhcp_relay_option82.PLATFORMS:
        return [_phase12_unsupported(display_name, "DHCP relay option 82", CapabilityStatus.NOT_IMPLEMENTED.value)]
    return [{"kind": "static", "text": dhcp_relay_option82.GLOBAL_LINE}]


NAT_STATEFUL_COMMENT = "nmas-nat44-stateful"


def _render_nat(platform: str, display_name: str, nat: dict, interfaces_by_id: dict, *, ubuntu=False) -> list[dict]:
    pools = _phase12_seq((nat.get("pools") or {}).values())
    rules = _phase12_seq((nat.get("rules") or {}).values())
    if not pools and not rules:
        return [{"kind": "static", "text": "! NAT: not configured in current candidate"}]
    lines = []
    for pool in pools:
        feature = f"NAT_POOL_{pool.get('family')}"
        cap = _service_policy_capability_or_not_implemented(platform, feature)
        lines.append(_phase12_unsupported(display_name, f"NAT pool {pool.get('name') or pool.get('id')}", cap.status.value))
    # the capability registry is the gate (as for every other feature); the Ubuntu nftables renderer is the only implementation
    supported_pat = [r for r in rules if ubuntu and r.get("family") == "NAT44" and r.get("mode") in ("PAT", "STATEFUL")
                     and _service_policy_capability_or_not_implemented(platform, f"NAT_NAT44_{r.get('mode')}").status == CapabilityStatus.SUPPORTED]
    if supported_pat:
        lines.extend(feature_template_renderer.render_descriptors(
            template_name="ubuntu_frr/nat_pat.j2", fields={}, flags={}
        ))
        for rule in supported_pat:
            outside = interfaces_by_id.get(rule.get("outside_interface_id") or "", {})
            source = rule.get("original_source") or "<source-prefix-required>"
            out_name = outside.get("name") or rule.get("outside_interface_id") or "<outside-interface-required>"
            # nftables masquerade is conntrack-based for both modes; the NMAS-owned rule comment (kept by the kernel and
            # printed by ``nft list ruleset``) records which intent mode the rule realises, so import can tell them apart.
            marker = f' comment "{NAT_STATEFUL_COMMENT}"' if rule.get("mode") == "STATEFUL" else ""
            lines.append({"kind": "static", "text": f'        oifname "{out_name}" ip saddr {source} masquerade{marker}'})
        lines.extend((
            {"kind": "static", "text": "    }"},
            {"kind": "static", "text": "}"},
        ))
    for rule in rules:
        if rule in supported_pat:
            continue
        feature = f"NAT_{rule.get('family')}_{rule.get('mode')}"
        cap = _service_policy_capability_or_not_implemented(platform, feature)
        label = f"{rule.get('family')} {rule.get('mode')} rule {rule.get('id')}"
        if rule.get("family") == "NAT_PT":
            label += " (DEPRECATED)"
        lines.append(_phase12_unsupported(display_name, label, cap.status.value))
    return lines


def _acl_match(match_type: str, value: str) -> str:
    if match_type == "ANY":
        return "any"
    if match_type == "HOST":
        return f"host {value or '<host-required>'}"
    return value or "<prefix-required>"


def _port_clause(value: str) -> str:
    if not value:
        return ""
    if "-" in str(value):
        start, end = str(value).split("-", 1)
        return f" range {start} {end}"
    return f" eq {value}"


# EOS spells "any protocol" and ICMP per family (cEOS 4.36.2F): ``ip`` / ``icmp`` in an IPv4 list, ``ipv6`` / ``icmpv6`` in an
# IPv6 list.  The intent vocabulary carries both spellings, so either maps to the one the list's family takes.
_CEOS_ACL_PROTOCOL = {"IPV4": {"IP": "ip", "IPV6": "ip", "ICMP": "icmp", "ICMPV6": "icmp"},
                      "IPV6": {"IP": "ipv6", "IPV6": "ipv6", "ICMP": "icmpv6", "ICMPV6": "icmpv6"}}


def ceos_acl_protocol(family: str, protocol) -> str:
    """The EOS protocol keyword of an intent ACL entry in a list of ``family`` (TCP / UDP unchanged, lower case)."""
    text = str(protocol or "IP").upper()
    return _CEOS_ACL_PROTOCOL.get(family, _CEOS_ACL_PROTOCOL["IPV4"]).get(text, text.lower())


def _render_ceos_acl(acl: dict) -> list[dict]:
    family = "IPV6" if acl.get("family") == "IPV6" else "IPV4"
    keyword = "ip" if family == "IPV4" else "ipv6"
    lines = feature_template_renderer.render_descriptors(
        template_name=f"ceos/acl_{family.lower()}.j2", fields={}, flags={"name": acl.get("name") or "<acl-name-required>"}
    )
    if acl.get("acl_type") == "STANDARD":
        # EOS only accepts source-only entries inside a ``standard`` list (verified on cEOS 4.36.2F, both families).
        lines = [{**row, "text": row["text"].replace(f"{keyword} access-list ", f"{keyword} access-list standard ", 1)}
                 if str(row.get("text", "")).startswith(f"{keyword} access-list ") else row for row in lines]
    for ace in sorted((acl.get("entries") or {}).values(), key=lambda row: (int(row.get("sequence") or 0), row.get("id", ""))):
        if family == "IPV6" and ace.get("logging"):
            # EOS accepts ``log`` here but warns "ipv6 logging not supported" and ignores it: never claim it was configured.
            lines.append(_phase12_unsupported("Arista cEOS", f"logging on IPv6 ACL {acl.get('name')} entry {ace.get('sequence')}",
                                              CapabilityStatus.UNSUPPORTED.value))
            continue
        action = str(ace.get("action") or "DENY").lower()
        protocol = ceos_acl_protocol(family, ace.get("protocol"))
        source = _acl_match(ace.get("source_type"), ace.get("source_value"))
        destination = _acl_match(ace.get("destination_type"), ace.get("destination_value"))
        if acl.get("acl_type") == "STANDARD":
            command = f"   {int(ace.get('sequence') or 0)} {action} {source}"
        else:
            command = f"   {int(ace.get('sequence') or 0)} {action} {protocol} {source}{_port_clause(ace.get('source_port'))} {destination}{_port_clause(ace.get('destination_port'))}"
        if ace.get("logging"):
            command += " log"
        lines.append({"kind": "static", "text": command})
    return lines


def _render_security(platform: str, display_name: str, security: dict, interfaces_by_id: dict, *, acl_renderer=None) -> list[dict]:
    acls = _phase12_seq((security.get("acls") or {}).values())
    attachments = _phase12_seq((security.get("attachments") or {}).values())
    if not acls and not attachments:
        return [{"kind": "static", "text": "! Security/ACL: not configured in current candidate"}]
    lines = []
    by_id = {acl.get("id"): acl for acl in acls}
    for acl in acls:
        feature = f"ACL_{acl.get('family')}_{acl.get('acl_type')}"
        cap = _service_policy_capability_or_not_implemented(platform, feature)
        if acl_renderer is not None and cap.status == CapabilityStatus.SUPPORTED:
            lines.extend(acl_renderer(acl))
        else:
            lines.append(_phase12_unsupported(display_name, f"ACL {acl.get('name') or acl.get('id')}", cap.status.value))
        lines.append({"kind": "static", "text": "!"})
    for attachment in attachments:
        acl = by_id.get(attachment.get("acl_id"), {})
        cap = _service_policy_capability_or_not_implemented(platform, f"ACL_ATTACH_{acl.get('family', 'IPV4')}")
        # Supported attachments were already composed into their interface
        # scope.  This renderer owns only definitions and unsupported markers.
        if not (acl_renderer is not None and cap.status == CapabilityStatus.SUPPORTED):
            lines.append(_phase12_unsupported(display_name, f"ACL attachment {attachment.get('id')}", cap.status.value))
    lines.append({"kind": "static", "text": "! Traffic-impact validation has not run; project validation pending."})
    return lines


def _render_ios_dhcp_relays(relays: list[dict], interfaces_by_id: dict) -> list[dict]:
    lines: list[dict] = []
    by_family = {
        family: [relay for relay in relays if relay.get("family") == family]
        for family in ("IPV4", "IPV6")
    }
    for family, family_relays in by_family.items():
        if not family_relays:
            continue
        keyword = "ipv4" if family == "IPV4" else "ipv6"
        lines.append({"kind": "static", "text": f"dhcp {keyword}"})
        for relay in family_relays:
            relay_id = relay.get("id") or "relay"
            profile = f"nmas-{relay_id}"
            interface = interfaces_by_id.get(relay.get("interface_id") or "", {})
            interface_name = interface.get("name") or "<interface-required>"
            destination = relay.get("destination") or "<destination-required>"
            lines.extend((
                {"kind": "static", "text": f" profile {profile} relay"},
                {"kind": "static", "text": f"  helper-address vrf default {destination}"},
                {"kind": "static", "text": " !"},
                {"kind": "static", "text": f" interface {interface_name} relay profile {profile}"},
            ))
        lines.append({"kind": "static", "text": "!"})
    return lines


def _render_services(
    platform: str, display_name: str, services: dict, interfaces_by_id: dict, *,
    ceos=False, iosxr=False, srlinux=False
) -> list[dict]:
    dhcp = services.get("dhcp") or {"mode": "INHERIT"}
    dns = services.get("dns") or {"mode": "INHERIT"}
    monitoring = services.get("monitoring") or {"mode": "INHERIT"}
    lines = []
    if dhcp.get("mode", "INHERIT") == "INHERIT":
        lines.append({"kind": "static", "text": "! DHCP/DHCPv6: INHERIT project defaults (NMAS primary / R2 secondary)"})
    else:
        relays = _phase12_seq((dhcp.get("relays") or {}).values())
        lines.extend(_option82_global_lines(platform, display_name, relays))
        if iosxr:
            lines.extend(_render_ios_dhcp_relays(relays, interfaces_by_id))
        for relay in relays:
            cap = _service_policy_capability_or_not_implemented(platform, f"DHCP_RELAY_{relay.get('family')}")
            # Supported relay commands were already composed into their
            # interface scope.
            if not ((ceos or iosxr or srlinux) and cap.status == CapabilityStatus.SUPPORTED):
                lines.append(_phase12_unsupported(display_name, f"DHCP relay {relay.get('id')}", cap.status.value))
        for client in _phase12_seq((dhcp.get("clients") or {}).values()):
            cap = _service_policy_capability_or_not_implemented(platform, f"DHCP_CLIENT_{client.get('family')}")
            lines.append(_phase12_unsupported(display_name, f"DHCP client {client.get('id')}", cap.status.value))
        if dhcp.get("local_server_override"):
            lines.append(_phase12_unsupported(display_name, "local DHCP server override", CapabilityStatus.NOT_IMPLEMENTED.value))
    if dns.get("mode", "INHERIT") == "INHERIT":
        lines.append({"kind": "static", "text": "! DNS: INHERIT project / host defaults"})
    else:
        lines.append(_phase12_unsupported(display_name, "DNS resolver override", _service_policy_capability_or_not_implemented(platform, "DNS_OVERRIDE").status.value))
    lines.append({"kind": "static", "text": f"! Monitoring: {monitoring.get('mode', 'INHERIT')} project defaults"})
    return lines


def _render_policy(platform: str, display_name: str, policy: dict) -> list[dict]:
    pbr = (policy.get("pbr") or {})
    policies = _phase12_seq((pbr.get("policies") or {}).values())
    attachments = _phase12_seq((pbr.get("attachments") or {}).values())
    if not policies and not attachments:
        return [{"kind": "static", "text": "! Policy/PBR: not configured in current candidate"}]
    lines = []
    for obj in policies:
        cap = _service_policy_capability_or_not_implemented(platform, f"PBR_{obj.get('family')}")
        lines.append(_phase12_unsupported(display_name, f"PBR policy {obj.get('name') or obj.get('id')}", cap.status.value))
    for obj in attachments:
        lines.append(_phase12_unsupported(display_name, f"PBR attachment {obj.get('id')}", CapabilityStatus.NOT_IMPLEMENTED.value))
    lines.append({"kind": "static", "text": "! PBR next-hop reachability and loop-risk validation are Phase 13 concerns."})
    return lines


def _render_phase12(
    platform: str, display_name: str, phase12: dict, interfaces: list[dict], *,
    ceos=False, ubuntu=False, iosxr=False, srlinux=False, acl_renderer=None
):
    phase12 = phase12 or {}
    interfaces_by_id = {item.get("id"): item for item in interfaces or []}
    lines = []
    lines.extend(_render_fhrp(platform, display_name, phase12.get("fhrp") or {}, interfaces_by_id, ceos=ceos))
    lines.extend(_render_nat(platform, display_name, phase12.get("nat") or {}, interfaces_by_id, ubuntu=ubuntu))
    lines.extend(_render_services(
        platform, display_name, phase12.get("services") or {}, interfaces_by_id,
        ceos=ceos, iosxr=iosxr, srlinux=srlinux,
    ))
    lines.extend(_render_security(platform, display_name, phase12.get("security") or {}, interfaces_by_id, acl_renderer=acl_renderer or (_render_ceos_acl if ceos else None)))
    lines.extend(_render_policy(platform, display_name, phase12.get("policy") or {}))
    return lines


# --- Cisco Catalyst 8000V / IOS XE -------------------------------------------------------------------------------

def _iosxe_network_and_mask(prefix: str) -> tuple[str, str]:
    try:
        network = ipaddress.ip_network(prefix, strict=False)
    except ValueError:
        return "<invalid-prefix>", "<invalid-mask>"
    if network.version != 4:
        return str(network), ""
    return str(network.network_address), str(network.netmask)


def _iosxe_static_route_descriptors(route: dict, interfaces_by_id: dict) -> list[dict]:
    if not route.get("enabled", True):
        return [{"kind": "static", "text": f"! static route {route.get('destination') or route.get('id')} disabled in intent; not rendered"}]
    destination = route.get("destination") or ""
    next_hop = _route_next_hop_display(route, interfaces_by_id)
    suffix = f" {route['distance']}" if route.get("distance") is not None else ""
    if route.get("tag") is not None:
        suffix += f" tag {route['tag']}"
    if route.get("family") == "IPV6":
        text = f"ipv6 route {destination} {next_hop}{suffix}"
    else:
        network, mask = _iosxe_network_and_mask(destination)
        text = f"ip route {network} {mask} {next_hop}{suffix}"
    return [{"kind": "field", "path": f"routing.static_routes.{route['id']}.destination", "template": text,
             "value": destination, "omit_if_empty": True}]


def _iosxe_rip_descriptors(instance: dict, interfaces_by_id: dict) -> list[dict]:
    if not instance.get("enabled", True):
        return [{"kind": "static", "text": f"{UNSUPPORTED_OBJECT_MARKER} a disabled RIP instance has no verified IOS XE form"}]
    lines = [{"kind": "static", "text": "router rip"}, {"kind": "static", "text": " version 2"}]
    for binding in sorted((instance.get("interfaces") or {}).values(), key=_seq_key):
        interface = interfaces_by_id.get(binding.get("interface_id") or "", {})
        lines.append({"kind": "static", "text": f" network {_connected_network_display(interface)}"})
        if binding.get("passive"):
            lines.append({"kind": "static", "text": f" passive-interface {interface.get('name') or binding.get('interface_id')}"})
    return lines


def _iosxe_ospf_descriptors(instance: dict, interfaces_by_id: dict) -> list[dict]:
    lines = _ospf_descriptors(
        instance, interfaces_by_id, v2_template="iosxe/routing_ospfv2.j2", v3_template="iosxe/routing_ospfv3.j2",
    )
    # Replace the shared CIDR form with IOS XE's network/wildcard form.
    lines = [line for line in lines if not (line.get("path", "").endswith(".prefix") and " network " in line.get("template", ""))]
    for network in sorted((instance.get("networks") or {}).values(), key=_seq_key):
        prefix = network.get("prefix") or ""
        try:
            parsed = ipaddress.ip_network(prefix, strict=False)
            address, wildcard = parsed.network_address, parsed.hostmask
            value = f"{address} {wildcard}"
        except ValueError:
            value = "<invalid-network> <invalid-wildcard>"
        lines.append({
            "kind": "field", "path": f"routing.ospf.{instance['id']}.networks.{network['id']}.prefix",
            "template": " network {value} area " + str(network.get("area") or "0.0.0.0"),
            "value": value, "omit_if_empty": True,
        })
    return lines


def _iosxe_ospf_interface_contributions(interface: dict) -> list[dict]:
    lines: list[dict] = []
    for binding in (interface.get("_scope") or {}).get("ospf", []):
        if binding.get("version") == "OSPFV3":
            continue
        process = binding.get("process_id") or "<process-id-required>"
        path = binding.get("path") or "routing.ospf"
        lines.append({"kind": "field", "path": f"{path}.area", "template": f" ip ospf {process} area {{value}}",
                      "value": binding.get("area") or "", "omit_if_empty": True})
        if binding.get("cost") is not None:
            lines.append({"kind": "field", "path": f"{path}.cost", "template": " ip ospf cost {value}", "value": binding["cost"]})
        if binding.get("network_type") == "POINT_TO_POINT":
            lines.append({"kind": "static", "text": " ip ospf network point-to-point"})
    return lines


def _iosxe_bgp_descriptors(instance: dict, interfaces_by_id: dict) -> list[dict]:
    return _bgp_instance_descriptors(
        instance, interfaces_by_id, template_name="iosxe/routing_bgp.j2", af_suffix=" unicast", close_af=True,
    )


# --- Cisco IOS XR (Phase 20.5): verified against Cisco's published IOS XR Interfaces / IP
# Addresses and Services / Implementing OSPF / Implementing BGP / Access Lists configuration
# guides. This driver represents IOS XR, never Catalyst 8000V / IOS XE.
# No deployed node exists in this lab -- fixture-tested, not live-tested.

def _cidr_to_address_mask(cidr: str) -> str:
    """IOS XR's `ipv4 address` leaf takes a dotted-decimal mask, unlike every
    other platform this project renders (which take CIDR prefix length)."""
    try:
        interface = ipaddress.ip_interface(cidr)
    except ValueError:
        return "<invalid-address>"
    if interface.version != 4:
        return "<invalid-address>"
    return f"{interface.ip} {interface.network.netmask}"


def _iosxr_static_route_descriptors(route: dict, interfaces_by_id: dict) -> list[dict]:
    if not route.get("enabled", True):
        return [{"kind": "static", "text": f"! static route {route.get('destination') or route.get('id')} disabled in intent; not rendered"}]
    af = "ipv6" if route.get("family") == "IPV6" else "ipv4"
    next_hop = _route_next_hop_display(route, interfaces_by_id)
    suffix = ""
    if route.get("distance") is not None:
        suffix += f" {route['distance']}"
    if route.get("tag") is not None:
        suffix += f" tag {route['tag']}"
    return feature_template_renderer.render_descriptors(
        template_name="iosxr/routing_static_route.j2",
        fields={"destination": {
            "path": f"routing.static_routes.{route['id']}.destination",
            "value": route.get("destination") or "", "omit_if_empty": True,
        }},
        flags={"af": af, "next_hop": next_hop, "suffix": suffix},
    )


def _iosxr_rip_descriptors(instance: dict, interfaces_by_id: dict) -> list[dict]:
    """Cisco 8000 IOS XR default-VRF RIPv2 hierarchy.

    IOS XR owns interface activation under ``router rip``; unlike classic IOS
    there is no network statement in the canonical subset rendered here.
    """
    if not instance.get("enabled", True):
        return [{"kind": "static", "text": f"{UNSUPPORTED_OBJECT_MARKER} a disabled RIP instance has no verified IOS XR form"}]
    lines = [{"kind": "static", "text": "router rip"}]
    for binding in sorted((instance.get("interfaces") or {}).values(), key=_seq_key):
        interface = interfaces_by_id.get(binding.get("interface_id") or "", {})
        name = interface.get("name") or "<interface-required>"
        lines.append({"kind": "static", "text": f" interface {name}"})
        if binding.get("passive"):
            lines.append({"kind": "static", "text": "  passive-interface"})
    return lines


def _iosxr_ospf_descriptors(instance: dict, interfaces_by_id: dict) -> list[dict]:
    return _ospf_descriptors(
        instance, interfaces_by_id,
        v2_template="iosxr/routing_ospfv2.j2", v3_template="iosxr/routing_ospfv3.j2",
    )


def _iosxr_ospf_interface_contributions(interface: dict) -> list[dict]:
    """IOS XR assigns an interface to an OSPF area under `router ospf`, not
    under the interface stanza -- rendered as its own small nested block,
    the same architectural tradeoff already used for FRR OSPF (see
    UbuntuFrrDriver.interface_contribution_descriptors) and SR Linix above."""
    lines: list[dict] = []
    name = interface.get("name") or "<interface-name-required>"
    for binding in (interface.get("_scope") or {}).get("ospf", []):
        is_v3 = binding.get("version") == "OSPFV3"
        keyword = "router ospfv3" if is_v3 else "router ospf"
        process = binding.get("process_id")
        process_display = str(process) if process not in (None, "") else "<process-id-required>"
        path = binding.get("path") or "routing.ospf"
        area = binding.get("area")
        block = [{"kind": "static", "text": "!"}, {"kind": "static", "text": f"{keyword} {process_display}"}]
        if area:
            block.append({
                "kind": "field", "path": f"{path}.area",
                "template": " area {value}", "value": area,
            })
            block.append({"kind": "static", "text": f"  interface {name}"})
            if binding.get("cost") is not None:
                block.append({
                    "kind": "field", "path": f"{path}.cost",
                    "template": "   cost {value}", "value": binding["cost"],
                })
            if binding.get("network_type") == "POINT_TO_POINT":
                block.append({"kind": "static", "text": "   network point-to-point"})
            lines.extend(block)
    return lines


def _iosxr_bgp_descriptors(instance: dict, interfaces_by_id: dict) -> list[dict]:
    """IOS XR enables no address family by default: both the global process
    and each neighbor must explicitly activate `address-family ipv4|ipv6
    unicast` (unlike classic IOS, which enables ipv4 unicast implicitly)."""
    instance_id = instance["id"]
    lines = [
        {"kind": "static", "text": f"router bgp {instance.get('local_asn')}"},
        {
            "kind": "field", "path": f"routing.bgp.{instance_id}.router_id",
            "template": " bgp router-id {value}", "value": instance.get("router_id") or "", "omit_if_empty": True,
        },
    ]
    neighbors = sorted((instance.get("neighbors") or {}).values(), key=_seq_key)
    for family, activate_key in (("ipv4", "activate_ipv4"), ("ipv6", "activate_ipv6")):
        active_neighbors = [n for n in neighbors if n.get(activate_key)]
        active_networks = sorted(
            (n for n in (instance.get("networks") or {}).values() if n.get("family") == family.upper()), key=_seq_key,
        )
        if not active_neighbors and not active_networks:
            continue
        lines.append({"kind": "static", "text": f" address-family {family} unicast"})
        for network in active_networks:
            lines.append({
                "kind": "field", "path": f"routing.bgp.{instance_id}.networks.{network['id']}.cidr",
                "template": "  network {value}", "value": network.get("cidr") or "", "omit_if_empty": True,
            })
    for neighbor in neighbors:
        peer = neighbor.get("peer_address")
        neighbor_id = neighbor["id"]
        lines.append({"kind": "static", "text": f" neighbor {peer}"})
        lines.append({
            "kind": "field", "path": f"routing.bgp.{instance_id}.neighbors.{neighbor_id}.remote_asn",
            "template": "  remote-as {value}", "value": neighbor.get("remote_asn"),
        })
        if neighbor.get("description"):
            lines.append({
                "kind": "field", "path": f"routing.bgp.{instance_id}.neighbors.{neighbor_id}.description",
                "template": "  description {value}", "value": neighbor.get("description"), "omit_if_empty": True,
            })
        if neighbor.get("update_source_interface_id"):
            source = interfaces_by_id.get(neighbor["update_source_interface_id"], {})
            lines.append({"kind": "static", "text": f"  update-source {source.get('name') or neighbor['update_source_interface_id']}"})
        if neighbor.get("ebgp_multihop") is not None:
            lines.append({
                "kind": "field", "path": f"routing.bgp.{instance_id}.neighbors.{neighbor_id}.ebgp_multihop",
                "template": "  ebgp-multihop {value}", "value": neighbor["ebgp_multihop"],
            })
        if neighbor.get("password_ref"):
            lines.append({"kind": "static", "text": f"  ! neighbor {peer} authentication reference present ({neighbor['password_ref']}); unresolved for deployment"})
        if neighbor.get("shutdown"):
            lines.append({"kind": "static", "text": "  shutdown"})
        for family, activate_key in (("ipv4", "activate_ipv4"), ("ipv6", "activate_ipv6")):
            if neighbor.get(activate_key):
                lines.append({"kind": "static", "text": f"  address-family {family} unicast"})
    return lines


def _iosxr_acl_match(match_type: str, value: str, family: str) -> str:
    if match_type == "ANY":
        return "any"
    if match_type == "HOST":
        suffix = "/32" if family == "IPV4" else "/128"
        return f"{value}{suffix}" if value else "<host-required>"
    return value or "<prefix-required>"


def _render_iosxr_acl(acl: dict) -> list[dict]:
    family = acl.get("family") or "IPV4"
    template_name = "iosxr/acl_ipv4.j2" if family == "IPV4" else "iosxr/acl_ipv6.j2"
    af_keyword = "ipv4" if family == "IPV4" else "ipv6"
    acl_name = acl.get("name") or "<acl-name-required>"
    lines = feature_template_renderer.render_descriptors(
        template_name=template_name, fields={}, flags={"name": acl_name}
    )
    for ace in sorted((acl.get("entries") or {}).values(), key=lambda row: (int(row.get("sequence") or 0), row.get("id", ""))):
        seq = int(ace.get("sequence") or 0)
        action = "permit" if str(ace.get("action") or "DENY").upper() == "PERMIT" else "deny"
        source = _iosxr_acl_match(ace.get("source_type"), ace.get("source_value"), family)
        if acl.get("acl_type") == "STANDARD":
            command = f" {seq} {action} {source}"
        else:
            protocol = str(ace.get("protocol") or af_keyword).lower()
            destination = _iosxr_acl_match(ace.get("destination_type"), ace.get("destination_value"), family)
            command = f" {seq} {action} {protocol} {source} {destination}"
        lines.append({"kind": "static", "text": command})
        if ace.get("source_port") or ace.get("destination_port") or ace.get("logging"):
            lines.append({"kind": "static", "text": f"! entry {seq}: port-range and log-action match are not rendered pending exact IOS XR syntax verification"})
    return lines


def _iosxr_acl_interface_contributions(interface: dict) -> list[dict]:
    lines: list[dict] = []
    name = interface.get("name") or "<interface-name-required>"
    for attachment in (interface.get("_scope") or {}).get("acl_attachments", []):
        family = attachment.get("family") or "IPV4"
        af_keyword = "ipv4" if family == "IPV4" else "ipv6"
        direction = "in" if str(attachment.get("direction") or "IN").upper() == "IN" else "out"
        lines.append({"kind": "static", "text": "!"})
        lines.append({"kind": "static", "text": f"interface {name}"})
        lines.append({"kind": "static", "text": f" {af_keyword} access-group {attachment.get('acl_name')} {direction}"})
    return lines


# --- SONiC (Phase 20.5): SONiC's authoritative configuration representation is config_db (a
# Redis-backed table/key/field store applied via `config load <file>.json` / `config reload`),
# not a `show running-config`-style CLI -- see the `_SONIC_*` evidence strings above and
# sonic-net/SONiC's own HLDs. Rather than force a CLI-line renderer onto a JSON document store,
# this driver builds one coherent config_db JSON fragment directly from the composed candidate.
# Preserved-but-unsupported intent still uses the same UNSUPPORTED_OBJECT_MARKER convention
# (as standalone lines outside the JSON, since JSON has no comment syntax) so that
# validation/capabilities.py and planning/snippets.py, which key off that marker, keep working
# unchanged; this candidate is therefore not asserted to be directly loadable as-is when
# unsupported objects are present, exactly like every other platform's "Tier-1 syntax
# acceptance only" candidate. No deployed node exists in this lab (fixture-tested only).

def _sonic_subif_name(interface: dict, interfaces_by_id: dict) -> str:
    if interface.get("kind") == "SUBINTERFACE":
        parent = interfaces_by_id.get(interface.get("parent_id") or "", {})
        vlan = interface.get("encapsulation_vlan")
        return f"{parent.get('name') or '<parent-required>'}.{vlan or '<vlan-required>'}"
    return interface.get("name") or "<interface-name-required>"


def _sonic_interface_table(kind: str) -> str | None:
    return {
        "ROUTED_PHYSICAL": "INTERFACE", "SUBINTERFACE": "INTERFACE",
        "LOOPBACK": "LOOPBACK_INTERFACE", "MANAGEMENT": "MGMT_INTERFACE",
        "SVI": "VLAN_INTERFACE",
    }.get(kind)


def _sonic_acl_match(match_type: str, value: str, family: str) -> str | None:
    if match_type == "ANY":
        return None  # SONiC ACL_RULE omits SRC_IP/DST_IP entirely to mean "any"
    if match_type == "HOST":
        suffix = "/32" if family == "IPV4" else "/128"
        return f"{value}{suffix}" if value else "<host-required>"
    return value or "<prefix-required>"


def _sonic_build_config_db(candidate: dict, unsupported_lines: list[str]) -> dict:
    field_values = candidate["field_values"] or {}
    interfaces = candidate["interfaces"] or []
    routing = candidate["routing"] or {}
    phase12 = candidate["phase12"] or {}
    interfaces_by_id = {item.get("id"): item for item in interfaces}

    doc: dict = {}
    hostname = field_values.get("device.hostname") or ""
    if hostname:
        doc["DEVICE_METADATA"] = {"localhost": {"hostname": hostname}}

    for interface in interfaces:
        capability = capability_for("sonic", interface.get("kind", ""))
        if capability.status != CapabilityStatus.SUPPORTED:
            unsupported_lines.append(
                f"{UNSUPPORTED_OBJECT_MARKER} {interface.get('name') or interface.get('id')} / "
                f"{interface.get('kind')} is {capability.status.value} for SONiC; intent preserved"
            )
            continue
        kind = interface["kind"]
        if kind in {"ACCESS", "TRUNK"}:
            port_name = interface.get("name") or "<interface-name-required>"
            memberships: list[tuple[int, str]] = []
            if kind == "ACCESS":
                vlan = interface.get("access_vlan")
                if vlan not in (None, ""):
                    memberships.append((int(vlan), "untagged"))
            else:
                allowed = {int(vlan) for vlan in (interface.get("trunk_allowed_vlans") or [])}
                native = interface.get("native_vlan")
                if native not in (None, ""):
                    allowed.add(int(native))
                memberships.extend(
                    (vlan, "untagged" if native not in (None, "") and vlan == int(native) else "tagged")
                    for vlan in sorted(allowed)
                )
            for vlan, tagging_mode in memberships:
                vlan_name = f"Vlan{vlan}"
                doc.setdefault("VLAN", {}).setdefault(vlan_name, {"vlanid": str(vlan)})
                doc.setdefault("VLAN_MEMBER", {})[f"{vlan_name}|{port_name}"] = {"tagging_mode": tagging_mode}
            continue
        table = _sonic_interface_table(kind)
        name = _sonic_subif_name(interface, interfaces_by_id)
        if kind == "SVI":
            vlan = interface.get("vlan_id")
            if vlan not in (None, ""):
                name = f"Vlan{int(vlan)}"
                doc.setdefault("VLAN", {}).setdefault(name, {"vlanid": str(int(vlan))})
        entry = doc.setdefault(table, {})
        entry.setdefault(name, {})
        for address in sorted((interface.get("addresses") or {}).values(), key=_seq_key):
            if address.get("source") == "AUTO" or not address.get("cidr"):
                continue
            entry[f"{name}|{address['cidr']}"] = {}

    static_routes = sorted((routing.get("static_routes") or {}).values(), key=_seq_key)
    for route in static_routes:
        if not route.get("enabled", True) or not route.get("destination"):
            continue
        if route.get("next_hop_type") == "INTERFACE":
            unsupported_lines.append(
                f"{UNSUPPORTED_OBJECT_MARKER} static route {route.get('destination')} (interface next-hop) is "
                "NOT_IMPLEMENTED for SONiC in this project's config_db model (STATIC_ROUTE next-hop "
                "requires an IP address here); intent preserved"
            )
            continue
        entry = {"nexthop": route.get("next_hop_address") or "<next-hop-required>"}
        if route.get("distance") is not None:
            entry["distance"] = str(route["distance"])
        doc.setdefault("STATIC_ROUTE", {})[f"default|{route['destination']}"] = entry

    for instance in sorted((routing.get("bgp") or {}).values(), key=_seq_key):
        asn = instance.get("local_asn")
        globals_entry = {"local_asn": str(asn) if asn is not None else "<asn-required>"}
        if instance.get("router_id"):
            globals_entry["router_id"] = instance["router_id"]
        doc.setdefault("BGP_GLOBALS", {})["default"] = globals_entry
        for neighbor in sorted((instance.get("neighbors") or {}).values(), key=_seq_key):
            peer = neighbor.get("peer_address") or "<peer-required>"
            doc.setdefault("BGP_NEIGHBOR", {})[f"default|{peer}"] = {
                "asn": str(neighbor.get("remote_asn")) if neighbor.get("remote_asn") is not None else "<remote-asn-required>",
                **({"name": neighbor["description"]} if neighbor.get("description") else {}),
            }
            for family, activate_key in (("ipv4_unicast", "activate_ipv4"), ("ipv6_unicast", "activate_ipv6")):
                if neighbor.get(activate_key):
                    doc.setdefault("BGP_NEIGHBOR_AF", {})[f"default|{peer}|{family}"] = {"admin_status": "true"}
        if any((instance.get("networks") or {}).values()):
            unsupported_lines.append(
                f"{UNSUPPORTED_OBJECT_MARKER} BGP network advertisement for AS{asn} is NOT_IMPLEMENTED for SONiC "
                "in this project's config_db model (redistribution needs a route-map/ROUTE_REDISTRIBUTE entry "
                "this project does not model); intent preserved"
            )

    acls = sorted((phase12.get("security") or {}).get("acls", {}).values(), key=_seq_key)
    attachments = sorted((phase12.get("security") or {}).get("attachments", {}).values(), key=_seq_key)
    by_acl_id = {acl["id"]: acl for acl in acls}
    ports_by_acl: dict[str, list[str]] = {}
    stage_by_acl: dict[str, str] = {}
    for attachment in attachments:
        acl = by_acl_id.get(attachment.get("acl_id"))
        if not acl:
            continue
        interface = interfaces_by_id.get(attachment.get("interface_id"), {})
        port_name = _sonic_subif_name(interface, interfaces_by_id) if interface else attachment.get("interface_id")
        ports_by_acl.setdefault(acl["id"], []).append(port_name)
        stage_by_acl.setdefault(acl["id"], "egress" if str(attachment.get("direction") or "IN").upper() == "OUT" else "ingress")

    for acl in acls:
        feature = f"ACL_{acl.get('family')}_{acl.get('acl_type')}"
        capability = _service_policy_capability_or_not_implemented("sonic", feature)
        if capability.status != CapabilityStatus.SUPPORTED:
            unsupported_lines.append(
                f"{UNSUPPORTED_OBJECT_MARKER} ACL {acl.get('name') or acl.get('id')} is {capability.status.value} for SONiC; intent preserved"
            )
            continue
        family = acl.get("family") or "IPV4"
        name = acl.get("name") or "<acl-name-required>"
        doc.setdefault("ACL_TABLE", {})[name] = {
            "type": "L3" if family == "IPV4" else "L3V6",
            "policy_desc": name,
            "ports": ports_by_acl.get(acl["id"], []),
            "stage": stage_by_acl.get(acl["id"], "ingress"),
        }
        for ace in sorted((acl.get("entries") or {}).values(), key=_seq_key):
            seq = int(ace.get("sequence") or 0)
            rule_entry = {
                "PRIORITY": str(seq),
                "PACKET_ACTION": "FORWARD" if str(ace.get("action") or "DENY").upper() == "PERMIT" else "DROP",
            }
            source = _sonic_acl_match(ace.get("source_type"), ace.get("source_value"), family)
            if source:
                rule_entry["SRC_IP" if family == "IPV4" else "SRC_IPV6"] = source
            if acl.get("acl_type") != "STANDARD":
                destination = _sonic_acl_match(ace.get("destination_type"), ace.get("destination_value"), family)
                if destination:
                    rule_entry["DST_IP" if family == "IPV4" else "DST_IPV6"] = destination
                protocol = str(ace.get("protocol") or "").upper()
                if protocol and protocol != "IP":
                    rule_entry["IP_PROTOCOL"] = protocol
            doc.setdefault("ACL_RULE", {})[f"{name}|RULE_{seq}"] = rule_entry

    for family in ("rip", "ospf", "isis", "eigrp"):
        for instance in sorted((routing.get(family) or {}).values(), key=_seq_key):
            protocol = _routing_object_protocol(family, instance)
            capability = capability_for_routing("sonic", protocol)
            unsupported_lines.append(
                f"{UNSUPPORTED_OBJECT_MARKER} {_routing_object_label(family, instance)} is {capability.status.value} for SONiC; intent preserved"
            )

    for instance in (phase12.get("fhrp") or {}).get("instances", {}).values():
        cap = _service_policy_capability_or_not_implemented("sonic", _fhrp_feature(instance))
        unsupported_lines.append(
            f"{UNSUPPORTED_OBJECT_MARKER} {instance.get('protocol')} {instance.get('id')} is {cap.status.value} for SONiC; intent preserved"
        )
    for rule in ((phase12.get("nat") or {}).get("rules") or {}).values():
        cap = _service_policy_capability_or_not_implemented("sonic", f"NAT_{rule.get('family')}_{rule.get('mode')}")
        unsupported_lines.append(
            f"{UNSUPPORTED_OBJECT_MARKER} {rule.get('family')} {rule.get('mode')} rule {rule.get('id')} is {cap.status.value} for SONiC; intent preserved"
        )
    return doc


class PlatformDriver:
    name: str = ""
    display_name: str = ""

    def supported_feature_names(self) -> list[str]:
        features = ["device_identity"]
        if any(cap.status == CapabilityStatus.SUPPORTED for cap in PLATFORM_CAPABILITIES[self.name].values()):
            features.extend(["interfaces", "addressing", "wan_metadata"])
        if any(cap.status == CapabilityStatus.SUPPORTED for cap in ROUTING_CAPABILITIES[self.name].values()):
            features.append("routing")
        if any(cap.status == CapabilityStatus.SUPPORTED for cap in SERVICE_POLICY_CAPABILITIES[self.name].values()):
            features.extend(["fhrp", "nat", "services", "security", "policy"])
        return features

    def identity_descriptors(self, field_values: dict) -> list[dict]:
        return []

    def render_routing(self, field_values: dict, routing: dict | None, interfaces: list[dict] | None = None) -> list[dict]:
        """Base contract: honest 'not configured'/'unsupported' handling.

        Concrete drivers for platforms with SUPPORTED routing protocols
        override this to emit real, evidence-backed syntax; every other
        platform (and every unsupported object on a supported platform)
        falls back to this honest, non-fabricating behavior.
        """
        routing = routing or {}
        if not any(routing.get(family) for family in _ROUTING_FAMILIES):
            return [{"kind": "static", "text": "! Routing: not configured in current candidate"}]
        return _unsupported_routing_lines(self.name, self.display_name, routing)

    def render_service_policy(self, phase12: dict | None, interfaces: list[dict] | None = None) -> list[dict]:
        return _render_phase12(self.name, self.display_name, phase12 or {}, interfaces or [])

    def routing_process_scope_key(self, family: str, instance: dict):
        """Semantic identity of one actual platform routing-process scope."""
        if family == "rip":
            return family, instance.get("address_family") or "IPV4"
        if family == "ospf":
            if self.name == "ubuntu_frr":
                return family, instance.get("version") or "OSPFV2"
            return family, instance.get("version") or "OSPFV2", instance.get("process_id")
        if family == "bgp":
            return family, instance.get("local_asn")
        if family == "isis" and self.name == "arista_ceos":
            return family, CEOS_ISIS_TAG  # one named instance per VRF: every IS-IS instance is the same CLI scope
        return family, instance.get("id")

    def compose_candidate(self, *, field_values: dict, interfaces=None, routing=None, phase12=None) -> dict:
        return candidate_composition.compose(
            field_values=field_values,
            interfaces=list(interfaces or []),
            routing=routing or {},
            phase12=phase12 or {},
            process_scope_key=self.routing_process_scope_key,
        )

    def interface_contribution_descriptors(self, interface: dict) -> list[dict]:
        return []

    def render_composed(self, candidate: dict) -> list[dict]:
        field_values = candidate["field_values"]
        interfaces = candidate["interfaces"]
        routing = candidate["routing"]
        phase12 = candidate["phase12"]
        lines = self.identity_descriptors(field_values)
        # Preserve Phase 9's honest unsupported-platform contract exactly.
        # An identity renderer which says it is not implemented must not be
        # followed by an "Interfaces: not configured" line that could imply
        # the rest of the platform renderer exists.
        if lines == [NOT_IMPLEMENTED_LINE]:
            has_phase12_objects = any((phase12.get("fhrp") or {}).get("instances", {})) or any(
                (phase12.get("nat") or {}).get(key, {}) for key in ("pools", "rules")
            ) or any(
                (phase12.get("services") or {}).get(name, {}).get("mode") == "OVERRIDE"
                for name in ("dhcp", "dns", "monitoring")
            ) or any((phase12.get("security") or {}).get(key, {}) for key in ("acls", "attachments")) or any(
                ((phase12.get("policy") or {}).get("pbr") or {}).get(key, {}) for key in ("policies", "attachments")
            )
            management = phase12.get("management")
            if not has_phase12_objects and not management_vrf.present(management):
                return lines
            lines.append({"kind": "static", "text": "!"})
            if has_phase12_objects:
                lines.extend(self.render_service_policy(phase12, interfaces or []))
            by_id = {item["id"]: item for item in interfaces or []}
            for part in ("definitions", "routes", "services"):
                lines.extend(management_vrf.render(self.name, part, management, by_id))
            return lines

        vlans = sorted({
            int(interface["vlan_id"])
            for interface in interfaces
            if interface.get("kind") == "SVI" and interface.get("vlan_id") not in (None, "")
            and capability_for(self.name, "SVI").status == CapabilityStatus.SUPPORTED
        })
        if vlans and self.name == "arista_ceos":
            lines.append({"kind": "static", "text": "!"})
            for vlan in vlans:
                lines.append({"kind": "static", "text": f"vlan {vlan}"})

        virtual_mac = (candidate.get("global") or {}).get("fhrp_virtual_mac")
        varp_supported = any(
            _service_policy_supported(self.name, _fhrp_feature(instance))
            for instance in ((phase12 or {}).get("fhrp") or {}).get("instances", {}).values() if instance.get("protocol") == "VARP"
        )
        if virtual_mac and self.name == "arista_ceos" and varp_supported:
            lines.append({"kind": "static", "text": "!"})
            lines.extend(feature_template_renderer.render_descriptors(
                template_name="ceos/fhrp_varp.j2",
                fields={"virtual_mac": {
                    "path": (candidate.get("global") or {}).get("fhrp_virtual_mac_path") or "fhrp.instances",
                    "value": virtual_mac,
                }},
                flags={},
            ))

        management = phase12.get("management")
        # V2 Phase 4: management VRF definitions precede every interface (an interface can join only an existing VRF).
        lines.extend(management_vrf.render(self.name, "definitions", management, {item["id"]: item for item in interfaces}))
        if not interfaces:
            lines.extend(({"kind": "static", "text": "!"}, {"kind": "static", "text": "! Interfaces: not configured in current candidate"}))
        else:
            by_id = {item["id"]: item for item in interfaces}
            for interface in interfaces:
                capability = capability_for(self.name, interface.get("kind", ""))
                if capability.status != CapabilityStatus.SUPPORTED:
                    lines.extend((
                        {"kind": "static", "text": "!"},
                        {"kind": "static", "text": f"{UNSUPPORTED_OBJECT_MARKER} {interface.get('name') or interface.get('id')} / {interface.get('kind')} is {capability.status.value} for {self.display_name}; intent preserved"},
                    ))
                    continue
                lines.extend(_interface_template_descriptors(self.template_platform, interface, by_id))  # pylint: disable=no-member  # template_platform is defined by every concrete driver subclass
                # the VRF binding precedes the addresses: the platforms discard an interface's addresses on a VRF change
                lines.extend(management_vrf.render(self.name, "binding", management, by_id, interface))
                lines.extend(_address_descriptors(self.template_platform, interface, by_id))  # pylint: disable=no-member  # template_platform is defined by every concrete driver subclass
                lines.extend(_wan_descriptors(interface))
                lines.extend(self.interface_contribution_descriptors(interface))
        lines.append({"kind": "static", "text": "!"})
        lines.extend(self.render_routing(field_values, routing, interfaces))
        lines.extend(management_vrf.render(self.name, "routes", management, {item["id"]: item for item in interfaces}))
        lines.append({"kind": "static", "text": "!"})
        lines.extend(self.render_service_policy(phase12, interfaces))
        lines.extend(management_vrf.render(self.name, "services", management, {item["id"]: item for item in interfaces}))
        for conflict in candidate.get("conflicts") or []:
            lines.append({
                "kind": "static",
                "text": (
                    f"! COMPOSITION CONFLICT [{conflict['scope_kind']} {conflict['scope_id']} / "
                    f"{conflict['field']}]: {conflict['existing_source']} conflicts with "
                    f"{conflict['incoming_source']}"
                ),
            })
        return lines

    def render_candidate(self, *, field_values: dict, interfaces: list[dict] | None = None, routing: dict | None = None, phase12: dict | None = None) -> list[dict]:
        candidate = self.compose_candidate(
            field_values=field_values, interfaces=interfaces, routing=routing, phase12=phase12
        )
        return self.render_composed(candidate)


class CeosDriver(PlatformDriver):
    name = "arista_ceos"
    display_name = "Arista cEOS"
    template_platform = "ceos"

    def identity_descriptors(self, field_values):
        return [
            {"kind": "field", "path": "device.hostname", "template": "hostname {value}", "value": field_values.get("device.hostname") or "", "omit_if_empty": True},
            {"kind": "field", "path": "device.description", "template": "! Description: {value}", "value": field_values.get("device.description") or "", "omit_if_empty": True},
        ]

    def render_routing(self, field_values, routing, interfaces=None):
        return _render_routing_generic(
            platform=self.name, display_name=self.display_name, routing=routing, interfaces=interfaces,
            static_renderer=lambda route, ifs: _static_route_descriptors(route, ifs, template_platform=self.template_platform),
            rip_renderer=_ceos_rip_descriptors,
            ospf_renderer=_ceos_ospf_descriptors,
            bgp_renderer=_ceos_bgp_descriptors,
            isis_renderer=_ceos_isis_descriptors,
        )

    def render_service_policy(self, phase12, interfaces=None):
        return _render_phase12(self.name, self.display_name, phase12 or {}, interfaces or [], ceos=True)

    def interface_contribution_descriptors(self, interface):
        lines = _ospf_interface_contributions(interface, ceos=True, platform=self.name)
        lines.extend(_ceos_isis_interface_contributions(interface, platform=self.name))
        lines.extend(_fhrp_interface_contributions(interface, platform=self.name))
        lines.extend(_acl_interface_contributions(interface, platform=self.name))
        lines.extend(_dhcp_interface_contributions(interface, platform=self.name))
        return lines


class UbuntuFrrDriver(PlatformDriver):
    name = "ubuntu_frr"
    display_name = "Ubuntu / FRR"
    template_platform = "ubuntu_frr"

    def identity_descriptors(self, field_values):
        hostname = field_values.get("device.hostname") or ""
        if not hostname:
            return [NOT_IMPLEMENTED_LINE]
        return [{"kind": "field", "path": "device.hostname", "template": "hostnamectl set-hostname {value}", "value": hostname, "omit_if_empty": True}]

    def render_routing(self, field_values, routing, interfaces=None):
        return _render_routing_generic(
            platform=self.name, display_name=self.display_name, routing=routing, interfaces=interfaces,
            static_renderer=lambda route, ifs: _static_route_descriptors(route, ifs, template_platform=self.template_platform),
            rip_renderer=_frr_rip_descriptors,
            ospf_renderer=_frr_ospf_descriptors,
            isis_renderer=_frr_isis_descriptors,
            bgp_renderer=_frr_bgp_descriptors,
        )

    def render_service_policy(self, phase12, interfaces=None):
        return _render_phase12(self.name, self.display_name, phase12 or {}, interfaces or [], ubuntu=True)

    def interface_contribution_descriptors(self, interface):
        lines = _ospf_interface_contributions(interface, ceos=False, platform=self.name)
        lines.extend(_frr_isis_interface_contributions(interface))
        if not lines:
            return []
        return [
            {"kind": "static", "text": "!"},
            {"kind": "static", "text": f"interface {interface.get('name') or '<interface-required>'}"},
            *lines,
        ]


class SrLinuxDriver(PlatformDriver):
    name = "nokia_srlinux"
    display_name = "Nokia SR Linux"
    template_platform = "srlinux"

    def identity_descriptors(self, field_values):
        hostname = field_values.get("device.hostname") or ""
        if not hostname:
            return [NOT_IMPLEMENTED_LINE]
        return [{"kind": "field", "path": "device.hostname", "template": "set system name host-name {value}", "value": hostname}]

    def render_routing(self, field_values, routing, interfaces=None):
        return _render_routing_generic(
            platform=self.name, display_name=self.display_name, routing=routing, interfaces=interfaces,
            static_renderer=_srl_static_route_descriptors,
            rip_renderer=None,
            ospf_renderer=_srl_ospf_descriptors,
            bgp_renderer=_srl_bgp_descriptors,
        )

    def render_service_policy(self, phase12, interfaces=None):
        return _render_phase12(
            self.name, self.display_name, phase12 or {}, interfaces or [],
            srlinux=True, acl_renderer=_render_srl_acl,
        )

    def interface_contribution_descriptors(self, interface):
        lines = _srl_ospf_interface_contributions(interface)
        lines.extend(_srl_acl_interface_contributions(interface))
        lines.extend(_srl_dhcp_interface_contributions(interface))
        return lines


class C8000vIosXeDriver(PlatformDriver):
    name = "cisco_c8000v_iosxe"
    display_name = "Cisco Catalyst 8000V / IOS XE"
    template_platform = "iosxe"

    def identity_descriptors(self, field_values):
        hostname = field_values.get("device.hostname") or ""
        if not hostname:
            return [NOT_IMPLEMENTED_LINE]
        return [{"kind": "field", "path": "device.hostname", "template": "hostname {value}", "value": hostname}]

    def render_routing(self, field_values, routing, interfaces=None):
        return _render_routing_generic(
            platform=self.name, display_name=self.display_name, routing=routing, interfaces=interfaces,
            static_renderer=_iosxe_static_route_descriptors, rip_renderer=_iosxe_rip_descriptors,
            ospf_renderer=_iosxe_ospf_descriptors, bgp_renderer=_iosxe_bgp_descriptors,
        )

    def interface_contribution_descriptors(self, interface):
        return _iosxe_ospf_interface_contributions(interface)


class IosXrDriver(PlatformDriver):
    name = "cisco_iosxr"
    display_name = "Cisco IOS XR"
    template_platform = "iosxr"

    def identity_descriptors(self, field_values):
        hostname = field_values.get("device.hostname") or ""
        if not hostname:
            return [NOT_IMPLEMENTED_LINE]
        return [{"kind": "field", "path": "device.hostname", "template": "hostname {value}", "value": hostname}]

    def render_routing(self, field_values, routing, interfaces=None):
        return _render_routing_generic(
            platform=self.name, display_name=self.display_name, routing=routing, interfaces=interfaces,
            static_renderer=_iosxr_static_route_descriptors,
            rip_renderer=_iosxr_rip_descriptors,
            ospf_renderer=_iosxr_ospf_descriptors,
            bgp_renderer=_iosxr_bgp_descriptors,
        )

    def render_service_policy(self, phase12, interfaces=None):
        return _render_phase12(
            self.name, self.display_name, phase12 or {}, interfaces or [],
            iosxr=True, acl_renderer=_render_iosxr_acl,
        )

    def interface_contribution_descriptors(self, interface):
        lines = _iosxr_ospf_interface_contributions(interface)
        lines.extend(_iosxr_acl_interface_contributions(interface))
        return lines


class SonicDriver(PlatformDriver):
    name = "sonic"
    display_name = "SONiC"
    template_platform = "sonic"

    def identity_descriptors(self, field_values):
        # Unused directly: render_composed is fully overridden below because
        # SONiC's authoritative representation is config_db JSON, not a
        # line-oriented CLI -- see the module-level SONiC helper block.
        return [NOT_IMPLEMENTED_LINE]

    def render_composed(self, candidate: dict) -> list[dict]:
        field_values = candidate["field_values"] or {}
        interfaces = candidate["interfaces"] or []
        routing = candidate["routing"] or {}
        phase12 = candidate["phase12"] or {}
        hostname = field_values.get("device.hostname") or ""
        has_routing_objects = any(routing.get(family) for family in _ROUTING_FAMILIES)
        has_phase12_objects = (
            bool((phase12.get("fhrp") or {}).get("instances"))
            or any((phase12.get("nat") or {}).get(key) for key in ("pools", "rules"))
            or any((phase12.get("security") or {}).get(key) for key in ("acls", "attachments"))
            or any(((phase12.get("policy") or {}).get("pbr") or {}).get(key) for key in ("policies", "attachments"))
        )
        management = phase12.get("management")
        if not hostname and not interfaces and not has_routing_objects and not has_phase12_objects and not management_vrf.present(management):
            return [NOT_IMPLEMENTED_LINE]

        unsupported_lines: list[str] = []
        doc = _sonic_build_config_db(candidate, unsupported_lines)
        doc.update(management_vrf.sonic_config_db(management, unsupported_lines))
        lines = [{"kind": "static", "text": line} for line in json.dumps(doc, indent=2).splitlines()]
        for text in unsupported_lines:
            lines.append({"kind": "static", "text": text})
        for conflict in candidate.get("conflicts") or []:
            lines.append({
                "kind": "static",
                "text": (
                    f"// COMPOSITION CONFLICT [{conflict['scope_kind']} {conflict['scope_id']} / "
                    f"{conflict['field']}]: {conflict['existing_source']} conflicts with "
                    f"{conflict['incoming_source']}"
                ),
            })
        return lines


PLATFORM_DRIVERS: dict[str, PlatformDriver] = {
    driver_cls.name: driver_cls()
    for driver_cls in (CeosDriver, UbuntuFrrDriver, SrLinuxDriver, C8000vIosXeDriver, IosXrDriver, SonicDriver)
}


def get_driver(platform: str) -> PlatformDriver:
    driver = PLATFORM_DRIVERS.get(platform)
    if driver is None:
        raise ValueError(f"No renderer registered for platform {platform!r}")
    return driver
