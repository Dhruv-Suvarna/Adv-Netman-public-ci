"""The execution capability model: which (platform, object type) pairs can be APPLIED, and which can be COMPENSATED.

Evidence-based, never inferred from vendor knowledge and never from the mere existence of candidate rendering.  Two
independent dimensions, each using the project's four-status vocabulary (SUPPORTED / NOT_IMPLEMENTED / UNSUPPORTED /
UNKNOWN):

* ``apply``         can the executor send this Configlet to a device of this platform?
* ``compensation``  can Complete mode PROVE an exact undo (additive Configlets whose inverse is exact and whose restored
                    state the Phase-15 read groups can confirm)?

cEOS  -- apply evidence: ``master.py::push_eos`` (Netmiko config mode, ``modules.eos_render.eos_commands`` flattening,
         explicit error-string detection); read/verify evidence: the Phase-15 ``health.live`` cEOS allowlist.
Linux -- apply evidence: the tracked R3/R4 scripts use iproute2 link/address commands, and the Phase-15 Linux transport is
         ``docker exec <container> <fixed argv>`` (credential-free). An isolated FRR 8.4.4 lab now also proves strict
         incremental vtysh IPv4/IPv6 static-route apply, route readback and exact inverse, and incremental OSPF,
         RIP/RIPng and BGP process changes with a captured-configuration inverse, and NAT44 masquerade as one
         dedicated nftables table (created atomically and deleted as a whole, or extended when that exact
         NMAS-shaped table exists and restored to its captured rule list). A table holding anything else
         is never merged into.
SR Linux -- apply evidence: an isolated SR Linux 24.10.7 node accepts the rendered ``set`` paths as one atomic gNMI
         CLI-origin SetRequest; interfaces, addresses and static routes are inverted against the running configuration
         captured by gNMI Get and restoration is proven by an identical configuration tree. Other object types have no
         verified list-key model and are refused.
IOS XE -- apply evidence: an isolated Catalyst 8000V (IOS XE 17.06.01a) accepts the rendered lines in one Netmiko
         configuration-mode session; interfaces, addresses, static routes and the OSPF, RIP and BGP process changes are
         inverted against the running configuration captured before apply (address-family sections inverted in their own
         mode) and restoration is proven by an identical running configuration.
"""

from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType

from .codes import Capability

CEOS_APPLY = frozenset({
    "interface", "address", "static_route", "routing_rip", "routing_ospf", "routing_isis", "routing_bgp", "routing_binding",
    "bgp_neighbor", "bgp_neighbor_af", "bgp_network", "fhrp", "dhcp_relay", "acl", "acl_attachment",
    "raw_configlet",  # Phase 18: the verified, pinned statements through the SAME Netmiko config-mode path (Partial (UAT) only)
    # Remove Configuration: parser-validated removal forms through the same config-mode path; verified by running-config read-back
    "config_removal", "config_removal_detach", "config_removal_delete",
    # V2 Phase 4 management VRF -- listed, but gated by recorded live evidence (``management_gate``)
    "mgmt_vrf", "mgmt_vrf_binding", "mgmt_vrf_route", "mgmt_vrf_service",
})
MANAGEMENT_TYPES = frozenset({"mgmt_vrf", "mgmt_vrf_binding", "mgmt_vrf_route", "mgmt_vrf_service"})
# additive-only compensation: exact inverse, provable read-back (an interface only when it did not exist beforehand)
REMOVAL_TYPES = frozenset({"config_removal", "config_removal_detach", "config_removal_delete"})
# The second group is compensated by exact running-configuration restoration (executors.ceos.CONFIG_BLOCK_TYPES).
CEOS_COMPENSABLE = frozenset({"interface", "address", "static_route", *REMOVAL_TYPES,
                              "acl", "acl_attachment", "dhcp_relay", "fhrp", "routing_rip", "routing_ospf", "routing_isis",
                              "routing_bgp", "routing_binding", "bgp_neighbor", "bgp_neighbor_af", "bgp_network",
                              *MANAGEMENT_TYPES})
_LINUX_ROUTING = ("routing_ospf", "routing_binding", "routing_rip", "routing_isis", "routing_bgp", "bgp_neighbor", "bgp_neighbor_af", "bgp_network")
LINUX_APPLY = frozenset({"interface", "address", "static_route", "nat_rule", *_LINUX_ROUTING})
LINUX_COMPENSABLE = frozenset({"interface", "address", "static_route", "nat_rule", *_LINUX_ROUTING})
# executors.srlinux.OBJECT_TYPES: every applied type is compensated from the captured configuration tree.  The routing and
# service types (V2 Phase 9) were proven on the isolated SR Linux 24.10.7 node against an FRR peer: adjacency / session /
# filtering / relaying, live import, exact restoration.
SRLINUX_APPLY = SRLINUX_COMPENSABLE = frozenset({"interface", "address", "static_route", "routing_ospf", "routing_binding",
                                                 "routing_bgp", "bgp_neighbor", "bgp_neighbor_af", "bgp_network", "acl",
                                                 "acl_attachment", "dhcp_relay"})
# executors.iosxe.OBJECT_TYPES: compensated from the captured running configuration.  The routing types (V2 Phase 9) were
# proven on the isolated Catalyst 8000V against an FRR peer: adjacency/session, live import, exact restoration.
IOSXE_APPLY = IOSXE_COMPENSABLE = frozenset({"interface", "address", "static_route", "routing_rip", "routing_ospf", "routing_bgp",
                                             "routing_binding", "bgp_neighbor", "bgp_neighbor_af", "bgp_network"})

_NOT_IMPLEMENTED_TYPES = {
    "device_identity": "A hostname rename changes the identity every telemetry stream is keyed by and has no verifier.",
    "nat_pool": "No platform renders NAT pools.", "nat_rule": "Multi-rule nftables table merge is unresolved (Phase 14 limitation).",
    "pbr_policy": "No platform supports PBR.", "pbr_attachment": "No platform supports PBR.",
    "raw_configlet": "No supported, incremental raw-FRR apply mechanism is proven (master.py applies frr.conf as a whole); a Raw Configlet is never run as a Linux shell command.",
    "routing_isis": "Rendered and executed on cEOS and FRR.", "routing_eigrp": "No renderer on any platform.",
    "mgmt_vrf": "Management VRF: rendered and validated; execution is implemented for cEOS only.",
    "mgmt_vrf_binding": "Management VRF: rendered and validated; execution is implemented for cEOS only.",
    "mgmt_vrf_route": "Management VRF: rendered and validated; execution is implemented for cEOS only.",
    "mgmt_vrf_service": "Management VRF: rendered and validated; execution is implemented for cEOS only.",
    "config_removal": "FRR removal is rendered and fixture-tested only; master.py applies frr.conf as a whole and no incremental FRR apply path is proven.",
    "config_removal_detach": "FRR removal is rendered and fixture-tested only; master.py applies frr.conf as a whole and no incremental FRR apply path is proven.",
    "config_removal_delete": "FRR removal is rendered and fixture-tested only; master.py applies frr.conf as a whole and no incremental FRR apply path is proven.",
}


@dataclass(frozen=True)
class ExecutionCapability:
    apply: str
    compensation: str
    transport: str
    evidence: str
    note: str = ""


PLATFORM_EVIDENCE = MappingProxyType({
    "arista_ceos": ("netmiko-config-mode", "master.py push_eos (Netmiko config mode + eos_commands); Phase-15 health.live cEOS read allowlist"),
    "ubuntu_frr": ("docker-exec", "tracked R3/R4 iproute2 commands; Phase-15 health.live docker-exec transport (no credentials)"),
    "nokia_srlinux": ("gnmi-set", "isolated SR Linux 24.10.7: atomic gNMI CLI-origin Set, gNMI Get captured-tree inverse; "
                      "not part of the approved live Labs 2/3 baseline, so no inventory target exists there."),
    "cisco_c8000v_iosxe": ("netmiko-config-mode", "isolated Catalyst 8000V / IOS XE 17.06.01a: Netmiko configuration mode, "
                           "captured running-config inverse; not part of the approved live Labs 2/3 baseline."),
    "cisco_iosxr": ("", "No repository evidence of any IOS XR session or configuration application."),
    "sonic": ("", "No repository evidence of any SONiC session or configuration application."),
})


def management_gate(platform: str, object_type: str, service: str = "") -> bool:
    """True only when the isolated Phase-4 fixture recorded live apply + compensation evidence for this management type.  The
    service type is gated per service (``...:execute:mgmt_vrf_service:SSH``): evidence for SSH says nothing about SNMP in a
    VRF, so a caller that does not name the service is refused."""
    from ..management import capability_evidence

    if object_type == "mgmt_vrf_service":
        return bool(service) and bool(capability_evidence.LIVE.get(f"{platform}:execute:{object_type}:{service.upper()}"))
    return bool(capability_evidence.LIVE.get(f"{platform}:execute:{object_type}"))


def capability_for(platform: str, object_type: str, service: str = "") -> ExecutionCapability:
    """The execution capability of one (platform, object type).  Unrecognised platforms are UNKNOWN, never assumed."""
    if platform not in PLATFORM_EVIDENCE:
        return ExecutionCapability(Capability.UNKNOWN, Capability.UNKNOWN, "", "Platform not recognised by the execution engine.")
    transport, evidence = PLATFORM_EVIDENCE[platform]
    if platform in ("cisco_iosxr", "sonic"):
        return ExecutionCapability(Capability.NOT_IMPLEMENTED, Capability.NOT_IMPLEMENTED, transport, evidence)
    apply_types, compensable = {"arista_ceos": (CEOS_APPLY, CEOS_COMPENSABLE),
                                "nokia_srlinux": (SRLINUX_APPLY, SRLINUX_COMPENSABLE),
                                "cisco_c8000v_iosxe": (IOSXE_APPLY, IOSXE_COMPENSABLE)}.get(platform, (LINUX_APPLY, LINUX_COMPENSABLE))
    if object_type in MANAGEMENT_TYPES and object_type in apply_types and not management_gate(platform, object_type, service):
        return ExecutionCapability(Capability.NOT_IMPLEMENTED, Capability.NOT_IMPLEMENTED, transport, evidence,
                                   "Management VRF execution is implemented for cEOS but no live evidence is recorded "
                                   "(management.capability_evidence.LIVE); it stays refused until the isolated fixture proves it.")
    if object_type not in apply_types:
        note = _NOT_IMPLEMENTED_TYPES.get(object_type, f"No evidence-backed apply path for {object_type or 'this object type'} on this platform.")
        return ExecutionCapability(Capability.NOT_IMPLEMENTED, Capability.NOT_IMPLEMENTED, transport, evidence, note)
    if object_type == "raw_configlet":  # never compensable: an inverse cannot be derived from opaque text
        return ExecutionCapability(Capability.SUPPORTED, Capability.NOT_IMPLEMENTED, transport, evidence,
                                   "Partial (UAT) only: a raw Configlet lacks proven transactional compensation, so Complete is refused.")
    if object_type in REMOVAL_TYPES:
        return ExecutionCapability(Capability.SUPPORTED, Capability.SUPPORTED, transport, evidence,
                                   "Intentional removal: the captured original lines are re-added and verified by running-config read-back; "
                                   "an object with redacted values is not restorable, so Complete mode refuses it.")
    if object_type in compensable:
        return ExecutionCapability(Capability.SUPPORTED, Capability.SUPPORTED, transport, evidence, "Additive: exact inverse, verified by read-back.")
    return ExecutionCapability(
        Capability.SUPPORTED, Capability.NOT_IMPLEMENTED, transport, evidence,
        "Partial (UAT) only: it modifies existing state and no exact restore is provable, so Complete is refused.",
    )


def capability_matrix() -> list[dict]:
    """A presentable table of every catalogued object type per platform (documentation / the execute page)."""
    from ..planning import priorities

    rows = []
    for platform in PLATFORM_EVIDENCE:
        for object_type in sorted(priorities.CATALOGUE):
            cap = capability_for(platform, object_type)
            rows.append({"platform": platform, "object_type": object_type, "apply": cap.apply, "compensation": cap.compensation})
    return rows
