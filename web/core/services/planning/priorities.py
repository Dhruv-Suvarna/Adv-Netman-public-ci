"""The ONE catalogue mapping validated object types to Configlet classes.

Priority is a coarse deployment class using the canonical
``models.DeploymentPriority`` (1 Foundation/access .. 9 Persistence); it is NOT
the sole ordering mechanism -- dependencies override it (see ``ordering``).
``ConfigletOperationType`` keeps a *definition* distinct from an *attachment /
activation*.

Choices worth stating:

* ACL / NAT-pool / PBR-policy DEFINITIONS are priority 6: they change no traffic
  until attached, and being earlier than their priority-7 attachment means the
  natural order already satisfies DEFINE_BEFORE_ATTACH.
* An address assignment is a DEFINE (it establishes the interface's addressing
  state); a routing-interface binding, BGP address-family activation / network
  advertisement, DHCP relay, NAT rule, ACL attachment and PBR attachment are
  ACTIVATE_ATTACH.
* Priority 8 (monitoring/mirroring) is inherited project infrastructure and 9
  (persistence) is the execution system's responsibility: neither is invented
  here (empty stages are normal).
"""

from __future__ import annotations

from dataclasses import dataclass

from ... import models

PLANNER_VERSION = "14.0.0"
PLAN_SCHEMA_VERSION = 1

P = models.DeploymentPriority
O = models.ConfigletOperationType
N = models.FeatureNamespace


@dataclass(frozen=True)
class ObjectClass:
    priority: int
    operation: str
    namespace: str
    noun: str
    requirement: str  # declarative verification requirement kind (Phase 15 owns the real check)


CATALOGUE: dict[str, ObjectClass] = {
    "device_identity": ObjectClass(P.FOUNDATION_ACCESS, O.CREATE_DEFINE, N.OTHER, "device identity", "IDENTITY_PRESENT"),
    "interface": ObjectClass(P.INTERFACE_CONSTRUCTION, O.CREATE_DEFINE, N.INTERFACES, "interface definition", "INTERFACE_PRESENT"),
    "address": ObjectClass(P.ADDRESSING, O.CREATE_DEFINE, N.INTERFACES, "address assignment", "ADDRESS_PRESENT"),
    "static_route": ObjectClass(P.BASIC_FORWARDING, O.CREATE_DEFINE, N.ROUTING, "static route", "ROUTE_INTENDED"),
    "routing_rip": ObjectClass(P.DYNAMIC_ROUTING, O.CREATE_DEFINE, N.ROUTING, "RIP process definition", "ROUTING_PROCESS_INTENDED"),
    "routing_ospf": ObjectClass(P.DYNAMIC_ROUTING, O.CREATE_DEFINE, N.ROUTING, "OSPF process definition", "ROUTING_PROCESS_INTENDED"),
    "routing_isis": ObjectClass(P.DYNAMIC_ROUTING, O.CREATE_DEFINE, N.ROUTING, "IS-IS process definition", "ROUTING_PROCESS_INTENDED"),
    "routing_eigrp": ObjectClass(P.DYNAMIC_ROUTING, O.CREATE_DEFINE, N.ROUTING, "EIGRP process definition", "ROUTING_PROCESS_INTENDED"),
    "routing_bgp": ObjectClass(P.DYNAMIC_ROUTING, O.CREATE_DEFINE, N.ROUTING, "BGP process definition", "ROUTING_PROCESS_INTENDED"),
    "routing_binding": ObjectClass(P.DYNAMIC_ROUTING, O.ACTIVATE_ATTACH, N.ROUTING, "routing interface attachment", "ROUTING_INTERFACE_ENABLED"),
    "bgp_neighbor": ObjectClass(P.DYNAMIC_ROUTING, O.CREATE_DEFINE, N.ROUTING, "BGP neighbor definition", "BGP_PEER_INTENDED"),
    "bgp_neighbor_af": ObjectClass(P.DYNAMIC_ROUTING, O.ACTIVATE_ATTACH, N.ROUTING, "BGP address-family activation", "BGP_AF_ACTIVATION_INTENDED"),
    "bgp_network": ObjectClass(P.DYNAMIC_ROUTING, O.ACTIVATE_ATTACH, N.ROUTING, "BGP network advertisement", "BGP_NETWORK_INTENDED"),
    "fhrp": ObjectClass(P.HIGHER_LEVEL_SERVICES, O.CREATE_DEFINE, N.FHRP, "FHRP definition", "FHRP_GROUP_INTENDED"),
    "dhcp_relay": ObjectClass(P.HIGHER_LEVEL_SERVICES, O.ACTIVATE_ATTACH, N.SERVICES, "DHCP relay attachment", "DHCP_RELAY_INTENDED"),
    "nat_pool": ObjectClass(P.HIGHER_LEVEL_SERVICES, O.CREATE_DEFINE, N.NAT, "NAT pool definition", "NAT_POOL_INTENDED"),
    "nat_rule": ObjectClass(P.TRAFFIC_AFFECTING_POLICY, O.ACTIVATE_ATTACH, N.NAT, "NAT rule activation", "NAT_RULE_INTENDED"),
    "acl": ObjectClass(P.HIGHER_LEVEL_SERVICES, O.CREATE_DEFINE, N.SECURITY, "ACL definition", "ACL_DEFINED"),
    "acl_attachment": ObjectClass(P.TRAFFIC_AFFECTING_POLICY, O.ACTIVATE_ATTACH, N.SECURITY, "ACL attachment", "ACL_ATTACHMENT_INTENDED"),
    "pbr_policy": ObjectClass(P.HIGHER_LEVEL_SERVICES, O.CREATE_DEFINE, N.OTHER, "PBR policy definition", "PBR_POLICY_DEFINED"),
    "pbr_attachment": ObjectClass(P.TRAFFIC_AFFECTING_POLICY, O.ACTIVATE_ATTACH, N.OTHER, "PBR attachment", "PBR_ATTACHMENT_INTENDED"),
    # V2 Phase 4 management VRF.  The binding moves an interface (and re-applies its addresses), so it is an ADDRESSING-stage
    # attachment; the explicit graph edges (VRF -> binding -> route / service) override stage order where needed.
    "mgmt_vrf": ObjectClass(P.INTERFACE_CONSTRUCTION, O.CREATE_DEFINE, N.ROUTING, "management VRF definition", "MGMT_VRF_PRESENT"),
    "mgmt_vrf_binding": ObjectClass(P.ADDRESSING, O.ACTIVATE_ATTACH, N.INTERFACES, "management VRF interface binding", "MGMT_VRF_BOUND"),
    "mgmt_vrf_route": ObjectClass(P.BASIC_FORWARDING, O.CREATE_DEFINE, N.ROUTING, "management VRF route", "MGMT_VRF_ROUTE_PRESENT"),
    "mgmt_vrf_service": ObjectClass(P.HIGHER_LEVEL_SERVICES, O.ACTIVATE_ATTACH, N.SERVICES, "management VRF service", "MGMT_SERVICE_IN_VRF"),
    # Phase 18: an OPAQUE operator-authored Raw Configlet.  Its priority is the operator's explicit, declared value (never inferred
    # from command text), so the priority below is only the catalogue default; ACTIVATE_ATTACH orders it after structured
    # definitions of the same priority.  Dependencies still override priority (see ``ordering``).
    "raw_configlet": ObjectClass(P.HIGHER_LEVEL_SERVICES, O.ACTIVATE_ATTACH, N.OTHER, "raw Configlet", "RAW_CONFIG_APPLIED"),
    # Remove Configuration: intentional removal of existing configuration (NOT compensation / rollback).  Every removal is
    # traffic-affecting; within the stage a detach precedes a delete, and explicit referrer-first edges override both.
    "config_removal_detach": ObjectClass(P.TRAFFIC_AFFECTING_POLICY, O.DEACTIVATE_DETACH, N.OTHER, "configuration detach", "CONFIG_REMOVED"),
    "config_removal_delete": ObjectClass(P.TRAFFIC_AFFECTING_POLICY, O.REMOVE_DELETE, N.OTHER, "configuration removal", "CONFIG_REMOVED"),
}

# Graph node types that do not get a Configlet of their own: they are rendered as part of another Configlet.
FOLDED_NODE_TYPES = {"pbr_sequence": "pbr_policy"}  # sequence entries are part of the policy definition
# Object types the planner recognises but that no supported platform can render today (Phase 13 blocks them).
OPERATION_RANK = {O.CREATE_DEFINE: 0, O.ACTIVATE_ATTACH: 1, O.DEACTIVATE_DETACH: 2, O.REMOVE_DELETE: 3}

STAGE_KEYS = {
    P.FOUNDATION_ACCESS: "FOUNDATION_ACCESS",
    P.INTERFACE_CONSTRUCTION: "INTERFACE_CONSTRUCTION",
    P.ADDRESSING: "ADDRESSING",
    P.BASIC_FORWARDING: "BASIC_FORWARDING",
    P.DYNAMIC_ROUTING: "DYNAMIC_ROUTING",
    P.HIGHER_LEVEL_SERVICES: "HIGHER_LEVEL_SERVICES",
    P.TRAFFIC_AFFECTING_POLICY: "TRAFFIC_AFFECTING_POLICY",
    P.MONITORING_MIRRORING: "MONITORING_MIRRORING",
    P.PERSISTENCE: "PERSISTENCE",
}


def stage_table() -> list[dict]:
    """The nine canonical stages in order, with their canonical labels."""
    return [{"priority": int(p), "key": STAGE_KEYS[p], "label": p.label} for p in P]
