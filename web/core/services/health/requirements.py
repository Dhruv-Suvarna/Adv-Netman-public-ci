"""Phase-14 verification descriptors -> executable requirements (table driven, no vendor/hostname conditionals).

Phase 14 stores one declarative descriptor per Configlet (``verification_spec.requirements[]``: ``requirement`` kind,
``device``, ``subject``, and -- descriptor schema 2 -- the secret-free ``expected`` facts).  Phase 15 CONSUMES those
descriptors: it never rebuilds expected state from intent and never edits a plan or Configlet.

``REQUIREMENT_MAP`` is the single mapping from a Phase-14 requirement kind to one or more Phase-15 *check types*.
Kinds with no evaluator are listed in ``KNOWN_NOT_IMPLEMENTED`` and evaluate to UNKNOWN / NOT_IMPLEMENTED -- never
PASS.  An unrecognised kind evaluates to UNKNOWN / REQUIREMENT_UNKNOWN_TYPE.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from types import MappingProxyType

NOT_IMPLEMENTED = "NOT_IMPLEMENTED"
UNKNOWN_TYPE = "UNKNOWN_TYPE"

# Executable check types (what an evaluator can actually decide from the current evidence adapters).
CHECK_TYPES = (
    "INTERFACE_PRESENT", "INTERFACE_ADMIN_STATE", "INTERFACE_OPER_STATE", "ADDRESS_PRESENT", "STATIC_ROUTE_PRESENT",
    "OSPF_NEIGHBOR_EXPECTED", "ISIS_NEIGHBOR_EXPECTED", "ISIS_ROUTE_EXPECTED", "RIP_NEIGHBOR_EXPECTED", "RIP_ROUTE_EXPECTED", "BGP_NEIGHBOR_EXPECTED", "FHRP_VIRTUAL_ADDRESS_PRESENT", "DHCP_RELAY_CONFIG_PRESENT",
    "ACL_DEFINITION_PRESENT", "ACL_ATTACHMENT_PRESENT", "NAT_RULE_PRESENT", "CONFIG_OBJECT_ABSENT",
    "ROUTING_PROCESS_CONFIG", "ROUTING_BINDING_CONFIG", "BGP_NEIGHBOR_CONFIG", "BGP_NETWORK_CONFIG",
    "MGMT_VRF_PRESENT", "MGMT_VRF_BOUND", "MGMT_VRF_ROUTE_PRESENT", "MGMT_SERVICE_IN_VRF",
)

# Phase-14 requirement kind -> ((match on descriptor.expected, check type), ...).  Every matching row applies; when none
# match, the requirement is NOT_IMPLEMENTED (for example a RIP binding: only OSPF adjacency has an evaluator today).
REQUIREMENT_MAP = MappingProxyType({
    "INTERFACE_PRESENT": (({}, "INTERFACE_PRESENT"), ({}, "INTERFACE_ADMIN_STATE"), ({}, "INTERFACE_OPER_STATE")),
    "ADDRESS_PRESENT": (({}, "ADDRESS_PRESENT"),),
    "ROUTE_INTENDED": (({}, "STATIC_ROUTE_PRESENT"),),
    "ROUTING_PROCESS_INTENDED": (({}, "ROUTING_PROCESS_CONFIG"),),
    "ROUTING_INTERFACE_ENABLED": (({"protocol": "ospf"}, "OSPF_NEIGHBOR_EXPECTED"), ({"protocol": "isis"}, "ISIS_NEIGHBOR_EXPECTED"),
                                  ({}, "ROUTING_BINDING_CONFIG")),
    # Stated by a migration stage, not derived from a Device Builder object: the route / peer facts ARE the requirement.
    "ISIS_ROUTE_INTENDED": (({}, "ISIS_ROUTE_EXPECTED"),),
    "RIP_PEERING_INTENDED": (({}, "RIP_NEIGHBOR_EXPECTED"),),
    "RIP_ROUTE_INTENDED": (({}, "RIP_ROUTE_EXPECTED"),),
    "BGP_PEER_INTENDED": (({}, "BGP_NEIGHBOR_EXPECTED"), ({}, "BGP_NEIGHBOR_CONFIG")),
    "BGP_AF_ACTIVATION_INTENDED": (({}, "BGP_NEIGHBOR_EXPECTED"), ({}, "BGP_NEIGHBOR_CONFIG")),
    "BGP_NETWORK_INTENDED": (({}, "BGP_NETWORK_CONFIG"),),
    "FHRP_GROUP_INTENDED": (({}, "FHRP_VIRTUAL_ADDRESS_PRESENT"),),
    "DHCP_RELAY_INTENDED": (({}, "DHCP_RELAY_CONFIG_PRESENT"),),
    "ACL_DEFINED": (({}, "ACL_DEFINITION_PRESENT"),),
    "ACL_ATTACHMENT_INTENDED": (({}, "ACL_ATTACHMENT_PRESENT"),),
    "NAT_RULE_INTENDED": (({}, "NAT_RULE_PRESENT"),),
    "CONFIG_REMOVED": (({}, "CONFIG_OBJECT_ABSENT"),),   # Remove Configuration: the removed statement must be gone
    "MGMT_VRF_PRESENT": (({}, "MGMT_VRF_PRESENT"),),
    "MGMT_VRF_BOUND": (({}, "MGMT_VRF_BOUND"),),
    "MGMT_VRF_ROUTE_PRESENT": (({}, "MGMT_VRF_ROUTE_PRESENT"),),
    "MGMT_SERVICE_IN_VRF": (({}, "MGMT_SERVICE_IN_VRF"),),
})

# Recognised Phase-14 kinds that no current adapter can verify -- honest gaps, not silent passes.
KNOWN_NOT_IMPLEMENTED = frozenset({
    "IDENTITY_PRESENT", "NAT_POOL_INTENDED",
    "PBR_POLICY_DEFINED", "PBR_ATTACHMENT_INTENDED",
    "RAW_CONFIG_APPLIED",  # Phase 18: an opaque Raw Configlet with no operator-declared assertion can never confirm its own effect
})


@dataclass(frozen=True)
class Requirement:
    """One normalized requirement of one Configlet (a descriptor may expand to several check types)."""

    cfg_id: str
    device: str
    kind: str                      # the Phase-14 requirement kind
    label: str = ""                # human subject label ("R1 Ethernet1")
    object_type: str = ""
    object_id: str = ""
    expected: dict | None = None   # None => an older descriptor with no expected facts
    check_types: tuple = field(default_factory=tuple)

    @property
    def subject(self) -> str:
        return self.label or f"{self.device}/{self.object_type}/{self.object_id}"


def expand(kind: str, expected: dict | None) -> tuple:
    """The check types a requirement expands to: executable names, or one NOT_IMPLEMENTED / UNKNOWN_TYPE marker."""
    if kind in REQUIREMENT_MAP:
        facts = expected or {}
        matched = tuple(check for match, check in REQUIREMENT_MAP[kind] if all(facts.get(k) == v for k, v in match.items()))
        return matched or (NOT_IMPLEMENTED,)
    if kind in KNOWN_NOT_IMPLEMENTED:
        return (NOT_IMPLEMENTED,)
    return (UNKNOWN_TYPE,)


def from_descriptor(cfg_id: str, descriptor: dict, *, device: str = "") -> Requirement:
    subject = descriptor.get("subject") or {}
    expected = descriptor.get("expected")
    expected = dict(expected) if isinstance(expected, dict) else None
    kind = str(descriptor.get("requirement") or "")
    return Requirement(
        cfg_id=cfg_id, device=str(descriptor.get("device") or device), kind=kind, label=str(subject.get("label") or ""),
        object_type=str(subject.get("object_type") or ""), object_id=str(subject.get("object_id") or ""),
        expected=expected, check_types=expand(kind, expected),
    )


def normalize_plan(plan) -> list[Requirement]:
    """Every requirement of a plan, in plan (dependency) order.  Reads the frozen Configlet descriptors only."""
    requirements = []
    for configlet in plan.configlets.order_by("sequence"):
        descriptors = (configlet.verification_spec or {}).get("requirements") or []
        for descriptor in descriptors:
            requirements.append(from_descriptor(configlet.cfg_id, descriptor, device=configlet.target_device))
    return requirements


def plan_interfaces(requirements) -> dict:
    """{device: {interface names CREATED by this plan}} -- a prerequisite on these is satisfied by the plan itself."""
    created: dict = {}
    for req in requirements:
        if req.kind == "INTERFACE_PRESENT" and req.expected and req.expected.get("interface"):
            created.setdefault(req.device, set()).add(req.expected["interface"])
    return created
