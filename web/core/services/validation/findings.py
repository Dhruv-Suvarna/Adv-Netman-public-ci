"""Finding vocabulary, stable codes, and safe (bounded, redacted) serialization."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field

from .. import secret_policy

ENGINE_VERSION = "13.2.0"
REPORT_SCHEMA_VERSION = 1

MAX_STRING = 400
MAX_LIST = 40
MAX_DEPTH = 4
MAX_FINDINGS = 400


class Severity:
    ERROR = "ERROR"
    WARNING = "WARNING"
    INFO = "INFO"
    ALL = (ERROR, WARNING, INFO)
    RANK = {ERROR: 0, WARNING: 1, INFO: 2}


class Category:
    SOURCE = "SOURCE"
    INTERNAL = "INTERNAL"
    PLATFORM = "PLATFORM"
    ADDRESSING = "ADDRESSING"
    INTERFACE = "INTERFACE"
    TOPOLOGY = "TOPOLOGY"
    ROUTING = "ROUTING"
    FHRP = "FHRP"
    NAT = "NAT"
    DHCP = "DHCP"
    DNS = "DNS"
    ACL = "ACL"
    PBR = "PBR"
    DEPENDENCY = "DEPENDENCY"
    RAW = "RAW"
    REMOVAL = "REMOVAL"
    MANAGEMENT = "MANAGEMENT"
    ALL = (
        SOURCE, INTERNAL, PLATFORM, ADDRESSING, INTERFACE, TOPOLOGY, ROUTING,
        FHRP, NAT, DHCP, DNS, ACL, PBR, DEPENDENCY, RAW, REMOVAL, MANAGEMENT,
    )


class Status:
    """Overall validation result vocabulary (STALE is a currency state, not a result)."""

    PASS = "PASS"
    PASS_WITH_WARNINGS = "PASS_WITH_WARNINGS"
    BLOCKED = "BLOCKED"
    INCOMPLETE = "INCOMPLETE"
    ALL = (PASS, PASS_WITH_WARNINGS, BLOCKED, INCOMPLETE)


class Currency:
    NEVER_RUN = "NEVER_RUN"
    CURRENT = "CURRENT"
    STALE = "STALE"
    ALL = (NEVER_RUN, CURRENT, STALE)


# code -> (category, default severity, default blocking, default incomplete, meaning)
_E, _W, _I = Severity.ERROR, Severity.WARNING, Severity.INFO
CODE_CATALOG: dict[str, tuple[str, str, bool, bool, str]] = {
    # SOURCE
    "SOURCE_NETBOX_UNAVAILABLE": (Category.SOURCE, _E, False, True, "NetBox could not be read; NetBox-dependent evidence is missing."),
    "SOURCE_TOPOLOGY_UNAVAILABLE": (Category.SOURCE, _E, False, True, "Topology metadata could not be read; link adjacency was not evaluated."),
    "SOURCE_INVENTORY_UNAVAILABLE": (Category.SOURCE, _E, False, True, "The fixed project inventory could not be read."),
    # PLATFORM
    "PLATFORM_FEATURE_UNSUPPORTED": (Category.PLATFORM, _E, True, False, "Registry: the platform cannot implement this object (known limitation)."),
    "PLATFORM_FEATURE_NOT_IMPLEMENTED": (Category.PLATFORM, _E, True, False, "Registry: the platform supports it but the project has no authoritative renderer."),
    "PLATFORM_FEATURE_UNKNOWN": (Category.PLATFORM, _E, False, True, "Registry: capability is unverified; planning must not proceed."),
    "PLATFORM_RENDERER_INCONSISTENT": (Category.PLATFORM, _E, True, False, "Registry and authoritative renderer disagree about an object."),
    "PLATFORM_INVENTORY_MISMATCH": (Category.PLATFORM, _E, True, False, "Intent platform differs from the fixed project inventory platform."),
    "DEVICE_NOT_IN_INVENTORY": (Category.PLATFORM, _W, False, False, "Existing-device intent names a device unknown to inventory/topology."),
    "INTENT_REVISION_MISSING": (Category.INTERNAL, _E, True, False, "A DeviceIntent has no candidate revision, so nothing accepted exists to validate."),
    # ADDRESSING
    "IP_DUPLICATE": (Category.ADDRESSING, _E, True, False, "The same host address is assigned to more than one candidate interface."),
    "IP_NETBOX_COLLISION": (Category.ADDRESSING, _E, True, False, "A candidate host address is already assigned to another NetBox object."),
    "IP_DHCP_POOL_CONFLICT": (Category.ADDRESSING, _E, True, False, "A static candidate address falls inside an active dynamic DHCP pool."),
    "IP_RESERVATION_CONFLICT": (Category.ADDRESSING, _E, True, False, "A candidate address conflicts with a reservation owned by another identity."),
    "AUTO_IP_UNRESOLVED": (Category.ADDRESSING, _E, True, False, "An AUTO address has no resolvable NetBox prefix."),
    "AUTO_IP_NO_AVAILABLE_ADDRESS": (Category.ADDRESSING, _E, True, False, "No free host address remains in the selected prefix."),
    "ADDRESS_INVALID": (Category.ADDRESSING, _E, True, False, "A persisted candidate address is not a valid interface address."),
    "ADDRESS_FAMILY_MISMATCH": (Category.ADDRESSING, _E, True, False, "A persisted address family does not match its address literal."),
    # INTERFACE / TOPOLOGY
    "LINK_PREFIX_MISMATCH": (Category.TOPOLOGY, _E, True, False, "The two ends of a direct routed link do not share a subnet."),
    "LINK_MODE_MISMATCH": (Category.TOPOLOGY, _W, False, False, "The two ends of a link use modes whose compatibility is ambiguous."),
    "LINK_ACCESS_VLAN_MISMATCH": (Category.TOPOLOGY, _E, True, False, "Two access ports of one link carry different VLANs."),
    "LINK_NATIVE_VLAN_MISMATCH": (Category.TOPOLOGY, _E, True, False, "Two trunk ports of one link use different native VLANs."),
    "LINK_TRUNK_VLAN_MISSING": (Category.TOPOLOGY, _E, True, False, "A trunk link does not carry a VLAN the design concretely requires."),
    "LINK_MTU_MISMATCH": (Category.TOPOLOGY, _W, False, False, "The two ends of a direct link use different MTUs."),
    "VLAN_NOT_IN_NETBOX": (Category.INTERFACE, _W, False, False, "A referenced VLAN ID is not modeled in NetBox."),
    "TOPOLOGY_DEVICE_UNKNOWN": (Category.TOPOLOGY, _W, False, False, "A Change device is not present in the topology source."),
    # ROUTING
    "ROUTER_ID_DUPLICATE": (Category.ROUTING, _E, True, False, "Two devices use the same router ID where uniqueness is required."),
    "BGP_PEER_UNRESOLVED": (Category.ROUTING, _W, False, False, "A BGP neighbor address maps to no project-known interface."),
    "BGP_REMOTE_AS_MISMATCH": (Category.ROUTING, _E, True, False, "Configured remote ASN differs from the peer's local ASN."),
    "BGP_AF_MISMATCH": (Category.ROUTING, _E, True, False, "Both BGP peers are candidate-controlled but share no address family."),
    "BGP_PEER_NO_RECIPROCAL": (Category.ROUTING, _W, False, False, "The resolved peer device has no neighbor pointing back."),
    "BGP_NETWORK_NO_EVIDENCE": (Category.ROUTING, _W, False, False, "An advertised prefix has no matching connected/static evidence."),
    "OSPF_AREA_MISMATCH": (Category.ROUTING, _E, True, False, "Both ends of a link run OSPF in different areas."),
    "OSPF_VERSION_MISMATCH": (Category.ROUTING, _E, True, False, "The two ends of a link run different OSPF versions."),
    "OSPF_NETWORK_TYPE_MISMATCH": (Category.ROUTING, _W, False, False, "Both ends set different OSPF network types."),
    "OSPF_ONE_SIDED": (Category.ROUTING, _I, False, False, "Only one end of a link participates in OSPF."),
    "ROUTING_INTERFACE_NO_ADDRESS": (Category.ROUTING, _W, False, False, "A routing interface binding has no address of the needed family."),
    "RIP_FAMILY_MISMATCH": (Category.ROUTING, _W, False, False, "Both ends of a link run RIP for different address families."),
    "ROUTE_FAMILY_MISMATCH": (Category.ROUTING, _E, True, False, "A static route mixes address families."),
    "ROUTE_NEXT_HOP_SELF": (Category.ROUTING, _E, True, False, "A static route's next hop is the device's own address."),
    "ROUTE_NEXT_HOP_UNRESOLVED": (Category.ROUTING, _W, False, False, "A static route next hop is not in a known connected network."),
    "ROUTE_EXIT_INTERFACE_IMPLAUSIBLE": (Category.ROUTING, _W, False, False, "A static route exits through a layer-2-only interface."),
    "OSPF_PROCESS_ID_REQUIRED": (Category.ROUTING, _E, True, False, "cEOS OSPF intent requires a process ID before it is deployable."),
    # FHRP
    "FHRP_VIP_CONFLICT": (Category.FHRP, _E, True, False, "A virtual IP collides with another FHRP domain or an ordinary address."),
    "FHRP_GROUP_MISMATCH": (Category.FHRP, _E, True, False, "Peers of one intended FHRP domain disagree on group or VIP set."),
    "FHRP_VIRTUAL_MAC_MISMATCH": (Category.FHRP, _E, True, False, "Virtual MAC differs inside one shared VARP domain."),
    "FHRP_PRIORITY_DUPLICATE": (Category.FHRP, _W, False, False, "Peers of one FHRP domain use the same priority."),
    "FHRP_VIP_OFF_SUBNET": (Category.FHRP, _W, False, False, "A VIP is outside every candidate subnet of its interface."),
    # NAT
    "NAT_INTERFACE_ROLE_CONFLICT": (Category.NAT, _E, True, False, "A NAT rule uses one interface as both inside and outside."),
    "NAT_POOL_CONFLICT": (Category.NAT, _E, True, False, "A NAT pool is family-incompatible, overlapping, or holds protected addresses."),
    "NAT_FAMILY_MISMATCH": (Category.NAT, _E, True, False, "A NAT rule mixes address families."),
    "NAT_ROLE_UNVERIFIED": (Category.NAT, _I, False, False, "Inside/outside directionality could not be proven from topology metadata."),
    # DHCP / DNS
    "DHCP_VLAN200_FORBIDDEN": (Category.DHCP, _E, True, False, "VLAN 200 management addressing must remain static."),
    "DHCP_POOL_OVERLAP": (Category.DHCP, _W, False, False, "NetBox DHCP pool state has a pre-existing safety problem."),
    "DHCP_RELAY_UNRESOLVED": (Category.DHCP, _W, False, False, "A DHCP relay destination is not a project-known service address."),
    "DHCP_RELAY_FAMILY_MISMATCH": (Category.DHCP, _E, True, False, "A DHCP relay destination family differs from the relay family."),
    "DNS_RESOLVER_UNRESOLVED": (Category.DNS, _W, False, False, "A DNS resolver address is not a project-known service address."),
    # ACL / PBR
    "ACL_REQUIRED_FLOW_DENIED": (Category.ACL, _E, True, False, "An explicit ACL deny provably blocks a required flow."),
    "ACL_EFFECT_UNKNOWN": (Category.ACL, _W, False, False, "The ACL effect on a required flow cannot be proven."),
    "ACL_ENTRY_SHADOWED": (Category.ACL, _W, False, False, "An ACL entry can never match because an earlier entry covers it."),
    "ACL_DUPLICATE_ATTACHMENT": (Category.ACL, _W, False, False, "More than one ACL is attached to one interface/direction/family."),
    "PBR_NEXT_HOP_UNRESOLVED": (Category.PBR, _W, False, False, "A PBR next hop is not in a known connected network."),
    # RAW CONFIGLETS (Phase 18): opaque verified artifacts -- validation never parses their CLI
    "RAW_TARGET_UNKNOWN": (Category.RAW, _E, True, False, "A Raw Configlet targets a device that has no Device Intent in this Change."),
    "RAW_PLATFORM_MISMATCH": (Category.RAW, _E, True, False, "The target device's platform differs from the platform the Raw Configlet revision was authored and verified for."),
    "RAW_VERIFIER_UNAVAILABLE": (Category.RAW, _E, True, False, "The platform has no supported raw verification path."),
    "RAW_NOT_VERIFIED": (Category.RAW, _E, True, False, "The Raw Configlet revision has never been verified."),
    "RAW_VERIFICATION_STALE": (Category.RAW, _E, True, False, "The Raw Configlet verification is STALE (content, platform, policy, verifier or backend changed)."),
    "RAW_VERIFICATION_BLOCKED": (Category.RAW, _E, True, False, "The Raw Configlet verification is BLOCKED (static policy or the platform parser rejected it)."),
    "RAW_VERIFICATION_INCOMPLETE": (Category.RAW, _E, False, True, "The Raw Configlet verification is INCOMPLETE (the sandbox could not complete it); nothing was verified."),
    "RAW_VERIFICATION_WARNINGS": (Category.RAW, _W, False, False, "The Raw Configlet verification passed with warnings."),
    "RAW_PRIORITY_INVALID": (Category.RAW, _E, True, False, "A Raw Configlet priority is not one of the nine canonical deployment priorities."),
    "RAW_DEPENDENCY_SELF": (Category.RAW, _E, True, False, "A Raw Configlet declares a dependency on itself."),
    "RAW_EXECUTION_NOT_SUPPORTED": (Category.RAW, _W, False, False, "The platform can verify but not execute Raw Configlets; a plan containing it cannot be executed."),
    # REMOVAL (Remove Configuration workflow): re-derived from the persisted sanitized snapshot, never from browser text
    "REMOVAL_TARGET_UNKNOWN": (Category.REMOVAL, _E, True, False, "A removal targets a device that is not a target of this Change."),
    "REMOVAL_EMPTY": (Category.REMOVAL, _E, True, False, "A removal selection resolves to nothing."),
    "REMOVAL_BLOCKED": (Category.REMOVAL, _E, True, False, "A removal selection is unsafe: partial context, a protected object, or a dependency that stays."),
    "REMOVAL_NOT_EXECUTABLE": (Category.REMOVAL, _E, True, False, "A removal form is not proven on this platform (fixture-only or not implemented); it can be previewed but not executed."),
    "REMOVAL_NOT_RESTORABLE": (Category.REMOVAL, _W, False, False, "A removed object carries redacted values, so exact compensation is not provable; Complete mode will refuse it."),
    "REMOVAL_POLICY_CHANGES": (Category.REMOVAL, _W, False, False, "A removal changes a policy that stays in use (for example one entry of a referenced ACL)."),
    "REMOVAL_PROPOSAL_AVAILABLE": (Category.REMOVAL, _I, False, False, "The removal leaves an object unused; it is proposed, not included."),
    # MANAGEMENT VRF (V2 Phase 4)
    "MGMT_VRF_PLATFORM_UNSUPPORTED": (Category.MANAGEMENT, _E, True, False, "The platform has no management VRF renderer."),
    "MGMT_VRF_REFERENCE_INVALID": (Category.MANAGEMENT, _E, True, False, "A management VRF binding, route or service references a missing VRF."),
    "MGMT_INTERFACE_REFERENCE_INVALID": (Category.MANAGEMENT, _E, True, False, "A management VRF object references a missing interface."),
    "MGMT_BINDING_INVALID": (Category.MANAGEMENT, _E, True, False, "Only a layer-3 interface can be placed in a management VRF."),
    "MGMT_BINDING_NO_ADDRESS": (Category.MANAGEMENT, _E, True, False, "A management VRF interface has no address and cannot carry management."),
    "MGMT_VRF_UNBOUND": (Category.MANAGEMENT, _E, True, False, "A management VRF has no interface."),
    "MGMT_VRF_NO_ACCESS_SERVICE": (Category.MANAGEMENT, _E, True, False, "A management VRF enables no access service (SSH / API)."),
    "MGMT_ROUTE_NEXT_HOP_UNREACHABLE": (Category.MANAGEMENT, _E, True, False, "A management VRF route's next hop is not inside a bound interface's subnet."),
    "MGMT_VRF_FEATURE_UNSUPPORTED": (Category.MANAGEMENT, _E, True, False, "A management VRF object cannot be rendered for the platform."),
    "MGMT_VRF_MOVES_MANAGEMENT_ADDRESS": (Category.MANAGEMENT, _E, True, False, "The binding moves the device's current management address into the VRF; NMAS's existing session would be cut."),
    "MGMT_VRF_EXECUTION_NOT_IMPLEMENTED": (Category.MANAGEMENT, _W, False, False, "Management VRF objects render and validate for this platform but no executor applies them."),
    # DEPENDENCY / INTERNAL
    "DEPENDENCY_MISSING": (Category.DEPENDENCY, _E, True, False, "An object references a stable ID that does not exist."),
    "DEPENDENCY_CYCLE": (Category.DEPENDENCY, _E, True, False, "The semantic dependency graph contains a cycle."),
    "CANDIDATE_COMPOSITION_CONFLICT": (Category.DEPENDENCY, _E, True, False, "Two incompatible intent contributions claim one configuration-scope property."),
    "INTERNAL_VALIDATION_ERROR": (Category.INTERNAL, _E, False, True, "A validator failed unexpectedly; its checks did not complete."),
    "REPORT_TRUNCATED": (Category.INTERNAL, _W, False, False, "The finding list exceeded the report bound and was truncated."),
}


class Code:
    """Attribute access to every stable finding code (Code.IP_DUPLICATE == "IP_DUPLICATE")."""


for _code in CODE_CATALOG:
    setattr(Code, _code, _code)


def _clip(text) -> str:
    text = str(text)
    return text if len(text) <= MAX_STRING else text[: MAX_STRING - 3] + "..."


def _secret_key(key) -> bool:
    lowered = str(key).lower()
    if lowered.endswith("_ref"):
        return False
    return any(part in lowered for part in secret_policy.FORBIDDEN_METADATA_KEY_SUBSTRINGS)


def sanitize(value, depth: int = 0):
    """Bounded, JSON-safe, secret-redacted copy (never raises, never mutates)."""
    if depth > MAX_DEPTH:
        return "[TRUNCATED]"
    if value is None or isinstance(value, (bool, int)):
        return value
    if isinstance(value, float):
        return round(value, 6)
    if isinstance(value, str):
        return _clip(value)
    if isinstance(value, dict):
        out = {}
        for key in sorted(value, key=str)[:MAX_LIST]:
            out[_clip(key)] = "[REDACTED]" if _secret_key(key) else sanitize(value[key], depth + 1)
        return out
    if isinstance(value, (list, tuple, set, frozenset)):
        items = sorted(value, key=str) if isinstance(value, (set, frozenset)) else list(value)
        return [sanitize(item, depth + 1) for item in items[:MAX_LIST]]
    return _clip(value)


@dataclass
class Finding:
    code: str
    message: str
    severity: str = ""
    category: str = ""
    blocking: bool | None = None
    incomplete: bool | None = None
    device: str | None = None
    object_type: str | None = None
    object_id: str | None = None
    field_path: str | None = None
    related_devices: list = field(default_factory=list)
    related_objects: list = field(default_factory=list)
    source: str = "INTENT"
    evidence: dict = field(default_factory=dict)
    remediation: str = ""

    def __post_init__(self):
        if self.code not in CODE_CATALOG:
            raise ValueError(f"Unknown finding code {self.code!r}")
        category, severity, blocking, incomplete, _ = CODE_CATALOG[self.code]
        self.category = self.category or category
        self.severity = self.severity or severity
        if self.severity not in Severity.ALL or self.category not in Category.ALL:
            raise ValueError("Invalid finding severity/category")
        # A finding only blocks when it is an ERROR; a caller may soften an
        # ERROR-by-default code to WARNING, which must also drop `blocking`.
        if self.blocking is None:
            self.blocking = blocking and self.severity == Severity.ERROR
        if self.incomplete is None:
            self.incomplete = incomplete and self.severity == Severity.ERROR
        self.related_devices = sorted({str(d) for d in self.related_devices if d})
        self.related_objects = sorted({str(o) for o in self.related_objects if o})

    def finding_id(self) -> str:
        basis = "|".join(
            [self.code, self.device or "", self.object_id or "", self.field_path or "",
             ",".join(self.related_objects), ",".join(self.related_devices)]
        )
        return hashlib.sha256(basis.encode()).hexdigest()[:12]

    def sort_key(self):
        return (
            Severity.RANK[self.severity], self.category, self.code, self.device or "",
            self.object_id or "", self.field_path or "", self.message,
        )

    def to_dict(self) -> dict:
        return {
            "finding_id": self.finding_id(),
            "code": self.code,
            "severity": self.severity,
            "category": self.category,
            "message": _clip(self.message),
            "blocking": bool(self.blocking),
            "incomplete": bool(self.incomplete),
            "device": self.device,
            "object_type": self.object_type,
            "object_id": self.object_id,
            "field_path": self.field_path,
            "related_devices": list(self.related_devices),
            "related_objects": list(self.related_objects),
            "source": self.source,
            "evidence": sanitize(self.evidence),
            "remediation": _clip(self.remediation),
        }


def canonical_json(value) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, default=str)


def sha256_of(value) -> str:
    return hashlib.sha256(canonical_json(value).encode()).hexdigest()


def derive_status(findings: list) -> str:
    """BLOCKED > INCOMPLETE > PASS_WITH_WARNINGS > PASS.  Never PASS with a gap."""
    if any(item.blocking for item in findings):
        return Status.BLOCKED
    if any(item.incomplete for item in findings):
        return Status.INCOMPLETE
    if any(item.severity == Severity.WARNING for item in findings):
        return Status.PASS_WITH_WARNINGS
    return Status.PASS
