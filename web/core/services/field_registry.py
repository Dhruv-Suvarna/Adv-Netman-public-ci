"""
Allowlist of Phase-9 editable field paths.

Field commit never accepts an arbitrary browser-supplied JSON path -- only
paths present here are resolvable, each bound to exactly one Tier-1
validator. There is no dynamic eval, no setattr from a browser-provided
attribute name: `mirrors_to` is a fixed string looked up in this module
only, used with plain, hardcoded `setattr(intent, mirrors_to, ...)` calls in
field_commit_service against a small, explicit set of known DeviceIntent
column names.

Interfaces/routing/services/security field paths do not exist yet --
Phase 10+ adds them here as their own namespaces once real feature modules
exist. Do not pre-register paths for functionality that isn't implemented.
"""

from __future__ import annotations

import ipaddress
import re

from . import (
    field_validators,
    interface_intent_service,
    platform_drivers,
    routing_intent_service,
    service_policy_intent_service,
)

FIELD_REGISTRY = {
    "device.hostname": {
        "label": "Hostname",
        "validator": field_validators.validate_hostname,
        "mirrors_to": None,
        "module": "device_identity",
    },
    "device.description": {
        "label": "Description",
        "validator": field_validators.validate_description,
        "mirrors_to": None,
        "module": "device_identity",
    },
    "device.target_type": {
        "label": "Target type",
        "validator": field_validators.validate_target_type,
        "mirrors_to": "target_type",
        "module": "device_identity",
    },
    "device.platform": {
        "label": "Platform",
        "validator": field_validators.validate_platform,
        "mirrors_to": "platform",
        "module": "platform",
    },
    "device.image_reference": {
        "label": "Image reference",
        "validator": field_validators.validate_image_reference,
        "mirrors_to": "image_reference",
        "module": "image_metadata",
    },
}

# DeviceIntent columns a field commit is permitted to mirror onto -- must be
# a subset of the *_to values above, checked defensively at import time so a
# typo in FIELD_REGISTRY can never open up an unintended attribute target.
_ALLOWED_MIRROR_FIELDS = {"target_type", "platform", "image_reference"}
for _spec in FIELD_REGISTRY.values():
    _mirror = _spec.get("mirrors_to")
    if _mirror is not None and _mirror not in _ALLOWED_MIRROR_FIELDS:
        raise RuntimeError(f"FIELD_REGISTRY: {_mirror!r} is not an allowed mirror target.")


def field_paths_for_module(module: str) -> list[str]:
    return [path for path, spec in FIELD_REGISTRY.items() if spec["module"] == module]


_INTERFACE_PATH_RE = re.compile(r"^interfaces\.(if_[0-9a-f]{16})\.([a-z_]+)$")
_ADDRESS_PATH_RE = re.compile(
    r"^interfaces\.(if_[0-9a-f]{16})\.addresses\.(addr_[0-9a-f]{16})\.([a-z_]+)$"
)
_WAN_PATH_RE = re.compile(r"^interfaces\.(if_[0-9a-f]{16})\.wan\.([a-z0-9_]+)$")


def _syntax_spec(label, validator, *, module="interfaces", binding=None):
    return {
        "label": label,
        "validator": validator,
        "mirrors_to": None,
        "module": module,
        "dynamic": True,
        "binding": binding,
    }


def _interface_has_auto_addresses(interface: dict) -> bool:
    return any(address.get("source") == "AUTO" for address in (interface.get("addresses") or {}).values())


def _interface_field_spec(*, revision, interface: dict, field: str):
    specs = {
        "name": _syntax_spec("Interface name", field_validators.validate_interface_name),
        "description": _syntax_spec("Description", field_validators.validate_interface_description),
        "admin_state": _syntax_spec(
            "Admin intent",
            lambda value: field_validators.validate_enum(
                value, allowed=interface_intent_service.ADMIN_STATES, label="admin intent"
            ),
        ),
        "mtu": _syntax_spec("MTU", field_validators.validate_mtu),
        "access_vlan": _syntax_spec("Access VLAN", field_validators.validate_vlan_id),
        "trunk_allowed_vlans": _syntax_spec("Allowed VLANs", field_validators.validate_vlan_set),
        "native_vlan": _syntax_spec(
            "Native VLAN", lambda value: field_validators.validate_vlan_id(value, optional=True)
        ),
        "encapsulation_vlan": _syntax_spec("Encapsulation VLAN", field_validators.validate_vlan_id),
        "vlan_id": _syntax_spec("SVI VLAN", field_validators.validate_vlan_id),
        "role": _syntax_spec(
            "Role", lambda value: field_validators.validate_bounded_label(value, label="Role")
        ),
        "operational_description": _syntax_spec(
            "Operational description", field_validators.validate_interface_description
        ),
    }
    if field == "kind":
        def validate_kind(value):
            if value not in interface_intent_service.INTERFACE_KINDS:
                return False, value, "Unknown interface type."
            if not platform_drivers.is_interface_kind_selectable(revision.device_intent.platform, value):
                return False, value, "That interface type is not implemented for the selected platform."
            if value == "MANAGEMENT" and _interface_has_auto_addresses(interface):
                return False, value, "Management addressing is static; change AUTO addresses to MANUAL first."
            return True, value, "Syntax accepted; project validation pending."
        return _syntax_spec("Interface type", validate_kind)
    if field == "parent_id":
        def validate_parent(value):
            value = (value or "").strip()
            if not value:
                return False, value, "A candidate-owned parent interface is required."
            try:
                parent = interface_intent_service.get_interface(revision, value)
            except interface_intent_service.CollectionOwnershipError:
                return False, value, "Parent must be an interface in this candidate revision."
            if parent["id"] == interface["id"]:
                return False, value, "An interface cannot be its own parent."
            return True, value, "Syntax accepted; parent is local to this candidate."
        return _syntax_spec("Parent interface", validate_parent)
    if field == "name":
        base = specs[field]
        def validate_name(value):
            ok, normalized, message = field_validators.validate_interface_name(value)
            if ok and normalized.lower() == "vlan200" and _interface_has_auto_addresses(interface):
                return False, value, "VLAN 200 management addressing is static; change AUTO addresses to MANUAL first."
            return ok, normalized, message
        return _syntax_spec(base["label"], validate_name)
    if field == "vlan_id":
        def validate_svi_vlan(value):
            ok, normalized, message = field_validators.validate_vlan_id(value)
            if ok and normalized == 200 and _interface_has_auto_addresses(interface):
                return False, value, "VLAN 200 management addressing is static; change AUTO addresses to MANUAL first."
            return ok, normalized, message
        return _syntax_spec("SVI VLAN", validate_svi_vlan)
    return specs.get(field)


def _address_field_spec(*, revision, interface: dict, address: dict, field: str):
    family = 4 if address.get("family") == "IPV4" else 6
    if field == "family":
        def validate_family(value):
            result = field_validators.validate_enum(
                value, allowed=interface_intent_service.ADDRESS_FAMILIES, label="address family"
            )
            if not result[0] or not address.get("cidr"):
                return result
            wanted = 4 if value == "IPV4" else 6
            cidr_ok, _, cidr_message = field_validators.validate_cidr(address["cidr"], family=wanted)
            if not cidr_ok:
                return False, value, cidr_message
            return result
        return _syntax_spec("Address family", validate_family, module="addressing")
    if field == "cidr":
        def validate_address_cidr(value):
            if address.get("source") == "AUTO" and value not in (None, ""):
                return False, value, "AUTO mode does not accept a manually assigned address; select an IPAM prefix instead."
            return field_validators.validate_cidr(value, family=family)
        return _syntax_spec("Interface CIDR", validate_address_cidr, module="addressing")
    if field == "source":
        def validate_source(value):
            result = field_validators.validate_enum(
                value, allowed=interface_intent_service.ADDRESS_SOURCES, label="address source"
            )
            if result[0] and value == "AUTO" and interface_intent_service.is_management_static(interface):
                return False, value, "Management/VLAN 200 addressing is static and cannot use AUTO mode."
            return result
        return _syntax_spec("Address source", validate_source, module="addressing")
    if field == "role":
        return _syntax_spec(
            "Address role",
            lambda value: field_validators.validate_enum(
                value, allowed=interface_intent_service.ADDRESS_ROLES, label="address role"
            ),
            module="addressing",
        )
    if field == "ipam_prefix":
        return _syntax_spec(
            "IPAM prefix",
            lambda value: field_validators.validate_prefix(value, family=family),
            module="addressing",
        )
    return None


def _wan_field_spec(field: str):
    specs = {
        "state": _syntax_spec(
            "WAN state",
            lambda value: field_validators.validate_enum(
                value, allowed=interface_intent_service.WAN_STATES, label="WAN state"
            ),
            module="wan",
        ),
        "provider_name": _syntax_spec(
            "Provider", lambda value: field_validators.validate_bounded_label(value, label="Provider"), module="wan"
        ),
        "peer_label": _syntax_spec(
            "Peer label", lambda value: field_validators.validate_bounded_label(value, label="Peer label"), module="wan"
        ),
        "peer_ipv4": _syntax_spec(
            "Peer IPv4", lambda value: field_validators.validate_ip_host(value, family=4, label="Peer IPv4"), module="wan"
        ),
        "peer_ipv6": _syntax_spec(
            "Peer IPv6", lambda value: field_validators.validate_ip_host(value, family=6, label="Peer IPv6"), module="wan"
        ),
        "gateway_ipv4": _syntax_spec(
            "Gateway IPv4", lambda value: field_validators.validate_ip_host(value, family=4, label="Gateway IPv4"), module="wan"
        ),
        "gateway_ipv6": _syntax_spec(
            "Gateway IPv6", lambda value: field_validators.validate_ip_host(value, family=6, label="Gateway IPv6"), module="wan"
        ),
        "mtu": _syntax_spec("WAN MTU", field_validators.validate_mtu, module="wan"),
        "description": _syntax_spec("WAN description", field_validators.validate_interface_description, module="wan"),
    }
    return specs.get(field)


_ROUTE_PATH_RE = re.compile(r"^routing\.static_routes\.(route_[0-9a-f]{16})\.([a-z0-9_]+)$")
_RIP_INSTANCE_PATH_RE = re.compile(r"^routing\.rip\.(rip_[0-9a-f]{16})\.([a-z0-9_]+)$")
_RIP_BINDING_PATH_RE = re.compile(r"^routing\.rip\.(rip_[0-9a-f]{16})\.interfaces\.(bind_[0-9a-f]{16})\.([a-z0-9_]+)$")
_OSPF_INSTANCE_PATH_RE = re.compile(r"^routing\.ospf\.(ospf_[0-9a-f]{16})\.([a-z0-9_]+)$")
_OSPF_BINDING_PATH_RE = re.compile(r"^routing\.ospf\.(ospf_[0-9a-f]{16})\.interfaces\.(bind_[0-9a-f]{16})\.([a-z0-9_]+)$")
_OSPF_NETWORK_PATH_RE = re.compile(r"^routing\.ospf\.(ospf_[0-9a-f]{16})\.networks\.(net_[0-9a-f]{16})\.([a-z0-9_]+)$")
_ISIS_INSTANCE_PATH_RE = re.compile(r"^routing\.isis\.(isis_[0-9a-f]{16})\.([a-z0-9_]+)$")
_ISIS_BINDING_PATH_RE = re.compile(r"^routing\.isis\.(isis_[0-9a-f]{16})\.interfaces\.(bind_[0-9a-f]{16})\.([a-z0-9_]+)$")
_EIGRP_INSTANCE_PATH_RE = re.compile(r"^routing\.eigrp\.(eigrp_[0-9a-f]{16})\.([a-z0-9_]+)$")
_EIGRP_BINDING_PATH_RE = re.compile(r"^routing\.eigrp\.(eigrp_[0-9a-f]{16})\.interfaces\.(bind_[0-9a-f]{16})\.([a-z0-9_]+)$")
_BGP_INSTANCE_PATH_RE = re.compile(r"^routing\.bgp\.(bgp_[0-9a-f]{16})\.([a-z0-9_]+)$")
_BGP_NEIGHBOR_PATH_RE = re.compile(r"^routing\.bgp\.(bgp_[0-9a-f]{16})\.neighbors\.(peer_[0-9a-f]{16})\.([a-z0-9_]+)$")
_BGP_NETWORK_PATH_RE = re.compile(r"^routing\.bgp\.(bgp_[0-9a-f]{16})\.networks\.(net_[0-9a-f]{16})\.([a-z0-9_]+)$")

_PHASE12_PATH_RE = re.compile(
    r"^(?:"
    r"fhrp\.instances\.fhrp_[0-9a-f]{16}(?:\.virtual_ips\.vip_[0-9a-f]{16})?|"
    r"nat\.(?:pools\.pool_[0-9a-f]{16}|rules\.nat_[0-9a-f]{16})|"
    r"services\.(?:dhcp\.(?:relays\.dhcp_[0-9a-f]{16}|clients\.dhcp_[0-9a-f]{16})|"
    r"dns\.(?:resolvers\.dns_[0-9a-f]{16}|search_domains\.dns_[0-9a-f]{16}))|"
    r"security\.(?:acls\.acl_[0-9a-f]{16}(?:\.entries\.ace_[0-9a-f]{16})?|attachments\.attach_[0-9a-f]{16})|"
    r"policy\.pbr\.(?:policies\.pbr_[0-9a-f]{16}(?:\.sequences\.pbrseq_[0-9a-f]{16})?|attachments\.attach_[0-9a-f]{16})"
    r")\.[a-z0-9_]+$"
)
_SERVICE_SCALAR_PATHS = {
    "services.dhcp.mode", "services.dns.mode", "services.dns.domain_name", "services.monitoring.mode"
}

_BINDING_PATH_RE_BY_FAMILY = {
    "rip": _RIP_BINDING_PATH_RE,
    "ospf": _OSPF_BINDING_PATH_RE,
    "isis": _ISIS_BINDING_PATH_RE,
    "eigrp": _EIGRP_BINDING_PATH_RE,
}
_INSTANCE_PATH_RE_BY_FAMILY = {
    "rip": _RIP_INSTANCE_PATH_RE,
    "ospf": _OSPF_INSTANCE_PATH_RE,
    "isis": _ISIS_INSTANCE_PATH_RE,
    "eigrp": _EIGRP_INSTANCE_PATH_RE,
}


def _route_field_spec(*, revision, route: dict, field: str):
    family = 4 if route.get("family") == "IPV4" else 6
    if field == "family":
        def validate_family(value):
            result = field_validators.validate_enum(value, allowed=routing_intent_service.ADDRESS_FAMILIES, label="address family")
            if not result[0] or not route.get("destination"):
                return result
            wanted = 4 if value == "IPV4" else 6
            ok, _, message = field_validators.validate_prefix(route["destination"], family=wanted)
            return result if ok else (False, value, message)
        return _syntax_spec("Address family", validate_family, module="routing")
    if field == "destination":
        return _syntax_spec("Destination prefix", lambda value: field_validators.validate_prefix(value, family=family), module="routing")
    if field == "next_hop_type":
        return _syntax_spec(
            "Next-hop type",
            lambda value: field_validators.validate_enum(value, allowed=routing_intent_service.NEXT_HOP_TYPES, label="next-hop type"),
            module="routing",
        )
    if field == "next_hop_address":
        def validate_next_hop_address(value):
            if route.get("next_hop_type") != "ADDRESS" and not value:
                return True, "", "Syntax accepted; project validation pending."
            return field_validators.validate_ip_host(value, family=family, label="Next-hop address")
        return _syntax_spec("Next-hop address", validate_next_hop_address, module="routing")
    if field == "next_hop_interface_id":
        def validate_next_hop_interface(value):
            value = (value or "").strip()
            if route.get("next_hop_type") != "INTERFACE" and not value:
                return True, "", "Syntax accepted; project validation pending."
            if not value:
                return False, value, "A candidate-owned exit interface is required."
            try:
                interface_intent_service.get_interface(revision, value)
            except interface_intent_service.CollectionOwnershipError:
                return False, value, "Exit interface must belong to this candidate revision."
            return True, value, "Syntax accepted; project validation pending."
        return _syntax_spec("Exit interface", validate_next_hop_interface, module="routing")
    if field == "distance":
        return _syntax_spec("Administrative distance", field_validators.validate_distance, module="routing")
    if field == "description":
        return _syntax_spec("Description", field_validators.validate_interface_description, module="routing")
    if field == "tag":
        return _syntax_spec(
            "Tag", lambda value: field_validators.validate_optional_integer(value, minimum=0, maximum=4294967295, label="Tag"), module="routing"
        )
    if field == "enabled":
        return _syntax_spec("Enabled", lambda value: field_validators.validate_bool(value, label="Enabled"), module="routing")
    return None


def _instance_field_spec(*, family: str, instance: dict, field: str):
    if family == "rip":
        if field == "address_family":
            return _syntax_spec(
                "Address family",
                lambda value: field_validators.validate_enum(value, allowed=routing_intent_service.ADDRESS_FAMILIES, label="RIP address family"),
                module="routing",
            )
        if field == "enabled":
            return _syntax_spec("Enabled", lambda value: field_validators.validate_bool(value, label="Enabled"), module="routing")
    if family == "ospf":
        if field == "version":
            return _syntax_spec(
                "Version",
                lambda value: field_validators.validate_enum(value, allowed=routing_intent_service.OSPF_VERSIONS, label="OSPF version"),
                module="routing",
            )
        if field == "process_id":
            return _syntax_spec(
                "Process ID",
                lambda value: field_validators.validate_optional_integer(value, minimum=1, maximum=65535, label="Process ID"),
                module="routing",
            )
        if field == "router_id":
            return _syntax_spec("Router ID", field_validators.validate_router_id, module="routing")
        if field == "reference_bandwidth":
            return _syntax_spec(
                "Reference bandwidth (Mbps)",
                lambda value: field_validators.validate_optional_integer(value, minimum=1, maximum=4294967, label="Reference bandwidth"),
                module="routing",
            )
    if family == "isis":
        if field == "net":
            return _syntax_spec("NET", field_validators.validate_isis_net, module="routing")
        if field == "level":
            return _syntax_spec(
                "Level",
                lambda value: field_validators.validate_enum(value, allowed=routing_intent_service.ISIS_LEVELS, label="IS-IS level"),
                module="routing",
            )
        if field in ("address_family_ipv4", "address_family_ipv6"):
            return _syntax_spec("Address family", lambda value: field_validators.validate_bool(value, label="Address family"), module="routing")
    if family == "eigrp":
        if field == "asn":
            return _syntax_spec(
                "AS number", lambda value: field_validators.validate_optional_integer(value, minimum=1, maximum=65535, label="EIGRP AS number"), module="routing"
            )
        if field == "router_id":
            return _syntax_spec("Router ID", field_validators.validate_router_id, module="routing")
        if field == "address_family":
            return _syntax_spec(
                "Address family",
                lambda value: field_validators.validate_enum(value, allowed=routing_intent_service.ADDRESS_FAMILIES, label="EIGRP address family"),
                module="routing",
            )
    if family == "bgp":
        if field == "local_asn":
            return _syntax_spec("Local ASN", field_validators.validate_as_number, module="routing")
        if field == "router_id":
            return _syntax_spec("Router ID", field_validators.validate_router_id, module="routing")
    return None


def _binding_field_spec(*, family: str, field: str):
    if field == "passive":
        return _syntax_spec("Passive", lambda value: field_validators.validate_bool(value, label="Passive"), module="routing")
    if family == "ospf":
        if field == "area":
            return _syntax_spec("Area", field_validators.validate_area_id, module="routing")
        if field == "cost":
            return _syntax_spec("Cost", lambda value: field_validators.validate_metric(value, minimum=1, maximum=65535, label="Cost"), module="routing")
        if field == "network_type":
            return _syntax_spec(
                "Network type",
                lambda value: field_validators.validate_enum(value or "", allowed=routing_intent_service.NETWORK_TYPES, label="network type"),
                module="routing",
            )
        if field == "hello_interval":
            return _syntax_spec(
                "Hello interval", lambda value: field_validators.validate_metric(value, minimum=1, maximum=65535, label="Hello interval"), module="routing"
            )
        if field == "dead_interval":
            return _syntax_spec(
                "Dead interval", lambda value: field_validators.validate_metric(value, minimum=1, maximum=65535, label="Dead interval"), module="routing"
            )
        if field == "priority":
            return _syntax_spec("Priority", lambda value: field_validators.validate_metric(value, minimum=0, maximum=255, label="Priority"), module="routing")
    if family == "isis" and field == "metric":
        return _syntax_spec("Metric", lambda value: field_validators.validate_metric(value, minimum=1, maximum=16777215, label="Metric"), module="routing")
    return None


def _bgp_neighbor_field_spec(*, revision, neighbor: dict, field: str):
    family = 4 if neighbor.get("family") == "IPV4" else 6
    if field == "family":
        def validate_family(value):
            result = field_validators.validate_enum(value, allowed=routing_intent_service.ADDRESS_FAMILIES, label="peer address family")
            if not result[0] or not neighbor.get("peer_address"):
                return result
            wanted = 4 if value == "IPV4" else 6
            ok, _, message = field_validators.validate_ip_host(neighbor["peer_address"], family=wanted, label="Peer address")
            return result if ok else (False, value, message)
        return _syntax_spec("Peer address family", validate_family, module="routing")
    if field == "peer_address":
        return _syntax_spec("Peer address", lambda value: field_validators.validate_ip_host(value, family=family, label="Peer address"), module="routing")
    if field == "remote_asn":
        return _syntax_spec("Remote ASN", field_validators.validate_as_number, module="routing")
    if field == "description":
        return _syntax_spec("Description", field_validators.validate_interface_description, module="routing")
    if field in ("activate_ipv4", "activate_ipv6", "next_hop_self", "route_reflector_client", "shutdown"):
        label = field.replace("_", " ").title()
        return _syntax_spec(label, lambda value: field_validators.validate_bool(value, label=label), module="routing")
    if field == "update_source_interface_id":
        def validate_update_source(value):
            value = (value or "").strip()
            if not value:
                return True, "", "Syntax accepted; project validation pending."
            try:
                interface_intent_service.get_interface(revision, value)
            except interface_intent_service.CollectionOwnershipError:
                return False, value, "Update-source must be an interface in this candidate revision."
            return True, value, "Syntax accepted; project validation pending."
        return _syntax_spec("Update source", validate_update_source, module="routing")
    if field == "ebgp_multihop":
        return _syntax_spec(
            "eBGP multihop", lambda value: field_validators.validate_metric(value, minimum=1, maximum=255, label="eBGP multihop"), module="routing"
        )
    if field == "password_ref":
        return _syntax_spec("Authentication reference", field_validators.validate_secret_ref, module="routing")
    return None


def _bgp_network_field_spec(*, network: dict, field: str):
    family = 4 if network.get("family") == "IPV4" else 6
    if field == "family":
        return _syntax_spec(
            "Address family",
            lambda value: field_validators.validate_enum(value, allowed=routing_intent_service.ADDRESS_FAMILIES, label="network address family"),
            module="routing",
        )
    if field == "cidr":
        return _syntax_spec("Network CIDR", lambda value: field_validators.validate_prefix(value, family=family), module="routing")
    return None


def _ospf_network_field_spec(*, field: str):
    if field == "prefix":
        return _syntax_spec("OSPF network prefix", lambda value: field_validators.validate_prefix(value, family=4), module="routing")
    if field == "area":
        return _syntax_spec("OSPF area", field_validators.validate_area_id, module="routing")
    return None


def _owned_interface_validator(revision, label):
    def validate(value):
        value = (value or "").strip()
        if not value:
            return True, "", "Syntax accepted; project validation pending."
        try:
            interface_intent_service.get_interface(revision, value)
        except interface_intent_service.CollectionOwnershipError:
            return False, value, f"{label} must belong to this candidate revision."
        return True, value, "Syntax accepted; project validation pending."
    return validate


def _phase12_address_validator(obj, field, *, family_key="family", required=False):
    family_value = obj.get(family_key)
    if family_value == "IPV4":
        family = 4
    elif family_value in ("IPV6", "NAT66", "NPTV6"):
        family = 6
    elif family_value in ("NAT64", "NAT_PT"):
        family = 6 if field == "original_source" else 4
    else:
        family = 4

    def validate(value):
        result = field_validators.validate_ip_or_prefix(
            value, family=family, required=required, label=field.replace("_", " ").title()
        )
        if not result[0] or family_value != "NPTV6" or not result[1]:
            return result
        if "/" not in result[1]:
            return False, value, "NPTv6 requires an IPv6 prefix, not a host address."
        other_field = "translated_source" if field == "original_source" else "original_source"
        other = obj.get(other_field)
        if other:
            try:
                if ipaddress.ip_network(result[1]).prefixlen != ipaddress.ip_network(other).prefixlen:
                    return False, value, "NPTv6 inside and outside prefixes must have equal prefix lengths."
            except ValueError:
                pass
        return result
    return validate


def _phase12_field_spec(path: str, *, revision):
    if path not in _SERVICE_SCALAR_PATHS and not _PHASE12_PATH_RE.fullmatch(path):
        return None
    sections = service_policy_intent_service._sections(revision)
    target, field = service_policy_intent_service._field_target(sections, path)
    if target is None or field is None:
        known_fields = set().union(
            service_policy_intent_service.FHRP_FIELDS,
            service_policy_intent_service.FHRP_VIP_FIELDS,
            service_policy_intent_service.NAT_POOL_FIELDS,
            service_policy_intent_service.NAT_RULE_FIELDS,
            service_policy_intent_service.DHCP_RELAY_FIELDS,
            service_policy_intent_service.DHCP_CLIENT_FIELDS,
            service_policy_intent_service.DNS_RESOLVER_FIELDS,
            service_policy_intent_service.DNS_DOMAIN_FIELDS,
            service_policy_intent_service.ACL_FIELDS,
            service_policy_intent_service.ACE_FIELDS,
            service_policy_intent_service.ACL_ATTACHMENT_FIELDS,
            service_policy_intent_service.PBR_POLICY_FIELDS,
            service_policy_intent_service.PBR_SEQUENCE_FIELDS,
            service_policy_intent_service.PBR_ATTACHMENT_FIELDS,
        )
        if path.split(".")[-1] not in known_fields:
            return None
        raise service_policy_intent_service.CollectionOwnershipError(
            "Phase-12 object ID does not belong to this candidate revision."
        )
    parts = path.split(".")

    if path.endswith(".mode") and parts[0] == "services":
        return _syntax_spec(
            "Inheritance mode",
            lambda value: field_validators.validate_enum(
                value, allowed=service_policy_intent_service.INHERITANCE_MODES, label="inheritance mode"
            ), module="services",
        )
    if path == "services.dns.domain_name":
        return _syntax_spec("Domain name", field_validators.validate_domain_name, module="services")

    if parts[0] == "fhrp":
        instance = sections["fhrp"]["instances"].get(parts[2], {})
        family = 4 if instance.get("address_family") == "IPV4" else 6
        if "virtual_ips" in parts:
            return _syntax_spec("Virtual IP", lambda value: field_validators.validate_ip_host(value, family=family, label="Virtual IP"), module="fhrp")
        specs = {
            "protocol": lambda v: field_validators.validate_enum(v, allowed=service_policy_intent_service.FHRP_PROTOCOLS, label="FHRP protocol"),
            "interface_id": _owned_interface_validator(revision, "FHRP interface"),
            "address_family": lambda v: field_validators.validate_enum(v, allowed=service_policy_intent_service.ADDRESS_FAMILIES, label="address family"),
            "group_id": lambda v: field_validators.validate_optional_integer(v, minimum=0, maximum=4095, label="FHRP group/virtual-router ID"),
            "priority": lambda v: field_validators.validate_optional_integer(v, minimum=0, maximum=255, label="FHRP priority"),
            "preempt": lambda v: field_validators.validate_bool(v, label="Preempt"),
            "preempt_delay": lambda v: field_validators.validate_optional_integer(v, minimum=0, maximum=3600, label="Preempt delay"),
            "hello_timer": lambda v: field_validators.validate_optional_integer(v, minimum=1, maximum=255, label="Hello timer"),
            "hold_timer": lambda v: field_validators.validate_optional_integer(v, minimum=1, maximum=255, label="Hold timer"),
            "virtual_mac": field_validators.validate_mac_address,
            "auth_secret_ref": field_validators.validate_secret_ref,
            "description": field_validators.validate_interface_description,
        }
        validator = specs.get(field)
        return _syntax_spec(field.replace("_", " ").title(), validator, module="fhrp") if validator else None

    if parts[:2] == ["nat", "pools"]:
        family = 6 if target.get("family") in ("NAT66", "NPTV6") else 4
        specs = {
            "name": field_validators.validate_acl_name,
            "family": lambda v: field_validators.validate_enum(v, allowed=service_policy_intent_service.NAT_FAMILIES, label="NAT family"),
            "start_address": lambda v: field_validators.validate_ip_host(v, family=family, label="Pool start"),
            "end_address": lambda v: field_validators.validate_ip_host(v, family=family, label="Pool end"),
            "prefix_length": lambda v: field_validators.validate_optional_integer(v, minimum=0, maximum=128 if family == 6 else 32, label="Prefix length"),
            "description": field_validators.validate_interface_description,
        }
        return _syntax_spec(field.replace("_", " ").title(), specs.get(field), module="nat") if specs.get(field) else None

    if parts[:2] == ["nat", "rules"]:
        specs = {
            "family": lambda v: field_validators.validate_enum(v, allowed=service_policy_intent_service.NAT_FAMILIES, label="NAT family"),
            "mode": lambda v: field_validators.validate_enum(v, allowed=service_policy_intent_service.NAT_MODES, label="NAT mode"),
            "original_source": _phase12_address_validator(target, "original_source"),
            "translated_source": _phase12_address_validator(target, "translated_source"),
            "protocol": lambda v: field_validators.validate_enum(v, allowed=("IP", "TCP", "UDP", "ICMP"), label="NAT protocol"),
            "original_port": field_validators.validate_port_spec,
            "translated_port": field_validators.validate_port_spec,
            "inside_interface_id": _owned_interface_validator(revision, "Inside interface"),
            "outside_interface_id": _owned_interface_validator(revision, "Outside interface"),
            "description": field_validators.validate_interface_description,
            "enabled": lambda v: field_validators.validate_bool(v, label="Enabled"),
        }
        if field == "pool_id":
            def validate_pool(value):
                value = (value or "").strip()
                if not value:
                    return True, "", "Syntax accepted; project validation pending."
                try:
                    service_policy_intent_service.get_nat_pool(revision, value)
                except service_policy_intent_service.CollectionOwnershipError:
                    return False, value, "NAT pool must belong to this candidate revision."
                return True, value, "Syntax accepted; project validation pending."
            return _syntax_spec("NAT pool", validate_pool, module="nat")
        validator = specs.get(field)
        return _syntax_spec(field.replace("_", " ").title(), validator, module="nat") if validator else None

    if parts[:3] in (["services", "dhcp", "relays"], ["services", "dhcp", "clients"]):
        family = 4 if target.get("family") == "IPV4" else 6
        specs = {
            "family": lambda v: field_validators.validate_enum(v, allowed=service_policy_intent_service.ADDRESS_FAMILIES, label="address family"),
            "interface_id": _owned_interface_validator(revision, "Service interface"),
            "destination": lambda v: field_validators.validate_ip_host(v, family=family, label="Relay destination"),
            "description": field_validators.validate_interface_description,
        }
        return _syntax_spec(field.replace("_", " ").title(), specs.get(field), module="services") if specs.get(field) else None

    if parts[:3] == ["services", "dns", "resolvers"]:
        family = 4 if target.get("family") == "IPV4" else 6
        specs = {
            "family": lambda v: field_validators.validate_enum(v, allowed=service_policy_intent_service.ADDRESS_FAMILIES, label="resolver family"),
            "address": lambda v: field_validators.validate_ip_host(v, family=family, label="Resolver"),
        }
        return _syntax_spec(field.title(), specs.get(field), module="services") if specs.get(field) else None
    if parts[:3] == ["services", "dns", "search_domains"]:
        return _syntax_spec("Search domain", lambda v: field_validators.validate_domain_name(v, required=True), module="services") if field == "domain" else None

    if parts[:2] == ["security", "acls"] and "entries" not in parts:
        specs = {
            "name": field_validators.validate_acl_name,
            "family": lambda v: field_validators.validate_enum(v, allowed=service_policy_intent_service.ACL_FAMILIES, label="ACL family"),
            "acl_type": lambda v: field_validators.validate_enum(v, allowed=service_policy_intent_service.ACL_TYPES, label="ACL type"),
            "description": field_validators.validate_interface_description,
        }
        return _syntax_spec(field.replace("_", " ").title(), specs.get(field), module="security") if specs.get(field) else None

    if parts[:2] == ["security", "acls"] and "entries" in parts:
        acl = sections["security"]["acls"].get(parts[2], {})
        family = 4 if acl.get("family") == "IPV4" else 6
        protocol = target.get("protocol")
        def match_value(value):
            match_type = target.get("source_type") if field == "source_value" else target.get("destination_type")
            if match_type == "ANY":
                return (True, "", "Syntax accepted; traffic-impact validation pending.") if not value else (False, value, "ANY match must not carry an address value.")
            if match_type == "HOST":
                return field_validators.validate_ip_host(value, family=family, label="ACL host")
            return field_validators.validate_prefix(value, family=family)
        def port(value):
            if protocol not in ("TCP", "UDP") and value not in (None, ""):
                return False, value, "Ports are only valid for TCP or UDP entries."
            return field_validators.validate_port_spec(value)
        specs = {
            "sequence": lambda v: field_validators.validate_optional_integer(v, minimum=1, maximum=4294967295, label="ACE sequence"),
            "action": lambda v: field_validators.validate_enum(v, allowed=service_policy_intent_service.ACL_ACTIONS, label="ACL action"),
            "protocol": lambda v: field_validators.validate_enum(v, allowed=service_policy_intent_service.ACL_PROTOCOLS, label="ACL protocol"),
            "source_type": lambda v: field_validators.validate_enum(v, allowed=service_policy_intent_service.MATCH_TYPES, label="source match type"),
            "destination_type": lambda v: field_validators.validate_enum(v, allowed=service_policy_intent_service.MATCH_TYPES, label="destination match type"),
            "source_value": match_value, "destination_value": match_value,
            "source_port": port, "destination_port": port,
            "description": field_validators.validate_interface_description,
            "logging": lambda v: field_validators.validate_bool(v, label="Logging"),
        }
        return _syntax_spec(field.replace("_", " ").title(), specs.get(field), module="security") if specs.get(field) else None

    if parts[:2] == ["security", "attachments"]:
        def acl_ref(value):
            try:
                service_policy_intent_service.get_acl(revision, (value or "").strip())
            except service_policy_intent_service.CollectionOwnershipError:
                return False, value, "ACL must belong to this candidate revision."
            return True, value, "Syntax accepted; traffic-impact validation pending."
        specs = {"acl_id": acl_ref, "interface_id": _owned_interface_validator(revision, "ACL interface"),
                 "direction": lambda v: field_validators.validate_enum(v, allowed=service_policy_intent_service.DIRECTIONS, label="ACL direction")}
        return _syntax_spec(field.replace("_", " ").title(), specs.get(field), module="security") if specs.get(field) else None

    if parts[:3] == ["policy", "pbr", "policies"] and "sequences" not in parts:
        specs = {"name": field_validators.validate_acl_name,
                 "family": lambda v: field_validators.validate_enum(v, allowed=service_policy_intent_service.ADDRESS_FAMILIES, label="PBR family"),
                 "description": field_validators.validate_interface_description}
        return _syntax_spec(field.title(), specs.get(field), module="policy") if specs.get(field) else None

    if parts[:3] == ["policy", "pbr", "policies"] and "sequences" in parts:
        policy = sections["policy"]["pbr"]["policies"].get(parts[3], {})
        family = 4 if policy.get("family") == "IPV4" else 6
        specs = {
            "sequence": lambda v: field_validators.validate_optional_integer(v, minimum=1, maximum=65535, label="PBR sequence"),
            "source_prefix": lambda v: field_validators.validate_prefix(v, family=family),
            "destination_prefix": lambda v: field_validators.validate_prefix(v, family=family),
            "protocol": lambda v: field_validators.validate_enum(v, allowed=service_policy_intent_service.ACL_PROTOCOLS, label="PBR protocol"),
            "next_hop": lambda v: field_validators.validate_ip_host(v, family=family, label="PBR next hop"),
            "output_interface_id": _owned_interface_validator(revision, "PBR output interface"),
            "description": field_validators.validate_interface_description,
        }
        return _syntax_spec(field.replace("_", " ").title(), specs.get(field), module="policy") if specs.get(field) else None

    if parts[:3] == ["policy", "pbr", "attachments"]:
        def policy_ref(value):
            try:
                service_policy_intent_service.get_pbr_policy(revision, (value or "").strip())
            except service_policy_intent_service.CollectionOwnershipError:
                return False, value, "PBR policy must belong to this candidate revision."
            return True, value, "Syntax accepted; project validation pending."
        specs = {"policy_id": policy_ref, "interface_id": _owned_interface_validator(revision, "PBR interface"),
                 "direction": lambda v: field_validators.validate_enum(v, allowed=("IN",), label="PBR direction")}
        return _syntax_spec(field.replace("_", " ").title(), specs.get(field), module="policy") if specs.get(field) else None
    return None


def resolve_field_spec(path: str, *, revision=None):
    """Resolve a static field or a candidate-owned dynamic collection path.

    The regexes are intentionally strict and every extracted object ID is
    looked up inside the supplied revision.  This is not a generic JSON-path
    mutator and never accepts arbitrary attributes.
    """
    if path in FIELD_REGISTRY:
        return FIELD_REGISTRY[path]
    if revision is None or not isinstance(path, str):
        return None

    phase12_spec = _phase12_field_spec(path, revision=revision)
    if phase12_spec is not None:
        return phase12_spec

    match = _INTERFACE_PATH_RE.fullmatch(path)
    if match:
        interface = interface_intent_service.get_interface(revision, match.group(1))
        return _interface_field_spec(revision=revision, interface=interface, field=match.group(2))
    match = _ADDRESS_PATH_RE.fullmatch(path)
    if match:
        interface = interface_intent_service.get_interface(revision, match.group(1))
        address = interface_intent_service.get_address(revision, match.group(1), match.group(2))
        return _address_field_spec(
            revision=revision, interface=interface, address=address, field=match.group(3)
        )
    match = _WAN_PATH_RE.fullmatch(path)
    if match:
        interface_intent_service.get_interface(revision, match.group(1))
        return _wan_field_spec(match.group(2))

    match = _ROUTE_PATH_RE.fullmatch(path)
    if match:
        route = routing_intent_service.get_static_route(revision, match.group(1))
        return _route_field_spec(revision=revision, route=route, field=match.group(2))

    for family, binding_re in _BINDING_PATH_RE_BY_FAMILY.items():
        match = binding_re.fullmatch(path)
        if match:
            routing_intent_service.get_interface_binding(revision, family, match.group(1), match.group(2))
            return _binding_field_spec(family=family, field=match.group(3))

    for family, instance_re in _INSTANCE_PATH_RE_BY_FAMILY.items():
        match = instance_re.fullmatch(path)
        if match:
            instance = routing_intent_service.get_protocol_instance(revision, family, match.group(1))
            return _instance_field_spec(family=family, instance=instance, field=match.group(2))

    match = _OSPF_NETWORK_PATH_RE.fullmatch(path)
    if match:
        routing_intent_service.get_ospf_network(revision, match.group(1), match.group(2))
        return _ospf_network_field_spec(field=match.group(3))

    match = _BGP_NEIGHBOR_PATH_RE.fullmatch(path)
    if match:
        neighbor = routing_intent_service.get_bgp_neighbor(revision, match.group(1), match.group(2))
        return _bgp_neighbor_field_spec(revision=revision, neighbor=neighbor, field=match.group(3))
    match = _BGP_NETWORK_PATH_RE.fullmatch(path)
    if match:
        network = routing_intent_service.get_bgp_network(revision, match.group(1), match.group(2))
        return _bgp_network_field_spec(network=network, field=match.group(3))
    match = _BGP_INSTANCE_PATH_RE.fullmatch(path)
    if match:
        instance = routing_intent_service.get_protocol_instance(revision, "bgp", match.group(1))
        return _instance_field_spec(family="bgp", instance=instance, field=match.group(2))

    return None
