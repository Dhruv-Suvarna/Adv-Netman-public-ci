"""Structured Phase-11 routing intent collection service.

Mirrors interface_intent_service.py's contract exactly: every mutation is
DRAFT-only, bounded, ownership-checked, application-state-only, and lives in
``DeviceIntentRevision.sections["routing"]`` next to the existing
``sections["interfaces"]`` namespace (never a new model, never a migration).
Stable opaque IDs -- never list position -- are the field-path identity.

Six sub-namespaces, one per protocol family: ``static_routes``, ``rip``,
``ospf``, ``isis``, ``eigrp``, ``bgp``. RIP/OSPF/IS-IS/EIGRP share an
"instance + candidate-owned interface bindings" shape and are handled by one
generic set of functions; BGP's shape (neighbors + network advertisements)
is different enough to warrant its own functions. Static routes have no
instance concept at all -- they are a flat, bounded collection.

Every routing object that references an interface (a static route's exit
interface, a protocol's interface binding, a BGP neighbor's update-source)
stores the interface's stable ID and is validated against
``interface_intent_service.get_interface()`` -- never a display name -- so a
later interface rename never breaks routing intent, and an ID from another
candidate revision is always rejected.
"""

from __future__ import annotations

from copy import deepcopy
from uuid import uuid4

from django.db import transaction

from .. import models
from . import field_validators, intent_service, interface_intent_service, platform_drivers
from .interface_intent_service import (
    CollectionLimitError,
    CollectionMutationError,
    CollectionOwnershipError,
    DraftOnlyError,
    require_draft,
)

MAX_STATIC_ROUTES_PER_REVISION = 64
MAX_PROTOCOL_INSTANCES_PER_FAMILY = 4
MAX_INTERFACE_BINDINGS_PER_INSTANCE = 64
MAX_BGP_NEIGHBORS_PER_INSTANCE = 32
MAX_BGP_NETWORKS_PER_INSTANCE = 64
MAX_OSPF_NETWORKS_PER_INSTANCE = 64

ADDRESS_FAMILIES = ("IPV4", "IPV6")
OSPF_VERSIONS = ("OSPFV2", "OSPFV3")
ISIS_LEVELS = ("LEVEL_1", "LEVEL_2", "LEVEL_1_2")
NEXT_HOP_TYPES = ("ADDRESS", "INTERFACE")
NETWORK_TYPES = ("", "BROADCAST", "POINT_TO_POINT")

PROTOCOL_FAMILIES = ("static_routes", "rip", "ospf", "isis", "eigrp", "bgp")
INSTANCE_FAMILIES = ("rip", "ospf", "isis", "eigrp", "bgp")
BINDING_FAMILIES = ("rip", "ospf", "isis", "eigrp")

ID_PREFIX = {"static_routes": "route", "rip": "rip", "ospf": "ospf", "isis": "isis", "eigrp": "eigrp", "bgp": "bgp"}

STATIC_ROUTE_FIELDS = (
    "family", "destination", "next_hop_type", "next_hop_address",
    "next_hop_interface_id", "distance", "description", "tag", "enabled",
)
INSTANCE_FIELDS = {
    "rip": ("address_family", "enabled"),
    "ospf": ("version", "process_id", "router_id", "reference_bandwidth"),
    "isis": ("net", "level", "address_family_ipv4", "address_family_ipv6"),
    "eigrp": ("asn", "router_id", "address_family"),
    "bgp": ("local_asn", "router_id"),
}
BINDING_FIELDS = {
    "rip": ("passive",),
    "ospf": ("area", "passive", "cost", "network_type", "hello_interval", "dead_interval", "priority"),
    "isis": ("passive", "metric"),
    "eigrp": ("passive",),
}
BGP_NEIGHBOR_FIELDS = (
    "peer_address", "family", "remote_asn", "description",
    "activate_ipv4", "activate_ipv6", "update_source_interface_id",
    "ebgp_multihop", "next_hop_self", "route_reflector_client", "shutdown", "password_ref",
)
BGP_NETWORK_FIELDS = ("family", "cidr")
OSPF_NETWORK_FIELDS = ("prefix", "area")


def _new_id(prefix: str) -> str:
    return f"{prefix}_{uuid4().hex[:16]}"


def _routing_sections(revision: models.DeviceIntentRevision) -> dict:
    sections = deepcopy(revision.sections or {})
    routing = sections.get("routing")
    if not isinstance(routing, dict):
        routing = {}
    for family in PROTOCOL_FAMILIES:
        if not isinstance(routing.get(family), dict):
            routing[family] = {}
    sections["routing"] = routing
    return sections


def routing_map(revision: models.DeviceIntentRevision) -> dict:
    return _routing_sections(revision)["routing"]


def _next_sequence(collection: dict) -> int:
    return max((int(item.get("sequence") or 0) for item in collection.values()), default=0) + 1


def _seed_state(revision, path: str, value) -> None:
    intent_service.set_draft_field(revision=revision, path=path, draft_value=value)
    intent_service.accept_field_value(revision=revision, path=path)


def ordered_collection(mapping: dict) -> list[dict]:
    return sorted(mapping.values(), key=lambda row: (int(row.get("sequence") or 0), row.get("id", "")))


def ordered_static_routes(revision) -> list[dict]:
    return ordered_collection(routing_map(revision)["static_routes"])


def ordered_instances(revision, family: str) -> list[dict]:
    return ordered_collection(routing_map(revision)[family])


# --- path builders --------------------------------------------------------

def _route_path(route_id: str, field: str) -> str:
    return f"routing.static_routes.{route_id}.{field}"


def _instance_path(family: str, instance_id: str, field: str) -> str:
    return f"routing.{family}.{instance_id}.{field}"


def _binding_path(family: str, instance_id: str, binding_id: str, field: str) -> str:
    return f"routing.{family}.{instance_id}.interfaces.{binding_id}.{field}"


def _bgp_neighbor_path(instance_id: str, peer_id: str, field: str) -> str:
    return f"routing.bgp.{instance_id}.neighbors.{peer_id}.{field}"


def _bgp_network_path(instance_id: str, net_id: str, field: str) -> str:
    return f"routing.bgp.{instance_id}.networks.{net_id}.{field}"


def _ospf_network_path(instance_id: str, net_id: str, field: str) -> str:
    return f"routing.ospf.{instance_id}.networks.{net_id}.{field}"


# --- ownership lookups (raise CollectionOwnershipError, never KeyError) ---

def get_static_route(revision, route_id: str) -> dict:
    route = routing_map(revision)["static_routes"].get(route_id)
    if not route or route.get("id") != route_id:
        raise CollectionOwnershipError("Static route ID does not belong to this candidate revision.")
    return route


def get_protocol_instance(revision, family: str, instance_id: str) -> dict:
    if family not in INSTANCE_FAMILIES:
        raise CollectionOwnershipError("Unknown routing protocol family.")
    instance = routing_map(revision)[family].get(instance_id)
    if not instance or instance.get("id") != instance_id:
        raise CollectionOwnershipError("Routing instance ID does not belong to this candidate revision.")
    return instance


def get_interface_binding(revision, family: str, instance_id: str, binding_id: str) -> dict:
    instance = get_protocol_instance(revision, family, instance_id)
    binding = (instance.get("interfaces") or {}).get(binding_id)
    if not binding or binding.get("id") != binding_id:
        raise CollectionOwnershipError("Interface binding ID does not belong to this candidate instance.")
    return binding


def get_bgp_neighbor(revision, instance_id: str, peer_id: str) -> dict:
    instance = get_protocol_instance(revision, "bgp", instance_id)
    neighbor = (instance.get("neighbors") or {}).get(peer_id)
    if not neighbor or neighbor.get("id") != peer_id:
        raise CollectionOwnershipError("BGP neighbor ID does not belong to this candidate instance.")
    return neighbor


def get_bgp_network(revision, instance_id: str, net_id: str) -> dict:
    instance = get_protocol_instance(revision, "bgp", instance_id)
    network = (instance.get("networks") or {}).get(net_id)
    if not network or network.get("id") != net_id:
        raise CollectionOwnershipError("BGP network advertisement ID does not belong to this candidate instance.")
    return network


def get_ospf_network(revision, instance_id: str, net_id: str) -> dict:
    instance = get_protocol_instance(revision, "ospf", instance_id)
    network = (instance.get("networks") or {}).get(net_id)
    if not network or network.get("id") != net_id:
        raise CollectionOwnershipError("OSPF network statement ID does not belong to this candidate instance.")
    return network


# --- capability helpers ----------------------------------------------------

def _routing_protocol_for(family: str, fields: dict) -> platform_drivers.RoutingProtocol:
    if family == "rip":
        return (
            platform_drivers.RoutingProtocol.RIPV2
            if fields.get("address_family") == "IPV4"
            else platform_drivers.RoutingProtocol.RIPNG
        )
    if family == "ospf":
        return (
            platform_drivers.RoutingProtocol.OSPFV2
            if fields.get("version") == "OSPFV2"
            else platform_drivers.RoutingProtocol.OSPFV3
        )
    if family == "isis":
        return platform_drivers.RoutingProtocol.ISIS
    if family == "eigrp":
        return (
            platform_drivers.RoutingProtocol.EIGRP_IPV4
            if fields.get("address_family") == "IPV4"
            else platform_drivers.RoutingProtocol.EIGRP_IPV6
        )
    raise ValueError(f"{family!r} has no single routing protocol (use BGP-specific capability checks).")


def _static_route_protocol(family: str) -> platform_drivers.RoutingProtocol:
    return platform_drivers.RoutingProtocol.STATIC_IPV4 if family == "IPV4" else platform_drivers.RoutingProtocol.STATIC_IPV6


def _bgp_protocol(family: str) -> platform_drivers.RoutingProtocol:
    return platform_drivers.RoutingProtocol.BGP_IPV4 if family == "IPV4" else platform_drivers.RoutingProtocol.BGP_IPV6


def _bgp_selectable(platform: str) -> bool:
    return platform_drivers.is_routing_protocol_selectable(
        platform, platform_drivers.RoutingProtocol.BGP_IPV4
    ) or platform_drivers.is_routing_protocol_selectable(platform, platform_drivers.RoutingProtocol.BGP_IPV6)


# --- static routes ----------------------------------------------------------

@transaction.atomic
def add_static_route(*, revision: models.DeviceIntentRevision, family: str = "IPV4") -> dict:
    require_draft(revision)
    if family not in ADDRESS_FAMILIES:
        raise CollectionMutationError("Unknown address family.")
    platform = revision.device_intent.platform
    if not platform_drivers.is_routing_protocol_selectable(platform, _static_route_protocol(family)):
        raise CollectionMutationError("Static routing for that address family is not implemented for the selected platform.")

    sections = _routing_sections(revision)
    routes = sections["routing"]["static_routes"]
    if len(routes) >= MAX_STATIC_ROUTES_PER_REVISION:
        raise CollectionLimitError(f"A candidate may contain at most {MAX_STATIC_ROUTES_PER_REVISION} static routes.")

    route_id = _new_id("route")
    route = {
        "id": route_id,
        "sequence": _next_sequence(routes),
        "family": family,
        "destination": "",
        "next_hop_type": "ADDRESS",
        "next_hop_address": "",
        "next_hop_interface_id": "",
        "distance": None,
        "description": "",
        "tag": None,
        "enabled": True,
    }
    routes[route_id] = route
    revision.sections = sections
    revision.save(update_fields=["sections"])
    for field in STATIC_ROUTE_FIELDS:
        _seed_state(revision, _route_path(route_id, field), route[field])
    return route


@transaction.atomic
def remove_static_route(*, revision: models.DeviceIntentRevision, route_id: str, confirmation: str) -> None:
    require_draft(revision)
    get_static_route(revision, route_id)
    if confirmation != "REMOVE":
        raise CollectionMutationError("Explicit REMOVE confirmation is required.")
    sections = _routing_sections(revision)
    del sections["routing"]["static_routes"][route_id]
    revision.sections = sections
    revision.save(update_fields=["sections"])
    revision.field_states.filter(path__startswith=f"routing.static_routes.{route_id}.").delete()


# --- protocol instances (RIP / OSPF / IS-IS / EIGRP / BGP) -----------------

def _instance_defaults(family: str, kwargs: dict) -> dict:
    if family == "rip":
        address_family = kwargs.get("address_family") or "IPV4"
        if address_family not in ADDRESS_FAMILIES:
            raise CollectionMutationError("Unknown RIP address family.")
        return {"address_family": address_family, "enabled": True}
    if family == "ospf":
        version = kwargs.get("version") or "OSPFV2"
        if version not in OSPF_VERSIONS:
            raise CollectionMutationError("Unknown OSPF version.")
        return {"version": version, "process_id": None, "router_id": "", "reference_bandwidth": None}
    if family == "isis":
        return {"net": "", "level": "LEVEL_2", "address_family_ipv4": True, "address_family_ipv6": False}
    if family == "eigrp":
        address_family = kwargs.get("address_family") or "IPV4"
        if address_family not in ADDRESS_FAMILIES:
            raise CollectionMutationError("Unknown EIGRP address family.")
        return {"asn": None, "router_id": "", "address_family": address_family}
    if family == "bgp":
        raw_asn = kwargs.get("local_asn")
        if raw_asn in (None, ""):
            raise CollectionMutationError("Local ASN is required to create a BGP instance.")
        ok, normalized, message = field_validators.validate_as_number(raw_asn)
        if not ok:
            raise CollectionMutationError(message)
        return {"local_asn": normalized, "router_id": ""}
    raise CollectionMutationError("Unknown routing protocol family.")


@transaction.atomic
def add_protocol_instance(*, revision: models.DeviceIntentRevision, family: str, **kwargs) -> dict:
    require_draft(revision)
    if family not in INSTANCE_FAMILIES:
        raise CollectionMutationError("Unknown routing protocol family.")
    platform = revision.device_intent.platform
    defaults = _instance_defaults(family, kwargs)

    if family == "bgp":
        if not _bgp_selectable(platform):
            raise CollectionMutationError("BGP is not implemented for the selected platform.")
    else:
        protocol = _routing_protocol_for(family, defaults)
        if not platform_drivers.is_routing_protocol_selectable(platform, protocol):
            raise CollectionMutationError(f"{family.upper()} is not implemented for the selected platform.")

    sections = _routing_sections(revision)
    instances = sections["routing"][family]
    if len(instances) >= MAX_PROTOCOL_INSTANCES_PER_FAMILY:
        raise CollectionLimitError(f"A candidate may contain at most {MAX_PROTOCOL_INSTANCES_PER_FAMILY} {family.upper()} instances.")

    instance_id = _new_id(ID_PREFIX[family])
    instance = {"id": instance_id, "sequence": _next_sequence(instances), **defaults}
    if family in BINDING_FAMILIES:
        instance["interfaces"] = {}
    if family == "ospf":
        instance["networks"] = {}
    if family == "bgp":
        instance["neighbors"] = {}
        instance["networks"] = {}
    instances[instance_id] = instance
    revision.sections = sections
    revision.save(update_fields=["sections"])
    for field in INSTANCE_FIELDS[family]:
        _seed_state(revision, _instance_path(family, instance_id, field), instance[field])
    return instance


@transaction.atomic
def remove_protocol_instance(*, revision: models.DeviceIntentRevision, family: str, instance_id: str, confirmation: str) -> None:
    require_draft(revision)
    get_protocol_instance(revision, family, instance_id)
    if confirmation != "REMOVE":
        raise CollectionMutationError("Explicit REMOVE confirmation is required.")
    sections = _routing_sections(revision)
    del sections["routing"][family][instance_id]
    revision.sections = sections
    revision.save(update_fields=["sections"])
    revision.field_states.filter(path__startswith=f"routing.{family}.{instance_id}.").delete()


# --- interface bindings (RIP / OSPF / IS-IS / EIGRP) ------------------------

def _binding_defaults(family: str) -> dict:
    if family == "rip":
        return {"passive": False}
    if family == "ospf":
        return {
            "area": "0.0.0.0", "passive": False, "cost": None,
            "network_type": "", "hello_interval": None, "dead_interval": None, "priority": None,
        }
    if family == "isis":
        return {"passive": False, "metric": None}
    if family == "eigrp":
        return {"passive": False}
    raise CollectionMutationError("That routing protocol does not support interface bindings.")


@transaction.atomic
def add_interface_binding(*, revision: models.DeviceIntentRevision, family: str, instance_id: str, interface_id: str) -> dict:
    require_draft(revision)
    if family not in BINDING_FAMILIES:
        raise CollectionMutationError("That routing protocol does not support interface bindings.")
    interface_intent_service.get_interface(revision, interface_id)
    instance = get_protocol_instance(revision, family, instance_id)

    sections = _routing_sections(revision)
    instance = sections["routing"][family][instance_id]
    bindings = instance.setdefault("interfaces", {})
    if len(bindings) >= MAX_INTERFACE_BINDINGS_PER_INSTANCE:
        raise CollectionLimitError(f"A routing instance may contain at most {MAX_INTERFACE_BINDINGS_PER_INSTANCE} interface bindings.")

    binding_id = _new_id("bind")
    binding = {
        "id": binding_id,
        "sequence": _next_sequence(bindings),
        "interface_id": interface_id,
        **_binding_defaults(family),
    }
    bindings[binding_id] = binding
    revision.sections = sections
    revision.save(update_fields=["sections"])
    for field in BINDING_FIELDS[family]:
        _seed_state(revision, _binding_path(family, instance_id, binding_id, field), binding[field])
    return binding


@transaction.atomic
def remove_interface_binding(*, revision: models.DeviceIntentRevision, family: str, instance_id: str, binding_id: str, confirmation: str) -> None:
    require_draft(revision)
    get_interface_binding(revision, family, instance_id, binding_id)
    if confirmation != "REMOVE":
        raise CollectionMutationError("Explicit REMOVE confirmation is required.")
    sections = _routing_sections(revision)
    del sections["routing"][family][instance_id]["interfaces"][binding_id]
    revision.sections = sections
    revision.save(update_fields=["sections"])
    revision.field_states.filter(path__startswith=f"routing.{family}.{instance_id}.interfaces.{binding_id}.").delete()


# --- OSPFv2 network statements ----------------------------------------------------------------------

@transaction.atomic
def add_ospf_network(*, revision: models.DeviceIntentRevision, instance_id: str, prefix: str, area: str = "0") -> dict:
    require_draft(revision)
    instance = get_protocol_instance(revision, "ospf", instance_id)
    if instance.get("version") != "OSPFV2":
        raise CollectionMutationError("Network statements are applicable to OSPFv2; use interface participation for OSPFv3.")
    ok_prefix, normalized_prefix, message = field_validators.validate_prefix(prefix, family=4)
    if not ok_prefix or not normalized_prefix:
        raise CollectionMutationError(message if not ok_prefix else "OSPF network prefix is required.")
    ok_area, normalized_area, message = field_validators.validate_area_id(area)
    if not ok_area:
        raise CollectionMutationError(message)
    sections = _routing_sections(revision)
    networks = sections["routing"]["ospf"][instance_id].setdefault("networks", {})
    if len(networks) >= MAX_OSPF_NETWORKS_PER_INSTANCE:
        raise CollectionLimitError(f"An OSPF instance may contain at most {MAX_OSPF_NETWORKS_PER_INSTANCE} network statements.")
    network_id = _new_id("net")
    network = {"id": network_id, "sequence": _next_sequence(networks), "prefix": normalized_prefix, "area": normalized_area}
    networks[network_id] = network
    revision.sections = sections
    revision.save(update_fields=["sections"])
    for field in OSPF_NETWORK_FIELDS:
        _seed_state(revision, _ospf_network_path(instance_id, network_id, field), network[field])
    return network


@transaction.atomic
def remove_ospf_network(*, revision: models.DeviceIntentRevision, instance_id: str, net_id: str, confirmation: str) -> None:
    require_draft(revision)
    get_ospf_network(revision, instance_id, net_id)
    if confirmation != "REMOVE":
        raise CollectionMutationError("Explicit REMOVE confirmation is required.")
    sections = _routing_sections(revision)
    del sections["routing"]["ospf"][instance_id]["networks"][net_id]
    revision.sections = sections
    revision.save(update_fields=["sections"])
    revision.field_states.filter(path__startswith=f"routing.ospf.{instance_id}.networks.{net_id}.").delete()


# --- BGP neighbors -----------------------------------------------------------

@transaction.atomic
def add_bgp_neighbor(*, revision: models.DeviceIntentRevision, instance_id: str, peer_address: str, remote_asn) -> dict:
    require_draft(revision)
    get_protocol_instance(revision, "bgp", instance_id)

    ok_asn, normalized_asn, asn_message = field_validators.validate_as_number(remote_asn)
    if not ok_asn or normalized_asn is None:
        raise CollectionMutationError(asn_message or "Remote ASN is required.")

    family = None
    normalized_address = None
    ok4, addr4, _ = field_validators.validate_ip_host(peer_address, family=4, label="Peer address")
    if ok4 and addr4:
        family, normalized_address = "IPV4", addr4
    else:
        ok6, addr6, _ = field_validators.validate_ip_host(peer_address, family=6, label="Peer address")
        if ok6 and addr6:
            family, normalized_address = "IPV6", addr6
    if family is None:
        raise CollectionMutationError("Peer address must be a valid IPv4 or IPv6 host address.")

    platform = revision.device_intent.platform
    if not platform_drivers.is_routing_protocol_selectable(platform, _bgp_protocol(family)):
        raise CollectionMutationError(f"BGP {family} is not implemented for the selected platform.")

    sections = _routing_sections(revision)
    instance = sections["routing"]["bgp"][instance_id]
    neighbors = instance.setdefault("neighbors", {})
    if len(neighbors) >= MAX_BGP_NEIGHBORS_PER_INSTANCE:
        raise CollectionLimitError(f"A BGP instance may contain at most {MAX_BGP_NEIGHBORS_PER_INSTANCE} neighbors.")

    peer_id = _new_id("peer")
    neighbor = {
        "id": peer_id,
        "sequence": _next_sequence(neighbors),
        "peer_address": normalized_address,
        "family": family,
        "remote_asn": normalized_asn,
        "description": "",
        "activate_ipv4": family == "IPV4",
        "activate_ipv6": family == "IPV6",
        "update_source_interface_id": "",
        "ebgp_multihop": None,
        "next_hop_self": False,
        "route_reflector_client": False,
        "shutdown": False,
        "password_ref": "",
    }
    neighbors[peer_id] = neighbor
    revision.sections = sections
    revision.save(update_fields=["sections"])
    for field in BGP_NEIGHBOR_FIELDS:
        _seed_state(revision, _bgp_neighbor_path(instance_id, peer_id, field), neighbor[field])
    return neighbor


@transaction.atomic
def remove_bgp_neighbor(*, revision: models.DeviceIntentRevision, instance_id: str, peer_id: str, confirmation: str) -> None:
    require_draft(revision)
    get_bgp_neighbor(revision, instance_id, peer_id)
    if confirmation != "REMOVE":
        raise CollectionMutationError("Explicit REMOVE confirmation is required.")
    sections = _routing_sections(revision)
    del sections["routing"]["bgp"][instance_id]["neighbors"][peer_id]
    revision.sections = sections
    revision.save(update_fields=["sections"])
    revision.field_states.filter(path__startswith=f"routing.bgp.{instance_id}.neighbors.{peer_id}.").delete()


# --- BGP network advertisements ----------------------------------------------

@transaction.atomic
def add_bgp_network(*, revision: models.DeviceIntentRevision, instance_id: str, family: str, cidr: str) -> dict:
    require_draft(revision)
    get_protocol_instance(revision, "bgp", instance_id)
    if family not in ADDRESS_FAMILIES:
        raise CollectionMutationError("Unknown address family.")

    platform = revision.device_intent.platform
    if not platform_drivers.is_routing_protocol_selectable(platform, _bgp_protocol(family)):
        raise CollectionMutationError(f"BGP {family} is not implemented for the selected platform.")

    ok, normalized, message = field_validators.validate_prefix(cidr, family=4 if family == "IPV4" else 6)
    if not ok or not normalized:
        raise CollectionMutationError(message if not ok else "Network CIDR is required.")

    sections = _routing_sections(revision)
    instance = sections["routing"]["bgp"][instance_id]
    networks = instance.setdefault("networks", {})
    if len(networks) >= MAX_BGP_NETWORKS_PER_INSTANCE:
        raise CollectionLimitError(f"A BGP instance may contain at most {MAX_BGP_NETWORKS_PER_INSTANCE} network advertisements.")

    net_id = _new_id("net")
    network = {"id": net_id, "sequence": _next_sequence(networks), "family": family, "cidr": normalized}
    networks[net_id] = network
    revision.sections = sections
    revision.save(update_fields=["sections"])
    for field in BGP_NETWORK_FIELDS:
        _seed_state(revision, _bgp_network_path(instance_id, net_id, field), network[field])
    return network


@transaction.atomic
def remove_bgp_network(*, revision: models.DeviceIntentRevision, instance_id: str, net_id: str, confirmation: str) -> None:
    require_draft(revision)
    get_bgp_network(revision, instance_id, net_id)
    if confirmation != "REMOVE":
        raise CollectionMutationError("Explicit REMOVE confirmation is required.")
    sections = _routing_sections(revision)
    del sections["routing"]["bgp"][instance_id]["networks"][net_id]
    revision.sections = sections
    revision.save(update_fields=["sections"])
    revision.field_states.filter(path__startswith=f"routing.bgp.{instance_id}.networks.{net_id}.").delete()


# --- dynamic field mirroring (called by field_commit_service) --------------

@transaction.atomic
def mirror_accepted_field(*, revision: models.DeviceIntentRevision, path: str, value) -> None:
    """Mirror one allowlisted accepted routing field into structured sections."""
    require_draft(revision)
    parts = path.split(".")
    sections = _routing_sections(revision)
    routing = sections["routing"]
    if len(parts) < 4 or parts[0] != "routing" or parts[1] not in PROTOCOL_FAMILIES:
        raise CollectionOwnershipError("Routing field does not belong to this candidate revision.")
    family = parts[1]

    if family == "static_routes":
        if len(parts) == 4 and parts[2] in routing["static_routes"] and parts[3] in STATIC_ROUTE_FIELDS:
            routing["static_routes"][parts[2]][parts[3]] = value
            revision.sections = sections
            revision.save(update_fields=["sections"])
            return
        raise CollectionOwnershipError("Static route field is not part of this candidate object.")

    instances = routing[family]
    if len(parts) == 4 and parts[2] in instances and parts[3] in INSTANCE_FIELDS[family]:
        instances[parts[2]][parts[3]] = value
        revision.sections = sections
        revision.save(update_fields=["sections"])
        return

    if family in BINDING_FAMILIES and len(parts) == 6 and parts[3] == "interfaces":
        instance = instances.get(parts[2])
        bindings = (instance or {}).get("interfaces") or {}
        if instance is not None and parts[4] in bindings and parts[5] in BINDING_FIELDS[family]:
            bindings[parts[4]][parts[5]] = value
            revision.sections = sections
            revision.save(update_fields=["sections"])
            return

    if family == "ospf" and len(parts) == 6 and parts[3] == "networks":
        instance = instances.get(parts[2])
        networks = (instance or {}).get("networks") or {}
        if instance is not None and parts[4] in networks and parts[5] in OSPF_NETWORK_FIELDS:
            networks[parts[4]][parts[5]] = value
            revision.sections = sections
            revision.save(update_fields=["sections"])
            return

    if family == "bgp" and len(parts) == 6:
        instance = instances.get(parts[2])
        if instance is not None and parts[3] == "neighbors":
            neighbors = instance.get("neighbors") or {}
            if parts[4] in neighbors and parts[5] in BGP_NEIGHBOR_FIELDS:
                neighbors[parts[4]][parts[5]] = value
                revision.sections = sections
                revision.save(update_fields=["sections"])
                return
        if instance is not None and parts[3] == "networks":
            networks = instance.get("networks") or {}
            if parts[4] in networks and parts[5] in BGP_NETWORK_FIELDS:
                networks[parts[4]][parts[5]] = value
                revision.sections = sections
                revision.save(update_fields=["sections"])
                return

    raise CollectionOwnershipError("Dynamic routing field path is not part of this candidate object.")


# --- editor presentation builder --------------------------------------------

def editor_routing_summary(*, revision: models.DeviceIntentRevision, platform: str) -> dict:
    """Presentation-safe view of the one underlying structured routing intent.

    Basic and Advanced both call this -- there is no separate Advanced state.
    """
    routing = routing_map(revision)
    interfaces_by_id = {row["id"]: row for row in interface_intent_service.ordered_interfaces(revision)}

    def interface_label(interface_id: str) -> str:
        return interfaces_by_id.get(interface_id, {}).get("name") or interface_id

    static_routes = []
    for route in ordered_collection(routing["static_routes"]):
        capability = platform_drivers.capability_for_routing(platform, _static_route_protocol(route["family"]))
        static_routes.append({
            **route,
            "paths": {field: _route_path(route["id"], field) for field in STATIC_ROUTE_FIELDS},
            "next_hop_interface_label": interface_label(route["next_hop_interface_id"]) if route.get("next_hop_interface_id") else "",
            "capability_status": capability.status.value,
            "capability_label": platform_drivers.CAPABILITY_STATUS_LABELS[capability.status],
            "is_compatible": capability.status == platform_drivers.CapabilityStatus.SUPPORTED,
        })

    def build_bindings(family: str, instance: dict) -> list[dict]:
        result = []
        for binding in ordered_collection(instance.get("interfaces") or {}):
            result.append({
                **binding,
                "paths": {field: _binding_path(family, instance["id"], binding["id"], field) for field in BINDING_FIELDS[family]},
                "interface_label": interface_label(binding.get("interface_id", "")),
            })
        return result

    def build_instances(family: str) -> list[dict]:
        result = []
        for instance in ordered_collection(routing[family]):
            if family == "bgp":
                capability_ok = _bgp_selectable(platform)
                neighbors = []
                for neighbor in ordered_collection(instance.get("neighbors") or {}):
                    cap = platform_drivers.capability_for_routing(platform, _bgp_protocol(neighbor["family"]))
                    neighbors.append({
                        **neighbor,
                        "paths": {field: _bgp_neighbor_path(instance["id"], neighbor["id"], field) for field in BGP_NEIGHBOR_FIELDS},
                        "update_source_label": interface_label(neighbor["update_source_interface_id"]) if neighbor.get("update_source_interface_id") else "",
                        "capability_status": cap.status.value,
                        "capability_label": platform_drivers.CAPABILITY_STATUS_LABELS[cap.status],
                        "is_compatible": cap.status == platform_drivers.CapabilityStatus.SUPPORTED,
                    })
                networks = []
                for network in ordered_collection(instance.get("networks") or {}):
                    networks.append({
                        **network,
                        "paths": {field: _bgp_network_path(instance["id"], network["id"], field) for field in BGP_NETWORK_FIELDS},
                    })
                result.append({
                    **instance,
                    "paths": {field: _instance_path("bgp", instance["id"], field) for field in INSTANCE_FIELDS["bgp"]},
                    "neighbors": neighbors,
                    "networks": networks,
                    "capability_status": (
                        platform_drivers.CapabilityStatus.SUPPORTED.value if capability_ok
                        else platform_drivers.CapabilityStatus.NOT_IMPLEMENTED.value
                    ),
                    "is_compatible": capability_ok,
                })
            else:
                capability = platform_drivers.capability_for_routing(platform, _routing_protocol_for(family, instance))
                ospf_networks = []
                if family == "ospf":
                    for network in ordered_collection(instance.get("networks") or {}):
                        ospf_networks.append({**network, "paths": {
                            field: _ospf_network_path(instance["id"], network["id"], field)
                            for field in OSPF_NETWORK_FIELDS
                        }})
                result.append({
                    **instance,
                    "paths": {field: _instance_path(family, instance["id"], field) for field in INSTANCE_FIELDS[family]},
                    "interfaces": build_bindings(family, instance),
                    "networks": ospf_networks,
                    "capability_status": capability.status.value,
                    "capability_label": platform_drivers.CAPABILITY_STATUS_LABELS[capability.status],
                    "is_compatible": capability.status == platform_drivers.CapabilityStatus.SUPPORTED,
                })
        return result

    by_family = {family: build_instances(family) for family in INSTANCE_FAMILIES}
    return {
        "static_routes": static_routes,
        "rip": by_family["rip"],
        "ospf": by_family["ospf"],
        "isis": by_family["isis"],
        "eigrp": by_family["eigrp"],
        "bgp": by_family["bgp"],
        "counts": {family: len(routing[family]) for family in PROTOCOL_FAMILIES},
        "has_incompatible_objects": any(
            not obj["is_compatible"]
            for objs in (static_routes, *by_family.values())
            for obj in objs
        ),
    }
