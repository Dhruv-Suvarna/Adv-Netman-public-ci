"""Structured Phase-10 interface/address/WAN intent collection service.

The service owns collection mutations in ``DeviceIntentRevision.sections``.
Every mutation is DRAFT-only, bounded, ownership-checked by its caller, and
application-state-only.  It never calls NetBox, Git, a device, or a topology
tool.  Stable opaque IDs, rather than list indexes or interface names, form
the field-path identity used by the Device Builder.
"""

from __future__ import annotations

from copy import deepcopy
from uuid import uuid4

from django.db import transaction

from .. import models
from . import intent_service

MAX_INTERFACES_PER_REVISION = 64
MAX_ADDRESSES_PER_INTERFACE = 16

ADDRESS_FAMILIES = ("IPV4", "IPV6")
ADDRESS_SOURCES = ("MANUAL", "AUTO")
ADDRESS_ROLES = ("PRIMARY", "SECONDARY")
ADMIN_STATES = ("ENABLED", "DISABLED")
WAN_STATES = ("DISABLED", "ENABLED")

INTERFACE_KINDS = (
    "ROUTED_PHYSICAL",
    "ACCESS",
    "TRUNK",
    "SUBINTERFACE",
    "SVI",
    "MANAGEMENT",
    "LOOPBACK",
    "LAG",
    "MLAG",
    "BOND",
    "BRIDGE",
    "TUNNEL",
    "GRE",
    "VXLAN_VTEP",
    "VIRTUAL",
    "RADIO_WLAN",
)

INTERFACE_KIND_LABELS = {
    "ROUTED_PHYSICAL": "Physical routed",
    "ACCESS": "Physical access",
    "TRUNK": "Physical trunk",
    "SUBINTERFACE": "Subinterface",
    "SVI": "SVI",
    "MANAGEMENT": "Management / OOB",
    "LOOPBACK": "Loopback",
    "LAG": "LAG / Port-Channel",
    "MLAG": "MLAG construct",
    "BOND": "Linux bond",
    "BRIDGE": "Linux bridge",
    "TUNNEL": "Tunnel",
    "GRE": "GRE",
    "VXLAN_VTEP": "VXLAN / VTEP",
    "VIRTUAL": "Virtual",
    "RADIO_WLAN": "Radio / WLAN",
}

KIND_MODES = {
    "ROUTED_PHYSICAL": "ROUTED",
    "ACCESS": "ACCESS",
    "TRUNK": "TRUNK",
    "SUBINTERFACE": "ROUTED",
    "SVI": "ROUTED",
    "MANAGEMENT": "MANAGEMENT_STATIC",
    "LOOPBACK": "ROUTED",
    "LAG": "AGGREGATED",
    "MLAG": "MULTICHASSIS",
    "BOND": "AGGREGATED",
    "BRIDGE": "BRIDGED",
    "TUNNEL": "TUNNEL",
    "GRE": "TUNNEL",
    "VXLAN_VTEP": "OVERLAY",
    "VIRTUAL": "VIRTUAL",
    "RADIO_WLAN": "WIRELESS",
}

INTERFACE_FIELDS = (
    "name",
    "kind",
    "description",
    "admin_state",
    "mtu",
    "access_vlan",
    "trunk_allowed_vlans",
    "native_vlan",
    "parent_id",
    "encapsulation_vlan",
    "vlan_id",
    "role",
    "operational_description",
)
ADDRESS_FIELDS = ("family", "cidr", "source", "role", "ipam_prefix")
WAN_FIELDS = (
    "state",
    "provider_name",
    "peer_label",
    "peer_ipv4",
    "peer_ipv6",
    "gateway_ipv4",
    "gateway_ipv6",
    "mtu",
    "description",
)


class CollectionMutationError(ValueError):
    pass


class DraftOnlyError(CollectionMutationError):
    pass


class CollectionLimitError(CollectionMutationError):
    pass


class CollectionOwnershipError(CollectionMutationError):
    pass


def _new_id(prefix: str) -> str:
    return f"{prefix}_{uuid4().hex[:16]}"


def require_draft(revision: models.DeviceIntentRevision) -> None:
    if revision.device_intent.change.lifecycle_state != models.ChangeLifecycleState.DRAFT:
        raise DraftOnlyError("Device Builder collections may be changed only while the Change is DRAFT.")


def _sections(revision: models.DeviceIntentRevision) -> dict:
    sections = deepcopy(revision.sections or {})
    interfaces = sections.get("interfaces")
    if not isinstance(interfaces, dict):
        interfaces = {}
    sections["interfaces"] = interfaces
    return sections


def interface_map(revision: models.DeviceIntentRevision) -> dict:
    return _sections(revision)["interfaces"]


def ordered_interfaces(revision: models.DeviceIntentRevision) -> list[dict]:
    rows = list(interface_map(revision).values())
    return sorted(rows, key=lambda row: (int(row.get("sequence") or 0), row.get("id", ""), row.get("name", "")))


def get_interface(revision: models.DeviceIntentRevision, interface_id: str) -> dict:
    interface = interface_map(revision).get(interface_id)
    if not interface or interface.get("id") != interface_id:
        raise CollectionOwnershipError("Interface ID does not belong to this candidate revision.")
    return interface


def get_address(revision: models.DeviceIntentRevision, interface_id: str, address_id: str) -> dict:
    interface = get_interface(revision, interface_id)
    address = (interface.get("addresses") or {}).get(address_id)
    if not address or address.get("id") != address_id:
        raise CollectionOwnershipError("Address ID does not belong to this candidate interface.")
    return address


def _interface_path(interface_id: str, field: str) -> str:
    return f"interfaces.{interface_id}.{field}"


def _address_path(interface_id: str, address_id: str, field: str) -> str:
    return f"interfaces.{interface_id}.addresses.{address_id}.{field}"


def _wan_path(interface_id: str, field: str) -> str:
    return f"interfaces.{interface_id}.wan.{field}"


def _seed_state(revision, path: str, value) -> None:
    intent_service.set_draft_field(revision=revision, path=path, draft_value=value)
    intent_service.accept_field_value(revision=revision, path=path)


def is_management_static(interface: dict) -> bool:
    return (
        interface.get("kind") == "MANAGEMENT"
        or str(interface.get("name", "")).lower() == "vlan200"
        or interface.get("vlan_id") == 200
        or interface.get("access_vlan") == 200 and interface.get("kind") == "MANAGEMENT"
    )


@transaction.atomic
def add_interface(*, revision: models.DeviceIntentRevision, kind: str, name: str = "") -> dict:
    require_draft(revision)
    from . import field_validators, platform_drivers

    if kind not in INTERFACE_KINDS:
        raise CollectionMutationError("Unknown interface type.")
    platform = revision.device_intent.platform
    if not platform_drivers.is_interface_kind_selectable(platform, kind):
        raise CollectionMutationError("That interface type is not implemented for the selected platform.")
    ok, normalized_name, message = field_validators.validate_interface_name(name)
    if not ok:
        raise CollectionMutationError(message)
    name = normalized_name

    sections = _sections(revision)
    interfaces = sections["interfaces"]
    if len(interfaces) >= MAX_INTERFACES_PER_REVISION:
        raise CollectionLimitError(f"A candidate may contain at most {MAX_INTERFACES_PER_REVISION} interfaces.")

    interface_id = _new_id("if")
    sequence = max((int(item.get("sequence") or 0) for item in interfaces.values()), default=0) + 1
    interface = {
        "id": interface_id,
        "sequence": sequence,
        "name": name,
        "kind": kind,
        "mode": KIND_MODES[kind],
        "description": "",
        "admin_state": "ENABLED",
        "mtu": None,
        "access_vlan": None,
        "trunk_allowed_vlans": [],
        "native_vlan": None,
        "parent_id": "",
        "encapsulation_vlan": None,
        "vlan_id": 200 if kind == "MANAGEMENT" and name.lower() == "vlan200" else None,
        "role": "MANAGEMENT" if kind == "MANAGEMENT" else "",
        "operational_description": "",
        "addresses": {},
        "wan": {
            "state": "DISABLED",
            "provider_name": "",
            "peer_label": "",
            "peer_ipv4": "",
            "peer_ipv6": "",
            "gateway_ipv4": "",
            "gateway_ipv6": "",
            "mtu": None,
            "description": "",
        },
    }
    interfaces[interface_id] = interface
    revision.sections = sections
    revision.save(update_fields=["sections"])

    for field in INTERFACE_FIELDS:
        _seed_state(revision, _interface_path(interface_id, field), interface[field])
    for field in WAN_FIELDS:
        _seed_state(revision, _wan_path(interface_id, field), interface["wan"][field])
    return interface


@transaction.atomic
def remove_interface(*, revision: models.DeviceIntentRevision, interface_id: str, confirmation: str) -> None:
    require_draft(revision)
    get_interface(revision, interface_id)
    if confirmation != "REMOVE":
        raise CollectionMutationError("Explicit REMOVE confirmation is required.")
    for other in interface_map(revision).values():
        if other.get("id") != interface_id and other.get("parent_id") == interface_id:
            raise CollectionMutationError("Remove or re-parent child subinterfaces before removing this interface.")
    sections = deepcopy(revision.sections or {})
    # Definitions/global objects are never silently deleted with an interface.
    # They must first be detached or explicitly removed through their owner.
    globally_owned_references = [
        item.get("interface_id") == interface_id
        for item in (sections.get("fhrp", {}).get("instances", {}) or {}).values()
    ]
    globally_owned_references.extend(
        route.get("next_hop_interface_id") == interface_id
        for route in (sections.get("routing", {}).get("static_routes", {}) or {}).values()
    )
    globally_owned_references.extend(
        neighbor.get("update_source_interface_id") == interface_id
        for instance in (sections.get("routing", {}).get("bgp", {}) or {}).values()
        for neighbor in (instance.get("neighbors") or {}).values()
    )
    pbr = sections.get("policy", {}).get("pbr", {}) or {}
    globally_owned_references.extend(
        row.get("output_interface_id") == interface_id
        for policy in (pbr.get("policies", {}) or {}).values()
        for row in (policy.get("sequences", {}) or {}).values()
    )
    if any(globally_owned_references):
        raise CollectionMutationError(
            "Detach or reassign global routing/service/policy objects before removing this interface."
        )

    removed_field_prefixes: list[str] = []

    # Routing bindings are interface-owned attachments.  Removing the draft
    # interface removes those bindings but preserves every routing process.
    routing = sections.get("routing") or {}
    for family in ("rip", "ospf", "isis", "eigrp"):
        for instance_id, instance in (routing.get(family) or {}).items():
            bindings = instance.get("interfaces") or {}
            for binding_id, binding in list(bindings.items()):
                if binding.get("interface_id") == interface_id:
                    del bindings[binding_id]
                    removed_field_prefixes.append(
                        f"routing.{family}.{instance_id}.interfaces.{binding_id}."
                    )

    # Service/policy attachment rows have no independent meaning without their
    # interface.  Their named/global definitions remain intact.
    dhcp = sections.get("services", {}).get("dhcp", {}) or {}
    for collection_name in ("relays", "clients"):
        collection = dhcp.get(collection_name) or {}
        for object_id, row in list(collection.items()):
            if row.get("interface_id") == interface_id:
                del collection[object_id]
                removed_field_prefixes.append(f"services.dhcp.{collection_name}.{object_id}.")

    security = sections.get("security") or {}
    attachments = security.get("attachments") or {}
    for attachment_id, attachment in list(attachments.items()):
        if attachment.get("interface_id") == interface_id:
            del attachments[attachment_id]
            removed_field_prefixes.append(f"security.attachments.{attachment_id}.")

    attachments = pbr.get("attachments") or {}
    for attachment_id, attachment in list(attachments.items()):
        if attachment.get("interface_id") == interface_id:
            del attachments[attachment_id]
            removed_field_prefixes.append(f"policy.pbr.attachments.{attachment_id}.")

    # NAT rules are global objects.  Keep them, but remove the deleted
    # interface's role/reference so no orphan interface contribution survives.
    cleared_paths: list[str] = []
    for rule_id, rule in (sections.get("nat", {}).get("rules", {}) or {}).items():
        for field in ("inside_interface_id", "outside_interface_id"):
            if rule.get(field) == interface_id:
                rule[field] = ""
                cleared_paths.append(f"nat.rules.{rule_id}.{field}")

    sections.setdefault("interfaces", {})
    del sections["interfaces"][interface_id]
    revision.sections = sections
    revision.save(update_fields=["sections"])
    revision.field_states.filter(path__startswith=f"interfaces.{interface_id}.").delete()
    for prefix in removed_field_prefixes:
        revision.field_states.filter(path__startswith=prefix).delete()
    for path in cleared_paths:
        revision.field_states.filter(path=path).update(
            accepted_value="", draft_value="", dirty=False
        )


@transaction.atomic
def add_address(
    *, revision: models.DeviceIntentRevision, interface_id: str, family: str = "IPV4", source: str = "MANUAL"
) -> dict:
    require_draft(revision)
    if family not in ADDRESS_FAMILIES:
        raise CollectionMutationError("Unknown address family.")
    if source not in ADDRESS_SOURCES:
        raise CollectionMutationError("Unknown address source mode.")

    sections = _sections(revision)
    interface = sections["interfaces"].get(interface_id)
    if not interface:
        raise CollectionOwnershipError("Interface ID does not belong to this candidate revision.")
    addresses = interface.setdefault("addresses", {})
    if len(addresses) >= MAX_ADDRESSES_PER_INTERFACE:
        raise CollectionLimitError(
            f"An interface may contain at most {MAX_ADDRESSES_PER_INTERFACE} addresses."
        )
    if source == "AUTO" and is_management_static(interface):
        raise CollectionMutationError("Management/VLAN 200 addressing is static and cannot use AUTO mode.")

    address_id = _new_id("addr")
    address = {
        "id": address_id,
        "sequence": max((int(item.get("sequence") or 0) for item in addresses.values()), default=0) + 1,
        "family": family,
        "cidr": "",
        "source": source,
        "role": "PRIMARY",
        "ipam_prefix": "",
    }
    addresses[address_id] = address
    revision.sections = sections
    revision.save(update_fields=["sections"])
    for field in ADDRESS_FIELDS:
        _seed_state(revision, _address_path(interface_id, address_id, field), address[field])
    return address


@transaction.atomic
def remove_address(
    *, revision: models.DeviceIntentRevision, interface_id: str, address_id: str, confirmation: str
) -> None:
    require_draft(revision)
    get_address(revision, interface_id, address_id)
    if confirmation != "REMOVE":
        raise CollectionMutationError("Explicit REMOVE confirmation is required.")
    sections = _sections(revision)
    del sections["interfaces"][interface_id]["addresses"][address_id]
    revision.sections = sections
    revision.save(update_fields=["sections"])
    revision.field_states.filter(path__startswith=f"interfaces.{interface_id}.addresses.{address_id}.").delete()


@transaction.atomic
def mirror_accepted_field(*, revision: models.DeviceIntentRevision, path: str, value) -> None:
    """Mirror one allowlisted accepted dynamic field into structured sections."""
    require_draft(revision)
    parts = path.split(".")
    sections = _sections(revision)
    interfaces = sections["interfaces"]
    if len(parts) < 3 or parts[0] != "interfaces" or parts[1] not in interfaces:
        raise CollectionOwnershipError("Interface field does not belong to this candidate revision.")
    interface = interfaces[parts[1]]

    if len(parts) == 3 and parts[2] in INTERFACE_FIELDS:
        interface[parts[2]] = value
        if parts[2] == "kind":
            interface["mode"] = KIND_MODES[value]
    elif len(parts) == 4 and parts[2] == "wan" and parts[3] in WAN_FIELDS:
        interface.setdefault("wan", {})[parts[3]] = value
    elif (
        len(parts) == 5
        and parts[2] == "addresses"
        and parts[3] in (interface.get("addresses") or {})
        and parts[4] in ADDRESS_FIELDS
    ):
        interface["addresses"][parts[3]][parts[4]] = value
    else:
        raise CollectionOwnershipError("Dynamic field path is not part of this candidate object.")

    revision.sections = sections
    revision.save(update_fields=["sections"])


def address_is_auto(revision, interface_id: str, address_id: str) -> bool:
    return get_address(revision, interface_id, address_id).get("source") == "AUTO"


def editor_interfaces(*, revision: models.DeviceIntentRevision, platform: str) -> list[dict]:
    """Presentation-safe view of the one underlying structured intent."""
    from . import field_validators, platform_drivers

    raw_rows = ordered_interfaces(revision)
    by_id = {row["id"]: row for row in raw_rows}
    result = []
    for row in raw_rows:
        interface_id = row["id"]
        values = {
            field: field_validators.vlan_set_display(row.get(field))
            if field == "trunk_allowed_vlans"
            else ("" if row.get(field) is None else row.get(field))
            for field in INTERFACE_FIELDS
        }
        addresses = []
        for address in sorted(
            (row.get("addresses") or {}).values(),
            key=lambda item: (int(item.get("sequence") or 0), item.get("id", "")),
        ):
            addresses.append({
                **address,
                "paths": {field: _address_path(interface_id, address["id"], field) for field in ADDRESS_FIELDS},
                "is_static_management": is_management_static(row),
            })
        capability = platform_drivers.capability_for(platform, row["kind"])
        result.append({
            **row,
            "values": values,
            "paths": {field: _interface_path(interface_id, field) for field in INTERFACE_FIELDS},
            "wan_paths": {field: _wan_path(interface_id, field) for field in WAN_FIELDS},
            "addresses": addresses,
            "address_summary": [
                address.get("cidr") or f"AUTO: {address.get('ipam_prefix') or 'prefix not selected'}"
                for address in addresses
            ],
            "parent_name": by_id.get(row.get("parent_id") or "", {}).get("name", ""),
            "parent_choices": [item for item in raw_rows if item["id"] != interface_id],
            "type_choices": platform_drivers.implemented_interface_choices(platform, preserve_kind=row["kind"]),
            "capability_status": capability.status.value,
            "capability_label": platform_drivers.CAPABILITY_STATUS_LABELS[capability.status],
            "is_compatible": capability.status == platform_drivers.CapabilityStatus.SUPPORTED,
            "is_static_management": is_management_static(row),
        })
    return result
