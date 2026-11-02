"""The canonical capability feature catalogue: one key per Device Builder feature, mapped to the registry lookups
and to the execution object type that would carry it to a device."""

from __future__ import annotations

from dataclasses import dataclass

from .. import interface_intent_service, platform_drivers

INTERFACE, ROUTING, SERVICE_POLICY = "interface", "routing", "service_policy"


@dataclass(frozen=True)
class Feature:
    key: str            # e.g. "interface.ROUTED_PHYSICAL", "routing.OSPFV2", "service_policy.ACL_IPV4_EXTENDED"
    family: str
    code: str           # the registry's own key
    label: str
    object_type: str    # execution object type (execution.capability / planning.priorities.CATALOGUE)


_ROUTING_OBJECT = {
    "STATIC_IPV4": "static_route", "STATIC_IPV6": "static_route", "RIPV2": "routing_rip", "RIPNG": "routing_rip",
    "OSPFV2": "routing_ospf", "OSPFV3": "routing_ospf", "ISIS": "routing_isis", "EIGRP_IPV4": "routing_eigrp",
    "EIGRP_IPV6": "routing_eigrp", "BGP_IPV4": "routing_bgp", "BGP_IPV6": "routing_bgp",
}
_SERVICE_PREFIX_OBJECT = (
    ("FHRP_", "fhrp"), ("NAT_POOL", "nat_pool"), ("NAT_", "nat_rule"), ("DHCP_RELAY", "dhcp_relay"),
    ("ACL_ATTACH", "acl_attachment"), ("ACL_", "acl"), ("PBR_ATTACH", "pbr_attachment"), ("PBR_", "pbr_policy"),
)


def _service_object(code: str) -> str:
    for prefix, object_type in _SERVICE_PREFIX_OBJECT:
        if code.startswith(prefix):
            return object_type
    return ""  # DHCP client / server, DNS, monitoring overrides: no execution object type exists


def catalogue() -> tuple[Feature, ...]:
    features: list[Feature] = []
    for kind in interface_intent_service.INTERFACE_KINDS:
        features.append(Feature(f"{INTERFACE}.{kind}", INTERFACE, str(kind),
                                str(interface_intent_service.INTERFACE_KIND_LABELS[kind]), "interface"))
    for protocol in platform_drivers.RoutingProtocol:
        features.append(Feature(f"{ROUTING}.{protocol.value}", ROUTING, protocol.value,
                                platform_drivers.ROUTING_PROTOCOL_LABELS[protocol], _ROUTING_OBJECT.get(protocol.value, "")))
    first_platform = next(iter(platform_drivers.SERVICE_POLICY_CAPABILITIES))
    for feature in platform_drivers.SERVICE_POLICY_CAPABILITIES[first_platform]:
        code = getattr(feature, "value", str(feature))
        features.append(Feature(f"{SERVICE_POLICY}.{code}", SERVICE_POLICY, code, code.replace("_", " ").title(), _service_object(code)))
    return tuple(features)


def by_key() -> dict[str, Feature]:
    return {f.key: f for f in catalogue()}


def platforms() -> tuple[str, ...]:
    return tuple(platform_drivers.PLATFORM_DRIVERS)
