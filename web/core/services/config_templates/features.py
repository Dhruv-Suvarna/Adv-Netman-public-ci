"""What a template intent REQUIRES: capability feature keys (Phase 1 catalogue), platform compatibility, and the
project-owned Jinja2 feature templates it renders through.  Derived from the intent; nothing here is hand-labelled."""

from __future__ import annotations

from ..capabilities import features as capability_features
from ..capabilities import registry as capability_registry
from ..feature_template_renderer import FEATURE_TEMPLATE_ROOT

_TEMPLATE_DIR = {"arista_ceos": "ceos", "ubuntu_frr": "ubuntu_frr", "nokia_srlinux": "srlinux",
                 "cisco_c8000v_iosxe": "iosxe", "cisco_iosxr": "iosxr"}
_FEATURE_TEMPLATE = {"routing.OSPFV2": "routing_ospfv2", "routing.OSPFV3": "routing_ospfv3", "routing.RIPV2": "routing_rip",
                     "routing.RIPNG": "routing_rip", "routing.BGP_IPV4": "routing_bgp", "routing.BGP_IPV6": "routing_bgp",
                     "routing.STATIC_IPV4": "routing_static_route", "routing.STATIC_IPV6": "routing_static_route",
                     "service_policy.FHRP_VARP_IPV4": "fhrp_varp", "service_policy.FHRP_VARP_IPV6": "fhrp_varp",
                     "service_policy.NAT_NAT44_PAT": "nat_pat", "service_policy.NAT_NAT44_STATIC": "nat_static",
                     "service_policy.ACL_IPV4_EXTENDED": "acl_ipv4",
                     "service_policy.ACL_IPV4_STANDARD": "acl_ipv4"}


def required_features(intent: dict) -> list[str]:
    """Capability feature keys used by the intent (objects behind a ``_when`` flag count: the template can produce them)."""
    found: set[str] = set()
    for row in intent.get("interfaces", []):
        if isinstance(row.get("kind"), str):
            found.add(f"interface.{row['kind']}")
        for relay in row.get("dhcp_relays", []):
            found.add(f"service_policy.DHCP_RELAY_{relay.get('family')}")
        for fhrp in row.get("fhrp", []):
            found.add(f"service_policy.FHRP_{fhrp.get('protocol')}_{fhrp.get('address_family')}")
        for attachment in row.get("acl_attachments", []):
            found.add(f"service_policy.ACL_ATTACH_{attachment.get('family')}")
    for route in intent.get("static_routes", []):
        found.add(f"routing.STATIC_{route.get('family')}")
    for instance in intent.get("routing", []):
        family, fields = instance.get("family"), instance.get("fields") or {}
        if family == "rip":
            found.add("routing.RIPV2" if fields.get("address_family") == "IPV4" else "routing.RIPNG")
        elif family == "ospf":
            found.add(f"routing.{fields.get('version') or 'OSPFV2'}")
        elif family == "bgp":
            families = {n.get("family") for n in instance.get("neighbors", [])} | {n.get("family") for n in instance.get("networks", [])}
            found |= {f"routing.BGP_{f}" for f in families if f in ("IPV4", "IPV6")} or {"routing.BGP_IPV4"}
        elif family == "isis":
            found.add("routing.ISIS")
        elif family == "eigrp":
            found.add("routing.EIGRP_IPV4" if fields.get("address_family") == "IPV4" else "routing.EIGRP_IPV6")
    for acl in intent.get("acls", []):
        found.add(f"service_policy.ACL_{acl.get('family')}_{acl.get('acl_type')}")
    for rule in intent.get("nat_rules", []):
        found.add(f"service_policy.NAT_{rule.get('family')}_{rule.get('mode')}")
    known = capability_features.by_key()
    return sorted(key for key in found if key in known)


def unknown_features(keys) -> list[str]:
    known = capability_features.by_key()
    return sorted(str(k)[:80] for k in keys if k not in known)


def supported_platforms(feature_keys) -> list[str]:
    """Platforms whose registry can render EVERY required feature (selectable in the Device Builder)."""
    known = capability_features.by_key()
    out = []
    for platform in capability_features.platforms():
        if all(capability_registry._render_capability(platform, known[key])[1] for key in feature_keys if key in known):  # noqa: SLF001
            out.append(platform)
    return out


def platform_gaps(feature_keys, platform: str) -> list[str]:
    known = capability_features.by_key()
    return [key for key in feature_keys if key in known and not capability_registry._render_capability(platform, known[key])[1]]  # noqa: SLF001


def feature_templates(feature_keys, platforms) -> list[str]:
    """References ('<platform dir>/<name>.j2') to the tracked Jinja2 feature templates this intent renders through."""
    references = set()
    for platform in platforms:
        directory = _TEMPLATE_DIR.get(platform)
        if not directory:
            continue
        for key in feature_keys:
            family, code = key.split(".", 1)
            name = f"interface_{code.lower()}" if family == "interface" else _FEATURE_TEMPLATE.get(key)
            if name and (FEATURE_TEMPLATE_ROOT / directory / f"{name}.j2").is_file():
                references.add(f"{directory}/{name}.j2")
    return sorted(references)
