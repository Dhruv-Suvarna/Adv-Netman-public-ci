"""Structured Phase-12 FHRP/NAT/services/security/policy intent.

All objects live in the existing DeviceIntentRevision.sections JSON document.
This module owns bounded, DRAFT-only collection mutation and candidate-local
references.  It deliberately performs Tier-1 validation only and never calls
NetBox, a device, Git, or a deployment subsystem.
"""

from __future__ import annotations

from copy import deepcopy
from uuid import uuid4

from django.db import transaction

from .. import models
from . import field_validators, interface_intent_service, intent_service

INHERITANCE_MODES = ("INHERIT", "OVERRIDE")
ADDRESS_FAMILIES = ("IPV4", "IPV6")
FHRP_PROTOCOLS = ("HSRP", "VRRP", "VARP", "GLBP", "ANYCAST_GATEWAY")
NAT_FAMILIES = ("NAT44", "NAT64", "NAT66", "NPTV6", "NAT_PT")
NAT_MODES = ("STATIC", "DYNAMIC", "PAT", "STATEFUL", "TWICE_NAT", "POLICY_NAT")
ACL_FAMILIES = ("IPV4", "IPV6")
ACL_TYPES = ("STANDARD", "EXTENDED")
ACL_ACTIONS = ("PERMIT", "DENY")
ACL_PROTOCOLS = ("IP", "IPV6", "TCP", "UDP", "ICMP", "ICMPV6")
MATCH_TYPES = ("ANY", "HOST", "PREFIX")
DIRECTIONS = ("IN", "OUT")

MAX_FHRP_INSTANCES = 32
MAX_VIPS_PER_FHRP = 16
MAX_NAT_POOLS = 32
MAX_NAT_RULES = 128
MAX_DHCP_RELAYS = 32
MAX_DHCP_CLIENTS = 32
MAX_DNS_RESOLVERS = 8
MAX_SEARCH_DOMAINS = 12
MAX_ACLS = 32
MAX_ACES_PER_ACL = 128
MAX_ACL_ATTACHMENTS = 64
MAX_PBR_POLICIES = 16
MAX_PBR_SEQUENCES = 64
MAX_PBR_ATTACHMENTS = 32

FHRP_FIELDS = (
    "protocol", "interface_id", "address_family", "group_id", "priority",
    "preempt", "preempt_delay", "hello_timer", "hold_timer", "virtual_mac",
    "auth_secret_ref", "description",
)
FHRP_VIP_FIELDS = ("address",)
NAT_POOL_FIELDS = ("name", "family", "start_address", "end_address", "prefix_length", "description")
NAT_RULE_FIELDS = (
    "family", "mode", "original_source", "translated_source", "pool_id",
    "protocol", "original_port", "translated_port", "inside_interface_id",
    "outside_interface_id", "description", "enabled",
)
DHCP_RELAY_FIELDS = ("family", "interface_id", "destination", "description")
DHCP_CLIENT_FIELDS = ("family", "interface_id", "description")
DNS_RESOLVER_FIELDS = ("family", "address")
DNS_DOMAIN_FIELDS = ("domain",)
ACL_FIELDS = ("name", "family", "acl_type", "description")
ACE_FIELDS = (
    "sequence", "action", "protocol", "source_type", "source_value",
    "destination_type", "destination_value", "source_port", "destination_port",
    "description", "logging",
)
ACL_ATTACHMENT_FIELDS = ("acl_id", "interface_id", "direction")
PBR_POLICY_FIELDS = ("name", "family", "description")
PBR_SEQUENCE_FIELDS = (
    "sequence", "source_prefix", "destination_prefix", "protocol",
    "next_hop", "output_interface_id", "description",
)
PBR_ATTACHMENT_FIELDS = ("policy_id", "interface_id", "direction")


class CollectionMutationError(ValueError):
    pass


class CollectionLimitError(CollectionMutationError):
    pass


class CollectionOwnershipError(CollectionMutationError):
    pass


def _new_id(prefix: str) -> str:
    return f"{prefix}_{uuid4().hex[:16]}"


def _next_sequence(mapping: dict) -> int:
    return max((int(item.get("sequence") or 0) for item in mapping.values()), default=0) + 1


def _next_rule_sequence(mapping: dict) -> int:
    """Return conventional rule ordering (10, 20, ...) without coupling IDs to order."""
    return max((int(item.get("sequence") or 0) for item in mapping.values()), default=0) + 10


def _seed(revision, path: str, value) -> None:
    intent_service.set_draft_field(revision=revision, path=path, draft_value=value)
    intent_service.accept_field_value(revision=revision, path=path)


def require_draft(revision) -> None:
    interface_intent_service.require_draft(revision)


def _sections(revision) -> dict:
    sections = deepcopy(revision.sections or {})
    defaults = {
        "fhrp": {"instances": {}},
        "nat": {"pools": {}, "rules": {}},
        "services": {
            "dhcp": {"mode": "INHERIT", "relays": {}, "clients": {}, "local_server_override": False},
            "dns": {"mode": "INHERIT", "resolvers": {}, "search_domains": {}, "domain_name": ""},
            "monitoring": {"mode": "INHERIT"},
        },
        "security": {"acls": {}, "attachments": {}},
        "policy": {"pbr": {"policies": {}, "attachments": {}}},
    }
    for namespace, default in defaults.items():
        if not isinstance(sections.get(namespace), dict):
            sections[namespace] = deepcopy(default)
            continue
        for key, value in default.items():
            if key not in sections[namespace] or not isinstance(sections[namespace][key], type(value)):
                sections[namespace][key] = deepcopy(value)
    services = sections["services"]
    for name in ("dhcp", "dns", "monitoring"):
        if not isinstance(services.get(name), dict):
            services[name] = deepcopy(defaults["services"][name])
    for key, value in defaults["services"]["dhcp"].items():
        services["dhcp"].setdefault(key, deepcopy(value))
    for key, value in defaults["services"]["dns"].items():
        services["dns"].setdefault(key, deepcopy(value))
    pbr = sections["policy"].setdefault("pbr", {})
    pbr.setdefault("policies", {})
    pbr.setdefault("attachments", {})
    return sections


def structured_sections(revision) -> dict:
    sections = _sections(revision)
    return {key: sections[key] for key in ("fhrp", "nat", "services", "security", "policy")}


def _save(revision, sections: dict) -> None:
    revision.sections = sections
    revision.save(update_fields=["sections"])


def _owned(mapping: dict, object_id: str, label: str) -> dict:
    obj = mapping.get(object_id)
    if not obj or obj.get("id") != object_id:
        raise CollectionOwnershipError(f"{label} ID does not belong to this candidate revision.")
    return obj


def _get_interface(revision, interface_id: str) -> dict:
    try:
        return interface_intent_service.get_interface(revision, interface_id)
    except interface_intent_service.CollectionOwnershipError as exc:
        raise CollectionOwnershipError(str(exc)) from exc


def _supported(revision, feature: str) -> bool:
    from . import platform_drivers
    return platform_drivers.is_service_policy_feature_selectable(revision.device_intent.platform, feature)


def _require_supported(revision, feature: str, label: str) -> None:
    if not _supported(revision, feature):
        raise CollectionMutationError(f"{label} is not implemented for the selected platform.")


def ordered(mapping: dict) -> list[dict]:
    return sorted(mapping.values(), key=lambda row: (int(row.get("sequence") or 0), row.get("id", "")))


# FHRP ---------------------------------------------------------------------

def get_fhrp_instance(revision, instance_id):
    return _owned(_sections(revision)["fhrp"]["instances"], instance_id, "FHRP instance")


def get_fhrp_vip(revision, instance_id, vip_id):
    return _owned(get_fhrp_instance(revision, instance_id).get("virtual_ips") or {}, vip_id, "FHRP virtual IP")


@transaction.atomic
def add_fhrp_instance(*, revision, protocol="VARP", interface_id="", address_family="IPV4"):
    require_draft(revision)
    if protocol not in FHRP_PROTOCOLS or address_family not in ADDRESS_FAMILIES:
        raise CollectionMutationError("Unknown FHRP protocol or address family.")
    _require_supported(revision, f"FHRP_{protocol}_{address_family}", f"{protocol} {address_family}")
    _get_interface(revision, interface_id)
    sections = _sections(revision)
    instances = sections["fhrp"]["instances"]
    if len(instances) >= MAX_FHRP_INSTANCES:
        raise CollectionLimitError(f"A candidate may contain at most {MAX_FHRP_INSTANCES} FHRP instances.")
    object_id = _new_id("fhrp")
    obj = {
        "id": object_id, "sequence": _next_sequence(instances), "protocol": protocol,
        "interface_id": interface_id, "address_family": address_family, "group_id": None,
        "priority": None, "preempt": False, "preempt_delay": None, "hello_timer": None,
        "hold_timer": None, "virtual_mac": "", "auth_secret_ref": "", "description": "",
        "virtual_ips": {},
    }
    instances[object_id] = obj
    _save(revision, sections)
    for field in FHRP_FIELDS:
        _seed(revision, f"fhrp.instances.{object_id}.{field}", obj[field])
    return obj


@transaction.atomic
def add_fhrp_vip(*, revision, instance_id, address=""):
    require_draft(revision)
    instance = get_fhrp_instance(revision, instance_id)
    family = 4 if instance["address_family"] == "IPV4" else 6
    ok, normalized, message = field_validators.validate_ip_host(address, family=family, label="Virtual IP")
    if not ok or not normalized:
        raise CollectionMutationError(message or "Virtual IP is required.")
    sections = _sections(revision)
    vips = sections["fhrp"]["instances"][instance_id].setdefault("virtual_ips", {})
    if len(vips) >= MAX_VIPS_PER_FHRP:
        raise CollectionLimitError(f"An FHRP instance may contain at most {MAX_VIPS_PER_FHRP} virtual IPs.")
    vip_id = _new_id("vip")
    vip = {"id": vip_id, "sequence": _next_sequence(vips), "address": normalized}
    vips[vip_id] = vip
    _save(revision, sections)
    _seed(revision, f"fhrp.instances.{instance_id}.virtual_ips.{vip_id}.address", normalized)
    return vip


# NAT ----------------------------------------------------------------------

def get_nat_pool(revision, pool_id):
    return _owned(_sections(revision)["nat"]["pools"], pool_id, "NAT pool")


def get_nat_rule(revision, rule_id):
    return _owned(_sections(revision)["nat"]["rules"], rule_id, "NAT rule")


@transaction.atomic
def add_nat_pool(*, revision, family="NAT44", name=""):
    require_draft(revision)
    if family not in NAT_FAMILIES:
        raise CollectionMutationError("Unknown NAT translation family.")
    _require_supported(revision, f"NAT_POOL_{family}", f"{family} pools")
    sections = _sections(revision)
    pools = sections["nat"]["pools"]
    if len(pools) >= MAX_NAT_POOLS:
        raise CollectionLimitError(f"A candidate may contain at most {MAX_NAT_POOLS} NAT pools.")
    pool_id = _new_id("pool")
    pool = {"id": pool_id, "sequence": _next_sequence(pools), "name": name, "family": family,
            "start_address": "", "end_address": "", "prefix_length": None, "description": ""}
    pools[pool_id] = pool
    _save(revision, sections)
    for field in NAT_POOL_FIELDS:
        _seed(revision, f"nat.pools.{pool_id}.{field}", pool[field])
    return pool


@transaction.atomic
def add_nat_rule(*, revision, family="NAT44", mode="PAT"):
    require_draft(revision)
    if family not in NAT_FAMILIES or mode not in NAT_MODES:
        raise CollectionMutationError("Unknown NAT family or mode.")
    _require_supported(revision, f"NAT_{family}_{mode}", f"{family} {mode}")
    sections = _sections(revision)
    rules = sections["nat"]["rules"]
    if len(rules) >= MAX_NAT_RULES:
        raise CollectionLimitError(f"A candidate may contain at most {MAX_NAT_RULES} NAT rules.")
    rule_id = _new_id("nat")
    rule = {"id": rule_id, "sequence": _next_sequence(rules), "family": family, "mode": mode,
            "original_source": "", "translated_source": "", "pool_id": "", "protocol": "IP",
            "original_port": "", "translated_port": "", "inside_interface_id": "",
            "outside_interface_id": "", "description": "", "enabled": True}
    rules[rule_id] = rule
    _save(revision, sections)
    for field in NAT_RULE_FIELDS:
        _seed(revision, f"nat.rules.{rule_id}.{field}", rule[field])
    return rule


# Services -----------------------------------------------------------------

def get_dhcp_relay(revision, relay_id):
    return _owned(_sections(revision)["services"]["dhcp"]["relays"], relay_id, "DHCP relay")


def get_dhcp_client(revision, client_id):
    return _owned(_sections(revision)["services"]["dhcp"]["clients"], client_id, "DHCP client")


def get_dns_resolver(revision, resolver_id):
    return _owned(_sections(revision)["services"]["dns"]["resolvers"], resolver_id, "DNS resolver")


def get_dns_domain(revision, domain_id):
    return _owned(_sections(revision)["services"]["dns"]["search_domains"], domain_id, "DNS search domain")


@transaction.atomic
def set_service_mode(*, revision, service: str, mode: str):
    require_draft(revision)
    if service not in ("dhcp", "dns", "monitoring") or mode not in INHERITANCE_MODES:
        raise CollectionMutationError("Unknown service or inheritance mode.")
    if mode == "OVERRIDE":
        _require_supported(revision, f"{service.upper()}_OVERRIDE", f"{service.upper()} override")
    sections = _sections(revision)
    sections["services"][service]["mode"] = mode
    _save(revision, sections)
    _seed(revision, f"services.{service}.mode", mode)
    return sections["services"][service]


@transaction.atomic
def add_dhcp_relay(*, revision, family="IPV4", interface_id="", destination=""):
    require_draft(revision)
    if family not in ADDRESS_FAMILIES:
        raise CollectionMutationError("Unknown DHCP relay address family.")
    _require_supported(revision, f"DHCP_RELAY_{family}", f"DHCP relay {family}")
    _get_interface(revision, interface_id)
    version = 4 if family == "IPV4" else 6
    ok, normalized, message = field_validators.validate_ip_host(destination, family=version, label="Relay destination")
    if not ok or not normalized:
        raise CollectionMutationError(message or "Relay destination is required.")
    sections = _sections(revision)
    relays = sections["services"]["dhcp"]["relays"]
    if len(relays) >= MAX_DHCP_RELAYS:
        raise CollectionLimitError(f"A candidate may contain at most {MAX_DHCP_RELAYS} DHCP relay destinations.")
    relay_id = _new_id("dhcp")
    relay = {"id": relay_id, "sequence": _next_sequence(relays), "family": family,
             "interface_id": interface_id, "destination": normalized, "description": ""}
    relays[relay_id] = relay
    sections["services"]["dhcp"]["mode"] = "OVERRIDE"
    _save(revision, sections)
    for field in DHCP_RELAY_FIELDS:
        _seed(revision, f"services.dhcp.relays.{relay_id}.{field}", relay[field])
    _seed(revision, "services.dhcp.mode", "OVERRIDE")
    return relay


@transaction.atomic
def set_dhcp_relay_option82(*, revision, relay_id, enabled=True, circuit_id="", remote_id=""):
    """V2 Phase 9: DHCP relay agent information (option 82) on one IPv4 relay object (Arista EOS only; see
    ``dhcp_relay_option82``).  Stored as ``relay['option82']``; the interface the relay sits on is the option 82 port."""
    from . import dhcp_relay_option82

    require_draft(revision)
    sections = _sections(revision)
    relay = _owned(sections["services"]["dhcp"]["relays"], relay_id, "DHCP relay")
    if relay.get("family") != "IPV4":
        raise CollectionMutationError("DHCP relay option 82 applies to IPv4 relays only.")
    interface = _get_interface(revision, relay.get("interface_id") or "")
    intent = dhcp_relay_option82.Option82Intent(str(interface.get("name") or ""), circuit_id, remote_id, enabled)
    problems = dhcp_relay_option82.validate_intent(revision.device_intent.platform, intent)
    if problems:
        raise CollectionMutationError(f"{problems[0]['code']}: {problems[0]['detail']}")
    relay["option82"] = {"enabled": enabled, "circuit_id": circuit_id, "remote_id": remote_id}
    _save(revision, sections)
    return relay


@transaction.atomic
def add_dhcp_client(*, revision, family="IPV4", interface_id=""):
    require_draft(revision)
    if family not in ADDRESS_FAMILIES:
        raise CollectionMutationError("Unknown DHCP client family.")
    interface = _get_interface(revision, interface_id)
    if interface_intent_service.is_management_static(interface):
        raise CollectionMutationError("VLAN 200/management is statically managed and cannot use DHCP or DHCPv6 client mode.")
    _require_supported(revision, f"DHCP_CLIENT_{family}", f"DHCP client {family}")
    sections = _sections(revision)
    clients = sections["services"]["dhcp"]["clients"]
    if len(clients) >= MAX_DHCP_CLIENTS:
        raise CollectionLimitError(f"A candidate may contain at most {MAX_DHCP_CLIENTS} DHCP client attachments.")
    object_id = _new_id("dhcp")
    obj = {"id": object_id, "sequence": _next_sequence(clients), "family": family,
           "interface_id": interface_id, "description": ""}
    clients[object_id] = obj
    sections["services"]["dhcp"]["mode"] = "OVERRIDE"
    _save(revision, sections)
    for field in DHCP_CLIENT_FIELDS:
        _seed(revision, f"services.dhcp.clients.{object_id}.{field}", obj[field])
    return obj


@transaction.atomic
def add_dns_resolver(*, revision, address=""):
    require_draft(revision)
    _require_supported(revision, "DNS_OVERRIDE", "DNS override")
    ok4, normalized, _ = field_validators.validate_ip_host(address, family=4, label="Resolver")
    family = "IPV4"
    if not ok4 or not normalized:
        ok6, normalized, message = field_validators.validate_ip_host(address, family=6, label="Resolver")
        family = "IPV6"
        if not ok6 or not normalized:
            raise CollectionMutationError(message or "Resolver address is required.")
    sections = _sections(revision)
    resolvers = sections["services"]["dns"]["resolvers"]
    if len(resolvers) >= MAX_DNS_RESOLVERS:
        raise CollectionLimitError(f"A candidate may contain at most {MAX_DNS_RESOLVERS} DNS resolvers.")
    object_id = _new_id("dns")
    obj = {"id": object_id, "sequence": _next_sequence(resolvers), "family": family, "address": normalized}
    resolvers[object_id] = obj
    sections["services"]["dns"]["mode"] = "OVERRIDE"
    _save(revision, sections)
    for field in DNS_RESOLVER_FIELDS:
        _seed(revision, f"services.dns.resolvers.{object_id}.{field}", obj[field])
    return obj


@transaction.atomic
def add_dns_search_domain(*, revision, domain=""):
    require_draft(revision)
    _require_supported(revision, "DNS_OVERRIDE", "DNS override")
    ok, normalized, message = field_validators.validate_domain_name(domain, required=True)
    if not ok:
        raise CollectionMutationError(message)
    sections = _sections(revision)
    domains = sections["services"]["dns"]["search_domains"]
    if len(domains) >= MAX_SEARCH_DOMAINS:
        raise CollectionLimitError(f"A candidate may contain at most {MAX_SEARCH_DOMAINS} DNS search domains.")
    object_id = _new_id("dns")
    obj = {"id": object_id, "sequence": _next_sequence(domains), "domain": normalized}
    domains[object_id] = obj
    sections["services"]["dns"]["mode"] = "OVERRIDE"
    _save(revision, sections)
    _seed(revision, f"services.dns.search_domains.{object_id}.domain", normalized)
    return obj


# ACL ----------------------------------------------------------------------

def get_acl(revision, acl_id):
    return _owned(_sections(revision)["security"]["acls"], acl_id, "ACL")


def get_ace(revision, acl_id, ace_id):
    return _owned(get_acl(revision, acl_id).get("entries") or {}, ace_id, "ACE")


def get_acl_attachment(revision, attachment_id):
    return _owned(_sections(revision)["security"]["attachments"], attachment_id, "ACL attachment")


@transaction.atomic
def add_acl(*, revision, name="", family="IPV4", acl_type="EXTENDED"):
    require_draft(revision)
    if family not in ACL_FAMILIES or acl_type not in ACL_TYPES:
        raise CollectionMutationError("Unknown ACL family or type.")
    _require_supported(revision, f"ACL_{family}_{acl_type}", f"{family} {acl_type} ACL")
    ok, normalized, message = field_validators.validate_acl_name(name)
    if not ok:
        raise CollectionMutationError(message)
    sections = _sections(revision)
    acls = sections["security"]["acls"]
    if len(acls) >= MAX_ACLS:
        raise CollectionLimitError(f"A candidate may contain at most {MAX_ACLS} ACLs.")
    acl_id = _new_id("acl")
    acl = {"id": acl_id, "sequence": _next_sequence(acls), "name": normalized, "family": family,
           "acl_type": acl_type, "description": "", "entries": {}}
    acls[acl_id] = acl
    _save(revision, sections)
    for field in ACL_FIELDS:
        _seed(revision, f"security.acls.{acl_id}.{field}", acl[field])
    return acl


@transaction.atomic
def add_ace(*, revision, acl_id, action="PERMIT", protocol="IP"):
    require_draft(revision)
    acl = get_acl(revision, acl_id)
    if action not in ACL_ACTIONS or protocol not in ACL_PROTOCOLS:
        raise CollectionMutationError("Unknown ACL action or protocol.")
    sections = _sections(revision)
    entries = sections["security"]["acls"][acl_id].setdefault("entries", {})
    if len(entries) >= MAX_ACES_PER_ACL:
        raise CollectionLimitError(f"An ACL may contain at most {MAX_ACES_PER_ACL} entries.")
    ace_id = _new_id("ace")
    obj = {"id": ace_id, "sequence": _next_rule_sequence(entries), "action": action, "protocol": protocol,
           "source_type": "ANY", "source_value": "", "destination_type": "ANY", "destination_value": "",
           "source_port": "", "destination_port": "", "description": "", "logging": False}
    entries[ace_id] = obj
    _save(revision, sections)
    for field in ACE_FIELDS:
        _seed(revision, f"security.acls.{acl_id}.entries.{ace_id}.{field}", obj[field])
    return obj


@transaction.atomic
def add_acl_attachment(*, revision, acl_id, interface_id, direction="IN"):
    require_draft(revision)
    acl = get_acl(revision, acl_id)
    _get_interface(revision, interface_id)
    if direction not in DIRECTIONS:
        raise CollectionMutationError("Unknown ACL direction.")
    _require_supported(revision, f"ACL_ATTACH_{acl['family']}", f"{acl['family']} ACL attachment")
    sections = _sections(revision)
    attachments = sections["security"]["attachments"]
    if len(attachments) >= MAX_ACL_ATTACHMENTS:
        raise CollectionLimitError(f"A candidate may contain at most {MAX_ACL_ATTACHMENTS} ACL attachments.")
    object_id = _new_id("attach")
    obj = {"id": object_id, "sequence": _next_sequence(attachments), "acl_id": acl_id,
           "interface_id": interface_id, "direction": direction}
    attachments[object_id] = obj
    _save(revision, sections)
    for field in ACL_ATTACHMENT_FIELDS:
        _seed(revision, f"security.attachments.{object_id}.{field}", obj[field])
    return obj


# PBR ----------------------------------------------------------------------

def get_pbr_policy(revision, policy_id):
    return _owned(_sections(revision)["policy"]["pbr"]["policies"], policy_id, "PBR policy")


def get_pbr_sequence(revision, policy_id, sequence_id):
    return _owned(get_pbr_policy(revision, policy_id).get("sequences") or {}, sequence_id, "PBR sequence")


def get_pbr_attachment(revision, attachment_id):
    return _owned(_sections(revision)["policy"]["pbr"]["attachments"], attachment_id, "PBR attachment")


@transaction.atomic
def add_pbr_policy(*, revision, name="", family="IPV4"):
    require_draft(revision)
    if family not in ADDRESS_FAMILIES:
        raise CollectionMutationError("Unknown PBR family.")
    _require_supported(revision, f"PBR_{family}", f"PBR {family}")
    ok, normalized, message = field_validators.validate_acl_name(name)
    if not ok:
        raise CollectionMutationError(message)
    sections = _sections(revision)
    policies = sections["policy"]["pbr"]["policies"]
    if len(policies) >= MAX_PBR_POLICIES:
        raise CollectionLimitError(f"A candidate may contain at most {MAX_PBR_POLICIES} PBR policies.")
    object_id = _new_id("pbr")
    obj = {"id": object_id, "sequence": _next_sequence(policies), "name": normalized,
           "family": family, "description": "", "sequences": {}}
    policies[object_id] = obj
    _save(revision, sections)
    for field in PBR_POLICY_FIELDS:
        _seed(revision, f"policy.pbr.policies.{object_id}.{field}", obj[field])
    return obj


@transaction.atomic
def add_pbr_sequence(*, revision, policy_id):
    require_draft(revision)
    get_pbr_policy(revision, policy_id)
    sections = _sections(revision)
    sequences = sections["policy"]["pbr"]["policies"][policy_id].setdefault("sequences", {})
    if len(sequences) >= MAX_PBR_SEQUENCES:
        raise CollectionLimitError(f"A PBR policy may contain at most {MAX_PBR_SEQUENCES} sequences.")
    object_id = _new_id("pbrseq")
    obj = {"id": object_id, "sequence": _next_rule_sequence(sequences), "source_prefix": "",
           "destination_prefix": "", "protocol": "IP", "next_hop": "", "output_interface_id": "",
           "description": ""}
    sequences[object_id] = obj
    _save(revision, sections)
    for field in PBR_SEQUENCE_FIELDS:
        _seed(revision, f"policy.pbr.policies.{policy_id}.sequences.{object_id}.{field}", obj[field])
    return obj


@transaction.atomic
def add_pbr_attachment(*, revision, policy_id, interface_id, direction="IN"):
    require_draft(revision)
    policy = get_pbr_policy(revision, policy_id)
    _get_interface(revision, interface_id)
    if direction != "IN":
        raise CollectionMutationError("PBR attachment direction must be IN for the current model.")
    _require_supported(revision, f"PBR_ATTACH_{policy['family']}", f"PBR {policy['family']} attachment")
    sections = _sections(revision)
    attachments = sections["policy"]["pbr"]["attachments"]
    if len(attachments) >= MAX_PBR_ATTACHMENTS:
        raise CollectionLimitError(f"A candidate may contain at most {MAX_PBR_ATTACHMENTS} PBR attachments.")
    object_id = _new_id("attach")
    obj = {"id": object_id, "sequence": _next_sequence(attachments), "policy_id": policy_id,
           "interface_id": interface_id, "direction": direction}
    attachments[object_id] = obj
    _save(revision, sections)
    for field in PBR_ATTACHMENT_FIELDS:
        _seed(revision, f"policy.pbr.attachments.{object_id}.{field}", obj[field])
    return obj


# Generic confirmed removal and field mirroring ----------------------------

_REMOVE_MAP = {
    "fhrp": ("fhrp", "instances"), "nat_pool": ("nat", "pools"), "nat_rule": ("nat", "rules"),
    "dhcp_relay": ("services", "dhcp", "relays"), "dhcp_client": ("services", "dhcp", "clients"),
    "dns_resolver": ("services", "dns", "resolvers"), "dns_domain": ("services", "dns", "search_domains"),
    "acl": ("security", "acls"), "acl_attachment": ("security", "attachments"),
    "pbr": ("policy", "pbr", "policies"), "pbr_attachment": ("policy", "pbr", "attachments"),
}


@transaction.atomic
def remove_object(*, revision, kind: str, object_id: str, confirmation: str, parent_id: str = ""):
    require_draft(revision)
    if confirmation != "REMOVE":
        raise CollectionMutationError("Explicit REMOVE confirmation is required.")
    sections = _sections(revision)
    if kind == "fhrp_vip":
        parent = _owned(sections["fhrp"]["instances"], parent_id, "FHRP instance")
        collection = parent.setdefault("virtual_ips", {})
        prefix = f"fhrp.instances.{parent_id}.virtual_ips.{object_id}."
    elif kind == "ace":
        parent = _owned(sections["security"]["acls"], parent_id, "ACL")
        collection = parent.setdefault("entries", {})
        prefix = f"security.acls.{parent_id}.entries.{object_id}."
    elif kind == "pbr_sequence":
        parent = _owned(sections["policy"]["pbr"]["policies"], parent_id, "PBR policy")
        collection = parent.setdefault("sequences", {})
        prefix = f"policy.pbr.policies.{parent_id}.sequences.{object_id}."
    else:
        keys = _REMOVE_MAP.get(kind)
        if not keys:
            raise CollectionMutationError("Unknown collection type.")
        if kind == "nat_pool" and any(
            rule.get("pool_id") == object_id for rule in sections["nat"]["rules"].values()
        ):
            raise CollectionMutationError("Remove or reassign NAT rules before removing this pool.")
        if kind == "acl" and any(
            attachment.get("acl_id") == object_id
            for attachment in sections["security"]["attachments"].values()
        ):
            raise CollectionMutationError("Detach this ACL before removing its definition.")
        if kind == "pbr" and any(
            attachment.get("policy_id") == object_id
            for attachment in sections["policy"]["pbr"]["attachments"].values()
        ):
            raise CollectionMutationError("Detach this PBR policy before removing its definition.")
        collection = sections
        for key in keys:
            collection = collection[key]
        prefix_map = {
            "fhrp": "fhrp.instances", "nat_pool": "nat.pools", "nat_rule": "nat.rules",
            "dhcp_relay": "services.dhcp.relays", "dhcp_client": "services.dhcp.clients",
            "dns_resolver": "services.dns.resolvers", "dns_domain": "services.dns.search_domains",
            "acl": "security.acls", "acl_attachment": "security.attachments",
            "pbr": "policy.pbr.policies", "pbr_attachment": "policy.pbr.attachments",
        }
        prefix = f"{prefix_map[kind]}.{object_id}."
    _owned(collection, object_id, kind.replace("_", " ").title())
    del collection[object_id]
    _save(revision, sections)
    revision.field_states.filter(path__startswith=prefix).delete()


def _field_target(sections: dict, path: str):
    parts = path.split(".")
    # Explicit shapes only; never a generic arbitrary JSON traversal.
    patterns = [
        (("fhrp", "instances"), FHRP_FIELDS, 4),
        (("fhrp", "instances", "*", "virtual_ips"), FHRP_VIP_FIELDS, 6),
        (("nat", "pools"), NAT_POOL_FIELDS, 4), (("nat", "rules"), NAT_RULE_FIELDS, 4),
        (("services", "dhcp", "relays"), DHCP_RELAY_FIELDS, 5),
        (("services", "dhcp", "clients"), DHCP_CLIENT_FIELDS, 5),
        (("services", "dns", "resolvers"), DNS_RESOLVER_FIELDS, 5),
        (("services", "dns", "search_domains"), DNS_DOMAIN_FIELDS, 5),
        (("security", "acls"), ACL_FIELDS, 4),
        (("security", "acls", "*", "entries"), ACE_FIELDS, 6),
        (("security", "attachments"), ACL_ATTACHMENT_FIELDS, 4),
        (("policy", "pbr", "policies"), PBR_POLICY_FIELDS, 5),
        (("policy", "pbr", "policies", "*", "sequences"), PBR_SEQUENCE_FIELDS, 7),
        (("policy", "pbr", "attachments"), PBR_ATTACHMENT_FIELDS, 5),
    ]
    for prefix, fields, length in patterns:
        if len(parts) != length or parts[-1] not in fields:
            continue
        if len(prefix) == 2 and parts[:2] == list(prefix):
            return sections[prefix[0]][prefix[1]].get(parts[2]), parts[-1]
        if prefix == ("fhrp", "instances", "*", "virtual_ips") and parts[:2] == ["fhrp", "instances"]:
            parent = sections["fhrp"]["instances"].get(parts[2]) or {}
            return (parent.get("virtual_ips") or {}).get(parts[4]), parts[-1]
        if prefix[:3] == tuple(parts[:3]) and "*" not in prefix:
            return sections[prefix[0]][prefix[1]][prefix[2]].get(parts[3]), parts[-1]
        if prefix == ("security", "acls", "*", "entries") and parts[:2] == ["security", "acls"]:
            parent = sections["security"]["acls"].get(parts[2]) or {}
            return (parent.get("entries") or {}).get(parts[4]), parts[-1]
        if prefix == ("policy", "pbr", "policies") and parts[:3] == ["policy", "pbr", "policies"]:
            return sections["policy"]["pbr"]["policies"].get(parts[3]), parts[-1]
        if prefix == ("policy", "pbr", "policies", "*", "sequences") and parts[:3] == ["policy", "pbr", "policies"]:
            parent = sections["policy"]["pbr"]["policies"].get(parts[3]) or {}
            return (parent.get("sequences") or {}).get(parts[5]), parts[-1]
        if prefix == ("policy", "pbr", "attachments") and parts[:3] == ["policy", "pbr", "attachments"]:
            return sections["policy"]["pbr"]["attachments"].get(parts[3]), parts[-1]
    if parts in (["services", "dhcp", "mode"], ["services", "dns", "mode"], ["services", "monitoring", "mode"]):
        return sections["services"][parts[1]], "mode"
    if parts == ["services", "dns", "domain_name"]:
        return sections["services"]["dns"], "domain_name"
    return None, None


@transaction.atomic
def mirror_accepted_field(*, revision, path: str, value):
    require_draft(revision)
    sections = _sections(revision)
    target, field = _field_target(sections, path)
    if not target or field is None:
        raise CollectionOwnershipError("Phase-12 field does not belong to this candidate revision.")
    target[field] = value
    _save(revision, sections)


def editor_summary(*, revision, platform: str) -> dict:
    sections = _sections(revision)
    interfaces = interface_intent_service.ordered_interfaces(revision)
    fhrp = deepcopy(ordered(sections["fhrp"]["instances"]))
    for instance in fhrp:
        instance["paths"] = {field: f"fhrp.instances.{instance['id']}.{field}" for field in FHRP_FIELDS}
        instance["virtual_ips_ordered"] = deepcopy(ordered(instance.get("virtual_ips") or {}))
        for vip in instance["virtual_ips_ordered"]:
            vip["paths"] = {field: f"fhrp.instances.{instance['id']}.virtual_ips.{vip['id']}.{field}" for field in FHRP_VIP_FIELDS}
    pools = deepcopy(ordered(sections["nat"]["pools"]))
    for obj in pools:
        obj["paths"] = {field: f"nat.pools.{obj['id']}.{field}" for field in NAT_POOL_FIELDS}
    rules = deepcopy(ordered(sections["nat"]["rules"]))
    for obj in rules:
        obj["paths"] = {field: f"nat.rules.{obj['id']}.{field}" for field in NAT_RULE_FIELDS}
    acls = deepcopy(ordered(sections["security"]["acls"]))
    for acl in acls:
        acl["paths"] = {field: f"security.acls.{acl['id']}.{field}" for field in ACL_FIELDS}
        acl["entries_ordered"] = deepcopy(ordered(acl.get("entries") or {}))
        for ace in acl["entries_ordered"]:
            ace["paths"] = {field: f"security.acls.{acl['id']}.entries.{ace['id']}.{field}" for field in ACE_FIELDS}
    acl_attachments = deepcopy(ordered(sections["security"]["attachments"]))
    for obj in acl_attachments:
        obj["paths"] = {field: f"security.attachments.{obj['id']}.{field}" for field in ACL_ATTACHMENT_FIELDS}
    pbr_policies = deepcopy(ordered(sections["policy"]["pbr"]["policies"]))
    for policy in pbr_policies:
        policy["paths"] = {field: f"policy.pbr.policies.{policy['id']}.{field}" for field in PBR_POLICY_FIELDS}
        policy["sequences_ordered"] = deepcopy(ordered(policy.get("sequences") or {}))
        for row in policy["sequences_ordered"]:
            row["paths"] = {field: f"policy.pbr.policies.{policy['id']}.sequences.{row['id']}.{field}" for field in PBR_SEQUENCE_FIELDS}
    pbr_attachments = deepcopy(ordered(sections["policy"]["pbr"]["attachments"]))
    for obj in pbr_attachments:
        obj["paths"] = {field: f"policy.pbr.attachments.{obj['id']}.{field}" for field in PBR_ATTACHMENT_FIELDS}
    dhcp = deepcopy(sections["services"]["dhcp"])
    dhcp["relays_ordered"] = deepcopy(ordered(dhcp.get("relays") or {}))
    dhcp["clients_ordered"] = deepcopy(ordered(dhcp.get("clients") or {}))
    for obj in dhcp["relays_ordered"]:
        obj["paths"] = {field: f"services.dhcp.relays.{obj['id']}.{field}" for field in DHCP_RELAY_FIELDS}
    for obj in dhcp["clients_ordered"]:
        obj["paths"] = {field: f"services.dhcp.clients.{obj['id']}.{field}" for field in DHCP_CLIENT_FIELDS}
    dns = deepcopy(sections["services"]["dns"])
    dns["resolvers_ordered"] = deepcopy(ordered(dns.get("resolvers") or {}))
    dns["search_domains_ordered"] = deepcopy(ordered(dns.get("search_domains") or {}))
    for obj in dns["resolvers_ordered"]:
        obj["paths"] = {field: f"services.dns.resolvers.{obj['id']}.{field}" for field in DNS_RESOLVER_FIELDS}
    for obj in dns["search_domains_ordered"]:
        obj["paths"] = {field: f"services.dns.search_domains.{obj['id']}.{field}" for field in DNS_DOMAIN_FIELDS}
    return {
        "sections": sections,
        "interfaces": interfaces,
        "fhrp": fhrp,
        "nat_pools": pools,
        "nat_rules": rules,
        "dhcp": dhcp,
        "dns": dns,
        "monitoring": sections["services"]["monitoring"],
        "acls": acls,
        "acl_attachments": acl_attachments,
        "pbr_policies": pbr_policies,
        "pbr_attachments": pbr_attachments,
        "platform": platform,
    }


def has_incompatible_intent(*, revision, platform: str) -> bool:
    sections = _sections(revision)
    features = []
    features.extend(f"FHRP_{obj.get('protocol')}_{obj.get('address_family')}" for obj in sections["fhrp"]["instances"].values())
    features.extend(f"NAT_POOL_{obj.get('family')}" for obj in sections["nat"]["pools"].values())
    features.extend(f"NAT_{obj.get('family')}_{obj.get('mode')}" for obj in sections["nat"]["rules"].values())
    dhcp = sections["services"]["dhcp"]
    features.extend(f"DHCP_RELAY_{obj.get('family')}" for obj in dhcp["relays"].values())
    features.extend(f"DHCP_CLIENT_{obj.get('family')}" for obj in dhcp["clients"].values())
    if sections["services"]["dns"].get("mode") == "OVERRIDE":
        features.append("DNS_OVERRIDE")
    for acl in sections["security"]["acls"].values():
        features.append(f"ACL_{acl.get('family')}_{acl.get('acl_type')}")
    for attachment in sections["security"]["attachments"].values():
        acl = sections["security"]["acls"].get(attachment.get("acl_id"), {})
        features.append(f"ACL_ATTACH_{acl.get('family', 'IPV4')}")
    features.extend(f"PBR_{obj.get('family')}" for obj in sections["policy"]["pbr"]["policies"].values())
    return any(not _supported_for_platform(platform, feature) for feature in features)


def _supported_for_platform(platform: str, feature: str) -> bool:
    from . import platform_drivers
    return platform_drivers.is_service_policy_feature_selectable(platform, feature)
