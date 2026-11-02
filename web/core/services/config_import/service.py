"""Orchestrates one explicit, read-only existing-device import:

    resolve inventory -> authenticate (existing sessions) -> retrieve
    complete running config -> sanitize -> parse -> apply supported
    features to the draft -> preserve everything else immutably

Reuses the SAME read-only transport already built and verified for the
legacy-bootstrap capture (`core.services.bootstrap.capture` /
`core.services.health.live`) -- there is no second device-access mechanism.
Never mutates the device: every call below is a `show`-class read.
"""

from __future__ import annotations

import json
from dataclasses import dataclass

from django.db import transaction
from django.utils import timezone

from .. import (
    field_commit_service,
    interface_intent_service,
    routing_intent_service,
    service_policy_intent_service,
)
from ..bootstrap import capture
from ..bundles import canonical
from ..bundles.legacy_sanitize import SanitizeError, sanitize_config
from ..health import live
from . import parser_ceos, parser_frr, parser_iosxe, parser_iosxr, parser_sonic, parser_srlinux
from .schema import ParsedConfig, UnmanagedBlock

IMPORT_SCHEMA_VERSION = 2

# Phase 20.5: SR Linix, IOS XR, and SONiC have no deployed node in this lab, so
# there is no live capture transport for them (see `capture.SECTIONS`) -- but
# that is a LIVE VERIFICATION limitation, not a software-implementation
# limitation. `import_from_fixture` below runs the exact same canonical-apply
# pipeline as `import_existing_device`, against source text/JSON supplied
# directly (a fixture, or a real capture a future capture transport could
# provide) instead of a live fetch. It is fixture-tested only
# (docs/PHASE_20_5_PLATFORM_CAPABILITY_AUDIT.md "Evidence boundary") and is
# never wired into the "Import Live Configuration" UI action, which remains
# scoped to platforms that actually have a live capture transport.
FIXTURE_PARSERS = {
    "nokia_srlinux": (parser_srlinux.parse, parser_srlinux.PARSER_VERSION),
    "cisco_c8000v_iosxe": (parser_iosxe.parse, parser_iosxe.PARSER_VERSION),
    "cisco_iosxr": (parser_iosxr.parse, parser_iosxr.PARSER_VERSION),
    "sonic": (parser_sonic.parse, parser_sonic.PARSER_VERSION),
}

# Per-feature parser claims.  A platform-level parser must not imply that it
# semantically imports every feature in the catalogue.
PARSER_FEATURES = {
    "cisco_c8000v_iosxe": frozenset({
        "interface.ROUTED_PHYSICAL", "interface.SUBINTERFACE", "interface.LOOPBACK", "interface.MANAGEMENT",
        "routing.STATIC_IPV4", "routing.STATIC_IPV6",
    }),
}


@dataclass
class ImportResult:
    status: str            # "imported" | "unavailable"
    message: str = ""
    interfaces_imported: int = 0
    unmanaged_block_count: int = 0
    provenance: dict | None = None
    feature_counts: dict | None = None


def fetch_running_config_outcome(device_name: str, *, session_factory=None, now=None) -> tuple[dict | None, str, str]:
    """-> (device_entry-and-sanitized-sections, error code, error message). Read-only; never mutates the device.

    ``code`` is "" on success, else ``DEVICE_NOT_FOUND`` / ``UNSUPPORTED_PLATFORM`` / a sanitized ``health.live`` code
    (e.g. ``CREDENTIAL_NOT_CONFIGURED``, ``AUTH_FAILED``, ``TIMEOUT``) / ``SANITIZE_FAILED``, so callers can tell the
    real failure apart instead of parsing the message."""
    scope = capture.managed_scope()
    entry = scope.get(device_name)
    if entry is None:
        return None, "DEVICE_NOT_FOUND", f"{device_name!r} is not a managed inventory device."
    now = now or timezone.now()
    platform = entry.get("platform", "")
    if platform not in capture.SECTIONS:
        return None, "UNSUPPORTED_PLATFORM", f"No read-only capture transport is defined for platform {platform!r}."

    requested_keys = capture.raw_keys(platform) + (("addr",) if platform == "linux" else ())
    evidence, raw, errors = live.read_device_with_raw(entry, requested_keys, session_factory=session_factory, now=now)
    read = capture.DeviceRead(entry, evidence, raw, errors, now)
    if read.evidence.live_error:
        return None, read.evidence.live_error, f"Could not read {device_name}: {read.evidence.live_error}"
    sections, problems = capture.sanitize_sections(read)
    # ``addr`` is already the fixed read-only Linux reachability probe. Ask
    # for its raw JSON in the same session and sanitize it here for config
    # import only; changing legacy-bootstrap's persisted section contract is
    # neither necessary nor desirable.
    if platform == "linux" and "addr" in raw and "addr" not in errors:
        try:
            cleaned = sanitize_config(raw["addr"])
            sections.append({
                "name": "linux-address-state", "command_key": "addr", "command": "ip -j addr show",
                "sanitized": cleaned.text, "sha256": canonical.text_hash(cleaned.text),
            })
        except SanitizeError as exc:
            problems.append(f"{device_name}:linux-address-state:{exc}")
    if problems:
        return None, "SANITIZE_FAILED", f"Could not read {device_name}: {problems[0]}"
    return {"entry": entry, "read": read, "sections": sections}, "", ""


def _fetch_sanitized_running_config(device_name: str, *, session_factory=None, now=None) -> tuple[dict | None, str]:
    """-> (device_entry-and-sanitized-sections, error-message). Read-only; never mutates the device."""
    fetched, _code, message = fetch_running_config_outcome(device_name, session_factory=session_factory, now=now)
    return fetched, message


def fetch_sanitized_running_config(device_name: str, *, session_factory=None, now=None) -> tuple[dict | None, str]:
    """Public name for the ONE read-only, sanitized running-config acquisition path (also used by the automation workbench)."""
    return _fetch_sanitized_running_config(device_name, session_factory=session_factory, now=now)


def running_config_digest(sections: list[dict]) -> str:
    """The provenance digest of a sanitized capture (identical for an import and a workbench snapshot)."""
    return canonical.text_hash("\n".join(s["sanitized"] for s in sections))


def _commit(*, change, intent, revision, path: str, value) -> None:
    field_commit_service.commit_field(
        change=change, intent=intent, revision=revision, path=path, raw_value=value
    )


def _prior_import_ids(revision) -> dict:
    value = ((revision.sections or {}).get("_import") or {}).get("managed_object_ids") or {}
    return value if isinstance(value, dict) else {}


def _remove_prior_import_objects(revision) -> None:
    """Replace only objects owned by the previous explicit import.

    Operator-authored objects have no entry in ``managed_object_ids`` and are
    untouched. This makes re-import rediscover direct CLI changes instead of
    silently retaining stale imported values or creating duplicates.
    """
    owned = _prior_import_ids(revision)
    if not owned:
        return
    sections = dict(revision.sections or {})
    locations = {
        "interfaces": ("interfaces",), "static_routes": ("routing", "static_routes"),
        "rip": ("routing", "rip"), "ospf": ("routing", "ospf"), "bgp": ("routing", "bgp"),
        "fhrp": ("fhrp", "instances"), "nat_rules": ("nat", "rules"),
        "dhcp_relays": ("services", "dhcp", "relays"), "acls": ("security", "acls"),
        "acl_attachments": ("security", "attachments"),
        # V2 Phase 4 management VRF (objects carry no field states; the prefixes below match nothing)
        "mgmt_vrfs": ("management", "vrfs"), "mgmt_bindings": ("management", "bindings"),
        "mgmt_routes": ("management", "routes"), "mgmt_services": ("management", "services"),
    }
    path_prefixes = {
        "interfaces": "interfaces", "static_routes": "routing.static_routes", "rip": "routing.rip",
        "ospf": "routing.ospf", "bgp": "routing.bgp", "fhrp": "fhrp.instances",
        "nat_rules": "nat.rules", "dhcp_relays": "services.dhcp.relays", "acls": "security.acls",
        "acl_attachments": "security.attachments",
        "mgmt_vrfs": "management.vrfs", "mgmt_bindings": "management.bindings",
        "mgmt_routes": "management.routes", "mgmt_services": "management.services",
    }
    # Every routing-instance family is owned and replaced the same way.  Without its entry a second import of the same
    # device would keep the first imported IS-IS process and add another one.
    for family in routing_intent_service.INSTANCE_FAMILIES:
        locations.setdefault(family, ("routing", family))
        path_prefixes.setdefault(family, f"routing.{family}")
    for category, ids in owned.items():
        keys = locations.get(category)
        if not keys or not isinstance(ids, list):
            continue
        target = sections
        for key in keys:
            target = target.get(key) if isinstance(target, dict) else None
        if not isinstance(target, dict):
            continue
        for object_id in ids:
            target.pop(object_id, None)
            revision.field_states.filter(path__startswith=f"{path_prefixes[category]}.{object_id}.").delete()
    sections.pop("_import", None)
    if isinstance(sections.get("management"), dict) and not any(sections["management"].get(k) for k in ("vrfs", "bindings", "routes", "services")):
        sections.pop("management")              # an emptied management namespace leaves the document as it was
    revision.sections = sections
    revision.save(update_fields=["sections"])


def _append_preserved(parsed: ParsedConfig, label: str, header: str, lines: list[str]) -> None:
    if lines:
        parsed.unmanaged_blocks.append(UnmanagedBlock(
            label=label, classification="RECOGNIZED_UNSUPPORTED", lines=[header, *lines]
        ))


def _apply_parsed_config(*, change, intent, revision, parsed: ParsedConfig,
                         existing_interface_ids: dict | None = None) -> tuple[int, dict, dict]:
    """Apply parsed records through canonical Device Builder services.

    Returns ``(interface_count, feature_counts, managed_object_ids)`` for
    provenance/re-import ownership.  No parser writes ``revision.sections``
    directly.

    ``existing_interface_ids`` ({name: id}) lets records reference interfaces
    that are ALREADY in the revision (V2 Phase 3: a template overlay on an
    imported running configuration) instead of only the ones created here.
    """
    if parsed.hostname:
        _commit(change=change, intent=intent, revision=revision, path="device.hostname", value=parsed.hostname)
    interface_ids: dict[str, str] = dict(existing_interface_ids or {})
    managed_ids = {name: [] for name in (
        "interfaces", "static_routes", "rip", "ospf", "bgp", "fhrp", "nat_rules",
        "dhcp_relays", "acls", "acl_attachments",
    )}
    # Every routing-instance family a parser can return has its list: the instance loop below indexes this by family.
    # (IS-IS was parsed, modelled and rendered but had no entry here, so importing ``router isis`` raised KeyError.)
    for family in routing_intent_service.INSTANCE_FAMILIES:
        managed_ids.setdefault(family, [])
    counts = {"interfaces": 0, "addresses": 0, "static_routes": 0, "routing_instances": 0,
              "neighbors": 0, "networks": 0, "fhrp": 0, "dhcp_relays": 0, "acls": 0,
              "nat_rules": 0}

    # Create every interface first so parent and cross-feature references can
    # be resolved in a deterministic second pass.
    for parsed_interface in parsed.interfaces:
        try:
            interface = interface_intent_service.add_interface(
                revision=revision, kind=parsed_interface.kind, name=parsed_interface.name
            )
        except interface_intent_service.CollectionMutationError as exc:
            _append_preserved(parsed, f"Interface {parsed_interface.name} (could not import: {exc})",
                              f"interface {parsed_interface.name}",
                              parsed_interface.preserved_lines or [f"interface {parsed_interface.name}"])
            continue
        if_id = interface["id"]
        interface_ids[parsed_interface.name] = if_id
        managed_ids["interfaces"].append(if_id); counts["interfaces"] += 1
        for field in ("description", "admin_state", "mtu", "access_vlan", "trunk_allowed_vlans",
                      "native_vlan", "encapsulation_vlan", "vlan_id"):
            value = getattr(parsed_interface, field)
            if value not in (None, "", []):
                _commit(change=change, intent=intent, revision=revision,
                        path=f"interfaces.{if_id}.{field}", value=value)
        for address in parsed_interface.addresses:
            added = interface_intent_service.add_address(
                revision=revision, interface_id=if_id, family=address["family"], source="MANUAL"
            )
            _commit(change=change, intent=intent, revision=revision,
                    path=f"interfaces.{if_id}.addresses.{added['id']}.cidr", value=address["cidr"])
            if address.get("role") == "SECONDARY":
                _commit(change=change, intent=intent, revision=revision,
                        path=f"interfaces.{if_id}.addresses.{added['id']}.role", value="SECONDARY")
            counts["addresses"] += 1
        _append_preserved(parsed, f"Additional configuration on interface {parsed_interface.name}",
                          f"interface {parsed_interface.name}", parsed_interface.preserved_lines)

    for parsed_interface in parsed.interfaces:
        if_id = interface_ids.get(parsed_interface.name)
        if not if_id:
            continue
        if parsed_interface.parent_name and parsed_interface.parent_name in interface_ids:
            _commit(change=change, intent=intent, revision=revision, path=f"interfaces.{if_id}.parent_id",
                    value=interface_ids[parsed_interface.parent_name])
        elif parsed_interface.parent_name:
            _append_preserved(
                parsed,
                f"Interface {parsed_interface.name} parent reference could not be resolved",
                f"interface {parsed_interface.name}",
                [f"parent {parsed_interface.parent_name}"],
            )

    for route in parsed.static_routes:
        obj = routing_intent_service.add_static_route(revision=revision, family=route.family)
        managed_ids["static_routes"].append(obj["id"]); counts["static_routes"] += 1
        base = f"routing.static_routes.{obj['id']}"
        _commit(change=change, intent=intent, revision=revision, path=f"{base}.destination", value=route.destination)
        if route.next_hop_address:
            _commit(change=change, intent=intent, revision=revision, path=f"{base}.next_hop_address", value=route.next_hop_address)
        elif route.next_hop_interface in interface_ids:
            _commit(change=change, intent=intent, revision=revision, path=f"{base}.next_hop_type", value="INTERFACE")
            _commit(change=change, intent=intent, revision=revision, path=f"{base}.next_hop_interface_id",
                    value=interface_ids[route.next_hop_interface])
        elif route.next_hop_interface:
            _append_preserved(
                parsed,
                f"Static route {route.destination} next-hop interface could not be resolved",
                f"route {route.destination}",
                route.lines or [f"next-hop interface {route.next_hop_interface}"],
            )
        if route.distance is not None:
            _commit(change=change, intent=intent, revision=revision, path=f"{base}.distance", value=route.distance)
        if route.tag is not None:
            _commit(change=change, intent=intent, revision=revision, path=f"{base}.tag", value=route.tag)

    for parsed_instance in parsed.routing_instances:
        family = parsed_instance.family
        kwargs = dict(parsed_instance.fields)
        instance = routing_intent_service.add_protocol_instance(revision=revision, family=family, **kwargs)
        managed_ids[family].append(instance["id"]); counts["routing_instances"] += 1
        for field in routing_intent_service.INSTANCE_FIELDS[family]:
            value = kwargs.get(field)
            if value not in (None, ""):
                _commit(change=change, intent=intent, revision=revision,
                        path=f"routing.{family}.{instance['id']}.{field}", value=value)
        for binding_data in parsed_instance.bindings:
            if_id = interface_ids.get(binding_data.get("interface_name", ""))
            if not if_id:
                _append_preserved(
                    parsed,
                    f"{family.upper()} interface binding could not be resolved",
                    f"router {family}",
                    [f"interface {binding_data.get('interface_name') or '(missing)'}"],
                )
                continue
            binding = routing_intent_service.add_interface_binding(
                revision=revision, family=family, instance_id=instance["id"], interface_id=if_id
            )
            for field in routing_intent_service.BINDING_FIELDS[family]:
                value = binding_data.get(field)
                if value not in (None, "", False):
                    _commit(change=change, intent=intent, revision=revision,
                            path=f"routing.{family}.{instance['id']}.interfaces.{binding['id']}.{field}", value=value)
        if family == "bgp":
            for neighbor_data in parsed_instance.neighbors:
                neighbor = routing_intent_service.add_bgp_neighbor(
                    revision=revision, instance_id=instance["id"], peer_address=neighbor_data["peer_address"],
                    remote_asn=neighbor_data["remote_asn"],
                )
                counts["neighbors"] += 1
                for field in routing_intent_service.BGP_NEIGHBOR_FIELDS:
                    value = neighbor_data.get(field)
                    if field == "update_source_interface":
                        continue
                    if value not in (None, "", False) and value != neighbor.get(field):
                        _commit(change=change, intent=intent, revision=revision,
                                path=f"routing.bgp.{instance['id']}.neighbors.{neighbor['id']}.{field}", value=value)
                source_id = interface_ids.get(neighbor_data.get("update_source_interface", ""))
                if source_id:
                    _commit(change=change, intent=intent, revision=revision,
                            path=f"routing.bgp.{instance['id']}.neighbors.{neighbor['id']}.update_source_interface_id",
                            value=source_id)
                elif neighbor_data.get("update_source_interface"):
                    _append_preserved(
                        parsed,
                        f"BGP neighbor {neighbor_data.get('peer_address')} update-source could not be resolved",
                        "router bgp",
                        [f"update-source {neighbor_data['update_source_interface']}"],
                    )
            for network in parsed_instance.networks:
                routing_intent_service.add_bgp_network(
                    revision=revision, instance_id=instance["id"], family=network["family"], cidr=network["cidr"]
                )
                counts["networks"] += 1
        elif family == "ospf":
            for network in parsed_instance.networks:
                routing_intent_service.add_ospf_network(
                    revision=revision, instance_id=instance["id"], prefix=network["prefix"], area=network["area"]
                )
                counts["networks"] += 1
        _append_preserved(parsed, f"Additional {family.upper()} configuration", f"router {family}",
                          parsed_instance.preserved_lines)

    acl_ids = {}
    for parsed_acl in parsed.acls:
        acl = service_policy_intent_service.add_acl(
            revision=revision, name=parsed_acl.name, family=parsed_acl.family, acl_type=parsed_acl.acl_type
        )
        acl_ids[(parsed_acl.family, parsed_acl.name.lower())] = acl["id"]
        managed_ids["acls"].append(acl["id"]); counts["acls"] += 1
        for entry in parsed_acl.entries:
            ace = service_policy_intent_service.add_ace(
                revision=revision, acl_id=acl["id"], action=entry["action"], protocol=entry["protocol"]
            )
            for field in service_policy_intent_service.ACE_FIELDS:
                value = entry.get(field)
                if value not in (None, "", False) and value != ace.get(field):
                    _commit(change=change, intent=intent, revision=revision,
                            path=f"security.acls.{acl['id']}.entries.{ace['id']}.{field}", value=value)
        _append_preserved(parsed, f"Additional ACL configuration for {parsed_acl.name}",
                          f"ip access-list {parsed_acl.name}", parsed_acl.preserved_lines)

    for parsed_interface in parsed.interfaces:
        if_id = interface_ids.get(parsed_interface.name)
        if not if_id:
            continue
        for relay in parsed_interface.dhcp_relays:
            obj = service_policy_intent_service.add_dhcp_relay(
                revision=revision, family=relay["family"], interface_id=if_id, destination=relay["destination"]
            )
            managed_ids["dhcp_relays"].append(obj["id"]); counts["dhcp_relays"] += 1
        for fhrp_data in parsed_interface.fhrp:
            obj = service_policy_intent_service.add_fhrp_instance(
                revision=revision, protocol=fhrp_data["protocol"], interface_id=if_id,
                address_family=fhrp_data["address_family"],
            )
            managed_ids["fhrp"].append(obj["id"]); counts["fhrp"] += 1
            if fhrp_data.get("virtual_mac"):
                _commit(change=change, intent=intent, revision=revision,
                        path=f"fhrp.instances.{obj['id']}.virtual_mac", value=fhrp_data["virtual_mac"])
            service_policy_intent_service.add_fhrp_vip(
                revision=revision, instance_id=obj["id"], address=fhrp_data["address"]
            )
        for attachment in parsed_interface.acl_attachments:
            acl_id = acl_ids.get((attachment["family"], attachment["name"].lower()))
            if acl_id:
                obj = service_policy_intent_service.add_acl_attachment(
                    revision=revision, acl_id=acl_id, interface_id=if_id, direction=attachment["direction"]
                )
                managed_ids["acl_attachments"].append(obj["id"])
            else:
                _append_preserved(
                    parsed,
                    f"ACL attachment on {parsed_interface.name} could not be resolved",
                    f"interface {parsed_interface.name}",
                    [
                        f"{attachment['family']} ACL {attachment['name']} "
                        f"direction {attachment['direction']}"
                    ],
                )

    for nat_data in parsed.nat_rules:
        obj = service_policy_intent_service.add_nat_rule(
            revision=revision, family=nat_data.family, mode=nat_data.mode
        )
        managed_ids["nat_rules"].append(obj["id"]); counts["nat_rules"] += 1
        if nat_data.original_source:
            _commit(change=change, intent=intent, revision=revision,
                    path=f"nat.rules.{obj['id']}.original_source", value=nat_data.original_source)
        if getattr(nat_data, "translated_source", ""):
            _commit(change=change, intent=intent, revision=revision,
                    path=f"nat.rules.{obj['id']}.translated_source", value=nat_data.translated_source)
        outside_id = interface_ids.get(nat_data.outside_interface)
        if outside_id:
            _commit(change=change, intent=intent, revision=revision,
                    path=f"nat.rules.{obj['id']}.outside_interface_id", value=outside_id)
        elif nat_data.outside_interface:
            _append_preserved(
                parsed,
                "NAT outside-interface reference could not be resolved",
                "nat rule",
                [f"outside interface {nat_data.outside_interface}"],
            )
    _apply_management(revision=revision, parsed=parsed, interface_ids=interface_ids, managed_ids=managed_ids, counts=counts)
    return counts["interfaces"], counts, {key: value for key, value in managed_ids.items() if value}


def _apply_management(*, revision, parsed: ParsedConfig, interface_ids: dict, managed_ids: dict, counts: dict) -> None:
    """V2 Phase 4: management-VRF records through the canonical ``management.vrf`` mutations.  A record the mutation
    refuses is preserved verbatim as unmanaged configuration (never dropped).  Nothing runs when the parser found none,
    so ``counts`` / ``managed_ids`` of every other import are unchanged."""
    records = getattr(parsed, "management", None) or {}
    if not any(records.get(key) for key in ("vrfs", "bindings", "routes", "services")):
        return
    from ..management import vrf as management_vrf

    vrf_ids: dict[str, str] = {}

    def attempt(label: str, lines: list[str], category: str, call):
        try:
            obj = call()
        except management_vrf.ManagementIntentError as exc:
            _append_preserved(parsed, f"{label} (could not import: {exc.code})", lines[0], lines[1:] or [lines[0]])
            return None
        managed_ids.setdefault(category, []).append(obj["id"])
        counts[category] = counts.get(category, 0) + 1
        return obj

    for record in records.get("vrfs", []):
        obj = attempt(f"Management VRF {record['name']}", record["lines"], "mgmt_vrfs",
                      lambda r=record: management_vrf.add_vrf(revision, name=r["name"], description=r["description"]))
        if obj:
            vrf_ids[record["name"]] = obj["id"]
    for category, key, label, make in (
            ("mgmt_bindings", "bindings", "Management VRF binding",
             lambda r, vid: management_vrf.add_binding(revision, vrf_id=vid, interface_id=interface_ids.get(r["interface"], ""))),
            ("mgmt_routes", "routes", "Management VRF route",
             lambda r, vid: management_vrf.add_route(revision, vrf_id=vid, destination=r["destination"], next_hop=r["next_hop"])),
            ("mgmt_services", "services", "Management VRF service",
             lambda r, vid: management_vrf.add_service(revision, vrf_id=vid, service=r["service"]))):
        for record in records.get(key, []):
            attempt(label, record["lines"], category, lambda r=record, m=make: m(r, vrf_ids.get(r["vrf"], "")))


# V2 Phase 3: the ONE canonical apply pipeline, public for the template clone (core.services.config_templates).
apply_parsed_config = _apply_parsed_config


def _store_unmanaged_and_provenance(
    *, revision, provenance: dict, unmanaged_blocks: list, unparsed_platform: bool = False,
    managed_object_ids: dict | None = None,
) -> None:
    sections = dict(revision.sections or {})
    sections["_import"] = {
        "schema_version": IMPORT_SCHEMA_VERSION,
        "provenance": provenance,
        "unparsed_platform": unparsed_platform,
        "managed_object_ids": managed_object_ids or {},
        "unmanaged": [
            {"label": b.label, "classification": b.classification, "text": "\n".join(b.lines)}
            for b in unmanaged_blocks
        ],
    }
    revision.sections = sections
    revision.save(update_fields=["sections"])


@transaction.atomic
def import_existing_device(
    *, change, intent, revision, device_name: str, session_factory=None, now=None
) -> ImportResult:
    """Read-only fetch + parse + apply, all-or-nothing on the fetch: a failed
    read never mutates `revision` and never creates partial draft state.
    Only ever called on an operator's explicit action -- never automatically."""
    fetched, error = _fetch_sanitized_running_config(device_name, session_factory=session_factory, now=now)
    if fetched is None:
        return ImportResult(status="unavailable", message=error)

    entry, read, sections = fetched["entry"], fetched["read"], fetched["sections"]
    platform = entry.get("platform", "")
    by_key = {section["command_key"]: section for section in sections}

    provenance = {
        "device": device_name,
        "platform": platform,
        "source": capture.transport_of(entry),
        "credential_ref": capture.credential_ref_of(entry),
        "captured_at": read.read_at.isoformat() if read.read_at else "",
        "config_digest": running_config_digest(sections),
        "parser_version": {
            "ceos": parser_ceos.PARSER_VERSION, "linux": parser_frr.PARSER_VERSION,
        }.get(platform, "none"),
    }

    if platform == "ceos" and "running_config" in by_key:
        parsed = parser_ceos.parse(by_key["running_config"]["sanitized"])
    elif platform == "linux" and "frr_config" in by_key:
        parsed = parser_frr.parse(
            by_key["frr_config"]["sanitized"],
            addr_json=(by_key.get("addr") or {}).get("sanitized", ""),
            nft_text=(by_key.get("nft") or {}).get("sanitized", ""),
            management_addresses=[entry.get("address"), entry.get("address_v6")],
        )
    else:
        # A real, sanitized read-only capture still happened; this project just
        # has no structured parser for this platform yet (honest, not fabricated
        # -- see docs/EXISTING_CONFIG_IMPORT.md). The whole capture is preserved.
        blocks = [
            UnmanagedBlock(
                label=f"Complete {section['name']} (no structured parser for platform {platform!r} yet)",
                classification="UNKNOWN", lines=section["sanitized"].splitlines(),
            )
            for section in sections
        ]
        _store_unmanaged_and_provenance(revision=revision, provenance=provenance, unmanaged_blocks=blocks, unparsed_platform=True)
        return ImportResult(status="imported", unmanaged_block_count=len(blocks), provenance=provenance)

    _remove_prior_import_objects(revision)
    imported_count, feature_counts, managed_ids = _apply_parsed_config(
        change=change, intent=intent, revision=revision, parsed=parsed
    )

    unmanaged_blocks = list(parsed.unmanaged_blocks)
    revision.refresh_from_db()
    _store_unmanaged_and_provenance(
        revision=revision, provenance=provenance, unmanaged_blocks=unmanaged_blocks,
        managed_object_ids=managed_ids,
    )
    return ImportResult(
        status="imported", interfaces_imported=imported_count,
        unmanaged_block_count=len(unmanaged_blocks), provenance=provenance, feature_counts=feature_counts,
    )


@transaction.atomic
def import_from_fixture(
    *, change, intent, revision, device_name: str, platform: str, source, now=None
) -> ImportResult:
    """Same canonical apply pipeline as `import_existing_device`, for a
    platform with no live capture transport in this lab (SR Linix, IOS XR,
    SONiC). `source` is parser-specific: JSON (str or dict) for SR Linix/
    SONiC, running-config text for IOS XR. Never called from the live
    "Import Live Configuration" UI action -- see `FIXTURE_PARSERS` docstring
    above."""
    if platform not in FIXTURE_PARSERS:
        return ImportResult(status="unavailable", message=f"No fixture importer is defined for platform {platform!r}.")
    if intent.platform != platform:
        return ImportResult(
            status="unavailable",
            message=(
                f"Fixture platform {platform!r} does not match candidate platform "
                f"{intent.platform!r}; no draft state was changed."
            ),
        )
    parse_fn, parser_version = FIXTURE_PARSERS[platform]
    now = now or timezone.now()
    source_text = source if isinstance(source, str) else json.dumps(source, sort_keys=True)
    parsed = parse_fn(source)

    provenance = {
        "device": device_name, "platform": platform,
        "source": "fixture (no live capture transport exists for this platform in this lab)",
        "credential_ref": "none (fixture)",
        "captured_at": now.isoformat(),
        "config_digest": canonical.text_hash(source_text),
        "parser_version": parser_version,
    }

    _remove_prior_import_objects(revision)
    imported_count, feature_counts, managed_ids = _apply_parsed_config(
        change=change, intent=intent, revision=revision, parsed=parsed
    )
    unmanaged_blocks = list(parsed.unmanaged_blocks)
    revision.refresh_from_db()
    _store_unmanaged_and_provenance(
        revision=revision, provenance=provenance, unmanaged_blocks=unmanaged_blocks,
        managed_object_ids=managed_ids,
    )
    return ImportResult(
        status="imported", interfaces_imported=imported_count,
        unmanaged_block_count=len(unmanaged_blocks), provenance=provenance, feature_counts=feature_counts,
    )
