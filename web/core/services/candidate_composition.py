"""Normalize feature intent into authoritative configuration scopes.

The editor persists feature-owned objects because that is the natural shape for
mutation and audit.  A network operating system does not render those objects
independently: several of them may own commands in the same interface, routing
process, or named-policy context.  This module is the boundary between those
two representations.

No vendor CLI lives here.  The result is still semantic intent, augmented with
scope-owned contributions.  Platform drivers consume it and are the only code
that turns the model into commands.
"""

from __future__ import annotations

import json
from copy import deepcopy
from dataclasses import asdict, dataclass
from typing import Callable, Hashable


ScopeKey = Callable[[str, dict], Hashable]


@dataclass(frozen=True)
class CompositionConflict:
    """Two non-identical contributions claim one single-valued scope slot."""

    scope_kind: str
    scope_id: str
    field: str
    existing: object
    incoming: object
    existing_source: str
    incoming_source: str

    def to_dict(self) -> dict:
        return asdict(self)


def _seq(row: dict) -> tuple:
    return (int(row.get("sequence") or 0), str(row.get("id") or ""))


def _canonical(value) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


def _semantic(row: dict, *, omit: tuple[str, ...] = ()) -> dict:
    ignored = {"id", "sequence", "_source", *omit}
    return {key: value for key, value in row.items() if key not in ignored}


class _Builder:
    def __init__(self, interfaces: list[dict]):
        self.conflicts: list[CompositionConflict] = []
        self.interfaces: list[dict] = []
        self.by_id: dict[str, dict] = {}
        self._by_name: dict[str, dict] = {}
        self._single: dict[tuple[str, str, str, str], tuple[object, str]] = {}
        self._many: dict[tuple[str, str, str, str], set[str]] = {}
        self._build_interfaces(interfaces)

    def conflict(
        self,
        *,
        scope_kind: str,
        scope_id: str,
        field: str,
        existing,
        incoming,
        existing_source: str,
        incoming_source: str,
    ) -> None:
        item = CompositionConflict(
            scope_kind=scope_kind,
            scope_id=scope_id,
            field=field,
            existing=existing,
            incoming=incoming,
            existing_source=existing_source,
            incoming_source=incoming_source,
        )
        if item not in self.conflicts:
            self.conflicts.append(item)

    def _build_interfaces(self, interfaces: list[dict]) -> None:
        """Create one normalized object per semantic interface name.

        Stable IDs remain valid references.  A historical/corrupt candidate
        with two IDs for one name is represented once and receives a conflict;
        it is never rendered as two copies of the same CLI context.
        """
        for raw in sorted(deepcopy(interfaces or []), key=_seq):
            interface_id = str(raw.get("id") or "")
            name = str(raw.get("name") or "")
            name_key = name.casefold() if name else f"__missing__:{interface_id}"
            existing = self._by_name.get(name_key)
            if existing is None:
                raw["_scope"] = {
                    "ospf": [],
                    "isis": [],
                    "fhrp": [],
                    "acl_attachments": [],
                    "pbr_attachments": [],
                    "nat_roles": [],
                    "dhcp_relays": [],
                }
                raw["_source_interface_ids"] = [interface_id]
                self._by_name[name_key] = raw
                self.interfaces.append(raw)
                existing = raw
            else:
                self.conflict(
                    scope_kind="INTERFACE",
                    scope_id=name or interface_id,
                    field="identity",
                    existing=existing.get("id"),
                    incoming=interface_id,
                    existing_source=f"interfaces.{existing.get('id')}",
                    incoming_source=f"interfaces.{interface_id}",
                )
                existing["_source_interface_ids"].append(interface_id)
                # Preserve non-identical addresses for a useful draft preview.
                known = {_canonical(_semantic(item)) for item in (existing.get("addresses") or {}).values()}
                for address_id, address in sorted((raw.get("addresses") or {}).items()):
                    marker = _canonical(_semantic(address))
                    if marker not in known:
                        copy = deepcopy(address)
                        copy["_source_interface_id"] = interface_id
                        existing.setdefault("addresses", {})[address_id] = copy
                        known.add(marker)
            if interface_id:
                self.by_id[interface_id] = existing

    def add_single(
        self,
        interface_id: str,
        bucket: str,
        slot: str,
        value: dict,
        *,
        semantic: object,
        source: str,
    ) -> None:
        interface = self.by_id.get(str(interface_id or ""))
        if interface is None:
            return
        scope_id = str(interface.get("name") or interface.get("id") or interface_id)
        key = ("INTERFACE", scope_id.casefold(), bucket, str(slot))
        prior = self._single.get(key)
        if prior is None:
            self._single[key] = (deepcopy(semantic), source)
            interface["_scope"][bucket].append(deepcopy(value))
            return
        if _canonical(prior[0]) == _canonical(semantic):
            return
        self.conflict(
            scope_kind="INTERFACE",
            scope_id=scope_id,
            field=f"{bucket}.{slot}",
            existing=prior[0],
            incoming=semantic,
            existing_source=prior[1],
            incoming_source=source,
        )

    def add_many(self, interface_id: str, bucket: str, slot: str, value: dict, *, semantic: object) -> None:
        interface = self.by_id.get(str(interface_id or ""))
        if interface is None:
            return
        scope_id = str(interface.get("name") or interface.get("id") or interface_id)
        key = ("INTERFACE", scope_id.casefold(), bucket, str(slot))
        seen = self._many.setdefault(key, set())
        marker = _canonical(semantic)
        if marker in seen:
            return
        seen.add(marker)
        interface["_scope"][bucket].append(deepcopy(value))


def _merge_child_collection(
    builder: _Builder,
    target: dict,
    incoming: dict,
    *,
    family: str,
    scope_id: str,
    collection: str,
    identity: Callable[[dict], Hashable],
) -> None:
    current = target.setdefault(collection, {})
    by_identity = {identity(row): row for row in current.values()}
    for row in sorted((incoming.get(collection) or {}).values(), key=_seq):
        key = identity(row)
        prior = by_identity.get(key)
        if prior is None:
            current[row["id"]] = deepcopy(row)
            by_identity[key] = current[row["id"]]
            continue
        left, right = _semantic(prior), _semantic(row)
        if _canonical(left) != _canonical(right):
            builder.conflict(
                scope_kind="ROUTING_PROCESS",
                scope_id=scope_id,
                field=f"{collection}.{key}",
                existing=left,
                incoming=right,
                existing_source=f"routing.{family}.{target.get('id')}.{collection}.{prior.get('id')}",
                incoming_source=f"routing.{family}.{incoming.get('id')}.{collection}.{row.get('id')}",
            )


def _merge_process(builder: _Builder, target: dict, incoming: dict, *, family: str, scope_id: str) -> None:
    children = ("neighbors", "networks") if family == "bgp" else ("interfaces",)
    for field, value in incoming.items():
        if field in {"id", "sequence", *children}:
            continue
        prior = target.get(field)
        if prior in (None, "") and value not in (None, ""):
            target[field] = deepcopy(value)
        elif value not in (None, "") and prior != value:
            builder.conflict(
                scope_kind="ROUTING_PROCESS",
                scope_id=scope_id,
                field=field,
                existing=prior,
                incoming=value,
                existing_source=f"routing.{family}.{target.get('id')}.{field}",
                incoming_source=f"routing.{family}.{incoming.get('id')}.{field}",
            )
    if family == "bgp":
        _merge_child_collection(
            builder, target, incoming, family=family, scope_id=scope_id, collection="neighbors",
            identity=lambda row: (row.get("family"), row.get("peer_address")),
        )
        _merge_child_collection(
            builder, target, incoming, family=family, scope_id=scope_id, collection="networks",
            identity=lambda row: (row.get("family"), row.get("cidr")),
        )
    else:
        _merge_child_collection(
            builder, target, incoming, family=family, scope_id=scope_id, collection="interfaces",
            identity=lambda row: row.get("interface_id"),
        )


def _compose_routing(builder: _Builder, routing: dict, process_scope_key: ScopeKey) -> dict:
    source = deepcopy(routing or {})
    result = {name: {} for name in ("static_routes", "rip", "ospf", "isis", "eigrp", "bgp")}

    route_markers: set[str] = set()
    for route in sorted((source.get("static_routes") or {}).values(), key=_seq):
        marker = _canonical(_semantic(route))
        if marker not in route_markers:
            result["static_routes"][route["id"]] = route
            route_markers.add(marker)

    for family in ("rip", "ospf", "isis", "eigrp", "bgp"):
        scopes: dict[Hashable, dict] = {}
        for instance in sorted((source.get(family) or {}).values(), key=_seq):
            key = process_scope_key(family, instance)
            scope_id = "/".join(str(part) for part in key) if isinstance(key, tuple) else str(key)
            prior = scopes.get(key)
            if prior is None:
                scopes[key] = deepcopy(instance)
                result[family][instance["id"]] = scopes[key]
            else:
                _merge_process(builder, prior, instance, family=family, scope_id=scope_id)
    return result


def _dedupe_named(
    builder: _Builder,
    mapping: dict,
    *,
    scope_kind: str,
    source_prefix: str,
) -> tuple[dict, dict[str, str]]:
    """Consolidate named CLI definition scopes and return old-ID aliases."""
    result: dict = {}
    aliases: dict[str, str] = {}
    by_name: dict[str, dict] = {}
    for row in sorted((mapping or {}).values(), key=_seq):
        object_id = str(row.get("id") or "")
        name = str(row.get("name") or "")
        key = name.casefold() if name else f"__missing__:{object_id}"
        prior = by_name.get(key)
        if prior is None:
            copy = deepcopy(row)
            result[object_id] = copy
            by_name[key] = copy
            aliases[object_id] = object_id
            continue
        aliases[object_id] = str(prior.get("id") or "")
        left, right = _semantic(prior), _semantic(row)
        if _canonical(left) != _canonical(right):
            builder.conflict(
                scope_kind=scope_kind,
                scope_id=name or object_id,
                field="definition",
                existing=left,
                incoming=right,
                existing_source=f"{source_prefix}.{prior.get('id')}",
                incoming_source=f"{source_prefix}.{object_id}",
            )
    return result, aliases


def _compose_named_scopes(builder: _Builder, phase12: dict) -> dict:
    result = deepcopy(phase12 or {})

    security = result.setdefault("security", {})
    acls, acl_aliases = _dedupe_named(
        builder, security.get("acls") or {}, scope_kind="NAMED_POLICY", source_prefix="security.acls"
    )
    security["acls"] = acls
    for attachment in (security.get("attachments") or {}).values():
        attachment["acl_id"] = acl_aliases.get(attachment.get("acl_id"), attachment.get("acl_id"))

    pbr = result.setdefault("policy", {}).setdefault("pbr", {})
    policies, policy_aliases = _dedupe_named(
        builder, pbr.get("policies") or {}, scope_kind="NAMED_POLICY", source_prefix="policy.pbr.policies"
    )
    pbr["policies"] = policies
    for attachment in (pbr.get("attachments") or {}).values():
        attachment["policy_id"] = policy_aliases.get(attachment.get("policy_id"), attachment.get("policy_id"))

    nat = result.setdefault("nat", {})
    pools, pool_aliases = _dedupe_named(
        builder, nat.get("pools") or {}, scope_kind="NAMED_OBJECT", source_prefix="nat.pools"
    )
    nat["pools"] = pools
    for rule in (nat.get("rules") or {}).values():
        rule["pool_id"] = pool_aliases.get(rule.get("pool_id"), rule.get("pool_id"))
    return result


def _contribute_interfaces(builder: _Builder, routing: dict, phase12: dict) -> dict:
    for instance in sorted((routing.get("ospf") or {}).values(), key=_seq):
        for binding in sorted((instance.get("interfaces") or {}).values(), key=_seq):
            path = f"routing.ospf.{instance.get('id')}.interfaces.{binding.get('id')}"
            value = {
                "id": binding.get("id"),
                "instance_id": instance.get("id"),
                "version": instance.get("version"),
                "process_id": instance.get("process_id"),
                "area": binding.get("area"),
                "cost": binding.get("cost"),
                "network_type": binding.get("network_type"),
                "path": path,
            }
            semantic = {key: value[key] for key in ("version", "process_id", "area", "cost", "network_type")}
            builder.add_single(
                binding.get("interface_id"), "ospf", str(instance.get("version") or "OSPF"), value,
                semantic=semantic, source=path,
            )

    for instance in sorted((routing.get("isis") or {}).values(), key=_seq):
        for binding in sorted((instance.get("interfaces") or {}).values(), key=_seq):
            path = f"routing.isis.{instance.get('id')}.interfaces.{binding.get('id')}"
            value = {"id": binding.get("id"), "instance_id": instance.get("id"), "passive": bool(binding.get("passive")),
                     "metric": binding.get("metric"), "path": path,
                     "address_family_ipv4": bool(instance.get("address_family_ipv4")),
                     "address_family_ipv6": bool(instance.get("address_family_ipv6")), "level": instance.get("level")}
            builder.add_single(
                binding.get("interface_id"), "isis", "ISIS", value,
                semantic={"passive": value["passive"], "metric": value["metric"],
                          "address_family_ipv4": value["address_family_ipv4"],
                          "address_family_ipv6": value["address_family_ipv6"], "level": value["level"]}, source=path,
            )

    fhrp = (phase12.get("fhrp") or {}).get("instances") or {}
    global_mac: tuple[str, str] | None = None
    for instance in sorted(fhrp.values(), key=_seq):
        path = f"fhrp.instances.{instance.get('id')}"
        value = deepcopy(instance)
        value["path"] = path
        builder.add_many(
            instance.get("interface_id"), "fhrp", str(instance.get("id")), value,
            semantic=_semantic(instance),
        )
        # The current global virtual-router MAC scope belongs to cEOS VARP.
        # Other FHRP protocols keep their semantic value on the instance and
        # remain subject to platform capability handling.
        mac = str(instance.get("virtual_mac") or "") if instance.get("protocol") == "VARP" else ""
        if mac:
            if global_mac is None:
                global_mac = (mac, path)
            elif global_mac[0] != mac:
                builder.conflict(
                    scope_kind="DEVICE_GLOBAL", scope_id="virtual-router",
                    field="virtual_mac", existing=global_mac[0], incoming=mac,
                    existing_source=global_mac[1], incoming_source=path,
                )

    security = phase12.get("security") or {}
    acls = security.get("acls") or {}
    for attachment in sorted((security.get("attachments") or {}).values(), key=_seq):
        acl = acls.get(attachment.get("acl_id") or "") or {}
        path = f"security.attachments.{attachment.get('id')}"
        value = {
            **deepcopy(attachment),
            "acl_name": acl.get("name") or attachment.get("acl_id"),
            "family": acl.get("family") or "IPV4",
            "path": path,
        }
        slot = f"{value['family']}:{str(attachment.get('direction') or 'IN').upper()}"
        builder.add_single(
            attachment.get("interface_id"), "acl_attachments", slot, value,
            semantic={"acl_name": value["acl_name"], "family": value["family"], "direction": attachment.get("direction")},
            source=path,
        )

    pbr = ((phase12.get("policy") or {}).get("pbr")) or {}
    policies = pbr.get("policies") or {}
    for attachment in sorted((pbr.get("attachments") or {}).values(), key=_seq):
        policy = policies.get(attachment.get("policy_id") or "") or {}
        path = f"policy.pbr.attachments.{attachment.get('id')}"
        value = {
            **deepcopy(attachment),
            "policy_name": policy.get("name") or attachment.get("policy_id"),
            "family": policy.get("family") or "IPV4",
            "path": path,
        }
        builder.add_single(
            attachment.get("interface_id"), "pbr_attachments", value["family"], value,
            semantic={"policy_name": value["policy_name"], "family": value["family"]}, source=path,
        )

    dhcp = ((phase12.get("services") or {}).get("dhcp")) or {}
    for relay in sorted((dhcp.get("relays") or {}).values(), key=_seq):
        path = f"services.dhcp.relays.{relay.get('id')}"
        value = {**deepcopy(relay), "path": path}
        builder.add_many(
            relay.get("interface_id"), "dhcp_relays", f"{relay.get('family')}:{relay.get('destination')}", value,
            semantic={"family": relay.get("family"), "destination": relay.get("destination")},
        )

    for rule in sorted(((phase12.get("nat") or {}).get("rules") or {}).values(), key=_seq):
        path = f"nat.rules.{rule.get('id')}"
        for role, field in (("INSIDE", "inside_interface_id"), ("OUTSIDE", "outside_interface_id")):
            interface_id = rule.get(field)
            if not interface_id:
                continue
            builder.add_single(
                interface_id, "nat_roles", "role", {"role": role, "rule_id": rule.get("id"), "path": path},
                semantic=role, source=f"{path}.{field}",
            )
    return {
        "fhrp_virtual_mac": global_mac[0] if global_mac else "",
        "fhrp_virtual_mac_path": f"{global_mac[1]}.virtual_mac" if global_mac else "",
    }


def compose(
    *,
    field_values: dict,
    interfaces: list[dict] | None,
    routing: dict | None,
    phase12: dict | None,
    process_scope_key: ScopeKey,
) -> dict:
    """Return the one normalized candidate representation used for rendering."""
    builder = _Builder(interfaces or [])
    normalized_routing = _compose_routing(builder, routing or {}, process_scope_key)
    normalized_phase12 = _compose_named_scopes(builder, phase12 or {})
    global_state = _contribute_interfaces(builder, normalized_routing, normalized_phase12)

    for interface in builder.interfaces:
        for values in interface["_scope"].values():
            values.sort(key=lambda row: (str(row.get("family") or row.get("version") or ""), _seq(row)))

    return {
        "field_values": deepcopy(field_values),
        "interfaces": builder.interfaces,
        "routing": normalized_routing,
        "phase12": normalized_phase12,
        "global": global_state,
        "conflicts": [item.to_dict() for item in sorted(
            builder.conflicts,
            key=lambda item: (item.scope_kind, item.scope_id, item.field, item.existing_source, item.incoming_source),
        )],
    }
