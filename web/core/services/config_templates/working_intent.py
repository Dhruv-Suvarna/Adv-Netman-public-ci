"""A Device Builder working revision (canonical ``sections``) back into the name-keyed template intent.

The inverse of ``config_import.service._apply_parsed_config``: database object ids become names, so a template never
depends on one NMAS instance's identifiers.  Used to create a new template version from an edited working clone."""

from __future__ import annotations

from .. import routing_intent_service, service_policy_intent_service

_INTERFACE_SCALARS = ("kind", "description", "mtu", "admin_state", "access_vlan", "trunk_allowed_vlans", "native_vlan",
                      "encapsulation_vlan", "vlan_id")


def _ordered(mapping) -> list[dict]:
    rows = [row for row in (mapping or {}).values() if isinstance(row, dict)]
    return sorted(rows, key=lambda row: (int(row.get("sequence") or 0), str(row.get("id", ""))))


def _keep(row: dict, fields) -> dict:
    return {f: row[f] for f in fields if row.get(f) not in (None, "", [], {})}


def intent_from_sections(sections: dict, *, hostname: str) -> dict:
    sections = sections or {}
    names = {row["id"]: row.get("name", "") for row in _ordered(sections.get("interfaces"))}
    relays, fhrp, attachments = {}, {}, {}
    for relay in _ordered(((sections.get("services") or {}).get("dhcp") or {}).get("relays")):
        relays.setdefault(relay.get("interface_id"), []).append(_keep(relay, ("family", "destination")))
    for instance in _ordered((sections.get("fhrp") or {}).get("instances")):
        for vip in _ordered(instance.get("virtual_ips")):
            fhrp.setdefault(instance.get("interface_id"), []).append(
                {**_keep(instance, ("protocol", "address_family", "virtual_mac")), "address": vip.get("address")})
    acls = {acl["id"]: acl for acl in _ordered((sections.get("security") or {}).get("acls"))}
    for attachment in _ordered((sections.get("security") or {}).get("attachments")):
        acl = acls.get(attachment.get("acl_id"))
        if acl:
            attachments.setdefault(attachment.get("interface_id"), []).append(
                {"family": acl.get("family"), "name": acl.get("name"), "direction": attachment.get("direction")})
    interfaces = []
    for row in _ordered(sections.get("interfaces")):
        item = {"name": row.get("name", ""), **_keep(row, _INTERFACE_SCALARS)}
        if row.get("parent_id") in names:
            item["parent_name"] = names[row["parent_id"]]
        addresses = [_keep(a, ("family", "cidr", "role")) for a in _ordered(row.get("addresses")) if a.get("cidr")]
        for key, value in (("addresses", addresses), ("dhcp_relays", relays.get(row["id"])), ("fhrp", fhrp.get(row["id"])),
                           ("acl_attachments", attachments.get(row["id"]))):
            if value:
                item[key] = value
        interfaces.append(item)
    routing_section = sections.get("routing") or {}
    routes = []
    for route in _ordered(routing_section.get("static_routes")):
        item = _keep(route, ("family", "destination", "next_hop_address", "distance", "tag"))
        if route.get("next_hop_interface_id") in names:
            item["next_hop_interface"] = names[route["next_hop_interface_id"]]
        routes.append(item)
    routing = []
    for family in ("rip", "ospf", "isis", "eigrp", "bgp"):
        for instance in _ordered(routing_section.get(family)):
            item = {"family": family, "fields": {f: instance[f] for f in routing_intent_service.INSTANCE_FIELDS[family]
                                                 if instance.get(f) not in (None, "")}}
            bindings = []
            for binding in _ordered(instance.get("interfaces")):
                if binding.get("interface_id") in names:
                    bindings.append({"interface_name": names[binding["interface_id"]],
                                     **{f: binding[f] for f in routing_intent_service.BINDING_FIELDS.get(family, ()) if binding.get(f) not in (None, "")}})
            neighbors = []
            for neighbor in _ordered(instance.get("neighbors")):
                row = _keep(neighbor, tuple(f for f in routing_intent_service.BGP_NEIGHBOR_FIELDS
                                            if f not in ("update_source_interface_id", "password_ref")))
                row.update({k: neighbor[k] for k in ("activate_ipv4", "activate_ipv6") if k in neighbor})
                if neighbor.get("update_source_interface_id") in names:
                    row["update_source_interface"] = names[neighbor["update_source_interface_id"]]
                neighbors.append(row)
            networks = [_keep(n, ("family", "cidr", "prefix", "area")) for n in _ordered(instance.get("networks"))]
            for key, value in (("bindings", bindings), ("neighbors", neighbors), ("networks", networks)):
                if value:
                    item[key] = value
            routing.append(item)
    acl_rows = [{**_keep(acl, ("name", "family", "acl_type")),
                 "entries": [_keep(e, service_policy_intent_service.ACE_FIELDS) for e in _ordered(acl.get("entries"))]} for acl in acls.values()]
    nat = []
    for rule in _ordered((sections.get("nat") or {}).get("rules")):
        item = _keep(rule, ("family", "mode", "original_source", "translated_source"))
        if rule.get("outside_interface_id") in names:
            item["outside_interface"] = names[rule["outside_interface_id"]]
        nat.append(item)
    intent = {"device": {"hostname": hostname}, "interfaces": interfaces, "static_routes": routes, "routing": routing,
              "acls": acl_rows, "nat_rules": nat}
    return {k: v for k, v in intent.items() if v not in ([], {})}
