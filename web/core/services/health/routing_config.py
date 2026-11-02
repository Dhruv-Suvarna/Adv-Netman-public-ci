"""Secret-free semantic routing facts derived from the supported config import parsers."""

from __future__ import annotations

import ipaddress

from ..config_import import parser_ceos, parser_frr


def normalized_area(value) -> str:
    """An OSPF / IS-IS area in one canonical form: dotted-quad areas as their integer ("0.0.0.0" -> "0"), others verbatim."""
    try:
        return str(int(ipaddress.IPv4Address(str(value))))
    except ipaddress.AddressValueError:
        return str(value)


_area = normalized_area


def _normalized_area_rows(rows):
    return [{**row, "area": _area(row["area"])} if row.get("area") is not None else dict(row)
            for row in rows]


def _network_bindings(instance, interfaces) -> list[dict]:
    """Interfaces an OSPFv2 process enables through a ``network <prefix> area <id>`` statement rather than on the interface.

    The most specific statement covering an interface IPv4 address decides its area, as the routing daemon itself does.
    An interface that carries its own binding is reported there, never twice.
    """
    if instance.family != "ospf" or instance.fields.get("version") != "OSPFV2":
        return []
    statements = []
    for row in instance.networks:
        try:
            statements.append((ipaddress.ip_network(str(row.get("prefix")), strict=False), row.get("area")))
        except ValueError:
            continue
    bound = {binding.get("interface_name") for binding in instance.bindings}
    found = []
    for interface in interfaces:
        if interface.name in bound:
            continue
        covering = []
        for address in interface.addresses:
            if address.get("family") != "IPV4":
                continue
            try:
                ip = ipaddress.ip_interface(str(address.get("cidr"))).ip
            except ValueError:
                continue
            covering.extend((network.prefixlen, area) for network, area in statements if network.version == 4 and ip in network)
        if covering:
            found.append({"interface_name": interface.name, "area": max(covering, key=lambda item: item[0])[1]})
    return _normalized_area_rows(found)


def _rows(parsed) -> list[dict]:
    rows = []
    for instance in parsed.routing_instances:
        fields = instance.fields
        rows.append({
            "protocol": instance.family,
            "version": fields.get("version") or fields.get("address_family") or "",
            "process_id": fields.get("process_id"),
            "local_asn": fields.get("local_asn"),
            "router_id": fields.get("router_id") or "",
            "enabled": fields.get("enabled", True),
            "networks": _normalized_area_rows(instance.networks),
            "bindings": _normalized_area_rows(instance.bindings),
            "network_bindings": _network_bindings(instance, parsed.interfaces),
            "neighbors": list(instance.neighbors),
            "redistributions": sorted(line.strip() for line in instance.preserved_lines
                                      if line.strip().startswith("redistribute ")),
        })
    return rows


def eos(text: str) -> list[dict]:
    return _rows(parser_ceos.parse(text))


def frr(text: str, addr_json: str) -> list[dict]:
    return _rows(parser_frr.parse(text, addr_json=addr_json))
