"""
Read-only NetBox adapter for NSOT.

NetBox remains passive storage: every function here only reads. This module
is a thin adapter around the existing, already-authenticated client/read API
in modules/netbox_ipam.py and modules/ipam_context.py (module import ordered
per the same sys.path convention netbox/scripts/*.py already use) -- it does
not open a second, differently-authenticated NetBox client, and it never
writes. No NetBox URL or token ever leaves this module: callers only ever
see the normalized dicts returned below.

Every public function returns one of two envelope shapes and never raises:
    {"status": "available", "source": "NETBOX", "fetched_at": <iso>, "data": ...}
    {"status": "unavailable", "source": "NETBOX", "message": <safe text>, "data": <empty>}
"""

from __future__ import annotations

import sys
import ipaddress
from datetime import datetime, timezone

from django.conf import settings

_REPO_ROOT = settings.REPO_ROOT
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from modules import ipam_context as ic  # noqa: E402
from modules import netbox_ipam as nb  # noqa: E402

SOURCE = "NETBOX"


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _ok(data) -> dict:
    return {"status": "available", "source": SOURCE, "fetched_at": _now_iso(), "data": data}


def _unavailable(exc: Exception, data=None) -> dict:
    return {
        "status": "unavailable",
        "source": SOURCE,
        "message": f"NetBox temporarily unavailable ({exc.__class__.__name__}).",
        "data": data,
    }


def _nested(obj, *names):
    """Best-effort read of a nested pynetbox record's label/value/name."""
    for name in names:
        value = getattr(obj, name, None)
        if value is not None:
            return value
    return None


def _label(obj):
    if obj is None:
        return None
    return _nested(obj, "label", "name", "value") or str(obj)


def health() -> dict:
    """Bounded NetBox readability check (status/version only, no secrets)."""
    try:
        result = nb.check_status()
    except Exception as exc:  # noqa: BLE001 - boundary must never raise
        return _unavailable(exc)
    return _ok(result)


def _client():
    return nb.build_client()


def _normalize_device(device) -> dict:
    tags = sorted(t.name for t in (device.tags or []))
    custom_fields = dict(device.custom_fields or {})
    return {
        "name": device.name,
        "role": _label(getattr(device, "role", None)),
        "device_type": _label(getattr(device.device_type, "model", None)) if device.device_type else None,
        "manufacturer": _label(getattr(device.device_type, "manufacturer", None)) if device.device_type else None,
        "platform": _label(getattr(device, "platform", None)),
        "status": _label(getattr(device, "status", None)),
        "site": _label(getattr(device, "site", None)),
        "primary_ipv4": str(device.primary_ip4).split("/")[0] if device.primary_ip4 else None,
        "primary_ipv6": str(device.primary_ip6).split("/")[0] if device.primary_ip6 else None,
        "managed": bool(custom_fields.get("iac_managed")),
        "tags": tags,
    }


def list_devices() -> dict:
    """Every IaC-owned device (managed and unmanaged), normalized."""
    try:
        client = _client()
        devices = list(client.dcim.devices.filter(tag="csci5840-iac"))
        rows = sorted((_normalize_device(d) for d in devices), key=lambda r: r["name"])
    except Exception as exc:  # noqa: BLE001
        return _unavailable(exc, data=[])
    return _ok(rows)


def managed_device_names() -> dict:
    """The NetBox-authoritative IaC-managed device names (``managed`` tag and ``iac_managed`` must agree; R5/WebServer are not)."""
    try:
        names = sorted(nb.get_managed_devices(_client()))
    except Exception as exc:  # noqa: BLE001
        return _unavailable(exc, data=[])
    return _ok(names)


def get_device_detail(name: str) -> dict:
    """Stored/intended NetBox facts for one device: summary + interfaces."""
    try:
        client = _client()
        device = next(
            (d for d in client.dcim.devices.filter(tag="csci5840-iac") if d.name == name),
            None,
        )
        if device is None:
            return {"status": "not_found", "source": SOURCE, "message": f"{name!r} is not a known NetBox device.", "data": None}
        summary = _normalize_device(device)
        interfaces = []
        for iface in client.dcim.interfaces.filter(device=name):
            addrs = [
                {
                    "address": str(a.address).split("/")[0],
                    "prefix_length": int(str(a.address).split("/")[1]) if "/" in str(a.address) else None,
                    "family": a.family.value if getattr(a, "family", None) else None,
                    "role": _label(getattr(a, "role", None)),
                }
                for a in client.ipam.ip_addresses.filter(interface_id=iface.id)
            ]
            interfaces.append(
                {
                    "name": iface.name,
                    "type": _label(getattr(iface, "type", None)),
                    "description": iface.description or None,
                    "mac_address": str(iface.mac_address) if getattr(iface, "mac_address", None) else None,
                    "mode": _label(getattr(iface, "mode", None)),
                    "untagged_vlan": iface.untagged_vlan.vid if getattr(iface, "untagged_vlan", None) else None,
                    "enabled": bool(getattr(iface, "enabled", True)),
                    "addresses": sorted(addrs, key=lambda a: (a["family"] or 0, a["address"])),
                }
            )
        interfaces.sort(key=lambda i: i["name"])
    except Exception as exc:  # noqa: BLE001
        return _unavailable(exc)
    return _ok({"summary": summary, "interfaces": interfaces})


def list_interfaces(device: str | None = None) -> dict:
    try:
        client = _client()
        query = client.dcim.interfaces.filter(device=device) if device else client.dcim.interfaces.filter(tag="csci5840-iac")
        rows = []
        for iface in query:
            addrs = list(client.ipam.ip_addresses.filter(interface_id=iface.id))
            rows.append(
                {
                    "device": iface.device.name if iface.device else None,
                    "name": iface.name,
                    "type": _label(getattr(iface, "type", None)),
                    "description": iface.description or None,
                    "mac_address": str(iface.mac_address) if getattr(iface, "mac_address", None) else None,
                    "mode": _label(getattr(iface, "mode", None)),
                    "untagged_vlan": iface.untagged_vlan.vid if getattr(iface, "untagged_vlan", None) else None,
                    "enabled": bool(getattr(iface, "enabled", True)),
                    "address_count": len(addrs),
                    "addresses": [str(a.address) for a in addrs],
                }
            )
        rows.sort(key=lambda r: (r["device"] or "", r["name"]))
    except Exception as exc:  # noqa: BLE001
        return _unavailable(exc, data=[])
    return _ok(rows)


def list_prefixes() -> dict:
    try:
        client = _client()
        rows = []
        for prefix in client.ipam.prefixes.filter(tag="csci5840-iac"):
            rows.append(
                {
                    "prefix": prefix.prefix,
                    "family": prefix.family.value if getattr(prefix, "family", None) else None,
                    "status": _label(getattr(prefix, "status", None)),
                    "role": _label(getattr(prefix, "role", None)),
                    "vlan": prefix.vlan.vid if getattr(prefix, "vlan", None) else None,
                    "description": prefix.description or None,
                }
            )
        rows.sort(key=lambda r: (r["family"] or 0, r["prefix"]))
    except Exception as exc:  # noqa: BLE001
        return _unavailable(exc, data=[])
    return _ok(rows)


def list_ip_addresses(prefix: str | None = None) -> dict:
    try:
        client = _client()
        network = ipaddress.ip_network(prefix, strict=False) if prefix else None
        query = client.ipam.ip_addresses.filter(tag="csci5840-iac")
        rows = []
        for addr in query:
            cidr = str(addr.address)
            if network is not None and ipaddress.ip_interface(cidr).ip not in network:
                continue
            assigned = getattr(addr, "assigned_object", None)
            rows.append(
                {
                    "address": cidr,
                    "status": _label(getattr(addr, "status", None)),
                    "role": _label(getattr(addr, "role", None)),
                    "device": assigned.device.name if assigned and hasattr(assigned, "device") else None,
                    "interface": assigned.name if assigned else None,
                    "description": addr.description or None,
                }
            )
        rows.sort(key=lambda r: r["address"])
    except Exception as exc:  # noqa: BLE001
        return _unavailable(exc, data=[])
    return _ok(rows)


def list_vlans() -> dict:
    try:
        client = _client()
        rows = []
        for vlan in client.ipam.vlans.filter(tag="csci5840-iac"):
            rows.append(
                {
                    "vid": vlan.vid,
                    "name": vlan.name,
                    "status": _label(getattr(vlan, "status", None)),
                    "role": _label(getattr(vlan, "role", None)),
                    "description": vlan.description or None,
                    "static_management": vlan.vid == 200,
                }
            )
        rows.sort(key=lambda r: r["vid"])
    except Exception as exc:  # noqa: BLE001
        return _unavailable(exc, data=[])
    return _ok(rows)


def list_dhcp_ranges() -> dict:
    try:
        client = _client()
        rows = nb.get_dhcp_ranges(client=client)
    except Exception as exc:  # noqa: BLE001
        return _unavailable(exc, data=[])
    return _ok(rows)


def list_asns() -> dict:
    """Honest current state: report whatever ASN objects NetBox actually
    holds, never fabricate a routing-intent model that doesn't exist yet."""
    try:
        client = _client()
        rows = [
            {
                "asn": asn.asn,
                "description": asn.description or None,
                "sites": [s.name for s in (asn.sites or [])] if hasattr(asn, "sites") else [],
            }
            for asn in client.ipam.asns.all()
        ]
    except Exception as exc:  # noqa: BLE001
        return _unavailable(exc, data=[])
    return _ok(rows)


def get_device_types() -> dict:
    try:
        client = _client()
        rows = []
        for dt in client.dcim.device_types.all():
            count = len(list(client.dcim.devices.filter(device_type_id=dt.id, tag="csci5840-iac")))
            rows.append(
                {
                    "model": dt.model,
                    "manufacturer": _label(getattr(dt, "manufacturer", None)),
                    "device_count": count,
                }
            )
        rows.sort(key=lambda r: r["model"])
    except Exception as exc:  # noqa: BLE001
        return _unavailable(exc, data=[])
    return _ok(rows)


def reservation_report() -> dict:
    """Read-only reservation readiness from a materialized NetBox snapshot.

    ``ic.get_address_reservations`` is intentionally convenient for scripts,
    but performs several REST reads per interface. An interactive NSOT page
    uses the same validator over bulk-fetched objects so VLAN200/static and
    identity semantics remain identical without a minute-long query cascade.
    """
    try:
        client = _client()
        managed = set(nb.get_managed_devices(client))
        interfaces = list(client.dcim.interfaces.filter(tag=nb.OWNERSHIP_TAG_FILTER))
        addresses = list(client.ipam.ip_addresses.filter(tag=nb.OWNERSHIP_TAG_FILTER))
        macs = list(client.dcim.mac_addresses.all())

        mac_by_id = {row.id: row for row in macs}
        address_by_interface: dict[int, list] = {}
        for address in addresses:
            assigned = getattr(address, "assigned_object", None)
            assigned_id = getattr(assigned, "id", None) or getattr(address, "assigned_object_id", None)
            if assigned_id:
                address_by_interface.setdefault(assigned_id, []).append(ipaddress.ip_interface(str(address.address)))

        rows = []
        for interface in interfaces:
            device_name = getattr(getattr(interface, "device", None), "name", None)
            if device_name not in managed:
                continue
            fields = interface.custom_fields or {}
            values = address_by_interface.get(interface.id, [])
            v4 = [value for value in values if value.version == 4]
            v6 = [value for value in values if value.version == 6]
            mac_ref = getattr(interface, "primary_mac_address", None)
            mac = mac_by_id.get(getattr(mac_ref, "id", None))
            mac_fields = getattr(mac, "custom_fields", None) or {}
            rows.append({
                "device": device_name, "platform": "", "interface": interface.name,
                "mac_address": str(getattr(mac, "mac_address", "")) or None,
                "mac_identity_status": mac_fields.get("identity_status") or None,
                "ipv4": str(v4[0].ip) if len(v4) == 1 else None,
                "ipv4_mode": fields.get("ipv4_assignment_mode") or "none",
                "ipv6": str(v6[0].ip) if len(v6) == 1 else None,
                "ipv6_mode": fields.get("ipv6_assignment_mode") or "none",
                "dhcpv6_duid": fields.get("dhcpv6_duid") or None,
                "dhcpv6_iaid": fields.get("dhcpv6_iaid") or None,
                "dhcpv6_identity_status": fields.get("dhcpv6_identity_status") or None,
            })
        rows.sort(key=lambda row: (row["device"], row["interface"]))
        report = ic.validate_reservations(rows, managed_devices=managed)
    except Exception as exc:  # noqa: BLE001
        return _unavailable(exc)
    return _ok(
        {
            "rows_checked": len(rows),
            "overall_status": report.overall_status,
            "readiness_counts": report.readiness_counts,
            "ok": report.ok,
        }
    )


def compare_device_facts(device_name: str) -> dict:
    """Git-template-derived facts vs NetBox-derived facts for one managed
    device -- reuses the exact machinery Phase 3A built for this, never a
    generic text diff."""
    try:
        client = _client()
        legacy = ic.extract_legacy_facts(device_name)
        netbox_facts = ic.build_netbox_facts(device_name, client=client)
        result = ic.compare_facts(device_name, legacy, netbox_facts)
    except Exception as exc:  # noqa: BLE001
        return _unavailable(exc)
    return _ok({"equivalent": result.equivalent, "differences": [d.__dict__ for d in result.differences]})


def compare_device_facts_many(device_names, *, max_workers: int | None = None) -> dict[str, dict]:
    """Materialized fleet comparison for the interactive Drift page.

    The legacy helper intentionally performs multiple REST lookups per
    interface and is useful for a one-device diagnostic. Repeating it for a
    fleet caused an N x interface query waterfall (minutes on the live
    NetBox). This path reads the relevant interfaces, addresses, and prefixes
    once, then performs the exact same ``ic.compare_facts`` semantics in
    memory. ``max_workers`` is retained as a compatibility keyword but no
    threads or shared pynetbox client are needed.
    """
    names = sorted(set(device_names))
    if not names:
        return {}
    try:
        client = _client()
        interfaces = list(client.dcim.interfaces.filter(tag="csci5840-iac"))
        addresses = list(client.ipam.ip_addresses.filter(tag="csci5840-iac"))
        prefixes = list(client.ipam.prefixes.all())

        interface_keys = {}
        for interface in interfaces:
            device = getattr(interface, "device", None)
            device_name = getattr(device, "name", None)
            if device_name:
                interface_keys[interface.id] = (device_name, interface.name)

        by_interface: dict[tuple[str, str], list] = {}
        address_rows = []
        for address in addresses:
            value = ipaddress.ip_interface(str(address.address))
            assigned = getattr(address, "assigned_object", None)
            assigned_id = getattr(assigned, "id", None) or getattr(address, "assigned_object_id", None)
            key = interface_keys.get(assigned_id)
            if key:
                by_interface.setdefault(key, []).append(value)
            role = str(_label(getattr(address, "role", None)) or "").lower()
            address_rows.append((value, role))

        prefix_rows = []
        prefix_universe = set()
        for prefix in prefixes:
            network = ipaddress.ip_network(str(prefix.prefix), strict=False)
            prefix_universe.add(str(network))
            vlan = getattr(prefix, "vlan", None)
            prefix_rows.append((network, getattr(vlan, "vid", None)))

        results = {}
        for name in names:
            try:
                legacy = ic.extract_legacy_facts(name)
                facts = ic.DeviceFacts()
                for interface_name in legacy.interfaces:
                    values = by_interface.get((name, interface_name), [])
                    facts.interfaces[interface_name] = {}
                    for family, version in (("ipv4", 4), ("ipv6", 6)):
                        matches = [value for value in values if value.version == version]
                        if len(matches) > 1:
                            raise ValueError(f"{name}/{interface_name}: multiple IPv{version} addresses")
                        cidr = str(matches[0]) if matches else None
                        facts.interfaces[interface_name][family] = cidr
                        if matches:
                            own = matches[0]
                            peers = [
                                value for value, _role in address_rows
                                if value.version == version and value.ip != own.ip and value.ip in own.network
                            ]
                            if len(peers) == 1:
                                facts.peer_candidates.add(str(peers[0].ip))

                for interface_name in legacy.vrrp_gateways:
                    vid = int(interface_name.removeprefix("Vlan"))
                    facts.vrrp_gateways[interface_name] = {}
                    for family, version in (("ipv4", 4), ("ipv6", 6)):
                        networks = [network for network, vlan_id in prefix_rows if vlan_id == vid and network.version == version]
                        gateways = [
                            value for value, role in address_rows
                            if role == "vrrp" and value.version == version and any(value.ip in network for network in networks)
                        ]
                        if len(gateways) > 1:
                            raise ValueError(f"VLAN{vid}: multiple IPv{version} VRRP addresses")
                        facts.vrrp_gateways[interface_name][family] = str(gateways[0].ip) if gateways else None

                canonical = lambda value: str(ipaddress.ip_network(value, strict=False))  # noqa: E731
                facts.nat_sources = {value for value in legacy.nat_sources if canonical(value) in prefix_universe}
                facts.referenced_prefixes = {
                    value for value in legacy.referenced_prefixes if canonical(value) in prefix_universe
                }
                comparison = ic.compare_facts(name, legacy, facts)
                results[name] = _ok({
                    "equivalent": comparison.equivalent,
                    "differences": [difference.__dict__ for difference in comparison.differences],
                })
            except Exception as exc:  # noqa: BLE001 - isolate one malformed device
                results[name] = _unavailable(exc)
        return results
    except Exception as exc:  # noqa: BLE001 - one fleet read failure degrades every row safely
        return {name: _unavailable(exc) for name in names}


def project_facts() -> dict:
    """Phase-13 Tier-2 validation facts, gathered with a handful of batched
    READ-ONLY list queries (never per-object round trips) through the same
    client every other function here uses.

    The heavier ``ipam_context.get_address_reservations`` /
    ``get_dhcp_pool_context`` helpers issue one query per interface/VLAN
    (measured ~49 s and ~20 s against the live instance), which is too slow
    for an interactive validation run, so the reservation/pool facts are
    derived from the same NetBox objects/custom fields in bulk instead.
    Everything returned is normalized and deterministically ordered so it
    can be fingerprinted; no NetBox URL, token, or free-text description is
    included.
    """
    try:
        client = _client()
        ip_rows = []
        for record in client.ipam.ip_addresses.filter(tag=nb.OWNERSHIP_TAG_FILTER):
            cidr = str(record.address)
            assigned = getattr(record, "assigned_object", None)
            device = getattr(getattr(assigned, "device", None), "name", None) if assigned else None
            role = getattr(record, "role", None)
            role_text = (getattr(role, "value", None) or str(role)).lower() if role else None
            ip_text, _, length = cidr.partition("/")
            ip_rows.append({
                "cidr": cidr,
                "ip": ip_text,
                "prefix_length": int(length) if length else None,
                "family": 6 if ":" in ip_text else 4,
                "device": device,
                "interface": getattr(assigned, "name", None) if assigned else None,
                "role": role_text,
            })
        ip_rows.sort(key=lambda r: (r["family"], r["ip"], r["device"] or "", r["interface"] or ""))

        prefix_rows = []
        for prefix in client.ipam.prefixes.filter(tag=nb.OWNERSHIP_TAG_FILTER):
            raw_targets = (prefix.custom_fields or {}).get("dhcp_relay_targets") or ""
            prefix_rows.append({
                "prefix": str(prefix.prefix),
                "family": 6 if ":" in str(prefix.prefix) else 4,
                "vlan": prefix.vlan.vid if getattr(prefix, "vlan", None) else None,
                "relay_targets": sorted(item.strip() for item in str(raw_targets).split(",") if item.strip()),
            })
        prefix_rows.sort(key=lambda r: (r["family"], r["prefix"]))

        vlans = sorted({int(v.vid) for v in client.ipam.vlans.filter(tag=nb.OWNERSHIP_TAG_FILTER)})
        ranges = [
            {"start": r["start"], "end": r["end"], "family": r["family"], "server": r["server"]}
            for r in nb.get_dhcp_ranges(client=client)
        ]

        mode_rows = []
        for iface in client.dcim.interfaces.filter(tag=nb.OWNERSHIP_TAG_FILTER):
            fields = iface.custom_fields or {}
            v4, v6 = fields.get("ipv4_assignment_mode"), fields.get("ipv6_assignment_mode")
            if v4 or v6:
                mode_rows.append({
                    "device": iface.device.name if iface.device else None,
                    "interface": iface.name,
                    "ipv4_mode": v4,
                    "ipv6_mode": v6,
                })
        mode_rows.sort(key=lambda r: (r["device"] or "", r["interface"]))
        devices = sorted(d.name for d in client.dcim.devices.filter(tag=nb.OWNERSHIP_TAG_FILTER))
        managed_devices = sorted(nb.get_managed_devices(client))
    except Exception as exc:  # noqa: BLE001 - boundary must never raise
        return _unavailable(exc)
    return _ok({
        "ip_addresses": ip_rows,
        "prefixes": prefix_rows,
        "vlans": vlans,
        "dhcp_ranges": ranges,
        "interface_modes": mode_rows,
        "devices": devices,
        # Distinct from all ownership-tagged devices: ordinary configuration writes are permitted only to this
        # authoritative IaC-managed subset (R5/WebServer remain outside it).
        "managed_devices": managed_devices,
    })
