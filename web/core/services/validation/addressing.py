"""Addressing validation: exact host identity, never mere prefix overlap.

* candidate-vs-candidate duplicate host addresses (link-local/loopback exempt)
* candidate-vs-NetBox collisions with an EXPLICIT ownership self-match
  (same device AND same interface AND same host) -- never a blanket
  same-device exemption
* static candidate address inside an active dynamic DHCP pool
* reservation ownership conflicts
* VLAN 200 defense in depth (static management, never dynamic)
* deterministic, read-only AUTO address derivation (a PROPOSAL: not written to
  NetBox, not reserved, must be rechecked at deployment)

Two addresses in the same subnet are DIFFERENT hosts and never collide.
"""

from __future__ import annotations

import ipaddress
import itertools

from .context import SHARED_NETBOX_ROLES, AddressRecord, is_management_interface, norm_name
from .findings import Code, Severity

AUTO_ALGORITHM = "lowest-free-host/v1"
AUTO_SCAN_LIMIT = 4096


def _exempt(ip) -> bool:
    return ip.is_link_local or ip.is_loopback or ip.is_unspecified or ip.is_multicast


def _pool_ranges(ctx, family: int):
    if ctx.netbox is None:
        return []
    ranges = []
    for row in ctx.netbox["dhcp_ranges"]:
        if row["family"] != family:
            continue
        try:
            ranges.append((ipaddress.ip_address(row["start"]), ipaddress.ip_address(row["end"]), row))
        except ValueError:
            continue
    return ranges


def pool_conflict(ctx, ip):
    """The dynamic pool row containing `ip`, or None (exact host containment)."""
    for start, end, row in _pool_ranges(ctx, ip.version):
        if start <= ip <= end:
            return row
    return None


def reservation_index(ctx) -> tuple[dict, dict]:
    """(ip -> owner identity, identity -> reserved ip|None) from NetBox custom fields.

    An identity is reserved when its assignment-mode custom field is
    dhcp-reserved/dhcpv6-reserved; its reserved address is the NetBox address
    assigned to that interface for the family.  Read-only; nothing is created.
    """
    by_ip: dict = {}
    identities: dict = {}
    if ctx.netbox is None:
        return by_ip, identities
    for row in ctx.netbox["interface_modes"]:
        for family, key, wanted in ((4, "ipv4_mode", "dhcp-reserved"), (6, "ipv6_mode", "dhcpv6-reserved")):
            if row.get(key) != wanted:
                continue
            identity = (row["device"], norm_name(row["interface"]), family)
            addresses = [a for a in ctx.netbox_addresses_of(row["device"], row["interface"]) if a["family"] == family]
            identities[identity] = addresses[0]["ip"] if addresses else None
            for address in addresses:
                by_ip[address["ip"]] = (row["device"], norm_name(row["interface"]))
    return by_ip, identities


def netbox_conflicts(ctx, ip, *, device: str, interface_name: str, shared_ok: bool) -> list[dict]:
    """NetBox rows that make `ip` a collision for (device, interface).

    Returns [{"row": ..., "kind": "assigned"|"unassigned"|"released"}].
    A row is a self-match (no conflict) only for the same device, the same
    interface and the same host.  `shared_ok` is True for FHRP VIPs, which
    may legitimately equal a NetBox shared-role (vrrp/...) record.
    """
    conflicts = []
    for row in ctx.netbox_records_for_ip(ip):
        role = (row.get("role") or "").lower()
        if row["device"] == device and norm_name(row["interface"]) == norm_name(interface_name):
            continue  # ownership self-match
        if shared_ok and role in SHARED_NETBOX_ROLES:
            continue
        if row["device"] is None:
            if role in SHARED_NETBOX_ROLES:
                conflicts.append({"row": row, "kind": "assigned"})  # a shared VIP used as an ordinary address
            else:
                conflicts.append({"row": row, "kind": "unassigned"})
            continue
        owner = ctx.model.devices.get(row["device"])
        if owner is not None:
            owner_iface = owner.interface_by_name(row["interface"] or "")
            if owner_iface is not None:
                holds = any(a.ip == ip for a in ctx.model.addresses_of(owner.name, owner_iface["id"]))
                if not holds:
                    conflicts.append({"row": row, "kind": "released"})
                    continue
        conflicts.append({"row": row, "kind": "assigned"})
    return conflicts


# --- checks -----------------------------------------------------------------

def _invalid_addresses(ctx) -> None:
    for item in ctx.model.invalid_addresses:
        interface, address = item["interface"], item["address"]
        code = Code.ADDRESS_FAMILY_MISMATCH if item["reason"] == "family" else Code.ADDRESS_INVALID
        ctx.add(
            code,
            f"{item['device']} {interface.get('name')}: persisted address {address.get('cidr')!r} "
            + ("does not match its declared family." if item["reason"] == "family" else "is not a valid interface address."),
            device=item["device"], object_type="address", object_id=address.get("id"),
            field_path=f"interfaces.{interface['id']}.addresses.{address.get('id')}.cidr",
            evidence={"cidr": address.get("cidr"), "declared_family": address.get("family")},
            remediation="Correct the address in the Device Builder.",
        )


def _candidate_duplicates(ctx) -> None:
    groups: dict = {}
    for record in ctx.model.addresses:
        if _exempt(record.ip):
            continue
        groups.setdefault(record.ip, []).append(record)
    for ip in sorted(groups, key=lambda a: (a.version, int(a))):
        records = groups[ip]
        if len(records) < 2:
            continue
        first = records[0]
        ctx.add(
            Code.IP_DUPLICATE,
            f"Host address {ip} is assigned to {len(records)} candidate interfaces: "
            + ", ".join(f"{r.device}:{r.interface_name}" for r in records) + ".",
            device=first.device, object_type="address", object_id=first.address_id,
            related_devices=[r.device for r in records if r.device != first.device],
            related_objects=[r.object_key for r in records],
            evidence={"address": str(ip), "assignments": [
                {"device": r.device, "interface": r.interface_name, "address_id": r.address_id, "cidr": str(r.iface)}
                for r in records]},
            remediation="Give each interface a unique host address (FHRP VIPs belong in the FHRP section).",
        )


def _netbox_collisions(ctx) -> None:
    for record in ctx.model.addresses:
        if record.source != "MANUAL" or _exempt(record.ip):
            continue
        for conflict in netbox_conflicts(ctx, record.ip, device=record.device,
                                         interface_name=record.interface_name, shared_ok=False):
            row, kind = conflict["row"], conflict["kind"]
            soft = kind in ("unassigned", "released")
            note = {
                "assigned": "is already assigned to another NetBox object",
                "unassigned": "exists in NetBox as an unassigned address record",
                "released": "is assigned in NetBox to an interface this Change no longer gives that address",
            }[kind]
            ctx.add(
                Code.IP_NETBOX_COLLISION,
                f"{record.device}:{record.interface_name} address {record.ip} {note}"
                + (f" ({row['device']}:{row['interface']})." if row["device"] else "."),
                severity=Severity.WARNING if soft else Severity.ERROR,
                device=record.device, object_type="address", object_id=record.address_id,
                related_devices=[row["device"]] if row["device"] else [],
                related_objects=[f"{row['device']}:{row['interface']}"] if row["device"] else [],
                source="NETBOX",
                evidence={"address": str(record.ip), "netbox_cidr": row["cidr"], "netbox_device": row["device"],
                          "netbox_interface": row["interface"], "netbox_role": row["role"], "kind": kind},
                remediation="Choose an unused host address, or release the NetBox assignment through IPAM first.",
            )


def _dhcp_pool_conflicts(ctx) -> None:
    for record in ctx.model.addresses:
        if record.source != "MANUAL" or _exempt(record.ip):
            continue
        row = pool_conflict(ctx, record.ip)
        if row:
            ctx.add(
                Code.IP_DHCP_POOL_CONFLICT,
                f"{record.device}:{record.interface_name} static address {record.ip} lies inside the active "
                f"{row['server'] or 'unknown'} dynamic DHCP pool {row['start']}-{row['end']}.",
                device=record.device, object_type="address", object_id=record.address_id, source="NETBOX",
                evidence={"address": str(record.ip), "pool_start": row["start"], "pool_end": row["end"], "pool_server": row["server"]},
                remediation="Move the address outside the dynamic range; no exclusion is invented by validation.",
            )


def _reservation_conflicts(ctx) -> None:
    by_ip, identities = reservation_index(ctx)
    if not by_ip and not identities:
        return
    for record in ctx.model.addresses:
        if record.source != "MANUAL":
            continue
        owner = by_ip.get(str(record.ip))
        me = (record.device, norm_name(record.interface_name))
        if owner is not None and owner != me:
            ctx.add(
                Code.IP_RESERVATION_CONFLICT,
                f"{record.device}:{record.interface_name} address {record.ip} is reserved in NetBox for "
                f"{owner[0]}:{owner[1]}.",
                device=record.device, object_type="address", object_id=record.address_id, source="NETBOX",
                related_devices=[owner[0]], related_objects=[f"{owner[0]}:{owner[1]}"],
                evidence={"address": str(record.ip), "reserved_for": f"{owner[0]}:{owner[1]}"},
                remediation="Use a different address or change the reservation through IPAM.",
            )
            continue
        identity = (record.device, norm_name(record.interface_name), record.family)
        if identity in identities and identities[identity] != str(record.ip):
            ctx.add(
                Code.IP_RESERVATION_CONFLICT,
                f"{record.device}:{record.interface_name} is reserved for dynamic (DHCP) assignment in NetBox "
                f"but the Change assigns static address {record.ip}.",
                device=record.device, object_type="address", object_id=record.address_id, source="NETBOX",
                evidence={"address": str(record.ip), "reserved_address": identities[identity], "family": record.family},
                remediation="Align the candidate address with the reservation, or change the interface's assignment mode.",
            )


def _vlan200_defense(ctx) -> None:
    def forbid(device, interface, object_type, object_id, why, path=""):
        ctx.add(
            Code.DHCP_VLAN200_FORBIDDEN,
            f"{device}:{interface.get('name')} is VLAN 200 / management and must stay statically addressed: {why}.",
            device=device, object_type=object_type, object_id=object_id, field_path=path,
            evidence={"interface": interface.get("name"), "reason": why},
            remediation="Remove the dynamic behavior; VLAN 200 management stays static.",
        )

    for item in ctx.model.auto_addresses:
        if is_management_interface(item["interface"]):
            forbid(item["device"], item["interface"], "address", item["address"].get("id"),
                   "AUTO/reservation-driven addressing is not allowed")
    for name in sorted(ctx.model.devices):
        device = ctx.model.devices[name]
        for client in sorted(device.dhcp.get("clients", {}).values(), key=lambda c: c.get("id", "")):
            interface = device.interfaces.get(client.get("interface_id") or "")
            if interface is not None and is_management_interface(interface):
                forbid(name, interface, "dhcp_client", client["id"], f"DHCP{'v6' if client.get('family') == 'IPV6' else ''} client mode",
                       f"services.dhcp.clients.{client['id']}.interface_id")
        for relay in sorted(device.dhcp.get("relays", {}).values(), key=lambda c: c.get("id", "")):
            interface = device.interfaces.get(relay.get("interface_id") or "")
            if interface is not None and is_management_interface(interface):
                forbid(name, interface, "dhcp_relay", relay["id"], "DHCP relay (dynamic delivery)",
                       f"services.dhcp.relays.{relay['id']}.interface_id")
        if ctx.netbox is not None:
            for interface in device.ordered(device.interfaces):
                if not is_management_interface(interface):
                    continue
                for row in ctx.netbox["interface_modes"]:
                    if row["device"] == name and norm_name(row["interface"]) == norm_name(interface.get("name")) and (
                        row["ipv4_mode"] == "dhcp-reserved" or row["ipv6_mode"] == "dhcpv6-reserved"
                    ):
                        forbid(name, interface, "interface", interface["id"], "NetBox records a DHCP reservation for it")


def _known_taken_addresses(ctx) -> set:
    taken = set()
    if ctx.netbox is not None:
        for row in ctx.netbox["ip_addresses"]:
            taken.add(ipaddress.ip_address(row["ip"]))
    for record in ctx.model.addresses:
        taken.add(record.ip)
    for name in ctx.model.devices:
        for instance in ctx.model.devices[name].fhrp_instances.values():
            for vip in (instance.get("virtual_ips") or {}).values():
                try:
                    taken.add(ipaddress.ip_address(vip.get("address")))
                except ValueError:
                    pass
    for text in ctx.known_service_addresses():
        try:
            taken.add(ipaddress.ip_address(text))
        except ValueError:
            pass
    return taken


def _auto_addresses(ctx) -> None:
    items = sorted(
        ctx.model.auto_addresses,
        key=lambda i: (i["device"], str(i["interface"].get("name") or ""), i["interface"]["id"],
                       str(i["address"].get("family")), str(i["address"].get("ipam_prefix") or ""), i["address"]["id"]),
    )
    if not items:
        return
    by_ip, _ = reservation_index(ctx)
    for item in items:
        device, interface, address = item["device"], item["interface"], item["address"]
        object_key = f"{device}:{interface.get('name')}:{address['id']}"
        path = f"interfaces.{interface['id']}.addresses.{address['id']}.ipam_prefix"
        prefix_text = (address.get("ipam_prefix") or "").strip()
        family = 4 if address.get("family") == "IPV4" else 6

        def unresolved(message, *, blocking=True, source="INTENT"):
            ctx.add(
                Code.AUTO_IP_UNRESOLVED, message,
                blocking=blocking, incomplete=not blocking,
                device=device, object_type="address", object_id=address["id"], field_path=path, source=source,
                evidence={"ipam_prefix": prefix_text, "family": address.get("family")},
                remediation="Select a NetBox prefix for this AUTO address (explicit Refresh prefixes in the editor).",
            )

        if not prefix_text:
            unresolved(f"{object_key}: AUTO address has no NetBox prefix selected.")
            continue
        if ctx.netbox is None:
            unresolved(f"{object_key}: AUTO address cannot be resolved because NetBox evidence is unavailable.",
                       blocking=False, source="NETBOX")
            continue
        try:
            network = ipaddress.ip_network(prefix_text, strict=False)
        except ValueError:
            unresolved(f"{object_key}: AUTO prefix {prefix_text!r} is not a valid prefix.")
            continue
        if network.version != family:
            unresolved(f"{object_key}: AUTO prefix {network} does not match the declared address family.")
            continue
        if str(network) not in {row["prefix"] for row in ctx.netbox["prefixes"]}:
            unresolved(f"{object_key}: AUTO prefix {network} is not a prefix known to NetBox.", source="NETBOX")
            continue

        taken = _known_taken_addresses(ctx)
        chosen = None
        for host in itertools.islice(network.hosts(), AUTO_SCAN_LIMIT):
            if host in taken or str(host) in by_ip or pool_conflict(ctx, host) is not None:
                continue
            chosen = host
            break
        if chosen is None:
            ctx.add(
                Code.AUTO_IP_NO_AVAILABLE_ADDRESS,
                f"{object_key}: no free host address remains in {network} after excluding assigned, "
                "candidate, reserved, dynamic-pool and project-owned addresses.",
                device=device, object_type="address", object_id=address["id"], field_path=path, source="NETBOX",
                evidence={"prefix": str(network), "scan_limit": AUTO_SCAN_LIMIT},
                remediation="Select a different prefix or free an address in IPAM.",
            )
            continue
        proposed = ipaddress.ip_interface(f"{chosen}/{network.prefixlen}")
        ctx.model.add_derived(AddressRecord(
            device=device, interface_id=interface["id"], interface_name=str(interface.get("name") or ""),
            interface_kind=str(interface.get("kind") or ""), address_id=address["id"], iface=proposed,
            source="DERIVED", role=str(address.get("role") or ""),
        ))
        ctx.derive(
            "AUTO_ADDRESS",
            object_id=address["id"], device=device, interface=str(interface.get("name") or ""),
            family=address.get("family"), selected_prefix=str(network), proposed_address=str(proposed),
            source="NETBOX_PREFIX_READ_ONLY", algorithm=AUTO_ALGORITHM, reserved=False, status="PROPOSED",
            note="PROPOSED, NOT RESERVED. Read-only derivation; must be rechecked immediately before deployment.",
        )


def _dhcp_pool_safety(ctx) -> None:
    """Re-use ipam_context.validate_dhcp_pool_safety on the NetBox pool facts."""
    if ctx.netbox is None or not ctx.netbox["dhcp_ranges"]:
        return
    from modules import ipam_context as ic  # same import path nsot_netbox established

    prefixes = ctx.netbox["prefixes"]
    pools = []
    for row in ctx.netbox["dhcp_ranges"]:
        start = ipaddress.ip_address(row["start"])
        containing = [
            p for p in prefixes
            if p["vlan"] is not None and p["family"] == row["family"] and start in ipaddress.ip_network(p["prefix"])
        ]
        if not containing:
            continue
        prefix = max(containing, key=lambda p: ipaddress.ip_network(p["prefix"]).prefixlen)
        network = ipaddress.ip_network(prefix["prefix"])
        gateway = next(
            (a["ip"] for a in ctx.netbox["ip_addresses"]
             if (a.get("role") or "").lower() == "vrrp" and a["family"] == row["family"]
             and ipaddress.ip_address(a["ip"]) in network),
            None,
        )
        pools.append(ic.DhcpPool(
            vlan=prefix["vlan"], family=row["family"], server=row["server"] or "unknown", prefix=prefix["prefix"],
            start=row["start"], end=row["end"], gateway=gateway, relay_targets=tuple(prefix["relay_targets"]),
            description=None,
        ))
    infrastructure = {
        a["ip"] for a in ctx.netbox["ip_addresses"]
        if a["device"] in ("S1", "S2") and (a["interface"] or "") in ("Vlan10", "Vlan20", "Vlan30")
    }
    for problem in ic.validate_dhcp_pool_safety(pools, infrastructure_addresses=infrastructure):
        ctx.add(
            Code.DHCP_POOL_OVERLAP,
            f"Pre-existing NetBox DHCP pool state: {problem}",
            source="NETBOX", object_type="dhcp_pool", object_id="netbox",
            evidence={"problem": problem},
            remediation="Repair the pool model in NetBox/IPAM; this is project state, not caused by the Change.",
        )


def validate_addressing(ctx) -> None:
    _invalid_addresses(ctx)
    _candidate_duplicates(ctx)
    _vlan200_defense(ctx)
    if ctx.netbox is not None:
        _netbox_collisions(ctx)
        _dhcp_pool_conflicts(ctx)
        _reservation_conflicts(ctx)
        _dhcp_pool_safety(ctx)
    _auto_addresses(ctx)
    ctx.checked["candidate_addresses"] = len([r for r in ctx.model.addresses if r.source == "MANUAL"])
    ctx.checked["auto_addresses"] = len(ctx.model.auto_addresses)
