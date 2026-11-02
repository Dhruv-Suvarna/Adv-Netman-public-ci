"""FHRP / VARP project-wide validation.

FHRP virtual IPs are INTENTIONALLY duplicated between peers, so they are
never run through the ordinary duplicate-address logic.  Instead peers are
correlated into domains and judged under FHRP rules:

    domain    same protocol + address family, and (a shared VIP, or the same
              VLAN context with the same group ID)
    checks    group ID agreement (HSRP/VRRP/GLBP), identical VIP sets,
              VARP virtual-MAC agreement (and one global MAC per cEOS device),
              duplicate priorities (WARNING; VARP has none)
    conflict  a VIP shared by two DIFFERENT domains, or equal to an ordinary
              candidate/NetBox interface address, or inside a dynamic DHCP pool
"""

from __future__ import annotations

import ipaddress
import re

from .addressing import netbox_conflicts, pool_conflict
from .context import vlan_context
from .findings import Code, Severity

_PRIORITY_PROTOCOLS = ("HSRP", "VRRP", "GLBP")
_GROUP_PROTOCOLS = ("HSRP", "VRRP", "GLBP")


def _norm_mac(value) -> str:
    return re.sub(r"[^0-9a-f]", "", str(value or "").lower())


def _vips(instance) -> dict:
    out = {}
    for vip in (instance.get("virtual_ips") or {}).values():
        try:
            ip = ipaddress.ip_address(str(vip.get("address")))
        except ValueError:
            continue
        out[ip] = vip
    return out


class _Members:
    def __init__(self, ctx):
        self.items = []
        for name in sorted(ctx.model.devices):
            device = ctx.model.devices[name]
            for instance in sorted(device.fhrp_instances.values(), key=lambda r: r.get("id", "")):
                interface = device.interfaces.get(instance.get("interface_id") or "") or {}
                self.items.append({
                    "device": name, "instance": instance, "interface": interface,
                    "vlan": vlan_context(interface) if interface else None, "vips": _vips(instance),
                })


def _domains(items) -> list[list[dict]]:
    parent = list(range(len(items)))

    def find(i):
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    for i, a in enumerate(items):
        for j in range(i + 1, len(items)):
            b = items[j]
            if a["device"] == b["device"]:
                continue
            ia, ib = a["instance"], b["instance"]
            if ia.get("protocol") != ib.get("protocol") or ia.get("address_family") != ib.get("address_family"):
                continue
            shares_vip = bool(set(a["vips"]) & set(b["vips"]))
            same_ctx = a["vlan"] is not None and a["vlan"] == b["vlan"] and ia.get("group_id") == ib.get("group_id")
            if shares_vip or same_ctx:
                parent[find(i)] = find(j)
    groups: dict = {}
    for i, item in enumerate(items):
        groups.setdefault(find(i), []).append(item)
    return sorted(groups.values(), key=lambda g: (g[0]["device"], g[0]["instance"]["id"]))


def validate_fhrp(ctx) -> None:
    members = _Members(ctx)
    if not members.items:
        return
    domains = _domains(members.items)
    vip_domain: dict = {}
    for index, domain in enumerate(domains):
        protocol = domain[0]["instance"].get("protocol")
        devices = sorted({m["device"] for m in domain})
        all_vips = sorted({str(ip) for m in domain for ip in m["vips"]})
        ctx.derive("FHRP_DOMAIN", protocol=protocol, address_family=domain[0]["instance"].get("address_family"),
                   devices=devices, virtual_ips=all_vips,
                   members=[f"{m['device']}:{m['instance']['id']}" for m in domain])
        for member in domain:
            for ip in member["vips"]:
                vip_domain.setdefault(ip, set()).add(index)
        if len(devices) < 2:
            continue
        first = domain[0]
        related = [m["device"] for m in domain if m["device"] != first["device"]]
        objects = [f"{m['device']}:{m['instance']['id']}" for m in domain]
        if protocol in _GROUP_PROTOCOLS:
            groups = {m["instance"].get("group_id") for m in domain if m["instance"].get("group_id") is not None}
            if len(groups) > 1:
                ctx.add(Code.FHRP_GROUP_MISMATCH,
                        f"{protocol} peers {', '.join(devices)} use different group IDs {sorted(groups)}.",
                        device=first["device"], object_type="fhrp", object_id=first["instance"]["id"],
                        related_devices=related, related_objects=objects, evidence={"group_ids": sorted(groups)},
                        remediation="Use one group ID on every peer of the domain.")
        vip_sets = {m["device"]: sorted(str(ip) for ip in m["vips"]) for m in domain}
        if len({tuple(v) for v in vip_sets.values()}) > 1:
            ctx.add(Code.FHRP_GROUP_MISMATCH,
                    f"{protocol} peers {', '.join(devices)} do not share the same virtual IP set.",
                    device=first["device"], object_type="fhrp", object_id=first["instance"]["id"],
                    related_devices=related, related_objects=objects, evidence={"virtual_ips_by_device": vip_sets},
                    remediation="Configure the same virtual IPs on every peer.")
        if protocol == "VARP":
            macs = {m["device"]: _norm_mac(m["instance"].get("virtual_mac")) for m in domain}
            set_macs = {v for v in macs.values() if v}
            if len(set_macs) > 1:
                ctx.add(Code.FHRP_VIRTUAL_MAC_MISMATCH,
                        f"VARP peers {', '.join(devices)} use different virtual-router MACs.",
                        device=first["device"], object_type="fhrp", object_id=first["instance"]["id"],
                        related_devices=related, related_objects=objects, evidence={"virtual_mac_by_device": macs},
                        remediation="Use one virtual-router MAC across the shared VARP domain.")
            elif set_macs and any(not v for v in macs.values()):
                ctx.add(Code.FHRP_VIRTUAL_MAC_MISMATCH,
                        f"Only some VARP peers ({', '.join(d for d, v in macs.items() if v)}) set a virtual MAC.",
                        severity=Severity.WARNING, device=first["device"], object_type="fhrp",
                        object_id=first["instance"]["id"], related_devices=related, related_objects=objects,
                        evidence={"virtual_mac_by_device": macs},
                        remediation="Set the shared virtual MAC on every peer, or on none.")
        if protocol in _PRIORITY_PROTOCOLS:
            priorities = [(m["device"], m["instance"].get("priority")) for m in domain if m["instance"].get("priority") is not None]
            counts = {}
            for _, value in priorities:
                counts[value] = counts.get(value, 0) + 1
            duplicated = sorted(v for v, n in counts.items() if n > 1)
            if duplicated:
                ctx.add(Code.FHRP_PRIORITY_DUPLICATE,
                        f"{protocol} peers use the same priority {duplicated}; the active router is decided by tie-break.",
                        device=first["device"], object_type="fhrp", object_id=first["instance"]["id"],
                        related_devices=related, related_objects=objects, evidence={"priorities": dict(priorities)},
                        remediation="Give the intended active router a higher priority.")

    # one global virtual-router MAC per cEOS device
    by_device: dict = {}
    for m in members.items:
        if m["instance"].get("protocol") == "VARP" and _norm_mac(m["instance"].get("virtual_mac")):
            by_device.setdefault(m["device"], set()).add(_norm_mac(m["instance"]["virtual_mac"]))
    for device, macs in sorted(by_device.items()):
        if len(macs) > 1:
            ctx.add(Code.FHRP_VIRTUAL_MAC_MISMATCH,
                    f"{device}: VARP uses one global virtual-router MAC but the Change sets {len(macs)} different values.",
                    device=device, object_type="fhrp", object_id=device, evidence={"virtual_macs": sorted(macs)},
                    remediation="Use a single virtual-router MAC per device.")

    for ip in sorted(vip_domain, key=lambda a: (a.version, int(a))):
        if len(vip_domain[ip]) > 1:
            owners = [m for m in members.items if ip in m["vips"]]
            ctx.add(Code.FHRP_VIP_CONFLICT,
                    f"Virtual IP {ip} is used by {len(vip_domain[ip])} unrelated FHRP domains.",
                    device=owners[0]["device"], object_type="fhrp", object_id=owners[0]["instance"]["id"],
                    related_devices=[m["device"] for m in owners[1:]],
                    related_objects=[f"{m['device']}:{m['instance']['id']}" for m in owners],
                    evidence={"virtual_ip": str(ip)},
                    remediation="Each FHRP domain needs its own virtual IP.")

    for m in members.items:
        for ip, vip in sorted(m["vips"].items(), key=lambda kv: (kv[0].version, int(kv[0]))):
            path = f"fhrp.instances.{m['instance']['id']}.virtual_ips.{vip['id']}.address"
            for record in ctx.model.addresses:
                if record.ip == ip:
                    ctx.add(Code.FHRP_VIP_CONFLICT,
                            f"Virtual IP {ip} on {m['device']} equals the ordinary interface address on "
                            f"{record.device}:{record.interface_name}.",
                            device=m["device"], object_type="fhrp", object_id=m["instance"]["id"], field_path=path,
                            related_devices=[record.device], related_objects=[record.object_key],
                            evidence={"virtual_ip": str(ip), "interface_address": str(record.iface)},
                            remediation="A virtual IP must not equal a real interface address.")
            interface = m["interface"]
            if interface and ctx.model.addresses_of(m["device"], interface.get("id")) and not any(
                r.family == ip.version and ip in r.network for r in ctx.model.addresses_of(m["device"], interface["id"])
            ) and any(r.family == ip.version for r in ctx.model.addresses_of(m["device"], interface["id"])):
                ctx.add(Code.FHRP_VIP_OFF_SUBNET,
                        f"Virtual IP {ip} is outside every candidate subnet of {m['device']}:{interface.get('name')}.",
                        device=m["device"], object_type="fhrp", object_id=m["instance"]["id"], field_path=path,
                        evidence={"virtual_ip": str(ip)}, remediation="Choose a VIP from the interface's subnet.")
            if ctx.netbox is not None:
                for conflict in netbox_conflicts(ctx, ip, device=m["device"], interface_name=interface.get("name") or "",
                                                 shared_ok=True):
                    row = conflict["row"]
                    ctx.add(Code.IP_NETBOX_COLLISION,
                            f"Virtual IP {ip} on {m['device']} collides with NetBox address {row['cidr']} "
                            f"({row['device']}:{row['interface']}), which is not a shared FHRP record.",
                            severity=Severity.WARNING if conflict["kind"] in ("unassigned", "released") else Severity.ERROR,
                            device=m["device"], object_type="fhrp", object_id=m["instance"]["id"], field_path=path,
                            source="NETBOX", evidence={"virtual_ip": str(ip), "netbox_cidr": row["cidr"], "kind": conflict["kind"]},
                            remediation="Choose an unused virtual IP.")
                pool = pool_conflict(ctx, ip)
                if pool:
                    ctx.add(Code.IP_DHCP_POOL_CONFLICT,
                            f"Virtual IP {ip} lies inside the dynamic DHCP pool {pool['start']}-{pool['end']}.",
                            device=m["device"], object_type="fhrp", object_id=m["instance"]["id"], field_path=path,
                            source="NETBOX", evidence={"virtual_ip": str(ip), "pool_start": pool["start"], "pool_end": pool["end"]},
                            remediation="Move the VIP outside the dynamic range.")
    ctx.checked["fhrp_instances"] = len(members.items)
