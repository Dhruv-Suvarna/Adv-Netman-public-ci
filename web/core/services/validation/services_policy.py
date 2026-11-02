"""NAT / DHCP relay / DNS / PBR project-level checks.

Deliberately NOT a NAT simulator: only relationships that can be proven from
structured intent + project evidence are judged (family consistency, distinct
inside/outside roles, pool integrity, project-known relay/resolver targets).
Inside/outside directionality is never fabricated -- the topology source has
no role metadata, so it is reported as NAT_ROLE_UNVERIFIED (INFO).

DNS resolvers are matched against project-known addresses only; no name is
ever resolved and no query is ever sent.  PBR next-hop reachability is judged
only for a platform whose registry actually SUPPORTS PBR (none today).
"""

from __future__ import annotations

import ipaddress

from .. import platform_drivers
from .findings import Code, Severity

_NAT_FAMILY = {"NAT44": 4, "NAT66": 6, "NPTV6": 6}


def _ip(text):
    try:
        return ipaddress.ip_address(str(text))
    except ValueError:
        return None


def _net(text):
    try:
        return ipaddress.ip_network(str(text), strict=False)
    except ValueError:
        return None


def _known(ctx, address) -> str | None:
    """Label of the project-known source for `address`, or None."""
    text = str(address)
    known = ctx.known_service_addresses()
    if text in known:
        return known[text]
    rows = ctx.netbox_records_for_ip(text)
    if rows:
        return f"netbox {rows[0]['device'] or 'shared'}:{rows[0]['interface'] or ''}".rstrip(":")
    return None


def _nat(ctx) -> None:
    mgmt = set()
    if ctx.inventory:
        mgmt = {ip for ip in (_ip(v) for v in ctx.inventory["management"].values()) if ip}
    for name in sorted(ctx.model.devices):
        device = ctx.model.devices[name]
        pools = device.nat.get("pools") or {}
        rules = sorted((device.nat.get("rules") or {}).values(), key=lambda r: r.get("id", ""))
        ranges = []
        for pool in sorted(pools.values(), key=lambda p: p.get("id", "")):
            family = _NAT_FAMILY.get(pool.get("family"))
            start, end = _ip(pool.get("start_address")), _ip(pool.get("end_address"))
            path = f"nat.pools.{pool['id']}"
            if family and any(a is not None and a.version != family for a in (start, end)):
                ctx.add(Code.NAT_POOL_CONFLICT,
                        f"{name}: NAT pool {pool.get('name')} ({pool.get('family')}) holds an address of the wrong family.",
                        device=name, object_type="nat_pool", object_id=pool["id"], field_path=path,
                        evidence={"start": pool.get("start_address"), "end": pool.get("end_address"), "family": pool.get("family")},
                        remediation="Use pool addresses of the NAT family.")
                continue
            if start is not None and end is not None:
                if end < start:
                    ctx.add(Code.NAT_POOL_CONFLICT,
                            f"{name}: NAT pool {pool.get('name')} ends before it starts.",
                            device=name, object_type="nat_pool", object_id=pool["id"], field_path=path,
                            evidence={"start": str(start), "end": str(end)}, remediation="Swap the pool boundaries.")
                    continue
                ranges.append((start, end, pool))
                for record in ctx.model.device_addresses(name):
                    if record.ip.version == start.version and start <= record.ip <= end:
                        ctx.add(Code.NAT_POOL_CONFLICT,
                                f"{name}: NAT pool {pool.get('name')} contains the interface address {record.ip} of {record.interface_name}.",
                                device=name, object_type="nat_pool", object_id=pool["id"], field_path=path,
                                related_objects=[record.object_key], evidence={"address": str(record.ip)},
                                remediation="Keep interface addresses outside translation pools.")
                for protected in sorted(mgmt, key=lambda a: (a.version, int(a))):
                    if protected.version == start.version and start <= protected <= end:
                        ctx.add(Code.NAT_POOL_CONFLICT,
                                f"{name}: NAT pool {pool.get('name')} contains the project management/service address {protected}.",
                                device=name, object_type="nat_pool", object_id=pool["id"], field_path=path,
                                evidence={"address": str(protected)}, remediation="Exclude management/service addresses from the pool.")
        for i, (s1, e1, p1) in enumerate(ranges):
            for s2, e2, p2 in ranges[i + 1:]:
                if s1.version == s2.version and s1 <= e2 and s2 <= e1:
                    ctx.add(Code.NAT_POOL_CONFLICT,
                            f"{name}: NAT pools {p1.get('name')} and {p2.get('name')} overlap.",
                            device=name, object_type="nat_pool", object_id=p1["id"], related_objects=[f"{name}:{p2['id']}"],
                            evidence={"pool_a": f"{s1}-{e1}", "pool_b": f"{s2}-{e2}"}, remediation="Make pool ranges disjoint.")
        for rule in rules:
            rid = rule["id"]
            path = f"nat.rules.{rid}"
            family = _NAT_FAMILY.get(rule.get("family"))
            for field_name in ("original_source", "translated_source"):
                value = rule.get(field_name)
                parsed = _net(value) if value else None
                if family and parsed is not None and parsed.version != family:
                    ctx.add(Code.NAT_FAMILY_MISMATCH,
                            f"{name}: NAT rule {rid} ({rule.get('family')}) {field_name} {value} is the wrong address family.",
                            device=name, object_type="nat_rule", object_id=rid, field_path=f"{path}.{field_name}",
                            evidence={field_name: value, "family": rule.get("family")},
                            remediation="Use addresses of the NAT rule's family.")
            inside, outside = rule.get("inside_interface_id") or "", rule.get("outside_interface_id") or ""
            if inside and inside == outside:
                ctx.add(Code.NAT_INTERFACE_ROLE_CONFLICT,
                        f"{name}: NAT rule {rid} uses the same interface as inside and outside.",
                        device=name, object_type="nat_rule", object_id=rid, field_path=path,
                        evidence={"interface": device.interfaces.get(inside, {}).get("name")},
                        remediation="Use distinct inside and outside interfaces.")
            elif inside and outside:
                i_wan = (device.interfaces.get(inside, {}).get("wan") or {}).get("state") == "ENABLED"
                o_wan = (device.interfaces.get(outside, {}).get("wan") or {}).get("state") == "ENABLED"
                if i_wan and not o_wan:
                    ctx.add(Code.NAT_INTERFACE_ROLE_CONFLICT,
                            f"{name}: NAT rule {rid} marks WAN-facing {device.interfaces[inside].get('name')} as inside "
                            f"and non-WAN {device.interfaces[outside].get('name')} as outside.",
                            severity=Severity.WARNING, device=name, object_type="nat_rule", object_id=rid, field_path=path,
                            evidence={"inside_wan": True, "outside_wan": False},
                            remediation="Confirm the inside/outside assignment; WAN metadata suggests they are reversed.")
            pool_id = rule.get("pool_id") or ""
            if pool_id and pool_id in pools:
                pool_family = _NAT_FAMILY.get(pools[pool_id].get("family"))
                if family and pool_family and family != pool_family:
                    ctx.add(Code.NAT_POOL_CONFLICT,
                            f"{name}: NAT rule {rid} ({rule.get('family')}) references pool {pools[pool_id].get('name')} of family {pools[pool_id].get('family')}.",
                            device=name, object_type="nat_rule", object_id=rid, field_path=f"{path}.pool_id",
                            related_objects=[f"{name}:{pool_id}"],
                            evidence={"rule_family": rule.get("family"), "pool_family": pools[pool_id].get("family")},
                            remediation="Reference a pool of the rule's address family.")
            elif not pool_id and rule.get("mode") == "DYNAMIC":
                ctx.add(Code.DEPENDENCY_MISSING,
                        f"{name}: dynamic NAT rule {rid} needs a translation pool but references none.",
                        device=name, object_type="nat_rule", object_id=rid, field_path=f"{path}.pool_id",
                        evidence={"mode": "DYNAMIC"}, remediation="Select a NAT pool for the dynamic rule.")
        if rules:
            ctx.add(Code.NAT_ROLE_UNVERIFIED,
                    f"{name}: NAT inside/outside directionality was not evaluated against topology (no role metadata exists); "
                    "no translation behavior is simulated.",
                    device=name, object_type="nat", object_id=name, source="TOPOLOGY",
                    evidence={"rules": len(rules)}, remediation="None required; roles are taken from the accepted intent.")


def _dhcp_dns(ctx) -> None:
    for name in sorted(ctx.model.devices):
        device = ctx.model.devices[name]
        for relay in sorted((device.dhcp.get("relays") or {}).values(), key=lambda r: r.get("id", "")):
            destination = _ip(relay.get("destination"))
            if destination is None:
                continue
            path = f"services.dhcp.relays.{relay['id']}.destination"
            want = 4 if relay.get("family") == "IPV4" else 6
            if destination.version != want:
                ctx.add(Code.DHCP_RELAY_FAMILY_MISMATCH,
                        f"{name}: DHCP relay {relay['id']} ({relay.get('family')}) targets {destination}, the wrong address family.",
                        device=name, object_type="dhcp_relay", object_id=relay["id"], field_path=path,
                        evidence={"destination": str(destination), "family": relay.get("family")},
                        remediation="Use a relay destination of the relay's address family.")
                continue
            label = _known(ctx, destination)
            if label:
                ctx.derive("DHCP_RELAY_DESTINATION", device=name, object_id=relay["id"], destination=str(destination), known_as=label)
            elif ctx.inventory is not None or ctx.netbox is not None:
                ctx.add(Code.DHCP_RELAY_UNRESOLVED,
                        f"{name}: DHCP relay destination {destination} is not a project-known service address (not pinged or resolved).",
                        device=name, object_type="dhcp_relay", object_id=relay["id"], field_path=path,
                        evidence={"destination": str(destination)},
                        remediation="Use the NMAS primary / R2 secondary DHCP server addresses, or confirm the target.")
        if device.dns.get("mode") == "OVERRIDE":
            for resolver in sorted((device.dns.get("resolvers") or {}).values(), key=lambda r: r.get("id", "")):
                address = _ip(resolver.get("address"))
                if address is None:
                    continue
                if not _known(ctx, address) and (ctx.inventory is not None or ctx.netbox is not None):
                    ctx.add(Code.DNS_RESOLVER_UNRESOLVED,
                            f"{name}: DNS resolver {address} is not a project-known address (no DNS query was made).",
                            device=name, object_type="dns_resolver", object_id=resolver["id"],
                            field_path=f"services.dns.resolvers.{resolver['id']}.address",
                            evidence={"address": str(address)},
                            remediation="Confirm the resolver address; no external lookup is performed by validation.")


def _pbr(ctx) -> None:
    for name in sorted(ctx.model.devices):
        device = ctx.model.devices[name]
        policies = device.pbr.get("policies") or {}
        for policy in sorted(policies.values(), key=lambda p: p.get("id", "")):
            feature = f"PBR_{policy.get('family')}"
            if not platform_drivers.is_service_policy_feature_selectable(device.platform, feature):
                continue  # capability validation already blocks it; no simulation of an undeployable feature
            local = [(r.network, r) for r in ctx.model.device_addresses(name)]
            for seq in sorted((policy.get("sequences") or {}).values(), key=lambda s: s.get("id", "")):
                hop = _ip(seq.get("next_hop"))
                if hop is not None and not any(n.version == hop.version and hop in n for n, _ in local):
                    ctx.add(Code.PBR_NEXT_HOP_UNRESOLVED,
                            f"{name}: PBR next hop {hop} is not in a directly connected candidate network.",
                            device=name, object_type="pbr_sequence", object_id=seq["id"],
                            field_path=f"policy.pbr.policies.{policy['id']}.sequences.{seq['id']}.next_hop",
                            evidence={"next_hop": str(hop)}, remediation="Use a next hop reachable over a connected interface.")


def validate_services_policy(ctx) -> None:
    _nat(ctx)
    _dhcp_dns(ctx)
    _pbr(ctx)
