"""Cross-device routing consistency (static, OSPF, RIP, BGP, router IDs).

This is NOT a routing simulator.  Every rule needs concrete evidence:

* static routes   family consistency, self next hop, connected-network
                  reachability of the next hop (WARNING when it cannot be
                  established), implausible layer-2 exit interfaces
* OSPF            version / area / network-type agreement across a topology
                  link when BOTH ends are candidate OSPF participants; a
                  one-sided end is only INFO (the other side may be
                  intentionally non-OSPF); router-ID uniqueness per version
* RIP             address-family agreement across a link
* BGP             peer resolution against candidate + NetBox addresses,
                  reciprocal ASN / address-family checks when both peers are
                  candidate-controlled, external/unresolved peers are a
                  WARNING never a false BLOCK, advertisement evidence
* router IDs      unique per protocol family, never across unrelated families
"""

from __future__ import annotations

import ipaddress

from .findings import Code, Severity
from .topology import get_link_pairs, link_label


def _parse_ip(text):
    try:
        return ipaddress.ip_address(str(text))
    except ValueError:
        return None


def _parse_net(text):
    try:
        return ipaddress.ip_network(str(text), strict=False)
    except ValueError:
        return None


def _device_networks(ctx, device: str):
    """(network, source label) for every connected network known for a device."""
    found = [(r.network, f"candidate {r.interface_name}") for r in ctx.model.device_addresses(device)]
    if ctx.netbox is not None:
        for row in ctx.netbox["ip_addresses"]:
            if row["device"] == device:
                found.append((ipaddress.ip_interface(row["cidr"]).network, f"netbox {row['interface']}"))
    return found


def _device_ips(ctx, device: str) -> set:
    ips = {r.ip for r in ctx.model.device_addresses(device)}
    if ctx.netbox is not None:
        ips |= {ipaddress.ip_address(row["ip"]) for row in ctx.netbox["ip_addresses"] if row["device"] == device}
    return ips


# --- static routes -----------------------------------------------------------

def _static_routes(ctx) -> None:
    for name in sorted(ctx.model.devices):
        device = ctx.model.devices[name]
        for route in sorted((device.routing.get("static_routes") or {}).values(), key=lambda r: r.get("id", "")):
            rid = route["id"]
            family = 4 if route.get("family") == "IPV4" else 6
            path = f"routing.static_routes.{rid}"
            destination = _parse_net(route.get("destination"))
            if destination is not None and destination.version != family:
                ctx.add(Code.ROUTE_FAMILY_MISMATCH,
                        f"{name}: static route destination {destination} is not {route.get('family')}.",
                        device=name, object_type="static_route", object_id=rid, field_path=path + ".destination",
                        evidence={"destination": str(destination), "family": route.get("family")},
                        remediation="Use a destination of the route's address family.")
                continue
            if route.get("next_hop_type") == "INTERFACE":
                interface = device.interfaces.get(route.get("next_hop_interface_id") or "")
                if interface is not None and interface.get("kind") in ("ACCESS", "TRUNK"):
                    ctx.add(Code.ROUTE_EXIT_INTERFACE_IMPLAUSIBLE,
                            f"{name}: static route {route.get('destination')} exits through layer-2 interface {interface.get('name')}.",
                            device=name, object_type="static_route", object_id=rid, field_path=path + ".next_hop_interface_id",
                            evidence={"interface": interface.get("name"), "kind": interface.get("kind")},
                            remediation="Route through a routed port, SVI or subinterface.")
                continue
            hop = _parse_ip(route.get("next_hop_address"))
            if hop is None:
                continue
            if hop.version != family:
                ctx.add(Code.ROUTE_FAMILY_MISMATCH,
                        f"{name}: next hop {hop} is not {route.get('family')}.",
                        device=name, object_type="static_route", object_id=rid, field_path=path + ".next_hop_address",
                        evidence={"next_hop": str(hop), "family": route.get("family")},
                        remediation="Use a next hop of the route's address family.")
                continue
            if hop in _device_ips(ctx, name):
                ctx.add(Code.ROUTE_NEXT_HOP_SELF,
                        f"{name}: static route {route.get('destination')} uses the device's own address {hop} as next hop.",
                        device=name, object_type="static_route", object_id=rid, field_path=path + ".next_hop_address",
                        evidence={"next_hop": str(hop)}, remediation="Point the route at a neighbor's address.")
                continue
            via = next((label for network, label in _device_networks(ctx, name)
                        if network.version == hop.version and hop in network), None)
            if via is None:
                ctx.add(Code.ROUTE_NEXT_HOP_UNRESOLVED,
                        f"{name}: next hop {hop} of static route {route.get('destination')} is not in any known connected network.",
                        device=name, object_type="static_route", object_id=rid, field_path=path + ".next_hop_address",
                        evidence={"next_hop": str(hop), "destination_contains_next_hop": bool(destination and hop in destination),
                                  "netbox_evidence": ctx.netbox is not None},
                        remediation="Reachability was not established; confirm a connected interface reaches the next hop.")
            else:
                owners = [r for r in ctx.model.addresses if r.ip == hop and r.device != name]
                ctx.derive("STATIC_ROUTE_NEXT_HOP", device=name, object_id=rid, next_hop=str(hop), via=via,
                           next_hop_owner=(f"{owners[0].device}:{owners[0].interface_name}" if owners else None))


# --- OSPF / RIP participation ---------------------------------------------------

def _area_key(value):
    text = str(value if value is not None else "").strip()
    if not text:
        return ""
    if text.isdigit():
        return int(text)
    try:
        return int(ipaddress.IPv4Address(text))
    except ValueError:
        return text.lower()


def _participation(model, family: str) -> dict:
    """(device, interface_id) -> [binding info] for one protocol family."""
    result: dict = {}
    for name in sorted(model.devices):
        device = model.devices[name]
        for instance in sorted((device.routing.get(family) or {}).values(), key=lambda r: r.get("id", "")):
            for binding in sorted((instance.get("interfaces") or {}).values(), key=lambda b: b.get("id", "")):
                result.setdefault((name, binding.get("interface_id")), []).append({
                    "instance": instance, "binding": binding,
                    "version": instance.get("version") or instance.get("address_family"),
                    "area": _area_key(binding.get("area")), "network_type": binding.get("network_type") or "",
                })
    return result


def _ospf(ctx) -> None:
    for name in sorted(ctx.model.devices):
        device = ctx.model.devices[name]
        if device.platform != "arista_ceos":
            continue
        for instance in sorted((device.routing.get("ospf") or {}).values(), key=lambda row: row.get("id", "")):
            if instance.get("process_id") in (None, ""):
                ctx.add(
                    Code.OSPF_PROCESS_ID_REQUIRED,
                    "OSPF enabled but process_id is not configured.",
                    device=name,
                    object_type="routing_ospf",
                    object_id=instance.get("id"),
                    field_path=f"routing.ospf.{instance.get('id')}.process_id",
                    evidence={"version": instance.get("version"), "platform": device.platform},
                    remediation="Configure the cEOS OSPF process ID before building a deployment plan.",
                )
    part = _participation(ctx.model, "ospf")
    for pair in get_link_pairs(ctx):
        a, z = pair["a"], pair["z"]
        if not (a["interface"] and z["interface"]):
            continue
        pa, pz = part.get((a["device"], a["interface"]["id"]), []), part.get((z["device"], z["interface"]["id"]), [])
        if not pa and not pz:
            continue
        if bool(pa) != bool(pz):
            side, other = (a, z) if pa else (z, a)
            ctx.add(Code.OSPF_ONE_SIDED,
                    f"{side['device']}:{side['name']} runs OSPF but {other['device']}:{other['name']} (same link) has no OSPF binding.",
                    device=side["device"], object_type="link", object_id=link_label(pair),
                    related_devices=[other["device"]], source="TOPOLOGY+INTENT",
                    evidence={"participating_end": f"{side['device']}:{side['name']}"},
                    remediation="Bind the far end if an adjacency is intended; otherwise this is informational.")
            continue
        versions_a, versions_z = {p["version"] for p in pa}, {p["version"] for p in pz}
        if not versions_a & versions_z:
            ctx.add(Code.OSPF_VERSION_MISMATCH,
                    f"OSPF versions differ across {link_label(pair)} ({sorted(versions_a)} vs {sorted(versions_z)}).",
                    device=a["device"], object_type="link", object_id=link_label(pair), related_devices=[z["device"]],
                    source="TOPOLOGY+INTENT", evidence={"a": sorted(versions_a), "z": sorted(versions_z)},
                    remediation="Run the same OSPF version on both ends of the link.")
            continue
        for version in sorted(versions_a & versions_z):
            ba = next(p for p in pa if p["version"] == version)
            bz = next(p for p in pz if p["version"] == version)
            if ba["area"] != bz["area"]:
                ctx.add(Code.OSPF_AREA_MISMATCH,
                        f"OSPF area differs across {link_label(pair)} ({ba['binding'].get('area')} vs {bz['binding'].get('area')}).",
                        device=a["device"], object_type="link", object_id=link_label(pair), related_devices=[z["device"]],
                        source="TOPOLOGY+INTENT",
                        evidence={"version": version, "a_area": ba["binding"].get("area"), "z_area": bz["binding"].get("area")},
                        remediation="Place both ends of the link in the same OSPF area.")
            if ba["network_type"] and bz["network_type"] and ba["network_type"] != bz["network_type"]:
                ctx.add(Code.OSPF_NETWORK_TYPE_MISMATCH,
                        f"OSPF network type differs across {link_label(pair)} ({ba['network_type']} vs {bz['network_type']}).",
                        device=a["device"], object_type="link", object_id=link_label(pair), related_devices=[z["device"]],
                        source="TOPOLOGY+INTENT", evidence={"a": ba["network_type"], "z": bz["network_type"]},
                        remediation="Use the same OSPF network type on both ends.")


def _rip(ctx) -> None:
    part = _participation(ctx.model, "rip")
    for pair in get_link_pairs(ctx):
        a, z = pair["a"], pair["z"]
        if not (a["interface"] and z["interface"]):
            continue
        pa, pz = part.get((a["device"], a["interface"]["id"]), []), part.get((z["device"], z["interface"]["id"]), [])
        if pa and pz and not ({p["version"] for p in pa} & {p["version"] for p in pz}):
            ctx.add(Code.RIP_FAMILY_MISMATCH,
                    f"RIP address families differ across {link_label(pair)}.",
                    device=a["device"], object_type="link", object_id=link_label(pair), related_devices=[z["device"]],
                    source="TOPOLOGY+INTENT",
                    evidence={"a": sorted({p["version"] for p in pa}), "z": sorted({p["version"] for p in pz})},
                    remediation="Run RIPv2 (IPv4) or RIPng (IPv6) consistently on both ends.")


def _binding_addresses(ctx) -> None:
    """IPv4 protocols need an IPv4 address; IPv6 protocols use link-local so are not judged."""
    if ctx.netbox is None:
        return
    for family in ("ospf", "rip"):
        for (device, interface_id), items in sorted(_participation(ctx.model, family).items(), key=lambda kv: (kv[0][0], str(kv[0][1]))):
            interface = ctx.model.find_interface(device, interface_id or "")
            if interface is None:
                continue  # dangling reference: reported by the dependency graph
            if not any(item["version"] in ("OSPFV2", "IPV4") for item in items):
                continue
            has_candidate = any(r.family == 4 for r in ctx.model.addresses_of(device, interface_id))
            has_netbox = any(row["family"] == 4 for row in ctx.netbox_addresses_of(device, interface.get("name") or ""))
            has_auto = any(a["address"].get("family") == "IPV4" and a["device"] == device and a["interface"]["id"] == interface_id
                           for a in ctx.model.auto_addresses)
            if not (has_candidate or has_netbox or has_auto):
                ctx.add(Code.ROUTING_INTERFACE_NO_ADDRESS,
                        f"{device}:{interface.get('name')} is bound to {family.upper()} but has no IPv4 address in the Change or NetBox.",
                        device=device, object_type="interface", object_id=interface_id, source="INTENT+NETBOX",
                        evidence={"protocol": family},
                        remediation="Assign an IPv4 address to the interface or unbind it.")


# --- BGP -------------------------------------------------------------------------

def _af_set(neighbor) -> set:
    return {name for name, flag in (("IPV4", neighbor.get("activate_ipv4")), ("IPV6", neighbor.get("activate_ipv6"))) if flag}


def _bgp(ctx) -> None:
    pairs: set = set()
    ctx.cache["bgp_peer_pairs"] = pairs
    afi_reported: set = set()
    for name in sorted(ctx.model.devices):
        device = ctx.model.devices[name]
        instances = sorted((device.routing.get("bgp") or {}).values(), key=lambda r: r.get("id", ""))
        for instance in instances:
            neighbors = sorted((instance.get("neighbors") or {}).values(), key=lambda n: n.get("id", ""))
            for neighbor in neighbors:
                _bgp_neighbor(ctx, name, instance, neighbor, pairs, afi_reported)
            active = set().union(*(_af_set(n) for n in neighbors)) if neighbors else set()
            for network in sorted((instance.get("networks") or {}).values(), key=lambda n: n.get("id", "")):
                _bgp_network(ctx, name, device, instance, network, active)


def _bgp_neighbor(ctx, name, instance, neighbor, pairs, afi_reported) -> None:
    nid = neighbor["id"]
    path = f"routing.bgp.{instance['id']}.neighbors.{nid}"
    ip = _parse_ip(neighbor.get("peer_address"))
    if ip is None:
        return
    if not _af_set(neighbor):
        ctx.add(Code.BGP_AF_MISMATCH,
                f"{name}: BGP neighbor {ip} activates no address family.",
                severity=Severity.WARNING, device=name, object_type="bgp_neighbor", object_id=nid, field_path=path,
                evidence={"neighbor_family": neighbor.get("family")},
                remediation="Activate the address family the neighbor should carry.")
    owners = [r for r in ctx.model.addresses if r.ip == ip and r.device != name]
    if owners:
        peer = owners[0]
        peer_device = ctx.model.devices[peer.device]
        peer_instances = sorted((peer_device.routing.get("bgp") or {}).values(), key=lambda r: r.get("id", ""))
        local_ips = _device_ips(ctx, name)

        def reciprocal_of(candidate_instance):
            for other in (candidate_instance.get("neighbors") or {}).values():
                other_ip = _parse_ip(other.get("peer_address"))
                if other_ip is not None and other_ip in local_ips:
                    return other
            return None

        chosen, reciprocal = None, None
        for candidate in peer_instances:
            found = reciprocal_of(candidate)
            if found is not None:
                chosen, reciprocal = candidate, found
                break
        if chosen is None and peer_instances:
            chosen = peer_instances[0]
        ctx.derive("BGP_PEER_RESOLVED", device=name, neighbor_id=nid, peer_address=str(ip), scope="CANDIDATE",
                   peer_device=peer.device, peer_interface=peer.interface_name,
                   peer_local_asn=(chosen or {}).get("local_asn"), reciprocal=reciprocal is not None)
        pairs.add(frozenset({name, peer.device}))
        if chosen is None:
            ctx.add(Code.BGP_PEER_NO_RECIPROCAL,
                    f"{name}: BGP peer {ip} resolves to {peer.device}:{peer.interface_name}, which has no BGP instance in the Change.",
                    device=name, object_type="bgp_neighbor", object_id=nid, field_path=path, related_devices=[peer.device],
                    evidence={"peer_device": peer.device}, remediation="Configure BGP on the peer or remove the neighbor.")
            return
        if neighbor.get("remote_asn") != chosen.get("local_asn"):
            ctx.add(Code.BGP_REMOTE_AS_MISMATCH,
                    f"{name}: neighbor {ip} is configured remote-as {neighbor.get('remote_asn')} but {peer.device} runs AS {chosen.get('local_asn')}.",
                    device=name, object_type="bgp_neighbor", object_id=nid, field_path=path + ".remote_asn",
                    related_devices=[peer.device],
                    evidence={"configured_remote_asn": neighbor.get("remote_asn"), "peer_local_asn": chosen.get("local_asn"),
                              "local_asn": instance.get("local_asn")},
                    remediation="Set the neighbor's remote ASN to the peer's local ASN.")
        if reciprocal is None:
            ctx.add(Code.BGP_PEER_NO_RECIPROCAL,
                    f"{peer.device} has no BGP neighbor pointing back at {name}; the session cannot establish from that side.",
                    device=name, object_type="bgp_neighbor", object_id=nid, field_path=path, related_devices=[peer.device],
                    evidence={"peer_device": peer.device}, remediation="Add the reciprocal neighbor on the peer.")
            return
        mine, theirs = _af_set(neighbor), _af_set(reciprocal)
        key = frozenset({(name, nid), (peer.device, reciprocal["id"])})
        if mine and theirs and not (mine & theirs) and key not in afi_reported:
            afi_reported.add(key)
            ctx.add(Code.BGP_AF_MISMATCH,
                    f"BGP peers {name} and {peer.device} activate no common address family ({sorted(mine)} vs {sorted(theirs)}).",
                    device=name, object_type="bgp_neighbor", object_id=nid, field_path=path, related_devices=[peer.device],
                    related_objects=[f"{peer.device}:{reciprocal['id']}"],
                    evidence={"local": sorted(mine), "peer": sorted(theirs)},
                    remediation="Activate a common address family on both peers.")
        return
    rows = ctx.netbox_records_for_ip(ip)
    if rows:
        row = rows[0]
        ctx.derive("BGP_PEER_RESOLVED", device=name, neighbor_id=nid, peer_address=str(ip), scope="NETBOX",
                   peer_device=row["device"], peer_interface=row["interface"], peer_local_asn=None, reciprocal=False)
        return
    ctx.add(Code.BGP_PEER_UNRESOLVED,
            f"{name}: BGP peer {ip} matches no project-known interface address (it may be an external provider outside inventory).",
            device=name, object_type="bgp_neighbor", object_id=nid, field_path=path + ".peer_address",
            evidence={"peer_address": str(ip), "session_type": "EBGP" if neighbor.get("remote_asn") != instance.get("local_asn") else "IBGP",
                      "netbox_evidence": ctx.netbox is not None},
            remediation="No action is required for an external peer; verify the address if the peer should be internal.")


def _bgp_network(ctx, name, device, instance, network, active) -> None:
    net = _parse_net(network.get("cidr"))
    if net is None:
        return
    fam = "IPV4" if net.version == 4 else "IPV6"
    path = f"routing.bgp.{instance['id']}.networks.{network['id']}"
    if instance.get("neighbors") and fam not in active:
        ctx.add(Code.BGP_AF_MISMATCH,
                f"{name}: BGP advertises {net} but no neighbor activates {fam}.",
                severity=Severity.WARNING, device=name, object_type="bgp_network", object_id=network["id"], field_path=path,
                evidence={"network_family": fam, "active_families": sorted(active)},
                remediation="Activate the address family on a neighbor, or remove the advertisement.")
    evidence = [label for candidate, label in _device_networks(ctx, name) if candidate == net]
    evidence += [f"static route {r.get('destination')}" for r in (device.routing.get("static_routes") or {}).values()
                 if _parse_net(r.get("destination")) == net]
    if not evidence and (ctx.netbox is not None or device.target_type == "NEW_DEVICE"):
        ctx.add(Code.BGP_NETWORK_NO_EVIDENCE,
                f"{name}: advertised prefix {net} has no matching connected or static route evidence.",
                device=name, object_type="bgp_network", object_id=network["id"], field_path=path,
                evidence={"prefix": str(net)},
                remediation="BGP advertises only prefixes present in the RIB; add the connected/static route or drop the network.")


# --- router IDs ---------------------------------------------------------------------

def _router_ids(ctx) -> None:
    pairs = ctx.cache.get("bgp_peer_pairs", set())
    groups: dict = {}
    for name in sorted(ctx.model.devices):
        device = ctx.model.devices[name]
        for instance in (device.routing.get("ospf") or {}).values():
            if instance.get("router_id"):
                groups.setdefault((instance.get("version") or "OSPF", instance["router_id"]), []).append((name, instance))
        for instance in (device.routing.get("bgp") or {}).values():
            if instance.get("router_id"):
                groups.setdefault(("BGP", instance["router_id"]), []).append((name, instance))
    for (family, rid), members in sorted(groups.items(), key=lambda kv: (kv[0][0], kv[0][1])):
        devices = sorted({name for name, _ in members})
        if len(devices) < 2:
            continue
        blocking = True
        if family == "BGP":
            asns = {inst.get("local_asn") for _, inst in members}
            peered = any(frozenset({a, b}) in pairs for a in devices for b in devices if a < b)
            blocking = len(asns) == 1 or peered
        ctx.add(Code.ROUTER_ID_DUPLICATE,
                f"Router ID {rid} is used by {family} on {', '.join(devices)}.",
                severity=Severity.ERROR if blocking else Severity.WARNING,
                device=devices[0], object_type="routing_instance", object_id=members[0][1]["id"],
                related_devices=devices[1:], related_objects=[f"{n}:{i['id']}" for n, i in members],
                evidence={"protocol": family, "router_id": rid, "devices": devices},
                remediation="Give every router a unique router ID within each protocol.")


def validate_routing(ctx) -> None:
    _static_routes(ctx)
    _ospf(ctx)
    _rip(ctx)
    _binding_addresses(ctx)
    _bgp(ctx)
    _router_ids(ctx)
    ctx.checked["routing_objects"] = sum(
        len(group or {}) for d in ctx.model.devices.values() for group in d.routing.values() if isinstance(group, dict)
    )
