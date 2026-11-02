"""Conservative ACL first-match traffic-impact analysis.

This is NOT a firewall theorem prover.  It evaluates only the structured
Phase-12 entries (action, protocol IP/IPV6/TCP/UDP/ICMP/ICMPV6, source/
destination ANY|HOST|PREFIX, optional port/range) -- never raw CLI -- against
a small catalogue of REQUIRED flows for which the project has concrete
endpoints:

    management (SSH/SNMP/gNMI/NETCONF/syslog to/from the inventory NMAS
    address on a management interface), OSPF hellos on an OSPF-bound
    interface, BGP TCP/179 for a candidate peer, DHCP relay client/server
    UDP on the relay interface.

Matching is THREE-VALUED (MATCH / NO_MATCH / MAYBE).  Evaluation follows
first-match order: a later permit never rescues an earlier matching deny, and
a later deny never matters after a definitive earlier permit.  Only an
EXPLICIT definitive deny yields ACL_REQUIRED_FLOW_DENIED (blocking).  Anything
uncertain -- unknown source, a MAYBE entry that could flip the outcome, or
reaching the implicit end-of-list deny -- is ACL_EFFECT_UNKNOWN (WARNING).
"""

from __future__ import annotations

import ipaddress

from .context import is_management_interface
from .findings import Code, Severity
from .topology import get_link_pairs

MATCH, NO_MATCH, MAYBE = "MATCH", "NO_MATCH", "MAYBE"
PERMIT, DENY, UNKNOWN, IMPLICIT_DENY = "PERMIT", "DENY", "UNKNOWN", "IMPLICIT_DENY"

MANAGEMENT_SERVICES = (
    ("ssh", "TCP", 22), ("snmp", "UDP", 161), ("gnmi", "TCP", 6030), ("netconf", "TCP", 830),
)
SYSLOG_PORT = 514


def _and(*values):
    if NO_MATCH in values:
        return NO_MATCH
    return MAYBE if MAYBE in values else MATCH


def _proto(entry_proto: str, flow_proto: str, family: int) -> str:
    if entry_proto == "IP":
        return MATCH if family == 4 else NO_MATCH
    if entry_proto == "IPV6":
        return MATCH if family == 6 else NO_MATCH
    if entry_proto == flow_proto:
        return MATCH
    return NO_MATCH


def _addr(match_type: str, value: str, flow_addr) -> str:
    if match_type == "ANY":
        return MATCH
    if flow_addr is None:
        return MAYBE
    try:
        if match_type == "HOST":
            return MATCH if ipaddress.ip_address(value) == flow_addr else NO_MATCH
        if match_type == "PREFIX":
            network = ipaddress.ip_network(value, strict=False)
            return MATCH if network.version == flow_addr.version and flow_addr in network else NO_MATCH
    except ValueError:
        return MAYBE
    return MAYBE


def _port_bounds(text: str):
    text = str(text or "").strip()
    if not text:
        return None
    try:
        if "-" in text:
            low, high = text.split("-", 1)
            return int(low), int(high)
        return int(text), int(text)
    except ValueError:
        return "invalid"


def _port(entry_port: str, flow_port, flow_proto: str) -> str:
    bounds = _port_bounds(entry_port)
    if bounds is None:
        return MATCH
    if flow_proto not in ("TCP", "UDP") or bounds == "invalid":
        return NO_MATCH if flow_proto not in ("TCP", "UDP") else MAYBE
    if flow_port is None:
        return MAYBE
    return MATCH if bounds[0] <= flow_port <= bounds[1] else NO_MATCH


def entry_match(entry: dict, flow: dict) -> str:
    return _and(
        _proto(entry.get("protocol"), flow["proto"], flow["family"]),
        _addr(entry.get("source_type"), entry.get("source_value"), flow.get("src")),
        _addr(entry.get("destination_type"), entry.get("destination_value"), flow.get("dst")),
        _port(entry.get("source_port"), flow.get("sport"), flow["proto"]),
        _port(entry.get("destination_port"), flow.get("dport"), flow["proto"]),
    )


def ordered_entries(acl: dict) -> list[dict]:
    return sorted((acl.get("entries") or {}).values(), key=lambda e: (int(e.get("sequence") or 0), e.get("id", "")))


def evaluate(acl: dict, flow: dict) -> dict:
    """First-match evaluation of one flow against one ACL (three-valued)."""
    maybe_actions = []
    for entry in ordered_entries(acl):
        verdict = entry_match(entry, flow)
        if verdict == NO_MATCH:
            continue
        if verdict == MAYBE:
            maybe_actions.append(entry.get("action"))
            continue
        if any(action != entry.get("action") for action in maybe_actions):
            return {"verdict": UNKNOWN, "entry": entry, "reason": "an earlier entry may match with the opposite action"}
        return {"verdict": PERMIT if entry.get("action") == "PERMIT" else DENY, "entry": entry, "reason": "first definitive match"}
    if "PERMIT" in maybe_actions:
        return {"verdict": UNKNOWN, "entry": None, "reason": "a permit may match but the flow attributes are not fully known"}
    return {"verdict": IMPLICIT_DENY, "entry": None, "reason": "no explicit entry matched; the implicit end-of-list deny applies"}


# --- shadowed entries -------------------------------------------------------------

def _addr_covers(a_type, a_val, b_type, b_val) -> bool:
    if a_type == "ANY":
        return True
    if b_type == "ANY":
        return False
    try:
        a = ipaddress.ip_network(a_val, strict=False) if a_type == "PREFIX" else ipaddress.ip_network(f"{a_val}/{ipaddress.ip_address(a_val).max_prefixlen}")
        b = ipaddress.ip_network(b_val, strict=False) if b_type == "PREFIX" else ipaddress.ip_network(f"{b_val}/{ipaddress.ip_address(b_val).max_prefixlen}")
        return a.version == b.version and b.subnet_of(a)
    except ValueError:
        return False


def _port_covers(a, b) -> bool:
    ba, bb = _port_bounds(a), _port_bounds(b)
    if ba is None:
        return True
    if bb is None or "invalid" in (ba, bb):
        return False
    return ba[0] <= bb[0] and bb[1] <= ba[1]


def _proto_covers(a: str, b: str, family: str) -> bool:
    return a == b or (a == "IP" and family == "IPV4") or (a == "IPV6" and family == "IPV6")


def _covers(a: dict, b: dict, family: str) -> bool:
    return (
        _proto_covers(a.get("protocol"), b.get("protocol"), family)
        and _addr_covers(a.get("source_type"), a.get("source_value"), b.get("source_type"), b.get("source_value"))
        and _addr_covers(a.get("destination_type"), a.get("destination_value"), b.get("destination_type"), b.get("destination_value"))
        and _port_covers(a.get("source_port"), b.get("source_port"))
        and _port_covers(a.get("destination_port"), b.get("destination_port"))
    )


def _shadowed(ctx) -> None:
    for name in sorted(ctx.model.devices):
        device = ctx.model.devices[name]
        for acl in sorted(device.acls.values(), key=lambda a: a.get("id", "")):
            entries = ordered_entries(acl)
            for index, later in enumerate(entries):
                cover = next((e for e in entries[:index] if _covers(e, later, acl.get("family"))), None)
                if cover is None:
                    continue
                contradictory = cover.get("action") != later.get("action")
                ctx.add(Code.ACL_ENTRY_SHADOWED,
                        f"{name}: ACL {acl.get('name')} entry {later.get('sequence')} ({later.get('action')}) can never match; "
                        f"entry {cover.get('sequence')} ({cover.get('action')}) covers it"
                        + (" with the opposite action." if contradictory else "."),
                        device=name, object_type="acl_entry", object_id=later.get("id"),
                        field_path=f"security.acls.{acl['id']}.entries.{later.get('id')}",
                        evidence={"shadowed_sequence": later.get("sequence"), "covering_sequence": cover.get("sequence"),
                                  "contradictory": contradictory},
                        remediation="Reorder or remove the unreachable entry.")


# --- required flows ---------------------------------------------------------------------

def _flow(name, purpose, direction, proto, family, *, src=None, dst=None, sport=None, dport=None):
    return {"name": name, "purpose": purpose, "direction": direction, "proto": proto, "family": family,
            "src": src, "dst": dst, "sport": sport, "dport": dport}


def _ip(text):
    try:
        return ipaddress.ip_address(str(text))
    except ValueError:
        return None


def _first_addr(ctx, device, interface_id, family):
    records = [r for r in ctx.model.addresses_of(device, interface_id) if r.family == family and not r.ip.is_link_local]
    return records[0].ip if records else None


def _link_peer_addr(ctx, device, interface_id, family):
    for pair in get_link_pairs(ctx):
        for near, far in ((pair["a"], pair["z"]), (pair["z"], pair["a"])):
            if near["device"] == device and near["interface"] and near["interface"]["id"] == interface_id:
                if far["interface"]:
                    addrs = [r.ip for r in ctx.model.addresses_of(far["device"], far["interface"]["id"])
                             if r.family == family and not r.ip.is_link_local]
                else:
                    addrs = [ipaddress.ip_address(r["ip"]) for r in ctx.netbox_addresses_of(far["device"], far["name"])
                             if r["family"] == family and not ipaddress.ip_address(r["ip"]).is_link_local]
                return addrs[0] if len(addrs) == 1 else None
    return None


def _required_flows(ctx, name, device, attachment, acl, interface) -> list[dict]:
    iid = interface["id"]
    family = 4 if acl.get("family") == "IPV4" else 6
    own = _first_addr(ctx, name, iid, family)
    flows: list[dict] = []

    if is_management_interface(interface) and ctx.inventory is not None:
        nmas = _ip(ctx.inventory["management"].get("nmas_ipv4" if family == 4 else "nmas_ipv6"))
        if nmas is not None:
            for service, proto, port in MANAGEMENT_SERVICES:
                flows.append(_flow(f"management-{service}-request", f"NMAS {service.upper()} to the device", "IN", proto, family,
                                   src=nmas, dst=own, dport=port))
                flows.append(_flow(f"management-{service}-reply", f"device {service.upper()} replies to NMAS", "OUT", proto, family,
                                   src=own, dst=nmas, sport=port))
            flows.append(_flow("management-syslog", "device syslog to NMAS", "OUT", "UDP", family, src=own, dst=nmas, dport=SYSLOG_PORT))

    for instance in sorted((device.routing.get("ospf") or {}).values(), key=lambda r: r.get("id", "")):
        version_family = 4 if instance.get("version") == "OSPFV2" else 6
        if version_family != family:
            continue
        for binding in (instance.get("interfaces") or {}).values():
            if binding.get("interface_id") != iid or binding.get("passive"):
                continue
            group = _ip("224.0.0.5" if family == 4 else "ff02::5")
            flows.append(_flow("ospf-hello-in", "OSPF hellos from the neighbor", "IN", "OSPF", family,
                               src=_link_peer_addr(ctx, name, iid, family), dst=group))
            flows.append(_flow("ospf-hello-out", "OSPF hellos to the neighbor", "OUT", "OSPF", family, src=own, dst=group))

    for instance in sorted((device.routing.get("bgp") or {}).values(), key=lambda r: r.get("id", "")):
        for neighbor in (instance.get("neighbors") or {}).values():
            peer = _ip(neighbor.get("peer_address"))
            if peer is None or peer.version != family:
                continue
            if not any(r.family == family and peer in r.network for r in ctx.model.addresses_of(name, iid)):
                continue  # the peer is not reached over this interface
            for direction, src, dst in (("IN", peer, own), ("OUT", own, peer)):
                flows.append(_flow(f"bgp-{direction.lower()}-to-179", f"BGP TCP/179 with {peer}", direction, "TCP", family,
                                   src=src, dst=dst, dport=179))
                flows.append(_flow(f"bgp-{direction.lower()}-from-179", f"BGP TCP/179 with {peer} (reverse)", direction, "TCP", family,
                                   src=src, dst=dst, sport=179))

    for relay in sorted((device.dhcp.get("relays") or {}).values(), key=lambda r: r.get("id", "")):
        if relay.get("interface_id") != iid or (4 if relay.get("family") == "IPV4" else 6) != family:
            continue
        if family == 4:
            flows.append(_flow("dhcp-client-to-relay", "DHCP client discover/request to the relay", "IN", "UDP", 4,
                               src=_ip("0.0.0.0"), dst=_ip("255.255.255.255"), sport=68, dport=67))
            flows.append(_flow("dhcp-relay-to-client", "DHCP relay reply toward the client", "OUT", "UDP", 4,
                               src=own, dst=_ip("255.255.255.255"), sport=67, dport=68))
        else:
            flows.append(_flow("dhcpv6-client-to-relay", "DHCPv6 solicit to the relay", "IN", "UDP", 6,
                               dst=_ip("ff02::1:2"), sport=546, dport=547))
            flows.append(_flow("dhcpv6-relay-to-client", "DHCPv6 relay reply toward the client", "OUT", "UDP", 6,
                               sport=547, dport=546))
    return flows


def validate_acls(ctx) -> None:
    _shadowed(ctx)
    evaluated = 0
    for name in sorted(ctx.model.devices):
        device = ctx.model.devices[name]
        seen: dict = {}
        for attachment in sorted(device.acl_attachments.values(), key=lambda a: a.get("id", "")):
            acl = device.acls.get(attachment.get("acl_id") or "")
            interface = device.interfaces.get(attachment.get("interface_id") or "")
            if acl is None or interface is None:
                continue  # dangling references are DEPENDENCY_MISSING, not an ACL-effect question
            key = (attachment.get("interface_id"), attachment.get("direction"), acl.get("family"))
            seen.setdefault(key, []).append((attachment, acl))
            for flow in _required_flows(ctx, name, device, attachment, acl, interface):
                if flow["direction"] != attachment.get("direction"):
                    continue
                evaluated += 1
                result = evaluate(acl, flow)
                flow_evidence = {
                    "flow": flow["name"], "purpose": flow["purpose"], "direction": flow["direction"],
                    "protocol": flow["proto"], "src": str(flow["src"]) if flow["src"] else None,
                    "dst": str(flow["dst"]) if flow["dst"] else None, "sport": flow["sport"], "dport": flow["dport"],
                    "acl": acl.get("name"), "interface": interface.get("name"),
                }
                entry = result["entry"]
                if result["verdict"] == DENY:
                    ctx.add(Code.ACL_REQUIRED_FLOW_DENIED,
                            f"{name}: ACL {acl.get('name')} ({attachment.get('direction')} on {interface.get('name')}) explicitly denies "
                            f"required flow '{flow['purpose']}' at entry {entry.get('sequence')} before any matching permit.",
                            device=name, object_type="acl_attachment", object_id=attachment["id"],
                            field_path=f"security.attachments.{attachment['id']}",
                            related_objects=[f"{name}:{acl['id']}:{entry.get('id')}"],
                            evidence={**flow_evidence, "matched_entry": {"id": entry.get("id"), "sequence": entry.get("sequence"),
                                                                         "action": entry.get("action")}},
                            remediation="Add a matching permit ahead of the deny, or narrow the deny.")
                elif result["verdict"] in (UNKNOWN, IMPLICIT_DENY):
                    ctx.add(Code.ACL_EFFECT_UNKNOWN,
                            f"{name}: the effect of ACL {acl.get('name')} on required flow '{flow['purpose']}' cannot be proven "
                            f"({result['reason']}).",
                            severity=Severity.WARNING, device=name, object_type="acl_attachment", object_id=attachment["id"],
                            field_path=f"security.attachments.{attachment['id']}",
                            evidence={**flow_evidence, "reason": result["reason"], "verdict": result["verdict"]},
                            remediation="Add an explicit permit for the required flow, or confirm it is intentionally blocked.")
        for key, rows in sorted(seen.items(), key=lambda kv: str(kv[0])):
            if len(rows) > 1:
                first = rows[0][0]
                ctx.add(Code.ACL_DUPLICATE_ATTACHMENT,
                        f"{name}: {len(rows)} ACLs are attached to the same interface, direction and family.",
                        device=name, object_type="acl_attachment", object_id=first["id"],
                        related_objects=[f"{name}:{a['id']}" for a, _ in rows],
                        evidence={"acls": [acl.get("name") for _, acl in rows]},
                        remediation="A device accepts one ACL per interface, direction and family.")
    ctx.checked["acl_flows_evaluated"] = evaluated
