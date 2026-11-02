"""Bounded, per-feature semantic samples for exhaustive OFFLINE probes.

Raw samples also exercise unsupported/historical intent through the renderer
and validator. They are never deployable authorization. The authoring probe
separately calls the real mutation API and records its refusal when appropriate.
"""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass

from .. import interface_intent_service as interfaces
from .. import routing_intent_service as routing
from .. import service_policy_intent_service as policy

IF = "if_0000000000000001"
PARENT = "if_0000000000000002"
OBJ = "0000000000000003"


def interface_name(platform, kind):
    physical = {"arista_ceos": "Ethernet1", "ubuntu_frr": "eth1", "nokia_srlinux": "ethernet-1/1",
                "cisco_c8000v_iosxe": "GigabitEthernet2", "cisco_iosxr": "GigabitEthernet0/0/0/0", "sonic": "Ethernet0"}[platform]
    if kind == "LOOPBACK":
        return "loopback44" if platform == "ubuntu_frr" else "lo44" if platform == "nokia_srlinux" else "Loopback44"
    if kind == "SUBINTERFACE":
        return physical + (".44" if platform != "nokia_srlinux" else ".44")
    if kind == "SVI":
        return "vlan44" if platform == "ubuntu_frr" else "Vlan44"
    if kind == "MANAGEMENT":
        return {"arista_ceos": "Management1", "ubuntu_frr": "eth0", "nokia_srlinux": "mgmt0",
                "cisco_c8000v_iosxe": "GigabitEthernet1", "cisco_iosxr": "MgmtEth0/RP0/CPU0/0", "sonic": "eth0"}[platform]
    return {"LAG": "PortChannel44", "MLAG": "PortChannel44", "BOND": "bond44", "BRIDGE": "br44",
            "TUNNEL": "Tunnel44", "GRE": "gre44", "VXLAN_VTEP": "Vxlan44", "VIRTUAL": "virt44",
            "RADIO_WLAN": "wlan44"}.get(kind, physical)


def iface(platform, kind="ROUTED_PHYSICAL", iid=IF):
    row = {
        "id": iid, "sequence": 1, "name": interface_name(platform, kind), "kind": kind,
        "mode": interfaces.KIND_MODES[kind], "description": "NMAS isolated assessment",
        "admin_state": "ENABLED", "mtu": 1500, "access_vlan": 44 if kind == "ACCESS" else None,
        "trunk_allowed_vlans": [44, 45] if kind == "TRUNK" else [], "native_vlan": 44 if kind == "TRUNK" else None,
        "parent_id": PARENT if kind == "SUBINTERFACE" else "", "encapsulation_vlan": 44 if kind == "SUBINTERFACE" else None,
        "vlan_id": 44 if kind == "SVI" else None, "role": "MANAGEMENT" if kind == "MANAGEMENT" else "",
        "operational_description": "", "wan": {"state": "DISABLED"}, "addresses": {},
    }
    if kind not in {"ACCESS", "TRUNK"}:
        for n, (family, cidr) in enumerate((("IPV4", "198.18.0.1/30"), ("IPV6", "2001:db8:44::1/64")), 4):
            aid = f"addr_{n:016x}"
            row["addresses"][aid] = {"id": aid, "sequence": n, "family": family, "cidr": cidr,
                                     "source": "MANUAL", "role": "PRIMARY", "ipam_prefix": ""}
    return row


@dataclass
class ProbeCase:
    sections: dict
    baseline: dict
    field_path: str
    good_value: object
    bad_value: object
    object_type: str
    expected: dict


def sample(platform, feature) -> ProbeCase:
    code = feature.code
    sections = {
        "interfaces": {IF: iface(platform)}, "routing": {}, "fhrp": {"instances": {}},
        "nat": {"pools": {}, "rules": {}},
        "services": {"dhcp": {"mode": "INHERIT", "relays": {}, "clients": {}, "local_server_override": False},
                     "dns": {"mode": "INHERIT", "resolvers": {}, "search_domains": {}},
                     "monitoring": {"mode": "INHERIT"}},
        "security": {"acls": {}, "attachments": {}}, "policy": {"pbr": {"policies": {}, "attachments": {}}},
    }
    baseline = deepcopy(sections)
    expected = {"interface": sections["interfaces"][IF]["name"]}
    object_type = feature.object_type or ""
    path, good, bad = "", None, None
    if feature.family == "interface":
        sections["interfaces"] = {IF: iface(platform, code)}
        baseline["interfaces"] = {}
        if code == "SUBINTERFACE":
            sections["interfaces"][IF]["mtu"] = None
            sections["interfaces"][PARENT] = iface(platform, iid=PARENT)
            # The parent is a carrier for the tagged child, not another owner
            # of the child's sample addresses.
            sections["interfaces"][PARENT]["addresses"] = {}
            baseline["interfaces"][PARENT] = deepcopy(sections["interfaces"][PARENT])
        expected = {"interface": sections["interfaces"][IF]["name"]}
        path, good, bad = f"interfaces.{IF}.kind", code, "INVALID_KIND"
    elif feature.family == "routing":
        if code.startswith("STATIC_"):
            rid = f"route_{OBJ}"
            family = code.split("_", 1)[1]
            destination, hop = ("203.0.113.0/24", "198.18.0.2") if family == "IPV4" else ("2001:db8:113::/64", "2001:db8:44::2")
            sections["routing"]["static_routes"] = {rid: {
                "id": rid, "sequence": 1, "family": family, "destination": destination,
                "next_hop_type": "IP", "next_hop_address": hop, "next_hop_interface_id": "",
                "distance": 200, "metric": None, "tag": None, "description": "", "enabled": True,
            }}
            path, good, bad = f"routing.static_routes.{rid}.destination", destination, "not-a-prefix"
            expected = {"prefix": destination, "next_hop": hop}
        else:
            family = next(f for f in ("rip", "ospf", "isis", "eigrp", "bgp") if code.lower().startswith(f))
            rid = f"{family}_{OBJ}"
            v6 = code in {"RIPNG", "OSPFV3", "EIGRP_IPV6", "BGP_IPV6"}
            kwargs = {"address_family": "IPV6" if v6 else "IPV4", "version": code, "local_asn": 65044}
            instance = {"id": rid, "sequence": 1, **routing._instance_defaults(family, kwargs),
                        "description": "", "redistribute": {}, "interfaces": {}, "networks": {}, "neighbors": {}}
            if family in {"ospf", "bgp", "eigrp"}:
                instance["router_id"] = "198.18.44.1"
            if family == "ospf":
                instance["process_id"] = 44
                instance["interfaces"] = {f"bind_{OBJ}": {"id": f"bind_{OBJ}", "interface_id": IF,
                    "area": "0", "passive": False, "cost": 10, "network_type": "POINT_TO_POINT"}}
                if not v6:
                    instance["networks"] = {f"net_{OBJ}": {"id": f"net_{OBJ}", "prefix": "198.18.0.0/30", "area": "0"}}
            if family == "rip":
                instance["interfaces"] = {f"bind_{OBJ}": {"id": f"bind_{OBJ}", "interface_id": IF, "passive": False}}
            if family == "bgp":
                peer = "2001:db8:44::2" if v6 else "198.18.0.2"
                instance["neighbors"] = {f"peer_{OBJ}": {"id": f"peer_{OBJ}", "family": "IPV6" if v6 else "IPV4",
                    "peer_address": peer, "remote_asn": 65045, "description": "", "enabled": True,
                    "activate_ipv4": not v6, "activate_ipv6": v6}}
                instance["networks"] = {f"net_{OBJ}": {"id": f"net_{OBJ}", "family": "IPV6" if v6 else "IPV4",
                    "cidr": "2001:db8:113::/64" if v6 else "203.0.113.0/24"}}
                path, good, bad = f"routing.bgp.{rid}.local_asn", 65044, -1
            elif family == "rip":
                path, good, bad = f"routing.rip.{rid}.address_family", kwargs["address_family"], "INVALID"
            elif family == "isis":
                path, good, bad = f"routing.isis.{rid}.net", "49.0001.0000.0000.0044.00", "invalid"
            else:
                path, good, bad = f"routing.{family}.{rid}.router_id", "198.18.44.1", "invalid"
            sections["routing"][family] = {rid: instance}
    elif code.startswith("FHRP_"):
        protocol, af = code[len("FHRP_"):].rsplit("_", 1)
        fid = f"fhrp_{OBJ}"
        vip = "198.18.0.3" if af == "IPV4" else "2001:db8:44::3"
        sections["fhrp"]["instances"][fid] = {"id": fid, "protocol": protocol, "interface_id": IF,
            "address_family": af, "group_id": 44, "priority": 110, "preempt": True,
            "virtual_mac": "00:1c:73:00:00:44", "description": "", "virtual_ips": {
                f"vip_{OBJ}": {"id": f"vip_{OBJ}", "address": vip}}}
        path, good, bad = f"fhrp.instances.{fid}.address_family", af, "INVALID"
    elif code.startswith("NAT_POOL_"):
        pid = f"pool_{OBJ}"
        sections["nat"]["pools"][pid] = {"id": pid, "name": "CAP_POOL", "family": "NAT44",
            "start_address": "203.0.113.44", "end_address": "203.0.113.45", "prefix_length": 24, "description": ""}
        path, good, bad = f"nat.pools.{pid}.start_address", "203.0.113.44", "invalid"
    elif code.startswith("NAT_"):
        payload = code[len("NAT_"):]
        family = next(f for f in policy.NAT_FAMILIES if payload.startswith(f + "_"))
        mode = payload[len(family) + 1:]
        nid = f"nat_{OBJ}"
        sections["nat"]["rules"][nid] = {"id": nid, "sequence": 1, "family": family, "mode": mode,
            "original_source": "198.18.0.0/30" if mode != "STATIC" else "198.18.0.2",
            "translated_source": "203.0.113.44", "pool_id": "", "protocol": "IP", "original_port": "",
            "translated_port": "", "inside_interface_id": IF, "outside_interface_id": PARENT, "enabled": True,
            "description": ""}
        sections["interfaces"][PARENT] = iface(platform, iid=PARENT)
        sections["interfaces"][PARENT]["name"] = interface_name(platform, "ROUTED_PHYSICAL").replace("1", "2")
        sections["interfaces"][PARENT]["addresses"] = {}
        baseline["interfaces"] = deepcopy(sections["interfaces"])
        path, good, bad = f"nat.rules.{nid}.mode", mode, "INVALID"
    elif code.startswith(("DHCP_RELAY_", "DHCP_CLIENT_")):
        client = code.startswith("DHCP_CLIENT_")
        af = code.rsplit("_", 1)[1]
        did = f"dhcp_{OBJ}"
        obj = {"id": did, "family": af, "interface_id": IF, "description": ""}
        if not client:
            obj["destination"] = "192.0.2.44" if af == "IPV4" else "2001:db8::44"
        sections["services"]["dhcp"].update(mode="OVERRIDE")
        sections["services"]["dhcp"]["clients" if client else "relays"][did] = obj
        path, good, bad = f"services.dhcp.{'clients' if client else 'relays'}.{did}.family", af, "INVALID"
    elif code in {"DHCP_OVERRIDE", "DHCP_LOCAL_SERVER", "DNS_OVERRIDE", "MONITORING_OVERRIDE"}:
        service = code.split("_", 1)[0].lower()
        sections["services"][service]["mode"] = "OVERRIDE"
        if code == "DHCP_LOCAL_SERVER":
            sections["services"][service]["local_server_override"] = True
        if service == "dns":
            sections["services"][service]["resolvers"] = {f"dns_{OBJ}": {"id": f"dns_{OBJ}", "address": "192.0.2.53"}}
        path, good, bad = f"services.{service}.mode", "OVERRIDE", "INVALID"
    elif code.startswith("ACL_"):
        parts = code.split("_")
        attach = parts[1] == "ATTACH"
        af, acl_type = (parts[2], "EXTENDED") if attach else (parts[1], parts[2])
        aid = f"acl_{OBJ}"
        sections["security"]["acls"][aid] = {"id": aid, "name": "CAP_ACL", "family": af, "acl_type": acl_type,
            "description": "", "entries": {f"ace_{OBJ}": {"id": f"ace_{OBJ}", "sequence": 10,
                "action": "PERMIT", "protocol": "IP", "source_type": "ANY", "source_value": "",
                "destination_type": "ANY", "destination_value": "", "source_port": "", "destination_port": "",
                "logging": False, "description": ""}}}
        if attach:
            tid = f"attach_{OBJ}"
            baseline["security"]["acls"] = deepcopy(sections["security"]["acls"])
            sections["security"]["attachments"][tid] = {"id": tid, "acl_id": aid, "interface_id": IF, "direction": "IN"}
            path, good, bad = f"security.attachments.{tid}.direction", "IN", "INVALID"
        else:
            path, good, bad = f"security.acls.{aid}.family", af, "INVALID"
    elif code.startswith("PBR_"):
        af = code.rsplit("_", 1)[1]
        pid = f"pbr_{OBJ}"
        sections["policy"]["pbr"]["policies"][pid] = {"id": pid, "name": "CAP_PBR", "family": af,
            "description": "", "sequences": {f"pbrseq_{OBJ}": {"id": f"pbrseq_{OBJ}", "sequence": 10,
                "source_prefix": "198.18.0.0/30" if af == "IPV4" else "2001:db8:44::/64",
                "destination_prefix": "", "protocol": "IP", "next_hop": "198.18.0.2" if af == "IPV4" else "2001:db8:44::2",
                "output_interface_id": "", "description": ""}}}
        if code.startswith("PBR_ATTACH_"):
            tid = f"attach_{OBJ}"
            baseline["policy"]["pbr"]["policies"] = deepcopy(sections["policy"]["pbr"]["policies"])
            sections["policy"]["pbr"]["attachments"][tid] = {"id": tid, "policy_id": pid, "interface_id": IF, "direction": "IN"}
            path, good, bad = f"policy.pbr.attachments.{tid}.direction", "IN", "INVALID"
        else:
            path, good, bad = f"policy.pbr.policies.{pid}.family", af, "INVALID"
    else:
        raise ValueError(f"No deliberate probe case for {feature.key}")
    return ProbeCase(sections, baseline, path, good, bad, object_type, expected)


def author(revision, platform, feature):
    """Invoke the real operator mutation API (dependencies are seeded offline)."""
    code = feature.code
    if feature.family == "interface":
        return interfaces.add_interface(revision=revision, kind=code, name=interface_name(platform, code))
    if feature.family == "routing":
        if code.startswith("STATIC_"):
            return routing.add_static_route(revision=revision, family=code.split("_", 1)[1])
        family = next(f for f in ("rip", "ospf", "isis", "eigrp", "bgp") if code.lower().startswith(f))
        return routing.add_protocol_instance(revision=revision, family=family, version=code, local_asn=65044,
                                             address_family="IPV6" if code in {"RIPNG", "OSPFV3", "BGP_IPV6", "EIGRP_IPV6"} else "IPV4")
    if code.startswith("FHRP_"):
        protocol, af = code[len("FHRP_"):].rsplit("_", 1)
        return policy.add_fhrp_instance(revision=revision, protocol=protocol, interface_id=IF, address_family=af)
    if code.startswith("NAT_POOL_"):
        return policy.add_nat_pool(revision=revision, family=code[len("NAT_POOL_"):], name="CAP_POOL")
    if code.startswith("NAT_"):
        payload = code[len("NAT_"):]
        family = next(f for f in policy.NAT_FAMILIES if payload.startswith(f + "_"))
        mode = payload[len(family) + 1:]
        return policy.add_nat_rule(revision=revision, family=family, mode=mode)
    if code.startswith("DHCP_RELAY_"):
        af = code.rsplit("_", 1)[1]
        return policy.add_dhcp_relay(revision=revision, family=af, interface_id=IF,
                                     destination="192.0.2.44" if af == "IPV4" else "2001:db8::44")
    if code.startswith("DHCP_CLIENT_"):
        return policy.add_dhcp_client(revision=revision, family=code.rsplit("_", 1)[1], interface_id=IF)
    if code in {"DHCP_OVERRIDE", "DNS_OVERRIDE", "MONITORING_OVERRIDE"}:
        return policy.set_service_mode(revision=revision, service=code.split("_", 1)[0].lower(), mode="OVERRIDE")
    if code == "DHCP_LOCAL_SERVER":
        # There is no public server collection mutation; explicitly test its field boundary.
        return None
    if code.startswith("ACL_ATTACH_"):
        return policy.add_acl_attachment(revision=revision, acl_id=f"acl_{OBJ}", interface_id=IF, direction="IN")
    if code.startswith("ACL_"):
        _, af, acl_type = code.split("_")
        return policy.add_acl(revision=revision, name="CAP_ACL", family=af, acl_type=acl_type)
    if code.startswith("PBR_ATTACH_"):
        return policy.add_pbr_attachment(revision=revision, policy_id=f"pbr_{OBJ}", interface_id=IF, direction="IN")
    if code.startswith("PBR_"):
        return policy.add_pbr_policy(revision=revision, name="CAP_PBR", family=code.rsplit("_", 1)[1])
    raise ValueError(f"No authoring probe for {feature.key}")
