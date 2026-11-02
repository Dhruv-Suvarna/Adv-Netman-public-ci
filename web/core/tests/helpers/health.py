"""Fixtures for the health / precheck / postcheck tests.  Application state and fakes only: no network, no device.

* ``topology_summary`` / ``snapshot``   a ``topology_service.get_topology_summary()``-shaped document with per-device age,
                                        CPU, memory, events, and links.
* ``FakeSession`` / ``session_factory``  a fake read-only device session returning canned command output (EOS-JSON or FRR-JSON shaped).
* ``device_evidence`` / ``evidence_set`` synthetic normalized evidence, for the evaluator engine.
* ``satisfied_evidence``                a world in which every evaluable requirement of a plan holds.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

from core.services.health import evidence as ev, inventory, live, telemetry
from core.services.health.thresholds import load_thresholds

NOW = datetime(2026, 9, 21, 12, 0, 0, tzinfo=timezone.utc)
MANAGED = tuple(inventory.inventory_devices())  # the real, tracked inventory: R1-R5, S1-S4, mgmt_swt


def _iso(moment):
    return moment.isoformat().replace("+00:00", "Z")


def topology_summary(*, now=NOW, ages=None, cpu=None, memory=None, backend="OK", events=None, links=None, default_age=5.0, unmonitored=()):
    """A topology-service summary.  ``ages``/``cpu``/``memory``/``events`` are {device: value}; ``links`` a list of edge dicts."""
    ages, cpu, memory, events = ages or {}, cpu or {}, memory or {}, events or {}
    nodes = []
    for name in MANAGED:
        age = ages.get(name, default_age)
        nodes.append({
            "id": name, "monitored": name not in unmonitored, "health": "HEALTHY",
            "last_telemetry_timestamp": None if age is None else _iso(now - timedelta(seconds=age)),
            "cpu_percent": cpu.get(name, 20), "memory_percent": memory.get(name, 30),
            "recent_critical_syslog_count": events.get(name, 0), "recent_snmp_trap_count": 0,
        })
    payload = {"generated_at": _iso(now), "health_thresholds_seconds": {"healthy_max": 60, "stale_max": 120},
               "backend": {"status": backend, "error": None}, "graph": {"nodes": nodes, "edges": list(links or [])}}
    return {"status": "available", "data": payload}


def unavailable_topology():
    return {"status": "unavailable", "message": "Topology service temporarily unavailable.", "data": None}


def snapshot(*, now=NOW, summary=None, **kwargs):
    return telemetry.collect(summary if summary is not None else topology_summary(now=now, **kwargs), now=now)


def edge(a, b, status="UP", plane="data"):
    return {"id": f"{a}--{b}", "source": a, "target": b, "plane": plane, "status": status, "health_reason": f"synthetic {status}", "endpoint_state": []}


# --- fake device sessions -----------------------------------------------------------------------------------------
class FakeSession:
    def __init__(self, outputs, ping_outputs=None):
        self.outputs, self.ran, self.closed = outputs, [], False
        self.ping_outputs, self.pinged = ping_outputs or {}, []

    def run(self, key):
        self.ran.append(key)
        value = self.outputs[key]
        if isinstance(value, Exception):
            raise value
        return value

    def ping(self, dest, count=3):
        self.pinged.append((dest, count))
        value = self.ping_outputs[dest]
        if isinstance(value, Exception):
            raise value
        return value

    def close(self):
        self.closed = True


def session_factory(by_device=None, *, default=None, fail=None, ping_by_device=None, ping_default=None):
    """factory(device) -> FakeSession.  ``fail`` maps device -> an exception raised when the session opens.
    ``ping_by_device``/``ping_default`` seed ``FakeSession.ping_outputs`` (a dict keyed by destination address)."""
    created = []

    def factory(device):
        if device["name"] in (fail or {}):
            raise fail[device["name"]]
        session = FakeSession((by_device or {}).get(device["name"], default), (ping_by_device or {}).get(device["name"], ping_default))
        created.append((device["name"], session))
        return session

    factory.created = created
    return factory


def ping_output(*, transmitted=3, received=3, rtt=(0.037, 0.041, 0.045)):
    """Standard iputils-style ping statistics text (shared by cEOS and Ubuntu/FRR, both Linux-based)."""
    loss = round((transmitted - received) / transmitted * 100) if transmitted else 100
    lines = [f"{transmitted} packets transmitted, {received} received, {loss}% packet loss, time 2000ms"]
    if received:
        lines.append(f"rtt min/avg/max/mdev = {rtt[0]}/{rtt[1]}/{rtt[2]}/0.003 ms")
    return "PING synthetic\n" + "\n".join(lines)


def _eos_ifaces(interfaces):
    return json.dumps({"interfaces": {n: {"interfaceStatus": s, "lineProtocolStatus": p} for n, (s, p) in interfaces.items()}})


def eos_outputs(*, interfaces=None, ipv4=None, ipv6=None, virtual=None, routes=(), ospf=(), bgp=None, config=""):
    """EOS ``| json`` shaped output.  routes: (prefix, next_hop|None, interface); ospf: (iface, router_id, state); bgp: (peer, asn, state)."""
    interfaces = interfaces if interfaces is not None else {"Ethernet1": ("connected", "up")}
    ip_blocks = {}
    for name, cidrs in (ipv4 or {}).items():
        first, rest = cidrs[0], cidrs[1:]
        address, _, length = first.partition("/")
        ip_blocks[name] = {"interfaceAddress": {"primaryIp": {"address": address, "maskLen": int(length)},
                                                 "secondaryIpsOrderedList": [{"address": c.split("/")[0], "maskLen": int(c.split("/")[1])} for c in rest],
                                                 "virtualIp": {"address": "0.0.0.0", "maskLen": 0}, "virtualSecondaryIpsOrderedList": []}}
    for name, vips in (virtual or {}).items():
        block = ip_blocks.setdefault(name, {"interfaceAddress": {"primaryIp": {"address": "0.0.0.0", "maskLen": 0}, "secondaryIpsOrderedList": [],
                                                                 "virtualSecondaryIpsOrderedList": []}})["interfaceAddress"]
        block["virtualIp"] = {"address": vips[0], "maskLen": 24}
        block["virtualSecondaryIpsOrderedList"] = [{"address": v, "maskLen": 24} for v in vips[1:]]
    v6 = {n: {"addresses": [{"address": c.split("/")[0], "subnet": f"x/{c.split('/')[1]}"} for c in cidrs]} for n, cidrs in (ipv6 or {}).items()}
    rib = {}
    for prefix, hop, interface in routes:
        rib[prefix] = {"routeType": "static", "vias": [{k: v for k, v in (("nexthopAddr", hop), ("interface", interface)) if v}]}
    v4rib, v6rib = ({p: r for p, r in rib.items() if (":" in p) == is6} for is6 in (False, True))
    neighbors = [{"routerId": rid, "interfaceName": iface, "adjacencyState": state} for iface, rid, state in ospf]
    peers = {p: {"asn": str(asn), "peerState": state} for p, asn, state in (bgp or ())}
    return {
        "interfaces": _eos_ifaces(interfaces), "ip_interfaces": json.dumps({"interfaces": ip_blocks}), "ipv6_interfaces": json.dumps({"interfaces": v6}),
        "ip_routes": json.dumps({"vrfs": {"default": {"routes": v4rib}}}), "ipv6_routes": json.dumps({"vrfs": {"default": {"routes": v6rib}}}),
        "ospf": json.dumps({"vrfs": {"default": {"instList": {"10": {"ospfNeighborEntries": neighbors}}}}}), "ospf3": json.dumps({"vrfs": {}}), "isis": json.dumps({"vrfs": {}}), "rip_neighbors": "",
        "bgp": json.dumps({"vrfs": {"default": {"peers": peers}}} if peers else {"errors": ["BGP inactive"]}), "bgp6": json.dumps({"errors": ["BGP inactive"]}),
        "running_config": config,
    }


def linux_outputs(*, interfaces=None, routes=(), nft="", frr_config="hostname R3\nend\n"):
    interfaces = interfaces if interfaces is not None else {"eth1": ["10.0.0.1/24"]}
    addr = [{"ifname": n, "flags": ["UP", "LOWER_UP"], "operstate": "UP",
             "addr_info": [{"local": c.split("/")[0], "prefixlen": int(c.split("/")[1]), "scope": "global"} for c in cidrs]} for n, cidrs in interfaces.items()]
    r4 = [{"dst": p, "gateway": h, "dev": d} for p, h, d in routes if ":" not in p]
    return {"addr": json.dumps(addr), "route4": json.dumps(r4), "route6": "[]", "ospf": "{}", "ospf6": "{}", "bgp": "{}",
            "frr_config": frr_config, "nft": nft}


# --- synthetic normalized evidence --------------------------------------------------------------------------------
def device_evidence(name, *, now=NOW, source="LIVE", age=0.0, complete=True, platform="ceos", live_ok=True, **groups):
    """Evidence for one device.  groups: interfaces/addresses/virtual_addresses/routes/ospf/bgp/config/nat (None => unavailable)."""
    evidence = ev.DeviceEvidence(device=name, platform=platform, live_attempted=live_ok, live_error="" if live_ok else "TIMEOUT")
    observed = now - timedelta(seconds=age)
    for group, data in groups.items():
        evidence.groups[group] = ev.FactGroup(data, source, observed, complete=complete) if data is not None else ev.unavailable(source, "GROUP_UNAVAILABLE")
    return evidence


def evidence_set(*devices, now=NOW, pipeline_ok=True, services=None):
    return ev.EvidenceSet(devices={d.device: d for d in devices}, now=now, thresholds=load_thresholds(),
                          pipeline={"available": pipeline_ok, "topology_available": pipeline_ok, "backend_status": "OK" if pipeline_ok else "ERROR"},
                          services=services or {})


def satisfied_evidence(requirements, *, now=NOW, extra_devices=()):
    """A world in which every EVALUABLE requirement holds (built only from the descriptors' own expected facts)."""
    live_norm = live
    world = {}

    def dev(name):
        return world.setdefault(name, {"interfaces": {}, "addresses": {}, "virtual_addresses": {}, "routes": [], "ospf": [], "bgp": [],
                                       "config": {"acl_definitions": [], "acl_attachments": [], "dhcp_relays": []}, "nat": {"tables": [], "rules": []}})

    for req in requirements:
        x, d = req.expected or {}, dev(req.device)
        if req.kind == "INTERFACE_PRESENT":
            d["interfaces"][x["interface"]] = {"admin": "UP" if x.get("admin_enabled", True) else "DOWN", "oper": "UP"}
        elif req.kind == "ADDRESS_PRESENT":
            d["addresses"].setdefault(x["interface"], []).append(live_norm.norm_cidr(x["address"]))
        elif req.kind == "ROUTE_INTENDED":
            d["routes"].append({"prefix": live_norm.norm_prefix(x["prefix"]), "type": "static", "next_hops": [x["next_hop"]] if x.get("next_hop") else [],
                                "interfaces": [x["exit_interface"]] if x.get("exit_interface") else []})
        elif req.kind == "ROUTING_INTERFACE_ENABLED" and x.get("protocol") == "ospf":
            d["ospf"].append({"family": x.get("version") or "OSPFV2", "neighbor_id": "10.255.0.1", "interface": x["interface"], "state": "FULL"})
        elif req.kind in ("BGP_PEER_INTENDED", "BGP_AF_ACTIVATION_INTENDED"):
            d["bgp"].append({"peer": live_norm.norm_ip(x["peer"]), "remote_as": str(x["remote_asn"]), "state": "ESTABLISHED", "family": x.get("family", 4)})
        elif req.kind == "FHRP_GROUP_INTENDED":
            d["virtual_addresses"].setdefault(x["interface"], []).extend(x["virtual_addresses"])
        elif req.kind == "DHCP_RELAY_INTENDED":
            d["config"]["dhcp_relays"].append({"interface": x["interface"], "destination": live_norm.norm_ip(x["destination"])})
        elif req.kind == "ACL_DEFINED":
            d["config"]["acl_definitions"].append(x["name"])
        elif req.kind == "ACL_ATTACHMENT_INTENDED":
            d["config"]["acl_attachments"].append({"interface": x["interface"], "acl": x["acl_name"], "direction": x["direction"].upper()})
        elif req.kind == "NAT_RULE_INTENDED":
            d["nat"]["rules"].append({"table": "T", "oif": x["outside_interface"], "action": "masquerade"})
    return evidence_set(*[device_evidence(name, now=now, **groups) for name, groups in world.items()],
                        *[device_evidence(name, now=now) for name in extra_devices], now=now)
