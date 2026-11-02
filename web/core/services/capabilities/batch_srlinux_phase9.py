"""Reversible SR Linux routing, ACL and DHCP-relay probes (V2 Phase 9) on the isolated ``srl`` node.

The DUT is the disposable ``srl`` node of the validation lab (ethernet-1/1 <-> FRR peer eth2).  Configlets are the
planner's own: the harness builds a planning context from the cell's sample intent and calls the registered
``planning.configlet_factory.HANDLERS`` (routing process, interface binding, BGP neighbor + address-family activation,
BGP network, ACL definition, ACL attachment, DHCP relay), so every line NMAS writes is exactly what a real plan carries.
The postcheck requirements are the engine's own descriptors of those Configlets (``verification_requirements``).

Lab prerequisites -- the ethernet-1/1 addressing, static anchors (the route a BGP network advertises, the route back to
the denied ACL source, the route to the DHCP server), the peer's addresses / originating dummy interface / FRR daemons
-- are written natively and are never part of the claim.  Everything NMAS claims goes through the registered
``SrLinuxExecutor`` in engine order: preflight all, apply, verify, compensate in reverse.

Verification of one scenario:

* operator postcheck -- the Phase-15 evaluators over a fresh gNMI read (configuration read back from the running tree,
  OSPF FULL / BGP ESTABLISHED from protocol state);
* live import -- ``parser_srlinux`` recovers the rendered intent from the live running configuration;
* behaviour -- OSPF / BGP: the DUT installs the peer's prefix from the protocol and the PEER sees the DUT (adjacency FULL,
  the DUT's network in its BGP table); ACL: traffic from the denied source is dropped while the permitted source is
  answered; DHCP relay: a client broadcast on the link reaches the server as a relayed message (and, for IPv4, the
  server's offer returns to the client through the relay);
* compensation -- the running configuration equals the capture taken before NMAS wrote anything and the behaviour is
  gone (no adjacency / session / learned route, both sources answered, no relayed message).

Each cell runs on a pristine node and on one that already holds related configuration NMAS must preserve.
"""

from __future__ import annotations

import json
import subprocess
import time
from copy import deepcopy
from types import SimpleNamespace

from django.utils import timezone

from .. import platform_drivers
from .. import srlinux_model as model
from ..config_import import parser_srlinux
from ..execution.executors.base import ConfigletSpec
from ..health import live
from ..health.requirements import from_descriptor
from ..health.routing_config import normalized_area
from ..planning import configlet_factory
from . import assessment
from .batch_frr_routing import FrrPair, _call, _postcheck, _transaction
from .batch_srlinux import LAB, PEER_DEV, PLATFORM, PORT, RUNTIME, SrlLab, _added
from .features import by_key
from .isolated_live import _run
from .probe_cases import sample

ROUTING_CELLS = ("routing.OSPFV2", "routing.OSPFV3", "routing.BGP_IPV4", "routing.BGP_IPV6")
ACL_CELLS = tuple(f"service_policy.{code}" for code in (
    "ACL_IPV4_STANDARD", "ACL_IPV4_EXTENDED", "ACL_IPV6_STANDARD", "ACL_IPV6_EXTENDED", "ACL_ATTACH_IPV4", "ACL_ATTACH_IPV6"))
DHCP_CELLS = ("service_policy.DHCP_RELAY_IPV4", "service_policy.DHCP_RELAY_IPV6")
CELLS = (*ROUTING_CELLS, *ACL_CELLS, *DHCP_CELLS)

PEER_DUMMY = "nmascap3"
PEER_LINK = {"IPV4": "198.18.0.2/30", "IPV6": "2001:db8:44::2/64"}
PEER_HOP = {"IPV4": "198.18.0.2", "IPV6": "2001:db8:44::2"}
DUT_LINK = {"IPV4": "198.18.0.1", "IPV6": "2001:db8:44::1"}
DUT_ROUTER_ID, PEER_ROUTER_ID = "198.18.44.1", "198.18.44.2"
# the prefix the peer originates (OSPF / BGP) and, for DHCP, the subnet of the server behind it
PEER_ORIGIN = {"IPV4": ("192.0.2.1/24", "192.0.2.0/24"), "IPV6": ("2001:db8:99::1/64", "2001:db8:99::/64")}
DHCP_SERVER = {"IPV4": "192.0.2.1", "IPV6": "2001:db8:99::1"}
# the ACL's denied source: a second peer address (IPv4 outside the /30, so the DUT needs a route back to it)
DENIED = {"IPV4": ("198.18.0.66", "198.18.0.66/32"), "IPV6": ("2001:db8:44::66", "2001:db8:44::66/64")}
DENIED_ROUTE = "198.18.0.64/30"
ANCHOR_GROUP = "nhg-nmas-cap"


def family(key: str) -> str:
    code = key.split(".", 1)[1]
    return "IPV6" if "IPV6" in code or code == "OSPFV3" else "IPV4"


def _static(prefix: str, hop: str, group: str = ANCHOR_GROUP) -> tuple[str, ...]:
    """A lab static route through the peer (prerequisite statements, never an NMAS claim)."""
    return (f"set / network-instance default static-routes route {prefix} next-hop-group {group}",
            f"set / network-instance default next-hop-groups group {group} nexthop 1 ip-address {hop}")


def _seed_loopback(fam: str) -> tuple[str, ...]:
    address = ("ipv6", "2001:db8:7::1/128") if fam == "IPV6" else ("ipv4", "198.18.7.1/32")
    return ("set / interface lo44 admin-state enable", "set / interface lo44 subinterface 0 admin-state enable",
            f"set / interface lo44 subinterface 0 {address[0]} admin-state enable",
            f"set / interface lo44 subinterface 0 {address[0]} address {address[1]}",
            "set / network-instance default interface lo44.0")


def _seed_ospf(fam: str) -> tuple[str, ...]:
    base = "set / network-instance default protocols ospf instance 44"
    return (*_seed_loopback(fam), f"{base} version {'ospf-v3' if fam == 'IPV6' else 'ospf-v2'}", f"{base} admin-state enable",
            *((f"{base} address-family ipv6-unicast",) if fam == "IPV6" else ()), f"{base} router-id {DUT_ROUTER_ID}",
            f"{base} area 0.0.0.0 interface lo44.0 passive true")


def _seed_bgp(fam: str) -> tuple[str, ...]:
    base, afi = "set / network-instance default protocols bgp", "ipv6-unicast" if fam == "IPV6" else "ipv4-unicast"
    peer = "2001:db8:9::9" if fam == "IPV6" else "198.18.9.9"
    return (f"{base} autonomous-system 65044", f"{base} router-id {DUT_ROUTER_ID}", f"{base} afi-safi {afi} admin-state enable",
            f"{base} group legacy admin-state enable", f"{base} neighbor {peer} peer-group legacy",
            f"{base} neighbor {peer} peer-as 65099")


def _seed_acl(fam: str) -> tuple[str, ...]:
    afi, prefix = ("ipv6", "2001:db8:51::/64") if fam == "IPV6" else ("ipv4", "198.51.100.0/24")
    return (f"set / acl acl-filter LEGACY type {afi} entry 10 match {afi} source-ip prefix {prefix}",
            f"set / acl acl-filter LEGACY type {afi} entry 10 action drop")


def _seed_dhcp(fam: str) -> tuple[str, ...]:
    afi, server = ("ipv6", "2001:db8:99::99") if fam == "IPV6" else ("ipv4", "192.0.2.99")
    return (f"set / interface {PORT} subinterface 0 {afi} dhcp-relay admin-state enable",
            f"set / interface {PORT} subinterface 0 {afi} dhcp-relay server [ {server} ]")


def seeds(key: str) -> tuple[str, ...]:
    """The "configured node" scenario: related configuration that exists BEFORE NMAS writes and must survive it -- an
    OSPF instance already running a passive loopback, a BGP process with an unrelated peer, an unrelated ACL, and a DHCP
    relay that already forwards to another server (the leaf-list NMAS must extend, never replace)."""
    fam = family(key)
    if key.startswith("routing.OSPF"):
        return _seed_ospf(fam)
    if key.startswith("routing.BGP"):
        return _seed_bgp(fam)
    if key in ACL_CELLS:
        return _seed_acl(fam)
    return _seed_dhcp(fam)


# Seed facts whose presence after compensation proves NMAS left the pre-existing objects alone.
def preserved(key: str, tree: dict) -> bool:
    parsed = parser_srlinux.parse(tree)
    fam = family(key)
    if key.startswith("routing.OSPF"):
        return any(r.family == "ospf" and r.fields.get("process_id") == 44 and any(b["interface_name"] == "lo44" and b["passive"]
                                                                                  for b in r.bindings) for r in parsed.routing_instances)
    if key.startswith("routing.BGP"):
        peer = "2001:db8:9::9" if fam == "IPV6" else "198.18.9.9"
        return any(r.family == "bgp" and any(live.norm_ip(n["peer_address"]) == peer and str(n["remote_asn"]) == "65099"
                                             for n in r.neighbors) for r in parsed.routing_instances)
    if key in ACL_CELLS:
        return any(acl.name == "LEGACY" and acl.family == fam for acl in parsed.acls)
    server = "2001:db8:99::99" if fam == "IPV6" else "192.0.2.99"
    row = next((i for i in parsed.interfaces if i.name == PORT), None)
    return bool(row) and any(live.norm_ip(r["destination"]) == server for r in row.dhcp_relays)


# --- intent ------------------------------------------------------------------------------------------------------
def _ace(first: dict, sequence: int, **fields) -> dict:
    ace_id = f"ace_00000000000000{sequence:02d}"
    return {**first, "id": ace_id, "sequence": sequence, "source_port": "", "destination_port": "", "logging": False,
            "destination_type": "ANY", "destination_value": "", "protocol": "IP", **fields}


def intent(key: str) -> dict:
    """The cell's sample intent, adjusted only where the behaviour test needs specific values: an ACL that drops the
    denied source and permits everything else (extended cells add protocol / port / logging entries) and is attached
    inbound on ethernet-1/1, and a DHCP relay pointing at the lab's server."""
    sections = deepcopy(sample(PLATFORM, by_key()[key]).sections)
    fam = family(key)
    iface_id = next(iter(sections["interfaces"]))
    if key in ACL_CELLS:
        acl = next(iter(sections["security"]["acls"].values()))
        first = next(iter(acl["entries"].values()))
        host = DENIED[fam][0]
        if acl.get("acl_type") == "EXTENDED":
            icmp = "ICMPV6" if fam == "IPV6" else "ICMP"
            entries = [_ace(first, 10, action="DENY", protocol=icmp, source_type="HOST", source_value=host),
                       _ace(first, 15, action="DENY", protocol="TCP", source_type="ANY", source_value="",
                            destination_type="HOST", destination_value=DUT_LINK[fam], source_port="1024-2048",
                            destination_port="80", logging=True),
                       _ace(first, 20, action="PERMIT", source_type="ANY", source_value="")]
        else:
            entries = [_ace(first, 10, action="DENY", source_type="HOST", source_value=host),
                       _ace(first, 20, action="PERMIT", source_type="ANY", source_value="")]
        acl["entries"] = {row["id"]: row for row in entries}
        sections["security"]["attachments"] = {"attach_0000000000000003": {
            "id": "attach_0000000000000003", "acl_id": acl["id"], "interface_id": iface_id, "direction": "IN"}}
    elif key in DHCP_CELLS:
        relay = next(iter(sections["services"]["dhcp"]["relays"].values()))
        relay["destination"] = DHCP_SERVER[fam]
    return sections


def planner_context(sections: dict):
    """A ``configlet_factory.DeviceContext`` over sample intent (the hydrated shape the planner itself uses)."""
    ctx = object.__new__(configlet_factory.DeviceContext)
    ctx.intent = SimpleNamespace(target_type="", device_name="srl", platform=PLATFORM)
    ctx.name, ctx.platform = "srl", PLATFORM
    ctx.driver = platform_drivers.get_driver(PLATFORM)
    ctx.hostname = "srl"
    ctx.field_values = {"device.hostname": "srl", "device.description": ""}
    ctx.interfaces = deepcopy(list(sections["interfaces"].values()))
    ctx.routing = deepcopy(sections.get("routing") or {})
    ctx.phase12 = {name: deepcopy(sections.get(name) or {}) for name in ("fhrp", "nat", "services", "security", "policy")}
    ctx.auto = {}
    return ctx


def _nodes(key: str, sections: dict) -> list[dict]:
    """The plan graph nodes of the cell's objects, in engine (priority) order."""
    nodes = []
    if key.startswith("routing.OSPF"):
        instance = next(iter(sections["routing"]["ospf"].values()))
        nodes.append(("routing_ospf", instance["id"]))
        nodes.extend(("routing_binding", binding_id) for binding_id in instance["interfaces"])
    elif key.startswith("routing.BGP"):
        instance = next(iter(sections["routing"]["bgp"].values()))
        nodes.append(("routing_bgp", instance["id"]))
        nodes.extend(("bgp_neighbor", peer_id) for peer_id in instance["neighbors"])
        nodes.extend(("bgp_network", network_id) for network_id in instance["networks"])
    elif key in ACL_CELLS:
        nodes.extend(("acl", acl_id) for acl_id in sections["security"]["acls"])
        nodes.extend(("acl_attachment", attach_id) for attach_id in sections["security"]["attachments"])
    else:
        nodes.extend(("dhcp_relay", relay_id) for relay_id in sections["services"]["dhcp"]["relays"])
    return [{"id": f"srl/{kind}/{object_id}", "type": kind, "object_id": object_id, "label": f"srl {kind} {object_id}"}
            for kind, object_id in nodes]


def _executor_spec(n: int, spec) -> ConfigletSpec:
    lines = tuple(line for line in spec.lines if line.strip() and not line.strip().startswith(("!", "#")))
    return ConfigletSpec(f"P9-SRL-{spec.object_type}-{n}", n, "srl", PLATFORM, spec.object_type, str(getattr(spec.object_class.operation, "value", spec.object_class.operation)),
                         lines, dict(spec.facts))


def plan(key: str):
    """-> (prerequisite statements, executor Configlet specs, postcheck requirements, intent sections)."""
    sections = intent(key)
    case = sample(PLATFORM, by_key()[key])
    baseline = deepcopy(case.baseline)
    prerequisites = _added(baseline, {**baseline, "interfaces": {}})
    fam = family(key)
    if key.startswith("routing.BGP"):
        network = next(iter(next(iter(sections["routing"]["bgp"].values()))["networks"].values()))["cidr"]
        prerequisites += list(_static(network, PEER_HOP[fam]))
    elif key in ACL_CELLS and fam == "IPV4":
        prerequisites += list(_static(DENIED_ROUTE, PEER_HOP[fam]))
    elif key in DHCP_CELLS:
        prerequisites += list(_static(PEER_ORIGIN[fam][1], PEER_HOP[fam]))
    ctx = planner_context(sections)
    planned = [spec for node in _nodes(key, sections) for spec in configlet_factory.HANDLERS[node["type"]](ctx, node)]
    specs = [_executor_spec(n, spec) for n, spec in enumerate(planned, 1)]
    requirements = [from_descriptor(spec.cfg_id, descriptor) for spec, plan_spec in zip(specs, planned)
                    for descriptor in configlet_factory.verification_requirements(plan_spec)]
    return prerequisites, specs, requirements, sections


# --- import --------------------------------------------------------------------------------------------------------
def _ace_view(row: dict, family_: str, extended: bool) -> tuple:
    """The comparable facts of one ACL entry (protocol "IP" and the v6 "IPV6" both mean any protocol)."""
    protocol = str(row.get("protocol") or "IP").upper()
    protocol = "IP" if protocol in ("IP", "IPV6") else ("ICMPV6" if family_ == "IPV6" and protocol == "ICMP" else protocol)
    view = (int(row.get("sequence") or 0), row.get("action"), row.get("source_type"), str(row.get("source_value") or ""))
    if not extended:
        return view
    return (*view, protocol, row.get("destination_type"), str(row.get("destination_value") or ""),
            str(row.get("source_port") or ""), str(row.get("destination_port") or ""), bool(row.get("logging")))


def imported(key: str, sections: dict, tree: dict) -> bool:
    """The live running configuration, imported by the operator parser, carries the intent NMAS rendered."""
    parsed = parser_srlinux.parse(tree)
    fam = family(key)
    if key.startswith("routing.OSPF"):
        instance = next(iter(sections["routing"]["ospf"].values()))
        binding = next(iter(instance["interfaces"].values()))
        row = next((r for r in parsed.routing_instances if r.family == "ospf" and r.fields["version"] == instance["version"]
                    and r.fields["process_id"] == instance["process_id"]), None)
        return bool(row) and row.fields["enabled"] and row.fields["router_id"] == instance["router_id"] and any(
            b["interface_name"] == PORT and normalized_area(b["area"]) == normalized_area(binding["area"])
            and b.get("cost") == binding.get("cost") and b.get("network_type") == binding.get("network_type")
            and b["passive"] == bool(binding.get("passive")) for b in row.bindings)
    if key.startswith("routing.BGP"):
        instance = next(iter(sections["routing"]["bgp"].values()))
        neighbor = next(iter(instance["neighbors"].values()))
        network = next(iter(instance["networks"].values()))["cidr"]
        row = next((r for r in parsed.routing_instances if r.family == "bgp" and r.fields["local_asn"] == instance["local_asn"]), None)
        return bool(row) and row.fields["router_id"] == instance["router_id"] and any(
            live.norm_ip(n["peer_address"]) == live.norm_ip(neighbor["peer_address"]) and n["remote_asn"] == neighbor["remote_asn"]
            and n[f"activate_{fam.lower()}"] for n in row.neighbors) and any(
            n["family"] == fam and live.norm_prefix(n["cidr"]) == live.norm_prefix(network) for n in row.networks)
    port = next((i for i in parsed.interfaces if i.name == PORT), None)
    if key in DHCP_CELLS:
        relay = next(iter(sections["services"]["dhcp"]["relays"].values()))
        return bool(port) and any(live.norm_ip(r["destination"]) == live.norm_ip(relay["destination"]) for r in port.dhcp_relays)
    acl = next(iter(sections["security"]["acls"].values()))
    extended = acl.get("acl_type") == "EXTENDED"
    row = next((a for a in parsed.acls if a.name == acl["name"] and a.family == acl["family"]), None)
    wanted = sorted(_ace_view(e, fam, extended) for e in acl["entries"].values())
    return bool(row) and row.acl_type == acl["acl_type"] and sorted(_ace_view(e, fam, extended) for e in row.entries) == wanted \
        and bool(port) and {"family": fam, "name": acl["name"], "direction": "IN"} in port.acl_attachments


# --- lab -------------------------------------------------------------------------------------------------------------
class SrlPhase9Lab(SrlLab):
    """``SrlLab`` plus what one cell's behaviour test needs on the FRR peer: MTU 1500 and the routing daemons (OSPF / BGP),
    the denied ACL source address, or the DHCP server subnet -- all removed on ``close`` before the baselines compare."""

    def __init__(self, key: str):
        super().__init__()
        self.key, self.family = key, family(key)
        self.daemons = ("zebra", {"routing.OSPFV2": "ospfd", "routing.OSPFV3": "ospf6d"}.get(key, "bgpd")) \
            if key in ROUTING_CELLS else ()
        self.started, self.mtu, self.pid = [], None, ""
        try:
            if any(FrrPair.alive(self.peer, daemon) for daemon in ("zebra", "ospfd", "ospf6d", "bgpd")):
                raise RuntimeError("SR Linux routing peer already runs FRR daemons; refusing to write.")
            if " proto ra " in f" {_call(self.peer, 'ip', '-6', 'route', 'show', 'dev', PEER_DEV).stdout} ":
                raise RuntimeError("SR Linux peer holds router-advertisement routes; refusing to write.")
            (doc,) = json.loads(_run(["docker", "inspect", self.peer], timeout=10).stdout or "[null]")
            self.pid = str(((doc or {}).get("State") or {}).get("Pid") or "")
            self.mtu = str(json.loads(_call(self.peer, "ip", "-j", "link", "show", "dev", PEER_DEV).stdout)[0]["mtu"])
            plan = [("link", "set", "dev", PEER_DEV, "mtu", "1500"), ("addr", "add", PEER_LINK["IPV4"], "dev", PEER_DEV),
                    ("-6", "addr", "add", PEER_LINK["IPV6"], "dev", PEER_DEV, "nodad")]
            if key in ACL_CELLS:
                plan.append(("-6", "addr", "add", DENIED["IPV6"][1], "dev", PEER_DEV, "nodad") if self.family == "IPV6"
                            else ("addr", "add", DENIED["IPV4"][1], "dev", PEER_DEV))
            else:
                plan += [("link", "add", PEER_DUMMY, "type", "dummy"), ("link", "set", "dev", PEER_DUMMY, "up"),
                         ("addr", "add", PEER_ORIGIN["IPV4"][0], "dev", PEER_DUMMY),
                         ("-6", "addr", "add", PEER_ORIGIN["IPV6"][0], "dev", PEER_DUMMY, "nodad")]
            self.prepare_peer(tuple(plan))
            for daemon in self.daemons:
                FrrPair.must(self.peer, f"/usr/lib/frr/{daemon}", "-d", "-u", "frr", "-g", "frr", "-A", "127.0.0.1")
                self.started.append(daemon)
            deadline = time.monotonic() + 20
            while self.daemons and not set(self.daemons) <= set(_call(self.peer, "vtysh", "-c", "show daemons").stdout.split()):
                if time.monotonic() > deadline:
                    raise RuntimeError("Peer FRR daemons did not answer vtysh.")
                time.sleep(1)
        except Exception:
            self.close()
            raise

    def peer_config(self, *commands) -> None:
        result = _call(self.peer, "vtysh", "-c", "configure terminal", *(part for c in commands for part in ("-c", c)))
        if result.returncode or "%" in result.stdout:
            raise RuntimeError(f"Native peer configuration was rejected: {result.stdout[:160]}")

    def peer_show(self, command: str) -> str:
        return _call(self.peer, "vtysh", "-c", command).stdout

    def peer_ns(self, *argv, timeout=20):
        """A host tool run inside the peer's network namespace (the FRR image carries no ping / python)."""
        if not self.pid:
            raise RuntimeError("Peer namespace is unknown.")
        return _run(["sudo", "-n", "nsenter", "-t", self.pid, "-n", *argv], timeout=timeout)

    def source_ping(self, target: str, source: str) -> bool:
        result = self.peer_ns("ping", "-c", "3", "-W", "1", "-I", source, target, timeout=30)
        return result.returncode == 0 and " 0% packet loss" in result.stdout

    def close(self) -> bool:
        for daemon in reversed(self.started):
            _call(self.peer, "pkill", "-x", daemon)
        deadline = time.monotonic() + 15
        while any(FrrPair.alive(self.peer, d) for d in self.started) and time.monotonic() < deadline:
            time.sleep(0.5)
        self.started = []
        if self.mtu:
            _call(self.peer, "ip", "link", "set", "dev", PEER_DEV, "mtu", self.mtu)
        return super().close()


def configure_peer(lab: SrlPhase9Lab, key: str, sections: dict) -> None:
    fam = family(key)
    if key == "routing.OSPFV2":
        lab.peer_config(f"interface {PEER_DEV}", "ip ospf area 0", "ip ospf network point-to-point", "exit",
                        f"interface {PEER_DUMMY}", "ip ospf area 0", "ip ospf passive", "exit",
                        "router ospf", f"ospf router-id {PEER_ROUTER_ID}")
    elif key == "routing.OSPFV3":
        lab.peer_config(f"interface {PEER_DEV}", "ipv6 ospf6 area 0", "ipv6 ospf6 network point-to-point", "exit",
                        f"interface {PEER_DUMMY}", "ipv6 ospf6 area 0", "ipv6 ospf6 passive", "exit",
                        "router ospf6", f"ospf6 router-id {PEER_ROUTER_ID}")
    elif key.startswith("routing.BGP"):
        instance = next(iter(sections["routing"]["bgp"].values()))
        neighbor = next(iter(instance["neighbors"].values()))
        lab.peer_config(f"router bgp {neighbor['remote_asn']}", f"bgp router-id {PEER_ROUTER_ID}", "no bgp default ipv4-unicast",
                        "no bgp ebgp-requires-policy", f"neighbor {DUT_LINK[fam]} remote-as {instance['local_asn']}",
                        f"address-family {fam.lower()} unicast", f"neighbor {DUT_LINK[fam]} activate",
                        f"network {PEER_ORIGIN[fam][1]}")


# --- behaviour -------------------------------------------------------------------------------------------------------
_DHCP4_SERVER = r"""
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind((sys.argv[1], 67)); s.settimeout(8)
try:
    data, peer = s.recvfrom(2048)
except socket.timeout:
    print("NONE"); sys.exit(0)
giaddr = socket.inet_ntoa(data[24:28])
reply = bytearray(data[:240]); reply[0] = 2; reply[16:20] = socket.inet_aton(sys.argv[2])
reply += bytes([53, 1, 2, 54, 4]) + socket.inet_aton(sys.argv[1]) + bytes([255])
s.sendto(bytes(reply), (giaddr, 67)); print("RELAYED", data[0], giaddr)
"""
_DHCP4_CLIENT = r"""
import fcntl, os, socket, struct, sys, time
dev = sys.argv[1].encode()
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1); s.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, dev)
s.bind(("0.0.0.0", 68)); s.settimeout(6)
mac = fcntl.ioctl(s.fileno(), 0x8927, struct.pack("256s", dev))[18:24]; xid = os.urandom(4)
pkt = struct.pack("!BBBB4sHH4s4s4s4s16s192s4s", 1, 1, 6, 0, xid, 0, 0x8000, b"\0" * 4, b"\0" * 4, b"\0" * 4, b"\0" * 4,
                  mac, b"", bytes([99, 130, 83, 99])) + bytes([53, 1, 1, 255])
time.sleep(1); s.sendto(pkt, ("255.255.255.255", 67))
try:
    while True:
        data, _ = s.recvfrom(2048)
        if data[0] == 2 and data[4:8] == xid:
            print("OFFER", socket.inet_ntoa(data[16:20])); break
except socket.timeout:
    print("NONE")
"""
_DHCP6_SERVER = r"""
import socket, sys
s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind((sys.argv[1], 547)); s.settimeout(8)
try:
    data, peer = s.recvfrom(2048)
except socket.timeout:
    print("NONE"); sys.exit(0)
print("RELAYED", data[0], socket.inet_ntop(socket.AF_INET6, data[2:18]))
"""
_DHCP6_CLIENT = r"""
import os, socket, sys, time
dev = sys.argv[1]
s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM); s.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, dev.encode())
s.bind(("::", 546)); duid = bytes([0, 3, 0, 1]) + os.urandom(6)
pkt = bytes([1]) + os.urandom(3) + bytes([0, 1, 0, len(duid)]) + duid + bytes([0, 8, 0, 2, 0, 0])
time.sleep(1); s.sendto(pkt, ("ff02::1:2", 547, 0, socket.if_nametoindex(dev))); print("SENT")
"""
OFFERED = "198.18.0.99"


def dhcp_exchange(lab: SrlPhase9Lab, fam: str) -> tuple[str, str]:
    """One client broadcast on the peer link and what the server behind the DUT saw: -> (server, client) output."""
    v6 = fam == "IPV6"
    server_args = [DHCP_SERVER[fam]] if v6 else [DHCP_SERVER[fam], OFFERED]
    server = subprocess.Popen(["sudo", "-n", "nsenter", "-t", lab.pid, "-n", "python3", "-I", "-c",
                               _DHCP6_SERVER if v6 else _DHCP4_SERVER, *server_args], stdout=subprocess.PIPE, text=True)
    try:
        client = lab.peer_ns("python3", "-I", "-c", _DHCP6_CLIENT if v6 else _DHCP4_CLIENT, PEER_DEV, timeout=30).stdout.strip()
        seen = server.communicate(timeout=20)[0].strip()
    finally:
        if server.poll() is None:
            server.kill()
    return seen, client


def dhcp_relayed(fam: str, seen: str, client: str) -> bool:
    """IPv6: a RELAY-FORW (type 12) whose link address is the DUT's.  IPv4: the server saw a DISCOVER whose giaddr is the
    DUT's interface address and its offer returned to the client through the relay."""
    if fam == "IPV6":
        return seen == f"RELAYED 12 {DUT_LINK['IPV6']}"
    return seen == f"RELAYED 1 {DUT_LINK['IPV4']}" and client == f"OFFER {OFFERED}"


def behaviour(lab: SrlPhase9Lab, key: str, sections: dict, observed) -> tuple[bool, str]:
    """The cell's behaviour while NMAS's Configlets are applied: -> (ok, detail)."""
    fam = family(key)
    if key.startswith("routing."):
        return _routing_runtime(lab, key, sections, observed)
    if key in ACL_CELLS:
        permit = lab.source_ping(DUT_LINK[fam], PEER_HOP[fam])
        deny = lab.source_ping(DUT_LINK[fam], DENIED[fam][0])
        return permit and not deny, f"permitted-source ping={permit}, denied-source ping={deny}"
    seen, client = dhcp_exchange(lab, fam)
    return dhcp_relayed(fam, seen, client), f"server saw [{seen}], client saw [{client}]"


def quiet(lab: SrlPhase9Lab, key: str, sections: dict) -> tuple[bool, str]:
    """The behaviour is absent (before NMAS writes and after compensation): -> (ok, detail)."""
    fam = family(key)
    if key.startswith("routing."):
        return _withdrawn(lab, key, sections)
    if key in ACL_CELLS:
        permit = lab.source_ping(DUT_LINK[fam], PEER_HOP[fam])
        deny = lab.source_ping(DUT_LINK[fam], DENIED[fam][0])
        return permit and deny, f"unfiltered: permitted-source ping={permit}, denied-source ping={deny}"
    seen, client = dhcp_exchange(lab, fam)
    return seen == "NONE", f"no relay: server saw [{seen}], client saw [{client}]"


def _routing_runtime(lab, key, sections, observed) -> tuple[bool, str]:
    fam = family(key)
    origin = PEER_ORIGIN[fam][1]
    routes = observed.facts("routes") or []
    if key.startswith("routing.OSPF"):
        version = "OSPFV3" if key.endswith("V3") else "OSPFV2"
        full = any(n["family"] == version and n["interface"] == PORT and n["state"] == "FULL" for n in observed.facts("ospf") or [])
        learned = any(r["prefix"] == origin and r["type"] == "ospf" for r in routes)
        peer_view = lab.peer_show("show ipv6 ospf6 neighbor" if version == "OSPFV3" else "show ip ospf neighbor")
        peer_full = DUT_ROUTER_ID in peer_view and "Full" in peer_view
        return full and learned and peer_full, (f"DUT {version} adjacency FULL on {PORT}={full}; DUT installed {origin} from OSPF="
                                                f"{learned}; peer sees the DUT FULL={peer_full}")
    instance = next(iter(sections["routing"]["bgp"].values()))
    neighbor = next(iter(instance["neighbors"].values()))
    network = next(iter(instance["networks"].values()))["cidr"]
    session = next((p for p in observed.facts("bgp") or [] if p["peer"] == live.norm_ip(neighbor["peer_address"])), {})
    learned = any(r["prefix"] == origin and r["type"] == "bgp" for r in routes)
    peer_rib = lab.peer_show(f"show bgp {fam.lower()} unicast {network} json")
    advertised = '"paths"' in peer_rib and DUT_LINK[fam] in peer_rib
    ok = session.get("state") == "ESTABLISHED" and str(session.get("remote_as")) == str(neighbor["remote_asn"]) and learned and advertised
    return ok, (f"session={session.get('state')} remote-as={session.get('remote_as')} prefixes received={session.get('prefixes_received')}; "
                f"DUT installed {origin} from BGP={learned}; peer BGP table holds {network} from the DUT={advertised}")


def _withdrawn(lab, key, sections) -> tuple[bool, str]:
    observed = live.read_device(lab.device, session_factory=lab.session_factory)
    fam = family(key)
    origin = PEER_ORIGIN[fam][1]
    routes = observed.facts("routes") or []
    if key.startswith("routing.OSPF"):
        version = "OSPFV3" if key.endswith("V3") else "OSPFV2"
        gone = not any(n["family"] == version and n["interface"] == PORT for n in observed.facts("ospf") or []) \
            and not any(r["prefix"] == origin and r["type"] == "ospf" for r in routes)
    else:
        instance = next(iter(sections["routing"]["bgp"].values()))
        neighbor = next(iter(instance["neighbors"].values()))
        network = next(iter(instance["networks"].values()))["cidr"]
        gone = not any(p["peer"] == live.norm_ip(neighbor["peer_address"]) for p in observed.facts("bgp") or []) \
            and not any(r["prefix"] == origin and r["type"] == "bgp" for r in routes) \
            and '"paths"' not in lab.peer_show(f"show bgp {fam.lower()} unicast {network} json")
    return gone, f"no adjacency/session and no {origin} learned from the peer={gone}"


def settled(lab: SrlPhase9Lab, key: str, sections: dict, limit: float = 120.0) -> tuple[bool, str]:
    """``quiet`` once the node has settled: a freshly addressed link answers after neighbour discovery, and a withdrawn
    session / route disappears after the protocol notices.  Bounded; -> (ok, detail with the time it took)."""
    started = time.monotonic()
    while True:
        ok, detail = quiet(lab, key, sections)
        if ok or time.monotonic() - started > limit:
            return ok, f"{detail} (after {int(time.monotonic() - started)} s)"
        time.sleep(3)


# --- scenario / probe ------------------------------------------------------------------------------------------------
def _scenario(key: str, seed) -> dict:
    prerequisites, specs, requirements, sections = plan(key)
    result = {"actions": [], "statuses": [], "detail": "", "failure": "", "imported": False, "control": False, "after": False,
              "preserved": True}
    lab = SrlPhase9Lab(key)
    try:
        lab.native(prerequisites)
        lab.native(seed)
        configure_peer(lab, key, sections)
        prepared_tree = lab.executor.config_tree()
        prepared = lab.executor.tree_digest(prepared_tree)
        # safety net only (never the claim): the lab's own undo of everything NMAS is about to send
        safety = model.inverse(model.additive([op for spec in specs for op in model.operations(spec.lines)], prepared_tree),
                               prepared_tree)
        result["control"], control_detail = settled(lab, key, sections)
        state = {}

        def verify():
            observed, post_ok, failed = _postcheck(lab.device, requirements, lab.session_factory)
            tree = lab.executor.config_tree()
            result["imported"] = imported(key, sections, tree)
            runtime, detail = behaviour(lab, key, sections, observed)
            kept = preserved(key, tree) if seed else True
            state.update(read_ok=bool(observed.live_reachable), post_ok=post_ok, preserved=kept)
            return post_ok and result["imported"] and runtime and kept, (
                f"operator postcheck over gNMI pass={post_ok} {failed}; live gNMI config import recovered intent="
                f"{result['imported']}; {detail}; pre-existing configuration preserved={kept}")

        result.update(_transaction(lab.executor, specs, verify, attempts=40))
        result.update(state)
        result["detail"] = f"control before apply: {control_detail}; " + result["detail"]
        result["config_restored"] = lab.digest() == prepared
        if seed:
            result["preserved"] = result.get("preserved", True) and preserved(key, lab.executor.config_tree())
        result["after"], gone_detail = settled(lab, key, sections)
        result["detail"] += f"; after compensation: {gone_detail}"
        if not result["config_restored"] and safety:        # never leave residue behind a failed claim
            lab.gnmi.set_cli(safety)
    except Exception as exc:  # pylint: disable=broad-exception-caught  # any lab or device failure is recorded as a FAIL, never a crash
        result["failure"] = f"{type(exc).__name__}: {str(exc)[:500]}"
    finally:
        result["restored"] = lab.close()
    return result


def probe_srlinux_phase9(cell, key: str):
    _, specs, _, _ = plan(key)
    scenarios = {"pristine node": _scenario(key, ()), "configured node": _scenario(key, seeds(key))}
    reference = f"live:{LAB}/srl-{key.split('.')[1].lower()}/{timezone.now().isoformat()}"
    rendered = "; ".join(f"[{spec.object_type}] " + " / ".join(line.removeprefix("set ") for line in spec.lines) for spec in specs)
    text = " || ".join(
        f"{label}: preflight={r['actions']}; {r['detail']}; compensation={r['statuses']} codes={r.get('compensation_codes')}; "
        f"running configuration identical to "
        f"pre-apply capture={r.get('config_restored')}; pre-existing configuration preserved={r.get('preserved')}; lab baseline "
        f"restored={r.get('restored')}; {r['failure'] or 'no failure'}" for label, r in scenarios.items())
    # outcomes first: stored evidence detail is bounded, and the rendered Configlets are reproducible from the plan
    detail = (f"isolated SR Linux {key} against an FRR 8.4.4 peer through the registered SrLinuxExecutor (atomic gNMI "
              f"CLI-origin Set, gNMI Get captured-tree inverse) || {text} || Configlets from the planner's own handlers: "
              f"NMAS rendered {rendered}")
    def every(*keys) -> bool:
        return all(r.get(k) for r in scenarios.values() for k in keys)

    for stage, ok, reason in (
        ("live_write", every("applied"), "FUNCTIONAL_TEST_FAILED"),
        ("live_read", every("read_ok"), "LIVE_READ_ABSENT"),
        ("live_post_write_validation", every("post_ok"), "POSTCHECK_ABSENT"),
        ("parser_import", every("imported"), "PARSER_ABSENT"),
        ("runtime_validation", every("verified", "control"), "FUNCTIONAL_TEST_FAILED"),
        ("compensation", every("compensated", "config_restored", "after", "restored", "preserved"), "COMPENSATION_ABSENT"),
    ):
        cell.probes[stage] = assessment.probe("PASS" if ok else "FAIL", detail[:3900], reason="" if ok else reason,
                                              test_type="LIVE", reference=reference)
    cell.runtime_version = RUNTIME
    return scenarios
