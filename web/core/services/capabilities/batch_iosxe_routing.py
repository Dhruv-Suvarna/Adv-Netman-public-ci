"""Reversible IOS XE routing probes (V2 Phase 9): OSPFv2, OSPFv3, RIPv2 and BGP on the isolated Catalyst 8000V.

The DUT is the disposable ``nmas-cap-iosxe`` router (GigabitEthernet2 <-> Linux peer eth1); the peer runs FRRouting 8.4.4
daemons started for one scenario only.  Lab prerequisites -- the GigabitEthernet2 addresses, a Null0 anchor route for the
BGP network NMAS advertises, the peer's addresses / originating dummy interface / FRR configuration -- are written natively
and are never part of the claim.  Everything NMAS claims goes through the registered ``IosXeExecutor`` in engine order:
preflight every Configlet (split as the planner splits them), apply, verify, compensate in reverse.

Verification of one scenario:

* operator postcheck -- the Phase-15 evaluators over a fresh live read (process / binding / neighbor / network config read
  back from the running configuration, OSPF FULL, BGP Established, RIP route installed);
* live import -- ``parser_iosxe`` recovers the rendered intent from the live running configuration;
* protocol behaviour -- the DUT installs the peer's originated prefix from the protocol, and the PEER sees the DUT (OSPF
  FULL from the peer's side, the DUT as a RIP information source, the DUT's BGP network in the peer's BGP table);
* compensation -- the running configuration equals the capture taken before NMAS wrote anything, the adjacency/session
  is gone, the learned route is withdrawn and, on a router that already ran the process, its unrelated objects survive.

Each cell runs on a pristine router and on one whose process already exists with unrelated configuration.
"""

from __future__ import annotations

import json
import time
from copy import deepcopy

from django.utils import timezone

from ..config_import import parser_iosxe
from ..execution.executors import iosxe
from ..execution.executors.base import ConfigletSpec
from ..execution.executors.ceos import _config_blocks
from ..health import live
from . import assessment
from .batch_frr_routing import FrrPair, _call, _postcheck, _requirements, _transaction
from .batch_iosxe import LAB, PEER_DEV, PLATFORM, PORT, RUNTIME, IosxeLab, _added
from .features import by_key
from .probe_cases import sample

PEER_DUMMY = "nmascap3"
PEER_LINK = {"IPV4": "198.18.0.2/30", "IPV6": "2001:db8:44::2/64"}
DUT_LINK = {"IPV4": "198.18.0.1", "IPV6": "2001:db8:44::1"}
PEER_ORIGIN = {"IPV4": ("192.0.2.1/24", "192.0.2.0/24"), "IPV6": ("2001:db8:99::1/64", "2001:db8:99::/64")}
DUT_ANCHOR = {"IPV4": "ip route 203.0.113.0 255.255.255.0 Null0", "IPV6": "ipv6 route 2001:db8:113::/64 Null0"}
# RIP: a lab-only loopback inside the classful network NMAS enables gives the DUT a route of its own to advertise.  Split
# horizon keeps GigabitEthernet2's own subnet out of updates sent on it, so without this the DUT has nothing to tell the peer.
DUT_RIP_SOURCE = ("interface Loopback44", " ip address 198.18.0.129 255.255.255.255")
RIP_ADVERTISED = "198.18.0.129/32"
CELLS = ("routing.OSPFV2", "routing.OSPFV3", "routing.RIPV2", "routing.BGP_IPV4", "routing.BGP_IPV6")
DAEMONS = {"routing.OSPFV2": "ospfd", "routing.OSPFV3": "ospf6d", "routing.RIPV2": "ripd",
           "routing.BGP_IPV4": "bgpd", "routing.BGP_IPV6": "bgpd"}
FAMILY = {"routing.OSPFV2": "IPV4", "routing.OSPFV3": "IPV6", "routing.RIPV2": "IPV4", "routing.BGP_IPV4": "IPV4",
          "routing.BGP_IPV6": "IPV6"}
# The "configured router" scenario: the process already exists with objects NMAS does not own and must preserve.
SEEDS = {
    "routing.OSPFV2": ("router ospf 44", " auto-cost reference-bandwidth 1000", " network 198.18.77.0 0.0.0.255 area 0"),
    "routing.OSPFV3": ("ipv6 router ospf 44", " auto-cost reference-bandwidth 1000"),
    "routing.RIPV2": ("router rip", " version 2", " network 10.0.0.0"),
    "routing.BGP_IPV4": ("router bgp 65044", " neighbor 198.18.9.9 remote-as 65099", " address-family ipv4",
                         "  network 198.51.100.0", " exit-address-family"),
    "routing.BGP_IPV6": ("router bgp 65044", " neighbor 2001:db8:9::9 remote-as 65099", " address-family ipv6",
                         "  neighbor 2001:db8:9::9 activate", "  network 2001:db8:114::/64", " exit-address-family"),
}
# Seed statements whose presence after compensation proves NMAS left the pre-existing process alone (as displayed).
PRESERVED = {
    "routing.OSPFV2": ("auto-cost reference-bandwidth 1000", "network 198.18.77.0 0.0.0.255 area 0"),
    "routing.OSPFV3": ("auto-cost reference-bandwidth 1000",),
    "routing.RIPV2": ("network 10.0.0.0",),
    "routing.BGP_IPV4": ("neighbor 198.18.9.9 remote-as 65099", "network 198.51.100.0"),
    "routing.BGP_IPV6": ("neighbor 2001:db8:9::9 remote-as 65099", "network 2001:db8:114::/64"),
}


def _spec(n, kind, lines, expected=None):
    return ConfigletSpec(f"P9-XE-{kind}-{n}", n, "iosxe", PLATFORM, kind, "CREATE_DEFINE", tuple(lines), expected or {})


def _blocks(lines):
    return [[header, *children] for header, children in _config_blocks(lines)]


def plan(key):
    """-> (prerequisite lines, Configlet specs, postcheck requirements, sections) split as the planner splits them:
    a process definition, its interface binding, and for BGP the neighbor, its address-family activation and the network."""
    case = sample(PLATFORM, by_key()[key])
    sections, baseline = deepcopy(case.sections), deepcopy(case.baseline)
    prerequisites = _added(baseline, {**baseline, "interfaces": {}})
    family = FAMILY[key]
    blocks = _blocks(_added(sections, baseline))
    binding = next((b for b in blocks if b[0].startswith("interface ")), None)
    process = next(b for b in blocks if not b[0].startswith("interface "))
    routing = sections["routing"]
    if key.startswith("routing.BGP"):
        instance = next(iter(routing["bgp"].values()))
        neighbor = next(iter(instance["neighbors"].values()))
        network = next(iter(instance["networks"].values()))["cidr"]
        header = process[0]
        af = f"   address-family {family.lower()}"
        inner = [line for line in process[1:] if line.startswith("      ")]
        top = [line for line in process[1:] if line not in inner and line.strip().lower() not in (af.strip(), "exit-address-family")]
        specs = [
            _spec(1, "routing_bgp", [header, *(line for line in top if "neighbor" not in line)]),
            _spec(2, "bgp_neighbor", [header, *(line for line in top if "neighbor" in line)]),
            _spec(3, "bgp_neighbor_af", [header, af, *(line for line in inner if "activate" in line), "   exit-address-family"]),
            _spec(4, "bgp_network", [header, af, *(line for line in inner if "network" in line), "   exit-address-family"]),
        ]
        requirements = _requirements([
            ("process", "ROUTING_PROCESS_INTENDED", {"protocol": "bgp", "local_asn": instance["local_asn"], "router_id": instance["router_id"]}),
            ("peer", "BGP_PEER_INTENDED", {"peer": neighbor["peer_address"], "remote_asn": neighbor["remote_asn"], "local_asn": instance["local_asn"]}),
            ("af", "BGP_AF_ACTIVATION_INTENDED", {"peer": neighbor["peer_address"], "remote_asn": neighbor["remote_asn"], "address_family": family}),
            ("network", "BGP_NETWORK_INTENDED", {"prefix": network, "family": family}),
        ], device="iosxe")
        return prerequisites, specs, requirements, {"instance": instance, "neighbor": neighbor, "network": network}
    if key == "routing.RIPV2":
        instance = next(iter(routing["rip"].values()))
        specs = [_spec(1, "routing_rip", process)]
        requirements = _requirements([
            ("process", "ROUTING_PROCESS_INTENDED", {"protocol": "rip", "version": "RIPV2"}),
            ("binding", "ROUTING_INTERFACE_ENABLED", {"protocol": "rip", "interface": PORT, "passive": False}),
            ("route", "RIP_ROUTE_INTENDED", {"prefix": PEER_ORIGIN["IPV4"][1]}),
        ], device="iosxe")
        return prerequisites, specs, requirements, {"instance": instance}
    instance = next(iter(routing["ospf"].values()))
    version = instance["version"]
    specs = [_spec(1, "routing_ospf", process), _spec(2, "routing_binding", binding)]
    requirements = _requirements([
        ("process", "ROUTING_PROCESS_INTENDED", {"protocol": "ospf", "version": version, "process_id": instance["process_id"],
                                                 "router_id": instance["router_id"]}),
        ("binding", "ROUTING_INTERFACE_ENABLED", {"protocol": "ospf", "version": version, "interface": PORT, "area": "0",
                                                  "passive": False}),
    ], device="iosxe")
    return prerequisites, specs, requirements, {"instance": instance}


def imported(key, context, text) -> bool:
    """The live running configuration, imported by the operator parser, carries the routing intent NMAS rendered."""
    parsed = parser_iosxe.parse(text)
    instance = context["instance"]
    if key.startswith("routing.BGP"):
        neighbor, family = context["neighbor"], FAMILY[key]
        row = next((r for r in parsed.routing_instances if r.family == "bgp" and r.fields["local_asn"] == instance["local_asn"]), None)
        return bool(row) and row.fields["router_id"] == instance["router_id"] and any(
            n["peer_address"] == live.norm_ip(neighbor["peer_address"]) and n["remote_asn"] == neighbor["remote_asn"]
            and n[f"activate_{family.lower()}"] for n in row.neighbors) and any(
            n["family"] == family and live.norm_prefix(n["cidr"]) == live.norm_prefix(context["network"]) for n in row.networks)
    if key == "routing.RIPV2":
        row = next((r for r in parsed.routing_instances if r.family == "rip"), None)
        return bool(row) and row.fields.get("rip_version") == "2" and any(b["interface_name"] == PORT for b in row.bindings)
    row = next((r for r in parsed.routing_instances if r.family == "ospf" and r.fields["version"] == instance["version"]
                and r.fields["process_id"] == instance["process_id"]), None)
    binding = next(iter(instance["interfaces"].values()))
    return bool(row) and row.fields["router_id"] == instance["router_id"] and any(
        b["interface_name"] == PORT and b["area"] == "0" and b.get("cost") == binding.get("cost")
        and b.get("network_type") == binding.get("network_type") for b in row.bindings)


class IosxeRoutingLab(IosxeLab):
    """``IosxeLab`` plus a disposable FRR routing peer: MTU 1500 (OSPF database exchange), an originating dummy interface
    and one protocol daemon, all removed on ``close`` before the router / peer baselines are compared."""

    def __init__(self, key):
        super().__init__()
        self.key, self.family = key, FAMILY[key]
        self.daemons = ("zebra", DAEMONS[key])
        self.started, self.mtu = [], None
        try:
            if any(FrrPair.alive(self.peer, daemon) for daemon in self.daemons):
                raise RuntimeError("IOS XE routing peer already runs FRR daemons; refusing to write.")
            # A route learned from an earlier router advertisement expires on its own and would change the peer's
            # route table between the baseline capture and the comparison: such a peer is not at a stable baseline.
            if " proto ra " in f" {_call(self.peer, 'ip', '-6', 'route', 'show', 'dev', PEER_DEV).stdout} ":
                raise RuntimeError("IOS XE routing peer holds router-advertisement routes; refusing to write.")
            self.mtu = str(json.loads(_call(self.peer, "ip", "-j", "link", "show", "dev", PEER_DEV).stdout)[0]["mtu"])
            self.prepare_peer((("link", "set", "dev", PEER_DEV, "mtu", "1500"),
                               ("addr", "add", PEER_LINK["IPV4"], "dev", PEER_DEV),
                               ("-6", "addr", "add", PEER_LINK["IPV6"], "dev", PEER_DEV, "nodad"),
                               ("link", "add", PEER_DUMMY, "type", "dummy"), ("link", "set", "dev", PEER_DUMMY, "up"),
                               ("addr", "add", PEER_ORIGIN["IPV4"][0], "dev", PEER_DUMMY),
                               ("-6", "addr", "add", PEER_ORIGIN["IPV6"][0], "dev", PEER_DUMMY, "nodad")))
            for daemon in self.daemons:
                FrrPair.must(self.peer, f"/usr/lib/frr/{daemon}", "-d", "-u", "frr", "-g", "frr", "-A", "127.0.0.1")
                self.started.append(daemon)
            deadline = time.monotonic() + 20
            while not set(self.daemons) <= set(_call(self.peer, "vtysh", "-c", "show daemons").stdout.split()):
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

    def peer_show(self, command) -> str:
        return _call(self.peer, "vtysh", "-c", command).stdout

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


def _configure_peer(lab, key, context) -> None:
    family = FAMILY[key]
    if key == "routing.OSPFV2":
        lab.peer_config(f"interface {PEER_DEV}", "ip ospf area 0", "ip ospf network point-to-point", "exit",
                        f"interface {PEER_DUMMY}", "ip ospf area 0", "ip ospf passive", "exit",
                        "router ospf", "ospf router-id 198.18.44.2")
    elif key == "routing.OSPFV3":
        lab.peer_config(f"interface {PEER_DEV}", "ipv6 ospf6 area 0", "ipv6 ospf6 network point-to-point", "exit",
                        f"interface {PEER_DUMMY}", "ipv6 ospf6 area 0", "ipv6 ospf6 passive", "exit",
                        "router ospf6", "ospf6 router-id 198.18.44.2")
    elif key == "routing.RIPV2":
        lab.peer_config("router rip", "version 2", f"network {PEER_DEV}", f"network {PEER_DUMMY}")
    else:
        instance = context["instance"]
        lab.peer_config(f"router bgp {context['neighbor']['remote_asn']}", "bgp router-id 198.18.44.2", "no bgp default ipv4-unicast",
                        "no bgp ebgp-requires-policy", f"neighbor {DUT_LINK[family]} remote-as {instance['local_asn']}",
                        f"address-family {family.lower()} unicast", f"neighbor {DUT_LINK[family]} activate",
                        f"network {PEER_ORIGIN[family][1]}")


def peer_rip_route(lab) -> bool:
    """The peer's routing table holds the DUT's advertised loopback as a RIP route."""
    try:
        table = json.loads(lab.peer_show(f"show ip route {RIP_ADVERTISED} json") or "{}")
    except ValueError:
        return False
    return any(row.get("protocol") == "rip" for row in table.get(RIP_ADVERTISED) or [])


def _runtime(lab, key, context, observed) -> tuple[bool, str]:
    """Protocol behaviour seen from both ends: -> (ok, detail)."""
    family, origin = FAMILY[key], PEER_ORIGIN[FAMILY[key]][1]
    routes = observed.facts("routes") or []
    if key.startswith("routing.OSPF"):
        version = context["instance"]["version"]
        full = any(n["family"] == version and n["interface"] == PORT and n["state"] == "FULL" for n in observed.facts("ospf") or [])
        learned = any(r["prefix"] == origin and r["type"] == "ospf" for r in routes)
        peer_view = lab.peer_show("show ipv6 ospf6 neighbor" if version == "OSPFV3" else "show ip ospf neighbor")
        peer_full = "198.18.44.1" in peer_view and "Full" in peer_view
        return full and learned and peer_full, (f"DUT {version} adjacency FULL on {PORT}={full}; DUT installed {origin} from OSPF="
                                                f"{learned}; peer sees the DUT FULL={peer_full}")
    if key == "routing.RIPV2":
        learned = any(r["prefix"] == origin and r["type"] == "rip" for r in routes)
        heard = peer_rip_route(lab)
        return learned and heard, f"DUT installed {origin} from RIP={learned}; peer installed the DUT's {RIP_ADVERTISED} from RIP={heard}"
    neighbor = context["neighbor"]
    session = next((p for p in observed.facts("bgp") or [] if p["peer"] == live.norm_ip(neighbor["peer_address"])), {})
    learned = any(r["prefix"] == origin and r["type"] == "bgp" for r in routes)
    peer_rib = lab.peer_show(f"show bgp {family.lower()} unicast {context['network']} json")
    advertised = '"paths"' in peer_rib and DUT_LINK[family] in peer_rib
    ok = session.get("state") == "ESTABLISHED" and str(session.get("remote_as")) == str(neighbor["remote_asn"]) and learned and advertised
    return ok, (f"session={session.get('state')} remote-as={session.get('remote_as')} prefixes received={session.get('prefixes_received')}; "
                f"DUT installed {origin} from BGP={learned}; peer BGP table holds {context['network']} from the DUT={advertised}")


def _withdrawn(lab, key, context) -> tuple[bool, str]:
    """After compensation: no adjacency / session from NMAS's configuration and the learned route is gone."""
    observed = live.read_device(lab.device, session_factory=lab.session_factory)
    family, origin = FAMILY[key], PEER_ORIGIN[FAMILY[key]][1]
    routes = observed.facts("routes") or []
    if key.startswith("routing.OSPF"):
        version = context["instance"]["version"]
        gone = not any(n["family"] == version and n["interface"] == PORT for n in observed.facts("ospf") or []) \
            and not any(r["prefix"] == origin for r in routes)
    elif key == "routing.RIPV2":
        gone = not any(r["prefix"] == origin and r["type"] == "rip" for r in routes) and not peer_rip_route(lab)
    else:
        gone = not any(p["peer"] == live.norm_ip(context["neighbor"]["peer_address"]) for p in observed.facts("bgp") or []) \
            and not any(r["prefix"] == origin for r in routes) \
            and '"paths"' not in lab.peer_show(f"show bgp {family.lower()} unicast {context['network']} json")
    return gone, f"adjacency/session and learned {origin} withdrawn after compensation={gone}"


def _scenario(key, seed) -> dict:
    prerequisites, specs, requirements, context = plan(key)
    result = {"actions": [], "statuses": [], "detail": "", "failure": "", "imported": False, "after": False, "preserved": True}
    lab = IosxeRoutingLab(key)
    try:
        lab.native(prerequisites)
        if key.startswith("routing.BGP"):
            lab.native([DUT_ANCHOR[FAMILY[key]]])
        elif key == "routing.RIPV2":
            lab.native(DUT_RIP_SOURCE)
        lab.native(seed)
        _configure_peer(lab, key, context)
        prepared_text = lab.executor._config_text()
        prepared = lab.executor.running_config_digest()
        safety = iosxe.config_inverse([line for spec in specs for line in spec.lines], prepared_text)
        state = {}

        def verify():
            observed, post_ok, failed = _postcheck(lab.device, requirements, lab.session_factory)
            text = lab.executor._config_text()
            result["imported"] = imported(key, context, text)
            runtime, detail = _runtime(lab, key, context, observed)
            preserved = all(line.lower() in text.lower() for line in PRESERVED[key]) if seed else True
            state.update(read_ok=bool(observed.live_reachable), post_ok=post_ok, preserved=preserved)
            return post_ok and result["imported"] and runtime and preserved, (
                f"operator postcheck pass={post_ok} {failed}; live running-config import recovered intent={result['imported']}; "
                f"{detail}; unrelated process configuration preserved={preserved}")

        result.update(_transaction(lab.executor, specs, verify, attempts=60))
        result.update(state)
        result["config_restored"] = lab.executor.running_config_digest() == prepared
        if seed:
            kept = lab.executor._config_text().lower()
            result["preserved"] = result.get("preserved", True) and all(line.lower() in kept for line in PRESERVED[key])
        # RIP keeps a route learned before ``no network`` until its invalid timer (180 s) expires: wait for withdrawal.
        started = time.monotonic()
        while True:
            result["after"], gone_detail = _withdrawn(lab, key, context)
            if result["after"] or time.monotonic() - started > 330:
                break
            time.sleep(5)
        result["detail"] += f"; {gone_detail} (after {int(time.monotonic() - started)} s)"
        if not result["config_restored"] and safety:        # never leave residue behind a failed claim
            lab.conn.send_config_set([line.strip() for line in safety], read_timeout=90)
    except Exception as exc:  # pylint: disable=broad-exception-caught  # any lab or device failure is recorded as a FAIL, never a crash
        result["failure"] = f"{type(exc).__name__}: {str(exc)[:500]}"
    finally:
        result["restored"] = lab.close()
    return result


def probe_iosxe_routing(cell, key: str):
    _, specs, _, _ = plan(key)
    scenarios = {"pristine router": _scenario(key, ()), "configured router": _scenario(key, SEEDS[key])}
    reference = f"live:{LAB}/iosxe-{key.split('.')[1].lower()}/{timezone.now().isoformat()}"
    rendered = "; ".join(f"[{spec.object_type}] " + " / ".join(line.strip() for line in spec.lines) for spec in specs)
    text = " || ".join(
        f"{label}: preflight={r['actions']}; {r['detail']}; compensation={r['statuses']}; running configuration identical to "
        f"pre-apply capture={r.get('config_restored')}; unrelated objects preserved={r.get('preserved')}; lab baseline restored="
        f"{r.get('restored')}; {r['failure'] or 'no failure'}" for label, r in scenarios.items())
    detail = (f"isolated IOS XE {key} against an FRR 8.4.4 peer through the registered IosXeExecutor (Netmiko configuration "
              f"mode, captured running-config inverse): NMAS rendered {rendered} || {text}")
    def every(*keys) -> bool:
        return all(r.get(k) for r in scenarios.values() for k in keys)

    for stage, ok, reason in (
        ("live_write", every("applied"), "FUNCTIONAL_TEST_FAILED"),
        ("live_read", every("read_ok"), "LIVE_READ_ABSENT"),
        ("live_post_write_validation", every("post_ok"), "POSTCHECK_ABSENT"),
        ("parser_import", every("imported"), "PARSER_ABSENT"),
        ("runtime_validation", every("verified"), "FUNCTIONAL_TEST_FAILED"),
        ("compensation", every("compensated", "config_restored", "after", "preserved", "restored"), "COMPENSATION_ABSENT"),
    ):
        cell.probes[stage] = assessment.probe("PASS" if ok else "FAIL", detail[:3900], reason="" if ok else reason,
                                              test_type="LIVE", reference=reference)
    cell.runtime_version = f"{RUNTIME} running FRRouting 8.4.4"
    return scenarios
