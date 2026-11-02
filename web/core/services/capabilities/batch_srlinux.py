"""Reversible SR Linux probes on the isolated ``srl`` node (ethernet-1/1 <-> FRR peer eth2).

One recipe for LOOPBACK, ROUTED_PHYSICAL, SUBINTERFACE and STATIC_IPV4/IPV6.  Lab prerequisites (peer addresses, the
routed uplink a static route needs) are applied natively and are never part of the claim.  The NMAS-rendered Configlets,
split exactly as the planner splits them, go through the registered ``SrLinuxExecutor`` in engine order: preflight all,
apply, verify, compensate in reverse.  Verification is the operator postcheck over gNMI state, a live import through
``parser_srlinux``, and real traffic from the node's own network-instance.  Each cell runs twice -- on a pristine node and
on a node that already holds related configuration -- and the running configuration must equal the capture taken before
NMAS wrote anything.
"""

from __future__ import annotations

import json
import os
from collections import Counter
from copy import deepcopy

from django.utils import timezone

from .. import srlinux_model as model
from ..config_import import parser_srlinux
from ..execution.executors.srlinux import SrLinuxExecutor
from ..execution.writers.srlinux_gnmi import GnmiSession
from ..health import live
from . import assessment
from .batch_frr_routing import FrrPair, _call, _postcheck, _requirements, _transaction
from .features import by_key
from .isolated_live import LAB, NETWORK, _run, _target
from .offline_verify import _descriptors
from .probe_cases import IF, sample

PLATFORM, IMAGE, PORT, PEER_DEV, DUMMY = "nokia_srlinux", "ghcr.io/nokia/srlinux:24.10", "ethernet-1/1", "eth2", "nmascap1"
RUNTIME = "ghcr.io/nokia/srlinux:24.10 (24.10.7) / FRR Linux peer"
V4, V6 = ("198.18.0.1/30", "198.18.0.2/30"), ("2001:db8:44::1/64", "2001:db8:44::2/64")
FAR = {"IPV4": "203.0.113.1/24", "IPV6": "2001:db8:113::1/64"}
_LINK = (("addr", "add", V4[1], "dev", PEER_DEV), ("-6", "addr", "add", V6[1], "dev", PEER_DEV, "nodad"))
_VLAN = (("link", "add", "link", PEER_DEV, "name", f"{PEER_DEV}.44", "type", "vlan", "id", "44"),
         ("addr", "add", V4[1], "dev", f"{PEER_DEV}.44"), ("-6", "addr", "add", V6[1], "dev", f"{PEER_DEV}.44", "nodad"),
         ("link", "set", "dev", f"{PEER_DEV}.44", "up"))
_FAR = (("link", "add", DUMMY, "type", "dummy"), ("link", "set", "dev", DUMMY, "up"),
        ("addr", "add", FAR["IPV4"], "dev", DUMMY), ("-6", "addr", "add", FAR["IPV6"], "dev", DUMMY, "nodad"))
# cell -> (peer prerequisites, ping targets that must answer once NMAS has applied)
PLANS = {
    "interface.LOOPBACK": ((), ("198.18.0.1", "2001:db8:44::1")),
    # mgmt0 lives in the built-in mgmt network-instance and keeps its DHCP addresses; NMAS only adds to it
    "interface.MANAGEMENT": ((), ("198.18.0.1", "2001:db8:44::1")),
    "interface.ROUTED_PHYSICAL": (_LINK, ("198.18.0.2", "2001:db8:44::2")),
    "interface.SUBINTERFACE": (_VLAN, ("198.18.0.2", "2001:db8:44::2")),
    "routing.STATIC_IPV4": ((*_LINK, *_FAR), ("203.0.113.1",)),
    "routing.STATIC_IPV6": ((*_LINK, *_FAR), ("2001:db8:113::1",)),
}
# Related configuration that exists BEFORE NMAS writes (the "configured node" scenario): a replaced value, an
# unrelated address / route NMAS must preserve, and a network-instance that must survive compensation.
NETNS = {"interface.MANAGEMENT": "srbase-mgmt"}
# Platform facts that explain an expected live refusal (observed natively on the isolated 24.10.7 node).
NOTES = {"interface.MANAGEMENT": "mgmt0 of this node is addressed by its DHCP client; SR Linux answers a static address with "
                                 "'ipv4 address not configurable while ipv4 dhcp-client present', and removing the DHCP "
                                 "client would cut the management session NMAS is using, so it is not attempted. "}
SEEDS = {
    "interface.MANAGEMENT": ('set / interface mgmt0 description "legacy management"',),
    "interface.LOOPBACK": ("set / interface lo44 admin-state enable", 'set / interface lo44 description "legacy loopback"',
                           "set / interface lo44 subinterface 0 admin-state enable",
                           "set / interface lo44 subinterface 0 ipv4 admin-state enable",
                           "set / interface lo44 subinterface 0 ipv4 address 198.18.7.1/32",
                           "set / network-instance default interface lo44.0"),
    "interface.ROUTED_PHYSICAL": (f'set / interface {PORT} description "legacy uplink"', f"set / interface {PORT} mtu 9000",
                                  f"set / interface {PORT} subinterface 0 ip-mtu 1400",
                                  f"set / interface {PORT} subinterface 0 admin-state enable",
                                  f"set / interface {PORT} subinterface 0 ipv4 admin-state enable",
                                  f"set / interface {PORT} subinterface 0 ipv4 address 198.18.7.1/24",
                                  f"set / network-instance default interface {PORT}.0"),
    "interface.SUBINTERFACE": (f"set / interface {PORT} vlan-tagging true",
                               f"set / interface {PORT} subinterface 45 type routed",
                               f"set / interface {PORT} subinterface 45 vlan encap single-tagged vlan-id 45",
                               f"set / interface {PORT} subinterface 45 ipv4 admin-state enable",
                               f"set / interface {PORT} subinterface 45 ipv4 address 198.18.45.1/24",
                               f"set / network-instance default interface {PORT}.45"),
    "routing.STATIC_IPV4": ("set / network-instance default static-routes route 192.0.2.0/24 next-hop-group nhg-legacy",
                            "set / network-instance default next-hop-groups group nhg-legacy nexthop 1 ip-address 198.18.0.2"),
    "routing.STATIC_IPV6": ("set / network-instance default static-routes route 2001:db8:99::/64 next-hop-group nhg-legacy",
                            "set / network-instance default next-hop-groups group nhg-legacy nexthop 1 ip-address 2001:db8:44::2"),
}


class SrlLab:
    """The isolated SR Linux node and its FRR peer, verified by identity and restored exactly on ``close``."""

    def __init__(self):
        container = f"clab-{LAB}-srl"
        (doc,) = json.loads(_run(["docker", "inspect", container], timeout=10).stdout or "[null]")
        labels = ((doc or {}).get("Config") or {}).get("Labels") or {}
        networks = ((doc or {}).get("NetworkSettings") or {}).get("Networks") or {}
        if not doc or labels.get("containerlab") != LAB or labels.get("clab-node-kind") != "nokia_srlinux" \
                or NETWORK not in networks or doc["Config"].get("Image") != IMAGE or not doc["State"].get("Running"):
            raise RuntimeError("SR Linux target identity does not match the isolated validation lab.")
        password = os.environ.get("NMAS_CAP_SRL_PASSWORD", "")
        if not password:
            raise RuntimeError("NMAS_CAP_SRL_PASSWORD is required for the isolated SR Linux node (never persisted).")
        self.container, self.peer = container, _target("ubuntu_frr")[0]["container"]
        self.device = {"name": "srl", "platform": PLATFORM, "container": container}
        self.gnmi = GnmiSession(host=networks[NETWORK]["IPAddress"], port=57400, password=password, timeout=30,
                                username=os.environ.get("NMAS_CAP_SRL_USERNAME", "admin"))
        self.executor = SrLinuxExecutor(self.device, connection_factory=lambda _device: self.gnmi)
        self.executor.connect()
        self.session_factory = lambda device: live.SrLinuxSession(device, gnmi=self.gnmi)
        tree = self.executor.config_tree()
        self.baseline, self.peer_baseline = self.executor.tree_digest(tree), FrrPair.kernel(self.peer)
        port = model.lookup(tree, (model.Step("interface", "name", PORT),))
        if any(row.get("name") == "default" for row in tree.get("network-instance") or []) \
                or any(row.get("name") == "lo44" for row in tree.get("interface") or []) \
                or port is model.MISSING or set(port) - {"name", "admin-state"} \
                or '"family":"inet"' in _call(self.peer, "ip", "-j", "addr", "show", "dev", PEER_DEV).stdout.replace(" ", ""):
            self.gnmi.disconnect()
            raise RuntimeError("SR Linux node / FRR peer eth2 are not at the disposable baseline; refusing to write.")
        self.ra = _call(self.peer, "sysctl", "-n", f"net.ipv6.conf.{PEER_DEV}.accept_ra").stdout.strip()
        self.undo, self.peer_links = [], []

    def native(self, statements) -> None:
        """Lab prerequisite written directly (never an NMAS claim); its exact undo is derived from the tree it found."""
        statements = list(statements)
        if not statements:
            return
        inverse = model.inverse(model.operations(statements), self.executor.config_tree())
        self.gnmi.set_cli(statements)
        self.undo.append(inverse or [])

    def prepare_peer(self, plan) -> None:
        FrrPair.must(self.peer, "sysctl", "-w", f"net.ipv6.conf.{PEER_DEV}.accept_ra=0")
        for argv in plan:
            if argv[:2] == ("link", "add"):
                self.peer_links.append(argv[2] if argv[2] != "link" else argv[5])
            FrrPair.must(self.peer, "ip", *argv)

    def ping(self, target, netns="srbase-default") -> bool:
        """Three echoes from inside the network-instance the tested object belongs to (never across VRFs)."""
        result = _run(["docker", "exec", self.container, "ip", "netns", "exec", netns, "ping", "-c", "3", "-W", "1",
                       target], timeout=30)
        return result.returncode == 0 and " 0% packet loss" in result.stdout

    def digest(self) -> str:
        return self.executor.running_config_digest()

    def close(self) -> bool:
        restored = False
        try:
            for inverse in reversed(self.undo):
                if inverse:
                    self.gnmi.set_cli(inverse)
            for name in self.peer_links:
                _call(self.peer, "ip", "link", "delete", name)
            _call(self.peer, "ip", "addr", "flush", "dev", PEER_DEV, "scope", "global")
            _call(self.peer, "sysctl", "-w", f"net.ipv6.conf.{PEER_DEV}.accept_ra={self.ra}")
            restored = self.digest() == self.baseline and FrrPair.kernel(self.peer) == self.peer_baseline
        finally:
            self.executor.close()
        if not restored:
            raise RuntimeError("Isolated SR Linux lab was not restored to its captured baseline.")
        return True


def _added(after, before) -> list[str]:
    return model.statements((Counter(_descriptors(PLATFORM, after)) - Counter(_descriptors(PLATFORM, before))).elements())


def _spec(n, kind, lines, expected):
    from ..execution.executors.base import ConfigletSpec
    return ConfigletSpec(f"P4-SRL-{kind}-{n}", n, "srl", PLATFORM, kind, "CREATE_DEFINE", tuple(lines), expected)


def plan(key):
    """-> (prerequisite statements, Configlet specs, postcheck requirements, expected facts).

    Configlets are the planner's own decomposition (``planning.configlet_factory``): an ``interface`` Configlet is the
    rendering of the interface without addresses, each ``address`` Configlet the differential of one address, and a
    ``static_route`` Configlet the differential of the route.  Whatever the sample's baseline holds is a prerequisite.
    """
    case = sample(PLATFORM, by_key()[key])
    sections, baseline = deepcopy(case.sections), deepcopy(case.baseline)
    prerequisites = _added(baseline, {**baseline, "interfaces": {}})
    if key.startswith("routing."):
        route = _added(sections, baseline)
        specs = [_spec(1, "static_route", route, dict(case.expected))]
        rows = [("route", "ROUTE_INTENDED", dict(case.expected))]
        return prerequisites, specs, _requirements(rows, device="srl"), dict(case.expected)
    iface = sections["interfaces"][IF]
    name = case.expected["interface"]
    others = {k: v for k, v in sections["interfaces"].items() if k != IF}
    stripped = {**iface, "addresses": {}}
    if others:
        # A pre-existing parent is rendered as the candidate renders it NEXT TO its child (an SR Linux tagged carrier
        # holds no untagged subinterface 0), not as it would render on its own.
        with_child = _added({**sections, "interfaces": {**others, IF: stripped}}, {**sections, "interfaces": {}})
        child = _added({**sections, "interfaces": {**others, IF: stripped}}, {**sections, "interfaces": others})
        prerequisites = [line for line in with_child if line not in child]
    specs = [_spec(1, "interface", _added({**sections, "interfaces": {**others, IF: stripped}}, {**sections, "interfaces": others}),
                   {"interface": name, "admin_enabled": True})]
    rows = [("interface", "INTERFACE_PRESENT", {"interface": name, "admin_enabled": True})]
    for n, address in enumerate(sorted(iface["addresses"].values(), key=lambda a: a["sequence"]), 2):
        one = {**sections, "interfaces": {**others, IF: {**iface, "addresses": {address["id"]: address}}}}
        facts = {"interface": name, "address": address["cidr"], "family": 6 if ":" in address["cidr"] else 4}
        specs.append(_spec(n, "address", _added(one, {**sections, "interfaces": {**others, IF: stripped}}), facts))
        rows.append((f"address-{n}", "ADDRESS_PRESENT", facts))
    return prerequisites, specs, _requirements(rows, device="srl"), {"interface": name, "kind": iface["kind"],
                                                                    "addresses": [a["cidr"] for a in iface["addresses"].values()]}


def imported(key, expected, tree) -> bool:
    """The live running configuration, imported by the operator parser, carries the semantic intent NMAS rendered."""
    parsed = parser_srlinux.parse(tree)
    if key.startswith("routing."):
        return any(r.destination == expected["prefix"] and r.next_hop_address == expected["next_hop"] for r in parsed.static_routes)
    row = next((i for i in parsed.interfaces if i.name == expected["interface"]), None)
    if row is None or row.kind != expected["kind"] or not {a["cidr"] for a in row.addresses} >= set(expected["addresses"]):
        return False
    return row.kind != "SUBINTERFACE" or (row.encapsulation_vlan == 44 and row.parent_name == PORT)


def _scenario(key, seed) -> dict:
    prerequisites, specs, requirements, expected = plan(key)
    peer_plan, reach = PLANS[key]
    netns = NETNS.get(key, "srbase-default")
    result = {"actions": [], "statuses": [], "detail": "", "failure": "", "imported": False, "control": False, "after": False}
    lab = SrlLab()
    try:
        lab.prepare_peer(peer_plan)
        lab.native(prerequisites)
        lab.native(seed)
        prepared_tree = lab.executor.config_tree()
        prepared = lab.executor.tree_digest(prepared_tree)
        # safety net only (never the claim): the lab's own undo of everything NMAS is about to send
        safety = model.inverse([op for spec in specs for op in model.operations(spec.lines)], prepared_tree)
        result["control"] = not any(lab.ping(target, netns) for target in reach)
        state = {}

        def verify():
            observed, post_ok, failed = _postcheck(lab.device, requirements, lab.session_factory)
            result["imported"] = imported(key, expected, lab.executor.config_tree())
            reached = {target: lab.ping(target, netns) for target in reach}
            oper = True
            if "interface" in expected:
                oper = ((observed.facts("interfaces") or {}).get(expected["interface"]) or {}).get("oper") == "UP"
            else:
                oper = any(r["prefix"] == live.norm_prefix(expected["prefix"]) and r["type"] == "static"
                           and live.norm_ip(expected["next_hop"]) in r["next_hops"] for r in observed.facts("routes") or [])
            state.update(read_ok=bool(observed.live_reachable), post_ok=post_ok)
            return post_ok and result["imported"] and oper and all(reached.values()), (
                f"operator postcheck over gNMI state pass={post_ok} {failed}; "
                f"{'interface oper-up' if 'interface' in expected else 'static route active in RIB with expected next hop'}={oper}; "
                f"live gNMI config import recovered intent={result['imported']}; pings from {netns} answered={reached}")

        result.update(_transaction(lab.executor, specs, verify, attempts=14))
        result.update(state)
        result["config_restored"] = lab.digest() == prepared
        result["after"] = not any(lab.ping(target, netns) for target in reach)
        if not result["config_restored"] and safety:        # never leave residue behind a failed claim
            lab.gnmi.set_cli(safety)
    except Exception as exc:
        result["failure"] = f"{type(exc).__name__}: {str(exc)[:500]}"
    finally:
        result["restored"] = lab.close()
    return result


def probe_srlinux(cell, key: str):
    _, specs, _, _ = plan(key)
    scenarios = {"pristine node": _scenario(key, ()), "configured node": _scenario(key, SEEDS[key])}
    reference = f"live:{LAB}/srl-{key.split('.')[1].lower()}/{timezone.now().isoformat()}"
    rendered = "; ".join(f"[{spec.object_type}] " + " / ".join(line.removeprefix("set ") for line in spec.lines) for spec in specs)
    text = " || ".join(
        f"{label}: preflight={r['actions']}; control before apply (no ping answered)={r['control']}; {r['detail']}; "
        f"compensation={r['statuses']}; running configuration identical to pre-apply capture={r.get('config_restored')}; "
        f"reachability gone after compensation={r['after']}; lab baseline restored={r.get('restored')}; "
        f"{r['failure'] or 'no failure'}" for label, r in scenarios.items())
    detail = (f"{NOTES.get(key, '')}isolated SR Linux {key} through the registered SrLinuxExecutor (atomic gNMI CLI-origin Set, gNMI Get "
              f"captured-tree inverse): NMAS rendered {rendered} || {text}")
    every = lambda *keys: all(r.get(k) for r in scenarios.values() for k in keys)   # noqa: E731
    for stage, ok, reason in (
        ("live_write", every("applied"), "FUNCTIONAL_TEST_FAILED"),
        ("live_read", every("read_ok"), "LIVE_READ_ABSENT"),
        ("live_post_write_validation", every("post_ok"), "POSTCHECK_ABSENT"),
        ("parser_import", every("imported"), "PARSER_ABSENT"),
        ("runtime_validation", every("verified", "control"), "FUNCTIONAL_TEST_FAILED"),
        ("compensation", every("compensated", "config_restored", "after", "restored"), "COMPENSATION_ABSENT"),
    ):
        cell.probes[stage] = assessment.probe("PASS" if ok else "FAIL", detail[:3900], reason="" if ok else reason,
                                              test_type="LIVE", reference=reference)
    cell.runtime_version = RUNTIME
    return scenarios


CELLS = tuple(PLANS)
