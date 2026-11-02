"""Reversible IOS XE probes on the isolated Catalyst 8000V (GigabitEthernet2 <-> Linux peer eth1).

Same contract as the SR Linux and cEOS probes: lab prerequisites are native and never part of the claim; the
NMAS-rendered Configlets -- split by the planner's own differential rendering -- go through the registered
``IosXeExecutor`` in engine order (preflight all, apply, verify, compensate in reverse).  Verification is the operator
postcheck over allowlisted ``show`` output, a live import through ``parser_iosxe`` and pings from the router.  Each cell
runs on a pristine router and on one that already holds related configuration, and the running configuration must
equal the capture taken before NMAS wrote anything.  IOS XE evidence is never reused for IOS XR.
"""

from __future__ import annotations

import json
import os
from copy import deepcopy

from django.utils import timezone

from .. import platform_drivers
from ..config_import import parser_iosxe
from ..execution.executors import iosxe
from ..execution.executors.base import ConfigletSpec
from ..health import live
from ..planning import snippets
from . import assessment
from .batch_frr_routing import FrrPair, _call, _postcheck, _requirements, _transaction
from .features import by_key
from .isolated_live import _iosxe_target, _run
from .probe_cases import IF, sample

PLATFORM, LAB, PORT, PEER_DEV, DUMMY = "cisco_c8000v_iosxe", "nmas-cap-iosxe", "GigabitEthernet2", "eth1", "nmascap2"
RUNTIME = "vrnetlab/cisco_c8000v:17.06.01a (IOS XE 17.06.01a) / Linux peer"
V4, V6 = "198.18.0.2/30", "2001:db8:44::2/64"
_LINK = (("addr", "add", V4, "dev", PEER_DEV), ("-6", "addr", "add", V6, "dev", PEER_DEV, "nodad"))
_VLAN = (("link", "add", "link", PEER_DEV, "name", f"{PEER_DEV}.44", "type", "vlan", "id", "44"),
         ("addr", "add", V4, "dev", f"{PEER_DEV}.44"), ("-6", "addr", "add", V6, "dev", f"{PEER_DEV}.44", "nodad"),
         ("link", "set", "dev", f"{PEER_DEV}.44", "up"))
_FAR = (("link", "add", DUMMY, "type", "dummy"), ("link", "set", "dev", DUMMY, "up"),
        ("addr", "add", "203.0.113.1/24", "dev", DUMMY), ("-6", "addr", "add", "2001:db8:113::1/64", "dev", DUMMY, "nodad"))
PLANS = {
    "interface.LOOPBACK": ((), ("198.18.0.1", "2001:db8:44::1")),
    "interface.MANAGEMENT": ((), ()),          # expected to be refused at preflight: see NOTES
    "interface.ROUTED_PHYSICAL": (_LINK, ("198.18.0.2", "2001:db8:44::2")),
    "interface.SUBINTERFACE": (_VLAN, ("198.18.0.2", "2001:db8:44::2")),
    "routing.STATIC_IPV4": ((*_LINK, *_FAR), ("203.0.113.1",)),
    "routing.STATIC_IPV6": ((*_LINK, *_FAR), ("2001:db8:113::1",)),
}
# The "configured router" scenario: a replaced value, addresses / routes NMAS must preserve, and a line it does not model.
NOTES = {"interface.MANAGEMENT": "GigabitEthernet1 carries the SSH session NMAS manages this router through, and an IOS XE "
                                 "'ip address' replaces the primary address in place; the executor therefore refuses the "
                                 "Configlet at preflight (MANAGEMENT_SESSION_AT_RISK) and nothing is written. "}
SEEDS = {
    "interface.MANAGEMENT": (),
    "interface.LOOPBACK": ("interface Loopback44", " description legacy loopback", " ip address 198.18.7.1 255.255.255.255"),
    "interface.ROUTED_PHYSICAL": (f"interface {PORT}", " description legacy uplink", " load-interval 30",
                                  " ip address 198.18.7.1 255.255.255.0", " ipv6 address 2001:db8:7::1/64", " no shutdown"),
    "interface.SUBINTERFACE": (f"interface {PORT}.45", " encapsulation dot1Q 45", " ip address 198.18.45.1 255.255.255.0"),
    "routing.STATIC_IPV4": ("ip route 192.0.2.0 255.255.255.0 198.18.0.2",),
    "routing.STATIC_IPV6": ("ipv6 route 2001:db8:99::/64 2001:db8:44::2",),
}


class IosxeLab:
    """The isolated Catalyst 8000V and its Linux peer, verified by identity and restored exactly on ``close``."""

    def __init__(self):
        host = _iosxe_target()
        password = os.environ.get("NMAS_CAP_IOSXE_PASSWORD", "")
        if not password:
            raise RuntimeError("NMAS_CAP_IOSXE_PASSWORD is required for the isolated IOS XE router (never persisted).")
        self.peer = f"clab-{LAB}-peer"
        (row,) = json.loads(_run(["docker", "inspect", self.peer], timeout=10).stdout or "[null]")
        if not row or row["Config"]["Labels"].get("containerlab") != LAB or not row["State"]["Running"]:
            raise RuntimeError("IOS XE peer is outside the isolated lab.")
        from netmiko import ConnectHandler

        self.conn = ConnectHandler(device_type="cisco_xe", host=host, username=os.environ.get("NMAS_CAP_IOSXE_USERNAME", "admin"),
                                   password=password, secret=password, conn_timeout=20, auth_timeout=20, banner_timeout=20)
        self.device = {"name": "iosxe", "platform": PLATFORM}
        self.executor = iosxe.IosXeExecutor(self.device, connection_factory=lambda _device: self.conn)
        self.executor.connect()
        self.session_factory = lambda device: live.IosXeSession(device, conn=self.conn)
        text = self.executor._config_text()
        section = [line.strip() for line in self.show(f"show running-config interface {PORT}").splitlines()]
        if "17.06.01a" not in self.show("show version | include IOS XE Software") or "shutdown" not in section \
                or "no ip address" not in section or any(marker in text.lower() for marker in ("interface loopback44", f"interface {PORT.lower()}.", "ip route 203.0.113.0",
                                                            "ip route 192.0.2.0", "ipv6 route 2001:db8:113::", "ipv6 route 2001:db8:99::")) \
                or '"family":"inet"' in _call(self.peer, "ip", "-j", "addr", "show", "dev", PEER_DEV).stdout.replace(" ", ""):
            self.conn.disconnect()
            raise RuntimeError("IOS XE router / peer eth1 are not at the disposable baseline; refusing to write.")
        self.baseline, self.peer_baseline = self.executor.running_config_digest(), FrrPair.kernel(self.peer)
        self.ra = _call(self.peer, "sysctl", "-n", f"net.ipv6.conf.{PEER_DEV}.accept_ra").stdout.strip()
        self.undo, self.peer_links = [], []

    def show(self, command) -> str:
        return self.conn.send_command(command, read_timeout=60)

    def native(self, lines) -> None:
        """Lab prerequisite written directly (never an NMAS claim); its exact undo is derived from the config it found."""
        lines = [line for line in lines if line.strip() and not line.lstrip().startswith("!")]
        if not lines:
            return
        inverse = iosxe.config_inverse(lines, self.executor._config_text())
        output = self.conn.send_config_set([line.strip() for line in lines], read_timeout=90)
        if inverse is None or any(marker in output for marker in iosxe.REJECTIONS):
            raise RuntimeError("Native IOS XE lab prerequisite was rejected or is not invertible.")
        self.undo.append(inverse)

    def prepare_peer(self, plan) -> None:
        FrrPair.must(self.peer, "sysctl", "-w", f"net.ipv6.conf.{PEER_DEV}.accept_ra=0")
        for argv in plan:
            if argv[:2] == ("link", "add"):
                self.peer_links.append(argv[2] if argv[2] != "link" else argv[5])
            FrrPair.must(self.peer, "ip", *argv)

    def ping(self, target) -> bool:
        """Five echoes from the router's global table; the first may be lost to ARP/ND resolution."""
        return self.show(f"ping {target} repeat 5 timeout 1").count("!") >= 3

    def close(self) -> bool:
        restored = False
        try:
            for inverse in reversed(self.undo):
                if inverse:
                    self.conn.send_config_set([line.strip() for line in inverse], read_timeout=90)
            for name in self.peer_links:
                _call(self.peer, "ip", "link", "delete", name)
            _call(self.peer, "ip", "addr", "flush", "dev", PEER_DEV, "scope", "global")
            _call(self.peer, "sysctl", "-w", f"net.ipv6.conf.{PEER_DEV}.accept_ra={self.ra}")
            restored = self.executor.running_config_digest() == self.baseline and FrrPair.kernel(self.peer) == self.peer_baseline
        finally:
            self.executor.close()
        if not restored:
            raise RuntimeError("Isolated IOS XE lab was not restored to its captured baseline.")
        return True


def _render(sections) -> list[str]:
    return snippets.render_lines(platform_drivers.get_driver(PLATFORM), {"device.hostname": "CAPDUT", "device.description": ""},
                                 interfaces=list(sections.get("interfaces", {}).values()), routing=sections.get("routing", {}),
                                 phase12={k: sections.get(k, {}) for k in ("fhrp", "nat", "services", "security", "policy")})


def _added(after, before) -> list[str]:
    return snippets.deployable(snippets.added_lines(_render(before), _render(after)))


def _spec(n, kind, lines, expected):
    return ConfigletSpec(f"P4-XE-{kind}-{n}", n, "iosxe", PLATFORM, kind, "CREATE_DEFINE", tuple(lines), expected)


def plan(key):
    """-> (prerequisite lines, Configlet specs, postcheck requirements, expected facts), decomposed as the planner does."""
    case = sample(PLATFORM, by_key()[key])
    sections, baseline = deepcopy(case.sections), deepcopy(case.baseline)
    prerequisites = _added(baseline, {**baseline, "interfaces": {}})
    if key.startswith("routing."):
        specs = [_spec(1, "static_route", _added(sections, baseline), dict(case.expected))]
        return prerequisites, specs, _requirements([("route", "ROUTE_INTENDED", dict(case.expected))], device="iosxe"), dict(case.expected)
    iface, name = sections["interfaces"][IF], case.expected["interface"]
    others = {k: v for k, v in sections["interfaces"].items() if k != IF}
    stripped = {**iface, "addresses": {}}
    with_stripped = {**sections, "interfaces": {**others, IF: stripped}}
    specs = [_spec(1, "interface", _added(with_stripped, {**sections, "interfaces": others}), {"interface": name, "admin_enabled": True})]
    rows = [("interface", "INTERFACE_PRESENT", {"interface": name, "admin_enabled": True})]
    for n, address in enumerate(sorted(iface["addresses"].values(), key=lambda a: a["sequence"]), 2):
        one = {**sections, "interfaces": {**others, IF: {**iface, "addresses": {address["id"]: address}}}}
        facts = {"interface": name, "address": address["cidr"], "family": 6 if ":" in address["cidr"] else 4}
        specs.append(_spec(n, "address", _added(one, with_stripped), facts))
        rows.append((f"address-{n}", "ADDRESS_PRESENT", facts))
    return prerequisites, specs, _requirements(rows, device="iosxe"), {
        "interface": name, "kind": iface["kind"], "addresses": [a["cidr"] for a in iface["addresses"].values()]}


def imported(key, expected, text) -> bool:
    """The live running configuration, imported by the operator parser, carries the semantic intent NMAS rendered."""
    parsed = parser_iosxe.parse(text)
    if key.startswith("routing."):
        return any(live.norm_prefix(r.destination) == live.norm_prefix(expected["prefix"])
                   and live.norm_ip(r.next_hop_address) == live.norm_ip(expected["next_hop"]) for r in parsed.static_routes)
    row = next((i for i in parsed.interfaces if i.name == expected["interface"]), None)
    if row is None or row.kind != expected["kind"]:
        return False
    held = {live.norm_cidr(a["cidr"]) for a in row.addresses}
    return held >= {live.norm_cidr(c) for c in expected["addresses"]} and (
        row.kind != "SUBINTERFACE" or (row.encapsulation_vlan == 44 and row.parent_name == PORT))


def _scenario(key, seed) -> dict:
    prerequisites, specs, requirements, expected = plan(key)
    peer_plan, reach = PLANS[key]
    result = {"actions": [], "statuses": [], "detail": "", "failure": "", "imported": False, "control": False, "after": False}
    lab = IosxeLab()
    try:
        lab.prepare_peer(peer_plan)
        lab.native(prerequisites)
        lab.native(seed)
        prepared_text = lab.executor._config_text()
        prepared = lab.executor.running_config_digest()
        # safety net only (never the claim): the lab's own undo of everything NMAS is about to send
        safety = iosxe.config_inverse([line for spec in specs for line in spec.lines], prepared_text)
        result["control"] = not any(lab.ping(target) for target in reach)
        state = {}

        def verify():
            observed, post_ok, failed = _postcheck(lab.device, requirements, lab.session_factory)
            result["imported"] = imported(key, expected, lab.executor._config_text())
            reached = {target: lab.ping(target) for target in reach}
            if "interface" in expected:
                up = ((observed.facts("interfaces") or {}).get(expected["interface"]) or {}).get("oper") == "UP"
            else:
                up = any(r["prefix"] == live.norm_prefix(expected["prefix"]) and r["type"] == "static"
                         and live.norm_ip(expected["next_hop"]) in r["next_hops"] for r in observed.facts("routes") or [])
            state.update(read_ok=bool(observed.live_reachable), post_ok=post_ok)
            return post_ok and result["imported"] and up and all(reached.values()), (
                f"operator postcheck over show-command state pass={post_ok} {failed}; "
                f"{'interface line protocol up' if 'interface' in expected else 'static route in RIB with expected next hop'}={up}; "
                f"live running-config import recovered intent={result['imported']}; pings from the router answered={reached}")

        result.update(_transaction(lab.executor, specs, verify, attempts=10))
        result.update(state)
        result["config_restored"] = lab.executor.running_config_digest() == prepared
        result["after"] = not any(lab.ping(target) for target in reach)
        if not result["config_restored"] and safety:        # never leave residue behind a failed claim
            lab.conn.send_config_set([line.strip() for line in safety], read_timeout=90)
    except Exception as exc:
        result["failure"] = f"{type(exc).__name__}: {str(exc)[:500]}"
    finally:
        result["restored"] = lab.close()
    return result


def probe_iosxe(cell, key: str):
    _, specs, _, _ = plan(key)
    scenarios = {"pristine router": _scenario(key, ())}
    if SEEDS[key]:
        scenarios["configured router"] = _scenario(key, SEEDS[key])
    reference = f"live:{LAB}/iosxe-{key.split('.')[1].lower()}/{timezone.now().isoformat()}"
    rendered = "; ".join(f"[{spec.object_type}] " + " / ".join(line.strip() for line in spec.lines) for spec in specs)
    text = " || ".join(
        f"{label}: preflight={r['actions']}; control before apply (no ping answered)={r['control']}; {r['detail']}; "
        f"compensation={r['statuses']}; running configuration identical to pre-apply capture={r.get('config_restored')}; "
        f"reachability gone after compensation={r['after']}; lab baseline restored={r.get('restored')}; "
        f"{r['failure'] or 'no failure'}" for label, r in scenarios.items())
    detail = (f"{NOTES.get(key, '')}isolated IOS XE {key} through the registered IosXeExecutor (Netmiko configuration mode, captured "
              f"running-config inverse): NMAS rendered {rendered} || {text}")
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
