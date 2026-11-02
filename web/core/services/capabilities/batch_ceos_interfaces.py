"""Reversible cEOS interface probes on the isolated Ethernet2 <-> Linux peer eth2 link.

One recipe for ROUTED_PHYSICAL, ACCESS, TRUNK, SUBINTERFACE and SVI: lab prerequisites are applied natively, the
NMAS-rendered interface Configlets go through the registered cEOS executor in engine order (preflight all, apply,
compensate in reverse), behaviour is proven with pings from the device, and the running configuration must equal the
capture taken before NMAS wrote anything.  Ethernet2 is a port that already exists, so every probe exercises the
captured-section inverse rather than ``default interface``.
"""

from __future__ import annotations

import json
from copy import deepcopy

from django.utils import timezone

from ..config_import import parser_ceos
from ..execution.executors.ceos import CeosExecutor
from ..health import live
from . import assessment
from .batch_frr_routing import FrrPair, _call, _configlet, _postcheck, _requirements, _transaction
from .features import by_key
from .isolated_live import LAB, NETWORK, DockerEosConfigConnection, _run, _target
from .offline_verify import _descriptors
from .probe_cases import sample

PORT = "Ethernet2"
V4, V6 = ("198.18.0.1/30", "198.18.0.2/30"), ("2001:db8:44::1/64", "2001:db8:44::2/64")
# kind -> (native cEOS prerequisites, peer prerequisites, ping targets that must answer, targets that must NOT answer)
PLANS = {
    "ROUTED_PHYSICAL": ((), (("addr", "add", V4[1], "dev", "eth2"), ("-6", "addr", "add", V6[1], "dev", "eth2", "nodad")),
                        ("198.18.0.2", "ipv6 2001:db8:44::2"), ()),
    "ACCESS": (("vlan 44", "vlan 45", "interface Vlan44\nip address 198.18.44.1/24\nno shutdown",
                "interface Vlan45\nip address 198.18.45.1/24\nno shutdown"),
               (("addr", "add", "198.18.44.2/24", "dev", "eth2"), ("addr", "add", "198.18.45.2/24", "dev", "eth2")),
               ("198.18.44.2",), ("198.18.45.2",)),            # the peer is only in VLAN44: VLAN45 must stay isolated
    "TRUNK": (("vlan 44", "vlan 45", "interface Vlan44\nip address 198.18.44.1/24\nno shutdown",
               "interface Vlan45\nip address 198.18.45.1/24\nno shutdown"),
              (("addr", "add", "198.18.44.2/24", "dev", "eth2"),
               ("link", "add", "link", "eth2", "name", "eth2.45", "type", "vlan", "id", "45"),
               ("addr", "add", "198.18.45.2/24", "dev", "eth2.45"), ("link", "set", "dev", "eth2.45", "up")),
              ("198.18.44.2", "198.18.45.2"), ()),             # native VLAN44 untagged and VLAN45 tagged on one port
    "SUBINTERFACE": ((), (("link", "add", "link", "eth2", "name", "eth2.44", "type", "vlan", "id", "44"),
                          ("addr", "add", V4[1], "dev", "eth2.44"), ("-6", "addr", "add", V6[1], "dev", "eth2.44", "nodad"),
                          ("link", "set", "dev", "eth2.44", "up")),
                     ("198.18.0.2", "ipv6 2001:db8:44::2"), ()),
    "SVI": ((f"interface {PORT}\nswitchport mode access\nswitchport access vlan 44",),
            (("addr", "add", V4[1], "dev", "eth2"), ("-6", "addr", "add", V6[1], "dev", "eth2", "nodad")),
            ("198.18.0.2", "ipv6 2001:db8:44::2"), ()),
}
UNDO = {"vlan 44": "no vlan 44", "vlan 45": "no vlan 45", "interface Vlan44": "no interface Vlan44",
        "interface Vlan45": "no interface Vlan45", f"interface {PORT}": f"default interface {PORT}"}


class CeosPortLab:
    def __init__(self):
        self.device, _, _ = _target("arista_ceos")
        self.peer = f"clab-{LAB}-peer"
        (row,) = json.loads(_run(["docker", "inspect", self.peer], timeout=10).stdout or "[null]")
        if not row or row["Config"]["Labels"].get("containerlab") != LAB or NETWORK not in row["NetworkSettings"]["Networks"]:
            raise RuntimeError("Interface peer is outside the isolated lab.")
        self.executor = CeosExecutor(self.device, connection_factory=DockerEosConfigConnection, reader=live.read_device)
        self.executor.connect()
        self.baseline = self.executor._config_state_digest()
        self.peer_baseline = FrrPair.kernel(self.peer)
        text = self.executor._config_text()
        if "no ip routing" not in text or self.eos(f"show running-config interfaces {PORT}").strip().splitlines()[-1].strip() != f"interface {PORT}" \
                or any(token in text for token in ("vlan 44", "vlan 45", "interface Vlan4", f"interface {PORT}.")) \
                or '"family":"inet"' in _call(self.peer, "ip", "-j", "addr", "show", "dev", "eth2").stdout.replace(" ", ""):
            self.executor.close()
            raise RuntimeError("cEOS Ethernet2 / peer eth2 are not at the disposable baseline; refusing to write.")
        self.mtu = json.loads(_call(self.peer, "ip", "-j", "link", "show", "dev", "eth2").stdout)[0]["mtu"]
        self.ra = _call(self.peer, "sysctl", "-n", "net.ipv6.conf.eth2.accept_ra").stdout.strip()
        self.native, self.peer_links = [], []

    def eos(self, command, *, config=False, check=True):
        payload = f"configure terminal\n{command}" if config else command
        result = _run(["docker", "exec", self.device["container"], "Cli", "-p", "15", "-c", payload], timeout=60)
        if check and (result.returncode or "% Error" in result.stdout or "% Invalid input" in result.stdout):
            raise RuntimeError(f"Disposable cEOS command failed: {command[:60]}: {result.stdout[:160]}")
        return result.stdout

    def ping(self, target) -> bool:
        out = self.eos(f"ping {target} repeat 3", check=False)
        return " 0% packet loss" in out

    def prepare(self, kind):
        native, peer, _, _ = PLANS[kind]
        FrrPair.must(self.peer, "ip", "link", "set", "dev", "eth2", "mtu", "1500")
        FrrPair.must(self.peer, "sysctl", "-w", "net.ipv6.conf.eth2.accept_ra=0")
        for argv in peer:
            if argv[:2] == ("link", "add"):
                self.peer_links.append(argv[5])
            FrrPair.must(self.peer, "ip", *argv)
        for command in ("ip routing", "ipv6 unicast-routing", *native):
            self.native.append(command)
            self.eos(command, config=True)

    def close(self) -> bool:
        try:
            for command in reversed(self.native):
                head = command.splitlines()[0]
                self.eos(UNDO.get(head, f"no {head}"), config=True, check=False)
            for name in self.peer_links:
                _call(self.peer, "ip", "link", "delete", name)
            _call(self.peer, "ip", "addr", "flush", "dev", "eth2", "scope", "global")
            _call(self.peer, "ip", "link", "set", "dev", "eth2", "mtu", str(self.mtu))
            _call(self.peer, "sysctl", "-w", f"net.ipv6.conf.eth2.accept_ra={self.ra}")
            restored = self.executor._config_state_digest() == self.baseline and FrrPair.kernel(self.peer) == self.peer_baseline
        finally:
            self.executor.close()
        if not restored:
            raise RuntimeError("Isolated cEOS port lab was not restored to its captured baseline.")
        return True


def _plan(kind):
    """NMAS-rendered Configlets in the planner's decomposition: (parent,) interface, then one Configlet per address."""
    case = sample("arista_ceos", by_key()[f"interface.{kind}"])
    sections = deepcopy(case.sections)
    for interface in sections["interfaces"].values():
        interface["name"] = interface["name"].replace("Ethernet1", PORT)
    name = case.expected["interface"].replace("Ethernet1", PORT)
    rendered = [line for line in _descriptors("arista_ceos", sections) if line.strip() and not line.lstrip().startswith("!")]
    blocks, current = [], None
    for line in rendered:
        if not line.startswith(" "):
            current = [line]
            blocks.append(current)
        else:
            current.append(line)
    wanted = [b for b in blocks if b[0] in (f"interface {name}", "vlan 44") or (kind == "SUBINTERFACE" and b[0] == f"interface {PORT}")]
    specs, n = [], 0
    target = next(b for b in wanted if b[0] == f"interface {name}")
    is_address = lambda line: line.strip().startswith(("ip address ", "ipv6 address "))   # noqa: E731
    for block in wanted:
        if block is target or len(block) == 1 and block[0] != "vlan 44":
            continue
        if block[0] == "vlan 44":
            continue
        n += 1                                              # the pre-existing physical parent of a subinterface
        specs.append(_configlet(n, "interface", block, {"interface": block[0].split()[1], "admin_enabled": True}))
    n += 1
    lead = [b[0] for b in wanted if b[0] == "vlan 44"]
    specs.append(_configlet(n, "interface", [*lead, target[0], *(line for line in target[1:] if not is_address(line))],
                            {"interface": name, "admin_enabled": True}))
    addresses = [line.strip().split()[2] for line in target[1:] if is_address(line)]
    for line in (line for line in target[1:] if is_address(line)):
        n += 1
        cidr = line.strip().split()[2]
        specs.append(_configlet(n, "address", [target[0], line],
                                {"interface": name, "address": cidr, "family": 6 if ":" in cidr else 4}))
    rows = [("interface", "INTERFACE_PRESENT", {"interface": name, "admin_enabled": True})]
    rows += [(f"address-{i}", "ADDRESS_PRESENT", {"interface": name, "address": cidr, "family": 6 if ":" in cidr else 4})
             for i, cidr in enumerate(addresses)]
    return name, specs, _requirements(rows, device="ceos")


def _imported(kind, name, text) -> bool:
    row = next((i for i in parser_ceos.parse(text).interfaces if i.name == name), None)
    if row is None or row.kind != kind:
        return False
    if kind == "ACCESS":
        return row.access_vlan == 44
    if kind == "TRUNK":
        return row.trunk_allowed_vlans == [44, 45] and row.native_vlan == 44
    if kind == "SUBINTERFACE":
        return row.encapsulation_vlan == 44 and row.parent_name == PORT
    return {a["cidr"] for a in row.addresses} >= {V4[0], V6[0]}


# A port that is NOT pristine: replaced values, a mode the Configlet leaves, and a line NMAS does not model.
_L2 = ("vlan 45", f"interface {PORT}\ndescription legacy uplink\nload-interval 30\nswitchport access vlan 45")
_L3 = (f"interface {PORT}\ndescription legacy uplink\nload-interval 30\nno switchport\nip address 198.18.7.1/24\n"
       "ipv6 address 2001:db8:7::1/64",)
SEEDS = {"ROUTED_PHYSICAL": _L2, "SUBINTERFACE": _L2, "ACCESS": _L3, "TRUNK": _L3}


def _scenario(kind, seed) -> dict:
    name, specs, requirements = _plan(kind)
    _, _, reach, isolated = PLANS[kind]
    result = {"actions": [], "statuses": [], "detail": "", "failure": "", "imported": False, "control": False, "after": False}
    lab = CeosPortLab()
    try:
        for command in seed:
            if command not in lab.native and command not in PLANS[kind][0]:
                lab.native.append(command)
                lab.eos(command, config=True)
        lab.prepare(kind)
        prepared = lab.executor._config_state_digest()
        section = lab.eos(f"show running-config interfaces {PORT}").strip()
        result["section"] = [line.strip() for line in section.splitlines()[1:] if line.strip() and not line.startswith(("interface", "!"))]
        result["control"] = not any(lab.ping(target) for target in reach)
        state = {}

        def verify():
            observed, post_ok, failed = _postcheck(lab.device, requirements)
            result["imported"] = _imported(kind, name, lab.executor._config_text())
            reached = {target: lab.ping(target) for target in reach}
            blocked = {target: not lab.ping(target) for target in isolated}
            state.update(read_ok=bool(observed.live_reachable), post_ok=post_ok)
            return post_ok and result["imported"] and all(reached.values()) and all(blocked.values()), (
                f"operator postcheck pass={post_ok} {failed}; live import recovered {kind} {name}={result['imported']}; "
                f"pings from cEOS answered={reached}; wrong-VLAN targets isolated={blocked}")

        result.update(_transaction(lab.executor, specs, verify, attempts=12))
        result.update(state)
        result["config_restored"] = lab.executor._config_state_digest() == prepared
        result["section_restored"] = lab.eos(f"show running-config interfaces {PORT}").strip() == section
        result["after"] = not any(lab.ping(target) for target in reach)
        if not result["config_restored"]:   # never leave residue: native removal before the lab baseline check
            for spec in reversed(specs):
                for line in (line for line in spec.lines if not line.startswith(" ")):
                    lab.eos(UNDO.get(line, f"no {line}"), config=True, check=False)
    except Exception as exc:
        result["failure"] = f"{type(exc).__name__}: {str(exc)[:500]}"
    finally:
        result["restored"] = lab.close()
    return result


def probe_ceos_interface(cell, kind: str):
    name, specs, _ = _plan(kind)
    scenarios = {"pristine port": _scenario(kind, ())}
    if kind in SEEDS:
        scenarios["configured port"] = _scenario(kind, SEEDS[kind])
    reference = f"live:{LAB}/ceos-{kind.lower()}/{timezone.now().isoformat()}"
    rendered = "; ".join(f"[{spec.object_type}] " + " / ".join(line.strip() for line in spec.lines) for spec in specs)
    text = " || ".join(
        f"{label}: {PORT} before NMAS={r.get('section')}; preflight={r['actions']}; control before apply (no ping answered)="
        f"{r['control']}; {r['detail']}; compensation={r['statuses']}; running-config identical to pre-apply capture="
        f"{r.get('config_restored')}; {PORT} section identical={r.get('section_restored')}; reachability gone after "
        f"compensation={r['after']}; lab baseline restored={r.get('restored')}; {r['failure'] or 'no failure'}"
        for label, r in scenarios.items())
    detail = f"isolated cEOS {kind} on pre-existing {PORT}: NMAS rendered {rendered} || {text}"
    every = lambda *keys: all(r.get(key) for r in scenarios.values() for key in keys)   # noqa: E731
    for stage, ok, reason in (
        ("live_write", every("applied"), "FUNCTIONAL_TEST_FAILED"),
        ("live_read", every("read_ok"), "LIVE_READ_ABSENT"),
        ("live_post_write_validation", every("post_ok"), "POSTCHECK_ABSENT"),
        ("parser_import", every("imported"), "PARSER_ABSENT"),
        ("runtime_validation", every("verified", "control"), "FUNCTIONAL_TEST_FAILED"),
        ("compensation", every("compensated", "config_restored", "section_restored", "after", "restored"), "COMPENSATION_ABSENT"),
    ):
        cell.probes[stage] = assessment.probe("PASS" if ok else "FAIL", detail[:3900], reason="" if ok else reason,
                                              test_type="LIVE", reference=reference)
    cell.runtime_version = "ceos:4.36.2F / Linux peer"
