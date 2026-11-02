"""Reversible routing probes: OSPF against the isolated cEOS, BGP and RIP/RIPng against the isolated FRR peer."""

from __future__ import annotations

import json
import time

from django.utils import timezone

from ..execution.executors.base import APPLY, ConfigletSpec
from ..execution.executors.ceos import CeosExecutor
from ..execution.executors.linux import LinuxExecutor
from ..health import live
from . import assessment
from .features import by_key
from .isolated_live import LAB, NETWORK, DockerEosConfigConnection, _run, _target
from .offline_verify import _descriptors
from .probe_cases import sample


def _peer() -> dict:
    device, _, _ = _target("arista_ceos")
    inspected = _run(["docker", "inspect", device["container"]], timeout=10)
    (row,) = json.loads(inspected.stdout)
    if row["Config"]["Labels"].get("containerlab") != LAB or NETWORK not in row["NetworkSettings"]["Networks"]:
        raise RuntimeError("OSPF peer is outside the isolated lab.")
    return device


def _call(container, *args):
    return _run(["docker", "exec", container, *args], timeout=45)


def _frr_link(container):
    result = _call(container, "ip", "-j", "addr", "show", "dev", "eth1")
    if result.returncode:
        raise RuntimeError("Disposable FRR eth1 cannot be read.")
    (row,) = json.loads(result.stdout)
    return {"mtu": row["mtu"], "flags": row["flags"],
            "addresses": sorted((a["family"], a["local"], a["prefixlen"]) for a in row["addr_info"])}


def _spec(version):
    case = sample("ubuntu_frr", by_key()[f"routing.{version}"])
    rendered = _descriptors("ubuntu_frr", case.sections)
    process = "router ospf6" if version == "OSPFV3" else "router ospf"
    start = rendered.index("interface eth1")
    interface_lines = [rendered[start]]
    for line in rendered[start + 1:]:
        if not line.startswith(" "):
            break
        interface_lines.append(line)
    start = rendered.index(process)
    process_lines = [rendered[start]]
    for line in rendered[start + 1:]:
        if not line.startswith(" "):
            break
        process_lines.append(line)
    return ConfigletSpec(f"P4-FRR-{version}", 1, "frr", "ubuntu_frr", "routing_ospf", "CREATE_DEFINE",
                         tuple(interface_lines + process_lines), {"version": version, "interface": "eth1"})


def probe_ospf(cell, version: str):
    v6 = version == "OSPFV3"
    target, _, _ = _target("ubuntu_frr")
    peer = _peer()
    fc, ec = target["container"], peer["container"]
    baseline_link = _frr_link(fc)
    eos = CeosExecutor(peer, connection_factory=DockerEosConfigConnection, reader=live.read_device)
    eos.connect()
    baseline_eos = eos._config_state_digest()
    if any(a[0] == ("inet6" if v6 else "inet") and (not v6 or not a[1].startswith("fe80:"))
           for a in baseline_link["addresses"]):
        eos.close()
        raise RuntimeError("Disposable FRR peer link already has a global address.")
    if eos._config_text().find("no ip routing") < 0 or eos._config_text().find("router ospf") >= 0:
        eos.close()
        raise RuntimeError("Disposable cEOS OSPF baseline is not pristine.")
    spec = _spec(version)
    executor = LinuxExecutor(target)
    address = "2001:db8:44::1/64" if v6 else "198.18.0.1/30"
    peer_address = "2001:db8:44::2/64" if v6 else "198.18.0.2/30"
    daemon = "ospf6d" if v6 else "ospfd"
    other_daemon = "ospfd" if v6 else "ospf6d"
    configured = started = extra_started = zebra = addressed = mtu_changed = peer_ready = applied = ra_changed = False
    ra_before = ""
    preflight = None
    read_ok = post_ok = runtime_ok = compensated = False
    failure = ""
    try:
        if _call(fc, "ip", "link", "set", "dev", "eth1", "mtu", "1500").returncode:
            raise RuntimeError("FRR OSPF MTU setup failed.")
        mtu_changed = True
        if v6:
            ra = _call(fc, "sysctl", "-n", "net.ipv6.conf.eth1.accept_ra")
            if ra.returncode or ra.stdout.strip() not in {"0", "1", "2"}:
                raise RuntimeError("FRR OSPFv3 RA setting could not be captured.")
            ra_before = ra.stdout.strip()
            if ra_before != "0":
                if _call(fc, "sysctl", "-w", "net.ipv6.conf.eth1.accept_ra=0").returncode:
                    raise RuntimeError("FRR OSPFv3 RA suppression failed.")
                ra_changed = True
        if _call(fc, "ip", "addr", "add", address, "dev", "eth1").returncode:
            raise RuntimeError("FRR OSPF address setup failed.")
        addressed = True
        peer_lines = ("ipv6 unicast-routing\ninterface Ethernet1\nno switchport\nipv6 address " + peer_address +
                      "\nno shutdown\nipv6 router ospf 45\nrouter-id 198.18.44.2\ninterface Ethernet1\nipv6 ospf 45 area 0\nipv6 ospf network point-to-point") if v6 else (
                      "ip routing\ninterface Ethernet1\nno switchport\nip address " + peer_address +
                      "\nno shutdown\nrouter ospf 45\nrouter-id 198.18.44.2\nnetwork 198.18.0.0/30 area 0\ninterface Ethernet1\nip ospf area 0\nip ospf network point-to-point")
        sent = _call(ec, "Cli", "-p", "15", "--abort-on-error", "-c", "configure terminal\n" + peer_lines)
        peer_ready = True
        if sent.returncode or "% Error" in sent.stdout or "% Invalid input" in sent.stdout:
            raise RuntimeError("Disposable cEOS OSPF peer rejected setup.")
        if _call(fc, "/usr/lib/frr/zebra", "-d", "-u", "frr", "-g", "frr", "-A", "127.0.0.1").returncode:
            raise RuntimeError("FRR zebra failed to start.")
        zebra = True
        if _call(fc, f"/usr/lib/frr/{daemon}", "-d", "-u", "frr", "-g", "frr", "-A", "127.0.0.1").returncode:
            raise RuntimeError("FRR OSPF daemon failed to start.")
        started = True
        if _call(fc, f"/usr/lib/frr/{other_daemon}", "-d", "-u", "frr", "-g", "frr", "-A", "127.0.0.1").returncode:
            raise RuntimeError("FRR auxiliary OSPF read daemon failed to start.")
        extra_started = True
        executor.connect()
        preflight = executor.assess(spec)
        if preflight.action != APPLY or not preflight.restorable:
            from ..execution.executors.linux import frr_routing_inverse
            raise RuntimeError(f"FRR executor cannot prove a safe OSPF inverse: reason={preflight.reason}, "
                               f"inverse={frr_routing_inverse(spec.lines, executor._routing_config())}, "
                               f"config={executor._routing_config()[-900:]!r}.")
        configured = True
        outcome = executor.apply(spec, preflight)
        if not outcome.ok:
            raise RuntimeError(f"FRR OSPF vtysh apply failed: {outcome.error_code}.")
        applied = True
        for attempt in range(16):
            observed = live.read_device(target)
            read_ok = observed.live_reachable
            runtime_ok = any(n.get("family") == version and n.get("interface") == "eth1" and n.get("state") == "FULL"
                             for n in observed.facts("ospf") or [])
            row = next((r for r in observed.facts("routing_config") or []
                        if r["protocol"] == "ospf" and r["version"] == version), None)
            post_ok = bool(row and row["router_id"] == "198.18.44.1" and
                           any(b.get("interface_name") == "eth1" and b.get("area") == "0"
                               for b in row["bindings"]))
            if runtime_ok and post_ok:
                break
            if attempt < 15:
                time.sleep(1)
        if not (runtime_ok and post_ok):
            frr_neighbors = _call(fc, "vtysh", "-c", "show ipv6 ospf6 neighbor" if v6 else "show ip ospf neighbor")
            eos_neighbors = _call(ec, "Cli", "-p", "15", "-c", "show ipv6 ospf neighbor" if v6 else "show ip ospf neighbor")
            failure = (f"OSPF state: FULL={runtime_ok}, semantic config={post_ok}; "
                       f"FRR={frr_neighbors.stdout[:350]!r}; cEOS={eos_neighbors.stdout[:350]!r}; "
                       f"rows={(observed.facts('routing_config') or [])[:1]!r}.")
    except Exception as exc:
        failure = f"{type(exc).__name__}: {str(exc)[:1000]}"
    finally:
        if configured and preflight:
            compensated = executor.compensate(spec, preflight).status == "COMPENSATED"
        if not compensated and configured:
            _call(fc, "vtysh", "-c", "configure terminal", "-c", "no router ospf6" if v6 else "no router ospf")
            _call(fc, "vtysh", "-c", "configure terminal", "-c", "no interface eth1")
        executor.close()
        if started:
            _call(fc, "sh", "-c", f"pkill -x {daemon}")
        if extra_started:
            _call(fc, "sh", "-c", f"pkill -x {other_daemon}")
        if zebra:
            _call(fc, "sh", "-c", "pkill -x zebra")
        if peer_ready:
            reset = _call(ec, "Cli", "-p", "15", "--abort-on-error", "-c",
                          "configure terminal\n" + ("no ipv6 router ospf 45\n" if v6 else "no router ospf 45\n") +
                          "default interface Ethernet1\n" + ("no ipv6 unicast-routing" if v6 else "no ip routing"))
            if reset.returncode:
                raise RuntimeError("Disposable cEOS OSPF peer could not be restored.")
        if addressed and _call(fc, "ip", "addr", "del", address, "dev", "eth1").returncode:
            raise RuntimeError("Disposable FRR OSPF address could not be restored.")
        if ra_changed and _call(fc, "sysctl", "-w", f"net.ipv6.conf.eth1.accept_ra={ra_before}").returncode:
            raise RuntimeError("Disposable FRR OSPF RA setting could not be restored.")
        if mtu_changed and _call(fc, "ip", "link", "set", "dev", "eth1", "mtu", str(baseline_link["mtu"])).returncode:
            raise RuntimeError("Disposable FRR OSPF MTU could not be restored.")
        restored = _frr_link(fc) == baseline_link and eos._config_state_digest() == baseline_eos
        eos.close()
        if not restored:
            raise RuntimeError("Disposable OSPF pair did not return to its captured baseline.")
    reference = f"live:{LAB}/frr-{version.lower()}/{timezone.now().isoformat()}"
    detail = f"isolated FRR {version}: rendered={list(spec.lines)}; FULL={runtime_ok}; semantic={post_ok}; NMAS compensation={compensated}; exact pair restoration={restored}; {failure or 'no failure'}"
    for name, ok, reason in (
        ("live_write", applied, "FUNCTIONAL_TEST_FAILED"),
        ("live_read", read_ok, "LIVE_READ_ABSENT"),
        ("live_post_write_validation", post_ok, "POSTCHECK_ABSENT"),
        ("runtime_validation", runtime_ok, "FUNCTIONAL_TEST_FAILED"),
        ("compensation", compensated, "COMPENSATION_ABSENT"),
    ):
        cell.probes[name] = assessment.probe("PASS" if ok else "FAIL", detail,
                                             reason="" if ok else reason, test_type="LIVE", reference=reference)
    cell.runtime_version = "FRRouting 8.4.4 / cEOS 4.36.2F isolated pair"


# --- BGP and RIP/RIPng against the disposable FRR peer (DUT eth3 <-> peer eth1) ----------------------------------------
PAIR_LINK = (("198.18.0.1/30", "198.18.0.2/30"), ("2001:db8:44::1/64", "2001:db8:44::2/64"))
DUMMY = "nmascap0"                                    # carries the prefix each side originates; lab prerequisite only
ORIGIN = {"dut": {"IPV4": "203.0.113.1/24", "IPV6": "2001:db8:113::1/64"},
          "peer": {"IPV4": "198.51.100.1/24", "IPV6": "2001:db8:114::1/64"}}
PEER_NET = {"IPV4": "198.51.100.0/24", "IPV6": "2001:db8:114::/64"}
UNRELATED = ("neighbor 198.18.9.9 remote-as 65099", "network 192.0.2.0/24")   # pre-existing BGP objects NMAS must preserve


class FrrPair:
    """The two disposable FRR containers, prepared for one protocol family and restored exactly on exit.

    NMAS never manages daemon lifecycle or the peer: addresses, the originating dummy interfaces, the FRR daemons and the
    whole peer configuration are lab prerequisites applied natively here and reverted in ``close``.
    """

    def __init__(self, daemons):
        self.dut, _, _ = _target("ubuntu_frr")
        self.fc, self.pc = self.dut["container"], f"clab-{LAB}-peer"
        (row,) = json.loads(_run(["docker", "inspect", self.pc], timeout=10).stdout or "[null]")
        if not row or row["Config"]["Labels"].get("containerlab") != LAB or NETWORK not in row["NetworkSettings"]["Networks"] \
                or not row["State"]["Running"]:
            raise RuntimeError("Routing peer is outside the isolated lab.")
        self.daemons = ("zebra", *daemons)
        self.started = {self.fc: [], self.pc: []}
        self.baseline = {c: self.kernel(c) for c in (self.fc, self.pc)}
        if any(self.alive(c, d) for c in (self.fc, self.pc) for d in self.daemons) or any(
                DUMMY in self.baseline[c] for c in (self.fc, self.pc)):
            raise RuntimeError("Disposable FRR pair is not at its daemon-free baseline; refusing to write.")
        self.prepared = True
        self.config_baseline = ""
        try:
            for container, side, dev, index in ((self.fc, "dut", "eth3", 0), (self.pc, "peer", "eth1", 1)):
                self.must(container, "ip", "link", "add", DUMMY, "type", "dummy")
                self.must(container, "ip", "link", "set", "dev", DUMMY, "up")
                for family, link in zip(("IPV4", "IPV6"), PAIR_LINK):
                    self.must(container, "ip", "addr", "add", ORIGIN[side][family], "dev", DUMMY, *(("nodad",) if family == "IPV6" else ()))
                    self.must(container, "ip", "addr", "add", link[index], "dev", dev, *(("nodad",) if family == "IPV6" else ()))
                for daemon in self.daemons:
                    self.must(container, f"/usr/lib/frr/{daemon}", "-d", "-u", "frr", "-g", "frr", "-A", "127.0.0.1")
                    self.started[container].append(daemon)
            deadline = time.monotonic() + 20
            while not all(set(self.daemons) <= set(_call(c, "vtysh", "-c", "show daemons").stdout.split()) for c in (self.fc, self.pc)):
                if time.monotonic() > deadline:
                    raise RuntimeError("FRR daemons did not answer vtysh.")
                time.sleep(1)
            self.config_baseline = self.config(self.fc)
        except Exception:
            self.close()
            raise

    @staticmethod
    def must(container, *argv):
        result = _call(container, *argv)
        if result.returncode:
            raise RuntimeError(f"Lab prerequisite failed: {' '.join(argv)[:80]}: {(result.stderr or result.stdout)[:120]}")
        return result.stdout

    @staticmethod
    def alive(container, daemon) -> bool:
        rows = _call(container, "ps", "-eo", "stat=,comm=").stdout.splitlines()
        return any(len(p := row.split()) == 2 and p[1] == daemon and not p[0].startswith("Z") for row in rows)

    @staticmethod
    def kernel(container) -> str:
        """Addresses and routes of the namespace, normalised (the comparison that proves exact link/route restoration)."""
        out = []
        for argv in (("ip", "-j", "addr", "show"), ("ip", "-j", "-4", "route", "show"), ("ip", "-j", "-6", "route", "show")):
            rows = json.loads(_call(container, *argv).stdout or "[]")
            for row in rows:
                for volatile in ("expires", "stats64"):
                    row.pop(volatile, None)
                for address in row.get("addr_info", []):
                    address.pop("valid_life_time", None), address.pop("preferred_life_time", None)
            out.append(json.dumps(rows, sort_keys=True))
        return "\n".join(out)

    @staticmethod
    def config(container) -> str:
        from ..execution.executors.linux import frr_config_digest, read_frr_config
        return frr_config_digest(read_frr_config(container, 30))

    def vty(self, container, *commands):
        result = _call(container, "vtysh", "-c", "configure terminal", *(part for c in commands for part in ("-c", c)))
        if result.returncode or "%" in result.stdout:
            raise RuntimeError(f"Native lab configuration was rejected: {result.stdout[:160]}")

    def show(self, container, command) -> str:
        return _call(container, "vtysh", "-c", command).stdout

    def close(self) -> bool:
        if not getattr(self, "prepared", False):
            return True
        for container, dev, index in ((self.fc, "eth3", 0), (self.pc, "eth1", 1)):
            for daemon in reversed(self.started[container]):
                _call(container, "pkill", "-x", daemon)
            deadline = time.monotonic() + 15
            while any(self.alive(container, d) for d in self.started[container]) and time.monotonic() < deadline:
                time.sleep(0.5)
            for link in PAIR_LINK:
                _call(container, "ip", "addr", "del", link[index], "dev", dev)
            _call(container, "ip", "link", "delete", DUMMY)
        self.prepared = False
        deadline = time.monotonic() + 15
        while (restored := all(self.kernel(c) == self.baseline[c] for c in (self.fc, self.pc))) is False and time.monotonic() < deadline:
            time.sleep(1)
        if not restored or any(self.alive(c, d) for c in (self.fc, self.pc) for d in self.daemons):
            raise RuntimeError("Disposable FRR pair did not return to its captured baseline.")
        return True


def _rendered_process(code, header_prefix):
    """NMAS-rendered process block of the matrix sample, bound to the DUT link that faces the FRR peer."""
    from copy import deepcopy
    case = sample("ubuntu_frr", by_key()[f"routing.{code}"])
    sections = deepcopy(case.sections)
    for interface in sections["interfaces"].values():
        if interface["name"] == "eth1":
            interface["name"] = "eth3"
    rendered = _descriptors("ubuntu_frr", sections)
    start = next(i for i, line in enumerate(rendered) if line.startswith(header_prefix))
    block = [rendered[start]]
    for line in rendered[start + 1:]:
        if line.strip() == "!":
            continue
        if not line.startswith(" "):
            break
        block.append(line)
    return block, sections


def _requirements(rows, device="frr"):
    from ..health.requirements import from_descriptor
    return [from_descriptor(cfg, {"requirement": kind, "device": device, "subject": {"label": cfg}, "expected": expected})
            for cfg, kind, expected in rows]


def _postcheck(target, requirements, session_factory=None):
    """The operator postcheck itself: Phase-15 evaluators over a fresh live read of the DUT."""
    from ..health.codes import Phase
    from ..health.evaluators import evaluate_requirements
    from ..health.evidence import EvidenceSet
    from ..health.thresholds import load_thresholds
    observed = live.read_device(target, session_factory=session_factory)
    evidence = EvidenceSet(devices={target["name"]: observed}, now=timezone.now(), thresholds=load_thresholds())
    evaluation = evaluate_requirements(requirements, Phase.POSTCHECK, evidence)
    failed = [f"{r.requirement}:{r.status}:{r.check_code}" for r in evaluation.results if r.status != "PASS"]
    return observed, not failed and bool(evaluation.results), failed


def _transaction(executor, specs, verify, attempts=40):
    """Engine order: preflight every Configlet, apply in order, verify, compensate in reverse.  -> result dict."""
    out = {"applied": False, "verified": False, "statuses": [], "actions": [], "failure": "", "detail": ""}
    done = []
    try:
        preflights = [executor.assess(spec) for spec in specs]
        out["actions"] = [f"{s.object_type}={p.action}/{p.restorable}/{p.reason or '-'}" for s, p in zip(specs, preflights)]
        if any(p.action == "REFUSE" or not p.restorable for p in preflights):
            raise RuntimeError("preflight could not prove a safe inverse")
        for spec, preflight in zip(specs, preflights):
            if preflight.action != APPLY:
                continue
            done.append((spec, preflight))
            outcome = executor.apply(spec, preflight)
            if not outcome.ok:
                raise RuntimeError(f"executor apply of {spec.object_type} failed: {outcome.error_code}")
        out["applied"] = bool(done)
        for attempt in range(attempts):
            out["verified"], out["detail"] = verify()
            if out["verified"]:
                break
            time.sleep(1.5)
    except Exception as exc:
        out["failure"] = f"{type(exc).__name__}: {str(exc)[:400]}"
    finally:
        out["statuses"] = [executor.compensate(spec, preflight).status for spec, preflight in reversed(done)]
    out["compensated"] = bool(done) and all(status == "COMPENSATED" for status in out["statuses"])
    return out


def _record(cell, code, runtime, scenarios, restored):
    reference = f"live:{LAB}/frr-{code.lower()}/{timezone.now().isoformat()}"
    text = " || ".join(f"{name}: preflight={r['actions']}; {r['detail']}; compensation={r['statuses']}; "
                       f"exact FRR running-config restored={r.get('config_restored')}; peer baseline={r.get('peer_clean')}; "
                       f"{r['failure'] or 'no failure'}" for name, r in scenarios.items())
    detail = f"isolated FRR {code} against FRR peer: {text}; pair kernel/daemon baseline restored={restored}"
    every = lambda key: bool(scenarios) and all(r.get(key) for r in scenarios.values())   # noqa: E731
    for name, ok, reason in (
        ("live_write", every("applied"), "FUNCTIONAL_TEST_FAILED"),
        ("live_read", every("read_ok"), "LIVE_READ_ABSENT"),
        ("live_post_write_validation", every("post_ok"), "POSTCHECK_ABSENT"),
        ("runtime_validation", every("verified"), "FUNCTIONAL_TEST_FAILED"),
        ("compensation", every("compensated") and every("config_restored") and every("peer_clean") and restored, "COMPENSATION_ABSENT"),
    ):
        cell.probes[name] = assessment.probe("PASS" if ok else "FAIL", detail[:3500], reason="" if ok else reason,
                                             test_type="LIVE", reference=reference)
    cell.runtime_version = runtime


def _configlet(n, kind, lines, expected=None):
    return ConfigletSpec(f"P4-FRR-{kind}-{n}", n, "frr", "ubuntu_frr", kind, "CREATE_DEFINE", tuple(lines), expected or {})


def probe_bgp(cell, code: str):
    """BGP IPv4/IPv6: a process NMAS creates and removes, then additive objects under a pre-existing process it preserves."""
    v6 = code == "BGP_IPV6"
    family = "IPV6" if v6 else "IPV4"
    af = f"address-family {family.lower()} unicast"
    block, sections = _rendered_process(code, "router bgp ")
    instance = next(iter(sections["routing"]["bgp"].values()))
    neighbor = next(iter(instance["neighbors"].values()))
    network = next(iter(instance["networks"].values()))["cidr"]
    peer, dut_address = neighbor["peer_address"], PAIR_LINK[v6][0].split("/")[0]
    header = block[0]
    top = [line for line in block[1:] if not line.startswith("      ") and "address-family" not in line]
    inner = [line for line in block if line.startswith("      ")]
    # the planner's Configlet decomposition: process, neighbor, address-family activation, network
    specs = [
        _configlet(1, "routing_bgp", [header, *(line for line in top if " neighbor " not in line)]),
        _configlet(2, "bgp_neighbor", [header, *(line for line in top if " neighbor " in line)]),
        _configlet(3, "bgp_neighbor_af", [header, f"   {af}", *(line for line in inner if "activate" in line), "   exit-address-family"]),
        _configlet(4, "bgp_network", [header, f"   {af}", *(line for line in inner if "network" in line), "   exit-address-family"]),
    ]
    requirements = _requirements([
        ("process", "ROUTING_PROCESS_INTENDED", {"protocol": "bgp", "local_asn": instance["local_asn"], "router_id": instance["router_id"]}),
        ("peer", "BGP_PEER_INTENDED", {"peer": peer, "remote_asn": neighbor["remote_asn"], "local_asn": instance["local_asn"]}),
        ("af", "BGP_AF_ACTIVATION_INTENDED", {"peer": peer, "remote_asn": neighbor["remote_asn"], "address_family": family}),
        ("network", "BGP_NETWORK_INTENDED", {"prefix": network, "family": family}),
    ])
    scenarios, restored = {}, False
    pair = FrrPair(("bgpd",))
    executor = LinuxExecutor(pair.dut)
    try:
        executor.connect()
        for name in ("new-process", "existing-process"):
            pair.vty(pair.pc, f"router bgp {neighbor['remote_asn']}", "bgp router-id 198.18.44.2", "no bgp default ipv4-unicast",
                     "no bgp ebgp-requires-policy", f"neighbor {dut_address} remote-as {instance['local_asn']}", af,
                     f"neighbor {dut_address} activate", f"network {PEER_NET[family]}")
            if name == "existing-process":   # native, unrelated BGP state that must survive apply and compensation untouched
                pair.vty(pair.fc, *(line.strip() for line in specs[0].lines), UNRELATED[0], "address-family ipv4 unicast", UNRELATED[1])
            before = pair.config(pair.fc)
            state = {}

            def verify():
                observed, post_ok, failed = _postcheck(pair.dut, requirements)
                row = next((p for p in observed.facts("bgp") or [] if p["peer"] == live.norm_ip(peer)), {})
                counters = (row.get("prefixes") or {}).get(family) or {}
                learned = any(r["prefix"] == PEER_NET[family] and r["type"] == "bgp" for r in observed.facts("routes") or [])
                peer_rib = pair.show(pair.pc, f"show bgp {family.lower()} unicast {network} json")
                advertised = '"paths"' in peer_rib and dut_address in peer_rib
                preserved = name == "new-process" or all(u in pair.show(pair.fc, "show running-config") for u in UNRELATED)
                state.update(read_ok=bool(observed.live_reachable), post_ok=post_ok)
                ok = post_ok and row.get("state") == "ESTABLISHED" and str(row.get("remote_as")) == str(neighbor["remote_asn"]) \
                    and (counters.get("received") or 0) >= 1 and (counters.get("sent") or 0) >= 1 and learned and advertised and preserved
                return ok, (f"session={row.get('state')} remote-as={row.get('remote_as')}; {family} prefixes received/sent={counters}; "
                            f"DUT kernel route to {PEER_NET[family]} via BGP={learned}; peer BGP table holds {network} from DUT={advertised}; "
                            f"operator postcheck pass={post_ok} {failed}; unrelated BGP objects preserved={preserved}")

            result = _transaction(executor, specs, verify)
            result.update(state)
            result["config_restored"] = pair.config(pair.fc) == before
            if name == "existing-process":
                kept = pair.show(pair.fc, "show running-config")
                result["config_restored"] = result["config_restored"] and all(u in kept for u in UNRELATED)
                _call(pair.fc, "vtysh", "-c", "configure terminal", "-c", f"no router bgp {instance['local_asn']}")
            # peer side: the session and the DUT's prefix are gone once NMAS compensated
            gone = False
            for _ in range(20):
                summary = pair.show(pair.pc, f"show bgp {family.lower()} unicast summary json")
                gone = '"state":"Established"' not in summary.replace(" ", "") and \
                    '"paths"' not in pair.show(pair.pc, f"show bgp {family.lower()} unicast {network} json")
                if gone:
                    break
                time.sleep(1)
            _call(pair.pc, "vtysh", "-c", "configure terminal", "-c", f"no router bgp {neighbor['remote_asn']}")
            result["peer_clean"] = gone
            if not result["config_restored"]:
                _call(pair.fc, "vtysh", "-c", "configure terminal", "-c", f"no router bgp {instance['local_asn']}")
            if pair.config(pair.fc) != pair.config_baseline:
                result["config_restored"] = False
                scenarios[name] = result
                break
            scenarios[name] = result
    finally:
        executor.close()
        restored = pair.close()
    _record(cell, code, "FRRouting 8.4.4 DUT / FRRouting 8.4.4 peer, isolated pair", scenarios, restored)


def probe_rip(cell, code: str):
    """RIPv2 / RIPng: NMAS-rendered process and interface binding; the DUT must learn the peer's prefix and lose it again."""
    v6 = code == "RIPNG"
    family = "IPV6" if v6 else "IPV4"
    process, daemon = ("router ripng", "ripngd") if v6 else ("router rip", "ripd")
    block, _sections = _rendered_process(code, process)
    specs = [_configlet(1, "routing_rip", block)]
    requirements = _requirements([
        ("process", "ROUTING_PROCESS_INTENDED", {"protocol": "rip", "version": code}),
        ("binding", "ROUTING_INTERFACE_ENABLED", {"protocol": "rip", "interface": "eth3", "passive": False}),
    ])
    scenarios, restored = {}, False
    pair = FrrPair((daemon,))
    executor = LinuxExecutor(pair.dut)
    status = "show ipv6 ripng status" if v6 else "show ip rip status"
    try:
        executor.connect()
        for name in ("new-process", "existing-process"):
            pair.vty(pair.pc, process, *(() if v6 else ("version 2",)), "network eth1", f"network {DUMMY}")
            if name == "existing-process":   # a native process with an unrelated binding that NMAS must leave untouched
                pair.vty(pair.fc, process, *(() if v6 else ("version 2",)), "network eth2", "passive-interface eth2")
            before = pair.config(pair.fc)
            state = {}

            def learned_now():
                observed = live.read_device(pair.dut)
                table = any(r["family"] == family and r["prefix"] == PEER_NET[family] and r["learned"] for r in observed.facts("rip") or [])
                kernel = any(r["prefix"] == PEER_NET[family] and "eth3" in r["interfaces"] for r in observed.facts("routes") or [])
                return observed, table, kernel

            def verify():
                observed, post_ok, failed = _postcheck(pair.dut, requirements)
                _, table, kernel = learned_now()
                participating = "eth3" in pair.show(pair.fc, status)
                source = next(a["local"] for a in json.loads(_call(
                    pair.fc, "ip", "-j", "-6", "addr", "show", "dev", "eth3", "scope", "link").stdout)[0]["addr_info"]
                    if a.get("local")) if v6 else PAIR_LINK[0][0].split("/")[0]
                heard = source in pair.show(pair.pc, status)
                running = pair.show(pair.fc, "show running-config")
                preserved = name == "new-process" or ("network eth2" in running and "passive-interface eth2" in running)
                state.update(read_ok=bool(observed.live_reachable), post_ok=post_ok)
                return post_ok and table and kernel and participating and heard and preserved, (
                    f"operator postcheck pass={post_ok} {failed}; RIP table learned {PEER_NET[family]} from peer={table}; "
                    f"kernel route via eth3={kernel}; eth3 participating per '{status}'={participating}; "
                    f"peer lists DUT {source} as routing information source={heard}; unrelated binding preserved={preserved}")

            result = _transaction(executor, specs, verify, attempts=60)
            result.update(state)
            result["config_restored"] = pair.config(pair.fc) == before
            # Removing only the binding leaves the learned route to the protocol's own timeout (180 s) and garbage timers.
            gone, started = False, time.monotonic()
            while time.monotonic() - started < 330:
                _, table, kernel = learned_now()
                gone = not table and not kernel
                if gone:
                    break
                time.sleep(3)
            result["detail"] += (f"; learned route absent after compensation={gone} "
                                 f"(after {int(time.monotonic() - started)} s; RIP table={table}, kernel={kernel})")
            result["compensated"] = result["compensated"] and gone
            result["peer_clean"] = True
            _call(pair.pc, "vtysh", "-c", "configure terminal", "-c", f"no {process}")
            if name == "existing-process" or not result["config_restored"]:
                _call(pair.fc, "vtysh", "-c", "configure terminal", "-c", f"no {process}")
            scenarios[name] = result
            if pair.config(pair.fc) != pair.config_baseline:
                result["config_restored"] = False
                break
    finally:
        executor.close()
        restored = pair.close()
    _record(cell, code, "FRRouting 8.4.4 DUT / FRRouting 8.4.4 peer, isolated pair", scenarios, restored)
