"""Strictly scoped reversible loopback probe against the disposable lab.

Uses the existing NMAS executor and normalized health reader, with only the
session transport exchanged for Docker CLI on the isolated cEOS container.
The container's Containerlab ownership, management network and image are
checked before every write run. No managed production target is accepted.
"""

from __future__ import annotations

import json
import os
import subprocess
import time
from pathlib import Path

from ..capabilities.live_verify import LiveVerification, _specs
from ..execution.executors.base import APPLY
from ..execution.executors.base import ConfigletSpec
from ..execution.executors.ceos import CeosExecutor
from ..execution.executors.linux import LinuxExecutor
from ..health import live
from ..config_import import parser_srlinux
from .features import by_key
from .offline_verify import _descriptors
from .probe_cases import sample
from collections import Counter

LAB = "nmas-cap-validation"
NETWORK = "nmas-cap-validation-mgmt"
TARGETS = {
    "arista_ceos": ("ceos", "ceos", "ceos:4.36.2F", "Loopback444", "198.18.44.11/32"),
    "ubuntu_frr": ("frr", "linux", "clab-raw-verifier-frr:8.4.4-1.1ubuntu6.7", "loopback44", "198.18.44.12/32"),
}


def _run(argv, *, timeout=30) -> subprocess.CompletedProcess:
    return subprocess.run(argv, capture_output=True, text=True, timeout=timeout, shell=False, check=False)


def _target(platform):
    if platform not in TARGETS:
        raise ValueError("Only the two implemented isolated executor platforms are allowed here.")
    node, kind, image, name, address = TARGETS[platform]
    container = f"clab-{LAB}-{node}"
    result = _run(["docker", "inspect", container], timeout=10)
    if result.returncode:
        raise RuntimeError("Disposable target is not running.")
    (doc,) = json.loads(result.stdout)
    labels, networks = (doc.get("Config") or {}).get("Labels") or {}, (doc.get("NetworkSettings") or {}).get("Networks") or {}
    if labels.get("containerlab") != LAB or labels.get("clab-node-kind") != ("arista_ceos" if kind == "ceos" else "linux") \
            or NETWORK not in networks or doc.get("Config", {}).get("Image") != image:
        raise RuntimeError("Target identity does not match the isolated validation lab.")
    if not doc.get("State", {}).get("Running"):
        raise RuntimeError("Disposable target is not running.")
    return {"name": node, "platform": kind, "container": container}, name, address


class DockerEosConfigConnection:
    """Minimal Netmiko-compatible transport for the explicitly isolated cEOS."""

    def __init__(self, device):
        self._container = device["container"]

    def send_command(self, command, **_kwargs):
        if not command.startswith("show "):
            raise ValueError("Only show commands can be sent from the read path.")
        result = _run(["docker", "exec", self._container, "Cli", "-p", "15", "-c", command], timeout=60)
        if result.returncode:
            raise RuntimeError("Isolated cEOS read command failed.")
        return result.stdout

    def config_mode(self, **_kwargs):
        return None

    def check_config_mode(self):
        return False

    def send_config_set(self, commands, **_kwargs):
        # Cli's noninteractive parser on cEOS 4.36.2F accepts newlines here;
        # its `-h` claim about carriage returns was checked and rejected live.
        payload = "configure terminal\n" + "\n".join(commands)
        result = _run(["docker", "exec", self._container, "Cli", "-p", "15", "--abort-on-error", "-c", payload], timeout=60)
        self.last_config_output = result.stdout[:1000]
        return result.stdout if result.returncode == 0 else "% Error: isolated cEOS command rejected"

    def disconnect(self):
        return None


def verify_loopback(platform) -> LiveVerification:
    """Create, read, parse, compensate, and prove absence, on one isolated DUT."""
    device, name, address = _target(platform)
    if platform == "arista_ceos":
        executor = CeosExecutor(device, connection_factory=DockerEosConfigConnection,
                                reader=live.read_device)
    else:
        executor = LinuxExecutor(device)
    interface, address_spec = _specs(platform, device["name"], name, address)
    applied = []
    post_write = compensation = restored = False
    try:
        executor.connect()
        initial = live.read_device(device)
        if not initial.live_reachable or name in (initial.facts("interfaces") or {}):
            raise RuntimeError("Disposable loopback is present or live pre-read failed; refusing write.")
        for spec in (interface, address_spec):
            assessment = executor.assess(spec)
            if assessment.action != APPLY or not assessment.restorable:
                raise RuntimeError("Executor preflight did not prove an additive inverse.")
            applied.append((spec, assessment))  # reserve restoration before first write
            outcome = executor.apply(spec, assessment)
            if not outcome.ok:
                raise RuntimeError(f"Isolated executor rejected {spec.object_type}: {outcome.error_code}.")
        observed = live.read_device(device)
        post_write = observed.live_reachable and name in (observed.facts("interfaces") or {}) \
            and address in (observed.facts("addresses") or {}).get(name, [])
        if not post_write:
            raise RuntimeError("Normalized live readback did not contain the loopback and its address.")
    finally:
        outcomes = []
        for spec, assessment in reversed(applied):
            outcomes.append(executor.compensate(spec, assessment).status)
        compensation = bool(applied) and all(status == "COMPENSATED" for status in outcomes)
        try:
            final = live.read_device(device)
            restored = final.live_reachable and name not in (final.facts("interfaces") or {}) \
                and not (final.facts("addresses") or {}).get(name)
        finally:
            executor.close()
    if not (post_write and compensation and restored):
        raise RuntimeError("Isolated loopback did not pass readback and restoration.")
    return LiveVerification(platform, device["name"], name, address, True, True, True, True,
                            f"isolated {device['container']}: created, read back, removed {name} {address}; absence proved")


def verify_frr_static_route(family="IPV4") -> LiveVerification:
    """Apply an actual rendered FRR route through NMAS, test forwarding choice, undo."""
    if family not in {"IPV4", "IPV6"}:
        raise ValueError("Only IPv4/IPv6 isolated static routes are permitted.")
    ipv6 = family == "IPV6"
    prefix = "2001:db8:113::/64" if ipv6 else "203.0.113.0/24"
    hop = "2001:db8:44::2" if ipv6 else "198.18.0.2"
    destination = "2001:db8:113::1" if ipv6 else "203.0.113.1"
    device, _name, _address = _target("ubuntu_frr")
    peer = f"clab-{LAB}-peer"
    inspection = _run(["docker", "inspect", peer], timeout=10)
    if inspection.returncode:
        raise RuntimeError("Disposable FRR peer is unavailable.")
    (peer_doc,) = json.loads(inspection.stdout)
    if (peer_doc.get("Config") or {}).get("Labels", {}).get("containerlab") != LAB \
            or NETWORK not in (peer_doc.get("NetworkSettings") or {}).get("Networks", {}):
        raise RuntimeError("FRR peer does not belong to the isolated lab.")

    def docker(container, *args):
        return _run(["docker", "exec", container, *args], timeout=30)

    for container, link in ((device["container"], "eth1"), (peer, "eth1")):
        check = docker(container, "ip", "-j", "addr", "show", "dev", link)
        if check.returncode or any(row.get("family") == ("inet6" if ipv6 else "inet") and
                                   (not ipv6 or not row.get("local", "").startswith("fe80:")) for iface in json.loads(check.stdout)
                                   for row in iface.get("addr_info", [])):
            raise RuntimeError("Disposable FRR data link is not pristine; refusing setup.")
    initial = live.read_device(device)
    if not initial.live_reachable or any(r.get("prefix") == prefix for r in initial.facts("routes") or []):
        raise RuntimeError("Disposable FRR route is already present or pre-read failed.")
    case = sample("ubuntu_frr", by_key()[f"routing.STATIC_{family}"])
    lines = [s for s in (Counter(_descriptors("ubuntu_frr", case.sections)) -
                         Counter(_descriptors("ubuntu_frr", case.baseline))).elements()
             if s.startswith("ipv6 route " if ipv6 else "ip route ")]
    expected_line = f"{'ipv6' if ipv6 else 'ip'} route {prefix} {hop} 200"
    if lines != [expected_line]:
        raise RuntimeError("FRR static-route renderer does not match the bounded validation target.")
    spec = ConfigletSpec("P4-FRR-STATIC", 1, "frr", "ubuntu_frr", "static_route", "CREATE_DEFINE",
                         tuple(lines), {"prefix": prefix, "next_hop": hop})
    setup = []
    executor = LinuxExecutor(device)
    assessment = None
    route_applied = False
    route_restored = False
    post_write = False
    try:
        endpoints = ((device["container"], "2001:db8:44::1/64", "eth1"),
                     (peer, "2001:db8:44::2/64", "eth1"), (peer, "2001:db8:113::1/128", "lo")) if ipv6 else (
                     (device["container"], "198.18.0.1/30", "eth1"),
                     (peer, "198.18.0.2/30", "eth1"), (peer, "203.0.113.1/32", "lo"))
        for container, cidr, link in endpoints:
            result = docker(container, "ip", "addr", "add", cidr, "dev", link)
            if result.returncode:
                raise RuntimeError("Disposable FRR data-link setup failed.")
            setup.append((container, cidr, link))
        executor.connect()
        assessment = executor.assess(spec)
        if assessment.action != APPLY or not assessment.restorable:
            raise RuntimeError("FRR static-route executor preflight failed to prove exact inverse.")
        route_applied = True  # even a rejected vtysh call might have a partial effect
        outcome = executor.apply(spec, assessment)
        if not outcome.ok:
            raise RuntimeError("FRR static-route executor rejected the rendered Configlet.")
        for attempt in range(6):
            observed = live.read_device(device)
            route_ok = any(r.get("prefix") == prefix and r.get("type") == "static"
                           and hop in r.get("next_hops", []) for r in observed.facts("routes") or [])
            forwarding = docker(device["container"], "ip", *(["-6"] if ipv6 else []), "route", "get", destination)
            post_write = route_ok and forwarding.returncode == 0 and f"via {hop} dev eth1" in forwarding.stdout
            if post_write:
                break
            if attempt < 5:
                time.sleep(1)
        if not post_write:
            raise RuntimeError(f"FRR route readback/kernel forwarding did not match: route={route_ok}, get_rc={forwarding.returncode}, "
                               f"chosen_peer={f'via {hop} dev eth1' in forwarding.stdout}.")
    finally:
        try:
            if route_applied and assessment is not None:
                route_restored = executor.compensate(spec, assessment).status == "COMPENSATED"
        finally:
            executor.close()
            for container, cidr, link in reversed(setup):
                result = docker(container, "ip", "addr", "del", cidr, "dev", link)
                if result.returncode:
                    raise RuntimeError("Disposable FRR data-link restoration failed.")
    final = live.read_device(device)
    route_restored = route_restored and final.live_reachable and not any(
        r.get("prefix") == prefix for r in final.facts("routes") or [])
    if not (post_write and route_restored):
        raise RuntimeError("FRR route postcheck/restoration did not pass.")
    return LiveVerification("ubuntu_frr", "frr", "eth1", f"{prefix} via {hop}", True, True, True, True,
                            f"isolated FRR 8.4.4: NMAS rendered/applied {family} static route, normalized readback and kernel forwarding matched, inverse removed route and temporary link addresses")


def verify_ceos_static_route(family="IPV4") -> LiveVerification:
    """Use the isolated bridge gateway only as a next hop for one disposable route."""
    if family not in {"IPV4", "IPV6"}:
        raise ValueError("Only IPv4/IPv6 isolated static routes are permitted.")
    ipv6 = family == "IPV6"
    device, _name, _address = _target("arista_ceos")
    prefix = "2001:db8:113::/64" if ipv6 else "203.0.113.0/24"
    hop = "fd00:ca:248::1" if ipv6 else "172.31.248.1"
    verb = "ipv6" if ipv6 else "ip"
    case = sample("arista_ceos", by_key()[f"routing.STATIC_{family}"])
    route = next(iter(case.sections["routing"]["static_routes"].values()))
    route["next_hop_address"] = hop
    lines = [s for s in (Counter(_descriptors("arista_ceos", case.sections)) -
                         Counter(_descriptors("arista_ceos", case.baseline))).elements() if s.startswith(f"{verb} route ")]
    if lines != [f"{verb} route {prefix} {hop} 200"]:
        raise RuntimeError("cEOS static-route renderer does not match the bounded test route.")
    spec = ConfigletSpec("P4-EOS-STATIC", 1, "ceos", "arista_ceos", "static_route", "CREATE_DEFINE",
                         tuple(lines), {"prefix": prefix, "next_hop": hop})
    executor = CeosExecutor(device, connection_factory=DockerEosConfigConnection, reader=live.read_device)
    assessment = None
    applied = post_write = restored = False
    try:
        executor.connect()
        before = live.read_device(device)
        if not before.live_reachable or any(r.get("prefix") == prefix for r in before.facts("routes") or []):
            raise RuntimeError("Disposable cEOS route already exists or pre-read failed.")
        assessment = executor.assess(spec)
        if assessment.action != APPLY or not assessment.restorable:
            raise RuntimeError("cEOS route preflight did not prove additive compensation.")
        applied = True
        result = executor.apply(spec, assessment)
        if not result.ok:
            raise RuntimeError("cEOS rejected the rendered static-route Configlet.")
        for attempt in range(6):
            observed = live.read_device(device)
            post_write = any(r.get("prefix") == prefix and r.get("type", "").lower() == "static"
                             and hop in r.get("next_hops", []) for r in observed.facts("routes") or [])
            if post_write:
                break
            if attempt < 5:
                time.sleep(1)
        if not post_write:
            raise RuntimeError("cEOS normalized route readback did not match the intent.")
    finally:
        try:
            if applied and assessment is not None:
                restored = executor.compensate(spec, assessment).status == "COMPENSATED"
        finally:
            executor.close()
    final = live.read_device(device)
    restored = restored and final.live_reachable and not any(r.get("prefix") == prefix for r in final.facts("routes") or [])
    if not (post_write and restored):
        raise RuntimeError("cEOS route readback/restoration did not pass.")
    return LiveVerification("arista_ceos", "ceos", "", f"{prefix} via {hop}", True, True, True, True,
                            f"isolated cEOS 4.36.2F: NMAS rendered/applied {family} static route, normalized readback matched, inverse removed it and absence verified")


def verify_ceos_ospfv2() -> LiveVerification:
    """Prove a real OSPF FULL adjacency and NMAS config-snapshot compensation."""
    from ..config_import import parser_ceos
    from ..execution.executors.base import ConfigletSpec

    device, _name, _address = _target("arista_ceos")
    peer = f"clab-{LAB}-peer"
    inspection = _run(["docker", "inspect", peer], timeout=10)
    if inspection.returncode:
        raise RuntimeError("Disposable OSPF peer is unavailable.")
    (peer_doc,) = json.loads(inspection.stdout)
    if (peer_doc.get("Config") or {}).get("Labels", {}).get("containerlab") != LAB \
            or NETWORK not in (peer_doc.get("NetworkSettings") or {}).get("Networks", {}):
        raise RuntimeError("OSPF peer is outside the isolated lab.")

    def peer_run(*args):
        return _run(["docker", "exec", peer, *args], timeout=30)

    e_before = _run(["docker", "exec", device["container"], "Cli", "-p", "15", "-c",
                     "show running-config interfaces Ethernet2"], timeout=20)
    global_before = _run(["docker", "exec", device["container"], "Cli", "-p", "15", "-c",
                          "show running-config"], timeout=20)
    peer_before = peer_run("ip", "-j", "addr", "show", "dev", "eth2")
    if e_before.returncode or e_before.stdout.strip() != "interface Ethernet2" or global_before.returncode \
            or "no ip routing" not in global_before.stdout or peer_before.returncode \
            or any(a.get("family") == "inet" for i in json.loads(peer_before.stdout) for a in i.get("addr_info", [])):
        raise RuntimeError("OSPF data links do not have the expected disposable baseline.")
    original_peer_mtu = int(json.loads(peer_before.stdout)[0]["mtu"])
    initial = live.read_device(device)
    if not initial.live_reachable or any(n.get("family") == "OSPFV2" for n in initial.facts("ospf") or []):
        raise RuntimeError("cEOS OSPF baseline already has a neighbor or cannot be read.")

    case = sample("arista_ceos", by_key()["routing.OSPFV2"])
    case.sections["interfaces"]["if_0000000000000001"]["name"] = "Ethernet2"
    rendered = _descriptors("arista_ceos", case.sections)

    def block(header):
        start = rendered.index(header)
        end = next((i for i in range(start + 1, len(rendered)) if rendered[i].startswith("!") or
                    (rendered[i] and not rendered[i].startswith(" "))), len(rendered))
        return rendered[start:end]

    lines = ["interface Ethernet2", *(line for line in block("interface Ethernet2") if line.strip().startswith("ip ospf ")),
             *block("router ospf 44")]
    if not lines or "   ip ospf area 0" not in lines or "   network 198.18.0.0/30 area 0" not in lines \
            or any(line.startswith("!") for line in lines):
        raise RuntimeError("cEOS OSPF renderer lacks the bounded interface/process configuration.")
    spec = ConfigletSpec("P4-EOS-OSPF", 1, "ceos", "arista_ceos", "routing_ospf", "CREATE_DEFINE",
                         tuple(lines), {"process_id": 44, "interface": "Ethernet2"})
    executor = CeosExecutor(device, connection_factory=DockerEosConfigConnection, reader=live.read_device)
    peer_addressed = peer_configured = eos_attempted = peer_mtu_changed = routing_enabled = False
    zebra_started = ospf_started = link_prepared = False
    full = restored = compensated = peer_cleanup_ok = False
    preflight = None
    try:
        routing_enabled = True
        enable = _run(["docker", "exec", device["container"], "Cli", "-p", "15", "--abort-on-error", "-c",
                       "configure terminal\nip routing"], timeout=30)
        if enable.returncode:
            raise RuntimeError("Disposable cEOS routing prerequisite was rejected.")
        interface_setup = _run(["docker", "exec", device["container"], "Cli", "-p", "15", "--abort-on-error", "-c",
                                "configure terminal\ninterface Ethernet2\nno switchport\nip address 198.18.0.1/30\nno shutdown"], timeout=30)
        if interface_setup.returncode:
            raise RuntimeError("Disposable cEOS OSPF link setup failed.")
        link_prepared = True
        if original_peer_mtu != 1500:
            if peer_run("ip", "link", "set", "dev", "eth2", "mtu", "1500").returncode:
                raise RuntimeError("Disposable OSPF peer MTU alignment failed.")
            peer_mtu_changed = True
        if peer_run("ip", "addr", "add", "198.18.0.2/30", "dev", "eth2").returncode:
            raise RuntimeError("Disposable peer OSPF address setup failed.")
        peer_addressed = True
        if peer_run("/usr/lib/frr/zebra", "-d", "-u", "frr", "-g", "frr", "-A", "127.0.0.1").returncode:
            raise RuntimeError("Disposable OSPF zebra daemon failed to start.")
        zebra_started = True
        if peer_run("/usr/lib/frr/ospfd", "-d", "-u", "frr", "-g", "frr", "-A", "127.0.0.1").returncode:
            raise RuntimeError("Disposable OSPF daemon failed to start.")
        ospf_started = True
        peer_commands = (
            "interface eth2", "ip ospf network point-to-point", "exit",
            "router ospf", "ospf router-id 198.18.44.2", "network 198.18.0.0/30 area 0",
        )
        peer_configured = True  # first command may be partially accepted
        result = peer_run("vtysh", "-c", "configure terminal",
                          *(part for command in peer_commands for part in ("-c", command)))
        if result.returncode or "% Unknown command" in result.stdout:
            raise RuntimeError("Disposable peer rejected OSPF setup.")
        executor.connect()
        preflight = executor.assess(spec)
        if preflight.action != APPLY or not preflight.restorable:
            raise RuntimeError("OSPF preflight could not derive a safe NMAS inverse.")
        eos_attempted = True
        outcome = executor.apply(spec, preflight)
        if not outcome.ok:
            raise RuntimeError("cEOS rejected rendered OSPF process/interface commands.")
        for attempt in range(10):
            observed = live.read_device(device)
            full = any(n.get("family") == "OSPFV2" and n.get("state") == "FULL" and
                       n.get("interface") == "Ethernet2" for n in observed.facts("ospf") or [])
            if full:
                break
            if attempt < 9:
                time.sleep(1)
        if not full:
            peer_neighbors = peer_run("vtysh", "-c", "show ip ospf neighbor json")
            peer_interface = peer_run("vtysh", "-c", "show ip ospf interface eth2")
            eos_interface = executor._conn.send_command("show ip ospf interface Ethernet2", read_timeout=20)
            running = executor._conn.send_command("show running-config", read_timeout=30)
            eos_sections = [line for line in running.splitlines() if "Ethernet2" in line or "ospf" in line.lower() or
                            "198.18.0.1" in line]
            raise RuntimeError(f"OSPFv2 FULL not observed: NMAS neighbors={observed.facts('ospf')}; "
                               f"peer_neighbors={peer_neighbors.stdout[:300]}; peer_interface={peer_interface.stdout[:300]}; "
                               f"eos_interface={eos_interface[:400]}; eos_running_lines={eos_sections[:20]}.")
        running = executor._conn.send_command("show running-config", read_timeout=30)
        parsed = parser_ceos.parse(running)
        if not any(i.family == "ospf" and i.fields.get("process_id") == 44 and
                   any(b.get("interface_name") == "Ethernet2" for b in i.bindings) for i in parsed.routing_instances):
            raise RuntimeError("cEOS live running-config import omitted the OSPF process/interface binding.")
        routing_rows = observed.facts("routing_config") or []
        if not any(row["protocol"] == "ospf" and row["version"] == "OSPFV2" and row["process_id"] == 44 and
                   row["router_id"] == "198.18.44.1" and
                   {"prefix": "198.18.0.0/30", "area": "0"} in row["networks"] and
                   any(b.get("interface_name") == "Ethernet2" and b.get("area") == "0" and not b.get("passive")
                       for b in row["bindings"]) for row in routing_rows):
            raise RuntimeError(f"NMAS semantic OSPFv2 process postcheck failed: {routing_rows!r}.")
    finally:
        try:
            try:
                if eos_attempted:
                    if preflight is not None:
                        compensated = executor.compensate(spec, preflight).status == "COMPENSATED"
                    if not compensated:  # isolated-device safety fallback; never counted as NMAS compensation
                        removal = executor._send(["no router ospf 44"])
                        if not removal.ok:
                            raise RuntimeError("Disposable cEOS OSPF/interface cleanup was rejected.")
                if link_prepared:
                    reset_link = _run(["docker", "exec", device["container"], "Cli", "-p", "15", "--abort-on-error", "-c",
                                       "configure terminal\ndefault interface Ethernet2"], timeout=30)
                    if reset_link.returncode:
                        raise RuntimeError("Disposable OSPF link fixture cleanup was rejected.")
            finally:
                if routing_enabled:
                    disable = _run(["docker", "exec", device["container"], "Cli", "-p", "15", "--abort-on-error", "-c",
                                    "configure terminal\nno ip routing"], timeout=30)
                    if disable.returncode:
                        raise RuntimeError("Disposable cEOS routing prerequisite cleanup failed.")
        finally:
            executor.close()
            if peer_configured:
                peer_cleanup_ok = peer_run("vtysh", "-c", "configure terminal", "-c", "no router ospf").returncode == 0
                peer_cleanup_ok = peer_run("vtysh", "-c", "configure terminal", "-c", "interface eth2", "-c", "no ip ospf network point-to-point").returncode == 0 and peer_cleanup_ok
            address_failed = bool(peer_addressed and peer_run("ip", "addr", "del", "198.18.0.2/30", "dev", "eth2").returncode)
            mtu_failed = bool(peer_mtu_changed and peer_run("ip", "link", "set", "dev", "eth2", "mtu", str(original_peer_mtu)).returncode)
            if address_failed or mtu_failed:
                raise RuntimeError("Disposable OSPF peer address/MTU cleanup failed.")
            if ospf_started:
                peer_run("sh", "-c", "pkill -x ospfd")
            if zebra_started:
                peer_run("sh", "-c", "pkill -x zebra")
    e_after = _run(["docker", "exec", device["container"], "Cli", "-p", "15", "-c",
                    "show running-config interfaces Ethernet2"], timeout=20)
    global_after = _run(["docker", "exec", device["container"], "Cli", "-p", "15", "-c",
                         "show running-config"], timeout=20)
    peer_after = peer_run("ip", "-j", "addr", "show", "dev", "eth2")
    peer_config_after = peer_run("vtysh", "-c", "show running-config")
    final = live.read_device(device)
    restored = e_after.returncode == 0 and e_after.stdout.strip() == "interface Ethernet2" and final.live_reachable \
        and not any(n.get("family") == "OSPFV2" for n in final.facts("ospf") or []) \
        and global_after.returncode == 0 and "no ip routing" in global_after.stdout and "router ospf 44" not in global_after.stdout \
        and peer_after.returncode == 0 and int(json.loads(peer_after.stdout)[0]["mtu"]) == original_peer_mtu \
        and not any(a.get("family") == "inet" for i in json.loads(peer_after.stdout) for a in i.get("addr_info", [])) \
        and peer_cleanup_ok and (peer_config_after.returncode != 0 or
                                 ("router ospf" not in peer_config_after.stdout and
                                  "ip ospf network point-to-point" not in peer_config_after.stdout))
    if not (full and restored):
        raise RuntimeError(f"OSPFv2 adjacency/restoration did not pass: full={full}, restored={restored}, "
                           f"compensated={compensated}, peer_cleanup={peer_cleanup_ok}.")
    return LiveVerification("arista_ceos", "ceos", "Ethernet2", "198.18.0.1/30", True, True, compensated, True,
                            f"isolated cEOS/FRR OSPFv2: NMAS rendered/applied process plus interface; FULL adjacency and live import matched; NMAS compensation={compensated}; baseline restored")


def verify_ceos_bgp(family="IPV4") -> LiveVerification:
    """Establish eBGP and exchange connected test prefixes in the disposable lab."""
    from ..config_import import parser_ceos

    if family not in {"IPV4", "IPV6"}:
        raise ValueError("Only the two explicitly modeled BGP address families are accepted.")
    v6 = family == "IPV6"
    peer_address = "2001:db8:44::2" if v6 else "198.18.0.2"
    eos_address = "2001:db8:44::1/64" if v6 else "198.18.0.1/30"
    peer_link = "2001:db8:44::2/64" if v6 else "198.18.0.2/30"
    eos_network = "2001:db8:113::/64" if v6 else "203.0.113.0/24"
    eos_loopback = "2001:db8:113::1/64" if v6 else "203.0.113.1/24"
    peer_network = "2001:db8:114::/64" if v6 else "198.51.100.0/24"
    peer_loop = "2001:db8:114::1/64" if v6 else "198.51.100.1/24"
    af = "ipv6" if v6 else "ipv4"
    ip_cmd = "ipv6" if v6 else "ip"
    addr_family = "inet6" if v6 else "inet"

    device, _, _ = _target("arista_ceos")
    peer = f"clab-{LAB}-peer"
    inspection = _run(["docker", "inspect", peer], timeout=10)
    if inspection.returncode:
        raise RuntimeError("Disposable BGP peer is unavailable.")
    (peer_doc,) = json.loads(inspection.stdout)
    if (peer_doc.get("Config") or {}).get("Labels", {}).get("containerlab") != LAB \
            or NETWORK not in (peer_doc.get("NetworkSettings") or {}).get("Networks", {}):
        raise RuntimeError("BGP peer is outside the isolated lab.")

    def eos(command, *, config=False):
        payload = f"configure terminal\n{command}" if config else command
        result = _run(["docker", "exec", device["container"], "Cli", "-p", "15", "--abort-on-error", "-c", payload], timeout=30)
        if result.returncode or "% Error" in result.stdout or "% Invalid input" in result.stdout:
            raise RuntimeError(f"Disposable cEOS {'configuration' if config else 'read'} failed: {command[:60]}")
        return result.stdout

    def peer_run(*args):
        return _run(["docker", "exec", peer, *args], timeout=30)

    def peer_vty(*commands):
        result = peer_run("vtysh", "-c", "configure terminal", *(part for command in commands for part in ("-c", command)))
        if result.returncode or "% Unknown command" in result.stdout or "% Command incomplete" in result.stdout:
            raise RuntimeError(f"Disposable FRR BGP configuration failed: {commands[:2]}")
        return result.stdout

    eos_before = eos("show running-config")
    peer_addr_before = peer_run("ip", "-j", "addr", "show", "dev", "eth2")
    peer_lo_before = peer_run("ip", "-j", "addr", "show", "dev", "lo")
    if "no ip routing" not in eos_before or "router bgp " in eos_before or "interface Loopback444" in eos_before \
            or eos("show running-config interfaces Ethernet2").strip() != "interface Ethernet2" \
            or peer_addr_before.returncode or peer_lo_before.returncode \
            or any(a.get("family") == addr_family and (not v6 or a.get("scope") == "global")
                   for i in json.loads(peer_addr_before.stdout) for a in i.get("addr_info", [])) \
            or any(a.get("local") == peer_loop.split("/")[0]
                   for i in json.loads(peer_lo_before.stdout) for a in i.get("addr_info", [])):
        raise RuntimeError("BGP link/loopback baseline is not the expected disposable state.")
    if peer_run("sh", "-c", "ps -eo stat=,comm= | awk '$2==\"bgpd\" && $1 !~ /^Z/'").stdout.strip():
        raise RuntimeError("Disposable peer already has a BGP daemon; baseline is ambiguous.")
    initial = live.read_device(device)
    if not initial.live_reachable or initial.facts("bgp"):
        raise RuntimeError("cEOS BGP baseline already has a neighbor or cannot be read.")

    case = sample("arista_ceos", by_key()[f"routing.BGP_{family}"])
    case.sections["interfaces"]["if_0000000000000001"]["name"] = "Ethernet2"
    rendered = _descriptors("arista_ceos", case.sections)
    start = rendered.index("router bgp 65044")
    lines = [line for line in rendered[start:] if line.strip() and not line.lstrip().startswith("!")]
    lines = lines[:next((i for i, line in enumerate(lines[1:], 1) if not line.startswith(" ")), len(lines))]
    required = (f"   neighbor {peer_address} remote-as 65045", f"   address-family {af}",
                f"      neighbor {peer_address} activate", f"      network {eos_network}")
    if not all(line in lines for line in required):
        raise RuntimeError("NMAS BGP renderer omitted the required peer or network statements.")
    spec = ConfigletSpec("P4-EOS-BGP4", 1, "ceos", "arista_ceos", "routing_bgp", "CREATE_DEFINE",
                         tuple(lines), {"local_asn": 65044})
    executor = CeosExecutor(device, connection_factory=DockerEosConfigConnection, reader=live.read_device)
    routing_enabled = eos_attempted = peer_config_attempted = peer_addressed = peer_loopback = False
    preflight = None
    compensated = False
    zebra_started = bgpd_started = False
    established = routes_exchanged = imported = False
    cleanup_errors = []
    try:
        eos("ip routing", config=True)
        routing_enabled = True
        eos_attempted = True
        eos(f"interface Ethernet2\nno switchport\n{ip_cmd} address {eos_address}\nno shutdown", config=True)
        eos(f"interface Loopback444\n{ip_cmd} address {eos_loopback}", config=True)
        if peer_run("ip", "-6" if v6 else "-4", "addr", "add", peer_link, "dev", "eth2").returncode:
            raise RuntimeError("Disposable FRR peer link address failed.")
        peer_addressed = True
        if peer_run("ip", "-6" if v6 else "-4", "addr", "add", peer_loop, "dev", "lo").returncode:
            raise RuntimeError("Disposable FRR peer advertised prefix failed.")
        peer_loopback = True
        if not peer_run("sh", "-c", "ps -eo stat=,comm= | awk '$2==\"zebra\" && $1 !~ /^Z/'").stdout.strip():
            if peer_run("/usr/lib/frr/zebra", "-d", "-u", "frr", "-g", "frr", "-A", "127.0.0.1").returncode:
                raise RuntimeError("Disposable zebra daemon failed to start.")
            zebra_started = True
        if peer_run("/usr/lib/frr/bgpd", "-d", "-u", "frr", "-g", "frr", "-A", "127.0.0.1").returncode:
            raise RuntimeError("Disposable BGP daemon failed to start.")
        bgpd_started = True
        peer_config_attempted = True
        peer_vty("router bgp 65045", "bgp router-id 198.18.44.2", "no bgp ebgp-requires-policy",
                 f"neighbor {eos_address.split('/')[0]} remote-as 65044",
                 f"address-family {af} unicast", f"neighbor {eos_address.split('/')[0]} activate", f"network {peer_network}")
        executor.connect()
        preflight = executor.assess(spec)
        if preflight.action != APPLY or not preflight.restorable:
            raise RuntimeError("NMAS BGP preflight could not derive a safe inverse.")
        eos_attempted = True
        if not executor.apply(spec, preflight).ok:
            raise RuntimeError("NMAS cEOS BGP apply was rejected.")
        for attempt in range(20):
            observed = live.read_device(device)
            established = any(p.get("peer") == peer_address and p.get("state") == "ESTABLISHED" and p.get("family") == (6 if v6 else 4)
                              for p in observed.facts("bgp") or [])
            eos_rib = executor._conn.send_command(f"show {ip_cmd} bgp {peer_network}")
            peer_rib = peer_run("vtysh", "-c", f"show bgp {af} unicast {eos_network}")
            routes_exchanged = peer_network in eos_rib and eos_network in peer_rib.stdout
            if established and routes_exchanged:
                break
            if attempt < 19:
                time.sleep(1)
        running = executor._conn.send_command("show running-config")
        parsed = parser_ceos.parse(running)
        imported = any(i.family == "bgp" and i.fields.get("local_asn") == 65044 and
                       any(n.get("peer_address") == peer_address and n.get("remote_asn") == 65045 for n in i.neighbors)
                       for i in parsed.routing_instances)
        semantic = any(row["protocol"] == "bgp" and row["local_asn"] == 65044 and
                       row["router_id"] == "198.18.44.1" and
                       any(n.get("peer_address") == peer_address and n.get("remote_asn") == 65045 and
                           n.get(f"activate_{family.lower()}") for n in row["neighbors"]) and
                       any(n.get("family") == family and n.get("cidr") == eos_network for n in row["networks"])
                       for row in observed.facts("routing_config") or [])
        if not (established and routes_exchanged and imported and semantic):
            peer_summary = peer_run("vtysh", "-c", f"show bgp {af} unicast summary")
            raise RuntimeError(f"BGP postcheck failed: established={established}, routes_exchanged={routes_exchanged}, "
                               f"imported={imported}, semantic={semantic}; peers={observed.facts('bgp')}; EOS route={eos_rib[:700]!r}; "
                               f"FRR route={peer_rib.stdout[:700]!r}; FRR summary={peer_summary.stdout[:700]!r}")
    finally:
        try:
            if eos_attempted and preflight is not None:
                compensated = executor.compensate(spec, preflight).status == "COMPENSATED"
            executor.close()
            if eos_attempted:
                for command in (("no interface Loopback444", "default interface Ethernet2") if compensated else
                                ("no router bgp 65044", "no interface Loopback444", "default interface Ethernet2")):
                    try: eos(command, config=True)
                    except RuntimeError as exc: cleanup_errors.append(str(exc))
            if routing_enabled:
                try: eos("no ip routing", config=True)
                except RuntimeError as exc: cleanup_errors.append(str(exc))
            if peer_config_attempted:
                try: peer_vty("no router bgp 65045")
                except RuntimeError as exc: cleanup_errors.append(str(exc))
            if peer_addressed and peer_run("ip", "-6" if v6 else "-4", "addr", "del", peer_link, "dev", "eth2").returncode:
                cleanup_errors.append("Peer link address removal failed")
            if peer_loopback and peer_run("ip", "-6" if v6 else "-4", "addr", "del", peer_loop, "dev", "lo").returncode:
                cleanup_errors.append("Peer loopback address removal failed")
        finally:
            if bgpd_started: peer_run("sh", "-c", "pkill -x bgpd")
            if zebra_started: peer_run("sh", "-c", "pkill -x zebra")
    eos_after = eos("show running-config")
    peer_after = peer_run("ip", "-j", "addr", "show", "dev", "eth2")
    peer_lo_after = peer_run("ip", "-j", "addr", "show", "dev", "lo")
    final = live.read_device(device)
    restored = not cleanup_errors and "no ip routing" in eos_after and "router bgp 65044" not in eos_after \
        and "interface Loopback444" not in eos_after and eos("show running-config interfaces Ethernet2").strip() == "interface Ethernet2" \
        and final.live_reachable and not final.facts("bgp") and peer_after.returncode == 0 and peer_lo_after.returncode == 0 \
        and not any(a.get("local") == peer_link.split("/")[0] for i in json.loads(peer_after.stdout) for a in i.get("addr_info", [])) \
        and not any(a.get("local") == peer_loop.split("/")[0] for i in json.loads(peer_lo_after.stdout) for a in i.get("addr_info", []))
    if not restored:
        raise RuntimeError(f"Disposable BGP cleanup did not restore baseline: {cleanup_errors}")
    return LiveVerification("arista_ceos", "ceos", "Ethernet2", eos_address, True, True, compensated, True,
                            f"isolated cEOS/FRR eBGP {family}: NMAS rendered/applied ASN, neighbor, remote-AS and network; ESTABLISHED and both advertised prefixes verified; live import matched; NMAS compensation={compensated}; baseline restored")


def verify_ceos_ospfv3() -> LiveVerification:
    """Prove an IPv6 OSPF FULL adjacency, then restore the disposable baseline."""
    from ..config_import import parser_ceos

    device, _, _ = _target("arista_ceos")
    peer = f"clab-{LAB}-peer"
    inspection = _run(["docker", "inspect", peer], timeout=10)
    if inspection.returncode:
        raise RuntimeError("Disposable OSPFv3 peer is unavailable.")
    (peer_doc,) = json.loads(inspection.stdout)
    if (peer_doc.get("Config") or {}).get("Labels", {}).get("containerlab") != LAB \
            or NETWORK not in (peer_doc.get("NetworkSettings") or {}).get("Networks", {}):
        raise RuntimeError("OSPFv3 peer is outside the isolated lab.")

    def peer_run(*args):
        return _run(["docker", "exec", peer, *args], timeout=30)

    def eos(command, *, config=False):
        payload = f"configure terminal\n{command}" if config else command
        result = _run(["docker", "exec", device["container"], "Cli", "-p", "15", "--abort-on-error", "-c", payload], timeout=30)
        if result.returncode or "% Error" in result.stdout or "% Invalid input" in result.stdout:
            raise RuntimeError(f"Disposable cEOS OSPFv3 {'write' if config else 'read'} failed: {command[:60]}")
        return result.stdout

    def peer_vty(*commands):
        result = peer_run("vtysh", "-c", "configure terminal", *(part for command in commands for part in ("-c", command)))
        if result.returncode or "% Unknown command" in result.stdout or "% Command incomplete" in result.stdout:
            raise RuntimeError(f"Disposable FRR OSPFv3 configuration failed: {commands[:2]}; {result.stdout[:180]}")

    before = eos("show running-config")
    peer_before = peer_run("ip", "-j", "addr", "show", "dev", "eth2")
    if "no ipv6 unicast-routing" not in eos("show running-config all") or "ipv6 router ospf 44" in before \
            or eos("show running-config interfaces Ethernet2").strip() != "interface Ethernet2" \
            or peer_before.returncode or any(a.get("family") == "inet6" and a.get("scope") == "global"
                                         for i in json.loads(peer_before.stdout) for a in i.get("addr_info", [])):
        raise RuntimeError("OSPFv3 baseline is not the expected disposable state.")
    original_mtu = int(json.loads(peer_before.stdout)[0]["mtu"])
    ra_before = peer_run("sysctl", "-n", "net.ipv6.conf.eth2.accept_ra")
    if ra_before.returncode or ra_before.stdout.strip() not in {"0", "1", "2"}:
        raise RuntimeError("Disposable peer RA setting could not be captured.")
    if peer_run("sh", "-c", "ps -eo stat=,comm= | awk '$2==\"ospf6d\" && $1 !~ /^Z/'").stdout.strip():
        raise RuntimeError("Disposable peer already has OSPFv3 running.")
    initial = live.read_device(device)
    if not initial.live_reachable or any(n.get("family") == "OSPFV3" for n in initial.facts("ospf") or []):
        raise RuntimeError("OSPFv3 baseline already has a neighbor or cannot be read.")
    case = sample("arista_ceos", by_key()["routing.OSPFV3"])
    case.sections["interfaces"]["if_0000000000000001"]["name"] = "Ethernet2"
    rendered = _descriptors("arista_ceos", case.sections)

    def block(header):
        start = rendered.index(header)
        end = next((i for i in range(start + 1, len(rendered)) if rendered[i] and
                    not rendered[i].startswith(" ") and not rendered[i].startswith("!")), len(rendered))
        return [line for line in rendered[start:end] if line.strip() and not line.lstrip().startswith("!")]

    lines = ["interface Ethernet2", *(line for line in block("interface Ethernet2") if line.strip().startswith("ipv6 ospf ")),
             *block("ipv6 router ospf 44")]
    if "   ipv6 ospf 44 area 0" not in lines or "   router-id 198.18.44.1" not in lines:
        raise RuntimeError("NMAS OSPFv3 renderer omitted the process/interface binding.")
    spec = ConfigletSpec("P4-EOS-OSPF3", 1, "ceos", "arista_ceos", "routing_ospf", "CREATE_DEFINE",
                         tuple(lines), {"process_id": 44, "interface": "Ethernet2"})
    executor = CeosExecutor(device, connection_factory=DockerEosConfigConnection, reader=live.read_device)
    routing_enabled = eos_attempted = peer_addressed = peer_config_attempted = mtu_changed = ra_changed = False
    preflight = None
    compensated = False
    zebra_started = ospf_started = False
    full = imported = False
    cleanup_errors = []
    try:
        if ra_before.stdout.strip() != "0":
            if peer_run("sysctl", "-w", "net.ipv6.conf.eth2.accept_ra=0").returncode:
                raise RuntimeError("Disposable peer RA suppression failed.")
            ra_changed = True
        eos("ipv6 unicast-routing", config=True)
        routing_enabled = True
        eos_attempted = True
        eos("interface Ethernet2\nno switchport\nipv6 address 2001:db8:44::1/64\nno shutdown", config=True)
        if original_mtu != 1500:
            if peer_run("ip", "link", "set", "dev", "eth2", "mtu", "1500").returncode:
                raise RuntimeError("Disposable peer MTU alignment failed.")
            mtu_changed = True
        if peer_run("ip", "-6", "addr", "add", "2001:db8:44::2/64", "dev", "eth2").returncode:
            raise RuntimeError("Disposable peer IPv6 address failed.")
        peer_addressed = True
        if not peer_run("sh", "-c", "ps -eo stat=,comm= | awk '$2==\"zebra\" && $1 !~ /^Z/'").stdout.strip():
            if peer_run("/usr/lib/frr/zebra", "-d", "-u", "frr", "-g", "frr", "-A", "127.0.0.1").returncode:
                raise RuntimeError("Disposable zebra daemon failed to start.")
            zebra_started = True
        if peer_run("/usr/lib/frr/ospf6d", "-d", "-u", "frr", "-g", "frr", "-A", "127.0.0.1").returncode:
            raise RuntimeError("Disposable OSPFv3 daemon failed to start.")
        ospf_started = True
        peer_config_attempted = True
        peer_vty("interface eth2", "ipv6 ospf6 area 0.0.0.0", "exit", "router ospf6", "ospf6 router-id 198.18.44.2")
        executor.connect()
        preflight = executor.assess(spec)
        if preflight.action != APPLY or not preflight.restorable:
            raise RuntimeError("NMAS OSPFv3 preflight could not derive a safe inverse.")
        if not executor.apply(spec, preflight).ok:
            raise RuntimeError(f"NMAS cEOS OSPFv3 apply was rejected: {getattr(executor._conn, 'last_config_output', '')[:600]!r}")
        for attempt in range(16):
            observed = live.read_device(device)
            full = any(n.get("family") == "OSPFV3" and n.get("state") == "FULL" and n.get("interface") == "Ethernet2"
                       for n in observed.facts("ospf") or [])
            if full:
                break
            if attempt < 15:
                time.sleep(1)
        running = executor._conn.send_command("show running-config")
        parsed = parser_ceos.parse(running)
        imported = any(i.family == "ospf" and i.fields.get("version") == "OSPFV3" and
                       i.fields.get("process_id") == 44 and
                       any(b.get("interface_name") == "Ethernet2" for b in i.bindings)
                       for i in parsed.routing_instances)
        semantic = any(row["protocol"] == "ospf" and row["version"] == "OSPFV3" and row["process_id"] == 44 and
                       row["router_id"] == "198.18.44.1" and
                       any(b.get("interface_name") == "Ethernet2" and b.get("area") == "0" and not b.get("passive")
                           for b in row["bindings"]) for row in observed.facts("routing_config") or [])
        if not (full and imported and semantic):
            peer_output = peer_run("vtysh", "-c", "show ipv6 ospf6 neighbor")
            raise RuntimeError(f"OSPFv3 postcheck failed: FULL={full}, import={imported}, semantic={semantic}; NMAS={observed.facts('ospf')}; FRR={peer_output.stdout[:500]!r}")
    finally:
        try:
            if eos_attempted and preflight is not None:
                compensated = executor.compensate(spec, preflight).status == "COMPENSATED"
            executor.close()
            if eos_attempted:
                for command in (("default interface Ethernet2",) if compensated else
                                ("no ipv6 router ospf 44", "default interface Ethernet2")):
                    try: eos(command, config=True)
                    except RuntimeError as exc: cleanup_errors.append(str(exc))
            if routing_enabled:
                try: eos("no ipv6 unicast-routing", config=True)
                except RuntimeError as exc: cleanup_errors.append(str(exc))
            if peer_config_attempted:
                for commands in (("no router ospf6",), ("interface eth2", "no ipv6 ospf6 area 0.0.0.0")):
                    try: peer_vty(*commands)
                    except RuntimeError as exc: cleanup_errors.append(str(exc))
            if peer_addressed and peer_run("ip", "-6", "addr", "del", "2001:db8:44::2/64", "dev", "eth2").returncode:
                cleanup_errors.append("Peer IPv6 address removal failed")
            if mtu_changed and peer_run("ip", "link", "set", "dev", "eth2", "mtu", str(original_mtu)).returncode:
                cleanup_errors.append("Peer MTU restoration failed")
            if ra_changed and peer_run("sysctl", "-w", f"net.ipv6.conf.eth2.accept_ra={ra_before.stdout.strip()}").returncode:
                cleanup_errors.append("Peer RA setting restoration failed")
        finally:
            if ospf_started: peer_run("sh", "-c", "pkill -x ospf6d")
            if zebra_started: peer_run("sh", "-c", "pkill -x zebra")
    after = eos("show running-config")
    peer_after = peer_run("ip", "-j", "addr", "show", "dev", "eth2")
    final = live.read_device(device)
    restored = not cleanup_errors and "ipv6 router ospf 44" not in after and \
        "no ipv6 unicast-routing" in eos("show running-config all") and \
        eos("show running-config interfaces Ethernet2").strip() == "interface Ethernet2" and \
        final.live_reachable and not any(n.get("family") == "OSPFV3" for n in final.facts("ospf") or []) and \
        peer_after.returncode == 0 and int(json.loads(peer_after.stdout)[0]["mtu"]) == original_mtu and \
        not any(a.get("local") == "2001:db8:44::2" for i in json.loads(peer_after.stdout) for a in i.get("addr_info", []))
    if not restored:
        raise RuntimeError(f"Disposable OSPFv3 cleanup did not restore baseline: {cleanup_errors}")
    return LiveVerification("arista_ceos", "ceos", "Ethernet2", "2001:db8:44::1/64", True, True, compensated, True,
                            f"isolated cEOS/FRR OSPFv3: NMAS rendered/applied process and binding; adjacency reached FULL; live import matched; NMAS compensation={compensated}; baseline restored")


def verify_ceos_ripv2() -> LiveVerification:
    """Apply modeled cEOS RIPv2 and prove routes in both directions."""
    from ..config_import import parser_ceos
    from .probe_cases import iface

    device, _, _ = _target("arista_ceos")
    peer = f"clab-{LAB}-peer"
    inspection = _run(["docker", "inspect", peer], timeout=10)
    if inspection.returncode:
        raise RuntimeError("Disposable RIP peer is unavailable.")
    (peer_doc,) = json.loads(inspection.stdout)
    if (peer_doc.get("Config") or {}).get("Labels", {}).get("containerlab") != LAB \
            or NETWORK not in (peer_doc.get("NetworkSettings") or {}).get("Networks", {}):
        raise RuntimeError("RIP peer is outside the isolated lab.")

    def peer_run(*args):
        return _run(["docker", "exec", peer, *args], timeout=30)

    def eos(command, *, config=False):
        payload = f"configure terminal\n{command}" if config else command
        result = _run(["docker", "exec", device["container"], "Cli", "-p", "15", "--abort-on-error", "-c", payload], timeout=30)
        if result.returncode or "% Error" in result.stdout or "% Invalid input" in result.stdout:
            raise RuntimeError(f"Disposable cEOS RIP {'write' if config else 'read'} failed: {command[:60]}")
        return result.stdout

    def peer_vty(*commands):
        result = peer_run("vtysh", "-c", "configure terminal", *(part for command in commands for part in ("-c", command)))
        if result.returncode or "% Unknown command" in result.stdout or "% Command incomplete" in result.stdout:
            raise RuntimeError(f"Disposable FRR RIP configuration failed: {commands[:2]}; {result.stdout[:180]}")

    before = eos("show running-config")
    peer_link_before = peer_run("ip", "-j", "addr", "show", "dev", "eth2")
    peer_lo_before = peer_run("ip", "-j", "addr", "show", "dev", "lo")
    if "no ip routing" not in before or "router rip" in before or "interface Loopback444" in before \
            or eos("show running-config interfaces Ethernet2").strip() != "interface Ethernet2" \
            or peer_link_before.returncode or peer_lo_before.returncode \
            or any(a.get("family") == "inet" for i in json.loads(peer_link_before.stdout) for a in i.get("addr_info", [])) \
            or any(a.get("local") == "198.51.100.1" for i in json.loads(peer_lo_before.stdout) for a in i.get("addr_info", [])) \
            or peer_run("sh", "-c", "ps -eo stat=,comm= | awk '$2==\"ripd\" && $1 !~ /^Z/'").stdout.strip():
        raise RuntimeError("RIPv2 baseline is not the expected disposable state.")
    initial = live.read_device(device)
    if not initial.live_reachable or any(r.get("prefix") == "198.51.100.0/24" for r in initial.facts("routes") or []):
        raise RuntimeError("cEOS RIP baseline route is already present or cannot be read.")

    case = sample("arista_ceos", by_key()["routing.RIPV2"])
    case.sections["interfaces"]["if_0000000000000001"]["name"] = "Ethernet2"
    loop_id = "if_0000000000000044"
    loop = iface("arista_ceos", "LOOPBACK", iid=loop_id)
    loop["name"] = "Loopback444"
    loop["addresses"] = {"addr_0000000000000044": {"id": "addr_0000000000000044", "sequence": 1,
        "family": "IPV4", "cidr": "203.0.113.1/24", "source": "MANUAL", "role": "PRIMARY", "ipam_prefix": ""}}
    case.sections["interfaces"][loop_id] = loop
    rip_instance = next(iter(case.sections["routing"]["rip"].values()))
    rip_instance["interfaces"]["bind_0000000000000044"] = {
        "id": "bind_0000000000000044", "interface_id": loop_id, "passive": False}
    rendered = _descriptors("arista_ceos", case.sections)
    start = rendered.index("router rip")
    lines = [line for line in rendered[start:] if line.strip() and not line.lstrip().startswith("!")]
    lines = lines[:next((i for i, line in enumerate(lines[1:], 1) if not line.startswith(" ")), len(lines))]
    if "   no shutdown" not in lines or "   network 198.18.0.0/30" not in lines \
            or "   network 203.0.113.0/24" not in lines or any("UNSUPPORTED" in line for line in lines):
        raise RuntimeError("NMAS RIP renderer omitted enable/link/advertised prefix or refused the live sample.")
    spec = ConfigletSpec("P4-EOS-RIP2", 1, "ceos", "arista_ceos", "routing_rip", "CREATE_DEFINE",
                         tuple(lines), {"interface": "Ethernet2", "version": "RIPV2"})
    executor = CeosExecutor(device, connection_factory=DockerEosConfigConnection, reader=live.read_device)
    routing_enabled = eos_attempted = peer_link = peer_loop = peer_config = False
    preflight = None
    compensated = False
    zebra_started = rip_started = False
    learned = peer_learned = imported = False
    cleanup_errors = []
    try:
        eos("ip routing", config=True)
        routing_enabled = True
        eos_attempted = True
        eos("interface Ethernet2\nno switchport\nip address 198.18.0.1/30\nno shutdown", config=True)
        eos("interface Loopback444\nip address 203.0.113.1/24", config=True)
        if peer_run("ip", "addr", "add", "198.18.0.2/30", "dev", "eth2").returncode:
            raise RuntimeError("Disposable RIP peer link address failed.")
        peer_link = True
        if peer_run("ip", "addr", "add", "198.51.100.1/24", "dev", "lo").returncode:
            raise RuntimeError("Disposable RIP peer loopback address failed.")
        peer_loop = True
        if not peer_run("sh", "-c", "ps -eo stat=,comm= | awk '$2==\"zebra\" && $1 !~ /^Z/'").stdout.strip():
            if peer_run("/usr/lib/frr/zebra", "-d", "-u", "frr", "-g", "frr", "-A", "127.0.0.1").returncode:
                raise RuntimeError("Disposable zebra daemon failed to start.")
            zebra_started = True
        if peer_run("/usr/lib/frr/ripd", "-d", "-u", "frr", "-g", "frr", "-A", "127.0.0.1").returncode:
            raise RuntimeError("Disposable RIP daemon failed to start.")
        rip_started = True
        peer_config = True
        peer_vty("router rip", "version 2", "network 198.18.0.0/30", "network 198.51.100.0/24",
                 "passive-interface lo")
        executor.connect()
        preflight = executor.assess(spec)
        if preflight.action != APPLY or not preflight.restorable:
            raise RuntimeError("NMAS RIP preflight could not derive a safe inverse.")
        outcome = executor.apply(spec, preflight)
        if not outcome.ok:
            raise RuntimeError(f"NMAS cEOS RIP apply was rejected: {getattr(executor._conn, 'last_config_output', '')[:600]!r}")
        for attempt in range(30):
            observed = live.read_device(device)
            learned = any(r.get("prefix") == "198.51.100.0/24" and "rip" in str(r.get("type", "")).lower()
                          for r in observed.facts("routes") or [])
            peer_routes = peer_run("vtysh", "-c", "show ip route rip")
            peer_learned = peer_routes.returncode == 0 and "203.0.113.0/24" in peer_routes.stdout
            if learned and peer_learned:
                break
            if attempt < 29:
                time.sleep(2)
        parsed = parser_ceos.parse(executor._conn.send_command("show running-config"))
        imported = any(i.family == "rip" and {"Ethernet2", "Loopback444"}.issubset(
                       {b.get("interface_name") for b in i.bindings}) for i in parsed.routing_instances)
        semantic = any(row["protocol"] == "rip" and row["version"] == "IPV4" and row["enabled"] and
                       {"Ethernet2", "Loopback444"}.issubset({b.get("interface_name") for b in row["bindings"]})
                       for row in observed.facts("routing_config") or [])
        if not (learned and peer_learned and imported and semantic):
            eos_status = executor._conn.send_command("show ip rip")
            peer_status = peer_run("vtysh", "-c", "show ip rip status")
            raise RuntimeError(f"RIPv2 postcheck failed: learned={learned}, peer_learned={peer_learned}, "
                               f"imported={imported}, semantic={semantic}; EOS routes={observed.facts('routes')}; "
                               f"EOS RIP={eos_status[:500]!r}; FRR status={peer_status.stdout[:500]!r}")
    finally:
        try:
            if eos_attempted and preflight is not None:
                compensated = executor.compensate(spec, preflight).status == "COMPENSATED"
            executor.close()
            if eos_attempted:
                for command in (("no interface Loopback444", "default interface Ethernet2") if compensated else
                                ("no router rip", "no interface Loopback444", "default interface Ethernet2")):
                    try: eos(command, config=True)
                    except RuntimeError as exc: cleanup_errors.append(str(exc))
            if routing_enabled:
                try: eos("no ip routing", config=True)
                except RuntimeError as exc: cleanup_errors.append(str(exc))
            if peer_config:
                try: peer_vty("no router rip")
                except RuntimeError as exc: cleanup_errors.append(str(exc))
            if peer_loop and peer_run("ip", "addr", "del", "198.51.100.1/24", "dev", "lo").returncode:
                cleanup_errors.append("Peer loopback removal failed")
            if peer_link and peer_run("ip", "addr", "del", "198.18.0.2/30", "dev", "eth2").returncode:
                cleanup_errors.append("Peer link removal failed")
        finally:
            if rip_started: peer_run("sh", "-c", "pkill -x ripd")
            if zebra_started: peer_run("sh", "-c", "pkill -x zebra")
    after = eos("show running-config")
    final = live.read_device(device)
    peer_after = peer_run("ip", "-j", "addr", "show", "dev", "eth2")
    peer_lo_after = peer_run("ip", "-j", "addr", "show", "dev", "lo")
    restored = not cleanup_errors and "router rip" not in after and "interface Loopback444" not in after \
        and "no ip routing" in after and eos("show running-config interfaces Ethernet2").strip() == "interface Ethernet2" \
        and final.live_reachable and not any(r.get("prefix") == "198.51.100.0/24" for r in final.facts("routes") or []) \
        and peer_after.returncode == 0 and peer_lo_after.returncode == 0 \
        and not any(a.get("family") == "inet" for i in json.loads(peer_after.stdout) for a in i.get("addr_info", [])) \
        and not any(a.get("local") == "198.51.100.1" for i in json.loads(peer_lo_after.stdout) for a in i.get("addr_info", []))
    if not restored:
        raise RuntimeError(f"Disposable RIP cleanup did not restore baseline: {cleanup_errors}")
    return LiveVerification("arista_ceos", "ceos", "Ethernet2", "198.18.0.1/30", True, True, compensated, True,
                            f"isolated cEOS/FRR RIPv2: NMAS rendered/applied enabled RIP process and two networks; both peers learned the other's advertised prefix; live import matched; NMAS compensation={compensated}; baseline restored")


def verify_ceos_ripng_absence() -> str:
    """Probe cEOS RIPng grammar only on the pinned disposable device."""
    device, _, _ = _target("arista_ceos")
    before_run = _run(["docker", "exec", device["container"], "Cli", "-p", "15", "-c", "show running-config"], timeout=30)
    if before_run.returncode or any(token in before_run.stdout for token in ("router ripng", "ipv6 router rip")):
        raise RuntimeError("RIPng baseline is unavailable or already contains RIPng configuration.")
    if not live.read_device(device).live_reachable:
        raise RuntimeError("Isolated cEOS live read failed before RIPng grammar probe.")
    commands = ("ipv6 router rip NMAS_CAP44", "router ripng NMAS_CAP44", "ipv6 router rip", "router ripng")
    results = []
    try:
        for command in commands:
            payload = "configure terminal\n" + command
            result = _run(["docker", "exec", device["container"], "Cli", "-p", "15", "--abort-on-error", "-c", payload], timeout=30)
            results.append((command, result.returncode, result.stdout))
    finally:
        # If a future image accepts any form, remove it before refusing a conclusion.
        for command in commands:
            _run(["docker", "exec", device["container"], "Cli", "-p", "15", "--abort-on-error", "-c",
                  "configure terminal\nno " + command], timeout=30)
    after_run = _run(["docker", "exec", device["container"], "Cli", "-p", "15", "-c", "show running-config"], timeout=30)
    if after_run.returncode or after_run.stdout != before_run.stdout:
        raise RuntimeError("Disposable cEOS configuration changed during RIPng grammar investigation.")
    if not all(code != 0 and "% Invalid input at line 2" in output for _, code, output in results):
        raise RuntimeError("RIPng syntax did not consistently fail; platform support requires further investigation.")
    return "isolated cEOS 4.36.2F: four RIPng process command forms were rejected by native CLI at line 2; live read succeeded and exact running-config baseline was preserved"


def verify_ceos_isis_native() -> str:
    """Exercise native IS-IS interoperability while NMAS has no ISIS renderer."""
    device, _, _ = _target("arista_ceos")
    peer = f"clab-{LAB}-peer"
    inspection = _run(["docker", "inspect", peer], timeout=10)
    if inspection.returncode:
        raise RuntimeError("Disposable IS-IS peer is unavailable.")
    (peer_doc,) = json.loads(inspection.stdout)
    if (peer_doc.get("Config") or {}).get("Labels", {}).get("containerlab") != LAB \
            or NETWORK not in (peer_doc.get("NetworkSettings") or {}).get("Networks", {}):
        raise RuntimeError("IS-IS peer is outside the isolated lab.")

    def peer_run(*args):
        return _run(["docker", "exec", peer, *args], timeout=30)

    def eos(command, *, config=False):
        payload = f"configure terminal\n{command}" if config else command
        result = _run(["docker", "exec", device["container"], "Cli", "-p", "15", "--abort-on-error", "-c", payload], timeout=30)
        if result.returncode or "% Error" in result.stdout or "% Invalid input" in result.stdout:
            raise RuntimeError(f"Disposable cEOS IS-IS {'write' if config else 'read'} failed: {command[:60]}; {result.stdout[:180]}")
        return result.stdout

    def peer_vty(*commands):
        result = peer_run("vtysh", "-c", "configure terminal", *(part for command in commands for part in ("-c", command)))
        if result.returncode or "% Unknown command" in result.stdout or "% Command incomplete" in result.stdout:
            raise RuntimeError(f"Disposable FRR IS-IS configuration failed: {commands[:2]}; {result.stdout[:180]}")

    before = eos("show running-config")
    peer_before = peer_run("ip", "-j", "addr", "show", "dev", "eth2")
    peer_lo_before = peer_run("ip", "-j", "addr", "show", "dev", "lo")
    if "no ip routing" not in before or "router isis NMAS44" in before or "interface Loopback444" in before \
            or eos("show running-config interfaces Ethernet2").strip() != "interface Ethernet2" \
            or peer_before.returncode or peer_lo_before.returncode \
            or any(a.get("family") == "inet" for i in json.loads(peer_before.stdout) for a in i.get("addr_info", [])) \
            or any(a.get("local") == "198.51.100.1" for i in json.loads(peer_lo_before.stdout) for a in i.get("addr_info", [])) \
            or peer_run("sh", "-c", "ps -eo stat=,comm= | awk '$2==\"isisd\" && $1 !~ /^Z/'").stdout.strip():
        raise RuntimeError("IS-IS baseline is not the expected disposable state.")
    original_mtu = int(json.loads(peer_before.stdout)[0]["mtu"])
    initial = live.read_device(device)
    if not initial.live_reachable or any(r.get("prefix") == "198.51.100.0/24" for r in initial.facts("routes") or []):
        raise RuntimeError("cEOS IS-IS baseline route is already present or cannot be read.")
    routing_enabled = eos_attempted = mtu_changed = peer_link = peer_loop = peer_config = False
    zebra_started = isis_started = False
    adjacency = learned = peer_learned = False
    cleanup_errors = []
    try:
        eos("ip routing", config=True)
        routing_enabled = True
        eos_attempted = True
        eos("interface Ethernet2\nno switchport\nip address 198.18.0.1/30\nno shutdown", config=True)
        eos("interface Loopback444\nip address 203.0.113.1/24", config=True)
        if original_mtu != 1500:
            if peer_run("ip", "link", "set", "dev", "eth2", "mtu", "1500").returncode:
                raise RuntimeError("Disposable IS-IS peer MTU alignment failed.")
            mtu_changed = True
        if peer_run("ip", "addr", "add", "198.18.0.2/30", "dev", "eth2").returncode:
            raise RuntimeError("Disposable IS-IS peer link address failed.")
        peer_link = True
        if peer_run("ip", "addr", "add", "198.51.100.1/24", "dev", "lo").returncode:
            raise RuntimeError("Disposable IS-IS peer loopback address failed.")
        peer_loop = True
        if not peer_run("sh", "-c", "ps -eo stat=,comm= | awk '$2==\"zebra\" && $1 !~ /^Z/'").stdout.strip():
            if peer_run("/usr/lib/frr/zebra", "-d", "-u", "frr", "-g", "frr", "-A", "127.0.0.1").returncode:
                raise RuntimeError("Disposable zebra daemon failed to start.")
            zebra_started = True
        if peer_run("/usr/lib/frr/isisd", "-d", "-u", "frr", "-g", "frr", "-A", "127.0.0.1").returncode:
            raise RuntimeError("Disposable IS-IS daemon failed to start.")
        isis_started = True
        peer_config = True
        peer_vty("router isis NMAS44", "net 49.0001.0000.0000.0045.00", "is-type level-2-only", "metric-style wide",
                 "exit", "interface eth2", "ip router isis NMAS44", "isis network point-to-point",
                 "isis circuit-type level-2-only", "exit", "interface lo", "ip router isis NMAS44")
        eos("router isis NMAS44\nnet 49.0001.0000.0000.0044.00\nis-type level-2\naddress-family ipv4 unicast", config=True)
        eos("interface Ethernet2\nisis enable NMAS44\nisis network point-to-point", config=True)
        eos("interface Loopback444\nisis enable NMAS44", config=True)
        for attempt in range(24):
            neighbors = eos("show isis neighbors")
            adjacency = "NMAS44" in neighbors and "peer" in neighbors and "UP" in neighbors and "Ethernet2" in neighbors
            observed = live.read_device(device)
            learned = any(r.get("prefix") == "198.51.100.0/24" and "isis" in str(r.get("type", "")).lower()
                          for r in observed.facts("routes") or [])
            peer_routes = peer_run("vtysh", "-c", "show ip route isis")
            peer_learned = peer_routes.returncode == 0 and "203.0.113.0/24" in peer_routes.stdout
            if adjacency and learned and peer_learned:
                break
            if attempt < 23:
                time.sleep(2)
        if not (adjacency and learned and peer_learned):
            peer_neighbors = peer_run("vtysh", "-c", "show isis neighbor")
            raise RuntimeError(f"Native IS-IS test failed: adjacency={adjacency}, cEOS learned={learned}, FRR learned={peer_learned}; "
                               f"EOS neighbors={neighbors[:500]!r}; FRR neighbors={peer_neighbors.stdout[:500]!r}; "
                               f"EOS routes={observed.facts('routes')}")
    finally:
        if eos_attempted:
            for command in ("no router isis NMAS44", "no interface Loopback444", "default interface Ethernet2"):
                try: eos(command, config=True)
                except RuntimeError as exc: cleanup_errors.append(str(exc))
        if routing_enabled:
            try: eos("no ip routing", config=True)
            except RuntimeError as exc: cleanup_errors.append(str(exc))
        if peer_config:
            for commands in (("interface eth2", "no ip router isis NMAS44"),
                             ("interface lo", "no ip router isis NMAS44"), ("no router isis NMAS44",)):
                try: peer_vty(*commands)
                except RuntimeError as exc: cleanup_errors.append(str(exc))
        if peer_loop and peer_run("ip", "addr", "del", "198.51.100.1/24", "dev", "lo").returncode:
            cleanup_errors.append("Peer loopback removal failed")
        if peer_link and peer_run("ip", "addr", "del", "198.18.0.2/30", "dev", "eth2").returncode:
            cleanup_errors.append("Peer link removal failed")
        if mtu_changed and peer_run("ip", "link", "set", "dev", "eth2", "mtu", str(original_mtu)).returncode:
            cleanup_errors.append("Peer MTU restoration failed")
        if isis_started: peer_run("sh", "-c", "pkill -x isisd")
        if zebra_started: peer_run("sh", "-c", "pkill -x zebra")
    after = eos("show running-config")
    final = live.read_device(device)
    peer_after = peer_run("ip", "-j", "addr", "show", "dev", "eth2")
    restored = not cleanup_errors and "router isis NMAS44" not in after and "interface Loopback444" not in after \
        and "no ip routing" in after and eos("show running-config interfaces Ethernet2").strip() == "interface Ethernet2" \
        and final.live_reachable and not any(r.get("prefix") == "198.51.100.0/24" for r in final.facts("routes") or []) \
        and peer_after.returncode == 0 and int(json.loads(peer_after.stdout)[0]["mtu"]) == original_mtu \
        and not any(a.get("family") == "inet" for i in json.loads(peer_after.stdout) for a in i.get("addr_info", []))
    if not restored:
        raise RuntimeError(f"Disposable IS-IS cleanup did not restore baseline: {cleanup_errors}")
    return "isolated cEOS 4.36.2F / FRR 8.4.4: native IS-IS reached UP adjacency and exchanged IPv4 loopback prefixes in both directions; NMAS normalized route read saw the learned route; manual inverse restored both baselines (NMAS ISIS renderer/executor/postcheck/compensation absent)"


def verify_ceos_eigrp_absence(family="IPV4") -> str:
    """Check both plausible EIGRP process forms on the disposable cEOS."""
    if family not in {"IPV4", "IPV6"}:
        raise ValueError("Only explicit EIGRP IPv4/IPv6 checks are accepted.")
    device, _, _ = _target("arista_ceos")
    before = _run(["docker", "exec", device["container"], "Cli", "-p", "15", "-c", "show running-config"], timeout=30)
    if before.returncode or "router eigrp" in before.stdout:
        raise RuntimeError("EIGRP baseline is unavailable or already contains an EIGRP process.")
    if not live.read_device(device).live_reachable:
        raise RuntimeError("Isolated cEOS live read failed before EIGRP grammar probe.")
    prefix = "ipv6 router eigrp" if family == "IPV6" else "router eigrp"
    commands = (f"{prefix} 44", prefix)
    results = []
    try:
        for command in commands:
            result = _run(["docker", "exec", device["container"], "Cli", "-p", "15", "--abort-on-error", "-c",
                           "configure terminal\n" + command], timeout=30)
            results.append((result.returncode, result.stdout))
    finally:
        for command in commands:
            _run(["docker", "exec", device["container"], "Cli", "-p", "15", "--abort-on-error", "-c",
                  "configure terminal\nno " + command], timeout=30)
    after = _run(["docker", "exec", device["container"], "Cli", "-p", "15", "-c", "show running-config"], timeout=30)
    if after.returncode or after.stdout != before.stdout:
        raise RuntimeError("Disposable cEOS configuration changed during EIGRP grammar investigation.")
    if not all(code != 0 and "% Invalid input at line 2" in output for code, output in results):
        raise RuntimeError("EIGRP process syntax did not consistently fail; platform support needs investigation.")
    return f"isolated cEOS 4.36.2F: native {family} EIGRP process forms with and without ASN were rejected at line 2; NMAS live read succeeded and exact running-config baseline was preserved"


def verify_ceos_routed_physical() -> LiveVerification:
    """Apply the actual routed-port candidate and prove IPv4/IPv6 traffic."""
    from ..config_import import parser_ceos

    device, _, _ = _target("arista_ceos")
    peer = f"clab-{LAB}-peer"
    inspection = _run(["docker", "inspect", peer], timeout=10)
    if inspection.returncode:
        raise RuntimeError("Disposable routed-port peer is unavailable.")
    (peer_doc,) = json.loads(inspection.stdout)
    if (peer_doc.get("Config") or {}).get("Labels", {}).get("containerlab") != LAB \
            or NETWORK not in (peer_doc.get("NetworkSettings") or {}).get("Networks", {}):
        raise RuntimeError("Routed-port peer is outside the isolated lab.")

    def peer_run(*args):
        return _run(["docker", "exec", peer, *args], timeout=30)

    def eos(command, *, config=False):
        payload = f"configure terminal\n{command}" if config else command
        result = _run(["docker", "exec", device["container"], "Cli", "-p", "15", "--abort-on-error", "-c", payload], timeout=30)
        if result.returncode or "% Error" in result.stdout or "% Invalid input" in result.stdout:
            raise RuntimeError(f"Disposable cEOS routed-port {'write' if config else 'read'} failed: {command[:60]}")
        return result.stdout

    before = eos("show running-config interfaces Ethernet2")
    global_before = eos("show running-config")
    peer_before = peer_run("ip", "-j", "addr", "show", "dev", "eth2")
    ra_before = peer_run("sysctl", "-n", "net.ipv6.conf.eth2.accept_ra")
    if before.strip() != "interface Ethernet2" or "no ip routing" not in global_before \
            or "no ipv6 unicast-routing" not in eos("show running-config all") \
            or peer_before.returncode or ra_before.returncode \
            or ra_before.stdout.strip() not in {"0", "1", "2"} \
            or any(a.get("family") == "inet" or a.get("family") == "inet6" and a.get("scope") == "global"
                   for i in json.loads(peer_before.stdout) for a in i.get("addr_info", [])):
        raise RuntimeError("Routed-port link is not at its disposable baseline.")
    original_mtu = int(json.loads(peer_before.stdout)[0]["mtu"])
    initial = live.read_device(device)
    if not initial.live_reachable or (initial.facts("addresses") or {}).get("Ethernet2"):
        raise RuntimeError("Routed-port pre-read failed or Ethernet2 already has addresses.")
    case = sample("arista_ceos", by_key()["interface.ROUTED_PHYSICAL"])
    case.sections["interfaces"]["if_0000000000000001"]["name"] = "Ethernet2"
    rendered = _descriptors("arista_ceos", case.sections)
    start = rendered.index("interface Ethernet2")
    lines = [line for line in rendered[start:] if line.strip() and not line.lstrip().startswith("!")]
    lines = lines[:next((i for i, line in enumerate(lines[1:], 1) if not line.startswith(" ")), len(lines))]
    if not all(line in lines for line in ("   no switchport", "   ip address 198.18.0.1/30",
                                           "   ipv6 address 2001:db8:44::1/64", "   no shutdown")):
        raise RuntimeError("NMAS routed-port renderer omitted required L3 interface commands.")
    spec = ConfigletSpec("P4-EOS-ROUTED", 1, "ceos", "arista_ceos", "interface", "CREATE_DEFINE",
                         tuple(lines), {"interface": "Ethernet2", "admin_enabled": True})
    executor = CeosExecutor(device, connection_factory=DockerEosConfigConnection, reader=live.read_device)
    attempted = peer_v4 = peer_v6 = mtu_changed = ra_changed = ip_enabled = ipv6_enabled = False
    observed_ok = parsed_ok = ping_v4 = ping_v6 = False
    cleanup_errors = []
    try:
        if ra_before.stdout.strip() != "0":
            if peer_run("sysctl", "-w", "net.ipv6.conf.eth2.accept_ra=0").returncode:
                raise RuntimeError("Disposable peer RA suppression failed.")
            ra_changed = True
        if original_mtu != 1500:
            if peer_run("ip", "link", "set", "dev", "eth2", "mtu", "1500").returncode:
                raise RuntimeError("Disposable peer MTU alignment failed.")
            mtu_changed = True
        if peer_run("ip", "addr", "add", "198.18.0.2/30", "dev", "eth2").returncode:
            raise RuntimeError("Disposable peer IPv4 address failed.")
        peer_v4 = True
        if peer_run("ip", "-6", "addr", "add", "2001:db8:44::2/64", "dev", "eth2").returncode:
            raise RuntimeError("Disposable peer IPv6 address failed.")
        peer_v6 = True
        eos("ip routing", config=True)
        ip_enabled = True
        eos("ipv6 unicast-routing", config=True)
        ipv6_enabled = True
        executor.connect()
        preflight = executor.assess(spec)
        if preflight.action != APPLY or preflight.restorable:
            raise RuntimeError("Existing physical interface unexpectedly appears fully compensable in NMAS preflight.")
        attempted = True
        outcome = executor.apply(spec, preflight)
        if not outcome.ok:
            raise RuntimeError(f"NMAS routed-port apply was rejected: {getattr(executor._conn, 'last_config_output', '')[:500]!r}")
        for attempt in range(8):
            observed = live.read_device(device)
            addresses = (observed.facts("addresses") or {}).get("Ethernet2", [])
            observed_ok = observed.live_reachable and "198.18.0.1/30" in addresses and "2001:db8:44::1/64" in addresses
            ping4_text = eos("ping 198.18.0.2 repeat 2")
            ping6_text = eos("ping ipv6 2001:db8:44::2 repeat 2")
            ping_v4 = "0% packet loss" in ping4_text or "100 percent" in ping4_text
            ping_v6 = "0% packet loss" in ping6_text or "100 percent" in ping6_text
            if observed_ok and ping_v4 and ping_v6:
                break
            if attempt < 7:
                time.sleep(1)
        running = executor._conn.send_command("show running-config")
        parsed = parser_ceos.parse(running)
        parsed_ok = any(i.name == "Ethernet2" and i.kind == "ROUTED_PHYSICAL" and
                        {"198.18.0.1/30", "2001:db8:44::1/64"}.issubset({a["cidr"] for a in i.addresses})
                        for i in parsed.interfaces)
        if not (observed_ok and ping_v4 and ping_v6 and parsed_ok):
            raise RuntimeError(f"Routed-port functional postcheck failed: addresses={observed_ok}, ping4={ping_v4}, "
                               f"ping6={ping_v6}, parsed={parsed_ok}")
    finally:
        executor.close()
        if attempted:
            try: eos("default interface Ethernet2", config=True)
            except RuntimeError as exc: cleanup_errors.append(str(exc))
        if ipv6_enabled:
            try: eos("no ipv6 unicast-routing", config=True)
            except RuntimeError as exc: cleanup_errors.append(str(exc))
        if ip_enabled:
            try: eos("no ip routing", config=True)
            except RuntimeError as exc: cleanup_errors.append(str(exc))
        if peer_v6 and peer_run("ip", "-6", "addr", "del", "2001:db8:44::2/64", "dev", "eth2").returncode:
            cleanup_errors.append("Peer IPv6 address removal failed")
        if peer_v4 and peer_run("ip", "addr", "del", "198.18.0.2/30", "dev", "eth2").returncode:
            cleanup_errors.append("Peer IPv4 address removal failed")
        if mtu_changed and peer_run("ip", "link", "set", "dev", "eth2", "mtu", str(original_mtu)).returncode:
            cleanup_errors.append("Peer MTU restoration failed")
        if ra_changed and peer_run("sysctl", "-w", f"net.ipv6.conf.eth2.accept_ra={ra_before.stdout.strip()}").returncode:
            cleanup_errors.append("Peer RA setting restoration failed")
    final = live.read_device(device)
    after = eos("show running-config interfaces Ethernet2")
    peer_after = peer_run("ip", "-j", "addr", "show", "dev", "eth2")
    restored = not cleanup_errors and after == before and "no ip routing" in eos("show running-config") \
        and "no ipv6 unicast-routing" in eos("show running-config all") and final.live_reachable \
        and not (final.facts("addresses") or {}).get("Ethernet2") and peer_after.returncode == 0 \
        and int(json.loads(peer_after.stdout)[0]["mtu"]) == original_mtu \
        and not any(a.get("family") == "inet" or a.get("family") == "inet6" and a.get("scope") == "global"
                    for i in json.loads(peer_after.stdout) for a in i.get("addr_info", []))
    if not restored:
        raise RuntimeError(f"Disposable routed-port cleanup did not restore baseline: {cleanup_errors}")
    return LiveVerification("arista_ceos", "ceos", "Ethernet2", "198.18.0.1/30 + 2001:db8:44::1/64", True, True,
                            False, True, "isolated cEOS Ethernet2: NMAS rendered/applied routed physical interface; normalized live addresses and native parser matched; IPv4 and IPv6 peer pings passed; manual default-interface inverse restored baseline (NMAS cannot compensate modification of an existing physical port)")


def verify_ceos_switchport(kind="ACCESS") -> LiveVerification:
    """Prove access or trunk forwarding through disposable SVIs and Linux peer."""
    from ..config_import import parser_ceos

    if kind not in {"ACCESS", "TRUNK"}:
        raise ValueError("Only bounded ACCESS/TRUNK switchport probes are accepted.")
    trunk = kind == "TRUNK"
    device, _, _ = _target("arista_ceos")
    peer = f"clab-{LAB}-peer"
    inspection = _run(["docker", "inspect", peer], timeout=10)
    if inspection.returncode:
        raise RuntimeError("Disposable switchport peer is unavailable.")
    (peer_doc,) = json.loads(inspection.stdout)
    if (peer_doc.get("Config") or {}).get("Labels", {}).get("containerlab") != LAB \
            or NETWORK not in (peer_doc.get("NetworkSettings") or {}).get("Networks", {}):
        raise RuntimeError("Switchport peer is outside the isolated lab.")

    def peer_run(*args):
        return _run(["docker", "exec", peer, *args], timeout=30)

    def eos(command, *, config=False):
        payload = f"configure terminal\n{command}" if config else command
        result = _run(["docker", "exec", device["container"], "Cli", "-p", "15", "--abort-on-error", "-c", payload], timeout=30)
        if result.returncode or "% Error" in result.stdout or "% Invalid input" in result.stdout:
            raise RuntimeError(f"Disposable cEOS {kind} {'write' if config else 'read'} failed: {command[:60]}; {result.stdout[:200]}")
        return result.stdout

    before = eos("show running-config")
    peer_before = peer_run("ip", "-j", "addr", "show", "dev", "eth2")
    if "no ip routing" not in before or eos("show running-config interfaces Ethernet2").strip() != "interface Ethernet2" \
            or any(token in before for token in ("vlan 44", "vlan 45", "interface Vlan44", "interface Vlan45")) \
            or peer_before.returncode or any(a.get("family") == "inet" for i in json.loads(peer_before.stdout)
                                             for a in i.get("addr_info", [])) \
            or peer_run("ip", "link", "show", "dev", "eth2.45").returncode == 0:
        raise RuntimeError("Switchport/VLAN baseline is not the expected disposable state.")
    original_mtu = int(json.loads(peer_before.stdout)[0]["mtu"])
    initial = live.read_device(device)
    if not initial.live_reachable or any(v in (initial.facts("interfaces") or {}) for v in ("Vlan44", "Vlan45")):
        raise RuntimeError("Switchport pre-read failed or temporary SVIs already exist.")
    case = sample("arista_ceos", by_key()[f"interface.{kind}"])
    case.sections["interfaces"]["if_0000000000000001"]["name"] = "Ethernet2"
    rendered = _descriptors("arista_ceos", case.sections)
    start = rendered.index("interface Ethernet2")
    lines = [line for line in rendered[start:] if line.strip() and not line.lstrip().startswith("!")]
    lines = lines[:next((i for i, line in enumerate(lines[1:], 1) if not line.startswith(" ")), len(lines))]
    expected_line = "   switchport mode trunk" if trunk else "   switchport mode access"
    vlan_line = "   switchport trunk allowed vlan 44-45" if trunk else "   switchport access vlan 44"
    if expected_line not in lines or vlan_line not in lines or "   no shutdown" not in lines:
        raise RuntimeError("NMAS switchport renderer omitted the required mode or VLAN.")
    spec = ConfigletSpec(f"P4-EOS-{kind}", 1, "ceos", "arista_ceos", "interface", "CREATE_DEFINE",
                         tuple(lines), {"interface": "Ethernet2", "admin_enabled": True})
    executor = CeosExecutor(device, connection_factory=DockerEosConfigConnection, reader=live.read_device)
    eos_attempted = peer_native = peer_tagged = mtu_changed = False
    ping_native = ping_tagged = parsed_ok = read_ok = False
    cleanup_errors = []
    try:
        if original_mtu != 1500:
            if peer_run("ip", "link", "set", "dev", "eth2", "mtu", "1500").returncode:
                raise RuntimeError("Disposable peer MTU alignment failed.")
            mtu_changed = True
        if peer_run("ip", "addr", "add", "198.18.44.2/24", "dev", "eth2").returncode:
            raise RuntimeError("Disposable peer native/access VLAN address failed.")
        peer_native = True
        if trunk:
            if peer_run("ip", "link", "add", "link", "eth2", "name", "eth2.45", "type", "vlan", "id", "45").returncode:
                raise RuntimeError("Disposable peer VLAN45 interface creation failed.")
            peer_tagged = True
            if peer_run("ip", "addr", "add", "198.18.45.2/24", "dev", "eth2.45").returncode \
                    or peer_run("ip", "link", "set", "dev", "eth2.45", "up").returncode:
                raise RuntimeError("Disposable peer VLAN45 address/link setup failed.")
        eos_attempted = True
        eos("ip routing", config=True)
        for vlan in ((44, 45) if trunk else (44,)):
            eos(f"vlan {vlan}", config=True)
            eos(f"interface Vlan{vlan}\nip address 198.18.{vlan}.1/24\nno shutdown", config=True)
        executor.connect()
        preflight = executor.assess(spec)
        if preflight.action != APPLY or preflight.restorable:
            raise RuntimeError("Existing physical switchport unexpectedly appears fully compensable in NMAS preflight.")
        outcome = executor.apply(spec, preflight)
        if not outcome.ok:
            raise RuntimeError(f"NMAS {kind} apply was rejected: {getattr(executor._conn, 'last_config_output', '')[:500]!r}")
        for attempt in range(8):
            observed = live.read_device(device)
            read_ok = observed.live_reachable and "Ethernet2" in (observed.facts("interfaces") or {}) \
                and "198.18.44.1/24" in (observed.facts("addresses") or {}).get("Vlan44", [])
            native_output = eos("ping 198.18.44.2 repeat 2")
            ping_native = "0% packet loss" in native_output and "100% packet loss" not in native_output
            if trunk:
                tagged_output = eos("ping 198.18.45.2 repeat 2")
                ping_tagged = "0% packet loss" in tagged_output and "100% packet loss" not in tagged_output
            else:
                ping_tagged = True
            if read_ok and ping_native and ping_tagged:
                break
            if attempt < 7:
                time.sleep(1)
        parsed = parser_ceos.parse(executor._conn.send_command("show running-config"))
        parsed_ok = any(i.name == "Ethernet2" and i.kind == kind and
                        (i.trunk_allowed_vlans == [44, 45] if trunk else i.access_vlan == 44)
                        for i in parsed.interfaces)
        if not (read_ok and ping_native and ping_tagged and parsed_ok):
            raise RuntimeError(f"{kind} forwarding postcheck failed: read={read_ok}, native/access ping={ping_native}, "
                               f"tagged ping={ping_tagged}, parsed={parsed_ok}; "
                               f"native={native_output[:200]!r}; tagged={tagged_output[:200] if trunk else ''!r}; "
                               f"interface={eos('show running-config interfaces Ethernet2')[:500]!r}; "
                               f"parsed={[(i.name, i.kind, i.access_vlan, i.trunk_allowed_vlans) for i in parsed.interfaces if i.name == 'Ethernet2']!r}")
    finally:
        executor.close()
        if eos_attempted:
            for command in ("default interface Ethernet2", "no interface Vlan45", "no interface Vlan44",
                            "no vlan 45", "no vlan 44", "no ip routing"):
                try: eos(command, config=True)
                except RuntimeError as exc: cleanup_errors.append(str(exc))
        if peer_tagged and peer_run("ip", "link", "del", "dev", "eth2.45").returncode:
            cleanup_errors.append("Peer VLAN45 interface removal failed")
        if peer_native and peer_run("ip", "addr", "del", "198.18.44.2/24", "dev", "eth2").returncode:
            cleanup_errors.append("Peer native/access address removal failed")
        if mtu_changed and peer_run("ip", "link", "set", "dev", "eth2", "mtu", str(original_mtu)).returncode:
            cleanup_errors.append("Peer MTU restoration failed")
    after = eos("show running-config")
    peer_after = peer_run("ip", "-j", "addr", "show", "dev", "eth2")
    final = live.read_device(device)
    restored = not cleanup_errors and "no ip routing" in after and \
        eos("show running-config interfaces Ethernet2").strip() == "interface Ethernet2" and \
        not any(token in after for token in ("vlan 44", "vlan 45", "interface Vlan44", "interface Vlan45")) \
        and final.live_reachable and peer_after.returncode == 0 and \
        not any(a.get("family") == "inet" for i in json.loads(peer_after.stdout) for a in i.get("addr_info", [])) \
        and int(json.loads(peer_after.stdout)[0]["mtu"]) == original_mtu and \
        peer_run("ip", "link", "show", "dev", "eth2.45").returncode != 0
    if not restored:
        raise RuntimeError(f"Disposable {kind} cleanup did not restore baseline: {cleanup_errors}")
    detail = ("native VLAN44 and tagged VLAN45 pings passed" if trunk else "untagged VLAN44 ping passed")
    return LiveVerification("arista_ceos", "ceos", "Ethernet2", "VLAN44-45" if trunk else "VLAN44", True, True,
                            False, True, f"isolated cEOS Ethernet2 {kind}: NMAS renderer/executor applied switchport mode; {detail}; live import matched; manual inverse restored baseline (NMAS cannot compensate existing physical port)")


def verify_ceos_subinterface() -> LiveVerification:
    """Apply a rendered tagged child over a disposable routed parent and test traffic."""
    from ..config_import import parser_ceos

    device, _, _ = _target("arista_ceos")
    peer = f"clab-{LAB}-peer"
    inspection = _run(["docker", "inspect", peer], timeout=10)
    if inspection.returncode:
        raise RuntimeError("Disposable tagged peer is unavailable.")
    (peer_doc,) = json.loads(inspection.stdout)
    if (peer_doc.get("Config") or {}).get("Labels", {}).get("containerlab") != LAB \
            or NETWORK not in (peer_doc.get("NetworkSettings") or {}).get("Networks", {}):
        raise RuntimeError("Tagged peer is outside the isolated lab.")

    def peer_run(*args):
        return _run(["docker", "exec", peer, *args], timeout=30)

    def eos(command, *, config=False):
        payload = f"configure terminal\n{command}" if config else command
        result = _run(["docker", "exec", device["container"], "Cli", "-p", "15", "--abort-on-error", "-c", payload], timeout=30)
        if result.returncode or "% Error" in result.stdout or "% Invalid input" in result.stdout:
            raise RuntimeError(f"Disposable cEOS tagged-port command rejected: {command[:80]}; {result.stdout[:200]}")
        return result.stdout

    parent_before = eos("show running-config interfaces Ethernet2")
    global_before = eos("show running-config")
    peer_before = peer_run("ip", "-j", "addr", "show", "dev", "eth2")
    if parent_before.strip() != "interface Ethernet2" or "interface Ethernet2.44" in global_before \
            or "no ip routing" not in global_before or "no ipv6 unicast-routing" not in eos("show running-config all") \
            or peer_before.returncode or peer_run("ip", "link", "show", "dev", "eth2.44").returncode == 0:
        raise RuntimeError("Tagged-port baseline is not pristine.")
    original_mtu = int(json.loads(peer_before.stdout)[0]["mtu"])
    case = sample("arista_ceos", by_key()["interface.SUBINTERFACE"])
    case.sections["interfaces"]["if_0000000000000001"]["name"] = "Ethernet2.44"
    case.sections["interfaces"]["if_0000000000000002"]["name"] = "Ethernet2"
    rendered = _descriptors("arista_ceos", case.sections)
    start = rendered.index("interface Ethernet2.44")
    lines = [line for line in rendered[start:] if line.strip() and not line.lstrip().startswith("!")]
    lines = lines[:next((i for i, line in enumerate(lines[1:], 1) if not line.startswith(" ")), len(lines))]
    if not all(line in lines for line in ("   encapsulation dot1q vlan 44", "   ip address 198.18.0.1/30",
                                           "   ipv6 address 2001:db8:44::1/64", "   no shutdown")):
        raise RuntimeError("NMAS renderer omitted tagged child commands.")
    parent_spec = ConfigletSpec("P4-EOS-PARENT", 1, "ceos", "arista_ceos", "interface", "CREATE_DEFINE",
                                ("interface Ethernet2", "   no switchport", "   no shutdown"),
                                {"interface": "Ethernet2", "admin_enabled": True})
    child_spec = ConfigletSpec("P4-EOS-SUBIF", 1, "ceos", "arista_ceos", "interface", "CREATE_DEFINE",
                               tuple(lines), {"interface": "Ethernet2.44", "admin_enabled": True})
    executor = CeosExecutor(device, connection_factory=DockerEosConfigConnection, reader=live.read_device)
    peer_tagged = peer_v4 = peer_v6 = parent_attempted = child_attempted = ip_enabled = ipv6_enabled = mtu_changed = False
    child_assessment = None
    child_compensated = False
    success = False
    cleanup_errors = []
    try:
        if original_mtu != 1500:
            if peer_run("ip", "link", "set", "dev", "eth2", "mtu", "1500").returncode:
                raise RuntimeError("Peer MTU alignment failed.")
            mtu_changed = True
        if peer_run("ip", "link", "add", "link", "eth2", "name", "eth2.44", "type", "vlan", "id", "44").returncode:
            raise RuntimeError("Peer tagged link creation failed.")
        peer_tagged = True
        if peer_run("ip", "addr", "add", "198.18.0.2/30", "dev", "eth2.44").returncode:
            raise RuntimeError("Peer tagged IPv4 assignment failed.")
        peer_v4 = True
        if peer_run("ip", "-6", "addr", "add", "2001:db8:44::2/64", "dev", "eth2.44").returncode:
            raise RuntimeError("Peer tagged IPv6 assignment failed.")
        peer_v6 = True
        if peer_run("ip", "link", "set", "dev", "eth2.44", "up").returncode:
            raise RuntimeError("Peer tagged link enable failed.")
        eos("ip routing", config=True)
        ip_enabled = True
        eos("ipv6 unicast-routing", config=True)
        ipv6_enabled = True
        executor.connect()
        parent_assessment = executor.assess(parent_spec)
        if parent_assessment.action != APPLY or parent_assessment.restorable:
            raise RuntimeError("Physical parent compensation preflight unexpectedly changed.")
        parent_attempted = True
        if not executor.apply(parent_spec, parent_assessment).ok:
            raise RuntimeError(f"Parent apply rejected: {getattr(executor._conn, 'last_config_output', '')[:500]!r}")
        child_assessment = executor.assess(child_spec)
        if child_assessment.action != APPLY or not child_assessment.restorable:
            raise RuntimeError(f"Child creation has no inverse: {child_assessment.reason}")
        child_attempted = True
        if not executor.apply(child_spec, child_assessment).ok:
            raise RuntimeError(f"Child apply rejected: {getattr(executor._conn, 'last_config_output', '')[:500]!r}")
        for attempt in range(8):
            observed = live.read_device(device)
            addresses = (observed.facts("addresses") or {}).get("Ethernet2.44", [])
            read_ok = observed.live_reachable and "198.18.0.1/30" in addresses and "2001:db8:44::1/64" in addresses
            ping4 = eos("ping 198.18.0.2 repeat 2")
            ping6 = eos("ping ipv6 2001:db8:44::2 repeat 2")
            traffic_ok = "0% packet loss" in ping4 and "100% packet loss" not in ping4 \
                and "0% packet loss" in ping6 and "100% packet loss" not in ping6
            if read_ok and traffic_ok:
                break
            if attempt < 7:
                time.sleep(1)
        parsed = parser_ceos.parse(executor._conn.send_command("show running-config"))
        parsed_ok = any(i.name == "Ethernet2.44" and i.kind == "SUBINTERFACE" and i.parent_name == "Ethernet2"
                        and i.encapsulation_vlan == 44 for i in parsed.interfaces)
        if not (read_ok and traffic_ok and parsed_ok):
            raise RuntimeError(f"Tagged subinterface postcheck failed: read={read_ok}, traffic={traffic_ok}, "
                               f"parse={parsed_ok}; ping4={ping4[:200]!r}; ping6={ping6[:200]!r}; "
                               f"config={eos('show running-config interfaces Ethernet2.44')[:500]!r}")
        success = True
    finally:
        if child_attempted and child_assessment is not None:
            child_compensated = executor.compensate(child_spec, child_assessment).status == "COMPENSATED"
        executor.close()
        if child_attempted:
            try: eos("no interface Ethernet2.44", config=True)
            except RuntimeError as exc: cleanup_errors.append(str(exc))
        if parent_attempted:
            try: eos("default interface Ethernet2", config=True)
            except RuntimeError as exc: cleanup_errors.append(str(exc))
        if ipv6_enabled:
            try: eos("no ipv6 unicast-routing", config=True)
            except RuntimeError as exc: cleanup_errors.append(str(exc))
        if ip_enabled:
            try: eos("no ip routing", config=True)
            except RuntimeError as exc: cleanup_errors.append(str(exc))
        if peer_tagged and peer_run("ip", "link", "del", "dev", "eth2.44").returncode:
            cleanup_errors.append("Peer tagged link removal failed")
        if mtu_changed and peer_run("ip", "link", "set", "dev", "eth2", "mtu", str(original_mtu)).returncode:
            cleanup_errors.append("Peer MTU restoration failed")
    restored = not cleanup_errors and eos("show running-config interfaces Ethernet2") == parent_before \
        and "interface Ethernet2.44" not in eos("show running-config") and "no ip routing" in eos("show running-config") \
        and "no ipv6 unicast-routing" in eos("show running-config all") \
        and peer_run("ip", "link", "show", "dev", "eth2.44").returncode != 0
    if not restored:
        raise RuntimeError(f"Tagged subinterface cleanup failed: {cleanup_errors}")
    if not success:
        raise RuntimeError("Tagged subinterface probe did not reach functional success.")
    return LiveVerification("arista_ceos", "ceos", "Ethernet2.44", "198.18.0.1/30 + 2001:db8:44::1/64",
                            True, True, child_compensated, True,
                            f"isolated cEOS tagged Ethernet2.44: NMAS applied parent and rendered child; IPv4/IPv6 tagged traffic and live import passed; child compensation={child_compensated}; manual parent restoration passed")


def verify_ceos_svi() -> LiveVerification:
    """Create VLAN44/SVI via NMAS and prove untagged IPv4/IPv6 forwarding."""
    from ..config_import import parser_ceos

    device, _, _ = _target("arista_ceos")
    peer = f"clab-{LAB}-peer"
    inspection = _run(["docker", "inspect", peer], timeout=10)
    if inspection.returncode:
        raise RuntimeError("Disposable SVI peer is unavailable.")
    (peer_doc,) = json.loads(inspection.stdout)
    if (peer_doc.get("Config") or {}).get("Labels", {}).get("containerlab") != LAB \
            or NETWORK not in (peer_doc.get("NetworkSettings") or {}).get("Networks", {}):
        raise RuntimeError("SVI peer is outside the isolated lab.")

    def peer_run(*args):
        return _run(["docker", "exec", peer, *args], timeout=30)

    def eos(command, *, config=False):
        payload = f"configure terminal\n{command}" if config else command
        result = _run(["docker", "exec", device["container"], "Cli", "-p", "15", "--abort-on-error", "-c", payload], timeout=30)
        if result.returncode or "% Error" in result.stdout or "% Invalid input" in result.stdout:
            raise RuntimeError(f"Disposable cEOS SVI command rejected: {command[:80]}; {result.stdout[:200]}")
        return result.stdout

    before = eos("show running-config")
    peer_before = peer_run("ip", "-j", "addr", "show", "dev", "eth2")
    if "no ip routing" not in before or "no ipv6 unicast-routing" not in eos("show running-config all") \
            or eos("show running-config interfaces Ethernet2").strip() != "interface Ethernet2" \
            or any(token in before for token in ("vlan 44", "interface Vlan44")) or peer_before.returncode \
            or any(a.get("family") == "inet" for i in json.loads(peer_before.stdout) for a in i.get("addr_info", [])):
        raise RuntimeError("SVI baseline is not pristine.")
    original_mtu = int(json.loads(peer_before.stdout)[0]["mtu"])
    ra_before = peer_run("sysctl", "-n", "net.ipv6.conf.eth2.accept_ra")
    if ra_before.returncode or ra_before.stdout.strip() not in {"0", "1", "2"}:
        raise RuntimeError("SVI peer RA baseline unavailable.")
    case = sample("arista_ceos", by_key()["interface.SVI"])
    rendered = _descriptors("arista_ceos", case.sections)
    start = rendered.index("vlan 44")
    stop = next((i for i, line in enumerate(rendered[start + 1:], start + 1)
                 if line == "interface Vlan44"), -1)
    if stop < 0:
        raise RuntimeError("NMAS SVI renderer omitted VLAN44 interface.")
    lines = ["vlan 44", "interface Vlan44"]
    lines.extend(line for line in rendered[stop + 1:] if line.startswith("   ") and not line.lstrip().startswith("!"))
    lines = lines[:next((i for i, line in enumerate(lines[2:], 2) if not line.startswith(" ")), len(lines))]
    if not all(line in lines for line in ("   ip address 198.18.0.1/30", "   ipv6 address 2001:db8:44::1/64", "   no shutdown")):
        raise RuntimeError("NMAS SVI renderer omitted required address/admin commands.")
    spec = ConfigletSpec("P4-EOS-SVI", 1, "ceos", "arista_ceos", "interface", "CREATE_DEFINE",
                         tuple(lines), {"interface": "Vlan44", "admin_enabled": True})
    executor = CeosExecutor(device, connection_factory=DockerEosConfigConnection, reader=live.read_device)
    peer_v4 = peer_v6 = mtu_changed = ra_changed = parent_attempted = svi_attempted = ip_enabled = ipv6_enabled = False
    success = False
    cleanup_errors = []
    try:
        if ra_before.stdout.strip() != "0":
            if peer_run("sysctl", "-w", "net.ipv6.conf.eth2.accept_ra=0").returncode:
                raise RuntimeError("SVI peer RA suppression failed.")
            ra_changed = True
        if original_mtu != 1500:
            if peer_run("ip", "link", "set", "dev", "eth2", "mtu", "1500").returncode:
                raise RuntimeError("SVI peer MTU alignment failed.")
            mtu_changed = True
        if peer_run("ip", "addr", "add", "198.18.0.2/30", "dev", "eth2").returncode:
            raise RuntimeError("SVI peer IPv4 setup failed.")
        peer_v4 = True
        if peer_run("ip", "-6", "addr", "add", "2001:db8:44::2/64", "dev", "eth2").returncode:
            raise RuntimeError("SVI peer IPv6 setup failed.")
        peer_v6 = True
        eos("ip routing", config=True)
        ip_enabled = True
        eos("ipv6 unicast-routing", config=True)
        ipv6_enabled = True
        parent_attempted = True
        eos("interface Ethernet2\nswitchport mode access\nswitchport access vlan 44\nno shutdown", config=True)
        executor.connect()
        preflight = executor.assess(spec)
        if preflight.action != APPLY:
            raise RuntimeError(f"NMAS SVI preflight refused: {preflight.reason}")
        svi_attempted = True
        if not executor.apply(spec, preflight).ok:
            raise RuntimeError(f"NMAS SVI apply rejected: {getattr(executor._conn, 'last_config_output', '')[:500]!r}")
        for attempt in range(8):
            observed = live.read_device(device)
            addresses = (observed.facts("addresses") or {}).get("Vlan44", [])
            read_ok = observed.live_reachable and "198.18.0.1/30" in addresses and "2001:db8:44::1/64" in addresses
            ping4 = eos("ping 198.18.0.2 repeat 2")
            ping6 = eos("ping ipv6 2001:db8:44::2 repeat 2")
            traffic_ok = "0% packet loss" in ping4 and "100% packet loss" not in ping4 \
                and "0% packet loss" in ping6 and "100% packet loss" not in ping6
            if read_ok and traffic_ok:
                break
            if attempt < 7:
                time.sleep(1)
        parsed = parser_ceos.parse(executor._conn.send_command("show running-config"))
        parsed_ok = any(i.name == "Vlan44" and i.kind == "SVI" and i.vlan_id == 44 \
                        and {"198.18.0.1/30", "2001:db8:44::1/64"}.issubset({a["cidr"] for a in i.addresses})
                        for i in parsed.interfaces)
        if not (read_ok and traffic_ok and parsed_ok):
            raise RuntimeError(f"SVI postcheck failed: read={read_ok}, traffic={traffic_ok}, parse={parsed_ok}; "
                               f"ping4={ping4[:200]!r}; ping6={ping6[:200]!r}")
        success = True
    finally:
        executor.close()
        if svi_attempted:
            for command in ("no interface Vlan44", "no vlan 44"):
                try: eos(command, config=True)
                except RuntimeError as exc: cleanup_errors.append(str(exc))
        if parent_attempted:
            try: eos("default interface Ethernet2", config=True)
            except RuntimeError as exc: cleanup_errors.append(str(exc))
        if ipv6_enabled:
            try: eos("no ipv6 unicast-routing", config=True)
            except RuntimeError as exc: cleanup_errors.append(str(exc))
        if ip_enabled:
            try: eos("no ip routing", config=True)
            except RuntimeError as exc: cleanup_errors.append(str(exc))
        if peer_v6 and peer_run("ip", "-6", "addr", "del", "2001:db8:44::2/64", "dev", "eth2").returncode:
            cleanup_errors.append("SVI peer IPv6 removal failed")
        if peer_v4 and peer_run("ip", "addr", "del", "198.18.0.2/30", "dev", "eth2").returncode:
            cleanup_errors.append("SVI peer IPv4 removal failed")
        if mtu_changed and peer_run("ip", "link", "set", "dev", "eth2", "mtu", str(original_mtu)).returncode:
            cleanup_errors.append("SVI peer MTU restoration failed")
        if ra_changed and peer_run("sysctl", "-w", f"net.ipv6.conf.eth2.accept_ra={ra_before.stdout.strip()}").returncode:
            cleanup_errors.append("SVI peer RA restoration failed")
    after = eos("show running-config")
    restored = not cleanup_errors and "no ip routing" in after and "no ipv6 unicast-routing" in eos("show running-config all") \
        and eos("show running-config interfaces Ethernet2").strip() == "interface Ethernet2" \
        and "interface Vlan44" not in after and "vlan 44" not in after
    if not restored:
        raise RuntimeError(f"SVI cleanup failed: {cleanup_errors}")
    if not success:
        raise RuntimeError("SVI probe did not reach functional success.")
    return LiveVerification("arista_ceos", "ceos", "Vlan44", "198.18.0.1/30 + 2001:db8:44::1/64",
                            True, True, False, True,
                            "isolated cEOS VLAN44/SVI: NMAS rendered/applied SVI; IPv4/IPv6 untagged traffic, normalized read and import passed; native inverse restored SVI/VLAN/physical port (NMAS SVI compensation unproven)")


def verify_ceos_management() -> LiveVerification:
    """Add only a secondary address on disposable Management0, then compensate."""
    from ..config_import import parser_ceos

    device, _, _ = _target("arista_ceos")
    peer = f"clab-{LAB}-peer"
    inspection = _run(["docker", "inspect", peer], timeout=10)
    if inspection.returncode:
        raise RuntimeError("Disposable management peer is unavailable.")
    (peer_doc,) = json.loads(inspection.stdout)
    if (peer_doc.get("Config") or {}).get("Labels", {}).get("containerlab") != LAB \
            or NETWORK not in (peer_doc.get("NetworkSettings") or {}).get("Networks", {}):
        raise RuntimeError("Management peer is outside the isolated lab.")

    def peer_run(*args):
        return _run(["docker", "exec", peer, *args], timeout=30)

    def eos(command, *, config=False):
        payload = f"configure terminal\n{command}" if config else command
        result = _run(["docker", "exec", device["container"], "Cli", "-p", "15", "--abort-on-error", "-c", payload], timeout=30)
        if result.returncode or "% Error" in result.stdout or "% Invalid input" in result.stdout:
            raise RuntimeError(f"Disposable management command rejected: {command[:80]}; {result.stdout[:200]}")
        return result.stdout

    before = eos("show running-config interfaces Management0")
    peer_before = peer_run("ip", "-j", "addr", "show", "dev", "eth0")
    if "ip address 172.31.248.11/24" not in before or "ipv6 address fd00:ca:248::5/64" not in before \
            or "198.18.200.1" in before or peer_before.returncode \
            or any(a.get("local") == "198.18.200.2" for i in json.loads(peer_before.stdout) for a in i.get("addr_info", [])):
        raise RuntimeError("Management control-link baseline differs from expected disposable state.")
    initial = live.read_device(device)
    if not initial.live_reachable or "Management0" not in (initial.facts("interfaces") or {}):
        raise RuntimeError("Management pre-read failed.")
    case = sample("arista_ceos", by_key()["interface.MANAGEMENT"])
    row = case.sections["interfaces"]["if_0000000000000001"]
    row["name"] = "Management0"
    row["description"] = ""
    row["mtu"] = None
    addresses = list(row["addresses"].values())
    row["addresses"] = {addresses[0]["id"]: {**addresses[0], "cidr": "198.18.200.1/24", "role": "SECONDARY"}}
    rendered = _descriptors("arista_ceos", case.sections)
    start = rendered.index("interface Management0")
    lines = [line for line in rendered[start:] if line.strip() and not line.lstrip().startswith("!")]
    lines = lines[:next((i for i, line in enumerate(lines[1:], 1) if not line.startswith(" ")), len(lines))]
    if "   ip address 198.18.200.1/24 secondary" not in lines or "   no shutdown" not in lines:
        raise RuntimeError("NMAS management renderer omitted secondary address/admin intent.")
    # The management port already exists. Model the additive secondary address
    # as an address Configlet so the executor can prove its exact inverse.
    spec = ConfigletSpec("P4-EOS-MGMT", 1, "ceos", "arista_ceos", "address", "CREATE_DEFINE",
                         ("interface Management0", "   ip address 198.18.200.1/24 secondary"),
                         {"interface": "Management0", "address": "198.18.200.1/24"})
    executor = CeosExecutor(device, connection_factory=DockerEosConfigConnection, reader=live.read_device)
    peer_added = attempted = False
    compensated = observed_ok = parsed_ok = traffic_ok = False
    cleanup_errors = []
    try:
        if peer_run("ip", "addr", "add", "198.18.200.2/24", "dev", "eth0").returncode:
            raise RuntimeError("Disposable management peer address setup failed.")
        peer_added = True
        executor.connect()
        preflight = executor.assess(spec)
        if preflight.action != APPLY or not preflight.restorable:
            raise RuntimeError(f"Existing management interface secondary address has no NMAS inverse: {preflight.reason}")
        attempted = True
        if not executor.apply(spec, preflight).ok:
            raise RuntimeError(f"NMAS management apply rejected: {getattr(executor._conn, 'last_config_output', '')[:500]!r}")
        for attempt in range(5):
            observed = live.read_device(device)
            observed_ok = observed.live_reachable and "198.18.200.1/24" in (observed.facts("addresses") or {}).get("Management0", [])
            ping = eos("ping 198.18.200.2 source 198.18.200.1 repeat 2")
            traffic_ok = "0% packet loss" in ping and "100% packet loss" not in ping
            if observed_ok and traffic_ok:
                break
            if attempt < 4:
                time.sleep(1)
        parsed = parser_ceos.parse(executor._conn.send_command("show running-config"))
        parsed_ok = any(i.name == "Management0" and i.kind == "MANAGEMENT" and
                        any(a["cidr"] == "198.18.200.1/24" and a["role"] == "SECONDARY" for a in i.addresses)
                        for i in parsed.interfaces)
        if not (observed_ok and traffic_ok and parsed_ok):
            raise RuntimeError(f"Management postcheck failed: read={observed_ok}, ping={traffic_ok}, parse={parsed_ok}; {ping[:250]!r}")
    finally:
        if attempted:
            compensated = executor.compensate(spec, preflight).status == "COMPENSATED"
        executor.close()
        if "198.18.200.1" in eos("show running-config interfaces Management0"):
            try: eos("interface Management0\nno ip address 198.18.200.1/24 secondary", config=True)
            except RuntimeError as exc: cleanup_errors.append(str(exc))
        if peer_added and peer_run("ip", "addr", "del", "198.18.200.2/24", "dev", "eth0").returncode:
            cleanup_errors.append("Management peer secondary address removal failed")
    after = eos("show running-config interfaces Management0")
    final = live.read_device(device)
    restored = not cleanup_errors and after == before and final.live_reachable \
        and "198.18.200.1/24" not in (final.facts("addresses") or {}).get("Management0", []) \
        and "172.31.248.11/24" in (final.facts("addresses") or {}).get("Management0", [])
    if not restored:
        raise RuntimeError(f"Management control-link restoration failed: {cleanup_errors}; before={before!r}; after={after!r}")
    if not (observed_ok and traffic_ok and parsed_ok):
        raise RuntimeError("Management probe did not reach functional success.")
    return LiveVerification("arista_ceos", "ceos", "Management0", "198.18.200.1/24 secondary", True, True,
                            compensated, True,
                            f"isolated cEOS Management0: NMAS rendered/applied secondary IPv4; live read/import and peer ping passed; NMAS compensation={compensated}; original management IPv4/IPv6 remained and exact interface config restored")


def verify_srlinux_loopback() -> LiveVerification:
    """Exercise the Nokia CLI candidate/commit + JSON import path in the same lab.

    This does not register an NMAS executor or claim operator support. It
    resolves the earlier question of whether the available runtime accepts
    the project's actual rendered commands.
    """
    container = f"clab-{LAB}-srl"
    result = _run(["docker", "inspect", container], timeout=10)
    if result.returncode:
        raise RuntimeError("Isolated SR Linux target is unavailable.")
    (doc,) = json.loads(result.stdout)
    labels = (doc.get("Config") or {}).get("Labels") or {}
    if labels.get("containerlab") != LAB or labels.get("clab-node-kind") != "nokia_srlinux" \
            or NETWORK not in (doc.get("NetworkSettings") or {}).get("Networks", {}):
        raise RuntimeError("SR Linux target is outside the isolated validation lab.")
    feature = by_key()["interface.LOOPBACK"]
    case = sample("nokia_srlinux", feature)
    lines = list((Counter(_descriptors("nokia_srlinux", case.sections)) -
                  Counter(_descriptors("nokia_srlinux", case.baseline))).elements())
    if not lines or not all(line.startswith("set interface lo44 ") or line == "set network-instance default interface lo44.0"
                                for line in lines):
        raise RuntimeError("SR Linux renderer emitted an unsafe/unexpected validation command.")

    def cli(*args):
        return _run(["docker", "exec", container, "sr_cli", "-d", *args], timeout=60)

    def read():
        raw = cli("info interface lo44 | as json")
        if raw.returncode:
            raise RuntimeError("SR Linux JSON config read failed.")
        try:
            return parser_srlinux.parse(raw.stdout)
        except (ValueError, KeyError, TypeError, AttributeError) as exc:
            raise RuntimeError("SR Linux JSON import parser rejected the live readback.") from exc

    before = read()
    if any(i.name == "lo44" for i in before.interfaces):
        raise RuntimeError("Disposable SR Linux loopback is already present.")
    applied = False
    post_write = restored = False
    try:
        for line in lines:
            applied = True  # first command may partially commit before reporting failure
            result = cli("-e", "-c", line)
            if result.returncode or "All changes have been committed" not in result.stdout:
                raise RuntimeError("SR Linux rejected a rendered loopback statement.")
        parsed = read()
        post_write = any(i.name == "lo44" and any(a.get("cidr") == "198.18.0.1/30" for a in i.addresses)
                         for i in parsed.interfaces)
        if not post_write:
            raise RuntimeError("SR Linux live JSON import did not contain the rendered loopback/address.")
    finally:
        if applied:
            detach = cli("-e", "-c", "delete network-instance default interface lo44.0")
            if detach.returncode:
                raise RuntimeError("SR Linux loopback network-instance detachment failed.")
            removal = cli("-e", "-c", "delete interface lo44")
            if removal.returncode:
                raise RuntimeError("SR Linux loopback restoration failed.")
        restored = not any(i.name == "lo44" for i in read().interfaces)
    if not (post_write and restored):
        raise RuntimeError("SR Linux loopback verification/restoration is incomplete.")
    return LiveVerification("nokia_srlinux", "srl", "lo44", "198.18.0.1/30", True, True, True, True,
                            "isolated SR Linux 24.10.7: rendered CLI accepted, JSON importer matched loopback/address, deletion and absence verified")


def _iosxe_target() -> str:
    container = "clab-nmas-cap-iosxe-iosxe"
    result = _run(["docker", "inspect", container], timeout=10)
    if result.returncode:
        raise RuntimeError("Disposable IOS XE target is unavailable.")
    (doc,) = json.loads(result.stdout)
    labels = (doc.get("Config") or {}).get("Labels") or {}
    networks = (doc.get("NetworkSettings") or {}).get("Networks") or {}
    if labels.get("containerlab") != "nmas-cap-iosxe" or labels.get("clab-node-kind") != "cisco_c8000v" \
            or doc.get("Config", {}).get("Image") != "vrnetlab/cisco_c8000v:17.06.01a" \
            or not doc.get("State", {}).get("Running") or "nmas-cap-iosxe-mgmt" not in networks:
        raise RuntimeError("IOS XE target identity does not match the isolated validation lab.")
    return networks["nmas-cap-iosxe-mgmt"]["IPAddress"]


def verify_iosxe_loopback() -> LiveVerification:
    """Prove IOS XE renderer/fixture syntax against a reversible disposable DUT.

    This is device-side research, NOT an NMAS executor or operator support.
    Credentials must be supplied at invocation time and are never persisted.
    """
    from ..config_import import parser_iosxe

    host = _iosxe_target()
    password = os.environ.get("NMAS_CAP_IOSXE_PASSWORD", "")
    if not password:
        raise RuntimeError("Isolated IOS XE credential was not supplied.")
    feature = by_key()["interface.LOOPBACK"]
    case = sample("cisco_c8000v_iosxe", feature)
    lines = list((Counter(_descriptors("cisco_c8000v_iosxe", case.sections)) -
                  Counter(_descriptors("cisco_c8000v_iosxe", case.baseline))).elements())
    if not lines or lines[0] != "interface Loopback44" or any(
            not line.startswith(("interface Loopback44", " description ", " no shutdown", " ip address ", " ipv6 address "))
            for line in lines):
        raise RuntimeError("IOS XE renderer emitted an unsafe/unexpected loopback candidate.")
    from netmiko import ConnectHandler

    conn = ConnectHandler(device_type="cisco_ios", host=host, username="admin", password=password,
                          secret=password, conn_timeout=15, auth_timeout=15, banner_timeout=15)
    applied = False
    post_write = restored = False
    try:
        version = conn.send_command("show version | include IOS XE Software", read_timeout=30)
        if "IOS XE Software, Version 17.06.01a" not in version:
            raise RuntimeError("Disposable router does not report the pinned IOS XE release.")
        before = conn.send_command("show running-config | section ^interface Loopback44", read_timeout=30)
        if "interface Loopback44" in before:
            raise RuntimeError("Disposable IOS XE loopback is already present; refusing write.")
        applied = True  # reserve compensation before sending any command
        output = conn.send_config_set([line.strip() for line in lines], cmd_verify=True, read_timeout=90)
        if any(marker in output for marker in ("% Invalid input", "% Incomplete command", "% Error")):
            raise RuntimeError("IOS XE rejected the rendered loopback configuration.")
        running = conn.send_command("show running-config | section ^interface Loopback44", read_timeout=30)
        parsed = parser_iosxe.parse(running)
        post_write = any(i.name == "Loopback44" and any(a.get("cidr") == "198.18.0.1/30"
                         for a in i.addresses) for i in parsed.interfaces)
        route = conn.send_command("show ip route 198.18.0.1", read_timeout=30)
        post_write = post_write and ("198.18.0.0/30" in route or "198.18.0.1/32" in route)
        if not post_write:
            raise RuntimeError("IOS XE running configuration/parser or connected route did not verify the loopback.")
    finally:
        try:
            if applied:
                output = conn.send_config_set(["no interface Loopback44"], cmd_verify=True, read_timeout=90)
                if any(marker in output for marker in ("% Invalid input", "% Incomplete command", "% Error")):
                    raise RuntimeError("IOS XE loopback removal was rejected.")
            running = conn.send_command("show running-config | section ^interface Loopback44", read_timeout=30)
            restored = "interface Loopback44" not in running
        finally:
            conn.disconnect()
    if not (post_write and restored):
        raise RuntimeError("IOS XE loopback verification/restoration did not pass.")
    return LiveVerification("cisco_c8000v_iosxe", "iosxe", "Loopback44", "198.18.0.1/30", True, True, True, True,
                            "isolated IOS XE 17.06.01a: rendered loopback applied, parsed from live running config, route present, inverse removed and absence verified")


def _sonic_target() -> None:
    """Pin SSH port 2233 to the explicit disposable QEMU snapshot process."""
    root = Path("/home/student/clab-quickstart/capability-validation")
    pid = int((root / "sonic.pid").read_text().strip())
    cmdline = Path(f"/proc/{pid}/cmdline").read_bytes().replace(b"\0", b" ").decode(errors="replace")
    if "qemu-system-x86_64" not in cmdline or "sonic-vs.img" not in cmdline \
            or "snapshot=on" not in cmdline or "hostfwd=tcp:127.0.0.1:2233-:22" not in cmdline:
        raise RuntimeError("SONiC SSH port is not owned by the isolated snapshot VM.")


def verify_sonic_loopback() -> LiveVerification:
    """Prove SONiC ConfigDB/OS readback and reversible loopback behavior.

    Uses only the disposable snapshot. It does NOT claim an NMAS SONiC executor.
    """
    import paramiko
    from ..config_import import parser_sonic

    _sonic_target()
    password = os.environ.get("NMAS_CAP_SONIC_PASSWORD", "")
    if not password:
        raise RuntimeError("Isolated SONiC credential was not supplied.")
    conn = paramiko.SSHClient()
    conn.set_missing_host_key_policy(paramiko.AutoAddPolicy())  # snapshot has a transient host key
    conn.connect("127.0.0.1", port=2233, username="admin", password=password,
                 timeout=10, auth_timeout=10, banner_timeout=10, look_for_keys=False, allow_agent=False)

    def run(command):
        _stdin, stdout, stderr = conn.exec_command(command, timeout=40)
        result, error, code = stdout.read().decode(errors="replace"), stderr.read().decode(errors="replace"), stdout.channel.recv_exit_status()
        if code:
            raise RuntimeError(f"Isolated SONiC command failed: {command.split()[0]} exit={code}; output suppressed.")
        return result

    def read():
        table = json.loads(run("sonic-cfggen -d --var-json LOOPBACK_INTERFACE"))
        return parser_sonic.parse({"LOOPBACK_INTERFACE": table}), table

    added = False
    post_write = restored = False
    try:
        version = run("show version")
        if "SONiC Software Version:" not in version:
            raise RuntimeError("Snapshot VM does not report SONiC identity.")
        before, _table = read()
        if any(i.name == "Loopback44" for i in before.interfaces):
            raise RuntimeError("Disposable SONiC loopback is already present; refusing write.")
        added = True
        run("sudo config loopback add Loopback44")
        run("sudo config interface ip add Loopback44 198.18.44.14/32 0.0.0.0")
        parsed, table = read()
        post_write = any(i.name == "Loopback44" and any(a.get("cidr") == "198.18.44.14/32"
                         for a in i.addresses) for i in parsed.interfaces)
        post_write = post_write and "Loopback44|198.18.44.14/32" in table
        if not post_write:
            raise RuntimeError("SONiC ConfigDB/semantic import did not verify the loopback and address.")
    finally:
        try:
            if added:
                run("sudo config loopback del Loopback44")
            parsed, _table = read()
            restored = not any(i.name == "Loopback44" for i in parsed.interfaces)
        finally:
            conn.close()
    if not (post_write and restored):
        raise RuntimeError("SONiC loopback verification/restoration did not pass.")
    return LiveVerification("sonic", "sonic", "Loopback44", "198.18.44.14/32", True, True, True, True,
                            "isolated SONiC snapshot: config CLI wrote loopback/address, ConfigDB JSON import matched, deletion and absence verified")
