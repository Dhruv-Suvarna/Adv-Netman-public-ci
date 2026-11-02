"""Isolated-lab probes for cells that pass every NMAS prerequisite layer.

``registry()`` maps a matrix cell to a callable that receives the cell's fresh
offline assessment, exercises the disposable ``nmas-cap-validation`` lab and
fills the live stages.  One lab session (addresses, routing, peer endpoints) is
prepared once and reused by every probe of a batch, then restored exactly.

Every device write goes through the registered NMAS cEOS executor (preflight,
apply, compensate); the post-write check uses the operator health reader's own
fact groups; behaviour is proven with real traffic from the peer namespaces.
"""

from __future__ import annotations

import json
import time
from collections import Counter
from copy import deepcopy

from django.utils import timezone

from ..config_import import parser_ceos
from ..execution.executors.base import APPLY, ConfigletSpec
from ..execution.executors.ceos import CeosExecutor
from ..execution.executors.ceos import REJECTIONS
from ..execution.executors.linux import LinuxExecutor
from ..health import live
from . import assessment
from .features import by_key
from .fixture_ceos_ssh import FixtureCeosSsh
from .isolated_live import LAB, NETWORK, _run, _target
from .offline_verify import _descriptors, _parsed_contains
from .probe_cases import sample

RUNTIME = "ceos:4.36.2F / Linux peer namespaces"
LINK4, LINK6 = ("198.18.0.1/24", "198.18.0.2/24", "198.18.0.66/24"), ("2001:db8:44::1/64", "2001:db8:44::2/64", "2001:db8:44::66/64")
FAR4, FAR6 = ("198.18.1.1/24", "198.18.1.2/24"), ("2001:db8:45::1/64", "2001:db8:45::2/64")
VMAC = "00:1c:73:00:00:44"

_DHCP4_SERVER = r"""
import socket, struct, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("198.18.1.2", 67)); s.settimeout(6)
try:
    data, peer = s.recvfrom(2048)
except socket.timeout:
    print("NONE"); sys.exit(0)
giaddr = socket.inet_ntoa(data[24:28])
reply = bytearray(data[:240]); reply[0] = 2; reply[16:20] = socket.inet_aton("198.18.0.99")
reply += bytes([53, 1, 2, 54, 4]) + socket.inet_aton("198.18.1.2") + bytes([255])
s.sendto(bytes(reply), (giaddr, 67)); print("RELAYED", data[0], giaddr)
"""
_DHCP4_CLIENT = r"""
import os, socket, struct, time
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1); s.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, b"eth1")
s.bind(("0.0.0.0", 68)); s.settimeout(5)
import fcntl
mac = fcntl.ioctl(s.fileno(), 0x8927, struct.pack("256s", b"eth1"))[18:24]; xid = os.urandom(4)
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
s.bind(("2001:db8:45::2", 547)); s.settimeout(6)
try:
    data, peer = s.recvfrom(2048)
except socket.timeout:
    print("NONE"); sys.exit(0)
print("RELAYED", data[0], socket.inet_ntop(socket.AF_INET6, data[2:18]))
"""
_DHCP6_CLIENT = r"""
import os, socket, time
s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM); s.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, b"eth1")
s.bind(("::", 546)); duid = bytes([0, 3, 0, 1]) + os.urandom(6)
pkt = bytes([1]) + os.urandom(3) + bytes([0, 1, 0, len(duid)]) + duid + bytes([0, 8, 0, 2, 0, 0])
time.sleep(1); s.sendto(pkt, ("ff02::1:2", 547, 0, socket.if_nametoindex("eth1"))); print("SENT")
"""


def _added_blocks(lines, base) -> list[tuple[str, list[str]]]:
    """Rendered lines absent from the baseline, regrouped under their configuration header."""
    remaining, blocks, header = Counter(base), [], ""
    for line in lines:
        top = not line.startswith(" ")
        if top:
            header = line
        if remaining[line] > 0:
            remaining[line] -= 1
            continue
        if not line.strip() or line.lstrip().startswith("!"):
            continue
        if top:
            blocks.append((line, []))
        elif blocks and blocks[-1][0] == header:
            blocks[-1][1].append(line)
        else:
            blocks.append((header, [line]))
    return blocks


def _object_type(header, children) -> str:
    text = " ".join([header, *children])
    if "access-group" in text:
        return "acl_attachment"
    if "access-list" in header:
        return "acl"
    return "dhcp_relay" if ("helper-address" in text or "dhcp relay" in text) else "fhrp"


class CeosServiceLab:
    """Prepared once per batch: routed cEOS between two Linux peers; restored exactly on close."""

    def __init__(self):
        self.device, _, _ = _target("arista_ceos")
        self.pids = {}
        for node in ("frr", "peer"):
            result = _run(["docker", "inspect", f"clab-{LAB}-{node}"], timeout=10)
            if result.returncode:
                raise RuntimeError("Disposable peer is unavailable.")
            (doc,) = json.loads(result.stdout)
            if (doc.get("Config") or {}).get("Labels", {}).get("containerlab") != LAB \
                    or NETWORK not in (doc.get("NetworkSettings") or {}).get("Networks", {}):
                raise RuntimeError("Peer is outside the isolated lab.")
            self.pids[node] = str(doc["State"]["Pid"])
        self.fixture = FixtureCeosSsh()
        self.reader = lambda device: live.read_device(device, session_factory=self.fixture.session)
        self.executor = CeosExecutor(self.device, connection_factory=lambda _device: self.fixture.conn, reader=self.reader)
        self.executor.connect()
        self.baseline = self.executor._config_state_digest()
        text = self.executor._config_text()
        if "no ip routing" not in text or "access-list" in text or "virtual-router" in text or any(
                self.eos(f"show running-config interfaces {name}").strip().splitlines()[-1].strip() != f"interface {name}"
                for name in ("Ethernet1", "Ethernet2")):
            raise RuntimeError("cEOS is not at the expected disposable baseline; refusing to write.")
        for node, dev in (("frr", "eth1"), ("peer", "eth2")):
            if any(row.get("addr_info") for row in json.loads(
                    self.ns(node, "ip", "-j", "addr", "show", "dev", dev, "scope", "global").stdout or "[]")):
                raise RuntimeError("Peer link already carries addresses; refusing to write.")
        self.prepared = True
        try:
            self._prepare()
        except Exception:
            self.close()   # a half-prepared lab is restored before the failure is reported
            raise

    def _prepare(self):
        self.eos("ip routing\nipv6 unicast-routing\n"
                 f"interface Ethernet1\nno switchport\nip address {LINK4[0]}\nipv6 address {LINK6[0]}\n"
                 f"interface Ethernet2\nno switchport\nip address {FAR4[0]}\nipv6 address {FAR6[0]}", config=True)
        for node, dev, v4, v6, gw4, gw6, far4, far6 in (
                ("frr", "eth1", LINK4[1], LINK6[1], "198.18.0.1", "2001:db8:44::1", "198.18.1.0/24", "2001:db8:45::/64"),
                ("peer", "eth2", FAR4[1], FAR6[1], "198.18.1.1", "2001:db8:45::1", "198.18.0.0/24", "2001:db8:44::/64")):
            for argv in (("addr", "replace", v4, "dev", dev), ("-6", "addr", "replace", v6, "dev", dev, "nodad"),
                         ("route", "replace", far4, "via", gw4, "dev", dev), ("-6", "route", "replace", far6, "via", gw6, "dev", dev)):
                if self.ns(node, "ip", *argv).returncode:
                    raise RuntimeError("Peer preparation failed.")
        self.ns("frr", "ip", "addr", "add", LINK4[2], "dev", "eth1")
        self.ns("frr", "ip", "-6", "addr", "add", LINK6[2], "dev", "eth1", "nodad")   # the IPv6 ACL's denied source
        self.prepared_digest = self.executor._config_state_digest()
        deadline = time.monotonic() + 30
        while not (self.ping("frr", "198.18.1.2") and self.ping("frr", "2001:db8:45::2")):
            if time.monotonic() > deadline:
                raise RuntimeError("Prepared lab does not forward between the peers.")
            time.sleep(2)

    def ns(self, node, *argv, timeout=20):
        return _run(["sudo", "-n", "nsenter", "-t", self.pids[node], "-n", *argv], timeout=timeout)

    def eos(self, command, *, config=False):
        if config:
            commands, in_interface = [], False
            for line in command.splitlines():
                global_command = line.startswith(("interface ", "default interface ", "ip routing", "no ip routing",
                                                  "ipv6 unicast-routing", "no ipv6 unicast-routing"))
                if in_interface and global_command:
                    commands.append("exit")
                    in_interface = False
                commands.append(line)
                if line.startswith("interface "):
                    in_interface = True
            result = self.fixture.conn.send_config_set(commands, read_timeout=90, cmd_verify=True)
        else:
            result = self.fixture.conn.send_command(command, read_timeout=60)
        if any(marker in result for marker in REJECTIONS):
            raise RuntimeError(f"Disposable cEOS {'write' if config else 'read'} failed: {command[:50]}")
        return result

    def ping(self, node, target, *, source="") -> bool:
        argv = ["ping", "-c", "2", "-W", "1", *(("-I", source) if source else ()), target]
        return self.ns(node, *argv).returncode == 0

    def neighbor_mac(self, node, target) -> str:
        rows = json.loads(self.ns(node, "ip", "-j", "neigh", "show", target).stdout or "[]")
        return (rows[0].get("lladdr") or "") if rows else ""

    def close(self) -> bool:
        restored = False
        try:
            if getattr(self, "prepared", False):
                self.eos("default interface Ethernet1\ndefault interface Ethernet2\nno ipv6 unicast-routing\nno ip routing", config=True)
                for node, dev in (("frr", "eth1"), ("peer", "eth2")):
                    self.ns(node, "ip", "addr", "flush", "dev", dev, "scope", "global")
                    for family, far in (("-4", "198.18.0.0/24"), ("-4", "198.18.1.0/24"),
                                        ("-6", "2001:db8:44::/64"), ("-6", "2001:db8:45::/64")):
                        self.ns(node, "ip", family, "route", "del", far, "dev", dev)   # absent routes are fine
            restored = self.executor._config_state_digest() == self.baseline
        finally:
            self.executor.close()
            self.fixture.close()
        if not restored:
            raise RuntimeError("Isolated cEOS was not restored to its captured baseline.")
        return restored


ACL_DENIED = {"IPV4": "198.18.0.66", "IPV6": "2001:db8:44::66"}


def acl_entries(acl: dict, first: dict) -> dict:
    """The behaviour-test entries of one ACL: deny the lab's denied source, permit everything else.  An EXTENDED list also
    carries a protocol entry and a TCP port-range / port entry (logged on IPv4; EOS ignores ``log`` in an IPv6 entry, so
    NMAS refuses it there), so import must recover protocol, ports and logging -- not only the list's name."""
    v6 = acl.get("family") == "IPV6"
    host, link = (ACL_DENIED["IPV6"], "2001:db8:44::1") if v6 else (ACL_DENIED["IPV4"], "198.18.0.1")
    base = {**first, "source_port": "", "destination_port": "", "logging": False, "destination_type": "ANY",
            "destination_value": "", "protocol": "IPV6" if v6 else "IP"}
    rows = [{**base, "sequence": 10, "action": "DENY", "source_type": "HOST", "source_value": host}]
    if acl.get("acl_type") == "EXTENDED":
        rows[0]["protocol"] = "ICMPV6" if v6 else "ICMP"
        rows.append({**base, "sequence": 15, "action": "DENY", "protocol": "TCP", "source_type": "ANY", "source_value": "",
                     "source_port": "1024-2048", "destination_type": "HOST", "destination_value": link,
                     "destination_port": "80", "logging": not v6})
    rows.append({**base, "sequence": 20, "action": "PERMIT", "source_type": "ANY", "source_value": ""})
    return {f"ace_00000000000000{row['sequence']:02d}": {**row, "id": f"ace_00000000000000{row['sequence']:02d}"} for row in rows}


def _ace_facts(row: dict, family: str, extended: bool) -> tuple:
    """The comparable facts of one ACL entry; "IP" / "IPV6" both mean any protocol and ICMP is ICMPV6 in an IPv6 list."""
    protocol = str(row.get("protocol") or "IP").upper()
    protocol = "IP" if protocol in ("IP", "IPV6") else ("ICMPV6" if family == "IPV6" and protocol == "ICMP" else protocol)
    facts = (int(row.get("sequence") or 0), str(row.get("action")).upper(), row.get("source_type"), str(row.get("source_value") or ""))
    if not extended:
        return (*facts, bool(row.get("logging")))
    return (*facts, protocol, row.get("destination_type"), str(row.get("destination_value") or ""),
            str(row.get("source_port") or ""), str(row.get("destination_port") or ""), bool(row.get("logging")))


def acl_imported(parsed, acl: dict) -> bool:
    """The imported list carries every intended entry exactly (sequence, action, protocol, addresses, ports, logging)."""
    extended = acl.get("acl_type") == "EXTENDED"
    row = next((a for a in parsed.acls if a.name == acl.get("name") and a.family == acl.get("family")), None)
    return bool(row) and row.acl_type == acl.get("acl_type") and not row.preserved_lines and \
        sorted(_ace_facts(e, acl["family"], extended) for e in row.entries) == \
        sorted(_ace_facts(e, acl["family"], extended) for e in acl["entries"].values())


def _plan(lab, key):
    """Intent sections (rendered by NMAS), operator postcheck and behaviour test of one cell."""
    feature = by_key()[key]
    case = sample("arista_ceos", feature)
    sections, code = deepcopy(case.sections), feature.code
    iface_id = next(iter(sections["interfaces"]))
    if code.startswith("ACL_"):
        acl = next(iter(sections["security"]["acls"].values()))
        acl["entries"] = acl_entries(acl, next(iter(acl["entries"].values())))
        sections["security"]["attachments"] = {"attach_0000000000000003": {
            "id": "attach_0000000000000003", "acl_id": acl["id"], "interface_id": iface_id, "direction": "IN"}}
        v6 = acl.get("family") == "IPV6"
        permitted, denied, far = ("2001:db8:44::2", ACL_DENIED["IPV6"], "2001:db8:45::2") if v6 else \
            ("198.18.0.2", ACL_DENIED["IPV4"], "198.18.1.2")

        def post(observed):
            config = observed.facts("config") or {}
            return "CAP_ACL" in config.get("acl_definitions", []) and \
                {"interface": "Ethernet1", "acl": "CAP_ACL", "direction": "IN"} in config.get("acl_attachments", [])

        def behave(active):
            permit = lab.ping("frr", far, source=permitted)
            deny = lab.ping("frr", far, source=denied)
            return (permit and not deny) if active else (permit and deny), f"permitted-source ping={permit}, denied-source ping={deny}"
        what = f"{acl.get('family')} {acl.get('acl_type')} ACL CAP_ACL (deny {denied}, permit any) attached inbound on Ethernet1"
    elif code.startswith("DHCP_RELAY_"):
        v6 = code.endswith("IPV6")
        relay = next(iter(sections["services"]["dhcp"]["relays"].values()))
        relay["destination"] = "2001:db8:45::2" if v6 else "198.18.1.2"

        def post(observed):
            return {"interface": "Ethernet1", "destination": relay["destination"]} in (observed.facts("config") or {}).get("dhcp_relays", [])

        def behave(active):
            import subprocess
            server = subprocess.Popen(["sudo", "-n", "nsenter", "-t", lab.pids["peer"], "-n", "python3", "-c",
                                       _DHCP6_SERVER if v6 else _DHCP4_SERVER], stdout=subprocess.PIPE, text=True)
            client = lab.ns("frr", "python3", "-c", _DHCP6_CLIENT if v6 else _DHCP4_CLIENT).stdout.strip()
            seen = server.communicate(timeout=15)[0].strip()
            if v6:   # RELAY-FORW (type 12) carrying the solicit must reach the configured destination
                ok = seen.startswith("RELAYED 12")
            else:    # the server sees giaddr of the relay and its offer returns to the client through the relay
                ok = seen == "RELAYED 1 198.18.0.1" and client == "OFFER 198.18.0.99"
            return (ok if active else seen == "NONE"), f"server saw [{seen}], client saw [{client}]"
        what = f"DHCP relay to {relay['destination']} on Ethernet1"
    else:
        v6 = code.endswith("IPV6")
        group = next(iter(sections["fhrp"]["instances"].values()))
        vip = next(iter(group["virtual_ips"].values()))["address"]

        def post(observed):
            return vip in (observed.facts("virtual_addresses") or {}).get("Ethernet1", [])

        def behave(active):
            # A host that uses the virtual address as its gateway must resolve the virtual MAC and be forwarded.
            family, far, real = (("-6",), "2001:db8:45::/64", "2001:db8:44::1") if v6 else ((), "198.18.1.0/24", "198.18.0.1")
            target = "2001:db8:45::2" if v6 else "198.18.1.2"
            lab.ns("frr", "ip", *family, "route", "replace", far, "via", vip, "dev", "eth1")
            lab.ns("frr", "ip", *family, "neigh", "flush", "dev", "eth1")
            try:
                forwarded = lab.ping("frr", target)
                mac = lab.neighbor_mac("frr", vip)
            finally:
                lab.ns("frr", "ip", *family, "route", "replace", far, "via", real, "dev", "eth1")
            return (forwarded and mac == VMAC) if active else not forwarded, \
                f"traffic via virtual gateway {vip} forwarded={forwarded}, gateway resolved to MAC={mac or 'none'}"
        what = f"VARP virtual address {vip} with virtual MAC {VMAC} on Ethernet1"
    blocks = _added_blocks(_descriptors("arista_ceos", sections), _descriptors("arista_ceos", case.baseline))
    grouped: dict[str, list[str]] = {}
    for header, children in blocks:
        grouped.setdefault(_object_type(header, children), []).extend([header, *children])
    order = [t for t in ("acl", "fhrp", "dhcp_relay", "acl_attachment") if t in grouped]
    specs = [ConfigletSpec(f"CAP-{n}", n, "ceos", "arista_ceos", kind, "CREATE_DEFINE", tuple(grouped[kind]), case.expected)
             for n, kind in enumerate(order, 1)]
    case.sections = sections
    return feature, case, specs, post, behave, what


def probe_cell(lab, cell, key) -> None:
    feature, case, specs, post, behave, what = _plan(lab, key)
    executor = lab.executor
    if executor._config_state_digest() != lab.prepared_digest:
        raise RuntimeError("Prepared lab state drifted before the probe.")
    control_ok, control = behave(False)
    if not control_ok:
        raise RuntimeError(f"Control behaviour without the feature is not as expected ({control}).")
    applied, wrote = [], False
    read_ok = post_ok = imported = behaved = restorable = False
    behaviour = facts = ""
    try:
        for spec in specs:
            preflight = executor.assess(spec)
            if preflight.action != APPLY:
                raise RuntimeError(f"NMAS executor preflight did not allow {spec.object_type} ({preflight.action}).")
            applied.append((spec, preflight))
            outcome = executor.apply(spec, preflight)
            if not outcome.ok:
                raise RuntimeError(f"cEOS rejected rendered {spec.object_type}: {outcome.error_code}.")
        wrote, restorable = True, all(p.restorable for _, p in applied)
        observed = lab.reader(lab.device)
        read_ok = bool(observed.live_reachable)
        post_ok = read_ok and bool(post(observed))
        facts = json.dumps({"virtual_addresses": (observed.facts("virtual_addresses") or {}).get("Ethernet1", []),
                            "config": observed.facts("config") or {}}, sort_keys=True)[:400]
        parsed = parser_ceos.parse(executor._config_text())
        imported = _parsed_contains(parsed, feature, case)
        if feature.code.startswith("ACL_"):
            imported = imported and acl_imported(parsed, next(iter(case.sections["security"]["acls"].values())))
        behaved, behaviour = behave(True)
    finally:
        statuses = [executor.compensate(spec, preflight).status for spec, preflight in reversed(applied)]
        restored = executor._config_state_digest() == lab.prepared_digest
        if not restored:   # never leave residue for the next cell: native removal, then the lab baseline check on close
            for spec, _ in reversed(applied):
                top = [line for line in spec.lines if not line.startswith(" ") and not line.startswith("interface ")]
                child = [line for line in spec.lines if line.startswith(" ")]
                undo = [f"no {line}" for line in top] + (["interface Ethernet1", *(f"no {line.strip()}" for line in child)]
                                                         if any(line.startswith("interface ") for line in spec.lines) else [])
                if undo:
                    lab.eos("\n".join(undo), config=True)
    after_ok, after = behave(False)
    compensated = bool(applied) and all(status == "COMPENSATED" for status in statuses) and restored and after_ok
    reference = f"live:{LAB}/ceos-{feature.code.lower()}/{timezone.now().isoformat()}"
    rendered = "; ".join(line.strip() for spec in specs for line in spec.lines)
    summary = f"isolated cEOS {what}: NMAS rendered [{rendered}] and applied it through the registered executor"

    def record(name, ok, detail, reason):
        cell.probes[name] = assessment.probe("PASS" if ok else "FAIL", detail, reason="" if ok else reason,
                                             test_type="LIVE", reference=reference)

    record("live_write", wrote, f"{summary}; device accepted every line={wrote}.", "FUNCTIONAL_TEST_FAILED")
    record("live_read", read_ok, f"{summary}; operator health reader reached the device and returned its fact groups={read_ok}.", "LIVE_READ_ABSENT")
    record("live_post_write_validation", post_ok,
           f"{summary}; operator health facts (config / virtual_addresses groups) contain the intended object={post_ok}; observed {facts}.", "POSTCHECK_ABSENT")
    record("parser_import", imported, f"{summary}; cEOS import parser recovered the same semantic object from live running-config={imported}.",
           "PARSER_ABSENT")
    record("runtime_validation", behaved and control_ok,
           f"{summary}; behaviour with feature: {behaviour}; control before: {control}; after removal: {after}.", "FUNCTIONAL_TEST_FAILED")
    record("compensation", compensated and restorable,
           f"{summary}; preflight proved exact inverse={restorable}; executor compensation statuses={statuses}; "
           f"running-config identical to pre-apply capture={restored}; behaviour reverted={after_ok}.", "COMPENSATION_ABSENT")
    cell.runtime_version = RUNTIME
    if not restored and executor._config_state_digest() != lab.prepared_digest:
        raise RuntimeError("Probe residue could not be removed from the isolated cEOS.")


CEOS_SERVICE_CELLS = tuple(f"service_policy.{code}" for code in (
    "ACL_IPV4_STANDARD", "ACL_IPV4_EXTENDED", "ACL_ATTACH_IPV4", "ACL_IPV6_STANDARD", "ACL_IPV6_EXTENDED", "ACL_ATTACH_IPV6",
    "DHCP_RELAY_IPV4", "DHCP_RELAY_IPV6", "FHRP_VARP_IPV4", "FHRP_VARP_IPV6"))


CEOS_INTERFACE_KINDS = ("ROUTED_PHYSICAL", "ACCESS", "TRUNK", "SUBINTERFACE", "SVI")
FRR_INTERFACE_CELLS = tuple(f"interface.{code}" for code in
                            ("MANAGEMENT", "ROUTED_PHYSICAL", "SUBINTERFACE", "SVI"))


def _frr_link(container: str, name: str) -> dict | None:
    result = _run(["docker", "exec", container, "ip", "-j", "-d", "link", "show", "dev", name])
    addresses = _run(["docker", "exec", container, "ip", "-j", "addr", "show", "dev", name])
    if result.returncode or addresses.returncode:
        return None
    rows = json.loads(result.stdout)
    address_rows = json.loads(addresses.stdout)
    return {**rows[0], "addr_info": address_rows[0].get("addr_info", [])} if rows and address_rows else None


def _frr_link_semantics(row: dict | None) -> dict | None:
    if row is None:
        return None
    return {
        "mtu": row.get("mtu"), "up": "UP" in row.get("flags", []),
        "kind": (row.get("linkinfo") or {}).get("info_kind"),
        "parent": row.get("link"),
        "vlan_id": ((row.get("linkinfo") or {}).get("info_data") or {}).get("id"),
        "addresses": sorted((a.get("family"), a.get("local"), a.get("prefixlen"))
                            for a in row.get("addr_info", []) if a.get("family") in {"inet", "inet6"}),
    }


def probe_frr_interface(cell, key: str) -> None:
    """Exercise one rendered Linux interface in the disposable FRR namespace."""
    device, _, _ = _target("ubuntu_frr")
    (inspected,) = json.loads(_run(["docker", "inspect", device["container"]], timeout=10).stdout)
    management_address = inspected["NetworkSettings"]["Networks"][NETWORK]["IPAddress"]   # how the lab manages this node
    case = sample("ubuntu_frr", by_key()[key])
    name = case.expected["interface"]
    code = key.split(".", 1)[1]
    container = device["container"]
    baseline = _frr_link_semantics(_frr_link(container, name))
    parent = _frr_link(container, "eth1") if code == "SUBINTERFACE" else None
    if code in {"MANAGEMENT", "ROUTED_PHYSICAL"}:
        if baseline is None or not baseline["up"]:
            raise RuntimeError("Existing disposable interface does not satisfy rendered admin intent.")
    elif baseline is not None:
        raise RuntimeError("Disposable interface already exists; refusing to overwrite it.")
    if code == "SUBINTERFACE" and parent is None:
        raise RuntimeError("Disposable VLAN parent is absent.")
    added = [s for s in (Counter(_descriptors("ubuntu_frr", case.sections)) -
                         Counter(_descriptors("ubuntu_frr", case.baseline))).elements() if not s.startswith("#")]
    addresses = [s for s in added if s.startswith("ip addr replace ") or s.startswith("ip -6 addr replace ")]
    create = [s for s in added if s.startswith("ip link show dev ")]
    expected_create = code in {"SUBINTERFACE", "SVI"}
    if len(addresses) != 2 or len(create) != int(expected_create):
        raise RuntimeError("FRR renderer changed the bounded interface fixture.")
    specs = []
    if True:   # an existing interface gets the same Configlet: only its rendered MTU / admin-state lines
        lines = tuple(s for s in added if s in create or s.startswith(f"ip link set dev {name} "))
        specs.append(ConfigletSpec("CAP-FRR-IF", 1, "frr", "ubuntu_frr", "interface", "CREATE_DEFINE",
                                   lines, {"interface": name, "admin_enabled": True}))
    for index, line in enumerate(addresses, 2):
        cidr = line.split()[4 if line.startswith("ip -6") else 3]
        specs.append(ConfigletSpec(f"CAP-FRR-ADDR-{index}", index, "frr", "ubuntu_frr", "address",
                                   "CREATE_DEFINE", (line,), {"interface": name, "address": cidr,
                                                               "family": 6 if ":" in cidr else 4}))
    executor = LinuxExecutor(device)
    applied, preflights, imported = [], [], ""
    write_ok = read_ok = post_ok = runtime_ok = compensation_ok = False
    observed_detail = ""
    failure = ""
    try:
        executor.connect()
        for spec in specs:
            preflight = executor.assess(spec)
            preflights.append(f"{spec.object_type}={preflight.action}/{preflight.restorable}")
            if preflight.action == "SKIP_SATISFIED":
                continue
            if preflight.action != APPLY or not preflight.restorable:
                raise RuntimeError(f"FRR executor cannot safely apply {spec.object_type}: {preflight.previous_state}.")
            applied.append((spec, preflight))
            outcome = executor.apply(spec, preflight)
            if not outcome.ok:
                raise RuntimeError(f"FRR executor rejected {spec.object_type}: {outcome.error_code}.")
        write_ok = True
        observed = live.read_device(device)
        read_ok = bool(observed.live_reachable)
        row = _frr_link(container, name)
        actual = _frr_link_semantics(row)
        expected_addresses = {"198.18.0.1/30", "2001:db8:44::1/64"}
        nmas_addresses = set((observed.facts("addresses") or {}).get(name, []))
        kind_ok = (code == "SUBINTERFACE" and actual and actual["kind"] == "vlan" and
                   actual["vlan_id"] == 44 and actual["parent"] == "eth1") or \
                  (code == "SVI" and actual and actual["kind"] == "bridge") or \
                  (code in {"MANAGEMENT", "ROUTED_PHYSICAL"} and actual is not None)
        mtu_ok = code == "SUBINTERFACE" or actual and actual["mtu"] == 1500
        # the import parser must classify the live namespace: the port the device is managed through is MANAGEMENT
        # (its own addresses and MTU preserved), every other physical port stays an ordinary routed port
        from ..config_import import parser_frr
        parsed = {i.name: i for i in parser_frr.parse(
            "", addr_json=_run(["docker", "exec", container, "ip", "-j", "addr", "show"]).stdout,
            management_addresses=[management_address]).interfaces}
        imported = {n: (i.kind, i.mtu, sorted(a["cidr"] for a in i.addresses if not a["cidr"].startswith("fe80"))[:4])
                    for n, i in parsed.items() if n in {"eth0", "eth1", name}}
        import_ok = parsed["eth0"].kind == "MANAGEMENT" and parsed["eth1"].kind == "ROUTED_PHYSICAL" and \
            any(a["cidr"].split("/")[0] == management_address for a in parsed["eth0"].addresses) and \
            expected_addresses <= {a["cidr"] for a in parsed[name].addresses}
        post_ok = bool(read_ok and actual and actual["up"] and expected_addresses <= nmas_addresses and kind_ok and mtu_ok
                       and (code not in {"MANAGEMENT", "ROUTED_PHYSICAL"} or import_ok))
        route = _run(["docker", "exec", container, "ip", "-j", "route", "get", "198.18.0.2"])
        route_rows = json.loads(route.stdout) if route.returncode == 0 else []
        runtime_ok = bool(post_ok and route_rows and route_rows[0].get("dev") == name and
                          route_rows[0].get("prefsrc") == "198.18.0.1")
        observed_detail = (f"preflight={preflights}, baseline={baseline}, live import={imported}, link={actual}, parent_ifindex={parent.get('ifindex') if parent else None}, "
                           f"kind_ok={kind_ok}, addresses={sorted(nmas_addresses)}, route={route_rows[:1]}")
    except Exception as exc:  # record a complete red assessment after safe restoration
        failure = f"{type(exc).__name__}: {str(exc)[:150]}"
    finally:
        statuses = []
        for spec, preflight in reversed(applied):
            statuses.append(executor.compensate(spec, preflight).status)
        executor.close()
        restored = _frr_link_semantics(_frr_link(container, name)) == baseline
        compensation_ok = bool(applied) and all(s == "COMPENSATED" for s in statuses) and restored
        if not restored:
            raise RuntimeError(f"Disposable FRR interface {name} was not restored to its pre-probe semantics.")
    reference = f"live:{LAB}/frr-{code.lower()}/{timezone.now().isoformat()}"
    context = f"isolated FRR {name}: rendered={added}; observed={observed_detail}; failure={failure or 'none'}"

    def record(stage, ok, detail, reason):
        cell.probes[stage] = assessment.probe("PASS" if ok else "FAIL", f"{context}; {detail}",
                                              reason="" if ok else reason, test_type="LIVE", reference=reference)

    record("live_write", write_ok, "registered LinuxExecutor applied bounded operations; an existing link is changed only "
           "where rendered intent differs from its captured state",
           "EXECUTOR_REFUSED")
    record("live_read", read_ok, "NMAS health reader reached the disposable FRR", "LIVE_READ_ABSENT")
    record("live_post_write_validation", post_ok, "interface kind, parent/VLAN, state and addresses matched", "POSTCHECK_ABSENT")
    record("runtime_validation", runtime_ok, "kernel route selected the new interface/source address", "FUNCTIONAL_TEST_FAILED")
    record("compensation", compensation_ok, f"executor statuses={statuses}; captured link semantics restored={restored}",
           "COMPENSATION_ABSENT")
    cell.runtime_version = "FRRouting 8.4.4 / Ubuntu 24.04 isolated container"


class LiveRegistry(dict):
    """Cell -> probe; lab sessions are opened on first use and closed (restored) once."""

    def __init__(self):
        super().__init__()
        self._labs = {}
        for key in CEOS_SERVICE_CELLS:
            self["arista_ceos", key] = lambda cell, key=key: probe_cell(self._lab("ceos-service", CeosServiceLab), cell, key)
        for key in FRR_INTERFACE_CELLS:
            self["ubuntu_frr", key] = lambda cell, key=key: probe_frr_interface(cell, key)
        from .batch_frr_routing import probe_bgp, probe_ospf, probe_rip
        from .batch_frr_isis import probe_frr_isis
        self["ubuntu_frr", "routing.ISIS"] = probe_frr_isis
        for code in ("BGP_IPV4", "BGP_IPV6"):
            self["ubuntu_frr", f"routing.{code}"] = lambda cell, code=code: probe_bgp(cell, code)
        from .batch_ceos_interfaces import probe_ceos_interface
        for kind in CEOS_INTERFACE_KINDS:
            self["arista_ceos", f"interface.{kind}"] = lambda cell, kind=kind: probe_ceos_interface(cell, kind)
        from .batch_ceos_isis import probe_ceos_isis
        self["arista_ceos", "routing.ISIS"] = probe_ceos_isis
        from .batch_frr_nat import probe_nat
        for code in ("NAT_NAT44_PAT", "NAT_NAT44_STATEFUL"):
            self["ubuntu_frr", f"service_policy.{code}"] = lambda cell, code=code: probe_nat(cell, code)
        from .batch_frr_nat import probe_nat_static
        self["ubuntu_frr", "service_policy.NAT_NAT44_STATIC"] = probe_nat_static     # V2 Phase 9: 1:1 static NAT44
        from .batch_frr_acl import CELLS as FRR_ACL_CELLS, probe_frr_acl
        for key in FRR_ACL_CELLS:           # V2 Phase 9: nftables ACLs and their IN / OUT attachments
            self["ubuntu_frr", key] = lambda cell, key=key: probe_frr_acl(cell, key)
        from .batch_frr_pbr import CELLS as FRR_PBR_CELLS, probe_frr_pbr
        for key in FRR_PBR_CELLS:           # V2 Phase 9: pbrd policy-based routing and its IN attachments
            self["ubuntu_frr", key] = lambda cell, key=key: probe_frr_pbr(cell, key)
        for code in ("RIPV2", "RIPNG"):
            self["ubuntu_frr", f"routing.{code}"] = lambda cell, code=code: probe_rip(cell, code)
        from .batch_srlinux import CELLS as SRLINUX_CELLS, probe_srlinux
        for key in SRLINUX_CELLS:
            self["nokia_srlinux", key] = lambda cell, key=key: probe_srlinux(cell, key)
        from .batch_srlinux_phase9 import CELLS as SRLINUX_PHASE9_CELLS, probe_srlinux_phase9
        for key in SRLINUX_PHASE9_CELLS:     # V2 Phase 9: OSPF / BGP / ACL / DHCP relay against an FRR peer
            self["nokia_srlinux", key] = lambda cell, key=key: probe_srlinux_phase9(cell, key)
        from .batch_iosxe import CELLS as IOSXE_CELLS, probe_iosxe
        for key in IOSXE_CELLS:
            self["cisco_c8000v_iosxe", key] = lambda cell, key=key: probe_iosxe(cell, key)
        for version in ("OSPFV2", "OSPFV3"):
            self["ubuntu_frr", f"routing.{version}"] = lambda cell, version=version: probe_ospf(cell, version)

    def _lab(self, name, factory):
        if name not in self._labs:
            self._labs[name] = factory()
        return self._labs[name]

    def close(self) -> None:
        labs, self._labs = self._labs, {}
        for lab in labs.values():
            lab.close()


def registry() -> LiveRegistry:
    return LiveRegistry()
