"""Reversible Ubuntu/FRR ACL probes (V2 Phase 9) on the isolated FRR container.

    FRR peer eth1  ---  DUT eth3   (198.18.0.0/30, 2001:db8:44::/64)

Configlets are the planner's own: the harness builds a planning context from the cell's sample intent and calls the
registered ``planning.configlet_factory.HANDLERS`` for the ACL definition and its attachment, so every line NMAS writes
is exactly what a real plan carries; the postcheck requirements are the engine's own descriptors of those Configlets.
Everything NMAS claims goes through the registered ``LinuxExecutor`` in engine order: preflight all, apply, verify,
compensate in reverse.

Lab prerequisites -- the link addresses, the ACL's denied source address (and its return route), and the ``nftables``
package (absent from the disposable image) -- are written natively and removed again; the namespaces are compared with
their captured baselines.  Traffic runs from host tools inside the container namespaces (``nsenter``).

Verification of one scenario:

* operator postcheck -- the Phase-15 evaluators over a fresh live read (ACL definition and attachment read back from
  ``nft list ruleset``);
* live import -- ``parser_frr`` recovers the ACL (type, every entry) and its attachment from the live ruleset;
* behaviour -- IN: the peer reaches the DUT from the permitted source and not from the denied one; an extended list
  also drops the TCP flow its port entry names while the same flow from another source port, and TCP from the
  ICMP-denied host, still connect.  OUT: the DUT's own packets leave the interface from the permitted source address
  and not from the denied one;
* compensation -- the ruleset equals the capture taken before NMAS wrote anything and every flow is answered again.

Each cell runs on a pristine node and on one whose ACL table already holds another NMAS list attached to another
interface, which must survive unchanged (and against which a conflicting attachment is refused); the attachment cells
also run the list attached OUT.
"""

from __future__ import annotations

import json
import random
import subprocess
import time
from copy import deepcopy
from types import SimpleNamespace

from django.utils import timezone

from .. import nft_acl, platform_drivers
from ..config_import import parser_frr
from ..execution.executors.base import ConfigletSpec, ExecutorError
from ..execution.executors.linux import LinuxExecutor, nft_digest
from ..health.requirements import from_descriptor
from ..planning import configlet_factory
from . import assessment
from .batch_frr_routing import FrrPair, _call, _postcheck, _transaction
from .features import by_key
from .isolated_live import LAB, NETWORK, _run, _target
from .probe_cases import sample

PLATFORM = "ubuntu_frr"
CELLS = tuple(f"service_policy.{code}" for code in (
    "ACL_IPV4_STANDARD", "ACL_IPV4_EXTENDED", "ACL_IPV6_STANDARD", "ACL_IPV6_EXTENDED", "ACL_ATTACH_IPV4", "ACL_ATTACH_IPV6"))
PORT, PEER_DEV, SEED_PORT = "eth3", "eth1", "eth2"
LINK = {"IPV4": ("198.18.0.1/30", "198.18.0.2/30"), "IPV6": ("2001:db8:44::1/64", "2001:db8:44::2/64")}
DUT_LINK = {"IPV4": "198.18.0.1", "IPV6": "2001:db8:44::1"}
PEER_HOP = {"IPV4": "198.18.0.2", "IPV6": "2001:db8:44::2"}
DENIED = {"IPV4": "198.18.0.66", "IPV6": "2001:db8:44::66"}     # the address the list denies, on the sending side
SEED_PREFIX = {"IPV4": "198.51.100.0/24", "IPV6": "2001:db8:51::/64"}
TCP_PORT = 80
DENIED_PORTS, OTHER_PORTS = (1024, 2048), (30000, 39999)   # the extended list's source-port range, and ports outside it
RUNTIME = "FRRouting 8.4.4 / Ubuntu 24.04 isolated container, nftables 1.0.9 (lab-installed)"
_SCENARIO_ERRORS = (RuntimeError, ExecutorError, OSError, subprocess.SubprocessError, ValueError, KeyError)

_SERVE = """
import socket, sys, time
s = socket.socket(socket.AF_INET6 if ":" in sys.argv[1] else socket.AF_INET); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind((sys.argv[1], int(sys.argv[2]))); s.listen(8); s.settimeout(0.5); end = time.time() + float(sys.argv[3]); n = 0
while time.time() < end:
    try:
        c, _ = s.accept(); c.close(); n += 1
    except socket.timeout:
        pass
print(n)
"""
_CONNECT = """
import socket, sys
s = socket.socket(socket.AF_INET6 if ":" in sys.argv[1] else socket.AF_INET); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind((sys.argv[1], int(sys.argv[2]))); s.settimeout(3)
try:
    s.connect((sys.argv[3], int(sys.argv[4]))); print("OPEN")
except OSError:
    print("NONE")
"""


def family(key: str) -> str:
    return "IPV6" if key.endswith("IPV6") or "_IPV6_" in key else "IPV4"


# --- intent / plan ---------------------------------------------------------------------------------------------------
def _ace(first: dict, sequence: int, **fields) -> dict:
    return {**first, "id": f"ace_00000000000000{sequence:02d}", "sequence": sequence, "source_port": "",
            "destination_port": "", "logging": False, "destination_type": "ANY", "destination_value": "", "protocol": "IP",
            **fields}


def intent(key: str, direction: str = "IN") -> dict:
    """The cell's sample intent, adjusted only where the behaviour test needs specific values: a list that denies the
    lab's denied source and permits everything else (an extended list denies only ICMP from it, plus a logged TCP
    source-port-range entry towards the DUT), attached ``direction`` on the DUT's lab port."""
    sections = deepcopy(sample(PLATFORM, by_key()[key]).sections)
    fam = family(key)
    interface = next(iter(sections["interfaces"].values()))
    interface["name"] = PORT
    acl = next(iter(sections["security"]["acls"].values()))
    first = next(iter(acl["entries"].values()))
    if acl.get("acl_type") == "EXTENDED":
        entries = [_ace(first, 10, action="DENY", protocol="ICMPV6" if fam == "IPV6" else "ICMP", source_type="HOST",
                        source_value=DENIED[fam]),
                   _ace(first, 15, action="DENY", protocol="TCP", destination_type="HOST", destination_value=DUT_LINK[fam],
                        source_port="{}-{}".format(*DENIED_PORTS), destination_port=str(TCP_PORT), logging=True),
                   _ace(first, 20, action="PERMIT", source_type="ANY", source_value="")]
    else:
        entries = [_ace(first, 10, action="DENY", source_type="HOST", source_value=DENIED[fam]),
                   _ace(first, 20, action="PERMIT", source_type="ANY", source_value="")]
    acl["entries"] = {row["id"]: row for row in entries}
    sections["security"]["attachments"] = {"attach_0000000000000003": {
        "id": "attach_0000000000000003", "acl_id": acl["id"], "interface_id": interface["id"], "direction": direction}}
    return sections


def planner_context(sections: dict):
    """A ``configlet_factory.DeviceContext`` over sample intent (the hydrated shape the planner itself uses)."""
    ctx = object.__new__(configlet_factory.DeviceContext)
    ctx.intent = SimpleNamespace(target_type="", device_name="frr", platform=PLATFORM)
    ctx.name, ctx.platform, ctx.hostname = "frr", PLATFORM, "frr"
    ctx.driver = platform_drivers.get_driver(PLATFORM)
    ctx.field_values = {"device.hostname": "frr", "device.description": ""}
    ctx.interfaces = deepcopy(list(sections["interfaces"].values()))
    ctx.routing = deepcopy(sections.get("routing") or {})
    ctx.phase12 = {name: deepcopy(sections.get(name) or {}) for name in ("fhrp", "nat", "services", "security", "policy")}
    ctx.auto = {}
    return ctx


def _executor_spec(n: int, spec) -> ConfigletSpec:
    """The engine's own reduction of a planned Configlet (``ConfigletSpec.from_configlet`` drops comment lines)."""
    lines = tuple(line.rstrip() for line in spec.lines if line.strip() and not line.strip().startswith(("!", "#")))
    operation = str(getattr(spec.object_class.operation, "value", spec.object_class.operation))
    return ConfigletSpec(f"P9-FRR-{spec.object_type}-{n}", n, "frr", PLATFORM, spec.object_type, operation, lines,
                         dict(spec.facts))


def plan(key: str, direction: str = "IN"):
    """-> (executor Configlet specs, postcheck requirements, intent sections)."""
    sections = intent(key, direction)
    ctx = planner_context(sections)
    nodes = [("acl", acl_id) for acl_id in sections["security"]["acls"]]
    nodes += [("acl_attachment", attach_id) for attach_id in sections["security"]["attachments"]]
    planned = [spec for kind, object_id in nodes for spec in configlet_factory.HANDLERS[kind](
        ctx, {"id": f"frr/{kind}/{object_id}", "type": kind, "object_id": object_id, "label": f"frr {kind} {object_id}"})]
    specs = [_executor_spec(n, spec) for n, spec in enumerate(planned, 1)]
    requirements = [from_descriptor(spec.cfg_id, descriptor) for spec, plan_spec in zip(specs, planned)
                    for descriptor in configlet_factory.verification_requirements(plan_spec)]
    return specs, requirements, sections


def seed(fam: str) -> str:
    """A pre-existing NMAS list attached IN on another interface: the table NMAS must extend and leave intact."""
    legacy = {"name": "LEGACY", "family": fam, "acl_type": "STANDARD", "entries": {"e": {
        "id": "e", "sequence": 10, "action": "DENY", "source_type": "PREFIX", "source_value": SEED_PREFIX[fam]}}}
    chain = nft_acl.chain_name(fam, "LEGACY")
    return (f"create table inet {nft_acl.TABLE}\n" + nft_acl.create_chain_commands(chain, nft_acl.acl_rules(legacy))
            + nft_acl.create_hook_commands("IN") + nft_acl.jump_commands("IN", [(SEED_PORT, fam, chain)]))


def preserved(fam: str, ruleset: str) -> bool:
    model = nft_acl.table_from_ruleset(ruleset)
    chain = nft_acl.chain_name(fam, "LEGACY")
    return bool(model) and chain in model["acls"] and (SEED_PORT, fam, chain) in model["hooks"]["IN"] \
        and [e["source_value"] for e in model["acls"][chain]["entries"]] == [SEED_PREFIX[fam]]


def conflicting(fam: str) -> ConfigletSpec:
    """An attachment of the cell's list IN on the seed's interface, where another list of the family already filters."""
    chain = nft_acl.chain_name(fam, "CAP_ACL")
    header = nft_acl.hook_header("IN")
    lines = (nft_acl.TABLE_HEADER, f"    {header[0]}", f"        {header[1]}",
             f"        {nft_acl.jump_rule('IN', SEED_PORT, fam, chain)}", "    }")
    return ConfigletSpec("P9-FRR-acl_attachment-conflict", 9, "frr", PLATFORM, "acl_attachment", "ATTACH", lines,
                         {"acl_name": "CAP_ACL", "interface": SEED_PORT, "direction": "IN"})


def imported(sections: dict, ruleset: str, direction: str) -> bool:
    """The live ruleset, imported by the operator parser, carries the ACL (type and every entry) and its attachment."""
    acl = next(iter(sections["security"]["acls"].values()))
    addr = json.dumps([{"ifname": PORT, "flags": ["UP"], "mtu": 1500, "addr_info": []}])
    parsed = parser_frr.parse("", addr_json=addr, nft_text=ruleset)
    row = next((a for a in parsed.acls if a.name == acl["name"] and a.family == acl["family"]), None)
    wanted = [nft_acl.entry_rule(acl["family"], acl["acl_type"], e)
              for e in sorted(acl["entries"].values(), key=lambda e: e["sequence"])]
    got = [nft_acl.entry_rule(row.family, row.acl_type, e) for e in row.entries] if row else []
    port = next((i for i in parsed.interfaces if i.name == PORT), None)
    return bool(row) and row.acl_type == acl["acl_type"] and got == wanted and bool(port) \
        and {"family": acl["family"], "name": acl["name"], "direction": direction} in port.acl_attachments


# --- lab -------------------------------------------------------------------------------------------------------------
class AclLab:
    """The DUT/peer link in both families plus the denied source on the sending side; nftables installed if absent."""

    def __init__(self, fam: str, direction: str):
        self.dut, _, _ = _target(PLATFORM)
        self.fc, self.pc = self.dut["container"], f"clab-{LAB}-peer"
        self.family, self.direction, self.pids = fam, direction, {}
        for container in (self.fc, self.pc):
            (row,) = json.loads(_run(["docker", "inspect", container], timeout=10).stdout or "[null]")
            if not row or row["Config"]["Labels"].get("containerlab") != LAB or NETWORK not in row["NetworkSettings"]["Networks"]:
                raise RuntimeError("ACL endpoint is outside the isolated lab.")
            self.pids[container] = str(row["State"]["Pid"])
        self.baseline = {c: FrrPair.kernel(c) for c in (self.fc, self.pc)}
        self.packages = _call(self.fc, "dpkg-query", "-W", "-f", "${Package}\n").stdout
        self.apt_lists = _call(self.fc, "ls", "/var/lib/apt/lists").stdout
        if any(addr.split("/")[0] in self.baseline[c] for c in (self.fc, self.pc) for addr in (*LINK["IPV4"], DENIED["IPV4"])):
            raise RuntimeError("Disposable FRR already carries ACL probe addresses; refusing to write.")
        self.installed = _call(self.fc, "nft", "--version").returncode != 0
        self.prepared = True
        # the denied source lives where the probed packets start: on the peer (IN) or on the DUT itself (OUT)
        self.sender, self.receiver = (self.pc, self.fc) if direction == "IN" else (self.fc, self.pc)
        try:
            if self.installed:
                for argv in (("apt-get", "update", "-qq"), ("apt-get", "install", "-y", "-qq", "--no-install-recommends", "nftables")):
                    if _run(["docker", "exec", "-e", "DEBIAN_FRONTEND=noninteractive", self.fc, *argv], timeout=240).returncode:
                        raise RuntimeError("nftables could not be installed in the disposable FRR container.")
            must = FrrPair.must
            for container, dev, side in ((self.fc, PORT, 0), (self.pc, PEER_DEV, 1)):
                must(container, "ip", "addr", "add", LINK["IPV4"][side], "dev", dev)
                must(container, "ip", "-6", "addr", "add", LINK["IPV6"][side], "dev", dev, "nodad")
            sender_dev = PEER_DEV if direction == "IN" else PORT
            receiver_dev = PORT if direction == "IN" else PEER_DEV
            back = PEER_HOP["IPV4"] if direction == "IN" else DUT_LINK["IPV4"]
            must(self.sender, "ip", "addr", "add", f"{DENIED['IPV4']}/32", "dev", sender_dev)
            must(self.sender, "ip", "-6", "addr", "add", f"{DENIED['IPV6']}/64", "dev", sender_dev, "nodad")
            must(self.receiver, "ip", "route", "add", f"{DENIED['IPV4']}/32", "via", back, "dev", receiver_dev)
            self.ruleset = nft_digest(must(self.fc, "nft", "list", "ruleset"))
        except Exception:
            self.close()
            raise

    def _ns(self, container, *argv, timeout=30):
        return _run(["sudo", "-n", "nsenter", "-t", self.pids[container], "-n", *argv], timeout=timeout)

    def ping(self, source: str, target: str) -> bool:
        result = self._ns(self.sender, "ping", "-c", "2", "-W", "1", "-I", source, target)
        return result.returncode == 0 and " 0% packet loss" in result.stdout

    def tcp(self, flows) -> list[bool]:
        """TCP connects (source, source-port range) -> the receiver's port 80 at ``DUT_LINK``: -> [connected?].  Each
        connect takes a fresh port from its range, so no flow ever meets a TIME_WAIT left by an earlier round."""
        target = DUT_LINK[self.family]
        server = subprocess.Popen(["sudo", "-n", "nsenter", "-t", self.pids[self.receiver], "-n", "python3", "-I", "-c", _SERVE,
                                   target, str(TCP_PORT), str(4 * len(flows) + 2)], stdout=subprocess.PIPE, text=True)
        try:
            time.sleep(0.5)
            results = [self._ns(self.sender, "python3", "-I", "-c", _CONNECT, source, str(random.randint(*ports)), target,
                                str(TCP_PORT)).stdout.strip() == "OPEN" for source, ports in flows]
        finally:
            if server.poll() is None:       # sudo relays SIGTERM to the listener; it has served every connect above
                server.terminate()
            server.communicate(timeout=15)
        return results

    def observe(self, extended: bool) -> dict:
        """The flows the scenario judges.  IN: the peer reaches the DUT; OUT: the DUT reaches the peer."""
        fam = self.family
        target = DUT_LINK[fam] if self.direction == "IN" else PEER_HOP[fam]
        permitted = PEER_HOP[fam] if self.direction == "IN" else DUT_LINK[fam]
        seen = {"ping permitted": self.ping(permitted, target), "ping denied": self.ping(DENIED[fam], target)}
        if self.direction == "IN":
            flows = {"tcp permitted, source port in denied range": (permitted, DENIED_PORTS),
                     "tcp permitted, other source port": (permitted, OTHER_PORTS),
                     "tcp denied source": (DENIED[fam], OTHER_PORTS)}
            seen.update(zip(flows, self.tcp(list(flows.values()))))
        return seen

    def expected(self, extended: bool, filtering: bool) -> dict:
        unfiltered = {"ping permitted": True, "ping denied": True}
        if self.direction == "IN":
            unfiltered.update({"tcp permitted, source port in denied range": True, "tcp permitted, other source port": True,
                               "tcp denied source": True})
        if not filtering:
            return unfiltered
        found = {**unfiltered, "ping denied": False}
        if self.direction == "IN":
            if extended:     # only ICMP from the denied host is dropped; the port entry drops the in-range source port
                found["tcp permitted, source port in denied range"] = False
            else:            # a standard list drops everything from the denied host
                found["tcp denied source"] = False
        return found

    def settled(self, extended: bool, filtering: bool, limit: float = 40.0) -> tuple[bool, dict, int]:
        """``observe`` until it matches ``expected`` (neighbour discovery on a freshly addressed link takes a moment)."""
        started = time.monotonic()
        while True:
            seen = self.observe(extended)
            if seen == self.expected(extended, filtering) or time.monotonic() - started > limit:
                return seen == self.expected(extended, filtering), seen, int(time.monotonic() - started)
            time.sleep(2)

    def close(self) -> bool:
        if not getattr(self, "prepared", False):
            return True
        self.prepared = False
        receiver_dev = PORT if self.direction == "IN" else PEER_DEV
        sender_dev = PEER_DEV if self.direction == "IN" else PORT
        _call(self.receiver, "ip", "route", "del", f"{DENIED['IPV4']}/32", "dev", receiver_dev)
        _call(self.sender, "ip", "-6", "addr", "del", f"{DENIED['IPV6']}/64", "dev", sender_dev)
        _call(self.sender, "ip", "addr", "del", f"{DENIED['IPV4']}/32", "dev", sender_dev)
        for container, dev, side in ((self.fc, PORT, 0), (self.pc, PEER_DEV, 1)):
            _call(container, "ip", "-6", "addr", "del", LINK["IPV6"][side], "dev", dev)
            _call(container, "ip", "addr", "del", LINK["IPV4"][side], "dev", dev)
        after = _call(self.fc, "nft", "list", "ruleset")
        leftover = "" if after.returncode or not hasattr(self, "ruleset") or nft_digest(after.stdout) == self.ruleset else after.stdout
        if self.installed:
            _run(["docker", "exec", "-e", "DEBIAN_FRONTEND=noninteractive", self.fc, "apt-get", "purge", "-y", "-qq",
                  "--auto-remove", "nftables"], timeout=180)
            if not self.apt_lists.strip():
                _call(self.fc, "sh", "-c", "rm -rf /var/lib/apt/lists/*")
        for container in (self.fc, self.pc):             # stale neighbour entries of the removed addresses
            _call(container, "ip", "neigh", "flush", "dev", PORT if container == self.fc else PEER_DEV)
        checks = {
            "kernel addresses/routes": all(FrrPair.kernel(c) == self.baseline[c] for c in (self.fc, self.pc)),
            "nft ruleset as captured": not leftover,
            "package set": _call(self.fc, "dpkg-query", "-W", "-f", "${Package}\n").stdout == self.packages,
        }
        if not all(checks.values()):
            raise RuntimeError(f"Disposable ACL lab did not return to its captured baseline: {checks}; nft={leftover[:200]!r}")
        return True


# --- scenario / probe ------------------------------------------------------------------------------------------------
def _scenario(key: str, *, seeded: bool, direction: str = "IN") -> dict:
    specs, requirements, sections = plan(key, direction)
    fam = family(key)
    extended = next(iter(sections["security"]["acls"].values()))["acl_type"] == "EXTENDED"   # the list actually written
    result = {"actions": [], "statuses": [], "detail": "", "failure": "", "imported": False, "control": False,
              "after": False, "preserved": True, "negative": ""}
    lab = AclLab(fam, direction)
    executor = LinuxExecutor(lab.dut)
    try:
        executor.connect()
        if seeded:
            FrrPair.must(lab.fc, "nft", seed(fam))
        before = _call(lab.fc, "nft", "list", "ruleset").stdout
        result["control"], seen, took = lab.settled(extended, filtering=False)
        control = f"control before apply (unfiltered expected) ok={result['control']} after {took} s: {seen}"
        if not result["control"]:
            raise RuntimeError(f"Control flows are not as expected: {seen!r}.")
        if seeded:
            found = executor.assess(conflicting(fam))
            result["negative"] = f"{found.action}/{found.restorable}/{found.reason or '-'}"
        state = {}

        def verify():
            observed, post_ok, failed = _postcheck(lab.dut, requirements)
            ruleset = _call(lab.fc, "nft", "list", "ruleset").stdout
            result["imported"] = imported(sections, ruleset, direction)
            kept = preserved(fam, ruleset) if seeded else True
            filtered, flows, _took = lab.settled(extended, filtering=True, limit=6)
            state.update(read_ok=bool(observed.live_reachable), post_ok=post_ok, preserved=kept)
            return post_ok and result["imported"] and filtered and kept, (
                f"operator postcheck pass={post_ok} {failed}; config facts={observed.facts('config')}; live nft import "
                f"recovered the list, its {len(sections['security']['acls'])} definition(s) and every entry, and the "
                f"{direction} attachment={result['imported']}; flows while attached (expected "
                f"{lab.expected(extended, True)}): {flows}; pre-existing NMAS list preserved={kept}")

        result.update(_transaction(executor, specs, verify, attempts=3))
        result.update(state)
        ruleset = _call(lab.fc, "nft", "list", "ruleset").stdout
        result["config_restored"] = nft_digest(ruleset) == nft_digest(before)
        if seeded:
            result["preserved"] = result.get("preserved", True) and preserved(fam, ruleset)
        result["after"], seen, took = lab.settled(extended, filtering=False)
        result["detail"] = f"{control}; " + result["detail"] + f"; after compensation (unfiltered expected) after {took} s: {seen}"
    except _SCENARIO_ERRORS as exc:     # recorded as the scenario's failure; anything else aborts the run (fail closed)
        result["failure"] = f"{type(exc).__name__}: {str(exc)[:400]}"
    finally:
        executor.close()
        _call(lab.fc, "nft", "delete", "table", "inet", nft_acl.TABLE)    # the native seed, or residue of a failed run
        result["restored"] = lab.close()
    return result


def scenarios_for(key: str) -> dict:
    found = {"pristine node": _scenario(key, seeded=False),
             "existing NMAS ACL table (another list attached elsewhere)": _scenario(key, seeded=True)}
    if key.startswith("service_policy.ACL_ATTACH_"):
        found["pristine node, attached OUT"] = _scenario(key, seeded=False, direction="OUT")
    return found


def probe_frr_acl(cell, key: str):
    specs, _, _ = plan(key)
    scenarios = scenarios_for(key)
    reference = f"live:{LAB}/frr-{key.split('.')[1].lower()}/{timezone.now().isoformat()}"
    rendered = "; ".join(f"[{spec.object_type}] " + " / ".join(line.strip() for line in spec.lines) for spec in specs)
    text = " || ".join(
        f"{label}: preflight={r['actions']}; conflicting-attachment preflight={r['negative'] or 'n/a'}; {r['detail']}; "
        f"compensation={r['statuses']} codes={r.get('compensation_codes')}; nft ruleset identical to pre-apply capture="
        f"{r.get('config_restored')}; pre-existing list preserved={r.get('preserved')}; lab baseline restored="
        f"{r.get('restored')}; {r['failure'] or 'no failure'}" for label, r in scenarios.items())
    # outcomes first: stored evidence detail is bounded, and the rendered Configlets are reproducible from the plan
    detail = (f"isolated FRR {key} against an FRR peer through the registered LinuxExecutor (nftables table "
              f"{nft_acl.TABLE}, atomic transactions, captured-ruleset inverse) || {text} || Configlets from the planner's "
              f"own handlers: {rendered}")
    negative_ok = scenarios["existing NMAS ACL table (another list attached elsewhere)"]["negative"] == \
        "APPLY/False/COMPENSATION_NOT_PROVABLE"

    def every(*keys) -> bool:
        return all(r.get(k) for r in scenarios.values() for k in keys)

    for stage, ok, reason in (
        ("live_write", every("applied"), "FUNCTIONAL_TEST_FAILED"),
        ("live_read", every("read_ok"), "LIVE_READ_ABSENT"),
        ("live_post_write_validation", every("post_ok"), "POSTCHECK_ABSENT"),
        ("parser_import", every("imported"), "PARSER_ABSENT"),
        ("runtime_validation", every("verified", "control") and negative_ok, "FUNCTIONAL_TEST_FAILED"),
        ("compensation", every("compensated", "config_restored", "after", "restored", "preserved"), "COMPENSATION_ABSENT"),
    ):
        cell.probes[stage] = assessment.probe("PASS" if ok else "FAIL", detail[:3900], reason="" if ok else reason,
                                              test_type="LIVE", reference=reference)
    cell.runtime_version = RUNTIME
    return scenarios
