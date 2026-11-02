"""Reversible NAT44 masquerade probe in the isolated FRR container.

    inside client (FRR peer, eth1)  ---  DUT eth3 | DUT nmasout0  ---  outside endpoint (namespace nmascapout)

The DUT's rendered nftables table is applied and removed by the registered LinuxExecutor.  The outside endpoint is a
UDP echo server that reports the source address it saw, so translation is observed directly rather than inferred.
Addresses, the veth/namespace pair, routes and the ``nft`` package (absent from the disposable image) are lab
prerequisites; every one of them is removed again and the namespace is compared with its captured baseline.
"""

from __future__ import annotations

import json
import subprocess
from copy import deepcopy

from django.utils import timezone

from ..config_import import parser_frr
from ..execution.executors.linux import LinuxExecutor, nft_digest
from . import assessment
from .batch_frr_routing import FrrPair, _call, _configlet, _postcheck, _requirements, _transaction
from .features import by_key
from .isolated_live import LAB, NETWORK, _run, _target
from .offline_verify import _descriptors
from .probe_cases import sample

NS, OUT, OUT_PEER = "nmascapout", "nmasout0", "nmasout1"
INSIDE, OUTSIDE = ("198.18.0.1/30", "198.18.0.2/30"), ("198.18.1.1/30", "198.18.1.2/30")
OTHER = "198.18.9.2"                                   # a client source outside the translated prefix
PORT = 47044
_SERVER = f"""
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind(("{OUTSIDE[1].split('/')[0]}", {PORT})); s.settimeout(5)
try:
    data, peer = s.recvfrom(64); s.sendto(b"ok", peer); print(peer[0])
except socket.timeout:
    print("NONE")
"""
_CLIENT = f"""
import socket, sys, time
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind((sys.argv[1], 0)); s.settimeout(3)
time.sleep(1); s.sendto(b"hi", ("{OUTSIDE[1].split('/')[0]}", {PORT}))
try:
    data, peer = s.recvfrom(64); print("REPLY", peer[0])
except socket.timeout:
    print("NONE")
"""


class NatLab:
    def __init__(self):
        self.dut, _, _ = _target("ubuntu_frr")
        self.fc, self.pc = self.dut["container"], f"clab-{LAB}-peer"
        self.pids = {}
        for container in (self.fc, self.pc):
            (row,) = json.loads(_run(["docker", "inspect", container], timeout=10).stdout or "[null]")
            if not row or row["Config"]["Labels"].get("containerlab") != LAB or NETWORK not in row["NetworkSettings"]["Networks"]:
                raise RuntimeError("NAT endpoint is outside the isolated lab.")
            self.pids[container] = str(row["State"]["Pid"])
        self.baseline = {c: FrrPair.kernel(c) for c in (self.fc, self.pc)}
        self.packages = _call(self.fc, "dpkg-query", "-W", "-f", "${Package}\n").stdout
        self.apt_lists = _call(self.fc, "ls", "/var/lib/apt/lists").stdout
        if _call(self.fc, "ip", "netns", "list").stdout.strip() or OUT in self.baseline[self.fc]:
            raise RuntimeError("Disposable FRR already carries NAT probe state; refusing to write.")
        self.installed = _call(self.fc, "nft", "--version").returncode != 0
        self.prepared = True
        try:
            if self.installed:
                for argv in (("apt-get", "update", "-qq"), ("apt-get", "install", "-y", "-qq", "--no-install-recommends", "nftables")):
                    if _run(["docker", "exec", "-e", "DEBIAN_FRONTEND=noninteractive", self.fc, *argv], timeout=240).returncode:
                        raise RuntimeError("nftables could not be installed in the disposable FRR container.")
            must = FrrPair.must
            must(self.fc, "ip", "netns", "add", NS)
            must(self.fc, "ip", "link", "add", OUT, "type", "veth", "peer", "name", OUT_PEER, "netns", NS)
            must(self.fc, "ip", "addr", "add", OUTSIDE[0], "dev", OUT)
            must(self.fc, "ip", "link", "set", "dev", OUT, "up")
            must(self.fc, "ip", "-n", NS, "addr", "add", OUTSIDE[1], "dev", OUT_PEER)
            must(self.fc, "ip", "-n", NS, "link", "set", "dev", OUT_PEER, "up")
            must(self.fc, "ip", "-n", NS, "route", "add", "default", "via", OUTSIDE[0].split("/")[0])
            must(self.fc, "ip", "addr", "add", INSIDE[0], "dev", "eth3")
            must(self.fc, "ip", "route", "add", f"{OTHER}/32", "via", INSIDE[1].split("/")[0], "dev", "eth3")
            must(self.pc, "ip", "addr", "add", INSIDE[1], "dev", "eth1")
            must(self.pc, "ip", "addr", "add", f"{OTHER}/32", "dev", "eth1")
            must(self.pc, "ip", "route", "add", "198.18.1.0/30", "via", INSIDE[0].split("/")[0], "dev", "eth1")
            self.ruleset = nft_digest(must(self.fc, "nft", "list", "ruleset"))
        except Exception:
            self.close()
            raise

    def flow(self, source) -> tuple[str, str]:
        """One UDP datagram from the inside client: -> (source address the outside endpoint saw, client result)."""
        outside = f"/proc/{self.pids[self.fc]}/root/run/netns/{NS}"
        server = subprocess.Popen(["sudo", "-n", "nsenter", f"--net={outside}", "python3", "-c", _SERVER],
                                  stdout=subprocess.PIPE, text=True)
        client = _run(["sudo", "-n", "nsenter", "-t", self.pids[self.pc], "-n", "python3", "-c", _CLIENT, source], timeout=20)
        return server.communicate(timeout=15)[0].strip(), client.stdout.strip()

    def close(self) -> bool:
        if not getattr(self, "prepared", False):
            return True
        self.prepared = False
        _call(self.pc, "ip", "route", "del", "198.18.1.0/30", "dev", "eth1")
        _call(self.pc, "ip", "addr", "del", f"{OTHER}/32", "dev", "eth1")
        _call(self.pc, "ip", "addr", "del", INSIDE[1], "dev", "eth1")
        _call(self.fc, "ip", "route", "del", f"{OTHER}/32", "dev", "eth3")
        _call(self.fc, "ip", "addr", "del", INSIDE[0], "dev", "eth3")
        _call(self.fc, "ip", "link", "delete", OUT)
        _call(self.fc, "ip", "netns", "delete", NS)
        after = _call(self.fc, "nft", "list", "ruleset")
        # the container's own Docker DNS NAT table must be exactly what it was before the probe wrote anything
        leftover = "" if after.returncode or not hasattr(self, "ruleset") or nft_digest(after.stdout) == self.ruleset else after.stdout
        if self.installed:
            _run(["docker", "exec", "-e", "DEBIAN_FRONTEND=noninteractive", self.fc, "apt-get", "purge", "-y", "-qq", "--auto-remove", "nftables"], timeout=180)
            if not self.apt_lists.strip():
                _call(self.fc, "sh", "-c", "rm -rf /var/lib/apt/lists/*")
        _call(self.fc, "umount", "/run/netns")            # mount point created by ``ip netns add``; absent at the image baseline
        _call(self.fc, "rmdir", "/run/netns")
        checks = {
            "kernel addresses/routes": all(FrrPair.kernel(c) == self.baseline[c] for c in (self.fc, self.pc)),
            "nft ruleset as captured": not leftover,
            "package set": _call(self.fc, "dpkg-query", "-W", "-f", "${Package}\n").stdout == self.packages,
            "no namespace": not _call(self.fc, "ip", "netns", "list").stdout.strip(),
        }
        if not all(checks.values()):
            raise RuntimeError(f"Disposable NAT lab did not return to its captured baseline: {checks}; nft={leftover[:200]!r}")
        return True


SEED = f'table ip DEVICE_BUILDER_PAT {{\n chain postrouting {{\n  type nat hook postrouting priority srcnat; policy accept;\n' \
       f'  oifname "{OUT}" ip saddr 198.18.9.0/24 masquerade\n }}\n}}'


def _scenario(code, block, specs, requirements, rule, seeded: bool) -> dict:
    client, translated = INSIDE[1].split("/")[0], OUTSIDE[0].split("/")[0]
    other_expected = translated if seeded else OTHER      # a pre-existing NMAS rule keeps translating its own prefix
    result = {"actions": [], "statuses": [], "detail": "", "failure": "", "control": ("", ""), "after": ("", "")}
    lab = NatLab()
    executor = LinuxExecutor(lab.dut)
    try:
        executor.connect()
        if seeded:
            FrrPair.must(lab.fc, "nft", SEED)
        before = nft_digest(_call(lab.fc, "nft", "list", "ruleset").stdout)
        result["control"] = (lab.flow(client)[0], lab.flow(OTHER)[0])
        if result["control"] != (client, other_expected):
            raise RuntimeError(f"Control flows are not as expected: outside endpoint saw {result['control']!r}.")
        state = {}

        def verify():
            observed, post_ok, failed = _postcheck(lab.dut, requirements)
            nat = observed.facts("nat") or {}
            imported = [(r.mode, r.outside_interface, r.original_source) for r in parser_frr.parse(
                "", nft_text=_call(lab.fc, "nft", "list", "ruleset").stdout).nat_rules]
            mode_ok = (rule.get("mode"), OUT, rule.get("original_source")) in imported
            seen, reply = lab.flow(client)
            other_seen, _ = lab.flow(OTHER)
            state.update(read_ok=bool(observed.live_reachable),
                         post_ok=post_ok and mode_ok and "DEVICE_BUILDER_PAT" in nat.get("tables", []))
            ok = state["post_ok"] and seen == translated and reply == f"REPLY {OUTSIDE[1].split('/')[0]}" and other_seen == other_expected
            return ok, (f"operator postcheck pass={post_ok} {failed}; nat facts={nat}; import parser read the live ruleset as "
                        f"{imported} (intent mode {rule.get('mode')} recovered={mode_ok}); outside endpoint saw source {seen} for client "
                        f"{client} (translated to DUT outside address {translated}); client got the return datagram [{reply}] "
                        f"(the reply to {translated} was reverse-translated, so connection state exists; conntrack table itself "
                        f"is not readable in this container); source {OTHER} outside the new rule's prefix was seen as {other_seen} "
                        f"(expected {other_expected})")

        result.update(_transaction(executor, specs, verify, attempts=3))
        result.update(state)
        result["after"] = (lab.flow(client)[0], lab.flow(OTHER)[0])
        result["config_restored"] = nft_digest(_call(lab.fc, "nft", "list", "ruleset").stdout) == before
        result["compensated"] = result["compensated"] and result["after"] == (client, other_expected)
    except Exception as exc:
        result["failure"] = f"{type(exc).__name__}: {str(exc)[:400]}"
    finally:
        executor.close()
        _call(lab.fc, "nft", "delete", "table", "ip", "DEVICE_BUILDER_PAT")   # the native seed, or residue of a failed run
        result["restored"] = lab.close()
    return result


def probe_nat(cell, code: str):
    case = sample("ubuntu_frr", by_key()[f"service_policy.{code}"])
    sections = deepcopy(case.sections)
    for interface in sections["interfaces"].values():
        interface["name"] = {"eth1": "eth3", "eth2": OUT}.get(interface["name"], interface["name"])
    rendered = _descriptors("ubuntu_frr", sections)
    start = next(i for i, line in enumerate(rendered) if line.startswith("table ip "))
    block = rendered[start:rendered.index("}", start) + 1]
    rule = next(iter(sections["nat"]["rules"].values()))
    specs = [_configlet(1, "nat_rule", block)]
    requirements = _requirements([("nat", "NAT_RULE_INTENDED", {
        "inside_interface": "eth3", "outside_interface": OUT, "mode": rule.get("mode"),
        "original_source": rule.get("original_source") or ""})])
    scenarios = {"new table": _scenario(code, block, specs, requirements, rule, False),
                 "existing NMAS table (rule appended)": _scenario(code, block, specs, requirements, rule, True)}
    reference = f"live:{LAB}/frr-{code.lower()}/{timezone.now().isoformat()}"
    text = " || ".join(
        f"{label}: preflight={r['actions']}; control before (client, other source seen as)={r['control']}; {r['detail']}; "
        f"compensation={r['statuses']}; after compensation seen as={r['after']}; nft ruleset identical to pre-apply capture="
        f"{r.get('config_restored')}; lab namespace/package baseline restored={r.get('restored')}; {r['failure'] or 'no failure'}"
        for label, r in scenarios.items())
    detail = f"isolated FRR {code}: rendered={[line.strip() for line in block]} || {text}"
    every = lambda *keys: all(r.get(key) for r in scenarios.values() for key in keys)   # noqa: E731
    for name, ok, reason in (
        ("live_write", every("applied"), "FUNCTIONAL_TEST_FAILED"),
        ("live_read", every("read_ok"), "LIVE_READ_ABSENT"),
        ("live_post_write_validation", every("post_ok"), "POSTCHECK_ABSENT"),
        ("runtime_validation", every("verified"), "FUNCTIONAL_TEST_FAILED"),
        ("compensation", every("compensated", "config_restored", "restored"), "COMPENSATION_ABSENT"),
    ):
        cell.probes[name] = assessment.probe("PASS" if ok else "FAIL", detail[:3900], reason="" if ok else reason,
                                             test_type="LIVE", reference=reference)
    cell.runtime_version = "FRRouting 8.4.4 / Ubuntu 24.04 isolated container, nftables 1.0.9 (lab-installed)"
