"""LIVE harness -- Ubuntu/FRR trusted-upstream isolation (nftables) against the disposable R4-equivalent fixture
``labs/frr-isolation-isolated/fixture.sh``.

NOT part of any automated suite (the module name does not match ``test*.py``).  ``run-harness.sh`` runs it with
``settings_fixture`` (a fresh migrated SQLite database under the git-ignored ``runtime/``).  Stages (state persists in that
database):

    prepare        UP4 adopted (the R4-equivalent upstream), R6FX / R6FXB registered and attached to UP4:eth4 / UP4:eth5 (routed,
                   approved), bootstrap networks A and B with UP4 as their trusted relay
    baseline       NO isolation: the hostile probe on port A reaches production (IPv4 + IPv6), the core, the upstream's SSH; its OSPF
                   forms an adjacency and leaks its loopback; DHCP through the relay works.  The gap being closed.
    plan-blocked   with the probe's OSPF adjacency up, planning is BLOCKED (a route already leaves through the port): never guessed
    isolate        probe OSPF stopped; plan -> precheck -> refused self-approval / wrong hash -> approve -> apply, while a production
                   ping crosses the upstream and the core OSPF adjacency is watched
    verify         probe OSPF restarted (premature OSPF attempt); read-back, active hooks, L2, routing, management plane, the traffic
                   matrix with deny-counter corroboration, DHCP through the relay; production paths unaffected
    release-fail   a release whose admission verification cannot pass: the table is removed, verification fails, the table is
                   re-created (digest-verified) -> ENFORCED, then verified again
    release        the admission release: table removed, OSPF FULL on the port, the device's loopback learned through it -> RELEASED
    fault          a new apply with a fault injected after the table was created: compensation deletes it, digest restored
    drift          port B isolated and verified with probe dev2; an out-of-band deletion of the forward drop rule -> DRIFTED, the
                   ZTP gate closes, and a one-way UDP datagram from the probe now reaches production (the drift is a real leak)
    uncertain      a fault plus an out-of-band nftables change during compensation: restoration unproven -> UNCERTAIN; reconcile
                   proves (and keeps) UNCERTAIN; every later isolation Change on the upstream is refused until resolved
    transport      the executor's SSH session: inventory-resolved target, pinned host key, key-only nmas-svc, sudo limited to
                   nft / vtysh; a wrong pin, a missing pin and a non-writable target are refused before any credential is offered
    report         the evidence index

REAL: FRR 8.4.4 (the production R4 build), nftables 1.0.9 (R4's build), ISC dhcrelay / dhcpd, the Linux kernel forwarding and
OSPF, every packet; the NMAS isolation service, transaction, Change records, the FRR isolation executor and its SSH transport
(``management.linux_ssh``: NMAS runs in the service host's network namespace and logs in to the upstream's loopback).
SUBSTITUTED: the NMAS database (fixture SQLite), ``inventory.yml`` (a fixture inventory listing only UP4, with the fixture's
pinned host key) and the secret provider store (fixture runtime/).  ``docker exec`` is used ONLY by this harness, as the
fixture's out-of-band observer (rulesets, adjacencies) and traffic generator -- never by NMAS.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import time
from pathlib import Path
from unittest import mock

import yaml
from django.conf import settings

from core import models

REPO = Path(settings.REPO_ROOT)
FX = REPO / "labs" / "frr-isolation-isolated"
RUNTIME = FX / "runtime"
EVIDENCE = Path(os.environ.get("NMAS_FRR_LIVE_EVIDENCE") or RUNTIME / "evidence")
OPERATOR, APPROVER, EXECUTOR = "olivia", "arthur", "erin"
P = "nmasfrrfx"
UP = f"{P}-up"
SERVICE, HTTP_PORT = "10.254.92.2", 8080
PROD_V4, PROD_V6, CORE_LO, UP_LO = "10.254.94.10", "2001:db8:fe94::10", "10.254.255.2", "10.254.255.4"
PORTS = {"A": {"device": "R6FX", "interface": "eth4", "probe": "dev", "v4": "10.254.90.2", "v6": "2001:db8:fe90::2", "gw": "10.254.90.1",
               "net": {"name": "frr-boot-a", "ipv4_prefix": "10.254.90.0/29", "gateway": "10.254.90.1", "pool_start": "10.254.90.4",
                       "pool_end": "10.254.90.6", "service_prefix": "10.254.92.0/30", "service_address": SERVICE}},
         "B": {"device": "R6FXB", "interface": "eth5", "probe": "dev2", "v4": "10.254.95.2", "v6": "2001:db8:fe95::2", "gw": "10.254.95.1",
               "net": {"name": "frr-boot-b", "ipv4_prefix": "10.254.95.0/29", "gateway": "10.254.95.1", "pool_start": "10.254.95.4",
                       "pool_end": "10.254.95.6", "service_prefix": "10.254.92.0/30", "service_address": SERVICE}}}
DEV_RID = "10.254.255.6"


# --- fixture plumbing ----------------------------------------------------------------------------------------------------------
def dx(node: str, *argv, timeout=60) -> subprocess.CompletedProcess:
    return subprocess.run(["docker", "exec", f"{P}-{node}", *argv], capture_output=True, text=True, timeout=timeout, check=False)


def fixture(*args, timeout=120) -> str:
    return subprocess.run([str(FX / "fixture.sh"), *args], capture_output=True, text=True, timeout=timeout, check=False).stdout


def evidence(name: str, payload) -> None:
    EVIDENCE.mkdir(parents=True, exist_ok=True)
    text = payload if isinstance(payload, str) else json.dumps(payload, indent=2, sort_keys=True, default=str)
    for marker in ("PRIVATE KEY", "secret sha512", "$6$"):
        assert marker not in text, f"evidence {name} would carry secret material ({marker})"
    (EVIDENCE / name).write_text(text + ("\n" if not text.endswith("\n") else ""), encoding="utf-8")
    print(f"[evidence] {name}")


def wait_for(predicate, *, timeout=60, step=2.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = predicate()
        if value:
            return value
        time.sleep(step)
    return None


def tcp(node: str, address: str, port: int) -> str:
    """OPEN / REFUSED (forwarded both ways, nothing listening) / TIMEOUT (dropped)."""
    done = dx(node, "timeout", "4", "bash", "-c", f"exec 3<>/dev/tcp/{address}/{port}", timeout=20)
    if done.returncode == 0:
        return "OPEN"
    return "REFUSED" if "refused" in (done.stderr or "").lower() else "TIMEOUT"


def forged_sport_tcp(probe: str, host: str, address: str, port: int, sport: int = 22) -> tuple[str, int]:
    """The hostile device opens TCP to ``address:port`` (fixture node ``host``) FROM source port ``sport`` (its own NAT rewrites the port, as any
    device can).  -> (tcp state, packets with that source port the destination host saw).  Without connection tracking a
    "tcp sport 22 accept" rule would forward this as if it were an SSH reply."""
    obs = "nmas_fx_obs"
    dx(host, "sh", "-c", f"nft add table ip {obs} && nft add chain ip {obs} in '{{ type filter hook input priority -10; }}' "
       f"&& nft add rule ip {obs} in tcp sport {sport} tcp dport {port} counter")
    dx(probe, "sh", "-c", "nft add table ip nmas_fx_forge && nft add chain ip nmas_fx_forge post '{ type nat hook postrouting priority srcnat; }' "
       f"&& nft add rule ip nmas_fx_forge post ip daddr {address} tcp dport {port} masquerade to :{sport}")
    try:
        state = tcp(probe, address, port)
    finally:
        dx(probe, "nft", "delete", "table", "ip", "nmas_fx_forge")
        listing = dx(host, "nft", "list", "table", "ip", obs).stdout
        dx(host, "nft", "delete", "table", "ip", obs)
    seen = re.search(r"counter packets (\d+)", listing or "")
    return state, int(seen.group(1)) if seen else -1


def udp_reaches(probe: str, address: str, port: int = 9999) -> bool:
    """One-way: does a UDP datagram from ``probe`` arrive at the production host (no reply needed)?"""
    listener = subprocess.Popen(["docker", "exec", f"{P}-prod", "timeout", "6", "nc", "-u", "-l", "-W", "1", str(port)],
                                stdout=subprocess.PIPE, text=True)
    time.sleep(1)
    dx(probe, "bash", "-c", f"for i in 1 2 3; do echo nmas-drift-probe > /dev/udp/{address}/{port}; sleep 0.5; done")
    out, _ = listener.communicate(timeout=20)
    return "nmas-drift-probe" in (out or "")


def ping(node: str, address: str) -> bool:
    return dx(node, "ping", *(["-6"] if ":" in address else []), "-c", "2", "-W", "1", address, timeout=20).returncode == 0


def ospf_neighbors(node: str = "up") -> str:
    return dx(node, "vtysh", "-c", "show ip ospf neighbor").stdout


def core_adjacency() -> dict:
    """The production-shaped OSPF area 0 adjacency on the upstream's bridged core link (must never flap)."""
    data = json.loads(dx("up", "vtysh", "-c", "show ip ospf neighbor json").stdout or "{}")
    for rid, rows in (data.get("neighbors") or {}).items():
        for row in rows:
            if str(row.get("ifaceName", "")).startswith("Vlan102"):
                return {"neighbor": rid, "state": row.get("nbrState"), "up_ms": row.get("upTimeInMsec")}
    return {}


def _stable(ruleset: str) -> list[str]:
    """A ruleset listing without counter values (what the transaction's digest compares)."""
    return [re.sub(r"counter packets \d+ bytes \d+", "counter", line.strip()) for line in (ruleset or "").splitlines() if line.strip()]


def nft(*args) -> str:
    return dx("up", "nft", *args).stdout


class Production:
    """Production paths across the upstream measured while NMAS writes: a 5/s ping prod -> svc (forwarded by the upstream on
    its core and service interfaces) and an IPv6 ping prod -> the upstream's Vlan102 address (its input hook)."""

    def __init__(self, seconds: int):
        count = str(seconds * 5)
        self.procs = {"prod->svc v4 (forwarded by up)": subprocess.Popen(
            ["docker", "exec", f"{P}-prod", "ping", "-i", "0.2", "-c", count, SERVICE], stdout=subprocess.PIPE, text=True),
                      "prod->up Vlan102 v6 (up's input)": subprocess.Popen(
            ["docker", "exec", f"{P}-prod", "ping", "-6", "-i", "0.2", "-c", count, "2001:db8:fe91::1"], stdout=subprocess.PIPE, text=True)}
        self.adjacency_before = core_adjacency()

    def result(self) -> dict:
        found = {}
        for name, proc in self.procs.items():
            out, _ = proc.communicate(timeout=300)
            match = re.search(r"(\d+) packets transmitted, (\d+) received", out or "")
            found[name] = {"sent": int(match.group(1)), "received": int(match.group(2))} if match else {"raw": (out or "")[-200:]}
        after = core_adjacency()
        found["core_ospf_adjacency"] = {"before": self.adjacency_before, "after": after,
                                        "no_flap": bool(after) and after.get("state", "").startswith("Full")
                                        and int(after.get("up_ms") or 0) >= int(self.adjacency_before.get("up_ms") or 0)}
        found["zero_loss"] = all(v.get("sent") == v.get("received") for k, v in found.items() if k.startswith("prod->"))
        return found


SVC_REF = "runtime://device-credentials/fx-frr-up4-nmas-svc"


def fingerprint_of(public_line: str) -> str:
    import base64
    import hashlib

    return "SHA256:" + base64.b64encode(hashlib.sha256(base64.b64decode(public_line.split()[1])).digest()).decode().rstrip("=")


def up_host_key() -> str:
    return fingerprint_of((RUNTIME / "keys" / "up_host_ed25519.pub").read_text())


def fixture_inventory() -> dict:
    with open(REPO / "inventory.yml", encoding="utf-8") as handle:
        document = yaml.safe_load(handle) or {}
    document["network_devices"] = {
        "UP4": {"username": "nmas-svc", "ssh_key_ref": SVC_REF, "ssh_host_key": up_host_key(),
                "monitoring": {"platform": "linux", "address": UP_LO, "source_interface": "lo"}}}
    document["management"] = {**(document.get("management") or {}), "nmas_ipv4": f"{SERVICE}/30", "nmas_ipv6": ""}
    document["hosts"] = {}
    document["lab_name"] = ""                     # no inventory-derived container name can ever address a production container
    return document


class Harness:
    def __init__(self):
        from core.services import nsot_live
        from core.services.health import inventory as health_inventory

        from modules import device_credentials

        self.inventory = fixture_inventory()
        for target, name in ((health_inventory, "load_inventory"), (nsot_live, "_load_inventory")):
            mock.patch.object(target, name, return_value=self.inventory).start()
        store = RUNTIME / "nmas-provider" / "store.json"
        device_credentials.FileSecretProvider(store).initialize(SVC_REF, (RUNTIME / "keys" / "nmas-svc").read_text(), replace=True)
        real_loader = device_credentials.load_ssh_private_key
        mock.patch.object(device_credentials, "load_ssh_private_key",
                          side_effect=lambda reference, path=None: real_loader(reference, path=store)).start()
        self.last_flows: list = []

    # -- lookups ------------------------------------------------------------------------------------------------------------
    @staticmethod
    def device(name):
        return models.ManagedDevice.objects.filter(name=name).exclude(lifecycle_state__in=tuple(models.DEVICE_LIFECYCLE_TERMINAL)).first()

    @staticmethod
    def attachment(device):
        return device.attachments.filter(upstream_device="UP4").exclude(approval_state=models.AttachmentApproval.REVOKED).order_by("-id").first()

    @staticmethod
    def policy(device):
        return models.IsolationPolicy.objects.filter(device=device).order_by("-id").first()

    @staticmethod
    def access():
        """The production Access for an Ubuntu/FRR upstream, unmodified: the FRR isolation executor over management.linux_ssh."""
        from core.services.execution.executors.frr_isolation import FrrIsolationExecutor
        from core.services.isolation import service as isolation

        base = isolation.default_access(models.Platform.UBUNTU_FRR)
        assert base.executor_factory is FrrIsolationExecutor
        return base

    # -- traffic (fixture vantage points; never an NMAS path) -------------------------------------------------------------------
    def flows(self, port: str = "A") -> list[dict]:
        spec = PORTS[port]
        probe, v4, v6, gw = spec["probe"], spec["v4"], spec["v6"], spec["gw"]
        rows = []

        def add(flow, expect, observed, detail=""):
            rows.append({"flow": flow, "expect": expect, "observed": observed, "detail": detail})

        state = tcp(probe, SERVICE, HTTP_PORT)
        add(f"{probe} -> bootstrap HTTP {SERVICE}:{HTTP_PORT}", "PERMIT", "PERMIT" if state == "OPEN" else "DENY", state)
        state = tcp("svc", v4, 22)
        add(f"NMAS service {SERVICE} -> {v4}:22 (NMAS management)", "PERMIT", "PERMIT" if state == "OPEN" else "DENY", state)
        add(f"{probe} -> production host {PROD_V4} (ICMP)", "DENY", "PERMIT" if ping(probe, PROD_V4) else "DENY")
        add(f"{probe} -> production host {PROD_V6} (ICMPv6)", "DENY", "PERMIT" if ping(probe, PROD_V6) else "DENY")
        add(f"{probe} -> core loopback {CORE_LO} (ICMP, lateral)", "DENY", "PERMIT" if ping(probe, CORE_LO) else "DENY")
        state = tcp(probe, SERVICE, 22)
        add(f"{probe} -> {SERVICE}:22 (not a bootstrap flow)", "DENY", "PERMIT" if state != "TIMEOUT" else "DENY", state)
        state, seen = forged_sport_tcp(probe, "svc", SERVICE, 22)
        add(f"{probe} -> {SERVICE}:22 from forged source port 22 (not an SSH reply)", "DENY",
            "PERMIT" if seen > 0 or state != "TIMEOUT" else "DENY", f"{state}; seen at service: {seen}")
        for address in (gw, UP_LO):
            state = tcp(probe, address, 22)
            add(f"{probe} -> upstream's own SSH {address}:22", "DENY", "PERMIT" if state != "TIMEOUT" else "DENY", state)
        add(f"{probe} -> upstream {gw} (ICMP)", "DENY", "PERMIT" if ping(probe, gw) else "DENY")
        add(f"production host -> {v4} (ICMP)", "DENY", "PERMIT" if ping("prod", v4) else "DENY")
        add(f"production host -> {v6} (ICMPv6)", "DENY", "PERMIT" if ping("prod", v6) else "DENY")
        return rows

    def traffic(self, port="A"):
        def run(_policy, _with_device):
            self.last_flows = self.flows(port)
            return self.last_flows
        return run

    @staticmethod
    def dhcp(port="A") -> dict:
        """The probe asks for a lease through the upstream's relay (then its static probe address is restored)."""
        spec = PORTS[port]
        if port != "A":
            return {"skipped": "port B probe has no DHCP client stage"}
        out = fixture("addr-dev", "dhcp", timeout=90)
        leased = re.search(r"inet (10\.254\.90\.\d+)/29", out or "")
        fixture("addr-dev", "static")
        pool = {f"10.254.90.{i}" for i in range(4, 7)}
        return {"flow": f"{spec['probe']} -> DHCP via relay {spec['gw']} -> dhcpd {SERVICE}", "expect": "PERMIT",
                "observed": "PERMIT" if leased and leased.group(1) in pool else "DENY", "lease": leased.group(1) if leased else "",
                "client_tail": (out or "")[-300:]}

    @staticmethod
    def ospf_state(port_if="eth4") -> dict:
        traffic = dx("dev", "vtysh", "-c", "show ip ospf interface traffic eth1").stdout
        hello = re.search(r"^eth1\s+(\d+)/(\d+)", traffic or "", re.M)
        return {"probe_ospfd_running": dx("dev", "pgrep", "-x", "ospfd").returncode == 0,
                "probe_hellos": {"received": int(hello.group(1)), "sent": int(hello.group(2))} if hello else {"raw": traffic[-200:]},
                "probe_neighbors": dx("dev", "vtysh", "-c", "show ip ospf neighbor").stdout,
                "upstream_neighbors": ospf_neighbors(),
                "core_route_to_device_loopback": dx("core", "ip", "route", "show", f"{DEV_RID}/32").stdout.strip(),
                "probe_on_port": [line for line in ospf_neighbors().splitlines() if port_if in line]}

    # =========================================================================================================================
    def stage_prepare(self):
        from core.services.devices import attachments, lifecycle
        from core.services.ztp import policy as ztp_policy

        record = {}
        if self.device("UP4") is None:
            result = lifecycle.adopt_existing("UP4", role="router", actor=APPROVER)
            assert result.ok, result.codes
        for key, spec in PORTS.items():
            if self.device(spec["device"]) is None:
                result = lifecycle.register_device(name=spec["device"], platform=models.Platform.ARISTA_CEOS, role="router", actor=OPERATOR,
                                                   expected_serial=f"FRRFX{key}0001", expected_base_mac=f"02:5a:77:00:00:{10 + ord(key) - 65:02x}")
                assert result.ok, result.codes
            device = self.device(spec["device"])
            if self.attachment(device) is None:
                result = attachments.register_attachment(device, upstream_device="UP4", upstream_interface=spec["interface"], local_interface="eth1",
                                                         purpose=models.AttachmentPurpose.PRODUCTION, connectivity=models.AttachmentConnectivity.ROUTED,
                                                         vlan=None, actor=OPERATOR)
                assert result.ok, result.codes
                result = attachments.approve_attachment(device, result.attachment.pk, actor=APPROVER)
                assert result.ok, result.codes
            if not models.BootstrapNetwork.objects.filter(name=spec["net"]["name"]).exists():
                _row, problems = ztp_policy.create_network(actor=APPROVER, **spec["net"], trusted_relays=[{"relay_address": spec["gw"], "upstream_device": "UP4"}],
                                                          config_root=str(RUNTIME / "dhcp"), lease_file="", provider="ISC_DHCP", http_port=HTTP_PORT, vlan=None)
                assert not problems, problems
            device = self.device(spec["device"])
            record[spec["device"]] = {"device_id": device.device_id, "state": device.lifecycle_state, "attachment": str(self.attachment(device))}
        up4 = self.device("UP4")
        record["UP4"] = {"device_id": up4.device_id, "state": up4.lifecycle_state, "origin": up4.origin}
        record["upstream_versions"] = {"frr": dx("up", "dpkg-query", "-W", "frr").stdout.strip(), "nft": nft("--version").strip(),
                                       "kernel": dx("up", "uname", "-r").stdout.strip()}
        evidence("00-prepare.json", record)

    def stage_baseline(self):
        fixture("dev-ospf", "start")
        wait_for(lambda: dx("core", "ip", "route", "show", f"{DEV_RID}/32").stdout.strip(), timeout=60)
        record = {"ospf": self.ospf_state(), "nft_ruleset": nft("list", "ruleset"), "flows": self.flows("A"), "flows_port_b": self.flows("B"),
                  "dhcp": self.dhcp("A"), "note": "NO isolation: every DENY-expected flow is observed PERMIT (the gap)"}
        evidence("10-baseline-no-isolation.json", record)

    def _require(self, port):
        from core.services.isolation import service as isolation

        spec = PORTS[port]
        device = self.device(spec["device"])
        policy = isolation.live_policy(self.attachment(device))
        if policy is None:
            result = isolation.require(device, self.attachment(device), network=models.BootstrapNetwork.objects.get(name=spec["net"]["name"]), actor=OPERATOR)
            assert result.ok, result.codes
            policy = result.policy
        return policy

    def stage_plan_blocked(self):
        from core.services.isolation import service as isolation

        fixture("dev-ospf", "start")
        wait_for(lambda: dx("up", "ip", "route", "show", f"{DEV_RID}/32").stdout.strip(), timeout=40)
        policy = self._require("A")
        planned = isolation.plan(policy, actor=OPERATOR, access=self.access())
        evidence("20-plan-blocked-while-routes-leave-the-port.json",
                 {"ok": planned.ok, "codes": planned.codes, "state": planned.policy.state if planned.policy else "",
                  "failure": planned.policy.failure if planned.policy else {}, "ospf": self.ospf_state()})
        assert not planned.ok, "planning must refuse a port that already carries routes"
        assert planned.codes == ["ISOLATION_PORT_SHARED"], planned.codes        # the routing refusal, not an unreadable upstream

    def _approved(self, policy, access, record):
        from core.services.isolation import service as isolation

        planned = isolation.plan(policy, actor=OPERATOR, access=access)
        record["plan"] = {"ok": planned.ok, "codes": planned.codes, "detail": {k: v for k, v in planned.detail.items() if k != "facts"}}
        assert planned.ok, (planned.codes, planned.policy.failure if planned.policy else None)
        policy = planned.policy
        record["ops"] = isolation.ops_of(policy)
        record["intent"] = policy.intent
        checked = isolation.precheck(policy, actor=OPERATOR, access=access)
        record["precheck"] = {"ok": checked.ok, "codes": checked.codes}
        assert checked.ok, checked.codes
        policy = models.IsolationPolicy.objects.get(pk=policy.pk)
        record["self_approval"] = isolation.approve(policy, actor=OPERATOR, confirmation=policy.plan_hash).codes
        record["wrong_hash"] = isolation.approve(policy, actor=APPROVER, confirmation="0" * 64).codes
        approved = isolation.approve(policy, actor=APPROVER, confirmation=policy.plan_hash)
        assert approved.ok, approved.codes
        return approved.policy

    def stage_isolate(self):
        from core.services.isolation import service as isolation

        fixture("dev-ospf", "stop")
        assert wait_for(lambda: not dx("up", "ip", "route", "show", f"{DEV_RID}/32").stdout.strip(), timeout=30) is not None
        access = self.access()
        record = {"ruleset_before": nft("list", "ruleset")}
        policy = self._approved(self._require("A"), access, record)
        production = Production(seconds=30)
        time.sleep(3)
        applied = isolation.apply(policy, actor=EXECUTOR, confirmation=policy.plan_hash, access=access)
        record["apply"] = {"ok": applied.ok, "codes": applied.codes, "outcome": applied.detail.get("outcome"),
                           "steps": applied.detail.get("report", {}).get("steps"), "state": applied.policy.state}
        record["production_during_apply"] = production.result()
        record["table"] = nft("list", "table", "inet", applied.policy.intent["elements"]["PACKET_FILTER"]["table"])
        record["hooks"] = [line.strip() for line in nft("list", "hooks").splitlines() if "nmas_iso" in line or line.startswith("family")]
        record["ruleset_after"] = nft("list", "ruleset")
        change = applied.policy.apply_change
        record["change"] = {"id": change.change_id, "lifecycle": models.Change.objects.get(pk=change.pk).lifecycle_state,
                            "configlets": list(change.configlets.values("cfg_id", "rendered_config", "rollback_config"))}
        evidence("30-isolate-apply.json", record)
        assert applied.ok, (applied.codes, applied.detail.get("report", {}).get("failure"))
        assert record["production_during_apply"]["zero_loss"] and record["production_during_apply"]["core_ospf_adjacency"]["no_flap"]

    def stage_verify(self):
        from core.services.isolation import service as isolation

        fixture("dev-ospf", "start")                      # the probe now tries to form OSPF on the isolated port
        time.sleep(10)
        assert dx("dev", "pgrep", "-x", "ospfd").returncode == 0, "the probe's ospfd must really run during verification"
        device = self.device("R6FX")
        policy = self.policy(device)
        production = Production(seconds=20)
        verified = isolation.verify(policy, actor=APPROVER, access=self.access(), traffic=self.traffic("A"))
        record = {"verify": {"ok": verified.ok, "codes": verified.codes, "summary": verified.detail}, "flows": self.last_flows,
                  "checks": list(models.IsolationCheck.objects.filter(policy=policy).order_by("-id").values("kind", "ok", "code", "facts")[:6]),
                  "ospf": self.ospf_state()}
        record.update({"dhcp_through_relay": self.dhcp("A"),
                  "table_with_counters": nft("list", "table", "inet", policy.intent["elements"]["PACKET_FILTER"]["table"]),
                  "production_during_verify": production.result(), "status": isolation.status(verified.policy),
                  "ztp_gate": isolation.ztp_problems(device, self.attachment(device))})
        evidence("40-verify-traffic-matrix.json", record)
        assert verified.ok, (verified.codes, self.last_flows)
        assert record["dhcp_through_relay"]["observed"] == "PERMIT"

    def _release(self, policy, *, expectations: dict, record: dict, settle: int):
        from core.services.commissioning import admission
        from core.services.isolation import service as isolation

        access = self.access()
        created = isolation.create_release(policy, actor=OPERATOR, reference={"fixture": "frr-isolation"})
        assert created.ok, created.codes
        policy = created.policy
        checked = isolation.release_precheck(policy, actor=OPERATOR, access=access)
        assert checked.ok, checked.codes
        policy = models.IsolationPolicy.objects.get(pk=policy.pk)
        approved = isolation.approve_release(policy, actor=APPROVER, requested_by=OPERATOR, confirmation=created.detail["plan_hash"], extra={})
        assert approved.ok, approved.codes

        def verify_admission(executor):
            deadline = time.monotonic() + settle
            while True:
                failed = admission.failures(executor, policy, expectations)
                if not failed or time.monotonic() >= deadline:
                    record.setdefault("admission_checks", []).append(failed)
                    return failed
                time.sleep(2)

        production = Production(seconds=settle + 15)
        released = isolation.execute_release(policy, actor=EXECUTOR, confirmation=created.detail["plan_hash"], access=access,
                                             verify_admission=verify_admission)
        record["release"] = {"ok": released.ok, "codes": released.codes, "outcome": released.detail.get("outcome"),
                             "restored": released.detail.get("restored"), "state": released.policy.state,
                             "compensation": released.detail.get("report", {}).get("compensation")}
        record["production_during_release"] = production.result()
        return released

    def stage_release_fail(self):
        from core.services.isolation import service as isolation

        device = self.device("R6FX")
        policy = self.policy(device)
        record = {"ruleset_before": nft("list", "ruleset")}
        released = self._release(policy, record=record, settle=10,
                                 expectations={"routing": "OSPF", "ospf_neighbors": ["10.254.255.99"], "routes_v4": ["10.254.255.99/32"],
                                               "routes_v6": [], "reachable": []})
        record["ruleset_after"] = nft("list", "ruleset")
        record["ruleset_identical_after_restore"] = _stable(record["ruleset_before"]) == _stable(record["ruleset_after"])
        time.sleep(8)                                     # the adjacency formed during the window dies (dead interval 4 s)
        verified = isolation.verify(released.policy, actor=APPROVER, access=self.access(), traffic=self.traffic("A"))
        record["reverify"] = {"ok": verified.ok, "codes": verified.codes, "state": verified.policy.state, "flows": self.last_flows}
        evidence("50-release-fail-restored.json", record)
        assert not released.ok and released.policy.state == models.IsolationState.ENFORCED, record["release"]
        assert verified.ok, verified.codes

    def stage_release(self):
        device = self.device("R6FX")
        policy = self.policy(device)
        record = {}
        released = self._release(policy, record=record, settle=40,
                                 expectations={"routing": "OSPF", "ospf_neighbors": [DEV_RID], "routes_v4": [f"{DEV_RID}/32"],
                                               "routes_v6": [], "reachable": [DEV_RID]})
        record["after"] = {"ospf": self.ospf_state(), "flows": self.flows("A"), "ruleset": nft("list", "ruleset")}
        evidence("60-release-admitted.json", record)
        assert released.ok, record["release"]

    def stage_fault(self):
        from core.services.isolation import service as isolation

        fixture("dev-ospf", "stop")
        assert wait_for(lambda: not dx("up", "ip", "route", "show", f"{DEV_RID}/32").stdout.strip(), timeout=30) is not None
        access = self.access()
        record = {"ruleset_before": nft("list", "ruleset")}
        policy = self._approved(self._require("A"), access, record)

        def observer(event, key):
            record.setdefault("observed", []).append([event, key])
            if event == "after" and key == "nft-table":
                record["table_present_at_fault"] = bool(nft("list", "table", "inet", policy.intent["elements"]["PACKET_FILTER"]["table"]))
                raise RuntimeError("fault injected after the table was created")

        applied = isolation.apply(policy, actor=EXECUTOR, confirmation=policy.plan_hash, access=access, observer=observer)
        report = applied.detail.get("report", {})
        record["apply"] = {"ok": applied.ok, "outcome": applied.detail.get("outcome"), "state": applied.policy.state,
                           "compensation": report.get("compensation"), "restored": report.get("restored"),
                           "baseline_digest": report.get("baseline_digest")}
        record["ruleset_after"] = nft("list", "ruleset")
        record["ruleset_identical"] = _stable(record["ruleset_before"]) == _stable(record["ruleset_after"])
        evidence("70-fault-compensated.json", record)
        assert applied.detail.get("outcome") == "FAILED_ROLLED_BACK" and record["ruleset_identical"], record["apply"]

    def stage_uncertain(self):
        from core.services.isolation import service as isolation

        access = self.access()
        record = {}
        policy = self._approved(self.policy(self.device("R6FX")), access, record)

        def observer(event, key):
            if event == "after" and key == "nft-table":
                raise RuntimeError("fault injected after the table was created")
            if event == "before" and key == "compensate":           # someone else changes the ruleset during the compensation
                record["out_of_band"] = dx("up", "nft", "add table inet fx_out_of_band").returncode == 0

        applied = isolation.apply(policy, actor=EXECUTOR, confirmation=policy.plan_hash, access=access, observer=observer)
        report = applied.detail.get("report", {})
        record["apply"] = {"ok": applied.ok, "outcome": applied.detail.get("outcome"), "state": applied.policy.state,
                           "failure": applied.policy.failure, "compensation": report.get("compensation"), "restored": report.get("restored")}
        record["ruleset_after"] = nft("list", "ruleset")
        reconciled = isolation.reconcile(applied.policy, actor=APPROVER, access=access)
        record["reconcile"] = {"ok": reconciled.ok, "codes": reconciled.codes, "state": reconciled.policy.state, "facts": reconciled.detail}
        record["gate_blocks_new_policy"] = isolation.require_problems(self.device("R6FX"), self.attachment(self.device("R6FX")),
                                                                      models.BootstrapNetwork.objects.get(name="frr-boot-a"))
        from core.services.isolation import transaction as iso_transaction

        record["unresolved_runs_on_upstream"] = iso_transaction.unresolved_runs("UP4")   # every later isolation Change on UP4 is refused
        record["operator_cleanup"] = dx("up", "nft", "delete", "table", "inet", "fx_out_of_band").returncode == 0
        evidence("80-uncertain.json", record)
        assert applied.policy.state == models.IsolationState.UNCERTAIN and reconciled.policy.state == models.IsolationState.UNCERTAIN

    def stage_drift(self):
        from core.services.isolation import service as isolation

        access = self.access()
        record = {}
        policy = self._approved(self._require("B"), access, record)
        applied = isolation.apply(policy, actor=EXECUTOR, confirmation=policy.plan_hash, access=access)
        assert applied.ok, applied.codes
        verified = isolation.verify(applied.policy, actor=APPROVER, access=access, traffic=self.traffic("B"))
        record["verify"] = {"ok": verified.ok, "codes": verified.codes, "flows": self.last_flows}
        assert verified.ok, (verified.codes, self.last_flows)
        clean = isolation.check_drift(verified.policy, actor=APPROVER, access=access)
        record["drift_check_clean"] = {"ok": clean.ok, "codes": clean.codes}
        table = policy.intent["elements"]["PACKET_FILTER"]["table"]
        record["udp_probe_to_production_before_drift"] = udp_reaches("dev2", PROD_V4)
        listing = dx("up", "nft", "-a", "list", "chain", "inet", table, "forward").stdout
        handle = re.search(r'iifname "eth5" counter packets \d+ bytes \d+ drop # handle (\d+)', listing).group(1)
        record["out_of_band"] = {"command": f"nft delete rule inet {table} forward handle {handle}  (the device-to-anything drop)",
                                 "rc": dx("up", "nft", "delete", "rule", "inet", table, "forward", "handle", handle).returncode}
        drifted = isolation.check_drift(models.IsolationPolicy.objects.get(pk=policy.pk), actor=APPROVER, access=access)
        record["drift_check"] = {"ok": drifted.ok, "codes": drifted.codes, "state": drifted.policy.state, "facts": drifted.detail}
        device = self.device("R6FXB")
        record["ztp_gate_after_drift"] = isolation.ztp_problems(device, self.attachment(device))
        record["udp_probe_to_production_after_drift"] = udp_reaches("dev2", PROD_V4)      # the drift is a real leak
        evidence("90-drift.json", record)
        assert not drifted.ok and drifted.policy.state == models.IsolationState.DRIFTED

    def stage_transport(self):
        """The executor's session, proven from both ends, and the refusals that happen before any credential is offered."""
        from core.services.execution.executors.base import ExecutorError
        from core.services.execution.executors.frr_isolation import FrrIsolationExecutor
        from core.services.management import linux_ssh

        record = {"target": {k: v for k, v in linux_ssh.target("UP4").items() if k != "ssh_key_ref"}}
        executor = FrrIsolationExecutor({"name": "UP4", "platform": "linux"})
        executor.connect()
        try:
            sock = executor._session._client.get_transport().sock        # pylint: disable=protected-access
            record["socket"] = {"local": list(sock.getsockname()[:2]), "peer": list(sock.getpeername()[:2])}
            record["remote_identity"] = executor._exec(["id", "-un"])[1].strip()                 # pylint: disable=protected-access
            record["privileged_nft_version"] = executor._exec(["nft", "--version"])[1].strip()   # pylint: disable=protected-access
            code, _out = executor._exec(["vtysh", "-c", "show version"])                           # pylint: disable=protected-access
            record["privileged_vtysh_rc"] = code
            done = executor._session._client.exec_command("sudo -n -- id -u", timeout=10)[1]     # pylint: disable=protected-access
            record["sudo_other_program_rc"] = done.channel.recv_exit_status()                     # only nft / vtysh are granted
            record["digest"] = executor.config_state_digest()
            # the upstream's own view of the session (out-of-band observer): established from the NMAS source to its loopback
            record["upstream_view"] = dx("up", "sh", "-c", "ss -tn state established '( sport = :22 )' | tail -n +2").stdout.strip()
        finally:
            executor.close()
        refusals = {}
        for label, change in (("wrong_pin", {"ssh_host_key": "SHA256:" + "A" * 43}), ("no_pin", {"ssh_host_key": ""}),
                              ("not_writable", {"ssh_key_ref": ""})):
            entry = self.inventory["network_devices"]["UP4"]
            saved = dict(entry)
            entry.update(change)
            try:
                FrrIsolationExecutor({"name": "UP4", "platform": "linux"}).connect()
                refusals[label] = "CONNECTED"
            except ExecutorError as exc:
                refusals[label] = exc.code
            finally:
                entry.clear()
                entry.update(saved)
        record["refusals"] = refusals
        record["executor_source_mentions_docker_exec"] = "docker_exec" in Path(
            __import__("core.services.execution.executors.frr_isolation", fromlist=["x"]).__file__).read_text()
        evidence("05-transport.json", record)
        assert record["remote_identity"] == "nmas-svc" and record["privileged_vtysh_rc"] == 0 and record["sudo_other_program_rc"] != 0
        assert record["socket"]["local"][0] == SERVICE and record["socket"]["peer"][0] == UP_LO
        assert refusals == {"wrong_pin": "CONNECTION_FAILED", "no_pin": "NOT_CONFIGURED", "not_writable": "NOT_CONFIGURED"}, refusals

    def stage_report(self):
        index = sorted(p.name for p in EVIDENCE.glob("*.json"))
        policies = list(models.IsolationPolicy.objects.order_by("id").values("id", "state", "upstream_device", "upstream_interface", "upstream_platform"))
        evidence("99-index.json", {"files": index, "policies": policies})


STAGES = ("prepare", "transport", "baseline", "plan-blocked", "isolate", "verify", "release-fail", "release", "fault", "drift", "uncertain", "report")


def main():
    stages = os.environ.get("NMAS_FRR_LIVE_STAGES", "").split()
    unknown = [s for s in stages if s not in STAGES]
    if not stages or unknown:
        raise SystemExit(f"stages: {' '.join(STAGES)} (unknown: {unknown})")
    harness = Harness()
    for stage in stages:
        print(f"=== {stage}")
        getattr(harness, "stage_" + stage.replace("-", "_"))()
