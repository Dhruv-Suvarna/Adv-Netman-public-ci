"""Test doubles shared by the console tests.  Nothing here reaches a device, a service or the network."""

from __future__ import annotations

import json
import shutil
import tempfile
import time
import unittest
from pathlib import Path

from challenge_console import models as m
from challenge_console.adapters.http import HttpResult
from challenge_console.adapters.process import CommandResult, assert_read_only
from challenge_console.config import ConsoleConfig
from challenge_console.state import EventBus, StateStore
from challenge_console.supervisor import Collector

INVENTORY = {
    "lab_name": "lab",
    "network_devices": {
        "R1": {"username": "a", "monitoring": {"platform": "ceos", "address": "192.0.2.1", "address_v6": "2001:db8::1"}},
        "R3": {"username": "a", "monitoring": {"platform": "linux", "address": "192.0.2.3", "address_v6": "2001:db8::3"}},
        "R5": {"edge": True, "monitoring": {"platform": "ceos", "address": "auto"}},
    },
    "hosts": {"H1": {"ipv4": True, "ipv6": True}, "H2": {"ipv4": True, "ipv6": True}, "H3": {"ipv4": True, "ipv6": True},
              "H4": {"ipv4": False, "ipv6": True}},
}
ADDRESSES = {"H1": ("192.168.10.102", "2001:db8:10::2001"), "H2": ("192.168.20.101", "2001:db8:20::2001"),
             "H3": ("192.168.10.103", "2001:db8:10::2003"), "H4": (None, "2001:db8:30::18e5")}


def wait_until(predicate, timeout: float = 5.0, period: float = 0.01) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(period)
    return bool(predicate())


def addr_json(v4: str | None, v6: str | None) -> str:
    info = [{"family": "inet6", "local": "fe80::1", "prefixlen": 64, "scope": "link"}]
    if v4:
        info.append({"family": "inet", "local": v4, "prefixlen": 24, "scope": "global", "dynamic": True})
    if v6:
        info.append({"family": "inet6", "local": v6, "prefixlen": 128, "scope": "global"})
    return json.dumps([
        {"ifname": "lo", "flags": ["LOOPBACK", "UP"], "addr_info": [{"family": "inet", "local": "127.0.0.1", "scope": "host"}]},
        {"ifname": "eth0", "flags": ["UP"], "addr_info": [{"family": "inet", "local": "172.20.20.2", "prefixlen": 24, "scope": "global"},
                                                         {"family": "inet6", "local": "3fff:172:20:20::2", "prefixlen": 64, "scope": "global"}]},
        {"ifname": "eth1", "flags": ["UP", "LOWER_UP"], "addr_info": info},
    ])


def ping_ok(rtt: float = 3.1) -> CommandResult:
    return CommandResult(0, stdout=f"PING x (x) 56(84) bytes of data.\n64 bytes from x: icmp_seq=1 ttl=63 time={rtt} ms\n\n--- x ping statistics ---\n"
                                   f"1 packets transmitted, 1 received, 0% packet loss, time 0ms\nrtt min/avg/max/mdev = {rtt}/{rtt}/{rtt}/0.000 ms\n")


def ping_timeout() -> CommandResult:
    return CommandResult(1, stdout="PING x (x) 56(84) bytes of data.\n\n--- x ping statistics ---\n1 packets transmitted, 0 received, 100% packet loss, time 0ms\n")


class FakeRunner:
    """A scripted process boundary.  Every argv is still checked against the real read-only allowlist, and recorded."""

    def __init__(self, addresses: dict | None = None):
        self.addresses = dict(ADDRESSES if addresses is None else addresses)
        self.calls: list[tuple] = []
        self.ping_results: dict[tuple[str, str], object] = {}      # (container, target) -> CommandResult | callable
        self.outputs: dict[tuple, object] = {}                     # argv tail -> CommandResult | callable
        self.down_containers: set[str] = set()

    def __call__(self, argv, *, timeout: float = 8.0) -> CommandResult:
        argv = assert_read_only(argv)
        self.calls.append(argv)
        if argv[:2] == ("docker", "exec"):
            container, inner = argv[2], argv[3:]
            if container in self.down_containers:
                return CommandResult(1, stderr_class="CONTAINER_NOT_RUNNING")
            if inner[0] == "ping":
                scripted = self.ping_results.get((container, inner[-1]), ping_ok())
                return scripted() if callable(scripted) else scripted
            if inner[:3] == ("ip", "-j", "addr"):
                name = container.rsplit("-", 1)[-1]
                if name not in self.addresses:
                    return CommandResult(1, stderr_class="NO_SUCH_CONTAINER")
                return CommandResult(0, stdout=addr_json(*self.addresses[name]))
            scripted = self.outputs.get((container, *inner))
            if scripted is not None:
                return scripted() if callable(scripted) else scripted
            return CommandResult(1, stderr_class="COMMAND_FAILED")
        scripted = self.outputs.get(argv)
        if scripted is None:
            scripted = self.outputs.get(argv[:3], CommandResult(1, stderr_class="COMMAND_FAILED"))
        return scripted() if callable(scripted) else scripted


class FakeGetter:
    """Scripted GET: {url prefix: HttpResult | callable(url, headers)}.  Unknown URL = connection refused.  Records every request."""

    def __init__(self, routes: dict | None = None):
        self.routes = dict(routes or {})
        self.requests: list[tuple[str, dict]] = []

    def __call__(self, url, *, timeout=4.0, headers=None, verify_tls=True, max_bytes=262144) -> HttpResult:
        self.requests.append((url, dict(headers or {})))
        for prefix in sorted(self.routes, key=len, reverse=True):
            if url.startswith(prefix):
                scripted = self.routes[prefix]
                return scripted(url, headers or {}) if callable(scripted) else scripted
        return HttpResult(None, error="CONNECTION_REFUSED")


def ok_json(document, status: int = 200) -> HttpResult:
    return HttpResult(status, body=json.dumps(document).encode(), elapsed_ms=1.5)


class ConsoleTestCase(unittest.TestCase):
    """A temp directory, a small fast config, a store and a bus with an in-memory event list."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="console-test-"))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        inventory = self.tmp / "inventory.json"          # YAML is a superset of JSON
        inventory.write_text(json.dumps(INVENTORY))
        policy = self.tmp / "topology.yml"
        policy.write_text("healthy_seconds: 60\nstale_seconds: 120\n")
        self.config = ConsoleConfig(
            lab_name="lab", repo_root=self.tmp, inventory_path=inventory, topology_policy_path=policy, deploy_root=self.tmp / "deploy",
            netbox_url="http://netbox.test", save_dir=self.tmp / "sessions", spool_dir=self.tmp / "spool",
            connectivity_interval=0.02, counters_interval=0.02, services_interval=0.02, automation_interval=0.02, nsot_interval=0.02,
            address_refresh_interval=3600, command_timeout=1.0, http_timeout=1.0, max_backoff=0.2, join_timeout=3.0, stall_factor=3.0)
        self.store = StateStore(history_maxlen=self.config.history_maxlen, retention_seconds=self.config.retention_seconds)
        self.events: list[m.Event] = []
        self.bus = EventBus(self.store)
        self.bus.subscribe(self.events.append)

    def kinds(self, kind: str) -> list[m.Event]:
        return [event for event in list(self.events) if event.kind == kind]


class CountingCollector(Collector):
    """A collector whose every cycle is one event; optionally fails, blocks or dies on demand."""

    def __init__(self, config, store, bus, name: str, *, interval: float = 0.01, fail=None, backoff: bool = True):
        super().__init__(config, store, bus, interval=interval)
        self.name = name
        self.fail = fail                       # callable(cycle) -> None | Exception to raise
        self.backoff_on_error = backoff
        self.count = 0
        self.torn_down = False

    def collect(self) -> None:
        self.count += 1
        problem = self.fail(self.count) if self.fail else None
        if problem is not None:
            raise problem
        self.emit(f"{self.name}.sample", target=self.name, outcome=m.OK, data={"n": self.count})

    def teardown(self) -> None:
        self.torn_down = True
