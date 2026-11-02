"""Fixtures for the one-time legacy-bootstrap tests.  A CONTROLLED CLOCK and a simulated network: no real time passes, no device, NetBox, Slack or socket.

* ``World``      a simulated network: every managed inventory device answers the production read-only sessions (``FakeSession``) with canned,
                 mutable command output -- including realistic SECRET-BEARING running configurations -- so the real capture, sanitizer, evidence,
                 evaluator and lifecycle code runs unchanged.  Only the SSH / docker read is replaced.
* ``captured``   capture a candidate from the world.   ``started`` / ``passed`` / ``approved``  drive the real lifecycle to that point.
* ``tick`` / ``drive``  one collector tick at an explicit instant / a sequence of ticks, optionally degrading telemetry per instant.

The tests run the REAL 30-minute policy: the clock is controlled, so 1799 s versus 1800 s is exercised without waiting.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from core import models
from core.services import bootstrap_service as bs
from core.services.health import inventory, live
from core.tests.helpers import health as h

# A controlled clock far from any wall-clock stamp (fixtures that run the real Phase-17 engine stamp REAL execution history, which must never look like
# interference against this timeline unless a test says so).
T0 = datetime(2035, 3, 1, 12, 0, 0, tzinfo=timezone.utc)
DURATION, INTERVAL = 1800, 300
END = T0 + timedelta(seconds=DURATION)
DHCP = {"nmas": {"ipv4": "active", "ipv6": "active"}, "r2": {"ipv4": "active", "ipv6": "active"}}
MANAGED = tuple(inventory.managed_devices())
PLATFORM = {name: entry["platform"] for name, entry in inventory.managed_devices().items()}

# secret material that must NEVER be persisted anywhere
SECRETS = ("$6$SALTsalt$hashHASHhash", "hunter2-enable", "0123456789abcdef0123456789abcdef", "S3cr3tCommunity", "070C285F4D06", "BgpNeighborPw", "OspfKeyMaterial")
EOS_CONFIG = """! Command: show running-config
! device: {name} (cEOSLab, EOS-4.36.2F)
!
hostname {name}
username admin privilege 15 role network-admin secret sha512 $6$SALTsalt$hashHASHhash
enable secret sha512 hunter2-enable
snmp-server community S3cr3tCommunity ro
snmp-server user nmas-monitor nmas-group v3 auth sha256 0123456789abcdef0123456789abcdef priv aes 0123456789abcdef0123456789abcdef
tacacs-server key 7 070C285F4D06
router bgp 65001
   neighbor 10.0.0.2 password 7 BgpNeighborPw
interface Ethernet1
   description uplink {name}
   ip address 10.0.{idx}.1/24
   ip ospf message-digest-key 1 md5 OspfKeyMaterial
router ospf 10
   network 10.0.0.0/8 area 0
!
end
"""
FRR_CONFIG = """Building configuration...

Current configuration:
!
frr version 8.4.4
hostname {name}
!
interface eth1
 ip address 10.0.{idx}.1/24
!
router ospf
 network 10.0.0.0/8 area 0
exit
!
end
"""
NFT = "table ip nat {\n\tchain postrouting {\n\t\ttype nat hook postrouting priority srcnat;\n\t}\n}\n"
LINKS = [h.edge("R1", "R2"), h.edge("R2", "R3"), h.edge("S1", "S2")]


def snapshot(now=T0, **kwargs):
    kwargs.setdefault("links", LINKS)
    return h.snapshot(now=now, **kwargs)


class World:
    """The simulated network.  Mutate ``outputs`` / ``down`` between reads to change what the devices report."""

    def __init__(self):
        self.outputs = {}
        self.down = {}
        self.opened = []
        for index, name in enumerate(MANAGED, start=1):
            self.outputs[name] = self._healthy(name, index)

    @staticmethod
    def _healthy(name, index):
        if PLATFORM[name] == "linux":
            outputs = h.linux_outputs(interfaces={"eth1": [f"10.0.{index}.1/24"]}, routes=[("10.9.0.0/24", "10.0.0.2", "eth1")], nft=NFT)
            outputs["frr_config"] = FRR_CONFIG.format(name=name, idx=index)
            return outputs
        return h.eos_outputs(
            interfaces={"Ethernet1": ("connected", "up"), "Management0": ("connected", "up")}, ipv4={"Ethernet1": [f"10.0.{index}.1/24"]},
            routes=[("10.9.0.0/24", "10.0.0.2", "Ethernet1")], ospf=[("Ethernet1", "10.255.0.9", "Full")], config=EOS_CONFIG.format(name=name, idx=index),
        )

    def factory(self, device):
        name = device["name"]
        self.opened.append(name)
        if name in self.down:
            raise self.down[name]
        return h.FakeSession(dict(self.outputs[name]))

    def set_config(self, name, text):
        self.outputs[name]["frr_config" if PLATFORM[name] == "linux" else "running_config"] = text

    def config_of(self, name):
        return self.outputs[name]["frr_config" if PLATFORM[name] == "linux" else "running_config"]

    def edit_config(self, name, old, new):
        assert old in self.config_of(name), old
        self.set_config(name, self.config_of(name).replace(old, new))

    def take_down(self, name, code="CONNECTION_FAILED"):
        self.down[name] = live.LiveError(code)


def captured(world=None, *, now=T0, snap=None, actor="tester"):
    """-> (result, world).  A real, read-only capture of the simulated network."""
    world = world or World()
    result = bs.capture_candidate(actor=actor, now=now, session_factory=world.factory, snapshot=snap or snapshot(now), dhcp_state=DHCP)
    return result, world


def candidate_of(world=None, *, now=T0):
    result, world = captured(world, now=now)
    assert result.bundle is not None, [b["code"] for b in result.blockers]
    return result.bundle, world


def tick(now, world, *, run_id="", telemetry_now=None, **telemetry):
    """One collector tick at ``now``.  ``telemetry``: ``ages`` / ``cpu`` / ``memory`` / ``events`` / ``backend`` / ``links`` for that instant."""
    return bs.run_tick(now=now, snapshot=snapshot(telemetry_now or now, **telemetry), session_factory=world.factory, dhcp_state=DHCP, run_id=run_id)


def drive(world, *, start, until, step=INTERVAL // 2, telemetry_at=None, skip=lambda t: False):
    """Tick every ``step`` seconds from ``start`` to ``until`` (inclusive) while a run is RUNNING.  ``skip(moment)`` simulates a collector outage."""
    reports, moment = [], start
    while moment <= until:
        if not models.LegacyBootstrapRun.objects.filter(state=models.SoakState.RUNNING).exists():
            break
        if not skip(moment):
            reports.append(tick(moment, world, **((telemetry_at(moment) if telemetry_at else None) or {})))
        moment += timedelta(seconds=step)
    return reports


def started(world=None, *, now=T0, actor="tester"):
    """A candidate with a RUNNING observation started at ``now``.  -> (run, candidate, world)"""
    candidate, world = candidate_of(world, now=now)
    result = bs.start_bootstrap(candidate, actor=actor, now=now)
    assert result.run is not None, [b["code"] for b in result.blockers]
    return result.run, candidate, world


def passed(world=None, *, start=T0):
    """An observation driven through its whole window on a healthy network -> COMPLETED / PASS (awaiting the operator's approval)."""
    run, candidate, world = started(world, now=start)
    drive(world, start=start, until=start + timedelta(seconds=DURATION + INTERVAL))
    run.refresh_from_db()
    assert run.is_technical_pass, (run.state, run.result, run.terminal_reason, run.evaluation.get("problems"))
    return run, candidate, world


def confirm_of(run) -> dict:
    return {"run_id": run.run_id, "candidate_id": run.candidate.bundle_id, "candidate_digest": run.candidate_digest, "baseline_digest": run.candidate.payload_digest}


def approved(world=None, *, start=T0, actor="operator"):
    """-> (result, run, candidate, world): a real observation, then the operator's explicit approval (the decision-time re-read sees the SAME world)."""
    run, candidate, world = passed(world, start=start)
    when = run.finished_at + timedelta(seconds=30)
    result = bs.approve(run, actor=actor, confirm=confirm_of(run), now=when, session_factory=world.factory)
    return result, run, candidate, world


# --- wiring the simulated network into the REAL default code paths (views / commands call the service with no injected fakes) -------------------
from contextlib import contextmanager  # noqa: E402
from unittest import mock  # noqa: E402

from django.utils import timezone  # noqa: E402

from core.services.health import telemetry as health_telemetry  # noqa: E402


@contextmanager
def wired(world, **telemetry):
    """Replace ONLY the SSH / docker read, the topology snapshot and the DHCP inspection, for code that takes no injectable arguments (a view, a
    management command).  Everything else -- capture, sanitizer, evidence, evaluator, lifecycle, approval -- is the production code on the real clock."""
    real, real_collect = live.read_device_with_raw, health_telemetry.collect   # captured BEFORE patching (``h.snapshot`` itself calls ``telemetry.collect``)

    def reader(device, raw_keys=(), *, session_factory=None, now=None):
        return real(device, raw_keys, session_factory=world.factory, now=now)

    def collect(*args, **kwargs):
        moment = timezone.now()
        return real_collect(h.topology_summary(now=moment, **{"links": LINKS, **telemetry}), now=moment)

    with mock.patch.object(live, "read_device_with_raw", reader), mock.patch.object(health_telemetry, "collect", collect), \
            mock.patch.object(live, "dhcp_service_state", return_value=DHCP):
        yield


@contextmanager
def no_device_access():
    """Any device read inside the block is a test failure (proves a GET page contacts nothing)."""
    def refuse(*args, **kwargs):
        raise AssertionError("a device was contacted")

    with mock.patch.object(live, "read_device_with_raw", refuse), mock.patch.object(live, "read_device", refuse), mock.patch.object(live, "dhcp_service_state", refuse):
        yield
