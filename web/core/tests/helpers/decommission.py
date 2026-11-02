"""Fixtures for the V2 Phase 7 decommission / restoration tests.  Application state and fakes only.

* ``router_config``  a transit router's running configuration (management on Ethernet5, two production links, OSPFv2 + OSPFv3)
* ``session``        the in-memory EOS session of ``helpers.isolation`` (OSPFv3 blocks understood), driven by the REAL CeosExecutor
* ``observation``    a ``readiness.Observation`` built from maintenance ``Flow`` values (all four family / direction cells)
* ``FakeObserver`` / ``FakeProbe`` / ``runtime``   a decommission ``Runtime`` with no sleeping
"""

from __future__ import annotations

import base64
import json

from core.services.decommission import readiness, service
from core.services.execution.executors.ceos import CeosExecutor
from core.services.maintenance_mode import model
from core.tests.helpers import isolation as I

MGMT = "10.254.70.2"
HOST_KEY_LINE = "ssh-ed25519 " + base64.b64encode(b"\x00\x00\x00\x0bssh-ed25519" + b"k" * 36).decode() + " P7"
OTHER_KEY_LINE = "ssh-ed25519 " + base64.b64encode(b"\x00\x00\x00\x0bssh-ed25519" + b"z" * 36).decode() + " P7"


def router_config(*, ospf=True, ospf6=True, mgmt=MGMT, extra=""):
    lines = ["hostname T1", "!", "interface Ethernet1", "   description to E1", "   no switchport", "   ip address 10.254.81.1/31", "!",
             "interface Ethernet2", "   description to E2", "   no switchport", "   ip address 10.254.83.0/31", "!",
             "interface Ethernet5", "   description NMAS management", "   no switchport", f"   ip address {mgmt}/24", "!",
             "interface Loopback0", "   ip address 10.254.255.2/32", "!", "ip routing", "ipv6 unicast-routing", "!"]
    if ospf:
        lines += ["router ospf 1", "   router-id 10.254.255.2", "   network 10.254.81.0/31 area 0.0.0.0", "!"]
    if ospf6:
        lines += ["ipv6 router ospf 1", "   router-id 10.254.255.2", "!"]
    lines += [line for line in extra.splitlines() if line]
    return "\n".join(lines) + "\nend\n"


def session(text=None, *, key=HOST_KEY_LINE, reject=None):
    fake = I.FakeEosSession(text or router_config(), outputs={"show management ssh hostkey ed25519 public": key}, reject=reject)
    fake.config.MODES = I.EosText.MODES + ("ipv6 router ",)
    return fake


def executor_factory(fake):
    return lambda device: CeosExecutor(device, connection_factory=lambda _d: fake, reader=I._facts)  # pylint: disable=protected-access


def flows(*, active=True, on_device=True):
    activity = model.ACTIVE if active else model.QUIESCED
    return [model.Flow(f"HA->HB {f} {d}", "HA to HB", f, d, model.PRODUCTION, activity, "test", on_device)
            for f in model.FAMILIES for d in model.DIRECTIONS]


def observation(device="T1", *, active=True, on_device=True, alternate=True, ospf=None, full=("E1", "E2"), blind=()):
    alternates = {(f, d): alternate for f in model.FAMILIES for d in model.DIRECTIONS} if on_device else {}
    return readiness.Observation(
        device=device, flows=flows(active=active, on_device=on_device), alternates=alternates,
        adjacencies={f: {"device": list(full), "graph": []} for f in model.FAMILIES},
        ospf={"IPV4": "router ospf 1", "IPV6": "ipv6 router ospf 1"} if ospf is None else ospf, blind_spots=list(blind))


class FakeObserver:
    """Returns the scripted observations in order (the last one repeats)."""

    def __init__(self, *observations):
        self.observations = list(observations)
        self.calls = 0

    def observe(self, device, window_seconds=None):  # pylint: disable=unused-argument
        value = self.observations[min(self.calls, len(self.observations) - 1)]
        self.calls += 1
        return value(device) if callable(value) else value


class FakeProbe:
    def __init__(self, measurement=None):
        self.measurement = measurement if measurement is not None else {"HA->HB IPV4": {"sent": 100, "received": 100},
                                                                         "HA->HB IPV6": {"sent": 100, "received": 100}}

    def stop(self):
        return self.measurement


def runtime(fake, observer, *, probe=None, factory=None):
    return service.Runtime(executor_factory=factory or executor_factory(fake), observer=observer,
                           management_addresses=lambda device: [MGMT], probe_factory=(lambda: probe) if probe is not None else None,
                           sleep=lambda seconds: None, settle_seconds=0.0, move_timeout_seconds=0.0, soak_seconds=0.0,
                           adjacency_timeout_seconds=0.0)


def route(connected=False, interface="Ethernet2", vias=1):
    body = {"directlyConnected": connected, "vias": [{"interface": interface}] * vias} if not connected else {"directlyConnected": True}
    return json.dumps({"vrfs": {"default": {"routes": {"10.254.85.0/24": body}}}})


def neighbors(*rows, key="ospfNeighborEntries"):
    return json.dumps({"vrfs": {"default": {"instList": {"1": {key: [
        {"routerId": rid, "interfaceName": ifname, "adjacencyState": state} for rid, ifname, state in rows]}}}}})


def ospf_id(rid):
    return json.dumps({"vrfs": {"default": {"instList": {"1": {"routerId": rid}}}}})
