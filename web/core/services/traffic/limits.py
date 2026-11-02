"""Hard, server-side bounds of the traffic workbench.  The UI offers these ranges; THIS module enforces them on the website.

Layer one of two: the traffic runner enforces the same numbers again from its own copy (``runner/policy.py``), and a contract test
keeps the two identical.

Conservative lab-safe values: the purpose is controlled validation, never load generation.  Nothing here can be raised by a request.
The ICMP count bound is the health engine's own (``health.live.PING_COUNT_BOUNDS``), so the two ping features cannot drift apart.
"""

from __future__ import annotations

from ... import models
from ..health import live

F = models.TrafficTestFamily
ENGINE_VERSION = "traffic-2"

PING_COUNT = live.PING_COUNT_BOUNDS                 # packets per ICMP test
PING_SIZE = (16, 1400)                              # ICMP payload bytes (below any lab MTU; no fragmentation tests)
PING_PER_PACKET_WAIT = 2                            # seconds
TRACEROUTE_MAX_HOPS = (1, 20)
TRACEROUTE_WAIT = 2                                 # seconds per probe; one probe per hop
PORT = (1, 65535)                                   # TCP / UDP probe destination port (ONE bounded attempt, not a scan)
PROBE_TIMEOUT = (1, 5)                              # seconds
UDP_PROBE_COUNT = (1, 5)                            # datagrams
UDP_PROBE_SIZE = (1, 512)                           # payload bytes
IPERF_PORTS = (5201, 5210)                          # the only ports a temporary iperf3 server may listen on
IPERF_DURATION = (1, 10)                            # seconds
IPERF_BANDWIDTH_KBPS = (64, 10_000)                 # requested bitrate: 64 kbit/s .. 10 Mbit/s (ALWAYS set; never unlimited)
IPERF_DEFAULT_BANDWIDTH_KBPS = 1_000
IPERF_PARALLEL = (1, 2)                             # streams
IPERF_UDP_LENGTH = (64, 1400)                       # datagram bytes
IPERF_SERVER_READY_SECONDS = 5                      # how long the one-off server may take to listen
IPERF_GRACE_SECONDS = 10                            # control-channel overhead on top of the test duration
RAW_OUTPUT_LIMIT = 16_384                           # bytes of tool output kept as evidence
MAX_ACTIVE_RUNS = 1                                 # enforced by the ``one_active_traffic_run`` DB constraint

PROTOCOL = {F.ICMP: ("ICMP",), F.TRACEROUTE: ("ICMP", "UDP"), F.TCP_CONNECT: ("TCP",), F.UDP_PROBE: ("UDP",), F.IPERF3: ("TCP", "UDP")}


def run_timeout_seconds(family: str, parameters: dict) -> int:
    """The wall-clock budget of one run -- every spawned process is killed at this bound."""
    if family == F.ICMP:
        return parameters["count"] * PING_PER_PACKET_WAIT + 5
    if family == F.TRACEROUTE:
        return parameters["max_hops"] * TRACEROUTE_WAIT + 5
    if family in (F.TCP_CONNECT, F.UDP_PROBE):
        return parameters["timeout"] * parameters.get("count", 1) + 5
    return IPERF_SERVER_READY_SECONDS + parameters["duration"] + IPERF_GRACE_SECONDS


class BoundsError(ValueError):
    def __init__(self, field: str, low, high):
        super().__init__(f"{field} must be between {low} and {high}.")
        self.field, self.low, self.high = field, low, high


def bounded_int(raw, field: str, bounds, default=None) -> int:
    """An integer inside ``bounds`` or a BoundsError.  Anything that is not a plain decimal integer is refused (no flags, no units)."""
    low, high = bounds
    text = str(raw).strip() if raw not in (None, "") else ""
    if not text:
        if default is None:
            raise BoundsError(field, low, high)
        return default
    if not text.isdigit() or len(text) > 9:
        raise BoundsError(field, low, high)
    value = int(text)
    if not low <= value <= high:
        raise BoundsError(field, low, high)
    return value
