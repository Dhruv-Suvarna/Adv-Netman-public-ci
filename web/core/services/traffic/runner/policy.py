"""The runner's OWN limits and request schema -- validation layer two.

The website validates first (``traffic.limits`` / ``traffic.service``).  Nothing here trusts that: a request is re-checked against these
constants, which a request cannot raise.  A contract test keeps the two layers' numbers identical; this copy is the one that guards the
runtime.  A request that is not EXACTLY the closed schema is refused -- an extra key (``container``, ``image``, ``argv``, ``command`` ...)
is a refusal, not something to ignore.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass

from . import PROTOCOL_VERSION

V4, V6 = "IPV4", "IPV6"
ADDRESS_FAMILIES = (V4, V6)
PROTOCOL = {"ICMP": ("ICMP",), "TRACEROUTE": ("ICMP", "UDP"), "TCP_CONNECT": ("TCP",), "UDP_PROBE": ("UDP",), "IPERF3": ("TCP", "UDP")}
BOUNDS = {
    "ICMP": {"count": (1, 5), "size": (16, 1400)},                    # packets, payload bytes (below any lab MTU)
    "TRACEROUTE": {"max_hops": (1, 20)},
    "TCP_CONNECT": {"port": (1, 65535), "timeout": (1, 5)},           # ONE bounded attempt, not a scan
    "UDP_PROBE": {"port": (1, 65535), "timeout": (1, 5), "count": (1, 5), "size": (1, 512)},
    # the only ports a temporary server may listen on; seconds; 64 kbit/s .. 10 Mbit/s (ALWAYS set, never unlimited); streams
    "IPERF3": {"port": (5201, 5210), "duration": (1, 10), "bandwidth_kbps": (64, 10_000), "parallel": (1, 2)},
}
IPERF_UDP_LENGTH = (64, 1400)                                          # datagram bytes; a parameter of IPERF3 over UDP only
PING_PER_PACKET_WAIT = 2
TRACEROUTE_WAIT = 2
IPERF_SERVER_READY_SECONDS = 5
IPERF_GRACE_SECONDS = 10
MAX_ACTIVE_RUNS = 1
MAX_REQUEST_BYTES = 4096
MAX_STDOUT_BYTES = 262_144
MAX_STDERR_BYTES = 4096

REQUEST_KEYS = frozenset({"v", "run_id", "source_endpoint_id", "destination_endpoint_id", "address_family", "test_type", "protocol", "parameters"})


class Refusal(Exception):
    """A request the runner will not execute.  Only the stable ``code`` (and the offending parameter name) leaves the runner."""

    def __init__(self, code: str, field: str = ""):
        super().__init__(code)
        self.code, self.field = code, field


@dataclass(frozen=True)
class Job:
    run_id: uuid.UUID
    source: str
    destination: str
    address_family: str
    test_type: str
    protocol: str
    parameters: dict

    def container_name(self, role: str) -> str:
        """The name of one temporary container of THIS run: derived from the run UUID, so two runs can never share or kill a container."""
        return f"nmas-traffic-{self.run_id.hex}-{role}"


def parameter_bounds(test_type: str, protocol: str) -> dict:
    bounds = dict(BOUNDS[test_type])
    if test_type == "IPERF3" and protocol == "UDP":
        bounds["length"] = IPERF_UDP_LENGTH
    return bounds


def tool_timeout_seconds(test_type: str, parameters: dict) -> int:
    """The wall-clock budget of the measuring tool; it is killed (and its container removed) at this bound."""
    if test_type == "ICMP":
        return parameters["count"] * PING_PER_PACKET_WAIT + 5
    if test_type == "TRACEROUTE":
        return parameters["max_hops"] * TRACEROUTE_WAIT + 5
    if test_type in ("TCP_CONNECT", "UDP_PROBE"):
        return parameters["timeout"] * parameters.get("count", 1) + 5
    return parameters["duration"] + IPERF_GRACE_SECONDS


def _run_id(value) -> uuid.UUID:
    if not isinstance(value, str) or len(value) != 36:
        raise Refusal("MALFORMED_REQUEST", "run_id")
    try:
        parsed = uuid.UUID(value)
    except ValueError as exc:
        raise Refusal("MALFORMED_REQUEST", "run_id") from exc
    if str(parsed) != value or parsed.version != 4:
        raise Refusal("MALFORMED_REQUEST", "run_id")
    return parsed


def validate(document, endpoints: dict) -> Job:
    """A closed-schema request -> Job, or a Refusal.  ``endpoints`` is the runner's catalogue: {id: object with ``.families``}."""
    if not isinstance(document, dict) or set(document) != REQUEST_KEYS:
        raise Refusal("MALFORMED_REQUEST")
    if type(document["v"]) is not int or document["v"] != PROTOCOL_VERSION:
        raise Refusal("UNSUPPORTED_VERSION")
    run_id = _run_id(document["run_id"])
    for key in ("source_endpoint_id", "destination_endpoint_id", "address_family", "test_type", "protocol"):
        if not isinstance(document[key], str) or len(document[key]) > 64:
            raise Refusal("MALFORMED_REQUEST", key)
    test_type, address_family, protocol = document["test_type"], document["address_family"], document["protocol"]
    if test_type not in BOUNDS:
        raise Refusal("UNSUPPORTED_TEST_TYPE")
    if address_family not in ADDRESS_FAMILIES:
        raise Refusal("ADDRESS_FAMILY_UNKNOWN")
    if protocol not in PROTOCOL[test_type]:
        raise Refusal("PROTOCOL_NOT_APPLICABLE")
    source, destination = document["source_endpoint_id"], document["destination_endpoint_id"]
    if source not in endpoints:                       # an id, looked up in the runner's own catalogue: never a container name or id
        raise Refusal("UNKNOWN_ENDPOINT", "source_endpoint_id")
    if destination not in endpoints:
        raise Refusal("UNKNOWN_ENDPOINT", "destination_endpoint_id")
    if source == destination:
        raise Refusal("SAME_ENDPOINT")
    if any(address_family not in endpoints[name].families for name in (source, destination)):
        raise Refusal("FAMILY_NOT_SUPPORTED_BY_ENDPOINT")
    bounds, parameters = parameter_bounds(test_type, protocol), document["parameters"]
    if not isinstance(parameters, dict) or set(parameters) != set(bounds):
        raise Refusal("MALFORMED_REQUEST", "parameters")
    for name, (low, high) in bounds.items():
        value = parameters[name]
        if type(value) is not int or not low <= value <= high:         # a real integer: never a bool, a string, a float or a flag
            raise Refusal("PARAMETER_OUT_OF_BOUNDS", name)
    return Job(run_id, source, destination, address_family, test_type, protocol, dict(parameters))
