"""Endpoint address discovery and the single-packet ICMP probe.

Addresses are read from the running endpoint (``ip -j addr show``): H1-H3 take theirs from DHCP, so a hard-coded address would go
stale.  A probe is ONE echo request with a one-second wait, sent from the endpoint's own network namespace with the ``ping`` already in
the image -- nothing is installed, configured or left behind.
"""

from __future__ import annotations

import ipaddress
import json
import re

from ..models import V4, V6
from . import process

_FAMILY = {"inet": V4, "inet6": V6}
_RTT = re.compile(r"time[=<]\s*([\d.]+)\s*ms")
_STATS = re.compile(r"(\d+)\s+packets transmitted,\s+(\d+)\s+(?:packets\s+)?received")


class DiscoveryError(Exception):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def parse_addresses(text: str, *, exclude_interface: str = "eth0") -> dict[str, str]:
    """{IPV4: address, IPV6: address}: the first global, non-management, non-loopback address of each family."""
    try:
        links = json.loads(text)
    except ValueError as exc:
        raise DiscoveryError("PARSE_ERROR") from exc
    if not isinstance(links, list):
        raise DiscoveryError("PARSE_ERROR")
    found: dict[str, str] = {}
    for link in links:
        if not isinstance(link, dict) or link.get("ifname") in (exclude_interface, "lo") or "LOOPBACK" in (link.get("flags") or []):
            continue
        for entry in link.get("addr_info") or []:
            family = _FAMILY.get(entry.get("family"))
            if family is None or entry.get("scope") != "global" or family in found:
                continue
            try:
                found[family] = str(ipaddress.ip_address(entry.get("local")))
            except ValueError:
                continue
    return found


def discover(container: str, *, runner=process.run, timeout: float = 8.0, exclude_interface: str = "eth0") -> dict[str, str]:
    result = runner(("docker", "exec", container, "ip", "-j", "addr", "show"), timeout=timeout)
    if not result.ok:
        raise DiscoveryError(result.error or result.stderr_class or "COMMAND_FAILED")
    return parse_addresses(result.stdout, exclude_interface=exclude_interface)


def parse_ping(text: str, returncode: int | None) -> tuple[bool, float | None, str]:
    """(success, rtt_ms, reason) from iputils ``ping -c 1`` output.  ``reason`` is "" on success, else a fixed code."""
    stats = _STATS.search(text or "")
    if stats and int(stats.group(2)) >= 1:
        rtt = _RTT.search(text)
        return True, (float(rtt.group(1)) if rtt else None), ""
    lowered = (text or "").lower()
    if "unreachable" in lowered:
        return False, None, "UNREACHABLE"
    if stats:
        return False, None, "TIMEOUT"
    return False, None, "PROBE_ERROR" if returncode not in (0, 1) else "TIMEOUT"


def ping(container: str, address: str, family: str, *, runner=process.run, wait: int = 1, timeout: float = 8.0) -> tuple[bool, float | None, str]:
    argv = ("docker", "exec", container, "ping", "-n", "-c", "1", "-W", str(int(wait)), "-6" if family == V6 else "-4", address)
    result = runner(argv, timeout=timeout)
    if result.error:
        return False, None, result.error               # TIMEOUT (of the command itself) / RUNTIME_UNAVAILABLE
    if result.returncode not in (0, 1) and result.stderr_class in ("NO_SUCH_CONTAINER", "CONTAINER_NOT_RUNNING", "PERMISSION_DENIED",
                                                                   "RUNTIME_UNAVAILABLE"):
        return False, None, "SOURCE_" + result.stderr_class
    if result.returncode not in (0, 1) and result.stderr_class == "NETWORK_UNREACHABLE":
        return False, None, "UNREACHABLE"
    return parse_ping(result.stdout, result.returncode)
