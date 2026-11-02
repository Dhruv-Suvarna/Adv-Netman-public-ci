"""Interface counters, read with each platform's own native source -- two parsers, not one forced onto both.

cEOS        ``show interfaces | json`` through the container's own ``Cli`` (the credential-free read the health engine's
            ``DockerEosSession`` already uses).  Counters come from ``interfaceCounters``; an interface without that block (an SVI,
            a loopback) is listed with its state and no counters.
Ubuntu/FRR  ``ip -j -s link show``: the kernel's 64-bit ``stats64`` per link.  The kernel exposes no negotiated speed for these
            veth links through iproute2, so speed is left empty rather than invented.

Both are show / read commands: nothing is configured, cleared or enabled on a device.
"""

from __future__ import annotations

import json

from ..models import DOWN, UNKNOWN, UP, InterfaceCounters
from . import process


class CounterReadError(Exception):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def _int(value) -> int | None:
    return int(value) if isinstance(value, (int, float)) and not isinstance(value, bool) else None


def _sum(*values) -> int | None:
    known = [v for v in (_int(value) for value in values) if v is not None]
    return sum(known) if known else None


def parse_ceos(text: str, device: str) -> list[InterfaceCounters]:
    try:
        interfaces = json.loads(text).get("interfaces")
    except (ValueError, AttributeError) as exc:
        raise CounterReadError("PARSE_ERROR") from exc
    if not isinstance(interfaces, dict):
        raise CounterReadError("PARSE_ERROR")
    rows = []
    for name, row in interfaces.items():
        if not isinstance(row, dict):
            continue
        status = str(row.get("interfaceStatus") or "").lower()
        protocol = str(row.get("lineProtocolStatus") or "").lower()
        counters = row.get("interfaceCounters") if isinstance(row.get("interfaceCounters"), dict) else {}
        rx_packets = _int(counters.get("inTotalPkts"))
        tx_packets = _int(counters.get("outTotalPkts"))
        rows.append(InterfaceCounters(
            device=device, name=str(name),
            admin=DOWN if status == "disabled" else UP if status else UNKNOWN,
            oper=UP if protocol == "up" else DOWN if protocol else UNKNOWN,
            speed_bps=_int(row.get("bandwidth")) or None, description=str(row.get("description") or ""),
            rx_bytes=_int(counters.get("inOctets")), tx_bytes=_int(counters.get("outOctets")),
            rx_packets=rx_packets if rx_packets is not None else _sum(counters.get("inUcastPkts"), counters.get("inMulticastPkts"), counters.get("inBroadcastPkts")),
            tx_packets=tx_packets if tx_packets is not None else _sum(counters.get("outUcastPkts"), counters.get("outMulticastPkts"), counters.get("outBroadcastPkts")),
            rx_errors=_int(counters.get("totalInErrors")), tx_errors=_int(counters.get("totalOutErrors")),
            rx_drops=_int(counters.get("inDiscards")), tx_drops=_int(counters.get("outDiscards")),
        ))
    return sorted(rows, key=lambda item: item.name)


def parse_linux(text: str, device: str) -> list[InterfaceCounters]:
    try:
        links = json.loads(text)
    except ValueError as exc:
        raise CounterReadError("PARSE_ERROR") from exc
    if not isinstance(links, list):
        raise CounterReadError("PARSE_ERROR")
    rows = []
    for link in links:
        if not isinstance(link, dict) or not link.get("ifname"):
            continue
        flags = link.get("flags") or []
        operstate = str(link.get("operstate") or "").upper()
        if operstate in ("UP", "DOWN"):
            oper = operstate
        elif operstate == "LOWERLAYERDOWN":
            oper = DOWN
        else:                         # UNKNOWN (loopback, dummy): the carrier flag is the kernel's own answer
            oper = UP if "LOWER_UP" in flags else DOWN if "NO-CARRIER" in flags else UNKNOWN
        stats = link.get("stats64") or link.get("stats") or {}
        rx, tx = stats.get("rx") or {}, stats.get("tx") or {}
        rows.append(InterfaceCounters(
            device=device, name=str(link["ifname"]), admin=UP if "UP" in flags else DOWN, oper=oper, description=str(link.get("ifalias") or ""),
            rx_bytes=_int(rx.get("bytes")), tx_bytes=_int(tx.get("bytes")), rx_packets=_int(rx.get("packets")), tx_packets=_int(tx.get("packets")),
            rx_errors=_int(rx.get("errors")), tx_errors=_int(tx.get("errors")), rx_drops=_int(rx.get("dropped")), tx_drops=_int(tx.get("dropped")),
        ))
    return sorted(rows, key=lambda item: item.name)


COMMANDS = {
    "ceos": (("Cli", "-p", "15", "-c", "show interfaces | json"), parse_ceos),
    "linux": (("ip", "-j", "-s", "link", "show"), parse_linux),
}


def read(device: str, container: str, platform: str, *, runner=process.run, timeout: float = 8.0) -> list[InterfaceCounters]:
    """One read of every interface of one device.  Raises ``CounterReadError`` with a fixed code."""
    if platform not in COMMANDS:
        raise CounterReadError("PLATFORM_NOT_SUPPORTED")
    argv, parser = COMMANDS[platform]
    result = runner(("docker", "exec", container, *argv), timeout=timeout)
    if result.error:
        raise CounterReadError(result.error)
    if not result.ok:
        raise CounterReadError(result.stderr_class or "COMMAND_FAILED")
    return parser(result.stdout, device)
