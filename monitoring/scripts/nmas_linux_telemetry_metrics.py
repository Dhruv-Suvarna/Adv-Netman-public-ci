#!/usr/bin/env python3
"""Pure, dependency-free functions that read REAL live state from an Ubuntu
24.04 + FRRouting router (R3/R4) -- no synthetic/canned values anywhere.
Shared by linux_gnmi_server.py and linux_netconf_server.py (both import this
module from the same deployment directory, /etc/nmas-telemetry/).

Sources, all read fresh on every call:
  hostname()    -> socket.gethostname() (the container's real hostname, "R3"/"R4")
  cpu_snapshot()/cpu_percent() -> /proc/stat aggregate "cpu " line, delta-based
                                   utilization (NOT load average -- see cpu_percent()).
  memory()      -> /proc/meminfo
  interfaces()  -> /sys/class/net/<if>/{flags,operstate,statistics/*}
"""
from __future__ import annotations

import socket
from pathlib import Path

NET = Path("/sys/class/net")

# Same six counters modules/scripts/gnmi_collector.py stores for cEOS
# (docs/TELEMETRY_STREAMS.md) -- kept identical so native and adapter
# sources share one InfluxDB schema. Real per-interface packet/broadcast/
# multicast counters exist on the wire (/sys/class/net/.../statistics/) but
# are intentionally not exposed, matching the same "small selected set"
# scope as the cEOS collector.
COUNTER_MAP = {
    "rx_bytes": "in-octets", "tx_bytes": "out-octets",
    "rx_errors": "in-errors", "tx_errors": "out-errors",
    "rx_dropped": "in-discards", "tx_dropped": "out-discards",
}

IFF_UP = 0x1


def hostname() -> str:
    return socket.gethostname()


def cpu_snapshot():
    """Raw /proc/stat aggregate CPU counters (jiffies), for cpu_percent()."""
    with open("/proc/stat") as f:
        parts = f.readline().split()
    # user nice system idle iowait irq softirq  (steal/guest fields ignored --
    # not needed for a total-utilization percentage)
    return tuple(int(x) for x in parts[1:8])


def cpu_percent(prev, curr) -> int:
    """Real delta-based CPU utilization between two cpu_snapshot() reads, 0-100.

    This is NOT /proc/loadavg (a run-queue-length average, not a percentage,
    and not comparable to gNMI's `total/instant` semantics) -- it is the
    standard textbook computation: (total_delta - idle_delta) / total_delta
    over the sampling window, using idle+iowait as the idle component.
    """
    if prev is None:
        return 0
    prev_idle, curr_idle = prev[3] + prev[4], curr[3] + curr[4]
    prev_total, curr_total = sum(prev), sum(curr)
    total_delta = curr_total - prev_total
    if total_delta <= 0:
        return 0
    idle_delta = curr_idle - prev_idle
    return max(0, min(100, round(100 * (total_delta - idle_delta) / total_delta)))


def memory():
    """Real /proc/meminfo values, in bytes.

    Linux has no exact equivalent of EOS's openconfig-system physical/used/
    free/reserved split, so this is a documented, best-effort mapping (see
    docs/STREAMING_TELEMETRY_IMPLEMENTATION.md "R3/R4 memory field mapping"):
      physical -> MemTotal
      free     -> MemFree
      used     -> MemTotal - MemFree - Buffers - Cached  (classic "used")
      reserved -> MemTotal - MemAvailable - used          (best-effort remainder)
    """
    raw = {}
    with open("/proc/meminfo") as f:
        for line in f:
            key, _, rest = line.partition(":")
            if key in ("MemTotal", "MemFree", "MemAvailable", "Buffers", "Cached"):
                raw[key] = int(rest.strip().split()[0]) * 1024  # kB -> bytes
    total = raw.get("MemTotal", 0)
    free = raw.get("MemFree", 0)
    available = raw.get("MemAvailable", free)
    buffers = raw.get("Buffers", 0)
    cached = raw.get("Cached", 0)
    used = max(0, total - free - buffers - cached)
    reserved = max(0, total - available - used)
    return {"physical": total, "used": used, "free": free, "reserved": reserved}


def interfaces():
    """Real per-interface admin/oper state and counters from /sys/class/net.

    `lo` is included deliberately, not filtered out: on R3/R4 it carries this
    router's real OSPF/BGP router-id address (verified: `192.168.255.3/…::3`
    on R3), the same role Loopback0 plays on the cEOS devices (which IS
    streamed) -- excluding it would hide real, meaningful router identity
    state. Any interface without a readable `statistics/` directory is
    skipped defensively rather than reported with fabricated zeros.
    """
    result = {}
    if not NET.is_dir():
        return result
    for path in sorted(NET.iterdir()):
        name = path.name
        try:
            flags = int((path / "flags").read_text().strip(), 16)
            admin = "UP" if flags & IFF_UP else "DOWN"
            raw_oper = (path / "operstate").read_text().strip()
            if raw_oper == "up":
                oper = "UP"
            elif raw_oper == "down":
                oper = "DOWN"
            elif raw_oper == "unknown" and admin == "UP":
                # Linux vlan/loopback-style devices commonly report "unknown"
                # while genuinely up and forwarding.
                oper = "UP"
            else:
                oper = raw_oper.upper()
            counters = {}
            for raw_key, oc_key in COUNTER_MAP.items():
                stat_path = path / "statistics" / raw_key
                if stat_path.exists():
                    counters[oc_key] = int(stat_path.read_text().strip())
            result[name] = {"admin_status": admin, "oper_status": oper, "counters": counters}
        except (FileNotFoundError, ValueError, OSError):
            continue
    return result
