#!/usr/bin/env python3
"""Phase 3G (Step 28): minimal, read-only observability for the dual DHCP
server architecture -- reports live daemon state for both servers without
introducing a new monitoring subsystem. Never modifies anything.

Usage:
    python3 netbox/scripts/verify_dhcp_servers.py

Exit code 0 if both servers report at least one active family; 1 if
either server cannot be inspected or reports both families inactive.
"""
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

BASE = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(BASE))

import yaml  # noqa: E402

INVENTORY_PATH = BASE / "inventory.yml"
LAB_NAME_DEFAULT = "srlceos01"


def _run(cmd: list[str], timeout: int = 15) -> str:
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    return result.stdout + result.stderr


def nmas_status() -> dict:
    v4 = _run(["systemctl", "is-active", "isc-dhcp-server"]).strip()
    v6 = _run(["systemctl", "is-active", "isc-dhcp-server6"]).strip()
    return {"server": "NMAS", "ipv4": v4, "ipv6": v6}


def r2_status() -> dict:
    inventory = yaml.safe_load(INVENTORY_PATH.read_text())
    lab = inventory.get("lab_name", LAB_NAME_DEFAULT)
    container = f"clab-{lab}-R2"
    output = _run(["docker", "exec", container, "Cli", "-p", "15", "-c", "show dhcp server"], timeout=30)
    v4_match = re.search(r"IPv4 DHCP server is (\w+)", output)
    v6_match = re.search(r"IPv6 DHCP server is (\w+)", output)
    lease_matches = re.findall(r"Active leases: (\d+)", output)
    return {
        "server": "R2",
        "ipv4": v4_match.group(1) if v4_match else "unknown",
        "ipv6": v6_match.group(1) if v6_match else "unknown",
        # First "Active leases" line is the server-wide IPv4 total, the
        # rest are per-subnet -- summing per-subnet counts for each
        # family would double count against the server-wide totals, so
        # this reports the raw count of non-zero subnet lines found
        # instead of a fabricated single number.
        "lease_lines": lease_matches,
    }


def main() -> int:
    try:
        nmas = nmas_status()
    except Exception as exc:  # pragma: no cover - defensive; systemctl is always present here
        print(f"FAIL: could not inspect NMAS: {exc}", file=sys.stderr)
        return 1
    try:
        r2 = r2_status()
    except Exception as exc:
        print(f"FAIL: could not inspect R2: {exc}", file=sys.stderr)
        return 1

    print(f"{'SERVER':<8}{'IPv4':<10}{'IPv6':<10}")
    print(f"{nmas['server']:<8}{nmas['ipv4']:<10}{nmas['ipv6']:<10}")
    print(f"{r2['server']:<8}{r2['ipv4']:<10}{r2['ipv6']:<10}")
    print(f"\nR2 lease-count entries observed: {r2['lease_lines']}")

    nmas_ok = "active" in (nmas["ipv4"], nmas["ipv6"])
    r2_ok = "active" in (r2["ipv4"], r2["ipv6"])
    if not nmas_ok or not r2_ok:
        print("\nFAIL: at least one server reports both families inactive", file=sys.stderr)
        return 1
    print("\nOverall: PASS (both servers reachable and reporting at least one active family)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
