#!/usr/bin/env python3
"""Phase 3B.1 (Phase 3B.3 corrected the underlying model): read-only
reservation/identity-readiness validation.

Prints the full DEVICE/INTERFACE/MAC/IPv4/IPv6/mode/identity assignment
matrix (Step 17) and an overall READY/BLOCKED/FAIL, without changing NetBox,
generating DHCP server configuration, or touching a device.

Since Phase 3B.3 established Vlan200 as the static management VLAN (see
docs/NETBOX_IPAM.md "Phase 3B.3"), no managed interface currently reports a
dhcp-reserved/dhcpv6-reserved assignment mode -- this script's readiness
list (and therefore its READY/BLOCKED counts) is correctly `0` targets,
not a defect and not something to fabricate a target to fill. It remains
fully general: any interface a future, deliberate policy change marks
dynamic will appear here without any change to this script.

Usage:
    python3 netbox/scripts/verify_reservations.py [-v]

Exit code 0 = READY. Exit code 1 = NetBox unusable. Exit code 2 = a
platform capability is explicitly BLOCKED. Exit code 3 = invalid,
ambiguous, or missing model data (FAIL).
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

BASE = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(BASE))

from modules import ipam_context as ic  # noqa: E402
from modules import netbox_ipam as nb  # noqa: E402


def _fmt(value) -> str:
    return value if value else "-"


def print_matrix(rows: list[dict], report: ic.ReservationReport) -> None:
    readiness = {(item.device, item.interface, item.family): item.status for item in report.readiness}
    header = (
        f"{'DEVICE':<10} {'PLATFORM':<7} {'INTERFACE':<10} {'MAC':<18} {'MAC STATUS':<21} "
        f"{'IPv4':<16} {'IPv4 MODE':<14} {'IPv6':<22} {'IPv6 MODE':<17} "
        f"{'DUID':<30} {'DUID STATUS':<21} {'IAID':<12} READINESS"
    )
    print(header)
    for row in rows:
        states = []
        for family, mode in ((4, row["ipv4_mode"]), (6, row["ipv6_mode"])):
            if mode in ("dhcp-reserved", "dhcpv6-reserved"):
                states.append(f"IPv{family}:{readiness.get((row['device'], row['interface'], family), ic.READINESS_FAIL)}")
        row_readiness = ",".join(states) if states else "STATIC/NONE"
        print(
            f"{row['device']:<10} {_fmt(row.get('platform')):<7} {row['interface']:<10} {_fmt(row['mac_address']):<18} "
            f"{_fmt(row.get('mac_identity_status')):<21} {_fmt(row['ipv4']):<16} {row['ipv4_mode']:<14} "
            f"{_fmt(row['ipv6']):<22} {row['ipv6_mode']:<17} {_fmt(row['dhcpv6_duid']):<30} "
            f"{_fmt(row.get('dhcpv6_identity_status')):<21} {_fmt(row['dhcpv6_iaid']):<12} {row_readiness}"
        )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("-v", "--verbose", action="store_true", help="Show every issue's full detail, including affected rows")
    args = parser.parse_args(argv)

    try:
        readiness = ic.validate_netbox_ready()
    except nb.NetboxError as exc:
        print(f"FAIL: NetBox is not ready: {exc}", file=sys.stderr)
        return 1
    print(f"Managed devices: {readiness['managed_devices']}\n")

    try:
        client = nb.build_client()
        rows = ic.get_address_reservations(client)
        dhcp_ranges = nb.get_dhcp_ranges(client=client)
    except nb.NetboxError as exc:
        print(f"FAIL: could not read reservation data from NetBox: {exc}", file=sys.stderr)
        return 1

    report = ic.validate_reservations(rows, dhcp_ranges=dhcp_ranges)
    print_matrix(rows, report)
    print()

    for issue in report.issues:
        print(f"{issue.status:<7} [{issue.category}] {issue.detail}")
        if args.verbose:
            for row in issue.rows:
                print(f"        {row}")

    counts = report.readiness_counts
    issue_failures = sum(issue.status == ic.READINESS_FAIL for issue in report.issues)
    issue_blockers = sum(issue.status == ic.READINESS_BLOCKED for issue in report.issues)
    print(f"\nRows checked: {len(rows)}. Reservation targets checked: {len(report.readiness)}.")
    print(
        f"Reservation readiness: READY={counts[ic.READINESS_READY]} "
        f"BLOCKED={counts[ic.READINESS_BLOCKED]} FAIL={counts[ic.READINESS_FAIL]}"
    )
    print(f"Validation issues: BLOCKED={issue_blockers} FAIL={issue_failures}")
    print("Overall:", report.overall_status)
    if report.overall_status == ic.READINESS_READY:
        return 0
    if report.overall_status == ic.READINESS_BLOCKED:
        return 2
    return 3


if __name__ == "__main__":
    raise SystemExit(main())
