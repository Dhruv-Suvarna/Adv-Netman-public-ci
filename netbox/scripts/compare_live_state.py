#!/usr/bin/env python3
"""Phase 2 live-state cross-check (Step 18): does the RUNNING network
currently resemble what NetBox models?

This is intentionally a SEPARATE question from
netbox/scripts/verify_netbox_model.py (which only asks "does NetBox match
what the IaC intends?"). This script never changes NetBox or any device --
it only reports differences between NetBox's modeled static infrastructure
addresses and a fresh `address_report.py` observation. Any drift found here
is reported, never silently used to "correct" NetBox or the live network.

Usage:
    python3 address_report.py                        # refresh the CSV first
    python3 netbox/scripts/compare_live_state.py [-v]

Rows excluded from the live side before comparing (these are never part of
NetBox's modeled static infrastructure addressing -- see
docs/NETBOX_IPAM.md "Containerlab management addresses" and "H1-H4"):
  * link-local (fe80::/10) and loopback (127.0.0.0/8, ::1/128) addresses
  * the Containerlab-runtime management network (172.20.20.0/24,
    3fff:172:20:20::/64), regardless of which device reports it
  * H1-H4's own DHCP-leased addresses (excluded by DEVICE, not by subnet --
    S1/S2 have their own legitimate STATIC addresses on those very same
    VLAN10/20/30 subnets, which must stay in the comparison)
"""
from __future__ import annotations

import argparse
import csv
import ipaddress
import sys
from pathlib import Path

BASE = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(BASE))

from modules import netbox_ipam as nb  # noqa: E402

CSV_PATH = BASE / "address_report.csv"

EXCLUDED_LIVE_NETWORKS = [
    ipaddress.ip_network("172.20.20.0/24"),
    ipaddress.ip_network("3fff:172:20:20::/64"),
]
DHCP_CLIENT_DEVICES = {"H1", "H2", "H3", "H4"}


def load_live_addresses(csv_path: Path) -> dict[str, tuple[str, str]]:
    """Return {address_with_prefixlen: (device, interface)} for every live
    address worth comparing (see module docstring for exclusions)."""
    if not csv_path.is_file():
        raise SystemExit(f"ERROR: {csv_path} does not exist. Run address_report.py first.")
    result: dict[str, tuple[str, str]] = {}
    with csv_path.open() as handle:
        for row in csv.DictReader(handle):
            if row["device"] in DHCP_CLIENT_DEVICES:
                continue
            try:
                iface = ipaddress.ip_interface(row["address"])
            except ValueError:
                continue
            if iface.ip.is_link_local or iface.ip.is_loopback:
                continue
            if any(iface.ip in network for network in EXCLUDED_LIVE_NETWORKS):
                continue
            result[str(iface)] = (row["device"], row["interface"])
    return result


def load_netbox_addresses(client) -> set[str]:
    """Every NetBox-modeled static infra address that is actually assigned
    to an interface (the 5 unassigned shared VRRP addresses are excluded --
    they are not any single interface's live address)."""
    addresses = set()
    for ip in client.ipam.ip_addresses.filter(tag="csci5840-iac"):
        if ip.assigned_object is not None:
            addresses.add(str(ipaddress.ip_interface(ip.address)))
    return addresses


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("-v", "--verbose", action="store_true", help="List every matching address too, not just differences")
    args = parser.parse_args(argv)

    try:
        client = nb.build_client()
        nb.check_status(nb.load_config())
    except nb.NetboxError as exc:
        print(f"ERROR: NetBox is not reachable/usable: {exc}", file=sys.stderr)
        return 1

    live = load_live_addresses(CSV_PATH)
    modeled = load_netbox_addresses(client)

    matching = sorted(set(live) & modeled)
    only_in_netbox = sorted(modeled - set(live))
    only_in_live = sorted(live)  # filled in below, minus matching
    only_in_live = sorted(a for a in live if a not in modeled)

    print(f"NetBox-modeled static infra addresses (assigned): {len(modeled)}")
    print(f"Live addresses observed (after exclusions):        {len(live)}")
    print(f"Matching:                                          {len(matching)}")
    if args.verbose:
        for addr in matching:
            print(f"  MATCH  {addr}")

    print(f"\nIn NetBox but NOT observed live ({len(only_in_netbox)}):")
    for addr in only_in_netbox:
        print(f"  MISSING-LIVE  {addr}")

    print(f"\nObserved live but NOT modeled in NetBox, and not an excluded "
          f"category ({len(only_in_live)}):")
    for addr in only_in_live:
        device, iface = live[addr]
        print(f"  DRIFT  {addr}  ({device}/{iface})")

    print(
        "\nThis is drift reporting only -- nothing above was changed in NetBox "
        "or on any device. See docs/NETBOX_IPAM.md for how to interpret it."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
