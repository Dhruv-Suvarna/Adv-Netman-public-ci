#!/usr/bin/env python3
"""Phase 3B: observe each managed device's live management-interface MAC
address (read-only) and reconcile it into NetBox as a dcim.MACAddress.

This is deliberately an OBSERVATIONAL sync, not a permanent migration
manifest entry (Step 9 explicitly forbids a parallel YAML file of
MAC/address mappings): it reads the CURRENTLY live value straight from the
running Containerlab containers every time it runs, the same way
address_report.py observes live addressing, and reconciles it into NetBox
idempotently -- if a future redeploy changes the MAC, the next run reports
an UPDATE, never silently masks the drift.

**Read-only against the lab.** This script only runs `ip -o link show` /
`cat /sys/class/net/.../address` inside each container via `docker exec`
-- it never modifies `/home/student/clab-quickstart`, never pushes
configuration, and never restarts anything.

See docs/NETBOX_IPAM.md "Phase 3B" for why the observed MAC addresses are
flagged unstable (Containerlab does not pin any interface MAC in
srlceos01.clab.yml, and the data-plane veth MACs are Linux-kernel-random,
regenerated on every redeploy).

Usage:
    python3 netbox/scripts/sync_interface_macs.py --check
    python3 netbox/scripts/sync_interface_macs.py --apply
"""
from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

BASE = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(BASE))

from modules import netbox_ipam as nb  # noqa: E402

LAB_NAME = "srlceos01"
MANAGEMENT_INTERFACE = "Vlan200"


def _container_name(device: str) -> str:
    return f"clab-{LAB_NAME}-{device}"


def _os_interface_name(device: str, client=None) -> str:
    """The actual Linux-visible interface name for the management SVI --
    cEOS exposes its SVIs to the Linux `ip link` view in lowercase
    ("vlan200"), while the Ubuntu/FRR devices' own bash-provisioned bridge
    keeps the exact-cased name ("Vlan200"). This is a read-time naming
    convention (the same kind already documented for Ethernet-vs-eth
    naming in docs/), not a hard-coded address mapping."""
    device_info = nb.get_device(device, client)
    is_ceos = (device_info["device_type"] or "").startswith("ceos")
    return MANAGEMENT_INTERFACE.lower() if is_ceos else MANAGEMENT_INTERFACE


def discover_mac(device: str, client=None) -> str:
    """Read-only: the live MAC address of `device`'s management interface,
    straight from the running container. Raises RuntimeError with the
    docker/ip output on any failure -- never returns a fabricated value."""
    os_iface = _os_interface_name(device, client)
    container = _container_name(device)
    result = subprocess.run(
        ["docker", "exec", container, "cat", f"/sys/class/net/{os_iface}/address"],
        capture_output=True, text=True, timeout=15,
    )
    if result.returncode != 0:
        raise RuntimeError(f"{device}: could not read MAC for {os_iface} in {container}: {result.stderr.strip()}")
    mac = result.stdout.strip()
    if not mac or mac.count(":") != 5:
        raise RuntimeError(f"{device}: unexpected MAC output for {os_iface}: {mac!r}")
    return mac


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true")
    mode.add_argument("--apply", action="store_true")
    args = parser.parse_args(argv)

    try:
        client = nb.build_client()
        nb.check_status(nb.load_config())
    except nb.NetboxError as exc:
        print(f"ERROR: NetBox is not reachable/usable: {exc}", file=sys.stderr)
        return 1

    managed = nb.get_managed_devices(client)
    print(f"{'DEVICE':<10} {'INTERFACE':<10} {'OBSERVED MAC':<20} ACTION")
    had_error = False
    for device in managed:
        try:
            mac = discover_mac(device, client)
        except RuntimeError as exc:
            print(f"{device:<10} {MANAGEMENT_INTERFACE:<10} {'-':<20} ERROR: {exc}", file=sys.stderr)
            had_error = True
            continue
        try:
            result = nb.ensure_interface_mac(device, MANAGEMENT_INTERFACE, mac, client, apply=args.apply)
        except nb.NetboxError as exc:
            print(f"{device:<10} {MANAGEMENT_INTERFACE:<10} {mac:<20} ERROR: {exc}", file=sys.stderr)
            had_error = True
            continue
        print(f"{device:<10} {MANAGEMENT_INTERFACE:<10} {mac:<20} {result.action}")

    print(
        "\nNote: these MAC addresses are LIVE-OBSERVED, not pinned in "
        "srlceos01.clab.yml -- see docs/NETBOX_IPAM.md 'MAC address "
        "stability findings' before treating any of them as a durable "
        "DHCPv4 client identity.",
    )
    return 1 if had_error else 0


if __name__ == "__main__":
    raise SystemExit(main())
