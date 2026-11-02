#!/usr/bin/env python3
"""Phase 3A: shadow rendering + legacy-vs-NetBox equivalence check.

Renders candidate device configuration from NetBox-sourced addressing and
compares it against the current templates' own addressing intent -- WITHOUT
ever touching a device, templates/*.cfg.j2, or master.py. See
modules/ipam_context.py for the underlying logic and docs/NETBOX_IPAM.md
"Phase 3A -- Shadow Provisioning" for the full design rationale.

Usage:
    python3 netbox/scripts/shadow_render.py --device R1
    python3 netbox/scripts/shadow_render.py --all
    python3 netbox/scripts/shadow_render.py --all --write-candidates

Exit code 0 = every requested device is EQUIVALENT. Exit code 1 = NetBox
was not ready (fail-closed, per Step 12/13) or a device could not be
processed. Exit code 2 = NetBox was ready but at least one device is NOT
equivalent -- differences are printed, never silently accepted.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

BASE = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(BASE))

from modules import ipam_context as ic  # noqa: E402
from modules import netbox_ipam as nb  # noqa: E402


def run_device(device: str, *, write_candidates: bool) -> ic.ComparisonResult:
    legacy = ic.extract_legacy_facts(device)
    netbox_facts = ic.build_netbox_facts(device)
    result = ic.compare_facts(device, legacy, netbox_facts)
    if write_candidates:
        path = ic.write_candidate_config(device)
        print(f"  candidate written: {path}")
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    target = parser.add_mutually_exclusive_group(required=True)
    target.add_argument("--device", metavar="NAME", help="Render/compare a single managed device")
    target.add_argument("--all", action="store_true", help="Render/compare every managed device")
    parser.add_argument("--write-candidates", action="store_true", help=f"Also write candidate config text under {ic.SHADOW_RUNTIME_DIR}")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show every difference's detail")
    args = parser.parse_args(argv)

    print("Validating NetBox is ready for shadow rendering...")
    try:
        readiness = ic.validate_netbox_ready()
    except nb.NetboxError as exc:
        print(f"FAIL: NetBox is not ready for shadow rendering: {exc}", file=sys.stderr)
        return 1
    print(f"  managed devices: {readiness['managed_devices']}")
    print()

    devices = [args.device] if args.device else list(ic.MANAGED_DEVICES)
    invalid = [d for d in devices if d not in ic.MANAGED_DEVICES]
    if invalid:
        print(f"ERROR: not a managed device: {invalid}", file=sys.stderr)
        return 1

    results: dict[str, ic.ComparisonResult] = {}
    had_error = False
    for device in devices:
        try:
            results[device] = run_device(device, write_candidates=args.write_candidates)
        except nb.NetboxError as exc:
            print(f"{device:<10} ERROR: {exc}", file=sys.stderr)
            had_error = True

    print()
    for device, result in results.items():
        status = "PASS" if result.equivalent else "FAIL"
        print(f"{device:<10} {status}")
        if args.verbose or not result.equivalent:
            for diff in result.differences:
                print(f"    {diff.category}: legacy={diff.legacy!r} netbox={diff.netbox!r} [{diff.classification}]")

    overall = "PASS" if results and all(r.equivalent for r in results.values()) and not had_error else "FAIL"
    print(f"\nOverall: {overall}")

    if had_error:
        return 1
    return 0 if overall == "PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
