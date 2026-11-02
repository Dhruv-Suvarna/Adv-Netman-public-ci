#!/usr/bin/env python3
"""Phase 3G: render-only NMAS primary-DHCP-server candidate configuration.

Reads NetBox -> normalizes a rendering context
(modules.ipam_context.build_and_validate_nmas_dhcp_context(), the same
fail-closed gate the real `master.py`/`setup_nmas()` path now calls) ->
renders both dhcp/dhcpd.conf.j2 and dhcp/dhcpd6.conf.j2 -> validates ISC
syntax with the real `dhcpd -t`/`dhcpd -6 -t` binary against the candidate
files -> prints/writes the candidates. This script NEVER installs a file
under /etc/dhcp, NEVER restarts a service, and NEVER touches NMAS's actual
running configuration.

Usage:
    python3 netbox/scripts/render_nmas_dhcp.py [-v] [--write]

Exit codes:
    0  both candidates rendered, validated safe, and passed ISC syntax check
    1  NetBox/context-build pre-render gate failed (unreachable, missing/
       unexpected pool, or pool-safety problem)
    3  a rendered candidate failed `dhcpd -t`/`dhcpd -6 -t` syntax validation
"""
from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

BASE = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(BASE))

from modules import ipam_context as ic  # noqa: E402
from modules import netbox_ipam as nb  # noqa: E402
from modules.eos_render import render  # noqa: E402

OUT_DIR = BASE / "netbox" / "runtime" / "nmas_dhcp"

# isc-dhcp-server's AppArmor profile (/etc/apparmor.d/usr.sbin.dhcpd)
# confines `dhcpd` to reading only /etc/dhcp/** (plus a short, unrelated
# allow-list) -- it refuses even a `-t` syntax-only read of a file under
# /tmp with "Permission denied", regardless of Unix file permissions. A
# genuine `dhcpd -t` validation therefore needs a scoped, clearly-named
# candidate file INSIDE /etc/dhcp/ -- never the real dhcpd.conf/dhcpd6.conf
# -- created and removed within this same run via sudo. This never installs
# the candidate as the active configuration and never touches/restarts the
# service.
_CANDIDATE_V4 = Path("/etc/dhcp/dhcpd.conf.render-candidate")
_CANDIDATE_V6 = Path("/etc/dhcp/dhcpd6.conf.render-candidate")


def _syntax_check_via_etc_dhcp(candidate_path: Path, text: str, dhcpd_args: list[str]) -> tuple[bool, str]:
    """Write `text` to `candidate_path` (under /etc/dhcp/, via sudo),
    run `dhcpd <dhcpd_args> -cf candidate_path`, then remove the file --
    always, even on failure. Never touches the real dhcpd.conf/dhcpd6.conf."""
    try:
        write = subprocess.run(
            ["sudo", "tee", str(candidate_path)], input=text, capture_output=True, text=True, timeout=15,
        )
        if write.returncode != 0:
            return False, f"could not write candidate to {candidate_path}: {write.stderr}"
        result = subprocess.run(
            ["sudo", "dhcpd", *dhcpd_args, "-cf", str(candidate_path)], capture_output=True, text=True, timeout=30,
        )
        return result.returncode == 0, result.stdout + result.stderr
    finally:
        subprocess.run(["sudo", "rm", "-f", str(candidate_path)], capture_output=True, text=True, timeout=15)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("-v", "--verbose", action="store_true")
    parser.add_argument("--write", action="store_true", help=f"Also write the candidates under {OUT_DIR}")
    args = parser.parse_args(argv)

    try:
        ic.validate_netbox_ready()
        client = nb.build_client()
        dhcp_context = ic.build_and_validate_nmas_dhcp_context(client)
    except nb.NetboxError as exc:
        print(f"FAIL: NetBox/DHCP-context pre-render gate failed: {exc}", file=sys.stderr)
        return 1
    print(f"Pool safety + context build: PASS ({len(dhcp_context['ipv4_subnets'])} IPv4 + {len(dhcp_context['ipv6_subnets'])} IPv6 primary subnets)")

    if args.verbose:
        print("\nPrimary (NMAS) pools:")
        for subnet in dhcp_context["ipv4_subnets"]:
            print(f"  VLAN{subnet['vlan']} IPv4: {subnet['network']}/{subnet['netmask']} range {subnet['start']}-{subnet['end']} gateway={subnet['gateway']}")
        for subnet in dhcp_context["ipv6_subnets"]:
            print(f"  VLAN{subnet['vlan']} IPv6: {subnet['prefix']} range {subnet['start']}-{subnet['end']}")

    candidate_v4 = render("dhcp/dhcpd.conf.j2", {"management": {}, "dhcp": dhcp_context}, base=BASE)
    candidate_v6 = render("dhcp/dhcpd6.conf.j2", {"management": {}, "dhcp": dhcp_context}, base=BASE)

    ok4, out4 = _syntax_check_via_etc_dhcp(_CANDIDATE_V4, candidate_v4, ["-t"])
    ok6, out6 = _syntax_check_via_etc_dhcp(_CANDIDATE_V6, candidate_v6, ["-6", "-t"])

    if not ok4:
        print("FAIL: dhcpd -t rejected the IPv4 candidate:", file=sys.stderr)
        print(out4, file=sys.stderr)
        return 3
    print("ISC DHCPv4 syntax validation (dhcpd -t): PASS")

    if not ok6:
        print("FAIL: dhcpd -6 -t rejected the IPv6 candidate:", file=sys.stderr)
        print(out6, file=sys.stderr)
        return 3
    print("ISC DHCPv6 syntax validation (dhcpd -6 -t): PASS")

    print("\n--- candidate dhcp/dhcpd.conf.j2 render ---\n")
    print(candidate_v4)
    print("--- candidate dhcp/dhcpd6.conf.j2 render ---\n")
    print(candidate_v6)

    if args.write:
        OUT_DIR.mkdir(parents=True, exist_ok=True)
        (OUT_DIR / "dhcpd.conf").write_text(candidate_v4)
        (OUT_DIR / "dhcpd6.conf").write_text(candidate_v6)
        print(f"\nWritten to {OUT_DIR}/ (never installed under /etc/dhcp, never applied).")

    print("\nOverall: PASS -- candidate only. Nothing was installed or restarted.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
