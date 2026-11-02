#!/usr/bin/env python3
"""Phase 3B.1 (refactored in Phase 3B.3): record the DELIBERATE,
mechanism-verified durable-identity DECISION for whichever managed
interfaces NetBox's OWN assignment-mode policy currently marks dynamic --
distinct from `sync_interface_macs.py`'s passive observation (Step 12).

Phase 3B.3 superseded the original assumption this script was built
around: it used to hard-code `Vlan200` as THE dynamic-assignment target on
every managed device. The user's architecture decision established that
Vlan200 is the management VLAN and stays STATIC, so as of
`netbox/scripts/populate_netbox.py`'s corrected `_assignment_mode()`
policy, no managed interface is currently classified dhcp-reserved/
dhcpv6-reserved -- this script now discovers its targets FROM that policy
(`modules.netbox_ipam.get_assignment_modes()`), never from a hard-coded
interface name, and correctly does nothing when there is nothing to pin
(see docs/NETBOX_IPAM.md "Phase 3B.3"). It remains ready to pin a
genuinely future dynamic-assignment target without any code change here.

This script writes ONLY to NetBox. It never touches a live device, never
computes a new MAC value from scratch (it promotes the value
`sync_interface_macs.py` already observed, once a genuine platform
mechanism to pin it has been verified -- see docs/NETBOX_IPAM.md "Phase
3B.1"), and never fabricates a DHCPv6 DUID: a Linux/FRR target's DUID-LL is
mathematically computed from its now-authoritative MAC (RFC 8415 type 3
= 0x0003, hardware type 1 = Ethernet, + the 6-byte MAC -- no randomness,
no timestamp), and a cEOS target would be marked `blocked` because no
viable DHCPv6-client identity mechanism was found on that platform build
(verified via safe, read-only CLI probing -- see the doc).

Prerequisite: `sync_interface_macs.py --apply` must have already recorded
the target interface's MAC (this script refuses to invent one).

Usage:
    python3 netbox/scripts/pin_stable_identities.py --check
    python3 netbox/scripts/pin_stable_identities.py --apply
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

BASE = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(BASE))

from modules import netbox_ipam as nb  # noqa: E402

# Full rationale/evidence for each of these (verified via safe, read-only
# CLI syntax-checking -- never a completed live change) is in
# docs/NETBOX_IPAM.md "Phase 3B.1"; kept short here to fit NetBox's
# 200-character description field.
CEOS_MAC_MECHANISM = (
    "Pin via EOS 'interface Vlan200/mac-address <value>' (verified: bare "
    "token -> Incomplete command, not Invalid). Preserves observed System "
    "MAC. Not yet applied -- see docs/NETBOX_IPAM.md."
)
LINUX_MAC_MECHANISM = (
    "Pin via 'ip link set dev Vlan200 address <value>' (per local 'ip "
    "link help'), overriding bridge inherit-from-eth3. Preserves observed "
    "MAC. Not yet applied -- see docs/NETBOX_IPAM.md."
)
CEOS_DHCPV6_BLOCKED_REASON = (
    "No DHCPv6-client identity (DUID/IAID) config surface found (verified "
    "read-only: 'ipv6 address dhcp'/'dhcp client duid/...' rejected as "
    "Invalid). Platform limitation, not worked around."
)


def _is_ceos(device: str, client) -> bool:
    return (nb.get_device(device, client)["device_type"] or "").startswith("ceos")


def duid_ll(mac_address: str) -> str:
    """RFC 8415 DUID-LL (type 3): 0003 + hardware-type Ethernet (0001) +
    the 6-byte MAC. Purely a deterministic transformation of an
    already-authoritative MAC -- no randomness, no timestamp, nothing
    invented."""
    normalized = mac_address.lower().replace("-", ":")
    octets = normalized.split(":")
    if len(octets) != 6 or any(not re.fullmatch(r"[0-9a-f]{2}", octet) for octet in octets):
        raise ValueError(f"not a 6-octet MAC: {mac_address!r}")
    if int(octets[0], 16) & 1 or all(octet == "00" for octet in octets):
        raise ValueError(f"not a usable unicast MAC: {mac_address!r}")
    return "00:03:00:01:" + ":".join(octets)


def predicted_iaid(mac_address: str) -> str:
    """The last 4 octets of the MAC -- matching the derivation empirically
    observed in H1's own isc-dhclient lease evidence (Phase 3B). Labelled
    PREDICTED, not verified, because no DHCPv6 client has run on R3/R4
    itself; see docs/NETBOX_IPAM.md for why this is non-blocking regardless
    (ISC dhcpd's fixed-address6 matching does not use IAID)."""
    # Reuse duid_ll's complete validation; the final six octets are the
    # normalized MAC and the final four are the observed dhclient-style
    # informational IAID prediction.
    octets = duid_ll(mac_address).split(":")[-6:]
    return ":".join(octets[-4:])


def planned_dhcpv6_identity(*, is_ceos: bool, mac_address: str) -> dict:
    """Return the explicit platform decision without touching NetBox."""
    if is_ceos:
        return {"status": nb.IDENTITY_BLOCKED, "duid": None, "iaid": None}
    return {
        "status": nb.IDENTITY_AUTHORITATIVE,
        "duid": duid_ll(mac_address),
        "iaid": predicted_iaid(mac_address),
    }


def discover_dynamic_targets(client) -> list[tuple[str, str, set[int]]]:
    """Every (device, interface) currently marked dynamic by NetBox's OWN
    assignment-mode policy (`ipv4_assignment_mode=dhcp-reserved` and/or
    `ipv6_assignment_mode=dhcpv6-reserved`), with the set of families that
    apply -- NEVER a hard-coded interface name (Phase 3B.3's fix for the
    root cause of the original Vlan200 assumption). Returns [] when no
    managed interface currently requests a dynamic identity, which is the
    correct, expected result of the current static-management-VLAN
    architecture (see docs/NETBOX_IPAM.md "Phase 3B.3")."""
    by_iface: dict[tuple[str, str], set[int]] = {}
    for device in nb.get_managed_devices(client):
        for interface in nb.get_device_interface_names(device, client):
            modes = nb.get_assignment_modes(device, interface, client)
            families = set()
            if modes["ipv4_mode"] == "dhcp-reserved":
                families.add(4)
            if modes["ipv6_mode"] == "dhcpv6-reserved":
                families.add(6)
            if families:
                by_iface[(device, interface)] = families
    return [(device, interface, families) for (device, interface), families in sorted(by_iface.items())]


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

    targets = discover_dynamic_targets(client)
    if not targets:
        print(
            "No managed interface is currently classified dhcp-reserved/dhcpv6-reserved.\n"
            "Nothing to pin -- this is the expected result of the corrected static-management-VLAN\n"
            "architecture (Vlan200 stays static; see docs/NETBOX_IPAM.md 'Phase 3B.3'). This script\n"
            "remains ready to pin a genuinely future dynamic-assignment target without modification.",
        )
        return 0

    print(f"{'DEVICE':<10} {'INTERFACE':<10} {'MAC ACTION':<20} {'DHCPv6 ACTION':<20}")
    had_error = False
    for device, interface, families in targets:
        try:
            is_ceos = _is_ceos(device, client)
            mac_result = None
            if 4 in families:
                mac_mechanism = CEOS_MAC_MECHANISM if is_ceos else LINUX_MAC_MECHANISM
                mac_result = nb.mark_mac_authoritative(device, interface, description=mac_mechanism, client=client, apply=args.apply)

            dhcpv6_result = None
            if 6 in families:
                observed = nb.get_interface_mac(device, interface, client)
                if observed is None:
                    raise nb.NetboxModelError(f"{device}/{interface}: dhcpv6-reserved but no MAC recorded -- run sync_interface_macs.py first")
                identity = planned_dhcpv6_identity(is_ceos=is_ceos, mac_address=observed["mac_address"])
                if identity["status"] == nb.IDENTITY_BLOCKED:
                    dhcpv6_result = nb.set_dhcpv6_identity(
                        device, interface, status=nb.IDENTITY_BLOCKED,
                        description=CEOS_DHCPV6_BLOCKED_REASON, client=client, apply=args.apply,
                    )
                else:
                    dhcpv6_result = nb.set_dhcpv6_identity(
                        device, interface, status=nb.IDENTITY_AUTHORITATIVE,
                        duid=identity["duid"], iaid=identity["iaid"],
                        description="Computed DUID-LL from the authoritative MAC; IAID predicted, non-blocking. See docs/NETBOX_IPAM.md.",
                        client=client, apply=args.apply,
                    )
        except (nb.NetboxError, ValueError) as exc:
            print(f"{device:<10} {interface:<10} ERROR: {exc}", file=sys.stderr)
            had_error = True
            continue

        mac_label = mac_result.action if mac_result is not None else "-"
        dhcpv6_label = dhcpv6_result.action if dhcpv6_result is not None else "-"
        print(f"{device:<10} {interface:<10} {mac_label:<20} {dhcpv6_label:<20}")

    print(
        "\nNote: this records the PLANNED, mechanism-verified identity decision "
        "in NetBox only -- no live device was touched, no DHCP client was "
        "enabled. See docs/NETBOX_IPAM.md 'Phase 3B.1' for the exact proposed "
        "cutover commands this decision implies (not yet applied).",
    )
    return 1 if had_error else 0


if __name__ == "__main__":
    raise SystemExit(main())
