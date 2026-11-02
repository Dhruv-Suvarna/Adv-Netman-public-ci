"""Deterministic Objective-1 IPAM coverage evidence (read-only).

NetBox is the ONLY IPAM / source of truth.  This module never writes to
NetBox and keeps no address store of its own: it compares the existing
desired-state manifest (``netbox/ipam.yml``, the input NetBox is populated
from) against what NetBox holds, and reports discrepancies.
"""
from __future__ import annotations

import ipaddress
from collections import Counter
from pathlib import Path

import yaml

from modules import netbox_ipam as nb


BASE = Path(__file__).resolve().parents[1]
MANIFEST = BASE / "netbox" / "ipam.yml"
MANAGED = ("R1", "R2", "R3", "R4", "S1", "S2", "S3", "S4", "mgmt_swt")


def load_manifest(path: Path = MANIFEST) -> dict:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def manifest_summary(manifest: dict) -> dict:
    assigned = [
        (device["name"], interface["name"], str(ipaddress.ip_interface(address["address"])))
        for device in manifest["devices"]
        for interface in device["interfaces"]
        for address in interface.get("addresses", [])
    ]
    virtual = [str(ipaddress.ip_interface(row["address"])) for row in manifest.get("virtual_ips", [])]
    prefixes = [str(ipaddress.ip_network(row["prefix"])) for row in manifest["prefixes"]]
    duplicate_assignments = sorted(value for value, count in Counter(row[2] for row in assigned).items() if count > 1)
    return {
        "prefix_count": len(prefixes),
        "prefix_ipv4_count": sum(ipaddress.ip_network(value).version == 4 for value in prefixes),
        "prefix_ipv6_count": sum(ipaddress.ip_network(value).version == 6 for value in prefixes),
        "assigned_address_count": len(assigned),
        "assigned_ipv4_count": sum(ipaddress.ip_interface(row[2]).version == 4 for row in assigned),
        "assigned_ipv6_count": sum(ipaddress.ip_interface(row[2]).version == 6 for row in assigned),
        "virtual_address_count": len(virtual),
        "total_address_count": len(assigned) + len(virtual),
        "dhcp_range_count": len(manifest.get("dhcp_ranges", [])),
        "duplicate_assignment_count": len(duplicate_assignments),
        "duplicate_assignments": duplicate_assignments,
        "expected_addresses": sorted(row[2] for row in assigned) + sorted(virtual),
    }


def collect_live_evidence(client=None, manifest: dict | None = None) -> dict:
    manifest = manifest or load_manifest()
    summary = manifest_summary(manifest)
    client = client or nb.build_client()

    prefixes = list(client.ipam.prefixes.all())
    addresses = list(client.ipam.ip_addresses.all())
    ranges = list(client.ipam.ip_ranges.all())
    canonical = Counter(str(ipaddress.ip_interface(str(row.address))) for row in addresses)
    expected = Counter(summary["expected_addresses"])
    missing = sorted((expected - canonical).elements())
    unexpected = sorted((canonical - expected).elements())
    duplicates = sorted(value for value, count in canonical.items() if count > 1)

    management = []
    for device_name in MANAGED:
        device = client.dcim.devices.get(name=device_name)
        interface = client.dcim.interfaces.get(device_id=device.id, name="Vlan200") if device else None
        assigned = list(client.ipam.ip_addresses.filter(interface_id=interface.id)) if interface else []
        families = {ipaddress.ip_interface(str(row.address)).version for row in assigned}
        modes = dict(getattr(interface, "custom_fields", {}) or {}) if interface else {}
        management.append({
            "device": device_name,
            "dual_stack": families == {4, 6},
            "static": modes.get("ipv4_assignment_mode") == "static" and modes.get("ipv6_assignment_mode") == "static",
            # Any non-static family would make this interface a DHCP
            # reservation target (see modules/ipam_context.py).
            "reservation_target": bool(interface) and not (
                modes.get("ipv4_assignment_mode") == "static" and modes.get("ipv6_assignment_mode") == "static"
            ),
        })
    static_count = sum(row["static"] for row in management)
    reservation_targets = sum(row["reservation_target"] for row in management)

    return {
        **{key: value for key, value in summary.items() if key != "expected_addresses"},
        "live_prefix_count": len(prefixes),
        "live_address_count": len(addresses),
        "live_dhcp_range_count": len(ranges),
        "missing_address_count": len(missing),
        "missing_addresses": missing,
        "unexpected_address_count": len(unexpected),
        "unexpected_addresses": unexpected,
        "duplicate_live_address_count": len(duplicates),
        "duplicate_live_addresses": duplicates,
        "management_dual_stack_count": sum(row["dual_stack"] for row in management),
        "management_static_count": static_count,
        "management_device_count": len(management),
        # Measured from NetBox custom fields, not asserted.
        "vlan200_policy": "STATIC" if management and static_count == len(management) else "NOT_UNIFORMLY_STATIC",
        "reservation_targets": reservation_targets,
        "runtime_exceptions": [
            "Containerlab auto-assigned bootstrap management addresses",
            "IPv6 link-local and host loopback-local addresses",
            "H1-H4 dynamic leases and SLAAC runtime addresses",
        ],
    }


def validate(evidence: dict) -> list[str]:
    failures = []
    expected_pairs = (
        ("prefix count", evidence["live_prefix_count"], evidence["prefix_count"]),
        ("IP address count", evidence["live_address_count"], evidence["total_address_count"]),
        ("DHCP range count", evidence["live_dhcp_range_count"], evidence["dhcp_range_count"]),
        ("management dual-stack coverage", evidence["management_dual_stack_count"], evidence["management_device_count"]),
        ("VLAN200 static policy coverage", evidence["management_static_count"], evidence["management_device_count"]),
    )
    for label, actual, expected in expected_pairs:
        if actual != expected:
            failures.append(f"{label}: expected {expected}, found {actual}")
    for key in ("missing_address_count", "unexpected_address_count", "duplicate_assignment_count", "duplicate_live_address_count"):
        if evidence[key]:
            failures.append(f"{key}: {evidence[key]}")
    if evidence["vlan200_policy"] != "STATIC" or evidence["reservation_targets"] != 0:
        failures.append("VLAN200 must remain static and absent from reservations")
    return failures
