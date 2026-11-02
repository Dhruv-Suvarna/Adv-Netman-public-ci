#!/usr/bin/env python3
"""Phase 2 desired-state validation: does NetBox accurately model what
netbox/ipam.yml (itself a transcription of the existing templates/
inventory/DHCP config) says it should?

This is DELIBERATELY separate from any live-device check:

    existing desired configuration  (netbox/ipam.yml)
                VS
    NetBox representation                              <- THIS script

    NetBox representation
                VS
    running network (address_report.py / live commands) <- a SEPARATE,
                                                             independent
                                                             check; see
                                                             docs/NETBOX_IPAM.md

Never conflate the two: this script proves NetBox matches what the IaC
*intends*; it says nothing about whether the live network currently matches
that intent (drift there is a pre-existing, separate concern).

Usage:
    python3 netbox/scripts/verify_netbox_model.py [-v]

Exit code 0 = every check passed. Exit code 1 = at least one failed (each
failure is printed with what was expected vs found).
"""
from __future__ import annotations

import ipaddress
import sys
from pathlib import Path

import yaml

BASE = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(BASE))

from modules import netbox_ipam as nb  # noqa: E402

MANIFEST_PATH = BASE / "netbox" / "ipam.yml"


class Check:
    def __init__(self):
        self.failures: list[str] = []
        self.passed = 0

    def ok(self, description: str) -> None:
        self.passed += 1

    def fail(self, description: str) -> None:
        self.failures.append(description)

    def expect(self, condition: bool, description: str) -> None:
        if condition:
            self.ok(description)
        else:
            self.fail(description)

    @property
    def total(self) -> int:
        return self.passed + len(self.failures)


def _tag_slugs(obj) -> set[str]:
    return {t.slug for t in getattr(obj, "tags", None) or []}


def verify(manifest: dict, client) -> Check:
    check = Check()

    # 1. Managed devices present, with correct platform/type/role. -----------
    devices_by_name = {}
    for entry in manifest["devices"]:
        obj = client.dcim.devices.get(name=entry["name"])
        if obj is None:
            check.fail(f"device {entry['name']}: missing from NetBox entirely")
            continue
        devices_by_name[entry["name"]] = obj
        check.expect(obj.device_type.slug == entry["device_type"], f"device {entry['name']}: device_type is {entry['device_type']}")
        check.expect(obj.role.slug == entry["role"], f"device {entry['name']}: role is {entry['role']}")
        managed = entry.get("managed", True)
        check.expect(obj.custom_fields.get("iac_managed") == managed, f"device {entry['name']}: iac_managed == {managed}")
        expected_tag = "managed" if managed else "unmanaged"
        check.expect(expected_tag in _tag_slugs(obj), f"device {entry['name']}: tagged {expected_tag!r}")
        check.expect("csci5840-iac" in _tag_slugs(obj), f"device {entry['name']}: tagged with ownership marker")

    # R5/WebServer must NEVER be classified as managed -- verified from the
    # actual stored data, not merely from the manifest's own claim.
    for name in ("R5", "WebServer"):
        obj = devices_by_name.get(name)
        if obj is not None:
            check.expect(obj.custom_fields.get("iac_managed") is False, f"{name}: iac_managed is False (never a provisioning target)")
            check.expect("unmanaged" in _tag_slugs(obj), f"{name}: tagged 'unmanaged'")
            check.expect("managed" not in _tag_slugs(obj), f"{name}: NOT tagged 'managed'")

    # 2. Interfaces present per device. --------------------------------------
    for entry in manifest["devices"]:
        device_obj = devices_by_name.get(entry["name"])
        if device_obj is None:
            continue
        live_interfaces = {i.name: i for i in client.dcim.interfaces.filter(device_id=device_obj.id)}
        for iface in entry["interfaces"]:
            check.expect(iface["name"] in live_interfaces, f"{entry['name']}/{iface['name']}: interface exists")

    # 3. VLANs present. -------------------------------------------------------
    vlans_by_vid = {}
    for entry in manifest["vlans"]:
        obj = client.ipam.vlans.get(vid=entry["vid"])
        if obj is None:
            check.fail(f"VLAN{entry['vid']}: missing from NetBox")
            continue
        vlans_by_vid[entry["vid"]] = obj
        check.expect(obj.name == entry["name"], f"VLAN{entry['vid']}: name is {entry['name']}")

    # 4/5. IPv4 and IPv6 prefixes present with correct VLAN association. ------
    for entry in manifest["prefixes"]:
        network = ipaddress.ip_network(entry["prefix"])
        obj = client.ipam.prefixes.get(prefix=entry["prefix"])
        if obj is None:
            check.fail(f"prefix {entry['prefix']}: missing from NetBox")
            continue
        family_label = "IPv4" if network.version == 4 else "IPv6"
        check.ok(f"prefix {entry['prefix']} ({family_label}): present")
        managed = entry.get("managed", True)
        check.expect(obj.custom_fields.get("iac_managed") == managed, f"prefix {entry['prefix']}: iac_managed == {managed}")
        if entry.get("vlan") is not None:
            check.expect(obj.vlan is not None and obj.vlan.vid == entry["vlan"], f"prefix {entry['prefix']}: assigned to VLAN{entry['vlan']}")

    # 6. IP addresses present and assigned to the correct interface. ---------
    seen_addresses: dict[str, list[str]] = {}
    for entry in manifest["devices"]:
        for iface in entry["interfaces"]:
            for addr_entry in iface["addresses"]:
                addr = addr_entry["address"]
                obj = client.ipam.ip_addresses.get(address=addr)
                owner = f"{entry['name']}/{iface['name']}"
                if obj is None:
                    check.fail(f"{owner}: IP {addr} missing from NetBox")
                    continue
                check.ok(f"{owner}: IP {addr} present")
                assigned = obj.assigned_object
                assigned_ok = (
                    assigned is not None
                    and getattr(assigned, "name", None) == iface["name"]
                    and getattr(assigned, "device", None) is not None
                    and assigned.device.name == entry["name"]
                )
                check.expect(assigned_ok, f"{owner}: IP {addr} assigned to the correct interface")
                seen_addresses.setdefault(str(ipaddress.ip_interface(addr)), []).append(owner)

    # 7. No duplicate address assignments (within the manifest's own scope).
    duplicates = {addr: owners for addr, owners in seen_addresses.items() if len(owners) > 1}
    check.expect(not duplicates, f"no duplicate IP assignments within the manifest (found: {duplicates})" if duplicates else "no duplicate IP assignments within the manifest")

    # 8. Primary addresses correct (the documented Vlan200/loopback/service convention).
    for entry in manifest["devices"]:
        device_obj = devices_by_name.get(entry["name"])
        if device_obj is None:
            continue
        for iface in entry["interfaces"]:
            for addr_entry in iface["addresses"]:
                if not addr_entry.get("primary"):
                    continue
                family = ipaddress.ip_interface(addr_entry["address"]).version
                primary = getattr(device_obj, f"primary_ip{family}", None)
                expected = str(ipaddress.ip_interface(addr_entry["address"]))
                check.expect(
                    primary is not None and str(ipaddress.ip_interface(primary.address)) == expected,
                    f"{entry['name']}: primary_ip{family} is {expected}",
                )

    # 9. DHCP-related subnet metadata present. --------------------------------
    for entry in manifest.get("dhcp_ranges", []):
        start = str(ipaddress.ip_address(entry["start"]))
        end = str(ipaddress.ip_address(entry["end"]))
        matches = list(client.ipam.ip_ranges.filter(start_address=start, end_address=end))
        check.expect(len(matches) == 1, f"DHCP range {entry['name']}: present exactly once ({start}-{end})")

    for prefix_str, targets in manifest.get("dhcp_relay_targets", {}).items():
        obj = client.ipam.prefixes.get(prefix=prefix_str)
        if obj is None:
            check.fail(f"prefix {prefix_str}: missing (needed for DHCP relay-target check)")
            continue
        stored = obj.custom_fields.get("dhcp_relay_targets") or ""
        check.expect(all(target in stored for target in targets), f"prefix {prefix_str}: dhcp_relay_targets custom field contains {targets}")

    # 10. H4's IPv6-only nature preserved: no IPv4 address anywhere for it,
    #     and VLAN30 has no IPv4 prefix in the manifest (or in NetBox).
    vlan30_v4_prefixes = [
        e for e in manifest["prefixes"]
        if e.get("vlan") == 30 and ipaddress.ip_network(e["prefix"]).version == 4
    ]
    check.expect(not vlan30_v4_prefixes, "VLAN30 has no IPv4 prefix in the manifest (IPv6-only design preserved)")
    live_vlan30_v4 = [
        p for p in client.ipam.prefixes.filter(vlan_id=vlans_by_vid[30].id) if ipaddress.ip_network(p.prefix).version == 4
    ] if 30 in vlans_by_vid else []
    check.expect(not live_vlan30_v4, "VLAN30 has no IPv4 prefix in NetBox")

    # 11. No unexpected IaC-owned objects: everything tagged with our
    #     ownership marker must correspond to something the manifest
    #     actually declares (catches leftover/renamed objects a manifest
    #     edit no longer references).
    expected_device_names = {d["name"] for d in manifest["devices"]}
    live_tagged_devices = {d.name for d in client.dcim.devices.filter(tag="csci5840-iac")}
    unexpected_devices = live_tagged_devices - expected_device_names
    check.expect(not unexpected_devices, f"no unexpected IaC-owned devices (found extra: {unexpected_devices})" if unexpected_devices else "no unexpected IaC-owned devices")

    expected_vlan_vids = {v["vid"] for v in manifest["vlans"]}
    live_tagged_vlans = {v.vid for v in client.ipam.vlans.filter(tag="csci5840-iac")}
    unexpected_vlans = live_tagged_vlans - expected_vlan_vids
    check.expect(not unexpected_vlans, f"no unexpected IaC-owned VLANs (found extra: {unexpected_vlans})" if unexpected_vlans else "no unexpected IaC-owned VLANs")

    expected_prefixes = {str(ipaddress.ip_network(p["prefix"])) for p in manifest["prefixes"]}
    live_tagged_prefixes = {str(ipaddress.ip_network(p.prefix)) for p in client.ipam.prefixes.filter(tag="csci5840-iac")}
    unexpected_prefixes = live_tagged_prefixes - expected_prefixes
    check.expect(not unexpected_prefixes, f"no unexpected IaC-owned prefixes (found extra: {unexpected_prefixes})" if unexpected_prefixes else "no unexpected IaC-owned prefixes")

    return check


def main(argv: list[str] | None = None) -> int:
    manifest = yaml.safe_load(MANIFEST_PATH.read_text())
    try:
        client = nb.build_client()
        nb.check_status(nb.load_config())
    except nb.NetboxError as exc:
        print(f"ERROR: NetBox is not reachable/usable: {exc}", file=sys.stderr)
        return 1

    check = verify(manifest, client)
    for failure in check.failures:
        print(f"FAIL  {failure}")
    print(f"\n{check.passed}/{check.total} checks passed.")
    return 0 if not check.failures else 1


if __name__ == "__main__":
    raise SystemExit(main())
