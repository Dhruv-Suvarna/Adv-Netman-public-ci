#!/usr/bin/env python3
"""Phase 2: idempotently model the existing lab in NetBox from
netbox/ipam.yml.

    existing templates/inventory
              |
              | extraction / reconciliation (this script)
              v
           NetBox
              |
              v
    validation/reporting only (see verify_netbox_model.py)

This script is NOT the cutover. It never renders device configuration and
is never called by master.py or any provisioning module -- it only reads
netbox/ipam.yml and reconciles NetBox objects against it, using
modules/netbox_ipam.py as the sole NetBox API access point (every actual
HTTP call happens inside reconcile_object()/ensure_tag()/
ensure_custom_field() in that module; this script only decides WHAT to
reconcile, using the generic primitives that module provides).

Usage:
    python3 netbox/scripts/populate_netbox.py --check   # dry run, no writes
    python3 netbox/scripts/populate_netbox.py --apply   # create/update

Exactly one of --check/--apply is required, so a bare invocation can never
accidentally write to NetBox.

Idempotent: running --apply twice in a row must report CREATE the first
time and UNCHANGED the second time for every object, with zero duplicates.
A CONFLICT is reported (and left untouched) rather than silently resolved.
"""
from __future__ import annotations

import argparse
import ipaddress
import sys
from collections import Counter
from pathlib import Path

import yaml

BASE = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(BASE))

from modules import netbox_ipam as nb  # noqa: E402

MANIFEST_PATH = BASE / "netbox" / "ipam.yml"


def load_manifest(path: Path = MANIFEST_PATH) -> dict:
    manifest = yaml.safe_load(path.read_text())
    _validate_manifest(manifest)
    return manifest


def _validate_manifest(manifest: dict) -> None:
    """Catch structural mistakes in the manifest itself before touching
    NetBox: duplicate names/prefixes/addresses, dangling references, and
    malformed IP/prefix syntax. Raises ValueError with a specific, actionable
    message -- never silently drops or "fixes" a bad entry."""
    errors: list[str] = []

    vlan_ids = {v["vid"] for v in manifest.get("vlans", [])}
    if len(vlan_ids) != len(manifest.get("vlans", [])):
        errors.append("Duplicate VLAN id in manifest")

    ipam_role_slugs = {r["slug"] for r in manifest.get("ipam_roles", [])}
    device_type_slugs = {t["slug"] for t in manifest.get("device_types", [])}
    device_role_slugs = {r["slug"] for r in manifest.get("device_roles", [])}

    seen_prefixes: set[str] = set()
    for entry in manifest.get("prefixes", []):
        raw = entry["prefix"]
        try:
            network = ipaddress.ip_network(raw, strict=True)
        except ValueError as exc:
            errors.append(f"Invalid prefix {raw!r}: {exc}")
            continue
        key = str(network)
        if key in seen_prefixes:
            errors.append(f"Duplicate prefix in manifest: {key}")
        seen_prefixes.add(key)
        if entry.get("vlan") is not None and entry["vlan"] not in vlan_ids:
            errors.append(f"Prefix {raw} references unknown vlan {entry['vlan']}")
        if entry.get("role") and entry["role"] not in ipam_role_slugs:
            errors.append(f"Prefix {raw} references unknown ipam role {entry['role']!r}")
        for gw_key in ("gateway_v4", "gateway_v6"):
            gw = entry.get(gw_key)
            if gw:
                try:
                    ip = ipaddress.ip_address(gw)
                except ValueError as exc:
                    errors.append(f"Prefix {raw} has invalid {gw_key} {gw!r}: {exc}")
                    continue
                if ip not in network:
                    errors.append(f"Prefix {raw} {gw_key} {gw} is not inside the prefix")

    for entry in manifest.get("dhcp_ranges", []):
        try:
            start = ipaddress.ip_address(entry["start"])
            end = ipaddress.ip_address(entry["end"])
        except ValueError as exc:
            errors.append(f"DHCP range {entry.get('name')!r} has an invalid address: {exc}")
            continue
        if start.version != end.version:
            errors.append(f"DHCP range {entry['name']!r} mixes address families")
        elif int(start) > int(end):
            errors.append(f"DHCP range {entry['name']!r} start is after end")
        if entry.get("vlan") is not None and entry["vlan"] not in vlan_ids:
            errors.append(f"DHCP range {entry['name']!r} references unknown vlan {entry['vlan']}")

    seen_addresses: dict[str, str] = {}
    seen_device_names: set[str] = set()
    for device in manifest.get("devices", []):
        name = device["name"]
        if name in seen_device_names:
            errors.append(f"Duplicate device name in manifest: {name}")
        seen_device_names.add(name)
        if device.get("device_type") not in device_type_slugs:
            errors.append(f"Device {name} references unknown device_type {device.get('device_type')!r}")
        if device.get("role") not in device_role_slugs:
            errors.append(f"Device {name} references unknown role {device.get('role')!r}")
        seen_iface_names: set[str] = set()
        for iface in device.get("interfaces", []):
            if iface["name"] in seen_iface_names:
                errors.append(f"Device {name} has duplicate interface name {iface['name']!r}")
            seen_iface_names.add(iface["name"])
            for addr_entry in iface.get("addresses", []):
                raw = addr_entry["address"]
                try:
                    iface_ip = ipaddress.ip_interface(raw)
                except ValueError as exc:
                    errors.append(f"{name}/{iface['name']}: invalid address {raw!r}: {exc}")
                    continue
                key = str(iface_ip)
                owner = f"{name}/{iface['name']}"
                if key in seen_addresses and seen_addresses[key] != owner:
                    errors.append(f"Duplicate IP assignment {key}: both {seen_addresses[key]} and {owner}")
                seen_addresses[key] = owner

    for vip in manifest.get("virtual_ips", []):
        try:
            ipaddress.ip_interface(vip["address"])
        except ValueError as exc:
            errors.append(f"Invalid virtual_ips address {vip['address']!r}: {exc}")

    if errors:
        raise ValueError("Manifest validation failed:\n  - " + "\n  - ".join(errors))


class Populator:
    """Owns the running tally of reconciliation outcomes and the NetBox
    object handles created along the way (site id, role ids, etc.) that
    later steps need to reference."""

    def __init__(self, client, manifest: dict, *, apply: bool):
        self.client = client
        self.manifest = manifest
        self.apply = apply
        self.results: list[tuple[str, str, nb.ReconcileResult]] = []
        self._site = None
        self._device_roles: dict[str, int] = {}
        self._device_types: dict[str, int] = {}
        self._ipam_roles: dict[str, int] = {}
        self._vlans: dict[int, int] = {}
        self._prefixes: dict[str, int] = {}

    def _record(self, kind: str, name: str, result: nb.ReconcileResult) -> nb.ReconcileResult:
        self.results.append((kind, name, result))
        return result

    def ownership_tags(self, *, managed: bool | None = None) -> list[str]:
        tags = [self.manifest["tags"]["ownership"]]
        if managed is True:
            tags.append(self.manifest["tags"]["managed"])
        elif managed is False:
            tags.append(self.manifest["tags"]["unmanaged"])
        return tags

    # -- foundational objects -------------------------------------------------

    def populate_tags(self) -> None:
        for key in ("ownership", "managed", "unmanaged", "dhcp_primary", "dhcp_secondary"):
            name = self.manifest["tags"][key]
            result = nb.ensure_tag(self.client, name, apply=self.apply)
            self._record("tag", name, result)

    def populate_custom_fields(self) -> None:
        result = nb.ensure_custom_field(
            self.client, "iac_managed", field_type="boolean",
            content_types=["dcim.device", "ipam.prefix"],
            label="IaC managed", apply=self.apply,
            description="May this repository's IaC configure/provision this object? See docs/NETBOX_IPAM.md.",
        )
        self._record("custom_field", "iac_managed", result)

        result = nb.ensure_custom_field(
            self.client, "dhcp_relay_targets", field_type="text",
            content_types=["ipam.prefix"], label="DHCP relay targets", apply=self.apply,
            description="Comma-separated relay/server addresses for this client prefix (Phase 2 metadata for the future DHCP phase).",
        )
        self._record("custom_field", "dhcp_relay_targets", result)

        # Phase 3B: assignment-policy + DHCPv6 identity metadata. Plain
        # "text" (validated in Python against nb.ASSIGNMENT_MODES) rather
        # than NetBox's "select" type: a select field requires a separate
        # linked CustomFieldChoiceSet object, which is unwarranted
        # complexity for a 4-value set this repository already validates
        # on every write (see populate_netbox.py's _assignment_mode()).
        for name, label, description in (
            ("ipv4_assignment_mode", "IPv4 assignment mode",
             "How this interface's IPv4 address reaches it: static, dhcp-reserved, or none. See docs/NETBOX_IPAM.md Phase 3B."),
            ("ipv6_assignment_mode", "IPv6 assignment mode",
             "How this interface's IPv6 address reaches it: static, dhcpv6-reserved, or none. See docs/NETBOX_IPAM.md Phase 3B."),
            ("dhcpv6_duid", "DHCPv6 DUID",
             "DUID: observed from a real client, or a computed deterministic DUID-LL from an authoritative MAC (Phase 3B.1) -- never guessed. NetBox has no native DUID field."),
            ("dhcpv6_iaid", "DHCPv6 IAID",
             "IAID -- informational only; ISC dhcpd fixed-address6 matching does not require it (see docs/NETBOX_IPAM.md). Never fabricated. No native NetBox field."),
            ("dhcpv6_identity_status", "DHCPv6 identity status",
             "observed / authoritative-planned / blocked (see modules.netbox_ipam.IDENTITY_STATUSES) -- Phase 3B.1's observed-vs-decided-vs-blocked distinction."),
        ):
            result = nb.ensure_custom_field(
                self.client, name, field_type="text", content_types=["dcim.interface"],
                label=label, description=description, apply=self.apply,
            )
            self._record("custom_field", name, result)

        result = nb.ensure_custom_field(
            self.client, "identity_status", field_type="text", content_types=["dcim.macaddress"],
            label="Identity status", apply=self.apply,
            description="observed / authoritative-planned / blocked -- is this MAC merely observed, or the deliberate, durable, to-be-pinned-at-cutover identity? See docs/NETBOX_IPAM.md.",
        )
        self._record("custom_field", "identity_status (mac)", result)

    def populate_site(self) -> None:
        site = self.manifest["site"]
        result = nb.reconcile_object(
            self.client.dcim.sites,
            lookup={"slug": site["slug"]},
            desired={
                "name": site["name"], "status": site["status"], "description": site["description"],
                "tags": self.ownership_tags(),
            },
            safe_update_fields=frozenset({"name", "status", "description"}),
            apply=self.apply,
        )
        self._record("site", site["slug"], result)
        if result.obj is not None:
            self._site = result.obj.id

    def populate_manufacturers(self) -> None:
        for entry in self.manifest["manufacturers"]:
            result = nb.reconcile_object(
                self.client.dcim.manufacturers,
                lookup={"slug": entry["slug"]},
                desired={"name": entry["name"], "description": entry.get("description", ""), "tags": self.ownership_tags()},
                safe_update_fields=frozenset({"name", "description"}),
                apply=self.apply,
            )
            self._record("manufacturer", entry["slug"], result)

    def populate_device_types(self) -> None:
        for entry in self.manifest["device_types"]:
            result = nb.reconcile_object(
                self.client.dcim.device_types,
                lookup={"slug": entry["slug"]},
                desired={
                    "model": entry["model"], "manufacturer": {"slug": entry["manufacturer"]},
                    "tags": self.ownership_tags(),
                },
                safe_update_fields=frozenset({"model"}),
                apply=self.apply,
            )
            self._record("device_type", entry["slug"], result)
            if result.obj is not None:
                self._device_types[entry["slug"]] = result.obj.id

    def populate_device_roles(self) -> None:
        for entry in self.manifest["device_roles"]:
            result = nb.reconcile_object(
                self.client.dcim.device_roles,
                lookup={"slug": entry["slug"]},
                desired={
                    "name": entry["name"], "color": entry.get("color", "9e9e9e"),
                    "description": entry.get("description", ""), "tags": self.ownership_tags(),
                },
                safe_update_fields=frozenset({"name", "color", "description"}),
                apply=self.apply,
            )
            self._record("device_role", entry["slug"], result)
            if result.obj is not None:
                self._device_roles[entry["slug"]] = result.obj.id

    def populate_ipam_roles(self) -> None:
        for entry in self.manifest["ipam_roles"]:
            result = nb.reconcile_object(
                self.client.ipam.roles,
                lookup={"slug": entry["slug"]},
                desired={"name": entry["name"], "description": entry.get("description", ""), "tags": self.ownership_tags()},
                safe_update_fields=frozenset({"name", "description"}),
                apply=self.apply,
            )
            self._record("ipam_role", entry["slug"], result)
            if result.obj is not None:
                self._ipam_roles[entry["slug"]] = result.obj.id

    def populate_vlans(self) -> None:
        if self._site is None:
            for entry in self.manifest["vlans"]:
                self._record("vlan", f"VLAN{entry['vid']}", _skipped("the site does not exist yet (run --apply first)"))
            return
        for entry in self.manifest["vlans"]:
            desired = {
                # NetBox's write serializer wants "site" (id or nested
                # dict); the read/filter side accepts "site_id" (see
                # `lookup` below) -- these are deliberately different keys.
                "name": entry["name"], "description": entry.get("description", ""),
                "status": "active", "tags": self.ownership_tags(), "site": {"id": self._site},
            }
            if entry.get("role"):
                desired["role"] = {"slug": entry["role"]}
            result = nb.reconcile_object(
                self.client.ipam.vlans,
                lookup={"vid": entry["vid"], "site_id": self._site},
                desired=desired,
                # "role" is deliberately NOT safe-updatable: a VLAN already
                # holding a different role than the manifest expects is
                # treated as a material conflict, not auto-corrected.
                safe_update_fields=frozenset({"name", "description", "status"}),
                apply=self.apply,
            )
            self._record("vlan", f"VLAN{entry['vid']}", result)
            if result.obj is not None:
                self._vlans[entry["vid"]] = result.obj.id

    def populate_prefixes(self) -> None:
        for entry in self.manifest["prefixes"]:
            managed = entry.get("managed", True)
            wants_vlan = entry.get("vlan") is not None
            if wants_vlan and entry["vlan"] not in self._vlans:
                self._record("prefix", entry["prefix"], _skipped(f"VLAN{entry['vlan']} does not exist yet (run --apply first)"))
                continue
            desired = {
                "status": "active", "description": entry.get("description", ""),
                "tags": self.ownership_tags(managed=managed),
                "custom_fields": {"iac_managed": managed},
            }
            if entry.get("role"):
                desired["role"] = {"slug": entry["role"]}
            if wants_vlan:
                desired["vlan"] = {"id": self._vlans[entry["vlan"]]}
            relay = self.manifest.get("dhcp_relay_targets", {}).get(entry["prefix"])
            if relay:
                desired["custom_fields"]["dhcp_relay_targets"] = ", ".join(relay)
            result = nb.reconcile_object(
                self.client.ipam.prefixes,
                lookup={"prefix": entry["prefix"]},
                desired=desired,
                # "role"/"vlan" are deliberately NOT safe-updatable: they are
                # structural/identity-defining for a prefix's place in the
                # topology, so a mismatch is a material conflict.
                safe_update_fields=frozenset({"description", "status"}),
                apply=self.apply,
            )
            self._record("prefix", entry["prefix"], result)
            if result.obj is not None:
                self._prefixes[entry["prefix"]] = result.obj.id

    def populate_dhcp_ranges(self) -> None:
        # ipam.IPRange has no direct VLAN foreign key; the manifest's own
        # `description` text (and the owning prefix, which does carry the
        # VLAN) already identify which VLAN each range serves, so nothing
        # further is invented here.
        #
        # Status: NetBox 4.7's ipam.IPRange model supports only
        # active/reserved/deprecated (verified live via an OPTIONS request
        # against this running instance -- "dhcp" is valid for
        # ipam.IPAddress but NOT for ipam.IPRange in this release). Per
        # Step 15's own instruction not to invent an unsupported status,
        # "reserved" is used: it is the genuinely-supported status whose
        # meaning ("this address space is set aside for a specific purpose")
        # accurately describes a DHCP pool boundary; the range's name/
        # description make the DHCP purpose explicit and unambiguous.
        # Phase 3C: each range also carries a `dhcp-primary`/`dhcp-secondary`
        # tag, driven by the manifest's own `server: nmas`/`server: r2` key
        # -- so a NetBox-only consumer (modules/netbox_ipam.get_dhcp_ranges())
        # can distinguish which server a pool belongs to without parsing
        # free-form description text.
        server_tag = {"nmas": "dhcp_primary", "r2": "dhcp_secondary"}
        for entry in self.manifest.get("dhcp_ranges", []):
            server = entry.get("server", "nmas")
            if server not in server_tag:
                raise ValueError(f"dhcp_ranges entry {entry['name']!r} has unknown server {server!r}")
            desired = {
                "status": "reserved", "description": entry.get("description", ""),
                "tags": self.ownership_tags(managed=True) + [self.manifest["tags"][server_tag[server]]],
            }
            result = nb.reconcile_object(
                self.client.ipam.ip_ranges,
                lookup={"start_address": _range_endpoint(entry["start"]), "end_address": _range_endpoint(entry["end"])},
                desired=desired,
                safe_update_fields=frozenset({"description", "status"}),
                apply=self.apply,
            )
            self._record("dhcp_range", entry["name"], result)

    # -- devices/interfaces/addresses ----------------------------------------

    def populate_devices(self) -> None:
        for device in self.manifest["devices"]:
            managed = device.get("managed", True)
            missing = [
                dep for dep, ok in (
                    ("site", self._site is not None),
                    (f"device_type {device['device_type']}", device["device_type"] in self._device_types),
                    (f"role {device['role']}", device["role"] in self._device_roles),
                ) if not ok
            ]
            if missing:
                self._record("device", device["name"], _skipped(f"{', '.join(missing)} do(es) not exist yet (run --apply first)"))
                continue
            result = nb.reconcile_object(
                self.client.dcim.devices,
                lookup={"name": device["name"], "site_id": self._site},
                desired={
                    "device_type": {"id": self._device_types[device["device_type"]]},
                    "role": {"id": self._device_roles[device["role"]]},
                    "site": {"id": self._site},
                    "status": "active",
                    "tags": self.ownership_tags(managed=managed),
                    "custom_fields": {"iac_managed": managed},
                },
                # "device_type"/"role" are deliberately NOT safe-updatable:
                # an existing device of the same name but a different
                # platform/role is a material conflict, not auto-corrected.
                safe_update_fields=frozenset({"status"}),
                apply=self.apply,
            )
            self._record("device", device["name"], result)
            if result.obj is None:
                continue  # CHECK-CREATE or CONFLICT: nothing to attach interfaces to
            self._populate_interfaces(device, result.obj.id)

    def _populate_interfaces(self, device: dict, device_id: int) -> None:
        primary_ids: dict[int, int] = {}  # family -> ip address id, for this device
        for iface in device["interfaces"]:
            has_v4 = any(_family_of(a["address"]) == 4 for a in iface["addresses"])
            has_v6 = any(_family_of(a["address"]) == 6 for a in iface["addresses"])
            iface_result = nb.reconcile_object(
                self.client.dcim.interfaces,
                lookup={"device_id": device_id, "name": iface["name"]},
                # "type": "virtual" for every modeled interface -- every
                # link in this Containerlab topology is a container veth
                # pair, not a real physical NIC, so none of NetBox's
                # physical-media types (copper/fiber speed grades, etc.)
                # would be accurate; "virtual" is the correct, honest choice
                # NetBox itself uses for this kind of interface (SVIs,
                # loopbacks, and here also the "routed port" links).
                desired={
                    "type": "virtual", "enabled": True, "tags": self.ownership_tags(), "device": {"id": device_id},
                    "custom_fields": {
                        "ipv4_assignment_mode": _assignment_mode(iface["name"], 4, has_v4),
                        "ipv6_assignment_mode": _assignment_mode(iface["name"], 6, has_v6),
                    },
                },
                safe_update_fields=frozenset({"enabled"}),
                # ipv4/ipv6_assignment_mode are POLICY this repository owns
                # outright (see _assignment_mode() above), not identity data
                # a human/other tool might set -- a later, deliberate policy
                # revision (e.g. Phase 3B.3's Vlan200 dhcp-reserved -> static
                # correction) must be able to update an already-recorded
                # value instead of being treated as an unexplained CONFLICT.
                safe_update_custom_fields=frozenset({"ipv4_assignment_mode", "ipv6_assignment_mode"}),
                apply=self.apply,
            )
            self._record("interface", f"{device['name']}/{iface['name']}", iface_result)
            if iface_result.obj is None:
                continue
            # Phase 3B.3: an interface no longer classified dynamic may
            # still carry DHCP-identity-planning metadata a PREVIOUS run
            # wrote before this correction (Vlan200's MAC
            # identity_status=authoritative-planned; its dhcpv6_duid/iaid/
            # identity_status). Both cleanups are self-guarding on the
            # interface's CURRENT mode, so this is a safe no-op everywhere
            # nothing dynamic was ever planned.
            self._record(
                "mac_identity_cleanup", f"{device['name']}/{iface['name']}",
                nb.clear_stale_mac_identity_status(device["name"], iface["name"], self.client, apply=self.apply)
                or nb.ReconcileResult(nb.UNCHANGED),
            )
            self._record(
                "dhcpv6_identity_cleanup", f"{device['name']}/{iface['name']}",
                nb.clear_stale_dhcpv6_identity(device["name"], iface["name"], self.client, apply=self.apply)
                or nb.ReconcileResult(nb.UNCHANGED),
            )
            for addr_entry in iface["addresses"]:
                ip_result = self._populate_ip_address(addr_entry, assigned_object_id=iface_result.obj.id)
                if ip_result.obj is not None and addr_entry.get("primary"):
                    family = ipaddress.ip_interface(addr_entry["address"]).version
                    primary_ids[family] = ip_result.obj.id
        if primary_ids:
            self._reconcile_primary_ips(device, device_id, primary_ids)

    def _reconcile_primary_ips(self, device: dict, device_id: int, primary_ids: dict[int, int]) -> None:
        """Set primary_ip4/primary_ip6 only when the device currently has
        none for that family. An existing primary that already matches is
        UNCHANGED; one that points somewhere else is a CONFLICT (reported,
        never silently overwritten) -- this can only happen if a human or
        another tool set a different primary IP on this device out of band.
        """
        # A plain GET is safe in --check mode too; only .save() is apply-gated.
        device_obj = self.client.dcim.devices.get(device_id)
        for family, desired_id in primary_ids.items():
            field = f"primary_ip{family}"
            current = getattr(device_obj, field, None)
            current_id = getattr(current, "id", None)
            label = f"{device['name']}.{field}"
            if current_id == desired_id:
                self._record("primary_ip", label, nb.ReconcileResult(nb.UNCHANGED, device_obj))
            elif current_id is None:
                if self.apply:
                    device_obj.update({field: desired_id})
                    device_obj.save()
                    result = nb.ReconcileResult(nb.CREATE, device_obj, changes={field: desired_id})
                else:
                    result = nb.ReconcileResult(nb.CHECK_CREATE, None, changes={field: desired_id})
                self._record("primary_ip", label, result)
            else:
                self._record(
                    "primary_ip", label,
                    nb.ReconcileResult(nb.CONFLICT, device_obj, conflicts={field: {"existing": current_id, "desired": desired_id}}),
                )

    def _populate_ip_address(self, addr_entry: dict, *, assigned_object_id: int | None) -> nb.ReconcileResult:
        desired = {
            "status": "active",
            "description": addr_entry.get("description", ""),
            "tags": self.ownership_tags(),
        }
        if addr_entry.get("role"):
            desired["role"] = addr_entry["role"]
        if assigned_object_id is not None:
            desired["assigned_object_type"] = "dcim.interface"
            desired["assigned_object_id"] = assigned_object_id
        result = nb.reconcile_object(
            self.client.ipam.ip_addresses,
            lookup={"address": addr_entry["address"]},
            desired=desired,
            # "assigned_object_type"/"assigned_object_id" are deliberately
            # NOT safe-updatable: an address already assigned to a
            # different interface/device than the manifest expects is a
            # material conflict, never silently reassigned.
            safe_update_fields=frozenset({"description", "role"}),
            apply=self.apply,
        )
        self._record("ip_address", addr_entry["address"], result)
        return result

    def populate_virtual_ips(self) -> None:
        for vip in self.manifest.get("virtual_ips", []):
            self._populate_ip_address(vip, assigned_object_id=None)

    def run(self) -> None:
        self.populate_tags()
        self.populate_custom_fields()
        self.populate_site()
        self.populate_manufacturers()
        self.populate_device_types()
        self.populate_device_roles()
        self.populate_ipam_roles()
        self.populate_vlans()
        self.populate_prefixes()
        self.populate_dhcp_ranges()
        self.populate_devices()
        self.populate_virtual_ips()


SKIPPED = "SKIPPED"


def _skipped(reason: str) -> nb.ReconcileResult:
    """A child object could not even be attempted because a prerequisite
    parent object (site/vlan/device_type/role/...) does not exist in NetBox
    yet. This only ever happens on a `--check` preview against a NetBox that
    does not yet have those parents (nothing has been reconciled at all
    yet) -- it is not a NetBox failure and not a CONFLICT, so it gets its
    own outcome rather than being force-fit into either. Running --apply
    once resolves it for every subsequent --check.
    """
    return nb.ReconcileResult(SKIPPED, None, changes={"reason": reason})


def _range_endpoint(value: str) -> str:
    """ipam.IPRange start/end addresses are stored WITHOUT a prefix length
    in NetBox's filter/lookup semantics but pynetbox's create/compare wants
    plain host addresses; normalize once here."""
    return str(ipaddress.ip_address(value))


def _family_of(cidr: str) -> int:
    return ipaddress.ip_interface(cidr).version


# Assignment-mode POLICY (Step 3 of Phase 3B; corrected in Phase 3B.3): the
# dedicated management SVI (Vlan200) on every managed device is a STATIC
# out-of-band management address, by explicit user architecture decision --
# it must never use DHCP/DHCPv6, never require a client MAC/DUID/IAID for
# its identity, and never appear as a reservation target. See
# docs/NETBOX_IPAM.md "Phase 3B.3 -- Management VLAN Policy Correction".
#
# HISTORICAL NOTE (superseded -- kept for context, not behavior): Phase
# 3B/3B.1 originally classified Vlan200 as the one candidate for future
# DHCP/DHCPv6-reserved dynamic assignment, mirroring a common real-world
# "device always gets the same IP via a server-side fixed reservation"
# pattern. That assumption is superseded: Vlan200 IS the management VLAN
# and stays static. Every other category was already, and remains, static
# by the same original design decision, documented in
# docs/NETBOX_IPAM.md "Step 3 -- interface classification":
#   * loopbacks: no ordinary Ethernet MAC-based DHCP relationship, and a
#     router identity that must exist independently of underlay
#     connectivity (Step 5) -- never DHCP.
#   * routed point-to-point RIP/OSPF/BGP transit links: both endpoints'
#     identities are a permanent, load-bearing part of the routing design,
#     not a dynamically-attaching endpoint -- conventional real-world
#     practice keeps these static.
#   * a switch's own client-VLAN SVI address (S1/S2's Vlan10/20/30): this
#     is infrastructure identity (the switch's own address), not an
#     end-host lease -- H1-H4 remain the actual DHCP clients on those
#     VLANs (Step 14).
# This is a POLICY decision recorded as reviewable Python, not a NetBox
# object requiring its own justification field. No interface is currently
# classified dhcp-reserved/dhcpv6-reserved; those ASSIGNMENT_MODES values
# remain valid in the schema for a genuinely future dynamic target, but
# nothing maps to them today -- a reservation-target count of 0 is the
# correct result of this architecture, not a gap to fill (Step 10).


def _assignment_mode(interface_name: str, family: int, has_address: bool) -> str:
    # interface_name/family are still accepted (not just has_address) so a
    # genuinely future dynamic-assignment policy can be reintroduced here
    # without changing every call site -- see the policy note above for why
    # nothing currently maps to dhcp-reserved/dhcpv6-reserved.
    if not has_address:
        return "none"
    return "static"


def summarize(results: list[tuple[str, str, nb.ReconcileResult]]) -> Counter:
    return Counter(result.action for _, _, result in results)


def print_report(results: list[tuple[str, str, nb.ReconcileResult]], *, verbose: bool) -> None:
    counts = summarize(results)
    for kind, name, result in results:
        if result.action in (nb.UNCHANGED,) and not verbose:
            continue
        line = f"{result.action:<14} {kind:<14} {name}"
        if result.action == nb.CONFLICT:
            line += f"  CONFLICT: {result.conflicts}"
        elif result.action == SKIPPED:
            line += f"  {result.changes['reason']}"
        elif result.changes and result.action in (nb.UPDATE, nb.CHECK_UPDATE, nb.CREATE, nb.CHECK_CREATE) and verbose:
            line += f"  ({result.changes})"
        print(line)
    print()
    print("Summary: " + ", ".join(f"{action}={count}" for action, count in sorted(counts.items())))
    if counts.get(SKIPPED):
        print(
            f"\nNote: {counts[SKIPPED]} object(s) could not be previewed because a prerequisite "
            "does not exist in NetBox yet. Run --apply once, then --check again for a complete picture.",
        )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true", help="Show the proposed reconciliation without changing NetBox")
    mode.add_argument("--apply", action="store_true", help="Create/update the expected objects in NetBox")
    parser.add_argument("--verbose", action="store_true", help="Also print UNCHANGED objects and change detail")
    parser.add_argument("--manifest", type=Path, default=MANIFEST_PATH, help="Path to the ipam.yml manifest")
    args = parser.parse_args(argv)

    try:
        manifest = load_manifest(args.manifest)
    except (OSError, yaml.YAMLError, ValueError, KeyError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    try:
        client = nb.build_client()
        nb.check_status(nb.load_config())
    except nb.NetboxError as exc:
        print(f"ERROR: NetBox is not reachable/usable: {exc}", file=sys.stderr)
        return 1

    populator = Populator(client, manifest, apply=args.apply)
    try:
        populator.run()
    except nb.NetboxError as exc:
        print(f"ERROR during reconciliation: {exc}", file=sys.stderr)
        return 1

    print_report(populator.results, verbose=args.verbose)
    conflicts = [r for _, _, r in populator.results if r.action == nb.CONFLICT]
    if conflicts:
        print(f"\n{len(conflicts)} CONFLICT(s) found -- nothing was overwritten for these objects.", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
