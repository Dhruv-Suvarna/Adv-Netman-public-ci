"""Parsed project model + shared validation context.

Built ONCE from the accepted snapshot and the source bundle; every validator
reads it and appends findings/derived facts.  Nothing here writes anywhere.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field

from .. import interface_intent_service
from .findings import Finding

_VLAN_NAME_RE = re.compile(r"^vlan(\d+)$", re.IGNORECASE)
SHARED_NETBOX_ROLES = frozenset({"vrrp", "hsrp", "glbp", "carp", "anycast"})
PHYSICAL_KINDS = ("ROUTED_PHYSICAL", "ACCESS", "TRUNK")


def norm_name(value) -> str:
    return str(value or "").strip().lower()


def vlan_context(interface: dict):
    """The VLAN an interface is bound to (SVI id / subinterface tag / VlanNN name)."""
    for key in ("vlan_id", "encapsulation_vlan"):
        if isinstance(interface.get(key), int):
            return interface[key]
    match = _VLAN_NAME_RE.match(str(interface.get("name") or ""))
    return int(match.group(1)) if match else None


def is_management_interface(interface: dict) -> bool:
    return interface_intent_service.is_management_static(interface)


@dataclass
class AddressRecord:
    device: str
    interface_id: str
    interface_name: str
    interface_kind: str
    address_id: str
    iface: ipaddress.IPv4Interface | ipaddress.IPv6Interface
    source: str  # MANUAL | DERIVED
    role: str = ""

    @property
    def ip(self):
        return self.iface.ip

    @property
    def network(self):
        return self.iface.network

    @property
    def family(self) -> int:
        return self.iface.version

    @property
    def object_key(self) -> str:
        return f"{self.device}:{self.interface_name}:{self.address_id}"


@dataclass
class DeviceModel:
    name: str
    platform: str
    target_type: str
    entry: dict

    @property
    def interfaces(self) -> dict:
        return self.entry.get("interfaces") or {}

    @property
    def routing(self) -> dict:
        return self.entry.get("routing") or {}

    @property
    def fhrp_instances(self) -> dict:
        return (self.entry.get("fhrp") or {}).get("instances") or {}

    @property
    def nat(self) -> dict:
        return self.entry.get("nat") or {}

    @property
    def dhcp(self) -> dict:
        return ((self.entry.get("services") or {}).get("dhcp")) or {}

    @property
    def dns(self) -> dict:
        return ((self.entry.get("services") or {}).get("dns")) or {}

    @property
    def acls(self) -> dict:
        return (self.entry.get("security") or {}).get("acls") or {}

    @property
    def acl_attachments(self) -> dict:
        return (self.entry.get("security") or {}).get("attachments") or {}

    @property
    def pbr(self) -> dict:
        return ((self.entry.get("policy") or {}).get("pbr")) or {}

    @property
    def management(self) -> dict:
        """V2 Phase 4 management VRF intent ({} when the device has none)."""
        return self.entry.get("management") or {}

    def interface_by_name(self, name: str):
        wanted = norm_name(name)
        for interface in self.interfaces.values():
            if norm_name(interface.get("name")) == wanted:
                return interface
        return None

    def ordered(self, mapping: dict) -> list[dict]:
        return sorted(mapping.values(), key=lambda row: (str(row.get("name") or ""), row.get("id", "")))


class ProjectModel:
    def __init__(self, snapshot: dict):
        self.snapshot = snapshot
        self.devices: dict[str, DeviceModel] = {
            entry["device_name"]: DeviceModel(entry["device_name"], entry["platform"], entry["target_type"], entry)
            for entry in snapshot["devices"]
        }
        self.addresses: list[AddressRecord] = []
        self.invalid_addresses: list[dict] = []
        self.auto_addresses: list[dict] = []
        self._parse_addresses()

    # -- construction -----------------------------------------------------
    def _parse_addresses(self) -> None:
        for name in sorted(self.devices):
            device = self.devices[name]
            for interface in sorted(device.interfaces.values(), key=lambda i: (str(i.get("name") or ""), i.get("id", ""))):
                for address in sorted((interface.get("addresses") or {}).values(), key=lambda a: a.get("id", "")):
                    if address.get("source") == "AUTO":
                        self.auto_addresses.append({
                            "device": name, "interface": interface, "address": address,
                        })
                        continue
                    cidr = address.get("cidr") or ""
                    if not cidr:
                        continue  # an empty MANUAL slot is a Tier-1 concern, not an address
                    try:
                        iface = ipaddress.ip_interface(cidr)
                    except ValueError:
                        self.invalid_addresses.append({"device": name, "interface": interface, "address": address, "reason": "unparseable"})
                        continue
                    declared = address.get("family")
                    if declared in ("IPV4", "IPV6") and (4 if declared == "IPV4" else 6) != iface.version:
                        self.invalid_addresses.append({"device": name, "interface": interface, "address": address, "reason": "family"})
                        continue
                    self.addresses.append(AddressRecord(
                        device=name, interface_id=interface["id"], interface_name=str(interface.get("name") or ""),
                        interface_kind=str(interface.get("kind") or ""), address_id=address["id"], iface=iface,
                        source="MANUAL", role=str(address.get("role") or ""),
                    ))

    # -- queries ----------------------------------------------------------
    def add_derived(self, record: AddressRecord) -> None:
        self.addresses.append(record)

    def addresses_of(self, device: str, interface_id: str) -> list[AddressRecord]:
        return [a for a in self.addresses if a.device == device and a.interface_id == interface_id]

    def owners_of_ip(self, ip) -> list[AddressRecord]:
        return [a for a in self.addresses if a.ip == ip]

    def device_addresses(self, device: str) -> list[AddressRecord]:
        return [a for a in self.addresses if a.device == device]

    def find_interface(self, device: str, interface_id: str):
        model = self.devices.get(device)
        return (model.interfaces.get(interface_id) if model else None)

    def interface_label(self, device: str, interface_id: str) -> str:
        interface = self.find_interface(device, interface_id)
        return str((interface or {}).get("name") or interface_id or "?")

    def has_any_interface(self) -> bool:
        return any(device.interfaces for device in self.devices.values())


@dataclass
class ValidationContext:
    snapshot: dict
    model: ProjectModel
    sources: object  # SourceBundle
    findings: list = field(default_factory=list)
    derived: list = field(default_factory=list)
    notes: list = field(default_factory=list)
    checked: dict = field(default_factory=dict)
    graph: dict = field(default_factory=dict)
    cache: dict = field(default_factory=dict)

    # -- output -----------------------------------------------------------
    def add(self, code: str, message: str, **kwargs) -> Finding:
        finding = Finding(code=code, message=message, **kwargs)
        self.findings.append(finding)
        return finding

    def derive(self, fact_type: str, **fields) -> dict:
        fact = {"type": fact_type, **fields}
        self.derived.append(fact)
        return fact

    # -- source views -----------------------------------------------------
    @property
    def netbox(self):
        result = self.sources.netbox
        return result.data if result.available else None

    @property
    def topology(self):
        result = self.sources.topology
        return result.data if result.available else None

    @property
    def inventory(self):
        result = self.sources.inventory
        return result.data if result.available else None

    def netbox_records_for_ip(self, ip) -> list[dict]:
        if self.netbox is None:
            return []
        text = str(ip)
        return [row for row in self.netbox["ip_addresses"] if row["ip"] == text]

    def netbox_addresses_of(self, device: str, interface_name: str) -> list[dict]:
        if self.netbox is None:
            return []
        return [
            row for row in self.netbox["ip_addresses"]
            if row["device"] == device and norm_name(row["interface"]) == norm_name(interface_name)
        ]

    def known_service_addresses(self) -> dict:
        """address text -> human label for project-known service endpoints."""
        known: dict[str, str] = {}
        inventory = self.inventory
        if inventory:
            for key, value in sorted(inventory["management"].items()):
                if value:
                    known[value] = f"inventory.management.{key}"
            for name, device in sorted(inventory["network_devices"].items()):
                for key in ("monitoring_address", "monitoring_address_v6"):
                    if device.get(key):
                        known.setdefault(device[key], f"inventory.{name}.{key}")
        if self.netbox:
            for prefix in self.netbox["prefixes"]:
                for target in prefix["relay_targets"]:
                    known.setdefault(target, "netbox.dhcp_relay_targets")
        for record in self.model.addresses:
            known.setdefault(str(record.ip), f"candidate {record.device}:{record.interface_name}")
        return known
