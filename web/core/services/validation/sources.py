"""Read-only source adapters + deterministic, secret-free fingerprints.

Every adapter returns a SourceResult and NEVER raises: an outage becomes an
``unavailable`` result with a fixed, sanitized message, and the engine turns
that into a SOURCE_* finding (never into a PASS).

    NetBox     -> core.services.nsot_netbox.project_facts (the existing
                  read-only client wrapper; no second client, no write)
    topology   -> the fixed runtime_metadata path named by
                  monitoring/config/topology.yml (read-only JSON file; no
                  subprocess, no containerlab)
    inventory  -> the fixed repository file inventory.yml, WHITELISTED keys
                  only (credentials/SNMP secrets are never read into a report)
    capability -> the SAME registries platform_drivers/renderer use
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

import yaml
from django.conf import settings

from .. import nsot_git, nsot_netbox, platform_drivers
from .findings import ENGINE_VERSION, sha256_of

NETBOX, TOPOLOGY, INVENTORY, CAPABILITY = "NETBOX", "TOPOLOGY", "INVENTORY", "CAPABILITY"
MAX_SOURCE_FILE_BYTES = 2 * 1024 * 1024

INVENTORY_PATH = Path(settings.REPO_ROOT) / "inventory.yml"
TOPOLOGY_CONFIG_PATH = Path(settings.REPO_ROOT) / "monitoring" / "config" / "topology.yml"

# inventory `monitoring.platform` -> Device Builder platform identifier
_INVENTORY_PLATFORMS = {"ceos": "arista_ceos", "linux": "ubuntu_frr"}
# topology node kind -> Device Builder platform identifier (routers only; hosts are plain linux)
_KIND_PLATFORMS = {"arista_ceos": "arista_ceos"}

_UNAVAILABLE_MESSAGES = {
    NETBOX: "NetBox is temporarily unavailable.",
    TOPOLOGY: "Topology metadata is unavailable.",
    INVENTORY: "Project inventory is unavailable.",
}


@dataclass
class SourceResult:
    name: str
    status: str  # "available" | "unavailable"
    data: dict | None = None
    message: str = ""
    fingerprint: str = "UNAVAILABLE"

    @property
    def available(self) -> bool:
        return self.status == "available"

    def provenance(self) -> dict:
        return {"source": self.name, "status": self.status, "fingerprint": self.fingerprint, "message": self.message}


def _unavailable(name: str) -> SourceResult:
    return SourceResult(name=name, status="unavailable", message=_UNAVAILABLE_MESSAGES[name])


@dataclass
class SourceBundle:
    netbox: SourceResult
    topology: SourceResult
    inventory: SourceResult
    capability: SourceResult
    repository_head: str = ""
    extra: dict = field(default_factory=dict)

    def all(self):
        return (self.netbox, self.topology, self.inventory, self.capability)

    def source_hash(self) -> str:
        """Staleness fingerprint: every consumed external source + engine version.

        Repository HEAD is provenance only and is deliberately excluded --
        an unrelated commit must not invalidate a validation."""
        return sha256_of({
            "engine": ENGINE_VERSION,
            "netbox": self.netbox.fingerprint,
            "topology": self.topology.fingerprint,
            "inventory": self.inventory.fingerprint,
            "capability": self.capability.fingerprint,
        })

    def provenance(self) -> dict:
        return {
            "engine_version": ENGINE_VERSION,
            "repository_head": self.repository_head,
            "sources": {item.name: item.provenance() for item in self.all()},
            "source_hash": self.source_hash(),
        }


# --- NetBox ---------------------------------------------------------------

def collect_netbox() -> SourceResult:
    try:
        envelope = nsot_netbox.project_facts()
    except Exception:  # noqa: BLE001 - adapter contract: never raise
        return _unavailable(NETBOX)
    if envelope.get("status") != "available" or not isinstance(envelope.get("data"), dict):
        return _unavailable(NETBOX)
    data = envelope["data"]
    return SourceResult(name=NETBOX, status="available", data=data, fingerprint=sha256_of(data))


# --- topology -------------------------------------------------------------

def _interface_name(kind: str, interface: str) -> str:
    """Topology `ethN` -> the cEOS `EthernetN` intent name (mirrors
    modules.topology._monitor_interface); Linux nodes keep `ethN`."""
    if kind == "arista_ceos" and interface.startswith("eth") and interface[3:].isdigit():
        return "Ethernet" + interface[3:]
    return interface


def _read_bounded_json(path: Path) -> dict:
    if not path.is_file() or path.stat().st_size > MAX_SOURCE_FILE_BYTES:
        raise ValueError("source file missing or too large")
    return json.loads(path.read_text())


def collect_topology() -> SourceResult:
    try:
        config = yaml.safe_load(TOPOLOGY_CONFIG_PATH.read_text())
        runtime_path = Path(str(config["runtime_metadata"]))
        raw = _read_bounded_json(runtime_path)
        nodes_raw, links_raw = raw["nodes"], raw["links"]
        if not isinstance(nodes_raw, dict) or not isinstance(links_raw, list):
            raise ValueError("unexpected topology schema")
        nodes = {
            name: {"kind": str(meta.get("kind", "")), "image": str(meta.get("image", ""))}
            for name, meta in nodes_raw.items()
        }
        links = []
        for link in links_raw:
            endpoints = link.get("endpoints")
            if not isinstance(endpoints, dict) or len(endpoints) != 2:
                raise ValueError("unexpected link schema")
            ends = []
            for key in sorted(endpoints):
                node, interface = endpoints[key].get("node"), endpoints[key].get("interface")
                if node not in nodes:  # host-side attachment (e.g. nmas-mgmt) is not a lab node
                    ends = []
                    break
                ends.append({
                    "device": node,
                    "interface": _interface_name(nodes[node]["kind"], str(interface)),
                    "raw_interface": str(interface),
                })
            if ends:
                ends.sort(key=lambda e: (e["device"], e["interface"]))
                links.append({"a": ends[0], "z": ends[1]})
        links.sort(key=lambda l: (l["a"]["device"], l["a"]["interface"], l["z"]["device"], l["z"]["interface"]))
        data = {"lab_name": str(raw.get("name", "")), "nodes": dict(sorted(nodes.items())), "links": links}
    except Exception:  # noqa: BLE001
        return _unavailable(TOPOLOGY)
    return SourceResult(name=TOPOLOGY, status="available", data=data, fingerprint=sha256_of(data))


# --- inventory ------------------------------------------------------------

_MANAGEMENT_KEYS = (
    "nmas_ipv4", "nmas_ipv6", "primary_dhcp_ipv4", "primary_dhcp_ipv6",
    "backup_dhcp_ipv4", "backup_dhcp_ipv6",
)


def _host_part(value) -> str:
    return str(value).split("/")[0] if value else ""


def collect_inventory() -> SourceResult:
    try:
        if not INVENTORY_PATH.is_file() or INVENTORY_PATH.stat().st_size > MAX_SOURCE_FILE_BYTES:
            raise ValueError("inventory missing or too large")
        raw = yaml.safe_load(INVENTORY_PATH.read_text())
        management = {key: _host_part((raw.get("management") or {}).get(key)) for key in _MANAGEMENT_KEYS}
        devices = {}
        for name, entry in sorted((raw.get("network_devices") or {}).items()):
            monitoring = (entry or {}).get("monitoring") or {}
            platform = _INVENTORY_PLATFORMS.get(str(monitoring.get("platform", "")), "")
            devices[str(name)] = {
                "platform": platform,
                "monitoring_address": _host_part(monitoring.get("address")) if monitoring.get("address") != "auto" else "",
                "monitoring_address_v6": _host_part(monitoring.get("address_v6")),
                "edge": bool((entry or {}).get("edge", False)),
            }
        hosts = sorted(str(name) for name in (raw.get("hosts") or {}))
        data = {"management": management, "network_devices": devices, "hosts": hosts}
    except Exception:  # noqa: BLE001
        return _unavailable(INVENTORY)
    return SourceResult(name=INVENTORY, status="available", data=data, fingerprint=sha256_of(data))


# --- capability registry (the same registries the renderer uses) -----------

def collect_capability() -> SourceResult:
    data = {
        "interfaces": {
            platform: {kind: cap.status.value for kind, cap in sorted(caps.items())}
            for platform, caps in sorted(platform_drivers.PLATFORM_CAPABILITIES.items())
        },
        "routing": {
            platform: {str(proto): cap.status.value for proto, cap in sorted(caps.items(), key=lambda kv: str(kv[0]))}
            for platform, caps in sorted(platform_drivers.ROUTING_CAPABILITIES.items())
        },
        "service_policy": {
            platform: {str(feature): cap.status.value for feature, cap in sorted(caps.items(), key=lambda kv: str(kv[0]))}
            for platform, caps in sorted(platform_drivers.SERVICE_POLICY_CAPABILITIES.items())
        },
    }
    return SourceResult(name=CAPABILITY, status="available", data=data, fingerprint=sha256_of(data))


def repository_head() -> str:
    """Provenance only (read-only git rev-parse through the existing adapter)."""
    try:
        state = nsot_git.get_repo_state()
    except Exception:  # noqa: BLE001
        return ""
    head = (state or {}).get("head_commit_full") or ""
    return str(head)[:64] if isinstance(head, str) else ""


def build_source_bundle() -> SourceBundle:
    """Collect every source once (all read-only)."""
    return SourceBundle(
        netbox=collect_netbox(),
        topology=collect_topology(),
        inventory=collect_inventory(),
        capability=collect_capability(),
        repository_head=repository_head(),
    )
