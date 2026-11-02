"""The tracked lab inventory, read once per call: which endpoints are probed, which devices are managed.

``inventory.yml`` is the same source the website's traffic endpoint catalogue and health engine use (``hosts`` and
``network_devices``); nothing here is a second inventory.  A device is treated as managed when it has a management-VLAN monitoring
address -- the tracked rule ("each managed device has a dedicated mgmt_swt link"); R5 (``address: auto``, ``edge``) is not.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import yaml

from ..models import V4, V6, ProbeSpec

PLATFORMS = {"ceos": "ceos", "arista_ceos": "ceos", "linux": "linux", "ubuntu_frr": "linux"}


@dataclass(frozen=True)
class Endpoint:
    name: str
    container: str
    families: tuple[str, ...]


@dataclass(frozen=True)
class ManagedDevice:
    name: str
    container: str
    platform: str                 # "ceos" / "linux"
    address: str = ""
    address_v6: str = ""


def load(path: Path) -> dict:
    with open(path, encoding="utf-8") as handle:
        return yaml.safe_load(handle) or {}


def endpoints(document: dict) -> list[Endpoint]:
    """The probed endpoints and the address families the lab design gives each (H4 is IPv6-only by design)."""
    lab = str(document.get("lab_name") or "")
    found = []
    for name, flags in sorted((document.get("hosts") or {}).items()):
        flags = flags or {}
        families = tuple(f for f, on in ((V4, flags.get("ipv4", True)), (V6, flags.get("ipv6", True))) if on)
        found.append(Endpoint(str(name), f"clab-{lab}-{name}", families))
    return found


def probe_plan(found: list[Endpoint]) -> list[ProbeSpec]:
    """One required row per endpoint and supported family.  Each endpoint probes the NEXT endpoint that has the family (a ring),
    so every row crosses the switched / routed fabric and no row exists for a family an endpoint does not have (no H4 IPv4)."""
    plan = []
    for family in (V4, V6):
        ring = [e for e in found if family in e.families]
        for index, endpoint in enumerate(ring):
            if len(ring) < 2:
                continue
            plan.append(ProbeSpec(endpoint.name, family, ring[(index + 1) % len(ring)].name))
    return sorted(plan, key=lambda spec: (spec.source, spec.family))


def managed_devices(document: dict) -> list[ManagedDevice]:
    lab = str(document.get("lab_name") or "")
    found = []
    for name, entry in sorted((document.get("network_devices") or {}).items()):
        monitoring = (entry or {}).get("monitoring") or {}
        address = monitoring.get("address")
        platform = PLATFORMS.get(str(monitoring.get("platform") or ""))
        if (entry or {}).get("edge") or not address or address == "auto" or platform is None:
            continue
        found.append(ManagedDevice(str(name), f"clab-{lab}-{name}", platform, str(address), str(monitoring.get("address_v6") or "")))
    return found


def network_device_names(document: dict) -> list[str]:
    return sorted(str(name) for name in (document.get("network_devices") or {}))
