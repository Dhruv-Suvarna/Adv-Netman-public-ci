"""The managed-device list and health targets -- from ``inventory.yml`` and the provisioning registry, never from the browser.

A device name that is neither a key of ``network_devices`` nor a live provisioning-registry entry is not a managed device: it can never be probed, never gets
a Deep Health run, and is a 404 in the UI.  Credentials are not read here; the cEOS live adapter reuses the Phase-7
``nsot_live.get_live_target`` for that, and the Linux adapter needs none (``docker exec``, see ``live.py``).
"""

from __future__ import annotations

from pathlib import Path

import yaml
from django.conf import settings

# inventory monitoring.platform / Device Builder Platform value -> the health platform key
HEALTH_PLATFORM = {
    "ceos": "ceos", "arista_ceos": "ceos",
    "linux": "linux", "ubuntu_frr": "linux",
    "nokia_srlinux": "nokia_srlinux", "cisco_c8000v_iosxe": "cisco_c8000v_iosxe", "cisco_iosxr": "cisco_iosxr", "sonic": "sonic",
}


def load_inventory() -> dict:
    with open(Path(settings.REPO_ROOT) / "inventory.yml", encoding="utf-8") as handle:
        return yaml.safe_load(handle) or {}


def health_platform(platform: str | None) -> str:
    return HEALTH_PLATFORM.get(str(platform or ""), str(platform or "unknown"))


def inventory_devices(document: dict | None = None) -> dict:
    """{name: {"name", "platform", "address", "address_v6", "container"}} for every ``inventory.yml`` network device (the tracked file only).

    ``document`` lets one caller reuse an already loaded inventory (the shared resolver); omitted, the tracked file is read."""
    inventory = load_inventory() if document is None else document
    lab = inventory.get("lab_name", "")
    devices = {}
    for name, entry in sorted((inventory.get("network_devices") or {}).items()):
        monitoring = (entry or {}).get("monitoring") or {}
        devices[name] = {
            "name": name,
            "platform": health_platform(monitoring.get("platform")),
            "address": monitoring.get("address") if monitoring.get("address") != "auto" else "",
            "address_v6": monitoring.get("address_v6") or "",
            "container": f"clab-{lab}-{name}" if lab else "",
        }
    return devices


def provisioned_devices() -> dict:
    """Devices a provisioning run admitted (V2 Phase 5A registry).  Fail closed: an unreadable registry admits nothing, and it can never
    break resolution of the tracked inventory."""
    try:
        from ..provisioning import registry

        return registry.devices()
    except Exception:  # noqa: BLE001 - no table yet, no database access in this context, ...: no provisioned device is resolvable
        return {}


def managed_devices() -> dict:
    """Every device NMAS manages: the tracked inventory, plus the devices a provisioning run admitted.

    ``inventory.yml`` always wins on a name -- the registry can only ADD a device, never redefine or hide a production one.
    Resolved by the shared managed-device resolver (``core.services.devices.resolver.engine_devices``), whose engine view is
    exactly this dictionary; registered devices that are not reachable yet are never part of it.
    """
    from ..devices import resolver

    return resolver.engine_devices()


def get_managed_device(name: str) -> dict | None:
    return managed_devices().get(str(name))


def dhcp_hosts() -> dict:
    """{"primary": address, "secondary": address, "secondary_device": name|None} from ``management`` (no name patterns)."""
    management = load_inventory().get("management") or {}
    secondary = management.get("backup_dhcp_ipv4")
    device = next((n for n, d in managed_devices().items() if secondary and d["address"] == secondary), None)
    return {"primary": management.get("primary_dhcp_ipv4"), "secondary": secondary, "secondary_device": device}
