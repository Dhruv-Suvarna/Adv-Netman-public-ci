"""Management VRF validation (V2 Phase 4): structure, platform renderability, execution capability and the management-cut
guard.  Pure: reads the accepted snapshot and the fixed inventory source only."""

from __future__ import annotations

import ipaddress

from ..management import vrf as management_vrf
from .findings import Code

_STRUCTURAL = {
    "MGMT_VRF_PLATFORM_UNSUPPORTED": Code.MGMT_VRF_PLATFORM_UNSUPPORTED,
    "MGMT_VRF_REFERENCE_INVALID": Code.MGMT_VRF_REFERENCE_INVALID,
    "MGMT_INTERFACE_REFERENCE_INVALID": Code.MGMT_INTERFACE_REFERENCE_INVALID,
    "MGMT_BINDING_INVALID": Code.MGMT_BINDING_INVALID,
    "MGMT_BINDING_NO_ADDRESS": Code.MGMT_BINDING_NO_ADDRESS,
    "MGMT_VRF_UNBOUND": Code.MGMT_VRF_UNBOUND,
    "MGMT_VRF_NO_ACCESS_SERVICE": Code.MGMT_VRF_NO_ACCESS_SERVICE,
    "MGMT_ROUTE_NEXT_HOP_UNREACHABLE": Code.MGMT_ROUTE_NEXT_HOP_UNREACHABLE,
}
EXECUTABLE_PLATFORMS = frozenset({"arista_ceos"})


def _management_addresses(ctx, device: str) -> set:
    inventory = ctx.inventory or {}
    entry = (inventory.get("network_devices") or {}).get(device) or {}
    found = set()
    for key in ("monitoring_address", "monitoring_address_v6"):
        try:
            if entry.get(key):
                found.add(ipaddress.ip_address(str(entry[key])))
        except ValueError:
            continue
    return found


def validate_management_vrf(ctx) -> None:
    for name in sorted(ctx.model.devices):
        device = ctx.model.devices[name]
        management = device.management
        if not management_vrf.present(management):
            continue
        interfaces = list(device.interfaces.values())
        for problem in management_vrf.problems(device.platform, management, interfaces):
            ctx.add(_STRUCTURAL[problem["code"]], f"{name}: {problem['message']}", device=name, object_type="management_vrf",
                    object_id=problem["object_id"] or None, remediation="Correct the management VRF intent in the Device Builder.")
        by_id = {row.get("id"): row for row in interfaces}
        if device.platform == "sonic":
            unsupported: list = []
            management_vrf.sonic_config_db(management, unsupported)
        else:
            rendered = []
            for part in ("definitions", "routes", "services"):
                rendered += management_vrf.render(device.platform, part, management, by_id)
            for interface in interfaces:
                rendered += management_vrf.render(device.platform, "binding", management, by_id, interface)
            unsupported = [d["text"] for d in rendered if str(d.get("text", "")).startswith(management_vrf.UNSUPPORTED)]
        for text in unsupported:
            ctx.add(Code.MGMT_VRF_FEATURE_UNSUPPORTED, f"{name}: {text.lstrip('!/ ')}"[:300], device=name, object_type="management_vrf",
                    remediation="Remove the object or use a platform whose renderer expresses it.")
        if device.platform not in EXECUTABLE_PLATFORMS and (device.platform in management_vrf.RENDERERS or device.platform == "sonic"):
            ctx.add(Code.MGMT_VRF_EXECUTION_NOT_IMPLEMENTED,
                    f"{name}: management VRF objects render for {device.platform} but no executor applies them.", device=name,
                    object_type="management_vrf", remediation="Plan and review only; apply through a platform with an executor.")
        current = _management_addresses(ctx, name)
        for binding in (management.get("bindings") or {}).values():
            interface = by_id.get(binding.get("interface_id")) or {}
            for address in (interface.get("addresses") or {}).values():
                try:
                    ip = ipaddress.ip_interface(str(address.get("cidr") or "")).ip
                except ValueError:
                    continue
                if ip in current:
                    ctx.add(Code.MGMT_VRF_MOVES_MANAGEMENT_ADDRESS,
                            f"{name}: binding {interface.get('name')} into the VRF moves the device's management address {ip}.",
                            device=name, object_type="management_vrf", object_id=binding.get("id"),
                            remediation="Bring the VRF up on a separate interface first, register and verify a ROUTED_VRF management "
                                        "path, then move the address in a later Change.")
