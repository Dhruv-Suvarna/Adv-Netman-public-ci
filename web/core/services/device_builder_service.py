"""
Service boundary for Device Builder.

Phase 9 graduates this out of the `not_integrated` placeholder list (the
same way monitoring_service did in Phase 6 and nsot_service did in Phase 7):
Device Identity plus Phase-10 interfaces, dual-stack addressing, and WAN
metadata are real, with browser-owned draft typing, Tier-1 field commit
validation, field-local rollback, and an authoritative Python candidate
renderer. Phase 11 adds structured routing intent (static routes, RIP,
OSPF, IS-IS, EIGRP, BGP) and Phase 12 completes the major catalogue with
FHRP, NAT, inherited services, ACL, and policy foundations on the same
contract.
"""

from __future__ import annotations

from . import change_service


def get_device_builder_summary() -> dict:
    changes = change_service.list_changes()
    return {
        "status": "operational",
        "message": (
            "Device Identity, modular interfaces, IPv4/IPv6 addressing, WAN "
            "metadata, structured routing, FHRP, NAT, inherited DHCP/DNS, "
            "ACL, and policy-foundation editing are live. Syntax acceptance "
            "is Tier-1 only; project/topology validation and deployment "
            "remain later phases."
        ),
        "total_changes": changes.count(),
        "recent_changes": list(changes[:5]),
    }
