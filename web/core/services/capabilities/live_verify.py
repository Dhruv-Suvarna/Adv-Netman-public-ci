"""Explicit, reversible live verification for the low-risk loopback capability.

This is never called by a page load or a static verification.  It uses the
registered executor and its own read-back/compensation contract, refuses all
devices except the two managed test targets, and always attempts restoration.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..execution.executors.base import APPLY, ConfigletSpec
from ..execution.executors.registry import executor_for
from ..health import inventory, live


TARGETS = {
    "arista_ceos": ("R1", "Loopback444", "198.18.44.1/32"),
    # The name intentionally uses the parser's canonical loopback prefix, so
    # live read and subsequent config import agree on the semantic kind.
    "ubuntu_frr": ("R3", "loopback44", "198.18.44.3/32"),
}


@dataclass(frozen=True)
class LiveVerification:
    platform: str
    device: str
    interface: str
    address: str
    write_verified: bool
    post_write_verified: bool
    compensation_verified: bool
    restored: bool
    detail: str


def _specs(platform: str, device: str, name: str, address: str) -> tuple[ConfigletSpec, ConfigletSpec]:
    if platform == "arista_ceos":
        interface_lines = (f"interface {name}", "   description NMAS_PHASE4_REVERSIBLE_TEST", "   no shutdown")
        address_lines = (f"interface {name}", f"   ip address {address}")
    else:
        interface_lines = (
            f"ip link show dev {name} >/dev/null 2>&1 || ip link add {name} type dummy",
            f"ip link set dev {name} mtu 1500", f"ip link set dev {name} up",
        )
        address_lines = (f"ip addr replace {address} dev {name}",)
    interface = ConfigletSpec(
        cfg_id="P4-LB-IF", sequence=1, device=device, platform=platform, object_type="interface",
        operation="CREATE_DEFINE", lines=interface_lines, expected={"interface": name, "admin_enabled": True},
    )
    address_spec = ConfigletSpec(
        cfg_id="P4-LB-IP", sequence=2, device=device, platform=platform, object_type="address",
        operation="CREATE_DEFINE", lines=address_lines, expected={"interface": name, "address": address, "family": 4},
    )
    return interface, address_spec


def verify_loopback(platform: str, *, device_name: str = "") -> LiveVerification:
    if platform not in TARGETS:
        raise ValueError("Live Phase-4 verification is limited to arista_ceos and ubuntu_frr loopbacks.")
    expected_device, name, address = TARGETS[platform]
    device_name = device_name or expected_device
    if device_name != expected_device:
        raise ValueError(f"{platform} live verification is restricted to managed target {expected_device}.")
    device = inventory.get_managed_device(device_name)
    if not device or device.get("platform") != ("ceos" if platform == "arista_ceos" else "linux"):
        raise ValueError("Managed target inventory does not match the requested platform.")

    executor = executor_for(device)
    interface, address_spec = _specs(platform, device_name, name, address)
    applied: list[tuple[ConfigletSpec, object]] = []
    post_write = compensation = restored = False
    try:
        executor.connect()
        initial = live.read_device(device)
        if not initial.live_reachable or name in (initial.facts("interfaces") or {}):
            raise RuntimeError("Temporary loopback is not safely absent before the run.")
        for spec in (interface, address_spec):
            assessment = executor.assess(spec)
            if assessment.action != APPLY or not assessment.restorable:
                raise RuntimeError(f"{spec.cfg_id} is not an additive, compensable change.")
            # Register the inverse before the first mutating command.  An
            # executor may report a rejected operation after an earlier line
            # was accepted, so even a failed apply must enter restoration.
            applied.append((spec, assessment))
            outcome = executor.apply(spec, assessment)
            if not outcome.ok:
                raise RuntimeError(f"{spec.cfg_id} apply failed with {outcome.error_code or 'UNKNOWN'}.")
        observed = live.read_device(device)
        post_write = observed.live_reachable and name in (observed.facts("interfaces") or {}) \
            and address in (observed.facts("addresses") or {}).get(name, [])
        if not post_write:
            raise RuntimeError("Live read-back did not contain the temporary loopback and address.")
    finally:
        outcomes = []
        for spec, assessment in reversed(applied):
            outcomes.append(executor.compensate(spec, assessment).status)
        compensation = bool(applied) and all(status == "COMPENSATED" for status in outcomes)
        try:
            final = live.read_device(device)
            restored = final.live_reachable and name not in (final.facts("interfaces") or {}) \
                and not (final.facts("addresses") or {}).get(name)
        finally:
            executor.close()
    if not (post_write and compensation and restored):
        raise RuntimeError("Live verification did not prove post-write state and restoration.")
    return LiveVerification(
        platform=platform, device=device_name, interface=name, address=address, write_verified=True,
        post_write_verified=True, compensation_verified=True, restored=True,
        detail=f"{device_name}: created/read back/removed {name} {address}; final read proved absence.",
    )
