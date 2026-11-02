"""The native-ZTP adapter registry: platform -> adapter.  Lifecycle code asks here and never imports a vendor module directly."""

from __future__ import annotations

from .arista_eos import AristaEosAdapter
from .base import EVIDENCE_CLASSES, NativeZtpAdapter  # noqa: F401 - re-exported contract
from .cisco_iosxe import CiscoIosXeAdapter
from .others import ADAPTER_CLASSES

ADAPTERS: dict[str, NativeZtpAdapter] = {cls.capability.adapter: cls() for cls in (AristaEosAdapter, CiscoIosXeAdapter, *ADAPTER_CLASSES)}
BY_PLATFORM: dict[str, str] = {a.capability.platform: key for key, a in ADAPTERS.items() if a.capability.platform}


def get(adapter_key: str) -> NativeZtpAdapter | None:
    return ADAPTERS.get(str(adapter_key or ""))


def for_platform(platform: str) -> NativeZtpAdapter | None:
    """The adapter of a catalogue platform (None when the platform has no adapter at all)."""
    return ADAPTERS.get(BY_PLATFORM.get(str(platform or ""), ""))


def capability_report() -> list[dict]:
    """Every adapter's capability, retry, recovery, ZTP-disable and transport facts (read-only, no device contact)."""
    return [adapter.describe() for adapter in ADAPTERS.values()]
