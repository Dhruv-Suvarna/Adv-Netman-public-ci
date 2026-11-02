"""Platform -> executor factory.  The ONLY place a platform name selects an implementation (never a hostname)."""

from __future__ import annotations

from types import MappingProxyType

from ...health import inventory
from .base import DeviceExecutor, ExecutorError
from .ceos import CeosExecutor
from .iosxe import IosXeExecutor
from .linux import LinuxExecutor
from .srlinux import SrLinuxExecutor

# health platform key (inventory.health_platform) -> executor class.  IOS XR / SONiC: deliberately absent.
EXECUTORS = MappingProxyType({"ceos": CeosExecutor, "linux": LinuxExecutor, "nokia_srlinux": SrLinuxExecutor,
                              "cisco_c8000v_iosxe": IosXeExecutor})


def executor_for(device: dict) -> DeviceExecutor:
    """A fresh executor for one inventory device dict; ``ExecutorError('UNSUPPORTED')`` when the platform has none."""
    cls = EXECUTORS.get(inventory.health_platform(device.get("platform")))
    if cls is None:
        raise ExecutorError("UNSUPPORTED")
    return cls(device)
