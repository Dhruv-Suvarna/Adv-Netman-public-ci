"""The five collectors.  Each one runs for the whole application lifetime, whichever view is visible."""

from .automation import AutomationCollector
from .connectivity import ConnectivityCollector
from .counters import InterfaceCounterCollector
from .nsot import NsotCollector
from .services import ServiceTelemetryCollector


def build_default(config, store, bus) -> list:
    """The production collector set, wired to the live read-only adapters."""
    nsot = NsotCollector(config, store, bus)
    return [
        ConnectivityCollector(config, store, bus),
        ServiceTelemetryCollector(config, store, bus, netbox_target=nsot.health_target),
        nsot,
        AutomationCollector(config, store, bus),
        InterfaceCounterCollector(config, store, bus),
    ]


__all__ = ["AutomationCollector", "ConnectivityCollector", "InterfaceCounterCollector", "NsotCollector", "ServiceTelemetryCollector",
           "build_default"]
