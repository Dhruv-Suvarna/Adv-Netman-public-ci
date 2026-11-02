"""DHCP providers behind one contract (``base.DhcpProvider``).  ``for_network`` builds the network's provider with the
validation / status commands of the isolated deployment (Django settings ``NMAS_ZTP_DHCP_COMMANDS``; none by default, in
which case nothing can be applied -- validation is never skipped)."""

from __future__ import annotations

from django.conf import settings

from .base import ApplyResult, BootstrapPolicy, DhcpProvider, ProviderError, Reservation  # noqa: F401 - re-exported contract
from .isc import IscDhcpProvider
from .kea import KeaDhcp4Provider

PROVIDERS = {"ISC_DHCP": IscDhcpProvider, "KEA": KeaDhcp4Provider}


def for_network(network, *, runner=None) -> DhcpProvider:
    cls = PROVIDERS.get(network.provider)
    if cls is None:
        raise ProviderError("DHCP_PROVIDER_UNSUPPORTED", "unknown provider")
    commands = (getattr(settings, "NMAS_ZTP_DHCP_COMMANDS", {}) or {}).get(network.provider, {})
    kwargs = {"validate_command": commands.get("validate"), "status_command": commands.get("status")}
    if runner is not None:
        kwargs["runner"] = runner
    return cls(network.config_root, **kwargs)
