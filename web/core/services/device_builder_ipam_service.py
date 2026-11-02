"""Explicit, read-only NetBox prefix lookup for Phase-10 AUTO intent.

This module is deliberately separate from normal rendering/field commits.
It is called only by the explicit "Refresh prefixes" endpoint.  It reuses
the repository's existing NetBox client/helper and performs no allocation,
suggestion, reservation, create, update, or delete operation.
"""

from __future__ import annotations

import ipaddress
import sys

from django.conf import settings

if str(settings.REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(settings.REPO_ROOT))

from modules import netbox_ipam  # noqa: E402

from . import interface_intent_service


class IpamLookupError(RuntimeError):
    pass


def list_prefixes_for_address(*, revision, interface_id: str, address_id: str) -> list[str]:
    address = interface_intent_service.get_address(revision, interface_id, address_id)
    if address.get("source") != "AUTO":
        raise interface_intent_service.CollectionMutationError(
            "Prefix lookup is available only for an AUTO address object."
        )
    family = 4 if address.get("family") == "IPV4" else 6
    # Existing helper: one read-only endpoint enumeration.  No local/free-IP
    # algorithm is introduced in Phase 10.
    try:
        prefixes = netbox_ipam.list_all_prefix_cidrs()
    except netbox_ipam.NetboxError as exc:
        raise IpamLookupError("NetBox prefix data is currently unavailable.") from exc
    try:
        parsed = [ipaddress.ip_network(prefix, strict=True) for prefix in prefixes]
    except (TypeError, ValueError) as exc:
        # Never expose a raw library/API exception (which may contain
        # endpoint or payload details) to the browser.
        raise IpamLookupError("NetBox prefix data is currently unavailable.") from exc
    return [
        str(prefix)
        for prefix in sorted(
            (prefix for prefix in parsed if prefix.version == family),
            key=lambda prefix: (prefix.version, int(prefix.network_address), prefix.prefixlen),
        )
    ]
