"""The probe-target guard.

NMAS contacts a management endpoint only when it is the endpoint of a REGISTERED, APPROVED, non-revoked ManagementPath of
a live managed device, bound to an APPROVED NMAS attachment.  A user-supplied address is never probed: callers pass a path
object, and the guard re-reads it from the database so a modified in-memory instance cannot redirect the probe.

The address itself must also be a plausible management target: never loopback, link-local, multicast, unspecified,
reserved or a Containerlab management address (those would be the hidden Containerlab / Docker management plane).  Layer-2
paths must sit inside their NMAS attachment's prefix.  ``NMAS_MGMT_ALLOW_LOOPBACK_TARGETS`` exists for the automated test
SSH server on 127.0.0.1 only; it is False everywhere else and never set by any runtime file.
"""

from __future__ import annotations

import ipaddress

from django.conf import settings
from yaml import YAMLError

from ... import models
from ..devices import codes, resolver


def _forbidden_networks():
    try:
        return resolver.forbidden_networks()
    except (OSError, ValueError, TypeError, AttributeError, YAMLError):
        # An unreadable or malformed topology still leaves Containerlab's default networks forbidden.
        return tuple(ipaddress.ip_network(value) for value in resolver.CONTAINERLAB_DEFAULT_MGMT)


def address_problems(address: str, *, network: str = "", layer2: bool = False) -> list[dict]:
    """Refusals for ``address`` as a management target (empty = acceptable)."""
    try:
        ip = ipaddress.ip_address(str(address))
    except ValueError:
        return [codes.blocker("MGMT_ENDPOINT_FORBIDDEN", reason="not an IP address")]
    allow_loopback = bool(getattr(settings, "NMAS_MGMT_ALLOW_LOOPBACK_TARGETS", False))
    if ip.is_loopback and not allow_loopback:
        return [codes.blocker("MGMT_ENDPOINT_FORBIDDEN", reason="loopback")]
    for label, flag in (("link-local", ip.is_link_local), ("multicast", ip.is_multicast), ("unspecified", ip.is_unspecified),
                        ("reserved", ip.is_reserved and not ip.is_loopback)):
        if flag:
            return [codes.blocker("MGMT_ENDPOINT_FORBIDDEN", reason=label)]
    if isinstance(ip, ipaddress.IPv4Address) and (ip.packed[0] == 0 or ip == ipaddress.IPv4Address("255.255.255.255")):
        return [codes.blocker("MGMT_ENDPOINT_FORBIDDEN", reason="reserved")]
    for forbidden in _forbidden_networks():
        if ip.version == forbidden.version and ip in forbidden:
            return [codes.blocker("MGMT_ENDPOINT_FORBIDDEN", reason="Containerlab management network")]
    if layer2 and network and not (ip.is_loopback and allow_loopback):
        try:
            prefix = ipaddress.ip_network(network, strict=False)
        except ValueError:
            return [codes.blocker("MGMT_ENDPOINT_OUTSIDE_NETWORK", network="invalid")]
        if ip.version != prefix.version or ip not in prefix:
            return [codes.blocker("MGMT_ENDPOINT_OUTSIDE_NETWORK", network=str(prefix))]
        if ip in (prefix.network_address, prefix.broadcast_address) and prefix.prefixlen < (31 if ip.version == 4 else 127):
            return [codes.blocker("MGMT_ENDPOINT_FORBIDDEN", reason="network / broadcast address")]
    return []


def authorized_target(path) -> tuple[models.ManagementPath | None, list[dict]]:
    """-> (the path as persisted, refusals).  The ONLY way a probe obtains an address to contact."""
    if not isinstance(path, models.ManagementPath) or not path.pk:
        return None, [codes.blocker("PROBE_TARGET_FORBIDDEN", reason="not a registered path")]
    stored = (models.ManagementPath.objects.select_related("device", "nmas_attachment", "attachment")
              .filter(pk=path.pk).first())
    if stored is None:
        return None, [codes.blocker("PROBE_TARGET_FORBIDDEN", reason="not a registered path")]
    if stored.approval_state != models.ManagementApproval.APPROVED:
        return None, [codes.blocker("PROBE_TARGET_FORBIDDEN", reason=f"path {stored.approval_state.lower()}")]
    if stored.device.is_terminal:
        return None, [codes.blocker("PROBE_TARGET_FORBIDDEN", reason="device retired")]
    if stored.nmas_attachment.approval_state != models.ManagementApproval.APPROVED:
        return None, [codes.blocker("NMAS_ATTACHMENT_NOT_APPROVED")]
    for field in ("endpoint_address", "port", "nmas_attachment_id"):
        if getattr(stored, field) != getattr(path, field):
            return None, [codes.blocker("PROBE_TARGET_FORBIDDEN", reason="in-memory path differs from the registered path")]
    if stored.path_type == models.ManagementPathType.ROUTED_VRF and (
            stored.nmas_attachment.upstream_device != stored.device.name or stored.attachment_id or
            (stored.via_device and stored.via_device != stored.device.name)):
        return None, [codes.blocker("L1_TOPOLOGY_UNVERIFIED", reason="routed path has no verified direct NMAS neighbor")]
    # Routed VRF paths currently require an on-link NMAS/device pair, so the
    # endpoint must also belong to this attachment's prefix.
    problems = address_problems(stored.endpoint_address, network=stored.nmas_attachment.network, layer2=True)
    if problems:
        return None, problems
    return stored, []
