"""Shared fixtures for the V2 Lifecycle Phase 2 tests (NMAS database only; the tracked inventory is read, never written)."""

from __future__ import annotations

from datetime import timedelta

from django.utils import timezone

from core import models
from core.services.devices import attachments, authorization, lifecycle

OPERATOR, APPROVER, OTHER = "olivia", "arthur", "oscar"
SERIAL, MAC = "SN-NEW1", "00:1c:73:00:00:01"
HOST_KEY = "SHA256:" + "A" * 43
SCOPE = ["BOOTSTRAP_FETCH", "DHCP_DISCOVERY"]


def adopt(name="S1", role="switch", actor=APPROVER):
    return lifecycle.adopt_existing(name, role=role, actor=actor)


def register(name="NEW1", *, serial=SERIAL, mac=MAC, platform=models.Platform.ARISTA_CEOS, actor=OPERATOR):
    return lifecycle.register_device(name=name, platform=platform, role="router", actor=actor, expected_serial=serial,
                                     expected_base_mac=mac)


def attach(device, *, upstream="S1", port="Ethernet7", vlan=30, purpose=models.AttachmentPurpose.PRODUCTION,
           connectivity=models.AttachmentConnectivity.ACCESS, local="Ethernet1", approve=True):
    result = attachments.register_attachment(device, upstream_device=upstream, upstream_interface=port, local_interface=local,
                                             purpose=purpose, connectivity=connectivity, vlan=vlan, actor=OPERATOR)
    if approve and result.ok:
        result = attachments.approve_attachment(device, result.attachment.pk, actor=APPROVER)
    return result


def window(minutes=60, start=None):
    start = start or timezone.now() - timedelta(minutes=1)
    return start, start + timedelta(minutes=minutes)


def request_auth(device, attachment, *, scope=None, uses=1, minutes=60, actor=OPERATOR):
    valid_from, valid_until = window(minutes)
    return authorization.request_authorization(device, attachment_id=attachment.pk, scope=list(scope or SCOPE), valid_from=valid_from,
                                               valid_until=valid_until, max_uses=uses, actor=actor, reason="first boot of NEW1")


def ready_device(*, approve_auth=True, uses=1):
    """S1 adopted; NEW1 registered with an approved access attachment on S1 and (optionally) an approved authorization."""
    adopt()
    device = register().device
    attachment = attach(device).attachment
    auth = request_auth(device, attachment, uses=uses).authorization
    if approve_auth:
        auth = authorization.approve(auth, actor=APPROVER, confirm_digest=auth.binding_digest).authorization
    device.refresh_from_db()
    return device, attachment, auth


def good_request(**overrides):
    return {"scope": "BOOTSTRAP_FETCH", "serial": SERIAL, "base_mac": MAC, "upstream_device": "S1", "upstream_interface": "Ethernet7",
            "attachment_source": models.ObservationSource.DHCP_RELAY_ATTACHMENT, **overrides}
