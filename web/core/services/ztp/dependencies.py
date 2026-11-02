"""Dependency-aware onboarding: every prerequisite of a device's bootstrap path, generic (no device is special-cased).

Phase 5: the bootstrap path opens only behind an ENFORCED / VERIFIED trusted-upstream isolation policy of the attachment
(``isolation.service.ztp_problems``); the DHCP policy stops answering a port whose isolation is no longer in force.

For R4 -> R6 -> R7 the rules below give: R7's authorized attachment names R6's port, so R7 is blocked until R6 is IN_SERVICE
and ADMITTED (``attachments.commissioned_upstream_problems``) AND a bootstrap network lists R6 as a trusted relay.  Once R6
qualifies nothing about R7 changes in code.  Native DHCP / ZTP retry and the legitimate recovery operations come from the
platform adapter; whether a link flap would restart DHCP is never assumed.
"""

from __future__ import annotations

from ... import models
from ..devices import attachments as attachment_service
from ..isolation import service as isolation_service
from . import adapters, policy


def evaluate(device, attachment, network, *, relay_readback: dict | None = None) -> list[dict]:
    """[{check, ok, code, detail}] for the device's bootstrap path through ``attachment`` on ``network``.

    Phase 9: the relay's option 82 configuration is checked too (``bootstrap_path_option82``): enabled, helper to the bootstrap
    service, effective circuit id = the attachment port, and giaddr identifying exactly one routed port (client option 82 is
    forgeable on EOS).  The read-back is ``relay_readback`` when given, else -- for an upstream whose platform has a verified option
    82 implementation -- NMAS's latest fresh stored read-back (``relay_option82.trusted_readback``); none blocks the path."""
    checks = []

    def add(check, ok, code="", detail=""):
        checks.append({"check": check, "ok": bool(ok), "code": "" if ok else code, "detail": str(detail)[:200]})

    if attachment is None:
        add("attachment", False, "ATTACHMENT_NOT_FOUND")
        return checks
    upstream = attachment_service.upstream_problems(device.name, attachment.upstream_device)
    add("upstream_ready", not upstream, upstream[0]["code"] if upstream else "", attachment.upstream_device)
    add("attachment_approved", attachment.approval_state == models.AttachmentApproval.APPROVED, "AUTHORIZATION_ATTACHMENT_INELIGIBLE",
        attachment.approval_state)
    add("attachment_not_mismatched", attachment.verification_state != models.AttachmentVerification.MISMATCH, "ATTACHMENT_MISMATCH")
    add("attachment_not_vlan200", attachment.vlan != attachment_service.MANAGEMENT_VLAN, "VLAN200_PURPOSE_FORBIDDEN", attachment.vlan)
    add("bootstrap_interface_known", bool(attachment.local_interface), "INTERFACE_INVALID",
        "the authorized attachment must name the device's local bootstrap interface")
    isolation = isolation_service.ztp_problems(device, attachment)
    add("trusted_isolation", not isolation, isolation[0]["code"] if isolation else "",
        isolation[0].get("details", {}) if isolation else "the upstream port isolation is enforced and freshly verified")
    if network is None:
        add("bootstrap_network", False, "BOOTSTRAP_NETWORK_NOT_FOUND")
        return checks
    network_issues = policy.stored_network_problems(network)
    add("bootstrap_network", not network_issues, network_issues[0]["code"] if network_issues else "", network.name)
    relay = policy.relay_for(network, attachment.upstream_device)
    add("bootstrap_path_relay", bool(relay), "BOOTSTRAP_PATH_UNAVAILABLE",
        f"{attachment.upstream_device} relays {network.name}" if relay else f"{attachment.upstream_device} is not a trusted relay of {network.name}")
    if relay_readback is None and relay:
        # The relay's option 82 state is READ, never assumed: an upstream with a verified option 82 implementation is trusted only
        # with NMAS's latest fresh read-back of it (the postcheck of a governed option 82 change, or a read-only refresh).
        from . import relay_option82

        if relay_option82.required_for(attachment.upstream_device):
            relay_readback = relay_option82.trusted_readback(attachment.upstream_device)
            if relay_readback is None:
                add("bootstrap_path_option82", False, "RELAY_READBACK_MISSING",
                    f"no fresh NMAS read-back of {attachment.upstream_device}'s DHCP relay option 82 configuration")
    if relay_readback is not None:
        from .. import dhcp_relay_option82

        option82 = dhcp_relay_option82.relay_trust_problems(network=network, attachment=attachment, readback=relay_readback)
        add("bootstrap_path_option82", not option82, option82[0]["code"] if option82 else "",
            option82[0]["reason"] if option82 else f"{attachment.upstream_device}:{attachment.upstream_interface} inserts its circuit id")
    adapter = adapters.for_platform(device.platform)
    if adapter is None or not adapter.capability.implemented:
        add("native_ztp_adapter", False, "ZTP_ADAPTER_UNAVAILABLE", device.platform)
    else:
        retry = adapter.determine_native_retry_behavior()
        add("native_ztp_adapter", True, detail=f"{adapter.capability.adapter}: {adapter.capability.evidence_status}")
        add("native_retry_known", True, detail=f"DHCP: {retry.dhcp_retry}; indefinite={retry.retries_indefinitely}")
    return checks


def blockers(checks) -> list[str]:
    return [c["code"] for c in checks if not c["ok"]]


def downstream_waiting(device) -> list[dict]:
    """Registered devices whose authorized attachment names ``device`` as upstream (what this device's readiness unblocks)."""
    return [{"device": a.device.device_id, "name": a.device.name, "attachment": a.pk, "upstream_interface": a.upstream_interface}
            for a in models.DeviceAttachment.objects.select_related("device").filter(
                attachment_service.LIVE_ATTACHMENT, upstream_device=device.name).exclude(device__lifecycle_state__in=tuple(models.DEVICE_LIFECYCLE_TERMINAL))]
