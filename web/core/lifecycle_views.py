"""V2 Lifecycle Phase 2 pages: managed devices, adoption, registration, expected attachments and bootstrap authorizations.

Every mutating view is a thin CSRF POST that calls one ``core.services.devices`` function and redirects with stable refusal
codes only (``?codes=``) -- no request text is echoed.  Authorization is enforced by the access middleware from
``core.services.identity.policy`` (each route carries the permission of the step it performs).  No view contacts a device;
only ``managed_device_netbox_compare`` / ``_import`` read NetBox, and nothing writes to it.  There is deliberately no
commission, isolation, bootstrap-delivery or decommission action: those edges are refused until their owning phase.
"""

from __future__ import annotations

from datetime import timedelta
from datetime import timezone as dt_timezone
from urllib.parse import urlencode

from django.db import transaction
from django.http import Http404, JsonResponse
from django.shortcuts import redirect, render
from django.urls import reverse
from django.utils import timezone
from django.utils.dateparse import parse_datetime
from django.views.decorators.http import require_GET, require_POST

from . import models
from .services.capabilities import lifecycle_features
from .services.devices import attachments as attachment_service
from .services.devices import authorization as authorization_service
from .services.devices import codes as device_codes
from .services.devices import events as device_events
from .services.devices import lifecycle, resolver
from .services.devices import netbox as device_netbox
from .services.identity.audit import actor_for as _actor

ROLES = lifecycle.ROLES
DECISIONS = frozenset(v for k, v in vars(authorization_service.Decision).items() if k.isupper())


def _device_or_404(device_id):
    device = lifecycle.get_device(device_id)
    if device is None:
        raise Http404("Unknown managed device.")
    return device


def _refusals(text: str) -> list[dict]:
    """Stable codes from the query string -> fixed messages (unknown codes are dropped)."""
    known = device_codes.BLOCKERS
    return [{"code": code, "message": known[code][0], "remediation": known[code][1]} for code in str(text).split(",")[:8] if code in known]


def _back(url: str, result=None, **extra) -> object:
    params = {}
    if result is not None and not result.ok:
        params["codes"] = ",".join(result.codes)
    params.update({k: v for k, v in extra.items() if v})
    return redirect(f"{url}?{urlencode(params)}" if params else url)


def _version(request):
    value = request.POST.get("expected_version", "")
    return int(value) if str(value).isdigit() else -1      # a missing version never matches: fail closed


# --- pages ----------------------------------------------------------------------------------------------------------------------
@require_GET
def managed_devices(request):
    resolution = resolver.resolve_all()
    registered = models.ManagedDevice.objects.order_by("name", "id")
    context = {
        "page_title": "Managed devices", "page_key": "automation", "targets": list(resolution.targets.values()),
        "discrepancies": [d.as_dict() for d in resolution.discrepancies], "candidates": lifecycle.adoption_candidates(),
        "registered": registered, "platforms": models.Platform.choices, "roles": ROLES,
        "refusals": _refusals(request.GET.get("codes", "")), "lifecycle_capabilities": [c.as_dict() for c in lifecycle_features.CAPABILITIES],
    }
    return render(request, "core/provisioning/devices.html", context)


@require_GET
def managed_device_detail(request, device_id):
    device = _device_or_404(device_id)
    decision = request.GET.get("decision", "")
    context = {
        "page_title": f"Managed device {device.device_id}", "page_key": "automation", "device": device,
        "target": resolver.resolve(device.name), "allowed": lifecycle.allowed_targets(device.lifecycle_state),
        "events": list(device.lifecycle_events.order_by("-sequence")[:80]), "chain_ok": device_events.verify_chain(device),
        "attachments": list(device.attachments.order_by("id")), "observations": list(device.observations.order_by("-observed_at", "-id")[:40]),
        "authorizations": list(device.bootstrap_authorizations.select_related("attachment").order_by("-id")),
        "maintenance": lifecycle.maintenance_state(device), "projection": device_netbox.projection(device),
        "purposes": models.AttachmentPurpose.choices, "connectivities": models.AttachmentConnectivity.choices,
        "scope_tokens": authorization_service.SCOPE_TOKENS, "observation_sources": models.ObservationSource.choices,
        "refusals": _refusals(request.GET.get("codes", "")),
        "decision": decision if decision in DECISIONS else "",
    }
    from .ztp_views import device_panel        # imported here: ztp_views imports this module's helpers
    context["ztp"] = device_panel(device)
    return render(request, "core/provisioning/device_detail.html", context)


@require_GET
def managed_devices_json(request):
    resolution = resolver.resolve_all()
    return JsonResponse({"targets": [t.as_dict() for t in resolution.targets.values()],
                         "discrepancies": [d.as_dict() for d in resolution.discrepancies]})


@require_GET
def managed_device_json(request, device_id):
    device = _device_or_404(device_id)
    target = resolver.resolve(device.name)
    return JsonResponse({
        "device_id": device.device_id, "name": device.name, "platform": device.platform, "role": device.role, "origin": device.origin,
        "inventory_authority": device.inventory_authority, "lifecycle_state": device.lifecycle_state, "identity_state": device.identity_state,
        "admission_state": device.admission_state, "ztp_state": device.ztp_state, "compliance_state": device.compliance_state,
        "version": device.version, "maintenance": lifecycle.maintenance_state(device), "allowed_transitions": lifecycle.allowed_targets(device.lifecycle_state),
        "resolution": target.as_dict() if target else None, "event_chain_intact": device_events.verify_chain(device),
    })


# --- registration / adoption / lifecycle ----------------------------------------------------------------------------------------
@require_POST
def managed_device_register(request):
    post = request.POST
    result = lifecycle.register_device(
        name=post.get("name", ""), platform=post.get("platform", ""), role=post.get("role", ""), actor=_actor(request),
        manufacturer=post.get("manufacturer", ""), model=post.get("model", ""), expected_serial=post.get("expected_serial", ""),
        expected_base_mac=post.get("expected_base_mac", ""), netbox_device_id=post.get("netbox_device_id", "") or None)
    if not result.ok:
        return _back(reverse("core:managed_devices"), result)
    return redirect(result.device.get_absolute_url())


@require_POST
def managed_device_adopt(request):
    name = request.POST.get("name", "")
    if request.POST.get("confirm_name", "") != name or not name:
        return _back(reverse("core:managed_devices"), codes="AUTHORIZATION_CONFIRMATION_MISMATCH")
    result = lifecycle.adopt_existing(name, role=request.POST.get("role", ""), actor=_actor(request))
    if result.device is None or not result.ok:
        return _back(reverse("core:managed_devices"), result)
    return redirect(result.device.get_absolute_url())


@require_POST
def managed_device_identity(request, device_id):
    device = _device_or_404(device_id)
    post = request.POST
    result = lifecycle.update_expected_identity(
        device, actor=_actor(request), expected_serial=post.get("expected_serial", ""), expected_base_mac=post.get("expected_base_mac", ""),
        manufacturer=post.get("manufacturer", ""), model=post.get("model", ""), expected_version=_version(request))
    return _back(device.get_absolute_url(), result)


@require_POST
def managed_device_withdraw(request, device_id):
    device = _device_or_404(device_id)
    if request.POST.get("confirm_name", "") != device.name:
        return _back(device.get_absolute_url(), codes="AUTHORIZATION_CONFIRMATION_MISMATCH")
    result = lifecycle.withdraw(device, actor=_actor(request), reason=request.POST.get("reason", ""), expected_version=_version(request))
    return _back(device.get_absolute_url(), result)


@require_POST
def managed_device_verify_identity(request, device_id):
    device = _device_or_404(device_id)
    result = lifecycle.verify_identity(device, request.POST.get("observation_id", ""), actor=_actor(request), expected_version=_version(request))
    return _back(device.get_absolute_url(), result)


# --- attachments ----------------------------------------------------------------------------------------------------------------
@require_POST
def managed_device_attachment_add(request, device_id):
    device = _device_or_404(device_id)
    post = request.POST
    result = attachment_service.register_attachment(
        device, upstream_device=post.get("upstream_device", ""), upstream_interface=post.get("upstream_interface", ""),
        local_interface=post.get("local_interface", ""), purpose=post.get("purpose", ""), connectivity=post.get("connectivity", ""),
        vlan=post.get("vlan", ""), actor=_actor(request))
    return _back(device.get_absolute_url(), result)


@require_POST
def managed_device_attachment_approve(request, device_id, attachment_id):
    device = _device_or_404(device_id)
    return _back(device.get_absolute_url(), attachment_service.approve_attachment(device, attachment_id, actor=_actor(request)))


@require_POST
def managed_device_attachment_revoke(request, device_id, attachment_id):
    device = _device_or_404(device_id)
    result = attachment_service.revoke_attachment(device, attachment_id, actor=_actor(request), reason=request.POST.get("reason", ""))
    return _back(device.get_absolute_url(), result)


# --- NetBox (read-only) ---------------------------------------------------------------------------------------------------------
@require_POST
def managed_device_netbox_compare(request, device_id):
    """Read the device's NetBox record and record the comparison on the device chain.  Writes nothing to NetBox."""
    device = _device_or_404(device_id)
    found = device_netbox.compare(device, device_netbox.NetboxDeviceReader())
    with transaction.atomic():
        device_events.record(device, "NETBOX_COMPARE", models.DeviceLifecycleEventOutcome.RECORDED, actor=_actor(request),
                             from_state=device.lifecycle_state, to_state=device.lifecycle_state, blockers=found["blockers"],
                             evidence={"available": found["available"], "discrepancies": found["discrepancies"],
                                       "netbox_status": (found["netbox"] or {}).get("status", "")})
    return _back(device.get_absolute_url(), codes=",".join(device_codes.codes(found["blockers"])))


@require_POST
def managed_device_netbox_import(request, device_id):
    """NetBox cables -> PENDING expected attachments (NMAS database only)."""
    device = _device_or_404(device_id)
    found = device_netbox.import_cable_attachments(device, actor=_actor(request), reader=device_netbox.NetboxDeviceReader())
    return _back(device.get_absolute_url(), codes=",".join(device_codes.codes(found["blockers"])))


# --- bootstrap authorizations ---------------------------------------------------------------------------------------------------
def _authorization_or_404(device, auth_id):
    auth = authorization_service.get_authorization(auth_id)
    if auth is None or auth.device_id != device.pk:
        raise Http404("Unknown bootstrap authorization.")
    return auth


def _window(post) -> tuple:
    """(valid_from, valid_until) from the form: an explicit ISO start (default now) and a duration in minutes.
    Malformed or out-of-range input -> (None, None), which the service refuses as AUTHORIZATION_WINDOW_INVALID."""
    minutes = str(post.get("duration_minutes", ""))
    if not minutes.isdigit() or len(minutes) > 6:
        return None, None
    try:
        start = parse_datetime(post.get("valid_from", "")) if post.get("valid_from") else timezone.now()
        if start is None:
            return None, None
        if timezone.is_naive(start):
            start = timezone.make_aware(start, dt_timezone.utc)
        return start, start + timedelta(minutes=int(minutes))
    except (ValueError, OverflowError):
        return None, None


@require_POST
def bootstrap_authorization_request(request, device_id):
    device = _device_or_404(device_id)
    post = request.POST
    valid_from, valid_until = _window(post)
    result = authorization_service.request_authorization(
        device, attachment_id=post.get("attachment_id", ""), scope=post.getlist("scope"), valid_from=valid_from, valid_until=valid_until,
        max_uses=post.get("max_uses", ""), actor=_actor(request), reason=post.get("reason", ""))
    return _back(device.get_absolute_url(), result)


@require_POST
def bootstrap_authorization_approve(request, device_id, auth_id):
    device = _device_or_404(device_id)
    auth = _authorization_or_404(device, auth_id)
    result = authorization_service.approve(auth, actor=_actor(request), confirm_digest=request.POST.get("confirm_digest", ""))
    return _back(device.get_absolute_url(), result)


@require_POST
def bootstrap_authorization_revoke(request, device_id, auth_id):
    device = _device_or_404(device_id)
    auth = _authorization_or_404(device, auth_id)
    result = authorization_service.revoke(auth, actor=_actor(request), reason=request.POST.get("reason", ""))
    return _back(device.get_absolute_url(), result)


@require_POST
def bootstrap_authorization_evaluate(request, device_id, auth_id):
    """A recorded dry-run decision for a described bootstrap request.  Consumes nothing, delivers nothing."""
    device = _device_or_404(device_id)
    auth = _authorization_or_404(device, auth_id)
    post = request.POST
    described = {key: post.get(key, "").strip() for key in authorization_service.REQUEST_KEYS if post.get(key, "").strip()}
    outcome = authorization_service.evaluate(auth, described, actor=_actor(request))
    return _back(device.get_absolute_url(), decision=outcome.decision, codes=",".join(device_codes.codes(outcome.blockers)))
