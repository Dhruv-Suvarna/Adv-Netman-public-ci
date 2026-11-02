"""V2 Phase 4 pages: NMAS management attachments, the SPOF report, per-device management paths, probes, selection,
bootstrap credential retirement, and the Device Builder management-VRF collection.

Same conventions as ``lifecycle_views`` / ``ztp_views``: every mutating view is a thin CSRF POST calling one
``core.services.management`` function and redirecting with stable refusal codes only; authorization comes from
``core.services.identity.policy`` (unknown routes are denied).  Page views read the NMAS database only.  The probe /
evaluate / bootstrap-execute views are the only ones that contact a device, and only a registered, APPROVED management
target over SSH with a pinned host key.  No view changes host routing, firewall rules, namespaces or NIC configuration,
and none shows a password or private key (references and public fingerprints only).
"""

from __future__ import annotations

from django.http import Http404, JsonResponse
from django.shortcuts import render
from django.urls import reverse
from django.views.decorators.http import require_GET, require_POST

from . import models
from .lifecycle_views import _back, _device_or_404, _refusals
from .services import interface_intent_service
from .services.capabilities import lifecycle_features
from .services.devices.codes import blocker
from .services.identity.audit import actor_for as _actor
from .services.management import bootstrap_credentials, nmas_side, paths, resolve, selector, vrf


class _Codes:
    def __init__(self, blockers):
        self.ok = not blockers
        self.codes = [b["code"] for b in blockers]


def _int(value):
    return int(value) if str(value or "").isdigit() else None


def _overview_url():
    return reverse("core:management_overview")


def _device_url(device):
    return reverse("core:management_device", args=[device.device_id])


def _attachment_or_404(attachment_id):
    row = models.NmasManagementAttachment.objects.filter(pk=_int(str(attachment_id).removeprefix("NMA-"))).first()
    if row is None:
        raise Http404("Unknown NMAS attachment.")
    return row


def _path_or_404(device, path_id):
    row = models.ManagementPath.objects.filter(pk=_int(str(path_id).removeprefix("MPATH-")), device=device).first()
    if row is None:
        raise Http404("Unknown management path.")
    return row


def _transition_or_404(device, transition_id):
    row = models.BootstrapCredentialTransition.objects.filter(pk=_int(str(transition_id).removeprefix("BCRED-")), device=device).first()
    if row is None:
        raise Http404("Unknown bootstrap credential transition.")
    return row


def device_summary(device) -> dict:
    """Context for the device page's management card (NMAS database only)."""
    state = models.DeviceManagementState.objects.filter(device=device).select_related("active_path").first()
    live = paths.ordered(paths.live_paths(device))
    return {"state": state, "paths": live, "approved": sum(1 for p in live if p.approval_state == models.ManagementApproval.APPROVED),
            "endpoint": resolve.endpoint(device.name)}


# --- pages ----------------------------------------------------------------------------------------------------------------------
@require_GET
def management_overview(request):
    attachments = list(models.NmasManagementAttachment.objects.order_by("id"))
    devices = list(models.ManagedDevice.objects.filter(management_paths__isnull=False).distinct().order_by("name"))
    context = {
        "page_title": "Management multihoming", "page_key": "automation", "attachments": attachments,
        "spof": nmas_side.spof_report(), "devices": [{"device": d, **device_summary(d)} for d in devices],
        "telemetry": resolve.telemetry_targets(), "matrix": vrf.capability_matrix(), "features": vrf.FEATURES,
        "lifecycle": [lifecycle_features.by_key()[k] for k in ("lifecycle.CREDENTIAL_ONBOARDING", "lifecycle.MGMT_VRF", "lifecycle.MGMT_FAILOVER")],
        "refusals": _refusals(request.GET.get("codes", "")),
    }
    return render(request, "core/provisioning/management_overview.html", context)


@require_GET
def management_device(request, device_id):
    device = _device_or_404(device_id)
    summary = device_summary(device)
    credentials = list(models.DeviceCredential.objects.filter(device_name=device.name, account_kind=models.AccountKind.SERVICE).order_by("username"))
    context = {
        "page_title": f"Management paths · {device.name}", "page_key": "automation", "device": device, **summary,
        "probes": list(models.ManagementPathProbe.objects.filter(path__device=device).select_related("path").order_by("-id")[:30]),
        "transitions": list(models.ManagementPathTransition.objects.filter(device=device).order_by("-id")[:30]),
        "nmas_attachments": list(models.NmasManagementAttachment.objects.filter(approval_state=models.ManagementApproval.APPROVED).order_by("id")),
        "attachments": list(device.attachments.filter(purpose=models.AttachmentPurpose.MANAGEMENT).order_by("id")),
        "credentials": credentials, "path_types": models.ManagementPathType.choices,
        "credential_sources": models.ManagementCredentialSource.choices, "in_flight": selector.in_flight(device),
        "bcred": [bootstrap_credentials.status(t) for t in device.bootstrap_credential_transitions.order_by("-id")[:10]],
        "bootstrap_session": bootstrap_credentials.bootstrap_session(device),
        "refusals": _refusals(request.GET.get("codes", "")),
    }
    return render(request, "core/provisioning/management_device.html", context)


@require_GET
def management_device_json(request, device_id):
    device = _device_or_404(device_id)
    endpoint = resolve.endpoint(device.name)
    return JsonResponse({**selector.device_status(device), "endpoint": {"source": endpoint.source, "address": endpoint.address,
                                                                         "path": endpoint.path_id,
                                                                         "codes": [b["code"] for b in endpoint.blockers]},
                         "bootstrap_credential": [bootstrap_credentials.status(t) for t in device.bootstrap_credential_transitions.order_by("-id")[:5]]})


@require_GET
def management_spof_json(request):
    return JsonResponse(nmas_side.spof_report())


# --- NMAS attachments ------------------------------------------------------------------------------------------------------------
@require_POST
def management_attachment_register(request):
    post = request.POST
    result = paths.register_nmas_attachment(name=post.get("name", ""), host_interface=post.get("host_interface", ""),
                                            upstream_device=post.get("upstream_device", ""), upstream_interface=post.get("upstream_interface", ""),
                                            source_address=post.get("source_address", ""), network=post.get("network", ""),
                                            failure_domain=post.get("failure_domain", ""), actor=_actor(request))
    return _back(_overview_url(), result)


@require_POST
def management_attachment_approve(request, attachment_id):
    return _back(_overview_url(), paths.approve_nmas_attachment(_attachment_or_404(attachment_id), actor=_actor(request)))


@require_POST
def management_attachment_revoke(request, attachment_id):
    return _back(_overview_url(), paths.revoke_nmas_attachment(_attachment_or_404(attachment_id), actor=_actor(request),
                                                                reason=request.POST.get("reason", "")))


@require_POST
def management_attachment_observe(request, attachment_id):
    return _back(_overview_url(), nmas_side.observe_and_record(_attachment_or_404(attachment_id), actor=_actor(request)))


# --- paths ---------------------------------------------------------------------------------------------------------------------------
@require_POST
def management_path_register(request, device_id):
    device = _device_or_404(device_id)
    post = request.POST
    result = paths.register_path(
        device, path_type=post.get("path_type", ""), endpoint_address=post.get("endpoint_address", ""),
        nmas_attachment_id=_int(post.get("nmas_attachment_id")), credential_source=post.get("credential_source", ""),
        credential_reference=post.get("credential_reference", ""), device_credential_id=_int(post.get("device_credential_id")),
        attachment_id=_int(post.get("attachment_id")), via_device=post.get("via_device", ""), vrf=post.get("vrf", ""),
        vlan=_int(post.get("vlan")), expected_host_key=post.get("expected_host_key", ""), reason=post.get("reason", ""),
        actor=_actor(request))
    return _back(_device_url(device), result)


@require_POST
def management_path_approve(request, device_id, path_id):
    device = _device_or_404(device_id)
    return _back(_device_url(device), paths.approve_path(_path_or_404(device, path_id), actor=_actor(request)))


@require_POST
def management_path_revoke(request, device_id, path_id):
    device = _device_or_404(device_id)
    return _back(_device_url(device), paths.revoke_path(_path_or_404(device, path_id), actor=_actor(request), reason=request.POST.get("reason", ""),
                                                        acknowledge_active=request.POST.get("acknowledge_active") == "yes"))


@require_POST
def management_path_probe(request, device_id, path_id):
    """One VERIFY probe of one approved path (rate-limited; refused for any unauthorized target)."""
    from .services.management import probes

    device = _device_or_404(device_id)
    report, _row, refusals = probes.probe(_path_or_404(device, path_id), actor=_actor(request))
    if refusals:
        return _back(_device_url(device), _Codes(refusals))
    return _back(_device_url(device), _Codes([] if report.passed else [blocker(report.failure_code or "MGMT_PATH_UNVERIFIED")]))


@require_POST
def management_evaluate(request, device_id):
    device = _device_or_404(device_id)
    result = selector.evaluate(device, actor=_actor(request), actor_kind="HUMAN")
    return _back(_device_url(device), _Codes(result.blockers))


@require_POST
def management_reconcile(request, device_id):
    device = _device_or_404(device_id)
    result = selector.acknowledge_reconciliation(device, actor=_actor(request), reason=request.POST.get("reason", ""))
    return _back(_device_url(device), _Codes(result["blockers"]))


# --- bootstrap credential retirement ---------------------------------------------------------------------------------------------
@require_POST
def bcred_plan(request, device_id):
    device = _device_or_404(device_id)
    result = bootstrap_credentials.plan(device, replacement_credential_id=_int(request.POST.get("replacement_credential_id")),
                                        path_id=_int(request.POST.get("path_id")), actor=_actor(request), reason=request.POST.get("reason", ""))
    return _back(_device_url(device), result)


@require_POST
def bcred_approve(request, device_id, transition_id):
    device = _device_or_404(device_id)
    return _back(_device_url(device), bootstrap_credentials.approve(_transition_or_404(device, transition_id), actor=_actor(request),
                                                                    digest=request.POST.get("digest", "")))


@require_POST
def bcred_cancel(request, device_id, transition_id):
    device = _device_or_404(device_id)
    return _back(_device_url(device), bootstrap_credentials.cancel(_transition_or_404(device, transition_id), actor=_actor(request),
                                                                   reason=request.POST.get("reason", "")))


@require_POST
def bcred_execute(request, device_id, transition_id):
    device = _device_or_404(device_id)
    return _back(_device_url(device), bootstrap_credentials.execute(_transition_or_404(device, transition_id), actor=_actor(request)))


# --- Device Builder: management VRF collection -----------------------------------------------------------------------------------
def _builder_target(change_id, intent_id):
    from .views import _resolve_editor_target

    return _resolve_editor_target(change_id, intent_id)


MANAGEMENT_ADD = {
    "vrf": lambda revision, post: vrf.add_vrf(revision, name=post.get("name", ""), description=post.get("description", "")),
    "binding": lambda revision, post: vrf.add_binding(revision, vrf_id=post.get("vrf_id", ""), interface_id=post.get("interface_id", "")),
    "route": lambda revision, post: vrf.add_route(revision, vrf_id=post.get("vrf_id", ""), destination=post.get("destination", ""),
                                                 next_hop=post.get("next_hop", "")),
    "service": lambda revision, post: vrf.add_service(revision, vrf_id=post.get("vrf_id", ""), service=post.get("service", ""),
                                                     host=post.get("host", ""), source_interface_id=post.get("source_interface_id", "")),
}
MANAGEMENT_COLLECTIONS = {"vrf": "vrfs", "binding": "bindings", "route": "routes", "service": "services"}
_ERRORS = (vrf.ManagementIntentError, interface_intent_service.DraftOnlyError, interface_intent_service.CollectionOwnershipError)


@require_POST
def device_builder_management_add(request, change_id, intent_id, kind):
    from .views import _collection_redirect

    change, intent, revision = _builder_target(change_id, intent_id)
    action = MANAGEMENT_ADD.get(kind)
    if action is None:
        raise Http404("Unknown management collection.")
    try:
        action(revision, request.POST)
    except _ERRORS as exc:
        return _collection_redirect(request, change, intent, error=f"{getattr(exc, 'code', 'MGMT_REFUSED')}: {exc}")
    return _collection_redirect(request, change, intent)


@require_POST
def device_builder_management_remove(request, change_id, intent_id, kind, object_id):
    from .views import _collection_redirect

    change, intent, revision = _builder_target(change_id, intent_id)
    collection = MANAGEMENT_COLLECTIONS.get(kind)
    if collection is None:
        raise Http404("Unknown management collection.")
    try:
        vrf.remove(revision, collection=collection, object_id=object_id)
    except _ERRORS as exc:
        return _collection_redirect(request, change, intent, error=f"{getattr(exc, 'code', 'MGMT_REFUSED')}: {exc}")
    return _collection_redirect(request, change, intent)


def editor_context(intent, revision) -> dict:
    """The Device Builder editor's management-VRF card."""
    management = vrf.section(revision)
    names = {k: v["name"] for k, v in management["vrfs"].items()}
    return {"management": management, "management_vrf_names": names,
            "management_capability": vrf.capability_matrix().get(intent.platform, {}),
            "management_services": vrf.SERVICES, "management_host_services": sorted(vrf.HOST_SERVICES)}
