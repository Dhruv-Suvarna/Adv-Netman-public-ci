"""V2 Phases 5 / 6 pages: trusted-upstream isolation, governed commissioning, dependencies and production admission.

Same conventions as ``lifecycle_views`` / ``management_views``: every mutating view is a thin CSRF POST calling one
``core.services.isolation`` / ``core.services.commissioning`` function and redirecting with stable refusal codes only;
authorization comes from ``core.services.identity.policy`` (unknown routes are denied), and every service call records its own
lifecycle event and audit row.  Page views read the NMAS database only.  The plan / precheck / apply / verify / drift / release
views are the only ones that contact a device, and only the TRUSTED upstream through the governed transaction.  Traffic
verification needs an external probe and is not offered here (verification from this page proves configuration, routing and
the management plane; it never claims traffic evidence).  No view shows a credential or private key.
"""

from __future__ import annotations

from django.http import Http404, JsonResponse
from django.shortcuts import render
from django.urls import reverse
from django.views.decorators.http import require_GET, require_POST

from . import models
from .lifecycle_views import _back, _device_or_404, _refusals
from .services.capabilities import lifecycle_features
from .services.commissioning import admission as admission_service
from .services.commissioning import dependencies, outbox, service as commissioning
from .services.identity.audit import actor_for as _actor
from .services.isolation import service as isolation

CAPABILITY_KEYS = ("lifecycle.ISOLATION", "lifecycle.COMMISSION", "lifecycle.ADMISSION")


def _int(value, prefix=""):
    text = str(value or "").removeprefix(prefix)
    return int(text) if text.isdigit() else None


def _device_url(device):
    return reverse("core:commissioning_device", args=[device.device_id])


def _policy_or_404(device, policy_id):
    row = models.IsolationPolicy.objects.filter(pk=_int(policy_id, "ISO-"), device=device).first()
    if row is None:
        raise Http404("Unknown isolation policy.")
    return row


def _record_or_404(device, record_id):
    row = models.CommissioningRecord.objects.filter(pk=_int(record_id, "COM-"), device=device).first()
    if row is None:
        raise Http404("Unknown commissioning record.")
    return row


def _admission_or_404(device, admission_id):
    row = models.ProductionAdmission.objects.filter(pk=_int(admission_id, "ADM-"), device=device).first()
    if row is None:
        raise Http404("Unknown production admission.")
    return row


def device_context(device) -> dict:
    policies = list(device.isolation_policies.order_by("-id")[:5])
    records = list(device.commissioning_records.select_related("provisioning_run").order_by("-id")[:5])
    admissions = list(device.production_admissions.order_by("-id")[:5])
    return {
        "policies": [isolation.status(p) for p in policies], "policy": policies[0] if policies else None,
        "records": [commissioning.status(r) for r in records], "record": records[0] if records else None,
        "admissions": [admission_service.status(a) for a in admissions], "admission": admissions[0] if admissions else None,
        "dependencies": dependencies.graph_view([device]),
        "dependency_rows": list(device.commissioning_dependencies.filter(state=models.DependencyState.ACTIVE).select_related("upstream")),
        "outbox": list(device.outbox_events.order_by("-id")[:10]),
    }


# --- pages ----------------------------------------------------------------------------------------------------------------------
@require_GET
def commissioning_overview(request):
    context = {
        "page_title": "Isolation and commissioning", "page_key": "automation",
        "policies": list(models.IsolationPolicy.objects.select_related("device").order_by("-id")[:50]),
        "records": list(models.CommissioningRecord.objects.select_related("device").order_by("-id")[:50]),
        "admissions": list(models.ProductionAdmission.objects.select_related("device").order_by("-id")[:50]),
        "graph": dependencies.graph_view(), "pending": outbox.pending(limit=50),
        "capabilities": [lifecycle_features.by_key()[k] for k in CAPABILITY_KEYS],
        "refusals": _refusals(request.GET.get("codes", "")),
    }
    return render(request, "core/provisioning/commissioning_overview.html", context)


@require_GET
def commissioning_device(request, device_id):
    device = _device_or_404(device_id)
    context = {
        "page_title": f"Isolation and commissioning · {device.name}", "page_key": "automation", "device": device, **device_context(device),
        "attachments": list(device.attachments.filter(connectivity=models.AttachmentConnectivity.ROUTED).order_by("id")),
        "networks": list(models.BootstrapNetwork.objects.filter(state=models.BootstrapNetworkState.ACTIVE).order_by("name")),
        "upstream_choices": list(models.ManagedDevice.objects.exclude(pk=device.pk).exclude(
            lifecycle_state__in=tuple(models.DEVICE_LIFECYCLE_TERMINAL)).order_by("name")),
        "dependency_kinds": models.DependencyKind.choices, "refusals": _refusals(request.GET.get("codes", "")),
    }
    return render(request, "core/provisioning/commissioning_device.html", context)


@require_GET
def commissioning_device_json(request, device_id):
    device = _device_or_404(device_id)
    found = device_context(device)
    return JsonResponse({"device": device.device_id, "lifecycle_state": device.lifecycle_state, "admission_state": device.admission_state,
                         "policies": found["policies"], "commissioning": found["records"], "admissions": found["admissions"],
                         "dependencies": found["dependencies"],
                         "outbox": [{"id": e.pk, "topic": e.topic, "state": e.state, "payload_digest": e.payload_digest} for e in found["outbox"]]})


# --- isolation ------------------------------------------------------------------------------------------------------------------
@require_POST
def isolation_require(request, device_id):
    device = _device_or_404(device_id)
    attachment = device.attachments.filter(pk=_int(request.POST.get("attachment_id"))).first()
    network = models.BootstrapNetwork.objects.filter(name=str(request.POST.get("network", ""))[:64]).first()
    return _back(_device_url(device), isolation.require(device, attachment, network=network, actor=_actor(request)))


def _isolation_action(request, device_id, policy_id, call):
    device = _device_or_404(device_id)
    return _back(_device_url(device), call(_policy_or_404(device, policy_id), _actor(request)))


@require_POST
def isolation_plan(request, device_id, policy_id):
    return _isolation_action(request, device_id, policy_id, lambda p, actor: isolation.plan(p, actor=actor))


@require_POST
def isolation_precheck(request, device_id, policy_id):
    return _isolation_action(request, device_id, policy_id, lambda p, actor: isolation.precheck(p, actor=actor))


@require_POST
def isolation_approve(request, device_id, policy_id):
    confirmation = str(request.POST.get("confirmation", ""))[:64]
    return _isolation_action(request, device_id, policy_id, lambda p, actor: isolation.approve(p, actor=actor, confirmation=confirmation))


@require_POST
def isolation_apply(request, device_id, policy_id):
    confirmation = str(request.POST.get("confirmation", ""))[:64]
    return _isolation_action(request, device_id, policy_id, lambda p, actor: isolation.apply(p, actor=actor, confirmation=confirmation))


@require_POST
def isolation_verify(request, device_id, policy_id):
    with_device = request.POST.get("with_device") == "yes"
    return _isolation_action(request, device_id, policy_id, lambda p, actor: isolation.verify(p, actor=actor, with_device=with_device))


@require_POST
def isolation_drift(request, device_id, policy_id):
    return _isolation_action(request, device_id, policy_id, lambda p, actor: isolation.check_drift(p, actor=actor))


@require_POST
def isolation_reconcile(request, device_id, policy_id):
    return _isolation_action(request, device_id, policy_id, lambda p, actor: isolation.reconcile(p, actor=actor))


@require_POST
def isolation_cancel(request, device_id, policy_id):
    reason = str(request.POST.get("reason", ""))[:200]
    return _isolation_action(request, device_id, policy_id, lambda p, actor: isolation.cancel(p, actor=actor, reason=reason))


# --- commissioning --------------------------------------------------------------------------------------------------------------
@require_POST
def commissioning_open(request, device_id):
    device = _device_or_404(device_id)
    return _back(_device_url(device), commissioning.open_commissioning(device, actor=_actor(request)))


def _record_action(request, device_id, record_id, call):
    device = _device_or_404(device_id)
    return _back(_device_url(device), call(_record_or_404(device, record_id), _actor(request)))


@require_POST
def commissioning_assess(request, device_id, record_id):
    return _record_action(request, device_id, record_id, lambda r, actor: commissioning.assess(r, actor=actor))


@require_POST
def commissioning_approve(request, device_id, record_id):
    confirmation = str(request.POST.get("confirmation", ""))[:64]
    comment = str(request.POST.get("comment", ""))[:500]
    return _record_action(request, device_id, record_id,
                          lambda r, actor: commissioning.approve(r, actor=actor, confirmation=confirmation, comment=comment))


@require_POST
def commissioning_record(request, device_id, record_id):
    return _record_action(request, device_id, record_id, lambda r, actor: commissioning.record_configuration(r, actor=actor))


@require_POST
def commissioning_abort(request, device_id, record_id):
    reason = str(request.POST.get("reason", ""))[:200]
    return _record_action(request, device_id, record_id, lambda r, actor: commissioning.abort(r, actor=actor, reason=reason))


@require_POST
def commissioning_reconcile(request, device_id, record_id):
    return _record_action(request, device_id, record_id, lambda r, actor: commissioning.reconcile(r, actor=actor))


# --- dependencies ---------------------------------------------------------------------------------------------------------------
@require_POST
def dependency_add(request, device_id):
    device = _device_or_404(device_id)
    upstream = models.ManagedDevice.objects.filter(pk=_int(request.POST.get("upstream_id"))).first()
    return _back(_device_url(device), dependencies.add(device, upstream, kind=str(request.POST.get("kind", ""))[:24], actor=_actor(request),
                                                       reason=str(request.POST.get("reason", ""))))


@require_POST
def dependency_remove(request, device_id, dependency_id):
    device = _device_or_404(device_id)
    row = models.CommissioningDependency.objects.filter(pk=_int(dependency_id), device=device).first()
    if row is None:
        raise Http404("Unknown dependency.")
    return _back(_device_url(device), dependencies.remove(row, actor=_actor(request), reason=str(request.POST.get("reason", ""))))


# --- admission ------------------------------------------------------------------------------------------------------------------
def _lines(value) -> list[str]:
    return [item.strip() for item in str(value or "").replace(",", "\n").splitlines() if item.strip()][:admission_service.MAX_ITEMS + 1]


@require_POST
def admission_plan(request, device_id, record_id):
    device = _device_or_404(device_id)
    expectations = {"routing": str(request.POST.get("routing", ""))[:8], "ospf_neighbors": _lines(request.POST.get("ospf_neighbors")),
                    "routes_v4": _lines(request.POST.get("routes_v4")), "routes_v6": _lines(request.POST.get("routes_v6")),
                    "reachable": _lines(request.POST.get("reachable"))}
    return _back(_device_url(device), admission_service.plan(_record_or_404(device, record_id), actor=_actor(request), expectations=expectations))


def _admission_action(request, device_id, admission_id, call):
    device = _device_or_404(device_id)
    return _back(_device_url(device), call(_admission_or_404(device, admission_id), _actor(request)))


@require_POST
def admission_precheck(request, device_id, admission_id):
    return _admission_action(request, device_id, admission_id, lambda a, actor: admission_service.precheck(a, actor=actor))


@require_POST
def admission_approve(request, device_id, admission_id):
    confirmation = str(request.POST.get("confirmation", ""))[:64]
    return _admission_action(request, device_id, admission_id, lambda a, actor: admission_service.approve(a, actor=actor, confirmation=confirmation))


@require_POST
def admission_execute(request, device_id, admission_id):
    return _admission_action(request, device_id, admission_id, lambda a, actor: admission_service.execute(a, actor=actor))


@require_POST
def admission_cancel(request, device_id, admission_id):
    reason = str(request.POST.get("reason", ""))[:200]
    return _admission_action(request, device_id, admission_id, lambda a, actor: admission_service.cancel(a, actor=actor, reason=reason))


@require_POST
def admission_reconcile(request, device_id, admission_id):
    return _admission_action(request, device_id, admission_id, lambda a, actor: admission_service.reconcile(a, actor=actor))
