"""V2 Phase 7 pages: governed decommissioning and restoration.

Same conventions as ``commissioning_views``: page views read the NMAS database only; every mutating view is a thin CSRF POST
calling one ``core.services.decommission.service`` function and redirecting with stable refusal codes only.  Authorization is
the route policy (``core.services.identity.policy``; unknown routes are denied) and every service call records its own lifecycle
event and audit row.  Evaluate / execute / reconcile / restore-check contact the device only through the configured runtime
(``NMAS_DECOMMISSION_RUNTIME``); without one they refuse with DECOMMISSION_RUNTIME_UNAVAILABLE -- readiness is never decided
without observing traffic.  No view shows a credential, key or configuration secret.
"""

from __future__ import annotations

from django.http import Http404
from django.shortcuts import render
from django.urls import reverse
from django.views.decorators.http import require_GET, require_POST

from . import models
from .lifecycle_views import _back, _device_or_404, _refusals
from .services.decommission import service as decommission
from .services.identity.audit import actor_for as _actor


def _record_or_404(device, record_id):
    row = decommission.get_record(record_id)
    if row is None or row.device_id != device.pk:
        raise Http404("Unknown decommission record.")
    return row


def _restoration_or_404(device, record_id):
    row = decommission.get_restoration(record_id)
    if row is None or row.device_id != device.pk:
        raise Http404("Unknown restoration record.")
    return row


def _device_url(device):
    return reverse("core:decommission_device", args=[device.device_id])


@require_GET
def decommission_overview(request):
    context = {"page_title": "Decommissioning and restoration", "page_key": "automation",
               "records": list(models.DecommissionRecord.objects.select_related("device").order_by("-id")[:50]),
               "restorations": list(models.RestorationRecord.objects.select_related("device", "successor").order_by("-id")[:50]),
               "runtime_configured": decommission.configured_runtime() is not None}
    return render(request, "core/provisioning/decommission_overview.html", context)


@require_GET
def decommission_device(request, device_id):
    device = _device_or_404(device_id)
    records = list(device.decommissions.select_related("baseline", "change").order_by("-id")[:10])
    context = {"page_title": f"Decommission {device.name}", "page_key": "automation", "device": device, "records": records,
               "record": records[0] if records else None,
               "restorations": list(device.restorations.select_related("successor").order_by("-id")[:10]),
               "refusals": _refusals(request.GET.get("codes", "")), "runtime_configured": decommission.configured_runtime() is not None}
    return render(request, "core/provisioning/decommission_device.html", context)


@require_POST
def decommission_request(request, device_id):
    device = _device_or_404(device_id)
    return _back(_device_url(device), decommission.request(device, actor=_actor(request), reason=request.POST.get("reason", "")))


@require_POST
def decommission_evaluate(request, device_id, record_id):
    device = _device_or_404(device_id)
    row = _record_or_404(device, record_id)
    return _back(_device_url(device), decommission.evaluate(row, actor=_actor(request), runtime=decommission.configured_runtime()))


@require_POST
def decommission_approve(request, device_id, record_id):
    device = _device_or_404(device_id)
    row = _record_or_404(device, record_id)
    return _back(_device_url(device), decommission.approve(row, actor=_actor(request), confirmation=request.POST.get("confirmation", "")))


@require_POST
def decommission_execute(request, device_id, record_id):
    device = _device_or_404(device_id)
    row = _record_or_404(device, record_id)
    return _back(_device_url(device), decommission.execute(row, actor=_actor(request), confirmation=request.POST.get("confirmation", ""),
                                                           runtime=decommission.configured_runtime()))


@require_POST
def decommission_cancel(request, device_id, record_id):
    device = _device_or_404(device_id)
    row = _record_or_404(device, record_id)
    return _back(_device_url(device), decommission.cancel(row, actor=_actor(request), reason=request.POST.get("reason", "")))


@require_POST
def decommission_reconcile(request, device_id, record_id):
    device = _device_or_404(device_id)
    row = _record_or_404(device, record_id)
    return _back(_device_url(device), decommission.reconcile(row, actor=_actor(request), runtime=decommission.configured_runtime()))


@require_POST
def restoration_request(request, device_id, record_id):
    device = _device_or_404(device_id)
    row = _record_or_404(device, record_id)
    return _back(_device_url(device), decommission.request_restore(row, actor=_actor(request)))


@require_POST
def restoration_check(request, device_id, record_id):
    device = _device_or_404(device_id)
    row = _restoration_or_404(device, record_id)
    return _back(_device_url(device), decommission.check_restore(row, actor=_actor(request), runtime=decommission.configured_runtime()))


@require_POST
def restoration_approve(request, device_id, record_id):
    device = _device_or_404(device_id)
    row = _restoration_or_404(device, record_id)
    return _back(_device_url(device), decommission.approve_restore(row, actor=_actor(request), confirmation=request.POST.get("confirmation", "")))


@require_POST
def restoration_execute(request, device_id, record_id):
    device = _device_or_404(device_id)
    row = _restoration_or_404(device, record_id)
    return _back(_device_url(device), decommission.execute_restore(row, actor=_actor(request), confirmation=request.POST.get("confirmation", ""),
                                                                   runtime=decommission.configured_runtime()))


@require_POST
def restoration_cancel(request, device_id, record_id):
    device = _device_or_404(device_id)
    row = _restoration_or_404(device, record_id)
    return _back(_device_url(device), decommission.cancel_restore(row, actor=_actor(request)))
