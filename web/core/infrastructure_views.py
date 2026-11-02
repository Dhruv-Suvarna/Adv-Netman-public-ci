"""V2 Phase 8 operator pages: the lifecycle outbox queue and the NetBox / topology / monitoring projections (read-only), plus
one CSRF-protected, RBAC-checked, audited POST that runs a single dispatch batch.

Authorization is enforced by ``core.middleware.NmasAccessMiddleware`` from ``core.services.identity.policy`` (route names
below must be classified there) and, defence in depth, re-checked in the POST view itself.  No page echoes request text,
payload bodies or credentials -- failures are shown as fixed codes.
"""

from __future__ import annotations

from django.http import HttpResponseForbidden, JsonResponse
from django.shortcuts import redirect, render
from django.urls import NoReverseMatch, reverse
from django.views.decorators.csrf import csrf_protect
from django.views.decorators.http import require_GET, require_POST

from . import models
from .services import secret_policy
from .services.identity import policy
from .services.identity.audit import actor_for
from .services.infrastructure import dispatcher, monitoring

DISPATCH_ACTION = policy.Action.APPROVE          # same class as the lifecycle reconcile decisions (admission / management)


def _url(name: str, fallback: str) -> str:
    try:
        return reverse(f"core:{name}")
    except NoReverseMatch:
        return fallback


def overview() -> dict:
    """Everything the page shows (identifiers, states and codes only)."""
    status = dispatcher.status()
    return {
        "status": status,
        "nodes": list(models.TopologyNode.objects.values("name", "platform", "state", "last_sequence").order_by("state", "name")),
        "edges": [{"device": e.device.name, "local_interface": e.local_interface, "peer": e.peer, "peer_interface": e.peer_interface,
                   "kind": e.kind, "source": e.source, "active": e.active}
                  for e in models.TopologyEdge.objects.select_related("device").order_by("-active", "device__name", "kind")[:200]],
        "targets": [{"name": t.name, "platform": t.platform, "state": t.state, "address": t.address,
                     "management_path": t.management_path.path_id if t.management_path_id else "", "generation": t.generation,
                     "collectors": sorted(k for k, v in (t.collectors or {}).items() if v.get("enabled")),
                     "registered_at": t.registered_at, "retired_at": t.retired_at}
                    for t in models.MonitoringTarget.objects.select_related("management_path").order_by("name")],
        "projections": [{"name": p.name, "state": p.state, "planned": (p.desired or {}).get("planned_operations", []),
                         "discrepancies": p.discrepancies, "write_enabled": (p.desired or {}).get("write_enabled", False)}
                        for p in models.NsotProjection.objects.order_by("name")],
        "exported_targets": monitoring.export_targets(),
    }


@require_GET
def infrastructure_overview(request):
    context = overview()
    context.update(dispatch_url=_url("infrastructure_dispatch", "dispatch/"), consumers=sorted(dispatcher.CONSUMERS),
                   can_dispatch=policy.user_can(request.user, DISPATCH_ACTION), json_url=_url("infrastructure_json", "api/"),
                   result=request.GET.get("result", "")[:16] if request.GET.get("result", "") in ("ok", "denied") else "")
    return render(request, "core/infrastructure/overview.html", context)


@require_GET
def infrastructure_json(request):
    data = overview()
    return JsonResponse(secret_policy.redact(data), json_dumps_params={"default": str, "sort_keys": True})


@require_POST
@csrf_protect
def infrastructure_dispatch(request):
    """Run ONE dispatch batch (optionally for one consumer).  RBAC: APPROVE.  Audited as INFRASTRUCTURE_RECONCILED."""
    if not policy.user_can(request.user, DISPATCH_ACTION):
        return HttpResponseForbidden("Not permitted.")
    consumer = request.POST.get("consumer") or None
    if consumer is not None and consumer not in dispatcher.CONSUMERS:
        return redirect(_url("infrastructure_overview", "../") + "?result=denied")
    actor = actor_for(request)
    result = dispatcher.dispatch(consumer, limit=50, actor=actor)
    models.AuditEvent.objects.create(
        event_type=models.AuditEventType.INFRASTRUCTURE_RECONCILED, object_type="LifecycleOutbox", object_id=(consumer or "all")[:64],
        actor=actor[:150], summary=f"infrastructure dispatch {consumer or 'all'}: {result['processed']} event(s)"[:255], outcome="success",
        metadata=secret_policy.redact({"consumer": consumer or "all", "processed": result["processed"], "counts": result["counts"],
                                       "codes": sorted({r["code"] for r in result["results"] if r["code"]})}))
    return redirect(_url("infrastructure_overview", "../") + "?result=ok")
