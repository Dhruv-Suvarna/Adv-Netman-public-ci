"""V2 Phase 3 pages: bootstrap networks, native-ZTP capability, ZTP sessions and their evidence.

Same conventions as ``lifecycle_views``: every mutating view is a thin CSRF POST calling one ``core.services.ztp`` function and
redirecting with stable refusal codes only; authorization comes from ``core.services.identity.policy`` (each route carries the
permission of its step).  Only ``ztp_session_contact`` / ``ztp_session_verify`` contact a device -- over the isolated bootstrap
network by SSH with a pinned host key -- and only the network apply / rollback views write the ISOLATED DHCP provider.  There
is no production-admission or commissioning action here.
"""

from __future__ import annotations

from django.http import Http404, JsonResponse
from django.shortcuts import render
from django.urls import reverse
from django.views.decorators.http import require_GET, require_POST

from . import models
from .lifecycle_views import _back, _device_or_404, _refusals
from .services.devices import authorization as authorization_service
from .services.devices.codes import blocker
from .services.identity.audit import actor_for as _actor
from .services.ztp import adapters, dependencies, discovery, policy, workflow


class _Codes:
    """A refusal list in the shape ``lifecycle_views._back`` expects."""

    def __init__(self, blockers):
        self.ok = not blockers
        self.codes = [b["code"] for b in blockers]


def _network_or_404(name):
    network = models.BootstrapNetwork.objects.filter(name=name).first()
    if network is None:
        raise Http404("Unknown bootstrap network.")
    return network


def _session_or_404(device, session_id):
    session = workflow.get_session(session_id)
    if session is None or session.device_id != device.pk:
        raise Http404("Unknown ZTP session.")
    return session


def device_panel(device) -> dict:
    """Context for the device page's native-ZTP card (NMAS database only; no device contact)."""
    adapter = adapters.for_platform(device.platform)
    networks = list(models.BootstrapNetwork.objects.filter(state=models.BootstrapNetworkState.ACTIVE).order_by("name"))
    approved = [a for a in device.bootstrap_authorizations.select_related("attachment").order_by("-id") if a.state == "APPROVED"]
    sessions = list(device.ztp_sessions.select_related("network", "authorization").order_by("-id")[:10])
    open_session = next((s for s in sessions if s.is_open), None)
    paths = []
    for auth in approved[:1]:
        for network in networks:
            paths.append({"auth": auth.auth_id, "network": network.name,
                          "checks": dependencies.evaluate(device, auth.attachment, network)})
    return {"adapter": adapter.describe() if adapter else None, "networks": networks, "approved": approved, "sessions": sessions,
            "open": workflow.status(open_session) if open_session else None, "open_session": open_session, "paths": paths,
            "downstream": dependencies.downstream_waiting(device)}


# --- pages ----------------------------------------------------------------------------------------------------------------------
@require_GET
def ztp_networks(request):
    networks = list(models.BootstrapNetwork.objects.order_by("name"))
    rows = [{"network": n, "current": policy.policy_current(n), "last": n.applications.order_by("-id").first(),
             "leases": list(n.lease_observations.order_by("-last_seen")[:15])} for n in networks]
    context = {"page_title": "Bootstrap networks (native ZTP)", "page_key": "automation", "rows": rows,
               "adapters": adapters.capability_report(), "providers": models.DhcpProviderKind.choices,
               "refusals": _refusals(request.GET.get("codes", ""))}
    return render(request, "core/provisioning/ztp_networks.html", context)


@require_GET
def ztp_adapters_json(request):
    return JsonResponse({"adapters": adapters.capability_report()})


@require_GET
def ztp_session_json(request, device_id, session_id):
    device = _device_or_404(device_id)
    return JsonResponse(workflow.status(_session_or_404(device, session_id)))


# --- bootstrap networks ---------------------------------------------------------------------------------------------------------
@require_POST
def ztp_network_create(request):
    post = request.POST
    relays = []
    for line in post.get("trusted_relays", "").splitlines():
        address, _, upstream = line.strip().partition("=")
        if address:
            relays.append({"relay_address": address.strip(), "upstream_device": upstream.strip()})
    _row, problems = policy.create_network(
        actor=_actor(request), name=post.get("name", ""), provider=post.get("provider", "ISC_DHCP"), ipv4_prefix=post.get("ipv4_prefix", ""),
        gateway=post.get("gateway", ""), pool_start=post.get("pool_start", ""), pool_end=post.get("pool_end", ""),
        service_prefix=post.get("service_prefix", ""), service_address=post.get("service_address", ""), vlan=post.get("vlan") or None,
        trusted_relays=relays, config_root=post.get("config_root", ""), lease_file=post.get("lease_file", ""),
        http_port=post.get("http_port") or 8080)
    return _back(reverse("core:ztp_networks"), _Codes(problems))


def _network_action(request, name, function):
    network = _network_or_404(name)
    _row, problems = function(network, actor=_actor(request))
    return _back(reverse("core:ztp_networks"), _Codes(problems))


@require_POST
def ztp_network_validate(request, name):
    return _network_action(request, name, policy.validate_policy)


@require_POST
def ztp_network_apply(request, name):
    return _network_action(request, name, policy.apply_policy)


@require_POST
def ztp_network_rollback(request, name):
    return _network_action(request, name, policy.rollback_policy)


@require_POST
def ztp_network_ingest(request, name):
    network = _network_or_404(name)
    try:
        discovery.ingest(network)
        problems = []
    except Exception:  # pylint: disable=broad-exception-caught  # noqa: BLE001 - an unreadable lease database is reported, never shown as discovery
        problems = [blocker("DHCP_PROVIDER_ERROR")]
    return _back(reverse("core:ztp_networks"), _Codes(problems))


# --- sessions -------------------------------------------------------------------------------------------------------------------
@require_POST
def ztp_session_open(request, device_id):
    device = _device_or_404(device_id)
    auth = authorization_service.get_authorization(request.POST.get("auth_id", ""))
    network = models.BootstrapNetwork.objects.filter(name=request.POST.get("network", ""), state="ACTIVE").first()
    return _back(device.get_absolute_url(), workflow.open_session(device, authorization=auth, network=network, actor=_actor(request)))


@require_POST
def ztp_session_cancel(request, device_id, session_id):
    device = _device_or_404(device_id)
    session = _session_or_404(device, session_id)
    return _back(device.get_absolute_url(), workflow.cancel_session(session, actor=_actor(request), reason=request.POST.get("reason", "")))


@require_POST
def ztp_session_contact(request, device_id, session_id):
    device = _device_or_404(device_id)
    return _back(device.get_absolute_url(), workflow.contact_management(_session_or_404(device, session_id), actor=_actor(request)))


@require_POST
def ztp_session_enroll(request, device_id, session_id):
    device = _device_or_404(device_id)
    session = _session_or_404(device, session_id)
    result = workflow.enroll_host_key(session, fingerprint=request.POST.get("fingerprint", ""), actor=_actor(request),
                                      basis=request.POST.get("basis", ""))
    return _back(device.get_absolute_url(), result)


@require_POST
def ztp_session_verify(request, device_id, session_id):
    device = _device_or_404(device_id)
    return _back(device.get_absolute_url(), workflow.verify_management(_session_or_404(device, session_id), actor=_actor(request)))


@require_POST
def ztp_session_fail_device(request, device_id, session_id):
    device = _device_or_404(device_id)
    if request.POST.get("confirm_name", "") != device.name:
        return _back(device.get_absolute_url(), codes="AUTHORIZATION_CONFIRMATION_MISMATCH")
    return _back(device.get_absolute_url(), workflow.fail_device(_session_or_404(device, session_id), actor=_actor(request)))
