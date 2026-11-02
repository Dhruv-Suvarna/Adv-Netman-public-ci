"""
Phase 3 views: page shells only.

Every view below is a thin adapter that calls exactly one function in
core/services/ and renders a template. No view in this module performs
Netmiko/pynetbox/subprocess/InfluxDB access, and none decides or mutates
network state -- see docs/DJANGO_UI_FOUNDATION.md ("Service-layer
boundary") for the architectural rule this enforces.
"""

from __future__ import annotations

import json
import re
from urllib.parse import parse_qs, quote, urlencode, urlsplit

import yaml
from django.core.paginator import Paginator
from django.http import Http404, HttpResponse, HttpResponseBadRequest, JsonResponse
from django.shortcuts import redirect, render
from django.urls import reverse
from django.utils.http import url_has_allowed_host_and_scheme
from django.views.decorators.http import require_GET, require_POST

from . import models, theme_registry
from .services import (
    automation_service,
    bootstrap_service,
    bundle_service,
    candidate_renderer,
    credential_service,
    change_service,
    change_plan_service,
    change_validation_service,
    device_builder_service,
    field_commit_service,
    field_registry,
    health_service,
    interface_intent_service,
    device_builder_ipam_service,
    execution_service,
    intent_service,
    monitoring_service,
    network_config_validation,
    notification_service,
    nsot_service,
    platform_drivers,
    provisioning_service,
    raw_configlet_service,
    routing_intent_service,
    service_policy_intent_service,
    topology_service,
    traffic_service,
    soak_service,
    workbench_service,
)
from .services.capabilities import registry as capability_registry
from .services.config_import import service as config_import_service
from .services.configuration_validation import service as configuration_validation_service
from .services.config_templates import clone as template_clone
from .services.config_templates import features as template_features
from .services.config_templates import package as template_package
from .services.config_templates import service as template_service
from .services.execution import transport_capability
from .services.identity.audit import actor_for as _actor

# V2 Phase 1: every browser-originated action is attributed to the AUTHENTICATED website user (``_actor(request)``),
# never to a hard-coded "<area>-operator" label.  Non-human principals (collectors, the execution engine, schedulers)
# keep their explicit service identities inside the services themselves.


def home(request):
    context = {
        "page_title": "Home",
        "topology": topology_service.get_topology_summary(),
        "sections": [
            {
                "label": "Monitoring",
                "url_name": "core:monitoring_landing",
                "description": (
                    "Fleet resource health, link events, and link "
                    "state/traffic, backed by the existing SNMP/gNMI/"
                    "syslog/InfluxDB/Grafana pipeline. Django supplies "
                    "validated controls and authenticated dashboard links."
                ),
            },
            {
                "label": "Device Builder",
                "url_name": "core:device_builder",
                "description": (
                    "Future guided device configuration intent capture and "
                    "candidate generation (Phases 8/9). No engine exists yet."
                ),
            },
            {
                "label": "NSOT",
                "url_name": "core:nsot",
                "description": (
                    "Read-only aggregation of device/interface/VLAN/prefix "
                    "inventory across NetBox, Git, live devices, and "
                    "topology. NetBox remains passive storage."
                ),
            },
            {
                "label": "Automation",
                "url_name": "core:automation_landing",
                "description": (
                    "Future fleet health, change management, rollback, "
                    "soak, history, and troubleshooting workflows. No "
                    "action in this area mutates live devices yet."
                ),
            },
        ],
    }
    return render(request, "core/home.html", context)


@require_GET
def topology_data(request):
    """Same-origin, GET-only projection of the existing topology service."""
    summary = topology_service.get_topology_summary()
    if summary["status"] != "available":
        return JsonResponse(
            {"status": "unavailable", "message": summary["message"]},
            status=503,
        )
    return JsonResponse(summary["data"])


def monitoring_landing(request):
    context = monitoring_service.get_monitoring_landing_context()
    return render(request, "core/monitoring/landing.html", context)


def _monitoring_subpage(request, dashboard_key, template_name):
    context = monitoring_service.get_monitoring_page_context(
        dashboard_key,
        request.GET,
        reset_url=request.path,
        embedding_origin=request.build_absolute_uri("/").rstrip("/"),
    )
    return render(request, template_name, context)


def monitoring_resources(request):
    return _monitoring_subpage(request, "resources", "core/monitoring/resources.html")


def monitoring_link_events(request):
    return _monitoring_subpage(request, "link_events", "core/monitoring/link_events.html")


def monitoring_link_state_traffic(request):
    return _monitoring_subpage(request, "link_state_traffic", "core/monitoring/link_state_traffic.html")


def device_builder(request):
    context = {
        "page_title": "Device Builder",
        "summary": device_builder_service.get_device_builder_summary(),
    }
    return render(request, "core/device_builder.html", context)


@require_GET
def device_builder_changes(request):
    """
    Phase 8 read-only inspection page: lists Changes recorded so far. No
    Push/Deploy control exists anywhere on this page or its detail page --
    there is no deployment engine yet.
    """
    changes = list(change_service.list_changes())
    for change in changes:
        change.can_delete_draft = change_service.can_delete_draft(change)
    context = {
        "page_title": "Changes",
        "changes": changes,
        "deleted": request.GET.get("deleted", "")[:32],
    }
    return render(request, "core/device_builder/changes.html", context)


@require_GET
def device_builder_change_detail(request, change_id):
    change = change_service.get_change_or_404(change_id)
    latest_plan = change_plan_service.get_latest_plan(change)
    context = {
        "page_title": change.change_id,
        "change": change,
        "targets": change.targets.all(),
        "device_intents": change.device_intents.all().prefetch_related("revisions"),
        "configlets": change.configlets.filter(plan__isnull=True).prefetch_related("dependencies__depends_on"),
        "lifecycle_events": change.lifecycle_events.all(),
        "can_delete_draft": change_service.can_delete_draft(change),
        "delete_error": request.GET.get("delete_error", "")[:300],
        "network_config_currency": network_config_validation.get_currency(change),
        "latest_whole_validation": change_validation_service.get_latest_validation(change),
        "whole_validation_currency": change_validation_service.get_validation_currency(change, check_sources=False),
        "latest_plan": latest_plan,
        "plan_currency": change_plan_service.get_plan_currency(latest_plan, check_sources=False) if latest_plan else None,
        "latest_precheck": health_service.latest_run(mode="CHANGE_PRECHECK", change=change),
        "latest_execution": execution_service.latest_run(change),
        "configuration_validation": configuration_validation_service.panel(change),
    }
    return render(request, "core/device_builder/change_detail.html", context)


@require_POST
def device_builder_delete_change(request, change_id):
    """Explicit, application-state-only abandonment of a never-executed
    DRAFT Change -- see change_service.delete_draft_change. Never touches a
    device, NetBox, or a Golden/Probation/UAT bundle."""
    change = change_service.get_change_or_404(change_id)
    try:
        change_service.delete_draft_change(
            change=change,
            confirmation=request.POST.get("confirmation", ""),
            actor=_actor(request),
        )
    except change_service.DraftDeletionError as exc:
        return redirect(f"{reverse('core:device_builder_change_detail', args=[change_id])}?delete_error={quote(str(exc)[:300])}")
    return redirect(f"{reverse('core:device_builder_changes')}?deleted={quote(change_id)}")


# =============================================================================
# Phase 9 -- interactive Device Builder editing shell.
#
# Typing never reaches any of these views: the browser mutates only its own
# JS state (see static/core/js/device_builder.js). Only an explicit
# Enter/Commit action calls device_builder_field_commit, and only an
# explicit "Create Draft Change" / "Add Device Intent" submit calls the two
# creation views below. None of this performs a NetBox/Git/GitHub/live-
# device request -- see docs/DEVICE_BUILDER_FOUNDATION.md.
# =============================================================================

_SAFE_FILENAME_RE = re.compile(r"[^A-Za-z0-9_-]")


def _safe_filename_component(value: str) -> str:
    return _SAFE_FILENAME_RE.sub("_", value) or "device"


def _create_intent_from_post(request, change: models.Change):
    """Shared by device_builder_create_change and device_builder_create_intent
    -- both accept the same four POST fields and either return a redirect
    into the editor (on success) or None (caller decides the fallback)."""
    device_name = request.POST.get("device_name", "").strip()
    platform = request.POST.get("platform", "")
    target_type = request.POST.get("target_type", models.DeviceIntentTargetType.EXISTING_DEVICE)
    image_reference = request.POST.get("image_reference", "").strip()

    if not device_name or platform not in models.Platform.values:
        return None
    if target_type not in models.DeviceIntentTargetType.values:
        target_type = models.DeviceIntentTargetType.EXISTING_DEVICE

    intent, _ = intent_service.create_or_get_device_intent(
        change=change,
        device_name=device_name,
        platform=platform,
        target_type=target_type,
        image_reference=image_reference,
    )
    revision = intent.latest_revision()
    if revision is None:
        revision = intent_service.create_candidate_revision(device_intent=intent)
        field_commit_service.seed_device_identity_field_states(intent=intent, revision=revision)
    return redirect("core:device_builder_edit", change_id=change.change_id, intent_id=intent.pk)


@require_POST
def device_builder_create_change(request):
    """
    Creates a draft Change (application state only -- no NetBox object, no
    topology change, no CI start). If a valid device_name/platform were
    also supplied, immediately creates the first DeviceIntent + its initial
    CandidateRevision and redirects into the Basic editor; otherwise lands
    on the read-only Change detail page so the operator can add an intent
    from there (see device_builder_create_intent).
    """
    title = request.POST.get("title", "").strip() or "Untitled draft"
    change = change_service.create_change(title=title, created_by=_actor(request))

    redirect_response = _create_intent_from_post(request, change)
    if redirect_response is not None:
        return redirect_response
    return redirect("core:device_builder_change_detail", change_id=change.change_id)


@require_POST
def device_builder_create_intent(request, change_id):
    """Adds a DeviceIntent to an existing draft Change (the "Continue Existing Draft" path)."""
    change = change_service.get_change_or_404(change_id)
    redirect_response = _create_intent_from_post(request, change)
    if redirect_response is not None:
        return redirect_response
    return redirect("core:device_builder_change_detail", change_id=change.change_id)


def _management_editor_context(intent, revision) -> dict:
    from .management_views import editor_context        # imported here: management_views imports this module's helpers

    return editor_context(intent, revision)


def _resolve_editor_target(change_id, intent_id):
    change = change_service.get_change_or_404(change_id)
    intent = field_commit_service.resolve_intent(change=change, intent_id=intent_id)
    try:
        revision = field_commit_service.resolve_active_revision(intent)
    except field_commit_service.RevisionMissingError as exc:
        raise Http404(str(exc)) from exc
    return change, intent, revision


def _editor_bootstrap(change, intent, revision) -> dict:
    field_states = {
        field_state.path: {
            "draftValue": field_state.draft_value,
            "acceptedValue": field_state.accepted_value,
            "dirty": field_state.dirty,
            "validationState": field_state.validation_state,
            "validationMessage": field_state.validation_message,
        }
        for field_state in revision.field_states.all()
    }
    candidate = candidate_renderer.render(intent, revision)
    return {
        "changeId": change.change_id,
        "intentId": intent.pk,
        "revisionId": revision.pk,
        "targetType": intent.target_type,
        "fieldStates": field_states,
        "fieldPaths": list(field_registry.FIELD_REGISTRY.keys()),
        "candidate": candidate,
        "commitUrl": reverse("core:device_builder_field_commit", args=[change.change_id, intent.pk]),
        "diffUrl": reverse("core:device_builder_candidate_diff", args=[change.change_id, intent.pk]),
        "interfaceTypeChoices": platform_drivers.implemented_interface_choices(intent.platform),
        "platformWarning": bool(interface_intent_service.ordered_interfaces(revision))
        or service_policy_intent_service.has_incompatible_intent(revision=revision, platform=intent.platform),
        "routingFamilySelectable": {
            family: _routing_family_selectable(intent.platform, family) for family in routing_intent_service.PROTOCOL_FAMILIES
        },
    }


_LOCKED_MODULES = []
_ROUTING_FAMILY_LABELS = {
    "static_routes": "Static Routes", "rip": "RIP", "ospf": "OSPF",
    "isis": "IS-IS", "eigrp": "EIGRP", "bgp": "BGP",
}
_ROUTING_FAMILY_PROTOCOLS = {
    "static_routes": (platform_drivers.RoutingProtocol.STATIC_IPV4, platform_drivers.RoutingProtocol.STATIC_IPV6),
    "rip": (platform_drivers.RoutingProtocol.RIPV2, platform_drivers.RoutingProtocol.RIPNG),
    "ospf": (platform_drivers.RoutingProtocol.OSPFV2, platform_drivers.RoutingProtocol.OSPFV3),
    "isis": (platform_drivers.RoutingProtocol.ISIS,),
    "eigrp": (platform_drivers.RoutingProtocol.EIGRP_IPV4, platform_drivers.RoutingProtocol.EIGRP_IPV6),
    "bgp": (platform_drivers.RoutingProtocol.BGP_IPV4, platform_drivers.RoutingProtocol.BGP_IPV6),
}


def _routing_family_selectable(platform: str, family: str) -> bool:
    return any(
        platform_drivers.is_routing_protocol_selectable(platform, protocol)
        for protocol in _ROUTING_FAMILY_PROTOCOLS[family]
    )


def _template_safe_key(path: str) -> str:
    return path.replace(".", "_")


def _editor_view(request, change_id, intent_id, *, mode: str, template: str):
    change, intent, revision = _resolve_editor_target(change_id, intent_id)
    bootstrap = _editor_bootstrap(change, intent, revision)
    # Template-safe view of current ACCEPTED field values (Django template dot
    # lookup can't address a dict key that itself contains a literal "."), so
    # inputs are pre-filled from the real IntentFieldState accepted_value --
    # never from intent.device_name, which intentionally does NOT get
    # rewritten by a hostname commit (see docs/DEVICE_BUILDER_FOUNDATION.md).
    field_initial = {
        _template_safe_key(path): fs["acceptedValue"] for path, fs in bootstrap["fieldStates"].items()
    }
    interfaces = interface_intent_service.editor_interfaces(revision=revision, platform=intent.platform)
    selected_id = request.GET.get("interface", "")
    selected_interface = next((item for item in interfaces if item["id"] == selected_id), None)
    if selected_interface is None and interfaces:
        selected_interface = interfaces[0]
    if selected_interface:
        for address in selected_interface["addresses"]:
            address["ipam_url"] = reverse(
                "core:device_builder_ipam_prefixes",
                args=[change.change_id, intent.pk, selected_interface["id"], address["id"]],
            )
    selected_query = f"?{urlencode({'interface': selected_interface['id']})}" if selected_interface else ""

    routing_summary = routing_intent_service.editor_routing_summary(revision=revision, platform=intent.platform)
    phase12_summary = service_policy_intent_service.editor_summary(revision=revision, platform=intent.platform)
    selected_routing_family = request.GET.get("routing_family") or "static_routes"
    if selected_routing_family not in routing_intent_service.PROTOCOL_FAMILIES:
        selected_routing_family = "static_routes"
    selected_routing_instance = None
    if selected_routing_family != "static_routes":
        candidates = routing_summary[selected_routing_family]
        selected_instance_id = request.GET.get("routing_instance", "")
        selected_routing_instance = next((item for item in candidates if item["id"] == selected_instance_id), None)
        if selected_routing_instance is None and candidates:
            selected_routing_instance = candidates[0]

    context = {
        "page_title": f"{'Advanced' if mode == 'advanced' else 'Edit'}: {intent.device_name}",
        "change": change,
        "intent": intent,
        "revision": revision,
        "mode": mode,
        "bootstrap": bootstrap,
        "field_initial": field_initial,
        "target_type_choices": models.DeviceIntentTargetType.choices,
        "platform_choices": models.Platform.choices,
        "interfaces": interfaces,
        "selected_interface": selected_interface,
        "implemented_interface_choices": platform_drivers.implemented_interface_choices(intent.platform),
        "address_family_choices": (("IPV4", "IPv4"), ("IPV6", "IPv6")),
        "address_source_choices": (("MANUAL", "MANUAL"), ("AUTO", "AUTO (IPAM-assisted, unresolved)")),
        "has_incompatible_interfaces": any(not item["is_compatible"] for item in interfaces)
        or service_policy_intent_service.has_incompatible_intent(revision=revision, platform=intent.platform),
        "collection_error": request.GET.get("collection_error", "")[:300],
        "locked_modules": _LOCKED_MODULES,
        "routing_summary": routing_summary,
        "routing_family_labels": list(_ROUTING_FAMILY_LABELS.items()),
        "selected_routing_family": selected_routing_family,
        "selected_routing_instance": selected_routing_instance,
        "routing_family_selectable": {
            family: _routing_family_selectable(intent.platform, family) for family in routing_intent_service.PROTOCOL_FAMILIES
        },
        "phase12": phase12_summary,
        **_management_editor_context(intent, revision),
        "service_policy_supported": {
            feature.value: platform_drivers.is_service_policy_feature_selectable(intent.platform, feature)
            for feature in platform_drivers.ServicePolicyFeature
        },
        "static_route_add_url": reverse("core:device_builder_static_route_add", args=[change.change_id, intent.pk]),
        "routing_instance_add_url": reverse(
            "core:device_builder_routing_instance_add", args=[change.change_id, intent.pk, selected_routing_family]
        ) if selected_routing_family != "static_routes" else "",
        "routing_binding_add_url": (
            reverse(
                "core:device_builder_routing_binding_add",
                args=[change.change_id, intent.pk, selected_routing_family, selected_routing_instance["id"]],
            )
            if selected_routing_instance and selected_routing_family in routing_intent_service.BINDING_FAMILIES
            else ""
        ),
        "bgp_neighbor_add_url": (
            reverse("core:device_builder_bgp_neighbor_add", args=[change.change_id, intent.pk, selected_routing_instance["id"]])
            if selected_routing_instance and selected_routing_family == "bgp" else ""
        ),
        "bgp_network_add_url": (
            reverse("core:device_builder_bgp_network_add", args=[change.change_id, intent.pk, selected_routing_instance["id"]])
            if selected_routing_instance and selected_routing_family == "bgp" else ""
        ),
        "ospf_network_add_url": (
            reverse("core:device_builder_ospf_network_add", args=[change.change_id, intent.pk, selected_routing_instance["id"]])
            if selected_routing_instance and selected_routing_family == "ospf"
            and selected_routing_instance.get("version") == "OSPFV2" else ""
        ),
        "basic_url": reverse("core:device_builder_edit", args=[change.change_id, intent.pk]) + selected_query,
        "advanced_url": reverse("core:device_builder_advanced", args=[change.change_id, intent.pk]) + selected_query,
        "download_url": reverse("core:device_builder_candidate_download", args=[change.change_id, intent.pk]),
        "diff_url": reverse("core:device_builder_candidate_diff", args=[change.change_id, intent.pk]),
        "can_import_existing_config": intent.target_type == models.DeviceIntentTargetType.EXISTING_DEVICE,
        "import_error": request.GET.get("import_error", "")[:300],
        "import_notice": request.GET.get("import_notice", "")[:300],
        "import_provenance": (revision.sections or {}).get("_import", {}).get("provenance"),
        "import_unmanaged_blocks": (revision.sections or {}).get("_import", {}).get("unmanaged") or [],
        "template_clone": (revision.metadata or {}).get("template_clone") or {},
    }
    return render(request, template, context)


@require_POST
def device_builder_import_existing_config(request, change_id, intent_id):
    """Explicit, operator-triggered, READ-ONLY existing-device import (spec
    sections 10-12): fetch the device's complete running configuration,
    parse the features this project understands into the same canonical
    model Device Builder edits, and preserve everything else immutably.
    Never triggered by a page load; never mutates the device; a failed fetch
    changes nothing about the draft."""
    change, intent, revision = _resolve_editor_target(change_id, intent_id)
    editor_url = reverse("core:device_builder_edit", args=[change.change_id, intent.pk])
    if intent.target_type != models.DeviceIntentTargetType.EXISTING_DEVICE:
        return redirect(f"{editor_url}?import_error={quote('Import is only available for an Existing Device intent.')}")
    result = config_import_service.import_existing_device(
        change=change, intent=intent, revision=revision, device_name=intent.device_name,
    )
    if result.status != "imported":
        return redirect(f"{editor_url}?import_error={quote(result.message[:300])}")
    notice = (
        f"Imported {result.interfaces_imported} interface(s) from the live device. "
        f"{result.unmanaged_block_count} configuration block(s) could not be imported and are preserved read-only."
    )
    return redirect(f"{editor_url}?import_notice={quote(notice)}")


@require_GET
def device_builder_edit(request, change_id, intent_id):
    """Basic editor: minimum/common Device Identity fields inline."""
    return _editor_view(request, change_id, intent_id, mode="basic", template="core/device_builder/editor.html")


@require_GET
def device_builder_advanced(request, change_id, intent_id):
    """
    Advanced editor: operates on the exact same DeviceIntent/CandidateRevision/
    IntentFieldState records as Basic -- there is no second AdvancedIntent
    model or copy of the state. A commit made here is immediately visible on
    Basic, and vice versa, because both simply re-render the same rows.
    """
    return _editor_view(request, change_id, intent_id, mode="advanced", template="core/device_builder/editor.html")


@require_POST
def device_builder_field_commit(request, change_id, intent_id):
    """
    The narrow, explicit mutation endpoint every field commit goes through.
    Never called on typing -- only on Enter/explicit Commit (see
    device_builder.js). Runs Tier-1 validation only; no NetBox/Git/GitHub/
    device call occurs here.
    """
    change, intent, revision = _resolve_editor_target(change_id, intent_id)

    try:
        payload = json.loads(request.body.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return JsonResponse({"ok": False, "message": "Malformed request body."}, status=400)

    path = payload.get("path")
    raw_value = payload.get("value")
    submitted_revision_id = payload.get("revisionId")
    if submitted_revision_id is not None:
        try:
            submitted_revision_id = int(submitted_revision_id)
        except (TypeError, ValueError):
            return JsonResponse({"ok": False, "message": "Invalid revision identifier."}, status=400)
        if submitted_revision_id != revision.pk:
            return JsonResponse({"ok": False, "message": "Stale revision -- reload the page."}, status=409)

    try:
        field_state = field_commit_service.commit_field(
            change=change, intent=intent, revision=revision, path=path, raw_value=raw_value
        )
    except field_commit_service.UnknownFieldPathError as exc:
        return JsonResponse({"ok": False, "message": str(exc)}, status=400)
    except field_commit_service.RecordOwnershipError as exc:
        return JsonResponse({"ok": False, "message": str(exc)}, status=403)

    intent.refresh_from_db()
    candidate = candidate_renderer.render(intent, revision)
    interfaces = interface_intent_service.ordered_interfaces(revision)
    return JsonResponse(
        {
            "ok": field_state.validation_state == models.FieldValidationState.VALID,
            "path": field_state.path,
            "draftValue": field_state.draft_value,
            "acceptedValue": field_state.accepted_value,
            "validationState": field_state.validation_state,
            "validationMessage": field_state.validation_message,
            "candidate": candidate,
            "platformWarning": path == "device.platform" and (
                bool(interfaces)
                or service_policy_intent_service.has_incompatible_intent(revision=revision, platform=intent.platform)
            ),
            "interfaceTypeChoices": {
                interface["id"]: platform_drivers.implemented_interface_choices(
                    intent.platform, preserve_kind=interface.get("kind")
                )
                for interface in interfaces
            },
            "newInterfaceTypeChoices": platform_drivers.implemented_interface_choices(intent.platform),
            "routingFamilySelectable": {
                family: _routing_family_selectable(intent.platform, family) for family in routing_intent_service.PROTOCOL_FAMILIES
            },
        }
    )


_COLLECTION_REDIRECT_PASSTHROUGH_PARAMS = ("interface", "routing_family", "routing_instance")


def _collection_redirect(
    request, change, intent, *, interface_id="", routing_family="", routing_instance="", error="", clear=()
):
    """Return to the editor page the operator was actually on.

    Every collection mutation (add/remove interface, address, routing
    instance/binding, FHRP/NAT/ACL/PBR/DHCP object, ...) redirects back here.
    This must never silently drop the operator into Basic mode or reset their
    current interface/routing-family/routing-instance selection merely
    because they were editing in Advanced mode or a different tab -- see
    docs/DEVICE_BUILDER_FOUNDATION.md "Non-refresh editing model". The
    Referer is same-origin (the editor page that rendered the form) and is
    only used to recover which mode/selection the operator was viewing; nothing
    here trusts it for anything security-sensitive.
    """
    parsed = urlsplit(request.META.get("HTTP_REFERER", ""))
    advanced_path = reverse("core:device_builder_advanced", args=[change.change_id, intent.pk])
    basic_path = reverse("core:device_builder_edit", args=[change.change_id, intent.pk])
    target_path = advanced_path if parsed.path == advanced_path else basic_path

    params = {
        key: values[0]
        for key, values in parse_qs(parsed.query).items()
        if key in _COLLECTION_REDIRECT_PASSTHROUGH_PARAMS and values
    }
    for key in clear:
        params.pop(key, None)
    if interface_id:
        params["interface"] = interface_id
    if routing_family:
        params["routing_family"] = routing_family
    if routing_instance:
        params["routing_instance"] = routing_instance
    if error:
        params["collection_error"] = error[:300]
    return redirect(target_path + (f"?{urlencode(params)}" if params else ""))


@require_POST
def device_builder_interface_add(request, change_id, intent_id):
    change, intent, revision = _resolve_editor_target(change_id, intent_id)
    try:
        interface = interface_intent_service.add_interface(
            revision=revision,
            kind=request.POST.get("kind", ""),
            name=request.POST.get("name", "").strip(),
        )
    except interface_intent_service.CollectionMutationError as exc:
        return _collection_redirect(request, change, intent, error=str(exc))
    return _collection_redirect(request, change, intent, interface_id=interface["id"])


@require_POST
def device_builder_interface_remove(request, change_id, intent_id, interface_id):
    change, intent, revision = _resolve_editor_target(change_id, intent_id)
    try:
        interface_intent_service.remove_interface(
            revision=revision,
            interface_id=interface_id,
            confirmation=request.POST.get("confirmation", ""),
        )
    except interface_intent_service.CollectionMutationError as exc:
        return _collection_redirect(request, change, intent, interface_id=interface_id, error=str(exc))
    return _collection_redirect(request, change, intent, clear=("interface",))


@require_POST
def device_builder_address_add(request, change_id, intent_id, interface_id):
    change, intent, revision = _resolve_editor_target(change_id, intent_id)
    try:
        interface_intent_service.add_address(
            revision=revision,
            interface_id=interface_id,
            family=request.POST.get("family", "IPV4"),
            source=request.POST.get("source", "MANUAL"),
        )
    except interface_intent_service.CollectionMutationError as exc:
        return _collection_redirect(request, change, intent, interface_id=interface_id, error=str(exc))
    return _collection_redirect(request, change, intent, interface_id=interface_id)


@require_POST
def device_builder_address_remove(request, change_id, intent_id, interface_id, address_id):
    change, intent, revision = _resolve_editor_target(change_id, intent_id)
    try:
        interface_intent_service.remove_address(
            revision=revision,
            interface_id=interface_id,
            address_id=address_id,
            confirmation=request.POST.get("confirmation", ""),
        )
    except interface_intent_service.CollectionMutationError as exc:
        return _collection_redirect(request, change, intent, interface_id=interface_id, error=str(exc))
    return _collection_redirect(request, change, intent, interface_id=interface_id)


@require_POST
def device_builder_static_route_add(request, change_id, intent_id):
    change, intent, revision = _resolve_editor_target(change_id, intent_id)
    try:
        routing_intent_service.add_static_route(revision=revision, family=request.POST.get("family", "IPV4"))
    except routing_intent_service.CollectionMutationError as exc:
        return _collection_redirect(request, change, intent, error=str(exc))
    return _collection_redirect(request, change, intent)


@require_POST
def device_builder_static_route_remove(request, change_id, intent_id, route_id):
    change, intent, revision = _resolve_editor_target(change_id, intent_id)
    try:
        routing_intent_service.remove_static_route(
            revision=revision, route_id=route_id, confirmation=request.POST.get("confirmation", "")
        )
    except routing_intent_service.CollectionMutationError as exc:
        return _collection_redirect(request, change, intent, error=str(exc))
    return _collection_redirect(request, change, intent)


@require_POST
def device_builder_routing_instance_add(request, change_id, intent_id, family):
    change, intent, revision = _resolve_editor_target(change_id, intent_id)
    kwargs = {}
    if family == "rip":
        kwargs["address_family"] = request.POST.get("address_family", "IPV4")
    elif family == "ospf":
        kwargs["version"] = request.POST.get("version", "OSPFV2")
    elif family == "eigrp":
        kwargs["address_family"] = request.POST.get("address_family", "IPV4")
    elif family == "bgp":
        kwargs["local_asn"] = request.POST.get("local_asn", "")
    try:
        instance = routing_intent_service.add_protocol_instance(revision=revision, family=family, **kwargs)
    except routing_intent_service.CollectionMutationError as exc:
        return _collection_redirect(request, change, intent, routing_family=family, error=str(exc))
    return _collection_redirect(request, change, intent, routing_family=family, routing_instance=instance["id"])


@require_POST
def device_builder_routing_instance_remove(request, change_id, intent_id, family, instance_id):
    change, intent, revision = _resolve_editor_target(change_id, intent_id)
    try:
        routing_intent_service.remove_protocol_instance(
            revision=revision, family=family, instance_id=instance_id, confirmation=request.POST.get("confirmation", "")
        )
    except routing_intent_service.CollectionMutationError as exc:
        return _collection_redirect(request, change, intent, routing_family=family, error=str(exc))
    return _collection_redirect(request, change, intent, routing_family=family, clear=("routing_instance",))


@require_POST
def device_builder_routing_binding_add(request, change_id, intent_id, family, instance_id):
    change, intent, revision = _resolve_editor_target(change_id, intent_id)
    try:
        routing_intent_service.add_interface_binding(
            revision=revision, family=family, instance_id=instance_id,
            interface_id=request.POST.get("interface_id", ""),
        )
    except routing_intent_service.CollectionMutationError as exc:
        return _collection_redirect(request, change, intent, error=str(exc))
    return _collection_redirect(request, change, intent)


@require_POST
def device_builder_routing_binding_remove(request, change_id, intent_id, family, instance_id, binding_id):
    change, intent, revision = _resolve_editor_target(change_id, intent_id)
    try:
        routing_intent_service.remove_interface_binding(
            revision=revision, family=family, instance_id=instance_id, binding_id=binding_id,
            confirmation=request.POST.get("confirmation", ""),
        )
    except routing_intent_service.CollectionMutationError as exc:
        return _collection_redirect(request, change, intent, error=str(exc))
    return _collection_redirect(request, change, intent)


@require_POST
def device_builder_bgp_neighbor_add(request, change_id, intent_id, instance_id):
    change, intent, revision = _resolve_editor_target(change_id, intent_id)
    try:
        routing_intent_service.add_bgp_neighbor(
            revision=revision, instance_id=instance_id,
            peer_address=request.POST.get("peer_address", ""),
            remote_asn=request.POST.get("remote_asn", ""),
        )
    except routing_intent_service.CollectionMutationError as exc:
        return _collection_redirect(request, change, intent, error=str(exc))
    return _collection_redirect(request, change, intent)


@require_POST
def device_builder_bgp_neighbor_remove(request, change_id, intent_id, instance_id, peer_id):
    change, intent, revision = _resolve_editor_target(change_id, intent_id)
    try:
        routing_intent_service.remove_bgp_neighbor(
            revision=revision, instance_id=instance_id, peer_id=peer_id,
            confirmation=request.POST.get("confirmation", ""),
        )
    except routing_intent_service.CollectionMutationError as exc:
        return _collection_redirect(request, change, intent, error=str(exc))
    return _collection_redirect(request, change, intent)


@require_POST
def device_builder_bgp_network_add(request, change_id, intent_id, instance_id):
    change, intent, revision = _resolve_editor_target(change_id, intent_id)
    try:
        routing_intent_service.add_bgp_network(
            revision=revision, instance_id=instance_id,
            family=request.POST.get("family", "IPV4"), cidr=request.POST.get("cidr", ""),
        )
    except routing_intent_service.CollectionMutationError as exc:
        return _collection_redirect(request, change, intent, error=str(exc))
    return _collection_redirect(request, change, intent)


@require_POST
def device_builder_bgp_network_remove(request, change_id, intent_id, instance_id, net_id):
    change, intent, revision = _resolve_editor_target(change_id, intent_id)
    try:
        routing_intent_service.remove_bgp_network(
            revision=revision, instance_id=instance_id, net_id=net_id,
            confirmation=request.POST.get("confirmation", ""),
        )
    except routing_intent_service.CollectionMutationError as exc:
        return _collection_redirect(request, change, intent, error=str(exc))
    return _collection_redirect(request, change, intent)


@require_POST
def device_builder_ospf_network_add(request, change_id, intent_id, instance_id):
    change, intent, revision = _resolve_editor_target(change_id, intent_id)
    try:
        routing_intent_service.add_ospf_network(
            revision=revision, instance_id=instance_id, prefix=request.POST.get("prefix", ""),
            area=request.POST.get("area", "0"),
        )
    except routing_intent_service.CollectionMutationError as exc:
        return _collection_redirect(request, change, intent, error=str(exc))
    return _collection_redirect(request, change, intent)


@require_POST
def device_builder_ospf_network_remove(request, change_id, intent_id, instance_id, net_id):
    change, intent, revision = _resolve_editor_target(change_id, intent_id)
    try:
        routing_intent_service.remove_ospf_network(
            revision=revision, instance_id=instance_id, net_id=net_id,
            confirmation=request.POST.get("confirmation", ""),
        )
    except routing_intent_service.CollectionMutationError as exc:
        return _collection_redirect(request, change, intent, error=str(exc))
    return _collection_redirect(request, change, intent)


_PHASE12_ADD_ACTIONS = {
    "fhrp": lambda r, p: service_policy_intent_service.add_fhrp_instance(
        revision=r, protocol=p.get("protocol", "VARP"), interface_id=p.get("interface_id", ""),
        address_family=p.get("address_family", "IPV4"),
    ),
    "fhrp_vip": lambda r, p: service_policy_intent_service.add_fhrp_vip(
        revision=r, instance_id=p.get("parent_id", ""), address=p.get("address", "")
    ),
    "nat_pool": lambda r, p: service_policy_intent_service.add_nat_pool(
        revision=r, family=p.get("family", "NAT44"), name=p.get("name", "")
    ),
    "nat_rule": lambda r, p: service_policy_intent_service.add_nat_rule(
        revision=r, family=p.get("family", "NAT44"), mode=p.get("mode", "PAT")
    ),
    "dhcp_relay": lambda r, p: service_policy_intent_service.add_dhcp_relay(
        revision=r, family=p.get("family", "IPV4"), interface_id=p.get("interface_id", ""),
        destination=p.get("destination", ""),
    ),
    "dhcp_client": lambda r, p: service_policy_intent_service.add_dhcp_client(
        revision=r, family=p.get("family", "IPV4"), interface_id=p.get("interface_id", "")
    ),
    "dns_resolver": lambda r, p: service_policy_intent_service.add_dns_resolver(
        revision=r, address=p.get("address", "")
    ),
    "dns_domain": lambda r, p: service_policy_intent_service.add_dns_search_domain(
        revision=r, domain=p.get("domain", "")
    ),
    "acl": lambda r, p: service_policy_intent_service.add_acl(
        revision=r, name=p.get("name", ""), family=p.get("family", "IPV4"),
        acl_type=p.get("acl_type", "EXTENDED"),
    ),
    "ace": lambda r, p: service_policy_intent_service.add_ace(
        revision=r, acl_id=p.get("parent_id", ""), action=p.get("action", "PERMIT"),
        protocol=p.get("protocol", "IP"),
    ),
    "acl_attachment": lambda r, p: service_policy_intent_service.add_acl_attachment(
        revision=r, acl_id=p.get("acl_id", ""), interface_id=p.get("interface_id", ""),
        direction=p.get("direction", "IN"),
    ),
    "pbr": lambda r, p: service_policy_intent_service.add_pbr_policy(
        revision=r, name=p.get("name", ""), family=p.get("family", "IPV4")
    ),
    "pbr_sequence": lambda r, p: service_policy_intent_service.add_pbr_sequence(
        revision=r, policy_id=p.get("parent_id", "")
    ),
    "pbr_attachment": lambda r, p: service_policy_intent_service.add_pbr_attachment(
        revision=r, policy_id=p.get("policy_id", ""), interface_id=p.get("interface_id", ""),
        direction=p.get("direction", "IN"),
    ),
}


# The DRAFT-only guard is shared with the interface/routing services and raises
# interface_intent_service.DraftOnlyError, which is NOT a subclass of
# service_policy_intent_service.CollectionMutationError.  Both must be
# refused gracefully (a redirect with an error), never surface as an HTTP 500.
_PHASE12_MUTATION_ERRORS = (
    service_policy_intent_service.CollectionMutationError,
    interface_intent_service.CollectionMutationError,
)


@require_POST
def device_builder_phase12_add(request, change_id, intent_id, kind):
    change, intent, revision = _resolve_editor_target(change_id, intent_id)
    action = _PHASE12_ADD_ACTIONS.get(kind)
    if action is None:
        return HttpResponseBadRequest("Unknown Phase-12 collection type.")
    try:
        action(revision, request.POST)
    except _PHASE12_MUTATION_ERRORS as exc:
        return _collection_redirect(request, change, intent, error=str(exc))
    return _collection_redirect(request, change, intent)


@require_POST
def device_builder_phase12_remove(request, change_id, intent_id, kind, object_id):
    change, intent, revision = _resolve_editor_target(change_id, intent_id)
    try:
        service_policy_intent_service.remove_object(
            revision=revision, kind=kind, object_id=object_id,
            parent_id=request.POST.get("parent_id", ""), confirmation=request.POST.get("confirmation", ""),
        )
    except _PHASE12_MUTATION_ERRORS as exc:
        return _collection_redirect(request, change, intent, error=str(exc))
    return _collection_redirect(request, change, intent)


@require_POST
def device_builder_service_mode(request, change_id, intent_id, service):
    change, intent, revision = _resolve_editor_target(change_id, intent_id)
    try:
        service_policy_intent_service.set_service_mode(
            revision=revision, service=service, mode=request.POST.get("mode", "INHERIT")
        )
    except _PHASE12_MUTATION_ERRORS as exc:
        return _collection_redirect(request, change, intent, error=str(exc))
    return _collection_redirect(request, change, intent)


@require_POST
def device_builder_ipam_prefixes(request, change_id, intent_id, interface_id, address_id):
    """Explicit read-only NetBox action. Normal typing/rendering never calls it."""
    change, intent, revision = _resolve_editor_target(change_id, intent_id)
    try:
        prefixes = device_builder_ipam_service.list_prefixes_for_address(
            revision=revision, interface_id=interface_id, address_id=address_id
        )
    except interface_intent_service.CollectionMutationError as exc:
        return JsonResponse({"ok": False, "message": str(exc)}, status=400)
    except device_builder_ipam_service.IpamLookupError:
        return JsonResponse({"ok": False, "message": "NetBox prefix data is currently unavailable."}, status=503)
    return JsonResponse({
        "ok": True,
        "prefixes": prefixes,
        "allocationState": "UNRESOLVED_UNRESERVED",
        "message": "Read-only prefix list. No address was allocated or reserved.",
    })


@require_GET
def device_builder_candidate_download(request, change_id, intent_id):
    """
    Server-generated authoritative ACCEPTED candidate only -- Phase 9 does
    not offer a draft download (the server cannot know true live-browser
    keystroke state without a request-per-keystroke, which is exactly what
    this project forbids; Copy Candidate already covers "copy what I see,
    including live draft" client-side). Filename is derived only from the
    already-validated device_name -- never an arbitrary path.
    """
    change, intent, revision = _resolve_editor_target(change_id, intent_id)
    candidate = candidate_renderer.render(intent, revision)
    filename = f"{_safe_filename_component(intent.device_name)}-candidate.txt"
    response = HttpResponse(candidate["text"] + "\n", content_type="text/plain; charset=utf-8")
    response["Content-Disposition"] = f'attachment; filename="{filename}"'
    return response


@require_GET
def device_builder_candidate_diff(request, change_id, intent_id):
    """
    Accepted Candidate vs current (last-committed-attempt) Draft Candidate.
    Computed only on this explicit page load, never automatically while
    typing, and never against live running configuration.
    """
    change, intent, revision = _resolve_editor_target(change_id, intent_id)
    diff = candidate_renderer.diff_accepted_vs_draft(intent, revision)
    context = {
        "page_title": f"Diff: {intent.device_name}",
        "change": change,
        "intent": intent,
        "diff": diff,
        "basic_url": reverse("core:device_builder_edit", args=[change.change_id, intent.pk]),
    }
    return render(request, "core/device_builder/diff.html", context)


@require_GET
def device_builder_capabilities(request):
    """The fail-closed, binary operator matrix; axis nuance stays in each cell's detail."""
    context = {
        "page_title": "Platform Capabilities",
        "evidence_matrix": capability_registry.evidence_matrix(),
    }
    return render(request, "core/device_builder/capabilities.html", context)


def _refresh_requested(request) -> bool:
    return request.GET.get("refresh") == "1"


def nsot(request):
    context = nsot_service.get_overview(force_refresh=_refresh_requested(request))
    context["page_title"] = "NSOT"
    return render(request, "core/nsot/overview.html", context)


def nsot_devices(request):
    listing = nsot_service.get_devices(force_refresh=_refresh_requested(request))
    rows = listing.get("data") or []

    device_filter = request.GET.get("device", "").strip()
    role_filter = request.GET.get("role", "").strip()
    if device_filter:
        rows = [r for r in rows if device_filter.lower() in r["name"].lower()]
    if role_filter:
        rows = [r for r in rows if (r.get("role") or "").lower() == role_filter.lower()]

    paginator = Paginator(rows, 25)
    page_obj = paginator.get_page(request.GET.get("page"))

    context = {
        "page_title": "NSOT · Devices",
        "listing": listing,
        "page_obj": page_obj,
        "devices": page_obj.object_list,
        "device_filter": device_filter,
        "role_filter": role_filter,
    }
    return render(request, "core/nsot/devices.html", context)


def nsot_device_detail(request, name):
    detail = nsot_service.get_device_detail(name, force_refresh=_refresh_requested(request))
    if detail["status"] == "not_found":
        raise Http404("Unknown device")
    context = {"page_title": f"NSOT · {name}", "device_name": name, "detail": detail}
    return render(request, "core/nsot/device_detail.html", context)


@require_GET
def nsot_device_running_config(request, name):
    """Explicit, bounded, read-only live fetch -- never triggered by any
    other page load. GET-only: it retrieves data, it never mutates state."""
    result = nsot_service.fetch_device_running_config(name)
    context = {"page_title": f"NSOT · {name} · Running Config", "device_name": name, "result": result}
    return render(request, "core/nsot/running_config.html", context)


def nsot_interfaces(request):
    device_filter = request.GET.get("device", "").strip() or None
    listing = nsot_service.get_interfaces(device_filter, force_refresh=_refresh_requested(request))
    rows = listing.get("data") or []
    paginator = Paginator(rows, 25)
    page_obj = paginator.get_page(request.GET.get("page"))
    context = {
        "page_title": "NSOT · Interfaces",
        "listing": listing,
        "page_obj": page_obj,
        "interfaces": page_obj.object_list,
        "device_filter": device_filter or "",
    }
    return render(request, "core/nsot/interfaces.html", context)


def nsot_ipam(request):
    context = nsot_service.get_ipam(force_refresh=_refresh_requested(request))
    context["page_title"] = "NSOT · IPAM"
    return render(request, "core/nsot/ipam.html", context)


def nsot_vlans(request):
    listing = nsot_service.get_vlans(force_refresh=_refresh_requested(request))
    context = {"page_title": "NSOT · VLANs", "listing": listing, "vlans": listing.get("data") or []}
    return render(request, "core/nsot/vlans.html", context)


def nsot_routing(request):
    context = nsot_service.get_routing(force_refresh=_refresh_requested(request))
    context["page_title"] = "NSOT · Routing / ASN"
    return render(request, "core/nsot/routing.html", context)


def nsot_platforms(request):
    context = nsot_service.get_platforms(force_refresh=_refresh_requested(request))
    context["page_title"] = "NSOT · Platforms"
    return render(request, "core/nsot/platforms.html", context)


def nsot_templates(request):
    catalogue = nsot_service.get_templates_catalogue(force_refresh=_refresh_requested(request))
    selected_path = request.GET.get("file", "").strip()
    selected_file = nsot_service.get_template_file(selected_path) if selected_path else None
    context = {
        "page_title": "NSOT · Templates / Code",
        "catalogue": catalogue,
        "files": catalogue.get("data") or [],
        "selected_path": selected_path,
        "selected_file": selected_file,
    }
    return render(request, "core/nsot/templates_code.html", context)


def nsot_drift(request):
    context = nsot_service.get_drift(force_refresh=_refresh_requested(request))
    context["page_title"] = "NSOT · Drift / Consistency"
    return render(request, "core/nsot/drift.html", context)


def automation_landing(request):
    context = {
        "page_title": "Automation",
        "summary": automation_service.get_automation_summary(),
        "sections": automation_service.get_automation_sections(),
    }
    return render(request, "core/automation/landing.html", context)


@require_GET
def credential_status(request):
    context = credential_service.get_credential_status_context()
    context["page_title"] = "Automation · Device Credentials"
    context["page_key"] = "automation"
    return render(request, "core/automation/credentials.html", context)


@require_GET
def credential_status_json(request):
    return JsonResponse(credential_service.get_credential_status_context())


def automation_section(request, slug):
    section = automation_service.get_automation_section(slug)
    if section is None:
        raise Http404("Unknown automation section")
    context = {
        "page_title": f"Automation · {section['label']}",
        "summary": automation_service.get_automation_summary(),
        "section": section,
    }
    return render(request, "core/automation/section.html", context)


def notifications(request):
    unread_only = request.GET.get("unread") == "1"
    severity = request.GET.get("severity") or None
    event_type = request.GET.get("event_type") or None

    queryset = notification_service.list_notifications(
        unread_only=unread_only, severity=severity, event_type=event_type
    )
    paginator = Paginator(queryset, 25)
    page_obj = paginator.get_page(request.GET.get("page"))

    querystring = request.GET.copy()
    querystring.pop("page", None)

    context = {
        "page_title": "Notifications",
        "notifications": page_obj.object_list,
        "page_obj": page_obj,
        "querystring": querystring.urlencode(),
        "unread_only": unread_only,
        "selected_severity": severity,
        "selected_event_type": event_type,
        "severity_choices": notification_service.severity_choices(),
        "event_type_choices": notification_service.event_type_choices(),
        "unread_count": notification_service.get_unread_count(),
        "max_dropdown": notification_service.MAX_DROPDOWN_NOTIFICATIONS,
    }
    return render(request, "core/notifications.html", context)


def notification_detail(request, pk):
    notification = notification_service.get_notification_or_404(pk)
    context = {
        "page_title": f"Notification · {notification.title}",
        "notification": notification,
    }
    return render(request, "core/notification_detail.html", context)


@require_POST
def notification_mark_read(request, pk):
    notification_service.mark_read(pk)
    next_url = request.POST.get("next") or reverse("core:notification_detail", args=[pk])
    return redirect(next_url)


@require_POST
def notification_mark_all_read(request):
    notification_service.mark_all_read()
    next_url = request.POST.get("next") or reverse("core:notifications")
    return redirect(next_url)


@require_POST
def notification_retry_slack(request, pk):
    notification_service.retry_slack_delivery(pk)
    next_url = request.POST.get("next") or reverse("core:notification_detail", args=[pk])
    return redirect(next_url)


def profile(request):
    return render(request, "core/profile.html", {"page_title": "Profile"})


@require_POST
def set_theme(request):
    """
    Persists the chosen top-level theme in a cookie and redirects back to
    the referring page. No database write, no session dependency -- see
    settings.THEME_COOKIE_NAME.
    """
    from django.conf import settings

    theme_name = theme_registry.resolve_theme(request.POST.get("theme"))
    next_url = request.POST.get("next") or "/"
    if not url_has_allowed_host_and_scheme(next_url, allowed_hosts={request.get_host()}, require_https=request.is_secure()):
        next_url = "/"  # V2 Phase 1: never an open redirect
    response = redirect(next_url)
    response.set_cookie(
        settings.THEME_COOKIE_NAME,
        theme_name,
        max_age=settings.THEME_COOKIE_MAX_AGE,
        samesite="Lax",
    )
    return response


# =============================================================================
# Phase 13 -- Tier-2 project-aware Change validation UI.
#
# Every view is a thin adapter over core.services.change_validation_service:
# resolve the Change, authorize the HTTP method, call the service, render.
# GET never persists anything; only the explicit POST "Run Change Validation"
# appends a validation run.  Validation uses committed/accepted intent only.
# =============================================================================

def _validation_page(request, change, run, *, historical: bool):
    check_sources = request.GET.get("check_sources") == "1"
    currency = change_validation_service.get_validation_currency(change, check_sources=check_sources)
    document = change_validation_service.serialize_validation_run(run) if run is not None else None
    filters = {
        "severity": request.GET.get("severity", ""),
        "category": request.GET.get("category", ""),
        "device": request.GET.get("device", ""),
        "blocking": request.GET.get("blocking") == "1",
    }
    findings, devices = [], []
    if document is not None:
        findings = change_validation_service.filter_findings(
            document["findings"], severity=filters["severity"], category=filters["category"],
            device=filters["device"], blocking_only=filters["blocking"],
        )
        devices = sorted({f["device"] for f in document["findings"] if f.get("device")})
    context = {
        "page_title": f"Validation: {change.change_id}",
        "change": change,
        "run": run,
        "document": document,
        "historical": historical,
        "is_latest": run is not None and run == currency.get("latest"),
        "currency": currency,
        "sources_checked": currency["sources_checked"],
        "history": change_validation_service.list_validation_runs(change),
        "findings": findings,
        "filters": filters,
        "filter_devices": devices,
        "dependency_rows": change_validation_service.dependency_rows(document["dependency_graph"]) if document else [],
        "auto_facts": [f for f in (document["derived_facts"] if document else []) if f.get("type") == "AUTO_ADDRESS"],
        "other_facts": [f for f in (document["derived_facts"] if document else []) if f.get("type") != "AUTO_ADDRESS"],
        "severities": change_validation_service.SEVERITIES,
        "categories": change_validation_service.CATEGORIES,
        "configuration_validation": configuration_validation_service.panel(change),
    }
    return render(request, "core/device_builder/validation.html", context)


@require_GET
def change_validation(request, change_id):
    change = change_service.get_change_or_404(change_id)
    return _validation_page(
        request, change, change_validation_service.get_latest_validation(change), historical=False
    )


@require_GET
def change_validation_detail(request, change_id, run_id):
    change = change_service.get_change_or_404(change_id)
    run = change_validation_service.get_validation_run(change, run_id)
    if run is None:
        raise Http404("No such validation run for this Change.")
    return _validation_page(request, change, run, historical=True)


@require_POST
def change_validation_run(request, change_id):
    """Explicit operator action.  Ignores every POST field: sources, paths and
    URLs are fixed server-side and never taken from the browser."""
    change = change_service.get_change_or_404(change_id)
    change_validation_service.validate_change(change, actor=_actor(request))
    return redirect("core:change_validation", change_id=change.change_id)


@require_GET
def change_configuration_validation(request, change_id):
    """The GitHub Actions Configuration Validation of a Change: its own page, distinct from Tier-2 Change Validation.
    Viewing it reconciles runs that still owe a result (an outbound GitHub read; no device, no NetBox)."""
    change = change_service.get_change_or_404(change_id)
    return render(request, "core/device_builder/configuration_validation.html", {
        "page_title": f"Configuration Validation: {change.change_id}", "change": change,
        "configuration_validation": configuration_validation_service.panel(change)})


@require_POST
def change_configuration_validation_refresh(request, change_id):
    """Explicit operator action: read this Change's Configuration Validation results from GitHub now.  Ignores every POST
    field; dispatches nothing, validates nothing and changes no hash."""
    change = change_service.get_change_or_404(change_id)
    configuration_validation_service.reconcile(change)
    return redirect("core:change_configuration_validation", change_id=change.change_id)


@require_GET
def change_validation_report(request, change_id, run_id):
    change = change_service.get_change_or_404(change_id)
    run = change_validation_service.get_validation_run(change, run_id)
    if run is None:
        raise Http404("No such validation run for this Change.")
    document = change_validation_service.serialize_validation_run(run)
    response = HttpResponse(
        json.dumps(document, indent=2, sort_keys=True) + "\n", content_type="application/json; charset=utf-8"
    )
    response["Content-Disposition"] = f'attachment; filename="{change_validation_service.report_filename(run)}"'
    response["X-Content-Type-Options"] = "nosniff"
    return response


# V2 Phase 2 -- NETWORK DEVICE CONFIGURATION validation.  This evidence is distinct from the Tier-2 page above.
def _network_config_validation_page(request, change, run=None):
    currency = network_config_validation.get_currency(change, check_sources=request.GET.get("check_sources") == "1")
    selected = run or currency.get("latest")
    return render(request, "core/device_builder/network_config_validation.html", {
        "page_title": f"Network Config Validation: {change.change_id}", "change": change,
        "run": selected, "document": network_config_validation.serialize(selected) if selected else None,
        "currency": currency, "history": network_config_validation.list_runs(change),
    })


@require_GET
def network_config_validation_page(request, change_id):
    return _network_config_validation_page(request, change_service.get_change_or_404(change_id))


@require_POST
def network_config_validation_run(request, change_id):
    change = change_service.get_change_or_404(change_id)
    network_config_validation.validate_candidate(change, actor=_actor(request))
    return redirect("core:network_config_validation", change_id=change.change_id)


@require_GET
def network_config_validation_detail(request, change_id, run_id):
    change = change_service.get_change_or_404(change_id)
    run = change.network_config_validation_runs.filter(run_id=run_id).first()
    if run is None:
        raise Http404("No such network configuration validation run for this Change.")
    return _network_config_validation_page(request, change, run)


@require_GET
def network_config_validation_report(request, change_id, run_id):
    change = change_service.get_change_or_404(change_id)
    run = change.network_config_validation_runs.filter(run_id=run_id).first()
    if run is None:
        raise Http404("No such network configuration validation run for this Change.")
    response = HttpResponse(json.dumps(network_config_validation.serialize(run), indent=2, sort_keys=True) + "\n",
                            content_type="application/json; charset=utf-8")
    response["Content-Disposition"] = f'attachment; filename="network-config-validation-{run.run_id}.json"'
    response["X-Content-Type-Options"] = "nosniff"
    return response


# =============================================================================
# Phase 14 -- unified priority / dependency PLAN
# =============================================================================
# Thin adapters over core.services.change_plan_service.  GET never builds or
# persists anything; only the explicit POST "Build Plan" does, and it ignores every
# POST field (sources, paths and IDs are fixed server-side).  Nothing here deploys,
# edits a Configlet, or changes the Change lifecycle.

def _plan_page(request, change, plan, *, historical: bool):
    check_sources = request.GET.get("check_sources") == "1"
    latest = change_plan_service.get_latest_plan(change)
    plan = plan if plan is not None else latest
    currency = change_plan_service.get_plan_currency(plan, check_sources=check_sources) if plan else None
    document = change_plan_service.serialize_plan(plan, currency=currency) if plan else None
    eligibility = change_plan_service.check_eligibility(change, check_sources=check_sources)
    validation_currency = eligibility["currency"]

    stage_blocks, describe = [], {}
    if document:
        describe = {c["cfg_id"]: c["description"] for c in document["configlets"]}
        for c in document["configlets"]:
            c["dependency_rows"] = [
                {"cfg_id": d["cfg_id"], "what": describe.get(d["cfg_id"], ""), "edge_types": d["edge_types"]}
                for d in c["dependencies"]
            ]
        for stage in document["stages"]:
            stage_blocks.append({
                "stage": stage,
                "configlets": [c for c in document["configlets"] if c["priority"] == stage["priority"]],
            })
    refused = request.GET.get("refused", "")
    context = {
        "page_title": f"Plan: {change.change_id}",
        "change": change,
        "plan": plan,
        "document": document,
        "historical": historical,
        "is_latest": plan is not None and plan == latest,
        "currency": currency,
        "eligibility": eligibility,
        "validation_currency": validation_currency,
        "validation_run": validation_currency.get("latest"),
        "sources_checked": validation_currency["sources_checked"],
        "stage_blocks": stage_blocks,
        "history": change_plan_service.list_plans(change),
        # only a known error CODE is ever looked up; nothing from the query string is echoed
        "refused_code": refused if refused in change_plan_service.ERROR_MESSAGES else "",
        "refused_message": change_plan_service.ERROR_MESSAGES.get(refused, ""),
    }
    return render(request, "core/device_builder/plan.html", context)


@require_GET
def change_plan(request, change_id):
    change = change_service.get_change_or_404(change_id)
    return _plan_page(request, change, None, historical=False)


@require_GET
def change_plan_detail(request, change_id, plan_id):
    change = change_service.get_change_or_404(change_id)
    plan = change_plan_service.get_plan(change, plan_id)
    if plan is None:
        raise Http404("No such plan for this Change.")
    return _plan_page(request, change, plan, historical=True)


@require_POST
def change_plan_build(request, change_id):
    """Explicit operator action.  Ignores every POST field; refuses (never re-validates) when validation is
    not CURRENT and PASS / PASS_WITH_WARNINGS."""
    change = change_service.get_change_or_404(change_id)
    try:
        change_plan_service.build_change_plan(change, actor=_actor(request), check_sources=True)
    except change_plan_service.PlanGenerationError as exc:
        return redirect(f"{reverse('core:change_plan', args=[change.change_id])}?{urlencode({'refused': exc.code})}")
    return redirect("core:change_plan", change_id=change.change_id)


@require_GET
def change_plan_report(request, change_id, plan_id):
    change = change_service.get_change_or_404(change_id)
    plan = change_plan_service.get_plan(change, plan_id)
    if plan is None:
        raise Http404("No such plan for this Change.")
    document = change_plan_service.serialize_plan(plan, currency=change_plan_service.get_plan_currency(plan))
    response = HttpResponse(json.dumps(document, indent=2, sort_keys=True) + "\n", content_type="application/json; charset=utf-8")
    response["Content-Disposition"] = f'attachment; filename="{change_plan_service.plan_report_filename(plan)}"'
    response["X-Content-Type-Options"] = "nosniff"
    return response


# =============================================================================
# Phase 15 -- fleet / per-device health and Change prechecks
# =============================================================================
# Thin adapters over core.services.health_service.  GET is read-only and never opens a device session (Fleet Quick
# reads the existing telemetry once).  Only the explicit POST actions -- record a snapshot, run Deep Health for ONE
# managed device, run a Change precheck -- may perform bounded read-only live queries, and each ignores every POST
# field: the target device comes from the URL and is looked up in the fixed inventory, never taken from the browser,
# and no command, source URL or query is ever supplied by the client.  Nothing here deploys or edits anything.

_RUN_MODES_GLOBAL = ("FLEET_QUICK", "DEVICE_DEEP")


def _managed_device_or_404(device):
    found = health_service.get_managed_device(device)
    if found is None:
        raise Http404("Not a managed device.")
    return found


def _run_context(run, *, back_url, back_label):
    document = health_service.serialize_health_run(run)
    report = document["report"]
    rows = report.get("results", [])
    return {
        "page_title": f"Run {str(run.run_id)[:8]}",
        "run": run, "document": document, "report": report, "rows": rows,
        "back_url": back_url, "back_label": back_label,
    }


@require_GET
def health_fleet(request):
    fleet = health_service.get_fleet_health()
    context = {
        "page_title": "Health",
        "fleet": fleet,
        "doc": health_service.serialize_fleet(fleet),
        "history": health_service.recent_runs(limit=10),
        "recorded": request.GET.get("recorded") == "1",
    }
    return render(request, "core/health/fleet.html", context)


@require_POST
def health_fleet_snapshot(request):
    """Explicit operator action: persist the current Fleet Quick summary.  Ignores every POST field."""
    health_service.record_fleet_snapshot(actor=_actor(request))
    return redirect(f"{reverse('core:health_fleet')}?recorded=1")


@require_GET
def health_device(request, device):
    managed = _managed_device_or_404(device)
    quick = health_service.get_device_quick(managed["name"])
    latest = health_service.latest_run(mode="DEVICE_DEEP", device=managed["name"])
    latest_connectivity = health_service.latest_connectivity_run(managed["name"])
    context = {
        "page_title": f"Health: {managed['name']}",
        "device": managed, "quick": quick,
        "capability": health_service.get_capability(managed["platform"]),
        "latest": latest,
        "report": health_service.serialize_health_run(latest)["report"] if latest else None,
        "history": health_service.recent_runs(device=managed["name"], limit=10),
        "ping_targets": health_service.ping_targets(managed["name"]),
        "latest_connectivity": latest_connectivity,
        "connectivity_report": health_service.serialize_health_run(latest_connectivity)["report"] if latest_connectivity else None,
    }
    return render(request, "core/health/device.html", context)


@require_POST
def health_device_deep(request, device):
    """Explicit Deep Health for ONE managed device (bounded, read-only, fixed server-owned commands)."""
    managed = _managed_device_or_404(device)
    run, _ = health_service.run_device_health(managed["name"], actor=_actor(request))
    return redirect("core:health_run", run_id=run.run_id)


@require_POST
def health_device_connectivity(request, device):
    """Explicit, read-only IP connectivity (ping) check FROM one managed device.  ``destination`` must be a KEY of
    the server-owned menu (``health_service.ping_targets``) -- NMAS or another managed device -- never a free-text
    address; an unknown key is a 400, not a live query.  ``family`` selects IPv4 ("4", default) or IPv6 ("6")."""
    managed = _managed_device_or_404(device)
    destination = request.POST.get("destination", "")
    family = request.POST.get("family") or "4"
    if family not in ("4", "6"):
        return HttpResponseBadRequest("Invalid address family.")
    try:
        run, _ = health_service.run_connectivity(managed["name"], destination, family, actor=_actor(request))
    except health_service.UnknownDestinationError:
        return HttpResponseBadRequest("Unknown connectivity destination.")
    return redirect("core:health_run", run_id=run.run_id)


@require_GET
def health_run(request, run_id):
    run = health_service.get_run(run_id)
    if run is None or run.mode not in _RUN_MODES_GLOBAL:
        raise Http404("No such health run.")
    back = reverse("core:health_device", args=[run.device]) if run.device else reverse("core:health_fleet")
    return render(request, "core/health/run.html", _run_context(run, back_url=back, back_label="Back to health"))


@require_GET
def health_run_report(request, run_id):
    run = health_service.get_run(run_id)
    if run is None or run.mode not in _RUN_MODES_GLOBAL:
        raise Http404("No such health run.")
    return _report_response(health_service.serialize_health_run(run), f"health-{run.mode.lower()}-{str(run.run_id)[:8]}.json")


def _report_response(document, filename):
    response = HttpResponse(json.dumps(document, indent=2, sort_keys=True, default=str) + "\n", content_type="application/json; charset=utf-8")
    response["Content-Disposition"] = f'attachment; filename="{filename}"'  # server-derived only; no client value reaches it
    response["X-Content-Type-Options"] = "nosniff"
    return response


@require_GET
def change_precheck(request, change_id):
    change = change_service.get_change_or_404(change_id)
    check_sources = request.GET.get("check_sources") == "1"
    eligibility = change_plan_service.check_eligibility(change, check_sources=check_sources)
    plan = change_plan_service.get_latest_plan(change)
    currency = change_plan_service.get_plan_currency(plan, check_sources=check_sources) if plan else None
    scope = health_service.build_affected_scope(plan).to_dict() if plan else None
    requirements = health_service.normalize_plan(plan) if plan else []
    latest = health_service.latest_run(mode="CHANGE_PRECHECK", change=change)
    context = {
        "page_title": f"Precheck: {change.change_id}",
        "change": change, "plan": plan, "currency": currency, "eligibility": eligibility,
        "validation_currency": eligibility["currency"], "validation_run": eligibility["currency"].get("latest"),
        "sources_checked": eligibility["currency"]["sources_checked"],
        "scope": scope,
        "requirement_summary": {
            "requirements": len(requirements),
            "unverifiable": sum(1 for r in requirements if r.check_types and r.check_types[0] in ("NOT_IMPLEMENTED", "UNKNOWN_TYPE")),
        },
        "latest": latest,
        "report": health_service.serialize_health_run(latest)["report"] if latest else None,
        "history": health_service.recent_runs(mode="CHANGE_PRECHECK", change=change, limit=10),
    }
    return render(request, "core/device_builder/precheck.html", context)


@require_POST
def change_precheck_run(request, change_id):
    """Explicit precheck.  Deploys nothing; ignores every POST field; refuses (never re-validates / rebuilds) when the
    validation or plan prerequisites do not hold -- the refusal is itself recorded as a BLOCKED / INCOMPLETE run."""
    change = change_service.get_change_or_404(change_id)
    outcome = health_service.run_change_precheck(change, actor=_actor(request))
    return redirect("core:change_precheck_detail", change_id=change.change_id, run_id=outcome.run.run_id)


@require_GET
def change_precheck_detail(request, change_id, run_id):
    change = change_service.get_change_or_404(change_id)
    run = health_service.get_run(run_id)
    if run is None or run.change_id != change.pk or run.mode != "CHANGE_PRECHECK":
        raise Http404("No such precheck for this Change.")
    return render(request, "core/health/run.html",
                  _run_context(run, back_url=reverse("core:change_precheck", args=[change.change_id]), back_label=f"Back to {change.change_id} precheck"))


# =============================================================================
# Phase 17 -- structured execution (Complete / Partial (UAT))
# =============================================================================
# Thin adapters over core.services.execution_service.  GET never executes, validates, plans or prechecks anything.
# Only the explicit POST "Execute" reaches the mutating engine, and it takes NO command, path, device or Configlet
# text from the browser: the operator supplies only (a) a confirmation of the Change's own mode, (b) for Partial (UAT)
# the five acknowledgement checkboxes and the id of the last plan Configlet to run (looked up in the plan, never
# echoed).  Everything else -- devices, order, syntax -- comes from the CURRENT plan.  CSRF middleware is project-wide.

_EXECUTION_BADGE = {"success": "success", "warning": "warning", "danger": "danger", "neutral": "neutral"}


def _execution_run_or_404(change, run_id):
    run = execution_service.get_run(change, run_id)
    if run is None:
        raise Http404("No such execution run for this Change.")
    return run


@require_GET
def change_execute(request, change_id):
    change = change_service.get_change_or_404(change_id)
    check_sources = request.GET.get("check_sources") == "1"
    gate = execution_service.check_execution_eligibility(change, for_submission=False, check_sources=check_sources)
    platforms = sorted(change.device_intents.values_list("platform", flat=True).distinct())
    context = {
        "page_title": f"Execute: {change.change_id}",
        "change": change, "gate": gate, "plan": gate.plan, "scope": gate.scope, "precheck": gate.precheck_run,
        "sources_checked": gate.checked_sources, "uat_acks": execution_service.UAT_ACK_FIELDS,
        "history": execution_service.list_runs(change, limit=10), "is_partial": change.execution_mode == models.ExecutionMode.PARTIAL_UAT,
        "capability_rows": gate.configlet_rows,
        "transport_matrix": [
            {
                "platform": platform,
                "platform_display": models.Platform(platform).label if platform in models.Platform.values else platform,
                "rows": transport_capability.deployment_transport_matrix(platform),
                "selected_transport": transport_capability.selected_transport(platform),
            }
            for platform in platforms
        ],
    }
    return render(request, "core/device_builder/execute.html", context)


@require_POST
def change_execute_run(request, change_id):
    """The ONLY mutating endpoint of Phase 17.  Explicit POST + CSRF; the engine refuses (recording why) unless every gate holds."""
    change = change_service.get_change_or_404(change_id)
    acknowledgements = {name: request.POST.get(name) == "on" for name, _label in execution_service.UAT_ACK_FIELDS}
    result = execution_service.execute_change(
        change, actor=_actor(request), through_cfg_id=request.POST.get("through_cfg_id", ""), acknowledgements=acknowledgements,
        confirm_mode=request.POST.get("confirm_mode", ""),
    )
    if result.run is None:  # refused before a plan existed: nothing to link to; the audit trail has it
        return redirect(f"{reverse('core:change_execute', args=[change.change_id])}?refused=1")
    return redirect("core:change_execution_detail", change_id=change.change_id, run_id=result.run.run_id)


@require_GET
def change_executions(request, change_id):
    change = change_service.get_change_or_404(change_id)
    return render(request, "core/device_builder/executions.html", {
        "page_title": f"Executions: {change.change_id}", "change": change, "history": execution_service.list_runs(change),
    })


@require_GET
def change_execution_detail(request, change_id, run_id):
    change = change_service.get_change_or_404(change_id)
    run = _execution_run_or_404(change, run_id)
    document = execution_service.serialize_run(run)
    postcheck = health_service.serialize_health_run(run.postcheck_run)["report"] if run.postcheck_run_id else None
    tone = execution_service.OUTCOME_PRESENTATION.get(run.outcome, ("neutral", ""))
    context = {
        "page_title": f"Execution {str(run.run_id)[:8]}", "change": change, "run": run, "document": document, "report": document["report"],
        "apply_results": [r for r in document["results"] if r["phase"] == "APPLY"],
        "compensation_results": [r for r in document["results"] if r["phase"] == "COMPENSATE"],
        "tone": _EXECUTION_BADGE[tone[0]], "explanation": tone[1], "postcheck_rows": (postcheck or {}).get("results", []),
        # Phase 19: read-only; a UAT bundle is only ever created by the explicit POST, never by opening this page
        "uat_bundle": bundle_service.check_uat_eligibility(run) if run.mode == models.ExecutionMode.PARTIAL_UAT and run.state == models.ExecutionRunState.FINISHED else None,
        # V2 Phase 5: the same, for a finished Complete run and its Deployed bundle (sealing is the explicit POST; probation is a later, separate action)
        "deployed_bundle": bundle_service.check_deployed_eligibility(run) if run.mode == models.ExecutionMode.COMPLETE and run.state == models.ExecutionRunState.FINISHED else None,
    }
    return render(request, "core/device_builder/execution_detail.html", context)


@require_GET
def change_execution_report(request, change_id, run_id):
    change = change_service.get_change_or_404(change_id)
    run = _execution_run_or_404(change, run_id)
    response = HttpResponse(execution_service.report_json(run), content_type="application/json; charset=utf-8")
    response["Content-Disposition"] = f'attachment; filename="{execution_service.report_filename(run)}"'  # server-derived only
    response["X-Content-Type-Options"] = "nosniff"
    return response


# =============================================================================
# Phase 18 -- Raw Configlets (an explicit, separate escape hatch from the structured Device Builder)
# =============================================================================
# Thin adapters over core.services.raw_configlet_service.  GET pages never verify, plan or execute anything and never start a
# sandbox.  Saving a revision, Verify and enable/disable are explicit CSRF POSTs; Verify takes only the revision NUMBER the
# operator was looking at.  Nothing here accepts a command, image, path, URL or device credential from the browser, and there is
# deliberately NO raw execute endpoint: a Raw Configlet can only run through a CURRENT plan and the Phase-17 execute POST, whose
# payload is always re-read from the pinned, immutable revision on the server.

_RAW_BADGE = {"PASS": "success", "PASS_WITH_WARNINGS": "warning", "BLOCKED": "danger", "INCOMPLETE": "warning"}


def _raw_or_404(change, raw_id):
    raw = raw_configlet_service.get_raw(change, raw_id)
    if raw is None:
        raise Http404("No such Raw Configlet in this Change.")
    return raw


def _raw_badge(status: dict) -> tuple[str, str]:
    """(css tone, label) for a status dict: an unmistakable Never verified / Current / Stale presentation."""
    if status["currency"] == "NEVER_RUN":
        return "neutral", "Never verified"
    if status["currency"] == "STALE":
        return "warning", "Stale"
    return _RAW_BADGE.get(status["result"], "neutral"), f"Current / {str(status['result']).replace('_', ' ')}"


def _raw_form_values(request) -> tuple[dict, list[str]]:
    """The bounded authoring fields.  Parse problems are returned as messages; the SERVICE re-validates everything."""
    post = request.POST
    assertions, errors = raw_configlet_service.parse_assertion_lines(post.get("assertions", ""))
    dependencies = [line.strip() for line in post.get("dependencies", "").splitlines() if line.strip() and not line.strip().startswith("#")]
    fields = {
        "target_device": post.get("target_device", ""), "name": post.get("name", ""), "description": post.get("description", ""),
        "priority": post.get("priority", ""), "content": post.get("content", ""), "dependencies": dependencies, "assertions": assertions,
    }
    return fields, errors


def _raw_editor_context(request, change, raw, *, form=None, findings=None, parse_errors=None):
    intents = list(change.device_intents.order_by("device_name"))
    revision = raw.latest_revision() if raw is not None else None
    status = raw_configlet_service.status_of(raw) if raw is not None else None
    tone, label = _raw_badge(status) if status else ("neutral", "Never verified")
    revisions = list(raw.revisions.order_by("-revision")) if raw is not None else []
    runs = list(models.RawConfigletVerificationRun.objects.filter(revision__raw=raw).select_related("revision").order_by("-started_at", "-id")[:15]) if raw is not None else []
    latest_validation = change_validation_service.get_latest_validation(change)
    graph_nodes = [n for n in ((latest_validation.dependency_graph or {}).get("nodes", []) if latest_validation else []) if n.get("type") != "raw_configlet"]
    initial = form or ({
        "target_device": revision.target_device, "name": revision.name, "description": revision.description, "priority": revision.priority,
        "content": revision.content, "dependencies": list(revision.dependencies), "assertions": list(revision.assertions),
    } if revision else {"target_device": "", "name": "", "description": "", "priority": 6, "content": "", "dependencies": [], "assertions": []})
    initial = {**initial, "assertions_text": "\n".join(
        " ".join([a["kind"], *[f"{k}={v}" for k, v in a.items() if k != "kind"]]) for a in (initial.get("assertions") or [])),
        "dependencies_text": "\n".join(initial.get("dependencies") or [])}
    return {
        "page_title": f"Raw Configlet: {raw.raw_id}" if raw else "New Raw Configlet", "change": change, "raw": raw, "revision": revision,
        "status": status, "status_tone": tone, "status_label": label, "revisions": revisions, "runs": runs, "form": initial,
        "findings": findings or [], "parse_errors": parse_errors or [], "intents": intents, "priorities": models.DeploymentPriority.choices,
        "dependency_targets": graph_nodes[:200], "assertion_kinds": raw_configlet_service.ASSERTION_KINDS, "limits": raw_configlet_service.LIMITS,
        "capabilities": raw_configlet_service.capability_matrix(), "policy_version": raw_configlet_service.POLICY_VERSION,
        "error": request.GET.get("error", ""), "notice": request.GET.get("notice", ""),
    }


@require_GET
def raw_configlets(request, change_id):
    change = change_service.get_change_or_404(change_id)
    rows = []
    for raw in raw_configlet_service.list_raw(change):
        status = raw_configlet_service.status_of(raw)
        tone, label = _raw_badge(status)
        rows.append({"raw": raw, "revision": status["revision"], "status": status, "tone": tone, "label": label})
    return render(request, "core/device_builder/raw_list.html", {
        "page_title": f"Raw Configlets: {change.change_id}", "change": change, "rows": rows,
        "capabilities": raw_configlet_service.capability_matrix(), "limits": raw_configlet_service.LIMITS,
    })


@require_GET
def raw_configlet_new(request, change_id):
    change = change_service.get_change_or_404(change_id)
    return render(request, "core/device_builder/raw_editor.html", _raw_editor_context(request, change, None))


@require_POST
def raw_configlet_create(request, change_id):
    change = change_service.get_change_or_404(change_id)
    fields, parse_errors = _raw_form_values(request)
    try:
        if parse_errors:
            raise raw_configlet_service.RawConfigletError([
                {"code": "RAW_ASSERTION_INVALID", "severity": "ERROR", "blocking": True, "message": message, "remediation": "", "line": None, "stage": "STATIC"}
                for message in parse_errors])
        raw, _revision = raw_configlet_service.create_raw_configlet(change, actor=_actor(request), **fields)
    except raw_configlet_service.RawConfigletError as exc:
        context = _raw_editor_context(request, change, None, form=raw_configlet_service.redisplay_safe(fields, exc.findings), findings=exc.findings, parse_errors=parse_errors)
        return render(request, "core/device_builder/raw_editor.html", context, status=400)
    return redirect(f"{reverse('core:raw_configlet_detail', args=[change.change_id, raw.raw_id])}?notice=CREATED")


@require_GET
def raw_configlet_detail(request, change_id, raw_id):
    change = change_service.get_change_or_404(change_id)
    return render(request, "core/device_builder/raw_editor.html", _raw_editor_context(request, change, _raw_or_404(change, raw_id)))


@require_POST
def raw_configlet_save(request, change_id, raw_id):
    """Save a NEW immutable revision (an unchanged save is a no-op).  Never verifies, plans or contacts a device."""
    change = change_service.get_change_or_404(change_id)
    raw = _raw_or_404(change, raw_id)
    fields, parse_errors = _raw_form_values(request)
    try:
        if parse_errors:
            raise raw_configlet_service.RawConfigletError([
                {"code": "RAW_ASSERTION_INVALID", "severity": "ERROR", "blocking": True, "message": message, "remediation": "", "line": None, "stage": "STATIC"}
                for message in parse_errors])
        _revision, created = raw_configlet_service.save_revision(raw, actor=_actor(request), **fields)
    except raw_configlet_service.RawConfigletError as exc:
        context = _raw_editor_context(request, change, raw, form=raw_configlet_service.redisplay_safe(fields, exc.findings), findings=exc.findings, parse_errors=parse_errors)
        return render(request, "core/device_builder/raw_editor.html", context, status=400)
    return redirect(f"{reverse('core:raw_configlet_detail', args=[change.change_id, raw.raw_id])}?notice={'SAVED' if created else 'UNCHANGED'}")


@require_POST
def raw_configlet_verify(request, change_id, raw_id):
    """Explicit Verify of the LATEST revision (the browser names the revision number it was looking at; a superseded number is refused)."""
    change = change_service.get_change_or_404(change_id)
    raw = _raw_or_404(change, raw_id)
    revision = raw.latest_revision()
    detail = reverse("core:raw_configlet_detail", args=[change.change_id, raw.raw_id])
    if revision is None or str(revision.revision) != request.POST.get("revision", ""):
        return redirect(f"{detail}?error=REVISION_SUPERSEDED")
    response = raw_configlet_service.request_verification(revision, actor=_actor(request))
    if response.refused:
        return redirect(f"{detail}?error={response.refused}")
    return redirect("core:raw_configlet_verification", change_id=change.change_id, raw_id=raw.raw_id, run_id=response.run.run_id)


@require_POST
def raw_configlet_toggle(request, change_id, raw_id):
    """Add to / remove from the EFFECTIVE Change input (soft; history is preserved).  Only the literal values 1 / 0 are accepted."""
    change = change_service.get_change_or_404(change_id)
    raw = _raw_or_404(change, raw_id)
    wanted = request.POST.get("enabled")
    if wanted not in ("0", "1"):
        return HttpResponseBadRequest("enabled must be 0 or 1")
    raw_configlet_service.set_enabled(raw, wanted == "1", actor=_actor(request))
    return redirect(f"{reverse('core:raw_configlet_detail', args=[change.change_id, raw.raw_id])}?notice={'ENABLED' if wanted == '1' else 'DISABLED'}")


@require_GET
def raw_configlet_revision(request, change_id, raw_id, revision):
    """A HISTORICAL revision: strictly read-only (there is no form and no POST route for editing it)."""
    change = change_service.get_change_or_404(change_id)
    raw = _raw_or_404(change, raw_id)
    found = raw_configlet_service.get_revision(raw, revision)
    if found is None:
        raise Http404("No such revision.")
    runs = list(found.verification_runs.order_by("-started_at", "-id"))
    status = raw_configlet_service.verification_currency(found)
    tone, label = _raw_badge({"currency": status["state"], "result": status["result"]})
    return render(request, "core/device_builder/raw_revision.html", {
        "page_title": f"{raw.raw_id} revision {found.revision}", "change": change, "raw": raw, "revision": found, "runs": runs,
        "is_latest": found.pk == raw.latest_revision().pk, "status_tone": tone, "status_label": label,
        "status_reasons": status["reasons"],
    })


@require_GET
def raw_configlet_verification(request, change_id, raw_id, run_id):
    change = change_service.get_change_or_404(change_id)
    raw = _raw_or_404(change, raw_id)
    run = raw_configlet_service.get_verification_run(raw, run_id)
    if run is None:
        raise Http404("No such verification run for this Raw Configlet.")
    status = raw_configlet_service.verification_currency(run.revision)
    is_current = status["run"] is not None and status["run"].pk == run.pk and status["state"] == "CURRENT"
    return render(request, "core/device_builder/raw_verification.html", {
        "page_title": f"Verification {str(run.run_id)[:8]}", "change": change, "raw": raw, "run": run, "revision": run.revision,
        "tone": _RAW_BADGE.get(run.result, "neutral"), "is_current": is_current, "currency_reasons": status["reasons"],
        "is_latest_revision": run.revision.pk == raw.latest_revision().pk,
    })


# =============================================================================
# Phase 19 -- immutable configuration bundles (UAT -> Probation -> Golden foundations)
# =============================================================================
# Thin adapters over core.services.bundle_service.  GET pages (list, detail, manifest export) are read-only: they create, verify-and-store,
# repair and contact nothing.  The two mutating endpoints are explicit CSRF POSTs and only create an ARTIFACT (database rows + one audit
# event): they never execute a Configlet, touch a device / NetBox / Git, start a soak or change the Change lifecycle.  The browser supplies
# only a confirmation checkbox and an id in the URL that is looked up server-side -- never a payload, a digest, a kind or a parent.
# There is deliberately NO route that creates a Golden bundle: that decision belongs to the Phase-20 probation soak workflow.

_BUNDLE_NOTICES = {
    "UAT_CREATED": ("success", "UAT bundle created. It is immutable: it records exactly the executed, verified scope and can never be edited."),
    "UAT_EXISTS": ("info", "This execution run already has its UAT bundle; no duplicate was created."),
    "DEPLOYED_CREATED": ("success", "Deployed bundle sealed from the successful Complete execution. It is immutable. No Probation bundle was created and no soak has started."),
    "DEPLOYED_EXISTS": ("info", "This execution run already has its Deployed bundle; no duplicate was created."),
    "PROBATION_CREATED": ("success", "Probation bundle created from the root bundle. The configuration payload is unchanged and the root bundle was not touched. No soak has started."),
    "PROBATION_EXISTS": ("info", "This root bundle already has its Probation bundle; no duplicate was created."),
    "PROBATION_REFUSED": ("danger", "The Probation bundle was not created; see the blockers below."),
    "CONFIRM_REQUIRED": ("warning", "Tick the confirmation to create the Probation bundle."),
    "SOAK_CONFIRM_REQUIRED": ("warning", "Tick the confirmation to start the soak."),
    "SOAK_START_REFUSED": ("danger", "The soak was not started; the blockers are listed in the soak panel below."),
    "APPROVED": ("success", "Golden approved: this new immutable Golden bundle was sealed from the exact Probation payload. No device was contacted and nothing was re-applied."),
    "APPROVED_EXISTS": ("info", "This soak was already approved; this is the existing Golden bundle. No duplicate was created."),
}
_BUNDLE_KIND_BADGE = {"UAT": "info", "DEPLOYED": "info", "PROBATION": "warning", "GOLDEN": "success", "LEGACY_BASELINE": "warning"}


def _bundle_or_404(bundle_id):
    bundle = bundle_service.get_bundle(bundle_id)
    if bundle is None:
        raise Http404("No such bundle.")
    return bundle


@require_GET
def bundles_list(request):
    kind = request.GET.get("kind", "")
    change_id = request.GET.get("change", "").strip()[:32]
    return render(request, "core/device_builder/bundles.html", {
        "page_title": "Configuration bundles",
        "bundles": bundle_service.list_bundles(kind=kind, change_id=change_id), "kinds": models.BundleKind.choices,
        "kind_filter": kind if kind in models.BundleKind.values else "", "change_filter": change_id, "kind_badge": _BUNDLE_KIND_BADGE,
    })


@require_GET
def bundle_detail(request, bundle_id):
    bundle = _bundle_or_404(bundle_id)
    integrity = bundle_service.verify_bundle_integrity(bundle)   # recomputed from the stored contents, read-only, bounded to this one bundle
    notice = _BUNDLE_NOTICES.get(request.GET.get("notice", "")) or _BOOTSTRAP_NOTICES.get(request.GET.get("notice", ""))
    if bundle.provenance == models.BundleProvenance.LEGACY_BOOTSTRAP:   # the one-time legacy baseline: no Change / plan / execution exists, so it has its own page
        return render(request, "core/bootstrap/legacy_bundle.html", _legacy_bundle_context(bundle, integrity, notice))
    context = {
        "page_title": f"Bundle {bundle.bundle_id}", "bundle": bundle, "integrity": integrity, "items": list(bundle.items.order_by("sequence")),
        "lineage": bundle_service.lineage_of(bundle), "notice": notice, "kind_badge": _BUNDLE_KIND_BADGE[bundle.kind],
        "probation": bundle_service.check_probation_eligibility(bundle, integrity=integrity) if bundle.kind in models.BUNDLE_ROOT_KINDS else None,
        "is_verified": bundle.verification_state == "VERIFIED",
    }
    root = context["lineage"].get("uat")   # the lineage root: a UAT bundle (Partial (UAT) run) or a Deployed bundle (Complete run)
    context["root_is_deployed"] = root is not None and root.kind == models.BundleKind.DEPLOYED
    context["root_label"] = "Deployed" if context["root_is_deployed"] else "UAT"
    if bundle.kind == models.BundleKind.PROBATION:   # Phase 20: the soak panel (all read-only; starting a soak is the explicit POST below)
        runs = soak_service.list_runs(bundle=bundle)
        context.update({
            "soak_start": soak_service.check_soak_start(bundle, integrity=integrity), "soak_runs": runs,
            "soak_active": next((r for r in runs if r.is_running), None), "soak_policy": soak_service.current_policy(),
            "soak_pending": next((r for r in runs if r.is_technical_pass and soak_service.decision_of(r) is None), None),
        })
        context["soak_progress"] = soak_service.progress(context["soak_active"]) if context["soak_active"] is not None else None
    elif bundle.kind == models.BundleKind.GOLDEN:
        decision = models.GoldenDecision.objects.filter(golden_bundle=bundle).select_related("run").first()
        context.update({"promotion": bundle.lineage.get("promotion") or {}, "decision": decision})
    return render(request, "core/device_builder/bundle_detail.html", context)


@require_GET
def bundle_manifest(request, bundle_id):
    bundle = _bundle_or_404(bundle_id)
    try:
        body = bundle_service.export_json(bundle)
    except bundle_service.BundleExportBlocked:
        return HttpResponse("This bundle's manifest failed the export secret-hygiene check and is not released.", status=409, content_type="text/plain; charset=utf-8")
    response = HttpResponse(body, content_type="application/json; charset=utf-8")
    response["Content-Disposition"] = f'attachment; filename="{bundle_service.export_filename(bundle)}"'   # server-derived only
    response["X-Content-Type-Options"] = "nosniff"
    return response


@require_POST
def change_execution_bundle_create(request, change_id, run_id):
    """Explicit POST + CSRF: seal a finished run into its ROOT bundle -- a Partial (UAT) run into a UAT bundle, a Complete run into a Deployed
    bundle.  The kind comes from the run's own recorded mode, never from the browser, and the server re-checks eligibility whatever the page
    showed.  Artifact creation only: no Probation bundle is derived and no soak starts here."""
    change = change_service.get_change_or_404(change_id)
    run = _execution_run_or_404(change, run_id)
    deployed = run.mode == models.ExecutionMode.COMPLETE
    if deployed:
        result = bundle_service.create_deployed_bundle(run, actor=_actor(request))
    else:
        result = bundle_service.create_uat_bundle(run, actor=_actor(request))
    if result.bundle is None:
        return redirect(f"{reverse('core:change_execution_detail', args=[change.change_id, run.run_id])}?{urlencode({'bundle': 'refused'})}")
    notice = ("DEPLOYED_CREATED" if result.created else "DEPLOYED_EXISTS") if deployed else ("UAT_CREATED" if result.created else "UAT_EXISTS")
    return redirect(f"{reverse('core:bundle_detail', args=[result.bundle.bundle_id])}?{urlencode({'notice': notice})}")


@require_POST
def bundle_derive_probation(request, bundle_id):
    """Explicit, confirmed POST + CSRF: seal an eligible root (UAT or Deployed) bundle into a NEW Probation bundle.  Not a soak, not Golden, no device."""
    bundle = _bundle_or_404(bundle_id)
    detail = reverse("core:bundle_detail", args=[bundle.bundle_id])
    if request.POST.get("confirm") != "on":
        return redirect(f"{detail}?{urlencode({'notice': 'CONFIRM_REQUIRED'})}")
    result = bundle_service.derive_probation_bundle(bundle, actor=_actor(request))
    if result.bundle is None:
        return redirect(f"{detail}?{urlencode({'notice': 'PROBATION_REFUSED'})}")
    notice = "PROBATION_CREATED" if result.created else "PROBATION_EXISTS"
    return redirect(f"{reverse('core:bundle_detail', args=[result.bundle.bundle_id])}?{urlencode({'notice': notice})}")


# --- Phase 20 -- probation soak + the operator's Golden decision -------------------------------------------------------------------------
# GET pages are read-only.  Every POST below mutates APPLICATION state only (soak / evidence / decision rows, audit, notifications, and for an
# explicit APPROVE one Golden artifact): none configures a device, writes NetBox / Git or saves a device configuration.  The browser never supplies a
# timestamp, a duration, a policy, evidence, a manifest or a digest to trust: the only echoes (soak id, bundle id, digest) are STALENESS GUARDS the
# server compares with its own records.
_SOAK_NOTICES = {
    "STARTED": ("success", "The probation soak started. The server fixed its start and required end; the collector now samples on a schedule."),
    "ACTIVE": ("info", "A soak is already running for this Probation bundle; no second one was started."),
    "START_REFUSED": ("danger", "The soak was not started; see the blockers on the Probation bundle."),
    "CONFIRM_REQUIRED": ("warning", "Tick the confirmation to continue."),
    "CANCELLED": ("info", "The soak was cancelled. Its evidence is kept; it can never become Golden and can not be resumed."),
    "CANCEL_REFUSED": ("warning", "The soak is not running, so it cannot be cancelled."),
    "APPROVED": ("success", "Golden approved: a new immutable Golden bundle was created. No device was contacted."),
    "APPROVED_EXISTS": ("info", "This soak was already approved; the existing Golden bundle is shown."),
    "REJECTED": ("info", "Golden rejected. Nothing was deleted or rolled back; a new soak is required to reconsider."),
    "DECISION_REFUSED": ("danger", "The decision was refused; see the reasons below. Nothing was changed."),
}


def _known_refusals(raw: str) -> list:
    """Refusal codes echoed through the query string are shown ONLY when they are known catalogue codes (with their fixed message): never reflected text."""
    catalogue = {**bundle_service.GOLDEN_BLOCKERS, **soak_service.DECISION_BLOCKERS}
    return [{"code": code, "message": catalogue[code][0], "remediation": catalogue[code][1]} for code in dict.fromkeys(raw.split(",")[:12]) if code in catalogue]


def _soak_or_404(soak_id):
    run = soak_service.get_run(soak_id)
    if run is None:
        raise Http404("No such soak.")
    return run


@require_GET
def soaks_list(request):
    return render(request, "core/device_builder/soaks.html", {"page_title": "Probation soaks", "runs": soak_service.list_runs()})


@require_GET
def probation_overview(request):
    """V2 Phase 5C: current Golden, the active probation candidates and their real progress.  Read-only; contacts no device."""
    context = {"page_title": "Golden and probation", **soak_service.overview()}
    return render(request, "core/device_builder/probation_overview.html", context)


@require_GET
def soak_detail(request, soak_id):
    run = _soak_or_404(soak_id)
    decision = soak_service.decision_of(run)
    integrity = bundle_service.verify_bundle_integrity(run.bundle)
    golden = bundle_service.check_golden_eligibility(run.bundle, run) if run.is_technical_pass and decision is None else None
    context = {
        "page_title": f"Soak {run.soak_id}", "run": run, "bundle": run.bundle, "progress": soak_service.progress(run), "decision": decision, "golden": golden,
        "integrity": integrity, "notice": _SOAK_NOTICES.get(request.GET.get("notice", "")), "reasons": soak_service.TERMINAL_REASONS,
        "timeline": list(run.samples.order_by("-bucket")[:soak_service.MAX_SAMPLE_ROWS_SHOWN]), "max_reason": soak_service.MAX_REASON_CHARS,
        "refusals": _known_refusals(request.GET.get("codes", "")),
    }
    return render(request, "core/device_builder/soak_detail.html", context)


@require_POST
def bundle_soak_start(request, bundle_id):
    """Explicit, confirmed POST + CSRF.  The browser sends ONLY the confirmation: the server decides the start time, the duration and every rule."""
    bundle = _bundle_or_404(bundle_id)
    detail = reverse("core:bundle_detail", args=[bundle.bundle_id])
    if request.POST.get("confirm") != "on":
        return redirect(f"{detail}?{urlencode({'notice': 'SOAK_CONFIRM_REQUIRED'})}")
    result = soak_service.start_soak(bundle, actor=_actor(request))
    if result.run is None:
        return redirect(f"{detail}?{urlencode({'notice': 'SOAK_START_REFUSED'})}")
    return redirect(f"{reverse('core:soak_detail', args=[result.run.soak_id])}?{urlencode({'notice': 'STARTED' if result.created else 'ACTIVE'})}")


@require_POST
def soak_cancel(request, soak_id):
    run = _soak_or_404(soak_id)
    target = reverse("core:soak_detail", args=[run.soak_id])
    if request.POST.get("confirm") != "on":
        return redirect(f"{target}?{urlencode({'notice': 'CONFIRM_REQUIRED'})}")
    result = soak_service.cancel_soak(run, actor=_actor(request))
    return redirect(f"{target}?{urlencode({'notice': 'CANCELLED' if result.cancelled else 'CANCEL_REFUSED'})}")


@require_POST
def soak_decision(request, soak_id):
    """The operator's explicit Golden decision.  APPROVE / REJECT + the acknowledgement + the echoed soak / bundle / digest (staleness guards) + a comment."""
    run = _soak_or_404(soak_id)
    target = reverse("core:soak_detail", args=[run.soak_id])
    if request.POST.get("confirm") != "on":
        return redirect(f"{target}?{urlencode({'notice': 'CONFIRM_REQUIRED'})}")
    result = soak_service.decide(
        run, decision=request.POST.get("decision", ""), actor=_actor(request), reason=request.POST.get("reason", ""),
        confirm={"soak_id": request.POST.get("expected_soak_id", ""), "bundle_id": request.POST.get("expected_bundle_id", ""),
                 "bundle_digest": request.POST.get("expected_bundle_digest", "")},
    )
    if result.refused:
        return redirect(f"{target}?{urlencode({'notice': 'DECISION_REFUSED', 'codes': ','.join(b['code'] for b in result.blockers)[:300]})}")
    if result.bundle is not None:
        notice = "APPROVED" if result.created else "APPROVED_EXISTS"
        return redirect(f"{reverse('core:bundle_detail', args=[result.bundle.bundle_id])}?{urlencode({'notice': notice})}")
    return redirect(f"{target}?{urlencode({'notice': 'REJECTED'})}")


# --- One-time legacy baseline bootstrap ---------------------------------------------------------------------------------------------------
# GET pages are read-only and contact NO device.  Every POST below changes APPLICATION state only (candidate / run / decision rows, audit,
# notifications -- and, for the explicit approval, the initial Golden artifact).  The capture and the readiness probe READ the devices through the existing
# read-only allowlisted sessions; nothing here configures a device, NetBox, Git or Containerlab.  The browser supplies only a confirmation (and an optional
# comment): never a duration, timestamp, policy, digest to trust, evidence, manifest or command.  The ONLY route to the initial Golden is
# ``bootstrap_approve``: an explicit operator POST on a technically passed observation.
_BOOTSTRAP_NOTICES = {
    "CAPTURED": ("success", "The current baseline was captured read-only into an immutable candidate. It is NOT Golden and no observation has started."),
    "CAPTURE_REFUSED": ("danger", "The baseline was not captured; the blockers are listed below. Nothing was created and nothing was changed on any device."),
    "STARTED": ("success", "The 30-minute observation started. The server fixed its start, end and policy. The collector command must keep running (see the runbook)."),
    "ACTIVE": ("info", "An observation is already running; no second one was started."),
    "START_REFUSED": ("danger", "The observation was not started; the blockers are listed below."),
    "CONFIRM_REQUIRED": ("warning", "Tick the confirmation to continue."),
    "CANCELLED": ("info", "The observation was cancelled. Its evidence is kept; it can never become Golden."),
    "CANCEL_REFUSED": ("warning", "The observation is not running, so it cannot be cancelled."),
    "APPROVED": ("success", "Initial Golden approved: an immutable Golden bundle with LEGACY_BOOTSTRAP provenance was sealed from the exact observed baseline. No device was contacted to create it."),
    "APPROVED_EXISTS": ("info", "This observation was already approved; the existing initial Golden is shown."),
    "APPROVE_REFUSED": ("danger", "Approval was refused; the reasons are listed below. Nothing was created."),
}


def _bootstrap_refusals(raw: str) -> list:
    """Refusal codes echoed through the query string are shown ONLY when they are known catalogue codes (with their fixed message): never reflected text."""
    catalogue = bootstrap_service.BOOTSTRAP_BLOCKERS
    return [{"code": code, "message": catalogue[code][0], "remediation": catalogue[code][1]} for code in dict.fromkeys(raw.split(",")[:12]) if code in catalogue]


def _bootstrap_run_or_404(run_id):
    run = bootstrap_service.get_run(run_id)
    if run is None:
        raise Http404("No such bootstrap observation.")
    return run


@require_GET
def bootstrap_home(request):
    """Read-only: why this exists, the one-time state, the two durations, the newest candidate, the active / latest run.  Contacts no device."""
    candidates = list(models.ConfigurationBundle.objects.filter(kind=models.BundleKind.LEGACY_BASELINE).order_by("-created_at", "-id")[:10])
    runs = bootstrap_service.list_runs(limit=10)
    active = next((r for r in runs if r.is_running), None)
    latest = candidates[0] if candidates else None
    golden = bootstrap_service.legacy_golden()
    pending = next((r for r in runs if r.is_technical_pass and bootstrap_service.decision_of(r) is None), None)
    context = {
        "page_title": "Initial Golden Bootstrap", "gate": bootstrap_service.gate_blockers(), "golden": golden, "candidates": candidates, "latest": latest, "runs": runs,
        "active": active, "pending": pending, "policy": bootstrap_service.current_policy(), "production": soak_service.current_policy(),
        "notice": _BOOTSTRAP_NOTICES.get(request.GET.get("notice", "")), "refusals": _bootstrap_refusals(request.GET.get("codes", "")),
        "progress": bootstrap_service.progress(active) if active is not None else None, "max_reason": bootstrap_service.MAX_REASON_CHARS,
        "start_check": bootstrap_service.check_start(latest)[0] if (latest is not None and active is None and golden is None) else [],
        "integrity": bundle_service.verify_bundle_integrity(latest) if latest is not None else None,
    }
    return render(request, "core/bootstrap/home.html", context)


@require_POST
def bootstrap_probe(request):
    """Explicit POST + CSRF: the READ-ONLY readiness probe.  It reads the devices through the allowlisted sessions and persists nothing."""
    report = bootstrap_service.readiness_probe()
    return render(request, "core/bootstrap/probe.html", {"page_title": "Readiness probe", "report": report})


@require_POST
def bootstrap_capture(request):
    """Explicit, confirmed POST + CSRF: capture the CURRENT running configuration (read-only, sanitized, all-or-nothing) into an immutable candidate."""
    home = reverse("core:bootstrap_home")
    if request.POST.get("confirm") != "on":
        return redirect(f"{home}?{urlencode({'notice': 'CONFIRM_REQUIRED'})}")
    result = bootstrap_service.capture_candidate(actor=_actor(request))
    if result.bundle is None:
        return redirect(f"{home}?{urlencode({'notice': 'CAPTURE_REFUSED', 'codes': ','.join(b['code'] for b in result.blockers)[:300]})}")
    return redirect(f"{home}?{urlencode({'notice': 'CAPTURED'})}")


@require_GET
def bootstrap_run_detail(request, run_id):
    run = _bootstrap_run_or_404(run_id)
    decision = bootstrap_service.decision_of(run)
    candidate = run.candidate
    approval = bootstrap_service.check_initial_golden(candidate, run, None) if run.is_technical_pass and decision is None else None
    blockers = [b for b in (approval or []) if b["code"] not in ("CONFIG_DRIFT_DETECTED", "DRIFT_CHECK_INCOMPLETE")]
    context = {
        "page_title": f"Bootstrap {run.run_id}", "run": run, "candidate": candidate, "progress": bootstrap_service.progress(run), "decision": decision,
        "integrity": bundle_service.verify_bundle_integrity(candidate), "notice": _BOOTSTRAP_NOTICES.get(request.GET.get("notice", "")),
        "reasons": bootstrap_service.TERMINAL_REASONS, "timeline": list(run.samples.order_by("-bucket")[:bootstrap_service.MAX_SAMPLE_ROWS_SHOWN]),
        "approval_blockers": blockers, "max_reason": bootstrap_service.MAX_REASON_CHARS, "refusals": _bootstrap_refusals(request.GET.get("codes", "")),
        "devices": (candidate.payload.get("baseline") or {}).get("devices") or [], "sanitization": (candidate.payload.get("baseline") or {}).get("sanitization") or {},
        "golden": decision.golden_bundle if decision else None, "production": soak_service.current_policy(),
    }
    return render(request, "core/bootstrap/run_detail.html", context)


@require_POST
def bootstrap_start(request, bundle_id):
    """Explicit, confirmed POST + CSRF.  The browser sends ONLY the confirmation: the server decides the start, the 30-minute duration and every rule."""
    candidate = _bundle_or_404(bundle_id)
    home = reverse("core:bootstrap_home")
    if request.POST.get("confirm") != "on":
        return redirect(f"{home}?{urlencode({'notice': 'CONFIRM_REQUIRED'})}")
    result = bootstrap_service.start_bootstrap(candidate, actor=_actor(request))
    if result.run is None:
        return redirect(f"{home}?{urlencode({'notice': 'START_REFUSED', 'codes': ','.join(b['code'] for b in result.blockers)[:300]})}")
    return redirect(f"{reverse('core:bootstrap_run_detail', args=[result.run.run_id])}?{urlencode({'notice': 'STARTED' if result.created else 'ACTIVE'})}")


@require_POST
def bootstrap_cancel(request, run_id):
    run = _bootstrap_run_or_404(run_id)
    target = reverse("core:bootstrap_run_detail", args=[run.run_id])
    if request.POST.get("confirm") != "on":
        return redirect(f"{target}?{urlencode({'notice': 'CONFIRM_REQUIRED'})}")
    result = bootstrap_service.cancel_bootstrap(run, actor=_actor(request))
    return redirect(f"{target}?{urlencode({'notice': 'CANCELLED' if result.cancelled else 'CANCEL_REFUSED'})}")


@require_POST
def bootstrap_approve(request, run_id):
    """The operator's explicit approval of the INITIAL Golden: the acknowledgement + the echoed run / candidate / digests (staleness guards) + a comment.
    The server re-reads every device's configuration first and refuses on any difference."""
    run = _bootstrap_run_or_404(run_id)
    target = reverse("core:bootstrap_run_detail", args=[run.run_id])
    if request.POST.get("confirm") != "on":
        return redirect(f"{target}?{urlencode({'notice': 'CONFIRM_REQUIRED'})}")
    result = bootstrap_service.approve(
        run, actor=_actor(request), reason=request.POST.get("reason", ""),
        confirm={"run_id": request.POST.get("expected_run_id", ""), "candidate_id": request.POST.get("expected_candidate_id", ""),
                 "candidate_digest": request.POST.get("expected_candidate_digest", ""), "baseline_digest": request.POST.get("expected_baseline_digest", "")},
    )
    if result.refused:
        return redirect(f"{target}?{urlencode({'notice': 'APPROVE_REFUSED', 'codes': ','.join(b['code'] for b in result.blockers)[:300]})}")
    return redirect(f"{reverse('core:bundle_detail', args=[result.bundle.bundle_id])}?{urlencode({'notice': 'APPROVED' if result.created else 'APPROVED_EXISTS'})}")


def _legacy_bundle_context(bundle, integrity, notice) -> dict:
    """The legacy candidate / initial Golden page (read-only): provenance, timestamps, the captured devices and -- for the Golden -- the observation and decision."""
    baseline = bundle.payload.get("baseline") or {}
    block = bundle.lineage.get("legacy_bootstrap") or {}
    decision = models.LegacyBootstrapDecision.objects.filter(golden_bundle=bundle).select_related("run", "candidate").first() if bundle.kind == models.BundleKind.GOLDEN else None
    lineage = bundle_service.lineage_of(bundle)
    return {
        "page_title": f"Bundle {bundle.bundle_id}", "bundle": bundle, "integrity": integrity, "notice": notice, "kind_badge": _BUNDLE_KIND_BADGE[bundle.kind],
        "baseline": baseline, "devices": baseline.get("devices") or [], "prov": block, "decision": decision, "lineage": lineage,
        "run": decision.run if decision else None, "sanitization": baseline.get("sanitization") or {}, "production": soak_service.current_policy(),
    }


# ---------------------------------------------------------------------------
# Automation workbench: Configuration Changes (incremental patch) and Remove Configuration (intentional removal).
#
# Both pages share one split layout: LEFT = what the operator wants to change / remove, RIGHT = the sanitized,
# line-numbered running configuration.  GET never contacts a device.  The only device reads are explicit POSTs
# (a read-only snapshot capture, and the read-only import a contribution uses as context).  Nothing here executes:
# "Push / Execute" hands off to the Change's own precheck + Execute pages (the one explicitly approved execution path).
# ---------------------------------------------------------------------------
_WORKFLOW_PAGES = {
    models.ChangeWorkflow.CONFIGURATION_CHANGES: "core:workbench_changes",
    models.ChangeWorkflow.REMOVE_CONFIGURATION: "core:workbench_remove",
}


def _workbench_context(request, workflow: str) -> dict:
    from django.core.exceptions import ValidationError

    snaps = workbench_service.snapshots
    scope = snaps.workbench_scope()      # the ONE shared scope: NetBox-managed AND capturable (never R5); fails closed
    devices = scope.devices
    device = (request.GET.get("device") or request.POST.get("device") or "").strip()
    row = scope.get(device)
    snapshot = None
    snapshot_id = (request.GET.get("snapshot") or request.POST.get("snapshot") or "").strip()
    if row and snapshot_id:
        try:
            snapshot = snaps.get_snapshot(snapshot_id, device)
        except (ValueError, ValidationError):
            snapshot = None
    change = None
    change_id = (request.GET.get("change") or request.POST.get("change") or "").strip()
    if change_id:
        change = models.Change.objects.filter(change_id=change_id, metadata__workflow=workflow).first()
    latest_plan = change_plan_service.get_latest_plan(change) if change else None
    return {
        "workflow": workflow, "devices": devices, "device": row, "snapshot": snapshot, "change": change,
        "scope_unavailable": scope.unavailable,
        "recent_changes": workbench_service.workflow_changes(workflow, row["name"] if row else None),
        "fragment_highlight": [], "preview": False, "page_key": "automation",
        "heading": "Configuration Changes" if workflow == models.ChangeWorkflow.CONFIGURATION_CHANGES else "Remove Configuration",
        "intro": ("Small incremental changes to a running device. The candidate is exactly your contribution -- never a full replacement "
                  "configuration -- and nothing is sent until the Change is prechecked and explicitly executed."
                  if workflow == models.ChangeWorkflow.CONFIGURATION_CHANGES else
                  "Intentionally remove selected configuration from a running device, by line range or by semantic object. Dependencies are "
                  "checked first; anything still in use is blocked, and now-unused objects are only proposed. This is not rollback."),
        "left_label": "Requested change" if workflow == models.ChangeWorkflow.CONFIGURATION_CHANGES else "Requested removal",
        "plan_rows": workbench_service.plan_rows(change) if change else [],
        "latest_validation": change_validation_service.get_latest_validation(change) if change else None,
        "validation_currency": change_validation_service.get_validation_currency(change, check_sources=False) if change else None,
        "network_config_currency": network_config_validation.get_currency(change) if change else None,
        "latest_plan": latest_plan,
        "plan_currency": change_plan_service.get_plan_currency(latest_plan, check_sources=False) if latest_plan else None,
        "latest_precheck": health_service.latest_run(mode="CHANGE_PRECHECK", change=change) if change else None,
        "latest_execution": execution_service.latest_run(change) if change else None,
        "latest_live_validation": network_config_validation.get_latest(
            change,
            operations=(models.NetworkConfigValidationOperation.POST_PUSH,
                        models.NetworkConfigValidationOperation.POST_REMOVAL),
        ) if change else None,
        "latest_intent": change.device_intents.order_by("device_name").first() if change else None,
        "page_url": reverse(_WORKFLOW_PAGES[workflow]),
        "running_validation": (
            snapshot.network_config_validation_runs.filter(
                operation_type=models.NetworkConfigValidationOperation.RUNNING
            ).order_by("-created_at", "-id").first() if snapshot else None
        ),
    }


def _workbench_redirect(workflow: str, **params) -> HttpResponse:
    return redirect(f"{reverse(_WORKFLOW_PAGES[workflow])}?{urlencode({k: v for k, v in params.items() if v})}")


@require_POST
def workbench_snapshot(request):
    """Explicit, read-only capture of one managed device's sanitized running configuration."""
    workflow = request.POST.get("workflow", "")
    if workflow not in _WORKFLOW_PAGES:
        return HttpResponseBadRequest("Unknown workflow.")
    device = (request.POST.get("device") or "").strip()[:64]
    # Scope is enforced inside the shared capture (not only by the dropdown): a crafted POST for R5 / an unknown name is refused.
    outcome = workbench_service.snapshots.capture(device, actor=_actor(request))
    if outcome.refused_request:
        return HttpResponseBadRequest(outcome.message, content_type="text/plain; charset=utf-8")
    if outcome.snapshot is None:
        return _workbench_redirect(workflow, device=device, error=outcome.message[:300])
    return _workbench_redirect(workflow, device=device, snapshot=str(outcome.snapshot.snapshot_id))


@require_POST
def workbench_validate_running(request, snapshot_id):
    """Explicit on-demand assessment of an existing managed device configuration; never remediates."""
    snapshot = workbench_service.snapshots.get_snapshot(snapshot_id)
    if snapshot is None:
        raise Http404("Unknown running configuration snapshot.")
    workflow = request.POST.get("workflow", models.ChangeWorkflow.CONFIGURATION_CHANGES)
    if workflow not in _WORKFLOW_PAGES:
        return HttpResponseBadRequest("Unknown workflow.")
    network_config_validation.validate_running(snapshot, actor=_actor(request))
    return _workbench_redirect(workflow, device=snapshot.device_name, snapshot=str(snapshot.snapshot_id))


@require_GET
def workbench_changes(request):
    context = _workbench_context(request, models.ChangeWorkflow.CONFIGURATION_CHANGES)
    snapshot = context["snapshot"]
    mode = request.GET.get("mode") if request.GET.get("mode") in ("cli", "structured") else "cli"
    op_key = request.GET.get("op") if request.GET.get("op") in workbench_service.contribution.OPERATIONS else "static_route"
    context.update({
        "mode": mode, "op_key": op_key, "error": request.GET.get("error", ""),
        "catalogue": workbench_service.contribution.operation_catalogue(snapshot.platform) if snapshot else [],
        "existing": workbench_service.contribution.snapshot_context(snapshot.text, snapshot.platform) if snapshot else {},
        "lines": workbench_service.snapshots.numbered(snapshot) if snapshot else [],
    })
    context["op_fields"] = workbench_service.contribution.OPERATIONS[op_key][2]
    return render(request, "core/automation/workbench/changes.html", context)


def _operations_from_post(request, snapshot) -> tuple[list, list]:
    """-> (operations, rejected lines).  Direct CLI is normalized; a widget is one structured operation."""
    contribution = workbench_service.contribution
    if request.POST.get("mode") == "cli":
        parsed = contribution.parse_direct_cli(request.POST.get("fragment", "")[:8000], snapshot.platform, snapshot.text)
        return parsed["operations"], parsed["rejected"]
    key = request.POST.get("op", "")
    if key not in contribution.OPERATIONS:
        return [], [{"line": 0, "text": "", "reason": "UNKNOWN_OPERATION"}]
    fields = ("destination", "next_hop", "distance", "interface", "cidr", "role", "name", "peer_address", "remote_asn", "area")
    return [{"op": key, **{f: request.POST.get(f, "").strip()[:128] for f in fields if request.POST.get(f, "").strip()}}], []


@require_POST
def workbench_changes_preview(request):
    """Normalize + statically check the requested contribution.  No database write, no device contact."""
    context = _workbench_context(request, models.ChangeWorkflow.CONFIGURATION_CHANGES)
    snapshot = context["snapshot"]
    if snapshot is None:
        return HttpResponseBadRequest("Capture a running configuration first.")
    contribution = workbench_service.contribution
    operations, rejected = _operations_from_post(request, snapshot)
    existing = contribution.snapshot_context(snapshot.text, snapshot.platform)
    problems = [p for op in operations for p in contribution.check_operation(op, snapshot.platform, existing)]
    highlight = sorted({n for op in operations for n in op.get("source_lines", [])}) if request.POST.get("mode") == "cli" else []
    context.update({
        "mode": request.POST.get("mode", "cli"), "op_key": request.POST.get("op") or "static_route", "preview": True,
        "operations": operations, "rejected": rejected, "problems": problems, "fragment": request.POST.get("fragment", "")[:8000],
        "operations_json": json.dumps([{k: v for k, v in op.items() if k != "source_lines"} for op in operations]),
        "catalogue": contribution.operation_catalogue(snapshot.platform), "existing": existing,
        "lines": workbench_service.snapshots.numbered(snapshot), "fragment_highlight": highlight,
    })
    context["op_fields"] = contribution.OPERATIONS.get(context["op_key"], contribution.OPERATIONS["static_route"])[2]
    return render(request, "core/automation/workbench/changes.html", context)


@require_POST
def workbench_changes_save(request):
    """Save Draft: build the incremental contribution Change (read-only import as context), then validate + plan it."""
    context = _workbench_context(request, models.ChangeWorkflow.CONFIGURATION_CHANGES)
    snapshot = context["snapshot"]
    if snapshot is None:
        return HttpResponseBadRequest("Capture a running configuration first.")
    try:
        operations = json.loads(request.POST.get("operations", "[]"))
    except ValueError:
        return HttpResponseBadRequest("Malformed operations.")
    if not isinstance(operations, list) or len(operations) > 20 or not all(isinstance(op, dict) for op in operations):
        return HttpResponseBadRequest("Malformed operations.")
    try:
        change = workbench_service.contribution.create_contribution_change(
            snapshot=snapshot, operations=operations, actor=_actor(request), title=request.POST.get("title", "")[:200])
    except workbench_service.contribution.ContributionError as exc:
        return _workbench_redirect(models.ChangeWorkflow.CONFIGURATION_CHANGES, device=snapshot.device_name,
                                   snapshot=str(snapshot.snapshot_id), error="; ".join(exc.problems)[:300])
    workbench_service.validate_and_plan(change, actor=_actor(request))
    return _workbench_redirect(models.ChangeWorkflow.CONFIGURATION_CHANGES, device=snapshot.device_name,
                               snapshot=str(snapshot.snapshot_id), change=change.change_id)


@require_GET
def workbench_remove(request):
    context = _workbench_context(request, models.ChangeWorkflow.REMOVE_CONFIGURATION)
    snapshot = context["snapshot"]
    mode = request.GET.get("mode") if request.GET.get("mode") in ("line", "smart") else "smart"
    analysis, selection = None, None
    if snapshot is not None:
        proposals = request.GET.getlist("proposal")
        try:
            if mode == "line" and request.GET.get("from_line") and request.GET.get("to_line"):
                selection = workbench_service.removal_selection(models.RemovalMode.LINE_RANGE, from_line=int(request.GET["from_line"]),
                                                                to_line=int(request.GET["to_line"]), accepted_proposals=proposals)
                analysis = workbench_service.analyze_removal(snapshot, models.RemovalMode.LINE_RANGE, selection)
            elif mode == "smart" and request.GET.getlist("obj"):
                selection = workbench_service.removal_selection(models.RemovalMode.SEMANTIC, object_ids=request.GET.getlist("obj")[:50],
                                                                accepted_proposals=proposals)
                analysis = workbench_service.analyze_removal(snapshot, models.RemovalMode.SEMANTIC, selection)
        except ValueError:
            analysis = {"status": "BLOCKED", "blockers": [{"code": "INVALID_SELECTION", "message": "Line numbers must be integers."}],
                        "items": [], "proposals": [], "warnings": [], "highlight": []}
    context.update({
        "mode": mode, "analysis": analysis, "selection": selection, "selection_json": json.dumps(selection or {}),
        "error": request.GET.get("error", ""),
        "objects": workbench_service.removal.object_catalogue(snapshot.text, snapshot.platform) if snapshot and mode == "smart" else [],
        "selected_objects": set(request.GET.getlist("obj")), "accepted": set(request.GET.getlist("proposal")),
        "lines": workbench_service.snapshots.numbered(snapshot, highlight=(analysis or {}).get("highlight", [])) if snapshot else [],
        "from_line": request.GET.get("from_line", ""), "to_line": request.GET.get("to_line", ""),
    })
    return render(request, "core/automation/workbench/remove.html", context)


@require_POST
def workbench_remove_save(request):
    """Save Draft: persist the READY removal as a Change (re-analyzed server-side), then validate + plan it."""
    context = _workbench_context(request, models.ChangeWorkflow.REMOVE_CONFIGURATION)
    snapshot = context["snapshot"]
    if snapshot is None:
        return HttpResponseBadRequest("Capture a running configuration first.")
    mode = request.POST.get("mode")
    if mode not in models.RemovalMode.values:
        return HttpResponseBadRequest("Unknown removal mode.")
    try:
        raw = json.loads(request.POST.get("selection", "{}"))
        selection = workbench_service.removal_selection(
            mode, from_line=raw.get("from_line"), to_line=raw.get("to_line"), object_ids=raw.get("object_ids") or (),
            accepted_proposals=raw.get("accepted_proposals") or ())
    except (ValueError, TypeError, AttributeError):
        return HttpResponseBadRequest("Malformed selection.")
    try:
        change = workbench_service.create_removal_change(snapshot=snapshot, mode=mode, selection=selection, actor=_actor(request),
                                                         title=request.POST.get("title", "")[:200])
    except workbench_service.RemovalRefused as exc:
        return _workbench_redirect(models.ChangeWorkflow.REMOVE_CONFIGURATION, device=snapshot.device_name,
                                   snapshot=str(snapshot.snapshot_id), error=str(exc)[:300])
    workbench_service.validate_and_plan(change, actor=_actor(request))
    return _workbench_redirect(models.ChangeWorkflow.REMOVE_CONFIGURATION, device=snapshot.device_name,
                               snapshot=str(snapshot.snapshot_id), change=change.change_id)


@require_POST
def workbench_revalidate(request, change_id):
    """Explicit re-validation + plan for a workbench Change (existing services; no device contact, no execution)."""
    change = models.Change.objects.filter(change_id=change_id, metadata__workflow__in=list(_WORKFLOW_PAGES)).first()
    if change is None:
        raise Http404("Unknown workbench change.")
    workbench_service.validate_and_plan(change, actor=_actor(request))
    guard = (change.metadata or {}).get("workflow_snapshot") or {}
    return _workbench_redirect(change.metadata["workflow"], device=guard.get("device", ""), snapshot=guard.get("snapshot_id", ""),
                               change=change.change_id)


@require_POST
def workbench_revise(request, change_id):
    """Start an immutable candidate revision, then hand editing to Device Builder."""
    change = models.Change.objects.filter(
        change_id=change_id, metadata__workflow=models.ChangeWorkflow.CONFIGURATION_CHANGES
    ).first()
    if change is None:
        raise Http404("Unknown Configuration Changes draft.")
    try:
        revisions = workbench_service.revise_change(
            change=change, actor=_actor(request), title=request.POST.get("title", "")
        )
    except workbench_service.RevisionRefused as exc:
        guard = (change.metadata or {}).get("workflow_snapshot") or {}
        return _workbench_redirect(
            models.ChangeWorkflow.CONFIGURATION_CHANGES,
            device=guard.get("device", ""), snapshot=guard.get("snapshot_id", ""),
            change=change.change_id, error=str(exc)[:300],
        )
    return redirect("core:device_builder_edit", change_id=change.change_id, intent_id=revisions[0].device_intent_id)


@require_POST
def workbench_archive(request, change_id):
    """Archive a workbench Change while retaining every audit/evidence row."""
    change = models.Change.objects.filter(change_id=change_id, metadata__workflow__in=list(_WORKFLOW_PAGES)).first()
    if change is None:
        raise Http404("Unknown workbench change.")
    if request.POST.get("confirmation") != "ARCHIVE":
        guard = (change.metadata or {}).get("workflow_snapshot") or {}
        return _workbench_redirect(
            change.metadata["workflow"], device=guard.get("device", ""), snapshot=guard.get("snapshot_id", ""),
            change=change.change_id, error="Type ARCHIVE to retire this Change without deleting its history.",
        )
    workbench_service.archive_change(change=change, actor=_actor(request))
    guard = (change.metadata or {}).get("workflow_snapshot") or {}
    return _workbench_redirect(change.metadata["workflow"], device=guard.get("device", ""), snapshot=guard.get("snapshot_id", ""))


# --- V2 Phase 3: template library -----------------------------------------------------------------------------------------
# Thin views over core.services.config_templates.  A template is only ever read here; "Use Template" produces an ordinary
# Change in Device Builder, and the ONE execution route remains that Change's own Execute page.

def _template_or_404(template_id):
    template = template_service.get_template(template_id)
    if template is None:
        raise Http404("Unknown template.")
    return template


def _template_version_or_404(template_id, version):
    row = template_service.get_version(template_id, version)
    if row is None:
        raise Http404("Unknown template version.")
    return row


def _template_redirect(name, *args, notice="", error=""):
    query = urlencode({k: v[:600] for k, v in (("notice", notice), ("error", error)) if v})
    return redirect(reverse(name, args=args) + (f"?{query}" if query else ""))


def _template_flash(request) -> dict:
    return {"notice": request.GET.get("notice", "")[:600], "error": request.GET.get("error", "")[:600]}


@require_GET
def template_library(request):
    filters = {"family": request.GET.get("family", ""), "platform": request.GET.get("platform", ""),
               "origin": request.GET.get("origin", ""), "query": request.GET.get("q", "").strip()[:80]}
    if filters["family"] not in models.TemplateFamily.values:
        filters["family"] = ""
    if filters["origin"] not in models.TemplateOrigin.values:
        filters["origin"] = ""
    if filters["platform"] not in models.Platform.values:
        filters["platform"] = ""
    scope = workbench_service.snapshots.workbench_scope()
    context = {
        "page_title": "Automation · Template Library", "page_key": "automation", "filters": filters,
        "rows": template_service.list_templates(include_retired=request.GET.get("retired") == "1", **filters),
        "show_retired": request.GET.get("retired") == "1",
        "families": models.TemplateFamily.choices, "origins": models.TemplateOrigin.choices, "platforms": models.Platform.choices,
        "devices": scope.devices, "scope_unavailable": scope.unavailable, **_template_flash(request),
    }
    return render(request, "core/templates_library/library.html", context)


@require_GET
def template_detail(request, template_id):
    template = _template_or_404(template_id)
    context = {"page_title": f"Template · {template.name}", "page_key": "automation", "template": template,
               "versions": list(template.versions.order_by("-version")), **_template_flash(request)}
    return render(request, "core/templates_library/detail.html", context)


@require_GET
def template_version_detail(request, template_id, version):
    row = _template_version_or_404(template_id, version)
    parameter_set = request.GET.get("set", "")
    if parameter_set not in (row.parameter_sets or {}):
        parameter_set = ""
    provenance = row.provenance or {}
    context = {
        "page_title": f"Template · {row.template.name} v{row.version}", "page_key": "automation", "version": row, "template": row.template,
        "intent_yaml": yaml.safe_dump(row.intent, sort_keys=False, default_flow_style=False),
        "parameters": template_clone.parameter_form(row, parameter_set=parameter_set),
        "parameter_set": parameter_set, "parameter_sets": sorted(row.parameter_sets or {}),
        "provenance": provenance, "sources": provenance.get("sources") or [], "differences": provenance.get("differences") or [],
        "conflicts": provenance.get("conflicts") or [], "derived_from": provenance.get("derived_from") or [],
        "import_metadata": template_service.import_metadata(row),
        "feature_templates": template_features.feature_templates(row.required_features, row.platforms),
        "publication_problems": [] if row.is_published else template_service.publication_problems(row),
        "deployable": (row.constraints or {}).get("deployable") is not False,
        "platform_choices": [(value, label) for value, label in models.Platform.choices if value in (row.platforms or [])],
        "draft_changes": models.Change.objects.filter(lifecycle_state=models.ChangeLifecycleState.DRAFT).exclude(
            metadata__has_key="archived_at").order_by("-created_at")[:25],
        "clone_modes": template_clone.MODES, **_template_flash(request),
    }
    return render(request, "core/templates_library/version.html", context)


@require_POST
def template_extract(request):
    """Create Template from Running Config: one explicit READ-ONLY capture of a managed device -> a draft template."""
    family = request.POST.get("family", models.TemplateFamily.CUSTOM)
    if family not in models.TemplateFamily.values:
        family = models.TemplateFamily.CUSTOM
    try:
        row = template_service.extract_from_device(request.POST.get("device", "")[:64], actor=_actor(request),
                                                   name=request.POST.get("name", "").strip()[:120], family=family)
    except template_service.TemplateError as exc:
        return _template_redirect("core:template_library", error="; ".join(exc.problems))
    return _template_redirect("core:template_version_detail", row.template.template_id, row.version,
                              notice="Draft template extracted from the running configuration. Review it, then publish.")


@require_POST
def template_publish(request, template_id, version):
    row = _template_version_or_404(template_id, version)
    try:
        template_service.publish(row, actor=_actor(request))
    except template_service.TemplateError as exc:
        return _template_redirect("core:template_version_detail", template_id, version, error="; ".join(exc.problems))
    return _template_redirect("core:template_version_detail", template_id, version, notice="Published. This version is now immutable.")


@require_POST
def template_discard(request, template_id, version):
    row = _template_version_or_404(template_id, version)
    try:
        template_service.discard_draft(row, actor=_actor(request))
    except template_service.TemplateError as exc:
        return _template_redirect("core:template_version_detail", template_id, version, error="; ".join(exc.problems))
    return _template_redirect("core:template_library", notice="Draft discarded.")


@require_POST
def template_retire(request, template_id):
    template_service.retire(_template_or_404(template_id), actor=_actor(request))
    return _template_redirect("core:template_detail", template_id, notice="Template retired. Its versions are retained.")


@require_GET
def template_export(request, template_id, version):
    row = _template_version_or_404(template_id, version)
    try:
        filename, data = template_service.export_package(row, actor=_actor(request))
    except template_service.TemplateError as exc:
        return _template_redirect("core:template_version_detail", template_id, version, error="; ".join(exc.problems))
    response = HttpResponse(data, content_type="application/yaml; charset=utf-8")
    response["Content-Disposition"] = f'attachment; filename="{_safe_filename_component(filename.rsplit(".nmas-template.yaml", 1)[0])}.nmas-template.yaml"'
    response["X-Content-Type-Options"] = "nosniff"
    return response


@require_POST
def template_import(request):
    upload = request.FILES.get("package")
    if upload is None:
        return _template_redirect("core:template_library", error="Choose a template package file.")
    if upload.size > template_package.MAX_PACKAGE_BYTES:
        return _template_redirect("core:template_library", error="PACKAGE_TOO_LARGE: the package exceeds the size limit.")
    try:
        row, created = template_service.import_package(upload.read(template_package.MAX_PACKAGE_BYTES + 1), actor=_actor(request))
    except template_service.TemplateError as exc:
        return _template_redirect("core:template_library", error=f"{exc.code}: " + "; ".join(exc.problems))
    return _template_redirect("core:template_version_detail", row.template.template_id, row.version,
                              notice="Package registered as an immutable version. Nothing was executed." if created
                              else "This exact package is already registered.")


@require_POST
def template_clone_into_change(request, template_id, version):
    """Use Template: clone into a NEW editable working intent (a new or an existing Draft Change).  Never pushes."""
    row = _template_version_or_404(template_id, version)
    change = None
    if request.POST.get("change_id"):
        change = models.Change.objects.filter(change_id=request.POST["change_id"][:32]).first()
        if change is None:
            return _template_redirect("core:template_version_detail", template_id, version, error="Unknown target Change.")
    values = {name: (request.POST.get(f"p_{name}") == "on" if spec.get("type") == "boolean" else request.POST.get(f"p_{name}", ""))
              for name, spec in (row.parameters or {}).items()}
    target_type = request.POST.get("target_type", models.DeviceIntentTargetType.EXISTING_DEVICE)
    try:
        result = template_clone.clone_into_change(
            version=row, device_name=request.POST.get("device_name", "").strip()[:64], platform=request.POST.get("platform", ""),
            parameter_values=values, actor=_actor(request), change=change, title=request.POST.get("title", "").strip()[:200],
            mode=request.POST.get("mode", template_clone.FULL), target_type=target_type)
    except template_service.TemplateError as exc:
        return _template_redirect("core:template_version_detail", template_id, version, error=f"{exc.code}: " + "; ".join(exc.problems))
    notice = (f"Working intent cloned from {row.ref}. The template is unchanged; edit, validate, plan and execute this Change as usual."
              + (f" {len(result.warnings)} note(s): " + " | ".join(result.warnings[:6]) if result.warnings else ""))
    return redirect(reverse("core:device_builder_edit", args=[result.change.change_id, result.intent.pk]) + "?" + urlencode({"import_notice": notice[:300]}))


@require_POST
def template_version_from_change(request, change_id, intent_id):
    """New template version (or a new derived template) from an edited Device Builder working intent."""
    change, intent, revision = _resolve_editor_target(change_id, intent_id)
    try:
        row = template_service.version_from_revision(revision, actor=_actor(request), name=request.POST.get("name", "").strip()[:120])
    except template_service.TemplateError as exc:
        return redirect(reverse("core:device_builder_edit", args=[change.change_id, intent.pk]) + "?" + urlencode({"import_error": "; ".join(exc.problems)[:300]}))
    return _template_redirect("core:template_version_detail", row.template.template_id, row.version,
                              notice="Draft template version created from the working intent. Review it, then publish.")


# =============================================================================
# V2 Phase 5A -- new-device provisioning.  Thin: every rule lives in ``provisioning_service``; a view parses the POST, calls ONE stage and
# redirects to the detail page, where the recorded ProvisioningEvent (advanced or blocked, with its codes) is what the operator reads.
# No view here writes to a device: the approved plan is executed through the ordinary ``change_execute_run`` route, whose engine gate
# enforces the provisioning approval.
# =============================================================================


def _provisioning_or_404(prov_id):
    run = provisioning_service.get_run(prov_id)
    if run is None:
        raise Http404("Unknown provisioning request")
    return run


@require_GET
def provisioning_list(request):
    context = {
        "page_title": "New device provisioning", "page_key": "automation", "runs": provisioning_service.list_runs(), "platforms": models.Platform.choices,
        "roles": provisioning_service.ROLES, "refusals": _provisioning_refusals(request.GET.get("codes", "")),
        "transports": [(value, label, provisioning_service.transport_support(value, "DOCKER_EXEC")) for value, label in models.Platform.choices],
    }
    return render(request, "core/provisioning/list.html", context)


def _provisioning_refusals(codes: str) -> list[dict]:
    """Stable codes from the query string -> fixed messages (unknown codes are dropped; no request text is ever echoed)."""
    known = provisioning_service.codes.BLOCKERS
    return [{"code": code, "message": known[code][0], "remediation": known[code][1]} for code in codes.split(",")[:8] if code in known]


@require_POST
def provisioning_create(request):
    result = provisioning_service.create_request(
        device_name=request.POST.get("device_name", ""), platform=request.POST.get("platform", ""), role=request.POST.get("role", ""),
        requested_by=_actor(request), site=request.POST.get("site", ""), image_reference=request.POST.get("image_reference", ""),
        disposable=request.POST.get("disposable") == "on",
    )
    if result.run is None:
        return redirect(f"{reverse('core:provisioning_list')}?{urlencode({'codes': ','.join(result.codes)})}")
    return redirect(result.run.get_absolute_url())


@require_GET
def provisioning_detail(request, prov_id):
    run = _provisioning_or_404(prov_id)
    soak = run.soak_run
    context = {
        "page_title": f"Provisioning {run.prov_id}", "page_key": "automation", "run": run, "stages": provisioning_service.stage_rows(run),
        "next_stage": provisioning_service.next_stage(run), "events": list(run.events.order_by("-sequence")[:60]),
        "registry": models.ProvisionedDevice.objects.filter(run=run).first(), "soak": soak,
        "soak_progress": soak_service.progress(soak) if soak else None,
        "transport_choices": models.BootstrapTransport.choices,
        "execution_modes": models.ExecutionMode.choices,
    }
    return render(request, "core/provisioning/detail.html", context)


def _provisioning_step(request, prov_id, call):
    run = _provisioning_or_404(prov_id)
    call(run)
    return redirect(run.get_absolute_url())


@require_POST
def provisioning_identity(request, prov_id):
    post = request.POST
    return _provisioning_step(request, prov_id, lambda run: provisioning_service.define_identity(
        run, actor=_actor(request), bootstrap_transport=post.get("bootstrap_transport", ""),
        bootstrap_target={"container": post.get("container", "").strip(), "lab": post.get("lab", "").strip()},
        management={"interface": post.get("mgmt_interface", "").strip(), "ipv4": post.get("mgmt_ipv4", "").strip() or None,
                    "ipv6": post.get("mgmt_ipv6", "").strip() or None, "vlan": post.get("mgmt_vlan", "").strip() or None,
                    "assignment": post.get("mgmt_assignment", "static")},
    ))


@require_POST
def provisioning_bootstrap(request, prov_id):
    return _provisioning_step(request, prov_id, lambda run: provisioning_service.classify_bootstrap(run, actor=_actor(request)))


@require_POST
def provisioning_capability(request, prov_id):
    return _provisioning_step(request, prov_id, lambda run: provisioning_service.resolve_capabilities(run, actor=_actor(request)))


@require_POST
def provisioning_ipam(request, prov_id):
    return _provisioning_step(request, prov_id, lambda run: provisioning_service.plan_ipam(run, actor=_actor(request)))


@require_POST
def provisioning_candidate(request, prov_id):
    mode = request.POST.get("execution_mode", models.ExecutionMode.COMPLETE)
    if mode not in models.ExecutionMode.values:
        mode = models.ExecutionMode.COMPLETE
    return _provisioning_step(request, prov_id, lambda run: provisioning_service.generate_candidate(run, actor=_actor(request), execution_mode=mode))


@require_POST
def provisioning_validation(request, prov_id):
    return _provisioning_step(request, prov_id, lambda run: provisioning_service.record_validation(run, actor=_actor(request)))


@require_POST
def provisioning_plan(request, prov_id):
    return _provisioning_step(request, prov_id, lambda run: provisioning_service.build_plan(run, actor=_actor(request)))


@require_POST
def provisioning_precheck(request, prov_id):
    return _provisioning_step(request, prov_id, lambda run: provisioning_service.run_precheck(run, actor=_actor(request)))


@require_POST
def provisioning_approve(request, prov_id):
    """The browser echoes the candidate hash it was shown (a staleness guard) and an explicit acknowledgement."""
    if request.POST.get("confirm") != "on":
        return redirect(_provisioning_or_404(prov_id).get_absolute_url())
    return _provisioning_step(request, prov_id, lambda run: provisioning_service.approve(
        run, actor=_actor(request), confirm_candidate_hash=request.POST.get("candidate_hash", ""), comment=request.POST.get("comment", "")))


@require_POST
def provisioning_nsot_sync(request, prov_id):
    return _provisioning_step(request, prov_id, lambda run: provisioning_service.sync_nsot(run, actor=_actor(request)))


@require_POST
def provisioning_probation(request, prov_id):
    if request.POST.get("confirm") != "on":
        return redirect(_provisioning_or_404(prov_id).get_absolute_url())
    return _provisioning_step(request, prov_id, lambda run: provisioning_service.start_probation(run, actor=_actor(request)))


@require_POST
def provisioning_cancel(request, prov_id):
    if request.POST.get("confirm") != "on":
        return redirect(_provisioning_or_404(prov_id).get_absolute_url())
    return _provisioning_step(request, prov_id, lambda run: provisioning_service.cancel(run, actor=_actor(request), reason=request.POST.get("reason", "")))


@require_POST
def provisioning_decommission(request, prov_id):
    if request.POST.get("confirm") != "on":
        return redirect(_provisioning_or_404(prov_id).get_absolute_url())
    return _provisioning_step(request, prov_id, lambda run: provisioning_service.decommission(run, actor=_actor(request)))


# =============================================================================
# V2 Phase 5B -- traffic / test workbench.  The browser sends endpoint NAMES, a test family and a few numbers; it never sends an address,
# a pid, a flag or a command.  Every rule and bound lives in ``traffic_service``; these views only parse and render.
# =============================================================================
_TRAFFIC_FIELDS = ("source", "destination", "address_family", "family", "protocol", "count", "size", "max_hops", "port", "timeout", "duration",
                   "bandwidth_kbps", "parallel", "length", "change_id", "prov_id", "soak_id")


@require_GET
def traffic_workbench(request):
    known = traffic_service.REFUSALS
    refusals = [{"code": code, "message": known[code]} for code in request.GET.get("codes", "").split(",")[:8] if code in known]
    context = {
        "page_title": "Traffic / test workbench", "page_key": "automation", "endpoints": list(traffic_service.catalogue().values()),
        "families": models.TrafficTestFamily.choices, "address_families": models.TrafficAddressFamily.choices,
        "limits": traffic_service.form_limits(), "active": traffic_service.active_run(), "runs": traffic_service.list_runs(),
        "refusals": refusals, "refused_field": request.GET.get("field", "")[:32] if refusals else "",
    }
    return render(request, "core/traffic/workbench.html", context)


@require_POST
def traffic_run_create(request):
    """Explicit POST + CSRF.  Runs ONE bounded test synchronously (its time budget is a few seconds) and shows the recorded evidence."""
    data = {name: request.POST.get(name, "") for name in _TRAFFIC_FIELDS}
    run, errors = traffic_service.request_run(data, operator=_actor(request))
    if run is None:
        query = {"codes": ",".join(e["code"] for e in errors)}
        field = next((e.get("field") for e in errors if e.get("field")), "")
        if field:
            query["field"] = field
        return redirect(f"{reverse('core:traffic_workbench')}?{urlencode(query)}")
    return redirect(run.get_absolute_url())


@require_GET
def traffic_run_detail(request, run_id):
    run = traffic_service.get_run(run_id)
    if run is None:
        raise Http404("Unknown traffic run")
    context = {"page_title": f"Traffic run {str(run.run_id)[:8]}", "page_key": "automation", "run": run,
               "failure_message": traffic_service.FAILURES.get(run.failure_reason, "")}
    return render(request, "core/traffic/run_detail.html", context)
