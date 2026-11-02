"""
Injects the resolved theme/context into every template's context, so no
individual view has to remember to do it. Page identity comes from the
URL name (set on ``request.resolver_match`` by Django's URL resolver
before templates render), mapped to a theme "page_key" via
``PAGE_URL_NAMES`` below.
"""

from __future__ import annotations

from django.conf import settings

from . import theme_assets, theme_registry

# Maps URL names -> the theme registry's page_key namespace. Sub-pages of a
# section (e.g. monitoring:resources) share that section's page_key so
# contextual theming is consistent across a whole area.
PAGE_URL_NAMES = {
    "core:home": "home",
    "core:monitoring_landing": "monitoring",
    "core:monitoring_resources": "monitoring",
    "core:monitoring_link_events": "monitoring",
    "core:monitoring_link_state_traffic": "monitoring",
    "core:device_builder": "device_builder",
    "core:device_builder_capabilities": "device_builder",
    "core:device_builder_changes": "device_builder",
    "core:device_builder_change_detail": "device_builder",
    "core:device_builder_edit": "device_builder",
    "core:device_builder_advanced": "device_builder",
    "core:device_builder_candidate_diff": "device_builder",
    "core:template_library": "automation",
    "core:template_detail": "automation",
    "core:template_version_detail": "automation",
    "core:change_validation": "device_builder",
    "core:change_validation_detail": "device_builder",
    "core:change_plan": "device_builder",
    "core:change_plan_detail": "device_builder",
    "core:change_precheck": "device_builder",
    "core:change_precheck_detail": "device_builder",
    "core:health_fleet": "health",
    "core:health_device": "health",
    "core:health_run": "health",
    "core:nsot": "nsot",
    "core:nsot_devices": "nsot",
    "core:nsot_device_detail": "nsot",
    "core:nsot_device_running_config": "nsot",
    "core:nsot_interfaces": "nsot",
    "core:nsot_ipam": "nsot",
    "core:nsot_vlans": "nsot",
    "core:nsot_routing": "nsot",
    "core:nsot_platforms": "nsot",
    "core:nsot_templates": "nsot",
    "core:nsot_drift": "nsot",
    "core:automation_landing": "automation",
    "core:maintenance_list": "automation",
    "core:maintenance_request": "automation",
    "core:maintenance_detail": "automation",
    "core:maintenance_readiness": "automation",
    "core:maintenance_plan": "automation",
    "core:maintenance_history": "automation",
    "core:automation_section": "automation",
    "core:notifications": "notifications",
    "core:notification_detail": "notifications",
    "core:profile": "profile",
}


def theme_context(request):
    raw_theme = request.COOKIES.get(settings.THEME_COOKIE_NAME)
    active_theme = theme_registry.resolve_theme(raw_theme)

    url_name = None
    if getattr(request, "resolver_match", None):
        url_name = request.resolver_match.view_name
    page_key = PAGE_URL_NAMES.get(url_name, "home")

    active_context = theme_registry.resolve_context(active_theme, page_key)

    return {
        "page_key": page_key,
        "active_theme": active_theme,
        "active_theme_context": active_context,
        "theme_choices": theme_registry.theme_choices(),
        "theme_registry": theme_registry.THEMES,
        "theme_cookie_name": settings.THEME_COOKIE_NAME,
        "theme_fell_back": bool(raw_theme) and raw_theme != active_theme,
        "watermark_url": theme_assets.watermark_for(active_theme, active_context),
        "brand_mark_url": theme_assets.brand_mark_url(),
    }


# Pages that change or plan a change of a device show which devices are under maintenance.
MAINTENANCE_NOTICE_PAGES = ("device_builder", "automation")


def maintenance_context(request):
    """``maintenance_notices``: one entry per device under maintenance, on the Device Builder and Automation pages only."""
    from django.db import DatabaseError
    from django.utils import timezone

    from .services.maintenance_mode import store

    url_name = request.resolver_match.view_name if getattr(request, "resolver_match", None) else None
    if PAGE_URL_NAMES.get(url_name) not in MAINTENANCE_NOTICE_PAGES:
        return {"maintenance_notices": []}
    try:
        return {"maintenance_notices": store.notices(timezone.now())}
    except DatabaseError:                    # a deployment whose database does not have the table yet shows no notice
        return {"maintenance_notices": []}
