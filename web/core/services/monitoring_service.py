"""Read-only Grafana integration for the Django Monitoring area.

Grafana remains the dashboard renderer and InfluxDB remains the telemetry
store. This module owns only stable dashboard metadata, validated
presentation filters, URL construction, and a bounded unauthenticated health
check. It never receives Grafana credentials and never queries InfluxDB.
"""

from __future__ import annotations

import json
import re
from types import MappingProxyType
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlsplit, urlunsplit
from urllib.request import ProxyHandler, Request, build_opener

from django.conf import settings


class UnknownDashboardError(ValueError):
    """Raised when a caller asks for anything outside the canonical set."""


TIME_RANGES = MappingProxyType(
    {
        "15m": {"label": "Last 15 minutes", "grafana_from": "now-15m"},
        "1h": {"label": "Last 1 hour", "grafana_from": "now-1h"},
        "3h": {"label": "Last 3 hours", "grafana_from": "now-3h"},
        "6h": {"label": "Last 6 hours", "grafana_from": "now-6h"},
        "24h": {"label": "Last 24 hours", "grafana_from": "now-24h"},
        "7d": {"label": "Last 7 days", "grafana_from": "now-7d"},
    }
)

PLATFORM_OPTIONS = (("ceos", "cEOS"), ("linux", "Linux / FRR"))
SEVERITY_OPTIONS = (("emerg", "Emergency"), ("alert", "Alert"), ("crit", "Critical"))
EVENT_TYPE_OPTIONS = (
    ("linkUp", "linkUp"),
    ("linkDown", "linkDown"),
    ("ceosTestNotification", "cEOS test notification"),
    ("other", "Other"),
)

_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,128}$")
_INTERFACE_RE = re.compile(r"^[A-Za-z0-9_.:/-]{1,128}$")

# Grafana 11.5 dashboard scenes enter full kiosk mode only for kiosk=true (or
# an empty kiosk value). The _dash flags are supported one-way URL controls
# that remove duplicate dashboard controls while leaving panels interactive.
# These parameters belong exclusively to iframe URLs; full dashboard links
# intentionally retain the normal Grafana application shell.
EMBED_PRESENTATION_QUERY = (
    ("kiosk", "true"),
    ("theme", "dark"),
    ("_dash.hideTimePicker", "true"),
    ("_dash.hideVariables", "true"),
    ("_dash.hideLinks", "true"),
)


def _text_filter(label: str, grafana_variable: str, *, interface: bool = False) -> dict:
    return {
        "label": label,
        "grafana_variable": grafana_variable,
        "kind": "text",
        "validator": "interface" if interface else "identifier",
    }


def _choice_filter(label: str, grafana_variable: str, options: tuple[tuple[str, str], ...]) -> dict:
    return {
        "label": label,
        "grafana_variable": grafana_variable,
        "kind": "choice",
        "options": options,
    }


def _boolean_filter(label: str, grafana_variable: str, default: str) -> dict:
    return {
        "label": label,
        "grafana_variable": grafana_variable,
        "kind": "boolean",
        "default": default,
        "options": (("false", "No"), ("true", "Yes")),
    }


# This is the one Django-side mapping from public GET parameters to Grafana
# variable names. Browser-supplied keys are never copied into a Grafana URL.
CANONICAL_DASHBOARDS = MappingProxyType(
    {
        "resources": {
            "label": "Resources",
            "grafana_uid": "nmas-resources",
            "grafana_slug": "nmas-resources",
            "source_file": "resources.json",
            "grafana_title": "NMAS Resources",
            "route_name": "core:monitoring_resources",
            "description": "Device health, CPU, memory, uptime, telemetry freshness, and resource events.",
            "default_time_range": "6h",
            "filters": {
                "device": _text_filter("Device", "device"),
                "platform": _choice_filter("Platform", "platform", PLATFORM_OPTIONS),
                "severity": _choice_filter("Severity", "severity", SEVERITY_OPTIONS),
                "unhealthy_only": _boolean_filter("Unhealthy only", "unhealthy_only", "false"),
            },
        },
        "link_events": {
            "label": "Link Events",
            "grafana_uid": "nmas-link-events",
            "grafana_slug": "nmas-link-events",
            "source_file": "link-events.json",
            "grafana_title": "NMAS Link Events",
            "route_name": "core:monitoring_link_events",
            "description": "Chronological SNMP notifications and the matching critical syslog feed.",
            "default_time_range": "24h",
            "filters": {
                "device": _text_filter("Device", "device"),
                "event_type": _choice_filter("Event type", "event_type", EVENT_TYPE_OPTIONS),
                "severity": _choice_filter("Severity", "severity", SEVERITY_OPTIONS),
            },
        },
        "link_state_traffic": {
            "label": "Link State & Traffic",
            "grafana_uid": "nmas-link-state-traffic",
            "grafana_slug": "nmas-link-state-traffic",
            "source_file": "link-state-traffic.json",
            "grafana_title": "NMAS Link State & Traffic",
            "route_name": "core:monitoring_link_state_traffic",
            "description": "Interface state, traffic rates, errors, discards, counters, and NETCONF snapshots.",
            "default_time_range": "3h",
            "filters": {
                "device": _text_filter("Device", "device"),
                "platform": _choice_filter("Platform", "platform", PLATFORM_OPTIONS),
                "interface": _text_filter("Interface", "interface", interface=True),
                "hide_zero_traffic": _boolean_filter("Hide zero traffic", "hide_zero_traffic", "false"),
                "hide_down": _boolean_filter("Hide down interfaces", "hide_down", "false"),
                "active_only": _boolean_filter("Active interfaces only", "active_only", "false"),
                "include_mgmt": _boolean_filter("Include management", "include_mgmt", "true"),
                "include_loopback": _boolean_filter("Include loopbacks", "include_loopback", "true"),
            },
        },
    }
)


def _dashboard(page_key: str) -> dict:
    try:
        return CANONICAL_DASHBOARDS[page_key]
    except KeyError as exc:
        raise UnknownDashboardError(f"Unknown canonical dashboard: {page_key}") from exc


def get_dashboard_metadata(page_key: str) -> dict:
    """Return safe canonical metadata; unknown/legacy keys are rejected."""
    return dict(_dashboard(page_key))


def _validated_base_url() -> str:
    value = settings.GRAFANA_BASE_URL.strip().rstrip("/")
    parsed = urlsplit(value)
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("GRAFANA_BASE_URL must be a credential-free HTTP(S) base URL")
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path.rstrip("/"), "", ""))


def _validate_filter_value(spec: dict, raw_value: object) -> str | None:
    value = str(raw_value).strip()
    if not value or value == "All":
        return None
    if spec["kind"] in {"choice", "boolean"}:
        allowed = {option[0] for option in spec["options"]}
        return value if value in allowed else None
    pattern = _INTERFACE_RE if spec.get("validator") == "interface" else _IDENTIFIER_RE
    return value if pattern.fullmatch(value) else None


def validate_filters(page_key: str, params) -> dict:
    """Validate only the explicit filter contract for one canonical page."""
    dashboard = _dashboard(page_key)
    selected: dict[str, str] = {}
    invalid: list[str] = []
    for name, spec in dashboard["filters"].items():
        raw = params.get(name)
        if raw in (None, "", "All"):
            continue
        value = _validate_filter_value(spec, raw)
        if value is None:
            invalid.append(name)
        else:
            selected[name] = value

    raw_time = str(params.get("time_range", "")).strip()
    if raw_time and raw_time not in TIME_RANGES:
        invalid.append("time_range")
        time_range = dashboard["default_time_range"]
    else:
        time_range = raw_time or dashboard["default_time_range"]
    return {"filters": selected, "time_range": time_range, "invalid": tuple(invalid)}


def build_dashboard_url(
    page_key: str,
    filters: dict[str, object] | None = None,
    *,
    time_range: str | None = None,
    embed: bool = False,
) -> str:
    """Build a canonical Grafana URL from an allowlisted dashboard/variables."""
    dashboard = _dashboard(page_key)
    raw = dict(filters or {})
    if time_range is not None:
        raw["time_range"] = time_range
    validated = validate_filters(page_key, raw)
    selected_time = validated["time_range"]
    query: list[tuple[str, str]] = [
        ("from", TIME_RANGES[selected_time]["grafana_from"]),
        ("to", "now"),
    ]
    for name, spec in dashboard["filters"].items():
        value = validated["filters"].get(name)
        if value is None:
            continue
        # Omit boolean defaults so reset/default state stays canonical.
        if spec["kind"] == "boolean" and value == spec["default"]:
            continue
        query.append((f"var-{spec['grafana_variable']}", value))
    if embed:
        query.extend(EMBED_PRESENTATION_QUERY)

    path = f"/d/{dashboard['grafana_uid']}/{dashboard['grafana_slug']}"
    return f"{_validated_base_url()}{path}?{urlencode(query)}"


def get_grafana_health() -> dict:
    """Perform one bounded, credential-free Grafana health request."""
    unavailable = {
        "status": "unavailable",
        "message": "Grafana monitoring service temporarily unavailable.",
    }
    try:
        url = f"{_validated_base_url()}/api/health"
        request = Request(url, headers={"Accept": "application/json"}, method="GET")
        opener = build_opener(ProxyHandler({}))
        with opener.open(request, timeout=settings.GRAFANA_HEALTH_TIMEOUT_SECONDS) as response:
            payload = response.read(65537)
        if len(payload) > 65536:
            return unavailable
        data = json.loads(payload.decode("utf-8"))
        if data.get("database") != "ok":
            return unavailable
    except (HTTPError, URLError, TimeoutError, OSError, ValueError, UnicodeError, json.JSONDecodeError):
        return unavailable
    return {
        "status": "available",
        "message": "Grafana monitoring service is available.",
    }


def _header_values(headers, name: str) -> tuple[str, ...]:
    """Return all values for one HTTP header without assuming a header type."""
    get_all = getattr(headers, "get_all", None)
    if callable(get_all):
        values = get_all(name)
        if values:
            return tuple(str(value) for value in values)
    value = headers.get(name)
    return (str(value),) if value else ()


def _frame_headers_allow_embedding(headers, *, embedding_origin: str) -> bool:
    """Conservatively accept only response headers compatible with framing."""
    if any(value.strip() for value in _header_values(headers, "X-Frame-Options")):
        # Grafana and Django use different ports and therefore different
        # origins. DENY and SAMEORIGIN both reject this deployment; unknown or
        # obsolete XFO values are treated conservatively as prohibitive too.
        return False

    grafana_origin = _validated_base_url()
    for policy in _header_values(headers, "Content-Security-Policy"):
        for raw_directive in policy.split(";"):
            parts = raw_directive.strip().split()
            if not parts or parts[0].lower() != "frame-ancestors":
                continue
            sources = {source.rstrip("/") for source in parts[1:]}
            if "*" in sources or embedding_origin.rstrip("/") in sources:
                continue
            if "'self'" in sources and embedding_origin.rstrip("/") == grafana_origin:
                continue
            return False
    return True


def grafana_allows_embedding(page_key: str, *, embedding_origin: str) -> bool:
    """Probe the live canonical dashboard for browser framing restrictions.

    This is deliberately credential-free. An authenticated Grafana deployment
    redirects the request to its login page; the final response still carries
    the effective global framing policy without exposing a browser session.
    """
    if not settings.GRAFANA_EMBED_ENABLED:
        return False
    try:
        url = build_dashboard_url(page_key, embed=True)
        request = Request(url, headers={"Accept": "text/html"}, method="GET")
        opener = build_opener(ProxyHandler({}))
        with opener.open(request, timeout=settings.GRAFANA_HEALTH_TIMEOUT_SECONDS) as response:
            return _frame_headers_allow_embedding(
                response.headers,
                embedding_origin=embedding_origin,
            )
    except (HTTPError, URLError, TimeoutError, OSError, ValueError):
        return False


def get_monitoring_summary() -> dict:
    """Compatibility wrapper retained for callers of the Phase-3 service."""
    return get_grafana_health()


def _filter_controls(dashboard: dict, selected: dict[str, str]) -> list[dict]:
    controls = []
    for name, spec in dashboard["filters"].items():
        control = {key: value for key, value in spec.items() if key != "validator"}
        control.update({"name": name, "value": selected.get(name, spec.get("default", ""))})
        controls.append(control)
    return controls


def get_monitoring_landing_context() -> dict:
    health = get_grafana_health()
    pages = []
    for key, dashboard in CANONICAL_DASHBOARDS.items():
        pages.append(
            {
                "key": key,
                "label": dashboard["label"],
                "grafana_uid": dashboard["grafana_uid"],
                "grafana_title": dashboard["grafana_title"],
                "route_name": dashboard["route_name"],
                "description": dashboard["description"],
                "status": health["status"],
            }
        )
    return {"page_title": "Monitoring", "summary": health, "pages": pages}


def get_monitoring_page_context(
    page_key: str,
    params,
    *,
    reset_url: str,
    embedding_origin: str,
) -> dict:
    dashboard = _dashboard(page_key)
    state = validate_filters(page_key, params)
    health = get_grafana_health()
    full_url = build_dashboard_url(
        page_key,
        state["filters"],
        time_range=state["time_range"],
    )
    embed_enabled = health["status"] == "available" and grafana_allows_embedding(
        page_key,
        embedding_origin=embedding_origin,
    )
    return {
        "page_title": f"Monitoring · {dashboard['label']}",
        "dashboard": get_dashboard_metadata(page_key),
        "summary": health,
        "filters": _filter_controls(dashboard, state["filters"]),
        "selected_filters": state["filters"],
        "invalid_filters": state["invalid"],
        "time_ranges": [
            {"value": value, "label": details["label"]}
            for value, details in TIME_RANGES.items()
        ],
        "selected_time_range": state["time_range"],
        "full_grafana_url": full_url,
        "embed_enabled": embed_enabled,
        "embed_url": build_dashboard_url(
            page_key,
            state["filters"],
            time_range=state["time_range"],
            embed=True,
        )
        if embed_enabled
        else None,
        "reset_url": reset_url,
    }
