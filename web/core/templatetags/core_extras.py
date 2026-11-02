import hashlib

from django import template
from django.contrib.staticfiles import finders
from django.templatetags.static import static as _static_url

from ..services import notification_service

register = template.Library()

_SEVERITY_ICONS = {
    "INFO": "ℹ",  # ℹ
    "SUCCESS": "✓",  # ✓
    "WARNING": "⚠",  # ⚠
    "ERROR": "✖",  # ✖
    "CRITICAL": "‼",  # ‼
}

_SEVERITY_BADGE_CLASSES = {
    "INFO": "info",
    "SUCCESS": "success",
    "WARNING": "warning",
    "ERROR": "danger",
    "CRITICAL": "critical",
}

_SLACK_STATUS_BADGE_CLASSES = {
    "NOT_CONFIGURED": "neutral",
    "PENDING": "neutral",
    "SENT": "success",
    "FAILED": "danger",
    "SKIPPED": "neutral",
}


@register.simple_tag
def versioned_static(path):
    """
    Cache-busting wrapper around {% static %}: appends "?v=<content hash>"
    so a browser fetches the current file after a CSS/JS change instead of
    an ordinary reload silently reusing whatever it cached last, without
    disabling caching altogether. The hash is derived from the file's own
    bytes (not a per-request random value), so the URL only changes when
    the file's content actually changes.
    """
    url = _static_url(path)
    found = finders.find(path)
    if not found:
        return url
    with open(found, "rb") as fh:
        digest = hashlib.md5(fh.read()).hexdigest()[:8]
    return f"{url}?v={digest}"


@register.simple_tag
def recent_notifications():
    """Used by the global header dropdown, which every page includes."""
    return notification_service.get_recent_notifications(limit=notification_service.MAX_DROPDOWN_NOTIFICATIONS)


@register.simple_tag
def unread_notification_count():
    return notification_service.get_unread_count()


@register.filter
def notification_badge_display(count):
    """Caps the header bell's unread count display at "9+" (documented cap)."""
    try:
        count = int(count)
    except (TypeError, ValueError):
        return ""
    if count <= 0:
        return ""
    if count > 9:
        return "9+"
    return str(count)


@register.filter
def severity_icon(value):
    """
    Severity is never conveyed by color alone (a red Mechanicus theme can
    make ERROR/CRITICAL badges look alike) -- every severity also gets a
    distinct icon glyph and label text.
    """
    return _SEVERITY_ICONS.get(value, "•")


@register.filter
def severity_badge_class(value):
    return _SEVERITY_BADGE_CLASSES.get(value, "neutral")


@register.filter
def slack_status_badge_class(value):
    return _SLACK_STATUS_BADGE_CLASSES.get(value, "neutral")


@register.filter
def get_item(mapping, key):
    """Dict lookup by a variable key -- Django's ``.`` template lookup only
    supports literal keys/attributes, not a runtime variable."""
    try:
        return mapping.get(key)
    except AttributeError:
        return None


_HEALTH_BADGE_CLASSES = {
    "PASS": "success", "HEALTHY": "success", "PASS_WITH_WARNINGS": "warning", "WARN": "warning", "DEGRADED": "warning",
    "FAIL": "danger", "UNHEALTHY": "danger", "BLOCKED": "danger", "UNKNOWN": "neutral", "INCOMPLETE": "neutral",
    "NOT_APPLICABLE": "neutral", "FRESH": "success", "STALE": "warning", "EXPIRED": "danger", "SUPPORTED": "success",
    "NOT_IMPLEMENTED": "not-implemented", "UNSUPPORTED": "not-implemented",
}


@register.filter
def health_badge_class(value):
    """Badge colour for a health / precheck / check status.  Unknown values are neutral, never green."""
    return _HEALTH_BADGE_CLASSES.get(str(value), "neutral")


@register.filter
def metric(value, suffix=""):
    """A metric or "not available": a missing value is never rendered as 0."""
    if value is None:
        return "not available"
    return f"{value:.0f}{suffix}" if isinstance(value, (int, float)) else str(value)


_EXECUTION_BADGES = {
    "SUCCEEDED": "success", "UAT_SCOPE_APPLIED": "success", "APPLIED": "success", "COMPENSATED": "success", "ALREADY_SATISFIED": "info",
    "UAT_SCOPE_APPLIED_UNVERIFIED": "warning", "FAILED_ROLLED_BACK": "warning", "POSTCHECK_FAILED_ROLLED_BACK": "warning",
    "IN_PROGRESS": "info", "RUNNING": "info", "NOT_ATTEMPTED": "neutral", "BLOCKED": "neutral", "SUPPORTED": "success",
    "NOT_IMPLEMENTED": "not-implemented", "UNSUPPORTED": "danger", "UNKNOWN": "warning",
}


@register.filter
def execution_badge_class(value):
    """Presentation only: a badge tone for an execution outcome / result status / capability (danger is the default for a failure word)."""
    return _EXECUTION_BADGES.get(str(value), "danger")


_BUNDLE_BADGES = {
    "UAT": "info", "DEPLOYED": "info", "PROBATION": "warning", "GOLDEN": "success", "LEGACY_BASELINE": "warning", "VERIFIED": "success", "UNVERIFIED": "warning", "INTACT": "success", "FAILED": "danger",
    # Phase 20 soak state / result / sample verdicts (presentation only; unknown values stay neutral, never green)
    "RUNNING": "info", "COMPLETED": "neutral", "INVALIDATED": "danger", "CANCELLED": "neutral", "PASS": "success", "PASS_WITH_WARNINGS": "warning",
    "INCOMPLETE": "warning", "FAIL": "danger", "APPROVE": "success", "REJECT": "warning", "FRESH": "success", "STALE": "warning", "EXPIRED": "danger",
}


_PROVISIONING_BADGES = {
    "DONE": "success", "NEXT": "info", "PENDING": "neutral", "BLOCKED": "warning", "FAILED": "danger", "ADVANCED": "success", "RECONCILED": "neutral",
    "PROBATION": "warning", "NSOT_SYNCED": "success", "POSTCHECKED": "success", "ROLLED_BACK": "danger", "CANCELLED": "neutral", "DECOMMISSIONED": "neutral",
    "REACHABLE_BOOTSTRAP": "success", "UNREACHABLE": "warning", "ALREADY_CONFIGURED": "danger", "SUPPORTED": "success", "UNSUPPORTED": "danger",
    "ACTIVE": "success", "ADMITTED": "info", "RETIRED": "neutral",
    "PASSED": "success", "TIMED_OUT": "danger", "INTERRUPTED": "warning", "CREATED": "info", "RUNNING": "info",
}


@register.filter
def provisioning_badge_class(value):
    """Presentation only: a badge tone for a provisioning status / stage state.  In-flight statuses are informational, never green."""
    return _PROVISIONING_BADGES.get(str(value), "info" if str(value) not in ("", "UNKNOWN", "DRAFT") else "neutral")


@register.filter
def bundle_badge_class(value):
    """Presentation only: a badge tone for a bundle kind / verification quality / integrity state.  Unknown values are neutral, never green."""
    return _BUNDLE_BADGES.get(str(value), "neutral")


@register.filter
def soak_duration(value):
    """Presentation only: 604800 -> '7d 0h 0m (168 h)'.  Never used for a decision."""
    try:
        seconds = max(0, int(value))
    except (TypeError, ValueError):
        return "—"
    days, rest = divmod(seconds, 86400)
    hours, rest = divmod(rest, 3600)
    minutes = rest // 60
    text = f"{days}d {hours}h {minutes}m" if days else (f"{hours}h {minutes}m" if hours else f"{minutes}m {rest % 60}s")
    return f"{text} ({seconds // 3600} h)" if seconds >= 3600 else text



_SUPPORT_LABELS = {"PARSER_VALIDATED": "validated", "FIXTURE_ONLY": "preview only", "NOT_IMPLEMENTED": "not implemented"}
_MODE_LABELS = {"COMPLETE_OR_PARTIAL": "Complete or Partial (UAT)", "PARTIAL_UAT_ONLY": "Partial (UAT) only", "NOT_EXECUTABLE": "not executable"}


@register.filter
def support_label(value):
    """Short operator wording for a removal-syntax evidence class (the code itself stays in the title attribute)."""
    return _SUPPORT_LABELS.get(str(value), str(value).replace("_", " ").lower())


@register.filter
def execution_mode_label(value):
    return _MODE_LABELS.get(str(value), str(value))
