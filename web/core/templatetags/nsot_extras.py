"""Template helpers for the NSOT provenance/drift-status presentation."""

from __future__ import annotations

from django import template

register = template.Library()

_BADGE_CLASSES = {
    "NETBOX": "badge--info",
    "GIT": "badge--neutral",
    "LIVE": "badge--warning",
    "TOPOLOGY": "badge--success",
    "INVENTORY": "badge--neutral",
    "MONITORING": "badge--info",
    "AUTOMATION": "badge--neutral",
    "IN_SYNC": "badge--success",
    "DRIFT": "badge--danger",
    "UNMANAGED": "badge--neutral",
    "UNAVAILABLE": "badge--warning",
    "NOT_COMPARABLE": "badge--neutral",
    "AVAILABLE": "badge--success",
    "NOT_FOUND": "badge--danger",
    "NOT_SUPPORTED": "badge--neutral",
    "CURRENT": "badge--success",
    "STALE": "badge--warning",
}


@register.filter
def badge_class(value):
    return _BADGE_CLASSES.get(str(value).upper(), "badge--neutral")


@register.filter
def get_item(mapping, key):
    if mapping is None:
        return None
    try:
        return mapping.get(key)
    except AttributeError:
        return None
