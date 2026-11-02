"""Identity field normalization, validation and conflict detection.  Pure apart from the conflict / collision queries.

Unknown stays blank: nothing here ever derives a serial, MAC or host key from a name, an address or another field.
"""

from __future__ import annotations

import re

from django.core.exceptions import ValidationError
from django.db.models import Q

from ... import models
from .. import secret_policy
from ..provisioning import ipam
from .codes import blocker

_MAC_HEX = re.compile(r"^[0-9a-f]{12}$")
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")
_SECRET_ASSIGNMENT = re.compile(r"(?i)\b(pass(word|wd|phrase)?|secret|token|api[_-]?key|private[_-]?key|community|psk)\s*[:=]")
LIVE = ~Q(lifecycle_state__in=tuple(models.DEVICE_LIFECYCLE_TERMINAL))


def normalize_serial(value) -> tuple[str, list[dict]]:
    text = str(value or "").strip()
    if not text:
        return "", []
    if not models.SERIAL_RE.fullmatch(text):
        return "", [blocker("SERIAL_INVALID")]
    return text.upper(), []


def normalize_mac(value) -> tuple[str, list[dict]]:
    """Accepts aa:bb:cc:dd:ee:ff, aa-bb-..., aabb.ccdd.eeff or aabbccddeeff; refuses group, all-zero and broadcast addresses."""
    text = str(value or "").strip().lower()
    if not text:
        return "", []
    hexdigits = re.sub(r"[:.\-]", "", text)
    if not _MAC_HEX.fullmatch(hexdigits) or len(text) not in (12, 14, 17):
        return "", [blocker("MAC_INVALID")]
    if int(hexdigits[:2], 16) & 1 or hexdigits in ("000000000000", "ffffffffffff"):
        return "", [blocker("MAC_INVALID")]
    return ":".join(hexdigits[i:i + 2] for i in range(0, 12, 2)), []


def normalize_host_key(value) -> tuple[str, list[dict]]:
    text = str(value or "").strip()
    if not text:
        return "", []
    if not models.HOST_KEY_RE.fullmatch(text):
        return "", [blocker("HOST_KEY_INVALID")]
    return text, []


def clean_text(value, *, max_length: int) -> tuple[str, list[dict]]:
    """A plain label / reason: no control characters, nothing secret-shaped, bounded."""
    text = str(value or "").strip()
    if _CONTROL.search(text) or _SECRET_ASSIGNMENT.search(text) or secret_policy.redact_text(text) != text or len(text) > max_length:
        return "", [blocker("TEXT_INVALID")]
    return text, []


def identity_conflicts(*, serial: str = "", mac: str = "", host_key: str = "", exclude_pk=None) -> list[dict]:
    """Another LIVE device already expecting or holding this hardware identity (expected and verified values both count)."""
    found = []
    rows = models.ManagedDevice.objects.filter(LIVE)
    if exclude_pk is not None:
        rows = rows.exclude(pk=exclude_pk)
    for kind, value, fields in (("serial", serial, ("expected_serial", "verified_serial")),
                                ("base_mac", mac, ("expected_base_mac", "verified_base_mac")),
                                ("host_key", host_key, ("verified_host_key",))):
        if not value:
            continue
        query = Q()
        for name in fields:
            query |= Q(**{name: value})
        holder = rows.filter(query).first()
        if holder is not None:
            found.append(blocker("IDENTITY_CONFLICT", kind=kind, device=holder.device_id))
    return found


def name_collisions(name: str, *, allow_adopted_inventory: bool = False) -> list[dict]:
    """Every source that already holds ``name``: the tracked inventory (devices, hosts, WebServer), the provisioning registry, a
    live provisioning request, and the lifecycle registry.  ``allow_adopted_inventory`` is the adoption path's own exception."""
    holders = []
    if name in ipam.inventory_names() and not allow_adopted_inventory:
        holders.append("INVENTORY")
    if models.ProvisionedDevice.objects.exclude(state=models.ProvisionedDeviceState.RETIRED).filter(name=name).exists():
        holders.append("PROVISIONING_REGISTRY")
    if models.ProvisioningRun.objects.filter(device_name=name).exclude(status__in=tuple(models.PROVISIONING_TERMINAL)).exists():
        holders.append("PROVISIONING_REQUEST")
    if models.ManagedDevice.objects.filter(LIVE, name=name).exists():
        holders.append("LIFECYCLE_REGISTRY")
    return [blocker("NAME_COLLISION", holders=holders)] if holders else []


def validate_name(value) -> tuple[str, list[dict]]:
    name = str(value or "").strip()
    try:
        models.DEVICE_NAME_VALIDATOR(name)
    except ValidationError:
        return "", [blocker("NAME_INVALID")]
    return name, []
