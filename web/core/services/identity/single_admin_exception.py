"""Explicit, owner-authorized single-administrator exception for one isolated lab exercise.

The normal two-person policy remains the default.  A capability exists only
while a root-owned, non-writable JSON scope document is present, has been
activated once in the append-only ``AuditEvent`` ledger, and is inside its
maximum 30-minute window.  Every use is exact-target, budgeted and audited as
``SINGLE_ADMIN_EXCEPTION``; no event claims separation of duties was met.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone as dt_timezone
from pathlib import Path

from django.contrib.auth import get_user_model
from django.db import transaction
from django.utils import timezone

from ... import models
from . import audit, policy

CONFIG_PATH = Path("/etc/nmas/single-admin-lab-exception.json")
SCHEMA = "nmas.single-admin-lab-exception/1"
MARKER = "OWNER_AUTHORIZED_SINGLE_ADMIN_LAB_EXCEPTION"
MODE = "SINGLE_ADMIN_EXCEPTION"
MAX_LIFETIME_SECONDS = 30 * 60
OBJECT_TYPE = "SingleAdminLabException"
ROUTE = "management_command:nmas_single_admin_lab_exception"


@dataclass(frozen=True)
class Capability:
    exception_id: str
    actor: str
    lab_id: str
    issued_at: datetime
    expires_at: datetime
    max_uses: int
    scope: dict[str, tuple[str, ...]]
    evidence: dict = field(default_factory=dict)
    digest: str = ""


@dataclass
class Result:
    ok: bool
    codes: list[str] = field(default_factory=list)
    capability: Capability | None = None
    event: object | None = None


def _refuse(*codes: str, capability=None) -> Result:
    return Result(False, list(dict.fromkeys(codes)), capability)


def _instant(value) -> datetime | None:
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None
    return parsed.astimezone(dt_timezone.utc) if parsed.tzinfo else None


def _digest(document: dict) -> str:
    return hashlib.sha256(json.dumps(document, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def parse(document: dict) -> Result:
    """Validate an already-loaded scope document.  This performs no I/O or DB write."""
    if not isinstance(document, dict) or document.get("schema") != SCHEMA or document.get("marker") != MARKER \
            or document.get("mode") != MODE:
        return _refuse("EXCEPTION_DOCUMENT_INVALID")
    exception_id = str(document.get("exception_id") or "")
    actor, lab_id = str(document.get("actor") or ""), str(document.get("lab_id") or "")
    issued, expires = _instant(document.get("issued_at")), _instant(document.get("expires_at"))
    try:
        uses = int(document.get("max_uses"))
    except (TypeError, ValueError):
        uses = 0
    raw_scope = document.get("scope")
    if not exception_id.startswith("OWNER-LAB-") or not actor or not lab_id or issued is None or expires is None \
            or expires <= issued or (expires - issued).total_seconds() > MAX_LIFETIME_SECONDS or not 1 <= uses <= 16 \
            or not isinstance(raw_scope, dict) or not raw_scope:
        return _refuse("EXCEPTION_DOCUMENT_INVALID")
    scope = {}
    for action, targets in raw_scope.items():
        if not isinstance(action, str) or not action or not isinstance(targets, list) or not targets \
                or any(not isinstance(target, str) or not target or len(target) > 128 for target in targets):
            return _refuse("EXCEPTION_SCOPE_INVALID")
        scope[action] = tuple(dict.fromkeys(targets))
    canonical = {
        "schema": SCHEMA, "marker": MARKER, "mode": MODE, "exception_id": exception_id,
        "actor": actor, "lab_id": lab_id, "issued_at": issued.isoformat(), "expires_at": expires.isoformat(),
        "max_uses": uses, "scope": {key: list(value) for key, value in sorted(scope.items())},
        "evidence": document.get("evidence") if isinstance(document.get("evidence"), dict) else {},
    }
    return Result(True, capability=Capability(exception_id, actor, lab_id, issued, expires, uses, scope,
                                               canonical["evidence"], _digest(canonical)))


def load(path: Path = CONFIG_PATH) -> Result:
    """Load only the fixed, root-owned capability file.  Missing means disabled."""
    try:
        if path != CONFIG_PATH or path.is_symlink():
            return _refuse("EXCEPTION_PATH_INVALID")
        info = path.stat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            return _refuse("EXCEPTION_FILE_INSECURE")
        document = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return _refuse("EXCEPTION_DISABLED")
    except (OSError, ValueError):
        return _refuse("EXCEPTION_DOCUMENT_INVALID")
    return parse(document)


def _user(capability: Capability):
    user = get_user_model().objects.filter(username=capability.actor, is_active=True).first()
    if user is None or not policy.user_can(user, policy.Action.SECURITY_ADMIN) \
            or not policy.user_can(user, policy.Action.APPROVE):
        return None
    try:
        confirmed = user.nmas_app_mfa.confirmed_at
    except models.AppMfaDevice.DoesNotExist:
        confirmed = None
    return user if confirmed else None


def _events(capability: Capability) -> list:
    return list(models.AuditEvent.objects.filter(object_type=OBJECT_TYPE, object_id=capability.exception_id).order_by("id"))


def _operation(event) -> str:
    return str((event.metadata or {}).get("exception_operation") or "")


def state(capability: Capability, *, now=None) -> Result:
    """Validate account, lab, activation, expiry, revocation and use budget."""
    now = now or timezone.now()
    if _user(capability) is None:
        return _refuse("EXCEPTION_ACTOR_UNAUTHORIZED", capability=capability)
    from ..health import inventory as health_inventory

    if str((health_inventory.load_inventory() or {}).get("lab_name") or "") != capability.lab_id:
        return _refuse("EXCEPTION_LAB_MISMATCH", capability=capability)
    events = _events(capability)
    activations = [e for e in events if _operation(e) == "ACTIVATE" and (e.metadata or {}).get("scope_digest") == capability.digest]
    if len(activations) != 1:
        return _refuse("EXCEPTION_NOT_ACTIVATED", capability=capability)
    if any(_operation(e) in ("REVOKE", "EXPIRE") for e in events):
        return _refuse("EXCEPTION_REVOKED", capability=capability)
    if now < capability.issued_at:
        return _refuse("EXCEPTION_NOT_YET_VALID", capability=capability)
    if now >= capability.expires_at:
        return _refuse("EXCEPTION_EXPIRED", capability=capability)
    uses = [e for e in events if _operation(e) == "USE"]
    if len(uses) >= capability.max_uses:
        return _refuse("EXCEPTION_EXHAUSTED", capability=capability)
    return Result(True, capability=capability)


def authorize(capability: Capability | None, *, action: str, target: str, actor: str, now=None) -> Result:
    if capability is None:
        return _refuse("EXCEPTION_DISABLED")
    current = state(capability, now=now)
    if not current.ok:
        return current
    if actor != capability.actor:
        return _refuse("EXCEPTION_ACTOR_MISMATCH", capability=capability)
    if target not in capability.scope.get(action, ()):  # exact string match; no wildcard or prefix scope
        return _refuse("EXCEPTION_TARGET_OUT_OF_SCOPE", capability=capability)
    for event in _events(capability):
        metadata = event.metadata or {}
        if _operation(event) == "USE" and metadata.get("exception_action") == action and metadata.get("target") == target:
            return _refuse("EXCEPTION_REPLAY", capability=capability)
    return Result(True, capability=capability)


def activate(capability: Capability, *, actor: str, now=None) -> Result:
    now = now or timezone.now()
    if actor != capability.actor or _user(capability) is None:
        return _refuse("EXCEPTION_ACTOR_UNAUTHORIZED", capability=capability)
    if not capability.issued_at <= now < capability.expires_at:
        return _refuse("EXCEPTION_WINDOW_INVALID", capability=capability)
    if _events(capability):
        return _refuse("EXCEPTION_ALREADY_ACTIVATED", capability=capability)
    user = _user(capability)
    event = audit.record(
        models.AuditEventType.WEB_ACTION, f"{MARKER} activated", user=user, actor=actor,
        outcome=audit.OUTCOME_SUCCESS, route=ROUTE, object_type=OBJECT_TYPE, object_id=capability.exception_id,
        metadata={"exception_operation": "ACTIVATE", "marker": MARKER, "approval_mode": MODE,
                  "scope_digest": capability.digest, "expires_at": capability.expires_at.isoformat(),
                  "max_uses": capability.max_uses, "lab_id": capability.lab_id,
                  "separation_of_duties_satisfied": False})
    return Result(True, capability=capability, event=event)


def consume(capability: Capability, *, action: str, target: str, actor: str, original_requester: str,
            evidence: dict | None = None, now=None) -> Result:
    """Atomically consume one exact action/target after the caller locked its approval row."""
    allowed = authorize(capability, action=action, target=target, actor=actor, now=now)
    if not allowed.ok:
        return allowed
    user = _user(capability)
    event = audit.record(
        models.AuditEventType.WEB_ACTION, f"{MARKER} used for {action} {target}", user=user, actor=actor,
        outcome=audit.OUTCOME_SUCCESS, route=ROUTE, object_type=OBJECT_TYPE, object_id=capability.exception_id,
        metadata={"exception_operation": "USE", "marker": MARKER, "approval_mode": MODE,
                  "scope_digest": capability.digest, "exception_action": action, "target": target,
                  "original_requester": original_requester, "separation_of_duties_satisfied": False,
                  "evidence": evidence or {}})
    return Result(True, capability=capability, event=event)


def revoke(capability: Capability, *, actor: str, reason: str, operation="REVOKE") -> Result:
    with transaction.atomic():
        current = state(capability)
        if not current.ok and current.codes not in (["EXCEPTION_EXPIRED"], ["EXCEPTION_EXHAUSTED"]):
            return current
        if actor != capability.actor and actor != "system:single-admin-exception-expiry":
            return _refuse("EXCEPTION_ACTOR_MISMATCH", capability=capability)
        event = audit.record(
            models.AuditEventType.WEB_ACTION, f"{MARKER} {operation.lower()}", actor=actor,
            outcome=audit.OUTCOME_SUCCESS, route=ROUTE, object_type=OBJECT_TYPE, object_id=capability.exception_id,
            metadata={"exception_operation": operation, "marker": MARKER, "approval_mode": MODE,
                      "scope_digest": capability.digest, "reason": str(reason)[:200],
                      "separation_of_duties_satisfied": False})
    return Result(True, capability=capability, event=event)
