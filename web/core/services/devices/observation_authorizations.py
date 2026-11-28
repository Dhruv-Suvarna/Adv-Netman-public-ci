"""Enforceable authorizations for read-only device observations (replaces the free-form ``--authorization-ref`` label).

An ``ObservationAuthorization`` grants, for a bounded validity window, exactly:

* a **device scope** -- named devices that the authoritative resolver places in a WRITABLE scope (R5 and every read-only /
  excluded / unknown name are refused at grant time *and* re-checked at use time);
* a **command scope** -- command ids from ``models.OBSERVATION_COMMAND_IDS`` (today only ``nos-version``: the platform's own
  ``observations.SPECS`` version command; nothing else can be authorized because nothing else can be sent);
* a **use budget** -- ``max_observations`` reserved uses in total (a refused attempt also consumes one);
* an **expiry** -- at most ``MAX_TTL_SECONDS`` after ``not_before``; checked before any session opens and again immediately
  before the observation is ingested (``still_valid``).

Separation of duties uses the existing NMAS RBAC (``identity.policy``): the approver is an active NMAS account holding APPROVE and
is not the requester; the operator who runs the observation is an active NMAS account holding EXECUTE and is neither the approver
nor (by construction of ``lifecycle.verify_identity``) able to verify the identity it records.  ``scope_digest`` binds the approved
scope; any row whose stored scope no longer reproduces its digest is refused (``AUTHORIZATION_TAMPERED``).

``reference(auth)`` (``OBSAUTH-000123#sha256=<scope digest>``) is what the session carries and what the evidence file records; the
evidence file's digest is part of the signed observation envelope, so every accepted observation is bound to the exact scope it ran
under.  Nothing here contacts a device, reads a credential or changes identity, lifecycle or admission state.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone as dt_timezone

from django.contrib.auth import get_user_model
from django.db import transaction
from django.utils import timezone

from ... import models
from ..identity import policy
from . import identity, observations, resolver

MAX_TTL_SECONDS = 24 * 3600
MIN_TTL_SECONDS = 60
MAX_DEVICES = 16
MAX_USES_PER_DEVICE = 4
COMMAND_FOR = {"nos-version": {platform: spec.command for platform, spec in observations.SPECS.items()}}
_TICKET = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{2,63}$")
_REF = re.compile(r"^OBSAUTH-(\d{6,})(?:#sha256=([0-9a-f]{64}))?$")
_DEVICE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")

REFUSALS = {
    "APPROVER_NOT_AUTHORIZED": "The approver is not an active NMAS account holding the APPROVE permission.",
    "APPROVER_NOT_INDEPENDENT": "The approver may not approve their own request.",
    "REQUESTER_MISSING": "The requester must be named.",
    "SCOPE_INVALID": "The device or command scope is empty, malformed or too large.",
    "DEVICE_UNKNOWN": "A device in the scope is not in the authoritative inventory.",
    "DEVICE_EXCLUDED": "A device in the scope is read-only, excluded or not yet manageable (e.g. R5).",
    "COMMAND_UNKNOWN": "A command in the scope is not an observation command NMAS can send.",
    "WINDOW_INVALID": "The validity window is outside the permitted bounds.",
    "TICKET_INVALID": "The change/ticket reference is missing or malformed.",
    "REASON_INVALID": "The reason text is not acceptable.",
    "AUTHORIZATION_UNKNOWN": "No such observation authorization.",
    "AUTHORIZATION_REF_MISMATCH": "The reference's scope digest is not the authorization's.",
    "AUTHORIZATION_TAMPERED": "The stored scope no longer matches its approved digest.",
    "AUTHORIZATION_REVOKED": "The authorization was revoked.",
    "AUTHORIZATION_NOT_YET_VALID": "The authorization's window has not started.",
    "AUTHORIZATION_EXPIRED": "The authorization has expired.",
    "AUTHORIZATION_EXHAUSTED": "The authorization's observation budget is used up.",
    "DEVICE_NOT_AUTHORIZED": "The device is outside the authorization's device scope.",
    "COMMAND_NOT_AUTHORIZED": "The command is outside the authorization's command scope.",
    "OPERATOR_NOT_AUTHORIZED": "The operator is not an active NMAS account holding the EXECUTE permission.",
    "OPERATOR_NOT_INDEPENDENT": "The approver of an authorization may not run observations under it.",
    "ALREADY_REVOKED": "The authorization is already revoked.",
    "REVOKER_NOT_AUTHORIZED": "Only an active NMAS account holding APPROVE may revoke an authorization.",
}


@dataclass
class Result:
    ok: bool
    codes: list = field(default_factory=list)
    authorization: object | None = None
    use: object | None = None

    @property
    def messages(self) -> list[str]:
        return [REFUSALS.get(code, code) for code in self.codes]


def _refuse(*codes_) -> Result:
    return Result(False, list(codes_))


# --- helpers ---------------------------------------------------------------------------------------------------------------------
def _account(username: str, action) -> object | None:
    user = get_user_model().objects.filter(username=str(username or "").strip()).first()
    return user if policy.user_can(user, action) else None


def _iso(value: datetime) -> str:
    return value.astimezone(dt_timezone.utc).isoformat()


def scope_digest(*, devices, commands, not_before, expires_at, max_observations, approved_by, requested_by, ticket) -> str:
    body = {"devices": sorted(devices), "commands": sorted(commands), "not_before": _iso(not_before), "expires_at": _iso(expires_at),
            "max_observations": int(max_observations), "approved_by": str(approved_by), "requested_by": str(requested_by),
            "ticket": str(ticket)}
    return hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _stored_digest(auth) -> str:
    return scope_digest(devices=auth.devices, commands=auth.commands, not_before=auth.not_before, expires_at=auth.expires_at,
                        max_observations=auth.max_observations, approved_by=auth.approved_by, requested_by=auth.requested_by,
                        ticket=auth.ticket)


def reference(auth) -> str:
    """The value a session carries and the evidence file records: id plus the approved-scope digest."""
    return f"{auth.auth_id}#sha256={auth.scope_digest}"


def command_id(platform: str, command: str) -> str:
    """The command-scope id of ``command`` on ``platform`` ("" when the command is not an authorizable observation command)."""
    for cid, by_platform in COMMAND_FOR.items():
        if by_platform.get(platform) == command:
            return cid
    return ""


def _scope_problem(name: str, document: dict | None) -> str:
    if not _DEVICE.fullmatch(name):
        return "SCOPE_INVALID"
    target = resolver.resolve(name, document=document)
    if target is None:
        return "DEVICE_UNKNOWN"
    if target.scope not in resolver.WRITABLE_SCOPES:
        return "DEVICE_EXCLUDED"
    return ""


# --- grant / revoke ----------------------------------------------------------------------------------------------------------------
def grant(*, devices, commands, ttl_seconds: int, approver: str, requested_by: str, ticket: str, reason: str = "",
          not_before: datetime | None = None, max_observations: int | None = None, now: datetime | None = None,
          document: dict | None = None, exception=None) -> Result:
    now = now or timezone.now()
    names = sorted({str(d).strip() for d in (devices or []) if str(d).strip()})
    cmds = sorted({str(c).strip() for c in (commands or []) if str(c).strip()})
    approver, requested_by = str(approver or "").strip(), str(requested_by or "").strip()
    codes_: list[str] = []
    if _account(approver, policy.Action.APPROVE) is None:
        codes_.append("APPROVER_NOT_AUTHORIZED")
    exceptional = None
    exception_target = f"{ticket}|{','.join(names)}|{','.join(cmds)}"
    if not requested_by:
        codes_.append("REQUESTER_MISSING")
    elif requested_by.lower() == approver.lower():
        from ..identity import single_admin_exception

        exceptional = single_admin_exception.authorize(
            exception, action="OBSERVATION_AUTHORIZATION_GRANT", target=exception_target, actor=approver)
        if not exceptional.ok:
            codes_.append("APPROVER_NOT_INDEPENDENT")
    if not names or len(names) > MAX_DEVICES or not cmds:
        codes_.append("SCOPE_INVALID")
    for name in names:
        problem = _scope_problem(name, document)
        if problem and problem not in codes_:
            codes_.append(problem)
    if any(c not in models.OBSERVATION_COMMAND_IDS for c in cmds):
        codes_.append("COMMAND_UNKNOWN")
    start = not_before or now
    try:
        ttl = int(ttl_seconds)
    except (TypeError, ValueError):
        ttl = 0
    if not MIN_TTL_SECONDS <= ttl <= MAX_TTL_SECONDS or start < now - timedelta(seconds=60) or start > now + timedelta(days=7):
        codes_.append("WINDOW_INVALID")
    budget = len(names) if max_observations is None else max_observations
    try:
        budget = int(budget)
    except (TypeError, ValueError):
        budget = 0
    if names and not 1 <= budget <= MAX_USES_PER_DEVICE * len(names):
        codes_.append("SCOPE_INVALID")
    if not _TICKET.fullmatch(str(ticket or "")):
        codes_.append("TICKET_INVALID")
    text, problems = identity.clean_text(reason, max_length=200)
    if problems:
        codes_.append("REASON_INVALID")
    if codes_:
        return _refuse(*dict.fromkeys(codes_))
    expires = start + timedelta(seconds=ttl)
    digest = scope_digest(devices=names, commands=cmds, not_before=start, expires_at=expires, max_observations=budget,
                          approved_by=approver, requested_by=requested_by, ticket=ticket)
    with transaction.atomic():
        auth = models.ObservationAuthorization.objects.create(
            devices=names, commands=cmds, ticket=str(ticket), reason=text, requested_by=requested_by[:150], approved_by=approver[:150],
            not_before=start, expires_at=expires, max_observations=budget, scope_digest=digest)
        if exceptional is not None:
            used = single_admin_exception.consume(
                exception, action="OBSERVATION_AUTHORIZATION_GRANT", target=exception_target, actor=approver,
                original_requester=requested_by,
                evidence={"authorization": auth.auth_id, "devices": names, "commands": cmds,
                          "separation_of_duties_satisfied": False})
            if not used.ok:
                transaction.set_rollback(True)
                return _refuse("APPROVER_NOT_INDEPENDENT")
    return Result(True, [], auth)


def revoke(auth, *, actor: str, reason: str = "", now: datetime | None = None) -> Result:
    if _account(actor, policy.Action.APPROVE) is None:
        return _refuse("REVOKER_NOT_AUTHORIZED")
    text, problems = identity.clean_text(reason, max_length=200)
    if problems:
        return _refuse("REASON_INVALID")
    with transaction.atomic():
        locked = models.ObservationAuthorization.objects.select_for_update().get(pk=auth.pk)
        if locked.revoked_at is not None:
            return _refuse("ALREADY_REVOKED")
        locked.revoked_at, locked.revoked_by, locked.revoke_reason = now or timezone.now(), str(actor)[:150], text
        locked.save()
    return Result(True, [], locked)


# --- use ---------------------------------------------------------------------------------------------------------------------------
def lookup(ref: str, *, require_digest: bool = False) -> Result:
    """Resolve an authorization reference.

    Administrative show/revoke operations may use the human-friendly bare id.  An
    observation execution must set ``require_digest`` so the caller presents the
    exact approved-scope reference emitted by :func:`reference`.
    """
    match = _REF.fullmatch(str(ref or "").strip())
    if not match:
        return _refuse("AUTHORIZATION_UNKNOWN")
    auth = models.ObservationAuthorization.objects.filter(pk=int(match.group(1))).first()
    if auth is None:
        return _refuse("AUTHORIZATION_UNKNOWN")
    if require_digest and not match.group(2):
        return _refuse("AUTHORIZATION_REF_MISMATCH")
    if match.group(2) and match.group(2) != auth.scope_digest:
        return _refuse("AUTHORIZATION_REF_MISMATCH")
    return Result(True, [], auth)


def still_valid(auth, *, now: datetime | None = None) -> str:
    """"" while the authorization is intact, unrevoked and inside its window; otherwise the refusal code.  Database read only."""
    now = now or timezone.now()
    fresh = models.ObservationAuthorization.objects.filter(pk=auth.pk).first()
    if fresh is None:
        return "AUTHORIZATION_UNKNOWN"
    if _stored_digest(fresh) != fresh.scope_digest or fresh.scope_digest != auth.scope_digest:
        return "AUTHORIZATION_TAMPERED"
    if fresh.revoked_at is not None:
        return "AUTHORIZATION_REVOKED"
    if now < fresh.not_before:
        return "AUTHORIZATION_NOT_YET_VALID"
    if now >= fresh.expires_at:
        return "AUTHORIZATION_EXPIRED"
    return ""


def admit(ref: str, *, device: str, platform: str, command: str, operator: str, now: datetime | None = None,
          document: dict | None = None) -> Result:
    """Check every scope rule for one observation and atomically reserve one use.  Called before any session is opened."""
    now = now or timezone.now()
    found = lookup(ref, require_digest=True)
    if not found.ok:
        return found
    auth = found.authorization
    operator = str(operator or "").strip()
    if _account(operator, policy.Action.EXECUTE) is None:
        return _refuse("OPERATOR_NOT_AUTHORIZED")
    if operator.lower() == auth.approved_by.lower():
        from ..identity import single_admin_exception

        target = f"{auth.ticket}|{','.join(sorted(auth.devices))}|{','.join(sorted(auth.commands))}"
        event = next((item for item in models.AuditEvent.objects.filter(
            object_type=single_admin_exception.OBJECT_TYPE,
            metadata__exception_operation="USE",
            metadata__exception_action="OBSERVATION_AUTHORIZATION_GRANT",
            metadata__target=target,
        ) if (item.metadata or {}).get("marker") == single_admin_exception.MARKER
            and (item.metadata or {}).get("approval_mode") == single_admin_exception.MODE
            and (item.metadata or {}).get("original_requester") == auth.requested_by), None)
        if event is None:
            return _refuse("OPERATOR_NOT_INDEPENDENT")
    problem = still_valid(auth, now=now)
    if problem:
        return _refuse(problem)
    if str(device) not in auth.devices:
        return _refuse("DEVICE_NOT_AUTHORIZED")
    problem = _scope_problem(str(device), document)
    if problem:
        return _refuse(problem)
    cid = command_id(platform, command)
    if not cid or cid not in auth.commands:
        return _refuse("COMMAND_NOT_AUTHORIZED")
    with transaction.atomic():
        locked = models.ObservationAuthorization.objects.select_for_update().get(pk=auth.pk)
        used = models.ObservationAuthorizationUse.objects.filter(authorization=locked).count()   # every reservation consumes budget
        if used >= locked.max_observations:
            return _refuse("AUTHORIZATION_EXHAUSTED")
        use = models.ObservationAuthorizationUse.objects.create(authorization=locked, device=str(device), command=cid,
                                                                operator=operator[:150])
    return Result(True, [], locked, use)


def finish(use, *, ok: bool, codes=(), nonce: str = "", evidence_ref: str = "", record=None, now: datetime | None = None):
    """Close a reserved use exactly once (ACCEPTED with the observation it produced, or REFUSED with its codes).  A refused use
    still counts against the budget: a retry needs budget the approver explicitly granted."""
    outcome = [str(c)[:64] for c in (codes or ())][:16]
    use.state = models.ObservationUseState.ACCEPTED if ok else models.ObservationUseState.REFUSED
    use.outcome_codes, use.nonce, use.evidence_ref = outcome, str(nonce or "")[:64], str(evidence_ref or "")[:200]
    use.version_observation = record if ok else None
    use.finished_at = now or timezone.now()
    use.save()
    return use
