"""Bootstrap authorization: the operator-approved context a future bootstrap request must match.

What an authorization IS: a bounded, time-limited, use-limited permission for ONE registered new device, bound to its
expected identity, platform and ONE approved expected attachment, to receive bootstrap-scope service (DHCP discovery,
bootstrap fetch, initial management).  What it is NOT: production admission (``decide`` reports ``production_admission``
False, always), a credential (it holds none -- no password, key, token or shared secret is accepted or stored), or a delivery
mechanism (Phase 3 delivers; this phase only decides).

Lifecycle: PENDING_APPROVAL -> APPROVED -> CONSUMED, and PENDING_APPROVAL / APPROVED -> REVOKED | EXPIRED.  The approver
must differ from the requester and must confirm the exact ``binding_digest`` they reviewed.  If the bound context changes
after the request (identity, attachment, platform), the decision is STALE until a new authorization is requested.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from django.db import IntegrityError, transaction
from django.db.models import F
from django.utils import timezone

from ... import models
from . import attachments as attachment_service
from . import events, identity
from .codes import blocker, codes

State = models.BootstrapAuthorizationState
S = models.DeviceLifecycleState
Outcome = models.DeviceLifecycleEventOutcome
SCOPE_TOKENS = ("DHCP_DISCOVERY", "BOOTSTRAP_FETCH", "INITIAL_MANAGEMENT")
MIN_WINDOW = timedelta(minutes=5)
MAX_WINDOW = timedelta(days=7)
MAX_START_DELAY = timedelta(days=30)
MAX_USES = 10
ELIGIBLE_STATES = (S.REGISTERED, S.DISCOVERED)
REQUEST_KEYS = ("scope", "serial", "base_mac", "upstream_device", "upstream_interface", "local_interface", "attachment_source")


class Decision:
    """The decision vocabulary.  Only AUTHORIZED permits bootstrap-scope service; nothing here admits a device to production."""

    AUTHORIZED = "AUTHORIZED"
    PENDING_APPROVAL = "PENDING_APPROVAL"
    PENDING_EVIDENCE = "PENDING_EVIDENCE"
    NOT_YET_VALID = "NOT_YET_VALID"
    EXPIRED = "EXPIRED"
    REVOKED = "REVOKED"
    EXHAUSTED = "EXHAUSTED"
    STALE = "STALE"
    IDENTITY_MISMATCH = "IDENTITY_MISMATCH"
    ATTACHMENT_MISMATCH = "ATTACHMENT_MISMATCH"
    OUT_OF_SCOPE = "OUT_OF_SCOPE"
    ALREADY_IN_SERVICE = "ALREADY_IN_SERVICE"
    CONFLICTING_REQUEST = "CONFLICTING_REQUEST"
    NOT_FOUND = "NOT_FOUND"


@dataclass(frozen=True)
class DecisionResult:
    decision: str
    auth_id: str = ""
    device_id: str = ""
    blockers: tuple = ()
    evaluated_at: str = ""
    production_admission: bool = False      # never True: bootstrap authorization is not production admission

    @property
    def authorized(self) -> bool:
        return self.decision == Decision.AUTHORIZED

    def as_dict(self) -> dict:
        return {"decision": self.decision, "authorized": self.authorized, "auth_id": self.auth_id, "device_id": self.device_id,
                "codes": codes(self.blockers), "blockers": list(self.blockers), "evaluated_at": self.evaluated_at,
                "production_admission": False}


@dataclass
class AuthorizationResult:
    authorization: object | None
    ok: bool
    action: str
    blockers: list = field(default_factory=list)
    event: object | None = None

    @property
    def codes(self) -> list[str]:
        return codes(self.blockers)


class _Refused(Exception):
    def __init__(self, blockers):
        super().__init__("refused")
        self.blockers = blockers


# --- binding --------------------------------------------------------------------------------------------------------------------
def binding(device, attachment, *, platform: str, scope, valid_from: datetime, valid_until: datetime, max_uses: int) -> dict:
    """The exact context an authorization is bound to (no secret: identity values are hardware identifiers)."""
    return {
        "device": device.device_id, "name": device.name, "origin": device.origin, "platform": platform,
        "expected_serial": device.expected_serial, "expected_base_mac": device.expected_base_mac,
        "attachment": {"id": attachment.pk, "upstream_device": attachment.upstream_device,
                       "upstream_interface": attachment.upstream_interface, "local_interface": attachment.local_interface,
                       "purpose": attachment.purpose, "connectivity": attachment.connectivity, "vlan": attachment.vlan,
                       "approval_state": attachment.approval_state},
        "scope": sorted(scope), "valid_from": valid_from.isoformat(), "valid_until": valid_until.isoformat(), "max_uses": int(max_uses),
    }


def binding_digest(payload: dict) -> str:
    return hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def current_digest(auth) -> str:
    """Recompute ``auth``'s binding from the CURRENT device and attachment rows (differs from ``binding_digest`` when stale)."""
    device = models.ManagedDevice.objects.get(pk=auth.device_id)
    attachment = models.DeviceAttachment.objects.get(pk=auth.attachment_id)
    return binding_digest(binding(device, attachment, platform=device.platform, scope=auth.scope, valid_from=auth.valid_from,
                                  valid_until=auth.valid_until, max_uses=auth.max_uses))


def get_authorization(auth_id: str):
    text = str(auth_id or "")
    if not text.startswith("BAUTH-") or not text[6:].isdigit():
        return None
    return models.BootstrapAuthorization.objects.select_related("device", "attachment").filter(pk=int(text[6:])).first()


# --- validation -----------------------------------------------------------------------------------------------------------------
def scope_problems(scope) -> list[dict]:
    """A non-empty set of known bootstrap scope tokens ([] when valid)."""
    if not isinstance(scope, (list, tuple)) or not scope or len(set(scope)) != len(scope) or any(t not in SCOPE_TOKENS for t in scope):
        return [blocker("AUTHORIZATION_SCOPE_INVALID", allowed=list(SCOPE_TOKENS))]
    return []


def window_problems(valid_from, valid_until, *, now=None) -> list[dict]:
    """Aware datetimes, 5 minutes to 7 days long, starting within 30 days, not already over ([] when valid)."""
    now = now or timezone.now()
    if not isinstance(valid_from, datetime) or not isinstance(valid_until, datetime) \
            or timezone.is_naive(valid_from) or timezone.is_naive(valid_until):
        return [blocker("AUTHORIZATION_WINDOW_INVALID", reason="aware start and end times are required")]
    length = valid_until - valid_from
    if length < MIN_WINDOW or length > MAX_WINDOW:
        return [blocker("AUTHORIZATION_WINDOW_INVALID", reason="the window must last 5 minutes to 7 days")]
    if valid_until <= now or valid_from > now + MAX_START_DELAY:
        return [blocker("AUTHORIZATION_WINDOW_INVALID", reason="the window is over or starts too far ahead")]
    return []


def uses_problems(max_uses) -> list[dict]:
    if isinstance(max_uses, bool) or not str(max_uses).isdigit() or not 1 <= int(max_uses) <= MAX_USES:
        return [blocker("AUTHORIZATION_USES_INVALID", maximum=MAX_USES)]
    return []


def device_problems(device) -> list[dict]:
    """Why ``device`` cannot hold a bootstrap authorization ([] when it can)."""
    if device.is_terminal:
        return [blocker("DEVICE_TERMINAL", state=device.lifecycle_state)]
    if device.origin != models.DeviceOrigin.REGISTERED_NEW or device.lifecycle_state == S.IN_SERVICE \
            or device.admission_state != models.ProductionAdmissionState.NOT_ADMITTED:
        return [blocker("ALREADY_IN_SERVICE", origin=device.origin, state=device.lifecycle_state)]
    if device.lifecycle_state not in ELIGIBLE_STATES:
        return [blocker("AUTHORIZATION_STATE_INVALID", state=device.lifecycle_state)]
    if device.identity_state == models.IdentityVerificationState.MISMATCH:
        return [blocker("IDENTITY_MISMATCH")]
    if not (device.expected_serial or device.expected_base_mac):
        return [blocker("IDENTITY_EVIDENCE_INSUFFICIENT", reason="an expected serial or base MAC is required")]
    return []


def attachment_problems(device, attachment) -> list[dict]:
    """Why ``attachment`` cannot be the bound bootstrap attachment ([] when it can).  VLAN 200 never carries bootstrap DHCP."""
    if attachment is None or attachment.device_id != device.pk:
        return [blocker("ATTACHMENT_NOT_FOUND")]
    if attachment.approval_state != models.AttachmentApproval.APPROVED or attachment.vlan == attachment_service.MANAGEMENT_VLAN:
        return [blocker("AUTHORIZATION_ATTACHMENT_INELIGIBLE", approval_state=attachment.approval_state, vlan=attachment.vlan)]
    if attachment.verification_state == models.AttachmentVerification.MISMATCH:
        return [blocker("ATTACHMENT_MISMATCH")]
    return attachment_service.upstream_problems(device.name, attachment.upstream_device)


def _refuse_device(device, action, blockers, *, actor, auth=None, attachment=None) -> AuthorizationResult:
    with transaction.atomic():
        event = events.record(device, action, Outcome.REFUSED, actor=actor, from_state=device.lifecycle_state, blockers=blockers,
                              bootstrap_authorization=auth, attachment=attachment)
    return AuthorizationResult(auth, False, action, list(blockers), event)


# --- operator actions -----------------------------------------------------------------------------------------------------------
def request_authorization(device, *, attachment_id, scope, valid_from, valid_until, max_uses, actor: str, reason: str) -> AuthorizationResult:
    """Request a bootstrap authorization (PENDING_APPROVAL) for a registered new device on one approved attachment."""
    action = "BOOTSTRAP_AUTH_REQUEST"
    attachment = attachment_service.get_attachment(device, attachment_id)
    text, blockers = identity.clean_text(reason, max_length=300)
    if not blockers and not text:
        blockers = [blocker("REASON_REQUIRED")]
    blockers += device_problems(device) + attachment_problems(device, attachment)
    blockers += scope_problems(scope) + window_problems(valid_from, valid_until) + uses_problems(max_uses)
    if device.bootstrap_authorizations.filter(state__in=tuple(models.BOOTSTRAP_AUTHORIZATION_OPEN)).exists():
        blockers.append(blocker("AUTHORIZATION_OPEN_EXISTS"))
    if blockers:
        return _refuse_device(device, action, blockers, actor=actor, attachment=attachment)
    payload = binding(device, attachment, platform=device.platform, scope=scope, valid_from=valid_from, valid_until=valid_until,
                      max_uses=int(max_uses))
    try:
        with transaction.atomic():
            auth = models.BootstrapAuthorization.objects.create(
                device=device, attachment=attachment, expected_platform=device.platform, scope=sorted(scope), requested_by=actor[:150],
                reason=text, valid_from=valid_from, valid_until=valid_until, max_uses=int(max_uses), binding_digest=binding_digest(payload))
            event = events.record(device, action, Outcome.RECORDED, actor=actor, from_state=device.lifecycle_state,
                                  to_state=device.lifecycle_state, bootstrap_authorization=auth, attachment=attachment,
                                  evidence={"binding_digest": auth.binding_digest, "scope": auth.scope, "max_uses": auth.max_uses,
                                            "valid_from": valid_from.isoformat(), "valid_until": valid_until.isoformat(),
                                            "production_admission": False})
    except IntegrityError:
        return _refuse_device(device, action, [blocker("AUTHORIZATION_OPEN_EXISTS")], actor=actor, attachment=attachment)
    return AuthorizationResult(auth, True, action, [], event)


def _transition(auth, to_state, *, actor, action, allowed_from, checks, evidence, **fields) -> AuthorizationResult:
    """Lock ``auth``, run ``checks(locked)`` (-> blockers), move it to ``to_state`` and record the event -- or refuse."""
    try:
        with transaction.atomic():
            locked = models.BootstrapAuthorization.objects.select_for_update().get(pk=auth.pk)
            if locked.state not in allowed_from:
                raise _Refused([blocker("AUTHORIZATION_STATE_INVALID", state=locked.state)])
            problems = checks(locked)
            if problems:
                raise _Refused(problems)
            locked.state = to_state
            for name, value in fields.items():
                setattr(locked, name, value)
            if to_state not in models.BOOTSTRAP_AUTHORIZATION_OPEN:
                locked.closed_at = timezone.now()
            locked.save()
            event = events.record(locked.device, action, Outcome.RECORDED, actor=actor, from_state=locked.device.lifecycle_state,
                                  to_state=locked.device.lifecycle_state, bootstrap_authorization=locked, attachment=locked.attachment,
                                  evidence={"state": {"to": to_state}, **evidence(locked)})
    except _Refused as refusal:
        return _refuse_device(auth.device, action, refusal.blockers, actor=actor, auth=auth)
    return AuthorizationResult(locked, True, action, [], event)


def approve(auth, *, actor: str, confirm_digest: str) -> AuthorizationResult:
    """Approve: a different person than the requester, confirming the exact binding digest, inside the window, not stale."""
    now = timezone.now()

    def checks(locked):
        problems = []
        if actor == locked.requested_by:
            problems.append(blocker("APPROVAL_SELF"))
        if str(confirm_digest or "").strip().lower() != locked.binding_digest:
            problems.append(blocker("AUTHORIZATION_CONFIRMATION_MISMATCH"))
        if locked.valid_until <= now:
            problems.append(blocker("EXPIRED"))
        if current_digest(locked) != locked.binding_digest:
            problems.append(blocker("STALE"))
        problems += device_problems(locked.device) + attachment_problems(locked.device, locked.attachment)
        return problems

    approval_digest = hashlib.sha256(f"{auth.binding_digest}|{actor[:150]}|{now.isoformat()}".encode()).hexdigest()
    return _transition(auth, State.APPROVED, actor=actor, action="BOOTSTRAP_AUTH_APPROVE", allowed_from=(State.PENDING_APPROVAL,),
                       checks=checks, evidence=lambda locked: {"approval_digest": approval_digest, "production_admission": False},
                       approved_by=actor[:150], approved_at=now, approval_digest=approval_digest)


def revoke(auth, *, actor: str, reason: str) -> AuthorizationResult:
    text, problems = identity.clean_text(reason, max_length=300)
    if problems or not text:
        return _refuse_device(auth.device, "BOOTSTRAP_AUTH_REVOKE", problems or [blocker("REASON_REQUIRED")], actor=actor, auth=auth)
    return _transition(auth, State.REVOKED, actor=actor, action="BOOTSTRAP_AUTH_REVOKE", allowed_from=tuple(models.BOOTSTRAP_AUTHORIZATION_OPEN),
                       checks=lambda locked: [], evidence=lambda locked: {"reason": text},
                       revoked_by=actor[:150], revoked_at=timezone.now(), revocation_reason=text)


def expire_due(*, actor: str = "system:bootstrap-authorization-expiry", now=None) -> list[str]:
    """Close every open authorization whose window is over (EXPIRED) -> the expired ids.  Idempotent."""
    now = now or timezone.now()
    expired = []
    for auth in models.BootstrapAuthorization.objects.select_related("device", "attachment").filter(
            state__in=tuple(models.BOOTSTRAP_AUTHORIZATION_OPEN), valid_until__lte=now):
        result = _transition(auth, State.EXPIRED, actor=actor, action="BOOTSTRAP_AUTH_EXPIRE",
                             allowed_from=tuple(models.BOOTSTRAP_AUTHORIZATION_OPEN), checks=lambda locked: [],
                             evidence=lambda locked: {"valid_until": locked.valid_until.isoformat()})
        if result.ok:
            expired.append(auth.auth_id)
    return expired


# --- the decision engine --------------------------------------------------------------------------------------------------------
def normalize_request(request: dict) -> tuple[dict, list[dict]]:
    """Validate a bootstrap request description (what a Phase 3 producer saw) -> (normalized, blockers)."""
    request = request if isinstance(request, dict) else {}
    out, problems = {}, [blocker("OBSERVATION_INVALID", key=str(k)[:32]) for k in request if k not in REQUEST_KEYS]
    scope = str(request.get("scope") or "")
    if scope not in SCOPE_TOKENS:
        problems.append(blocker("AUTHORIZATION_SCOPE_INVALID", allowed=list(SCOPE_TOKENS)))
    out["scope"] = scope
    for key, normalizer in (("serial", identity.normalize_serial), ("base_mac", identity.normalize_mac)):
        value, issues = normalizer(request.get(key))
        problems += issues
        out[key] = value
    for key in ("upstream_device", "upstream_interface", "local_interface"):
        value = str(request.get(key) or "").strip()
        if value and not models.INTERFACE_RE.fullmatch(value):
            problems.append(blocker("OBSERVATION_INVALID", key=key))
        out[key] = value
    source = str(request.get("attachment_source") or "")
    if source and source not in models.ObservationSource.values:
        problems.append(blocker("OBSERVATION_INVALID", key="attachment_source"))
    out["attachment_trust"] = models.OBSERVATION_TRUST[models.ObservationSource(source)] if source in models.ObservationSource.values else ""
    return out, problems


def decide(auth, request: dict | None = None, *, now=None) -> DecisionResult:
    """Decide whether a bootstrap request matches ``auth``.  Reads, never writes.  Checks run in a fixed order and the first
    failing one decides; a claim can only ever contradict, and trusted attachment evidence is required to authorize."""
    now = now or timezone.now()
    stamp = now.isoformat()
    if auth is None:
        return DecisionResult(Decision.NOT_FOUND, blockers=(blocker("AUTHORIZATION_NOT_FOUND"),), evaluated_at=stamp)
    device = models.ManagedDevice.objects.get(pk=auth.device_id)
    attachment = models.DeviceAttachment.objects.get(pk=auth.attachment_id)

    def result(decision, code, **details):
        return DecisionResult(decision, auth.auth_id, device.device_id, (blocker(code, **details),) if code else (), stamp)

    req, problems = normalize_request(request or {})
    if problems:
        return DecisionResult(Decision.OUT_OF_SCOPE, auth.auth_id, device.device_id, tuple(problems), stamp)
    if auth.state == State.REVOKED or device.is_terminal:
        return result(Decision.REVOKED, "REVOKED")
    if auth.state == State.EXPIRED or now >= auth.valid_until:
        return result(Decision.EXPIRED, "EXPIRED")
    if auth.state == State.CONSUMED or auth.use_count >= auth.max_uses:
        return result(Decision.EXHAUSTED, "EXHAUSTED")
    if auth.state == State.PENDING_APPROVAL:
        return result(Decision.PENDING_APPROVAL, "PENDING_APPROVAL")
    if now < auth.valid_from:
        return result(Decision.NOT_YET_VALID, "NOT_YET_VALID")
    if device.origin != models.DeviceOrigin.REGISTERED_NEW or device.lifecycle_state == S.IN_SERVICE \
            or device.admission_state != models.ProductionAdmissionState.NOT_ADMITTED:
        return result(Decision.ALREADY_IN_SERVICE, "ALREADY_IN_SERVICE")
    if current_digest(auth) != auth.binding_digest:
        return result(Decision.STALE, "STALE")
    if req["scope"] not in (auth.scope or []):
        return result(Decision.OUT_OF_SCOPE, "OUT_OF_SCOPE", requested=req["scope"])
    conflicts = identity.identity_conflicts(serial=req["serial"], mac=req["base_mac"], exclude_pk=device.pk)
    if conflicts:
        return DecisionResult(Decision.CONFLICTING_REQUEST, auth.auth_id, device.device_id, tuple(conflicts), stamp)
    if req["upstream_device"] and models.DeviceAttachment.objects.filter(
            attachment_service.LIVE_ATTACHMENT, upstream_device=req["upstream_device"],
            upstream_interface=req["upstream_interface"]).exclude(device=device).exists():
        return result(Decision.CONFLICTING_REQUEST, "CONFLICTING_REQUEST", reason="the port is expected to carry another device")
    if device.identity_state == models.IdentityVerificationState.MISMATCH \
            or (req["serial"] and device.expected_serial and req["serial"] != device.expected_serial) \
            or (req["base_mac"] and device.expected_base_mac and req["base_mac"] != device.expected_base_mac):
        return result(Decision.IDENTITY_MISMATCH, "IDENTITY_MISMATCH")
    if attachment.approval_state != models.AttachmentApproval.APPROVED \
            or attachment.verification_state == models.AttachmentVerification.MISMATCH \
            or (req["upstream_device"] and (req["upstream_device"], req["upstream_interface"])
                != (attachment.upstream_device, attachment.upstream_interface)) \
            or (req["local_interface"] and attachment.local_interface and req["local_interface"] != attachment.local_interface):
        return result(Decision.ATTACHMENT_MISMATCH, "ATTACHMENT_MISMATCH")
    identity_claimed = (req["serial"] and req["serial"] == device.expected_serial) or \
        (req["base_mac"] and req["base_mac"] == device.expected_base_mac)
    if not identity_claimed:
        return result(Decision.PENDING_EVIDENCE, "PENDING_EVIDENCE", missing="a claimed identity matching the expected one")
    attachment_observed = attachment.verification_state == models.AttachmentVerification.VERIFIED or (
        req["attachment_trust"] == models.ObservationTrust.OBSERVED and req["upstream_device"])
    if not attachment_observed:
        return result(Decision.PENDING_EVIDENCE, "PENDING_EVIDENCE", missing="trusted attachment evidence")
    return result(Decision.AUTHORIZED, "")


def evaluate(auth, request: dict | None = None, *, actor: str, now=None) -> DecisionResult:
    """``decide`` and record the decision on the device chain (a dry run for the operator; it consumes nothing)."""
    outcome = decide(auth, request, now=now)
    if auth is not None:
        with transaction.atomic():
            device = models.ManagedDevice.objects.get(pk=auth.device_id)
            events.record(device, "BOOTSTRAP_AUTH_DECIDE", Outcome.RECORDED, actor=actor, from_state=device.lifecycle_state,
                          to_state=device.lifecycle_state, bootstrap_authorization=auth, blockers=outcome.blockers,
                          authorization={"decision": outcome.decision, "production_admission": False},
                          evidence={"request_keys": sorted(k for k in (request or {}) if k in REQUEST_KEYS), "dry_run": True})
    return outcome


def consume(auth, request: dict, *, actor: str, now=None) -> DecisionResult:
    """The Phase 3 contract: decide under a row lock and, only when AUTHORIZED, count one use (CONSUMED at the limit).

    Counts a use and records it; it delivers nothing and changes no lifecycle state (the bootstrap producer owns that)."""
    if auth is None:
        return decide(None, request, now=now)
    with transaction.atomic():
        locked = models.BootstrapAuthorization.objects.select_for_update().get(pk=auth.pk)
        outcome = decide(locked, request, now=now)
        device = models.ManagedDevice.objects.get(pk=locked.device_id)
        if outcome.authorized:
            # compare-and-swap on the use count: a concurrent consumer that won makes this one refuse (never a lost update,
            # whatever the database's row-lock semantics)
            stamp = timezone.now()
            fields = {"use_count": F("use_count") + 1, "updated_at": stamp}
            if locked.use_count + 1 >= locked.max_uses:
                fields.update(state=State.CONSUMED, closed_at=stamp)
            won = models.BootstrapAuthorization.objects.filter(pk=locked.pk, state=State.APPROVED, use_count=locked.use_count).update(**fields)
            locked.refresh_from_db()
            if not won:
                outcome =DecisionResult(Decision.CONFLICTING_REQUEST, locked.auth_id, device.device_id,
                                         (blocker("CONCURRENT_MODIFICATION"),), outcome.evaluated_at)
        events.record(device, "BOOTSTRAP_AUTH_CONSUME", Outcome.RECORDED if outcome.authorized else Outcome.REFUSED, actor=actor,
                      actor_kind=events.AUTOMATION, from_state=device.lifecycle_state, to_state=device.lifecycle_state,
                      bootstrap_authorization=locked, blockers=outcome.blockers,
                      authorization={"decision": outcome.decision, "production_admission": False},
                      evidence={"use_count": locked.use_count, "max_uses": locked.max_uses})
    return outcome
