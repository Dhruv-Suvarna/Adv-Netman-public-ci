"""Bootstrap artifacts: render-once, secret-free, bounded, and delivered only to the device the trusted lease binds.

Identity: ``artifact_id`` is derived from the session and the content digest (``ART-<24 hex>``); the only request path is
``/ztp/v1/<artifact_id>/<filename>`` and nothing is ever read from the filesystem, so traversal, enumeration of other files
and exposure of source or database files are impossible by construction.  URLs carry no secret, so logging them leaks nothing
(the servers still log only a digest).

Delivery decision (``authorize``), first failing check wins, every refusal is the same uniform ``ARTIFACT_NOT_AVAILABLE`` to
the requester and a specific code in the evidence:

    path form -> artifact ACTIVE, unexpired, filename matches -> session open -> the requester's address holds this
    session's CORRELATED, trusted-relay, unexpired lease -> first delivery: Phase 2 ``authorization.consume`` (one use per
    artifact; claims from the lease, attachment from the trusted relay) / repeat: the authorization is still live and the
    per-artifact delivery bound is not reached

A served artifact proves only that bytes left NMAS.  It is never evidence that the device applied them.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass

from django.db import transaction
from django.db.models import F
from django.utils import timezone

from ... import models
from ..devices import authorization as authorization_service
from ..devices import events
from . import adapters
from .adapters.base import secret_findings

PATH_RE = re.compile(r"^/?ztp/v1/(ART-[0-9a-f]{24})/([A-Za-z0-9][A-Za-z0-9._-]{0,63})$")
FILENAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
MAX_DELIVERIES = 5
Outcome = models.DeviceLifecycleEventOutcome
State = models.BootstrapArtifactState
ACTOR = "system:ztp-artifact-service"


@dataclass
class DeliveryDecision:
    ok: bool
    code: str = ""
    artifact: object | None = None
    session: object | None = None
    content: bytes = b""
    content_type: str = "text/plain"
    duplicate: bool = False
    counted: bool = False
    request_digest: str = ""


def make_artifact_id(session, sha256: str) -> str:
    return "ART-" + hashlib.sha256(f"{session.pk}|{sha256}".encode()).hexdigest()[:24]


def create(session, rendered, *, expires_at, max_deliveries: int = MAX_DELIVERIES):
    """Store a rendered artifact (superseding the session's active one).  Refuses secret-shaped content and unsafe names."""
    if not FILENAME_RE.fullmatch(rendered.filename) or secret_findings(rendered.content):
        raise ValueError("ARTIFACT_SECRET_DETECTED" if secret_findings(rendered.content) else "ARTIFACT_NOT_AVAILABLE")
    digest = hashlib.sha256(rendered.content.encode()).hexdigest()
    with transaction.atomic():
        for old in session.artifacts.select_for_update().filter(state=State.ACTIVE):
            old.state = State.SUPERSEDED
            old.save(update_fields=["state", "updated_at"])
        return models.BootstrapArtifact.objects.create(
            session=session, artifact_id=make_artifact_id(session, digest), filename=rendered.filename, content=rendered.content,
            content_type=rendered.content_type, sha256=digest, transport=session.transport, expires_at=expires_at,
            max_deliveries=max_deliveries)


def close_for_session(session, state=State.REVOKED) -> int:
    count = 0
    for artifact in session.artifacts.filter(state=State.ACTIVE):
        artifact.state = state
        artifact.save(update_fields=["state", "updated_at"])
        count += 1
    return count


def expire_due(*, now=None) -> int:
    """Expire every active artifact past its window or whose session is closed (idempotent; safe after a restart)."""
    now = now or timezone.now()
    count = 0
    for artifact in models.BootstrapArtifact.objects.select_related("session").filter(state=State.ACTIVE):
        if artifact.expires_at <= now or not artifact.session.is_open:
            artifact.state = State.EXPIRED
            artifact.save(update_fields=["state", "updated_at"])
            count += 1
    return count


def _bound_lease(session, client_address: str, now):
    """The session's correlated trusted lease for ``client_address`` that is still valid (None otherwise)."""
    return (session.lease_observations.filter(outcome=models.DhcpLeaseOutcome.CORRELATED, relay_trusted=True, address=client_address)
            .exclude(lease_ends__lte=now).order_by("-last_seen", "-id").first())


def request_for_lease(session, lease) -> dict:
    """The Phase 2 bootstrap request a delivery presents to ``authorization.consume``: claims from the lease (untrusted, can only
    contradict), the attachment from the trusted relay (OBSERVED)."""
    adapter = adapters.get(session.adapter)
    claims, _native = adapter.extract_dhcp_claims({"vendor_class": lease.vendor_class, "client_id": lease.client_id,
                                                   "hostname": lease.hostname}) if adapter else ({}, False)
    return {"scope": "BOOTSTRAP_FETCH", "serial": claims.get("serial", ""), "base_mac": claims.get("base_mac", ""),
            "upstream_device": lease.upstream_device, "upstream_interface": lease.upstream_interface,
            "attachment_source": models.ObservationSource.DHCP_RELAY_ATTACHMENT}


def _live_authorization(auth, now) -> bool:
    return auth.state in (models.BootstrapAuthorizationState.APPROVED, models.BootstrapAuthorizationState.CONSUMED) \
        and auth.valid_from <= now < auth.valid_until and authorization_service.current_digest(auth) == auth.binding_digest


def authorize(path: str, client_address: str, transport: str, *, now=None) -> DeliveryDecision:
    """Decide (and, for a first delivery, consume one authorization use) -- see the module docstring for the order."""
    now = now or timezone.now()
    text = str(path or "")[:512]
    decision = DeliveryDecision(False, request_digest=hashlib.sha256(text.encode("utf-8", "replace")).hexdigest())
    match = PATH_RE.fullmatch(text.split("?", 1)[0])
    if not match:
        decision.code = "PATH_INVALID"
        return decision
    artifact = models.BootstrapArtifact.objects.select_related("session", "session__authorization", "session__device").filter(
        artifact_id=match.group(1)).first()
    if artifact is None or artifact.filename != match.group(2):
        decision.code = "ARTIFACT_UNKNOWN"
        return decision
    decision.artifact, decision.session = artifact, artifact.session
    session = artifact.session
    if artifact.state != State.ACTIVE or artifact.expires_at <= now:
        decision.code = "ARTIFACT_EXPIRED" if artifact.state in (State.ACTIVE, State.EXPIRED) else f"ARTIFACT_{artifact.state}"
        return decision
    if not session.is_open or artifact.transport != transport:
        decision.code = "SESSION_CLOSED" if not session.is_open else "TRANSPORT_MISMATCH"
        return decision
    lease = _bound_lease(session, client_address, now)
    if lease is None:
        decision.code = "REQUESTER_NOT_BOUND"
        return decision
    auth = session.authorization
    with transaction.atomic():
        locked = models.BootstrapArtifact.objects.select_for_update().get(pk=artifact.pk)
        if locked.delivery_count >= locked.max_deliveries:
            decision.code = "ARTIFACT_DELIVERY_LIMIT"
            return decision
        if not locked.authorization_use_counted:
            outcome = authorization_service.consume(auth, request_for_lease(session, lease), actor=ACTOR, now=now)
            if not outcome.authorized:
                decision.code = f"AUTH_{outcome.decision}"
                return decision
            decision.counted = True
        else:
            auth.refresh_from_db()
            if not _live_authorization(auth, now):
                decision.code = f"AUTH_{auth.state}" if auth.state not in ("APPROVED", "CONSUMED") else "AUTH_EXPIRED_OR_STALE"
                return decision
            decision.duplicate = True
        won = models.BootstrapArtifact.objects.filter(pk=locked.pk, delivery_count=locked.delivery_count).update(
            delivery_count=F("delivery_count") + 1, authorization_use_counted=True, updated_at=timezone.now())
        if not won:
            transaction.set_rollback(True)          # a use consumed for a delivery that will not happen is undone
            decision.code, decision.counted = "CONCURRENT_MODIFICATION", False
            return decision
    decision.ok = True
    decision.content = artifact.content.encode()
    decision.content_type = artifact.content_type
    return decision


def record(decision: DeliveryDecision, *, client_address: str, transport: str, outcome: str, bytes_sent: int = 0) -> object:
    """Persist the delivery evidence; the first SERVED delivery also advances the session to DELIVERED (one lifecycle event)."""
    with transaction.atomic():
        row = models.BootstrapDelivery.objects.create(
            artifact=decision.artifact, session=decision.session, transport=transport, client_address=client_address,
            request_digest=decision.request_digest, outcome=outcome, code=decision.code[:40], bytes_sent=int(bytes_sent),
            duplicate=decision.duplicate, counted_authorization_use=decision.counted)
        session = decision.session
        if outcome == models.BootstrapDeliveryOutcome.SERVED and session is not None and not decision.duplicate:
            fresh = models.ZtpSession.objects.select_for_update().get(pk=session.pk)
            if fresh.stage in (models.ZtpSessionStage.AWAITING_DISCOVERY, models.ZtpSessionStage.DISCOVERED):
                fresh.stage = models.ZtpSessionStage.DELIVERED
                fresh.version += 1
                fresh.save(update_fields=["stage", "version", "updated_at"])
            device = models.ManagedDevice.objects.get(pk=session.device_id)
            events.record(device, "ZTP_ARTIFACT_DELIVERED", Outcome.RECORDED, actor=ACTOR, actor_kind=events.AUTOMATION,
                          from_state=device.lifecycle_state, to_state=device.lifecycle_state, bootstrap_authorization=session.authorization,
                          evidence={"session": session.session_id, "artifact": decision.artifact.artifact_id, "sha256": decision.artifact.sha256,
                                    "transport": transport, "client_address": client_address, "bytes": int(bytes_sent),
                                    "bootstrap_use_counted": decision.counted,
                                    "meaning": "bytes left NMAS; not proof the device applied them"})
        elif outcome != models.BootstrapDeliveryOutcome.SERVED:
            events.audit("ZTP_ARTIFACT_DELIVERY", Outcome.REFUSED, actor=ACTOR, object_id=(session.session_id if session else "unknown"),
                         summary=f"bootstrap artifact request {outcome.lower()} ({decision.code})",
                         metadata={"transport": transport, "client_address": client_address, "code": decision.code,
                                   "request_digest": decision.request_digest})
    return row
