"""The native-ZTP session: the one place Phase 3 moves a device from DISCOVERED to BOOTSTRAPPED -- on evidence, never on hope.

Evidence stages are kept apart (each is its own record):

    discovery        DhcpLeaseObservation CORRELATED through a trusted relay      -> session DISCOVERED, device DISCOVERED
    authorization    Phase 2 BootstrapAuthorization APPROVED; one use consumed per artifact at first delivery
    delivery         BootstrapDelivery SERVED                                     -> session DELIVERED (not "applied")
    native execution read back over the authenticated session (e.g. EOS ``show zerotouch`` disabled)
    management       first host key seen (MANAGEMENT_REACHED, untrusted) -> enrolled out of band by an approver ->
                     authenticated, host-key-pinned verification of the minimal bootstrap -> MANAGEMENT_VERIFIED
    identity         an AUTHENTICATED_SESSION observation is recorded; VERIFIED stays the operator's Phase 2 action
    lifecycle        DISCOVERED -> BOOTSTRAPPED (pending commission).  admission_state stays NOT_ADMITTED, always.

Retryable failures (unreachable, key not yet accepted, ZTP still running) leave the session open with the adapter's native
retry / recovery guidance; non-retryable ones (identity or host-key mismatch, production services found) close it FAILED.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import secrets
import subprocess
import uuid
import warnings
from dataclasses import dataclass, field
from datetime import timedelta

from django.db import IntegrityError, transaction
from django.utils import timezone

from ... import models
from ..devices import authorization as authorization_service
from ..devices import events, identity, lifecycle
from ..devices.codes import blocker, codes
from . import adapters, artifacts, dependencies, management, policy
from .adapters.base import BootstrapContext, TransportPolicy

Stage = models.ZtpSessionStage
Outcome = models.DeviceLifecycleEventOutcome
S = models.DeviceLifecycleState
ENROLLMENT_USER = "nmas-enroll"
SYSTEM = "system:ztp-workflow"
REQUIRED_SCOPE = {"DHCP_DISCOVERY", "BOOTSTRAP_FETCH"}
ARTIFACT_LIFETIME = timedelta(hours=24)


@dataclass
class ZtpResult:
    ok: bool
    action: str
    session: object | None = None
    blockers: list = field(default_factory=list)
    event: object | None = None
    detail: dict = field(default_factory=dict)

    @property
    def codes(self) -> list[str]:
        return codes(self.blockers)


def get_session(session_id):
    text = str(session_id or "")
    if not text.startswith("ZTP-") or not text[4:].isdigit():
        return None
    return models.ZtpSession.objects.select_related("device", "authorization", "authorization__attachment", "network").filter(
        pk=int(text[4:])).first()


def _refuse(device, action, blockers_, *, actor, session=None, actor_kind=events.HUMAN, **evidence) -> ZtpResult:
    device = models.ManagedDevice.objects.get(pk=device.pk)
    with transaction.atomic():
        event = events.record(device, action, Outcome.REFUSED, actor=actor, actor_kind=actor_kind, from_state=device.lifecycle_state,
                              to_state=device.lifecycle_state, blockers=blockers_,
                              bootstrap_authorization=session.authorization if session else None,
                              evidence={"session": session.session_id if session else "", **evidence})
    return ZtpResult(False, action, session, list(blockers_), event)


# --- enrollment material ----------------------------------------------------------------------------------------------------
def locked_sha512_crypt() -> str:
    """A SHA-512 crypt hash of 32 random bytes that are discarded at once: a password field no one can satisfy."""
    secret = secrets.token_hex(32)
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            import crypt  # noqa: PLC0415 - stdlib until 3.13

        return crypt.crypt(secret, crypt.mksalt(crypt.METHOD_SHA512))
    except ImportError:
        done = subprocess.run(["openssl", "passwd", "-6", "-stdin"], input=secret, capture_output=True, text=True, timeout=10,
                              check=True, shell=False)  # noqa: S603,S607 - fixed argv
        return done.stdout.strip()
    finally:
        del secret


def generate_enrollment_key(key_types, comment: str) -> tuple[str, str, str]:
    """-> (private OpenSSH PEM, public line, fingerprint) in the strongest algorithm the adapter's artifact can install."""
    from ..credentials.mfa import generate_service_keypair, public_key_fingerprint

    if "ssh-ed25519" in key_types:
        return generate_service_keypair(comment)
    if "ssh-rsa" in key_types:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa

        key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
        private = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.OpenSSH, serialization.NoEncryption()).decode()
        public = key.public_key().public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH).decode() + f" {comment}"
        return private, public, public_key_fingerprint(public)
    raise ValueError("ZTP_ENROLLMENT_BLOCKED")


def context_for(session, *, locked_password_hash: str = "") -> BootstrapContext:
    network, attachment = session.network, session.authorization.attachment
    relay = policy.relay_for(network, attachment.upstream_device) or network.gateway
    return BootstrapContext(
        hostname=session.device.name, session_id=session.session_id, auth_id=session.authorization.auth_id,
        interface=attachment.local_interface, address=session.reserved_address,
        prefixlen=ipaddress.IPv4Network(network.ipv4_prefix).prefixlen, gateway=relay, service_address=network.service_address,
        service_prefix=network.service_prefix, enrollment_user=ENROLLMENT_USER, enrollment_public_key=session.enrollment_public_key,
        locked_password_hash=locked_password_hash)


# --- open / cancel --------------------------------------------------------------------------------------------------------------
def open_problems(device, auth, network, *, now=None) -> list[dict]:
    now = now or timezone.now()
    problems = []
    if device.is_terminal:
        return [blocker("DEVICE_TERMINAL", state=device.lifecycle_state)]
    if device.origin != models.DeviceOrigin.REGISTERED_NEW:
        return [blocker("ORIGIN_NOT_ELIGIBLE", origin=device.origin)]
    if device.lifecycle_state not in (S.REGISTERED, S.DISCOVERED) or device.admission_state != models.ProductionAdmissionState.NOT_ADMITTED:
        problems.append(blocker("OUT_OF_SCOPE", state=device.lifecycle_state))
    if device.identity_state == models.IdentityVerificationState.MISMATCH:
        problems.append(blocker("IDENTITY_MISMATCH"))
    if auth is None or auth.device_id != device.pk:
        return problems + [blocker("AUTHORIZATION_NOT_FOUND")]
    if auth.state != models.BootstrapAuthorizationState.APPROVED:
        problems.append(blocker("PENDING_APPROVAL" if auth.state == "PENDING_APPROVAL" else "AUTHORIZATION_STATE_INVALID", state=auth.state))
    elif not auth.valid_from <= now < auth.valid_until:
        problems.append(blocker("EXPIRED" if now >= auth.valid_until else "NOT_YET_VALID"))
    elif authorization_service.current_digest(auth) != auth.binding_digest:
        problems.append(blocker("STALE"))
    if not REQUIRED_SCOPE <= set(auth.scope or ()):
        problems.append(blocker("AUTHORIZATION_SCOPE_INVALID", required=sorted(REQUIRED_SCOPE)))
    if models.ZtpSession.objects.filter(device=device, stage__in=tuple(models.ZTP_SESSION_OPEN)).exists():
        problems.append(blocker("ZTP_SESSION_OPEN_EXISTS"))
    checks = dependencies.evaluate(device, auth.attachment, network)
    problems += [blocker(c["code"], check=c["check"], detail=c["detail"]) for c in checks if not c["ok"]]
    adapter = adapters.for_platform(device.platform)
    if adapter is not None and adapter.capability.implemented:
        _cap, cap_codes = adapter.detect_native_ztp_capability()
        problems += [blocker(code) for code in cap_codes]
        if not adapter.capability.enrollment_key_types:
            problems.append(blocker("ZTP_ENROLLMENT_BLOCKED"))
    return problems


def open_session(device, *, authorization, network, actor: str, transport_policy: str = TransportPolicy.ISOLATED_LAB) -> ZtpResult:
    """Open a ZTP session: choose the native adapter and transport, reserve an address, create the enrollment key (private
    half to the protected provider only), render and store the secret-free minimal bootstrap.  Applies nothing to DHCP."""
    action = "ZTP_SESSION_OPEN"
    problems = open_problems(device, authorization, network)
    adapter = adapters.for_platform(device.platform)
    decision = adapter.select_bootstrap_transport(transport_policy) if adapter and adapter.capability.implemented else None
    if decision is not None and decision.blockers:
        problems += [blocker(code, policy=transport_policy) for code in decision.blockers]
    address = policy.allocate_address(network) if network is not None and not problems else ""
    if not problems and not address:
        problems.append(blocker("BOOTSTRAP_POOL_EXHAUSTED"))
    if problems:
        return _refuse(device, action, problems, actor=actor)
    from modules.device_credentials import SecretProviderError, make_reference

    reference = make_reference(f"ztp-enroll-{device.pk}-{uuid.uuid4().hex[:12]}")
    try:
        private, public, key_fingerprint = generate_enrollment_key(adapter.capability.enrollment_key_types, f"{ENROLLMENT_USER}@{device.device_id}")
    except ValueError:
        return _refuse(device, action, [blocker("ZTP_ENROLLMENT_BLOCKED")], actor=actor)
    try:
        with transaction.atomic():
            session = models.ZtpSession.objects.create(
                device=device, authorization=authorization, network=network, adapter=adapter.capability.adapter, platform=device.platform,
                transport=decision.selected, transport_decision=decision.as_dict(), reserved_address=address, enrollment_key_ref=reference,
                enrollment_public_key=public, enrollment_key_fingerprint=key_fingerprint, opened_by=actor[:150])
            rendered, refusal = adapter.prepare_bootstrap_artifact(context_for(session, locked_password_hash=locked_sha512_crypt()
                                                                               if adapter.capability.adapter == "arista_eos" else ""))
            if refusal:
                raise _Abort(refusal)
            artifact = artifacts.create(session, rendered, expires_at=min(authorization.valid_until, timezone.now() + ARTIFACT_LIFETIME))
            event = events.record(device, action, Outcome.RECORDED, actor=actor, from_state=device.lifecycle_state,
                                  to_state=device.lifecycle_state, bootstrap_authorization=authorization, attachment=authorization.attachment,
                                  evidence={"session": session.session_id, "adapter": session.adapter, "evidence_status": adapter.capability.evidence_status,
                                            "transport": decision.as_dict(), "network": network.name, "reserved_address": address,
                                            "artifact": artifact.artifact_id, "artifact_sha256": artifact.sha256, "artifact_kind": rendered.kind,
                                            "enrollment_key_fingerprint": key_fingerprint, "bootstrap_plaintext_material": False,
                                            "production_admission": False})
            # Last step, inside the transaction: the private half reaches the protected provider only once every record
            # exists, so a refusal above leaves no orphaned key; a provider failure rolls the whole session back.
            try:
                management.secret_provider().initialize(reference, private)
            except SecretProviderError:
                raise _Abort(["ZTP_ENROLLMENT_BLOCKED"]) from None
    except _Abort as abort:
        return _refuse(device, action, [blocker(code) for code in abort.codes], actor=actor)
    except IntegrityError:
        return _refuse(device, action, [blocker("ZTP_SESSION_OPEN_EXISTS")], actor=actor)
    finally:
        private = None  # noqa: F841 - drop the only reference to the private half
    return ZtpResult(True, action, session, [], event, {"artifact": artifact.artifact_id, "dhcp_policy_current": False})


class _Abort(Exception):
    def __init__(self, codes_):
        super().__init__("abort")
        self.codes = codes_


def _close(session, stage, *, actor, artifact_state=models.BootstrapArtifactState.REVOKED, **fields):
    session.stage, session.closed_by, session.closed_at = stage, actor[:150], timezone.now()
    for name, value in fields.items():
        setattr(session, name, value)
    session.version += 1
    session.save()
    artifacts.close_for_session(session, artifact_state)


def cancel_session(session, *, actor: str, reason: str) -> ZtpResult:
    action = "ZTP_SESSION_CANCEL"
    text, problems = identity.clean_text(reason, max_length=300)
    if problems or not text:
        return _refuse(session.device, action, problems or [blocker("REASON_REQUIRED")], actor=actor, session=session)
    with transaction.atomic():
        fresh = models.ZtpSession.objects.select_for_update().get(pk=session.pk)
        if not fresh.is_open:
            return _refuse(session.device, action, [blocker("ZTP_SESSION_STATE_INVALID", stage=fresh.stage)], actor=actor, session=fresh)
        _close(fresh, Stage.CANCELLED, actor=actor, failure={**(fresh.failure or {}), "cancel_reason": text})
        device = models.ManagedDevice.objects.get(pk=fresh.device_id)
        event = events.record(device, action, Outcome.RECORDED, actor=actor, from_state=device.lifecycle_state, to_state=device.lifecycle_state,
                              bootstrap_authorization=fresh.authorization, evidence={"session": fresh.session_id, "reason": text,
                                                                                     "dhcp_policy_reapply_required": True})
    return ZtpResult(True, action, fresh, [], event)


# --- failures -------------------------------------------------------------------------------------------------------------------
def record_failure(session, code: str, *, retryable: bool, actor: str, detail: str = "") -> ZtpResult:
    """Record a failure with the adapter's native guidance.  Retryable: the session stays open (attempts + 1).  Not retryable:
    the session closes FAILED; the device is NOT failed automatically (``fail_device`` is a separate, evidenced step)."""
    action = "ZTP_FAILURE"
    adapter = adapters.get(session.adapter)
    guidance = {"retry": adapter.determine_native_retry_behavior().as_dict(),
                "recovery": [a.as_dict() for a in adapter.determine_supported_recovery_actions()]} if adapter else {}
    with transaction.atomic():
        fresh = models.ZtpSession.objects.select_for_update().get(pk=session.pk)
        failure = {"code": code, "retryable": bool(retryable), "stage": fresh.stage, "detail": str(detail)[:200],
                   "recorded_at": timezone.now().isoformat(), **guidance}
        if retryable and fresh.is_open:
            fresh.failure, fresh.attempts, fresh.version = failure, fresh.attempts + 1, fresh.version + 1
            fresh.save(update_fields=["failure", "attempts", "version", "updated_at"])
        elif fresh.is_open:
            _close(fresh, Stage.FAILED, actor=actor, failure=failure)
        device = models.ManagedDevice.objects.get(pk=fresh.device_id)
        event = events.record(device, action, Outcome.RECORDED, actor=actor, actor_kind=events.AUTOMATION, from_state=device.lifecycle_state,
                              to_state=device.lifecycle_state, bootstrap_authorization=fresh.authorization, blockers=[blocker(code)],
                              evidence={"session": fresh.session_id, "retryable": bool(retryable), "stage": fresh.stage})
    return ZtpResult(False, action, fresh, [blocker(code)], event, {"failure": failure})


def fail_device(session, *, actor: str) -> ZtpResult:
    """DISCOVERED -> FAILED on a closed, non-retryable session failure (an operator decision with the session as evidence)."""
    result = lifecycle.transition(session.device, S.FAILED, actor=actor, actor_kind=events.HUMAN, evidence={"ztp_session": session.pk})
    return ZtpResult(result.ok, "ZTP_FAIL_DEVICE", session, result.blockers, result.event)


# --- management: first contact, host-key enrollment, verification --------------------------------------------------------------
def contact_management(session, *, actor: str, observe=management.observe_host_key) -> ZtpResult:
    """Read the device's SSH host key over the bootstrap network (key exchange only).  Recorded as UNTRUSTED first contact."""
    action = "ZTP_MANAGEMENT_CONTACT"
    if session.stage not in (Stage.DELIVERED, Stage.MANAGEMENT_REACHED):
        return _refuse(session.device, action, [blocker("ZTP_SESSION_STATE_INVALID", stage=session.stage)], actor=actor, session=session)
    try:
        seen = observe(session.reserved_address)
    except management.ManagementError as exc:
        return record_failure(session, exc.code, retryable=True, actor=actor, detail=exc.detail)
    current = models.ZtpSession.objects.get(pk=session.pk)
    if current.enrolled_host_key and seen != current.enrolled_host_key:
        return record_failure(current, "HOST_KEY_MISMATCH", retryable=False, actor=actor)
    if current.observed_host_key and seen != current.observed_host_key:
        return record_failure(current, "HOST_KEY_MISMATCH", retryable=False, actor=actor, detail="the host key changed since first contact")
    with transaction.atomic():
        fresh = models.ZtpSession.objects.select_for_update().get(pk=session.pk)
        fresh.observed_host_key = fresh.observed_host_key or seen
        if fresh.stage == Stage.DELIVERED:
            fresh.stage = Stage.MANAGEMENT_REACHED
        fresh.version += 1
        fresh.save(update_fields=["observed_host_key", "stage", "version", "updated_at"])
        device = models.ManagedDevice.objects.get(pk=fresh.device_id)
        event = events.record(device, action, Outcome.RECORDED, actor=actor, actor_kind=events.AUTOMATION, from_state=device.lifecycle_state,
                              to_state=device.lifecycle_state, bootstrap_authorization=fresh.authorization,
                              evidence={"session": fresh.session_id, "observed_host_key": seen, "trusted": False,
                                        "meaning": "first-seen host key; trusted only after out-of-band enrollment"})
    return ZtpResult(True, action, fresh, [], event, {"observed_host_key": seen})


def enroll_host_key(session, *, fingerprint: str, actor: str, basis: str) -> ZtpResult:
    """An approver (not the session opener) enrolls the host key they confirmed OUT OF BAND (e.g. the device console's
    ``show management ssh hostkey``).  It must equal what management contact observed, when that exists."""
    action = "ZTP_HOST_KEY_ENROLL"
    value, problems = identity.normalize_host_key(fingerprint)
    text, more = identity.clean_text(basis, max_length=200)
    problems += more
    if not problems and not (value and text):
        problems.append(blocker("REASON_REQUIRED"))
    if actor == session.opened_by:
        problems.append(blocker("APPROVAL_SELF"))
    if not session.is_open:
        problems.append(blocker("ZTP_SESSION_STATE_INVALID", stage=session.stage))
    if session.observed_host_key and value and value != session.observed_host_key:
        problems.append(blocker("HOST_KEY_MISMATCH"))
    if value:
        problems += identity.identity_conflicts(host_key=value, exclude_pk=session.device_id)
    if problems:
        return _refuse(session.device, action, problems, actor=actor, session=session)
    with transaction.atomic():
        fresh = models.ZtpSession.objects.select_for_update().get(pk=session.pk)
        fresh.enrolled_host_key, fresh.host_key_enrolled_by, fresh.host_key_enrollment_basis = value, actor[:150], text
        fresh.version += 1
        fresh.save(update_fields=["enrolled_host_key", "host_key_enrolled_by", "host_key_enrollment_basis", "version", "updated_at"])
        device = models.ManagedDevice.objects.get(pk=fresh.device_id)
        event = events.record(device, action, Outcome.RECORDED, actor=actor, from_state=device.lifecycle_state, to_state=device.lifecycle_state,
                              bootstrap_authorization=fresh.authorization,
                              evidence={"session": fresh.session_id, "enrolled_host_key": value, "basis": text,
                                        "matches_first_contact": bool(fresh.observed_host_key)})
    return ZtpResult(True, action, fresh, [], event)


NON_RETRYABLE_CHECKS = {"platform", "no_production_services", "only_bootstrap_routes", "routing_disabled", "only_bootstrap_interface_addressed"}


def verify_management(session, *, actor: str, run=management.run_commands) -> ZtpResult:
    """Authenticated, host-key-pinned verification of the minimal bootstrap; on success DISCOVERED -> BOOTSTRAPPED."""
    action = "ZTP_MANAGEMENT_VERIFY"
    if session.stage not in (Stage.DELIVERED, Stage.MANAGEMENT_REACHED):
        return _refuse(session.device, action, [blocker("ZTP_SESSION_STATE_INVALID", stage=session.stage)], actor=actor, session=session)
    if not session.enrolled_host_key:
        return _refuse(session.device, action, [blocker("HOST_KEY_NOT_ENROLLED")], actor=actor, session=session)
    auth_state = models.BootstrapAuthorization.objects.filter(pk=session.authorization_id).values_list("state", flat=True).first()
    if auth_state not in policy.DHCP_ELIGIBLE_AUTH:      # revoked / withdrawn: never contact the device to complete the onboarding
        return _refuse(session.device, action, [blocker("AUTHORIZATION_STATE_INVALID", state=auth_state)], actor=actor, session=session)
    adapter = adapters.get(session.adapter)
    try:
        found = run(session.reserved_address, username=ENROLLMENT_USER, key_reference=session.enrollment_key_ref,
                    enrolled_host_key=session.enrolled_host_key, commands=adapter.verification_commands())
    except management.ManagementError as exc:
        return record_failure(session, exc.code, retryable=exc.code != "HOST_KEY_MISMATCH", actor=actor, detail=exc.detail)
    ctx = context_for(session)
    report = adapter.verify_bootstrap_result(found["outputs"], ctx)
    claims = {k: v for k, v in report.claims.items() if k in ("serial", "base_mac")}
    observed = lifecycle.record_observation(session.device, kind=models.ObservationKind.IDENTITY, source=models.ObservationSource.AUTHENTICATED_SESSION,
                                            actor=SYSTEM, claims={**claims, "host_key": found["host_key"]})
    observation = getattr(observed, "observation", None)
    if observation is None or observation.result == models.ObservationResult.MISMATCH:
        report.add("identity_matches_authorized", False, "the authenticated session reports another hardware identity")
    digest = hashlib.sha256(json.dumps(report.as_dict(), sort_keys=True).encode()).hexdigest()
    with transaction.atomic():
        fresh = models.ZtpSession.objects.select_for_update().get(pk=session.pk)
        fresh.verification = {**report.as_dict(), "digest": digest, "observation": observation.pk if observation else None,
                              "verified_at": timezone.now().isoformat(), "host_key": found["host_key"]}
        if report.ok:
            fresh.stage = Stage.MANAGEMENT_VERIFIED
        fresh.version += 1
        fresh.save(update_fields=["verification", "stage", "version", "updated_at"])
        device = models.ManagedDevice.objects.get(pk=fresh.device_id)
        events.record(device, action, Outcome.RECORDED if report.ok else Outcome.REFUSED, actor=actor, actor_kind=events.AUTOMATION,
                      from_state=device.lifecycle_state, to_state=device.lifecycle_state, bootstrap_authorization=fresh.authorization,
                      observation=observation, blockers=[] if report.ok else [blocker("BOOTSTRAP_VERIFICATION_FAILED")],
                      evidence={"session": fresh.session_id, "verification_digest": digest,
                                "failed_checks": [c["check"] for c in report.checks if not c["ok"]],
                                "ztp_disabled": report.ztp_disabled, "production_services": report.production_services})
    if not report.ok:
        failed = {c["check"] for c in report.checks if not c["ok"]}
        retryable = not (failed & (NON_RETRYABLE_CHECKS | {"identity_matches_authorized"}))
        return record_failure(fresh, "BOOTSTRAP_VERIFICATION_FAILED", retryable=retryable, actor=actor, detail=",".join(sorted(failed)))
    moved = lifecycle.transition(fresh.device, S.BOOTSTRAPPED, actor=f"{SYSTEM} (requested by {actor})"[:150], actor_kind=events.AUTOMATION,
                                 evidence={"ztp_session": fresh.pk, "observation": observation.pk, "verification_digest": digest})
    if not moved.ok:
        return ZtpResult(False, action, fresh, moved.blockers, moved.event)
    with transaction.atomic():
        fresh = models.ZtpSession.objects.select_for_update().get(pk=session.pk)
        _close(fresh, Stage.BOOTSTRAPPED, actor=actor, artifact_state=models.BootstrapArtifactState.EXPIRED)
    auth = models.BootstrapAuthorization.objects.get(pk=fresh.authorization_id)
    if auth.state == models.BootstrapAuthorizationState.APPROVED:
        authorization_service.revoke(auth, actor=SYSTEM, reason="Bootstrap completed; remaining bootstrap uses closed.")
    return ZtpResult(True, action, fresh, [], moved.event, {"verification": report.as_dict()})


# --- status (UI / API) ----------------------------------------------------------------------------------------------------------
def status(session) -> dict:
    """Every evidence stage, separately -- nothing is displayed as complete without its own record."""
    device, auth = session.device, session.authorization
    leases = list(session.lease_observations.order_by("-last_seen")[:10])
    deliveries = list(session.deliveries.order_by("-created_at")[:20])
    adapter = adapters.get(session.adapter)
    return {
        "session": session.session_id, "stage": session.stage, "adapter": session.adapter,
        "evidence_status": adapter.capability.evidence_status if adapter else "", "transport": session.transport_decision,
        "reserved_address": session.reserved_address, "network": session.network.name,
        "discovery": {"correlated": any(l.outcome == models.DhcpLeaseOutcome.CORRELATED for l in leases),
                      "leases": [{"id": l.pk, "address": l.address, "outcome": l.outcome, "code": l.code, "relay_trusted": l.relay_trusted,
                                  "upstream": f"{l.upstream_device}:{l.upstream_interface}" if l.relay_trusted else "",
                                  "seen_count": l.seen_count, "last_seen": l.last_seen.isoformat()} for l in leases]},
        "authorization": {"auth_id": auth.auth_id, "state": auth.state, "use_count": auth.use_count, "max_uses": auth.max_uses},
        "delivery": {"served": sum(1 for d in deliveries if d.outcome == "SERVED"),
                     "refused": sum(1 for d in deliveries if d.outcome == "REFUSED"),
                     "rows": [{"outcome": d.outcome, "code": d.code, "transport": d.transport, "client": d.client_address,
                               "duplicate": d.duplicate, "counted_use": d.counted_authorization_use, "at": d.created_at.isoformat()}
                              for d in deliveries]},
        "management": {"observed_host_key": session.observed_host_key, "enrolled_host_key": session.enrolled_host_key,
                       "enrolled_by": session.host_key_enrolled_by, "verified": session.stage in (Stage.MANAGEMENT_VERIFIED, Stage.BOOTSTRAPPED)},
        "native_execution": {"ztp_disabled": (session.verification or {}).get("ztp_disabled")},
        "verification": session.verification, "failure": session.failure, "attempts": session.attempts,
        "identity_state": device.identity_state, "lifecycle_state": device.lifecycle_state, "ztp_state": device.ztp_state,
        "production_admission": {"state": device.admission_state, "allowed": False, "owner_phases": [5, 6]},
    }
