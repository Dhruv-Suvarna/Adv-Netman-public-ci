"""Governed replacement and retirement of a device's bootstrap (ZTP enrollment) credential  (``BCRED-000001``).

A natively onboarded device is reachable with the per-session enrollment key (account ``nmas-enroll``).  That key is a
bootstrap credential: it must be replaced by the device's operational SERVICE credential and then retired -- revoked on the
device, PROVEN rejected by the device, and only then removed from the protected provider.  Deleting the private-key file
alone never counts as retirement.

Order (each step is recorded; ``execute`` resumes from the recorded state and is idempotent):

    PLANNED --approve (different operator, digest-bound)--> APPROVED
    APPROVED              preflight over the bootstrap session; install the replacement account + key (configure session)
                          -> REPLACEMENT_INSTALLED                       (install failure -> FAILED, bootstrap intact)
    REPLACEMENT_INSTALLED verify the replacement over a NEW, independent session (pinned host key, its own key only)
                          -> REPLACEMENT_VERIFIED                         (failure -> replacement removed -> FAILED)
    REPLACEMENT_VERIFIED  over the REPLACEMENT session: ``no username <bootstrap>`` with ``commit timer`` (the device
                          restores the bootstrap account by itself unless NMAS confirms)  -> REVOCATION_PENDING
    REVOCATION_PENDING    prove: running-config has no bootstrap account AND the bootstrap key is REJECTED; then confirm the
                          commit and re-prove -> RETIREMENT_PENDING      (bootstrap still accepted -> stays, never confirmed)
    RETIREMENT_PENDING    retire the enrollment secret in the provider and prove it is gone -> COMPLETE

The bootstrap credential is never removed before the replacement is verified; the replacement must be a key-only SERVICE
account (never a human / MFA credential).  Implemented for Arista EOS only; every other platform is refused with
BCRED_PLATFORM_NOT_IMPLEMENTED.  No secret, private key or password is ever stored, logged or returned.
"""

from __future__ import annotations

import hashlib
import json
import secrets
from dataclasses import dataclass, field

from django.db import IntegrityError, transaction
from django.utils import timezone

from ... import models
from ..devices import codes, events, identity
from . import guard, resolve, ssh

S = models.BootstrapCredentialState
Outcome = models.DeviceLifecycleEventOutcome
SUPPORTED_PLATFORMS = frozenset({models.Platform.ARISTA_CEOS.value})
RESERVED_USERNAMES = frozenset({"nmas-enroll", "root", "admin", "cvpadmin"})
COMMIT_TIMER = "00:10:00"
MAX_STEPS = 40


@dataclass
class Result:
    ok: bool
    action: str
    blockers: list = field(default_factory=list)
    transition: object | None = None
    event: object | None = None

    @property
    def codes(self) -> list[str]:
        return codes.codes(self.blockers)


# --- helpers ----------------------------------------------------------------------------------------------------------------------
def _digest(**fields) -> str:
    return hashlib.sha256(json.dumps(fields, sort_keys=True, default=str).encode()).hexdigest()


def _refuse(device, action, blockers, *, actor, transition=None):
    with transaction.atomic():
        event = events.record(device, action, Outcome.REFUSED, actor=actor, from_state=device.lifecycle_state, blockers=blockers,
                              evidence={"transition": transition.transition_id} if transition else {})
    return Result(False, action, list(blockers), transition=transition, event=event)


def bootstrap_session(device):
    """The device's verified enrollment session (closed BOOTSTRAPPED, host key enrolled), or None."""
    return (models.ZtpSession.objects.filter(device=device, stage=models.ZtpSessionStage.BOOTSTRAPPED)
            .exclude(enrolled_host_key="").exclude(enrollment_key_ref="").order_by("-created_at", "-id").first())


def _bootstrap_secret_present(session) -> bool:
    from modules.device_credentials import SecretProviderError

    from ..ztp import management as ztp_management

    try:
        ztp_management.secret_provider().current(session.enrollment_key_ref)
        return True
    except SecretProviderError:
        return False


def _replacement_problems(device, credential) -> list[dict]:
    if credential is None or credential.device_name != device.name:
        return [codes.blocker("BCRED_REPLACEMENT_INVALID", reason="not a credential of this device")]
    if credential.account_kind == models.AccountKind.HUMAN or credential.auth_method == models.DeviceAuthMethod.PASSWORD_AND_TOTP:
        return [codes.blocker("BCRED_REPLACEMENT_HUMAN")]
    if credential.account_kind != models.AccountKind.SERVICE or credential.auth_method != models.DeviceAuthMethod.PUBLICKEY \
            or not credential.ssh_key_ref or not credential.ssh_public_key or not credential.ssh_public_key_fingerprint:
        return [codes.blocker("BCRED_REPLACEMENT_INVALID", reason="a key-only SERVICE credential with an enrolled public key is required")]
    if credential.username.lower() in RESERVED_USERNAMES:
        return [codes.blocker("BCRED_RESERVED_USERNAME", username=credential.username)]
    if not models.HOST_KEY_RE.fullmatch(credential.ssh_public_key_fingerprint):
        return [codes.blocker("BCRED_REPLACEMENT_INVALID", reason="the public-key fingerprint is not an OpenSSH SHA256 fingerprint")]
    return []


def _binding(device, session, credential, path) -> str:
    return _digest(device=device.device_id, session=session.session_id, bootstrap_user=session_username(),
                   bootstrap_fp=session.enrollment_key_fingerprint, replacement=credential.pk, replacement_user=credential.username,
                   replacement_fp=credential.ssh_public_key_fingerprint, path=path.path_id if path else "")


def session_username() -> str:
    from ..ztp.workflow import ENROLLMENT_USER

    return ENROLLMENT_USER


# --- plan / approve / cancel -----------------------------------------------------------------------------------------------------
def plan(device, *, replacement_credential_id, actor: str, path_id=None, reason: str = "") -> Result:
    action = "BCRED_PLAN"
    text, problems = identity.clean_text(reason, max_length=200)
    if problems:
        return _refuse(device, action, problems, actor=actor)
    if device.platform not in SUPPORTED_PLATFORMS:
        return _refuse(device, action, [codes.blocker("BCRED_PLATFORM_NOT_IMPLEMENTED", platform=device.platform)], actor=actor)
    session = bootstrap_session(device)
    if session is None or not _bootstrap_secret_present(session):
        return _refuse(device, action, [codes.blocker("BCRED_NO_BOOTSTRAP")], actor=actor)
    credential = models.DeviceCredential.objects.filter(pk=replacement_credential_id).first()
    blockers = _replacement_problems(device, credential)
    path = None
    if path_id is not None:
        path = models.ManagementPath.objects.filter(pk=path_id, device=device, approval_state=models.ManagementApproval.APPROVED).first()
        if path is None or path.credential_source != models.ManagementCredentialSource.DEVICE_CREDENTIAL \
                or path.device_credential_id != getattr(credential, "pk", None):
            blockers.append(codes.blocker("BCRED_REPLACEMENT_INVALID", reason="the path must be APPROVED and use the replacement credential"))
        elif path.expected_host_key != session.enrolled_host_key:
            blockers.append(codes.blocker("L5_HOST_KEY_MISMATCH", reason="the path's pinned host key differs from the enrolled one"))
    selected = resolve.endpoint(device.name, purpose=resolve.WRITE)
    if selected.source == resolve.BLOCKED:
        blockers.extend(selected.blockers)
    elif (selected.source == resolve.PATH and (path is None or path.path_id != selected.path_id)) \
            or (selected.source == resolve.LEGACY and path is not None):
        blockers.append(codes.blocker("MGMT_NO_USABLE_PATH", reason="retirement must use the selected write path"))
    if models.ManagementPath.objects.filter(device=device, credential_source=models.ManagementCredentialSource.ZTP_ENROLLMENT) \
            .exclude(approval_state=models.ManagementApproval.REVOKED).exists():
        blockers.append(codes.blocker("BCRED_PREFLIGHT_FAILED", reason="a management path still uses the bootstrap credential; "
                                      "revoke it and register a path with the replacement credential first"))
    if models.BootstrapCredentialTransition.objects.filter(device=device, state__in=models.BOOTSTRAP_CREDENTIAL_OPEN).exists():
        blockers.append(codes.blocker("BCRED_OPEN_EXISTS"))
    if blockers:
        return _refuse(device, action, blockers, actor=actor)
    try:
        with transaction.atomic():
            row = models.BootstrapCredentialTransition.objects.create(
                device=device, ztp_session=session, bootstrap_username=session_username(),
                bootstrap_key_reference=session.enrollment_key_ref, bootstrap_key_fingerprint=session.enrollment_key_fingerprint,
                replacement_credential=credential, replacement_username=credential.username,
                replacement_key_fingerprint=credential.ssh_public_key_fingerprint, path=path,
                binding_digest=_binding(device, session, credential, path), requested_by=actor[:150], reason=text)
            event = events.record(device, action, Outcome.RECORDED, actor=actor, from_state=device.lifecycle_state,
                                  to_state=device.lifecycle_state,
                                  evidence={"transition": row.transition_id, "replacement_user": row.replacement_username,
                                            "replacement_fp": row.replacement_key_fingerprint, "digest": row.binding_digest})
    except IntegrityError:
        return _refuse(device, action, [codes.blocker("BCRED_OPEN_EXISTS")], actor=actor)
    return Result(True, action, transition=row, event=event)


def approve(transition, *, actor: str, digest: str) -> Result:
    action = "BCRED_APPROVE"
    device = transition.device
    if transition.state != S.PLANNED:
        return _refuse(device, action, [codes.blocker("BCRED_STATE_INVALID", state=transition.state)], actor=actor, transition=transition)
    if actor == transition.requested_by:
        return _refuse(device, action, [codes.blocker("BCRED_SELF_APPROVAL")], actor=actor, transition=transition)
    credential = transition.replacement_credential
    current = _binding(device, transition.ztp_session, credential, transition.path)
    if digest != transition.binding_digest or current != transition.binding_digest:
        return _refuse(device, action, [codes.blocker("BCRED_DIGEST_MISMATCH")], actor=actor, transition=transition)
    with transaction.atomic():
        locked = models.BootstrapCredentialTransition.objects.select_for_update().get(pk=transition.pk)
        if locked.state != S.PLANNED:
            return _refuse(device, action, [codes.blocker("BCRED_STATE_INVALID", state=locked.state)], actor=actor, transition=locked)
        locked.state, locked.approved_by, locked.approved_at, locked.version = S.APPROVED, actor[:150], timezone.now(), locked.version + 1
        locked.save(update_fields=["state", "approved_by", "approved_at", "version", "updated_at"])
        event = events.record(device, action, Outcome.RECORDED, actor=actor, from_state=device.lifecycle_state, to_state=device.lifecycle_state,
                              evidence={"transition": locked.transition_id, "digest": locked.binding_digest})
    return Result(True, action, transition=locked, event=event)


def cancel(transition, *, actor: str, reason: str) -> Result:
    action = "BCRED_CANCEL"
    device = transition.device
    text, problems = identity.clean_text(reason, max_length=200)
    if problems or not text:
        return _refuse(device, action, problems or [codes.blocker("REASON_REQUIRED")], actor=actor, transition=transition)
    with transaction.atomic():
        locked = models.BootstrapCredentialTransition.objects.select_for_update().get(pk=transition.pk)
        if locked.state not in (S.PLANNED, S.APPROVED) or locked.executed_by:
            return _refuse(device, action, [codes.blocker("BCRED_STATE_INVALID", state=locked.state)], actor=actor, transition=locked)
        locked.state, locked.reason, locked.version = S.CANCELLED, text, locked.version + 1
        locked.save(update_fields=["state", "reason", "version", "updated_at"])
        event = events.record(device, action, Outcome.RECORDED, actor=actor, from_state=device.lifecycle_state, to_state=device.lifecycle_state,
                              evidence={"transition": locked.transition_id})
    return Result(True, action, transition=locked, event=event)


# --- execution -----------------------------------------------------------------------------------------------------------------------
class _Keys:
    """In-memory private keys, loaded from the protected providers at use time (never stored)."""

    @staticmethod
    def bootstrap(transition):
        from ..ztp import management as ztp_management

        return ztp_management.load_private_key(transition.bootstrap_key_reference)

    @staticmethod
    def replacement(transition):
        from modules.device_credentials import load_ssh_private_key

        return load_ssh_private_key(transition.replacement_credential.ssh_key_ref)


def target(transition) -> tuple[str, int, str]:
    """(address, port, pinned host key): the approved replacement path if named, else the enrollment session's address."""
    session = transition.ztp_session
    if transition.path_id:
        path = transition.path
        return path.endpoint_address, path.port, session.enrolled_host_key
    return session.reserved_address, 22, session.enrolled_host_key


def _record_step(transition, step: str, ok: bool, *, code: str = "", facts: dict | None = None, state: str | None = None,
                 actor: str, failure: dict | None = None):
    with transaction.atomic():
        locked = models.BootstrapCredentialTransition.objects.select_for_update().get(pk=transition.pk)
        row = {"step": step, "ok": bool(ok), "code": code, "at": timezone.now().isoformat(), "facts": dict(facts or {})}
        locked.steps = [*(locked.steps or []), row][-MAX_STEPS:]
        before = locked.state
        if state:
            locked.state = state
        if failure is not None:
            locked.failure = failure
        if state == S.COMPLETE:
            locked.completed_at = timezone.now()
        locked.executed_by = actor[:150]
        locked.version += 1
        locked.save(update_fields=["steps", "state", "failure", "completed_at", "executed_by", "version", "updated_at"])
        name = "BCRED_COMPLETE" if state == S.COMPLETE else "BCRED_FAILED" if not ok and state in (S.FAILED, S.UNCERTAIN) else "BCRED_STEP"
        device = locked.device
        events.record(device, name, Outcome.RECORDED if ok else Outcome.REFUSED, actor=actor, actor_kind=events.AUTOMATION,
                      from_state=device.lifecycle_state, to_state=device.lifecycle_state,
                      blockers=[codes.blocker(code)] if code in codes.BLOCKERS else [],
                      evidence={"transition": locked.transition_id, "step": step, "ok": bool(ok), "code": code,
                                "from": before, "to": locked.state, **{k: v for k, v in (facts or {}).items() if k != "detail"}})
    transition.refresh_from_db()
    return transition


def _key_installed(text: str, username: str, public_key: str) -> bool:
    blob = public_key.split()[1] if len(public_key.split()) > 1 else ""
    return bool(blob) and any(line.strip().startswith(f"username {username} ") and "ssh-key" in line and blob in line
                              for line in text.splitlines())


def _account_present(text: str, username: str) -> bool:
    return any(line.strip().startswith(f"username {username} ") or line.strip() == f"username {username}" for line in text.splitlines())


USERS = "show running-config section username"


def _open(connect, transition, kind: str, keys):
    selected = resolve.endpoint(transition.device.name, purpose=resolve.WRITE)
    if selected.source == resolve.BLOCKED or (transition.path_id and
            (selected.source != resolve.PATH or selected.path_id != transition.path.path_id)) or (
            not transition.path_id and selected.source != resolve.LEGACY):
        raise ssh.CliError("UNREACHABLE", "selected write path changed")
    address, port, host_key = target(transition)
    pkey = keys.bootstrap(transition) if kind == "bootstrap" else keys.replacement(transition)
    username = transition.bootstrap_username if kind == "bootstrap" else transition.replacement_username
    kwargs = {"address": address, "port": port, "username": username, "pkey": pkey, "expected_host_key": host_key}
    if transition.path_id and connect is ssh.connect:
        from . import ssh_transport

        path, problems = guard.authorized_target(transition.path)
        if problems or path is None or path.nmas_attachment.verification_state != models.AttachmentVerification.VERIFIED:
            raise ssh.CliError("UNREACHABLE", "management path no longer approved or verified")
        if path.expected_host_key != host_key:
            raise ssh.CliError("HOST_KEY_MISMATCH", "path pin differs from enrollment pin")
        try:
            kwargs["sock"] = ssh_transport.bound_socket(path, ssh.CONNECT_TIMEOUT)
        except ssh_transport.ManagedConnectionRejected as exc:
            raise ssh.CliError("UNREACHABLE", exc.args[0]) from None
    return connect(**kwargs)


def execute(transition, *, actor: str, connect=ssh.connect, keys=_Keys, provider=None) -> Result:
    """Run (or resume) the transition from its recorded state until COMPLETE or a recorded stop."""
    from ..execution.device_mutex import DeviceBusy, DeviceMutex

    try:
        with DeviceMutex([transition.device.name], bootstrap_transition=transition.pk):
            transition.refresh_from_db()
            return _execute(transition, actor=actor, connect=connect, keys=keys, provider=provider)
    except DeviceBusy:
        return _refuse(transition.device, "BCRED_EXECUTE", [codes.blocker("MGMT_EXECUTION_IN_FLIGHT")], actor=actor, transition=transition)


def _execute(transition, *, actor, connect, keys, provider):
    action = "BCRED_EXECUTE"
    device = transition.device
    if transition.state not in (S.APPROVED, S.REPLACEMENT_INSTALLED, S.REPLACEMENT_VERIFIED, S.REVOCATION_PENDING,
                                S.RETIREMENT_PENDING, S.UNCERTAIN):
        return _refuse(device, action, [codes.blocker("BCRED_STATE_INVALID", state=transition.state)], actor=actor, transition=transition)
    if not transition.approved_by:
        return _refuse(device, action, [codes.blocker("BCRED_STATE_INVALID", state="UNAPPROVED")], actor=actor, transition=transition)
    if models.ExecutionDeviceLock.objects.filter(device=device.name).exists():
        return _refuse(device, action, [codes.blocker("MGMT_EXECUTION_IN_FLIGHT")], actor=actor, transition=transition)
    selected = resolve.endpoint(device.name, purpose=resolve.WRITE)
    if selected.source == resolve.BLOCKED:
        return _refuse(device, action, list(selected.blockers), actor=actor, transition=transition)
    if (transition.path_id and (selected.source != resolve.PATH or selected.path_id != transition.path.path_id)) or (
            not transition.path_id and selected.source != resolve.LEGACY):
        return _refuse(device, action, [codes.blocker("MGMT_NO_USABLE_PATH", reason="selected write path changed")],
                       actor=actor, transition=transition)
    address, _port, _key = target(transition)
    problems = guard.address_problems(address)
    if problems:
        return _refuse(device, action, problems, actor=actor, transition=transition)
    if _binding(device, transition.ztp_session, transition.replacement_credential, transition.path) != transition.binding_digest:
        return _refuse(device, action, [codes.blocker("BCRED_DIGEST_MISMATCH")], actor=actor, transition=transition)
    if not transition.executed_by:
        _record_step(transition, "execution_started", True, actor=actor)
    for _round in range(8):
        state = transition.state
        if state == S.COMPLETE:
            return Result(True, action, transition=transition)
        if state in (S.FAILED, S.CANCELLED):
            return Result(False, action, [codes.blocker((transition.failure or {}).get("code") or "BCRED_STATE_INVALID")], transition=transition)
        step = {S.APPROVED: _install, S.REPLACEMENT_INSTALLED: _verify_replacement, S.REPLACEMENT_VERIFIED: _revoke,
                S.REVOCATION_PENDING: _prove_and_confirm, S.RETIREMENT_PENDING: _retire, S.UNCERTAIN: _reconcile}[state]
        stop = step(transition, actor=actor, connect=connect, keys=keys, provider=provider)
        transition.refresh_from_db()
        if stop:
            return Result(False, action, [codes.blocker(stop)], transition=transition)
    return Result(False, action, [codes.blocker("BCRED_STATE_INVALID", state=transition.state)], transition=transition)


def _session_name(transition, kind: str) -> str:
    # EOS refuses to re-enter a completed session name ("already completed"), so the name carries the transition's own
    # binding digest as well as its row id: a reset or restored NMAS database never collides with a session already on the device
    return f"nmas-bcred-{transition.pk}-{transition.binding_digest[:8]}-{kind}"


def _install(transition, *, actor, connect, keys, provider):
    credential = transition.replacement_credential
    try:
        cli = _open(connect, transition, "bootstrap", keys)
    except ssh.CliError as exc:
        _record_step(transition, "preflight", False, code="BCRED_PREFLIGHT_FAILED", facts={"transport": exc.code}, state=S.FAILED,
                     actor=actor, failure={"code": "BCRED_PREFLIGHT_FAILED", "transport": exc.code, "bootstrap_intact": True})
        return "BCRED_PREFLIGHT_FAILED"
    try:
        users = cli.show(USERS)
        if not _account_present(users, transition.bootstrap_username):
            _record_step(transition, "preflight", False, code="BCRED_PREFLIGHT_FAILED", facts={"bootstrap_account": False},
                         state=S.FAILED, actor=actor, failure={"code": "BCRED_PREFLIGHT_FAILED", "reason": "bootstrap account not configured"})
            return "BCRED_PREFLIGHT_FAILED"
        if _key_installed(users, credential.username, credential.ssh_public_key):
            _record_step(transition, "install", True, facts={"action": "ALREADY_PRESENT"}, state=S.REPLACEMENT_INSTALLED, actor=actor)
            return ""
        if _account_present(users, credential.username):
            # an existing account of that name with another key: NMAS would MODIFY an account it does not own -- refuse
            _record_step(transition, "preflight", False, code="BCRED_PREFLIGHT_FAILED", facts={"replacement_account_exists": True},
                         state=S.FAILED, actor=actor, failure={"code": "BCRED_PREFLIGHT_FAILED", "reason": "the replacement account already exists"})
            return "BCRED_PREFLIGHT_FAILED"
        _record_step(transition, "preflight", True, facts={"bootstrap_account": True, "replacement_account": False}, actor=actor)
        role = credential.account_role or "network-admin"
        privilege = credential.privilege_level or 15
        unusable = secrets.token_urlsafe(32)          # an unrecoverable password: the account is usable by its key only
        lines = [f"configure session {_session_name(transition, 'install')}",
                 f"username {credential.username} privilege {privilege} role {role} secret {unusable}",
                 f"username {credential.username} ssh-key {credential.ssh_public_key.strip()}",
                 "commit"]
        del unusable
        _record_step(transition, "before_install", True, state=S.UNCERTAIN, actor=actor)
        try:
            cli.configure(lines)
        except ssh.CliError as exc:
            _record_step(transition, "install", False, code="BCRED_INSTALL_FAILED", facts={"transport": exc.code}, state=S.UNCERTAIN,
                         actor=actor, failure={"code": "BCRED_INSTALL_FAILED", "transport": exc.code})
            return "BCRED_INSTALL_FAILED"
        finally:
            lines.clear()                          # drop the only copy of the unusable password
        _record_step(transition, "install", True, facts={"action": "INSTALLED", "username": credential.username}, state=S.REPLACEMENT_INSTALLED,
                     actor=actor)
        return ""
    finally:
        cli.close()


def _verify_replacement(transition, *, actor, connect, keys, provider):
    credential = transition.replacement_credential
    try:
        cli = _open(connect, transition, "replacement", keys)
    except ssh.CliError as exc:
        return _undo_replacement(transition, actor=actor, connect=connect, keys=keys, reason=exc.code)
    try:
        users = cli.show(USERS)
        ok = _key_installed(users, credential.username, credential.ssh_public_key) and _account_present(users, transition.bootstrap_username)
    except ssh.CliError as exc:
        ok, users = False, exc.code
    finally:
        cli.close()
    if not ok:
        return _undo_replacement(transition, actor=actor, connect=connect, keys=keys, reason="CONFIG_MISMATCH")
    _record_step(transition, "verify_replacement", True, facts={"independent_session": True, "host_key_pinned": True},
                 state=S.REPLACEMENT_VERIFIED, actor=actor)
    return ""


def _undo_replacement(transition, *, actor, connect, keys, reason):
    """The replacement did not verify: remove it over the bootstrap session (still intact) and fail safely."""
    try:
        cli = _open(connect, transition, "bootstrap", keys)
        try:
            _record_step(transition, "before_undo", True, state=S.UNCERTAIN, actor=actor)
            cli.configure([f"configure session {_session_name(transition, 'undo')}", f"no username {transition.replacement_username}", "commit"])
            gone = not _account_present(cli.show(USERS), transition.replacement_username)
        finally:
            cli.close()
    except ssh.CliError as exc:
        _record_step(transition, "verify_replacement", False, code="BCRED_REPLACEMENT_UNVERIFIED", facts={"reason": reason, "undo": exc.code},
                     state=S.UNCERTAIN, actor=actor, failure={"code": "BCRED_REPLACEMENT_UNVERIFIED", "undo": "FAILED"})
        return "BCRED_REPLACEMENT_UNVERIFIED"
    state = S.FAILED if gone else S.UNCERTAIN
    _record_step(transition, "verify_replacement", False, code="BCRED_REPLACEMENT_UNVERIFIED", facts={"reason": reason, "replacement_removed": gone},
                 state=state, actor=actor, failure={"code": "BCRED_REPLACEMENT_UNVERIFIED", "replacement_removed": gone, "bootstrap_intact": True})
    return "BCRED_REPLACEMENT_UNVERIFIED"


def _revoke(transition, *, actor, connect, keys, provider):
    try:
        cli = _open(connect, transition, "replacement", keys)
    except ssh.CliError as exc:
        _record_step(transition, "revoke", False, code="BCRED_REVOCATION_FAILED", facts={"transport": exc.code}, actor=actor,
                     failure={"code": "BCRED_REVOCATION_FAILED", "transport": exc.code, "sent": False})
        return "BCRED_REVOCATION_FAILED"
    try:
        _record_step(transition, "before_revoke", True, state=S.UNCERTAIN, actor=actor)
        cli.configure([f"configure session {_session_name(transition, 'revoke')}", f"no username {transition.bootstrap_username}",
                       f"commit timer {COMMIT_TIMER}"])
    except ssh.CliError as exc:
        _record_step(transition, "revoke", False, code="BCRED_REVOCATION_FAILED", facts={"transport": exc.code}, state=S.UNCERTAIN,
                     actor=actor, failure={"code": "BCRED_REVOCATION_FAILED", "transport": exc.code, "sent": True})
        return "BCRED_REVOCATION_FAILED"
    finally:
        cli.close()
    _record_step(transition, "revoke", True, facts={"commit_timer": COMMIT_TIMER, "confirmed": False}, state=S.REVOCATION_PENDING, actor=actor)
    return ""


def _bootstrap_rejected(transition, *, connect, keys) -> str:
    """'' when the device REJECTS the bootstrap key (proof); else the observed code (ACCEPTED / UNREACHABLE / ...)."""
    try:
        cli = _open(connect, transition, "bootstrap", keys)
    except ssh.CliError as exc:
        return "" if exc.code == "AUTH_FAILED" else exc.code
    cli.close()
    return "ACCEPTED"


def _prove_and_confirm(transition, *, actor, connect, keys, provider):
    try:
        cli = _open(connect, transition, "replacement", keys)
    except ssh.CliError as exc:
        _record_step(transition, "prove_revocation", False, code="BCRED_REVOCATION_FAILED", facts={"transport": exc.code}, actor=actor,
                     failure={"code": "BCRED_REVOCATION_FAILED", "transport": exc.code})
        return "BCRED_REVOCATION_FAILED"
    try:
        absent = not _account_present(cli.show(USERS), transition.bootstrap_username)
        rejected = _bootstrap_rejected(transition, connect=connect, keys=keys) if absent else "NOT_REVOKED"
        if not absent or rejected:
            code = "BCRED_BOOTSTRAP_STILL_ACCEPTED" if rejected == "ACCEPTED" else "BCRED_REVOCATION_FAILED"
            facts = {"account_absent": absent, "bootstrap_auth": rejected or "REJECTED"}
            if not absent:
                # the staged removal never took effect (live finding: a commit cut short leaves the session pending with
                # ``no username`` staged); abort it so nobody can commit a half-run revocation later.  Rolling back restores
                # the account, so the bootstrap credential stays intact either way.
                try:
                    cli.configure([f"configure session {_session_name(transition, 'revoke')} abort"])
                    facts["uncommitted_session"] = "ABORTED"
                except ssh.CliError as exc:
                    facts["uncommitted_session"] = f"ABORT_FAILED:{exc.code}"
            _record_step(transition, "prove_revocation", False, code=code, facts=facts,
                         actor=actor, failure={"code": code, "confirmed": False,
                                               "note": "the commit was NOT confirmed; the device restores the bootstrap account when the timer expires"})
            return code
        cli.configure([f"configure session {_session_name(transition, 'revoke')} commit"])
        still_absent = not _account_present(cli.show(USERS), transition.bootstrap_username)
    except ssh.CliError as exc:
        _record_step(transition, "confirm_revocation", False, code="BCRED_REVOCATION_FAILED", facts={"transport": exc.code},
                     state=S.UNCERTAIN, actor=actor, failure={"code": "BCRED_REVOCATION_FAILED", "transport": exc.code})
        return "BCRED_REVOCATION_FAILED"
    finally:
        cli.close()
    rejected_after = _bootstrap_rejected(transition, connect=connect, keys=keys)
    if not still_absent or rejected_after:
        _record_step(transition, "confirm_revocation", False, code="BCRED_REVOCATION_FAILED",
                     facts={"account_absent": still_absent, "bootstrap_auth": rejected_after or "REJECTED"}, state=S.UNCERTAIN, actor=actor,
                     failure={"code": "BCRED_REVOCATION_FAILED", "confirmed": True})
        return "BCRED_REVOCATION_FAILED"
    _record_step(transition, "confirm_revocation", True, facts={"account_absent": True, "bootstrap_auth": "REJECTED", "confirmed": True},
                 state=S.RETIREMENT_PENDING, actor=actor)
    return ""


def _retire(transition, *, actor, connect, keys, provider):
    from modules.device_credentials import SecretNotFound, SecretProviderError

    from ..ztp import management as ztp_management

    store = provider or ztp_management.secret_provider()
    try:
        try:
            version = store.current(transition.bootstrap_key_reference).version
            store.retire(transition.bootstrap_key_reference, version)
        except SecretNotFound:
            pass                                   # already retired by an interrupted earlier attempt: prove it below
        try:
            store.current(transition.bootstrap_key_reference)
            gone = False
        except SecretNotFound:
            gone = True
    except SecretProviderError as exc:
        _record_step(transition, "retire_secret", False, code="BCRED_RETIREMENT_FAILED", facts={"provider": type(exc).__name__}, actor=actor,
                     failure={"code": "BCRED_RETIREMENT_FAILED"})
        return "BCRED_RETIREMENT_FAILED"
    if not gone:
        _record_step(transition, "retire_secret", False, code="BCRED_RETIREMENT_FAILED", facts={"still_present": True}, actor=actor,
                     failure={"code": "BCRED_RETIREMENT_FAILED"})
        return "BCRED_RETIREMENT_FAILED"
    _record_step(transition, "retire_secret", True, facts={"provider_record": "ABSENT"}, state=S.COMPLETE, actor=actor, failure={})
    return ""


def _reconcile(transition, *, actor, connect, keys, provider):
    """UNCERTAIN: read the device and move to the state it proves.  Never guesses."""
    facts: dict = {}
    try:
        cli = _open(connect, transition, "replacement", keys)
        try:
            users = cli.show(USERS)
        finally:
            cli.close()
        facts["replacement_works"] = True
    except ssh.CliError as exc:
        users, facts["replacement_works"] = "", exc.code
    bootstrap = _bootstrap_rejected(transition, connect=connect, keys=keys)
    facts["bootstrap_auth"] = bootstrap or "REJECTED"
    if facts["replacement_works"] is True:
        installed = _key_installed(users, transition.replacement_username, transition.replacement_credential.ssh_public_key)
        if installed and bootstrap == "ACCEPTED":
            state = S.REPLACEMENT_VERIFIED if _account_present(users, transition.bootstrap_username) else None
        elif installed and not bootstrap and not _account_present(users, transition.bootstrap_username):
            state = S.REVOCATION_PENDING           # revoked and rejected; the confirm step re-proves and confirms
        else:
            state = None
    elif bootstrap == "ACCEPTED":
        state = S.APPROVED                         # replacement absent / not working; bootstrap intact: install again
    else:
        state = None
    if state is None:
        _record_step(transition, "reconcile", False, code="BCRED_REVOCATION_FAILED", facts=facts, actor=actor)
        return "BCRED_REVOCATION_FAILED"
    _record_step(transition, "reconcile", True, facts=facts, state=state, actor=actor)
    return ""


def status(transition) -> dict:
    return {"id": transition.transition_id, "device": transition.device.name, "state": transition.state,
            "bootstrap_username": transition.bootstrap_username, "bootstrap_key_fingerprint": transition.bootstrap_key_fingerprint,
            "replacement_username": transition.replacement_username, "replacement_key_fingerprint": transition.replacement_key_fingerprint,
            "path": transition.path.path_id if transition.path_id else "", "digest": transition.binding_digest,
            "requested_by": transition.requested_by, "approved_by": transition.approved_by, "executed_by": transition.executed_by,
            "steps": list(transition.steps or []), "failure": dict(transition.failure or {}),
            "complete": transition.state == S.COMPLETE}
