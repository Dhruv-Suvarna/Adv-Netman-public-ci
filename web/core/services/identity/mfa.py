"""NMAS WEBSITE TOTP MFA (RFC 6238, Microsoft Authenticator compatible) -- separate from ALL network-device MFA.

* TOTP math: ``pyotp`` (mature library; no home-grown crypto).  30-second step, 6 digits, SHA-1 -- the parameters
  Microsoft Authenticator supports.  A verification accepts the current step +/- one (clock skew) and REJECTS any step
  at or before the last accepted one (replay).
* Seed at rest: Fernet (``cryptography``) with a key from ``NMAS_APP_MFA_KEY`` or, if unset, derived from SECRET_KEY
  with a fixed, purpose-specific HKDF info string.  Rotating SECRET_KEY without NMAS_APP_MFA_KEY therefore requires a
  re-enrollment (documented).  The seed is never logged, audited or shown after enrollment completes.
* Pending enrollment: the candidate seed lives only in the server-side session, encrypted with the same key, until the
  user proves possession with a valid code.
* Nothing here references privacyIDEA, RADIUS, DeviceLoginMfaPolicy, device credentials or the device MFA enrollment.
"""

from __future__ import annotations

import base64
import io
import re

import pyotp
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from django.conf import settings
from django.db import transaction
from django.utils import timezone

from ... import models

ISSUER = "NMAS"
STEP_SECONDS = 30
DIGITS = 6
VALID_WINDOW = 1
SESSION_PENDING_KEY = "nmas_app_mfa_pending"
SESSION_VERIFIED_KEY = "nmas_app_mfa_verified_at"
SESSION_FAILURES_KEY = "nmas_app_mfa_failures"
_HKDF_INFO = b"nmas-website-app-mfa-seed-v1"
SEED_LENGTH = 32                                 # base32 characters = 160 bits, the RFC 4226 recommended secret length
_SEED_ALPHABET = re.compile(r"[A-Z2-7]+")


class MfaError(Exception):
    """A user-facing, secret-free MFA failure."""


def _fernet() -> Fernet:
    configured = getattr(settings, "NMAS_APP_MFA_KEY", "") or ""
    if configured:
        return Fernet(configured.encode())
    derived = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=_HKDF_INFO).derive(settings.SECRET_KEY.encode())
    return Fernet(base64.urlsafe_b64encode(derived))


def _encrypt(seed: str) -> str:
    return _fernet().encrypt(seed.encode()).decode()


def _decrypt(token: str) -> str:
    try:
        return _fernet().decrypt(token.encode()).decode()
    except InvalidToken as exc:
        raise MfaError("The stored authenticator cannot be read (the MFA key changed). An administrator must reset it.") from exc


def _normalise(code: str) -> str:
    return "".join(ch for ch in (code or "") if ch.isdigit())


def device_for(user) -> models.AppMfaDevice | None:
    if not getattr(user, "is_authenticated", False):
        return None
    return models.AppMfaDevice.objects.filter(user=user, confirmed_at__isnull=False).first()


def is_enrolled(user) -> bool:
    return device_for(user) is not None


# --- enrollment ---------------------------------------------------------------------------------------------------

def begin_enrollment(session) -> str:
    """Create (or keep) a pending seed in the session and return it -- for the enrollment page ONLY."""
    pending = session.get(SESSION_PENDING_KEY)
    if pending:
        try:
            return validate_seed(_decrypt(pending))
        except MfaError:
            pass
    seed = pyotp.random_base32(length=SEED_LENGTH)
    session[SESSION_PENDING_KEY] = _encrypt(seed)
    return seed


def validate_seed(seed) -> str:
    """The seed contract: exactly SEED_LENGTH upper-case RFC 4648 base32 characters (32 is a multiple of 8, so such a
    string always decodes without padding).  The error never contains the value (a seed is a secret)."""
    if not isinstance(seed, str) or len(seed) != SEED_LENGTH or not _SEED_ALPHABET.fullmatch(seed):
        raise MfaError(f"The authenticator seed is invalid (expected {SEED_LENGTH} base32 characters).")
    return seed


def provisioning_uri(user, seed: str) -> str:
    """otpauth:// URI for the enrollment QR code.  Refuses (MfaError) an invalid seed or a value that is not a user."""
    validate_seed(seed)
    if not callable(getattr(user, "get_username", None)) or not getattr(user, "is_authenticated", False):
        raise MfaError("An authenticated user is required to enroll an authenticator.")
    return pyotp.TOTP(seed, digits=DIGITS, interval=STEP_SECONDS).provisioning_uri(name=user.get_username(), issuer_name=ISSUER)


def qr_svg_data_uri(uri: str) -> str:
    """An inline SVG data URI rendered in memory (never written to disk, never logged)."""
    import segno

    buffer = io.BytesIO()
    segno.make(uri, error="m").save(buffer, kind="svg", scale=5, border=2, dark="#000", light="#fff")
    return "data:image/svg+xml;base64," + base64.b64encode(buffer.getvalue()).decode()


def _matching_step(seed: str, code: str, *, after_step: int | None) -> int | None:
    code = _normalise(code)
    if len(code) != DIGITS:
        return None
    totp = pyotp.TOTP(seed, digits=DIGITS, interval=STEP_SECONDS)
    now = timezone.now()
    current = totp.timecode(now)
    for offset in range(-VALID_WINDOW, VALID_WINDOW + 1):
        step = current + offset
        if after_step is not None and step <= after_step:
            continue
        if pyotp.utils.strings_equal(totp.generate_otp(step), code):
            return step
    return None


def complete_enrollment(user, session, code: str) -> models.AppMfaDevice:
    pending = session.get(SESSION_PENDING_KEY)
    if not pending:
        raise MfaError("No enrollment is in progress. Reload the enrollment page.")
    if is_enrolled(user):
        raise MfaError("An authenticator is already enrolled. An administrator must reset it first.")
    seed = _decrypt(pending)
    step = _matching_step(seed, code, after_step=None)
    if step is None:
        raise MfaError("That code is not valid. Check the authenticator app's clock and try the current code.")
    now = timezone.now()
    with transaction.atomic():
        models.AppMfaDevice.objects.filter(user=user).delete()
        device = models.AppMfaDevice.objects.create(
            user=user, encrypted_seed=_encrypt(seed), confirmed_at=now, last_used_step=step, last_verified_at=now
        )
    session.pop(SESSION_PENDING_KEY, None)
    return device


# --- verification ------------------------------------------------------------------------------------------------

def verify(user, code: str) -> bool:
    """True when ``code`` is a fresh valid code for the user's confirmed authenticator (replay-safe, row-locked)."""
    with transaction.atomic():
        device = models.AppMfaDevice.objects.select_for_update().filter(user=user, confirmed_at__isnull=False).first()
        if device is None:
            raise MfaError("No website authenticator is enrolled for this account.")
        step = _matching_step(_decrypt(device.encrypted_seed), code, after_step=device.last_used_step)
        if step is None:
            return False
        device.last_used_step = step
        device.last_verified_at = timezone.now()
        device.save(update_fields=["last_used_step", "last_verified_at"])
        return True


def mark_session_verified(session) -> None:
    session[SESSION_VERIFIED_KEY] = timezone.now().isoformat()
    session.pop(SESSION_FAILURES_KEY, None)


def session_verified(session) -> bool:
    return bool(session.get(SESSION_VERIFIED_KEY))


def register_failure(session) -> int:
    failures = int(session.get(SESSION_FAILURES_KEY, 0)) + 1
    session[SESSION_FAILURES_KEY] = failures
    return failures


def reset(user) -> bool:
    """Administrative reset: remove the user's website authenticator (they must re-enroll at next login)."""
    deleted, _ = models.AppMfaDevice.objects.filter(user=user).delete()
    return bool(deleted)
