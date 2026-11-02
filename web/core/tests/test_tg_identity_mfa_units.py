"""Lab 7 -- website TOTP MFA (core.services.identity.mfa), each public function called directly, positive + negative.

POSITIVE: the enrollment / verification / session helpers accept a valid code and record the right state.
NEGATIVE: a wrong code, a replayed code, a non-digit / wrong-length code, no enrollment in progress, a second enrollment,
an anonymous user, an unreadable stored seed (key changed) and a reset of a user with no authenticator are all refused
without leaking the seed.  Website MFA only -- nothing here touches device credentials, privacyIDEA or RADIUS.
"""

from __future__ import annotations

from unittest import mock

import pyotp
from django.contrib.auth import get_user_model
from django.contrib.auth.models import AnonymousUser
from django.test import TestCase
from django.utils import timezone

from core import models
from core.services.identity import mfa


def _code(seed: str, offset: int = 0) -> str:
    totp = pyotp.TOTP(seed, digits=mfa.DIGITS, interval=mfa.STEP_SECONDS)
    return totp.generate_otp(totp.timecode(timezone.now()) + offset)


class MfaUnitTests(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user("mfa-unit", password="pw-unit-123456")
        self.session: dict = {}

    def _enroll(self) -> tuple[str, models.AppMfaDevice]:
        seed = mfa.begin_enrollment(self.session)
        return seed, mfa.complete_enrollment(self.user, self.session, _code(seed))

    # -- enrollment -----------------------------------------------------------------------------------------
    def test_begin_enrollment_returns_a_stable_pending_seed(self):
        seed = mfa.begin_enrollment(self.session)
        self.assertEqual(len(seed), 32)
        self.assertNotIn(seed, self.session[mfa.SESSION_PENDING_KEY])           # encrypted at rest in the session
        self.assertEqual(mfa.begin_enrollment(self.session), seed)

    def test_begin_enrollment_replaces_an_unreadable_pending_seed(self):
        self.session[mfa.SESSION_PENDING_KEY] = "corrupt-token"
        seed = mfa.begin_enrollment(self.session)
        self.assertEqual(mfa._decrypt(self.session[mfa.SESSION_PENDING_KEY]), seed)

    def test_provisioning_uri_and_qr_code_accept_a_valid_seed(self):
        seed = pyotp.random_base32(length=32)
        uri = mfa.provisioning_uri(self.user, seed)
        self.assertTrue(uri.startswith("otpauth://totp/NMAS:mfa-unit?"))
        self.assertIn("issuer=NMAS", uri)
        self.assertTrue(mfa.qr_svg_data_uri(uri).startswith("data:image/svg+xml;base64,"))

    def test_provisioning_uri_and_qr_code_refuse_invalid_input(self):
        """O3 regression: the seed is validated (never echoed in the error); a non-user object is refused; an over-long URI
        cannot become a QR code."""
        bad_seeds = {"empty": "", "none": None, "wrong type (bytes)": b"A" * 32, "wrong type (int)": 7,
                     "too short": "A" * 16, "too long": "A" * 40, "lower case": "a" * 32,
                     "illegal characters (0/1/8/9)": "0189" * 8, "punctuation": "AAAA-AAAA" * 3 + "AAAAA",
                     "whitespace": " " + "A" * 31, "padding": "A" * 30 + "=="}
        for label, seed in bad_seeds.items():
            with self.subTest(seed=label):
                with self.assertRaises(mfa.MfaError) as caught:
                    mfa.provisioning_uri(self.user, seed)
                self.assertEqual(str(caught.exception), "The authenticator seed is invalid (expected 32 base32 characters).")
        for user in (object(), AnonymousUser()):
            with self.subTest(user=type(user).__name__), self.assertRaises(mfa.MfaError):
                mfa.provisioning_uri(user, "A" * 32)
        import segno

        with self.assertRaises(segno.DataOverflowError):
            mfa.qr_svg_data_uri("otpauth://totp/x?secret=" + "A" * 8000)

    def test_validate_seed_accepts_a_generated_seed_unchanged(self):
        seed = pyotp.random_base32(length=mfa.SEED_LENGTH)
        self.assertEqual(mfa.validate_seed(seed), seed)

    def test_validate_seed_refuses_malformed_base32_without_echoing_it(self):
        for seed in ("A" * 31 + "1", "Z" * 31 + "!", "", None):
            with self.subTest(seed=repr(seed)[:6]), self.assertRaises(mfa.MfaError) as caught:
                mfa.validate_seed(seed)
            if seed:
                self.assertNotIn(seed, str(caught.exception))

    def test_begin_enrollment_replaces_a_pending_seed_that_is_not_valid_base32(self):
        self.session[mfa.SESSION_PENDING_KEY] = mfa._encrypt("not-a-valid-seed")
        seed = mfa.begin_enrollment(self.session)
        self.assertEqual(mfa.validate_seed(seed), seed)
        self.assertEqual(mfa._decrypt(self.session[mfa.SESSION_PENDING_KEY]), seed)

    def test_complete_enrollment_accepts_a_valid_code(self):
        seed, device = self._enroll()
        self.assertIsNotNone(device.confirmed_at)
        self.assertEqual(mfa._decrypt(device.encrypted_seed), seed)
        self.assertNotIn(mfa.SESSION_PENDING_KEY, self.session)
        self.assertEqual(mfa.device_for(self.user), device)

    def test_complete_enrollment_refuses_wrong_missing_or_duplicate_enrollment(self):
        with self.assertRaises(mfa.MfaError):
            mfa.complete_enrollment(self.user, {}, "123456")                       # nothing pending
        seed = mfa.begin_enrollment(self.session)
        for label, code in (("wrong code", str((int(_code(seed)) + 1) % 1_000_000).zfill(6)), ("short", "123"), ("letters", "abcdef")):
            with self.subTest(case=f"invalid {label}"), self.assertRaises(mfa.MfaError):
                mfa.complete_enrollment(self.user, self.session, code)
        mfa.complete_enrollment(self.user, self.session, _code(seed))
        second = {}
        other_seed = mfa.begin_enrollment(second)
        with self.assertRaises(mfa.MfaError):                                      # already enrolled: an admin must reset
            mfa.complete_enrollment(self.user, second, _code(other_seed))

    def test_device_for_returns_the_confirmed_device(self):
        _seed, device = self._enroll()
        self.assertEqual(mfa.device_for(self.user), device)

    def test_device_for_anonymous_or_unconfirmed_users_is_none(self):
        self.assertIsNone(mfa.device_for(AnonymousUser()))
        models.AppMfaDevice.objects.create(user=self.user, encrypted_seed=mfa._encrypt("A" * 32), confirmed_at=None)
        self.assertIsNone(mfa.device_for(self.user))

    # -- verification ---------------------------------------------------------------------------------------
    def test_verify_accepts_a_fresh_valid_code(self):
        seed, device = self._enroll()
        device.last_used_step = 0
        device.save(update_fields=["last_used_step"])
        self.assertTrue(mfa.verify(self.user, _code(seed)))

    def test_verify_rejects_replayed_wrong_and_unenrolled_codes(self):
        seed, _device = self._enroll()
        self.assertFalse(mfa.verify(self.user, _code(seed)))                      # the enrollment code: replay refused
        self.assertFalse(mfa.verify(self.user, "000000" if _code(seed, 1) != "000000" else "111111"))
        self.assertFalse(mfa.verify(self.user, "12 34"))
        stranger = get_user_model().objects.create_user("mfa-none", password="pw-unit-123456")
        with self.assertRaises(mfa.MfaError):
            mfa.verify(stranger, "123456")

    def test_verify_refuses_a_seed_that_cannot_be_decrypted(self):
        self._enroll()
        with self.settings(NMAS_APP_MFA_KEY="aW52YWxpZC1rZXktaW52YWxpZC1rZXktaW52YWxpZDA="), self.assertRaises(mfa.MfaError) as caught:
            mfa.verify(self.user, "123456")
        self.assertIn("administrator must reset", str(caught.exception))

    # -- session helpers / reset ----------------------------------------------------------------------------
    def test_mark_session_verified_records_success_and_clears_failures(self):
        session = {mfa.SESSION_FAILURES_KEY: 3}
        mfa.mark_session_verified(session)
        self.assertTrue(mfa.session_verified(session))
        self.assertNotIn(mfa.SESSION_FAILURES_KEY, session)

    def test_mark_session_verified_on_an_invalid_session_object_raises(self):
        with self.assertRaises(TypeError):
            mfa.mark_session_verified(None)

    def test_register_failure_counts_each_failed_attempt(self):
        session = {}
        self.assertEqual([mfa.register_failure(session) for _ in range(3)], [1, 2, 3])

    def test_register_failure_with_a_corrupt_counter_raises(self):
        with self.assertRaises(ValueError):
            mfa.register_failure({mfa.SESSION_FAILURES_KEY: "many"})

    def test_reset_removes_an_enrolled_authenticator(self):
        self._enroll()
        self.assertTrue(mfa.reset(self.user))
        self.assertFalse(mfa.is_enrolled(self.user))

    def test_reset_of_a_user_without_an_authenticator_returns_false(self):
        self.assertFalse(mfa.reset(self.user))
        with mock.patch.object(models.AppMfaDevice.objects, "filter", wraps=models.AppMfaDevice.objects.filter) as query:
            mfa.reset(self.user)
        query.assert_called_once_with(user=self.user)
