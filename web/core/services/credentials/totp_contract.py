"""Non-live contract fixture for the Phase-24 password + TOTP policy.

This is deliberately not a RADIUS server and does not generate or store real
TOTP seeds.  Tests supply fake per-time-step OTP values so the required
accept/reject, expiry, replay, lock and service-exemption behavior can be
proved without creating enrollment material.
"""
from __future__ import annotations

import hmac
import re
from dataclasses import dataclass, field


ACCEPT = "ACCEPT"
REJECT = "REJECT"
UNAVAILABLE = "UNAVAILABLE"
OTP_DIGITS = 6
_OTP_RE = re.compile(r"^[0-9]{6}$")


@dataclass(frozen=True)
class HumanFixture:
    username: str
    password: str
    otp_by_counter: dict[int, str]
    enabled: bool = True


@dataclass(frozen=True)
class MachineFixture:
    username: str
    password: str
    allowed_sources: frozenset[str]
    enabled: bool = True


@dataclass
class FixtureAuthenticator:
    """Small stateful policy oracle used only by offline tests."""

    humans: dict[str, HumanFixture]
    machines: dict[str, MachineFixture]
    available: bool = True
    accepted_counters: set[tuple[str, int]] = field(default_factory=set)

    def authenticate_human(self, username: str, submitted: str, *, counter: int) -> tuple[str, str]:
        if not self.available:
            return UNAVAILABLE, "CENTRAL_AAA_UNAVAILABLE"
        record = self.humans.get(username)
        if record is None:
            return REJECT, "UNKNOWN_HUMAN"
        if not record.enabled:
            return REJECT, "HUMAN_DISABLED"
        if not isinstance(submitted, str) or len(submitted) <= OTP_DIGITS:
            return REJECT, "MALFORMED_COMBINED_CREDENTIAL"
        password, otp = submitted[:-OTP_DIGITS], submitted[-OTP_DIGITS:]
        if not _OTP_RE.fullmatch(otp):
            return REJECT, "MALFORMED_OTP"
        if not hmac.compare_digest(password, record.password):
            return REJECT, "PASSWORD_REJECTED"
        expected = record.otp_by_counter.get(counter)
        if expected is None or not hmac.compare_digest(otp, expected):
            if otp in record.otp_by_counter.values():
                return REJECT, "OTP_EXPIRED"
            return REJECT, "OTP_REJECTED"
        replay_key = (username, counter)
        if replay_key in self.accepted_counters:
            return REJECT, "OTP_REPLAYED"
        self.accepted_counters.add(replay_key)
        return ACCEPT, "HUMAN_PASSWORD_AND_TOTP_ACCEPTED"

    def authenticate_machine(self, username: str, submitted: str, *, source: str) -> tuple[str, str]:
        """Validate the separate non-interactive service path without OTP."""
        record = self.machines.get(username)
        if record is None:
            return REJECT, "NOT_AN_APPROVED_MACHINE_IDENTITY"
        if not record.enabled:
            return REJECT, "MACHINE_DISABLED"
        if source not in record.allowed_sources:
            return REJECT, "MACHINE_SOURCE_NOT_ALLOWED"
        if not hmac.compare_digest(submitted, record.password):
            return REJECT, "MACHINE_CREDENTIAL_REJECTED"
        return ACCEPT, "APPROVED_MACHINE_IDENTITY_ACCEPTED_WITHOUT_OTP"


def human_probe_matrix(authenticator: FixtureAuthenticator, username: str, password: str, otp: str, *, counter: int) -> dict[str, str]:
    """Return redacted outcome codes for the five mandatory human probes."""
    attempts = {
        "correct_password_only": password,
        "otp_only": otp,
        "wrong_password_correct_otp": "WRONG_TEST_PASSWORD" + otp,
        "correct_password_wrong_otp": password + "000000",
        "correct_password_correct_otp": password + otp,
    }
    return {
        name: authenticator.authenticate_human(username, submitted, counter=counter)[0]
        for name, submitted in attempts.items()
    }
