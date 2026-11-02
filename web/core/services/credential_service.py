"""Read-only operator projection of safe device-credential metadata."""
from __future__ import annotations

from ..models import CredentialRotationRun, DeviceCredential, DeviceLoginMfaPolicy


SAFE_CREDENTIAL_FIELDS = (
    "id", "device_name", "platform", "username", "account_kind", "auth_method", "secret_ref",
    "ssh_key_ref", "ssh_public_key_fingerprint",
    "account_role", "rotation_enabled", "rotation_interval_days", "last_rotated_at",
    "next_due_at", "last_attempt_at", "last_status", "last_result_code",
)
SAFE_RUN_FIELDS = (
    "run_id", "credential_id", "trigger_reason", "started_at", "completed_at",
    "prior_secret_version", "new_secret_version", "device_change_result",
    "phase", "session_name", "checkpoint_file", "checkpoint_sha256", "checkpoint_md5",
    "pre_change_digest", "post_change_digest", "transaction_metadata",
    "login_verification_result", "old_login_verification_result",
    "operational_validation_result", "transaction_confirmation_result",
    "persistence_result", "startup_verification_result", "provider_promotion_result",
    "final_status", "error_category", "completed_detail",
)

SAFE_MFA_FIELDS = (
    "device_name", "platform", "required", "mechanism", "enforcement_state", "blocked_reason",
    "central_aaa_state", "radius_server", "radius_secret_ref", "radius_source_interface", "automation_exempt",
    "emergency_path", "candidate_digest", "last_verified_at", "last_verification_result",
)


def get_credential_status_context() -> dict:
    return {
        "credentials": list(DeviceCredential.objects.values(*SAFE_CREDENTIAL_FIELDS)),
        "recent_runs": list(CredentialRotationRun.objects.values(*SAFE_RUN_FIELDS)[:50]),
        "secret_boundary": "Actual passwords remain in the protected runtime provider and are never rendered.",
        "live_status": "NOT LIVE VERIFIED",
        "mfa_policies": list(DeviceLoginMfaPolicy.objects.values(*SAFE_MFA_FIELDS)),
        "two_factor_status": "REQUIRED BY PROJECT OWNER -- PLANNED: Microsoft Authenticator TOTP via local RADIUS; NOT CONFIGURED, ENFORCED, OR LIVE VERIFIED",
        "human_mfa_method": "Password (knowledge) + Microsoft Authenticator TOTP (possession)",
        "automation_mfa_status": (
            "EXEMPT -- dedicated local non-interactive service identity; protected rotating credential, no OTP; "
            "human use prohibited"
        ),
    }
