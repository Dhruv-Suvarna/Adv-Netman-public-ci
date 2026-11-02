"""Password-change adapters.  Only live-deployed cEOS is implemented.

Exceptions raised here deliberately break the exception chain (``from None``):
Netmiko's ``cmd_verify`` / read-timeout errors quote the command text, and the
password-change command contains the replacement secret.
"""
from __future__ import annotations

import re
import sys
from dataclasses import dataclass

from django.conf import settings

from .. import nsot_live

if str(settings.REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(settings.REPO_ROOT))

from modules.device_credentials import SecretProviderError, load_ssh_private_key  # noqa: E402
from .ceos_transaction import (  # noqa: E402
    CeosConfirmationFailed,
    CeosOperationalValidationFailed,
    CeosPersistenceFailed,
    CeosRotationTransactionController,
    CeosTransactionRejected,
    CeosTransactionUncertain,
    SafeDeviceTransaction,
)


class RotationAdapterError(RuntimeError):
    code = "ADAPTER_ERROR"
    uncertain = False

    def __init__(self, code: str | None = None, *, uncertain: bool | None = None, evidence: dict | None = None):
        self.code = code or self.code
        self.uncertain = self.uncertain if uncertain is None else uncertain
        self.evidence = evidence or {}
        super().__init__(self.code)


class PlatformNotImplemented(RotationAdapterError):
    code = "PLATFORM_NOT_IMPLEMENTED"


class CurrentLoginFailed(RotationAdapterError):
    code = "CURRENT_LOGIN_FAILED"


class CredentialAuthenticationRejected(CurrentLoginFailed):
    code = "CREDENTIAL_AUTHENTICATION_REJECTED"


class DeviceChangeRejected(RotationAdapterError):
    code = "DEVICE_CHANGE_REJECTED"


class DeviceChangeUncertain(RotationAdapterError):
    code = "DEVICE_CHANGE_UNCERTAIN"
    uncertain = True


class NewLoginVerificationFailed(RotationAdapterError):
    code = "NEW_LOGIN_VERIFICATION_FAILED"
    uncertain = True


class OldCredentialStillAccepted(RotationAdapterError):
    code = "OLD_CREDENTIAL_STILL_ACCEPTED"
    uncertain = True


class OldCredentialVerificationFailed(RotationAdapterError):
    code = "OLD_CREDENTIAL_VERIFICATION_FAILED"
    uncertain = True


class OperationalValidationFailed(RotationAdapterError):
    code = "OPERATIONAL_VALIDATION_FAILED"
    uncertain = True


class TransactionConfirmationFailed(RotationAdapterError):
    code = "TRANSACTION_CONFIRM_FAILED"
    uncertain = True


class PersistenceFailed(RotationAdapterError):
    code = "PERSISTENCE_FAILED"
    uncertain = True


def ssh_auth_kwargs(credential, *, key_loader=load_ssh_private_key) -> dict:
    """Netmiko kwargs for an optional machine SSH key, if enrolled.

    This preserves the Phase-23 automation path and is independent from the
    authoritative human Microsoft Authenticator TOTP policy. A configured key
    that cannot be loaded fails CLOSED -- never a silent downgrade.
    """
    if not getattr(credential, "ssh_key_ref", ""):
        return {}
    try:
        pkey = key_loader(credential.ssh_key_ref)
    except SecretProviderError:
        raise CurrentLoginFailed("SSH_KEY_UNAVAILABLE") from None
    return {"use_keys": True, "pkey": pkey, "allow_agent": False}


_NAME_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_.-]{0,63}")
_HOSTNAME_RE = re.compile(r"^Hostname:\s*(\S+)\s*$", re.MULTILINE)
REJECTIONS = ("% Invalid input", "% Incomplete command", "% Ambiguous command", "% Error")


def ceos_password_command(credential, replacement: str) -> str:
    """Generate one EOS local-user command without ever logging its result."""
    if not _NAME_RE.fullmatch(credential.username):
        raise DeviceChangeRejected("INVALID_ACCOUNT_METADATA")
    if not replacement or any(ch.isspace() or ch in "'\"`\\;$" for ch in replacement):
        raise DeviceChangeRejected("INVALID_REPLACEMENT_FORMAT")
    parts = ["username", credential.username]
    if credential.privilege_level is not None:
        parts.extend(("privilege", str(credential.privilege_level)))
    if credential.account_role:
        if not _NAME_RE.fullmatch(credential.account_role):
            raise DeviceChangeRejected("INVALID_ACCOUNT_METADATA")
        parts.extend(("role", credential.account_role))
    parts.extend(("secret", replacement))
    return " ".join(parts)


@dataclass
class CeosPasswordAdapter:
    connection_factory: object | None = None
    transaction_controller: object | None = None

    def _target(self, credential):
        target = nsot_live.get_live_target_metadata(credential.device_name, purpose="WRITE")
        if target is None or target.get("platform") != "ceos":
            raise PlatformNotImplemented("TARGET_NOT_CONFIGURED")
        if (target.get("management") or {}).get("source") == "PATH":
            # The legacy rotation transaction controller uses a Docker CLI
            # transport.  It cannot enforce the selected management path.
            raise PlatformNotImplemented("PATH_ROTATION_NOT_IMPLEMENTED")
        return target

    def preflight(self, credential) -> None:
        """Resolve the target and prove there is no conflicting EOS transaction."""
        self._target(credential)
        self._controller().preflight(credential)

    def _controller(self):
        if self.transaction_controller is None:
            self.transaction_controller = CeosRotationTransactionController()
        return self.transaction_controller

    def _connect(self, credential, password: str):
        target = self._target(credential)
        auth = ssh_auth_kwargs(credential)
        if self.connection_factory is not None:
            try:
                return self.connection_factory(target, credential.username, password, **auth)
            except (CredentialAuthenticationRejected, CurrentLoginFailed):
                raise
            except Exception:
                raise CurrentLoginFailed("CURRENT_CONNECTION_FAILED") from None
        try:
            from netmiko import ConnectHandler
            from netmiko.exceptions import NetmikoAuthenticationException, NetmikoTimeoutException
            return ConnectHandler(
                device_type="arista_eos",
                host=target["address"],
                username=credential.username,
                password=password,
                secret=password,
                fast_cli=False,
                conn_timeout=settings.EXECUTION_DEVICE_TIMEOUT_SECONDS,
                auth_timeout=settings.EXECUTION_DEVICE_TIMEOUT_SECONDS,
                banner_timeout=settings.EXECUTION_DEVICE_TIMEOUT_SECONDS,
                **auth,
            )
        except NetmikoAuthenticationException:
            raise CredentialAuthenticationRejected() from None
        except NetmikoTimeoutException:
            raise CurrentLoginFailed("CURRENT_CONNECTION_FAILED") from None
        except Exception:
            raise CurrentLoginFailed("CURRENT_CONNECTION_FAILED") from None

    @staticmethod
    def _close(conn) -> None:
        try:
            conn.disconnect()
        except Exception:  # noqa: BLE001 - never relay connection details
            pass

    @staticmethod
    def _translate_transaction_error(exc):
        if isinstance(exc, CeosTransactionRejected):
            raise DeviceChangeRejected(exc.code, evidence=exc.evidence) from None
        if isinstance(exc, CeosOperationalValidationFailed):
            raise OperationalValidationFailed(exc.code, evidence=exc.evidence) from None
        if isinstance(exc, CeosConfirmationFailed):
            raise TransactionConfirmationFailed(exc.code, evidence=exc.evidence) from None
        if isinstance(exc, CeosPersistenceFailed):
            raise PersistenceFailed(exc.code, evidence=exc.evidence) from None
        if isinstance(exc, CeosTransactionUncertain):
            raise DeviceChangeUncertain(exc.code, evidence=exc.evidence) from None
        raise DeviceChangeUncertain() from None

    def arm_transaction(
        self, credential, current_password: str, replacement: str, run_id: str,
    ) -> SafeDeviceTransaction:
        """Checkpoint, stage, and commit the password change under an EOS timer."""
        command = ceos_password_command(credential, replacement)
        try:
            return self._controller().arm(
                credential, command, current_password, replacement, str(run_id),
            )
        except (
            CeosTransactionRejected, CeosTransactionUncertain,
            CeosOperationalValidationFailed, CeosConfirmationFailed, CeosPersistenceFailed,
        ) as exc:
            self._translate_transaction_error(exc)

    def verify_password(self, credential, replacement: str) -> None:
        try:
            conn = self._connect(credential, replacement)
        except CurrentLoginFailed:
            raise NewLoginVerificationFailed() from None
        try:
            output = conn.send_command("show hostname", read_timeout=settings.EXECUTION_DEVICE_TIMEOUT_SECONDS)
            match = _HOSTNAME_RE.search(str(output))
            if not match or match.group(1).lower() != credential.device_name.lower():
                raise NewLoginVerificationFailed("NEW_LOGIN_IDENTITY_MISMATCH")
        except NewLoginVerificationFailed:
            raise
        except Exception:
            raise NewLoginVerificationFailed() from None
        finally:
            self._close(conn)

    def probe_password(self, credential, candidate: str) -> str:
        """Return only ACCEPT/REJECT/ERROR; never return or log the candidate."""
        try:
            conn = self._connect(credential, candidate)
        except CredentialAuthenticationRejected:
            return "REJECT"
        except CurrentLoginFailed:
            return "ERROR"
        else:
            self._close(conn)
            return "ACCEPT"

    def verify_old_rejected(self, credential, previous: str) -> None:
        """Require an explicit authentication rejection, not a timeout or error."""
        try:
            conn = self._connect(credential, previous)
        except CredentialAuthenticationRejected:
            return
        except CurrentLoginFailed:
            raise OldCredentialVerificationFailed() from None
        else:
            self._close(conn)
            raise OldCredentialStillAccepted() from None

    def operational_validate(self, credential, transaction, *, new_verified=True, old_rejected=True, expect_timer=True):
        try:
            return self._controller().validate(
                credential, transaction, new_verified=new_verified,
                old_rejected=old_rejected, expect_timer=expect_timer,
            )
        except CeosOperationalValidationFailed as exc:
            self._translate_transaction_error(exc)

    def confirm_transaction(self, credential, transaction) -> str:
        try:
            return self._controller().confirm(credential, transaction)
        except CeosConfirmationFailed as exc:
            self._translate_transaction_error(exc)

    def persist_transaction(self, credential, transaction) -> dict:
        try:
            return self._controller().persist(credential, transaction)
        except CeosPersistenceFailed as exc:
            self._translate_transaction_error(exc)

    def inspect_recovery(self, credential, transaction) -> dict:
        try:
            return self._controller().inspect(credential, transaction)
        except CeosTransactionUncertain as exc:
            self._translate_transaction_error(exc)

    def complete_recovery(self, credential, transaction) -> dict:
        try:
            return self._controller().complete_recovery(credential, transaction)
        except (CeosOperationalValidationFailed, CeosPersistenceFailed, CeosTransactionUncertain) as exc:
            self._translate_transaction_error(exc)


def adapter_for(credential, *, connection_factory=None):
    if credential.platform == "arista_ceos":
        return CeosPasswordAdapter(connection_factory=connection_factory)
    raise PlatformNotImplemented()
