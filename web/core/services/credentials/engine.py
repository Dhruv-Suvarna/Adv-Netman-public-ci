"""Crash-recoverable managed-device credential rotation state machine.

For cEOS the provider keeps current+pending candidates until EOS has applied
the replacement under a commit timer, both authentication outcomes are
proven, operational validation passes, the timer is confirmed, and startup
equals running. Provider promotion is the final external step.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta
import sys

from django.conf import settings
from django.db import transaction
from django.utils import timezone

if str(settings.REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(settings.REPO_ROOT))

from modules.device_credentials import FileSecretProvider, SecretProviderError

from ...models import (
    CredentialRotationPhase,
    CredentialRotationRun,
    CredentialStatus,
    DeviceCredential,
    RotationTrigger,
)
from .ceos_transaction import SafeDeviceTransaction
from .passwords import generate_password
from .platforms import (
    DeviceChangeRejected,
    OperationalValidationFailed,
    PersistenceFailed,
    PlatformNotImplemented,
    RotationAdapterError,
    TransactionConfirmationFailed,
    adapter_for,
)
from .policy import NON_RUNNABLE, due_credentials, is_due, next_due_at


RECOVERY_RETRY_DELAY = timedelta(days=1)
_PHASE_ORDER = {value: index for index, value in enumerate(CredentialRotationPhase.values)}


@dataclass(frozen=True)
class RotationOutcome:
    credential_id: int
    run_id: str | None
    status: str
    code: str


def _at_least(run, phase: str) -> bool:
    return _PHASE_ORDER.get(run.phase, -1) >= _PHASE_ORDER[phase]


def _record_phase(run, phase: str, **fields) -> None:
    run.phase = phase
    update_fields = ["phase"]
    for name, value in fields.items():
        setattr(run, name, value)
        update_fields.append(name)
    run.save(update_fields=update_fields)


def _merge_metadata(run, **values) -> dict:
    metadata = dict(run.transaction_metadata or {})
    metadata.update(values)
    run.transaction_metadata = metadata
    run.save(update_fields=["transaction_metadata"])
    return metadata


def _finish(
    credential, run, *, at, status, code, device_result, verify_result,
    detail="", rotated=False, retry_after=None,
) -> RotationOutcome:
    # Database finalization is all-or-nothing. Provider/device state is already
    # durable at this boundary, so a process death cannot leave SUCCESS on the
    # credential while its audit row still says STARTED (or vice versa).
    with transaction.atomic():
        credential.last_attempt_at = at
        credential.last_status = status
        credential.last_result_code = code
        update_fields = ["last_attempt_at", "last_status", "last_result_code", "updated_at"]
        if rotated:
            credential.last_rotated_at = at
            credential.next_due_at = next_due_at(at, credential.rotation_interval_days)
            update_fields.extend(("last_rotated_at", "next_due_at"))
        elif retry_after is not None:
            credential.next_due_at = at + retry_after
            update_fields.append("next_due_at")
        credential.save(update_fields=update_fields)

        run.completed_at = at
        run.device_change_result = device_result
        run.login_verification_result = verify_result
        run.final_status = status
        run.error_category = "" if status == CredentialStatus.SUCCESS else code
        run.completed_detail = detail[:200]
        update_run = [
            "completed_at", "device_change_result", "login_verification_result",
            "final_status", "error_category", "completed_detail",
        ]
        if status != CredentialStatus.UNCERTAIN:
            run.phase = CredentialRotationPhase.COMPLETE
            update_run.append("phase")
        run.save(update_fields=update_run)
    return RotationOutcome(credential.pk, str(run.run_id), status, code)


def _shared_reference(credential) -> bool:
    return DeviceCredential.objects.filter(secret_ref=credential.secret_ref).exclude(pk=credential.pk).exists()


def _claim(credential_id: int, at) -> bool:
    """Atomic compare-and-set: manual and timer callers cannot double-rotate."""
    return bool(
        DeviceCredential.objects.filter(pk=credential_id, rotation_enabled=True)
        .exclude(last_status__in=NON_RUNNABLE)
        .update(last_status=CredentialStatus.IN_PROGRESS, last_attempt_at=at, last_result_code="STARTED", updated_at=at)
    )


def _record_transaction(run, tx: SafeDeviceTransaction) -> None:
    _record_phase(
        run, CredentialRotationPhase.DEVICE_TIMER_ARMED,
        session_name=tx.session_name,
        checkpoint_file=tx.checkpoint_file,
        checkpoint_sha256=tx.checkpoint_sha256,
        checkpoint_md5=tx.checkpoint_md5,
        pre_change_digest=tx.pre_change_digest,
        post_change_digest=tx.post_change_digest,
        transaction_metadata=tx.metadata(),
        device_change_result="TIMER_ARMED",
    )


def rotate_credential(
    credential_id: int, *, trigger: str = RotationTrigger.SCHEDULED,
    at=None, provider=None, adapter=None, password_factory=generate_password,
) -> RotationOutcome:
    """Perform one safe transaction. No secret value is returned or logged."""
    at = at or timezone.now()
    provider = provider or FileSecretProvider()

    with transaction.atomic():
        credential = DeviceCredential.objects.get(pk=credential_id)
        if not credential.rotation_enabled:
            return RotationOutcome(credential.pk, None, "SKIPPED", "DISABLED")
        if credential.last_status in NON_RUNNABLE:
            return RotationOutcome(credential.pk, None, "SKIPPED", f"STATUS_{credential.last_status}")
        if trigger == RotationTrigger.SCHEDULED and not is_due(credential, at=at):
            return RotationOutcome(credential.pk, None, "SKIPPED", "NOT_DUE")
        if _shared_reference(credential):
            run = CredentialRotationRun.objects.create(credential=credential, trigger_reason=trigger, started_at=at)
            return _finish(
                credential, run, at=at, status=CredentialStatus.BLOCKED,
                code="SHARED_SECRET_REF", device_result="NOT_ATTEMPTED", verify_result="NOT_ATTEMPTED",
                detail="One secret reference is assigned to multiple accounts; isolated rotation is refused.",
            )
        if not _claim(credential.pk, at):
            return RotationOutcome(credential.pk, None, "SKIPPED", "CLAIMED_ELSEWHERE")
        credential.refresh_from_db()
        run = CredentialRotationRun.objects.create(credential=credential, trigger_reason=trigger, started_at=at)

    def finish(**kwargs):
        return _finish(credential, run, at=timezone.now(), **kwargs)

    try:
        adapter = adapter or adapter_for(credential)
        adapter.preflight(credential)
    except PlatformNotImplemented as exc:
        return finish(status=CredentialStatus.BLOCKED, code=exc.code, device_result="NOT_ATTEMPTED", verify_result="NOT_ATTEMPTED")
    except RotationAdapterError as exc:
        return finish(
            status=CredentialStatus.FAILED, code=exc.code,
            device_result="NOT_ATTEMPTED", verify_result="NOT_ATTEMPTED",
            retry_after=RECOVERY_RETRY_DELAY,
        )

    try:
        if provider.has_pending(credential.secret_ref):
            return finish(
                status=CredentialStatus.UNCERTAIN, code="PENDING_REPLACEMENT_UNRESOLVED",
                device_result="NOT_ATTEMPTED", verify_result="NOT_ATTEMPTED",
                detail="A previous replacement was never finalized; run reconcile_device_credential.",
            )
        current = provider.current(credential.secret_ref)
    except SecretProviderError:
        return finish(
            status=CredentialStatus.FAILED, code="SECRET_PREPARE_FAILED",
            device_result="NOT_ATTEMPTED", verify_result="NOT_ATTEMPTED",
            retry_after=RECOVERY_RETRY_DELAY,
        )

    replacement = password_factory()
    if not replacement or replacement == current.value:
        return finish(
            status=CredentialStatus.FAILED, code="REPLACEMENT_NOT_DISTINCT",
            device_result="NOT_ATTEMPTED", verify_result="NOT_ATTEMPTED",
            retry_after=RECOVERY_RETRY_DELAY,
        )
    try:
        prior_version, new_version = provider.stage(credential.secret_ref, replacement)
        pending = provider.pending(credential.secret_ref, new_version)
        if pending.value != replacement:
            raise SecretProviderError("Staged device credential could not be confirmed.")
    except SecretProviderError:
        return finish(
            status=CredentialStatus.UNCERTAIN, code="SECRET_STAGE_FAILED",
            device_result="NOT_ATTEMPTED", verify_result="NOT_ATTEMPTED",
            detail="The provider may hold a partial pending replacement; reconcile before retrying.",
        )
    _record_phase(run, CredentialRotationPhase.PROVIDER_STAGED,
                  prior_secret_version=prior_version, new_secret_version=new_version)

    def discard_failed(code, device_result):
        try:
            provider.discard_pending(credential.secret_ref, new_version)
        except SecretProviderError:
            return finish(
                status=CredentialStatus.UNCERTAIN, code=f"{code}_CLEANUP_FAILED"[:64],
                device_result=device_result, verify_result="NOT_ATTEMPTED",
            )
        return finish(
            status=CredentialStatus.FAILED, code=code, device_result=device_result,
            verify_result="NOT_ATTEMPTED", retry_after=RECOVERY_RETRY_DELAY,
        )

    try:
        tx = adapter.arm_transaction(credential, current.value, replacement, str(run.run_id))
    except DeviceChangeRejected as exc:
        return discard_failed(exc.code, "REJECTED")
    except RotationAdapterError as exc:
        _merge_metadata(run, adapter_error_evidence=exc.evidence)
        return finish(
            status=CredentialStatus.UNCERTAIN, code=exc.code,
            device_result="UNCERTAIN", verify_result="NOT_ATTEMPTED",
            detail="Current and pending candidates are retained; an EOS timer may be armed.",
        )
    _record_transaction(run, tx)

    try:
        adapter.verify_password(credential, replacement)
    except RotationAdapterError as exc:
        return finish(
            status=CredentialStatus.UNCERTAIN, code=exc.code,
            device_result="TIMER_ARMED", verify_result="FAILED",
            detail="EOS timer is not confirmed; both provider candidates are retained.",
        )
    _record_phase(run, CredentialRotationPhase.NEW_VERIFIED, login_verification_result="SUCCESS")

    try:
        adapter.verify_old_rejected(credential, current.value)
    except RotationAdapterError as exc:
        run.old_login_verification_result = "ACCEPTED" if exc.code == "OLD_CREDENTIAL_STILL_ACCEPTED" else "INDETERMINATE"
        run.save(update_fields=["old_login_verification_result"])
        return finish(
            status=CredentialStatus.UNCERTAIN, code=exc.code,
            device_result="TIMER_ARMED", verify_result="SUCCESS",
            detail="Previous credential rejection was not proven; EOS timer remains unconfirmed.",
        )
    _record_phase(run, CredentialRotationPhase.OLD_REJECTED, old_login_verification_result="REJECTED")

    try:
        validation = adapter.operational_validate(
            credential, tx, new_verified=True, old_rejected=True, expect_timer=True,
        )
    except OperationalValidationFailed as exc:
        _merge_metadata(run, operational_validation=exc.evidence)
        run.operational_validation_result = "FAILED"
        run.save(update_fields=["operational_validation_result"])
        return finish(
            status=CredentialStatus.UNCERTAIN, code=exc.code,
            device_result="TIMER_ARMED", verify_result="SUCCESS",
            detail="Operational validation failed; EOS timer will restore prior state.",
        )
    _merge_metadata(run, operational_validation=validation)
    _record_phase(run, CredentialRotationPhase.OPERATIONAL_VALIDATED, operational_validation_result="SUCCESS")

    try:
        adapter.confirm_transaction(credential, tx)
    except TransactionConfirmationFailed as exc:
        _merge_metadata(run, confirmation_evidence=exc.evidence)
        run.transaction_confirmation_result = "FAILED"
        run.save(update_fields=["transaction_confirmation_result"])
        return finish(
            status=CredentialStatus.UNCERTAIN, code=exc.code,
            device_result="UNCERTAIN", verify_result="SUCCESS",
            detail="Transaction confirmation was not proven; provider candidates remain available.",
        )
    _record_phase(run, CredentialRotationPhase.DEVICE_CONFIRMED, transaction_confirmation_result="SUCCESS")

    try:
        persistence = adapter.persist_transaction(credential, tx)
    except PersistenceFailed as exc:
        _merge_metadata(run, persistence_evidence=exc.evidence)
        run.persistence_result = "FAILED"
        run.startup_verification_result = "FAILED"
        run.save(update_fields=["persistence_result", "startup_verification_result"])
        return finish(
            status=CredentialStatus.UNCERTAIN, code=exc.code,
            device_result="CONFIRMED", verify_result="SUCCESS",
            detail="Device is confirmed; pending provider credential is retained for recovery.",
        )
    _merge_metadata(run, persistence=persistence)
    _record_phase(run, CredentialRotationPhase.STARTUP_PERSISTED,
                  persistence_result="SUCCESS", startup_verification_result="SUCCESS")

    try:
        provider.promote(credential.secret_ref, new_version)
    except SecretProviderError:
        run.provider_promotion_result = "FAILED"
        run.save(update_fields=["provider_promotion_result"])
        return finish(
            status=CredentialStatus.UNCERTAIN, code="SECRET_FINALIZE_FAILED",
            device_result="CONFIRMED_PERSISTED", verify_result="SUCCESS",
            detail="Verified pending credential remains available; reconciliation can finish promotion.",
        )
    _record_phase(run, CredentialRotationPhase.PROVIDER_PROMOTED, provider_promotion_result="SUCCESS")
    return finish(
        status=CredentialStatus.SUCCESS, code="ROTATION_SUCCESS",
        device_result="CONFIRMED_PERSISTED", verify_result="SUCCESS", rotated=True,
    )


def rotate_due_credentials(*, at=None, provider=None, adapter_factory=adapter_for, password_factory=generate_password):
    """Scheduler entry: snapshot due IDs, then run each account independently."""
    at = at or timezone.now()
    ids = list(due_credentials(at=at).values_list("pk", flat=True))
    outcomes = []
    for credential_id in ids:
        credential = DeviceCredential.objects.get(pk=credential_id)
        try:
            adapter = adapter_factory(credential)
        except PlatformNotImplemented:
            adapter = None
        outcomes.append(rotate_credential(
            credential_id, trigger=RotationTrigger.SCHEDULED, at=at,
            provider=provider, adapter=adapter, password_factory=password_factory,
        ))
    return outcomes


def _source_run(credential):
    return (
        credential.rotation_runs.exclude(trigger_reason=RotationTrigger.RECONCILE)
        .filter(final_status__in=("STARTED", "UNCERTAIN"))
        .order_by("-started_at", "-id").first()
    )


def _mark_reconciled(source, reconciliation_run, outcome: str) -> None:
    if source is None:
        return
    metadata = dict(source.transaction_metadata or {})
    metadata["reconciliation"] = {"run_id": str(reconciliation_run.run_id), "outcome": outcome}
    source.transaction_metadata = metadata
    source.save(update_fields=["transaction_metadata"])


def reconcile_credential(credential_id: int, *, provider=None, adapter=None, at=None) -> RotationOutcome:
    """Deterministically reconcile an interrupted/uncertain safe transaction."""
    at = at or timezone.now()
    provider = provider or FileSecretProvider()
    credential = DeviceCredential.objects.get(pk=credential_id)
    if credential.last_status not in (CredentialStatus.UNCERTAIN, CredentialStatus.IN_PROGRESS):
        return RotationOutcome(credential.pk, None, "SKIPPED", "NOTHING_TO_RECONCILE")
    source = _source_run(credential)
    run = CredentialRotationRun.objects.create(
        credential=credential, trigger_reason=RotationTrigger.RECONCILE, started_at=at,
    )

    def finish(**kwargs):
        return _finish(credential, run, at=timezone.now(), device_result="NOT_ATTEMPTED", **kwargs)

    try:
        adapter = adapter or adapter_for(credential)
    except PlatformNotImplemented as exc:
        return finish(status=CredentialStatus.UNCERTAIN, code=exc.code, verify_result="NOT_ATTEMPTED")
    try:
        pending = provider.pending(credential.secret_ref) if provider.has_pending(credential.secret_ref) else None
        current = provider.current(credential.secret_ref)
    except SecretProviderError:
        return finish(status=CredentialStatus.UNCERTAIN, code="SECRET_READ_FAILED", verify_result="NOT_ATTEMPTED")

    current_auth = adapter.probe_password(credential, current.value)
    pending_auth = adapter.probe_password(credential, pending.value) if pending is not None else "ABSENT"
    _merge_metadata(run, authentication={"current": current_auth, "pending": pending_auth})
    if "ERROR" in (current_auth, pending_auth):
        return finish(status=CredentialStatus.UNCERTAIN, code="RECONCILE_AUTH_INDETERMINATE", verify_result="INDETERMINATE")

    has_transaction = bool(source and source.session_name and source.pre_change_digest and source.post_change_digest)
    tx = SafeDeviceTransaction.from_run(source) if has_transaction else None
    if tx is not None:
        try:
            state = adapter.inspect_recovery(credential, tx)
        except RotationAdapterError:
            return finish(status=CredentialStatus.UNCERTAIN, code="RECOVERY_STATE_UNAVAILABLE", verify_result="INDETERMINATE")
        _merge_metadata(run, device_state=state)
        if state["timer_pending"]:
            return finish(
                status=CredentialStatus.UNCERTAIN, code="TIMER_REVERT_PENDING", verify_result="NOT_ATTEMPTED",
                detail="EOS transaction remains timer-armed; let it revert before reconciling again.",
            )
    else:
        state = {"pre_change_matches": False, "post_change_matches": False,
                 "startup_matches_running": False, "no_open_sessions": False}

    if pending is not None and current_auth == "ACCEPT" and pending_auth == "REJECT":
        if has_transaction and not (state["pre_change_matches"] and state["startup_matches_running"] and state["no_open_sessions"]):
            return finish(status=CredentialStatus.UNCERTAIN, code="RECOVERY_DEVICE_STATE_MISMATCH", verify_result="CURRENT_SUCCESS")
        try:
            provider.discard_pending(credential.secret_ref, pending.version)
        except SecretProviderError:
            return finish(status=CredentialStatus.UNCERTAIN, code="SECRET_DISCARD_FAILED", verify_result="CURRENT_SUCCESS")
        _mark_reconciled(source, run, "PRIOR_STATE_RETAINED")
        return finish(
            status=CredentialStatus.FAILED, code="RECONCILED_PRIOR_STATE_RETAINED",
            verify_result="CURRENT_SUCCESS", retry_after=RECOVERY_RETRY_DELAY,
            detail="Prior device/provider state is healthy; automatic retry deferred for 24 hours.",
        )

    if pending is not None and current_auth == "REJECT" and pending_auth == "ACCEPT":
        if not has_transaction or not state["post_change_matches"] or not state["no_open_sessions"]:
            return finish(status=CredentialStatus.UNCERTAIN, code="RECOVERY_DEVICE_STATE_MISMATCH", verify_result="PENDING_SUCCESS")
        if source is None or not _at_least(source, CredentialRotationPhase.OPERATIONAL_VALIDATED):
            return finish(status=CredentialStatus.UNCERTAIN, code="CONFIRMATION_NOT_PROVEN", verify_result="PENDING_SUCCESS")
        try:
            recovery = adapter.complete_recovery(credential, tx)
            provider.promote(credential.secret_ref, pending.version)
        except (RotationAdapterError, SecretProviderError):
            return finish(status=CredentialStatus.UNCERTAIN, code="RECOVERY_FINALIZE_FAILED", verify_result="PENDING_SUCCESS")
        run.prior_secret_version = current.version
        run.new_secret_version = pending.version
        run.old_login_verification_result = "REJECTED"
        run.operational_validation_result = "SUCCESS"
        run.transaction_confirmation_result = "SUCCESS"
        run.persistence_result = "SUCCESS"
        run.startup_verification_result = "SUCCESS"
        run.provider_promotion_result = "SUCCESS"
        run.transaction_metadata = {**(run.transaction_metadata or {}), "recovery": recovery}
        run.save(update_fields=[
            "prior_secret_version", "new_secret_version", "old_login_verification_result",
            "operational_validation_result", "transaction_confirmation_result", "persistence_result",
            "startup_verification_result", "provider_promotion_result", "transaction_metadata",
        ])
        _mark_reconciled(source, run, "PENDING_PROMOTED")
        return finish(status=CredentialStatus.SUCCESS, code="RECONCILED_PROMOTED_PENDING",
                      verify_result="PENDING_SUCCESS", rotated=True)

    if pending is None and source is not None and current.version == source.new_secret_version:
        prerequisites = (
            _at_least(source, CredentialRotationPhase.STARTUP_PERSISTED)
            and source.old_login_verification_result == "REJECTED"
            and source.operational_validation_result == "SUCCESS"
            and source.transaction_confirmation_result == "SUCCESS"
            and source.persistence_result == "SUCCESS"
            and source.startup_verification_result == "SUCCESS"
        )
        if not (
            prerequisites and current_auth == "ACCEPT" and has_transaction
            and state["post_change_matches"] and state["startup_matches_running"] and state["no_open_sessions"]
        ):
            return finish(status=CredentialStatus.UNCERTAIN, code="POST_PROMOTION_STATE_UNPROVEN",
                          verify_result="CURRENT_SUCCESS" if current_auth == "ACCEPT" else "FAILED")
        run.prior_secret_version = source.prior_secret_version
        run.new_secret_version = current.version
        run.provider_promotion_result = "SUCCESS"
        run.save(update_fields=["prior_secret_version", "new_secret_version", "provider_promotion_result"])
        _mark_reconciled(source, run, "POST_PROMOTION_FINALIZED")
        return finish(status=CredentialStatus.SUCCESS, code="RECONCILED_POST_PROMOTION",
                      verify_result="CURRENT_SUCCESS", rotated=True)

    if pending is None and current_auth == "ACCEPT" and source is not None and not source.new_secret_version:
        _mark_reconciled(source, run, "CLAIM_ONLY_NO_CHANGE")
        return finish(
            status=CredentialStatus.FAILED, code="RECONCILED_CLAIM_ONLY",
            verify_result="CURRENT_SUCCESS", retry_after=RECOVERY_RETRY_DELAY,
            detail="The process stopped before provider staging; automatic retry deferred for 24 hours.",
        )

    if pending is None and current_auth == "ACCEPT" and source is not None and current.version == source.prior_secret_version:
        _mark_reconciled(source, run, "NO_DEVICE_CHANGE")
        return finish(status=CredentialStatus.FAILED, code="RECONCILED_NO_DEVICE_CHANGE",
                      verify_result="CURRENT_SUCCESS", retry_after=RECOVERY_RETRY_DELAY)

    return finish(
        status=CredentialStatus.UNCERTAIN, code="RECONCILE_AMBIGUOUS_STATE", verify_result="FAILED",
        detail="Provider/device state is ambiguous; use the documented emergency console path.",
    )
