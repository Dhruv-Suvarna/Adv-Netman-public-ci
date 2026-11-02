"""Append-only verification runs: duplicate-run guard, lease reaping, currency, current-result reuse, the pinned-run check.

Verification is ALWAYS an explicit action (``request_verification``): opening a page, saving a revision, validating a Change and
building a plan never start a sandbox.  A run is created RUNNING -- the partial UNIQUE index ``unique_active_raw_verification_per_
revision`` makes a second concurrent attempt for the same revision impossible at the database level -- and is finalised exactly
ONCE; a finished run is never turned into a later result.  This lock is separate from the Phase-17 device execution locks.

CURRENCY (never stored; computed): a revision's LATEST finished run is CURRENT only while every pinned fact still matches --
content hash, platform (the run's AND the target device's current one), static policy version, verifier framework version, adapter
id / version and the sandbox backend identity (the server-owned image tag).  Any difference makes it STALE.  A new revision
(even one byte) has NEVER_RUN: an old revision's verification is never carried forward.

REUSE (documented rule): an explicit Verify of a revision whose latest run is CURRENT *and acceptable* (PASS / PASS_WITH_WARNINGS)
returns that existing run instead of spending a sandbox.  BLOCKED / INCOMPLETE / STALE results are never reused.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta

from django.conf import settings
from django.db import IntegrityError, transaction
from django.utils import timezone

from ... import models
from . import codes, verifier
from .codes import Currency, Result, finding


@dataclass
class VerificationResponse:
    run: object | None
    reused: bool = False
    refused: str = ""          # "" | "VERIFICATION_IN_PROGRESS"


def lease_seconds() -> float:
    return float(getattr(settings, "RAW_VERIFIER_LEASE_SECONDS", 600))


def latest_finished(revision):
    return revision.verification_runs.filter(state=models.RawVerificationState.FINISHED).order_by("-started_at", "-id").first()


def active_run(revision, *, now: datetime | None = None):
    now = now or timezone.now()
    return revision.verification_runs.filter(state=models.RawVerificationState.RUNNING, lease_expires_at__gt=now).first()


def reap_expired(now: datetime | None = None) -> list[str]:
    """Finalise abandoned runs (lease expired while RUNNING) as INCOMPLETE so a crash never blocks a revision forever."""
    now = now or timezone.now()
    reaped = []
    for run in list(models.RawConfigletVerificationRun.objects.filter(state=models.RawVerificationState.RUNNING, lease_expires_at__lte=now)):
        run.state, run.result, run.finished_at = models.RawVerificationState.FINISHED, Result.INCOMPLETE, now
        run.findings = [finding("VERIFICATION_INTERRUPTED")]
        run.save()
        reaped.append(str(run.run_id))
    return reaped


def currency(revision, *, current_platform: str | None = None, context=None) -> dict:
    """``{"state", "reasons", "run", "result"}`` for ONE revision.  Never starts a sandbox and never writes."""
    run = latest_finished(revision)
    if run is None:
        return {"state": Currency.NEVER_RUN, "reasons": [], "run": None, "result": None}
    identity = verifier.identity(revision.platform, context=context)
    reasons = []
    if run.content_hash != revision.content_hash:
        reasons.append("CONTENT_CHANGED")
    if run.platform != revision.platform or (current_platform is not None and current_platform != revision.platform):
        reasons.append("PLATFORM_CHANGED")
    if run.policy_version != identity["policy_version"]:
        reasons.append("POLICY_VERSION_CHANGED")
    if run.verifier_version != identity["verifier_version"]:
        reasons.append("VERIFIER_VERSION_CHANGED")
    if (run.adapter_id, run.adapter_version) != (identity["adapter_id"], identity["adapter_version"]):
        reasons.append("ADAPTER_CHANGED")
    if run.backend != identity["backend"]:
        reasons.append("BACKEND_CHANGED")
    return {"state": Currency.STALE if reasons else Currency.CURRENT, "reasons": reasons, "run": run, "result": run.result}


def acceptable(status: dict) -> bool:
    return status["state"] == Currency.CURRENT and status["result"] in Result.ACCEPTABLE


def _audit(revision, event_type: str, summary: str, actor: str, metadata: dict) -> None:
    models.AuditEvent.objects.create(
        event_type=event_type, change=revision.raw.change, object_type="RawConfigletRevision",
        object_id=f"{revision.raw.raw_id}:{revision.revision}", actor=actor, summary=summary[:255], metadata=metadata,
    )


def request_verification(revision, *, actor: str = "", context=None, reuse: bool = True, now: datetime | None = None) -> VerificationResponse:
    """The explicit Verify action for ONE exact revision.  Returns the (possibly reused) run, or a refusal for a duplicate."""
    now = now or timezone.now()
    reap_expired(now)
    raw = revision.raw
    if reuse:
        status = currency(revision, current_platform=None, context=context)
        if acceptable(status):
            return VerificationResponse(status["run"], reused=True)
    identity = verifier.identity(revision.platform, context=context)
    try:
        with transaction.atomic():
            run = models.RawConfigletVerificationRun.objects.create(
                revision=revision, content_hash=revision.content_hash, platform=revision.platform, verifier_version=identity["verifier_version"],
                policy_version=identity["policy_version"], adapter_id=identity["adapter_id"], adapter_version=identity["adapter_version"],
                backend=identity["backend"], actor=actor, started_at=now, lease_expires_at=now + timedelta(seconds=lease_seconds()),
            )
            _audit(revision, models.AuditEventType.RAW_VERIFICATION_REQUESTED,
                   f"{raw.change.change_id}: verification requested for {raw.raw_id} rev {revision.revision}", actor,
                   {"run_id": str(run.run_id), "raw_id": raw.raw_id, "revision": revision.revision, "content_hash": revision.content_hash,
                    "platform": revision.platform})
    except IntegrityError:
        return VerificationResponse(None, refused="VERIFICATION_IN_PROGRESS")

    try:
        outcome = verifier.verify_raw_configlet(revision, context or verifier.VerificationContext(actor=actor))
    except Exception:  # noqa: BLE001 - the run must ALWAYS be finalised; a defect is INCOMPLETE, never PASS, never a stuck lock
        outcome = None
    return VerificationResponse(_finalize(run, revision, outcome, actor))


def _finalize(run, revision, outcome, actor: str):
    now = timezone.now()
    if outcome is None:
        result, findings = Result.INCOMPLETE, [finding("VERIFIER_INTERNAL_ERROR")]
        static, evidence, provenance = {}, {}, {}
    else:
        result, findings, static, evidence, provenance = outcome.result, outcome.findings, outcome.static, outcome.evidence, outcome.provenance
    with transaction.atomic():
        run.state, run.result, run.finished_at = models.RawVerificationState.FINISHED, result, now
        run.static_result, run.findings, run.evidence, run.provenance = static, findings, evidence, provenance
        run.save()
        raw = revision.raw
        _audit(revision, models.AuditEventType.RAW_VERIFICATION_COMPLETED,
               f"{raw.change.change_id}: verification {result} for {raw.raw_id} rev {revision.revision}", actor,
               {"run_id": str(run.run_id), "raw_id": raw.raw_id, "revision": revision.revision, "result": result,
                "codes": sorted({f["code"] for f in findings})[:20], "adapter": run.adapter_id, "backend": run.backend})
    return run


def pinned_verification_state(configlet) -> tuple[bool, str]:
    """Execution-time re-check of a RAW plan Configlet's pinned verification.  -> (ok, reason code; "" when ok).

    Every fact is re-read server-side: the pinned revision exists and still hashes to the pinned value, the pinned run belongs to that
    revision, is FINISHED and acceptable, and is STILL CURRENT (policy / verifier / adapter / backend / platform unchanged).
    """
    from . import text as text_module

    revision, run = configlet.raw_revision, configlet.raw_verification
    pins = (configlet.metadata or {}).get("raw") or {}
    if revision is None or run is None:
        return False, "RAW_PIN_MISSING"
    if text_module.content_hash(revision.content) != revision.content_hash or revision.content_hash != pins.get("content_hash"):
        return False, "RAW_REVISION_INTEGRITY"
    if run.revision_id != revision.pk or run.state != models.RawVerificationState.FINISHED or run.content_hash != revision.content_hash:
        return False, "RAW_VERIFICATION_MISMATCH"
    if run.result not in Result.ACCEPTABLE:
        return False, "RAW_VERIFICATION_NOT_ACCEPTABLE"
    status = currency(revision)
    if status["state"] != Currency.CURRENT or status["run"] is None or status["run"].pk != run.pk:
        return False, "RAW_VERIFICATION_STALE"
    return True, ""
