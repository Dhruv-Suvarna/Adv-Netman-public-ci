"""Start, cancel and COLLECT: the lifecycle of the one-time bootstrap observation.  Short read-only units of work on a schedule.

    start_bootstrap(candidate, actor=..)   explicit; the one-time gate and every eligibility rule re-checked inside the transaction; pins the server's
                                           start, required end and policy; idempotent (a double click returns the active run)
    cancel_bootstrap(run, actor=..)        explicit; audited; evidence kept; can never be resumed or become Golden
    run_tick(now=..)                       the idempotent collector: for the RUNNING run, take the due sample (if any), re-check integrity and
                                           interference, evaluate and -- only when the verdict is terminal -- finalise exactly once
    drive(run, ..)                         the one-time operator command's loop: tick, then WAIT (never a busy loop) until the next sample is due

Same guarantees as the Phase-20 collector: network reads happen OUTSIDE every transaction; one sample per bucket and at most one finalisation (database
constraints); a crash loses nothing and downtime is NEVER backfilled; the server clock is the only clock (no backdating, no fake time, no timestamp
edits -- an interruption simply leaves a gap, and a run whose coverage no longer satisfies the policy ends INCOMPLETE).

This module can never create a Golden bundle: it does not import the approval path.  A technical PASS only makes the run READY for the operator.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from django.db import IntegrityError, transaction
from django.db.models import Max
from django.utils import timezone

from ... import models
from .. import notification_service, secret_policy
from ..bundles import legacy
from ..bundles.integrity import verify_bundle_integrity
from ..bundles.persistence import record_integrity_failure
from ..soak.policy import SoakPolicy
from . import baseline, codes, evaluator, evidence, interference, policy as bootstrap_policy
from .codes import COLLECTOR_ACTOR, COLLECTOR_VERSION, blocker

log = logging.getLogger(__name__)
MIN_WAIT_SECONDS = 5.0
State, Result = models.SoakState, models.SoakResult
Notif = models.Notification


def parse_run_id(value) -> int | None:
    import re

    match = re.fullmatch(r"BOOT-(\d{6,})", str(value or ""))
    return int(match.group(1)) if match else None


def get_run(run_id: str):
    pk = parse_run_id(run_id)
    return models.LegacyBootstrapRun.objects.select_related("candidate").filter(pk=pk).first() if pk else None


def list_runs(limit: int = 50):
    return list(models.LegacyBootstrapRun.objects.select_related("candidate").order_by("-started_at", "-id")[:limit])


def decision_of(run):
    return models.LegacyBootstrapDecision.objects.filter(run=run).select_related("golden_bundle").first()


# --- audit + best-effort notifications -----------------------------------------------------------------------------------------
def audit_event(event_type: str, run, *, actor: str, summary: str, extra: dict | None = None) -> None:
    models.AuditEvent.objects.create(
        event_type=event_type, change=None, object_type="LegacyBootstrapRun", object_id=run.run_id, actor=actor, summary=f"legacy bootstrap: {summary}"[:255],
        metadata=secret_policy.assert_no_secret_shaped_keys(
            {"run_id": run.run_id, "candidate_bundle_id": run.candidate.bundle_id, "candidate_bundle_digest": run.candidate_digest, "state": run.state,
             "result": run.result, "provenance_type": "LEGACY_BOOTSTRAP", **(extra or {})}, context="Bootstrap audit"),
    )


@dataclass
class Note:
    event_type: str
    severity: str
    title: str
    message: str
    correlation: str
    metadata: dict = field(default_factory=dict)


def publish(notes) -> None:
    """Persist-then-Slack through the ONE notification service.  A delivery failure NEVER touches run state (and never raises)."""
    for note in notes:
        try:
            with transaction.atomic():
                notification_service.publish_event(event_type=note.event_type, severity=note.severity, title=note.title, message=note.message,
                                                   source="legacy-bootstrap", metadata=note.metadata, correlation_key=note.correlation)
        except Exception:   # noqa: BLE001 - a notification must never corrupt or block the observation
            log.exception("Bootstrap notification could not be published (run state is unaffected).")


def note_for(run, event_type: str, severity: str, title: str, message: str, suffix: str, **metadata) -> Note:
    return Note(event_type, severity, title, message, f"BOOT:{run.run_id}:{suffix}", {"run_id": run.run_id, "candidate_bundle_id": run.candidate.bundle_id, **metadata})


# --- start ----------------------------------------------------------------------------------------------------------------------
@dataclass
class StartResult:
    run: object | None
    created: bool = False
    blockers: list = field(default_factory=list)
    refused: bool = False


def check_start(candidate, *, now: datetime | None = None) -> tuple[list, object | None]:
    """Every blocker for starting an observation of this candidate RIGHT NOW.  Read-only.  -> (blockers, integrity report | None)."""
    now = now or timezone.now()
    blockers = legacy.gate_blockers()
    if candidate.kind != models.BundleKind.LEGACY_BASELINE or candidate.provenance != models.BundleProvenance.LEGACY_BOOTSTRAP:
        return blockers + [blocker("CANDIDATE_NOT_LEGACY", kind=candidate.kind)], None
    report = verify_bundle_integrity(candidate)
    if not report.ok:
        blockers.append(blocker("CANDIDATE_INTEGRITY_FAILED", findings=report.codes))
    captured = interference.capture_finished_at(candidate)
    age = (now - captured).total_seconds() if captured is not None else float("inf")
    if age > bootstrap_policy.candidate_max_age_seconds():
        blockers.append(blocker("CANDIDATE_STALE", age_seconds=None if captured is None else int(age)))
    if interference.find_interference(candidate):
        blockers.append(blocker("CANDIDATE_INTERFERED"))
    return blockers, report


def start_bootstrap(candidate, *, actor: str, now: datetime | None = None) -> StartResult:
    """Explicitly start the observation.  The SERVER decides every timestamp and the duration; the caller supplies only the candidate and the actor."""
    now = now or timezone.now()
    notes = []
    with transaction.atomic():
        locked = models.ConfigurationBundle.objects.select_for_update().get(pk=candidate.pk)
        active = baseline.active_run()
        if active is not None:      # a double click / a racing request: return the run that exists, never a second one
            return StartResult(active)
        blockers, report = check_start(locked, now=now)
        if blockers:
            if report is not None and not report.ok:
                record_integrity_failure(locked, report, actor=actor, context="bootstrap start refused")
            return StartResult(None, blockers=blockers, refused=True)
        pinned = bootstrap_policy.current_policy()
        run = models.LegacyBootstrapRun(
            candidate=locked, candidate_digest=locked.bundle_digest, policy_version=pinned.version, policy=pinned.to_dict(), started_at=now,
            required_end_at=now + timedelta(seconds=pinned.duration_seconds), started_by=actor,
        )
        try:
            with transaction.atomic():
                run.save()
        except IntegrityError:      # lost the race for the one-active-run constraint
            winner = baseline.active_run()
            if winner is not None:
                return StartResult(winner)
            raise
        run.candidate = locked
        audit_event(models.AuditEventType.LEGACY_BOOTSTRAP_STARTED, run, actor=actor, summary=f"observation {run.run_id} started for {locked.bundle_id}",
                    extra={"required_end_at": evaluator.iso(run.required_end_at), "duration_seconds": pinned.duration_seconds,
                           "sample_interval_seconds": pinned.sample_interval_seconds, "policy_version": pinned.version})
        notes.append(note_for(run, Notif.EventType.SOAK_STARTED, Notif.Severity.INFO, f"Legacy bootstrap observation {run.run_id} started",
                              f"{locked.bundle_id} entered a {pinned.duration_seconds // 60}-minute observation window (ONE-TIME legacy bootstrap); required end "
                              f"{evaluator.iso(run.required_end_at)}.", "started", required_end_at=evaluator.iso(run.required_end_at)))
    publish(notes)
    return StartResult(run, created=True)


# --- finalisation (inside the caller's transaction, on a row locked by the caller) --------------------------------------------------
_OUTCOMES = {
    (State.COMPLETED, Result.PASS): (models.AuditEventType.LEGACY_BOOTSTRAP_READY, Notif.EventType.SOAK_COMPLETE, Notif.Severity.SUCCESS, "ready"),
    (State.COMPLETED, Result.FAIL): (models.AuditEventType.LEGACY_BOOTSTRAP_FAILED, Notif.EventType.SOAK_REGRESSION, Notif.Severity.ERROR, "failed"),
    (State.COMPLETED, Result.INCOMPLETE): (models.AuditEventType.LEGACY_BOOTSTRAP_INCOMPLETE, Notif.EventType.SOAK_REGRESSION, Notif.Severity.WARNING, "incomplete"),
    (State.INVALIDATED, ""): (models.AuditEventType.LEGACY_BOOTSTRAP_INVALIDATED, Notif.EventType.SOAK_REGRESSION, Notif.Severity.ERROR, "invalidated"),
    (State.CANCELLED, ""): (models.AuditEventType.LEGACY_BOOTSTRAP_CANCELLED, None, None, "cancelled"),
}


def finalize(run, pinned: SoakPolicy, samples, verdict, now: datetime, *, actor: str, notes: list) -> None:
    """Finalise a RUNNING run EXACTLY ONCE: state, result, reason, the canonical evidence summary + digest, one audit event, one notification."""
    run.state, run.result, run.terminal_reason, run.finished_at, run.ended_by = verdict.state, verdict.result, verdict.reason, now, actor
    run.evaluation = evaluator.final_summary(run, pinned, samples, verdict, now)
    run.evidence_digest = evaluator.evidence_digest(run.evaluation)
    run.save()
    event, notification, severity, suffix = _OUTCOMES[(verdict.state, verdict.result)]
    stats = verdict.stats
    audit_event(event, run, actor=actor, summary=f"observation {run.run_id} {suffix} ({codes.TERMINAL_REASONS[verdict.reason][:120]})",
                extra={"reason": verdict.reason, "problems": list(verdict.problems)[:5], "samples": stats.get("samples", 0),
                       "coverage_percent": stats.get("coverage_percent", 0), "evidence_digest": run.evidence_digest})
    if notification is not None:
        if (verdict.state, verdict.result) == (State.COMPLETED, Result.PASS):
            title, message = (f"Legacy bootstrap {run.run_id} passed: operator approval required",
                              f"The technical observation of {run.candidate.bundle_id} passed. Nothing is promoted until the operator explicitly approves the initial Golden.")
        else:
            title, message = f"Legacy bootstrap {run.run_id} {suffix}", f"{run.candidate.bundle_id}: {codes.TERMINAL_REASONS[verdict.reason]} It can not become Golden."
        notes.append(note_for(run, notification, severity, title, message, suffix, reason=verdict.reason, result=verdict.result or verdict.state))


# --- cancel ----------------------------------------------------------------------------------------------------------------------
@dataclass
class CancelResult:
    run: object
    cancelled: bool = False
    blockers: list = field(default_factory=list)


def cancel_bootstrap(run, *, actor: str, now: datetime | None = None) -> CancelResult:
    now = now or timezone.now()
    with transaction.atomic():
        locked = models.LegacyBootstrapRun.objects.select_for_update().select_related("candidate").get(pk=run.pk)
        if not locked.is_running:
            return CancelResult(locked, blockers=[blocker("NOT_RUNNING", state=locked.state)])
        pinned = SoakPolicy.from_dict(locked.policy)
        samples = list(locked.samples.all())
        facts = [evaluator.facts_of(s) for s in samples]
        verdict = evaluator.Verdict(State.CANCELLED, reason=codes.CANCELLED_BY_OPERATOR,
                                    stats=evaluator.statistics(pinned, locked.started_at, locked.required_end_at, facts))
        notes: list = []
        finalize(locked, pinned, samples, verdict, now, actor=actor, notes=notes)
    publish(notes)
    return CancelResult(locked, cancelled=True)


# --- the collector -----------------------------------------------------------------------------------------------------------------
@dataclass
class RunReport:
    run_id: str
    action: str            # SAMPLED | DUPLICATE | NOT_DUE | WOULD_SAMPLE | FINALIZED | NOT_RUNNING | CLOCK_ANOMALY | ERROR
    bucket: int | None = None
    sample_result: str = ""
    state: str = ""
    result: str = ""
    detail: str = ""

    def to_dict(self) -> dict:
        return {k: v for k, v in self.__dict__.items() if v not in (None, "")}


@dataclass
class TickReport:
    now: datetime
    dry_run: bool = False
    runs: list = field(default_factory=list)

    def to_dict(self) -> dict:
        return {"now": evaluator.iso(self.now), "dry_run": self.dry_run, "runs": [r.to_dict() for r in self.runs]}


def _process(run_pk: int, now: datetime, *, snapshot, session_factory, live_reads: bool, dhcp_state, dry_run: bool) -> RunReport:
    run = models.LegacyBootstrapRun.objects.select_related("candidate").get(pk=run_pk)
    if not run.is_running:
        return RunReport(run.run_id, "NOT_RUNNING", state=run.state, result=run.result)
    pinned = SoakPolicy.from_dict(run.policy)
    elapsed = (now - run.started_at).total_seconds()
    latest = run.samples.aggregate(latest=Max("sampled_at"))["latest"]
    if elapsed < 0 or (latest is not None and now < latest):   # never fabricate continuity across a clock that moved backwards
        return RunReport(run.run_id, "CLOCK_ANOMALY", detail="The server clock is earlier than recorded evidence; nothing was collected.")
    bucket = min(int(elapsed // pinned.sample_interval_seconds), pinned.total_buckets)
    due = not run.samples.filter(bucket=bucket).exists()
    if dry_run:
        return RunReport(run.run_id, "WOULD_SAMPLE" if due else "NOT_DUE", bucket=bucket, state=run.state)
    assessed = guard = None
    if due:     # network reads happen OUTSIDE every transaction and hold no lock
        assessed = evidence.collect(run.candidate, now=now, snapshot=snapshot, session_factory=session_factory, live_reads=live_reads, dhcp_state=dhcp_state)
    else:
        guard = evidence.guard(run.candidate)
    notes: list = []
    action, sample_result = "NOT_DUE", ""
    with transaction.atomic():
        locked = models.LegacyBootstrapRun.objects.select_for_update().select_related("candidate").get(pk=run.pk)
        if not locked.is_running:
            return RunReport(locked.run_id, "NOT_RUNNING", state=locked.state, result=locked.result)
        if assessed is not None:
            try:
                with transaction.atomic():
                    models.LegacyBootstrapSample(run=locked, bucket=bucket, sampled_at=now, collector_version=COLLECTOR_VERSION, **assessed.to_kwargs()).save()
                action, sample_result = "SAMPLED", assessed.result
            except IntegrityError:   # another collector persisted this interval first: exactly one sample per bucket survives
                action = "DUPLICATE"
        samples = list(locked.samples.all())
        facts = [evaluator.facts_of(s) for s in samples]
        verdict = evaluator.evaluate(pinned, locked.started_at, locked.required_end_at, facts, now, guard=guard)
        if verdict.terminal:
            finalize(locked, pinned, samples, verdict, now, actor=COLLECTOR_ACTOR, notes=notes)
            action = "FINALIZED"
    publish(notes)
    return RunReport(locked.run_id, action, bucket=bucket, sample_result=sample_result, state=locked.state, result=locked.result, detail=locked.terminal_reason)


def run_tick(*, now: datetime | None = None, snapshot=None, session_factory=None, live_reads: bool = True, dhcp_state=None, dry_run: bool = False,
             run_id: str = "") -> TickReport:
    """Process the RUNNING observation once (or one, by id).  Safe to run twice at once, safe to restart, and it configures nothing."""
    now = now or timezone.now()
    report = TickReport(now=now, dry_run=dry_run)
    runs = models.LegacyBootstrapRun.objects.filter(state=State.RUNNING).order_by("id")
    if run_id:
        runs = runs.filter(pk=parse_run_id(run_id) or 0)
    for pk in list(runs.values_list("pk", flat=True)):
        try:
            report.runs.append(_process(pk, now, snapshot=snapshot, session_factory=session_factory, live_reads=live_reads, dhcp_state=dhcp_state, dry_run=dry_run))
        except Exception as exc:   # noqa: BLE001 - one broken tick must not end the observation; the next tick retries from the persisted state
            log.exception("Bootstrap run %s tick failed.", pk)
            report.runs.append(RunReport(f"BOOT-{pk:06d}", "ERROR", detail=exc.__class__.__name__))
    return report


def next_wake(run, *, now: datetime) -> float:
    """Seconds until the next sample is due: the next interval boundary, and the single closing sample at / just after the required end.  Never negative."""
    pinned = SoakPolicy.from_dict(run.policy)
    elapsed = (now - run.started_at).total_seconds()
    end_offset = (run.required_end_at - run.started_at).total_seconds()
    boundary = (int(elapsed // pinned.sample_interval_seconds) + 1) * pinned.sample_interval_seconds
    return max(0.0, min(boundary, end_offset) - elapsed) if elapsed < end_offset else 0.0


def drive(run, *, snapshot_fn=None, session_factory=None, dhcp_state=None, sleep=time.sleep, clock=timezone.now, emit=lambda text: None, max_sleep: float = 15.0, settle: float = 1.5) -> object:
    """The one-time command's loop: tick, then WAIT until the next sample is due, until the run leaves RUNNING.  NEVER a busy loop (``sleep`` is
    injectable for tests only).  Interruption is safe: the run stays RUNNING, nothing is fabricated, and starting the driver again resumes it -- the
    gap is real and counts against coverage.  ``settle`` makes the wake-up land just AFTER the boundary so the bucket is the intended one."""
    while True:
        now = clock()
        report = run_tick(now=now, snapshot=snapshot_fn() if snapshot_fn else None, session_factory=session_factory, dhcp_state=dhcp_state, run_id=run.run_id)
        for item in report.runs:
            emit(f"[{evaluator.iso(now)}] {item.run_id} {item.action}" + (f" bucket={item.bucket}" if item.bucket is not None else "") +
                 (f" sample={item.sample_result}" if item.sample_result else "") + (f" -> {item.state}/{item.result} {item.detail}" if item.action == "FINALIZED" else ""))
        run = models.LegacyBootstrapRun.objects.select_related("candidate").get(pk=run.pk)
        if not run.is_running:
            return run
        remaining = max(next_wake(run, now=clock()) + settle, MIN_WAIT_SECONDS)   # a floor: a failing tick can never turn this into a spin
        emit(f"    next sample in {remaining:0.0f}s")
        while remaining > 0:
            step = min(max_sleep, remaining)
            sleep(step)      # a bounded wait (never a busy loop); KeyboardInterrupt propagates to the command, which leaves the run RUNNING
            remaining -= step


def progress(run, *, now: datetime | None = None) -> dict:
    """Server-side progress of a run (a page never counts down on its own clock).  Read-only."""
    now = now or timezone.now()
    pinned = SoakPolicy.from_dict(run.policy)
    samples = list(run.samples.order_by("bucket"))
    facts = [evaluator.facts_of(s) for s in samples]
    verdict = evaluator.evaluate(pinned, run.started_at, run.required_end_at, facts, run.finished_at if not run.is_running else now)
    total = (run.required_end_at - run.started_at).total_seconds()
    end = run.finished_at if not run.is_running else now
    elapsed = max(0.0, min((end - run.started_at).total_seconds(), total))
    return {
        "policy": pinned, "stats": verdict.stats, "verdict": verdict, "samples": samples, "latest": samples[-1] if samples else None,
        "elapsed_seconds": int(elapsed), "remaining_seconds": int(max(0.0, (run.required_end_at - now).total_seconds())) if run.is_running else 0,
        "percent_elapsed": round(100 * elapsed / total, 1) if total else 100.0,
    }
