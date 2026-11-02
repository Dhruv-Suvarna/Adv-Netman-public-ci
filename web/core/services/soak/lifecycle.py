"""Start, cancel and COLLECT: the soak lifecycle.  Short read-only units of work on a schedule -- never a lock, a session or a transaction held
for the window.

    start_soak(bundle, actor=..)       explicit; eligibility re-checked inside the transaction; pins the policy and the server-side start /
                                       required end; idempotent (a double click returns the active run)
    cancel_soak(run, actor=..)         explicit; audited; evidence kept; can never be resumed or become Golden
    run_tick(now=..)                   the idempotent collector: for every RUNNING run, take the due sample (if any), re-check integrity and
                                       interference, evaluate and -- only when the verdict is terminal -- finalise exactly once

Concurrency is DATABASE-backed, not distributed: a partial unique index allows one RUNNING run per bundle, ``UNIQUE (run, bucket)`` allows one
sample per interval, and every write happens under ``select_for_update`` (a no-op on SQLite; the constraints still hold).  Reads of monitoring
and devices happen OUTSIDE any transaction.  A crash between ticks loses nothing: the next tick re-derives the state from the persisted samples
and never backfills a sample for downtime.

This module can never create a Golden bundle: it does not import ``bundles.golden`` or ``decision``; a technical PASS only makes the run
READY for the operator's decision.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from django.conf import settings
from django.db import IntegrityError, transaction
from django.db.models import Max
from django.utils import timezone

from ... import models
from .. import notification_service, secret_policy
from ..bundles.persistence import record_integrity_failure
from ..health import telemetry
from . import baseline as baseline_module, codes, config_state, eligibility, evaluator, sampling
from .codes import COLLECTOR_ACTOR, COLLECTOR_VERSION, DECISION_BLOCKERS, START_BLOCKERS, blocker
from .policy import SoakPolicy, current_policy

log = logging.getLogger(__name__)
State, Result = models.SoakState, models.SoakResult
Notif = models.Notification
_SOAK_ID = re.compile(r"SOAK-(\d{6,})")


def parse_soak_id(value) -> int | None:
    match = _SOAK_ID.fullmatch(str(value or ""))
    return int(match.group(1)) if match else None


def get_run(soak_id: str):
    pk = parse_soak_id(soak_id)
    return models.ProbationSoakRun.objects.select_related("bundle__change", "bundle__source_uat").filter(pk=pk).first() if pk else None


# --- audit + best-effort notifications -----------------------------------------------------------------------------------------
def audit_event(event_type: str, run, *, actor: str, summary: str, extra: dict | None = None) -> None:
    models.AuditEvent.objects.create(
        event_type=event_type, change=run.bundle.change, object_type="ProbationSoakRun", object_id=run.soak_id, actor=actor,
        summary=f"{run.bundle.change.change_id}: {summary}"[:255],
        metadata=secret_policy.assert_no_secret_shaped_keys(
            {"soak_id": run.soak_id, "bundle_id": run.bundle.bundle_id, "bundle_digest": run.bundle_digest, "state": run.state, "result": run.result,
             **(extra or {})}, context="Soak audit"),
    )


@dataclass
class Note:
    event_type: str
    severity: str
    title: str
    message: str
    correlation: str
    change_id: str
    metadata: dict = field(default_factory=dict)


def publish(notes) -> None:
    """Persist-then-Slack through the ONE notification service.  A delivery failure NEVER touches soak state (and never raises)."""
    for note in notes:
        try:
            with transaction.atomic():
                notification_service.publish_event(
                    event_type=note.event_type, severity=note.severity, title=note.title, message=note.message, source="probation-soak",
                    change_id=note.change_id, metadata=note.metadata, correlation_key=note.correlation,
                )
        except Exception:   # noqa: BLE001 - a notification must never corrupt or block the soak
            log.exception("Soak notification could not be published (soak state is unaffected).")


def note_for(run, event_type: str, severity: str, title: str, message: str, suffix: str, **metadata) -> Note:
    return Note(event_type, severity, title, message, f"SOAK:{run.soak_id}:{suffix}", run.bundle.change.change_id,
                {"soak_id": run.soak_id, "bundle_id": run.bundle.bundle_id, **metadata})


# --- start ----------------------------------------------------------------------------------------------------------------------
@dataclass
class StartResult:
    run: object | None
    created: bool = False
    blockers: list = field(default_factory=list)
    refused: bool = False


def start_soak(bundle, *, actor: str, now: datetime | None = None, session_factory=None, snapshot=None) -> StartResult:
    """Explicitly start a soak.  The SERVER decides every timestamp and the duration; the caller supplies only the bundle and the actor.

    Before the run is written, the configuration digest of every observed device is read (read-only, outside every transaction) and pinned
    with the rest of the start-time baseline.  ``session_factory`` / ``snapshot`` are injectable for tests only.
    """
    now = now or timezone.now()
    notes = []
    existing = eligibility.active_run(bundle)
    if existing is not None:
        return StartResult(existing)
    preview = eligibility.check_start(bundle)
    device_digests, start_assessment = {}, None
    if not preview.blockers:      # nothing is read for a soak that cannot start anyway
        device_digests = config_state.read(preview.devices, session_factory=session_factory, now=now)
        unreadable = {name: row["error"] for name, row in device_digests.items() if row["state"] != config_state.OK}
        if unreadable and settings.PROBATION_SOAK_REQUIRE_BASELINE_DIGEST:
            return StartResult(None, blockers=[blocker(START_BLOCKERS, "BASELINE_UNREADABLE", devices=unreadable)], refused=True)
        if not unreadable:
            try:   # the health / postcheck / telemetry picture at the start instant (the same read a sample makes; nothing is persisted)
                snapshot = snapshot or telemetry.collect(now=now)
                start_assessment = sampling.collect(bundle, now=now, snapshot=snapshot, session_factory=session_factory)
            except Exception:  # noqa: BLE001 - the start picture is context; its absence is recorded, never invented
                start_assessment = None
    with transaction.atomic():
        locked = models.ConfigurationBundle.objects.select_for_update().select_related("change", "plan", "execution_run").get(pk=bundle.pk)
        active = eligibility.active_run(locked)
        if active is not None:      # a double click / a racing request: return the run that exists, never a second one
            return StartResult(active)
        check = eligibility.check_start(locked)
        if check.blockers:
            if check.integrity is not None and not check.integrity.ok:
                record_integrity_failure(locked, check.integrity, actor=actor, context="soak start refused")
            return StartResult(None, blockers=check.blockers, refused=True)
        policy = current_policy()
        required_end_at = now + timedelta(seconds=policy.duration_seconds)
        document = baseline_module.build(locked, policy=policy, started_at=now, required_end_at=required_end_at, device_digests=device_digests,
                                         start_assessment=start_assessment, snapshot=snapshot, actor=actor)
        run = models.ProbationSoakRun(
            bundle=locked, bundle_digest=locked.bundle_digest, policy_version=policy.version, policy=policy.to_dict(), started_at=now,
            required_end_at=required_end_at, started_by=actor, baseline=document, baseline_digest=baseline_module.digest(document),
        )
        try:
            with transaction.atomic():
                run.save()
        except IntegrityError:      # lost the race for the one-active-soak constraint
            winner = eligibility.active_run(locked)
            if winner is not None:
                return StartResult(winner)
            raise
        run.bundle = locked
        audit_event(models.AuditEventType.PROBATION_SOAK_STARTED, run, actor=actor,
               summary=f"probation soak {run.soak_id} started for {locked.bundle_id}",
               extra={"required_end_at": evaluator.iso(run.required_end_at), "duration_seconds": policy.duration_seconds,
                      "sample_interval_seconds": policy.sample_interval_seconds, "policy_version": policy.version})
        notes.append(note_for(
            run, Notif.EventType.SOAK_STARTED, Notif.Severity.INFO, f"Probation soak {run.soak_id} started",
            f"{locked.bundle_id} entered a {policy.duration_seconds // 3600}-hour observation window; required end {evaluator.iso(run.required_end_at)}.",
            "started", required_end_at=evaluator.iso(run.required_end_at)))
    publish(notes)
    return StartResult(run, created=True)


# --- finalisation (always inside the caller's transaction, on a row locked by the caller) -----------------------------------------
_OUTCOMES = {
    (State.COMPLETED, Result.PASS): (models.AuditEventType.PROBATION_SOAK_READY, Notif.EventType.SOAK_COMPLETE, Notif.Severity.SUCCESS, "ready"),
    (State.COMPLETED, Result.FAIL): (models.AuditEventType.PROBATION_SOAK_FAILED, Notif.EventType.SOAK_REGRESSION, Notif.Severity.ERROR, "failed"),
    (State.COMPLETED, Result.INCOMPLETE): (models.AuditEventType.PROBATION_SOAK_INCOMPLETE, Notif.EventType.SOAK_REGRESSION, Notif.Severity.WARNING, "incomplete"),
    (State.INVALIDATED, ""): (models.AuditEventType.PROBATION_SOAK_INVALIDATED, Notif.EventType.SOAK_REGRESSION, Notif.Severity.ERROR, "invalidated"),
    (State.CANCELLED, ""): (models.AuditEventType.PROBATION_SOAK_CANCELLED, None, None, "cancelled"),
}


def finalize(run, policy: SoakPolicy, facts, verdict, now: datetime, *, actor: str, notes: list) -> None:
    """Finalise a RUNNING run EXACTLY ONCE: state, result, reason, the canonical evidence summary + digest, one audit event, one notification."""
    run.state, run.result, run.terminal_reason, run.finished_at, run.ended_by = verdict.state, verdict.result, verdict.reason, now, actor
    run.evaluation = evaluator.final_summary(run, policy, facts, verdict, now)
    run.evidence_digest = evaluator.evidence_digest(run.evaluation)
    run.save()
    event, notification, severity, suffix = _OUTCOMES[(verdict.state, verdict.result)]
    stats = verdict.stats
    audit_event(event, run, actor=actor, summary=f"probation soak {run.soak_id} {suffix} ({codes.TERMINAL_REASONS[verdict.reason][:120]})",
           extra={"reason": verdict.reason, "problems": list(verdict.problems)[:5], "samples": stats.get("samples", 0),
                  "coverage_percent": stats.get("coverage_percent", 0), "evidence_digest": run.evidence_digest})
    if notification is not None:
        if (verdict.state, verdict.result) == (State.COMPLETED, Result.PASS):
            title, message = f"Probation soak {run.soak_id} passed: Golden decision required", (
                f"The technical soak of {run.bundle.bundle_id} passed. Nothing is promoted until the operator explicitly approves or rejects Golden.")
        else:
            title, message = f"Probation soak {run.soak_id} {suffix}", f"{run.bundle.bundle_id}: {codes.TERMINAL_REASONS[verdict.reason]} It can not become Golden."
        notes.append(note_for(run, notification, severity, title, message, suffix, reason=verdict.reason, result=verdict.result or verdict.state))


# --- cancel ---------------------------------------------------------------------------------------------------------------------
@dataclass
class CancelResult:
    run: object
    cancelled: bool = False
    blockers: list = field(default_factory=list)


def cancel_soak(run, *, actor: str, now: datetime | None = None) -> CancelResult:
    """Explicit cancellation: evidence stays, the bundle is untouched, no device is contacted and the run can never be resumed."""
    now = now or timezone.now()
    with transaction.atomic():
        locked = models.ProbationSoakRun.objects.select_for_update().select_related("bundle__change").get(pk=run.pk)
        if not locked.is_running:
            return CancelResult(locked, blockers=[blocker(DECISION_BLOCKERS, "NOT_RUNNING", state=locked.state)])
        policy = SoakPolicy.from_dict(locked.policy)
        facts = [evaluator.facts_of(s) for s in locked.samples.all()]
        verdict = evaluator.Verdict(State.CANCELLED, reason=codes.CANCELLED_BY_OPERATOR, stats=evaluator.statistics(policy, locked.started_at, locked.required_end_at, facts))
        notes: list = []
        finalize(locked, policy, facts, verdict, now, actor=actor, notes=notes)
    publish(notes)
    return CancelResult(locked, cancelled=True)


# --- the collector --------------------------------------------------------------------------------------------------------------
@dataclass
class RunReport:
    soak_id: str
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


def _process(run_pk: int, now: datetime, *, snapshot, session_factory, live_reads: bool, dry_run: bool) -> RunReport:
    run = models.ProbationSoakRun.objects.select_related("bundle__change").get(pk=run_pk)
    if not run.is_running:
        return RunReport(run.soak_id, "NOT_RUNNING", state=run.state, result=run.result)
    policy = SoakPolicy.from_dict(run.policy)
    elapsed = (now - run.started_at).total_seconds()
    latest = run.samples.aggregate(latest=Max("sampled_at"))["latest"]
    if elapsed < 0 or (latest is not None and now < latest):   # never fabricate continuity across a clock that moved backwards
        return RunReport(run.soak_id, "CLOCK_ANOMALY", detail="The server clock is earlier than recorded evidence; nothing was collected.")
    bucket = min(int(elapsed // policy.sample_interval_seconds), policy.total_buckets)
    due = not run.samples.filter(bucket=bucket).exists()
    if dry_run:
        return RunReport(run.soak_id, "WOULD_SAMPLE" if due else "NOT_DUE", bucket=bucket, state=run.state)
    assessment = guard = None
    if due:     # network reads happen OUTSIDE every transaction and hold no lock
        assessment = sampling.collect(run.bundle, now=now, snapshot=snapshot, session_factory=session_factory, live_reads=live_reads,
                                      baseline=(run.baseline or {}).get("devices"))
    else:
        guard = sampling.guard(run.bundle)
    notes: list = []
    action, sample_result = "NOT_DUE", ""
    with transaction.atomic():
        locked = models.ProbationSoakRun.objects.select_for_update().select_related("bundle__change").get(pk=run.pk)
        if not locked.is_running:
            return RunReport(locked.soak_id, "NOT_RUNNING", state=locked.state, result=locked.result)
        if assessment is not None:
            try:
                with transaction.atomic():
                    models.ProbationSoakSample(run=locked, bucket=bucket, sampled_at=now, collector_version=COLLECTOR_VERSION, **assessment.to_kwargs()).save()
                action, sample_result = "SAMPLED", assessment.result
            except IntegrityError:   # another collector persisted this interval first: exactly one sample per bucket survives
                action = "DUPLICATE"
        facts = [evaluator.facts_of(s) for s in locked.samples.all()]
        verdict = evaluator.evaluate(policy, locked.started_at, locked.required_end_at, facts, now, guard=guard)
        if verdict.terminal:
            finalize(locked, policy, facts, verdict, now, actor=COLLECTOR_ACTOR, notes=notes)
            action = "FINALIZED"
    publish(notes)
    return RunReport(locked.soak_id, action, bucket=bucket, sample_result=sample_result, state=locked.state, result=locked.result,
                     detail=locked.terminal_reason)


def run_tick(*, now: datetime | None = None, snapshot=None, session_factory=None, live_reads: bool = True, dry_run: bool = False, soak_id: str = "") -> TickReport:
    """Process every RUNNING soak once (or one, by id).  Safe to run twice at once, safe to restart, and it configures nothing."""
    now = now or timezone.now()
    report = TickReport(now=now, dry_run=dry_run)
    runs = models.ProbationSoakRun.objects.filter(state=State.RUNNING).order_by("id")
    if soak_id:
        runs = runs.filter(pk=parse_soak_id(soak_id) or 0)
    for pk in list(runs.values_list("pk", flat=True)):
        try:
            report.runs.append(_process(pk, now, snapshot=snapshot, session_factory=session_factory, live_reads=live_reads, dry_run=dry_run))
        except Exception as exc:   # noqa: BLE001 - one broken run must not stop the others; the next tick retries from the persisted state
            log.exception("Soak %s tick failed.", pk)
            report.runs.append(RunReport(f"SOAK-{pk:06d}", "ERROR", detail=exc.__class__.__name__))
    return report


# --- read models for the pages ---------------------------------------------------------------------------------------------------
def progress(run, *, now: datetime | None = None) -> dict:
    """Server-side progress of a run (the page never counts down on its own clock).  Read-only."""
    now = now or timezone.now()
    policy = SoakPolicy.from_dict(run.policy)
    samples = list(run.samples.order_by("bucket"))
    facts = [evaluator.facts_of(s) for s in samples]
    verdict = evaluator.evaluate(policy, run.started_at, run.required_end_at, facts, run.finished_at if not run.is_running else now)
    total = (run.required_end_at - run.started_at).total_seconds()
    end = run.finished_at if not run.is_running else now
    elapsed = max(0.0, min((end - run.started_at).total_seconds(), total))
    return {
        "policy": policy, "stats": verdict.stats, "verdict": verdict, "samples": samples, "latest": samples[-1] if samples else None,
        "elapsed_seconds": int(elapsed), "remaining_seconds": int(max(0.0, (run.required_end_at - now).total_seconds())) if run.is_running else 0,
        "percent_elapsed": round(100 * elapsed / total, 1) if total else 100.0, "next_bucket": None if not run.is_running else min(
            int(max(0.0, (now - run.started_at).total_seconds()) // policy.sample_interval_seconds) + 1, policy.total_buckets),
    }
