"""The maintenance lifecycle of one device: request, readiness, plan, approval, entry, active, exit, restore.

A ``Record`` is the state of one maintenance transaction.  Every step is a method that either moves the state or raises
``MaintenanceError``; a refused step leaves the record where it was and keeps the findings.  Nothing here writes to a
device: the callers that will one day run a drain hand in what they measured.

Timing: the requested duration is the operator's intended window and ends nothing by itself.  Separately, every
maintenance has a safety deadline one maintenance cycle (7 days) after entry.  At that deadline NMAS starts the defined
restore workflow for the maintenance-only changes and validates the result; when the restore cannot be shown safe the
record fails closed into ``RESTORE_FAILED_ESCALATED`` with every maintenance-only statement still listed.  A device is
never returned to service blindly.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from . import gates, model, plan, policy, readiness

REQUESTED, BLOCKED, READY, PLANNED, APPROVED = "REQUESTED", "READINESS_BLOCKED", "READY", "PLANNED", "APPROVED"
ENTERING, ACTIVE, RESTORING, RESTORED = "ENTERING", "ACTIVE", "RESTORING", "RESTORED"
ABORTED_RESTORED = "ENTRY_ABORTED_RESTORED"                  # entry failed and the device is verified back as it was
RESTORE_FAILED = "RESTORE_FAILED_ESCALATED"                  # maintenance-only state remains; an operator must act
CANCELLED = "CANCELLED"

RESOLVED = (RESTORED, ABORTED_RESTORED, CANCELLED)
IN_MAINTENANCE = (ENTERING, ACTIVE, RESTORING, RESTORE_FAILED)   # the device must be treated as under maintenance
MANUAL_EXIT, DEADLINE, ENTRY_ABORT = "MANUAL_EXIT", "DEADLINE", "ENTRY_ABORT"


@dataclass
class Record:
    request: model.Request
    state: str = REQUESTED
    report: model.Report | None = None
    steps: tuple = ()
    approved_by: str = ""
    entered_at: datetime | None = None
    restore_trigger: str = ""
    findings: list = field(default_factory=list)             # why the last step was refused, or why it escalated
    maintenance_only_state: tuple[str, ...] = ()             # every statement that exists only because of this maintenance
    escalated: bool = False
    baseline_untrusted: bool = False                         # the unresolved state makes the whole topology baseline untrustworthy
    history: list = field(default_factory=list)
    evidence: dict = field(default_factory=dict)             # what was observed and executed: observation, pre-state, entry and restore runs
    plan: dict = field(default_factory=dict)                 # the immutable plan document (plan.document); its hash binds the approval

    # -- helpers ------------------------------------------------------------------------------------------------------
    def _move(self, to: str, at: datetime, actor: str, note: str = "") -> None:
        self.history.append({"at": at, "from": self.state, "to": to, "actor": actor, "note": note})
        self.state = to

    def _require(self, *states: str) -> None:
        if self.state not in states:
            raise model.MaintenanceError("STATE_NOT_ALLOWED", f"{self.state}; this step needs {' or '.join(states)}")

    @property
    def requested_until(self) -> datetime | None:
        """End of the operator's intended window.  Shown to the operator; it does not end the maintenance."""
        return None if self.entered_at is None else self.entered_at + self.request.requested_duration

    @property
    def cycle_deadline(self) -> datetime | None:
        """The safety deadline: one maintenance cycle after entry."""
        return None if self.entered_at is None else self.entered_at + model.MAINTENANCE_CYCLE

    def deadline_due(self, now: datetime) -> bool:
        return self.state == ACTIVE and self.cycle_deadline is not None and now >= self.cycle_deadline

    # -- before entry -------------------------------------------------------------------------------------------------
    def evaluate(self, flows, dependencies=(), *, at: datetime, alternates=None, mechanisms=None) -> model.Report:
        self._require(REQUESTED, BLOCKED, READY, PLANNED, APPROVED)       # a new evaluation discards plan and approval
        self.report = readiness.evaluate(self.request, flows, dependencies, alternates=alternates, mechanisms=mechanisms)
        self.steps, self.approved_by, self.findings, self.plan = (), "", list(self.report.blockers), {}
        self._move(READY if self.report.ready else BLOCKED, at, "nmas", "; ".join(f.text() for f in self.report.blockers))
        return self.report

    def build_plan(self, *, at: datetime) -> tuple:
        self._require(READY)
        self.steps = plan.build(self.report)
        self._move(PLANNED, at, "nmas", f"{len(self.steps)} drain step(s)")
        return self.steps

    def refuse_plan(self, findings, *, at: datetime) -> None:
        """READY, but no plan this drain can be executed and reversed from exists (the pre-state is not the baseline, the
        tracked design does not match, an operation would touch the protected scope): the record is blocked."""
        self._require(READY)
        self.findings = list(findings)
        self.report.blockers.extend(self.findings)
        self.steps, self.plan = (), {}
        self._move(BLOCKED, at, "nmas", "no executable plan: " + "; ".join(f.text() for f in self.findings))

    def approve(self, approver: str, *, at: datetime) -> None:
        self._require(PLANNED)
        if not approver.strip():
            raise model.MaintenanceError("APPROVER_REQUIRED")
        self.approved_by = approver
        self._move(APPROVED, at, approver, "approved")

    def cancel(self, actor: str, *, at: datetime) -> None:
        self._require(REQUESTED, BLOCKED, READY, PLANNED, APPROVED)
        self._move(CANCELLED, at, actor, "cancelled before entry")

    # -- entry --------------------------------------------------------------------------------------------------------
    def begin_enter(self, facts: gates.Facts, *, at: datetime, actor: str, precheck=()) -> None:
        """Refused (state unchanged, findings kept) unless every gate holds.  ``precheck``: the findings of the drain
        executor's own read-only precheck; each one refuses the entry like any gate.  There is no override."""
        self._require(APPROVED)
        self.findings = [*gates.entry_findings(self.report, facts), *precheck]
        if self.findings:
            raise model.MaintenanceError("ENTRY_REFUSED", "; ".join(f.text() for f in self.findings))
        self._move(ENTERING, at, actor, "entry gate passed")

    def confirm_active(self, proofs, *, at: datetime, maintenance_only_state=()) -> None:
        """ACTIVE only when every planned direction is proven clear with zero loss.  Anything else aborts the entry:
        the record goes to RESTORING and must be restored like any other maintenance."""
        self._require(ENTERING)
        self.maintenance_only_state = tuple(maintenance_only_state)
        self.findings = plan.proof_findings(self.steps, proofs)
        if self.findings:
            self.restore_trigger = ENTRY_ABORT
            self._move(RESTORING, at, "nmas", "entry aborted: " + "; ".join(f.text() for f in self.findings))
            raise model.MaintenanceError("ENTRY_ABORTED", "; ".join(f.text() for f in self.findings))
        self.entered_at = at
        self._move(ACTIVE, at, "nmas", "every direction proven clear")

    def interrupt(self, *, at: datetime, detail: str) -> None:
        """The entry was interrupted (the worker that held it stopped): the device state is unknown, so the entry is
        aborted and the record must be restored like any other maintenance; it is never assumed drained or untouched."""
        self._require(ENTERING)
        self.restore_trigger = ENTRY_ABORT
        self.findings = [model.Finding("ENTRY_INTERRUPTED", detail=detail)]
        self._move(RESTORING, at, "nmas", f"entry interrupted: {detail}")

    # -- exit and restore ---------------------------------------------------------------------------------------------
    def request_exit(self, actor: str, *, at: datetime) -> None:
        self._require(ACTIVE)
        self.restore_trigger = MANUAL_EXIT
        self._move(RESTORING, at, actor, "manual exit")

    def on_deadline(self, *, now: datetime) -> bool:
        """Start the restore workflow when the 7-day safety deadline has passed.  -> whether it was started.
        The end of the requested window starts nothing."""
        if not self.deadline_due(now):
            return False
        self.restore_trigger = DEADLINE
        self._move(RESTORING, now, "nmas", f"maintenance cycle deadline {self.cycle_deadline.isoformat()} reached")
        return True

    def finish_restore(self, *, at: datetime, restore_findings=(), remaining=None, baseline_untrusted: bool = False) -> str:
        """Close the restore.  ``restore_findings`` are the reasons the restore could not be done or validated safely
        (an unhealthy device is one); ``remaining`` is every maintenance-only statement still present (it must be
        stated, an empty tuple included).  Restored only with no finding and nothing remaining; otherwise fail closed
        and escalate.  ``baseline_untrusted`` says the unresolved state makes the topology baseline untrustworthy for
        every device, which is the only case that blocks unrelated maintenance."""
        self._require(RESTORING)
        if remaining is None:
            raise model.MaintenanceError("REMAINING_STATE_UNDOCUMENTED", "state what maintenance-only configuration is still present")
        self.maintenance_only_state, self.findings = tuple(remaining), list(restore_findings)
        self.baseline_untrusted = bool(baseline_untrusted) and bool(self.findings or self.maintenance_only_state)
        if self.findings or self.maintenance_only_state:
            self.escalated = True
            self._move(RESTORE_FAILED, at, "nmas", "restore not proven safe; escalated: " + "; ".join(f.text() for f in self.findings))
        else:
            self._move(ABORTED_RESTORED if self.restore_trigger == ENTRY_ABORT else RESTORED, at, "nmas", f"restored ({self.restore_trigger})")
        return self.state

    def retry_restore(self, actor: str, *, at: datetime) -> None:
        """An operator starts the restore workflow again after an escalation.  The escalation stays on record."""
        self._require(RESTORE_FAILED)
        self._move(RESTORING, at, actor, "restore retried by an operator")


def request(device: str, operator: str, reason: str, requested_duration, *, at: datetime, existing=()) -> Record:
    """A new maintenance record.  Refused while another maintenance of the same device is not resolved."""
    open_ones = [r for r in existing if r.request.device == device and r.state not in RESOLVED]
    if open_ones:
        raise model.MaintenanceError("MAINTENANCE_ALREADY_OPEN", f"{device} is {open_ones[0].state}")
    record = Record(model.Request(device, operator, reason, requested_duration, at))
    record.history.append({"at": at, "from": "", "to": REQUESTED, "actor": operator, "note": reason})
    return record


def unresolved(existing, *, device: str, intersects=None) -> tuple[str, ...]:
    """Devices whose unresolved maintenance refuses a new entry on ``device``.  Feeds ``gates.Facts.prior_unresolved``.

    Counted: anything of ``device`` itself that is past entry; an escalated restore on a device the plan intersects
    (``intersects``, by default the path its traffic would move to and its attached devices); and an escalated restore
    anywhere that left the topology baseline untrustworthy.  An escalated restore on an unrelated device is not."""
    related = set(policy.intersecting(device) if intersects is None else intersects)
    found = set()
    for record in existing:
        other = record.request.device
        if other == device and record.state in IN_MAINTENANCE:
            found.add(other)
        elif record.state == RESTORE_FAILED and (other in related or record.baseline_untrusted):
            found.add(other)
    return tuple(sorted(found))
