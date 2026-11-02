"""The operator's explicit approval of the initial Golden.  The ONLY caller of the initial-Golden creation path.

    approve(run, actor=.., reason=.., confirm={run_id, candidate_id, candidate_digest, baseline_digest})

* A technical PASS never promotes anything by itself.  Golden needs this explicit call, which a view makes only on an operator POST (or the
  operator-run ``legacy_bootstrap approve`` command, which calls this same function).
* ``confirm`` is what the page SHOWED: a staleness guard compared with the current records, never an authority.  The browser cannot supply a
  manifest, a digest replacement, a timestamp or any evidence.
* IMMEDIATELY before approval the running configuration of every included device is RE-READ and compared with the observed baseline.  A device
  that differs blocks approval (a changed configuration is never silently adopted; a new bootstrap is required); an unreadable device blocks it
  too.  The Golden payload is then the candidate's pinned payload -- nothing read after approval is ever substituted for it.
* Approval sends nothing to any device: promotion is artifact + audit work.  Idempotent: a repeat returns the existing initial Golden.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from django.utils import timezone

from ... import models
from ..bundles import legacy
from ..raw_configlets import static_gate
from . import capture, lifecycle
from .codes import MAX_REASON_CHARS, blocker

Notif = models.Notification
_RECHECK_CODES = ("CONFIG_DRIFT_DETECTED", "DRIFT_CHECK_INCOMPLETE")


@dataclass
class DecisionResult:
    decision: object | None = None
    bundle: object | None = None
    created: bool = False
    blockers: list = field(default_factory=list)
    refused: bool = False
    recheck: dict | None = None


def _refuse(blockers, recheck=None) -> DecisionResult:
    return DecisionResult(blockers=list(blockers), refused=True, recheck=recheck)


def _confirmation_blockers(run, confirm) -> list:
    expected = {"run_id": run.run_id, "candidate_id": run.candidate.bundle_id, "candidate_digest": run.candidate_digest, "baseline_digest": run.candidate.payload_digest}
    given = {k: str((confirm or {}).get(k, "")) for k in expected}
    return [] if given == expected else [blocker("CONFIRMATION_MISMATCH")]


def approve(run, *, actor: str, reason: str = "", confirm: dict | None = None, now: datetime | None = None, session_factory=None) -> DecisionResult:
    """Approve THIS technically passed observation as the initial Golden.  Every server-side rule is re-checked here, whatever the page showed."""
    now = now or timezone.now()
    run = models.LegacyBootstrapRun.objects.select_related("candidate").get(pk=run.pk)
    existing = lifecycle.decision_of(run)
    if existing is not None:
        return DecisionResult(existing, existing.golden_bundle, created=False)
    reason = str(reason or "").strip()[:MAX_REASON_CHARS]
    blockers = _confirmation_blockers(run, confirm)
    if any(static_gate.secret_patterns(line) for line in reason.splitlines()):
        blockers.append(blocker("REASON_SECRET_SHAPED"))
    if blockers:
        return _refuse(blockers)
    # cheap, network-free refusals first: never read the devices for an approval that could not succeed anyway
    early = [b for b in legacy.check_initial_golden(run.candidate, run, None, now=now) if b["code"] not in _RECHECK_CODES]
    if early:
        return _refuse(early)
    recheck = capture.recheck_configuration(run.candidate, session_factory=session_factory, now=timezone.now() if now is None else now)
    result = legacy.create_initial_golden(run.candidate, evidence=run, recheck=recheck, actor=actor, reason=reason, now=now)
    if result.bundle is None:
        return _refuse(result.blockers, recheck)
    row = lifecycle.decision_of(run)
    if result.created:
        lifecycle.publish([lifecycle.note_for(
            run, Notif.EventType.GOLDEN_APPROVED, Notif.Severity.SUCCESS, f"Initial Golden approved: {result.bundle.bundle_id}",
            f"The operator approved the legacy baseline {run.candidate.bundle_id} as the INITIAL Golden ({result.bundle.bundle_id}) after {run.run_id}. "
            "Provenance: LEGACY_BOOTSTRAP. No device was contacted to create it.", "approved", golden_bundle_id=result.bundle.bundle_id)])
    return DecisionResult(row, result.bundle, created=result.created, recheck=recheck)
