"""The immutable evidence of a maintenance transaction, and its audit events.

Every step that matters is appended as one ``MaintenanceEvidence`` row: the request, each observation, the plan, the
approval, every refusal, the drain run, the restore run, the escalation, the deadline.  The rows are append-only and
hash-chained per record (``entry_digest`` covers the payload digest and the previous entry), so a missing or altered
entry is detected by ``verify``.  The record's ``snapshot`` is only its current state; this chain is what happened.

Each appended entry also writes one ``AuditEvent`` into the one existing audit ledger (``MAINTENANCE_TRANSITION`` /
``MAINTENANCE_REFUSED`` / ``MAINTENANCE_QUEUED``) with ids, states, the plan hash and finding codes; never configuration
text, never a secret.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

from django.db import transaction

SCHEMA = 1
REQUESTED, OBSERVED, PLANNED, APPROVED, QUEUED = "REQUESTED", "OBSERVATION", "PLAN", "APPROVAL", "QUEUED"
REFUSED, ENTRY, RESTORE, TRANSITION, CLAIM = "REFUSED", "ENTRY_RUN", "RESTORE_RUN", "TRANSITION", "CLAIM"
STEP = "STEP"          # the write-ahead journal of a run: "before <operation>" / "after <operation>", one entry each, durable at once
AUDIT = {REFUSED: "MAINTENANCE_REFUSED", QUEUED: "MAINTENANCE_QUEUED"}


def _json(value):
    """The JSON form of ``value`` as it is stored (dates as ISO text): what is hashed is exactly what is kept."""
    return json.loads(json.dumps(value, default=lambda o: o.isoformat() if isinstance(o, datetime) else str(o)))


def _digest(domain: str, value) -> str:
    from ..bundles import canonical

    return canonical._digest(domain, SCHEMA, value)


def _entry_digest(record_id: str, sequence: int, kind: str, at: str, actor: str, state_from: str, state_to: str, payload_digest: str, previous: str) -> str:
    return _digest("nmas.maintenance.evidence.entry", {"record": record_id, "sequence": sequence, "kind": kind, "at": at, "actor": actor,
                                                       "from": state_from, "to": state_to, "payload": payload_digest, "previous": previous})


def append(row, *, kind: str, actor: str, at: datetime, payload: dict, state_from: str = "", state_to: str = "", summary: str = ""):
    """Append one entry to the chain of ``row`` and write its audit event.  -> the entry."""
    from core import models

    payload, at = _json(payload), at.astimezone(timezone.utc)          # stored and re-read in UTC: hashed in UTC
    with transaction.atomic():
        last = models.MaintenanceEvidence.objects.filter(record=row).order_by("-sequence").first()
        sequence, previous = (last.sequence + 1, last.entry_digest) if last else (1, "")
        payload_digest = _digest("nmas.maintenance.evidence.payload", payload)
        entry = models.MaintenanceEvidence.objects.create(
            record=row, sequence=sequence, kind=kind, at=at, actor=actor[:150], state_from=state_from, state_to=state_to, summary=summary[:300],
            payload=payload, payload_digest=payload_digest, previous_digest=previous,
            entry_digest=_entry_digest(row.record_id, sequence, kind, at.isoformat(), actor[:150], state_from, state_to, payload_digest, previous))
        if kind == STEP:                    # the journal is evidence of the run; the audit ledger keeps the run's own entries
            return entry
        models.AuditEvent.objects.create(
            event_type=AUDIT.get(kind, "MAINTENANCE_TRANSITION"), object_type="MaintenanceRecord", object_id=row.record_id, actor=actor[:150],
            summary=f"{row.record_id} {row.device_name}: {summary or kind}"[:255],
            metadata={"record": row.record_id, "device": row.device_name, "kind": kind, "sequence": sequence, "from": state_from, "to": state_to,
                      "plan_hash": row.plan_hash, "entry_digest": entry.entry_digest,
                      "codes": sorted({str(f.get("code")) for f in payload.get("findings") or [] if isinstance(f, dict) and f.get("code")})})
    return entry


def journal(row) -> dict:
    """What the step journal of ``row``'s last run says: the last event and the operation that was begun and not
    finished ('' when every begun operation was finished).  An open operation is UNKNOWN completion."""
    from core import models

    steps = list(models.MaintenanceEvidence.objects.filter(record=row, kind=STEP).order_by("sequence"))
    probes = sorted({entry.payload["probe_run"] for entry in steps if entry.payload.get("event") == "probes" and entry.payload.get("probe_run")})
    last = next((entry for entry in reversed(steps) if entry.payload.get("event") in ("before", "after")), None)
    if last is None:
        return {"last": "", "open": "", "probe_runs": probes}
    event, key = last.payload.get("event", ""), last.payload.get("operation", "")
    return {"last": f"{event} {key}".strip(), "open": key if event == "before" else "", "probe_runs": probes}


def verify(row) -> tuple[bool, list[str]]:
    """Recompute the chain of ``row``.  -> (intact, problems)."""
    from core import models

    problems, previous, expected = [], "", 1
    for entry in models.MaintenanceEvidence.objects.filter(record=row).order_by("sequence"):
        if entry.sequence != expected:
            problems.append(f"entry {expected} is missing (next is {entry.sequence})")
        payload_digest = _digest("nmas.maintenance.evidence.payload", entry.payload)
        if payload_digest != entry.payload_digest:
            problems.append(f"entry {entry.sequence}: payload does not match its digest")
        if entry.previous_digest != previous:
            problems.append(f"entry {entry.sequence}: not chained to the previous entry")
        if entry.entry_digest != _entry_digest(row.record_id, entry.sequence, entry.kind, entry.at.isoformat(), entry.actor, entry.state_from,
                                               entry.state_to, entry.payload_digest, entry.previous_digest):
            problems.append(f"entry {entry.sequence}: entry digest does not match")
        previous, expected = entry.entry_digest, entry.sequence + 1
    return not problems, problems


def entries(row) -> list:
    from core import models

    return list(models.MaintenanceEvidence.objects.filter(record=row).order_by("sequence"))
