"""The ONLY write/read path to the Ts* troubleshooting tables (M1).

Rules enforced here (and mirrored by model-level guards in core.models):
  * every call is tenant-scoped through an ``Actor``; cross-tenant / out-of-scope device access raises ``AccessDenied``;
  * a device is probe-able only if it is in the case's affected scope, in the actor's device scope AND its intake-time
    admission/lifecycle state is ``VERIFIED`` (unverified / withdrawn / unknown => ``TargetRefused``, audited);
  * secrets are redacted BEFORE persistence (raw blobs, JSON values); original bytes are never stored, only their hash;
  * claims cite evidence that exists in the same case; an OBSERVED claim with no evidence is refused;
  * permission-denied / failed / unavailable collection is stored as a *missing-data* record, never a fabricated value;
  * every mutating call writes a hash-chained audit event; ``verify_audit_chain`` detects any later tampering;
  * idempotency keys make collection, evidence, observations and case intake replay-safe across retry/restart.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Iterable

from django.db import IntegrityError, transaction
from django.db.models import Max

from core import models as m
from core.services.secret_policy import assert_no_secret_shaped_keys

from . import contracts as c


class AccessDenied(PermissionError):
    """Cross-tenant / out-of-scope request."""


class TargetRefused(PermissionError):
    """Device may not be probed (invalid, unverified, withdrawn or unauthorized)."""


class IntegrityError_(RuntimeError):
    """Stored evidence or journal failed an integrity check."""


@dataclass(frozen=True)
class Actor:
    name: str
    actor_type: str = "user"  # user | agent | tool | system
    tenant: str = "default"
    devices: frozenset[str] | None = None  # None == every device of the tenant
    tool_id: str = ""

    def can_see_device(self, device: str) -> bool:
        return not device or self.devices is None or device in self.devices


SYSTEM = Actor("nmas-system", "system")


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _rid(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:12]}"


def _clean(value: Any) -> Any:
    """Redact then verify the secret-key policy for structured data."""
    value = c.redact_value(value)
    if isinstance(value, (dict, list)):
        assert_no_secret_shaped_keys({"v": value}, context="troubleshooting")
    return value


# ------------------------------------------------------------------------------------------------------ audit hash chain
_AUDIT_FIELDS = ("seq", "actor", "actor_type", "tool_id", "action", "decision", "result", "risk", "approver", "operation",
                 "rationale", "evidence_ids", "occurred_at")


def _audit_digest(prev_hash: str, payload: dict[str, Any]) -> str:
    return c.sha256_text(prev_hash + "|" + c.canonical_json(payload))


def _audit_payload(ev: m.TsAuditEvent) -> dict[str, Any]:
    d = {f: getattr(ev, f) for f in _AUDIT_FIELDS}
    d["occurred_at"] = c.iso(ev.occurred_at)
    d["case"] = ev.case.case_id
    return d


def audit(actor: Actor, case: m.TsCase, action: str, *, decision: str = "", result: str = "", risk: str = "",
          approver: str = "", operation: str = "", rationale: str = "", evidence_ids: Iterable[str] = (),
          now: datetime | None = None) -> m.TsAuditEvent:
    """Append one audit event to the case's hash chain."""
    with transaction.atomic():
        last = m.TsAuditEvent.objects.filter(case=case).order_by("-seq").first()
        seq = (last.seq if last else 0) + 1
        ev = m.TsAuditEvent(
            case=case, seq=seq, actor=actor.name, actor_type=actor.actor_type, tool_id=actor.tool_id, action=action,
            decision=c.redact_text(decision)[0][:255], result=c.redact_text(result)[0][:64], risk=risk, approver=approver,
            operation=c.redact_text(operation)[0][:255], rationale=c.redact_text(rationale)[0],
            evidence_ids=list(evidence_ids), occurred_at=now or _now(), prev_hash=last.event_hash if last else "",
            event_hash="0" * 64,
        )
        ev.event_hash = _audit_digest(ev.prev_hash, _audit_payload(ev))
        ev.save()
        return ev


def verify_audit_chain(case: m.TsCase) -> list[str]:
    """Recompute the chain from the DB (bypassing ORM guards is NOT needed to detect it: any edited row mismatches)."""
    problems, prev, expected_seq = [], "", 1
    for ev in m.TsAuditEvent.objects.filter(case=case).order_by("seq").select_related("case"):
        if ev.seq != expected_seq:
            problems.append(f"audit sequence gap: expected {expected_seq}, found {ev.seq}")
            expected_seq = ev.seq
        if ev.prev_hash != prev:
            problems.append(f"audit event {ev.seq}: prev_hash does not link to the preceding event")
        if _audit_digest(ev.prev_hash, _audit_payload(ev)) != ev.event_hash:
            problems.append(f"audit event {ev.seq}: content does not match its hash (tampered)")
        prev, expected_seq = ev.event_hash, expected_seq + 1
    return problems


# ------------------------------------------------------------------------------------------------------------ case access
def get_case(actor: Actor, case_id: str) -> m.TsCase:
    case = m.TsCase.objects.filter(case_id=case_id).first()
    if case is None or case.tenant != actor.tenant:
        raise AccessDenied("case not found in the caller's tenant/project scope")
    return case


def list_cases(actor: Actor, *, state: str | None = None, device: str | None = None) -> list[m.TsCase]:
    qs = m.TsCase.objects.filter(tenant=actor.tenant)
    if state:
        qs = qs.filter(state=state)
    out = []
    for case in qs:
        devices = set(case.affected_scope.get("devices", []))
        if actor.devices is not None and not (devices & set(actor.devices)):
            continue
        if device and device not in devices:
            continue
        out.append(case)
    return out


def _case_devices(case: m.TsCase) -> set[str]:
    return set(case.affected_scope.get("devices", []))


def _check_device_scope(actor: Actor, case: m.TsCase, device: str) -> None:
    if device and not actor.can_see_device(device):
        raise AccessDenied(f"device {device!r} is outside the caller's authorization")
    if device and device not in _case_devices(case) and device not in set(case.target_states):
        raise AccessDenied(f"device {device!r} is not part of case {case.case_id}'s scope")


def _check_open(case: m.TsCase) -> None:
    if case.state in m.TS_TERMINAL_CASE_STATES:
        raise ValueError(f"case {case.case_id} is closed ({case.state}); open a follow-up case")


# ------------------------------------------------------------------------------------------------------------- intake
def open_case(actor: Actor, *, trigger_source: str, service_intent: dict | None = None, flow_scope: dict | None = None,
              affected_scope: dict | None = None, target_states: dict[str, str] | None = None, severity: str = "MEDIUM",
              trigger_ref: str = "", idempotency_key: str = "", title: str = "", symptom: str = "", runbook: str = "",
              owner: str = "", first_detected_at: datetime | None = None, last_known_good_at: datetime | None = None,
              last_known_good_ref: str = "", worked_before: bool | None = None, changed_recently: bool | None = None,
              change_window_refs: list | None = None, now: datetime | None = None) -> m.TsCase:
    """Validated incident intake (UT-001).  Replaying the same ``idempotency_key`` returns the original case."""
    if not trigger_source:
        raise ValueError("trigger_source is required")
    if severity not in ("LOW", "MEDIUM", "HIGH", "CRITICAL"):
        raise ValueError(f"invalid severity {severity!r}")
    if not (service_intent or flow_scope):
        raise ValueError("a service intent or production-flow scope is required")
    devices = list((affected_scope or {}).get("devices", []))
    if not devices or not all(isinstance(d, str) and d for d in devices):
        raise ValueError("affected_scope.devices must list at least one device")
    if actor.devices is not None and not set(devices) <= set(actor.devices):
        raise AccessDenied("affected devices outside the caller's authorization")
    if idempotency_key:
        existing = m.TsCase.objects.filter(tenant=actor.tenant, idempotency_key=idempotency_key).first()
        if existing:
            return existing
    opened = now or _now()
    with transaction.atomic():
        case = m.TsCase(
            case_id=f"TS-{opened:%Y%m%d}-{uuid.uuid4().hex[:8].upper()}", tenant=actor.tenant, trigger_source=trigger_source,
            trigger_ref=trigger_ref, idempotency_key=idempotency_key, title=title, symptom=_clean(symptom),
            runbook=runbook, service_intent=_clean(service_intent or {}), flow_scope=_clean(flow_scope or {}),
            severity=severity, affected_scope=_clean(affected_scope or {}), target_states=dict(target_states or {}),
            state=m.TsCaseState.OPEN, opened_at=opened, first_detected_at=first_detected_at,
            last_known_good_at=last_known_good_at, last_known_good_ref=last_known_good_ref, worked_before=worked_before,
            changed_recently=changed_recently, change_window_refs=list(change_window_refs or []),
            owner=owner or actor.name,
        )
        case.save()
        audit(actor, case, "CASE_OPENED", decision=f"intake from {trigger_source}", result="OK", now=opened,
              rationale=f"severity={severity}; devices={','.join(sorted(devices))}")
        from . import notify   # lazy: avoid an import cycle; best-effort, only after the case is committed
        transaction.on_commit(lambda: notify.notify_issue(case))
    return case


_TRANSITIONS = {
    "OPEN": {"SCOPING", "COLLECTING", "EXTERNALLY_BLOCKED", "NO_FAULT_FOUND"},
    "SCOPING": {"COLLECTING", "EXTERNALLY_BLOCKED"},
    "COLLECTING": {"ANALYSING", "TESTING", "UNRESOLVED", "EXTERNALLY_BLOCKED"},
    "ANALYSING": {"TESTING", "COLLECTING", "NO_FAULT_FOUND", "UNRESOLVED"},
    "TESTING": {"ANALYSING", "COLLECTING", "AI_INVESTIGATING", "REMEDIATING", "NO_FAULT_FOUND", "UNRESOLVED", "EXTERNALLY_BLOCKED"},
    "AI_INVESTIGATING": {"TESTING", "REMEDIATING", "UNRESOLVED", "NO_FAULT_FOUND", "EXTERNALLY_BLOCKED"},
    "REMEDIATING": {"VERIFYING", "UNRESOLVED", "TESTING"},
    "VERIFYING": {"RESOLVED_VERIFIED", "UNRESOLVED", "REMEDIATING", "TESTING"},
}


def transition_case(actor: Actor, case: m.TsCase, new_state: str, *, reason: str = "", now: datetime | None = None,
                    disposition: dict | None = None) -> m.TsCase:
    case = get_case(actor, case.case_id)
    if new_state not in m.TsCaseState.values:
        raise ValueError(f"unknown state {new_state!r}")
    if case.state == new_state:
        return case
    if new_state not in _TRANSITIONS.get(case.state, set()):
        raise ValueError(f"illegal case transition {case.state} -> {new_state}")
    stamp = now or _now()
    with transaction.atomic():
        old = case.state
        case.state = new_state
        if disposition is not None:
            case.disposition = _clean(disposition)
        if new_state in m.TS_TERMINAL_CASE_STATES:
            case.closed_at = stamp
        case.save()
        audit(actor, case, "CASE_STATE", decision=f"{old} -> {new_state}", result="OK", rationale=reason, now=stamp)
    return case


def close_case(actor: Actor, case: m.TsCase, state: str, *, disposition: dict, now: datetime | None = None) -> m.TsCase:
    """Close with an explicit disposition.  RESOLVED_VERIFIED requires a VERIFIED VerificationRecord (UT-074/079)."""
    if state not in [s.value for s in m.TS_TERMINAL_CASE_STATES]:
        raise ValueError("close_case needs a terminal state")
    case = get_case(actor, case.case_id)
    if state == "RESOLVED_VERIFIED" and not case.tsverificationrecord_records.filter(outcome="VERIFIED").exists():
        raise ValueError("RESOLVED_VERIFIED requires a VERIFIED verification record with a passed service check")
    return transition_case(actor, case, state, reason="close", now=now, disposition=disposition)


# ---------------------------------------------------------------------------------------------------------- probe gating
def authorize_probe(actor: Actor, case: m.TsCase, device: str, *, now: datetime | None = None) -> None:
    """Gate every outbound read (UT-002).  Refusals are themselves audited."""
    case = get_case(actor, case.case_id)
    reason = None
    if not device or not isinstance(device, str):
        reason = "invalid target"
    elif not actor.can_see_device(device):
        reason = "unauthorized for this actor"
    elif device not in _case_devices(case):
        reason = "not in case scope"
    else:
        state = case.target_states.get(device, "UNKNOWN")
        if state != "VERIFIED":
            reason = f"device state is {state}, not VERIFIED"
    if case.state in m.TS_TERMINAL_CASE_STATES:
        reason = reason or "case is closed"
    if reason:
        audit(actor, case, "PROBE_REFUSED", decision=f"{device or '<none>'}: {reason}", result="REFUSED", now=now)
        raise TargetRefused(f"{device!r} cannot be probed: {reason}")


# ------------------------------------------------------------------------------------------------------------ evidence
def store_evidence(actor: Actor, case: m.TsCase, *, source_type: str, device: str = "", command_or_api: str = "",
                   adapter: str = "", adapter_version: str = "", parser: str = "", parser_version: str = "",
                   collected_at: datetime | None = None, raw: str | bytes | None = None, raw_pointer: str = "",
                   operator_url: str = "", link_checker: Callable[[str], bool] | None = None, quality: str = "GOOD",
                   scope: dict | None = None) -> m.TsEvidenceRef:
    """Persist an immutable evidence reference (UT-004/011/012).  Idempotent: same inputs -> same ``evidence_id``."""
    case = get_case(actor, case.case_id)
    _check_device_scope(actor, case, device)
    collected = collected_at or _now()
    blob = None
    raw_hash, size, status = "", 0, "NOT_APPLICABLE"
    if raw is not None:
        original = raw.encode("utf-8", "replace") if isinstance(raw, str) else raw
        raw_hash, size = c.sha256_text(original), len(original)
        text, n = c.redact_text(original.decode("utf-8", "replace"))
        status = "REDACTED" if n else "CLEAN"
        stored = c.sha256_text(text)
        blob = m.TsEvidenceBlob.objects.filter(stored_sha256=stored).first() or m.TsEvidenceBlob.objects.create(
            stored_sha256=stored, raw_sha256=raw_hash, content=text, size_bytes=len(text.encode()), redaction_count=n)
    if quality not in c.QUALITIES:
        raise ValueError(f"invalid quality {quality!r}")
    # Operator URL is recorded exactly as supplied or not at all -- never synthesised (UT-011).
    if not operator_url:
        link_status, note = "MISSING", "no operator-view URL exists for this evidence"
    elif link_checker is None:
        link_status, note = "UNVERIFIED", "link not verified"
    else:
        ok = bool(link_checker(operator_url))
        link_status, note = ("OK", "") if ok else ("BROKEN", "link target did not resolve")
    evidence_id = "EV-" + c.sha256_text(c.canonical_json(
        [case.case_id, source_type, device, command_or_api, c.iso(collected), raw_hash, raw_pointer]))[:14]
    existing = m.TsEvidenceRef.objects.filter(evidence_id=evidence_id).first()
    if existing:
        return existing
    with transaction.atomic():
        ref = m.TsEvidenceRef.objects.create(
            evidence_id=evidence_id, case=case, source_type=source_type, device=device,
            command_or_api=command_or_api, adapter=adapter, adapter_version=adapter_version, parser=parser,
            parser_version=parser_version, collected_at=collected, raw_sha256=raw_hash, raw_blob=blob,
            raw_pointer=raw_pointer, raw_size_bytes=size, redaction_status=status, operator_url=operator_url,
            link_status=link_status, link_note=note, quality=quality, scope=_clean(scope or {}))
        audit(actor, case, "EVIDENCE_STORED", decision=f"{source_type}:{device}:{command_or_api}"[:255], result=link_status,
              evidence_ids=[evidence_id], now=collected)
    return ref


def get_evidence(actor: Actor, evidence_id: str) -> m.TsEvidenceRef:
    ref = m.TsEvidenceRef.objects.select_related("case").filter(evidence_id=evidence_id).first()
    if ref is None or ref.case.tenant != actor.tenant or not actor.can_see_device(ref.device):
        raise AccessDenied("evidence not found in the caller's scope")
    return ref


def read_raw_evidence(actor: Actor, evidence_id: str, *, privileged: bool = False) -> str:
    """On-demand raw (already redacted) evidence.  Verifies the stored hash; requires an explicit privileged flag."""
    ref = get_evidence(actor, evidence_id)
    if not privileged:
        raise AccessDenied("raw evidence requires an explicit privileged on-demand request")
    if ref.raw_blob is None:
        raise ValueError("no raw content is held for this evidence (see raw_pointer)")
    if c.sha256_text(ref.raw_blob.content) != ref.raw_blob.stored_sha256:
        raise IntegrityError_(f"raw evidence {evidence_id} failed its integrity check")
    audit(actor, ref.case, "RAW_EVIDENCE_READ", decision=evidence_id, result="OK", evidence_ids=[evidence_id])
    return ref.raw_blob.content


def _validate_evidence_ids(case: m.TsCase, ids: Iterable[str]) -> list[str]:
    ids = list(dict.fromkeys(ids))
    found = set(m.TsEvidenceRef.objects.filter(case=case, evidence_id__in=ids).values_list("evidence_id", flat=True))
    missing = [i for i in ids if i not in found]
    if missing:
        raise ValueError(f"unknown evidence for case {case.case_id}: {', '.join(missing)}")
    return ids


# ------------------------------------------------------------------------------------------------- collection runs (UT-007)
def begin_collection_run(actor: Actor, case: m.TsCase, *, idempotency_key: str, collector: str, targets: list[str],
                         command_or_api: str, adapter: str = "", adapter_version: str = "", privileges: str = "read-only",
                         timeout_seconds: int = 30, max_attempts: int = 3, rate_budget: dict | None = None,
                         stage: str = "COLLECT", now: datetime | None = None) -> m.TsCollectionRun:
    """Create (or return the existing) run.  Every target must pass the probe gate.  Write privileges are refused."""
    case = get_case(actor, case.case_id)
    _check_open(case)
    existing = m.TsCollectionRun.objects.filter(case=case, idempotency_key=idempotency_key).first()
    if existing:
        return existing
    if privileges != "read-only":
        audit(actor, case, "RUN_REFUSED", decision=f"{collector}: privileges={privileges}", result="REFUSED", now=now)
        raise TargetRefused("troubleshooting collection is read-only")
    if stage not in c.STAGES:
        raise ValueError(f"invalid stage {stage!r}")
    for t in targets:
        authorize_probe(actor, case, t, now=now)
    with transaction.atomic():
        seq = (m.TsCollectionRun.objects.filter(case=case).aggregate(x=Max("seq"))["x"] or 0) + 1
        run = m.TsCollectionRun.objects.create(
            record_id=_rid("RUN"), case=case, stage=stage, seq=seq, idempotency_key=idempotency_key, collector=collector,
            adapter=adapter, adapter_version=adapter_version, targets=list(targets), privileges=privileges,
            command_or_api=_clean(command_or_api), timeout_seconds=timeout_seconds, max_attempts=max_attempts,
            rate_budget=_clean(rate_budget or {}), status="PENDING")
        audit(actor, case, "RUN_PLANNED", decision=f"#{seq} {collector} {command_or_api}"[:255], result="PENDING", now=now)
    return run


def start_attempt(actor: Actor, run: m.TsCollectionRun, *, now: datetime | None = None) -> m.TsCollectionRun:
    run = m.TsCollectionRun.objects.get(pk=run.pk)
    get_case(actor, run.case.case_id)
    if run.status in m.TsCollectionRun.FINAL:
        return run
    if run.attempts >= run.max_attempts:
        return finish_run(actor, run, "FAILED", error="retry budget exhausted", now=now)
    run.attempts += 1
    run.status = "RUNNING"
    run.started_at = run.started_at or now or _now()
    run.save()
    return run


def finish_run(actor: Actor, run: m.TsCollectionRun, status: str, *, error: str = "", raw_ref: m.TsEvidenceRef | None = None,
               now: datetime | None = None) -> m.TsCollectionRun:
    if status not in m.TsCollectionRun.FINAL:
        raise ValueError(f"{status!r} is not a final run status")
    run = m.TsCollectionRun.objects.get(pk=run.pk)
    get_case(actor, run.case.case_id)
    if run.status in m.TsCollectionRun.FINAL:
        return run  # idempotent on duplicate completion
    run.status, run.error = status, c.redact_text(error)[0][:512]
    run.finished_at = now or _now()
    run.raw_ref = raw_ref
    run.save()
    audit(actor, run.case, "RUN_FINISHED", decision=f"#{run.seq} {run.collector}", result=status, rationale=run.error,
          evidence_ids=[raw_ref.evidence_id] if raw_ref else [], now=run.finished_at)
    return run


def resumable_runs(actor: Actor, case: m.TsCase) -> list[m.TsCollectionRun]:
    """After a restart: unfinished runs, in their original order, ready for ``start_attempt``."""
    case = get_case(actor, case.case_id)
    return list(m.TsCollectionRun.objects.filter(case=case).exclude(status__in=m.TsCollectionRun.FINAL).order_by("seq"))


# ----------------------------------------------------------------------------------------------------------- observations
def record_observation(actor: Actor, case: m.TsCase, *, key: str, target: str, observed_at: datetime, value: Any = None,
                       unit: str = "", source: str = "", quality: str = "GOOD", basis: str = "OBSERVED",
                       run: m.TsCollectionRun | None = None, evidence: m.TsEvidenceRef | None = None,
                       evidence_ids: Iterable[str] = (), max_age_seconds: int = 300, confidence: float = 1.0,
                       parser_version: str = "", stage: str = "NORMALIZE", stage_decision: str = "", dedupe_key: str = "",
                       is_missing_data: bool = False, missing_reason: str = "") -> m.TsObservation:
    case = get_case(actor, case.case_id)
    _check_open(case)
    _check_device_scope(actor, case, target)
    if quality not in c.QUALITIES or basis not in c.BASES:
        raise ValueError("invalid quality or basis")
    if dedupe_key:
        existing = m.TsObservation.objects.filter(case=case, dedupe_key=dedupe_key).first()
        if existing:
            return existing
    ids = list(evidence_ids) + ([evidence.evidence_id] if evidence else [])
    if is_missing_data:
        value, quality = None, "MISSING"
    elif basis == "OBSERVED" and not ids:
        raise ValueError("an OBSERVED observation must cite source evidence")
    ids = _validate_evidence_ids(case, ids)
    ev = evidence or (m.TsEvidenceRef.objects.filter(evidence_id=ids[0]).first() if ids else None)
    try:
        with transaction.atomic():
            return m.TsObservation.objects.create(
                record_id=_rid("OBS"), case=case, basis=basis, stage=stage, stage_decision=stage_decision, evidence_ids=ids,
                run=run, evidence=ev, dedupe_key=dedupe_key, key=key, value=_clean(value), unit=unit, target=target,
                observed_at=observed_at, max_age_seconds=max_age_seconds, source=source, quality=quality,
                confidence=confidence, parser_version=parser_version, raw_hash=ev.raw_sha256 if ev else "",
                raw_pointer=ev.raw_pointer if ev else "", redaction_status=ev.redaction_status if ev else "NOT_APPLICABLE",
                is_missing_data=is_missing_data, missing_reason=c.redact_text(missing_reason)[0][:255])
    except IntegrityError:  # concurrent replay of the same dedupe_key
        return m.TsObservation.objects.get(case=case, dedupe_key=dedupe_key)


def record_missing_data(actor: Actor, case: m.TsCase, *, key: str, target: str, reason: str, observed_at: datetime | None = None,
                        run: m.TsCollectionRun | None = None, source: str = "", dedupe_key: str = "") -> m.TsObservation:
    """Permission denied / timeout / unsupported => an explicit gap record (UT-024); no value is invented."""
    return record_observation(actor, case, key=key, target=target, observed_at=observed_at or _now(), source=source,
                              run=run, is_missing_data=True, missing_reason=reason, basis="OBSERVED", dedupe_key=dedupe_key)


def evaluate_observation(obs: m.TsObservation, now: datetime) -> str:
    return c.freshness(obs.observed_at, obs.max_age_seconds, now, quality=obs.quality, is_missing=obs.is_missing_data)


def current_state(actor: Actor, case: m.TsCase, key: str, target: str, now: datetime,
                  predicate: Callable[[Any], bool] | None = None) -> dict[str, Any]:
    """Latest usable observation -> HEALTHY/FAULT/UNKNOWN with the reason (UT-006/087).  Never claims live status from stale data."""
    case = get_case(actor, case.case_id)
    qs = m.TsObservation.objects.filter(case=case, key=key, target=target).order_by("-observed_at", "-id")
    latest = qs.first()
    if latest is None:
        return {"state": c.UNKNOWN, "freshness": c.NO_DATA, "reason": "no observation exists", "observation_id": ""}
    fr = evaluate_observation(latest, now)
    result = None if (predicate is None or fr != c.FRESH) else bool(predicate(latest.value))
    reason = {c.FRESH: "fresh observation", c.STALE: "latest observation is stale", c.NO_DATA: latest.missing_reason or "data missing",
              c.UNTRUSTED: "latest observation is untrusted"}[fr]
    return {"state": c.tri_state(fr, result), "freshness": fr, "reason": reason, "observation_id": latest.record_id,
            "observed_at": c.iso(latest.observed_at), "age_seconds": int((now - latest.observed_at).total_seconds())}


# ------------------------------------------------------------------------------------------------- collection bundle ingest
def ingest_collection_bundle(actor: Actor, bundle: dict[str, Any], *, now: datetime | None = None) -> m.TsCollectionRun:
    """Validate a ``collection_bundle/1`` and persist run + evidence + observations atomically; replay-safe."""
    c.assert_valid(bundle, "collection_bundle/1")
    case = get_case(actor, bundle["case_id"])
    run = begin_collection_run(
        actor, case, idempotency_key=bundle["idempotency_key"], collector=bundle["collector"], targets=bundle["targets"],
        command_or_api=bundle["command_or_api"], adapter=bundle["adapter"], adapter_version=bundle["adapter_version"],
        privileges=bundle.get("privileges", "read-only"), timeout_seconds=bundle.get("timeout_seconds", 30), now=now,
        rate_budget=bundle.get("rate_budget"))
    if run.status in m.TsCollectionRun.FINAL:
        return run
    with transaction.atomic():
        start_attempt(actor, run, now=c.parse_time(bundle.get("started_at")) or now)
        raw = bundle.get("raw") or {}
        ref = None
        if bundle["status"] in ("SUCCEEDED", "PARTIAL", "FAILED") and (raw or bundle["targets"]):
            ref = store_evidence(
                actor, case, source_type=raw.get("source_type", "cli"), device=bundle["targets"][0] if bundle["targets"] else "",
                command_or_api=bundle["command_or_api"], adapter=bundle["adapter"], adapter_version=bundle["adapter_version"],
                parser=raw.get("parser", ""), parser_version=raw.get("parser_version", ""),
                collected_at=c.parse_time(bundle.get("finished_at")) or now, raw=raw.get("text"),
                raw_pointer=raw.get("pointer", ""), operator_url=raw.get("operator_url", ""))
        for o in bundle["observations"]:
            if o.get("is_missing_data"):
                record_missing_data(actor, case, key=o["key"], target=o["target"], reason=o.get("missing_reason", "unavailable"),
                                    observed_at=c.parse_time(o["observed_at"]), run=run, source=o["source"],
                                    dedupe_key=o.get("dedupe_key", ""))
            else:
                record_observation(
                    actor, case, key=o["key"], target=o["target"], observed_at=c.parse_time(o["observed_at"]), value=o.get("value"),
                    unit=o.get("unit", ""), source=o["source"], quality=o["quality"], basis=o["basis"], run=run,
                    evidence_ids=[ref.evidence_id] if ref else [o["evidence_id"]] if o.get("evidence_id") else [],
                    max_age_seconds=o.get("max_age_seconds", 300), confidence=o.get("confidence", 1.0),
                    parser_version=o.get("parser_version", ""), dedupe_key=o.get("dedupe_key", ""),
                    stage_decision=o.get("stage_decision", ""))
        return finish_run(actor, run, bundle["status"] if bundle["status"] in m.TsCollectionRun.FINAL else "FAILED",
                          error=bundle.get("error", ""), raw_ref=ref, now=c.parse_time(bundle.get("finished_at")) or now)


# ------------------------------------------------------------------------------------------------------- diagnostic tests
def record_test(actor: Actor, case: m.TsCase, verdict_doc: dict[str, Any], *, now: datetime | None = None) -> m.TsDiagnosticTest:
    """Persist a ``test_verdict/1``.  PASS/FAIL need evidence; SKIPPED/UNAVAILABLE/INCONCLUSIVE need a specific reason (UT-009/041)."""
    c.assert_valid(verdict_doc, "test_verdict/1")
    case = get_case(actor, case.case_id)
    _check_open(case)
    verdict = verdict_doc["verdict"]
    ids = _validate_evidence_ids(case, verdict_doc.get("evidence_ids", []))
    if verdict in ("PASS", "FAIL") and not ids:
        raise ValueError(f"a {verdict} verdict must cite source evidence; otherwise record INCONCLUSIVE/UNAVAILABLE")
    if verdict != "PASS" and len(verdict_doc.get("reason", "").strip()) < 8:
        raise ValueError(f"a {verdict} test needs a specific reason")
    hyp = m.TsHypothesis.objects.filter(case=case, record_id=verdict_doc.get("hypothesis", "")).first()
    with transaction.atomic():
        seq = (m.TsDiagnosticTest.objects.filter(case=case).aggregate(x=Max("seq"))["x"] or 0)
        attempt = verdict_doc.get("attempt", 1)
        if attempt > 1:  # retry of the latest test with same id keeps its seq
            prev = m.TsDiagnosticTest.objects.filter(case=case, test_id=verdict_doc["test_id"]).order_by("-seq", "-attempt").first()
            seq = prev.seq if prev else seq + 1
        else:
            seq += 1
        test = m.TsDiagnosticTest.objects.create(
            record_id=_rid("TST"), case=case, basis=verdict_doc.get("basis", "OBSERVED"), stage="TEST",
            stage_decision=f"{verdict_doc['test_id']} -> {verdict}", evidence_ids=ids, seq=seq, attempt=attempt,
            test_id=verdict_doc["test_id"], test_version=verdict_doc["test_version"], hypothesis=hyp,
            hypothesized_condition=verdict_doc.get("hypothesized_condition", ""), preconditions=_clean(verdict_doc.get("preconditions", [])),
            target=verdict_doc["target"], command_or_api=_clean(verdict_doc.get("command_or_api", "")),
            expected=verdict_doc["expected"], observed=_clean(verdict_doc.get("observed", {})),
            observed_summary=c.redact_text(verdict_doc.get("observed_summary", ""))[0][:512], verdict=verdict,
            reason=c.redact_text(verdict_doc.get("reason", ""))[0][:512], interpretation=verdict_doc.get("interpretation", "")[:512],
            next_action=verdict_doc.get("next_action", "")[:255], executed_at=c.parse_time(verdict_doc.get("executed_at")) or now or _now())
        audit(actor, case, "TEST_RECORDED", decision=f"{test.test_id} {verdict}", result=verdict, evidence_ids=ids, now=now)
    return test


# ---------------------------------------------------------- generic typed records (baseline/drift/correlation/hypothesis/...)
_KINDS: dict[str, type] = {
    "baseline": m.TsBaselineReference, "drift": m.TsDriftAssessment, "topology_path": m.TsTopologyPath,
    "hypothesis": m.TsHypothesis, "correlation": m.TsCorrelationRecord, "flow_monitor": m.TsProductionFlowMonitor,
    "exception": m.TsExceptionPolicy, "ai_handoff": m.TsAIHandoff, "remediation_plan": m.TsRemediationPlan,
    "verification": m.TsVerificationRecord,
}
_PREFIX = {"baseline": "BSL", "drift": "DRF", "topology_path": "TPA", "hypothesis": "HYP", "correlation": "COR",
           "flow_monitor": "PFM", "exception": "EXC", "ai_handoff": "AIH", "remediation_plan": "RPL", "verification": "VER"}
_STAGE = {"baseline": "BASELINE", "drift": "BASELINE", "topology_path": "CORRELATE", "hypothesis": "DIAGNOSE",
          "correlation": "CORRELATE", "flow_monitor": "BASELINE", "exception": "BASELINE", "ai_handoff": "AI",
          "remediation_plan": "REMEDIATE", "verification": "VERIFY"}
_NEEDS_EVIDENCE = {"drift", "correlation", "topology_path", "baseline"}


def record(actor: Actor, case: m.TsCase, kind: str, *, basis: str = "OBSERVED", evidence_ids: Iterable[str] = (),
           stage: str = "", stage_decision: str = "", now: datetime | None = None, **fields: Any):
    """Create one typed record.  JSON/text fields are redacted; evidence must exist in-case; derived claims need evidence."""
    model = _KINDS.get(kind)
    if model is None:
        raise ValueError(f"unknown record kind {kind!r}; known: {sorted(_KINDS)}")
    case = get_case(actor, case.case_id)
    _check_open(case)
    if basis not in c.BASES:
        raise ValueError(f"invalid basis {basis!r}")
    ids = _validate_evidence_ids(case, evidence_ids)
    if kind in _NEEDS_EVIDENCE and not ids and basis != "OPERATOR_CONFIRMED":
        raise ValueError(f"a {kind} record must cite source evidence")
    if kind == "exception":
        fields.setdefault("requested_by", actor.name)
    if kind == "hypothesis" and not ids and fields.get("state", "OPEN") not in ("OPEN", "UNVERIFIED", "ELIMINATED"):
        raise ValueError("a supported/confirmed hypothesis must cite evidence")
    if kind == "hypothesis" and basis == "AI_INFERRED" and not (fields.get("supporting_evidence") or ids):
        fields["state"] = "UNVERIFIED"  # unsupported AI claim is marked unverified (UT-060)
    clean = {k: (_clean(v) if isinstance(v, (dict, list, str)) else v) for k, v in fields.items()}
    if "baseline" in clean and isinstance(clean["baseline"], dict) and kind == "drift":
        pass
    with transaction.atomic():
        obj = model.objects.create(record_id=_rid(_PREFIX[kind]), case=case, basis=basis, stage=stage or _STAGE[kind],
                                   stage_decision=stage_decision, evidence_ids=ids, **clean)
        audit(actor, case, f"{kind.upper()}_RECORDED", decision=f"{obj.record_id} {stage_decision}"[:255], result="OK",
              evidence_ids=ids, now=now)
    return obj


def update_hypothesis(actor: Actor, hypothesis: m.TsHypothesis, *, state: str, rationale: str = "",
                      supporting: Iterable[str] = (), contradicting: Iterable[str] = (), confidence: float | None = None,
                      now: datetime | None = None) -> m.TsHypothesis:
    case = get_case(actor, hypothesis.case.case_id)
    hyp = m.TsHypothesis.objects.get(pk=hypothesis.pk)
    sup = _validate_evidence_ids(case, list(hyp.supporting_evidence) + list(supporting))
    con = _validate_evidence_ids(case, list(hyp.contradicting_evidence) + list(contradicting))
    if state in ("SUPPORTED", "CONFIRMED") and not sup:
        raise ValueError(f"{state} requires supporting evidence")
    if state == "ELIMINATED" and len(rationale.strip()) < 8:
        raise ValueError("elimination needs a rationale")
    old = hyp.state
    hyp.state, hyp.supporting_evidence, hyp.contradicting_evidence = state, sup, con
    if confidence is not None:
        hyp.confidence = confidence
    if state == "ELIMINATED":
        hyp.elimination_rationale = c.redact_text(rationale)[0]
    hyp.save()
    audit(actor, case, "HYPOTHESIS_UPDATED", decision=f"{hyp.record_id}: {old} -> {state}", result="OK", rationale=rationale,
          evidence_ids=sup + con, now=now)
    return hyp


# --------------------------------------------------------------------------------------------------- exception policies
def exception_status(policy: m.TsExceptionPolicy, current_revisions: dict[str, str], now: datetime) -> str:
    """ACTIVE only while unexpired and every bound policy/config revision is unchanged (UT-033)."""
    if policy.status != "ACTIVE":
        return policy.status
    if policy.expires_at <= now:
        return "EXPIRED"
    for name, rev in policy.bound_revisions.items():
        if current_revisions.get(name) != rev:
            return "INVALIDATED"
    return "ACTIVE"


# ------------------------------------------------------------------------------------------------- traceability / ordering
def trace_claim(actor: Actor, case: m.TsCase, record_id: str) -> dict[str, Any]:
    """Resolve a record to {basis, stage, stage_decision, evidence} (UT-010).  Dangling references are reported, not hidden."""
    case = get_case(actor, case.case_id)
    for model in (m.TsObservation, m.TsDiagnosticTest, *_KINDS.values(), m.TsCollectionRun):
        obj = model.objects.filter(case=case, record_id=record_id).first()
        if obj:
            refs = {r.evidence_id: r for r in m.TsEvidenceRef.objects.filter(case=case, evidence_id__in=obj.evidence_ids)}
            return {"record_id": record_id, "kind": model.__name__, "basis": obj.basis, "stage": obj.stage,
                    "stage_decision": obj.stage_decision,
                    "evidence": [{"evidence_id": i, "source_type": refs[i].source_type, "device": refs[i].device,
                                  "raw_sha256": refs[i].raw_sha256, "operator_url": refs[i].operator_url,
                                  "link_status": refs[i].link_status} for i in obj.evidence_ids if i in refs],
                    "missing_evidence": [i for i in obj.evidence_ids if i not in refs],
                    "traceable": bool(obj.evidence_ids) and all(i in refs for i in obj.evidence_ids) and bool(obj.stage)}
    raise AccessDenied("record not found in this case")


def stage_journal(actor: Actor, case: m.TsCase) -> list[dict[str, Any]]:
    """Case timeline ordered by (stage order, per-stage sequence, creation id) -- stable across retry/restart (UT-007)."""
    case = get_case(actor, case.case_id)
    rows = []
    for run in m.TsCollectionRun.objects.filter(case=case):
        rows.append((c.STAGES.index("COLLECT"), run.seq, 0, "collection_run", run.record_id, f"{run.collector} {run.status}"))
    for t in m.TsDiagnosticTest.objects.filter(case=case):
        rows.append((c.STAGES.index("TEST"), t.seq, t.attempt, "test", t.record_id, f"{t.test_id} {t.verdict}"))
    for kind, model in _KINDS.items():
        for o in model.objects.filter(case=case).order_by("id"):
            rows.append((c.STAGES.index(o.stage) if o.stage in c.STAGES else 99, 0, o.id, kind, o.record_id, o.stage_decision))
    rows.sort(key=lambda r: r[:3] + (r[4],))
    return [{"stage": c.STAGES[r[0]] if r[0] < len(c.STAGES) else "?", "kind": r[3], "record_id": r[4], "summary": r[5]} for r in rows]


# ------------------------------------------------------------------------------------------------------------------ export
def export_case(actor: Actor, case: m.TsCase, *, now: datetime | None = None, retention_days: int = 365) -> dict[str, Any]:
    """Redacted, integrity-checked, retention-labelled export (UT-090).  Refuses to export a case whose journal/blobs fail verification."""
    case = get_case(actor, case.case_id)
    problems = verify_audit_chain(case)
    for ref in m.TsEvidenceRef.objects.filter(case=case).select_related("raw_blob"):
        if ref.raw_blob and c.sha256_text(ref.raw_blob.content) != ref.raw_blob.stored_sha256:
            problems.append(f"evidence {ref.evidence_id}: raw blob hash mismatch")
    if problems:
        raise IntegrityError_("; ".join(problems))
    stamp = now or _now()
    def rows(model, fields):
        return [{f: _plain(getattr(o, f)) for f in fields} for o in model.objects.filter(case=case).order_by("id")]
    doc = {
        "schema": "nmas.troubleshooting.export/1", "case_id": case.case_id, "exported_at": c.iso(stamp),
        "retention_until": c.iso(stamp.replace(microsecond=0) + timedelta(days=retention_days)),
        "evidence": rows(m.TsEvidenceRef, ["evidence_id", "source_type", "device", "command_or_api", "raw_sha256", "operator_url", "link_status", "redaction_status"]),
        "observations": rows(m.TsObservation, ["record_id", "key", "target", "value", "unit", "observed_at", "quality", "basis", "evidence_ids", "is_missing_data"]),
        "tests": rows(m.TsDiagnosticTest, ["record_id", "seq", "test_id", "target", "verdict", "reason", "observed_summary", "evidence_ids"]),
        "audit": rows(m.TsAuditEvent, ["seq", "actor", "action", "decision", "result", "occurred_at", "event_hash"]),
        "audit_chain_head": (m.TsAuditEvent.objects.filter(case=case).order_by("-seq").values_list("event_hash", flat=True).first() or ""),
    }
    doc = c.redact_value(doc)
    audit(actor, case, "CASE_EXPORTED", decision="export", result="OK", now=stamp)
    return doc


def _plain(v: Any) -> Any:
    return c.iso(v) if isinstance(v, datetime) else v
