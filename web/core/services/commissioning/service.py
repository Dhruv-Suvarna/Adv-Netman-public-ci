"""Governed commissioning of one ISOLATED, natively onboarded device (``COM-000001``): the one writer of ``CommissioningRecord``.

    open      -> OPEN        the device is ISOLATED behind a VERIFIED policy; a ProvisioningRun (transport ZTP_MANAGEMENT) is
                             created for its production configuration and bound to the record
    (operator)               the run walks the ordinary provisioning stages: bootstrap classification over the commissioning
                             transport, capability, IPAM planning, Device Builder candidate, validation, plan, precheck
    assess    -> READY       every readiness check passes; the evidence (identity, attachment, authorization, native ZTP,
                             credential retirement, isolation, dependencies, candidate) is frozen and hashed.
                             Lifecycle ISOLATED -> READY_FOR_COMMISSIONING.  A failing re-assessment returns to OPEN.
    approve   -> APPROVED    another operator confirms the evidence hash; the provisioning run is approved by the same act.
                             Lifecycle READY_FOR_COMMISSIONING -> COMMISSIONING.
    (operator)               the run executes through the ordinary execution engine (its gate re-checks this record's freshness)
    record_configuration     the run POSTCHECKED and the isolation still reads back intact -> CONFIGURED (still isolated);
                             a restored failure -> ABORTED (lifecycle back to ISOLATED); an unproven one -> UNCERTAIN
    reconcile                UNCERTAIN after an unproven restoration -> ABORTED only when a fresh device read matches the run's
                             pre-execution digest (otherwise it stays UNCERTAIN)
    admission                ``core.services.commissioning.admission`` (controlled isolation release)

Native ZTP: EOS disables ZeroTouch itself once its startup-config is saved (Phase 3 evidence); readiness records the device's
OBSERVED ztp_state and never treats ZTP completion as admission.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import timedelta

from django.conf import settings
from django.db import IntegrityError, transaction
from django.utils import timezone

from ... import models
from .. import provisioning_service as ps
from ..devices import events, lifecycle
from ..devices.codes import blocker, codes
from ..isolation import service as isolation
from . import dependencies, transport

St = models.CommissioningState
S = models.DeviceLifecycleState
P = models.ProvisioningStatus
Outcome = models.DeviceLifecycleEventOutcome
CANDIDATE_READY = (P.PRECHECKED,)
CANDIDATE_APPROVED = (P.PRECHECKED, P.APPROVED, P.PROVISIONING)  # PRECHECKED: the instant the approval itself is evaluated


def approval_max_age_seconds() -> float:
    return float(getattr(settings, "NMAS_COMMISSIONING_APPROVAL_MAX_AGE_SECONDS", 8 * 3600))


@dataclass
class CommissioningResult:
    ok: bool
    action: str
    record: object | None = None
    blockers: list = field(default_factory=list)
    detail: dict = field(default_factory=dict)

    @property
    def codes(self) -> list[str]:
        return codes(self.blockers)


def get_record(record_id):
    text = str(record_id or "")
    pk = int(text[4:]) if text.startswith("COM-") and text[4:].isdigit() else (int(text) if text.isdigit() else None)
    return models.CommissioningRecord.objects.select_related("device", "isolation_policy", "provisioning_run").filter(pk=pk).first() if pk else None


def open_record(device):
    return models.CommissioningRecord.objects.filter(device=device, state__in=tuple(models.COMMISSIONING_OPEN)).first()


def _actor_kind(actor: str) -> str:
    return events.AUTOMATION if actor.startswith("system:") else events.HUMAN


def _event(device, action: str, outcome: str, *, actor: str, record=None, blockers=(), evidence=None):
    fresh = models.ManagedDevice.objects.select_for_update().get(pk=device.pk)
    return events.record(fresh, action, outcome, actor=actor, actor_kind=_actor_kind(actor), from_state=fresh.lifecycle_state,
                         to_state=fresh.lifecycle_state, blockers=list(blockers),
                         evidence={"commissioning": record.commissioning_id if record is not None and record.pk else "", **(evidence or {})})


def _refuse(device, action, problems, *, actor, record=None) -> CommissioningResult:
    with transaction.atomic():
        _event(device, action, Outcome.REFUSED, actor=actor, record=record, blockers=problems)
    return CommissioningResult(False, action, record, list(problems))


class _Stale(Exception):
    pass


class _Abort(Exception):
    def __init__(self, blockers):
        super().__init__("abort")
        self.blockers = blockers


def _save(record, **fields):
    fresh = models.CommissioningRecord.objects.select_for_update().get(pk=record.pk)
    if fresh.version != record.version:
        raise _Stale()
    for name, value in fields.items():
        setattr(fresh, name, value)
    fresh.version += 1
    fresh.__dict__["_commissioning_write"] = True
    fresh.save()
    return fresh


def _transition(device, to_state: str, *, actor: str, record) -> None:
    """Move the device along a commissioning edge inside the caller's transaction (raises _Abort on refusal)."""
    fresh = models.ManagedDevice.objects.get(pk=device.pk)
    if fresh.lifecycle_state == to_state:
        return
    result = lifecycle.transition(fresh, to_state, actor=actor, actor_kind=_actor_kind(actor), evidence={"commissioning": record.commissioning_id})
    if not result.ok:
        raise _Abort(result.blockers)


# ------------------------------------------------------------------------------------------------------------- open
def session_of(device):
    return models.ZtpSession.objects.select_related("authorization", "network").filter(
        device=device, stage=models.ZtpSessionStage.BOOTSTRAPPED).order_by("-id").first()


def management_of(device, policy) -> dict:
    """The device's management addressing as the ZTP session established it (never typed by a person)."""
    import ipaddress

    session = session_of(device)
    if session is None:
        return {}
    prefixlen = ipaddress.ip_network(session.network.ipv4_prefix).prefixlen
    return {"interface": policy.attachment.local_interface, "ipv4": f"{session.reserved_address}/{prefixlen}", "assignment": "static"}


def open_problems(device) -> list[dict]:
    problems = []
    if device.is_terminal or device.origin != models.DeviceOrigin.REGISTERED_NEW:
        return [blocker("COMMISSIONING_STATE_INVALID", origin=device.origin, state=device.lifecycle_state)]
    if device.lifecycle_state != S.ISOLATED:
        problems.append(blocker("COMMISSIONING_DEVICE_NOT_ISOLATED", state=device.lifecycle_state))
    if open_record(device) is not None:
        problems.append(blocker("COMMISSIONING_OPEN_EXISTS"))
    policy = isolation.device_policy(device)
    if policy is None or policy.state != models.IsolationState.VERIFIED:
        problems.append(blocker("ISOLATION_NOT_VERIFIED", state=getattr(policy, "state", "")))
    found = transport.problems(device, purpose="READ")
    if found:
        problems.append(blocker("COMMISSIONING_TRANSPORT_UNAVAILABLE", reasons=found))
    return problems


def open_commissioning(device, *, actor: str, role: str = "") -> CommissioningResult:
    """Open the commissioning of an ISOLATED device and create its production-configuration ProvisioningRun (ZTP_MANAGEMENT)."""
    action = "COM_OPEN"
    problems = open_problems(device)
    if problems:
        return _refuse(device, action, problems, actor=actor)
    policy = isolation.device_policy(device)
    request = ps.create_request(device_name=device.name, platform=device.platform, role=role or device.role, requested_by=actor)
    if not request.ok:
        return _refuse(device, action, [blocker("COMMISSIONING_STATE_INVALID", provisioning=request.codes)], actor=actor)
    run = request.run
    identified = ps.define_identity(run, actor=actor, bootstrap_transport=models.BootstrapTransport.ZTP_MANAGEMENT,
                                    bootstrap_target={"device": device.device_id}, management=management_of(device, policy))
    if not identified.ok:
        ps.cancel(run, actor=actor, reason="commissioning could not bind the device identity")
        return _refuse(device, action, [blocker("COMMISSIONING_STATE_INVALID", provisioning=identified.codes)], actor=actor)
    try:
        with transaction.atomic():
            record = models.CommissioningRecord(device=device, isolation_policy=policy, provisioning_run=run, requested_by=actor[:150])
            record.__dict__["_commissioning_write"] = True
            record.save()
            dependencies.derive(device, actor=actor)
            _event(device, action, Outcome.RECORDED, actor=actor, record=record, evidence={"provisioning_run": run.prov_id, "policy": policy.policy_id})
    except IntegrityError:
        ps.cancel(run, actor=actor, reason="another commissioning opened concurrently")
        return _refuse(device, action, [blocker("COMMISSIONING_OPEN_EXISTS")], actor=actor)
    return CommissioningResult(True, action, record, [], {"provisioning_run": run.prov_id})


# ------------------------------------------------------------------------------------------------------------- readiness
def _check(rows, name, ok, code, detail=""):
    rows.append({"check": name, "ok": bool(ok), "code": "" if ok else code, "detail": str(detail)[:200]})


def authorization_intact(auth) -> bool:
    """The bootstrap authorization was used as approved and never withdrawn by a person: CONSUMED, still APPROVED, or closed by
    the ZTP workflow itself when the bootstrap completed (its remaining uses).  An operator's revocation or an expiry before
    completion stops commissioning."""
    from ..ztp import workflow

    if auth is None:
        return False
    State = models.BootstrapAuthorizationState
    return auth.state in (State.APPROVED, State.CONSUMED) or (auth.state == State.REVOKED and auth.revoked_by == workflow.SYSTEM)


def readiness(record, *, approved: bool = False) -> tuple[list[dict], dict]:
    """-> (checks, evidence).  ``approved``: evaluated for an approved / configuring record (lifecycle and run stage move on)."""
    device = models.ManagedDevice.objects.get(pk=record.device_id)
    policy = models.IsolationPolicy.objects.get(pk=record.isolation_policy_id)
    run = models.ProvisioningRun.objects.filter(pk=record.provisioning_run_id).first()
    session = session_of(device)
    credential = transport.credential_transition(device)
    rows: list[dict] = []
    _check(rows, "identity_verified", device.identity_state == models.IdentityVerificationState.VERIFIED and bool(device.verified_host_key),
           "COMMISSIONING_IDENTITY_UNVERIFIED", device.identity_state)
    _check(rows, "host_key_enrolled", session is not None and session.enrolled_host_key == device.verified_host_key and bool(session.enrolled_host_key),
           "COMMISSIONING_IDENTITY_UNVERIFIED", "the verified host key is the out-of-band enrolled one")
    _check(rows, "attachment_verified", policy.attachment.verification_state == models.AttachmentVerification.VERIFIED
           and policy.attachment.approval_state == models.AttachmentApproval.APPROVED, "ISOLATION_DEVICE_NOT_OBSERVED",
           policy.attachment.verification_state)
    auth = session.authorization if session is not None else None
    _check(rows, "bootstrap_authorization", authorization_intact(auth), "AUTHORIZATION_STATE_INVALID",
           f"{getattr(auth, 'state', 'none')} by {getattr(auth, 'revoked_by', '') or '-'}")
    _check(rows, "native_bootstrap", session is not None and bool((session.verification or {}).get("ok")), "BOOTSTRAP_VERIFICATION_FAILED",
           f"ztp_state={device.ztp_state} (observed; native ZTP completion is never admission)")
    found = transport.problems(device, purpose="READ")
    _check(rows, "management_transport", not found, "COMMISSIONING_TRANSPORT_UNAVAILABLE", ",".join(found))
    _check(rows, "credential_transitioned", credential is not None and not models.BootstrapCredentialTransition.objects.filter(
        device=device, state__in=tuple(models.BOOTSTRAP_CREDENTIAL_OPEN)).exists(), "COMMISSIONING_CREDENTIAL_NOT_TRANSITIONED",
        "bootstrap credential revoked, proven rejected and retired; the service credential works" if credential else "no COMPLETE BCRED")
    iso = isolation.isolate_problems(device)
    _check(rows, "isolation_verified", not iso and policy.state == models.IsolationState.VERIFIED, iso[0]["code"] if iso else "ISOLATION_NOT_VERIFIED",
           policy.state)
    unmet = dependencies.unmet(device)
    _check(rows, "dependencies", not unmet, unmet[0]["code"] if unmet else "", "; ".join(str(b.get("details", "")) for b in unmet)[:200])
    states = (S.READY_FOR_COMMISSIONING, S.COMMISSIONING) if approved else (S.ISOLATED, S.READY_FOR_COMMISSIONING)
    _check(rows, "lifecycle", device.lifecycle_state in states and device.admission_state == models.ProductionAdmissionState.NOT_ADMITTED,
           "COMMISSIONING_DEVICE_NOT_ISOLATED", device.lifecycle_state)
    stages = CANDIDATE_APPROVED if approved else CANDIDATE_READY
    _check(rows, "production_candidate", run is not None and run.status in stages and bool(run.candidate_hash), "COMMISSIONING_CONFIG_NOT_APPLIED",
           f"{getattr(run, 'prov_id', '')} {getattr(run, 'status', '')}: validated, planned and prechecked through the ordinary provisioning stages")
    evidence = {
        "schema": 1,
        "device": {"id": device.device_id, "name": device.name, "platform": device.platform, "verified_host_key": device.verified_host_key,
                   "verified_serial": device.verified_serial, "identity_verified_at": str(device.identity_verified_at or "")},
        "attachment": {"id": policy.attachment_id, "upstream": f"{policy.upstream_device}:{policy.upstream_interface}",
                       "local_interface": policy.attachment.local_interface, "verification_state": policy.attachment.verification_state},
        "bootstrap_grant": {"id": getattr(auth, "auth_id", ""), "state": getattr(auth, "state", "")},
        "ztp": {"session": getattr(session, "session_id", ""), "enrolled_host_key": getattr(session, "enrolled_host_key", ""),
                "ztp_state": device.ztp_state},
        "bcred": {"transition": getattr(credential, "transition_id", ""), "replacement_fingerprint": getattr(credential, "replacement_key_fingerprint", ""),
                       "completed_at": str(getattr(credential, "completed_at", "") or "")},
        "isolation": {"policy": policy.policy_id, "intent_hash": policy.intent_hash, "plan_hash": policy.plan_hash,
                      "enforced_digest": policy.enforced_digest},
        "dependencies": sorted(f"{d.upstream.name}:{d.kind}" for d in models.CommissioningDependency.objects.select_related("upstream").filter(
            device=device, state=models.DependencyState.ACTIVE)),
        "candidate": {"prov_id": getattr(run, "prov_id", ""), "candidate_hash": getattr(run, "candidate_hash", ""),
                      "plan": str(getattr(run, "plan_id", "") or ""), "change": getattr(getattr(run, "change", None), "change_id", "")},
    }
    return rows, evidence


def digest(evidence: dict) -> str:
    return hashlib.sha256(json.dumps(evidence, sort_keys=True, separators=(",", ":"), default=str).encode()).hexdigest()


def staleness(record, *, now=None) -> list[dict]:
    """Why an approved commissioning may no longer act ([] = still current): any readiness check failing, the evidence hash
    differing from the approved one (identity, attachment, isolation, credential, dependency or candidate change), or age."""
    now = now or timezone.now()
    rows, evidence = readiness(record, approved=True)
    found = [blocker(row["code"] or "COMMISSIONING_EVIDENCE_STALE", check=row["check"]) for row in rows if not row["ok"]]
    if digest(evidence) != record.evidence_digest:
        found.append(blocker("COMMISSIONING_EVIDENCE_STALE", detail="the evidence changed since approval"))
    if record.approved_at is None or (now - record.approved_at) > timedelta(seconds=approval_max_age_seconds()):
        found.append(blocker("COMMISSIONING_EVIDENCE_STALE", detail="the approval expired"))
    return found


def assess(record, *, actor: str) -> CommissioningResult:
    """Evaluate readiness (idempotent).  All checks pass -> READY with the evidence frozen; otherwise OPEN with the blockers."""
    action = "COM_READINESS"
    if record.state not in (St.OPEN, St.READY):
        return _refuse(record.device, action, [blocker("COMMISSIONING_STATE_INVALID", state=record.state)], actor=actor, record=record)
    rows, evidence = readiness(record)
    ready = all(row["ok"] for row in rows)
    report = {"at": timezone.now().isoformat(), "checks": rows, "ready": ready}
    try:
        with transaction.atomic():
            if ready:
                record = _save(record, state=St.READY, readiness=report, evidence=evidence, evidence_digest=digest(evidence), failure={})
                _transition(record.device, S.READY_FOR_COMMISSIONING, actor=actor, record=record)
            else:
                record = _save(record, state=St.OPEN, readiness=report, evidence={}, evidence_digest="",
                               failure={"codes": [row["code"] for row in rows if not row["ok"]]})
                if models.ManagedDevice.objects.get(pk=record.device_id).lifecycle_state == S.READY_FOR_COMMISSIONING:
                    _transition(record.device, S.ISOLATED, actor=actor, record=record)
            _event(record.device, action, Outcome.RECORDED if ready else Outcome.REFUSED, actor=actor, record=record,
                   blockers=[] if ready else [blocker(row["code"], check=row["check"]) for row in rows if not row["ok"]],
                   evidence={"ready": ready, "evidence_digest": record.evidence_digest})
    except _Abort as abort:
        return _refuse(record.device, action, abort.blockers, actor=actor, record=record)
    except _Stale:
        return _refuse(record.device, action, [blocker("COMMISSIONING_STATE_INVALID", detail="changed concurrently")], actor=actor, record=record)
    found = [] if ready else [blocker(row["code"], check=row["check"]) for row in rows if not row["ok"]]
    return CommissioningResult(ready, action, record, found, report)


def approve(record, *, actor: str, confirmation: str, comment: str = "") -> CommissioningResult:
    """Approve exactly the frozen evidence (its hash) as someone other than the requester; approves the provisioning candidate in
    the same transaction and moves the device to COMMISSIONING."""
    action = "COM_APPROVE"
    run = record.provisioning_run
    if record.state != St.READY:
        return _refuse(record.device, action, [blocker("COMMISSIONING_STATE_INVALID", state=record.state)], actor=actor, record=record)
    if not actor or actor in (record.requested_by, getattr(run, "requested_by", "")):
        return _refuse(record.device, action, [blocker("COMMISSIONING_SELF_APPROVAL")], actor=actor, record=record)
    if confirmation != record.evidence_digest:
        return _refuse(record.device, action, [blocker("COMMISSIONING_CONFIRMATION_MISMATCH")], actor=actor, record=record)
    rows, evidence = readiness(record)
    failing = [row for row in rows if not row["ok"]]
    if failing or digest(evidence) != record.evidence_digest:
        problems = [blocker(row["code"], check=row["check"]) for row in failing] or [blocker("COMMISSIONING_EVIDENCE_STALE")]
        return _refuse(record.device, action, problems, actor=actor, record=record)
    try:
        with transaction.atomic():
            record = _save(record, state=St.APPROVED, approved_by=actor[:150], approved_at=timezone.now())
            approved = ps.approve(run, actor=actor, confirm_candidate_hash=run.candidate_hash, comment=comment)
            if not approved.ok:
                raise _Abort(approved.blockers)
            _transition(record.device, S.COMMISSIONING, actor=actor, record=record)
            _event(record.device, action, Outcome.RECORDED, actor=actor, record=record,
                   evidence={"evidence_digest": record.evidence_digest, "candidate_hash": run.candidate_hash, "prov_id": run.prov_id})
    except _Abort as abort:
        return _refuse(record.device, action, abort.blockers, actor=actor, record=models.CommissioningRecord.objects.get(pk=record.pk))
    except _Stale:
        return _refuse(record.device, action, [blocker("COMMISSIONING_STATE_INVALID", detail="changed concurrently")], actor=actor, record=record)
    return CommissioningResult(True, action, record)


def mark_configuring(run) -> None:
    """Provisioning's pre-write hook for a commissioning run: the record enters CONFIGURING (write-ahead)."""
    record = models.CommissioningRecord.objects.filter(provisioning_run=run, state=St.APPROVED).first()
    if record is not None:
        with transaction.atomic():
            record = _save(record, state=St.CONFIGURING)
            _event(record.device, "COM_CONFIGURE", Outcome.RECORDED, actor=run.approval.get("approved_by", "") or "system:commissioning",
                   record=record, evidence={"prov_id": run.prov_id, "phase": "configuration started"})


def record_configuration(record, *, actor: str, access=None) -> CommissioningResult:
    """Fold the provisioning execution result in.  POSTCHECKED and the isolation still intact -> CONFIGURED (still isolated)."""
    action = "COM_CONFIGURE"
    run = models.ProvisioningRun.objects.get(pk=record.provisioning_run_id)
    if record.state not in (St.APPROVED, St.CONFIGURING):
        return _refuse(record.device, action, [blocker("COMMISSIONING_STATE_INVALID", state=record.state)], actor=actor, record=record)
    if run.status in (P.APPROVED, P.PROVISIONING):
        return _refuse(record.device, action, [blocker("COMMISSIONING_CONFIG_NOT_APPLIED", status=run.status)], actor=actor, record=record)
    # The upstream read-back is network I/O: it runs BEFORE the write transaction and records its own DRIFT check.  A transaction
    # held across the SSH session blocks every other writer (SQLite: "database is locked"; PostgreSQL: a long-held row lock).
    # What it observed -- the run status and the policy version it read against -- is re-validated under lock below, so a
    # change in between is refused (retryable), never folded in.
    drift = None
    if run.status == P.POSTCHECKED:      # read against the policy as stored now (never a relation cached on the caller's record)
        drift = isolation.check_drift(models.IsolationPolicy.objects.get(pk=record.isolation_policy_id), actor=actor, access=access)
    try:
        with transaction.atomic():
            current = models.ProvisioningRun.objects.select_for_update().get(pk=run.pk)
            if current.status != run.status:
                raise _Abort([blocker("COMMISSIONING_STATE_INVALID", detail="provisioning run changed during the read-back",
                                      status=current.status)])
            if run.status == P.POSTCHECKED:
                if not drift.ok:
                    record = _save(record, state=St.UNCERTAIN, failure={"code": "ISOLATION_DRIFTED", "detail": drift.codes})
                    _event(record.device, action, Outcome.REFUSED, actor=actor, record=record, blockers=drift.blockers)
                    return CommissioningResult(False, action, record, drift.blockers)
                policy = models.IsolationPolicy.objects.select_for_update().get(pk=record.isolation_policy_id)
                if (policy.version, policy.state) != (drift.policy.version, drift.policy.state):
                    raise _Abort([blocker("ISOLATION_STATE_INVALID", detail="the isolation policy changed after its read-back",
                                          state=policy.state)])
                record = _save(record, state=St.CONFIGURED, failure={})
                outcome, found = Outcome.RECORDED, []
            elif run.status == P.ROLLED_BACK:
                record = _save(record, state=St.ABORTED, closed_at=timezone.now(),
                               failure={"code": "COMMISSIONING_CONFIG_NOT_APPLIED", "provisioning": run.failure.get("code", ""), "restored": True})
                _transition(record.device, S.ISOLATED, actor=actor, record=record)
                outcome, found = Outcome.REFUSED, [blocker("COMMISSIONING_CONFIG_NOT_APPLIED", restored=True)]
            else:
                record = _save(record, state=St.UNCERTAIN, failure={"code": "COMMISSIONING_CONFIG_NOT_APPLIED", "provisioning": run.status, "restored": False})
                outcome, found = Outcome.REFUSED, [blocker("COMMISSIONING_CONFIG_NOT_APPLIED", restored=False, status=run.status)]
            _event(record.device, action, outcome, actor=actor, record=record, blockers=found,
                   evidence={"prov_id": run.prov_id, "run_status": run.status, "post_config_digest": run.post_config_digest})
    except _Abort as abort:
        return _refuse(record.device, action, abort.blockers, actor=actor, record=record)
    except _Stale:
        return _refuse(record.device, action, [blocker("COMMISSIONING_STATE_INVALID", detail="changed concurrently")], actor=actor, record=record)
    return CommissioningResult(not found, action, record, found)


def abort(record, *, actor: str, reason: str) -> CommissioningResult:
    """Stop a commissioning that has not started releasing isolation.  The device stays (or returns to) ISOLATED behind its
    policy; an unexecuted provisioning run is cancelled (its NetBox reservation released).  Production configuration already
    applied to the isolated device is NOT removed here (recorded; Phase 7 decommission owns removal)."""
    action = "COM_ABORT"
    text = str(reason or "").strip()[:200]
    if record.state not in (St.OPEN, St.READY, St.APPROVED, St.CONFIGURED) or not text:
        return _refuse(record.device, action, [blocker("COMMISSIONING_STATE_INVALID", state=record.state)], actor=actor, record=record)
    run = record.provisioning_run
    try:
        with transaction.atomic():
            configured = record.state == St.CONFIGURED
            record = _save(record, state=St.ABORTED, closed_at=timezone.now(),
                           failure={"code": "ABORTED", "reason": text, "production_configuration_left_on_isolated_device": configured})
            if run is not None and not run.is_terminal and run.status not in (P.PROVISIONING, P.POSTCHECKED, P.NSOT_SYNCED):
                ps.cancel(run, actor=actor, reason=f"commissioning aborted: {text}")
            state = models.ManagedDevice.objects.get(pk=record.device_id).lifecycle_state
            if state in (S.READY_FOR_COMMISSIONING, S.COMMISSIONING):
                _transition(record.device, S.ISOLATED, actor=actor, record=record)
            _event(record.device, action, Outcome.RECORDED, actor=actor, record=record, evidence={"reason": text, "configured": configured})
    except _Abort as abort_:
        return _refuse(record.device, action, abort_.blockers, actor=actor, record=record)
    except _Stale:
        return _refuse(record.device, action, [blocker("COMMISSIONING_STATE_INVALID", detail="changed concurrently")], actor=actor, record=record)
    return CommissioningResult(True, action, record)


def restoration_problems(record, *, reader=None) -> tuple[list[dict], dict]:
    """Is the device PROVABLY back to the state its failed commissioning run found?  -> (blockers, facts).

    The proof is a fresh read of the device's running configuration through the commissioning transport whose digest equals the
    run's pre-execution digest (``ProvisioningRun.pre_config_digest``, the same reader and formula).  Anything else -- no baseline,
    an unreadable device, a different configuration -- is not proof."""
    run = models.ProvisioningRun.objects.get(pk=record.provisioning_run_id)
    facts = {"prov_id": run.prov_id, "run_status": run.status, "pre_config_digest": run.pre_config_digest}
    if not run.is_terminal or not run.pre_config_digest:
        return [blocker("COMMISSIONING_CONFIG_NOT_APPLIED", restored=False, status=run.status)], facts
    try:
        text = (reader or transport.config_reader)({"name": record.device.name, "platform": "ceos"})
    except Exception:  # pylint: disable=broad-exception-caught  # noqa: BLE001 - unreadable is not restored
        text = ""
    facts["device_digest"] = hashlib.sha256(str(text).encode()).hexdigest() if text else ""
    if facts["device_digest"] != run.pre_config_digest:
        return [blocker("COMMISSIONING_CONFIG_NOT_APPLIED", restored=False, readable=bool(text))], facts
    return [], facts


def _reconcile_unproven(record, *, actor: str, reader=None) -> CommissioningResult:
    """UNCERTAIN after a configuration run whose restoration the engine could not prove: close it (ABORTED, device back to
    ISOLATED) only when the device is demonstrably back to the run's pre-execution state; otherwise it stays UNCERTAIN."""
    action = "COM_RECONCILE"
    found, facts = restoration_problems(record, reader=reader)
    if found:
        return _refuse(record.device, action, found, actor=actor, record=record)
    try:
        with transaction.atomic():
            record = _save(record, state=St.ABORTED, closed_at=timezone.now(),
                           failure={**(record.failure or {}), "restored": True, "restoration_proven_by": action, "device_digest": facts["device_digest"]})
            _transition(record.device, S.ISOLATED, actor=actor, record=record)
            _event(record.device, action, Outcome.RECORDED, actor=actor, record=record, evidence=facts)
    except _Abort as abort_:
        return _refuse(record.device, action, abort_.blockers, actor=actor, record=record)
    except _Stale:
        return _refuse(record.device, action, [blocker("COMMISSIONING_STATE_INVALID", detail="changed concurrently")], actor=actor, record=record)
    return CommissioningResult(True, action, record, [], facts)


def reconcile(record, *, actor: str, access=None, reader=None) -> CommissioningResult:
    """Restart recovery: CONFIGURING after a lost response is re-derived from the provisioning run's recorded outcome (never from
    the absence of an error); an UNCERTAIN configuration run is closed only on proof that the device is back to its pre-run state;
    ADMITTING / UNCERTAIN admissions defer to the admission's own reconciliation."""
    action = "COM_RECONCILE"
    if record.state == St.CONFIGURING:
        run = models.ProvisioningRun.objects.get(pk=record.provisioning_run_id)
        if run.status == P.PROVISIONING:
            unresolved = run.change.execution_runs.exclude(outcome__isnull=False).exists() if run.change_id else False
            return _refuse(record.device, action, [blocker("COMMISSIONING_CONFIG_NOT_APPLIED", status=run.status, running=unresolved)],
                           actor=actor, record=record)
        return record_configuration(record, actor=actor, access=access)
    if record.state in (St.ADMITTING, St.UNCERTAIN):
        from . import admission as admission_service

        admission = models.ProductionAdmission.objects.filter(commissioning=record).order_by("-id").first()
        if admission is not None and admission.state in (models.AdmissionState.RELEASING, models.AdmissionState.UNCERTAIN):
            result = admission_service.reconcile(admission, actor=actor, access=access)
            return CommissioningResult(result.ok, action, get_record(record.pk), result.blockers, result.detail)
    if record.state == St.UNCERTAIN and (record.failure or {}).get("code") == "COMMISSIONING_CONFIG_NOT_APPLIED":
        return _reconcile_unproven(record, actor=actor, reader=reader)
    return _refuse(record.device, action, [blocker("COMMISSIONING_STATE_INVALID", state=record.state)], actor=actor, record=record)


def status(record) -> dict:
    run = record.provisioning_run
    return {"commissioning": record.commissioning_id, "device": record.device.device_id, "state": record.state,
            "policy": record.isolation_policy.policy_id, "isolation_state": record.isolation_policy.state,
            "provisioning_run": getattr(run, "prov_id", ""), "provisioning_status": getattr(run, "status", ""),
            "candidate_hash": getattr(run, "candidate_hash", ""), "evidence_digest": record.evidence_digest,
            "readiness": record.readiness, "requested_by": record.requested_by, "approved_by": record.approved_by,
            "failure": record.failure, "dependencies": dependencies.graph_view([record.device])}
