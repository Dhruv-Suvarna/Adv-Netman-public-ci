"""Governed production admission (``ADM-000001``): the controlled release of a CONFIGURED device's trusted-upstream isolation.

    plan      -> PLANNED     validated expectations (routing protocol, adjacencies, routes, reachable addresses) and the isolation
                             release Change (validated + planned); the admission evidence (commissioning evidence, release plan hash,
                             enforced upstream digest, expectations) is hashed
    precheck                 the upstream still holds exactly the enforced policy; isolation evidence fresh; dependencies satisfied
    approve   -> APPROVED    an operator other than the requester confirms the evidence hash (approves the release plan with it)
    execute   -> RELEASING   write-ahead; the release runs through the governed transaction on the TRUSTED upstream, and its final
                             postcheck polls the expectations there (OSPF / OSPFv3 FULL with the expected router ids on the policy port, the
                             expected routes learned through it, reachability from the upstream, and optional external flows)
              -> ADMITTED    everything held: isolation RELEASED, device IN_SERVICE / ADMITTED, NSOT / topology / monitoring
                             hand-offs written in the same transaction, then the provisioning run's NSOT activation
              -> RESTORED    any expectation failed and every removed statement was re-applied and digest-verified (the device
                             stays COMMISSIONING behind an ENFORCED policy that must be verified again)
              -> UNCERTAIN   restoration could not be proven: nothing is retried automatically; ``reconcile`` proves the state

Isolation is never removed to "restore management", and nothing here touches the device being admitted.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import time
from dataclasses import dataclass, field

from django.conf import settings
from django.db import IntegrityError, transaction
from django.utils import timezone

from ... import models
from .. import provisioning_service as ps
from ..devices import events, lifecycle
from ..devices.codes import blocker, codes
from ..isolation import eos, frr, service as isolation
from ..isolation import transaction as iso_transaction
from . import dependencies, outbox
from . import service as commissioning

St = models.AdmissionState
C = models.CommissioningState
S = models.DeviceLifecycleState
Outcome = models.DeviceLifecycleEventOutcome
ROUTING = ("OSPF", "RIP", "OSPFV3")
MAX_ITEMS = 16


def settle_seconds() -> float:
    return float(getattr(settings, "NMAS_ADMISSION_SETTLE_SECONDS", 90))


def poll_seconds() -> float:
    return float(getattr(settings, "NMAS_ADMISSION_POLL_SECONDS", 5))


@dataclass
class AdmissionResult:
    ok: bool
    action: str
    admission: object | None = None
    blockers: list = field(default_factory=list)
    detail: dict = field(default_factory=dict)

    @property
    def codes(self) -> list[str]:
        return codes(self.blockers)


def get_admission(admission_id):
    text = str(admission_id or "")
    pk = int(text[4:]) if text.startswith("ADM-") and text[4:].isdigit() else (int(text) if text.isdigit() else None)
    return models.ProductionAdmission.objects.select_related("device", "commissioning", "isolation_policy").filter(pk=pk).first() if pk else None


def open_admission(device):
    return models.ProductionAdmission.objects.filter(device=device, state__in=tuple(models.ADMISSION_OPEN)).first()


def _actor_kind(actor: str) -> str:
    return events.AUTOMATION if actor.startswith("system:") else events.HUMAN


def _event(device, action, outcome, *, actor, admission=None, blockers=(), evidence=None):
    fresh = models.ManagedDevice.objects.select_for_update().get(pk=device.pk)
    return events.record(fresh, action, outcome, actor=actor, actor_kind=_actor_kind(actor), from_state=fresh.lifecycle_state,
                         to_state=fresh.lifecycle_state, blockers=list(blockers),
                         evidence={"admission": admission.admission_id if admission is not None and admission.pk else "", **(evidence or {})})


def _refuse(device, action, problems, *, actor, admission=None) -> AdmissionResult:
    with transaction.atomic():
        _event(device, action, Outcome.REFUSED, actor=actor, admission=admission, blockers=problems)
    return AdmissionResult(False, action, admission, list(problems))


class _Stale(Exception):
    pass


class _Abort(Exception):
    def __init__(self, blockers):
        super().__init__("abort")
        self.blockers = blockers


def _save(admission, **fields):
    fresh = models.ProductionAdmission.objects.select_for_update().get(pk=admission.pk)
    if fresh.version != admission.version:
        raise _Stale()
    for name, value in fields.items():
        setattr(fresh, name, value)
    fresh.version += 1
    fresh.__dict__["_admission_write"] = True
    fresh.save()
    return fresh


def _record_state(record, state, **fields):
    """Commissioning-record transitions owned by admission (through the commissioning service's own writer)."""
    return commissioning._save(models.CommissioningRecord.objects.get(pk=record.pk), state=state, **fields)


# ------------------------------------------------------------------------------------------------------------- expectations
def validate_expectations(raw: dict) -> tuple[dict, list[dict]]:
    """-> (normalized expectations, problems).  OSPF needs at least one expected neighbor router id; RIP has none (route-based);
    OSPFV3 (IPv6-only routing) needs at least one expected OSPFv3 neighbor router id and an expected IPv6 route; OSPFv3 neighbors
    may also accompany OSPF or RIP (a dual-stack device routing IPv6 with OSPFv3) and then need an expected IPv6 route too;
    at least one expected route; addresses are literal IPv4 / IPv6 addresses (no names)."""
    raw = dict(raw or {})
    problems = []
    routing = str(raw.get("routing") or "").upper()
    if routing not in ROUTING:
        problems.append(f"routing must be one of {ROUTING}")
    clean = {"routing": routing, "ospf_neighbors": [], "ospfv3_neighbors": [], "routes_v4": [], "routes_v6": [], "reachable": []}
    for key, kind in (("ospf_neighbors", "rid"), ("ospfv3_neighbors", "rid"), ("routes_v4", 4), ("routes_v6", 6), ("reachable", "addr")):
        values = raw.get(key) or []
        if not isinstance(values, (list, tuple)) or len(values) > MAX_ITEMS:
            problems.append(f"{key} must be a list of at most {MAX_ITEMS}")
            continue
        for value in values:
            text = str(value).strip()
            try:
                if kind == "rid":
                    clean[key].append(str(ipaddress.IPv4Address(text)))
                elif kind == "addr":
                    clean[key].append(str(ipaddress.ip_address(text)))
                else:
                    network = ipaddress.ip_network(text, strict=True)
                    if network.version != kind:
                        raise ValueError(text)
                    clean[key].append(str(network))
            except ValueError:
                problems.append(f"{key}: {text[:48]!r} is not valid")
    for key in ("ospf_neighbors", "ospfv3_neighbors", "routes_v4", "routes_v6", "reachable"):
        clean[key] = sorted(set(clean[key]))
    if routing == "OSPF" and not clean["ospf_neighbors"]:
        problems.append("OSPF admission names the expected neighbor router id(s)")
    if routing == "RIP" and clean["ospf_neighbors"]:
        problems.append("RIP admission is route-based: no OSPF neighbors")
    if routing == "OSPFV3" and clean["ospf_neighbors"]:
        problems.append("OSPFV3 admission routes IPv6 only: name OSPFv3 neighbors, not OSPF ones")
    if routing == "OSPFV3" and not clean["ospfv3_neighbors"]:
        problems.append("OSPFV3 admission names the expected OSPFv3 neighbor router id(s)")
    if clean["ospfv3_neighbors"] and not clean["routes_v6"]:
        problems.append("an OSPFv3 adjacency is admitted with at least one expected IPv6 route learned through the released port")
    if not clean["routes_v4"] and not clean["routes_v6"]:
        problems.append("at least one expected route learned through the released port")
    extra = sorted(set(raw) - set(clean))
    if extra:
        problems.append(f"unknown keys {extra[:5]}")
    return clean, [blocker("ADMISSION_EXPECTATIONS_INVALID", detail=p) for p in problems]


def _default_access(admission):
    """The production access of the admission's upstream platform (cEOS unless the policy names Ubuntu/FRR)."""
    policy = models.IsolationPolicy.objects.filter(pk=admission.isolation_policy_id).first()
    return isolation.default_access(policy.upstream_platform) if policy is not None else isolation.default_access()


def frr_failures(executor, policy, expectations: dict) -> list[dict]:
    """``failures`` on an Ubuntu/FRR upstream: ospfd / ospf6d neighbours on the port, kernel routes learned through it."""
    found = []
    port = policy.upstream_interface
    snapshot = executor.snapshot()
    if expectations.get("routing") == "OSPF":
        neighbors = frr.ospf_neighbors_on(snapshot.get("ospf_neighbors") or "", port)
        for rid in expectations.get("ospf_neighbors", []):
            row = next((n for n in neighbors if n["neighbor"] == rid), None)
            if row is None or not row["state"].upper().startswith("FULL"):
                found.append({"check": "ospf_adjacency", "detail": f"{rid} on {port}: {row['state'] if row else 'absent'}"})
    if expectations.get("ospfv3_neighbors"):
        neighbors6 = frr.ospf_neighbors_on(snapshot.get("ospf6_neighbors") or "", port)
        for rid in expectations["ospfv3_neighbors"]:
            row = next((n for n in neighbors6 if n["neighbor"] == rid), None)
            if row is None or not row["state"].upper().startswith("FULL"):
                found.append({"check": "ospfv3_adjacency", "detail": f"{rid} on {port}: {row['state'] if row else 'absent'}"})
    for family in (4, 6):
        wanted = expectations.get(f"routes_v{family}", [])
        rows = snapshot.get(f"routes{family}")
        if not wanted:
            continue
        if rows is None:
            found.append({"check": f"routes_v{family}", "detail": "route table unreadable"})
            continue
        learned = set(frr.route_via_port({f"routes{family}": rows}, port))
        for prefix in wanted:
            if prefix not in learned:
                found.append({"check": f"routes_v{family}", "detail": f"{prefix} not learned through {port}"})
    return found


def failures(executor, policy, expectations: dict, *, traffic=None, admission=None) -> list[dict]:
    """What does NOT hold right now on the upstream ([] = admitted).  Read-only: show commands and two-packet pings."""
    found = []
    port = policy.upstream_interface
    if isolation.is_frr(policy):
        found = frr_failures(executor, policy, expectations)
    elif expectations.get("routing") == "OSPF":
        neighbors = eos.ospf_neighbors_on(executor.show("show ip ospf neighbor"), port)
        for rid in expectations.get("ospf_neighbors", []):
            row = next((n for n in neighbors if n["neighbor"] == rid), None)
            if row is None or not row["state"].upper().startswith("FULL"):
                found.append({"check": "ospf_adjacency", "detail": f"{rid} on {port}: {row['state'] if row else 'absent'}"})
    if expectations.get("ospfv3_neighbors") and not isolation.is_frr(policy):
        neighbors = eos.ospf6_neighbors_on(executor.show("show ipv6 ospf neighbor | json"), port)
        if neighbors is None:
            found.append({"check": "ospfv3_adjacency", "detail": "OSPFv3 neighbor table unreadable"})
        for rid in expectations["ospfv3_neighbors"] if neighbors is not None else []:
            row = next((n for n in neighbors if n["neighbor"] == rid), None)
            if row is None or not row["state"].upper().startswith("FULL"):
                found.append({"check": "ospfv3_adjacency", "detail": f"{rid} on {port}: {row['state'] if row else 'absent'}"})
    for family, command in ((4, "show ip route | json"), (6, "show ipv6 route | json")):
        wanted = expectations.get(f"routes_v{family}", [])
        if not wanted or isolation.is_frr(policy):
            continue
        learned = eos.routes_via(executor.show(command), port, [])
        if learned is None:
            found.append({"check": f"routes_v{family}", "detail": "route table unreadable"})
            continue
        for prefix in wanted:
            if prefix not in learned:
                found.append({"check": f"routes_v{family}", "detail": f"{prefix} not learned through {port}"})
    for address in expectations.get("reachable", []):
        if not executor.reachable(address):
            found.append({"check": "reachability", "detail": f"{address} unreachable from {policy.upstream_device}"})
    if traffic is not None:
        for flow in list(traffic(admission)):
            if flow.get("observed") != flow.get("expect"):
                found.append({"check": "traffic", "detail": f"{str(flow.get('flow'))[:80]}: expected {flow.get('expect')}, "
                                                            f"observed {flow.get('observed')}"})
    return found


def _poller(policy, expectations, *, traffic, admission, sleep, settle):
    """``verify_admission`` for the release's final postcheck: poll until the expectations hold or ``settle`` seconds pass."""
    def verify(executor):
        deadline = time.monotonic() + settle
        while True:
            found = failures(executor, policy, expectations, traffic=traffic, admission=admission)
            if not found or time.monotonic() >= deadline:
                return found
            sleep(min(poll_seconds(), max(0.0, deadline - time.monotonic())))
    return verify


# ------------------------------------------------------------------------------------------------------------- evidence
def evidence(record, policy, expectations: dict) -> dict:
    change = policy.release_change
    built = iso_transaction.latest_plan(change) if change is not None else None
    return {"schema": 1, "commissioning": record.commissioning_id, "commissioning_evidence": record.evidence_digest,
            "policy": policy.policy_id, "enforced_digest": policy.enforced_digest, "intent_hash": policy.intent_hash,
            "release_change": getattr(change, "change_id", ""), "release_plan_hash": getattr(built, "plan_hash", ""),
            "provisioning_run": getattr(record.provisioning_run, "prov_id", ""),
            "post_config_digest": getattr(record.provisioning_run, "post_config_digest", ""), "expectations": expectations}


def digest(value: dict) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode()).hexdigest()


def plan_problems(record) -> list[dict]:
    device = models.ManagedDevice.objects.get(pk=record.device_id)
    policy = models.IsolationPolicy.objects.get(pk=record.isolation_policy_id)
    problems = []
    if record.state != C.CONFIGURED:
        problems.append(blocker("ADMISSION_STATE_INVALID", commissioning=record.state))
    if device.lifecycle_state != S.COMMISSIONING or device.admission_state != models.ProductionAdmissionState.NOT_ADMITTED:
        problems.append(blocker("ADMISSION_STATE_INVALID", lifecycle=device.lifecycle_state, admission=device.admission_state))
    if open_admission(device) is not None:
        problems.append(blocker("ADMISSION_OPEN_EXISTS"))
    problems += isolation.isolate_problems(device)
    problems += dependencies.unmet(device)
    if policy.state != models.IsolationState.VERIFIED and not any(p["code"].startswith("ISOLATION_") for p in problems):
        problems.append(blocker("ISOLATION_NOT_VERIFIED", state=policy.state))
    return problems


def current_problems(admission) -> list[dict]:
    """Is the approved admission still exactly what was approved, and are its preconditions still true?"""
    record = models.CommissioningRecord.objects.get(pk=admission.commissioning_id)
    policy = models.IsolationPolicy.objects.get(pk=admission.isolation_policy_id)
    device = models.ManagedDevice.objects.get(pk=admission.device_id)
    problems = []
    if record.state != C.CONFIGURED or device.lifecycle_state != S.COMMISSIONING:
        problems.append(blocker("ADMISSION_STATE_INVALID", commissioning=record.state, lifecycle=device.lifecycle_state))
    problems += isolation.isolate_problems(device)
    problems += dependencies.unmet(device)
    if digest(evidence(record, policy, admission.expectations)) != admission.evidence_digest:
        problems.append(blocker("COMMISSIONING_EVIDENCE_STALE", detail="the admission evidence changed"))
    return problems


# ------------------------------------------------------------------------------------------------------------- workflow
def plan(record, *, actor: str, expectations: dict) -> AdmissionResult:
    action = "ADM_PLAN"
    problems = plan_problems(record)
    clean, invalid = validate_expectations(expectations)
    problems += invalid
    if problems:
        return _refuse(record.device, action, problems, actor=actor)
    policy = record.isolation_policy
    try:
        with transaction.atomic():
            released = isolation.create_release(policy, actor=actor, reference={"commissioning": record.commissioning_id})
            if not released.ok:
                raise _Abort(released.blockers)
            policy = models.IsolationPolicy.objects.get(pk=policy.pk)
            facts = evidence(record, policy, clean)
            admission = models.ProductionAdmission(commissioning=record, device=record.device, isolation_policy=policy,
                                                   release_change=policy.release_change, evidence_digest=digest(facts), expectations=clean,
                                                   requested_by=actor[:150])
            admission.__dict__["_admission_write"] = True
            admission.save()
            _event(record.device, action, Outcome.RECORDED, actor=actor, admission=admission,
                   evidence={"evidence_digest": admission.evidence_digest, "release_change": facts["release_change"],
                             "release_plan_hash": facts["release_plan_hash"]})
    except _Abort as abort:
        return _refuse(record.device, action, abort.blockers, actor=actor)
    except IntegrityError:
        return _refuse(record.device, action, [blocker("ADMISSION_OPEN_EXISTS")], actor=actor)
    return AdmissionResult(True, action, admission, [], {"evidence": facts})


def precheck(admission, *, actor: str, access=None) -> AdmissionResult:
    action = "ADM_PRECHECK"
    if admission.state not in (St.PLANNED, St.APPROVED):
        return _refuse(admission.device, action, [blocker("ADMISSION_STATE_INVALID", state=admission.state)], actor=actor, admission=admission)
    problems = current_problems(admission)
    checked = isolation.release_precheck(models.IsolationPolicy.objects.get(pk=admission.isolation_policy_id), actor=actor, access=access)
    problems += checked.blockers
    report = {"at": timezone.now().isoformat(), "ok": not problems, "codes": codes(problems), **checked.detail}
    try:
        with transaction.atomic():
            admission = _save(admission, verification={**(admission.verification or {}), "precheck": report})
            _event(admission.device, action, Outcome.REFUSED if problems else Outcome.RECORDED, actor=actor, admission=admission,
                   blockers=problems, evidence={"precheck_run": checked.detail.get("precheck_run", "")})
    except _Stale:
        return _refuse(admission.device, action, [blocker("ADMISSION_STATE_INVALID", detail="changed concurrently")], actor=actor, admission=admission)
    return AdmissionResult(not problems, action, admission, problems, report)


def approve(admission, *, actor: str, confirmation: str) -> AdmissionResult:
    """Approve exactly the admission evidence (its hash binds the release plan, the commissioning evidence and the expectations)."""
    action = "ADM_APPROVE"
    if admission.state != St.PLANNED:
        return _refuse(admission.device, action, [blocker("ADMISSION_STATE_INVALID", state=admission.state)], actor=actor, admission=admission)
    if not actor or actor == admission.requested_by:
        return _refuse(admission.device, action, [blocker("ADMISSION_SELF_APPROVAL")], actor=actor, admission=admission)
    if confirmation != admission.evidence_digest:
        return _refuse(admission.device, action, [blocker("COMMISSIONING_CONFIRMATION_MISMATCH")], actor=actor, admission=admission)
    problems = current_problems(admission)
    if problems:
        return _refuse(admission.device, action, problems, actor=actor, admission=admission)
    policy = models.IsolationPolicy.objects.get(pk=admission.isolation_policy_id)
    plan_hash = evidence(admission.commissioning, policy, admission.expectations)["release_plan_hash"]
    try:
        with transaction.atomic():
            approved = isolation.approve_release(policy, actor=actor, requested_by=admission.requested_by, confirmation=plan_hash,
                                                 extra={"admission": admission.admission_id, "evidence_digest": admission.evidence_digest})
            if not approved.ok:
                raise _Abort(approved.blockers)
            admission = _save(admission, state=St.APPROVED, approved_by=actor[:150], approved_at=timezone.now())
            _event(admission.device, action, Outcome.RECORDED, actor=actor, admission=admission, evidence={"evidence_digest": admission.evidence_digest})
    except _Abort as abort:
        return _refuse(admission.device, action, abort.blockers, actor=actor, admission=admission)
    except _Stale:
        return _refuse(admission.device, action, [blocker("ADMISSION_STATE_INVALID", detail="changed concurrently")], actor=actor, admission=admission)
    return AdmissionResult(True, action, admission)


def _admitted(admission, *, actor: str, verification: dict, gateway=None) -> AdmissionResult:
    """The release is proven: ADMITTED, commissioning ADMITTED, lifecycle COMMISSION_COMPLETE (admission_state ADMITTED) and the
    hand-offs, in one transaction; then the provisioning run's NSOT activation (retryable on its own; never undoes admission)."""
    action = "ADM_EXECUTE"
    try:
        return _admit(admission, actor=actor, verification=verification, gateway=gateway)
    except (_Abort, _Stale, commissioning._Stale) as exc:
        # the release itself is proven; only the records could not be written: the admission stays RELEASING (reconcile finishes it)
        found = getattr(exc, "blockers", None) or [blocker("ADMISSION_STATE_INVALID", detail="changed concurrently")]
        return _refuse(admission.device, action, found, actor=actor, admission=admission)


def _admit(admission, *, actor: str, verification: dict, gateway=None) -> AdmissionResult:
    action = "ADM_EXECUTE"
    with transaction.atomic():
        admission = _save(admission, state=St.ADMITTED, verification={**(admission.verification or {}), **verification},
                          executed_by=actor[:150], finished_at=timezone.now())
        record = _record_state(admission.commissioning, C.ADMITTED, closed_at=timezone.now(), failure={})
        result = lifecycle.transition(models.ManagedDevice.objects.get(pk=admission.device_id), S.IN_SERVICE, actor=actor,
                                      actor_kind=_actor_kind(actor),
                                      evidence={"commissioning": record.commissioning_id, "admission": admission.admission_id})
        if not result.ok:
            raise _Abort(result.blockers)      # never: every prerequisite was written above; rolls the whole fact back
        handed = outbox.record_admission(admission, actor=actor)
        _event(admission.device, action, Outcome.RECORDED, actor=actor, admission=admission,
               evidence={"outbox": [e.pk for e in handed], "state": admission.state})
    synced = ps.sync_nsot(record.provisioning_run, actor=actor, gateway=gateway) if record.provisioning_run_id else None
    return AdmissionResult(True, action, admission, [], {"nsot_sync": getattr(synced, "ok", None), "outbox": [e.pk for e in handed]})


def execute(admission, *, actor: str, access=None, traffic=None, observer=None, gateway=None) -> AdmissionResult:
    """Release the isolation and prove the admission (see the module docstring).  ``traffic(admission)`` optionally adds flows
    observed from outside the upstream ``[{flow, expect, observed}]``."""
    action = "ADM_EXECUTE"
    access = access or _default_access(admission)
    if admission.state != St.APPROVED:
        return _refuse(admission.device, action, [blocker("ADMISSION_STATE_INVALID", state=admission.state)], actor=actor, admission=admission)
    problems = current_problems(admission)
    if problems:
        return _refuse(admission.device, action, problems, actor=actor, admission=admission)
    policy = models.IsolationPolicy.objects.get(pk=admission.isolation_policy_id)
    plan_hash = evidence(admission.commissioning, policy, admission.expectations)["release_plan_hash"]
    try:
        with transaction.atomic():                                   # write-ahead: a crash from here on is reconciled, never guessed
            admission = _save(admission, state=St.RELEASING, executed_by=actor[:150])
            _record_state(admission.commissioning, C.ADMITTING)
            _event(admission.device, action, Outcome.RECORDED, actor=actor, admission=admission, evidence={"phase": "release started"})
    except _Stale:
        return _refuse(admission.device, action, [blocker("ADMISSION_STATE_INVALID", detail="changed concurrently")], actor=actor, admission=admission)
    verify = _poller(policy, admission.expectations, traffic=traffic, admission=admission, sleep=access.sleep, settle=settle_seconds())
    released = isolation.execute_release(policy, actor=actor, confirmation=plan_hash, access=access, verify_admission=verify, observer=observer)
    report = released.detail.get("report") or {}
    facts = {"release_run": released.detail.get("run", ""), "release_outcome": released.detail.get("outcome", ""),
             "postcheck": report.get("postcheck", {}), "failure": report.get("failure", {}),
             "compensation": (report.get("compensation") or {}).get("status", "")}
    if released.ok:
        return _admitted(admission, actor=actor, verification={"release": facts, "at": timezone.now().isoformat()}, gateway=gateway)
    outcome = released.detail.get("outcome", "")
    if released.detail.get("restored"):
        state, record_state, code = St.RESTORED, C.CONFIGURED, "ADMISSION_VERIFICATION_FAILED"
    elif outcome in (iso_transaction.Outcome.BLOCKED, iso_transaction.Outcome.FAILED_NO_MUTATION) or not released.detail.get("run"):
        state, record_state, code = St.FAILED, C.CONFIGURED, "ADMISSION_VERIFICATION_FAILED"
    else:
        state, record_state, code = St.UNCERTAIN, C.UNCERTAIN, "ADMISSION_RESTORE_UNPROVEN"
    found = [blocker(code, outcome=outcome)]
    with transaction.atomic():
        admission = _save(admission, state=state, finished_at=timezone.now() if state != St.UNCERTAIN else None,
                          restoration={"restored": bool(released.detail.get("restored")), "outcome": outcome, **facts},
                          failure={"code": code, "outcome": outcome, "isolation": released.codes})
        _record_state(admission.commissioning, record_state, failure={"code": code, "admission": admission.admission_id})
        _event(admission.device, action, Outcome.REFUSED, actor=actor, admission=admission, blockers=found,
               evidence={"state": state, "outcome": outcome})
    return AdmissionResult(False, action, admission, found, facts)


def cancel(admission, *, actor: str, reason: str) -> AdmissionResult:
    """Withdraw a PLANNED / APPROVED admission.  Nothing was sent; the release Change is never executed."""
    action = "ADM_CANCEL"
    text = str(reason or "").strip()[:200]
    if admission.state not in (St.PLANNED, St.APPROVED) or not text:
        return _refuse(admission.device, action, [blocker("ADMISSION_STATE_INVALID", state=admission.state)], actor=actor, admission=admission)
    try:
        with transaction.atomic():
            admission = _save(admission, state=St.CANCELLED, finished_at=timezone.now(), failure={"code": "CANCELLED", "reason": text})
            _event(admission.device, action, Outcome.RECORDED, actor=actor, admission=admission, evidence={"reason": text})
    except _Stale:
        return _refuse(admission.device, action, [blocker("ADMISSION_STATE_INVALID", detail="changed concurrently")], actor=actor, admission=admission)
    return AdmissionResult(True, action, admission)


def reconcile(admission, *, actor: str, access=None, traffic=None, gateway=None) -> AdmissionResult:
    """Restart recovery of RELEASING / UNCERTAIN: prove the upstream's state (``isolation.reconcile_release``), then
    ENFORCED -> RESTORED (commissioning back to CONFIGURED), RELEASED -> ADMITTED, anything else stays UNCERTAIN."""
    action = "ADM_RECONCILE"
    access = access or _default_access(admission)
    if admission.state not in (St.RELEASING, St.UNCERTAIN):
        return _refuse(admission.device, action, [blocker("ADMISSION_STATE_INVALID", state=admission.state)], actor=actor, admission=admission)
    policy = models.IsolationPolicy.objects.get(pk=admission.isolation_policy_id)
    verify = _poller(policy, admission.expectations, traffic=traffic, admission=admission, sleep=access.sleep, settle=0)
    if policy.state == models.IsolationState.RELEASED:
        proven = isolation.IsolationResult(True, "ISO_RECONCILE", policy)
    else:
        proven = isolation.reconcile_release(policy, actor=actor, access=access, verify_admission=verify)
    state = proven.policy.state if proven.policy is not None else policy.state
    if state == models.IsolationState.RELEASED:
        return _admitted(admission, actor=actor, verification={"reconciled": True, "at": timezone.now().isoformat()}, gateway=gateway)
    if state == models.IsolationState.ENFORCED:
        with transaction.atomic():
            admission = _save(admission, state=St.RESTORED, finished_at=timezone.now(), restoration={"restored": True, "reconciled": True},
                              failure={"code": "ADMISSION_VERIFICATION_FAILED", "reconciled": True})
            _record_state(admission.commissioning, C.CONFIGURED, failure={"code": "ADMISSION_VERIFICATION_FAILED"})
            _event(admission.device, action, Outcome.RECORDED, actor=actor, admission=admission, evidence={"state": admission.state})
        return AdmissionResult(True, action, admission, [], proven.detail)
    found = [blocker("ADMISSION_RESTORE_UNPROVEN")]
    with transaction.atomic():
        admission = _save(admission, state=St.UNCERTAIN, failure={"code": "ADMISSION_RESTORE_UNPROVEN", "facts": proven.detail})
        _record_state(admission.commissioning, C.UNCERTAIN, failure={"code": "ADMISSION_RESTORE_UNPROVEN"})
        _event(admission.device, action, Outcome.REFUSED, actor=actor, admission=admission, blockers=found)
    return AdmissionResult(False, action, admission, found, proven.detail)


def status(admission) -> dict:
    return {"admission": admission.admission_id, "device": admission.device.device_id, "state": admission.state,
            "commissioning": admission.commissioning.commissioning_id, "policy": admission.isolation_policy.policy_id,
            "release_change": admission.release_change.change_id if admission.release_change_id else "",
            "evidence_digest": admission.evidence_digest, "expectations": admission.expectations, "verification": admission.verification,
            "restoration": admission.restoration, "failure": admission.failure, "requested_by": admission.requested_by,
            "approved_by": admission.approved_by}

