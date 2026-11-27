"""The lifecycle stage projection: one read-only view of a device across every authoritative lifecycle record.

The conceptual onboarding stages

    REGISTERED -> DISCOVERED -> IDENTITY_VERIFIED -> AUTHORIZED -> BOOTSTRAPPED -> ISOLATED -> COMMISSIONING -> IN_SERVICE
    -> MAINTENANCE -> DECOMMISSIONED

are NOT a second state machine.  Each stage is DERIVED from the record that owns it, and no state is duplicated or written:

    REGISTERED          ManagedDevice (origin, registered_by)
    DISCOVERED          ZtpSession discovery / DhcpLeaseObservation CORRELATED / DISCOVER lifecycle event
    IDENTITY_VERIFIED   ManagedDevice.identity_state (+ expected / claimed / observed / verified identity)
    AUTHORIZED          BootstrapAuthorization (time-bounded; scope; uses)
    BOOTSTRAPPED        ZtpSession BOOTSTRAPPED / BOOTSTRAP lifecycle event; ztp_state
    ISOLATED            IsolationPolicy (ENFORCED / VERIFIED / RELEASED)
    COMMISSIONING       CommissioningRecord (+ ProductionAdmission)
    IN_SERVICE          ManagedDevice.lifecycle_state + admission_state
    MAINTENANCE         MaintenanceRecord (core.services.maintenance_mode)
    DECOMMISSIONED      DecommissionRecord / lifecycle_state

Identity, authorization, observation, admission and operational readiness are reported as five SEPARATE verdicts: a verified
identity is not an authorization, an observation is not identity proof, and admission is not readiness.

Legacy truthfulness.  An adopted device (LEGACY_ADOPTION / admission LEGACY_PREEXISTING) predates NMAS onboarding: its
discovery, authorization, bootstrap, isolation and commissioning stages are PREDATES_NMAS -- never COMPLETE -- and its admission
verdict stays LEGACY_PREEXISTING.  Nothing here can make it ADMITTED.

Stage status vocabulary: COMPLETE, CURRENT, PENDING, FAILED, PREDATES_NMAS, NOT_APPLICABLE.
"""

from __future__ import annotations

from django.utils import timezone

from ... import models
from . import events

S = models.DeviceLifecycleState
A = models.ProductionAdmissionState
I = models.IdentityVerificationState  # noqa: E741
COMPLETE, CURRENT, PENDING, FAILED, PREDATES, NA = "COMPLETE", "CURRENT", "PENDING", "FAILED", "PREDATES_NMAS", "NOT_APPLICABLE"
STAGES = ("REGISTERED", "DISCOVERED", "IDENTITY_VERIFIED", "AUTHORIZED", "BOOTSTRAPPED", "ISOLATED", "COMMISSIONING", "IN_SERVICE",
          "MAINTENANCE", "DECOMMISSIONED")
REPORT_SCHEMA = "nmas.lifecycle.stage-report/1"
FAILURE_STATES = {"FAILED", "UNCERTAIN", "ABORTED", "RESTORED", "ROLLED_BACK", "BLOCKED", "DRIFTED", "ENTRY_ABORTED_RESTORED",
                  "RESTORE_FAILED_ESCALATED"}
_ONBOARDING_ORDER = (S.REGISTERED, S.DISCOVERED, S.BOOTSTRAPPED, S.ISOLATED, S.READY_FOR_COMMISSIONING, S.COMMISSIONING, S.IN_SERVICE)


def _iso(value):
    return value.isoformat() if value else None


def _stage(status: str, basis: str, **evidence) -> dict:
    return {"status": status, "basis": basis, "evidence": {k: v for k, v in evidence.items() if v not in (None, "", [], {})}}


def _legacy(device) -> bool:
    return device.origin == models.DeviceOrigin.LEGACY_ADOPTION or device.admission_state == A.LEGACY_PREEXISTING


def _reached(device, state) -> bool:
    """Has the device's lifecycle passed ``state`` on the onboarding path (from its own chain, not inferred)?"""
    if device.lifecycle_state in _ONBOARDING_ORDER and state in _ONBOARDING_ORDER:
        return _ONBOARDING_ORDER.index(device.lifecycle_state) >= _ONBOARDING_ORDER.index(state)
    return device.lifecycle_events.filter(to_state=state, outcome=models.DeviceLifecycleEventOutcome.ADVANCED).exists()


# --- separate verdicts ---------------------------------------------------------------------------------------------------------
def identity_verdict(device) -> dict:
    claimed = device.observations.filter(kind=models.ObservationKind.IDENTITY, trust=models.ObservationTrust.CLAIMED).order_by("-observed_at", "-id").first()
    observed = device.observations.filter(kind=models.ObservationKind.IDENTITY).exclude(
        trust=models.ObservationTrust.CLAIMED).order_by("-observed_at", "-id").first()
    return {
        "state": device.identity_state,
        "expected": {"serial": device.expected_serial, "base_mac": device.expected_base_mac},
        "claimed": ({"source": claimed.source, "claims": {k: claimed.claims.get(k) for k in ("serial", "base_mac", "model") if claimed.claims.get(k)},
                     "result": claimed.result, "observed_at": _iso(claimed.observed_at), "trust": claimed.trust} if claimed else None),
        "observed": ({"source": observed.source, "trust": observed.trust, "result": observed.result,
                      "claims": {k: observed.claims.get(k) for k in ("serial", "base_mac", "model") if observed.claims.get(k)},
                      "observed_at": _iso(observed.observed_at)} if observed else None),
        "verified": ({"serial": device.verified_serial, "base_mac": device.verified_base_mac, "host_key": device.verified_host_key,
                      "at": _iso(device.identity_verified_at), "by": device.identity_verified_by} if device.identity_state == I.VERIFIED else None),
        "meaning": "a DHCP / LLDP claim can only contradict; VERIFIED needs independently observed evidence",
    }


def authorization_verdict(device, now) -> dict:
    auth = device.bootstrap_authorizations.order_by("-id").first()
    if auth is None:
        return {"state": "NONE", "meaning": "no bootstrap was ever authorized" + (" (device predates NMAS onboarding)" if _legacy(device) else "")}
    live = auth.state in (models.BootstrapAuthorizationState.APPROVED, models.BootstrapAuthorizationState.CONSUMED) and auth.valid_from <= now < auth.valid_until
    return {"state": auth.state, "auth_id": auth.auth_id, "valid_from": _iso(auth.valid_from), "valid_until": _iso(auth.valid_until),
            "expired": now >= auth.valid_until, "live": live, "uses": f"{auth.use_count}/{auth.max_uses}", "scope": list(auth.scope or []),
            "requested_by": auth.requested_by, "approved_by": auth.approved_by, "attachment": auth.attachment_id,
            "count": device.bootstrap_authorizations.count()}


def observation_verdict(device) -> dict:
    attachments = [{"id": a.pk, "upstream": f"{a.upstream_device}:{a.upstream_interface}", "local_interface": a.local_interface,
                    "purpose": a.purpose, "connectivity": a.connectivity, "vlan": a.vlan, "approval": a.approval_state,
                    "verification": a.verification_state} for a in device.attachments.order_by("id")]
    latest = device.observations.filter(kind=models.ObservationKind.ATTACHMENT).order_by("-observed_at", "-id").first()
    return {"attachments": attachments,
            "latest_attachment_observation": ({"source": latest.source, "trust": latest.trust, "result": latest.result,
                                                "upstream": f"{latest.upstream_device}:{latest.upstream_interface}",
                                                "observed_at": _iso(latest.observed_at)} if latest else None),
            "observations": device.observations.count()}


def management_verdict(device) -> dict:
    state = models.DeviceManagementState.objects.filter(device=device).select_related("active_path").first()
    paths = []
    for path in models.ManagementPath.objects.filter(device=device).order_by("preference_class", "id"):
        paths.append({"path": path.path_id, "type": path.path_type, "class": path.preference_class, "via": path.via_device,
                      "vlan": path.vlan, "tagged": path.tagged, "vrf": path.vrf, "approval": path.approval_state, "health": path.health_state,
                      "active": bool(state and state.active_path_id == path.pk)})
    return {"status": state.status if state else models.ManagementStatus.UNKNOWN,
            "active_path": state.active_path.path_id if state and state.active_path_id else "",
            "reconciliation_required": bool(state and state.reconciliation_required),
            "last_transition_at": _iso(state.last_transition_at) if state else None, "paths": paths,
            "hierarchy": "DIRECT_OOB (1) > VLAN_ADJACENT_SWITCH (2, by switch identity) > ROUTED_VRF (3)"}


def admission_verdict(device) -> dict:
    admission = models.ProductionAdmission.objects.filter(device=device).order_by("-id").first()
    out = {"state": device.admission_state}
    if admission:
        out.update({"admission": admission.admission_id, "record_state": admission.state, "finished_at": _iso(admission.finished_at),
                    "approved_by": admission.approved_by})
    if device.admission_state == A.LEGACY_PREEXISTING:
        out["meaning"] = "production participation predates NMAS admission control; it is not an NMAS admission"
    return out


def readiness_verdict(device, management: dict, maintenance: dict, chain_ok: bool) -> dict:
    from ..maintenance_mode import lifecycle as maintenance_lifecycle

    reasons, notes = [], []
    if device.lifecycle_state != S.IN_SERVICE:
        reasons.append(f"lifecycle {device.lifecycle_state}")
    if management["status"] == models.ManagementStatus.NO_PATH:
        reasons.append("management NO_PATH (the resolver fails closed)")
    elif management["status"] == models.ManagementStatus.UNKNOWN:
        notes.append("management paths not evaluated by the selector (resolved from the registry target)")
    if management["reconciliation_required"]:
        reasons.append("management reconciliation required")
    if maintenance.get("state") in maintenance_lifecycle.IN_MAINTENANCE:
        reasons.append(f"in maintenance {maintenance['record_id']}")
    if not chain_ok:
        reasons.append("lifecycle evidence chain broken")
    return {"ready": not reasons, "reasons": reasons, "notes": notes,
            "meaning": "operational readiness from stored lifecycle records only; live reachability is the health engine's verdict"}


# --- stages ----------------------------------------------------------------------------------------------------------------------
def _stages(device, verdicts: dict, now) -> dict:
    legacy = _legacy(device)
    session = device.ztp_sessions.order_by("-id").first()
    isolation = models.IsolationPolicy.objects.filter(device=device).order_by("-id").first()
    commissioning = models.CommissioningRecord.objects.filter(device=device).order_by("-id").first()
    decommission = models.DecommissionRecord.objects.filter(device=device).order_by("-id").first()
    maintenance = verdicts["maintenance"]
    lc = device.lifecycle_state
    stages = {"REGISTERED": _stage(COMPLETE, "adopted existing device" if device.origin == models.DeviceOrigin.LEGACY_ADOPTION else "registered",
                                   origin=device.origin, registered_by=device.registered_by, at=_iso(device.created_at))}

    def onboarding(name, done: bool, basis: str, **evidence):
        if legacy:
            stages[name] = _stage(PREDATES, "device predates NMAS onboarding (no fabricated history)")
        elif done:
            stages[name] = _stage(COMPLETE, basis, **evidence)
        elif lc in (S.FAILED, S.WITHDRAWN):
            stages[name] = _stage(FAILED if lc == S.FAILED else NA, f"lifecycle {lc}")
        else:
            stages[name] = _stage(PENDING, basis, **evidence)

    discovered = _reached(device, S.DISCOVERED)
    onboarding("DISCOVERED", discovered, "trusted relay evidence correlated" if discovered else "awaiting native DHCP discovery",
               session=session.session_id if session else "", stage=session.stage if session else "",
               lease=(session.discovery or {}).get("lease_observation") if session else None)
    ident = verdicts["identity"]["state"]
    stages["IDENTITY_VERIFIED"] = (_stage(COMPLETE, "independently observed identity verified", by=device.identity_verified_by,
                                          at=_iso(device.identity_verified_at)) if ident == I.VERIFIED else
                                   _stage(FAILED, "observed identity conflicts with the authorized identity") if ident == I.MISMATCH else
                                   _stage(PENDING, f"identity {ident}"))
    auth = verdicts["authorization"]
    used = device.bootstrap_authorizations.filter(use_count__gt=0).order_by("-id").first()
    onboarding("AUTHORIZED", auth["state"] in ("APPROVED", "CONSUMED") or used is not None,
               f"bootstrap authorization {auth['state']}" + (f" (used by {used.auth_id} before it closed)" if used and auth["state"] not in ("APPROVED", "CONSUMED") else ""),
               auth=auth.get("auth_id"), valid_until=auth.get("valid_until"), uses=auth.get("uses"))
    if not legacy and auth["state"] in ("REVOKED", "EXPIRED") and used is None and not _reached(device, S.BOOTSTRAPPED):
        stages["AUTHORIZED"]["status"] = FAILED
    onboarding("BOOTSTRAPPED", _reached(device, S.BOOTSTRAPPED), f"ZTP {session.stage if session else 'not opened'}; ztp_state {device.ztp_state}",
               session=session.session_id if session else "", ztp_state=device.ztp_state)
    if isolation is not None and not legacy:
        status = (FAILED if isolation.state in FAILURE_STATES else COMPLETE if isolation.state == "RELEASED"
                  else CURRENT if isolation.state in ("ENFORCED", "VERIFIED", "RELEASE_PENDING") else PENDING)
        stages["ISOLATED"] = _stage(status, f"isolation {isolation.state}", policy=isolation.policy_id,
                                    upstream=f"{isolation.upstream_device}:{isolation.upstream_interface}",
                                    verified_at=_iso(isolation.verified_at), released_at=_iso(isolation.released_at))
    else:
        onboarding("ISOLATED", _reached(device, S.ISOLATED), "no isolation policy")
    if commissioning is not None and not legacy:
        status = (COMPLETE if commissioning.state == "ADMITTED" else FAILED if commissioning.state in FAILURE_STATES else CURRENT)
        stages["COMMISSIONING"] = _stage(status, f"commissioning {commissioning.state}", record=commissioning.commissioning_id,
                                         admission=verdicts["admission"].get("admission"), approved_by=commissioning.approved_by)
    else:
        onboarding("COMMISSIONING", _reached(device, S.IN_SERVICE), "no commissioning record")
    if lc == S.IN_SERVICE:
        stages["IN_SERVICE"] = _stage(CURRENT, f"in service; admission {device.admission_state}", admission=device.admission_state)
    elif lc in (S.DECOMMISSION_PENDING, S.DECOMMISSIONED) or (decommission and decommission.state == "DECOMMISSIONED"):
        stages["IN_SERVICE"] = _stage(COMPLETE, "was in service")
    else:
        stages["IN_SERVICE"] = _stage(PENDING, f"lifecycle {lc}")
    from ..maintenance_mode import lifecycle as maintenance_lifecycle

    if maintenance.get("state") in maintenance_lifecycle.IN_MAINTENANCE:
        stages["MAINTENANCE"] = _stage(CURRENT, f"maintenance {maintenance['state']}", record=maintenance["record_id"])
    elif maintenance.get("state") in maintenance_lifecycle.RESOLVED:
        stages["MAINTENANCE"] = _stage(NA, f"last maintenance {maintenance['state']} (resolved)", record=maintenance["record_id"])
    elif maintenance:
        stages["MAINTENANCE"] = _stage(PENDING, f"maintenance {maintenance['state']} (not entered)", record=maintenance["record_id"])
    else:
        stages["MAINTENANCE"] = _stage(NA, "never in maintenance")
    if lc == S.DECOMMISSIONED:
        stages["DECOMMISSIONED"] = _stage(COMPLETE, "decommissioned", record=decommission.record_id if decommission else "", retired_at=_iso(device.retired_at))
    elif decommission is not None and decommission.is_open:
        stages["DECOMMISSIONED"] = _stage(CURRENT, f"decommission {decommission.state}", record=decommission.record_id,
                                          blockers=[b.get("code") for b in (decommission.blockers or []) if isinstance(b, dict)][:10])
    elif decommission is not None:
        stages["DECOMMISSIONED"] = _stage(FAILED if decommission.state in FAILURE_STATES else NA, f"last decommission {decommission.state}",
                                          record=decommission.record_id)
    else:
        stages["DECOMMISSIONED"] = _stage(NA, "no decommission requested")
    return stages


def eligibility(device) -> dict:
    """What the lifecycle graph and the open records allow next (the readiness engines decide with live evidence when asked)."""
    from . import lifecycle

    allowed = lifecycle.allowed_targets(device.lifecycle_state)
    open_decommission = models.DecommissionRecord.objects.filter(device=device, state__in=tuple(models.DECOMMISSION_OPEN)).first()
    return {"allowed_transitions": allowed,
            "maintenance": {"eligible_to_request": device.lifecycle_state == S.IN_SERVICE,
                            "rule": "active production traffic without a proven lossless move blocks entry (ACTIVE_TRAFFIC_NO_LOSSLESS_DRAIN)"},
            "decommission": {"eligible_to_request": S.DECOMMISSION_PENDING in allowed and open_decommission is None,
                             "open_record": open_decommission.record_id if open_decommission else "",
                             "rule": "readiness READY_IDLE / READY_LOSSLESS only; active traffic without a lossless alternative is BLOCKED"}}


def failures(device, limit: int = 15) -> list[dict]:
    """Refused / failed lifecycle attempts and rolled-back records, newest first (evidence ids only)."""
    # every row carries the same keys (the page renders them uniformly)
    rows = [{"kind": "event", "reference": f"#{e.sequence} {e.action}", "status": e.outcome, "at": _iso(e.created_at),
             "codes": [b.get("code") for b in (e.blockers or []) if isinstance(b, dict) and b.get("code")][:5], "rollback": False}
            for e in device.lifecycle_events.filter(outcome=models.DeviceLifecycleEventOutcome.REFUSED).order_by("-sequence")[:limit]]
    for model, ident in ((models.IsolationPolicy, "policy_id"), (models.CommissioningRecord, "commissioning_id"),
                         (models.ProductionAdmission, "admission_id"), (models.DecommissionRecord, "record_id")):
        for record in model.objects.filter(device=device, state__in=tuple(FAILURE_STATES)).order_by("-id")[:5]:
            failure = getattr(record, "failure", None) or {}
            code = failure.get("code", "") if isinstance(failure, dict) else ""
            rows.append({"kind": model.__name__, "reference": getattr(record, ident), "status": record.state,
                         "at": _iso(getattr(record, "updated_at", None)), "codes": [code] if code else [],
                         "rollback": bool(getattr(record, "restoration", None)) or record.state in ("RESTORED", "ROLLED_BACK")})
    return rows


def device_report(device, *, now=None) -> dict:
    now = now or timezone.now()
    from . import lifecycle

    chain_ok = events.verify_chain(device)
    last = device.lifecycle_events.order_by("-sequence").first()
    verdicts = {"identity": identity_verdict(device), "authorization": authorization_verdict(device, now),
                "observation": observation_verdict(device), "admission": admission_verdict(device),
                "management": management_verdict(device), "maintenance": lifecycle.maintenance_state(device)}
    verdicts["readiness"] = readiness_verdict(device, verdicts["management"], verdicts["maintenance"], chain_ok)
    stages = _stages(device, verdicts, now)
    return {"schema": REPORT_SCHEMA, "device": device.device_id, "name": device.name, "platform": device.platform, "role": device.role,
            "origin": device.origin, "legacy": _legacy(device), "lifecycle_state": device.lifecycle_state,
            "admission_state": device.admission_state, "identity_state": device.identity_state, "ztp_state": device.ztp_state,
            "stages": [{"stage": name, **stages[name]} for name in STAGES], "verdicts": verdicts, "eligibility": eligibility(device),
            "failures": failures(device),
            "evidence": {"chain_intact": chain_ok, "events": device.lifecycle_events.count(), "last_sequence": last.sequence if last else 0,
                         "head_digest": last.entry_digest if last else ""},
            "generated_at": now.isoformat()}


def fleet_report(*, now=None, include_retired: bool = False) -> dict:
    now = now or timezone.now()
    devices = models.ManagedDevice.objects.order_by("id")
    if not include_retired:
        devices = devices.exclude(lifecycle_state__in=tuple(models.DEVICE_LIFECYCLE_TERMINAL))
    reports = [device_report(d, now=now) for d in devices]
    summary = {"devices": len(reports), "chains_intact": sum(r["evidence"]["chain_intact"] for r in reports),
               "admitted": sum(r["admission_state"] == A.ADMITTED for r in reports),
               "legacy_preexisting": sum(r["admission_state"] == A.LEGACY_PREEXISTING for r in reports),
               "identity_verified": sum(r["identity_state"] == I.VERIFIED for r in reports),
               "ready": sum(r["verdicts"]["readiness"]["ready"] for r in reports)}
    return {"schema": "nmas.lifecycle.fleet-report/1", "summary": summary, "devices": reports, "generated_at": now.isoformat()}
