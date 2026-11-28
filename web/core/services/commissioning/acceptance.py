"""Live commissioning acceptance gates (R4 -> R6 -> R7 shape; no device name is special-cased).

Read-only.  It composes the verdicts the lifecycle services already own -- the stage projection (``devices.stage_report``), the
commissioning dependency graph, the upstream-trust rule, bootstrap-authorization windows, ZTP lease / renewal evidence, the
isolation policy records and the management-path registry -- with the latest traffic-runner evidence and an optional
device-specific live-change scope.  It never writes, never contacts a device and never executes a lifecycle step: a disruptive
step runs only through its own governed workflow (Change / isolation / commissioning / admission approvals), and this gate is
re-run before and after every such step.

Verdict per gate: PASS, FAIL (an invariant is broken: stop), BLOCKED (a prerequisite is missing: fix it first) or
NOT_APPLICABLE.  Overall: FAIL if any gate fails, else BLOCKED if any is blocked, else READY.  READY means "every precondition
the scope names holds"; it is never an authorization by itself.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta

from django.utils import timezone

from ... import models
from ..devices import attachments as attachment_service
from ..devices import codes as device_codes
from ..devices import stage_report
from ..ztp import adapters as ztp_adapters
from ..ztp import lease as ztp_lease
from ..ztp import policy as ztp_policy
from . import dependencies

SCHEMA = "nmas.lifecycle.acceptance-gates/1"
SCOPE_SCHEMA = "nmas.lifecycle.live-scope/1"
PASS, FAIL, BLOCKED, NOT_APPLICABLE, PLANNED = "PASS", "FAIL", "BLOCKED", "NOT_APPLICABLE", "PLANNED"
READY = "READY"
DEFAULT_TRAFFIC_FRESHNESS_SECONDS = 900

#: The disruptive operations a live scope may authorize, each with the governed workflow that performs it and its rollback.
#: The gate validates a scope against this vocabulary; it performs none of them.
OPERATIONS = {
    "BOOTSTRAP_AUTHORIZE": ("bootstrap authorization (request -> second-person approval), bounded window and use count",
                            "revoke the authorization (authorization.revoke); expiry closes it on its own"),
    "ISOLATION_ENFORCE": ("isolation policy plan -> governed Change on the trusted upstream -> enforce -> verify",
                          "isolation release / restore of the recorded exact inverse (plan ops), upstream digest re-checked"),
    "ZTP_REBOOTSTRAP": ("device erase + reload into native ZTP behind the enforced isolation, DHCP via the trusted relay",
                        "restore the device's saved startup-config; the DHCP policy rollback (ztp.policy.rollback_policy)"),
    "DHCP_RENEWAL_WINDOW": ("controlled re-discovery window (ztp.lease.expect_renewal) re-deciding authorization + upstream",
                            "window lapses on its own deadline; OVERDUE offers native-only recovery actions"),
    "COMMISSIONING_CONFIGURE": ("commissioning record: configure while isolated (isolation stays VERIFIED, no drift)",
                                "commissioning abort -> restore the device to its pre-commissioning digest"),
    "ADMISSION": ("production admission plan -> precheck -> second-person approval -> execute -> verify",
                  "failed verification restores the upstream byte-identical and re-verifies isolation (ADMISSION_VERIFICATION_FAILED)"),
    "MANAGEMENT_PATH_APPROVE": ("management path register -> second-person approval (Management VRF or VLAN 200)",
                                "revoke the path (management.paths.revoke_path); the selector fails closed to the remaining paths"),
}
SCOPE_CONTINUITY = ("ZERO_LOSS", "APPROVED_OUTAGE_WINDOW")

#: Gate codes (message, remediation).  Kept here, not in ``devices.codes``, so this read-only module stays additive: codes the
#: lifecycle services already own are taken from their registry unchanged.
CODES = {
    "LIVE_SCOPE_NOT_PROVIDED": ("No device-specific live-change scope was given.", "Prepare one (scope-template) and have a second person approve it."),
    "LIVE_SCOPE_SCHEMA_INVALID": ("The scope is not a nmas.lifecycle.live-scope/1 document.", "Start from scope-template."),
    "LIVE_SCOPE_DEVICES_INVALID": ("The scope names no devices.", "List each device with its operations."),
    "LIVE_SCOPE_DEVICES_MISMATCH": ("The scope's devices differ from the devices being checked.", "Check exactly the scoped devices, in order."),
    "LIVE_SCOPE_OPERATION_UNKNOWN": ("A scoped operation is empty or not in the allowed vocabulary.", "Use only allowed_operations."),
    "LIVE_SCOPE_NOT_APPROVED": ("The scope has no preparer or no approver.", "A second authorized operator must approve it."),
    "LIVE_SCOPE_SELF_APPROVAL": ("The preparer approved their own scope.", "A different authorized operator must approve."),
    "LIVE_SCOPE_WINDOW_INVALID": ("The scope window is missing, naive or empty.", "Give timezone-aware start < end."),
    "LIVE_SCOPE_EXPIRED": ("The scope window has ended.", "Prepare and approve a new scope."),
    "LIVE_SCOPE_NOT_YET_OPEN": ("The scope window has not started.", "Wait for the window."),
    "LIVE_SCOPE_CONTINUITY_INVALID": ("The traffic-continuity requirement is missing or malformed.", "ZERO_LOSS, or an approved outage window."),
    "LIVE_SCOPE_MANAGEMENT_NOT_RETAINED": ("The scope does not require management access to be retained.", "Set retain_management."),
    "TRAFFIC_FLOWS_NOT_DECLARED": ("No production flows are declared for the continuity baseline.", "Declare every protected flow."),
    "COMMISSIONING_DEPENDENCY_NOT_DECLARED": ("The device rides on an NMAS-onboarded upstream with no ACTIVE dependency.",
                                              "Declare (derive) the ATTACHMENT_UPSTREAM dependency."),
    "RELAY_NOT_DECLARED": ("No trusted DHCP relay is declared for the device's upstream on its bootstrap network.",
                           "Record the upstream as a trusted relay of the bootstrap network."),
    "DHCP_RENEWAL_OVERDUE": ("A controlled re-discovery window passed without a renewal.", "Follow the adapter's native recovery actions."),
    "ISOLATION_POLICY_NOT_FOUND": ("An attachment has no isolation policy.", "Plan the isolation before any bootstrap."),
    "ISOLATION_VERIFICATION_INCOMPLETE": ("The latest isolation verification is missing a check or a check failed.", "Re-verify the isolation."),
    "ISOLATION_FAMILY_UNCOVERED": ("The isolation does not cover both IPv4 and IPv6 (OSPFv2 and OSPFv3).", "Re-plan it dual-stack."),
    "ISOLATION_INVERSE_MISSING": ("The isolation plan holds no exact inverse.", "Re-plan the isolation; no release without an inverse."),
    "ISOLATION_STATE_UNSAFE": ("The isolation is DRIFTED, UNCERTAIN or BLOCKED.", "Reconcile it before anything else."),
    "ISOLATION_NOT_RELEASED": ("An in-service device's isolation was never released.", "Reconcile the admission record."),
}


def blocker(code: str, **details) -> dict:
    message, remediation = device_codes.BLOCKERS.get(code) or CODES[code]
    return {"code": code, "message": message, "remediation": remediation, **({"details": details} if details else {})}


def _gate(name: str, status: str, codes=(), **evidence) -> dict:
    return {"gate": name, "status": status, "codes": list(codes), "evidence": evidence}


def _iso(value):
    return value.isoformat() if value else None


def _codes(problems) -> list[str]:
    return [p.get("code", "") for p in problems if isinstance(p, dict)]


# --- scope ------------------------------------------------------------------------------------------------------------------------
def scope_problems(scope: dict | None, *, now=None) -> list[dict]:
    """Why ``scope`` cannot authorize a live step ([] when it is well-formed, approved by a second person and current)."""
    now = now or timezone.now()
    if not scope:
        return [blocker("LIVE_SCOPE_NOT_PROVIDED")]
    found = []
    if scope.get("schema") != SCOPE_SCHEMA:
        found.append(blocker("LIVE_SCOPE_SCHEMA_INVALID", expected=SCOPE_SCHEMA))
    devices = scope.get("devices")
    if not isinstance(devices, list) or not devices or not all(isinstance(d, dict) and d.get("name") for d in devices):
        found.append(blocker("LIVE_SCOPE_DEVICES_INVALID"))
        devices = []
    for entry in devices:
        unknown = sorted(set(entry.get("operations") or []) - set(OPERATIONS))
        if unknown or not entry.get("operations"):
            found.append(blocker("LIVE_SCOPE_OPERATION_UNKNOWN", device=entry["name"], operations=unknown))
    prepared, approved = str(scope.get("prepared_by") or ""), str(scope.get("approved_by") or "")
    if not prepared or not approved:
        found.append(blocker("LIVE_SCOPE_NOT_APPROVED"))
    elif prepared == approved:
        found.append(blocker("LIVE_SCOPE_SELF_APPROVAL", actor=prepared))
    window = scope.get("window") or {}
    try:
        start, end = datetime.fromisoformat(window["start"]), datetime.fromisoformat(window["end"])
        if start.tzinfo is None or end.tzinfo is None:
            raise ValueError("naive")
    except (KeyError, TypeError, ValueError):
        found.append(blocker("LIVE_SCOPE_WINDOW_INVALID"))
    else:
        if end <= start:
            found.append(blocker("LIVE_SCOPE_WINDOW_INVALID"))
        elif now >= end:
            found.append(blocker("LIVE_SCOPE_EXPIRED", end=end.isoformat()))
        elif now < start:
            found.append(blocker("LIVE_SCOPE_NOT_YET_OPEN", start=start.isoformat()))
    continuity = scope.get("traffic_continuity") or {}
    if continuity.get("mode") not in SCOPE_CONTINUITY:
        found.append(blocker("LIVE_SCOPE_CONTINUITY_INVALID", allowed=list(SCOPE_CONTINUITY)))
    elif continuity["mode"] == "APPROVED_OUTAGE_WINDOW" and not (isinstance(continuity.get("max_outage_seconds"), int)
                                                                 and continuity["max_outage_seconds"] > 0):
        found.append(blocker("LIVE_SCOPE_CONTINUITY_INVALID", reason="an outage window needs a positive max_outage_seconds"))
    if not scope.get("retain_management"):
        found.append(blocker("LIVE_SCOPE_MANAGEMENT_NOT_RETAINED"))
    if not isinstance(scope.get("flows"), list) or not scope["flows"]:
        found.append(blocker("TRAFFIC_FLOWS_NOT_DECLARED"))
    return found


def scope_digest(scope: dict | None) -> str:
    return hashlib.sha256(json.dumps(scope or {}, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def scoped_operations(scope: dict | None, name: str) -> set[str]:
    for entry in (scope or {}).get("devices") or []:
        if isinstance(entry, dict) and entry.get("name") == name:
            return set(entry.get("operations") or [])
    return set()


# --- per-device gates ---------------------------------------------------------------------------------------------------------------
def live_attachments(device):
    return list(device.attachments.filter(attachment_service.LIVE_ATTACHMENT).order_by("id"))


def lifecycle_gate(device, report: dict) -> dict:
    ev = report["evidence"]
    status = PASS if ev["chain_intact"] else FAIL
    return _gate("LIFECYCLE", status, [] if ev["chain_intact"] else ["LIFECYCLE_CHAIN_BROKEN"],
                 lifecycle_state=report["lifecycle_state"], admission_state=report["admission_state"], origin=report["origin"],
                 events=ev["events"], head_digest=ev["head_digest"],
                 stages={s["stage"]: s["status"] for s in report["stages"]})


def identity_gate(device, report: dict) -> dict:
    verdict = report["verdicts"]["identity"]
    verified = verdict["verified"] or {}
    if device.identity_state != models.IdentityVerificationState.VERIFIED:
        return _gate("IDENTITY", FAIL, ["IDENTITY_NOT_VERIFIED"], state=device.identity_state)
    if not verified.get("host_key"):
        return _gate("IDENTITY", FAIL, ["IDENTITY_HOST_KEY_NOT_PINNED"], state=device.identity_state)
    return _gate("IDENTITY", PASS, state=device.identity_state, serial=verified.get("serial"), base_mac=verified.get("base_mac"),
                 verified_at=verified.get("at"), verified_by=verified.get("by"))


def dependency_gate(device) -> dict:
    """R6 before R7: every ACTIVE dependency satisfied, no cycle, and an attachment on an NMAS-onboarded upstream is declared."""
    problems = dependencies.unmet(device)
    declared = {d.upstream_id for d in device.commissioning_dependencies.filter(state=models.DependencyState.ACTIVE)}
    for attachment in live_attachments(device):
        upstream = models.ManagedDevice.objects.filter(name=attachment.upstream_device,
                                                       origin=models.DeviceOrigin.REGISTERED_NEW).first()
        if upstream is not None and upstream.pk not in declared:
            problems.append(blocker("COMMISSIONING_DEPENDENCY_NOT_DECLARED", upstream=upstream.name, attachment=attachment.pk))
    rows = [{"upstream": d.upstream.name, "kind": d.kind, "satisfied": dependencies.satisfied(d.upstream)[1]}
            for d in device.commissioning_dependencies.select_related("upstream").filter(state=models.DependencyState.ACTIVE)]
    return _gate("DEPENDENCY", FAIL if problems else PASS, _codes(problems), dependencies=rows, problems=problems)


def upstream_gate(device) -> dict:
    attachments = live_attachments(device)
    if not attachments:
        return _gate("UPSTREAM", BLOCKED, ["ATTACHMENT_NOT_REGISTERED"])
    rows, problems = [], []
    for attachment in attachments:
        found = attachment_service.upstream_problems(device.name, attachment.upstream_device)
        problems += found
        rows.append({"attachment": attachment.pk, "upstream": f"{attachment.upstream_device}:{attachment.upstream_interface}",
                     "purpose": attachment.purpose, "approval": attachment.approval_state, "trusted": not found})
    return _gate("UPSTREAM", FAIL if problems else PASS, _codes(problems), attachments=rows, single_homed=len(attachments) == 1)


def authorization_gate(device, operations: set[str], window_end, now) -> dict:
    """An open bootstrap grant exists only inside an approved live scope; every closed grant must already be refused."""
    rows, open_grants = [], []
    for auth in device.bootstrap_authorizations.order_by("id"):
        problems = ztp_policy.authorization_problems(auth, now=now)
        rows.append({"auth": auth.auth_id, "state": auth.state, "valid_until": _iso(auth.valid_until), "uses": f"{auth.use_count}/{auth.max_uses}",
                     "refused_now": _codes(problems)})
        if not problems:
            open_grants.append(auth)
    wants_bootstrap = bool(operations & {"ZTP_REBOOTSTRAP", "DHCP_RENEWAL_WINDOW"})
    if open_grants and not wants_bootstrap:
        return _gate("BOOTSTRAP_AUTHORIZATION", FAIL, ["BOOTSTRAP_AUTHORIZATION_OPEN_OUTSIDE_SCOPE"], authorizations=rows)
    if wants_bootstrap:
        covering = [a for a in open_grants if window_end is None or a.valid_until >= window_end]
        if not covering:
            return _gate("BOOTSTRAP_AUTHORIZATION", BLOCKED, ["BOOTSTRAP_AUTHORIZATION_REQUIRED"], authorizations=rows,
                         window_end=_iso(window_end))
    return _gate("BOOTSTRAP_AUTHORIZATION", PASS, authorizations=rows)


_BOOTSTRAP_OPS = frozenset({"ZTP_REBOOTSTRAP", "DHCP_RENEWAL_WINDOW"})


def dhcp_gate(device, operations: set[str], now) -> dict:
    """Lease, renewal and relay evidence of the device's latest ZTP session.

    An OVERDUE renewal window is an invariant break (FAIL).  The bootstrap network's validity and its trusted relay matter only
    for a scoped re-bootstrap: once the device is onboarded its own addresses lie inside that subnet, so the historical network
    no longer validates as a *new* bootstrap network -- reported as evidence, and BLOCKED only when a re-bootstrap is scoped."""
    wants = bool(operations & _BOOTSTRAP_OPS)
    session = device.ztp_sessions.select_related("network").order_by("-id").first()
    if session is None:
        return _gate("DHCP_LEASE_RELAY", BLOCKED if wants else NOT_APPLICABLE, ["ZTP_SESSION_NOT_FOUND"] if wants else [])
    network = session.network
    findings = ztp_policy.stored_network_problems(network)
    relays = {a.upstream_device: ztp_policy.relay_for(network, a.upstream_device) for a in live_attachments(device)}
    if not any(relays.values()):
        findings.append(blocker("RELAY_NOT_DECLARED", network=network.name if network else ""))
    renewal = ztp_lease.renewal_status(session, now=now)
    window = ztp_lease.renewal_window_seconds(ztp_adapters.get(session.adapter))
    evidence = {"session": session.session_id, "stage": session.stage, "network": network.name if network else "", "relays": relays,
                "lease": ztp_lease.status(session, now=now), "renewal": renewal, "renewal_window_seconds": window,
                "network_findings": findings}
    if renewal.get("state") == ztp_lease.OVERDUE:
        return _gate("DHCP_LEASE_RELAY", FAIL, ["DHCP_RENEWAL_OVERDUE"], **evidence)
    if wants and findings:
        return _gate("DHCP_LEASE_RELAY", BLOCKED, _codes(findings), **evidence)
    if window is None and "DHCP_RENEWAL_WINDOW" in operations:
        return _gate("DHCP_LEASE_RELAY", BLOCKED, ["NATIVE_RETRY_UNDOCUMENTED"], **evidence)
    return _gate("DHCP_LEASE_RELAY", PASS, **evidence)


def isolation_gate(device) -> dict:
    """The upstream-side isolation that kept the device's OSPFv2/OSPFv3 and routes out of production until admission."""
    rows, problems = [], []
    for attachment in live_attachments(device):
        policy = attachment.isolation_policies.order_by("-id").first()
        if policy is None:
            problems.append(blocker("ISOLATION_POLICY_NOT_FOUND", attachment=attachment.pk))
            continue
        elements = (policy.intent or {}).get("elements") or {}
        checks = (policy.verification or {}).get("checks") or {}
        failed = sorted(k for k, v in checks.items() if not (isinstance(v, dict) and v.get("ok")))
        if not checks or failed:
            problems.append(blocker("ISOLATION_VERIFICATION_INCOMPLETE", policy=policy.policy_id, failed=failed))
        missing = [family for family in ("IPV4", "IPV6") if not elements.get(family)]
        if missing:
            problems.append(blocker("ISOLATION_FAMILY_UNCOVERED", policy=policy.policy_id, families=missing))
        if not ((policy.plan or {}).get("ops")):
            problems.append(blocker("ISOLATION_INVERSE_MISSING", policy=policy.policy_id))
        if policy.state in (models.IsolationState.DRIFTED, models.IsolationState.UNCERTAIN, models.IsolationState.BLOCKED):
            problems.append(blocker("ISOLATION_STATE_UNSAFE", policy=policy.policy_id, state=policy.state))
        if device.lifecycle_state == models.DeviceLifecycleState.IN_SERVICE and policy.state != models.IsolationState.RELEASED:
            problems.append(blocker("ISOLATION_NOT_RELEASED", policy=policy.policy_id, state=policy.state))
        rows.append({"policy": policy.policy_id, "state": policy.state, "upstream": f"{policy.upstream_device}:{policy.upstream_interface}",
                     "upstream_platform": policy.upstream_platform, "elements": sorted(elements), "checks": sorted(checks),
                     "verified_at": _iso(policy.verified_at), "released_at": _iso(policy.released_at),
                     "apply_change": policy.apply_change_id, "release_change": policy.release_change_id})
    return _gate("ISOLATION", FAIL if problems else PASS, _codes(problems), policies=rows, problems=problems)


def _in_band(path) -> bool:
    if path.path_type == models.ManagementPathType.ROUTED_VRF:
        return bool(path.vrf)
    return path.path_type == models.ManagementPathType.VLAN_ADJACENT_SWITCH and path.vlan == attachment_service.MANAGEMENT_VLAN


def management_gate(device, report: dict) -> dict:
    """Approved in-band management (Management VRF or VLAN 200) that stays usable while the device is worked on."""
    paths = [p for p in models.ManagementPath.objects.filter(device=device).order_by("preference_class", "id")]
    approved = [p for p in paths if p.approval_state == models.ManagementApproval.APPROVED]
    in_band = [p for p in approved if _in_band(p)]
    healthy = [p for p in in_band if p.health_state == models.ManagementPathHealth.HEALTHY]
    rows = [{"path": p.path_id, "type": p.path_type, "vrf": p.vrf, "vlan": p.vlan, "approval": p.approval_state, "health": p.health_state}
            for p in paths]
    verdict = report["verdicts"]["management"]
    if verdict["reconciliation_required"]:
        return _gate("MANAGEMENT", FAIL, ["MANAGEMENT_RECONCILIATION_REQUIRED"], paths=rows)
    if not in_band:
        return _gate("MANAGEMENT", BLOCKED, ["MANAGEMENT_PATH_NOT_APPROVED"], paths=rows, management_status=verdict["status"])
    if not healthy:
        return _gate("MANAGEMENT", BLOCKED, ["MANAGEMENT_PATH_NOT_HEALTHY"], paths=rows, management_status=verdict["status"])
    return _gate("MANAGEMENT", PASS, paths=rows, management_status=verdict["status"], redundant=len([p for p in approved
                                                                                          if p.health_state == models.ManagementPathHealth.HEALTHY]) > 1)


_CHANGE_ACTIVE = (models.ChangeLifecycleState.DEPLOYING,)
_CHANGE_PENDING = (models.ChangeLifecycleState.VALIDATED, models.ChangeLifecycleState.CI_PENDING, models.ChangeLifecycleState.READY_TO_DEPLOY)


def quiescence_gate(device, report: dict) -> dict:
    """No maintenance, no in-flight or pending governed Change on the device or its upstreams."""
    names = {device.name} | {a.upstream_device for a in live_attachments(device)}
    targets = models.ChangeTarget.objects.select_related("change").filter(device_name__in=sorted(names))
    active = sorted({t.change.change_id for t in targets if t.change.lifecycle_state in _CHANGE_ACTIVE})
    pending = sorted({t.change.change_id for t in targets if t.change.lifecycle_state in _CHANGE_PENDING})
    readiness = report["verdicts"]["readiness"]
    maintenance = report["verdicts"]["maintenance"]
    if active:
        return _gate("QUIESCENCE", FAIL, ["CHANGE_IN_FLIGHT"], changes=active, scope=sorted(names))
    codes = (["CHANGE_PENDING"] if pending else []) + ([] if readiness["ready"] else ["DEVICE_NOT_READY"])
    return _gate("QUIESCENCE", BLOCKED if codes else PASS, codes, pending_changes=pending, readiness=readiness,
                 maintenance=maintenance, scope=sorted(names))


# --- traffic ---------------------------------------------------------------------------------------------------------------------------
def traffic_gate(flows, *, now, freshness_seconds: int = DEFAULT_TRAFFIC_FRESHNESS_SECONDS) -> dict:
    """Every declared production flow has a fresh PASSED traffic-runner run (the continuity baseline)."""
    if not flows:
        return _gate("TRAFFIC_BASELINE", BLOCKED, ["TRAFFIC_FLOWS_NOT_DECLARED"])
    cutoff = now - timedelta(seconds=freshness_seconds)
    rows, fail, stale = [], False, False
    for flow in flows:
        q = models.TrafficRun.objects.filter(source=flow.get("source", ""), destination=flow.get("destination", ""),
                                             family=flow.get("protocol", ""), address_family=flow.get("family", ""))
        run = q.exclude(status__in=(models.TrafficRunStatus.CREATED, models.TrafficRunStatus.RUNNING)).order_by("-finished_at", "-id").first()
        if run is None:
            state = "NO_EVIDENCE"
            stale = True
        elif run.status != models.TrafficRunStatus.PASSED:
            state, fail = run.status, True
        elif run.finished_at is None or run.finished_at < cutoff:
            state, stale = "STALE", True
        else:
            state = "FRESH_PASS"
        rows.append({**{k: flow.get(k) for k in ("source", "destination", "protocol", "family", "through")}, "state": state,
                     "run": str(run.run_id) if run else None, "finished_at": _iso(run.finished_at) if run else None})
    if fail:
        return _gate("TRAFFIC_BASELINE", FAIL, ["TRAFFIC_BASELINE_FAILED"], flows=rows, freshness_seconds=freshness_seconds)
    if stale:
        return _gate("TRAFFIC_BASELINE", BLOCKED, ["TRAFFIC_BASELINE_STALE"], flows=rows, freshness_seconds=freshness_seconds)
    return _gate("TRAFFIC_BASELINE", PASS, flows=rows, freshness_seconds=freshness_seconds)


def continuity_gate(device, upstream: dict, flows, scope: dict | None) -> dict:
    """A single-homed device cannot be re-onboarded with ZERO_LOSS for the flows that traverse it."""
    through = [f for f in flows or [] if device.name in (f.get("through") or [])]
    mode = ((scope or {}).get("traffic_continuity") or {}).get("mode")
    evidence = {"single_homed": upstream["evidence"].get("single_homed"), "flows_through": len(through), "mode": mode}
    if not through:
        return _gate("CONTINUITY", PASS, **evidence)
    if upstream["evidence"].get("single_homed") and mode != "APPROVED_OUTAGE_WINDOW":
        return _gate("CONTINUITY", BLOCKED, ["NO_REDUNDANT_PATH"], **evidence)
    return _gate("CONTINUITY", PASS, **evidence)


# --- report ----------------------------------------------------------------------------------------------------------------------------
#: A prerequisite that a scoped step itself produces: before that step completes the gate is PLANNED (non-blocking); once the
#: operator declares the step completed (``completed``) the prerequisite must really hold, so a failed step cannot hide.
PRODUCED_BY = {"BOOTSTRAP_AUTHORIZATION_REQUIRED": "BOOTSTRAP_AUTHORIZE", "MANAGEMENT_PATH_NOT_APPROVED": "MANAGEMENT_PATH_APPROVE",
               "MANAGEMENT_PATH_NOT_HEALTHY": "MANAGEMENT_PATH_APPROVE"}


def plan_aware(gate: dict, operations: set[str], completed: set[str]) -> dict:
    if gate["status"] != BLOCKED or not gate["codes"]:
        return gate
    producers = {PRODUCED_BY.get(code) for code in gate["codes"]}
    if None in producers or not producers <= operations or producers & completed:
        return gate
    return {**gate, "status": PLANNED, "evidence": {**gate["evidence"], "planned_by": sorted(producers)}}


def overall(gates) -> str:
    statuses = {g["status"] for g in gates}
    return FAIL if FAIL in statuses else BLOCKED if BLOCKED in statuses else READY


def device_gates(device, *, scope=None, flows=None, completed=(), now=None) -> dict:
    now = now or timezone.now()
    report = stage_report.device_report(device, now=now)
    operations = scoped_operations(scope, device.name)
    window_end = None
    try:
        window_end = datetime.fromisoformat(((scope or {}).get("window") or {})["end"])
    except (KeyError, TypeError, ValueError):
        pass
    upstream = upstream_gate(device)
    gates = [lifecycle_gate(device, report), identity_gate(device, report), dependency_gate(device), upstream,
             authorization_gate(device, operations, window_end, now), dhcp_gate(device, operations, now), isolation_gate(device),
             management_gate(device, report), quiescence_gate(device, report), continuity_gate(device, upstream, flows, scope)]
    done = {item.split(":", 1)[1] for item in completed if item.split(":", 1)[0] == device.name and ":" in item}
    gates = [plan_aware(g, operations, done) for g in gates]
    return {"device": device.device_id, "name": device.name, "platform": device.platform, "operations": sorted(operations),
            "verdict": overall(gates), "gates": gates}


def evaluate(names, *, scope=None, flows=None, completed=(), freshness_seconds: int = DEFAULT_TRAFFIC_FRESHNESS_SECONDS,
             now=None) -> dict:
    """The full read-only acceptance report for ``names`` (validated against the dependency order) and ``scope``."""
    now = now or timezone.now()
    flows = flows if flows is not None else (scope or {}).get("flows") or []
    rows = list(models.ManagedDevice.objects.filter(name__in=list(names)))
    found = {d.name for d in rows}
    global_gates = []
    missing = [n for n in names if n not in found]
    if missing:
        global_gates.append(_gate("DEVICES", FAIL, ["DEVICE_NOT_FOUND"], missing=missing))
    by_pk = {d.pk: d for d in rows}
    try:
        order = dependencies.order(list(by_pk))
        planned = [by_pk[pk].name for pk in order]
    except ValueError:
        order, planned = list(by_pk), []
        global_gates.append(_gate("ORDER", FAIL, ["COMMISSIONING_DEPENDENCY_CYCLE"]))
    else:
        requested = [n for n in names if n in found]
        status = PASS if requested == planned else FAIL
        global_gates.append(_gate("ORDER", status, [] if status == PASS else ["ORDER_VIOLATES_DEPENDENCY"],
                                  requested=requested, required=planned))
    scope_found = scope_problems(scope, now=now)
    if scope is not None:
        listed = [e.get("name") for e in scope.get("devices") or [] if isinstance(e, dict)]
        if listed and listed != [n for n in names if n in found]:
            scope_found.append(blocker("LIVE_SCOPE_DEVICES_MISMATCH", scope=listed, requested=list(names)))
    scope_status = BLOCKED if scope is None else (FAIL if scope_found else PASS)
    global_gates.append(_gate("LIVE_SCOPE", scope_status, _codes(scope_found), digest=scope_digest(scope) if scope else "",
                              change=(scope or {}).get("change", ""), problems=scope_found))
    global_gates.append(traffic_gate(flows, now=now, freshness_seconds=freshness_seconds))
    devices = [device_gates(by_pk[pk], scope=scope, flows=flows, completed=completed, now=now) for pk in order]
    every = global_gates + [g for d in devices for g in d["gates"]]
    body = {"schema": SCHEMA, "generated_at": now.isoformat(), "requested": list(names), "completed": sorted(completed),
            "verdict": overall(every),
            "global": global_gates, "devices": devices,
            "meaning": "read-only preconditions; READY is not an authorization -- each live step runs through its own governed workflow"}
    body["digest"] = hashlib.sha256(json.dumps(body, sort_keys=True, default=str, separators=(",", ":")).encode()).hexdigest()
    return body


def prerequisites(report: dict) -> list[dict]:
    """The BLOCKED / FAILED gates as an operator checklist (what must change before a live step may start)."""
    out = []
    for gate in report["global"]:
        if gate["status"] in (FAIL, BLOCKED):
            out.append({"device": "*", "gate": gate["gate"], "status": gate["status"], "codes": gate["codes"]})
    for device in report["devices"]:
        for gate in device["gates"]:
            if gate["status"] in (FAIL, BLOCKED):
                out.append({"device": device["name"], "gate": gate["gate"], "status": gate["status"], "codes": gate["codes"]})
    return out
