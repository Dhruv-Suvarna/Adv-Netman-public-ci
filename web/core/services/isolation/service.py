"""Trusted-upstream isolation: the one writer of ``IsolationPolicy``.  Enforcement happens on the TRUSTED upstream's port, never on
the untrusted device, through the governed single-device transaction (``transaction``):

    require   -> REQUIRED      the device, its approved routed attachment and a trusted upstream are bound to one policy
                               (cEOS: port ACLs, ``eos``; Ubuntu/FRR: one NMAS-owned nftables table, ``frr``)
    plan      -> PLANNED       the upstream's running configuration is read; the intent and its exact operations are derived
                 | BLOCKED     (anything the upstream cannot enforce, or that NMAS would have to overwrite, blocks the policy)
    precheck                   a fresh read must still produce the same intent; recorded as the Change's precheck
    approve                    another operator approves exactly that plan hash
    apply     -> APPLYING -> ENFORCED | REQUIRED (restored) | UNCERTAIN (restoration unproven)
    verify    -> VERIFIED      read-back, L2, routing, management plane, and (when a traffic source exists) permitted /
                               denied flows corroborated by the enforcement point's deny counters
                 | DRIFTED     the upstream no longer holds the policy (never re-applied automatically)
    release   -> RELEASE_PENDING -> RELEASED   (production admission; ``core.services.commissioning``)

The NMAS side remains a single point of failure: if NMAS is down the policy simply stays enforced on the upstream (fail
closed), and nothing here can prove the upstream itself is uncompromised -- it is trusted because it is a managed, in-service
device.  ``reconcile`` never removes isolation; it only proves what the upstream holds.
"""

from __future__ import annotations

import ipaddress
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import timedelta

from django.conf import settings
from django.db import IntegrityError, transaction as db_transaction
from django.utils import timezone

from ... import models
from ..devices import attachments as attachment_service
from ..devices import events
from ..devices.codes import blocker, codes
from ..execution.executors.base import ExecutorError
from . import eos, frr, intent as intent_service, transaction

St = models.IsolationState
Kind = models.IsolationCheckKind
Outcome = models.DeviceLifecycleEventOutcome
X = transaction.Outcome
APPLY_KIND, RELEASE_KIND = "TRUSTED_ISOLATION_APPLY", "TRUSTED_ISOLATION_RELEASE"
CONFIG_CHECKS = (Kind.READ_BACK, Kind.L2, Kind.ROUTING, Kind.MANAGEMENT_PLANE)
ELIGIBLE_LIFECYCLE = (models.DeviceLifecycleState.REGISTERED, models.DeviceLifecycleState.DISCOVERED, models.DeviceLifecycleState.BOOTSTRAPPED)


def evidence_max_age_seconds() -> float:
    """How old a passing verification may be when a gate (ZTP open, ISOLATE, commissioning) relies on it."""
    return float(getattr(settings, "NMAS_ISOLATION_EVIDENCE_MAX_AGE_SECONDS", 3600))


def routing_settle_seconds() -> float:
    return float(getattr(settings, "NMAS_ISOLATION_ROUTING_SETTLE_SECONDS", 20))


# ------------------------------------------------------------------------------------------------------------- access
@dataclass
class Access:
    """How NMAS reaches the trusted upstream.  The default is the production cEOS executor resolved through ``nsot_live``."""

    executor_factory: Callable
    nmas_sources: tuple = ()
    sleep: Callable = time.sleep


def default_access(platform: str = models.Platform.ARISTA_CEOS) -> Access:
    """The production access of an upstream of ``platform``: the cEOS executor, or the Ubuntu/FRR nftables executor."""
    from ..execution.executors.ceos import CeosExecutor
    from ..execution.executors.frr_isolation import FrrIsolationExecutor
    from ..health import inventory

    management = (inventory.load_inventory() or {}).get("management") or {}
    sources = []
    for key in ("nmas_ipv4", "nmas_ipv6"):
        try:
            sources.append(str(ipaddress.ip_interface(str(management.get(key) or "")).ip))
        except ValueError:
            continue
    factory = FrrIsolationExecutor if platform == models.Platform.UBUNTU_FRR else CeosExecutor
    return Access(executor_factory=factory, nmas_sources=tuple(sources))


SUPPORTED_PLATFORMS = (models.Platform.ARISTA_CEOS, models.Platform.UBUNTU_FRR)


def is_frr(policy) -> bool:
    """An Ubuntu/FRR upstream (a policy without a recorded platform is cEOS, the column's historical value)."""
    return getattr(policy, "upstream_platform", models.Platform.ARISTA_CEOS) == models.Platform.UBUNTU_FRR


def upstream_device(policy) -> dict:
    if is_frr(policy):
        return {"name": policy.upstream_device, "platform": "linux"}      # reached only over management.linux_ssh
    return {"name": policy.upstream_device, "platform": "ceos"}


def read_config(executor) -> str:
    """The sanitized running configuration through ``executor``'s own session.  Raises ExecutorError when unreadable."""
    from ..bundles.legacy_sanitize import SanitizeError, sanitize_config

    try:
        return sanitize_config(executor.show("show running-config")).text
    except SanitizeError:
        raise ExecutorError("PREVIOUS_STATE_UNAVAILABLE") from None


# ------------------------------------------------------------------------------------------------------------- results
@dataclass
class IsolationResult:
    ok: bool
    action: str
    policy: object | None = None
    blockers: list = field(default_factory=list)
    detail: dict = field(default_factory=dict)

    @property
    def codes(self) -> list[str]:
        return codes(self.blockers)


def get_policy(policy_id):
    text = str(policy_id or "")
    pk = int(text[4:]) if text.startswith("ISO-") and text[4:].isdigit() else (int(text) if text.isdigit() else None)
    return models.IsolationPolicy.objects.select_related("device", "attachment", "network").filter(pk=pk).first() if pk else None


def live_policy(attachment):
    """The attachment's policy that is not RELEASED (at most one), or None."""
    if attachment is None:
        return None
    return models.IsolationPolicy.objects.filter(attachment=attachment).exclude(state=St.RELEASED).first()


def device_policy(device):
    """The device's live policy (any attachment), or None."""
    return models.IsolationPolicy.objects.filter(device=device).exclude(state=St.RELEASED).order_by("-id").first()


def _event(device, action: str, outcome: str, *, actor: str, policy=None, blockers=(), evidence: dict | None = None, correlation_id=""):
    fresh = models.ManagedDevice.objects.select_for_update().get(pk=device.pk)
    payload = {"policy": policy.policy_id if policy is not None and policy.pk else "", **(evidence or {})}
    return events.record(fresh, action, outcome, actor=actor, actor_kind=events.HUMAN if not actor.startswith("system:") else events.AUTOMATION,
                         from_state=fresh.lifecycle_state, to_state=fresh.lifecycle_state, blockers=list(blockers), evidence=payload,
                         correlation_id=correlation_id)


def _refuse(device, action: str, problems, *, actor: str, policy=None) -> IsolationResult:
    found = [problem if "message" in problem else blocker(problem["code"], detail=problem.get("detail", "")) for problem in problems]
    if device is not None:
        with db_transaction.atomic():
            _event(device, action, Outcome.REFUSED, actor=actor, policy=policy, blockers=found)
    return IsolationResult(False, action, policy, found)


def _save(policy, **fields):
    """Write ``fields`` on the policy row (locked, version-checked).  -> the fresh row."""
    fresh = models.IsolationPolicy.objects.select_for_update().get(pk=policy.pk)
    if fresh.version != policy.version:
        raise _Stale()
    for name, value in fields.items():
        setattr(fresh, name, value)
    fresh.version += 1
    fresh.__dict__["_isolation_write"] = True
    fresh.save()
    return fresh


class _Stale(Exception):
    pass


def _check(policy, kind: str, ok: bool, *, code: str = "", facts: dict | None = None, with_device: bool = False, actor: str,
           correlation_id: str) -> models.IsolationCheck:
    return models.IsolationCheck.objects.create(policy=policy, kind=kind, ok=bool(ok), code="" if ok else code[:48], with_device=with_device,
                                                facts=facts or {}, recorded_by=actor[:150], correlation_id=correlation_id)


# ------------------------------------------------------------------------------------------------------------- require
def require_problems(device, attachment, network) -> list[dict]:
    problems = []
    if device.is_terminal or device.origin != models.DeviceOrigin.REGISTERED_NEW or device.lifecycle_state not in ELIGIBLE_LIFECYCLE \
            or device.admission_state != models.ProductionAdmissionState.NOT_ADMITTED:
        problems.append(blocker("ISOLATION_DEVICE_INELIGIBLE", state=device.lifecycle_state, origin=device.origin))
    if attachment is None or attachment.device_id != device.pk:
        return problems + [blocker("ISOLATION_ATTACHMENT_INELIGIBLE", detail="not an attachment of this device")]
    if attachment.approval_state != models.AttachmentApproval.APPROVED or attachment.verification_state == models.AttachmentVerification.MISMATCH \
            or attachment.connectivity != models.AttachmentConnectivity.ROUTED or attachment.vlan == attachment_service.MANAGEMENT_VLAN:
        problems.append(blocker("ISOLATION_ATTACHMENT_INELIGIBLE", approval=attachment.approval_state, connectivity=attachment.connectivity,
                                detail="an approved, unmismatched ROUTED attachment is required (the only verified enforcement point)"))
    upstream = attachment_service.upstream_problems(device.name, attachment.upstream_device)
    if upstream:
        problems.append(blocker("ISOLATION_UPSTREAM_UNTRUSTED", upstream=attachment.upstream_device, reason=upstream[0]["code"]))
    else:
        from ..devices import resolver

        target = resolver.resolve(attachment.upstream_device)
        if target is None or target.platform not in SUPPORTED_PLATFORMS:
            problems.append(blocker("ISOLATION_PLATFORM_NOT_IMPLEMENTED", platform=getattr(target, "platform", "")))
    if network is None:
        problems.append(blocker("BOOTSTRAP_NETWORK_NOT_FOUND"))
    else:
        from ..ztp import policy as ztp_policy

        if network.state != models.BootstrapNetworkState.ACTIVE or not ztp_policy.relay_for(network, attachment.upstream_device):
            problems.append(blocker("ISOLATION_BOOTSTRAP_NETWORK_MISMATCH", network=network.name,
                                    detail=f"{attachment.upstream_device} is not a trusted relay of {network.name}"))
    if models.IsolationPolicy.objects.exclude(state=St.RELEASED).filter(attachment=attachment).exists() or \
            models.IsolationPolicy.objects.exclude(state=St.RELEASED).filter(upstream_device=attachment.upstream_device,
                                                                            upstream_interface=attachment.upstream_interface).exists():
        problems.append(blocker("ISOLATION_EXISTS"))
    return problems


def require(device, attachment, *, network, actor: str) -> IsolationResult:
    """Bind one device, its routed attachment and the bootstrap network to a new policy (REQUIRED).  Touches no device."""
    action = "ISO_REQUIRE"
    problems = require_problems(device, attachment, network)
    if problems:
        return _refuse(device, action, problems, actor=actor)
    from ..devices import resolver

    platform = resolver.resolve(attachment.upstream_device).platform      # require_problems proved it is a supported platform
    try:
        with db_transaction.atomic():
            policy = models.IsolationPolicy(device=device, attachment=attachment, network=network, upstream_device=attachment.upstream_device,
                                            upstream_interface=attachment.upstream_interface, upstream_platform=platform,
                                            requested_by=actor[:150])
            policy.__dict__["_isolation_write"] = True
            policy.save()
            _event(device, action, Outcome.RECORDED, actor=actor, policy=policy,
                   evidence={"upstream": f"{policy.upstream_device}:{policy.upstream_interface}", "network": network.name, "state": policy.state})
    except IntegrityError:
        return _refuse(device, action, [blocker("ISOLATION_EXISTS")], actor=actor)
    return IsolationResult(True, action, policy)


# ------------------------------------------------------------------------------------------------------------- plan
def _read_upstream(policy, access):
    """Connect, read the configuration and its digest.  -> (executor | None, text, digest, problem | None)."""
    executor = access.executor_factory(upstream_device(policy))
    try:
        executor.connect()
        text = read_state(policy, executor, access)
        digest = executor.config_state_digest()
    except ExecutorError as exc:
        _close(executor)
        return None, "", "", blocker("ISOLATION_UPSTREAM_UNREADABLE", reason=exc.code)
    return executor, text, digest, None


def _close(executor) -> None:
    try:
        executor.close()
    except Exception:  # pylint: disable=broad-exception-caught  # noqa: BLE001 - closing a session never masks the outcome
        pass


def read_state(policy, executor, access) -> object:
    """What the platform's checks read: the sanitized running configuration (cEOS) or one read-only snapshot (Ubuntu/FRR)."""
    if is_frr(policy):
        return executor.snapshot(access.nmas_sources)
    return read_config(executor)


def derive(policy, config_text, access) -> tuple[dict, list, list, dict]:
    if is_frr(policy):
        return frr.build(device_id=policy.device.device_id, upstream=policy.upstream_device, interface=policy.upstream_interface,
                         network=policy.network, snapshot=config_text, nmas_sources=access.nmas_sources)
    return intent_service.build(device_id=policy.device.device_id, upstream=policy.upstream_device, interface=policy.upstream_interface,
                                network=policy.network, config_text=config_text, nmas_sources=access.nmas_sources)


def _as_blockers(problems) -> list[dict]:
    return [blocker(p["code"], detail=p.get("detail", "")) for p in problems]


def ops_of(policy) -> list[dict]:
    return list((policy.plan or {}).get("ops") or [])


def plan(policy, *, actor: str, access: Access | None = None) -> IsolationResult:
    """Read the upstream and derive the policy's exact operations; create the governed apply Change (PLANNED) or BLOCKED."""
    action = "ISO_PLAN"
    access = access or default_access(policy.upstream_platform)
    if policy.state not in (St.REQUIRED, St.BLOCKED):
        return _refuse(policy.device, action, [blocker("ISOLATION_STATE_INVALID", state=policy.state)], actor=actor, policy=policy)
    fresh_problems = [p for p in require_problems(policy.device, policy.attachment, policy.network) if p["code"] != "ISOLATION_EXISTS"]
    if fresh_problems:
        return _refuse(policy.device, action, fresh_problems, actor=actor, policy=policy)
    executor, text, digest, problem = _read_upstream(policy, access)
    if problem:
        return _refuse(policy.device, action, [problem], actor=actor, policy=policy)
    _close(executor)
    intent, ops, problems, facts = derive(policy, text, access)
    try:
        with db_transaction.atomic():
            if problems:
                policy = _save(policy, state=St.BLOCKED, intent=intent, intent_hash=intent_service.digest(intent) if intent else "", plan={},
                               plan_hash="", preflight=facts, basis_digest=digest, failure={"codes": [p["code"] for p in problems], "problems": problems[:20]})
                _event(policy.device, action, Outcome.REFUSED, actor=actor, policy=policy, blockers=_as_blockers(problems))
                return IsolationResult(False, action, policy, _as_blockers(problems), {"facts": facts})
            change = transaction.create_change(
                kind=APPLY_KIND, device=policy.upstream_device, actor=actor,
                title=f"Trusted isolation of {policy.device.name} on {policy.upstream_device}:{policy.upstream_interface}",
                description=f"{policy.policy_id}: isolate the untrusted bootstrap port before onboarding {policy.device.device_id}.",
                reference={"policy": policy.policy_id, "device": policy.device.device_id})
            transaction.validate(change, ops, actor=actor, findings=[], source={"upstream": policy.upstream_device, "basis_digest": digest})
            built = transaction.build_plan(change, ops, actor=actor, device=policy.upstream_device,
                                           summary={"policy": policy.policy_id, "elements": sorted(intent["elements"])})
            policy = _save(policy, state=St.PLANNED, intent=intent, intent_hash=intent_service.digest(intent), plan={"ops": ops},
                           plan_hash=built.plan_hash, preflight=facts, basis_digest=digest, apply_change=change, failure={},
                           approved_by="", approved_at=None)
            _event(policy.device, action, Outcome.RECORDED, actor=actor, policy=policy,
                   evidence={"change": change.change_id, "plan_hash": built.plan_hash, "operations": [op["key"] for op in ops]})
    except _Stale:
        return _refuse(policy.device, action, [blocker("ISOLATION_STATE_INVALID", detail="changed concurrently")], actor=actor, policy=policy)
    return IsolationResult(True, action, policy, [], {"change": change.change_id, "plan_hash": built.plan_hash})


def _same_intent(policy, text: str, access) -> list[dict]:
    intent, _ops, problems, _facts = derive(policy, text, access)
    if problems:
        return _as_blockers(problems)
    if intent_service.digest(intent) != policy.intent_hash:
        return [blocker("ISOLATION_PLAN_STALE", detail="the upstream changed since the policy was planned")]
    return []


def precheck(policy, *, actor: str, access: Access | None = None) -> IsolationResult:
    """A fresh read-only check that the planned operations still fit the upstream; recorded as the Change's precheck."""
    action = "ISO_PRECHECK"
    access = access or default_access(policy.upstream_platform)
    if policy.state != St.PLANNED or policy.apply_change is None:
        return _refuse(policy.device, action, [blocker("ISOLATION_STATE_INVALID", state=policy.state)], actor=actor, policy=policy)
    started = timezone.now()
    executor, text, digest, problem = _read_upstream(policy, access)
    found = [problem] if problem else _same_intent(policy, text, access)
    if executor is not None:
        _close(executor)
    others = transaction.unresolved_runs(policy.upstream_device)
    if others:
        found.append(blocker("ISOLATION_UNCERTAIN", detail=f"{others[0]} left {policy.upstream_device} unresolved"))
    change = policy.apply_change
    built = transaction.latest_plan(change)
    stale = transaction.plan_problems(built, ops_of(policy), policy.upstream_device) if built else [transaction.blocker("PLAN_MISSING")]
    found += [blocker("ISOLATION_PLAN_STALE", detail=b["message"]) for b in stale]
    with db_transaction.atomic():
        run = transaction.record_precheck(change, built, actor=actor, started=started, blockers=found,
                                          facts={"policy": policy.policy_id, "digest": digest})
        _event(policy.device, action, Outcome.RECORDED if not found else Outcome.REFUSED, actor=actor, policy=policy, blockers=found,
               evidence={"change": change.change_id, "precheck_run": str(run.run_id)})
    return IsolationResult(not found, action, policy, found, {"precheck_run": str(run.run_id)})


_APPROVAL_CODES = {"SELF_APPROVAL": "ISOLATION_SELF_APPROVAL", "CONFIRMATION_MISMATCH": "ISOLATION_CONFIRMATION_MISMATCH"}


def approve(policy, *, actor: str, confirmation: str) -> IsolationResult:
    """Approve exactly the planned operations (their plan hash) after a passing precheck; never by the requester."""
    action = "ISO_APPROVE"
    if policy.state != St.PLANNED or policy.apply_change is None:
        return _refuse(policy.device, action, [blocker("ISOLATION_STATE_INVALID", state=policy.state)], actor=actor, policy=policy)
    if actor == policy.requested_by:
        return _refuse(policy.device, action, [blocker("ISOLATION_SELF_APPROVAL")], actor=actor, policy=policy)
    try:
        with db_transaction.atomic():
            transaction.approve(policy.apply_change, ops_of(policy), actor=actor, requested_by=policy.requested_by, confirmation=confirmation,
                                device=policy.upstream_device, extra={"policy": policy.policy_id})
            policy = _save(policy, approved_by=actor[:150], approved_at=timezone.now())
            _event(policy.device, action, Outcome.RECORDED, actor=actor, policy=policy, evidence={"plan_hash": policy.plan_hash})
    except transaction.TransactionError as exc:
        return _refuse(policy.device, action, [blocker(_APPROVAL_CODES.get(b["code"], "ISOLATION_PRECHECK_FAILED"), detail=b["message"])
                                               for b in exc.blockers], actor=actor, policy=policy)
    except _Stale:
        return _refuse(policy.device, action, [blocker("ISOLATION_STATE_INVALID", detail="changed concurrently")], actor=actor, policy=policy)
    return IsolationResult(True, action, policy)


# ------------------------------------------------------------------------------------------------------------- apply
def _poll(check, access, deadline_seconds: float):
    """Run ``check()`` -> failed rows until it passes or the deadline passes (routing withdrawal is not instantaneous)."""
    deadline = time.monotonic() + deadline_seconds
    while True:
        failed = check()
        if not failed or time.monotonic() >= deadline:
            return failed
        access.sleep(2.0)


def config_findings(policy, text) -> dict:
    """The configuration-level checks of an enforced policy -> {kind: (ok, code, facts)}."""
    if is_frr(policy):
        return frr.config_findings(policy.intent, text, policy.upstream_interface)
    ops = eos.render_apply(policy.intent)
    found = intent_service.presence(text, ops)
    wrong = intent_service.acl_exact(text, policy.intent)
    port = eos.interface_facts(text, policy.upstream_interface)
    names = set(eos.acl_names(policy.device.device_id).values())
    foreign = sorted(v for v in port["access_groups"].values() if v not in names)
    missing = sorted(k for k, v in found.items() if v != "PRESENT")
    read_back = (not missing and not wrong and not foreign, "ISOLATION_DRIFTED", {"missing": missing, "acl_mismatch": wrong, "foreign": foreign})
    l2 = (port["exists"] and port["routed"] and not port["channel_group"] and not port["subinterfaces"], "ISOLATION_DRIFTED",
          {"routed": port["routed"], "subinterfaces": port["subinterfaces"], "channel_group": port["channel_group"]})
    denied = eos.management_denied(port["ipv4"], port["ipv6"])
    exposure = eos.management_exposure(text, denied, port["vrf"])
    management = (not exposure, "ISOLATION_MGMT_PLANE_EXPOSED", {"exposed": exposure, "denied": denied})
    return {Kind.READ_BACK: read_back, Kind.L2: l2, Kind.MANAGEMENT_PLANE: management}


def routing_findings(policy, executor, text) -> tuple[bool, str, dict]:
    if is_frr(policy):
        return frr.routing_findings(policy.intent, text, policy.upstream_interface)
    port = eos.interface_facts(text, policy.upstream_interface)
    routing = eos.routing_facts(text, policy.upstream_interface)
    neighbors = eos.ospf_neighbors_on(executor.show("show ip ospf neighbor"), policy.upstream_interface)
    neighbors6 = eos.ospf6_neighbors_on(executor.show("show ipv6 ospf neighbor | json"), policy.upstream_interface)
    leaked4 = eos.routes_via(executor.show("show ip route | json"), policy.upstream_interface, port["ipv4"])
    leaked6 = eos.routes_via(executor.show("show ipv6 route | json"), policy.upstream_interface, port["ipv6"])
    facts = {"ospf_active": routing["ospf"], "unsupported": routing["unsupported"], "neighbors": neighbors,
             "leaked_ipv4": leaked4, "leaked_ipv6": leaked6}
    if routing["ospf6"] or routing["already_passive6"] or neighbors6:
        facts.update({"ospf6_active": routing["ospf6"], "neighbors6": neighbors6})
    readable = leaked4 is not None and leaked6 is not None and neighbors6 is not None
    ok = (not routing["ospf"] and not routing["ospf6"] and not routing["unsupported"] and not neighbors and neighbors6 == []
          and leaked4 == [] and leaked6 == [])
    return ok, ("ISOLATION_LEAK" if readable else "ISOLATION_UPSTREAM_UNREADABLE"), facts


def _final_checks(policy, access):
    """The apply postcheck: everything enforced reads back, nothing leaks, the management plane is closed."""
    def final(executor):
        text = read_state(policy, executor, access)
        failed = [{"check": kind, "detail": str(facts)[:200]} for kind, (ok, _code, facts) in config_findings(policy, text).items() if not ok]
        ok, _code, facts = routing_findings(policy, executor, text)
        if not ok:
            failed.append({"check": Kind.ROUTING, "detail": str(facts)[:200]})
        return failed
    return final


def apply(policy, *, actor: str, confirmation: str, access: Access | None = None, observer=None) -> IsolationResult:
    """Execute the approved plan on the upstream (write-ahead APPLYING).  Never leaves the policy claiming more than was proven."""
    action = "ISO_APPLY"
    access = access or default_access(policy.upstream_platform)
    if policy.state != St.PLANNED or not policy.approved_by or policy.apply_change is None:
        return _refuse(policy.device, action, [blocker("ISOLATION_STATE_INVALID", state=policy.state, approved=bool(policy.approved_by))],
                       actor=actor, policy=policy)
    try:
        with db_transaction.atomic():
            policy = _save(policy, state=St.APPLYING, failure={})
    except _Stale:
        return _refuse(policy.device, action, [blocker("ISOLATION_STATE_INVALID", detail="changed concurrently")], actor=actor, policy=policy)

    def preflight(executor):
        return _same_intent(policy, read_state(policy, executor, access), access)

    def settle(executor):
        return _poll(lambda: _final_checks(policy, access)(executor), access, routing_settle_seconds())

    result = transaction.execute(policy.apply_change, ops_of(policy), actor=actor, confirmation=confirmation, device=upstream_device(policy),
                                 executor_factory=access.executor_factory, preflight=preflight, final=settle, observer=observer)
    now = timezone.now()
    if result.succeeded:
        fields = {"state": St.ENFORCED, "enforced_at": now, "enforced_digest": result.report.get("final_digest") or "", "failure": {}}
    elif result.outcome == X.BLOCKED:
        fields = {"state": St.PLANNED, "failure": {"code": "ISOLATION_PRECHECK_FAILED", "blockers": [b["code"] for b in result.blockers]}}
    elif result.outcome in (X.FAILED_NO_MUTATION, X.FAILED_ROLLED_BACK, X.POSTCHECK_FAILED_ROLLED_BACK):
        fields = {"state": St.REQUIRED, "approved_by": "", "approved_at": None,
                  "failure": {"code": "ISOLATION_APPLY_FAILED", "outcome": result.outcome, "restored": True,
                              "blockers": [b["code"] for b in result.blockers]}}
    else:
        fields = {"state": St.UNCERTAIN, "failure": {"code": "ISOLATION_UNCERTAIN", "outcome": result.outcome, "restored": False,
                                                     "blockers": [b["code"] for b in result.blockers]}}
    with db_transaction.atomic():
        policy = models.IsolationPolicy.objects.get(pk=policy.pk)
        policy = _save(policy, **fields)
        _event(policy.device, action, Outcome.RECORDED if result.succeeded else Outcome.REFUSED, actor=actor, policy=policy,
               blockers=[] if result.succeeded else [blocker(fields["failure"]["code"], outcome=result.outcome)],
               evidence={"run": str(result.run.run_id) if result.run is not None else "", "outcome": result.outcome, "state": policy.state})
    return IsolationResult(result.succeeded, action, policy, [] if result.succeeded else [blocker(fields["failure"]["code"], outcome=result.outcome)],
                           {"run": str(result.run.run_id) if result.run is not None else "", "outcome": result.outcome, "report": result.report})


# ------------------------------------------------------------------------------------------------------------- verify
def counters(executor, intent: dict) -> dict:
    """Deny-entry match counters of the policy's four port ACLs (sequence ``DENY_SEQUENCE``), or of the nftables table's
    drop rules per chain (Ubuntu/FRR)."""
    if (intent.get("upstream") or {}).get("platform") == frr.PLATFORM:
        return frr.deny_counters(executor.table_json(intent["elements"]["PACKET_FILTER"]["table"]))
    found = {}
    for key, keyword in (("IPV4", "ip"), ("IPV6", "ipv6")):
        element = intent["elements"][key]
        for name in (element["acl"], element["out_acl"]):
            found[name] = eos.acl_counters(executor.show(f"show {keyword} access-lists {name}")).get(eos.DENY_SEQUENCE, 0)
    return found


def _attachment_check(policy, executor) -> tuple[bool, str, dict]:
    """The device is on the enforced port: the upstream resolved the session's address on that port to the MAC the trusted
    relay leased it to.  An upstream observation (OBSERVED trust), never the device's claim."""
    session = models.ZtpSession.objects.filter(device=policy.device).order_by("-id").first()     # reserved_address is mandatory
    if session is None:
        return False, "ISOLATION_DEVICE_NOT_OBSERVED", {"detail": "no ZTP session"}
    lease = models.DhcpLeaseObservation.objects.filter(pk=(session.discovery or {}).get("lease_observation")).first()
    if is_frr(policy):
        entry = frr.neighbor_entry(executor.neighbors(), session.reserved_address)
    else:
        entry = eos.arp_entry(executor.show(f"show ip arp {session.reserved_address}"), session.reserved_address)
    facts = {"address": session.reserved_address, "arp": entry, "lease_mac": lease.client_mac if lease else ""}
    ok = bool(entry) and entry["interface"] == policy.upstream_interface and lease is not None and entry["mac"] == lease.client_mac.lower()
    return ok, "ISOLATION_DEVICE_NOT_OBSERVED", facts


def verify(policy, *, actor: str, access: Access | None = None, traffic=None, with_device: bool = False) -> IsolationResult:
    """Prove the policy on the upstream: read-back, L2, routing, management plane; with the device present, the attachment;
    and, when ``traffic`` is given, flows.  ``traffic(policy, with_device) -> [{flow, expect, observed, detail}]`` where
    expect / observed are PERMIT or DENY; denied flows must also move the enforcement point's deny counters."""
    action = "ISO_VERIFY"
    access = access or default_access(policy.upstream_platform)
    if policy.state not in (St.ENFORCED, St.VERIFIED, St.DRIFTED):
        return _refuse(policy.device, action, [blocker("ISOLATION_STATE_INVALID", state=policy.state)], actor=actor, policy=policy)
    correlation = events.new_correlation_id()
    executor, text, _digest, problem = _read_upstream(policy, access)
    if problem:
        with db_transaction.atomic():
            _check(policy, Kind.READ_BACK, False, code="ISOLATION_UPSTREAM_UNREADABLE", actor=actor, correlation_id=correlation,
                   with_device=with_device, facts={"reason": problem.get("reason", "")})
        return _refuse(policy.device, action, [problem], actor=actor, policy=policy)
    results: dict = {}
    try:
        for kind, row in config_findings(policy, text).items():
            results[kind] = row
        results[Kind.ROUTING] = routing_findings(policy, executor, text)
        if with_device:
            results[Kind.ATTACHMENT] = _attachment_check(policy, executor)
        if traffic is not None:
            before = counters(executor, policy.intent)
            flows = list(traffic(policy, with_device))
            after = counters(executor, policy.intent)
            delta = {name: after.get(name, 0) - before.get(name, 0) for name in after}
            wrong = [f for f in flows if f.get("observed") != f.get("expect")]
            denied = [f for f in flows if f.get("expect") == "DENY"]
            permitted = [f for f in flows if f.get("expect") == "PERMIT"]
            corroborated = not denied or sum(delta.values()) > 0
            results[Kind.TRAFFIC] = (bool(flows) and bool(denied) and bool(permitted) and not wrong and corroborated, "ISOLATION_LEAK",
                                     {"flows": flows[:40], "deny_counter_delta": delta, "corroborated": corroborated})
    except ExecutorError as exc:
        results.setdefault(Kind.ROUTING, (False, "ISOLATION_UPSTREAM_UNREADABLE", {"reason": exc.code}))
    finally:
        _close(executor)
    config_ok = all(results[k][0] for k in (Kind.READ_BACK, Kind.L2, Kind.MANAGEMENT_PLANE))
    routing_ok = results[Kind.ROUTING][0]
    traffic_row = results.get(Kind.TRAFFIC)
    attachment_row = results.get(Kind.ATTACHMENT)
    now = timezone.now()
    if not config_ok:
        fields = {"state": St.DRIFTED, "failure": {"code": "ISOLATION_DRIFTED"},
                  "drift": {"at": now.isoformat(), "kinds": [k for k in CONFIG_CHECKS if not results[k][0]]}}
    elif not routing_ok or (traffic_row is not None and not traffic_row[0]):
        fields = {"state": St.ENFORCED, "failure": {"code": results[Kind.ROUTING][1] if not routing_ok else "ISOLATION_LEAK"}}
    elif traffic_row is not None:
        fields = {"state": St.VERIFIED, "verified_at": now, "failure": {}}
    else:
        fields = {"state": St.VERIFIED if policy.state == St.VERIFIED else St.ENFORCED,
                  "failure": {} if policy.state == St.VERIFIED else {"code": "ISOLATION_TRAFFIC_UNVERIFIED"}}
    if attachment_row is not None and not attachment_row[0] and fields["state"] == St.VERIFIED:
        fields["failure"] = {"code": "ISOLATION_DEVICE_NOT_OBSERVED"}
    summary = {"at": now.isoformat(), "correlation_id": correlation, "with_device": with_device,
               "checks": {k: {"ok": v[0], "code": "" if v[0] else v[1]} for k, v in results.items()}}
    fields["verification"] = summary
    try:
        with db_transaction.atomic():
            for kind, (ok, code, facts) in results.items():
                _check(policy, kind, ok, code=code, facts=facts, with_device=with_device, actor=actor, correlation_id=correlation)
            policy = _save(policy, **fields)
            if attachment_row is not None and attachment_row[0]:
                from ..devices import lifecycle

                lifecycle.record_observation(policy.device, kind=models.ObservationKind.ATTACHMENT,
                                             source=models.ObservationSource.TRUSTED_UPSTREAM_INTERFACE, actor=actor,
                                             upstream_device=policy.upstream_device, upstream_interface=policy.upstream_interface,
                                             local_interface=policy.attachment.local_interface, correlation_id=correlation)
            ok = all(row[0] for row in results.values())
            _event(policy.device, action, Outcome.RECORDED if ok else Outcome.REFUSED, actor=actor, policy=policy, correlation_id=correlation,
                   blockers=[] if ok else [blocker(fields["failure"].get("code") or "ISOLATION_NOT_VERIFIED")],
                   evidence={"state": policy.state, "checks": summary["checks"]})
    except _Stale:
        return _refuse(policy.device, action, [blocker("ISOLATION_STATE_INVALID", detail="changed concurrently")], actor=actor, policy=policy)
    ok = all(row[0] for row in results.values())
    found = [] if ok else [blocker(v[1], check=k) for k, v in results.items() if not v[0]]
    return IsolationResult(ok, action, policy, found, summary)


def check_drift(policy, *, actor: str, access: Access | None = None) -> IsolationResult:
    """Read-only drift check of an enforced policy (a DRIFT row; DRIFTED on any difference).  Never re-applies anything."""
    action = "ISO_DRIFT"
    access = access or default_access(policy.upstream_platform)
    if policy.state not in (St.ENFORCED, St.VERIFIED, St.DRIFTED):
        return _refuse(policy.device, action, [blocker("ISOLATION_STATE_INVALID", state=policy.state)], actor=actor, policy=policy)
    correlation = events.new_correlation_id()
    executor, text, digest, problem = _read_upstream(policy, access)
    if problem:
        with db_transaction.atomic():
            _check(policy, Kind.DRIFT, False, code="ISOLATION_UPSTREAM_UNREADABLE", actor=actor, correlation_id=correlation)
        return _refuse(policy.device, action, [problem], actor=actor, policy=policy)
    _close(executor)
    rows = config_findings(policy, text)
    bad = [kind for kind, (ok, _c, _f) in rows.items() if not ok]
    facts = {"digest": digest, "enforced_digest": policy.enforced_digest, "failed": bad,
             "detail": {kind: rows[kind][2] for kind in bad}}
    try:
        with db_transaction.atomic():
            _check(policy, Kind.DRIFT, not bad, code="ISOLATION_DRIFTED", facts=facts, actor=actor, correlation_id=correlation)
            if bad:
                policy = _save(policy, state=St.DRIFTED, failure={"code": "ISOLATION_DRIFTED"}, drift={"at": timezone.now().isoformat(), "kinds": bad})
            _event(policy.device, action, Outcome.REFUSED if bad else Outcome.RECORDED, actor=actor, policy=policy, correlation_id=correlation,
                   blockers=[blocker("ISOLATION_DRIFTED", kinds=bad)] if bad else [], evidence={"state": policy.state})
    except _Stale:
        return _refuse(policy.device, action, [blocker("ISOLATION_STATE_INVALID", detail="changed concurrently")], actor=actor, policy=policy)
    return IsolationResult(not bad, action, policy, [blocker("ISOLATION_DRIFTED", kinds=bad)] if bad else [], facts)


def reconcile(policy, *, actor: str, access: Access | None = None) -> IsolationResult:
    """Restart recovery for APPLYING / UNCERTAIN: prove what the upstream holds.  Everything enforced and reading back -> ENFORCED
    (verification must run again); anything else stays UNCERTAIN with the facts.  Never removes or re-applies isolation."""
    action = "ISO_RECONCILE"
    access = access or default_access(policy.upstream_platform)
    if policy.state not in (St.APPLYING, St.UNCERTAIN):
        return _refuse(policy.device, action, [blocker("ISOLATION_STATE_INVALID", state=policy.state)], actor=actor, policy=policy)
    executor, text, digest, problem = _read_upstream(policy, access)
    if problem:
        return _refuse(policy.device, action, [problem], actor=actor, policy=policy)
    try:
        rows = config_findings(policy, text)
        routing = routing_findings(policy, executor, text)
    except ExecutorError as exc:
        return _refuse(policy.device, action, [blocker("ISOLATION_UPSTREAM_UNREADABLE", reason=exc.code)], actor=actor, policy=policy)
    finally:
        _close(executor)
    presence = presence_of(policy, text)
    enforced = all(ok for ok, _c, _f in rows.values()) and routing[0]
    facts = {"presence": presence, "digest": digest, "routing_ok": routing[0]}
    try:
        with db_transaction.atomic():
            if enforced:
                policy = _save(policy, state=St.ENFORCED, enforced_digest=digest, enforced_at=policy.enforced_at or timezone.now(),
                               failure={"code": "ISOLATION_TRAFFIC_UNVERIFIED", "reconciled": True})
            else:
                policy = _save(policy, state=St.UNCERTAIN, failure={"code": "ISOLATION_UNCERTAIN", "presence": presence})
            _event(policy.device, action, Outcome.RECORDED if enforced else Outcome.REFUSED, actor=actor, policy=policy,
                   blockers=[] if enforced else [blocker("ISOLATION_UNCERTAIN")], evidence=facts)
    except _Stale:
        return _refuse(policy.device, action, [blocker("ISOLATION_STATE_INVALID", detail="changed concurrently")], actor=actor, policy=policy)
    return IsolationResult(enforced, action, policy, [] if enforced else [blocker("ISOLATION_UNCERTAIN")], facts)


def cancel(policy, *, actor: str, reason: str) -> IsolationResult:
    """Close a policy that never reached the upstream (REQUIRED / PLANNED / BLOCKED).  Nothing is sent to any device."""
    action = "ISO_CANCEL"
    if policy.state not in (St.REQUIRED, St.PLANNED, St.BLOCKED) or not str(reason or "").strip():
        return _refuse(policy.device, action, [blocker("ISOLATION_STATE_INVALID", state=policy.state)], actor=actor, policy=policy)
    try:
        with db_transaction.atomic():
            policy = _save(policy, state=St.RELEASED, released_at=timezone.now(),
                           failure={"code": "CANCELLED", "reason": str(reason)[:200], "device_changed": False})
            _event(policy.device, action, Outcome.RECORDED, actor=actor, policy=policy, evidence={"reason": str(reason)[:200]})
    except _Stale:
        return _refuse(policy.device, action, [blocker("ISOLATION_STATE_INVALID", detail="changed concurrently")], actor=actor, policy=policy)
    return IsolationResult(True, action, policy)


# ------------------------------------------------------------------------------------------------------------- gates
def _latest(policy, kind: str, *, with_device: bool | None = None, since=None):
    rows = policy.checks.filter(kind=kind)
    if with_device is not None:
        rows = rows.filter(with_device=with_device) if with_device else rows
    if since is not None:
        rows = rows.filter(created_at__gte=since)
    return rows.order_by("-created_at", "-id").first()


def fresh_problems(policy, kinds, *, now=None, with_device: bool = False) -> list[dict]:
    """Each of ``kinds`` has a passing check newer than the enforcement and younger than the evidence maximum age."""
    now = now or timezone.now()
    floor = max(filter(None, (policy.enforced_at, now - timedelta(seconds=evidence_max_age_seconds()))))
    problems = []
    for kind in kinds:
        row = _latest(policy, kind, with_device=True if with_device else None, since=floor)
        if row is None or not row.ok:
            problems.append(blocker("ISOLATION_NOT_VERIFIED", check=kind, with_device=with_device,
                                    detail="no passing check since enforcement within the evidence maximum age"))
    return problems


_STATE_BLOCKER = {St.DRIFTED: "ISOLATION_DRIFTED", St.UNCERTAIN: "ISOLATION_UNCERTAIN", St.BLOCKED: "ISOLATION_PLATFORM_NOT_IMPLEMENTED"}


def ztp_problems(device, attachment, *, now=None) -> list[dict]:
    """Phase 3 integration: a native-ZTP session opens only behind an ENFORCED / VERIFIED policy whose configuration-level
    checks (read-back, L2, routing, management plane) passed recently.  -> [] when isolated."""
    policy = live_policy(attachment)
    if policy is None or policy.device_id != device.pk:
        return [blocker("ISOLATION_NOT_FOUND")]
    if policy.state not in (St.ENFORCED, St.VERIFIED):
        return [blocker(_STATE_BLOCKER.get(policy.state, "ISOLATION_NOT_ENFORCED"), state=policy.state, policy=policy.policy_id)]
    return fresh_problems(policy, CONFIG_CHECKS, now=now)


def enforced(attachment) -> bool:
    """Is the attachment's isolation in force right now (ENFORCED / VERIFIED)?  The DHCP policy answers only such ports."""
    policy = live_policy(attachment)
    return policy is not None and policy.state in (St.ENFORCED, St.VERIFIED)


def isolate_problems(device, *, now=None) -> list[dict]:
    """BOOTSTRAPPED -> ISOLATED: the device's policy is VERIFIED, and with the device on the port the upstream observed it there
    and the permitted / denied flows held, all recently; the attachment is VERIFIED by trusted observation."""
    policy = device_policy(device)
    if policy is None:
        return [blocker("ISOLATION_NOT_FOUND")]
    if policy.state != St.VERIFIED:
        return [blocker(_STATE_BLOCKER.get(policy.state, "ISOLATION_NOT_VERIFIED"), state=policy.state, policy=policy.policy_id)]
    problems = fresh_problems(policy, CONFIG_CHECKS, now=now)
    problems += fresh_problems(policy, (Kind.ATTACHMENT, Kind.TRAFFIC), now=now, with_device=True)
    if policy.attachment.verification_state != models.AttachmentVerification.VERIFIED:
        problems.append(blocker("ISOLATION_DEVICE_NOT_OBSERVED", attachment=policy.attachment_id))
    return problems


# ------------------------------------------------------------------------------------------------------------- release
def presence_of(policy, text) -> dict:
    return frr.presence(policy.intent, text) if is_frr(policy) else intent_service.presence(text, eos.render_apply(policy.intent))


def release_ops(policy) -> list[dict]:
    return frr.render_release(policy.intent) if is_frr(policy) else eos.render_release(policy.intent)


def create_release(policy, *, actor: str, reference: dict) -> IsolationResult:
    """The governed release Change of a VERIFIED policy (validation and plan; nothing is sent)."""
    action = "ISO_RELEASE_PLAN"
    if policy.state != St.VERIFIED:
        return _refuse(policy.device, action, [blocker("ISOLATION_NOT_VERIFIED", state=policy.state)], actor=actor, policy=policy)
    ops = release_ops(policy)
    try:
        with db_transaction.atomic():
            change = transaction.create_change(
                kind=RELEASE_KIND, device=policy.upstream_device, actor=actor,
                title=f"Production admission of {policy.device.name}: release isolation on {policy.upstream_device}:{policy.upstream_interface}",
                description=f"{policy.policy_id}: controlled release; restored on failure.", reference={"policy": policy.policy_id, **reference})
            transaction.validate(change, ops, actor=actor, findings=[], source={"upstream": policy.upstream_device, "policy": policy.policy_id})
            built = transaction.build_plan(change, ops, actor=actor, device=policy.upstream_device, summary={"policy": policy.policy_id})
            policy = _save(policy, release_change=change)
            _event(policy.device, action, Outcome.RECORDED, actor=actor, policy=policy, evidence={"change": change.change_id, "plan_hash": built.plan_hash})
    except _Stale:
        return _refuse(policy.device, action, [blocker("ISOLATION_STATE_INVALID", detail="changed concurrently")], actor=actor, policy=policy)
    return IsolationResult(True, action, policy, [], {"change": change.change_id, "plan_hash": built.plan_hash})


def release_preflight_problems(policy, text) -> list[dict]:
    """Before a release, the upstream must hold exactly the enforced policy (otherwise the restore path is not the truth)."""
    rows = config_findings(policy, text)
    return [blocker("ISOLATION_DRIFTED", check=kind) for kind, (ok, _c, _f) in rows.items() if not ok]


def release_absent_problems(policy, text) -> list[dict]:
    found = presence_of(policy, text)
    left = sorted(k for k, v in found.items() if v != "ABSENT")
    return [{"check": "RELEASE", "detail": f"still on the upstream: {left}"}] if left else []


def release_precheck(policy, *, actor: str, access: Access | None = None) -> IsolationResult:
    action = "ISO_RELEASE_PRECHECK"
    access = access or default_access(policy.upstream_platform)
    change = policy.release_change
    if policy.state != St.VERIFIED or change is None:
        return _refuse(policy.device, action, [blocker("ISOLATION_STATE_INVALID", state=policy.state)], actor=actor, policy=policy)
    started = timezone.now()
    executor, text, digest, problem = _read_upstream(policy, access)
    found = [problem] if problem else release_preflight_problems(policy, text)
    if executor is not None:
        _close(executor)
    built = transaction.latest_plan(change)
    found += [blocker("ISOLATION_PLAN_STALE", detail=b["message"]) for b in (transaction.plan_problems(built, release_ops(policy), policy.upstream_device)
                                                                              if built else [transaction.blocker("PLAN_MISSING")])]
    with db_transaction.atomic():
        run = transaction.record_precheck(change, built, actor=actor, started=started, blockers=found, facts={"policy": policy.policy_id, "digest": digest})
        _event(policy.device, action, Outcome.RECORDED if not found else Outcome.REFUSED, actor=actor, policy=policy, blockers=found,
               evidence={"change": change.change_id, "precheck_run": str(run.run_id)})
    return IsolationResult(not found, action, policy, found, {"precheck_run": str(run.run_id)})


def approve_release(policy, *, actor: str, requested_by: str, confirmation: str, extra: dict) -> IsolationResult:
    action = "ISO_RELEASE_APPROVE"
    if policy.state != St.VERIFIED or policy.release_change is None:
        return _refuse(policy.device, action, [blocker("ISOLATION_STATE_INVALID", state=policy.state)], actor=actor, policy=policy)
    try:
        with db_transaction.atomic():
            transaction.approve(policy.release_change, release_ops(policy), actor=actor, requested_by=requested_by, confirmation=confirmation,
                                device=policy.upstream_device, extra={"policy": policy.policy_id, **extra})
            _event(policy.device, action, Outcome.RECORDED, actor=actor, policy=policy, evidence={"change": policy.release_change.change_id})
    except transaction.TransactionError as exc:
        return _refuse(policy.device, action, [blocker(_APPROVAL_CODES.get(b["code"], "ISOLATION_PRECHECK_FAILED"), detail=b["message"])
                                               for b in exc.blockers], actor=actor, policy=policy)
    return IsolationResult(True, action, policy)


def execute_release(policy, *, actor: str, confirmation: str, access: Access | None = None, verify_admission=None,
                    observer=None) -> IsolationResult:
    """Release the isolation (RELEASE_PENDING), then ``verify_admission(executor) -> failed rows`` must pass; any failure
    re-applies every removed statement (digest-verified).  -> RELEASED | ENFORCED (restored, re-verify) | UNCERTAIN."""
    action = "ISO_RELEASE"
    access = access or default_access(policy.upstream_platform)
    if policy.state != St.VERIFIED or policy.release_change is None:
        return _refuse(policy.device, action, [blocker("ISOLATION_STATE_INVALID", state=policy.state)], actor=actor, policy=policy)
    previous = policy.state
    try:
        with db_transaction.atomic():
            policy = _save(policy, state=St.RELEASE_PENDING)
    except _Stale:
        return _refuse(policy.device, action, [blocker("ISOLATION_STATE_INVALID", detail="changed concurrently")], actor=actor, policy=policy)

    def preflight(executor):
        return release_preflight_problems(policy, read_state(policy, executor, access))

    def final(executor):
        failed = release_absent_problems(policy, read_state(policy, executor, access))
        return failed or (list(verify_admission(executor)) if verify_admission is not None else [])

    result = transaction.execute(policy.release_change, release_ops(policy), actor=actor, confirmation=confirmation,
                                 device=upstream_device(policy), executor_factory=access.executor_factory, preflight=preflight, final=final,
                                 observer=observer)
    if result.succeeded:
        fields = {"state": St.RELEASED, "released_at": timezone.now(), "failure": {}}
    elif result.outcome in (X.BLOCKED, X.FAILED_NO_MUTATION):
        fields = {"state": previous, "failure": {"code": "ISOLATION_PRECHECK_FAILED", "outcome": result.outcome}}
    elif result.restored:
        fields = {"state": St.ENFORCED, "failure": {"code": "ISOLATION_TRAFFIC_UNVERIFIED", "outcome": result.outcome, "restored": True}}
    else:
        fields = {"state": St.UNCERTAIN, "failure": {"code": "ISOLATION_UNCERTAIN", "outcome": result.outcome, "restored": False}}
    with db_transaction.atomic():
        policy = models.IsolationPolicy.objects.get(pk=policy.pk)
        policy = _save(policy, **fields)
        _event(policy.device, action, Outcome.RECORDED if result.succeeded else Outcome.REFUSED, actor=actor, policy=policy,
               blockers=[] if result.succeeded else [blocker(fields["failure"]["code"], outcome=result.outcome)],
               evidence={"run": str(result.run.run_id) if result.run is not None else "", "outcome": result.outcome, "state": policy.state})
    return IsolationResult(result.succeeded, action, policy, [] if result.succeeded else [blocker(fields["failure"]["code"], outcome=result.outcome)],
                           {"run": str(result.run.run_id) if result.run is not None else "", "outcome": result.outcome, "report": result.report,
                            "restored": result.restored})


def reconcile_release(policy, *, actor: str, access: Access | None = None, verify_admission=None) -> IsolationResult:
    """Restart recovery of a release (RELEASE_PENDING / UNCERTAIN after a release): prove what the upstream holds, never change it.

    every isolation statement present and reading back      -> ENFORCED (restored; must be verified again)
    every statement absent and ``verify_admission`` passes  -> RELEASED (the admission is proven)
    anything else                                           -> UNCERTAIN (operator action; isolation is never re-applied here)"""
    action = "ISO_RECONCILE"
    access = access or default_access(policy.upstream_platform)
    if policy.state not in (St.RELEASE_PENDING, St.UNCERTAIN) or policy.release_change_id is None:
        return _refuse(policy.device, action, [blocker("ISOLATION_STATE_INVALID", state=policy.state)], actor=actor, policy=policy)
    executor, text, digest, problem = _read_upstream(policy, access)
    if problem:
        return _refuse(policy.device, action, [problem], actor=actor, policy=policy)
    try:
        presence = presence_of(policy, text)
        intact = all(v == "PRESENT" for v in presence.values()) and all(ok for ok, _c, _f in config_findings(policy, text).values())
        absent = all(v == "ABSENT" for v in presence.values())
        failed = list(verify_admission(executor)) if absent and verify_admission is not None else None
    except ExecutorError as exc:
        return _refuse(policy.device, action, [blocker("ISOLATION_UPSTREAM_UNREADABLE", reason=exc.code)], actor=actor, policy=policy)
    finally:
        _close(executor)
    facts = {"presence": presence, "digest": digest, "admission_failures": failed}
    if intact:
        fields, code = {"state": St.ENFORCED, "failure": {"code": "ISOLATION_TRAFFIC_UNVERIFIED", "reconciled": True, "restored": True}}, ""
    elif absent and failed == []:
        fields, code = {"state": St.RELEASED, "released_at": timezone.now(), "failure": {}}, ""
    else:
        fields, code = {"state": St.UNCERTAIN, "failure": {"code": "ISOLATION_UNCERTAIN", "presence": presence}}, "ISOLATION_UNCERTAIN"
    try:
        with db_transaction.atomic():
            policy = _save(policy, **fields)
            _event(policy.device, action, Outcome.REFUSED if code else Outcome.RECORDED, actor=actor, policy=policy,
                   blockers=[blocker(code)] if code else [], evidence={**facts, "state": policy.state})
    except _Stale:
        return _refuse(policy.device, action, [blocker("ISOLATION_STATE_INVALID", detail="changed concurrently")], actor=actor, policy=policy)
    return IsolationResult(not code, action, policy, [blocker(code)] if code else [], facts)


def status(policy) -> dict:
    """A bounded, secret-free summary for the UI / API."""
    latest = {kind: _latest(policy, kind) for kind in Kind.values}
    return {"policy": policy.policy_id, "device": policy.device.device_id, "state": policy.state,
            "upstream": f"{policy.upstream_device}:{policy.upstream_interface}", "plan_hash": policy.plan_hash,
            "apply_change": policy.apply_change.change_id if policy.apply_change_id else "",
            "release_change": policy.release_change.change_id if policy.release_change_id else "",
            "failure": policy.failure, "requested_by": policy.requested_by, "approved_by": policy.approved_by,
            "checks": {kind: ({"ok": row.ok, "code": row.code, "with_device": row.with_device, "at": row.created_at.isoformat()} if row else None)
                       for kind, row in latest.items()},
            "limitations": ["NMAS is a single point of failure for re-verification; the upstream keeps enforcing while NMAS is down.",
                            "The upstream is trusted because it is a managed, in-service device; NMAS cannot prove it is uncompromised."]}
