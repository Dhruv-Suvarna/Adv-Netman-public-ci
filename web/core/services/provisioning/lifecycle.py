"""The provisioning stage machine.  One linear path; a stage either ADVANCES the run or records why it did not.

    DRAFT -> IDENTIFIED -> BOOTSTRAP_CLASSIFIED -> CAPABILITY_RESOLVED -> IPAM_PLANNED -> CANDIDATE_READY -> VALIDATED -> PLANNED
          -> PRECHECKED -> APPROVED -> (PROVISIONING) -> POSTCHECKED -> NSOT_SYNCED -> PROBATION
    any non-terminal stage -> CANCELLED;  a failed provision -> ROLLED_BACK (the device was restored) or FAILED (it was not).

There is NO provisioning execution entry point.  The approved plan is executed by the operator through the one ordinary execute route
(the execution engine's own entry point, called by its explicit POST view); this module only supplies the provisioning part of that engine's gate (``execution_blockers``), its
pre-write baseline hook (``before_first_mutation``) and its result recorder (``after_execution``).

Reuse, not reimplementation.  The candidate is an ordinary Change (category NEW_DEVICE_PROVISIONING) with a NEW_DEVICE intent, edited in the
ordinary Device Builder; validation, network-configuration validation, the plan, the precheck, execution, the postcheck, the bundles and the soak
are the existing services, called here and REFERENCED from the run.  This module adds only what a new device needs and the Change lifecycle lacks:
identity, bootstrap classification, the full Phase-4 capability gate, NetBox reservation, an explicit approval bound to the exact candidate, the
registry admission that lets the engines resolve the device, configuration digests, NSOT synchronization and failure reconciliation.

Every attempt writes one append-only ``ProvisioningEvent``; a refusal changes nothing else.  Device, NetBox and telemetry access are injected
(``prober``, ``gateway``, the module-level ``CONFIG_READER`` / ``GATEWAY_FACTORY``, the precheck keyword arguments) so the rules are testable without a lab.
"""

from __future__ import annotations

import hashlib
import subprocess
from dataclasses import dataclass, field

from django.conf import settings
from django.db import IntegrityError, transaction
from django.utils import timezone

from ... import models
from .. import (
    bundle_service, change_plan_service, change_service, change_validation_service as cvs, field_commit_service, health_service,
    intent_service,
    network_config_validation as ncv, secret_policy, soak_service,
)
from ..execution.codes import Outcome
from ..validation.findings import Currency, Status
from . import bootstrap, capability_gate, commissioning_gate, ipam, registry
from ..execution.codes import blocker as execution_blocker
from .codes import BLOCKERS, RESERVED_STATUSES, STAGE_BY_NAME, blocker

S, E = models.ProvisioningStatus, models.ProvisioningEventOutcome
ROLES = ("router", "switch", "edge")
_PASSING = (Status.PASS, Status.PASS_WITH_WARNINGS)
_NCV_PASSING = (models.NetworkConfigValidationStatus.PASS, models.NetworkConfigValidationStatus.WARNING)
_PRECHECK_PERMITS = ("PASS", "PASS_WITH_WARNINGS")
# execution outcomes after which the device demonstrably holds none of this run's configuration
_RESTORED = frozenset({Outcome.BLOCKED, Outcome.FAILED_NO_MUTATION, Outcome.FAILED_ROLLED_BACK, Outcome.POSTCHECK_FAILED_ROLLED_BACK})
_APPLIED = frozenset({Outcome.SUCCEEDED, Outcome.UAT_SCOPE_APPLIED})
_ROOT_BUNDLE = {models.ExecutionMode.COMPLETE: "create_deployed_bundle", models.ExecutionMode.PARTIAL_UAT: "create_uat_bundle"}


@dataclass
class StageResult:
    run: object
    ok: bool
    stage: str = ""
    blockers: list = field(default_factory=list)
    event: object | None = None

    @property
    def codes(self) -> list[str]:
        return [b["code"] for b in self.blockers]


# --- plumbing ------------------------------------------------------------------------------------------------------------------
def repository_head() -> str:
    try:
        return subprocess.run(["git", "rev-parse", "HEAD"], cwd=settings.REPO_ROOT, capture_output=True, check=True, text=True,  # noqa: S603,S607
                              timeout=5).stdout.strip()[:40]
    except (OSError, subprocess.SubprocessError):
        return ""


def _event(run, stage, outcome, from_status, *, actor, blockers=(), evidence=None):
    sequence = (run.events.order_by("-sequence").values_list("sequence", flat=True).first() or 0) + 1
    row = models.ProvisioningEvent.objects.create(
        run=run, sequence=sequence, stage=stage, outcome=outcome, from_status=from_status, to_status=run.status, actor=actor[:150],
        blockers=list(blockers), evidence=secret_policy.redact(evidence or {}),
    )
    audit = {E.ADVANCED: models.AuditEventType.PROVISIONING_STAGE_RECORDED, E.BLOCKED: models.AuditEventType.PROVISIONING_BLOCKED,
             E.FAILED: models.AuditEventType.PROVISIONING_FAILED, E.RECONCILED: models.AuditEventType.PROVISIONING_RECONCILED}[outcome]
    models.AuditEvent.objects.create(
        event_type=audit, change=run.change, object_type="ProvisioningRun", object_id=run.prov_id, actor=actor[:150],
        summary=f"{run.prov_id} {stage}: {outcome} ({from_status} -> {run.status})"[:255],
        metadata={"prov_id": run.prov_id, "device": run.device_name, "stage": stage, "outcome": outcome,
                  "codes": [b["code"] for b in blockers]},
    )
    return row


def _refuse(run, stage, blockers, *, actor, evidence=None) -> StageResult:
    """A refusal: one event, no state change."""
    return StageResult(run, False, stage, list(blockers), _event(run, stage, E.BLOCKED, run.status, actor=actor, blockers=blockers, evidence=evidence))


def _advance(run, stage, *, actor, evidence=None, fields=()) -> StageResult:
    previous = run.status
    run.status = STAGE_BY_NAME[stage][1]
    run.save(update_fields=["status", "updated_at", *fields])
    return StageResult(run, True, stage, [], _event(run, stage, E.ADVANCED, previous, actor=actor, evidence=evidence))


def _entry(run, stage) -> list[dict]:
    """The stage-order gate every action starts with."""
    if run.is_terminal:
        return [blocker("RUN_FINISHED", status=run.status)]
    if run.status != STAGE_BY_NAME[stage][0]:
        return [blocker("WRONG_STAGE", stage=stage, status=run.status, expected=STAGE_BY_NAME[stage][0])]
    return []


def _secret_free(*values) -> bool:
    try:
        for value in values:
            if isinstance(value, dict):
                secret_policy.assert_no_secret_shaped_keys(value, context="provisioning request")
        return True
    except ValueError:
        return False


# --- 0. the request ------------------------------------------------------------------------------------------------------------
def create_request(*, device_name: str, platform: str, role: str, requested_by: str, site: str = "", image_reference: str = "",
                   disposable: bool = False) -> StageResult:
    """Create a DRAFT request.  Refused (nothing written) on an invalid or conflicting identity."""
    name = str(device_name or "").strip()
    blockers = []
    try:
        models.DEVICE_NAME_VALIDATOR(name)
    except Exception:  # noqa: BLE001 - django ValidationError
        blockers.append(blocker("NAME_INVALID"))
    if platform not in models.Platform.values:
        blockers.append(blocker("PLATFORM_UNKNOWN", platform=str(platform)[:32]))
    if role not in ROLES:
        blockers.append(blocker("ROLE_INVALID", roles=list(ROLES)))
    if not blockers and (name in ipam.inventory_names() or registry.is_provisioned(name)):
        blockers.append(blocker("NAME_CONFLICT", name=name))
    if blockers:
        return StageResult(None, False, "REQUEST", blockers)
    try:
        with transaction.atomic():
            run = models.ProvisioningRun.objects.create(
                device_name=name, platform=platform, role=role, requested_by=requested_by[:150], site=site[:100],
                image_reference=image_reference[:255], disposable=bool(disposable), repository_head=repository_head(),
            )
            models.AuditEvent.objects.create(
                event_type=models.AuditEventType.PROVISIONING_REQUESTED, object_type="ProvisioningRun", object_id=run.prov_id,
                actor=requested_by[:150], summary=f"{run.prov_id}: provision {name} ({platform})"[:255],
                metadata={"prov_id": run.prov_id, "device": name, "platform": platform, "role": role, "disposable": bool(disposable)},
            )
    except IntegrityError:   # the DB constraint: another live request already owns this name
        return StageResult(None, False, "REQUEST", [blocker("NAME_CONFLICT", name=name)])
    return StageResult(run, True, "REQUEST")


# --- 1. identity / platform / connectivity information -------------------------------------------------------------------------
def define_identity(run, *, actor: str, bootstrap_transport: str, bootstrap_target: dict, management: dict, template_version=None) -> StageResult:
    stage = "IDENTITY"
    blockers = _entry(run, stage)
    if blockers:
        return _refuse(run, stage, blockers, actor=actor)
    target = {k: str(v)[:128] for k, v in dict(bootstrap_target or {}).items() if k in ("container", "lab", "address", "device")}
    mgmt = {k: (str(v)[:64] if v is not None else None) for k, v in dict(management or {}).items()
            if k in ("interface", "ipv4", "ipv6", "vlan", "assignment")}
    if not _secret_free(dict(bootstrap_target or {}), dict(management or {})):
        return _refuse(run, stage, [blocker("SECRET_SHAPED_INPUT")], actor=actor)
    blockers = bootstrap.target_blockers(run.platform, bootstrap_transport, target)
    if not blockers and bootstrap_transport == models.BootstrapTransport.ZTP_MANAGEMENT:
        blockers = commissioning_gate.identity_blockers(run, target)
    owner = registry.owner_of_container(target.get("container", ""))
    # ... or another request that is still in flight has already named it
    claimed = models.ProvisioningRun.objects.exclude(pk=run.pk).exclude(status__in=list(models.PROVISIONING_TERMINAL)).filter(
        bootstrap_target__container=target.get("container", "")).first() if target.get("container") else None
    if not blockers and (owner is not None or claimed is not None):
        blockers = [blocker("BOOTSTRAP_TARGET_IN_USE", device=owner.name if owner is not None else claimed.device_name)]
    parsed, address_blockers = ipam.parse_management(mgmt)
    blockers.extend(address_blockers)
    if parsed is not None:
        blockers.extend(ipam.vlan_policy_blockers(parsed, disposable=run.disposable))
    if blockers:
        return _refuse(run, stage, blockers, actor=actor)
    run.bootstrap_transport, run.bootstrap_target, run.management, run.template_version = bootstrap_transport, target, mgmt, template_version
    return _advance(run, stage, actor=actor, evidence={"transport": bootstrap_transport, "target": target, "management": mgmt},
                    fields=("bootstrap_transport", "bootstrap_target", "management", "template_version"))


# --- 2. bootstrap reality ------------------------------------------------------------------------------------------------------
def classify_bootstrap(run, *, actor: str, prober=None) -> StageResult:
    """Probe (read-only) and classify.  The classification is always recorded; only REACHABLE_BOOTSTRAP may later be executed."""
    stage = "BOOTSTRAP"
    # a staged (unreachable) request may be re-probed any time before approval, without re-walking the earlier stages
    reprobe = run.bootstrap_state == models.BootstrapState.UNREACHABLE and not run.is_terminal and run.status in (
        S.BOOTSTRAP_CLASSIFIED, S.CAPABILITY_RESOLVED, S.IPAM_PLANNED, S.CANDIDATE_READY, S.VALIDATED, S.PLANNED, S.PRECHECKED)
    if not reprobe:
        blockers = _entry(run, stage)
        if blockers:
            return _refuse(run, stage, blockers, actor=actor)
    state, evidence, blockers = bootstrap.classify(run, prober=prober)
    if blockers:
        return _refuse(run, stage, blockers, actor=actor, evidence=evidence)
    run.bootstrap_state = state
    if state == models.BootstrapState.ALREADY_CONFIGURED:
        run.save(update_fields=["bootstrap_state", "updated_at"])
        return _refuse(run, stage, [blocker("DEVICE_ALREADY_CONFIGURED")], actor=actor, evidence=evidence)
    if reprobe:
        run.save(update_fields=["bootstrap_state", "updated_at"])
        return StageResult(run, True, stage, [], _event(run, stage, E.ADVANCED, run.status, actor=actor, evidence={**evidence, "reprobe": True}))
    return _advance(run, stage, actor=actor, evidence={**evidence, "state": state}, fields=("bootstrap_state",))


# --- 3. capability resolution --------------------------------------------------------------------------------------------------
def resolve_capabilities(run, *, actor: str) -> StageResult:
    stage = "CAPABILITY"
    blockers = _entry(run, stage)
    if blockers:
        return _refuse(run, stage, blockers, actor=actor)
    resolution, blockers = capability_gate.resolve_platform(run.platform, run.bootstrap_transport)
    if blockers:
        return _refuse(run, stage, blockers, actor=actor, evidence=resolution)
    run.capability_resolution = {"platform": resolution}
    return _advance(run, stage, actor=actor, evidence={"supported_count": resolution["supported_count"]}, fields=("capability_resolution",))


# --- 4. NetBox / IPAM planning + reservation -----------------------------------------------------------------------------------
def plan_ipam(run, *, actor: str, gateway=None) -> StageResult:
    stage = "IPAM"
    blockers = _entry(run, stage)
    if blockers:
        return _refuse(run, stage, blockers, actor=actor)
    gateway = gateway or _gateway()
    others = set(models.ProvisionedDevice.objects.exclude(state=models.ProvisionedDeviceState.RETIRED).values_list("name", flat=True))
    document, blockers = ipam.plan(run, gateway, registry_names=others)
    if blockers:
        return _refuse(run, stage, blockers, actor=actor, evidence={"plan": document})
    try:
        refs = ipam.reserve(document, gateway, provenance={"prov_id": run.prov_id, "requested_by": run.requested_by})
    except ipam.ReservationFailed as exc:
        return _refuse(run, stage, [blocker("IPAM_RESERVATION_FAILED")], actor=actor,
                       evidence={"attempted": exc.created, "released": exc.released, "clean": all(r["released"] for r in exc.released)})
    run.netbox = {"plan": document, **refs}
    run.planned_interfaces, run.planned_addresses = document["interfaces"], document["addresses"]
    return _advance(run, stage, actor=actor, evidence={"created": refs["created"], "device_id": refs["device_id"]},
                    fields=("netbox", "planned_interfaces", "planned_addresses"))


# --- 5. candidate generation ---------------------------------------------------------------------------------------------------
def generate_candidate(run, *, actor: str, execution_mode: str = models.ExecutionMode.COMPLETE) -> StageResult:
    """Create the ordinary Change + NEW_DEVICE intent the operator fills in the Device Builder, and admit the device to the registry.

    Complete is the normal mode: the whole plan is applied atomically, compensated on failure, and a verified success seals a Deployed
    bundle that can enter Golden probation.  Partial (UAT) keeps its own meaning (an explicitly acknowledged ordered prefix that is
    preserved on failure) and is available, but it is never chosen merely to reach probation.
    """
    stage = "CANDIDATE"
    blockers = _entry(run, stage)
    if blockers:
        return _refuse(run, stage, blockers, actor=actor)
    with transaction.atomic():
        change = change_service.create_change(
            title=f"Provision {run.device_name} ({run.prov_id})"[:200], category=models.ChangeCategory.NEW_DEVICE_PROVISIONING,
            description=f"New-device provisioning request {run.prov_id}.", execution_mode=execution_mode, created_by=actor,
            metadata={"provisioning": {"prov_id": run.prov_id}},
        )
        change_service.add_target(change=change, device_name=run.device_name)
        intent, _ = intent_service.create_or_get_device_intent(
            change=change, device_name=run.device_name, platform=run.platform, target_type=models.DeviceIntentTargetType.NEW_DEVICE,
            image_reference=run.image_reference, netbox_device_ref=str((run.netbox or {}).get("device_id") or ""),
        )
        revision = intent_service.create_candidate_revision(device_intent=intent, sections={}, created_by=actor)
        field_commit_service.seed_device_identity_field_states(intent=intent, revision=revision)
        entry = registry.admit(run, netbox_device_id=(run.netbox or {}).get("device_id"))
        run.change = change
        result = _advance(run, stage, actor=actor, evidence={"change_id": change.change_id, "registry": entry.state,
                                                             "execution_mode": execution_mode}, fields=("change",))
    return result


# --- 6. validation -------------------------------------------------------------------------------------------------------------
def record_validation(run, *, actor: str, sources=None) -> StageResult:
    """Run the two existing validations on the CURRENT candidate; advance only when both pass."""
    stage = "VALIDATION"
    blockers = _entry(run, stage)
    if blockers:
        return _refuse(run, stage, blockers, actor=actor)
    change = run.change
    intent = change.device_intents.filter(device_name=run.device_name).first()
    revision = intent.latest_revision() if intent else None
    if revision is None or not any((revision.sections or {}).values()):
        return _refuse(run, stage, [blocker("INTENT_EMPTY")], actor=actor)
    config_run = ncv.validate_candidate(change, actor=actor, sources=sources)
    validation = cvs.validate_change(change, actor=actor, sources=sources, network_validated=config_run.status in _NCV_PASSING)
    evidence = {"validation_run_id": str(validation.run_id), "validation_status": validation.status,
                "network_config_validation_run_id": str(config_run.run_id), "network_config_status": config_run.status}
    if config_run.status not in _NCV_PASSING or validation.status not in _PASSING:
        return _refuse(run, stage, [blocker("VALIDATION_NOT_PASSING", **{k: v for k, v in evidence.items() if k.endswith("status")})],
                       actor=actor, evidence=evidence)
    run.validation_run, run.network_config_validation_run = validation, config_run
    return _advance(run, stage, actor=actor, evidence=evidence, fields=("validation_run", "network_config_validation_run"))


# --- 7. provisioning plan (+ the exact capability gate) ------------------------------------------------------------------------
def candidate_text(plan) -> str:
    """The plan's rendered candidate, in plan order."""
    parts = []
    for configlet in plan.configlets.order_by("sequence"):
        parts.append(f"! {configlet.cfg_id} {configlet.target_device}\n{(configlet.rendered_config or '').rstrip()}")
    return "\n".join(parts) + "\n"


def build_plan(run, *, actor: str, sources=None) -> StageResult:
    stage = "PLAN"
    blockers = _entry(run, stage)
    if blockers:
        return _refuse(run, stage, blockers, actor=actor)
    currency = cvs.get_validation_currency(run.change, sources=sources, check_sources=sources is not None)
    if currency["state"] != Currency.CURRENT or currency["last_status"] not in _PASSING:
        return _refuse(run, stage, [blocker("VALIDATION_NOT_PASSING", state=str(currency["state"]))], actor=actor)
    try:
        plan, _created = change_plan_service.build_change_plan(run.change, actor=actor, sources=sources)
    except Exception as exc:  # noqa: BLE001 - the builder's refusal is a stable PlanError code, reported as evidence
        return _refuse(run, stage, [blocker("PLAN_NOT_CURRENT", reason=type(exc).__name__, plan_code=str(getattr(exc, "code", ""))[:64])], actor=actor)
    resolution, blockers = capability_gate.resolve_plan(run.platform, plan)
    foreign = sorted({c.target_device for c in plan.configlets.all()} - {run.device_name})
    if foreign:   # a provisioning plan configures the new device and nothing else
        blockers.append(blocker("CAPABILITY_UNSUPPORTED", feature="scope", platform=run.platform,
                                reason=f"The plan also targets {', '.join(foreign)}; provisioning never changes another device."))
    if blockers:
        return _refuse(run, stage, blockers, actor=actor, evidence={"plan_id": str(plan.plan_id), "capability": resolution})
    text = candidate_text(plan)
    run.plan, run.candidate_config, run.candidate_hash = plan, text, hashlib.sha256(text.encode()).hexdigest()
    run.capability_resolution = {**(run.capability_resolution or {}), "plan": resolution}
    return _advance(run, stage, actor=actor, evidence={"plan_id": str(plan.plan_id), "candidate_hash": run.candidate_hash,
                                                       "features": [c["feature"] for c in resolution["cells"]]},
                    fields=("plan", "candidate_config", "candidate_hash", "capability_resolution"))


# --- 8. precheck ---------------------------------------------------------------------------------------------------------------
def run_precheck(run, *, actor: str, sources=None, **precheck_options) -> StageResult:
    stage = "PRECHECK"
    refresh = run.status == S.APPROVED     # the execution gate needs a RECENT precheck: an approved request may refresh an expired one
    blockers = [] if refresh else _entry(run, stage)
    if blockers:
        return _refuse(run, stage, blockers, actor=actor)
    if run.bootstrap_state != models.BootstrapState.REACHABLE_BOOTSTRAP:
        return _refuse(run, stage, [blocker("DEVICE_UNREACHABLE", bootstrap_state=run.bootstrap_state)], actor=actor)
    outcome = health_service.run_change_precheck(run.change, actor=actor, sources=sources, **precheck_options)
    evidence = {"result": outcome.result, "run_id": str(outcome.run.run_id) if outcome.run else ""}
    if outcome.result not in _PRECHECK_PERMITS or outcome.run is None:
        return _refuse(run, stage, [blocker("PRECHECK_NOT_PERMITTING", result=outcome.result)], actor=actor, evidence=evidence)
    run.precheck_run = outcome.run
    if refresh:
        run.save(update_fields=["precheck_run", "updated_at"])
        return StageResult(run, True, stage, [], _event(run, stage, E.ADVANCED, run.status, actor=actor, evidence={**evidence, "refresh": True}))
    return _advance(run, stage, actor=actor, evidence=evidence, fields=("precheck_run",))


# --- 9. approval ---------------------------------------------------------------------------------------------------------------
def approve(run, *, actor: str, confirm_candidate_hash: str, comment: str = "") -> StageResult:
    """An explicit approval of ONE exact candidate.  The echoed hash is a staleness guard, never authority."""
    stage = "APPROVAL"
    blockers = _entry(run, stage)
    if blockers:
        return _refuse(run, stage, blockers, actor=actor)
    if (getattr(settings, "PROVISIONING_REQUIRE_SEPARATE_APPROVER", False) or commissioning_gate.is_commissioning(run)) and actor == run.requested_by:
        return _refuse(run, stage, [blocker("APPROVAL_SELF")], actor=actor)      # commissioning: separation is mandatory
    commissioning = commissioning_gate.approval_blockers(run, actor)
    if commissioning:
        return _refuse(run, stage, commissioning, actor=actor)
    if not run.candidate_hash or confirm_candidate_hash != run.candidate_hash:
        return _refuse(run, stage, [blocker("APPROVAL_CONFIRMATION_MISMATCH")], actor=actor)
    stale = _approval_staleness(run)
    if stale:
        return _refuse(run, stage, stale, actor=actor)
    if secret_policy.redact_text(comment) != comment:
        return _refuse(run, stage, [blocker("SECRET_SHAPED_INPUT")], actor=actor)
    run.approval = {"approved_by": actor[:150], "approved_at": timezone.now().isoformat(), "candidate_hash": run.candidate_hash,
                    "plan_id": str(run.plan.plan_id), "precheck_run_id": str(run.precheck_run.run_id), "comment": comment[:500]}
    result = _advance(run, stage, actor=actor, evidence={k: v for k, v in run.approval.items() if k != "comment"}, fields=("approval",))
    models.AuditEvent.objects.create(
        event_type=models.AuditEventType.PROVISIONING_APPROVED, change=run.change, object_type="ProvisioningRun", object_id=run.prov_id,
        actor=actor[:150], summary=f"{run.prov_id} approved by {actor}"[:255],
        metadata={"prov_id": run.prov_id, "candidate_hash": run.candidate_hash, "plan_id": str(run.plan.plan_id)},
    )
    return result


def _approval_staleness(run) -> list[dict]:
    """The approved artifact must still be THE current one: same latest plan, same rendered candidate."""
    latest = change_plan_service.get_latest_plan(run.change)
    if latest is None or run.plan_id != latest.pk:
        return [blocker("APPROVAL_STALE", reason="a newer plan exists")]
    if hashlib.sha256(candidate_text(latest).encode()).hexdigest() != run.candidate_hash:
        return [blocker("APPROVAL_STALE", reason="the candidate text changed")]
    return []


# --- 10. provision (execute + postcheck) ---------------------------------------------------------------------------------------
def linux_config_reader(device: dict) -> str:
    """Read-only running state of a Linux/FRR device: the FRR running configuration plus its link/address table."""
    from ..execution.executors import linux
    from ..execution.codes import device_timeout_seconds

    timeout = device_timeout_seconds()
    config = linux.read_frr_config(device["container"], timeout)
    links = linux.docker_exec(device["container"], ["ip", "-j", "addr", "show"], timeout)
    if links.returncode:
        raise RuntimeError("READ_FAILED")
    return f"{config}\n--links--\n{links.stdout}"


def config_digest(run) -> str:
    """SHA-256 of the device's current running state, or '' when it cannot be read (never a fabricated digest)."""
    device = registry.devices().get(run.device_name)
    if device is None:
        return ""
    try:
        reader = CONFIG_READER or (commissioning_gate.config_reader if device.get("platform") == "ceos" else linux_config_reader)
        text = reader(device)
    except Exception:  # noqa: BLE001 - unreadable is unreadable
        return ""
    return hashlib.sha256(str(text).encode()).hexdigest() if text else ""


# Device / NetBox access used by the engine hooks below.  None selects the real implementation; tests substitute fakes here.
CONFIG_READER = None
GATEWAY_FACTORY = None


def _gateway():
    return (GATEWAY_FACTORY or ipam.NetboxGateway)()


def execution_blockers(change) -> list[dict]:
    """The provisioning part of THE execution gate (called by ``execution.eligibility`` for every Change; read-only).

    A provisioning Change is executable only while its request is APPROVED, the approved candidate is still the current one and the
    device was classified as a reachable bootstrap device.  This is what makes the ordinary execute route safe for a provisioning Change:
    there is no separate provisioning execution entry point, and the ordinary one cannot skip approval.
    """
    run = models.ProvisioningRun.objects.filter(change=change).first()
    if run is None:
        return []
    if run.status != S.APPROVED:
        return [execution_blocker("PROVISIONING_NOT_APPROVED", prov_id=run.prov_id, status=run.status)]
    if _approval_staleness(run):
        return [execution_blocker("PROVISIONING_APPROVAL_STALE", prov_id=run.prov_id)]
    if run.bootstrap_state != models.BootstrapState.REACHABLE_BOOTSTRAP:
        return [execution_blocker("PROVISIONING_DEVICE_UNREACHABLE", prov_id=run.prov_id, bootstrap_state=run.bootstrap_state)]
    return commissioning_gate.execution_blockers(run)


def before_first_mutation(change) -> list[dict]:
    """Engine hook, called inside the device lock after every Configlet was assessed and BEFORE the first write.

    Captures the device's pre-change configuration digest (a provision without a real baseline digest is refused) and marks the request
    PROVISIONING.  Returns execution blockers; an empty list lets the engine proceed.  A non-provisioning Change is untouched.
    """
    run = models.ProvisioningRun.objects.filter(change=change).first()
    if run is None:
        return []
    blockers = execution_blockers(change)
    if blockers:
        return blockers
    digest = config_digest(run)
    if not digest:
        _refuse(run, "PROVISION", [blocker("DIGEST_UNAVAILABLE", when="before")], actor=run.approval.get("approved_by", ""))
        return [execution_blocker("PROVISIONING_BASELINE_UNREADABLE", prov_id=run.prov_id)]
    run.pre_config_digest, run.status = digest, S.PROVISIONING
    run.save(update_fields=["status", "pre_config_digest", "updated_at"])
    commissioning_gate.mark_configuring(run)
    return []


def after_execution(execution) -> StageResult | None:
    """Engine hook, called once after an execution run of a provisioning Change was finalised.  Records what really happened.

    Success needs the engine's own verdict (which includes the Phase-15 postcheck) AND a readable resulting configuration.  Anything else
    ends the request: NetBox objects this run created are released, the registry entry is retired, and the run is ROLLED_BACK when the
    device demonstrably holds none of this run's configuration, FAILED otherwise.  A refusal before the first write changes nothing.
    """
    run = models.ProvisioningRun.objects.filter(change_id=execution.change_id).first()
    if run is None or run.is_terminal:
        return None
    stage, actor, outcome = "PROVISION", execution.actor, str(execution.outcome or "")
    evidence = {"execution_run_id": str(execution.run_id), "outcome": outcome,
                "blockers": [b.get("code") for b in ((execution.report or {}).get("blockers") or [])]}
    if run.status != S.PROVISIONING:      # refused before the first-mutation hook: nothing was written, the request stays where it was
        return _refuse(run, stage, [blocker("EXECUTION_BLOCKED", outcome=outcome)], actor=actor, evidence=evidence)
    run.execution_run, run.postcheck_run = execution, execution.postcheck_run
    if outcome not in _APPLIED:
        code = "EXECUTION_BLOCKED" if outcome == Outcome.BLOCKED else (
            "POSTCHECK_NOT_PASSING" if "POSTCHECK" in outcome or "UNVERIFIED" in outcome else "EXECUTION_FAILED")
        return _fail(run, stage, code, actor=actor, evidence=evidence, restored=outcome in _RESTORED)
    run.post_config_digest = config_digest(run)
    if not run.post_config_digest:
        return _fail(run, stage, "DIGEST_UNAVAILABLE", actor=actor, evidence=evidence, restored=False)
    postcheck = (execution.report or {}).get("postcheck") or {}
    run.result = {"execution_outcome": outcome, "execution_mode": str(execution.mode),
                  "postcheck": {"result": postcheck.get("result"), "run_id": postcheck.get("run_id", "")},
                  "runtime_identity": {"name": run.device_name, "platform": str(run.platform), **(run.bootstrap_target or {})},
                  "config_changed": run.post_config_digest != run.pre_config_digest}
    previous = run.status
    run.status = S.POSTCHECKED
    run.save(update_fields=["status", "execution_run", "postcheck_run", "post_config_digest", "result", "updated_at"])
    return StageResult(run, True, stage, [], _event(run, stage, E.ADVANCED, previous, actor=actor, evidence={
        **evidence, "pre_config_digest": run.pre_config_digest, "post_config_digest": run.post_config_digest}))


# --- failure / cancellation reconciliation -------------------------------------------------------------------------------------
def reconcile(run, *, gateway=None) -> dict:
    """Undo what THIS run reserved or admitted: release its NetBox objects, retire its registry entry.  Reports; never raises."""
    report = {"netbox": [], "registry": "NONE", "clean": True}
    created = (run.netbox or {}).get("created") or []
    if created:
        try:
            report["netbox"] = ipam.release(gateway or _gateway(), created)
        except Exception:  # noqa: BLE001 - e.g. NetBox not configured at all
            report["netbox"] = [{**item, "released": False} for item in created]
        report["clean"] = all(item["released"] for item in report["netbox"])
    entry = registry.live_entry(run.device_name)
    if entry is not None and entry.run_id == run.pk:
        registry.retire(entry)
        report["registry"] = "RETIRED"
    return report


def _fail(run, stage, code, *, actor, evidence, restored: bool) -> StageResult:
    previous = run.status
    after = run.pre_config_digest if restored else config_digest(run)     # read back BEFORE the registry entry is retired
    reconciliation = reconcile(run)
    run.failure = {"stage": stage, "code": code, "message": BLOCKERS[code][0], "device_restored": bool(restored),
                   "device_digest_after": after, "reconciliation": reconciliation, **evidence}
    run.status, run.finished_at = (S.ROLLED_BACK if restored else S.FAILED), timezone.now()
    run.save(update_fields=["status", "failure", "finished_at", "execution_run", "postcheck_run", "updated_at"])
    event = _event(run, stage, E.FAILED, previous, actor=actor, blockers=[blocker(code)], evidence=run.failure)
    return StageResult(run, False, stage, [blocker(code)], event)


def cancel(run, *, actor: str, gateway=None, reason: str = "") -> StageResult:
    """Operator cancellation before the device was provisioned.  Releases the reservation and retires the registry entry."""
    stage = "CANCEL"
    if run.is_terminal:
        return _refuse(run, stage, [blocker("RUN_FINISHED", status=run.status)], actor=actor)
    if run.status in (S.PROVISIONING, S.POSTCHECKED, S.NSOT_SYNCED):
        return _refuse(run, stage, [blocker("WRONG_STAGE", status=run.status, stage=stage)], actor=actor)
    previous = run.status
    reconciliation = reconcile(run, gateway=gateway) if previous in RESERVED_STATUSES else {"netbox": [], "registry": "NONE", "clean": True}
    run.failure = {"stage": stage, "code": "CANCELLED", "reason": secret_policy.redact_text(reason)[:500], "reconciliation": reconciliation}
    run.status, run.finished_at = S.CANCELLED, timezone.now()
    run.save(update_fields=["status", "failure", "finished_at", "updated_at"])
    models.AuditEvent.objects.create(
        event_type=models.AuditEventType.PROVISIONING_CANCELLED, change=run.change, object_type="ProvisioningRun", object_id=run.prov_id,
        actor=actor[:150], summary=f"{run.prov_id} cancelled"[:255], metadata={"prov_id": run.prov_id, "clean": reconciliation["clean"]},
    )
    return StageResult(run, True, stage, [], _event(run, stage, E.RECONCILED, previous, actor=actor, evidence=run.failure))


# --- 11. NSOT synchronization --------------------------------------------------------------------------------------------------
def sync_nsot(run, *, actor: str, gateway=None) -> StageResult:
    """The device is provisioned and verified: NetBox objects become active and the registry entry becomes an ordinary managed device.

    A disposable device never joins the IaC managed scope (its objects keep only the provisioning tags).
    """
    stage = "NSOT_SYNC"
    blockers = _entry(run, stage) or commissioning_gate.sync_blockers(run)
    if blockers:
        return _refuse(run, stage, blockers, actor=actor)
    try:
        refs = ipam.activate(gateway or _gateway(), {k: v for k, v in (run.netbox or {}).items() if k != "plan"},
                             managed=not run.disposable)
    except Exception:  # noqa: BLE001 - NetBox unavailable: the device stays ADMITTED; the stage can be retried
        return _refuse(run, stage, [blocker("NSOT_SYNC_FAILED")], actor=actor)
    entry = registry.live_entry(run.device_name)
    registry.activate(entry)
    run.netbox = {**(run.netbox or {}), **refs}
    run.result = {**(run.result or {}), "netbox_identity": {"device_id": refs.get("device_id"), "name": run.device_name,
                                                              "status": refs["status"], "managed_scope": refs["managed_scope"]},
                  "config_digest": run.post_config_digest}
    result = _advance(run, stage, actor=actor, evidence=run.result["netbox_identity"], fields=("netbox", "result"))
    models.AuditEvent.objects.create(
        event_type=models.AuditEventType.PROVISIONING_COMPLETED, change=run.change, object_type="ProvisioningRun", object_id=run.prov_id,
        actor=actor[:150], summary=f"{run.prov_id}: {run.device_name} provisioned"[:255],
        metadata={"prov_id": run.prov_id, "config_digest": run.post_config_digest},
    )
    return result


# --- 12. Golden probation ------------------------------------------------------------------------------------------------------
def probation_candidate(run, *, actor: str) -> tuple[object | None, list[dict], object | None]:
    """Seal the executed scope into its root and Probation bundles and report whether a soak MAY start.  Starts nothing.

    The root artifact follows the execution that really happened: a verified Complete run seals a Deployed bundle, a Partial (UAT) run a
    UAT bundle.  Neither is relabelled as the other, and both freeze the run's own pinned records (references, never copies).
    -> (probation bundle or None, blockers, soak start eligibility or None)
    """
    if run.execution_run is None:
        return None, [blocker("PROBATION_NOT_STARTABLE", step="EXECUTION")], None
    root = getattr(bundle_service, _ROOT_BUNDLE[run.execution_run.mode])(run.execution_run, actor=actor)
    if root.bundle is None:
        return None, [blocker("PROBATION_NOT_STARTABLE", step="ROOT_BUNDLE", codes=[b.get("code") for b in root.blockers])], None
    probation = bundle_service.derive_probation_bundle(root.bundle, actor=actor)
    if probation.bundle is None:
        return None, [blocker("PROBATION_NOT_STARTABLE", step="PROBATION_BUNDLE", codes=[b.get("code") for b in probation.blockers])], None
    eligibility = soak_service.check_soak_start(probation.bundle)
    blockers = [] if eligibility.eligible else [blocker("PROBATION_NOT_STARTABLE", step="SOAK", codes=[b.get("code") for b in eligibility.blockers])]
    return probation.bundle, blockers, eligibility


def start_probation(run, *, actor: str) -> StageResult:
    """Seal the executed scope into its bundles and start the NORMAL soak (the server-owned 7-day policy; never a shortened one)."""
    stage = "PROBATION"
    blockers = _entry(run, stage)
    if blockers:
        return _refuse(run, stage, blockers, actor=actor)
    bundle, blockers, _eligibility = probation_candidate(run, actor=actor)
    if blockers:
        return _refuse(run, stage, blockers, actor=actor, evidence={"probation_bundle": bundle.bundle_id if bundle else ""})
    started = soak_service.start_soak(bundle, actor=actor)
    if started.run is None:
        return _refuse(run, stage, [blocker("PROBATION_NOT_STARTABLE", step="SOAK", codes=[b.get("code") for b in started.blockers])],
                       actor=actor, evidence={"probation_bundle": bundle.bundle_id})
    soak = started.run
    run.probation_bundle, run.soak_run, run.finished_at = bundle, soak, timezone.now()
    return _advance(run, stage, actor=actor, evidence={
        "probation_bundle": bundle.bundle_id, "soak_id": soak.soak_id, "started_at": soak.started_at.isoformat(),
        "required_end_at": soak.required_end_at.isoformat(), "duration_seconds": soak.duration_seconds,
    }, fields=("probation_bundle", "soak_run", "finished_at"))


# --- decommission (cleanup of a provisioned device) ----------------------------------------------------------------------------
def decommission(run, *, actor: str, gateway=None) -> dict:
    """Remove a provisioned device from NMAS: retire its registry entry and release the NetBox objects its run created.

    This never touches the device itself (removing disposable infrastructure is a lab operation).  A request that was still open
    (provisioned, not yet in probation) ends as DECOMMISSIONED, so it stops holding the device name and bootstrap target; a request that
    already finished is immutable and is not edited -- the reconciliation is recorded as an audit event either way.
    """
    entry = registry.live_entry(run.device_name)
    report = {"netbox": [], "registry": "NONE", "clean": True}
    created = (run.netbox or {}).get("created") or []
    if created:
        try:
            report["netbox"] = ipam.release(gateway or _gateway(), created)
        except Exception:  # noqa: BLE001
            report["netbox"] = [{**item, "released": False} for item in created]
        report["clean"] = all(item["released"] for item in report["netbox"])
    if entry is not None and entry.run_id == run.pk:
        registry.retire(entry)
        report["registry"] = "RETIRED"
    if not run.is_terminal and run.status in (S.POSTCHECKED, S.NSOT_SYNCED):
        previous = run.status
        run.status, run.finished_at = S.DECOMMISSIONED, timezone.now()
        run.result = {**(run.result or {}), "decommission": {"clean": report["clean"], "registry": report["registry"]}}
        run.save(update_fields=["status", "finished_at", "result", "updated_at"])
        _event(run, "DECOMMISSION", E.RECONCILED, previous, actor=actor, evidence=report)
    models.AuditEvent.objects.create(
        event_type=models.AuditEventType.DEVICE_DECOMMISSIONED, change=run.change, object_type="ProvisioningRun", object_id=run.prov_id,
        actor=actor[:150], summary=f"{run.device_name} retired from NMAS ({run.prov_id})"[:255],
        metadata={"prov_id": run.prov_id, "device": run.device_name, "clean": report["clean"],
                  "netbox": [{k: item[k] for k in ("kind", "id", "released")} for item in report["netbox"]]},
    )
    return report
