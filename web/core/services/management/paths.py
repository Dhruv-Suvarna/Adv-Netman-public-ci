"""The NMAS-side attachment and management-path registry, priority ordering and L1 (topology) verification.

Priority hierarchy (applied only among paths that are actually USABLE -- approved, verified, healthy):

    1. DIRECT_OOB            -- the device's own approved MANAGEMENT attachment straight to the switch NMAS is attached to
    2. VLAN_ADJACENT_SWITCH  -- the management VLAN through an approved, connected adjacent switch; ordered by ascending
                                switch identity: natural order of the switch's managed name (S1 < S3 < S10), ties broken by
                                its stable lifecycle id (DEV-000001 < DEV-000002)
    3. ROUTED_VRF            -- a routed management VRF

The class is a property of the path TYPE (``models.MANAGEMENT_PATH_CLASS``); no caller chooses it.

Registering a path changes no device and no network: it is an expectation, PENDING until a different operator approves it.
A path never carries a credential; it names a credential SOURCE (inventory key, DeviceCredential id, ZTP session id).
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field

from django.db import IntegrityError, transaction
from django.db.models import Q
from django.utils import timezone

from ... import models
from ..devices import codes, events, identity, resolver
from ..devices.attachments import MANAGEMENT_VLAN
from . import guard

T = models.ManagementPathType
Approval = models.ManagementApproval
Outcome = models.DeviceLifecycleEventOutcome
LIVE_PATH = ~Q(approval_state=Approval.REVOKED)
MAX_VLAN_HOPS = 8
RESERVED_VRF_NAMES = frozenset({"default", "global", "mgmt-default"})
# Platforms with a path verifier (L2 configuration read-back + L6 identity).  A path for any other platform could never
# verify, and approving one would make the device fail closed -- so it is refused at registration instead.
VERIFIED_PLATFORMS = frozenset({models.Platform.ARISTA_CEOS.value})


@dataclass
class Result:
    ok: bool
    action: str
    blockers: list = field(default_factory=list)
    path: object | None = None
    attachment: object | None = None
    event: object | None = None

    @property
    def codes(self) -> list[str]:
        return codes.codes(self.blockers)


class _Refused(Exception):
    def __init__(self, blockers):
        super().__init__("refused")
        self.blockers = blockers


# --- ordering -------------------------------------------------------------------------------------------------------------------
def natural_key(name: str) -> tuple:
    """``S1`` < ``S3`` < ``S10``: digit runs compare numerically, letters case-insensitively."""
    return tuple((0, int(part), "") if part.isdigit() else (1, 0, part.lower()) for part in re.findall(r"\d+|\D+", str(name or "")))


def switch_identity(name: str) -> tuple:
    """The deterministic adjacent-switch identity used for class-2 ordering: (natural name, DEV id number)."""
    row = models.ManagedDevice.objects.filter(identity.LIVE, name=name).order_by("pk").first()
    return natural_key(name), row.pk if row else 10 ** 9


def priority_key(path) -> tuple:
    """Total order of a device's paths (lower = preferred)."""
    within = switch_identity(path.via_device) if path.path_type == T.VLAN_ADJACENT_SWITCH else ((), 0)
    return path.preference_class, within, path.pk or 0


def ordered(paths) -> list:
    return sorted(paths, key=priority_key)


def live_paths(device):
    return ordered(models.ManagementPath.objects.filter(LIVE_PATH, device=device).select_related("nmas_attachment", "attachment"))


def approved_paths(device):
    return [p for p in live_paths(device) if p.approval_state == Approval.APPROVED]


# --- evidence helpers -----------------------------------------------------------------------------------------------------------
def _audit(action: str, outcome: str, *, actor: str, object_type: str, object_id: str, summary: str, metadata: dict | None = None):
    from .. import secret_policy

    event_type = (models.AuditEventType.DEVICE_LIFECYCLE_REFUSED if outcome == Outcome.REFUSED
                  else models.AuditEventType.MANAGEMENT_PATH_CHANGED)
    return models.AuditEvent.objects.create(event_type=event_type, object_type=object_type, object_id=object_id[:64], actor=actor[:150],
                                            summary=summary[:255], outcome=outcome.lower()[:16],
                                            metadata=secret_policy.redact({"action": action, **(metadata or {})}))


def _refuse_device(device, action, blockers, *, actor):
    with transaction.atomic():
        event = events.record(device, action, Outcome.REFUSED, actor=actor, from_state=device.lifecycle_state, blockers=blockers)
    return Result(False, action, list(blockers), event=event)


def _refuse_attachment(action, blockers, *, actor, object_id="NMA-NEW"):
    _audit(action, Outcome.REFUSED, actor=actor, object_type="NmasManagementAttachment", object_id=object_id,
           summary=f"{object_id}: {action} refused", metadata={"codes": codes.codes(blockers)})
    return Result(False, action, list(blockers))


# --- NMAS-side attachments ------------------------------------------------------------------------------------------------------
def register_nmas_attachment(*, name: str, host_interface: str, upstream_device: str, source_address: str, network: str,
                             failure_domain: str = "", upstream_interface: str = "", actor: str) -> Result:
    """Record where the NMAS host is attached (PENDING).  Pure expectation: the host is never reconfigured."""
    action = "NMAS_ATTACHMENT_REGISTER"
    name, host_interface, upstream_device = (str(v or "").strip() for v in (name, host_interface, upstream_device))
    upstream_interface, failure_domain = str(upstream_interface or "").strip(), str(failure_domain or "").strip() or str(upstream_device)
    blockers = []
    try:
        ip = ipaddress.ip_address(str(source_address))
        prefix = ipaddress.ip_network(str(network), strict=False)
        if ip.version != prefix.version or ip not in prefix:
            blockers.append(codes.blocker("NMAS_ATTACHMENT_INVALID", reason="source address outside the network"))
        # never the Containerlab / Docker management plane (or loopback / link-local) as a substitute attachment
        blockers += guard.address_problems(str(ip))
        if any(prefix.version == bad.version and prefix.overlaps(bad) for bad in guard._forbidden_networks()):
            blockers.append(codes.blocker("MGMT_ENDPOINT_FORBIDDEN", reason="Containerlab management network"))
    except ValueError:
        blockers.append(codes.blocker("NMAS_ATTACHMENT_INVALID", reason="address / network malformed"))
        prefix = None
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", name) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._@-]{0,31}", host_interface):
        blockers.append(codes.blocker("NMAS_ATTACHMENT_INVALID", reason="name / host interface malformed"))
    if upstream_interface and not models.INTERFACE_RE.fullmatch(upstream_interface):
        blockers.append(codes.blocker("NMAS_ATTACHMENT_INVALID", reason="upstream interface malformed"))
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}", failure_domain):
        blockers.append(codes.blocker("NMAS_ATTACHMENT_INVALID", reason="failure domain malformed"))
    if not blockers:
        target = resolver.resolve(upstream_device)
        if target is None or not target.writable:
            blockers.append(codes.blocker("MGMT_PATH_SWITCH_UNAUTHORIZED", switch=upstream_device[:64]))
    if blockers:
        return _refuse_attachment(action, blockers, actor=actor)
    try:
        with transaction.atomic():
            row = models.NmasManagementAttachment.objects.create(
                name=name, host_interface=host_interface, upstream_device=upstream_device, upstream_interface=upstream_interface,
                source_address=str(ip), network=str(prefix), failure_domain=failure_domain, created_by=actor[:150])
            _audit(action, Outcome.RECORDED, actor=actor, object_type="NmasManagementAttachment", object_id=row.attachment_id,
                   summary=f"{row.attachment_id}: {host_interface} -> {upstream_device} registered",
                   metadata={"source_address": str(ip), "network": str(prefix), "failure_domain": failure_domain})
    except IntegrityError:
        return _refuse_attachment(action, [codes.blocker("MGMT_PATH_DUPLICATE")], actor=actor)
    return Result(True, action, attachment=row)


def approve_nmas_attachment(attachment, *, actor: str) -> Result:
    action = "NMAS_ATTACHMENT_APPROVE"
    blockers = []
    if attachment.approval_state != Approval.PENDING:
        blockers.append(codes.blocker("MGMT_PATH_NOT_PENDING", state=attachment.approval_state))
    if actor == attachment.created_by:
        blockers.append(codes.blocker("MGMT_PATH_SELF_APPROVAL"))
    if blockers:
        return _refuse_attachment(action, blockers, actor=actor, object_id=attachment.attachment_id)
    with transaction.atomic():
        locked = models.NmasManagementAttachment.objects.select_for_update().get(pk=attachment.pk)
        if locked.approval_state != Approval.PENDING:
            return _refuse_attachment(action, [codes.blocker("MGMT_STATE_CONFLICT")], actor=actor, object_id=attachment.attachment_id)
        locked.approval_state, locked.approved_by, locked.approved_at = Approval.APPROVED, actor[:150], timezone.now()
        locked.version += 1
        locked.save()
        _audit(action, Outcome.RECORDED, actor=actor, object_type="NmasManagementAttachment", object_id=locked.attachment_id,
               summary=f"{locked.attachment_id} approved")
    return Result(True, action, attachment=locked)


def revoke_nmas_attachment(attachment, *, actor: str, reason: str) -> Result:
    action = "NMAS_ATTACHMENT_REVOKE"
    text, problems = identity.clean_text(reason, max_length=200)
    if problems or not text:
        return _refuse_attachment(action, problems or [codes.blocker("REASON_REQUIRED")], actor=actor, object_id=attachment.attachment_id)
    if attachment.approval_state == Approval.REVOKED:
        return _refuse_attachment(action, [codes.blocker("MGMT_PATH_REVOKED")], actor=actor, object_id=attachment.attachment_id)
    if models.ManagementPath.objects.filter(LIVE_PATH, nmas_attachment=attachment).exists():
        return _refuse_attachment(action, [codes.blocker("MGMT_PATH_ACTIVE", reason="live paths use this attachment")], actor=actor,
                                  object_id=attachment.attachment_id)
    with transaction.atomic():
        locked = models.NmasManagementAttachment.objects.select_for_update().get(pk=attachment.pk)
        locked.approval_state, locked.revoked_by, locked.revoked_at = Approval.REVOKED, actor[:150], timezone.now()
        locked.version += 1
        locked.save()
        _audit(action, Outcome.RECORDED, actor=actor, object_type="NmasManagementAttachment", object_id=locked.attachment_id,
               summary=f"{locked.attachment_id} revoked", metadata={"reason": text})
    return Result(True, action, attachment=locked)


def record_nmas_observation(attachment, observation: dict, *, actor: str) -> Result:
    """Apply one read-only host observation (``nmas_side.observe_interface``): VERIFIED only when the interface is up and holds
    the source address; MISMATCH otherwise.  The observation is facts only."""
    action = "NMAS_ATTACHMENT_OBSERVE"
    facts = {key: observation.get(key) for key in ("interface", "exists", "oper_up", "addresses", "holds_source", "source")}
    verified = bool(facts.get("exists") and facts.get("oper_up") and facts.get("holds_source"))
    with transaction.atomic():
        locked = models.NmasManagementAttachment.objects.select_for_update().get(pk=attachment.pk)
        if locked.approval_state == Approval.REVOKED:
            return _refuse_attachment(action, [codes.blocker("MGMT_PATH_REVOKED")], actor=actor, object_id=locked.attachment_id)
        locked.verification_state = models.AttachmentVerification.VERIFIED if verified else models.AttachmentVerification.MISMATCH
        locked.observation, locked.observed_at = facts, timezone.now()
        locked.version += 1
        locked.save()
        _audit(action, Outcome.RECORDED, actor=actor, object_type="NmasManagementAttachment", object_id=locked.attachment_id,
               summary=f"{locked.attachment_id} observed: {locked.verification_state}", metadata=facts)
    return Result(True, action, attachment=locked)


# --- path registration ----------------------------------------------------------------------------------------------------------
def _device_scope_problems(device) -> list[dict]:
    if device.is_terminal:
        return [codes.blocker("DEVICE_TERMINAL", state=device.lifecycle_state)]
    target = resolver.resolve(device.name)
    if target is not None and target.scope == resolver.Scope.READ_ONLY:
        return [codes.blocker("OUT_OF_WRITABLE_SCOPE")]
    return []


def _switch_problems(device_name: str, name: str) -> list[dict]:
    """The adjacent / management switch must be a live, managed, writable switch NMAS trusts as an upstream."""
    from ..devices.attachments import upstream_problems

    if not name:
        return [codes.blocker("MGMT_PATH_SWITCH_UNAUTHORIZED", reason="no switch named")]
    problems = upstream_problems(device_name, name)
    return [codes.blocker("MGMT_PATH_SWITCH_UNAUTHORIZED", switch=name[:64], reason=",".join(codes.codes(problems)))] if problems else []


def _credential_problems(device, source: str, reference: str, credential) -> list[dict]:
    S = models.ManagementCredentialSource
    if source not in S.values:
        return [codes.blocker("MGMT_CREDENTIAL_INVALID", reason="unknown source")]
    if source == S.INVENTORY:
        target = resolver.resolve(device.name)
        if target is None or target.authority != resolver.Authority.INVENTORY_FILE or reference != device.name \
                or not (target.credential_refs.get("credential_ref") or target.credential_refs.get("ssh_key_ref")):
            return [codes.blocker("MGMT_CREDENTIAL_INVALID", reason="no inventory credential reference for this device")]
        return []
    if source == S.DEVICE_CREDENTIAL:
        if credential is None or credential.device_name != device.name:
            return [codes.blocker("MGMT_CREDENTIAL_INVALID", reason="credential belongs to another device")]
        if credential.account_kind == models.AccountKind.HUMAN or credential.auth_method == models.DeviceAuthMethod.PASSWORD_AND_TOTP:
            return [codes.blocker("MGMT_CREDENTIAL_HUMAN")]
        if credential.account_kind != models.AccountKind.SERVICE:
            return [codes.blocker("MGMT_CREDENTIAL_INVALID", reason="not a service account")]
        return []
    session = models.ZtpSession.objects.filter(pk=_ztp_pk(reference), device=device).first()
    if session is None or not session.enrolled_host_key:
        return [codes.blocker("MGMT_CREDENTIAL_INVALID", reason="no ZTP session with an enrolled host key")]
    return []


def _ztp_pk(reference: str):
    match = re.fullmatch(r"ZTP-(\d{6})", str(reference or ""))
    return int(match.group(1)) if match else None


def _attachment_problems(device, path_type: str, attachment, nmas_attachment, via_device: str, vlan) -> list[dict]:
    if path_type == T.ROUTED_VRF:
        # A bound source socket proves the egress interface, but by itself it
        # cannot authorize an arbitrary routed next hop behind that interface.
        # The currently verified routed shape is the on-link NMAS <-> device
        # neighbor used by the isolated cEOS fixture.  Multi-hop routes need
        # explicit upstream route and physical-neighbor proof before support.
        if nmas_attachment.upstream_device != device.name:
            return [codes.blocker("L1_TOPOLOGY_UNVERIFIED", reason="routed path has no verified direct NMAS neighbor")]
        if attachment is not None or (via_device and via_device != device.name):
            return [codes.blocker("MGMT_PATH_ATTACHMENT_INVALID", reason="direct routed path cannot name an intermediate switch")]
        return []
    if attachment is None:
        return [codes.blocker("MGMT_PATH_ATTACHMENT_REQUIRED")]
    if attachment.device_id != device.pk or attachment.approval_state != models.AttachmentApproval.APPROVED \
            or attachment.purpose != models.AttachmentPurpose.MANAGEMENT:
        return [codes.blocker("MGMT_PATH_ATTACHMENT_INVALID", reason="not this device's approved MANAGEMENT attachment")]
    if via_device and attachment.upstream_device != via_device:
        return [codes.blocker("MGMT_PATH_ATTACHMENT_INVALID", reason="the attachment's upstream is not the path's switch")]
    if path_type == T.DIRECT_OOB and attachment.upstream_device != nmas_attachment.upstream_device:
        return [codes.blocker("MGMT_PATH_ATTACHMENT_INVALID", reason="out-of-band paths attach directly to NMAS's management switch")]
    if path_type == T.VLAN_ADJACENT_SWITCH:
        if attachment.upstream_device == nmas_attachment.upstream_device:
            return [codes.blocker("MGMT_PATH_ATTACHMENT_INVALID", reason="a direct attachment to the management switch is DIRECT_OOB")]
        if vlan != MANAGEMENT_VLAN or attachment.vlan != MANAGEMENT_VLAN:
            return [codes.blocker("MGMT_VLAN_INVALID")]
    if attachment.connectivity == models.AttachmentConnectivity.ROUTED:
        return [codes.blocker("MGMT_PATH_ATTACHMENT_INVALID", reason="a routed attachment carries no management VLAN")]
    return []


def register_path(device, *, path_type: str, endpoint_address: str, nmas_attachment_id, credential_source: str, actor: str,
                  credential_reference: str = "", device_credential_id=None, attachment_id=None, via_device: str = "",
                  remote_interface: str = "", vrf: str = "", vlan=None, transport: str = models.ManagementTransport.SSH, port=22,
                  expected_host_key: str = "", expected_topology: dict | None = None, policy: dict | None = None,
                  reason: str = "") -> Result:
    """Record one expected management path (PENDING approval).  Every refusal is recorded on the device's chain."""
    action = "MGMT_PATH_REGISTER"
    blockers = list(_device_scope_problems(device))
    if device.platform not in VERIFIED_PLATFORMS:
        blockers.append(codes.blocker("L2_PLATFORM_NOT_IMPLEMENTED", platform=device.platform))
    if path_type not in T.values:
        return _refuse_device(device, action, blockers + [codes.blocker("MGMT_PATH_TYPE_INVALID")], actor=actor)
    nmas_attachment = models.NmasManagementAttachment.objects.filter(pk=nmas_attachment_id).first() if nmas_attachment_id else None
    if nmas_attachment is None:
        blockers.append(codes.blocker("NMAS_ATTACHMENT_NOT_FOUND"))
    elif nmas_attachment.approval_state != Approval.APPROVED:
        blockers.append(codes.blocker("NMAS_ATTACHMENT_NOT_APPROVED"))
    attachment = models.DeviceAttachment.objects.filter(pk=attachment_id).first() if attachment_id else None
    via_device = str(via_device or "").strip() or (attachment.upstream_device if attachment else "")
    remote_interface = str(remote_interface or "").strip() or (attachment.upstream_interface if attachment else "")
    local_interface = attachment.local_interface if attachment else ""
    try:
        vlan = int(vlan) if vlan not in (None, "") else (attachment.vlan if attachment else None)
        port = int(port)
    except (TypeError, ValueError):
        blockers.append(codes.blocker("MGMT_VLAN_INVALID", reason="vlan / port not a number"))
        vlan, port = None, 22
    if not 1 <= port <= 65535:
        blockers.append(codes.blocker("MGMT_ENDPOINT_FORBIDDEN", reason="port out of range"))
    vrf = str(vrf or "").strip()
    if path_type == T.ROUTED_VRF and (not models.MGMT_VRF_NAME_RE.fullmatch(vrf) or vrf.lower() in RESERVED_VRF_NAMES):
        blockers.append(codes.blocker("MGMT_VRF_INVALID"))
    if path_type != T.ROUTED_VRF and vrf:
        blockers.append(codes.blocker("MGMT_VRF_INVALID", reason="only routed paths name a VRF"))
    if transport not in models.ManagementTransport.values:
        blockers.append(codes.blocker("MGMT_PATH_TYPE_INVALID", reason="transport"))
    elif transport != models.ManagementTransport.SSH:
        blockers.append(codes.blocker("MGMT_PATH_TYPE_INVALID", reason="only SSH paths have a verified consumer transport"))
    if remote_interface and not models.INTERFACE_RE.fullmatch(remote_interface):
        blockers.append(codes.blocker("INTERFACE_INVALID"))
    if nmas_attachment is not None and not blockers:
        blockers += _attachment_problems(device, path_type, attachment, nmas_attachment, via_device, vlan)
        if path_type in (T.DIRECT_OOB, T.VLAN_ADJACENT_SWITCH):
            blockers += _switch_problems(device.name, via_device)
        blockers += guard.address_problems(endpoint_address, network=nmas_attachment.network,
                                           layer2=path_type != T.ROUTED_VRF or nmas_attachment.upstream_device == device.name)
    credential = models.DeviceCredential.objects.filter(pk=device_credential_id).first() if device_credential_id else None
    credential_reference = str(credential_reference or "").strip()
    if credential_source == models.ManagementCredentialSource.INVENTORY and not credential_reference:
        credential_reference = device.name
    blockers += _credential_problems(device, credential_source, credential_reference, credential)
    host_key, problems = identity.normalize_host_key(expected_host_key)
    blockers += problems
    if not host_key and credential_source == models.ManagementCredentialSource.ZTP_ENROLLMENT:
        session = models.ZtpSession.objects.filter(pk=_ztp_pk(credential_reference), device=device).first()
        host_key = session.enrolled_host_key if session else ""
    host_key = host_key or device.verified_host_key
    if not host_key:
        blockers.append(codes.blocker("MGMT_HOST_KEY_REQUIRED"))
    elif device.verified_host_key and host_key != device.verified_host_key:
        blockers.append(codes.blocker("HOST_KEY_MISMATCH", reason="differs from the device's verified host key"))
    text, problems = identity.clean_text(reason, max_length=200)
    blockers += problems
    if blockers:
        return _refuse_device(device, action, blockers, actor=actor)
    topology = dict(expected_topology or {}) or {
        "hops": [hop for hop in ({"device": device.name, "interface": local_interface},
                                 {"device": via_device, "interface": remote_interface} if via_device else None,
                                 {"nmas": nmas_attachment.attachment_id, "upstream": nmas_attachment.upstream_device}) if hop],
        "vlan": vlan, "vrf": vrf}
    try:
        with transaction.atomic():
            if models.ManagementPath.objects.filter(LIVE_PATH, device=device, path_type=path_type, endpoint_address=endpoint_address,
                                                    via_device=via_device, vrf=vrf).exists():
                raise _Refused([codes.blocker("MGMT_PATH_DUPLICATE")])
            row = models.ManagementPath.objects.create(
                device=device, path_type=path_type, preference_class=models.MANAGEMENT_PATH_CLASS[T(path_type)], attachment=attachment,
                via_device=via_device, local_interface=local_interface, remote_interface=remote_interface, vlan=vlan,
                tagged=bool(attachment and attachment.connectivity == models.AttachmentConnectivity.TRUNK), vrf=vrf,
                endpoint_address=str(ipaddress.ip_address(endpoint_address)), transport=transport, port=port,
                credential_source=credential_source, credential_reference=credential_reference, device_credential=credential,
                expected_host_key=host_key, nmas_attachment=nmas_attachment, expected_topology=topology,
                policy={k: v for k, v in (policy or {}).items() if k in ("failure_threshold", "restore_threshold")},
                reason=text, created_by=actor[:150])
            event = events.record(device, action, Outcome.RECORDED, actor=actor, from_state=device.lifecycle_state,
                                  to_state=device.lifecycle_state, attachment=attachment, evidence={
                                      "path": row.path_id, "type": path_type, "class": row.preference_class, "endpoint": row.endpoint_address,
                                      "via": via_device, "vlan": vlan, "vrf": vrf, "nmas_attachment": nmas_attachment.attachment_id,
                                      "credential_source": credential_source})
    except _Refused as refusal:
        return _refuse_device(device, action, refusal.blockers, actor=actor)
    except IntegrityError:
        return _refuse_device(device, action, [codes.blocker("MGMT_PATH_DUPLICATE")], actor=actor)
    return Result(True, action, path=row, event=event)


def approve_path(path, *, actor: str) -> Result:
    action = "MGMT_PATH_APPROVE"
    device = path.device
    blockers = list(_device_scope_problems(device))
    if path.approval_state != Approval.PENDING:
        blockers.append(codes.blocker("MGMT_PATH_NOT_PENDING", state=path.approval_state))
    if actor == path.created_by:
        blockers.append(codes.blocker("MGMT_PATH_SELF_APPROVAL"))
    if path.nmas_attachment.approval_state != Approval.APPROVED:
        blockers.append(codes.blocker("NMAS_ATTACHMENT_NOT_APPROVED"))
    if path.attachment_id and path.attachment.approval_state != models.AttachmentApproval.APPROVED:
        blockers.append(codes.blocker("MGMT_PATH_ATTACHMENT_INVALID", reason="attachment no longer approved"))
    if blockers:
        return _refuse_device(device, action, blockers, actor=actor)
    with transaction.atomic():
        locked = models.ManagementPath.objects.select_for_update().get(pk=path.pk)
        if locked.approval_state != Approval.PENDING:
            return _refuse_device(device, action, [codes.blocker("MGMT_STATE_CONFLICT")], actor=actor)
        locked.approval_state, locked.approved_by, locked.approved_at = Approval.APPROVED, actor[:150], timezone.now()
        locked.save(update_fields=["approval_state", "approved_by", "approved_at", "updated_at"])
        event = events.record(device, action, Outcome.RECORDED, actor=actor, from_state=device.lifecycle_state,
                              to_state=device.lifecycle_state, evidence={"path": locked.path_id, "approval_state": Approval.APPROVED})
    return Result(True, action, path=locked, event=event)


def revoke_path(path, *, actor: str, reason: str, acknowledge_active: bool = False) -> Result:
    """Revoke a path.  The ACTIVE path is revoked only with an explicit acknowledgement; the selector then re-selects."""
    from . import selector

    action = "MGMT_PATH_REVOKE"
    device = path.device
    text, problems = identity.clean_text(reason, max_length=200)
    if problems or not text:
        return _refuse_device(device, action, problems or [codes.blocker("REASON_REQUIRED")], actor=actor)
    if path.approval_state == Approval.REVOKED:
        return _refuse_device(device, action, [codes.blocker("MGMT_PATH_REVOKED")], actor=actor)
    if path.is_active and not acknowledge_active:
        return _refuse_device(device, action, [codes.blocker("MGMT_PATH_ACTIVE")], actor=actor)
    with transaction.atomic():
        locked = models.ManagementPath.objects.select_for_update().get(pk=path.pk)
        if locked.approval_state == Approval.REVOKED:
            return _refuse_device(device, action, [codes.blocker("MGMT_PATH_REVOKED")], actor=actor)
        if locked.is_active and not acknowledge_active:
            return _refuse_device(device, action, [codes.blocker("MGMT_PATH_ACTIVE")], actor=actor)
        was_active = locked.is_active
        if was_active:
            selector.deactivate(locked, actor=actor, reason_code="MGMT_PATH_REVOKED")
            locked.refresh_from_db()
        locked.approval_state, locked.revoked_by, locked.revoked_at, locked.reason = Approval.REVOKED, actor[:150], timezone.now(), text
        locked.save(update_fields=["approval_state", "revoked_by", "revoked_at", "reason", "updated_at"])
        event = events.record(device, action, Outcome.RECORDED, actor=actor, from_state=device.lifecycle_state,
                              to_state=device.lifecycle_state, evidence={"path": locked.path_id, "was_active": was_active, "reason": text})
    return Result(True, action, path=locked, event=event)


# --- L1 topology ----------------------------------------------------------------------------------------------------------------
def _management_vlan_edges(device_name: str) -> list:
    """Approved + trust-verified MANAGEMENT attachments of ``device_name`` that carry the management VLAN (or are untagged
    access ports in it)."""
    return list(models.DeviceAttachment.objects.filter(
        device__name=device_name, device__lifecycle_state__in=[s for s in models.DeviceLifecycleState.values
                                                               if s not in models.DEVICE_LIFECYCLE_TERMINAL],
        purpose=models.AttachmentPurpose.MANAGEMENT, approval_state=models.AttachmentApproval.APPROVED,
        verification_state=models.AttachmentVerification.VERIFIED, vlan=MANAGEMENT_VLAN,
    ).exclude(connectivity=models.AttachmentConnectivity.ROUTED))


def vlan_chain(start: str, goal: str) -> list[str] | None:
    """Breadth-first search from switch ``start`` up its verified management-VLAN attachments to ``goal`` (NMAS's switch).
    -> the hop list, or None when no verified chain exists.  Bounded (``MAX_VLAN_HOPS``); cycles are ignored."""
    if start == goal:
        return [start]
    frontier, seen = [[start]], {start}
    while frontier:
        chain = frontier.pop(0)
        if len(chain) > MAX_VLAN_HOPS:
            continue
        for edge in _management_vlan_edges(chain[-1]):
            nxt = edge.upstream_device
            if nxt == goal:
                return chain + [nxt]
            if nxt not in seen:
                seen.add(nxt)
                frontier.append(chain + [nxt])
    return None


def topology_problems(path) -> list[dict]:
    """L1: the physical provenance of the path is approved, independently verified and continuous to NMAS."""
    problems = []
    nmas = path.nmas_attachment
    if nmas.approval_state != Approval.APPROVED:
        problems.append(codes.blocker("NMAS_ATTACHMENT_NOT_APPROVED"))
    elif nmas.verification_state != models.AttachmentVerification.VERIFIED:
        problems.append(codes.blocker("L1_NMAS_ATTACHMENT_DOWN", state=nmas.verification_state))
    if path.path_type == T.ROUTED_VRF:
        if nmas.upstream_device != path.device.name or path.attachment_id or (path.via_device and path.via_device != path.device.name):
            problems.append(codes.blocker("L1_TOPOLOGY_UNVERIFIED", reason="routed path has no verified direct NMAS neighbor"))
        problems.extend(guard.address_problems(path.endpoint_address, network=nmas.network, layer2=True))
        return problems
    attachment = path.attachment
    if attachment is None or attachment.approval_state != models.AttachmentApproval.APPROVED:
        problems.append(codes.blocker("L1_TOPOLOGY_UNVERIFIED", reason="attachment not approved"))
        return problems
    if attachment.verification_state != models.AttachmentVerification.VERIFIED:
        problems.append(codes.blocker("L1_TOPOLOGY_UNVERIFIED", reason=f"attachment {attachment.verification_state.lower()}"))
    if path.path_type == T.VLAN_ADJACENT_SWITCH and vlan_chain(path.via_device, nmas.upstream_device) is None:
        problems.append(codes.blocker("MGMT_VLAN_NOT_CONTINUOUS", switch=path.via_device, goal=nmas.upstream_device))
    return problems


def management_vlan_attachments(device) -> list:
    """Every approved MANAGEMENT attachment of ``device`` that places it in the management VLAN (used by the L2 loop check)."""
    return list(models.DeviceAttachment.objects.filter(device=device, purpose=models.AttachmentPurpose.MANAGEMENT,
                                                       approval_state=models.AttachmentApproval.APPROVED, vlan=MANAGEMENT_VLAN)
                .exclude(connectivity=models.AttachmentConnectivity.ROUTED))
