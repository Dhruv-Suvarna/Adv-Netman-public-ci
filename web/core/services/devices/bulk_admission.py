"""Bulk admission of the pre-existing srlceos01 managed topology (nine devices) as ONE tracked, restart-safe batch.

Every governed step goes through the existing NMAS services -- nothing here writes approval state directly:

  EVIDENCE    host-key evidence from an independent device-side channel (cEOS console ``show management ssh hostkey``;
              Linux: the container host administrator reading ``/etc/ssh/ssh_host_ed25519_key.pub``), cross-checked against
              the key the device presents on the network, validated by ``host_key_pins.validate_evidence`` with ``dhruv`` as
              enroller (the collector is the labelled automated console capture, never a person).
  ADOPT       ``lifecycle.adopt_existing`` (LEGACY_ADOPTION; existing devices are adopted, never ZTP'd).
  ATTACH      ``attachments.register_attachment`` (requester ``dhruv``) + a TRUSTED_UPSTREAM_INTERFACE observation from the
              live topology service edge (gNMI state of both ends of the tracked Containerlab cable) recorded by
              ``source:nmas-topology``, exactly as R2/S2 were admitted.
  CREDENTIAL  a dedicated ``nmas-diag`` account per device (``modules.diagnostic_accounts``) + its DeviceCredential metadata
              row, and a live RBAC proof (read works; configuration / shell refused by the device or the broker).
  PATH        ``paths.register_path`` (requester ``dhruv``).  cEOS: before identity; FRR: after its legacy-route identity
              observation (an FRR device with a registered path is no longer reachable on the legacy route).
  APPROVE     inside ONE owner-authorized single-admin exception window (``single_admin_exception``; <= 30 min, <= 16 uses,
              exact targets, ``separation_of_duties_satisfied=false`` on every use): attachment approvals, one observation
              authorization for all newly admitted devices, path approvals.  The exception is revoked at the end.
  ACTIVATE    ``selector.evaluate`` probes every approved path layer by layer and activates it.
  IDENTITY    ``device_observe`` under the observation authorization (signed observer source), then
              ``lifecycle.verify_identity`` by ``dhruv`` -- independent of the automated recorder.

The checkpoint file (``<evidence>/state.json``) records each device's completed phases, codes and evidence references; a
re-run resumes, and every phase is itself idempotent.  A device that fails a phase stays exactly as restricted as the
phase left it, and the batch result says so -- a failure is never reported as success.
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import subprocess
from contextlib import redirect_stdout
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from django.db import transaction
from django.utils import timezone as dj_timezone

from ... import models

SCHEMA = "nmas.bulk-admission/1"
LAB = "srlceos01"
ACTOR = "dhruv"
TOPOLOGY_ACTOR = "source:nmas-topology"
COLLECTOR = "nmas-bulk-admission-console"
NMA_ID = 1
MANAGEMENT_VLAN = 200
TOPOLOGY_API = "http://127.0.0.1:8811/api/topology/"
OBSERVATION_EVIDENCE_DIR = Path("/home/student/Scripts/nmas-evidence/device-observations")


@dataclass(frozen=True)
class Member:
    name: str
    platform: str            # models.Platform value
    role: str
    address: str
    upstream_interface: str  # mgmt_swt port ("" for mgmt_swt itself)
    local_interface: str     # device-side port ("" for mgmt_swt itself)
    edge_id: str             # topology service edge id ("" for mgmt_swt)

    @property
    def frr(self) -> bool:
        return self.platform == models.Platform.UBUNTU_FRR

    @property
    def self_switch(self) -> bool:
        return not self.upstream_interface


CEOS, FRR = models.Platform.ARISTA_CEOS.value, models.Platform.UBUNTU_FRR.value
MEMBERS = (
    Member("R1", CEOS, "router", "192.168.200.1", "Ethernet1", "Ethernet3", "R1:eth3--mgmt_swt:eth1"),
    Member("R2", CEOS, "router", "192.168.200.2", "Ethernet2", "Ethernet3", "R2:eth3--mgmt_swt:eth2"),
    Member("R3", FRR, "router", "192.168.200.3", "Ethernet3", "eth3", "R3:eth3--mgmt_swt:eth3"),
    Member("R4", FRR, "router", "192.168.200.4", "Ethernet4", "eth3", "R4:eth3--mgmt_swt:eth4"),
    Member("S1", CEOS, "switch", "192.168.200.11", "Ethernet5", "Ethernet5", "S1:eth5--mgmt_swt:eth5"),
    Member("S2", CEOS, "switch", "192.168.200.12", "Ethernet6", "Ethernet5", "S2:eth5--mgmt_swt:eth6"),
    Member("S3", CEOS, "switch", "192.168.200.13", "Ethernet7", "Ethernet4", "S3:eth4--mgmt_swt:eth7"),
    Member("S4", CEOS, "switch", "192.168.200.14", "Ethernet8", "Ethernet4", "S4:eth4--mgmt_swt:eth8"),
    Member("mgmt_swt", CEOS, "switch", "192.168.200.10", "", "", ""),
)
BY_NAME = {m.name: m for m in MEMBERS}


# --------------------------------------------------------------------------------------------------------------- checkpoint
@dataclass
class Batch:
    root: Path
    state: dict = field(default_factory=dict)

    @classmethod
    def open(cls, root: str | Path) -> "Batch":
        root = Path(root)
        root.mkdir(mode=0o700, parents=True, exist_ok=True)
        path = root / "state.json"
        state = json.loads(path.read_text(encoding="utf-8")) if path.exists() else {
            "schema": SCHEMA, "lab": LAB, "devices": {m.name: {"phases": {}} for m in MEMBERS}, "log": []}
        return cls(root, state)

    def save(self) -> None:
        path = self.root / "state.json"
        tmp = path.with_suffix(".tmp")
        tmp.write_text(json.dumps(self.state, indent=1, sort_keys=True, default=str), encoding="utf-8")
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)

    def done(self, device: str, phase: str) -> bool:
        return (self.state["devices"][device]["phases"].get(phase) or {}).get("status") == "DONE"

    def mark(self, device: str, phase: str, status: str, **data) -> dict:
        row = {"status": status, "at": datetime.now(timezone.utc).isoformat(), **data}
        self.state["devices"][device]["phases"][phase] = row
        self.state["log"].append({"device": device, "phase": phase, "status": status, "at": row["at"],
                                  "codes": data.get("codes", [])})
        self.save()
        return row

    def evidence(self, name: str, document: dict) -> str:
        data = json.dumps(document, indent=1, sort_keys=True, default=str).encode()
        path = self.root / name
        path.write_bytes(data)
        os.chmod(path, 0o600)
        return f"local-unattested:{path.name}#sha256={hashlib.sha256(data).hexdigest()}"


def _device(name: str):
    from . import identity

    return models.ManagedDevice.objects.filter(identity.LIVE, name=name).order_by("-pk").first()


def _run(argv: list[str], timeout: int = 30) -> subprocess.CompletedProcess:
    return subprocess.run(argv, capture_output=True, text=True, timeout=timeout, check=False)


# ----------------------------------------------------------------------------------------------------------------- EVIDENCE
def console_public_key(member: Member) -> str:
    container = f"clab-{LAB}-{member.name}"
    if member.frr:
        out = _run(["docker", "exec", container, "cat", "/etc/ssh/ssh_host_ed25519_key.pub"]).stdout
    else:
        out = _run(["docker", "exec", container, "Cli", "-p", "15", "-c", "show management ssh hostkey ed25519 public"]).stdout
    parts = out.strip().split()
    return f"{parts[0]} {parts[1]}" if len(parts) >= 2 and parts[0] == "ssh-ed25519" else ""


def network_public_key(member: Member) -> str:
    out = _run(["ssh-keyscan", "-T", "5", "-t", "ed25519", member.address]).stdout
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 3 and parts[0] == member.address and parts[1] == "ssh-ed25519":
            return f"{parts[1]} {parts[2]}"
    return ""


def phase_evidence(batch: Batch, member: Member) -> dict:
    from . import host_key_pins

    console, network = console_public_key(member), network_public_key(member)
    document = {"schema": host_key_pins.SCHEMA, "device": member.name, "platform": member.platform,
                "channel": "CONTAINER_HOST_ADMIN" if member.frr else "DEVICE_CONSOLE", "captured_by": COLLECTOR,
                "captured_at": dj_timezone.now().isoformat(), "public_key": console}
    verdict = host_key_pins.validate_evidence(document, enroller=ACTOR)
    network_pin, _t = host_key_pins.fingerprint(network)
    codes = list(verdict.codes)
    if verdict.ok and network_pin != verdict.pin:
        codes.append("CROSS_CHANNEL_MISMATCH")
    if verdict.registered.get("conflict"):
        codes.append("REGISTERED_PIN_CONFLICT")
    ref = batch.evidence(f"hostkey-{member.name}.json", {"capture": document, "network_handshake_key": network,
                                                          "network_pin": network_pin, "verdict": verdict.__dict__,
                                                          "evidence_digest": verdict.evidence_digest})
    return batch.mark(member.name, "EVIDENCE", "DONE" if not codes else "FAILED", pin=verdict.pin if not codes else "",
                      evidence_ref=ref, evidence_digest=verdict.evidence_digest, registered=verdict.registered, codes=codes)


# -------------------------------------------------------------------------------------------------------------------- ADOPT
def phase_adopt(batch: Batch, member: Member) -> dict:
    from . import lifecycle

    device = _device(member.name)
    if device is not None:
        return batch.mark(member.name, "ADOPT", "DONE", device_id=device.device_id, changed=False)
    result = lifecycle.adopt_existing(member.name, role=member.role, actor=ACTOR)
    if not result.ok:
        return batch.mark(member.name, "ADOPT", "FAILED", codes=result.codes)
    return batch.mark(member.name, "ADOPT", "DONE", device_id=result.device.device_id, changed=result.changed)


# ------------------------------------------------------------------------------------------------------------------- ATTACH
def topology_edge(edge_id: str) -> dict | None:
    import urllib.request

    with urllib.request.urlopen(TOPOLOGY_API, timeout=15) as handle:     # noqa: S310 - fixed loopback URL
        doc = json.loads(handle.read().decode())
    edge = next((e for e in (doc.get("graph") or {}).get("edges") or doc.get("graph", {}).get("links") or []
                 if e.get("id") == edge_id), None)
    return {"edge": edge, "backend": doc.get("backend"), "generated_at": doc.get("generated_at")} if edge else None


def phase_attach(batch: Batch, member: Member) -> dict:
    from . import attachments, lifecycle

    if member.self_switch:
        return batch.mark(member.name, "ATTACH", "DONE", attachment=None,
                          note="NMAS's own management switch: its L1 provenance is the approved, VERIFIED NMA-000001")
    device = _device(member.name)
    row = models.DeviceAttachment.objects.filter(device=device, upstream_device="mgmt_swt",
                                                 upstream_interface=member.upstream_interface).exclude(
        approval_state=models.AttachmentApproval.REVOKED).first()
    if row is None:
        result = attachments.register_attachment(
            device, upstream_device="mgmt_swt", upstream_interface=member.upstream_interface, purpose=models.AttachmentPurpose.MANAGEMENT,
            connectivity=models.AttachmentConnectivity.ACCESS, actor=ACTOR, local_interface=member.local_interface, vlan=MANAGEMENT_VLAN)
        if not result.ok:
            return batch.mark(member.name, "ATTACH", "FAILED", codes=result.codes)
        row = result.attachment
    observation = models.DeviceObservation.objects.filter(
        device=device, attachment=row, kind=models.ObservationKind.ATTACHMENT, source=models.ObservationSource.TRUSTED_UPSTREAM_INTERFACE,
        trust=models.ObservationTrust.OBSERVED, result=models.ObservationResult.MATCH).order_by("-pk").first()
    if observation is None:
        captured = topology_edge(member.edge_id)
        edge = (captured or {}).get("edge") or {}
        states = edge.get("endpoint_state") or []
        fresh_up = len(states) == 2 and all(s.get("evidence_fresh") and s.get("admin_status") == "UP" and s.get("oper_status") == "UP"
                                             for s in states)
        if not (captured and edge.get("status") == "UP" and fresh_up and edge.get("plane") == "management"):
            return batch.mark(member.name, "ATTACH", "FAILED", attachment=row.pk, codes=["TOPOLOGY_EDGE_NOT_VERIFIED_UP"])
        ref = batch.evidence(f"attachment-{member.name}.json", {"record": {**captured, "device": member.name,
                                                                           "purpose": "trusted upstream management-attachment observation"},
                                                                "storage": "local-unattested (not gateway attestation)"})
        result = lifecycle.record_observation(
            device, kind=models.ObservationKind.ATTACHMENT, source=models.ObservationSource.TRUSTED_UPSTREAM_INTERFACE,
            actor=TOPOLOGY_ACTOR, upstream_device="mgmt_swt", upstream_interface=member.upstream_interface,
            local_interface=member.local_interface)
        if not result.ok:
            return batch.mark(member.name, "ATTACH", "FAILED", attachment=row.pk, codes=result.codes)
        observation = result.observation
        row.refresh_from_db()
        sha = ref.rsplit("=", 1)[1]
    else:
        sha = (batch.state["devices"][member.name]["phases"].get("ATTACH") or {}).get("evidence_sha256", "")
    ok = observation.result == models.ObservationResult.MATCH and row.verification_state == models.AttachmentVerification.VERIFIED
    return batch.mark(member.name, "ATTACH", "DONE" if ok else "FAILED", attachment=row.pk, observation=observation.pk,
                      evidence_sha256=sha, approval_state=row.approval_state, verification_state=row.verification_state,
                      codes=[] if ok else ["ATTACHMENT_NOT_VERIFIED"])


# --------------------------------------------------------------------------------------------------------------- CREDENTIAL
def phase_credential(batch: Batch, member: Member, *, broker_commands=None) -> dict:
    from modules import diagnostic_accounts as da

    from ..credentials import linux_mfa
    from ..troubleshooting.diagnostic_worker import LINUX_DIAG_ROLE, broker_allowlist

    pin = (batch.state["devices"][member.name]["phases"].get("EVIDENCE") or {}).get("pin")
    if not pin:
        return batch.mark(member.name, "CREDENTIAL", "FAILED", codes=["NO_VERIFIED_HOST_KEY"])
    changed: list = []
    if member.frr:
        public, created = da.ensure_keypair(member.name)
        target = linux_mfa.target_for(member.name)
        changed = da.apply_frr(member.name, public, broker_commands or broker_allowlist(),
                               dropin=linux_mfa.sshd_dropin(target), expected_previous_dropin=linux_mfa.sshd_dropin(target, include_diagnostic=False))
        verification = da.verify_frr(member.name, member.address, pin=pin, pkey=da.load_pkey(member.name))
        from .host_key_pins import fingerprint
        defaults = {"platform": member.platform, "account_kind": models.AccountKind.SERVICE, "auth_method": models.DeviceAuthMethod.PUBLICKEY,
                    "secret_ref": "", "ssh_key_ref": da.key_ref(member.name), "ssh_public_key": public,
                    "ssh_public_key_fingerprint": fingerprint(public)[0], "account_role": LINUX_DIAG_ROLE, "privilege_level": None}
    else:
        password, created = da.ensure_password(member.name)
        probe = da.verify_ceos(member.name, member.address, pin=pin, password=password)
        if not probe.login:                          # absent (or not yet this secret): apply the IaC template, then prove it
            da.apply_ceos(member.name, password)
            changed.append("eos_account")
            probe = da.verify_ceos(member.name, member.address, pin=pin, password=password)
        verification = probe
        if probe.passed:                              # enable has no secret on these devices: authorization must still refuse config
            escalation = da.verify_ceos_escalation(member.name, member.address, pin=pin, password=password)
            verification.details["escalation"] = escalation
            verification.write_denied = verification.write_denied and escalation["passed"]
        password = ""
        defaults = {"platform": member.platform, "account_kind": models.AccountKind.SERVICE, "auth_method": models.DeviceAuthMethod.PASSWORD,
                    "secret_ref": da.secret_ref(member.name), "ssh_key_ref": "", "account_role": "network-operator", "privilege_level": 1}
    if not verification.passed:
        return batch.mark(member.name, "CREDENTIAL", "FAILED", verification=verification.as_dict(), changed=changed,
                          codes=["DIAGNOSTIC_RBAC_NOT_PROVEN"])
    with transaction.atomic():
        row, _ = models.DeviceCredential.objects.update_or_create(
            device_name=member.name, username=da.USERNAME,
            defaults={**defaults, "rotation_enabled": False, "last_status": "SUCCESS",
                      "last_result_code": "OWNER_AUTHORIZED_BULK_DIAGNOSTIC_ADMISSION"})
    return batch.mark(member.name, "CREDENTIAL", "DONE", credential_id=row.pk, created_secret=created, changed=changed,
                      verification=verification.as_dict())


# --------------------------------------------------------------------------------------------------------------------- PATH
def phase_path(batch: Batch, member: Member) -> dict:
    from ..management import paths

    device = _device(member.name)
    existing = models.ManagementPath.objects.filter(device=device, endpoint_address=member.address).exclude(
        approval_state=models.ManagementApproval.REVOKED).first()
    if existing is not None:
        return batch.mark(member.name, "PATH", "DONE", path=existing.path_id, approval_state=existing.approval_state)
    pin = (batch.state["devices"][member.name]["phases"].get("EVIDENCE") or {}).get("pin", "")
    attachment = (batch.state["devices"][member.name]["phases"].get("ATTACH") or {}).get("attachment")
    if member.frr:
        credential = models.DeviceCredential.objects.filter(device_name=member.name, username="nmas-diag").first()
        source = {"credential_source": models.ManagementCredentialSource.DEVICE_CREDENTIAL,
                  "device_credential_id": credential.pk if credential else None}
    else:
        source = {"credential_source": models.ManagementCredentialSource.INVENTORY, "credential_reference": member.name}
    result = paths.register_path(
        device, path_type=models.ManagementPathType.DIRECT_OOB, endpoint_address=member.address, nmas_attachment_id=NMA_ID,
        actor=ACTOR, attachment_id=attachment, vlan=MANAGEMENT_VLAN, expected_host_key=pin,
        reason=f"Owner-authorized bulk admission of the {LAB} managed topology (read-only diagnostics)", **source)
    if not result.ok:
        return batch.mark(member.name, "PATH", "FAILED", codes=result.codes)
    return batch.mark(member.name, "PATH", "DONE", path=result.path.path_id, approval_state=result.path.approval_state)


# ---------------------------------------------------------------------------------------------- the exception document
def exception_document(batch: Batch, *, minutes: int = 25, issued_at: datetime | None = None, grant: bool = True) -> dict:
    """The exact-target scope for the single bulk window.  Targets are only the PENDING records this batch created."""
    issued = issued_at or dj_timezone.now()
    attachments, sha, path_targets, devices = {}, {}, [], []
    for member in MEMBERS:
        phases = batch.state["devices"][member.name]["phases"]
        device = _device(member.name)
        att = (phases.get("ATTACH") or {}).get("attachment")
        if att and models.DeviceAttachment.objects.filter(pk=att, approval_state=models.AttachmentApproval.PENDING).exists():
            target = f"{device.device_id}:{att}"
            attachments[target] = phases["ATTACH"]["observation"]
            sha[target] = phases["ATTACH"].get("evidence_sha256", "")
        path_ids = [p for p in models.ManagementPath.objects.filter(device=device, approval_state=models.ManagementApproval.PENDING)
                    .values_list("pk", flat=True)] if device else []
        path_targets += [f"MPATH-{pk:06d}" for pk in path_ids]
        if device is not None and device.identity_state != models.IdentityVerificationState.VERIFIED:
            devices.append(member.name)
    # Window A covers attachments, the observation grant and the PENDING (cEOS) paths; window B exists only for the FRR paths,
    # which can be registered only after their legacy-route identity observation (made under window A's grant).
    scope = {}
    if attachments:
        scope["ATTACHMENT_APPROVE"] = sorted(attachments)
    if devices and grant:
        scope["OBSERVATION_AUTHORIZATION_GRANT"] = [f"{batch.state.get('ticket')}|{','.join(sorted(devices))}|nos-version"]
    if path_targets:
        scope["MGMT_PATH_APPROVE"] = sorted(path_targets)
    return {"scope": scope, "path_targets": sorted(path_targets), "attachment_observations": attachments,
            "attachment_evidence_sha256s": sha, "devices": sorted(devices), "issued_at": issued.isoformat(),
            "expires_at": (issued + dj_timezone.timedelta(minutes=minutes)).isoformat()}


def matrix(batch: Batch) -> list[dict]:
    rows = []
    for member in MEMBERS:
        device = _device(member.name)
        path = (models.ManagementPath.objects.filter(device=device).exclude(approval_state=models.ManagementApproval.REVOKED)
                .order_by("-pk").first()) if device else None
        cred = models.DeviceCredential.objects.filter(device_name=member.name, username="nmas-diag").first()
        att = models.DeviceAttachment.objects.filter(device=device, purpose=models.AttachmentPurpose.MANAGEMENT).exclude(
            approval_state=models.AttachmentApproval.REVOKED).first() if device else None
        rows.append({
            "device": member.name, "platform": member.platform, "address": member.address,
            "device_id": device.device_id if device else "", "identity": device.identity_state if device else "UNREGISTERED",
            "verified_host_key": device.verified_host_key if device else "",
            "attachment": (f"{att.upstream_device}:{att.upstream_interface} {att.approval_state}/{att.verification_state}"
                           if att else ("self (NMA-000001)" if member.self_switch else "none")),
            "path": path.path_id if path else "", "path_state": (f"{path.approval_state}/{'ACTIVE' if path.is_active else 'inactive'}/"
                                                                f"{path.health_state}" if path else ""),
            "diag_credential": f"{cred.account_role}/{cred.auth_method}" if cred else "",
            "phases": {k: v.get("status") for k, v in batch.state["devices"][member.name]["phases"].items()},
        })
    return rows


def admitted(row: dict) -> bool:
    return row["identity"] == "VERIFIED" and row["path_state"] == "APPROVED/ACTIVE/HEALTHY" and bool(row["diag_credential"]) \
        and row["phases"].get("CREDENTIAL") == "DONE"


# ----------------------------------------------------------------------------------------------------- IDENTITY + ACTIVATE
def activate(batch: Batch, member: Member) -> dict:
    from ..management import selector

    device = _device(member.name)
    evaluation = selector.evaluate(device, actor="nmas-bulk-admission", purpose=models.ProbePurpose.VERIFY)
    path = models.ManagementPath.objects.filter(device=device, approval_state=models.ManagementApproval.APPROVED).order_by("-pk").first()
    ok = bool(path and path.is_active and path.health_state == models.ManagementPathHealth.HEALTHY)
    return batch.mark(member.name, "ACTIVATE", "DONE" if ok else "FAILED", path=path.path_id if path else "",
                      health=path.health_state if path else "", failure=path.last_failure_code if path else "",
                      layer=path.last_layer_passed if path else None, decision=str(getattr(evaluation, "decision", ""))[:80],
                      codes=[] if ok else [(path.last_failure_code if path else "") or "PATH_NOT_ACTIVE"])


def observe_identity(batch: Batch, member: Member, *, authorization_ref: str, source_id: str, evidence_dir: str) -> dict:
    from django.core.management import call_command

    from . import lifecycle

    device = _device(member.name)
    if device.identity_state == models.IdentityVerificationState.VERIFIED:
        return batch.mark(member.name, "IDENTITY", "DONE", changed=False, verified_host_key=device.verified_host_key)
    out = io.StringIO()
    try:
        with redirect_stdout(out):
            call_command("device_observe", device=member.name, source=source_id, authorization_ref=authorization_ref,
                         operator=ACTOR, evidence_dir=evidence_dir, stdout=out)
    except Exception as exc:  # pylint: disable=broad-exception-caught  # noqa: BLE001 - CommandError text carries only stable codes
        return batch.mark(member.name, "IDENTITY", "FAILED", codes=[str(exc)[:200]])
    observation = models.DeviceObservation.objects.filter(
        device=device, kind=models.ObservationKind.IDENTITY, source=models.ObservationSource.AUTHENTICATED_SESSION).order_by("-pk").first()
    pin = (batch.state["devices"][member.name]["phases"].get("EVIDENCE") or {}).get("pin")
    if observation is None or (observation.claims or {}).get("host_key") != pin:
        return batch.mark(member.name, "IDENTITY", "FAILED", codes=["OBSERVED_HOST_KEY_NOT_THE_EVIDENCE_PIN"])
    result = lifecycle.verify_identity(device, observation.pk, actor=ACTOR)
    if not result.ok:
        return batch.mark(member.name, "IDENTITY", "FAILED", observation=observation.pk, codes=result.codes)
    return batch.mark(member.name, "IDENTITY", "DONE", observation=observation.pk, verified_host_key=result.device.verified_host_key,
                      observed=out.getvalue().strip()[:200])
