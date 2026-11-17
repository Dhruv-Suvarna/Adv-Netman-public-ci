"""Standalone, typed diagnostic worker for admitted NMAS devices.

Requests never contain an address or command.  The worker independently reads
the active management path and authoritative target snapshot, authorizes a
fixed command-catalog operation, revalidates both immediately before opening
the connection, and obtains credentials transiently through the existing NMAS
credential broker.
"""

from __future__ import annotations

import hashlib
import grp
import os
import re
import secrets
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable

from . import collectors
from .target_policy import Capability, Principal, PrincipalKind, TargetRequest
from .worker_ipc import IpcRefused, ServerConfig, UnixWorkerClient, UnixWorkerServer, load_key

DIAGNOSTIC_SCHEMA = "nmas.troubleshooting.diagnostic-request/1"
DIAGNOSTIC_RESULT_SCHEMA = "nmas.troubleshooting.diagnostic-result/1"
_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_AUTH = re.compile(r"^handoff:[A-Za-z0-9][A-Za-z0-9_.:-]{1,127}$")
_PAYLOAD_FIELDS = frozenset({"schema", "topology_id", "tenant", "agent", "authorization_ref",
                             "authorization_expires_at", "device", "operation_id", "params"})
MAX_OUTPUT_BYTES = 512 * 1024


def _parse_time(value: Any) -> datetime:
    if not isinstance(value, str) or len(value) > 40:
        raise IpcRefused("INVALID_AUTHORIZATION")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise IpcRefused("INVALID_AUTHORIZATION") from exc
    if parsed.tzinfo is None:
        raise IpcRefused("INVALID_AUTHORIZATION")
    return parsed.astimezone(timezone.utc)


@dataclass(frozen=True)
class DiagnosticRequest:
    topology_id: str
    tenant: str
    agent: str
    authorization_ref: str
    authorization_expires_at: datetime
    device: str
    operation_id: str
    params: dict

    @classmethod
    def parse(cls, envelope: dict) -> "DiagnosticRequest":
        value = envelope.get("payload")
        if not isinstance(value, dict) or set(value) != _PAYLOAD_FIELDS or value.get("schema") != DIAGNOSTIC_SCHEMA:
            raise IpcRefused("INVALID_DIAGNOSTIC_REQUEST")
        strings = ("topology_id", "tenant", "agent", "device", "operation_id")
        if any(not isinstance(value.get(key), str) or not _NAME.fullmatch(value[key]) for key in strings):
            raise IpcRefused("INVALID_DIAGNOSTIC_REQUEST")
        if envelope.get("principal") != value["agent"]:
            raise IpcRefused("PRINCIPAL_MISMATCH")
        if not isinstance(value.get("authorization_ref"), str) or not _AUTH.fullmatch(value["authorization_ref"]):
            raise IpcRefused("INVALID_AUTHORIZATION")
        params = value.get("params")
        if not isinstance(params, dict) or len(params) > 8 or any(not isinstance(k, str) or len(k) > 32 for k in params):
            raise IpcRefused("INVALID_OPERATION_PARAMETERS")
        return cls(topology_id=value["topology_id"], tenant=value["tenant"], agent=value["agent"],
                   authorization_ref=value["authorization_ref"],
                   authorization_expires_at=_parse_time(value["authorization_expires_at"]),
                   device=value["device"], operation_id=value["operation_id"], params=dict(params))


def _active_path(device: str):
    """Resolve the exact healthy active path without a legacy-address fallback."""
    from core import models
    from core.services.management import guard, resolve

    selected = resolve.endpoint(device, purpose=resolve.READ)
    if selected.source != resolve.PATH or not selected.path_id.startswith("MPATH-"):
        raise IpcRefused("NO_APPROVED_MANAGEMENT_PATH")
    try:
        pk = int(selected.path_id.removeprefix("MPATH-"))
    except ValueError as exc:
        raise IpcRefused("NO_APPROVED_MANAGEMENT_PATH") from exc
    path = (models.ManagementPath.objects.select_related("device", "nmas_attachment", "device_credential")
            .filter(pk=pk, device__name=device).first())
    stored, problems = guard.authorized_target(path)
    if path is None or stored is None or problems or stored.path_id != selected.path_id:
        raise IpcRefused("MANAGEMENT_PATH_CHANGED")
    if not stored.is_active or stored.health_state != models.ManagementPathHealth.HEALTHY:
        raise IpcRefused("MANAGEMENT_PATH_NOT_HEALTHY")
    if stored.transport != models.ManagementTransport.SSH or not stored.expected_host_key:
        raise IpcRefused("PINNED_SSH_PATH_REQUIRED")
    if stored.endpoint_address != selected.address or stored.port != selected.port:
        raise IpcRefused("MANAGEMENT_PATH_CHANGED")
    return stored


def _operation(path, request: DiagnosticRequest):
    key = request.operation_id.removeprefix("cli:") if request.operation_id.startswith("cli:") else ""
    spec = collectors.COMMAND_CATALOG.get(collectors.nz.canonical_platform(path.device.platform), {}).get(key)
    if spec is None or spec.kind == "config" or request.operation_id != f"cli:{spec.key}":
        raise IpcRefused("OPERATION_NOT_REGISTERED")
    try:
        rendered = collectors.render_command(spec, request.params)
    except collectors.CommandNotAllowed as exc:
        raise IpcRefused("INVALID_OPERATION_PARAMETERS", type(exc).__name__) from exc
    if not isinstance(rendered, str):
        # Current approved ManagementPath session verification supports cEOS
        # only.  Linux argv execution is intentionally not converted to a
        # remote shell string.
        raise IpcRefused("PLATFORM_TRANSPORT_NOT_SUPPORTED")
    return spec, rendered


def _worker_bind(path) -> tuple[str, str]:
    """Source binding for the isolated worker.

    The worker runs in its own network namespace, where the host attachment
    (e.g. 192.168.200.100 on nmas-mgmt) does not exist; the host SNATs the
    namespace link to that address under the approved nft policy.  When the
    deployment declares the namespace egress, bind there; otherwise keep the
    attachment binding (in-host transport, unchanged behaviour)."""
    source = os.environ.get("NMAS_TS_DIAGNOSTIC_BIND_SOURCE", "").strip()
    interface = os.environ.get("NMAS_TS_DIAGNOSTIC_BIND_INTERFACE", "").strip()
    if source and interface:
        return source, interface
    if source or interface:
        raise IpcRefused("WORKER_BIND_MISCONFIGURED")
    return path.nmas_attachment.source_address, path.nmas_attachment.host_interface


class NmasSshExecutor:
    """Existing pinned/source-bound transport plus brokered credentials."""

    def execute(self, *, path, command: str, revalidate: Callable[[], None]) -> tuple[str, dict]:
        from core.services.management import policy, probes

        revalidate()
        # Re-read once more after policy authorization.  The guard rejects an
        # in-memory endpoint/path substitution and the resolver rejects a
        # replaced active path.
        current = _active_path(path.device.name)
        if current.pk != path.pk or current.version != path.version:
            raise IpcRefused("MANAGEMENT_PATH_CHANGED")
        try:
            username, methods = _diagnostic_auth_material(current)
        except probes.CredentialUnavailable as exc:
            raise IpcRefused("CREDENTIAL_BROKER_UNAVAILABLE", type(exc).__name__) from exc
        report = probes.ProbeReport(path_id=current.path_id)
        limits = policy.effective(current)
        try:
            revalidate()
            output = probes.ParamikoTransport().run(
                source=_worker_bind(current)[0],
                interface=_worker_bind(current)[1],
                address=current.endpoint_address,
                port=current.port,
                timeout=limits.probe_timeout_seconds,
                expected_host_key=current.expected_host_key,
                username=username,
                methods=methods,
                commands=(command,),
                report=report,
            ).get(command, "")
        except probes.ProbeFailure as exc:
            raise IpcRefused("DIAGNOSTIC_TRANSPORT_FAILED", exc.code) from exc
        finally:
            methods.clear()
        raw = str(output)
        size = len(raw.encode("utf-8", "replace"))
        if size > MAX_OUTPUT_BYTES:
            raise IpcRefused("OUTPUT_TOO_LARGE")
        endpoint_hash = hashlib.sha256(f"{current.endpoint_address}:{current.port}".encode()).hexdigest()[:24]
        return raw, {"path_id": current.path_id, "path_version": current.version, "endpoint_hash": endpoint_hash,
                     "host_key_verified": bool(report.presented_host_key), "bytes": size}


def _diagnostic_auth_material(path, *, credential_lookup=None, provider=None) -> tuple[str, list[dict]]:
    """Resolve a device's dedicated read-only diagnostic identity when one is enrolled.

    The approved ManagementPath remains the endpoint/identity authority.  A
    ``nmas-diag`` row may narrow only the SSH login used by this isolated
    worker; it cannot change the path, endpoint, host-key pin, target policy or
    command catalogue.  If no dedicated row exists, the existing path
    credential behavior is preserved (currently R2).  If a row exists but is
    not the exact least-privileged contract, fail closed rather than falling
    back to a write-capable credential.
    """
    from core import models
    from core.services.management import probes
    from modules.device_credentials import FileSecretProvider, SecretProviderError

    lookup = credential_lookup or (
        lambda device: models.DeviceCredential.objects.filter(device_name=device, username="nmas-diag").first()
    )
    credential = lookup(path.device.name)
    if credential is None:
        return probes.auth_material(path)
    valid = (
        credential.account_kind == models.AccountKind.SERVICE
        and credential.auth_method == models.DeviceAuthMethod.PASSWORD
        and credential.account_role == "network-operator"
        and credential.privilege_level == 1
        and credential.secret_ref == f"runtime://device-credentials/{path.device.name.lower()}-nmas-diag"
        and not credential.ssh_key_ref
    )
    if not valid:
        raise probes.CredentialUnavailable("dedicated diagnostic credential metadata is invalid")
    try:
        source = provider or FileSecretProvider()
        methods = [{"password": item.value} for item in source.candidates(credential.secret_ref)]
    except (SecretProviderError, OSError, ValueError) as exc:
        raise probes.CredentialUnavailable(type(exc).__name__) from None
    if not methods:
        raise probes.CredentialUnavailable("dedicated diagnostic credential material is absent")
    return credential.username, methods


class DiagnosticHandler:
    def __init__(self, *, policy_factory: Callable[[], Any] | None = None, executor: Any = None):
        self.policy_factory = policy_factory or self._policy
        self.executor = executor or NmasSshExecutor()

    @staticmethod
    def _policy():
        from .adapters.nmas_providers import target_policy
        return target_policy()

    def __call__(self, envelope: dict) -> dict:
        request = DiagnosticRequest.parse(envelope)
        path = _active_path(request.device)
        spec, command = _operation(path, request)
        policy = self.policy_factory()
        principal = Principal(request.agent, PrincipalKind.TROUBLESHOOTER_AGENT,
                              frozenset({Capability.READ_DIAGNOSTIC}), tenant=request.tenant)
        target_request = TargetRequest(
            principal=principal, capability=Capability.READ_DIAGNOSTIC,
            topology_id=request.topology_id, device=request.device,
            endpoint=path.endpoint_address, port=path.port, transport="SSH",
            operation_id=request.operation_id, authorization_ref=request.authorization_ref,
            authorization_expires_at=request.authorization_expires_at,
        )
        try:
            grant = policy.authorize(target_request)
        except Exception as exc:
            code = getattr(exc, "code", "TARGET_REFUSED")
            raise IpcRefused(str(code), type(exc).__name__) from exc

        def revalidate():
            try:
                policy.revalidate(grant, operation_id=request.operation_id, endpoint=path.endpoint_address)
            except Exception as exc:
                raise IpcRefused(str(getattr(exc, "code", "AUTHORIZATION_CHANGED")), type(exc).__name__) from exc

        output, evidence = self.executor.execute(path=path, command=command, revalidate=revalidate)
        revalidate()
        return {"schema": DIAGNOSTIC_RESULT_SCHEMA, "device": request.device,
                "operation_id": request.operation_id, "output": output,
                "output_sha256": hashlib.sha256(output.encode("utf-8", "replace")).hexdigest(),
                "evidence": evidence, "catalog_kind": spec.kind}


class DiagnosticWorkerClient:
    """Application adapter.  It exposes typed catalogue operations only."""

    def __init__(self, *, socket_path: str, key: bytes, agent: str, tenant: str,
                 topology_id: str, authorization_ref: str, authorization_expires_at: datetime,
                 timeout_seconds: float = 20.0):
        self.agent, self.tenant, self.topology_id = agent, tenant, topology_id
        self.authorization_ref, self.authorization_expires_at = authorization_ref, authorization_expires_at
        self.ipc = UnixWorkerClient(kind="diagnostic", socket_path=socket_path, key=key,
                                    principal=agent, timeout_seconds=timeout_seconds)

    def execute(self, *, device: str, operation_id: str, params: dict | None = None) -> str:
        request_id = secrets.token_hex(16)
        payload = {"schema": DIAGNOSTIC_SCHEMA, "topology_id": self.topology_id, "tenant": self.tenant,
                   "agent": self.agent, "authorization_ref": self.authorization_ref,
                   "authorization_expires_at": self.authorization_expires_at.astimezone(timezone.utc).isoformat(),
                   "device": device, "operation_id": operation_id, "params": dict(params or {})}
        result = self.ipc.call(payload, request_id=request_id)
        if not isinstance(result, dict) or result.get("schema") != DIAGNOSTIC_RESULT_SCHEMA or result.get("device") != device \
                or result.get("operation_id") != operation_id or not isinstance(result.get("output"), str):
            raise IpcRefused("INVALID_DIAGNOSTIC_RESULT")
        if not secrets.compare_digest(hashlib.sha256(result["output"].encode("utf-8", "replace")).hexdigest(),
                                      str(result.get("output_sha256") or "")):
            raise IpcRefused("DIAGNOSTIC_RESULT_TAMPERED")
        return result["output"]


class DiagnosticCliTransport:
    """Collector-facing adapter which cannot accept an arbitrary command."""

    def __init__(self, *, device: str, platform: str, client: DiagnosticWorkerClient):
        self.device, self.platform, self.client = device, collectors.nz.canonical_platform(platform), client

    def execute(self, _rendered):
        raise IpcRefused("UNTYPED_DIAGNOSTIC_REFUSED")

    def execute_operation(self, operation_id: str, params: dict, rendered) -> str:
        spec = collectors.COMMAND_CATALOG.get(self.platform, {}).get(operation_id)
        if spec is None or spec.kind == "config":
            raise IpcRefused("OPERATION_NOT_REGISTERED")
        try:
            expected = collectors.render_command(spec, params)
        except collectors.CommandNotAllowed as exc:
            raise IpcRefused("INVALID_OPERATION_PARAMETERS") from exc
        if expected != rendered:
            raise IpcRefused("OPERATION_SUBSTITUTION")
        return self.client.execute(device=self.device, operation_id=f"cli:{operation_id}", params=params)

    def provenance(self) -> dict:
        return {"transport": "isolated-diagnostic-worker", "authenticated_ipc": True,
                "arbitrary_command_api": False, "arbitrary_destination_api": False}


def server_from_environment() -> UnixWorkerServer:
    key = load_key("NMAS_TS_DIAGNOSTIC_IPC_KEY")
    try:
        uid = int(os.environ["NMAS_TS_DIAGNOSTIC_CLIENT_UID"])
    except (KeyError, ValueError) as exc:
        raise IpcRefused("CLIENT_UID_UNAVAILABLE") from exc
    group_name = os.environ.get("NMAS_TS_DIAGNOSTIC_SOCKET_GROUP", "")
    config = ServerConfig(
        kind="diagnostic", key=key, allowed_uid=uid,
        socket_path=os.environ.get("NMAS_TS_DIAGNOSTIC_SOCKET", "/run/nmas-ts-diagnostic/worker.sock"),
        replay_path=os.environ.get("NMAS_TS_DIAGNOSTIC_REPLAY_DB", "/var/lib/nmas-ts-diagnostic/replay.sqlite3"),
        audit_path=os.environ.get("NMAS_TS_DIAGNOSTIC_AUDIT_LOG", "/var/log/nmas-ts-diagnostic/audit.jsonl"),
        socket_gid=grp.getgrnam(group_name).gr_gid if group_name else None,
    )
    return UnixWorkerServer(config, DiagnosticHandler())
