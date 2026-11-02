"""The management transport of a natively onboarded device that is not (and must not be) in ``inventory.yml``.

A Phase 3 device is reached at its ZTP session's address with the host key an approver enrolled out of band; Phase 4 replaced
its bootstrap credential with a key-only SERVICE credential and proved the bootstrap credential rejected (BCRED COMPLETE).  That
pair -- pinned host key + retired-bootstrap service credential -- is the ONLY way this module opens a session, and only:

    READ   while the device is BOOTSTRAPPED or later, identity VERIFIED, host key matching the verified one
    WRITE  additionally while its commissioning is APPROVED / CONFIGURING (the ProvisioningRun execution) or it is IN_SERVICE
           and ADMITTED by NMAS

``nsot_live.get_live_target(..., platform="ceos")`` falls back to ``live_target`` for a name that has no inventory entry, so the cEOS executor,
health reader and provisioning digest reach the device through their ordinary code paths -- no second engine, no inventory edit.
Nothing here stores, logs or returns key material.
"""

from __future__ import annotations

from ... import models

S = models.DeviceLifecycleState
SOURCE = "COMMISSIONING"
READ_STATES = (S.BOOTSTRAPPED, S.ISOLATED, S.READY_FOR_COMMISSIONING, S.COMMISSIONING, S.IN_SERVICE)
WRITE_COMMISSIONING = ("APPROVED", "CONFIGURING")


def credential_transition(device):
    """The device's latest COMPLETE bootstrap-credential transition (Phase 4), or None."""
    return (models.BootstrapCredentialTransition.objects.select_related("ztp_session", "replacement_credential", "path")
            .filter(device=device, state=models.BootstrapCredentialState.COMPLETE).order_by("-completed_at", "-id").first())


def device_for(name: str):
    return models.ManagedDevice.objects.filter(name=name, origin=models.DeviceOrigin.REGISTERED_NEW).exclude(
        lifecycle_state__in=tuple(models.DEVICE_LIFECYCLE_TERMINAL)).first()


def write_authorized(device) -> bool:
    if device.lifecycle_state == S.IN_SERVICE and device.admission_state == models.ProductionAdmissionState.ADMITTED:
        return True
    return models.CommissioningRecord.objects.filter(device=device, state__in=WRITE_COMMISSIONING).exists()


def problems(device, *, purpose: str = "READ") -> list[str]:
    """Why this device has no commissioning transport for ``purpose`` ([] when it has)."""
    if device is None:
        return ["NOT_REGISTERED"]
    found = []
    if device.platform != models.Platform.ARISTA_CEOS:
        found.append("PLATFORM_NOT_IMPLEMENTED")
    if device.lifecycle_state not in READ_STATES:
        found.append("LIFECYCLE_STATE")
    if device.identity_state != models.IdentityVerificationState.VERIFIED or not device.verified_host_key:
        found.append("IDENTITY_UNVERIFIED")
    transition = credential_transition(device)
    if transition is None:
        found.append("CREDENTIAL_NOT_TRANSITIONED")
    elif transition.ztp_session.enrolled_host_key != device.verified_host_key:
        found.append("HOST_KEY_MISMATCH")
    if purpose == "WRITE" and not write_authorized(device):
        found.append("WRITE_NOT_AUTHORIZED")
    return found


def endpoint(device) -> dict:
    """{address, port, host_key, username, credential} -- references and public data only."""
    from ..management import bootstrap_credentials

    transition = credential_transition(device)
    address, port, host_key = bootstrap_credentials.target(transition)
    return {"address": address, "port": int(port), "host_key": host_key, "username": transition.replacement_username,
            "credential": transition.replacement_credential, "transition": transition.transition_id}


def live_target(device_name: str, *, purpose: str = "READ") -> dict | None:
    """A ``nsot_live``-shaped target for a commissioned / commissioning device, or None (fail closed)."""
    device = device_for(device_name)
    if problems(device, purpose=purpose):
        return None
    from modules.device_credentials import SecretProviderError, load_ssh_private_key

    found = endpoint(device)
    try:
        key = load_ssh_private_key(found["credential"].ssh_key_ref)
    except SecretProviderError:
        return None
    auth = {"username": found["username"], "password": "", "ssh_auth": {"use_keys": True, "pkey": key, "allow_agent": False}}
    return {"device_name": device_name, "purpose": purpose, "platform": "ceos", "address": found["address"], "port": found["port"],
            "pinned_host_key": found["host_key"], "management": {"source": SOURCE, "transition": found["transition"], "port": found["port"]},
            "username": found["username"], "password": "", "password_candidates": ("",), "ssh_auth": auth["ssh_auth"],
            "auth_candidates": (auth,), "credential_ref": "", "ssh_key_ref": "", "access_profiles": ()}


def connect_pinned(target: dict, auth: dict, timeout: float):
    """Netmiko (Arista) over a plain socket whose server key must be ``target['pinned_host_key']``; key-only, no agent, no files."""
    import socket
    from contextlib import suppress

    import paramiko
    from netmiko.arista.arista import AristaSSH

    from ..management import probes

    expected = target["pinned_host_key"]

    class PinnedHostKey(paramiko.MissingHostKeyPolicy):
        def missing_host_key(self, _client, _hostname, key):
            if probes.fingerprint(key) != expected:
                raise paramiko.SSHException("HOST_KEY_MISMATCH")

    class PinnedAristaSSH(AristaSSH):
        def _build_ssh_client(self):
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(PinnedHostKey())
            return client

    sock = socket.create_connection((target["address"], int(target.get("port") or 22)), timeout=timeout)
    conn = None
    try:
        conn = PinnedAristaSSH(device_type="arista_eos", host=target["address"], port=int(target.get("port") or 22), username=auth["username"],
                               password="", secret="", fast_cli=False, conn_timeout=timeout, auth_timeout=timeout, banner_timeout=timeout,
                               sock=sock, auto_connect=False, allow_agent=False, ssh_strict=True, system_host_keys=False, alt_host_keys=False,
                               use_keys=False, pkey=(auth.get("ssh_auth") or {}).get("pkey"))
        conn._open()
        return conn
    except Exception:
        if conn is not None:
            with suppress(Exception):
                conn.disconnect()
        sock.close()
        raise


def read_connection(device: dict):
    """A privileged-EXEC session for READING only (the executor's own factory always asks for a WRITE target)."""
    from ..execution.codes import device_timeout_seconds
    from ..execution.executors.base import ExecutorError

    target = live_target(device["name"], purpose="READ")
    if target is None:
        raise ExecutorError("NOT_CONFIGURED")
    try:
        conn = connect_pinned(target, target["auth_candidates"][0], device_timeout_seconds())
    except Exception as exc:  # noqa: BLE001 - never relay connection details
        raise ExecutorError("CONNECTION_FAILED") from exc
    if not conn.check_enable_mode():
        conn.enable()
    return conn


def config_reader(device: dict) -> str:
    """The sanitized running configuration of a commissioning device (provisioning's digest reader for cEOS)."""
    from ..execution.executors.ceos import CeosExecutor
    from ..isolation.service import read_config

    executor = CeosExecutor(device, connection_factory=read_connection)
    executor.connect()
    try:
        return read_config(executor)
    finally:
        executor.close()


def prober(target: dict):
    """The provisioning bootstrap probe for the ZTP_MANAGEMENT transport (read-only): does the device answer over its
    commissioning session, and does it already hold production configuration beyond the minimal ZTP bootstrap?"""
    from ..execution.executors.base import ExecutorError
    from ..provisioning.bootstrap import Probe
    from ..ztp import adapters

    device = models.ManagedDevice.objects.filter(pk=_pk(target.get("device"))).first()
    if device is None:
        return Probe(error="TARGET_INVALID")
    found = problems(device, purpose="READ")
    if found:
        return Probe(exists=True, error=found[0])
    try:
        text = config_reader({"name": device.name, "platform": "ceos"})
    except (ExecutorError, OSError):
        return Probe(exists=True, running=True, error="NO_MANAGEMENT_PLANE")
    adapter = adapters.for_platform(device.platform)
    findings = adapter.production_findings(text) if adapter is not None else ["no adapter"]
    return Probe(exists=True, running=True, answers=True, configured=bool(findings),
                 facts={"config_lines": len(text.splitlines()), "production_findings": findings[:10]})


def _pk(device_id) -> int | None:
    text = str(device_id or "")
    return int(text[4:]) if text.startswith("DEV-") and text[4:].isdigit() else None
