"""Broker-backed ``connection_factory`` for ``observation_sessions.session_provider``.

``ObservationConnectionFactory()(request: ConnectionRequest)`` returns a connection exposing ``host_key`` (the fingerprint the
peer actually presented, read back from the live SSH transport), ``host_key_pinned`` (True only after that fingerprint equalled the
pin), ``close()`` and ``send_command(str)`` (cEOS) or ``run(argv, timeout)`` (FRR).  It reuses, and does not replace, the existing
mechanisms:

* endpoint / source / port / path: ``management.resolve.endpoint`` and the guard, re-resolved immediately before connecting and
  compared with the request (a changed address, port, source or path id refuses -- no fallback to another route);
* cEOS approved path: ``nsot_live.get_live_target`` + ``ssh_transport.connect_eos`` (path re-read, source/interface-bound socket,
  pin checked by the Paramiko policy before authentication); cEOS legacy: the same entry point with the inventory pin
  (``commissioning.transport.connect_pinned``, key-only);
* FRR: ``linux_ssh.target`` + ``linux_ssh.connect_found`` (legacy source only, key-only, pin checked before authentication,
  commands only as argv).
* never a shared fleet credential: an identity observation must be made with the device's own dedicated account.  A legacy
  route (or an approved path using the inventory's references) whose references come from the inventory's fleet-wide fallback
  profile (``profile == FLEET_FALLBACK``, still produced by older resolvers), and a path bound to a ``LEGACY_SHARED`` account,
  are refused with ``SHARED_CREDENTIAL_REFUSED`` before anything is contacted.  The broker model itself is unchanged.

Credentials are never read here: the broker references (``runtime://...``) are resolved inside those existing helpers at the moment
of connection.  Nothing is approved, persisted or deployed.  Every failure is an ``ObservationConnectionError`` carrying only a
stable code (also kept in ``factory.last_error``); no address, key, credential or device output is included.
"""

from __future__ import annotations

import re
from contextlib import suppress

from ... import models
from ..management import guard, linux_ssh, probes, ssh_transport
from ..management import resolve as management_resolve
from . import observations, resolver

CONNECT_TIMEOUT = 15.0
_PIN = re.compile(r"^SHA256:[A-Za-z0-9+/]{43}$")

ERRORS = {
    "REQUEST_INVALID": "The connection request is not a read-only, authorized request.",
    "PIN_MISSING": "No valid host-key pin accompanies the request; nothing is contacted.",
    "PIN_CHANGED": "The registered host-key pin differs from the one in the request.",
    "TARGET_CHANGED": "The device no longer resolves to a manageable target for this platform.",
    "ENDPOINT_CHANGED": "The re-resolved address, port, source or path differs from the request.",
    "ENDPOINT_PROHIBITED": "The endpoint is forbidden as a management target.",
    "PATH_BLOCKED": "The management resolver refuses the device; no fallback is attempted.",
    "ROUTE_UNSUPPORTED": "This platform/source combination has no approved read-only route.",
    "CREDENTIAL_UNAVAILABLE": "No usable credential reference could be resolved from the broker.",
    "SHARED_CREDENTIAL_REFUSED": "Only the device's own dedicated account may produce an identity observation (fleet-shared refused).",
    "KEY_AUTH_UNAVAILABLE": "The pinned legacy route is key-only and no key reference is enrolled.",
    "HOST_KEY_MISMATCH": "The presented host key is not the pinned one.",
    "HOST_KEY_UNOBSERVED": "The presented host key could not be read from the transport.",
    "AUTH_FAILED": "Authentication was refused.",
    "CONNECTION_FAILED": "The connection could not be established.",
}


class ObservationConnectionError(Exception):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


class EosObservationConnection:
    """Netmiko connection wrapper: exactly the cEOS version command, host-key provenance fixed at construction."""

    def __init__(self, conn, host_key: str, command: str):
        self._conn, self._command = conn, command
        self.host_key, self.host_key_pinned = host_key, True      # constructed only after the presented key matched the pin

    def send_command(self, command):
        if command != self._command:
            raise PermissionError("only the version command is permitted")
        return self._conn.send_command(command)

    def close(self) -> None:
        with suppress(Exception):
            self._conn.disconnect()


def presented_host_key(conn) -> str:
    """The fingerprint the peer presented on this Netmiko connection ("" when it cannot be read)."""
    for holder in ("remote_conn_pre", "remote_conn"):
        client = getattr(conn, holder, None)
        transport = client.get_transport() if callable(getattr(client, "get_transport", None)) else None
        key = transport.get_remote_server_key() if transport is not None else None
        if key is not None:
            return probes.fingerprint(key)
    return ""


class ObservationConnectionFactory:
    """Callable ``request -> connection``.  Collaborators are injectable for tests; defaults are the production helpers."""

    def __init__(self, *, document: dict | None = None, endpoint_resolver=None, live_target=None, eos_connect=None,
                 active_path=None, linux_target=None, linux_connect=None, timeout: float = CONNECT_TIMEOUT):
        self._document = document
        self._endpoint = endpoint_resolver or management_resolve.endpoint
        self._live_target = live_target
        self._eos_connect = eos_connect or ssh_transport.connect_eos
        self._active_path = active_path or ssh_transport.active_path
        self._linux_target = linux_target or linux_ssh.target
        self._linux_connect = linux_connect or linux_ssh.connect_found
        self._timeout = timeout
        self.last_error = ""

    # --- entry point ------------------------------------------------------------------------------------------------------
    def __call__(self, request):
        self.last_error = ""
        try:
            return self._open(request)
        except ObservationConnectionError as exc:
            self.last_error = exc.code
            raise
        except Exception:  # noqa: BLE001 - never relay connection parameters
            self.last_error = "CONNECTION_FAILED"
            raise ObservationConnectionError("CONNECTION_FAILED") from None

    def _open(self, request):
        platform = request.platform
        if (request.read_only is not True or not str(request.authorization_ref or "").strip()
                or platform not in (models.Platform.ARISTA_CEOS.value, models.Platform.UBUNTU_FRR.value)
                or request.source not in (management_resolve.LEGACY, management_resolve.PATH)):
            raise ObservationConnectionError("REQUEST_INVALID")
        pin = str(request.expected_host_key or "")
        if not _PIN.fullmatch(pin):
            raise ObservationConnectionError("PIN_MISSING")
        selected, target = self._reresolve(request)
        if request.source == management_resolve.LEGACY and _fleet_profile(target):
            raise ObservationConnectionError("SHARED_CREDENTIAL_REFUSED")
        if platform == models.Platform.UBUNTU_FRR.value:
            return self._frr(request, pin)
        return self._ceos(request, pin, selected)

    # --- re-resolution ------------------------------------------------------------------------------------------------------
    def _reresolve(self, request):
        target = resolver.resolve(request.device, document=self._document)
        if target is None or target.platform != request.platform or target.scope not in resolver.WRITABLE_SCOPES:
            raise ObservationConnectionError("TARGET_CHANGED")
        selected = self._endpoint(request.device, legacy_address=target.primary_address(4), purpose=management_resolve.READ)
        if not selected.usable:
            raise ObservationConnectionError("PATH_BLOCKED")
        if (selected.source, selected.address, int(selected.port or 22), selected.path_id) != (
                request.source, request.address, int(request.port), request.path_id):
            raise ObservationConnectionError("ENDPOINT_CHANGED")
        if guard.address_problems(selected.address):
            raise ObservationConnectionError("ENDPOINT_PROHIBITED")
        return selected, target

    # --- cEOS ----------------------------------------------------------------------------------------------------------------
    def _ceos(self, request, pin: str, selected):
        live = self._live_target
        if live is None:
            from .. import nsot_live

            live = nsot_live.get_live_target
        target = live(request.device, purpose=management_resolve.READ, platform="ceos")
        if not target:
            raise ObservationConnectionError("CREDENTIAL_UNAVAILABLE")
        management = target.get("management") or {}
        if (management.get("source"), target.get("address"), int(management.get("port") or 22), management.get("path_id", "")) != (
                request.source, request.address, int(request.port), request.path_id):
            raise ObservationConnectionError("ENDPOINT_CHANGED")
        target = {**target, "device_name": request.device, "purpose": management_resolve.READ}
        if request.source == management_resolve.PATH:
            try:
                path = self._active_path(target)
            except ssh_transport.ManagedConnectionRejected:
                raise ObservationConnectionError("ENDPOINT_CHANGED") from None
            if path.expected_host_key != pin:
                raise ObservationConnectionError("PIN_CHANGED")
            if _shared_path_credential(path, request.device, self._document):
                raise ObservationConnectionError("SHARED_CREDENTIAL_REFUSED")
        else:
            if self._inventory_pin(request.device) != pin:
                raise ObservationConnectionError("PIN_CHANGED")
            target = {**target, "pinned_host_key": pin, "port": request.port}
        candidates = list(target.get("auth_candidates") or ())
        if request.source == management_resolve.LEGACY:                 # pinned legacy transport is key-only
            candidates = [c for c in candidates if (c.get("ssh_auth") or {}).get("pkey") is not None]
            if not candidates:
                raise ObservationConnectionError("KEY_AUTH_UNAVAILABLE")
        if not candidates:
            raise ObservationConnectionError("CREDENTIAL_UNAVAILABLE")
        conn = self._connect_candidates(target, candidates)
        try:
            presented = presented_host_key(conn)
            if not presented:
                raise ObservationConnectionError("HOST_KEY_UNOBSERVED")
            if presented != pin:
                raise ObservationConnectionError("HOST_KEY_MISMATCH")
        except BaseException:
            with suppress(Exception):
                conn.disconnect()
            raise
        return EosObservationConnection(conn, presented, observations.SPECS[request.platform].command)

    def _connect_candidates(self, target: dict, candidates: list):
        failure = "AUTH_FAILED"
        for candidate in candidates:
            try:
                return self._eos_connect(target, candidate, self._timeout)
            except ssh_transport.ManagedConnectionRejected as exc:
                if str(exc) == "HOST_KEY_MISMATCH":
                    raise ObservationConnectionError("HOST_KEY_MISMATCH") from None
                raise ObservationConnectionError("ENDPOINT_CHANGED" if "CHANGED" in str(exc) else "CONNECTION_FAILED") from None
            except Exception as exc:  # pylint: disable=broad-exception-caught  # noqa: BLE001 - any non-authentication failure is CONNECTION_FAILED; the exception text may carry connection parameters
                if not _is_auth_failure(exc):
                    failure = "CONNECTION_FAILED"
                    break
        raise ObservationConnectionError(failure)

    # --- FRR -------------------------------------------------------------------------------------------------------------------
    def _frr(self, request, pin: str):
        if request.source != management_resolve.LEGACY:
            raise ObservationConnectionError("ROUTE_UNSUPPORTED")
        try:
            found = self._linux_target(request.device, purpose=management_resolve.READ)
        except Exception:  # noqa: BLE001
            raise ObservationConnectionError("CREDENTIAL_UNAVAILABLE") from None
        if (found.get("address"), int(found.get("port") or 22)) != (request.address, int(request.port)):
            raise ObservationConnectionError("ENDPOINT_CHANGED")
        if found.get("host_key") != pin:
            raise ObservationConnectionError("PIN_CHANGED")
        found = _frr_diagnostic_identity(request.device, found)
        try:
            session = self._linux_connect(found, timeout=self._timeout)
        except Exception as exc:  # noqa: BLE001
            code = getattr(exc, "code", "")
            raise ObservationConnectionError("AUTH_FAILED" if code == "AUTH_FAILED" else "CONNECTION_FAILED") from None
        presented = str(getattr(session, "host_key", "") or "")
        if not presented or getattr(session, "host_key_pinned", False) is not True or presented != pin:
            with suppress(Exception):
                session.close()
            raise ObservationConnectionError("HOST_KEY_MISMATCH" if presented else "HOST_KEY_UNOBSERVED")
        return session

    # --- helpers ---------------------------------------------------------------------------------------------------------------
    def _inventory_pin(self, name: str) -> str:
        document = self._document
        if document is None:
            from ..health import inventory

            document = inventory.load_inventory()
        return str((((document.get("network_devices") or {}).get(name)) or {}).get("ssh_host_key") or "")


def _frr_diagnostic_identity(device: str, found: dict) -> dict:
    """Prefer the device's own read-only broker account for an FRR observation.

    ``nmas-automation`` holds no sudo grant on the Phase 26B hosts, so it cannot run the version query; granting it one would add
    write capability.  When the device has its dedicated ``nmas-diag`` broker credential (exact contract: SERVICE, PUBLICKEY,
    role ``diagnostic-broker``, ``<device>-nmas-diag-sshkey``), the session logs in as that account instead -- same address, port
    and pinned host key -- and the broker runs only allowlisted queries.  Without it the original target is unchanged."""
    from ..management.linux_ssh import BROKER_USERNAME

    row = models.DeviceCredential.objects.filter(device_name=device, username=BROKER_USERNAME).first()
    if row is None or row.account_kind != models.AccountKind.SERVICE or row.auth_method != models.DeviceAuthMethod.PUBLICKEY \
            or row.account_role != "diagnostic-broker" or row.secret_ref \
            or row.ssh_key_ref != f"runtime://device-credentials/{device.lower()}-nmas-diag-sshkey":
        return found
    return {**found, "username": BROKER_USERNAME, "ssh_key_ref": row.ssh_key_ref}


def _fleet_profile(target) -> bool:
    """The inventory references were taken from the fleet-wide shared fallback profile (never acceptable for observations)."""
    return str((getattr(target, "credential_refs", None) or {}).get("profile") or "").upper() == "FLEET_FALLBACK"


def _shared_path_credential(path, device: str, document) -> bool:
    credential = getattr(path, "device_credential", None)
    if credential is not None and getattr(credential, "account_kind", "") == models.AccountKind.LEGACY_SHARED:
        return True
    if getattr(path, "credential_source", "") == models.ManagementCredentialSource.INVENTORY:
        return _fleet_profile(resolver.resolve(device, document=document))
    return False


def _is_auth_failure(exc: Exception) -> bool:
    try:
        import paramiko
        from netmiko.exceptions import NetmikoAuthenticationException

        return isinstance(exc, (NetmikoAuthenticationException, paramiko.AuthenticationException))
    except ImportError:  # pragma: no cover
        return type(exc).__name__ in {"NetmikoAuthenticationException", "AuthenticationException"}


def connection_factory(**kwargs) -> ObservationConnectionFactory:
    """The factory to pass as ``observation_sessions.session_provider(connection_factory, authorization_ref)``."""
    return ObservationConnectionFactory(**kwargs)
