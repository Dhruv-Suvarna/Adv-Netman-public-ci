"""Policy-bound read-only observation sessions for ``observation_collector.collect(session_provider=...)``.

The provider owns no selection logic.  The endpoint comes from the existing management resolver (``management.resolve.endpoint``,
the same choke point ``nsot_live`` uses): an ACTIVE, HEALTHY, APPROVED path (selector failover / hold-down already applied), or
-- only when the device has no registered path -- the inventory-declared LEGACY address.  A BLOCKED answer is final: the
provider never tries another address, the legacy address, Docker or Containerlab.  An approved path must additionally pass
``management.guard.authorized_target``; the legacy address passes ``guard.address_problems``.

Nothing here reads a credential or opens a connection itself: the injected ``connection_factory(request)`` does that and must
return an object exposing ``host_key`` (what the peer actually presented), ``host_key_pinned`` (True only when that key matched
a pin), ``close()`` and ``send_command(str)`` (cEOS) or ``run(argv, timeout) -> (status, output)`` (FRR, e.g.
``management.linux_ssh.LinuxSession``).  The returned session permits exactly the platform's ``observations.SPECS`` version
command; FRR is sent as the argv built by ``linux_ssh.frr_show``.  No identity verification or admission is performed.
"""

from __future__ import annotations

from dataclasses import dataclass

from ... import models
from ..management import guard, linux_ssh, paths
from ..management import resolve as management_resolve
from ..execution.executors.base import ExecutorError
from . import identity, observations

REFUSALS = {
    "AUTHORIZATION_MISSING": "No authorization reference was injected.",
    "CONNECTION_FACTORY_MISSING": "No connection factory was injected.",
    "PLATFORM_UNSUPPORTED": "No read-only observation session is supported for this platform.",
    "PATH_BLOCKED": "The management resolver refuses the device (no usable approved path / retired); no fallback is attempted.",
    "ENDPOINT_NOT_REQUESTED": "The policy-selected endpoint is not the requested address.",
    "ENDPOINT_EMPTY": "The policy-selected endpoint has no address.",
    "ENDPOINT_PROHIBITED": "The endpoint is forbidden as a management target (loopback, link-local, Containerlab/Docker, ...).",
    "PATH_NOT_AUTHORIZED": "The selected management path is not registered/approved for probing.",
    "PATH_PLATFORM_UNSUPPORTED": "Identity observations over a management path are cEOS-only (Linux/FRR identity uses the legacy route).",
    "CONNECTION_FAILED": "The connection factory could not open a session.",
    "CONNECTION_UNUSABLE": "The connection does not offer the required execution interface.",
    "HOST_KEY_MISSING": "The connection presented no valid host key.",
    "HOST_KEY_NOT_PINNED": "The connection did not verify a pinned host key.",
    "HOST_KEY_PIN_MISMATCH": "The presented host key differs from the inventory pin.",
}
SUPPORTED = (models.Platform.ARISTA_CEOS.value, models.Platform.UBUNTU_FRR.value)
FRR_TIMEOUT = 20.0


class CommandNotPermitted(Exception):
    """Raised for any command other than the platform's version command."""


@dataclass(frozen=True)
class ConnectionRequest:
    device: str
    platform: str
    address: str
    port: int
    source: str                 # LEGACY | PATH
    path_id: str
    authorization_ref: str
    expected_host_key: str      # inventory pin ("" when none); the factory enforces it, the provider re-checks the presented key
    read_only: bool = True


class ObservationSession:
    """Collector-shaped session whose only operation is the platform version command."""

    transport = "SSH"
    read_only = True

    def __init__(self, connection, *, platform: str, command: str, address: str, authorization_ref: str, host_key: str,
                 host_key_pinned: bool, evidence_refs=()):
        self._connection, self._platform, self._command = connection, platform, command
        self.address, self.authorization_ref, self.host_key = address, authorization_ref, host_key
        self.host_key_pinned, self.evidence_refs = host_key_pinned, tuple(evidence_refs)
        self.commands_sent: list = []
        self.closed = False

    def execute(self, command) -> str:
        if self.closed or command != self._command:
            raise CommandNotPermitted("only the version command is permitted")
        self.commands_sent.append(command)
        if self._platform == models.Platform.UBUNTU_FRR.value:
            status, output = self._connection.run(linux_ssh.frr_show("show version"), FRR_TIMEOUT)
            if status != 0:
                raise ExecutorError("COMMAND_FAILED")
            return output
        return self._connection.send_command(command)

    def close(self) -> None:
        self.closed = True
        closer = getattr(self._connection, "close", None)
        if callable(closer):
            try:
                closer()
            except Exception:  # noqa: BLE001 - closing never changes the outcome
                pass


class ObservationSessionProvider:
    """``provider(target, address)`` -> ``ObservationSession`` or ``None``; ``last_refusal`` holds the reason code."""

    def __init__(self, connection_factory, authorization_ref: str, *, document: dict | None = None, endpoint_resolver=None,
                 path_authorizer=None):
        self._factory = connection_factory
        self._auth = str(authorization_ref or "").strip()
        self._document = document
        self._endpoint = endpoint_resolver or management_resolve.endpoint
        self._authorize = path_authorizer or self._stored_path_check
        self.last_refusal = ""

    def _refuse(self, code: str):
        self.last_refusal = code
        return None

    @staticmethod
    def _stored_path_check(target, selected) -> bool:
        """-> the guard-authorized stored path (truthy) or None."""
        try:
            pk = int(str(selected.path_id).rsplit("-", 1)[-1])
        except ValueError:
            return None
        path = models.ManagementPath.objects.filter(pk=pk, device__name=target.name).first()
        stored, problems = guard.authorized_target(path) if path is not None else (None, [1])
        return stored if stored is not None and not problems and stored.endpoint_address == selected.address else None

    def _pin(self, name: str) -> str:
        document = self._document
        if document is None:
            from ..health import inventory
            document = inventory.load_inventory()
        return str((((document.get("network_devices") or {}).get(name)) or {}).get("ssh_host_key") or "")

    def __call__(self, target, address):
        self.last_refusal = ""
        if not self._auth:
            return self._refuse("AUTHORIZATION_MISSING")
        if not callable(self._factory):
            return self._refuse("CONNECTION_FACTORY_MISSING")
        spec = observations.SPECS.get(target.platform)
        if target.platform not in SUPPORTED or spec is None:
            return self._refuse("PLATFORM_UNSUPPORTED")
        selected = self._endpoint(target.name, legacy_address=target.primary_address(4), purpose=management_resolve.READ)
        if not selected.usable:
            return self._refuse("PATH_BLOCKED")                  # governed refusal: never fall back to another address
        if not selected.address:
            return self._refuse("ENDPOINT_EMPTY")
        if selected.address != str(address):
            return self._refuse("ENDPOINT_NOT_REQUESTED")
        if guard.address_problems(selected.address):
            return self._refuse("ENDPOINT_PROHIBITED")
        if selected.source == management_resolve.PATH:
            # Identity observations over a management PATH are cEOS-only: Linux/FRR paths serve the read-only diagnostic broker,
            # and an FRR identity is observed on the legacy route before its path exists (bulk admission ordering).
            if target.platform not in paths.VERIFIED_PLATFORMS or target.platform != models.Platform.ARISTA_CEOS.value:
                return self._refuse("PATH_PLATFORM_UNSUPPORTED")
            stored = self._authorize(target, selected)
            if not stored:
                return self._refuse("PATH_NOT_AUTHORIZED")
            pin = str(getattr(stored, "expected_host_key", "") or "")      # the approved path's own registered pin
        else:
            pin = self._pin(target.name)
        request = ConnectionRequest(target.name, target.platform, selected.address, int(selected.port or 22), selected.source,
                                    selected.path_id, self._auth, pin)
        try:
            connection = self._factory(request)
        except Exception:  # noqa: BLE001 - factory detail may contain connection parameters
            return self._refuse("CONNECTION_FAILED")
        if connection is None:
            return self._refuse("CONNECTION_FAILED")
        code = self._connection_problem(connection, target.platform, pin)
        if code:
            ObservationSession(connection, platform=target.platform, command=spec.command, address="", authorization_ref="",
                               host_key="", host_key_pinned=False).close()
            return self._refuse(code)
        host_key, _bad = identity.normalize_host_key(getattr(connection, "host_key", ""))
        return ObservationSession(connection, platform=target.platform, command=spec.command, address=selected.address,
                                  authorization_ref=self._auth, host_key=host_key, host_key_pinned=True,
                                  evidence_refs=(f"path:{selected.path_id}",) if selected.path_id else ("legacy-inventory",))

    @staticmethod
    def _connection_problem(connection, platform: str, pin: str) -> str:
        needed = "run" if platform == models.Platform.UBUNTU_FRR.value else "send_command"
        if not callable(getattr(connection, needed, None)):
            return "CONNECTION_UNUSABLE"
        host_key, bad = identity.normalize_host_key(getattr(connection, "host_key", ""))
        if bad or not host_key:
            return "HOST_KEY_MISSING"
        if getattr(connection, "host_key_pinned", False) is not True:
            return "HOST_KEY_NOT_PINNED"
        if pin and pin != host_key:
            return "HOST_KEY_PIN_MISMATCH"
        return ""


def session_provider(connection_factory, authorization_ref: str, **kwargs) -> ObservationSessionProvider:
    """Build the provider to pass as ``observation_collector.collect(session_provider=...)``."""
    return ObservationSessionProvider(connection_factory, authorization_ref, **kwargs)
