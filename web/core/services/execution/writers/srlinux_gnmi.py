"""Fixture-tested SR Linux gNMI CLI-origin writer.

Nokia SR Linux 24.10 documents that a gNMI Set update with origin ``cli`` and
ASCII content accepts full-context ``/`` commands, uses a private exclusive
candidate, and applies all operations in one SetRequest transaction.  The
Phase-20.5 SR Linux renderer already emits the equivalent documented ``set``
paths, so this adapter performs only the mechanical, auditable conversion.

``GnmiSession`` is the one SR Linux management session of NMAS: gNMI Get (JSON_IETF) for configuration and state, and
one CLI-origin Set per change.  A Set is a single SetRequest, so the device commits all of its statements or none of
them.  It was verified against an isolated SR Linux 24.10.7 node; the installed pygnmi client does not expose Nokia's
commit-confirmed extension, so NMAS relies on that atomicity plus its own captured-state compensation instead.

``apply`` keeps its explicit ``runtime_enabled`` gate for callers that hold a bare client: only the registered
``executors.srlinux.SrLinuxExecutor`` (through ``GnmiSession``) writes to a device.
"""

from __future__ import annotations

from dataclasses import dataclass

from ... import platform_drivers


class WriterInputError(ValueError):
    pass


class WriterRuntimeDisabled(RuntimeError):
    pass


@dataclass(frozen=True)
class GnmiSetPlan:
    origin: str
    encoding: str
    update: tuple[tuple[str, str], ...]
    atomic: bool
    private_candidate: bool
    live_verified: bool = False


def build_set_plan(candidate_text: str) -> GnmiSetPlan:
    """Convert a fully rendered SR Linux candidate to one atomic CLI-origin update."""
    if platform_drivers.UNSUPPORTED_OBJECT_MARKER in candidate_text:
        raise WriterInputError("Candidate contains an unsupported-object marker.")
    if "<" in candidate_text or "COMPOSITION CONFLICT" in candidate_text:
        raise WriterInputError("Candidate contains a placeholder or composition conflict.")

    commands: list[str] = []
    for raw in candidate_text.splitlines():
        line = raw.strip()
        if not line or line.startswith("!"):
            continue
        if not line.startswith("set "):
            raise WriterInputError(f"Non-SR-Linux candidate statement: {line!r}")
        commands.append("/" + line.removeprefix("set "))
    if not commands:
        raise WriterInputError("Candidate contains no SR Linux configuration statements.")

    return GnmiSetPlan(
        origin="cli",
        encoding="ascii",
        update=(("cli:", "\n".join(commands)),),
        atomic=True,
        private_candidate=True,
    )


def apply(client, plan: GnmiSetPlan, *, runtime_enabled: bool = False):
    """Send the prepared SetRequest only when an external runtime gate is enabled.

    The web execution registry never enables this path.  ``client`` is
    injected so fixture tests can prove the pygnmi call without networking.
    """
    if not runtime_enabled:
        raise WriterRuntimeDisabled("SR Linux gNMI writes are fixture-tested but runtime-disabled.")
    if plan.origin != "cli" or plan.encoding != "ascii" or not plan.atomic:
        raise WriterInputError("Invalid SR Linux gNMI Set plan.")
    return client.set(update=list(plan.update), encoding=plan.encoding)


# --- live session ----------------------------------------------------------------------------------------------------
class GnmiError(Exception):
    """A sanitized gNMI failure: only ``code`` leaves this module (gRPC error text can echo statements and targets)."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def _code(exc: Exception, *, default: str) -> str:
    text = f"{type(exc).__name__} {exc}".lower()
    if "invalid session id" in text:
        return "SESSION_EXPIRED"
    if "unauthenticated" in text or "authentication" in text or "permission_denied" in text:
        return "AUTH_FAILED"
    if "deadline" in text or "timeout" in text:
        return "TIMEOUT"
    if any(marker in text for marker in ("failed with error", "parsing error", "error in path", "invalidargument",
                                         "invalid_argument", "failedprecondition", "failed_precondition")):
        return "COMMAND_REJECTED"
    return default


class GnmiSession:
    """One authenticated gNMI channel to one SR Linux node.  ``client`` is injectable for fixture tests."""

    def __init__(self, *, host: str = "", port: int = 57400, username: str = "", password: str = "", insecure: bool = False,
                 timeout: float = 20, client=None):
        self._client = client
        self._client_ctor = None
        self._client_kwargs = {}
        if client is not None:
            return
        try:
            from pygnmi.client import gNMIclient
        except ImportError as exc:  # pragma: no cover - pygnmi is a project dependency
            raise GnmiError("CONNECTION_FAILED") from exc
        # Lab nodes present a self-signed certificate: the channel is encrypted but the peer is not authenticated.
        options = {"insecure": True} if insecure else {"skip_verify": True}
        self._client_ctor = gNMIclient
        self._client_kwargs = dict(target=(host, int(port)), username=username, password=password,
                                   timeout=int(timeout), **options)
        self._renew()

    def _renew(self) -> None:
        """Open a fresh authenticated channel after an explicit invalid-session refusal."""
        if self._client_ctor is None:
            raise GnmiError("SESSION_EXPIRED")
        self.disconnect()
        try:
            self._client = self._client_ctor(**self._client_kwargs)
            self._client.connect()
            self._client.capabilities()
        except Exception as exc:  # noqa: BLE001 - only a fixed error code escapes
            self.disconnect()
            raise GnmiError(_code(exc, default="CONNECTION_FAILED")) from None

    def get(self, path: str, datatype: str = "config") -> dict:
        if datatype not in ("config", "state"):
            raise GnmiError("COMMAND_NOT_ALLOWED")
        for attempt in range(2):
            try:
                return self._client.get(path=[path], datatype=datatype, encoding="json_ietf") or {}
            except Exception as exc:  # noqa: BLE001 - only an explicit expired session is renewed
                code = _code(exc, default="COMMAND_FAILED")
                if code == "SESSION_EXPIRED" and not attempt:
                    self._renew()
                    continue
                raise GnmiError(code) from None
        raise GnmiError("COMMAND_FAILED")

    def set_cli(self, statements) -> int:
        """Commit ``set`` / ``delete`` statements as ONE transaction; -> number of statements sent."""
        lines = []
        for raw in statements:
            verb, _, rest = raw.strip().partition(" ")
            rest = rest.strip().removeprefix("/").strip()
            if verb not in ("set", "delete") or not rest or "\n" in raw:
                raise GnmiError("COMMAND_REJECTED")
            lines.append(f"{verb} / {rest}")
        if not lines:
            raise GnmiError("COMMAND_REJECTED")
        try:
            self._client.set(update=[("cli:/", "\n".join(lines))], encoding="ascii")
        except Exception as exc:  # noqa: BLE001 - a write is never blindly retried
            code = _code(exc, default="TRANSPORT_ERROR")
            if code == "SESSION_EXPIRED":
                self._renew()  # the caller must read back through this channel before deciding to retry
            raise GnmiError(code) from None
        return len(lines)

    def disconnect(self) -> None:
        client, self._client = self._client, None
        if client is not None:
            try:
                client.close()
            except Exception:  # noqa: BLE001
                pass


def inventory_session(device: dict) -> GnmiSession:
    """The session for an inventory-managed SR Linux device (target and credential from the trusted inventory lookup)."""
    from ... import nsot_live
    from ..codes import device_timeout_seconds

    target = nsot_live.get_live_target(device.get("name", ""), purpose="WRITE")
    if target is None or target.get("platform") != "nokia_srlinux":
        raise GnmiError("NOT_CONFIGURED")
    return GnmiSession(host=target["address"], port=int(device.get("gnmi_port") or 57400), username=target["username"],
                       password=target["password"], timeout=device_timeout_seconds())
