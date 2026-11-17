"""CLI transports for ``CliCollector``.  A transport has ``execute(rendered_command) -> str`` and optionally ``provenance() -> dict``.

Every transport is read-only by construction: ``CliCollector`` only hands it commands that passed ``validate_read_only``; the
transports additionally refuse anything outside their own allowlist (health.live) or kind (gateway ``show``/``peer`` only -- the
gateway ``config`` kind is never used).  Credentials never enter these objects' public surface or provenance.
"""

from __future__ import annotations

import sys
from typing import Any

from ..collectors import CommandNotAllowed, PermissionDenied, TransportError

GATEWAY_CLIENT_DIR = "/opt/ai-orchestrator/gateway/client"


class HealthLiveTransport:
    """Reuses ``core.services.health.live`` sessions (Netmiko for cEOS with an inventory address, ``docker exec`` for Containerlab-addressed
    cEOS and Linux/FRR).  Only commands present in the EXISTING health allowlists (``CEOS_COMMANDS`` / ``LINUX_COMMANDS``) pass; the catalog
    commands outside them (e.g. ``show spanning-tree``) are refused here with ``CommandNotAllowed`` -> missing-data, until the health
    allowlist is deliberately extended (we do not widen another module's allowlist)."""

    def __init__(self, device: dict, *, session_factory=None):
        from core.services.health import live   # lazy: requires Django settings
        self._live = live
        factory = session_factory or live.default_session_factory(device)
        self._session = factory(device)
        self._reverse = {}
        platform = device.get("platform", "")
        if platform == "ceos":
            self._reverse = {cmd: key for key, cmd in live.CEOS_COMMANDS.items()}
        elif platform == "linux":
            self._reverse = {tuple(argv): key for key, argv in live.LINUX_COMMANDS.items()}
        self._device = device

    def execute(self, rendered) -> str:
        key = self._reverse.get(tuple(rendered) if isinstance(rendered, (list, tuple)) else rendered)
        if key is None:
            raise CommandNotAllowed("command is outside the existing health.live read-only allowlist")
        try:
            return self._session.run(key)
        except self._live.LiveError as exc:
            if exc.code == "AUTH_FAILED":
                raise PermissionDenied() from exc
            if exc.code == "TIMEOUT":
                raise TimeoutError() from exc
            raise TransportError(exc.code, transient=exc.code in ("CONNECTION_FAILED", "COMMAND_FAILED")) from exc

    def close(self) -> None:
        self._session.close()


class NetmikoLikeTransport:
    """Any object with ``send_command(str)`` (Netmiko ``BaseConnection`` or the gateway's ``NetmikoAdapter``).  No config methods are touched."""

    def __init__(self, connection: Any, *, label: str = "netmiko"):
        self._conn, self._label = connection, label

    def execute(self, rendered) -> str:
        if not isinstance(rendered, str):
            raise CommandNotAllowed("network CLI transport takes string commands")
        try:
            return self._conn.send_command(rendered)
        except TimeoutError:
            raise
        except Exception as exc:  # noqa: BLE001 - sanitized: never echo connection parameters
            name = exc.__class__.__name__
            if "Timeout" in name:
                raise TimeoutError() from exc
            if "Authentication" in name:
                raise PermissionDenied() from exc
            raise TransportError(name[:40], transient=False) from exc

    def provenance(self) -> dict | None:
        seqs = getattr(self._conn, "last_evidence", None)
        return {"gateway_evidence_seqs": list(seqs)} if seqs else None


class ArgvRunnerTransport:
    """``runner(argv: list[str]) -> object with .stdout`` (the gateway ``PeerRunner``) or a plain string; no shell is involved."""

    def __init__(self, runner, *, label: str = "argv"):
        self._runner, self._label = runner, label

    def execute(self, rendered) -> str:
        if not isinstance(rendered, (tuple, list)):
            raise CommandNotAllowed("argv transport takes argv tuples")
        try:
            result = self._runner(list(rendered))
        except TimeoutError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise TransportError(exc.__class__.__name__[:40], transient=False) from exc
        text = getattr(result, "stdout", result)
        code = getattr(result, "returncode", 0)
        if code not in (0, None) and not str(text).strip():
            raise TransportError("COMMAND_FAILED", transient=False)
        return str(text)


class GatewayTransport:
    """Read-only CLI through the trusted execution gateway (fixtures only).  Uses the gateway ``show`` kind for EOS/IOS XE and ``peer`` argv
    for FRR; the ``config`` kind is NEVER invoked.  ``provenance()`` returns the gateway evidence sequence numbers recorded for this
    transport, the fixture id and source pin -- the only values that make a result *live* evidence."""

    def __init__(self, gateway, fixture_id: str, node: str, platform: str, *, pin_id: str | None = None, label: str | None = None):
        if GATEWAY_CLIENT_DIR not in sys.path:
            sys.path.insert(0, GATEWAY_CLIENT_DIR)
        import aiorch_gw   # pylint: disable=import-error,import-outside-toplevel  # noqa: PLC0415 - the gateway client exists only inside an orchestrator sandbox
        self._gw_error = aiorch_gw.GatewayError
        self.fixture_id, self.node, self.pin_id, self.platform = fixture_id, node, pin_id, platform
        self._seqs: list[int] = []
        if platform in ("ceos", "iosxe"):
            self._conn = aiorch_gw.NetmikoAdapter(gateway, fixture_id, node, pin_id=pin_id, label=label)
            self._peer = None
        else:
            self._conn = None
            self._peer = aiorch_gw.PeerRunner(gateway, fixture_id, node)

    def execute(self, rendered) -> str:
        try:
            if self._conn is not None:
                if not isinstance(rendered, str):
                    raise CommandNotAllowed("network CLI takes strings")
                before = len(self._conn.last_evidence)
                out = self._conn.send_command(rendered)
                self._seqs.extend(self._conn.last_evidence[before:])
                return out
            if not isinstance(rendered, (tuple, list)):
                raise CommandNotAllowed("peer takes argv")
            result = self._peer(list(rendered))
            if getattr(result, "evidence_seq", None) is not None:
                self._seqs.append(result.evidence_seq)
            return str(getattr(result, "stdout", result))
        except self._gw_error as exc:
            text = str(exc).lower()
            if "allowlist" in text or "not allowed" in text or "refused" in text:
                raise PermissionDenied() from exc
            raise TransportError("GATEWAY_ERROR", transient=False) from exc

    def provenance(self) -> dict:
        return {"live": True, "fixture_id": self.fixture_id, "node": self.node, "pin_id": self.pin_id, "gateway_evidence_seqs": list(self._seqs)}
