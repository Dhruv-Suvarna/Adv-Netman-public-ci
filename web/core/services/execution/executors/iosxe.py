"""Cisco IOS XE (Catalyst 8000V) executor: one Netmiko configuration-mode session, captured running-config inverse.

IOS XE is not IOS XR and shares no code path with it.  Evidence (isolated Catalyst 8000V, IOS XE 17.06.01a):

* apply            the Configlet's own rendered lines in configuration mode; rejection is detected from the device's
                   ``%`` error markers.  IOS XE configuration mode is NOT transactional, so a rejected Configlet may
                   leave earlier lines applied (``partial_effects``) and is always compensated.
* previous state   the sanitized running configuration, read through the same session immediately before THIS
                   Configlet is applied.
* inverse          a block that did not exist is removed as a whole (``no interface Loopback44``, ``no ip route ...``).
                   Under an interface that already existed, each line the Configlet introduces is negated on its own
                   and every captured line is then re-sent verbatim, which restores replaced values and leaves lines
                   NMAS does not model untouched.  A top-level line that would replace a configured value, or a
                   captured section holding a redacted value, has no provable inverse and fails closed.
* restoration      after compensation the running configuration must be identical to the capture (volatile banner
                   lines aside); anything else is COMPENSATION_FAILED / STATE_NOT_RESTORED.
* management path  IOS XE has no transactional commit here, so a Configlet that replaces the primary IPv4 address,
                   shuts down or re-homes the interface this very SSH session terminates on is REFUSED at preflight
                   (``MANAGEMENT_SESSION_AT_RISK``): the session that would have to deliver compensation would be gone.
* persistence      running configuration only; ``write memory`` is never issued.
"""

from __future__ import annotations

import re

from ... import nsot_live
from ..codes import device_timeout_seconds
from . import state
from .base import APPLY, REFUSE, SKIP_SATISFIED, ApplyOutcome, Assessment, CompensationOutcome, ConfigletSpec, DeviceExecutor, ExecutorError
from .ceos import _config_blocks, _stem

PLATFORM = "cisco_c8000v_iosxe"
OBJECT_TYPES = frozenset({"interface", "address", "static_route"})
REJECTIONS = ("% Invalid input", "% Incomplete command", "% Ambiguous command", "% Error", "% Bad ", "overlaps with",
              "% Unrecognized")
VOLATILE = ("Building configuration", "Current configuration", "! Last configuration change", "! NVRAM config last updated")


def netmiko_connection(device: dict):
    """One privileged-EXEC Netmiko session to an inventory-managed IOS XE device; failures are sanitized codes."""
    target = nsot_live.get_live_target(device.get("name", ""), purpose="WRITE")
    if target is None or target.get("platform") != PLATFORM:
        raise ExecutorError("NOT_CONFIGURED")
    try:
        from netmiko import ConnectHandler
        from netmiko.exceptions import NetmikoAuthenticationException, NetmikoTimeoutException
    except ImportError as exc:  # pragma: no cover - netmiko is a project dependency
        raise ExecutorError("CONNECTION_FAILED") from exc
    timeout = device_timeout_seconds()
    try:
        conn = ConnectHandler(device_type="cisco_xe", host=target["address"], username=target["username"],
                              password=target["password"], secret=target["password"], conn_timeout=timeout,
                              auth_timeout=timeout, banner_timeout=timeout, **target.get("ssh_auth", {}))
        if not conn.check_enable_mode():
            conn.enable()
        return conn
    except NetmikoAuthenticationException as exc:
        raise ExecutorError("AUTH_FAILED") from exc
    except NetmikoTimeoutException as exc:
        raise ExecutorError("TIMEOUT") from exc
    except Exception as exc:  # noqa: BLE001 - never relay connection details
        raise ExecutorError("CONNECTION_FAILED") from exc


def stable_config(text: str) -> str:
    """Running configuration without the banner lines that change on every read or every change."""
    return "\n".join(line.rstrip() for line in (text or "").splitlines()
                     if line.strip() and not line.startswith(VOLATILE) and line.strip() not in ("!", "end"))


_SSH_LOCAL = re.compile(r"^\S+\s+(\d+\.\d+\.\d+\.\d+)\.22\s+\S+\s+ESTAB", re.M)


def session_interfaces(tcp_text: str, running_text: str) -> set[str]:
    """Interfaces (lower-case) owning a local address that an established inbound SSH session terminates on."""
    local = set(_SSH_LOCAL.findall(tcp_text or ""))
    return {header.lower() for header, children in _config_blocks(running_text.splitlines())
            if header.startswith("interface ") and any(
                child.split()[:2] == ["ip", "address"] and len(child.split()) > 2 and child.split()[2] in local for child in children)}


def endangers_session(spec_lines, interfaces: set[str]) -> bool:
    for header, children in _config_blocks(spec_lines):
        if header.lower() in interfaces and any(
                (text := child.strip()) in ("shutdown", "no ip address") or text.removeprefix("no ").startswith("vrf forwarding")
                or (text.startswith("ip address ") and not text.endswith(" secondary")) for child in children):
            return True
        if header.lower().removeprefix("no ") in interfaces and header.lower().startswith("no "):
            return True
    return False


def _negate(line: str) -> str:
    return line[3:] if line.startswith("no ") else f"no {line}"


def config_inverse(spec_lines, running_text: str) -> list[str] | None:
    """Exact inverse of a Configlet relative to the captured configuration: [] when satisfied, None when unprovable."""
    running: dict[str, list[str]] = {}
    for header, children in _config_blocks(running_text.splitlines()):
        running.setdefault(header, []).extend(child.strip() for child in children)
    present = {key.lower() for key in running}
    undo: list[list[str]] = []
    for header, children in _config_blocks(spec_lines):
        if header.lower() not in present:
            if header.startswith("no "):
                return None
            if not children and any(other.lower().startswith(_stem(header).lower()) for other in running):
                return None                                   # would replace a configured value of the same command
            undo.append([f"no {header}"])
            continue
        if not children:
            continue                                          # the top-level line is already configured
        captured = next(lines for key, lines in running.items() if key.lower() == header.lower())
        held = {line.lower() for line in captured}
        if any("<REDACTED" in line for line in captured):
            return None
        new = []
        for child in (child.strip() for child in children):
            # IOS XE does not display defaults: ``no X`` is satisfied whenever X is not configured.
            satisfied = _negate(child).lower() not in held if child.startswith("no ") else child.lower() in held
            if not satisfied and child not in new:
                new.append(child)
        if new:
            undo.append([header, *(f" {_negate(line)}" for line in reversed(new)), *(f" {line}" for line in captured)])
    return [line for block in reversed(undo) for line in block]


class IosXeExecutor(DeviceExecutor):
    platform = PLATFORM

    def __init__(self, device: dict, *, connection_factory=None, reader=None):
        self._device = device
        self._connection_factory = connection_factory or netmiko_connection
        self._reader = reader                               # accepted for registry symmetry; state comes from the session
        self._conn = None
        self._inverses: dict[str, list[str]] = {}
        self._applied: dict[str, str] = {}
        self._session_interfaces: set[str] | None = None

    def _management_interfaces(self, running_text: str) -> set[str]:
        if self._session_interfaces is None:
            try:
                self._session_interfaces = session_interfaces(self._conn.send_command("show tcp brief", read_timeout=30), running_text)
            except Exception:  # noqa: BLE001 - the management path could not be determined: nothing is assumed safe
                raise ExecutorError("PREVIOUS_STATE_UNAVAILABLE") from None
        return self._session_interfaces

    def connect(self) -> None:
        self._conn = self._connection_factory(self._device)

    def close(self) -> None:
        if self._conn is not None:
            try:
                self._conn.disconnect()
            except Exception:  # noqa: BLE001
                pass
            self._conn = None

    def _config_text(self) -> str:
        from ...bundles.legacy_sanitize import SanitizeError, sanitize_config

        if self._conn is None:
            raise ExecutorError("PREVIOUS_STATE_UNAVAILABLE")
        try:
            text = stable_config(sanitize_config(self._conn.send_command("show running-config", read_timeout=120)).text)
        except SanitizeError:
            raise ExecutorError("PREVIOUS_STATE_UNAVAILABLE") from None
        except Exception:  # noqa: BLE001 - reduced to a fixed code
            raise ExecutorError("PREVIOUS_STATE_UNAVAILABLE") from None
        if "interface " not in text:
            raise ExecutorError("PREVIOUS_STATE_UNAVAILABLE")    # not a running configuration: never treat it as empty
        return text

    def running_config_digest(self) -> str:
        from ...bundles import canonical

        return canonical.text_hash(self._config_text())

    def assess(self, spec: ConfigletSpec) -> Assessment:
        if spec.origin != "STRUCTURED" or not spec.lines or spec.object_type not in OBJECT_TYPES:
            return Assessment(REFUSE, False, {}, spec.integrity_error or "PLATFORM_EXECUTION_UNSUPPORTED")
        from ...bundles import canonical

        text = self._config_text()
        if endangers_session(list(spec.lines), self._management_interfaces(text)):
            return Assessment(REFUSE, False, {"kind": "config_block", "management_interface": True}, "MANAGEMENT_SESSION_AT_RISK")
        inverse = config_inverse(list(spec.lines), text)
        facts = {"kind": "config_block", "modelled": False}
        if inverse is None:
            return Assessment(APPLY, False, facts, state.COMPENSATION_NOT_PROVABLE)
        facts["config_digest"] = canonical.text_hash(text)
        if not inverse:
            return Assessment(SKIP_SATISFIED, True, facts)
        self._inverses[spec.cfg_id] = inverse
        return Assessment(APPLY, True, facts)

    def _send(self, lines) -> ApplyOutcome:
        commands = [line.strip() for line in lines if line.strip()]
        try:
            output = self._conn.send_config_set(commands, cmd_verify=True, read_timeout=120)
        except Exception as exc:  # noqa: BLE001 - reduced to a fixed category; the exception text is never used
            try:
                self._conn.exit_config_mode()
            except Exception:  # noqa: BLE001
                pass
            code = "TIMEOUT" if "imeout" in exc.__class__.__name__ else "TRANSPORT_ERROR"
            return ApplyOutcome(False, code, partial_effects=True, lines_sent=len(commands))
        if any(marker in (output or "") for marker in REJECTIONS):
            return ApplyOutcome(False, "COMMAND_REJECTED", partial_effects=True, lines_sent=len(commands))
        return ApplyOutcome(True, lines_sent=len(commands))

    def apply(self, spec: ConfigletSpec, assessment: Assessment) -> ApplyOutcome:
        # Preflight ran before any Configlet of the plan was applied: capture the configuration as it is NOW.
        from ...bundles import canonical

        try:
            text = self._config_text()
        except ExecutorError as exc:
            return ApplyOutcome(False, exc.code)
        inverse = config_inverse(list(spec.lines), text)
        if inverse is None or endangers_session(list(spec.lines), self._session_interfaces or set()):
            return ApplyOutcome(False, "COMMAND_REJECTED")      # nothing sent: no inverse is provable any more
        self._inverses[spec.cfg_id], self._applied[spec.cfg_id] = inverse, canonical.text_hash(text)
        if not inverse:
            return ApplyOutcome(True, lines_sent=0)
        return self._send(spec.lines)

    def compensate(self, spec: ConfigletSpec, assessment: Assessment) -> CompensationOutcome:
        wanted = self._applied.get(spec.cfg_id) or assessment.previous_state.get("config_digest")
        inverse = self._inverses.get(spec.cfg_id)
        try:
            if wanted and self.running_config_digest() == wanted:
                return CompensationOutcome("COMPENSATED", detail={"action": "NONE_NEEDED"})
            if not wanted or not inverse:
                return CompensationOutcome("COMPENSATION_FAILED", "UNSUPPORTED")
            sent = self._send(inverse)
            if not sent.ok:
                return CompensationOutcome("COMPENSATION_FAILED", sent.error_code)
            if self.running_config_digest() != wanted:
                return CompensationOutcome("COMPENSATION_FAILED", "STATE_NOT_RESTORED")
        except ExecutorError as exc:
            return CompensationOutcome("COMPENSATION_UNVERIFIED", exc.code)
        return CompensationOutcome("COMPENSATED", detail={"action": "INVERSE_APPLIED", "commands": len(inverse)})
