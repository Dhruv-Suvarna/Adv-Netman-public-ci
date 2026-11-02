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
import time

from ... import nsot_live
from ..codes import device_timeout_seconds
from . import state
from .base import APPLY, REFUSE, SKIP_SATISFIED, ApplyOutcome, Assessment, CompensationOutcome, ConfigletSpec, DeviceExecutor, ExecutorError
from .ceos import _config_blocks, _stem

PLATFORM = "cisco_c8000v_iosxe"
ROUTING_TYPES = frozenset({"routing_rip", "routing_ospf", "routing_bgp", "routing_binding", "bgp_neighbor", "bgp_neighbor_af",
                           "bgp_network"})
OBJECT_TYPES = frozenset({"interface", "address", "static_route", *ROUTING_TYPES})
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


# A running-configuration read is retried while the device prefixes it with a notice.  Measured on 17.06.01a: after
# ``no address-family ipv4`` the "Topology ... is currently being deconfigured" notice stays for ~61 s, then the display is
# exactly the pre-change configuration.  The budget (~100 s) covers that with margin and then fails closed.
READ_ATTEMPTS, READ_RETRY_SECONDS = 50, 2.0
_NOTICE = re.compile(r"^%", re.M)


def in_transition(text: str) -> bool:
    """True when a running-configuration read carries a device notice line (``%...``), which is never configuration."""
    return bool(_NOTICE.search(text or ""))


def stable_config(text: str) -> str:
    """Running configuration without the banner lines that change on every read or every change."""
    return "\n".join(line.rstrip() for line in (text or "").splitlines()
                     if line.strip() and not line.startswith(VOLATILE) and line.strip() not in ("!", "end"))


# The TCP table WITHOUT name resolution: plain ``show tcp brief`` reverse-resolves every foreign address (about 8 s each
# with no reachable DNS server, 17.06.01a), which pushes the read past its timeout as soon as a few connections exist.
TCP_SESSIONS_COMMAND = "show tcp brief numeric"
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


_SECTION_END = "exit-address-family"
# Global switches that enable a feature and carry no value: their ``no`` form is their exact inverse, and an unrelated line
# that merely shares the first word (``ipv6 route ...`` beside ``ipv6 unicast-routing``) is not a replaced value.
GLOBAL_SWITCHES = frozenset({"ipv6 unicast-routing", "ip routing", "ip multicast-routing"})
# Negations IOS XE DISPLAYS because they turn off a default-on behaviour (17.06.01a): such a line is satisfied only when it
# is shown, and its positive form is its inverse.  Every other ``no X`` is satisfied whenever X is not configured.
DISPLAYED_NEGATIONS = frozenset({"no bgp default ipv4-unicast"})
_BGP_FAMILIES = ("address-family ipv4", "address-family ipv6")


def _sections(children) -> dict[str, list[str]]:
    """Child lines of one block, grouped by nested ``address-family`` section (key "" holds the block's own lines).

    IOS XE changes configuration mode by command, not by indentation: a section runs from its ``address-family`` line to
    ``exit-address-family``.  Keys are the lower-cased section headers."""
    sections: dict[str, list[str]] = {"": []}
    current = ""
    for raw in children:
        text = raw.strip()
        if text.lower().startswith("address-family "):
            current = text.lower()
            sections.setdefault(current, [])
        elif text.lower() == _SECTION_END:
            current = ""
        elif text:
            sections[current].append(text)
    return sections


def _new_lines(wanted: list[str], held: set[str]) -> list[str]:
    new = []
    for child in wanted:
        # IOS XE does not display defaults: ``no X`` is satisfied whenever X is not configured -- except a displayed negation.
        if child.startswith("no ") and child.lower() not in DISPLAYED_NEGATIONS:
            satisfied = _negate(child).lower() not in held
        else:
            satisfied = child.lower() in held
        if not satisfied and child not in new:
            new.append(child)
    return new


def _emptied_sections(header: str, held: dict[str, list[str]]) -> list[str]:
    """``router bgp`` address-family sections the captured block did not display, removed again by the inverse.

    IOS XE keeps an address-family section it once entered on display even after its last line is negated (an empty
    ``address-family ipv4`` / ``exit-address-family`` pair), so negating the Configlet's lines alone does not restore the
    captured display.  The section held no configuration at capture time, so ``no address-family`` removes only what the
    Configlet introduced.  With ``bgp default ipv4-unicast`` in effect an absent IPv4 section still means implicitly
    activated neighbors, so the IPv4 section is only removed under ``no bgp default ipv4-unicast``."""
    if not header.lower().startswith("router bgp "):
        return []
    explicit_v4 = "no bgp default ipv4-unicast" in {line.lower() for line in held.get("", [])}
    return [f" no {family}" for family in _BGP_FAMILIES
            if family not in held and (family.endswith("ipv6") or explicit_v4)]


def config_inverse(spec_lines, running_text: str) -> list[str] | None:
    """Exact inverse of a Configlet relative to the captured configuration: [] when satisfied, None when unprovable.

    Under a block that already exists, every line the Configlet introduces is negated in its own section (the
    ``address-family`` sections of ``router bgp`` first, then the block's own lines, so an activation is never negated
    after its neighbor is gone) and the captured block is then re-sent verbatim, which puts back any value a negation or
    the Configlet itself replaced."""
    running: dict[str, list[str]] = {}
    for header, children in _config_blocks(running_text.splitlines()):
        running.setdefault(header, []).extend(children)
    present = {key.lower() for key in running}
    undo: list[list[str]] = []
    for header, children in _config_blocks(spec_lines):
        if header.lower() not in present:
            if header.startswith("no "):
                return None
            if not children and header.strip().lower() not in GLOBAL_SWITCHES \
                    and any(other.lower().startswith(_stem(header).lower()) for other in running):
                return None                                   # would replace a configured value of the same command
            undo.append([f"no {header}"])
            continue
        if not children:
            continue                                          # the top-level line is already configured
        captured_raw = next(lines for key, lines in running.items() if key.lower() == header.lower())
        captured = [line.strip() for line in captured_raw]
        if any("<REDACTED" in line for line in captured):
            return None
        held, wanted = _sections(captured_raw), _sections(children)
        negations: list[str] = []
        for section in [key for key in wanted if key] + [""]:
            new = _new_lines(wanted[section], {line.lower() for line in held.get(section, [])})
            if any(line.startswith("no ") for line in new) and section:
                return None                                   # a negated value inside a nested section is never modelled
            if not new:
                continue
            body = [f" {_negate(line)}" for line in reversed(new)]
            negations.extend([f" {section}", *body, f" {_SECTION_END}"] if section else body)
        if negations:
            undo.append([header, *negations, *_emptied_sections(header, held), *(f" {line}" for line in captured)])
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
                self._session_interfaces = session_interfaces(self._conn.send_command(TCP_SESSIONS_COMMAND, read_timeout=30), running_text)
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
        """The stable running configuration.  A read that carries a device notice (``% ...``, e.g. "Topology ... is
        currently being deconfigured" while IOS XE removes an address family asynchronously) is a configuration in
        transition: it is read again, and if the notice persists the state is unavailable rather than guessed."""
        from ...bundles.legacy_sanitize import SanitizeError, sanitize_config

        if self._conn is None:
            raise ExecutorError("PREVIOUS_STATE_UNAVAILABLE")
        for attempt in range(READ_ATTEMPTS):
            try:
                text = stable_config(sanitize_config(self._conn.send_command("show running-config", read_timeout=120)).text)
            except SanitizeError:
                raise ExecutorError("PREVIOUS_STATE_UNAVAILABLE") from None
            except Exception:  # noqa: BLE001 - reduced to a fixed code
                raise ExecutorError("PREVIOUS_STATE_UNAVAILABLE") from None
            if not in_transition(text):
                break
            if attempt + 1 < READ_ATTEMPTS:
                time.sleep(READ_RETRY_SECONDS)
        else:
            raise ExecutorError("PREVIOUS_STATE_UNAVAILABLE")
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
