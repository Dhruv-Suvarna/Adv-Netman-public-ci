"""cEOS executor: Netmiko configuration mode, the SAME mechanism ``master.py::push_eos`` uses for every EOS device.

Evidence for each design choice:

* target / credentials   ``nsot_live.get_live_target`` (inventory in legacy mode, selected path credential source in Phase 4).
                         Credentials go straight into the SSH connector; they are never stored, logged or echoed,
                         and every exception is reduced to a fixed code -- Netmiko exceptions can echo connection parameters.
* command flattening     ``modules.eos_render.eos_commands`` (indentation -> explicit ``exit``s), exactly as ``push_eos``.
* apply                  enable, ``configure terminal``, ``send_config_set(..., cmd_verify=True)``, rejection detected by the same
                         four EOS error strings ``push_eos`` checks, then leave configuration mode.
* NO ``write memory``    ``apply`` and ``compensate`` change the RUNNING configuration only.  Durable persistence is deliberately
                         not part of a Complete transaction or a UAT scope (it belongs to the later Golden/Probation phases), so
                         a reload reverts an unpersisted change.  This is reported as a limitation, not hidden.  The one
                         exception is ``save_startup``, which nothing in the general engine calls: the route-shield transition
                         lifecycle sends it once per device after verifying exactly what is running, and reads it back.
* read / verify          the Phase-15 read path (``health.live.read_device``) -- injected as ``reader`` so tests need no device.
"""

from __future__ import annotations

import ipaddress
import re
import sys
from contextlib import suppress

from django.conf import settings

from ... import nsot_live
from ...health import live
from ..codes import device_timeout_seconds
from . import state
from .base import APPLY, SKIP_SATISFIED, ApplyOutcome, Assessment, CompensationOutcome, ConfigletSpec, DeviceExecutor, ExecutorError, REFUSE

# master.py push_eos, plus "% Unavailable command": EOS refuses a command the running platform does not offer with that marker
# (live, V2 Phase 9: ``router rip`` before cEOS has made RIP available).  Without it a refused command was reported as applied.
REJECTIONS = ("% Invalid input", "% Incomplete command", "% Ambiguous command", "% Error", "% Unavailable command")


def _eos_commands(lines) -> list[str]:
    root = str(settings.REPO_ROOT)
    if root not in sys.path:
        sys.path.insert(0, root)
    from modules.eos_render import eos_commands  # the exact flattening master.py uses

    return eos_commands("\n".join(lines))


def _commands_for(spec, lines) -> list[str]:
    """master.py's flattening for every object, except management-VRF Configlets (nested blocks, see structural_commands)."""
    return structural_commands(lines) if spec.object_type in MANAGEMENT_TYPES else _eos_commands(lines)


def netmiko_connection(device: dict):
    """One privileged-EXEC Netmiko session.  Every failure is a sanitized ExecutorError."""
    target = nsot_live.get_live_target(device["name"], purpose="WRITE", platform="ceos")
    if target is None or target.get("platform") != "ceos":
        raise ExecutorError("NOT_CONFIGURED")
    try:
        from ...management.ssh_transport import connect_eos
        from netmiko.exceptions import NetmikoAuthenticationException, NetmikoTimeoutException
    except ImportError as exc:  # pragma: no cover - netmiko is a project dependency
        raise ExecutorError("CONNECTION_FAILED") from exc
    timeout = device_timeout_seconds()
    try:
        conn = None
        auth_error = None
        for auth in target.get("auth_candidates", ({
            "username": target["username"], "password": target["password"], "ssh_auth": target.get("ssh_auth", {}),
        },)):
            try:
                conn = connect_eos(target, auth, timeout)
                break
            except NetmikoAuthenticationException as exc:
                auth_error = exc
        if conn is None:
            raise auth_error or NetmikoAuthenticationException("authentication failed")
        if not conn.check_enable_mode():
            conn.enable()
        return conn
    except NetmikoAuthenticationException as exc:
        if conn is not None:
            with suppress(Exception):
                conn.disconnect()
        raise ExecutorError("AUTH_FAILED") from exc
    except NetmikoTimeoutException as exc:
        if conn is not None:
            with suppress(Exception):
                conn.disconnect()
        raise ExecutorError("TIMEOUT") from exc
    except Exception as exc:  # noqa: BLE001 - never relay connection details
        if conn is not None:
            with suppress(Exception):
                conn.disconnect()
        raise ExecutorError("CONNECTION_FAILED") from exc


def inverse_lines(spec: ConfigletSpec) -> list[str] | None:
    """The EXACT inverse of an additive Configlet, or None when none is provable.

    * ``address`` / ``static_route``  the Configlet's own leaf line prefixed with ``no`` under its own block header(s);
    * ``interface``                   ``no interface X`` -- only for a block whose sole top-level line is that interface header
                                      (a Configlet that also creates a VLAN etc. cannot be proven restored by the read groups).
    """
    lines = [line for line in spec.lines]
    if not lines:
        return None
    if spec.object_type == "interface":
        top = [line for line in lines if not line.startswith(" ")]
        if len(top) != 1 or not top[0].startswith("interface "):
            return None
        return [f"no {top[0]}"]
    if spec.object_type == "static_route":
        top = [line for line in lines if not line.startswith(" ")]
        return [f"no {top[0]}"] if len(top) == 1 and len(lines) == 1 else None
    if spec.object_type == "address":
        leaf = lines[-1]
        if not leaf.startswith(" ") or len([ln for ln in lines if not ln.startswith(" ")]) != 1:
            return None
        headers = [ln for ln in lines if not ln.startswith(" ")]
        return [*headers, f"   no {leaf.strip()}"]
    return None


# Object types with no modelled operational state.  Their exact compensation is proven differently: the inverse is derived
# against the running configuration captured BEFORE apply, and compensation only succeeds when the running configuration
# is byte-for-byte (comment lines aside) the captured one again.
# Routing objects use the same captured running-config inverse.  A new process
# may be removed as a whole only when its header was absent before apply;
# modifications beneath an existing process remove only provably additive lines.
CONFIG_BLOCK_TYPES = frozenset({"acl", "acl_attachment", "dhcp_relay", "fhrp", "routing_rip", "routing_ospf", "routing_isis",
                                "routing_bgp", "routing_binding", "bgp_neighbor", "bgp_neighbor_af", "bgp_network",
                                # a statement of the route-shield workflow (temporary cover / floating static routes): never
                                # judged from the routing table, where a floating copy of an installed route is invisible
                                "route_shield",
                                # V2 Phase 5: a trusted-upstream isolation statement (ACL definition / attachment / OSPF passive
                                # interface), carrying its own exact inverse and presence paths like a route-shield statement
                                "isolation",
                                # V2 Phase 9: a DHCP relay option 82 statement, inverted against the relay's own pre-change read-back
                                "dhcp_relay_option82"})
DECLARED_INVERSE_TYPES = frozenset({"route_shield", "isolation", "dhcp_relay_option82"})


# Single-valued interface settings whose replacement has an exact inverse: re-applying the one captured line.  Proven on
# cEOS 4.36.2F for the IS-IS interface metric (the running configuration is byte-identical after the restore).  Every other
# replacement of a configured value stays unprovable and is refused.
RESTORABLE_STEMS = frozenset({"isis metric "})

# Child statements whose ``no`` form is itself stored as an explicit override, so only ``default`` returns to the prior state.
# Proven on cEOS 4.36.2F: ``router ospf N / no passive-interface X`` is kept as ``no passive-interface X`` in the running
# configuration; ``default passive-interface X`` leaves it byte-identical to before the statement was added.
DEFAULT_RESTORED_STEMS = ("passive-interface ",)
# Child commands of which a block holds one line per value: a new line coexists with its siblings and never replaces one.
COEXISTING_STEMS = ("passive-interface ",)
# One-value commands of which a block holds one line per value: ``router rip`` / ``router bgp`` keep every
# ``network <prefix>`` line and ``no network <prefix>`` removes only that one (proven on cEOS 4.36.2F, Lab 8 R7).  Only the
# bare two-token form coexists; ``network <prefix> area <id>`` keeps its prefix-specific stem and its replacement guard.
COEXISTING_VALUE_COMMANDS = frozenset({"network"})
# Paired child statements that replace each other in place: under ``router rip`` cEOS 4.36.2F stores ``shutdown`` when the
# process is suspended and ``no shutdown`` when it runs; re-applying the captured line restores it byte-identically
# (aborted configuration session on the isolated Lab 8 R7).  Only an exact captured partner makes the toggle provable.
TOGGLED_CHILDREN = {"no shutdown": "shutdown", "shutdown": "no shutdown"}


def _coexists(text: str) -> bool:
    words = text.split()
    return text.startswith(COEXISTING_STEMS) or (len(words) == 2 and words[0] in COEXISTING_VALUE_COMMANDS)


def child_negation(text: str) -> str:
    """The statement that undoes one added child line: ``default <line>`` for ``DEFAULT_RESTORED_STEMS``, else ``no <line>``."""
    text = text.strip()
    return f"default {text}" if text.startswith(DEFAULT_RESTORED_STEMS) else f"no {text}"


def _config_blocks(lines) -> list[tuple[str, list[str]]]:
    blocks: list[tuple[str, list[str]]] = []
    for line in lines:
        if not line.strip() or line.lstrip().startswith("!"):
            continue
        if not line.startswith(" "):
            blocks.append((line.rstrip(), []))
        elif blocks:
            blocks[-1][1].append(line.rstrip())
    return blocks


def _state_digest(text: str) -> str:
    """The configured state of a running configuration: comment lines dropped (``CeosExecutor.config_state_digest``)."""
    from ...bundles import canonical

    return canonical.text_hash("\n".join(line.rstrip() for line in text.splitlines() if line.strip() and not line.lstrip().startswith("!")))


def own_lines_present(spec_lines, running_text: str, before_text: str) -> bool:
    """Does the running configuration hold a line of this Configlet that the configuration it found did not (a top-level line,
    or a child under its header)?  Only such a line is this Configlet's own effect, which its inverse removes."""
    def index(text):
        found = set()
        for header, kids in _config_blocks(text.splitlines()):
            found.add((header, None))
            found.update((header, kid.strip()) for kid in kids)
        return found

    now, then = index(running_text), index(before_text)
    header = None
    for line in spec_lines:
        if not line.strip() or line.lstrip().startswith("!"):
            continue
        key = (line.rstrip(), None) if not line.startswith(" ") else (header, line.strip())
        if not line.startswith(" "):
            header = line.rstrip()
        if key in now and key not in then:
            return True
    return False


def _stem(line: str) -> str:
    return line.strip().rsplit(" ", 1)[0] + " "


def config_inverse(spec_lines, running_text: str) -> list[str] | None:
    """The exact inverse of additive configuration lines relative to ``running_text``, or None when none is provable.

    * a block whose header is absent is undone by ``no <header>``;
    * under an existing header only new, non-nested, non-negated child lines that do not replace a sibling of the same
      command stem are undone, each by its own ``no`` form; a ``RESTORABLE_STEMS`` line that replaces exactly one sibling
      is undone by re-applying that captured sibling;
    * a top-level line whose explicit negation is configured is undone by that negation.
    Lines already present are left alone.  Anything else (replacement, nested change of an existing block) is unprovable.
    """
    running = dict()
    for header, children in _config_blocks(running_text.splitlines()):
        running.setdefault(header, []).extend(child.strip() for child in children)
    undo: list[list[str]] = []
    for header, children in _config_blocks(spec_lines):
        if header not in running:
            if header.startswith("no "):
                return None
            if not children and f"no {header}" not in running and any(
                    other.startswith(_stem(header)) for other in running if " " in header.strip()):
                return None                                   # would replace a configured value of the same command
            undo.append([f"no {header}"])
            continue
        new = [child for child in children if child.strip() not in running[header]]
        if not new:
            continue
        if any(len(child) - len(child.lstrip()) != len(new[0]) - len(new[0].lstrip()) for child in new):
            return None                                       # nested change inside an existing block
        restore = []
        for child in new:
            text = child.strip()
            if TOGGLED_CHILDREN.get(text) in running[header]:
                restore.append(f"   {TOGGLED_CHILDREN[text]}")   # put the captured partner back
                continue
            prior = [] if _coexists(text) else [existing for existing in running[header] if existing.startswith(_stem(text))]
            if text.startswith("no "):
                return None
            if prior:
                if _stem(text) not in RESTORABLE_STEMS or len(prior) != 1:
                    return None
                restore.append(f"   {prior[0]}")                # a single-valued setting: put the captured value back
            else:
                restore.append(f"   {child_negation(text)}")
        undo.append([header, *reversed(restore)])
    return [line for block in reversed(undo) for line in block]   # dependants are removed before what they reference


# V2 Phase 4 -- management VRF.  The VRF definition, VRF routes and VRF services are configuration blocks inverted against the
# captured running configuration (``management_inverse``: it also understands the nested ``management ssh / vrf X / no
# shutdown`` sub-blocks, which ``config_inverse`` refuses); the interface binding is a snapshot type, because a VRF change
# discards the interface's addresses and only the captured-section inverse restores them exactly.
MANAGEMENT_BLOCK_TYPES = frozenset({"mgmt_vrf", "mgmt_vrf_route", "mgmt_vrf_service"})
CONFIG_BLOCK_TYPES = CONFIG_BLOCK_TYPES | MANAGEMENT_BLOCK_TYPES
MANAGEMENT_TYPES = MANAGEMENT_BLOCK_TYPES | {"mgmt_vrf_binding"}
SINGLE_VALUED_VRF_STEMS = ("logging vrf {vrf} source-interface ",)
SINGLE_VALUED_CHILDREN = frozenset({"description"})


def _tree(lines) -> list[dict]:
    root: list[dict] = []
    stack: list[tuple[int, list]] = [(-1, root)]
    for raw in lines:
        if not raw.strip() or raw.strip().startswith("!"):
            continue
        indent = len(raw) - len(raw.lstrip(" "))
        node = {"line": raw.strip(), "children": []}
        while stack[-1][0] >= indent:
            stack.pop()
        stack[-1][1].append(node)
        stack.append((indent, node["children"]))
    return root


def _render_tree(nodes, depth: int = 0) -> list[str]:
    out = []
    for node in nodes:
        out.append(" " * (3 * depth) + node["line"])
        out.extend(_render_tree(node["children"], depth + 1))
    return out


def structural_commands(lines) -> list[str]:
    """Flatten indented EOS text with an explicit ``exit`` after every block that has children (nesting is taken from the
    indentation itself, so ``management ssh / vrf X / no shutdown`` needs no prefix list).  Used for management-VRF
    Configlets only; every other object keeps master.py's exact flattening."""
    commands: list[str] = []

    def walk(nodes):
        for node in nodes:
            commands.append(node["line"])
            if node["children"]:
                walk(node["children"])
                commands.append("exit")

    walk(_tree([line for line in lines if line.strip() not in ("configure", "configure terminal", "end")]))
    return commands


def management_inverse(spec_lines, running_text: str) -> list[str] | None:
    """The exact inverse of additive management-VRF configuration relative to ``running_text`` ([] = already present,
    None = unprovable).

    * a top-level line / block absent from the running configuration is undone by ``no <header>``;
    * under an existing header, an absent child (leaf or sub-block) is undone by ``no <child>`` under that header; a
      present sub-block whose own children differ is unprovable (it would be a modification, not an addition);
    * a single-valued per-VRF setting (``logging vrf X source-interface``) that replaces another value is unprovable.
    """
    running = {node["line"]: node for node in _tree(running_text.splitlines())}
    undo: list[list[str]] = []
    for node in _tree(spec_lines):
        header = node["line"]
        if header.startswith("no "):
            return None
        for template in SINGLE_VALUED_VRF_STEMS:
            parts = header.split()
            if len(parts) >= 3 and header.startswith(template.format(vrf=parts[2])):
                stem = template.format(vrf=parts[2])
                if any(other.startswith(stem) and other != header for other in running):
                    return None
        existing = running.get(header)
        if existing is None:
            undo.append([f"no {header}"])
            continue
        current = {child["line"]: child for child in existing["children"]}
        removals = []
        for child in node["children"]:
            found = current.get(child["line"])
            if found is None:
                first = child["line"].split()[0]
                if child["line"].startswith("no ") or (first in SINGLE_VALUED_CHILDREN and any(
                        line.split()[0] == first for line in current)):
                    return None                       # replaces a value the inverse could not restore
                removals.append(f"   no {child['line']}")
            elif _render_tree(child["children"]) and _render_tree(found["children"]) != _render_tree(child["children"]):
                wanted = set(_render_tree(child["children"]))
                if not wanted.issubset(set(_render_tree(found["children"]))):
                    return None
        if removals:
            undo.append([header, *reversed(removals)])
    return [line for block in reversed(undo) for line in block]


SNAPSHOT_TYPES = frozenset({"interface", "address", "mgmt_vrf_binding"})


def _snapshot_key(line: str) -> str | None:
    """What single-valued setting a child line configures; None for lines that coexist with their siblings."""
    text = line.strip().removeprefix("no ")
    if text.startswith("description"):
        return "description"
    if text.startswith("ipv6 address ") or text.endswith(" secondary"):
        return None
    if text in ("switchport", "shutdown"):
        return text
    return _stem(text)


def interface_snapshot_inverse(spec_lines, running_text: str) -> list[str] | None:
    """Captured-state inverse of interface configuration: [] when already satisfied, None when none is provable.

    An ``interface`` block that already exists is restored from the section captured before apply, never defaulted:

    * each new line that introduces a setting the captured section did not hold is undone on its own (``no <line>`` for
      a coexisting line such as an IPv6 or secondary address, ``default <setting>`` for a single-valued one);
    * then every captured child line is sent again, verbatim and in order.  Re-sending restores a replaced value
      (access VLAN, MTU, primary address) and anything the platform discarded as a side effect of a mode change, and
      is a no-op for lines that never changed.  Lines NMAS does not model are therefore preserved untouched.

    A captured section holding a redacted value cannot be re-sent and fails closed.  Everything that is not an
    existing interface block (a new SVI or subinterface, a VLAN) follows ``config_inverse``.
    """
    running = dict()
    for header, children in _config_blocks(running_text.splitlines()):
        running.setdefault(header, []).extend(child.strip() for child in children)
    undo: list[list[str]] = []
    for header, children in _config_blocks(spec_lines):
        if not (header.startswith("interface ") and header in running):
            generic = config_inverse([header, *children], running_text)
            if generic is None:
                return None
            if generic:
                undo.append(generic)
            continue
        captured = running[header]
        wanted = [child.strip() for child in children]
        if any(len(child) - len(child.lstrip()) != len(children[0]) - len(children[0].lstrip()) for child in children) \
                or any("<REDACTED" in line for line in captured):
            return None
        new = [line for line in wanted if line not in captured]
        if not new:
            continue
        block = [header]
        for line in reversed(new):
            key = _snapshot_key(line)
            if key is None:
                block.append(f"   no {line}")
            elif not any(_snapshot_key(old) == key for old in captured):
                block.append(f"   default {line.removeprefix('no ')}")
        undo.append(block + [f"   {line}" for line in captured])
    return [line for block in reversed(undo) for line in block]


class CeosExecutor(DeviceExecutor):
    platform = "arista_ceos"

    def __init__(self, device: dict, *, connection_factory=None, reader=None):
        self._device = device
        self._connection_factory = connection_factory or netmiko_connection
        self._reader = reader or live.read_device
        self._conn = None
        self._config_inverses: dict[str, list[str]] = {}   # cfg_id -> inverse derived at assess time (never persisted)
        self._config_applied: dict[str, str] = {}          # cfg_id -> configuration digest captured right before that apply
        self._config_found: dict[str, str] = {}            # cfg_id -> the (sanitized) configuration a modelled apply found

    # -- session --------------------------------------------------------------------------------------------------------
    def connect(self) -> None:
        self._conn = self._connection_factory(self._device)

    def close(self) -> None:
        if self._conn is not None:
            try:
                self._conn.disconnect()
            except Exception:  # noqa: BLE001
                pass
            self._conn = None

    def _read(self):
        evidence = self._reader(self._device)
        if not getattr(evidence, "live_reachable", False):
            raise ExecutorError("PREVIOUS_STATE_UNAVAILABLE")
        return evidence

    def _config_text(self) -> str:
        """The SANITIZED running configuration through this run's own session (privileged EXEC ``show`` only)."""
        from ...bundles.legacy_sanitize import SanitizeError, sanitize_config

        try:
            raw = self._conn.send_command("show running-config", read_timeout=120)
            return sanitize_config(raw).text
        except SanitizeError:
            raise ExecutorError("PREVIOUS_STATE_UNAVAILABLE") from None
        except Exception:  # noqa: BLE001 - reduced to a fixed code
            raise ExecutorError("PREVIOUS_STATE_UNAVAILABLE") from None

    def running_config_digest(self) -> str:
        """Same digest formula as a workbench snapshot / import provenance: proves the basis a Change was built from is current."""
        from ...bundles import canonical

        return canonical.text_hash(self._config_text())

    def _config_state_digest(self) -> str:
        return _state_digest(self._config_text())

    def config_state_digest(self) -> str:
        """The running configuration with comment lines dropped: equal digests mean the same configured state."""
        return self._config_state_digest()

    def startup_config_text(self) -> str:
        """The SANITIZED startup configuration through this run's own session (``show startup-config``, read-only)."""
        from ...bundles.legacy_sanitize import SanitizeError, sanitize_config

        try:
            return sanitize_config(self._conn.send_command("show startup-config", read_timeout=120)).text
        except SanitizeError:
            raise ExecutorError("PREVIOUS_STATE_UNAVAILABLE") from None
        except Exception:  # noqa: BLE001 - reduced to a fixed code
            raise ExecutorError("PREVIOUS_STATE_UNAVAILABLE") from None

    def startup_state_digest(self) -> str:
        """The startup configuration under the formula of ``config_state_digest``: equal digests mean that a reload
        boots exactly the configured state that is running now."""
        from ...bundles import canonical

        return canonical.text_hash("\n".join(
            line.rstrip() for line in self.startup_config_text().splitlines() if line.strip() and not line.lstrip().startswith("!")))

    def save_startup(self) -> ApplyOutcome:
        """``copy running-config startup-config``: the ONLY persistence command, sent only by a workflow that has just
        verified what the running configuration is (the transition lifecycle).  The caller reads the result back."""
        try:
            output = self._conn.send_command("copy running-config startup-config", read_timeout=120)
        except Exception as exc:  # noqa: BLE001 - reduced to a fixed category
            return ApplyOutcome(False, "TIMEOUT" if "imeout" in exc.__class__.__name__ else "TRANSPORT_ERROR", partial_effects=True, lines_sent=1)
        if any(marker in (output or "") for marker in REJECTIONS):
            return ApplyOutcome(False, "COMMAND_REJECTED", partial_effects=True, lines_sent=1)
        return ApplyOutcome(True, lines_sent=1)

    def show(self, command: str) -> str:
        """One read-only ``show`` command through this run's own session (the transition workflow's read-back)."""
        if not re.fullmatch(r"show [A-Za-z0-9 :./|-]{1,120}", command) or "|" in command.replace("| json", ""):
            raise ExecutorError("COMMAND_REJECTED")
        try:
            return self._conn.send_command(command, read_timeout=60)
        except Exception:  # noqa: BLE001 - reduced to a fixed code
            raise ExecutorError("PREVIOUS_STATE_UNAVAILABLE") from None

    def neighbour_answers(self, address: str, interface: str = "") -> bool:
        """Two echo requests to a directly connected IPv6 next hop.  Changes no configuration; resolves the neighbour entry."""
        try:
            target = ipaddress.ip_address(address)
        except ValueError:
            return False
        if target.version != 6 or (interface and not re.fullmatch(r"[A-Za-z][A-Za-z0-9/.-]{0,31}", interface)):
            return False
        command = f"ping ipv6 {target}" + (f" interface {interface}" if interface else "") + " repeat 2"
        try:
            output = self._conn.send_command(command, read_timeout=30)
        except Exception:  # noqa: BLE001
            return False
        return bool(re.search(r"\b2 received\b", output or ""))

    def reachable(self, address: str) -> bool:
        """Two echo requests (IPv4 or IPv6) from this device to ``address``.  Changes no configuration (admission reachability)."""
        try:
            target = ipaddress.ip_address(address)
        except ValueError:
            return False
        command = f"ping {'ipv6 ' if target.version == 6 else ''}{target} repeat 2"
        try:
            output = self._conn.send_command(command, read_timeout=30)
        except Exception:  # pylint: disable=broad-exception-caught  # noqa: BLE001 - an unanswered ping is unreachable
            return False
        return bool(re.search(r"\b2 received\b", output or ""))

    def _declared_inverse(self, spec: ConfigletSpec, text: str):
        """A route-shield or isolation statement that names its own exact inverse and the paths that prove it is configured (a nested
        child such as a redistribution under an address family has no derivable inverse).  -> (inverse, found, wanted) or None."""
        declared = spec.expected.get("inverse_lines") if spec.object_type in DECLARED_INVERSE_TYPES else None
        if declared is None:
            return None
        from ...config_workbench.structure import config_paths

        wanted = [str(path) for path in spec.expected.get("present_paths") or []]
        present = config_paths(text)
        return [str(line) for line in declared], [path for path in wanted if path in present], wanted

    def _assess_config_block(self, spec: ConfigletSpec) -> Assessment:
        text = self._config_text()
        facts = {"kind": "config_block", "modelled": False}
        declared = self._declared_inverse(spec, text)
        if declared is not None:
            inverse, found, wanted = declared
            if not inverse or not wanted or (found and len(found) != len(wanted)):
                return Assessment(REFUSE, False, facts, "REMOVAL_TARGET_DRIFTED" if found else "PLATFORM_EXECUTION_UNSUPPORTED")
            facts["config_digest"] = self._config_state_digest()
            if found:
                return Assessment(SKIP_SATISFIED, True, facts)
            self._config_inverses[spec.cfg_id] = inverse
            return Assessment(APPLY, True, facts)
        inverse = (management_inverse if spec.object_type in MANAGEMENT_BLOCK_TYPES else config_inverse)(list(spec.lines), text)
        if inverse is None:
            return Assessment(APPLY, False, facts, state.COMPENSATION_NOT_PROVABLE)
        facts["config_digest"] = self._config_state_digest()
        if not inverse:
            return Assessment(SKIP_SATISFIED, True, facts)      # every line is already configured: nothing is sent
        self._config_inverses[spec.cfg_id] = inverse
        return Assessment(APPLY, True, facts)

    def _assess_interface_snapshot(self, spec: ConfigletSpec) -> Assessment | None:
        """Interface state NMAS cannot prove restorable from the read groups: invert it from the captured section."""
        try:
            text = self._config_text()
            digest = self._config_state_digest()
        except ExecutorError:
            return None                                    # no captured section: nothing is provable (fail closed)
        inverse = interface_snapshot_inverse(list(spec.lines), text)
        if inverse is None:
            return None
        facts = {"kind": "config_block", "modelled": False, "snapshot": True, "config_digest": digest}
        if not inverse:
            return Assessment(SKIP_SATISFIED, True, facts)
        self._config_inverses[spec.cfg_id] = inverse
        return Assessment(APPLY, True, facts)

    def _compensate_config_block(self, spec: ConfigletSpec, assessment: Assessment) -> CompensationOutcome:
        wanted = self._config_applied.get(spec.cfg_id) or assessment.previous_state.get("config_digest")
        inverse = self._config_inverses.get(spec.cfg_id)
        if inverse is None and spec.object_type in DECLARED_INVERSE_TYPES:
            # A fresh session (the run's own was lost) holds no assess-time state: a declared-inverse statement carries its
            # exact inverse in the frozen plan, and the assess-time digest above still decides whether it is needed and held.
            inverse = [str(line) for line in spec.expected.get("inverse_lines") or []] or None
        try:
            if wanted and self._config_state_digest() == wanted:
                return CompensationOutcome("COMPENSATED", detail={"action": "NONE_NEEDED"})
            if not wanted or not inverse:
                return CompensationOutcome("COMPENSATION_FAILED", "UNSUPPORTED")
            sent = self._send(_commands_for(spec, inverse))
            if not sent.ok:
                return CompensationOutcome("COMPENSATION_FAILED", sent.error_code)
            if self._config_state_digest() != wanted:
                return CompensationOutcome("COMPENSATION_FAILED", "STATE_NOT_RESTORED")
        except ExecutorError as exc:
            return CompensationOutcome("COMPENSATION_UNVERIFIED", exc.code)
        return CompensationOutcome("COMPENSATED", detail={"action": "INVERSE_APPLIED", "commands": len(inverse)})

    def _removal_presence(self, spec: ConfigletSpec) -> tuple[list[str], list[str]]:
        from ...config_workbench.structure import config_paths

        paths = list((spec.removal or {}).get("absent_paths") or [])
        present = config_paths(self._config_text())
        return paths, [path for path in paths if path in present]

    def _assess_removal(self, spec: ConfigletSpec) -> Assessment:
        removal = spec.removal or {}
        if not spec.lines or not removal.get("absent_paths"):
            return Assessment(REFUSE, False, {}, "PLATFORM_EXECUTION_UNSUPPORTED")
        paths, found = self._removal_presence(spec)
        facts = {"kind": "config_removal", "object": str(removal.get("item", ""))[:120], "present": bool(found), "paths_checked": len(paths)}
        if not found:
            return Assessment(SKIP_SATISFIED, True, facts)          # already absent: nothing is sent
        if len(found) != len(paths):
            return Assessment(REFUSE, False, facts, "REMOVAL_TARGET_DRIFTED")
        restorable = bool(removal.get("restorable")) and bool(removal.get("restore_lines"))
        return Assessment(APPLY, restorable, facts, "" if restorable else state.COMPENSATION_NOT_PROVABLE)

    def _compensate_removal(self, spec: ConfigletSpec) -> CompensationOutcome:
        """Undo an intentional removal after a failed Complete run: re-add the captured original lines, then read back."""
        removal = spec.removal or {}
        try:
            paths, found = self._removal_presence(spec)
        except ExecutorError as exc:
            return CompensationOutcome("COMPENSATION_UNVERIFIED", exc.code)
        if paths and len(found) == len(paths):
            return CompensationOutcome("COMPENSATED", detail={"action": "NONE_NEEDED"})
        restore = list(removal.get("restore_lines") or [])
        if not removal.get("restorable") or not restore:
            return CompensationOutcome("COMPENSATION_FAILED", "UNSUPPORTED")
        sent = self._send(_eos_commands(restore))
        if not sent.ok:
            return CompensationOutcome("COMPENSATION_FAILED", sent.error_code)
        try:
            paths, found = self._removal_presence(spec)
        except ExecutorError as exc:
            return CompensationOutcome("COMPENSATION_UNVERIFIED", exc.code)
        if len(found) != len(paths):
            return CompensationOutcome("COMPENSATION_FAILED", "STATE_NOT_RESTORED")
        return CompensationOutcome("COMPENSATED", detail={"action": "ORIGINAL_LINES_RESTORED", "commands": len(restore)})

    # -- contract -------------------------------------------------------------------------------------------------------
    def assess(self, spec: ConfigletSpec) -> Assessment:
        if spec.origin == "REMOVAL":
            return self._assess_removal(spec)
        if spec.origin == "RAW":
            # Opaque, verified statements from the pinned revision: no state is modelled and no inverse is provable, so this is
            # never restorable (Complete is refused earlier).  The device must still be reachable BEFORE any mutation.
            if spec.integrity_error or not spec.lines:
                return Assessment(REFUSE, False, {}, spec.integrity_error or "PLATFORM_EXECUTION_UNSUPPORTED")
            self._read()
            return Assessment(APPLY, False, {"modelled": False, "raw": dict(spec.raw or {})}, state.COMPENSATION_NOT_PROVABLE)
        if not spec.lines:
            return Assessment(REFUSE, False, {}, "PLATFORM_EXECUTION_UNSUPPORTED")
        found = state.assess(spec, self._read(), additive_overwrites_primary=True)
        if spec.object_type in CONFIG_BLOCK_TYPES and found.action == APPLY:
            return self._assess_config_block(spec)
        if spec.object_type in SNAPSHOT_TYPES and found.action == APPLY and (not found.restorable or inverse_lines(spec) is None):
            snapshot = self._assess_interface_snapshot(spec)
            if snapshot is not None:
                return snapshot
        if found.action == APPLY and found.restorable and inverse_lines(spec) is None:
            found.restorable, found.reason = False, state.COMPENSATION_NOT_PROVABLE
        return found

    def _leave_config_mode(self) -> None:
        try:
            while self._conn.check_config_mode():
                self._conn.exit_config_mode()
        except Exception:  # noqa: BLE001 - best effort: the session is closed at the end of the run anyway
            pass

    def _send(self, commands: list[str]) -> ApplyOutcome:
        try:
            self._conn.config_mode(config_command="configure terminal", pattern=r"\(config[^\)]*\)#")
            output = self._conn.send_config_set(commands, enter_config_mode=False, exit_config_mode=False, cmd_verify=True, read_timeout=120)
            rejected = any(marker in (output or "") for marker in REJECTIONS)
        except Exception as exc:  # noqa: BLE001 - reduced to a fixed category; the exception text is never used
            self._leave_config_mode()  # never leave a failed session sitting in configuration mode
            code = "TIMEOUT" if "imeout" in exc.__class__.__name__ else "TRANSPORT_ERROR"
            return ApplyOutcome(False, code, partial_effects=True, lines_sent=len(commands))
        self._leave_config_mode()
        if rejected:
            return ApplyOutcome(False, "COMMAND_REJECTED", partial_effects=True, lines_sent=len(commands))
        return ApplyOutcome(True, lines_sent=len(commands))

    def apply(self, spec: ConfigletSpec, assessment: Assessment) -> ApplyOutcome:
        if isinstance(assessment.previous_state, dict) and assessment.previous_state.get("snapshot") is True:
            # Preflight ran before any Configlet of the plan was applied: capture the section as it is NOW, so that
            # reverse-order compensation restores exactly the state this Configlet found.
            try:
                text = self._config_text()
                digest = self._config_state_digest()
            except ExecutorError as exc:
                return ApplyOutcome(False, exc.code)
            inverse = interface_snapshot_inverse(list(spec.lines), text)
            if inverse is None:
                return ApplyOutcome(False, "COMMAND_REJECTED")     # nothing sent: no inverse is provable any more
            self._config_inverses[spec.cfg_id], self._config_applied[spec.cfg_id] = inverse, digest
        elif spec.object_type in CONFIG_BLOCK_TYPES and spec.object_type not in DECLARED_INVERSE_TYPES \
                and isinstance(assessment.previous_state, dict) and assessment.previous_state.get("kind") == "config_block":
            # The engine assesses EVERY Configlet before applying any, so the assess-time digest (and inverse) describe the
            # state before the whole plan.  Several configuration-block Configlets on one device are compensated in reverse
            # order, each while the earlier ones are still applied: capture the inverse and digest of the state this Configlet
            # really found.  Found live twice: Phase 4 for the management VRF, Phases 5/6 for a commissioning plan (an OSPF
            # binding on a loopback created earlier in the same plan was otherwise inverted to ``no interface Loopback0``).
            # A declared-inverse statement (route shield, isolation) carries its own exact inverse and is left as assessed.
            try:
                text = self._config_text()
                digest = self._config_state_digest()
            except ExecutorError as exc:
                return ApplyOutcome(False, exc.code)
            inverse = (management_inverse if spec.object_type in MANAGEMENT_BLOCK_TYPES else config_inverse)(list(spec.lines), text)
            if inverse is None:
                return ApplyOutcome(False, "COMMAND_REJECTED")     # nothing sent: no inverse is provable any more
            self._config_inverses[spec.cfg_id], self._config_applied[spec.cfg_id] = inverse, digest
            if not inverse:
                return ApplyOutcome(True, lines_sent=0)            # an earlier Configlet already configured it: nothing to send
        elif spec.origin not in ("RAW", "REMOVAL") and getattr(assessment, "restorable", False) is True:
            # A modelled Configlet is proven restored by its read groups AND by the exact configured state it found.  The read
            # groups alone are blind to configuration EOS keeps for a port without a backing link (absent from interface
            # telemetry, present in the running configuration), so the state digest is captured right before this apply.
            # Without it a later compensation could not be proven: nothing is sent.
            try:
                text = self._config_text()
            except ExecutorError as exc:
                return ApplyOutcome(False, exc.code)
            self._config_applied[spec.cfg_id], self._config_found[spec.cfg_id] = _state_digest(text), text
        return self._send(_commands_for(spec, spec.lines))

    def compensate(self, spec: ConfigletSpec, assessment: Assessment) -> CompensationOutcome:
        if spec.origin == "REMOVAL":
            return self._compensate_removal(spec)
        if assessment.previous_state.get("kind") == "config_block":
            return self._compensate_config_block(spec, assessment)
        wanted = self._config_applied.get(spec.cfg_id)       # the exact configured state this Configlet found (``apply``)
        try:
            current = self._read()
            text = self._config_text() if wanted else ""
        except ExecutorError as exc:
            return CompensationOutcome("COMPENSATION_UNVERIFIED", exc.code)
        exact = _state_digest(text) == wanted if wanted else True
        if state.restored(spec, current, assessment.previous_state) and exact:
            return CompensationOutcome("COMPENSATED", detail={"action": "NONE_NEEDED"})
        if wanted and not own_lines_present(list(spec.lines), text, self._config_found.get(spec.cfg_id, "")):
            # The configuration is not the one this Configlet found, yet none of its own lines is there: its inverse would ADD
            # configuration (``interface X`` re-creates the port), never remove it.  Not provably restored; nothing is sent.
            return CompensationOutcome("COMPENSATION_FAILED", "STATE_NOT_RESTORED", detail={"exact_configuration": False})
        inverse = inverse_lines(spec)
        if inverse is None:
            return CompensationOutcome("COMPENSATION_FAILED", "UNSUPPORTED")
        sent = self._send(_eos_commands(inverse))
        if not sent.ok:
            return CompensationOutcome("COMPENSATION_FAILED", sent.error_code)
        try:
            verdict = state.restored(spec, self._read(), assessment.previous_state)
            exact = self._config_state_digest() == wanted if wanted else True
        except ExecutorError as exc:
            return CompensationOutcome("COMPENSATION_UNVERIFIED", exc.code)
        if verdict is None:
            return CompensationOutcome("COMPENSATION_UNVERIFIED", "VERIFICATION_UNAVAILABLE")
        if not verdict or not exact:      # the read groups say restored, but the configuration still differs: never RESTORED
            return CompensationOutcome("COMPENSATION_FAILED", "STATE_NOT_RESTORED", detail={"exact_configuration": exact})
        return CompensationOutcome("COMPENSATED", detail={"action": "INVERSE_APPLIED", "commands": len(inverse), "exact_configuration": bool(wanted)})
