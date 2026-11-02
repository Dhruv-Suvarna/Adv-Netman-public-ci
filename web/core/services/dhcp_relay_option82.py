"""V2 Phase 9: DHCP relay agent information (option 82) for downstream native ZTP -- Arista EOS only.

Why.  Native ZTP of a device behind a commissioned upstream (R6 -> R7) is trusted only when its DHCP request arrives through a
listed trusted relay (giaddr) AND carries the relay-inserted option 82 circuit id of the approved attachment port: the ISC
policy (``ztp.dhcp.isc``) matches ``packet(24, 4)`` = giaddr AND ``option agent.circuit-id`` = the attachment's upstream
interface, and discovery (``ztp.discovery.fold``) refuses a lease without a trusted giaddr or a circuit id.  Until Phase 9 the
Device Builder could not render the relay side, so a downstream relay depended on hand configuration.

Platform syntax (live-verified on a disposable cEOS 4.36.2F, ``labs/phase9-option82-isolated``):

    ip dhcp relay information option                          global; default OFF (``no ...`` in ``show running-config all``)
    interface EthernetN
       ip dhcp relay information option circuit-id <id>       default = the interface name (``Ethernet1``)
       ip dhcp relay information option remote-id <id>        default = none

``no`` of each line returns exactly to the default (the full running-config digest is restored).  Other platforms are refused
(OPTION82_PLATFORM_NOT_IMPLEMENTED): no other NOS has been verified here and cEOS evidence is never reused for another NOS.

LIVE SECURITY FINDING (cEOS 4.36.2F, evidence option82-ceos-live.json): the relay forwards a CLIENT-SUPPLIED option 82 unchanged
-- with ``ip dhcp relay information option`` on or off -- and this release has no replace / drop policy for it.  A downstream
device can therefore put any circuit id it likes into its request; the circuit id is NOT proof of the port by itself.  What the
device cannot forge is giaddr: the relay sets it to the address of the interface that received the request.  NMAS therefore
trusts a relayed discovery only when giaddr identifies exactly ONE routed relay port (no SVI / VLAN interface shared by several
access ports, and no other relay port with that address); the circuit id then only has to agree with it.

Trust model.  ``relay_trust_problems`` is the ZTP-side gate: the relay must be a listed trusted relay of the bootstrap network,
its read-back must show option 82 enabled, the attachment port must exist with a helper to the bootstrap service, and the
EFFECTIVE circuit id of that port must equal the attachment's upstream interface (the value the DHCP reservation matches).
A custom circuit id other than the interface name therefore renders and validates, but is refused for ZTP trust.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass

PLATFORMS = frozenset({"arista_ceos"})
GLOBAL_LINE = "ip dhcp relay information option"
CIRCUIT_LINE = "ip dhcp relay information option circuit-id"
REMOTE_LINE = "ip dhcp relay information option remote-id"
_INTERFACE = re.compile(r"(?:Ethernet\d+(?:/\d+){0,2}(?:\.\d+)?|Vlan\d+|Port-Channel\d+(?:\.\d+)?)")
_ROUTED_PORT = re.compile(r"Ethernet\d+(?:/\d+){0,2}(?:\.\d+)?")
_VALUE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,62}")
# platform -> secret-free live evidence file (set only after a recorded live run; see docs/V2_PHASE9_CAPABILITY_CLOSURE.md)
LIVE = {"arista_ceos": "docs/evidence/v2-phase7-9/phase9/option82-ceos-live.json"}


class Option82Error(ValueError):
    def __init__(self, code: str, detail: str = ""):
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class Option82Intent:
    interface: str
    circuit_id: str = ""     # '' = the platform default (the interface name)
    remote_id: str = ""      # '' = none
    enabled: bool = True

    def effective_circuit_id(self) -> str:
        return self.circuit_id or self.interface


def validate_intent(platform: str, intent: Option82Intent) -> list[dict]:
    """Tier-1 syntax / semantic validation -> [{code, field, detail}] (empty = valid)."""
    problems = []
    if platform not in PLATFORMS:
        problems.append({"code": "OPTION82_PLATFORM_NOT_IMPLEMENTED", "field": "platform",
                         "detail": f"{platform}: DHCP relay option 82 is implemented and live-verified for Arista EOS only"})
    if not isinstance(intent.interface, str) or not _INTERFACE.fullmatch(intent.interface):
        problems.append({"code": "INTERFACE_INVALID", "field": "interface", "detail": "an EOS routed relay interface name is required"})
    for field in ("circuit_id", "remote_id"):
        value = getattr(intent, field)
        if not isinstance(value, str) or (value and not _VALUE.fullmatch(value)):
            problems.append({"code": "OPTION82_VALUE_INVALID", "field": field,
                             "detail": "1-63 characters of letters, digits and . _ : / - (starting alphanumeric)"})
    if not isinstance(intent.enabled, bool):
        problems.append({"code": "OPTION82_VALUE_INVALID", "field": "enabled", "detail": "enabled must be a boolean"})
    return problems


def intent_from_relay(relay: dict, interface_name: str) -> Option82Intent | None:
    """The option 82 intent stored on one Device Builder DHCP relay object (``relay['option82']``), or None."""
    data = (relay or {}).get("option82")
    if not isinstance(data, dict) or relay.get("family") != "IPV4":
        return None
    return Option82Intent(interface_name, str(data.get("circuit_id") or ""), str(data.get("remote_id") or ""),
                          data.get("enabled") is True)


def render_eos(intent: Option82Intent) -> list[str]:
    """EOS configuration lines for one intent (enabled: global + per-port ids; disabled: remove this port's ids only)."""
    problems = validate_intent("arista_ceos", intent)
    if problems:
        raise Option82Error(problems[0]["code"], problems[0]["detail"])
    if not intent.enabled:
        return [f"interface {intent.interface}", f"   no {CIRCUIT_LINE}", f"   no {REMOTE_LINE}"]
    block = [f"interface {intent.interface}"]
    block.append(f"   {CIRCUIT_LINE} {intent.circuit_id}" if intent.circuit_id else f"   no {CIRCUIT_LINE}")
    block.append(f"   {REMOTE_LINE} {intent.remote_id}" if intent.remote_id else f"   no {REMOTE_LINE}")
    return [GLOBAL_LINE, *block]


def parse_eos(running_config: str) -> dict:
    """Read-back / import of ``show running-config``: {enabled, interfaces: {name: {circuit_id, remote_id, helpers}}}."""
    result = {"enabled": False, "interfaces": {}}
    current = None
    for raw in str(running_config or "").splitlines():
        line = raw.rstrip()
        if not line or line.startswith("!"):
            if line.startswith("!"):
                current = None
            continue
        if not line.startswith(" "):
            current = None
            if line == GLOBAL_LINE:
                result["enabled"] = True
            elif line.startswith("interface "):
                current = result["interfaces"].setdefault(line.split(None, 1)[1], {"circuit_id": "", "remote_id": "", "helpers": [],
                                                                                    "addresses": []})
            continue
        if current is None:
            continue
        text = line.strip()
        if text.startswith(CIRCUIT_LINE + " "):
            current["circuit_id"] = text[len(CIRCUIT_LINE) + 1:].strip()
        elif text.startswith(REMOTE_LINE + " "):
            current["remote_id"] = text[len(REMOTE_LINE) + 1:].strip()
        elif text.startswith("ip helper-address "):
            current["helpers"].append(text.split()[2])
        elif text.startswith("ip address ") and len(text.split()) >= 3:
            current["addresses"].append(text.split()[2].split("/")[0])
    return result


def effective_circuit_id(readback: dict, interface: str) -> str:
    """What the relay inserts as circuit id on ``interface`` ('' when option 82 is off or the port is not configured)."""
    port = (readback or {}).get("interfaces", {}).get(interface)
    if not (readback or {}).get("enabled") or port is None:
        return ""
    return port.get("circuit_id") or interface


def postcheck(intent: Option82Intent, readback: dict) -> list[str]:
    """Read-back verification of an applied intent -> problem codes (empty = the device carries exactly the intent)."""
    port = (readback or {}).get("interfaces", {}).get(intent.interface)
    if port is None:
        return ["OPTION82_PORT_MISSING"]
    problems = []
    if intent.enabled and not readback.get("enabled"):
        problems.append("OPTION82_GLOBAL_DISABLED")
    # EOS stores no line for a circuit id equal to its default (the interface name): live-verified on 4.36.2F
    stored = "" if intent.circuit_id in ("", intent.interface) else intent.circuit_id
    if port.get("circuit_id", "") != (stored if intent.enabled else ""):
        problems.append("OPTION82_CIRCUIT_ID_MISMATCH")
    if port.get("remote_id", "") != (intent.remote_id if intent.enabled else ""):
        problems.append("OPTION82_REMOTE_ID_MISMATCH")
    return problems


def compensation_eos(prior: dict, intent: Option82Intent) -> list[str]:
    """The exact inverse of ``render_eos(intent)`` given the pre-change read-back ``prior``."""
    port = (prior or {}).get("interfaces", {}).get(intent.interface)
    if port is None:
        raise Option82Error("OPTION82_PORT_MISSING", "the pre-change read-back does not contain the relay port")
    lines = [f"interface {intent.interface}",
             f"   {CIRCUIT_LINE} {port['circuit_id']}" if port.get("circuit_id") else f"   no {CIRCUIT_LINE}",
             f"   {REMOTE_LINE} {port['remote_id']}" if port.get("remote_id") else f"   no {REMOTE_LINE}"]
    if intent.enabled and not prior.get("enabled"):
        lines.append(f"no {GLOBAL_LINE}")
    return lines


def config_digest(running_config: str) -> str:
    """sha256 of the running-config without CLI banner / comment lines (stable across reads of an unchanged device)."""
    body = [line.rstrip() for line in str(running_config or "").splitlines()
            if line.strip() and not line.lstrip().startswith(("!", ">"))]
    return hashlib.sha256("\n".join(body).encode()).hexdigest()


def change_payload(lines: list[str]) -> str:
    """One EOS configuration session for ``lines`` (refuses an empty change)."""
    if not lines:
        raise Option82Error("OPTION82_EMPTY_CHANGE", "nothing to apply")
    return "\n".join(["configure", *(line.strip() for line in lines), "end"])


def relay_trust_problems(*, network, attachment, readback: dict) -> list[dict]:
    """ZTP gate: may DHCP discovery through ``attachment``'s upstream be trusted with this relay read-back? -> blockers."""
    from ..models import AttachmentApproval, AttachmentVerification
    from .ztp import policy

    def bad(code, reason):
        return {"code": code, "reason": reason}

    if attachment is None:
        return [bad("ATTACHMENT_MISMATCH", "no attachment")]
    problems = []
    if attachment.approval_state != AttachmentApproval.APPROVED or attachment.verification_state == AttachmentVerification.MISMATCH:
        problems.append(bad("ATTACHMENT_MISMATCH", "the attachment is not approved or is contradicted by an observation"))
    if not policy.relay_for(network, attachment.upstream_device):
        problems.append(bad("BOOTSTRAP_PATH_UNAVAILABLE", f"{attachment.upstream_device} is not a trusted relay of {network.name}"))
    port = (readback or {}).get("interfaces", {}).get(attachment.upstream_interface)
    if not (readback or {}).get("enabled"):
        problems.append(bad("RELAY_UNTRUSTED", "option 82 (relay agent information) is not enabled on the relay"))
    if port is None:
        problems.append(bad("INTERFACE_INVALID", f"{attachment.upstream_interface} is not configured on the relay"))
    else:
        if str(network.service_address) not in port.get("helpers", []):
            problems.append(bad("BOOTSTRAP_PATH_UNAVAILABLE", "the relay port does not forward to the bootstrap service"))
        relay_address = policy.relay_for(network, attachment.upstream_device)
        holders = [name for name, item in readback.get("interfaces", {}).items() if relay_address in item.get("addresses", [])]
        if not _ROUTED_PORT.fullmatch(attachment.upstream_interface) or holders != [attachment.upstream_interface]:
            problems.append(bad("RELAY_UNTRUSTED", "giaddr must identify exactly one routed relay port: the relay forwards "
                                                   "client-supplied option 82 unchanged, so the circuit id alone is forgeable"))
        circuit = effective_circuit_id(readback, attachment.upstream_interface)
        if circuit and circuit != attachment.upstream_interface:
            problems.append(bad("RELAY_UNTRUSTED", f"the relay inserts circuit id {circuit!r}, not the attachment port"))
    return problems
