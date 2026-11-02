"""V2 Phase 9: DHCP relay option 82 as a governed change, and the relay read-back ZTP trusts.

Execution.  The option 82 intent of one relay port (``dhcp_relay_option82.Option82Intent``, from the Device Builder relay object
``relay['option82']``) becomes operations of the governed single-device transaction (``isolation.transaction``): an immutable
validation and plan, a precheck from a fresh read, approval of the plan hash by someone other than the requester, execution
under the device lock through NMAS's own cEOS executor (SSH, pinned host key), a read-back postcheck, and digest-verified
compensation newest first on any failure.  Each operation is computed against the relay's own pre-change read-back, so it
carries its EXACT inverse:

    global ``ip dhcp relay information option``      added only when it is off; inverse ``no ...``
    per-port circuit-id / remote-id                  set or replaced: inverse re-applies the captured value (or ``no ...``)
                                                     removed (a disabled intent): a removal whose restore path is the captured line

What ZTP trusts.  A relayed discovery is trusted only against NMAS's latest FRESH read-back of the relay (``DhcpRelayReadback``:
the postcheck of such a change, or a read-only refresh over the same transport), never against intent: the relay's option 82
state must be read, not assumed.  For an upstream whose platform has a verified option 82 implementation, a missing or stale
read-back blocks the ZTP session (``RELAY_READBACK_MISSING``), and discovery refuses a lease whose circuit id does not match the
one port that owns the lease's giaddr (``OPTION82_CIRCUIT_FORGED``): cEOS forwards a client-supplied option 82 unchanged, so the
circuit id alone is a claim, while giaddr is set by the relay.
"""

from __future__ import annotations

import ipaddress
from dataclasses import asdict, dataclass, field

from django.conf import settings
from django.utils import timezone

from ... import models
from .. import dhcp_relay_option82 as o82
from ..execution.executors.base import ExecutorError
from ..isolation import transaction

KIND = "DHCP_RELAY_OPTION82"
OBJECT_TYPE = "dhcp_relay_option82"
ACTION_PLAN, ACTION_APPROVE, ACTION_EXECUTE, ACTION_REFRESH = "OPTION82_PLAN", "OPTION82_APPROVE", "OPTION82_EXECUTE", "OPTION82_REFRESH"


def readback_max_age_seconds() -> float:
    """How long a relay read-back is trusted by ZTP (default one day)."""
    return float(getattr(settings, "NMAS_OPTION82_READBACK_MAX_AGE_SECONDS", 86400))


@dataclass
class Option82Result:
    ok: bool
    action: str
    change: object | None = None
    blockers: list = field(default_factory=list)
    detail: dict = field(default_factory=dict)

    @property
    def codes(self) -> list[str]:
        return [b["code"] for b in self.blockers]


def _blocker(code: str, detail: str = "") -> dict:
    return transaction.blocker(code, detail)


# ------------------------------------------------------------------------------------------------------------- intent
def intent_from_revision(revision, relay_id: str) -> o82.Option82Intent:
    """The option 82 intent of one Device Builder relay object (the interface the relay sits on is the option 82 port)."""
    sections = revision.sections or {}
    relay = (((sections.get("services") or {}).get("dhcp") or {}).get("relays") or {}).get(relay_id)
    if not isinstance(relay, dict) or relay.get("id") != relay_id:
        raise o82.Option82Error("OPTION82_RELAY_NOT_FOUND", f"{relay_id} is not a relay of this revision")
    interface = ((sections.get("interfaces") or {}).get(relay.get("interface_id") or "") or {})
    intent = o82.intent_from_relay(relay, str(interface.get("name") or ""))
    if intent is None:
        raise o82.Option82Error("OPTION82_INTENT_MISSING", "the relay carries no IPv4 option 82 intent")
    return intent


def _stored_circuit(intent: o82.Option82Intent) -> str:
    """What EOS keeps in its running configuration for the intended circuit id (no line for the default, the port name)."""
    return "" if not intent.enabled or intent.circuit_id in ("", intent.interface) else intent.circuit_id


def port_state(readback: dict, interface: str) -> dict:
    """The facts an option 82 change depends on: the global switch and this port's ids, helpers and addresses."""
    port = (readback or {}).get("interfaces", {}).get(interface)
    state = {"enabled": bool((readback or {}).get("enabled")), "interface": interface, "present": port is not None}
    if port is not None:
        state.update(circuit_id=str(port.get("circuit_id") or ""), remote_id=str(port.get("remote_id") or ""),
                     helpers=sorted(port.get("helpers") or []), addresses=sorted(port.get("addresses") or []))
    return state


def _op(key: str, kind: str, lines: list[str], inverse: list[str], paths: list[str], description: str) -> dict:
    op = {"key": key, "kind": kind, "lines": list(lines), "inverse": list(inverse), "paths": list(paths), "description": description,
          "namespace": models.FeatureNamespace.SERVICES.value, "priority": int(models.DeploymentPriority.HIGHER_LEVEL_SERVICES)}
    if kind == "ADD":
        op["object_type"] = OBJECT_TYPE
    return op


def operations(intent: o82.Option82Intent, prior: dict) -> list[dict]:
    """The governed operations that take the relay from ``prior`` (port_state) to ``intent``; [] when it already holds."""
    problems = o82.validate_intent("arista_ceos", intent)
    if problems:
        raise o82.Option82Error(problems[0]["code"], problems[0]["detail"])
    if not prior.get("present"):
        raise o82.Option82Error("OPTION82_PORT_MISSING", f"{intent.interface} is not configured on the relay")
    header = f"interface {intent.interface}"
    ops = []
    if intent.enabled and not prior["enabled"]:
        ops.append(_op("global", "ADD", [o82.GLOBAL_LINE], [f"no {o82.GLOBAL_LINE}"], [o82.GLOBAL_LINE],
                       "DHCP relay agent information (option 82) enabled"))
    for key, line, wanted, current in (("circuit-id", o82.CIRCUIT_LINE, _stored_circuit(intent), prior.get("circuit_id", "")),
                                       ("remote-id", o82.REMOTE_LINE, intent.remote_id if intent.enabled else "", prior.get("remote_id", ""))):
        if wanted == current:
            continue
        if wanted:
            restore = f"   {line} {current}" if current else f"   no {line}"
            ops.append(_op(key, "ADD", [header, f"   {line} {wanted}"], [header, restore], [f"{header} > {line} {wanted}"],
                           f"option 82 {key} {wanted} on {intent.interface}"))
        else:
            ops.append(_op(key, "REMOVE", [header, f"   no {line}"], [header, f"   {line} {current}"], [f"{header} > {line} {current}"],
                           f"option 82 {key} removed from {intent.interface}"))
    return ops


def _intent_of(change) -> o82.Option82Intent:
    data = ((change.metadata or {}).get("transition") or {}).get("intent") or {}
    return o82.Option82Intent(str(data.get("interface") or ""), str(data.get("circuit_id") or ""), str(data.get("remote_id") or ""),
                              data.get("enabled") is True)


def _reference(change) -> dict:
    return dict((change.metadata or {}).get("transition") or {})


def ops_of(change) -> list[dict]:
    """The operations of an option 82 Change, recomputed from its stored intent and pre-change read-back (deterministic)."""
    return operations(_intent_of(change), _reference(change).get("prior") or {})


# ------------------------------------------------------------------------------------------------------------- device access
def _device_ref(name: str) -> dict:
    return {"name": name, "platform": "ceos"}


def _default_executor_factory():
    from ..execution.executors.ceos import CeosExecutor

    return CeosExecutor


def _read_config(executor) -> str:
    from ..isolation.service import read_config as isolation_read

    return isolation_read(executor)


def _read(device: str, executor_factory) -> tuple[str, str, dict | None]:
    """-> (sanitized running configuration, state digest, blocker or None) over one fresh NMAS session."""
    executor = executor_factory(_device_ref(device))
    try:
        executor.connect()
        text = _read_config(executor)
        return text, executor.config_state_digest(), None
    except ExecutorError as exc:
        return "", "", _blocker("RELAY_UNREADABLE", exc.code)
    finally:
        try:
            executor.close()
        except Exception:  # pylint: disable=broad-exception-caught  # noqa: BLE001 - closing a session never masks the outcome
            pass


def platform_of(device: str) -> str:
    from ..devices import resolver

    target = resolver.resolve(device)
    return target.platform if target is not None else ""


def required_for(upstream_device: str) -> bool:
    """Whether ZTP through ``upstream_device`` must be proven by an option 82 read-back (a verified option 82 platform)."""
    return platform_of(upstream_device) in o82.PLATFORMS


# ------------------------------------------------------------------------------------------------------------- validation
def port_findings(device: str, intent: o82.Option82Intent, prior: dict, *, network=None) -> list[dict]:
    """Why ``intent`` must not be planned against this read-back (the relay side of DHCP source / attachment validation)."""
    from . import policy

    findings = [{"code": p["code"], "detail": p["detail"]} for p in o82.validate_intent(platform_of(device), intent)]
    if not prior.get("present"):
        return findings + [{"code": "OPTION82_PORT_MISSING", "detail": f"{intent.interface} is not configured on {device}"}]
    if not o82._ROUTED_PORT.fullmatch(intent.interface):          # pylint: disable=protected-access
        findings.append({"code": "OPTION82_PORT_NOT_ROUTED", "detail": "giaddr identifies a port only on a routed port"})
    if not prior.get("addresses"):
        findings.append({"code": "OPTION82_PORT_UNADDRESSED", "detail": "the relay port has no IPv4 address to use as giaddr"})
    if network is not None:
        if str(network.service_address) not in prior.get("helpers", []):
            findings.append({"code": "BOOTSTRAP_PATH_UNAVAILABLE", "detail": "the relay port does not forward to the bootstrap service"})
        relay = policy.relay_for(network, device)
        if not relay:
            findings.append({"code": "BOOTSTRAP_PATH_UNAVAILABLE", "detail": f"{device} is not a trusted relay of {network.name}"})
        elif relay not in prior.get("addresses", []):
            findings.append({"code": "RELAY_UNTRUSTED", "detail": f"the trusted relay address {relay} is not this port's address"})
    return findings


# ------------------------------------------------------------------------------------------------------------- workflow
def plan(*, device: str, intent: o82.Option82Intent, actor: str, network=None, source: dict | None = None,
         executor_factory=None) -> Option82Result:
    """Read the relay, validate, and build the immutable plan and its precheck.  Nothing is written to the device."""
    executor_factory = executor_factory or _default_executor_factory()
    unresolved = transaction.unresolved_runs(device)
    if unresolved:
        return Option82Result(False, ACTION_PLAN, None, [_blocker("PRIOR_TRANSITION_UNRESOLVED", f"{unresolved[0]} left {device} unresolved")])
    text, digest, problem = _read(device, executor_factory)
    if problem:
        return Option82Result(False, ACTION_PLAN, None, [problem])
    prior = port_state(o82.parse_eos(text), intent.interface)
    findings = port_findings(device, intent, prior, network=network)
    try:
        ops = [] if findings else operations(intent, prior)
    except o82.Option82Error as exc:
        findings.append({"code": exc.code, "detail": exc.detail})
        ops = []
    if not findings and not ops:
        return Option82Result(True, ACTION_PLAN, None, [], {"satisfied": True, "prior": prior})
    change = transaction.create_change(
        kind=KIND, device=device, title=f"{device}: DHCP relay option 82 on {intent.interface}",
        description=f"DHCP relay agent information (option 82) on {device} {intent.interface}: "
                    f"{'enable' if intent.enabled else 'disable'} (circuit id {intent.effective_circuit_id() if intent.enabled else '-'})",
        actor=actor, reference={"device": device, "intent": asdict(intent), "prior": prior, "basis_digest": digest,
                                "network": getattr(network, "name", ""), "source": dict(source or {})})
    transaction.validate(change, ops, actor=actor, findings=findings, source={"device": device, "basis_digest": digest})
    if findings:
        return Option82Result(False, ACTION_PLAN, change, [_blocker(f["code"], f["detail"]) for f in findings])
    built = transaction.build_plan(change, ops, actor=actor, device=device, summary={"interface": intent.interface})
    transaction.record_precheck(change, built, actor=actor, blockers=[], facts={"prior": prior, "basis_digest": digest})
    return Option82Result(True, ACTION_PLAN, change, [], {"plan_hash": built.plan_hash, "operations": ops, "prior": prior})


def precheck(change, *, actor: str, executor_factory=None) -> Option82Result:
    """A fresh read-only precheck of the plan: the relay port must still be exactly the state the plan was built from."""
    executor_factory = executor_factory or _default_executor_factory()
    reference = _reference(change)
    built = transaction.latest_plan(change)
    if built is None:
        return Option82Result(False, "OPTION82_PRECHECK", change, [_blocker("PLAN_MISSING")])
    started = timezone.now()
    text, digest, problem = _read(reference["device"], executor_factory)
    current = port_state(o82.parse_eos(text), _intent_of(change).interface) if not problem else {}
    blockers = [problem] if problem else ([] if current == reference.get("prior") else [_blocker("BASIS_CHANGED", "the relay port changed since planning")])
    transaction.record_precheck(change, built, actor=actor, blockers=blockers, facts={"current": current, "basis_digest": digest}, started=started)
    return Option82Result(not blockers, "OPTION82_PRECHECK", change, blockers)


def approve(change, *, actor: str, confirmation: str) -> Option82Result:
    try:
        transaction.approve(change, ops_of(change), actor=actor, requested_by=change.created_by, confirmation=confirmation,
                            device=_reference(change)["device"])
    except transaction.TransactionError as exc:
        return Option82Result(False, ACTION_APPROVE, change, list(exc.blockers))
    return Option82Result(True, ACTION_APPROVE, change)


def execute(change, *, actor: str, confirmation: str, executor_factory=None, observer=None) -> Option82Result:
    """Run the approved plan: preflight (basis still current), apply, read-back postcheck, compensation on any failure.  A
    succeeded run records the postcheck read-back as the relay's trusted read-back."""
    executor_factory = executor_factory or _default_executor_factory()
    reference, intent = _reference(change), _intent_of(change)
    device = reference["device"]
    seen = {}

    def preflight(executor):
        current = port_state(o82.parse_eos(_read_config(executor)), intent.interface)
        return [] if current == reference.get("prior") else [_blocker("BASIS_CHANGED", "the relay port changed since planning")]

    def final(executor):
        readback = o82.parse_eos(_read_config(executor))
        seen.update(readback=readback, digest=executor.config_state_digest())
        return [{"check": code, "detail": f"{device} {intent.interface}"} for code in o82.postcheck(intent, readback)]

    result = transaction.execute(change, ops_of(change), actor=actor, confirmation=confirmation, device=_device_ref(device),
                                 executor_factory=executor_factory, preflight=preflight, final=final, observer=observer)
    detail = {"run": str(result.run.run_id) if result.run is not None else "", "outcome": result.outcome, "report": result.report}
    if result.succeeded and seen.get("readback") is not None:
        row = record_readback(device, seen["readback"], source=models.DhcpRelayReadbackSource.POSTCHECK, digest=seen["digest"],
                              actor=actor, change=change, run_id=detail["run"])
        detail["readback"] = row.pk
    return Option82Result(result.succeeded, ACTION_EXECUTE, change, list(result.blockers), detail)


def refresh(device: str, *, actor: str, executor_factory=None) -> Option82Result:
    """A read-only read-back of the relay's option 82 configuration over NMAS's transport (no change; nothing is written)."""
    if platform_of(device) not in o82.PLATFORMS:
        return Option82Result(False, ACTION_REFRESH, None, [_blocker("OPTION82_PLATFORM_NOT_IMPLEMENTED", device)])
    text, digest, problem = _read(device, executor_factory or _default_executor_factory())
    if problem:
        return Option82Result(False, ACTION_REFRESH, None, [problem])
    row = record_readback(device, o82.parse_eos(text), source=models.DhcpRelayReadbackSource.READ, digest=digest, actor=actor)
    return Option82Result(True, ACTION_REFRESH, None, [], {"readback": row.pk})


# ------------------------------------------------------------------------------------------------------------- read-back
def record_readback(device: str, readback: dict, *, source: str, digest: str, actor: str, change=None, run_id: str = "",
                    now=None) -> models.DhcpRelayReadback:
    return models.DhcpRelayReadback.objects.create(device=device, source=source, change=change, run_id=run_id, readback=readback,
                                                   config_digest=digest, captured_by=actor, captured_at=now or timezone.now())


def trusted_readback(device: str, *, now=None) -> dict | None:
    """The latest read-back of ``device`` while it is fresh, else None."""
    now = now or timezone.now()
    row = models.DhcpRelayReadback.objects.filter(device=device).order_by("-captured_at", "-id").first()
    if row is None or (now - row.captured_at).total_seconds() > readback_max_age_seconds():
        return None
    return dict(row.readback)


def giaddr_port(readback: dict, relay_address: str) -> str:
    """The ONE relay port that owns ``relay_address`` ('' when none or several do)."""
    try:
        wanted = str(ipaddress.IPv4Address(relay_address))
    except ValueError:
        return ""
    holders = [name for name, port in (readback or {}).get("interfaces", {}).items() if wanted in port.get("addresses", [])]
    return holders[0] if len(holders) == 1 and o82._ROUTED_PORT.fullmatch(holders[0]) else ""   # pylint: disable=protected-access


def lease_problem(upstream_device: str, relay_address: str, circuit_id: str, *, now=None) -> str:
    """Discovery: why a lease relayed by ``upstream_device`` must not be trusted ('' when it may).  Only for a platform whose option
    82 behaviour is verified; elsewhere the existing giaddr + circuit rules stand alone."""
    if not required_for(upstream_device):
        return ""
    readback = trusted_readback(upstream_device, now=now)
    if readback is None:
        return "RELAY_READBACK_MISSING"
    port = giaddr_port(readback, relay_address)
    if not port:
        return "RELAY_UNTRUSTED"
    return "" if circuit_id == o82.effective_circuit_id(readback, port) else "OPTION82_CIRCUIT_FORGED"
