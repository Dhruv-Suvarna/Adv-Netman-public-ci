"""Unattended incident intake: monitoring observation -> fault correlation -> case -> deterministic run -> Codex dispatch.

Detection is read-only.  Each pass reads every in-scope managed device's physical-interface status (``Observation``) and
compares it with the authoritative intent (``hc._intended_admin_states``).  A violation is an interface whose intent is
``up`` but whose link is disabled/down.  It must persist for ``confirm_seconds`` (debounce, so a single flap or a sample
taken mid-change is not an incident).

Correlation: the two ends of one topology link are ONE incident.  The fingerprint is the link (or the interface when it has
no modelled peer), and the case is scoped to the device whose side is administratively disabled (else both ends).

Safety:
- At most one open case per fingerprint.
- A per-fingerprint cooldown after a case is opened (a recurrence inside it goes to a human, not to a new automated case).
- A global hourly case budget.
- Idempotency keys.
- Every case is opened under the system identity ``nmas-intake``.
- Execution stays exclusively with the standing-policy recovery watcher and the Change Engine; the intake never writes to a
  device and never approves anything.
- Durable state is the case table itself, so dedup survives restarts.
"""

from __future__ import annotations

import json
import re
import subprocess
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Callable

from django.conf import settings

from ... import models
from . import notify
from . import repository as repo
from .runbooks import hc

ACTOR_NAME = "nmas-intake"
TRIGGER_SOURCE = "monitoring"
HANDOFF_ID = re.compile(r"^AIH-[0-9a-f]{12}$")
DEFAULT_DEVICES = ("R1", "R2", "R5", "S1", "S2", "S3", "S4")


@dataclass(frozen=True)
class Observation:
    device: str
    interface: str
    link: str            # cEOS linkStatus: connected | notconnect | disabled | errdisabled | ...
    protocol: str        # lineProtocolStatus: up | down | ...


@dataclass
class IntakeConfig:
    devices: tuple[str, ...] = DEFAULT_DEVICES
    confirm_seconds: int = 30
    cooldown_seconds: int = 900
    max_cases_per_hour: int = 4
    container_prefix: str = "clab-srlceos01-"
    fingerprint_prefix: str = ""          # "REPLAY:" for controlled replays, so they never cool down a live fingerprint

    @classmethod
    def from_settings(cls) -> "IntakeConfig":
        devs = tuple(d.strip() for d in str(getattr(settings, "NMAS_TS_INTAKE_DEVICES", "") or "").split(",") if d.strip())
        return cls(devices=devs or DEFAULT_DEVICES,
                   confirm_seconds=int(getattr(settings, "NMAS_TS_INTAKE_CONFIRM_SECONDS", 30)),
                   cooldown_seconds=int(getattr(settings, "NMAS_TS_INTAKE_COOLDOWN_SECONDS", 900)),
                   max_cases_per_hour=int(getattr(settings, "NMAS_TS_INTAKE_MAX_CASES_PER_HOUR", 4)))


# ------------------------------------------------------------------------------------------------------------- observation
def read_device(device: str, cfg: IntakeConfig) -> list[Observation] | None:
    """Read-only physical-interface status of one managed device (the same read path the recovery service uses)."""
    argv = ["docker", "exec", f"{cfg.container_prefix}{device}", "Cli", "-p", "15", "-c", "show interfaces status | json"]
    try:
        out = subprocess.run(argv, capture_output=True, text=True, timeout=20, check=False)
        rows = json.loads(out.stdout).get("interfaceStatuses") or {}
    except (OSError, subprocess.SubprocessError, ValueError):
        return None
    return [Observation(device, name, str(v.get("linkStatus", "")), str(v.get("lineProtocolStatus", ""))) for name, v in rows.items()]


def violations(observations: list[Observation], intent: Callable[[str], dict | None]) -> dict[tuple[str, str], Observation]:
    """Interfaces present in the status read whose authoritative intent is up but which are not connected/up."""
    out: dict[tuple[str, str], Observation] = {}
    cache: dict[str, dict] = {}
    for ob in observations:
        if ob.interface.startswith("Management"):
            continue
        want = cache.setdefault(ob.device, intent(ob.device) or {})
        if want.get(ob.interface) == "up" and (ob.link != "connected" or ob.protocol != "up"):
            out[(ob.device, ob.interface)] = ob
    return out


def peers(devices: set[str]) -> dict[tuple[str, str], tuple[str, str]]:
    """Link peers from the tracked Containerlab topology (cEOS ``ethN`` == ``EthernetN``)."""
    from .intake_scope import _links

    def name(iface: str) -> str:
        m = re.fullmatch(r"eth(\d+)", iface)
        return f"Ethernet{m.group(1)}" if m else iface

    out = {}
    for row in _links(devices):
        s = row["scope"]
        a, b = (s["a"], name(s["a_if"])), (s["b"], name(s["b_if"]))
        out[a], out[b] = b, a
    return out


@dataclass
class Incident:
    fingerprint: str
    devices: list[str]                       # case scope: the administratively-disabled side, else both ends
    members: list[Observation]
    onset: datetime

    def symptom(self) -> str:
        seen = "; ".join(f"{o.device} {o.interface} link={o.link} protocol={o.protocol}" for o in self.members)
        return (f"Monitoring alarm (automatic intake): interface state deviates from intended up state for >= confirmation window. "
                f"Observed: {seen}.")


def correlate(current: dict[tuple[str, str], Observation], link_peers: dict, onset: dict[tuple[str, str], datetime]) -> list[Incident]:
    out, done = [], set()
    for key in sorted(current):
        if key in done:
            continue
        peer = link_peers.get(key)
        members = [current[key]] + ([current[peer]] if peer in current else [])
        done.update((o.device, o.interface) for o in members)
        ends = sorted([key, peer]) if peer else [key]
        fp = "LINK:" + "|".join(f"{d}:{i}" for d, i in ends) if peer else f"IFACE:{key[0]}:{key[1]}"
        disabled = sorted({o.device for o in members if o.link in ("disabled", "errdisabled")})
        devices = disabled or sorted({o.device for o in members})
        out.append(Incident(fp, devices, members, min(onset[(o.device, o.interface)] for o in members)))
    return out


# -------------------------------------------------------------------------------------------------------------- case intake
def _open_for(fp: str):
    return models.TsCase.objects.filter(trigger_source=TRIGGER_SOURCE, trigger_ref=fp).exclude(
        state__in=[s.value if hasattr(s, "value") else s for s in models.TS_TERMINAL_CASE_STATES]).first()


def admission(incident: Incident, cfg: IntakeConfig, now: datetime) -> tuple[bool, str]:
    """Dedup / loop / budget gates.  Durable: decided from the case table, so a restart never re-opens a case."""
    if _open_for(incident.fingerprint) is not None:
        return False, "OPEN_CASE_EXISTS"
    last = models.TsCase.objects.filter(trigger_source=TRIGGER_SOURCE, trigger_ref=incident.fingerprint).order_by("-opened_at").first()
    if last is not None and (now - last.opened_at).total_seconds() < cfg.cooldown_seconds:
        return False, "COOLDOWN_ACTIVE"
    live = models.TsCase.objects.filter(trigger_source=TRIGGER_SOURCE, opened_at__gte=now - timedelta(hours=1)).exclude(trigger_ref__startswith="REPLAY")
    if live.count() >= cfg.max_cases_per_hour:                              # controlled replays never consume the live budget
        return False, "HOURLY_CASE_BUDGET_EXHAUSTED"
    return True, ""


IDLE_AFTER_SECONDS = 600


def idle_reason(fp: str, now: datetime) -> str:
    """The fault is still present but its open case has made no progress for IDLE_AFTER_SECONDS (e.g. diagnosed without a
    proposal): never a duplicate case, but a human is told once instead of the intake staying silently blocked."""
    case = _open_for(fp)
    if case is None:
        return ""
    last = models.TsAuditEvent.objects.filter(case=case).order_by("-occurred_at").values_list("occurred_at", flat=True).first()
    if last is not None and (now - last).total_seconds() >= IDLE_AFTER_SECONDS:
        return f"OPEN_CASE_IDLE {case.case_id} ({case.state})"
    return ""


def start_dispatch(handoff_id: str) -> bool:
    """Start the existing sandboxed dispatcher unit for this handoff (polkit allows exactly this unit pattern, verb start)."""
    if not HANDOFF_ID.fullmatch(handoff_id):
        return False
    rc = subprocess.run(["systemctl", "start", "--no-block", f"nmas-troubleshooter-dispatch@{handoff_id}.service"],
                        capture_output=True, text=True, timeout=30, check=False).returncode
    return rc == 0


@dataclass
class IntakeDeps:
    run_case: Callable[..., Any] | None = None
    open_handoff: Callable[..., Any] | None = None
    dispatch: Callable[[str], bool] = start_dispatch
    notify: Callable[[str, str], Any] = notify.send


def open_incident(incident: Incident, deps: IntakeDeps | None = None, *, now: datetime | None = None) -> dict:
    """Open the case, run the deterministic Troubleshooter, delegate to Codex and start the dispatcher.  No device write."""
    from core import troubleshooting_views as tv

    from . import ai
    from . import runtime as rt

    deps = deps or IntakeDeps()
    now = now or datetime.now(timezone.utc)
    actor = repo.Actor(ACTOR_NAME, "system", tenant="default", devices=frozenset(incident.devices))
    case = repo.open_case(
        actor, trigger_source=TRIGGER_SOURCE, trigger_ref=incident.fingerprint, severity="HIGH",
        idempotency_key=f"intake:{incident.fingerprint}:{int(incident.onset.timestamp())}",
        title=f"Monitoring: {', '.join(incident.devices)} interface intent violation", symptom=incident.symptom(),
        service_intent={"service": "managed-device interface intent", "source": "nmas-intake"},
        affected_scope={"devices": incident.devices}, target_states={d: "UNKNOWN" for d in incident.devices}, runbook="RB02",
        first_detected_at=incident.onset, now=now)
    (deps.run_case or rt.run_case)(actor, case.case_id, tv._runtime_deps())
    case = models.TsCase.objects.get(pk=case.pk)
    handoff = (deps.open_handoff or ai.open_handoff)(
        actor, case, agent_identity="",
        uncertainty=(f"Monitoring alarm on managed device(s) {', '.join(incident.devices)}: {incident.symptom()} End-host configuration is "
                     "out of scope. Collect live evidence on the affected target(s) with request_diagnostic_test for the applicable catalogue "
                     "tests, then determine the cause on the managed device(s). If a causal fault is evidenced and a registered corrective "
                     "operation applies, call propose_remediation with the exact minimal operation, the causal evidence ids and a "
                     "rollback plan BEFORE submit_investigation_result; then submit the result."),
        special_case_reason=f"monitoring-triggered incident {incident.fingerprint}: unattended diagnosis requested by NMAS intake")
    started = deps.dispatch(handoff.record_id)
    repo.audit(actor, case, "INTAKE_DISPATCH", decision=f"{handoff.record_id} started={started}", result="OK" if started else "NOT_STARTED",
               rationale=f"fingerprint {incident.fingerprint}")                     # actual dispatch time, not the poll's
    if not started:
        deps.notify(f"[NMAS] Intake could not start Codex dispatch for {case.case_id}",
                    f"Handoff {handoff.record_id} is open but the dispatcher unit did not start; an administrator must start it.\n")
    return {"case": case.case_id, "handoff": handoff.record_id, "dispatch_started": started, "fingerprint": incident.fingerprint}


# ------------------------------------------------------------------------------------------------------------------ the loop
@dataclass
class Intake:
    cfg: IntakeConfig = field(default_factory=IntakeConfig.from_settings)
    reader: Callable[[str, IntakeConfig], list[Observation] | None] = read_device
    intent: Callable[[str], dict | None] = hc._intended_admin_states
    deps: IntakeDeps = field(default_factory=IntakeDeps)
    first_seen: dict[tuple[str, str], datetime] = field(default_factory=dict)
    suppressed: set[tuple[str, str]] = field(default_factory=set)
    _peers: dict | None = None

    def poll(self, now: datetime | None = None) -> list[dict]:
        now = now or datetime.now(timezone.utc)
        observations: list[Observation] = []
        unread = []
        for device in self.cfg.devices:
            rows = self.reader(device, self.cfg)
            if rows is None:
                unread.append(device)            # unreadable is NOT healthy: keep its pending violations, decide nothing new
                continue
            observations += rows
        current = violations(observations, self.intent)
        for key in list(self.first_seen):
            if key not in current and key[0] not in unread:
                self.first_seen.pop(key)                                         # cleared before confirmation: a flap, not an incident
        for key in current:
            self.first_seen.setdefault(key, now)
        confirmed = {k: v for k, v in current.items() if (now - self.first_seen[k]).total_seconds() >= self.cfg.confirm_seconds}
        if self._peers is None:
            self._peers = peers(set(self.cfg.devices))
        results = []
        for incident in correlate(confirmed, self._peers, self.first_seen):
            incident.fingerprint = self.cfg.fingerprint_prefix + incident.fingerprint
            ok, why = admission(incident, self.cfg, now)
            if not ok and why == "OPEN_CASE_EXISTS":
                why = idle_reason(incident.fingerprint, now) or why
            if not ok:
                if why != "OPEN_CASE_EXISTS" and (incident.fingerprint, why) not in self.suppressed:
                    self.suppressed.add((incident.fingerprint, why))
                    self.deps.notify(f"[NMAS] Incident {incident.fingerprint} not auto-opened: {why}",
                                     f"{incident.symptom()}\nAutomatic intake declined ({why}); a human must review.\n")
                results.append({"fingerprint": incident.fingerprint, "skipped": why})
                continue
            try:
                results.append(open_incident(incident, self.deps, now=now))
            except Exception as exc:  # noqa: BLE001 - one failed intake never stops monitoring
                results.append({"fingerprint": incident.fingerprint, "error": f"{type(exc).__name__}: {exc}"[:300]})
        live = {self.cfg.fingerprint_prefix + i.fingerprint for i in correlate(confirmed, self._peers, self.first_seen)}
        self.suppressed = {s for s in self.suppressed if s[0] in live}
        return results
