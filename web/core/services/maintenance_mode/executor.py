"""Run one ordered list of maintenance operations: staged, read back, loss-checked, and undone exactly on any failure.

The same shape as the baseline migration's attempt (``route_shield.lifecycle``), on the same primitives: its
``Environment``, the platform executors' ``assess`` / ``apply`` / ``compensate``, the ``Operation`` gates, the production
probes and the host gate.  It differs in what it is tied to: a maintenance record instead of a Change, and it runs in
both directions (the restore of a maintenance is a forward run of the reverse operations).

    precheck      read-only: host gate, probes healthy, the caller's own checks; nothing was written if it fails
    stages        between two stages the window guard; per operation: before-gates, state digest unchanged since our last
                  step, assess, apply, read-back, after-gates, zero lost probes, pause, zero lost probes
    final         the caller's final checks, then the startup configuration of every written cEOS device
    failure       everything applied is compensated newest first; what cannot be undone is reported, never hidden

There is no argument that forces a step, skips a gate or tolerates a lost probe.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from django.utils import timezone

from ..execution.executors.base import APPLY, SKIP_SATISFIED, ConfigletSpec, ExecutorError
from ..route_shield import gates
from ..route_shield.lifecycle import _settle
from ..route_shield.migration import ADD

NOT_A_PRIMITIVE = "NOT_A_MAINTENANCE_PRIMITIVE"
READ_ONLY = "MAINTENANCE_READ_ONLY_DEVICE"

COMPENSATED = "COMPENSATED"
SUCCEEDED, BLOCKED, ROLLED_BACK, INCOMPLETE = "SUCCEEDED", "BLOCKED", "FAILED_ROLLED_BACK", "FAILED_COMPENSATION_INCOMPLETE"


def spec_of(op, sequence: int) -> ConfigletSpec:
    """The executor's view of one operation (as ``route_shield.lifecycle._configlet_fields`` plans it)."""
    cfg = f"MNT-{sequence:03d}"
    if op.cover is not None:                     # a core kernel cover is a migration guard, never a maintenance step
        raise ExecutorError(NOT_A_PRIMITIVE)
    if op.action == ADD:
        return ConfigletSpec(cfg, sequence, op.device, "arista_ceos", "route_shield", "CREATE_DEFINE", tuple(op.lines),
                             {"present_paths": list(op.paths), "inverse_lines": list(op.inverse)})
    removal = {"item": op.key, "absent_paths": list(op.paths), "restorable": True, "restore_lines": list(op.inverse)}
    return ConfigletSpec(cfg, sequence, op.device, "arista_ceos", "config_removal_delete", "REMOVE_DELETE", tuple(op.lines),
                         {"absent_paths": list(op.paths)}, origin="REMOVAL", removal=removal)


class CoreReader:
    """A core router (R3/R4) as Maintenance Mode sees it: the read methods of its executor and nothing else.  Every
    write method raises; a maintenance can observe the cores, never change them."""

    READS = frozenset({"connect", "close", "routes", "routes_within", "full_neighbours", "static_route_digest", "frr_config_digest",
                       "client_route", "persistent_config_digest", "management_interfaces", "neighbour_state", "identity", "platform"})

    def __init__(self, inner):
        self._inner = inner

    def __getattr__(self, name):
        if name not in self.READS:
            raise ExecutorError(READ_ONLY)
        return getattr(self._inner, name)


def read_only(factory, names):
    """``factory`` (device -> executor) with every device of ``names`` handed out as a ``CoreReader``."""
    names = frozenset(names)

    def build(device):
        executor = factory(device)
        return CoreReader(executor) if device.get("name") in names else executor

    return build


@dataclass
class Run:
    env: object                                         # route_shield.lifecycle.Environment, connected by the caller
    ops: list
    persist: tuple[str, ...] = ()                       # cEOS devices whose startup configuration follows the verified result
    prechecks: tuple = ()                               # migration.Check rows: all must hold before the first write
    final: tuple = ()                                   # migration.Check rows: the state this run must end in
    resume: bool = False                                # a restore: an operation already in place is accepted (an interrupted run is finished)
    guard: object = None                                # (op) -> '' or why the operation may not be sent (protection.violations); checked before every write
    startup_accepted: dict = field(default_factory=dict)    # device -> a startup digest accepted besides "equal to running" (a restore: the pre-state's)
    stages: list = field(default_factory=list)
    applied: list = field(default_factory=list)         # (op, spec, assessment, digest before)
    compensation: list = field(default_factory=list)
    failure: dict = field(default_factory=dict)
    persisted: dict = field(default_factory=dict)
    probes_lost: int = 0
    lost_at_start: int = 0
    restored: bool | None = None
    _expected: dict = field(default_factory=dict)
    _startup: dict = field(default_factory=dict)

    # -- evidence ---------------------------------------------------------------------------------------------------------
    def note(self, stage: str, status: str, **facts) -> None:
        self.stages.append({"stage": stage, "at": timezone.now().isoformat(), "status": status, **facts})

    def lost(self) -> int:
        self.probes_lost = max(self.probes_lost, int(self.env.probes.lost()) - self.lost_at_start)
        return self.probes_lost

    def fail(self, code: str, detail: str = "", key: str = "") -> None:
        if not self.failure:
            self.failure = {"code": code, "detail": str(detail)[:300], "operation": key}
            self.note("abort", code, operation=key, detail=str(detail)[:300])

    def _gate(self, checks, key: str, phase: str) -> bool:
        for check in checks:
            ok, detail = _settle(check, self.env)
            if not ok:
                self.fail("GATE_FAILED", f"{phase}: {check.label}: {detail}", key)
                return False
        return True

    def _pause(self, seconds: float) -> None:
        if seconds:
            self.env.sleep(seconds)
        maintain = getattr(self.env.probes, "maintain", None)
        if maintain is not None:
            maintain()

    def _digest(self, device: str):
        executor = self.env.executors[device]
        return executor.config_state_digest() if hasattr(executor, "config_state_digest") else None

    # -- precheck (read-only) ---------------------------------------------------------------------------------------------
    def precheck(self) -> list[dict]:
        """Everything that must hold before the first write.  -> blockers; nothing was sent to any device."""
        env, blockers = self.env, []
        if env.probes is None or env.host_gate is None:
            return [{"code": gates.PROBES_UNHEALTHY if env.probes is None else gates.HOST_GATE, "detail": "no probe source / host gate was supplied"}]
        ok, host = env.host_gate()
        if not ok:
            blockers.append({"code": gates.HOST_GATE, "detail": str(host)[:200]})
        ok, detail = env.probes.healthy()
        if not ok:
            blockers.append({"code": gates.PROBES_UNHEALTHY, "detail": str(detail)[:200]})
        try:
            for name in self.persist:
                startup = env.executors[name].startup_state_digest()
                if startup != env.executors[name].config_state_digest() and startup != self.startup_accepted.get(name):
                    blockers.append({"code": "STARTUP_NOT_IN_SYNC", "detail": f"{name}: the startup configuration is not the running configuration"})
            for check in self.prechecks:
                ok, detail = _settle(check, env)
                if not ok:
                    blockers.append({"code": "PRECHECK_FAILED", "detail": f"{check.label}: {detail}"})
        except ExecutorError as exc:
            blockers.append({"code": gates.EVIDENCE_UNAVAILABLE, "detail": exc.code})
        self.note("precheck", "BLOCKED" if blockers else "PASS", blockers=[b["code"] for b in blockers], host=host, probes=detail if not blockers else None)
        return blockers

    # -- forward ----------------------------------------------------------------------------------------------------------
    def drive(self) -> str:
        """Run the operations.  -> SUCCEEDED, FAILED_ROLLED_BACK or FAILED_COMPENSATION_INCOMPLETE.  The caller ran
        ``precheck`` first; a run with nothing applied that fails is rolled back by definition."""
        env = self.env
        self.lost_at_start = int(env.probes.lost())
        try:
            devices = {op.device for op in self.ops} | set(self.persist)
            self._expected = {name: self._digest(name) for name in devices}
            self._startup = {name: env.executors[name].startup_state_digest() for name in self.persist}
            stage = None
            for sequence, op in enumerate(self.ops, 1):
                if op.stage != stage and not self.window_guard(op.stage):          # abort BEFORE the next stage, never inside one
                    break
                stage = op.stage
                if not self.apply(op, spec_of(op, sequence)):
                    break
            if not self.failure and self.window_guard("FINAL_VALIDATION"):
                self.finish()
        except Exception as exc:  # noqa: BLE001 - an engine or hook failure after the first write takes the reverse path
            self.fail("INTERNAL_ERROR", type(exc).__name__)
        if not self.failure:
            return SUCCEEDED
        self.compensate()
        return ROLLED_BACK if self.restored else INCOMPLETE

    def window_guard(self, stage: str) -> bool:
        """Between two stages: the host is still inside the window's resource condition, every probe flow still delivers
        samples and none was lost.  A busy host or a silent probe is never read as "nothing was lost"."""
        env = self.env
        samples = getattr(env.host_gate, "consecutive_samples", None)
        ok, facts = False, {}
        for _sample in range(max(1, int(samples() if callable(samples) else samples or 1))):
            ok, facts = env.host_gate()
            if ok:
                break
        if not ok:
            self.fail(gates.WINDOW_CONDITION_LOST, f"before {stage}: " + "; ".join((facts or {}).get("failed") or ["host gate failed"]), stage)
            return False
        advancing = getattr(env.probes, "advancing", None)
        ok, detail = advancing() if advancing is not None else (False, {"errors": ["the probe source cannot report progress"]})
        if not ok:
            self.fail(gates.PROBE_TIMING_UNRELIABLE, f"before {stage}: stalled flows {detail.get('stalled_flows') or detail.get('errors')}", stage)
            return False
        if self.lost():
            self.fail(gates.PACKET_LOSS, f"production probes were lost before {stage}", stage)
            return False
        self.note("window", "PASS", before=stage, load1=(facts or {}).get("load1"), probes_lost=0)
        return True

    def apply(self, op, spec) -> bool:
        if self.guard is not None:
            refused = self.guard(op)  # pylint: disable=not-callable  # injected callable (dataclass field annotated object)
            if refused:
                self.fail(refused.split(":", 1)[0], refused, op.key)
                return False
        env, executor = self.env, self.env.executors[op.device]
        env.notify("before", op.key)
        before = self._digest(op.device)
        if before is not None and before != self._expected[op.device]:
            self.fail(gates.OUT_OF_BAND, f"{op.device} changed between two steps of this run", op.key)
            return False
        assessment = executor.assess(spec)
        if assessment.action == SKIP_SATISFIED and self.resume:
            self.note(op.stage, "ALREADY_IN_PLACE", operation=op.key, device=op.device, state=op.state)
            return self._gate(op.after, op.key, "after")
        if not self._gate(op.before, op.key, "before"):
            return False
        if assessment.action != APPLY or not assessment.restorable:
            code = gates.OUT_OF_BAND if assessment.action == SKIP_SATISFIED else (assessment.reason or "COMPENSATION_NOT_PROVABLE")
            self.fail(code, f"{op.key}: {assessment.action} ({assessment.reason or 'state is not the planned one'})", op.key)
            return False
        outcome = executor.apply(spec, assessment)
        env.last_change_at = env.clock()
        if outcome.ok or outcome.partial_effects:
            self.applied.append((op, spec, assessment, before))
        if not outcome.ok:
            self.fail("APPLY_FAILED", f"{op.key}: {outcome.error_code}", op.key)
            return False
        read_back = executor.assess(spec).action
        after = self._digest(op.device)
        if after is not None:
            self._expected[op.device] = after
        self.note(op.stage, "APPLIED", operation=op.key, device=op.device, state=op.state, lines=list(op.lines), read_back=read_back, probes_lost=self.lost())
        if read_back != SKIP_SATISFIED:
            self.fail("READ_BACK_MISMATCH", f"{op.key}: the device does not report the operation as in place", op.key)
            return False
        if not self._gate(op.after, op.key, "after"):
            return False
        env.notify("after", op.key)
        if self.lost():
            self.fail(gates.PACKET_LOSS, f"production probes were lost at {op.key}", op.key)
            return False
        self._pause(op.pause)
        if self.lost():
            self.fail(gates.PACKET_LOSS, f"production probes were lost after {op.key}", op.key)
            return False
        return True

    # -- final state and persistence --------------------------------------------------------------------------------------
    def finish(self) -> None:
        env = self.env
        env.notify("before", "FINAL_VALIDATION")
        failed = []
        for check in self.final:
            ok, detail = _settle(check, env)
            if not ok:
                failed.append({"check": check.label, "detail": detail})
        if self.lost():
            failed.append({"check": "no production probe was lost", "detail": str(self.probes_lost)})
        self.note("FINAL_VALIDATION", "FAIL" if failed else "PASS", failed=failed[:10], probes_lost=self.probes_lost)
        if failed:
            self.fail("FINAL_STATE_NOT_VERIFIED", f"{failed[0]['check']}: {failed[0]['detail']}")
            return
        for name in self.persist:                       # exactly the verified running configuration becomes the startup configuration
            executor, wanted = env.executors[name], self._expected[name]
            env.notify("before", f"PERSISTENCE-{name}")
            if executor.config_state_digest() != wanted:
                self.fail("PERSISTENCE_NOT_VERIFIED", f"{name}: the running configuration changed after the final validation")
                return
            self.persisted[name] = "NOT_VERIFIED"       # recorded before the write: recovery covers a half-written device
            outcome = executor.save_startup()
            if not outcome.ok or executor.startup_state_digest() != wanted:
                self.fail("PERSISTENCE_NOT_VERIFIED", f"{name}: startup and running configuration are not the same state")
                return
            self.persisted[name] = "VERIFIED"
            self.note("PERSISTENCE", "VERIFIED", device=name)
            env.notify("after", f"PERSISTENCE-{name}")

    # -- reverse path -----------------------------------------------------------------------------------------------------
    def compensate(self) -> None:
        """Undo, newest first, exactly what this run applied.  Stops at the first step that cannot be proven safe or
        restored; the startup configuration this run wrote follows the restored running configuration."""
        env, complete = self.env, True
        for op, spec, assessment, before in reversed(self.applied):
            entry = {"operation": op.key, "device": op.device, "state": op.state}
            self.compensation.append(entry)
            try:
                unsafe = next((c for c in op.undo_before if not _settle(c, env)[0]), None)
                if unsafe is not None:
                    entry.update(status="NOT_COMPENSATED", error=f"not safe to undo: {unsafe.label}")
                    complete = False
                    break
                outcome = env.executors[op.device].compensate(spec, assessment)
                env.last_change_at = env.clock()
                status, error = outcome.status, outcome.error_code
                if status == COMPENSATED and before is not None and self._digest(op.device) != before:
                    status, error = "COMPENSATION_FAILED", "STATE_NOT_RESTORED"
                entry.update(status=status, error=error)
                if status != COMPENSATED:
                    complete = False
                    break
                unverified = next((c for c in op.undo_after if not _settle(c, env)[0]), None)
                if unverified is not None:
                    entry.update(status="COMPENSATED_UNVERIFIED", error=f"not verified: {unverified.label}")
                    complete = False
                    break
                self.lost()
                self._pause(op.undo_pause)
            except Exception as exc:  # noqa: BLE001 - compensation never raises past its own evidence
                entry.update(status="NOT_COMPENSATED", error=type(exc).__name__)
                complete = False
                break
        for name in self.persisted if complete else ():
            try:
                outcome = env.executors[name].save_startup()
                back = outcome.ok and env.executors[name].startup_state_digest() == self._startup[name]
            except Exception:  # noqa: BLE001
                back = False
            self.persisted[name] = "STARTUP_RESTORED" if back else "NOT_RESTORED"
            complete = complete and back
        self.restored = complete
        self.lost()
        self.note("restore", "RESTORED" if complete else "RESTORE_INCOMPLETE", compensated=sum(e.get("status") == COMPENSATED for e in self.compensation),
                  probes_lost=self.probes_lost)

    def report(self, outcome: str) -> dict:
        probes = getattr(self.env.probes, "report", None)
        return {"outcome": outcome, "failure": self.failure, "stages": self.stages, "applied": [entry[0].key for entry in self.applied],
                "compensation": self.compensation, "restored": self.restored, "persistence": self.persisted,
                "probes": {"lost": self.probes_lost, **({"flows": probes()} if probes is not None else {})}}
