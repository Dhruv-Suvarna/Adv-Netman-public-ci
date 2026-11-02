"""Operations for the reviewed R1 2FA pilot helper (``manage.py r1_mfa_pilot``).

Read-only / non-persistent:  validate, status, verify-logins, verify-positive
Mutating (approval + gates): checkpoint, stage1, stage2, confirm, replace
Metadata (approval + gates): record-verification (R1 policy row only; no device change)

Every mutating operation first reads the operator's approval phrase from an
interactive terminal, then re-checks all gates against the LIVE device and the
recorded evidence, and refuses on any failure.  Evidence is append-only
``AuditEvent(MFA_PILOT_STEP)`` metadata that is checked secret-free before it is
written.  See ``r1_pilot`` for transport, redaction and leak detection.
"""
from __future__ import annotations

import datetime
import json
import time
from dataclasses import dataclass, field
from typing import Callable

from django.db import transaction

from ...models import (AuditEvent, AuditEventType, CentralAaaState, DeviceCredential, DeviceLoginMfaPolicy,
                       MfaEnforcementState, MfaMechanism)
from . import r1_pilot as p
from .mfa import render_candidate

ACCEPT, REJECT = "ACCEPT", "REJECT"
FLEET_CEOS = ("R2", "S1", "S2", "S3", "S4", "mgmt_swt")
FLEET_IDENTITY = "admin"


# --------------------------------------------------------------------------- evidence
class PilotEvidence:
    """Append-only pilot evidence.  Refuses to persist anything containing a known secret."""

    def __init__(self, device: str = p.PILOT_DEVICE):
        self.device = device

    def record(self, step: str, *, ok: bool, known: p.SecretSet, at: float, actor: str = "", **data) -> dict:
        metadata = {"step": step, "ok": bool(ok), "at": at, "device": self.device, **data}
        blob = json.dumps(metadata, sort_keys=True, default=str)
        if known.checkable().occurs_in(blob):
            raise p.PilotError(f"Evidence for {step} contained a known secret; it was NOT recorded.")
        AuditEvent.objects.create(
            event_type=AuditEventType.MFA_PILOT_STEP, object_type="DeviceLoginMfaPolicy", object_id=self.device,
            actor=actor[:150], summary=f"{self.device} MFA rollout {step}: {'PASS' if ok else 'FAIL'}"[:255],
            metadata=json.loads(blob),
        )
        return metadata

    def latest(self, step: str, *, ok: bool | None = None, since: float | None = None) -> dict | None:
        entry = self.latest_entry(step, ok=ok, since=since)
        return entry[1] if entry else None

    def latest_entry(self, step: str, *, ok: bool | None = None, since: float | None = None) -> tuple[int, dict] | None:
        """(AuditEvent id, metadata) of the most recent matching step."""
        rows = AuditEvent.objects.filter(event_type=AuditEventType.MFA_PILOT_STEP, object_id=self.device).order_by("-id")
        for row in rows:
            meta = row.metadata or {}
            if meta.get("step") != step:
                continue
            if ok is not None and bool(meta.get("ok")) != ok:
                continue
            if since is not None and float(meta.get("at", 0)) < since:
                continue
            return row.id, meta
        return None


# --------------------------------------------------------------------------- dependencies
def _read_tty_line(prompt: str, *, device: str = "/dev/tty") -> str:
    # Separate read/write handles: a terminal is not seekable, so a text-mode
    # "r+" open raises io.UnsupportedOperation (an OSError) on a real TTY.
    # O_NOCTTY prevents a test pseudo-terminal (or a detached automation
    # session) from becoming this process's controlling terminal and sending
    # SIGHUP when it closes.
    import os

    try:
        out_fd = os.open(device, os.O_WRONLY | os.O_NOCTTY)
        in_fd = os.open(device, os.O_RDONLY | os.O_NOCTTY)
        with os.fdopen(out_fd, "w", encoding="utf-8") as out, os.fdopen(in_fd, "r", encoding="utf-8") as inp:
            out.write(prompt)
            out.flush()
            return inp.readline().rstrip("\r\n")
    except OSError:
        raise p.PilotError("An interactive terminal is required for the approval phrase.") from None


def tty_approval_reader(phrase: str = p.APPROVAL_PHRASE) -> str:
    return _read_tty_line(f'Type exactly "{phrase}" to proceed: ')


def tty_human_factor_reader() -> tuple[str, str]:
    import getpass

    try:
        password = getpass.getpass(f"{p.HUMAN_USERNAME} password (not echoed): ")
        otp = getpass.getpass("Current Microsoft Authenticator code (not echoed): ")
    except (EOFError, OSError):
        raise p.PilotError("An interactive terminal is required for the human factor check.") from None
    return password, otp


def paramiko_login(username: str, password: str, *, address: str = p.PILOT_MGMT_ADDRESS) -> dict:
    """One fresh SSH password login with a redacted exact privilege result."""
    import paramiko

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(address, username=username, password=password, look_for_keys=False, allow_agent=False,
                       timeout=15, auth_timeout=20, banner_timeout=15)
        _, stdout, _ = client.exec_command("show privilege", timeout=15)
        text = " ".join(stdout.read().decode(errors="replace").split())
        level = p.parse_privilege_level(text)
        return {"login": ACCEPT, "privilege_level": level,
                "privilege": "PASS" if level == 15 else "FAIL"}
    except paramiko.AuthenticationException:
        return {"login": REJECT}
    except Exception as exc:  # noqa: BLE001 - connection details are never echoed
        return {"login": f"ERROR {exc.__class__.__name__}"}
    finally:
        client.close()


def single_password_login(username: str, password: str, *, address: str = p.PILOT_MGMT_ADDRESS, port: int = 22,
                          command: str = "show privilege") -> dict:
    """EXACTLY ONE SSH password authentication (no keyboard-interactive fallback, no retry, no
    keys/agent), then one read-only command.  Distinguishes an unreachable R1 (nothing was
    sent) from a rejected login, and a refused command after a successful login."""
    import socket

    import paramiko

    try:
        sock = socket.create_connection((address, port), timeout=15)
    except OSError as exc:
        return {"login": "UNREACHABLE", "stage": "connect", "error": exc.__class__.__name__}
    transport = paramiko.Transport(sock)
    try:
        try:
            transport.start_client(timeout=15)
        except Exception as exc:  # noqa: BLE001
            return {"login": "UNREACHABLE", "stage": "handshake", "error": exc.__class__.__name__}
        try:
            transport.auth_password(username, password, fallback=False)
        except paramiko.AuthenticationException:
            return {"login": REJECT, "stage": "auth"}
        except Exception as exc:  # noqa: BLE001
            return {"login": f"ERROR {exc.__class__.__name__}", "stage": "auth"}
        if not transport.is_authenticated():
            return {"login": REJECT, "stage": "auth"}
        try:
            channel = transport.open_session(timeout=15)
            channel.settimeout(15)
            channel.exec_command(command)
            raw = channel.makefile("rb").read() + channel.makefile_stderr("rb").read()
            text = " ".join(raw.decode(errors="replace").split())
        except Exception as exc:  # noqa: BLE001
            return {"login": ACCEPT, "stage": "command", "command": "ERROR", "error": exc.__class__.__name__}
        return {"login": ACCEPT, "stage": "command", "command": p.classify_command_output(text),
                "privilege_level": p.parse_privilege_level(text)}
    finally:
        transport.close()


# Every committed configuration session makes EOS emit SNMP config-change notifications
# (arista-config-man-event / ent-config-change, enabled by global default), which Health
# counts as "recent critical events" for its 15-minute window.  The pilot's own commits
# therefore always produce that WARN, so it is tolerated -- but only when no critical
# syslog event is involved.  CPU in the warning band (a critical CPU is already a FAIL)
# is tolerated too.  Any FAIL, UNKNOWN or other WARN fails verification.
TOLERATED_HEALTH_WARNINGS = ("CRITICAL_EVENTS_RECENT", "CPU_HIGH")


def health_verdict(report: dict) -> dict:
    tolerated, blocking = [], []
    for result in report.get("results") or []:
        status, code = result.get("status"), result.get("check_code")
        if status in ("PASS", "NOT_APPLICABLE"):
            continue
        observed = result.get("observed") or {}
        if status == "WARN" and code == "CRITICAL_EVENTS_RECENT" and int(observed.get("critical_syslog") or 0) == 0:
            tolerated.append({"check_code": code, "snmp_traps": observed.get("snmp_traps")})
        elif status == "WARN" and code == "CPU_HIGH":
            tolerated.append({"check_code": code, "message": str(result.get("message", ""))[:120]})
        else:
            blocking.append({"check_code": code, "status": status, "message": str(result.get("message", ""))[:160]})
    return {"ok": bool(report.get("results")) and not blocking, "status": report.get("status"),
            "tolerated_warnings": tolerated, "blocking": blocking}


def nmas_read_paths(device: str = p.PILOT_DEVICE) -> dict:
    """Canonical resolver identities plus target NSOT/config/Health reads."""
    from .. import nsot_live
    from ..config_import import service as config_import
    from ..health.device import run_device_health

    def identities(device):
        meta = nsot_live.get_live_target_metadata(device, purpose="WRITE") or {}
        return [profile["username"] for profile in meta.get("access_profiles", ())]

    other_devices = [name for name in p.MANAGED_CEOS_MFA_DEVICES if name != device]
    other = {name: identities(name) for name in other_devices}
    nsot = nsot_live.fetch_running_config(device)
    fetched, _ = config_import.fetch_sanitized_running_config(device)
    _, report = run_device_health(device, persist=False)
    verdict = health_verdict(report)
    return {
        "target_identities": identities(device),
        "other_identities": other,
        "nsot": nsot.get("status") == "available",
        "config_retrieval": fetched is not None,
        "health": verdict["ok"],
        "health_status": report.get("status"),
        "health_tolerated_warnings": verdict["tolerated_warnings"],
        "health_blocking": verdict["blocking"],
    }


def reviewed_candidate(target: p.CeosMfaTarget | None = None) -> p.StagedCandidate:
    target = target or p.target_for(p.PILOT_DEVICE)
    policy = DeviceLoginMfaPolicy.objects.get(device_name=target.device)
    credentials = list(DeviceCredential.objects.filter(device_name=target.device))
    return p.staged_candidate(render_candidate(policy, credentials), target)


@dataclass
class PilotDependencies:
    transport: p.EosCliTransport = field(default_factory=p.EosCliTransport)
    resolver: p.PilotSecretResolver = field(default_factory=p.PilotSecretResolver)
    evidence: PilotEvidence = field(default_factory=PilotEvidence)
    candidate: Callable[[], p.StagedCandidate] = reviewed_candidate
    infrastructure: Callable[[], tuple[bool, list]] = p.mfa_infrastructure_healthy
    reachable: Callable[[], bool] = p.management_reachable
    ssh_login: Callable[[str, str], dict] = paramiko_login
    nmas_reads: Callable[[], dict] = nmas_read_paths
    human_factors: Callable[[], tuple[str, str]] = tty_human_factor_reader
    human_login: Callable[[str, str], dict] = single_password_login
    privacyidea: p.PrivacyIdeaReader = field(default_factory=p.PrivacyIdeaReader)
    approval: Callable[[], str] = tty_approval_reader
    clock: Callable[[], float] = time.time
    actor: str = ""


def dependencies_for(target: p.CeosMfaTarget) -> PilotDependencies:
    """Bind every live dependency to exactly one immutable device target."""
    return PilotDependencies(
        transport=p.EosCliTransport(container=target.container),
        evidence=PilotEvidence(device=target.device),
        candidate=lambda: reviewed_candidate(target),
        reachable=lambda: p.management_reachable(target.management_address),
        ssh_login=lambda username, password: paramiko_login(username, password, address=target.management_address),
        nmas_reads=lambda: nmas_read_paths(target.device),
        human_login=lambda username, password: single_password_login(
            username, password, address=target.management_address),
        approval=lambda: tty_approval_reader(target.approval_phrase),
    )


# --------------------------------------------------------------------------- runner
class R1PilotRunner:
    """Backward-compatible name for the device-aware cEOS MFA rollout runner."""

    def __init__(self, deps: PilotDependencies | None = None, *, device: str = p.PILOT_DEVICE,
                 target: p.CeosMfaTarget | None = None):
        self.target = target or p.target_for(device)
        self.deps = deps or dependencies_for(self.target)
        self.device = self.target.device
        self._shape_values: set[str] = set()  # real values read ONLY to shape canaries (memory only)

    # ---- shared helpers
    @property
    def t(self) -> p.EosCliTransport:
        return self.deps.transport

    def _require_device(self) -> None:
        if self.device != self.target.device or self.t.container != self.target.container:
            raise p.PilotError(
                f"This runner only targets {self.target.device}; transport/target mismatch refuses {self.device!r}.")

    def _require_approval(self) -> None:
        if self.deps.approval() != self.target.approval_phrase:
            raise p.PilotError("Approval phrase not supplied exactly; nothing was changed.")

    def _record(self, step, *, ok, known=p.SecretSet(), at: float | None = None, **data) -> dict:
        at = self.deps.clock() if at is None else at
        return self.deps.evidence.record(step, ok=ok, known=known, at=at, actor=self.deps.actor, **data)

    def _state(self) -> tuple[str, str, dict]:
        config = p.running_config(self.t)
        return config, p.running_digest(config), p.config_sessions(self.t)

    def _expected_candidate_digest(self) -> str:
        if self.target.compatibility_r1:
            return p.REVIEWED_CANDIDATE_DIGEST
        policy = DeviceLoginMfaPolicy.objects.filter(device_name=self.device).first()
        return policy.candidate_digest if policy else ""

    def _expected_original_digest(self) -> str:
        if self.target.compatibility_r1:
            return p.REVIEWED_ORIGINAL_DIGEST
        precheck = self.deps.evidence.latest("precheck", ok=True)
        if precheck is None:
            raise p.PilotError("A fresh passing precheck is required before the original checkpoint.")
        return str(precheck.get("running_digest") or "")

    def _gates(self, *, expected_digest: str | None, digest: str, sessions: dict, allowed_sessions=()) -> p.GateReport:
        gates = p.GateReport()
        gates.check("device", self.device == self.target.device and self.t.container == self.target.container, self.device)
        try:
            staged = self.deps.candidate()
            reviewed = self._expected_candidate_digest()
            gates.check("candidate_digest", bool(reviewed) and staged.digest == reviewed,
                        "render digest differs from the reviewed/recorded digest")
        except (p.PilotError, DeviceLoginMfaPolicy.DoesNotExist) as exc:
            gates.check("candidate_digest", False, str(exc))
        if expected_digest is not None:
            gates.check("pre_change_digest", digest == expected_digest,
                        f"{self.device} running-config differs from the expected pre-change state")
        unexpected = sorted(set(p.open_sessions(sessions)) - set(allowed_sessions))
        gates.check("config_sessions", not unexpected, f"unexpected sessions {unexpected}")
        missing = [ref for ref in self.target.config_refs if not self.deps.resolver.exists(ref)]
        missing += [ref for ref in self.target.login_only_refs if not self.deps.resolver.exists(ref, for_config=False)]
        gates.check("protected_refs", not missing, f"missing/invalid {missing}")
        healthy, problems = self.deps.infrastructure()
        gates.check("human_mfa_infrastructure", healthy, f"unhealthy {problems}")
        gates.check("management_reachability", self.deps.reachable(),
                    f"TCP/22 to {self.target.management_address} failed")
        return gates

    @staticmethod
    def _enforce(gates: p.GateReport) -> None:
        if not gates.ok:
            raise p.PilotError("Gate(s) failed; refusing: " + "; ".join(gates.failures))

    def _checkpoint(self, name: str) -> dict | None:
        return self.deps.evidence.latest(f"checkpoint:{name}", ok=True)

    def _checkpoint_intact(self, name: str) -> dict:
        recorded = self._checkpoint(name)
        if recorded is None:
            raise p.PilotError(f"flash:{name}.cfg has not been recorded.")
        current = self.t.file_digests(f"/mnt/flash/{name}.cfg")
        if current is None or current["sha256"] != recorded["file_sha256"] or current["md5"] != recorded["file_md5"]:
            raise p.PilotError(f"flash:{name}.cfg is missing or no longer matches its recorded digests.")
        return recorded

    def _two_phase(self, session: str, lines: list[str], known: p.SecretSet, commit_command: str) -> tuple[p.CliResult, p.CliResult | None]:
        """Open+fill (no commit) -> inspect -> commit from exec mode, or abort."""
        staged = self.t.run([f"configure session {session}", *lines, "show session-config diffs"], known)
        _, _, sessions = self._state()
        if not staged.clean or session not in p.open_sessions(sessions):
            self.t.run([f"configure session {session} abort"])
            return staged, None
        committed = self.t.run([commit_command], known)
        return staged, committed

    def _shape_of(self, reference: str) -> str | None:
        """Real value for canary SHAPING only (in memory; never sent).  Config refs only."""
        if reference not in self.target.config_refs:
            return None
        try:
            value = self.deps.resolver.resolve(reference)
        except p.PilotError:
            return None
        self._shape_values.add(value)
        return value

    def _preflight(self, session: str, template_lines: tuple[str, ...]) -> dict:
        """Parse the exact lines with fresh canaries in an aborted session BEFORE any real
        secret is sent: EOS accounting records a rejected command verbatim, so a parse
        failure must only ever happen with a canary."""
        canary = p.CanaryResolver(shape_of=self._shape_of)
        lines, _ = p.substitute(template_lines, canary)
        name = f"{session}-PF"
        # Local leak checks also cover the real values used for shaping (never sent to R1).
        result = self.t.run([f"configure session {name}", *lines, "abort"], canary.known.merged(p.SecretSet(self._shape_values)))
        if name in p.open_sessions(p.config_sessions(self.t)):
            self.t.run([f"configure session {name} abort"])
        if not result.clean:
            raise p.PilotError("Canary pre-flight parse failed; no real secret was sent. Do not proceed.")
        return {"preflight_parse_clean": True}

    @staticmethod
    def _leak_summary(*results: p.CliResult | None) -> dict:
        summary: dict[str, bool] = {}
        for result in results:
            if result is None:
                continue
            for category, leaked in result.leaks.items():
                summary[category] = summary.get(category, False) or leaked
        return summary

    # ---- validate (non-persistent parser validation with canaries)
    def validate(self) -> dict:
        self._require_device()
        _, before, sessions = self._state()
        if p.open_sessions(sessions):
            raise p.PilotError(f"Refusing to validate while configuration sessions are open: {sorted(p.open_sessions(sessions))}")
        staged = self.deps.candidate()
        canary = p.CanaryResolver(shape_of=self._shape_of)
        s1, _ = p.substitute(staged.stage1, canary)
        s2, _ = p.substitute(staged.stage2, canary)
        rb, _ = p.substitute(staged.rollback, canary)
        substitution_known = canary.known  # canaries standing in for real secrets; must never persist on R1
        echo_canary = canary.extra("echo")
        echo_line = f"nmas-canary-invalid-command {echo_canary}"
        # Output/process/evidence checks also cover real shaping values; the R1 file scan
        # below uses canaries only, so no real value is ever sent to the device.
        known = canary.known.merged(p.SecretSet(self._shape_values))
        v1s, v12, vrb, vecho = self.target.validation_sessions
        runs: dict[str, p.CliResult] = {}
        try:
            runs["stage1"] = self.t.run([f"configure session {v1s}", *s1, "show session-config diffs"], known)
            persists = v1s in p.open_sessions(p.config_sessions(self.t))
            runs["stage1_abort"] = self.t.run([f"configure session {v1s} abort"], known)
            runs["stage1_stage2"] = self.t.run([f"configure session {v12}", *s1, *s2, "show session-config diffs", "abort"], known)
            runs["stage1_stage2_rollback"] = self.t.run(
                [f"configure session {vrb}", *s1, *s2, *rb, "show session-config diffs", "abort"], known)
            runs["echo_probe"] = self.t.run([f"configure session {vecho}", echo_line, "show clock", "abort"], known)
        finally:
            for leftover in set(p.open_sessions(p.config_sessions(self.t))) & set(self.target.validation_sessions):
                self.t.run([f"configure session {leftover} abort"])
        _, after, sessions_after = self._state()
        # EOS command accounting masks secrets of commands that PARSE but records a
        # rejected command verbatim.  The candidate/rollback canaries must never be
        # found on R1; the deliberately rejected echo-probe canary is expected there.
        device_hits = self.t.device_leak_scan(substitution_known)
        rejected_logged = self.t.device_leak_scan(p.SecretSet([echo_canary]))

        added_stage2 = p.diff_changed_lines(runs["stage1_stage2"].output)
        stage2_shape = (f"+{p.ACTIVATION_MARKER}" in [l.rstrip() for l in added_stage2]
                        and any(l.startswith("-username admin ") for l in added_stage2))
        rb_changed = p.diff_changed_lines(runs["stage1_stage2_rollback"].output)
        rb_on_device = all(l[1:].startswith("username admin ") for l in rb_changed)
        echo = runs["echo_probe"]
        parser_ok = all(not runs[k].errors for k in ("stage1", "stage1_abort", "stage1_stage2", "stage1_stage2_rollback"))
        leak_free = all(not runs[k].leaked for k in ("stage1", "stage1_abort", "stage1_stage2", "stage1_stage2_rollback"))
        echo_ok = (bool(echo.errors) and echo.leaks["cli_output"] and not known.occurs_in(echo.output)
                   and not any(v for k, v in echo.leaks.items() if k != "cli_output"))
        pairing = p.rollback_pairing(staged, self.target)
        result = {
            "running_digest_before": before, "running_digest_after": after,
            "running_config_unchanged": before == after,
            "sessions_after": sorted(p.open_sessions(sessions_after)),
            "candidate_digest": staged.digest,
            "candidate_digest_reviewed": staged.digest == self._expected_candidate_digest(),
            "parser_errors": {k: v.errors for k, v in runs.items() if k != "echo_probe"},
            "parser_accepts_candidate_and_rollback": parser_ok,
            "stage2_diff_shape_ok": stage2_shape,
            "rollback_reverts_candidate_on_device": rb_on_device,
            "rollback_residual_diff_lines": len(rb_changed),
            "rollback_pairing": pairing,
            "session_persists_after_cli_exit": persists,
            "cli_continues_after_error": "Timezone" in echo.output,
            "leaks": {k: v.leaks for k, v in runs.items() if k != "echo_probe"},
            "echo_probe": {"parser_error_seen": bool(echo.errors), "canary_echo_detected": echo.leaks["cli_output"],
                           "canary_absent_from_emitted_output": not known.occurs_in(echo.output), "PASS": echo_ok},
            "device_leak_files": device_hits,
            "rejected_command_logged_verbatim_in": rejected_logged,
            "canaries_shaped_like_real_secrets": sorted(canary.shaped),
        }
        result["PASS"] = (before == after and not p.open_sessions(sessions_after) and parser_ok and leak_free and echo_ok and stage2_shape
                          and rb_on_device and pairing["valid"] and not device_hits and persists
                          and staged.digest == self._expected_candidate_digest())
        self._record("validate", ok=result["PASS"], known=known, **result)
        return result

    # ---- precheck (read-only closure immediately before first mutation)
    def precheck(self) -> dict:
        self._require_device()
        config, digest, sessions = self._state()
        users = set(p.local_usernames(config))
        gates = self._gates(expected_digest=None, digest=digest, sessions=sessions)
        gates.check("legacy_admin_present", "admin" in users, "legacy admin is not available for the pre-migration state")
        gates.check("stage1_accounts_absent", not (users & set(self.target.accounts)),
                    f"already present {sorted(users & set(self.target.accounts))}")
        try:
            recovery = "Software image version" in self.t.show("show version")
        except p.PilotError:
            recovery = False
        gates.check("docker_exec_recovery", recovery, "privileged container Cli check failed")
        try:
            routing = self.deps.nmas_reads()
            target_identities = routing.get("target_identities", routing.get("r1_identities", []))
            other_identities = routing.get("other_identities", routing.get("fleet_identities", {}))
            gates.check("canonical_credential_resolver", bool(target_identities), "target has no credential route")
        except Exception:  # noqa: BLE001 - evidence remains sanitized
            target_identities, other_identities = [], {}
            gates.check("canonical_credential_resolver", False, "credential resolver/read paths failed")
        checkpoint_exists = any(self.t.file_digests(f"/mnt/flash/{name}.cfg") is not None
                                for name in self.target.checkpoints)
        gates.check("checkpoint_names_unused", not checkpoint_exists, "a target checkpoint file already exists")
        result = {
            "device": self.device,
            "PASS": gates.ok,
            "running_digest": digest,
            "local_users": sorted(users),
            "security_config": p.security_summary(config),
            "management_address": self.target.management_address,
            "checkpoint_status": "READY" if not checkpoint_exists else "EXISTS",
            "recovery_path": "docker exec privileged Cli + exact checkpoint restore",
            "candidate_digest": self.deps.candidate().digest,
            "candidate_summary": {"stage1_lines": len(self.deps.candidate().stage1),
                                  "stage2_lines": len(self.deps.candidate().stage2)},
            "target_identities": target_identities,
            "other_device_identities": other_identities,
            "timer_behavior": f"EOS commit timer {p.COMMIT_TIMER}; unconfirmed Stage 2 auto-reverts",
            "rollback": f"allow timer reversion or restore flash:{self.target.checkpoint_original}.cfg by recorded MD5",
            "gates": {"passed": gates.passed, "failed": gates.failures},
        }
        self._record("precheck", ok=result["PASS"], **result)
        return result

    # ---- status (read-only)
    def status(self) -> dict:
        self._require_device()
        config, digest, sessions = self._state()
        armed = self.deps.evidence.latest("stage2-armed", ok=True)
        confirmed = self.deps.evidence.latest("confirm", ok=True, since=armed["at"] if armed else None)
        gates = self._gates(expected_digest=None, digest=digest, sessions=sessions,
                            allowed_sessions=(self.target.stage2_session,))
        try:
            original = self._expected_original_digest()
        except p.PilotError:
            original = ""
        return {
            "device": self.device, "running_digest": digest,
            "running_digest_is_reviewed_original": bool(original) and digest == original,
            "sessions": {name: meta.get("state") for name, meta in sessions.items()},
            "timer": p.timer_state(sessions=sessions, config_text=config, armed_at=armed["at"] if armed else None,
                                   confirmed_at=confirmed["at"] if confirmed else None, now=self.deps.clock(),
                                   stage2_session=self.target.stage2_session),
            "local_users": p.local_usernames(config),
            "security_config": p.security_summary(config),
            "checkpoints": {name: {k: (self._checkpoint(name) or {}).get(k) for k in ("file_sha256", "file_md5", "running_sha256")}
                            for name in self.target.checkpoints},
            "gates": {"passed": gates.passed, "failed": gates.failures},
            "last_validate": (self.deps.evidence.latest("validate") or {}).get("ok"),
            "policy": self._policy_summary(),
        }

    def _policy_summary(self) -> dict | None:
        policy = DeviceLoginMfaPolicy.objects.filter(device_name=self.device).first()
        if policy is None:
            return None
        return {"enforcement_state": policy.enforcement_state, "central_aaa_state": policy.central_aaa_state,
                "last_verified_at": policy.last_verified_at.isoformat() if policy.last_verified_at else None,
                "last_verification_result": policy.last_verification_result}

    # ---- checkpoint
    def checkpoint(self, name: str) -> dict:
        self._require_device()
        if name not in self.target.checkpoints:
            raise p.PilotError(f"Checkpoint must be one of {list(self.target.checkpoints)}.")
        self._require_approval()
        config, digest, sessions = self._state()
        users = set(p.local_usernames(config))
        if name == self.target.checkpoint_original:
            expected = self._expected_original_digest()
            if users & set(self.target.accounts):
                raise p.PilotError("Pilot accounts already exist; the original checkpoint must precede Stage 1.")
        else:
            stage1 = self.deps.evidence.latest("stage1", ok=True)
            verified = self.deps.evidence.latest("verify:post-stage1", ok=True, since=stage1["at"] if stage1 else None)
            if stage1 is None or verified is None or self._checkpoint(self.target.checkpoint_original) is None:
                raise p.PilotError("The Stage 2 checkpoint requires the original checkpoint, Stage 1 and its passing verification.")
            if not {*self.target.accounts, "admin"} <= users:
                raise p.PilotError("The Stage 2 checkpoint requires both pilot accounts and admin to be present.")
            expected = stage1["running_digest_after"]
        self._enforce(self._gates(expected_digest=expected, digest=digest, sessions=sessions))
        if self.t.file_digests(f"/mnt/flash/{name}.cfg") is not None:
            raise p.PilotError(f"flash:{name}.cfg already exists; refusing to overwrite a recovery point.")
        copied = self.t.run([f"copy running-config flash:{name}.cfg"])
        digests = self.t.file_digests(f"/mnt/flash/{name}.cfg")
        ok = copied.clean and digests is not None and digests["normalized"] == p._normalized_config(config)
        return self._record(f"checkpoint:{name}", ok=ok, file=f"flash:{name}.cfg",
                            file_sha256=(digests or {}).get("sha256"), file_md5=(digests or {}).get("md5"),
                            running_sha256=digest, file_matches_running=bool(ok), copy_errors=copied.errors)

    # ---- stage 1
    def stage1(self) -> dict:
        self._require_device()
        self._require_approval()
        _, digest, sessions = self._state()
        expected_original = self._expected_original_digest()
        self._enforce(self._gates(expected_digest=expected_original, digest=digest, sessions=sessions))
        original = self._checkpoint_intact(self.target.checkpoint_original)
        if original["running_sha256"] != expected_original:
            raise p.PilotError("The original checkpoint was not taken from the reviewed original state.")
        validation = self.deps.evidence.latest("validate", ok=True)
        if validation is None or not validation.get("session_persists_after_cli_exit"):
            raise p.PilotError("A passing `validate` run (two-phase sessions proven) is required first.")
        staged = self.deps.candidate()
        self._preflight(self.target.stage1_session, staged.stage1)
        lines, known = p.substitute(staged.stage1, self.deps.resolver.resolve)
        opened, committed = self._two_phase(
            self.target.stage1_session, lines, known, f"configure session {self.target.stage1_session} commit")
        config, after, _ = self._state()
        created = set(self.target.accounts) <= set(p.local_usernames(config))
        device_hits = self.t.device_leak_scan(known)
        ok = committed is not None and committed.clean and created and not device_hits
        record = self._record("stage1", ok=ok, known=known, running_digest_before=digest, running_digest_after=after,
                              parser_errors=opened.errors + (committed.errors if committed else []),
                              leaks=self._leak_summary(opened, committed), device_leak_files=device_hits,
                              accounts_present=created, committed=committed is not None)
        if not ok:
            if created:
                self._remove_pilot_accounts()
            raise p.PilotError("Stage 1 failed; pilot accounts were not left in place. Do not proceed.")
        verification = self.verify("post-stage1")
        if not verification["PASS"]:
            self._remove_pilot_accounts()
            raise p.PilotError("Stage 1 verification failed; both pilot accounts were removed. Do not proceed to Stage 2.")
        return {"stage1": record, "verification": verification}

    def _remove_pilot_accounts(self) -> dict:
        lines = [f"no username {name}" for name in self.target.accounts]
        opened, committed = self._two_phase(
            self.target.cleanup_session, lines, p.SecretSet(), f"configure session {self.target.cleanup_session} commit")
        config, digest, _ = self._state()
        removed = not set(self.target.accounts) & set(p.local_usernames(config))
        return self._record("stage1-cleanup", ok=removed and committed is not None, running_digest_after=digest,
                            accounts_removed=removed, back_to_original=digest == self._expected_original_digest())

    # ---- verification contract
    def verify(self, phase: str) -> dict:
        self._require_device()
        if phase not in ("post-stage1", "post-stage2"):
            raise p.PilotError("Phase must be post-stage1 or post-stage2.")
        known = p.SecretSet()
        checks: dict[str, bool] = {}
        detail: dict = {}

        def login(user: str, password: str) -> dict:
            outcome = self.deps.ssh_login(user, password)
            detail[user if user not in detail else f"{user}#2"] = outcome
            return outcome

        for user in self.target.accounts:
            secret = self.deps.resolver.resolve(self.target.account_refs[user])
            known = known.merged(p.SecretSet([secret]))
            outcome = login(user, secret)
            checks[f"{user}_login"] = outcome.get("login") == ACCEPT
            checks[f"{user}_privilege15"] = outcome.get("privilege_level") == 15
        reads = self.deps.nmas_reads()
        detail["nmas_reads"] = reads
        target_identities = reads.get("target_identities", reads.get("r1_identities", []))
        other_identities = reads.get("other_identities", reads.get("fleet_identities", {}))
        checks["target_nmas_identity_is_nmas_automation"] = (
            target_identities[:1] == [self.target.automation_account]
            and checks[f"{self.target.automation_account}_login"]
            and checks[f"{self.target.automation_account}_privilege15"])
        # The operation may not rewrite or retarget any other device. Compare
        # against the canonical resolver metadata rather than assuming every
        # not-yet-migrated node must forever remain `admin`.
        precheck = self.deps.evidence.latest("precheck", ok=True)
        expected_other = (precheck or {}).get("other_device_identities")
        if expected_other is None and self.target.compatibility_r1:
            expected_other = {name: [FLEET_IDENTITY] for name in other_identities}
        expected_other = expected_other or {}
        checks["other_device_identity_routing_unchanged"] = all(
            other_identities.get(name) == expected for name, expected in expected_other.items())
        if self.target.compatibility_r1:
            # Preserve the evidence keys consumed by the completed R1 closure.
            checks["r1_nmas_identity_is_nmas_automation"] = checks["target_nmas_identity_is_nmas_automation"]
            checks["fleet_identity_unchanged_outside_r1"] = checks["other_device_identity_routing_unchanged"]
        checks["health"] = bool(reads["health"])
        checks["nsot"] = bool(reads["nsot"])
        checks["config_retrieval"] = bool(reads["config_retrieval"])
        try:
            checks["docker_exec_privileged_cli"] = "Software image version" in self.t.show("show version") \
                and bool(self.t.show("show running-config section username"))
        except p.PilotError:
            checks["docker_exec_privileged_cli"] = False
        if phase == "post-stage2":
            admin_secret = self.deps.resolver.resolve(self.target.account_refs["admin"], for_config=False)
            known = known.merged(p.SecretSet([admin_secret]))
            checks["admin_remote_login_rejected"] = login("admin", admin_secret).get("login") == REJECT
            password, otp = self.deps.human_factors()
            known = known.merged(p.SecretSet([password, otp]))
            checks["human_password_only_rejected"] = login(p.HUMAN_USERNAME, password).get("login") == REJECT
            human = login(p.HUMAN_USERNAME, password + otp)
            checks["human_password_plus_totp_accepted"] = (
                human.get("login") == ACCEPT and human.get("privilege_level") == 15)
            del password, otp
        passed = all(checks.values())
        self._record(f"verify:{phase}", ok=passed, known=known, checks=checks, detail=detail)
        return {"phase": phase, "PASS": passed, "checks": checks, "detail": detail}

    # ---- verify-positive (routine: ONE human attempt, no deliberate failure, no policy change)
    def _positive_guards(self) -> tuple[p.GateReport, dict | None, dict | None, int | None]:
        guards = p.GateReport()
        healthy, problems = self.deps.infrastructure()
        unexplained = not healthy and not problems  # unhealthy without a named container: trust neither
        pi_problems = sorted(set(problems) - {p.FREERADIUS_CONTAINER})
        guards.check("freeradius_healthy", p.FREERADIUS_CONTAINER not in problems and not unexplained,
                     "FreeRADIUS container is not healthy")
        guards.check("privacyidea_healthy", not pi_problems and not unexplained, f"unhealthy {pi_problems or 'unknown'}")
        token = None
        try:
            token = self.deps.privacyidea.token(p.HUMAN_TOKEN_SERIAL)
        except p.PilotError as exc:
            guards.check("token_readable", False, str(exc))
        if token is not None:
            guards.check("token_identity", token.get("serial") == p.HUMAN_TOKEN_SERIAL and token.get("type") == "totp"
                         and token.get("owner") == p.HUMAN_USERNAME, "token serial/type/owner differ")
            guards.check("token_active", token.get("active") is True, "token inactive")
            guards.check("token_not_locked", token.get("locked") is False, "token locked")
            guards.check("token_not_revoked", token.get("revoked") is False, "token revoked")
            guards.check("token_failcount_below_limit", int(token.get("failcount", p.POSITIVE_FAILCOUNT_LIMIT)) < p.POSITIVE_FAILCOUNT_LIMIT,
                         f"failcount {token.get('failcount')} >= {p.POSITIVE_FAILCOUNT_LIMIT}")
        reachability_check = "r1_management_reachability" if self.target.compatibility_r1 else "management_reachability"
        guards.check(reachability_check, self.deps.reachable(),
                     f"TCP/22 to {self.target.management_address} failed")
        radius_before = audit_before = None
        try:
            radius_before = p.parse_radius_counters(self.t.show("show radius"))
            guards.check("radius_counters_readable", True)
        except p.PilotError as exc:
            guards.check("radius_counters_readable", False, str(exc))
        try:
            audit_before = int(self.deps.privacyidea.audit(p.HUMAN_USERNAME)["max_id"])
            guards.check("privacyidea_audit_readable", True)
        except (p.PilotError, KeyError, TypeError, ValueError) as exc:
            guards.check("privacyidea_audit_readable", False, str(exc))
        return guards, token, radius_before, audit_before

    @staticmethod
    def _token_flags(token: dict | None) -> dict | None:
        return {k: token.get(k) for k in ("active", "locked", "revoked", "failcount", "maxfail")} if token else None

    def verify_positive(self) -> dict:
        """ONE nmas-admin password+TOTP attempt, attributed from read-only evidence.  Every guard
        is checked BEFORE the factors are requested; a failed guard sends nothing."""
        self._require_device()
        guards, token, radius_before, audit_before = self._positive_guards()
        if not guards.ok:
            raise p.PilotError("Guard(s) failed; NO login attempt was sent: " + "; ".join(guards.failures))
        password, otp = self.deps.human_factors()
        if not password or not (len(otp) == 6 and otp.isdigit()):
            del password, otp
            raise p.PilotError("Password empty or code is not 6 digits; NO login attempt was sent.")
        known = p.SecretSet([password, otp, password + otp])
        login = self.deps.human_login(p.HUMAN_USERNAME, password + otp)  # the ONLY attempt
        del password, otp
        try:
            delta = p.radius_delta(radius_before, p.parse_radius_counters(self.t.show("show radius")))
        except p.PilotError:
            delta = None
        try:
            rows = self.deps.privacyidea.audit(p.HUMAN_USERNAME, after_id=audit_before)["rows"]
        except (p.PilotError, KeyError, TypeError):
            rows = None
        try:
            token_after = self.deps.privacyidea.token(p.HUMAN_TOKEN_SERIAL)
        except p.PilotError:
            token_after = None
        result, reason = p.attribute_positive_attempt(login, delta, rows)
        ok = result in p.PositiveResult.SUCCESS
        ssh = {k: login.get(k) for k in ("login", "stage", "command", "error") if login.get(k) is not None}
        record = self._record("verify:positive", ok=ok, known=known, result=result, reason=reason, attempts=1,
                              ssh=ssh, radius_delta=delta, privacyidea_rows=rows, privacyidea_audit_baseline=audit_before,
                              token_before=self._token_flags(token), token_after=self._token_flags(token_after),
                              guards=guards.passed)
        return {"PASS": ok, "result": result, "reason": reason, "attempts": 1, "ssh": ssh, "radius_delta": delta,
                "privacyidea_rows": rows, "token_after": record["token_after"], "policy_changed": False}

    # ---- record-verification (R1 policy metadata from recorded evidence; no device change)
    def record_verification(self) -> dict:
        self._require_device()
        self._require_approval()
        gates = p.GateReport()
        policy = DeviceLoginMfaPolicy.objects.filter(device_name=self.device).first()
        gates.check("policy_row_radius_totp", policy is not None and policy.mechanism == MfaMechanism.RADIUS_TOTP,
                    f"no {self.device} RADIUS_TOTP policy row")
        gates.check("policy_enforced", policy is not None and policy.enforcement_state in (
            MfaEnforcementState.ENFORCED, MfaEnforcementState.LIVE_VERIFIED),
            f"{self.device} policy is not ENFORCED")
        armed = self.deps.evidence.latest("stage2-armed", ok=True)
        verified_entry = self.deps.evidence.latest_entry("verify:post-stage2", ok=True, since=armed["at"]) if armed else None
        gates.check("post_stage2_verification_passed", verified_entry is not None,
                    "no passing verify:post-stage2 during the last armed Stage 2 timer")
        checks = (verified_entry[1].get("checks") or {}) if verified_entry else {}
        required = p.REQUIRED_POST_STAGE2_CHECKS if self.target.compatibility_r1 else self.target.required_post_stage2_checks
        missing = [name for name in required if checks.get(name) is not True]
        gates.check("post_stage2_required_checks", verified_entry is not None and not missing, f"not passed {missing}")
        confirm_entry = (self.deps.evidence.latest_entry("confirm", ok=True, since=verified_entry[1]["at"])
                         if verified_entry else None)
        gates.check("confirm_after_verification", confirm_entry is not None, "no passing confirm after that verification")
        config, digest, sessions = self._state()
        gates.check("confirm_digest_is_current", confirm_entry is not None and confirm_entry[1].get("running_digest_after") == digest,
                    f"{self.device} running-config differs from the confirmed digest")
        timer = p.timer_state(sessions=sessions, config_text=config, armed_at=armed["at"] if armed else None,
                              confirmed_at=confirm_entry[1]["at"] if confirm_entry else None, now=self.deps.clock(),
                              stage2_session=self.target.stage2_session)
        gates.check("timer_confirmed", timer["state"] == p.TimerState.CONFIRMED, f"timer is {timer['state']}")
        rolled_back = bool(confirm_entry) and any(
            self.deps.evidence.latest(f"replace:{name}", ok=True, since=confirm_entry[1]["at"])
            for name in self.target.checkpoints)
        gates.check("no_rollback_since_confirm", not rolled_back, "a checkpoint was restored after confirm")
        startup = self.t.show("show startup-config")
        gates.check("startup_matches_running", p._normalized_config(startup) == p._normalized_config(config),
                    "startup-config differs from running-config (not persisted)")
        gates.check("no_open_config_session", not p.open_sessions(sessions), f"open {sorted(p.open_sessions(sessions))}")
        if not self.target.compatibility_r1:
            persisted = self.deps.evidence.latest("persist", ok=True, since=confirm_entry[1]["at"] if confirm_entry else None)
            gates.check("persisted_after_confirm", persisted is not None and persisted.get("running_digest") == digest,
                        "no matching write-memory evidence after confirm")
        if not gates.ok:
            raise p.PilotError(f"Gate(s) failed; the {self.device} policy row was NOT changed: " + "; ".join(gates.failures))
        evidence_id, verified = verified_entry
        verified_at = datetime.datetime.fromtimestamp(float(verified["at"]), tz=datetime.timezone.utc)
        before = self._policy_summary()
        # Row change and its evidence commit together: a refused evidence write rolls the row back.
        with transaction.atomic():
            row = DeviceLoginMfaPolicy.objects.select_for_update().get(device_name=self.device)
            row.central_aaa_state = CentralAaaState.VERIFIED
            row.enforcement_state = MfaEnforcementState.LIVE_VERIFIED
            row.last_verified_at = verified_at  # the evidence's own timestamp, never the wall clock
            row.last_verification_result = f"verify:post-stage2 PASS evidence#{evidence_id}"[:64]
            try:
                row.save(update_fields=["central_aaa_state", "enforcement_state", "last_verified_at",
                                        "last_verification_result", "updated_at"])
            except ValueError as exc:
                raise p.PilotError(f"{self.device} policy row refused the transition: {exc}") from None
            return self._record("record-verification", ok=True, policy_before=before, policy_after=self._policy_summary(),
                                verification_evidence_id=evidence_id, confirm_evidence_id=confirm_entry[0],
                                verified_at=verified_at.isoformat(), running_digest=digest, gates_passed=gates.passed)

    # ---- stage 2 (atomic, commit timer)
    def stage2(self) -> dict:
        self._require_device()
        self._require_approval()
        config, digest, sessions = self._state()
        checkpoint = self._checkpoint_intact(self.target.checkpoint_stage2)
        self._enforce(self._gates(expected_digest=checkpoint["running_sha256"], digest=digest, sessions=sessions))
        stage1 = self.deps.evidence.latest("stage1", ok=True)
        if stage1 is None or self.deps.evidence.latest("verify:post-stage1", ok=True, since=stage1["at"]) is None:
            raise p.PilotError("Stage 1 and its passing verification are required before Stage 2.")
        if not {*self.target.accounts, "admin"} <= set(p.local_usernames(config)):
            raise p.PilotError("Stage 2 requires both pilot accounts (and admin, which it retires) to be present.")
        staged = self.deps.candidate()
        self._preflight(self.target.stage2_session, staged.stage2)
        lines, known = p.substitute(staged.stage2, self.deps.resolver.resolve)
        armed_at = self.deps.clock()
        opened, committed = self._two_phase(
            self.target.stage2_session, lines, known,
            f"configure session {self.target.stage2_session} commit timer {p.COMMIT_TIMER}")
        after_config, after, after_sessions = self._state()
        device_hits = self.t.device_leak_scan(known)
        armed = committed is not None and committed.clean and p.ACTIVATION_MARKER in after_config
        # `at` is taken BEFORE the commit so the computed remaining time is never overstated.
        record = self._record("stage2-armed", ok=armed, known=known, at=armed_at, running_digest_before=digest, running_digest_after=after,
                              commit_timer=p.COMMIT_TIMER, parser_errors=opened.errors + (committed.errors if committed else []),
                              leaks=self._leak_summary(opened, committed), device_leak_files=device_hits,
                              session_state=(after_sessions.get(self.target.stage2_session) or {}).get("state"))
        if not armed:
            raise p.PilotError(
                f"Stage 2 was not armed (session aborted or rejected). {self.device} retains the Stage 2 checkpoint state.")
        return {"stage2": record, "timer": self.status()["timer"],
                "next": "Run `verify-logins --phase post-stage2`; confirm only if every check passes, otherwise let the timer expire."}

    # ---- confirm
    def confirm(self) -> dict:
        self._require_device()
        self._require_approval()
        armed = self.deps.evidence.latest("stage2-armed", ok=True)
        if armed is None:
            raise p.PilotError("No armed Stage 2 commit timer is recorded.")
        config, _, sessions = self._state()
        timer = p.timer_state(sessions=sessions, config_text=config, armed_at=armed["at"], confirmed_at=None,
                              now=self.deps.clock(), stage2_session=self.target.stage2_session)
        if timer["state"] != p.TimerState.ARMED or timer["remaining_seconds"] < p.CONFIRM_SAFETY_MARGIN_SECONDS:
            raise p.PilotError(f"Timer is {timer['state']} ({timer['remaining_seconds']}s left); refusing to confirm.")
        verified = self.deps.evidence.latest("verify:post-stage2", since=armed["at"])
        if verified is None or not verified.get("ok"):
            raise p.PilotError("Post-Stage-2 verification has not passed during this timer; let the timer expire (automatic rollback).")
        result = self.t.run([f"configure session {self.target.stage2_session} commit"])
        config, digest, sessions = self._state()
        ok = result.clean and p.ACTIVATION_MARKER in config and "admin" not in p.local_usernames(config)
        if ok:
            DeviceLoginMfaPolicy.objects.filter(device_name=self.device).update(enforcement_state=MfaEnforcementState.ENFORCED)
        return self._record("confirm", ok=ok, running_digest_after=digest, errors=result.errors,
                            session_state=(sessions.get(self.target.stage2_session) or {}).get("state"))

    # ---- persist (only after a confirmed timer and passing verification)
    def persist(self) -> dict:
        self._require_device()
        self._require_approval()
        confirmed = self.deps.evidence.latest("confirm", ok=True)
        if confirmed is None:
            raise p.PilotError("A passing confirm is required before write memory.")
        config, digest, sessions = self._state()
        timer = p.timer_state(
            sessions=sessions, config_text=config,
            armed_at=(self.deps.evidence.latest("stage2-armed", ok=True) or {}).get("at"),
            confirmed_at=confirmed.get("at"), now=self.deps.clock(), stage2_session=self.target.stage2_session,
        )
        if timer["state"] != p.TimerState.CONFIRMED or p.open_sessions(sessions):
            raise p.PilotError("Commit timer is not safely confirmed or a configuration session remains open.")
        if confirmed.get("running_digest_after") != digest:
            raise p.PilotError("Running configuration changed after confirm; refusing to persist.")
        result = self.t.run(["write memory"])
        startup = self.t.show("show startup-config")
        after_config, after_digest, after_sessions = self._state()
        ok = (result.clean and after_digest == digest
              and p._normalized_config(startup) == p._normalized_config(after_config)
              and not p.open_sessions(after_sessions))
        return self._record("persist", ok=ok, running_digest=digest, running_digest_after=after_digest,
                            startup_matches_running=p._normalized_config(startup) == p._normalized_config(after_config),
                            errors=result.errors)

    # ---- replace (restore a checkpoint)
    def replace(self, name: str) -> dict:
        self._require_device()
        if name not in self.target.checkpoints:
            raise p.PilotError(f"Checkpoint must be one of {list(self.target.checkpoints)}.")
        self._require_approval()
        config, digest, sessions = self._state()
        armed = self.deps.evidence.latest("stage2-armed", ok=True)
        if armed and p.timer_state(sessions=sessions, config_text=config, armed_at=armed["at"], confirmed_at=None,
                                   now=self.deps.clock(), stage2_session=self.target.stage2_session)["state"] == p.TimerState.ARMED:
            raise p.PilotError("A Stage 2 commit timer is armed; let it expire (automatic rollback) before replacing.")
        if p.open_sessions(sessions):
            raise p.PilotError(f"Refusing to replace while configuration sessions are open: {sorted(p.open_sessions(sessions))}")
        recorded = self._checkpoint_intact(name)
        result = self.t.run([f"configure replace flash:{name}.cfg md5 {recorded['file_md5']}"])
        config, after, _ = self._state()
        users = p.local_usernames(config)
        restored = after == recorded["running_sha256"] or p._normalized_config(config) == self.t.file_digests(f"/mnt/flash/{name}.cfg")["normalized"]
        reads = self.deps.nmas_reads()
        ok = result.clean and restored and "admin" in users and p.ACTIVATION_MARKER not in config and reads["nsot"]
        if ok:
            # A rollback must never leave stale LIVE_VERIFIED / VERIFIED metadata behind.
            DeviceLoginMfaPolicy.objects.filter(device_name=self.device).update(
                enforcement_state=MfaEnforcementState.PLANNED, central_aaa_state=CentralAaaState.PLANNED,
                last_verified_at=None, last_verification_result="")
        return self._record(f"replace:{name}", ok=ok, running_digest_before=digest, running_digest_after=after,
                            matches_checkpoint=restored, local_users=users, errors=result.errors,
                            nmas_reads_after=reads,
                            target_credential_routing=reads.get("target_identities", reads.get("r1_identities", [])))
