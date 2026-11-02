"""Secret-safe EOS Microsoft Authenticator rollout primitives.

The R1 names remain as compatibility constants for the completed pilot. New
devices use :class:`CeosMfaTarget`; there is one implementation, not one copy
per device.

Secret-safe transport
    Real secrets are read from the protected runtime providers straight into
    process memory and are fed to ``docker exec -i <R1> Cli -p 15`` on STDIN
    only.  They never enter argv, the child environment, files, evidence or
    output.  EOS Cli echoes a line that fails to parse, so every byte the device
    returns is redacted in memory BEFORE anything is kept; a known secret seen in
    device output marks the operation failed.

Two-phase sessions
    A configuration session is first opened and filled in one Cli process (no
    commit).  Only when that process reported no parser error and no secret
    leak is the session committed from exec mode in a second process
    (``configure session <name> commit`` / ``... commit timer hh:mm:ss``);
    otherwise it is aborted.  A partially parsed session is therefore never
    committed, whether or not piped Cli stops at its first error.

Two checkpoints
    ``flash:pre-2fa-pilot.cfg`` (true original state, before Stage 1) and
    ``flash:pre-2fa-stage2.cfg`` (after Stage 1 is verified).  SHA-256 and MD5
    are recorded without displaying file contents; restore always uses
    ``configure replace flash:<file> md5 <recorded>``.

Nothing here runs on import.  Every live operation is behind explicit gates
(see ``PilotGates``) and the operator's interactive approval phrase.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import secrets as _secrets
import socket
import subprocess
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterable

import yaml

from modules.device_credentials import BASE, FileSecretProvider, SecretProviderError

PILOT_DEVICE = "R1"
PILOT_CONTAINER = "clab-srlceos01-R1"
PILOT_MGMT_ADDRESS = "192.168.200.1"
APPROVAL_PHRASE = "APPLY THE R1 2FA PILOT"
REVIEWED_CANDIDATE_DIGEST = "43769c2e19ba0c491024540d69eaf40ab827ae0be95e641e415d38077139b88a"
REVIEWED_ORIGINAL_DIGEST = "148470d860acb4205d6ce74190737a5eb2db10311e96752266d284487af32693"
STAGE1_SESSION = "NMAS-R1-2FA-STAGE1"
STAGE2_SESSION = "R1-2FA-PILOT"
CLEANUP_SESSION = "NMAS-R1-2FA-CLEANUP"
COMMIT_TIMER = "00:10:00"
COMMIT_TIMER_SECONDS = 600
CONFIRM_SAFETY_MARGIN_SECONDS = 30
CHECKPOINT_ORIGINAL = "pre-2fa-pilot"
CHECKPOINT_STAGE2 = "pre-2fa-stage2"
CHECKPOINTS = (CHECKPOINT_ORIGINAL, CHECKPOINT_STAGE2)
PILOT_ACCOUNTS = ("nmas-automation", "r1-breakglass")
HUMAN_USERNAME = "nmas-admin"
ACTIVATION_MARKER = "aaa authentication login default local group NMAS-HUMAN-MFA"
ACCOUNT_REFS = {
    "nmas-automation": "runtime://device-credentials/r1-nmas-automation",
    "r1-breakglass": "runtime://device-credentials/r1-breakglass",
    "admin": "runtime://device-credentials/ceos-admin-shared",
}
RADIUS_REF = "runtime://human-mfa/radius/r1"
# Refs substituted into EOS configuration (strict charset) vs. used only for SSH login checks.
CONFIG_REFS = (ACCOUNT_REFS["nmas-automation"], ACCOUNT_REFS["r1-breakglass"], RADIUS_REF)
LOGIN_ONLY_REFS = (ACCOUNT_REFS["admin"],)
RADIUS_SECRET_DIR = BASE / "monitoring" / "runtime" / "human-mfa" / "secrets"
# Human-MFA infrastructure: container -> required state ("healthy" or "running").
MFA_CONTAINERS = {
    "human_mfa-human-mfa-radius-1": "healthy",
    "nmas-human-mfa-pi-privacyidea-1": "healthy",
    "nmas-human-mfa-pi-db-1": "healthy",
    "nmas-human-mfa-pi-privacyidea-app-1": "running",
}
# Bounded device-side leak scan: only locations a config session, checkpoint or
# Cli log could write to.  Never an unbounded host scan.
DEVICE_LEAK_SCAN_DIRS = ("/mnt/flash", "/var/log", "/tmp", "/var/tmp")
VALIDATION_SESSIONS = ("NMAS-R1-VAL-S1", "NMAS-R1-VAL-S12", "NMAS-R1-VAL-RB", "NMAS-R1-VAL-ECHO")
# Post-pilot routine verification (verify-positive) and metadata recording (record-verification).
HUMAN_TOKEN_SERIAL = "TOTP0001522E"
POSITIVE_FAILCOUNT_LIMIT = 9  # refuse before sending when the token's failcount is at or above this
FREERADIUS_CONTAINER = "human_mfa-human-mfa-radius-1"
PRIVACYIDEA_APP_CONTAINER = "nmas-human-mfa-pi-privacyidea-app-1"
PRIVACYIDEA_PYTHON = "/opt/privacyidea/bin/python"
# Every check the recorded post-Stage-2 verification must have passed before R1 metadata
# may be marked LIVE_VERIFIED / central AAA VERIFIED.
REQUIRED_POST_STAGE2_CHECKS = (
    "human_password_plus_totp_accepted", "human_password_only_rejected", "admin_remote_login_rejected",
    "nmas-automation_login", "nmas-automation_privilege15", "r1-breakglass_login", "r1-breakglass_privilege15",
    "r1_nmas_identity_is_nmas_automation",
    "fleet_identity_unchanged_outside_r1", "health", "nsot", "config_retrieval", "docker_exec_privileged_cli",
)

MANAGED_CEOS_MFA_DEVICES = ("R1", "R2", "S1", "S2", "S3", "S4", "mgmt_swt")
FLEET_ROLLOUT_DEVICES = ("R2", "S1", "S2", "S3", "S4", "mgmt_swt")
EXPLICITLY_DEFERRED_DEVICES = ("R3", "R4", "R5")


@dataclass(frozen=True)
class CeosMfaTarget:
    """All non-secret, device-specific rollout routing in one immutable value."""

    device: str
    container: str
    management_address: str
    automation_account: str
    breakglass_account: str
    automation_ref: str
    breakglass_ref: str
    legacy_ref: str
    radius_ref: str
    checkpoint_original: str
    checkpoint_stage2: str
    stage1_session: str
    stage2_session: str
    cleanup_session: str
    validation_sessions: tuple[str, str, str, str]
    approval_phrase: str
    compatibility_r1: bool = False

    @property
    def accounts(self) -> tuple[str, str]:
        return self.automation_account, self.breakglass_account

    @property
    def account_refs(self) -> dict[str, str]:
        return {
            self.automation_account: self.automation_ref,
            self.breakglass_account: self.breakglass_ref,
            "admin": self.legacy_ref,
        }

    @property
    def config_refs(self) -> tuple[str, str, str]:
        return self.automation_ref, self.breakglass_ref, self.radius_ref

    @property
    def login_only_refs(self) -> tuple[str]:
        return (self.legacy_ref,)

    @property
    def checkpoints(self) -> tuple[str, str]:
        return self.checkpoint_original, self.checkpoint_stage2

    @property
    def required_post_stage2_checks(self) -> tuple[str, ...]:
        return (
            "human_password_plus_totp_accepted", "human_password_only_rejected", "admin_remote_login_rejected",
            f"{self.automation_account}_login", f"{self.automation_account}_privilege15",
            f"{self.breakglass_account}_login", f"{self.breakglass_account}_privilege15",
            "target_nmas_identity_is_nmas_automation", "other_device_identity_routing_unchanged",
            "health", "nsot", "config_retrieval", "docker_exec_privileged_cli",
        )


def _short_device_token(device: str) -> str:
    token = re.sub(r"[^A-Za-z0-9]", "-", device).upper().strip("-")
    if not token or len(token) > 20:
        raise PilotError("Device name cannot be represented safely in EOS session names.")
    return token


def target_for(device: str, *, inventory_path: Path | None = None) -> CeosMfaTarget:
    """Resolve and validate one eligible managed cEOS target from inventory.

    R3/R4, R5, unknown nodes, non-cEOS metadata, dynamic addresses and any
    device outside the reviewed set fail closed before a command is built.
    """
    if device not in MANAGED_CEOS_MFA_DEVICES:
        reason = "explicitly deferred" if device in EXPLICITLY_DEFERRED_DEVICES else "not in the reviewed cEOS MFA target set"
        raise PilotError(f"{device!r} is {reason}.")
    path = inventory_path or (BASE / "inventory.yml")
    try:
        inventory = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, yaml.YAMLError):
        raise PilotError("NMAS inventory is unavailable or invalid.") from None
    entry = (inventory.get("network_devices") or {}).get(device) or {}
    monitoring = entry.get("monitoring") or {}
    if monitoring.get("platform") != "ceos":
        raise PilotError(f"{device!r} is not classified as cEOS in the authoritative NMAS inventory.")
    address = monitoring.get("address")
    if not isinstance(address, str) or not address or address == "auto":
        raise PilotError(f"{device!r} has no static management address for this rollout.")
    slug = device.lower()
    token = _short_device_token(device)
    compatibility = device == PILOT_DEVICE
    if compatibility:
        return CeosMfaTarget(
            device=device, container=PILOT_CONTAINER, management_address=PILOT_MGMT_ADDRESS,
            automation_account="nmas-automation", breakglass_account="r1-breakglass",
            automation_ref=ACCOUNT_REFS["nmas-automation"], breakglass_ref=ACCOUNT_REFS["r1-breakglass"],
            legacy_ref=ACCOUNT_REFS["admin"], radius_ref=RADIUS_REF,
            checkpoint_original=CHECKPOINT_ORIGINAL, checkpoint_stage2=CHECKPOINT_STAGE2,
            stage1_session=STAGE1_SESSION, stage2_session=STAGE2_SESSION, cleanup_session=CLEANUP_SESSION,
            validation_sessions=VALIDATION_SESSIONS, approval_phrase=APPROVAL_PHRASE, compatibility_r1=True,
        )
    return CeosMfaTarget(
        device=device, container=f"clab-srlceos01-{device}", management_address=address,
        automation_account="nmas-automation", breakglass_account=f"{slug}-breakglass",
        automation_ref=f"runtime://device-credentials/{slug}-nmas-automation",
        breakglass_ref=f"runtime://device-credentials/{slug}-breakglass",
        legacy_ref="runtime://device-credentials/ceos-admin-shared",
        radius_ref=f"runtime://human-mfa/radius/{slug}",
        checkpoint_original=f"pre-mfa-{slug}", checkpoint_stage2=f"pre-mfa-stage2-{slug}",
        stage1_session=f"NMAS-{token}-MFA-S1", stage2_session=f"NMAS-{token}-MFA-S2",
        cleanup_session=f"NMAS-{token}-MFA-CLEAN",
        validation_sessions=(f"NMAS-{token}-VAL-S1", f"NMAS-{token}-VAL-S12", f"NMAS-{token}-VAL-RB", f"NMAS-{token}-VAL-E"),
        approval_phrase=f"APPLY {device} MFA ROLLOUT", compatibility_r1=False,
    )

_PLACEHOLDER = re.compile(r"<provider:(runtime://[^>]+)>")
# One EOS token: no whitespace, no `?` (help), quotes, `!` or backslash.  base64 `+/=` is fine.
_EOS_SAFE_SECRET = re.compile(r"^[A-Za-z0-9_+/=.-]{16,128}$")
_PUNCTUATION = "_+/=.-"
_RADIUS_REF = re.compile(r"^runtime://human-mfa/radius/([a-z0-9][a-z0-9_.-]{0,63})$")
_STRUCTURAL_REDACTIONS = (
    re.compile(r"(?i)(\bsecret\s+(?:(?:sha512|0|5|7|8a)\s+)?)\S+"),
    re.compile(r"(?i)(\bkey\s+(?:(?:0|7|8a)\s+)?)\S+"),
    re.compile(r"(?i)(\b(?:password|community|key-string|authentication-key|pre-shared-key)\s+(?:\d+\s+)?)\S+"),
    re.compile(r"(?i)(\bauth\s+(?:md5|sha|sha256|sha384|sha512)\s+)\S+"),
    re.compile(r"(?i)(\bpriv\s+(?:des|3des|aes|aes192|aes256)\s+)\S+"),
)
REDACTED = "<REDACTED>"


class PilotError(Exception):
    """A refused or failed pilot operation.  Messages never contain secret material."""


# --------------------------------------------------------------------------- secrets
class SecretSet:
    """In-memory known secret values; the only place they are held."""

    def __init__(self, values: Iterable[str] = ()):
        self._values = tuple(sorted({v for v in values if v}, key=len, reverse=True))

    def __len__(self) -> int:
        return len(self._values)

    def __iter__(self):
        return iter(self._values)

    def __repr__(self) -> str:  # never render values
        return f"SecretSet(<{len(self._values)} redacted>)"

    def checkable(self, min_length: int = 12) -> "SecretSet":
        """Values long enough for a meaningful substring check.  A short login-only value
        (the lab `admin` password) or a 6-digit TOTP would match ordinary evidence text
        (the username `admin`, timestamps, digests); those are never written to evidence by
        construction and are only covered by output redaction."""
        return SecretSet(v for v in self._values if len(v) >= min_length)

    def merged(self, other: "SecretSet") -> "SecretSet":
        return SecretSet((*self._values, *other._values))

    def occurs_in(self, text: str | bytes) -> bool:
        if isinstance(text, bytes):
            return any(v.encode() in text for v in self._values)
        return any(v in text for v in self._values)

    def redact(self, text: str) -> tuple[str, bool]:
        """-> (fully redacted text, whether a known secret was present)."""
        leaked = False
        for value in self._values:
            if value in text:
                leaked = True
                text = text.replace(value, REDACTED)
        for pattern in _STRUCTURAL_REDACTIONS:
            text = pattern.sub(lambda m: m.group(1) + REDACTED, text)
        return text, leaked


def radius_secret_path(reference: str, *, root: Path | None = None) -> Path:
    match = _RADIUS_REF.fullmatch(reference)
    if not match:
        raise PilotError("RADIUS shared secret must be a runtime://human-mfa/radius/<device> reference.")
    return (root or RADIUS_SECRET_DIR) / f"radius_{match.group(1)}_secret"


class PilotSecretResolver:
    """Resolve provider references to in-memory values (device credentials + RADIUS)."""

    def __init__(self, *, provider: FileSecretProvider | None = None, radius_root: Path | None = None):
        self.provider = provider or FileSecretProvider()
        self.radius_root = radius_root

    def resolve(self, reference: str, *, for_config: bool = True) -> str:
        """In-memory value.  ``for_config`` enforces the EOS-safe token rule; login-only
        use (SSH checks, never substituted into configuration) only requires a single token."""
        if reference.startswith("runtime://device-credentials/"):
            try:
                value = self.provider.current(reference).value
            except SecretProviderError as exc:
                raise PilotError(f"{reference} is unavailable ({exc.__class__.__name__}).") from None
        elif reference.startswith("runtime://human-mfa/radius/"):
            path = radius_secret_path(reference, root=self.radius_root)
            try:
                stat = path.lstat()
            except FileNotFoundError:
                raise PilotError(f"{reference} is unavailable (missing).") from None
            if path.is_symlink() or not path.is_file() or stat.st_mode & 0o077:
                raise PilotError(f"{reference} store must be a private regular file.")
            value = path.read_text(encoding="utf-8").strip()
        else:
            raise PilotError(f"Unsupported provider reference {reference}.")
        if for_config and not _EOS_SAFE_SECRET.fullmatch(value):
            raise PilotError(f"{reference} does not match the EOS-safe secret charset/length.")
        if not value or any(c.isspace() for c in value):
            raise PilotError(f"{reference} is empty or contains whitespace.")
        return value

    def exists(self, reference: str, *, for_config: bool = True) -> bool:
        try:
            self.resolve(reference, for_config=for_config)
        except PilotError:
            return False
        return True


def references_in(lines: Iterable[str]) -> list[str]:
    return sorted({m.group(1) for line in lines for m in _PLACEHOLDER.finditer(line)})


def substitute(lines: Iterable[str], resolve: Callable[[str], str]) -> tuple[list[str], SecretSet]:
    values: list[str] = []

    def _one(match):
        value = resolve(match.group(1))
        values.append(value)
        return value

    return [_PLACEHOLDER.sub(_one, line) for line in lines], SecretSet(values)


def shaped_canary(template: str) -> str:
    """Random value with the template's length and punctuation multiset (random positions).

    It exercises the EOS parser on the same token shape (e.g. base64 ``+``/``/``) as the
    real secret without ever sending the real value.  The first character keeps its class.
    """
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    punct = [c for c in template if c in _PUNCTUATION]
    chars = [_secrets.choice(alphabet) for _ in range(len(template))]
    slots = list(range(1, len(template))) if template[:1] not in _PUNCTUATION else list(range(len(template)))
    if template[:1] in _PUNCTUATION:
        chars[0], punct = template[0], punct[1:]
        slots = slots[1:]
    for c in punct:
        slot = slots.pop(_secrets.randbelow(len(slots)))
        chars[slot] = c
    return "".join(chars)


class CanaryResolver:
    """TEST-ONLY canary value per reference: generated fresh, held in memory, never persisted/shown.

    With ``shape_of`` (reference -> real value or None) each canary mirrors the real secret's
    shape; the real value is only read in memory and is never sent anywhere.
    """

    def __init__(self, shape_of: Callable[[str], str | None] | None = None):
        self._values: dict[str, str] = {}
        self.shape_of = shape_of
        self.shaped: set[str] = set()

    def __call__(self, reference: str) -> str:
        if reference not in self._values:
            template = self.shape_of(reference) if self.shape_of else None
            if template:
                value = shaped_canary(template)
                while value == template:
                    value = shaped_canary(template)
                self.shaped.add(reference)
            else:
                value = "nmasCanary" + _secrets.token_hex(20)
            self._values[reference] = value
        return self._values[reference]

    def extra(self, label: str) -> str:
        return self(f"canary://{label}")

    @property
    def known(self) -> SecretSet:
        return SecretSet(self._values.values())


# --------------------------------------------------------------------------- leak detection
def minimal_child_environment() -> dict[str, str]:
    """The ONLY environment given to child processes; never carries secrets."""
    env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "LANG": "C.UTF-8"}
    for key in ("HOME", "DOCKER_HOST", "DOCKER_CONFIG"):
        if os.environ.get(key):
            env[key] = os.environ[key]
    return env


class ProcessTableScanner:
    """Bounded scan of the process table (argv + readable environ) while a child runs."""

    def __init__(self, known: SecretSet, *, proc_root: Path = Path("/proc"), interval: float = 0.05):
        self.known, self.proc_root, self.interval = known, proc_root, interval
        self.hits: set[str] = set()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def scan_once(self) -> None:
        try:
            entries = [p for p in self.proc_root.iterdir() if p.name.isdigit()]
        except OSError:
            return
        for entry in entries:
            for leaf, category in (("cmdline", "process_argv"), ("environ", "process_environment")):
                try:
                    blob = (entry / leaf).read_bytes()
                except OSError:
                    continue  # other users' environ is unreadable by design
                if self.known.occurs_in(blob):
                    self.hits.add(category)

    def _loop(self) -> None:
        while not self._stop.is_set():
            self.scan_once()
            self._stop.wait(self.interval)

    def __enter__(self):
        if len(self.known):
            self._thread = threading.Thread(target=self._loop, daemon=True)
            self._thread.start()
        return self

    def __exit__(self, *exc):
        self._stop.set()
        if self._thread is not None:
            self._thread.join()
        if len(self.known):
            self.scan_once()


@dataclass
class CliResult:
    output: str                       # redacted
    errors: list[str]                 # redacted parser-error lines
    leaks: dict[str, bool]            # category -> leak detected
    returncode: int

    @property
    def leaked(self) -> bool:
        return any(self.leaks.values())

    @property
    def clean(self) -> bool:
        return not self.errors and not self.leaked and self.returncode == 0


Runner = Callable[..., subprocess.CompletedProcess]


class EosCliTransport:
    """docker-exec Cli transport.  Commands (and any secrets) go through stdin ONLY."""

    def __init__(self, container: str = PILOT_CONTAINER, *, runner: Runner = subprocess.run,
                 scanner_factory: Callable[[SecretSet], ProcessTableScanner] = ProcessTableScanner):
        self.container, self.runner, self.scanner_factory = container, runner, scanner_factory

    @property
    def stdin_argv(self) -> list[str]:
        return ["docker", "exec", "-i", self.container, "Cli", "-p", "15"]

    def run(self, commands: list[str], known: SecretSet = SecretSet(), *, timeout: int = 180) -> CliResult:
        env = minimal_child_environment()
        argv = self.stdin_argv
        leaks = {
            "argv_constructed": known.occurs_in(" ".join(argv)),
            "child_environment": known.occurs_in("\n".join(env.values())),
            "parent_environment": known.occurs_in("\n".join(os.environ.values())),
        }
        if leaks["argv_constructed"] or leaks["child_environment"]:
            raise PilotError("Refusing to start: a known secret would reach argv or the child environment.")
        with self.scanner_factory(known) as scanner:
            completed = self.runner(argv, input="\n".join(commands) + "\n", capture_output=True, text=True,
                                    timeout=timeout, env=env, check=False)
        raw = f"{completed.stdout or ''}\n{completed.stderr or ''}"
        output, leaked = known.redact(raw)
        del raw
        leaks["cli_output"] = leaked
        leaks["process_argv"] = "process_argv" in scanner.hits
        leaks["process_environment"] = "process_environment" in scanner.hits
        errors = [line.strip() for line in output.splitlines() if line.lstrip().startswith("%")]
        return CliResult(output=output, errors=errors, leaks=leaks, returncode=completed.returncode)

    def show(self, command: str, *, timeout: int = 60) -> str:
        """Read-only fixed show command (never carries secrets); output is structurally redacted."""
        if not command.startswith("show ") or _PLACEHOLDER.search(command):
            raise PilotError("Only fixed show commands may use the argv path.")
        completed = self.runner(["docker", "exec", self.container, "Cli", "-p", "15", "-c", command],
                                capture_output=True, text=True, timeout=timeout, env=minimal_child_environment(), check=False)
        if completed.returncode != 0:
            raise PilotError(f"R1 '{command}' failed (exit {completed.returncode}).")
        return completed.stdout

    def file_digests(self, path: str, *, timeout: int = 60) -> dict | None:
        """SHA-256/MD5 of a flash file computed in memory; contents are never kept or shown."""
        completed = self.runner(["docker", "exec", self.container, "cat", path], capture_output=True,
                                timeout=timeout, env=minimal_child_environment(), check=False)
        if completed.returncode != 0:
            return None
        blob = completed.stdout if isinstance(completed.stdout, bytes) else completed.stdout.encode()
        return {"sha256": hashlib.sha256(blob).hexdigest(),
                "md5": hashlib.md5(blob).hexdigest(),  # noqa: S324 - EOS `configure replace ... md5`
                "normalized": _normalized_config(blob.decode(errors="replace"))}

    def device_leak_scan(self, known: SecretSet, dirs: Iterable[str] = DEVICE_LEAK_SCAN_DIRS, *, timeout: int = 180) -> list[str]:
        """grep R1's bounded locations; patterns via stdin; returns matching FILE NAMES only."""
        if not len(known):
            return []
        completed = self.runner(
            ["docker", "exec", "-i", self.container, "grep", "-rlF", "-f", "/dev/stdin", *dirs],
            input="\n".join(known) + "\n", capture_output=True, text=True, timeout=timeout,
            env=minimal_child_environment(), check=False,
        )
        return sorted(set(line.strip() for line in (completed.stdout or "").splitlines() if line.strip()))


def _normalized_config(text: str) -> str:
    """Config text without volatile headers or the `Cli -c` command echo (`> show ...`)."""
    return "\n".join(line for line in text.splitlines()
                     if not line.startswith(("! Command:", "! Startup-config last", "> "))).strip()


# --------------------------------------------------------------------------- device state
def running_config(transport: EosCliTransport) -> str:
    return transport.show("show running-config")


def running_digest(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def config_sessions(transport: EosCliTransport) -> dict:
    """Sessions keyed by name.  EOS 4.36.2F reports a running commit timer only at top
    level (`commitTimerSessionName` / `commitTimerExpireTime`, observed live) while the
    session itself reads "committed"; that session is marked ``timer_pending``."""
    text = transport.show("show configuration sessions detail | json")
    data = json.loads(text[text.find("{"):])  # tolerate a `Cli -c` command echo
    sessions = {name: dict(meta or {}) for name, meta in (data.get("sessions") or {}).items()}
    pending = data.get("commitTimerSessionName")
    if pending:
        sessions.setdefault(pending, {}).update(
            {"timer_pending": True, "commitTimerExpireTime": data.get("commitTimerExpireTime")})
    return sessions


# EOS 4.36.2F reports a finished session as {"state": "committed", "completedTime": ...}
# (observed live); "completed"/"aborted" are accepted defensively.
CLOSED_SESSION_STATES = ("committed", "completed", "aborted")


def session_closed(meta: dict | None) -> bool:
    if (meta or {}).get("timer_pending"):
        return False  # a committed session awaiting commit-timer confirmation is still open
    state = str((meta or {}).get("state", "")).lower()
    if state:
        return state in CLOSED_SESSION_STATES
    return bool((meta or {}).get("completedTime"))


def open_sessions(sessions: dict) -> dict:
    """Sessions that are still pending (or timer-pending).  EOS keeps the last
    finished session listed (``maxSavedSessions``); that is history, not an open session."""
    return {name: meta for name, meta in sessions.items() if not session_closed(meta)}


def local_usernames(config_text: str) -> list[str]:
    return sorted(line.split()[1] for line in config_text.splitlines() if line.startswith("username "))


def security_summary(config_text: str) -> list[str]:
    """AAA / RADIUS / SSH / username lines, structurally redacted (no hashes/keys)."""
    keep = re.compile(r"^(aaa |no aaa|radius-server|ip radius|management ssh|username )")
    lines, in_ssh = [], False
    for line in config_text.splitlines():
        if keep.match(line):
            in_ssh = line.startswith("management ssh")
            lines.append(SecretSet().redact(line)[0])
        elif in_ssh and line.startswith("   "):
            lines.append(SecretSet().redact(line)[0])
        else:
            in_ssh = False
    return lines


# --------------------------------------------------------------------------- candidate
@dataclass(frozen=True)
class StagedCandidate:
    digest: str
    stage1: tuple[str, ...]
    stage2: tuple[str, ...]
    rollback: tuple[str, ...]


def staged_candidate(candidate, target: CeosMfaTarget | None = None) -> StagedCandidate:
    """Split a rendered candidate into the reviewed two-stage structure."""
    target = target or target_for(PILOT_DEVICE)
    if candidate.blockers:
        raise PilotError(f"Renderer blockers: {'; '.join(candidate.blockers)}")
    lines = tuple(candidate.lines)
    stage1, stage2 = lines[:2], lines[2:]
    if not (len(stage1) == 2 and stage1[0].startswith(f"username {target.automation_account} ")
            and stage1[1].startswith(f"username {target.breakglass_account} ") and stage2[:1] == ("no username admin",)
            and ACTIVATION_MARKER in stage2):
        raise PilotError("Rendered candidate no longer has the reviewed Stage 1 / Stage 2 structure.")
    return StagedCandidate(candidate.digest, stage1, stage2, tuple(candidate.rollback_lines))


_INVERSES = (
    ("username nmas-automation ", "no username nmas-automation"),
    ("username r1-breakglass ", "no username r1-breakglass"),
    ("no username admin", "username admin "),
    ("radius-server host ", "no radius-server host "),
    ("aaa group server radius ", "no aaa group server radius "),
    ("ip radius source-interface ", "no ip radius source-interface"),
    ("aaa authentication login console ", "no aaa authentication login console"),
    ("aaa authentication login default ", "no aaa authentication login default"),
    ("aaa authorization exec default ", "no aaa authorization exec default"),
    ("aaa authorization commands all default local", "no aaa authorization commands all default local"),
    ("authentication protocol ", "default authentication protocol"),
)
_CONTEXT_LINES = {"management ssh"}


def rollback_pairing(staged: StagedCandidate, target: CeosMfaTarget | None = None) -> dict:
    """Every candidate statement must have exactly its reviewed inverse in the rollback."""
    target = target or target_for(PILOT_DEVICE)
    inverses = (
        (f"username {target.automation_account} ", f"no username {target.automation_account}"),
        (f"username {target.breakglass_account} ", f"no username {target.breakglass_account}"),
        *_INVERSES[2:],
    )
    rollback = [line.strip() for line in staged.rollback]
    unpaired, used = [], set()
    for raw in (*staged.stage1, *staged.stage2):
        line = raw.strip()
        if line in _CONTEXT_LINES or line.startswith("server "):
            continue  # sub-mode context/member removed with its parent
        inverse = next((inv for prefix, inv in inverses if line.startswith(prefix)), None)
        match = next((i for i, r in enumerate(rollback) if inverse and r.startswith(inverse)), None)
        if match is None:
            unpaired.append(line.split(" secret ")[0].split(" key ")[0])
        else:
            used.add(match)
    orphans = [r for i, r in enumerate(rollback) if i not in used and r not in _CONTEXT_LINES]
    return {"valid": not unpaired and not orphans, "unpaired": unpaired, "orphans": orphans}


def diff_changed_lines(diff_output: str) -> list[str]:
    return [line for line in diff_output.splitlines()
            if line.startswith(("+", "-")) and not line.startswith(("+++", "---"))]


# --------------------------------------------------------------------------- commit timer
class TimerState:
    NOT_ARMED = "NOT_ARMED"
    ARMED = "ARMED"
    CONFIRMED = "CONFIRMED"
    AUTO_REVERTED = "AUTO_REVERTED"
    UNKNOWN = "UNKNOWN"


def timer_state(*, sessions: dict, config_text: str, armed_at: float | None, confirmed_at: float | None,
                now: float, stage2_session: str = STAGE2_SESSION,
                activation_marker: str = ACTIVATION_MARKER) -> dict:
    """Classify the Stage 2 commit timer from device state + recorded evidence."""
    session = sessions.get(stage2_session) or {}
    if session.get("timer_pending"):
        expires = session.get("commitTimerExpireTime")
        remaining = expires - now if expires else (armed_at + COMMIT_TIMER_SECONDS - now if armed_at else 0)
        return {"state": TimerState.ARMED, "remaining_seconds": max(0, int(remaining)),
                "device_expire_time": expires, "device_session_state": session.get("state")}
    if armed_at is None:
        return {"state": TimerState.NOT_ARMED, "remaining_seconds": None}
    active = config_text and activation_marker in config_text
    if active and confirmed_at is not None and confirmed_at >= armed_at:
        return {"state": TimerState.CONFIRMED, "remaining_seconds": None}
    if not active and now >= armed_at:
        return {"state": TimerState.AUTO_REVERTED, "remaining_seconds": None}
    return {"state": TimerState.UNKNOWN, "remaining_seconds": None}


# --------------------------------------------------------------------------- gates
@dataclass
class GateReport:
    failures: list[str] = field(default_factory=list)
    passed: list[str] = field(default_factory=list)

    def check(self, name: str, ok: bool, detail: str = "") -> None:
        (self.passed if ok else self.failures).append(name if ok else f"{name}: {detail}".rstrip(": "))

    @property
    def ok(self) -> bool:
        return not self.failures


def mfa_infrastructure_healthy(runner: Runner = subprocess.run, containers: dict | None = None) -> tuple[bool, list[str]]:
    containers = MFA_CONTAINERS if containers is None else containers
    problems = []
    for name, required in containers.items():
        completed = runner(["docker", "inspect", "-f", "{{.State.Status}} {{if .State.Health}}{{.State.Health.Status}}{{end}}", name],
                           capture_output=True, text=True, timeout=20, env=minimal_child_environment(), check=False)
        status = (completed.stdout or "").split()
        if completed.returncode != 0 or not status or status[0] != "running" or (required == "healthy" and status[-1] != "healthy"):
            problems.append(name)
    return not problems, problems


def management_reachable(address: str = PILOT_MGMT_ADDRESS, port: int = 22, timeout: float = 5.0) -> bool:
    try:
        with socket.create_connection((address, port), timeout=timeout):
            return True
    except OSError:
        return False


# --------------------------------------------------------------------------- post-pilot routine verification
class PositiveResult:
    """Outcome classes of ``verify-positive`` (one human attempt, attributed from read-only evidence)."""
    AUTH_SUCCESS = "AUTH_SUCCESS"
    AUTH_SUCCESS_COMMAND_DENIED = "AUTH_SUCCESS_COMMAND_DENIED"
    AUTH_SUCCESS_PRIVILEGE_MISMATCH = "AUTH_SUCCESS_PRIVILEGE_MISMATCH"
    PRIVACYIDEA_REJECT = "PRIVACYIDEA_REJECT"
    RADIUS_TRANSPORT_FAILURE = "RADIUS_TRANSPORT_FAILURE"
    EOS_REJECT_AFTER_RADIUS_ACCEPT = "EOS_REJECT_AFTER_RADIUS_ACCEPT"
    R1_SSH_UNREACHABLE = "R1_SSH_UNREACHABLE"
    UNKNOWN = "UNKNOWN"
    SUCCESS = (AUTH_SUCCESS, AUTH_SUCCESS_COMMAND_DENIED)


# `show radius` (EOS 4.36.2F, observed on R1): "   Messages sent:     6" -- first server block only.
_RADIUS_COUNTERS = {
    "Messages sent": "messages_sent", "Messages received": "messages_received",
    "Requests accepted": "requests_accepted", "Requests rejected": "requests_rejected",
    "Requests timeout": "requests_timeout", "Requests retransmitted": "requests_retransmitted",
    "Bad responses": "bad_responses", "Connection errors": "connection_errors",
}
_RADIUS_COUNTER_LINE = re.compile(r"^\s*(" + "|".join(_RADIUS_COUNTERS) + r"):\s+(\d+)\s*$")


def parse_radius_counters(text: str) -> dict[str, int]:
    counters: dict[str, int] = {}
    for line in text.splitlines():
        m = _RADIUS_COUNTER_LINE.match(line)
        if m and _RADIUS_COUNTERS[m.group(1)] not in counters:
            counters[_RADIUS_COUNTERS[m.group(1)]] = int(m.group(2))
    missing = set(_RADIUS_COUNTERS.values()) - set(counters)
    if missing:
        raise PilotError(f"R1 'show radius' counters incomplete: missing {sorted(missing)}")
    return counters


def radius_delta(before: dict[str, int], after: dict[str, int]) -> dict[str, int]:
    return {key: after[key] - before[key] for key in before}


def classify_command_output(text: str) -> str:
    """Post-login command result: an authorization refusal is NOT an authentication failure."""
    if re.search(r"%\s*Authorization denied", text, re.IGNORECASE):
        return "DENIED"
    level = parse_privilege_level(text)
    if level == 15:
        return "OK"
    if level is not None:
        return "UNEXPECTED_LEVEL"
    return "OTHER"


def parse_privilege_level(text: str) -> int | None:
    """Return only the numeric EOS session level; never retain raw command output."""
    match = re.search(r"\bprivilege\s+level\s+is\s+(\d{1,2})\b", text, re.IGNORECASE)
    if not match:
        return None
    level = int(match.group(1))
    return level if 0 <= level <= 15 else None


def attribute_positive_attempt(login: dict, delta: dict[str, int] | None, rows: list[dict] | None) -> tuple[str, str]:
    """Classify ONE nmas-admin attempt from its SSH outcome, R1 RADIUS counter deltas and the
    privacyIDEA audit rows written since the baseline.  Anything that cannot be attributed
    unambiguously is UNKNOWN -- never a guess."""
    state = login.get("login")
    if state == "UNREACHABLE":
        return PositiveResult.R1_SSH_UNREACHABLE, "SSH connect/handshake to R1 failed; no authentication was sent"
    if delta is None or rows is None:
        return PositiveResult.UNKNOWN, "post-attempt RADIUS/privacyIDEA evidence could not be read"
    requests = delta["messages_sent"] - delta["requests_retransmitted"]
    if requests > 1 or len(rows) > 1:
        return PositiveResult.UNKNOWN, f"{requests} RADIUS request(s) and {len(rows)} privacyIDEA row(s) since the baseline"
    row = rows[0] if rows else None
    pi_accept = row is not None and row.get("authentication") == "ACCEPT" and bool(row.get("success"))
    if state == "ACCEPT":
        if pi_accept and delta["requests_accepted"] == 1:
            if login.get("command") == "DENIED":
                return PositiveResult.AUTH_SUCCESS_COMMAND_DENIED, "authenticated; only command authorization was refused"
            if login.get("command") == "UNEXPECTED_LEVEL":
                return PositiveResult.AUTH_SUCCESS_PRIVILEGE_MISMATCH, "authenticated; EOS session privilege was not 15"
            return PositiveResult.AUTH_SUCCESS, "authenticated via RADIUS/privacyIDEA"
        return PositiveResult.UNKNOWN, "SSH accepted without a matching RADIUS + privacyIDEA accept"
    if row is not None:
        if pi_accept:
            if delta["requests_accepted"] == 1:
                return PositiveResult.EOS_REJECT_AFTER_RADIUS_ACCEPT, "privacyIDEA and R1 RADIUS accepted, but SSH login failed"
            if delta["requests_timeout"] or delta["messages_received"] < requests:
                return PositiveResult.RADIUS_TRANSPORT_FAILURE, "privacyIDEA accepted but R1 received no Access-Accept"
            return PositiveResult.UNKNOWN, "privacyIDEA accepted but R1 counters do not show the reply"
        if delta["requests_rejected"] == 1:
            return PositiveResult.PRIVACYIDEA_REJECT, f"privacyIDEA: {str(row.get('info') or '-')[:80]}"
        return PositiveResult.UNKNOWN, "privacyIDEA rejected but R1 counters do not show the Access-Reject"
    if delta["requests_timeout"] or delta["connection_errors"] or delta["messages_received"] < requests:
        return PositiveResult.RADIUS_TRANSPORT_FAILURE, "EOS -> FreeRADIUS: request unanswered"
    if requests == 1 and delta["requests_rejected"] == 1:
        return PositiveResult.RADIUS_TRANSPORT_FAILURE, "FreeRADIUS rejected without a privacyIDEA decision (FreeRADIUS -> privacyIDEA)"
    return PositiveResult.UNKNOWN, f"no privacyIDEA row; {requests} RADIUS request(s) from R1"


# Fixed, read-only privacyIDEA metadata script (stdin of `docker exec -i ... python -`).  It only
# ever reads token flags/counters and audit rows; never the OTP key, a PIN or a password.
_PRIVACYIDEA_SCRIPT = """
import json
PARAMS = json.loads({params!r})
from privacyidea.app import create_docker_app
app = create_docker_app()
with app.app_context():
    if PARAMS["kind"] == "token":
        from privacyidea.lib.token import get_one_token
        tok = get_one_token(serial=PARAMS["serial"])
        user = tok.user
        out = {{"serial": tok.token.serial, "type": tok.type, "owner": getattr(user, "login", None) if user else None,
               "active": bool(tok.token.active), "locked": bool(tok.is_locked()), "revoked": bool(tok.token.revoked),
               "failcount": int(tok.token.failcount), "maxfail": int(tok.token.maxfail)}}
    else:
        from privacyidea.models import db
        from privacyidea.models.audit import Audit
        query = db.session.query(Audit).filter(Audit.user == PARAMS["user"])
        latest = query.order_by(Audit.id.desc()).first()
        rows = []
        if PARAMS["after_id"] is not None:
            for row in query.filter(Audit.id > PARAMS["after_id"], Audit.action == "POST /validate/radiuscheck").order_by(Audit.id).limit(10):
                rows.append({{"id": row.id, "success": bool(row.success), "authentication": row.authentication or "",
                             "serial": row.serial or "", "policies": (row.policies or "")[:80], "info": (row.info or "")[:80]}})
        out = {{"max_id": latest.id if latest else 0, "rows": rows}}
    print("NMAS-JSON:" + json.dumps(out))
"""


class PrivacyIdeaReader:
    """Read-only privacyIDEA metadata via a fixed script on stdin; argv carries no parameters."""

    def __init__(self, container: str = PRIVACYIDEA_APP_CONTAINER, *, runner: Runner = subprocess.run):
        self.container, self.runner = container, runner

    def _query(self, params: dict) -> dict:
        completed = self.runner(["docker", "exec", "-i", self.container, PRIVACYIDEA_PYTHON, "-"],
                                input=_PRIVACYIDEA_SCRIPT.format(params=json.dumps(params)), capture_output=True,
                                text=True, timeout=60, env=minimal_child_environment(), check=False)
        for line in reversed((completed.stdout or "").splitlines()):
            if line.startswith("NMAS-JSON:"):
                return json.loads(line[len("NMAS-JSON:"):])
        raise PilotError(f"privacyIDEA metadata read failed (exit {completed.returncode}).")

    def token(self, serial: str = HUMAN_TOKEN_SERIAL) -> dict:
        return self._query({"kind": "token", "serial": serial})

    def audit(self, user: str = HUMAN_USERNAME, after_id: int | None = None) -> dict:
        return self._query({"kind": "audit", "user": user, "after_id": after_id})
