"""Dedicated read-only diagnostic identities (``nmas-diag``) on the managed lab devices -- Infrastructure as Code.

One account per device, never shared, never write-capable:

* **Arista cEOS** (R1, R2, S1, S2, S3, S4, mgmt_swt): ``username nmas-diag role network-operator secret <unique>`` rendered
  from ``templates/monitoring/ceos_diag_user.j2``.  The devices run ``aaa authorization commands all default local``, so the
  built-in ``network-operator`` role is *enforced* (configuration mode is denied); ``verify_ceos`` proves that live.
* **Ubuntu/FRR** (R3, R4): a locked-password account whose only key is pinned to a forced command
  (``restrict,command="/usr/local/libexec/nmas-diag-broker"``).  The broker compares the requested command string with a
  root-owned allowlist generated from the Troubleshooter's read-only Linux catalogue
  (``diagnostic_worker.broker_allowlist``) and executes the matching argv directly -- no shell, no sudo, bounded time and
  output.  Membership of ``frrvty`` lets ``vtysh`` answer the allowlisted ``show`` queries; the broker can never send
  anything else.  sshd admits the account only from NMAS (192.168.200.100) and only by public key
  (``core.services.credentials.linux_mfa.sshd_dropin``).

Secrets: cEOS passwords and FRR private keys are generated here and kept ONLY in the protected runtime provider
(``FileSecretProvider``), under ``runtime://device-credentials/<device>-nmas-diag`` / ``...-nmas-diag-sshkey``.  Values are
never printed, logged, put on argv or returned to callers other than the verifier.  Configuration reaches the devices
through the trusted Containerlab console (``docker exec -i``, data on stdin), exactly like the SNMP / gNMI / syslog phases.

Rerun-safe: an existing secret is reused; an account that already logs in with the stored secret is left untouched
(``changed=False``).  ``rotate=True`` stages a fresh secret, applies it and promotes it only after a successful login.
"""

from __future__ import annotations

import io
import json
import re
import secrets
import socket
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, StrictUndefined

BASE = Path(__file__).resolve().parent.parent
USERNAME = "nmas-diag"
CEOS_DEVICES = ("R1", "R2", "S1", "S2", "S3", "S4", "mgmt_swt")
FRR_DEVICES = ("R3", "R4")
CONTAINER_PREFIX = "clab-srlceos01-"
NMAS_SOURCE = "192.168.200.100"
BROKER_PATH = "/usr/local/libexec/nmas-diag-broker"
ALLOWLIST_PATH = "/etc/nmas-diag/allowlist"
MAX_BROKER_OUTPUT = 512 * 1024
BROKER_TIMEOUT = 20
REFUSED_MARKER = "NMAS_DIAG_REFUSED"
_EOS_ERROR = re.compile(r"% (Invalid|Error|Incomplete|Unrecognized|Ambiguous)")


class DiagnosticAccountError(RuntimeError):
    """Sanitized failure: a stable code, never a secret or raw device output."""


def secret_ref(device: str) -> str:
    return f"runtime://device-credentials/{device.lower()}-nmas-diag"


def key_ref(device: str) -> str:
    return f"runtime://device-credentials/{device.lower()}-nmas-diag-sshkey"


def container(device: str) -> str:
    return CONTAINER_PREFIX + device


# ------------------------------------------------------------------------------------------------------------------ broker
BROKER_SCRIPT = f'''#!/usr/bin/python3 -I
"""NMAS read-only diagnostic broker (forced command for {USERNAME}).  Managed by NMAS IaC -- do not edit on the device."""
import os, shlex, subprocess, sys
ALLOWLIST = "{ALLOWLIST_PATH}"
requested = os.environ.get("SSH_ORIGINAL_COMMAND", "")
try:
    with open(ALLOWLIST, encoding="utf-8") as handle:
        allowed = {{line.rstrip("\\n") for line in handle if line.strip() and not line.startswith("#")}}
except OSError:
    allowed = set()
if requested not in allowed:
    sys.stderr.write("{REFUSED_MARKER}: command is not in the read-only allowlist\\n")
    sys.exit(126)
try:
    done = subprocess.run(shlex.split(requested), stdin=subprocess.DEVNULL, capture_output=True, timeout={BROKER_TIMEOUT},
                          env={{"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8"}})
except subprocess.TimeoutExpired:
    sys.stderr.write("{REFUSED_MARKER}: timeout\\n")
    sys.exit(124)
sys.stdout.buffer.write(done.stdout[:{MAX_BROKER_OUTPUT}])
sys.exit(done.returncode)
'''


def allowlist_text(commands) -> str:
    rows = sorted({str(c) for c in commands})
    if not rows or any("\n" in c or not c.strip() for c in rows):
        raise DiagnosticAccountError("ALLOWLIST_INVALID")
    return "# NMAS read-only diagnostic broker allowlist (generated from the Troubleshooter Linux catalogue)\n" + "\n".join(rows) + "\n"


def authorized_key_line(public_key: str) -> str:
    parts = public_key.strip().split()
    if len(parts) < 2 or parts[0] != "ssh-ed25519":
        raise DiagnosticAccountError("PUBLIC_KEY_INVALID")
    return f'restrict,command="{BROKER_PATH}" {parts[0]} {parts[1]} {USERNAME}@nmas\n'


FRR_APPLY_PROGRAM = r'''
import json, os, pathlib, pwd, grp, signal, subprocess, sys, tempfile
data = json.loads(sys.stdin.read()); out = {"changed": []}
def atomic(path, value, mode, owner=None):
    path = pathlib.Path(path); path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and path.read_text() == value and (path.stat().st_mode & 0o777) == mode:
        return False
    fd, temp = tempfile.mkstemp(prefix="." + path.name + "-", dir=path.parent)
    with os.fdopen(fd, "w") as handle:
        handle.write(value); handle.flush(); os.fsync(handle.fileno())
    os.chmod(temp, mode)
    if owner:
        os.chown(temp, owner.pw_uid, owner.pw_gid)
    os.replace(temp, path); return True
def run(argv):
    done = subprocess.run(argv, capture_output=True, text=True)
    if done.returncode:
        raise SystemExit(json.dumps({"failed": argv[0], "code": done.returncode}))
user = data["user"]
try:
    pwd.getpwnam(user)
except KeyError:
    run(["useradd", "--create-home", "--shell", "/bin/sh", "--groups", "frrvty", user]); out["changed"].append("user")
if user not in grp.getgrnam("frrvty").gr_mem:
    run(["usermod", "--append", "--groups", "frrvty", user]); out["changed"].append("frrvty")
run(["passwd", "--lock", user])
if atomic(data["broker_path"], data["broker"], 0o755): out["changed"].append("broker")
if atomic(data["allowlist_path"], data["allowlist"], 0o644): out["changed"].append("allowlist")
owner = pwd.getpwnam(user); ssh = pathlib.Path(owner.pw_dir) / ".ssh"; ssh.mkdir(mode=0o700, exist_ok=True); os.chown(ssh, owner.pw_uid, owner.pw_gid)
if atomic(ssh / "authorized_keys", data["authorized_key"], 0o600, owner): out["changed"].append("authorized_key")
dropin = pathlib.Path(data["dropin_path"]); previous = dropin.read_text() if dropin.exists() else None
if previous != data["dropin"]:
    if previous != data["expected_previous_dropin"]:
        raise SystemExit(json.dumps({"failed": "dropin_drift", "code": 3}))
    atomic(dropin, data["dropin"], 0o644)
    if subprocess.run(["sshd", "-t"], capture_output=True).returncode:
        atomic(dropin, previous, 0o644)
        raise SystemExit(json.dumps({"failed": "sshd_validate_rolled_back", "code": 4}))
    pid = subprocess.run(["pgrep", "-o", "sshd"], capture_output=True, text=True).stdout.strip()
    os.kill(int(pid), signal.SIGHUP); out["changed"].append("sshd_dropin")
print(json.dumps(out))
'''


# ------------------------------------------------------------------------------------------------------------ secrets
def _provider(store_path=None):
    from modules.device_credentials import FileSecretProvider

    return FileSecretProvider(store_path)


def ensure_password(device: str, *, provider=None, rotate: bool = False) -> tuple[str, bool]:
    """-> (password, newly created).  A rotation stages a pending value (promoted by the caller after a verified login)."""
    from modules.device_credentials import SecretNotFound

    provider = provider or _provider()
    ref = secret_ref(device)
    try:
        current = provider.current(ref).value
    except SecretNotFound:
        value = secrets.token_urlsafe(24)
        provider.initialize(ref, value)
        return value, True
    if rotate:
        value = secrets.token_urlsafe(24)
        provider.stage(ref, value)
        return value, True
    return current, False


def ensure_keypair(device: str, *, provider=None) -> tuple[str, bool]:
    """-> (OpenSSH public key line, newly created).  The private key lives only in the provider."""
    import paramiko
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from modules.device_credentials import SecretNotFound

    provider = provider or _provider()
    ref = key_ref(device)
    created = False
    try:
        pem = provider.current(ref).value
    except SecretNotFound:
        private = Ed25519PrivateKey.generate()
        pem = private.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.OpenSSH,
                                    serialization.NoEncryption()).decode()
        provider.initialize(ref, pem)
        created = True
    key = paramiko.Ed25519Key.from_private_key(io.StringIO(pem))
    return f"{key.get_name()} {key.get_base64()}", created


# ------------------------------------------------------------------------------------------------------------ apply
def _docker(argv: list[str], *, stdin: str | None = None, timeout: int = 90) -> subprocess.CompletedProcess:
    return subprocess.run(["docker", *argv], input=stdin, capture_output=True, text=True, timeout=timeout, check=False)


def render_ceos(password: str) -> str:
    env = Environment(loader=FileSystemLoader(BASE / "templates/monitoring"), undefined=StrictUndefined)
    return env.get_template("ceos_diag_user.j2").render(username=USERNAME, password=password) + "\n"


def apply_ceos(device: str, password: str) -> None:
    done = _docker(["exec", "-i", container(device), "Cli", "-p", "15", "--abort-on-error"], stdin=render_ceos(password))
    if done.returncode or _EOS_ERROR.search(done.stdout + done.stderr):
        raise DiagnosticAccountError(f"{device}: EOS_REJECTED_ACCOUNT_CONFIGURATION")


def apply_frr(device: str, public_key: str, allowlist, *, dropin: str, expected_previous_dropin: str,
              dropin_path: str = "/etc/ssh/sshd_config.d/60-nmas-human-mfa.conf") -> list[str]:
    payload = json.dumps({"user": USERNAME, "broker_path": BROKER_PATH, "broker": BROKER_SCRIPT,
                          "allowlist_path": ALLOWLIST_PATH, "allowlist": allowlist_text(allowlist),
                          "authorized_key": authorized_key_line(public_key), "dropin_path": dropin_path, "dropin": dropin,
                          "expected_previous_dropin": expected_previous_dropin})
    done = _docker(["exec", "-i", container(device), "python3", "-c", FRR_APPLY_PROGRAM], stdin=payload)
    if done.returncode:
        detail = done.stderr.strip().splitlines()[-1:] or ["unknown"]
        code = detail[0] if detail[0].startswith("{") else "APPLY_FAILED"
        raise DiagnosticAccountError(f"{device}: FRR_APPLY_FAILED {code}"[:200])
    return json.loads(done.stdout.strip().splitlines()[-1]).get("changed", [])


# ------------------------------------------------------------------------------------------------------------ verify
@dataclass
class Verification:
    device: str
    login: bool = False
    read_ok: bool = False
    write_denied: bool = False
    shell_denied: bool = False
    presented_host_key: str = ""
    details: dict = field(default_factory=dict)

    @property
    def passed(self) -> bool:
        return self.login and self.read_ok and self.write_denied and self.shell_denied

    def as_dict(self) -> dict:
        return {"device": self.device, "login": self.login, "read_ok": self.read_ok, "write_denied": self.write_denied,
                "shell_denied": self.shell_denied, "presented_host_key": self.presented_host_key, "passed": self.passed,
                "details": self.details}


def _connect(address: str, *, pin: str, username: str, password: str = "", pkey=None, timeout: float = 15.0):
    import base64
    import hashlib

    import paramiko

    sock = socket.create_connection((address, 22), timeout=timeout, source_address=(NMAS_SOURCE, 0))
    transport = paramiko.Transport(sock)
    transport.start_client(timeout=timeout)
    presented = "SHA256:" + base64.b64encode(hashlib.sha256(transport.get_remote_server_key().asbytes()).digest()).decode().rstrip("=")
    if presented != pin:
        transport.close()
        raise DiagnosticAccountError("HOST_KEY_MISMATCH")
    if pkey is not None:
        transport.auth_publickey(username, pkey)
    else:
        transport.auth_password(username, password)
    if not transport.is_authenticated():
        transport.close()
        raise DiagnosticAccountError("AUTH_FAILED")
    return transport, presented


def _exec(transport, command: str, timeout: float = 20.0) -> tuple[int, str, str]:
    channel = transport.open_session(timeout=timeout)
    channel.settimeout(timeout)
    channel.exec_command(command)
    out, err = b"", b""
    while True:
        chunk = channel.recv(65536)
        if not chunk:
            break
        out += chunk
    while channel.recv_stderr_ready():
        err += channel.recv_stderr(65536)
    code = channel.recv_exit_status()
    channel.close()
    return code, out.decode("utf-8", "replace"), err.decode("utf-8", "replace")


def verify_ceos(device: str, address: str, *, pin: str, password: str) -> Verification:
    result = Verification(device)
    try:
        transport, result.presented_host_key = _connect(address, pin=pin, username=USERNAME, password=password)
    except (DiagnosticAccountError, OSError, Exception) as exc:  # noqa: BLE001 - any failure is "no login"
        result.details["login_error"] = getattr(exc, "args", ["?"])[0] if isinstance(exc, DiagnosticAccountError) else type(exc).__name__
        return result
    result.login = True
    try:
        _code, out, _err = _exec(transport, "show version | json")
        result.read_ok = '"version"' in out or '"modelName"' in out
        _code, out, err = _exec(transport, "configure terminal")
        text = (out + err).lower()
        result.write_denied = "authorization denied" in text or "not authorized" in text or "privileged mode required" in text
        result.details["configure_response"] = (out + err).strip()[:120]
        _code, out, err = _exec(transport, "bash id")
        text = (out + err).lower()
        result.shell_denied = "authorization denied" in text or "not authorized" in text or "privileged mode required" in text \
            or "invalid input" in text
        result.details["bash_response"] = (out + err).strip()[:120]
    finally:
        transport.close()
    return result


def verify_ceos_escalation(device: str, address: str, *, pin: str, password: str) -> dict:
    """Interactive escalation test: ``enable`` may succeed (no enable secret), so the device's command AUTHORIZATION must refuse
    ``configure terminal`` afterwards.  -> {"enable_prompt": bool, "configure_denied": bool, "passed": bool}."""
    import time

    transport, _presented = _connect(address, pin=pin, username=USERNAME, password=password)
    out = ""
    try:
        channel = transport.open_session()
        channel.get_pty()
        channel.invoke_shell()
        time.sleep(2)
        channel.recv(65536)
        for command in ("enable", "configure terminal"):
            channel.send(command + "\n")
            time.sleep(1.5)
            while channel.recv_ready():
                out += channel.recv(65536).decode("utf-8", "replace")
        channel.close()
    finally:
        transport.close()
    denied = "Authorization denied for command 'configure terminal'" in out or "privileged mode required" in out
    entered_config = "(config)#" in out
    return {"enable_prompt": f"{device}#" in out, "configure_denied": denied and not entered_config,
            "passed": denied and not entered_config}


def verify_frr(device: str, address: str, *, pin: str, pkey) -> Verification:
    result = Verification(device)
    try:
        transport, result.presented_host_key = _connect(address, pin=pin, username=USERNAME, pkey=pkey)
    except (DiagnosticAccountError, OSError, Exception) as exc:  # noqa: BLE001
        result.details["login_error"] = getattr(exc, "args", ["?"])[0] if isinstance(exc, DiagnosticAccountError) else type(exc).__name__
        return result
    result.login = True
    try:
        code, out, _err = _exec(transport, "hostname")
        result.read_ok = code == 0 and out.strip() == device
        code, out, err = _exec(transport, "vtysh -c 'show ip ospf neighbor json'")
        result.details["vtysh_read"] = code == 0 and out.lstrip().startswith("{")
        result.read_ok = result.read_ok and result.details["vtysh_read"]
        code, _out, err = _exec(transport, "vtysh -c 'configure terminal'")
        result.write_denied = code == 126 and REFUSED_MARKER in err
        code, _out, err = _exec(transport, "id")
        result.shell_denied = code == 126 and REFUSED_MARKER in err
        code, _out, err = _exec(transport, "ip link set dev lo down")
        result.details["interface_change_refused"] = code == 126 and REFUSED_MARKER in err
        result.write_denied = result.write_denied and result.details["interface_change_refused"]
    finally:
        transport.close()
    return result


def load_pkey(device: str, *, provider=None):
    import paramiko

    provider = provider or _provider()
    return paramiko.Ed25519Key.from_private_key(io.StringIO(provider.current(key_ref(device)).value))


def promote_if_staged(device: str, *, provider=None) -> None:
    provider = provider or _provider()
    ref = secret_ref(device)
    if provider.has_pending(ref):
        provider.promote(ref, provider.pending(ref).version)
