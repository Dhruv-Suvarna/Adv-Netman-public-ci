"""Reviewed R3/R4 Ubuntu SSH/PAM MFA transaction primitives.

Secrets are resolved only into memory and sent to the target on docker-exec
stdin.  They never enter argv, the environment, output, evidence, or Git.
"""
from __future__ import annotations

import json
import re
import secrets
import subprocess
from dataclasses import dataclass
from pathlib import Path

from django.conf import settings

from modules.device_credentials import FileSecretProvider, load_ssh_private_key

from ...models import DeviceCredential
from .mfa import render_candidate

NMAS_ADDRESS = "192.168.200.100"
HUMAN_USERNAME = "nmas-admin"
SERVICE_USERNAME = "nmas-automation"
ROLLBACK_SECONDS = 600
TOKEN_RE = re.compile(r"^[a-f0-9]{24}$")
CONFIG_PATHS = (
    "/etc/ssh/sshd_config.d/60-nmas-human-mfa.conf",
    "/etc/pam.d/sshd",
    "/etc/pam_radius_auth.conf",
    "/etc/sudoers.d/60-nmas-mfa",
)


class LinuxMfaError(RuntimeError):
    """Sanitized rollout failure."""


ACTIVATION_STAGES = (
    "resolve_protected_material",
    "invoke_device_activation_helper",
    "decode_activation_diagnostics",
    "ensure_accounts",
    "set_local_passwords",
    "lock_service_password",
    "prepare_service_ssh_directory",
    "install_service_authorized_key",
    "deploy_pam_radius_config",
    "deploy_pam_stack",
    "deploy_sshd_dropin",
    "deploy_sudoers_policy",
    "validate_sudoers",
    "validate_sshd_config",
    "locate_sshd_listener",
    "reload_sshd",
    "post_reload_configuration_inspection",
)

_STAGE_CATEGORIES = {
    "resolve_protected_material": "protected_provider",
    "invoke_device_activation_helper": "container_execution",
    "decode_activation_diagnostics": "diagnostic_validation",
    "ensure_accounts": "account_management",
    "set_local_passwords": "account_management",
    "lock_service_password": "account_management",
    "prepare_service_ssh_directory": "filesystem",
    "install_service_authorized_key": "filesystem",
    "deploy_pam_radius_config": "protected_file_install",
    "deploy_pam_stack": "pam_config_install",
    "deploy_sshd_dropin": "sshd_config_install",
    "deploy_sudoers_policy": "sudoers_config_install",
    "validate_sudoers": "sudoers_validation",
    "validate_sshd_config": "sshd_validation",
    "locate_sshd_listener": "process_discovery",
    "reload_sshd": "sshd_reload",
    "post_reload_configuration_inspection": "post_reload_validation",
}

_STAGE_PATHS = {
    "install_service_authorized_key": "/home/nmas-automation/.ssh/authorized_keys",
    "deploy_pam_radius_config": "/etc/pam_radius_auth.conf",
    "deploy_pam_stack": "/etc/pam.d/sshd",
    "deploy_sshd_dropin": "/etc/ssh/sshd_config.d/60-nmas-human-mfa.conf",
    "deploy_sudoers_policy": "/etc/sudoers.d/60-nmas-mfa",
    "validate_sudoers": "/etc/sudoers.d/60-nmas-mfa",
    "validate_sshd_config": "/etc/ssh/sshd_config",
}

_STAGE_SUMMARIES = {
    stage: f"{category.replace('_', ' ')} did not complete"
    for stage, category in _STAGE_CATEGORIES.items()
}


class LinuxMfaActivationError(LinuxMfaError):
    """Structured, bounded activation failure with no command or secret output."""

    def __init__(self, *, stage: str, return_code: int | None, exception_class: str,
                 stage_trace: list[dict] | None = None, helper_return_code: int | None = None):
        self.stage = stage if stage in ACTIVATION_STAGES else "post_reload_configuration_inspection"
        self.return_code = return_code if isinstance(return_code, int) else None
        self.exception_class = exception_class if exception_class in {
            "StageCommandError", "OSError", "PermissionError", "FileNotFoundError",
            "ProcessLookupError", "TimeoutExpired", "RuntimeError", "ValueError",
        } else "ActivationError"
        self.command_category = _STAGE_CATEGORIES[self.stage]
        self.stderr_summary = _STAGE_SUMMARIES[self.stage]
        self.stage_trace = sanitize_activation_trace(stage_trace or [])
        self.helper_return_code = helper_return_code if isinstance(helper_return_code, int) else None
        super().__init__(f"Linux MFA activation failed at {self.stage}; automatic rollback must remain armed.")

    def as_dict(self) -> dict:
        result = {
            "failed_stage": self.stage,
            "command_category": self.command_category,
            "return_code": self.return_code,
            "helper_return_code": self.helper_return_code,
            "exception_class": self.exception_class,
            "stderr_summary": self.stderr_summary,
            "sshd_reload_started": any(
                item["stage"] == "reload_sshd" and item["status"] == "started" for item in self.stage_trace
            ),
            "sshd_reload_completed": any(
                item["stage"] == "reload_sshd" and item["status"] == "completed" for item in self.stage_trace
            ),
            "stage_trace": self.stage_trace,
        }
        if self.stage in _STAGE_PATHS:
            result["target_path"] = _STAGE_PATHS[self.stage]
        if self.stage in ("locate_sshd_listener", "reload_sshd"):
            result["service_name"] = "sshd"
        return result


def sanitize_activation_trace(value) -> list[dict]:
    """Accept only known stage/status/timing fields from the device helper."""
    cleaned = []
    if not isinstance(value, list):
        return cleaned
    for item in value[:64]:
        if not isinstance(item, dict) or item.get("stage") not in ACTIVATION_STAGES:
            continue
        status = item.get("status")
        if status not in ("started", "completed", "failed"):
            continue
        event = {"stage": item["stage"], "status": status}
        at = item.get("at")
        if isinstance(at, (int, float)):
            event["at"] = float(at)
        rc = item.get("return_code")
        if isinstance(rc, int):
            event["return_code"] = rc
        cleaned.append(event)
    return cleaned


@dataclass(frozen=True)
class LinuxMfaTarget:
    device: str
    container: str
    address: str
    source_address: str
    breakglass_username: str
    service_key_ref: str
    breakglass_ref: str
    radius_ref: str


TARGETS = {
    device: LinuxMfaTarget(
        device=device,
        container=f"clab-srlceos01-{device}",
        address=f"192.168.200.{3 if device == 'R3' else 4}",
        source_address=NMAS_ADDRESS,
        breakglass_username=f"{device.lower()}-breakglass",
        service_key_ref=f"runtime://device-credentials/{device.lower()}-nmas-automation-sshkey",
        breakglass_ref=f"runtime://device-credentials/{device.lower()}-breakglass",
        radius_ref=f"runtime://human-mfa/radius/{device.lower()}",
    ) for device in ("R3", "R4")
}


def target_for(device: str) -> LinuxMfaTarget:
    try:
        return TARGETS[device]
    except KeyError:
        raise LinuxMfaError("Linux MFA rollout is restricted to R3 and R4.") from None


def radius_secret_path(device: str, repo_root: Path | None = None) -> Path:
    root = Path(repo_root or settings.REPO_ROOT)
    return root / "monitoring" / "runtime" / "human-mfa" / "secrets" / f"radius_{device.lower()}_secret"


def private_runtime_value(path: Path) -> str:
    try:
        stat = path.lstat()
    except OSError:
        raise LinuxMfaError("Protected runtime material is missing.") from None
    if path.is_symlink() or not path.is_file() or stat.st_mode & 0o077:
        raise LinuxMfaError("Protected runtime material has unsafe permissions.")
    value = path.read_text(encoding="utf-8").strip()
    if not value or any(ch.isspace() for ch in value):
        raise LinuxMfaError("Protected runtime material is invalid.")
    return value


def reviewed_candidate(target: LinuxMfaTarget):
    from ...models import DeviceLoginMfaPolicy
    policy = DeviceLoginMfaPolicy.objects.get(device_name=target.device)
    return render_candidate(policy, DeviceCredential.objects.filter(device_name=target.device))


def pam_sshd() -> str:
    return """# NMAS Phase 26B: only nmas-admin uses central RADIUS/TOTP.
auth [success=2 default=ignore] pam_succeed_if.so quiet user = nmas-admin
auth substack common-auth
auth [success=done default=die] pam_permit.so
auth required pam_radius_auth.so conf=/etc/pam_radius_auth.conf client_id=nmas-linux-ssh
account required pam_nologin.so
@include common-account
session [success=ok ignore=ignore module_unknown=ignore default=bad] pam_selinux.so close
session required pam_loginuid.so
session optional pam_keyinit.so force revoke
@include common-session
session optional pam_motd.so motd=/run/motd.dynamic
session optional pam_motd.so noupdate
session optional pam_mail.so standard noenv
session required pam_limits.so
session required pam_env.so
session required pam_env.so user_readenv=1 envfile=/etc/default/locale
session [success=ok ignore=ignore module_unknown=ignore default=bad] pam_selinux.so open
@include common-password
"""


def sshd_dropin(target: LinuxMfaTarget) -> str:
    return f"""# NMAS Phase 26B managed human/service/recovery separation.
UsePAM yes
PermitRootLogin no
PasswordAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
AllowUsers {HUMAN_USERNAME}@{target.source_address} {SERVICE_USERNAME}@{target.source_address} {target.breakglass_username}@{target.source_address}

Match User {HUMAN_USERNAME} Address {target.source_address}
    AuthenticationMethods keyboard-interactive:pam
    KbdInteractiveAuthentication yes
    PasswordAuthentication no
    PubkeyAuthentication no

Match User {SERVICE_USERNAME} Address {target.source_address}
    AuthenticationMethods publickey
    PubkeyAuthentication yes
    KbdInteractiveAuthentication no
    PasswordAuthentication no

Match User {target.breakglass_username} Address {target.source_address}
    AuthenticationMethods password
    PasswordAuthentication yes
    KbdInteractiveAuthentication no
    PubkeyAuthentication no

Match all
"""


def sudoers(target: LinuxMfaTarget) -> str:
    return f"""# Interactive privilege follows a successful MFA/emergency SSH login.
{HUMAN_USERNAME} ALL=(ALL:ALL) NOPASSWD: ALL
{target.breakglass_username} ALL=(ALL:ALL) NOPASSWD: ALL
"""


class DockerTransport:
    def __init__(self, target: LinuxMfaTarget, runner=subprocess.run):
        self.target, self.runner = target, runner

    def run(self, argv: list[str], *, stdin: str | None = None, timeout: int = 60) -> subprocess.CompletedProcess:
        completed = self.runner(
            ["docker", "exec", "-i", self.target.container, *argv], input=stdin,
            text=True, capture_output=True, timeout=timeout, check=False,
        )
        return completed

    def python(self, program: str, *args: str, secret_input: str | None = None, timeout: int = 60):
        # The fixed program may be visible in argv; protected data is stdin-only.
        return self.run(["python3", "-c", program, *args], stdin=secret_input, timeout=timeout)


BACKUP_PROGRAM = r'''
import hashlib, json, os, pathlib, shutil, sys
root = pathlib.Path(sys.argv[1]); root.mkdir(parents=True, mode=0o700, exist_ok=False)
paths = json.loads(sys.argv[2]); files = []
for name in paths:
    source = pathlib.Path(name); existed = source.exists()
    item = {"path": name, "existed": existed}
    if existed:
        target = root / "files" / name.lstrip("/"); target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)
        if name != "/etc/pam_radius_auth.conf":
            item["sha256"] = hashlib.sha256(source.read_bytes()).hexdigest()
        else:
            item["protected"] = True
        item["mode"] = oct(source.stat().st_mode & 0o777)
    files.append(item)
(root / "manifest.json").write_text(json.dumps({"files": files, "created_users": ["nmas-admin", "nmas-automation", sys.argv[3]]}, sort_keys=True))
os.chmod(root / "manifest.json", 0o600)
print(json.dumps({"files": [{k: x[k] for k in ("path", "existed", "sha256", "protected") if k in x} for x in files]}))
'''


APPLY_PROGRAM = r'''
import json, os, pathlib, pwd, signal, subprocess, sys, tempfile, time
data = json.loads(sys.stdin.read()); trace = []; stage = "ensure_accounts"
class StageCommandError(RuntimeError):
    def __init__(self, returncode): self.returncode = returncode
def event(name, status, return_code=None):
    item = {"stage": name, "status": status, "at": time.time()}
    if isinstance(return_code, int): item["return_code"] = return_code
    trace.append(item)
def operation(name, callback):
    global stage
    stage = name; event(name, "started")
    try: result = callback()
    except Exception as exc:
        event(name, "failed", getattr(exc, "returncode", None)); raise
    event(name, "completed"); return result
def command(argv, *, protected_input=None):
    result = subprocess.run(argv, input=protected_input, text=True, capture_output=True, check=False)
    if result.returncode: raise StageCommandError(result.returncode)
    return result
def atomic(path, value, mode):
    path = pathlib.Path(path); path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp = tempfile.mkstemp(prefix="." + path.name + "-", dir=path.parent)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "w") as handle: fd = None; handle.write(value); handle.flush(); os.fsync(handle.fileno())
        os.replace(temp, path); temp = None
    finally:
        if fd is not None: os.close(fd)
        if temp is not None:
            try: os.unlink(temp)
            except FileNotFoundError: pass
def ensure_user(name):
    try: pwd.getpwnam(name); return False
    except KeyError:
        command(["useradd", "--create-home", "--shell", "/bin/bash", name])
        return True
try:
    created = operation("ensure_accounts", lambda: [ensure_user(name) for name in (data["human"], data["service"], data["breakglass"])])
    factors = f'{data["human"]}:{data["human_local"]}\n{data["breakglass"]}:{data["breakglass_password"]}\n'
    operation("set_local_passwords", lambda: command(["chpasswd"], protected_input=factors)); factors = ""
    operation("lock_service_password", lambda: command(["passwd", "-l", data["service"]]))
    def prepare_ssh():
        home = pathlib.Path(pwd.getpwnam(data["service"]).pw_dir); ssh = home / ".ssh"; ssh.mkdir(mode=0o700, exist_ok=True)
        return ssh
    ssh = operation("prepare_service_ssh_directory", prepare_ssh)
    def install_key():
        atomic(ssh / "authorized_keys", data["public_key"].rstrip() + "\n", 0o600)
        uid = pwd.getpwnam(data["service"]); os.chown(ssh, uid.pw_uid, uid.pw_gid); os.chown(ssh / "authorized_keys", uid.pw_uid, uid.pw_gid)
    operation("install_service_authorized_key", install_key)
    operation("deploy_pam_radius_config", lambda: atomic("/etc/pam_radius_auth.conf", data["radius_line"] + "\n", 0o600))
    operation("deploy_pam_stack", lambda: atomic("/etc/pam.d/sshd", data["pam"], 0o644))
    operation("deploy_sshd_dropin", lambda: atomic("/etc/ssh/sshd_config.d/60-nmas-human-mfa.conf", data["sshd"], 0o644))
    operation("deploy_sudoers_policy", lambda: atomic("/etc/sudoers.d/60-nmas-mfa", data["sudoers"], 0o440))
    operation("validate_sudoers", lambda: command(["visudo", "-cf", "/etc/sudoers.d/60-nmas-mfa"]))
    operation("validate_sshd_config", lambda: command(["sshd", "-t"]))
    def locate_sshd():
        value = command(["pgrep", "-o", "sshd"]).stdout.strip()
        if not value: raise StageCommandError(1)
        return value
    pids = operation("locate_sshd_listener", locate_sshd)
    operation("reload_sshd", lambda: os.kill(int(pids), signal.SIGHUP))
    print(json.dumps({"applied": True, "sshd_valid": True, "users": [data["human"], data["service"], data["breakglass"]], "stage_trace": trace}))
except Exception as exc:
    print(json.dumps({"applied": False, "failed_stage": stage, "return_code": getattr(exc, "returncode", None),
                      "exception_class": exc.__class__.__name__, "stage_trace": trace}))
    raise SystemExit(min(max(getattr(exc, "returncode", 40) or 40, 1), 125))
'''


def backup(transport: DockerTransport, token: str) -> dict:
    if not TOKEN_RE.fullmatch(token):
        raise LinuxMfaError("Invalid rollback token.")
    root = f"/run/nmas-linux-mfa/{transport.target.device.lower()}/{token}"
    result = transport.python(BACKUP_PROGRAM, root, json.dumps(CONFIG_PATHS), transport.target.breakglass_username)
    if result.returncode:
        raise LinuxMfaError("Device-local configuration backup failed.")
    try:
        return {"root": root, **json.loads(result.stdout)}
    except ValueError:
        raise LinuxMfaError("Device-local backup evidence was invalid.") from None


def apply(transport: DockerTransport, provider: FileSecretProvider | None = None) -> dict:
    provider = provider or FileSecretProvider()
    target = transport.target
    try:
        key = DeviceCredential.objects.get(device_name=target.device, username=SERVICE_USERNAME)
        private = provider.current(target.service_key_ref)
        # Parse in memory before target mutation; the private value never leaves this process except to Paramiko later.
        load_ssh_private_key(target.service_key_ref, path=provider.path)
        breakglass = provider.current(target.breakglass_ref)
        radius = private_runtime_value(radius_secret_path(target.device))
    except Exception as exc:
        raise LinuxMfaActivationError(
            stage="resolve_protected_material", return_code=None,
            exception_class="ValueError" if isinstance(exc, DeviceCredential.DoesNotExist) else "RuntimeError",
        ) from None
    data = {
        "human": HUMAN_USERNAME, "service": SERVICE_USERNAME, "breakglass": target.breakglass_username,
        "human_local": secrets.token_urlsafe(48), "breakglass_password": breakglass.value,
        "public_key": key.ssh_public_key,
        "radius_line": f"192.168.200.100:1812 {radius} 3 {target.address}",
        "pam": pam_sshd(), "sshd": sshd_dropin(target), "sudoers": sudoers(target),
    }
    secret_blob = json.dumps(data)
    try:
        result = transport.python(APPLY_PROGRAM, secret_input=secret_blob)
    except (OSError, subprocess.SubprocessError) as exc:
        raise LinuxMfaActivationError(
            stage="invoke_device_activation_helper", return_code=None,
            exception_class=exc.__class__.__name__,
        ) from None
    finally:
        del secret_blob, data, radius, breakglass, private
    try:
        payload = json.loads(result.stdout)
    except ValueError:
        payload = {}
    if result.returncode or not payload.get("applied"):
        stage = payload.get("failed_stage")
        raise LinuxMfaActivationError(
            stage=stage if stage in ACTIVATION_STAGES else (
                "invoke_device_activation_helper" if result.returncode else "decode_activation_diagnostics"
            ),
            return_code=payload.get("return_code"), exception_class=payload.get("exception_class", "ActivationError"),
            stage_trace=payload.get("stage_trace"), helper_return_code=result.returncode,
        )
    payload["stage_trace"] = sanitize_activation_trace(payload.get("stage_trace"))
    return payload


def config_hashes(transport: DockerTransport) -> dict:
    program = r'''
import hashlib, json, pathlib, subprocess, sys
paths=json.loads(sys.argv[1]); out={}
for name in paths:
 p=pathlib.Path(name)
 if name == "/etc/pam_radius_auth.conf": out[name]={"exists": p.exists(), "protected": True}
 else: out[name]={"exists": p.exists(), "sha256": hashlib.sha256(p.read_bytes()).hexdigest() if p.exists() else ""}
out["sshd_valid"] = subprocess.run(["sshd", "-t"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0
print(json.dumps(out))
'''
    completed = transport.python(program, json.dumps(CONFIG_PATHS))
    if completed.returncode:
        raise LinuxMfaError("Could not inspect Linux MFA configuration state.")
    return json.loads(completed.stdout)


def ssh_key_login(target: LinuxMfaTarget) -> dict:
    import paramiko
    client = paramiko.SSHClient(); client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        pkey = load_ssh_private_key(target.service_key_ref)
        client.connect(target.address, username=SERVICE_USERNAME, pkey=pkey, look_for_keys=False, allow_agent=False,
                       timeout=12, auth_timeout=15, banner_timeout=12)
        _stdin, stdout, _stderr = client.exec_command("id -un", timeout=10)
        return {"login": "ACCEPT" if stdout.read().decode().strip() == SERVICE_USERNAME else "ERROR"}
    except paramiko.AuthenticationException:
        return {"login": "REJECT"}
    except Exception as exc:
        return {"login": "ERROR", "error": exc.__class__.__name__}
    finally:
        client.close()


def ssh_password_login(target: LinuxMfaTarget, username: str, password: str, *, privileged: bool = False) -> dict:
    import paramiko
    client = paramiko.SSHClient(); client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(target.address, username=username, password=password, look_for_keys=False, allow_agent=False,
                       timeout=12, auth_timeout=15, banner_timeout=12)
        command = "sudo -n id -u" if privileged else "id -un"
        _stdin, stdout, _stderr = client.exec_command(command, timeout=10)
        output = stdout.read().decode().strip()
        return {"login": "ACCEPT", "privileged": output == "0" if privileged else None}
    except paramiko.AuthenticationException:
        return {"login": "REJECT"}
    except Exception as exc:
        return {"login": "ERROR", "error": exc.__class__.__name__}
    finally:
        client.close()


def ssh_keyboard_login(target: LinuxMfaTarget, response: str) -> dict:
    """One keyboard-interactive attempt; the protected response is never logged."""
    import paramiko, socket
    sock = None; transport = None
    try:
        sock = socket.create_connection((target.address, 22), timeout=12)
        transport = paramiko.Transport(sock); transport.start_client(timeout=12)
        used = False
        def handler(_title, _instructions, prompts):
            nonlocal used
            answers = []
            for _prompt, _echo in prompts:
                answers.append(response if not used else "")
                used = True
            return answers
        transport.auth_interactive(HUMAN_USERNAME, handler)
        if not transport.is_authenticated(): return {"login": "REJECT"}
        channel = transport.open_session(timeout=10); channel.exec_command("sudo -n id -u")
        output = channel.makefile("rb").read().decode().strip()
        return {"login": "ACCEPT", "privileged": output == "0"}
    except paramiko.AuthenticationException:
        return {"login": "REJECT"}
    except Exception as exc:
        return {"login": "ERROR", "error": exc.__class__.__name__}
    finally:
        if transport is not None: transport.close()
        elif sock is not None: sock.close()


def timer_unit(device: str, token: str) -> str:
    if device not in TARGETS or not TOKEN_RE.fullmatch(token):
        raise LinuxMfaError("Invalid rollback timer identity.")
    return f"nmas-linux-mfa-{device.lower()}-{token}"


def arm_timer(device: str, token: str, *, runner=subprocess.run, seconds: int = ROLLBACK_SECONDS) -> str:
    unit = timer_unit(device, token)
    script = Path(settings.REPO_ROOT) / "monitoring" / "scripts" / "linux_mfa_rollback.py"
    argv = ["systemd-run", "--user", f"--unit={unit}", f"--on-active={seconds}s", "--collect",
            "/usr/bin/python3", str(script), "--device", device, "--token", token]
    completed = runner(argv, capture_output=True, text=True, timeout=20, check=False)
    if completed.returncode:
        raise LinuxMfaError("Host-side automatic rollback timer could not be armed.")
    return unit


def timer_active(device: str, token: str, *, runner=subprocess.run) -> bool:
    unit = timer_unit(device, token) + ".timer"
    return runner(["systemctl", "--user", "is-active", "--quiet", unit], timeout=10, check=False).returncode == 0


def cancel_timer(device: str, token: str, *, runner=subprocess.run) -> None:
    unit = timer_unit(device, token) + ".timer"
    completed = runner(["systemctl", "--user", "stop", unit], capture_output=True, text=True, timeout=20, check=False)
    if completed.returncode:
        raise LinuxMfaError("Automatic rollback timer could not be canceled.")
