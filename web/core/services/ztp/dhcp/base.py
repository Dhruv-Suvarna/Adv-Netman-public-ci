"""The DHCP provider contract: provider-neutral bootstrap policy in, provider configuration / state / leases out.

A provider never decides who may bootstrap: ``policy.build_policy`` turns open ZTP sessions with approved Phase 2 authorizations
into ``Reservation`` rows, each bound to ONE trusted relay port (giaddr + option 82 circuit id).  The provider renders exactly
that -- one class-scoped single-address pool per reservation and no dynamic pool -- so an unauthorized device on the bootstrap
network gets no lease at all.  DHCP never authenticates identity: the lease is evidence, the delivery decision is separate.

Safety: a provider writes only its own isolated ``config_root`` (never ``/etc/dhcp``, the production lease database or a
production service, and only under ``provider_roots()``), validates every candidate with the provider's own parser before
applying it, keeps the previous configuration for recovery and reads the applied state back -- a candidate whose read-back
fails is replaced by the previous configuration again, so FAILED always means "previous configuration kept".
"""

from __future__ import annotations

import hashlib
import os
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

SAFE_VALUE = re.compile(r"^[A-Za-z0-9 ._:/;=+,@%~?&#-]{0,255}$")
FORBIDDEN_ROOTS = ("/etc", "/var/lib/dhcp", "/var/lib/kea", "/run", "/var/run", "/usr", "/bin", "/sbin", "/boot", "/proc", "/sys")


class ProviderError(Exception):
    """A provider refusal or failure with a stable code and bounded detail (never raw secrets)."""

    def __init__(self, code: str, detail: str = ""):
        super().__init__(code)
        self.code = code
        self.detail = str(detail)[:2000]


@dataclass(frozen=True)
class Reservation:
    session_id: str
    device: str
    address: str
    relay_address: str               # trusted relay (giaddr) on the authorized upstream
    circuit_id: str                  # the authorized upstream interface, as option 82 circuit id
    vendor_class_prefix: str = ""    # adapter-selected option 60 prefix ('' = none)
    options: tuple = ()              # adapter-selected ((name, value), ...)


@dataclass(frozen=True)
class BootstrapPolicy:
    network: str
    subnet: str                      # e.g. 10.254.30.0/24
    gateway: str
    service_prefix: str
    reservations: tuple = ()
    lease_seconds: int = 600

    def as_dict(self) -> dict:
        return {"network": self.network, "subnet": self.subnet, "gateway": self.gateway, "service_prefix": self.service_prefix,
                "lease_seconds": self.lease_seconds, "reservations": [r.__dict__ for r in self.reservations]}


@dataclass
class ApplyResult:
    ok: bool
    state: str                       # VALIDATED / APPLIED / FAILED / ROLLED_BACK
    config_text: str
    config_sha256: str
    previous_sha256: str = ""
    validation: dict = field(default_factory=dict)
    read_back: dict = field(default_factory=dict)
    code: str = ""


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def check_value(value: str) -> str:
    """Refuse anything that could break out of a quoted provider value."""
    text = str(value)
    if not SAFE_VALUE.fullmatch(text) or '"' in text or "\\" in text:
        raise ProviderError("DHCP_PROVIDER_ERROR", "an option value contains characters NMAS never renders")
    return text


def provider_roots() -> list[Path]:
    """The only directories a provider directory may live under: Django setting ``NMAS_ZTP_PROVIDER_ROOTS``, by default the
    disposable fixture runtime (``labs/ztp-isolated/runtime``) and ``web/var/ztp``.  An operator-entered path anywhere else (a
    checkout, a home directory, another service's data) is refused even when it is not a system location."""
    from django.conf import settings

    configured = getattr(settings, "NMAS_ZTP_PROVIDER_ROOTS", None)
    if configured is None:
        configured = (Path(settings.REPO_ROOT) / "labs" / "ztp-isolated" / "runtime", Path(settings.BASE_DIR) / "var" / "ztp")
    return [Path(os.path.realpath(str(root))) for root in configured if str(root or "").strip()]


def safe_root(config_root: str) -> Path:
    """The isolated provider directory, refusing system / production locations, anything outside ``provider_roots()`` and
    symlinks."""
    text = str(config_root or "")
    if not text or not os.path.isabs(text) or ".." in Path(text).parts:
        raise ProviderError("DHCP_CONFIG_ROOT_UNSAFE", "an absolute isolated directory is required")
    resolved = os.path.realpath(text)
    for forbidden in FORBIDDEN_ROOTS:
        if resolved == forbidden or resolved.startswith(forbidden + "/"):
            raise ProviderError("DHCP_CONFIG_ROOT_UNSAFE", "system and production DHCP locations are never written")
    if not any(resolved == str(root) or resolved.startswith(str(root) + "/") for root in provider_roots()):
        raise ProviderError("DHCP_CONFIG_ROOT_UNSAFE", "the directory is outside the configured NMAS ZTP provider roots")
    path = Path(text)
    if path.is_symlink() or (path.exists() and not path.is_dir()):
        raise ProviderError("DHCP_CONFIG_ROOT_UNSAFE", "the configuration root must be a real directory")
    return path


def atomic_write(path: Path, text: str) -> None:
    tmp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    with open(tmp, "w", encoding="utf-8") as handle:
        handle.write(text)
        handle.flush()
        os.fsync(handle.fileno())
    os.chmod(tmp, 0o644)
    os.replace(tmp, path)


def run_command(argv: list[str], timeout: int = 30) -> tuple[int, str]:
    """Run a fixed argv (never a shell) -> (returncode, bounded output)."""
    try:
        done = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, check=False, shell=False)  # noqa: S603
    except (OSError, subprocess.SubprocessError) as exc:
        return 127, f"{type(exc).__name__}"
    return done.returncode, (done.stdout + done.stderr)[-2000:]


class DhcpProvider:
    """The provider contract.  ``runner(argv) -> (rc, output)`` executes validation / status commands (injected in tests)."""

    kind = ""
    config_name = ""
    operational = False               # True only when apply + read-back + lease observation are implemented

    def __init__(self, config_root: str, *, validate_command=None, status_command=None, runner=run_command):
        self.config_root = config_root
        self.validate_command = list(validate_command or [])
        self.status_command = list(status_command or [])
        self.runner = runner

    # contract
    def render(self, policy: BootstrapPolicy) -> str:
        raise NotImplementedError

    def validate(self, text: str) -> dict:
        raise NotImplementedError

    def apply(self, policy: BootstrapPolicy) -> ApplyResult:
        raise ProviderError("DHCP_PROVIDER_UNSUPPORTED", f"{self.kind} apply is not implemented")

    def rollback(self) -> ApplyResult:
        raise ProviderError("DHCP_PROVIDER_UNSUPPORTED", f"{self.kind} recovery is not implemented")

    def read_back(self) -> dict:
        raise ProviderError("DHCP_PROVIDER_UNSUPPORTED", f"{self.kind} read-back is not implemented")

    def parse_leases(self, text: str) -> list[dict]:
        raise NotImplementedError

    # shared validation step: write the candidate inside the isolated root and run the provider's own parser on it
    def _validate_file(self, text: str, candidate_name: str) -> dict:
        root = safe_root(self.config_root)
        root.mkdir(parents=True, exist_ok=True)
        candidate = root / candidate_name
        atomic_write(candidate, text)
        if not self.validate_command:
            return {"ok": False, "validator": "", "output": "no provider validator is configured: nothing is applied unvalidated"}
        argv = [part.replace("{path}", str(candidate)).replace("{name}", candidate_name) for part in self.validate_command]
        rc, output = self.runner(argv)
        return {"ok": rc == 0, "validator": " ".join(self.validate_command[:3]), "returncode": rc, "output": output[-1500:]}
