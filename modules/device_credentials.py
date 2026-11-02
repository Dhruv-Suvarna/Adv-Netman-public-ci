"""Protected runtime storage for managed-device passwords.

Only opaque ``runtime://device-credentials/<key>`` references belong in Git
or Django.  Secret values (passwords and SSH private keys) live in a regular
mode-0600 JSON file inside a dedicated mode-0700 directory under the
already-ignored ``monitoring/runtime`` tree.  This is intentionally not
encryption: filesystem protection is the lab's existing secret boundary.
The shared ``monitoring/runtime`` directory itself is never re-permissioned
(Grafana / InfluxDB bind-mount their own subdirectories from it).

Every read-modify-write holds an exclusive ``fcntl`` lock on a sibling lock
file, so the rotation scheduler and an operator import cannot interleave.

Rotation uses a two-slot record.  ``stage`` durably records a replacement
before a device is touched; ``promote`` atomically makes that verified value
current.  If a process dies between those operations, both current and
pending candidates remain available for explicit recovery.
"""
from __future__ import annotations

import fcntl
import json
import os
import re
import secrets
import tempfile
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any


BASE = Path(__file__).resolve().parents[1]
DEFAULT_STORE = BASE / "monitoring" / "runtime" / "device-credentials" / "store.json"
REFERENCE_PREFIX = "runtime://device-credentials/"
_KEY_RE = re.compile(r"[a-z0-9][a-z0-9_.-]{2,63}")


class SecretProviderError(RuntimeError):
    """A sanitized provider failure; messages never contain secret values."""


class SecretNotFound(SecretProviderError):
    pass


class SecretConflict(SecretProviderError):
    pass


@dataclass(frozen=True)
class SecretMaterial:
    version: str
    value: str


@dataclass(frozen=True)
class CeosAccessProfile:
    """Non-secret, device-specific account references for one cEOS device."""

    username: str
    credential_ref: str
    ssh_key_ref: str = ""


@dataclass(frozen=True)
class LinuxAccessProfile:
    """Non-secret public-key machine identity for an Ubuntu/FRR target."""

    username: str
    ssh_key_ref: str


def linux_access_profile(inventory: dict, device_name: str) -> LinuxAccessProfile:
    entry = (inventory.get("network_devices") or {}).get(device_name) or {}
    monitoring = entry.get("monitoring") or {}
    if monitoring.get("platform") != "linux":
        raise SecretProviderError("Linux automation profile requested for a non-Linux target.")
    username = entry.get("username")
    key_reference = entry.get("ssh_key_ref")
    if not isinstance(username, str) or not username:
        raise SecretProviderError("Linux automation username is not configured.")
    reference_key(key_reference)
    return LinuxAccessProfile(username=username, ssh_key_ref=key_reference)


def ceos_access_profile(inventory: dict, device_name: str) -> CeosAccessProfile:
    """Resolve one device's dedicated automation identity; never a fleet fallback."""
    devices = inventory.get("network_devices") or {}
    entry = devices.get(device_name) or {}
    username = entry.get("username")
    credential_ref = entry.get("credential_ref")
    ssh_key_ref = entry.get("ssh_key_ref") or ""
    if not isinstance(username, str) or not username:
        raise SecretProviderError("cEOS automation username is not configured.")
    reference_key(credential_ref)
    if ssh_key_ref:
        reference_key(ssh_key_ref)
    return CeosAccessProfile(username=username, credential_ref=credential_ref, ssh_key_ref=ssh_key_ref)


def ceos_access_profiles(inventory: dict, device_name: str) -> tuple[CeosAccessProfile, ...]:
    """Compatibility tuple containing only the dedicated device identity."""
    return (ceos_access_profile(inventory, device_name),)


def reference_key(reference: str) -> str:
    if not isinstance(reference, str) or not reference.startswith(REFERENCE_PREFIX):
        raise SecretProviderError("Unsupported device credential reference.")
    key = reference.removeprefix(REFERENCE_PREFIX)
    if not _KEY_RE.fullmatch(key):
        raise SecretProviderError("Invalid device credential reference key.")
    return key


def make_reference(key: str) -> str:
    if not _KEY_RE.fullmatch(str(key)):
        raise SecretProviderError("Invalid device credential reference key.")
    return f"{REFERENCE_PREFIX}{key}"


class FileSecretProvider:
    """Atomic file-backed provider using the project's runtime-secret policy."""

    schema_version = 1

    def __init__(self, path: Path | str | None = None):
        # Resolved at call time so tests / tooling can redirect DEFAULT_STORE.
        self.path = Path(path) if path is not None else DEFAULT_STORE

    def _empty(self) -> dict[str, Any]:
        return {"schema_version": self.schema_version, "secrets": {}}

    def _load(self, *, allow_missing: bool = False) -> dict[str, Any]:
        if not self.path.exists():
            if allow_missing:
                return self._empty()
            raise SecretProviderError("Device credential store is not initialized.")
        try:
            stat = self.path.lstat()
        except OSError as exc:
            raise SecretProviderError("Device credential store cannot be inspected.") from exc
        if self.path.is_symlink() or not self.path.is_file() or stat.st_mode & 0o077:
            raise SecretProviderError("Device credential store must be a regular mode-0600 file.")
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise SecretProviderError("Device credential store is unreadable or invalid.") from exc
        if data.get("schema_version") != self.schema_version or not isinstance(data.get("secrets"), dict):
            raise SecretProviderError("Device credential store schema is invalid.")
        return data

    def _ensure_directory(self) -> None:
        try:
            self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            if self.path.parent.is_symlink():
                raise SecretProviderError("Device credential store directory must not be a symlink.")
            self.path.parent.chmod(0o700)
        except OSError as exc:
            raise SecretProviderError("Device credential store directory cannot be protected.") from exc

    @contextmanager
    def _locked(self):
        """Exclusive advisory lock held across one load-modify-write."""
        self._ensure_directory()
        lock_path = self.path.with_name(self.path.name + ".lock")
        try:
            fd = os.open(lock_path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        except OSError as exc:
            raise SecretProviderError("Device credential store lock cannot be opened.") from exc
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            yield
        finally:
            try:
                fcntl.flock(fd, fcntl.LOCK_UN)
            finally:
                os.close(fd)

    def _write(self, data: dict[str, Any]) -> None:
        self._ensure_directory()
        fd = None
        tmp_name = None
        try:
            fd, tmp_name = tempfile.mkstemp(prefix=".device-credentials-", dir=self.path.parent)
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                fd = None
                json.dump(data, handle, sort_keys=True, separators=(",", ":"))
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp_name, self.path)
            tmp_name = None
            self.path.chmod(0o600)
            directory_fd = os.open(self.path.parent, os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        except OSError as exc:
            raise SecretProviderError("Device credential store update failed.") from exc
        finally:
            if fd is not None:
                os.close(fd)
            if tmp_name is not None:
                try:
                    os.unlink(tmp_name)
                except FileNotFoundError:
                    pass

    @staticmethod
    def _material(raw: Any, label: str) -> SecretMaterial:
        if not isinstance(raw, dict) or not isinstance(raw.get("version"), str) or not isinstance(raw.get("value"), str):
            raise SecretProviderError(f"Device credential {label} record is invalid.")
        if not raw["version"] or not raw["value"]:
            raise SecretProviderError(f"Device credential {label} record is empty.")
        return SecretMaterial(version=raw["version"], value=raw["value"])

    def initialize(self, reference: str, value: str, *, replace: bool = False) -> str:
        """Import a value from a protected caller (normally an environment variable)."""
        key = reference_key(reference)
        if not isinstance(value, str) or not value:
            raise SecretProviderError("Initial device credential is empty.")
        with self._locked():
            data = self._load(allow_missing=True)
            existing = data["secrets"].get(key)
            if existing is not None and not replace:
                raise SecretConflict("Device credential reference already exists.")
            if isinstance(existing, dict) and existing.get("pending") is not None:
                raise SecretConflict("Device credential has an unresolved pending replacement; reconcile it first.")
            version = secrets.token_hex(12)
            data["secrets"][key] = {"current": {"version": version, "value": value}, "pending": None}
            self._write(data)
        return version

    def has_pending(self, reference: str) -> bool:
        key = reference_key(reference)
        record = self._load()["secrets"].get(key)
        if not isinstance(record, dict):
            raise SecretNotFound("Device credential reference is not present.")
        return record.get("pending") is not None

    def current(self, reference: str) -> SecretMaterial:
        key = reference_key(reference)
        record = self._load()["secrets"].get(key)
        if not isinstance(record, dict):
            raise SecretNotFound("Device credential reference is not present.")
        return self._material(record.get("current"), "current")

    def candidates(self, reference: str) -> tuple[SecretMaterial, ...]:
        """Return current then pending, de-duplicated, for recovery-aware login."""
        key = reference_key(reference)
        record = self._load()["secrets"].get(key)
        if not isinstance(record, dict):
            raise SecretNotFound("Device credential reference is not present.")
        values = [self._material(record.get("current"), "current")]
        if record.get("pending") is not None:
            values.append(self._material(record["pending"], "pending"))
        seen: set[str] = set()
        return tuple(item for item in values if not (item.version in seen or seen.add(item.version)))

    def stage(self, reference: str, value: str) -> tuple[str, str]:
        key = reference_key(reference)
        if not isinstance(value, str) or not value:
            raise SecretProviderError("Replacement device credential is empty.")
        with self._locked():
            data = self._load()
            record = data["secrets"].get(key)
            if not isinstance(record, dict):
                raise SecretNotFound("Device credential reference is not present.")
            current = self._material(record.get("current"), "current")
            if record.get("pending") is not None:
                raise SecretConflict("Device credential already has a pending replacement.")
            version = secrets.token_hex(12)
            record["pending"] = {"version": version, "value": value}
            self._write(data)
        return current.version, version

    def pending(self, reference: str, version: str | None = None) -> SecretMaterial:
        key = reference_key(reference)
        record = self._load()["secrets"].get(key)
        if not isinstance(record, dict) or record.get("pending") is None:
            raise SecretNotFound("Device credential has no pending replacement.")
        material = self._material(record["pending"], "pending")
        if version is not None and material.version != version:
            raise SecretConflict("Pending device credential version changed.")
        return material

    def promote(self, reference: str, version: str) -> tuple[str, str]:
        key = reference_key(reference)
        with self._locked():
            data = self._load()
            record = data["secrets"].get(key)
            if not isinstance(record, dict):
                raise SecretNotFound("Device credential reference is not present.")
            current = self._material(record.get("current"), "current")
            pending = self._material(record.get("pending"), "pending")
            if pending.version != version:
                raise SecretConflict("Pending device credential version changed.")
            record["current"] = dict(record["pending"])
            record["pending"] = None
            self._write(data)
        return current.version, pending.version

    def discard_pending(self, reference: str, version: str) -> None:
        key = reference_key(reference)
        with self._locked():
            data = self._load()
            record = data["secrets"].get(key)
            if not isinstance(record, dict) or record.get("pending") is None:
                return
            pending = self._material(record["pending"], "pending")
            if pending.version != version:
                raise SecretConflict("Pending device credential version changed.")
            record["pending"] = None
            self._write(data)

    def retire(self, reference: str, version: str) -> str:
        """Permanently remove ``reference`` (V2 Phase 4: a retired bootstrap credential).

        Only the exact ``version`` the caller verified is removed, and never while a pending replacement exists (that would
        lose an in-flight rotation).  Afterwards ``current(reference)`` raises ``SecretNotFound`` -- the caller proves the
        retirement with that read, not by trusting this call.  Returns the retired version.
        """
        key = reference_key(reference)
        with self._locked():
            data = self._load()
            record = data["secrets"].get(key)
            if not isinstance(record, dict):
                raise SecretNotFound("Device credential reference is not present.")
            current = self._material(record.get("current"), "current")
            if record.get("pending") is not None:
                raise SecretConflict("Device credential has a pending replacement; it cannot be retired.")
            if current.version != version:
                raise SecretConflict("Device credential version changed.")
            del data["secrets"][key]
            self._write(data)
        return current.version


def load_password_candidates(reference: str, *, path: Path | str | None = None) -> tuple[str, ...]:
    """Small consumer API used by legacy scripts; values must never be logged."""
    return tuple(item.value for item in FileSecretProvider(path).candidates(reference))


def load_ssh_private_key(reference: str, *, path: Path | str | None = None):
    """Return the current SSH private key for ``reference`` as an in-memory paramiko key.

    The key never touches disk outside the protected store; parse failures are
    sanitized so a malformed record cannot echo key material into a traceback.
    """
    import io

    import paramiko

    value = FileSecretProvider(path).current(reference).value
    for key_class in (paramiko.Ed25519Key, paramiko.ECDSAKey, paramiko.RSAKey):
        try:
            return key_class.from_private_key(io.StringIO(value))
        except (paramiko.SSHException, ValueError):
            continue
    raise SecretProviderError("Device SSH key record is not a supported unencrypted private key.")


def ssh_auth_kwargs(key_reference: str | None, *, path: Path | str | None = None) -> dict:
    """Netmiko kwargs presenting the SSH possession factor, or ``{}`` if none is enrolled."""
    if not key_reference:
        return {}
    return {"use_keys": True, "pkey": load_ssh_private_key(key_reference, path=path), "allow_agent": False}
