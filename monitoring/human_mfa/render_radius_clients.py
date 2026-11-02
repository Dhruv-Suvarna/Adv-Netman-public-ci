#!/usr/bin/env python3
"""Render protected FreeRADIUS clients for explicitly selected managed devices.

Only device names are accepted on argv. Shared secrets are read from private
runtime files and written atomically to the ignored runtime clients.conf; they
are never printed, returned, logged, or placed in the environment.
"""
from __future__ import annotations

import argparse
import os
import tempfile
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
INVENTORY = REPO_ROOT / "inventory.yml"
RUNTIME = REPO_ROOT / "monitoring" / "runtime" / "human-mfa"
CEOS_ELIGIBLE = ("R1", "R2", "S1", "S2", "S3", "S4", "mgmt_swt")
LINUX_ELIGIBLE = ("R3", "R4")
ELIGIBLE = (*CEOS_ELIGIBLE, *LINUX_ELIGIBLE)


class RadiusClientError(RuntimeError):
    pass


def _private_secret(path: Path) -> str:
    try:
        stat = path.lstat()
    except FileNotFoundError:
        raise RadiusClientError(f"Protected RADIUS secret is missing for {path.name}.") from None
    if path.is_symlink() or not path.is_file() or stat.st_mode & 0o077:
        raise RadiusClientError(f"Protected RADIUS secret file is unsafe for {path.name}.")
    value = path.read_text(encoding="utf-8").strip()
    if not value or any(ch.isspace() for ch in value):
        raise RadiusClientError(f"Protected RADIUS secret is invalid for {path.name}.")
    return value


def client_addresses(inventory_path: Path = INVENTORY) -> dict[str, str]:
    try:
        inventory = yaml.safe_load(inventory_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, yaml.YAMLError):
        raise RadiusClientError("Inventory is unavailable or invalid.") from None
    result = {}
    for device in ELIGIBLE:
        entry = (inventory.get("network_devices") or {}).get(device) or {}
        monitoring = entry.get("monitoring") or {}
        expected = "linux" if device in LINUX_ELIGIBLE else "ceos"
        if monitoring.get("platform") != expected:
            label = "Linux" if expected == "linux" else "cEOS"
            raise RadiusClientError(f"{device} is not {label} in inventory.")
        address = monitoring.get("address")
        if not isinstance(address, str) or not address or address == "auto":
            raise RadiusClientError(f"{device} has no static management address.")
        result[device] = address
    return result


def render(devices: list[str], *, inventory_path: Path = INVENTORY, secret_root: Path | None = None) -> str:
    if not devices or len(set(devices)) != len(devices):
        raise RadiusClientError("Select one or more unique devices.")
    unknown = sorted(set(devices) - set(ELIGIBLE))
    if unknown:
        raise RadiusClientError(f"Devices are outside the reviewed cEOS MFA scope: {unknown}")
    addresses = client_addresses(inventory_path)
    root = secret_root or (RUNTIME / "secrets")
    blocks = ["# Generated from inventory + protected runtime secrets. Do not commit.\n"]
    for device in ELIGIBLE:  # stable order, independent of caller ordering
        if device not in devices:
            continue
        secret = _private_secret(root / f"radius_{device.lower()}_secret")
        blocks.append(f"client {device} {{\n    ipaddr = {addresses[device]}\n    secret = {secret}\n}}\n")
    fixture = _private_secret(root / "radius_fixture_secret")
    blocks.append(f"client local_fixture {{\n    ipaddr = 127.0.0.1\n    secret = {fixture}\n}}\n")
    return "\n".join(blocks)


def write_atomic(text: str, destination: Path) -> None:
    destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    destination.parent.chmod(0o700)
    fd = None
    temporary = None
    try:
        fd, temporary = tempfile.mkstemp(prefix=".clients-", dir=destination.parent)
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            fd = None
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, destination)
        temporary = None
        destination.chmod(0o600)
    finally:
        if fd is not None:
            os.close(fd)
        if temporary is not None:
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--device", action="append", required=True, dest="devices")
    parser.add_argument("--output", type=Path, default=RUNTIME / "freeradius" / "clients.conf")
    args = parser.parse_args()
    try:
        text = render(args.devices)
        write_atomic(text, args.output)
    except RadiusClientError as exc:
        parser.error(str(exc))
    print("Rendered protected RADIUS clients for: " + ", ".join(args.devices))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
