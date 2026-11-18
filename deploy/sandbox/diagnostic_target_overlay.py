#!/usr/bin/env python3
"""Apply one reviewed, additive diagnostic target without rebuilding its namespace.

The base namespace controller remains the owner of the namespace, veth and nft
tables.  This helper may add only exact TCP/22 target tuples and matching host
routes.  It records a root-only receipt bound to the active base activation so
the controller can validate the combined policy without weakening its normal
exact-set checks.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile


SCHEMA = "nmas.diagnostic-target-overlay/1"
RECEIPT_SCHEMA = "nmas.diagnostic-target-overlay-receipt/1"
BASE_CONFIG = Path("/etc/nmas/diagnostic-namespace.env")
BASE_STATE = Path("/var/lib/nmas-ts-namespaces/diagnostic.json")
RECEIPT = Path("/var/lib/nmas-ts-namespaces/diagnostic-target-overlay.json")
NAMESPACE = "nmas-ts-diagnostic"
NS_TABLE = "nmas_diagnostic"
HOST_TABLE = "nmas_host_diagnostic"
INTERFACE = "nmas-ts-diag0"
ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:/@-]{7,127}$")


class Refused(RuntimeError):
    pass


def _read_json(path: Path, *, mode: int) -> dict:
    info = path.lstat()
    if (path.is_symlink() or not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_gid != 0
            or stat.S_IMODE(info.st_mode) != mode):
        raise Refused(f"{path} must be a root-owned mode-{mode:04o} regular file")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise Refused(f"{path} must contain an object")
    return value


def _base_values() -> dict[str, str]:
    info = BASE_CONFIG.lstat()
    if BASE_CONFIG.is_symlink() or not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
        raise Refused("base diagnostic configuration is not protected")
    values: dict[str, str] = {}
    for raw in BASE_CONFIG.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if line and not line.startswith("#") and "=" in line:
            key, value = line.split("=", 1)
            values[key.strip()] = value.strip()
    return values


def _policy(path: Path) -> tuple[dict, str]:
    raw = path.read_bytes()
    value = _read_json(path, mode=0o600)
    if set(value) != {"schema", "overlay_id", "base_activation_id", "base_config_digest",
                     "authorization_id", "expires_at", "targets"} or value["schema"] != SCHEMA:
        raise Refused("overlay policy schema is invalid")
    for key in ("overlay_id", "base_activation_id", "authorization_id"):
        if not isinstance(value[key], str) or not ID_RE.fullmatch(value[key]):
            raise Refused(f"invalid {key}")
    if not re.fullmatch(r"[0-9a-f]{64}", str(value["base_config_digest"])):
        raise Refused("invalid base_config_digest")
    try:
        expires = datetime.fromisoformat(str(value["expires_at"]).replace("Z", "+00:00"))
    except ValueError as exc:
        raise Refused("invalid expires_at") from exc
    if expires.tzinfo is None or expires.astimezone(timezone.utc) <= datetime.now(timezone.utc):
        raise Refused("overlay authorization is expired")
    targets = value["targets"]
    if not isinstance(targets, list) or not 1 <= len(targets) <= 16:
        raise Refused("overlay needs one to sixteen exact targets")
    normalized = []
    for item in targets:
        if not isinstance(item, dict) or set(item) != {"address", "port"} or item.get("port") != 22:
            raise Refused("only exact TCP/22 targets are supported")
        address = ipaddress.ip_address(str(item["address"]))
        if address.version != 4 or address.is_loopback or address.is_multicast or address.is_unspecified:
            raise Refused("overlay target must be an exact unicast IPv4 address")
        normalized.append({"address": str(address), "port": 22})
    if len({item["address"] for item in normalized}) != len(normalized):
        raise Refused("duplicate overlay target")
    value["targets"] = normalized
    return value, hashlib.sha256(raw).hexdigest()


def _run(*argv: str, capture: bool = False, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(argv, text=True, capture_output=capture, check=check)


def _base(policy: dict) -> tuple[dict, str]:
    state = _read_json(BASE_STATE, mode=0o600)
    values = _base_values()
    if (state.get("status") != "active" or state.get("namespace") != NAMESPACE
            or state.get("activation_id") != policy["base_activation_id"]
            or state.get("config_digest") != policy["base_config_digest"]
            or values.get("ACTIVATION_ID") != policy["base_activation_id"]):
        raise Refused("overlay is not bound to the active base namespace")
    gateway = values.get("IPV4_GATEWAY", "")
    ipaddress.IPv4Address(gateway)
    return state, gateway


def _elements(table: str) -> set[str]:
    result = _run("nft", "-j", "list", "set", "inet", table, "targets4", capture=True)
    data = json.loads(result.stdout)
    found: set[str] = set()
    for obj in data.get("nftables", []):
        for elem in obj.get("set", {}).get("elem", []):
            if isinstance(elem, dict) and isinstance(elem.get("concat"), list) and len(elem["concat"]) == 2:
                found.add(f"{ipaddress.ip_address(elem['concat'][0])}:{int(elem['concat'][1])}")
    return found


def _ns_elements() -> set[str]:
    result = _run("ip", "netns", "exec", NAMESPACE, "nft", "-j", "list", "set", "inet", NS_TABLE,
                  "targets4", capture=True)
    data = json.loads(result.stdout)
    found: set[str] = set()
    for obj in data.get("nftables", []):
        for elem in obj.get("set", {}).get("elem", []):
            if isinstance(elem, dict) and isinstance(elem.get("concat"), list) and len(elem["concat"]) == 2:
                found.add(f"{ipaddress.ip_address(elem['concat'][0])}:{int(elem['concat'][1])}")
    return found


def _routes() -> set[str]:
    result = _run("ip", "-j", "-n", NAMESPACE, "-4", "route", "show", capture=True)
    return {str(row.get("dst")) for row in json.loads(result.stdout) if row.get("gateway")}


def _atomic_receipt(value: dict) -> None:
    RECEIPT.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix=".diagnostic-overlay-", dir=RECEIPT.parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            fd = -1
            json.dump(value, stream, sort_keys=True, separators=(",", ":"))
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, RECEIPT)
        name = ""
    finally:
        if fd >= 0:
            os.close(fd)
        if name:
            try:
                os.unlink(name)
            except FileNotFoundError:
                pass


def validate(policy: dict, digest: str) -> dict:
    _state, gateway = _base(policy)
    base_targets = {item.removeprefix("tcp:").replace(":22", ":22")
                    for item in _base_values().get("TARGETS", "").split()}
    overlay = {f"{item['address']}:22" for item in policy["targets"]}
    expected = base_targets | overlay
    if _elements(HOST_TABLE) != expected or _ns_elements() != expected:
        raise Refused("diagnostic nft target sets differ from base plus overlay policy")
    expected_routes = {item.rsplit(":", 1)[0] for item in expected}
    if _routes() != expected_routes:
        raise Refused("diagnostic namespace routes differ from base plus overlay policy")
    receipt = _read_json(RECEIPT, mode=0o600)
    if (receipt.get("schema") != RECEIPT_SCHEMA or receipt.get("status") != "active"
            or receipt.get("policy_sha256") != digest or receipt.get("base_config_digest") != policy["base_config_digest"]
            or receipt.get("targets") != policy["targets"] or receipt.get("gateway") != gateway):
        raise Refused("diagnostic overlay receipt does not match policy")
    return {"status": "active", "overlay_id": policy["overlay_id"], "targets": len(overlay)}


def apply(policy: dict, digest: str) -> dict:
    _state, gateway = _base(policy)
    additions = [item["address"] for item in policy["targets"]]
    try:
        for address in additions:
            key = f"{address}:22"
            if key not in _elements(HOST_TABLE):
                _run("nft", "add", "element", "inet", HOST_TABLE, "targets4", "{", f"{address} . 22", "}")
            if key not in _ns_elements():
                _run("ip", "netns", "exec", NAMESPACE, "nft", "add", "element", "inet", NS_TABLE,
                     "targets4", "{", f"{address} . 22", "}")
            if address not in _routes():
                _run("ip", "-n", NAMESPACE, "route", "add", f"{address}/32", "via", gateway, "dev", INTERFACE)
        _atomic_receipt({"schema": RECEIPT_SCHEMA, "status": "active", "overlay_id": policy["overlay_id"],
                         "authorization_id": policy["authorization_id"], "base_activation_id": policy["base_activation_id"],
                         "base_config_digest": policy["base_config_digest"], "policy_sha256": digest,
                         "targets": policy["targets"], "gateway": gateway, "expires_at": policy["expires_at"],
                         "applied_at": datetime.now(timezone.utc).isoformat()})
        return validate(policy, digest)
    except Exception:
        for address in reversed(additions):
            _run("ip", "-n", NAMESPACE, "route", "del", f"{address}/32", check=False)
            _run("ip", "netns", "exec", NAMESPACE, "nft", "delete", "element", "inet", NS_TABLE,
                 "targets4", "{", f"{address} . 22", "}", check=False)
            _run("nft", "delete", "element", "inet", HOST_TABLE, "targets4", "{", f"{address} . 22", "}", check=False)
        raise


def rollback(policy: dict, digest: str) -> dict:
    _base(policy)
    for item in reversed(policy["targets"]):
        address = item["address"]
        _run("ip", "-n", NAMESPACE, "route", "del", f"{address}/32", check=False)
        _run("ip", "netns", "exec", NAMESPACE, "nft", "delete", "element", "inet", NS_TABLE,
             "targets4", "{", f"{address} . 22", "}", check=False)
        _run("nft", "delete", "element", "inet", HOST_TABLE, "targets4", "{", f"{address} . 22", "}", check=False)
    _atomic_receipt({"schema": RECEIPT_SCHEMA, "status": "rolled_back", "overlay_id": policy["overlay_id"],
                     "base_config_digest": policy["base_config_digest"], "policy_sha256": digest,
                     "targets": policy["targets"], "rolled_back_at": datetime.now(timezone.utc).isoformat()})
    return {"status": "rolled_back", "overlay_id": policy["overlay_id"]}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("apply", "validate", "rollback"))
    parser.add_argument("policy", type=Path)
    args = parser.parse_args()
    policy, digest = _policy(args.policy)
    result = {"apply": apply, "validate": validate, "rollback": rollback}[args.action](policy, digest)
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, json.JSONDecodeError, subprocess.CalledProcessError, Refused) as exc:
        print(json.dumps({"status": "refused", "reason": type(exc).__name__}), file=os.sys.stderr)
        raise SystemExit(2)
