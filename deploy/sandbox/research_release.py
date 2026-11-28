#!/usr/bin/env python3
"""Validate the complete content-addressed Stage B research activation set."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import re
import stat
from pathlib import Path
from types import SimpleNamespace


SCHEMA = "nmas.stage-b-research-release/1"
SHA256 = re.compile(r"^[0-9a-f]{64}$")


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def load_regular(path: Path) -> bytes:
    info = path.lstat()
    if path.is_symlink() or not stat.S_ISREG(info.st_mode):
        raise ValueError(f"unsafe release input: {path}")
    return path.read_bytes()


def parse_env(data: bytes) -> dict[str, str]:
    result: dict[str, str] = {}
    for raw in data.decode("utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        key, separator, value = line.partition("=")
        if not separator or key in result:
            raise ValueError("invalid release environment")
        result[key] = value
    return result


def controller_policy(root: Path, config_path: Path, policy: bytes) -> tuple[dict, str]:
    controller_path = root / "deploy/sandbox/namespace_activation.py"
    spec = importlib.util.spec_from_file_location("nmas_release_controller", controller_path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(module)
    target = "/etc/nmas/research-egress.nft"
    original_lstat, original_file = Path.lstat, Path.is_file
    original_symlink, original_read = Path.is_symlink, Path.read_bytes

    def patched_lstat(path: Path):
        value = original_lstat(path)
        if path == config_path:
            return SimpleNamespace(st_mode=stat.S_IFREG | 0o600, st_uid=0, st_gid=value.st_gid,
                                   st_dev=value.st_dev, st_ino=value.st_ino)
        return value

    Path.lstat = patched_lstat
    Path.is_file = lambda path: True if str(path) == target else original_file(path)
    Path.is_symlink = lambda path: False if str(path) in {target, str(config_path)} else original_symlink(path)
    Path.read_bytes = lambda path: policy if str(path) == target else original_read(path)
    try:
        config = module.normalized_config(config_path, "research", test_mode=False)
        generated = module.host_policy(config)
    finally:
        Path.lstat, Path.is_file = original_lstat, original_file
        Path.is_symlink, Path.read_bytes = original_symlink, original_read
    return config, generated


def validate(manifest_path: Path, root: Path) -> dict:
    manifest_bytes = load_regular(manifest_path)
    manifest = json.loads(manifest_bytes)
    if set(manifest) != {"schema", "release_id", "files", "identities"} or manifest["schema"] != SCHEMA:
        raise ValueError("invalid research release schema")
    files: dict[str, dict] = {}
    for item in manifest["files"]:
        if set(item) != {"path", "sha256", "size", "install_mode"}:
            raise ValueError("invalid research release file entry")
        relative = Path(item["path"])
        if relative.is_absolute() or ".." in relative.parts or str(relative) in files or not SHA256.fullmatch(item["sha256"]):
            raise ValueError("unsafe or duplicate research release path")
        content = load_regular(root / relative)
        if digest(content) != item["sha256"] or len(content) != item["size"]:
            raise ValueError(f"release input drift: {relative}")
        if item["install_mode"] not in {384, 416, 420, 448, 493}:
            raise ValueError(f"unsafe install mode: {relative}")
        files[str(relative)] = item
    identities = manifest["identities"]
    required_identities = {"overlay_sha256", "controller_sha256", "host_policy_sha256",
                           "resolver_root_sha256", "namespace_config_sha256", "nft_policy_sha256"}
    if set(identities) != required_identities or not all(SHA256.fullmatch(value) for value in identities.values()):
        raise ValueError("invalid research release identities")
    bindings = {
        "overlay_sha256": "deploy/sandbox/stage-b/worker-overlay-manifest.json.legacy-receipt-review",
        "controller_sha256": "deploy/sandbox/namespace_activation.py",
        "host_policy_sha256": "deploy/sandbox/stage-b/research-host-egress.nft.activation-review",
        "resolver_root_sha256": "deploy/sandbox/resolver_root.py",
        "namespace_config_sha256": "deploy/sandbox/stage-b/research-namespace.env.activation-review",
        "nft_policy_sha256": "deploy/sandbox/stage-b/research-egress.nft.proposed",
    }
    for name, path in bindings.items():
        if path not in files or files[path]["sha256"] != identities[name]:
            raise ValueError(f"release identity is not bound: {name}")

    overlay = json.loads((root / bindings["overlay_sha256"]).read_text(encoding="utf-8"))
    for entry in overlay["files"]:
        if entry["path"] not in files or files[entry["path"]]["sha256"] != entry["sha256"]:
            raise ValueError(f"overlay dependency missing from activation release: {entry['path']}")

    config_path = root / bindings["namespace_config_sha256"]
    policy = (root / bindings["nft_policy_sha256"]).read_bytes()
    config, generated = controller_policy(root, config_path, policy)
    reviewed = (root / bindings["host_policy_sha256"]).read_text(encoding="utf-8").splitlines()
    reviewed_policy = "\n".join(reviewed[2:]) + "\n"
    if generated != reviewed_policy:
        raise ValueError("reviewed host policy differs from controller output")
    if config["schema"] != "nmas.namespace-activation/3" or config["ipv6"] is not None:
        raise ValueError("lifecycle schema or IPv6 policy drift")

    env = parse_env(config_path.read_bytes())
    destinations = json.loads((root / "deploy/sandbox/stage-b/research-destinations.json.proposed").read_text())
    destination_ips = sorted({ip for values in destinations.values() for ip in values})
    configured_ips = sorted(item.split(":")[1] for item in env["HTTPS_TARGETS"].split())
    if destination_ips != configured_ips or env["DNS_SERVERS"].split() != config["dns_servers"]:
        raise ValueError("destination dependency mismatch")
    if digest(policy) != env["NFT_POLICY_SHA256"]:
        raise ValueError("namespace-to-nft digest mismatch")

    service = (root / "deploy/sandbox/nmas-research-broker.service.in").read_text()
    for directive in ("NetworkNamespacePath=/run/netns/nmas-ts-research",
                      "BindReadOnlyPaths=/etc/netns/nmas-ts-research/resolv.conf:/etc/resolv.conf",
                      "InaccessiblePaths=/run/docker.sock"):
        if directive not in service:
            raise ValueError(f"service isolation directive missing: {directive}")
    receipt = json.loads((root / "deploy/sandbox/fixtures/research-v2-rollback-receipt.json").read_text())
    legacy = config["legacy_config_digests"].get(receipt["schema"])
    if receipt["status"] != "rollback" or legacy != receipt["config_digest"] or any(
        receipt.get(key) for key in ("namespace_owned", "marker_owned", "host_link_owned", "host_table_owned",
                                     "resolver_file_owned", "resolver_directory_owned")
    ):
        raise ValueError("historical receipt compatibility drift")
    return {"schema": SCHEMA, "result": "valid", "release_id": manifest["release_id"],
            "release_sha256": digest(manifest_bytes), "files": len(files),
            "config_digest": config["config_digest"], "legacy_digest": legacy,
            "host_policy_sha256": identities["host_policy_sha256"]}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[2])
    args = parser.parse_args()
    print(json.dumps(validate(args.manifest.resolve(), args.root.resolve()), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
