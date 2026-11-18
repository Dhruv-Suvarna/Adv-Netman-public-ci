#!/usr/bin/env python3
"""Independent, fail-closed lifecycle for NMAS diagnostic/research netns.

Each worker namespace is attached to VM1 by one owned, VM-local veth pair. The
host end carries a private point-to-point address; one owned host nft table
filters and source-NATs that link onto exactly one approved existing egress
interface. No address is taken from any network outside VM1 and no existing
host interface, address, route, rule, sysctl or firewall table is modified.

The controller never discovers or infers authorized networks. Every network,
policy and approval is supplied by one reviewed configuration file.
``preflight`` is strictly read-only. Mutating actions journal ownership before
each command and only remove resources owned by the selected activation.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import fcntl
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import signal
import stat
import subprocess
import sys
import tempfile
from typing import Any


SCHEMA = "nmas.namespace-activation/3"
LEGACY_SCHEMAS = frozenset({"nmas.namespace-activation/2"})
GENERATION_RE = re.compile(r"^[0-9a-f]{32}$")
OWNERSHIP_FLAGS = ("namespace_owned", "marker_owned", "host_link_owned", "host_table_owned",
                   "resolver_file_owned", "resolver_directory_owned")
INACTIVE_TERMINAL_STATES = frozenset({"rollback", "deactivate", "activation-failed-cleaned",
                                      "resolver-prepare-failed-cleaned"})
KINDS = {
    "diagnostic": {"namespace": "nmas-ts-diagnostic", "interface": "nmas-ts-diag0", "host_interface": "nmas-ts-diagh0",
                   "table": "nmas_diagnostic", "host_table": "nmas_host_diagnostic",
                   "test_host_interface": "nmas-test-dh0"},
    "research": {"namespace": "nmas-ts-research", "interface": "nmas-ts-res0", "host_interface": "nmas-ts-resh0",
                 "table": "nmas_research", "host_table": "nmas_host_research",
                 "test_host_interface": "nmas-test-rh0"},
}
PRODUCTION_STATE = Path("/var/lib/nmas-ts-namespaces")
PRODUCTION_NETNS_ETC = Path("/etc/netns")
PRODUCTION_RESOLVER_ROOT_STATE = Path("/var/lib/nmas-stage-b-resolver-root.json")
RESOLVER_ROOT_SCHEMA = "nmas.resolver-root-ownership/1"
NAME_RE = re.compile(r"^[A-Za-z0-9_.:@-]{1,15}$")
ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:/@-]{7,127}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
TEST_NAMESPACE_RE = re.compile(r"^nmas-test-[a-z0-9-]{1,40}$")
TARGET_RE = re.compile(r"^tcp:(?:\[([0-9A-Fa-f:]+)\]|([0-9.]+)):([0-9]{1,5})$")
ALLOWED_KEYS = {
    "NAMESPACE", "ACTIVATION_ID", "AUTHORIZATION_APPROVED", "AUTHORIZATION_ID",
    "EGRESS_INTERFACE", "HOST_NETWORKING_APPROVAL_ID", "FIREWALL_POLICY_APPROVAL_ID",
    "NFT_POLICY", "NFT_POLICY_SHA256",
    "IPV4_MODE", "IPV4_LINK_CIDR", "IPV4_GATEWAY", "IPV4_NAT", "IPV4_NAT_APPROVAL_ID",
    "IPV4_FOREIGN_FORWARD_APPROVAL_ID",
    "IPV6_MODE", "IPV6_LINK_CIDR", "IPV6_GATEWAY", "IPV6_NAT", "IPV6_NAT_APPROVAL_ID",
    "IPV6_FOREIGN_FORWARD_APPROVAL_ID",
    "TARGETS", "HTTPS_TARGETS", "DNS_MODE", "DNS_SERVERS", "DNS_TRANSPORTS", "RESEARCH_EGRESS_APPROVAL_ID", "EXTRA_DENY_CIDRS",
    "TEST_NAMESPACE_NAME", "TEST_HOST_NAMESPACE",
}
# Mirrors research-egress.nft.in. Enforced a second time on the host side so a
# compromised namespace cannot widen its own reach.
RESEARCH_DENY4 = ("0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12",
                  "192.0.0.0/24", "192.0.2.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24",
                  "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4")
RESEARCH_DENY6 = ("::/128", "::1/128", "::ffff:0:0/96", "64:ff9b::/96", "100::/64", "2001:db8::/32", "2001:10::/28",
                  "2002::/16", "fc00::/7", "fe80::/10", "ff00::/8")
LINK_PREFIXES = {4: (30, 31), 6: (126, 127)}
STEPS = ("netns", "marker", "loopback", "ipv4_forwarding", "ipv6_forwarding", "accept_ra", "ipv6_disable", "nft",
         "host_nft", "link", "host_marker", "host_move", "ipv4_address", "ipv4_host_address", "ipv6_address",
         "ipv6_host_address", "host_up", "interface", "ipv4_route", "ipv6_route", "dns")


class Refused(RuntimeError):
    pass


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def atomic_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    parent = path.parent.lstat()
    expected_uid, expected_gid = os.geteuid(), os.getegid()
    if (stat.S_ISLNK(parent.st_mode) or not stat.S_ISDIR(parent.st_mode)
            or parent.st_uid != expected_uid or parent.st_gid != expected_gid
            or stat.S_IMODE(parent.st_mode) != 0o700):
        raise Refused("activation state directory must be trusted-owner mode 0700")
    if path.exists() or path.is_symlink():
        current = path.lstat()
        if (stat.S_ISLNK(current.st_mode) or not stat.S_ISREG(current.st_mode)
                or current.st_uid != expected_uid or current.st_gid != expected_gid
                or stat.S_IMODE(current.st_mode) != 0o600):
            raise Refused("activation state target is unsafe")
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(value, stream, indent=1, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def parse_config(path: Path, *, test_mode: bool) -> dict[str, str]:
    try:
        info = path.lstat()
    except OSError as exc:
        raise Refused(f"configuration is not readable: {exc}") from exc
    if not stat.S_ISREG(info.st_mode) or path.is_symlink():
        raise Refused("configuration must be a regular non-symlink file")
    if info.st_mode & 0o022:
        raise Refused("configuration must not be group/world writable")
    if not test_mode and info.st_uid != 0:
        raise Refused("production configuration must be root-owned")
    result: dict[str, str] = {}
    for number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            raise Refused(f"configuration line {number} is not KEY=VALUE")
        key, value = line.split("=", 1)
        key, value = key.strip(), value.strip()
        if key not in ALLOWED_KEYS:
            raise Refused(f"unknown configuration key: {key}")
        if key in result:
            raise Refused(f"duplicate configuration key: {key}")
        if any(character in value for character in "\x00\r\n"):
            raise Refused(f"invalid value for {key}")
        result[key] = value
    return result


def required(config: dict[str, str], key: str) -> str:
    value = config.get(key, "").strip()
    if not value:
        raise Refused(f"missing required approved configuration: {key}")
    return value


def approval(config: dict[str, str], key: str) -> str:
    value = required(config, key)
    if not ID_RE.fullmatch(value):
        raise Refused(f"{key} must be an attributable approval identifier")
    return value


def command(argv: list[str], *, capture: bool = False, check: bool = True,
            stdin: str | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(argv, check=check, text=True, capture_output=capture, input=stdin)


def host_ip(config: dict[str, Any], *args: str) -> list[str]:
    """``ip`` in the host network namespace (a disposable stand-in in test mode)."""
    prefix = ["-n", config["host_namespace"]] if config["host_namespace"] else []
    return ["/usr/sbin/ip", *prefix, *args]


def host_exec(config: dict[str, Any], argv: list[str]) -> list[str]:
    if config["host_namespace"]:
        return ["/usr/sbin/ip", "netns", "exec", config["host_namespace"], *argv]
    return argv


def ns_exec(config: dict[str, Any], argv: list[str]) -> list[str]:
    return ["/usr/sbin/ip", "netns", "exec", config["namespace"], *argv]


def run_json(argv: list[str]) -> Any:
    return json.loads(command(argv, capture=True).stdout or "[]")


def namespace_names() -> set[str]:
    completed = command(["/usr/sbin/ip", "netns", "list"], capture=True)
    return {line.split()[0] for line in completed.stdout.splitlines() if line.split()}


def validate_family(config: dict[str, str], family: int, kind: str) -> dict[str, str] | None:
    prefix = f"IPV{family}_"
    mode = required(config, prefix + "MODE")
    if mode not in {"enabled", "disabled"}:
        raise Refused(f"{prefix}MODE must be explicitly enabled or disabled")
    fields = tuple(prefix + name for name in ("LINK_CIDR", "GATEWAY", "NAT", "NAT_APPROVAL_ID",
                                               "FOREIGN_FORWARD_APPROVAL_ID"))
    if mode == "disabled":
        if any(config.get(field, "").strip() for field in fields):
            raise Refused(f"disabled IPv{family} must not contain link, gateway, NAT or approval values")
        return None
    source_text, gateway_text = required(config, fields[0]), required(config, fields[1])
    try:
        source = ipaddress.ip_interface(source_text)
        gateway = ipaddress.ip_address(gateway_text)
    except ValueError as exc:
        raise Refused(f"invalid IPv{family} link/gateway: {exc}") from exc
    if source.version != family or gateway.version != family:
        raise Refused(f"IPv{family} link and gateway must use IPv{family}")
    if source.ip == gateway or gateway not in source.network:
        raise Refused(f"IPv{family} gateway must be a distinct address in the VM-local link prefix")
    if source.network.prefixlen not in LINK_PREFIXES[family]:
        raise Refused(f"IPv{family} link must be a point-to-point /{' or /'.join(map(str, LINK_PREFIXES[family]))}")
    local = source.network.is_link_local if family == 4 else source.network.subnet_of(ipaddress.ip_network("fc00::/7"))
    if not (local or (family == 4 and source.network.is_private and not source.network.is_loopback)):
        raise Refused(f"IPv{family} link prefix must be VM-local: IPv4 link-local/private or IPv6 ULA, never routable")
    nat = required(config, fields[2])
    if nat != "masquerade":
        try:
            address = ipaddress.ip_address(nat)
        except ValueError as exc:
            raise Refused(f"{fields[2]} must be 'masquerade' or one literal address") from exc
        if address.version != family or address in source.network:
            raise Refused(f"{fields[2]} must be an IPv{family} address outside the VM-local link")
        nat = str(address)
    elif kind == "diagnostic":
        raise Refused("diagnostic NAT must name the exact approved existing management source address")
    result = {"source": str(source), "gateway": str(gateway), "network": str(source.network), "nat": nat,
              "nat_approval": approval(config, fields[3])}
    if config.get(fields[4], "").strip():
        result["foreign_forward_approval"] = approval(config, fields[4])
    return result


def parse_targets(text: str, families: dict[int, Any]) -> list[list[Any]]:
    targets: set[tuple[str, int]] = set()
    for item in text.split():
        match = TARGET_RE.fullmatch(item)
        if not match:
            raise Refused(f"TARGETS entry is not tcp:ADDRESS:PORT or tcp:[ADDRESS]:PORT: {item}")
        try:
            address = ipaddress.ip_address(match.group(1) or match.group(2))
        except ValueError as exc:
            raise Refused(f"TARGETS entry has an invalid address: {item}") from exc
        port = int(match.group(3))
        if not 1 <= port <= 65535:
            raise Refused(f"TARGETS entry has an invalid port: {item}")
        if address.is_unspecified or address.is_multicast or address.is_loopback or address.is_link_local:
            raise Refused(f"TARGETS entry is not an exact unicast device address: {item}")
        family = families[address.version]
        if not family:
            raise Refused(f"TARGETS entry uses a disabled address family: {item}")
        if address in ipaddress.ip_network(family["network"]) or str(address) == family["nat"]:
            raise Refused(f"TARGETS entry collides with the VM-local link or NAT source: {item}")
        targets.add((str(address), port))
    if not targets:
        raise Refused("diagnostic activation requires at least one exact approved target")
    return [list(item) for item in sorted(targets)]


def parse_extra_deny(text: str) -> list[str]:
    networks = []
    for item in text.split():
        try:
            networks.append(str(ipaddress.ip_network(item, strict=True)))
        except ValueError as exc:
            raise Refused(f"EXTRA_DENY_CIDRS contains an invalid network: {item}") from exc
    return sorted(set(networks))


def normalized_config(path: Path, kind: str, *, test_mode: bool) -> dict[str, Any]:
    config = parse_config(path, test_mode=test_mode)
    if required(config, "NAMESPACE") != kind:
        raise Refused("configuration namespace does not match the selected namespace")
    activation_id = approval(config, "ACTIVATION_ID")
    if config.get("AUTHORIZATION_APPROVED") != "yes":
        raise Refused("AUTHORIZATION_APPROVED must explicitly equal yes")
    egress = required(config, "EGRESS_INTERFACE")
    if not NAME_RE.fullmatch(egress) or egress == "lo":
        raise Refused("invalid egress interface")
    nft = Path(required(config, "NFT_POLICY"))
    if not nft.is_absolute() or nft.is_symlink() or not nft.is_file():
        raise Refused("NFT_POLICY must be an existing absolute regular non-symlink file")
    policy_digest = required(config, "NFT_POLICY_SHA256")
    if not SHA256_RE.fullmatch(policy_digest) or sha256(nft.read_bytes()) != policy_digest:
        raise Refused("NFT_POLICY_SHA256 does not match the approved policy")
    ipv4, ipv6 = validate_family(config, 4, kind), validate_family(config, 6, kind)
    if not ipv4 and not ipv6:
        raise Refused("at least one explicitly approved address family must be enabled")
    dns_mode = required(config, "DNS_MODE")
    if dns_mode not in {"enabled", "disabled"}:
        raise Refused("DNS_MODE must be explicitly enabled or disabled")
    dns_servers: list[str] = []
    if dns_mode == "enabled":
        transports = {item.strip() for item in required(config, "DNS_TRANSPORTS").split(",") if item.strip()}
        if transports != {"udp", "tcp"}:
            raise Refused("enabled DNS requires the explicitly approved udp,tcp transports")
        try:
            dns_servers = [str(ipaddress.ip_address(item)) for item in required(config, "DNS_SERVERS").split()]
        except ValueError as exc:
            raise Refused(f"DNS_SERVERS must contain only literal IP addresses: {exc}") from exc
        if not dns_servers:
            raise Refused("enabled DNS requires explicit resolver addresses")
        for resolver in dns_servers:
            version = ipaddress.ip_address(resolver).version
            if (version == 4 and not ipv4) or (version == 6 and not ipv6):
                raise Refused(f"DNS resolver {resolver} uses a disabled address family")
    elif config.get("DNS_SERVERS", "").strip() or config.get("DNS_TRANSPORTS", "").strip():
        raise Refused("disabled DNS must not contain resolver or transport values")
    targets: list[list[Any]] = []
    https_targets: list[list[Any]] = []
    extra_deny: list[str] = []
    if kind == "diagnostic":
        if dns_mode != "disabled":
            raise Refused("diagnostic DNS must be explicitly disabled; targets are exact authorized IP addresses")
        for key in ("RESEARCH_EGRESS_APPROVAL_ID", "EXTRA_DENY_CIDRS", "HTTPS_TARGETS"):
            if config.get(key, "").strip():
                raise Refused(f"diagnostic configuration must not contain {key}")
        targets = parse_targets(required(config, "TARGETS"), {4: ipv4, 6: ipv6})
    else:
        if dns_mode != "enabled":
            raise Refused("research activation requires explicitly approved DNS")
        if config.get("TARGETS", "").strip():
            raise Refused("research configuration must not contain diagnostic targets")
        https_targets = parse_targets(required(config, "HTTPS_TARGETS"), {4: ipv4, 6: ipv6})
        if any(port != 443 for _address, port in https_targets):
            raise Refused("research HTTPS_TARGETS must contain TCP port 443 only")
        approval(config, "RESEARCH_EGRESS_APPROVAL_ID")
        extra_deny = parse_extra_deny(config.get("EXTRA_DENY_CIDRS", ""))
    for key in ("AUTHORIZATION_ID", "HOST_NETWORKING_APPROVAL_ID", "FIREWALL_POLICY_APPROVAL_ID"):
        approval(config, key)
    namespace = KINDS[kind]["namespace"]
    interface = KINDS[kind]["interface"]
    host_interface = KINDS[kind]["host_interface"]
    host_namespace = None
    if test_mode:
        namespace = required(config, "TEST_NAMESPACE_NAME")
        host_namespace = required(config, "TEST_HOST_NAMESPACE")
        if not TEST_NAMESPACE_RE.fullmatch(namespace) or not TEST_NAMESPACE_RE.fullmatch(host_namespace):
            raise Refused("test namespaces must match nmas-test-[a-z0-9-]+")
        if namespace == host_namespace:
            raise Refused("test host namespace must differ from the worker namespace")
        interface = "nmas-test0"
        host_interface = KINDS[kind]["test_host_interface"]
    elif config.get("TEST_NAMESPACE_NAME", "").strip() or config.get("TEST_HOST_NAMESPACE", "").strip():
        raise Refused("TEST_* keys are forbidden in production mode")
    if egress in {interface, host_interface}:
        raise Refused("egress interface must be an existing interface, not the owned veth")
    normalized = {
        "schema": SCHEMA, "kind": kind, "namespace": namespace, "interface": interface,
        "host_interface": host_interface, "host_namespace": host_namespace,
        "table": KINDS[kind]["table"], "host_table": KINDS[kind]["host_table"],
        "activation_id": activation_id, "egress": egress,
        "nft_policy": str(nft), "nft_sha256": policy_digest, "ipv4": ipv4, "ipv6": ipv6,
        "dns_mode": dns_mode, "dns_servers": dns_servers, "targets": targets, "https_targets": https_targets,
        "extra_deny": extra_deny,
        "approvals": {key: config[key] for key in sorted(config) if key.endswith("_ID")},
    }
    canonical = json.dumps(normalized, sort_keys=True, separators=(",", ":")).encode()
    normalized["config_digest"] = sha256(canonical)
    # Receipt schema is controller metadata, not an operator-approved policy
    # value.  Preserve the exact digest each supported legacy controller would
    # have computed so a terminal receipt can be authenticated across a schema
    # upgrade without weakening comparison of any network or approval field.
    normalized["legacy_config_digests"] = {}
    for legacy_schema in sorted(LEGACY_SCHEMAS):
        legacy = {key: value for key, value in normalized.items()
                  if key not in {"config_digest", "legacy_config_digests"}}
        legacy["schema"] = legacy_schema
        legacy_canonical = json.dumps(legacy, sort_keys=True, separators=(",", ":")).encode()
        normalized["legacy_config_digests"][legacy_schema] = sha256(legacy_canonical)
    return normalized


def ensure_test_paths(test_root: Path | None) -> tuple[Path, Path]:
    if test_root is None:
        return PRODUCTION_STATE, PRODUCTION_NETNS_ETC
    if os.geteuid() != 0:
        raise Refused("test mode requires root inside the disposable harness")
    resolved = test_root.resolve()
    if not str(resolved).startswith("/tmp/nmas-namespace-test-"):
        raise Refused("test root must be below /tmp/nmas-namespace-test-*")
    return resolved / "state", resolved / "etc-netns"


def read_state(path: Path) -> dict[str, Any] | None:
    if not path.exists() and not path.is_symlink():
        return None
    info = path.lstat()
    if (stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.geteuid() or info.st_gid != os.getegid()
            or stat.S_IMODE(info.st_mode) != 0o600):
        raise Refused("activation state must be a trusted-owner mode-0600 regular file")
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        opened = os.fstat(fd)
        if (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino):
            os.close(fd)
            raise Refused("activation state changed while opening")
        with os.fdopen(fd, "r", encoding="utf-8") as stream:
            state = json.load(stream)
    except (OSError, json.JSONDecodeError) as exc:
        raise Refused(f"activation state is unreadable: {exc}") from exc
    if state.get("schema") not in {SCHEMA, *LEGACY_SCHEMAS}:
        raise Refused("activation state schema is not owned by this controller")
    generation = state.get("generation")
    if state.get("schema") == SCHEMA and not GENERATION_RE.fullmatch(str(generation or "")):
        raise Refused("activation state generation is invalid")
    return state


def assert_state_owner(state: dict[str, Any], config: dict[str, Any]) -> None:
    for key in ("kind", "namespace", "activation_id"):
        if state.get(key) != config.get(key):
            raise Refused(f"state ownership mismatch for {key}; refusing cross-activation mutation")
    if state.get("config_digest") == config.get("config_digest"):
        return
    legacy_digest = config.get("legacy_config_digests", {}).get(state.get("schema"))
    if state.get("schema") in LEGACY_SCHEMAS and state.get("config_digest") == legacy_digest:
        return
    raise Refused("state ownership mismatch for config_digest; refusing cross-activation mutation")


def _secure_history_directory(path: Path) -> None:
    if not path.exists():
        path.mkdir(mode=0o700)
    info = path.lstat()
    if (stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode)
            or info.st_uid != os.geteuid() or info.st_gid != os.getegid()
            or stat.S_IMODE(info.st_mode) != 0o700):
        raise Refused("activation history directory must be trusted-owner mode 0700")


def archive_receipt(state_path: Path, state: dict[str, Any]) -> dict[str, str]:
    """Atomically retain the exact terminal receipt before replacing current state."""
    info = state_path.lstat()
    fd = os.open(state_path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        opened = os.fstat(fd)
        if ((opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino)
                or opened.st_uid != os.geteuid() or opened.st_gid != os.getegid()
                or stat.S_IMODE(opened.st_mode) != 0o600):
            raise Refused("terminal activation receipt changed while archiving")
        with os.fdopen(fd, "rb") as stream:
            fd = -1
            content = stream.read()
    finally:
        if fd >= 0:
            os.close(fd)
    try:
        if json.loads(content) != state:
            raise Refused("terminal activation receipt bytes do not match verified state")
    except json.JSONDecodeError as exc:
        raise Refused("terminal activation receipt is invalid during archive") from exc
    digest = sha256(content)
    generation = str(state.get("generation") or f"legacy-{digest[:16]}")
    if not re.fullmatch(r"(?:[0-9a-f]{32}|legacy-[0-9a-f]{16})", generation):
        raise Refused("terminal activation receipt generation is unsafe")
    history_root = state_path.parent / "history"
    history_kind = history_root / state_path.stem
    _secure_history_directory(history_root)
    _secure_history_directory(history_kind)
    destination = history_kind / f"{generation}-{digest}.json"
    if destination.exists() or destination.is_symlink():
        archived_info = destination.lstat()
        if (stat.S_ISLNK(archived_info.st_mode) or not stat.S_ISREG(archived_info.st_mode)
                or archived_info.st_uid != os.geteuid() or archived_info.st_gid != os.getegid()
                or stat.S_IMODE(archived_info.st_mode) != 0o600
                or destination.read_bytes() != content):
            raise Refused("historical activation receipt conflicts with verified terminal state")
        return {"generation": generation, "sha256": digest, "path": str(destination)}
    temporary = history_kind / f".archive-{secrets.token_hex(16)}"
    archive_fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        os.fchmod(archive_fd, 0o600)
        with os.fdopen(archive_fd, "wb") as stream:
            archive_fd = -1
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.link(temporary, destination, follow_symlinks=False)
        directory_fd = os.open(history_kind, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except FileExistsError as exc:
        raise Refused("historical activation receipt appeared concurrently") from exc
    finally:
        if archive_fd >= 0:
            os.close(archive_fd)
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
    return {"generation": generation, "sha256": digest, "path": str(destination)}


def marker(config: dict[str, Any], generation: str | None = None) -> str:
    value = "nmas-owner:" + config["activation_id"] + ":" + config["config_digest"][:16]
    return value if generation is None else value + ":" + generation


def nft_set(name: str, kind: str, elements: list[str], *, interval: bool = False) -> str:
    flags = " flags interval;" if interval else ""
    body = f" elements = {{ {', '.join(elements)} }}" if elements else ""
    return f"  set {name} {{ type {kind};{flags}{body} }}\n"


def host_policy(config: dict[str, Any], generation: str | None = None) -> str:
    """The complete owned host table, generated only from approved configuration.

    Every rule is scoped to the owned veth. Accept verdicts never override other
    tables; the terminal drops guarantee nothing else enters or leaves the link.
    """
    hif, egress, kind = config["host_interface"], config["egress"], config["kind"]
    families = [(4, "ip", config["ipv4"]), (6, "ip6", config["ipv6"])]
    neighbor = "    icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert } accept\n" if config["ipv6"] else ""
    sets, forward, nat = "", "", ""
    for version, keyword, family in families:
        if not family:
            continue
        source = str(ipaddress.ip_interface(family["source"]).ip)
        forward += (f'    iifname "{egress}" oifname "{hif}" {keyword} daddr {source} '
                    "ct state established,related accept\n")
    forward += f'    iifname != "{hif}" counter drop\n    oifname != "{egress}" counter drop\n'
    for version, keyword, family in families:
        if not family:
            continue
        source = str(ipaddress.ip_interface(family["source"]).ip)
        address_type = "ipv4_addr" if version == 4 else "ipv6_addr"
        if kind == "diagnostic":
            elements = [f"{address} . {port}" for address, port in config["targets"]
                        if ipaddress.ip_address(address).version == version]
            sets += nft_set(f"targets{version}", f"{address_type} . inet_service", elements)
            forward += f"    {keyword} saddr {source} {keyword} daddr . tcp dport @targets{version} accept\n"
        else:
            resolvers = [item for item in config["dns_servers"] if ipaddress.ip_address(item).version == version]
            deny = list(RESEARCH_DENY4 if version == 4 else RESEARCH_DENY6)
            deny += [item for item in config["extra_deny"] if ipaddress.ip_network(item).version == version]
            deny = [str(item) for item in ipaddress.collapse_addresses(ipaddress.ip_network(item) for item in deny)]
            sets += nft_set(f"dns{version}", address_type, resolvers)
            sets += nft_set(f"deny{version}", address_type, deny, interval=True)
            destinations = [f"{address} . {port}" for address, port in config["https_targets"]
                            if ipaddress.ip_address(address).version == version]
            sets += nft_set(f"https{version}", f"{address_type} . inet_service", destinations)
            forward += (f"    {keyword} saddr {source} {keyword} daddr @dns{version} udp dport 53 accept\n"
                        f"    {keyword} saddr {source} {keyword} daddr @dns{version} tcp dport 53 accept\n"
                        f"    {keyword} daddr @deny{version} counter drop\n"
                        f"    {keyword} saddr {source} {keyword} daddr . tcp dport @https{version} accept\n")
        action = "masquerade" if family["nat"] == "masquerade" else f"snat {keyword} to {family['nat']}"
        nat += f'    iifname "{hif}" oifname "{egress}" {keyword} saddr {source} {action}\n'
    return (f"table inet {config['host_table']} {{\n"
            f'  comment "{marker(config, generation)}"\n{sets}'
            "  chain input {\n    type filter hook input priority filter - 20; policy accept;\n"
            f'    iifname != "{hif}" return\n{neighbor}    counter drop\n  }}\n'
            "  chain output {\n    type filter hook output priority filter - 20; policy accept;\n"
            f'    oifname != "{hif}" return\n{neighbor}    counter drop\n  }}\n'
            "  chain forward {\n    type filter hook forward priority filter - 20; policy accept;\n"
            f'    iifname != "{hif}" oifname != "{hif}" return\n{forward}    counter drop\n  }}\n'
            "  chain postrouting {\n    type nat hook postrouting priority srcnat - 20; policy accept;\n"
            f"{nat}  }}\n}}\n")


def host_link(config: dict[str, Any]) -> dict[str, Any] | None:
    result = command(host_ip(config, "-j", "-d", "link", "show", "dev", config["host_interface"]), capture=True, check=False)
    if result.returncode:
        return None
    links = json.loads(result.stdout or "[]")
    return links[0] if links else None


def host_table(config: dict[str, Any]) -> list[dict[str, Any]] | None:
    result = command(host_exec(config, ["/usr/sbin/nft", "-j", "list", "table", "inet", config["host_table"]]),
                     capture=True, check=False)
    if result.returncode:
        return None
    return json.loads(result.stdout).get("nftables", [])


def table_comment(objects: list[dict[str, Any]]) -> str | None:
    for item in objects:
        if "table" in item:
            return item["table"].get("comment")
    return None


def set_elements(objects: list[dict[str, Any]], name: str) -> set[tuple[str, int]]:
    for item in objects:
        if item.get("set", {}).get("name") == name:
            return {(str(ipaddress.ip_address(element["concat"][0])), int(element["concat"][1]))
                    for element in item["set"].get("elem", [])}
    return set()


def address_set_elements(objects: list[dict[str, Any]], name: str) -> set[str]:
    for item in objects:
        if item.get("set", {}).get("name") == name:
            return {str(ipaddress.ip_address(element)) for element in item["set"].get("elem", [])}
    return set()


def host_sysctl(config: dict[str, Any], key: str) -> str:
    return command(host_exec(config, ["/usr/sbin/sysctl", "-n", key]), capture=True).stdout.strip()


def resolver_root_safe(path: Path) -> bool:
    try:
        info = path.lstat()
    except OSError:
        return False
    return (stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode) and info.st_uid == 0 and info.st_gid == 0
            and stat.S_IMODE(info.st_mode) == 0o755)


def secure_regular(path: Path, *, mode: int, label: str) -> os.stat_result:
    """Return a root-owned regular file without following a final symlink."""
    try:
        info = path.lstat()
    except OSError as exc:
        raise Refused(f"{label} is missing or unavailable") from exc
    if (stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode)
            or info.st_uid != 0 or info.st_gid != 0 or stat.S_IMODE(info.st_mode) != mode):
        raise Refused(f"{label} must be a root-owned non-symlink regular file with mode {mode:04o}")
    return info


def read_secure_regular(path: Path, *, mode: int, label: str) -> tuple[os.stat_result, bytes]:
    before = secure_regular(path, mode=mode, label=label)
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError as exc:
        raise Refused(f"{label} could not be opened without following links") from exc
    try:
        opened = os.fstat(fd)
        if ((opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino)
                or not stat.S_ISREG(opened.st_mode) or opened.st_uid != 0 or opened.st_gid != 0
                or stat.S_IMODE(opened.st_mode) != mode):
            raise Refused(f"{label} changed during verification")
        with os.fdopen(fd, "rb") as stream:
            fd = -1
            return opened, stream.read()
    finally:
        if fd >= 0:
            os.close(fd)


def secure_directory(path: Path, *, mode: int, label: str) -> os.stat_result:
    try:
        info = path.lstat()
    except OSError as exc:
        raise Refused(f"{label} is missing or unavailable") from exc
    if (stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode)
            or info.st_uid != 0 or info.st_gid != 0 or stat.S_IMODE(info.st_mode) != mode):
        raise Refused(f"{label} must be a root-owned non-symlink directory with mode {mode:04o}")
    return info


def verify_resolver_root_receipt(path: Path, change_id: str) -> dict[str, Any]:
    """Bind the trusted resolver root to resolver_root.py's ownership receipt."""
    if path != PRODUCTION_NETNS_ETC:
        return {"test_fixture": True}
    root = secure_directory(path, mode=0o755, label="namespace resolver root")
    receipt_info, receipt_bytes = read_secure_regular(PRODUCTION_RESOLVER_ROOT_STATE, mode=0o600,
                                                      label="resolver-root ownership receipt")
    try:
        receipt = json.loads(receipt_bytes)
    except json.JSONDecodeError as exc:
        raise Refused("resolver-root ownership receipt is invalid") from exc
    if (not isinstance(receipt, dict) or receipt.get("schema") != RESOLVER_ROOT_SCHEMA
            or receipt.get("change_id") != change_id or receipt.get("path") != str(path)
            or receipt.get("uid") != 0 or receipt.get("gid") != 0 or receipt.get("mode") != "0755"
            or (receipt.get("directory_dev"), receipt.get("directory_ino")) != (root.st_dev, root.st_ino)):
        raise Refused("resolver-root ownership receipt does not match this activation")
    parent = path.parent.lstat()
    if (stat.S_ISLNK(parent.st_mode) or not stat.S_ISDIR(parent.st_mode)
            or (receipt.get("parent_dev"), receipt.get("parent_ino")) != (parent.st_dev, parent.st_ino)):
        raise Refused("resolver-root parent identity differs from the ownership receipt")
    return {"receipt_dev": receipt_info.st_dev, "receipt_ino": receipt_info.st_ino}


def service_preflight(config: dict[str, Any], config_path: Path, netns_etc: Path) -> dict[str, Any]:
    """Verify the worker's actual namespace, resolver bind and approved policy.

    This is run as the root-only ``ExecStartPre=+`` command after systemd has
    joined the worker network namespace and built its private mount namespace.
    The broker itself still starts as the unprivileged service identity.
    """
    if config["kind"] != "research" or config["dns_mode"] != "enabled":
        raise Refused("service preflight is only valid for DNS-enabled research")
    if config["ipv6"] is not None:
        raise Refused("research worker service requires IPv6 to remain disabled")
    read_secure_regular(config_path, mode=0o600, label="research namespace configuration")
    _policy_info, policy_bytes = read_secure_regular(Path(config["nft_policy"]), mode=0o600,
                                                     label="research nft policy")
    if sha256(policy_bytes) != config["nft_sha256"]:
        raise Refused("research nft policy changed during service preflight")
    verify_resolver_root_receipt(netns_etc, config["approvals"]["AUTHORIZATION_ID"])
    directory, resolver = resolver_paths(config, netns_etc)
    secure_directory(directory, mode=0o755, label="research resolver directory")
    source, source_content = read_secure_regular(resolver, mode=0o644, label="research resolver file")
    expected = resolver_content(config)
    if source_content != expected:
        raise Refused("research resolver content differs from approved DNS_SERVERS")

    namespace_path = Path("/run/netns") / config["namespace"]
    try:
        namespace_lstat = namespace_path.lstat()
        namespace = namespace_path.stat()
        current = Path("/proc/self/ns/net").stat()
    except OSError as exc:
        raise Refused("research service network namespace identity is unavailable") from exc
    if stat.S_ISLNK(namespace_lstat.st_mode) or (namespace.st_dev, namespace.st_ino) != (current.st_dev, current.st_ino):
        raise Refused("research service is not running in the approved network namespace")

    try:
        mounted = Path("/etc/resolv.conf").stat()
        mounted_fd = os.open("/etc/resolv.conf", os.O_RDONLY)
        with os.fdopen(mounted_fd, "rb") as stream:
            mounted_open = os.fstat(stream.fileno())
            if (mounted_open.st_dev, mounted_open.st_ino) != (mounted.st_dev, mounted.st_ino):
                raise Refused("worker resolver mount changed during verification")
            mounted_content = stream.read()
    except OSError as exc:
        raise Refused("worker resolver mount is unavailable") from exc
    if (mounted.st_dev, mounted.st_ino) != (source.st_dev, source.st_ino) or mounted_content != expected:
        raise Refused("worker /etc/resolv.conf is not the exact approved resolver file")
    return {
        "action": "service-preflight", "result": "valid", "kind": "research",
        "namespace": config["namespace"], "resolver_sha256": sha256(expected),
        "nft_policy_sha256": config["nft_sha256"], "ipv6": "disabled",
    }


def preflight(config: dict[str, Any], state_path: Path, netns_etc: Path) -> dict[str, Any]:
    if config["host_namespace"] and config["host_namespace"] not in namespace_names():
        raise Refused("disposable test host namespace does not exist")
    try:
        egress = run_json(host_ip(config, "-j", "address", "show", "dev", config["egress"]))
    except subprocess.CalledProcessError as exc:
        raise Refused("approved egress interface does not exist") from exc
    if len(egress) != 1:
        raise Refused("approved egress interface is ambiguous")
    egress_addresses = {info["local"] for info in egress[0].get("addr_info", [])}
    assigned = [ipaddress.ip_interface(f"{info['local']}/{info['prefixlen']}")
                for link in run_json(host_ip(config, "-j", "address", "show"))
                if link.get("ifname") != config["host_interface"] for info in link.get("addr_info", [])]
    foreign_drop = set()
    chains = json.loads(command(host_exec(config, ["/usr/sbin/nft", "-j", "list", "chains"]), capture=True).stdout)
    for item in chains.get("nftables", []):
        chain = item.get("chain", {})
        if (chain.get("hook") == "forward" and chain.get("policy") == "drop"
                and chain.get("table") != config["host_table"]):
            foreign_drop |= {"ip": {4}, "ip6": {6}, "inet": {4, 6}}.get(chain.get("family"), set())
    for version, key in ((4, "net.ipv4.ip_forward"), (6, "net.ipv6.conf.all.forwarding")):
        family = config[f"ipv{version}"]
        if not family:
            continue
        network = ipaddress.ip_network(family["network"])
        for existing in assigned:
            if existing.version == version and existing.network.overlaps(network):
                raise Refused(f"VM-local IPv{version} link overlaps an address already present on the host: {existing}")
        routes = run_json(host_ip(config, "-j", f"-{version}", "route", "show", "table", "all"))
        for route in routes:
            destination = route.get("dst", "default")
            if destination == "default" or route.get("dev") == config["host_interface"]:
                continue
            try:
                routed = ipaddress.ip_network(destination, strict=False)
            except ValueError:
                continue
            if routed.overlaps(network):
                raise Refused(f"VM-local IPv{version} link overlaps an existing host route: {destination}")
        if family["nat"] != "masquerade" and family["nat"] not in egress_addresses:
            raise Refused(f"approved IPv{version} NAT source is not an existing address of the egress interface")
        if host_sysctl(config, key) != "1":
            raise Refused(f"host IPv{version} forwarding is not already enabled; the controller never changes it")
        if version in foreign_drop and "foreign_forward_approval" not in family:
            raise Refused(f"a foreign default-drop forward chain governs IPv{version}; disable the family or supply "
                          f"IPV{version}_FOREIGN_FORWARD_APPROVAL_ID after its owner admits this exact path")
    try:
        command(["/usr/sbin/nft", "-c", "-f", config["nft_policy"]])
    except subprocess.CalledProcessError as exc:
        raise Refused("approved nft policy failed syntax validation") from exc
    existing_state = read_state(state_path)
    if existing_state:
        assert_state_owner(existing_state, config)
    generation = existing_state.get("generation") if existing_state and existing_state.get("schema") == SCHEMA else None
    policy = host_policy(config, generation)
    try:
        command(host_exec(config, ["/usr/sbin/nft", "-c", "-f", "-"]), stdin=policy, capture=True)
    except subprocess.CalledProcessError as exc:
        raise Refused(f"generated host policy failed syntax validation: {exc.stderr}") from exc
    if config["dns_mode"] == "enabled":
        if not resolver_root_safe(netns_etc):
            raise Refused("approved namespace resolver root is missing or unsafe")
        if not config["host_namespace"]:
            verify_resolver_root_receipt(netns_etc, config["approvals"]["AUTHORIZATION_ID"])
    exists = config["namespace"] in namespace_names()
    link, table = host_link(config), host_table(config)
    if existing_state:
        assert_state_owner(existing_state, config)
        if existing_state.get("status") == "resolver-prepared":
            validate_resolver_state(config, netns_etc, existing_state)
        if existing_state.get("status") == "active" and not exists:
            raise Refused("owned active namespace is missing")
    owned = bool(existing_state) and (existing_state.get("status") == "active" or existing_state.get("namespace_owned")
                                      or bool(existing_state.get("pending_step"))
                                      or existing_state.get("status") == "activation-failed-cleanup-required")
    if not owned:
        if exists:
            raise Refused("namespace already exists without matching ownership state")
        if link is not None:
            raise Refused("host veth name already exists without matching ownership state")
        if table is not None:
            raise Refused("host nft table already exists without matching ownership state")
    return {"action": "preflight", "kind": config["kind"], "namespace": config["namespace"],
            "activation_id": config["activation_id"], "config_digest": config["config_digest"],
            "generation": generation, "host_policy_sha256": sha256(policy.encode()),
            "state": existing_state.get("status") if existing_state else "absent", "mutations": 0}


def persist(state_path: Path, state: dict[str, Any]) -> None:
    state["sequence"] = int(state.get("sequence", 0)) + 1
    atomic_json(state_path, state)


def failpoint(step: str, enabled: str | None) -> None:
    if enabled == step:
        raise Refused(f"injected test failure after {step}")


def run_step(state_path: Path, state: dict[str, Any], step: str, commands: list[list[str]], *,
             fail_after: str | None, stdin: str | None = None) -> None:
    state["pending_step"] = step
    persist(state_path, state)
    for argv in commands:
        command(argv, stdin=stdin)
    state["completed_steps"].append(step)
    state["pending_step"] = ""
    persist(state_path, state)
    failpoint(step, fail_after)


def resolver_paths(config: dict[str, Any], netns_etc: Path) -> tuple[Path, Path]:
    directory = netns_etc / config["namespace"]
    return directory, directory / "resolv.conf"


def verify_terminal_generation(config: dict[str, Any], state: dict[str, Any], netns_etc: Path) -> None:
    """Require a fully inactive, unambiguous generation before starting another."""
    assert_state_owner(state, config)
    if state.get("status") not in INACTIVE_TERMINAL_STATES:
        raise Refused("existing activation generation is not in a reusable terminal state")
    if state.get("pending_step") or any(state.get(flag) for flag in OWNERSHIP_FLAGS):
        raise Refused("terminal activation receipt retains stale or ambiguous ownership")
    directory, resolv = resolver_paths(config, netns_etc)
    if (config["namespace"] in namespace_names() or host_link(config) is not None or host_table(config) is not None
            or directory.exists() or directory.is_symlink() or resolv.exists() or resolv.is_symlink()):
        raise Refused("terminal activation receipt conflicts with existing or foreign resources")


def begin_generation(config: dict[str, Any], state_path: Path, netns_etc: Path, *, status: str) -> dict[str, Any]:
    previous = read_state(state_path)
    archived = None
    if previous:
        verify_terminal_generation(config, previous, netns_etc)
        archived = archive_receipt(state_path, previous)
    generation = secrets.token_hex(16)
    state = new_state(config, host_policy(config, generation), generation=generation, status=status)
    if archived:
        state["previous_generation"] = archived["generation"]
        state["previous_receipt_sha256"] = archived["sha256"]
        state["previous_receipt_path"] = archived["path"]
    persist(state_path, state)
    return state


def resolver_content(config: dict[str, Any]) -> bytes:
    return ("".join(f"nameserver {value}\n" for value in config["dns_servers"])).encode()


def create_resolver(config: dict[str, Any], netns_etc: Path, state_path: Path, state: dict[str, Any], fail_after: str | None) -> None:
    directory, resolv = resolver_paths(config, netns_etc)
    if directory.exists() or resolv.exists():
        raise Refused("research resolver path already exists and is not adoptable")
    state["pending_step"] = "dns"
    persist(state_path, state)
    directory.mkdir(mode=0o755, parents=False)
    os.chmod(directory, 0o755, follow_symlinks=False)
    directory_info = secure_directory(directory, mode=0o755, label="created research resolver directory")
    state["resolver_directory_owned"] = True
    state["resolver_directory_dev"] = directory_info.st_dev
    state["resolver_directory_ino"] = directory_info.st_ino
    persist(state_path, state)
    data = resolver_content(config)
    directory_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    fd = os.open("resolv.conf", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644,
                 dir_fd=directory_fd)
    try:
        os.fchmod(fd, 0o644)
        os.fchown(fd, 0, 0)
        with os.fdopen(fd, "wb") as stream:
            fd = -1
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        if fd >= 0:
            os.close(fd)
        os.close(directory_fd)
    file_info = secure_regular(resolv, mode=0o644, label="created research resolver file")
    observed_directory = directory.lstat()
    if (observed_directory.st_dev, observed_directory.st_ino) != (directory_info.st_dev, directory_info.st_ino):
        raise Refused("research resolver directory changed during creation")
    state["resolver_file_owned"] = True
    state["resolver_file_dev"] = file_info.st_dev
    state["resolver_file_ino"] = file_info.st_ino
    state["resolver_sha256"] = sha256(data)
    state["completed_steps"].append("dns")
    state["pending_step"] = ""
    persist(state_path, state)
    failpoint("dns", fail_after)


def validate_resolver_state(config: dict[str, Any], netns_etc: Path, state: dict[str, Any]) -> None:
    directory, resolv = resolver_paths(config, netns_etc)
    directory_info = secure_directory(directory, mode=0o755, label="owned research resolver directory")
    resolver_info, resolver_bytes = read_secure_regular(resolv, mode=0o644, label="owned research resolver file")
    if ((directory_info.st_dev, directory_info.st_ino) !=
            (state.get("resolver_directory_dev"), state.get("resolver_directory_ino"))
            or (resolver_info.st_dev, resolver_info.st_ino) !=
            (state.get("resolver_file_dev"), state.get("resolver_file_ino"))
            or resolver_bytes != resolver_content(config)
            or state.get("resolver_sha256") != sha256(resolver_content(config))):
        raise Refused("owned resolver file differs from approved configuration")


def new_state(config: dict[str, Any], policy: str, *, generation: str, status: str) -> dict[str, Any]:
    if not GENERATION_RE.fullmatch(generation):
        raise Refused("new activation generation is invalid")
    return {"schema": SCHEMA, "kind": config["kind"], "namespace": config["namespace"],
            "activation_id": config["activation_id"], "config_digest": config["config_digest"],
            "generation": generation, "generation_started_at": datetime.now(timezone.utc).isoformat(),
            "status": status, "sequence": 0, "pending_step": "", "completed_steps": [],
            "namespace_owned": False, "marker_owned": False, "host_link_owned": False, "host_table_owned": False,
            "host_policy_sha256": sha256(policy.encode()),
            "resolver_file_owned": False, "resolver_directory_owned": False}


def prepare_resolver(config: dict[str, Any], state_path: Path, netns_etc: Path, *, fail_after: str | None = None) -> dict[str, Any]:
    """Create only the reviewed resolver file before network activation."""
    if config["kind"] != "research" or config["dns_mode"] != "enabled":
        raise Refused("prepare-resolver is only valid for DNS-enabled research")
    preflight(config, state_path, netns_etc)
    existing = read_state(state_path)
    if existing:
        assert_state_owner(existing, config)
        if existing.get("status") == "resolver-prepared":
            validate_resolver_state(config, netns_etc, existing)
            return {"action": "prepare-resolver", "result": "already-prepared", "kind": "research",
                    "namespace": config["namespace"], "generation": existing["generation"], "mutations": 0}
        verify_terminal_generation(config, existing, netns_etc)
    state = begin_generation(config, state_path, netns_etc, status="preparing-resolver")
    try:
        create_resolver(config, netns_etc, state_path, state, fail_after)
        state["status"] = "resolver-prepared"
        persist(state_path, state)
    except BaseException:
        try:
            cleanup(config, state_path, state, netns_etc, "resolver-prepare-failed-cleaned")
        except BaseException as cleanup_error:
            state["status"] = "activation-failed-cleanup-required"
            state["cleanup_error"] = str(cleanup_error)
            persist(state_path, state)
        raise
    return {"action": "prepare-resolver", "result": "prepared", "kind": "research",
            "namespace": config["namespace"], "generation": state["generation"],
            "resolver_sha256": state["resolver_sha256"]}


def ownership_marker(namespace: str) -> str | None:
    result = command(["/usr/sbin/ip", "-j", "-n", namespace, "link", "show", "dev", "lo"], capture=True, check=False)
    if result.returncode:
        return None
    links = json.loads(result.stdout or "[]")
    return links[0].get("ifalias") if links else None


def cleanup(config: dict[str, Any], state_path: Path, state: dict[str, Any], netns_etc: Path, status: str) -> None:
    """Remove only what this activation owns: host veth, namespace, host table, resolver.

    The host end reaches the host namespace already carrying the ownership alias,
    and the host table is created atomically with its ownership comment, so both
    are deleted only on an exact marker match.
    """
    assert_state_owner(state, config)
    generation = state.get("generation")
    expected_marker = marker(config, generation)
    namespace = config["namespace"]
    completed = state.get("completed_steps", [])
    link = host_link(config)
    if link is not None:
        if (link.get("ifalias") == expected_marker and link.get("linkinfo", {}).get("info_kind") == "veth"
                and (state.get("host_link_ifindex") is None or link.get("ifindex") == state.get("host_link_ifindex"))):
            command(host_ip(config, "link", "delete", "dev", config["host_interface"]))
        elif state.get("host_link_owned"):
            raise Refused("host veth ownership marker changed; refusing deletion")
    # A pending command is not proof that it created anything.  In particular,
    # ``ip netns add`` may have failed because a foreign namespace appeared
    # after preflight.  Only a successfully journaled step/ownership flag may
    # authorize deletion; an ambiguous crash window is left for explicit
    # operator reconciliation rather than risking removal of someone else's
    # namespace.
    namespace_owned = state.get("namespace_owned") or "netns" in completed
    marker_owned = state.get("marker_owned") or "marker" in completed
    if namespace in namespace_names() and namespace_owned:
        namespace_path = Path("/run/netns") / namespace
        if state.get("namespace_dev") is not None:
            observed_namespace = namespace_path.lstat()
            if ((observed_namespace.st_dev, observed_namespace.st_ino) !=
                    (state.get("namespace_dev"), state.get("namespace_ino"))):
                raise Refused("namespace inode changed; refusing deletion")
        elif state.get("schema") == SCHEMA:
            raise Refused("current-generation namespace lacks recorded identity; refusing deletion")
        observed = ownership_marker(namespace)
        if marker_owned and observed != expected_marker:
            raise Refused("namespace ownership marker changed; refusing deletion")
        command(["/usr/sbin/ip", "netns", "delete", namespace])
    table = host_table(config)
    if table is not None:
        if table_comment(table) == expected_marker:
            command(host_exec(config, ["/usr/sbin/nft", "delete", "table", "inet", config["host_table"]]))
        elif state.get("host_table_owned"):
            raise Refused("host nft table ownership marker changed; refusing deletion")
    directory, resolv = resolver_paths(config, netns_etc)
    # Likewise, ``pending_step=dns`` does not prove that mkdir/open(O_EXCL)
    # succeeded.  A path created concurrently after preflight is foreign.  The
    # explicit flags are persisted only after this activation creates each
    # object, and are therefore the sole deletion authority.
    if state.get("resolver_file_owned") and resolv.exists():
        info, data = read_secure_regular(resolv, mode=0o644, label="owned research resolver file")
        if (info.st_dev, info.st_ino) != (state.get("resolver_file_dev"), state.get("resolver_file_ino")):
            raise Refused("resolver file inode changed; refusing deletion")
        expected = state.get("resolver_sha256") or sha256(resolver_content(config))
        if sha256(data) != expected:
            raise Refused("resolver ownership content changed; refusing deletion")
        resolv.unlink()
    if state.get("resolver_directory_owned") and directory.exists():
        info = secure_directory(directory, mode=0o755, label="owned research resolver directory")
        if (info.st_dev, info.st_ino) != (state.get("resolver_directory_dev"), state.get("resolver_directory_ino")):
            raise Refused("resolver directory inode changed; refusing deletion")
        try:
            directory.rmdir()
        except OSError as exc:
            raise Refused("owned resolver directory is not empty; refusing broad cleanup") from exc
    state.update({"status": status, "pending_step": "", "namespace_owned": False, "marker_owned": False,
                  "host_link_owned": False, "host_table_owned": False,
                  "resolver_file_owned": False, "resolver_directory_owned": False})
    persist(state_path, state)


def route_commands(config: dict[str, Any], version: int) -> list[list[str]]:
    family, ns, iface = config[f"ipv{version}"], config["namespace"], config["interface"]
    base = ["/usr/sbin/ip", "-n", ns, f"-{version}", "route", "add"]
    if config["kind"] == "research":
        return [[*base, "default", "via", family["gateway"], "dev", iface]]
    return [[*base, address, "via", family["gateway"], "dev", iface]
            for address in sorted({address for address, _port in config["targets"]
                                   if ipaddress.ip_address(address).version == version})]


def diagnostic_overlay_targets(config: dict[str, Any]) -> set[tuple[str, int]]:
    """Return exact targets from the root-owned additive overlay receipt.

    The overlay is optional and production-only.  It is accepted solely when
    bound to this active base activation/config digest and still within its
    explicit authorization lifetime.  Test namespaces therefore retain their
    original exact-set contract.
    """
    if config["kind"] != "diagnostic" or config.get("host_namespace"):
        return set()
    path = PRODUCTION_STATE / "diagnostic-target-overlay.json"
    if not path.exists() and not path.is_symlink():
        return set()
    _info, raw = read_secure_regular(path, mode=0o600, label="diagnostic target overlay receipt")
    try:
        receipt = json.loads(raw)
        expires = datetime.fromisoformat(str(receipt.get("expires_at", "")).replace("Z", "+00:00"))
    except (json.JSONDecodeError, ValueError) as exc:
        raise Refused("diagnostic target overlay receipt is invalid") from exc
    if (not isinstance(receipt, dict) or receipt.get("schema") != "nmas.diagnostic-target-overlay-receipt/1"
            or receipt.get("status") != "active" or receipt.get("base_activation_id") != config["activation_id"]
            or receipt.get("base_config_digest") != config["config_digest"]
            or expires.tzinfo is None or expires.astimezone(timezone.utc) <= datetime.now(timezone.utc)):
        raise Refused("diagnostic target overlay receipt is not active for this base activation")
    targets: set[tuple[str, int]] = set()
    for item in receipt.get("targets", []):
        if not isinstance(item, dict) or set(item) != {"address", "port"} or item.get("port") != 22:
            raise Refused("diagnostic target overlay receipt has an invalid target")
        try:
            address = ipaddress.ip_address(str(item["address"]))
        except ValueError as exc:
            raise Refused("diagnostic target overlay receipt has an invalid address") from exc
        if address.version != 4 or address.is_loopback or address.is_multicast or address.is_unspecified:
            raise Refused("diagnostic target overlay receipt target is not exact unicast IPv4")
        targets.add((str(address), 22))
    if not targets or len(targets) != len(receipt.get("targets", [])):
        raise Refused("diagnostic target overlay receipt is empty or duplicated")
    return targets


def activate(config: dict[str, Any], state_path: Path, netns_etc: Path, *, fail_after: str | None) -> dict[str, Any]:
    report = preflight(config, state_path, netns_etc)
    existing = read_state(state_path)
    if existing and existing.get("status") == "active":
        validate_active(config, state_path, netns_etc)
        return {**report, "action": "activate", "result": "already-active", "mutations": 0}
    if config["kind"] == "research":
        if not existing or existing.get("status") != "resolver-prepared":
            raise Refused("research resolver generation must be prepared before network activation")
        validate_resolver_state(config, netns_etc, existing)
        state = existing
        state["status"] = "activating"
    else:
        if existing:
            verify_terminal_generation(config, existing, netns_etc)
        state = begin_generation(config, state_path, netns_etc, status="activating")
    generation = state["generation"]
    policy = host_policy(config, generation)
    state["host_policy_sha256"] = sha256(policy.encode())
    persist(state_path, state)
    ns, iface, hif = config["namespace"], config["interface"], config["host_interface"]
    ip_ns = ["/usr/sbin/ip", "-n", ns]
    sysctl = ["/usr/sbin/sysctl", "-q", "-w"]

    def step(name: str, *commands: list[str], stdin: str | None = None) -> None:
        run_step(state_path, state, name, list(commands), fail_after=fail_after, stdin=stdin)

    try:
        state["pending_step"] = "netns"
        persist(state_path, state)
        command(["/usr/sbin/ip", "netns", "add", ns])
        namespace_info = (Path("/run/netns") / ns).lstat()
        state["namespace_owned"] = True
        state["namespace_dev"] = namespace_info.st_dev
        state["namespace_ino"] = namespace_info.st_ino
        state["completed_steps"].append("netns")
        state["pending_step"] = ""
        persist(state_path, state)
        failpoint("netns", fail_after)
        step("marker", [*ip_ns, "link", "set", "lo", "alias", marker(config, generation)])
        state["marker_owned"] = True
        persist(state_path, state)
        step("loopback", [*ip_ns, "link", "set", "lo", "up"])
        step("ipv4_forwarding", ns_exec(config, [*sysctl, "net.ipv4.ip_forward=0"]))
        step("ipv6_forwarding", ns_exec(config, [*sysctl, "net.ipv6.conf.all.forwarding=0"]))
        step("accept_ra", ns_exec(config, [*sysctl, "net.ipv6.conf.all.accept_ra=0", "net.ipv6.conf.default.accept_ra=0"]))
        if not config["ipv6"]:
            step("ipv6_disable", ns_exec(config, [*sysctl, "net.ipv6.conf.all.disable_ipv6=1",
                                                  "net.ipv6.conf.default.disable_ipv6=1"]))
        # Both policies are in force before any link exists, so there is never an
        # unfiltered moment on either side of the veth.
        step("nft", ns_exec(config, ["/usr/sbin/nft", "-f", config["nft_policy"]]))
        step("host_nft", host_exec(config, ["/usr/sbin/nft", "-f", "-"]), stdin=policy)
        state["host_table_owned"] = True
        persist(state_path, state)
        # The pair is created and marked inside the owned namespace; the host end
        # only enters the host namespace already carrying the ownership alias.
        step("link", [*ip_ns, "link", "add", "name", hif, "type", "veth", "peer", "name", iface],
             [*ip_ns, "link", "set", "dev", iface, "addrgenmode", "none"])
        step("host_marker", [*ip_ns, "link", "set", "dev", hif, "alias", marker(config, generation)])
        step("host_move", [*ip_ns, "link", "set", "dev", hif, "netns", config["host_namespace"] or "1"])
        moved_link = host_link(config)
        if moved_link is None:
            raise Refused("owned host veth is missing after namespace move")
        state["host_link_owned"] = True
        state["host_link_ifindex"] = moved_link.get("ifindex")
        persist(state_path, state)
        for version in (4, 6):
            family = config[f"ipv{version}"]
            if not family:
                continue
            nodad = ["nodad"] if version == 6 else []
            prefix = ipaddress.ip_interface(family["source"]).network.prefixlen
            step(f"ipv{version}_address", [*ip_ns, "address", "add", family["source"], "dev", iface, *nodad])
            step(f"ipv{version}_host_address",
                 host_ip(config, "address", "add", f"{family['gateway']}/{prefix}", "dev", hif, *nodad))
        # A namespace move resets IPv6 address generation, so it is switched off
        # again before the host end comes up: no link-local address ever appears.
        step("host_up", host_ip(config, "link", "set", "dev", hif, "addrgenmode", "none"),
             host_ip(config, "link", "set", "dev", hif, "up"))
        step("interface", [*ip_ns, "link", "set", "dev", iface, "up"])
        for version in (4, 6):
            if config[f"ipv{version}"]:
                step(f"ipv{version}_route", *route_commands(config, version))
        if config["dns_mode"] == "enabled" and not state.get("resolver_file_owned"):
            raise Refused("research resolver ownership disappeared during network activation")
        state["status"] = "active"
        persist(state_path, state)
        validate_active(config, state_path, netns_etc)
        return {"action": "activate", "result": "activated", "kind": config["kind"], "namespace": ns,
                "activation_id": config["activation_id"], "config_digest": config["config_digest"],
                "generation": generation, "host_policy_sha256": state["host_policy_sha256"]}
    except BaseException:
        try:
            cleanup(config, state_path, state, netns_etc, "activation-failed-cleaned")
        except BaseException as cleanup_error:
            state["status"] = "activation-failed-cleanup-required"
            state["cleanup_error"] = str(cleanup_error)
            persist(state_path, state)
        raise


def link_addresses(argv: list[str]) -> set[str]:
    return {info["local"] + "/" + str(info["prefixlen"]) for link in run_json(argv) for info in link.get("addr_info", [])}


def validate_active(config: dict[str, Any], state_path: Path, netns_etc: Path) -> dict[str, Any]:
    state = read_state(state_path)
    if not state:
        raise Refused("no ownership state exists")
    assert_state_owner(state, config)
    if state.get("status") != "active" or not state.get("namespace_owned"):
        raise Refused("selected activation is not active")
    generation = state.get("generation")
    if not GENERATION_RE.fullmatch(str(generation or "")):
        raise Refused("active namespace generation is invalid")
    expected_marker = marker(config, generation)
    ns, iface, hif = config["namespace"], config["interface"], config["host_interface"]
    if ns not in namespace_names() or ownership_marker(ns) != expected_marker:
        raise Refused("namespace or ownership marker is missing")
    namespace_info = (Path("/run/netns") / ns).lstat()
    if ((namespace_info.st_dev, namespace_info.st_ino) !=
            (state.get("namespace_dev"), state.get("namespace_ino"))):
        raise Refused("namespace identity differs from the activation receipt")
    links = run_json(["/usr/sbin/ip", "-j", "-n", ns, "-d", "link", "show"])
    if any("UP" in link.get("flags", []) for link in links if link["ifname"] not in {"lo", iface}):
        raise Refused("namespace has an active interface other than loopback and the owned veth")
    if next(link for link in links if link["ifname"] == iface).get("linkinfo", {}).get("info_kind") != "veth":
        raise Refused("owned namespace interface is not a veth")
    host_end = host_link(config)
    if (host_end is None or host_end.get("ifalias") != expected_marker
            or host_end.get("linkinfo", {}).get("info_kind") != "veth" or host_end.get("master")):
        raise Refused("owned host veth is missing, unmarked, bridged or has the wrong type")
    if host_end.get("ifindex") != state.get("host_link_ifindex"):
        raise Refused("host veth identity differs from the activation receipt")
    addresses = link_addresses(["/usr/sbin/ip", "-j", "-n", ns, "address", "show", "dev", iface])
    host_addresses = link_addresses(host_ip(config, "-j", "address", "show", "dev", hif))
    expected, host_expected = set(), set()
    overlay_targets = diagnostic_overlay_targets(config)
    for version, key in ((4, "net.ipv4.ip_forward"), (6, "net.ipv6.conf.all.forwarding")):
        family = config[f"ipv{version}"]
        routes = [route for route in run_json(["/usr/sbin/ip", "-j", "-n", ns, f"-{version}", "route", "show"])
                  if route.get("gateway") or route.get("dst") == "default"]
        observed = sorted((route["dst"], route.get("gateway"), route.get("dev")) for route in routes)
        wanted: list[tuple[str, str, str]] = []
        if family:
            prefix = ipaddress.ip_interface(family["source"]).network.prefixlen
            expected.add(family["source"])
            host_expected.add(f"{family['gateway']}/{prefix}")
            if config["kind"] == "research":
                wanted = [("default", family["gateway"], iface)]
            else:
                combined_targets = {(address, port) for address, port in config["targets"]} | overlay_targets
                wanted = sorted({(address, family["gateway"], iface) for address, _port in combined_targets
                                 if ipaddress.ip_address(address).version == version})
            if host_sysctl(config, key) != "1":
                raise Refused(f"host IPv{version} forwarding changed since activation")
        if observed != wanted:
            raise Refused(f"IPv{version} namespace routes differ from the approved exact set")
    if addresses != expected or host_addresses != host_expected:
        raise Refused("veth addresses differ from the approved VM-local link")
    for key in ("net.ipv4.ip_forward", "net.ipv6.conf.all.forwarding", "net.ipv6.conf.all.accept_ra"):
        value = command(ns_exec(config, ["/usr/sbin/sysctl", "-n", key]), capture=True).stdout.strip()
        if value != "0":
            raise Refused(f"namespace sysctl is unexpectedly enabled: {key}")
    ruleset = json.loads(command(ns_exec(config, ["/usr/sbin/nft", "-j", "list", "ruleset"]), capture=True).stdout)
    objects = ruleset.get("nftables", [])
    tables = [(item["table"].get("family"), item["table"].get("name")) for item in objects if "table" in item]
    if tables != [("inet", config["table"])]:
        raise Refused("namespace nft table set differs from the single approved table")
    chains = {item["chain"]["name"]: item["chain"].get("policy") for item in objects if "chain" in item}
    if chains != {"input": "drop", "forward": "drop", "output": "drop"}:
        raise Refused("namespace must have separate default-drop input, forward and output chains")
    table = host_table(config)
    if table is None or table_comment(table) != expected_marker:
        raise Refused("owned host nft table is missing or its ownership marker changed")
    hooks = {item["chain"]["name"]: item["chain"].get("hook") for item in table if "chain" in item}
    if hooks != {"input": "input", "output": "output", "forward": "forward", "postrouting": "postrouting"}:
        raise Refused("owned host nft table chains differ from the generated policy")
    if state.get("host_policy_sha256") != sha256(host_policy(config, generation).encode()):
        raise Refused("generated host policy differs from the activated policy")
    if config["kind"] == "diagnostic":
        approved = {(address, port) for address, port in config["targets"]} | overlay_targets
        for source, label in ((objects, "namespace"), (table, "host")):
            if set_elements(source, "targets4") | set_elements(source, "targets6") != approved:
                raise Refused(f"{label} diagnostic target set differs from the approved exact targets")
    else:
        approved = {(address, port) for address, port in config["https_targets"]}
        for source, label in ((objects, "namespace"), (table, "host")):
            if set_elements(source, "https4") | set_elements(source, "https6") != approved:
                raise Refused(f"{label} research HTTPS set differs from the approved exact targets")
        approved_dns = set(config["dns_servers"])
        for source, label in ((objects, "namespace"), (table, "host")):
            if address_set_elements(source, "dns4") | address_set_elements(source, "dns6") != approved_dns:
                raise Refused(f"{label} research DNS set differs from the approved exact resolvers")
    if config["dns_mode"] == "enabled":
        validate_resolver_state(config, netns_etc, state)
    return {"action": "validate", "result": "valid", "kind": config["kind"], "namespace": ns,
            "activation_id": config["activation_id"], "config_digest": config["config_digest"]}


def deactivate(config: dict[str, Any], state_path: Path, netns_etc: Path, status: str) -> dict[str, Any]:
    state = read_state(state_path)
    if not state:
        if config["namespace"] in namespace_names():
            raise Refused("namespace exists without ownership state; refusing deletion")
        return {"action": status, "result": "already-absent", "kind": config["kind"],
                "namespace": config["namespace"], "mutations": 0}
    assert_state_owner(state, config)
    directory, resolv = resolver_paths(config, netns_etc)
    owned_flags = ("namespace_owned", "pending_step", "host_link_owned", "host_table_owned", "resolver_file_owned",
                   "resolver_directory_owned")
    if (state.get("status") == status and not any(state.get(flag) for flag in owned_flags)
            and config["namespace"] not in namespace_names() and not resolv.exists() and not directory.exists()):
        return {"action": status, "result": f"already-{status}", "kind": config["kind"],
                "namespace": config["namespace"], "activation_id": config["activation_id"],
                "config_digest": config["config_digest"], "mutations": 0}
    cleanup(config, state_path, state, netns_etc, status)
    return {"action": status, "result": status, "kind": config["kind"], "namespace": config["namespace"],
            "activation_id": config["activation_id"], "config_digest": config["config_digest"]}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("action", choices=("preflight", "service-preflight", "prepare-resolver", "activate", "validate", "deactivate", "rollback", "host-policy"))
    parser.add_argument("namespace", choices=tuple(KINDS))
    parser.add_argument("config", type=Path)
    parser.add_argument("--test-root", type=Path, help=argparse.SUPPRESS)
    parser.add_argument("--fail-after", choices=STEPS, help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    test_mode = args.test_root is not None
    if args.fail_after and not test_mode:
        raise Refused("failure injection is test-only")
    state_root, netns_etc = ensure_test_paths(args.test_root)
    config = normalized_config(args.config, args.namespace, test_mode=test_mode)
    state_path = state_root / f"{args.namespace}.json"
    if args.action == "host-policy":
        sys.stdout.write(host_policy(config))
        return 0
    if args.action == "preflight":
        print(json.dumps(preflight(config, state_path, netns_etc), sort_keys=True))
        return 0
    if args.action == "service-preflight":
        if os.geteuid() != 0:
            raise Refused("research service preflight requires root")
        print(json.dumps(service_preflight(config, args.config, netns_etc), sort_keys=True))
        return 0
    if os.geteuid() != 0:
        raise Refused("mutating namespace actions require root")
    state_root.mkdir(mode=0o700, parents=True, exist_ok=True)
    if state_root.is_symlink() or not state_root.is_dir():
        raise Refused("state directory is unsafe")
    state_info = state_root.stat()
    if state_info.st_uid != 0 or state_info.st_mode & 0o077:
        raise Refused("state directory must be root-owned and inaccessible to group/other")
    lock_path = state_root / f"{args.namespace}.lock"
    lock_fd = os.open(lock_path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(lock_fd, fcntl.LOCK_EX)
        if args.action == "prepare-resolver":
            result = prepare_resolver(config, state_path, netns_etc, fail_after=args.fail_after)
        elif args.action == "activate":
            result = activate(config, state_path, netns_etc, fail_after=args.fail_after)
        elif args.action == "validate":
            result = validate_active(config, state_path, netns_etc)
        else:
            result = deactivate(config, state_path, netns_etc, args.action)
        print(json.dumps(result, sort_keys=True))
        return 0
    finally:
        os.close(lock_fd)


def _signal(signum: int, _frame: Any) -> None:
    raise Refused(f"interrupted by signal {signum}")


if __name__ == "__main__":
    for signal_number in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        signal.signal(signal_number, _signal)
    try:
        raise SystemExit(main())
    except Refused as exc:
        print(f"REFUSED: {exc}", file=sys.stderr)
        raise SystemExit(65)
