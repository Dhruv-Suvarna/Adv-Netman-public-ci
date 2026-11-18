#!/usr/bin/env python3
"""Validate an operator-reviewed sandbox manifest and render activation files.

This renderer never discovers targets.  Its input must be an export of exact
authorized inventory/path decisions, reviewed during the change window.  It
refuses excluded devices, protected host addresses, hostnames as device
targets, and empty IPv4/IPv6 policy.  It does not run systemctl, ip, nft or
Docker and therefore is safe to exercise in CI.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
from pathlib import Path


class ManifestRefused(ValueError):
    pass


def validate(manifest: dict) -> tuple[list[tuple[str, int]], list[str], dict[str, list[str]]]:
    if not isinstance(manifest, dict) or not str(manifest.get("topology_id", "")).strip():
        raise ManifestRefused("exact topology_id is required")
    if len(str(manifest.get("inventory_revision", ""))) < 16:
        raise ManifestRefused("inventory_revision is required")
    protected = {str(ipaddress.ip_address(v)) for v in manifest.get("protected_addresses", [])}
    endpoints, devices = [], set()
    for row in manifest.get("approved_targets", []):
        device = str(row.get("device", ""))
        if not device or device == "R5" or row.get("excluded") or row.get("identity_state") != "VERIFIED":
            raise ManifestRefused(f"target {device or '?'} is excluded or unverified")
        if row.get("lifecycle_state") != "IN_SERVICE" or row.get("admission_state") not in {"ADMITTED", "LEGACY_PREEXISTING"}:
            raise ManifestRefused(f"target {device} is not lifecycle-admitted")
        if device in devices:
            raise ManifestRefused(f"duplicate target {device}")
        devices.add(device)
        paths = row.get("approved_paths")
        if paths is None:  # compatibility with the reviewed 190-path candidate; SSH/22 was its only staged transport
            paths = [{"address": value, "port": 22, "transport": "SSH"} for value in row.get("approved_path_endpoints", [])]
        for path in paths:
            if not isinstance(path, dict) or path.get("transport") != "SSH":
                raise ManifestRefused(f"target {device} has a non-SSH or malformed diagnostic path")
            ip = str(ipaddress.ip_address(path.get("address", "")))
            port = path.get("port")
            if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
                raise ManifestRefused(f"target {device} has an invalid management port")
            if ip in protected:
                raise ManifestRefused(f"target {device} resolves to a protected host address")
            endpoints.append((ip, port))
    if not endpoints:
        raise ManifestRefused("at least one exact approved management endpoint is required")
    dns = [str(ipaddress.ip_address(v)) for v in manifest.get("dns_resolvers", [])]
    if not dns:
        raise ManifestRefused("explicit DNS resolvers are required for the research namespace")
    destinations = {}
    for row in manifest.get("research_destinations", []):
        if not isinstance(row, dict):
            raise ManifestRefused("research destinations must be hostname/address records")
        host = str(row.get("hostname", "")).lower().rstrip(".")
        if not host or "/" in host or ":" in host or host in destinations:
            raise ManifestRefused("exact unique research hostnames are required")
        addresses = []
        for value in row.get("addresses", []):
            address = ipaddress.ip_address(value)
            if not address.is_global or address.is_private or address.is_loopback or address.is_link_local \
                    or address.is_multicast or address.is_reserved \
                    or (address.version == 6 and address.ipv4_mapped is not None):
                raise ManifestRefused(f"research destination {host} contains a non-public address")
            addresses.append(str(address))
        if not addresses:
            raise ManifestRefused(f"research destination {host} needs reviewed literal addresses")
        destinations[host] = sorted(set(addresses))
    if not destinations:
        raise ManifestRefused("exact research hostname and address records are required")
    return sorted(set(endpoints)), sorted(set(dns)), dict(sorted(destinations.items()))


def render(manifest: dict, service_template: str, nft_template: str, diagnostic_nft_template: str | None = None) -> dict[str, str]:
    endpoints, dns, destinations = validate(manifest)
    allow = "\n".join(f"IPAddressAllow={ip}/{'32' if ipaddress.ip_address(ip).version == 4 else '128'}" for ip, _port in endpoints)
    service = service_template.replace("@DEVICE_IP_ADDRESS_ALLOW@", allow)
    paths = manifest.get("deployment_paths") or {}
    expected = {
        "@PRODUCTION_DATABASE@": "/home/student/Scripts/clab_dualstack_lab-deploy/web/db.sqlite3",
        "@PRODUCTION_WEB_DIRECTORY@": "/home/student/Scripts/clab_dualstack_lab-deploy/web",
        "@PRODUCTION_INVENTORY@": "/home/student/Scripts/clab_dualstack_lab-deploy/inventory.yml",
        "@DEVICE_CREDENTIAL_STORE@": "/home/student/Scripts/clab_dualstack_lab-deploy/monitoring/runtime/device-credentials/store.json",
    }
    for marker, required in expected.items():
        key = marker.strip("@").lower()
        value = str(paths.get(key) or "")
        if value != required:
            raise ManifestRefused(f"deployment path {key} must equal the reviewed production path")
        service = service.replace(marker, value)
    runtime_template = (Path(__file__).resolve().parent / "nmas-troubleshooter-runtime@.service.in").read_text(encoding="utf-8")
    runtime_service = runtime_template
    for marker, required in expected.items():
        runtime_service = runtime_service.replace(marker, required)
    research_service = (Path(__file__).resolve().parent / "nmas-research-broker.service.in").read_text(encoding="utf-8")
    dns4_values = ", ".join(ip for ip in dns if ipaddress.ip_address(ip).version == 4)
    dns6_values = ", ".join(ip for ip in dns if ipaddress.ip_address(ip).version == 6)
    dns4 = f"elements = {{ {dns4_values} }}" if dns4_values else ""
    dns6 = f"elements = {{ {dns6_values} }}" if dns6_values else ""
    https = sorted({address for values in destinations.values() for address in values})
    https4_values = ", ".join(f"{ip} . 443" for ip in https if ipaddress.ip_address(ip).version == 4)
    https6_values = ", ".join(f"{ip} . 443" for ip in https if ipaddress.ip_address(ip).version == 6)
    https4 = f"elements = {{ {https4_values} }}" if https4_values else ""
    https6 = f"elements = {{ {https6_values} }}" if https6_values else ""
    nft = (nft_template.replace("@DNS4@", dns4).replace("@DNS6@", dns6)
           .replace("@HTTPS4@", https4).replace("@HTTPS6@", https6))
    template = diagnostic_nft_template or (Path(__file__).resolve().parent / "diagnostic-egress.nft.in").read_text(encoding="utf-8")
    targets4_values = ", ".join(f"{ip} . {port}" for ip, port in endpoints if ipaddress.ip_address(ip).version == 4)
    targets6_values = ", ".join(f"{ip} . {port}" for ip, port in endpoints if ipaddress.ip_address(ip).version == 6)
    targets4 = f"elements = {{ {targets4_values} }}" if targets4_values else ""
    targets6 = f"elements = {{ {targets6_values} }}" if targets6_values else ""
    diagnostic_nft = template.replace("@TARGETS4@", targets4).replace("@TARGETS6@", targets6)
    env = "NMAS_TS_RESEARCH_ALLOWED_DESTINATIONS=" + json.dumps(destinations, separators=(",", ":")) + "\n"
    # The namespace controller routes and host-filters exactly these tuples; it never falls back to a default route.
    targets = "TARGETS=" + " ".join(f"tcp:{ip}:{port}" if ipaddress.ip_address(ip).version == 4 else f"tcp:[{ip}]:{port}"
                                    for ip, port in endpoints) + "\n"
    https_targets = "HTTPS_TARGETS=" + " ".join(
        f"tcp:{ip}:443" if ipaddress.ip_address(ip).version == 4 else f"tcp:[{ip}]:443" for ip in https) + "\n"
    return {"nmas-troubleshooter-device-worker.service": service,
            "nmas-troubleshooter-runtime@.service": runtime_service,
            "nmas-research-broker.service": research_service,
            "nmas-troubleshooter.sysusers": (Path(__file__).resolve().parent / "nmas-troubleshooter.sysusers.in").read_text(encoding="utf-8"),
            "diagnostic-egress.nft": diagnostic_nft,
            "diagnostic-targets.env": targets,
            "research-egress.nft": nft, "research-allowlist.env": env,
            "research-targets.env": https_targets}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    base = Path(__file__).resolve().parent
    manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
    rendered = render(manifest, (base / "nmas-troubleshooter-device-worker.service.in").read_text(encoding="utf-8"),
                      (base / "research-egress.nft.in").read_text(encoding="utf-8"))
    args.output.mkdir(mode=0o700, parents=True, exist_ok=False)
    for name, text in rendered.items():
        path = args.output / name
        path.write_text(text, encoding="utf-8")
        path.chmod(0o600)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
