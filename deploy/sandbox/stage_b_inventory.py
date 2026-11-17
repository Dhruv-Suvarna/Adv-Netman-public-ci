#!/usr/bin/env python3
"""Read-only Stage B inventory-to-ManagementPath eligibility report."""

from __future__ import annotations

import argparse
import ipaddress
import json
from pathlib import Path
import sqlite3

import yaml


SUPPORTED_PATH_PLATFORMS = frozenset({"ceos"})
ADMITTED = frozenset({"ADMITTED", "LEGACY_PREEXISTING"})


def _database(path: Path) -> sqlite3.Connection:
    return sqlite3.connect(f"file:{path.resolve()}?mode=ro&immutable=1", uri=True)


def _ceos_interface(name: str) -> str:
    return "Ethernet" + name[3:] if name.startswith("eth") and name[3:].isdigit() else name


def _direct_links(topology_path: Path | None, upstream: str) -> dict[str, dict[str, str]]:
    if topology_path is None:
        return {}
    topology = yaml.safe_load(topology_path.read_text(encoding="utf-8")) or {}
    result = {}
    for link in (topology.get("topology") or {}).get("links") or []:
        endpoints = link.get("endpoints") if isinstance(link, dict) else None
        if not isinstance(endpoints, list) or len(endpoints) != 2:
            continue
        parsed = []
        for endpoint in endpoints:
            node, separator, interface = str(endpoint).partition(":")
            if not separator:
                break
            parsed.append((node, interface))
        if len(parsed) != 2:
            continue
        left, right = parsed
        if left[0] == upstream and right[0] != upstream:
            result[right[0]] = {"local_interface": _ceos_interface(right[1]),
                                "upstream_interface": _ceos_interface(left[1])}
        elif right[0] == upstream and left[0] != upstream:
            result[left[0]] = {"local_interface": _ceos_interface(left[1]),
                               "upstream_interface": _ceos_interface(right[1])}
    return result


def report(inventory_path: Path, database_path: Path, topology_path: Path | None = None) -> dict:
    inventory = yaml.safe_load(inventory_path.read_text(encoding="utf-8")) or {}
    management = inventory.get("management") or {}
    management_upstream = str(management.get("upstream_device") or "").strip()
    direct_links = _direct_links(topology_path, management_upstream)
    networks = []
    for key in ("nmas_ipv4", "nmas_ipv6"):
        if management.get(key):
            networks.append(ipaddress.ip_interface(management[key]).network)
    db = _database(database_path)
    db.row_factory = sqlite3.Row
    managed = {row["name"]: dict(row) for row in db.execute(
        "SELECT id,name,platform,lifecycle_state,identity_state,admission_state,verified_host_key "
        "FROM core_manageddevice ORDER BY name"
    )}
    approved_nmas_attachments = db.execute(
        "SELECT COUNT(*) FROM core_nmasmanagementattachment WHERE approval_state='APPROVED' AND verification_state='VERIFIED'"
    ).fetchone()[0]
    approved_device_attachments = {row[0] for row in db.execute(
        "SELECT device_id FROM core_deviceattachment WHERE purpose='MANAGEMENT' AND approval_state='APPROVED' "
        "AND verification_state='VERIFIED'"
    )}
    paths = list(db.execute(
        "SELECT p.id,d.name,p.endpoint_address,p.port,p.transport,p.approval_state,p.health_state,p.is_active,"
        "p.expected_host_key FROM core_managementpath p JOIN core_manageddevice d ON d.id=p.device_id"
    ))
    approved = []
    for path in paths:
        if (path["approval_state"] == "APPROVED" and path["health_state"] == "HEALTHY" and path["is_active"]
                and path["transport"] == "SSH" and path["expected_host_key"]):
            approved.append({"device": path["name"], "address": path["endpoint_address"], "port": path["port"],
                             "path_id": f"MPATH-{path['id']:06d}"})
    candidates, unsupported, excluded = [], [], []
    for name, entry in sorted((inventory.get("network_devices") or {}).items()):
        entry = entry or {}
        monitoring = entry.get("monitoring") or {}
        platform, address = str(monitoring.get("platform") or ""), monitoring.get("address")
        if entry.get("edge") or name == "R5":
            excluded.append({"device": name, "reason": "inventory edge/read-only scope"})
            continue
        if platform not in SUPPORTED_PATH_PLATFORMS:
            unsupported.append({"device": name, "platform": platform,
                                "reason": "ManagementPath verifier and diagnostic SSH consumer are not implemented"})
            continue
        if name == management_upstream:
            unsupported.append({"device": name, "platform": platform,
                                "reason": "current ManagementPath schema has no truthful direct host-to-same-switch path shape"})
            continue
        blockers = []
        row = managed.get(name)
        if row is None:
            blockers.append("NOT_ADOPTED")
        else:
            if row["lifecycle_state"] != "IN_SERVICE":
                blockers.append("LIFECYCLE_NOT_IN_SERVICE")
            if row["admission_state"] not in ADMITTED:
                blockers.append("NOT_ADMITTED")
            if row["identity_state"] != "VERIFIED":
                blockers.append("IDENTITY_UNVERIFIED")
            if not row["verified_host_key"]:
                blockers.append("HOST_KEY_NOT_ENROLLED")
        if not approved_nmas_attachments:
            blockers.append("NMAS_ATTACHMENT_NOT_APPROVED")
        if row is None or row["id"] not in approved_device_attachments:
            blockers.append("DEVICE_MANAGEMENT_ATTACHMENT_NOT_APPROVED")
        try:
            endpoint = ipaddress.ip_address(address)
        except ValueError:
            blockers.append("STATIC_MANAGEMENT_ADDRESS_INVALID")
            endpoint = None
        if endpoint is not None and not any(endpoint.version == net.version and endpoint in net for net in networks):
            blockers.append("STATIC_MANAGEMENT_ADDRESS_OUTSIDE_NMAS_NETWORK")
        if not (entry.get("credential_ref") and entry.get("username")):
            blockers.append("DEDICATED_CREDENTIAL_REFERENCE_MISSING")
        link = direct_links.get(name)
        if topology_path is not None and link is None:
            blockers.append("DIRECT_MANAGEMENT_ATTACHMENT_NOT_IN_FROZEN_TOPOLOGY")
        candidates.append({"device": name, "platform": platform, "address": str(endpoint) if endpoint else str(address),
                           "port": 22, "transport": "SSH", "path_type": "DIRECT_OOB",
                           "local_interface": link["local_interface"] if link else "",
                           "via_device": management_upstream,
                           "upstream_interface": link["upstream_interface"] if link else "",
                           "credential_source": "INVENTORY", "credential_reference": name,
                           "route_basis": "authoritative static inventory address plus frozen topology attachment on nmas-mgmt",
                           "blockers": blockers, "approval_ready": not blockers})
    return {"schema": "nmas.stage-b-diagnostic-eligibility/1", "inventory": str(inventory_path.resolve()),
            "topology": str(topology_path.resolve()) if topology_path else None,
            "database": str(database_path.resolve()), "approved_eligible": sorted(approved, key=lambda row: row["device"]),
            "candidate_batch": candidates, "managed_but_path_unsupported": unsupported, "excluded": excluded,
            "approved_verified_nmas_attachments": approved_nmas_attachments,
            "governance": {"discovery_is_approval": False, "self_approval_allowed": False,
                           "required_path_state": "APPROVED+HEALTHY+ACTIVE+pinned SSH"}}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--inventory", type=Path, required=True)
    parser.add_argument("--topology", type=Path, required=True)
    parser.add_argument("--database", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    value = report(args.inventory, args.database, args.topology)
    text = json.dumps(value, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(text, encoding="utf-8")
    else:
        print(text, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
