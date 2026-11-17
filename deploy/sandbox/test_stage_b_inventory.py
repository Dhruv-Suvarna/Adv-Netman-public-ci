#!/usr/bin/env python3
"""Disposable eligibility tests: inventory authority, admission and exclusions."""

from __future__ import annotations

import importlib.util
from pathlib import Path
import sqlite3
import tempfile


HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("stage_b_inventory", HERE / "stage_b_inventory.py")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="nmas-stage-b-inventory-") as temporary:
        root = Path(temporary)
        inventory = root / "inventory.yml"
        inventory.write_text("""management:
  nmas_ipv4: 192.168.200.100/24
  upstream_device: mgmt_swt
network_devices:
  R1: {username: worker, credential_ref: 'runtime://r1', monitoring: {platform: ceos, address: 192.168.200.1}}
  R2: {username: worker, credential_ref: 'runtime://r2', monitoring: {platform: ceos, address: 192.168.200.2}}
  R3: {username: worker, ssh_key_ref: 'runtime://r3', monitoring: {platform: linux, address: 192.168.200.3}}
  R5: {edge: true, monitoring: {platform: ceos, address: auto}}
  mgmt_swt: {username: worker, credential_ref: 'runtime://mgmt', monitoring: {platform: ceos, address: 192.168.200.10}}
hosts: {H1: {ipv4: true}}
""", encoding="utf-8")
        topology = root / "topology.yml"
        topology.write_text("""topology:
  links:
    - endpoints: [mgmt_swt:eth1, R1:eth3]
    - endpoints: [mgmt_swt:eth2, R2:eth3]
""", encoding="utf-8")
        database = root / "db.sqlite3"
        db = sqlite3.connect(database)
        db.executescript("""
CREATE TABLE core_manageddevice(id INTEGER PRIMARY KEY,name TEXT,platform TEXT,lifecycle_state TEXT,identity_state TEXT,admission_state TEXT,verified_host_key TEXT);
CREATE TABLE core_managementpath(id INTEGER PRIMARY KEY,device_id INTEGER,endpoint_address TEXT,port INTEGER,transport TEXT,approval_state TEXT,health_state TEXT,is_active INTEGER,expected_host_key TEXT);
CREATE TABLE core_nmasmanagementattachment(id INTEGER PRIMARY KEY,approval_state TEXT,verification_state TEXT);
CREATE TABLE core_deviceattachment(id INTEGER PRIMARY KEY,device_id INTEGER,purpose TEXT,approval_state TEXT,verification_state TEXT);
INSERT INTO core_manageddevice VALUES(1,'R1','arista_ceos','IN_SERVICE','VERIFIED','LEGACY_PREEXISTING','SHA256:test');
INSERT INTO core_manageddevice VALUES(2,'R2','arista_ceos','IN_SERVICE','UNVERIFIED','LEGACY_PREEXISTING','');
INSERT INTO core_manageddevice VALUES(3,'R9','arista_ceos','IN_SERVICE','VERIFIED','ADMITTED','SHA256:outside');
INSERT INTO core_managementpath VALUES(1,1,'192.168.200.1',22,'SSH','APPROVED','HEALTHY',1,'SHA256:test');
INSERT INTO core_nmasmanagementattachment VALUES(1,'APPROVED','VERIFIED');
INSERT INTO core_deviceattachment VALUES(1,1,'MANAGEMENT','APPROVED','VERIFIED');
""")
        db.commit(); db.close()
        value = MODULE.report(inventory, database, topology)
        assert value["approved_eligible"] == [{"device": "R1", "address": "192.168.200.1", "port": 22,
                                                "path_id": "MPATH-000001"}]
        rows = {row["device"]: row for row in value["candidate_batch"]}
        assert rows["R1"]["approval_ready"]
        assert (rows["R1"]["local_interface"], rows["R1"]["upstream_interface"], rows["R1"]["via_device"]) == \
               ("Ethernet3", "Ethernet1", "mgmt_swt")
        assert rows["R2"]["blockers"] == ["IDENTITY_UNVERIFIED", "HOST_KEY_NOT_ENROLLED",
                                           "DEVICE_MANAGEMENT_ATTACHMENT_NOT_APPROVED"]
        unsupported = {row["device"]: row["reason"] for row in value["managed_but_path_unsupported"]}
        assert set(unsupported) == {"R3", "mgmt_swt"}
        assert "same-switch path shape" in unsupported["mgmt_swt"]
        assert value["excluded"] == [{"device": "R5", "reason": "inventory edge/read-only scope"}]
        assert "R9" not in rows and all(row["device"] != "R9" for row in value["approved_eligible"])
    print("PASS: authoritative inventory, admission, platform and exclusion eligibility tests")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
