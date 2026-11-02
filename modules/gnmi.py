"""gNMI/gRPC IaC and persistent streaming collector lifecycle for all ten
monitored devices.

The eight cEOS nodes use their native gNMI implementation. R3/R4 have no
native server and use the explicitly labelled repository-owned Linux/FRR lab
adapter; see docs/STREAMING_TELEMETRY_IMPLEMENTATION.md.

Mirrors modules/snmp.py's/modules/syslog.py's structure: reuse their
low-level docker/CLI plumbing rather than duplicating it.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import time

import yaml
from jinja2 import Environment, FileSystemLoader, StrictUndefined

from modules.monitoring_config import load_gnmi_paths
from modules.nmas import BASE, MONITORING, VENV, NmasError, verify_nmas
from modules.snmp import cli, command, docker, influx

RUNTIME = MONITORING / "runtime"
SSL_PROFILE = "NMAS_GNMI"
TELEMETRY_USERNAME = "nmas-telemetry"
PATHS_CONFIG = load_gnmi_paths()   # validated: a malformed gnmi_paths.yml fails here, not on the collector host


def devices():
    """All monitored network devices, including the R3/R4 lab adapters."""
    inventory = yaml.safe_load((BASE / "inventory.yml").read_text())
    result = []
    for name, meta in inventory["network_devices"].items():
        if "monitoring" not in meta:
            raise NmasError(f"{name}: monitoring metadata missing")
        item = dict(meta["monitoring"], device=name, container="clab-" + inventory["lab_name"] + "-" + name)
        if item["platform"] not in ("ceos", "linux"):
            raise NmasError(f"{name}: unsupported telemetry platform")
        info = json.loads(docker("inspect", item["container"]))[0]
        if not info["State"]["Running"]:
            raise NmasError(f"{name}: container is not running")
        if item["address"] == "auto":
            item["address"] = next(n["IPAddress"] for n in info["NetworkSettings"]["Networks"].values() if n.get("IPAddress", "").startswith("172.20.20."))
        result.append(item)
    return result


def render(name, context):
    return Environment(loader=FileSystemLoader(BASE / "templates/monitoring"), undefined=StrictUndefined).get_template(name).render(**context) + "\n"


def protected_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as stream:
        json.dump(value, stream, indent=2)
    path.chmod(0o600)


def credentials(create=False):
    path = RUNTIME / "telemetry-secrets.json"
    if not path.exists() and create:
        protected_json(path, {"password": secrets.token_urlsafe(24)})
    if not path.is_file() or path.is_symlink() or path.stat().st_mode & 0o077:
        raise NmasError("Telemetry credentials missing or insecure; require protected telemetry-secrets.json")
    value = json.loads(path.read_text())
    if not re.fullmatch(r"[A-Za-z0-9_-]{16,64}", value.get("password", "")):
        raise NmasError("Invalid telemetry runtime credentials")
    return value


def profile_state(item):
    text = cli(item, f"show management security ssl profile {SSL_PROFILE}")
    match = re.search(r"^" + re.escape(SSL_PROFILE) + r"\s+(\S+)", text, re.MULTILINE)
    return match.group(1) if match else "absent"


def fetch_ca(item):
    """Save this device's containerlab-generated lab CA (shared root across
    all cEOS nodes in this deployment) so pygnmi/ncclient can validate the
    server certificate. Not a secret -- a public CA certificate -- but kept
    under monitoring/runtime/ alongside other per-device derived material."""
    ca_dir = RUNTIME / "gnmi-ca"
    ca_dir.mkdir(parents=True, exist_ok=True)
    dest = ca_dir / f"{item['device']}.crt"
    if item["platform"] == "linux":
        from modules.linux_telemetry_adapter import fetch_certificate
        return fetch_certificate(item, dest)
    text = docker("exec", item["container"], "cat", "/persist/secure/ssl/certs/ca.crt")
    if "BEGIN CERTIFICATE" not in text:
        raise NmasError(f"{item['device']}: could not read lab CA certificate from the container")
    if not dest.exists() or dest.read_text() != text:
        dest.write_text(text)
    dest.chmod(0o644)
    return dest


def configure_device(item, password):
    if item["platform"] == "linux":
        from modules.linux_telemetry_adapter import configure
        configure(item, TELEMETRY_USERNAME, password)
        fetch_ca(item)
        return
    statefile = RUNTIME / (item["device"] + "-gnmi-state.json")
    security = render("ceos_gnmi_security.j2", {"ssl_profile": SSL_PROFILE, "username": TELEMETRY_USERNAME, "password": password})
    enable = render("ceos_gnmi_enable.j2", {"ssl_profile": SSL_PROFILE})
    desired_hash = hashlib.sha256((security + enable).encode()).hexdigest()

    current = cli(item, "show running-config | section management security\nshow running-config | section management api gnmi\nshow running-config | section username " + TELEMETRY_USERNAME)
    current_hash = hashlib.sha256(current.encode()).hexdigest()
    prior = json.loads(statefile.read_text()) if statefile.exists() else {}
    if prior.get("desired") == desired_hash and prior.get("actual") == current_hash and profile_state(item) == "valid":
        print(item["device"] + ": gNMI TLS/auth unchanged", flush=True)
        return

    # Phase 1: certificate/key binding + dedicated read-only telemetry user.
    # Pushed and confirmed valid *before* Phase 2 assigns it to the gNMI
    # transport -- on this cEOS-lab build, assigning an ssl profile that has
    # not yet finished validating its certificate/key pair disables the
    # entire gNMI server (`Enabled: no`), not just TLS; see
    # docs/STREAMING_TELEMETRY_IMPLEMENTATION.md for the verified evidence.
    cli(item, "configure terminal\n" + security + "end")
    for _ in range(10):
        if profile_state(item) == "valid":
            break
        time.sleep(1)
    else:
        raise NmasError(item["device"] + f": ssl profile {SSL_PROFILE} did not become valid")

    # Phase 2: bind the now-valid profile to the gNMI gRPC transport.
    cli(item, "configure terminal\n" + enable + "end")
    if not re.search(r"Enabled:\s*yes", cli(item, "show management api gnmi")):
        raise NmasError(item["device"] + ": gNMI server did not come up after TLS enablement")

    cli(item, "write memory")
    current = cli(item, "show running-config | section management security\nshow running-config | section management api gnmi\nshow running-config | section username " + TELEMETRY_USERNAME)
    protected_json(statefile, {"desired": desired_hash, "actual": hashlib.sha256(current.encode()).hexdigest()})
    print(item["device"] + ": gNMI TLS/auth converged", flush=True)


def gnmi_target(item):
    ca = fetch_ca(item)
    creds = credentials()
    return {
        "target": (item["address"], 6030),
        "username": TELEMETRY_USERNAME,
        "password": creds["password"],
        "insecure": False,
        "path_root": str(ca),
        "override": item["device"],
        "gnmi_timeout": 15,
    }


def verify_capabilities_and_get(item):
    from pygnmi.client import gNMIclient
    with gNMIclient(**gnmi_target(item)) as gc:
        cap = gc.capabilities()
        models = cap.get("supported_models", [])
        if not models:
            raise NmasError(item["device"] + ": gNMI Capabilities returned no supported models")
        got = gc.get(path=["/system/state/hostname"])
        hostname = got["notification"][0]["update"][0]["val"]
        if hostname != item["device"]:
            raise NmasError(item["device"] + f": gNMI Get hostname mismatch ({hostname!r})")
        if item["platform"] == "linux":
            cpu = gc.get(path=["/system/cpus/cpu[index=0]/state/total/instant"])
            cpu_value = cpu["notification"][0]["update"][0]["val"]
            if not isinstance(cpu_value, int) or not 0 <= cpu_value <= 100:
                raise NmasError(item["device"] + ": adapter returned invalid CPU state")
            memory = gc.get(path=["/system/memory/state"])
            memory_value = memory["notification"][0]["update"][0]["val"]
            expected_memory = {
                "openconfig-system:physical", "openconfig-system:used",
                "openconfig-system:free", "openconfig-system:reserved",
            }
            if not expected_memory.issubset(memory_value):
                raise NmasError(item["device"] + ": adapter returned incomplete memory state")
            interface = item["source_interface"]
            state = gc.get(path=[f"/interfaces/interface[name={interface}]/state/oper-status"])
            updates = state.get("notification", [{}])[0].get("update", [])
            if len(updates) != 1 or f"interface[name={interface}]" not in updates[0].get("path", ""):
                raise NmasError(item["device"] + ": adapter did not honor the interface PathElem key")
        return len(models)


def verify_subscribe_once(item):
    from pygnmi.client import gNMIclient
    path = (
        f'/interfaces/interface[name={item["source_interface"]}]/state/oper-status'
        if item["platform"] == "linux"
        else "/system/cpus/cpu[index=0]/state/total/instant"
    )
    sub = {
        "subscription": [{"path": path, "mode": "sample", "sample_interval": 5000000000}],
        "mode": "stream",
        "encoding": "json_ietf",
    }
    with gNMIclient(**gnmi_target(item)) as gc:
        it = gc.subscribe(subscribe=sub)
        msg = next(it)
        if not msg.update.update:
            raise NmasError(item["device"] + ": gNMI Subscribe returned an empty update")
        if item["platform"] == "linux":
            interface_keys = [
                elem.key.get("name")
                for update in msg.update.update
                for elem in update.path.elem
                if elem.name == "interface"
            ]
            if interface_keys != [item["source_interface"]]:
                raise NmasError(item["device"] + ": subscribed update lost its interface PathElem key")
        return msg.update.timestamp


def verify_gnmi(items):
    results = []
    failed = []
    print("DEVICE     GNMI  TLS   AUTH  CAPS SUBSCRIBE")
    for item in items:
        try:
            model_count = verify_capabilities_and_get(item)
            ts = verify_subscribe_once(item)
            try:
                bad = dict(gnmi_target(item))
                bad["password"] = "wrong-password"
                from pygnmi.client import gNMIclient
                with gNMIclient(**bad) as gc:
                    gc.capabilities()
            except Exception:
                pass
            else:
                raise NmasError(item["device"] + ": gNMI accepted an incorrect password")
            results.append({"device": item["device"], "models": model_count, "subscribe_timestamp_ns": ts})
            print(f'{item["device"]:<10} PASS  PASS  PASS  PASS PASS', flush=True)
        except Exception as exc:
            failed.append(item["device"])
            print(item["device"] + ": FAIL " + str(exc), flush=True)
    protected_json(RUNTIME / "gnmi-verification.json", results)
    if failed:
        raise NmasError("gNMI verification failed: " + ", ".join(failed))
    return results


def ensure_collector(items):
    creds = credentials()
    _, env = influx()
    devices_payload = []
    for item in items:
        ca = fetch_ca(item)
        devices_payload.append({
            "device": item["device"],
            "platform": item["platform"],
            "address": item["address"],
            "port": 6030,
            "ca_cert": ca.read_text(),
        })
    payload = {
        "python": str(VENV / "bin/python"),
        "collector_script": (MONITORING / "scripts/gnmi_collector.py").read_text(),
        "devices": devices_payload,
        "paths": PATHS_CONFIG,
        "username": TELEMETRY_USERNAME,
        "password": creds["password"],
        "influx_org": env["INFLUXDB_ORG"],
        "influx_bucket": env["INFLUXDB_BUCKET"],
        "influx_token": env["INFLUXDB_TOKEN"],
    }
    script = (MONITORING / "scripts/provision_gnmi_collector.py").read_text()
    print(command(["sudo", "-n", "python3", "-c", script], json.dumps(payload)).strip(), flush=True)


def verify_collector_stream(items, quiet=False):
    """Prove the *persistent daemon* (not just the one-shot verify_gnmi Subscribe
    above) is actually streaming: query InfluxDB for a fresh gnmi_telemetry
    point per device, then query it back to prove storage+retrieval."""
    session, env = influx()
    failed = []
    if not quiet:
        print("DEVICE     STREAM INFLUX")
    required = {
        "system_identity", "system_cpu", "system_memory", "interface_state",
        "interface_counters", "hostname", "cpu_total_pct",
        "mem_physical_bytes", "mem_used_bytes", "mem_free_bytes",
        "mem_reserved_bytes", "oper_status", "admin_status", "in_octets",
        "out_octets", "in_errors", "out_errors", "in_discards", "out_discards",
    }
    for item in items:
        query = (
            f'from(bucket: {json.dumps(env["INFLUXDB_BUCKET"])}) |> range(start: -90s) '
            f'|> filter(fn: (r) => r._measurement == "gnmi_telemetry" and r.device == "{item["device"]}") '
            '|> keep(columns: ["device", "category", "_field", "_value"])'
        )
        r = session.post("http://127.0.0.1:8086/api/v2/query", params={"org": env["INFLUXDB_ORG"]}, headers={"Content-Type": "application/vnd.flux"}, data=query, timeout=15)
        r.raise_for_status()
        missing = sorted(value for value in required if value not in r.text)
        if item["device"] in r.text and not missing:
            if not quiet:
                print(f'{item["device"]:<10} PASS   PASS', flush=True)
        else:
            failed.append(item["device"])
            if not quiet:
                detail = "missing " + ",".join(missing[:4]) if missing else "no fresh point"
                print(f'{item["device"]:<10} FAIL   FAIL ({detail} in the last 90s)', flush=True)
    if failed:
        raise NmasError("gNMI streaming verification failed: " + ", ".join(failed))


def ensure_gnmi_infrastructure(verbose=False):
    verify_nmas(verbose)
    items = devices()
    creds = credentials(create=True)
    for item in items:
        configure_device(item, creds["password"])
    verify_gnmi(items)
    ensure_collector(items)
    time.sleep(25)  # let the daemon complete at least one 20s sample cycle
    verify_collector_stream(items)
    return items
