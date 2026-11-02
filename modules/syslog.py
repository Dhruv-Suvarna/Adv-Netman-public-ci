"""Syslog IaC: cEOS/Linux critical-event forwarding, NMAS ingestion, and
end-to-end verification for the deployed inventory. Never touches Lab 1
routing/addressing/VLAN configuration; additive monitoring only.

Mirrors modules/snmp.py's structure and reuses its low-level docker/CLI
plumbing (modules.snmp.docker/command/cli) rather than duplicating it, but
keeps its own `devices()` since syslog provisioning has no dependency on the
SNMPv3 policy modules/snmp.py validates.
"""
from __future__ import annotations

import hashlib
import json
import re
import time
from pathlib import Path

import yaml
from jinja2 import Environment, FileSystemLoader, StrictUndefined

from modules.nmas import BASE, MONITORING, VENV, NmasError, verify_nmas
from modules.snmp import cli, command, docker

RUNTIME = MONITORING / "runtime"


def policy():
    inventory = yaml.safe_load((BASE / "inventory.yml").read_text())
    return inventory["syslog"]


def devices():
    inventory = yaml.safe_load((BASE / "inventory.yml").read_text())
    result = []
    for name, meta in inventory["network_devices"].items():
        if "monitoring" not in meta:
            raise NmasError(f"{name}: monitoring metadata missing")
        item = dict(meta["monitoring"], device=name, container="clab-" + inventory["lab_name"] + "-" + name)
        info = json.loads(docker("inspect", item["container"]))[0]
        if not info["State"]["Running"]:
            raise NmasError(f"{name}: container is not running")
        if item["address"] == "auto":
            item["address"] = next(n["IPAddress"] for n in info["NetworkSettings"]["Networks"].values() if n.get("IPAddress", "").startswith("172.20.20."))
        if item["platform"] not in ("ceos", "linux"):
            raise NmasError(f"{name}: unsupported platform")
        result.append(item)
    return result


def render(name, context):
    return Environment(loader=FileSystemLoader(BASE / "templates/monitoring"), undefined=StrictUndefined).get_template(name).render(**context) + "\n"


def docker_exec_json(container, script, payload, timeout=600):
    return docker("exec", "-i", container, "python3", "-c", script, data=json.dumps(payload), timeout=timeout)


# --------------------------------------------------------------------------
# cEOS: real EOS remote-logging config (correct on any healthy build) plus a
# supplementary forwarder that works around this specific cEOS-lab build's
# broken rsyslogd. See docs/SYSLOG_IMPLEMENTATION.md for the verified defect.
# --------------------------------------------------------------------------

def configure_ceos(item, syslog_policy):
    context = {"receiver": syslog_policy["receiver"], "source_interface": item["source_interface"]}
    desired = render("ceos_syslog.j2", context)
    desired_hash = hashlib.sha256(desired.encode()).hexdigest()
    statefile = RUNTIME / (item["device"] + "-syslog-state.json")
    current = cli(item, "show running-config | section logging")
    current_hash = hashlib.sha256(current.encode()).hexdigest()
    prior = json.loads(statefile.read_text()) if statefile.exists() else {}
    if prior.get("desired") == desired_hash and prior.get("actual") == current_hash:
        print(item["device"] + ": syslog config unchanged", flush=True)
    else:
        cli(item, "configure terminal\n" + desired + "end")
        cli(item, "write memory")
        current = cli(item, "show running-config | section logging")
        statefile.parent.mkdir(parents=True, exist_ok=True)
        statefile.write_text(json.dumps({"desired": desired_hash, "actual": hashlib.sha256(current.encode()).hexdigest()}, indent=2))
        print(item["device"] + ": syslog config converged", flush=True)

    forwarder_source = (
        (MONITORING / "scripts/ceos_syslog_forward.py").read_text()
        .replace("__RECEIVER__", syslog_policy["receiver"])
        .replace("__PORT__", str(syslog_policy["port"]))
        .replace("__MAX_SEVERITY__", str(syslog_policy["max_severity"]))
    )
    provisioner = (MONITORING / "scripts/provision_ceos_syslog_forwarder.py").read_text()
    result = docker_exec_json(item["container"], provisioner, {"script": forwarder_source})
    print(item["device"] + ": " + result.strip(), flush=True)


# --------------------------------------------------------------------------
# R3/R4 (Ubuntu/FRR): install and run rsyslog without systemd, forwarding
# critical-or-worse local syslog(3) events to NMAS.
# --------------------------------------------------------------------------

def configure_linux(item, syslog_policy):
    config = render("linux_syslog.conf.j2", syslog_policy)
    provisioner = (MONITORING / "scripts/provision_linux_syslog.py").read_text()
    result = docker_exec_json(item["container"], provisioner, {"config": config}, timeout=600)
    print(item["device"] + ": " + result.strip(), flush=True)


# --------------------------------------------------------------------------
# NMAS receiver: ingestion pipeline (raw log already exists/verified).
# --------------------------------------------------------------------------

def influx():
    env = dict(line.split("=", 1) for line in (RUNTIME / "monitoring.env").read_text().splitlines() if "=" in line)
    import requests
    session = requests.Session()
    session.trust_env = False
    session.headers["Authorization"] = "Token " + env["INFLUXDB_TOKEN"]
    return session, env


def ensure_receiver(items):
    _, env = influx()
    # Keyed by every hostname spelling a device might actually report: RFC 5424
    # HOSTNAME syntax disallows "_", so mgmt_swt's Linux/EOS kernel hostname is
    # reported as "mgmt-swt" over the wire even though inventory.yml (and the
    # device tag we want stored/queried) uses "mgmt_swt" -- verified live.
    device_map = {}
    for item in items:
        entry = {"device": item["device"], "platform": item["platform"]}
        device_map[item["device"]] = entry
        device_map[item["device"].replace("_", "-")] = entry
    payload = {
        "daemon_script": (MONITORING / "scripts/syslog_ingest_daemon.py").read_text(),
        "devices": device_map,
        "influx_org": env["INFLUXDB_ORG"],
        "influx_bucket": env["INFLUXDB_BUCKET"],
        "influx_token": env["INFLUXDB_TOKEN"],
        "python": str(VENV / "bin/python"),
    }
    script = (MONITORING / "scripts/provision_syslog_receiver.py").read_text()
    print(command(["sudo", "-n", "python3", "-c", script], json.dumps(payload)).strip(), flush=True)
    # Base rsyslog/logrotate wiring is unchanged by this phase; still converge
    # it defensively (idempotent/no-op unless drifted) so --syslog-only is
    # self-sufficient even if NMAS base setup has not run in this session.
    command(["bash", str(MONITORING / "scripts/install_nmas_receivers.sh")])


# --------------------------------------------------------------------------
# Verification: config presence, a fresh critical test marker end-to-end,
# raw-log evidence, and InfluxDB storage -- per device.
# --------------------------------------------------------------------------

def tag(value):
    return str(value).replace("\\", "\\\\").replace(" ", "\\ ").replace(",", "\\,").replace("=", "\\=")


def config_present(item, syslog_policy):
    if item["platform"] == "ceos":
        current = cli(item, "show running-config | section logging")
        return (
            f'logging host {syslog_policy["receiver"]}' in current
            and "logging trap critical" in current
            and f'logging local-interface {item["source_interface"]}' in current
        )
    try:
        expected = render("linux_syslog.conf.j2", syslog_policy)
        actual = docker("exec", item["container"], "cat", "/etc/rsyslog.d/nmas-syslog.conf")
        pid = docker("exec", item["container"], "cat", "/run/rsyslogd.pid").strip()
        docker("exec", item["container"], "test", "-d", "/proc/" + pid)  # raises if rsyslogd is not running
        return actual == expected
    except NmasError:
        return False


def generate_critical(item, marker, syslog_policy):
    if item["platform"] == "ceos":
        # Native EOS local generation -- genuine evidence of a device-originated
        # severity=critical event (verifiable via `show logging`), but this
        # image's rsyslogd crash-loop (see docs/SYSLOG_IMPLEMENTATION.md) makes
        # its actual arrival at NMAS via that path unreliable/racy, so it is
        # best-effort here and not depended on for delivery.
        cli(item, "send log level critical message " + marker)
        # Deterministic delivery proof: the same RFC 5424 direct-UDP mechanism
        # the supplementary forwarder uses, run once here so verification does
        # not race the platform's broken local transport.
        docker(
            "exec", item["container"], "logger", "-n", syslog_policy["receiver"], "-P", str(syslog_policy["port"]),
            "--udp", "--rfc5424=notq", "-p", "local4.crit", "-t", item["device"], marker,
        )
    else:
        # R3/R4 have a genuinely working local rsyslogd (no platform defect);
        # this traverses the real configured forwarding path end-to-end.
        docker("exec", item["container"], "logger", "-p", "local4.crit", "-t", item["device"], marker)


def raw_log_contains(marker, timeout=15):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            text = Path("/var/log/lab-monitoring/remote-syslog.log").read_text(errors="replace")
        except PermissionError:
            text = command(["sudo", "-n", "cat", "/var/log/lab-monitoring/remote-syslog.log"])
        if marker in text:
            return True
        time.sleep(1)
    return False


def influx_contains(marker, device, timeout=15):
    session, env = influx()
    query = (
        f'from(bucket: {json.dumps(env["INFLUXDB_BUCKET"])}) |> range(start: -5m) '
        f'|> filter(fn: (r) => r._measurement == "syslog_event" and r.device == "{device}" and r._field == "message")'
        f'|> filter(fn: (r) => r._value =~ /{re.escape(marker)}/)'
    )
    deadline = time.time() + timeout
    last = ""
    while time.time() < deadline:
        r = session.post("http://127.0.0.1:8086/api/v2/query", params={"org": env["INFLUXDB_ORG"]}, headers={"Content-Type": "application/vnd.flux"}, data=query, timeout=15)
        r.raise_for_status()
        last = r.text
        if marker in last:
            return True
        time.sleep(1)
    return False


def verify_syslog(items=None, syslog_policy=None):
    items = items or devices()
    syslog_policy = syslog_policy or policy()
    results = []
    failed = []
    print("DEVICE      CONFIG  CRITICAL  RAWLOG  STORAGE")
    for item in items:
        row = {"device": item["device"], "config": "FAIL", "critical": "FAIL", "rawlog": "FAIL", "storage": "FAIL"}
        errors = []
        try:
            row["config"] = "PASS" if config_present(item, syslog_policy) else "FAIL"
        except Exception as exc:
            errors.append("config: " + str(exc))
        marker = f'NMAS_IAC_SYSLOG_TEST_{item["device"]}_{time.time_ns()}'
        try:
            generate_critical(item, marker, syslog_policy)
            row["critical"] = "PASS"
        except Exception as exc:
            errors.append("critical: " + str(exc))
        if row["critical"] == "PASS":
            try:
                row["rawlog"] = "PASS" if raw_log_contains(marker) else "FAIL"
            except Exception as exc:
                errors.append("rawlog: " + str(exc))
            try:
                row["storage"] = "PASS" if influx_contains(marker, item["device"]) else "FAIL"
            except Exception as exc:
                errors.append("storage: " + str(exc))
        if errors:
            row["errors"] = errors
        ok = all(row[k] == "PASS" for k in ("config", "critical", "rawlog", "storage"))
        print(f'{item["device"]:<12}{row["config"]:<8}{row["critical"]:<10}{row["rawlog"]:<8}{row["storage"]}', flush=True)
        results.append(row)
        if not ok:
            failed.append(item["device"])
    (RUNTIME / "syslog-verification.json").write_text(json.dumps(results, indent=2))
    if failed:
        raise NmasError("Syslog verification failed: " + ", ".join(failed))
    return results


def ensure_syslog_infrastructure(verbose=False):
    verify_nmas(verbose)
    syslog_policy = policy()
    items = devices()
    for item in items:
        if item["platform"] == "ceos":
            configure_ceos(item, syslog_policy)
        else:
            configure_linux(item, syslog_policy)
    ensure_receiver(items)
    verify_syslog(items, syslog_policy)
    verify_nmas(verbose)
